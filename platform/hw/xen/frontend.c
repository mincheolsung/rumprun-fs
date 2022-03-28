/*
 * Copyright (c) 2018 Mincheol Sung.  All Rights Reserved.
 * Copyright (c) 2018 Ruslan Nikolaev.  All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <mini-os/os.h>
#include <mini-os/events.h>
#include <mini-os/gnttab.h>
#include <mini-os/gntmap.h>
#include <mini-os/semaphore.h>

#include <bmk-core/errno.h>
#include <bmk-core/memalloc.h>
#include <bmk-core/pgalloc.h>
#include <bmk-core/string.h>
#include <bmk-core/sched.h>
#include <bmk-core/platform.h>
#include <bmk-core/printf.h>

#include <bmk-rumpuser/core_types.h>
#include <bmk-rumpuser/rumpuser.h>

//#include "../librumpfs_myfs/myfs.h"

#include <xen/fs.h>
#include <xen/fs_ring.h>
#include <xen/fs_hypercall.h>

#define frontend_virt_to_pfn(a)	((uint64_t) (a) >> PAGE_SHIFT)

static backend_connect_t fs_dom_info;
static frontend_connect_t app_dom_info;

#define FSDOM_ARING(fring)	\
	((struct fsdom_aring *) ((char *) fring + 2 * PAGE_SIZE))
#define FSDOM_BUF(fring)	\
	((char *) fring + 4 * PAGE_SIZE)

static struct fsdom_fring *caller_fring = NULL;
static struct fsdom_aring *caller_aring = NULL;
static void *caller_buf = NULL;

static frontend_grefs_1_t *_frontend_grefs_1;
static frontend_grefs_2_t *_frontend_grefs_2;

/* Address space range */
static uint64_t *range;
#define ADDR_MIN range[0];
#define ADDR_MAX range[1];

//static _Atomic(int) frontend_terminating = ATOMIC_VAR_INIT(0);

static void frontend_hello_handler(evtchn_port_t port, struct pt_regs *regs,
		void *data)
{
	/* XXX Does nothing for now */
}

static void frontend_interrupt_handler(evtchn_port_t port,
		struct pt_regs *regs, void *data)
{
	bmk_printf("frontend_interrupt_handler\n");
}

static void frontend_grant_range(uint64_t min, uint64_t max, uint64_t num,
		                 frontend_grefs_1_t **pgrefs_1, frontend_grefs_2_t **pgrefs_2, uint32_t *result)
{
	uint64_t i;
	uint32_t nr_frames_grefs_level2;
	frontend_grefs_1_t *grefs_1;
	frontend_grefs_2_t *grefs_2;

	grefs_1 = bmk_pgalloc(1);
	if (!grefs_1)
		bmk_platform_halt("grefs_1 shared page not allocated\n");

	*pgrefs_1 = grefs_1;

	/* grant level1 grefs */
	result[0] = gnttab_grant_access(fs_dom_info.domid,
		                        frontend_virt_to_pfn(grefs_1), 0);
        result[1] = gnttab_grant_access(fs_dom_info.domid,
			                frontend_virt_to_pfn((char *)grefs_1 + PAGE_SIZE), 0);

	nr_frames_grefs_level2 = sizeof(grant_ref_t)*gntmap_map2order(num); /* 64 frames for grefs of 64K entries */
	grefs_1->len = (uint32_t)nr_frames_grefs_level2;

	grefs_2 = bmk_pgalloc(gntmap_map2order(nr_frames_grefs_level2));
	if (!grefs_2)
		bmk_platform_halt("grefs_2 shared page not allocated\n");

	*pgrefs_2 = grefs_2;

	/* grant level2 grefs (0 ... 63)*/
	for (i = 0; i < nr_frames_grefs_level2; i++) {
		grefs_1->range_grefs_1[i] = gnttab_grant_access(fs_dom_info.domid, \
						frontend_virt_to_pfn((char *)grefs_2 + i*PAGE_SIZE), 0);
	}

	/* grant frontend memory space */
	for (i = 0; i < num; i++) {
		grefs_2->range_grefs_2[i] = gnttab_grant_access(fs_dom_info.domid, frontend_virt_to_pfn(min + i * PAGE_SIZE), 0);
	}

	grefs_2->base = (uint64_t)min;
	grefs_2->len = (uint32_t)num;
}

static struct fsdom_fring * frontend_init_ring(uint64_t min)
{
	struct fsdom_aring *aring;
	struct fsdom_fring *fring;

	fring = bmk_pgalloc(gntmap_map2order(4 + FSDOM_RING_DATA_PAGES));
	if (!fring)
		bmk_platform_halt("shared pages are not allocated\n");
	aring = FSDOM_ARING(fring);

	lfring_init_empty((struct lfring *) aring->ring, FSDOM_RING_ORDER);
	lfring_init_full((struct lfring *) fring->ring, FSDOM_RING_ORDER);
	atomic_init(&aring->readers, 0);

	_frontend_grefs_2->fring_addr =  (uint64_t)fring;
	return fring;
}

struct block_caller {
	struct bmk_block_data header;
	size_t *idx;
};

static void
caller_callback(struct bmk_thread *prev, struct bmk_block_data *_block)
{
	struct block_caller *bc = (struct block_caller *)_block;

	bmk_printf("caller_callback, idx: %lu\n", *bc->idx);

	lfring_enqueue((struct lfring *) caller_aring->ring,
			FSDOM_RING_ORDER, *bc->idx);

	/* Wake up the other side. */
	if (atomic_load(&caller_aring->readers) <= 0)
		minios_notify_remote_via_evtchn(app_dom_info.port);
}

int frontend_syscall(syscall_args_t *syscall_args, long int *retval)
{
	size_t idx;
	void *buf;
	int ret;

	struct block_caller bc;
	bc.header.callback = caller_callback;
	bc.idx = &idx;

	if (!caller_fring)
	{
		bmk_printf("Caller's fring is null\n");
		return -1;
	}

	syscall_args->thread = bmk_current;

	bmk_printf("args: (%lu, %lu, %lu, %lu, %lu, %lu, %lx, %lu), retval: %ld\n", syscall_args->arg[0], syscall_args->arg[1], \
			syscall_args->arg[2], syscall_args->arg[3], syscall_args->arg[4], syscall_args->arg[5], \
		      (uint64_t)syscall_args->thread, syscall_args->call_id, *retval);

	idx = lfring_dequeue((struct lfring *) caller_fring->ring,
		FSDOM_RING_ORDER, false);
	if (idx == LFRING_EMPTY)
		return -1;

	buf = caller_buf + idx * FSDOM_DATA_SIZE;
	bmk_memcpy(buf, syscall_args, sizeof(syscall_args_t));

	bmk_sched_blockprepare();
	bmk_sched_block(&bc.header);

	*retval = *(long int *)buf;
	ret = *(int *)(buf + sizeof(long int));

  	lfring_enqueue((struct lfring *)caller_fring->ring,
			         	FSDOM_RING_ORDER, idx);

	bmk_printf("Caller wakes up, ret: %d, retval: %ld\n", ret, *retval);
	return ret;
}

void frontend_init(void)
{
	struct fsdom_fring *_fring;
	int err = 0;
	evtchn_port_t old_hello_port;

	bmk_printf("Initializing fsdom-frontend...\n");
	err = HYPERVISOR_syscall_service_op(SYSCALL_SERVICE_QUERY, SYSID_FS,
			&fs_dom_info);
	if (err)
		bmk_platform_halt("HYP query fails");

	range = bmk_mem_range();
	/* Let's hardcode the base address to 1mb */
	range[0] = 0x100000;
	bmk_printf("address min: %lu, address max: %lu\n", range[0], range[1]);
	bmk_printf("total num of pages: %lu\n", (range[1]-range[0]) >> BMK_PCPU_PAGE_SHIFT);

	frontend_grant_range(range[0], range[1], (range[1]-range[0]) >> BMK_PCPU_PAGE_SHIFT, &_frontend_grefs_1, &_frontend_grefs_2, app_dom_info.grefs);

	/* init the front-end ring buffers */
	_fring = frontend_init_ring(range[0]);

	/* pass the runq's address */
	_frontend_grefs_2->runq_addr = (uint64_t)bmk_sched_runq();

	/* initialize TX free ring when everything is ready */
	__asm__ __volatile__("" ::: "memory");
	caller_fring = _fring;
	caller_aring = FSDOM_ARING(_fring);
	caller_buf = FSDOM_BUF(_fring);

	__asm__ __volatile__("" ::: "memory");

	/* bind the channel to backend's welcome port */
	err = minios_evtchn_bind_interdomain(fs_dom_info.domid,
			fs_dom_info.welcome_port, frontend_hello_handler,
			NULL, &app_dom_info.hello_port);
	if (err)
		bmk_platform_halt("bind interdomain fails");

	/* create an main event channel with port*/
	err = minios_evtchn_alloc_unbound(fs_dom_info.domid,
			frontend_interrupt_handler, NULL, &app_dom_info.port);
	if (err)
		bmk_platform_halt("main event channel alloc fails");

	old_hello_port = app_dom_info.hello_port;

	err = minios_evtchn_alloc_unbound(DOMID_BACKEND,
			frontend_hello_handler, NULL, &app_dom_info.hello_port);
	if (err)
		bmk_platform_halt("main event channel alloc fails");

	//app_dom_info.status = FRONTEND_ACTIVE;

	/* register frontend */
	err = HYPERVISOR_syscall_service_op(SYSCALL_SERVICE_REGISTER_APP, SYSID_FS,
			&app_dom_info);
	if (err)
		bmk_platform_halt("HYP register app fails\n");

	/* say hello to backend */
	err = minios_notify_remote_via_evtchn(old_hello_port);
	if (err)
		bmk_printf("notify welcome port fails\n");

	//minios_unmask_evtchn(app_dom_info.port);
	minios_unmask_evtchn(app_dom_info.hello_port);
}
