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
#include <bmk-core/core.h>

#include <bmk-rumpuser/core_types.h>
#include <bmk-rumpuser/rumpuser.h>

//#include "../librumpfs_myfs/myfs.h"

#include <xen/fs.h>
#include <xen/fs_ring.h>
#include <xen/fs_hypercall.h>
#include <xen/_rumprun.h>

#define frontend_virt_to_pfn(a)	((uint64_t) (a) >> PAGE_SHIFT)

static backend_connect_t fs_dom_info;
static frontend_connect_t app_dom_info;

static struct fsdom_fring *frontend_fring = NULL;
static struct fsdom_aring *frontend_req_aring = NULL;
static struct fsdom_aring *frontend_rsp_aring = NULL;
static void *frontend_buf = NULL;

static frontend_grefs_t *frontend_grefs;

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

static void frontend_grant_range(frontend_grefs_t **pgrefs, uint32_t *result)
{
	uint32_t i;

	/* Address space range */
	uint64_t *range;
	uint64_t num_range;
	frontend_grefs_t *grefs;
	uint32_t grefs_required;

	/* Retreive address space range */
	range = bmk_mem_range();
	bmk_assert(range[0] <= range[1]);

	bmk_printf("\n================frontend_grant_range====================\n");
	bmk_printf("bmk_mem_range returns (0x%lx ~ 0x%lx)\n", range[0], range[1]);

	/* Let's hardcode the base address to 1mb */
	range[0] = 0x100000;
	bmk_assert(range[1] > 0x100000);
	num_range = (range[1]-range[0]) >> BMK_PCPU_PAGE_SHIFT;

	bmk_printf("hardcoded range (0x%lx ~ 0x%lx)\n", range[0], range[1]);
	bmk_printf("total num of frames in the range: %lu\n", num_range);

	grefs_required = (24 + 4*num_range - 1) / BMK_PCPU_PAGE_SIZE + 1;
	bmk_assert(grefs_required <= GREFS_PAGES - 1);

	bmk_printf("GREFS_PAGES: %lu, grefs_required %u\n", (uint64_t)GREFS_PAGES, grefs_required);

	grefs = bmk_pgalloc(gntmap_map2order(GREFS_PAGES));
	if (!grefs) {
		bmk_platform_halt("grefs shared page not allocated\n");
	}

	*pgrefs = grefs;

	result[0] = grefs_required;
	for (i = 0; i < grefs_required; i++) {
                result[i+1] = gnttab_grant_access(fs_dom_info.domid, \
                        frontend_virt_to_pfn((void *) grefs + i*PAGE_SIZE), 0);
		//bmk_printf("grefs[%u]: %d\n", i+1, result[i+1]);
        }

	/* grant frontend memory space */
	for (i = 0; i < num_range; i++) {
		grefs->range_grefs[i] = gnttab_grant_access(fs_dom_info.domid, \
				frontend_virt_to_pfn(range[0] + i*PAGE_SIZE), 0);
		//bmk_printf("range_grefs[%u]: %d\n", i, grefs->range_grefs[i]);
	}

	grefs->base = range[0];
	grefs->len = num_range;
}

static void frontend_init_ring(void)
{
	frontend_fring = bmk_pgalloc(gntmap_map2order(3*RING_PAGES + \
						FSDOM_RING_DATA_PAGES));
	if (!frontend_fring)
		bmk_platform_halt("shared pages are not allocated\n");

	__asm__ __volatile__("" ::: "memory");

	frontend_grefs->fring_addr = (uint64_t)frontend_fring;
	frontend_req_aring = FSDOM_REQ_ARING(frontend_fring);
	frontend_rsp_aring = FSDOM_RSP_ARING(frontend_fring);
	frontend_buf = FSDOM_BUF(frontend_fring);

	__asm__ __volatile__("" ::: "memory");

	lfring_init_full((struct lfring *) frontend_fring->ring, FSDOM_RING_ORDER);
	lfring_init_empty((struct lfring *) frontend_req_aring->ring, FSDOM_RING_ORDER);
	lfring_init_empty((struct lfring *) frontend_rsp_aring->ring, FSDOM_RING_ORDER);

	atomic_init(&frontend_fring->readers, 1);
	atomic_init(&frontend_req_aring->readers, 0);
	atomic_init(&frontend_rsp_aring->readers, 0);
	atomic_signal_fence(memory_order_seq_cst);
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

	lfring_enqueue((struct lfring *) frontend_req_aring->ring,
			FSDOM_RING_ORDER, *bc->idx, false);

	/* Wake up the other side. */
	if (atomic_load(&frontend_req_aring->readers) <= 0)
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

	if (!frontend_fring)
	{
		bmk_printf("Caller's fring is null\n");
		return -1;
	}

	syscall_args->thread = bmk_current;

	bmk_printf("args: (%lu, %lu, %lu, %lu, %lu, %lu, %lx, %lu), retval: %ld\n", \
		  syscall_args->arg[0], syscall_args->arg[1], \
		  syscall_args->arg[2], syscall_args->arg[3], \
		  syscall_args->arg[4], syscall_args->arg[5], \
	(uint64_t)syscall_args->thread, syscall_args->call_id, *retval);

	idx = lfring_dequeue((struct lfring *) frontend_fring->ring,
		FSDOM_RING_ORDER, false);
	if (idx == LFRING_EMPTY)
		return -1;

	buf = frontend_buf + idx * FSDOM_DATA_SIZE;
	bmk_memcpy(buf, syscall_args, sizeof(syscall_args_t));

	bmk_sched_blockprepare();
	bmk_sched_block(&bc.header);

	*retval = *(long int *)buf;
	ret = *(int *)(buf + sizeof(long int));

  	lfring_enqueue((struct lfring *)frontend_fring->ring,
			         	FSDOM_RING_ORDER, idx, false);

	bmk_printf("Caller wakes up, ret: %d, retval: %ld\n", ret, *retval);
	return ret;
}

void frontend_init(void)
{
	int err = 0;
	evtchn_port_t old_hello_port;

	bmk_printf("Initializing fsdom-frontend...\n");
	err = HYPERVISOR_syscall_service_op(RUMPRUN_SERVICE_QUERY, SYSID_FS,
			&fs_dom_info);
	if (err) {
		bmk_platform_halt("HYP query fails");
	}

	/* grant frontend's memory space */
	frontend_grant_range(&frontend_grefs, app_dom_info.grefs);

	/* init the front-end ring buffers */
	frontend_init_ring();

	/* bind the channel to backend's welcome port */
	err = minios_evtchn_bind_interdomain(fs_dom_info.domid,
			fs_dom_info.welcome_port, frontend_hello_handler,
			NULL, &app_dom_info.hello_port);
	if (err) {
		bmk_platform_halt("bind interdomain fails");
	}

	/* create an main event channel with port*/
	err = minios_evtchn_alloc_unbound(fs_dom_info.domid,
			frontend_interrupt_handler, NULL, &app_dom_info.port);
	if (err) {
		bmk_platform_halt("main event channel alloc fails");
	}

	old_hello_port = app_dom_info.hello_port;

	err = minios_evtchn_alloc_unbound(DOMID_BACKEND,
			frontend_hello_handler, NULL, &app_dom_info.hello_port);
	if (err) {
		bmk_platform_halt("main event channel alloc fails");
	}

	app_dom_info.status = RUMPRUN_FRONTEND_ACTIVE;

	/* register frontend */
	err = HYPERVISOR_syscall_service_op(RUMPRUN_SERVICE_REGISTER_APP, SYSID_FS,
			&app_dom_info);
	if (err) {
		bmk_platform_halt("HYP register app fails\n");
	}

	/* say hello to backend */
	err = minios_notify_remote_via_evtchn(old_hello_port);
	if (err) {
		bmk_printf("notify welcome port fails\n");
	}

	minios_unmask_evtchn(app_dom_info.port);
	minios_unmask_evtchn(app_dom_info.hello_port);
}
