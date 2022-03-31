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
#include <mini-os/gntmap.h>
#include <mini-os/hypervisor.h>
#include <mini-os/types.h>

#include <bmk-core/errno.h>
#include <bmk-core/memalloc.h>
#include <bmk-core/string.h>
#include <bmk-core/sched.h>
#include <bmk-core/platform.h>
#include <bmk-core/printf.h>

#include <bmk-rumpuser/core_types.h>
#include <bmk-rumpuser/rumpuser.h>

#include <rumprun-base/rumprun.h>

#include <xen/fs.h>
#include <xen/fs_ring.h>
#include <xen/fs_hypercall.h>
#include <xen/_rumprun.h>

#include "../librumpfs_myfs/myfs.h"

static backend_connect_t fs_dom_info;
static frontend_connect_t app_dom_info[RUMPRUN_NUM_OF_APPS];

static struct gntmap backend_map[RUMPRUN_NUM_OF_APPS];

/* ring buffer structures */
static struct fsdom_fring *backend_fring[RUMPRUN_NUM_OF_APPS];
static struct fsdom_aring *backend_req_aring[RUMPRUN_NUM_OF_APPS];
static struct fsdom_aring *backend_rsp_aring[RUMPRUN_NUM_OF_APPS];

static void *backend_buf[RUMPRUN_NUM_OF_APPS];

static uint64_t frontend_base[RUMPRUN_NUM_OF_APPS];
static void *frontend_mem[RUMPRUN_NUM_OF_APPS];

/* receiver thread */
struct backend_thread {
	_Alignas(LF_CACHE_BYTES) struct bmk_thread * thread;
	_Atomic(unsigned int) state;
	unsigned int dom;
	_Alignas(LF_CACHE_BYTES) char pad[0];
};
static struct backend_thread backend_threads[RUMPRUN_NUM_OF_APPS];

static _Atomic(unsigned int) frontend_dom = ATOMIC_VAR_INIT(0);

static inline void backend_interrupt_handler(unsigned int dom,
		struct pt_regs *regs, void *data)
{
	//bmk_printf("Interrupt from dom%u arrives\n", dom);
	if (atomic_exchange(&backend_req_aring[dom]->readers, 1) == 0)
		bmk_sched_wake(backend_threads[dom].thread);
}

#define BACKEND_INTERRUPT(dom)						\
static void _backend_interrupt_handler_##dom(evtchn_port_t port,	\
		struct pt_regs *regs, void * data)			\
{									\
	return backend_interrupt_handler(dom, regs, data);		\
}

typedef void (*backend_interrupt_t) (unsigned int, struct pt_regs *, void *);

BACKEND_INTERRUPT(0)
BACKEND_INTERRUPT(1)
BACKEND_INTERRUPT(2)
BACKEND_INTERRUPT(3)
BACKEND_INTERRUPT(4)

static backend_interrupt_t backend_interrupt_handlers[RUMPRUN_NUM_OF_APPS] = {
	_backend_interrupt_handler_0,
	_backend_interrupt_handler_1,
	_backend_interrupt_handler_2,
	_backend_interrupt_handler_3,
	_backend_interrupt_handler_4
};

static void backend_welcome_handler(evtchn_port_t port, struct pt_regs *regs,
		void *data)
{
	bmk_printf("Interrupt from port %d arrives\n", port);
	backend_connect(port);
}


struct receiver_block_data {
	struct bmk_block_data header;
	unsigned int dom;
};

static void
receiver_callback(struct bmk_thread *prev, struct bmk_block_data *_block)
{
	struct receiver_block_data *block =
		(struct receiver_block_data *) _block;
	unsigned int dom = block->dom;
	long old = -1;

	if (!atomic_compare_exchange_strong(&backend_req_aring[dom]->readers, &old, 0))
		bmk_sched_wake(backend_threads[dom].thread);
}

static void backend_receiver(void *arg)
{
	struct backend_thread * bt = arg;
	struct receiver_block_data block_data;
	unsigned int dom = bt->dom;
	size_t idx, fails;
	syscall_args_t *syscall_args = NULL;
	void *buf;
	long int retval;
	int error = 0;
	uint64_t offset;
	//struct lfring **_frontend_runq;
	//struct bmk_thread *_frontend_thread;

	block_data.header.callback = receiver_callback;
	block_data.dom = dom;
	offset = (uint64_t)frontend_mem[dom] - frontend_base[dom];

	/* Give us a rump kernel context */
	//rumpuser__hyp.hyp_schedule();
	//rumpuser__hyp.hyp_lwproc_newlwp(0);
	//rumpuser__hyp.hyp_unschedule();

	atomic_store(&backend_req_aring[dom]->readers, 1);
start_over:
	fails = 0;
again:
	while ((idx = lfring_dequeue((struct lfring *) backend_req_aring[dom]->ring,
			FSDOM_RING_ORDER, false)) != LFRING_EMPTY) {
retry:
		fails = 0;
		buf = backend_buf[dom] + idx * FSDOM_DATA_SIZE;
		syscall_args = (syscall_args_t *)buf;

		rumpuser__hyp.hyp_schedule();

		/* XXX do system call here? */
		bmk_printf("args: (%lu, %lu, %lu, %lu, %lu, %lu, %lx, %lu)\n", \
				syscall_args->arg[0], syscall_args->arg[1], syscall_args->arg[2], syscall_args->arg[3], \
				syscall_args->arg[4], syscall_args->arg[5], (uint64_t)syscall_args->thread, syscall_args->call_id);

		switch (syscall_args->call_id) {
			case OPEN:
			{
				char *path;
				uint64_t flags;
				uint64_t mode;

				path = (char *)syscall_args->arg[0] + offset;
				flags = syscall_args->arg[1];
				mode  = syscall_args->arg[2];
				bmk_printf("(OPEN) path: %s, flags: %lu, mode: %lu\n", path, flags, mode);
				error = rump_fsdom_open(path, flags, mode, &retval);
				bmk_printf("rump_fsdom_open returns, error: %d, retval: %d\n", error, (int)retval);
				break;
			}

			case READ:
			{
				uint64_t fd;
				void *buffer;
				uint64_t nbyte;

				fd = syscall_args->arg[0];
				buffer = (void *)syscall_args->arg[1] + offset;
				nbyte  = syscall_args->arg[2];
				bmk_printf("(READ) fd: %d, nbyte: %lu\n", (int)fd, nbyte);
				error = rump_fsdom_read(fd, buffer, nbyte, &retval);
				bmk_printf("rump_fsdom_read returns, error: %d, retval: %d\n", error, (int)retval);

				break;
			}
			case WRITE:
			{
				// char *data;
				//data = (char *)(syscall_args->arg[1] + offset);
				//bmk_printf("data: %s\n", data);

				break;
			}

			case CLOSE:
				break;

			case FCNTL:
			{
				uint64_t fd;
				uint64_t cmd;
				void *arg;

				fd = syscall_args->arg[0];
				cmd  = syscall_args->arg[1];
				arg = (void *)syscall_args->arg[2] + offset;
				bmk_printf("(FCNTL) fd: %d, cmd: %d\n", (int)fd, (int)cmd);
				error = rump_fsdom_fcntl(fd, cmd, arg, &retval);
				bmk_printf("rump_fsdom_fcntl returns, error: %d, retval: %d\n", error, (int)retval);

				break;
			}

			default:
				bmk_printf("Wrong file operation\n");
				error = 19;
				break;
		}

		//bmk_memcpy(&syscall_args->arg[0], &retval, sizeof(uint64_t));
		syscall_args->arg[0] = retval;
		syscall_args->arg[1] = error;
		rumpuser__hyp.hyp_unschedule();
	}

	if (++fails < 256) {
		bmk_sched_yield();
		goto again;
	}

	/* Shut down the thread */
	atomic_store(&backend_req_aring[dom]->readers, -1);
	idx = lfring_dequeue((struct lfring *) backend_req_aring[dom]->ring,
			FSDOM_RING_ORDER, false);

	if (idx != LFRING_EMPTY)
		goto retry;

	if (syscall_args != NULL)
	{
		/* Wake up the frontend */
		//_frontend_runq = (struct lfring **)(frontend_runq[dom] + offset);
		//_frontend_thread = (struct bmk_thread *)((uint64_t)syscall_args->thread + offset);
		//bmk_sched_wake_runq(_frontend_runq, offset, _frontend_thread);
	}

	bmk_sched_blockprepare();
	bmk_sched_block(&block_data.header);

	goto start_over;
}


void backend_init(void)
{
	static _Atomic(int) init = 0;
	int init_old = 0;
	int err = 0;

	/* allow only one thread to enter, just one interface for now */
	if (!atomic_compare_exchange_strong(&init, &init_old, 1)) {
		return;
	}

	bmk_printf("Initializing fs-backend...\n");

        /* allocate port table in the backend_connect_t */
	fs_dom_info.port = bmk_memalloc(sizeof(*fs_dom_info.port) * RUMPRUN_NUM_OF_APPS, 0, BMK_MEMWHO_RUMPKERN);
	if (fs_dom_info.port == NULL) {
		bmk_platform_halt("fs_dom_info.port fails\n");
	}

	/* assign welcome port */
	err = minios_evtchn_alloc_unbound(DOMID_BACKEND, backend_welcome_handler,
			"regular", &fs_dom_info.welcome_port);
	if (err) {
		bmk_platform_halt("Alloc welcome port fails\n");
	}

	minios_unmask_evtchn(fs_dom_info.welcome_port);

	/* register backend */
	err = HYPERVISOR_syscall_service_op(RUMPRUN_SERVICE_REGISTER, SYSID_FS, &fs_dom_info);
	if (err) {
		bmk_platform_halt("HYP register fails\n");
	}
}

void backend_connect(evtchn_port_t port)
{
	unsigned int dom;
	int err = 0;
	int ret = 1;
	frontend_grefs_t *frontend_grefs;
	uint32_t domids[1];
	uint64_t fring_offset;
	uint32_t grefs_required;
	/*
	 * frontend_dom is an internal domid only used in this fs driver.
	 * Note that domid in Xenstore is NOT related to the frontend_dom.
	 */
	dom = atomic_fetch_add(&frontend_dom, 1);
	if (dom > RUMPRUN_NUM_OF_APPS) {
		bmk_platform_halt("Too many frontend domains\n");
	}

	ret = HYPERVISOR_syscall_service_op(RUMPRUN_SERVICE_FETCH, SYSID_FS, \
						app_dom_info);
	if (ret) {
		bmk_platform_halt("HYP fetch fails\n");
	}

	domids[0] = app_dom_info[dom].domid;

	gntmap_init(&backend_map[dom]);

	grefs_required = app_dom_info[dom].grefs[0];
	//bmk_printf("grefs_required: %u\n", grefs_required);

	/* first, retrieve grefs of the shared pages */
	frontend_grefs = gntmap_map_grant_refs(&backend_map[dom],
		grefs_required, domids, 0, app_dom_info[dom].grefs + 1, 1);

	int i;
	for (i = 1; i < grefs_required + 1; i++) {
		bmk_printf("grefs[%u]: %d\n", i, app_dom_info[dom].grefs[i]);
	}

	/* map frontend's entire memory space */
	frontend_mem[dom] = gntmap_map_grant_refs(&backend_map[dom],
		frontend_grefs->len, domids, 0, frontend_grefs->range_grefs, 1);

	__asm__ __volatile__("" ::: "memory");

	fring_offset = frontend_grefs->fring_addr - frontend_grefs->base;
	backend_fring[dom] = (struct fsdom_fring *)(frontend_mem[dom] + fring_offset);
	backend_req_aring[dom] = FSDOM_REQ_ARING(backend_fring[dom]);
	backend_rsp_aring[dom] = FSDOM_RSP_ARING(backend_fring[dom]);
	backend_buf[dom] = FSDOM_BUF(backend_fring[dom]);

	frontend_base[dom] = frontend_grefs->base;

	gntmap_munmap(&backend_map[dom], (uint64_t) frontend_grefs, grefs_required);

	/* create a receiver thread */
	backend_threads[dom].dom = dom;
	backend_threads[dom].thread = bmk_sched_create("backend_receiver", NULL, 1,
				-1, backend_receiver, &backend_threads[dom], NULL, 0);
	if (backend_threads[dom].thread == NULL) {
		bmk_platform_halt("fatal thread creation failure\n");
	}

	__asm__ __volatile__("" ::: "memory");

	/* bind the port to the app dom */
	err = minios_evtchn_bind_interdomain(app_dom_info[dom].domid,
		app_dom_info[dom].port, backend_interrupt_handlers[dom], NULL,
		&fs_dom_info.port[dom]);
	if (err) {
		bmk_platform_halt("Bind interdomain fails\n");
	}

	minios_unmask_evtchn(fs_dom_info.port[dom]);

	/* assign new welcome port */
	err = minios_evtchn_alloc_unbound(DOMID_BACKEND,
			backend_welcome_handler, "regular", &fs_dom_info.welcome_port);
	if (err) {
		bmk_printf("Alloc welcome port fails\n");
	}

	/* register backend */
	err = HYPERVISOR_syscall_service_op(RUMPRUN_SERVICE_REGISTER, SYSID_FS, \
						&fs_dom_info);
	if (err) {
		bmk_platform_halt("HYP register fails\n");
	}

	minios_unmask_evtchn(fs_dom_info.welcome_port);

	bmk_printf("Connected fsdom-frontend\n");
}