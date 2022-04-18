#include <sys/filedesc.h>
#include <sys/systm.h>
#include <sys/syscallargs.h>
#include <sys/workqueue.h>
#include <sys/lwp.h>
#include <sys/proc.h>

#include <xen/fs.h>
#include <xen/_rumprun.h>

#include "rump_private.h"
#include "myfs.h"

//#define DEBUG

static uint64_t rump_offset;
static struct workqueue *rump_fsdom_workqueue;

static struct lwp *rump_app_lwp_tbl[RUMPRUN_NUM_OF_APPS];
static void *rump_fsdom_switch(struct lwp **new)
{
	struct lwp *old;

	old = curlwp;

	if (*new == NULL) {
		*new = rump__lwproc_alloclwp(NULL);
		(*new)->l_proc->p_fd->fd_freefile = 3;
	}

	rump_lwproc_switch(*new);

	return old;
}

static void rump_fsdom_work(struct work *wk, void *dummy)
{
	int ret;
	struct lwp *old;
	syscall_args_t *args;
	register_t retval = 0;

	args = (syscall_args_t *)wk;

	KASSERT(args->domid < RUMPRUN_NUM_OF_APPS);
	old = rump_fsdom_switch(&rump_app_lwp_tbl[args->domid]);

	switch (args->call_id) {
		case OPEN:
		{
			struct sys_open_args syscall_args;
			struct sys_open_args *uap = (struct sys_open_args *)((uint64_t)args->uap + rump_offset);

			SCARG(&syscall_args, path) = (char *)((uint64_t)SCARG(uap, path) + rump_offset);
		        SCARG(&syscall_args, flags) = SCARG(uap, flags);
     			SCARG(&syscall_args, mode) = SCARG(uap, mode);

			ret = sys_open(curlwp, (const struct sys_open_args *)&syscall_args, &retval);
#ifdef DEBUG
			aprint_normal("OPEN path: %s, flags: %d, mode: %d, ret: %d, retval: %ld\n",
				SCARG(&syscall_args, path),
				SCARG(&syscall_args, flags),
				SCARG(&syscall_args, mode),
				ret, retval);
#endif
			break;
		}

		case READ:
		{
			struct sys_read_args syscall_args;
			struct sys_read_args *uap = (struct sys_read_args *)((uint64_t)args->uap + rump_offset);
			SCARG(&syscall_args, fd) = SCARG(uap, fd);
		        SCARG(&syscall_args, buf) = (void *)((uint64_t)SCARG(uap, buf) + rump_offset);
     			SCARG(&syscall_args, nbyte) = SCARG(uap, nbyte);

			ret = sys_read(curlwp, (const struct sys_read_args *)&syscall_args, &retval);
#ifdef DEBUG
			aprint_normal("READ fd: %d, nbyte: %ld, ret: %d, retval: %ld, buf:\n%s\n",
                                SCARG(&syscall_args, fd),
                                SCARG(&syscall_args, nbyte),
                                ret, retval,
				(char *)SCARG(&syscall_args, buf));
#endif
			break;
		}

		case WRITE:
		{
			struct sys_write_args syscall_args;
			struct sys_write_args *uap = (struct sys_write_args *)((uint64_t)args->uap + rump_offset);
			SCARG(&syscall_args, fd) = SCARG(uap, fd);
		        SCARG(&syscall_args, buf) = (void *)((uint64_t)SCARG(uap, buf) + rump_offset);
     			SCARG(&syscall_args, nbyte) = SCARG(uap, nbyte);

			ret = sys_write(curlwp, (const struct sys_write_args *)&syscall_args, &retval);
#ifdef DEBUG
			aprint_normal("WRITE fd: %d, nbyte: %ld, ret: %d, retval: %ld, buf:\n%s\n",
                                SCARG(&syscall_args, fd),
                                SCARG(&syscall_args, nbyte),
                                ret, retval,
				(const char *)SCARG(&syscall_args, buf));
#endif
			break;
		}

		case CLOSE:
		{
			struct sys_close_args syscall_args;
                        struct sys_close_args *uap = (struct sys_close_args *)((uint64_t)args->uap + rump_offset);
                        SCARG(&syscall_args, fd) = SCARG(uap, fd);

                        ret = sys_close(curlwp, (const struct sys_close_args *)&syscall_args, &retval);
#ifdef DEBUG
                        aprint_normal("CLOSE fd: %d, ret: %d, retval: %ld\n",
                                SCARG(&syscall_args, fd),
                                ret, retval);
#endif
			break;
		}

		case FCNTL:
		{
			struct sys_fcntl_args syscall_args;
			struct sys_fcntl_args *uap = (struct sys_fcntl_args *)((uint64_t)args->uap + rump_offset);
			SCARG(&syscall_args, fd) = SCARG(uap, fd);
     			SCARG(&syscall_args, cmd) = SCARG(uap, cmd);
		        SCARG(&syscall_args, arg) = (void *)((uint64_t)SCARG(uap, arg) + rump_offset);

			ret = sys_fcntl(curlwp, (const struct sys_fcntl_args *)&syscall_args, &retval);
#ifdef DEBUG
			aprint_normal("FCNTL fd: %d, cmd: %d, arg: %lx, ret: %d, retval: %ld\n",
                                SCARG(&syscall_args, fd),
                                SCARG(&syscall_args, cmd),
                                *(uint64_t *)SCARG(&syscall_args, arg),
                                ret, retval);
#endif
			break;
		}

		case LSEEK:
		{
			struct sys_lseek_args syscall_args;
			struct sys_lseek_args *uap = (struct sys_lseek_args *)((uint64_t)args->uap + rump_offset);

			SCARG(&syscall_args, fd) = SCARG(uap, fd);
		        SCARG(&syscall_args, PAD) = SCARG(uap, PAD);
			SCARG(&syscall_args, offset) = SCARG(uap, offset);
			SCARG(&syscall_args, whence) = SCARG(uap, whence);

			ret = sys_lseek(curlwp, (const struct sys_lseek_args *)&syscall_args, &retval);
#ifdef DEBUG
			aprint_normal("LSEEK fd: %d, PAD: %d, offset: %ld, whence: %d, ret: %d, retval: %ld\n",
                                SCARG(&syscall_args, fd),
                                SCARG(&syscall_args, PAD),
                                SCARG(&syscall_args, offset),
                                SCARG(&syscall_args, whence),
                                ret, retval);
#endif
			break;
		}

		case FSYNC:
		{
			struct sys_fsync_args syscall_args;
			struct sys_fsync_args *uap = (struct sys_fsync_args *)((uint64_t)args->uap + rump_offset);

			SCARG(&syscall_args, fd) = SCARG(uap, fd);

			ret = sys_fsync(curlwp, (const struct sys_fsync_args *)&syscall_args, &retval);
#ifdef DEBUG
			aprint_normal("FSYNC fd: %d, ret: %d, retval: %ld\n",
                                SCARG(&syscall_args, fd),
                                ret, retval);
#endif
			break;
		}

		default:
		{
			aprint_normal("Unsupported operation\n");
			ret = -1;
		}
	}

	args->ret  = ret;
	args->retval = retval;

	rump_fsdom_switch(&old);

#ifndef FSDOM_FRONTEND
	rumpuser_fsdom_send(args);
#endif
}

void rump_fsdom_init_workqueue(void)
{
	int error, i;
	if ((error = workqueue_create(&rump_fsdom_workqueue, "fsdoned", \
            rump_fsdom_work, NULL, PRI_NONE, IPL_NONE, WQ_MPSAFE))) {
		aprint_normal("workqueue_create fails, error: %d\n", error);
	}

	for (i = 0; i < RUMPRUN_NUM_OF_APPS; i++) {
		rump_app_lwp_tbl[i] = NULL;
		//rump_fd_tbl[i] = NULL;
	}
}

void rump_fsdom_set_offset(uint64_t offset)
{
	rump_offset = offset;
}

void rump_fsdom_enqueue(void *wk)
{
	workqueue_enqueue(rump_fsdom_workqueue, (struct work *)wk, NULL);
}

int rump_local_syscall(struct lwp *l, const void *uap, register_t *retval, int op)
{
	int ret;

	switch (op) {
		case READ:
		{
			ret = sys_read(l,(const struct sys_read_args *) uap, retval);
			break;
		}

		case WRITE:
		{
			ret = sys_write(l, (const struct sys_write_args *)uap, retval);
			break;
		}

		case FCNTL:
		{
			ret = sys_fcntl(l, (const struct sys_fcntl_args *)uap, retval);
			break;
		}

		case CLOSE:
		{
			ret = sys_close(l, (const struct sys_close_args *)uap, retval);
			break;
		}

		case LSEEK:
		{
			ret = sys_lseek(l, (const struct sys_lseek_args *)uap, retval);
			break;
		}

		case FSYNC:
		{
			ret = sys_fsync(l, (const struct sys_fsync_args *)uap, retval);
			break;
		}

		default:
		{
			aprint_normal("rump_local_syscall: unsupported op\n");
			ret = -1;
			break;
		}
	}

	return ret;
}

void rump_fsdom_print_curlwp(int i)
{
	aprint_normal("FOOBAR [%d] lwp: %p, proc: %p, p_fd: %p\n", i, curlwp, curlwp->l_proc, curlwp->l_proc->p_fd);
}
