#include <sys/filedesc.h>
#include <sys/systm.h>
#include <sys/syscallargs.h>
#include <sys/workqueue.h>

#include <xen/fs.h>
#include "myfs.h"

//#define DEBUG

static uint64_t rump_offset;
static struct workqueue *rump_fsdom_workqueue;
filedesc_t *fdesc;

static void rump_fsdom_work(struct work *wk, void *dummy)
{
	int ret;
	register_t retval;
	syscall_args_t *args;

	args = (syscall_args_t *)wk;

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
			aprint_normal("OPEN path: %s, flags: %d, mode: %d, ret: %d, retval: %lu\n",
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
			aprint_normal("READ fd: %d, nbyte: %ld, ret: %d, retval: %lu, buf:\n%s\n",
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
			aprint_normal("WRITE fd: %d, nbyte: %ld, ret: %d, retval: %lu, buf:\n%s\n",
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
                        aprint_normal("CLOSE fd: %d, ret: %d, retval: %lu\n",
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
			aprint_normal("FCNTL fd: %d, cmd: %d, arg: %lx, ret: %d, retval: %lu\n",
                                SCARG(&syscall_args, fd),
                                SCARG(&syscall_args, cmd),
                                *(uint64_t *)SCARG(&syscall_args, arg),
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

#ifndef FSDOM_FRONTEND
	rumpuser_fsdom_send(args);
#endif
}

void rump_fsdom_init_workqueue(void)
{
	int error;
	if ((error = workqueue_create(&rump_fsdom_workqueue, "fsdoned", \
            rump_fsdom_work, NULL, PRI_NONE, IPL_NONE, WQ_MPSAFE))) {
		aprint_normal("workqueue_create fails, error: %d\n", error);
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
