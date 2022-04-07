#include <sys/filedesc.h>
#include <sys/systm.h>
#include <sys/syscallargs.h>
#include <sys/workqueue.h>

#include <xen/fs.h>
#include "myfs.h"

static uint64_t rump_offset;
static struct workqueue *rump_fsdom_workqueue;
filedesc_t *fdesc;

static void rump_fsdom_work(struct work *wk, void *dummy)
{
	int ret;
	register_t retval;
	syscall_args_t *args;

	args = (syscall_args_t *)wk;

	KASSERT((uint64_t)&args->wk == (uint64_t)wk);

	aprint_normal("rump_fsdom_work offset: %lx\n", rump_offset);

	switch (args->call_id) {
	/*
		case GETFILE:
		{
        		aprint_normal("rump_fd_getfile(%u)\n", fd);
        		file_t *fp;
			fp = fd_getfile(fd);
			if (fp == NULL) {
				ret = -1;
			} else {
				ret = 0;
			}
			break;
		}
	*/
		case OPEN:
		{
			struct sys_open_args syscall_args;
			struct sys_open_args *uap = (struct sys_open_args *)((uint64_t)args->uap + rump_offset);

			SCARG(&syscall_args, path) = (char *)((uint64_t)SCARG(uap, path) + rump_offset);
		        SCARG(&syscall_args, flags) = SCARG(uap, flags);
     			SCARG(&syscall_args, mode) = SCARG(uap, mode);

			ret = sys_open(curlwp, (const struct sys_open_args *)&syscall_args, &retval);

			aprint_normal("rump_fsdom_open path: %s, flags: %d, mode: %d, ret: %d, retval: %lu\n",
				SCARG(&syscall_args, path),
				SCARG(&syscall_args, flags),
				SCARG(&syscall_args, mode),
				ret, retval);
			break;
		}

		case READ:
		{
			struct sys_read_args syscall_args;
			struct sys_read_args *uap = (struct sys_read_args *)((uint64_t)args->uap + rump_offset);
			SCARG(&syscall_args, fd) = SCARG(uap, fd);
		        SCARG(&syscall_args, buf) = (void *)((uint64_t)SCARG(uap, buf) + rump_offset);
     			SCARG(&syscall_args, nbyte) = SCARG(uap, nbyte);

			aprint_normal("rump_fsdom_read fd: %d, buf: %s, nbyte: %ld, ret: %d, retval: %lu\n",
                                SCARG(&syscall_args, fd),
                                (char *)SCARG(&syscall_args, buf),
                                SCARG(&syscall_args, nbyte),
                                ret, retval);

			ret = sys_read(curlwp, (const struct sys_read_args *)&syscall_args, &retval);
			break;
		}

		case WRITE:
		{
			aprint_normal("rump_fsdom_write\n");
			//ret = sys_write(curlwp, (const struct sys_write_args *)args->uap, &args->retval);
			break;
		}

		case CLOSE:
		{
			aprint_normal("rump_fsdom_close\n");
			//ret = sys_close(curlwp, (const struct sys_close_args *)args->uap, &args->retval);
			break;
		}

		case FCNTL:
		{
			aprint_normal("rump_fsdom_read\n");
			//ret = sys_fcntl(curlwp, (const struct sys_fcntl_args *)args->uap, &args->retval);
			break;
		}

		default:
		{
			aprint_normal("Unsupported operation\n");
			ret = -1;
		}
	}
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

file_t *rump_fd_getfile(unsigned fd)
{
        aprint_normal("rump_fd_getfile(%u)\n", fd);
        return NULL;
        //return fd_getfile(fd);
}

void rump_fsdom_receive(void *slot, int args)
{
	return;
}
