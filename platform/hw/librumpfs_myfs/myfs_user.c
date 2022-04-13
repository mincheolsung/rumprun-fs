#include <bmk-rumpuser/rumpuser.h>
#include <bmk-rumpuser/core_types.h>
#include <bmk-core/printf.h>
#include <bmk-core/string.h>

#include <xen/fs.h>
#include <xen/fs_syscall.h>

#include "myfs.h"

#include <stdatomic.h>

//#define DEBUG

#ifndef FSDOM_FRONTEND
void(*rumpuser_fsdom_send)(void *) = backend_send;
#endif

void rumpuser_fsdom_init(void)
{
#ifdef FSDOM_FRONTEND
        frontend_init();
#else
	backend_init();
#endif
}

int rumpuser_fsdom_open(struct lwp *l, const void *uap, register_t *retval)
{
#ifdef FSDOM_FRONTEND
        int ret;
        syscall_args_t args;
	args.argp = &args;
	args.uap = (void *)uap;
        args.call_id = OPEN;

        ret = frontend_send(&args, retval);
#ifdef DEBUG
	bmk_printf("OPEN path: %s, flags: %d, mode: %d, ret: %d, retval: %lu\n",
				SCARG((struct sys_open_args *)uap, path),
				SCARG((struct sys_open_args *)uap, flags),
				SCARG((struct sys_open_args *)uap, mode),
                                ret, *retval);
#endif
        return ret;
#else
	return 0;
#endif
}

int rumpuser_fsdom_read(struct lwp *l, const void *uap, register_t *retval)
{
#ifdef FSDOM_FRONTEND
        int ret;
        syscall_args_t args;
	args.argp = &args;
	args.uap = (void *)uap;
        args.call_id = READ;

	if (SCARG((struct sys_read_args *)uap, fd) < 3) {
		ret = rump_local_syscall(l, uap, retval, READ);
	} else {
		ret = frontend_send(&args, retval);
	}
#ifdef DEBUG
	bmk_printf("READ fd: %d, nbyte: %ld, ret: %d, retval: %lu, buf:\n%s\n",
				SCARG((struct sys_read_args *)uap, fd),
				SCARG((struct sys_read_args *)uap, nbyte),
                                ret, *retval,
				(char *)SCARG((struct sys_read_args *)uap, buf));
#endif
	return ret;
#else
	return 0;
#endif
}

int rumpuser_fsdom_write(struct lwp *l, const void *uap, register_t *retval)
{
#ifdef FSDOM_FRONTEND
        int ret;
        syscall_args_t args;
	args.argp = &args;
        args.uap = (void *)uap;
	args.call_id = WRITE;

	if (SCARG((struct sys_read_args *)uap, fd) < 3) {
                ret = rump_local_syscall(l, uap, retval, WRITE);
        } else {
		ret = frontend_send(&args, retval);
	}
#ifdef DEBUG
        bmk_printf("WRITE fd: %d, nbyte: %ld, ret: %d, retval: %lu, buf:\n%s\n",
                                SCARG((struct sys_read_args *)uap, fd),
                                SCARG((struct sys_read_args *)uap, nbyte),
                                ret, *retval,
                                (const char *)SCARG((struct sys_read_args *)uap, buf));
#endif
	return ret;
#else
	return 0;
#endif
}

int rumpuser_fsdom_fcntl(struct lwp *l, const void *uap, register_t *retval)
{
#ifdef FSDOM_FRONTEND
	int ret;
        syscall_args_t args;
	args.argp = &args;
        args.uap = (void *)uap;
	args.call_id = FCNTL;

	if (SCARG((struct sys_read_args *)uap, fd) < 3) {
                ret = rump_local_syscall(l, uap, retval, FCNTL);
        } else {
		ret = frontend_send(&args, retval);
	}
#ifdef DEBUG
        bmk_printf("FCNTL fd: %d, cmd: %d, arg: %lx, ret: %d, retval: %lu\n",
                                SCARG((struct sys_fcntl_args *)uap, fd),
                                SCARG((struct sys_fcntl_args *)uap, cmd),
                                *(uint64_t *)SCARG((struct sys_fcntl_args *)uap, arg),
                                ret, *retval);
#endif
	return ret;
#else
	return 0;
#endif
}

int rumpuser_fsdom_close(struct lwp *l, const void* uap, register_t *retval)
{
#ifdef FSDOM_FRONTEND
        int ret;
        syscall_args_t args;
	args.argp = &args;
	args.uap = (void *)uap;
        args.call_id = CLOSE;

	if (SCARG((struct sys_read_args *)uap, fd) < 3) {
		ret = rump_local_syscall(l, uap, retval, CLOSE);
        } else {
		ret = frontend_send(&args, retval);
	}

#ifdef DEBUG
	bmk_printf("CLOSE fd: %d, ret: %d, retval: %lu\n",
				SCARG((struct sys_close_args *)uap, fd),
                                ret, *retval);
#endif
        return ret;
#else
	return 0;
#endif
}
