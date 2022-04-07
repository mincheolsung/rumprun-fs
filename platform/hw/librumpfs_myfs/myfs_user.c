#include <bmk-rumpuser/rumpuser.h>
#include <bmk-rumpuser/core_types.h>
#include <bmk-core/printf.h>
#include <bmk-core/string.h>

#include <xen/fs.h>
#include <xen/fs_syscall.h>

#include "myfs.h"

#include <stdatomic.h>

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
	args.uap = (void *)uap;
        args.call_id = OPEN;

	bmk_printf("rump_fsdom_open1 path: %s, flags: %d, mode: %d, ret: %d, retval: %lu\n",
				SCARG((struct sys_open_args *)uap, path),
				SCARG((struct sys_open_args *)uap, flags),
				SCARG((struct sys_open_args *)uap, mode),
                                ret, *retval);

        ret = frontend_send(&args, retval);
        bmk_printf("rump_fsdom_open2 ret: %d, retval: %ld\n", ret, *retval);

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
	args.uap = (void *)uap;
        args.call_id = READ;

	bmk_printf("rump_fsdom_read1 fd: %d, buf: %s, nbyte: %ld, ret: %d, retval: %lu\n",
				SCARG((struct sys_read_args *)uap, fd),
				(char *)SCARG((struct sys_read_args *)uap, buf),
				SCARG((struct sys_read_args *)uap, nbyte),
                                ret, *retval);


        ret = frontend_send(&args, retval);
        bmk_printf("rump_fsdom_read2 ret: %d, retval: %ld\n", ret, *retval);

	return ret;
#else
	return 0;
#endif
}

int rumpuser_fsdom_write(struct lwp *l, const void *uap, register_t *retval)
{
#ifdef FSDOM_FRONTEND
        syscall_args_t args;
        args.uap = (void *)uap;
	args.call_id = WRITE;

        return frontend_send(&args, retval);
#else
	return 0;
#endif
}

int rumpuser_fsdom_fcntl(struct lwp *l, const void *uap, register_t *retval)
{
#ifdef FSDOM_FRONTEND
        syscall_args_t args;
        args.uap = (void *)uap;
	args.call_id = FCNTL;

        return frontend_send(&args, retval);
#else
	return 0;
#endif
}

int rumpuser_fsdom_close(struct lwp *l, const void* uap, register_t *retval)
{
#ifdef FSDOM_FRONTEND
        //return frontend_send((void *)uap, retval);
        return 0;
#else
	return 0;
#endif
}

file_t *rumpuser_fd_getfile(unsigned fd)
{
        bmk_printf("rumpuser_fd_getfile(%u)\n", fd);
        return rump_fd_getfile(fd);
}
