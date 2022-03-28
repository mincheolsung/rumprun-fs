#include <bmk-rumpuser/rumpuser.h>
#include <bmk-rumpuser/core_types.h>
#include <bmk-core/printf.h>
#include <bmk-core/string.h>

#include <xen/fs.h>
#include <xen/fs_syscall.h>

#include "myfs_user.h"
#include "myfs.h"

#include <stdatomic.h>

#ifdef FSDOM_FRONTEND
void rumpuser_fsdom_init(void)
{
        frontend_init();
}

int rumpuser_fsdom_open(struct lwp *l, const void *uap, register_t *retval)
{
        /* {
                syscallarg(const char *) path;
                syscallarg(int)          flags;
                syscallarg(int)          mode;
        } */
        int ret;
        syscall_args_t args;
        bmk_memset(&args, 0, sizeof(args));
        args.arg[0] = (uint64_t)SCARG((struct sys_open_args *)uap, path);
        args.arg[1] = (uint64_t)SCARG((struct sys_open_args *)uap, flags);
        args.arg[2] = (uint64_t)SCARG((struct sys_open_args *)uap, mode);
        args.call_id = OPEN;

        ret = frontend_syscall(&args, retval);
        bmk_printf("ret: %d, retval: %ld\n", ret, *retval);

        return ret;
}

int rumpuser_fsdom_read(struct lwp *l, const void *uap, register_t *retval)
{
        /* {
                syscallarg(int)          fd;
                syscallarg(void *)       buf;
                syscallarg(size_t)       nbyte;
        } */

        syscall_args_t args;
        bmk_memset(&args, 0, sizeof(args));
        args.arg[0] = (uint64_t)SCARG((struct sys_read_args *)uap, fd);
        args.arg[1] = (uint64_t)SCARG((struct sys_read_args *)uap, buf);
        args.arg[2] = (uint64_t)SCARG((struct sys_read_args *)uap, nbyte);
        args.call_id = READ;

        return frontend_syscall(&args, retval);
}

int rumpuser_fsdom_write(struct lwp *l, const void *uap, register_t *retval)
{
        /* {
                syscallarg(int)          fd;
                syscallarg(void *)       buf;
                syscallarg(size_t)       nbyte;
        } */

        syscall_args_t args;
        bmk_memset(&args, 0, sizeof(args));
        args.arg[0] = (uint64_t)SCARG((struct sys_write_args *)uap, fd);
        args.arg[1] = (uint64_t)SCARG((struct sys_write_args *)uap, buf);
        args.arg[2] = (uint64_t)SCARG((struct sys_write_args *)uap, nbyte);
        args.call_id = WRITE;

        return frontend_syscall(&args, retval);
}

int rumpuser_fsdom_fcntl(struct lwp *l, const void *uap, register_t *retval)
{
        /* {
                syscallarg(int)         fd;
                syscallarg(int)         cmd;
                syscallarg(void *)      arg;
        } */

        syscall_args_t args;
        bmk_memset(&args, 0, sizeof(args));
        args.arg[0] = (uint64_t)SCARG((struct sys_fcntl_args *)uap, fd);
        args.arg[1] = (uint64_t)SCARG((struct sys_fcntl_args *)uap, cmd);
        args.arg[2] = (uint64_t)SCARG((struct sys_fcntl_args *)uap, arg);
        args.call_id = FCNTL;

        return frontend_syscall(&args, retval);
}

int rumpuser_fsdom_close(struct lwp *l, const void* uap, register_t *retval)
{
        /* {
                syscallarg(int) fd;
        } */

        //bmk_printf("rumpuser_fsdom_close\n");
        return rump_fsdom_close(l, uap, retval);
}

file_t *rumpuser_fd_getfile(unsigned fd)
{
        bmk_printf("rumpuser_fd_getfile(%u)\n", fd);
        return rump_fd_getfile(fd);
}

#else
void rumpuser_fsdom_init(void)
{
	backend_init();
}

int rumpuser_fsdom_open(struct lwp *l, const void *uap, register_t *retval)
{
	//bmk_printf("rumpuser_fsdom_open\n");
	//return rump_fsdom_open(l, uap, retval);
	return 0;
}

int rumpuser_fsdom_read(struct lwp *l, const void *uap, register_t *retval)
{
	//bmk_printf("rumpuser_fsdom_read\n");
	//return rump_fsdom_read(l, uap, retval);
	return 0;
}

int rumpuser_fsdom_write(struct lwp *l, const void *uap, register_t *retval)
{
	//bmk_printf("rumpuser_fsdom_write\n");
	//return rump_fsdom_write(l, uap, retval);
	return 0;
}

int rumpuser_fsdom_close(struct lwp *l, const void* uap, register_t *retval)
{
	//bmk_printf("rumpuser_fsdom_close\n");
	//return rump_fsdom_close(l, uap, retval);
	return 0;
}

file_t *rumpuser_fd_getfile(unsigned fd)
{
	//bmk_printf("rumpuser_fd_getfile(%u)\n", fd);
	return rump_fd_getfile(fd);
}
#endif
