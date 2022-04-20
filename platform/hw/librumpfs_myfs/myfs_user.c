#include <bmk-rumpuser/rumpuser.h>
#include <bmk-rumpuser/core_types.h>
#include <bmk-core/printf.h>
#include <bmk-core/string.h>
#include <bmk-core/core.h>

#include <xen/fs.h>
#include <xen/fs_syscall.h>

#include "myfs.h"

#include <stdatomic.h>

//#define DEBUG

#ifndef FSDOM_FRONTEND /* backend */
void(*rumpuser_fsdom_init)(void) = backend_init;
void(*rumpuser_fsdom_send)(void *) = backend_send;

#else /* frontend */
#define NDFILE 20
static int rumpuser_fsdom_fds[NDFILE] = {0};
void(*rumpuser_fsdom_init)(void) = frontend_init;

int rumpuser_fsdom_open(struct lwp *l, const void *uap, register_t *retval)
{
        int ret;
        syscall_args_t args;
	args.argp = &args;
	args.uap = (void *)uap;
        args.call_id = OPEN;

        ret = frontend_send(&args, retval);
#ifdef DEBUG
	bmk_printf("OPEN path: %s, flags: %d, mode: %d, ret: %d, retval: %ld\n",
				SCARG((struct sys_open_args *)uap, path),
				SCARG((struct sys_open_args *)uap, flags),
				SCARG((struct sys_open_args *)uap, mode),
                                ret, *retval);
#endif
        return ret;
}

int rumpuser_fsdom_read(struct lwp *l, const void *uap, register_t *retval)
{
        int ret;
	int fd;
        syscall_args_t args;
	args.argp = &args;
	args.uap = (void *)uap;
        args.call_id = READ;

	fd = SCARG((struct sys_read_args *)uap, fd);
	bmk_assert(fd < NDFILE);

	if (rumpuser_fsdom_fds[fd]) {
		ret = rump_local_syscall(l, uap, retval, READ);
	} else {
		ret = frontend_send(&args, retval);
	}
#ifdef DEBUG
	bmk_printf("READ fd: %d, nbyte: %ld, ret: %d, retval: %ld, buf:\n%s\n",
				SCARG((struct sys_read_args *)uap, fd),
				SCARG((struct sys_read_args *)uap, nbyte),
                                ret, *retval,
				(char *)SCARG((struct sys_read_args *)uap, buf));
#endif
	return ret;
}

int rumpuser_fsdom_write(struct lwp *l, const void *uap, register_t *retval)
{
        int ret;
	int fd;
        syscall_args_t args;
	args.argp = &args;
        args.uap = (void *)uap;
	args.call_id = WRITE;

	fd = SCARG((struct sys_write_args *)uap, fd);
        bmk_assert(fd < NDFILE);

	if (rumpuser_fsdom_fds[fd]) {
                ret = rump_local_syscall(l, uap, retval, WRITE);
        } else {
		ret = frontend_send(&args, retval);
	}
#ifdef DEBUG
        bmk_printf("WRITE fd: %d, nbyte: %ld, ret: %d, retval: %ld, buf:\n%s\n",
                                SCARG((struct sys_write_args *)uap, fd),
                                SCARG((struct sys_write_args *)uap, nbyte),
                                ret, *retval,
                                (const char *)SCARG((struct sys_write_args *)uap, buf));
#endif
	return ret;
}

int rumpuser_fsdom_fcntl(struct lwp *l, const void *uap, register_t *retval)
{
	int ret;
	int fd;
        syscall_args_t args;
	args.argp = &args;
        args.uap = (void *)uap;
	args.call_id = FCNTL;

	fd = SCARG((struct sys_fcntl_args *)uap, fd);
        bmk_assert(fd < NDFILE);

	if (rumpuser_fsdom_fds[fd]) {
                ret = rump_local_syscall(l, uap, retval, FCNTL);
        } else {
		ret = frontend_send(&args, retval);
	}
#ifdef DEBUG
        bmk_printf("FCNTL fd: %d, cmd: %d, arg: %lx, ret: %d, retval: %ld\n",
                                SCARG((struct sys_fcntl_args *)uap, fd),
                                SCARG((struct sys_fcntl_args *)uap, cmd),
                                *(uint64_t *)SCARG((struct sys_fcntl_args *)uap, arg),
                                ret, *retval);
#endif
	return ret;
}

int rumpuser_fsdom_close(struct lwp *l, const void* uap, register_t *retval)
{
        int ret;
	int fd;
        syscall_args_t args;
	args.argp = &args;
	args.uap = (void *)uap;
        args.call_id = CLOSE;

	fd = SCARG((struct sys_close_args *)uap, fd);
        bmk_assert(fd < NDFILE);

	if (rumpuser_fsdom_fds[fd]) {
		ret = rump_local_syscall(l, uap, retval, CLOSE);
        } else {
		ret = frontend_send(&args, retval);
	}

#ifdef DEBUG
	bmk_printf("CLOSE fd: %d, ret: %d, retval: %ld\n",
				SCARG((struct sys_close_args *)uap, fd), ret, *retval);
#endif
        return ret;
}

int rumpuser_fsdom_lseek(struct lwp *l, const void *uap, register_t *retval)
{
        int ret;
	int fd;
        syscall_args_t args;
	args.argp = &args;
	args.uap = (void *)uap;
        args.call_id = LSEEK;

	fd = SCARG((struct sys_lseek_args *)uap, fd);
        bmk_assert(fd < NDFILE);

	if (rumpuser_fsdom_fds[fd]) {
		ret = rump_local_syscall(l, uap, retval, LSEEK);
        } else {
		ret = frontend_send(&args, retval);
	}
#ifdef DEBUG
	bmk_printf("LSEEK fd: %d, PAD: %d, offset: %ld, whence: %d, ret: %d, retval: %ld\n",
				SCARG((struct sys_lseek_args *)uap, fd),
				SCARG((struct sys_lseek_args *)uap, PAD),
				SCARG((struct sys_lseek_args *)uap, offset),
				SCARG((struct sys_lseek_args *)uap, whence),
                                ret, *retval);
#endif
        return ret;
}

int rumpuser_fsdom_fsync(struct lwp *l, const void *uap, register_t *retval)
{
        int ret;
	int fd;
        syscall_args_t args;
	args.argp = &args;
	args.uap = (void *)uap;
        args.call_id = FSYNC;

	fd = SCARG((struct sys_fsync_args *)uap, fd);
        bmk_assert(fd < NDFILE);

        if (rumpuser_fsdom_fds[fd]) {
		ret = rump_local_syscall(l, uap, retval, FSYNC);
        } else {
		ret = frontend_send(&args, retval);
	}
#ifdef DEBUG
	bmk_printf("FSYNC fd: %d, ret: %d, retval: %ld\n",
				SCARG((struct sys_fsync_args *)uap, fd), ret, *retval);
#endif
        return ret;
}

int rumpuser_fsdom_setfd(int fd)
{
#ifdef DEBUG
	bmk_printf("rumpuser_fsdom_setfd: %d\n", fd);
#endif
	if (fd >= NDFILE) {
		bmk_printf("rumpuser_fsdom_socreate: %d >= NDFILE\n", fd);
		return -1;
	}

	if (rumpuser_fsdom_fds[fd] != 0) {
		bmk_printf("rumpuser_fsdom_setfd: fd(%d) is not available\n", fd);
		return -1;
	}

	rumpuser_fsdom_fds[fd] = 1;
#if 0
	int i;
	for (i = 0; i < NDFILE; i++) {
		bmk_printf("%d: %d\n", i, rumpuser_fsdom_fds[i]);
	}
#endif
	return 0;
}

int rumpuser_fsdom_removefd(int fd)
{
#ifdef DEBUG
	bmk_printf("rumpuser_fsdom_removefd: %d\n", fd);
#endif
	if (fd >= NDFILE) {
		bmk_printf("rumpuser_fsdom_socreate: %d >= NDFILE\n", fd);
		return -1;
	}

	if (rumpuser_fsdom_fds[fd] != 1) {
		bmk_printf("rumpuser_fsdom_removefd: fd(%d) does not exists\n", fd);
		return -1;
	}

	rumpuser_fsdom_fds[fd] = 0;

	return 0;
}
#endif // FSDOM_FRONTEND
