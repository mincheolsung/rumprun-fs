//#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/systm.h>
#include <sys/syscallargs.h>

#include "myfs.h"

filedesc_t *fdesc;

#ifdef FSDOM_FRONTEND
// frontend
file_t *rump_fd_getfile(unsigned fd)
{
        aprint_normal("rump_fd_getfile(%u)\n", fd);
        return fd_getfile(fd);
}
/*
void rump_init_fdesc(void)
{
        aprint_normal("rump_init_fdesc\n");
        fdesc = fd_init(NULL);
}
*/

int rump_fsdom_open(struct lwp *l, const void *uap, register_t *retval)
{
        //aprint_normal("rump_fsdom_open\n");
        return sys_open(l, (const struct sys_open_args *)uap, retval);
}

int rump_fsdom_read(struct lwp *l, const void *uap, register_t *retval)
{
        //aprint_normal("rump_fsdom_read\n");
        return sys_read(l,(const struct sys_read_args *) uap, retval);
}
int rump_fsdom_write(struct lwp *l, const void *uap, register_t *retval)
{
        //aprint_normal("rump_fsdom_write\n");
        return sys_write(l, (const struct sys_write_args *)uap, retval);
}
int rump_fsdom_close(struct lwp *l, const void *uap, register_t *retval)
{
        //aprint_normal("rump_fsdom_close\n");
        return sys_close(l, (const struct sys_close_args *)uap, retval);
}

#else
// backend
file_t *rump_fd_getfile(unsigned fd)
{
	aprint_normal("rump_fd_getfile(%u)\n", fd);
	return NULL;
	//return fd_getfile(fd);
}

int rump_fsdom_open(const char * path, int flags, mode_t mode, register_t *retval)
{
	aprint_normal("rump_fsdom_open\n");

        /* {
	 *	syscallarg(const char *) path;
	 *     	syscallarg(int) flags;
	 *      syscallarg(int) mode;
	} */

	struct sys_open_args syscall_args;
	memset(&syscall_args, 0, sizeof(struct sys_open_args));
	SCARG(&syscall_args, path) = path;
	SCARG(&syscall_args, flags) = flags;
	SCARG(&syscall_args, mode) = mode;

	return sys_open(curlwp, &syscall_args, retval);
}

int rump_fsdom_read(int fd, void *buf, size_t nbyte, register_t *retval)
{
	aprint_normal("rump_fsdom_read\n");

	/* {
	 *	syscallarg(int) fd;
	 *     	syscallarg(void) buf;
	 *      syscallarg(size_t) nbyte;
	} */

	struct sys_read_args syscall_args;
	memset(&syscall_args, 0, sizeof(struct sys_read_args));
	SCARG(&syscall_args, fd) = fd;
	SCARG(&syscall_args, buf) = buf;
	SCARG(&syscall_args, nbyte) = nbyte;

	return sys_read(curlwp, &syscall_args, retval);
}

int rump_fsdom_write(struct lwp *l, const void *uap, register_t *retval)
{
	aprint_normal("rump_fsdom_write\n");
	/* {
	 *	syscallarg(int) fd;
	 *     	syscallarg(const void) buf;
	 *      syscallarg(size_t) nbyte;
	} */
	return sys_write(l, (const struct sys_write_args *)uap, retval);
}

int rump_fsdom_close(struct lwp *l, const void *uap, register_t *retval)
{
	aprint_normal("rump_fsdom_close\n");
	return sys_close(l, (const struct sys_close_args *)uap, retval);
}

int rump_fsdom_fcntl(int fd, int cmd, void *arg, register_t *retval)
{
	aprint_normal("rump_fsdom_read\n");

	/* {
	 *	syscallarg(int) fd;
	 *     	syscallarg(int) cmd;
	 *      syscallarg(void *) arg;
	} */

	struct sys_fcntl_args syscall_args;
	memset(&syscall_args, 0, sizeof(struct sys_fcntl_args));
	SCARG(&syscall_args, fd) = fd;
	SCARG(&syscall_args, cmd) = cmd;
	SCARG(&syscall_args, arg) = arg;

	return sys_fcntl(curlwp, &syscall_args, retval);
}
#endif
