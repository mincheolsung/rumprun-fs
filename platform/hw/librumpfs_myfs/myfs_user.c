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
#define NDFILE 1024

struct fd_entry {
	int l_fd; // local fd
	int r_fd; // remote fd
};
static struct fd_entry fd_table[NDFILE];

static int find_idx(int l_fd)
{
	int i;
	for (i = 0; i < NDFILE; i++) {
		if (fd_table[i].l_fd == l_fd) {
			return i;
		}
	}

	return -1;
}

static int get_free_idx(int fd)
{
	int i;

	for (i = 0; i < NDFILE; i++) {
		if (fd_table[i].l_fd == -1) {
			return i;
		}
	}

	return -1;
}

static int get_remote_fd(int l_fd)
{
	int i;
	for (i = 0; i < NDFILE; i++) {
		if (fd_table[i].l_fd == l_fd) {
			/* return -1 if fd is local */
			return fd_table[i].r_fd;
		}
	}

	return -2;
}

void rumpuser_fsdom_init_fd_table(void)
{
	int i;
	for (i = 0; i < NDFILE; i++) {
		fd_table[i].l_fd = -1;
		fd_table[i].r_fd = -1;
	}
}
/*
static void printf_fdtbl(void)
{
	int i;
	for (i = 0; i < NDFILE; i++) {
		if (fd_table[i].l_fd != -1 || fd_table[i].r_fd != -1) {
			bmk_printf("[%d] l_fd: %d, r_fd: %d\n", i,
				fd_table[i].l_fd, fd_table[i].r_fd);
		}
	}
}
*/
int rumpuser_fsdom_setfd(int l_fd, int r_fd)
{
	struct fd_entry *new_fd;
	int idx;

	//bmk_printf("rumpuser_fsdom_setfd: %d, %d\n", l_fd, r_fd);

	idx = find_idx(l_fd);
	if (idx == -1) {
		/* if l_fd not exists, find an available one */
		idx = get_free_idx(l_fd);
		if (idx == -1) {
			bmk_printf("fd_table is full\n");
			/* EMFILE 24 */
			return 24;
		}
	}

	new_fd = &fd_table[idx];

	new_fd->l_fd = l_fd;
	new_fd->r_fd = r_fd;

	//printf_fdtbl();

	return 0;
}

int rumpuser_fsdom_removefd(int l_fd)
{
	struct fd_entry *target_fd;
	int idx;

	//bmk_printf("rumpuser_fsdom_removefd: %d\n", l_fd);

	idx = find_idx(l_fd);
	if (idx == -1) {
		bmk_printf("%d not found\n", l_fd);
		return 22;
	}

	target_fd = &fd_table[idx];
	target_fd->l_fd = -1;
	target_fd->r_fd = -1;

	return 0;
}

void(*rumpuser_fsdom_init)(void) = frontend_init;

int rumpuser_fsdom_open(struct lwp *l, const void *uap, register_t *retval)
{
        int ret, l_fd, r_fd;
        syscall_args_t args;
	args.argp = &args;
	args.uap = (void *)uap;
        args.call_id = OPEN;

        ret = frontend_send(&args, retval);
	if (ret) {
		return ret;
	}

	r_fd = *retval;
	*retval = 0;

	ret = rump_fsdom_fd_alloc(&l_fd);
	if (ret) {
		return ret;
	}

	ret = rumpuser_fsdom_setfd(l_fd, r_fd);
	if (ret) {
		return ret;
	}

	*retval = l_fd;

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
	int l_fd, r_fd;
        syscall_args_t args;
	args.argp = &args;
	args.uap = (void *)uap;
        args.call_id = READ;

	l_fd = SCARG((struct sys_read_args *)uap, fd);

	if ((r_fd = get_remote_fd(l_fd)) == -1) {
		ret = rump_local_syscall(l, uap, retval, READ);
	} else if (r_fd == -2) {
		bmk_printf("fails to find remote fd\n");
	} else {
		SCARG((struct sys_read_args *)uap, fd) = r_fd;
		ret = frontend_send(&args, retval);
	}
#ifdef DEBUG
	bmk_printf("%s READ fd: %d, nbyte: %ld, ret: %d, retval: %ld\n",
				r_fd == -1 ? "Local" : "Remote",
				SCARG((struct sys_read_args *)uap, fd),
				SCARG((struct sys_read_args *)uap, nbyte),
                                ret, *retval);
				//(char *)SCARG((struct sys_read_args *)uap, buf));
#endif
	return ret;
}

int rumpuser_fsdom_write(struct lwp *l, const void *uap, register_t *retval)
{
        int ret;
	int l_fd, r_fd;
        syscall_args_t args;
	args.argp = &args;
        args.uap = (void *)uap;
	args.call_id = WRITE;

	l_fd = SCARG((struct sys_write_args *)uap, fd);

	if ((r_fd = get_remote_fd(l_fd)) == -1) {
                ret = rump_local_syscall(l, uap, retval, WRITE);
	} else if (r_fd == -2) {
		bmk_printf("fails to find remote fd\n");
        } else {
		SCARG((struct sys_write_args *)uap, fd) = r_fd;
		ret = frontend_send(&args, retval);
	}

#ifdef DEBUG
        bmk_printf("%s WRITE fd: %d, nbyte: %ld, ret: %d, retval: %ld\n",
				r_fd == -1 ? "Local" : "Remote",
                                SCARG((struct sys_write_args *)uap, fd),
                                SCARG((struct sys_write_args *)uap, nbyte),
                                ret, *retval);
                                //(const char *)SCARG((struct sys_write_args *)uap, buf));
#endif
	return ret;
}

int rumpuser_fsdom_fcntl(struct lwp *l, const void *uap, register_t *retval)
{
	int ret;
	int l_fd, r_fd;
        syscall_args_t args;
	args.argp = &args;
        args.uap = (void *)uap;
	args.call_id = FCNTL;

	l_fd = SCARG((struct sys_fcntl_args *)uap, fd);

	if ((r_fd = get_remote_fd(l_fd)) == -1) {
                ret = rump_local_syscall(l, uap, retval, FCNTL);
	} else if ( r_fd == -2) {
		bmk_printf("fails to find remote fd\n");
        } else {
		SCARG((struct sys_fcntl_args *)uap, fd) = r_fd;
		ret = frontend_send(&args, retval);
	}
/*
	bmk_printf("FCNTL fd:%d\n", SCARG((struct sys_fcntl_args *)uap, fd));
	bmk_printf("     cmd:%d\n", SCARG((struct sys_fcntl_args *)uap, cmd));
	bmk_printf("     arg:%p\n", SCARG((struct sys_fcntl_args *)uap, arg));
	bmk_printf("     ret:%d\n", ret);
	bmk_printf("  retval:%ld\n", *retval);
*/
#ifdef DEBUG
        bmk_printf("%s FCNTL fd: %d, cmd: %d, ret: %d, retval: %ld\n",
				r_fd == -1 ? "Local" : "Remote",
                                SCARG((struct sys_fcntl_args *)uap, fd),
                                SCARG((struct sys_fcntl_args *)uap, cmd),
                                //*(uint64_t *)SCARG((struct sys_fcntl_args *)uap, arg),
                                ret, *retval);
#endif
	return ret;
}

int rumpuser_fsdom_close(struct lwp *l, const void* uap, register_t *retval)
{
        int ret, l_fd, r_fd;
        syscall_args_t args;
	args.argp = &args;
	args.uap = (void *)uap;
        args.call_id = CLOSE;

	l_fd = SCARG((struct sys_close_args *)uap, fd);

	if ((r_fd = get_remote_fd(l_fd)) == -1) {
		ret = rump_local_syscall(l, uap, retval, CLOSE);
		//bmk_printf("close local %d\n", l_fd);
	} else if (r_fd == -2) {
		bmk_printf("fails to find remote fd\n");
        } else {
                SCARG((struct sys_close_args *)uap, fd) = r_fd;
		ret = frontend_send(&args, retval);
		//bmk_printf("close remote %d\n", r_fd);
		if (ret == 0) {
			rump_fsdom_fd_abort(l_fd);
		}
	}

#ifdef DEBUG
	bmk_printf("%s CLOSE fd: %d, ret: %d, retval: %ld\n",
				r_fd == -1 ? "Local" : "Remote",
				SCARG((struct sys_close_args *)uap, fd), ret, *retval);
#endif
        return ret;
}

int rumpuser_fsdom_lseek(struct lwp *l, const void *uap, register_t *retval)
{
        int ret;
	int l_fd, r_fd;
        syscall_args_t args;
	args.argp = &args;
	args.uap = (void *)uap;
        args.call_id = LSEEK;

	l_fd = SCARG((struct sys_lseek_args *)uap, fd);

	if ((r_fd = get_remote_fd(l_fd)) == -1) {
		ret = rump_local_syscall(l, uap, retval, LSEEK);
	} else if (r_fd == -2) {
		bmk_printf("fails to find remote fd\n");
        } else {
                SCARG((struct sys_lseek_args *)uap, fd) = r_fd;
		ret = frontend_send(&args, retval);
	}
#ifdef DEBUG
	bmk_printf("%s LSEEK fd: %d, offset: %ld, whence: %d, ret: %d, retval: %ld\n",
				r_fd == -1 ? "Local" : "Remote",
				SCARG((struct sys_lseek_args *)uap, fd),
				SCARG((struct sys_lseek_args *)uap, offset),
				SCARG((struct sys_lseek_args *)uap, whence),
                                ret, *retval);
#endif
        return ret;
}

int rumpuser_fsdom_fsync(struct lwp *l, const void *uap, register_t *retval)
{
        int ret;
	int l_fd, r_fd;
        syscall_args_t args;
	args.argp = &args;
	args.uap = (void *)uap;
        args.call_id = FSYNC;

	l_fd = SCARG((struct sys_fsync_args *)uap, fd);

	if ((r_fd = get_remote_fd(l_fd)) == -1) {
		ret = rump_local_syscall(l, uap, retval, FSYNC);
	} else if (r_fd == -2) {
		bmk_printf("fails to find remote fd\n");
        } else {
		SCARG((struct sys_fsync_args *)uap, fd) = r_fd;
		ret = frontend_send(&args, retval);
	}
#ifdef DEBUG
	bmk_printf("%s FSYNC fd: %d, ret: %d, retval: %ld\n",
				r_fd == -1 ? "Local" : "Remote",
				SCARG((struct sys_fsync_args *)uap, fd), ret, *retval);
#endif
        return ret;
}

int rumpuser_fsdom_fstat(struct lwp *l, const void *uap, register_t *retval)
{
        int ret;
	int l_fd, r_fd;
        syscall_args_t args;
        args.argp = &args;
        args.uap = (void *)uap;
        args.call_id = FSTAT;

	l_fd = SCARG((struct sys___fstat50_args *)uap, fd);

	if ((r_fd = get_remote_fd(l_fd)) == -1) {
		ret = rump_local_syscall(l, uap, retval, FSTAT);
	} else if (r_fd == -2) {
		bmk_printf("fails to find remote fd\n");
        } else {
		SCARG((struct sys___fstat50_args *)uap, fd) = r_fd;
		ret = frontend_send(&args, retval);
	}
#ifdef DEBUG
        bmk_printf("%s FSTAT fd: %d, sb: %p, ret: %d, retval: %ld\n",
				r_fd == -1 ? "Local" : "Remote",
				SCARG((struct sys___fstat50_args *)uap, fd),
				SCARG((struct sys___fstat50_args *)uap, sb),
				ret, *retval);
#endif
        return ret;
}

int rumpuser_fsdom_stat(struct lwp *l, const void *uap, register_t *retval)
{
        int ret;
        syscall_args_t args;
        args.argp = &args;
        args.uap = (void *)uap;
        args.call_id = STAT;

        ret = frontend_send(&args, retval);

#ifdef DEBUG
        bmk_printf("STAT ret: %d, retval: %ld\n",
				ret, *retval);
#endif
        return ret;
}

int rumpuser_fsdom_lstat(struct lwp *l, const void *uap, register_t *retval)
{
        int ret;
        syscall_args_t args;
        args.argp = &args;
        args.uap = (void *)uap;
        args.call_id = LSTAT;

        ret = frontend_send(&args, retval);

#ifdef DEBUG
        bmk_printf("LSTAT ret: %d, retval: %ld\n",
				ret, *retval);
#endif
        return ret;
}

int rumpuser_fsdom_statvfs1(struct lwp *l, const void *uap, register_t *retval)
{
        int ret;
        syscall_args_t args;
        args.argp = &args;
        args.uap = (void *)uap;
        args.call_id = STATVFS1;

        ret = frontend_send(&args, retval);

#ifdef DEBUG
        bmk_printf("STATVFS1 ret: %d, retval: %ld\n",
				ret, *retval);
#endif
        return ret;
}

int rumpuser_fsdom_pread(struct lwp *l, const void *uap, register_t *retval)
{
        int ret;
	int l_fd, r_fd;
        syscall_args_t args;
	args.argp = &args;
	args.uap = (void *)uap;
        args.call_id = PREAD;

	l_fd = SCARG((struct sys_pread_args *)uap, fd);

	if ((r_fd = get_remote_fd(l_fd)) == -1) {
		ret = rump_local_syscall(l, uap, retval, PREAD);
	} else if (r_fd == -2) {
		bmk_printf("fails to find remote fd\n");
	} else {
		SCARG((struct sys_pread_args *)uap, fd) = r_fd;
		ret = frontend_send(&args, retval);
	}
#ifdef DEBUG
	bmk_printf("%s PREAD fd: %d, nbyte: %ld, offset: %ld, ret: %d, retval: %ld\n",
				r_fd == -1 ? "Local" : "Remote",
				SCARG((struct sys_pread_args *)uap, fd),
				SCARG((struct sys_pread_args *)uap, nbyte),
				SCARG((struct sys_pread_args *)uap, offset),
                                ret, *retval);
#endif
	return ret;
}

int rumpuser_fsdom_pwrite(struct lwp *l, const void *uap, register_t *retval)
{
        int ret;
	int l_fd, r_fd;
        syscall_args_t args;
	args.argp = &args;
	args.uap = (void *)uap;
        args.call_id = PWRITE;

	l_fd = SCARG((struct sys_pwrite_args *)uap, fd);

	if ((r_fd = get_remote_fd(l_fd)) == -1) {
		ret = rump_local_syscall(l, uap, retval, PWRITE);
	} else if (r_fd == -2) {
		bmk_printf("fails to find remote fd\n");
	} else {
		SCARG((struct sys_pwrite_args *)uap, fd) = r_fd;
		ret = frontend_send(&args, retval);
	}
#ifdef DEBUG
	bmk_printf("%s PWRITE fd: %d, nbyte: %ld, offset: %ld, ret: %d, retval: %ld\n",
				r_fd == -1 ? "Local" : "Remote",
				SCARG((struct sys_pwrite_args *)uap, fd),
				SCARG((struct sys_pwrite_args *)uap, nbyte),
				SCARG((struct sys_pwrite_args *)uap, offset),
                                ret, *retval);
#endif
	return ret;
}

int rumpuser_fsdom_access(struct lwp *l, const void *uap, register_t *retval)
{
        int ret;
        syscall_args_t args;
        args.argp = &args;
        args.uap = (void *)uap;
        args.call_id = ACCESS;

        ret = frontend_send(&args, retval);

#ifdef DEBUG
        bmk_printf("ACCESS ret: %d, retval: %ld\n",
				ret, *retval);
#endif
        return ret;
}

int rumpuser_fsdom_mkdir(struct lwp *l, const void *uap, register_t *retval)
{
        int ret;
        syscall_args_t args;
        args.argp = &args;
        args.uap = (void *)uap;
        args.call_id = MKDIR;

        ret = frontend_send(&args, retval);

#ifdef DEBUG
        bmk_printf("MKDIR ret: %d, retval: %ld\n",
				ret, *retval);
#endif
        return ret;
}

int rumpuser_fsdom_chown(struct lwp *l, const void *uap, register_t *retval)
{
        int ret;
        syscall_args_t args;
        args.argp = &args;
        args.uap = (void *)uap;
        args.call_id = CHOWN;

        ret = frontend_send(&args, retval);

#ifdef DEBUG
        bmk_printf("CHOWN ret: %d, retval: %ld\n",
				ret, *retval);
#endif
        return ret;
}

int rumpuser_fsdom_dup2(struct lwp *l, const void *uap, register_t *retval)
{
        int ret;
        int from, to, r_fd;
        syscall_args_t args;
        args.argp = &args;
        args.uap = (void *)uap;

        from = SCARG((struct sys_dup2_args *)uap, from);
        to = SCARG((struct sys_dup2_args *)uap, to);

        if ((r_fd = get_remote_fd(from)) == -1) {
                ret = rump_local_syscall(l, uap, retval, DUP2);
		if (ret) {
			return ret;
		}
		ret = rumpuser_fsdom_setfd(from, -1);
		if (ret) {
			return ret;
		}
        } else if (r_fd == -2) {
                bmk_printf("oldfd is invalid\n");
		return 9; /* EBADF */
        } else {
		ret = rumpuser_fsdom_setfd(to, r_fd);
		if (ret) {
			return ret;
		}
		*retval	= to;
        }

#ifdef DEBUG
        bmk_printf("DUP2 from: %d, to: %d, ret: %d, retval: %ld\n",
                                SCARG((struct sys_dup2_args *)uap, from),
                                SCARG((struct sys_dup2_args *)uap, to),
                                ret, *retval);
#endif

	//printf_fdtbl();
        return ret;
}

#endif // FSDOM_FRONTEND
