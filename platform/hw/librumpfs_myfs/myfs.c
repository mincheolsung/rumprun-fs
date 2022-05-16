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

#ifndef FSDOM_FRONTEND /* backend */
static uint64_t rump_offset;
static struct workqueue *rump_fsdom_workqueue;

static struct lwp *rump_app_lwp_tbl[RUMPRUN_NUM_OF_APPS];
/*
static void *rump_fsdom_switch(struct lwp **new)
{
	struct lwp *old;

	old = curlwp;

	if (*new == NULL) {
		*new = rump__lwproc_alloclwp(NULL);
	}

	rump_lwproc_switch(*new);

	return old;
}
*/
static void rump_fsdom_work(struct work *wk, void *dummy)
{
	int ret;
	//struct lwp *old;
	syscall_args_t *args;
	register_t retval = 0;

	args = (syscall_args_t *)wk;

	KASSERT(args->domid < RUMPRUN_NUM_OF_APPS);
	//old = rump_fsdom_switch(&rump_app_lwp_tbl[args->domid]);

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

		case OPENAT:
		{
			struct sys_openat_args syscall_args;
			struct sys_openat_args *uap = (struct sys_openat_args *)((uint64_t)args->uap + rump_offset);

			SCARG(&syscall_args, fd) = SCARG(uap, fd);
			SCARG(&syscall_args, path) = (char *)((uint64_t)SCARG(uap, path) + rump_offset);
		        SCARG(&syscall_args, oflags) = SCARG(uap, oflags);
			SCARG(&syscall_args, mode) = SCARG(uap, mode);

			ret = sys_openat(curlwp, (const struct sys_openat_args *)&syscall_args, &retval);
//#ifdef DEBUG
			aprint_normal("OPENAT fd: %d, path: %s, oflags: %d, mode: %d, ret: %d, retval: %ld\n",
				SCARG(&syscall_args, fd),
				SCARG(&syscall_args, path),
				SCARG(&syscall_args, oflags),
				SCARG(&syscall_args, mode),
				ret, retval);
//#endif
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
			aprint_normal("READ fd: %d, nbyte: %ld, ret: %d, retval: %ld,  buf:\n%s\n",
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
			SCARG(&syscall_args, offset) = SCARG(uap, offset);
			SCARG(&syscall_args, whence) = SCARG(uap, whence);

			ret = sys_lseek(curlwp, (const struct sys_lseek_args *)&syscall_args, &retval);
#ifdef DEBUG
			aprint_normal("LSEEK fd: %d, offset: %ld, whence: %d, ret: %d, retval: %ld\n",
                                SCARG(&syscall_args, fd),
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

		case FSTAT:
		{
			struct sys___fstat50_args syscall_args;
			struct sys___fstat50_args *uap = (struct sys___fstat50_args *)((uint64_t)args->uap + rump_offset);

			SCARG(&syscall_args, fd) = SCARG(uap, fd);
			SCARG(&syscall_args, sb) = (struct stat *)((uint64_t)SCARG(uap, sb) + rump_offset);

			ret = sys___fstat50(curlwp, (const struct sys___fstat50_args *)&syscall_args, &retval);
#ifdef DEBUG
			aprint_normal("FSTAT fd: %d, sb: %p, ret: %d, retval: %ld\n",
                                SCARG(&syscall_args, fd), SCARG(&syscall_args, sb),
                                ret, retval);
#endif
			break;
		}

		case STAT:
		{
			struct sys___stat50_args syscall_args;
			struct sys___stat50_args *uap = (struct sys___stat50_args *)((uint64_t)args->uap + rump_offset);

			SCARG(&syscall_args, path) = (char *)((uint64_t)SCARG(uap, path) + rump_offset);
			SCARG(&syscall_args, ub) = (struct stat *)((uint64_t)SCARG(uap, ub) + rump_offset);

			ret = sys___stat50(curlwp, (const struct sys___stat50_args *)&syscall_args, &retval);
#ifdef DEBUG
			aprint_normal("STAT path: %s, ub: %p, ret: %d, retval: %ld\n",
                                SCARG(&syscall_args, path), SCARG(&syscall_args, ub),
                                ret, retval);
#endif
			break;
		}

		case LSTAT:
		{
			struct sys___lstat50_args syscall_args;
			struct sys___lstat50_args *uap = (struct sys___lstat50_args *)((uint64_t)args->uap + rump_offset);

			SCARG(&syscall_args, path) = (char *)((uint64_t)SCARG(uap, path) + rump_offset);
			SCARG(&syscall_args, ub) = (struct stat *)((uint64_t)SCARG(uap, ub) + rump_offset);

			ret = sys___lstat50(curlwp, (const struct sys___lstat50_args *)&syscall_args, &retval);
#ifdef DEBUG
			aprint_normal("LSTAT path: %s, ub: %p, ret: %d, retval: %ld\n",
                                SCARG(&syscall_args, path), SCARG(&syscall_args, ub),
                                ret, retval);
#endif
			break;
		}

		case STATVFS1:
		{
			struct sys_statvfs1_args syscall_args;
			struct sys_statvfs1_args *uap = (struct sys_statvfs1_args *)((uint64_t)args->uap + rump_offset);

			SCARG(&syscall_args, path) = (char *)((uint64_t)SCARG(uap, path) + rump_offset);
			SCARG(&syscall_args, buf) = (struct statvfs *)((uint64_t)SCARG(uap, buf) + rump_offset);
		        SCARG(&syscall_args, flags) = SCARG(uap, flags);

			ret = sys_statvfs1(curlwp, (const struct sys_statvfs1_args *)&syscall_args, &retval);
#ifdef DEBUG
			aprint_normal("STATVFS1 path: %s, flags: %d, buf: %p, ret: %d, retval: %ld\n",
                                SCARG(&syscall_args, path),
				SCARG(&syscall_args, flags),
				SCARG(&syscall_args, buf),
                                ret, retval);
#endif
			break;
		}

		case PREAD:
		{
			struct sys_pread_args syscall_args;
			struct sys_pread_args *uap = (struct sys_pread_args *)((uint64_t)args->uap + rump_offset);
			SCARG(&syscall_args, fd) = SCARG(uap, fd);
		        SCARG(&syscall_args, buf) = (void *)((uint64_t)SCARG(uap, buf) + rump_offset);
     			SCARG(&syscall_args, nbyte) = SCARG(uap, nbyte);
     			SCARG(&syscall_args, offset) = SCARG(uap, offset);

			ret = sys_pread(curlwp, (const struct sys_pread_args *)&syscall_args, &retval);
#ifdef DEBUG
			aprint_normal("PREAD fd: %d, nbyte: %ld, offset: %ld, ret: %d, retval: %ld\n",
                                SCARG(&syscall_args, fd),
                                SCARG(&syscall_args, nbyte),
                                SCARG(&syscall_args, offset),
                                ret, retval);
#endif
			break;
		}

		case PWRITE:
		{
			struct sys_pwrite_args syscall_args;
			struct sys_pwrite_args *uap = (struct sys_pwrite_args *)((uint64_t)args->uap + rump_offset);
			SCARG(&syscall_args, fd) = SCARG(uap, fd);
		        SCARG(&syscall_args, buf) = (void *)((uint64_t)SCARG(uap, buf) + rump_offset);
     			SCARG(&syscall_args, nbyte) = SCARG(uap, nbyte);
     			SCARG(&syscall_args, offset) = SCARG(uap, offset);

			ret = sys_pwrite(curlwp, (const struct sys_pwrite_args *)&syscall_args, &retval);
#ifdef DEBUG
			aprint_normal("PWRITE fd: %d, nbyte: %ld, offset: %ld, ret: %d, retval: %ld\n",
                                SCARG(&syscall_args, fd),
                                SCARG(&syscall_args, nbyte),
                                SCARG(&syscall_args, offset),
                                ret, retval);
#endif
			break;
		}

		case ACCESS:
                {
                        struct sys_access_args syscall_args;
                        struct sys_access_args *uap = (struct sys_access_args *)((uint64_t)args->uap + rump_offset);

                        SCARG(&syscall_args, path) = (char *)((uint64_t)SCARG(uap, path) + rump_offset);
                        SCARG(&syscall_args, flags) = SCARG(uap, flags);

                        ret = sys_access(curlwp, (const struct sys_access_args *)&syscall_args, &retval);
#ifdef DEBUG
                        aprint_normal("ACCESS path: %s, flags: %d, ret: %d, retval: %ld\n",
                                SCARG(&syscall_args, path), SCARG(&syscall_args, flags),
                                ret, retval);
#endif
                        break;
                }

		case MKDIR:
                {
                        struct sys_mkdir_args syscall_args;
                        struct sys_mkdir_args *uap = (struct sys_mkdir_args *)((uint64_t)args->uap + rump_offset);

                        SCARG(&syscall_args, path) = (char *)((uint64_t)SCARG(uap, path) + rump_offset);
                        SCARG(&syscall_args, mode) = SCARG(uap, mode);

                        ret = sys_mkdir(curlwp, (const struct sys_mkdir_args *)&syscall_args, &retval);
#ifdef DEBUG
                        aprint_normal("MKDIR path: %s, mode: %d, ret: %d, retval: %ld\n",
                                SCARG(&syscall_args, path), SCARG(&syscall_args, mode),
                                ret, retval);
#endif
                        break;
                }

		case RMDIR:
                {
                        struct sys_rmdir_args syscall_args;
                        struct sys_rmdir_args *uap = (struct sys_rmdir_args *)((uint64_t)args->uap + rump_offset);

                        SCARG(&syscall_args, path) = (char *)((uint64_t)SCARG(uap, path) + rump_offset);

                        ret = sys_rmdir(curlwp, (const struct sys_rmdir_args *)&syscall_args, &retval);
#ifdef DEBUG
                        aprint_normal("RMDIR path: %s, ret: %d, retval: %ld\n",
                                SCARG(&syscall_args, path),
                                ret, retval);
#endif
                        break;
                }

		case CHOWN:
                {
                        struct sys_chown_args syscall_args;
                        struct sys_chown_args *uap = (struct sys_chown_args *)((uint64_t)args->uap + rump_offset);

                        SCARG(&syscall_args, path) = (char *)((uint64_t)SCARG(uap, path) + rump_offset);
                        SCARG(&syscall_args, uid) = SCARG(uap, uid);
                        SCARG(&syscall_args, gid) = SCARG(uap, gid);

                        ret = sys_chown(curlwp, (const struct sys_chown_args *)&syscall_args, &retval);
#ifdef DEBUG
                        aprint_normal("CHOWN path: %s, uid: %u, gid: %u, ret: %d, retval: %ld\n",
                                SCARG(&syscall_args, path),
				SCARG(&syscall_args, uid),
				SCARG(&syscall_args, gid),
                                ret, retval);
#endif
			break;
		}

		case CHDIR:
                {
                        struct sys_chdir_args syscall_args;
                        struct sys_chdir_args *uap = (struct sys_chdir_args *)((uint64_t)args->uap + rump_offset);

                        SCARG(&syscall_args, path) = (char *)((uint64_t)SCARG(uap, path) + rump_offset);

                        ret = sys_chdir(curlwp, (const struct sys_chdir_args *)&syscall_args, &retval);
#ifdef DEBUG
                        aprint_normal("CHDIR path: %s, ret: %d, retval: %ld\n",
                                SCARG(&syscall_args, path),
                                ret, retval);
#endif
                        break;
                }

		case UNLINK:
                {
                        struct sys_unlink_args syscall_args;
                        struct sys_unlink_args *uap = (struct sys_unlink_args *)((uint64_t)args->uap + rump_offset);

                        SCARG(&syscall_args, path) = (char *)((uint64_t)SCARG(uap, path) + rump_offset);

                        ret = sys_unlink(curlwp, (const struct sys_unlink_args *)&syscall_args, &retval);
#ifdef DEBUG
                        aprint_normal("UNLINK path: %s, ret: %d, retval: %ld\n",
                                SCARG(&syscall_args, path),
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

	//rump_fsdom_switch(&old);

	rumpuser_fsdom_send(args);
}

void rump_fsdom_init_workqueue(void)
{
	int error, i;
	if ((error = workqueue_create(&rump_fsdom_workqueue, "fsdoned", \
            rump_fsdom_work, NULL, PRI_VM, IPL_VM, WQ_MPSAFE))) {
		aprint_normal("workqueue_create fails, error: %d\n", error);
	}

	for (i = 0; i < RUMPRUN_NUM_OF_APPS; i++) {
		rump_app_lwp_tbl[i] = NULL;
	}
}

void rump_fsdom_set_offset(uint64_t offset)
{
	rump_offset = offset;
}

void rump_fsdom_enqueue(void *wk)
{
	rump_schedule_cpu(curlwp);
	workqueue_enqueue(rump_fsdom_workqueue, (struct work *)wk, NULL);
	rump_unschedule_cpu(curlwp);
}

#else /* frontend */
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

		case FSTAT:
		{
			ret = sys___fstat50(l, (const struct sys___fstat50_args *)uap, retval);
			break;
		}

		case PREAD:
		{
			ret = sys_pread(l,(const struct sys_pread_args *) uap, retval);
			break;
		}

		case PWRITE:
		{
			ret = sys_pwrite(l, (const struct sys_pwrite_args *)uap, retval);
			break;
		}

		case DUP2:
		{
			ret = sys_dup2(l, (const struct sys_dup2_args *)uap, retval);
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

int rump_fsdom_fd_alloc(int *new_fd)
{
        int error;
        proc_t *p = curproc;

        while ((error = fd_alloc(p, 0, new_fd)) != 0) {
                if (error != ENOSPC) {
			aprint_normal("fd_alloc fails, errno: %d\n", error);
                        return error;
                }
                fd_tryexpand(p);
        }

        return 0;
}

void rump_fsdom_fd_abort(int target_fd)
{
        proc_t *p = curproc;
	fd_abort(p, NULL, target_fd);
}
#endif

void rump_fsdom_print_curlwp(int i)
{
	aprint_normal("FOOBAR [%d] lwp: %p, proc: %p, p_fd: %p, freefile: %d, lastfile: %d\n", i, curlwp, curlwp->l_proc, curlwp->l_proc->p_fd, curlwp->l_proc->p_fd->fd_freefile, curlwp->l_proc->p_fd->fd_lastfile);
}
