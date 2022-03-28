#ifdef FSDOM_FRONTEND
file_t *rump_fd_getfile(unsigned fd);
int rump_fsdom_open(struct lwp *l, const void *uap, register_t *retval);
int rump_fsdom_read(struct lwp *l, const void *uap, register_t *retval);
int rump_fsdom_write(struct lwp *l, const void *uap, register_t *retval);
int rump_fsdom_close(struct lwp *l, const void *uap, register_t *retval);

#else
file_t *rump_fd_getfile(unsigned fd);
int rump_fsdom_open(const char * path, int flags, mode_t mode, register_t *retval);
int rump_fsdom_read(int fd, void *buf, size_t nbyte, register_t *retval);
int rump_fsdom_write(struct lwp *l, const void *uap, register_t *retval);
int rump_fsdom_close(struct lwp *l, const void *uap, register_t *retval);
int rump_fsdom_fcntl(int fd, int cmd, void *arg, register_t *retval);
#endif
