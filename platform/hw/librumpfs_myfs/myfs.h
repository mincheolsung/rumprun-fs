file_t *rump_fd_getfile(unsigned);
int rump_fsdom_open(const char *, int, mode_t, register_t *);
int rump_fsdom_read(int, void *, size_t, register_t *);
int rump_fsdom_write(struct lwp *, const void *, register_t *);
int rump_fsdom_close(struct lwp *, const void *, register_t *);
int rump_fsdom_fcntl(int, int, void *, register_t *);
