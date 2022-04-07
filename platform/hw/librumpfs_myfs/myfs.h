typedef struct syscall_args {
        void *wk; /* struct work */
	void *uap;
	register_t retval;
        uint64_t call_id;
} syscall_args_t;

void rump_fsdom_init_workqueue(void);
void rump_fsdom_set_offset(uint64_t);
void rump_fsdom_enqueue(void *);
void rump_fsdom_receive(void *slot, int args);

file_t *rump_fd_getfile(unsigned);
/*
int rump_fsdom_open(const char *, int, mode_t, register_t *);
int rump_fsdom_read(int, void *, size_t, register_t *);
int rump_fsdom_write(struct lwp *, const void *, register_t *);
int rump_fsdom_close(struct lwp *, const void *, register_t *);
int rump_fsdom_fcntl(int, int, void *, register_t *);
*/
