typedef struct syscall_args {
        uint64_t wk; /* struct work */
	void *argp;
	void *uap;
	void *thread;
	_Atomic(int) done;
	int ret;
	register_t retval;
        uint64_t call_id;
	uint64_t domid;
} syscall_args_t;

void rump_fsdom_init_workqueue(void);
void rump_fsdom_set_offset(uint64_t);
void rump_fsdom_enqueue(void *);
void rump_fsdom_print_curlwp(int);
int rump_local_syscall(struct lwp *, const void *, register_t *, int);
int rump_fsdom_fd_alloc(int *);
void rump_fsdom_fd_abort(int);

extern void (*rumpuser_fsdom_send)(void *);
