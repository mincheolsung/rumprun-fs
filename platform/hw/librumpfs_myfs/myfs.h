typedef struct syscall_args {
        uint64_t wk; /* struct work */
	void *argp;
	void *uap;
	void *thread;
	int ret;
	register_t retval;
        uint64_t call_id;
	uint64_t padding;
} syscall_args_t;

void rump_fsdom_init_workqueue(void);
void rump_fsdom_set_offset(uint64_t);
void rump_fsdom_enqueue(void *);

extern void (*rumpuser_fsdom_send)(void *);
