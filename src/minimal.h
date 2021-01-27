#define MAX_CHILDREN 12

struct exec_ctx {
  long ip;
  int pid;
};

struct timing {
  __u64 enter_ns;
  __u64 exit_ns;
};

struct child_timing {
  long ip;
  __u32 count;
  __u64 last_enter_ns;
  __u64 sum_ns;
};

struct timing_event {
  struct exec_ctx ectx;
  struct timing t;
  struct child_timing children[MAX_CHILDREN];
};
