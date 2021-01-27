#define MAX_CHILDREN 12

struct exec_ctx {
  long ip;
  int pid;
};

struct timing {
  struct exec_ctx ectx;
  __u64 enter_ns;
  __u64 exit_ns;
};

struct timing_event {
  struct timing t;
  int child_cnt;
  struct timing children[MAX_CHILDREN];
};
