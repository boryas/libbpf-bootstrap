// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stdbool.h>

#include "minimal.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, long);
	__type(value, char[64]);
} ip_to_name SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct exec_ctx);
  __type(value, struct timing_event);
} execs SEC(".maps");

// map child IP to timing slot
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, long);
  __type(value, unsigned int);
} slots SEC(".maps");

long parent_ip = 0;
__u64 threshold = 0;

static __always_inline void dump_stack(const long *bp, int before, int after)
{
	int i = 0;
	long val;

	for (i = after; i >= before; i--) {
		bpf_probe_read_kernel(&val, sizeof(val), bp + i);
		bpf_printk("0x%lx %d: %lx", (long)bp, i * 8, val);
	}
}

static __always_inline void dump_kprobe(struct pt_regs *regs)
{
	long tmp;

	bpf_printk("hrtimer_start_range_ns() ADDR: %lx", 0xffffffff81133ac0);
	bpf_printk("IP: %lx, FP: %lx, SP: %lx", PT_REGS_IP(regs), PT_REGS_FP(regs), PT_REGS_SP(regs));
	bpf_printk("STACK AT RBP");
	dump_stack((void *)PT_REGS_FP(regs), 0, 16);
	bpf_printk("STACK AT RSP");
	dump_stack((void *)PT_REGS_SP(regs), 0, 16);

	/*
	bpf_probe_read(&tmp, 8, (void *)PT_REGS_FP(regs));
	dump_stack((void *)tmp, 0, 16);
	*/
}

static __always_inline void dump_ftrace(void *ctx)
{
	bpf_printk("hrtimer_start_range_ns() ADDR: %lx", 0xffffffff81133ac0);
	bpf_printk("__x64_sys_write() ADDR: %lx", 0xffffffff812b01e0);
	bpf_printk("CTX: %lx", (long)ctx);
	dump_stack(ctx, 0, 16);
}

static __always_inline long get_ftrace_caller_ip(void *ctx, int arg_cnt)
{
	long ip;
	long off = 1 /* skip orig rbp */ + 1 /* skip reserved space for ret value */;

	if (arg_cnt <= 6)
		off += arg_cnt;
	else
		off += 6;
	off = (long)ctx + off * 8;

	if (bpf_probe_read_kernel(&ip, sizeof(ip), (void *)off)) {
		bpf_printk("FAILED TO GET CALLER IP AT %lx", off);
		return 0;
	}

	ip -= 5; /* compensate for 5-byte fentry stub */
	return ip;
}

static int handle_parent(void *ctx, bool entry) {
  struct timing_event e;
  struct exec_ctx ectx;
  __u64 now;
	int pid = bpf_get_current_pid_tgid() >> 32;

  __builtin_memset(&ectx, 0, sizeof(ectx));
  ectx.ip = parent_ip;
  ectx.pid = pid;
  now = bpf_ktime_get_ns();

	if (entry) {
    __builtin_memset(&e, 0, sizeof(e));
    e.t.enter_ns = now;
    e.ectx.ip = parent_ip;
    e.ectx.pid = pid;
    bpf_map_update_elem(&execs, &ectx, &e, 0);
  } else {
    struct timing_event *e_lkp;
    e_lkp = bpf_map_lookup_elem(&execs, &ectx);
    if (!e_lkp)
      return 0;
    e_lkp->t.exit_ns = now;
    if (e_lkp->t.exit_ns - e_lkp->t.enter_ns > threshold)
      bpf_ringbuf_output(&rb, e_lkp, sizeof(*e_lkp), 0);
  }
  return 0;
}

static int handle_child(void *ctx, long ip, bool entry) {
  struct timing_event *e;
  struct exec_ctx ectx;
  __u64 now;
  unsigned int *slot;
	int pid = bpf_get_current_pid_tgid() >> 32;
  struct child_timing *ct;

  __builtin_memset(&ectx, 0, sizeof(ectx));
  ectx.ip = parent_ip;
  ectx.pid = pid;

  e = bpf_map_lookup_elem(&execs, &ectx);
  if (!e)
    return 0;

  slot = bpf_map_lookup_elem(&slots, &ip);
  if (!slot)
    return 0;
  if (*slot >= MAX_CHILDREN)
    return 0;

  ct = &(e->children[*slot]);

  now = bpf_ktime_get_ns();
  if (entry) {
    ct->ip = ip;
    ct->last_enter_ns = now;
  } else {
    ct->sum_ns += now - ct->last_enter_ns;
    ++ct->count;
  }
  return 0;
}

static __noinline int handle(void *ctx, int arg_cnt, bool entry)
{
	long ip;

	ip = get_ftrace_caller_ip(ctx, arg_cnt);
  if (ip == parent_ip)
    return handle_parent(ctx, entry);
  else
    return handle_child(ctx, ip, entry);

  /*
  now = bpf_ktime_get_ns();
	if (entry) {
    bpf_map_update_elem(&execs, &(e.ectx), &now, 0);
  } else {
    // todo: rewrite 
    start = bpf_map_lookup_elem(&execs, &(e.ectx));
    if (start) {
      e.duration = now - *start;
      if (ip == parent_ip) {
        if (e.duration > threshold)
          bpf_ringbuf_output(&rb, &e, sizeof(e), 0);
      } else {
      }
    } else
      bpf_printk("%s (%d) no start...\n");
  }
	return 0;
  */
}

#define DEF_PROGS(arg_cnt) \
SEC("fentry/__x64_sys_write") \
int fentry ## arg_cnt(void *ctx) \
{ \
	return handle(ctx, arg_cnt, true); \
} \
SEC("fexit/__x64_sys_write") \
int fexit ## arg_cnt(void *ctx) \
{ \
	return handle(ctx, arg_cnt, false); \
}

DEF_PROGS(0)
DEF_PROGS(1)
DEF_PROGS(2)
DEF_PROGS(3)
DEF_PROGS(4)
DEF_PROGS(5)
DEF_PROGS(6)
DEF_PROGS(7)
DEF_PROGS(8)
DEF_PROGS(9)
DEF_PROGS(10)
DEF_PROGS(11)
