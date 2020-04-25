#!/usr/bin/python

import bcc
from sys import stderr
from time import sleep
from string import Template
import signal
import os
import errno

def preprocess(pid = None, tid = None, stack_storage_size = 16384, include_idle = False):
    idle_filter = "false" if include_idle else "pid == 0"
    thread_filter = \
        f"tgid != {pid}" if pid is not None else \
        f"pid != {tid}" if tid is not None else \
        "false"
    user_stacks_id = "-1" if user_stacks_only else "stack_traces.get_stackid(&ctx->regs, 0)"
    kernel_stacks_id = "-1" if kernel_stacks_only else "stack_traces.get_stackid(&ctx->regs, BPF_F_USER_STACK)"
    bpf_text = Template("""
    #include <uapi/linux/ptrace.h>
    #include <uapi/linux/bpf_perf_event.h>
    #include <linux/sched.h>

    struct key_t {
        u32 pid;
        u64 kernel_ip;
        u64 kernel_ret_ip;
        int user_stack_id;
        int kernel_stack_id;
        char name[TASK_COMM_LEN];
    };
    BPF_HASH(counts, struct key_t);
    BPF_STACK_TRACE(stack_traces, $stack_storage_size);

    int do_perf_event(struct bpf_perf_event_data *ctx) {
        u64 id = bpf_get_current_pid_tgid();
        u32 tgid = id >> 32;
        u32 pid = id;

        if ($idle_filter)
            return 0;

        if ($thread_filter)
            return 0;

        // create map key
        struct key_t key = {.pid = tgid};
        bpf_get_current_comm(&key.name, sizeof(key.name));

        // get stacks
        key.user_stack_id = $user_stacks_id;
        key.kernel_stack_id = $kernel_stacks_id;

        if (key.kernel_stack_id >= 0) {
            // populate extras to fix the kernel stack
            u64 ip = PT_REGS_IP(&ctx->regs);
            u64 page_offset;

            // if ip isn't sane, leave key ips as zero for later checking
    #if defined(CONFIG_X86_64) && defined(__PAGE_OFFSET_BASE)
            // x64, 4.16, ..., 4.11, etc., but some earlier kernel didn't have it
            page_offset = __PAGE_OFFSET_BASE;
    #elif defined(CONFIG_X86_64) && defined(__PAGE_OFFSET_BASE_L4)
            // x64, 4.17, and later
    #if defined(CONFIG_DYNAMIC_MEMORY_LAYOUT) && defined(CONFIG_X86_5LEVEL)
            page_offset = __PAGE_OFFSET_BASE_L5;
    #else
            page_offset = __PAGE_OFFSET_BASE_L4;
    #endif
    #else
            // earlier x86_64 kernels, e.g., 4.6, comes here
            // arm64, s390, powerpc, x86_32
            page_offset = PAGE_OFFSET;
    #endif

            if (ip > page_offset) {
                key.kernel_ip = ip;
            }
        }

        counts.increment(key);
        return 0;
    }""").substitute(**locals())
    return bpf_text

def compile(bpf_text):
    return bcc.BPF(text=bpf_text)

def attach(b, cpu = -1, sample_period = 0, sample_freq = 49):
    b.attach_perf_event(ev_type=bcc.PerfType.SOFTWARE,
        ev_config=bcc.PerfSWConfig.CPU_CLOCK, fn_name="do_perf_event",
        sample_period=sample_period, sample_freq=sample_freq, cpu=cpu)

def wait(duration = 999999999):
    try:
        sleep(duration)
    except KeyboardInterrupt:
        def signal_ignore(signal, frame):
            pass
        signal.signal(signal.SIGINT, signal_ignore)

def report(b, folded = False, need_delimiter = False, annotations = False):
    def aksym(addr):
        if annotations:
            return b.ksym(addr) + "_[k]".encode()
        else:
            return b.ksym(addr)

    def stack_id_err(stack_id):
        # -EFAULT in get_stackid normally means the stack-trace is not available,
        # Such as getting kernel stack trace in userspace code
        return (stack_id < 0) and (stack_id != -errno.EFAULT)

    missing_stacks = 0
    has_enomem = False
    counts = b.get_table("counts")
    stack_traces = b.get_table("stack_traces")
    for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
        # handle get_stackid errors
        if not user_stacks_only and stack_id_err(k.kernel_stack_id):
            missing_stacks += 1
            has_enomem = has_enomem or k.kernel_stack_id == -errno.ENOMEM
        if not kernel_stacks_only and stack_id_err(k.user_stack_id):
            missing_stacks += 1
            has_enomem = has_enomem or k.user_stack_id == -errno.ENOMEM

        user_stack = [] if k.user_stack_id < 0 else \
            stack_traces.walk(k.user_stack_id)
        kernel_tmp = [] if k.kernel_stack_id < 0 else \
            stack_traces.walk(k.kernel_stack_id)

        # fix kernel stack
        kernel_stack = []
        if k.kernel_stack_id >= 0:
            for addr in kernel_tmp:
                kernel_stack.append(addr)
            # the later IP checking
            if k.kernel_ip:
                kernel_stack.insert(0, k.kernel_ip)

        if folded:
            # print folded stack output
            user_stack = list(user_stack)
            kernel_stack = list(kernel_stack)
            line = [k.name]
            # if we failed to get the stack is, such as due to no space (-ENOMEM) or
            # hash collision (-EEXIST), we still print a placeholder for consistency
            if not kernel_stacks_only:
                if stack_id_err(k.user_stack_id):
                    line.append(b"[Missed User Stack]")
                else:
                    line.extend([b.sym(addr, k.pid) for addr in reversed(user_stack)])
            if not user_stacks_only:
                line.extend([b"-"] if (need_delimiter and k.kernel_stack_id >= 0 and k.user_stack_id >= 0) else [])
                if stack_id_err(k.kernel_stack_id):
                    line.append(b"[Missed Kernel Stack]")
                else:
                    line.extend([aksym(addr) for addr in reversed(kernel_stack)])
            print("%s %d" % (b";".join(line).decode('utf-8', 'replace'), v.value))
        else:
            # print default multi-line stack output
            if not user_stacks_only:
                if stack_id_err(k.kernel_stack_id):
                    print("    [Missed Kernel Stack]")
                else:
                    for addr in kernel_stack:
                        print("    %s" % aksym(addr))
            if not kernel_stacks_only:
                if need_delimiter and k.user_stack_id >= 0 and k.kernel_stack_id >= 0:
                    print("    --")
                if stack_id_err(k.user_stack_id):
                    print("    [Missed User Stack]")
                else:
                    for addr in user_stack:
                        print("    %s" % b.sym(addr, k.pid).decode('utf-8', 'replace'))
            print("    %-16s %s (%d)" % ("-", k.name.decode('utf-8', 'replace'), k.pid))
            print("        %d\n" % v.value)

    if missing_stacks > 0:
        print("WARNING: %d stack traces could not be displayed." % missing_stacks, file=stderr)
        if has_enomem:
            print("Consider increasing stack storage size.", file=stderr)

if __name__ == "__main__":
    user_stacks_only = False
    kernel_stacks_only = False
    bpf_text = preprocess()
    b = compile(bpf_text)
    attach(b)
    wait()
    report(b)
