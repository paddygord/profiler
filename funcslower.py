#!/usr/bin/env python

import bcc
from string import Template
import time

def preprocess(functions, arguments, tgid, duration_ns = 10):
    bpf_text = \
    ("#define GRAB_ARGS\n" if arguments is not None else "") + \
    ("#define USER_STACKS\n" if get_user_stack is not None else "") + \
    ("#define KERNEL_STACKS\n" if get_kernel_stack is not None else "") + \
    """
    #include <uapi/linux/ptrace.h>
    #include <linux/sched.h>    // for TASK_COMM_LEN

    struct entry_t {
        u64 id;
        u64 start_ns;
    #ifdef GRAB_ARGS
        u64 args[6];
    #endif
    };

    struct data_t {
        u64 id;
        u64 tgid_pid;
        u64 start_ns;
        u64 duration_ns;
        u64 retval;
        char comm[TASK_COMM_LEN];
    #ifdef GRAB_ARGS
        u64 args[6];
    #endif
    #ifdef USER_STACKS
        int user_stack_id;
    #endif
    #ifdef KERNEL_STACKS
        int kernel_stack_id;
        u64 kernel_ip;
    #endif
    };

    BPF_HASH(entryinfo, u64, struct entry_t);
    BPF_PERF_OUTPUT(events);

    #if defined(USER_STACKS) || defined(KERNEL_STACKS)
    BPF_STACK_TRACE(stacks, 2048);
    #endif

    static int trace_entry(struct pt_regs *ctx, int id) {
        u64 tgid_pid = bpf_get_current_pid_tgid();
        u32 tgid = tgid_pid >> 32;
        if (""" + (\
            "tgid != " + str(tgid) if tgid is not None else "false"\
        ) + """)
            return 0;

        u32 pid = tgid_pid;

        struct entry_t entry = {};
        entry.start_ns = bpf_ktime_get_ns();
        entry.id = id;
    #ifdef GRAB_ARGS
        entry.args[0] = PT_REGS_PARM1(ctx);
        entry.args[1] = PT_REGS_PARM2(ctx);
        entry.args[2] = PT_REGS_PARM3(ctx);
        entry.args[3] = PT_REGS_PARM4(ctx);
        entry.args[4] = PT_REGS_PARM5(ctx);
        entry.args[5] = PT_REGS_PARM6(ctx);
    #endif

        entryinfo.update(&tgid_pid, &entry);

        return 0;
    }

    int trace_return(struct pt_regs *ctx) {
        struct entry_t *entryp;
        u64 tgid_pid = bpf_get_current_pid_tgid();

        entryp = entryinfo.lookup(&tgid_pid);
        if (entryp == 0) {
            return 0;
        }

        u64 delta_ns = bpf_ktime_get_ns() - entryp->start_ns;
        entryinfo.delete(&tgid_pid);

        if (delta_ns < """ + str(duration_ns) + """)
            return 0;

        struct data_t data = {};
        data.id = entryp->id;
        data.tgid_pid = tgid_pid;
        data.start_ns = entryp->start_ns;
        data.duration_ns = delta_ns;
        data.retval = PT_REGS_RC(ctx);

    #ifdef USER_STACKS
        data.user_stack_id = stacks.get_stackid(ctx, BPF_F_USER_STACK);
    #endif

    #ifdef KERNEL_STACKS
        data.kernel_stack_id = stacks.get_stackid(ctx, 0);

        if (data.kernel_stack_id >= 0) {
            u64 ip = PT_REGS_IP(ctx);
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
                data.kernel_ip = ip;
            }
        }
    #endif

    #ifdef GRAB_ARGS
        bpf_probe_read(&data.args[0], sizeof(data.args), entryp->args);
    #endif
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }
    """

    for i in range(len(functions)):
        bpf_text += """
    int trace_%d(struct pt_regs *ctx) {
        return trace_entry(ctx, %d);
    }
    """ % (i, i)
    return bpf_text

def compile(bpf_text):
    return bcc.BPF(text=bpf_text)

def attach(b, functions):
    for i, function in enumerate(functions):
        if ":" in function:
            library, func = function.split(":")
            b.attach_uprobe(name=library, sym=func, fn_name="trace_%d" % i)
            b.attach_uretprobe(name=library, sym=func, fn_name="trace_return")
        else:
            b.attach_kprobe(event=function, fn_name="trace_%d" % i)
            b.attach_kretprobe(event=function, fn_name="trace_return")

def wait_and_report():
    time_designator = "us" if min_us else "ms"
    time_value = min_us or min_ms or 1
    time_col = time_abs or time_rel
    time_multiplier = 1000 if min_us else 1000000

    # Do not print header when folded
    if not folded:
        print("Tracing function calls slower than %g %s... Ctrl+C to quit." %
              (time_value, time_designator))
        print((("%-10s " % "TIME" if time_col else "") + "%-14s %-6s %7s %16s %s") %
            ("COMM", "PID", "LAT(%s)" % time_designator, "RVAL",
            "FUNC" + (" ARGS" if arguments else "")))

    earliest_ts = 0

    def time_str(event):
        if time_abs:
            return "%-10s " % time.strftime("%H:%M:%S")
        if time_rel:
            global earliest_ts
            if earliest_ts == 0:
                earliest_ts = event.start_ns
            return "%-10.6f " % ((event.start_ns - earliest_ts) / 1000000000.0)
        return ""

    def args_str(event):
        if not arguments:
            return ""
        return str.join(" ", ["0x%x" % arg for arg in event.args[:arguments]])

    def print_stack(event):
        user_stack = []
        stack_traces = b.get_table("stacks")

        if get_user_stack and event.user_stack_id > 0:
            user_stack = stack_traces.walk(event.user_stack_id)

        kernel_stack = []
        if get_kernel_stack and event.kernel_stack_id > 0:
            kernel_tmp = stack_traces.walk(event.kernel_stack_id)

            # fix kernel stack
            for addr in kernel_tmp:
                kernel_stack.append(addr)

        do_delimiter = user_stack and kernel_stack

        if folded:
            # print folded stack output
            user_stack = list(user_stack)
            kernel_stack = list(kernel_stack)
            line = [event.comm.decode('utf-8', 'replace')] + \
                [b.sym(addr, event.tgid_pid) for addr in reversed(user_stack)] + \
                (do_delimiter and ["-"] or []) + \
                [b.ksym(addr) for addr in reversed(kernel_stack)]
            print("%s %d" % (";".join(line), 1))
        else:
            # print default multi-line stack output.
            for addr in kernel_stack:
                print("    %s" % b.ksym(addr))
            for addr in user_stack:
                print("    %s" % b.sym(addr, event.tgid_pid))

    def print_event(cpu, data, size):
        event = b["events"].event(data)
        ts = float(event.duration_ns) / time_multiplier
        if not folded:
            print((time_str(event) + "%-14.14s %-6s %7.2f %16x %s %s") %
                (event.comm.decode('utf-8', 'replace'), event.tgid_pid >> 32,
                 ts, event.retval, functions[event.id], args_str(event)))
        if get_user_stack or get_kernel_stack:
            print_stack(event)

    b["events"].open_perf_buffer(print_event, page_cnt=64)
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

if __name__ == "__main__":
    min_ms = None
    min_us = None
    time_abs = False
    time_rel = True
    folded = True
    get_user_stack = True
    get_kernel_stack = True
    functions = ["c:open"]
    arguments = 3
    tgid = 0

    bpf_text = preprocess(functions, arguments, tgid)
    b = compile(bpf_text)
    attach(b, functions)
    wait_and_report()
