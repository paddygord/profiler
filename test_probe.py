#!/usr/bin/env python
import bcc

def run(binary, offset):
    bpf_text = """
    BPF_HASH(count, u32, u64);
    BPF_HASH(prev_time, u32, u64);
    int trace(struct pt_regs *ctx) {
        u32 tid = bpf_get_current_pid_tgid();

        u64* c = count.lookup(&tid);
        if (c) {
            bpf_trace_printk("step %d\\n", *c);
        }
        count.increment(tid);

        u64* pt = prev_time.lookup(&tid);
        u64 current_time = bpf_ktime_get_ns();
        if (pt) {
            u64 t = *pt;
            prev_time.update(&tid, &current_time);
            u64 delta_time = current_time - t;
            bpf_trace_printk("time delta %lluns\\n", delta_time);
        } else {
            prev_time.insert(&tid, &current_time);
        }

        return 0;
    }
    """

    b = bcc.BPF(text=bpf_text)
    b.attach_uprobe(name=binary, addr=offset, fn_name="trace")

    print('good')
    while True:
        try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
            print(msg)
        except ValueError:
            pass
