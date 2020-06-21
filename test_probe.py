#!/usr/bin/env python
import bcc

def run(binary, offset):
    bpf_text = """
    BPF_ARRAY(count, u64, 1);
    BPF_ARRAY(prev_time, u64, 1);
    int trace(struct pt_regs *ctx) {
        int zero = 0;
        u64* c = count.lookup(&zero);
        if (c) {
            bpf_trace_printk("step %d\\n", *c);
        }
        count.increment(zero);

        u64* pt = prev_time.lookup(&zero);
        u64 t = 0;
        if (pt) {
            u64 t = *pt;
        }
        u64 current_time = bpf_ktime_get_ns();
        prev_time.update(&zero, &current_time);
        if (pt) {
            u64 delta_time = current_time - t;
            bpf_trace_printk("time delta %lluns\\n", delta_time);
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
