#!/usr/bin/env python
import bcc

def run(binary, offset):
    bpf_text = """
    BPF_ARRAY(count, u64, 1);
    int trace(struct pt_regs *ctx) {
        int zero = 0;
        u64* c = count.lookup(&zero);
        if (c) {
            bpf_trace_printk("step %d\\n", *c);
        }
        count.increment(zero);
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
