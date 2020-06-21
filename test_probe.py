#!/usr/bin/env python
import bcc

def run(binary, offset):
    bpf_text = """
    struct entry {
        u64 tick;
        u64 time;
    };
    BPF_HASH(stuff, u32, struct entry);

    int trace(struct pt_regs *ctx) {
        u32 tid = bpf_get_current_pid_tgid();

        struct entry* e = stuff.lookup(&tid);
        u64 current_time = bpf_ktime_get_ns();
        if (e) {
            bpf_trace_printk("thread %lu tick %llu time %lluns\\n", tid, e->tick, current_time - e->time);
            e->time = current_time;
            e->tick += 1;
            //TODO is it safe to use this pointer?
            //won't there be concurrent inserts to the map
            //that will invalidate the pointer
        } else {
            struct entry e;
            e.tick = 0;
            e.time = current_time;
            stuff.insert(&tid, &e);
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
