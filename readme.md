# live interactive profiler (sampling and tracing)

## motivation

- sampling is good if your problem is visible when you average over time (e.g. perf and flamegraphs)
- tracing is good if you already have a strong hypothesis of what the problem is (e.g. all `recv` calls are slow, or this one `recv` call is slow)
    - static (compile time or manual instrumentation)
        - it's slow and painful to iterate
    - dynamic (run time) e.g. bpf based
        - doesn't have great tooling yet
        - doesn't make use of it's unique advantage: run time dynamism
- no existing end user tool does either of these (AFAIK)
    - dynamic tracing of user code
    - combining sampling and tracing information
- extra benefits
    - live interaction between user, profiler and running application
    - distributed, can collect from many machines to one

## existing tools

- sampling (visualisation tools mostly based on perf)
    - [flamegraphs](github.com/brendangregg/flamegraph#flame-graphs-visualize-profiled-code)
        - no live capability
        - only one view
    - [flamescope](github.com/netflix/flamescope#flamescope)
        - can highlight something that doesn't appear in the time average
        - but only in a specific way
    - [speedscope](github.com/jlfwong/speedscope#speedscope)
    - [heat maps](http://www.brendangregg.com/heatmaps.html)
- tracing
    - [jaeger](https://www.jaegertracing.io/)
        - code instrumentation
        - manual, static
    - [vampir](https://vampir.eu/)
        - compiler based instrumentation
        - automatic, static
    - [tracy](https://github.com/wolfpld/tracy)
        - code zone/scope instrumentation
        - manual, static
    - [dtrace](http://dtrace.org/blogs/)
        - probe/action based
        - some dynamic probes
        - user code probes are manual, static
    - [systemtap](https://sourceware.org/systemtap/)
        - probe/script based
        - some dynamic probes
        - user code probes are manual, static
- sampling and tracing
    - [bpf](http://www.brendangregg.com/blog/2019-01-01/learn-ebpf-tracing.html)
        - fully dynamic user code probes
            - but quite awkward to implement
            - need to process dwarf debug information yourself
            - no end user facing tool offers this yet
        - possible to combine tracing and sampling
            - using perf events and user probes
            - again, no end user facing tool offers this yet

## a new kind of interactive profiling

- sampling with trace information, or decision based on trace information
- e.g. separate stacks based on whether a function higher up the stacktraces duration was in the 95th percentile
- because every step (sampling, tracing, output) is dynamic (enabled by bpf), you never need to recompile or restart the target application or profiling application
- this enables interactive profiling, digging into the problem, e.g. (highest level) sample everything -> sample where high level function in 95th percentile -> sample only when this branch is taken -> (lowest level) trace `recv` calls at `main.cc:1312`
- it would even allow tracing an if-statement, other branch, or an arbitrary line of code, rather than just function entry/exit. this would be enabled by [dwarf debug info integration](#future)
- rather than fixed time windows (e.g. run for 10 seconds then stop and report), reporting can be streaming (present data from last 10 seconds or an exponentially weighted moving average of all time)

## approach

writing [bpf c](github.com/iovisor/bcc) is hard, so combine existing tools that do bits of this problem
- [profile](github.com/iovisor/bcc/blob/master/tools/profile.py): sample on-cpu stack traces at a regular interval
- [funclatency](github.com/iovisor/bcc/blob/master/tools/funclatency.py): histogram duration of calls of a function
- [funcslower](github.com/iovisor/bcc/blob/master/tools/funcslower.py): trace calls of a function that are slower than x ms

## dependencies

- [bcc](https://github.com/iovisor/bcc/blob/master/INSTALL.md)

## progress

- [x] modularise profile.py, funclatency.py, and funcslower.py from bcc-tools
- [x] combine profile and funcslower into one script (don't actually need funclatency?)
- [x] integrate dwarf line number getter
- [ ] add state that is reused between them
- [ ] separate samples based on some high level decision
- [ ] for any call taking longer than the 95th percentile, show me a flamegraph of all samples inside those calls
- [ ] generate a [difference flamegraph](http://www.brendangregg.com/blog/2014-11-09/differential-flame-graphs.html) for the samples inside/outside the 95th percentile

## future

- Maybe use dwarf debug info to access local variables (rather than just function arguments)
- Maybe use [plotly dash](https://dash.plotly.com/interactive-graphing) for a graphical frontend
- Maybe use [kernel density estimation](https://scikit-learn.org/stable/modules/density.html#kernel-density-estimation) rather than histograms for visualisation and/or automatic discovery
- Maybe come up with a gdb/[radare2](https://rada.re/n/radare2.html)/[cutter](https://cutter.re/)-like UI for interactive probing of program structure (functions, loops, conditions, basic blocks, lexical blocks, etc)
