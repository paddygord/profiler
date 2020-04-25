# live interactive profiler (sampling and tracing)

## motivation

- profiling is good if your problem is visible when you average over time (e.g. perf and flamegraphs)
- tracing is good if you already have a strong hypothesis of what the problem is (e.g. all `recv` calls are slow, or this one `recv` call is slow)
    - static (compile time or manual instrumentation)
        - it's slow and painful to iterate
    - dynamic (run time) e.g. bpf based
        - doesn't have great tooling yet
        - doesn't make use of it's unique advantage: run time dynamism

## existing tools

- sampling (perf)
    1. it's single machine
    2. the live possibilities are limited
- sampling visualisations
    - [flamegraphs](github.com/brendangregg/flamegraph#flame-graphs-visualize-profiled-code)
        - no live capability
        - only one view
    - [flamescope](github.com/netflix/flamescope#flamescope)
        - can highlight something that doesn't appear in the time average
        - but only in a specific way
    - [speedscope](github.com/jlfwong/speedscope#speedscope)

## a new kind of interactive profiling

- sampling with trace information, or decision based on trace information
- e.g. separate stacks based on whether a function higher up the stacktraces duration was in the 95th percentile
- because every step (sampling, tracing, output) is dynamic (enabled by bpf), you never need to recompile or restart the target application or profiling application
- this enables interactive profiling, digging into the problem, e.g. (highest level) sample everything -> sample where high level function in 95th percentile -> sample only when this branch is taken -> (lowest level) trace `recv` calls at `main.cc:1312`
- rather than fixed time windows (e.g. run for 10 seconds then stop and report), reporting can be streaming (present data from last 10 seconds or an exponentially weighted moving average of all time)

## approach

writing [bpf c](github.com/iovisor/bcc) is hard, so combine existing tools that do bits of this problem
- [profile](github.com/iovisor/bcc/blob/master/tools/profile.py): sample on-cpu stack traces at a regular interval
- [funclatency](github.com/iovisor/bcc/blob/master/tools/funclatency.py): histogram duration of calls of a function
- [funcslower](github.com/iovisor/bcc/blob/master/tools/funcslower.py): trace calls of a function that are slower than x ms

## dependencies

- [bcc](github.com/iovisor/bcc/blob/master/INSTALL.md)

## progress

- [ ] modularise profile.py, funclatency.py, and funcslower.py from bcc-tools
- [ ] combine them into one script that does multiple
- [ ] add state that is reused between them
- [ ] separate samples based on some high level decision
- [ ] for any step taking longer than the 95th percentile, show me a flamegraph of all samples inside those steps

## future

- Maybe use [plotly dash](https://dash.plotly.com/interactive-graphing) for a graphical frontend
- Maybe use [kernel density estimation](https://scikit-learn.org/stable/modules/density.html#kernel-density-estimation) rather than histograms for visualisation and/or automatic discovery
