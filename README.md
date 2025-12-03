# perf_wrapper

Minimal C++ helper around perf_event_open that profiles an existing PID or a
spawned command with user-selected counters.


## Build

    cmake -S . -B build
    cmake --build build


## Usage

    ./perf_wrapper [-p PID] [-d SECONDS] [-c COUNTERS] [-- COMMAND ...]

- -p monitor an existing process (default: wrapper PID). Cannot be combined with `-- COMMAND`.
- -d stop after the given number of seconds; otherwise wait for the target.
- -c comma-separated counters using sw-* / hw-* names (see -h for list).
- -g create a counter group (comma-separated). Repeat the flag to add several groups like `perf stat -g`. Append `:P`
    to a counter name (e.g. `sw-cpu-clock:P`) to request `perf_event_attr.pinned=1` for that leader; only the first
    counter inside a group may be pinned.
- -- terminate option parsing; everything after is executed under perf.


Example:

    ./perf_wrapper -d 5 -c sw-cpu-clock -g hw-instructions,hw-branch-instructions -- ./my_binary

Sample output:

```
Timeout exit (total 5000 ms)
                  count  name                           | comment                          | coverage  | group
              13,456,789  sw-cpu-clock                  | 2.691 M/sec                      | (100.00%) | -
              67,890,123  hw-instructions               | 13.578 M/sec                     | (100.00%) | 1
               1,234,567  hw-branch-misses              | 1.818181 miss rate               | (100.00%) | 1
```


