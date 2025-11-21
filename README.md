# perf_wrapper

Minimal C++ helper around perf_event_open that profiles an existing PID or a
spawned command with user-selected counters.


## Build

    cmake -S . -B build
    cmake --build build


## Usage

    ./perf_wrapper [-p PID] [-d SECONDS] [-c COUNTERS] [-- COMMAND ...]

- -p monitor an existing process (default: wrapper PID).
- -d stop after the given number of seconds; otherwise wait for the target.
- -c comma-separated counters using sw-* / hw-* names (see -h for list).
- -- terminate option parsing; everything after is executed under perf.


Example:

    ./perf_wrapper -d 5 -c sw-cpu-clock,hw-cpu-cycles -- ./my_binary


