# dyntools
Helpful Dyninst-based utilities for static/dynamic control-flow graph analysis.

## Installation Notes
* Requires Dyninst **v9.3.0**.
* After building Dyninst, edit `Makefile` and replace `DYN_ROOT` with the path to your Dyninst build directory.
* Then, run `make all`.

## Static CFG analysis with dsAnalyzeCFG
This utility applies basic static analysis on a binary's extracted control-flow graph.

* **NOTE**: this is an approximation at best, as indirect control-flow modeling is a challenge for Dyninst (as well as all static binary rewriters).

```
Usage: dsAnalyzeCFG [input_binary] [analysis_options]
	Analysis options:
		-M: minimum block size (default: 1)
		-N: number of blocks to skip (default: 0)
		-A: path to list of block addresses to skip
		-I: skip initialization functions (e.g., _start)
		-C: get stats on critical edges
		-F: get names of all functions analyzed
	Additional options:
		-V: verbose mode
```


## Dynamic CFG analysis with dtInstrument + dtCollect + dtAnalyzeCFG
These two utilities allow dynamic CFG analysis given a set of test case data and sizes dumps (generated using afl-fid's `afl-fuzz-saveinputs`).

* **NOTE**: due to instrumentation issues, only binaries compiled with `-O3`-level optimizations are currently supported.


1. After collecting test case data/sizes dumps, instrument the binary for dynamic tracing with `dtInstrument`:
```
dtInstrument [input_binary] -O [output_binary] -T [dynamic_trace_path]
```

2. Then, "replay" the test cases and record their dynamic traces using `dtCollect`:
```
dtCollect -I [input_data_dump] -S [input_sizes_dump] -F [cur_input] -T [dynamic_trace_path] -t [trace_tmout] -M [max_traces] -- [target_path] [target_args]
```

3. Lastly, AnalyzeCFG the traces using `dtAnalyzeCFG`:
```
dtAnalyzeCFG -T [dynamic_trace_path] -M [max_traces] -V [verbose]
```

