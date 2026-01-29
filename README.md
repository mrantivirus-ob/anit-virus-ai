# anit-virus-ai
yah I'm makin' an ai for my AV

## Local sanitizer & fuzzing commands ✅

Use these to reproduce the GitHub Actions `sanitizers` job locally (Ubuntu/Debian):

1) Install compilers:

```bash
sudo apt update && sudo apt install -y g++ clang
```

2) Build and run sanitized unit tests:

```bash
# Build + run ASan+UBSan tests
g++ -std=c++17 -O1 -g -DTEST_RUNNER -fsanitize=address,undefined -fno-omit-frame-pointer engine.cpp tests/pe_tests.cpp -o run_pe_tests_sanitized
./run_pe_tests_sanitized

g++ -std=c++17 -O1 -g -DTEST_RUNNER -fsanitize=address,undefined -fno-omit-frame-pointer engine.cpp tests/pe_malformed_tests.cpp -o run_malformed_tests_sanitized
./run_malformed_tests_sanitized

g++ -std=c++17 -O1 -g -DTEST_RUNNER -fsanitize=address,undefined -fno-omit-frame-pointer engine.cpp tests/pe_edge_tests.cpp -o run_edge_tests_sanitized
./run_edge_tests_sanitized

# Replay fuzz corpus (if present)
g++ -std=c++17 -O1 -g -DTEST_RUNNER -fsanitize=address,undefined -fno-omit-frame-pointer engine.cpp tests/fuzz_corpus_replay_tests.cpp -o run_fuzz_corpus_replay_sanitized
./run_fuzz_corpus_replay_sanitized
```

3) Build fuzz target (clang only):

```bash
clang++ -std=c++17 -O1 -g -fsanitize=fuzzer,address,undefined engine.cpp tests/fuzz_pe.cpp -o fuzz_pe
```

4) Makefile (optional): run `make` to build and run tests, or `make fuzz` to build the fuzz binary.

### Tips
- Use `ASAN_OPTIONS` and `UBSAN_OPTIONS` to tune sanitizer behavior (see docs).
- libFuzzer requires clang; do not attempt to run a g++-built fuzz binary.
- Run fuzzing on dedicated infra for long jobs; CI should only run short reproductions and corpus replays.
