CXX = g++
CLANGXX = clang++
CXXFLAGS = -std=c++17 -O1 -g -DTEST_RUNNER -fsanitize=address,undefined -fno-omit-frame-pointer
FUZZFLAGS = -std=c++17 -O1 -g -fsanitize=fuzzer,address,undefined

SANITIZED_TESTS = \
	run_pe_tests_sanitized \
	run_malformed_tests_sanitized \\n	run_edge_tests_sanitized \\n	run_fuzz_corpus_replay_sanitized

FUZZ_TARGET = fuzz_pe

.PHONY: all test fuzz clean

all: test fuzz

test: $(SANITIZED_TESTS)
	@echo "Running sanitized tests..."
	./run_pe_tests_sanitized
	./run_malformed_tests_sanitized
	./run_edge_tests_sanitized
	./run_fuzz_corpus_replay_sanitized

fuzz: $(FUZZ_TARGET)

# Individual sanitized test binaries
run_pe_tests_sanitized: engine.cpp tests/pe_tests.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@

run_malformed_tests_sanitized: engine.cpp tests/pe_malformed_tests.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@

run_edge_tests_sanitized: engine.cpp tests/pe_edge_tests.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@

run_fuzz_corpus_replay_sanitized: engine.cpp tests/fuzz_corpus_replay_tests.cpp
	$(CXX) $(CXXFLAGS) $^ -o $@

# Fuzz target (clang only)
$(FUZZ_TARGET): engine.cpp tests/fuzz_pe.cpp
	$(CLANGXX) $(FUZZFLAGS) $^ -o $@

# Tools
export_features: tools/export_features.cpp
	$(CXX) -std=c++17 -O2 tools/export_features.cpp -o export_features

export_ember_features: tools/export_ember_features.cpp engine.cpp
	# Compile the engine without the main/test runner to avoid duplicate mains
	$(CXX) -std=c++17 -O2 -DHEADER_ONLY -c engine.cpp -o engine_header.o
	$(CXX) -std=c++17 -O2 tools/export_ember_features.cpp engine_header.o -o export_ember_features

.PHONY: gen_dataset train predict

gen_dataset:
	python3 tools/generate_dataset.py

train: export_ember_features
	python3 -m pip install --user -r requirements.txt
	python3 tools/train_detector.py --ember

predict: export_ember_features
	python3 tools/predict.py $(file)

clean:
	rm -f $(SANITIZED_TESTS) $(FUZZ_TARGET) export_features