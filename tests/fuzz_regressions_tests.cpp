#include <iostream>
#include <fstream>
#include <vector>
#include <cassert>
#include <cstdint>
#include <filesystem>

extern "C" void fuzz_parse_pe_bytes(const uint8_t* bytes, size_t size);

int main() {
    namespace fs = std::filesystem;
    const fs::path files[] = {
        "tests/fuzz_corpus/crash-786543377484770e9ceca8bd0eef2ff259e30614",
        "tests/fuzz_corpus/crash-1e2325113ba798af6ed0e4c3c8604f344bc84ecd",
        "tests/fuzz_corpus/crash-da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "tests/fuzz_corpus/crash-2f7aeefd4c0459592674f78d601d5d8a385482b0"
    };

    size_t processed = 0;
    for (auto &p : files) {
        if (!fs::exists(p) || !fs::is_regular_file(p)) {
            std::cerr << "Missing regression file: " << p << " (skipping)\n";
            continue;
        }
        std::ifstream f(p, std::ios::binary);
        assert(f && "Failed to open regression input");
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        std::cout << "Replaying regression file: " << p << " (" << data.size() << " bytes)\n";

        // Should not crash under ASan/UBSan
        fuzz_parse_pe_bytes(data.data(), data.size());
        ++processed;
    }

    std::cout << "Processed " << processed << " regression artifacts" << std::endl;
    return 0;
}
