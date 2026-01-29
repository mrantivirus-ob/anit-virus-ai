#include <iostream>
#include <fstream>
#include <vector>
#include <cassert>
#include <cstdint>
#include <filesystem>

extern "C" void fuzz_parse_pe_bytes(const uint8_t* bytes, size_t size);

int main() {
    namespace fs = std::filesystem;
    const fs::path dir = "tests/fuzz_corpus";
    size_t processed = 0;

    if (!fs::exists(dir)) {
        std::cout << "No fuzz corpus directory (" << dir << ") found; nothing to replay" << std::endl;
        return 0; // not an error
    }

    for (auto &entry : fs::directory_iterator(dir)) {
        if (!entry.is_regular_file()) continue;
        std::ifstream f(entry.path(), std::ios::binary);
        if (!f) continue;
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

        // Call the memory-only parser; under ASAN/UBSAN this will surface crashes.
        fuzz_parse_pe_bytes(data.data(), data.size());
        ++processed;
    }

    std::cout << "Replayed " << processed << " corpus files from " << dir << std::endl;
    return 0;
}
