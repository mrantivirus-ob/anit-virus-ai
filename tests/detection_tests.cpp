#include <iostream>
#include <fstream>
#include <vector>
#include <cassert>
#include <cstdint>

namespace AVEngine {
    struct DetectionResult { double score; bool is_malware; std::string reason; };
    class FileFeatureExtractor;
    class Detector {
    public:
        struct DetectionResult { double score; bool is_malware; std::string reason; };
        static DetectionResult detect_from_bytes(const std::vector<uint8_t>&, double threshold = 0.5);
        static DetectionResult detect_from_file(const std::string&, double threshold = 0.5);
    };
}

extern "C" double detect_pe_score_from_bytes(const uint8_t* bytes, size_t size, double threshold);
extern "C" int detect_pe_label_from_file(const char* path, double threshold, char* reason_buf, size_t reason_len);

int main() {
    using namespace AVEngine;

    // 1) Minimal benign PE (re-use pattern from pe_tests.cpp)
    std::vector<uint8_t> data(512, 0);
    data[0] = 'M'; data[1] = 'Z';
    uint32_t pe_off = 0x80;
    data[0x3C] = (uint8_t)(pe_off & 0xFF);
    data[0x3D] = (uint8_t)((pe_off >> 8) & 0xFF);
    data[0x3E] = (uint8_t)((pe_off >> 16) & 0xFF);
    data[0x3F] = (uint8_t)((pe_off >> 24) & 0xFF);
    if (data.size() < pe_off + 64) data.resize(pe_off + 256, 0);
    data[pe_off + 0] = 'P'; data[pe_off + 1] = 'E'; data[pe_off + 2] = 0; data[pe_off + 3] = 0;
    // COFF header with 1 section
    data[pe_off + 4 + 0] = 0x4C; data[pe_off + 4 + 1] = 0x01;
    data[pe_off + 4 + 2] = 1; data[pe_off + 4 + 3] = 0;

    double score_benign = detect_pe_score_from_bytes(data.data(), data.size(), 0.5);
    std::cout << "benign score=" << score_benign << std::endl;
    assert(score_benign < 0.5);

    // 2) Packed-like PE (UPX in section name)
    size_t section_off = pe_off + 4 + 20;
    const char* name = "UPX";
    for (size_t i = 0; i < 8; ++i) data[section_off + i] = (i < 3) ? name[i] : 0;

    double score_packed = detect_pe_score_from_bytes(data.data(), data.size(), 0.5);
    std::cout << "packed score=" << score_packed << std::endl;
    assert(score_packed >= 0.5);

    // 3) Suspicious imports (simulate function names in import list by placing ASCII strings)
    std::string import_blob = "GetProcAddress\0LoadLibraryA\0VirtualAlloc\0";
    data.insert(data.end(), import_blob.begin(), import_blob.end());
    double score_imports = detect_pe_score_from_bytes(data.data(), data.size(), 0.5);
    std::cout << "suspicious imports score=" << score_imports << std::endl;
    assert(score_imports >= 0.5);

    // 4) Ensure regression artifacts are handled (non-crashing)
    const char* regression_paths[] = {
        "tests/fuzz_corpus/crash-786543377484770e9ceca8bd0eef2ff259e30614",
        "tests/fuzz_corpus/crash-1e2325113ba798af6ed0e4c3c8604f344bc84ecd",
        "tests/fuzz_corpus/crash-2f7aeefd4c0459592674f78d601d5d8a385482b0",
        "tests/fuzz_corpus/crash-da39a3ee5e6b4b0d3255bfef95601890afd80709"
    };
    for (auto p : regression_paths) {
        auto r = Detector::detect_from_file(p);
        std::cout << "regression " << p << " score=" << r.score << " reason=" << r.reason << std::endl;
        // no crash and predictable return
    }

    std::cout << "Detection tests passed" << std::endl;
    return 0;
}
