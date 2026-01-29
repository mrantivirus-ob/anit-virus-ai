#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Lightweight harness: call extract_pe_headers by writing buffer to a temp file
    std::vector<uint8_t> v(data, data + size);
    std::string tmp = "/tmp/fuzz_pe_input.bin";
    FILE *f = fopen(tmp.c_str(), "wb");
    if (!f) return 0;
    fwrite(v.data(), 1, v.size(), f);
    fclose(f);

    // Call into the engine functions; use their fully qualified names to avoid includes
    namespace AVEngine2 = AVEngine; // rely on engine.cpp providing symbols at link time
    AVEngine2::MVPScanner::PEHeaderInfo info = AVEngine2::MVPScanner::extract_pe_headers(tmp);
    (void)info;

    // Call the memory-only extractor if available
    try {
        auto feats = AVEngine2::FileFeatureExtractor::extract_ember_pe_features(v);
        (void)feats;
    } catch(...) {}

    return 0;
}
