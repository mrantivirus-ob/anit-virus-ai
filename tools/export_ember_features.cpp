#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <filesystem>

// We call the engine's C++ extractor directly when compiling alongside engine.cpp
// (this avoids subtle C-wrapper linkage issues in some CI toolchains)

namespace AVEngine {
    struct EMBERFeatures {
        std::vector<double> to_vector(size_t target_size = 512);
    };
    class FileFeatureExtractor {
    public:
        static void extract_ember_pe_features(const std::vector<uint8_t>& data, EMBERFeatures& features);
    };
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: export_ember_features <label> <file1> [file2 ...]\n";
        std::cerr << "  label: 0 (benign) or 1 (malware)\n";
        return 1;
    }

    int label = std::stoi(argv[1]);

    for (int i = 2; i < argc; ++i) {
        const std::string path = argv[i];
        std::ifstream f(path, std::ios::binary);
        if (!f) {
            std::cerr << "Failed to open: " << path << " (skipping)\n";
            continue;
        }
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

        // Use the engine's C++ API directly (we compile with engine.cpp so this is available)
        AVEngine::EMBERFeatures feats;
        AVEngine::FileFeatureExtractor::extract_ember_pe_features(data, feats);
        auto vec = feats.to_vector(512);
        size_t got = vec.size();

        // Print CSV: path,label,feat0,feat1,...
        std::cout << path << "," << label;
        for (size_t idx = 0; idx < got; ++idx) std::cout << "," << std::fixed << std::setprecision(6) << vec[idx];
        // pad with zeros if needed
        for (size_t idx = got; idx < 512; ++idx) std::cout << ",0.000000";
        std::cout << "\n";
    }

    return 0;
}
