#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <filesystem>

// Forward declarations from engine.cpp (we link with engine object compiled with HEADER_ONLY)
extern "C" size_t ember_features_from_bytes(const uint8_t* bytes, size_t size, double* out, size_t out_len);

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

        // Use the C wrapper to obtain EMBER features (safe linkage)
        std::vector<double> vec(512, 0.0);
        size_t got = ember_features_from_bytes(data.data(), data.size(), vec.data(), vec.size());

        // Print CSV: path,label,feat0,feat1,...
        std::cout << path << "," << label;
        for (size_t idx = 0; idx < got; ++idx) std::cout << "," << std::fixed << std::setprecision(6) << vec[idx];
        // pad with zeros if needed
        for (size_t idx = got; idx < 512; ++idx) std::cout << ",0.000000";
        std::cout << "\n";
    }

    return 0;
}
