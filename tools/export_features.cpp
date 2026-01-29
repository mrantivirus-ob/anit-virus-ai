#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <filesystem>
#include <cmath>

static double compute_entropy(const std::vector<uint8_t>& data) {
    if (data.empty()) return 0.0;
    std::vector<size_t> freq(256);
    for (uint8_t b : data) freq[b]++;
    double e = 0.0;
    for (size_t f : freq) {
        if (f == 0) continue;
        double p = (double)f / data.size();
        e -= p * std::log2(p);
    }
    return e;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: export_features <label> <file1> [file2 ...]\n";
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

        // Feature vector: 128 dims
        std::vector<double> feat(128, 0.0);

        // 1) grouped byte histogram: 64 groups of 4 bytes
        std::vector<size_t> hist(256, 0);
        for (uint8_t b : data) hist[b]++;
        for (size_t g = 0; g < 64; ++g) {
            size_t start = g * 4;
            double sum = 0.0;
            for (size_t j = 0; j < 4; ++j) sum += hist[start + j];
            feat[g] = data.empty() ? 0.0 : sum / (double)data.size();
        }

        // 2) entropy
        feat[64] = compute_entropy(data) / 8.0; // normalized

        // 3) file size (normalized)
        feat[65] = std::min((double)data.size() / 1e6, 1.0);

        // 4) packing signatures
        std::string s(data.begin(), data.end());
        feat[66] = s.find("UPX") != std::string::npos ? 1.0 : 0.0;
        feat[67] = s.find(".packed") != std::string::npos ? 1.0 : 0.0;

        // 5) suspicious import names (counts)
        int has_getproc = s.find("GetProcAddress") != std::string::npos;
        int has_loadlib = s.find("LoadLibrary") != std::string::npos;
        int has_virtalloc = s.find("VirtualAlloc") != std::string::npos;
        feat[68] = has_getproc;
        feat[69] = has_loadlib;
        feat[70] = has_virtalloc;

        // 6) number of printable strings length>=4
        int strings = 0;
        int cur = 0;
        for (size_t p = 0; p < s.size(); ++p) {
            unsigned char c = s[p];
            if ((c >= 32 && c <= 126)) cur++; else { if (cur >= 4) strings++; cur = 0; }
        }
        feat[71] = std::min(strings, 100) / 100.0;

        // 7) fill rest with zeros or simple aggregates
        double avg_byte = 0.0, max_byte = 0.0;
        for (int b = 0; b < 256; ++b) { avg_byte += hist[b] * b; if (hist[b]) max_byte = std::max(max_byte, (double)hist[b]); }
        if (!data.empty()) avg_byte /= data.size();
        feat[72] = avg_byte / 255.0;
        feat[73] = std::min(max_byte / (double)data.size(), 1.0);

        // remaining features are zeros already

        // Output CSV: path,label,feat0,...
        std::cout << path << "," << label;
        for (double v : feat) std::cout << "," << std::fixed << std::setprecision(6) << v;
        std::cout << "\n";
    }

    return 0;
}
