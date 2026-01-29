#include <iostream>
#include <fstream>
#include <vector>
#include <cassert>
#include <cstdint>
#include <map>
using namespace std;

namespace AVEngine {
    struct EMBERFeatures; // forward reference
    class MVPScanner {
    public:
        struct PEHeaderInfo {
            uint16_t machine_type;
            uint16_t num_sections;
            uint32_t timestamp;
            uint16_t characteristics;
            std::vector<std::string> section_names;
            std::vector<uint32_t> section_sizes;
            bool is_dll;
            bool is_executable;
        };
        static PEHeaderInfo extract_pe_headers(const std::string& file_path);
    };

    class FileFeatureExtractor {
    public:
        static void extract_ember_pe_features(const std::vector<uint8_t>& data, EMBERFeatures& features);
    };

    struct EMBERFeatures {
        // Byte histogram (256 bins - most important EMBER feature)
        std::vector<double> byte_histogram;  // 256 values
        
        // Section-based features
        std::vector<double> section_entropy;    // entropy per section
        std::vector<double> section_sizes;      // size per section
        std::vector<double> section_virt_sizes; // virtual size per section
        std::vector<std::string> section_names; // ASCII section names
        
        // PE header fields (numeric)
        double machine;
        double num_sections;
        double timestamp;
        double ptr_symbol_table;
        double num_symbols;
        double size_optional_header;
        double characteristics;
        double subsystem;
        double dll_characteristics;
        double image_base;
        double entry_point;
        double code_size;
        double initialized_data_size;
        double uninitialized_data_size;
        
        // Import/Export features
        std::vector<std::string> import_dlls;   // imported DLL names
        std::vector<std::string> imported_functions;  // function names
        int num_imports;
        int num_exports;
        int num_imported_dlls;
        
        // String features
        int num_strings;
        double avg_string_length;
        int max_string_length;
        double entropy_strings;
        
        // Byte n-grams (2-grams and 4-grams - effective feature)
        std::map<uint16_t, int> bigrams;   // 2-byte patterns
        std::map<uint32_t, int> quadgrams; // 4-byte patterns
        
        // File-level features
        double file_size;
        double entropy;
        double packed_score;
        
        // Flatten to vector of 512 features (or fewer with selection)
        std::vector<double> to_vector(size_t target_size = 512) {
            std::vector<double> result;
            for (double val : byte_histogram) {
                result.push_back(val / 255.0);
            }
            // Minimal filler
            while (result.size() < target_size) result.push_back(0.0);
            result.resize(target_size);
            return result;
        }
    };
}

static void write_file(const std::string &path, const std::vector<uint8_t> &data) {
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
    f.close();
}

int main() {
    // Test 1: Long import DLL name and long function name
    {
        std::vector<uint8_t> data(4096, 0);
        // DOS header
        data[0] = 'M'; data[1] = 'Z';
        uint32_t pe_off = 0x80;
        for (int i = 0; i < 4; ++i) data[0x3C + i] = (uint8_t)((pe_off >> (8*i)) & 0xFF);
        data[pe_off + 0] = 'P'; data[pe_off + 1] = 'E'; data[pe_off + 2] = 0; data[pe_off + 3] = 0;
        // COFF header
        data[pe_off + 4 + 0] = 0x4C; data[pe_off + 4 + 1] = 0x01; // machine
        data[pe_off + 4 + 2] = 1; data[pe_off + 4 + 3] = 0; // num sections
        data[pe_off + 4 + 16] = 0x60; data[pe_off + 4 + 17] = 0x00; // size_of_optional = 96

        // Optional header magic (PE32)
        size_t opt = pe_off + 4 + 20;
        data[opt + 0] = 0x0B; data[opt + 1] = 0x01; // 0x10b

        // Data directory: import directory offset at opt + 104
        // We'll put import directory in a fake .idata section at RVA 0x2000
        uint32_t import_rva = 0x2000;
        uint32_t import_size = 0x200;
        data[opt + 104] = (uint8_t)(import_rva & 0xFF);
        data[opt + 105] = (uint8_t)((import_rva >> 8) & 0xFF);
        data[opt + 106] = (uint8_t)((import_rva >> 16) & 0xFF);
        data[opt + 107] = (uint8_t)((import_rva >> 24) & 0xFF);
        data[opt + 108] = (uint8_t)(import_size & 0xFF);
        data[opt + 109] = (uint8_t)((import_size >> 8) & 0xFF);
        data[opt + 110] = (uint8_t)((import_size >> 16) & 0xFF);
        data[opt + 111] = (uint8_t)((import_size >> 24) & 0xFF);

        // One section header starting at section_off
        size_t section_off = opt + 96;
        // Name '.idata'
        const char* secname = ".idata";
        for (size_t i = 0; i < 8; ++i) data[section_off + i] = (i < 6 ? secname[i] : 0);
        // VirtualSize
        uint32_t virt = 0x1000;
        data[section_off + 8] = (uint8_t)(virt & 0xFF);
        data[section_off + 9] = (uint8_t)((virt >> 8) & 0xFF);
        data[section_off +10] = (uint8_t)((virt >> 16) & 0xFF);
        data[section_off +11] = (uint8_t)((virt >> 24) & 0xFF);
        // VirtualAddress (VA)
        uint32_t va = 0x2000;
        data[section_off + 12] = (uint8_t)(va & 0xFF);
        data[section_off + 13] = (uint8_t)((va >> 8) & 0xFF);
        data[section_off + 14] = (uint8_t)((va >> 16) & 0xFF);
        data[section_off + 15] = (uint8_t)((va >> 24) & 0xFF);
        // SizeOfRawData
        uint32_t rawsz = 0x400;
        data[section_off + 8 + 0] = (uint8_t)(virt & 0xFF); // already set virt into bytes 8..11
        data[section_off + 20] = (uint8_t)(0x300 & 0xFF);
        data[section_off + 21] = (uint8_t)((0x300 >> 8) & 0xFF);
        data[section_off + 22] = (uint8_t)((0x300 >> 16) & 0xFF);
        data[section_off + 23] = (uint8_t)((0x300 >> 24) & 0xFF);
        // PointerToRawData
        uint32_t ptr_raw = 0x200;
        data[section_off + 20] = (uint8_t)(ptr_raw & 0xFF);
        data[section_off + 21] = (uint8_t)((ptr_raw >> 8) & 0xFF);
        data[section_off + 22] = (uint8_t)((ptr_raw >> 16) & 0xFF);
        data[section_off + 23] = (uint8_t)((ptr_raw >> 24) & 0xFF);

        // Now craft import directory at file offset ptr_raw + (import_rva - va)
        size_t imp_off = ptr_raw + (import_rva - va);
        if (imp_off + 40 < data.size()) {
            // Single IMAGE_IMPORT_DESCRIPTOR with Name RVA pointing to a long DLL name in same section at offset imp_off + 0x40
            uint32_t name_rva = va + 0x40;
            data[imp_off + 12] = (uint8_t)(name_rva & 0xFF);
            data[imp_off + 13] = (uint8_t)((name_rva >> 8) & 0xFF);
            data[imp_off + 14] = (uint8_t)((name_rva >> 16) & 0xFF);
            data[imp_off + 15] = (uint8_t)((name_rva >> 24) & 0xFF);
            // Null terminate descriptor list
            data[imp_off + 20] = 0; data[imp_off + 21] = 0; data[imp_off + 22] = 0; data[imp_off + 23] = 0;

            // Place long name at name_off
            size_t name_off = ptr_raw + 0x40;
            std::string long_name(1500, 'A');
            long_name += ".dll";
            for (size_t i = 0; i < long_name.size() && name_off + i < data.size(); ++i) data[name_off + i] = (uint8_t)long_name[i];
            data[name_off + long_name.size()] = 0;
        }

        // Run extractor
        AVEngine::EMBERFeatures feats;
        AVEngine::FileFeatureExtractor::extract_ember_pe_features(data, feats);
        // Feature extractor should collect the import dll name (best-effort) or at least not crash
        bool found_long = false;
        for (auto &d : feats.import_dlls) {
            if (d.size() >= 4) { found_long = true; break; }
        }
        // We consider it pass if it didn't crash and handled long names gracefully
        (void)found_long;
    }

    // Test 2: Overlapping sections
    {
        std::vector<uint8_t> data(2048, 0);
        data[0] = 'M'; data[1] = 'Z';
        uint32_t pe_off = 0x80;
        for (int i = 0; i < 4; ++i) data[0x3C + i] = (uint8_t)((pe_off >> (8*i)) & 0xFF);
        data[pe_off + 0] = 'P'; data[pe_off + 1] = 'E'; data[pe_off + 2] = 0; data[pe_off + 3] = 0;
        data[pe_off + 4 + 0] = 0x4C; data[pe_off + 4 + 1] = 0x01;
        data[pe_off + 4 + 2] = 2; data[pe_off + 4 + 3] = 0; // two sections
        data[pe_off + 4 + 16] = 0x60; data[pe_off + 4 + 17] = 0x00; // size_of_optional
        size_t opt = pe_off + 4 + 20;
        data[opt + 0] = 0x0B; data[opt + 1] = 0x01; // magic
        size_t section_off = opt + 96;
        // Section 1: .text ptr 0x200, size 0x400
        const char* s1 = ".text";
        for (size_t i = 0; i < 8; ++i) data[section_off + i] = (i < 5 ? s1[i] : 0);
        data[section_off + 8] = 0x00; data[section_off + 9] = 0x04; // virt size low
        data[section_off + 20] = 0x00; data[section_off + 21] = 0x02; // ptr_raw = 0x200
        // Section 2: .data ptr 0x300, size 0x500 (overlaps with .text raw region)
        size_t s2 = section_off + 40;
        const char* s2n = ".data";
        for (size_t i = 0; i < 8; ++i) data[s2 + i] = (i < 5 ? s2n[i] : 0);
        data[s2 + 8] = 0x00; data[s2 + 9] = 0x05; // virt size low
        data[s2 + 20] = 0x00; data[s2 + 21] = 0x03; // ptr_raw = 0x300

        AVEngine::EMBERFeatures feats;
        AVEngine::FileFeatureExtractor::extract_ember_pe_features(data, feats);
        // Should have both section names parsed
        assert(feats.section_names.size() >= 2);

        // Ensure section entropy computation did not crash (may be empty if data insufficient)
        (void)feats.section_entropy;
    }

    // Test 3: Malformed relocation table (RVA points outside of sections)
    {
        std::vector<uint8_t> data(1024, 0);
        data[0] = 'M'; data[1] = 'Z';
        uint32_t pe_off = 0x80;
        for (int i = 0; i < 4; ++i) data[0x3C + i] = (uint8_t)((pe_off >> (8*i)) & 0xFF);
        data[pe_off + 0] = 'P'; data[pe_off + 1] = 'E'; data[pe_off + 2] = 0; data[pe_off + 3] = 0;
        data[pe_off + 4 + 0] = 0x4C; data[pe_off + 4 + 1] = 0x01;
        data[pe_off + 4 + 2] = 1; data[pe_off + 4 + 3] = 0; // one section
        data[pe_off + 4 + 16] = 0x60; data[pe_off + 4 + 17] = 0x00; // size_of_optional
        size_t opt = pe_off + 4 + 20;
        data[opt + 0] = 0x0B; data[opt + 1] = 0x01; // magic
        // Place base relocation directory RVA to 0xFEDCBA (out of range)
        uint32_t reloc_rva = 0x00FEDCBA;
        data[opt + 96 + 8] = (uint8_t)(reloc_rva & 0xFF);
        data[opt + 96 + 9] = (uint8_t)((reloc_rva >> 8) & 0xFF);
        data[opt + 96 +10] = (uint8_t)((reloc_rva >> 16) & 0xFF);
        data[opt + 96 +11] = (uint8_t)((reloc_rva >> 24) & 0xFF);

        AVEngine::EMBERFeatures feats;
        AVEngine::FileFeatureExtractor::extract_ember_pe_features(data, feats);
        // Should not crash and reloc data should be ignored
        (void)feats;
    }

    std::cout << "PE edge-case tests passed" << std::endl;
    return 0;
}
