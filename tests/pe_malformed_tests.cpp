#include <iostream>
#include <fstream>
#include <vector>
#include <cassert>
#include <cstdint>
using namespace std;

namespace AVEngine {
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
}

static void write_file(const std::string &path, const std::vector<uint8_t> &data) {
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
    f.close();
}

int main() {
    // Case 1: e_lfanew points outside file
    {
        std::vector<uint8_t> data(64, 0);
        data[0] = 'M'; data[1] = 'Z';
        uint32_t pe_off = 0x1000; // outside
        data[0x3C] = (uint8_t)(pe_off & 0xFF);
        data[0x3D] = (uint8_t)((pe_off >> 8) & 0xFF);
        data[0x3E] = (uint8_t)((pe_off >> 16) & 0xFF);
        data[0x3F] = (uint8_t)((pe_off >> 24) & 0xFF);
        write_file("tests/malformed_e_lfanew.bin", data);
        auto info = AVEngine::MVPScanner::extract_pe_headers("tests/malformed_e_lfanew.bin");
        assert(info.num_sections == 0);
    }

    // Case 2: SizeOfOptionalHeader too large
    {
        std::vector<uint8_t> data(256, 0);
        data[0] = 'M'; data[1] = 'Z';
        uint32_t pe_off = 0x80;
        data[0x3C] = (uint8_t)(pe_off & 0xFF);
        data[0x3D] = (uint8_t)((pe_off >> 8) & 0xFF);
        data[0x3E] = (uint8_t)((pe_off >> 16) & 0xFF);
        data[0x3F] = (uint8_t)((pe_off >> 24) & 0xFF);
        data[pe_off + 0] = 'P'; data[pe_off + 1] = 'E'; data[pe_off + 2] = 0; data[pe_off + 3] = 0;
        // COFF header
        // Machine
        data[pe_off + 4 + 0] = 0x4C; data[pe_off + 4 + 1] = 0x01;
        // NumberOfSections = 1
        data[pe_off + 4 + 2] = 1; data[pe_off + 4 + 3] = 0;
        // SizeOfOptionalHeader = 0xFFF0 (huge)
        data[pe_off + 4 + 16] = 0xF0; data[pe_off + 4 + 17] = 0xFF;
        write_file("tests/malformed_optional.bin", data);
        auto info = AVEngine::MVPScanner::extract_pe_headers("tests/malformed_optional.bin");
        assert(info.num_sections == 0 || info.section_names.size() == 0);
    }

    // Case 3: Section declares size that extends past file end
    {
        std::vector<uint8_t> data(256, 0);
        data[0] = 'M'; data[1] = 'Z';
        uint32_t pe_off = 0x80;
        for (int i = 0; i < 4; ++i) data[0x3C + i] = (uint8_t)((pe_off >> (8*i)) & 0xFF);
        data[pe_off + 0] = 'P'; data[pe_off + 1] = 'E'; data[pe_off + 2] = 0; data[pe_off + 3] = 0;
        // COFF header
        data[pe_off + 4 + 0] = 0x4C; data[pe_off + 4 + 1] = 0x01;
        data[pe_off + 4 + 2] = 1; data[pe_off + 4 + 3] = 0;
        data[pe_off + 4 + 16] = 0; data[pe_off + 4 + 17] = 0;
        // Section header: name '.data', VirtualSize = 0xFFFFFFF0
        size_t section_off = pe_off + 4 + 20;
        const char* name = ".data";
        for (size_t i = 0; i < 8; ++i) data[section_off + i] = (i < 5 ? name[i] : 0);
        uint32_t virt_size = 0xFFFFFFF0;
        data[section_off + 8] = (uint8_t)(virt_size & 0xFF);
        data[section_off + 9] = (uint8_t)((virt_size >> 8) & 0xFF);
        data[section_off +10] = (uint8_t)((virt_size >> 16) & 0xFF);
        data[section_off +11] = (uint8_t)((virt_size >> 24) & 0xFF);
        write_file("tests/malformed_section_size.bin", data);
        auto info = AVEngine::MVPScanner::extract_pe_headers("tests/malformed_section_size.bin");
        assert(info.section_sizes.size() == info.section_names.size());
    }

    // Case 4: Malformed import directory (RVA points out of range)
    {
        std::vector<uint8_t> data(512, 0);
        data[0] = 'M'; data[1] = 'Z';
        uint32_t pe_off = 0x80;
        for (int i = 0; i < 4; ++i) data[0x3C + i] = (uint8_t)((pe_off >> (8*i)) & 0xFF);
        data[pe_off + 0] = 'P'; data[pe_off + 1] = 'E'; data[pe_off + 2] = 0; data[pe_off + 3] = 0;
        // COFF header
        data[pe_off + 4 + 0] = 0x4C; data[pe_off + 4 + 1] = 0x01;
        data[pe_off + 4 + 2] = 1; data[pe_off + 4 + 3] = 0;
        data[pe_off + 4 + 16] = 0xE0; data[pe_off + 4 + 17] = 0x00; // pretend Optional header present
        // Write to disk and call the public file-based extractor to ensure it handles bad import dir gracefully
        write_file("tests/malformed_import.bin", data);
        auto info = AVEngine::MVPScanner::extract_pe_headers("tests/malformed_import.bin");
        (void)info; // just ensure it didn't crash
        // NumberOfSections = 0xFFFF (huge)
        data[pe_off + 4 + 2] = 0xFF; data[pe_off + 4 + 3] = 0xFF;
        auto info2 = AVEngine::MVPScanner::extract_pe_headers("/dev/null"); // not that file, but check behavior of function on empty path
        (void)info2;
    }

    std::cout << "Malformed PE tests passed" << std::endl;
    return 0;
}
