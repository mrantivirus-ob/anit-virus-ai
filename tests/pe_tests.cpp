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

        // Do not declare main in production code; test only uses extract_pe_headers here.
    };
}

int main() {
    const std::string path = "tests/test_min_pe.bin";

    // Build a minimal PE file in memory
    std::vector<uint8_t> data(512, 0);
    // DOS header 'MZ'
    data[0] = 'M'; data[1] = 'Z';
    // e_lfanew -> 0x80
    uint32_t pe_off = 0x80;
    data[0x3C] = (uint8_t)(pe_off & 0xFF);
    data[0x3D] = (uint8_t)((pe_off >> 8) & 0xFF);
    data[0x3E] = (uint8_t)((pe_off >> 16) & 0xFF);
    data[0x3F] = (uint8_t)((pe_off >> 24) & 0xFF);

    // Ensure buffer covers pe_off + headers
    if (data.size() < pe_off + 64) data.resize(pe_off + 256, 0);

    // PE signature
    data[pe_off + 0] = 'P'; data[pe_off + 1] = 'E'; data[pe_off + 2] = 0; data[pe_off + 3] = 0;

    // COFF header:
    // Machine (Intel 386 = 0x014c)
    data[pe_off + 4 + 0] = 0x4C; data[pe_off + 4 + 1] = 0x01;
    // NumberOfSections = 1
    data[pe_off + 4 + 2] = 1; data[pe_off + 4 + 3] = 0;
    // TimeDateStamp
    data[pe_off + 4 + 4] = 1; data[pe_off + 4 + 5] = 0; data[pe_off + 4 + 6] = 0; data[pe_off + 4 + 7] = 0;
    // SizeOfOptionalHeader = 0 (for simplicity)
    data[pe_off + 4 + 16] = 0; data[pe_off + 4 + 17] = 0;
    // Characteristics = 0x0002 (executable)
    data[pe_off + 4 + 18] = 0x02; data[pe_off + 4 + 19] = 0x00;

    // Section header (starts immediately after COFF+Optional)
    size_t section_off = pe_off + 4 + 20;
    // Name '.text' padded to 8
    const char* name = ".text";
    for (size_t i = 0; i < 8; ++i) {
        data[section_off + i] = (i < 5) ? name[i] : 0;
    }
    // VirtualSize
    uint32_t virt_size = 0x1000;
    data[section_off + 8] = (uint8_t)(virt_size & 0xFF);
    data[section_off + 9] = (uint8_t)((virt_size >> 8) & 0xFF);
    data[section_off +10] = (uint8_t)((virt_size >> 16) & 0xFF);
    data[section_off +11] = (uint8_t)((virt_size >> 24) & 0xFF);

    // Write file
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
    f.close();

    // Parse with MVPScanner
    auto pe_info = AVEngine::MVPScanner::extract_pe_headers(path);
    assert(pe_info.num_sections == 1);
    assert(pe_info.section_names.size() >= 1);
    assert(pe_info.section_names[0].find(".text") != std::string::npos);
    assert(pe_info.machine_type == 0x014c);

    // Truncated PE: should not crash and return empty/zero fields
    const std::string path2 = "tests/test_truncated_pe.bin";
    std::ofstream f2(path2, std::ios::binary);
    char mz[2] = {'M', 'Z'};
    f2.write(mz, 2);
    f2.close();

    auto pe_info2 = AVEngine::MVPScanner::extract_pe_headers(path2);
    assert(pe_info2.num_sections == 0);
    assert(pe_info2.section_names.size() == 0);

    std::cout << "PE parser unit tests passed" << std::endl;
    return 0;
}
