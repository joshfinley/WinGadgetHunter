#include <Windows.h>
#undef min
#include <iostream>
#include <filesystem>
#include <cstdint>
#include <vector>
#include <utility>
#include <optional>
#include <iomanip>
#include <algorithm>
#include <stdexcept>
#include <sstream>
#include <string>

// Define an optional byte type to use for wildcards
using OptByte = std::optional<uint8_t>;

// Function to parse the pattern string into bytes or wildcards (*)
std::vector<OptByte> parse_pattern_string(const std::string& pattern_str) {
    std::vector<OptByte> pattern;  // Vector to hold the pattern
    std::istringstream iss(pattern_str);  // String stream for parsing
    std::string byte_str;  // Temporary string to hold each byte representation

    // Loop through each space-separated part of the pattern string
    while (iss >> byte_str) {
        if (byte_str == "*") {
            // Wildcard: push a nullopt into the pattern
            pattern.push_back(std::nullopt);
        }
        else {
            // Byte value: convert hex string to integer and push it into the pattern
            uint8_t byte = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
            pattern.push_back(byte);
        }
    }
    return pattern;
}

// Function to find all pattern matches in a block of data
std::vector<size_t> find_all_matches(const std::vector<uint8_t>& data, const std::vector<OptByte>& pattern) {
    std::vector<size_t> matches;  // Vector to hold match positions

    // Handling edge cases
    if (pattern.empty() || data.empty() || pattern.size() > data.size()) {
        return matches;
    }

    // Main loop for finding matches
    for (size_t i = 0; i <= data.size() - pattern.size(); ) {
        bool match = true;  // Assume a match until proven otherwise

        // Check each byte against the pattern
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (pattern[j].has_value() && pattern[j].value() != data[i + j]) {
                match = false;  // Pattern does not match
                break;
            }
        }

        if (match) {
            // If match found, store the start index
            matches.push_back(i);

            // Move just past this match for the next iteration
            i += pattern.size();
        }
        else {
            // If not a match, move one byte forward
            ++i;
        }
    }

    return matches;
}


// Struct to hold base address and size of a code section
struct CodeBuffer {
    uint8_t* base_address;
    size_t size;
};

// Function to get the .text (code) section of a loaded DLL
std::optional<CodeBuffer> get_code_section(HMODULE mod_base) {
    if (mod_base == nullptr) return std::nullopt;

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(mod_base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return std::nullopt;
    }

    auto nth = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<PBYTE>(mod_base) + dos->e_lfanew);
    if (nth->Signature != IMAGE_NT_SIGNATURE) {
        return std::nullopt;
    }

    auto section = IMAGE_FIRST_SECTION(nth);
    for (WORD i = 0; i < nth->FileHeader.NumberOfSections; ++i, ++section) {
        if (std::memcmp(section->Name, ".text", 5) == 0) {
            auto base_address = reinterpret_cast<uint8_t*>(
                reinterpret_cast<uintptr_t>(mod_base) + section->PointerToRawData);
            return CodeBuffer{ base_address, section->SizeOfRawData };
        }
    }

    return std::nullopt;
}

// Function to get terminal width, useful for formatting
int get_terminal_width() {
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (!GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)) {
        return 80;  // Fallback to default if unable to get info
    }
    return csbi.srWindow.Right - csbi.srWindow.Left + 1;
}

// Function to print a pattern match, including bytes around it
void print_match(const std::vector<uint8_t>& data, size_t start_idx, size_t match_len, const std::filesystem::path& dll_path) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    const WORD REGULAR_COLOR = 15;  // White
    const WORD HIGHLIGHT_COLOR = 12; // Red

    if (start_idx + match_len > data.size()) {
        std::cerr << "Invalid start index or match length." << std::endl;
        return;
    }

    // Extract and print the DLL base name
    std::cout << std::filesystem::path(dll_path).filename().string() << "+0x" << std::hex << start_idx << ": ";

    // Calculate how many bytes we can fit
    int term_width = get_terminal_width();
    int max_bytes = (term_width - std::filesystem::path(dll_path).filename().string().length() - 11) / 3; // 3 characters per byte "FF "

    int preceding_bytes = std::min(4, static_cast<int>(start_idx));
    int following_bytes = std::min(max_bytes - preceding_bytes - static_cast<int>(match_len), static_cast<int>(data.size() - start_idx - match_len));

    // Print preceding bytes in regular color
    SetConsoleTextAttribute(hConsole, REGULAR_COLOR);
    for (int i = static_cast<int>(start_idx) - preceding_bytes; i < static_cast<int>(start_idx); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]) << ' ';
    }

    // Print the matching bytes in red
    SetConsoleTextAttribute(hConsole, HIGHLIGHT_COLOR);
    for (size_t i = 0; i < match_len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[start_idx + i]) << ' ';
    }

    // Print the following bytes in regular color
    SetConsoleTextAttribute(hConsole, REGULAR_COLOR);
    for (int i = 1; i <= following_bytes; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[start_idx + match_len + i - 1]) << ' ';
    }

    std::cout << std::endl;

    // Reset console color
    SetConsoleTextAttribute(hConsole, REGULAR_COLOR);
}

int main(int argc, char* argv[]) {
    // Check for proper usage
    if (argc < 2) {
        std::cerr << "Usage: WinGadgetHunter.exe <pattern> [-i <path>]\n";
        return 1;
    }

    try {
        // Parse the search pattern
        std::string pattern_str = argv[1];
        std::vector<OptByte> pattern = parse_pattern_string(pattern_str);

        // Define the default path or get it from arguments
        std::filesystem::path path_to_check = "C:\\Windows\\System32";  // default path
        if (argc >= 4 && std::string(argv[2]) == "-i") {
            path_to_check = argv[3];
        }

        // Check if is a file or directory and either loop over files and match
        // or just match against the single file
        if (std::filesystem::is_directory(path_to_check)) {
            for (const auto& entry : std::filesystem::directory_iterator(path_to_check)) {
                if (entry.path().extension() == ".dll") {
                    HMODULE hModule = LoadLibraryExA(entry.path().string().c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE);
                    if (hModule) {
                        if (auto code = get_code_section(hModule); code) {
                            std::vector<uint8_t> dll_data(code->base_address, code->base_address + code->size);
                            auto matches = find_all_matches(dll_data, pattern);
                            for (auto match : matches) {
                                print_match(dll_data, match, pattern.size(), entry.path());
                            }
                        }
                        FreeLibrary(hModule);
                    }
                }
            }
        }
        else if (std::filesystem::is_regular_file(path_to_check) && path_to_check.extension() == ".dll") {
            HMODULE hModule = LoadLibraryExA(path_to_check.string().c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE);
            if (hModule) {
                if (auto code = get_code_section(hModule); code) {
                    std::vector<uint8_t> dll_data(code->base_address, code->base_address + code->size);
                    auto matches = find_all_matches(dll_data, pattern);
                    for (auto match : matches) {
                        print_match(dll_data, match, pattern.size(), path_to_check);
                    }
                }
                FreeLibrary(hModule);
            }
        }
        else {
            std::cerr << "Invalid path specified. Must be a DLL or directory containing DLLs.\n";
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }
}