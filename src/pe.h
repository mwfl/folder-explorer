#pragma once
#include <filesystem>
#include <string>
#include <vector>
namespace folder_explorer {
struct PeInfo {
    bool is_pe = false, is_64_bit = false, signature_valid = false;
    std::wstring machine, description, company, product, version, signature_status;
    std::vector<std::wstring> imports;
    std::wstring error;
};
PeInfo InspectPe(const std::filesystem::path& path);
PeInfo InspectPe(const std::filesystem::path& path, bool verify_signature);
std::wstring DescribePe(const PeInfo& info);
}  // namespace folder_explorer
