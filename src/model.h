#pragma once
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace folder_explorer {
struct FileEntry {
    std::filesystem::path relative_path;
    std::uintmax_t size = 0;
    std::filesystem::file_time_type modified{};
    bool directory = false;
    bool symlink = false;
};
struct ExtensionSummary {
    std::wstring extension;
    std::size_t count = 0;
    std::uintmax_t bytes = 0;
};
struct ScanOptions {
    std::size_t item_limit = 100000;
    bool include_directories = true;
};
struct ScanResult {
    std::vector<FileEntry> entries;
    std::vector<ExtensionSummary> extensions;
    std::uintmax_t total_bytes = 0;
    std::size_t files = 0, directories = 0, errors = 0;
    bool cancelled = false, limit_reached = false;
};
using Progress = std::function<void(std::size_t, std::wstring_view)>;
ScanResult ScanFolder(const std::filesystem::path&, ScanOptions,
                      const std::atomic_bool* cancel = nullptr, Progress = {});
bool MatchesFilter(const FileEntry&, std::wstring_view filter);
std::wstring FormatBytes(std::uintmax_t bytes);
}  // namespace folder_explorer
