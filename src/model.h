#pragma once
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace folder_explorer {
// search_path is a normalized projection used to filter a snapshot cheaply.
struct FileEntry {
    std::filesystem::path relative_path;
    std::wstring search_path;
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
    // Reaching the cap returns a usable partial result with limit_reached set.
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
// Synchronous worker operation. Progress stays off the UI thread; directory
// symlinks are inventoried but not traversed, preventing cycles.
ScanResult ScanFolder(const std::filesystem::path&, ScanOptions,
                      const std::atomic_bool* cancel = nullptr, Progress = {});
bool MatchesFilter(const FileEntry&, std::wstring_view filter);
bool MatchesNormalizedFilter(const FileEntry&, std::wstring_view normalized_filter);
std::wstring NormalizeFilter(std::wstring_view filter);
std::wstring FormatBytes(std::uintmax_t bytes);
}  // namespace folder_explorer
