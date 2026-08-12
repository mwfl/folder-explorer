#include "model.h"
#include <algorithm>
#include <cwctype>
#include <format>

namespace folder_explorer {
namespace {
std::wstring Lower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](wchar_t c) { return std::towlower(c); });
    return value;
}
}  // namespace
ScanResult ScanFolder(const std::filesystem::path& root, ScanOptions options,
                      const std::atomic_bool* cancel, Progress progress) {
    ScanResult result;
    std::map<std::wstring, ExtensionSummary, std::less<>> summaries;
    std::error_code error;
    std::filesystem::recursive_directory_iterator it(
        root, std::filesystem::directory_options::skip_permission_denied, error),
        end;
    if (error) ++result.errors;
    for (; it != end; it.increment(error)) {
        if (cancel && cancel->load(std::memory_order_relaxed)) {
            result.cancelled = true;
            break;
        }
        if (error) {
            ++result.errors;
            error.clear();
            continue;
        }
        if (result.entries.size() >= options.item_limit) {
            result.limit_reached = true;
            break;
        }
        const auto status = it->symlink_status(error);
        if (error) {
            ++result.errors;
            error.clear();
            continue;
        }
        FileEntry entry;
        entry.relative_path = it->path().lexically_relative(root);
        entry.search_path = Lower(entry.relative_path.generic_wstring());
        entry.symlink = std::filesystem::is_symlink(status);
        entry.directory = it->is_directory(error);
        if (error) {
            ++result.errors;
            error.clear();
            entry.directory = false;
        }
        if (entry.symlink && entry.directory) it.disable_recursion_pending();
        if (entry.directory) {
            ++result.directories;
            if (!options.include_directories) continue;
        } else if (std::filesystem::is_regular_file(status)) {
            entry.size = it->file_size(error);
            if (error) {
                ++result.errors;
                error.clear();
                entry.size = 0;
            }
            entry.modified = it->last_write_time(error);
            error.clear();
            ++result.files;
            result.total_bytes += entry.size;
            auto extension = Lower(it->path().extension().wstring());
            if (extension.empty()) extension = L"(no extension)";
            auto& item = summaries[extension];
            item.extension = extension;
            ++item.count;
            item.bytes += entry.size;
        } else
            continue;
        result.entries.push_back(std::move(entry));
        if (progress && result.entries.size() % 512 == 0)
            progress(result.entries.size(), result.entries.back().relative_path.generic_wstring());
    }
    for (auto& [key, value] : summaries) {
        static_cast<void>(key);
        result.extensions.push_back(std::move(value));
    }
    std::ranges::sort(result.extensions,
                      [](const auto& a, const auto& b) { return a.count > b.count; });
    return result;
}
bool MatchesFilter(const FileEntry& entry, std::wstring_view filter) {
    if (filter.empty()) return true;
    return MatchesNormalizedFilter(entry, NormalizeFilter(filter));
}
bool MatchesNormalizedFilter(const FileEntry& entry, std::wstring_view normalized_filter) {
    if (normalized_filter.empty()) return true;
    const auto& path = entry.search_path.empty() ? entry.relative_path.native() : entry.search_path;
    return path.find(normalized_filter) != std::wstring::npos;
}
std::wstring NormalizeFilter(std::wstring_view filter) {
    return Lower(std::wstring(filter));
}
std::wstring FormatBytes(std::uintmax_t bytes) {
    if (bytes >= 1024ull * 1024 * 1024)
        return std::format(L"{:.2f} GB", bytes / (1024.0 * 1024 * 1024));
    if (bytes >= 1024ull * 1024) return std::format(L"{:.2f} MB", bytes / (1024.0 * 1024));
    if (bytes >= 1024) return std::format(L"{:.1f} KB", bytes / 1024.0);
    return std::to_wstring(bytes) + L" B";
}
}  // namespace folder_explorer
