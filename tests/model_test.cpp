#include "../src/model.h"
#include <windows.h>
#include <fstream>
#include <iostream>
#include "../src/pe.h"

int wmain() {
    const auto root = std::filesystem::temp_directory_path() /
                      (L"folder-explorer-test-" + std::to_wstring(::GetCurrentProcessId()));
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root / L"bin");
    {
        std::ofstream(root / L"readme.txt") << "hello";
        std::ofstream(root / L"bin/a.dll") << "not pe";
        std::ofstream(root / L"bin/b.dll") << "other";
    }
    const auto result = folder_explorer::ScanFolder(root, {100, true});
    if (result.files != 3 || result.directories != 1 || result.total_bytes != 16 ||
        result.extensions.empty())
        return 1;
    const auto found = std::ranges::find_if(
        result.entries, [](const auto& e) { return e.relative_path.filename() == L"readme.txt"; });
    if (found == result.entries.end() || !folder_explorer::MatchesFilter(*found, L"README") ||
        folder_explorer::MatchesFilter(*found, L"dll"))
        return 2;
    const auto limited = folder_explorer::ScanFolder(root, {2, true});
    if (!limited.limit_reached || limited.entries.size() != 2) return 3;
    std::atomic_bool cancel{true};
    if (!folder_explorer::ScanFolder(root, {100, true}, &cancel).cancelled) return 4;
    wchar_t executable[MAX_PATH]{};
    ::GetModuleFileNameW(nullptr, executable, MAX_PATH);
    const auto pe = folder_explorer::InspectPe(executable);
    if (!pe.is_pe || pe.machine.empty() || pe.signature_status.empty()) return 5;
    const auto fast_pe = folder_explorer::InspectPe(executable, false);
    if (!fast_pe.is_pe || fast_pe.signature_status != L"Not checked during folder summary")
        return 6;
    std::filesystem::remove_all(root, ec);
    std::wcout << L"folder explorer model tests passed\n";
    return 0;
}
