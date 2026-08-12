#include <atomic>
#include <filesystem>
#include <format>
#include <map>
#include <memory>
#include <mutex>
#include <mwfl/mwfl.h>
#include <optional>
#include <shellapi.h>
#include <thread>
#include <vector>
#include "ai.h"
#include "model.h"
#include "pe.h"

using mwfl::operator""_dip;
namespace {
constexpr mwfl::ControlId kOpen{100}, kCancel{101}, kContinue{102}, kFilter{103}, kList{104},
    kInspect{105}, kGoogle{106}, kTool{107}, kReveal{108}, kAi{109}, kProvider{110},
    kDependencies{111};

std::wstring UrlEncode(std::wstring_view value) {
    const int size = ::WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                                           nullptr, 0, nullptr, nullptr);
    std::string utf8(static_cast<std::size_t>(size), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), utf8.data(),
                          size, nullptr, nullptr);
    constexpr wchar_t hex[] = L"0123456789ABCDEF";
    std::wstring encoded;
    for (const unsigned char c : utf8) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~')
            encoded.push_back(static_cast<wchar_t>(c));
        else {
            encoded.push_back(L'%');
            encoded.push_back(hex[c >> 4]);
            encoded.push_back(hex[c & 15]);
        }
    }
    return encoded;
}

class FileListModel final : public mwfl::VirtualListModel {
   public:
    void Set(std::shared_ptr<const folder_explorer::ScanResult> result, std::wstring filter) {
        result_ = std::move(result);
        rows_.clear();
        const auto normalized = folder_explorer::NormalizeFilter(filter);
        if (result_)
            for (std::size_t i = 0; i < result_->entries.size(); ++i)
                if (folder_explorer::MatchesNormalizedFilter(result_->entries[i], normalized))
                    rows_.push_back(i);
    }
    std::size_t GetRowCount() const noexcept override { return rows_.size(); }
    std::size_t VisibleCount() const noexcept { return rows_.size(); }
    mwfl::ListItemId GetRowId(std::size_t row) const noexcept override {
        return row < rows_.size() ? mwfl::ListItemId{rows_[row] + 1} : mwfl::ListItemId{};
    }
    std::wstring GetCellText(std::size_t row, int column) const override {
        if (!result_ || row >= rows_.size()) return {};
        const auto& e = result_->entries[rows_[row]];
        switch (column) {
            case 0:
                return e.relative_path.generic_wstring();
            case 1:
                return e.directory ? L"Folder" : e.relative_path.extension().wstring();
            case 2:
                return e.directory ? L"" : folder_explorer::FormatBytes(e.size);
            case 3:
                return e.symlink ? L"Link" : e.directory ? L"Folder" : L"File";
            default:
                return {};
        }
    }
    const folder_explorer::FileEntry* GetById(mwfl::ListItemId id) const noexcept {
        if (!result_ || id.value == 0 || id.value > result_->entries.size()) return nullptr;
        return &result_->entries[id.value - 1];
    }

   private:
    std::shared_ptr<const folder_explorer::ScanResult> result_;
    std::vector<std::size_t> rows_;
};

class MainWindow final : public mwfl::WindowBase {
   public:
    ~MainWindow() noexcept override {
        cancel_.store(true);
        if (worker_.joinable()) worker_.join();
    }
    void BuildUI() override {
        SetTitle(L"Folder Explorer — understand an installation folder");
        mwfl::ControlHost ui{*this};
        ui.Add(open_, kOpen, L"Open…");
        ui.Add(cancel_button_, kCancel, L"Cancel");
        ui.Add(continue_button_, kContinue, L"Continue: 500k");
        ui.Add(filter_, kFilter, L"");
        ui.Add(inspect_, kInspect, L"Inspect");
        ui.Add(google_, kGoogle, L"Search");
        ui.Add(tool_, kTool, L"PE tool…");
        ui.Add(reveal_, kReveal, L"Reveal");
        ui.Add(dependencies_, kDependencies, L"Libraries");
        ui.Add(ai_, kAi, L"Ask AI");
        ui.Add(provider_, kProvider, L"AI: Ollama");
        ui.Add(host_, L"http://127.0.0.1:11434");
        ui.Add(model_name_, L"llama3.2");
        mwfl::TextBoxOptions key_options;
        key_options.style |= ES_PASSWORD;
        ui.Add(api_key_, L"", key_options);
        ui.Add(pe_tool_, L"");
        ui.Add(summary_,
               L"Open a folder to scan it recursively. Nothing is "
               L"uploaded automatically.");
        ui.Add(extensions_, L"Extension summary will appear here.");
        ui.Add(list_, kList, mwfl::ListViewOptions{.virtual_data = true});
        mwfl::TextBoxOptions detail_options;
        detail_options.style |= ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL | ES_READONLY;
        ui.Add(detail_, L"Select a file, then inspect or ask AI.", detail_options);
        filter_.SetCueBanner(L"Filter by any part of the relative path");
        host_.SetCueBanner(L"AI host");
        model_name_.SetCueBanner(L"Model");
        api_key_.SetCueBanner(L"API key (kept in memory only)");
        pe_tool_.SetCueBanner(L"Optional PE tool executable path");
        list_.SetExtendedListStyle(LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER |
                                   LVS_EX_HEADERDRAGDROP | LVS_EX_GRIDLINES);
        mwfl::Must(
            mwfl::AddColumns(
                list_,
                {{L"Relative path", 520}, {L"Extension", 105}, {L"Size", 100}, {L"Kind", 80}}),
            "add columns");
        model_ = std::make_shared<FileListModel>();
        mwfl::Must(list_.SetVirtualModel(model_), "attach model");
        for (const auto& [hwnd, name] : std::initializer_list<std::pair<HWND, const wchar_t*>>{
                 {filter_.GetHwnd(), L"File name filter"},
                 {list_.GetHwnd(), L"Folder contents"},
                 {detail_.GetHwnd(), L"File details and AI result"},
                 {api_key_.GetHwnd(), L"AI API key"}})
            mwfl::Must(mwfl::SetAccessibleName(hwnd, name), "set accessible name");
        SetLayout(mwfl::Column()
                      .Margin(8.0_dip)
                      .Gap(6.0_dip)
                      .Add(mwfl::Row()
                               .Gap(6.0_dip)
                               .Add(open_, mwfl::Auto())
                               .Add(cancel_button_, mwfl::Auto())
                               .Add(continue_button_, mwfl::Auto())
                               .Add(filter_, mwfl::Stretch()),
                           mwfl::Auto())
                      .Add(mwfl::Row()
                               .Gap(6.0_dip)
                               .Add(inspect_, mwfl::Auto())
                               .Add(google_, mwfl::Auto())
                               .Add(tool_, mwfl::Auto())
                               .Add(reveal_, mwfl::Auto())
                               .Add(dependencies_, mwfl::Auto())
                               .Add(ai_, mwfl::Auto())
                               .Add(provider_, mwfl::Auto()),
                           mwfl::Auto())
                      .Add(mwfl::Row()
                               .Gap(6.0_dip)
                               .Add(host_, mwfl::Stretch())
                               .Add(model_name_, mwfl::Fixed(150.0_dip))
                               .Add(api_key_, mwfl::Fixed(190.0_dip))
                               .Add(pe_tool_, mwfl::Stretch()),
                           mwfl::Auto())
                      .Add(summary_, mwfl::Auto())
                      .Add(extensions_, mwfl::Auto())
                      .Add(mwfl::Row()
                               .Gap(6.0_dip)
                               .Add(list_, mwfl::Stretch())
                               .Add(detail_, mwfl::Fixed(480.0_dip),
                                    {.native_size = mwfl::SizeDip{480.0_dip, 0.0_dip}}),
                           mwfl::Stretch()));
        cancel_button_.SetEnabled(false);
        continue_button_.SetEnabled(false);
        SetFileActionsEnabled(false);
        mwfl::EnableFileDrop(GetHwnd());
        mwfl::ApplyWindowAppearance(GetHwnd());
    }
    mwfl::EventResult OnCommand(const mwfl::CommandEvent& e) override {
        if (e.IsClicked(open_)) {
            const auto r = mwfl::ShowFolderDialog(
                {.owner = GetHwnd(), .title = L"Choose an installation or application folder"});
            if (r.accepted) StartScan(r.path, 100000);
            return mwfl::EventResult::Handled();
        }
        if (e.IsClicked(cancel_button_)) {
            cancel_.store(true);
            summary_.SetText(L"Cancelling…");
            return mwfl::EventResult::Handled();
        }
        if (e.IsClicked(continue_button_)) {
            StartScan(root_, 500000);
            return mwfl::EventResult::Handled();
        }
        if (e.Is(filter_, EN_CHANGE)) {
            ApplyFilter();
            ShowSummary();
            return mwfl::EventResult::Handled();
        }
        if (e.IsClicked(inspect_)) {
            InspectSelected();
            return mwfl::EventResult::Handled();
        }
        if (e.IsClicked(google_)) {
            SearchSelected();
            return mwfl::EventResult::Handled();
        }
        if (e.IsClicked(tool_)) {
            OpenTool();
            return mwfl::EventResult::Handled();
        }
        if (e.IsClicked(reveal_)) {
            RevealSelected();
            return mwfl::EventResult::Handled();
        }
        if (e.IsClicked(dependencies_)) {
            SummarizeDependencies();
            return mwfl::EventResult::Handled();
        }
        if (e.IsClicked(ai_)) {
            StartAi();
            return mwfl::EventResult::Handled();
        }
        if (e.IsClicked(provider_)) {
            provider_.SetText(provider_.GetText().find(L"Ollama") != std::wstring::npos
                                  ? L"AI: OpenAI"
                                  : L"AI: Ollama");
            return mwfl::EventResult::Handled();
        }
        return mwfl::EventResult::Propagate();
    }
    mwfl::EventResult OnNotify(const mwfl::NotifyEvent& e) override {
        if (e.IsFrom(list_)) {
            LRESULT result = 0;
            if (list_.HandleNotification(e.header, result)) {
                if (list_.TakeVirtualException())
                    detail_.SetText(L"The file list could not render one or more rows safely.");
                return mwfl::EventResult::Handled(result);
            }
            if (const auto n = list_.DecodeNotification(e.header);
                n && n->kind == mwfl::ListViewNotificationKind::activated) {
                InspectSelected();
                return mwfl::EventResult::Handled();
            }
        }
        return mwfl::EventResult::Propagate();
    }
    mwfl::EventResult OnMessage(const mwfl::WindowMessage& e) override {
        if (e.id == WM_DROPFILES) {
            const auto files = mwfl::ReadDroppedFiles(reinterpret_cast<HDROP>(e.wparam));
            std::error_code ec;
            if (!files.empty() && std::filesystem::is_directory(files[0], ec) && !ec)
                StartScan(files[0], 100000);
            return mwfl::EventResult::Handled();
        }
        if (e.id == WM_THEMECHANGED || e.id == WM_SETTINGCHANGE) {
            mwfl::ApplyWindowAppearance(GetHwnd());
            return mwfl::EventResult::Handled();
        }
        return mwfl::EventResult::Propagate();
    }
    mwfl::EventResult OnWakeup() noexcept override {
        try {
            std::optional<folder_explorer::ScanResult> scan;
            std::optional<folder_explorer::AiResponse> ai;
            std::optional<std::wstring> detail;
            std::wstring progress, failure;
            {
                std::scoped_lock lock(mutex_);
                scan = std::move(pending_scan_);
                pending_scan_.reset();
                ai = std::move(pending_ai_);
                pending_ai_.reset();
                detail = std::move(pending_detail_);
                pending_detail_.reset();
                progress = std::move(progress_);
                progress_.clear();
                failure = std::move(pending_failure_);
                pending_failure_.clear();
            }
            if (!failure.empty()) {
                FinishWorker();
                summary_.SetText(failure);
                detail_.SetText(failure);
            } else if (scan) {
                result_ = std::make_shared<folder_explorer::ScanResult>(std::move(*scan));
                FinishWorker();
                ApplyFilter();
                ShowSummary();
            } else if (ai) {
                FinishWorker();
                detail_.SetText(ai->error.empty() ? ai->text : ai->error);
            } else if (detail) {
                FinishWorker();
                detail_.SetText(*detail);
            } else if (!progress.empty())
                summary_.SetText(progress);
        } catch (...) {
            summary_.SetText(L"Background operation failed safely.");
        }
        return mwfl::EventResult::Handled();
    }

   private:
    void FinishWorker() {
        if (worker_.joinable()) worker_.join();
        busy_ = false;
        open_.SetEnabled(true);
        cancel_button_.SetEnabled(false);
        SetFileActionsEnabled(result_ != nullptr);
    }
    void SetFileActionsEnabled(bool enabled) {
        inspect_.SetEnabled(enabled);
        google_.SetEnabled(enabled);
        tool_.SetEnabled(enabled);
        reveal_.SetEnabled(enabled);
        dependencies_.SetEnabled(enabled);
        ai_.SetEnabled(enabled);
    }
    void StartScan(std::filesystem::path root, std::size_t limit) {
        if (busy_) return;
        if (worker_.joinable()) worker_.join();
        root_ = std::move(root);
        result_.reset();
        ApplyFilter();
        cancel_.store(false);
        busy_ = true;
        open_.SetEnabled(false);
        SetFileActionsEnabled(false);
        cancel_button_.SetEnabled(true);
        continue_button_.SetEnabled(false);
        summary_.SetText(L"Scanning on a worker thread…");
        const auto wake = GetWakeup();
        worker_ = std::jthread([this, limit, wake] {
            try {
                auto result = folder_explorer::ScanFolder(
                    root_, {limit, true}, &cancel_,
                    [this, wake](std::size_t count, std::wstring_view path) {
                        {
                            std::scoped_lock lock(mutex_);
                            progress_ = std::format(L"Scanning… {} items · {}", count, path);
                        }
                        wake.TryWake();
                    });
                std::scoped_lock lock(mutex_);
                pending_scan_ = std::move(result);
            } catch (const std::exception& e) {
                std::scoped_lock lock(mutex_);
                pending_failure_ =
                    L"Scan failed safely: " +
                    std::wstring(e.what(), e.what() + std::char_traits<char>::length(e.what()));
            } catch (...) {
                std::scoped_lock lock(mutex_);
                pending_failure_ = L"Scan failed safely.";
            }
            wake.TryWake();
        });
    }
    void ApplyFilter() {
        if (!model_) return;
        model_->Set(result_, filter_.GetText());
        mwfl::Must(list_.SetVirtualModel(model_), "refresh model");
        list_.RefreshVirtualModel();
    }
    void ShowSummary() {
        if (!result_) return;
        const auto filtered = filter_.GetText().empty()
                                  ? L""
                                  : std::format(L" · {} matching", model_->VisibleCount());
        summary_.SetText(std::format(
            L"{} files · {} folders · {} · {} errors{}{}", result_->files, result_->directories,
            folder_explorer::FormatBytes(result_->total_bytes), result_->errors, filtered,
            result_->cancelled       ? L" · cancelled"
            : result_->limit_reached ? L" · paused at safety limit"
                                     : L""));
        std::wstring text = L"Top types: ";
        for (std::size_t i = 0; i < std::min<std::size_t>(8, result_->extensions.size()); ++i) {
            if (i) text += L"   ";
            text += std::format(L"{} {} ({})", result_->extensions[i].extension,
                                result_->extensions[i].count,
                                folder_explorer::FormatBytes(result_->extensions[i].bytes));
        }
        extensions_.SetText(text);
        continue_button_.SetEnabled(result_->limit_reached && result_->entries.size() < 500000);
    }
    const folder_explorer::FileEntry* Selected() const {
        const auto ids = list_.GetSelectedItemIds();
        return ids.empty() ? nullptr : model_->GetById(ids.front());
    }
    std::filesystem::path SelectedPath() const {
        const auto* e = Selected();
        return e ? root_ / e->relative_path : std::filesystem::path{};
    }
    void InspectSelected() {
        if (busy_) return;
        const auto path = SelectedPath();
        std::error_code ec;
        if (path.empty() || std::filesystem::is_directory(path, ec) || ec) return;
        busy_ = true;
        open_.SetEnabled(false);
        SetFileActionsEnabled(false);
        detail_.SetText(L"Inspecting PE metadata and signature…");
        const auto wake = GetWakeup();
        worker_ = std::jthread([this, path, wake] {
            try {
                const auto info = folder_explorer::InspectPe(path);
                std::scoped_lock lock(mutex_);
                pending_detail_ = path.wstring() + L"\r\n" + folder_explorer::DescribePe(info);
            } catch (...) {
                std::scoped_lock lock(mutex_);
                pending_failure_ = L"PE inspection failed safely.";
            }
            wake.TryWake();
        });
    }
    void SearchSelected() {
        const auto path = SelectedPath();
        if (path.empty()) return;
        const auto query = L"\"" + path.filename().wstring() + L"\" Windows file purpose";
        const auto url = L"https://www.google.com/search?q=" + UrlEncode(query);
        ::ShellExecuteW(GetHwnd(), L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    }
    void RevealSelected() {
        const auto path = SelectedPath();
        if (path.empty()) return;
        const auto args = L"/select,\"" + path.wstring() + L"\"";
        ::ShellExecuteW(GetHwnd(), L"open", L"explorer.exe", args.c_str(), nullptr, SW_SHOWNORMAL);
    }
    void OpenTool() {
        const auto path = SelectedPath();
        if (path.empty()) {
            detail_.SetText(L"Select a file first.");
            return;
        }
        auto exe = pe_tool_.GetText();
        if (exe.empty()) {
            const auto chosen = mwfl::ShowOpenFileDialog(
                {.owner = GetHwnd(),
                 .title = L"Choose a PE inspection tool",
                 .filters = {{L"Windows applications", L"*.exe"}, {L"All files", L"*.*"}}});
            if (!chosen.accepted) return;
            exe = chosen.path.wstring();
            pe_tool_.SetText(exe);
        }
        const auto args = L"\"" + path.wstring() + L"\"";
        if (reinterpret_cast<INT_PTR>(::ShellExecuteW(GetHwnd(), L"open", exe.c_str(), args.c_str(),
                                                      nullptr, SW_SHOWNORMAL)) <= 32)
            detail_.SetText(L"Could not start the configured PE tool.");
    }
    void SummarizeDependencies() {
        if (busy_ || !result_) return;
        std::vector<std::filesystem::path> binaries;
        for (const auto& entry : result_->entries) {
            if (entry.directory) continue;
            auto extension = entry.relative_path.extension().wstring();
            std::ranges::transform(extension, extension.begin(), ::towlower);
            if (extension == L".exe" || extension == L".dll")
                binaries.push_back(root_ / entry.relative_path);
        }
        if (binaries.empty()) {
            detail_.SetText(L"No EXE or DLL files were found in this scan.");
            return;
        }
        busy_ = true;
        cancel_.store(false);
        open_.SetEnabled(false);
        SetFileActionsEnabled(false);
        cancel_button_.SetEnabled(true);
        detail_.SetText(L"Summarizing imported libraries on a worker thread…");
        const auto wake = GetWakeup();
        worker_ = std::jthread([this, binaries = std::move(binaries), wake] {
            try {
                std::map<std::wstring, std::size_t, std::less<>> imports;
                std::size_t inspected = 0, pe_files = 0;
                for (const auto& path : binaries) {
                    if (cancel_.load(std::memory_order_relaxed)) break;
                    const auto info = folder_explorer::InspectPe(path, false);
                    ++inspected;
                    if (info.is_pe) {
                        ++pe_files;
                        for (auto name : info.imports) {
                            std::ranges::transform(name, name.begin(), ::towlower);
                            ++imports[name];
                        }
                    }
                    if (inspected % 32 == 0) {
                        std::scoped_lock lock(mutex_);
                        progress_ = std::format(L"Summarizing libraries… {}/{} binaries", inspected,
                                                binaries.size());
                        wake.TryWake();
                    }
                }
                std::vector<std::pair<std::wstring, std::size_t>> ranked(imports.begin(),
                                                                         imports.end());
                std::ranges::sort(ranked, [](const auto& a, const auto& b) {
                    return a.second != b.second ? a.second > b.second : a.first < b.first;
                });
                std::wstring text = std::format(
                    L"Folder library summary\r\nInspected: {} of {} EXE/DLL files{}\r\n"
                    L"PE files: {} · distinct imported libraries: {}\r\n\r\n",
                    inspected, binaries.size(),
                    cancel_.load(std::memory_order_relaxed) ? L" (cancelled)" : L"", pe_files,
                    ranked.size());
                for (const auto& [name, count] : ranked)
                    text += std::format(L"  {}  —  used by {} file{}\r\n", name, count,
                                        count == 1 ? L"" : L"s");
                std::scoped_lock lock(mutex_);
                pending_detail_ = std::move(text);
            } catch (...) {
                std::scoped_lock lock(mutex_);
                pending_failure_ = L"Library summary failed safely.";
            }
            wake.TryWake();
        });
    }
    void StartAi() {
        if (busy_) return;
        const auto path = SelectedPath();
        if (path.empty() || !result_) return;
        folder_explorer::AiRequest request;
        request.provider = provider_.GetText().find(L"Ollama") != std::wstring::npos
                               ? folder_explorer::AiProvider::ollama
                               : folder_explorer::AiProvider::openai_compatible;
        request.host = host_.GetText();
        request.model = model_name_.GetText();
        request.api_key = api_key_.GetText();
        request.prompt = std::format(
            L"Explain what this file is likely used for in concise plain language. "
            L"Do not claim certainty beyond metadata.\nFile: {}\nFolder summary: "
            L"{} files, {}, top extensions: {}\nPE metadata:\n",
            path.filename().wstring(), result_->files,
            folder_explorer::FormatBytes(result_->total_bytes), extensions_.GetText());
        busy_ = true;
        open_.SetEnabled(false);
        SetFileActionsEnabled(false);
        cancel_button_.SetEnabled(false);
        detail_.SetText(L"Waiting for AI response…");
        const auto wake = GetWakeup();
        worker_ = std::jthread([this, path, request = std::move(request), wake]() mutable {
            try {
                request.prompt += folder_explorer::DescribePe(folder_explorer::InspectPe(path));
                auto response = folder_explorer::GenerateSummary(request);
                std::scoped_lock lock(mutex_);
                pending_ai_ = std::move(response);
            } catch (...) {
                std::scoped_lock lock(mutex_);
                pending_failure_ = L"AI request failed safely.";
            }
            wake.TryWake();
        });
    }
    std::filesystem::path root_;
    std::shared_ptr<folder_explorer::ScanResult> result_;
    std::shared_ptr<FileListModel> model_;
    std::atomic_bool cancel_{false};
    std::mutex mutex_;
    std::optional<folder_explorer::ScanResult> pending_scan_;
    std::optional<folder_explorer::AiResponse> pending_ai_;
    std::optional<std::wstring> pending_detail_;
    std::wstring progress_, pending_failure_;
    std::jthread worker_;
    bool busy_ = false;
    mwfl::Button open_, cancel_button_, continue_button_, inspect_, google_, tool_, reveal_,
        dependencies_, ai_, provider_;
    mwfl::TextBox filter_, host_, model_name_, api_key_, pe_tool_, detail_;
    mwfl::ListView list_;
    mwfl::Label summary_, extensions_;
};
}  // namespace
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
    return mwfl::RunApplication<MainWindow>(
        instance, show,
        {.title = L"Folder Explorer",
         .initial_bounds = {{30.0_dip, 30.0_dip}, {1500.0_dip, 900.0_dip}},
         .use_default_bounds = false});
}
