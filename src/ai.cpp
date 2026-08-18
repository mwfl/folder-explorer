#include "ai.h"
#include <windows.h>
#include <format>
#include <vector>
#include <winhttp.h>

namespace folder_explorer {
namespace {
std::string Utf8(std::wstring_view text) {
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                        nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), n,
                          nullptr, nullptr);
    return out;
}
std::wstring Wide(std::string_view text) {
    const int n =
        ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring out(n, L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), n);
    return out;
}
std::string Escape(std::wstring_view value) {
    std::string out;
    for (char c : Utf8(value)) {
        if (c == '"' || c == '\\') {
            out += '\\';
            out += c;
        } else if (c == '\n')
            out += "\\n";
        else if (c == '\r') {
        } else
            out += c;
    }
    return out;
}
std::wstring JsonString(const std::string& json, std::string_view key) {
    const std::string token = "\"" + std::string(key) + "\"";
    auto pos = json.find(token);
    if (pos == std::string::npos) return {};
    pos = json.find(':', pos + token.size());
    pos = json.find('"', pos);
    if (pos == std::string::npos) return {};
    ++pos;
    std::string out;
    bool escaped = false;
    for (; pos < json.size(); ++pos) {
        char c = json[pos];
        if (escaped) {
            out += c == 'n' ? '\n' : c;
            escaped = false;
        } else if (c == '\\')
            escaped = true;
        else if (c == '"')
            break;
        else
            out += c;
    }
    return Wide(out);
}
}  // namespace
AiResponse GenerateSummary(const AiRequest& request) {
    AiResponse result;
    URL_COMPONENTS parts{sizeof(parts)};
    wchar_t host[256]{}, path[2048]{};
    parts.lpszHostName = host;
    parts.dwHostNameLength = 256;
    parts.lpszUrlPath = path;
    parts.dwUrlPathLength = 2048;
    std::wstring url = request.host;
    while (!url.empty() && url.back() == L'/') url.pop_back();
    if (request.provider == AiProvider::ollama)
        url += L"/api/generate";
    else
        url += url.ends_with(L"/v1") ? L"/chat/completions" : L"/v1/chat/completions";
    if (!::WinHttpCrackUrl(url.c_str(), 0, 0, &parts)) {
        result.error = L"Invalid AI host URL.";
        return result;
    }
    HINTERNET session = ::WinHttpOpen(L"Folder Explorer/0.1", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                      nullptr, nullptr, 0);
    if (!session) {
        result.error = L"Could not initialize HTTP.";
        return result;
    }
    ::WinHttpSetTimeouts(session, 10000, 10000, 30000, 60000);
    HINTERNET connect = ::WinHttpConnect(
        session, std::wstring(host, parts.dwHostNameLength).c_str(), parts.nPort, 0);
    const DWORD flags = parts.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET call =
        connect ? ::WinHttpOpenRequest(connect, L"POST",
                                       std::wstring(path, parts.dwUrlPathLength).c_str(), nullptr,
                                       WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags)
                : nullptr;
    const std::string body = request.provider == AiProvider::ollama
                                 ? "{\"model\":\"" + Escape(request.model) +
                                       "\",\"stream\":false,\"prompt\":\"" +
                                       Escape(request.prompt) + "\"}"
                                 : "{\"model\":\"" + Escape(request.model) +
                                       "\",\"messages\":[{\"role\":\"user\",\"content\":\"" +
                                       Escape(request.prompt) + "\"}],\"temperature\":0.2}";
    std::wstring headers = L"Content-Type: application/json\r\n";
    request.api_key.WithView([&](std::wstring_view key) {
        if (!key.empty()) headers += L"Authorization: Bearer " + std::wstring(key) + L"\r\n";
    });
    BOOL ok = call &&
              ::WinHttpSendRequest(call, headers.c_str(), static_cast<DWORD>(-1),
                                   const_cast<char*>(body.data()), static_cast<DWORD>(body.size()),
                                   static_cast<DWORD>(body.size()), 0) &&
              ::WinHttpReceiveResponse(call, nullptr);
    if (!headers.empty()) ::SecureZeroMemory(headers.data(), headers.size() * sizeof(wchar_t));
    DWORD status = 0, status_size = sizeof(status);
    if (ok && !::WinHttpQueryHeaders(call, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                     WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size,
                                     WINHTTP_NO_HEADER_INDEX))
        ok = FALSE;
    constexpr std::size_t max_response_bytes = 4 * 1024 * 1024;
    std::string response;
    while (ok) {
        DWORD available = 0;
        if (!::WinHttpQueryDataAvailable(call, &available)) {
            ok = FALSE;
            break;
        }
        if (!available) break;
        if (response.size() + available > max_response_bytes) {
            result.error = L"The AI service response exceeded the 4 MB safety limit.";
            ok = FALSE;
            break;
        }
        std::vector<char> chunk(available);
        DWORD read = 0;
        if (!::WinHttpReadData(call, chunk.data(), available, &read)) {
            ok = FALSE;
            break;
        }
        response.append(chunk.data(), read);
    }
    if (!ok && result.error.empty())
        result.error = L"AI request failed. Check the host, model, and local service.";
    else if (status < 200 || status >= 300) {
        auto message = JsonString(response, "error");
        if (message.empty()) message = JsonString(response, "message");
        result.error = std::format(L"AI service returned HTTP {}{}{}.", status,
                                   message.empty() ? L"" : L": ", message);
    } else {
        result.text =
            JsonString(response, request.provider == AiProvider::ollama ? "response" : "content");
        if (result.text.empty()) result.error = L"The AI service returned an unexpected response.";
    }
    if (call) ::WinHttpCloseHandle(call);
    if (connect) ::WinHttpCloseHandle(connect);
    ::WinHttpCloseHandle(session);
    return result;
}
}  // namespace folder_explorer
