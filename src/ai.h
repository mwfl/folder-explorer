#pragma once
#include <string>
namespace folder_explorer {
enum class AiProvider { ollama, openai_compatible };
struct AiRequest {
    AiProvider provider = AiProvider::ollama;
    std::wstring host = L"http://127.0.0.1:11434";
    std::wstring model = L"llama3.2";
    std::wstring api_key;
    std::wstring prompt;
};
struct AiResponse {
    std::wstring text;
    std::wstring error;
};
AiResponse GenerateSummary(const AiRequest& request);
}  // namespace folder_explorer
