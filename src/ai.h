#pragma once
#include <mwfl/security.h>
#include <string>
namespace folder_explorer {
enum class AiProvider { ollama, openai_compatible };
struct AiRequest {
    AiProvider provider = AiProvider::ollama;
    std::wstring host = L"http://127.0.0.1:11434";
    std::wstring model = L"llama3.2";
    // Memory-only credential: callers must not persist or log it.
    mwfl::SecureString api_key;
    // Constructed from displayed metadata; file bytes are outside this contract.
    std::wstring prompt;
};
struct AiResponse {
    std::wstring text;
    std::wstring error;
};
// Blocking network operation intended for a worker thread. Provider failures
// are returned as text rather than thrown across UI code.
AiResponse GenerateSummary(const AiRequest& request);
}  // namespace folder_explorer
