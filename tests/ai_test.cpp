#include "../src/ai.h"
#include <string>
#include <thread>
#include <winsock2.h>
#include <ws2tcpip.h>

namespace {
class MockServer {
   public:
    MockServer(std::string status, std::string body)
        : status_(std::move(status)), body_(std::move(body)) {
        WSADATA data{};
        if (::WSAStartup(MAKEWORD(2, 2), &data) != 0) return;
        socket_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (socket_ == INVALID_SOCKET) return;
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::bind(socket_, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0 ||
            ::listen(socket_, 1) != 0)
            return;
        int length = sizeof(address);
        if (::getsockname(socket_, reinterpret_cast<sockaddr*>(&address), &length) != 0) return;
        port_ = ntohs(address.sin_port);
        thread_ = std::thread([this] { Serve(); });
    }

    ~MockServer() {
        if (socket_ != INVALID_SOCKET) ::closesocket(socket_);
        if (thread_.joinable()) thread_.join();
        ::WSACleanup();
    }

    unsigned short Port() const noexcept { return port_; }

   private:
    void Serve() const noexcept {
        const SOCKET client = ::accept(socket_, nullptr, nullptr);
        if (client == INVALID_SOCKET) return;
        char request[8192]{};
        static_cast<void>(::recv(client, request, sizeof(request), 0));
        const std::string response = "HTTP/1.1 " + status_ +
                                     "\r\nContent-Type: application/json\r\n" +
                                     "Content-Length: " + std::to_string(body_.size()) +
                                     "\r\nConnection: close\r\n\r\n" + body_;
        static_cast<void>(::send(client, response.data(), static_cast<int>(response.size()), 0));
        ::shutdown(client, SD_BOTH);
        ::closesocket(client);
    }

    SOCKET socket_ = INVALID_SOCKET;
    unsigned short port_ = 0;
    std::string status_;
    std::string body_;
    std::thread thread_;
};
}  // namespace

int wmain() {
    {
        MockServer server{"200 OK", R"({"response":"Local summary"})"};
        if (!server.Port()) return 1;
        folder_explorer::AiRequest request;
        request.host = L"http://127.0.0.1:" + std::to_wstring(server.Port());
        request.prompt = L"Describe test.dll";
        const auto response = folder_explorer::GenerateSummary(request);
        if (!response.error.empty() || response.text != L"Local summary") return 2;
    }
    {
        MockServer server{"401 Unauthorized", R"({"error":"bad key"})"};
        folder_explorer::AiRequest request;
        request.provider = folder_explorer::AiProvider::openai_compatible;
        request.host = L"http://127.0.0.1:" + std::to_wstring(server.Port());
        const auto response = folder_explorer::GenerateSummary(request);
        if (response.error.find(L"HTTP 401: bad key") == std::wstring::npos) return 3;
    }
    return 0;
}
