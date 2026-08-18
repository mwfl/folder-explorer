#include "pe.h"

#include <mwfl/deployment.h>
#include <windows.h>

#include <algorithm>
#include <format>
#include <fstream>

namespace folder_explorer {
namespace {
template <class T>
const T* At(const std::vector<std::byte>& data, std::size_t offset) {
    return offset <= data.size() && sizeof(T) <= data.size() - offset
               ? reinterpret_cast<const T*>(data.data() + offset)
               : nullptr;
}
std::wstring VersionValue(const std::filesystem::path& path, const wchar_t* name) {
    DWORD ignored = 0;
    const DWORD size = ::GetFileVersionInfoSizeW(path.c_str(), &ignored);
    if (!size) return {};
    std::vector<std::byte> data(size);
    if (!::GetFileVersionInfoW(path.c_str(), 0, size, data.data())) return {};
    struct Translation {
        WORD language, code_page;
    }* translations = nullptr;
    UINT count = 0;
    if (!::VerQueryValueW(data.data(), L"\\VarFileInfo\\Translation",
                          reinterpret_cast<void**>(&translations), &count) ||
        count < sizeof(Translation))
        return {};
    const auto query = std::format(L"\\StringFileInfo\\{:04x}{:04x}\\{}", translations[0].language,
                                   translations[0].code_page, name);
    wchar_t* value = nullptr;
    UINT length = 0;
    return ::VerQueryValueW(data.data(), query.c_str(), reinterpret_cast<void**>(&value),
                            &length) &&
                   value
               ? std::wstring(value, length ? length - 1 : 0)
               : std::wstring{};
}
std::wstring VerifySignature(const std::filesystem::path& path, bool& valid) {
    auto verification = mwfl::VerifyAuthenticode(path, mwfl::RevocationPolicy::Offline);
    if (!verification) {
        valid = false;
        return L"Signature verification failed";
    }
    valid = verification.Value().status == mwfl::SignatureStatus::Valid;
    switch (verification.Value().status) {
        case mwfl::SignatureStatus::Valid: return L"Valid Authenticode signature";
        case mwfl::SignatureStatus::Unsigned: return L"Not signed";
        case mwfl::SignatureStatus::Untrusted: return L"Signature is not trusted";
        case mwfl::SignatureStatus::RevocationUnavailable:
            return L"Signature revocation status unavailable";
        case mwfl::SignatureStatus::Invalid: break;
    }
    return std::format(L"Signature invalid (0x{:08X})",
                       static_cast<unsigned long>(verification.Value().native_status));
}
}  // namespace
PeInfo InspectPe(const std::filesystem::path& path) {
    return InspectPe(path, true);
}

PeInfo InspectPe(const std::filesystem::path& path, bool verify_signature) {
    PeInfo out;
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        out.error = L"Could not open the file.";
        return out;
    }
    stream.seekg(0, std::ios::end);
    const auto length = stream.tellg();
    if (length <= 0 || length > static_cast<std::streamoff>(512ull * 1024 * 1024)) {
        out.error = L"File is empty or too large to inspect.";
        return out;
    }
    std::vector<std::byte> bytes(static_cast<std::size_t>(length));
    stream.seekg(0);
    stream.read(reinterpret_cast<char*>(bytes.data()), length);
    const auto* dos = At<IMAGE_DOS_HEADER>(bytes, 0);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0) return out;
    const std::size_t nt_offset = static_cast<std::size_t>(dos->e_lfanew);
    const auto* signature = At<DWORD>(bytes, nt_offset);
    const auto* file = At<IMAGE_FILE_HEADER>(bytes, nt_offset + sizeof(DWORD));
    if (!signature || *signature != IMAGE_NT_SIGNATURE || !file) return out;
    out.is_pe = true;
    out.machine = file->Machine == IMAGE_FILE_MACHINE_AMD64   ? L"x64"
                  : file->Machine == IMAGE_FILE_MACHINE_ARM64 ? L"ARM64"
                  : file->Machine == IMAGE_FILE_MACHINE_I386
                      ? L"x86"
                      : std::format(L"0x{:04X}", file->Machine);
    const std::size_t optional_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    const auto* magic = At<WORD>(bytes, optional_offset);
    if (!magic) return out;
    out.is_64_bit = *magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    IMAGE_DATA_DIRECTORY import_dir{};
    if (out.is_64_bit) {
        if (const auto* h = At<IMAGE_OPTIONAL_HEADER64>(bytes, optional_offset))
            import_dir = h->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    } else {
        if (const auto* h = At<IMAGE_OPTIONAL_HEADER32>(bytes, optional_offset))
            import_dir = h->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    }
    const std::size_t section_offset = optional_offset + file->SizeOfOptionalHeader;
    const auto rva_to_offset = [&](DWORD rva) -> std::size_t {
        for (WORD i = 0; i < file->NumberOfSections; ++i)
            if (const auto* s = At<IMAGE_SECTION_HEADER>(
                    bytes, section_offset + i * sizeof(IMAGE_SECTION_HEADER));
                s && rva >= s->VirtualAddress &&
                rva < s->VirtualAddress + std::max(s->Misc.VirtualSize, s->SizeOfRawData))
                return s->PointerToRawData + (rva - s->VirtualAddress);
        return 0;
    };
    constexpr std::size_t max_imports = 4096;
    for (std::size_t offset = rva_to_offset(import_dir.VirtualAddress);
         offset && out.imports.size() < max_imports; offset += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        const auto* item = At<IMAGE_IMPORT_DESCRIPTOR>(bytes, offset);
        if (!item || !item->Name) break;
        const auto name_offset = rva_to_offset(item->Name);
        if (!name_offset || name_offset >= bytes.size()) break;
        const char* name = reinterpret_cast<const char*>(bytes.data() + name_offset);
        const auto available = bytes.size() - name_offset;
        const auto end = std::find(name, name + available, '\0');
        if (end == name + available) break;
        const int wide =
            ::MultiByteToWideChar(CP_ACP, 0, name, static_cast<int>(end - name), nullptr, 0);
        std::wstring value(wide, L'\0');
        ::MultiByteToWideChar(CP_ACP, 0, name, static_cast<int>(end - name), value.data(), wide);
        out.imports.push_back(std::move(value));
    }
    out.description = VersionValue(path, L"FileDescription");
    out.company = VersionValue(path, L"CompanyName");
    out.product = VersionValue(path, L"ProductName");
    if (auto version = mwfl::QueryFileVersion(path); version) {
        out.version = std::format(L"{}.{}.{}.{}", version.Value().major, version.Value().minor,
                                  version.Value().build, version.Value().revision);
    } else {
        out.version = VersionValue(path, L"FileVersion");
    }
    if (verify_signature)
        out.signature_status = VerifySignature(path, out.signature_valid);
    else
        out.signature_status = L"Not checked during folder summary";
    return out;
}
std::wstring DescribePe(const PeInfo& p) {
    if (!p.error.empty()) return p.error;
    if (!p.is_pe) return L"Not a Windows PE image.";
    std::wstring text = std::format(
        L"PE image · {} · {}\r\nSignature: {}\r\nDescription: {}\r\nCompany: "
        L"{}\r\nProduct: {}\r\nVersion: {}\r\n\r\nImported libraries ({}):\r\n",
        p.machine, p.is_64_bit ? L"64-bit" : L"32-bit", p.signature_status, p.description,
        p.company, p.product, p.version, p.imports.size());
    for (const auto& item : p.imports) text += L"  • " + item + L"\r\n";
    return text;
}
}  // namespace folder_explorer
