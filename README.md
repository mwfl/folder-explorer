# Folder Explorer

[![CI](https://github.com/mwfl/folder-explorer/actions/workflows/ci.yml/badge.svg)](https://github.com/mwfl/folder-explorer/actions/workflows/ci.yml)

Folder Explorer is a native Windows application built with [mwfl](https://github.com/mwfl/mwfl) for understanding an unfamiliar installation or application directory.

It recursively inventories a folder without freezing the UI, presents a flat filterable virtual list, summarizes file types and disk usage, inspects PE metadata/imports/Authenticode status, launches an external PE tool, searches the web, and can ask either Ollama or an OpenAI-compatible model to explain a selected file.

## Initial version

- Worker-thread recursive scan with cancellation and permission-error accounting.
- 100,000-item safety pause; explicit continuation raises the cap to 500,000.
- Virtual `ListView`, so hundreds of thousands of rows do not create native list items.
- Case-insensitive relative-path filtering without rescanning.
- File/folder counts, total bytes, and top extension counts/bytes.
- PE32/PE32+ architecture, version resources, imported DLL names, and Authenticode verification.
- Explicit buttons for Explorer reveal, Google search, and a user-configured PE utility.
- Ollama and OpenAI-compatible summaries. Only the displayed metadata/summary is sent after an explicit click; file bytes are never uploaded.
- API keys remain memory-only and are not written to disk.

## Build

Visual Studio 2026 is recommended. For development beside a local `mwfl` checkout:

```powershell
cmake --preset vs2026-x64
cmake --build --preset vs2026-x64-debug
ctest --preset vs2026-x64-debug
```

For a standalone clone, use Visual Studio 2022 or configure manually with `FOLDER_EXPLORER_USE_LOCAL_MWFL=OFF`; CMake fetches the pinned mwfl v0.1.0 release.

## AI setup

Ollama defaults to `http://127.0.0.1:11434` and model `llama3.2`. Start Ollama and ensure that model exists, select a file, then choose **Ask AI**.

For OpenAI-compatible services, toggle the provider, enter the HTTPS host, model, and key. A host ending in `/v1` and a bare API host are both accepted. The key is deliberately not persisted.

## Quick workflow

1. Choose **Open…** or drop a directory onto the window.
2. Type any part of a relative path to filter the flattened file list.
3. Select an EXE or DLL and choose **Inspect** to see version metadata, architecture, signature status, and imported libraries.
4. Choose **Search**, **Reveal**, or **PE tool…**. The first PE-tool use opens a picker for tools such as PE-bear, Dependencies, or PE Explorer.
5. Optionally configure Ollama or an OpenAI-compatible endpoint and choose **Ask AI**. This is the only action that transmits metadata externally.

## Large folders

The first scan stops at 100,000 visible entries and keeps the partial summary usable. **Continue to 500k** explicitly opts into the higher bound. Cancellation is checked during enumeration; inaccessible paths are counted and scanning continues. Symlinked directories are displayed but not followed, preventing cycles. The hard bound keeps worst-case memory predictable; future versions can add a disk-backed index if multi-million-file trees become a real use case.

## Privacy and trust

Folder scans and PE inspection are local. Web search opens the browser with the selected filename. AI requests contain the filename, folder aggregate, and PE metadata only. PE descriptions and AI responses are informational and may be incomplete; Authenticode validity is reported separately from inferred purpose.
