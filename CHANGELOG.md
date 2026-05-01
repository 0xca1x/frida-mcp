# Changelog

All notable changes to fuzzmind-frida-mcp will be documented in this file.

## [0.1.0] - 2026-05-01

### Added
- Initial release by FuzzMind Security Lab
- Broad MCP tool surface for macOS, iOS, Android, Windows, Linux, and kernel-oriented Frida workflows
- Practical Frida Python SDK and GumJS API wrapper coverage for agent-driven dynamic analysis
- Device/session lifecycle management with multi-session support
- Script injection, compilation, eternalization, and bytecode loading
- Memory read/write/scan/protect/alloc/dump with typed access
- Interceptor attach/replace/revert with auto-revert timers
- Stalker coverage collection and configurable tracing
- ObjC/Swift/Java runtime bridges with class/method enumeration and hooking
- Platform-specific tools: Win32 API/COM/.NET/Registry/AMSI/ETW, Android Intent/ContentProvider/JNI, iOS Keychain/ATS, Linux syscall/GOT/D-Bus/seccomp
- Security recipes: SSL pinning bypass, SSL keylog, crypto hooking, anti-root/debug bypass, string sniffing, time warping
- Agent workflow tools: target snapshot, host diagnostics, bridge management, Gadget config
- Official Frida API tools: Bus, Compiler, Portal, Service, Channel, PackageManager
- Kernel memory access tools
- Cloak (stealth) tools for thread/range/FD hiding
- Profiler and sampler tools
- Automated tests covering registration, workflows, static release checks, and real Frida smoke paths
- GitHub Actions workflows for CI and release gates
- JS injection safety via `_js_literal()` enforcement
