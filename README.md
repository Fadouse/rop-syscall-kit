# rop-syscall-kit

`rop-syscall-kit` is a Windows x64 C++ library for resolving Native API syscall numbers at runtime and invoking them through compact ROP-style syscall stubs with stack spoof(optional).

## Notice

> For educational exchange and authorized security research only. Use these PoCs only in local labs, CTFs, coursework, or systems you own or are explicitly authorized to test. The examples are intentionally benign and are provided to study windows mechanisms, not for unauthorized access or misuse.

## Features

- **Minimal API**: call `rop_syscall::invoke<Ret>(...)` or `rop_syscall::invoke_spoofed<Ret>(...)` directly.
- **Automatic syscall parsing**: scans the local `ntdll.dll` export table and extracts syscall numbers from real Native API stubs.
- **ROP syscall dispatch**: generated stubs transfer control to an existing `syscall; ret` gadget inside `ntdll.dll`.
- **Stack spoofing**: optional spoofed invocation path builds a configurable return chain before entering the syscall gadget.
- **Automatic argument forwarding**: variadic C++ templates preserve the requested function signature.
- **Automatic stack allocation**: the x64 spoofed stub reserves stack space and copies stack arguments into the expected Windows x64 ABI layout.
- **Lowercase project layout**: directory names are shell-friendly on Windows, Linux, and WSL.

## Project Layout

```text
rop-syscall-kit/
  include/rop_syscall/
    shared.hpp
    syscall.hpp
  src/
    syscall.cpp
    image_stub.asm
  lib/
    rop_syscall_kit.vcxproj
    rop_syscall_kit.vcxproj.filters
  examples/benign-poc/
    main.cpp
    benign-poc.vcxproj
    benign-poc.vcxproj.filters
  rop-syscall-kit.sln
  LICENSE
```

## Quick Start

```cpp
#include <rop_syscall/syscall.hpp>

int main()
{
    if (!rop_syscall::initialize()) {
        return 1;
    }

    LARGE_INTEGER system_time = {};
    NTSTATUS status = rop_syscall::invoke<NTSTATUS>(
        "NtQuerySystemTime",
        &system_time);

    return NT_SUCCESS(status) ? 0 : 1;
}
```

Spoofed call example:

```cpp
auto config = rop_syscall::create_spoof_config();

PROCESS_BASIC_INFORMATION info = {};
ULONG returned = 0;

NTSTATUS status = rop_syscall::invoke_spoofed<NTSTATUS>(
    "NtQueryInformationProcess",
    config,
    NtCurrentProcess(),
    ProcessBasicInformation,
    &info,
    sizeof(info),
    &returned);
```

## Build

Requirements:

- Windows x64
- Visual Studio 2022 C++ toolchain
- Windows SDK 10.0 or newer
- MASM build customization

Build release:

```cmd
cd /d D:\Code\Security\rop-syscall-kit
msbuild rop-syscall-kit.sln /p:Configuration=Release /p:Platform=x64
```

Build debug:

```cmd
msbuild rop-syscall-kit.sln /p:Configuration=Debug /p:Platform=x64
```

Output:

```text
x64\Release\rop_syscall_kit.lib
x64\Release\benign_poc.exe
x64\Debug\rop_syscall_kit.lib
x64\Debug\benign_poc.exe
```

## Run the Example

```cmd
x64\Release\benign_poc.exe
```

The example performs local calls only:

1. Resolves syscall metadata.
2. Prints syscall numbers.
3. Calls `NtQuerySystemTime` and prints UTC time.
4. Calls `NtQueryInformationProcess` on the current process and prints returned fields.
5. Calls `NtDelayExecution` for a short delay.
6. Creates a local event with `CreateEventW` and closes it with `NtClose`.

Expected output shape:

```text
rop-syscall-kit benign poc
============================

Resolved syscall numbers:
  NtQuerySystemTime -> #...
  NtQueryInformationProcess -> #...
  NtDelayExecution -> #...
  NtClose -> #...

Stack-spoofed invocation path: enabled

NtQuerySystemTime returned UTC: ...

NtQueryInformationProcess returned:
  current pid : ...
  peb address : 0x...
  bytes       : ...

NtDelayExecution returned after about ... ms

NtClose closed a local event handle successfully

Demo completed successfully.
```

## How It Works

### Native syscall stubs

Windows x64 Native API exports in `ntdll.dll` commonly use a small syscall entry stub:

```asm
mov r10, rcx
mov eax, <syscall_number>
syscall
ret
```

The important value is the immediate loaded into `eax`. That value is the syscall number for the current Windows build.

`rop-syscall-kit` parses the local `ntdll.dll`, finds these stubs, extracts the immediate value, and stores it in an in-memory lookup table.

### ROP syscall dispatch

Instead of emitting a standalone `syscall` instruction in generated memory, the normal generated stub jumps to a real `syscall; ret` gadget already present in `ntdll.dll`:

```asm
mov r10, rcx
mov eax, <syscall_number>
mov r11, <ntdll_syscall_ret_gadget>
jmp r11
```

This keeps syscall dispatch compact and reuses the host module's existing instruction sequence.

### Minimal typed calls

The public API is built around variadic templates:

```cpp
template<typename Ret, typename... Args>
inline Ret invoke(const std::string& syscall_name, Args... args)
```

The wrapper resolves the syscall, obtains the correct generated stub, casts it to the requested function signature, then forwards the arguments:

```cpp
using func_t = Ret(NTAPI*)(Args...);
func_t fn = reinterpret_cast<func_t>(stub);
return fn(std::forward<Args>(args)...);
```

The caller only supplies the return type, Native API name, and normal arguments.

### Automatic argument and stack handling

On Windows x64:

- arguments 1-4 are passed in `rcx`, `rdx`, `r8`, and `r9`,
- additional arguments are passed on the stack,
- each call reserves shadow space,
- stack alignment must remain valid across the call boundary.

The normal path relies on the compiler-generated call sequence for the typed function pointer.

The spoofed x64 path additionally reserves a temporary stack area, copies stack arguments into a new home area, places fake return anchors, performs the syscall gadget call, restores the original return address, then returns to the caller.

### Stack spoofing

`create_spoof_config` creates a `stack_spoof_config` containing return anchors. `invoke_spoofed` uses that config to prepare a stack layout before dispatching the syscall.

Conceptual layout:

```text
higher addresses
  caller frames
  fake return anchor #2
  fake return anchor #1
  copied stack arguments
  shadow / temporary stack area.
  syscall; ret gadget call
lower addresses
```

The x64 assembly implementation lives in `src/image_stub.asm`.

## Code Walkthrough

### `include/rop_syscall/syscall.hpp`

Public declarations and template wrappers.

Important structures:

```cpp
struct syscall_entry {
    std::string name;
    uint32_t number;
    void* gadget_address;
    void* stub_normal;
};
```

`syscall_entry` stores one resolved Native API entry.

```cpp
struct stack_spoof_config {
    void* fake_return_1 = nullptr;
    void* fake_return_2 = nullptr;
    void* fake_return_3 = nullptr;
    bool enabled = false;
};
```

`stack_spoof_config` controls spoofed invocation.

Primary functions:

```cpp
bool initialize();
bool get_syscall_number(const std::string& function_name, uint32_t& out_syscall_number);
bool get_gadget_address(const std::string& function_name, void*& out_gadget_address);
stack_spoof_config create_spoof_config(void* ret1 = nullptr, void* ret2 = nullptr, void* ret3 = nullptr);
```

Primary templates:

```cpp
rop_syscall::invoke<Ret>(name, args...)
rop_syscall::invoke_spoofed<Ret>(name, config, args...)
```

### `src/syscall.cpp`

Implementation of parsing, lookup, stub generation, and spoof config creation.

Main flow:

1. `initialize()` calls the internal extraction routine.
2. `extract_syscalls()` reads `ntdll.dll` and parses PE exports.
3. Exported functions beginning with `4C 8B D1 B8` are treated as syscall stubs.
4. The immediate after `B8` is stored as the syscall number.
5. `find_syscall_gadget()` locates `0F 05 C3` in the loaded `ntdll.dll` image.
6. `get_or_build_normal_stub()` returns a cached generated stub.
7. `build_spoofed_stub()` prepares the shared image stub context for spoofed calls.

Important byte signatures:

```text
4C 8B D1 B8    mov r10, rcx; mov eax, imm32
0F 05 C3       syscall; ret
```

### `src/image_stub.asm`

x64 MASM stub used for spoofed calls.

Core behavior:

```asm
sub rsp, 0B8h
; copy stack arguments into the reserved home area
; place fake return anchors
mov r10, rcx
mov eax, dword ptr [g_image_stub_ctx + 0]
mov r11, qword ptr [g_image_stub_ctx + 8]
call r11
; restore caller return address
add rsp, 0B8h
ret
```

This is where automatic stack space allocation and stack argument copying happen for spoofed invocation.

### `examples/benign-poc/main.cpp`

Small demonstration program that exercises both direct and spoofed calls. It prints values returned by local Native API calls so users can verify the library behavior without additional setup.

## Integration

Use the static library project:

```text
lib/rop_syscall_kit.vcxproj
```

Or include these files in another MSBuild project:

```text
include/rop_syscall/syscall.hpp
include/rop_syscall/shared.hpp
src/syscall.cpp
src/image_stub.asm
```

Then include the public header:

```cpp
#include <rop_syscall/syscall.hpp>
```

Initialize once:

```cpp
if (!rop_syscall::initialize()) {
    return 1;
}
```

Call Native APIs by name:

```cpp
uint32_t number = 0;
if (rop_syscall::get_syscall_number("NtClose", number)) {
    // number contains the current host's syscall number.
}
```

## License

This project is released under the MIT License. See [`LICENSE`](LICENSE).

Copyright (c) 2026 Fadouse

