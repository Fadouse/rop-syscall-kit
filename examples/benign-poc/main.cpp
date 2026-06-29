#include <rop_syscall/syscall.hpp>

#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

namespace {

std::string status_to_hex(NTSTATUS status)
{
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << static_cast<unsigned long>(status);
    return oss.str();
}

void print_syscall_number(const std::string& name)
{
    uint32_t number = 0;
    if (rop_syscall::get_syscall_number(name, number)) {
        std::cout << "  " << name << " -> #" << std::dec << number
                  << " (0x" << std::hex << number << std::dec << ")\n";
        return;
    }

    std::cout << "  " << name << " -> not found\n";
}

bool print_system_time()
{
    LARGE_INTEGER system_time = {};
    NTSTATUS status = rop_syscall::invoke<NTSTATUS>(
        "NtQuerySystemTime",
        &system_time);

    if (!NT_SUCCESS(status)) {
        std::cerr << "NtQuerySystemTime failed: " << status_to_hex(status) << "\n";
        return false;
    }

    FILETIME file_time = {};
    file_time.dwLowDateTime = static_cast<DWORD>(system_time.LowPart);
    file_time.dwHighDateTime = static_cast<DWORD>(system_time.HighPart);

    SYSTEMTIME utc = {};
    if (!FileTimeToSystemTime(&file_time, &utc)) {
        std::cerr << "FileTimeToSystemTime failed: " << GetLastError() << "\n";
        return false;
    }

    std::cout << "\nNtQuerySystemTime returned UTC: "
              << utc.wYear << '-'
              << std::setw(2) << std::setfill('0') << utc.wMonth << '-'
              << std::setw(2) << std::setfill('0') << utc.wDay << ' '
              << std::setw(2) << std::setfill('0') << utc.wHour << ':'
              << std::setw(2) << std::setfill('0') << utc.wMinute << ':'
              << std::setw(2) << std::setfill('0') << utc.wSecond << '.'
              << std::setw(3) << std::setfill('0') << utc.wMilliseconds
              << std::setfill(' ') << "\n";
    return true;
}

bool print_current_process_info(const rop_syscall::stack_spoof_config& spoof_cfg)
{
    PROCESS_BASIC_INFORMATION process_info = {};
    ULONG returned = 0;

    NTSTATUS status = rop_syscall::invoke_spoofed<NTSTATUS>(
        "NtQueryInformationProcess",
        spoof_cfg,
        NtCurrentProcess(),
        ProcessBasicInformation,
        &process_info,
        sizeof(process_info),
        &returned);

    if (!NT_SUCCESS(status)) {
        std::cerr << "NtQueryInformationProcess failed: " << status_to_hex(status) << "\n";
        return false;
    }

    std::cout << "\nNtQueryInformationProcess returned:\n"
              << "  current pid : " << static_cast<unsigned long long>(process_info.UniqueProcessId) << "\n"
              << "  peb address : 0x" << std::hex
              << reinterpret_cast<std::uintptr_t>(process_info.PebBaseAddress)
              << std::dec << "\n"
              << "  bytes       : " << returned << "\n";
    return true;
}

bool run_short_delay(const rop_syscall::stack_spoof_config& spoof_cfg)
{
    LARGE_INTEGER interval = {};
    interval.QuadPart = -100 * 10000LL; // 100 ms, relative NT time units.

    auto start = std::chrono::steady_clock::now();
    NTSTATUS status = rop_syscall::invoke_spoofed<NTSTATUS>(
        "NtDelayExecution",
        spoof_cfg,
        FALSE,
        &interval);
    auto end = std::chrono::steady_clock::now();

    if (!NT_SUCCESS(status)) {
        std::cerr << "NtDelayExecution failed: " << status_to_hex(status) << "\n";
        return false;
    }

    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    std::cout << "\nNtDelayExecution returned after about " << elapsed_ms << " ms\n";
    return true;
}

bool close_local_handle_with_syscall()
{
    HANDLE event_handle = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!event_handle) {
        std::cerr << "CreateEventW failed: " << GetLastError() << "\n";
        return false;
    }

    NTSTATUS status = rop_syscall::invoke<NTSTATUS>(
        "NtClose",
        event_handle);

    if (!NT_SUCCESS(status)) {
        CloseHandle(event_handle);
        std::cerr << "NtClose failed: " << status_to_hex(status) << "\n";
        return false;
    }

    std::cout << "\nNtClose closed a local event handle successfully\n";
    return true;
}

} // namespace

int main()
{
    std::cout << "rop-syscall-kit benign poc\n";
    std::cout << "============================\n";

    if (!rop_syscall::initialize()) {
        std::cerr << "failed to initialize rop_syscall metadata\n";
        return 1;
    }

    std::cout << "\nResolved syscall numbers:\n";
    print_syscall_number("NtQuerySystemTime");
    print_syscall_number("NtQueryInformationProcess");
    print_syscall_number("NtDelayExecution");
    print_syscall_number("NtClose");

    rop_syscall::stack_spoof_config spoof_cfg = rop_syscall::create_spoof_config();
    std::cout << "\nStack-spoofed invocation path: "
              << (spoof_cfg.enabled ? "enabled" : "anchors unavailable; direct path fallback")
              << "\n";

    if (!print_system_time()) {
        return 1;
    }
    if (!print_current_process_info(spoof_cfg)) {
        return 1;
    }
    if (!run_short_delay(spoof_cfg)) {
        return 1;
    }
    if (!close_local_handle_with_syscall()) {
        return 1;
    }

    std::cout << "\nDemo completed successfully.\n";
    return 0;
}
