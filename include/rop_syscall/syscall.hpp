#ifndef ROP_SYSCALL_HPP
#define ROP_SYSCALL_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <mutex>
#include <memory>
#include <cstring>
#include <utility>

#include <Windows.h>
#include <winnt.h>

#include "shared.hpp"

namespace rop_syscall {

    // Global state (extern declarations; definitions in syscall.cpp)
    extern std::mutex g_syscall_mutex;

    struct syscall_entry {
        std::string name;
        uint32_t number;
        void* gadget_address;   // pointer to "syscall; ret"
        void* stub_normal;      // generated executable stub for non-spoofed calls (cached)
    };

    extern std::unordered_map<std::string, syscall_entry> g_syscall_map;
    extern bool g_initialized;

    // Stack spoofing configuration
    struct stack_spoof_config {
        void* fake_return_1 = nullptr;
        void* fake_return_2 = nullptr;
        void* fake_return_3 = nullptr;
        bool enabled = false;
    };

    struct image_stub_context {
        uint32_t syscall_number = 0;
        uint32_t pad = 0;
        void* gadget_address = nullptr;
        void* fake_return_1 = nullptr;
        void* fake_return_2 = nullptr;
        void* fake_return_3 = nullptr;
    };

    static_assert(offsetof(image_stub_context, syscall_number) == 0, "image_stub_context layout mismatch");
    static_assert(offsetof(image_stub_context, gadget_address) == 8, "image_stub_context layout mismatch");
    static_assert(offsetof(image_stub_context, fake_return_1) == 16, "image_stub_context layout mismatch");
    static_assert(offsetof(image_stub_context, fake_return_2) == 24, "image_stub_context layout mismatch");
    static_assert(offsetof(image_stub_context, fake_return_3) == 32, "image_stub_context layout mismatch");
    static_assert(sizeof(image_stub_context) == 40, "image_stub_context size mismatch");

#if defined(_WIN64)
    extern "C" image_stub_context g_image_stub_ctx;
    extern "C" void image_spoofed_syscall_stub();
#endif

    // Initialization and query helpers
    bool initialize();
    bool is_initialized();

    // Replaced std::optional with bool-out-param to support pre-C++17
    bool get_syscall_number(const std::string& function_name, uint32_t& out_syscall_number);
    bool get_gadget_address(const std::string& function_name, void*& out_gadget_address);

    // Internal helpers implemented in syscall.cpp

    // NOTE: Callers MUST hold g_syscall_mutex before calling this function.
    // Try exact name first, then "Nt<->Zw" alias fallback.
    bool try_get_entry_by_name_nolock(const std::string& name, syscall_entry*& out_entry);

    // Build or fetch an executable stub for a syscall number + gadget
    void* get_or_build_normal_stub(uint32_t syscall_number, void* gadget_address);

    // Build a spoofed stub (not cached due to dependency on spoof_cfg)
    void* build_spoofed_stub(uint32_t syscall_number, void* gadget_address, const stack_spoof_config& spoof_cfg);

    // Public API: invoke without stack spoofing
    template<typename Ret, typename... Args>
    inline Ret invoke(const std::string& syscall_name, Args... args) {
        bool needs_init = false;
        {
            std::lock_guard<std::mutex> lock(g_syscall_mutex);
            needs_init = !g_initialized;
        }
        if (needs_init) {
            initialize();
        }

        std::lock_guard<std::mutex> lock(g_syscall_mutex);

        syscall_entry* entry = nullptr;
        if (!try_get_entry_by_name_nolock(syscall_name, entry) || entry == nullptr || entry->gadget_address == nullptr) {
            return Ret{};
        }

        void* stub = get_or_build_normal_stub(entry->number, entry->gadget_address);
        if (!stub) {
            return Ret{};
        }

        using func_t = Ret(NTAPI*)(Args...);
        func_t fn = reinterpret_cast<func_t>(stub);
        return fn(std::forward<Args>(args)...);
    }

    // Public API: invoke with stack spoofing (if enabled in spoof_cfg)
    template<typename Ret, typename... Args>
    inline Ret invoke_spoofed(const std::string& syscall_name, const stack_spoof_config& spoof_cfg, Args... args) {
        bool needs_init = false;
        {
            std::lock_guard<std::mutex> lock(g_syscall_mutex);
            needs_init = !g_initialized;
        }
        if (needs_init) {
            initialize();
        }

        std::lock_guard<std::mutex> lock(g_syscall_mutex);

        syscall_entry* entry = nullptr;
        if (!try_get_entry_by_name_nolock(syscall_name, entry) || entry == nullptr || entry->gadget_address == nullptr) {
            return Ret{};
        }

        if (!spoof_cfg.enabled) {
            void* stub = get_or_build_normal_stub(entry->number, entry->gadget_address);
            if (!stub) {
                return Ret{};
            }
            using func_t = Ret(NTAPI*)(Args...);
            func_t fn = reinterpret_cast<func_t>(stub);
            return fn(std::forward<Args>(args)...);
        }

        void* stub = build_spoofed_stub(entry->number, entry->gadget_address, spoof_cfg);
        if (!stub) {
            return Ret{};
        }

        using func_t = Ret(NTAPI*)(Args...);
        func_t fn = reinterpret_cast<func_t>(stub);
        return fn(std::forward<Args>(args)...);
    }

    // Convenience: create stack spoofing config
    stack_spoof_config create_spoof_config(void* ret1 = nullptr, void* ret2 = nullptr, void* ret3 = nullptr);
}

#endif
