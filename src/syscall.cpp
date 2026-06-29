#include <rop_syscall/syscall.hpp>

#include <vector>
#include <iterator>



namespace rop_syscall {

#if defined(_WIN64)
    extern "C" image_stub_context g_image_stub_ctx = {};
#endif

    // Definitions of globals
    std::mutex g_syscall_mutex;
    std::unordered_map<std::string, syscall_entry> g_syscall_map;
    bool g_initialized = false;

    namespace detail {

        // Convert RVA to file offset in PE
        static uint32_t rva_to_offset(uint32_t rva, IMAGE_NT_HEADERS* nt_headers) {
            IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt_headers);
            for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
                IMAGE_SECTION_HEADER& section = sections[i];
                if (rva >= section.VirtualAddress &&
                    rva < section.VirtualAddress + section.Misc.VirtualSize) {
                    return rva - section.VirtualAddress + section.PointerToRawData;
                }
            }
            return rva;
        }

        // Find a "syscall; ret" gadget in ntdll .text
        static void* find_syscall_gadget(HMODULE ntdll_handle) {
            if (!ntdll_handle) return nullptr;

            IMAGE_DOS_HEADER* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(ntdll_handle);
            IMAGE_NT_HEADERS* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(
                reinterpret_cast<uint8_t*>(ntdll_handle) + dos_header->e_lfanew);

            IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt_headers);

            for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
                IMAGE_SECTION_HEADER& section = sections[i];
                if (std::strncmp(reinterpret_cast<const char*>(section.Name), ".text", 5) == 0) {
                    uint8_t* section_start = reinterpret_cast<uint8_t*>(ntdll_handle) + section.VirtualAddress;
                    size_t section_size = section.Misc.VirtualSize;

                    for (size_t j = 0; j + 2 < section_size; j++) {
                        // 0F 05 C3  => syscall; ret
                        if (section_start[j] == 0x0F &&
                            section_start[j + 1] == 0x05 &&
                            section_start[j + 2] == 0xC3) {
                            return &section_start[j];
                        }
                    }
                }
            }
            return nullptr;
        }

        // Extract syscall numbers by scanning ntdll export stubs
        static bool extract_syscalls() {
            HMODULE ntdll_handle = GetModuleHandleA("ntdll.dll");
            if (!ntdll_handle) return false;

            void* common_gadget = find_syscall_gadget(ntdll_handle);
            if (!common_gadget) return false;

            char ntdll_path[MAX_PATH] = {};
            if (!GetModuleFileNameA(ntdll_handle, ntdll_path, MAX_PATH)) {
                return false;
            }

            std::ifstream ntdll_file(ntdll_path, std::ios::binary);
            if (!ntdll_file.is_open()) {
                return false;
            }

            std::vector<uint8_t> ntdll_data((std::istreambuf_iterator<char>(ntdll_file)),
                std::istreambuf_iterator<char>());
            ntdll_file.close();

            IMAGE_DOS_HEADER* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(ntdll_data.data());
            IMAGE_NT_HEADERS* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(
                ntdll_data.data() + dos_header->e_lfanew);

            uint32_t export_dir_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            IMAGE_EXPORT_DIRECTORY* export_dir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
                ntdll_data.data() + rva_to_offset(export_dir_rva, nt_headers));

            uint32_t* function_rvas = reinterpret_cast<uint32_t*>(
                ntdll_data.data() + rva_to_offset(export_dir->AddressOfFunctions, nt_headers));
            uint32_t* name_rvas = reinterpret_cast<uint32_t*>(
                ntdll_data.data() + rva_to_offset(export_dir->AddressOfNames, nt_headers));
            uint16_t* ordinals = reinterpret_cast<uint16_t*>(
                ntdll_data.data() + rva_to_offset(export_dir->AddressOfNameOrdinals, nt_headers));

            // Signature at start of syscall stubs in ntdll: 4C 8B D1 B8 (mov r10, rcx; mov eax, imm32)
            const uint32_t sig = 0xB8D18B4C;

            for (uint32_t i = 0; i < export_dir->NumberOfNames; i++) {
                const char* name = reinterpret_cast<const char*>(
                    ntdll_data.data() + rva_to_offset(name_rvas[i], nt_headers));

                uint16_t ordinal = ordinals[i];
                uint32_t function_rva = function_rvas[ordinal];
                uint8_t* function_start = ntdll_data.data() + rva_to_offset(function_rva, nt_headers);

                if (*reinterpret_cast<uint32_t*>(function_start) == sig) {
                    std::string func_name(name);
                    uint32_t syscall_number = *reinterpret_cast<uint32_t*>(function_start + 4);

                    syscall_entry entry;
                    entry.name = func_name;
                    entry.number = syscall_number;
                    entry.gadget_address = common_gadget;
                    entry.stub_normal = nullptr;

                    g_syscall_map.emplace(entry.name, entry);
                }
            }

            return !g_syscall_map.empty();
        }

        // Allocate executable memory and write code bytes
        static void* alloc_executable_stub(const std::vector<uint8_t>& code)
        {
            void* mem = VirtualAlloc(nullptr, code.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!mem) return nullptr;
            std::memcpy(mem, code.data(), code.size());
            DWORD oldProt;
            VirtualProtect(mem, code.size(), PAGE_EXECUTE_READ, &oldProt);
            FlushInstructionCache(GetCurrentProcess(), mem, code.size());
            return mem;
        }

        static void append_u32(std::vector<uint8_t>& code, uint32_t value)
        {
            uint8_t* p = reinterpret_cast<uint8_t*>(&value);
            code.insert(code.end(), p, p + sizeof(value));
        }

        static void append_u64(std::vector<uint8_t>& code, uint64_t value)
        {
            uint8_t* p = reinterpret_cast<uint8_t*>(&value);
            code.insert(code.end(), p, p + sizeof(value));
        }

        // Small emit helpers keep the stub layout readable and consistent.
        static void emit_mov_r10_rcx(std::vector<uint8_t>& code)
        {
            code.push_back(0x4C); code.push_back(0x8B); code.push_back(0xD1);
        }

        static void emit_mov_eax_imm32(std::vector<uint8_t>& code, uint32_t value)
        {
            code.push_back(0xB8);
            append_u32(code, value);
        }

        static void emit_mov_r11_imm64(std::vector<uint8_t>& code, void* value)
        {
            code.push_back(0x49); code.push_back(0xBB);
            append_u64(code, reinterpret_cast<uint64_t>(value));
        }

        static void emit_mov_rax_imm64(std::vector<uint8_t>& code, void* value)
        {
            code.push_back(0x48); code.push_back(0xB8);
            append_u64(code, reinterpret_cast<uint64_t>(value));
        }

        static void emit_mov_rax_rsp_disp32(std::vector<uint8_t>& code, uint32_t disp)
        {
            code.push_back(0x48); code.push_back(0x8B); code.push_back(0x84); code.push_back(0x24);
            append_u32(code, disp);
        }

        static void emit_mov_rsp_disp32_rax(std::vector<uint8_t>& code, uint32_t disp)
        {
            code.push_back(0x48); code.push_back(0x89); code.push_back(0x84); code.push_back(0x24);
            append_u32(code, disp);
        }

        static void emit_mov_r11_rsp_disp32(std::vector<uint8_t>& code, uint32_t disp)
        {
            code.push_back(0x4C); code.push_back(0x8B); code.push_back(0x9C); code.push_back(0x24);
            append_u32(code, disp);
        }

        static void emit_mov_rsp_disp32_r11(std::vector<uint8_t>& code, uint32_t disp)
        {
            code.push_back(0x4C); code.push_back(0x89); code.push_back(0x9C); code.push_back(0x24);
            append_u32(code, disp);
        }

        [[maybe_unused]] static void emit_push_rax(std::vector<uint8_t>& code)
        {
            code.push_back(0x50);
        }

        [[maybe_unused]] static void emit_push_r11(std::vector<uint8_t>& code)
        {
            code.push_back(0x41); code.push_back(0x53);
        }

        static void emit_call_r11(std::vector<uint8_t>& code)
        {
            code.push_back(0x41); code.push_back(0xFF); code.push_back(0xD3);
        }

        static void emit_jmp_r11(std::vector<uint8_t>& code)
        {
            code.push_back(0x41); code.push_back(0xFF); code.push_back(0xE3);
        }

        static void emit_sub_rsp_imm32(std::vector<uint8_t>& code, uint32_t value)
        {
            code.push_back(0x48); code.push_back(0x81); code.push_back(0xEC);
            append_u32(code, value);
        }

        static void emit_add_rsp_imm32(std::vector<uint8_t>& code, uint32_t value)
        {
            code.push_back(0x48); code.push_back(0x81); code.push_back(0xC4);
            append_u32(code, value);
        }

        // Build a non-spoofed stub:
        //   mov r10, rcx
        //   mov eax, imm32
        //   mov r11, imm64 (gadget)
        //   jmp r11
        static void* build_normal_stub_bytes(uint32_t syscall_number, void* gadget_address)
        {
            std::vector<uint8_t> code;
            code.reserve(3 + 5 + 10 + 3);

            emit_mov_r10_rcx(code);
            emit_mov_eax_imm32(code, syscall_number);
            emit_mov_r11_imm64(code, gadget_address);
            emit_jmp_r11(code);

            return alloc_executable_stub(code);
        }

        // Build a spoofed stub (Win64 ABI):
        // - Reserve shadow space + stack-args scratch + fake return slots
        // - Copy stack arguments to a new home area
        // - Lay out a fake call chain (3 return addresses)
        // - Execute syscall gadget via call
        // - Restore stack and return to caller
        static void* build_spoofed_stub_bytes(uint32_t syscall_number, void* gadget_address, const stack_spoof_config& spoof_cfg)
        {
            std::vector<uint8_t> code;

            const uint32_t kShadowSpace = 0x20;
            const uint32_t kStackArgHome = 0x28; // ret(8) + shadow(0x20)
            const uint32_t kArgSlotSize = 8;
            const uint32_t kMaxStackArgsToCopy = 16;
            const uint32_t kFakeReturnBytes = 0x18;
            const uint32_t reserve_size = kShadowSpace + kMaxStackArgsToCopy * kArgSlotSize + kFakeReturnBytes;

            // sub rsp, reserve_size (reserve shadow space + stack arg area + fake returns)
            emit_sub_rsp_imm32(code, reserve_size);

            const uint32_t kRetAddrOffset = reserve_size;
            const uint32_t kSavedRetOffset = reserve_size - kArgSlotSize;
            const bool kSpoofCallerReturn = spoof_cfg.fake_return_2 != nullptr;

            if (kSpoofCallerReturn) {
                // Save original return address and temporarily replace it with a fake one.
                emit_mov_rax_rsp_disp32(code, kRetAddrOffset);
                emit_mov_rsp_disp32_rax(code, kSavedRetOffset);
                emit_mov_rax_imm64(code, spoof_cfg.fake_return_2);
                emit_mov_rsp_disp32_rax(code, kRetAddrOffset);
            }

            const uint32_t kArgHomeOffset = kFakeReturnBytes + 0x08;

            // Copy original stack args to a new home:
            // Origin: [rsp + reserve_size + kStackArgHome + i*8] == original RSP + kStackArgHome + i*8
            // Target: [rsp + kArgHomeOffset + i*8]
            //
            // The kArgHomeOffset keeps arg5 at [rsp + 0x28] after:
            //   call gadget
            for (uint32_t i = 0; i < kMaxStackArgsToCopy; ++i) {
                uint32_t src_off = reserve_size + kStackArgHome + i * kArgSlotSize;
                uint32_t dst_off = kArgHomeOffset + i * kArgSlotSize;

                emit_mov_rax_rsp_disp32(code, src_off);
                emit_mov_rsp_disp32_rax(code, dst_off);
            }

            // Fake call chain (top-most return placed last in memory).
            emit_mov_r11_imm64(code, spoof_cfg.fake_return_1);
            emit_mov_rsp_disp32_r11(code, 0x08);
            emit_mov_rax_imm64(code, spoof_cfg.fake_return_2);
            emit_mov_rsp_disp32_rax(code, 0x10);
            emit_mov_r11_imm64(code, spoof_cfg.fake_return_3);
            emit_mov_rsp_disp32_r11(code, 0x00);

            emit_mov_r10_rcx(code);
            emit_mov_eax_imm32(code, syscall_number);
            emit_mov_r11_imm64(code, gadget_address);
            emit_call_r11(code);

            if (kSpoofCallerReturn) {
                // Restore original return address before leaving the stub.
                emit_mov_r11_rsp_disp32(code, kSavedRetOffset);
                emit_mov_rsp_disp32_r11(code, kRetAddrOffset);
            }

            // add rsp, reserve_size
            emit_add_rsp_imm32(code, reserve_size);

            // ret
            code.push_back(0xC3);

            return alloc_executable_stub(code);
        }

#if defined(_WIN64)
        typedef PRUNTIME_FUNCTION (NTAPI* rtl_lookup_function_entry_t)(DWORD64, PDWORD64, PUNWIND_HISTORY_TABLE);
#endif

        static bool has_valid_unwind_info(void* address)
        {
#if defined(_WIN64)
            if (!address) {
                return false;
            }
            HMODULE module = nullptr;
            if (!GetModuleHandleExA(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                    reinterpret_cast<LPCSTR>(address),
                    &module)) {
                return false;
            }
            HMODULE ntdll = GetModuleHandleA("ntdll.dll");
            if (!ntdll) {
                return false;
            }
            rtl_lookup_function_entry_t lookup = reinterpret_cast<rtl_lookup_function_entry_t>(
                GetProcAddress(ntdll, "RtlLookupFunctionEntry"));
            if (!lookup) {
                return false;
            }
            DWORD64 image_base = 0;
            PRUNTIME_FUNCTION entry = lookup(reinterpret_cast<DWORD64>(address), &image_base, nullptr);
            return entry != nullptr && image_base != 0;
#else
            return address != nullptr;
#endif
        }

        static void* pick_unwind_return_from_module(const char* module_name, const char* const* candidates, size_t count)
        {
            HMODULE module = GetModuleHandleA(module_name);
            if (!module) {
                return nullptr;
            }
            for (size_t i = 0; i < count; ++i) {
                FARPROC proc = GetProcAddress(module, candidates[i]);
                if (!proc) {
                    continue;
                }
                void* address = reinterpret_cast<void*>(proc);
                if (has_valid_unwind_info(address)) {
                    return address;
                }
            }
            return nullptr;
        }

        static void* resolve_unwind_return(void* preferred, const char* module_name, const char* const* candidates, size_t count)
        {
            if (preferred && has_valid_unwind_info(preferred)) {
                return preferred;
            }
            return pick_unwind_return_from_module(module_name, candidates, count);
        }

    } // namespace detail

    bool initialize() {
        if (g_initialized) {
            return true;
        }
        std::lock_guard<std::mutex> lock(g_syscall_mutex);
        if (g_initialized) return true;

        if (detail::extract_syscalls()) {
            g_initialized = true;
        }
        return g_initialized;
    }

    bool is_initialized() {
        std::lock_guard<std::mutex> lock(g_syscall_mutex);
        return g_initialized;
    }

    // Try exact name, then "Nt" <-> "Zw" alias swap
    bool try_get_entry_by_name_nolock(const std::string& name, syscall_entry*& out_entry) {
        out_entry = nullptr;

        std::unordered_map<std::string, syscall_entry>::iterator it = g_syscall_map.find(name);
        if (it != g_syscall_map.end()) {
            out_entry = &it->second;
            return true;
        }

        // Build alias: Nt<->Zw
        if (name.size() > 2) {
            if (name[0] == 'N' && name[1] == 't') {
                std::string alt = std::string("Zw") + name.substr(2);
                it = g_syscall_map.find(alt);
                if (it != g_syscall_map.end()) {
                    out_entry = &it->second;
                    return true;
                }
            }
            else if (name[0] == 'Z' && name[1] == 'w') {
                std::string alt = std::string("Nt") + name.substr(2);
                it = g_syscall_map.find(alt);
                if (it != g_syscall_map.end()) {
                    out_entry = &it->second;
                    return true;
                }
            }
        }

        return false;
    }

    bool get_syscall_number(const std::string& function_name, uint32_t& out_syscall_number) {
        std::lock_guard<std::mutex> lock(g_syscall_mutex);

        syscall_entry* entry = nullptr;
        if (!try_get_entry_by_name_nolock(function_name, entry) || entry == nullptr) {
            return false;
        }
        out_syscall_number = entry->number;
        return true;
    }

    bool get_gadget_address(const std::string& function_name, void*& out_gadget_address) {
        std::lock_guard<std::mutex> lock(g_syscall_mutex);

        syscall_entry* entry = nullptr;
        if (!try_get_entry_by_name_nolock(function_name, entry) || entry == nullptr) {
            return false;
        }
        out_gadget_address = entry->gadget_address;
        return true;
    }

    void* get_or_build_normal_stub(uint32_t syscall_number, void* gadget_address) {
        // Called with g_syscall_mutex held by public wrappers
        for (std::unordered_map<std::string, syscall_entry>::iterator it = g_syscall_map.begin();
            it != g_syscall_map.end(); ++it) {
            syscall_entry& e = it->second;
            if (e.number == syscall_number) {
                if (e.stub_normal) return e.stub_normal;
                e.stub_normal = detail::build_normal_stub_bytes(syscall_number, gadget_address);
                return e.stub_normal;
            }
        }
        // Not found by number; build and return uncached
        return detail::build_normal_stub_bytes(syscall_number, gadget_address);
    }

    void* build_spoofed_stub(uint32_t syscall_number, void* gadget_address, const stack_spoof_config& spoof_cfg)
    {
        if (!spoof_cfg.enabled ||
            spoof_cfg.fake_return_1 == nullptr ||
            spoof_cfg.fake_return_2 == nullptr ||
            spoof_cfg.fake_return_3 == nullptr) {
            return nullptr;
        }
#if defined(_WIN64)
        g_image_stub_ctx.syscall_number = syscall_number;
        g_image_stub_ctx.gadget_address = gadget_address;
        g_image_stub_ctx.fake_return_1 = spoof_cfg.fake_return_1;
        g_image_stub_ctx.fake_return_2 = spoof_cfg.fake_return_2;
        g_image_stub_ctx.fake_return_3 = spoof_cfg.fake_return_3;
        return reinterpret_cast<void*>(&image_spoofed_syscall_stub);
#else
        return detail::build_spoofed_stub_bytes(syscall_number, gadget_address, spoof_cfg);
#endif
    }

    stack_spoof_config create_spoof_config(void* ret1, void* ret2, void* ret3)
    {
        stack_spoof_config cfg;
        static const char* kNtdllReturns[] = {
            "RtlUserThreadStart",
            "RtlUserFiberStart",
            "RtlExitUserThread",
            "RtlExitUserProcess",
            "LdrInitializeThunk",
            "KiUserApcDispatcher",
            "KiUserExceptionDispatcher",
            "KiUserCallbackDispatcher"
        };
        static const char* kKernel32Returns[] = {
            "BaseThreadInitThunk",
            "ExitThread",
            "WaitForSingleObject",
            "Sleep",
            "SleepEx",
            "CloseHandle",
            "GetCurrentThread",
            "GetCurrentProcess"
        };
        static const char* kKernelBaseReturns[] = {
            "GetCurrentProcess",
            "GetCurrentThread",
            "WaitForSingleObject",
            "ExitThread",
            "Sleep",
            "SleepEx",
            "CloseHandle",
            "GetCurrentThread",
            "GetCurrentProcess"
        };

        cfg.fake_return_1 = detail::resolve_unwind_return(
            ret1,
            "ntdll.dll",
            kNtdllReturns,
            sizeof(kNtdllReturns) / sizeof(kNtdllReturns[0]));
        cfg.fake_return_2 = detail::resolve_unwind_return(
            ret2,
            "kernel32.dll",
            kKernel32Returns,
            sizeof(kKernel32Returns) / sizeof(kKernel32Returns[0]));
        cfg.fake_return_3 = detail::resolve_unwind_return(
            ret3,
            "kernelbase.dll",
            kKernelBaseReturns,
            sizeof(kKernelBaseReturns) / sizeof(kKernelBaseReturns[0]));
        cfg.enabled = (cfg.fake_return_1 != nullptr &&
                       cfg.fake_return_2 != nullptr &&
                       cfg.fake_return_3 != nullptr);
        if (!cfg.enabled) {
            cfg.fake_return_1 = nullptr;
            cfg.fake_return_2 = nullptr;
            cfg.fake_return_3 = nullptr;
        }
        return cfg;
    }

} // namespace rop_syscall
