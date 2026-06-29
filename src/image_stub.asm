option casemap:none

EXTERN g_image_stub_ctx:BYTE
PUBLIC image_spoofed_syscall_stub

.code
image_spoofed_syscall_stub PROC FRAME
    sub rsp, 0B8h
    .allocstack 0B8h
    .endprolog

    xor r11d, r11d
copy_loop:
    mov rax, qword ptr [rsp + 0B8h + 28h + r11*8]
    mov qword ptr [rsp + 20h + r11*8], rax
    inc r11
    cmp r11, 10h
    jl copy_loop

    ; Save and spoof caller return address (keeps real caller out of the stack trace)
    mov rax, qword ptr [rsp + 0B8h]
    mov qword ptr [rsp + 0B0h], rax
    mov rax, qword ptr [g_image_stub_ctx + 24]
    test rax, rax
    je skip_ret_spoof
    mov qword ptr [rsp + 0B8h], rax
skip_ret_spoof:

    mov r11, qword ptr [g_image_stub_ctx + 16]
    mov qword ptr [rsp + 08h], r11
    mov rax, qword ptr [g_image_stub_ctx + 24]
    mov qword ptr [rsp + 10h], rax
    mov r11, qword ptr [g_image_stub_ctx + 32]
    mov qword ptr [rsp + 00h], r11

    mov r10, rcx
    mov eax, dword ptr [g_image_stub_ctx + 0]
    mov r11, qword ptr [g_image_stub_ctx + 8]
    call r11

    mov r11, qword ptr [rsp + 0B0h]
    mov qword ptr [rsp + 0B8h], r11

    add rsp, 0B8h
    ret
image_spoofed_syscall_stub ENDP

END
