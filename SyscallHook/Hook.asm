extern halCounterQueryRoutine:QWORD
extern circularKernelContextLogger:QWORD
extern keQueryPerformanceCounterHook:PROC
.code
; Not the most reliable and clean check, but still better than
; having to pattern scan for functions and checking the stack backtrace
checkLogger PROC
	cmp rbx, circularKernelContextLogger
	je correctLogger
	cmp rbp, circularKernelContextLogger
	je correctLogger
	cmp rsi, circularKernelContextLogger
	je correctLogger
	cmp rdi, circularKernelContextLogger
	je correctLogger
	cmp r10, circularKernelContextLogger
	je correctLogger
	cmp r11, circularKernelContextLogger
	je correctLogger
	cmp r12, circularKernelContextLogger
	je correctLogger
	cmp r13, circularKernelContextLogger
	je correctLogger
	cmp r14, circularKernelContextLogger
	je correctLogger
	cmp r15, circularKernelContextLogger
	jne exit
correctLogger:
	push rcx
	push rdx
	push r8
	push r9
	call keQueryPerformanceCounterHook
	pop r9
	pop r8
	pop rdx
	pop rcx
exit:
	mov rax, halCounterQueryRoutine
	jmp rax
checkLogger ENDP
end