0x00471a00:	pusha
0x00471a01:	movl %esi, $0x45b000<UINT32>
0x00471a06:	leal %edi, -368640(%esi)
0x00471a0c:	pushl %edi
0x00471a0d:	jmp 0x00471a1a
0x00471a1a:	movl %ebx, (%esi)
0x00471a1c:	subl %esi, $0xfffffffc<UINT8>
0x00471a1f:	adcl %ebx, %ebx
0x00471a21:	jb 0x00471a10
0x00471a10:	movb %al, (%esi)
0x00471a12:	incl %esi
0x00471a13:	movb (%edi), %al
0x00471a15:	incl %edi
0x00471a16:	addl %ebx, %ebx
0x00471a18:	jne 0x00471a21
0x00471a23:	movl %eax, $0x1<UINT32>
0x00471a28:	addl %ebx, %ebx
0x00471a2a:	jne 0x00471a33
0x00471a33:	adcl %eax, %eax
0x00471a35:	addl %ebx, %ebx
0x00471a37:	jae 0x00471a44
0x00471a39:	jne 0x00471a63
0x00471a63:	xorl %ecx, %ecx
0x00471a65:	subl %eax, $0x3<UINT8>
0x00471a68:	jb 0x00471a7b
0x00471a6a:	shll %eax, $0x8<UINT8>
0x00471a6d:	movb %al, (%esi)
0x00471a6f:	incl %esi
0x00471a70:	xorl %eax, $0xffffffff<UINT8>
0x00471a73:	je 0x00471aea
0x00471a75:	sarl %eax
0x00471a77:	movl %ebp, %eax
0x00471a79:	jmp 0x00471a86
0x00471a86:	jb 0x00471a54
0x00471a54:	addl %ebx, %ebx
0x00471a56:	jne 0x00471a5f
0x00471a5f:	adcl %ecx, %ecx
0x00471a61:	jmp 0x00471ab5
0x00471ab5:	cmpl %ebp, $0xfffffb00<UINT32>
0x00471abb:	adcl %ecx, $0x2<UINT8>
0x00471abe:	leal %edx, (%edi,%ebp)
0x00471ac1:	cmpl %ebp, $0xfffffffc<UINT8>
0x00471ac4:	jbe 0x00471ad4
0x00471ad4:	movl %eax, (%edx)
0x00471ad6:	addl %edx, $0x4<UINT8>
0x00471ad9:	movl (%edi), %eax
0x00471adb:	addl %edi, $0x4<UINT8>
0x00471ade:	subl %ecx, $0x4<UINT8>
0x00471ae1:	ja 0x00471ad4
0x00471ae3:	addl %edi, %ecx
0x00471ae5:	jmp 0x00471a16
0x00471a88:	incl %ecx
0x00471a89:	addl %ebx, %ebx
0x00471a8b:	jne 0x00471a94
0x00471a94:	jb 0x00471a54
0x00471a7b:	addl %ebx, %ebx
0x00471a7d:	jne 0x00471a86
0x00471ac6:	movb %al, (%edx)
0x00471ac8:	incl %edx
0x00471ac9:	movb (%edi), %al
0x00471acb:	incl %edi
0x00471acc:	decl %ecx
0x00471acd:	jne 0x00471ac6
0x00471acf:	jmp 0x00471a16
0x00471a2c:	movl %ebx, (%esi)
0x00471a2e:	subl %esi, $0xfffffffc<UINT8>
0x00471a31:	adcl %ebx, %ebx
0x00471a96:	addl %ebx, %ebx
0x00471a98:	jne 0x00471aa1
0x00471aa1:	adcl %ecx, %ecx
0x00471aa3:	addl %ebx, %ebx
0x00471aa5:	jae 0x00471a96
0x00471aa7:	jne 0x00471ab2
0x00471ab2:	addl %ecx, $0x2<UINT8>
0x00471a44:	decl %eax
0x00471a45:	addl %ebx, %ebx
0x00471a47:	jne 0x00471a50
0x00471a50:	adcl %eax, %eax
0x00471a52:	jmp 0x00471a28
0x00471a7f:	movl %ebx, (%esi)
0x00471a81:	subl %esi, $0xfffffffc<UINT8>
0x00471a84:	adcl %ebx, %ebx
0x00471a3b:	movl %ebx, (%esi)
0x00471a3d:	subl %esi, $0xfffffffc<UINT8>
0x00471a40:	adcl %ebx, %ebx
0x00471a42:	jb 0x00471a63
0x00471a58:	movl %ebx, (%esi)
0x00471a5a:	subl %esi, $0xfffffffc<UINT8>
0x00471a5d:	adcl %ebx, %ebx
0x00471a9a:	movl %ebx, (%esi)
0x00471a9c:	subl %esi, $0xfffffffc<UINT8>
0x00471a9f:	adcl %ebx, %ebx
0x00471a49:	movl %ebx, (%esi)
0x00471a4b:	subl %esi, $0xfffffffc<UINT8>
0x00471a4e:	adcl %ebx, %ebx
0x00471aa9:	movl %ebx, (%esi)
0x00471aab:	subl %esi, $0xfffffffc<UINT8>
0x00471aae:	adcl %ebx, %ebx
0x00471ab0:	jae 0x00471a96
0x00471a8d:	movl %ebx, (%esi)
0x00471a8f:	subl %esi, $0xfffffffc<UINT8>
0x00471a92:	adcl %ebx, %ebx
0x00471aea:	popl %esi
0x00471aeb:	movl %edi, %esi
0x00471aed:	movl %ecx, $0xd08<UINT32>
0x00471af2:	movb %al, (%edi)
0x00471af4:	incl %edi
0x00471af5:	subb %al, $0xffffffe8<UINT8>
0x00471af7:	cmpb %al, $0x1<UINT8>
0x00471af9:	ja 0x00471af2
0x00471afb:	cmpb (%edi), $0xa<UINT8>
0x00471afe:	jne 0x00471af2
0x00471b00:	movl %eax, (%edi)
0x00471b02:	movb %bl, 0x4(%edi)
0x00471b05:	shrw %ax, $0x8<UINT8>
0x00471b09:	roll %eax, $0x10<UINT8>
0x00471b0c:	xchgb %ah, %al
0x00471b0e:	subl %eax, %edi
0x00471b10:	subb %bl, $0xffffffe8<UINT8>
0x00471b13:	addl %eax, %esi
0x00471b15:	movl (%edi), %eax
0x00471b17:	addl %edi, $0x5<UINT8>
0x00471b1a:	movb %al, %bl
0x00471b1c:	loop 0x00471af7
0x00471b1e:	leal %edi, 0x6f000(%esi)
0x00471b24:	movl %eax, (%edi)
0x00471b26:	orl %eax, %eax
0x00471b28:	je 0x00471b66
0x00471b2a:	movl %ebx, 0x4(%edi)
0x00471b2d:	leal %eax, 0x714fc(%eax,%esi)
0x00471b34:	addl %ebx, %esi
0x00471b36:	pushl %eax
0x00471b37:	addl %edi, $0x8<UINT8>
0x00471b3a:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x00471b40:	xchgl %ebp, %eax
0x00471b41:	movb %al, (%edi)
0x00471b43:	incl %edi
0x00471b44:	orb %al, %al
0x00471b46:	je 0x00471b24
0x00471b48:	movl %ecx, %edi
0x00471b4a:	pushl %edi
0x00471b4b:	decl %eax
0x00471b4c:	repn scasb %al, %es:(%edi)
0x00471b4e:	pushl %ebp
0x00471b4f:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00471b55:	orl %eax, %eax
0x00471b57:	je 7
0x00471b59:	movl (%ebx), %eax
0x00471b5b:	addl %ebx, $0x4<UINT8>
0x00471b5e:	jmp 0x00471b41
GetProcAddress@KERNEL32.DLL: API Node	
0x00471b66:	movl %ebp, 0x715ac(%esi)
0x00471b6c:	leal %edi, -4096(%esi)
0x00471b72:	movl %ebx, $0x1000<UINT32>
0x00471b77:	pushl %eax
0x00471b78:	pushl %esp
0x00471b79:	pushl $0x4<UINT8>
0x00471b7b:	pushl %ebx
0x00471b7c:	pushl %edi
0x00471b7d:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00471b7f:	leal %eax, 0x20f(%edi)
0x00471b85:	andb (%eax), $0x7f<UINT8>
0x00471b88:	andb 0x28(%eax), $0x7f<UINT8>
0x00471b8c:	popl %eax
0x00471b8d:	pushl %eax
0x00471b8e:	pushl %esp
0x00471b8f:	pushl %eax
0x00471b90:	pushl %ebx
0x00471b91:	pushl %edi
0x00471b92:	call VirtualProtect@kernel32.dll
0x00471b94:	popl %eax
0x00471b95:	popa
0x00471b96:	leal %eax, -128(%esp)
0x00471b9a:	pushl $0x0<UINT8>
0x00471b9c:	cmpl %esp, %eax
0x00471b9e:	jne 0x00471b9a
0x00471ba0:	subl %esp, $0xffffff80<UINT8>
0x00471ba3:	jmp 0x00407f58
0x00407f58:	call 0x00413cd6
0x00413cd6:	pushl %ebp
0x00413cd7:	movl %ebp, %esp
0x00413cd9:	subl %esp, $0x14<UINT8>
0x00413cdc:	andl -12(%ebp), $0x0<UINT8>
0x00413ce0:	andl -8(%ebp), $0x0<UINT8>
0x00413ce4:	movl %eax, 0x43a618
0x00413ce9:	pushl %esi
0x00413cea:	pushl %edi
0x00413ceb:	movl %edi, $0xbb40e64e<UINT32>
0x00413cf0:	movl %esi, $0xffff0000<UINT32>
0x00413cf5:	cmpl %eax, %edi
0x00413cf7:	je 0x00413d06
0x00413d06:	leal %eax, -12(%ebp)
0x00413d09:	pushl %eax
0x00413d0a:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x00413d10:	movl %eax, -8(%ebp)
0x00413d13:	xorl %eax, -12(%ebp)
0x00413d16:	movl -4(%ebp), %eax
0x00413d19:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x00413d1f:	xorl -4(%ebp), %eax
0x00413d22:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x00413d28:	xorl -4(%ebp), %eax
0x00413d2b:	leal %eax, -20(%ebp)
0x00413d2e:	pushl %eax
0x00413d2f:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x00413d35:	movl %ecx, -16(%ebp)
0x00413d38:	leal %eax, -4(%ebp)
0x00413d3b:	xorl %ecx, -20(%ebp)
0x00413d3e:	xorl %ecx, -4(%ebp)
0x00413d41:	xorl %ecx, %eax
0x00413d43:	cmpl %ecx, %edi
0x00413d45:	jne 0x00413d4e
0x00413d4e:	testl %esi, %ecx
0x00413d50:	jne 0x00413d5e
0x00413d5e:	movl 0x43a618, %ecx
0x00413d64:	notl %ecx
0x00413d66:	movl 0x43a61c, %ecx
0x00413d6c:	popl %edi
0x00413d6d:	popl %esi
0x00413d6e:	movl %esp, %ebp
0x00413d70:	popl %ebp
0x00413d71:	ret

0x00407f5d:	jmp 0x00407d97
0x00407d97:	pushl $0x14<UINT8>
0x00407d99:	pushl $0x4361f0<UINT32>
0x00407d9e:	call 0x00408d40
0x00408d40:	pushl $0x408de0<UINT32>
0x00408d45:	pushl %fs:0
0x00408d4c:	movl %eax, 0x10(%esp)
0x00408d50:	movl 0x10(%esp), %ebp
0x00408d54:	leal %ebp, 0x10(%esp)
0x00408d58:	subl %esp, %eax
0x00408d5a:	pushl %ebx
0x00408d5b:	pushl %esi
0x00408d5c:	pushl %edi
0x00408d5d:	movl %eax, 0x43a618
0x00408d62:	xorl -4(%ebp), %eax
0x00408d65:	xorl %eax, %ebp
0x00408d67:	pushl %eax
0x00408d68:	movl -24(%ebp), %esp
0x00408d6b:	pushl -8(%ebp)
0x00408d6e:	movl %eax, -4(%ebp)
0x00408d71:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00408d78:	movl -8(%ebp), %eax
0x00408d7b:	leal %eax, -16(%ebp)
0x00408d7e:	movl %fs:0, %eax
0x00408d84:	ret

0x00407da3:	pushl $0x1<UINT8>
0x00407da5:	call 0x00413c89
0x00413c89:	pushl %ebp
0x00413c8a:	movl %ebp, %esp
0x00413c8c:	movl %eax, 0x8(%ebp)
0x00413c8f:	movl 0x43c178, %eax
0x00413c94:	popl %ebp
0x00413c95:	ret

0x00407daa:	popl %ecx
0x00407dab:	movl %eax, $0x5a4d<UINT32>
0x00407db0:	cmpw 0x400000, %ax
0x00407db7:	je 0x00407dbd
0x00407dbd:	movl %eax, 0x40003c
0x00407dc2:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00407dcc:	jne -21
0x00407dce:	movl %ecx, $0x10b<UINT32>
0x00407dd3:	cmpw 0x400018(%eax), %cx
0x00407dda:	jne -35
0x00407ddc:	xorl %ebx, %ebx
0x00407dde:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00407de5:	jbe 9
0x00407de7:	cmpl 0x4000e8(%eax), %ebx
0x00407ded:	setne %bl
0x00407df0:	movl -28(%ebp), %ebx
0x00407df3:	call 0x0040d2a9
0x0040d2a9:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x0040d2af:	xorl %ecx, %ecx
0x0040d2b1:	movl 0x43c7d0, %eax
0x0040d2b6:	testl %eax, %eax
0x0040d2b8:	setne %cl
0x0040d2bb:	movl %eax, %ecx
0x0040d2bd:	ret

0x00407df8:	testl %eax, %eax
0x00407dfa:	jne 0x00407e04
0x00407e04:	call 0x0040bf83
0x0040bf83:	call 0x004065a7
0x004065a7:	pushl %esi
0x004065a8:	pushl $0x0<UINT8>
0x004065aa:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x004065b0:	movl %esi, %eax
0x004065b2:	pushl %esi
0x004065b3:	call 0x0040d296
0x0040d296:	pushl %ebp
0x0040d297:	movl %ebp, %esp
0x0040d299:	movl %eax, 0x8(%ebp)
0x0040d29c:	movl 0x43c7c8, %eax
0x0040d2a1:	popl %ebp
0x0040d2a2:	ret

0x004065b8:	pushl %esi
0x004065b9:	call 0x004090c3
0x004090c3:	pushl %ebp
0x004090c4:	movl %ebp, %esp
0x004090c6:	movl %eax, 0x8(%ebp)
0x004090c9:	movl 0x43c064, %eax
0x004090ce:	popl %ebp
0x004090cf:	ret

0x004065be:	pushl %esi
0x004065bf:	call 0x0040e169
0x0040e169:	pushl %ebp
0x0040e16a:	movl %ebp, %esp
0x0040e16c:	movl %eax, 0x8(%ebp)
0x0040e16f:	movl 0x43cafc, %eax
0x0040e174:	popl %ebp
0x0040e175:	ret

0x004065c4:	pushl %esi
0x004065c5:	call 0x0040e195
0x0040e195:	pushl %ebp
0x0040e196:	movl %ebp, %esp
0x0040e198:	movl %eax, 0x8(%ebp)
0x0040e19b:	movl 0x43cb00, %eax
0x0040e1a0:	movl 0x43cb04, %eax
0x0040e1a5:	movl 0x43cb08, %eax
0x0040e1aa:	movl 0x43cb0c, %eax
0x0040e1af:	popl %ebp
0x0040e1b0:	ret

0x004065ca:	pushl %esi
0x004065cb:	call 0x0040df7f
0x0040df7f:	pushl $0x40df38<UINT32>
0x0040df84:	call EncodePointer@KERNEL32.DLL
0x0040df8a:	movl 0x43caf8, %eax
0x0040df8f:	ret

0x004065d0:	pushl %esi
0x004065d1:	call 0x0040e6a2
0x0040e6a2:	pushl %ebp
0x0040e6a3:	movl %ebp, %esp
0x0040e6a5:	movl %eax, 0x8(%ebp)
0x0040e6a8:	movl 0x43cb14, %eax
0x0040e6ad:	popl %ebp
0x0040e6ae:	ret

0x004065d6:	addl %esp, $0x18<UINT8>
0x004065d9:	popl %esi
0x004065da:	jmp 0x0040abe5
0x0040abe5:	pushl %esi
0x0040abe6:	pushl %edi
0x0040abe7:	pushl $0x430738<UINT32>
0x0040abec:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0040abf2:	movl %esi, 0x4290d4
0x0040abf8:	movl %edi, %eax
0x0040abfa:	pushl $0x431398<UINT32>
0x0040abff:	pushl %edi
0x0040ac00:	call GetProcAddress@KERNEL32.DLL
0x0040ac02:	xorl %eax, 0x43a618
0x0040ac08:	pushl $0x4313a4<UINT32>
0x0040ac0d:	pushl %edi
0x0040ac0e:	movl 0x46d780, %eax
0x0040ac13:	call GetProcAddress@KERNEL32.DLL
0x0040ac15:	xorl %eax, 0x43a618
0x0040ac1b:	pushl $0x4313ac<UINT32>
0x0040ac20:	pushl %edi
0x0040ac21:	movl 0x46d784, %eax
0x0040ac26:	call GetProcAddress@KERNEL32.DLL
0x0040ac28:	xorl %eax, 0x43a618
0x0040ac2e:	pushl $0x4313b8<UINT32>
0x0040ac33:	pushl %edi
0x0040ac34:	movl 0x46d788, %eax
0x0040ac39:	call GetProcAddress@KERNEL32.DLL
0x0040ac3b:	xorl %eax, 0x43a618
0x0040ac41:	pushl $0x4313c4<UINT32>
0x0040ac46:	pushl %edi
0x0040ac47:	movl 0x46d78c, %eax
0x0040ac4c:	call GetProcAddress@KERNEL32.DLL
0x0040ac4e:	xorl %eax, 0x43a618
0x0040ac54:	pushl $0x4313e0<UINT32>
0x0040ac59:	pushl %edi
0x0040ac5a:	movl 0x46d790, %eax
0x0040ac5f:	call GetProcAddress@KERNEL32.DLL
0x0040ac61:	xorl %eax, 0x43a618
0x0040ac67:	pushl $0x4313f0<UINT32>
0x0040ac6c:	pushl %edi
0x0040ac6d:	movl 0x46d794, %eax
0x0040ac72:	call GetProcAddress@KERNEL32.DLL
0x0040ac74:	xorl %eax, 0x43a618
0x0040ac7a:	pushl $0x431404<UINT32>
0x0040ac7f:	pushl %edi
0x0040ac80:	movl 0x46d798, %eax
0x0040ac85:	call GetProcAddress@KERNEL32.DLL
0x0040ac87:	xorl %eax, 0x43a618
0x0040ac8d:	pushl $0x43141c<UINT32>
0x0040ac92:	pushl %edi
0x0040ac93:	movl 0x46d79c, %eax
0x0040ac98:	call GetProcAddress@KERNEL32.DLL
0x0040ac9a:	xorl %eax, 0x43a618
0x0040aca0:	pushl $0x431434<UINT32>
0x0040aca5:	pushl %edi
0x0040aca6:	movl 0x46d7a0, %eax
0x0040acab:	call GetProcAddress@KERNEL32.DLL
0x0040acad:	xorl %eax, 0x43a618
0x0040acb3:	pushl $0x431448<UINT32>
0x0040acb8:	pushl %edi
0x0040acb9:	movl 0x46d7a4, %eax
0x0040acbe:	call GetProcAddress@KERNEL32.DLL
0x0040acc0:	xorl %eax, 0x43a618
0x0040acc6:	pushl $0x431468<UINT32>
0x0040accb:	pushl %edi
0x0040accc:	movl 0x46d7a8, %eax
0x0040acd1:	call GetProcAddress@KERNEL32.DLL
0x0040acd3:	xorl %eax, 0x43a618
0x0040acd9:	pushl $0x431480<UINT32>
0x0040acde:	pushl %edi
0x0040acdf:	movl 0x46d7ac, %eax
0x0040ace4:	call GetProcAddress@KERNEL32.DLL
0x0040ace6:	xorl %eax, 0x43a618
0x0040acec:	pushl $0x431498<UINT32>
0x0040acf1:	pushl %edi
0x0040acf2:	movl 0x46d7b0, %eax
0x0040acf7:	call GetProcAddress@KERNEL32.DLL
0x0040acf9:	xorl %eax, 0x43a618
0x0040acff:	pushl $0x4314ac<UINT32>
0x0040ad04:	pushl %edi
0x0040ad05:	movl 0x46d7b4, %eax
0x0040ad0a:	call GetProcAddress@KERNEL32.DLL
0x0040ad0c:	xorl %eax, 0x43a618
0x0040ad12:	movl 0x46d7b8, %eax
0x0040ad17:	pushl $0x4314c0<UINT32>
0x0040ad1c:	pushl %edi
0x0040ad1d:	call GetProcAddress@KERNEL32.DLL
0x0040ad1f:	xorl %eax, 0x43a618
0x0040ad25:	pushl $0x4314dc<UINT32>
0x0040ad2a:	pushl %edi
0x0040ad2b:	movl 0x46d7bc, %eax
0x0040ad30:	call GetProcAddress@KERNEL32.DLL
0x0040ad32:	xorl %eax, 0x43a618
0x0040ad38:	pushl $0x4314fc<UINT32>
0x0040ad3d:	pushl %edi
0x0040ad3e:	movl 0x46d7c0, %eax
0x0040ad43:	call GetProcAddress@KERNEL32.DLL
0x0040ad45:	xorl %eax, 0x43a618
0x0040ad4b:	pushl $0x431518<UINT32>
0x0040ad50:	pushl %edi
0x0040ad51:	movl 0x46d7c4, %eax
0x0040ad56:	call GetProcAddress@KERNEL32.DLL
0x0040ad58:	xorl %eax, 0x43a618
0x0040ad5e:	pushl $0x431538<UINT32>
0x0040ad63:	pushl %edi
0x0040ad64:	movl 0x46d7c8, %eax
0x0040ad69:	call GetProcAddress@KERNEL32.DLL
0x0040ad6b:	xorl %eax, 0x43a618
0x0040ad71:	pushl $0x43154c<UINT32>
0x0040ad76:	pushl %edi
0x0040ad77:	movl 0x46d7cc, %eax
0x0040ad7c:	call GetProcAddress@KERNEL32.DLL
0x0040ad7e:	xorl %eax, 0x43a618
0x0040ad84:	pushl $0x431568<UINT32>
0x0040ad89:	pushl %edi
0x0040ad8a:	movl 0x46d7d0, %eax
0x0040ad8f:	call GetProcAddress@KERNEL32.DLL
0x0040ad91:	xorl %eax, 0x43a618
0x0040ad97:	pushl $0x43157c<UINT32>
0x0040ad9c:	pushl %edi
0x0040ad9d:	movl 0x46d7d8, %eax
0x0040ada2:	call GetProcAddress@KERNEL32.DLL
0x0040ada4:	xorl %eax, 0x43a618
0x0040adaa:	pushl $0x43158c<UINT32>
0x0040adaf:	pushl %edi
0x0040adb0:	movl 0x46d7d4, %eax
0x0040adb5:	call GetProcAddress@KERNEL32.DLL
0x0040adb7:	xorl %eax, 0x43a618
0x0040adbd:	pushl $0x43159c<UINT32>
0x0040adc2:	pushl %edi
0x0040adc3:	movl 0x46d7dc, %eax
0x0040adc8:	call GetProcAddress@KERNEL32.DLL
0x0040adca:	xorl %eax, 0x43a618
0x0040add0:	pushl $0x4315ac<UINT32>
0x0040add5:	pushl %edi
0x0040add6:	movl 0x46d7e0, %eax
0x0040addb:	call GetProcAddress@KERNEL32.DLL
0x0040addd:	xorl %eax, 0x43a618
0x0040ade3:	pushl $0x4315bc<UINT32>
0x0040ade8:	pushl %edi
0x0040ade9:	movl 0x46d7e4, %eax
0x0040adee:	call GetProcAddress@KERNEL32.DLL
0x0040adf0:	xorl %eax, 0x43a618
0x0040adf6:	pushl $0x4315d8<UINT32>
0x0040adfb:	pushl %edi
0x0040adfc:	movl 0x46d7e8, %eax
0x0040ae01:	call GetProcAddress@KERNEL32.DLL
0x0040ae03:	xorl %eax, 0x43a618
0x0040ae09:	pushl $0x4315ec<UINT32>
0x0040ae0e:	pushl %edi
0x0040ae0f:	movl 0x46d7ec, %eax
0x0040ae14:	call GetProcAddress@KERNEL32.DLL
0x0040ae16:	xorl %eax, 0x43a618
0x0040ae1c:	pushl $0x4315fc<UINT32>
0x0040ae21:	pushl %edi
0x0040ae22:	movl 0x46d7f0, %eax
0x0040ae27:	call GetProcAddress@KERNEL32.DLL
0x0040ae29:	xorl %eax, 0x43a618
0x0040ae2f:	pushl $0x431610<UINT32>
0x0040ae34:	pushl %edi
0x0040ae35:	movl 0x46d7f4, %eax
0x0040ae3a:	call GetProcAddress@KERNEL32.DLL
0x0040ae3c:	xorl %eax, 0x43a618
0x0040ae42:	movl 0x46d7f8, %eax
0x0040ae47:	pushl $0x431620<UINT32>
0x0040ae4c:	pushl %edi
0x0040ae4d:	call GetProcAddress@KERNEL32.DLL
0x0040ae4f:	xorl %eax, 0x43a618
0x0040ae55:	pushl $0x431640<UINT32>
0x0040ae5a:	pushl %edi
0x0040ae5b:	movl 0x46d7fc, %eax
0x0040ae60:	call GetProcAddress@KERNEL32.DLL
0x0040ae62:	xorl %eax, 0x43a618
0x0040ae68:	popl %edi
0x0040ae69:	movl 0x46d800, %eax
0x0040ae6e:	popl %esi
0x0040ae6f:	ret

0x0040bf88:	call 0x00408150
0x00408150:	pushl %esi
0x00408151:	pushl %edi
0x00408152:	movl %esi, $0x43a638<UINT32>
0x00408157:	movl %edi, $0x43bf10<UINT32>
0x0040815c:	cmpl 0x4(%esi), $0x1<UINT8>
0x00408160:	jne 22
0x00408162:	pushl $0x0<UINT8>
0x00408164:	movl (%esi), %edi
0x00408166:	addl %edi, $0x18<UINT8>
0x00408169:	pushl $0xfa0<UINT32>
0x0040816e:	pushl (%esi)
0x00408170:	call 0x0040ab77
0x0040ab77:	pushl %ebp
0x0040ab78:	movl %ebp, %esp
0x0040ab7a:	movl %eax, 0x46d790
0x0040ab7f:	xorl %eax, 0x43a618
0x0040ab85:	je 13
0x0040ab87:	pushl 0x10(%ebp)
0x0040ab8a:	pushl 0xc(%ebp)
0x0040ab8d:	pushl 0x8(%ebp)
0x0040ab90:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x0040ab92:	popl %ebp
0x0040ab93:	ret

0x00000fa0:	addb (%eax), %al
0x00000fa2:	addb (%eax), %al
0x00000fa4:	addb (%eax), %al
0x00000fa6:	addb (%eax), %al
0x00000fa8:	addb (%eax), %al
0x00000faa:	addb (%eax), %al
0x00000fac:	addb (%eax), %al
0x00000fae:	addb (%eax), %al
0x00000fb0:	addb (%eax), %al
0x00000fb2:	addb (%eax), %al
0x00000fb4:	addb (%eax), %al
0x00000fb6:	addb (%eax), %al
0x00000fb8:	addb (%eax), %al
0x00000fba:	addb (%eax), %al
0x00000fbc:	addb (%eax), %al
0x00000fbe:	addb (%eax), %al
0x00000fc0:	addb (%eax), %al
0x00000fc2:	addb (%eax), %al
0x00000fc4:	addb (%eax), %al
0x00000fc6:	addb (%eax), %al
0x00000fc8:	addb (%eax), %al
0x00000fca:	addb (%eax), %al
0x00000fcc:	addb (%eax), %al
0x00000fce:	addb (%eax), %al
0x00000fd0:	addb (%eax), %al
0x00000fd2:	addb (%eax), %al
0x00000fd4:	addb (%eax), %al
0x00000fd6:	addb (%eax), %al
0x00000fd8:	addb (%eax), %al
0x00000fda:	addb (%eax), %al
0x00000fdc:	addb (%eax), %al
0x00000fde:	addb (%eax), %al
0x00000fe0:	addb (%eax), %al
0x00000fe2:	addb (%eax), %al
0x00000fe4:	addb (%eax), %al
0x00000fe6:	addb (%eax), %al
0x00000fe8:	addb (%eax), %al
0x00000fea:	addb (%eax), %al
0x00000fec:	addb (%eax), %al
0x00000fee:	addb (%eax), %al
0x00000ff0:	addb (%eax), %al
0x00000ff2:	addb (%eax), %al
0x00000ff4:	addb (%eax), %al
0x00000ff6:	addb (%eax), %al
0x00000ff8:	addb (%eax), %al
0x00000ffa:	addb (%eax), %al
0x00000ffc:	addb (%eax), %al
0x00000ffe:	addb (%eax), %al
0x00001000:	addb (%eax), %al
0x00001002:	addb (%eax), %al
0x00001004:	addb (%eax), %al
0x00001006:	addb (%eax), %al
