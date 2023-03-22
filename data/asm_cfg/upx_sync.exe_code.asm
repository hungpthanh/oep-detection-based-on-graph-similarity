0x00427af0:	pusha
0x00427af1:	movl %esi, $0x41b000<UINT32>
0x00427af6:	leal %edi, -106496(%esi)
0x00427afc:	pushl %edi
0x00427afd:	orl %ebp, $0xffffffff<UINT8>
0x00427b00:	jmp 0x00427b12
0x00427b12:	movl %ebx, (%esi)
0x00427b14:	subl %esi, $0xfffffffc<UINT8>
0x00427b17:	adcl %ebx, %ebx
0x00427b19:	jb 0x00427b08
0x00427b08:	movb %al, (%esi)
0x00427b0a:	incl %esi
0x00427b0b:	movb (%edi), %al
0x00427b0d:	incl %edi
0x00427b0e:	addl %ebx, %ebx
0x00427b10:	jne 0x00427b19
0x00427b1b:	movl %eax, $0x1<UINT32>
0x00427b20:	addl %ebx, %ebx
0x00427b22:	jne 0x00427b2b
0x00427b2b:	adcl %eax, %eax
0x00427b2d:	addl %ebx, %ebx
0x00427b2f:	jae 0x00427b20
0x00427b31:	jne 0x00427b3c
0x00427b3c:	xorl %ecx, %ecx
0x00427b3e:	subl %eax, $0x3<UINT8>
0x00427b41:	jb 0x00427b50
0x00427b50:	addl %ebx, %ebx
0x00427b52:	jne 0x00427b5b
0x00427b5b:	adcl %ecx, %ecx
0x00427b5d:	addl %ebx, %ebx
0x00427b5f:	jne 0x00427b68
0x00427b68:	adcl %ecx, %ecx
0x00427b6a:	jne 0x00427b8c
0x00427b8c:	cmpl %ebp, $0xfffff300<UINT32>
0x00427b92:	adcl %ecx, $0x1<UINT8>
0x00427b95:	leal %edx, (%edi,%ebp)
0x00427b98:	cmpl %ebp, $0xfffffffc<UINT8>
0x00427b9b:	jbe 0x00427bac
0x00427b9d:	movb %al, (%edx)
0x00427b9f:	incl %edx
0x00427ba0:	movb (%edi), %al
0x00427ba2:	incl %edi
0x00427ba3:	decl %ecx
0x00427ba4:	jne 0x00427b9d
0x00427ba6:	jmp 0x00427b0e
0x00427b43:	shll %eax, $0x8<UINT8>
0x00427b46:	movb %al, (%esi)
0x00427b48:	incl %esi
0x00427b49:	xorl %eax, $0xffffffff<UINT8>
0x00427b4c:	je 0x00427bc2
0x00427b4e:	movl %ebp, %eax
0x00427bac:	movl %eax, (%edx)
0x00427bae:	addl %edx, $0x4<UINT8>
0x00427bb1:	movl (%edi), %eax
0x00427bb3:	addl %edi, $0x4<UINT8>
0x00427bb6:	subl %ecx, $0x4<UINT8>
0x00427bb9:	ja 0x00427bac
0x00427bbb:	addl %edi, %ecx
0x00427bbd:	jmp 0x00427b0e
0x00427b54:	movl %ebx, (%esi)
0x00427b56:	subl %esi, $0xfffffffc<UINT8>
0x00427b59:	adcl %ebx, %ebx
0x00427b6c:	incl %ecx
0x00427b6d:	addl %ebx, %ebx
0x00427b6f:	jne 0x00427b78
0x00427b78:	adcl %ecx, %ecx
0x00427b7a:	addl %ebx, %ebx
0x00427b7c:	jae 0x00427b6d
0x00427b7e:	jne 0x00427b89
0x00427b89:	addl %ecx, $0x2<UINT8>
0x00427b61:	movl %ebx, (%esi)
0x00427b63:	subl %esi, $0xfffffffc<UINT8>
0x00427b66:	adcl %ebx, %ebx
0x00427b24:	movl %ebx, (%esi)
0x00427b26:	subl %esi, $0xfffffffc<UINT8>
0x00427b29:	adcl %ebx, %ebx
0x00427b33:	movl %ebx, (%esi)
0x00427b35:	subl %esi, $0xfffffffc<UINT8>
0x00427b38:	adcl %ebx, %ebx
0x00427b3a:	jae 0x00427b20
0x00427b80:	movl %ebx, (%esi)
0x00427b82:	subl %esi, $0xfffffffc<UINT8>
0x00427b85:	adcl %ebx, %ebx
0x00427b87:	jae 0x00427b6d
0x00427b71:	movl %ebx, (%esi)
0x00427b73:	subl %esi, $0xfffffffc<UINT8>
0x00427b76:	adcl %ebx, %ebx
0x00427bc2:	popl %esi
0x00427bc3:	movl %edi, %esi
0x00427bc5:	movl %ecx, $0x5d2<UINT32>
0x00427bca:	movb %al, (%edi)
0x00427bcc:	incl %edi
0x00427bcd:	subb %al, $0xffffffe8<UINT8>
0x00427bcf:	cmpb %al, $0x1<UINT8>
0x00427bd1:	ja 0x00427bca
0x00427bd3:	cmpb (%edi), $0x5<UINT8>
0x00427bd6:	jne 0x00427bca
0x00427bd8:	movl %eax, (%edi)
0x00427bda:	movb %bl, 0x4(%edi)
0x00427bdd:	shrw %ax, $0x8<UINT8>
0x00427be1:	roll %eax, $0x10<UINT8>
0x00427be4:	xchgb %ah, %al
0x00427be6:	subl %eax, %edi
0x00427be8:	subb %bl, $0xffffffe8<UINT8>
0x00427beb:	addl %eax, %esi
0x00427bed:	movl (%edi), %eax
0x00427bef:	addl %edi, $0x5<UINT8>
0x00427bf2:	movb %al, %bl
0x00427bf4:	loop 0x00427bcf
0x00427bf6:	leal %edi, 0x24000(%esi)
0x00427bfc:	movl %eax, (%edi)
0x00427bfe:	orl %eax, %eax
0x00427c00:	je 0x00427c3e
0x00427c02:	movl %ebx, 0x4(%edi)
0x00427c05:	leal %eax, 0x27538(%eax,%esi)
0x00427c0c:	addl %ebx, %esi
0x00427c0e:	pushl %eax
0x00427c0f:	addl %edi, $0x8<UINT8>
0x00427c12:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00427c18:	xchgl %ebp, %eax
0x00427c19:	movb %al, (%edi)
0x00427c1b:	incl %edi
0x00427c1c:	orb %al, %al
0x00427c1e:	je 0x00427bfc
0x00427c20:	movl %ecx, %edi
0x00427c22:	pushl %edi
0x00427c23:	decl %eax
0x00427c24:	repn scasb %al, %es:(%edi)
0x00427c26:	pushl %ebp
0x00427c27:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00427c2d:	orl %eax, %eax
0x00427c2f:	je 7
0x00427c31:	movl (%ebx), %eax
0x00427c33:	addl %ebx, $0x4<UINT8>
0x00427c36:	jmp 0x00427c19
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x00427c3e:	addl %edi, $0x4<UINT8>
0x00427c41:	leal %ebx, -4(%esi)
0x00427c44:	xorl %eax, %eax
0x00427c46:	movb %al, (%edi)
0x00427c48:	incl %edi
0x00427c49:	orl %eax, %eax
0x00427c4b:	je 0x00427c6f
0x00427c4d:	cmpb %al, $0xffffffef<UINT8>
0x00427c4f:	ja 0x00427c62
0x00427c51:	addl %ebx, %eax
0x00427c53:	movl %eax, (%ebx)
0x00427c55:	xchgb %ah, %al
0x00427c57:	roll %eax, $0x10<UINT8>
0x00427c5a:	xchgb %ah, %al
0x00427c5c:	addl %eax, %esi
0x00427c5e:	movl (%ebx), %eax
0x00427c60:	jmp 0x00427c44
0x00427c62:	andb %al, $0xf<UINT8>
0x00427c64:	shll %eax, $0x10<UINT8>
0x00427c67:	movw %ax, (%edi)
0x00427c6a:	addl %edi, $0x2<UINT8>
0x00427c6d:	jmp 0x00427c51
0x00427c6f:	movl %ebp, 0x275e8(%esi)
0x00427c75:	leal %edi, -4096(%esi)
0x00427c7b:	movl %ebx, $0x1000<UINT32>
0x00427c80:	pushl %eax
0x00427c81:	pushl %esp
0x00427c82:	pushl $0x4<UINT8>
0x00427c84:	pushl %ebx
0x00427c85:	pushl %edi
0x00427c86:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00427c88:	leal %eax, 0x20f(%edi)
0x00427c8e:	andb (%eax), $0x7f<UINT8>
0x00427c91:	andb 0x28(%eax), $0x7f<UINT8>
0x00427c95:	popl %eax
0x00427c96:	pushl %eax
0x00427c97:	pushl %esp
0x00427c98:	pushl %eax
0x00427c99:	pushl %ebx
0x00427c9a:	pushl %edi
0x00427c9b:	call VirtualProtect@kernel32.dll
0x00427c9d:	popl %eax
0x00427c9e:	popa
0x00427c9f:	leal %eax, -128(%esp)
0x00427ca3:	pushl $0x0<UINT8>
0x00427ca5:	cmpl %esp, %eax
0x00427ca7:	jne 0x00427ca3
0x00427ca9:	subl %esp, $0xffffff80<UINT8>
0x00427cac:	jmp 0x004049fe
0x004049fe:	call 0x0040a3a4
0x0040a3a4:	pushl %ebp
0x0040a3a5:	movl %ebp, %esp
0x0040a3a7:	subl %esp, $0x14<UINT8>
0x0040a3aa:	andl -12(%ebp), $0x0<UINT8>
0x0040a3ae:	andl -8(%ebp), $0x0<UINT8>
0x0040a3b2:	movl %eax, 0x41e348
0x0040a3b7:	pushl %esi
0x0040a3b8:	pushl %edi
0x0040a3b9:	movl %edi, $0xbb40e64e<UINT32>
0x0040a3be:	movl %esi, $0xffff0000<UINT32>
0x0040a3c3:	cmpl %eax, %edi
0x0040a3c5:	je 0x0040a3d4
0x0040a3d4:	leal %eax, -12(%ebp)
0x0040a3d7:	pushl %eax
0x0040a3d8:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040a3de:	movl %eax, -8(%ebp)
0x0040a3e1:	xorl %eax, -12(%ebp)
0x0040a3e4:	movl -4(%ebp), %eax
0x0040a3e7:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040a3ed:	xorl -4(%ebp), %eax
0x0040a3f0:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040a3f6:	xorl -4(%ebp), %eax
0x0040a3f9:	leal %eax, -20(%ebp)
0x0040a3fc:	pushl %eax
0x0040a3fd:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040a403:	movl %ecx, -16(%ebp)
0x0040a406:	leal %eax, -4(%ebp)
0x0040a409:	xorl %ecx, -20(%ebp)
0x0040a40c:	xorl %ecx, -4(%ebp)
0x0040a40f:	xorl %ecx, %eax
0x0040a411:	cmpl %ecx, %edi
0x0040a413:	jne 0x0040a41c
0x0040a41c:	testl %esi, %ecx
0x0040a41e:	jne 0x0040a42c
0x0040a42c:	movl 0x41e348, %ecx
0x0040a432:	notl %ecx
0x0040a434:	movl 0x41e34c, %ecx
0x0040a43a:	popl %edi
0x0040a43b:	popl %esi
0x0040a43c:	movl %esp, %ebp
0x0040a43e:	popl %ebp
0x0040a43f:	ret

0x00404a03:	jmp 0x00404883
0x00404883:	pushl $0x14<UINT8>
0x00404885:	pushl $0x41ca38<UINT32>
0x0040488a:	call 0x00405740
0x00405740:	pushl $0x4057a0<UINT32>
0x00405745:	pushl %fs:0
0x0040574c:	movl %eax, 0x10(%esp)
0x00405750:	movl 0x10(%esp), %ebp
0x00405754:	leal %ebp, 0x10(%esp)
0x00405758:	subl %esp, %eax
0x0040575a:	pushl %ebx
0x0040575b:	pushl %esi
0x0040575c:	pushl %edi
0x0040575d:	movl %eax, 0x41e348
0x00405762:	xorl -4(%ebp), %eax
0x00405765:	xorl %eax, %ebp
0x00405767:	pushl %eax
0x00405768:	movl -24(%ebp), %esp
0x0040576b:	pushl -8(%ebp)
0x0040576e:	movl %eax, -4(%ebp)
0x00405771:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00405778:	movl -8(%ebp), %eax
0x0040577b:	leal %eax, -16(%ebp)
0x0040577e:	movl %fs:0, %eax
0x00405784:	ret

0x0040488f:	pushl $0x1<UINT8>
0x00404891:	call 0x0040a357
0x0040a357:	pushl %ebp
0x0040a358:	movl %ebp, %esp
0x0040a35a:	movl %eax, 0x8(%ebp)
0x0040a35d:	movl 0x41f560, %eax
0x0040a362:	popl %ebp
0x0040a363:	ret

0x00404896:	popl %ecx
0x00404897:	movl %eax, $0x5a4d<UINT32>
0x0040489c:	cmpw 0x400000, %ax
0x004048a3:	je 0x004048a9
0x004048a9:	movl %eax, 0x40003c
0x004048ae:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x004048b8:	jne -21
0x004048ba:	movl %ecx, $0x10b<UINT32>
0x004048bf:	cmpw 0x400018(%eax), %cx
0x004048c6:	jne -35
0x004048c8:	xorl %ebx, %ebx
0x004048ca:	cmpl 0x400074(%eax), $0xe<UINT8>
0x004048d1:	jbe 9
0x004048d3:	cmpl 0x4000e8(%eax), %ebx
0x004048d9:	setne %bl
0x004048dc:	movl -28(%ebp), %ebx
0x004048df:	call 0x00409299
0x00409299:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x0040929f:	xorl %ecx, %ecx
0x004092a1:	movl 0x41fbb8, %eax
0x004092a6:	testl %eax, %eax
0x004092a8:	setne %cl
0x004092ab:	movl %eax, %ecx
0x004092ad:	ret

0x004048e4:	testl %eax, %eax
0x004048e6:	jne 0x004048f0
0x004048f0:	call 0x00409181
0x00409181:	call 0x00403adc
0x00403adc:	pushl %esi
0x00403add:	pushl $0x0<UINT8>
0x00403adf:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00403ae5:	movl %esi, %eax
0x00403ae7:	pushl %esi
0x00403ae8:	call 0x0040928c
0x0040928c:	pushl %ebp
0x0040928d:	movl %ebp, %esp
0x0040928f:	movl %eax, 0x8(%ebp)
0x00409292:	movl 0x41fbb0, %eax
0x00409297:	popl %ebp
0x00409298:	ret

0x00403aed:	pushl %esi
0x00403aee:	call 0x00405a59
0x00405a59:	pushl %ebp
0x00405a5a:	movl %ebp, %esp
0x00405a5c:	movl %eax, 0x8(%ebp)
0x00405a5f:	movl 0x41f44c, %eax
0x00405a64:	popl %ebp
0x00405a65:	ret

0x00403af3:	pushl %esi
0x00403af4:	call 0x004097c5
0x004097c5:	pushl %ebp
0x004097c6:	movl %ebp, %esp
0x004097c8:	movl %eax, 0x8(%ebp)
0x004097cb:	movl 0x41fee4, %eax
0x004097d0:	popl %ebp
0x004097d1:	ret

0x00403af9:	pushl %esi
0x00403afa:	call 0x004097df
0x004097df:	pushl %ebp
0x004097e0:	movl %ebp, %esp
0x004097e2:	movl %eax, 0x8(%ebp)
0x004097e5:	movl 0x41fee8, %eax
0x004097ea:	movl 0x41feec, %eax
0x004097ef:	movl 0x41fef0, %eax
0x004097f4:	movl 0x41fef4, %eax
0x004097f9:	popl %ebp
0x004097fa:	ret

0x00403aff:	pushl %esi
0x00403b00:	call 0x004097b4
0x004097b4:	pushl $0x409780<UINT32>
0x004097b9:	call EncodePointer@KERNEL32.DLL
0x004097bf:	movl 0x41fee0, %eax
0x004097c4:	ret

0x00403b05:	pushl %esi
0x00403b06:	call 0x004099f0
0x004099f0:	pushl %ebp
0x004099f1:	movl %ebp, %esp
0x004099f3:	movl %eax, 0x8(%ebp)
0x004099f6:	movl 0x41fefc, %eax
0x004099fb:	popl %ebp
0x004099fc:	ret

0x00403b0b:	addl %esp, $0x18<UINT8>
0x00403b0e:	popl %esi
0x00403b0f:	jmp 0x00407e6d
0x00407e6d:	pushl %esi
0x00407e6e:	pushl %edi
0x00407e6f:	pushl $0x418ce4<UINT32>
0x00407e74:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00407e7a:	movl %esi, 0x412094
0x00407e80:	movl %edi, %eax
0x00407e82:	pushl $0x418d00<UINT32>
0x00407e87:	pushl %edi
0x00407e88:	call GetProcAddress@KERNEL32.DLL
0x00407e8a:	xorl %eax, 0x41e348
0x00407e90:	pushl $0x418d0c<UINT32>
0x00407e95:	pushl %edi
0x00407e96:	movl 0x420060, %eax
0x00407e9b:	call GetProcAddress@KERNEL32.DLL
0x00407e9d:	xorl %eax, 0x41e348
0x00407ea3:	pushl $0x418d14<UINT32>
0x00407ea8:	pushl %edi
0x00407ea9:	movl 0x420064, %eax
0x00407eae:	call GetProcAddress@KERNEL32.DLL
0x00407eb0:	xorl %eax, 0x41e348
0x00407eb6:	pushl $0x418d20<UINT32>
0x00407ebb:	pushl %edi
0x00407ebc:	movl 0x420068, %eax
0x00407ec1:	call GetProcAddress@KERNEL32.DLL
0x00407ec3:	xorl %eax, 0x41e348
0x00407ec9:	pushl $0x418d2c<UINT32>
0x00407ece:	pushl %edi
0x00407ecf:	movl 0x42006c, %eax
0x00407ed4:	call GetProcAddress@KERNEL32.DLL
0x00407ed6:	xorl %eax, 0x41e348
0x00407edc:	pushl $0x418d48<UINT32>
0x00407ee1:	pushl %edi
0x00407ee2:	movl 0x420070, %eax
0x00407ee7:	call GetProcAddress@KERNEL32.DLL
0x00407ee9:	xorl %eax, 0x41e348
0x00407eef:	pushl $0x418d58<UINT32>
0x00407ef4:	pushl %edi
0x00407ef5:	movl 0x420074, %eax
0x00407efa:	call GetProcAddress@KERNEL32.DLL
0x00407efc:	xorl %eax, 0x41e348
0x00407f02:	pushl $0x418d6c<UINT32>
0x00407f07:	pushl %edi
0x00407f08:	movl 0x420078, %eax
0x00407f0d:	call GetProcAddress@KERNEL32.DLL
0x00407f0f:	xorl %eax, 0x41e348
0x00407f15:	pushl $0x418d84<UINT32>
0x00407f1a:	pushl %edi
0x00407f1b:	movl 0x42007c, %eax
0x00407f20:	call GetProcAddress@KERNEL32.DLL
0x00407f22:	xorl %eax, 0x41e348
0x00407f28:	pushl $0x418d9c<UINT32>
0x00407f2d:	pushl %edi
0x00407f2e:	movl 0x420080, %eax
0x00407f33:	call GetProcAddress@KERNEL32.DLL
0x00407f35:	xorl %eax, 0x41e348
0x00407f3b:	pushl $0x418db0<UINT32>
0x00407f40:	pushl %edi
0x00407f41:	movl 0x420084, %eax
0x00407f46:	call GetProcAddress@KERNEL32.DLL
0x00407f48:	xorl %eax, 0x41e348
0x00407f4e:	pushl $0x418dd0<UINT32>
0x00407f53:	pushl %edi
0x00407f54:	movl 0x420088, %eax
0x00407f59:	call GetProcAddress@KERNEL32.DLL
0x00407f5b:	xorl %eax, 0x41e348
0x00407f61:	pushl $0x418de8<UINT32>
0x00407f66:	pushl %edi
0x00407f67:	movl 0x42008c, %eax
0x00407f6c:	call GetProcAddress@KERNEL32.DLL
0x00407f6e:	xorl %eax, 0x41e348
0x00407f74:	pushl $0x418e00<UINT32>
0x00407f79:	pushl %edi
0x00407f7a:	movl 0x420090, %eax
0x00407f7f:	call GetProcAddress@KERNEL32.DLL
0x00407f81:	xorl %eax, 0x41e348
0x00407f87:	pushl $0x418e14<UINT32>
0x00407f8c:	pushl %edi
0x00407f8d:	movl 0x420094, %eax
0x00407f92:	call GetProcAddress@KERNEL32.DLL
0x00407f94:	xorl %eax, 0x41e348
0x00407f9a:	movl 0x420098, %eax
0x00407f9f:	pushl $0x418e28<UINT32>
0x00407fa4:	pushl %edi
0x00407fa5:	call GetProcAddress@KERNEL32.DLL
0x00407fa7:	xorl %eax, 0x41e348
0x00407fad:	pushl $0x418e44<UINT32>
0x00407fb2:	pushl %edi
0x00407fb3:	movl 0x42009c, %eax
0x00407fb8:	call GetProcAddress@KERNEL32.DLL
0x00407fba:	xorl %eax, 0x41e348
0x00407fc0:	pushl $0x418e64<UINT32>
0x00407fc5:	pushl %edi
0x00407fc6:	movl 0x4200a0, %eax
0x00407fcb:	call GetProcAddress@KERNEL32.DLL
0x00407fcd:	xorl %eax, 0x41e348
0x00407fd3:	pushl $0x418e80<UINT32>
0x00407fd8:	pushl %edi
0x00407fd9:	movl 0x4200a4, %eax
0x00407fde:	call GetProcAddress@KERNEL32.DLL
0x00407fe0:	xorl %eax, 0x41e348
0x00407fe6:	pushl $0x418ea0<UINT32>
0x00407feb:	pushl %edi
0x00407fec:	movl 0x4200a8, %eax
0x00407ff1:	call GetProcAddress@KERNEL32.DLL
0x00407ff3:	xorl %eax, 0x41e348
0x00407ff9:	pushl $0x418eb4<UINT32>
0x00407ffe:	pushl %edi
0x00407fff:	movl 0x4200ac, %eax
0x00408004:	call GetProcAddress@KERNEL32.DLL
0x00408006:	xorl %eax, 0x41e348
0x0040800c:	pushl $0x418ed0<UINT32>
0x00408011:	pushl %edi
0x00408012:	movl 0x4200b0, %eax
0x00408017:	call GetProcAddress@KERNEL32.DLL
0x00408019:	xorl %eax, 0x41e348
0x0040801f:	pushl $0x418ee4<UINT32>
0x00408024:	pushl %edi
0x00408025:	movl 0x4200b8, %eax
0x0040802a:	call GetProcAddress@KERNEL32.DLL
0x0040802c:	xorl %eax, 0x41e348
0x00408032:	pushl $0x418ef4<UINT32>
0x00408037:	pushl %edi
0x00408038:	movl 0x4200b4, %eax
0x0040803d:	call GetProcAddress@KERNEL32.DLL
0x0040803f:	xorl %eax, 0x41e348
0x00408045:	pushl $0x418f04<UINT32>
0x0040804a:	pushl %edi
0x0040804b:	movl 0x4200bc, %eax
0x00408050:	call GetProcAddress@KERNEL32.DLL
0x00408052:	xorl %eax, 0x41e348
0x00408058:	pushl $0x418f14<UINT32>
0x0040805d:	pushl %edi
0x0040805e:	movl 0x4200c0, %eax
0x00408063:	call GetProcAddress@KERNEL32.DLL
0x00408065:	xorl %eax, 0x41e348
0x0040806b:	pushl $0x418f24<UINT32>
0x00408070:	pushl %edi
0x00408071:	movl 0x4200c4, %eax
0x00408076:	call GetProcAddress@KERNEL32.DLL
0x00408078:	xorl %eax, 0x41e348
0x0040807e:	pushl $0x418f40<UINT32>
0x00408083:	pushl %edi
0x00408084:	movl 0x4200c8, %eax
0x00408089:	call GetProcAddress@KERNEL32.DLL
0x0040808b:	xorl %eax, 0x41e348
0x00408091:	pushl $0x418f54<UINT32>
0x00408096:	pushl %edi
0x00408097:	movl 0x4200cc, %eax
0x0040809c:	call GetProcAddress@KERNEL32.DLL
0x0040809e:	xorl %eax, 0x41e348
0x004080a4:	pushl $0x418f64<UINT32>
0x004080a9:	pushl %edi
0x004080aa:	movl 0x4200d0, %eax
0x004080af:	call GetProcAddress@KERNEL32.DLL
0x004080b1:	xorl %eax, 0x41e348
0x004080b7:	pushl $0x418f78<UINT32>
0x004080bc:	pushl %edi
0x004080bd:	movl 0x4200d4, %eax
0x004080c2:	call GetProcAddress@KERNEL32.DLL
0x004080c4:	xorl %eax, 0x41e348
0x004080ca:	movl 0x4200d8, %eax
0x004080cf:	pushl $0x418f88<UINT32>
0x004080d4:	pushl %edi
0x004080d5:	call GetProcAddress@KERNEL32.DLL
0x004080d7:	xorl %eax, 0x41e348
0x004080dd:	pushl $0x418fa8<UINT32>
0x004080e2:	pushl %edi
0x004080e3:	movl 0x4200dc, %eax
0x004080e8:	call GetProcAddress@KERNEL32.DLL
0x004080ea:	xorl %eax, 0x41e348
0x004080f0:	popl %edi
0x004080f1:	movl 0x4200e0, %eax
0x004080f6:	popl %esi
0x004080f7:	ret

0x00409186:	call 0x00404bd6
0x00404bd6:	pushl %esi
0x00404bd7:	pushl %edi
0x00404bd8:	movl %esi, $0x41e360<UINT32>
0x00404bdd:	movl %edi, $0x41f2f8<UINT32>
0x00404be2:	cmpl 0x4(%esi), $0x1<UINT8>
0x00404be6:	jne 22
0x00404be8:	pushl $0x0<UINT8>
0x00404bea:	movl (%esi), %edi
0x00404bec:	addl %edi, $0x18<UINT8>
0x00404bef:	pushl $0xfa0<UINT32>
0x00404bf4:	pushl (%esi)
0x00404bf6:	call 0x00407dfe
0x00407dfe:	pushl %ebp
0x00407dff:	movl %ebp, %esp
0x00407e01:	movl %eax, 0x420070
0x00407e06:	xorl %eax, 0x41e348
0x00407e0c:	je 13
0x00407e0e:	pushl 0x10(%ebp)
0x00407e11:	pushl 0xc(%ebp)
0x00407e14:	pushl 0x8(%ebp)
0x00407e17:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x00407e19:	popl %ebp
0x00407e1a:	ret

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
