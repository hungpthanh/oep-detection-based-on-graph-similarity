0x00427aa0:	pusha
0x00427aa1:	movl %esi, $0x41b000<UINT32>
0x00427aa6:	leal %edi, -106496(%esi)
0x00427aac:	pushl %edi
0x00427aad:	jmp 0x00427aba
0x00427aba:	movl %ebx, (%esi)
0x00427abc:	subl %esi, $0xfffffffc<UINT8>
0x00427abf:	adcl %ebx, %ebx
0x00427ac1:	jb 0x00427ab0
0x00427ab0:	movb %al, (%esi)
0x00427ab2:	incl %esi
0x00427ab3:	movb (%edi), %al
0x00427ab5:	incl %edi
0x00427ab6:	addl %ebx, %ebx
0x00427ab8:	jne 0x00427ac1
0x00427ac3:	movl %eax, $0x1<UINT32>
0x00427ac8:	addl %ebx, %ebx
0x00427aca:	jne 0x00427ad3
0x00427ad3:	adcl %eax, %eax
0x00427ad5:	addl %ebx, %ebx
0x00427ad7:	jae 0x00427ac8
0x00427ad9:	jne 0x00427ae4
0x00427ae4:	xorl %ecx, %ecx
0x00427ae6:	subl %eax, $0x3<UINT8>
0x00427ae9:	jb 0x00427af8
0x00427aeb:	shll %eax, $0x8<UINT8>
0x00427aee:	movb %al, (%esi)
0x00427af0:	incl %esi
0x00427af1:	xorl %eax, $0xffffffff<UINT8>
0x00427af4:	je 0x00427b6a
0x00427af6:	movl %ebp, %eax
0x00427af8:	addl %ebx, %ebx
0x00427afa:	jne 0x00427b03
0x00427b03:	adcl %ecx, %ecx
0x00427b05:	addl %ebx, %ebx
0x00427b07:	jne 0x00427b10
0x00427b10:	adcl %ecx, %ecx
0x00427b12:	jne 0x00427b34
0x00427b34:	cmpl %ebp, $0xfffff300<UINT32>
0x00427b3a:	adcl %ecx, $0x1<UINT8>
0x00427b3d:	leal %edx, (%edi,%ebp)
0x00427b40:	cmpl %ebp, $0xfffffffc<UINT8>
0x00427b43:	jbe 0x00427b54
0x00427b54:	movl %eax, (%edx)
0x00427b56:	addl %edx, $0x4<UINT8>
0x00427b59:	movl (%edi), %eax
0x00427b5b:	addl %edi, $0x4<UINT8>
0x00427b5e:	subl %ecx, $0x4<UINT8>
0x00427b61:	ja 0x00427b54
0x00427b63:	addl %edi, %ecx
0x00427b65:	jmp 0x00427ab6
0x00427b09:	movl %ebx, (%esi)
0x00427b0b:	subl %esi, $0xfffffffc<UINT8>
0x00427b0e:	adcl %ebx, %ebx
0x00427b45:	movb %al, (%edx)
0x00427b47:	incl %edx
0x00427b48:	movb (%edi), %al
0x00427b4a:	incl %edi
0x00427b4b:	decl %ecx
0x00427b4c:	jne 0x00427b45
0x00427b4e:	jmp 0x00427ab6
0x00427afc:	movl %ebx, (%esi)
0x00427afe:	subl %esi, $0xfffffffc<UINT8>
0x00427b01:	adcl %ebx, %ebx
0x00427b14:	incl %ecx
0x00427b15:	addl %ebx, %ebx
0x00427b17:	jne 0x00427b20
0x00427b20:	adcl %ecx, %ecx
0x00427b22:	addl %ebx, %ebx
0x00427b24:	jae 0x00427b15
0x00427b26:	jne 0x00427b31
0x00427b31:	addl %ecx, $0x2<UINT8>
0x00427adb:	movl %ebx, (%esi)
0x00427add:	subl %esi, $0xfffffffc<UINT8>
0x00427ae0:	adcl %ebx, %ebx
0x00427ae2:	jae 0x00427ac8
0x00427acc:	movl %ebx, (%esi)
0x00427ace:	subl %esi, $0xfffffffc<UINT8>
0x00427ad1:	adcl %ebx, %ebx
0x00427b19:	movl %ebx, (%esi)
0x00427b1b:	subl %esi, $0xfffffffc<UINT8>
0x00427b1e:	adcl %ebx, %ebx
0x00427b28:	movl %ebx, (%esi)
0x00427b2a:	subl %esi, $0xfffffffc<UINT8>
0x00427b2d:	adcl %ebx, %ebx
0x00427b2f:	jae 0x00427b15
0x00427b6a:	popl %esi
0x00427b6b:	movl %edi, %esi
0x00427b6d:	movl %ecx, $0x5df<UINT32>
0x00427b72:	movb %al, (%edi)
0x00427b74:	incl %edi
0x00427b75:	subb %al, $0xffffffe8<UINT8>
0x00427b77:	cmpb %al, $0x1<UINT8>
0x00427b79:	ja 0x00427b72
0x00427b7b:	cmpb (%edi), $0x5<UINT8>
0x00427b7e:	jne 0x00427b72
0x00427b80:	movl %eax, (%edi)
0x00427b82:	movb %bl, 0x4(%edi)
0x00427b85:	shrw %ax, $0x8<UINT8>
0x00427b89:	roll %eax, $0x10<UINT8>
0x00427b8c:	xchgb %ah, %al
0x00427b8e:	subl %eax, %edi
0x00427b90:	subb %bl, $0xffffffe8<UINT8>
0x00427b93:	addl %eax, %esi
0x00427b95:	movl (%edi), %eax
0x00427b97:	addl %edi, $0x5<UINT8>
0x00427b9a:	movb %al, %bl
0x00427b9c:	loop 0x00427b77
0x00427b9e:	leal %edi, 0x24000(%esi)
0x00427ba4:	movl %eax, (%edi)
0x00427ba6:	orl %eax, %eax
0x00427ba8:	je 0x00427be6
0x00427baa:	movl %ebx, 0x4(%edi)
0x00427bad:	leal %eax, 0x27548(%eax,%esi)
0x00427bb4:	addl %ebx, %esi
0x00427bb6:	pushl %eax
0x00427bb7:	addl %edi, $0x8<UINT8>
0x00427bba:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00427bc0:	xchgl %ebp, %eax
0x00427bc1:	movb %al, (%edi)
0x00427bc3:	incl %edi
0x00427bc4:	orb %al, %al
0x00427bc6:	je 0x00427ba4
0x00427bc8:	movl %ecx, %edi
0x00427bca:	pushl %edi
0x00427bcb:	decl %eax
0x00427bcc:	repn scasb %al, %es:(%edi)
0x00427bce:	pushl %ebp
0x00427bcf:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00427bd5:	orl %eax, %eax
0x00427bd7:	je 7
0x00427bd9:	movl (%ebx), %eax
0x00427bdb:	addl %ebx, $0x4<UINT8>
0x00427bde:	jmp 0x00427bc1
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x00427be6:	addl %edi, $0x4<UINT8>
0x00427be9:	leal %ebx, -4(%esi)
0x00427bec:	xorl %eax, %eax
0x00427bee:	movb %al, (%edi)
0x00427bf0:	incl %edi
0x00427bf1:	orl %eax, %eax
0x00427bf3:	je 0x00427c17
0x00427bf5:	cmpb %al, $0xffffffef<UINT8>
0x00427bf7:	ja 0x00427c0a
0x00427bf9:	addl %ebx, %eax
0x00427bfb:	movl %eax, (%ebx)
0x00427bfd:	xchgb %ah, %al
0x00427bff:	roll %eax, $0x10<UINT8>
0x00427c02:	xchgb %ah, %al
0x00427c04:	addl %eax, %esi
0x00427c06:	movl (%ebx), %eax
0x00427c08:	jmp 0x00427bec
0x00427c0a:	andb %al, $0xf<UINT8>
0x00427c0c:	shll %eax, $0x10<UINT8>
0x00427c0f:	movw %ax, (%edi)
0x00427c12:	addl %edi, $0x2<UINT8>
0x00427c15:	jmp 0x00427bf9
0x00427c17:	movl %ebp, 0x275f8(%esi)
0x00427c1d:	leal %edi, -4096(%esi)
0x00427c23:	movl %ebx, $0x1000<UINT32>
0x00427c28:	pushl %eax
0x00427c29:	pushl %esp
0x00427c2a:	pushl $0x4<UINT8>
0x00427c2c:	pushl %ebx
0x00427c2d:	pushl %edi
0x00427c2e:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00427c30:	leal %eax, 0x20f(%edi)
0x00427c36:	andb (%eax), $0x7f<UINT8>
0x00427c39:	andb 0x28(%eax), $0x7f<UINT8>
0x00427c3d:	popl %eax
0x00427c3e:	pushl %eax
0x00427c3f:	pushl %esp
0x00427c40:	pushl %eax
0x00427c41:	pushl %ebx
0x00427c42:	pushl %edi
0x00427c43:	call VirtualProtect@kernel32.dll
0x00427c45:	popl %eax
0x00427c46:	popa
0x00427c47:	leal %eax, -128(%esp)
0x00427c4b:	pushl $0x0<UINT8>
0x00427c4d:	cmpl %esp, %eax
0x00427c4f:	jne 0x00427c4b
0x00427c51:	subl %esp, $0xffffff80<UINT8>
0x00427c54:	jmp 0x0040480c
0x0040480c:	call 0x0040a3e2
0x0040a3e2:	pushl %ebp
0x0040a3e3:	movl %ebp, %esp
0x0040a3e5:	subl %esp, $0x14<UINT8>
0x0040a3e8:	andl -12(%ebp), $0x0<UINT8>
0x0040a3ec:	andl -8(%ebp), $0x0<UINT8>
0x0040a3f0:	movl %eax, 0x41e0d0
0x0040a3f5:	pushl %esi
0x0040a3f6:	pushl %edi
0x0040a3f7:	movl %edi, $0xbb40e64e<UINT32>
0x0040a3fc:	movl %esi, $0xffff0000<UINT32>
0x0040a401:	cmpl %eax, %edi
0x0040a403:	je 0x0040a412
0x0040a412:	leal %eax, -12(%ebp)
0x0040a415:	pushl %eax
0x0040a416:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040a41c:	movl %eax, -8(%ebp)
0x0040a41f:	xorl %eax, -12(%ebp)
0x0040a422:	movl -4(%ebp), %eax
0x0040a425:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040a42b:	xorl -4(%ebp), %eax
0x0040a42e:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040a434:	xorl -4(%ebp), %eax
0x0040a437:	leal %eax, -20(%ebp)
0x0040a43a:	pushl %eax
0x0040a43b:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040a441:	movl %ecx, -16(%ebp)
0x0040a444:	leal %eax, -4(%ebp)
0x0040a447:	xorl %ecx, -20(%ebp)
0x0040a44a:	xorl %ecx, -4(%ebp)
0x0040a44d:	xorl %ecx, %eax
0x0040a44f:	cmpl %ecx, %edi
0x0040a451:	jne 0x0040a45a
0x0040a45a:	testl %esi, %ecx
0x0040a45c:	jne 0x0040a46a
0x0040a46a:	movl 0x41e0d0, %ecx
0x0040a470:	notl %ecx
0x0040a472:	movl 0x41e0d4, %ecx
0x0040a478:	popl %edi
0x0040a479:	popl %esi
0x0040a47a:	movl %esp, %ebp
0x0040a47c:	popl %ebp
0x0040a47d:	ret

0x00404811:	jmp 0x00404691
0x00404691:	pushl $0x14<UINT8>
0x00404693:	pushl $0x41caa8<UINT32>
0x00404698:	call 0x00406650
0x00406650:	pushl $0x4066b0<UINT32>
0x00406655:	pushl %fs:0
0x0040665c:	movl %eax, 0x10(%esp)
0x00406660:	movl 0x10(%esp), %ebp
0x00406664:	leal %ebp, 0x10(%esp)
0x00406668:	subl %esp, %eax
0x0040666a:	pushl %ebx
0x0040666b:	pushl %esi
0x0040666c:	pushl %edi
0x0040666d:	movl %eax, 0x41e0d0
0x00406672:	xorl -4(%ebp), %eax
0x00406675:	xorl %eax, %ebp
0x00406677:	pushl %eax
0x00406678:	movl -24(%ebp), %esp
0x0040667b:	pushl -8(%ebp)
0x0040667e:	movl %eax, -4(%ebp)
0x00406681:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00406688:	movl -8(%ebp), %eax
0x0040668b:	leal %eax, -16(%ebp)
0x0040668e:	movl %fs:0, %eax
0x00406694:	ret

0x0040469d:	pushl $0x1<UINT8>
0x0040469f:	call 0x0040a395
0x0040a395:	pushl %ebp
0x0040a396:	movl %ebp, %esp
0x0040a398:	movl %eax, 0x8(%ebp)
0x0040a39b:	movl 0x41f780, %eax
0x0040a3a0:	popl %ebp
0x0040a3a1:	ret

0x004046a4:	popl %ecx
0x004046a5:	movl %eax, $0x5a4d<UINT32>
0x004046aa:	cmpw 0x400000, %ax
0x004046b1:	je 0x004046b7
0x004046b7:	movl %eax, 0x40003c
0x004046bc:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x004046c6:	jne -21
0x004046c8:	movl %ecx, $0x10b<UINT32>
0x004046cd:	cmpw 0x400018(%eax), %cx
0x004046d4:	jne -35
0x004046d6:	xorl %ebx, %ebx
0x004046d8:	cmpl 0x400074(%eax), $0xe<UINT8>
0x004046df:	jbe 9
0x004046e1:	cmpl 0x4000e8(%eax), %ebx
0x004046e7:	setne %bl
0x004046ea:	movl -28(%ebp), %ebx
0x004046ed:	call 0x0040691b
0x0040691b:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x00406921:	xorl %ecx, %ecx
0x00406923:	movl 0x41fde0, %eax
0x00406928:	testl %eax, %eax
0x0040692a:	setne %cl
0x0040692d:	movl %eax, %ecx
0x0040692f:	ret

0x004046f2:	testl %eax, %eax
0x004046f4:	jne 0x004046fe
0x004046fe:	call 0x00405718
0x00405718:	call 0x00402a38
0x00402a38:	pushl %esi
0x00402a39:	pushl $0x0<UINT8>
0x00402a3b:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00402a41:	movl %esi, %eax
0x00402a43:	pushl %esi
0x00402a44:	call 0x00406404
0x00406404:	pushl %ebp
0x00406405:	movl %ebp, %esp
0x00406407:	movl %eax, 0x8(%ebp)
0x0040640a:	movl 0x41fdb8, %eax
0x0040640f:	popl %ebp
0x00406410:	ret

0x00402a49:	pushl %esi
0x00402a4a:	call 0x0040493b
0x0040493b:	pushl %ebp
0x0040493c:	movl %ebp, %esp
0x0040493e:	movl %eax, 0x8(%ebp)
0x00404941:	movl 0x41f608, %eax
0x00404946:	popl %ebp
0x00404947:	ret

0x00402a4f:	pushl %esi
0x00402a50:	call 0x00406411
0x00406411:	pushl %ebp
0x00406412:	movl %ebp, %esp
0x00406414:	movl %eax, 0x8(%ebp)
0x00406417:	movl 0x41fdbc, %eax
0x0040641c:	popl %ebp
0x0040641d:	ret

0x00402a55:	pushl %esi
0x00402a56:	call 0x0040642b
0x0040642b:	pushl %ebp
0x0040642c:	movl %ebp, %esp
0x0040642e:	movl %eax, 0x8(%ebp)
0x00406431:	movl 0x41fdc0, %eax
0x00406436:	movl 0x41fdc4, %eax
0x0040643b:	movl 0x41fdc8, %eax
0x00406440:	movl 0x41fdcc, %eax
0x00406445:	popl %ebp
0x00406446:	ret

0x00402a5b:	pushl %esi
0x00402a5c:	call 0x004063cd
0x004063cd:	pushl $0x406399<UINT32>
0x004063d2:	call EncodePointer@KERNEL32.DLL
0x004063d8:	movl 0x41fdb4, %eax
0x004063dd:	ret

0x00402a61:	pushl %esi
0x00402a62:	call 0x0040663c
0x0040663c:	pushl %ebp
0x0040663d:	movl %ebp, %esp
0x0040663f:	movl %eax, 0x8(%ebp)
0x00406642:	movl 0x41fdd4, %eax
0x00406647:	popl %ebp
0x00406648:	ret

0x00402a67:	addl %esp, $0x18<UINT8>
0x00402a6a:	popl %esi
0x00402a6b:	jmp 0x00405b30
0x00405b30:	pushl %esi
0x00405b31:	pushl %edi
0x00405b32:	pushl $0x419100<UINT32>
0x00405b37:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00405b3d:	movl %esi, 0x41209c
0x00405b43:	movl %edi, %eax
0x00405b45:	pushl $0x41911c<UINT32>
0x00405b4a:	pushl %edi
0x00405b4b:	call GetProcAddress@KERNEL32.DLL
0x00405b4d:	xorl %eax, 0x41e0d0
0x00405b53:	pushl $0x419128<UINT32>
0x00405b58:	pushl %edi
0x00405b59:	movl 0x420040, %eax
0x00405b5e:	call GetProcAddress@KERNEL32.DLL
0x00405b60:	xorl %eax, 0x41e0d0
0x00405b66:	pushl $0x419130<UINT32>
0x00405b6b:	pushl %edi
0x00405b6c:	movl 0x420044, %eax
0x00405b71:	call GetProcAddress@KERNEL32.DLL
0x00405b73:	xorl %eax, 0x41e0d0
0x00405b79:	pushl $0x41913c<UINT32>
0x00405b7e:	pushl %edi
0x00405b7f:	movl 0x420048, %eax
0x00405b84:	call GetProcAddress@KERNEL32.DLL
0x00405b86:	xorl %eax, 0x41e0d0
0x00405b8c:	pushl $0x419148<UINT32>
0x00405b91:	pushl %edi
0x00405b92:	movl 0x42004c, %eax
0x00405b97:	call GetProcAddress@KERNEL32.DLL
0x00405b99:	xorl %eax, 0x41e0d0
0x00405b9f:	pushl $0x419164<UINT32>
0x00405ba4:	pushl %edi
0x00405ba5:	movl 0x420050, %eax
0x00405baa:	call GetProcAddress@KERNEL32.DLL
0x00405bac:	xorl %eax, 0x41e0d0
0x00405bb2:	pushl $0x419174<UINT32>
0x00405bb7:	pushl %edi
0x00405bb8:	movl 0x420054, %eax
0x00405bbd:	call GetProcAddress@KERNEL32.DLL
0x00405bbf:	xorl %eax, 0x41e0d0
0x00405bc5:	pushl $0x419188<UINT32>
0x00405bca:	pushl %edi
0x00405bcb:	movl 0x420058, %eax
0x00405bd0:	call GetProcAddress@KERNEL32.DLL
0x00405bd2:	xorl %eax, 0x41e0d0
0x00405bd8:	pushl $0x4191a0<UINT32>
0x00405bdd:	pushl %edi
0x00405bde:	movl 0x42005c, %eax
0x00405be3:	call GetProcAddress@KERNEL32.DLL
0x00405be5:	xorl %eax, 0x41e0d0
0x00405beb:	pushl $0x4191b8<UINT32>
0x00405bf0:	pushl %edi
0x00405bf1:	movl 0x420060, %eax
0x00405bf6:	call GetProcAddress@KERNEL32.DLL
0x00405bf8:	xorl %eax, 0x41e0d0
0x00405bfe:	pushl $0x4191cc<UINT32>
0x00405c03:	pushl %edi
0x00405c04:	movl 0x420064, %eax
0x00405c09:	call GetProcAddress@KERNEL32.DLL
0x00405c0b:	xorl %eax, 0x41e0d0
0x00405c11:	pushl $0x4191ec<UINT32>
0x00405c16:	pushl %edi
0x00405c17:	movl 0x420068, %eax
0x00405c1c:	call GetProcAddress@KERNEL32.DLL
0x00405c1e:	xorl %eax, 0x41e0d0
0x00405c24:	pushl $0x419204<UINT32>
0x00405c29:	pushl %edi
0x00405c2a:	movl 0x42006c, %eax
0x00405c2f:	call GetProcAddress@KERNEL32.DLL
0x00405c31:	xorl %eax, 0x41e0d0
0x00405c37:	pushl $0x41921c<UINT32>
0x00405c3c:	pushl %edi
0x00405c3d:	movl 0x420070, %eax
0x00405c42:	call GetProcAddress@KERNEL32.DLL
0x00405c44:	xorl %eax, 0x41e0d0
0x00405c4a:	pushl $0x419230<UINT32>
0x00405c4f:	pushl %edi
0x00405c50:	movl 0x420074, %eax
0x00405c55:	call GetProcAddress@KERNEL32.DLL
0x00405c57:	xorl %eax, 0x41e0d0
0x00405c5d:	movl 0x420078, %eax
0x00405c62:	pushl $0x419244<UINT32>
0x00405c67:	pushl %edi
0x00405c68:	call GetProcAddress@KERNEL32.DLL
0x00405c6a:	xorl %eax, 0x41e0d0
0x00405c70:	pushl $0x419260<UINT32>
0x00405c75:	pushl %edi
0x00405c76:	movl 0x42007c, %eax
0x00405c7b:	call GetProcAddress@KERNEL32.DLL
0x00405c7d:	xorl %eax, 0x41e0d0
0x00405c83:	pushl $0x419280<UINT32>
0x00405c88:	pushl %edi
0x00405c89:	movl 0x420080, %eax
0x00405c8e:	call GetProcAddress@KERNEL32.DLL
0x00405c90:	xorl %eax, 0x41e0d0
0x00405c96:	pushl $0x41929c<UINT32>
0x00405c9b:	pushl %edi
0x00405c9c:	movl 0x420084, %eax
0x00405ca1:	call GetProcAddress@KERNEL32.DLL
0x00405ca3:	xorl %eax, 0x41e0d0
0x00405ca9:	pushl $0x4192bc<UINT32>
0x00405cae:	pushl %edi
0x00405caf:	movl 0x420088, %eax
0x00405cb4:	call GetProcAddress@KERNEL32.DLL
0x00405cb6:	xorl %eax, 0x41e0d0
0x00405cbc:	pushl $0x4192d0<UINT32>
0x00405cc1:	pushl %edi
0x00405cc2:	movl 0x42008c, %eax
0x00405cc7:	call GetProcAddress@KERNEL32.DLL
0x00405cc9:	xorl %eax, 0x41e0d0
0x00405ccf:	pushl $0x4192ec<UINT32>
0x00405cd4:	pushl %edi
0x00405cd5:	movl 0x420090, %eax
0x00405cda:	call GetProcAddress@KERNEL32.DLL
0x00405cdc:	xorl %eax, 0x41e0d0
0x00405ce2:	pushl $0x419300<UINT32>
0x00405ce7:	pushl %edi
0x00405ce8:	movl 0x420098, %eax
0x00405ced:	call GetProcAddress@KERNEL32.DLL
0x00405cef:	xorl %eax, 0x41e0d0
0x00405cf5:	pushl $0x419310<UINT32>
0x00405cfa:	pushl %edi
0x00405cfb:	movl 0x420094, %eax
0x00405d00:	call GetProcAddress@KERNEL32.DLL
0x00405d02:	xorl %eax, 0x41e0d0
0x00405d08:	pushl $0x419320<UINT32>
0x00405d0d:	pushl %edi
0x00405d0e:	movl 0x42009c, %eax
0x00405d13:	call GetProcAddress@KERNEL32.DLL
0x00405d15:	xorl %eax, 0x41e0d0
0x00405d1b:	pushl $0x419330<UINT32>
0x00405d20:	pushl %edi
0x00405d21:	movl 0x4200a0, %eax
0x00405d26:	call GetProcAddress@KERNEL32.DLL
0x00405d28:	xorl %eax, 0x41e0d0
0x00405d2e:	pushl $0x419340<UINT32>
0x00405d33:	pushl %edi
0x00405d34:	movl 0x4200a4, %eax
0x00405d39:	call GetProcAddress@KERNEL32.DLL
0x00405d3b:	xorl %eax, 0x41e0d0
0x00405d41:	pushl $0x41935c<UINT32>
0x00405d46:	pushl %edi
0x00405d47:	movl 0x4200a8, %eax
0x00405d4c:	call GetProcAddress@KERNEL32.DLL
0x00405d4e:	xorl %eax, 0x41e0d0
0x00405d54:	pushl $0x419370<UINT32>
0x00405d59:	pushl %edi
0x00405d5a:	movl 0x4200ac, %eax
0x00405d5f:	call GetProcAddress@KERNEL32.DLL
0x00405d61:	xorl %eax, 0x41e0d0
0x00405d67:	pushl $0x419380<UINT32>
0x00405d6c:	pushl %edi
0x00405d6d:	movl 0x4200b0, %eax
0x00405d72:	call GetProcAddress@KERNEL32.DLL
0x00405d74:	xorl %eax, 0x41e0d0
0x00405d7a:	pushl $0x419394<UINT32>
0x00405d7f:	pushl %edi
0x00405d80:	movl 0x4200b4, %eax
0x00405d85:	call GetProcAddress@KERNEL32.DLL
0x00405d87:	xorl %eax, 0x41e0d0
0x00405d8d:	movl 0x4200b8, %eax
0x00405d92:	pushl $0x4193a4<UINT32>
0x00405d97:	pushl %edi
0x00405d98:	call GetProcAddress@KERNEL32.DLL
0x00405d9a:	xorl %eax, 0x41e0d0
0x00405da0:	pushl $0x4193c4<UINT32>
0x00405da5:	pushl %edi
0x00405da6:	movl 0x4200bc, %eax
0x00405dab:	call GetProcAddress@KERNEL32.DLL
0x00405dad:	xorl %eax, 0x41e0d0
0x00405db3:	popl %edi
0x00405db4:	movl 0x4200c0, %eax
0x00405db9:	popl %esi
0x00405dba:	ret

0x0040571d:	call 0x004059f6
0x004059f6:	pushl %esi
0x004059f7:	pushl %edi
0x004059f8:	movl %esi, $0x41ec20<UINT32>
0x004059fd:	movl %edi, $0x41f630<UINT32>
0x00405a02:	cmpl 0x4(%esi), $0x1<UINT8>
0x00405a06:	jne 22
0x00405a08:	pushl $0x0<UINT8>
0x00405a0a:	movl (%esi), %edi
0x00405a0c:	addl %edi, $0x18<UINT8>
0x00405a0f:	pushl $0xfa0<UINT32>
0x00405a14:	pushl (%esi)
0x00405a16:	call 0x00405ac2
0x00405ac2:	pushl %ebp
0x00405ac3:	movl %ebp, %esp
0x00405ac5:	movl %eax, 0x420050
0x00405aca:	xorl %eax, 0x41e0d0
0x00405ad0:	je 13
0x00405ad2:	pushl 0x10(%ebp)
0x00405ad5:	pushl 0xc(%ebp)
0x00405ad8:	pushl 0x8(%ebp)
0x00405adb:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x00405add:	popl %ebp
0x00405ade:	ret

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
