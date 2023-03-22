0x006c0a90:	pusha
0x006c0a91:	movl %esi, $0x60d000<UINT32>
0x006c0a96:	leal %edi, -2146304(%esi)
0x006c0a9c:	pushl %edi
0x006c0a9d:	jmp 0x006c0aaa
0x006c0aaa:	movl %ebx, (%esi)
0x006c0aac:	subl %esi, $0xfffffffc<UINT8>
0x006c0aaf:	adcl %ebx, %ebx
0x006c0ab1:	jb 0x006c0aa0
0x006c0aa0:	movb %al, (%esi)
0x006c0aa2:	incl %esi
0x006c0aa3:	movb (%edi), %al
0x006c0aa5:	incl %edi
0x006c0aa6:	addl %ebx, %ebx
0x006c0aa8:	jne 0x006c0ab1
0x006c0ab3:	movl %eax, $0x1<UINT32>
0x006c0ab8:	addl %ebx, %ebx
0x006c0aba:	jne 0x006c0ac3
0x006c0ac3:	adcl %eax, %eax
0x006c0ac5:	addl %ebx, %ebx
0x006c0ac7:	jae 0x006c0ad4
0x006c0ac9:	jne 0x006c0af3
0x006c0af3:	xorl %ecx, %ecx
0x006c0af5:	subl %eax, $0x3<UINT8>
0x006c0af8:	jb 0x006c0b0b
0x006c0afa:	shll %eax, $0x8<UINT8>
0x006c0afd:	movb %al, (%esi)
0x006c0aff:	incl %esi
0x006c0b00:	xorl %eax, $0xffffffff<UINT8>
0x006c0b03:	je 0x006c0b7a
0x006c0b05:	sarl %eax
0x006c0b07:	movl %ebp, %eax
0x006c0b09:	jmp 0x006c0b16
0x006c0b16:	jb 0x006c0ae4
0x006c0ae4:	addl %ebx, %ebx
0x006c0ae6:	jne 0x006c0aef
0x006c0aef:	adcl %ecx, %ecx
0x006c0af1:	jmp 0x006c0b45
0x006c0b45:	cmpl %ebp, $0xfffffb00<UINT32>
0x006c0b4b:	adcl %ecx, $0x2<UINT8>
0x006c0b4e:	leal %edx, (%edi,%ebp)
0x006c0b51:	cmpl %ebp, $0xfffffffc<UINT8>
0x006c0b54:	jbe 0x006c0b64
0x006c0b56:	movb %al, (%edx)
0x006c0b58:	incl %edx
0x006c0b59:	movb (%edi), %al
0x006c0b5b:	incl %edi
0x006c0b5c:	decl %ecx
0x006c0b5d:	jne 0x006c0b56
0x006c0b5f:	jmp 0x006c0aa6
0x006c0b64:	movl %eax, (%edx)
0x006c0b66:	addl %edx, $0x4<UINT8>
0x006c0b69:	movl (%edi), %eax
0x006c0b6b:	addl %edi, $0x4<UINT8>
0x006c0b6e:	subl %ecx, $0x4<UINT8>
0x006c0b71:	ja 0x006c0b64
0x006c0b73:	addl %edi, %ecx
0x006c0b75:	jmp 0x006c0aa6
0x006c0b18:	incl %ecx
0x006c0b19:	addl %ebx, %ebx
0x006c0b1b:	jne 0x006c0b24
0x006c0b24:	jb 0x006c0ae4
0x006c0b26:	addl %ebx, %ebx
0x006c0b28:	jne 0x006c0b31
0x006c0b31:	adcl %ecx, %ecx
0x006c0b33:	addl %ebx, %ebx
0x006c0b35:	jae 0x006c0b26
0x006c0b37:	jne 0x006c0b42
0x006c0b42:	addl %ecx, $0x2<UINT8>
0x006c0b0b:	addl %ebx, %ebx
0x006c0b0d:	jne 0x006c0b16
0x006c0acb:	movl %ebx, (%esi)
0x006c0acd:	subl %esi, $0xfffffffc<UINT8>
0x006c0ad0:	adcl %ebx, %ebx
0x006c0ad2:	jb 0x006c0af3
0x006c0b1d:	movl %ebx, (%esi)
0x006c0b1f:	subl %esi, $0xfffffffc<UINT8>
0x006c0b22:	adcl %ebx, %ebx
0x006c0b2a:	movl %ebx, (%esi)
0x006c0b2c:	subl %esi, $0xfffffffc<UINT8>
0x006c0b2f:	adcl %ebx, %ebx
0x006c0ae8:	movl %ebx, (%esi)
0x006c0aea:	subl %esi, $0xfffffffc<UINT8>
0x006c0aed:	adcl %ebx, %ebx
0x006c0b0f:	movl %ebx, (%esi)
0x006c0b11:	subl %esi, $0xfffffffc<UINT8>
0x006c0b14:	adcl %ebx, %ebx
0x006c0ad4:	decl %eax
0x006c0ad5:	addl %ebx, %ebx
0x006c0ad7:	jne 0x006c0ae0
0x006c0ae0:	adcl %eax, %eax
0x006c0ae2:	jmp 0x006c0ab8
0x006c0abc:	movl %ebx, (%esi)
0x006c0abe:	subl %esi, $0xfffffffc<UINT8>
0x006c0ac1:	adcl %ebx, %ebx
0x006c0ad9:	movl %ebx, (%esi)
0x006c0adb:	subl %esi, $0xfffffffc<UINT8>
0x006c0ade:	adcl %ebx, %ebx
0x006c0b39:	movl %ebx, (%esi)
0x006c0b3b:	subl %esi, $0xfffffffc<UINT8>
0x006c0b3e:	adcl %ebx, %ebx
0x006c0b40:	jae 0x006c0b26
0x006c0b7a:	popl %esi
0x006c0b7b:	movl %edi, %esi
0x006c0b7d:	movl %ecx, $0x376b<UINT32>
0x006c0b82:	movb %al, (%edi)
0x006c0b84:	incl %edi
0x006c0b85:	subb %al, $0xffffffe8<UINT8>
0x006c0b87:	cmpb %al, $0x1<UINT8>
0x006c0b89:	ja 0x006c0b82
0x006c0b8b:	cmpb (%edi), $0x16<UINT8>
0x006c0b8e:	jne 0x006c0b82
0x006c0b90:	movl %eax, (%edi)
0x006c0b92:	movb %bl, 0x4(%edi)
0x006c0b95:	shrw %ax, $0x8<UINT8>
0x006c0b99:	roll %eax, $0x10<UINT8>
0x006c0b9c:	xchgb %ah, %al
0x006c0b9e:	subl %eax, %edi
0x006c0ba0:	subb %bl, $0xffffffe8<UINT8>
0x006c0ba3:	addl %eax, %esi
0x006c0ba5:	movl (%edi), %eax
0x006c0ba7:	addl %edi, $0x5<UINT8>
0x006c0baa:	movb %al, %bl
0x006c0bac:	loop 0x006c0b87
0x006c0bae:	leal %edi, 0x2ba000(%esi)
0x006c0bb4:	movl %eax, (%edi)
0x006c0bb6:	orl %eax, %eax
0x006c0bb8:	je 0x006c0bff
0x006c0bba:	movl %ebx, 0x4(%edi)
0x006c0bbd:	leal %eax, 0x2c073c(%eax,%esi)
0x006c0bc4:	addl %ebx, %esi
0x006c0bc6:	pushl %eax
0x006c0bc7:	addl %edi, $0x8<UINT8>
0x006c0bca:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x006c0bd0:	xchgl %ebp, %eax
0x006c0bd1:	movb %al, (%edi)
0x006c0bd3:	incl %edi
0x006c0bd4:	orb %al, %al
0x006c0bd6:	je 0x006c0bb4
0x006c0bd8:	movl %ecx, %edi
0x006c0bda:	jns 0x006c0be3
0x006c0be3:	pushl %edi
0x006c0be4:	decl %eax
0x006c0be5:	repn scasb %al, %es:(%edi)
0x006c0be7:	pushl %ebp
0x006c0be8:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x006c0bee:	orl %eax, %eax
0x006c0bf0:	je 7
0x006c0bf2:	movl (%ebx), %eax
0x006c0bf4:	addl %ebx, $0x4<UINT8>
0x006c0bf7:	jmp 0x006c0bd1
GetProcAddress@KERNEL32.DLL: API Node	
0x006c0bdc:	movzwl %eax, (%edi)
0x006c0bdf:	incl %edi
0x006c0be0:	pushl %eax
0x006c0be1:	incl %edi
0x006c0be2:	movl %ecx, $0xaef24857<UINT32>
0x006c0bff:	addl %edi, $0x4<UINT8>
0x006c0c02:	leal %ebx, -4(%esi)
0x006c0c05:	xorl %eax, %eax
0x006c0c07:	movb %al, (%edi)
0x006c0c09:	incl %edi
0x006c0c0a:	orl %eax, %eax
0x006c0c0c:	je 0x006c0c30
0x006c0c0e:	cmpb %al, $0xffffffef<UINT8>
0x006c0c10:	ja 0x006c0c23
0x006c0c12:	addl %ebx, %eax
0x006c0c14:	movl %eax, (%ebx)
0x006c0c16:	xchgb %ah, %al
0x006c0c18:	roll %eax, $0x10<UINT8>
0x006c0c1b:	xchgb %ah, %al
0x006c0c1d:	addl %eax, %esi
0x006c0c1f:	movl (%ebx), %eax
0x006c0c21:	jmp 0x006c0c05
0x006c0c23:	andb %al, $0xf<UINT8>
0x006c0c25:	shll %eax, $0x10<UINT8>
0x006c0c28:	movw %ax, (%edi)
0x006c0c2b:	addl %edi, $0x2<UINT8>
0x006c0c2e:	jmp 0x006c0c12
0x006c0c30:	movl %ebp, 0x2c08a8(%esi)
0x006c0c36:	leal %edi, -4096(%esi)
0x006c0c3c:	movl %ebx, $0x1000<UINT32>
0x006c0c41:	pushl %eax
0x006c0c42:	pushl %esp
0x006c0c43:	pushl $0x4<UINT8>
0x006c0c45:	pushl %ebx
0x006c0c46:	pushl %edi
0x006c0c47:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x006c0c49:	leal %eax, 0x21f(%edi)
0x006c0c4f:	andb (%eax), $0x7f<UINT8>
0x006c0c52:	andb 0x28(%eax), $0x7f<UINT8>
0x006c0c56:	popl %eax
0x006c0c57:	pushl %eax
0x006c0c58:	pushl %esp
0x006c0c59:	pushl %eax
0x006c0c5a:	pushl %ebx
0x006c0c5b:	pushl %edi
0x006c0c5c:	call VirtualProtect@kernel32.dll
0x006c0c5e:	popl %eax
0x006c0c5f:	popa
0x006c0c60:	leal %eax, -128(%esp)
0x006c0c64:	pushl $0x0<UINT8>
0x006c0c66:	cmpl %esp, %eax
0x006c0c68:	jne 0x006c0c64
0x006c0c6a:	subl %esp, $0xffffff80<UINT8>
0x006c0c6d:	jmp 0x00443cc8
0x00443cc8:	call 0x004507c1
0x004507c1:	pushl %ebp
0x004507c2:	movl %ebp, %esp
0x004507c4:	subl %esp, $0x14<UINT8>
0x004507c7:	andl -12(%ebp), $0x0<UINT8>
0x004507cb:	andl -8(%ebp), $0x0<UINT8>
0x004507cf:	movl %eax, 0x4c5400
0x004507d4:	pushl %esi
0x004507d5:	pushl %edi
0x004507d6:	movl %edi, $0xbb40e64e<UINT32>
0x004507db:	movl %esi, $0xffff0000<UINT32>
0x004507e0:	cmpl %eax, %edi
0x004507e2:	je 0x004507f1
0x004507f1:	leal %eax, -12(%ebp)
0x004507f4:	pushl %eax
0x004507f5:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x004507fb:	movl %eax, -8(%ebp)
0x004507fe:	xorl %eax, -12(%ebp)
0x00450801:	movl -4(%ebp), %eax
0x00450804:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0045080a:	xorl -4(%ebp), %eax
0x0045080d:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x00450813:	xorl -4(%ebp), %eax
0x00450816:	leal %eax, -20(%ebp)
0x00450819:	pushl %eax
0x0045081a:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x00450820:	movl %ecx, -16(%ebp)
0x00450823:	leal %eax, -4(%ebp)
0x00450826:	xorl %ecx, -20(%ebp)
0x00450829:	xorl %ecx, -4(%ebp)
0x0045082c:	xorl %ecx, %eax
0x0045082e:	cmpl %ecx, %edi
0x00450830:	jne 0x00450839
0x00450839:	testl %esi, %ecx
0x0045083b:	jne 0x00450849
0x00450849:	movl 0x4c5400, %ecx
0x0045084f:	notl %ecx
0x00450851:	movl 0x4c5404, %ecx
0x00450857:	popl %edi
0x00450858:	popl %esi
0x00450859:	movl %esp, %ebp
0x0045085b:	popl %ebp
0x0045085c:	ret

0x00443ccd:	jmp 0x00443b07
0x00443b07:	pushl $0x14<UINT8>
0x00443b09:	pushl $0x4bfbe8<UINT32>
0x00443b0e:	call 0x00446dd0
0x00446dd0:	pushl $0x446e70<UINT32>
0x00446dd5:	pushl %fs:0
0x00446ddc:	movl %eax, 0x10(%esp)
0x00446de0:	movl 0x10(%esp), %ebp
0x00446de4:	leal %ebp, 0x10(%esp)
0x00446de8:	subl %esp, %eax
0x00446dea:	pushl %ebx
0x00446deb:	pushl %esi
0x00446dec:	pushl %edi
0x00446ded:	movl %eax, 0x4c5400
0x00446df2:	xorl -4(%ebp), %eax
0x00446df5:	xorl %eax, %ebp
0x00446df7:	pushl %eax
0x00446df8:	movl -24(%ebp), %esp
0x00446dfb:	pushl -8(%ebp)
0x00446dfe:	movl %eax, -4(%ebp)
0x00446e01:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00446e08:	movl -8(%ebp), %eax
0x00446e0b:	leal %eax, -16(%ebp)
0x00446e0e:	movl %fs:0, %eax
0x00446e14:	ret

0x00443b13:	pushl $0x1<UINT8>
0x00443b15:	call 0x00450774
0x00450774:	pushl %ebp
0x00450775:	movl %ebp, %esp
0x00450777:	movl %eax, 0x8(%ebp)
0x0045077a:	movl 0x4ca248, %eax
0x0045077f:	popl %ebp
0x00450780:	ret

0x00443b1a:	popl %ecx
0x00443b1b:	movl %eax, $0x5a4d<UINT32>
0x00443b20:	cmpw 0x400000, %ax
0x00443b27:	je 0x00443b2d
0x00443b2d:	movl %eax, 0x40003c
0x00443b32:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00443b3c:	jne -21
0x00443b3e:	movl %ecx, $0x10b<UINT32>
0x00443b43:	cmpw 0x400018(%eax), %cx
0x00443b4a:	jne -35
0x00443b4c:	xorl %ebx, %ebx
0x00443b4e:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00443b55:	jbe 9
0x00443b57:	cmpl 0x4000e8(%eax), %ebx
0x00443b5d:	setne %bl
0x00443b60:	movl -28(%ebp), %ebx
0x00443b63:	call 0x004472a2
0x004472a2:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x004472a8:	xorl %ecx, %ecx
0x004472aa:	movl 0x4ca87c, %eax
0x004472af:	testl %eax, %eax
0x004472b1:	setne %cl
0x004472b4:	movl %eax, %ecx
0x004472b6:	ret

0x00443b68:	testl %eax, %eax
0x00443b6a:	jne 0x00443b74
0x00443b74:	call 0x00444c06
0x00444c06:	call 0x0043fbdb
0x0043fbdb:	pushl %esi
0x0043fbdc:	pushl $0x0<UINT8>
0x0043fbde:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x0043fbe4:	movl %esi, %eax
0x0043fbe6:	pushl %esi
0x0043fbe7:	call 0x00447075
0x00447075:	pushl %ebp
0x00447076:	movl %ebp, %esp
0x00447078:	movl %eax, 0x8(%ebp)
0x0044707b:	movl 0x4ca244, %eax
0x00447080:	popl %ebp
0x00447081:	ret

0x0043fbec:	pushl %esi
0x0043fbed:	call 0x00443e21
0x00443e21:	pushl %ebp
0x00443e22:	movl %ebp, %esp
0x00443e24:	movl %eax, 0x8(%ebp)
0x00443e27:	movl 0x4ca218, %eax
0x00443e2c:	popl %ebp
0x00443e2d:	ret

0x0043fbf2:	pushl %esi
0x0043fbf3:	call 0x0044a539
0x0044a539:	pushl %ebp
0x0044a53a:	movl %ebp, %esp
0x0044a53c:	movl %eax, 0x8(%ebp)
0x0044a53f:	movl 0x4caae0, %eax
0x0044a544:	popl %ebp
0x0044a545:	ret

0x0043fbf8:	pushl %esi
0x0043fbf9:	call 0x0044a565
0x0044a565:	pushl %ebp
0x0044a566:	movl %ebp, %esp
0x0044a568:	movl %eax, 0x8(%ebp)
0x0044a56b:	movl 0x4caae4, %eax
0x0044a570:	movl 0x4caae8, %eax
0x0044a575:	movl 0x4caaec, %eax
0x0044a57a:	movl 0x4caaf0, %eax
0x0044a57f:	popl %ebp
0x0044a580:	ret

0x0043fbfe:	pushl %esi
0x0043fbff:	call 0x0044a34f
0x0044a34f:	pushl $0x44a308<UINT32>
0x0044a354:	call EncodePointer@KERNEL32.DLL
0x0044a35a:	movl 0x4caadc, %eax
0x0044a35f:	ret

0x0043fc04:	pushl %esi
0x0043fc05:	call 0x004411e6
0x004411e6:	pushl %ebp
0x004411e7:	movl %ebp, %esp
0x004411e9:	movl %eax, 0x8(%ebp)
0x004411ec:	movl 0x4c9eec, %eax
0x004411f1:	popl %ebp
0x004411f2:	ret

0x0043fc0a:	addl %esp, $0x18<UINT8>
0x0043fc0d:	popl %esi
0x0043fc0e:	jmp 0x00448adc
0x00448adc:	pushl %esi
0x00448add:	pushl %edi
0x00448ade:	pushl $0x4a09bc<UINT32>
0x00448ae3:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00448ae9:	movl %esi, 0x49127c
0x00448aef:	movl %edi, %eax
0x00448af1:	pushl $0x492934<UINT32>
0x00448af6:	pushl %edi
0x00448af7:	call GetProcAddress@KERNEL32.DLL
0x00448af9:	xorl %eax, 0x4c5400
0x00448aff:	pushl $0x492940<UINT32>
0x00448b04:	pushl %edi
0x00448b05:	movl 0x4cb6c0, %eax
0x00448b0a:	call GetProcAddress@KERNEL32.DLL
0x00448b0c:	xorl %eax, 0x4c5400
0x00448b12:	pushl $0x492948<UINT32>
0x00448b17:	pushl %edi
0x00448b18:	movl 0x4cb6c4, %eax
0x00448b1d:	call GetProcAddress@KERNEL32.DLL
0x00448b1f:	xorl %eax, 0x4c5400
0x00448b25:	pushl $0x492954<UINT32>
0x00448b2a:	pushl %edi
0x00448b2b:	movl 0x4cb6c8, %eax
0x00448b30:	call GetProcAddress@KERNEL32.DLL
0x00448b32:	xorl %eax, 0x4c5400
0x00448b38:	pushl $0x492960<UINT32>
0x00448b3d:	pushl %edi
0x00448b3e:	movl 0x4cb6cc, %eax
0x00448b43:	call GetProcAddress@KERNEL32.DLL
0x00448b45:	xorl %eax, 0x4c5400
0x00448b4b:	pushl $0x49297c<UINT32>
0x00448b50:	pushl %edi
0x00448b51:	movl 0x4cb6d0, %eax
0x00448b56:	call GetProcAddress@KERNEL32.DLL
0x00448b58:	xorl %eax, 0x4c5400
0x00448b5e:	pushl $0x49298c<UINT32>
0x00448b63:	pushl %edi
0x00448b64:	movl 0x4cb6d4, %eax
0x00448b69:	call GetProcAddress@KERNEL32.DLL
0x00448b6b:	xorl %eax, 0x4c5400
0x00448b71:	pushl $0x4929a0<UINT32>
0x00448b76:	pushl %edi
0x00448b77:	movl 0x4cb6d8, %eax
0x00448b7c:	call GetProcAddress@KERNEL32.DLL
0x00448b7e:	xorl %eax, 0x4c5400
0x00448b84:	pushl $0x4929b8<UINT32>
0x00448b89:	pushl %edi
0x00448b8a:	movl 0x4cb6dc, %eax
0x00448b8f:	call GetProcAddress@KERNEL32.DLL
0x00448b91:	xorl %eax, 0x4c5400
0x00448b97:	pushl $0x4929d0<UINT32>
0x00448b9c:	pushl %edi
0x00448b9d:	movl 0x4cb6e0, %eax
0x00448ba2:	call GetProcAddress@KERNEL32.DLL
0x00448ba4:	xorl %eax, 0x4c5400
0x00448baa:	pushl $0x4929e4<UINT32>
0x00448baf:	pushl %edi
0x00448bb0:	movl 0x4cb6e4, %eax
0x00448bb5:	call GetProcAddress@KERNEL32.DLL
0x00448bb7:	xorl %eax, 0x4c5400
0x00448bbd:	pushl $0x492a04<UINT32>
0x00448bc2:	pushl %edi
0x00448bc3:	movl 0x4cb6e8, %eax
0x00448bc8:	call GetProcAddress@KERNEL32.DLL
0x00448bca:	xorl %eax, 0x4c5400
0x00448bd0:	pushl $0x492a1c<UINT32>
0x00448bd5:	pushl %edi
0x00448bd6:	movl 0x4cb6ec, %eax
0x00448bdb:	call GetProcAddress@KERNEL32.DLL
0x00448bdd:	xorl %eax, 0x4c5400
0x00448be3:	pushl $0x492a34<UINT32>
0x00448be8:	pushl %edi
0x00448be9:	movl 0x4cb6f0, %eax
0x00448bee:	call GetProcAddress@KERNEL32.DLL
0x00448bf0:	xorl %eax, 0x4c5400
0x00448bf6:	pushl $0x492a48<UINT32>
0x00448bfb:	pushl %edi
0x00448bfc:	movl 0x4cb6f4, %eax
0x00448c01:	call GetProcAddress@KERNEL32.DLL
0x00448c03:	xorl %eax, 0x4c5400
0x00448c09:	movl 0x4cb6f8, %eax
0x00448c0e:	pushl $0x492a5c<UINT32>
0x00448c13:	pushl %edi
0x00448c14:	call GetProcAddress@KERNEL32.DLL
0x00448c16:	xorl %eax, 0x4c5400
0x00448c1c:	pushl $0x492a78<UINT32>
0x00448c21:	pushl %edi
0x00448c22:	movl 0x4cb6fc, %eax
0x00448c27:	call GetProcAddress@KERNEL32.DLL
0x00448c29:	xorl %eax, 0x4c5400
0x00448c2f:	pushl $0x492a98<UINT32>
0x00448c34:	pushl %edi
0x00448c35:	movl 0x4cb700, %eax
0x00448c3a:	call GetProcAddress@KERNEL32.DLL
0x00448c3c:	xorl %eax, 0x4c5400
0x00448c42:	pushl $0x492ab4<UINT32>
0x00448c47:	pushl %edi
0x00448c48:	movl 0x4cb704, %eax
0x00448c4d:	call GetProcAddress@KERNEL32.DLL
0x00448c4f:	xorl %eax, 0x4c5400
0x00448c55:	pushl $0x492ad4<UINT32>
0x00448c5a:	pushl %edi
0x00448c5b:	movl 0x4cb708, %eax
0x00448c60:	call GetProcAddress@KERNEL32.DLL
0x00448c62:	xorl %eax, 0x4c5400
0x00448c68:	pushl $0x492ae8<UINT32>
0x00448c6d:	pushl %edi
0x00448c6e:	movl 0x4cb70c, %eax
0x00448c73:	call GetProcAddress@KERNEL32.DLL
0x00448c75:	xorl %eax, 0x4c5400
0x00448c7b:	pushl $0x492b04<UINT32>
0x00448c80:	pushl %edi
0x00448c81:	movl 0x4cb710, %eax
0x00448c86:	call GetProcAddress@KERNEL32.DLL
0x00448c88:	xorl %eax, 0x4c5400
0x00448c8e:	pushl $0x492b18<UINT32>
0x00448c93:	pushl %edi
0x00448c94:	movl 0x4cb718, %eax
0x00448c99:	call GetProcAddress@KERNEL32.DLL
0x00448c9b:	xorl %eax, 0x4c5400
0x00448ca1:	pushl $0x492b28<UINT32>
0x00448ca6:	pushl %edi
0x00448ca7:	movl 0x4cb714, %eax
0x00448cac:	call GetProcAddress@KERNEL32.DLL
0x00448cae:	xorl %eax, 0x4c5400
0x00448cb4:	pushl $0x492b38<UINT32>
0x00448cb9:	pushl %edi
0x00448cba:	movl 0x4cb71c, %eax
0x00448cbf:	call GetProcAddress@KERNEL32.DLL
0x00448cc1:	xorl %eax, 0x4c5400
0x00448cc7:	pushl $0x492b48<UINT32>
0x00448ccc:	pushl %edi
0x00448ccd:	movl 0x4cb720, %eax
0x00448cd2:	call GetProcAddress@KERNEL32.DLL
0x00448cd4:	xorl %eax, 0x4c5400
0x00448cda:	pushl $0x492b58<UINT32>
0x00448cdf:	pushl %edi
0x00448ce0:	movl 0x4cb724, %eax
0x00448ce5:	call GetProcAddress@KERNEL32.DLL
0x00448ce7:	xorl %eax, 0x4c5400
0x00448ced:	pushl $0x492b74<UINT32>
0x00448cf2:	pushl %edi
0x00448cf3:	movl 0x4cb728, %eax
0x00448cf8:	call GetProcAddress@KERNEL32.DLL
0x00448cfa:	xorl %eax, 0x4c5400
0x00448d00:	pushl $0x492b88<UINT32>
0x00448d05:	pushl %edi
0x00448d06:	movl 0x4cb72c, %eax
0x00448d0b:	call GetProcAddress@KERNEL32.DLL
0x00448d0d:	xorl %eax, 0x4c5400
0x00448d13:	pushl $0x492b98<UINT32>
0x00448d18:	pushl %edi
0x00448d19:	movl 0x4cb730, %eax
0x00448d1e:	call GetProcAddress@KERNEL32.DLL
0x00448d20:	xorl %eax, 0x4c5400
0x00448d26:	pushl $0x492bac<UINT32>
0x00448d2b:	pushl %edi
0x00448d2c:	movl 0x4cb734, %eax
0x00448d31:	call GetProcAddress@KERNEL32.DLL
0x00448d33:	xorl %eax, 0x4c5400
0x00448d39:	movl 0x4cb738, %eax
0x00448d3e:	pushl $0x492bbc<UINT32>
0x00448d43:	pushl %edi
0x00448d44:	call GetProcAddress@KERNEL32.DLL
0x00448d46:	xorl %eax, 0x4c5400
0x00448d4c:	pushl $0x492bdc<UINT32>
0x00448d51:	pushl %edi
0x00448d52:	movl 0x4cb73c, %eax
0x00448d57:	call GetProcAddress@KERNEL32.DLL
0x00448d59:	xorl %eax, 0x4c5400
0x00448d5f:	popl %edi
0x00448d60:	movl 0x4cb740, %eax
0x00448d65:	popl %esi
0x00448d66:	ret

0x00444c0b:	call 0x004474ad
0x004474ad:	pushl %esi
0x004474ae:	pushl %edi
0x004474af:	movl %esi, $0x4c5b70<UINT32>
0x004474b4:	movl %edi, $0x4ca880<UINT32>
0x004474b9:	cmpl 0x4(%esi), $0x1<UINT8>
0x004474bd:	jne 22
0x004474bf:	pushl $0x0<UINT8>
0x004474c1:	movl (%esi), %edi
0x004474c3:	addl %edi, $0x18<UINT8>
0x004474c6:	pushl $0xfa0<UINT32>
0x004474cb:	pushl (%esi)
0x004474cd:	call 0x00448a6e
0x00448a6e:	pushl %ebp
0x00448a6f:	movl %ebp, %esp
0x00448a71:	movl %eax, 0x4cb6d0
0x00448a76:	xorl %eax, 0x4c5400
0x00448a7c:	je 13
0x00448a7e:	pushl 0x10(%ebp)
0x00448a81:	pushl 0xc(%ebp)
0x00448a84:	pushl 0x8(%ebp)
0x00448a87:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x00448a89:	popl %ebp
0x00448a8a:	ret

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
