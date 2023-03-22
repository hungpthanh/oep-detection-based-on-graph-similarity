0x004fcad0:	pusha
0x004fcad1:	movl %esi, $0x4ad000<UINT32>
0x004fcad6:	leal %edi, -704512(%esi)
0x004fcadc:	movl 0xe1984(%edi), $0x31c20b00<UINT32>
0x004fcae6:	pushl %edi
0x004fcae7:	orl %ebp, $0xffffffff<UINT8>
0x004fcaea:	jmp 0x004fcafa
0x004fcafa:	movl %ebx, (%esi)
0x004fcafc:	subl %esi, $0xfffffffc<UINT8>
0x004fcaff:	adcl %ebx, %ebx
0x004fcb01:	jb 0x004fcaf0
0x004fcaf0:	movb %al, (%esi)
0x004fcaf2:	incl %esi
0x004fcaf3:	movb (%edi), %al
0x004fcaf5:	incl %edi
0x004fcaf6:	addl %ebx, %ebx
0x004fcaf8:	jne 0x004fcb01
0x004fcb03:	movl %eax, $0x1<UINT32>
0x004fcb08:	addl %ebx, %ebx
0x004fcb0a:	jne 0x004fcb13
0x004fcb13:	adcl %eax, %eax
0x004fcb15:	addl %ebx, %ebx
0x004fcb17:	jae 0x004fcb24
0x004fcb19:	jne 0x004fcb43
0x004fcb43:	xorl %ecx, %ecx
0x004fcb45:	subl %eax, $0x3<UINT8>
0x004fcb48:	jb 0x004fcb5b
0x004fcb5b:	addl %ebx, %ebx
0x004fcb5d:	jne 0x004fcb66
0x004fcb66:	jb 0x004fcb34
0x004fcb68:	incl %ecx
0x004fcb69:	addl %ebx, %ebx
0x004fcb6b:	jne 0x004fcb74
0x004fcb74:	jb 0x004fcb34
0x004fcb34:	addl %ebx, %ebx
0x004fcb36:	jne 0x004fcb3f
0x004fcb3f:	adcl %ecx, %ecx
0x004fcb41:	jmp 0x004fcb95
0x004fcb95:	cmpl %ebp, $0xfffffb00<UINT32>
0x004fcb9b:	adcl %ecx, $0x2<UINT8>
0x004fcb9e:	leal %edx, (%edi,%ebp)
0x004fcba1:	cmpl %ebp, $0xfffffffc<UINT8>
0x004fcba4:	jbe 0x004fcbb4
0x004fcba6:	movb %al, (%edx)
0x004fcba8:	incl %edx
0x004fcba9:	movb (%edi), %al
0x004fcbab:	incl %edi
0x004fcbac:	decl %ecx
0x004fcbad:	jne 0x004fcba6
0x004fcbaf:	jmp 0x004fcaf6
0x004fcb4a:	shll %eax, $0x8<UINT8>
0x004fcb4d:	movb %al, (%esi)
0x004fcb4f:	incl %esi
0x004fcb50:	xorl %eax, $0xffffffff<UINT8>
0x004fcb53:	je 0x004fcbca
0x004fcb55:	sarl %eax
0x004fcb57:	movl %ebp, %eax
0x004fcb59:	jmp 0x004fcb66
0x004fcbb4:	movl %eax, (%edx)
0x004fcbb6:	addl %edx, $0x4<UINT8>
0x004fcbb9:	movl (%edi), %eax
0x004fcbbb:	addl %edi, $0x4<UINT8>
0x004fcbbe:	subl %ecx, $0x4<UINT8>
0x004fcbc1:	ja 0x004fcbb4
0x004fcbc3:	addl %edi, %ecx
0x004fcbc5:	jmp 0x004fcaf6
0x004fcb1b:	movl %ebx, (%esi)
0x004fcb1d:	subl %esi, $0xfffffffc<UINT8>
0x004fcb20:	adcl %ebx, %ebx
0x004fcb22:	jb 0x004fcb43
0x004fcb76:	addl %ebx, %ebx
0x004fcb78:	jne 0x004fcb81
0x004fcb81:	adcl %ecx, %ecx
0x004fcb83:	addl %ebx, %ebx
0x004fcb85:	jae 0x004fcb76
0x004fcb87:	jne 0x004fcb92
0x004fcb89:	movl %ebx, (%esi)
0x004fcb8b:	subl %esi, $0xfffffffc<UINT8>
0x004fcb8e:	adcl %ebx, %ebx
0x004fcb90:	jae 0x004fcb76
0x004fcb92:	addl %ecx, $0x2<UINT8>
0x004fcb7a:	movl %ebx, (%esi)
0x004fcb7c:	subl %esi, $0xfffffffc<UINT8>
0x004fcb7f:	adcl %ebx, %ebx
0x004fcb24:	decl %eax
0x004fcb25:	addl %ebx, %ebx
0x004fcb27:	jne 0x004fcb30
0x004fcb30:	adcl %eax, %eax
0x004fcb32:	jmp 0x004fcb08
0x004fcb0c:	movl %ebx, (%esi)
0x004fcb0e:	subl %esi, $0xfffffffc<UINT8>
0x004fcb11:	adcl %ebx, %ebx
0x004fcb38:	movl %ebx, (%esi)
0x004fcb3a:	subl %esi, $0xfffffffc<UINT8>
0x004fcb3d:	adcl %ebx, %ebx
0x004fcb29:	movl %ebx, (%esi)
0x004fcb2b:	subl %esi, $0xfffffffc<UINT8>
0x004fcb2e:	adcl %ebx, %ebx
0x004fcb6d:	movl %ebx, (%esi)
0x004fcb6f:	subl %esi, $0xfffffffc<UINT8>
0x004fcb72:	adcl %ebx, %ebx
0x004fcb5f:	movl %ebx, (%esi)
0x004fcb61:	subl %esi, $0xfffffffc<UINT8>
0x004fcb64:	adcl %ebx, %ebx
0x004fcbca:	popl %esi
0x004fcbcb:	movl %edi, %esi
0x004fcbcd:	movl %ecx, $0x3fb6<UINT32>
0x004fcbd2:	movb %al, (%edi)
0x004fcbd4:	incl %edi
0x004fcbd5:	subb %al, $0xffffffe8<UINT8>
0x004fcbd7:	cmpb %al, $0x1<UINT8>
0x004fcbd9:	ja 0x004fcbd2
0x004fcbdb:	cmpb (%edi), $0x16<UINT8>
0x004fcbde:	jne 0x004fcbd2
0x004fcbe0:	movl %eax, (%edi)
0x004fcbe2:	movb %bl, 0x4(%edi)
0x004fcbe5:	shrw %ax, $0x8<UINT8>
0x004fcbe9:	roll %eax, $0x10<UINT8>
0x004fcbec:	xchgb %ah, %al
0x004fcbee:	subl %eax, %edi
0x004fcbf0:	subb %bl, $0xffffffe8<UINT8>
0x004fcbf3:	addl %eax, %esi
0x004fcbf5:	movl (%edi), %eax
0x004fcbf7:	addl %edi, $0x5<UINT8>
0x004fcbfa:	movb %al, %bl
0x004fcbfc:	loop 0x004fcbd7
0x004fcbfe:	leal %edi, 0xf9000(%esi)
0x004fcc04:	movl %eax, (%edi)
0x004fcc06:	orl %eax, %eax
0x004fcc08:	je 0x004fcc46
0x004fcc0a:	movl %ebx, 0x4(%edi)
0x004fcc0d:	leal %eax, 0x101bfc(%eax,%esi)
0x004fcc14:	addl %ebx, %esi
0x004fcc16:	pushl %eax
0x004fcc17:	addl %edi, $0x8<UINT8>
0x004fcc1a:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004fcc20:	xchgl %ebp, %eax
0x004fcc21:	movb %al, (%edi)
0x004fcc23:	incl %edi
0x004fcc24:	orb %al, %al
0x004fcc26:	je 0x004fcc04
0x004fcc28:	movl %ecx, %edi
0x004fcc2a:	pushl %edi
0x004fcc2b:	decl %eax
0x004fcc2c:	repn scasb %al, %es:(%edi)
0x004fcc2e:	pushl %ebp
0x004fcc2f:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x004fcc35:	orl %eax, %eax
0x004fcc37:	je 7
0x004fcc39:	movl (%ebx), %eax
0x004fcc3b:	addl %ebx, $0x4<UINT8>
0x004fcc3e:	jmp 0x004fcc21
GetProcAddress@KERNEL32.DLL: API Node	
0x004fcc46:	movl %ebp, 0x101d3c(%esi)
0x004fcc4c:	leal %edi, -4096(%esi)
0x004fcc52:	movl %ebx, $0x1000<UINT32>
0x004fcc57:	pushl %eax
0x004fcc58:	pushl %esp
0x004fcc59:	pushl $0x4<UINT8>
0x004fcc5b:	pushl %ebx
0x004fcc5c:	pushl %edi
0x004fcc5d:	call VirtualProtect@KERNEL32.DLL
VirtualProtect@KERNEL32.DLL: API Node	
0x004fcc5f:	leal %eax, 0x23f(%edi)
0x004fcc65:	andb (%eax), $0x7f<UINT8>
0x004fcc68:	andb 0x28(%eax), $0x7f<UINT8>
0x004fcc6c:	popl %eax
0x004fcc6d:	pushl %eax
0x004fcc6e:	pushl %esp
0x004fcc6f:	pushl %eax
0x004fcc70:	pushl %ebx
0x004fcc71:	pushl %edi
0x004fcc72:	call VirtualProtect@KERNEL32.DLL
0x004fcc74:	popl %eax
0x004fcc75:	popa
0x004fcc76:	leal %eax, -128(%esp)
0x004fcc7a:	pushl $0x0<UINT8>
0x004fcc7c:	cmpl %esp, %eax
0x004fcc7e:	jne 0x004fcc7a
0x004fcc80:	subl %esp, $0xffffff80<UINT8>
0x004fcc83:	jmp 0x004212c6
0x004212c6:	call 0x00421ddb
0x00421ddb:	pushl %ebp
0x00421ddc:	movl %ebp, %esp
0x00421dde:	subl %esp, $0x14<UINT8>
0x00421de1:	andl -12(%ebp), $0x0<UINT8>
0x00421de5:	andl -8(%ebp), $0x0<UINT8>
0x00421de9:	movl %eax, 0x4cff1c
0x00421dee:	pushl %esi
0x00421def:	pushl %edi
0x00421df0:	movl %edi, $0xbb40e64e<UINT32>
0x00421df5:	movl %esi, $0xffff0000<UINT32>
0x00421dfa:	cmpl %eax, %edi
0x00421dfc:	je 0x00421e0b
0x00421e0b:	leal %eax, -12(%ebp)
0x00421e0e:	pushl %eax
0x00421e0f:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x00421e15:	movl %eax, -8(%ebp)
0x00421e18:	xorl %eax, -12(%ebp)
0x00421e1b:	movl -4(%ebp), %eax
0x00421e1e:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x00421e24:	xorl -4(%ebp), %eax
0x00421e27:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x00421e2d:	xorl -4(%ebp), %eax
0x00421e30:	leal %eax, -20(%ebp)
0x00421e33:	pushl %eax
0x00421e34:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x00421e3a:	movl %ecx, -16(%ebp)
0x00421e3d:	leal %eax, -4(%ebp)
0x00421e40:	xorl %ecx, -20(%ebp)
0x00421e43:	xorl %ecx, -4(%ebp)
0x00421e46:	xorl %ecx, %eax
0x00421e48:	cmpl %ecx, %edi
0x00421e4a:	jne 0x00421e53
0x00421e53:	testl %esi, %ecx
0x00421e55:	jne 0x00421e63
0x00421e63:	movl 0x4cff1c, %ecx
0x00421e69:	notl %ecx
0x00421e6b:	movl 0x4cff18, %ecx
0x00421e71:	popl %edi
0x00421e72:	popl %esi
0x00421e73:	movl %esp, %ebp
0x00421e75:	popl %ebp
0x00421e76:	ret

0x004212cb:	jmp 0x00421139
0x00421139:	pushl $0x14<UINT8>
0x0042113b:	pushl $0x4c4428<UINT32>
0x00421140:	call 0x00421d80
0x00421d80:	pushl $0x43e560<UINT32>
0x00421d85:	pushl %fs:0
0x00421d8c:	movl %eax, 0x10(%esp)
0x00421d90:	movl 0x10(%esp), %ebp
0x00421d94:	leal %ebp, 0x10(%esp)
0x00421d98:	subl %esp, %eax
0x00421d9a:	pushl %ebx
0x00421d9b:	pushl %esi
0x00421d9c:	pushl %edi
0x00421d9d:	movl %eax, 0x4cff1c
0x00421da2:	xorl -4(%ebp), %eax
0x00421da5:	xorl %eax, %ebp
0x00421da7:	pushl %eax
0x00421da8:	movl -24(%ebp), %esp
0x00421dab:	pushl -8(%ebp)
0x00421dae:	movl %eax, -4(%ebp)
0x00421db1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00421db8:	movl -8(%ebp), %eax
0x00421dbb:	leal %eax, -16(%ebp)
0x00421dbe:	movl %fs:0, %eax
0x00421dc4:	repn ret

0x00421145:	pushl $0x1<UINT8>
0x00421147:	call 0x00420e43
0x00420e43:	pushl %ebp
0x00420e44:	movl %ebp, %esp
0x00420e46:	cmpl 0x8(%ebp), $0x0<UINT8>
0x00420e4a:	jne 0x00420e53
0x00420e53:	call 0x004219da
0x004219da:	pushl %ebp
0x004219db:	movl %ebp, %esp
0x004219dd:	andl 0x4e2988, $0x0<UINT8>
0x004219e4:	subl %esp, $0x28<UINT8>
0x004219e7:	pushl %ebx
0x004219e8:	xorl %ebx, %ebx
0x004219ea:	incl %ebx
0x004219eb:	orl 0x4cff2c, %ebx
0x004219f1:	pushl $0xa<UINT8>
0x004219f3:	call 0x00492f7e
0x00492f7e:	jmp IsProcessorFeaturePresent@KERNEL32.DLL
IsProcessorFeaturePresent@KERNEL32.DLL: API Node	
0x004219f8:	testl %eax, %eax
0x004219fa:	je 365
0x00421a00:	andl -16(%ebp), $0x0<UINT8>
0x00421a04:	xorl %eax, %eax
0x00421a06:	orl 0x4cff2c, $0x2<UINT8>
0x00421a0d:	xorl %ecx, %ecx
0x00421a0f:	pushl %esi
0x00421a10:	pushl %edi
0x00421a11:	movl 0x4e2988, %ebx
0x00421a17:	leal %edi, -40(%ebp)
0x00421a1a:	pushl %ebx
0x00421a1b:	cpuid
0x00421a1d:	movl %esi, %ebx
0x00421a1f:	popl %ebx
0x00421a20:	movl (%edi), %eax
0x00421a22:	movl 0x4(%edi), %esi
0x00421a25:	movl 0x8(%edi), %ecx
0x00421a28:	movl 0xc(%edi), %edx
0x00421a2b:	movl %eax, -40(%ebp)
0x00421a2e:	movl %ecx, -28(%ebp)
0x00421a31:	movl -8(%ebp), %eax
0x00421a34:	xorl %ecx, $0x49656e69<UINT32>
0x00421a3a:	movl %eax, -32(%ebp)
0x00421a3d:	xorl %eax, $0x6c65746e<UINT32>
0x00421a42:	orl %ecx, %eax
0x00421a44:	movl %eax, -36(%ebp)
0x00421a47:	pushl $0x1<UINT8>
0x00421a49:	xorl %eax, $0x756e6547<UINT32>
0x00421a4e:	orl %ecx, %eax
0x00421a50:	popl %eax
0x00421a51:	pushl $0x0<UINT8>
0x00421a53:	popl %ecx
0x00421a54:	pushl %ebx
0x00421a55:	cpuid
0x00421a57:	movl %esi, %ebx
0x00421a59:	popl %ebx
0x00421a5a:	movl (%edi), %eax
0x00421a5c:	movl 0x4(%edi), %esi
0x00421a5f:	movl 0x8(%edi), %ecx
0x00421a62:	movl 0xc(%edi), %edx
0x00421a65:	jne 67
0x00421a67:	movl %eax, -40(%ebp)
0x00421a6a:	andl %eax, $0xfff3ff0<UINT32>
0x00421a6f:	cmpl %eax, $0x106c0<UINT32>
0x00421a74:	je 35
0x00421a76:	cmpl %eax, $0x20660<UINT32>
0x00421a7b:	je 28
0x00421a7d:	cmpl %eax, $0x20670<UINT32>
0x00421a82:	je 21
0x00421a84:	cmpl %eax, $0x30650<UINT32>
0x00421a89:	je 14
0x00421a8b:	cmpl %eax, $0x30660<UINT32>
0x00421a90:	je 7
0x00421a92:	cmpl %eax, $0x30670<UINT32>
0x00421a97:	jne 0x00421aaa
0x00421aaa:	movl %edi, 0x4e298c
0x00421ab0:	cmpl -8(%ebp), $0x7<UINT8>
0x00421ab4:	movl %eax, -28(%ebp)
0x00421ab7:	movl -24(%ebp), %eax
0x00421aba:	movl %eax, -32(%ebp)
0x00421abd:	movl -4(%ebp), %eax
0x00421ac0:	movl -20(%ebp), %eax
0x00421ac3:	jl 0x00421af7
0x00421af7:	popl %edi
0x00421af8:	popl %esi
0x00421af9:	testl %eax, $0x100000<UINT32>
0x00421afe:	je 0x00421b6d
0x00421b6d:	xorl %eax, %eax
0x00421b6f:	popl %ebx
0x00421b70:	movl %esp, %ebp
0x00421b72:	popl %ebp
0x00421b73:	ret

0x00420e58:	call 0x004409eb
0x004409eb:	call 0x004445d6
0x004445d6:	movl %eax, 0x4cff1c
0x004445db:	andl %eax, $0x1f<UINT8>
0x004445de:	pushl $0x20<UINT8>
0x004445e0:	popl %ecx
0x004445e1:	subl %ecx, %eax
0x004445e3:	xorl %eax, %eax
0x004445e5:	rorl %eax, %cl
0x004445e7:	xorl %eax, 0x4cff1c
0x004445ed:	movl 0x4e2d28, %eax
0x004445f2:	ret

0x004409f0:	call 0x00440fe0
0x00440fe0:	movl %eax, 0x4cff1c
0x00440fe5:	movl %edx, $0x4e2d00<UINT32>
0x00440fea:	pushl %esi
0x00440feb:	andl %eax, $0x1f<UINT8>
0x00440fee:	xorl %esi, %esi
0x00440ff0:	pushl $0x20<UINT8>
0x00440ff2:	popl %ecx
0x00440ff3:	subl %ecx, %eax
0x00440ff5:	movl %eax, $0x4e2cdc<UINT32>
0x00440ffa:	rorl %esi, %cl
0x00440ffc:	xorl %ecx, %ecx
0x00440ffe:	xorl %esi, 0x4cff1c
0x00441004:	cmpl %edx, %eax
0x00441006:	sbbl %edx, %edx
0x00441008:	andl %edx, $0xfffffff7<UINT8>
0x0044100b:	addl %edx, $0x9<UINT8>
0x0044100e:	incl %ecx
0x0044100f:	movl (%eax), %esi
0x00441011:	leal %eax, 0x4(%eax)
0x00441014:	cmpl %ecx, %edx
0x00441016:	jne 0x0044100e
0x00441018:	popl %esi
0x00441019:	ret

0x004409f5:	call 0x004447be
0x004447be:	pushl %esi
0x004447bf:	pushl %edi
0x004447c0:	movl %edi, $0x4e2d2c<UINT32>
0x004447c5:	xorl %esi, %esi
0x004447c7:	pushl $0x0<UINT8>
0x004447c9:	pushl $0xfa0<UINT32>
0x004447ce:	pushl %edi
0x004447cf:	call 0x00440f9a
0x00440f9a:	pushl %ebp
0x00440f9b:	movl %ebp, %esp
0x00440f9d:	pushl %esi
0x00440f9e:	pushl $0x4b5de4<UINT32>
0x00440fa3:	pushl $0x4b5ddc<UINT32>
0x00440fa8:	pushl $0x4b2d64<UINT32>
0x00440fad:	pushl $0x8<UINT8>
0x00440faf:	call 0x00440c21
0x00440c21:	pushl %ebp
0x00440c22:	movl %ebp, %esp
0x00440c24:	movl %eax, 0x8(%ebp)
0x00440c27:	xorl %ecx, %ecx
0x00440c29:	pushl %ebx
0x00440c2a:	pushl %esi
0x00440c2b:	pushl %edi
0x00440c2c:	leal %ebx, 0x4e2cdc(,%eax,4)
0x00440c33:	xorl %eax, %eax
0x00440c35:	cmpxchgl (%ebx), %ecx
0x00440c39:	movl %edx, 0x4cff1c
0x00440c3f:	orl %edi, $0xffffffff<UINT8>
0x00440c42:	movl %ecx, %edx
0x00440c44:	movl %esi, %edx
0x00440c46:	andl %ecx, $0x1f<UINT8>
0x00440c49:	xorl %esi, %eax
0x00440c4b:	rorl %esi, %cl
0x00440c4d:	cmpl %esi, %edi
0x00440c4f:	je 0x00440cba
0x00440c51:	testl %esi, %esi
0x00440c53:	je 0x00440c59
0x00440c59:	movl %esi, 0x10(%ebp)
0x00440c5c:	cmpl %esi, 0x14(%ebp)
0x00440c5f:	je 26
0x00440c61:	pushl (%esi)
0x00440c63:	call 0x00440cc1
0x00440cc1:	pushl %ebp
0x00440cc2:	movl %ebp, %esp
0x00440cc4:	pushl %ebx
0x00440cc5:	movl %ebx, 0x8(%ebp)
0x00440cc8:	xorl %ecx, %ecx
0x00440cca:	pushl %edi
0x00440ccb:	xorl %eax, %eax
0x00440ccd:	leal %edi, 0x4e2ccc(,%ebx,4)
0x00440cd4:	cmpxchgl (%edi), %ecx
0x00440cd8:	movl %ecx, %eax
0x00440cda:	testl %ecx, %ecx
0x00440cdc:	je 0x00440ce9
0x00440ce9:	movl %ebx, 0x4b5cb4(,%ebx,4)
0x00440cf0:	pushl %esi
0x00440cf1:	pushl $0x800<UINT32>
0x00440cf6:	pushl $0x0<UINT8>
0x00440cf8:	pushl %ebx
0x00440cf9:	call LoadLibraryExW@KERNEL32.DLL
LoadLibraryExW@KERNEL32.DLL: API Node	
0x00440cff:	movl %esi, %eax
0x00440d01:	testl %esi, %esi
0x00440d03:	jne 0x00440d2c
0x00440d2c:	movl %eax, %esi
0x00440d2e:	xchgl (%edi), %eax
0x00440d30:	testl %eax, %eax
0x00440d32:	je 0x00440d3b
0x00440d3b:	movl %eax, %esi
0x00440d3d:	popl %esi
0x00440d3e:	popl %edi
0x00440d3f:	popl %ebx
0x00440d40:	popl %ebp
0x00440d41:	ret

0x00440c68:	popl %ecx
0x00440c69:	testl %eax, %eax
0x00440c6b:	jne 0x00440c9c
0x00440c9c:	movl %edx, 0x4cff1c
0x00440ca2:	jmp 0x00440c7d
0x00440c7d:	testl %eax, %eax
0x00440c7f:	je 41
0x00440c81:	pushl 0xc(%ebp)
0x00440c84:	pushl %eax
0x00440c85:	call GetProcAddress@KERNEL32.DLL
0x00440c8b:	movl %esi, %eax
0x00440c8d:	testl %esi, %esi
0x00440c8f:	je 0x00440ca4
0x00440ca4:	movl %edx, 0x4cff1c
0x00440caa:	movl %eax, %edx
0x00440cac:	pushl $0x20<UINT8>
0x00440cae:	andl %eax, $0x1f<UINT8>
0x00440cb1:	popl %ecx
0x00440cb2:	subl %ecx, %eax
0x00440cb4:	rorl %edi, %cl
0x00440cb6:	xorl %edi, %edx
0x00440cb8:	xchgl (%ebx), %edi
0x00440cba:	xorl %eax, %eax
0x00440cbc:	popl %edi
0x00440cbd:	popl %esi
0x00440cbe:	popl %ebx
0x00440cbf:	popl %ebp
0x00440cc0:	ret

0x00440fb4:	movl %esi, %eax
0x00440fb6:	addl %esp, $0x10<UINT8>
0x00440fb9:	testl %esi, %esi
0x00440fbb:	je 0x00440fd1
0x00440fd1:	pushl 0xc(%ebp)
0x00440fd4:	pushl 0x8(%ebp)
0x00440fd7:	call InitializeCriticalSectionAndSpinCount@KERNEL32.DLL
InitializeCriticalSectionAndSpinCount@KERNEL32.DLL: API Node	
0x00440fdd:	popl %esi
0x00440fde:	popl %ebp
0x00440fdf:	ret

0x004447d4:	addl %esp, $0xc<UINT8>
0x004447d7:	testl %eax, %eax
0x004447d9:	je 21
0x004447db:	incl 0x4e2d44
0x004447e1:	addl %esi, $0x18<UINT8>
0x004447e4:	addl %edi, $0x18<UINT8>
0x004447e7:	cmpl %esi, $0x18<UINT8>
0x004447ea:	jb -37
0x004447ec:	movb %al, $0x1<UINT8>
0x004447ee:	jmp 0x004447f7
0x004447f7:	popl %edi
0x004447f8:	popl %esi
0x004447f9:	ret

0x004409fa:	testb %al, %al
0x004409fc:	jne 0x00440a01
0x00440a01:	call 0x00444513
0x00444513:	pushl $0x444421<UINT32>
0x00444518:	call 0x00440eaf
0x00440eaf:	pushl %ebp
0x00440eb0:	movl %ebp, %esp
0x00440eb2:	pushl %esi
0x00440eb3:	pushl $0x4b5dc4<UINT32>
0x00440eb8:	pushl $0x4b5dbc<UINT32>
0x00440ebd:	pushl $0x4b2d38<UINT32>
0x00440ec2:	pushl $0x4<UINT8>
0x00440ec4:	call 0x00440c21
0x00440d05:	call GetLastError@KERNEL32.DLL
GetLastError@KERNEL32.DLL: API Node	
0x00440d0b:	cmpl %eax, $0x57<UINT8>
0x00440d0e:	jne 0x00440d1d
0x00440d1d:	xorl %esi, %esi
0x00440d1f:	testl %esi, %esi
0x00440d21:	jne 9
0x00440d23:	orl %eax, $0xffffffff<UINT8>
0x00440d26:	xchgl (%edi), %eax
0x00440d28:	xorl %eax, %eax
0x00440d2a:	jmp 0x00440d3d
0x00440c6d:	addl %esi, $0x4<UINT8>
0x00440c70:	cmpl %esi, 0x14(%ebp)
0x00440c73:	jne 0x00440c61
0x00440c91:	pushl %esi
0x00440c92:	call 0x00440a7e
0x00440a7e:	pushl %ebp
0x00440a7f:	movl %ebp, %esp
0x00440a81:	movl %eax, 0x4cff1c
0x00440a86:	andl %eax, $0x1f<UINT8>
0x00440a89:	pushl $0x20<UINT8>
0x00440a8b:	popl %ecx
0x00440a8c:	subl %ecx, %eax
0x00440a8e:	movl %eax, 0x8(%ebp)
0x00440a91:	rorl %eax, %cl
0x00440a93:	xorl %eax, 0x4cff1c
0x00440a99:	popl %ebp
0x00440a9a:	ret

0x00440c97:	popl %ecx
0x00440c98:	xchgl (%ebx), %eax
0x00440c9a:	jmp 0x00440c55
0x00440c55:	movl %eax, %esi
0x00440c57:	jmp 0x00440cbc
0x00440ec9:	movl %esi, %eax
0x00440ecb:	addl %esp, $0x10<UINT8>
0x00440ece:	testl %esi, %esi
0x00440ed0:	je 15
0x00440ed2:	pushl 0x8(%ebp)
0x00440ed5:	movl %ecx, %esi
0x00440ed7:	call 0x00421d6e
0x00421d6e:	jmp 0x00421f52
0x00421f52:	ret

0x00440edc:	call FlsAlloc@kernel32.dll
FlsAlloc@kernel32.dll: API Node	
0x00440ede:	popl %esi
0x00440edf:	popl %ebp
0x00440ee0:	ret

0x0044451d:	movl 0x4cffa0, %eax
0x00444522:	popl %ecx
0x00444523:	cmpl %eax, $0xffffffff<UINT8>
0x00444526:	jne 0x0044452b
0x0044452b:	pushl $0x4e2d00<UINT32>
0x00444530:	pushl %eax
0x00444531:	call 0x00440f5d
0x00440f5d:	pushl %ebp
0x00440f5e:	movl %ebp, %esp
0x00440f60:	pushl %esi
0x00440f61:	pushl $0x4b5ddc<UINT32>
0x00440f66:	pushl $0x4b5dd4<UINT32>
0x00440f6b:	pushl $0x4b2d58<UINT32>
0x00440f70:	pushl $0x7<UINT8>
0x00440f72:	call 0x00440c21
0x00440cde:	leal %eax, 0x1(%ecx)
0x00440ce1:	negl %eax
0x00440ce3:	sbbl %eax, %eax
0x00440ce5:	andl %eax, %ecx
0x00440ce7:	jmp 0x00440d3e
0x00440f77:	addl %esp, $0x10<UINT8>
0x00440f7a:	movl %esi, %eax
0x00440f7c:	pushl 0xc(%ebp)
0x00440f7f:	pushl 0x8(%ebp)
0x00440f82:	testl %esi, %esi
0x00440f84:	je 11
0x00440f86:	movl %ecx, %esi
0x00440f88:	call 0x00421d6e
0x00440f8d:	call FlsSetValue@kernel32.dll
FlsSetValue@kernel32.dll: API Node	
0x00440f8f:	jmp 0x00440f97
0x00440f97:	popl %esi
0x00440f98:	popl %ebp
0x00440f99:	ret

0x00444536:	popl %ecx
0x00444537:	popl %ecx
0x00444538:	testl %eax, %eax
0x0044453a:	jne 0x00444543
0x00444543:	movb %al, $0x1<UINT8>
0x00444545:	ret

0x00440a06:	testb %al, %al
0x00440a08:	jne 0x00440a11
0x00440a11:	movb %al, $0x1<UINT8>
0x00440a13:	ret

0x00420e5d:	testb %al, %al
0x00420e5f:	jne 0x00420e65
0x00420e65:	call 0x00472ce1
0x00472ce1:	pushl $0x4b7a30<UINT32>
0x00472ce6:	pushl $0x4b79b8<UINT32>
0x00472ceb:	call 0x00485525
0x00485525:	movl %edi, %edi
0x00485527:	pushl %ebp
0x00485528:	movl %ebp, %esp
0x0048552a:	pushl %ecx
0x0048552b:	movl %eax, 0x4cff1c
0x00485530:	xorl %eax, %ebp
0x00485532:	movl -4(%ebp), %eax
0x00485535:	pushl %edi
0x00485536:	movl %edi, 0x8(%ebp)
0x00485539:	cmpl %edi, 0xc(%ebp)
0x0048553c:	jne 0x00485542
0x00485542:	pushl %esi
0x00485543:	movl %esi, %edi
0x00485545:	pushl %ebx
0x00485546:	movl %ebx, (%esi)
0x00485548:	testl %ebx, %ebx
0x0048554a:	je 0x0048555a
0x0048554c:	movl %ecx, %ebx
0x0048554e:	call 0x00421f52
0x00485554:	call 0x00472bc2
0x00472bb0:	pushl $0x4d00f8<UINT32>
0x00472bb5:	movl %ecx, $0x4e389c<UINT32>
0x00472bba:	call 0x00472cb0
0x00472cb0:	movl %edi, %edi
0x00472cb2:	pushl %ebp
0x00472cb3:	movl %ebp, %esp
0x00472cb5:	leal %eax, 0x4(%ecx)
0x00472cb8:	movl %edx, %eax
0x00472cba:	subl %edx, %ecx
0x00472cbc:	addl %edx, $0x3<UINT8>
0x00472cbf:	pushl %esi
0x00472cc0:	xorl %esi, %esi
0x00472cc2:	shrl %edx, $0x2<UINT8>
0x00472cc5:	cmpl %eax, %ecx
0x00472cc7:	sbbl %eax, %eax
0x00472cc9:	notl %eax
0x00472ccb:	andl %eax, %edx
0x00472ccd:	je 13
0x00472ccf:	movl %edx, 0x8(%ebp)
0x00472cd2:	incl %esi
0x00472cd3:	movl (%ecx), %edx
0x00472cd5:	leal %ecx, 0x4(%ecx)
0x00472cd8:	cmpl %esi, %eax
0x00472cda:	jne -10
0x00472cdc:	popl %esi
0x00472cdd:	popl %ebp
0x00472cde:	ret $0x4<UINT16>

0x00472bbf:	movb %al, $0x1<UINT8>
0x00472bc1:	ret

0x00485556:	testb %al, %al
0x00485558:	je 8
0x0048555a:	addl %esi, $0x8<UINT8>
0x0048555d:	cmpl %esi, 0xc(%ebp)
0x00485560:	jne 0x00485546
0x00472bf0:	movl %eax, 0x4cff1c
0x00472bf5:	pushl %esi
0x00472bf6:	pushl $0x20<UINT8>
0x00472bf8:	andl %eax, $0x1f<UINT8>
0x00472bfb:	xorl %esi, %esi
0x00472bfd:	popl %ecx
0x00472bfe:	subl %ecx, %eax
0x00472c00:	rorl %esi, %cl
0x00472c02:	xorl %esi, 0x4cff1c
0x00472c08:	pushl %esi
0x00472c09:	call 0x0046d0eb
0x0046d0eb:	movl %edi, %edi
0x0046d0ed:	pushl %ebp
0x0046d0ee:	movl %ebp, %esp
0x0046d0f0:	pushl 0x8(%ebp)
0x0046d0f3:	movl %ecx, $0x4e2dc4<UINT32>
0x0046d0f8:	call 0x0046cf7c
0x0046cf7c:	movl %edi, %edi
0x0046cf7e:	pushl %ebp
0x0046cf7f:	movl %ebp, %esp
0x0046cf81:	leal %eax, 0x4(%ecx)
0x0046cf84:	movl %edx, %eax
0x0046cf86:	subl %edx, %ecx
0x0046cf88:	addl %edx, $0x3<UINT8>
0x0046cf8b:	pushl %esi
0x0046cf8c:	xorl %esi, %esi
0x0046cf8e:	shrl %edx, $0x2<UINT8>
0x0046cf91:	cmpl %eax, %ecx
0x0046cf93:	sbbl %eax, %eax
0x0046cf95:	notl %eax
0x0046cf97:	andl %eax, %edx
0x0046cf99:	je 13
0x0046cf9b:	movl %edx, 0x8(%ebp)
0x0046cf9e:	incl %esi
0x0046cf9f:	movl (%ecx), %edx
0x0046cfa1:	leal %ecx, 0x4(%ecx)
0x0046cfa4:	cmpl %esi, %eax
0x0046cfa6:	jne -10
0x0046cfa8:	popl %esi
0x0046cfa9:	popl %ebp
0x0046cfaa:	ret $0x4<UINT16>

0x0046d0fd:	popl %ebp
0x0046d0fe:	ret

0x00472c0e:	pushl %esi
0x00472c0f:	call 0x004710e0
0x004710e0:	movl %edi, %edi
0x004710e2:	pushl %ebp
0x004710e3:	movl %ebp, %esp
0x004710e5:	pushl 0x8(%ebp)
0x004710e8:	movl %ecx, $0x4e2dd0<UINT32>
0x004710ed:	call 0x004710ac
0x004710ac:	movl %edi, %edi
0x004710ae:	pushl %ebp
0x004710af:	movl %ebp, %esp
0x004710b1:	leal %eax, 0x4(%ecx)
0x004710b4:	movl %edx, %eax
0x004710b6:	subl %edx, %ecx
0x004710b8:	addl %edx, $0x3<UINT8>
0x004710bb:	pushl %esi
0x004710bc:	xorl %esi, %esi
0x004710be:	shrl %edx, $0x2<UINT8>
0x004710c1:	cmpl %eax, %ecx
0x004710c3:	sbbl %eax, %eax
0x004710c5:	notl %eax
0x004710c7:	andl %eax, %edx
0x004710c9:	je 13
0x004710cb:	movl %edx, 0x8(%ebp)
0x004710ce:	incl %esi
0x004710cf:	movl (%ecx), %edx
0x004710d1:	leal %ecx, 0x4(%ecx)
0x004710d4:	cmpl %esi, %eax
0x004710d6:	jne -10
0x004710d8:	popl %esi
0x004710d9:	popl %ebp
0x004710da:	ret $0x4<UINT16>

0x004710f2:	popl %ebp
0x004710f3:	ret

0x00472c14:	pushl %esi
0x00472c15:	call 0x004858a1
0x004858a1:	movl %edi, %edi
0x004858a3:	pushl %ebp
0x004858a4:	movl %ebp, %esp
0x004858a6:	pushl 0x8(%ebp)
0x004858a9:	movl %ecx, $0x4e3bdc<UINT32>
0x004858ae:	call 0x004857fd
0x004857fd:	movl %edi, %edi
0x004857ff:	pushl %ebp
0x00485800:	movl %ebp, %esp
0x00485802:	leal %eax, 0x4(%ecx)
0x00485805:	movl %edx, %eax
0x00485807:	subl %edx, %ecx
0x00485809:	addl %edx, $0x3<UINT8>
0x0048580c:	pushl %esi
0x0048580d:	xorl %esi, %esi
0x0048580f:	shrl %edx, $0x2<UINT8>
0x00485812:	cmpl %eax, %ecx
0x00485814:	sbbl %eax, %eax
0x00485816:	notl %eax
0x00485818:	andl %eax, %edx
0x0048581a:	je 13
0x0048581c:	movl %edx, 0x8(%ebp)
0x0048581f:	incl %esi
0x00485820:	movl (%ecx), %edx
0x00485822:	leal %ecx, 0x4(%ecx)
0x00485825:	cmpl %esi, %eax
0x00485827:	jne -10
0x00485829:	popl %esi
0x0048582a:	popl %ebp
0x0048582b:	ret $0x4<UINT16>

0x004858b3:	pushl 0x8(%ebp)
0x004858b6:	movl %ecx, $0x4e3be0<UINT32>
0x004858bb:	call 0x004857fd
0x004858c0:	pushl 0x8(%ebp)
0x004858c3:	movl %ecx, $0x4e3be4<UINT32>
0x004858c8:	call 0x004857fd
0x004858cd:	pushl 0x8(%ebp)
0x004858d0:	movl %ecx, $0x4e3be8<UINT32>
0x004858d5:	call 0x004857fd
0x004858da:	popl %ebp
0x004858db:	ret

0x00472c1a:	pushl %esi
0x00472c1b:	call 0x00472f80
0x00472f80:	movl %edi, %edi
0x00472f82:	pushl %ebp
0x00472f83:	movl %ebp, %esp
0x00472f85:	pushl 0x8(%ebp)
0x00472f88:	movl %ecx, $0x4e3748<UINT32>
0x00472f8d:	call 0x00472f33
0x00472f33:	movl %edi, %edi
0x00472f35:	pushl %ebp
0x00472f36:	movl %ebp, %esp
0x00472f38:	leal %eax, 0x4(%ecx)
0x00472f3b:	movl %edx, %eax
0x00472f3d:	subl %edx, %ecx
0x00472f3f:	addl %edx, $0x3<UINT8>
0x00472f42:	pushl %esi
0x00472f43:	xorl %esi, %esi
0x00472f45:	shrl %edx, $0x2<UINT8>
0x00472f48:	cmpl %eax, %ecx
0x00472f4a:	sbbl %eax, %eax
0x00472f4c:	notl %eax
0x00472f4e:	andl %eax, %edx
0x00472f50:	je 13
0x00472f52:	movl %edx, 0x8(%ebp)
0x00472f55:	incl %esi
0x00472f56:	movl (%ecx), %edx
0x00472f58:	leal %ecx, 0x4(%ecx)
0x00472f5b:	cmpl %esi, %eax
0x00472f5d:	jne -10
0x00472f5f:	popl %esi
0x00472f60:	popl %ebp
0x00472f61:	ret $0x4<UINT16>

0x00472f92:	popl %ebp
0x00472f93:	ret

0x00472c20:	pushl %esi
0x00472c21:	call 0x004716aa
0x004716aa:	movl %edi, %edi
0x004716ac:	pushl %ebp
0x004716ad:	movl %ebp, %esp
0x004716af:	movl %eax, 0x8(%ebp)
0x004716b2:	movl 0x4e2dd8, %eax
0x004716b7:	popl %ebp
0x004716b8:	ret

0x00472c26:	addl %esp, $0x14<UINT8>
0x00472c29:	movb %al, $0x1<UINT8>
0x00472c2b:	popl %esi
0x00472c2c:	ret

0x0047d9dd:	movl %eax, 0x4cff1c
0x0047d9e2:	pushl %edi
0x0047d9e3:	pushl $0x20<UINT8>
0x0047d9e5:	andl %eax, $0x1f<UINT8>
0x0047d9e8:	movl %edi, $0x4e3b08<UINT32>
0x0047d9ed:	popl %ecx
0x0047d9ee:	subl %ecx, %eax
0x0047d9f0:	xorl %eax, %eax
0x0047d9f2:	rorl %eax, %cl
0x0047d9f4:	xorl %eax, 0x4cff1c
0x0047d9fa:	pushl $0x20<UINT8>
0x0047d9fc:	popl %ecx
0x0047d9fd:	rep stosl %es:(%edi), %eax
0x0047d9ff:	movb %al, $0x1<UINT8>
0x0047da01:	popl %edi
0x0047da02:	ret

0x00472bea:	movb %al, $0x1<UINT8>
0x00472bec:	ret

0x00474ab3:	movl %edi, %edi
0x00474ab5:	pushl %esi
0x00474ab6:	pushl %edi
0x00474ab7:	movl %edi, $0x4e3760<UINT32>
0x00474abc:	xorl %esi, %esi
0x00474abe:	pushl $0x0<UINT8>
0x00474ac0:	pushl $0xfa0<UINT32>
0x00474ac5:	pushl %edi
0x00474ac6:	call 0x0047d4fe
0x0047d4fe:	movl %edi, %edi
0x0047d500:	pushl %ebp
0x0047d501:	movl %ebp, %esp
0x0047d503:	pushl %ecx
0x0047d504:	movl %eax, 0x4cff1c
0x0047d509:	xorl %eax, %ebp
0x0047d50b:	movl -4(%ebp), %eax
0x0047d50e:	pushl %esi
0x0047d50f:	pushl $0x4b9074<UINT32>
0x0047d514:	pushl $0x4b906c<UINT32>
0x0047d519:	pushl $0x4b2d64<UINT32>
0x0047d51e:	pushl $0x14<UINT8>
0x0047d520:	call 0x0047cdd0
0x0047cdd0:	movl %edi, %edi
0x0047cdd2:	pushl %ebp
0x0047cdd3:	movl %ebp, %esp
0x0047cdd5:	movl %eax, 0x8(%ebp)
0x0047cdd8:	pushl %ebx
0x0047cdd9:	pushl %esi
0x0047cdda:	pushl %edi
0x0047cddb:	leal %ebx, 0x4e3b08(,%eax,4)
0x0047cde2:	movl %eax, (%ebx)
0x0047cde4:	movl %edx, 0x4cff1c
0x0047cdea:	orl %edi, $0xffffffff<UINT8>
0x0047cded:	movl %ecx, %edx
0x0047cdef:	movl %esi, %edx
0x0047cdf1:	andl %ecx, $0x1f<UINT8>
0x0047cdf4:	xorl %esi, %eax
0x0047cdf6:	rorl %esi, %cl
0x0047cdf8:	cmpl %esi, %edi
0x0047cdfa:	je 0x0047ce65
0x0047cdfc:	testl %esi, %esi
0x0047cdfe:	je 0x0047ce04
0x0047ce04:	movl %esi, 0x10(%ebp)
0x0047ce07:	cmpl %esi, 0x14(%ebp)
0x0047ce0a:	je 26
0x0047ce0c:	pushl (%esi)
0x0047ce0e:	call 0x0047ce6c
0x0047ce6c:	movl %edi, %edi
0x0047ce6e:	pushl %ebp
0x0047ce6f:	movl %ebp, %esp
0x0047ce71:	movl %eax, 0x8(%ebp)
0x0047ce74:	pushl %edi
0x0047ce75:	leal %edi, 0x4e3ab8(,%eax,4)
0x0047ce7c:	movl %ecx, (%edi)
0x0047ce7e:	testl %ecx, %ecx
0x0047ce80:	je 0x0047ce8d
0x0047ce8d:	pushl %ebx
0x0047ce8e:	movl %ebx, 0x4b8a58(,%eax,4)
0x0047ce95:	pushl %esi
0x0047ce96:	pushl $0x800<UINT32>
0x0047ce9b:	pushl $0x0<UINT8>
0x0047ce9d:	pushl %ebx
0x0047ce9e:	call LoadLibraryExW@KERNEL32.DLL
0x0047cea4:	movl %esi, %eax
0x0047cea6:	testl %esi, %esi
0x0047cea8:	jne 0x0047ced1
0x0047ced1:	movl %eax, %esi
0x0047ced3:	xchgl (%edi), %eax
0x0047ced5:	testl %eax, %eax
0x0047ced7:	je 0x0047cee0
0x0047cee0:	movl %eax, %esi
0x0047cee2:	popl %esi
0x0047cee3:	popl %ebx
0x0047cee4:	popl %edi
0x0047cee5:	popl %ebp
0x0047cee6:	ret

0x0047ce13:	popl %ecx
0x0047ce14:	testl %eax, %eax
0x0047ce16:	jne 0x0047ce47
0x0047ce47:	movl %edx, 0x4cff1c
0x0047ce4d:	jmp 0x0047ce28
0x0047ce28:	testl %eax, %eax
0x0047ce2a:	je 41
0x0047ce2c:	pushl 0xc(%ebp)
0x0047ce2f:	pushl %eax
0x0047ce30:	call GetProcAddress@KERNEL32.DLL
0x0047ce36:	movl %esi, %eax
0x0047ce38:	testl %esi, %esi
0x0047ce3a:	je 0x0047ce4f
0x0047ce4f:	movl %edx, 0x4cff1c
0x0047ce55:	movl %eax, %edx
0x0047ce57:	pushl $0x20<UINT8>
0x0047ce59:	andl %eax, $0x1f<UINT8>
0x0047ce5c:	popl %ecx
0x0047ce5d:	subl %ecx, %eax
0x0047ce5f:	rorl %edi, %cl
0x0047ce61:	xorl %edi, %edx
0x0047ce63:	xchgl (%ebx), %edi
0x0047ce65:	xorl %eax, %eax
0x0047ce67:	popl %edi
0x0047ce68:	popl %esi
0x0047ce69:	popl %ebx
0x0047ce6a:	popl %ebp
0x0047ce6b:	ret

0x0047d525:	movl %esi, %eax
0x0047d527:	addl %esp, $0x10<UINT8>
0x0047d52a:	testl %esi, %esi
0x0047d52c:	je 0x0047d543
0x0047d543:	pushl 0xc(%ebp)
0x0047d546:	pushl 0x8(%ebp)
0x0047d549:	call InitializeCriticalSectionAndSpinCount@KERNEL32.DLL
0x0047d54f:	movl %ecx, -4(%ebp)
0x0047d552:	xorl %ecx, %ebp
0x0047d554:	popl %esi
0x0047d555:	call 0x00420bd0
0x00420bd0:	cmpl %ecx, 0x4cff1c
0x00420bd6:	repn jne 2
0x00420bd9:	repn ret

0x0047d55a:	movl %esp, %ebp
0x0047d55c:	popl %ebp
0x0047d55d:	ret $0xc<UINT16>

0x00474acb:	testl %eax, %eax
0x00474acd:	je 24
0x00474acf:	incl 0x4e3898
0x00474ad5:	addl %esi, $0x18<UINT8>
0x00474ad8:	addl %edi, $0x18<UINT8>
0x00474adb:	cmpl %esi, $0x138<UINT32>
0x00474ae1:	jb 0x00474abe
0x00474ae3:	movb %al, $0x1<UINT8>
0x00474ae5:	jmp 0x00474af1
0x00474af1:	popl %edi
0x00474af2:	popl %esi
0x00474af3:	ret

0x00485504:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x0048550a:	testl %eax, %eax
0x0048550c:	movl 0x4e3bd4, %eax
0x00485511:	setne %al
0x00485514:	ret

0x0047ae31:	pushl $0x47aad4<UINT32>
0x0047ae36:	call 0x0047d081
0x0047d081:	movl %edi, %edi
0x0047d083:	pushl %ebp
0x0047d084:	movl %ebp, %esp
0x0047d086:	pushl %ecx
0x0047d087:	movl %eax, 0x4cff1c
0x0047d08c:	xorl %eax, %ebp
0x0047d08e:	movl -4(%ebp), %eax
0x0047d091:	pushl %esi
0x0047d092:	pushl $0x4b8f28<UINT32>
0x0047d097:	pushl $0x4b8f20<UINT32>
0x0047d09c:	pushl $0x4b2d38<UINT32>
0x0047d0a1:	pushl $0x3<UINT8>
0x0047d0a3:	call 0x0047cdd0
0x0047ceaa:	call GetLastError@KERNEL32.DLL
0x0047ceb0:	cmpl %eax, $0x57<UINT8>
0x0047ceb3:	jne 0x0047cec2
0x0047cec2:	xorl %esi, %esi
0x0047cec4:	testl %esi, %esi
0x0047cec6:	jne 9
0x0047cec8:	orl %eax, $0xffffffff<UINT8>
0x0047cecb:	xchgl (%edi), %eax
0x0047cecd:	xorl %eax, %eax
0x0047cecf:	jmp 0x0047cee2
0x0047ce18:	addl %esi, $0x4<UINT8>
0x0047ce1b:	cmpl %esi, 0x14(%ebp)
0x0047ce1e:	jne 0x0047ce0c
0x0047ce3c:	pushl %esi
0x0047ce3d:	call 0x00440a7e
0x0047ce42:	popl %ecx
0x0047ce43:	xchgl (%ebx), %eax
0x0047ce45:	jmp 0x0047ce00
0x0047ce00:	movl %eax, %esi
0x0047ce02:	jmp 0x0047ce67
0x0047d0a8:	movl %esi, %eax
0x0047d0aa:	addl %esp, $0x10<UINT8>
0x0047d0ad:	testl %esi, %esi
0x0047d0af:	je 15
0x0047d0b1:	pushl 0x8(%ebp)
0x0047d0b4:	movl %ecx, %esi
0x0047d0b6:	call 0x00421f52
0x0047d0bc:	call FlsAlloc@kernel32.dll
0x0047d0be:	jmp 0x0047d0c6
0x0047d0c6:	movl %ecx, -4(%ebp)
0x0047d0c9:	xorl %ecx, %ebp
0x0047d0cb:	popl %esi
0x0047d0cc:	call 0x00420bd0
0x0047d0d1:	movl %esp, %ebp
0x0047d0d3:	popl %ebp
0x0047d0d4:	ret $0x4<UINT16>

0x0047ae3b:	movl 0x4d00f0, %eax
0x0047ae40:	cmpl %eax, $0xffffffff<UINT8>
0x0047ae43:	jne 0x0047ae48
0x0047ae48:	call 0x0047adac
0x0047adac:	movl %edi, %edi
0x0047adae:	pushl %ebx
0x0047adaf:	pushl %esi
0x0047adb0:	pushl %edi
0x0047adb1:	call GetLastError@KERNEL32.DLL
0x0047adb7:	movl %esi, %eax
0x0047adb9:	xorl %ebx, %ebx
0x0047adbb:	movl %eax, 0x4d00f0
0x0047adc0:	cmpl %eax, $0xffffffff<UINT8>
0x0047adc3:	je 12
0x0047adc5:	pushl %eax
0x0047adc6:	call 0x0047d12d
0x0047d12d:	movl %edi, %edi
0x0047d12f:	pushl %ebp
0x0047d130:	movl %ebp, %esp
0x0047d132:	pushl %ecx
0x0047d133:	movl %eax, 0x4cff1c
0x0047d138:	xorl %eax, %ebp
0x0047d13a:	movl -4(%ebp), %eax
0x0047d13d:	pushl %esi
0x0047d13e:	pushl $0x4b8f38<UINT32>
0x0047d143:	pushl $0x4b8f30<UINT32>
0x0047d148:	pushl $0x4b2d4c<UINT32>
0x0047d14d:	pushl $0x5<UINT8>
0x0047d14f:	call 0x0047cdd0
0x0047ce82:	leal %eax, 0x1(%ecx)
0x0047ce85:	negl %eax
0x0047ce87:	sbbl %eax, %eax
0x0047ce89:	andl %eax, %ecx
0x0047ce8b:	jmp 0x0047cee4
0x0047d154:	addl %esp, $0x10<UINT8>
0x0047d157:	movl %esi, %eax
0x0047d159:	pushl 0x8(%ebp)
0x0047d15c:	testl %esi, %esi
0x0047d15e:	je 12
0x0047d160:	movl %ecx, %esi
0x0047d162:	call 0x00421f52
0x0047d168:	call FlsGetValue@kernel32.dll
FlsGetValue@kernel32.dll: API Node	
0x0047d16a:	jmp 0x0047d172
0x0047d172:	movl %ecx, -4(%ebp)
0x0047d175:	xorl %ecx, %ebp
0x0047d177:	popl %esi
0x0047d178:	call 0x00420bd0
0x0047d17d:	movl %esp, %ebp
0x0047d17f:	popl %ebp
0x0047d180:	ret $0x4<UINT16>

0x0047adcb:	movl %edi, %eax
0x0047adcd:	testl %edi, %edi
0x0047adcf:	jne 0x0047ae22
0x0047add1:	pushl $0x364<UINT32>
0x0047add6:	pushl $0x1<UINT8>
0x0047add8:	call 0x00474b65
0x00474b65:	movl %edi, %edi
0x00474b67:	pushl %ebp
0x00474b68:	movl %ebp, %esp
0x00474b6a:	pushl %esi
0x00474b6b:	movl %esi, 0x8(%ebp)
0x00474b6e:	testl %esi, %esi
0x00474b70:	je 12
0x00474b72:	pushl $0xffffffe0<UINT8>
0x00474b74:	xorl %edx, %edx
0x00474b76:	popl %eax
0x00474b77:	divl %eax, %esi
0x00474b79:	cmpl %eax, 0xc(%ebp)
0x00474b7c:	jb 52
0x00474b7e:	imull %esi, 0xc(%ebp)
0x00474b82:	testl %esi, %esi
0x00474b84:	jne 0x00474b9d
0x00474b9d:	pushl %esi
0x00474b9e:	pushl $0x8<UINT8>
0x00474ba0:	pushl 0x4e3bd4
0x00474ba6:	call HeapAlloc@KERNEL32.DLL
HeapAlloc@KERNEL32.DLL: API Node	
0x00474bac:	testl %eax, %eax
0x00474bae:	je -39
0x00474bb0:	jmp 0x00474bbf
0x00474bbf:	popl %esi
0x00474bc0:	popl %ebp
0x00474bc1:	ret

0x0047addd:	movl %edi, %eax
0x0047addf:	popl %ecx
0x0047ade0:	popl %ecx
0x0047ade1:	testl %edi, %edi
0x0047ade3:	jne 0x0047adee
0x0047adee:	pushl %edi
0x0047adef:	pushl 0x4d00f0
0x0047adf5:	call 0x0047d183
0x0047d183:	movl %edi, %edi
0x0047d185:	pushl %ebp
0x0047d186:	movl %ebp, %esp
0x0047d188:	pushl %ecx
0x0047d189:	movl %eax, 0x4cff1c
0x0047d18e:	xorl %eax, %ebp
0x0047d190:	movl -4(%ebp), %eax
0x0047d193:	pushl %esi
0x0047d194:	pushl $0x4b8f40<UINT32>
0x0047d199:	pushl $0x4b8f38<UINT32>
0x0047d19e:	pushl $0x4b2d58<UINT32>
0x0047d1a3:	pushl $0x6<UINT8>
0x0047d1a5:	call 0x0047cdd0
0x0047d1aa:	addl %esp, $0x10<UINT8>
0x0047d1ad:	movl %esi, %eax
0x0047d1af:	pushl 0xc(%ebp)
0x0047d1b2:	pushl 0x8(%ebp)
0x0047d1b5:	testl %esi, %esi
0x0047d1b7:	je 12
0x0047d1b9:	movl %ecx, %esi
0x0047d1bb:	call 0x00421f52
0x0047d1c1:	call FlsSetValue@kernel32.dll
0x0047d1c3:	jmp 0x0047d1cb
0x0047d1cb:	movl %ecx, -4(%ebp)
0x0047d1ce:	xorl %ecx, %ebp
0x0047d1d0:	popl %esi
0x0047d1d1:	call 0x00420bd0
0x0047d1d6:	movl %esp, %ebp
0x0047d1d8:	popl %ebp
0x0047d1d9:	ret $0x8<UINT16>

0x0047adfa:	testl %eax, %eax
0x0047adfc:	jne 0x0047ae01
0x0047ae01:	pushl $0x4e389c<UINT32>
0x0047ae06:	pushl %edi
0x0047ae07:	call 0x0047aa42
0x0047aa42:	movl %edi, %edi
0x0047aa44:	pushl %ebp
0x0047aa45:	movl %ebp, %esp
0x0047aa47:	pushl %ecx
0x0047aa48:	pushl %ecx
0x0047aa49:	movl %eax, 0x8(%ebp)
0x0047aa4c:	xorl %ecx, %ecx
0x0047aa4e:	incl %ecx
0x0047aa4f:	pushl $0x43<UINT8>
0x0047aa51:	movl 0x18(%eax), %ecx
0x0047aa54:	movl %eax, 0x8(%ebp)
0x0047aa57:	movl (%eax), $0x4b78c8<UINT32>
0x0047aa5d:	movl %eax, 0x8(%ebp)
0x0047aa60:	movl 0x350(%eax), %ecx
0x0047aa66:	movl %eax, 0x8(%ebp)
0x0047aa69:	popl %ecx
0x0047aa6a:	movl 0x48(%eax), $0x4d05f8<UINT32>
0x0047aa71:	movl %eax, 0x8(%ebp)
0x0047aa74:	movw 0x6c(%eax), %cx
0x0047aa78:	movl %eax, 0x8(%ebp)
0x0047aa7b:	movw 0x172(%eax), %cx
0x0047aa82:	movl %eax, 0x8(%ebp)
0x0047aa85:	andl 0x34c(%eax), $0x0<UINT8>
0x0047aa8c:	leal %eax, 0x8(%ebp)
0x0047aa8f:	movl -4(%ebp), %eax
0x0047aa92:	leal %eax, -4(%ebp)
0x0047aa95:	pushl %eax
0x0047aa96:	pushl $0x5<UINT8>
0x0047aa98:	call 0x0047a868
0x0047a868:	movl %edi, %edi
0x0047a86a:	pushl %ebp
0x0047a86b:	movl %ebp, %esp
0x0047a86d:	subl %esp, $0xc<UINT8>
0x0047a870:	movl %eax, 0x8(%ebp)
0x0047a873:	leal %ecx, -1(%ebp)
0x0047a876:	movl -8(%ebp), %eax
0x0047a879:	movl -12(%ebp), %eax
0x0047a87c:	leal %eax, -8(%ebp)
0x0047a87f:	pushl %eax
0x0047a880:	pushl 0xc(%ebp)
0x0047a883:	leal %eax, -12(%ebp)
0x0047a886:	pushl %eax
0x0047a887:	call 0x0047a7a8
0x0047a7a8:	pushl $0x8<UINT8>
0x0047a7aa:	pushl $0x4c7808<UINT32>
0x0047a7af:	call 0x00421d80
0x0047a7b4:	movl %eax, 0x8(%ebp)
0x0047a7b7:	pushl (%eax)
0x0047a7b9:	call 0x00474af4
0x00474af4:	movl %edi, %edi
0x00474af6:	pushl %ebp
0x00474af7:	movl %ebp, %esp
0x00474af9:	imull %eax, 0x8(%ebp), $0x18<UINT8>
0x00474afd:	addl %eax, $0x4e3760<UINT32>
0x00474b02:	pushl %eax
0x00474b03:	call EnterCriticalSection@KERNEL32.DLL
EnterCriticalSection@KERNEL32.DLL: API Node	
0x00474b09:	popl %ebp
0x00474b0a:	ret

0x0047a7be:	popl %ecx
0x0047a7bf:	andl -4(%ebp), $0x0<UINT8>
0x0047a7c3:	movl %eax, 0xc(%ebp)
0x0047a7c6:	movl %eax, (%eax)
0x0047a7c8:	movl %eax, (%eax)
0x0047a7ca:	movl %eax, 0x48(%eax)
0x0047a7cd:	incl (%eax)
0x0047a7d0:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0047a7d7:	call 0x0047a7e4
0x0047a7e4:	movl %eax, 0x10(%ebp)
0x0047a7e7:	pushl (%eax)
0x0047a7e9:	call 0x00474b3c
0x00474b3c:	movl %edi, %edi
0x00474b3e:	pushl %ebp
0x00474b3f:	movl %ebp, %esp
0x00474b41:	imull %eax, 0x8(%ebp), $0x18<UINT8>
0x00474b45:	addl %eax, $0x4e3760<UINT32>
0x00474b4a:	pushl %eax
0x00474b4b:	call LeaveCriticalSection@KERNEL32.DLL
LeaveCriticalSection@KERNEL32.DLL: API Node	
0x00474b51:	popl %ebp
0x00474b52:	ret

0x0047a7ee:	popl %ecx
0x0047a7ef:	ret

0x0047a7dc:	call 0x00421dc6
0x00421dc6:	movl %ecx, -16(%ebp)
0x00421dc9:	movl %fs:0, %ecx
0x00421dd0:	popl %ecx
0x00421dd1:	popl %edi
0x00421dd2:	popl %edi
0x00421dd3:	popl %esi
0x00421dd4:	popl %ebx
0x00421dd5:	movl %esp, %ebp
0x00421dd7:	popl %ebp
0x00421dd8:	pushl %ecx
0x00421dd9:	repn ret

0x0047a7e1:	ret $0xc<UINT16>

0x0047a88c:	movl %esp, %ebp
0x0047a88e:	popl %ebp
0x0047a88f:	ret

0x0047aa9d:	leal %eax, 0x8(%ebp)
0x0047aaa0:	movl -8(%ebp), %eax
0x0047aaa3:	leal %eax, 0xc(%ebp)
0x0047aaa6:	movl -4(%ebp), %eax
0x0047aaa9:	leal %eax, -8(%ebp)
0x0047aaac:	pushl %eax
0x0047aaad:	pushl $0x4<UINT8>
0x0047aaaf:	call 0x0047a818
0x0047a818:	movl %edi, %edi
0x0047a81a:	pushl %ebp
0x0047a81b:	movl %ebp, %esp
0x0047a81d:	subl %esp, $0xc<UINT8>
0x0047a820:	movl %eax, 0x8(%ebp)
0x0047a823:	leal %ecx, -1(%ebp)
0x0047a826:	movl -8(%ebp), %eax
0x0047a829:	movl -12(%ebp), %eax
0x0047a82c:	leal %eax, -8(%ebp)
0x0047a82f:	pushl %eax
0x0047a830:	pushl 0xc(%ebp)
0x0047a833:	leal %eax, -12(%ebp)
0x0047a836:	pushl %eax
0x0047a837:	call 0x0047a6ac
0x0047a6ac:	pushl $0x8<UINT8>
0x0047a6ae:	pushl $0x4c7828<UINT32>
0x0047a6b3:	call 0x00421d80
0x0047a6b8:	movl %eax, 0x8(%ebp)
0x0047a6bb:	pushl (%eax)
0x0047a6bd:	call 0x00474af4
0x0047a6c2:	popl %ecx
0x0047a6c3:	andl -4(%ebp), $0x0<UINT8>
0x0047a6c7:	movl %ecx, 0xc(%ebp)
0x0047a6ca:	movl %eax, 0x4(%ecx)
0x0047a6cd:	movl %eax, (%eax)
0x0047a6cf:	pushl (%eax)
0x0047a6d1:	movl %eax, (%ecx)
0x0047a6d3:	pushl (%eax)
0x0047a6d5:	call 0x0047ac9d
0x0047ac9d:	movl %edi, %edi
0x0047ac9f:	pushl %ebp
0x0047aca0:	movl %ebp, %esp
0x0047aca2:	pushl %esi
0x0047aca3:	movl %esi, 0x8(%ebp)
0x0047aca6:	cmpl 0x4c(%esi), $0x0<UINT8>
0x0047acaa:	je 0x0047acd4
0x0047acd4:	movl %eax, 0xc(%ebp)
0x0047acd7:	movl 0x4c(%esi), %eax
0x0047acda:	popl %esi
0x0047acdb:	testl %eax, %eax
0x0047acdd:	je 7
0x0047acdf:	pushl %eax
0x0047ace0:	call 0x00486f7d
0x00486f7d:	movl %edi, %edi
0x00486f7f:	pushl %ebp
0x00486f80:	movl %ebp, %esp
0x00486f82:	movl %eax, 0x8(%ebp)
0x00486f85:	incl 0xc(%eax)
0x00486f89:	movl %ecx, 0x7c(%eax)
0x00486f8c:	testl %ecx, %ecx
0x00486f8e:	je 0x00486f93
0x00486f93:	movl %ecx, 0x84(%eax)
0x00486f99:	testl %ecx, %ecx
0x00486f9b:	je 0x00486fa0
0x00486fa0:	movl %ecx, 0x80(%eax)
0x00486fa6:	testl %ecx, %ecx
0x00486fa8:	je 0x00486fad
0x00486fad:	movl %ecx, 0x8c(%eax)
0x00486fb3:	testl %ecx, %ecx
0x00486fb5:	je 0x00486fba
0x00486fba:	pushl %esi
0x00486fbb:	pushl $0x6<UINT8>
0x00486fbd:	leal %ecx, 0x28(%eax)
0x00486fc0:	popl %esi
0x00486fc1:	cmpl -8(%ecx), $0x4d01b8<UINT32>
0x00486fc8:	je 0x00486fd3
0x00486fca:	movl %edx, (%ecx)
0x00486fcc:	testl %edx, %edx
0x00486fce:	je 0x00486fd3
0x00486fd3:	cmpl -12(%ecx), $0x0<UINT8>
0x00486fd7:	je 0x00486fe3
0x00486fe3:	addl %ecx, $0x10<UINT8>
0x00486fe6:	subl %esi, $0x1<UINT8>
0x00486fe9:	jne 0x00486fc1
0x00486feb:	pushl 0x9c(%eax)
0x00486ff1:	call 0x00487144
0x00487144:	movl %edi, %edi
0x00487146:	pushl %ebp
0x00487147:	movl %ebp, %esp
0x00487149:	movl %ecx, 0x8(%ebp)
0x0048714c:	testl %ecx, %ecx
0x0048714e:	je 22
0x00487150:	cmpl %ecx, $0x4b88a8<UINT32>
0x00487156:	je 0x00487166
0x00487166:	movl %eax, $0x7fffffff<UINT32>
0x0048716b:	popl %ebp
0x0048716c:	ret

0x00486ff6:	popl %ecx
0x00486ff7:	popl %esi
0x00486ff8:	popl %ebp
0x00486ff9:	ret

0x0047ace5:	popl %ecx
0x0047ace6:	popl %ebp
0x0047ace7:	ret

0x0047a6da:	popl %ecx
0x0047a6db:	popl %ecx
0x0047a6dc:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0047a6e3:	call 0x0047a6f0
0x0047a6f0:	movl %eax, 0x10(%ebp)
0x0047a6f3:	pushl (%eax)
0x0047a6f5:	call 0x00474b3c
0x0047a6fa:	popl %ecx
0x0047a6fb:	ret

0x0047a6e8:	call 0x00421dc6
0x0047a6ed:	ret $0xc<UINT16>

0x0047a83c:	movl %esp, %ebp
0x0047a83e:	popl %ebp
0x0047a83f:	ret

0x0047aab4:	addl %esp, $0x10<UINT8>
0x0047aab7:	movl %esp, %ebp
0x0047aab9:	popl %ebp
0x0047aaba:	ret

0x0047ae0c:	pushl %ebx
0x0047ae0d:	call 0x00475680
0x00475680:	movl %edi, %edi
0x00475682:	pushl %ebp
0x00475683:	movl %ebp, %esp
0x00475685:	cmpl 0x8(%ebp), $0x0<UINT8>
0x00475689:	je 0x004756b8
0x004756b8:	popl %ebp
0x004756b9:	ret

0x0047ae12:	addl %esp, $0xc<UINT8>
0x0047ae15:	testl %edi, %edi
0x0047ae17:	jne 0x0047ae22
0x0047ae22:	pushl %esi
0x0047ae23:	call SetLastError@KERNEL32.DLL
SetLastError@KERNEL32.DLL: API Node	
0x0047ae29:	movl %ebx, %edi
0x0047ae2b:	popl %edi
0x0047ae2c:	popl %esi
0x0047ae2d:	movl %eax, %ebx
0x0047ae2f:	popl %ebx
0x0047ae30:	ret

0x0047ae4d:	testl %eax, %eax
0x0047ae4f:	jne 0x0047ae5a
0x0047ae5a:	movb %al, $0x1<UINT8>
0x0047ae5c:	ret

0x0047c7e0:	pushl $0xc<UINT8>
0x0047c7e2:	pushl $0x4c78a8<UINT32>
0x0047c7e7:	call 0x00421d80
0x0047c7ec:	pushl $0x7<UINT8>
0x0047c7ee:	call 0x00474af4
0x0047c7f3:	popl %ecx
0x0047c7f4:	xorl %ebx, %ebx
0x0047c7f6:	movb -25(%ebp), %bl
0x0047c7f9:	movl -4(%ebp), %ebx
0x0047c7fc:	pushl %ebx
0x0047c7fd:	call 0x00481717
0x00481717:	pushl $0x14<UINT8>
0x00481719:	pushl $0x4c7a88<UINT32>
0x0048171e:	call 0x00421d80
0x00481723:	cmpl 0x8(%ebp), $0x2000<UINT32>
0x0048172a:	sbbl %eax, %eax
0x0048172c:	negl %eax
0x0048172e:	jne 0x00481747
0x00481747:	xorl %esi, %esi
0x00481749:	movl -28(%ebp), %esi
0x0048174c:	pushl $0x7<UINT8>
0x0048174e:	call 0x00474af4
0x00481753:	popl %ecx
0x00481754:	movl -4(%ebp), %esi
0x00481757:	movl %edi, %esi
0x00481759:	movl %eax, 0x4e3ab0
0x0048175e:	movl -32(%ebp), %edi
0x00481761:	cmpl 0x8(%ebp), %eax
0x00481764:	jl 0x00481785
0x00481766:	cmpl 0x4e38b0(,%edi,4), %esi
0x0048176d:	jne 49
0x0048176f:	call 0x00481668
0x00481668:	movl %edi, %edi
0x0048166a:	pushl %ebp
0x0048166b:	movl %ebp, %esp
0x0048166d:	pushl %ecx
0x0048166e:	pushl %ecx
0x0048166f:	pushl %ebx
0x00481670:	pushl %edi
0x00481671:	pushl $0x30<UINT8>
0x00481673:	pushl $0x40<UINT8>
0x00481675:	call 0x00474b65
0x0048167a:	movl %edi, %eax
0x0048167c:	xorl %ebx, %ebx
0x0048167e:	movl -8(%ebp), %edi
0x00481681:	popl %ecx
0x00481682:	popl %ecx
0x00481683:	testl %edi, %edi
0x00481685:	jne 0x0048168b
0x0048168b:	leal %eax, 0xc00(%edi)
0x00481691:	cmpl %edi, %eax
0x00481693:	je 62
0x00481695:	pushl %esi
0x00481696:	leal %esi, 0x20(%edi)
0x00481699:	movl %edi, %eax
0x0048169b:	pushl %ebx
0x0048169c:	pushl $0xfa0<UINT32>
0x004816a1:	leal %eax, -32(%esi)
0x004816a4:	pushl %eax
0x004816a5:	call 0x0047d4fe
0x004816aa:	orl -8(%esi), $0xffffffff<UINT8>
0x004816ae:	movl (%esi), %ebx
0x004816b0:	leal %esi, 0x30(%esi)
0x004816b3:	movl -44(%esi), %ebx
0x004816b6:	leal %eax, -32(%esi)
0x004816b9:	movl -40(%esi), $0xa0a0000<UINT32>
0x004816c0:	movb -36(%esi), $0xa<UINT8>
0x004816c4:	andb -35(%esi), $0xfffffff8<UINT8>
0x004816c8:	movb -34(%esi), %bl
0x004816cb:	cmpl %eax, %edi
0x004816cd:	jne 0x0048169b
0x004816cf:	movl %edi, -8(%ebp)
0x004816d2:	popl %esi
0x004816d3:	pushl %ebx
0x004816d4:	call 0x00475680
0x004816d9:	popl %ecx
0x004816da:	movl %eax, %edi
0x004816dc:	popl %edi
0x004816dd:	popl %ebx
0x004816de:	movl %esp, %ebp
0x004816e0:	popl %ebp
0x004816e1:	ret

0x00481774:	movl 0x4e38b0(,%edi,4), %eax
0x0048177b:	testl %eax, %eax
0x0048177d:	jne 0x00481793
0x00481793:	movl %eax, 0x4e3ab0
0x00481798:	addl %eax, $0x40<UINT8>
0x0048179b:	movl 0x4e3ab0, %eax
0x004817a0:	incl %edi
0x004817a1:	jmp 0x0048175e
0x00481785:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0048178c:	call 0x004817a6
0x004817a6:	pushl $0x7<UINT8>
0x004817a8:	call 0x00474b3c
0x004817ad:	popl %ecx
0x004817ae:	ret

0x00481791:	jmp 0x0048173f
0x0048173f:	movl %eax, %esi
0x00481741:	call 0x00421dc6
0x00481746:	ret

0x0047c802:	popl %ecx
0x0047c803:	testl %eax, %eax
0x0047c805:	jne 15
0x0047c807:	call 0x0047c674
0x0047c674:	movl %edi, %edi
0x0047c676:	pushl %ebp
0x0047c677:	movl %ebp, %esp
0x0047c679:	subl %esp, $0x48<UINT8>
0x0047c67c:	leal %eax, -72(%ebp)
0x0047c67f:	pushl %eax
0x0047c680:	call GetStartupInfoW@KERNEL32.DLL
GetStartupInfoW@KERNEL32.DLL: API Node	
0x0047c686:	cmpw -22(%ebp), $0x0<UINT8>
0x0047c68b:	je 0x0047c726
0x0047c726:	movl %esp, %ebp
0x0047c728:	popl %ebp
0x0047c729:	ret

0x0047c80c:	call 0x0047c72a
0x0047c72a:	movl %edi, %edi
0x0047c72c:	pushl %ebx
0x0047c72d:	pushl %esi
0x0047c72e:	pushl %edi
0x0047c72f:	xorl %edi, %edi
0x0047c731:	movl %eax, %edi
0x0047c733:	movl %ecx, %edi
0x0047c735:	andl %eax, $0x3f<UINT8>
0x0047c738:	sarl %ecx, $0x6<UINT8>
0x0047c73b:	imull %esi, %eax, $0x30<UINT8>
0x0047c73e:	addl %esi, 0x4e38b0(,%ecx,4)
0x0047c745:	cmpl 0x18(%esi), $0xffffffff<UINT8>
0x0047c749:	je 0x0047c757
0x0047c757:	movl %eax, %edi
0x0047c759:	movb 0x28(%esi), $0xffffff81<UINT8>
0x0047c75d:	subl %eax, $0x0<UINT8>
0x0047c760:	je 0x0047c772
0x0047c772:	pushl $0xfffffff6<UINT8>
0x0047c774:	popl %eax
0x0047c775:	pushl %eax
0x0047c776:	call GetStdHandle@KERNEL32.DLL
GetStdHandle@KERNEL32.DLL: API Node	
0x0047c77c:	movl %ebx, %eax
0x0047c77e:	cmpl %ebx, $0xffffffff<UINT8>
0x0047c781:	je 13
0x0047c783:	testl %ebx, %ebx
0x0047c785:	je 9
0x0047c787:	pushl %ebx
0x0047c788:	call GetFileType@KERNEL32.DLL
GetFileType@KERNEL32.DLL: API Node	
0x0047c78e:	jmp 0x0047c792
0x0047c792:	testl %eax, %eax
0x0047c794:	je 30
0x0047c796:	andl %eax, $0xff<UINT32>
0x0047c79b:	movl 0x18(%esi), %ebx
0x0047c79e:	cmpl %eax, $0x2<UINT8>
0x0047c7a1:	jne 6
0x0047c7a3:	orb 0x28(%esi), $0x40<UINT8>
0x0047c7a7:	jmp 0x0047c7d2
0x0047c7d2:	incl %edi
0x0047c7d3:	cmpl %edi, $0x3<UINT8>
0x0047c7d6:	jne 0x0047c731
0x0047c762:	subl %eax, $0x1<UINT8>
0x0047c765:	je 0x0047c76e
0x0047c76e:	pushl $0xfffffff5<UINT8>
0x0047c770:	jmp 0x0047c774
0x0047c767:	pushl $0xfffffff4<UINT8>
0x0047c769:	subl %eax, $0x1<UINT8>
0x0047c76c:	jmp 0x0047c774
0x0047c7dc:	popl %edi
0x0047c7dd:	popl %esi
0x0047c7de:	popl %ebx
0x0047c7df:	ret

0x0047c811:	movb %bl, $0x1<UINT8>
0x0047c813:	movb -25(%ebp), %bl
0x0047c816:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0047c81d:	call 0x0047c82d
0x0047c82d:	pushl $0x7<UINT8>
0x0047c82f:	call 0x00474b3c
0x0047c834:	popl %ecx
0x0047c835:	ret

0x0047c822:	movb %al, %bl
0x0047c824:	call 0x00421dc6
0x0047c829:	ret

0x00484a47:	call GetCommandLineA@KERNEL32.DLL
GetCommandLineA@KERNEL32.DLL: API Node	
0x00484a4d:	movl 0x4e3bc4, %eax
0x00484a52:	call GetCommandLineW@KERNEL32.DLL
GetCommandLineW@KERNEL32.DLL: API Node	
0x00484a58:	movl 0x4e3bc8, %eax
0x00484a5d:	movb %al, $0x1<UINT8>
0x00484a5f:	ret

0x004846c0:	cmpb 0x4e3bb4, $0x0<UINT8>
0x004846c7:	jne 0x004846db
0x004846c9:	pushl $0x1<UINT8>
0x004846cb:	pushl $0xfffffffd<UINT8>
0x004846cd:	call 0x004845bf
0x004845bf:	movl %edi, %edi
0x004845c1:	pushl %ebp
0x004845c2:	movl %ebp, %esp
0x004845c4:	subl %esp, $0xc<UINT8>
0x004845c7:	call 0x0047ad28
0x0047ad28:	movl %edi, %edi
0x0047ad2a:	pushl %esi
0x0047ad2b:	pushl %edi
0x0047ad2c:	call GetLastError@KERNEL32.DLL
0x0047ad32:	movl %esi, %eax
0x0047ad34:	movl %eax, 0x4d00f0
0x0047ad39:	cmpl %eax, $0xffffffff<UINT8>
0x0047ad3c:	je 12
0x0047ad3e:	pushl %eax
0x0047ad3f:	call 0x0047d12d
0x0047ad44:	movl %edi, %eax
0x0047ad46:	testl %edi, %edi
0x0047ad48:	jne 0x0047ad93
0x0047ad93:	pushl %esi
0x0047ad94:	call SetLastError@KERNEL32.DLL
0x0047ad9a:	movl %eax, %edi
0x0047ad9c:	popl %edi
0x0047ad9d:	popl %esi
0x0047ad9e:	ret

0x004845cc:	movl -4(%ebp), %eax
0x004845cf:	call 0x004846de
0x004846de:	pushl $0xc<UINT8>
0x004846e0:	pushl $0x4c7bd0<UINT32>
0x004846e5:	call 0x00421d80
0x004846ea:	xorl %esi, %esi
0x004846ec:	movl -28(%ebp), %esi
0x004846ef:	call 0x0047ad28
0x004846f4:	movl %edi, %eax
0x004846f6:	movl %ecx, 0x4d081c
0x004846fc:	testl 0x350(%edi), %ecx
0x00484702:	je 0x00484715
0x00484715:	pushl $0x5<UINT8>
0x00484717:	call 0x00474af4
0x0048471c:	popl %ecx
0x0048471d:	movl -4(%ebp), %esi
0x00484720:	movl %esi, 0x48(%edi)
0x00484723:	movl -28(%ebp), %esi
0x00484726:	cmpl %esi, 0x4d0818
0x0048472c:	je 0x0048475e
0x0048475e:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00484765:	call 0x0048476f
0x0048476f:	pushl $0x5<UINT8>
0x00484771:	call 0x00474b3c
0x00484776:	popl %ecx
0x00484777:	ret

0x0048476a:	jmp 0x0048470c
0x0048470c:	testl %esi, %esi
0x0048470e:	jne 0x00484778
0x00484778:	movl %eax, %esi
0x0048477a:	call 0x00421dc6
0x0048477f:	ret

0x004845d4:	pushl 0x8(%ebp)
0x004845d7:	call 0x00484353
0x00484353:	movl %edi, %edi
0x00484355:	pushl %ebp
0x00484356:	movl %ebp, %esp
0x00484358:	subl %esp, $0x10<UINT8>
0x0048435b:	leal %ecx, -16(%ebp)
0x0048435e:	pushl $0x0<UINT8>
0x00484360:	call 0x0044a7e7
0x0044a7e7:	movl %edi, %edi
0x0044a7e9:	pushl %ebp
0x0044a7ea:	movl %ebp, %esp
0x0044a7ec:	pushl %edi
0x0044a7ed:	movl %edi, %ecx
0x0044a7ef:	movl %ecx, 0x8(%ebp)
0x0044a7f2:	movb 0xc(%edi), $0x0<UINT8>
0x0044a7f6:	testl %ecx, %ecx
0x0044a7f8:	je 0x0044a804
0x0044a804:	movl %eax, 0x4e3754
0x0044a809:	testl %eax, %eax
0x0044a80b:	jne 18
0x0044a80d:	movl %eax, 0x4d01b0
0x0044a812:	movl 0x4(%edi), %eax
0x0044a815:	movl %eax, 0x4d01b4
0x0044a81a:	movl 0x8(%edi), %eax
0x0044a81d:	jmp 0x0044a863
0x0044a863:	movl %eax, %edi
0x0044a865:	popl %edi
0x0044a866:	popl %ebp
0x0044a867:	ret $0x4<UINT16>

0x00484365:	andl 0x4e3bb0, $0x0<UINT8>
0x0048436c:	movl %eax, 0x8(%ebp)
0x0048436f:	cmpl %eax, $0xfffffffe<UINT8>
0x00484372:	jne 0x00484386
0x00484386:	cmpl %eax, $0xfffffffd<UINT8>
0x00484389:	jne 0x0048439d
0x0048438b:	movl 0x4e3bb0, $0x1<UINT32>
0x00484395:	call GetACP@KERNEL32.DLL
GetACP@KERNEL32.DLL: API Node	
0x0048439b:	jmp 0x004843b2
0x004843b2:	cmpb -4(%ebp), $0x0<UINT8>
0x004843b6:	je 0x004843c2
0x004843c2:	movl %esp, %ebp
0x004843c4:	popl %ebp
0x004843c5:	ret

0x004845dc:	popl %ecx
0x004845dd:	movl %ecx, -4(%ebp)
0x004845e0:	movl -12(%ebp), %eax
0x004845e3:	movl %ecx, 0x48(%ecx)
0x004845e6:	cmpl %eax, 0x4(%ecx)
0x004845e9:	jne 0x004845ef
0x004845ef:	pushl %ebx
0x004845f0:	pushl %esi
0x004845f1:	pushl %edi
0x004845f2:	pushl $0x220<UINT32>
0x004845f7:	call 0x004756ba
0x004756ba:	movl %edi, %edi
0x004756bc:	pushl %ebp
0x004756bd:	movl %ebp, %esp
0x004756bf:	pushl %esi
0x004756c0:	movl %esi, 0x8(%ebp)
0x004756c3:	cmpl %esi, $0xffffffe0<UINT8>
0x004756c6:	ja 48
0x004756c8:	testl %esi, %esi
0x004756ca:	jne 0x004756e3
0x004756e3:	pushl %esi
0x004756e4:	pushl $0x0<UINT8>
0x004756e6:	pushl 0x4e3bd4
0x004756ec:	call HeapAlloc@KERNEL32.DLL
0x004756f2:	testl %eax, %eax
0x004756f4:	je -39
0x004756f6:	jmp 0x00475705
0x00475705:	popl %esi
0x00475706:	popl %ebp
0x00475707:	ret

0x004845fc:	movl %edi, %eax
0x004845fe:	orl %ebx, $0xffffffff<UINT8>
0x00484601:	popl %ecx
0x00484602:	testl %edi, %edi
0x00484604:	je 46
0x00484606:	movl %esi, -4(%ebp)
0x00484609:	movl %ecx, $0x88<UINT32>
0x0048460e:	movl %esi, 0x48(%esi)
0x00484611:	rep movsl %es:(%edi), %ds:(%esi)
0x00484613:	movl %edi, %eax
0x00484615:	pushl %edi
0x00484616:	pushl -12(%ebp)
0x00484619:	andl (%edi), $0x0<UINT8>
0x0048461c:	call 0x004847d5
0x004847d5:	movl %edi, %edi
0x004847d7:	pushl %ebp
0x004847d8:	movl %ebp, %esp
0x004847da:	subl %esp, $0x20<UINT8>
0x004847dd:	movl %eax, 0x4cff1c
0x004847e2:	xorl %eax, %ebp
0x004847e4:	movl -4(%ebp), %eax
0x004847e7:	pushl %ebx
0x004847e8:	pushl %esi
0x004847e9:	pushl 0x8(%ebp)
0x004847ec:	movl %esi, 0xc(%ebp)
0x004847ef:	call 0x00484353
0x0048439d:	cmpl %eax, $0xfffffffc<UINT8>
0x004843a0:	jne 0x004843b2
0x004847f4:	movl %ebx, %eax
0x004847f6:	popl %ecx
0x004847f7:	testl %ebx, %ebx
0x004847f9:	jne 0x00484809
0x00484809:	pushl %edi
0x0048480a:	xorl %edi, %edi
0x0048480c:	movl %ecx, %edi
0x0048480e:	movl %eax, %edi
0x00484810:	movl -28(%ebp), %ecx
0x00484813:	cmpl 0x4d0300(%eax), %ebx
0x00484819:	je 234
0x0048481f:	incl %ecx
0x00484820:	addl %eax, $0x30<UINT8>
0x00484823:	movl -28(%ebp), %ecx
0x00484826:	cmpl %eax, $0xf0<UINT32>
0x0048482b:	jb 0x00484813
0x0048482d:	cmpl %ebx, $0xfde8<UINT32>
0x00484833:	je 200
0x00484839:	cmpl %ebx, $0xfde9<UINT32>
0x0048483f:	je 188
0x00484845:	movzwl %eax, %bx
0x00484848:	pushl %eax
0x00484849:	call IsValidCodePage@KERNEL32.DLL
IsValidCodePage@KERNEL32.DLL: API Node	
0x0048484f:	testl %eax, %eax
0x00484851:	je 170
0x00484857:	leal %eax, -24(%ebp)
0x0048485a:	pushl %eax
0x0048485b:	pushl %ebx
0x0048485c:	call GetCPInfo@KERNEL32.DLL
GetCPInfo@KERNEL32.DLL: API Node	
0x00484862:	testl %eax, %eax
0x00484864:	je 132
0x0048486a:	pushl $0x101<UINT32>
0x0048486f:	leal %eax, 0x18(%esi)
0x00484872:	pushl %edi
0x00484873:	pushl %eax
0x00484874:	call 0x0043e1b0
0x0043e1b0:	movl %ecx, 0xc(%esp)
0x0043e1b4:	movzbl %eax, 0x8(%esp)
0x0043e1b9:	movl %edx, %edi
0x0043e1bb:	movl %edi, 0x4(%esp)
0x0043e1bf:	testl %ecx, %ecx
0x0043e1c1:	je 316
0x0043e1c7:	imull %eax, %eax, $0x1010101<UINT32>
0x0043e1cd:	cmpl %ecx, $0x20<UINT8>
0x0043e1d0:	jle 223
0x0043e1d6:	cmpl %ecx, $0x80<UINT32>
0x0043e1dc:	jl 139
0x0043e1e2:	btl 0x4e298c, $0x1<UINT8>
0x0043e1ea:	jae 0x0043e1f5
0x0043e1f5:	btl 0x4cff2c, $0x1<UINT8>
0x0043e1fd:	jae 178
0x0043e203:	movd %xmm0, %eax
0x0043e207:	pshufd %xmm0, %xmm0, $0x0<UINT8>
0x0043e20c:	addl %ecx, %edi
0x0043e20e:	movups (%edi), %xmm0
0x0043e211:	addl %edi, $0x10<UINT8>
0x0043e214:	andl %edi, $0xfffffff0<UINT8>
0x0043e217:	subl %ecx, %edi
0x0043e219:	cmpl %ecx, $0x80<UINT32>
0x0043e21f:	jle 0x0043e26d
0x0043e221:	leal %esp, (%esp)
0x0043e228:	leal %esp, (%esp)
0x0043e22f:	nop
0x0043e230:	movdqa (%edi), %xmm0
0x0043e234:	movdqa 0x10(%edi), %xmm0
0x0043e239:	movdqa 0x20(%edi), %xmm0
0x0043e23e:	movdqa 0x30(%edi), %xmm0
0x0043e243:	movdqa 0x40(%edi), %xmm0
0x0043e248:	movdqa 0x50(%edi), %xmm0
0x0043e24d:	movdqa 0x60(%edi), %xmm0
0x0043e252:	movdqa 0x70(%edi), %xmm0
0x0043e257:	leal %edi, 0x80(%edi)
0x0043e25d:	subl %ecx, $0x80<UINT32>
0x0043e263:	testl %ecx, $0xffffff00<UINT32>
0x0043e269:	jne 0x0043e230
0x0043e26b:	jmp 0x0043e280
0x0043e280:	cmpl %ecx, $0x20<UINT8>
0x0043e283:	jb 28
0x0043e285:	movdqu (%edi), %xmm0
0x0043e289:	movdqu 0x10(%edi), %xmm0
0x0043e28e:	addl %edi, $0x20<UINT8>
0x0043e291:	subl %ecx, $0x20<UINT8>
0x0043e294:	cmpl %ecx, $0x20<UINT8>
0x0043e297:	jae 0x0043e285
0x0043e299:	testl %ecx, $0x1f<UINT32>
0x0043e29f:	je 98
0x0043e2a1:	leal %edi, -32(%ecx,%edi)
0x0043e2a5:	movdqu (%edi), %xmm0
0x0043e2a9:	movdqu 0x10(%edi), %xmm0
0x0043e2ae:	movl %eax, 0x4(%esp)
0x0043e2b2:	movl %edi, %edx
0x0043e2b4:	ret

0x00484879:	movl 0x4(%esi), %ebx
0x0048487c:	addl %esp, $0xc<UINT8>
0x0048487f:	xorl %ebx, %ebx
0x00484881:	movl 0x21c(%esi), %edi
0x00484887:	incl %ebx
0x00484888:	cmpl -24(%ebp), %ebx
0x0048488b:	jbe 81
0x0048488d:	cmpb -18(%ebp), $0x0<UINT8>
0x00484891:	leal %eax, -18(%ebp)
0x00484894:	je 0x004848b7
0x004848b7:	leal %eax, 0x1a(%esi)
0x004848ba:	movl %ecx, $0xfe<UINT32>
0x004848bf:	orb (%eax), $0x8<UINT8>
0x004848c2:	incl %eax
0x004848c3:	subl %ecx, $0x1<UINT8>
0x004848c6:	jne 0x004848bf
0x004848c8:	pushl 0x4(%esi)
0x004848cb:	call 0x00484315
0x00484315:	movl %edi, %edi
0x00484317:	pushl %ebp
0x00484318:	movl %ebp, %esp
0x0048431a:	movl %eax, 0x8(%ebp)
0x0048431d:	subl %eax, $0x3a4<UINT32>
0x00484322:	je 40
0x00484324:	subl %eax, $0x4<UINT8>
0x00484327:	je 28
0x00484329:	subl %eax, $0xd<UINT8>
0x0048432c:	je 16
0x0048432e:	subl %eax, $0x1<UINT8>
0x00484331:	je 4
0x00484333:	xorl %eax, %eax
0x00484335:	popl %ebp
0x00484336:	ret

0x004848d0:	addl %esp, $0x4<UINT8>
0x004848d3:	movl 0x21c(%esi), %eax
0x004848d9:	movl 0x8(%esi), %ebx
0x004848dc:	jmp 0x004848e1
0x004848e1:	xorl %eax, %eax
0x004848e3:	leal %edi, 0xc(%esi)
0x004848e6:	stosl %es:(%edi), %eax
0x004848e7:	stosl %es:(%edi), %eax
0x004848e8:	stosl %es:(%edi), %eax
0x004848e9:	jmp 0x004849ac
0x004849ac:	pushl %esi
0x004849ad:	call 0x0048442b
0x0048442b:	movl %edi, %edi
0x0048442d:	pushl %ebp
0x0048442e:	movl %ebp, %esp
0x00484430:	subl %esp, $0x720<UINT32>
0x00484436:	movl %eax, 0x4cff1c
0x0048443b:	xorl %eax, %ebp
0x0048443d:	movl -4(%ebp), %eax
0x00484440:	pushl %ebx
0x00484441:	pushl %esi
0x00484442:	movl %esi, 0x8(%ebp)
0x00484445:	leal %eax, -1816(%ebp)
0x0048444b:	pushl %edi
0x0048444c:	pushl %eax
0x0048444d:	pushl 0x4(%esi)
0x00484450:	call GetCPInfo@KERNEL32.DLL
0x00484456:	xorl %ebx, %ebx
0x00484458:	movl %edi, $0x100<UINT32>
0x0048445d:	testl %eax, %eax
0x0048445f:	je 240
0x00484465:	movl %eax, %ebx
0x00484467:	movb -260(%ebp,%eax), %al
0x0048446e:	incl %eax
0x0048446f:	cmpl %eax, %edi
0x00484471:	jb 0x00484467
0x00484473:	movb %al, -1810(%ebp)
0x00484479:	leal %ecx, -1810(%ebp)
0x0048447f:	movb -260(%ebp), $0x20<UINT8>
0x00484486:	jmp 0x004844a7
0x004844a7:	testb %al, %al
0x004844a9:	jne -35
0x004844ab:	pushl %ebx
0x004844ac:	pushl 0x4(%esi)
0x004844af:	leal %eax, -1796(%ebp)
0x004844b5:	pushl %eax
0x004844b6:	pushl %edi
0x004844b7:	leal %eax, -260(%ebp)
0x004844bd:	pushl %eax
0x004844be:	pushl $0x1<UINT8>
0x004844c0:	pushl %ebx
0x004844c1:	call 0x00486e60
0x00486e60:	movl %edi, %edi
0x00486e62:	pushl %ebp
0x00486e63:	movl %ebp, %esp
0x00486e65:	subl %esp, $0x18<UINT8>
0x00486e68:	movl %eax, 0x4cff1c
0x00486e6d:	xorl %eax, %ebp
0x00486e6f:	movl -4(%ebp), %eax
0x00486e72:	pushl %ebx
0x00486e73:	pushl %esi
0x00486e74:	pushl %edi
0x00486e75:	pushl 0x8(%ebp)
0x00486e78:	leal %ecx, -24(%ebp)
0x00486e7b:	call 0x0044a7e7
0x00486e80:	movl %ecx, 0x1c(%ebp)
0x00486e83:	testl %ecx, %ecx
0x00486e85:	jne 0x00486e92
0x00486e92:	xorl %eax, %eax
0x00486e94:	xorl %edi, %edi
0x00486e96:	cmpl 0x20(%ebp), %eax
0x00486e99:	pushl %edi
0x00486e9a:	pushl %edi
0x00486e9b:	pushl 0x14(%ebp)
0x00486e9e:	setne %al
0x00486ea1:	pushl 0x10(%ebp)
0x00486ea4:	leal %eax, 0x1(,%eax,8)
0x00486eab:	pushl %eax
0x00486eac:	pushl %ecx
0x00486ead:	call MultiByteToWideChar@KERNEL32.DLL
MultiByteToWideChar@KERNEL32.DLL: API Node	
0x00486eb3:	movl -8(%ebp), %eax
0x00486eb6:	testl %eax, %eax
0x00486eb8:	je 153
0x00486ebe:	leal %ebx, (%eax,%eax)
0x00486ec1:	leal %ecx, 0x8(%ebx)
0x00486ec4:	cmpl %ebx, %ecx
0x00486ec6:	sbbl %eax, %eax
0x00486ec8:	testl %ecx, %eax
0x00486eca:	je 74
0x00486ecc:	leal %ecx, 0x8(%ebx)
0x00486ecf:	cmpl %ebx, %ecx
0x00486ed1:	sbbl %eax, %eax
0x00486ed3:	andl %eax, %ecx
0x00486ed5:	leal %ecx, 0x8(%ebx)
0x00486ed8:	cmpl %eax, $0x400<UINT32>
0x00486edd:	ja 25
0x00486edf:	cmpl %ebx, %ecx
0x00486ee1:	sbbl %eax, %eax
0x00486ee3:	andl %eax, %ecx
0x00486ee5:	call 0x00497c10
0x00497c10:	pushl %ecx
0x00497c11:	leal %ecx, 0x8(%esp)
0x00497c15:	subl %ecx, %eax
0x00497c17:	andl %ecx, $0xf<UINT8>
0x00497c1a:	addl %eax, %ecx
0x00497c1c:	sbbl %ecx, %ecx
0x00497c1e:	orl %eax, %ecx
0x00497c20:	popl %ecx
0x00497c21:	jmp 0x00420c50
0x00420c50:	pushl %ecx
0x00420c51:	leal %ecx, 0x4(%esp)
0x00420c55:	subl %ecx, %eax
0x00420c57:	sbbl %eax, %eax
0x00420c59:	notl %eax
0x00420c5b:	andl %ecx, %eax
0x00420c5d:	movl %eax, %esp
0x00420c5f:	andl %eax, $0xfffff000<UINT32>
0x00420c64:	cmpl %ecx, %eax
0x00420c66:	repn jb 11
0x00420c69:	movl %eax, %ecx
0x00420c6b:	popl %ecx
0x00420c6c:	xchgl %esp, %eax
0x00420c6d:	movl %eax, (%eax)
0x00420c6f:	movl (%esp), %eax
0x00420c72:	repn ret

0x00486eea:	movl %esi, %esp
0x00486eec:	testl %esi, %esi
0x00486eee:	je 96
0x00486ef0:	movl (%esi), $0xcccc<UINT32>
0x00486ef6:	jmp 0x00486f11
0x00486f11:	addl %esi, $0x8<UINT8>
0x00486f14:	jmp 0x00486f18
0x00486f18:	testl %esi, %esi
0x00486f1a:	je 52
0x00486f1c:	pushl %ebx
0x00486f1d:	pushl %edi
0x00486f1e:	pushl %esi
0x00486f1f:	call 0x0043e1b0
0x00486f24:	addl %esp, $0xc<UINT8>
0x00486f27:	pushl -8(%ebp)
0x00486f2a:	pushl %esi
0x00486f2b:	pushl 0x14(%ebp)
0x00486f2e:	pushl 0x10(%ebp)
0x00486f31:	pushl $0x1<UINT8>
0x00486f33:	pushl 0x1c(%ebp)
0x00486f36:	call MultiByteToWideChar@KERNEL32.DLL
0x00486f3c:	testl %eax, %eax
0x00486f3e:	je 16
0x00486f40:	pushl 0x18(%ebp)
0x00486f43:	pushl %eax
0x00486f44:	pushl %esi
0x00486f45:	pushl 0xc(%ebp)
0x00486f48:	call GetStringTypeW@KERNEL32.DLL
GetStringTypeW@KERNEL32.DLL: API Node	
0x00486f4e:	movl %edi, %eax
0x00486f50:	pushl %esi
0x00486f51:	call 0x00423add
0x00423add:	pushl %ebp
0x00423ade:	movl %ebp, %esp
0x00423ae0:	movl %eax, 0x8(%ebp)
0x00423ae3:	testl %eax, %eax
0x00423ae5:	je 0x00423af9
0x00423ae7:	subl %eax, $0x8<UINT8>
0x00423aea:	cmpl (%eax), $0xdddd<UINT32>
0x00423af0:	jne 0x00423af9
0x00423af9:	popl %ebp
0x00423afa:	ret

0x00486f56:	popl %ecx
0x00486f57:	cmpb -12(%ebp), $0x0<UINT8>
0x00486f5b:	je 0x00486f67
0x00486f67:	movl %eax, %edi
0x00486f69:	leal %esp, -36(%ebp)
0x00486f6c:	popl %edi
0x00486f6d:	popl %esi
0x00486f6e:	popl %ebx
0x00486f6f:	movl %ecx, -4(%ebp)
0x00486f72:	xorl %ecx, %ebp
0x00486f74:	call 0x00420bd0
0x00486f79:	movl %esp, %ebp
0x00486f7b:	popl %ebp
0x00486f7c:	ret

0x004844c6:	pushl %ebx
0x004844c7:	pushl 0x4(%esi)
0x004844ca:	leal %eax, -516(%ebp)
0x004844d0:	pushl %edi
0x004844d1:	pushl %eax
0x004844d2:	pushl %edi
0x004844d3:	leal %eax, -260(%ebp)
0x004844d9:	pushl %eax
0x004844da:	pushl %edi
0x004844db:	pushl 0x21c(%esi)
0x004844e1:	pushl %ebx
0x004844e2:	call 0x0047b5c7
0x0047b5c7:	movl %edi, %edi
0x0047b5c9:	pushl %ebp
0x0047b5ca:	movl %ebp, %esp
0x0047b5cc:	subl %esp, $0x10<UINT8>
0x0047b5cf:	pushl 0x8(%ebp)
0x0047b5d2:	leal %ecx, -16(%ebp)
0x0047b5d5:	call 0x0044a7e7
0x0047b5da:	pushl 0x28(%ebp)
0x0047b5dd:	leal %eax, -12(%ebp)
0x0047b5e0:	pushl 0x24(%ebp)
0x0047b5e3:	pushl 0x20(%ebp)
0x0047b5e6:	pushl 0x1c(%ebp)
0x0047b5e9:	pushl 0x18(%ebp)
0x0047b5ec:	pushl 0x14(%ebp)
0x0047b5ef:	pushl 0x10(%ebp)
0x0047b5f2:	pushl 0xc(%ebp)
0x0047b5f5:	pushl %eax
0x0047b5f6:	call 0x0047b3aa
0x0047b3aa:	movl %edi, %edi
0x0047b3ac:	pushl %ebp
0x0047b3ad:	movl %ebp, %esp
0x0047b3af:	pushl %ecx
0x0047b3b0:	pushl %ecx
0x0047b3b1:	movl %eax, 0x4cff1c
0x0047b3b6:	xorl %eax, %ebp
0x0047b3b8:	movl -4(%ebp), %eax
0x0047b3bb:	pushl %ebx
0x0047b3bc:	pushl %esi
0x0047b3bd:	movl %esi, 0x18(%ebp)
0x0047b3c0:	pushl %edi
0x0047b3c1:	testl %esi, %esi
0x0047b3c3:	jle 20
0x0047b3c5:	pushl %esi
0x0047b3c6:	pushl 0x14(%ebp)
0x0047b3c9:	call 0x004755db
0x004755db:	movl %edi, %edi
0x004755dd:	pushl %ebp
0x004755de:	movl %ebp, %esp
0x004755e0:	movl %ecx, 0x8(%ebp)
0x004755e3:	xorl %eax, %eax
0x004755e5:	cmpb (%ecx), %al
0x004755e7:	je 12
0x004755e9:	cmpl %eax, 0xc(%ebp)
0x004755ec:	je 0x004755f5
0x004755ee:	incl %eax
0x004755ef:	cmpb (%eax,%ecx), $0x0<UINT8>
0x004755f3:	jne 0x004755e9
0x004755f5:	popl %ebp
0x004755f6:	ret

0x0047b3ce:	popl %ecx
0x0047b3cf:	cmpl %eax, %esi
0x0047b3d1:	popl %ecx
0x0047b3d2:	leal %esi, 0x1(%eax)
0x0047b3d5:	jl 2
0x0047b3d7:	movl %esi, %eax
0x0047b3d9:	movl %edi, 0x24(%ebp)
0x0047b3dc:	testl %edi, %edi
0x0047b3de:	jne 0x0047b3eb
0x0047b3eb:	xorl %eax, %eax
0x0047b3ed:	cmpl 0x28(%ebp), %eax
0x0047b3f0:	pushl $0x0<UINT8>
0x0047b3f2:	pushl $0x0<UINT8>
0x0047b3f4:	pushl %esi
0x0047b3f5:	pushl 0x14(%ebp)
0x0047b3f8:	setne %al
0x0047b3fb:	leal %eax, 0x1(,%eax,8)
0x0047b402:	pushl %eax
0x0047b403:	pushl %edi
0x0047b404:	call MultiByteToWideChar@KERNEL32.DLL
0x0047b40a:	movl -8(%ebp), %eax
0x0047b40d:	testl %eax, %eax
0x0047b40f:	je 397
0x0047b415:	leal %edx, (%eax,%eax)
0x0047b418:	leal %ecx, 0x8(%edx)
0x0047b41b:	cmpl %edx, %ecx
0x0047b41d:	sbbl %eax, %eax
0x0047b41f:	testl %ecx, %eax
0x0047b421:	je 82
0x0047b423:	leal %ecx, 0x8(%edx)
0x0047b426:	cmpl %edx, %ecx
0x0047b428:	sbbl %eax, %eax
0x0047b42a:	andl %eax, %ecx
0x0047b42c:	leal %ecx, 0x8(%edx)
0x0047b42f:	cmpl %eax, $0x400<UINT32>
0x0047b434:	ja 29
0x0047b436:	cmpl %edx, %ecx
0x0047b438:	sbbl %eax, %eax
0x0047b43a:	andl %eax, %ecx
0x0047b43c:	call 0x00497c10
0x0047b441:	movl %ebx, %esp
0x0047b443:	testl %ebx, %ebx
0x0047b445:	je 332
0x0047b44b:	movl (%ebx), $0xcccc<UINT32>
0x0047b451:	jmp 0x0047b470
0x0047b470:	addl %ebx, $0x8<UINT8>
0x0047b473:	jmp 0x0047b477
0x0047b477:	testl %ebx, %ebx
0x0047b479:	je 280
0x0047b47f:	pushl -8(%ebp)
0x0047b482:	pushl %ebx
0x0047b483:	pushl %esi
0x0047b484:	pushl 0x14(%ebp)
0x0047b487:	pushl $0x1<UINT8>
0x0047b489:	pushl %edi
0x0047b48a:	call MultiByteToWideChar@KERNEL32.DLL
0x0047b490:	testl %eax, %eax
0x0047b492:	je 255
0x0047b498:	movl %edi, -8(%ebp)
0x0047b49b:	xorl %eax, %eax
0x0047b49d:	pushl %eax
0x0047b49e:	pushl %eax
0x0047b49f:	pushl %eax
0x0047b4a0:	pushl %eax
0x0047b4a1:	pushl %eax
0x0047b4a2:	pushl %edi
0x0047b4a3:	pushl %ebx
0x0047b4a4:	pushl 0x10(%ebp)
0x0047b4a7:	pushl 0xc(%ebp)
0x0047b4aa:	call 0x0047d62d
0x0047d62d:	movl %edi, %edi
0x0047d62f:	pushl %ebp
0x0047d630:	movl %ebp, %esp
0x0047d632:	pushl %ecx
0x0047d633:	movl %eax, 0x4cff1c
0x0047d638:	xorl %eax, %ebp
0x0047d63a:	movl -4(%ebp), %eax
0x0047d63d:	pushl %esi
0x0047d63e:	pushl $0x4b9098<UINT32>
0x0047d643:	pushl $0x4b9090<UINT32>
0x0047d648:	pushl $0x4b3054<UINT32>
0x0047d64d:	pushl $0x16<UINT8>
0x0047d64f:	call 0x0047cdd0
0x0047d654:	movl %esi, %eax
0x0047d656:	addl %esp, $0x10<UINT8>
0x0047d659:	testl %esi, %esi
0x0047d65b:	je 39
0x0047d65d:	pushl 0x28(%ebp)
0x0047d660:	movl %ecx, %esi
0x0047d662:	pushl 0x24(%ebp)
0x0047d665:	pushl 0x20(%ebp)
0x0047d668:	pushl 0x1c(%ebp)
0x0047d66b:	pushl 0x18(%ebp)
0x0047d66e:	pushl 0x14(%ebp)
0x0047d671:	pushl 0x10(%ebp)
0x0047d674:	pushl 0xc(%ebp)
0x0047d677:	pushl 0x8(%ebp)
0x0047d67a:	call 0x00421f52
0x0047d680:	call LCMapStringEx@kernel32.dll
LCMapStringEx@kernel32.dll: API Node	
0x0047d682:	jmp 0x0047d6a4
0x0047d6a4:	movl %ecx, -4(%ebp)
0x0047d6a7:	xorl %ecx, %ebp
0x0047d6a9:	popl %esi
0x0047d6aa:	call 0x00420bd0
0x0047d6af:	movl %esp, %ebp
0x0047d6b1:	popl %ebp
0x0047d6b2:	ret $0x24<UINT16>

0x0047b4af:	movl %esi, %eax
0x0047b4b1:	testl %esi, %esi
0x0047b4b3:	je 0x0047b597
0x0047b4b9:	testl 0x10(%ebp), $0x400<UINT32>
0x0047b597:	xorl %esi, %esi
0x0047b599:	pushl %ebx
0x0047b59a:	call 0x00423add
0x0047b59f:	popl %ecx
0x0047b5a0:	movl %eax, %esi
0x0047b5a2:	leal %esp, -20(%ebp)
0x0047b5a5:	popl %edi
0x0047b5a6:	popl %esi
0x0047b5a7:	popl %ebx
0x0047b5a8:	movl %ecx, -4(%ebp)
0x0047b5ab:	xorl %ecx, %ebp
0x0047b5ad:	call 0x00420bd0
0x0047b5b2:	movl %esp, %ebp
0x0047b5b4:	popl %ebp
0x0047b5b5:	ret

0x0047b5fb:	addl %esp, $0x24<UINT8>
0x0047b5fe:	cmpb -4(%ebp), $0x0<UINT8>
0x0047b602:	je 0x0047b60e
0x0047b60e:	movl %esp, %ebp
0x0047b610:	popl %ebp
0x0047b611:	ret

0x004844e7:	addl %esp, $0x40<UINT8>
0x004844ea:	leal %eax, -772(%ebp)
0x004844f0:	pushl %ebx
0x004844f1:	pushl 0x4(%esi)
0x004844f4:	pushl %edi
0x004844f5:	pushl %eax
0x004844f6:	pushl %edi
0x004844f7:	leal %eax, -260(%ebp)
0x004844fd:	pushl %eax
0x004844fe:	pushl $0x200<UINT32>
0x00484503:	pushl 0x21c(%esi)
0x00484509:	pushl %ebx
0x0048450a:	call 0x0047b5c7
0x0048450f:	addl %esp, $0x24<UINT8>
0x00484512:	movl %ecx, %ebx
0x00484514:	movzwl %eax, -1796(%ebp,%ecx,2)
0x0048451c:	testb %al, $0x1<UINT8>
0x0048451e:	je 0x0048452e
0x0048452e:	testb %al, $0x2<UINT8>
0x00484530:	je 0x00484547
0x00484547:	movb 0x119(%esi,%ecx), %bl
0x0048454e:	incl %ecx
0x0048454f:	cmpl %ecx, %edi
0x00484551:	jb 0x00484514
0x00484520:	orb 0x19(%esi,%ecx), $0x10<UINT8>
0x00484525:	movb %al, -516(%ebp,%ecx)
0x0048452c:	jmp 0x0048453e
0x0048453e:	movb 0x119(%esi,%ecx), %al
0x00484545:	jmp 0x0048454e
0x00484532:	orb 0x19(%esi,%ecx), $0x20<UINT8>
0x00484537:	movb %al, -772(%ebp,%ecx)
0x00484553:	jmp 0x004845ae
0x004845ae:	movl %ecx, -4(%ebp)
0x004845b1:	popl %edi
0x004845b2:	popl %esi
0x004845b3:	xorl %ecx, %ebp
0x004845b5:	popl %ebx
0x004845b6:	call 0x00420bd0
0x004845bb:	movl %esp, %ebp
0x004845bd:	popl %ebp
0x004845be:	ret

0x004849b2:	popl %ecx
0x004849b3:	xorl %eax, %eax
0x004849b5:	popl %edi
0x004849b6:	movl %ecx, -4(%ebp)
0x004849b9:	popl %esi
0x004849ba:	xorl %ecx, %ebp
0x004849bc:	popl %ebx
0x004849bd:	call 0x00420bd0
0x004849c2:	movl %esp, %ebp
0x004849c4:	popl %ebp
0x004849c5:	ret

0x00484621:	movl %esi, %eax
0x00484623:	popl %ecx
0x00484624:	popl %ecx
0x00484625:	cmpl %esi, %ebx
0x00484627:	jne 0x00484646
0x00484646:	cmpb 0xc(%ebp), $0x0<UINT8>
0x0048464a:	jne 0x00484651
0x00484651:	movl %eax, -4(%ebp)
0x00484654:	movl %eax, 0x48(%eax)
0x00484657:	xaddl (%eax), %ebx
0x0048465b:	decl %ebx
0x0048465c:	jne 21
0x0048465e:	movl %eax, -4(%ebp)
0x00484661:	cmpl 0x48(%eax), $0x4d05f8<UINT32>
0x00484668:	je 0x00484673
0x00484673:	movl (%edi), $0x1<UINT32>
0x00484679:	movl %ecx, %edi
0x0048467b:	movl %eax, -4(%ebp)
0x0048467e:	xorl %edi, %edi
0x00484680:	movl 0x48(%eax), %ecx
0x00484683:	movl %eax, -4(%ebp)
0x00484686:	testb 0x350(%eax), $0x2<UINT8>
0x0048468d:	jne -89
0x0048468f:	testb 0x4d081c, $0x1<UINT8>
0x00484696:	jne -98
0x00484698:	leal %eax, -4(%ebp)
0x0048469b:	movl -12(%ebp), %eax
0x0048469e:	leal %eax, -12(%ebp)
0x004846a1:	pushl %eax
0x004846a2:	pushl $0x5<UINT8>
0x004846a4:	call 0x004841e3
0x004841e3:	movl %edi, %edi
0x004841e5:	pushl %ebp
0x004841e6:	movl %ebp, %esp
0x004841e8:	subl %esp, $0xc<UINT8>
0x004841eb:	movl %eax, 0x8(%ebp)
0x004841ee:	leal %ecx, -1(%ebp)
0x004841f1:	movl -8(%ebp), %eax
0x004841f4:	movl -12(%ebp), %eax
0x004841f7:	leal %eax, -8(%ebp)
0x004841fa:	pushl %eax
0x004841fb:	pushl 0xc(%ebp)
0x004841fe:	leal %eax, -12(%ebp)
0x00484201:	pushl %eax
0x00484202:	call 0x004841a0
0x004841a0:	pushl $0x8<UINT8>
0x004841a2:	pushl $0x4c7bf0<UINT32>
0x004841a7:	call 0x00421d80
0x004841ac:	movl %eax, 0x8(%ebp)
0x004841af:	pushl (%eax)
0x004841b1:	call 0x00474af4
0x004841b6:	popl %ecx
0x004841b7:	andl -4(%ebp), $0x0<UINT8>
0x004841bb:	movl %ecx, 0xc(%ebp)
0x004841be:	call 0x00484251
0x00484251:	movl %edi, %edi
0x00484253:	pushl %esi
0x00484254:	movl %esi, %ecx
0x00484256:	pushl $0xc<UINT8>
0x00484258:	movl %eax, (%esi)
0x0048425a:	movl %eax, (%eax)
0x0048425c:	movl %eax, 0x48(%eax)
0x0048425f:	movl %eax, 0x4(%eax)
0x00484262:	movl 0x4e3b9c, %eax
0x00484267:	movl %eax, (%esi)
0x00484269:	movl %eax, (%eax)
0x0048426b:	movl %eax, 0x48(%eax)
0x0048426e:	movl %eax, 0x8(%eax)
0x00484271:	movl 0x4e3ba0, %eax
0x00484276:	movl %eax, (%esi)
0x00484278:	movl %eax, (%eax)
0x0048427a:	movl %eax, 0x48(%eax)
0x0048427d:	movl %eax, 0x21c(%eax)
0x00484283:	movl 0x4e3b98, %eax
0x00484288:	movl %eax, (%esi)
0x0048428a:	movl %eax, (%eax)
0x0048428c:	movl %eax, 0x48(%eax)
0x0048428f:	addl %eax, $0xc<UINT8>
0x00484292:	pushl %eax
0x00484293:	pushl $0xc<UINT8>
0x00484295:	pushl $0x4e3ba4<UINT32>
0x0048429a:	call 0x004849c6
0x004849c6:	movl %edi, %edi
0x004849c8:	pushl %ebp
0x004849c9:	movl %ebp, %esp
0x004849cb:	pushl %esi
0x004849cc:	movl %esi, 0x14(%ebp)
0x004849cf:	testl %esi, %esi
0x004849d1:	jne 0x004849d7
0x004849d7:	movl %eax, 0x8(%ebp)
0x004849da:	testl %eax, %eax
0x004849dc:	jne 0x004849f1
0x004849f1:	pushl %edi
0x004849f2:	movl %edi, 0x10(%ebp)
0x004849f5:	testl %edi, %edi
0x004849f7:	je 20
0x004849f9:	cmpl 0xc(%ebp), %esi
0x004849fc:	jb 15
0x004849fe:	pushl %esi
0x004849ff:	pushl %edi
0x00484a00:	pushl %eax
0x00484a01:	call 0x0043e6d0
0x0043e6d0:	pushl %edi
0x0043e6d1:	pushl %esi
0x0043e6d2:	movl %esi, 0x10(%esp)
0x0043e6d6:	movl %ecx, 0x14(%esp)
0x0043e6da:	movl %edi, 0xc(%esp)
0x0043e6de:	movl %eax, %ecx
0x0043e6e0:	movl %edx, %ecx
0x0043e6e2:	addl %eax, %esi
0x0043e6e4:	cmpl %edi, %esi
0x0043e6e6:	jbe 0x0043e6f0
0x0043e6f0:	cmpl %ecx, $0x20<UINT8>
0x0043e6f3:	jb 0x0043ebcb
0x0043ebcb:	andl %ecx, $0x1f<UINT8>
0x0043ebce:	je 48
0x0043ebd0:	movl %eax, %ecx
0x0043ebd2:	shrl %ecx, $0x2<UINT8>
0x0043ebd5:	je 0x0043ebe6
0x0043ebd7:	movl %edx, (%esi)
0x0043ebd9:	movl (%edi), %edx
0x0043ebdb:	addl %edi, $0x4<UINT8>
0x0043ebde:	addl %esi, $0x4<UINT8>
0x0043ebe1:	subl %ecx, $0x1<UINT8>
0x0043ebe4:	jne 0x0043ebd7
0x0043ebe6:	movl %ecx, %eax
0x0043ebe8:	andl %ecx, $0x3<UINT8>
0x0043ebeb:	je 0x0043ec00
0x0043ec00:	movl %eax, 0xc(%esp)
0x0043ec04:	popl %esi
0x0043ec05:	popl %edi
0x0043ec06:	ret

0x00484a06:	addl %esp, $0xc<UINT8>
0x00484a09:	xorl %eax, %eax
0x00484a0b:	jmp 0x00484a43
0x00484a43:	popl %edi
0x00484a44:	popl %esi
0x00484a45:	popl %ebp
0x00484a46:	ret

0x0048429f:	movl %eax, (%esi)
0x004842a1:	movl %ecx, $0x101<UINT32>
0x004842a6:	pushl %ecx
0x004842a7:	movl %eax, (%eax)
0x004842a9:	movl %eax, 0x48(%eax)
0x004842ac:	addl %eax, $0x18<UINT8>
0x004842af:	pushl %eax
0x004842b0:	pushl %ecx
0x004842b1:	pushl $0x4d03f0<UINT32>
0x004842b6:	call 0x004849c6
0x0043e6f9:	cmpl %ecx, $0x80<UINT32>
0x0043e6ff:	jae 0x0043e714
0x0043e714:	btl 0x4e298c, $0x1<UINT8>
0x0043e71c:	jae 0x0043e727
0x0043e727:	movl %eax, %edi
0x0043e729:	xorl %eax, %esi
0x0043e72b:	testl %eax, $0xf<UINT32>
0x0043e730:	jne 0x0043e740
0x0043e732:	btl 0x4cff2c, $0x1<UINT8>
0x0043e73a:	jb 0x0043eb20
0x0043eb20:	movl %eax, %esi
0x0043eb22:	andl %eax, $0xf<UINT8>
0x0043eb25:	testl %eax, %eax
0x0043eb27:	jne 227
0x0043eb2d:	movl %edx, %ecx
0x0043eb2f:	andl %ecx, $0x7f<UINT8>
0x0043eb32:	shrl %edx, $0x7<UINT8>
0x0043eb35:	je 102
0x0043eb37:	leal %esp, (%esp)
0x0043eb3e:	movl %edi, %edi
0x0043eb40:	movdqa %xmm0, (%esi)
0x0043eb44:	movdqa %xmm1, 0x10(%esi)
0x0043eb49:	movdqa %xmm2, 0x20(%esi)
0x0043eb4e:	movdqa %xmm3, 0x30(%esi)
0x0043eb53:	movdqa (%edi), %xmm0
0x0043eb57:	movdqa 0x10(%edi), %xmm1
0x0043eb5c:	movdqa 0x20(%edi), %xmm2
0x0043eb61:	movdqa 0x30(%edi), %xmm3
0x0043eb66:	movdqa %xmm4, 0x40(%esi)
0x0043eb6b:	movdqa %xmm5, 0x50(%esi)
0x0043eb70:	movdqa %xmm6, 0x60(%esi)
0x0043eb75:	movdqa %xmm7, 0x70(%esi)
0x0043eb7a:	movdqa 0x40(%edi), %xmm4
0x0043eb7f:	movdqa 0x50(%edi), %xmm5
0x0043eb84:	movdqa 0x60(%edi), %xmm6
0x0043eb89:	movdqa 0x70(%edi), %xmm7
0x0043eb8e:	leal %esi, 0x80(%esi)
0x0043eb94:	leal %edi, 0x80(%edi)
0x0043eb9a:	decl %edx
0x0043eb9b:	jne 0x0043eb40
0x0043eb9d:	testl %ecx, %ecx
0x0043eb9f:	je 95
0x0043eba1:	movl %edx, %ecx
0x0043eba3:	shrl %edx, $0x5<UINT8>
0x0043eba6:	testl %edx, %edx
0x0043eba8:	je 0x0043ebcb
0x0043ebed:	movb %al, (%esi)
0x0043ebef:	movb (%edi), %al
0x0043ebf1:	incl %esi
0x0043ebf2:	incl %edi
0x0043ebf3:	decl %ecx
0x0043ebf4:	jne -9
0x0043ebf6:	leal %esp, (%esp)
0x0043ebfd:	leal %ecx, (%ecx)
0x004842bb:	movl %eax, (%esi)
0x004842bd:	movl %ecx, $0x100<UINT32>
0x004842c2:	pushl %ecx
0x004842c3:	movl %eax, (%eax)
0x004842c5:	movl %eax, 0x48(%eax)
0x004842c8:	addl %eax, $0x119<UINT32>
0x004842cd:	pushl %eax
0x004842ce:	pushl %ecx
0x004842cf:	pushl $0x4d04f8<UINT32>
0x004842d4:	call 0x004849c6
0x0043e740:	btl 0x4e298c, $0x0<UINT8>
0x0043e748:	jae 0x0043e8f7
0x0043e8f7:	testl %edi, $0x3<UINT32>
0x0043e8fd:	je 0x0043e912
0x0043e912:	movl %edx, %ecx
0x0043e914:	cmpl %ecx, $0x20<UINT8>
0x0043e917:	jb 686
0x0043e91d:	shrl %ecx, $0x2<UINT8>
0x0043e920:	rep movsl %es:(%edi), %ds:(%esi)
0x0043e922:	andl %edx, $0x3<UINT8>
0x0043e925:	jmp 0x0043e944
0x0043e944:	movl %eax, 0xc(%esp)
0x0043e948:	popl %esi
0x0043e949:	popl %edi
0x0043e94a:	ret

0x004842d9:	movl %eax, 0x4d0818
0x004842de:	addl %esp, $0x30<UINT8>
0x004842e1:	orl %ecx, $0xffffffff<UINT8>
0x004842e4:	xaddl (%eax), %ecx
0x004842e8:	jne 0x004842fd
0x004842fd:	movl %eax, (%esi)
0x004842ff:	movl %eax, (%eax)
0x00484301:	movl %eax, 0x48(%eax)
0x00484304:	movl 0x4d0818, %eax
0x00484309:	movl %eax, (%esi)
0x0048430b:	movl %eax, (%eax)
0x0048430d:	movl %eax, 0x48(%eax)
0x00484310:	incl (%eax)
0x00484313:	popl %esi
0x00484314:	ret

0x004841c3:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004841ca:	call 0x004841d7
0x004841d7:	movl %eax, 0x10(%ebp)
0x004841da:	pushl (%eax)
0x004841dc:	call 0x00474b3c
0x004841e1:	popl %ecx
0x004841e2:	ret

0x004841cf:	call 0x00421dc6
0x004841d4:	ret $0xc<UINT16>

0x00484207:	movl %esp, %ebp
0x00484209:	popl %ebp
0x0048420a:	ret

0x004846a9:	cmpb 0xc(%ebp), $0x0<UINT8>
0x004846ad:	popl %ecx
0x004846ae:	popl %ecx
0x004846af:	je -123
0x004846b1:	movl %eax, 0x4d0818
0x004846b6:	movl 0x4d01b4, %eax
0x004846bb:	jmp 0x00484636
0x00484636:	pushl %edi
0x00484637:	call 0x00475680
0x0048463c:	popl %ecx
0x0048463d:	popl %edi
0x0048463e:	movl %eax, %esi
0x00484640:	popl %esi
0x00484641:	popl %ebx
0x00484642:	movl %esp, %ebp
0x00484644:	popl %ebp
0x00484645:	ret

0x004846d2:	popl %ecx
0x004846d3:	popl %ecx
0x004846d4:	movb 0x4e3bb4, $0x1<UINT8>
0x004846db:	movb %al, $0x1<UINT8>
0x004846dd:	ret

0x00472bdf:	movb %al, $0x1<UINT8>
0x00472be1:	ret

0x00472bc2:	pushl $0x4e3104<UINT32>
0x00472bc7:	call 0x00472b4f
0x00472b4f:	movl %edi, %edi
0x00472b51:	pushl %ebp
0x00472b52:	movl %ebp, %esp
0x00472b54:	pushl %esi
0x00472b55:	movl %esi, 0x8(%ebp)
0x00472b58:	testl %esi, %esi
0x00472b5a:	jne 0x00472b61
0x00472b61:	movl %eax, (%esi)
0x00472b63:	cmpl %eax, 0x8(%esi)
0x00472b66:	jne 31
0x00472b68:	movl %eax, 0x4cff1c
0x00472b6d:	andl %eax, $0x1f<UINT8>
0x00472b70:	pushl $0x20<UINT8>
0x00472b72:	popl %ecx
0x00472b73:	subl %ecx, %eax
0x00472b75:	xorl %eax, %eax
0x00472b77:	rorl %eax, %cl
0x00472b79:	xorl %eax, 0x4cff1c
0x00472b7f:	movl (%esi), %eax
0x00472b81:	movl 0x4(%esi), %eax
0x00472b84:	movl 0x8(%esi), %eax
0x00472b87:	xorl %eax, %eax
0x00472b89:	popl %esi
0x00472b8a:	popl %ebp
0x00472b8b:	ret

0x00472bcc:	movl (%esp), $0x4e3110<UINT32>
0x00472bd3:	call 0x00472b4f
0x00472bd8:	popl %ecx
0x00472bd9:	movb %al, $0x1<UINT8>
0x00472bdb:	ret

0x00485562:	cmpl %esi, 0xc(%ebp)
0x00485565:	jne 4
0x00485567:	movb %al, $0x1<UINT8>
0x00485569:	jmp 0x00485597
0x00485597:	popl %ebx
0x00485598:	popl %esi
0x00485599:	movl %ecx, -4(%ebp)
0x0048559c:	xorl %ecx, %ebp
0x0048559e:	popl %edi
0x0048559f:	call 0x00420bd0
0x004855a4:	movl %esp, %ebp
0x004855a6:	popl %ebp
0x004855a7:	ret

0x00472cf0:	popl %ecx
0x00472cf1:	popl %ecx
0x00472cf2:	ret

0x00420e6a:	testb %al, %al
0x00420e6c:	jne 0x00420e78
0x00420e78:	movb %al, $0x1<UINT8>
0x00420e7a:	popl %ebp
0x00420e7b:	ret

0x0042114c:	popl %ecx
0x0042114d:	testb %al, %al
0x0042114f:	jne 0x00421158
0x00421158:	xorb %bl, %bl
0x0042115a:	movb -25(%ebp), %bl
0x0042115d:	andl -4(%ebp), $0x0<UINT8>
0x00421161:	call 0x00420d46
0x00420d46:	call 0x00421b78
0x00421b78:	xorl %eax, %eax
0x00421b7a:	cmpl 0x4e5828, %eax
0x00421b80:	setne %al
0x00421b83:	ret

0x00420d4b:	testl %eax, %eax
0x00420d4d:	jne 3
0x00420d4f:	xorb %al, %al
0x00420d51:	ret

0x00421166:	movb -36(%ebp), %al
0x00421169:	movl %eax, 0x4e2618
0x0042116e:	xorl %ecx, %ecx
0x00421170:	incl %ecx
0x00421171:	cmpl %eax, %ecx
0x00421173:	je -36
0x00421175:	testl %eax, %eax
0x00421177:	jne 73
0x00421179:	movl 0x4e2618, %ecx
0x0042117f:	pushl $0x49c51c<UINT32>
0x00421184:	pushl $0x49c4f8<UINT32>
0x00421189:	call 0x004731ad
0x004731ad:	movl %edi, %edi
0x004731af:	pushl %ebp
0x004731b0:	movl %ebp, %esp
0x004731b2:	pushl %ecx
0x004731b3:	movl %eax, 0x4cff1c
0x004731b8:	xorl %eax, %ebp
0x004731ba:	movl -4(%ebp), %eax
0x004731bd:	pushl %esi
0x004731be:	movl %esi, 0x8(%ebp)
0x004731c1:	pushl %edi
0x004731c2:	jmp 0x004731db
0x004731db:	cmpl %esi, 0xc(%ebp)
0x004731de:	jne 0x004731c4
0x004731c4:	movl %edi, (%esi)
0x004731c6:	testl %edi, %edi
0x004731c8:	je 0x004731d8
0x004731d8:	addl %esi, $0x4<UINT8>
0x004731ca:	movl %ecx, %edi
0x004731cc:	call 0x00421f52
0x004731d2:	call 0x004215ea
0x00421071:	pushl %esi
0x00421072:	pushl $0x2<UINT8>
0x00421074:	call 0x00472eef
0x00472eef:	movl %edi, %edi
0x00472ef1:	pushl %ebp
0x00472ef2:	movl %ebp, %esp
0x00472ef4:	movl %eax, 0x8(%ebp)
0x00472ef7:	movl 0x4e311c, %eax
0x00472efc:	popl %ebp
0x00472efd:	ret

0x00421079:	call 0x00421e7d
0x00421e7d:	movl %eax, $0x4000<UINT32>
0x00421e82:	ret

0x0042107e:	pushl %eax
0x0042107f:	call 0x0046cd28
0x0046cd28:	movl %edi, %edi
0x0046cd2a:	pushl %ebp
0x0046cd2b:	movl %ebp, %esp
0x0046cd2d:	movl %eax, 0x8(%ebp)
0x0046cd30:	cmpl %eax, $0x4000<UINT32>
0x0046cd35:	je 0x0046cd5a
0x0046cd5a:	movl %ecx, $0x4e3b90<UINT32>
0x0046cd5f:	xchgl (%ecx), %eax
0x0046cd61:	xorl %eax, %eax
0x0046cd63:	popl %ebp
0x0046cd64:	ret

0x00421084:	call 0x004749ca
0x004749ca:	movl %eax, $0x4e375c<UINT32>
0x004749cf:	ret

0x00421089:	movl %esi, %eax
0x0042108b:	call 0x00421e7a
0x00421e7a:	xorl %eax, %eax
0x00421e7c:	ret

0x00421090:	pushl $0x1<UINT8>
0x00421092:	movl (%esi), %eax
0x00421094:	call 0x00420e7c
0x00420e7c:	pushl %ebp
0x00420e7d:	movl %ebp, %esp
0x00420e7f:	subl %esp, $0xc<UINT8>
0x00420e82:	pushl %esi
0x00420e83:	movl %esi, 0x8(%ebp)
0x00420e86:	testl %esi, %esi
0x00420e88:	je 5
0x00420e8a:	cmpl %esi, $0x1<UINT8>
0x00420e8d:	jne 124
0x00420e8f:	call 0x00421b78
0x00420e94:	testl %eax, %eax
0x00420e96:	je 0x00420ec2
0x00420ec2:	movl %eax, 0x4cff1c
0x00420ec7:	leal %esi, -12(%ebp)
0x00420eca:	pushl %edi
0x00420ecb:	andl %eax, $0x1f<UINT8>
0x00420ece:	movl %edi, $0x4e2620<UINT32>
0x00420ed3:	pushl $0x20<UINT8>
0x00420ed5:	popl %ecx
0x00420ed6:	subl %ecx, %eax
0x00420ed8:	orl %eax, $0xffffffff<UINT8>
0x00420edb:	rorl %eax, %cl
0x00420edd:	xorl %eax, 0x4cff1c
0x00420ee3:	movl -12(%ebp), %eax
0x00420ee6:	movl -8(%ebp), %eax
0x00420ee9:	movl -4(%ebp), %eax
0x00420eec:	movsl %es:(%edi), %ds:(%esi)
0x00420eed:	movsl %es:(%edi), %ds:(%esi)
0x00420eee:	movsl %es:(%edi), %ds:(%esi)
0x00420eef:	movl %edi, $0x4e262c<UINT32>
0x00420ef4:	movl -12(%ebp), %eax
0x00420ef7:	movl -8(%ebp), %eax
0x00420efa:	leal %esi, -12(%ebp)
0x00420efd:	movl -4(%ebp), %eax
0x00420f00:	movb %al, $0x1<UINT8>
0x00420f02:	movsl %es:(%edi), %ds:(%esi)
0x00420f03:	movsl %es:(%edi), %ds:(%esi)
0x00420f04:	movsl %es:(%edi), %ds:(%esi)
0x00420f05:	popl %edi
0x00420f06:	popl %esi
0x00420f07:	movl %esp, %ebp
0x00420f09:	popl %ebp
0x00420f0a:	ret

0x00421099:	addl %esp, $0xc<UINT8>
0x0042109c:	popl %esi
0x0042109d:	testb %al, %al
0x0042109f:	je 108
0x004210a1:	fnclex
0x004210a3:	call 0x00421efc
0x00421efc:	pushl %ebx
0x00421efd:	pushl %esi
0x00421efe:	movl %esi, $0x4c30c0<UINT32>
0x00421f03:	movl %ebx, $0x4c30c0<UINT32>
0x00421f08:	cmpl %esi, %ebx
0x00421f0a:	jae 0x00421f24
0x00421f24:	popl %esi
0x00421f25:	popl %ebx
0x00421f26:	ret

0x004210a8:	pushl $0x421f27<UINT32>
0x004210ad:	call 0x0042104e
0x0042104e:	pushl %ebp
0x0042104f:	movl %ebp, %esp
0x00421051:	pushl 0x8(%ebp)
0x00421054:	call 0x00420fe2
0x00420fe2:	pushl %ebp
0x00420fe3:	movl %ebp, %esp
0x00420fe5:	movl %eax, 0x4cff1c
0x00420fea:	movl %ecx, %eax
0x00420fec:	xorl %eax, 0x4e2620
0x00420ff2:	andl %ecx, $0x1f<UINT8>
0x00420ff5:	pushl 0x8(%ebp)
0x00420ff8:	rorl %eax, %cl
0x00420ffa:	cmpl %eax, $0xffffffff<UINT8>
0x00420ffd:	jne 7
0x00420fff:	call 0x00472b1c
0x00472b1c:	movl %edi, %edi
0x00472b1e:	pushl %ebp
0x00472b1f:	movl %ebp, %esp
0x00472b21:	pushl 0x8(%ebp)
0x00472b24:	pushl $0x4e3104<UINT32>
0x00472b29:	call 0x00472b8c
0x00472b8c:	movl %edi, %edi
0x00472b8e:	pushl %ebp
0x00472b8f:	movl %ebp, %esp
0x00472b91:	pushl %ecx
0x00472b92:	pushl %ecx
0x00472b93:	leal %eax, 0x8(%ebp)
0x00472b96:	movl -8(%ebp), %eax
0x00472b99:	leal %eax, 0xc(%ebp)
0x00472b9c:	movl -4(%ebp), %eax
0x00472b9f:	leal %eax, -8(%ebp)
0x00472ba2:	pushl %eax
0x00472ba3:	pushl $0x2<UINT8>
0x00472ba5:	call 0x00472792
0x00472792:	movl %edi, %edi
0x00472794:	pushl %ebp
0x00472795:	movl %ebp, %esp
0x00472797:	subl %esp, $0xc<UINT8>
0x0047279a:	movl %eax, 0x8(%ebp)
0x0047279d:	leal %ecx, -1(%ebp)
0x004727a0:	movl -8(%ebp), %eax
0x004727a3:	movl -12(%ebp), %eax
0x004727a6:	leal %eax, -8(%ebp)
0x004727a9:	pushl %eax
0x004727aa:	pushl 0xc(%ebp)
0x004727ad:	leal %eax, -12(%ebp)
0x004727b0:	pushl %eax
0x004727b1:	call 0x004726c8
0x004726c8:	pushl $0xc<UINT8>
0x004726ca:	pushl $0x4c76c0<UINT32>
0x004726cf:	call 0x00421d80
0x004726d4:	andl -28(%ebp), $0x0<UINT8>
0x004726d8:	movl %eax, 0x8(%ebp)
0x004726db:	pushl (%eax)
0x004726dd:	call 0x00474af4
0x004726e2:	popl %ecx
0x004726e3:	andl -4(%ebp), $0x0<UINT8>
0x004726e7:	movl %ecx, 0xc(%ebp)
0x004726ea:	call 0x00472992
0x00472992:	movl %edi, %edi
0x00472994:	pushl %ebp
0x00472995:	movl %ebp, %esp
0x00472997:	subl %esp, $0xc<UINT8>
0x0047299a:	movl %eax, %ecx
0x0047299c:	movl -8(%ebp), %eax
0x0047299f:	pushl %esi
0x004729a0:	movl %eax, (%eax)
0x004729a2:	movl %esi, (%eax)
0x004729a4:	testl %esi, %esi
0x004729a6:	jne 0x004729b0
0x004729b0:	movl %eax, 0x4cff1c
0x004729b5:	movl %ecx, %eax
0x004729b7:	pushl %ebx
0x004729b8:	movl %ebx, (%esi)
0x004729ba:	andl %ecx, $0x1f<UINT8>
0x004729bd:	pushl %edi
0x004729be:	movl %edi, 0x4(%esi)
0x004729c1:	xorl %ebx, %eax
0x004729c3:	movl %esi, 0x8(%esi)
0x004729c6:	xorl %edi, %eax
0x004729c8:	xorl %esi, %eax
0x004729ca:	rorl %edi, %cl
0x004729cc:	rorl %esi, %cl
0x004729ce:	rorl %ebx, %cl
0x004729d0:	cmpl %edi, %esi
0x004729d2:	jne 0x00472a8c
0x004729d8:	subl %esi, %ebx
0x004729da:	movl %eax, $0x200<UINT32>
0x004729df:	sarl %esi, $0x2<UINT8>
0x004729e2:	cmpl %esi, %eax
0x004729e4:	ja 2
0x004729e6:	movl %eax, %esi
0x004729e8:	leal %edi, (%eax,%esi)
0x004729eb:	testl %edi, %edi
0x004729ed:	jne 3
0x004729ef:	pushl $0x20<UINT8>
0x004729f1:	popl %edi
0x004729f2:	cmpl %edi, %esi
0x004729f4:	jb 29
0x004729f6:	pushl $0x4<UINT8>
0x004729f8:	pushl %edi
0x004729f9:	pushl %ebx
0x004729fa:	call 0x00485486
0x00485486:	movl %edi, %edi
0x00485488:	pushl %ebp
0x00485489:	movl %ebp, %esp
0x0048548b:	popl %ebp
0x0048548c:	jmp 0x00485491
0x00485491:	movl %edi, %edi
0x00485493:	pushl %ebp
0x00485494:	movl %ebp, %esp
0x00485496:	pushl %esi
0x00485497:	movl %esi, 0xc(%ebp)
0x0048549a:	testl %esi, %esi
0x0048549c:	je 27
0x0048549e:	pushl $0xffffffe0<UINT8>
0x004854a0:	xorl %edx, %edx
0x004854a2:	popl %eax
0x004854a3:	divl %eax, %esi
0x004854a5:	cmpl %eax, 0x10(%ebp)
0x004854a8:	jae 0x004854b9
0x004854b9:	pushl %ebx
0x004854ba:	movl %ebx, 0x8(%ebp)
0x004854bd:	pushl %edi
0x004854be:	testl %ebx, %ebx
0x004854c0:	je 0x004854cd
0x004854cd:	xorl %edi, %edi
0x004854cf:	imull %esi, 0x10(%ebp)
0x004854d3:	pushl %esi
0x004854d4:	pushl %ebx
0x004854d5:	call 0x0047576c
0x0047576c:	movl %edi, %edi
0x0047576e:	pushl %ebp
0x0047576f:	movl %ebp, %esp
0x00475771:	pushl %edi
0x00475772:	movl %edi, 0x8(%ebp)
0x00475775:	testl %edi, %edi
0x00475777:	jne 11
0x00475779:	pushl 0xc(%ebp)
0x0047577c:	call 0x004756ba
0x00475781:	popl %ecx
0x00475782:	jmp 0x004757a8
0x004757a8:	popl %edi
0x004757a9:	popl %ebp
0x004757aa:	ret

0x004854da:	movl %ebx, %eax
0x004854dc:	popl %ecx
0x004854dd:	popl %ecx
0x004854de:	testl %ebx, %ebx
0x004854e0:	je 21
0x004854e2:	cmpl %edi, %esi
0x004854e4:	jae 17
0x004854e6:	subl %esi, %edi
0x004854e8:	leal %eax, (%ebx,%edi)
0x004854eb:	pushl %esi
0x004854ec:	pushl $0x0<UINT8>
0x004854ee:	pushl %eax
0x004854ef:	call 0x0043e1b0
0x0043e26d:	btl 0x4cff2c, $0x1<UINT8>
0x0043e275:	jae 62
0x0043e277:	movd %xmm0, %eax
0x0043e27b:	pshufd %xmm0, %xmm0, $0x0<UINT8>
0x004854f4:	addl %esp, $0xc<UINT8>
0x004854f7:	popl %edi
0x004854f8:	movl %eax, %ebx
0x004854fa:	popl %ebx
0x004854fb:	popl %esi
0x004854fc:	popl %ebp
0x004854fd:	ret

0x004729ff:	pushl $0x0<UINT8>
0x00472a01:	movl -4(%ebp), %eax
0x00472a04:	call 0x00475680
0x00472a09:	movl %ecx, -4(%ebp)
0x00472a0c:	addl %esp, $0x10<UINT8>
0x00472a0f:	testl %ecx, %ecx
0x00472a11:	jne 0x00472a3b
0x00472a3b:	leal %eax, (%ecx,%esi,4)
0x00472a3e:	movl %ebx, %ecx
0x00472a40:	movl -4(%ebp), %eax
0x00472a43:	leal %esi, (%ecx,%edi,4)
0x00472a46:	movl %eax, 0x4cff1c
0x00472a4b:	movl %edi, -4(%ebp)
0x00472a4e:	andl %eax, $0x1f<UINT8>
0x00472a51:	pushl $0x20<UINT8>
0x00472a53:	popl %ecx
0x00472a54:	subl %ecx, %eax
0x00472a56:	xorl %eax, %eax
0x00472a58:	rorl %eax, %cl
0x00472a5a:	movl %ecx, %edi
0x00472a5c:	xorl %eax, 0x4cff1c
0x00472a62:	movl -12(%ebp), %eax
0x00472a65:	movl %eax, %esi
0x00472a67:	subl %eax, %edi
0x00472a69:	addl %eax, $0x3<UINT8>
0x00472a6c:	shrl %eax, $0x2<UINT8>
0x00472a6f:	cmpl %esi, %edi
0x00472a71:	sbbl %edx, %edx
0x00472a73:	notl %edx
0x00472a75:	andl %edx, %eax
0x00472a77:	movl -4(%ebp), %edx
0x00472a7a:	je 16
0x00472a7c:	movl %edx, -12(%ebp)
0x00472a7f:	xorl %eax, %eax
0x00472a81:	incl %eax
0x00472a82:	movl (%ecx), %edx
0x00472a84:	leal %ecx, 0x4(%ecx)
0x00472a87:	cmpl %eax, -4(%ebp)
0x00472a8a:	jne 0x00472a81
0x00472a8c:	movl %eax, -8(%ebp)
0x00472a8f:	movl %eax, 0x4(%eax)
0x00472a92:	pushl (%eax)
0x00472a94:	call 0x004727ba
0x004727ba:	movl %edi, %edi
0x004727bc:	pushl %ebp
0x004727bd:	movl %ebp, %esp
0x004727bf:	movl %eax, 0x4cff1c
0x004727c4:	andl %eax, $0x1f<UINT8>
0x004727c7:	pushl $0x20<UINT8>
0x004727c9:	popl %ecx
0x004727ca:	subl %ecx, %eax
0x004727cc:	movl %eax, 0x8(%ebp)
0x004727cf:	rorl %eax, %cl
0x004727d1:	xorl %eax, 0x4cff1c
0x004727d7:	popl %ebp
0x004727d8:	ret

0x00472a99:	pushl %ebx
0x00472a9a:	movl (%edi), %eax
0x00472a9c:	call 0x00420c91
0x00420c91:	pushl %ebp
0x00420c92:	movl %ebp, %esp
0x00420c94:	movl %eax, 0x4cff1c
0x00420c99:	andl %eax, $0x1f<UINT8>
0x00420c9c:	pushl $0x20<UINT8>
0x00420c9e:	popl %ecx
0x00420c9f:	subl %ecx, %eax
0x00420ca1:	movl %eax, 0x8(%ebp)
0x00420ca4:	rorl %eax, %cl
0x00420ca6:	xorl %eax, 0x4cff1c
0x00420cac:	popl %ebp
0x00420cad:	ret

0x00472aa1:	movl %ebx, -8(%ebp)
0x00472aa4:	movl %ecx, (%ebx)
0x00472aa6:	movl %ecx, (%ecx)
0x00472aa8:	movl (%ecx), %eax
0x00472aaa:	leal %eax, 0x4(%edi)
0x00472aad:	pushl %eax
0x00472aae:	call 0x00420c91
0x00472ab3:	movl %ecx, (%ebx)
0x00472ab5:	pushl %esi
0x00472ab6:	movl %ecx, (%ecx)
0x00472ab8:	movl 0x4(%ecx), %eax
0x00472abb:	call 0x00420c91
0x00472ac0:	movl %ecx, (%ebx)
0x00472ac2:	addl %esp, $0x10<UINT8>
0x00472ac5:	movl %ecx, (%ecx)
0x00472ac7:	movl 0x8(%ecx), %eax
0x00472aca:	xorl %eax, %eax
0x00472acc:	popl %edi
0x00472acd:	popl %ebx
0x00472ace:	popl %esi
0x00472acf:	movl %esp, %ebp
0x00472ad1:	popl %ebp
0x00472ad2:	ret

0x004726ef:	movl %esi, %eax
0x004726f1:	movl -28(%ebp), %esi
0x004726f4:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004726fb:	call 0x0047270d
0x0047270d:	movl %eax, 0x10(%ebp)
0x00472710:	pushl (%eax)
0x00472712:	call 0x00474b3c
0x00472717:	popl %ecx
0x00472718:	ret

0x00472700:	movl %eax, %esi
0x00472702:	call 0x00421dc6
0x00472707:	ret $0xc<UINT16>

0x004727b6:	movl %esp, %ebp
0x004727b8:	popl %ebp
0x004727b9:	ret

0x00472baa:	popl %ecx
0x00472bab:	popl %ecx
0x00472bac:	movl %esp, %ebp
0x00472bae:	popl %ebp
0x00472baf:	ret

0x00472b2e:	popl %ecx
0x00472b2f:	popl %ecx
0x00472b30:	popl %ebp
0x00472b31:	ret

0x00421004:	jmp 0x00421011
0x00421011:	negl %eax
0x00421013:	popl %ecx
0x00421014:	sbbl %eax, %eax
0x00421016:	notl %eax
0x00421018:	andl %eax, 0x8(%ebp)
0x0042101b:	popl %ebp
0x0042101c:	ret

0x00421059:	negl %eax
0x0042105b:	popl %ecx
0x0042105c:	sbbl %eax, %eax
0x0042105e:	negl %eax
0x00421060:	decl %eax
0x00421061:	popl %ebp
0x00421062:	ret

0x004210b2:	call 0x00421b74
0x00421b74:	xorl %eax, %eax
0x00421b76:	incl %eax
0x00421b77:	ret

0x004210b7:	pushl %eax
0x004210b8:	call 0x00471e85
0x00471e85:	movl %edi, %edi
0x00471e87:	pushl %ebp
0x00471e88:	movl %ebp, %esp
0x00471e8a:	popl %ebp
0x00471e8b:	jmp 0x0047177b
0x0047177b:	movl %edi, %edi
0x0047177d:	pushl %ebp
0x0047177e:	movl %ebp, %esp
0x00471780:	subl %esp, $0xc<UINT8>
0x00471783:	cmpl 0x8(%ebp), $0x2<UINT8>
0x00471787:	pushl %esi
0x00471788:	je 28
0x0047178a:	cmpl 0x8(%ebp), $0x1<UINT8>
0x0047178e:	je 0x004717a6
0x004717a6:	pushl %ebx
0x004717a7:	pushl %edi
0x004717a8:	call 0x004846c0
0x004717ad:	pushl $0x104<UINT32>
0x004717b2:	movl %esi, $0x4e2de0<UINT32>
0x004717b7:	xorl %edi, %edi
0x004717b9:	pushl %esi
0x004717ba:	pushl %edi
0x004717bb:	call GetModuleFileNameA@KERNEL32.DLL
GetModuleFileNameA@KERNEL32.DLL: API Node	
0x004717c1:	movl %ebx, 0x4e3bc4
0x004717c7:	movl 0x4e3bcc, %esi
0x004717cd:	testl %ebx, %ebx
0x004717cf:	je 5
0x004717d1:	cmpb (%ebx), $0x0<UINT8>
0x004717d4:	jne 0x004717d8
0x004717d8:	leal %eax, -12(%ebp)
0x004717db:	movl -4(%ebp), %edi
0x004717de:	pushl %eax
0x004717df:	leal %eax, -4(%ebp)
0x004717e2:	movl -12(%ebp), %edi
0x004717e5:	pushl %eax
0x004717e6:	pushl %edi
0x004717e7:	pushl %edi
0x004717e8:	pushl %ebx
0x004717e9:	call 0x004719f2
0x004719f2:	movl %edi, %edi
0x004719f4:	pushl %ebp
0x004719f5:	movl %ebp, %esp
0x004719f7:	pushl %ecx
0x004719f8:	movl %eax, 0x14(%ebp)
0x004719fb:	pushl %ebx
0x004719fc:	movl %ebx, 0x18(%ebp)
0x004719ff:	pushl %esi
0x00471a00:	movl %esi, 0x8(%ebp)
0x00471a03:	pushl %edi
0x00471a04:	andl (%ebx), $0x0<UINT8>
0x00471a07:	movl %edi, 0x10(%ebp)
0x00471a0a:	movl (%eax), $0x1<UINT32>
0x00471a10:	movl %eax, 0xc(%ebp)
0x00471a13:	testl %eax, %eax
0x00471a15:	je 0x00471a1f
0x00471a1f:	xorb %cl, %cl
0x00471a21:	movb -1(%ebp), %cl
0x00471a24:	cmpb (%esi), $0x22<UINT8>
0x00471a27:	jne 0x00471a36
0x00471a29:	testb %cl, %cl
0x00471a2b:	movb %al, $0x22<UINT8>
0x00471a2d:	sete %cl
0x00471a30:	incl %esi
0x00471a31:	movb -1(%ebp), %cl
0x00471a34:	jmp 0x00471a6b
0x00471a6b:	testb %cl, %cl
0x00471a6d:	jne 0x00471a24
0x00471a36:	incl (%ebx)
0x00471a38:	testl %edi, %edi
0x00471a3a:	je 0x00471a41
0x00471a41:	movb %al, (%esi)
0x00471a43:	incl %esi
0x00471a44:	movb -2(%ebp), %al
0x00471a47:	movsbl %eax, %al
0x00471a4a:	pushl %eax
0x00471a4b:	call 0x00475317
0x00475317:	movl %edi, %edi
0x00475319:	pushl %ebp
0x0047531a:	movl %ebp, %esp
0x0047531c:	pushl $0x4<UINT8>
0x0047531e:	pushl $0x0<UINT8>
0x00475320:	pushl 0x8(%ebp)
0x00475323:	pushl $0x0<UINT8>
0x00475325:	call 0x004750db
0x004750db:	movl %edi, %edi
0x004750dd:	pushl %ebp
0x004750de:	movl %ebp, %esp
0x004750e0:	subl %esp, $0x10<UINT8>
0x004750e3:	pushl %esi
0x004750e4:	pushl 0x8(%ebp)
0x004750e7:	leal %ecx, -16(%ebp)
0x004750ea:	call 0x0044a7e7
0x004750ef:	movzbl %esi, 0xc(%ebp)
0x004750f3:	movl %eax, -8(%ebp)
0x004750f6:	movb %cl, 0x14(%ebp)
0x004750f9:	testb 0x19(%eax,%esi), %cl
0x004750fd:	jne 27
0x004750ff:	xorl %edx, %edx
0x00475101:	cmpl 0x10(%ebp), %edx
0x00475104:	je 0x00475114
0x00475114:	movl %eax, %edx
0x00475116:	testl %eax, %eax
0x00475118:	je 0x0047511d
0x0047511d:	cmpb -4(%ebp), $0x0<UINT8>
0x00475121:	popl %esi
0x00475122:	je 0x0047512e
0x0047512e:	movl %eax, %edx
0x00475130:	movl %esp, %ebp
0x00475132:	popl %ebp
0x00475133:	ret

0x0047532a:	addl %esp, $0x10<UINT8>
0x0047532d:	popl %ebp
0x0047532e:	ret

0x00471a50:	popl %ecx
0x00471a51:	testl %eax, %eax
0x00471a53:	je 0x00471a61
0x00471a61:	movb %al, -2(%ebp)
0x00471a64:	testb %al, %al
0x00471a66:	je 0x00471a81
0x00471a81:	decl %esi
0x00471a82:	movb -1(%ebp), $0x0<UINT8>
0x00471a86:	cmpb (%esi), $0x0<UINT8>
0x00471a89:	je 0x00471b51
0x00471b51:	movl %ecx, 0xc(%ebp)
0x00471b54:	popl %edi
0x00471b55:	popl %esi
0x00471b56:	popl %ebx
0x00471b57:	testl %ecx, %ecx
0x00471b59:	je 0x00471b5e
0x00471b5e:	movl %eax, 0x14(%ebp)
0x00471b61:	incl (%eax)
0x00471b63:	movl %esp, %ebp
0x00471b65:	popl %ebp
0x00471b66:	ret

0x004717ee:	pushl $0x1<UINT8>
0x004717f0:	pushl -12(%ebp)
0x004717f3:	pushl -4(%ebp)
0x004717f6:	call 0x00471e30
0x00471e30:	movl %edi, %edi
0x00471e32:	pushl %ebp
0x00471e33:	movl %ebp, %esp
0x00471e35:	pushl %esi
0x00471e36:	movl %esi, 0x8(%ebp)
0x00471e39:	cmpl %esi, $0x3fffffff<UINT32>
0x00471e3f:	jb 0x00471e45
0x00471e45:	pushl %edi
0x00471e46:	orl %edi, $0xffffffff<UINT8>
0x00471e49:	movl %ecx, 0xc(%ebp)
0x00471e4c:	xorl %edx, %edx
0x00471e4e:	movl %eax, %edi
0x00471e50:	divl %eax, 0x10(%ebp)
0x00471e53:	cmpl %ecx, %eax
0x00471e55:	jae 13
0x00471e57:	imull %ecx, 0x10(%ebp)
0x00471e5b:	shll %esi, $0x2<UINT8>
0x00471e5e:	subl %edi, %esi
0x00471e60:	cmpl %edi, %ecx
0x00471e62:	ja 0x00471e68
0x00471e68:	leal %eax, (%ecx,%esi)
0x00471e6b:	pushl $0x1<UINT8>
0x00471e6d:	pushl %eax
0x00471e6e:	call 0x00474b65
0x00471e73:	pushl $0x0<UINT8>
0x00471e75:	movl %esi, %eax
0x00471e77:	call 0x00475680
0x00471e7c:	addl %esp, $0xc<UINT8>
0x00471e7f:	movl %eax, %esi
0x00471e81:	popl %edi
0x00471e82:	popl %esi
0x00471e83:	popl %ebp
0x00471e84:	ret

0x004717fb:	movl %esi, %eax
0x004717fd:	addl %esp, $0x20<UINT8>
0x00471800:	testl %esi, %esi
0x00471802:	jne 0x00471810
0x00471810:	leal %eax, -12(%ebp)
0x00471813:	pushl %eax
0x00471814:	leal %eax, -4(%ebp)
0x00471817:	pushl %eax
0x00471818:	movl %eax, -4(%ebp)
0x0047181b:	leal %eax, (%esi,%eax,4)
0x0047181e:	pushl %eax
0x0047181f:	pushl %esi
0x00471820:	pushl %ebx
0x00471821:	call 0x004719f2
0x00471a17:	movl (%eax), %edi
0x00471a19:	addl %eax, $0x4<UINT8>
0x00471a1c:	movl 0xc(%ebp), %eax
0x00471a3c:	movb %al, (%esi)
0x00471a3e:	movb (%edi), %al
0x00471a40:	incl %edi
0x00471b5b:	andl (%ecx), $0x0<UINT8>
0x00471826:	addl %esp, $0x14<UINT8>
0x00471829:	cmpl 0x8(%ebp), $0x1<UINT8>
0x0047182d:	jne 22
0x0047182f:	movl %eax, -4(%ebp)
0x00471832:	decl %eax
0x00471833:	movl 0x4e3bb8, %eax
0x00471838:	movl %eax, %esi
0x0047183a:	movl %esi, %edi
0x0047183c:	movl 0x4e3bbc, %eax
0x00471841:	movl %ebx, %edi
0x00471843:	jmp 0x0047188f
0x0047188f:	pushl %esi
0x00471890:	call 0x00475680
0x00471895:	popl %ecx
0x00471896:	popl %edi
0x00471897:	movl %eax, %ebx
0x00471899:	popl %ebx
0x0047189a:	popl %esi
0x0047189b:	movl %esp, %ebp
0x0047189d:	popl %ebp
0x0047189e:	ret

0x004210bd:	popl %ecx
0x004210be:	popl %ecx
0x004210bf:	testl %eax, %eax
0x004210c1:	jne 74
0x004210c3:	call 0x00421e89
0x00421e89:	pushl $0x4e2998<UINT32>
0x00421e8e:	call InitializeSListHead@KERNEL32.DLL
InitializeSListHead@KERNEL32.DLL: API Node	
0x00421e94:	ret

0x004210c8:	call 0x00421ee4
0x00421ee4:	xorl %eax, %eax
0x00421ee6:	cmpl 0x4cff30, %eax
0x00421eec:	sete %al
0x00421eef:	ret

0x004210cd:	testl %eax, %eax
0x004210cf:	je 0x004210dc
0x004210dc:	call 0x00421ec5
0x00421ec5:	ret

0x004210e1:	call 0x00421ec6
0x00421ec6:	ret

0x004210e6:	call 0x00421ea4
0x00421ea4:	pushl $0x30000<UINT32>
0x00421ea9:	pushl $0x10000<UINT32>
0x00421eae:	pushl $0x0<UINT8>
0x00421eb0:	call 0x00474a54
0x00474a54:	movl %edi, %edi
0x00474a56:	pushl %ebp
0x00474a57:	movl %ebp, %esp
0x00474a59:	movl %ecx, 0x10(%ebp)
0x00474a5c:	movl %eax, 0xc(%ebp)
0x00474a5f:	andl %ecx, $0xfff7ffff<UINT32>
0x00474a65:	andl %eax, %ecx
0x00474a67:	pushl %esi
0x00474a68:	movl %esi, 0x8(%ebp)
0x00474a6b:	testl %eax, $0xfcf0fce0<UINT32>
0x00474a70:	je 0x00474a96
0x00474a96:	pushl %ecx
0x00474a97:	pushl 0xc(%ebp)
0x00474a9a:	testl %esi, %esi
0x00474a9c:	je 0x00474aa7
0x00474aa7:	call 0x00488e5a
0x00488e5a:	movl %edi, %edi
0x00488e5c:	pushl %ebp
0x00488e5d:	movl %ebp, %esp
0x00488e5f:	subl %esp, $0x10<UINT8>
0x00488e62:	fwait
0x00488e63:	fnstcw -8(%ebp)
0x00488e66:	movw %ax, -8(%ebp)
0x00488e6a:	xorl %ecx, %ecx
0x00488e6c:	testb %al, $0x1<UINT8>
0x00488e6e:	je 0x00488e73
0x00488e73:	testb %al, $0x4<UINT8>
0x00488e75:	je 0x00488e7a
0x00488e7a:	testb %al, $0x8<UINT8>
0x00488e7c:	je 3
0x00488e7e:	orl %ecx, $0x4<UINT8>
0x00488e81:	testb %al, $0x10<UINT8>
0x00488e83:	je 3
0x00488e85:	orl %ecx, $0x2<UINT8>
0x00488e88:	testb %al, $0x20<UINT8>
0x00488e8a:	je 0x00488e8f
0x00488e8f:	testb %al, $0x2<UINT8>
0x00488e91:	je 0x00488e99
0x00488e99:	pushl %ebx
0x00488e9a:	pushl %esi
0x00488e9b:	movzwl %esi, %ax
0x00488e9e:	movl %ebx, $0xc00<UINT32>
0x00488ea3:	movl %edx, %esi
0x00488ea5:	pushl %edi
0x00488ea6:	movl %edi, $0x200<UINT32>
0x00488eab:	andl %edx, %ebx
0x00488ead:	je 38
0x00488eaf:	cmpl %edx, $0x400<UINT32>
0x00488eb5:	je 24
0x00488eb7:	cmpl %edx, $0x800<UINT32>
0x00488ebd:	je 12
0x00488ebf:	cmpl %edx, %ebx
0x00488ec1:	jne 18
0x00488ec3:	orl %ecx, $0x300<UINT32>
0x00488ec9:	jmp 0x00488ed5
0x00488ed5:	andl %esi, $0x300<UINT32>
0x00488edb:	je 12
0x00488edd:	cmpl %esi, %edi
0x00488edf:	jne 0x00488eef
0x00488eef:	movl %edx, $0x1000<UINT32>
0x00488ef4:	testw %dx, %ax
0x00488ef7:	je 6
0x00488ef9:	orl %ecx, $0x40000<UINT32>
0x00488eff:	movl %edi, 0xc(%ebp)
0x00488f02:	movl %esi, %edi
0x00488f04:	movl %eax, 0x8(%ebp)
0x00488f07:	notl %esi
0x00488f09:	andl %esi, %ecx
0x00488f0b:	andl %eax, %edi
0x00488f0d:	orl %esi, %eax
0x00488f0f:	cmpl %esi, %ecx
0x00488f11:	je 166
0x00488f17:	pushl %esi
0x00488f18:	call 0x004891a8
0x004891a8:	movl %edi, %edi
0x004891aa:	pushl %ebp
0x004891ab:	movl %ebp, %esp
0x004891ad:	movl %ecx, 0x8(%ebp)
0x004891b0:	xorl %eax, %eax
0x004891b2:	testb %cl, $0x10<UINT8>
0x004891b5:	je 0x004891b8
0x004891b8:	testb %cl, $0x8<UINT8>
0x004891bb:	je 0x004891c0
0x004891c0:	testb %cl, $0x4<UINT8>
0x004891c3:	je 3
0x004891c5:	orl %eax, $0x8<UINT8>
0x004891c8:	testb %cl, $0x2<UINT8>
0x004891cb:	je 3
0x004891cd:	orl %eax, $0x10<UINT8>
0x004891d0:	testb %cl, $0x1<UINT8>
0x004891d3:	je 0x004891d8
0x004891d8:	testl %ecx, $0x80000<UINT32>
0x004891de:	je 0x004891e3
0x004891e3:	pushl %esi
0x004891e4:	movl %edx, %ecx
0x004891e6:	movl %esi, $0x300<UINT32>
0x004891eb:	pushl %edi
0x004891ec:	movl %edi, $0x200<UINT32>
0x004891f1:	andl %edx, %esi
0x004891f3:	je 35
0x004891f5:	cmpl %edx, $0x100<UINT32>
0x004891fb:	je 22
0x004891fd:	cmpl %edx, %edi
0x004891ff:	je 11
0x00489201:	cmpl %edx, %esi
0x00489203:	jne 19
0x00489205:	orl %eax, $0xc00<UINT32>
0x0048920a:	jmp 0x00489218
0x00489218:	movl %edx, %ecx
0x0048921a:	andl %edx, $0x30000<UINT32>
0x00489220:	je 12
0x00489222:	cmpl %edx, $0x10000<UINT32>
0x00489228:	jne 6
0x0048922a:	orl %eax, %edi
0x0048922c:	jmp 0x00489230
0x00489230:	popl %edi
0x00489231:	popl %esi
0x00489232:	testl %ecx, $0x40000<UINT32>
0x00489238:	je 5
0x0048923a:	orl %eax, $0x1000<UINT32>
0x0048923f:	popl %ebp
0x00489240:	ret

0x00488f1d:	popl %ecx
0x00488f1e:	movw -4(%ebp), %ax
0x00488f22:	fldcw -4(%ebp)
0x00488f25:	fwait
0x00488f26:	fnstcw -4(%ebp)
0x00488f29:	movw %ax, -4(%ebp)
0x00488f2d:	xorl %esi, %esi
0x00488f2f:	testb %al, $0x1<UINT8>
0x00488f31:	je 0x00488f36
0x00488f36:	testb %al, $0x4<UINT8>
0x00488f38:	je 0x00488f3d
0x00488f3d:	testb %al, $0x8<UINT8>
0x00488f3f:	je 3
0x00488f41:	orl %esi, $0x4<UINT8>
0x00488f44:	testb %al, $0x10<UINT8>
0x00488f46:	je 3
0x00488f48:	orl %esi, $0x2<UINT8>
0x00488f4b:	testb %al, $0x20<UINT8>
0x00488f4d:	je 0x00488f52
0x00488f52:	testb %al, $0x2<UINT8>
0x00488f54:	je 0x00488f5c
0x00488f5c:	movzwl %edx, %ax
0x00488f5f:	movl %ecx, %edx
0x00488f61:	andl %ecx, %ebx
0x00488f63:	je 42
0x00488f65:	cmpl %ecx, $0x400<UINT32>
0x00488f6b:	je 28
0x00488f6d:	cmpl %ecx, $0x800<UINT32>
0x00488f73:	je 12
0x00488f75:	cmpl %ecx, %ebx
0x00488f77:	jne 22
0x00488f79:	orl %esi, $0x300<UINT32>
0x00488f7f:	jmp 0x00488f8f
0x00488f8f:	andl %edx, $0x300<UINT32>
0x00488f95:	je 16
0x00488f97:	cmpl %edx, $0x200<UINT32>
0x00488f9d:	jne 14
0x00488f9f:	orl %esi, $0x10000<UINT32>
0x00488fa5:	jmp 0x00488fad
0x00488fad:	movl %edx, $0x1000<UINT32>
0x00488fb2:	testw %dx, %ax
0x00488fb5:	je 6
0x00488fb7:	orl %esi, $0x40000<UINT32>
0x00488fbd:	cmpl 0x4e2988, $0x1<UINT8>
0x00488fc4:	jl 393
0x00488fca:	andl %edi, $0x308031f<UINT32>
0x00488fd0:	stmxcsr -16(%ebp)
0x00488fd4:	movl %eax, -16(%ebp)
0x00488fd7:	xorl %ecx, %ecx
0x00488fd9:	testb %al, %al
0x00488fdb:	jns 0x00488fe0
0x00488fe0:	testl %eax, $0x200<UINT32>
0x00488fe5:	je 3
0x00488fe7:	orl %ecx, $0x8<UINT8>
0x00488fea:	testl %eax, $0x400<UINT32>
0x00488fef:	je 3
0x00488ff1:	orl %ecx, $0x4<UINT8>
0x00488ff4:	testl %eax, $0x800<UINT32>
0x00488ff9:	je 3
0x00488ffb:	orl %ecx, $0x2<UINT8>
0x00488ffe:	testl %edx, %eax
0x00489000:	je 3
0x00489002:	orl %ecx, $0x1<UINT8>
0x00489005:	testl %eax, $0x100<UINT32>
0x0048900a:	je 0x00489012
0x00489012:	movl %edx, %eax
0x00489014:	movl %ebx, $0x6000<UINT32>
0x00489019:	andl %edx, %ebx
0x0048901b:	je 0x00489047
0x00489047:	pushl $0x40<UINT8>
0x00489049:	andl %eax, $0x8040<UINT32>
0x0048904e:	popl %ebx
0x0048904f:	subl %eax, %ebx
0x00489051:	je 27
0x00489053:	subl %eax, $0x7fc0<UINT32>
0x00489058:	je 12
0x0048905a:	subl %eax, %ebx
0x0048905c:	jne 0x00489074
0x00489074:	movl %eax, %edi
0x00489076:	andl %edi, 0x8(%ebp)
0x00489079:	notl %eax
0x0048907b:	andl %eax, %ecx
0x0048907d:	orl %eax, %edi
0x0048907f:	cmpl %eax, %ecx
0x00489081:	je 0x0048913c
0x0048913c:	movl %eax, %ecx
0x0048913e:	orl %ecx, %esi
0x00489140:	xorl %eax, %esi
0x00489142:	testl %eax, $0x8031f<UINT32>
0x00489147:	je 6
0x00489149:	orl %ecx, $0x80000000<UINT32>
0x0048914f:	movl %eax, %ecx
0x00489151:	jmp 0x00489155
0x00489155:	popl %edi
0x00489156:	popl %esi
0x00489157:	popl %ebx
0x00489158:	movl %esp, %ebp
0x0048915a:	popl %ebp
0x0048915b:	ret

0x00474aac:	popl %ecx
0x00474aad:	popl %ecx
0x00474aae:	xorl %eax, %eax
0x00474ab0:	popl %esi
0x00474ab1:	popl %ebp
0x00474ab2:	ret

0x00421eb5:	addl %esp, $0xc<UINT8>
0x00421eb8:	testl %eax, %eax
0x00421eba:	jne 1
0x00421ebc:	ret

0x004210eb:	call 0x00421e86
0x00421e86:	xorl %eax, %eax
0x00421e88:	ret

0x004210f0:	pushl %eax
0x004210f1:	call 0x004739bd
0x004739bd:	movl %edi, %edi
0x004739bf:	pushl %ebp
0x004739c0:	movl %ebp, %esp
0x004739c2:	pushl %esi
0x004739c3:	call 0x0047ad28
0x004739c8:	movl %edx, 0x8(%ebp)
0x004739cb:	movl %esi, %eax
0x004739cd:	pushl $0x0<UINT8>
0x004739cf:	popl %eax
0x004739d0:	movl %ecx, 0x350(%esi)
0x004739d6:	testb %cl, $0x2<UINT8>
0x004739d9:	sete %al
0x004739dc:	incl %eax
0x004739dd:	cmpl %edx, $0xffffffff<UINT8>
0x004739e0:	je 51
0x004739e2:	testl %edx, %edx
0x004739e4:	je 0x00473a1c
0x00473a1c:	popl %esi
0x00473a1d:	popl %ebp
0x00473a1e:	ret

0x004210f6:	popl %ecx
0x004210f7:	call 0x00421ea1
0x00421ea1:	movb %al, $0x1<UINT8>
0x00421ea3:	ret

0x004210fc:	testb %al, %al
0x004210fe:	je 5
0x00421100:	call 0x00472694
0x00472694:	jmp 0x00471f3f
0x00471f3f:	cmpl 0x4e30f4, $0x0<UINT8>
0x00471f46:	je 0x00471f4b
0x00471f4b:	pushl %esi
0x00471f4c:	pushl %edi
0x00471f4d:	call 0x004846c0
0x00471f52:	call 0x00484b8c
0x00484b8c:	movl %edi, %edi
0x00484b8e:	pushl %ebp
0x00484b8f:	movl %ebp, %esp
0x00484b91:	pushl %ecx
0x00484b92:	pushl %ebx
0x00484b93:	pushl %esi
0x00484b94:	pushl %edi
0x00484b95:	call GetEnvironmentStringsW@KERNEL32.DLL
GetEnvironmentStringsW@KERNEL32.DLL: API Node	
0x00484b9b:	movl %esi, %eax
0x00484b9d:	xorl %edi, %edi
0x00484b9f:	testl %esi, %esi
0x00484ba1:	je 86
0x00484ba3:	pushl %esi
0x00484ba4:	call 0x00484b47
0x00484b47:	movl %edi, %edi
0x00484b49:	pushl %ebp
0x00484b4a:	movl %ebp, %esp
0x00484b4c:	movl %edx, 0x8(%ebp)
0x00484b4f:	pushl %edi
0x00484b50:	xorl %edi, %edi
0x00484b52:	cmpw (%edx), %di
0x00484b55:	je 33
0x00484b57:	pushl %esi
0x00484b58:	movl %ecx, %edx
0x00484b5a:	leal %esi, 0x2(%ecx)
0x00484b5d:	movw %ax, (%ecx)
0x00484b60:	addl %ecx, $0x2<UINT8>
0x00484b63:	cmpw %ax, %di
0x00484b66:	jne 0x00484b5d
0x00484b68:	subl %ecx, %esi
0x00484b6a:	sarl %ecx
0x00484b6c:	leal %edx, (%edx,%ecx,2)
0x00484b6f:	addl %edx, $0x2<UINT8>
0x00484b72:	cmpw (%edx), %di
0x00484b75:	jne 0x00484b58
0x00484b77:	popl %esi
0x00484b78:	leal %eax, 0x2(%edx)
0x00484b7b:	popl %edi
0x00484b7c:	popl %ebp
0x00484b7d:	ret

0x00484ba9:	popl %ecx
0x00484baa:	pushl %edi
0x00484bab:	pushl %edi
0x00484bac:	pushl %edi
0x00484bad:	movl %ebx, %eax
0x00484baf:	pushl %edi
0x00484bb0:	subl %ebx, %esi
0x00484bb2:	sarl %ebx
0x00484bb4:	pushl %ebx
0x00484bb5:	pushl %esi
0x00484bb6:	pushl %edi
0x00484bb7:	pushl %edi
0x00484bb8:	call WideCharToMultiByte@KERNEL32.DLL
WideCharToMultiByte@KERNEL32.DLL: API Node	
0x00484bbe:	movl -4(%ebp), %eax
0x00484bc1:	testl %eax, %eax
0x00484bc3:	je 52
0x00484bc5:	pushl %eax
0x00484bc6:	call 0x004756ba
0x00484bcb:	movl %edi, %eax
0x00484bcd:	popl %ecx
0x00484bce:	testl %edi, %edi
0x00484bd0:	je 28
0x00484bd2:	xorl %eax, %eax
0x00484bd4:	pushl %eax
0x00484bd5:	pushl %eax
0x00484bd6:	pushl -4(%ebp)
0x00484bd9:	pushl %edi
0x00484bda:	pushl %ebx
0x00484bdb:	pushl %esi
0x00484bdc:	pushl %eax
0x00484bdd:	pushl %eax
0x00484bde:	call WideCharToMultiByte@KERNEL32.DLL
0x00484be4:	testl %eax, %eax
0x00484be6:	je 6
0x00484be8:	movl %ebx, %edi
0x00484bea:	xorl %edi, %edi
0x00484bec:	jmp 0x00484bf0
0x00484bf0:	pushl %edi
0x00484bf1:	call 0x00475680
0x00484bf6:	popl %ecx
0x00484bf7:	jmp 0x00484bfb
0x00484bfb:	testl %esi, %esi
0x00484bfd:	je 7
0x00484bff:	pushl %esi
0x00484c00:	call FreeEnvironmentStringsW@KERNEL32.DLL
FreeEnvironmentStringsW@KERNEL32.DLL: API Node	
0x00484c06:	popl %edi
0x00484c07:	popl %esi
0x00484c08:	movl %eax, %ebx
0x00484c0a:	popl %ebx
0x00484c0b:	movl %esp, %ebp
0x00484c0d:	popl %ebp
0x00484c0e:	ret

0x00471f57:	movl %esi, %eax
0x00471f59:	testl %esi, %esi
0x00471f5b:	jne 0x00471f62
0x00471f62:	pushl %esi
0x00471f63:	call 0x00472067
0x00472067:	movl %edi, %edi
0x00472069:	pushl %ebp
0x0047206a:	movl %ebp, %esp
0x0047206c:	pushl %ecx
0x0047206d:	pushl %ecx
0x0047206e:	pushl %ebx
0x0047206f:	pushl %esi
0x00472070:	pushl %edi
0x00472071:	movl %edi, 0x8(%ebp)
0x00472074:	xorl %edx, %edx
0x00472076:	movl %esi, %edi
0x00472078:	movb %al, (%edi)
0x0047207a:	jmp 0x00472094
0x00472094:	testb %al, %al
0x00472096:	jne 0x0047207c
0x0047207c:	cmpb %al, $0x3d<UINT8>
0x0047207e:	je 0x00472081
0x00472081:	movl %ecx, %esi
0x00472083:	leal %ebx, 0x1(%ecx)
0x00472086:	movb %al, (%ecx)
0x00472088:	incl %ecx
0x00472089:	testb %al, %al
0x0047208b:	jne 0x00472086
0x0047208d:	subl %ecx, %ebx
0x0047208f:	incl %esi
0x00472090:	addl %esi, %ecx
0x00472092:	movb %al, (%esi)
0x00472098:	leal %eax, 0x1(%edx)
0x0047209b:	pushl $0x4<UINT8>
0x0047209d:	pushl %eax
0x0047209e:	call 0x00474b65
0x004720a3:	movl %ebx, %eax
0x004720a5:	popl %ecx
0x004720a6:	popl %ecx
0x004720a7:	testl %ebx, %ebx
0x004720a9:	je 109
0x004720ab:	movl -4(%ebp), %ebx
0x004720ae:	jmp 0x00472102
0x00472102:	cmpb (%edi), $0x0<UINT8>
0x00472105:	jne 0x004720b0
0x004720b0:	movl %ecx, %edi
0x004720b2:	leal %edx, 0x1(%ecx)
0x004720b5:	movb %al, (%ecx)
0x004720b7:	incl %ecx
0x004720b8:	testb %al, %al
0x004720ba:	jne 0x004720b5
0x004720bc:	subl %ecx, %edx
0x004720be:	cmpb (%edi), $0x3d<UINT8>
0x004720c1:	leal %eax, 0x1(%ecx)
0x004720c4:	movl -8(%ebp), %eax
0x004720c7:	je 0x00472100
0x00472100:	addl %edi, %eax
0x00472107:	jmp 0x0047211a
0x0047211a:	pushl $0x0<UINT8>
0x0047211c:	call 0x00475680
0x00472121:	popl %ecx
0x00472122:	popl %edi
0x00472123:	popl %esi
0x00472124:	movl %eax, %ebx
0x00472126:	popl %ebx
0x00472127:	movl %esp, %ebp
0x00472129:	popl %ebp
0x0047212a:	ret

0x00471f68:	popl %ecx
0x00471f69:	testl %eax, %eax
0x00471f6b:	jne 0x00471f72
0x00471f72:	pushl %eax
0x00471f73:	movl %ecx, $0x4e30f4<UINT32>
0x00471f78:	movl 0x4e3100, %eax
0x00471f7d:	call 0x00472599
0x00472599:	movl %edi, %edi
0x0047259b:	pushl %ebp
0x0047259c:	movl %ebp, %esp
0x0047259e:	leal %eax, 0x4(%ecx)
0x004725a1:	movl %edx, %eax
0x004725a3:	subl %edx, %ecx
0x004725a5:	addl %edx, $0x3<UINT8>
0x004725a8:	pushl %esi
0x004725a9:	xorl %esi, %esi
0x004725ab:	shrl %edx, $0x2<UINT8>
0x004725ae:	cmpl %eax, %ecx
0x004725b0:	sbbl %eax, %eax
0x004725b2:	notl %eax
0x004725b4:	andl %eax, %edx
0x004725b6:	je 13
0x004725b8:	movl %edx, 0x8(%ebp)
0x004725bb:	incl %esi
0x004725bc:	movl (%ecx), %edx
0x004725be:	leal %ecx, 0x4(%ecx)
0x004725c1:	cmpl %esi, %eax
0x004725c3:	jne -10
0x004725c5:	popl %esi
0x004725c6:	popl %ebp
0x004725c7:	ret $0x4<UINT16>

0x00471f82:	xorl %edi, %edi
0x00471f84:	pushl $0x0<UINT8>
0x00471f86:	call 0x00475680
0x00471f8b:	popl %ecx
0x00471f8c:	pushl %esi
0x00471f8d:	call 0x00475680
0x0047568b:	pushl 0x8(%ebp)
0x0047568e:	pushl $0x0<UINT8>
0x00475690:	pushl 0x4e3bd4
0x00475696:	call HeapFree@KERNEL32.DLL
HeapFree@KERNEL32.DLL: API Node	
0x0047569c:	testl %eax, %eax
0x0047569e:	jne 0x004756b8
0x00471f92:	popl %ecx
0x00471f93:	movl %eax, %edi
0x00471f95:	popl %edi
0x00471f96:	popl %esi
0x00471f97:	ret

0x00421105:	call 0x00421cd2
0x00421cd2:	xorl %eax, %eax
0x00421cd4:	ret

0x0042110a:	xorl %eax, %eax
0x0042110c:	ret

0x004731d4:	testl %eax, %eax
0x004731d6:	jne 10
0x00421115:	call 0x00421ec7
0x00421ec7:	call 0x00401310
0x00401310:	movl %eax, $0x4e5818<UINT32>
0x00401315:	ret

0x00421ecc:	movl %ecx, 0x4(%eax)
0x00421ecf:	orl (%eax), $0x4<UINT8>
0x00421ed2:	movl 0x4(%eax), %ecx
0x00421ed5:	call 0x00411d70
0x00411d70:	movl %eax, $0x4df478<UINT32>
0x00411d75:	ret

0x00421eda:	movl %ecx, 0x4(%eax)
0x00421edd:	orl (%eax), $0x2<UINT8>
0x00421ee0:	movl 0x4(%eax), %ecx
0x00421ee3:	ret

0x0042111a:	xorl %eax, %eax
0x0042111c:	ret

0x004215ea:	pushl %ebx
0x004215eb:	pushl %esi
0x004215ec:	pushl %edi
0x004215ed:	pushl $0x0<UINT8>
0x004215ef:	pushl $0xfa0<UINT32>
0x004215f4:	pushl $0x4e295c<UINT32>
0x004215f9:	call 0x00440f9a
0x004215fe:	addl %esp, $0xc<UINT8>
0x00421601:	pushl $0x4b19f0<UINT32>
0x00421606:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0042160c:	movl %esi, %eax
0x0042160e:	testl %esi, %esi
0x00421610:	je 140
0x00421616:	pushl $0x4b1a0c<UINT32>
0x0042161b:	pushl %esi
0x0042161c:	call GetProcAddress@KERNEL32.DLL
0x00421622:	pushl $0x4b1a28<UINT32>
0x00421627:	pushl %esi
0x00421628:	movl %ebx, %eax
0x0042162a:	call GetProcAddress@KERNEL32.DLL
0x00421630:	pushl $0x4b1a44<UINT32>
0x00421635:	pushl %esi
0x00421636:	movl %edi, %eax
0x00421638:	call GetProcAddress@KERNEL32.DLL
0x0042163e:	movl %esi, %eax
0x00421640:	testl %ebx, %ebx
0x00421642:	je 55
0x00421644:	testl %edi, %edi
0x00421646:	je 51
0x00421648:	testl %esi, %esi
0x0042164a:	je 47
0x0042164c:	andl 0x4e2978, $0x0<UINT8>
0x00421653:	movl %ecx, %ebx
0x00421655:	pushl $0x4e2974<UINT32>
0x0042165a:	call 0x00421d6e
0x0042165f:	call InitializeConditionVariable@kernel32.dll
InitializeConditionVariable@kernel32.dll: API Node	
0x00421661:	pushl %edi
0x00421662:	call 0x004216d2
0x004216d2:	pushl %ebp
0x004216d3:	movl %ebp, %esp
0x004216d5:	movl %eax, 0x4cff1c
0x004216da:	andl %eax, $0x1f<UINT8>
0x004216dd:	pushl $0x20<UINT8>
0x004216df:	popl %ecx
0x004216e0:	subl %ecx, %eax
0x004216e2:	movl %eax, 0x8(%ebp)
0x004216e5:	rorl %eax, %cl
0x004216e7:	xorl %eax, 0x4cff1c
0x004216ed:	popl %ebp
0x004216ee:	ret

0x00421667:	pushl %esi
0x00421668:	movl 0x4e297c, %eax
0x0042166d:	call 0x004216ef
0x004216ef:	pushl %ebp
0x004216f0:	movl %ebp, %esp
0x004216f2:	movl %eax, 0x4cff1c
0x004216f7:	andl %eax, $0x1f<UINT8>
0x004216fa:	pushl $0x20<UINT8>
0x004216fc:	popl %ecx
0x004216fd:	subl %ecx, %eax
0x004216ff:	movl %eax, 0x8(%ebp)
0x00421702:	rorl %eax, %cl
0x00421704:	xorl %eax, 0x4cff1c
0x0042170a:	popl %ebp
0x0042170b:	ret

0x00421672:	popl %ecx
0x00421673:	popl %ecx
0x00421674:	movl 0x4e2980, %eax
0x00421679:	jmp 0x00421691
0x00421691:	pushl $0x42170c<UINT32>
0x00421696:	call 0x0042104e
0x0042169b:	popl %ecx
0x0042169c:	popl %edi
0x0042169d:	popl %esi
0x0042169e:	xorl %eax, %eax
0x004216a0:	popl %ebx
0x004216a1:	ret

0x7efde000:	addb (%eax), %al
0x0043e560:	pushl %ebp
0x0043e561:	movl %ebp, %esp
0x0043e563:	subl %esp, $0x1c<UINT8>
0x0043e566:	pushl %ebx
0x0043e567:	pushl %esi
0x0043e568:	movl %esi, 0xc(%ebp)
0x0043e56b:	pushl %edi
0x0043e56c:	movb -1(%ebp), $0x0<UINT8>
0x0043e570:	movl -12(%ebp), $0x1<UINT32>
0x0043e577:	movl %ebx, 0x8(%esi)
0x0043e57a:	leal %eax, 0x10(%esi)
0x0043e57d:	xorl %ebx, 0x4cff1c
0x0043e583:	pushl %eax
0x0043e584:	pushl %ebx
0x0043e585:	movl -20(%ebp), %eax
0x0043e588:	movl -8(%ebp), %ebx
0x0043e58b:	call 0x0043e520
0x0043e520:	pushl %ebp
0x0043e521:	movl %ebp, %esp
0x0043e523:	pushl %esi
0x0043e524:	movl %esi, 0x8(%ebp)
0x0043e527:	pushl %edi
0x0043e528:	movl %edi, 0xc(%ebp)
0x0043e52b:	movl %eax, (%esi)
0x0043e52d:	cmpl %eax, $0xfffffffe<UINT8>
0x0043e530:	je 0x0043e53f
0x0043e53f:	movl %eax, 0x8(%esi)
0x0043e542:	movl %ecx, 0xc(%esi)
0x0043e545:	addl %ecx, %edi
0x0043e547:	xorl %ecx, (%eax,%edi)
0x0043e54a:	popl %edi
0x0043e54b:	popl %esi
0x0043e54c:	popl %ebp
0x0043e54d:	jmp 0x00420bd0
0x0043e590:	movl %edi, 0x10(%ebp)
0x0043e593:	pushl %edi
0x0043e594:	call 0x004445bc
0x004445bc:	ret

0x0043e599:	movl %eax, 0x8(%ebp)
0x0043e59c:	addl %esp, $0xc<UINT8>
0x0043e59f:	testb 0x4(%eax), $0x66<UINT8>
0x0043e5a3:	jne 186
0x0043e5a9:	movl -28(%ebp), %eax
0x0043e5ac:	leal %eax, -28(%ebp)
0x0043e5af:	movl -24(%ebp), %edi
0x0043e5b2:	movl %edi, 0xc(%esi)
0x0043e5b5:	movl -4(%esi), %eax
0x0043e5b8:	cmpl %edi, $0xfffffffe<UINT8>
0x0043e5bb:	je 201
0x0043e5c1:	leal %eax, 0x2(%edi)
0x0043e5c4:	leal %eax, (%edi,%eax,2)
0x0043e5c7:	movl %ecx, 0x4(%ebx,%eax,4)
0x0043e5cb:	leal %eax, (%ebx,%eax,4)
0x0043e5ce:	movl %ebx, (%eax)
0x0043e5d0:	movl -16(%ebp), %eax
0x0043e5d3:	testl %ecx, %ecx
0x0043e5d5:	je 101
0x0043e5d7:	leal %edx, 0x10(%esi)
0x0043e5da:	call 0x004446fe
0x004446fe:	pushl %ebp
0x004446ff:	pushl %esi
0x00444700:	pushl %edi
0x00444701:	pushl %ebx
0x00444702:	movl %ebp, %edx
0x00444704:	xorl %eax, %eax
0x00444706:	xorl %ebx, %ebx
0x00444708:	xorl %edx, %edx
0x0044470a:	xorl %esi, %esi
0x0044470c:	xorl %edi, %edi
0x0044470e:	call 0x0042125e
0x0042125e:	movl %ecx, -20(%ebp)
0x00421261:	movl %eax, (%ecx)
0x00421263:	movl %eax, (%eax)
0x00421265:	movl -32(%ebp), %eax
0x00421268:	pushl %ecx
0x00421269:	pushl %eax
0x0042126a:	call 0x0047122e
0x0047122e:	movl %edi, %edi
0x00471230:	pushl %ebp
0x00471231:	movl %ebp, %esp
0x00471233:	pushl %ecx
0x00471234:	pushl %ecx
0x00471235:	movl %eax, 0x4cff1c
0x0047123a:	xorl %eax, %ebp
0x0047123c:	movl -4(%ebp), %eax
0x0047123f:	pushl %esi
0x00471240:	call 0x0047adac
0x00471245:	movl %esi, %eax
0x00471247:	testl %esi, %esi
0x00471249:	je 323
0x0047124f:	movl %edx, (%esi)
0x00471251:	movl %ecx, %edx
0x00471253:	pushl %ebx
0x00471254:	xorl %ebx, %ebx
0x00471256:	pushl %edi
0x00471257:	leal %eax, 0x90(%edx)
0x0047125d:	cmpl %edx, %eax
0x0047125f:	je 14
0x00471261:	movl %edi, 0x8(%ebp)
0x00471264:	cmpl (%ecx), %edi
0x00471266:	je 9
0x00471268:	addl %ecx, $0xc<UINT8>
0x0047126b:	cmpl %ecx, %eax
0x0047126d:	jne 0x00471264
0x0047126f:	movl %ecx, %ebx
0x00471271:	testl %ecx, %ecx
0x00471273:	je 0x0047127c
0x0047127c:	xorl %eax, %eax
0x0047127e:	jmp 0x00471390
0x00471390:	popl %edi
0x00471391:	popl %ebx
0x00471392:	movl %ecx, -4(%ebp)
0x00471395:	xorl %ecx, %ebp
0x00471397:	popl %esi
0x00471398:	call 0x00420bd0
0x0047139d:	movl %esp, %ebp
0x0047139f:	popl %ebp
0x004713a0:	ret

0x0042126f:	popl %ecx
0x00421270:	popl %ecx
0x00421271:	ret

0x00444710:	popl %ebx
0x00444711:	popl %edi
0x00444712:	popl %esi
0x00444713:	popl %ebp
0x00444714:	ret

0x0043e5df:	movb %cl, $0x1<UINT8>
0x0043e5e1:	movb -1(%ebp), %cl
0x0043e5e4:	testl %eax, %eax
0x0043e5e6:	js 102
0x0043e5e8:	jle 0x0043e63f
0x0043e63f:	movl %edi, %ebx
0x0043e641:	cmpl %ebx, $0xfffffffe<UINT8>
0x0043e644:	je 0x0043e65a
0x0043e65a:	testb %cl, %cl
0x0043e65c:	je 44
0x0043e65e:	movl %ebx, -8(%ebp)
0x0043e661:	jmp 0x0043e67e
0x0043e67e:	pushl -20(%ebp)
0x0043e681:	pushl %ebx
0x0043e682:	call 0x0043e520
0x0043e687:	addl %esp, $0x8<UINT8>
0x0043e68a:	movl %eax, -12(%ebp)
0x0043e68d:	popl %edi
0x0043e68e:	popl %esi
0x0043e68f:	popl %ebx
0x0043e690:	movl %esp, %ebp
0x0043e692:	popl %ebp
0x0043e693:	ret

0x7efde002:	addb (%eax), %al
0x7efde004:	nop
0x7efde006:	nop
0x7efde008:	addb (%eax), %al
0x7efde00a:	incl %eax
0x7efde00b:	addb 0x241e(%eax), %ah
0x7efde011:	addb (%eax), %al
0x7efde013:	addb (%eax), %al
0x7efde015:	addb (%eax), %al
0x7efde017:	addb (%eax), %al
0x7efde019:	addb (%eax), %al
0x7efde01b:	addb (%eax), %al
0x7efde01d:	addb (%eax), %al
0x7efde01f:	addb (%eax), %al
0x7efde021:	addb (%eax), %al
0x7efde023:	addb (%eax), %al
0x7efde025:	addb (%eax), %al
0x7efde027:	addb (%eax), %al
0x7efde029:	addb (%eax), %al
0x7efde02b:	addb (%eax), %al
0x7efde02d:	addb (%eax), %al
0x7efde02f:	addb (%eax), %al
0x7efde031:	addb (%eax), %al
0x7efde033:	addb (%eax), %al
0x7efde035:	addb (%eax), %al
0x7efde037:	addb (%eax), %al
0x7efde039:	addb (%eax), %al
0x7efde03b:	addb (%eax), %al
0x7efde03d:	addb (%eax), %al
0x7efde03f:	addb (%eax), %al
0x7efde041:	addb (%eax), %al
0x7efde043:	addb (%eax), %al
0x7efde045:	addb (%eax), %al
0x7efde047:	addb (%eax), %al
0x7efde049:	addb (%eax), %al
0x7efde04b:	addb (%eax), %al
0x7efde04d:	addb (%eax), %al
0x7efde04f:	addb (%eax), %al
0x7efde051:	addb (%eax), %al
0x7efde053:	addb (%eax), %al
0x7efde055:	addb (%eax), %al
0x7efde057:	addb (%eax), %al
0x7efde059:	addb (%eax), %al
0x7efde05b:	addb (%eax), %al
0x7efde05d:	addb (%eax), %al
0x7efde05f:	addb (%eax), %al
0x7efde061:	addb (%eax), %al
0x7efde063:	addb (%eax), %al
0x7efde065:	addb (%eax), %al
0x7efde067:	addb (%eax), %al
0x7efde069:	addb (%eax), %al
0x7efde06b:	addb (%eax), %al
0x7efde06d:	addb (%eax), %al
0x7efde06f:	addb (%eax), %al
0x0047b4c0:	je 0x0047b4fa
0x0047b4fa:	leal %edx, (%esi,%esi)
0x0047b4fd:	leal %ecx, 0x8(%edx)
0x0047b500:	cmpl %edx, %ecx
0x0047b502:	sbbl %eax, %eax
0x0047b504:	testl %ecx, %eax
0x0047b506:	je 0x0047b552
0x0047b552:	xorl %edi, %edi
0x0047b554:	testl %edi, %edi
0x0047b556:	je 0x0047b590
0x0047b590:	pushl %edi
0x0047b591:	call 0x00423add
0x0047b596:	popl %ecx
0x00000000:	addb (%eax), %al
0x00000002:	addb (%eax), %al
0x00000004:	addb (%eax), %al
0x00000006:	addb (%eax), %al
0x00000008:	addb (%eax), %al
0x0000000a:	addb (%eax), %al
0x0000000c:	addb (%eax), %al
0x0000000e:	addb (%eax), %al
0x00000010:	addb (%eax), %al
0x00000012:	addb (%eax), %al
0x00000014:	addb (%eax), %al
0x00000016:	addb (%eax), %al
0x00000018:	addb (%eax), %al
0x0000001a:	addb (%eax), %al
0x0000001c:	addb (%eax), %al
0x0000001e:	addb (%eax), %al
0x00000020:	addb (%eax), %al
0x00000022:	addb (%eax), %al
0x00000024:	addb (%eax), %al
0x00000026:	addb (%eax), %al
0x00000028:	addb (%eax), %al
0x0000002a:	addb (%eax), %al
0x0000002c:	addb (%eax), %al
0x0000002e:	addb (%eax), %al
0x00000030:	addb (%eax), %al
0x00000032:	addb (%eax), %al
0x00000034:	addb (%eax), %al
0x00000036:	addb (%eax), %al
0x00000038:	addb (%eax), %al
0x0000003a:	addb (%eax), %al
0x0000003c:	addb (%eax), %al
0x0000003e:	addb (%eax), %al
0x00000040:	addb (%eax), %al
0x00000042:	addb (%eax), %al
0x00000044:	addb (%eax), %al
0x00000046:	addb (%eax), %al
0x00000048:	addb (%eax), %al
0x0000004a:	addb (%eax), %al
0x0000004c:	addb (%eax), %al
0x0000004e:	addb (%eax), %al
0x00000050:	addb (%eax), %al
0x00000052:	addb (%eax), %al
0x00000054:	addb (%eax), %al
0x00000056:	addb (%eax), %al
0x00000058:	addb (%eax), %al
0x0000005a:	addb (%eax), %al
0x0000005c:	addb (%eax), %al
0x0000005e:	addb (%eax), %al
0x00000060:	addb (%eax), %al
0x00000062:	addb (%eax), %al
0x00000064:	addb (%eax), %al
