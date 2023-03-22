0x0043ce80:	pusha
0x0043ce81:	movl %esi, $0x42d000<UINT32>
0x0043ce86:	leal %edi, -180224(%esi)
0x0043ce8c:	pushl %edi
0x0043ce8d:	jmp 0x0043ce9a
0x0043ce9a:	movl %ebx, (%esi)
0x0043ce9c:	subl %esi, $0xfffffffc<UINT8>
0x0043ce9f:	adcl %ebx, %ebx
0x0043cea1:	jb 0x0043ce90
0x0043ce90:	movb %al, (%esi)
0x0043ce92:	incl %esi
0x0043ce93:	movb (%edi), %al
0x0043ce95:	incl %edi
0x0043ce96:	addl %ebx, %ebx
0x0043ce98:	jne 0x0043cea1
0x0043cea3:	movl %eax, $0x1<UINT32>
0x0043cea8:	addl %ebx, %ebx
0x0043ceaa:	jne 0x0043ceb3
0x0043ceb3:	adcl %eax, %eax
0x0043ceb5:	addl %ebx, %ebx
0x0043ceb7:	jae 0x0043cea8
0x0043ceb9:	jne 0x0043cec4
0x0043cec4:	xorl %ecx, %ecx
0x0043cec6:	subl %eax, $0x3<UINT8>
0x0043cec9:	jb 0x0043ced8
0x0043cecb:	shll %eax, $0x8<UINT8>
0x0043cece:	movb %al, (%esi)
0x0043ced0:	incl %esi
0x0043ced1:	xorl %eax, $0xffffffff<UINT8>
0x0043ced4:	je 0x0043cf4a
0x0043ced6:	movl %ebp, %eax
0x0043ced8:	addl %ebx, %ebx
0x0043ceda:	jne 0x0043cee3
0x0043cee3:	adcl %ecx, %ecx
0x0043cee5:	addl %ebx, %ebx
0x0043cee7:	jne 0x0043cef0
0x0043cef0:	adcl %ecx, %ecx
0x0043cef2:	jne 0x0043cf14
0x0043cf14:	cmpl %ebp, $0xfffff300<UINT32>
0x0043cf1a:	adcl %ecx, $0x1<UINT8>
0x0043cf1d:	leal %edx, (%edi,%ebp)
0x0043cf20:	cmpl %ebp, $0xfffffffc<UINT8>
0x0043cf23:	jbe 0x0043cf34
0x0043cf34:	movl %eax, (%edx)
0x0043cf36:	addl %edx, $0x4<UINT8>
0x0043cf39:	movl (%edi), %eax
0x0043cf3b:	addl %edi, $0x4<UINT8>
0x0043cf3e:	subl %ecx, $0x4<UINT8>
0x0043cf41:	ja 0x0043cf34
0x0043cf43:	addl %edi, %ecx
0x0043cf45:	jmp 0x0043ce96
0x0043ceac:	movl %ebx, (%esi)
0x0043ceae:	subl %esi, $0xfffffffc<UINT8>
0x0043ceb1:	adcl %ebx, %ebx
0x0043cef4:	incl %ecx
0x0043cef5:	addl %ebx, %ebx
0x0043cef7:	jne 0x0043cf00
0x0043cf00:	adcl %ecx, %ecx
0x0043cf02:	addl %ebx, %ebx
0x0043cf04:	jae 0x0043cef5
0x0043cf06:	jne 0x0043cf11
0x0043cf11:	addl %ecx, $0x2<UINT8>
0x0043cedc:	movl %ebx, (%esi)
0x0043cede:	subl %esi, $0xfffffffc<UINT8>
0x0043cee1:	adcl %ebx, %ebx
0x0043cee9:	movl %ebx, (%esi)
0x0043ceeb:	subl %esi, $0xfffffffc<UINT8>
0x0043ceee:	adcl %ebx, %ebx
0x0043cebb:	movl %ebx, (%esi)
0x0043cebd:	subl %esi, $0xfffffffc<UINT8>
0x0043cec0:	adcl %ebx, %ebx
0x0043cec2:	jae 0x0043cea8
0x0043cf08:	movl %ebx, (%esi)
0x0043cf0a:	subl %esi, $0xfffffffc<UINT8>
0x0043cf0d:	adcl %ebx, %ebx
0x0043cf0f:	jae 0x0043cef5
0x0043cf25:	movb %al, (%edx)
0x0043cf27:	incl %edx
0x0043cf28:	movb (%edi), %al
0x0043cf2a:	incl %edi
0x0043cf2b:	decl %ecx
0x0043cf2c:	jne 0x0043cf25
0x0043cf2e:	jmp 0x0043ce96
0x0043cef9:	movl %ebx, (%esi)
0x0043cefb:	subl %esi, $0xfffffffc<UINT8>
0x0043cefe:	adcl %ebx, %ebx
0x0043cf4a:	popl %esi
0x0043cf4b:	movl %edi, %esi
0x0043cf4d:	movl %ecx, $0x426<UINT32>
0x0043cf52:	movb %al, (%edi)
0x0043cf54:	incl %edi
0x0043cf55:	subb %al, $0xffffffe8<UINT8>
0x0043cf57:	cmpb %al, $0x1<UINT8>
0x0043cf59:	ja 0x0043cf52
0x0043cf5b:	cmpb (%edi), $0x7<UINT8>
0x0043cf5e:	jne 0x0043cf52
0x0043cf60:	movl %eax, (%edi)
0x0043cf62:	movb %bl, 0x4(%edi)
0x0043cf65:	shrw %ax, $0x8<UINT8>
0x0043cf69:	roll %eax, $0x10<UINT8>
0x0043cf6c:	xchgb %ah, %al
0x0043cf6e:	subl %eax, %edi
0x0043cf70:	subb %bl, $0xffffffe8<UINT8>
0x0043cf73:	addl %eax, %esi
0x0043cf75:	movl (%edi), %eax
0x0043cf77:	addl %edi, $0x5<UINT8>
0x0043cf7a:	movb %al, %bl
0x0043cf7c:	loop 0x0043cf57
0x0043cf7e:	leal %edi, 0x3a000(%esi)
0x0043cf84:	movl %eax, (%edi)
0x0043cf86:	orl %eax, %eax
0x0043cf88:	je 0x0043cfcf
0x0043cf8a:	movl %ebx, 0x4(%edi)
0x0043cf8d:	leal %eax, 0x3df38(%eax,%esi)
0x0043cf94:	addl %ebx, %esi
0x0043cf96:	pushl %eax
0x0043cf97:	addl %edi, $0x8<UINT8>
0x0043cf9a:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x0043cfa0:	xchgl %ebp, %eax
0x0043cfa1:	movb %al, (%edi)
0x0043cfa3:	incl %edi
0x0043cfa4:	orb %al, %al
0x0043cfa6:	je 0x0043cf84
0x0043cfa8:	movl %ecx, %edi
0x0043cfaa:	jns 0x0043cfb3
0x0043cfb3:	pushl %edi
0x0043cfb4:	decl %eax
0x0043cfb5:	repn scasb %al, %es:(%edi)
0x0043cfb7:	pushl %ebp
0x0043cfb8:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0043cfbe:	orl %eax, %eax
0x0043cfc0:	je 7
0x0043cfc2:	movl (%ebx), %eax
0x0043cfc4:	addl %ebx, $0x4<UINT8>
0x0043cfc7:	jmp 0x0043cfa1
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x0043cfac:	movzwl %eax, (%edi)
0x0043cfaf:	incl %edi
0x0043cfb0:	pushl %eax
0x0043cfb1:	incl %edi
0x0043cfb2:	movl %ecx, $0xaef24857<UINT32>
0x0043cfcf:	movl %ebp, 0x3e040(%esi)
0x0043cfd5:	leal %edi, -4096(%esi)
0x0043cfdb:	movl %ebx, $0x1000<UINT32>
0x0043cfe0:	pushl %eax
0x0043cfe1:	pushl %esp
0x0043cfe2:	pushl $0x4<UINT8>
0x0043cfe4:	pushl %ebx
0x0043cfe5:	pushl %edi
0x0043cfe6:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0043cfe8:	leal %eax, 0x227(%edi)
0x0043cfee:	andb (%eax), $0x7f<UINT8>
0x0043cff1:	andb 0x28(%eax), $0x7f<UINT8>
0x0043cff5:	popl %eax
0x0043cff6:	pushl %eax
0x0043cff7:	pushl %esp
0x0043cff8:	pushl %eax
0x0043cff9:	pushl %ebx
0x0043cffa:	pushl %edi
0x0043cffb:	call VirtualProtect@kernel32.dll
0x0043cffd:	popl %eax
0x0043cffe:	popa
0x0043cfff:	leal %eax, -128(%esp)
0x0043d003:	pushl $0x0<UINT8>
0x0043d005:	cmpl %esp, %eax
0x0043d007:	jne 0x0043d003
0x0043d009:	subl %esp, $0xffffff80<UINT8>
0x0043d00c:	jmp 0x0040b4b8
0x0040b4b8:	pushl %ebp
0x0040b4b9:	movl %ebp, %esp
0x0040b4bb:	pushl $0xffffffff<UINT8>
0x0040b4bd:	pushl $0x4145b0<UINT32>
0x0040b4c2:	pushl $0x40ae34<UINT32>
0x0040b4c7:	movl %eax, %fs:0
0x0040b4cd:	pushl %eax
0x0040b4ce:	movl %fs:0, %esp
0x0040b4d5:	subl %esp, $0x58<UINT8>
0x0040b4d8:	pushl %ebx
0x0040b4d9:	pushl %esi
0x0040b4da:	pushl %edi
0x0040b4db:	movl -24(%ebp), %esp
0x0040b4de:	call GetVersion@KERNEL32.DLL
GetVersion@KERNEL32.DLL: API Node	
0x0040b4e4:	xorl %edx, %edx
0x0040b4e6:	movb %dl, %ah
0x0040b4e8:	movl 0x433680, %edx
0x0040b4ee:	movl %ecx, %eax
0x0040b4f0:	andl %ecx, $0xff<UINT32>
0x0040b4f6:	movl 0x43367c, %ecx
0x0040b4fc:	shll %ecx, $0x8<UINT8>
0x0040b4ff:	addl %ecx, %edx
0x0040b501:	movl 0x433678, %ecx
0x0040b507:	shrl %eax, $0x10<UINT8>
0x0040b50a:	movl 0x433674, %eax
0x0040b50f:	pushl $0x1<UINT8>
0x0040b511:	call 0x0040bf36
0x0040bf36:	xorl %eax, %eax
0x0040bf38:	pushl $0x0<UINT8>
0x0040bf3a:	cmpl 0x8(%esp), %eax
0x0040bf3e:	pushl $0x1000<UINT32>
0x0040bf43:	sete %al
0x0040bf46:	pushl %eax
0x0040bf47:	call HeapCreate@KERNEL32.DLL
HeapCreate@KERNEL32.DLL: API Node	
0x0040bf4d:	testl %eax, %eax
0x0040bf4f:	movl 0x4369dc, %eax
0x0040bf54:	je 21
0x0040bf56:	call 0x0040c011
0x0040c011:	pushl $0x140<UINT32>
0x0040c016:	pushl $0x0<UINT8>
0x0040c018:	pushl 0x4369dc
0x0040c01e:	call HeapAlloc@KERNEL32.DLL
HeapAlloc@KERNEL32.DLL: API Node	
0x0040c024:	testl %eax, %eax
0x0040c026:	movl 0x4369d8, %eax
0x0040c02b:	jne 0x0040c02e
0x0040c02e:	andl 0x4369d0, $0x0<UINT8>
0x0040c035:	andl 0x4369d4, $0x0<UINT8>
0x0040c03c:	pushl $0x1<UINT8>
0x0040c03e:	movl 0x4369cc, %eax
0x0040c043:	movl 0x4369c4, $0x10<UINT32>
0x0040c04d:	popl %eax
0x0040c04e:	ret

0x0040bf5b:	testl %eax, %eax
0x0040bf5d:	jne 0x0040bf6e
0x0040bf6e:	pushl $0x1<UINT8>
0x0040bf70:	popl %eax
0x0040bf71:	ret

0x0040b516:	popl %ecx
0x0040b517:	testl %eax, %eax
0x0040b519:	jne 0x0040b523
0x0040b523:	call 0x0040ccf9
0x0040ccf9:	pushl %esi
0x0040ccfa:	call 0x0040bf72
0x0040bf72:	pushl %esi
0x0040bf73:	movl %esi, 0x4140a8
0x0040bf79:	pushl 0x431308
0x0040bf7f:	call InitializeCriticalSection@KERNEL32.DLL
InitializeCriticalSection@KERNEL32.DLL: API Node	
0x0040bf81:	pushl 0x4312f8
0x0040bf87:	call InitializeCriticalSection@KERNEL32.DLL
0x0040bf89:	pushl 0x4312e8
0x0040bf8f:	call InitializeCriticalSection@KERNEL32.DLL
0x0040bf91:	pushl 0x4312c8
0x0040bf97:	call InitializeCriticalSection@KERNEL32.DLL
0x0040bf99:	popl %esi
0x0040bf9a:	ret

0x0040ccff:	call TlsAlloc@KERNEL32.DLL
TlsAlloc@KERNEL32.DLL: API Node	
0x0040cd05:	cmpl %eax, $0xffffffff<UINT8>
0x0040cd08:	movl 0x4313a0, %eax
0x0040cd0d:	je 58
0x0040cd0f:	pushl $0x74<UINT8>
0x0040cd11:	pushl $0x1<UINT8>
0x0040cd13:	call 0x0040e140
0x0040e140:	pushl %ebx
0x0040e141:	pushl %esi
0x0040e142:	movl %esi, 0xc(%esp)
0x0040e146:	pushl %edi
0x0040e147:	imull %esi, 0x14(%esp)
0x0040e14c:	cmpl %esi, $0xffffffe0<UINT8>
0x0040e14f:	movl %ebx, %esi
0x0040e151:	ja 13
0x0040e153:	testl %esi, %esi
0x0040e155:	jne 0x0040e15a
0x0040e15a:	addl %esi, $0xf<UINT8>
0x0040e15d:	andl %esi, $0xfffffff0<UINT8>
0x0040e160:	xorl %edi, %edi
0x0040e162:	cmpl %esi, $0xffffffe0<UINT8>
0x0040e165:	ja 58
0x0040e167:	cmpl %ebx, 0x431384
0x0040e16d:	ja 29
0x0040e16f:	pushl $0x9<UINT8>
0x0040e171:	call 0x0040bf9b
0x0040bf9b:	pushl %ebp
0x0040bf9c:	movl %ebp, %esp
0x0040bf9e:	movl %eax, 0x8(%ebp)
0x0040bfa1:	pushl %esi
0x0040bfa2:	cmpl 0x4312c4(,%eax,4), $0x0<UINT8>
0x0040bfaa:	leal %esi, 0x4312c4(,%eax,4)
0x0040bfb1:	jne 0x0040bff1
0x0040bff1:	pushl (%esi)
0x0040bff3:	call EnterCriticalSection@KERNEL32.DLL
EnterCriticalSection@KERNEL32.DLL: API Node	
0x0040bff9:	popl %esi
0x0040bffa:	popl %ebp
0x0040bffb:	ret

0x0040e176:	pushl %ebx
0x0040e177:	call 0x0040c3a5
0x0040c3a5:	pushl %ebp
0x0040c3a6:	movl %ebp, %esp
0x0040c3a8:	subl %esp, $0x14<UINT8>
0x0040c3ab:	movl %eax, 0x4369d4
0x0040c3b0:	movl %edx, 0x4369d8
0x0040c3b6:	pushl %ebx
0x0040c3b7:	pushl %esi
0x0040c3b8:	leal %eax, (%eax,%eax,4)
0x0040c3bb:	pushl %edi
0x0040c3bc:	leal %edi, (%edx,%eax,4)
0x0040c3bf:	movl %eax, 0x8(%ebp)
0x0040c3c2:	movl -4(%ebp), %edi
0x0040c3c5:	leal %ecx, 0x17(%eax)
0x0040c3c8:	andl %ecx, $0xfffffff0<UINT8>
0x0040c3cb:	movl -16(%ebp), %ecx
0x0040c3ce:	sarl %ecx, $0x4<UINT8>
0x0040c3d1:	decl %ecx
0x0040c3d2:	cmpl %ecx, $0x20<UINT8>
0x0040c3d5:	jnl 14
0x0040c3d7:	orl %esi, $0xffffffff<UINT8>
0x0040c3da:	shrl %esi, %cl
0x0040c3dc:	orl -8(%ebp), $0xffffffff<UINT8>
0x0040c3e0:	movl -12(%ebp), %esi
0x0040c3e3:	jmp 0x0040c3f5
0x0040c3f5:	movl %eax, 0x4369cc
0x0040c3fa:	movl %ebx, %eax
0x0040c3fc:	cmpl %ebx, %edi
0x0040c3fe:	movl 0x8(%ebp), %ebx
0x0040c401:	jae 0x0040c41c
0x0040c41c:	cmpl %ebx, -4(%ebp)
0x0040c41f:	jne 0x0040c49a
0x0040c421:	movl %ebx, %edx
0x0040c423:	cmpl %ebx, %eax
0x0040c425:	movl 0x8(%ebp), %ebx
0x0040c428:	jae 0x0040c43f
0x0040c43f:	jne 89
0x0040c441:	cmpl %ebx, -4(%ebp)
0x0040c444:	jae 0x0040c457
0x0040c457:	jne 38
0x0040c459:	movl %ebx, %edx
0x0040c45b:	cmpl %ebx, %eax
0x0040c45d:	movl 0x8(%ebp), %ebx
0x0040c460:	jae 0x0040c46f
0x0040c46f:	jne 14
0x0040c471:	call 0x0040c6ae
0x0040c6ae:	movl %eax, 0x4369d4
0x0040c6b3:	movl %ecx, 0x4369c4
0x0040c6b9:	pushl %esi
0x0040c6ba:	pushl %edi
0x0040c6bb:	xorl %edi, %edi
0x0040c6bd:	cmpl %eax, %ecx
0x0040c6bf:	jne 0x0040c6f1
0x0040c6f1:	movl %ecx, 0x4369d8
0x0040c6f7:	pushl $0x41c4<UINT32>
0x0040c6fc:	pushl $0x8<UINT8>
0x0040c6fe:	leal %eax, (%eax,%eax,4)
0x0040c701:	pushl 0x4369dc
0x0040c707:	leal %esi, (%ecx,%eax,4)
0x0040c70a:	call HeapAlloc@KERNEL32.DLL
0x0040c710:	cmpl %eax, %edi
0x0040c712:	movl 0x10(%esi), %eax
0x0040c715:	je 42
0x0040c717:	pushl $0x4<UINT8>
0x0040c719:	pushl $0x2000<UINT32>
0x0040c71e:	pushl $0x100000<UINT32>
0x0040c723:	pushl %edi
0x0040c724:	call VirtualAlloc@KERNEL32.DLL
VirtualAlloc@KERNEL32.DLL: API Node	
0x0040c72a:	cmpl %eax, %edi
0x0040c72c:	movl 0xc(%esi), %eax
0x0040c72f:	jne 0x0040c745
0x0040c745:	orl 0x8(%esi), $0xffffffff<UINT8>
0x0040c749:	movl (%esi), %edi
0x0040c74b:	movl 0x4(%esi), %edi
0x0040c74e:	incl 0x4369d4
0x0040c754:	movl %eax, 0x10(%esi)
0x0040c757:	orl (%eax), $0xffffffff<UINT8>
0x0040c75a:	movl %eax, %esi
0x0040c75c:	popl %edi
0x0040c75d:	popl %esi
0x0040c75e:	ret

0x0040c476:	movl %ebx, %eax
0x0040c478:	testl %ebx, %ebx
0x0040c47a:	movl 0x8(%ebp), %ebx
0x0040c47d:	je 20
0x0040c47f:	pushl %ebx
0x0040c480:	call 0x0040c75f
0x0040c75f:	pushl %ebp
0x0040c760:	movl %ebp, %esp
0x0040c762:	pushl %ecx
0x0040c763:	movl %ecx, 0x8(%ebp)
0x0040c766:	pushl %ebx
0x0040c767:	pushl %esi
0x0040c768:	pushl %edi
0x0040c769:	movl %esi, 0x10(%ecx)
0x0040c76c:	movl %eax, 0x8(%ecx)
0x0040c76f:	xorl %ebx, %ebx
0x0040c771:	testl %eax, %eax
0x0040c773:	jl 0x0040c77a
0x0040c77a:	movl %eax, %ebx
0x0040c77c:	pushl $0x3f<UINT8>
0x0040c77e:	imull %eax, %eax, $0x204<UINT32>
0x0040c784:	popl %edx
0x0040c785:	leal %eax, 0x144(%eax,%esi)
0x0040c78c:	movl -4(%ebp), %eax
0x0040c78f:	movl 0x8(%eax), %eax
0x0040c792:	movl 0x4(%eax), %eax
0x0040c795:	addl %eax, $0x8<UINT8>
0x0040c798:	decl %edx
0x0040c799:	jne 0x0040c78f
0x0040c79b:	movl %edi, %ebx
0x0040c79d:	pushl $0x4<UINT8>
0x0040c79f:	shll %edi, $0xf<UINT8>
0x0040c7a2:	addl %edi, 0xc(%ecx)
0x0040c7a5:	pushl $0x1000<UINT32>
0x0040c7aa:	pushl $0x8000<UINT32>
0x0040c7af:	pushl %edi
0x0040c7b0:	call VirtualAlloc@KERNEL32.DLL
0x0040c7b6:	testl %eax, %eax
0x0040c7b8:	jne 0x0040c7c2
0x0040c7c2:	leal %edx, 0x7000(%edi)
0x0040c7c8:	cmpl %edi, %edx
0x0040c7ca:	ja 60
0x0040c7cc:	leal %eax, 0x10(%edi)
0x0040c7cf:	orl -8(%eax), $0xffffffff<UINT8>
0x0040c7d3:	orl 0xfec(%eax), $0xffffffff<UINT8>
0x0040c7da:	leal %ecx, 0xffc(%eax)
0x0040c7e0:	movl -4(%eax), $0xff0<UINT32>
0x0040c7e7:	movl (%eax), %ecx
0x0040c7e9:	leal %ecx, -4100(%eax)
0x0040c7ef:	movl 0x4(%eax), %ecx
0x0040c7f2:	movl 0xfe8(%eax), $0xff0<UINT32>
0x0040c7fc:	addl %eax, $0x1000<UINT32>
0x0040c801:	leal %ecx, -16(%eax)
0x0040c804:	cmpl %ecx, %edx
0x0040c806:	jbe 0x0040c7cf
0x0040c808:	movl %eax, -4(%ebp)
0x0040c80b:	leal %ecx, 0xc(%edi)
0x0040c80e:	addl %eax, $0x1f8<UINT32>
0x0040c813:	pushl $0x1<UINT8>
0x0040c815:	popl %edi
0x0040c816:	movl 0x4(%eax), %ecx
0x0040c819:	movl 0x8(%ecx), %eax
0x0040c81c:	leal %ecx, 0xc(%edx)
0x0040c81f:	movl 0x8(%eax), %ecx
0x0040c822:	movl 0x4(%ecx), %eax
0x0040c825:	andl 0x44(%esi,%ebx,4), $0x0<UINT8>
0x0040c82a:	movl 0xc4(%esi,%ebx,4), %edi
0x0040c831:	movb %al, 0x43(%esi)
0x0040c834:	movb %cl, %al
0x0040c836:	incb %cl
0x0040c838:	testb %al, %al
0x0040c83a:	movl %eax, 0x8(%ebp)
0x0040c83d:	movb 0x43(%esi), %cl
0x0040c840:	jne 3
0x0040c842:	orl 0x4(%eax), %edi
0x0040c845:	movl %edx, $0x80000000<UINT32>
0x0040c84a:	movl %ecx, %ebx
0x0040c84c:	shrl %edx, %cl
0x0040c84e:	notl %edx
0x0040c850:	andl 0x8(%eax), %edx
0x0040c853:	movl %eax, %ebx
0x0040c855:	popl %edi
0x0040c856:	popl %esi
0x0040c857:	popl %ebx
0x0040c858:	leave
0x0040c859:	ret

0x0040c485:	popl %ecx
0x0040c486:	movl %ecx, 0x10(%ebx)
0x0040c489:	movl (%ecx), %eax
0x0040c48b:	movl %eax, 0x10(%ebx)
0x0040c48e:	cmpl (%eax), $0xffffffff<UINT8>
0x0040c491:	jne 0x0040c49a
0x0040c49a:	movl 0x4369cc, %ebx
0x0040c4a0:	movl %eax, 0x10(%ebx)
0x0040c4a3:	movl %edx, (%eax)
0x0040c4a5:	cmpl %edx, $0xffffffff<UINT8>
0x0040c4a8:	movl -4(%ebp), %edx
0x0040c4ab:	je 20
0x0040c4ad:	movl %ecx, 0xc4(%eax,%edx,4)
0x0040c4b4:	movl %edi, 0x44(%eax,%edx,4)
0x0040c4b8:	andl %ecx, -8(%ebp)
0x0040c4bb:	andl %edi, %esi
0x0040c4bd:	orl %ecx, %edi
0x0040c4bf:	jne 0x0040c4f8
0x0040c4f8:	movl %ecx, %edx
0x0040c4fa:	xorl %edi, %edi
0x0040c4fc:	imull %ecx, %ecx, $0x204<UINT32>
0x0040c502:	leal %ecx, 0x144(%ecx,%eax)
0x0040c509:	movl -12(%ebp), %ecx
0x0040c50c:	movl %ecx, 0x44(%eax,%edx,4)
0x0040c510:	andl %ecx, %esi
0x0040c512:	jne 13
0x0040c514:	movl %ecx, 0xc4(%eax,%edx,4)
0x0040c51b:	pushl $0x20<UINT8>
0x0040c51d:	andl %ecx, -8(%ebp)
0x0040c520:	popl %edi
0x0040c521:	testl %ecx, %ecx
0x0040c523:	jl 0x0040c52a
0x0040c525:	shll %ecx
0x0040c527:	incl %edi
0x0040c528:	jmp 0x0040c521
0x0040c52a:	movl %ecx, -12(%ebp)
0x0040c52d:	movl %edx, 0x4(%ecx,%edi,8)
0x0040c531:	movl %ecx, (%edx)
0x0040c533:	subl %ecx, -16(%ebp)
0x0040c536:	movl %esi, %ecx
0x0040c538:	movl -8(%ebp), %ecx
0x0040c53b:	sarl %esi, $0x4<UINT8>
0x0040c53e:	decl %esi
0x0040c53f:	cmpl %esi, $0x3f<UINT8>
0x0040c542:	jle 3
0x0040c544:	pushl $0x3f<UINT8>
0x0040c546:	popl %esi
0x0040c547:	cmpl %esi, %edi
0x0040c549:	je 0x0040c65c
0x0040c65c:	testl %ecx, %ecx
0x0040c65e:	je 11
0x0040c660:	movl (%edx), %ecx
0x0040c662:	movl -4(%ecx,%edx), %ecx
0x0040c666:	jmp 0x0040c66b
0x0040c66b:	movl %esi, -16(%ebp)
0x0040c66e:	addl %edx, %ecx
0x0040c670:	leal %ecx, 0x1(%esi)
0x0040c673:	movl (%edx), %ecx
0x0040c675:	movl -4(%edx,%esi), %ecx
0x0040c679:	movl %esi, -12(%ebp)
0x0040c67c:	movl %ecx, (%esi)
0x0040c67e:	testl %ecx, %ecx
0x0040c680:	leal %edi, 0x1(%ecx)
0x0040c683:	movl (%esi), %edi
0x0040c685:	jne 0x0040c6a1
0x0040c687:	cmpl %ebx, 0x4369d0
0x0040c68d:	jne 0x0040c6a1
0x0040c6a1:	movl %ecx, -4(%ebp)
0x0040c6a4:	movl (%eax), %ecx
0x0040c6a6:	leal %eax, 0x4(%edx)
0x0040c6a9:	popl %edi
0x0040c6aa:	popl %esi
0x0040c6ab:	popl %ebx
0x0040c6ac:	leave
0x0040c6ad:	ret

0x0040e17c:	pushl $0x9<UINT8>
0x0040e17e:	movl %edi, %eax
0x0040e180:	call 0x0040bffc
0x0040bffc:	pushl %ebp
0x0040bffd:	movl %ebp, %esp
0x0040bfff:	movl %eax, 0x8(%ebp)
0x0040c002:	pushl 0x4312c4(,%eax,4)
0x0040c009:	call LeaveCriticalSection@KERNEL32.DLL
LeaveCriticalSection@KERNEL32.DLL: API Node	
0x0040c00f:	popl %ebp
0x0040c010:	ret

0x0040e185:	addl %esp, $0xc<UINT8>
0x0040e188:	testl %edi, %edi
0x0040e18a:	jne 0x0040e1b7
0x0040e1b7:	pushl %ebx
0x0040e1b8:	pushl $0x0<UINT8>
0x0040e1ba:	pushl %edi
0x0040e1bb:	call 0x00410510
0x00410510:	movl %edx, 0xc(%esp)
0x00410514:	movl %ecx, 0x4(%esp)
0x00410518:	testl %edx, %edx
0x0041051a:	je 71
0x0041051c:	xorl %eax, %eax
0x0041051e:	movb %al, 0x8(%esp)
0x00410522:	pushl %edi
0x00410523:	movl %edi, %ecx
0x00410525:	cmpl %edx, $0x4<UINT8>
0x00410528:	jb 45
0x0041052a:	negl %ecx
0x0041052c:	andl %ecx, $0x3<UINT8>
0x0041052f:	je 0x00410539
0x00410539:	movl %ecx, %eax
0x0041053b:	shll %eax, $0x8<UINT8>
0x0041053e:	addl %eax, %ecx
0x00410540:	movl %ecx, %eax
0x00410542:	shll %eax, $0x10<UINT8>
0x00410545:	addl %eax, %ecx
0x00410547:	movl %ecx, %edx
0x00410549:	andl %edx, $0x3<UINT8>
0x0041054c:	shrl %ecx, $0x2<UINT8>
0x0041054f:	je 6
0x00410551:	rep stosl %es:(%edi), %eax
0x00410553:	testl %edx, %edx
0x00410555:	je 0x0041055d
0x0041055d:	movl %eax, 0x8(%esp)
0x00410561:	popl %edi
0x00410562:	ret

0x0040e1c0:	addl %esp, $0xc<UINT8>
0x0040e1c3:	movl %eax, %edi
0x0040e1c5:	popl %edi
0x0040e1c6:	popl %esi
0x0040e1c7:	popl %ebx
0x0040e1c8:	ret

0x0040cd18:	movl %esi, %eax
0x0040cd1a:	popl %ecx
0x0040cd1b:	testl %esi, %esi
0x0040cd1d:	popl %ecx
0x0040cd1e:	je 41
0x0040cd20:	pushl %esi
0x0040cd21:	pushl 0x4313a0
0x0040cd27:	call TlsSetValue@KERNEL32.DLL
TlsSetValue@KERNEL32.DLL: API Node	
0x0040cd2d:	testl %eax, %eax
0x0040cd2f:	je 24
0x0040cd31:	pushl %esi
0x0040cd32:	call 0x0040cd4d
0x0040cd4d:	movl %eax, 0x4(%esp)
0x0040cd51:	movl 0x50(%eax), $0x431760<UINT32>
0x0040cd58:	movl 0x14(%eax), $0x1<UINT32>
0x0040cd5f:	ret

0x0040cd37:	popl %ecx
0x0040cd38:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040cd3e:	orl 0x4(%esi), $0xffffffff<UINT8>
0x0040cd42:	pushl $0x1<UINT8>
0x0040cd44:	movl (%esi), %eax
0x0040cd46:	popl %eax
0x0040cd47:	popl %esi
0x0040cd48:	ret

0x0040b528:	testl %eax, %eax
0x0040b52a:	jne 0x0040b534
0x0040b534:	xorl %esi, %esi
0x0040b536:	movl -4(%ebp), %esi
0x0040b539:	call 0x0040df84
0x0040df84:	pushl %ebp
0x0040df85:	movl %ebp, %esp
0x0040df87:	subl %esp, $0x48<UINT8>
0x0040df8a:	pushl %ebx
0x0040df8b:	pushl %esi
0x0040df8c:	pushl %edi
0x0040df8d:	pushl $0x480<UINT32>
0x0040df92:	call 0x0040a837
0x0040a837:	pushl 0x4335fc
0x0040a83d:	pushl 0x8(%esp)
0x0040a841:	call 0x0040a849
0x0040a849:	cmpl 0x4(%esp), $0xffffffe0<UINT8>
0x0040a84e:	ja 34
0x0040a850:	pushl 0x4(%esp)
0x0040a854:	call 0x0040a875
0x0040a875:	pushl %esi
0x0040a876:	movl %esi, 0x8(%esp)
0x0040a87a:	cmpl %esi, 0x431384
0x0040a880:	pushl %edi
0x0040a881:	ja 0x0040a8a4
0x0040a8a4:	testl %esi, %esi
0x0040a8a6:	jne 0x0040a8ab
0x0040a8ab:	addl %esi, $0xf<UINT8>
0x0040a8ae:	andl %esi, $0xfffffff0<UINT8>
0x0040a8b1:	pushl %esi
0x0040a8b2:	pushl $0x0<UINT8>
0x0040a8b4:	pushl 0x4369dc
0x0040a8ba:	call HeapAlloc@KERNEL32.DLL
0x0040a8c0:	popl %edi
0x0040a8c1:	popl %esi
0x0040a8c2:	ret

0x0040a859:	testl %eax, %eax
0x0040a85b:	popl %ecx
0x0040a85c:	jne 0x0040a874
0x0040a874:	ret

0x0040a846:	popl %ecx
0x0040a847:	popl %ecx
0x0040a848:	ret

0x0040df97:	movl %esi, %eax
0x0040df99:	popl %ecx
0x0040df9a:	testl %esi, %esi
0x0040df9c:	jne 0x0040dfa6
0x0040dfa6:	movl 0x4368c0, %esi
0x0040dfac:	movl 0x4369c0, $0x20<UINT32>
0x0040dfb6:	leal %eax, 0x480(%esi)
0x0040dfbc:	cmpl %esi, %eax
0x0040dfbe:	jae 0x0040dfde
0x0040dfc0:	andb 0x4(%esi), $0x0<UINT8>
0x0040dfc4:	orl (%esi), $0xffffffff<UINT8>
0x0040dfc7:	andl 0x8(%esi), $0x0<UINT8>
0x0040dfcb:	movb 0x5(%esi), $0xa<UINT8>
0x0040dfcf:	movl %eax, 0x4368c0
0x0040dfd4:	addl %esi, $0x24<UINT8>
0x0040dfd7:	addl %eax, $0x480<UINT32>
0x0040dfdc:	jmp 0x0040dfbc
0x0040dfde:	leal %eax, -72(%ebp)
0x0040dfe1:	pushl %eax
0x0040dfe2:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x0040dfe8:	cmpw -22(%ebp), $0x0<UINT8>
0x0040dfed:	je 209
0x0040dff3:	movl %eax, -20(%ebp)
0x0040dff6:	testl %eax, %eax
0x0040dff8:	je 198
0x0040dffe:	movl %edi, (%eax)
0x0040e000:	leal %ebx, 0x4(%eax)
0x0040e003:	leal %eax, (%ebx,%edi)
0x0040e006:	movl -4(%ebp), %eax
0x0040e009:	movl %eax, $0x800<UINT32>
0x0040e00e:	cmpl %edi, %eax
0x0040e010:	jl 0x0040e014
0x0040e014:	cmpl 0x4369c0, %edi
0x0040e01a:	jnl 0x0040e072
0x0040e072:	xorl %esi, %esi
0x0040e074:	testl %edi, %edi
0x0040e076:	jle 0x0040e0c4
0x0040e0c4:	xorl %ebx, %ebx
0x0040e0c6:	movl %ecx, 0x4368c0
0x0040e0cc:	leal %eax, (%ebx,%ebx,8)
0x0040e0cf:	cmpl (%ecx,%eax,4), $0xffffffff<UINT8>
0x0040e0d3:	leal %esi, (%ecx,%eax,4)
0x0040e0d6:	jne 77
0x0040e0d8:	testl %ebx, %ebx
0x0040e0da:	movb 0x4(%esi), $0xffffff81<UINT8>
0x0040e0de:	jne 0x0040e0e5
0x0040e0e0:	pushl $0xfffffff6<UINT8>
0x0040e0e2:	popl %eax
0x0040e0e3:	jmp 0x0040e0ef
0x0040e0ef:	pushl %eax
0x0040e0f0:	call GetStdHandle@KERNEL32.DLL
GetStdHandle@KERNEL32.DLL: API Node	
0x0040e0f6:	movl %edi, %eax
0x0040e0f8:	cmpl %edi, $0xffffffff<UINT8>
0x0040e0fb:	je 23
0x0040e0fd:	pushl %edi
0x0040e0fe:	call GetFileType@KERNEL32.DLL
GetFileType@KERNEL32.DLL: API Node	
0x0040e104:	testl %eax, %eax
0x0040e106:	je 12
0x0040e108:	andl %eax, $0xff<UINT32>
0x0040e10d:	movl (%esi), %edi
0x0040e10f:	cmpl %eax, $0x2<UINT8>
0x0040e112:	jne 6
0x0040e114:	orb 0x4(%esi), $0x40<UINT8>
0x0040e118:	jmp 0x0040e129
0x0040e129:	incl %ebx
0x0040e12a:	cmpl %ebx, $0x3<UINT8>
0x0040e12d:	jl 0x0040e0c6
0x0040e0e5:	movl %eax, %ebx
0x0040e0e7:	decl %eax
0x0040e0e8:	negl %eax
0x0040e0ea:	sbbl %eax, %eax
0x0040e0ec:	addl %eax, $0xfffffff5<UINT8>
0x0040e12f:	pushl 0x4369c0
0x0040e135:	call SetHandleCount@KERNEL32.DLL
SetHandleCount@KERNEL32.DLL: API Node	
0x0040e13b:	popl %edi
0x0040e13c:	popl %esi
0x0040e13d:	popl %ebx
0x0040e13e:	leave
0x0040e13f:	ret

0x0040b53e:	call GetCommandLineA@KERNEL32.DLL
GetCommandLineA@KERNEL32.DLL: API Node	
0x0040b544:	movl 0x4369e0, %eax
0x0040b549:	call 0x0040f125
0x0040f125:	pushl %ecx
0x0040f126:	pushl %ecx
0x0040f127:	movl %eax, 0x4337e4
0x0040f12c:	pushl %ebx
0x0040f12d:	pushl %ebp
0x0040f12e:	movl %ebp, 0x4140f0
0x0040f134:	pushl %esi
0x0040f135:	pushl %edi
0x0040f136:	xorl %ebx, %ebx
0x0040f138:	xorl %esi, %esi
0x0040f13a:	xorl %edi, %edi
0x0040f13c:	cmpl %eax, %ebx
0x0040f13e:	jne 51
0x0040f140:	call GetEnvironmentStringsW@KERNEL32.DLL
GetEnvironmentStringsW@KERNEL32.DLL: API Node	
0x0040f142:	movl %esi, %eax
0x0040f144:	cmpl %esi, %ebx
0x0040f146:	je 12
0x0040f148:	movl 0x4337e4, $0x1<UINT32>
0x0040f152:	jmp 0x0040f17c
0x0040f17c:	cmpl %esi, %ebx
0x0040f17e:	jne 0x0040f18c
0x0040f18c:	cmpw (%esi), %bx
0x0040f18f:	movl %eax, %esi
0x0040f191:	je 14
0x0040f193:	incl %eax
0x0040f194:	incl %eax
0x0040f195:	cmpw (%eax), %bx
0x0040f198:	jne 0x0040f193
0x0040f19a:	incl %eax
0x0040f19b:	incl %eax
0x0040f19c:	cmpw (%eax), %bx
0x0040f19f:	jne 0x0040f193
0x0040f1a1:	subl %eax, %esi
0x0040f1a3:	movl %edi, 0x4140ac
0x0040f1a9:	sarl %eax
0x0040f1ab:	pushl %ebx
0x0040f1ac:	pushl %ebx
0x0040f1ad:	incl %eax
0x0040f1ae:	pushl %ebx
0x0040f1af:	pushl %ebx
0x0040f1b0:	pushl %eax
0x0040f1b1:	pushl %esi
0x0040f1b2:	pushl %ebx
0x0040f1b3:	pushl %ebx
0x0040f1b4:	movl 0x34(%esp), %eax
0x0040f1b8:	call WideCharToMultiByte@KERNEL32.DLL
WideCharToMultiByte@KERNEL32.DLL: API Node	
0x0040f1ba:	movl %ebp, %eax
0x0040f1bc:	cmpl %ebp, %ebx
0x0040f1be:	je 50
0x0040f1c0:	pushl %ebp
0x0040f1c1:	call 0x0040a837
0x0040f1c6:	cmpl %eax, %ebx
0x0040f1c8:	popl %ecx
0x0040f1c9:	movl 0x10(%esp), %eax
0x0040f1cd:	je 35
0x0040f1cf:	pushl %ebx
0x0040f1d0:	pushl %ebx
0x0040f1d1:	pushl %ebp
0x0040f1d2:	pushl %eax
0x0040f1d3:	pushl 0x24(%esp)
0x0040f1d7:	pushl %esi
0x0040f1d8:	pushl %ebx
0x0040f1d9:	pushl %ebx
0x0040f1da:	call WideCharToMultiByte@KERNEL32.DLL
0x0040f1dc:	testl %eax, %eax
0x0040f1de:	jne 0x0040f1ee
0x0040f1ee:	movl %ebx, 0x10(%esp)
0x0040f1f2:	pushl %esi
0x0040f1f3:	call FreeEnvironmentStringsW@KERNEL32.DLL
FreeEnvironmentStringsW@KERNEL32.DLL: API Node	
0x0040f1f9:	movl %eax, %ebx
0x0040f1fb:	jmp 0x0040f250
0x0040f250:	popl %edi
0x0040f251:	popl %esi
0x0040f252:	popl %ebp
0x0040f253:	popl %ebx
0x0040f254:	popl %ecx
0x0040f255:	popl %ecx
0x0040f256:	ret

0x0040b54e:	movl 0x4335f0, %eax
0x0040b553:	call 0x0040eed8
0x0040eed8:	pushl %ebp
0x0040eed9:	movl %ebp, %esp
0x0040eedb:	pushl %ecx
0x0040eedc:	pushl %ecx
0x0040eedd:	pushl %ebx
0x0040eede:	xorl %ebx, %ebx
0x0040eee0:	cmpl 0x4368b4, %ebx
0x0040eee6:	pushl %esi
0x0040eee7:	pushl %edi
0x0040eee8:	jne 5
0x0040eeea:	call 0x00411b9f
0x00411b9f:	cmpl 0x4368b4, $0x0<UINT8>
0x00411ba6:	jne 18
0x00411ba8:	pushl $0xfffffffd<UINT8>
0x00411baa:	call 0x004117c7
0x004117c7:	pushl %ebp
0x004117c8:	movl %ebp, %esp
0x004117ca:	subl %esp, $0x18<UINT8>
0x004117cd:	pushl %ebx
0x004117ce:	pushl %esi
0x004117cf:	pushl %edi
0x004117d0:	pushl $0x19<UINT8>
0x004117d2:	call 0x0040bf9b
0x0040bfb3:	pushl %edi
0x0040bfb4:	pushl $0x18<UINT8>
0x0040bfb6:	call 0x0040a837
0x0040a883:	pushl $0x9<UINT8>
0x0040a885:	call 0x0040bf9b
0x0040a88a:	pushl %esi
0x0040a88b:	call 0x0040c3a5
0x0040c403:	movl %ecx, 0x4(%ebx)
0x0040c406:	movl %edi, (%ebx)
0x0040c408:	andl %ecx, -8(%ebp)
0x0040c40b:	andl %edi, %esi
0x0040c40d:	orl %ecx, %edi
0x0040c40f:	jne 0x0040c41c
0x0040a890:	pushl $0x9<UINT8>
0x0040a892:	movl %edi, %eax
0x0040a894:	call 0x0040bffc
0x0040a899:	addl %esp, $0xc<UINT8>
0x0040a89c:	testl %edi, %edi
0x0040a89e:	je 4
0x0040a8a0:	movl %eax, %edi
0x0040a8a2:	jmp 0x0040a8c0
0x0040bfbb:	movl %edi, %eax
0x0040bfbd:	popl %ecx
0x0040bfbe:	testl %edi, %edi
0x0040bfc0:	jne 0x0040bfca
0x0040bfca:	pushl $0x11<UINT8>
0x0040bfcc:	call 0x0040bf9b
0x0040bfd1:	cmpl (%esi), $0x0<UINT8>
0x0040bfd4:	popl %ecx
0x0040bfd5:	pushl %edi
0x0040bfd6:	jne 10
0x0040bfd8:	call InitializeCriticalSection@KERNEL32.DLL
0x0040bfde:	movl (%esi), %edi
0x0040bfe0:	jmp 0x0040bfe8
0x0040bfe8:	pushl $0x11<UINT8>
0x0040bfea:	call 0x0040bffc
0x0040bfef:	popl %ecx
0x0040bff0:	popl %edi
0x004117d7:	pushl 0x8(%ebp)
0x004117da:	call 0x00411974
0x00411974:	movl %eax, 0x4(%esp)
0x00411978:	andl 0x43385c, $0x0<UINT8>
0x0041197f:	cmpl %eax, $0xfffffffe<UINT8>
0x00411982:	jne 0x00411994
0x00411994:	cmpl %eax, $0xfffffffd<UINT8>
0x00411997:	jne 16
0x00411999:	movl 0x43385c, $0x1<UINT32>
0x004119a3:	jmp GetACP@KERNEL32.DLL
GetACP@KERNEL32.DLL: API Node	
0x004117df:	movl %ebx, %eax
0x004117e1:	popl %ecx
0x004117e2:	cmpl %ebx, 0x43667c
0x004117e8:	popl %ecx
0x004117e9:	movl 0x8(%ebp), %ebx
0x004117ec:	jne 0x004117f5
0x004117f5:	testl %ebx, %ebx
0x004117f7:	je 342
0x004117fd:	xorl %edx, %edx
0x004117ff:	movl %eax, $0x4319c8<UINT32>
0x00411804:	cmpl (%eax), %ebx
0x00411806:	je 116
0x00411808:	addl %eax, $0x30<UINT8>
0x0041180b:	incl %edx
0x0041180c:	cmpl %eax, $0x431ab8<UINT32>
0x00411811:	jl 0x00411804
0x00411813:	leal %eax, -24(%ebp)
0x00411816:	pushl %eax
0x00411817:	pushl %ebx
0x00411818:	call GetCPInfo@KERNEL32.DLL
GetCPInfo@KERNEL32.DLL: API Node	
0x0041181e:	pushl $0x1<UINT8>
0x00411820:	popl %esi
0x00411821:	cmpl %eax, %esi
0x00411823:	jne 289
0x00411829:	pushl $0x40<UINT8>
0x0041182b:	andl 0x4368a4, $0x0<UINT8>
0x00411832:	popl %ecx
0x00411833:	xorl %eax, %eax
0x00411835:	movl %edi, $0x4367a0<UINT32>
0x0041183a:	cmpl -24(%ebp), %esi
0x0041183d:	rep stosl %es:(%edi), %eax
0x0041183f:	stosb %es:(%edi), %al
0x00411840:	movl 0x43667c, %ebx
0x00411846:	jbe 235
0x0041184c:	cmpb -18(%ebp), $0x0<UINT8>
0x00411850:	je 0x00411912
0x00411912:	movl %eax, %esi
0x00411914:	orb 0x4367a1(%eax), $0x8<UINT8>
0x0041191b:	incl %eax
0x0041191c:	cmpl %eax, $0xff<UINT32>
0x00411921:	jb 0x00411914
0x00411923:	pushl %ebx
0x00411924:	call 0x004119be
0x004119be:	movl %eax, 0x4(%esp)
0x004119c2:	subl %eax, $0x3a4<UINT32>
0x004119c7:	je 34
0x004119c9:	subl %eax, $0x4<UINT8>
0x004119cc:	je 23
0x004119ce:	subl %eax, $0xd<UINT8>
0x004119d1:	je 12
0x004119d3:	decl %eax
0x004119d4:	je 3
0x004119d6:	xorl %eax, %eax
0x004119d8:	ret

0x00411929:	popl %ecx
0x0041192a:	movl 0x4368a4, %eax
0x0041192f:	movl 0x43668c, %esi
0x00411935:	jmp 0x0041193e
0x0041193e:	xorl %eax, %eax
0x00411940:	movl %edi, $0x436680<UINT32>
0x00411945:	stosl %es:(%edi), %eax
0x00411946:	stosl %es:(%edi), %eax
0x00411947:	stosl %es:(%edi), %eax
0x00411948:	jmp 0x00411958
0x00411958:	call 0x00411a1a
0x00411a1a:	pushl %ebp
0x00411a1b:	movl %ebp, %esp
0x00411a1d:	subl %esp, $0x514<UINT32>
0x00411a23:	leal %eax, -20(%ebp)
0x00411a26:	pushl %esi
0x00411a27:	pushl %eax
0x00411a28:	pushl 0x43667c
0x00411a2e:	call GetCPInfo@KERNEL32.DLL
0x00411a34:	cmpl %eax, $0x1<UINT8>
0x00411a37:	jne 278
0x00411a3d:	xorl %eax, %eax
0x00411a3f:	movl %esi, $0x100<UINT32>
0x00411a44:	movb -276(%ebp,%eax), %al
0x00411a4b:	incl %eax
0x00411a4c:	cmpl %eax, %esi
0x00411a4e:	jb 0x00411a44
0x00411a50:	movb %al, -14(%ebp)
0x00411a53:	movb -276(%ebp), $0x20<UINT8>
0x00411a5a:	testb %al, %al
0x00411a5c:	je 0x00411a95
0x00411a95:	pushl $0x0<UINT8>
0x00411a97:	leal %eax, -1300(%ebp)
0x00411a9d:	pushl 0x4368a4
0x00411aa3:	pushl 0x43667c
0x00411aa9:	pushl %eax
0x00411aaa:	leal %eax, -276(%ebp)
0x00411ab0:	pushl %esi
0x00411ab1:	pushl %eax
0x00411ab2:	pushl $0x1<UINT8>
0x00411ab4:	call 0x00410e6c
0x00410e6c:	pushl %ebp
0x00410e6d:	movl %ebp, %esp
0x00410e6f:	pushl $0xffffffff<UINT8>
0x00410e71:	pushl $0x414978<UINT32>
0x00410e76:	pushl $0x40ae34<UINT32>
0x00410e7b:	movl %eax, %fs:0
0x00410e81:	pushl %eax
0x00410e82:	movl %fs:0, %esp
0x00410e89:	subl %esp, $0x18<UINT8>
0x00410e8c:	pushl %ebx
0x00410e8d:	pushl %esi
0x00410e8e:	pushl %edi
0x00410e8f:	movl -24(%ebp), %esp
0x00410e92:	movl %eax, 0x4337f0
0x00410e97:	xorl %ebx, %ebx
0x00410e99:	cmpl %eax, %ebx
0x00410e9b:	jne 62
0x00410e9d:	leal %eax, -28(%ebp)
0x00410ea0:	pushl %eax
0x00410ea1:	pushl $0x1<UINT8>
0x00410ea3:	popl %esi
0x00410ea4:	pushl %esi
0x00410ea5:	pushl $0x414970<UINT32>
0x00410eaa:	pushl %esi
0x00410eab:	call GetStringTypeW@KERNEL32.DLL
GetStringTypeW@KERNEL32.DLL: API Node	
0x00410eb1:	testl %eax, %eax
0x00410eb3:	je 4
0x00410eb5:	movl %eax, %esi
0x00410eb7:	jmp 0x00410ed6
0x00410ed6:	movl 0x4337f0, %eax
0x00410edb:	cmpl %eax, $0x2<UINT8>
0x00410ede:	jne 0x00410f04
0x00410f04:	cmpl %eax, $0x1<UINT8>
0x00410f07:	jne 148
0x00410f0d:	cmpl 0x18(%ebp), %ebx
0x00410f10:	jne 0x00410f1a
0x00410f1a:	pushl %ebx
0x00410f1b:	pushl %ebx
0x00410f1c:	pushl 0x10(%ebp)
0x00410f1f:	pushl 0xc(%ebp)
0x00410f22:	movl %eax, 0x20(%ebp)
0x00410f25:	negl %eax
0x00410f27:	sbbl %eax, %eax
0x00410f29:	andl %eax, $0x8<UINT8>
0x00410f2c:	incl %eax
0x00410f2d:	pushl %eax
0x00410f2e:	pushl 0x18(%ebp)
0x00410f31:	call MultiByteToWideChar@KERNEL32.DLL
MultiByteToWideChar@KERNEL32.DLL: API Node	
0x00410f37:	movl -32(%ebp), %eax
0x00410f3a:	cmpl %eax, %ebx
0x00410f3c:	je 99
0x00410f3e:	movl -4(%ebp), %ebx
0x00410f41:	leal %edi, (%eax,%eax)
0x00410f44:	movl %eax, %edi
0x00410f46:	addl %eax, $0x3<UINT8>
0x00410f49:	andb %al, $0xfffffffc<UINT8>
0x00410f4b:	call 0x0040ab00
0x0040ab00:	pushl %ecx
0x0040ab01:	cmpl %eax, $0x1000<UINT32>
0x0040ab06:	leal %ecx, 0x8(%esp)
0x0040ab0a:	jb 0x0040ab20
0x0040ab20:	subl %ecx, %eax
0x0040ab22:	movl %eax, %esp
0x0040ab24:	testl (%ecx), %eax
0x0040ab26:	movl %esp, %ecx
0x0040ab28:	movl %ecx, (%eax)
0x0040ab2a:	movl %eax, 0x4(%eax)
0x0040ab2d:	pushl %eax
0x0040ab2e:	ret

0x00410f50:	movl -24(%ebp), %esp
0x00410f53:	movl %esi, %esp
0x00410f55:	movl -36(%ebp), %esi
0x00410f58:	pushl %edi
0x00410f59:	pushl %ebx
0x00410f5a:	pushl %esi
0x00410f5b:	call 0x00410510
