0x00544d20:	pusha
0x00544d21:	movl %esi, $0x4da000<UINT32>
0x00544d26:	leal %edi, -888832(%esi)
0x00544d2c:	pushl %edi
0x00544d2d:	orl %ebp, $0xffffffff<UINT8>
0x00544d30:	jmp 0x00544d42
0x00544d42:	movl %ebx, (%esi)
0x00544d44:	subl %esi, $0xfffffffc<UINT8>
0x00544d47:	adcl %ebx, %ebx
0x00544d49:	jb 0x00544d38
0x00544d38:	movb %al, (%esi)
0x00544d3a:	incl %esi
0x00544d3b:	movb (%edi), %al
0x00544d3d:	incl %edi
0x00544d3e:	addl %ebx, %ebx
0x00544d40:	jne 0x00544d49
0x00544d4b:	movl %eax, $0x1<UINT32>
0x00544d50:	addl %ebx, %ebx
0x00544d52:	jne 0x00544d5b
0x00544d5b:	adcl %eax, %eax
0x00544d5d:	addl %ebx, %ebx
0x00544d5f:	jae 0x00544d6c
0x00544d61:	jne 0x00544d8b
0x00544d8b:	xorl %ecx, %ecx
0x00544d8d:	subl %eax, $0x3<UINT8>
0x00544d90:	jb 0x00544da3
0x00544da3:	addl %ebx, %ebx
0x00544da5:	jne 0x00544dae
0x00544dae:	jb 0x00544d7c
0x00544d7c:	addl %ebx, %ebx
0x00544d7e:	jne 0x00544d87
0x00544d87:	adcl %ecx, %ecx
0x00544d89:	jmp 0x00544ddd
0x00544ddd:	cmpl %ebp, $0xfffffb00<UINT32>
0x00544de3:	adcl %ecx, $0x2<UINT8>
0x00544de6:	leal %edx, (%edi,%ebp)
0x00544de9:	cmpl %ebp, $0xfffffffc<UINT8>
0x00544dec:	jbe 0x00544dfc
0x00544dee:	movb %al, (%edx)
0x00544df0:	incl %edx
0x00544df1:	movb (%edi), %al
0x00544df3:	incl %edi
0x00544df4:	decl %ecx
0x00544df5:	jne 0x00544dee
0x00544df7:	jmp 0x00544d3e
0x00544d92:	shll %eax, $0x8<UINT8>
0x00544d95:	movb %al, (%esi)
0x00544d97:	incl %esi
0x00544d98:	xorl %eax, $0xffffffff<UINT8>
0x00544d9b:	je 0x00544e12
0x00544d9d:	sarl %eax
0x00544d9f:	movl %ebp, %eax
0x00544da1:	jmp 0x00544dae
0x00544dfc:	movl %eax, (%edx)
0x00544dfe:	addl %edx, $0x4<UINT8>
0x00544e01:	movl (%edi), %eax
0x00544e03:	addl %edi, $0x4<UINT8>
0x00544e06:	subl %ecx, $0x4<UINT8>
0x00544e09:	ja 0x00544dfc
0x00544e0b:	addl %edi, %ecx
0x00544e0d:	jmp 0x00544d3e
0x00544db0:	incl %ecx
0x00544db1:	addl %ebx, %ebx
0x00544db3:	jne 0x00544dbc
0x00544dbc:	jb 0x00544d7c
0x00544dbe:	addl %ebx, %ebx
0x00544dc0:	jne 0x00544dc9
0x00544dc9:	adcl %ecx, %ecx
0x00544dcb:	addl %ebx, %ebx
0x00544dcd:	jae 0x00544dbe
0x00544dcf:	jne 0x00544dda
0x00544dda:	addl %ecx, $0x2<UINT8>
0x00544d63:	movl %ebx, (%esi)
0x00544d65:	subl %esi, $0xfffffffc<UINT8>
0x00544d68:	adcl %ebx, %ebx
0x00544d6a:	jb 0x00544d8b
0x00544d54:	movl %ebx, (%esi)
0x00544d56:	subl %esi, $0xfffffffc<UINT8>
0x00544d59:	adcl %ebx, %ebx
0x00544d6c:	decl %eax
0x00544d6d:	addl %ebx, %ebx
0x00544d6f:	jne 0x00544d78
0x00544d78:	adcl %eax, %eax
0x00544d7a:	jmp 0x00544d50
0x00544da7:	movl %ebx, (%esi)
0x00544da9:	subl %esi, $0xfffffffc<UINT8>
0x00544dac:	adcl %ebx, %ebx
0x00544d71:	movl %ebx, (%esi)
0x00544d73:	subl %esi, $0xfffffffc<UINT8>
0x00544d76:	adcl %ebx, %ebx
0x00544db5:	movl %ebx, (%esi)
0x00544db7:	subl %esi, $0xfffffffc<UINT8>
0x00544dba:	adcl %ebx, %ebx
0x00544d80:	movl %ebx, (%esi)
0x00544d82:	subl %esi, $0xfffffffc<UINT8>
0x00544d85:	adcl %ebx, %ebx
0x00544dc2:	movl %ebx, (%esi)
0x00544dc4:	subl %esi, $0xfffffffc<UINT8>
0x00544dc7:	adcl %ebx, %ebx
0x00544dd1:	movl %ebx, (%esi)
0x00544dd3:	subl %esi, $0xfffffffc<UINT8>
0x00544dd6:	adcl %ebx, %ebx
0x00544dd8:	jae 0x00544dbe
0x00544e12:	popl %esi
0x00544e13:	movl %edi, %esi
0x00544e15:	movl %ecx, $0x1d7d<UINT32>
0x00544e1a:	movb %al, (%edi)
0x00544e1c:	incl %edi
0x00544e1d:	subb %al, $0xffffffe8<UINT8>
0x00544e1f:	cmpb %al, $0x1<UINT8>
0x00544e21:	ja 0x00544e1a
0x00544e23:	cmpb (%edi), $0x13<UINT8>
0x00544e26:	jne 0x00544e1a
0x00544e28:	movl %eax, (%edi)
0x00544e2a:	movb %bl, 0x4(%edi)
0x00544e2d:	shrw %ax, $0x8<UINT8>
0x00544e31:	roll %eax, $0x10<UINT8>
0x00544e34:	xchgb %ah, %al
0x00544e36:	subl %eax, %edi
0x00544e38:	subb %bl, $0xffffffe8<UINT8>
0x00544e3b:	addl %eax, %esi
0x00544e3d:	movl (%edi), %eax
0x00544e3f:	addl %edi, $0x5<UINT8>
0x00544e42:	movb %al, %bl
0x00544e44:	loop 0x00544e1f
0x00544e46:	leal %edi, 0x13f000(%esi)
0x00544e4c:	movl %eax, (%edi)
0x00544e4e:	orl %eax, %eax
0x00544e50:	je 0x00544e97
0x00544e52:	movl %ebx, 0x4(%edi)
0x00544e55:	leal %eax, 0x145ec0(%eax,%esi)
0x00544e5c:	addl %ebx, %esi
0x00544e5e:	pushl %eax
0x00544e5f:	addl %edi, $0x8<UINT8>
0x00544e62:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x00544e68:	xchgl %ebp, %eax
0x00544e69:	movb %al, (%edi)
0x00544e6b:	incl %edi
0x00544e6c:	orb %al, %al
0x00544e6e:	je 0x00544e4c
0x00544e70:	movl %ecx, %edi
0x00544e72:	jns 0x00544e7b
0x00544e7b:	pushl %edi
0x00544e7c:	decl %eax
0x00544e7d:	repn scasb %al, %es:(%edi)
0x00544e7f:	pushl %ebp
0x00544e80:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00544e86:	orl %eax, %eax
0x00544e88:	je 7
0x00544e8a:	movl (%ebx), %eax
0x00544e8c:	addl %ebx, $0x4<UINT8>
0x00544e8f:	jmp 0x00544e69
GetProcAddress@KERNEL32.DLL: API Node	
0x00544e74:	movzwl %eax, (%edi)
0x00544e77:	incl %edi
0x00544e78:	pushl %eax
0x00544e79:	incl %edi
0x00544e7a:	movl %ecx, $0xaef24857<UINT32>
0x00544e97:	addl %edi, $0x4<UINT8>
0x00544e9a:	leal %ebx, -4(%esi)
0x00544e9d:	xorl %eax, %eax
0x00544e9f:	movb %al, (%edi)
0x00544ea1:	incl %edi
0x00544ea2:	orl %eax, %eax
0x00544ea4:	je 0x00544ec8
0x00544ea6:	cmpb %al, $0xffffffef<UINT8>
0x00544ea8:	ja 0x00544ebb
0x00544ebb:	andb %al, $0xf<UINT8>
0x00544ebd:	shll %eax, $0x10<UINT8>
0x00544ec0:	movw %ax, (%edi)
0x00544ec3:	addl %edi, $0x2<UINT8>
0x00544ec6:	jmp 0x00544eaa
0x00544eaa:	addl %ebx, %eax
0x00544eac:	movl %eax, (%ebx)
0x00544eae:	xchgb %ah, %al
0x00544eb0:	roll %eax, $0x10<UINT8>
0x00544eb3:	xchgb %ah, %al
0x00544eb5:	addl %eax, %esi
0x00544eb7:	movl (%ebx), %eax
0x00544eb9:	jmp 0x00544e9d
0x00544ec8:	movl %ebp, 0x145ff8(%esi)
0x00544ece:	leal %edi, -4096(%esi)
0x00544ed4:	movl %ebx, $0x1000<UINT32>
0x00544ed9:	pushl %eax
0x00544eda:	pushl %esp
0x00544edb:	pushl $0x4<UINT8>
0x00544edd:	pushl %ebx
0x00544ede:	pushl %edi
0x00544edf:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00544ee1:	leal %eax, 0x237(%edi)
0x00544ee7:	andb (%eax), $0x7f<UINT8>
0x00544eea:	andb 0x28(%eax), $0x7f<UINT8>
0x00544eee:	popl %eax
0x00544eef:	pushl %eax
0x00544ef0:	pushl %esp
0x00544ef1:	pushl %eax
0x00544ef2:	pushl %ebx
0x00544ef3:	pushl %edi
0x00544ef4:	call VirtualProtect@kernel32.dll
0x00544ef6:	popl %eax
0x00544ef7:	popa
0x00544ef8:	leal %eax, -128(%esp)
0x00544efc:	pushl $0x0<UINT8>
0x00544efe:	cmpl %esp, %eax
0x00544f00:	jne 0x00544efc
0x00544f02:	subl %esp, $0xffffff80<UINT8>
0x00544f05:	jmp 0x004313a5
0x004313a5:	call 0x0043ea88
0x0043ea88:	pushl %ebp
0x0043ea89:	movl %ebp, %esp
0x0043ea8b:	subl %esp, $0x14<UINT8>
0x0043ea8e:	andl -12(%ebp), $0x0<UINT8>
0x0043ea92:	andl -8(%ebp), $0x0<UINT8>
0x0043ea96:	movl %eax, 0x45f120
0x0043ea9b:	pushl %esi
0x0043ea9c:	pushl %edi
0x0043ea9d:	movl %edi, $0xbb40e64e<UINT32>
0x0043eaa2:	movl %esi, $0xffff0000<UINT32>
0x0043eaa7:	cmpl %eax, %edi
0x0043eaa9:	je 0x0043eab8
0x0043eab8:	leal %eax, -12(%ebp)
0x0043eabb:	pushl %eax
0x0043eabc:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0043eac2:	movl %eax, -8(%ebp)
0x0043eac5:	xorl %eax, -12(%ebp)
0x0043eac8:	movl -4(%ebp), %eax
0x0043eacb:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0043ead1:	xorl -4(%ebp), %eax
0x0043ead4:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0043eada:	xorl -4(%ebp), %eax
0x0043eadd:	leal %eax, -20(%ebp)
0x0043eae0:	pushl %eax
0x0043eae1:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0043eae7:	movl %ecx, -16(%ebp)
0x0043eaea:	leal %eax, -4(%ebp)
0x0043eaed:	xorl %ecx, -20(%ebp)
0x0043eaf0:	xorl %ecx, -4(%ebp)
0x0043eaf3:	xorl %ecx, %eax
0x0043eaf5:	cmpl %ecx, %edi
0x0043eaf7:	jne 0x0043eb00
0x0043eb00:	testl %esi, %ecx
0x0043eb02:	jne 0x0043eb10
0x0043eb10:	movl 0x45f120, %ecx
0x0043eb16:	notl %ecx
0x0043eb18:	movl 0x45f124, %ecx
0x0043eb1e:	popl %edi
0x0043eb1f:	popl %esi
0x0043eb20:	movl %esp, %ebp
0x0043eb22:	popl %ebp
0x0043eb23:	ret

0x004313aa:	jmp 0x004313af
0x004313af:	pushl $0x14<UINT8>
0x004313b1:	pushl $0x45c7e0<UINT32>
0x004313b6:	call 0x00433460
0x00433460:	pushl $0x42fb80<UINT32>
0x00433465:	pushl %fs:0
0x0043346c:	movl %eax, 0x10(%esp)
0x00433470:	movl 0x10(%esp), %ebp
0x00433474:	leal %ebp, 0x10(%esp)
0x00433478:	subl %esp, %eax
0x0043347a:	pushl %ebx
0x0043347b:	pushl %esi
0x0043347c:	pushl %edi
0x0043347d:	movl %eax, 0x45f120
0x00433482:	xorl -4(%ebp), %eax
0x00433485:	xorl %eax, %ebp
0x00433487:	pushl %eax
0x00433488:	movl -24(%ebp), %esp
0x0043348b:	pushl -8(%ebp)
0x0043348e:	movl %eax, -4(%ebp)
0x00433491:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00433498:	movl -8(%ebp), %eax
0x0043349b:	leal %eax, -16(%ebp)
0x0043349e:	movl %fs:0, %eax
0x004334a4:	ret

0x004313bb:	call 0x00432988
0x00432988:	pushl %ebp
0x00432989:	movl %ebp, %esp
0x0043298b:	subl %esp, $0x44<UINT8>
0x0043298e:	leal %eax, -68(%ebp)
0x00432991:	pushl %eax
0x00432992:	call GetStartupInfoW@KERNEL32.DLL
GetStartupInfoW@KERNEL32.DLL: API Node	
0x00432998:	testb -24(%ebp), $0x1<UINT8>
0x0043299c:	je 0x004329a4
0x004329a4:	pushl $0xa<UINT8>
0x004329a6:	popl %eax
0x004329a7:	movl %esp, %ebp
0x004329a9:	popl %ebp
0x004329aa:	ret

0x004313c0:	movzwl %esi, %ax
0x004313c3:	pushl $0x2<UINT8>
0x004313c5:	call 0x0043ea3b
0x0043ea3b:	pushl %ebp
0x0043ea3c:	movl %ebp, %esp
0x0043ea3e:	movl %eax, 0x8(%ebp)
0x0043ea41:	movl 0x462a48, %eax
0x0043ea46:	popl %ebp
0x0043ea47:	ret

0x004313ca:	popl %ecx
0x004313cb:	movl %eax, $0x5a4d<UINT32>
0x004313d0:	cmpw 0x400000, %ax
0x004313d7:	je 0x004313dd
0x004313dd:	movl %eax, 0x40003c
0x004313e2:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x004313ec:	jne -21
0x004313ee:	movl %ecx, $0x10b<UINT32>
0x004313f3:	cmpw 0x400018(%eax), %cx
0x004313fa:	jne -35
0x004313fc:	xorl %ebx, %ebx
0x004313fe:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00431405:	jbe 9
0x00431407:	cmpl 0x4000e8(%eax), %ebx
0x0043140d:	setne %bl
0x00431410:	movl -28(%ebp), %ebx
0x00431413:	call 0x00433590
0x00433590:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x00433596:	xorl %ecx, %ecx
0x00433598:	movl 0x4630a4, %eax
0x0043359d:	testl %eax, %eax
0x0043359f:	setne %cl
0x004335a2:	movl %eax, %ecx
0x004335a4:	ret

0x00431418:	testl %eax, %eax
0x0043141a:	jne 0x00431424
0x00431424:	call 0x004325de
0x004325de:	call 0x0042a768
0x0042a768:	pushl %esi
0x0042a769:	pushl $0x0<UINT8>
0x0042a76b:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x0042a771:	movl %esi, %eax
0x0042a773:	pushl %esi
0x0042a774:	call 0x0042dc01
0x0042dc01:	pushl %ebp
0x0042dc02:	movl %ebp, %esp
0x0042dc04:	movl %eax, 0x8(%ebp)
0x0042dc07:	movl 0x462588, %eax
0x0042dc0c:	popl %ebp
0x0042dc0d:	ret

0x0042a779:	pushl %esi
0x0042a77a:	call 0x004317c4
0x004317c4:	pushl %ebp
0x004317c5:	movl %ebp, %esp
0x004317c7:	movl %eax, 0x8(%ebp)
0x004317ca:	movl 0x4628d0, %eax
0x004317cf:	popl %ebp
0x004317d0:	ret

0x0042a77f:	pushl %esi
0x0042a780:	call 0x00433227
0x00433227:	pushl %ebp
0x00433228:	movl %ebp, %esp
0x0043322a:	movl %eax, 0x8(%ebp)
0x0043322d:	movl 0x463080, %eax
0x00433232:	popl %ebp
0x00433233:	ret

0x0042a785:	pushl %esi
0x0042a786:	call 0x00433241
0x00433241:	pushl %ebp
0x00433242:	movl %ebp, %esp
0x00433244:	movl %eax, 0x8(%ebp)
0x00433247:	movl 0x463084, %eax
0x0043324c:	movl 0x463088, %eax
0x00433251:	movl 0x46308c, %eax
0x00433256:	movl 0x463090, %eax
0x0043325b:	popl %ebp
0x0043325c:	ret

0x0042a78b:	pushl %esi
0x0042a78c:	call 0x00433216
0x00433216:	pushl $0x4331cf<UINT32>
0x0043321b:	call EncodePointer@KERNEL32.DLL
0x00433221:	movl 0x46307c, %eax
0x00433226:	ret

0x0042a791:	pushl %esi
0x0042a792:	call 0x00433452
0x00433452:	pushl %ebp
0x00433453:	movl %ebp, %esp
0x00433455:	movl %eax, 0x8(%ebp)
0x00433458:	movl 0x463098, %eax
0x0043345d:	popl %ebp
0x0043345e:	ret

0x0042a797:	addl %esp, $0x18<UINT8>
0x0042a79a:	popl %esi
0x0042a79b:	jmp 0x00432a19
0x00432a19:	pushl %esi
0x00432a1a:	pushl %edi
0x00432a1b:	pushl $0x44fb4c<UINT32>
0x00432a20:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00432a26:	movl %esi, 0x449330
0x00432a2c:	movl %edi, %eax
0x00432a2e:	pushl $0x454658<UINT32>
0x00432a33:	pushl %edi
0x00432a34:	call GetProcAddress@KERNEL32.DLL
0x00432a36:	xorl %eax, 0x45f120
0x00432a3c:	pushl $0x454664<UINT32>
0x00432a41:	pushl %edi
0x00432a42:	movl 0x464440, %eax
0x00432a47:	call GetProcAddress@KERNEL32.DLL
0x00432a49:	xorl %eax, 0x45f120
0x00432a4f:	pushl $0x45466c<UINT32>
0x00432a54:	pushl %edi
0x00432a55:	movl 0x464444, %eax
0x00432a5a:	call GetProcAddress@KERNEL32.DLL
0x00432a5c:	xorl %eax, 0x45f120
0x00432a62:	pushl $0x454678<UINT32>
0x00432a67:	pushl %edi
0x00432a68:	movl 0x464448, %eax
0x00432a6d:	call GetProcAddress@KERNEL32.DLL
0x00432a6f:	xorl %eax, 0x45f120
0x00432a75:	pushl $0x454684<UINT32>
0x00432a7a:	pushl %edi
0x00432a7b:	movl 0x46444c, %eax
0x00432a80:	call GetProcAddress@KERNEL32.DLL
0x00432a82:	xorl %eax, 0x45f120
0x00432a88:	pushl $0x4546a0<UINT32>
0x00432a8d:	pushl %edi
0x00432a8e:	movl 0x464450, %eax
0x00432a93:	call GetProcAddress@KERNEL32.DLL
0x00432a95:	xorl %eax, 0x45f120
0x00432a9b:	pushl $0x4546b0<UINT32>
0x00432aa0:	pushl %edi
0x00432aa1:	movl 0x464454, %eax
0x00432aa6:	call GetProcAddress@KERNEL32.DLL
0x00432aa8:	xorl %eax, 0x45f120
0x00432aae:	pushl $0x4546c4<UINT32>
0x00432ab3:	pushl %edi
0x00432ab4:	movl 0x464458, %eax
0x00432ab9:	call GetProcAddress@KERNEL32.DLL
0x00432abb:	xorl %eax, 0x45f120
0x00432ac1:	pushl $0x4546dc<UINT32>
0x00432ac6:	pushl %edi
0x00432ac7:	movl 0x46445c, %eax
0x00432acc:	call GetProcAddress@KERNEL32.DLL
0x00432ace:	xorl %eax, 0x45f120
0x00432ad4:	pushl $0x4546f4<UINT32>
0x00432ad9:	pushl %edi
0x00432ada:	movl 0x464460, %eax
0x00432adf:	call GetProcAddress@KERNEL32.DLL
0x00432ae1:	xorl %eax, 0x45f120
0x00432ae7:	pushl $0x454708<UINT32>
0x00432aec:	pushl %edi
0x00432aed:	movl 0x464464, %eax
0x00432af2:	call GetProcAddress@KERNEL32.DLL
0x00432af4:	xorl %eax, 0x45f120
0x00432afa:	pushl $0x454728<UINT32>
0x00432aff:	pushl %edi
0x00432b00:	movl 0x464468, %eax
0x00432b05:	call GetProcAddress@KERNEL32.DLL
0x00432b07:	xorl %eax, 0x45f120
0x00432b0d:	pushl $0x454740<UINT32>
0x00432b12:	pushl %edi
0x00432b13:	movl 0x46446c, %eax
0x00432b18:	call GetProcAddress@KERNEL32.DLL
0x00432b1a:	xorl %eax, 0x45f120
0x00432b20:	pushl $0x454758<UINT32>
0x00432b25:	pushl %edi
0x00432b26:	movl 0x464470, %eax
0x00432b2b:	call GetProcAddress@KERNEL32.DLL
0x00432b2d:	xorl %eax, 0x45f120
0x00432b33:	pushl $0x45476c<UINT32>
0x00432b38:	pushl %edi
0x00432b39:	movl 0x464474, %eax
0x00432b3e:	call GetProcAddress@KERNEL32.DLL
0x00432b40:	xorl %eax, 0x45f120
0x00432b46:	movl 0x464478, %eax
0x00432b4b:	pushl $0x454780<UINT32>
0x00432b50:	pushl %edi
0x00432b51:	call GetProcAddress@KERNEL32.DLL
0x00432b53:	xorl %eax, 0x45f120
0x00432b59:	pushl $0x45479c<UINT32>
0x00432b5e:	pushl %edi
0x00432b5f:	movl 0x46447c, %eax
0x00432b64:	call GetProcAddress@KERNEL32.DLL
0x00432b66:	xorl %eax, 0x45f120
0x00432b6c:	pushl $0x4547bc<UINT32>
0x00432b71:	pushl %edi
0x00432b72:	movl 0x464480, %eax
0x00432b77:	call GetProcAddress@KERNEL32.DLL
0x00432b79:	xorl %eax, 0x45f120
0x00432b7f:	pushl $0x4547d8<UINT32>
0x00432b84:	pushl %edi
0x00432b85:	movl 0x464484, %eax
0x00432b8a:	call GetProcAddress@KERNEL32.DLL
0x00432b8c:	xorl %eax, 0x45f120
0x00432b92:	pushl $0x4547f8<UINT32>
0x00432b97:	pushl %edi
0x00432b98:	movl 0x464488, %eax
0x00432b9d:	call GetProcAddress@KERNEL32.DLL
0x00432b9f:	xorl %eax, 0x45f120
0x00432ba5:	pushl $0x4503d4<UINT32>
0x00432baa:	pushl %edi
0x00432bab:	movl 0x46448c, %eax
0x00432bb0:	call GetProcAddress@KERNEL32.DLL
0x00432bb2:	xorl %eax, 0x45f120
0x00432bb8:	pushl $0x45480c<UINT32>
0x00432bbd:	pushl %edi
0x00432bbe:	movl 0x464490, %eax
0x00432bc3:	call GetProcAddress@KERNEL32.DLL
0x00432bc5:	xorl %eax, 0x45f120
0x00432bcb:	pushl $0x454820<UINT32>
0x00432bd0:	pushl %edi
0x00432bd1:	movl 0x464498, %eax
0x00432bd6:	call GetProcAddress@KERNEL32.DLL
0x00432bd8:	xorl %eax, 0x45f120
0x00432bde:	pushl $0x454830<UINT32>
0x00432be3:	pushl %edi
0x00432be4:	movl 0x464494, %eax
0x00432be9:	call GetProcAddress@KERNEL32.DLL
0x00432beb:	xorl %eax, 0x45f120
0x00432bf1:	pushl $0x454840<UINT32>
0x00432bf6:	pushl %edi
0x00432bf7:	movl 0x46449c, %eax
0x00432bfc:	call GetProcAddress@KERNEL32.DLL
0x00432bfe:	xorl %eax, 0x45f120
0x00432c04:	pushl $0x454850<UINT32>
0x00432c09:	pushl %edi
0x00432c0a:	movl 0x4644a0, %eax
0x00432c0f:	call GetProcAddress@KERNEL32.DLL
0x00432c11:	xorl %eax, 0x45f120
0x00432c17:	pushl $0x454860<UINT32>
0x00432c1c:	pushl %edi
0x00432c1d:	movl 0x4644a4, %eax
0x00432c22:	call GetProcAddress@KERNEL32.DLL
0x00432c24:	xorl %eax, 0x45f120
0x00432c2a:	pushl $0x45487c<UINT32>
0x00432c2f:	pushl %edi
0x00432c30:	movl 0x4644a8, %eax
0x00432c35:	call GetProcAddress@KERNEL32.DLL
0x00432c37:	xorl %eax, 0x45f120
0x00432c3d:	pushl $0x454890<UINT32>
0x00432c42:	pushl %edi
0x00432c43:	movl 0x4644ac, %eax
0x00432c48:	call GetProcAddress@KERNEL32.DLL
0x00432c4a:	xorl %eax, 0x45f120
0x00432c50:	pushl $0x4548a0<UINT32>
0x00432c55:	pushl %edi
0x00432c56:	movl 0x4644b0, %eax
0x00432c5b:	call GetProcAddress@KERNEL32.DLL
0x00432c5d:	xorl %eax, 0x45f120
0x00432c63:	pushl $0x4548b4<UINT32>
0x00432c68:	pushl %edi
0x00432c69:	movl 0x4644b4, %eax
0x00432c6e:	call GetProcAddress@KERNEL32.DLL
0x00432c70:	xorl %eax, 0x45f120
0x00432c76:	movl 0x4644b8, %eax
0x00432c7b:	pushl $0x4548c4<UINT32>
0x00432c80:	pushl %edi
0x00432c81:	call GetProcAddress@KERNEL32.DLL
0x00432c83:	xorl %eax, 0x45f120
0x00432c89:	pushl $0x4548e4<UINT32>
0x00432c8e:	pushl %edi
0x00432c8f:	movl 0x4644bc, %eax
0x00432c94:	call GetProcAddress@KERNEL32.DLL
0x00432c96:	xorl %eax, 0x45f120
0x00432c9c:	popl %edi
0x00432c9d:	movl 0x4644c0, %eax
0x00432ca2:	popl %esi
0x00432ca3:	ret

0x004325e3:	call 0x004328bc
0x004328bc:	pushl %esi
0x004328bd:	pushl %edi
0x004328be:	movl %esi, $0x45fa28<UINT32>
0x004328c3:	movl %edi, $0x4628f8<UINT32>
0x004328c8:	cmpl 0x4(%esi), $0x1<UINT8>
0x004328cc:	jne 22
0x004328ce:	pushl $0x0<UINT8>
0x004328d0:	movl (%esi), %edi
0x004328d2:	addl %edi, $0x18<UINT8>
0x004328d5:	pushl $0xfa0<UINT32>
0x004328da:	pushl (%esi)
0x004328dc:	call 0x004329ab
0x004329ab:	pushl %ebp
0x004329ac:	movl %ebp, %esp
0x004329ae:	movl %eax, 0x464450
0x004329b3:	xorl %eax, 0x45f120
0x004329b9:	je 13
0x004329bb:	pushl 0x10(%ebp)
0x004329be:	pushl 0xc(%ebp)
0x004329c1:	pushl 0x8(%ebp)
0x004329c4:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x004329c6:	popl %ebp
0x004329c7:	ret

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
