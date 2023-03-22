0x00711cf0:	pusha
0x00711cf1:	movl %esi, $0x60c000<UINT32>
0x00711cf6:	leal %edi, -2142208(%esi)
0x00711cfc:	pushl %edi
0x00711cfd:	orl %ebp, $0xffffffff<UINT8>
0x00711d00:	jmp 0x00711d12
0x00711d12:	movl %ebx, (%esi)
0x00711d14:	subl %esi, $0xfffffffc<UINT8>
0x00711d17:	adcl %ebx, %ebx
0x00711d19:	jb 0x00711d08
0x00711d08:	movb %al, (%esi)
0x00711d0a:	incl %esi
0x00711d0b:	movb (%edi), %al
0x00711d0d:	incl %edi
0x00711d0e:	addl %ebx, %ebx
0x00711d10:	jne 0x00711d19
0x00711d1b:	movl %eax, $0x1<UINT32>
0x00711d20:	addl %ebx, %ebx
0x00711d22:	jne 0x00711d2b
0x00711d2b:	adcl %eax, %eax
0x00711d2d:	addl %ebx, %ebx
0x00711d2f:	jae 0x00711d3c
0x00711d31:	jne 0x00711d5b
0x00711d5b:	xorl %ecx, %ecx
0x00711d5d:	subl %eax, $0x3<UINT8>
0x00711d60:	jb 0x00711d73
0x00711d73:	addl %ebx, %ebx
0x00711d75:	jne 0x00711d7e
0x00711d7e:	jb 0x00711d4c
0x00711d80:	incl %ecx
0x00711d81:	addl %ebx, %ebx
0x00711d83:	jne 0x00711d8c
0x00711d8c:	jb 0x00711d4c
0x00711d8e:	addl %ebx, %ebx
0x00711d90:	jne 0x00711d99
0x00711d99:	adcl %ecx, %ecx
0x00711d9b:	addl %ebx, %ebx
0x00711d9d:	jae 0x00711d8e
0x00711d9f:	jne 0x00711daa
0x00711daa:	addl %ecx, $0x2<UINT8>
0x00711dad:	cmpl %ebp, $0xfffffb00<UINT32>
0x00711db3:	adcl %ecx, $0x2<UINT8>
0x00711db6:	leal %edx, (%edi,%ebp)
0x00711db9:	cmpl %ebp, $0xfffffffc<UINT8>
0x00711dbc:	jbe 0x00711dcc
0x00711dbe:	movb %al, (%edx)
0x00711dc0:	incl %edx
0x00711dc1:	movb (%edi), %al
0x00711dc3:	incl %edi
0x00711dc4:	decl %ecx
0x00711dc5:	jne 0x00711dbe
0x00711dc7:	jmp 0x00711d0e
0x00711d4c:	addl %ebx, %ebx
0x00711d4e:	jne 0x00711d57
0x00711d57:	adcl %ecx, %ecx
0x00711d59:	jmp 0x00711dad
0x00711d62:	shll %eax, $0x8<UINT8>
0x00711d65:	movb %al, (%esi)
0x00711d67:	incl %esi
0x00711d68:	xorl %eax, $0xffffffff<UINT8>
0x00711d6b:	je 0x00711de2
0x00711d6d:	sarl %eax
0x00711d6f:	movl %ebp, %eax
0x00711d71:	jmp 0x00711d7e
0x00711dcc:	movl %eax, (%edx)
0x00711dce:	addl %edx, $0x4<UINT8>
0x00711dd1:	movl (%edi), %eax
0x00711dd3:	addl %edi, $0x4<UINT8>
0x00711dd6:	subl %ecx, $0x4<UINT8>
0x00711dd9:	ja 0x00711dcc
0x00711ddb:	addl %edi, %ecx
0x00711ddd:	jmp 0x00711d0e
0x00711d24:	movl %ebx, (%esi)
0x00711d26:	subl %esi, $0xfffffffc<UINT8>
0x00711d29:	adcl %ebx, %ebx
0x00711da1:	movl %ebx, (%esi)
0x00711da3:	subl %esi, $0xfffffffc<UINT8>
0x00711da6:	adcl %ebx, %ebx
0x00711da8:	jae 0x00711d8e
0x00711d77:	movl %ebx, (%esi)
0x00711d79:	subl %esi, $0xfffffffc<UINT8>
0x00711d7c:	adcl %ebx, %ebx
0x00711d3c:	decl %eax
0x00711d3d:	addl %ebx, %ebx
0x00711d3f:	jne 0x00711d48
0x00711d48:	adcl %eax, %eax
0x00711d4a:	jmp 0x00711d20
0x00711d33:	movl %ebx, (%esi)
0x00711d35:	subl %esi, $0xfffffffc<UINT8>
0x00711d38:	adcl %ebx, %ebx
0x00711d3a:	jb 0x00711d5b
0x00711d50:	movl %ebx, (%esi)
0x00711d52:	subl %esi, $0xfffffffc<UINT8>
0x00711d55:	adcl %ebx, %ebx
0x00711d85:	movl %ebx, (%esi)
0x00711d87:	subl %esi, $0xfffffffc<UINT8>
0x00711d8a:	adcl %ebx, %ebx
0x00711d92:	movl %ebx, (%esi)
0x00711d94:	subl %esi, $0xfffffffc<UINT8>
0x00711d97:	adcl %ebx, %ebx
0x00711d41:	movl %ebx, (%esi)
0x00711d43:	subl %esi, $0xfffffffc<UINT8>
0x00711d46:	adcl %ebx, %ebx
0x00711de2:	popl %esi
0x00711de3:	movl %edi, %esi
0x00711de5:	movl %ecx, $0x8cb3<UINT32>
0x00711dea:	movb %al, (%edi)
0x00711dec:	incl %edi
0x00711ded:	subb %al, $0xffffffe8<UINT8>
0x00711def:	cmpb %al, $0x1<UINT8>
0x00711df1:	ja 0x00711dea
0x00711df3:	cmpb (%edi), $0x47<UINT8>
0x00711df6:	jne 0x00711dea
0x00711df8:	movl %eax, (%edi)
0x00711dfa:	movb %bl, 0x4(%edi)
0x00711dfd:	shrw %ax, $0x8<UINT8>
0x00711e01:	roll %eax, $0x10<UINT8>
0x00711e04:	xchgb %ah, %al
0x00711e06:	subl %eax, %edi
0x00711e08:	subb %bl, $0xffffffe8<UINT8>
0x00711e0b:	addl %eax, %esi
0x00711e0d:	movl (%edi), %eax
0x00711e0f:	addl %edi, $0x5<UINT8>
0x00711e12:	movb %al, %bl
0x00711e14:	loop 0x00711def
0x00711e16:	leal %edi, 0x30e000(%esi)
0x00711e1c:	movl %eax, (%edi)
0x00711e1e:	orl %eax, %eax
0x00711e20:	je 0x00711e67
0x00711e22:	movl %ebx, 0x4(%edi)
0x00711e25:	leal %eax, 0x330474(%eax,%esi)
0x00711e2c:	addl %ebx, %esi
0x00711e2e:	pushl %eax
0x00711e2f:	addl %edi, $0x8<UINT8>
0x00711e32:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00711e38:	xchgl %ebp, %eax
0x00711e39:	movb %al, (%edi)
0x00711e3b:	incl %edi
0x00711e3c:	orb %al, %al
0x00711e3e:	je 0x00711e1c
0x00711e40:	movl %ecx, %edi
0x00711e42:	jns 0x00711e4b
0x00711e4b:	pushl %edi
0x00711e4c:	decl %eax
0x00711e4d:	repn scasb %al, %es:(%edi)
0x00711e4f:	pushl %ebp
0x00711e50:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00711e56:	orl %eax, %eax
0x00711e58:	je 7
0x00711e5a:	movl (%ebx), %eax
0x00711e5c:	addl %ebx, $0x4<UINT8>
0x00711e5f:	jmp 0x00711e39
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x00711e44:	movzwl %eax, (%edi)
0x00711e47:	incl %edi
0x00711e48:	pushl %eax
0x00711e49:	incl %edi
0x00711e4a:	movl %ecx, $0xaef24857<UINT32>
0x00711e67:	movl %ebp, 0x330594(%esi)
0x00711e6d:	leal %edi, -4096(%esi)
0x00711e73:	movl %ebx, $0x1000<UINT32>
0x00711e78:	pushl %eax
0x00711e79:	pushl %esp
0x00711e7a:	pushl $0x4<UINT8>
0x00711e7c:	pushl %ebx
0x00711e7d:	pushl %edi
0x00711e7e:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00711e80:	leal %eax, 0x227(%edi)
0x00711e86:	andb (%eax), $0x7f<UINT8>
0x00711e89:	andb 0x28(%eax), $0x7f<UINT8>
0x00711e8d:	popl %eax
0x00711e8e:	pushl %eax
0x00711e8f:	pushl %esp
0x00711e90:	pushl %eax
0x00711e91:	pushl %ebx
0x00711e92:	pushl %edi
0x00711e93:	call VirtualProtect@kernel32.dll
0x00711e95:	popl %eax
0x00711e96:	popa
0x00711e97:	leal %eax, -128(%esp)
0x00711e9b:	pushl $0x0<UINT8>
0x00711e9d:	cmpl %esp, %eax
0x00711e9f:	jne 0x00711e9b
0x00711ea1:	subl %esp, $0xffffff80<UINT8>
0x00711ea4:	jmp 0x004f7c76
0x004f7c76:	call 0x004fd530
0x004fd530:	movl %edi, %edi
0x004fd532:	pushl %ebp
0x004fd533:	movl %ebp, %esp
0x004fd535:	subl %esp, $0x10<UINT8>
0x004fd538:	movl %eax, 0x57d770
0x004fd53d:	andl -8(%ebp), $0x0<UINT8>
0x004fd541:	andl -4(%ebp), $0x0<UINT8>
0x004fd545:	pushl %ebx
0x004fd546:	pushl %edi
0x004fd547:	movl %edi, $0xbb40e64e<UINT32>
0x004fd54c:	movl %ebx, $0xffff0000<UINT32>
0x004fd551:	cmpl %eax, %edi
0x004fd553:	je 0x004fd562
0x004fd562:	pushl %esi
0x004fd563:	leal %eax, -8(%ebp)
0x004fd566:	pushl %eax
0x004fd567:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x004fd56d:	movl %esi, -4(%ebp)
0x004fd570:	xorl %esi, -8(%ebp)
0x004fd573:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x004fd579:	xorl %esi, %eax
0x004fd57b:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x004fd581:	xorl %esi, %eax
0x004fd583:	call GetTickCount@KERNEL32.DLL
GetTickCount@KERNEL32.DLL: API Node	
0x004fd589:	xorl %esi, %eax
0x004fd58b:	leal %eax, -16(%ebp)
0x004fd58e:	pushl %eax
0x004fd58f:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x004fd595:	movl %eax, -12(%ebp)
0x004fd598:	xorl %eax, -16(%ebp)
0x004fd59b:	xorl %esi, %eax
0x004fd59d:	cmpl %esi, %edi
0x004fd59f:	jne 0x004fd5a8
0x004fd5a8:	testl %ebx, %esi
0x004fd5aa:	jne 0x004fd5b3
0x004fd5b3:	movl 0x57d770, %esi
0x004fd5b9:	notl %esi
0x004fd5bb:	movl 0x57d774, %esi
0x004fd5c1:	popl %esi
0x004fd5c2:	popl %edi
0x004fd5c3:	popl %ebx
0x004fd5c4:	leave
0x004fd5c5:	ret

0x004f7c7b:	jmp 0x004f7af9
0x004f7af9:	pushl $0x58<UINT8>
0x004f7afb:	pushl $0x55fbc0<UINT32>
0x004f7b00:	call 0x004fa434
0x004fa434:	pushl $0x4f93c0<UINT32>
0x004fa439:	pushl %fs:0
0x004fa440:	movl %eax, 0x10(%esp)
0x004fa444:	movl 0x10(%esp), %ebp
0x004fa448:	leal %ebp, 0x10(%esp)
0x004fa44c:	subl %esp, %eax
0x004fa44e:	pushl %ebx
0x004fa44f:	pushl %esi
0x004fa450:	pushl %edi
0x004fa451:	movl %eax, 0x57d770
0x004fa456:	xorl -4(%ebp), %eax
0x004fa459:	xorl %eax, %ebp
0x004fa45b:	pushl %eax
0x004fa45c:	movl -24(%ebp), %esp
0x004fa45f:	pushl -8(%ebp)
0x004fa462:	movl %eax, -4(%ebp)
0x004fa465:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004fa46c:	movl -8(%ebp), %eax
0x004fa46f:	leal %eax, -16(%ebp)
0x004fa472:	movl %fs:0, %eax
0x004fa478:	ret

0x004f7b05:	xorl %esi, %esi
0x004f7b07:	movl -4(%ebp), %esi
0x004f7b0a:	leal %eax, -104(%ebp)
0x004f7b0d:	pushl %eax
0x004f7b0e:	call GetStartupInfoW@KERNEL32.DLL
GetStartupInfoW@KERNEL32.DLL: API Node	
0x004f7b14:	pushl $0xfffffffe<UINT8>
0x004f7b16:	popl %edi
0x004f7b17:	movl -4(%ebp), %edi
0x004f7b1a:	movl %eax, $0x5a4d<UINT32>
0x004f7b1f:	cmpw 0x400000, %ax
0x004f7b26:	jne 56
0x004f7b28:	movl %eax, 0x40003c
0x004f7b2d:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x004f7b37:	jne 39
0x004f7b39:	movl %ecx, $0x10b<UINT32>
0x004f7b3e:	cmpw 0x400018(%eax), %cx
0x004f7b45:	jne 25
0x004f7b47:	cmpl 0x400074(%eax), $0xe<UINT8>
0x004f7b4e:	jbe 16
0x004f7b50:	xorl %ecx, %ecx
0x004f7b52:	cmpl 0x4000e8(%eax), %esi
0x004f7b58:	setne %cl
0x004f7b5b:	movl -28(%ebp), %ecx
0x004f7b5e:	jmp 0x004f7b63
0x004f7b63:	xorl %ebx, %ebx
0x004f7b65:	incl %ebx
0x004f7b66:	pushl %ebx
0x004f7b67:	call 0x004fd500
0x004fd500:	movl %edi, %edi
0x004fd502:	pushl %ebp
0x004fd503:	movl %ebp, %esp
0x004fd505:	xorl %eax, %eax
0x004fd507:	cmpl 0x8(%ebp), %eax
0x004fd50a:	pushl $0x0<UINT8>
0x004fd50c:	sete %al
0x004fd50f:	pushl $0x1000<UINT32>
0x004fd514:	pushl %eax
0x004fd515:	call HeapCreate@KERNEL32.DLL
HeapCreate@KERNEL32.DLL: API Node	
0x004fd51b:	movl 0x588dfc, %eax
0x004fd520:	testl %eax, %eax
0x004fd522:	jne 0x004fd526
0x004fd526:	xorl %eax, %eax
0x004fd528:	incl %eax
0x004fd529:	movl 0x58b704, %eax
0x004fd52e:	popl %ebp
0x004fd52f:	ret

0x004f7b6c:	popl %ecx
0x004f7b6d:	testl %eax, %eax
0x004f7b6f:	jne 0x004f7b79
0x004f7b79:	call 0x004fd373
0x004fd373:	movl %edi, %edi
0x004fd375:	pushl %esi
0x004fd376:	pushl %edi
0x004fd377:	movl %esi, $0x53ba80<UINT32>
0x004fd37c:	pushl %esi
0x004fd37d:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x004fd383:	testl %eax, %eax
0x004fd385:	jne 0x004fd38e
0x004fd38e:	movl %edi, %eax
0x004fd390:	testl %edi, %edi
0x004fd392:	je 350
0x004fd398:	movl %esi, 0x51d368
0x004fd39e:	pushl $0x53bacc<UINT32>
0x004fd3a3:	pushl %edi
0x004fd3a4:	call GetProcAddress@KERNEL32.DLL
0x004fd3a6:	pushl $0x53bac0<UINT32>
0x004fd3ab:	pushl %edi
0x004fd3ac:	movl 0x588dec, %eax
0x004fd3b1:	call GetProcAddress@KERNEL32.DLL
0x004fd3b3:	pushl $0x53bab4<UINT32>
0x004fd3b8:	pushl %edi
0x004fd3b9:	movl 0x588df0, %eax
0x004fd3be:	call GetProcAddress@KERNEL32.DLL
0x004fd3c0:	pushl $0x53baac<UINT32>
0x004fd3c5:	pushl %edi
0x004fd3c6:	movl 0x588df4, %eax
0x004fd3cb:	call GetProcAddress@KERNEL32.DLL
0x004fd3cd:	cmpl 0x588dec, $0x0<UINT8>
0x004fd3d4:	movl %esi, 0x51d1f8
0x004fd3da:	movl 0x588df8, %eax
0x004fd3df:	je 22
0x004fd3e1:	cmpl 0x588df0, $0x0<UINT8>
0x004fd3e8:	je 13
0x004fd3ea:	cmpl 0x588df4, $0x0<UINT8>
0x004fd3f1:	je 4
0x004fd3f3:	testl %eax, %eax
0x004fd3f5:	jne 0x004fd41b
0x004fd41b:	call TlsAlloc@KERNEL32.DLL
TlsAlloc@KERNEL32.DLL: API Node	
0x004fd421:	movl 0x57da1c, %eax
0x004fd426:	cmpl %eax, $0xffffffff<UINT8>
0x004fd429:	je 204
0x004fd42f:	pushl 0x588df0
0x004fd435:	pushl %eax
0x004fd436:	call TlsSetValue@KERNEL32.DLL
TlsSetValue@KERNEL32.DLL: API Node	
0x004fd438:	testl %eax, %eax
0x004fd43a:	je 187
0x004fd440:	call 0x004fc23d
0x004fc23d:	movl %edi, %edi
0x004fc23f:	pushl %esi
0x004fc240:	call 0x004fcfd5
0x004fcfd5:	pushl $0x0<UINT8>
0x004fcfd7:	call 0x004fcf63
0x004fcf63:	movl %edi, %edi
0x004fcf65:	pushl %ebp
0x004fcf66:	movl %ebp, %esp
0x004fcf68:	pushl %esi
0x004fcf69:	pushl 0x57da1c
0x004fcf6f:	movl %esi, 0x51d20c
0x004fcf75:	call TlsGetValue@KERNEL32.DLL
TlsGetValue@KERNEL32.DLL: API Node	
0x004fcf77:	testl %eax, %eax
0x004fcf79:	je 33
0x004fcf7b:	movl %eax, 0x57da18
0x004fcf80:	cmpl %eax, $0xffffffff<UINT8>
0x004fcf83:	je 0x004fcf9c
0x004fcf9c:	movl %esi, $0x53ba80<UINT32>
0x004fcfa1:	pushl %esi
0x004fcfa2:	call GetModuleHandleW@KERNEL32.DLL
0x004fcfa8:	testl %eax, %eax
0x004fcfaa:	jne 0x004fcfb7
0x004fcfb7:	pushl $0x53ba70<UINT32>
0x004fcfbc:	pushl %eax
0x004fcfbd:	call GetProcAddress@KERNEL32.DLL
0x004fcfc3:	testl %eax, %eax
0x004fcfc5:	je 8
0x004fcfc7:	pushl 0x8(%ebp)
0x004fcfca:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x004fcfcc:	movl 0x8(%ebp), %eax
0x004fcfcf:	movl %eax, 0x8(%ebp)
0x004fcfd2:	popl %esi
0x004fcfd3:	popl %ebp
0x004fcfd4:	ret

0x004fcfdc:	popl %ecx
0x004fcfdd:	ret

0x004fc245:	movl %esi, %eax
0x004fc247:	pushl %esi
0x004fc248:	call 0x00505a36
0x00505a36:	movl %edi, %edi
0x00505a38:	pushl %ebp
0x00505a39:	movl %ebp, %esp
0x00505a3b:	movl %eax, 0x8(%ebp)
0x00505a3e:	movl 0x58929c, %eax
0x00505a43:	popl %ebp
0x00505a44:	ret

0x004fc24d:	pushl %esi
0x004fc24e:	call 0x00508bed
0x00508bed:	movl %edi, %edi
0x00508bef:	pushl %ebp
0x00508bf0:	movl %ebp, %esp
0x00508bf2:	movl %eax, 0x8(%ebp)
0x00508bf5:	movl 0x5892cc, %eax
0x00508bfa:	popl %ebp
0x00508bfb:	ret

0x004fc253:	pushl %esi
0x004fc254:	call 0x004fd6cc
0x004fd6cc:	movl %edi, %edi
0x004fd6ce:	pushl %ebp
0x004fd6cf:	movl %ebp, %esp
0x004fd6d1:	movl %eax, 0x8(%ebp)
0x004fd6d4:	movl 0x589124, %eax
0x004fd6d9:	popl %ebp
0x004fd6da:	ret

0x004fc259:	pushl %esi
0x004fc25a:	call 0x00508064
0x00508064:	movl %edi, %edi
0x00508066:	pushl %ebp
0x00508067:	movl %ebp, %esp
0x00508069:	movl %eax, 0x8(%ebp)
0x0050806c:	movl 0x5892b0, %eax
0x00508071:	popl %ebp
0x00508072:	ret

0x004fc25f:	pushl %esi
0x004fc260:	call 0x00508bde
0x00508bde:	movl %edi, %edi
0x00508be0:	pushl %ebp
0x00508be1:	movl %ebp, %esp
0x00508be3:	movl %eax, 0x8(%ebp)
0x00508be6:	movl 0x5892c8, %eax
0x00508beb:	popl %ebp
0x00508bec:	ret

0x004fc265:	pushl %esi
0x004fc266:	call 0x005089cc
0x005089cc:	movl %edi, %edi
0x005089ce:	pushl %ebp
0x005089cf:	movl %ebp, %esp
0x005089d1:	movl %eax, 0x8(%ebp)
0x005089d4:	movl 0x5892b4, %eax
0x005089d9:	movl 0x5892b8, %eax
0x005089de:	movl 0x5892bc, %eax
0x005089e3:	movl 0x5892c0, %eax
0x005089e8:	popl %ebp
0x005089e9:	ret

0x004fc26b:	pushl %esi
0x004fc26c:	call 0x004f9330
0x004f9330:	ret

0x004fc271:	pushl %esi
0x004fc272:	call 0x004ff2e8
0x004ff2e8:	pushl $0x4ff264<UINT32>
0x004ff2ed:	call 0x004fcf63
0x004ff2f2:	popl %ecx
0x004ff2f3:	movl 0x589130, %eax
0x004ff2f8:	ret

0x004fc277:	pushl $0x4fc209<UINT32>
0x004fc27c:	call 0x004fcf63
0x004fc281:	addl %esp, $0x24<UINT8>
0x004fc284:	movl 0x57d900, %eax
0x004fc289:	popl %esi
0x004fc28a:	ret

0x004fd445:	pushl 0x588dec
0x004fd44b:	call 0x004fcf63
0x004fd450:	pushl 0x588df0
0x004fd456:	movl 0x588dec, %eax
0x004fd45b:	call 0x004fcf63
0x004fd460:	pushl 0x588df4
0x004fd466:	movl 0x588df0, %eax
0x004fd46b:	call 0x004fcf63
0x004fd470:	pushl 0x588df8
0x004fd476:	movl 0x588df4, %eax
0x004fd47b:	call 0x004fcf63
0x004fd480:	addl %esp, $0x10<UINT8>
0x004fd483:	movl 0x588df8, %eax
0x004fd488:	call 0x00504dc3
0x00504dc3:	movl %edi, %edi
0x00504dc5:	pushl %esi
0x00504dc6:	pushl %edi
0x00504dc7:	xorl %esi, %esi
0x00504dc9:	movl %edi, $0x589148<UINT32>
0x00504dce:	cmpl 0x57dcbc(,%esi,8), $0x1<UINT8>
0x00504dd6:	jne 0x00504df6
0x00504dd8:	leal %eax, 0x57dcb8(,%esi,8)
0x00504ddf:	movl (%eax), %edi
0x00504de1:	pushl $0xfa0<UINT32>
0x00504de6:	pushl (%eax)
0x00504de8:	addl %edi, $0x18<UINT8>
0x00504deb:	call 0x00508bfc
0x00508bfc:	pushl $0x10<UINT8>
0x00508bfe:	pushl $0x560158<UINT32>
0x00508c03:	call 0x004fa434
0x00508c08:	andl -4(%ebp), $0x0<UINT8>
0x00508c0c:	pushl 0xc(%ebp)
0x00508c0f:	pushl 0x8(%ebp)
0x00508c12:	call InitializeCriticalSectionAndSpinCount@KERNEL32.DLL
InitializeCriticalSectionAndSpinCount@KERNEL32.DLL: API Node	
0x00508c18:	movl -28(%ebp), %eax
0x00508c1b:	jmp 0x00508c4c
0x00508c4c:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00508c53:	movl %eax, -28(%ebp)
0x00508c56:	call 0x004fa479
0x004fa479:	movl %ecx, -16(%ebp)
0x004fa47c:	movl %fs:0, %ecx
0x004fa483:	popl %ecx
0x004fa484:	popl %edi
0x004fa485:	popl %edi
0x004fa486:	popl %esi
0x004fa487:	popl %ebx
0x004fa488:	movl %esp, %ebp
0x004fa48a:	popl %ebp
0x004fa48b:	pushl %ecx
0x004fa48c:	ret

0x00508c5b:	ret

0x00504df0:	popl %ecx
0x00504df1:	popl %ecx
0x00504df2:	testl %eax, %eax
0x00504df4:	je 12
0x00504df6:	incl %esi
0x00504df7:	cmpl %esi, $0x24<UINT8>
0x00504dfa:	jl 0x00504dce
0x00504dfc:	xorl %eax, %eax
0x00504dfe:	incl %eax
0x00504dff:	popl %edi
0x00504e00:	popl %esi
0x00504e01:	ret

0x004fd48d:	testl %eax, %eax
0x004fd48f:	je 101
0x004fd491:	pushl $0x4fd244<UINT32>
0x004fd496:	pushl 0x588dec
0x004fd49c:	call 0x004fcfde
0x004fcfde:	movl %edi, %edi
0x004fcfe0:	pushl %ebp
0x004fcfe1:	movl %ebp, %esp
0x004fcfe3:	pushl %esi
0x004fcfe4:	pushl 0x57da1c
0x004fcfea:	movl %esi, 0x51d20c
0x004fcff0:	call TlsGetValue@KERNEL32.DLL
0x004fcff2:	testl %eax, %eax
0x004fcff4:	je 33
0x004fcff6:	movl %eax, 0x57da18
0x004fcffb:	cmpl %eax, $0xffffffff<UINT8>
0x004fcffe:	je 0x004fd017
0x004fd017:	movl %esi, $0x53ba80<UINT32>
0x004fd01c:	pushl %esi
0x004fd01d:	call GetModuleHandleW@KERNEL32.DLL
0x004fd023:	testl %eax, %eax
0x004fd025:	jne 0x004fd032
0x004fd032:	pushl $0x53ba9c<UINT32>
0x004fd037:	pushl %eax
0x004fd038:	call GetProcAddress@KERNEL32.DLL
0x004fd03e:	testl %eax, %eax
0x004fd040:	je 8
0x004fd042:	pushl 0x8(%ebp)
0x004fd045:	call DecodePointer@KERNEL32.DLL
DecodePointer@KERNEL32.DLL: API Node	
0x004fd047:	movl 0x8(%ebp), %eax
0x004fd04a:	movl %eax, 0x8(%ebp)
0x004fd04d:	popl %esi
0x004fd04e:	popl %ebp
0x004fd04f:	ret

0x004fd4a1:	popl %ecx
0x004fd4a2:	call FlsAlloc@KERNEL32.DLL
FlsAlloc@KERNEL32.DLL: API Node	
0x004fd4a4:	movl 0x57da18, %eax
0x004fd4a9:	cmpl %eax, $0xffffffff<UINT8>
0x004fd4ac:	je 72
0x004fd4ae:	pushl $0x214<UINT32>
0x004fd4b3:	pushl $0x1<UINT8>
0x004fd4b5:	call 0x0050090e
0x0050090e:	movl %edi, %edi
0x00500910:	pushl %ebp
0x00500911:	movl %ebp, %esp
0x00500913:	pushl %esi
0x00500914:	pushl %edi
0x00500915:	xorl %esi, %esi
0x00500917:	pushl $0x0<UINT8>
0x00500919:	pushl 0xc(%ebp)
0x0050091c:	pushl 0x8(%ebp)
0x0050091f:	call 0x00505a6d
0x00505a6d:	pushl $0xc<UINT8>
0x00505a6f:	pushl $0x55ff80<UINT32>
0x00505a74:	call 0x004fa434
0x00505a79:	movl %ecx, 0x8(%ebp)
0x00505a7c:	xorl %edi, %edi
0x00505a7e:	cmpl %ecx, %edi
0x00505a80:	jbe 46
0x00505a82:	pushl $0xffffffe0<UINT8>
0x00505a84:	popl %eax
0x00505a85:	xorl %edx, %edx
0x00505a87:	divl %eax, %ecx
0x00505a89:	cmpl %eax, 0xc(%ebp)
0x00505a8c:	sbbl %eax, %eax
0x00505a8e:	incl %eax
0x00505a8f:	jne 0x00505ab0
0x00505ab0:	imull %ecx, 0xc(%ebp)
0x00505ab4:	movl %esi, %ecx
0x00505ab6:	movl 0x8(%ebp), %esi
0x00505ab9:	cmpl %esi, %edi
0x00505abb:	jne 0x00505ac0
0x00505ac0:	xorl %ebx, %ebx
0x00505ac2:	movl -28(%ebp), %ebx
0x00505ac5:	cmpl %esi, $0xffffffe0<UINT8>
0x00505ac8:	ja 105
0x00505aca:	cmpl 0x58b704, $0x3<UINT8>
0x00505ad1:	jne 0x00505b1e
0x00505b1e:	cmpl %ebx, %edi
0x00505b20:	jne 97
0x00505b22:	pushl %esi
0x00505b23:	pushl $0x8<UINT8>
0x00505b25:	pushl 0x588dfc
0x00505b2b:	call HeapAlloc@KERNEL32.DLL
HeapAlloc@KERNEL32.DLL: API Node	
0x00505b31:	movl %ebx, %eax
0x00505b33:	cmpl %ebx, %edi
0x00505b35:	jne 0x00505b83
0x00505b83:	movl %eax, %ebx
0x00505b85:	call 0x004fa479
0x00505b8a:	ret

0x00500924:	movl %edi, %eax
0x00500926:	addl %esp, $0xc<UINT8>
0x00500929:	testl %edi, %edi
0x0050092b:	jne 0x00500954
0x00500954:	movl %eax, %edi
0x00500956:	popl %edi
0x00500957:	popl %esi
0x00500958:	popl %ebp
0x00500959:	ret

0x004fd4ba:	movl %esi, %eax
0x004fd4bc:	popl %ecx
0x004fd4bd:	popl %ecx
0x004fd4be:	testl %esi, %esi
0x004fd4c0:	je 52
0x004fd4c2:	pushl %esi
0x004fd4c3:	pushl 0x57da18
0x004fd4c9:	pushl 0x588df4
0x004fd4cf:	call 0x004fcfde
0x004fd000:	pushl %eax
0x004fd001:	pushl 0x57da1c
0x004fd007:	call TlsGetValue@KERNEL32.DLL
0x004fd009:	call FlsGetValue@KERNEL32.DLL
FlsGetValue@KERNEL32.DLL: API Node	
0x004fd00b:	testl %eax, %eax
0x004fd00d:	je 0x004fd017
0x004fd4d4:	popl %ecx
0x004fd4d5:	call FlsSetValue@KERNEL32.DLL
FlsSetValue@KERNEL32.DLL: API Node	
0x004fd4d7:	testl %eax, %eax
0x004fd4d9:	je 27
0x004fd4db:	pushl $0x0<UINT8>
0x004fd4dd:	pushl %esi
0x004fd4de:	call 0x004fd0ca
0x004fd0ca:	pushl $0xc<UINT8>
0x004fd0cc:	pushl $0x55fe08<UINT32>
0x004fd0d1:	call 0x004fa434
0x004fd0d6:	movl %esi, $0x53ba80<UINT32>
0x004fd0db:	pushl %esi
0x004fd0dc:	call GetModuleHandleW@KERNEL32.DLL
0x004fd0e2:	testl %eax, %eax
0x004fd0e4:	jne 0x004fd0ed
0x004fd0ed:	movl -28(%ebp), %eax
0x004fd0f0:	movl %esi, 0x8(%ebp)
0x004fd0f3:	movl 0x5c(%esi), $0x53b9f8<UINT32>
0x004fd0fa:	xorl %edi, %edi
0x004fd0fc:	incl %edi
0x004fd0fd:	movl 0x14(%esi), %edi
0x004fd100:	testl %eax, %eax
0x004fd102:	je 36
0x004fd104:	pushl $0x53ba70<UINT32>
0x004fd109:	pushl %eax
0x004fd10a:	movl %ebx, 0x51d368
0x004fd110:	call GetProcAddress@KERNEL32.DLL
0x004fd112:	movl 0x1f8(%esi), %eax
0x004fd118:	pushl $0x53ba9c<UINT32>
0x004fd11d:	pushl -28(%ebp)
0x004fd120:	call GetProcAddress@KERNEL32.DLL
0x004fd122:	movl 0x1fc(%esi), %eax
0x004fd128:	movl 0x70(%esi), %edi
0x004fd12b:	movb 0xc8(%esi), $0x43<UINT8>
0x004fd132:	movb 0x14b(%esi), $0x43<UINT8>
0x004fd139:	movl 0x68(%esi), $0x57e1d8<UINT32>
0x004fd140:	pushl $0xd<UINT8>
0x004fd142:	call 0x00504f3f
0x00504f3f:	movl %edi, %edi
0x00504f41:	pushl %ebp
0x00504f42:	movl %ebp, %esp
0x00504f44:	movl %eax, 0x8(%ebp)
0x00504f47:	pushl %esi
0x00504f48:	leal %esi, 0x57dcb8(,%eax,8)
0x00504f4f:	cmpl (%esi), $0x0<UINT8>
0x00504f52:	jne 0x00504f67
0x00504f67:	pushl (%esi)
0x00504f69:	call EnterCriticalSection@KERNEL32.DLL
EnterCriticalSection@KERNEL32.DLL: API Node	
0x00504f6f:	popl %esi
0x00504f70:	popl %ebp
0x00504f71:	ret

0x004fd147:	popl %ecx
0x004fd148:	andl -4(%ebp), $0x0<UINT8>
0x004fd14c:	pushl 0x68(%esi)
0x004fd14f:	call InterlockedIncrement@KERNEL32.DLL
InterlockedIncrement@KERNEL32.DLL: API Node	
0x004fd155:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004fd15c:	call 0x004fd19f
0x004fd19f:	pushl $0xd<UINT8>
0x004fd1a1:	call 0x00504e65
0x00504e65:	movl %edi, %edi
0x00504e67:	pushl %ebp
0x00504e68:	movl %ebp, %esp
0x00504e6a:	movl %eax, 0x8(%ebp)
0x00504e6d:	pushl 0x57dcb8(,%eax,8)
0x00504e74:	call LeaveCriticalSection@KERNEL32.DLL
LeaveCriticalSection@KERNEL32.DLL: API Node	
0x00504e7a:	popl %ebp
0x00504e7b:	ret

0x004fd1a6:	popl %ecx
0x004fd1a7:	ret

0x004fd161:	pushl $0xc<UINT8>
0x004fd163:	call 0x00504f3f
0x004fd168:	popl %ecx
0x004fd169:	movl -4(%ebp), %edi
0x004fd16c:	movl %eax, 0xc(%ebp)
0x004fd16f:	movl 0x6c(%esi), %eax
0x004fd172:	testl %eax, %eax
0x004fd174:	jne 8
0x004fd176:	movl %eax, 0x57e1c8
0x004fd17b:	movl 0x6c(%esi), %eax
0x004fd17e:	pushl 0x6c(%esi)
0x004fd181:	call 0x005090af
0x005090af:	movl %edi, %edi
0x005090b1:	pushl %ebp
0x005090b2:	movl %ebp, %esp
0x005090b4:	pushl %ebx
0x005090b5:	pushl %esi
0x005090b6:	movl %esi, 0x51d1e8
0x005090bc:	pushl %edi
0x005090bd:	movl %edi, 0x8(%ebp)
0x005090c0:	pushl %edi
0x005090c1:	call InterlockedIncrement@KERNEL32.DLL
0x005090c3:	movl %eax, 0xb0(%edi)
0x005090c9:	testl %eax, %eax
0x005090cb:	je 0x005090d0
0x005090d0:	movl %eax, 0xb8(%edi)
0x005090d6:	testl %eax, %eax
0x005090d8:	je 0x005090dd
0x005090dd:	movl %eax, 0xb4(%edi)
0x005090e3:	testl %eax, %eax
0x005090e5:	je 0x005090ea
0x005090ea:	movl %eax, 0xc0(%edi)
0x005090f0:	testl %eax, %eax
0x005090f2:	je 0x005090f7
0x005090f7:	leal %ebx, 0x50(%edi)
0x005090fa:	movl 0x8(%ebp), $0x6<UINT32>
0x00509101:	cmpl -8(%ebx), $0x57e0e8<UINT32>
0x00509108:	je 0x00509113
0x0050910a:	movl %eax, (%ebx)
0x0050910c:	testl %eax, %eax
0x0050910e:	je 0x00509113
0x00509113:	cmpl -4(%ebx), $0x0<UINT8>
0x00509117:	je 0x00509123
0x00509123:	addl %ebx, $0x10<UINT8>
0x00509126:	decl 0x8(%ebp)
0x00509129:	jne 0x00509101
0x0050912b:	movl %eax, 0xd4(%edi)
0x00509131:	addl %eax, $0xb4<UINT32>
0x00509136:	pushl %eax
0x00509137:	call InterlockedIncrement@KERNEL32.DLL
0x00509139:	popl %edi
0x0050913a:	popl %esi
0x0050913b:	popl %ebx
0x0050913c:	popl %ebp
0x0050913d:	ret

0x004fd186:	popl %ecx
0x004fd187:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004fd18e:	call 0x004fd1a8
0x004fd1a8:	pushl $0xc<UINT8>
0x004fd1aa:	call 0x00504e65
0x004fd1af:	popl %ecx
0x004fd1b0:	ret

0x004fd193:	call 0x004fa479
0x004fd198:	ret

0x004fd4e3:	popl %ecx
0x004fd4e4:	popl %ecx
0x004fd4e5:	call GetCurrentThreadId@KERNEL32.DLL
0x004fd4eb:	orl 0x4(%esi), $0xffffffff<UINT8>
0x004fd4ef:	movl (%esi), %eax
0x004fd4f1:	xorl %eax, %eax
0x004fd4f3:	incl %eax
0x004fd4f4:	jmp 0x004fd4fd
0x004fd4fd:	popl %edi
0x004fd4fe:	popl %esi
0x004fd4ff:	ret

0x004f7b7e:	testl %eax, %eax
0x004f7b80:	jne 0x004f7b8a
0x004f7b8a:	call 0x004fcf17
0x004fcf17:	movl %edi, %edi
0x004fcf19:	pushl %esi
0x004fcf1a:	movl %eax, $0x55ab48<UINT32>
0x004fcf1f:	movl %esi, $0x55ab48<UINT32>
0x004fcf24:	pushl %edi
0x004fcf25:	movl %edi, %eax
0x004fcf27:	cmpl %eax, %esi
0x004fcf29:	jae 0x004fcf3a
0x004fcf3a:	popl %edi
0x004fcf3b:	popl %esi
0x004fcf3c:	ret

0x004f7b8f:	movl -4(%ebp), %ebx
0x004f7b92:	call 0x004fccc3
0x004fccc3:	pushl $0x54<UINT8>
0x004fccc5:	pushl $0x55fde8<UINT32>
0x004fccca:	call 0x004fa434
0x004fcccf:	xorl %edi, %edi
0x004fccd1:	movl -4(%ebp), %edi
0x004fccd4:	leal %eax, -100(%ebp)
0x004fccd7:	pushl %eax
0x004fccd8:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x004fccde:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004fcce5:	pushl $0x40<UINT8>
0x004fcce7:	pushl $0x20<UINT8>
0x004fcce9:	popl %esi
0x004fccea:	pushl %esi
0x004fcceb:	call 0x0050090e
0x004fccf0:	popl %ecx
0x004fccf1:	popl %ecx
0x004fccf2:	cmpl %eax, %edi
0x004fccf4:	je 532
0x004fccfa:	movl 0x58b720, %eax
0x004fccff:	movl 0x58b708, %esi
0x004fcd05:	leal %ecx, 0x800(%eax)
0x004fcd0b:	jmp 0x004fcd3d
0x004fcd3d:	cmpl %eax, %ecx
0x004fcd3f:	jb 0x004fcd0d
0x004fcd0d:	movb 0x4(%eax), $0x0<UINT8>
0x004fcd11:	orl (%eax), $0xffffffff<UINT8>
0x004fcd14:	movb 0x5(%eax), $0xa<UINT8>
0x004fcd18:	movl 0x8(%eax), %edi
0x004fcd1b:	movb 0x24(%eax), $0x0<UINT8>
0x004fcd1f:	movb 0x25(%eax), $0xa<UINT8>
0x004fcd23:	movb 0x26(%eax), $0xa<UINT8>
0x004fcd27:	movl 0x38(%eax), %edi
0x004fcd2a:	movb 0x34(%eax), $0x0<UINT8>
0x004fcd2e:	addl %eax, $0x40<UINT8>
0x004fcd31:	movl %ecx, 0x58b720
0x004fcd37:	addl %ecx, $0x800<UINT32>
0x004fcd41:	cmpw -50(%ebp), %di
0x004fcd45:	je 266
0x004fcd4b:	movl %eax, -48(%ebp)
0x004fcd4e:	cmpl %eax, %edi
0x004fcd50:	je 255
0x004fcd56:	movl %edi, (%eax)
0x004fcd58:	leal %ebx, 0x4(%eax)
0x004fcd5b:	leal %eax, (%ebx,%edi)
0x004fcd5e:	movl -28(%ebp), %eax
0x004fcd61:	movl %esi, $0x800<UINT32>
0x004fcd66:	cmpl %edi, %esi
0x004fcd68:	jl 0x004fcd6c
0x004fcd6c:	movl -32(%ebp), $0x1<UINT32>
0x004fcd73:	jmp 0x004fcdd0
0x004fcdd0:	cmpl 0x58b708, %edi
0x004fcdd6:	jl -99
0x004fcdd8:	jmp 0x004fcde0
0x004fcde0:	andl -32(%ebp), $0x0<UINT8>
0x004fcde4:	testl %edi, %edi
0x004fcde6:	jle 0x004fce55
0x004fce55:	xorl %ebx, %ebx
0x004fce57:	movl %esi, %ebx
0x004fce59:	shll %esi, $0x6<UINT8>
0x004fce5c:	addl %esi, 0x58b720
0x004fce62:	movl %eax, (%esi)
0x004fce64:	cmpl %eax, $0xffffffff<UINT8>
0x004fce67:	je 0x004fce74
0x004fce74:	movb 0x4(%esi), $0xffffff81<UINT8>
0x004fce78:	testl %ebx, %ebx
0x004fce7a:	jne 0x004fce81
0x004fce7c:	pushl $0xfffffff6<UINT8>
0x004fce7e:	popl %eax
0x004fce7f:	jmp 0x004fce8b
0x004fce8b:	pushl %eax
0x004fce8c:	call GetStdHandle@KERNEL32.DLL
GetStdHandle@KERNEL32.DLL: API Node	
0x004fce92:	movl %edi, %eax
0x004fce94:	cmpl %edi, $0xffffffff<UINT8>
0x004fce97:	je 67
0x004fce99:	testl %edi, %edi
0x004fce9b:	je 63
0x004fce9d:	pushl %edi
0x004fce9e:	call GetFileType@KERNEL32.DLL
GetFileType@KERNEL32.DLL: API Node	
0x004fcea4:	testl %eax, %eax
0x004fcea6:	je 52
0x004fcea8:	movl (%esi), %edi
0x004fceaa:	andl %eax, $0xff<UINT32>
0x004fceaf:	cmpl %eax, $0x2<UINT8>
0x004fceb2:	jne 6
0x004fceb4:	orb 0x4(%esi), $0x40<UINT8>
0x004fceb8:	jmp 0x004fcec3
0x004fcec3:	pushl $0xfa0<UINT32>
0x004fcec8:	leal %eax, 0xc(%esi)
0x004fcecb:	pushl %eax
0x004fcecc:	call 0x00508bfc
0x004fced1:	popl %ecx
0x004fced2:	popl %ecx
0x004fced3:	testl %eax, %eax
0x004fced5:	je 55
0x004fced7:	incl 0x8(%esi)
0x004fceda:	jmp 0x004fcee6
0x004fcee6:	incl %ebx
0x004fcee7:	cmpl %ebx, $0x3<UINT8>
0x004fceea:	jl 0x004fce57
0x004fce81:	movl %eax, %ebx
0x004fce83:	decl %eax
0x004fce84:	negl %eax
0x004fce86:	sbbl %eax, %eax
0x004fce88:	addl %eax, $0xfffffff5<UINT8>
0x004fcef0:	pushl 0x58b708
0x004fcef6:	call SetHandleCount@KERNEL32.DLL
SetHandleCount@KERNEL32.DLL: API Node	
0x004fcefc:	xorl %eax, %eax
0x004fcefe:	jmp 0x004fcf11
0x004fcf11:	call 0x004fa479
0x004fcf16:	ret

0x004f7b97:	testl %eax, %eax
0x004f7b99:	jnl 0x004f7ba3
0x004f7ba3:	call 0x004fccbd
0x004fccbd:	jmp GetCommandLineW@KERNEL32.DLL
GetCommandLineW@KERNEL32.DLL: API Node	
0x004f7ba8:	movl 0x58b834, %eax
0x004f7bad:	call 0x004fcc66
0x004fcc66:	movl %edi, %edi
0x004fcc68:	pushl %esi
0x004fcc69:	call GetEnvironmentStringsW@KERNEL32.DLL
GetEnvironmentStringsW@KERNEL32.DLL: API Node	
0x004fcc6f:	movl %esi, %eax
0x004fcc71:	xorl %ecx, %ecx
0x004fcc73:	cmpl %esi, %ecx
0x004fcc75:	jne 0x004fcc7b
0x004fcc7b:	cmpw (%esi), %cx
0x004fcc7e:	je 14
0x004fcc80:	incl %eax
0x004fcc81:	incl %eax
0x004fcc82:	cmpw (%eax), %cx
0x004fcc85:	jne 0x004fcc80
0x004fcc87:	incl %eax
0x004fcc88:	incl %eax
0x004fcc89:	cmpw (%eax), %cx
0x004fcc8c:	jne 0x004fcc80
0x004fcc8e:	subl %eax, %esi
0x004fcc90:	incl %eax
0x004fcc91:	pushl %ebx
0x004fcc92:	incl %eax
0x004fcc93:	movl %ebx, %eax
0x004fcc95:	pushl %edi
0x004fcc96:	pushl %ebx
0x004fcc97:	call 0x005008c9
0x005008c9:	movl %edi, %edi
0x005008cb:	pushl %ebp
0x005008cc:	movl %ebp, %esp
0x005008ce:	pushl %esi
0x005008cf:	pushl %edi
0x005008d0:	xorl %esi, %esi
0x005008d2:	pushl 0x8(%ebp)
0x005008d5:	call 0x004f8dd9
0x004f8dd9:	movl %edi, %edi
0x004f8ddb:	pushl %ebp
0x004f8ddc:	movl %ebp, %esp
0x004f8dde:	pushl %esi
0x004f8ddf:	movl %esi, 0x8(%ebp)
0x004f8de2:	cmpl %esi, $0xffffffe0<UINT8>
0x004f8de5:	ja 161
0x004f8deb:	pushl %ebx
0x004f8dec:	pushl %edi
0x004f8ded:	movl %edi, 0x51d158
0x004f8df3:	cmpl 0x588dfc, $0x0<UINT8>
0x004f8dfa:	jne 0x004f8e14
0x004f8e14:	movl %eax, 0x58b704
0x004f8e19:	cmpl %eax, $0x1<UINT8>
0x004f8e1c:	jne 14
0x004f8e1e:	testl %esi, %esi
0x004f8e20:	je 4
0x004f8e22:	movl %eax, %esi
0x004f8e24:	jmp 0x004f8e29
0x004f8e29:	pushl %eax
0x004f8e2a:	jmp 0x004f8e48
0x004f8e48:	pushl $0x0<UINT8>
0x004f8e4a:	pushl 0x588dfc
0x004f8e50:	call HeapAlloc@KERNEL32.DLL
0x004f8e52:	movl %ebx, %eax
0x004f8e54:	testl %ebx, %ebx
0x004f8e56:	jne 0x004f8e86
0x004f8e86:	popl %edi
0x004f8e87:	movl %eax, %ebx
0x004f8e89:	popl %ebx
0x004f8e8a:	jmp 0x004f8ea0
0x004f8ea0:	popl %esi
0x004f8ea1:	popl %ebp
0x004f8ea2:	ret

0x005008da:	movl %edi, %eax
0x005008dc:	popl %ecx
0x005008dd:	testl %edi, %edi
0x005008df:	jne 0x00500908
0x00500908:	movl %eax, %edi
0x0050090a:	popl %edi
0x0050090b:	popl %esi
0x0050090c:	popl %ebp
0x0050090d:	ret

0x004fcc9c:	movl %edi, %eax
0x004fcc9e:	popl %ecx
0x004fcc9f:	testl %edi, %edi
0x004fcca1:	jne 0x004fccb0
0x004fccb0:	pushl %ebx
0x004fccb1:	pushl %esi
0x004fccb2:	pushl %edi
0x004fccb3:	call 0x004f9d50
0x004f9d50:	pushl %ebp
0x004f9d51:	movl %ebp, %esp
0x004f9d53:	pushl %edi
0x004f9d54:	pushl %esi
0x004f9d55:	movl %esi, 0xc(%ebp)
0x004f9d58:	movl %ecx, 0x10(%ebp)
0x004f9d5b:	movl %edi, 0x8(%ebp)
0x004f9d5e:	movl %eax, %ecx
0x004f9d60:	movl %edx, %ecx
0x004f9d62:	addl %eax, %esi
0x004f9d64:	cmpl %edi, %esi
0x004f9d66:	jbe 8
0x004f9d68:	cmpl %edi, %eax
0x004f9d6a:	jb 420
0x004f9d70:	cmpl %ecx, $0x100<UINT32>
0x004f9d76:	jb 0x004f9d97
0x004f9d78:	cmpl 0x58a6d0, $0x0<UINT8>
0x004f9d7f:	je 0x004f9d97
0x004f9d97:	testl %edi, $0x3<UINT32>
0x004f9d9d:	jne 21
0x004f9d9f:	shrl %ecx, $0x2<UINT8>
0x004f9da2:	andl %edx, $0x3<UINT8>
0x004f9da5:	cmpl %ecx, $0x8<UINT8>
0x004f9da8:	jb 0x004f9dd4
0x004f9daa:	rep movsl %es:(%edi), %ds:(%esi)
0x004f9dac:	jmp 0x004f9ee8
0x004f9ee8:	movb %al, (%esi)
0x004f9eea:	movb (%edi), %al
0x004f9eec:	movb %al, 0x1(%esi)
0x004f9eef:	movb 0x1(%edi), %al
0x004f9ef2:	movl %eax, 0x8(%ebp)
0x004f9ef5:	popl %esi
0x004f9ef6:	popl %edi
0x004f9ef7:	leave
0x004f9ef8:	ret

0x004fccb8:	addl %esp, $0xc<UINT8>
0x004fccbb:	jmp 0x004fcca3
0x004fcca3:	pushl %esi
0x004fcca4:	call FreeEnvironmentStringsW@KERNEL32.DLL
FreeEnvironmentStringsW@KERNEL32.DLL: API Node	
0x004fccaa:	movl %eax, %edi
0x004fccac:	popl %edi
0x004fccad:	popl %ebx
0x004fccae:	popl %esi
0x004fccaf:	ret

0x004f7bb2:	movl 0x58887c, %eax
0x004f7bb7:	call 0x004fcbb8
0x004fcbb8:	movl %edi, %edi
0x004fcbba:	pushl %ebp
0x004fcbbb:	movl %ebp, %esp
0x004fcbbd:	pushl %ecx
0x004fcbbe:	pushl %ecx
0x004fcbbf:	pushl %ebx
0x004fcbc0:	pushl %esi
0x004fcbc1:	pushl %edi
0x004fcbc2:	pushl $0x104<UINT32>
0x004fcbc7:	movl %esi, $0x588be0<UINT32>
0x004fcbcc:	pushl %esi
0x004fcbcd:	xorl %eax, %eax
0x004fcbcf:	xorl %ebx, %ebx
0x004fcbd1:	pushl %ebx
0x004fcbd2:	movw 0x588de8, %ax
0x004fcbd8:	call GetModuleFileNameW@KERNEL32.DLL
GetModuleFileNameW@KERNEL32.DLL: API Node	
0x004fcbde:	movl %eax, 0x58b834
0x004fcbe3:	movl 0x5888b0, %esi
0x004fcbe9:	cmpl %eax, %ebx
0x004fcbeb:	je 7
0x004fcbed:	movl %edi, %eax
0x004fcbef:	cmpw (%eax), %bx
0x004fcbf2:	jne 0x004fcbf6
0x004fcbf6:	leal %eax, -4(%ebp)
0x004fcbf9:	pushl %eax
0x004fcbfa:	pushl %ebx
0x004fcbfb:	leal %ebx, -8(%ebp)
0x004fcbfe:	xorl %ecx, %ecx
0x004fcc00:	movl %eax, %edi
0x004fcc02:	call 0x004fca67
0x004fca67:	movl %edi, %edi
0x004fca69:	pushl %ebp
0x004fca6a:	movl %ebp, %esp
0x004fca6c:	pushl %ecx
0x004fca6d:	pushl %esi
0x004fca6e:	xorl %edx, %edx
0x004fca70:	pushl %edi
0x004fca71:	movl %edi, 0xc(%ebp)
0x004fca74:	movl (%ebx), %edx
0x004fca76:	movl %esi, %ecx
0x004fca78:	movl (%edi), $0x1<UINT32>
0x004fca7e:	cmpl 0x8(%ebp), %edx
0x004fca81:	je 0x004fca8c
0x004fca8c:	cmpw (%eax), $0x22<UINT8>
0x004fca90:	jne 0x004fcaa5
0x004fca92:	movl %edi, 0xc(%ebp)
0x004fca95:	xorl %ecx, %ecx
0x004fca97:	testl %edx, %edx
0x004fca99:	sete %cl
0x004fca9c:	pushl $0x22<UINT8>
0x004fca9e:	incl %eax
0x004fca9f:	incl %eax
0x004fcaa0:	movl %edx, %ecx
0x004fcaa2:	popl %ecx
0x004fcaa3:	jmp 0x004fcabd
0x004fcabd:	testl %edx, %edx
0x004fcabf:	jne 0x004fca8c
0x004fcaa5:	incl (%ebx)
0x004fcaa7:	testl %esi, %esi
0x004fcaa9:	je 0x004fcab3
0x004fcab3:	movzwl %ecx, (%eax)
0x004fcab6:	incl %eax
0x004fcab7:	incl %eax
0x004fcab8:	testw %cx, %cx
0x004fcabb:	je 0x004fcaf9
0x004fcac1:	cmpw %cx, $0x20<UINT8>
0x004fcac5:	je 6
0x004fcac7:	cmpw %cx, $0x9<UINT8>
0x004fcacb:	jne 0x004fca8c
0x004fcaf9:	decl %eax
0x004fcafa:	decl %eax
0x004fcafb:	jmp 0x004fcad7
0x004fcad7:	andl -4(%ebp), $0x0<UINT8>
0x004fcadb:	xorl %edx, %edx
0x004fcadd:	cmpw (%eax), %dx
0x004fcae0:	je 0x004fcba9
0x004fcba9:	movl %eax, 0x8(%ebp)
0x004fcbac:	cmpl %eax, %edx
0x004fcbae:	je 0x004fcbb2
0x004fcbb2:	incl (%edi)
0x004fcbb4:	popl %edi
0x004fcbb5:	popl %esi
0x004fcbb6:	leave
0x004fcbb7:	ret

0x004fcc07:	movl %ebx, -4(%ebp)
0x004fcc0a:	popl %ecx
0x004fcc0b:	popl %ecx
0x004fcc0c:	cmpl %ebx, $0x3fffffff<UINT32>
0x004fcc12:	jae 74
0x004fcc14:	movl %ecx, -8(%ebp)
0x004fcc17:	cmpl %ecx, $0x7fffffff<UINT32>
0x004fcc1d:	jae 63
0x004fcc1f:	leal %eax, (%ecx,%ebx,2)
0x004fcc22:	addl %eax, %eax
0x004fcc24:	addl %ecx, %ecx
0x004fcc26:	cmpl %eax, %ecx
0x004fcc28:	jb 52
0x004fcc2a:	pushl %eax
0x004fcc2b:	call 0x005008c9
0x004fcc30:	movl %esi, %eax
0x004fcc32:	popl %ecx
0x004fcc33:	testl %esi, %esi
0x004fcc35:	je 39
0x004fcc37:	leal %eax, -4(%ebp)
0x004fcc3a:	pushl %eax
0x004fcc3b:	leal %ecx, (%esi,%ebx,4)
0x004fcc3e:	pushl %esi
0x004fcc3f:	leal %ebx, -8(%ebp)
0x004fcc42:	movl %eax, %edi
0x004fcc44:	call 0x004fca67
0x004fca83:	movl %ecx, 0x8(%ebp)
0x004fca86:	addl 0x8(%ebp), $0x4<UINT8>
0x004fca8a:	movl (%ecx), %esi
0x004fcaab:	movw %cx, (%eax)
0x004fcaae:	movw (%esi), %cx
0x004fcab1:	incl %esi
0x004fcab2:	incl %esi
0x004fcbb0:	movl (%eax), %edx
0x004fcc49:	movl %eax, -4(%ebp)
0x004fcc4c:	decl %eax
0x004fcc4d:	popl %ecx
0x004fcc4e:	movl 0x588890, %eax
0x004fcc53:	popl %ecx
0x004fcc54:	movl 0x588898, %esi
0x004fcc5a:	xorl %eax, %eax
0x004fcc5c:	jmp 0x004fcc61
0x004fcc61:	popl %edi
0x004fcc62:	popl %esi
0x004fcc63:	popl %ebx
0x004fcc64:	leave
0x004fcc65:	ret

0x004f7bbc:	testl %eax, %eax
0x004f7bbe:	jnl 0x004f7bc8
0x004f7bc8:	call 0x004fc989
0x004fc989:	movl %edi, %edi
0x004fc98b:	pushl %esi
0x004fc98c:	movl %esi, 0x58887c
0x004fc992:	pushl %edi
0x004fc993:	xorl %edi, %edi
0x004fc995:	testl %esi, %esi
0x004fc997:	jne 0x004fc9b3
0x004fc9b3:	movzwl %eax, (%esi)
0x004fc9b6:	testw %ax, %ax
0x004fc9b9:	jne 0x004fc9a1
0x004fc9a1:	cmpw %ax, $0x3d<UINT8>
0x004fc9a5:	je 0x004fc9a8
0x004fc9a8:	pushl %esi
0x004fc9a9:	call 0x004fa4c4
0x004fa4c4:	movl %edi, %edi
0x004fa4c6:	pushl %ebp
0x004fa4c7:	movl %ebp, %esp
0x004fa4c9:	movl %eax, 0x8(%ebp)
0x004fa4cc:	movw %cx, (%eax)
0x004fa4cf:	incl %eax
0x004fa4d0:	incl %eax
0x004fa4d1:	testw %cx, %cx
0x004fa4d4:	jne 0x004fa4cc
0x004fa4d6:	subl %eax, 0x8(%ebp)
0x004fa4d9:	sarl %eax
0x004fa4db:	decl %eax
0x004fa4dc:	popl %ebp
0x004fa4dd:	ret

0x004fc9ae:	popl %ecx
0x004fc9af:	leal %esi, 0x2(%esi,%eax,2)
0x004fc9a7:	incl %edi
0x004fc9bb:	pushl %ebx
0x004fc9bc:	pushl $0x4<UINT8>
0x004fc9be:	incl %edi
0x004fc9bf:	pushl %edi
0x004fc9c0:	call 0x0050090e
0x004fc9c5:	movl %ebx, %eax
0x004fc9c7:	popl %ecx
0x004fc9c8:	popl %ecx
0x004fc9c9:	movl 0x5888a4, %ebx
0x004fc9cf:	testl %ebx, %ebx
0x004fc9d1:	jne 0x004fc9d8
0x004fc9d8:	movl %esi, 0x58887c
0x004fc9de:	jmp 0x004fca24
0x004fca24:	cmpw (%esi), $0x0<UINT8>
0x004fca28:	jne 0x004fc9e0
0x004fc9e0:	pushl %esi
0x004fc9e1:	call 0x004fa4c4
0x004fc9e6:	movl %edi, %eax
0x004fc9e8:	incl %edi
0x004fc9e9:	cmpw (%esi), $0x3d<UINT8>
0x004fc9ed:	popl %ecx
0x004fc9ee:	je 0x004fca21
0x004fca21:	leal %esi, (%esi,%edi,2)
0x004fc9f0:	pushl $0x2<UINT8>
0x004fc9f2:	pushl %edi
0x004fc9f3:	call 0x0050090e
0x004fc9f8:	popl %ecx
0x004fc9f9:	popl %ecx
0x004fc9fa:	movl (%ebx), %eax
0x004fc9fc:	testl %eax, %eax
0x004fc9fe:	je 80
0x004fca00:	pushl %esi
0x004fca01:	pushl %edi
0x004fca02:	pushl %eax
0x004fca03:	call 0x004f8f71
0x004f8f71:	movl %edi, %edi
0x004f8f73:	pushl %ebp
0x004f8f74:	movl %ebp, %esp
0x004f8f76:	movl %edx, 0x8(%ebp)
0x004f8f79:	pushl %ebx
0x004f8f7a:	pushl %esi
0x004f8f7b:	pushl %edi
0x004f8f7c:	xorl %edi, %edi
0x004f8f7e:	cmpl %edx, %edi
0x004f8f80:	je 7
0x004f8f82:	movl %ebx, 0xc(%ebp)
0x004f8f85:	cmpl %ebx, %edi
0x004f8f87:	ja 0x004f8fa7
0x004f8fa7:	movl %esi, 0x10(%ebp)
0x004f8faa:	cmpl %esi, %edi
0x004f8fac:	jne 0x004f8fb5
0x004f8fb5:	movl %ecx, %edx
0x004f8fb7:	movzwl %eax, (%esi)
0x004f8fba:	movw (%ecx), %ax
0x004f8fbd:	incl %ecx
0x004f8fbe:	incl %ecx
0x004f8fbf:	incl %esi
0x004f8fc0:	incl %esi
0x004f8fc1:	cmpw %ax, %di
0x004f8fc4:	je 0x004f8fc9
0x004f8fc6:	decl %ebx
0x004f8fc7:	jne 0x004f8fb7
0x004f8fc9:	xorl %eax, %eax
0x004f8fcb:	cmpl %ebx, %edi
0x004f8fcd:	jne 0x004f8fa2
0x004f8fa2:	popl %edi
0x004f8fa3:	popl %esi
0x004f8fa4:	popl %ebx
0x004f8fa5:	popl %ebp
0x004f8fa6:	ret

0x004fca08:	addl %esp, $0xc<UINT8>
0x004fca0b:	testl %eax, %eax
0x004fca0d:	je 0x004fca1e
0x004fca1e:	addl %ebx, $0x4<UINT8>
0x004fca2a:	pushl 0x58887c
0x004fca30:	call 0x004f8ee3
0x004f8ee3:	pushl $0xc<UINT8>
0x004f8ee5:	pushl $0x55fd28<UINT32>
0x004f8eea:	call 0x004fa434
0x004f8eef:	movl %esi, 0x8(%ebp)
0x004f8ef2:	testl %esi, %esi
0x004f8ef4:	je 117
0x004f8ef6:	cmpl 0x58b704, $0x3<UINT8>
0x004f8efd:	jne 0x004f8f42
0x004f8f42:	pushl %esi
0x004f8f43:	pushl $0x0<UINT8>
0x004f8f45:	pushl 0x588dfc
0x004f8f4b:	call HeapFree@KERNEL32.DLL
HeapFree@KERNEL32.DLL: API Node	
0x004f8f51:	testl %eax, %eax
0x004f8f53:	jne 0x004f8f6b
0x004f8f6b:	call 0x004fa479
0x004f8f70:	ret

0x004fca35:	andl 0x58887c, $0x0<UINT8>
0x004fca3c:	andl (%ebx), $0x0<UINT8>
0x004fca3f:	movl 0x58b820, $0x1<UINT32>
0x004fca49:	xorl %eax, %eax
0x004fca4b:	popl %ecx
0x004fca4c:	popl %ebx
0x004fca4d:	popl %edi
0x004fca4e:	popl %esi
0x004fca4f:	ret

0x004f7bcd:	testl %eax, %eax
0x004f7bcf:	jnl 0x004f7bd9
0x004f7bd9:	pushl %ebx
0x004f7bda:	call 0x004fc042
0x004fc042:	movl %edi, %edi
0x004fc044:	pushl %ebp
0x004fc045:	movl %ebp, %esp
0x004fc047:	cmpl 0x53b3e8, $0x0<UINT8>
0x004fc04e:	je 25
0x004fc050:	pushl $0x53b3e8<UINT32>
0x004fc055:	call 0x00506b50
0x00506b50:	movl %edi, %edi
0x00506b52:	pushl %ebp
0x00506b53:	movl %ebp, %esp
0x00506b55:	pushl $0xfffffffe<UINT8>
0x00506b57:	pushl $0x55ffa0<UINT32>
0x00506b5c:	pushl $0x4f93c0<UINT32>
0x00506b61:	movl %eax, %fs:0
0x00506b67:	pushl %eax
0x00506b68:	subl %esp, $0x8<UINT8>
0x00506b6b:	pushl %ebx
0x00506b6c:	pushl %esi
0x00506b6d:	pushl %edi
0x00506b6e:	movl %eax, 0x57d770
0x00506b73:	xorl -8(%ebp), %eax
0x00506b76:	xorl %eax, %ebp
0x00506b78:	pushl %eax
0x00506b79:	leal %eax, -16(%ebp)
0x00506b7c:	movl %fs:0, %eax
0x00506b82:	movl -24(%ebp), %esp
0x00506b85:	movl -4(%ebp), $0x0<UINT32>
0x00506b8c:	pushl $0x400000<UINT32>
0x00506b91:	call 0x00506ac0
0x00506ac0:	movl %edi, %edi
0x00506ac2:	pushl %ebp
0x00506ac3:	movl %ebp, %esp
0x00506ac5:	movl %ecx, 0x8(%ebp)
0x00506ac8:	movl %eax, $0x5a4d<UINT32>
0x00506acd:	cmpw (%ecx), %ax
0x00506ad0:	je 0x00506ad6
0x00506ad6:	movl %eax, 0x3c(%ecx)
0x00506ad9:	addl %eax, %ecx
0x00506adb:	cmpl (%eax), $0x4550<UINT32>
0x00506ae1:	jne -17
0x00506ae3:	xorl %edx, %edx
0x00506ae5:	movl %ecx, $0x10b<UINT32>
0x00506aea:	cmpw 0x18(%eax), %cx
0x00506aee:	sete %dl
0x00506af1:	movl %eax, %edx
0x00506af3:	popl %ebp
0x00506af4:	ret

0x00506b96:	addl %esp, $0x4<UINT8>
0x00506b99:	testl %eax, %eax
0x00506b9b:	je 85
0x00506b9d:	movl %eax, 0x8(%ebp)
0x00506ba0:	subl %eax, $0x400000<UINT32>
0x00506ba5:	pushl %eax
0x00506ba6:	pushl $0x400000<UINT32>
0x00506bab:	call 0x00506b00
0x00506b00:	movl %edi, %edi
0x00506b02:	pushl %ebp
0x00506b03:	movl %ebp, %esp
0x00506b05:	movl %eax, 0x8(%ebp)
0x00506b08:	movl %ecx, 0x3c(%eax)
0x00506b0b:	addl %ecx, %eax
0x00506b0d:	movzwl %eax, 0x14(%ecx)
0x00506b11:	pushl %ebx
0x00506b12:	pushl %esi
0x00506b13:	movzwl %esi, 0x6(%ecx)
0x00506b17:	xorl %edx, %edx
0x00506b19:	pushl %edi
0x00506b1a:	leal %eax, 0x18(%eax,%ecx)
0x00506b1e:	testl %esi, %esi
0x00506b20:	jbe 27
0x00506b22:	movl %edi, 0xc(%ebp)
0x00506b25:	movl %ecx, 0xc(%eax)
0x00506b28:	cmpl %edi, %ecx
0x00506b2a:	jb 9
0x00506b2c:	movl %ebx, 0x8(%eax)
0x00506b2f:	addl %ebx, %ecx
0x00506b31:	cmpl %edi, %ebx
0x00506b33:	jb 0x00506b3f
0x00506b3f:	popl %edi
0x00506b40:	popl %esi
0x00506b41:	popl %ebx
0x00506b42:	popl %ebp
0x00506b43:	ret

0x00506bb0:	addl %esp, $0x8<UINT8>
0x00506bb3:	testl %eax, %eax
0x00506bb5:	je 59
0x00506bb7:	movl %eax, 0x24(%eax)
0x00506bba:	shrl %eax, $0x1f<UINT8>
0x00506bbd:	notl %eax
0x00506bbf:	andl %eax, $0x1<UINT8>
0x00506bc2:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00506bc9:	movl %ecx, -16(%ebp)
0x00506bcc:	movl %fs:0, %ecx
0x00506bd3:	popl %ecx
0x00506bd4:	popl %edi
0x00506bd5:	popl %esi
0x00506bd6:	popl %ebx
0x00506bd7:	movl %esp, %ebp
0x00506bd9:	popl %ebp
0x00506bda:	ret

0x004fc05a:	popl %ecx
0x004fc05b:	testl %eax, %eax
0x004fc05d:	je 10
0x004fc05f:	pushl 0x8(%ebp)
0x004fc062:	call 0x004f9391
0x004f9391:	movl %edi, %edi
0x004f9393:	pushl %ebp
0x004f9394:	movl %ebp, %esp
0x004f9396:	call 0x004f9331
0x004f9331:	movl %eax, $0x5069dc<UINT32>
0x004f9336:	movl 0x57dddc, %eax
0x004f933b:	movl 0x57dde0, $0x5060c3<UINT32>
0x004f9345:	movl 0x57dde4, $0x506077<UINT32>
0x004f934f:	movl 0x57dde8, $0x5060b0<UINT32>
0x004f9359:	movl 0x57ddec, $0x506019<UINT32>
0x004f9363:	movl 0x57ddf0, %eax
0x004f9368:	movl 0x57ddf4, $0x506954<UINT32>
0x004f9372:	movl 0x57ddf8, $0x506035<UINT32>
0x004f937c:	movl 0x57ddfc, $0x505f97<UINT32>
0x004f9386:	movl 0x57de00, $0x505f24<UINT32>
0x004f9390:	ret

0x004f939b:	call 0x00506a89
0x00506a89:	pushl $0x53bd04<UINT32>
0x00506a8e:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x00506a94:	testl %eax, %eax
0x00506a96:	je 21
0x00506a98:	pushl $0x53bce8<UINT32>
0x00506a9d:	pushl %eax
0x00506a9e:	call GetProcAddress@KERNEL32.DLL
0x00506aa4:	testl %eax, %eax
0x00506aa6:	je 5
0x00506aa8:	pushl $0x0<UINT8>
0x00506aaa:	call IsProcessorFeaturePresent@KERNEL32
IsProcessorFeaturePresent@KERNEL32: API Node	
0x00506aac:	ret

0x004f93a0:	cmpl 0x8(%ebp), $0x0<UINT8>
0x004f93a4:	movl 0x588888, %eax
0x004f93a9:	je 5
0x004f93ab:	call 0x00506a20
0x00506a20:	movl %edi, %edi
0x00506a22:	pushl %esi
0x00506a23:	pushl $0x30000<UINT32>
0x00506a28:	pushl $0x10000<UINT32>
0x00506a2d:	xorl %esi, %esi
0x00506a2f:	pushl %esi
0x00506a30:	call 0x0050d208
0x0050d208:	movl %edi, %edi
0x0050d20a:	pushl %ebp
0x0050d20b:	movl %ebp, %esp
0x0050d20d:	movl %eax, 0x10(%ebp)
0x0050d210:	movl %ecx, 0xc(%ebp)
0x0050d213:	andl %eax, $0xfff7ffff<UINT32>
0x0050d218:	andl %ecx, %eax
0x0050d21a:	pushl %esi
0x0050d21b:	testl %ecx, $0xfcf0fce0<UINT32>
0x0050d221:	je 0x0050d254
0x0050d254:	movl %esi, 0x8(%ebp)
0x0050d257:	pushl %eax
0x0050d258:	pushl 0xc(%ebp)
0x0050d25b:	testl %esi, %esi
0x0050d25d:	je 0x0050d268
0x0050d268:	call 0x00510849
0x00510849:	movl %edi, %edi
0x0051084b:	pushl %ebp
0x0051084c:	movl %ebp, %esp
0x0051084e:	subl %esp, $0x14<UINT8>
0x00510851:	pushl %ebx
0x00510852:	pushl %esi
0x00510853:	pushl %edi
0x00510854:	fwait
0x00510855:	fnstcw -8(%ebp)
0x00510858:	movl %ebx, -8(%ebp)
0x0051085b:	xorl %edx, %edx
0x0051085d:	testb %bl, $0x1<UINT8>
0x00510860:	je 0x00510865
0x00510865:	testb %bl, $0x4<UINT8>
0x00510868:	je 3
0x0051086a:	orl %edx, $0x8<UINT8>
0x0051086d:	testb %bl, $0x8<UINT8>
0x00510870:	je 3
0x00510872:	orl %edx, $0x4<UINT8>
0x00510875:	testb %bl, $0x10<UINT8>
0x00510878:	je 0x0051087d
0x0051087d:	testb %bl, $0x20<UINT8>
0x00510880:	je 3
0x00510882:	orl %edx, $0x1<UINT8>
0x00510885:	testb %bl, $0x2<UINT8>
0x00510888:	je 0x00510890
0x00510890:	movzwl %ecx, %bx
0x00510893:	movl %eax, %ecx
0x00510895:	movl %esi, $0xc00<UINT32>
0x0051089a:	andl %eax, %esi
0x0051089c:	movl %edi, $0x300<UINT32>
0x005108a1:	je 36
0x005108a3:	cmpl %eax, $0x400<UINT32>
0x005108a8:	je 23
0x005108aa:	cmpl %eax, $0x800<UINT32>
0x005108af:	je 8
0x005108b1:	cmpl %eax, %esi
0x005108b3:	jne 18
0x005108b5:	orl %edx, %edi
0x005108b7:	jmp 0x005108c7
0x005108c7:	andl %ecx, %edi
0x005108c9:	je 16
0x005108cb:	cmpl %ecx, $0x200<UINT32>
0x005108d1:	jne 14
0x005108d3:	orl %edx, $0x10000<UINT32>
0x005108d9:	jmp 0x005108e1
0x005108e1:	testl %ebx, $0x1000<UINT32>
0x005108e7:	je 6
0x005108e9:	orl %edx, $0x40000<UINT32>
0x005108ef:	movl %edi, 0xc(%ebp)
0x005108f2:	movl %ecx, 0x8(%ebp)
0x005108f5:	movl %eax, %edi
0x005108f7:	notl %eax
0x005108f9:	andl %eax, %edx
0x005108fb:	andl %ecx, %edi
0x005108fd:	orl %eax, %ecx
0x005108ff:	movl 0xc(%ebp), %eax
0x00510902:	cmpl %eax, %edx
0x00510904:	je 0x005109b8
0x005109b8:	xorl %esi, %esi
0x005109ba:	cmpl 0x58a6d0, %esi
0x005109c0:	je 0x00510b53
0x00510b53:	popl %edi
0x00510b54:	popl %esi
0x00510b55:	popl %ebx
0x00510b56:	leave
0x00510b57:	ret

0x0050d26d:	popl %ecx
0x0050d26e:	popl %ecx
0x0050d26f:	xorl %eax, %eax
0x0050d271:	popl %esi
0x0050d272:	popl %ebp
0x0050d273:	ret

0x00506a35:	addl %esp, $0xc<UINT8>
0x00506a38:	testl %eax, %eax
0x00506a3a:	je 0x00506a49
0x00506a49:	popl %esi
0x00506a4a:	ret

0x004f93b0:	fnclex
0x004f93b2:	popl %ebp
0x004f93b3:	ret

0x004fc068:	popl %ecx
0x004fc069:	call 0x005069ff
0x005069ff:	movl %edi, %edi
0x00506a01:	pushl %esi
0x00506a02:	pushl %edi
0x00506a03:	xorl %edi, %edi
0x00506a05:	leal %esi, 0x57dddc(%edi)
0x00506a0b:	pushl (%esi)
0x00506a0d:	call 0x004fcf63
0x004fcf85:	pushl %eax
0x004fcf86:	pushl 0x57da1c
0x004fcf8c:	call TlsGetValue@KERNEL32.DLL
0x004fcf8e:	call FlsGetValue@KERNEL32.DLL
0x004fcf90:	testl %eax, %eax
0x004fcf92:	je 8
0x004fcf94:	movl %eax, 0x1f8(%eax)
0x004fcf9a:	jmp 0x004fcfc3
0x00506a12:	addl %edi, $0x4<UINT8>
0x00506a15:	popl %ecx
0x00506a16:	movl (%esi), %eax
0x00506a18:	cmpl %edi, $0x28<UINT8>
0x00506a1b:	jb 0x00506a05
0x00506a1d:	popl %edi
0x00506a1e:	popl %esi
0x00506a1f:	ret

0x004fc06e:	pushl $0x51d798<UINT32>
0x004fc073:	pushl $0x51d77c<UINT32>
0x004fc078:	call 0x004fc01e
0x004fc01e:	movl %edi, %edi
0x004fc020:	pushl %ebp
0x004fc021:	movl %ebp, %esp
0x004fc023:	pushl %esi
0x004fc024:	movl %esi, 0x8(%ebp)
0x004fc027:	xorl %eax, %eax
0x004fc029:	jmp 0x004fc03a
0x004fc03a:	cmpl %esi, 0xc(%ebp)
0x004fc03d:	jb 0x004fc02b
0x004fc02b:	testl %eax, %eax
0x004fc02d:	jne 16
0x004fc02f:	movl %ecx, (%esi)
0x004fc031:	testl %ecx, %ecx
0x004fc033:	je 0x004fc037
0x004fc037:	addl %esi, $0x4<UINT8>
0x004fc035:	call 0x004fc5f1
0x004f87b1:	movl %edi, %edi
0x004f87b3:	pushl %esi
0x004f87b4:	pushl $0x4<UINT8>
0x004f87b6:	pushl $0x20<UINT8>
0x004f87b8:	call 0x0050090e
0x004f87bd:	movl %esi, %eax
0x004f87bf:	pushl %esi
0x004f87c0:	call 0x004fcf63
0x004f87c5:	addl %esp, $0xc<UINT8>
0x004f87c8:	movl 0x58b828, %eax
0x004f87cd:	movl 0x58b824, %eax
0x004f87d2:	testl %esi, %esi
0x004f87d4:	jne 0x004f87db
0x004f87db:	andl (%esi), $0x0<UINT8>
0x004f87de:	xorl %eax, %eax
0x004f87e0:	popl %esi
0x004f87e1:	ret

0x004ff66b:	movl %eax, 0x58b700
0x004ff670:	pushl %esi
0x004ff671:	pushl $0x14<UINT8>
0x004ff673:	popl %esi
0x004ff674:	testl %eax, %eax
0x004ff676:	jne 7
0x004ff678:	movl %eax, $0x200<UINT32>
0x004ff67d:	jmp 0x004ff685
0x004ff685:	movl 0x58b700, %eax
0x004ff68a:	pushl $0x4<UINT8>
0x004ff68c:	pushl %eax
0x004ff68d:	call 0x0050090e
0x004ff692:	popl %ecx
0x004ff693:	popl %ecx
0x004ff694:	movl 0x58a6f0, %eax
0x004ff699:	testl %eax, %eax
0x004ff69b:	jne 0x004ff6bb
0x004ff6bb:	xorl %edx, %edx
0x004ff6bd:	movl %ecx, $0x57da30<UINT32>
0x004ff6c2:	jmp 0x004ff6c9
0x004ff6c9:	movl (%edx,%eax), %ecx
0x004ff6cc:	addl %ecx, $0x20<UINT8>
0x004ff6cf:	addl %edx, $0x4<UINT8>
0x004ff6d2:	cmpl %ecx, $0x57dcb0<UINT32>
0x004ff6d8:	jl 0x004ff6c4
0x004ff6c4:	movl %eax, 0x58a6f0
0x004ff6da:	pushl $0xfffffffe<UINT8>
0x004ff6dc:	popl %esi
0x004ff6dd:	xorl %edx, %edx
0x004ff6df:	movl %ecx, $0x57da40<UINT32>
0x004ff6e4:	pushl %edi
0x004ff6e5:	movl %eax, %edx
0x004ff6e7:	sarl %eax, $0x5<UINT8>
0x004ff6ea:	movl %eax, 0x58b720(,%eax,4)
0x004ff6f1:	movl %edi, %edx
0x004ff6f3:	andl %edi, $0x1f<UINT8>
0x004ff6f6:	shll %edi, $0x6<UINT8>
0x004ff6f9:	movl %eax, (%edi,%eax)
0x004ff6fc:	cmpl %eax, $0xffffffff<UINT8>
0x004ff6ff:	je 8
0x004ff701:	cmpl %eax, %esi
0x004ff703:	je 4
0x004ff705:	testl %eax, %eax
0x004ff707:	jne 0x004ff70b
0x004ff70b:	addl %ecx, $0x20<UINT8>
0x004ff70e:	incl %edx
0x004ff70f:	cmpl %ecx, $0x57daa0<UINT32>
0x004ff715:	jl 0x004ff6e5
0x004ff717:	popl %edi
0x004ff718:	xorl %eax, %eax
0x004ff71a:	popl %esi
0x004ff71b:	ret

0x00505e3b:	andl 0x58a6cc, $0x0<UINT8>
0x00505e42:	call 0x0050cbab
0x0050cbab:	movl %edi, %edi
0x0050cbad:	pushl %ebp
0x0050cbae:	movl %ebp, %esp
0x0050cbb0:	subl %esp, $0x18<UINT8>
0x0050cbb3:	xorl %eax, %eax
0x0050cbb5:	pushl %ebx
0x0050cbb6:	movl -4(%ebp), %eax
0x0050cbb9:	movl -12(%ebp), %eax
0x0050cbbc:	movl -8(%ebp), %eax
0x0050cbbf:	pushl %ebx
0x0050cbc0:	pushfl
0x0050cbc1:	popl %eax
0x0050cbc2:	movl %ecx, %eax
0x0050cbc4:	xorl %eax, $0x200000<UINT32>
0x0050cbc9:	pushl %eax
0x0050cbca:	popfl
0x0050cbcb:	pushfl
0x0050cbcc:	popl %edx
0x0050cbcd:	subl %edx, %ecx
0x0050cbcf:	je 0x0050cbf0
0x0050cbf0:	popl %ebx
0x0050cbf1:	testl -4(%ebp), $0x4000000<UINT32>
0x0050cbf8:	je 0x0050cc08
0x0050cc08:	xorl %eax, %eax
0x0050cc0a:	popl %ebx
0x0050cc0b:	leave
0x0050cc0c:	ret

0x00505e47:	movl 0x58a6cc, %eax
0x00505e4c:	xorl %eax, %eax
0x00505e4e:	ret

0x00509950:	cmpl 0x58b82c, $0x0<UINT8>
0x00509957:	jne 18
0x00509959:	pushl $0xfffffffd<UINT8>
0x0050995b:	call 0x005097b6
0x005097b6:	pushl $0x14<UINT8>
0x005097b8:	pushl $0x5601b8<UINT32>
0x005097bd:	call 0x004fa434
0x005097c2:	orl -32(%ebp), $0xffffffff<UINT8>
0x005097c6:	call 0x004fd22a
0x004fd22a:	movl %edi, %edi
0x004fd22c:	pushl %esi
0x004fd22d:	call 0x004fd1b1
0x004fd1b1:	movl %edi, %edi
0x004fd1b3:	pushl %esi
0x004fd1b4:	pushl %edi
0x004fd1b5:	call GetLastError@KERNEL32.DLL
GetLastError@KERNEL32.DLL: API Node	
0x004fd1bb:	pushl 0x57da18
0x004fd1c1:	movl %edi, %eax
0x004fd1c3:	call 0x004fd059
0x004fd059:	movl %edi, %edi
0x004fd05b:	pushl %esi
0x004fd05c:	pushl 0x57da1c
0x004fd062:	call TlsGetValue@KERNEL32.DLL
0x004fd068:	movl %esi, %eax
0x004fd06a:	testl %esi, %esi
0x004fd06c:	jne 0x004fd089
0x004fd089:	movl %eax, %esi
0x004fd08b:	popl %esi
0x004fd08c:	ret

0x004fd1c8:	call FlsGetValue@KERNEL32.DLL
0x004fd1ca:	movl %esi, %eax
0x004fd1cc:	testl %esi, %esi
0x004fd1ce:	jne 0x004fd21e
0x004fd21e:	pushl %edi
0x004fd21f:	call SetLastError@KERNEL32.DLL
SetLastError@KERNEL32.DLL: API Node	
0x004fd225:	popl %edi
0x004fd226:	movl %eax, %esi
0x004fd228:	popl %esi
0x004fd229:	ret

0x004fd232:	movl %esi, %eax
0x004fd234:	testl %esi, %esi
0x004fd236:	jne 0x004fd240
0x004fd240:	movl %eax, %esi
0x004fd242:	popl %esi
0x004fd243:	ret

0x005097cb:	movl %edi, %eax
0x005097cd:	movl -36(%ebp), %edi
0x005097d0:	call 0x005094b1
0x005094b1:	pushl $0xc<UINT8>
0x005094b3:	pushl $0x560198<UINT32>
0x005094b8:	call 0x004fa434
0x005094bd:	call 0x004fd22a
0x005094c2:	movl %edi, %eax
0x005094c4:	movl %eax, 0x57e6f8
0x005094c9:	testl 0x70(%edi), %eax
0x005094cc:	je 0x005094eb
0x005094eb:	pushl $0xd<UINT8>
0x005094ed:	call 0x00504f3f
0x005094f2:	popl %ecx
0x005094f3:	andl -4(%ebp), $0x0<UINT8>
0x005094f7:	movl %esi, 0x68(%edi)
0x005094fa:	movl -28(%ebp), %esi
0x005094fd:	cmpl %esi, 0x57e600
0x00509503:	je 0x0050953b
0x0050953b:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00509542:	call 0x0050954c
0x0050954c:	pushl $0xd<UINT8>
0x0050954e:	call 0x00504e65
0x00509553:	popl %ecx
0x00509554:	ret

0x00509547:	jmp 0x005094d7
0x005094d7:	testl %esi, %esi
0x005094d9:	jne 0x005094e3
0x005094e3:	movl %eax, %esi
0x005094e5:	call 0x004fa479
0x005094ea:	ret

0x005097d5:	movl %ebx, 0x68(%edi)
0x005097d8:	movl %esi, 0x8(%ebp)
0x005097db:	call 0x00509555
0x00509555:	movl %edi, %edi
0x00509557:	pushl %ebp
0x00509558:	movl %ebp, %esp
0x0050955a:	subl %esp, $0x10<UINT8>
0x0050955d:	pushl %ebx
0x0050955e:	xorl %ebx, %ebx
0x00509560:	pushl %ebx
0x00509561:	leal %ecx, -16(%ebp)
0x00509564:	call 0x004fd9fd
0x004fd9fd:	movl %edi, %edi
0x004fd9ff:	pushl %ebp
0x004fda00:	movl %ebp, %esp
0x004fda02:	movl %eax, 0x8(%ebp)
0x004fda05:	pushl %esi
0x004fda06:	movl %esi, %ecx
0x004fda08:	movb 0xc(%esi), $0x0<UINT8>
0x004fda0c:	testl %eax, %eax
0x004fda0e:	jne 0x004fda73
0x004fda10:	call 0x004fd22a
0x004fda15:	movl 0x8(%esi), %eax
0x004fda18:	movl %ecx, 0x6c(%eax)
0x004fda1b:	movl (%esi), %ecx
0x004fda1d:	movl %ecx, 0x68(%eax)
0x004fda20:	movl 0x4(%esi), %ecx
0x004fda23:	movl %ecx, (%esi)
0x004fda25:	cmpl %ecx, 0x57e1c8
0x004fda2b:	je 0x004fda3f
0x004fda3f:	movl %eax, 0x4(%esi)
0x004fda42:	cmpl %eax, 0x57e600
0x004fda48:	je 0x004fda60
0x004fda60:	movl %eax, 0x8(%esi)
0x004fda63:	testb 0x70(%eax), $0x2<UINT8>
0x004fda67:	jne 20
0x004fda69:	orl 0x70(%eax), $0x2<UINT8>
0x004fda6d:	movb 0xc(%esi), $0x1<UINT8>
0x004fda71:	jmp 0x004fda7d
0x004fda7d:	movl %eax, %esi
0x004fda7f:	popl %esi
0x004fda80:	popl %ebp
0x004fda81:	ret $0x4<UINT16>

0x00509569:	movl 0x5893c0, %ebx
0x0050956f:	cmpl %esi, $0xfffffffe<UINT8>
0x00509572:	jne 0x00509592
0x00509592:	cmpl %esi, $0xfffffffd<UINT8>
0x00509595:	jne 0x005095a9
0x00509597:	movl 0x5893c0, $0x1<UINT32>
0x005095a1:	call GetACP@KERNEL32.DLL
GetACP@KERNEL32.DLL: API Node	
0x005095a7:	jmp 0x00509584
0x00509584:	cmpb -4(%ebp), %bl
0x00509587:	je 69
0x00509589:	movl %ecx, -8(%ebp)
0x0050958c:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00509590:	jmp 0x005095ce
0x005095ce:	popl %ebx
0x005095cf:	leave
0x005095d0:	ret

0x005097e0:	movl 0x8(%ebp), %eax
0x005097e3:	cmpl %eax, 0x4(%ebx)
0x005097e6:	je 343
0x005097ec:	pushl $0x220<UINT32>
0x005097f1:	call 0x005008c9
0x005097f6:	popl %ecx
0x005097f7:	movl %ebx, %eax
0x005097f9:	testl %ebx, %ebx
0x005097fb:	je 326
0x00509801:	movl %ecx, $0x88<UINT32>
0x00509806:	movl %esi, 0x68(%edi)
0x00509809:	movl %edi, %ebx
0x0050980b:	rep movsl %es:(%edi), %ds:(%esi)
0x0050980d:	andl (%ebx), $0x0<UINT8>
0x00509810:	pushl %ebx
0x00509811:	pushl 0x8(%ebp)
0x00509814:	call 0x005095d1
0x005095d1:	movl %edi, %edi
0x005095d3:	pushl %ebp
0x005095d4:	movl %ebp, %esp
0x005095d6:	subl %esp, $0x20<UINT8>
0x005095d9:	movl %eax, 0x57d770
0x005095de:	xorl %eax, %ebp
0x005095e0:	movl -4(%ebp), %eax
0x005095e3:	pushl %ebx
0x005095e4:	movl %ebx, 0xc(%ebp)
0x005095e7:	pushl %esi
0x005095e8:	movl %esi, 0x8(%ebp)
0x005095eb:	pushl %edi
0x005095ec:	call 0x00509555
0x005095a9:	cmpl %esi, $0xfffffffc<UINT8>
0x005095ac:	jne 0x005095c0
0x005095c0:	cmpb -4(%ebp), %bl
0x005095c3:	je 7
0x005095c5:	movl %eax, -8(%ebp)
0x005095c8:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x005095cc:	movl %eax, %esi
0x005095f1:	movl %edi, %eax
0x005095f3:	xorl %esi, %esi
0x005095f5:	movl 0x8(%ebp), %edi
0x005095f8:	cmpl %edi, %esi
0x005095fa:	jne 0x0050960a
0x0050960a:	movl -28(%ebp), %esi
0x0050960d:	xorl %eax, %eax
0x0050960f:	cmpl 0x57e608(%eax), %edi
0x00509615:	je 145
0x0050961b:	incl -28(%ebp)
0x0050961e:	addl %eax, $0x30<UINT8>
0x00509621:	cmpl %eax, $0xf0<UINT32>
0x00509626:	jb 0x0050960f
0x00509628:	cmpl %edi, $0xfde8<UINT32>
0x0050962e:	je 368
0x00509634:	cmpl %edi, $0xfde9<UINT32>
0x0050963a:	je 356
0x00509640:	movzwl %eax, %di
0x00509643:	pushl %eax
0x00509644:	call IsValidCodePage@KERNEL32.DLL
IsValidCodePage@KERNEL32.DLL: API Node	
0x0050964a:	testl %eax, %eax
0x0050964c:	je 338
0x00509652:	leal %eax, -24(%ebp)
0x00509655:	pushl %eax
0x00509656:	pushl %edi
0x00509657:	call GetCPInfo@KERNEL32.DLL
GetCPInfo@KERNEL32.DLL: API Node	
0x0050965d:	testl %eax, %eax
0x0050965f:	je 307
0x00509665:	pushl $0x101<UINT32>
0x0050966a:	leal %eax, 0x1c(%ebx)
0x0050966d:	pushl %esi
0x0050966e:	pushl %eax
0x0050966f:	call 0x004f9550
0x004f9550:	movl %edx, 0xc(%esp)
0x004f9554:	movl %ecx, 0x4(%esp)
0x004f9558:	testl %edx, %edx
0x004f955a:	je 105
0x004f955c:	xorl %eax, %eax
0x004f955e:	movb %al, 0x8(%esp)
0x004f9562:	testb %al, %al
0x004f9564:	jne 22
0x004f9566:	cmpl %edx, $0x100<UINT32>
0x004f956c:	jb 0x004f957c
0x004f956e:	cmpl 0x58a6d0, $0x0<UINT8>
0x004f9575:	je 0x004f957c
0x004f957c:	pushl %edi
0x004f957d:	movl %edi, %ecx
0x004f957f:	cmpl %edx, $0x4<UINT8>
0x004f9582:	jb 49
0x004f9584:	negl %ecx
0x004f9586:	andl %ecx, $0x3<UINT8>
0x004f9589:	je 0x004f9597
0x004f9597:	movl %ecx, %eax
0x004f9599:	shll %eax, $0x8<UINT8>
0x004f959c:	addl %eax, %ecx
0x004f959e:	movl %ecx, %eax
0x004f95a0:	shll %eax, $0x10<UINT8>
0x004f95a3:	addl %eax, %ecx
0x004f95a5:	movl %ecx, %edx
0x004f95a7:	andl %edx, $0x3<UINT8>
0x004f95aa:	shrl %ecx, $0x2<UINT8>
0x004f95ad:	je 6
0x004f95af:	rep stosl %es:(%edi), %eax
0x004f95b1:	testl %edx, %edx
0x004f95b3:	je 0x004f95bf
0x004f95b5:	movb (%edi), %al
0x004f95b7:	addl %edi, $0x1<UINT8>
0x004f95ba:	subl %edx, $0x1<UINT8>
0x004f95bd:	jne -10
0x004f95bf:	movl %eax, 0x8(%esp)
0x004f95c3:	popl %edi
0x004f95c4:	ret

0x00509674:	xorl %edx, %edx
0x00509676:	incl %edx
0x00509677:	addl %esp, $0xc<UINT8>
0x0050967a:	movl 0x4(%ebx), %edi
0x0050967d:	movl 0xc(%ebx), %esi
0x00509680:	cmpl -24(%ebp), %edx
0x00509683:	jbe 248
0x00509689:	cmpb -18(%ebp), $0x0<UINT8>
0x0050968d:	je 0x00509762
0x00509762:	leal %eax, 0x1e(%ebx)
0x00509765:	movl %ecx, $0xfe<UINT32>
0x0050976a:	orb (%eax), $0x8<UINT8>
0x0050976d:	incl %eax
0x0050976e:	decl %ecx
0x0050976f:	jne 0x0050976a
0x00509771:	movl %eax, 0x4(%ebx)
0x00509774:	call 0x0050928b
0x0050928b:	subl %eax, $0x3a4<UINT32>
0x00509290:	je 34
0x00509292:	subl %eax, $0x4<UINT8>
0x00509295:	je 23
0x00509297:	subl %eax, $0xd<UINT8>
0x0050929a:	je 12
0x0050929c:	decl %eax
0x0050929d:	je 3
0x0050929f:	xorl %eax, %eax
0x005092a1:	ret

0x00509779:	movl 0xc(%ebx), %eax
0x0050977c:	movl 0x8(%ebx), %edx
0x0050977f:	jmp 0x00509784
0x00509784:	xorl %eax, %eax
0x00509786:	movzwl %ecx, %ax
0x00509789:	movl %eax, %ecx
0x0050978b:	shll %ecx, $0x10<UINT8>
0x0050978e:	orl %eax, %ecx
0x00509790:	leal %edi, 0x10(%ebx)
0x00509793:	stosl %es:(%edi), %eax
0x00509794:	stosl %es:(%edi), %eax
0x00509795:	stosl %es:(%edi), %eax
0x00509796:	jmp 0x00509740
0x00509740:	movl %esi, %ebx
0x00509742:	call 0x0050931e
0x0050931e:	movl %edi, %edi
0x00509320:	pushl %ebp
0x00509321:	movl %ebp, %esp
0x00509323:	subl %esp, $0x51c<UINT32>
0x00509329:	movl %eax, 0x57d770
0x0050932e:	xorl %eax, %ebp
0x00509330:	movl -4(%ebp), %eax
0x00509333:	pushl %ebx
0x00509334:	pushl %edi
0x00509335:	leal %eax, -1304(%ebp)
0x0050933b:	pushl %eax
0x0050933c:	pushl 0x4(%esi)
0x0050933f:	call GetCPInfo@KERNEL32.DLL
0x00509345:	movl %edi, $0x100<UINT32>
0x0050934a:	testl %eax, %eax
0x0050934c:	je 251
0x00509352:	xorl %eax, %eax
0x00509354:	movb -260(%ebp,%eax), %al
0x0050935b:	incl %eax
0x0050935c:	cmpl %eax, %edi
0x0050935e:	jb 0x00509354
0x00509360:	movb %al, -1298(%ebp)
0x00509366:	movb -260(%ebp), $0x20<UINT8>
0x0050936d:	testb %al, %al
0x0050936f:	je 0x0050939f
0x0050939f:	pushl $0x0<UINT8>
0x005093a1:	pushl 0xc(%esi)
0x005093a4:	leal %eax, -1284(%ebp)
0x005093aa:	pushl 0x4(%esi)
0x005093ad:	pushl %eax
0x005093ae:	pushl %edi
0x005093af:	leal %eax, -260(%ebp)
0x005093b5:	pushl %eax
0x005093b6:	pushl $0x1<UINT8>
0x005093b8:	pushl $0x0<UINT8>
0x005093ba:	call 0x0050d960
0x0050d960:	movl %edi, %edi
0x0050d962:	pushl %ebp
0x0050d963:	movl %ebp, %esp
0x0050d965:	subl %esp, $0x10<UINT8>
0x0050d968:	pushl 0x8(%ebp)
0x0050d96b:	leal %ecx, -16(%ebp)
0x0050d96e:	call 0x004fd9fd
0x0050d973:	pushl 0x24(%ebp)
0x0050d976:	leal %ecx, -16(%ebp)
0x0050d979:	pushl 0x20(%ebp)
0x0050d97c:	pushl 0x1c(%ebp)
0x0050d97f:	pushl 0x18(%ebp)
0x0050d982:	pushl 0x14(%ebp)
0x0050d985:	pushl 0x10(%ebp)
0x0050d988:	pushl 0xc(%ebp)
0x0050d98b:	call 0x0050d7a6
0x0050d7a6:	movl %edi, %edi
0x0050d7a8:	pushl %ebp
0x0050d7a9:	movl %ebp, %esp
0x0050d7ab:	pushl %ecx
0x0050d7ac:	pushl %ecx
0x0050d7ad:	movl %eax, 0x57d770
0x0050d7b2:	xorl %eax, %ebp
0x0050d7b4:	movl -4(%ebp), %eax
0x0050d7b7:	movl %eax, 0x589428
0x0050d7bc:	pushl %ebx
0x0050d7bd:	pushl %esi
0x0050d7be:	xorl %ebx, %ebx
0x0050d7c0:	pushl %edi
0x0050d7c1:	movl %edi, %ecx
0x0050d7c3:	cmpl %eax, %ebx
0x0050d7c5:	jne 58
0x0050d7c7:	leal %eax, -8(%ebp)
0x0050d7ca:	pushl %eax
0x0050d7cb:	xorl %esi, %esi
0x0050d7cd:	incl %esi
0x0050d7ce:	pushl %esi
0x0050d7cf:	pushl $0x550080<UINT32>
0x0050d7d4:	pushl %esi
0x0050d7d5:	call GetStringTypeW@KERNEL32.DLL
GetStringTypeW@KERNEL32.DLL: API Node	
0x0050d7db:	testl %eax, %eax
0x0050d7dd:	je 8
0x0050d7df:	movl 0x589428, %esi
0x0050d7e5:	jmp 0x0050d81b
0x0050d81b:	movl -8(%ebp), %ebx
0x0050d81e:	cmpl 0x18(%ebp), %ebx
0x0050d821:	jne 0x0050d82b
0x0050d82b:	movl %esi, 0x51d348
0x0050d831:	xorl %eax, %eax
0x0050d833:	cmpl 0x20(%ebp), %ebx
0x0050d836:	pushl %ebx
0x0050d837:	pushl %ebx
0x0050d838:	pushl 0x10(%ebp)
0x0050d83b:	setne %al
0x0050d83e:	pushl 0xc(%ebp)
0x0050d841:	leal %eax, 0x1(,%eax,8)
0x0050d848:	pushl %eax
0x0050d849:	pushl 0x18(%ebp)
0x0050d84c:	call MultiByteToWideChar@KERNEL32.DLL
MultiByteToWideChar@KERNEL32.DLL: API Node	
0x0050d84e:	movl %edi, %eax
0x0050d850:	cmpl %edi, %ebx
0x0050d852:	je 171
0x0050d858:	jle 60
0x0050d85a:	cmpl %edi, $0x7ffffff0<UINT32>
0x0050d860:	ja 52
0x0050d862:	leal %eax, 0x8(%edi,%edi)
0x0050d866:	cmpl %eax, $0x400<UINT32>
0x0050d86b:	ja 19
0x0050d86d:	call 0x004f95d0
0x004f95d0:	pushl %ecx
0x004f95d1:	leal %ecx, 0x8(%esp)
0x004f95d5:	subl %ecx, %eax
0x004f95d7:	andl %ecx, $0xf<UINT8>
0x004f95da:	addl %eax, %ecx
0x004f95dc:	sbbl %ecx, %ecx
0x004f95de:	orl %eax, %ecx
0x004f95e0:	popl %ecx
0x004f95e1:	jmp 0x004fa260
0x004fa260:	pushl %ecx
0x004fa261:	leal %ecx, 0x4(%esp)
0x004fa265:	subl %ecx, %eax
0x004fa267:	sbbl %eax, %eax
0x004fa269:	notl %eax
0x004fa26b:	andl %ecx, %eax
0x004fa26d:	movl %eax, %esp
0x004fa26f:	andl %eax, $0xfffff000<UINT32>
0x004fa274:	cmpl %ecx, %eax
0x004fa276:	jb 10
0x004fa278:	movl %eax, %ecx
0x004fa27a:	popl %ecx
0x004fa27b:	xchgl %esp, %eax
0x004fa27c:	movl %eax, (%eax)
0x004fa27e:	movl (%esp), %eax
0x004fa281:	ret

0x0050d872:	movl %eax, %esp
0x0050d874:	cmpl %eax, %ebx
0x0050d876:	je 28
0x0050d878:	movl (%eax), $0xcccc<UINT32>
0x0050d87e:	jmp 0x0050d891
0x0050d891:	addl %eax, $0x8<UINT8>
0x0050d894:	movl %ebx, %eax
0x0050d896:	testl %ebx, %ebx
0x0050d898:	je 105
0x0050d89a:	leal %eax, (%edi,%edi)
0x0050d89d:	pushl %eax
0x0050d89e:	pushl $0x0<UINT8>
0x0050d8a0:	pushl %ebx
0x0050d8a1:	call 0x004f9550
0x0050d8a6:	addl %esp, $0xc<UINT8>
0x0050d8a9:	pushl %edi
0x0050d8aa:	pushl %ebx
0x0050d8ab:	pushl 0x10(%ebp)
0x0050d8ae:	pushl 0xc(%ebp)
0x0050d8b1:	pushl $0x1<UINT8>
0x0050d8b3:	pushl 0x18(%ebp)
0x0050d8b6:	call MultiByteToWideChar@KERNEL32.DLL
0x0050d8b8:	testl %eax, %eax
0x0050d8ba:	je 17
0x0050d8bc:	pushl 0x14(%ebp)
0x0050d8bf:	pushl %eax
0x0050d8c0:	pushl %ebx
0x0050d8c1:	pushl 0x8(%ebp)
0x0050d8c4:	call GetStringTypeW@KERNEL32.DLL
0x0050d8ca:	movl -8(%ebp), %eax
0x0050d8cd:	pushl %ebx
0x0050d8ce:	call 0x0050d4b9
0x0050d4b9:	movl %edi, %edi
0x0050d4bb:	pushl %ebp
0x0050d4bc:	movl %ebp, %esp
0x0050d4be:	movl %eax, 0x8(%ebp)
0x0050d4c1:	testl %eax, %eax
0x0050d4c3:	je 18
0x0050d4c5:	subl %eax, $0x8<UINT8>
0x0050d4c8:	cmpl (%eax), $0xdddd<UINT32>
0x0050d4ce:	jne 0x0050d4d7
0x0050d4d7:	popl %ebp
0x0050d4d8:	ret

0x0050d8d3:	movl %eax, -8(%ebp)
0x0050d8d6:	popl %ecx
0x0050d8d7:	jmp 0x0050d94e
0x0050d94e:	leal %esp, -20(%ebp)
0x0050d951:	popl %edi
0x0050d952:	popl %esi
0x0050d953:	popl %ebx
0x0050d954:	movl %ecx, -4(%ebp)
0x0050d957:	xorl %ecx, %ebp
0x0050d959:	call 0x004f7c80
0x004f7c80:	cmpl %ecx, 0x57d770
0x004f7c86:	jne 2
0x004f7c88:	rep ret

0x0050d95e:	leave
0x0050d95f:	ret

0x0050d990:	addl %esp, $0x1c<UINT8>
0x0050d993:	cmpb -4(%ebp), $0x0<UINT8>
0x0050d997:	je 7
0x0050d999:	movl %ecx, -8(%ebp)
0x0050d99c:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0050d9a0:	leave
0x0050d9a1:	ret

0x005093bf:	xorl %ebx, %ebx
0x005093c1:	pushl %ebx
0x005093c2:	pushl 0x4(%esi)
0x005093c5:	leal %eax, -516(%ebp)
0x005093cb:	pushl %edi
0x005093cc:	pushl %eax
0x005093cd:	pushl %edi
0x005093ce:	leal %eax, -260(%ebp)
0x005093d4:	pushl %eax
0x005093d5:	pushl %edi
0x005093d6:	pushl 0xc(%esi)
0x005093d9:	pushl %ebx
0x005093da:	call 0x0050dd95
0x0050dd95:	movl %edi, %edi
0x0050dd97:	pushl %ebp
0x0050dd98:	movl %ebp, %esp
0x0050dd9a:	subl %esp, $0x10<UINT8>
0x0050dd9d:	pushl 0x8(%ebp)
0x0050dda0:	leal %ecx, -16(%ebp)
0x0050dda3:	call 0x004fd9fd
0x0050dda8:	pushl 0x28(%ebp)
0x0050ddab:	leal %ecx, -16(%ebp)
0x0050ddae:	pushl 0x24(%ebp)
0x0050ddb1:	pushl 0x20(%ebp)
0x0050ddb4:	pushl 0x1c(%ebp)
0x0050ddb7:	pushl 0x18(%ebp)
0x0050ddba:	pushl 0x14(%ebp)
0x0050ddbd:	pushl 0x10(%ebp)
0x0050ddc0:	pushl 0xc(%ebp)
0x0050ddc3:	call 0x0050d9f0
0x0050d9f0:	movl %edi, %edi
0x0050d9f2:	pushl %ebp
0x0050d9f3:	movl %ebp, %esp
0x0050d9f5:	subl %esp, $0x14<UINT8>
0x0050d9f8:	movl %eax, 0x57d770
0x0050d9fd:	xorl %eax, %ebp
0x0050d9ff:	movl -4(%ebp), %eax
0x0050da02:	pushl %ebx
0x0050da03:	pushl %esi
0x0050da04:	xorl %ebx, %ebx
0x0050da06:	pushl %edi
0x0050da07:	movl %esi, %ecx
0x0050da09:	cmpl 0x58942c, %ebx
0x0050da0f:	jne 0x0050da49
0x0050da11:	pushl %ebx
0x0050da12:	pushl %ebx
0x0050da13:	xorl %edi, %edi
0x0050da15:	incl %edi
0x0050da16:	pushl %edi
0x0050da17:	pushl $0x550080<UINT32>
0x0050da1c:	pushl $0x100<UINT32>
0x0050da21:	pushl %ebx
0x0050da22:	call LCMapStringW@KERNEL32.DLL
LCMapStringW@KERNEL32.DLL: API Node	
0x0050da28:	testl %eax, %eax
0x0050da2a:	je 8
0x0050da2c:	movl 0x58942c, %edi
0x0050da32:	jmp 0x0050da49
0x0050da49:	cmpl 0x14(%ebp), %ebx
0x0050da4c:	jle 0x0050da70
0x0050da70:	movl %eax, 0x58942c
0x0050da75:	cmpl %eax, $0x2<UINT8>
0x0050da78:	je 428
0x0050da7e:	cmpl %eax, %ebx
0x0050da80:	je 420
0x0050da86:	cmpl %eax, $0x1<UINT8>
0x0050da89:	jne 460
0x0050da8f:	movl -8(%ebp), %ebx
0x0050da92:	cmpl 0x20(%ebp), %ebx
0x0050da95:	jne 0x0050da9f
0x0050da9f:	movl %esi, 0x51d348
0x0050daa5:	xorl %eax, %eax
0x0050daa7:	cmpl 0x24(%ebp), %ebx
0x0050daaa:	pushl %ebx
0x0050daab:	pushl %ebx
0x0050daac:	pushl 0x14(%ebp)
0x0050daaf:	setne %al
0x0050dab2:	pushl 0x10(%ebp)
0x0050dab5:	leal %eax, 0x1(,%eax,8)
0x0050dabc:	pushl %eax
0x0050dabd:	pushl 0x20(%ebp)
0x0050dac0:	call MultiByteToWideChar@KERNEL32.DLL
0x0050dac2:	movl %edi, %eax
0x0050dac4:	cmpl %edi, %ebx
0x0050dac6:	je 0x0050dc5b
0x0050dc5b:	xorl %eax, %eax
0x0050dc5d:	jmp 0x0050dd83
0x0050dd83:	leal %esp, -32(%ebp)
0x0050dd86:	popl %edi
0x0050dd87:	popl %esi
0x0050dd88:	popl %ebx
0x0050dd89:	movl %ecx, -4(%ebp)
0x0050dd8c:	xorl %ecx, %ebp
0x0050dd8e:	call 0x004f7c80
0x0050dd93:	leave
0x0050dd94:	ret

0x0050ddc8:	addl %esp, $0x20<UINT8>
0x0050ddcb:	cmpb -4(%ebp), $0x0<UINT8>
0x0050ddcf:	je 7
0x0050ddd1:	movl %ecx, -8(%ebp)
0x0050ddd4:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0050ddd8:	leave
0x0050ddd9:	ret

0x005093df:	addl %esp, $0x44<UINT8>
0x005093e2:	pushl %ebx
0x005093e3:	pushl 0x4(%esi)
0x005093e6:	leal %eax, -772(%ebp)
0x005093ec:	pushl %edi
0x005093ed:	pushl %eax
0x005093ee:	pushl %edi
0x005093ef:	leal %eax, -260(%ebp)
0x005093f5:	pushl %eax
0x005093f6:	pushl $0x200<UINT32>
0x005093fb:	pushl 0xc(%esi)
0x005093fe:	pushl %ebx
0x005093ff:	call 0x0050dd95
0x00509404:	addl %esp, $0x24<UINT8>
0x00509407:	xorl %eax, %eax
0x00509409:	movzwl %ecx, -1284(%ebp,%eax,2)
0x00509411:	testb %cl, $0x1<UINT8>
0x00509414:	je 0x00509424
0x00509424:	testb %cl, $0x2<UINT8>
0x00509427:	je 0x0050943e
0x0050943e:	movb 0x11d(%esi,%eax), $0x0<UINT8>
0x00509446:	incl %eax
0x00509447:	cmpl %eax, %edi
0x00509449:	jb -66
0x0050944b:	jmp 0x005094a3
0x005094a3:	movl %ecx, -4(%ebp)
0x005094a6:	popl %edi
0x005094a7:	xorl %ecx, %ebp
0x005094a9:	popl %ebx
0x005094aa:	call 0x004f7c80
0x005094af:	leave
0x005094b0:	ret

0x00509747:	jmp 0x00509603
0x00509603:	xorl %eax, %eax
0x00509605:	jmp 0x005097a7
0x005097a7:	movl %ecx, -4(%ebp)
0x005097aa:	popl %edi
0x005097ab:	popl %esi
0x005097ac:	xorl %ecx, %ebp
0x005097ae:	popl %ebx
0x005097af:	call 0x004f7c80
0x005097b4:	leave
0x005097b5:	ret

0x00509819:	popl %ecx
0x0050981a:	popl %ecx
0x0050981b:	movl -32(%ebp), %eax
0x0050981e:	testl %eax, %eax
0x00509820:	jne 252
0x00509826:	movl %esi, -36(%ebp)
0x00509829:	pushl 0x68(%esi)
0x0050982c:	call InterlockedDecrement@KERNEL32.DLL
InterlockedDecrement@KERNEL32.DLL: API Node	
0x00509832:	testl %eax, %eax
0x00509834:	jne 17
0x00509836:	movl %eax, 0x68(%esi)
0x00509839:	cmpl %eax, $0x57e1d8<UINT32>
0x0050983e:	je 0x00509847
0x00509847:	movl 0x68(%esi), %ebx
0x0050984a:	pushl %ebx
0x0050984b:	movl %edi, 0x51d1e8
0x00509851:	call InterlockedIncrement@KERNEL32.DLL
0x00509853:	testb 0x70(%esi), $0x2<UINT8>
0x00509857:	jne 234
0x0050985d:	testb 0x57e6f8, $0x1<UINT8>
0x00509864:	jne 221
0x0050986a:	pushl $0xd<UINT8>
0x0050986c:	call 0x00504f3f
0x00509871:	popl %ecx
0x00509872:	andl -4(%ebp), $0x0<UINT8>
0x00509876:	movl %eax, 0x4(%ebx)
0x00509879:	movl 0x5893d0, %eax
0x0050987e:	movl %eax, 0x8(%ebx)
0x00509881:	movl 0x5893d4, %eax
0x00509886:	movl %eax, 0xc(%ebx)
0x00509889:	movl 0x5893d8, %eax
0x0050988e:	xorl %eax, %eax
0x00509890:	movl -28(%ebp), %eax
0x00509893:	cmpl %eax, $0x5<UINT8>
0x00509896:	jnl 0x005098a8
0x00509898:	movw %cx, 0x10(%ebx,%eax,2)
0x0050989d:	movw 0x5893c4(,%eax,2), %cx
0x005098a5:	incl %eax
0x005098a6:	jmp 0x00509890
0x005098a8:	xorl %eax, %eax
0x005098aa:	movl -28(%ebp), %eax
0x005098ad:	cmpl %eax, $0x101<UINT32>
0x005098b2:	jnl 0x005098c1
0x005098b4:	movb %cl, 0x1c(%eax,%ebx)
0x005098b8:	movb 0x57e3f8(%eax), %cl
0x005098be:	incl %eax
0x005098bf:	jmp 0x005098aa
0x005098c1:	xorl %eax, %eax
0x005098c3:	movl -28(%ebp), %eax
0x005098c6:	cmpl %eax, $0x100<UINT32>
0x005098cb:	jnl 0x005098dd
0x005098cd:	movb %cl, 0x11d(%eax,%ebx)
0x005098d4:	movb 0x57e500(%eax), %cl
0x005098da:	incl %eax
0x005098db:	jmp 0x005098c3
0x005098dd:	pushl 0x57e600
0x005098e3:	call InterlockedDecrement@KERNEL32.DLL
0x005098e9:	testl %eax, %eax
0x005098eb:	jne 0x00509900
0x00509900:	movl 0x57e600, %ebx
0x00509906:	pushl %ebx
0x00509907:	call InterlockedIncrement@KERNEL32.DLL
0x00509909:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00509910:	call 0x00509917
0x00509917:	pushl $0xd<UINT8>
0x00509919:	call 0x00504e65
0x0050991e:	popl %ecx
0x0050991f:	ret

0x00509915:	jmp 0x00509947
0x00509947:	movl %eax, -32(%ebp)
0x0050994a:	call 0x004fa479
0x0050994f:	ret

0x00509960:	popl %ecx
0x00509961:	movl 0x58b82c, $0x1<UINT32>
0x0050996b:	xorl %eax, %eax
0x0050996d:	ret

0x0050cc0d:	call 0x0050cbab
0x0050cc12:	movl 0x58a6d0, %eax
0x0050cc17:	xorl %eax, %eax
0x0050cc19:	ret

0x004fc5f1:	pushl $0x4fc5af<UINT32>
0x004fc5f6:	call SetUnhandledExceptionFilter@KERNEL32.DLL
SetUnhandledExceptionFilter@KERNEL32.DLL: API Node	
0x004fc5fc:	xorl %eax, %eax
0x004fc5fe:	ret

0x004fc03f:	popl %esi
0x004fc040:	popl %ebp
0x004fc041:	ret

0x004fc07d:	popl %ecx
0x004fc07e:	popl %ecx
0x004fc07f:	testl %eax, %eax
0x004fc081:	jne 66
0x004fc083:	pushl $0x4fcf3d<UINT32>
0x004fc088:	call 0x004f881e
0x004f881e:	movl %edi, %edi
0x004f8820:	pushl %ebp
0x004f8821:	movl %ebp, %esp
0x004f8823:	pushl 0x8(%ebp)
0x004f8826:	call 0x004f87e2
0x004f87e2:	pushl $0xc<UINT8>
0x004f87e4:	pushl $0x55fca8<UINT32>
0x004f87e9:	call 0x004fa434
0x004f87ee:	call 0x004fbfef
0x004fbfef:	pushl $0x8<UINT8>
0x004fbff1:	call 0x00504f3f
0x004fbff6:	popl %ecx
0x004fbff7:	ret

0x004f87f3:	andl -4(%ebp), $0x0<UINT8>
0x004f87f7:	pushl 0x8(%ebp)
0x004f87fa:	call 0x004f86f7
0x004f86f7:	movl %edi, %edi
0x004f86f9:	pushl %ebp
0x004f86fa:	movl %ebp, %esp
0x004f86fc:	pushl %ecx
0x004f86fd:	pushl %ebx
0x004f86fe:	pushl %esi
0x004f86ff:	pushl %edi
0x004f8700:	pushl 0x58b828
0x004f8706:	call 0x004fcfde
0x004fd00f:	movl %eax, 0x1fc(%eax)
0x004fd015:	jmp 0x004fd03e
0x004f870b:	pushl 0x58b824
0x004f8711:	movl %edi, %eax
0x004f8713:	movl -4(%ebp), %edi
0x004f8716:	call 0x004fcfde
0x004f871b:	movl %esi, %eax
0x004f871d:	popl %ecx
0x004f871e:	popl %ecx
0x004f871f:	cmpl %esi, %edi
0x004f8721:	jb 131
0x004f8727:	movl %ebx, %esi
0x004f8729:	subl %ebx, %edi
0x004f872b:	leal %eax, 0x4(%ebx)
0x004f872e:	cmpl %eax, $0x4<UINT8>
0x004f8731:	jb 119
0x004f8733:	pushl %edi
0x004f8734:	call 0x004fc32c
0x004fc32c:	pushl $0x10<UINT8>
0x004fc32e:	pushl $0x55fda8<UINT32>
0x004fc333:	call 0x004fa434
0x004fc338:	xorl %eax, %eax
0x004fc33a:	movl %ebx, 0x8(%ebp)
0x004fc33d:	xorl %edi, %edi
0x004fc33f:	cmpl %ebx, %edi
0x004fc341:	setne %al
0x004fc344:	cmpl %eax, %edi
0x004fc346:	jne 0x004fc365
0x004fc365:	cmpl 0x58b704, $0x3<UINT8>
0x004fc36c:	jne 0x004fc3a6
0x004fc3a6:	pushl %ebx
0x004fc3a7:	pushl %edi
0x004fc3a8:	pushl 0x588dfc
0x004fc3ae:	call HeapSize@KERNEL32.DLL
HeapSize@KERNEL32.DLL: API Node	
0x004fc3b4:	movl %esi, %eax
0x004fc3b6:	movl %eax, %esi
0x004fc3b8:	call 0x004fa479
0x004fc3bd:	ret

0x004f8739:	movl %edi, %eax
0x004f873b:	leal %eax, 0x4(%ebx)
0x004f873e:	popl %ecx
0x004f873f:	cmpl %edi, %eax
0x004f8741:	jae 0x004f878b
0x004f878b:	pushl 0x8(%ebp)
0x004f878e:	call 0x004fcf63
0x004f8793:	movl (%esi), %eax
0x004f8795:	addl %esi, $0x4<UINT8>
0x004f8798:	pushl %esi
0x004f8799:	call 0x004fcf63
0x004f879e:	popl %ecx
0x004f879f:	movl 0x58b824, %eax
0x004f87a4:	movl %eax, 0x8(%ebp)
0x004f87a7:	popl %ecx
0x004f87a8:	jmp 0x004f87ac
0x004f87ac:	popl %edi
0x004f87ad:	popl %esi
0x004f87ae:	popl %ebx
0x004f87af:	leave
0x004f87b0:	ret

0x004f87ff:	popl %ecx
0x004f8800:	movl -28(%ebp), %eax
0x004f8803:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004f880a:	call 0x004f8818
0x004f8818:	call 0x004fbff8
0x004fbff8:	pushl $0x8<UINT8>
0x004fbffa:	call 0x00504e65
0x004fbfff:	popl %ecx
0x004fc000:	ret

0x004f881d:	ret

0x004f880f:	movl %eax, -28(%ebp)
0x004f8812:	call 0x004fa479
0x004f8817:	ret

0x004f882b:	negl %eax
0x004f882d:	sbbl %eax, %eax
0x004f882f:	negl %eax
0x004f8831:	popl %ecx
0x004f8832:	decl %eax
0x004f8833:	popl %ebp
0x004f8834:	ret

0x004fc08d:	movl %eax, $0x51d6a4<UINT32>
0x004fc092:	movl (%esp), $0x51d778<UINT32>
0x004fc099:	call 0x004fc001
0x004fc001:	movl %edi, %edi
0x004fc003:	pushl %ebp
0x004fc004:	movl %ebp, %esp
0x004fc006:	pushl %esi
0x004fc007:	movl %esi, %eax
0x004fc009:	jmp 0x004fc016
0x004fc016:	cmpl %esi, 0x8(%ebp)
0x004fc019:	jb 0x004fc00b
0x004fc00b:	movl %eax, (%esi)
0x004fc00d:	testl %eax, %eax
0x004fc00f:	je 0x004fc013
0x004fc013:	addl %esi, $0x4<UINT8>
0x004fc011:	call 0x0051c120
0x0051c3d1:	pushl $0x51c71b<UINT32>
0x0051c3d6:	call 0x004f881e
0x0051c3db:	popl %ecx
0x0051c3dc:	ret

0x0051c3dd:	pushl $0x51c725<UINT32>
0x0051c3e2:	call 0x004f881e
0x0051c3e7:	popl %ecx
0x0051c3e8:	ret

0x0051c40d:	movl %ecx, $0x5869b8<UINT32>
0x0051c412:	jmp 0x004e854e
0x004e854e:	movl %eax, %ecx
0x004e8550:	movl (%eax), $0x538280<UINT32>
0x004e8556:	xorl %ecx, %ecx
0x004e8558:	movl 0x10(%eax), $0x2<UINT32>
0x004e855f:	movl 0x8(%eax), %ecx
0x004e8562:	movl 0xc(%eax), %ecx
0x004e8565:	movw 0x14(%eax), %cx
0x004e8569:	movw 0x16(%eax), %cx
0x004e856d:	movl 0x4(%eax), %eax
0x004e8570:	ret

0x0051c680:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x0051c686:	pushl $0x51c7a2<UINT32>
0x0051c68b:	movl 0x589434, $0x53cfd4<UINT32>
0x0051c695:	movl 0x589438, %eax
0x0051c69a:	movb 0x58943c, $0x0<UINT8>
0x0051c6a1:	call 0x004f881e
0x0051c6a6:	popl %ecx
0x0051c6a7:	ret

0x0051c6a8:	pushl $0x589434<UINT32>
0x0051c6ad:	movl %ecx, $0x589440<UINT32>
0x0051c6b2:	call 0x005110b9
0x005110b9:	movl %edi, %edi
0x005110bb:	pushl %ebp
0x005110bc:	movl %ebp, %esp
0x005110be:	movl %eax, %ecx
0x005110c0:	movl %ecx, 0x8(%ebp)
0x005110c3:	movl 0x4(%eax), %ecx
0x005110c6:	movl (%eax), $0x53cfe8<UINT32>
0x005110cc:	xorl %ecx, %ecx
0x005110ce:	movl 0x14(%eax), $0x2<UINT32>
0x005110d5:	movl 0xc(%eax), %ecx
0x005110d8:	movl 0x10(%eax), %ecx
0x005110db:	movw 0x18(%eax), %cx
0x005110df:	movw 0x1a(%eax), %cx
0x005110e3:	movl 0x8(%eax), %eax
0x005110e6:	popl %ebp
0x005110e7:	ret $0x4<UINT16>

0x0051c6b7:	pushl $0x51c7ac<UINT32>
0x0051c6bc:	call 0x004f881e
0x0051c6c1:	popl %ecx
0x0051c6c2:	ret

0x0051c6c3:	movl %ecx, $0x58945c<UINT32>
0x0051c6c8:	call 0x005112c4
0x005112c4:	movl %edi, %edi
0x005112c6:	pushl %esi
0x005112c7:	movl %esi, %ecx
0x005112c9:	call 0x00511290
0x00511290:	movl %edi, %edi
0x00511292:	pushl %esi
0x00511293:	movl %esi, %ecx
0x00511295:	leal %ecx, 0x14(%esi)
0x00511298:	call 0x0051122f
0x0051122f:	movl %edi, %edi
0x00511231:	pushl %esi
0x00511232:	pushl $0x18<UINT8>
0x00511234:	movl %esi, %ecx
0x00511236:	pushl $0x0<UINT8>
0x00511238:	pushl %esi
0x00511239:	call 0x004f9550
0x0051123e:	addl %esp, $0xc<UINT8>
0x00511241:	movl %eax, %esi
0x00511243:	popl %esi
0x00511244:	ret

0x0051129d:	xorl %eax, %eax
0x0051129f:	movl 0x2c(%esi), %eax
0x005112a2:	movl 0x30(%esi), %eax
0x005112a5:	movl 0x34(%esi), %eax
0x005112a8:	movl %eax, %esi
0x005112aa:	popl %esi
0x005112ab:	ret

0x005112ce:	movl %eax, $0x400000<UINT32>
0x005112d3:	leal %ecx, 0x14(%esi)
0x005112d6:	movl (%esi), $0x38<UINT32>
0x005112dc:	movl 0x8(%esi), %eax
0x005112df:	movl 0x4(%esi), %eax
0x005112e2:	movl 0xc(%esi), $0x900<UINT32>
0x005112e9:	movl 0x10(%esi), $0x53d010<UINT32>
0x005112f0:	call 0x00511245
0x00511245:	pushl $0xc<UINT8>
0x00511247:	pushl $0x560320<UINT32>
0x0051124c:	call 0x004fa434
0x00511251:	andl -4(%ebp), $0x0<UINT8>
0x00511255:	pushl %ecx
0x00511256:	call InitializeCriticalSection@KERNEL32.DLL
InitializeCriticalSection@KERNEL32.DLL: API Node	
0x0051125c:	andl -28(%ebp), $0x0<UINT8>
0x00511260:	jmp 0x00511280
0x00511280:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00511287:	movl %eax, -28(%ebp)
0x0051128a:	call 0x004fa479
0x0051128f:	ret

0x005112f5:	testl %eax, %eax
0x005112f7:	jnl 0x00511300
0x00511300:	movl %eax, %esi
0x00511302:	popl %esi
0x00511303:	ret

0x0051c6cd:	pushl $0x51c7b7<UINT32>
0x0051c6d2:	call 0x004f881e
0x0051c6d7:	popl %ecx
0x0051c6d8:	ret

0x0051c6d9:	pushl $0x900<UINT32>
0x0051c6de:	pushl $0x0<UINT8>
0x0051c6e0:	call 0x00515a96
0x00515a96:	movl %edi, %edi
0x00515a98:	pushl %ebp
0x00515a99:	movl %ebp, %esp
0x00515a9b:	call 0x004e76e3
0x004e76e3:	pushl $0x4e7046<UINT32>
0x004e76e8:	movl %ecx, $0x5869b4<UINT32>
0x004e76ed:	call 0x004f44eb
0x004f44eb:	pushl $0x4<UINT8>
0x004f44ed:	movl %eax, $0x51a886<UINT32>
0x004f44f2:	call 0x004f99e2
0x004f99e2:	pushl %eax
0x004f99e3:	pushl %fs:0
0x004f99ea:	leal %eax, 0xc(%esp)
0x004f99ee:	subl %esp, 0xc(%esp)
0x004f99f2:	pushl %ebx
0x004f99f3:	pushl %esi
0x004f99f4:	pushl %edi
0x004f99f5:	movl (%eax), %ebp
0x004f99f7:	movl %ebp, %eax
0x004f99f9:	movl %eax, 0x57d770
0x004f99fe:	xorl %eax, %ebp
0x004f9a00:	pushl %eax
0x004f9a01:	pushl -4(%ebp)
0x004f9a04:	movl -4(%ebp), $0xffffffff<UINT32>
0x004f9a0b:	leal %eax, -12(%ebp)
0x004f9a0e:	movl %fs:0, %eax
0x004f9a14:	ret

0x004f44f7:	movl %esi, %ecx
0x004f44f9:	xorl %eax, %eax
0x004f44fb:	cmpl 0x8(%ebp), %eax
0x004f44fe:	setne %al
0x004f4501:	testl %eax, %eax
0x004f4503:	jne 0x004f450a
0x004f450a:	cmpl (%esi), $0x0<UINT8>
0x004f450d:	jne 0x004f4545
0x004f450f:	movl %ecx, 0x5885d4
0x004f4515:	testl %ecx, %ecx
0x004f4517:	jne 0x004f453a
0x004f4519:	movl %ecx, $0x5885d8<UINT32>
0x004f451e:	movl -16(%ebp), %ecx
0x004f4521:	andl -4(%ebp), $0x0<UINT8>
0x004f4525:	call 0x004f4201
0x004f4201:	xorl %eax, %eax
0x004f4203:	pushl %esi
0x004f4204:	movl %esi, %ecx
0x004f4206:	movl 0x14(%esi), %eax
0x004f4209:	movl 0x18(%esi), $0x4<UINT32>
0x004f4210:	movl 0x4(%esi), %eax
0x004f4213:	movl 0x8(%esi), $0x1<UINT32>
0x004f421a:	movl 0xc(%esi), %eax
0x004f421d:	movl 0x10(%esi), %eax
0x004f4220:	call TlsAlloc@KERNEL32.DLL
0x004f4226:	movl (%esi), %eax
0x004f4228:	cmpl %eax, $0xffffffff<UINT8>
0x004f422b:	jne 0x004f4232
0x004f4232:	leal %eax, 0x1c(%esi)
0x004f4235:	pushl %eax
0x004f4236:	call InitializeCriticalSection@KERNEL32.DLL
0x004f423c:	movl %eax, %esi
0x004f423e:	popl %esi
0x004f423f:	ret

0x004f452a:	orl -4(%ebp), $0xffffffff<UINT8>
0x004f452e:	movl %ecx, %eax
0x004f4530:	movl 0x5885d4, %ecx
0x004f4536:	testl %eax, %eax
0x004f4538:	je -53
0x004f453a:	call 0x004f40e9
0x004f40e9:	movl %edi, %edi
0x004f40eb:	pushl %ebp
0x004f40ec:	movl %ebp, %esp
0x004f40ee:	pushl %ecx
0x004f40ef:	pushl %ecx
0x004f40f0:	pushl %ebx
0x004f40f1:	pushl %esi
0x004f40f2:	movl %esi, %ecx
0x004f40f4:	leal %eax, 0x1c(%esi)
0x004f40f7:	pushl %edi
0x004f40f8:	pushl %eax
0x004f40f9:	movl -4(%ebp), %eax
0x004f40fc:	call EnterCriticalSection@KERNEL32.DLL
0x004f4102:	movl %ebx, 0x4(%esi)
0x004f4105:	movl %edi, 0x8(%esi)
0x004f4108:	cmpl %edi, %ebx
0x004f410a:	jnl 0x004f4119
0x004f4119:	xorl %edi, %edi
0x004f411b:	incl %edi
0x004f411c:	cmpl %ebx, %edi
0x004f411e:	jle 0x004f413b
0x004f413b:	movl %eax, 0x10(%esi)
0x004f413e:	addl %ebx, $0x20<UINT8>
0x004f4141:	testl %eax, %eax
0x004f4143:	jne 21
0x004f4145:	pushl $0x8<UINT8>
0x004f4147:	pushl %ebx
0x004f4148:	call 0x004e8527
0x004e8527:	movl %edi, %edi
0x004e8529:	pushl %ebp
0x004e852a:	movl %ebp, %esp
0x004e852c:	pushl %ecx
0x004e852d:	pushl 0xc(%ebp)
0x004e8530:	leal %eax, -4(%ebp)
0x004e8533:	pushl 0x8(%ebp)
0x004e8536:	pushl %eax
0x004e8537:	call 0x004e7767
0x004e7767:	movl %edi, %edi
0x004e7769:	pushl %ebp
0x004e776a:	movl %ebp, %esp
0x004e776c:	movl %eax, 0xc(%ebp)
0x004e776f:	mull %eax, 0x10(%ebp)
0x004e7772:	testl %edx, %edx
0x004e7774:	ja 5
0x004e7776:	cmpl %eax, $0xffffffff<UINT8>
0x004e7779:	jbe 0x004e7782
0x004e7782:	movl %ecx, 0x8(%ebp)
0x004e7785:	movl (%ecx), %eax
0x004e7787:	xorl %eax, %eax
0x004e7789:	popl %ebp
0x004e778a:	ret

0x004e853c:	addl %esp, $0xc<UINT8>
0x004e853f:	testl %eax, %eax
0x004e8541:	jnl 0x004e8549
0x004e8549:	movl %eax, -4(%ebp)
0x004e854c:	leave
0x004e854d:	ret

0x004f414d:	popl %ecx
0x004f414e:	popl %ecx
0x004f414f:	pushl %eax
0x004f4150:	pushl $0x2<UINT8>
0x004f4152:	call GlobalAlloc@KERNEL32.DLL
GlobalAlloc@KERNEL32.DLL: API Node	
0x004f4158:	jmp 0x004f4184
0x004f4184:	testl %eax, %eax
0x004f4186:	jne 0x004f41ab
0x004f41ab:	pushl %eax
0x004f41ac:	call GlobalLock@KERNEL32.DLL
GlobalLock@KERNEL32.DLL: API Node	
0x004f41b2:	movl %ecx, 0x4(%esi)
0x004f41b5:	movl %edx, %ebx
0x004f41b7:	subl %edx, %ecx
0x004f41b9:	shll %edx, $0x3<UINT8>
0x004f41bc:	pushl %edx
0x004f41bd:	movl -8(%ebp), %eax
0x004f41c0:	leal %eax, (%eax,%ecx,8)
0x004f41c3:	pushl $0x0<UINT8>
0x004f41c5:	pushl %eax
0x004f41c6:	call 0x004f9550
0x004f41cb:	movl %eax, -8(%ebp)
0x004f41ce:	addl %esp, $0xc<UINT8>
0x004f41d1:	movl 0x4(%esi), %ebx
0x004f41d4:	movl 0x10(%esi), %eax
0x004f41d7:	cmpl %edi, 0xc(%esi)
0x004f41da:	jl 6
0x004f41dc:	leal %eax, 0x1(%edi)
0x004f41df:	movl 0xc(%esi), %eax
0x004f41e2:	movl %eax, 0x10(%esi)
0x004f41e5:	pushl -4(%ebp)
0x004f41e8:	leal %eax, (%eax,%edi,8)
0x004f41eb:	orl (%eax), $0x1<UINT8>
0x004f41ee:	leal %eax, 0x1(%edi)
0x004f41f1:	movl 0x8(%esi), %eax
0x004f41f4:	call LeaveCriticalSection@KERNEL32.DLL
0x004f41fa:	movl %eax, %edi
0x004f41fc:	popl %edi
0x004f41fd:	popl %esi
0x004f41fe:	popl %ebx
0x004f41ff:	leave
0x004f4200:	ret

0x004f453f:	movl (%esi), %eax
0x004f4541:	testl %eax, %eax
0x004f4543:	je -64
0x004f4545:	pushl (%esi)
0x004f4547:	movl %ecx, 0x5885d4
0x004f454d:	call 0x004f3f5b
0x004f3f5b:	movl %edi, %edi
0x004f3f5d:	pushl %ebp
0x004f3f5e:	movl %ebp, %esp
0x004f3f60:	pushl %ebx
0x004f3f61:	pushl %esi
0x004f3f62:	movl %esi, %ecx
0x004f3f64:	pushl %edi
0x004f3f65:	leal %ebx, 0x1c(%esi)
0x004f3f68:	pushl %ebx
0x004f3f69:	call EnterCriticalSection@KERNEL32.DLL
0x004f3f6f:	movl %edi, 0x8(%ebp)
0x004f3f72:	testl %edi, %edi
0x004f3f74:	jle 39
0x004f3f76:	cmpl %edi, 0xc(%esi)
0x004f3f79:	jnl 34
0x004f3f7b:	pushl (%esi)
0x004f3f7d:	call TlsGetValue@KERNEL32.DLL
0x004f3f83:	testl %eax, %eax
0x004f3f85:	je 0x004f3f9d
0x004f3f9d:	pushl %ebx
0x004f3f9e:	call LeaveCriticalSection@KERNEL32.DLL
0x004f3fa4:	xorl %eax, %eax
0x004f3fa6:	popl %edi
0x004f3fa7:	popl %esi
0x004f3fa8:	popl %ebx
0x004f3fa9:	popl %ebp
0x004f3faa:	ret $0x4<UINT16>

0x004f4552:	movl %edi, %eax
0x004f4554:	testl %edi, %edi
0x004f4556:	jne 0x004f456b
0x004f4558:	call 0x004e70eb
0x004e7046:	pushl $0x164<UINT32>
0x004e704b:	call 0x004f3f28
0x004f3f28:	movl %edi, %edi
0x004f3f2a:	pushl %ebp
0x004f3f2b:	movl %ebp, %esp
0x004f3f2d:	pushl 0x8(%ebp)
0x004f3f30:	pushl $0x40<UINT8>
0x004f3f32:	call LocalAlloc@KERNEL32.DLL
LocalAlloc@KERNEL32.DLL: API Node	
0x004f3f38:	testl %eax, %eax
0x004f3f3a:	jne 0x004f3f41
0x004f3f41:	popl %ebp
0x004f3f42:	ret $0x4<UINT16>

0x004e7050:	testl %eax, %eax
0x004e7052:	je 7
0x004e7054:	movl %ecx, %eax
0x004e7056:	jmp 0x004e6f48
0x004e6f48:	movl %eax, %ecx
0x004e6f4a:	xorl %edx, %edx
0x004e6f4c:	xorl %ecx, %ecx
0x004e6f4e:	movl (%eax), $0x537e28<UINT32>
0x004e6f54:	movl 0x34(%eax), %edx
0x004e6f57:	movl 0x54(%eax), %edx
0x004e6f5a:	movl 0x4c(%eax), %ecx
0x004e6f5d:	movl 0x50(%eax), %edx
0x004e6f60:	ret

0x004f455b:	movl %ecx, 0x5885d4
0x004f4561:	movl %edi, %eax
0x004f4563:	pushl %edi
0x004f4564:	pushl (%esi)
0x004f4566:	call 0x004f42a8
0x004f42a8:	pushl $0x10<UINT8>
0x004f42aa:	movl %eax, $0x51a85b<UINT32>
0x004f42af:	call 0x004f9a15
0x004f9a15:	pushl %eax
0x004f9a16:	pushl %fs:0
0x004f9a1d:	leal %eax, 0xc(%esp)
0x004f9a21:	subl %esp, 0xc(%esp)
0x004f9a25:	pushl %ebx
0x004f9a26:	pushl %esi
0x004f9a27:	pushl %edi
0x004f9a28:	movl (%eax), %ebp
0x004f9a2a:	movl %ebp, %eax
0x004f9a2c:	movl %eax, 0x57d770
0x004f9a31:	xorl %eax, %ebp
0x004f9a33:	pushl %eax
0x004f9a34:	movl -16(%ebp), %esp
0x004f9a37:	pushl -4(%ebp)
0x004f9a3a:	movl -4(%ebp), $0xffffffff<UINT32>
0x004f9a41:	leal %eax, -12(%ebp)
0x004f9a44:	movl %fs:0, %eax
0x004f9a4a:	ret

0x004f42b4:	movl %edi, %ecx
0x004f42b6:	movl -24(%ebp), %edi
0x004f42b9:	leal %esi, 0x1c(%edi)
0x004f42bc:	pushl %esi
0x004f42bd:	movl -20(%ebp), %esi
0x004f42c0:	call EnterCriticalSection@KERNEL32.DLL
0x004f42c6:	movl %eax, 0x8(%ebp)
0x004f42c9:	xorl %ebx, %ebx
0x004f42cb:	cmpl %eax, %ebx
0x004f42cd:	jle 251
0x004f42d3:	cmpl %eax, 0xc(%edi)
0x004f42d6:	jge 242
0x004f42dc:	pushl (%edi)
0x004f42de:	call TlsGetValue@KERNEL32.DLL
0x004f42e4:	movl %esi, %eax
0x004f42e6:	cmpl %esi, %ebx
0x004f42e8:	je 0x004f431a
0x004f431a:	pushl $0x10<UINT8>
0x004f431c:	movl -4(%ebp), %ebx
0x004f431f:	call 0x004f3f28
0x004f4324:	cmpl %eax, %ebx
0x004f4326:	je 10
0x004f4328:	movl (%eax), $0x53aa88<UINT32>
0x0051a85b:	movl %edx, 0x8(%esp)
0x0051a85f:	leal %eax, 0xc(%edx)
0x0051a862:	movl %ecx, -32(%edx)
0x0051a865:	xorl %ecx, %eax
0x0051a867:	call 0x004f7c80
0x0051a86c:	movl %eax, $0x55f830<UINT32>
0x0051a871:	jmp 0x004f9689
0x004f9689:	pushl %ebp
0x004f968a:	movl %ebp, %esp
0x004f968c:	subl %esp, $0x8<UINT8>
0x004f968f:	pushl %ebx
0x004f9690:	pushl %esi
0x004f9691:	pushl %edi
0x004f9692:	cld
0x004f9693:	movl -4(%ebp), %eax
0x004f9696:	xorl %eax, %eax
0x004f9698:	pushl %eax
0x004f9699:	pushl %eax
0x004f969a:	pushl %eax
0x004f969b:	pushl -4(%ebp)
0x004f969e:	pushl 0x14(%ebp)
0x004f96a1:	pushl 0x10(%ebp)
0x004f96a4:	pushl 0xc(%ebp)
0x004f96a7:	pushl 0x8(%ebp)
0x004f96aa:	call 0x005078c6
0x005078c6:	movl %edi, %edi
0x005078c8:	pushl %ebp
0x005078c9:	movl %ebp, %esp
0x005078cb:	pushl %ebx
0x005078cc:	pushl %esi
0x005078cd:	pushl %edi
0x005078ce:	call 0x004fd22a
0x005078d3:	cmpl 0x20c(%eax), $0x0<UINT8>
0x005078da:	movl %eax, 0x18(%ebp)
0x005078dd:	movl %ecx, 0x8(%ebp)
0x005078e0:	movl %edi, $0xe06d7363<UINT32>
0x005078e5:	movl %esi, $0x1fffffff<UINT32>
0x005078ea:	movl %ebx, $0x19930522<UINT32>
0x005078ef:	jne 32
0x005078f1:	movl %edx, (%ecx)
0x005078f3:	cmpl %edx, %edi
0x005078f5:	je 26
0x005078f7:	cmpl %edx, $0x80000026<UINT32>
0x005078fd:	je 18
0x005078ff:	movl %edx, (%eax)
0x00507901:	andl %edx, %esi
0x00507903:	cmpl %edx, %ebx
0x00507905:	jb 10
0x00507907:	testb 0x20(%eax), $0x1<UINT8>
0x0050790b:	jne 0x005079a4
0x005079a4:	xorl %eax, %eax
0x005079a6:	incl %eax
0x005079a7:	popl %edi
0x005079a8:	popl %esi
0x005079a9:	popl %ebx
0x005079aa:	popl %ebp
0x005079ab:	ret

0x004f96af:	addl %esp, $0x20<UINT8>
0x004f96b2:	movl -8(%ebp), %eax
0x004f96b5:	popl %edi
0x004f96b6:	popl %esi
0x004f96b7:	popl %ebx
0x004f96b8:	movl %eax, -8(%ebp)
0x004f96bb:	movl %esp, %ebp
0x004f96bd:	popl %ebp
0x004f96be:	ret

0x004f432e:	movl %esi, %eax
0x004f4330:	jmp 0x004f4334
0x004f4334:	orl -4(%ebp), $0xffffffff<UINT8>
0x004f4338:	pushl %esi
0x004f4339:	leal %ecx, 0x14(%edi)
0x004f433c:	movl 0x8(%esi), %ebx
0x004f433f:	movl 0xc(%esi), %ebx
0x004f4342:	call 0x004f405a
0x004f405a:	movl %edi, %edi
0x004f405c:	pushl %ebp
0x004f405d:	movl %ebp, %esp
0x004f405f:	pushl %esi
0x004f4060:	pushl %edi
0x004f4061:	movl %edi, 0x8(%ebp)
0x004f4064:	pushl %edi
0x004f4065:	movl %esi, %ecx
0x004f4067:	call 0x004f4040
0x004f4040:	movl %edi, %edi
0x004f4042:	pushl %ebp
0x004f4043:	movl %ebp, %esp
0x004f4045:	cmpl 0x8(%ebp), $0x0<UINT8>
0x004f4049:	jne 0x004f4050
0x004f4050:	movl %eax, 0x4(%ecx)
0x004f4053:	addl %eax, 0x8(%ebp)
0x004f4056:	popl %ebp
0x004f4057:	ret $0x4<UINT16>

0x004f406c:	movl %ecx, (%esi)
0x004f406e:	movl (%eax), %ecx
0x004f4070:	movl (%esi), %edi
0x004f4072:	popl %edi
0x004f4073:	popl %esi
0x004f4074:	popl %ebp
0x004f4075:	ret $0x4<UINT16>

0x004f4347:	jmp 0x004f42ff
0x004f42ff:	cmpl 0xc(%esi), %ebx
0x004f4302:	jne 0x004f435f
0x004f4304:	pushl $0x4<UINT8>
0x004f4306:	pushl 0xc(%edi)
0x004f4309:	call 0x004e8527
0x004f430e:	popl %ecx
0x004f430f:	popl %ecx
0x004f4310:	pushl %eax
0x004f4311:	pushl %ebx
0x004f4312:	call LocalAlloc@KERNEL32.DLL
0x004f4318:	jmp 0x004f4377
0x004f4377:	cmpl %eax, %ebx
0x004f4379:	jne 0x004f4389
0x004f4389:	movl %ecx, 0x8(%esi)
0x004f438c:	movl 0xc(%esi), %eax
0x004f438f:	movl %edx, 0xc(%edi)
0x004f4392:	subl %edx, %ecx
0x004f4394:	shll %edx, $0x2<UINT8>
0x004f4397:	pushl %edx
0x004f4398:	leal %eax, (%eax,%ecx,4)
0x004f439b:	pushl %ebx
0x004f439c:	pushl %eax
0x004f439d:	call 0x004f9550
0x004f43a2:	movl %eax, 0xc(%edi)
0x004f43a5:	addl %esp, $0xc<UINT8>
0x004f43a8:	pushl %esi
0x004f43a9:	movl 0x8(%esi), %eax
0x004f43ac:	pushl (%edi)
0x004f43ae:	call TlsSetValue@KERNEL32.DLL
0x004f43b4:	movl %ecx, 0x8(%ebp)
0x004f43b7:	movl %eax, 0xc(%esi)
0x004f43ba:	cmpl %eax, %ebx
0x004f43bc:	je 11
0x004f43be:	cmpl %ecx, 0x8(%esi)
0x004f43c1:	jnl 6
0x004f43c3:	movl %edx, 0xc(%ebp)
0x004f43c6:	movl (%eax,%ecx,4), %edx
0x004f43c9:	pushl -20(%ebp)
0x004f43cc:	jmp 0x004f43cf
0x004f43cf:	call LeaveCriticalSection@KERNEL32.DLL
0x004f43d5:	call 0x004f9aba
0x004f9aba:	movl %ecx, -12(%ebp)
0x004f9abd:	movl %fs:0, %ecx
0x004f9ac4:	popl %ecx
0x004f9ac5:	popl %edi
0x004f9ac6:	popl %edi
0x004f9ac7:	popl %esi
0x004f9ac8:	popl %ebx
0x004f9ac9:	movl %esp, %ebp
0x004f9acb:	popl %ebp
0x004f9acc:	pushl %ecx
0x004f9acd:	ret

0x004f43da:	ret $0x8<UINT16>

0x004f456b:	movl %eax, %edi
0x004f456d:	call 0x004f9aba
0x004f4572:	ret $0x4<UINT16>

0x004e76f2:	testl %eax, %eax
0x004e76f4:	jne 0x004e76fb
0x004e76fb:	movl %eax, 0x4(%eax)
0x004e76fe:	testl %eax, %eax
0x004e7700:	jne 19
0x004e7702:	pushl $0x4e76b4<UINT32>
0x004e7707:	movl %ecx, $0x5869b0<UINT32>
0x004e770c:	call 0x004f3fc7
0x004f3fc7:	pushl $0x8<UINT8>
0x004f3fc9:	movl %eax, $0x51a840<UINT32>
0x004f3fce:	call 0x004f9a15
0x004f3fd3:	movl %esi, %ecx
0x004f3fd5:	movl %eax, (%esi)
0x004f3fd7:	testl %eax, %eax
0x004f3fd9:	jne 0x004f3ffc
0x004f3fdb:	pushl $0x10<UINT8>
0x004f3fdd:	call 0x004f6632
0x004f6632:	movl %edi, %edi
0x004f6634:	pushl %ebp
0x004f6635:	movl %ebp, %esp
0x004f6637:	pushl %ebx
0x004f6638:	pushl %esi
0x004f6639:	pushl %edi
0x004f663a:	movl %edi, 0x8(%ebp)
0x004f663d:	cmpl %edi, $0x11<UINT8>
0x004f6640:	jb 0x004f6647
0x004f6647:	cmpl 0x58867c, $0x0<UINT8>
0x004f664e:	jne 0x004f6655
0x004f6650:	call 0x004f65c9
0x004f65c9:	cmpl 0x58867c, $0x0<UINT8>
0x004f65d0:	jne 21
0x004f65d2:	pushl $0x588818<UINT32>
0x004f65d7:	movl 0x58867c, $0x1<UINT32>
0x004f65e1:	call InitializeCriticalSection@KERNEL32.DLL
0x004f65e7:	movl %eax, 0x58867c
0x004f65ec:	ret

0x004f6655:	movl %ebx, 0x51d208
0x004f665b:	leal %esi, 0x588830(,%edi,4)
0x004f6662:	cmpl (%esi), $0x0<UINT8>
0x004f6665:	jne 0x004f6691
0x004f6667:	pushl $0x588818<UINT32>
0x004f666c:	call EnterCriticalSection@KERNEL32.DLL
0x004f666e:	cmpl (%esi), $0x0<UINT8>
0x004f6671:	jne 19
0x004f6673:	movl %eax, %edi
0x004f6675:	imull %eax, %eax, $0x18<UINT8>
0x004f6678:	addl %eax, $0x588680<UINT32>
0x004f667d:	pushl %eax
0x004f667e:	call InitializeCriticalSection@KERNEL32.DLL
0x004f6684:	incl (%esi)
0x004f6686:	pushl $0x588818<UINT32>
0x004f668b:	call LeaveCriticalSection@KERNEL32.DLL
0x004f6691:	imull %edi, %edi, $0x18<UINT8>
0x004f6694:	addl %edi, $0x588680<UINT32>
0x004f669a:	pushl %edi
0x004f669b:	call EnterCriticalSection@KERNEL32.DLL
0x004f669d:	popl %edi
0x004f669e:	popl %esi
0x004f669f:	popl %ebx
0x004f66a0:	popl %ebp
0x004f66a1:	ret $0x4<UINT16>

0x004f3fe2:	movl %eax, (%esi)
0x004f3fe4:	andl -4(%ebp), $0x0<UINT8>
0x004f3fe8:	testl %eax, %eax
0x004f3fea:	jne 5
0x004f3fec:	call 0x004e76b4
0x004e76b4:	pushl $0x4<UINT8>
0x004e76b6:	movl %eax, $0x51a160<UINT32>
0x004e76bb:	call 0x004f99e2
0x004e76c0:	pushl $0x8c<UINT32>
0x004e76c5:	call 0x004f3f28
0x004e76ca:	movl %ecx, %eax
0x004e76cc:	movl -16(%ebp), %ecx
0x004e76cf:	xorl %eax, %eax
0x004e76d1:	movl -4(%ebp), %eax
0x004e76d4:	cmpl %ecx, %eax
0x004e76d6:	je 5
0x004e76d8:	call 0x004e767e
0x004e767e:	movl %edi, %edi
0x004e7680:	pushl %esi
0x004e7681:	pushl $0x1<UINT8>
0x004e7683:	movl %esi, %ecx
0x004e7685:	call 0x004e7543
0x004e7543:	pushl $0xc<UINT8>
0x004e7545:	movl %eax, $0x51a13c<UINT32>
0x004e754a:	call 0x004f9a15
0x004e754f:	movl %esi, %ecx
0x004e7551:	movl -20(%ebp), %esi
0x004e7554:	movl (%esi), $0x537e38<UINT32>
0x0051a13c:	movl %edx, 0x8(%esp)
0x0051a140:	leal %eax, 0xc(%edx)
0x0051a143:	movl %ecx, -28(%edx)
0x0051a146:	xorl %ecx, %eax
0x0051a148:	call 0x004f7c80
0x0051a14d:	movl %eax, $0x55e968<UINT32>
0x0051a152:	jmp 0x004f9689
0x004e755a:	xorl %edi, %edi
0x004e755c:	movl 0x1c(%esi), %edi
0x004e755f:	movl 0x20(%esi), %edi
0x004e7562:	leal %ebx, 0x34(%esi)
0x004e7565:	movl %ecx, %ebx
0x004e7567:	movl 0x24(%esi), %edi
0x004e756a:	movl 0x28(%esi), %edi
0x004e756d:	call 0x00402070
0x00402070:	pushl %esi
0x00402071:	movl %esi, %ecx
0x00402073:	call 0x004e849e
0x004e849e:	movl %eax, $0x5869b8<UINT32>
0x004e84a3:	ret

0x00402078:	testl %eax, %eax
0x0040207a:	jne 0x00402086
0x00402086:	movl %edx, (%eax)
0x00402088:	movl %ecx, %eax
0x0040208a:	movl %eax, 0xc(%edx)
0x0040208d:	call 0x004e8571
0x004e8571:	xorl %edx, %edx
0x004e8573:	leal %eax, 0x10(%ecx)
0x004e8576:	incl %edx
0x004e8577:	xaddl (%eax), %edx
0x004e857b:	leal %eax, 0x4(%ecx)
0x004e857e:	ret

0x0040208f:	addl %eax, $0x10<UINT8>
0x00402092:	movl (%esi), %eax
0x00402094:	movl %eax, %esi
0x00402096:	popl %esi
0x00402097:	ret

0x004e7572:	movl 0x40(%esi), %edi
0x004e7575:	movl 0x44(%esi), %edi
0x004e7578:	orl 0x50(%esi), $0xffffffff<UINT8>
0x004e757c:	movl -4(%ebp), %edi
0x004e757f:	movl 0x54(%esi), %edi
0x004e7582:	movl 0x68(%esi), %edi
0x004e7585:	movl 0x6c(%esi), %edi
0x004e7588:	movb %al, 0x8(%ebp)
0x004e758b:	pushl $0x1000<UINT32>
0x004e7590:	movl %ecx, %ebx
0x004e7592:	movl 0x28(%esi), $0x20<UINT32>
0x004e7599:	movl 0x20(%esi), $0x14<UINT32>
0x004e75a0:	movl 0x18(%esi), %edi
0x004e75a3:	movb 0x14(%esi), %al
0x004e75a6:	movb -4(%ebp), $0x2<UINT8>
0x004e75aa:	call 0x00402330
0x00402330:	pushl %esi
0x00402331:	movl %esi, %ecx
0x00402333:	movl %eax, (%esi)
0x00402335:	movl %edx, -8(%eax)
0x00402338:	subl %eax, $0x10<UINT8>
0x0040233b:	movl %ecx, $0x1<UINT32>
0x00402340:	subl %ecx, 0xc(%eax)
0x00402343:	movl %eax, 0x8(%esp)
0x00402347:	subl %edx, %eax
0x00402349:	orl %ecx, %edx
0x0040234b:	jnl 8
0x0040234d:	pushl %eax
0x0040234e:	movl %ecx, %esi
0x00402350:	call 0x004022e0
0x004022e0:	movl %eax, (%ecx)
0x004022e2:	movl %edx, 0x4(%esp)
0x004022e6:	subl %eax, $0x10<UINT8>
0x004022e9:	pushl %esi
0x004022ea:	movl %esi, 0x4(%eax)
0x004022ed:	cmpl %esi, %edx
0x004022ef:	jle 0x004022f3
0x004022f3:	cmpl 0xc(%eax), $0x1<UINT8>
0x004022f7:	popl %esi
0x004022f8:	jle 9
0x004022fa:	movl 0x4(%esp), %edx
0x004022fe:	jmp 0x00402210
0x00402210:	pushl %ecx
0x00402211:	pushl %ebx
0x00402212:	pushl %ebp
0x00402213:	pushl %esi
0x00402214:	movl %esi, (%ecx)
0x00402216:	movl %ebx, -12(%esi)
0x00402219:	subl %esi, $0x10<UINT8>
0x0040221c:	movl 0xc(%esp), %ecx
0x00402220:	movl %ecx, (%esi)
0x00402222:	movl %eax, (%ecx)
0x00402224:	movl %edx, 0x10(%eax)
0x00402227:	pushl %edi
0x00402228:	call 0x00511106
0x00511106:	movl %eax, %ecx
0x00511108:	ret

0x0040222a:	movl %edx, (%eax)
0x0040222c:	movl %ebp, 0x18(%esp)
0x00402230:	pushl $0x2<UINT8>
0x00402232:	movl %ecx, %eax
0x00402234:	movl %eax, (%edx)
0x00402236:	pushl %ebp
0x00402237:	call 0x004e84a4
0x004e84a4:	movl %edi, %edi
0x004e84a6:	pushl %ebp
0x004e84a7:	movl %ebp, %esp
0x004e84a9:	pushl %esi
0x004e84aa:	movl %esi, 0x8(%ebp)
0x004e84ad:	pushl %edi
0x004e84ae:	movl %edi, %ecx
0x004e84b0:	testl %esi, %esi
0x004e84b2:	jnl 0x004e84b8
0x004e84b8:	leal %eax, 0x1(%esi)
0x004e84bb:	imull %eax, 0xc(%ebp)
0x004e84bf:	addl %eax, $0x10<UINT8>
0x004e84c2:	pushl %eax
0x004e84c3:	call 0x004f8dd9
0x004e84c8:	popl %ecx
0x004e84c9:	testl %eax, %eax
0x004e84cb:	je -25
0x004e84cd:	andl 0x4(%eax), $0x0<UINT8>
0x004e84d1:	movl (%eax), %edi
0x004e84d3:	movl 0xc(%eax), $0x1<UINT32>
0x004e84da:	movl 0x8(%eax), %esi
0x004e84dd:	popl %edi
0x004e84de:	popl %esi
0x004e84df:	popl %ebp
0x004e84e0:	ret $0x8<UINT16>

0x00402239:	movl %edi, %eax
0x0040223b:	testl %edi, %edi
0x0040223d:	jne 0x00402244
0x00402244:	cmpl %ebx, %ebp
0x00402246:	jnl 2
0x00402248:	movl %ebp, %ebx
0x0040224a:	leal %eax, 0x2(%ebp,%ebp)
0x0040224e:	pushl %eax
0x0040224f:	leal %ecx, 0x10(%esi)
0x00402252:	pushl %ecx
0x00402253:	pushl %eax
0x00402254:	leal %ebp, 0x10(%edi)
0x00402257:	pushl %ebp
0x00402258:	call 0x004f7c8f
0x004f7c8f:	movl %edi, %edi
0x004f7c91:	pushl %ebp
0x004f7c92:	movl %ebp, %esp
0x004f7c94:	pushl %esi
0x004f7c95:	movl %esi, 0x14(%ebp)
0x004f7c98:	pushl %edi
0x004f7c99:	xorl %edi, %edi
0x004f7c9b:	cmpl %esi, %edi
0x004f7c9d:	jne 0x004f7ca3
0x004f7ca3:	cmpl 0x8(%ebp), %edi
0x004f7ca6:	jne 0x004f7cc3
0x004f7cc3:	cmpl 0x10(%ebp), %edi
0x004f7cc6:	je 22
0x004f7cc8:	cmpl 0xc(%ebp), %esi
0x004f7ccb:	jb 17
0x004f7ccd:	pushl %esi
0x004f7cce:	pushl 0x10(%ebp)
0x004f7cd1:	pushl 0x8(%ebp)
0x004f7cd4:	call 0x004f9d50
0x004f9dd4:	jmp 0x004f9e88
0x004f9ebb:	jmp 0x004f9ee8
0x004f7cd9:	addl %esp, $0xc<UINT8>
0x004f7cdc:	jmp 0x004f7c9f
0x004f7c9f:	xorl %eax, %eax
0x004f7ca1:	jmp 0x004f7d08
0x004f7d08:	popl %edi
0x004f7d09:	popl %esi
0x004f7d0a:	popl %ebp
0x004f7d0b:	ret

0x0040225d:	addl %esp, $0x10<UINT8>
0x00402260:	movl 0x4(%edi), %ebx
0x00402263:	leal %edx, 0xc(%esi)
0x00402266:	orl %eax, $0xffffffff<UINT8>
0x00402269:	xaddl (%edx), %eax
0x0040226d:	decl %eax
0x0040226e:	testl %eax, %eax
0x00402270:	jg 0x0040227c
0x0040227c:	movl %ecx, 0x10(%esp)
0x00402280:	popl %edi
0x00402281:	popl %esi
0x00402282:	movl (%ecx), %ebp
0x00402284:	popl %ebp
0x00402285:	popl %ebx
0x00402286:	popl %ecx
0x00402287:	ret $0x4<UINT16>

0x00402355:	movl %eax, (%esi)
0x00402357:	popl %esi
0x00402358:	ret $0x4<UINT16>

0x004e75af:	xorl %ebx, %ebx
0x004e75b1:	incl %ebx
0x004e75b2:	movl -4(%ebp), %ebx
0x004e75b5:	jmp 0x004e75d8
0x004e75d8:	pushl $0xc<UINT8>
0x004e75da:	movl 0x30(%esi), %ebx
0x004e75dd:	movl 0x44(%esi), $0x18<UINT32>
0x004e75e4:	call 0x004e6cc9
0x004e6cc9:	movl %edi, %edi
0x004e6ccb:	pushl %ebp
0x004e6ccc:	movl %ebp, %esp
0x004e6cce:	pushl %esi
0x004e6ccf:	jmp 0x004e6ce4
0x004e6ce4:	pushl 0x8(%ebp)
0x004e6ce7:	call 0x004f8dd9
0x004e6cec:	movl %esi, %eax
0x004e6cee:	popl %ecx
0x004e6cef:	testl %esi, %esi
0x004e6cf1:	je -34
0x004e6cf3:	movl %eax, %esi
0x004e6cf5:	popl %esi
0x004e6cf6:	popl %ebp
0x004e6cf7:	ret

0x004e75e9:	movl 0x78(%esi), %eax
0x004e75ec:	movl (%esp), $0x188<UINT32>
0x004e75f3:	call 0x004f3f28
0x004e75f8:	movl %ecx, %eax
0x004e75fa:	movl 0x8(%ebp), %ecx
0x004e75fd:	movb -4(%ebp), $0x4<UINT8>
0x004e7601:	cmpl %ecx, %edi
0x004e7603:	je 7
0x004e7605:	call 0x004e7235
0x004e7235:	pushl $0x4<UINT8>
0x004e7237:	movl %eax, $0x51a0f0<UINT32>
0x004e723c:	call 0x004f99e2
0x004e7241:	movl %esi, %ecx
0x004e7243:	pushl $0x5400d8<UINT32>
0x004e7248:	leal %ecx, -16(%ebp)
0x004e724b:	call 0x00401f20
0x00401f20:	pushl $0xffffffff<UINT8>
0x00401f22:	pushl $0x51b938<UINT32>
0x00401f27:	movl %eax, %fs:0
0x00401f2d:	pushl %eax
0x00401f2e:	pushl %ecx
0x00401f2f:	pushl %esi
0x00401f30:	pushl %edi
0x00401f31:	movl %eax, 0x57d770
0x00401f36:	xorl %eax, %esp
0x00401f38:	pushl %eax
0x00401f39:	leal %eax, 0x10(%esp)
0x00401f3d:	movl %fs:0, %eax
0x00401f43:	movl %edi, %ecx
0x00401f45:	movl 0xc(%esp), %edi
0x00401f49:	call 0x004e849e
0x00401f4e:	xorl %ecx, %ecx
0x00401f50:	testl %eax, %eax
0x00401f52:	setne %cl
0x00401f55:	testl %ecx, %ecx
0x00401f57:	jne 0x00401f63
0x00401f63:	movl %edx, (%eax)
0x00401f65:	movl %ecx, %eax
0x00401f67:	movl %eax, 0xc(%edx)
0x00401f6a:	call 0x004e8571
0x00401f6c:	addl %eax, $0x10<UINT8>
0x00401f6f:	movl (%edi), %eax
0x00401f71:	movl %edx, 0x20(%esp)
0x00401f75:	movl 0x18(%esp), $0x0<UINT32>
0x00401f7d:	testl %edx, %edx
0x00401f7f:	je 32
0x00401f81:	testl %edx, $0xffff0000<UINT32>
0x00401f87:	jne 0x00401fa5
0x00401fa5:	movl %eax, %edx
0x00401fa7:	leal %esi, 0x2(%eax)
0x00401faa:	leal %ebx, (%ebx)
0x00401fb0:	movw %cx, (%eax)
0x00401fb3:	addl %eax, $0x2<UINT8>
0x00401fb6:	testw %cx, %cx
0x00401fb9:	jne 0x00401fb0
0x00401fbb:	subl %eax, %esi
0x00401fbd:	sarl %eax
0x00401fbf:	pushl %eax
0x00401fc0:	pushl %edx
0x00401fc1:	movl %ecx, %edi
0x00401fc3:	call 0x00401dd0
0x00401dd0:	pushl %ebp
0x00401dd1:	pushl %edi
0x00401dd2:	movl %edi, 0x10(%esp)
0x00401dd6:	movl %ebp, %ecx
0x00401dd8:	testl %edi, %edi
0x00401dda:	jne 0x00401de6
0x00401de6:	pushl %esi
0x00401de7:	movl %esi, 0x10(%esp)
0x00401deb:	testl %esi, %esi
0x00401ded:	jne 0x00401df9
0x00401df9:	movl %eax, (%ebp)
0x00401dfc:	movl %edx, -8(%eax)
0x00401dff:	movl %ecx, $0x1<UINT32>
0x00401e04:	subl %ecx, -4(%eax)
0x00401e07:	subl %esi, %eax
0x00401e09:	subl %edx, %edi
0x00401e0b:	sarl %esi
0x00401e0d:	orl %ecx, %edx
0x00401e0f:	pushl %ebx
0x00401e10:	movl %ebx, -12(%eax)
0x00401e13:	jnl 8
0x00401e15:	pushl %edi
0x00401e16:	movl %ecx, %ebp
0x00401e18:	call 0x004022e0
0x00401e1d:	movl %eax, (%ebp)
0x00401e20:	movl %edx, -8(%eax)
0x00401e23:	addl %edx, %edx
0x00401e25:	cmpl %esi, %ebx
0x00401e27:	leal %ebx, (%edi,%edi)
0x00401e2a:	pushl %ebx
0x00401e2b:	ja 0x00401e3a
0x00401e3a:	movl %ecx, 0x18(%esp)
0x00401e3e:	pushl %ecx
0x00401e3f:	pushl %edx
0x00401e40:	pushl %eax
0x00401e41:	call 0x004f7c8f
0x004f9e80:	movl %eax, -24(%esi,%ecx,4)
0x004f9e84:	movl -24(%edi,%ecx,4), %eax
0x004f9e88:	movl %eax, -20(%esi,%ecx,4)
0x004f9e8c:	movl -20(%edi,%ecx,4), %eax
0x004f9e90:	movl %eax, -16(%esi,%ecx,4)
0x004f9e94:	movl -16(%edi,%ecx,4), %eax
0x004f9e98:	movl %eax, -12(%esi,%ecx,4)
0x004f9e9c:	movl -12(%edi,%ecx,4), %eax
0x004f9ea0:	movl %eax, -8(%esi,%ecx,4)
0x004f9ea4:	movl -8(%edi,%ecx,4), %eax
0x004f9ea8:	movl %eax, -4(%esi,%ecx,4)
0x004f9eac:	movl -4(%edi,%ecx,4), %eax
0x004f9eb0:	leal %eax, (,%ecx,4)
0x004f9eb7:	addl %esi, %eax
0x004f9eb9:	addl %edi, %eax
0x004f9ed4:	movl %eax, 0x8(%ebp)
0x004f9ed7:	popl %esi
0x004f9ed8:	popl %edi
0x004f9ed9:	leave
0x004f9eda:	ret

0x00401e46:	addl %esp, $0x10<UINT8>
0x00401e49:	testl %edi, %edi
0x00401e4b:	jl 27
0x00401e4d:	movl %eax, (%ebp)
0x00401e50:	cmpl %edi, -8(%eax)
0x00401e53:	jg 19
0x00401e55:	movl -12(%eax), %edi
0x00401e58:	movl %eax, (%ebp)
0x00401e5b:	xorl %ecx, %ecx
0x00401e5d:	movw (%ebx,%eax), %cx
0x00401e61:	popl %ebx
0x00401e62:	popl %esi
0x00401e63:	popl %edi
0x00401e64:	popl %ebp
0x00401e65:	ret $0x8<UINT16>

0x00401fc8:	movl %eax, %edi
0x00401fca:	movl %ecx, 0x10(%esp)
0x00401fce:	movl %fs:0, %ecx
0x00401fd5:	popl %ecx
0x00401fd6:	popl %edi
0x00401fd7:	popl %esi
0x00401fd8:	addl %esp, $0x10<UINT8>
0x00401fdb:	ret $0x4<UINT16>

0x004e7250:	leal %eax, -16(%ebp)
0x004e7253:	xorl %edi, %edi
0x004e7255:	pushl %eax
0x004e7256:	movl %ecx, %esi
0x004e7258:	movl -4(%ebp), %edi
0x004e725b:	call 0x004e71e7
0x004e71e7:	movl %edi, %edi
0x004e71e9:	pushl %ebp
0x004e71ea:	movl %ebp, %esp
0x004e71ec:	pushl %esi
0x004e71ed:	pushl 0x8(%ebp)
0x004e71f0:	movl %esi, %ecx
0x004e71f2:	leal %ecx, 0xc(%esi)
0x004e71f5:	movl (%esi), $0x537e40<UINT32>
0x004e71fb:	call 0x004e7100
0x004e7100:	movl %edi, %edi
0x004e7102:	pushl %ebp
0x004e7103:	movl %ebp, %esp
0x004e7105:	pushl %esi
0x004e7106:	pushl 0x8(%ebp)
0x004e7109:	movl %esi, %ecx
0x004e710b:	call 0x004e705e
0x004e705e:	movl %edi, %edi
0x004e7060:	pushl %ebp
0x004e7061:	movl %ebp, %esp
0x004e7063:	movl %eax, 0x8(%ebp)
0x004e7066:	movl %eax, (%eax)
0x004e7068:	pushl %esi
0x004e7069:	subl %eax, $0x10<UINT8>
0x004e706c:	pushl %eax
0x004e706d:	movl %esi, %ecx
0x004e706f:	call 0x00401ac0
0x00401ac0:	pushl %esi
0x00401ac1:	movl %esi, 0x8(%esp)
0x00401ac5:	movl %ecx, (%esi)
0x00401ac7:	movl %eax, (%ecx)
0x00401ac9:	movl %edx, 0x10(%eax)
0x00401acc:	pushl %edi
0x00401acd:	call 0x00511106
0x00401acf:	cmpl 0xc(%esi), $0x0<UINT8>
0x00401ad3:	leal %ecx, 0xc(%esi)
0x00401ad6:	jl 20
0x00401ad8:	cmpl %eax, (%esi)
0x00401ada:	jne 16
0x00401adc:	movl %edi, %esi
0x00401ade:	movl %eax, $0x1<UINT32>
0x00401ae3:	xaddl (%ecx), %eax
0x00401ae7:	movl %eax, %edi
0x00401ae9:	popl %edi
0x00401aea:	popl %esi
0x00401aeb:	ret

0x004e7074:	addl %eax, $0x10<UINT8>
0x004e7077:	movl (%esi), %eax
0x004e7079:	popl %ecx
0x004e707a:	movl %eax, %esi
0x004e707c:	popl %esi
0x004e707d:	popl %ebp
0x004e707e:	ret $0x4<UINT16>

0x004e7110:	movl %eax, %esi
0x004e7112:	popl %esi
0x004e7113:	popl %ebp
0x004e7114:	ret $0x4<UINT16>

0x004e7200:	andl 0x4(%esi), $0x0<UINT8>
0x004e7204:	movb 0x8(%esi), $0x0<UINT8>
0x004e7208:	movl %eax, %esi
0x004e720a:	popl %esi
0x004e720b:	popl %ebp
0x004e720c:	ret $0x4<UINT16>

0x004e7260:	movl %ecx, -16(%ebp)
0x004e7263:	addl %ecx, $0xfffffff0<UINT8>
0x004e7266:	call 0x00402430
0x00402430:	leal %eax, 0xc(%ecx)
0x00402433:	orl %edx, $0xffffffff<UINT8>
0x00402436:	xaddl (%eax), %edx
0x0040243a:	decl %edx
0x0040243b:	testl %edx, %edx
0x0040243d:	jg 0x0040244b
0x0040244b:	ret

0x004e726b:	movl (%esi), $0x537e48<UINT32>
0x004e7271:	movl 0x10(%esi), %edi
0x004e7274:	movl 0x14(%esi), %edi
0x004e7277:	movl 0x18(%esi), %edi
0x004e727a:	movl 0x1c(%esi), %edi
0x004e727d:	movl 0x20(%esi), %edi
0x004e7280:	movl 0x24(%esi), %edi
0x004e7283:	movl 0x28(%esi), %edi
0x004e7286:	movl 0x2c(%esi), %edi
0x004e7289:	movl 0x30(%esi), %edi
0x004e728c:	movl 0x34(%esi), %edi
0x004e728f:	movl 0x38(%esi), %edi
0x004e7292:	movl 0x3c(%esi), %edi
0x004e7295:	movl 0x40(%esi), %edi
0x004e7298:	movl 0x44(%esi), %edi
0x004e729b:	movl 0x48(%esi), %edi
0x004e729e:	movl 0x4c(%esi), %edi
0x004e72a1:	movl 0x50(%esi), %edi
0x004e72a4:	movl 0x54(%esi), %edi
0x004e72a7:	movl 0x58(%esi), %edi
0x004e72aa:	movl 0x5c(%esi), %edi
0x004e72ad:	movl 0x60(%esi), %edi
0x004e72b0:	movl 0x64(%esi), %edi
0x004e72b3:	movl 0x68(%esi), %edi
0x004e72b6:	movl 0x6c(%esi), %edi
0x004e72b9:	movl 0x70(%esi), %edi
0x004e72bc:	movl 0x74(%esi), %edi
0x004e72bf:	movl 0x78(%esi), %edi
0x004e72c2:	movl 0x7c(%esi), %edi
0x004e72c5:	movl 0x80(%esi), %edi
0x004e72cb:	movl 0x84(%esi), %edi
0x004e72d1:	movl 0x88(%esi), %edi
0x004e72d7:	movl 0x8c(%esi), %edi
0x004e72dd:	movl 0x90(%esi), %edi
0x004e72e3:	movl 0x94(%esi), %edi
0x004e72e9:	movl 0x98(%esi), %edi
0x004e72ef:	movl 0x9c(%esi), %edi
0x004e72f5:	movl 0xa0(%esi), %edi
0x004e72fb:	movl 0xa4(%esi), %edi
0x004e7301:	movl 0xa8(%esi), %edi
0x004e7307:	movl 0xac(%esi), %edi
0x004e730d:	movl 0xb0(%esi), %edi
0x004e7313:	movl 0xb4(%esi), %edi
0x004e7319:	movl 0xb8(%esi), %edi
0x004e731f:	movl 0xbc(%esi), %edi
0x004e7325:	movl 0xc0(%esi), %edi
0x004e732b:	movl 0xc4(%esi), %edi
0x004e7331:	movl 0xc8(%esi), %edi
0x004e7337:	movl 0xcc(%esi), %edi
0x004e733d:	movl 0xd0(%esi), %edi
0x004e7343:	movl 0xd4(%esi), %edi
0x004e7349:	movl 0xd8(%esi), %edi
0x004e734f:	movl 0xdc(%esi), %edi
0x004e7355:	movl 0xe0(%esi), %edi
0x004e735b:	movl 0xe4(%esi), %edi
0x004e7361:	movl 0xe8(%esi), %edi
0x004e7367:	movl 0xec(%esi), %edi
0x004e736d:	movl 0xf0(%esi), %edi
0x004e7373:	movl 0xf4(%esi), %edi
0x004e7379:	movl 0xf8(%esi), %edi
0x004e737f:	movl 0xfc(%esi), %edi
0x004e7385:	movl 0x100(%esi), %edi
0x004e738b:	movl 0x104(%esi), %edi
0x004e7391:	movl 0x108(%esi), %edi
0x004e7397:	movl 0x10c(%esi), %edi
0x004e739d:	movl 0x110(%esi), %edi
0x004e73a3:	movl 0x114(%esi), %edi
0x004e73a9:	movl 0x118(%esi), %edi
0x004e73af:	movl 0x11c(%esi), %edi
0x004e73b5:	movl 0x120(%esi), %edi
0x004e73bb:	movl 0x124(%esi), %edi
0x004e73c1:	movl 0x128(%esi), %edi
0x004e73c7:	movl 0x12c(%esi), %edi
0x004e73cd:	movl 0x130(%esi), %edi
0x004e73d3:	movl 0x134(%esi), %edi
0x004e73d9:	movl 0x138(%esi), %edi
0x004e73df:	movl 0x13c(%esi), %edi
0x004e73e5:	movl 0x140(%esi), %edi
0x004e73eb:	movl 0x144(%esi), %edi
0x004e73f1:	movl 0x148(%esi), %edi
0x004e73f7:	movl 0x14c(%esi), %edi
0x004e73fd:	movl 0x150(%esi), %edi
0x004e7403:	movl 0x154(%esi), %edi
0x004e7409:	movl 0x158(%esi), %edi
0x004e740f:	movl 0x15c(%esi), %edi
0x004e7415:	movl 0x160(%esi), %edi
0x004e741b:	movl 0x164(%esi), %edi
0x004e7421:	movl 0x168(%esi), %edi
0x004e7427:	movl 0x16c(%esi), %edi
0x004e742d:	movl 0x170(%esi), %edi
0x004e7433:	movl 0x174(%esi), %edi
0x004e7439:	movl 0x178(%esi), %edi
0x004e743f:	movl 0x17c(%esi), %edi
0x004e7445:	movl 0x180(%esi), %edi
0x004e744b:	movl 0x184(%esi), %edi
0x004e7451:	movl %eax, %esi
0x004e7453:	call 0x004f9aba
0x004e7458:	ret

0x004e760a:	jmp 0x004e760e
0x004e760e:	movl %ecx, 0x78(%esi)
0x004e7611:	pushl $0x64<UINT8>
0x004e7613:	movb -4(%ebp), %bl
0x004e7616:	movl (%ecx), %eax
0x004e7618:	call 0x004f3f28
0x004e761d:	movl %ecx, %eax
0x004e761f:	movl 0x8(%ebp), %ecx
0x004e7622:	movb -4(%ebp), $0x5<UINT8>
0x004e7626:	cmpl %ecx, %edi
0x004e7628:	je 7
0x004e762a:	call 0x004e7459
0x004e7459:	pushl $0x4<UINT8>
0x004e745b:	movl %eax, $0x51a0f0<UINT32>
0x004e7460:	call 0x004f99e2
0x004e7465:	movl %esi, %ecx
0x004e7467:	pushl $0x537e54<UINT32>
0x004e746c:	leal %ecx, -16(%ebp)
0x004e746f:	call 0x00401f20
0x004e7474:	leal %eax, -16(%ebp)
0x004e7477:	xorl %edi, %edi
0x004e7479:	pushl %eax
0x004e747a:	movl %ecx, %esi
0x004e747c:	movl -4(%ebp), %edi
0x004e747f:	call 0x004e71e7
0x0051a0f0:	movl %edx, 0x8(%esp)
0x0051a0f4:	leal %eax, 0xc(%edx)
0x0051a0f7:	movl %ecx, -20(%edx)
0x0051a0fa:	xorl %ecx, %eax
0x0051a0fc:	call 0x004f7c80
0x0051a101:	movl %eax, $0x55e920<UINT32>
0x0051a106:	jmp 0x004f9689
0x004e7484:	movl %ecx, -16(%ebp)
0x004e7487:	addl %ecx, $0xfffffff0<UINT8>
0x004e748a:	call 0x00402430
0x004e748f:	movl (%esi), $0x537e50<UINT32>
0x004e7495:	movl 0x10(%esi), %edi
0x004e7498:	movl 0x14(%esi), %edi
0x004e749b:	movl 0x18(%esi), %edi
0x004e749e:	movl 0x1c(%esi), %edi
0x004e74a1:	movl 0x20(%esi), %edi
0x004e74a4:	movl 0x24(%esi), %edi
0x004e74a7:	movl 0x28(%esi), %edi
0x004e74aa:	movl 0x2c(%esi), %edi
0x004e74ad:	movl 0x30(%esi), %edi
0x004e74b0:	movl 0x34(%esi), %edi
0x004e74b3:	movl 0x38(%esi), %edi
0x004e74b6:	movl 0x3c(%esi), %edi
0x004e74b9:	movl 0x40(%esi), %edi
0x004e74bc:	movl 0x44(%esi), %edi
0x004e74bf:	movl 0x48(%esi), %edi
0x004e74c2:	movl 0x4c(%esi), %edi
0x004e74c5:	movl 0x50(%esi), %edi
0x004e74c8:	movl 0x54(%esi), %edi
0x004e74cb:	movl 0x58(%esi), %edi
0x004e74ce:	movl 0x5c(%esi), %edi
0x004e74d1:	movl 0x60(%esi), %edi
0x004e74d4:	movl %eax, %esi
0x004e74d6:	call 0x004f9aba
0x004e74db:	ret

0x004e762f:	jmp 0x004e7633
0x004e7633:	movl %ecx, 0x78(%esi)
0x004e7636:	pushl $0x14<UINT8>
0x004e7638:	movb -4(%ebp), %bl
0x004e763b:	movl 0x4(%ecx), %eax
0x004e763e:	call 0x004f3f28
0x004e7643:	movl %ecx, %eax
0x004e7645:	movl 0x8(%ebp), %ecx
0x004e7648:	movb -4(%ebp), $0x6<UINT8>
0x004e764c:	cmpl %ecx, %edi
0x004e764e:	je 7
0x004e7650:	call 0x004e74fc
0x004e74fc:	pushl $0x4<UINT8>
0x004e74fe:	movl %eax, $0x51a0f0<UINT32>
0x004e7503:	call 0x004f99e2
0x004e7508:	movl %esi, %ecx
0x004e750a:	pushl $0x537e78<UINT32>
0x004e750f:	leal %ecx, -16(%ebp)
0x004e7512:	call 0x00401f20
0x004e7517:	andl -4(%ebp), $0x0<UINT8>
0x004e751b:	leal %eax, -16(%ebp)
0x004e751e:	pushl %eax
0x004e751f:	movl %ecx, %esi
0x004e7521:	call 0x004e71e7
0x004e7526:	movl %ecx, -16(%ebp)
0x004e7529:	addl %ecx, $0xfffffff0<UINT8>
0x004e752c:	call 0x00402430
0x004e7531:	movl (%esi), $0x537e74<UINT32>
0x004e7537:	andl 0x10(%esi), $0x0<UINT8>
0x004e753b:	movl %eax, %esi
0x004e753d:	call 0x004f9aba
0x004e7542:	ret

0x004e7655:	jmp 0x004e7659
0x004e7659:	movl %ecx, 0x78(%esi)
0x004e765c:	movl 0x8(%ecx), %eax
0x004e765f:	movl 0x7c(%esi), %ebx
0x004e7662:	movl 0x80(%esi), %edi
0x004e7668:	movl 0x84(%esi), %edi
0x004e766e:	movl 0x88(%esi), %edi
0x004e7674:	movl %eax, %esi
0x004e7676:	call 0x004f9aba
0x004e767b:	ret $0x4<UINT16>

0x004e768a:	movl (%esi), $0x537e94<UINT32>
0x004e7690:	movl %eax, %esi
0x004e7692:	popl %esi
0x004e7693:	ret

0x004e76dd:	call 0x004f9aba
0x004e76e2:	ret

0x004f3fef:	movl (%esi), %eax
0x004f3ff1:	orl -4(%ebp), $0xffffffff<UINT8>
0x004f3ff5:	pushl $0x10<UINT8>
0x004f3ff7:	call 0x004f66a4
0x004f66a4:	movl %edi, %edi
0x004f66a6:	pushl %ebp
0x004f66a7:	movl %ebp, %esp
0x004f66a9:	movl %eax, 0x8(%ebp)
0x004f66ac:	cmpl %eax, $0x11<UINT8>
0x004f66af:	jb 0x004f66b6
0x004f66b6:	imull %eax, %eax, $0x18<UINT8>
0x004f66b9:	addl %eax, $0x588680<UINT32>
0x004f66be:	pushl %eax
0x004f66bf:	call LeaveCriticalSection@KERNEL32.DLL
0x004f66c5:	popl %ebp
0x004f66c6:	ret $0x4<UINT16>

0x004f3ffc:	movl %eax, (%esi)
0x004f3ffe:	call 0x004f9aba
0x004f4003:	ret $0x4<UINT16>

0x004e7711:	testl %eax, %eax
0x004e7713:	je -31
0x004e7715:	ret

0x00515aa0:	movb %cl, 0x8(%ebp)
0x00515aa3:	movb 0x14(%eax), %cl
0x00515aa6:	xorl %eax, %eax
0x00515aa8:	incl %eax
0x00515aa9:	popl %ebp
0x00515aaa:	ret $0x8<UINT16>

0x0051c6e5:	pushl $0x515aad<UINT32>
0x0051c6ea:	call 0x004f881e
0x0051c6ef:	popl %ecx
0x0051c6f0:	movb 0x5894a4, %al
0x0051c6f5:	ret

0x0051c3e9:	pushl $0x51c72f<UINT32>
0x0051c3ee:	call 0x004f881e
0x0051c3f3:	popl %ecx
0x0051c3f4:	ret

0x0051c3f5:	pushl $0x51c73a<UINT32>
0x0051c3fa:	call 0x004f881e
0x0051c3ff:	popl %ecx
0x0051c400:	ret

0x0051c401:	pushl $0x51c745<UINT32>
0x0051c406:	call 0x004f881e
0x0051c40b:	popl %ecx
0x0051c40c:	ret

0x0051c417:	pushl $0x0<UINT8>
0x0051c419:	movl %ecx, $0x5869d0<UINT32>
0x0051c41e:	call 0x004e7b3d
0x004e7b3d:	movl %edi, %edi
0x004e7b3f:	pushl %ebp
0x004e7b40:	movl %ebp, %esp
0x004e7b42:	movl %eax, %ecx
0x004e7b44:	movl %ecx, 0x8(%ebp)
0x004e7b47:	movl 0x4(%eax), %ecx
0x004e7b4a:	popl %ebp
0x004e7b4b:	ret $0x4<UINT16>

0x0051c423:	andl 0x5869dc, $0x0<UINT8>
0x0051c42a:	andl 0x5869e0, $0x0<UINT8>
0x0051c431:	pushl $0x51c750<UINT32>
0x0051c436:	movl 0x5869d0, $0x538444<UINT32>
0x0051c440:	movl 0x586ae4, $0xf022<UINT32>
0x0051c44a:	call 0x004f881e
0x0051c44f:	popl %ecx
0x0051c450:	ret

0x0051c451:	pushl $0x0<UINT8>
0x0051c453:	movl %ecx, $0x586ae8<UINT32>
0x0051c458:	call 0x004e7b3d
0x0051c45d:	andl 0x586af4, $0x0<UINT8>
0x0051c464:	andl 0x586af8, $0x0<UINT8>
0x0051c46b:	pushl $0x51c75b<UINT32>
0x0051c470:	movl 0x586ae8, $0x538460<UINT32>
0x0051c47a:	movl 0x586bfc, $0xf024<UINT32>
0x0051c484:	call 0x004f881e
0x0051c489:	popl %ecx
0x0051c48a:	ret

0x0051c48b:	pushl $0x51c766<UINT32>
0x0051c490:	call 0x004f881e
0x0051c495:	popl %ecx
0x0051c496:	ret

0x0051c497:	pushl $0x5398a0<UINT32>
0x0051c49c:	call RegisterWindowMessageW@USER32.dll
RegisterWindowMessageW@USER32.dll: API Node	
0x0051c4a2:	movl 0x588440, %eax
0x0051c4a7:	ret

0x0051c4a8:	movl %ecx, $0x588448<UINT32>
0x0051c4ad:	call 0x004ec513
0x004ec513:	movl %edi, %edi
0x004ec515:	pushl %esi
0x004ec516:	movl %esi, %ecx
0x004ec518:	call 0x004e76e3
0x004f3f87:	cmpl %edi, 0x8(%eax)
0x004f3f8a:	jnl 0x004f3f9d
0x004f3f8c:	movl %eax, 0xc(%eax)
0x004f3f8f:	movl %edi, (%eax,%edi,4)
0x004f3f92:	pushl %ebx
0x004f3f93:	call LeaveCriticalSection@KERNEL32.DLL
0x004f3f99:	movl %eax, %edi
0x004f3f9b:	jmp 0x004f3fa6
0x004ec51d:	movl 0x1c(%esi), %eax
0x004ec520:	xorl %eax, %eax
0x004ec522:	incl %eax
0x004ec523:	xorl %ecx, %ecx
0x004ec525:	movl 0x4(%esi), %eax
0x004ec528:	movl 0x14(%esi), %eax
0x004ec52b:	movl 0x8(%esi), %ecx
0x004ec52e:	movl 0xc(%esi), %ecx
0x004ec531:	movl 0x10(%esi), %ecx
0x004ec534:	movl 0x18(%esi), %ecx
0x004ec537:	movl %eax, %esi
0x004ec539:	popl %esi
0x004ec53a:	ret

0x0051c4b2:	xorl %eax, %eax
0x0051c4b4:	pushl $0x51c770<UINT32>
0x0051c4b9:	movl 0x588448, $0x53927c<UINT32>
0x0051c4c3:	movl 0x588478, $0x5391ec<UINT32>
0x0051c4cd:	movl 0x58847c, $0x539260<UINT32>
0x0051c4d7:	movl 0x588468, %eax
0x0051c4dc:	movb 0x58846c, %al
0x0051c4e1:	movl 0x588474, %eax
0x0051c4e6:	movl 0x588480, %eax
0x0051c4eb:	movl 0x588484, %eax
0x0051c4f0:	movl 0x588488, %eax
0x0051c4f5:	movl 0x58848c, %eax
0x0051c4fa:	movl 0x588490, %eax
0x0051c4ff:	movl 0x588494, %eax
0x0051c504:	movl 0x588498, %eax
0x0051c509:	call 0x004f881e
0x0051c50e:	popl %ecx
0x0051c50f:	ret

0x0051c510:	movl %ecx, $0x5884a0<UINT32>
0x0051c515:	call 0x004ec513
0x0051c51a:	xorl %eax, %eax
0x0051c51c:	pushl $0x51c77a<UINT32>
0x0051c521:	movl 0x5884a0, $0x53927c<UINT32>
0x0051c52b:	movl 0x5884d0, $0x5391ec<UINT32>
0x0051c535:	movl 0x5884d4, $0x539260<UINT32>
0x0051c53f:	movl 0x5884c0, $0x1<UINT32>
0x0051c549:	movb 0x5884c4, %al
0x0051c54e:	movl 0x5884cc, %eax
0x0051c553:	movl 0x5884d8, %eax
0x0051c558:	movl 0x5884dc, %eax
0x0051c55d:	movl 0x5884e0, %eax
0x0051c562:	movl 0x5884e4, %eax
0x0051c567:	movl 0x5884e8, %eax
0x0051c56c:	movl 0x5884ec, %eax
0x0051c571:	movl 0x5884f0, %eax
0x0051c576:	call 0x004f881e
0x0051c57b:	popl %ecx
0x0051c57c:	ret

0x0051c57d:	movl %ecx, $0x5884f8<UINT32>
0x0051c582:	call 0x004ec513
0x0051c587:	orl 0x588518, $0xffffffff<UINT8>
0x0051c58e:	xorl %eax, %eax
0x0051c590:	pushl $0x51c784<UINT32>
0x0051c595:	movl 0x5884f8, $0x53927c<UINT32>
0x0051c59f:	movl 0x588528, $0x5391ec<UINT32>
0x0051c5a9:	movl 0x58852c, $0x539260<UINT32>
0x0051c5b3:	movb 0x58851c, %al
0x0051c5b8:	movl 0x588524, %eax
0x0051c5bd:	movl 0x588530, %eax
0x0051c5c2:	movl 0x588534, %eax
0x0051c5c7:	movl 0x588538, %eax
0x0051c5cc:	movl 0x58853c, %eax
0x0051c5d1:	movl 0x588540, %eax
0x0051c5d6:	movl 0x588544, %eax
0x0051c5db:	movl 0x588548, %eax
0x0051c5e0:	call 0x004f881e
0x0051c5e5:	popl %ecx
0x0051c5e6:	ret

0x0051c5e7:	movl %ecx, $0x588550<UINT32>
0x0051c5ec:	call 0x004ec513
0x0051c5f1:	xorl %eax, %eax
0x0051c5f3:	pushl $0x51c78e<UINT32>
0x0051c5f8:	movl 0x588550, $0x53927c<UINT32>
0x0051c602:	movl 0x588580, $0x5391ec<UINT32>
0x0051c60c:	movl 0x588584, $0x539260<UINT32>
0x0051c616:	movl 0x588570, $0xfffffffe<UINT32>
0x0051c620:	movb 0x588574, %al
0x0051c625:	movl 0x58857c, %eax
0x0051c62a:	movl 0x588588, %eax
0x0051c62f:	movl 0x58858c, %eax
0x0051c634:	movl 0x588590, %eax
0x0051c639:	movl 0x588594, %eax
0x0051c63e:	movl 0x588598, %eax
0x0051c643:	movl 0x58859c, %eax
0x0051c648:	movl 0x5885a0, %eax
0x0051c64d:	call 0x004f881e
0x0051c652:	popl %ecx
0x0051c653:	ret

0x0051c654:	movl %ecx, $0x588610<UINT32>
0x0051c659:	call 0x004f4f70
0x004f4f70:	movl %edi, %edi
0x004f4f72:	pushl %ebx
0x004f4f73:	pushl %esi
0x004f4f74:	pushl %edi
0x004f4f75:	movl %esi, %ecx
0x004f4f77:	call 0x004f4f14
0x004f4f14:	movl %edi, %edi
0x004f4f16:	pushl %ebx
0x004f4f17:	pushl %esi
0x004f4f18:	movl %esi, 0x51d5b0
0x004f4f1e:	pushl %edi
0x004f4f1f:	pushl $0xb<UINT8>
0x004f4f21:	movl %edi, %ecx
0x004f4f23:	call GetSystemMetrics@USER32.dll
GetSystemMetrics@USER32.dll: API Node	
0x004f4f25:	pushl $0xc<UINT8>
0x004f4f27:	movl 0x8(%edi), %eax
0x004f4f2a:	call GetSystemMetrics@USER32.dll
0x004f4f2c:	pushl $0x2<UINT8>
0x004f4f2e:	movl 0xc(%edi), %eax
0x004f4f31:	call GetSystemMetrics@USER32.dll
0x004f4f33:	incl %eax
0x004f4f34:	pushl $0x3<UINT8>
0x004f4f36:	movl 0x588610, %eax
0x004f4f3b:	call GetSystemMetrics@USER32.dll
0x004f4f3d:	incl %eax
0x004f4f3e:	pushl $0x0<UINT8>
0x004f4f40:	movl 0x588614, %eax
0x004f4f45:	call GetDC@USER32.dll
GetDC@USER32.dll: API Node	
0x004f4f4b:	movl %esi, 0x51d12c
0x004f4f51:	movl %ebx, %eax
0x004f4f53:	pushl $0x58<UINT8>
0x004f4f55:	pushl %ebx
0x004f4f56:	call GetDeviceCaps@GDI32.dll
GetDeviceCaps@GDI32.dll: API Node	
0x004f4f58:	pushl $0x5a<UINT8>
0x004f4f5a:	pushl %ebx
0x004f4f5b:	movl 0x18(%edi), %eax
0x004f4f5e:	call GetDeviceCaps@GDI32.dll
0x004f4f60:	pushl %ebx
0x004f4f61:	pushl $0x0<UINT8>
0x004f4f63:	movl 0x1c(%edi), %eax
0x004f4f66:	call ReleaseDC@USER32.dll
ReleaseDC@USER32.dll: API Node	
0x004f4f6c:	popl %edi
0x004f4f6d:	popl %esi
0x004f4f6e:	popl %ebx
0x004f4f6f:	ret

0x004f4f7c:	xorl %ebx, %ebx
0x004f4f7e:	movl %ecx, %esi
0x004f4f80:	movl 0x24(%esi), %ebx
0x004f4f83:	call 0x004f4ece
0x004f4ece:	movl %edi, %edi
0x004f4ed0:	pushl %esi
0x004f4ed1:	pushl %edi
0x004f4ed2:	movl %edi, 0x51d5c8
0x004f4ed8:	pushl $0xf<UINT8>
0x004f4eda:	movl %esi, %ecx
0x004f4edc:	call GetSysColor@USER32.dll
GetSysColor@USER32.dll: API Node	
0x004f4ede:	pushl $0x10<UINT8>
0x004f4ee0:	movl 0x28(%esi), %eax
0x004f4ee3:	call GetSysColor@USER32.dll
0x004f4ee5:	pushl $0x14<UINT8>
0x004f4ee7:	movl 0x2c(%esi), %eax
0x004f4eea:	call GetSysColor@USER32.dll
0x004f4eec:	pushl $0x12<UINT8>
0x004f4eee:	movl 0x30(%esi), %eax
0x004f4ef1:	call GetSysColor@USER32.dll
0x004f4ef3:	pushl $0x6<UINT8>
0x004f4ef5:	movl 0x34(%esi), %eax
0x004f4ef8:	call GetSysColor@USER32.dll
0x004f4efa:	movl %edi, 0x51d414
0x004f4f00:	pushl $0xf<UINT8>
0x004f4f02:	movl 0x38(%esi), %eax
0x004f4f05:	call GetSysColorBrush@USER32.dll
GetSysColorBrush@USER32.dll: API Node	
0x004f4f07:	pushl $0x6<UINT8>
0x004f4f09:	movl 0x24(%esi), %eax
0x004f4f0c:	call GetSysColorBrush@USER32.dll
0x004f4f0e:	popl %edi
0x004f4f0f:	movl 0x20(%esi), %eax
0x004f4f12:	popl %esi
0x004f4f13:	ret

0x004f4f88:	movl %edi, 0x51d410
0x004f4f8e:	pushl $0x7f02<UINT32>
0x004f4f93:	pushl %ebx
0x004f4f94:	call LoadCursorW@USER32.dll
LoadCursorW@USER32.dll: API Node	
0x004f4f96:	pushl $0x7f00<UINT32>
0x004f4f9b:	pushl %ebx
0x004f4f9c:	movl 0x3c(%esi), %eax
0x004f4f9f:	call LoadCursorW@USER32.dll
0x004f4fa1:	pushl $0x2<UINT8>
0x004f4fa3:	movl 0x40(%esi), %eax
0x004f4fa6:	popl %eax
0x004f4fa7:	movl 0x10(%esi), %eax
0x004f4faa:	movl 0x14(%esi), %eax
0x004f4fad:	popl %edi
0x004f4fae:	movl 0x50(%esi), %ebx
0x004f4fb1:	movl 0x44(%esi), %ebx
0x004f4fb4:	movl %eax, %esi
0x004f4fb6:	popl %esi
0x004f4fb7:	popl %ebx
0x004f4fb8:	ret

0x0051c65e:	pushl $0x51c798<UINT32>
0x0051c663:	call 0x004f881e
0x0051c668:	popl %ecx
0x0051c669:	ret

0x0051c66a:	pushl $0x57d698<UINT32>
0x0051c66f:	call 0x004f3efd
0x004f3efd:	movl %edi, %edi
0x004f3eff:	pushl %ebp
0x004f3f00:	movl %ebp, %esp
0x004f3f02:	pushl %esi
0x004f3f03:	call 0x004e76e3
0x004f3f08:	pushl $0x0<UINT8>
0x004f3f0a:	movl %esi, %eax
0x004f3f0c:	call 0x004f6632
0x004f3f11:	pushl 0x8(%ebp)
0x004f3f14:	leal %ecx, 0x1c(%esi)
0x004f3f17:	call 0x004f405a
0x004f3f1c:	pushl $0x0<UINT8>
0x004f3f1e:	call 0x004f66a4
0x004f3f23:	popl %esi
0x004f3f24:	popl %ebp
0x004f3f25:	ret $0x4<UINT16>

0x0051c674:	ret

0x0051c675:	pushl $0x57d734<UINT32>
0x0051c67a:	call 0x004f3efd
0x0051c67f:	ret

0x0051c700:	pushl $0x51c7d0<UINT32>
0x0051c705:	call 0x004f881e
0x0051c70a:	popl %ecx
0x0051c70b:	ret

0x0051c020:	pushl $0x53e510<UINT32>
0x0051c025:	call RegisterWindowMessageW@USER32.dll
0x0051c02b:	movl 0x5894c8, %eax
0x0051c030:	ret

0x0051c040:	pushl $0x53e510<UINT32>
0x0051c045:	call RegisterWindowMessageW@USER32.dll
0x0051c04b:	movl 0x5894cc, %eax
0x0051c050:	ret

0x0051c060:	pushl $0x53e510<UINT32>
0x0051c065:	call RegisterWindowMessageW@USER32.dll
0x0051c06b:	movl 0x5894d0, %eax
0x0051c070:	ret

0x0051c080:	pushl $0x53e510<UINT32>
0x0051c085:	call RegisterWindowMessageW@USER32.dll
0x0051c08b:	movl 0x5894d4, %eax
0x0051c090:	ret

0x0051c0a0:	pushl $0x53e510<UINT32>
0x0051c0a5:	call RegisterWindowMessageW@USER32.dll
0x0051c0ab:	movl 0x5894d8, %eax
0x0051c0b0:	ret

0x0051c0c0:	pushl $0x53e510<UINT32>
0x0051c0c5:	call RegisterWindowMessageW@USER32.dll
0x0051c0cb:	movl 0x5894dc, %eax
0x0051c0d0:	ret

0x0051c0e0:	pushl $0x53e510<UINT32>
0x0051c0e5:	call RegisterWindowMessageW@USER32.dll
0x0051c0eb:	movl 0x5894e0, %eax
0x0051c0f0:	ret

0x0051c100:	pushl $0x53e510<UINT32>
0x0051c105:	call RegisterWindowMessageW@USER32.dll
0x0051c10b:	movl 0x5894e4, %eax
0x0051c110:	ret

0x0051c120:	call 0x00409990
0x00409990:	pushl $0xffffffff<UINT8>
0x00409992:	pushl $0x51b3d7<UINT32>
0x00409997:	movl %eax, %fs:0
0x0040999d:	pushl %eax
0x0040999e:	subl %esp, $0x414<UINT32>
0x004099a4:	movl %eax, 0x57d770
0x004099a9:	xorl %eax, %esp
0x004099ab:	movl 0x410(%esp), %eax
0x004099b2:	pushl %ebx
0x004099b3:	pushl %ebp
0x004099b4:	pushl %esi
0x004099b5:	pushl %edi
0x004099b6:	movl %eax, 0x57d770
0x004099bb:	xorl %eax, %esp
0x004099bd:	pushl %eax
0x004099be:	leal %eax, 0x428(%esp)
0x004099c5:	movl %fs:0, %eax
0x004099cb:	movl %ecx, $0x5894e8<UINT32>
0x004099d0:	xorl %edi, %edi
0x004099d2:	pushl %edi
0x004099d3:	movl 0x1c(%esp), %ecx
0x004099d7:	call 0x004f3500
0x004f3500:	pushl $0x4<UINT8>
0x004f3502:	movl %eax, $0x51a73a<UINT32>
0x004f3507:	call 0x004f99e2
0x004f350c:	movl %esi, %ecx
0x004f350e:	movl -16(%ebp), %esi
0x004f3511:	call 0x004ebe86
0x004ebe86:	pushl $0x4<UINT8>
0x004ebe88:	movl %eax, $0x51a451<UINT32>
0x004ebe8d:	call 0x004f99e2
0x004ebe92:	movl %esi, %ecx
0x004ebe94:	movl -16(%ebp), %esi
0x004ebe97:	call 0x004ec513
0x004ebe9c:	xorl %eax, %eax
0x004ebe9e:	movl %ecx, %esi
0x004ebea0:	movl -4(%ebp), %eax
0x004ebea3:	movl (%esi), $0x538ce4<UINT32>
0x004ebea9:	movl 0x34(%esi), %eax
0x004ebeac:	movl 0x38(%esi), %eax
0x004ebeaf:	call 0x004ebb42
0x004ebb42:	movl %edi, %edi
0x004ebb44:	pushl %esi
0x004ebb45:	movl %esi, %ecx
0x004ebb47:	pushl %edi
0x004ebb48:	xorl %edi, %edi
0x004ebb4a:	movl 0x20(%esi), %edi
0x004ebb4d:	movl 0x24(%esi), %edi
0x004ebb50:	movl 0x2c(%esi), %edi
0x004ebb53:	movl 0x30(%esi), %edi
0x004ebb56:	call 0x004e7117
0x004e7117:	pushl $0x4e7046<UINT32>
0x004e711c:	movl %ecx, $0x5869b4<UINT32>
0x004e7121:	call 0x004f44eb
0x004e7126:	testl %eax, %eax
0x004e7128:	jne 0x004e712f
0x004e712f:	ret

0x004ebb5b:	movl 0x34(%eax), %edi
0x004ebb5e:	movl 0x54(%eax), %edi
0x004ebb61:	addl %eax, $0x4c<UINT8>
0x004ebb64:	pushl %eax
0x004ebb65:	call GetCursorPos@USER32.dll
GetCursorPos@USER32.dll: API Node	
0x004ebb6b:	movl 0x40(%esi), %edi
0x004ebb6e:	movl 0x3c(%esi), %edi
0x004ebb71:	popl %edi
0x004ebb72:	movl 0x28(%esi), $0x1<UINT32>
0x004ebb79:	popl %esi
0x004ebb7a:	ret

0x004ebeb4:	movl %eax, %esi
0x004ebeb6:	call 0x004f9aba
0x004ebebb:	ret

0x004f3516:	xorl %edi, %edi
0x004f3518:	movl -4(%ebp), %edi
0x004f351b:	movl (%esi), $0x53a8ac<UINT32>
0x004f3521:	cmpl 0x8(%ebp), %edi
0x004f3524:	je 0x004f3534
0x004f3534:	movl 0x50(%esi), %edi
0x004f3537:	call 0x004e76e3
0x004f353c:	movl %ebx, %eax
0x004f353e:	cmpl %ebx, %edi
0x004f3540:	jne 0x004f3547
0x004f3547:	leal %ecx, 0x74(%ebx)
0x004f354a:	call 0x004e71d3
0x004e71d3:	pushl $0x4e70eb<UINT32>
0x004e71d8:	call 0x004f44eb
0x004f410c:	movl %eax, 0x10(%esi)
0x004f410f:	testb (%eax,%edi,8), $0x1<UINT8>
0x004f4113:	je 0x004f41d7
0x004e70eb:	pushl $0x54<UINT8>
0x004e70ed:	call 0x004f3f28
0x004e70f2:	testl %eax, %eax
0x004e70f4:	je 7
0x004e70f6:	movl %ecx, %eax
0x004e70f8:	jmp 0x004e70a1
0x004e70a1:	movl %eax, %ecx
0x004e70a3:	xorl %ecx, %ecx
0x004e70a5:	movl (%eax), $0x537e30<UINT32>
0x0051a886:	movl %edx, 0x8(%esp)
0x0051a88a:	leal %eax, 0xc(%edx)
0x0051a88d:	movl %ecx, -20(%edx)
0x0051a890:	xorl %ecx, %eax
0x0051a892:	call 0x004f7c80
0x0051a897:	movl %eax, $0x55f85c<UINT32>
0x0051a89c:	jmp 0x004f9689
0x004e70ab:	movl 0x8(%eax), %ecx
0x004e70ae:	movl 0xc(%eax), %ecx
0x004e70b1:	orl 0x44(%eax), $0xffffffff<UINT8>
0x004e70b5:	orl 0x4c(%eax), $0xffffffff<UINT8>
0x004e70b9:	movl 0x48(%eax), %ecx
0x004e70bc:	movl 0xc(%eax), $0x6c<UINT32>
0x004e70c3:	movl 0x28(%eax), $0x4e6cad<UINT32>
0x004e70ca:	ret

0x004f42ea:	movl %ecx, 0x8(%ebp)
0x004f42ed:	cmpl %ecx, 0x8(%esi)
0x004f42f0:	jl 193
0x004f42f6:	cmpl 0xc(%ebp), %ebx
0x004f42f9:	je 184
0x004f435f:	pushl $0x2<UINT8>
0x004f4361:	pushl $0x4<UINT8>
0x004f4363:	pushl 0xc(%edi)
0x004f4366:	call 0x004e8527
0x004f436b:	popl %ecx
0x004f436c:	popl %ecx
0x004f436d:	pushl %eax
0x004f436e:	pushl 0xc(%esi)
0x004f4371:	call LocalReAlloc@KERNEL32.DLL
LocalReAlloc@KERNEL32.DLL: API Node	
0x004e71dd:	testl %eax, %eax
0x004e71df:	jne 0x004e71e6
0x004e71e6:	ret

0x004f354f:	cmpl %eax, %edi
0x004f3551:	je -17
0x004f3553:	movl 0x4(%eax), %esi
0x004f3556:	call GetCurrentThread@KERNEL32.DLL
GetCurrentThread@KERNEL32.DLL: API Node	
0x004f355c:	movl 0x2c(%esi), %eax
0x004f355f:	call GetCurrentThreadId@KERNEL32.DLL
0x004f3565:	movl 0x30(%esi), %eax
0x004f3568:	movl 0x4(%ebx), %esi
0x004f356b:	xorl %eax, %eax
0x004f356d:	movw 0x92(%esi), %ax
0x004f3574:	movw 0x90(%esi), %ax
0x004f357b:	movl 0x44(%esi), %edi
0x004f357e:	movl 0x7c(%esi), %edi
0x004f3581:	movl 0x64(%esi), %edi
0x004f3584:	movl 0x68(%esi), %edi
0x004f3587:	movl 0x54(%esi), %edi
0x004f358a:	movl 0x60(%esi), %edi
0x004f358d:	movl 0x88(%esi), %edi
0x004f3593:	movl 0x58(%esi), %edi
0x004f3596:	movl 0x48(%esi), %edi
0x004f3599:	movl 0x8c(%esi), %edi
0x004f359f:	movl 0x80(%esi), %edi
0x004f35a5:	movl 0x84(%esi), %edi
0x004f35ab:	movl 0x70(%esi), %edi
0x004f35ae:	movl 0x74(%esi), %edi
0x004f35b1:	movl 0x94(%esi), %edi
0x004f35b7:	movl 0x9c(%esi), %edi
0x004f35bd:	movl 0x5c(%esi), %edi
0x004f35c0:	movl 0x6c(%esi), %edi
0x004f35c3:	movl 0x98(%esi), $0x200<UINT32>
0x004f35cd:	movl %eax, %esi
0x004f35cf:	call 0x004f9aba
0x004f35d4:	ret $0x4<UINT16>

0x004099dc:	movl 0x430(%esp), %edi
0x004099e3:	movl %eax, $0x53aa34<UINT32>
0x004099e8:	movl 0x5894e8, $0x540b3c<UINT32>
0x004099f2:	movl 0x589dfc, %edi
0x004099f8:	movl 0x589df8, %eax
0x004099fd:	movl 0x589e04, %edi
0x00409a03:	movl 0x589e00, %eax
0x00409a08:	movb %bl, $0x2<UINT8>
0x00409a0a:	pushl $0x840<UINT32>
0x00409a0f:	movb 0x434(%esp), %bl
0x00409a16:	call 0x004e6cc9
0x00409a1b:	addl %esp, $0x4<UINT8>
0x00409a1e:	movl 0x14(%esp), %eax
0x00409a22:	movb 0x430(%esp), $0x3<UINT8>
0x00409a2a:	cmpl %eax, %edi
0x00409a2c:	je 8
0x00409a2e:	pushl %eax
0x00409a2f:	call 0x004133e0
0x004133e0:	pushl $0xffffffff<UINT8>
0x004133e2:	pushl $0x51ac8e<UINT32>
0x004133e7:	movl %eax, %fs:0
0x004133ed:	pushl %eax
0x004133ee:	pushl %ecx
0x004133ef:	pushl %ebx
0x004133f0:	pushl %esi
0x004133f1:	movl %eax, 0x57d770
0x004133f6:	xorl %eax, %esp
0x004133f8:	pushl %eax
0x004133f9:	leal %eax, 0x10(%esp)
0x004133fd:	movl %fs:0, %eax
0x00413403:	movl %esi, 0x20(%esp)
0x00413407:	xorl %eax, %eax
0x00413409:	movw 0x4(%esi), %ax
0x0041340d:	xorl %ebx, %ebx
0x0041340f:	movl 0x18(%esp), %ebx
0x00413413:	pushl $0xd9c<UINT32>
0x00413418:	movl (%esi), $0x54ccfc<UINT32>
0x0041341e:	call 0x004e6cc9
0x00413423:	addl %esp, $0x4<UINT8>
0x00413426:	movl 0xc(%esp), %eax
0x0041342a:	movb 0x18(%esp), $0x1<UINT8>
0x0041342f:	cmpl %eax, %ebx
0x00413431:	je 9
0x00413433:	movl %ecx, %eax
0x00413435:	call 0x004385a6
0x004385a6:	pushl %ebp
0x004385a7:	leal %ebp, -392(%esp)
0x004385ae:	subl %esp, $0x208<UINT32>
0x004385b4:	movl %eax, 0x57d770
0x004385b9:	xorl %eax, %ebp
0x004385bb:	movl 0x184(%ebp), %eax
0x004385c1:	pushl %ebx
0x004385c2:	xorl %ebx, %ebx
0x004385c4:	pushl %esi
0x004385c5:	movl %esi, %ecx
0x004385c7:	pushl %edi
0x004385c8:	orl %edi, $0xffffffff<UINT8>
0x004385cb:	pushl $0x200<UINT32>
0x004385d0:	leal %eax, -124(%ebp)
0x004385d3:	pushl %eax
0x004385d4:	movl (%esi), $0x51f244<UINT32>
0x004385da:	movb 0x410(%esi), %bl
0x004385e0:	movb 0x610(%esi), %bl
0x004385e6:	movb 0x210(%esi), %bl
0x004385ec:	movb 0xa10(%esi), %bl
0x004385f2:	movb 0xb10(%esi), %bl
0x004385f8:	movb 0x810(%esi), %bl
0x004385fe:	movb 0x4(%esi), %bl
0x00438601:	movb 0xb78(%esi), %bl
0x00438607:	movl 0x204(%esi), %edi
0x0043860d:	movl 0xb6c(%esi), %ebx
0x00438613:	movl 0x208(%esi), %ebx
0x00438619:	movl 0x20c(%esi), %ebx
0x0043861f:	movl 0xb5c(%esi), %ebx
0x00438625:	movl 0xb60(%esi), %ebx
0x0043862b:	movl 0xb64(%esi), %ebx
0x00438631:	movl 0xd7c(%esi), %ebx
0x00438637:	movl 0xd80(%esi), $0x1<UINT32>
0x00438641:	movl 0xb50(%esi), %edi
0x00438647:	movl 0xb54(%esi), %edi
0x0043864d:	movl 0xb58(%esi), %edi
0x00438653:	movl 0xb68(%esi), %edi
0x00438659:	movl 0xd78(%esi), %edi
0x0043865f:	movl 0xd84(%esi), %edi
0x00438665:	movl 0xd88(%esi), %edi
0x0043866b:	movl 0xd8c(%esi), %edi
0x00438671:	movl 0xd90(%esi), %edi
0x00438677:	movl 0xb70(%esi), %ebx
0x0043867d:	movl 0xb74(%esi), %ebx
0x00438683:	movb -124(%ebp), %bl
0x00438686:	call GetSystemWindowsDirectoryA@KERNEL32.DLL
GetSystemWindowsDirectoryA@KERNEL32.DLL: API Node	
0x0043868c:	movl -128(%ebp), %eax
0x0043868f:	cmpl %eax, %ebx
0x00438691:	jbe 115
0x00438693:	pushl $0x51f238<UINT32>
0x00438698:	leal %eax, -124(%ebp)
0x0043869b:	pushl $0x200<UINT32>
0x004386a0:	pushl %eax
0x004386a1:	call 0x0045327b
0x0045327b:	pushl %ebp
0x0045327c:	movl %ebp, %esp
0x0045327e:	subl %esp, $0x204<UINT32>
0x00453284:	movl %eax, 0x57d770
0x00453289:	xorl %eax, %ebp
0x0045328b:	movl -4(%ebp), %eax
0x0045328e:	pushl %esi
0x0045328f:	movl %esi, 0x8(%ebp)
0x00453292:	leal %eax, 0x14(%ebp)
0x00453295:	pushl %eax
0x00453296:	pushl 0x10(%ebp)
0x00453299:	leal %eax, -260(%ebp)
0x0045329f:	pushl %eax
0x004532a0:	call 0x0040c500
0x0040c500:	movl %eax, 0xc(%esp)
0x0040c504:	movl %ecx, 0x8(%esp)
0x0040c508:	movl %edx, 0x4(%esp)
0x0040c50c:	pushl %eax
0x0040c50d:	pushl %ecx
0x0040c50e:	pushl $0x100<UINT32>
0x0040c513:	pushl %edx
0x0040c514:	call 0x004f8c56
0x004f8c56:	movl %edi, %edi
0x004f8c58:	pushl %ebp
0x004f8c59:	movl %ebp, %esp
0x004f8c5b:	pushl 0x14(%ebp)
0x004f8c5e:	pushl $0x0<UINT8>
0x004f8c60:	pushl 0x10(%ebp)
0x004f8c63:	pushl 0xc(%ebp)
0x004f8c66:	pushl 0x8(%ebp)
0x004f8c69:	call 0x004f8bce
0x004f8bce:	movl %edi, %edi
0x004f8bd0:	pushl %ebp
0x004f8bd1:	movl %ebp, %esp
0x004f8bd3:	pushl %ebx
0x004f8bd4:	xorl %ebx, %ebx
0x004f8bd6:	cmpl 0x10(%ebp), %ebx
0x004f8bd9:	jne 0x004f8bf8
0x004f8bf8:	pushl %esi
0x004f8bf9:	movl %esi, 0x8(%ebp)
0x004f8bfc:	cmpl %esi, %ebx
0x004f8bfe:	je 5
0x004f8c00:	cmpl 0xc(%ebp), %ebx
0x004f8c03:	ja 0x004f8c12
0x004f8c12:	pushl 0x18(%ebp)
0x004f8c15:	pushl 0x14(%ebp)
0x004f8c18:	pushl 0x10(%ebp)
0x004f8c1b:	pushl 0xc(%ebp)
0x004f8c1e:	pushl %esi
0x004f8c1f:	pushl $0x503f2a<UINT32>
0x004f8c24:	call 0x004f8b02
0x004f8b02:	movl %edi, %edi
0x004f8b04:	pushl %ebp
0x004f8b05:	movl %ebp, %esp
0x004f8b07:	subl %esp, $0x20<UINT8>
0x004f8b0a:	pushl %ebx
0x004f8b0b:	xorl %ebx, %ebx
0x004f8b0d:	cmpl 0x14(%ebp), %ebx
0x004f8b10:	jne 0x004f8b32
0x004f8b32:	pushl %esi
0x004f8b33:	movl %esi, 0xc(%ebp)
0x004f8b36:	pushl %edi
0x004f8b37:	movl %edi, 0x10(%ebp)
0x004f8b3a:	cmpl %edi, %ebx
0x004f8b3c:	je 33
0x004f8b3e:	cmpl %esi, %ebx
0x004f8b40:	jne 0x004f8b5f
0x004f8b5f:	movl %eax, $0x7fffffff<UINT32>
0x004f8b64:	movl -28(%ebp), %eax
0x004f8b67:	cmpl %edi, %eax
0x004f8b69:	ja 3
0x004f8b6b:	movl -28(%ebp), %edi
0x004f8b6e:	pushl 0x1c(%ebp)
0x004f8b71:	leal %eax, -32(%ebp)
0x004f8b74:	pushl 0x18(%ebp)
0x004f8b77:	movl -20(%ebp), $0x42<UINT32>
0x004f8b7e:	pushl 0x14(%ebp)
0x004f8b81:	movl -24(%ebp), %esi
0x004f8b84:	pushl %eax
0x004f8b85:	movl -32(%ebp), %esi
0x004f8b88:	call 0x00503f2a
0x00503f2a:	movl %edi, %edi
0x00503f2c:	pushl %ebp
0x00503f2d:	movl %ebp, %esp
0x00503f2f:	subl %esp, $0x278<UINT32>
0x00503f35:	movl %eax, 0x57d770
0x00503f3a:	xorl %eax, %ebp
0x00503f3c:	movl -4(%ebp), %eax
0x00503f3f:	pushl %ebx
0x00503f40:	movl %ebx, 0xc(%ebp)
0x00503f43:	pushl %esi
0x00503f44:	movl %esi, 0x8(%ebp)
0x00503f47:	xorl %eax, %eax
0x00503f49:	pushl %edi
0x00503f4a:	movl %edi, 0x14(%ebp)
0x00503f4d:	pushl 0x10(%ebp)
0x00503f50:	leal %ecx, -592(%ebp)
0x00503f56:	movl -608(%ebp), %esi
0x00503f5c:	movl -548(%ebp), %edi
0x00503f62:	movl -604(%ebp), %eax
0x00503f68:	movl -528(%ebp), %eax
0x00503f6e:	movl -564(%ebp), %eax
0x00503f74:	movl -536(%ebp), %eax
0x00503f7a:	movl -560(%ebp), %eax
0x00503f80:	movl -600(%ebp), %eax
0x00503f86:	movl -568(%ebp), %eax
0x00503f8c:	call 0x004fd9fd
0x00503f91:	testl %esi, %esi
0x00503f93:	jne 0x00503fca
0x00503fca:	testb 0xc(%esi), $0x40<UINT8>
0x00503fce:	jne 0x0050402e
0x0050402e:	xorl %eax, %eax
0x00504030:	cmpl %ebx, %eax
0x00504032:	je -163
0x00504038:	movb %dl, (%ebx)
0x0050403a:	movl -552(%ebp), %eax
0x00504040:	movl -544(%ebp), %eax
0x00504046:	movl -576(%ebp), %eax
0x0050404c:	movl -596(%ebp), %eax
0x00504052:	movb -529(%ebp), %dl
0x00504058:	testb %dl, %dl
0x0050405a:	je 2640
0x00504060:	incl %ebx
0x00504061:	xorl %eax, %eax
0x00504063:	cmpl -552(%ebp), %eax
0x00504069:	movl -572(%ebp), %ebx
0x0050406f:	jl 2579
0x00504075:	movb %cl, %dl
0x00504077:	subb %cl, $0x20<UINT8>
0x0050407a:	cmpb %cl, $0x58<UINT8>
0x0050407d:	ja 13
0x0050407f:	movsbl %eax, %dl
0x00504082:	movzbl %eax, 0x53bb70(%eax)
0x00504089:	andl %eax, $0xf<UINT8>
0x0050408c:	movl %ecx, -576(%ebp)
0x00504092:	imull %eax, %eax, $0x9<UINT8>
0x00504095:	movzbl %eax, 0x53bb90(%eax,%ecx)
0x0050409d:	pushl $0x8<UINT8>
0x0050409f:	shrl %eax, $0x4<UINT8>
0x005040a2:	popl %esi
0x005040a3:	movl -576(%ebp), %eax
0x005040a9:	cmpl %eax, %esi
0x005040ab:	je -284
0x005040b1:	pushl $0x7<UINT8>
0x005040b3:	popl %ecx
0x005040b4:	cmpl %eax, %ecx
0x005040b6:	ja 2477
0x005040bc:	jmp 0x005042c4
0x005042c4:	andl -568(%ebp), $0x0<UINT8>
0x005042cb:	leal %eax, -592(%ebp)
0x005042d1:	pushl %eax
0x005042d2:	movzbl %eax, %dl
0x005042d5:	pushl %eax
0x005042d6:	call 0x00509e8f
0x00509e8f:	movl %edi, %edi
0x00509e91:	pushl %ebp
0x00509e92:	movl %ebp, %esp
0x00509e94:	subl %esp, $0x10<UINT8>
0x00509e97:	pushl 0xc(%ebp)
0x00509e9a:	leal %ecx, -16(%ebp)
0x00509e9d:	call 0x004fd9fd
0x004fda73:	movl %ecx, (%eax)
0x004fda75:	movl (%esi), %ecx
0x004fda77:	movl %eax, 0x4(%eax)
0x004fda7a:	movl 0x4(%esi), %eax
0x00509ea2:	movzbl %eax, 0x8(%ebp)
0x00509ea6:	movl %ecx, -16(%ebp)
0x00509ea9:	movl %ecx, 0xc8(%ecx)
0x00509eaf:	movzwl %eax, (%ecx,%eax,2)
0x00509eb3:	andl %eax, $0x8000<UINT32>
0x00509eb8:	cmpb -4(%ebp), $0x0<UINT8>
0x00509ebc:	je 0x00509ec5
0x00509ec5:	leave
0x00509ec6:	ret

0x005042db:	popl %ecx
0x005042dc:	testl %eax, %eax
0x005042de:	movb %al, -529(%ebp)
0x005042e4:	popl %ecx
0x005042e5:	je 0x00504309
0x00504309:	movl %ecx, -608(%ebp)
0x0050430f:	leal %esi, -552(%ebp)
0x00504315:	call 0x005032ec
0x005032ec:	testb 0xc(%ecx), $0x40<UINT8>
0x005032f0:	je 6
0x005032f2:	cmpl 0x8(%ecx), $0x0<UINT8>
0x005032f6:	je 36
0x005032f8:	decl 0x4(%ecx)
0x005032fb:	js 11
0x005032fd:	movl %edx, (%ecx)
0x005032ff:	movb (%edx), %al
0x00503301:	incl (%ecx)
0x00503303:	movzbl %eax, %al
0x00503306:	jmp 0x00503314
0x00503314:	cmpl %eax, $0xffffffff<UINT8>
0x00503317:	jne 0x0050331c
0x0050331c:	incl (%esi)
0x0050331e:	ret

0x0050431a:	jmp 0x00504a69
0x00504a69:	movl %ebx, -572(%ebp)
0x00504a6f:	movb %al, (%ebx)
0x00504a71:	movb -529(%ebp), %al
0x00504a77:	testb %al, %al
0x00504a79:	je 0x00504a88
0x00504a7b:	movl %edi, -548(%ebp)
0x00504a81:	movb %dl, %al
0x00504a83:	jmp 0x00504060
0x00504a88:	xorl %esi, %esi
0x00504a8a:	cmpl -576(%ebp), %esi
0x00504a90:	je 0x00504ab0
0x00504ab0:	cmpb -580(%ebp), $0x0<UINT8>
0x00504ab7:	je 10
0x00504ab9:	movl %eax, -584(%ebp)
0x00504abf:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x00504ac3:	movl %eax, -552(%ebp)
0x00504ac9:	movl %ecx, -4(%ebp)
0x00504acc:	popl %edi
0x00504acd:	popl %esi
0x00504ace:	xorl %ecx, %ebp
0x00504ad0:	popl %ebx
0x00504ad1:	call 0x004f7c80
0x00504ad6:	leave
0x00504ad7:	ret

0x004f8b8b:	addl %esp, $0x10<UINT8>
0x004f8b8e:	movl 0x14(%ebp), %eax
0x004f8b91:	cmpl %esi, %ebx
0x004f8b93:	je 52
0x004f8b95:	cmpl %eax, %ebx
0x004f8b97:	jl 34
0x004f8b99:	decl -28(%ebp)
0x004f8b9c:	js 7
0x004f8b9e:	movl %eax, -32(%ebp)
0x004f8ba1:	movb (%eax), %bl
0x004f8ba3:	jmp 0x004f8bb6
0x004f8bb6:	movl %eax, 0x14(%ebp)
0x004f8bb9:	jmp 0x004f8bc9
0x004f8bc9:	popl %edi
0x004f8bca:	popl %esi
0x004f8bcb:	popl %ebx
0x004f8bcc:	leave
0x004f8bcd:	ret

0x004f8c29:	addl %esp, $0x18<UINT8>
0x004f8c2c:	cmpl %eax, %ebx
0x004f8c2e:	jnl 0x004f8c32
0x004f8c32:	cmpl %eax, $0xfffffffe<UINT8>
0x004f8c35:	jne 0x004f8c52
0x004f8c52:	popl %esi
0x004f8c53:	popl %ebx
0x004f8c54:	popl %ebp
0x004f8c55:	ret

0x004f8c6e:	addl %esp, $0x14<UINT8>
0x004f8c71:	popl %ebp
0x004f8c72:	ret

0x0040c519:	addl %esp, $0x10<UINT8>
0x0040c51c:	ret

0x004532a5:	leal %eax, -260(%ebp)
0x004532ab:	pushl %eax
0x004532ac:	leal %eax, -516(%ebp)
0x004532b2:	pushl $0x100<UINT32>
0x004532b7:	pushl %eax
0x004532b8:	call 0x004f919d
0x004f919d:	movl %edi, %edi
0x004f919f:	pushl %ebp
0x004f91a0:	movl %ebp, %esp
0x004f91a2:	leal %eax, 0x14(%ebp)
0x004f91a5:	pushl %eax
0x004f91a6:	pushl $0x0<UINT8>
0x004f91a8:	pushl 0x10(%ebp)
0x004f91ab:	pushl 0xc(%ebp)
0x004f91ae:	pushl 0x8(%ebp)
0x004f91b1:	call 0x004f8bce
0x004f91b6:	addl %esp, $0x14<UINT8>
0x004f91b9:	popl %ebp
0x004f91ba:	ret

0x004532bd:	leal %eax, -516(%ebp)
0x004532c3:	pushl %eax
0x004532c4:	pushl 0xc(%ebp)
0x004532c7:	pushl %esi
0x004532c8:	call 0x004f91bb
0x004f91bb:	movl %edi, %edi
0x004f91bd:	pushl %ebp
0x004f91be:	movl %ebp, %esp
0x004f91c0:	movl %eax, 0x8(%ebp)
0x004f91c3:	pushl %ebx
0x004f91c4:	xorl %ebx, %ebx
0x004f91c6:	pushl %esi
0x004f91c7:	pushl %edi
0x004f91c8:	cmpl %eax, %ebx
0x004f91ca:	je 7
0x004f91cc:	movl %edi, 0xc(%ebp)
0x004f91cf:	cmpl %edi, %ebx
0x004f91d1:	ja 0x004f91ee
0x004f91ee:	movl %esi, 0x10(%ebp)
0x004f91f1:	cmpl %esi, %ebx
0x004f91f3:	jne 0x004f91f9
0x004f91f9:	movl %edx, %eax
0x004f91fb:	cmpb (%edx), %bl
0x004f91fd:	je 0x004f9203
0x004f91ff:	incl %edx
0x004f9200:	decl %edi
0x004f9201:	jne 0x004f91fb
0x004f9203:	cmpl %edi, %ebx
0x004f9205:	je -18
0x004f9207:	movb %cl, (%esi)
0x004f9209:	movb (%edx), %cl
0x004f920b:	incl %edx
0x004f920c:	incl %esi
0x004f920d:	cmpb %cl, %bl
0x004f920f:	je 0x004f9214
0x004f9211:	decl %edi
0x004f9212:	jne 0x004f9207
0x004f9214:	cmpl %edi, %ebx
0x004f9216:	jne 0x004f9228
0x004f9228:	xorl %eax, %eax
0x004f922a:	popl %edi
0x004f922b:	popl %esi
0x004f922c:	popl %ebx
0x004f922d:	popl %ebp
0x004f922e:	ret

0x004532cd:	movl %ecx, -4(%ebp)
0x004532d0:	addl %esp, $0x24<UINT8>
0x004532d3:	xorl %ecx, %ebp
0x004532d5:	popl %esi
0x004532d6:	call 0x004f7c80
0x004532db:	leave
0x004532dc:	ret

0x004386a6:	addl %esp, $0xc<UINT8>
0x004386a9:	leal %eax, -124(%ebp)
0x004386ac:	pushl %eax
0x004386ad:	call GetFileAttributesA@KERNEL32.DLL
GetFileAttributesA@KERNEL32.DLL: API Node	
0x004386b3:	cmpl %eax, %edi
0x004386b5:	je 0x004386bb
0x004386bb:	movl -128(%ebp), %ebx
0x004386be:	cmpl -128(%ebp), %ebx
0x004386c1:	jbe 0x00438706
0x00438706:	movl %ecx, 0x184(%ebp)
0x0043870c:	popl %edi
0x0043870d:	movl %eax, %esi
0x0043870f:	popl %esi
0x00438710:	xorl %ecx, %ebp
0x00438712:	popl %ebx
0x00438713:	call 0x004f7c80
0x00438718:	addl %ebp, $0x188<UINT32>
0x0043871e:	leave
0x0043871f:	ret

0x0041343a:	jmp 0x0041343e
0x0041343e:	movb 0x18(%esp), %bl
0x00413442:	pushl $0x18<UINT8>
0x00413444:	movl 0x80c(%esi), %eax
0x0041344a:	call 0x004e6cc9
0x0041344f:	addl %esp, $0x4<UINT8>
0x00413452:	movl 0xc(%esp), %eax
0x00413456:	movb 0x18(%esp), $0x2<UINT8>
0x0041345b:	cmpl %eax, %ebx
0x0041345d:	je 9
0x0041345f:	movl %ecx, %eax
0x00413461:	call 0x004302ac
0x004302ac:	pushl $0x4<UINT8>
0x004302ae:	movl %eax, $0x51699d<UINT32>
0x004302b3:	call 0x004f99e2
0x004302b8:	movl %esi, %ecx
0x004302ba:	andl 0x4(%esi), $0x0<UINT8>
0x004302be:	pushl $0x9e04<UINT32>
0x004302c3:	movl (%esi), $0x51d85c<UINT32>
0x004302c9:	movl 0x10(%esi), $0x8<UINT32>
0x004302d0:	call 0x004e6cf8
0x004e6cf8:	movl %edi, %edi
0x004e6cfa:	pushl %ebp
0x004e6cfb:	movl %ebp, %esp
0x004e6cfd:	popl %ebp
0x004e6cfe:	jmp 0x004e6cc9
0x004302d5:	popl %ecx
0x004302d6:	movl -16(%ebp), %eax
0x004302d9:	andl -4(%ebp), $0x0<UINT8>
0x004302dd:	testl %eax, %eax
0x004302df:	je 32
0x004302e1:	pushl $0x40<UINT8>
0x004302e3:	popl %ecx
0x004302e4:	pushl $0x43012c<UINT32>
0x004302e9:	pushl $0x42fcaa<UINT32>
0x004302ee:	pushl %ecx
0x004302ef:	leal %edi, 0x4(%eax)
0x004302f2:	pushl $0x278<UINT32>
0x004302f7:	pushl %edi
0x004302f8:	movl (%eax), %ecx
0x004302fa:	call 0x004f8123
0x004f8123:	pushl $0x10<UINT8>
0x004f8125:	pushl $0x55fbe8<UINT32>
0x004f812a:	call 0x004fa434
0x004f812f:	xorl %eax, %eax
0x004f8131:	movl -32(%ebp), %eax
0x004f8134:	movl -4(%ebp), %eax
0x004f8137:	movl -28(%ebp), %eax
0x004f813a:	movl %eax, -28(%ebp)
0x004f813d:	cmpl %eax, 0x10(%ebp)
0x004f8140:	jnl 19
0x004f8142:	movl %esi, 0x8(%ebp)
0x004f8145:	movl %ecx, %esi
0x004f8147:	call 0x0042fcaa
0x0042fcaa:	flds 0x550068
0x0042fcb0:	pushl %ebx
0x0042fcb1:	pushl %ebp
0x0042fcb2:	xorl %ebx, %ebx
0x0042fcb4:	pushl %esi
0x0042fcb5:	movl %esi, %ecx
0x0042fcb7:	orl %ebp, $0xffffffff<UINT8>
0x0042fcba:	fsts 0x1e8(%esi)
0x0042fcc0:	pushl %edi
0x0042fcc1:	pushl $0x8<UINT8>
0x0042fcc3:	popl %ecx
0x0042fcc4:	xorl %eax, %eax
0x0042fcc6:	movl (%esi), $0x51d8b8<UINT32>
0x0042fccc:	movb 0x1c(%esi), %bl
0x0042fccf:	movb 0x7c(%esi), %bl
0x0042fcd2:	movb 0x17c(%esi), %bl
0x0042fcd8:	movb 0x1c4(%esi), %bl
0x0042fcde:	movb 0x3c(%esi), %bl
0x0042fce1:	movb 0x19c(%esi), %bl
0x0042fce7:	movl 0x18(%esi), %ebp
0x0042fcea:	movl 0x208(%esi), %ebx
0x0042fcf0:	movl 0x1bc(%esi), %ebx
0x0042fcf6:	movl 0x20c(%esi), %ebx
0x0042fcfc:	movl 0x210(%esi), %ebp
0x0042fd02:	movl 0x1ec(%esi), %ebp
0x0042fd08:	movl 0x1e4(%esi), %ebp
0x0042fd0e:	leal %edi, 0x5c(%esi)
0x0042fd11:	rep stosl %es:(%edi), %eax
0x0042fd13:	fsts 0x240(%esi)
0x0042fd19:	fsts 0x218(%esi)
0x0042fd1f:	fsts 0x21c(%esi)
0x0042fd25:	fsts 0x220(%esi)
0x0042fd2b:	fsts 0x224(%esi)
0x0042fd31:	pushl $0xc<UINT8>
0x0042fd33:	fsts 0x22c(%esi)
0x0042fd39:	movl 0x4(%esi), %ebx
0x0042fd3c:	fsts 0x230(%esi)
0x0042fd42:	movl 0xc(%esi), %ebx
0x0042fd45:	fstps 0x228(%esi)
0x0042fd4b:	movl 0x10(%esi), %ebx
0x0042fd4e:	movl 0x14(%esi), %ebp
0x0042fd51:	movl 0x238(%esi), %ebp
0x0042fd57:	movl 0x1f0(%esi), %ebp
0x0042fd5d:	movl 0x1f4(%esi), %ebp
0x0042fd63:	movl 0x1f8(%esi), %ebp
0x0042fd69:	movl 0x244(%esi), %ebp
0x0042fd6f:	call 0x004e6cc9
0x0042fd74:	popl %ecx
0x0042fd75:	cmpl %eax, %ebx
0x0042fd77:	je 9
0x0042fd79:	movl %ecx, %eax
0x0042fd7b:	call 0x0042fc6c
0x0042fc6c:	movl %eax, %ecx
0x0042fc6e:	andl 0x4(%eax), $0x0<UINT8>
0x0042fc72:	andl 0x8(%eax), $0x0<UINT8>
0x0042fc76:	movl (%eax), $0x51d8a0<UINT32>
0x0042fc7c:	ret

0x0042fd80:	jmp 0x0042fd84
0x0042fd84:	popl %edi
0x0042fd85:	movl 0x214(%esi), %eax
0x0042fd8b:	movl 0x1fc(%esi), %ebx
0x0042fd91:	movl 0x200(%esi), %ebp
0x0042fd97:	movl 0x204(%esi), %ebx
0x0042fd9d:	movl 0x1c0(%esi), %ebx
0x0042fda3:	movb 0x23c(%esi), %bl
0x0042fda9:	movb 0x23d(%esi), %bl
0x0042fdaf:	movl 0x248(%esi), %ebx
0x0042fdb5:	movl 0x24c(%esi), %ebx
0x0042fdbb:	movl 0x250(%esi), %ebx
0x0042fdc1:	movl 0x254(%esi), %ebx
0x0042fdc7:	movl 0x258(%esi), %ebx
0x0042fdcd:	movl 0x260(%esi), %ebx
0x0042fdd3:	movl 0x264(%esi), %ebx
0x0042fdd9:	movl 0x268(%esi), %ebx
0x0042fddf:	movl 0x270(%esi), %ebx
0x0042fde5:	movl 0x274(%esi), %ebx
0x0042fdeb:	movb 0x25c(%esi), $0xffffffff<UINT8>
0x0042fdf2:	movb 0x26c(%esi), $0xffffffff<UINT8>
0x0042fdf9:	movl %eax, %esi
0x0042fdfb:	popl %esi
0x0042fdfc:	popl %ebp
0x0042fdfd:	popl %ebx
0x0042fdfe:	ret

0x004f814a:	addl %esi, 0xc(%ebp)
0x004f814d:	movl 0x8(%ebp), %esi
0x004f8150:	incl -28(%ebp)
0x004f8153:	jmp 0x004f813a
