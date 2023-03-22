0x0061ef50:	pusha
0x0061ef51:	movl %esi, $0x567000<UINT32>
0x0061ef56:	leal %edi, -1466368(%esi)
0x0061ef5c:	pushl %edi
0x0061ef5d:	orl %ebp, $0xffffffff<UINT8>
0x0061ef60:	jmp 0x0061ef72
0x0061ef72:	movl %ebx, (%esi)
0x0061ef74:	subl %esi, $0xfffffffc<UINT8>
0x0061ef77:	adcl %ebx, %ebx
0x0061ef79:	jb 0x0061ef68
0x0061ef68:	movb %al, (%esi)
0x0061ef6a:	incl %esi
0x0061ef6b:	movb (%edi), %al
0x0061ef6d:	incl %edi
0x0061ef6e:	addl %ebx, %ebx
0x0061ef70:	jne 0x0061ef79
0x0061ef7b:	movl %eax, $0x1<UINT32>
0x0061ef80:	addl %ebx, %ebx
0x0061ef82:	jne 0x0061ef8b
0x0061ef8b:	adcl %eax, %eax
0x0061ef8d:	addl %ebx, %ebx
0x0061ef8f:	jae 0x0061ef9c
0x0061ef91:	jne 0x0061efbb
0x0061efbb:	xorl %ecx, %ecx
0x0061efbd:	subl %eax, $0x3<UINT8>
0x0061efc0:	jb 0x0061efd3
0x0061efd3:	addl %ebx, %ebx
0x0061efd5:	jne 0x0061efde
0x0061efde:	jb 0x0061efac
0x0061efac:	addl %ebx, %ebx
0x0061efae:	jne 0x0061efb7
0x0061efb7:	adcl %ecx, %ecx
0x0061efb9:	jmp 0x0061f00d
0x0061f00d:	cmpl %ebp, $0xfffffb00<UINT32>
0x0061f013:	adcl %ecx, $0x2<UINT8>
0x0061f016:	leal %edx, (%edi,%ebp)
0x0061f019:	cmpl %ebp, $0xfffffffc<UINT8>
0x0061f01c:	jbe 0x0061f02c
0x0061f01e:	movb %al, (%edx)
0x0061f020:	incl %edx
0x0061f021:	movb (%edi), %al
0x0061f023:	incl %edi
0x0061f024:	decl %ecx
0x0061f025:	jne 0x0061f01e
0x0061f027:	jmp 0x0061ef6e
0x0061efc2:	shll %eax, $0x8<UINT8>
0x0061efc5:	movb %al, (%esi)
0x0061efc7:	incl %esi
0x0061efc8:	xorl %eax, $0xffffffff<UINT8>
0x0061efcb:	je 0x0061f042
0x0061efcd:	sarl %eax
0x0061efcf:	movl %ebp, %eax
0x0061efd1:	jmp 0x0061efde
0x0061f02c:	movl %eax, (%edx)
0x0061f02e:	addl %edx, $0x4<UINT8>
0x0061f031:	movl (%edi), %eax
0x0061f033:	addl %edi, $0x4<UINT8>
0x0061f036:	subl %ecx, $0x4<UINT8>
0x0061f039:	ja 0x0061f02c
0x0061f03b:	addl %edi, %ecx
0x0061f03d:	jmp 0x0061ef6e
0x0061efb0:	movl %ebx, (%esi)
0x0061efb2:	subl %esi, $0xfffffffc<UINT8>
0x0061efb5:	adcl %ebx, %ebx
0x0061efe0:	incl %ecx
0x0061efe1:	addl %ebx, %ebx
0x0061efe3:	jne 0x0061efec
0x0061efec:	jb 0x0061efac
0x0061ef9c:	decl %eax
0x0061ef9d:	addl %ebx, %ebx
0x0061ef9f:	jne 0x0061efa8
0x0061efa8:	adcl %eax, %eax
0x0061efaa:	jmp 0x0061ef80
0x0061efee:	addl %ebx, %ebx
0x0061eff0:	jne 0x0061eff9
0x0061eff9:	adcl %ecx, %ecx
0x0061effb:	addl %ebx, %ebx
0x0061effd:	jae 0x0061efee
0x0061efff:	jne 0x0061f00a
0x0061f00a:	addl %ecx, $0x2<UINT8>
0x0061ef84:	movl %ebx, (%esi)
0x0061ef86:	subl %esi, $0xfffffffc<UINT8>
0x0061ef89:	adcl %ebx, %ebx
0x0061ef93:	movl %ebx, (%esi)
0x0061ef95:	subl %esi, $0xfffffffc<UINT8>
0x0061ef98:	adcl %ebx, %ebx
0x0061ef9a:	jb 0x0061efbb
0x0061efe5:	movl %ebx, (%esi)
0x0061efe7:	subl %esi, $0xfffffffc<UINT8>
0x0061efea:	adcl %ebx, %ebx
0x0061efd7:	movl %ebx, (%esi)
0x0061efd9:	subl %esi, $0xfffffffc<UINT8>
0x0061efdc:	adcl %ebx, %ebx
0x0061eff2:	movl %ebx, (%esi)
0x0061eff4:	subl %esi, $0xfffffffc<UINT8>
0x0061eff7:	adcl %ebx, %ebx
0x0061efa1:	movl %ebx, (%esi)
0x0061efa3:	subl %esi, $0xfffffffc<UINT8>
0x0061efa6:	adcl %ebx, %ebx
0x0061f001:	movl %ebx, (%esi)
0x0061f003:	subl %esi, $0xfffffffc<UINT8>
0x0061f006:	adcl %ebx, %ebx
0x0061f008:	jae 0x0061efee
0x0061f042:	popl %esi
0x0061f043:	movl %edi, %esi
0x0061f045:	movl %ecx, $0x3c72<UINT32>
0x0061f04a:	movb %al, (%edi)
0x0061f04c:	incl %edi
0x0061f04d:	subb %al, $0xffffffe8<UINT8>
0x0061f04f:	cmpb %al, $0x1<UINT8>
0x0061f051:	ja 0x0061f04a
0x0061f053:	cmpb (%edi), $0x12<UINT8>
0x0061f056:	jne 0x0061f04a
0x0061f058:	movl %eax, (%edi)
0x0061f05a:	movb %bl, 0x4(%edi)
0x0061f05d:	shrw %ax, $0x8<UINT8>
0x0061f061:	roll %eax, $0x10<UINT8>
0x0061f064:	xchgb %ah, %al
0x0061f066:	subl %eax, %edi
0x0061f068:	subb %bl, $0xffffffe8<UINT8>
0x0061f06b:	addl %eax, %esi
0x0061f06d:	movl (%edi), %eax
0x0061f06f:	addl %edi, $0x5<UINT8>
0x0061f072:	movb %al, %bl
0x0061f074:	loop 0x0061f04f
0x0061f076:	leal %edi, 0x216000(%esi)
0x0061f07c:	movl %eax, (%edi)
0x0061f07e:	orl %eax, %eax
0x0061f080:	je 0x0061f0c7
0x0061f082:	movl %ebx, 0x4(%edi)
0x0061f085:	leal %eax, 0x226b44(%eax,%esi)
0x0061f08c:	addl %ebx, %esi
0x0061f08e:	pushl %eax
0x0061f08f:	addl %edi, $0x8<UINT8>
0x0061f092:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x0061f098:	xchgl %ebp, %eax
0x0061f099:	movb %al, (%edi)
0x0061f09b:	incl %edi
0x0061f09c:	orb %al, %al
0x0061f09e:	je 0x0061f07c
0x0061f0a0:	movl %ecx, %edi
0x0061f0a2:	jns 0x0061f0ab
0x0061f0ab:	pushl %edi
0x0061f0ac:	decl %eax
0x0061f0ad:	repn scasb %al, %es:(%edi)
0x0061f0af:	pushl %ebp
0x0061f0b0:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0061f0b6:	orl %eax, %eax
0x0061f0b8:	je 7
0x0061f0ba:	movl (%ebx), %eax
0x0061f0bc:	addl %ebx, $0x4<UINT8>
0x0061f0bf:	jmp 0x0061f099
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x0061f0a4:	movzwl %eax, (%edi)
0x0061f0a7:	incl %edi
0x0061f0a8:	pushl %eax
0x0061f0a9:	incl %edi
0x0061f0aa:	movl %ecx, $0xaef24857<UINT32>
0x0061f0c7:	addl %edi, $0x4<UINT8>
0x0061f0ca:	leal %ebx, -4(%esi)
0x0061f0cd:	xorl %eax, %eax
0x0061f0cf:	movb %al, (%edi)
0x0061f0d1:	incl %edi
0x0061f0d2:	orl %eax, %eax
0x0061f0d4:	je 0x0061f0f8
0x0061f0d6:	cmpb %al, $0xffffffef<UINT8>
0x0061f0d8:	ja 0x0061f0eb
0x0061f0da:	addl %ebx, %eax
0x0061f0dc:	movl %eax, (%ebx)
0x0061f0de:	xchgb %ah, %al
0x0061f0e0:	roll %eax, $0x10<UINT8>
0x0061f0e3:	xchgb %ah, %al
0x0061f0e5:	addl %eax, %esi
0x0061f0e7:	movl (%ebx), %eax
0x0061f0e9:	jmp 0x0061f0cd
0x0061f0eb:	andb %al, $0xf<UINT8>
0x0061f0ed:	shll %eax, $0x10<UINT8>
0x0061f0f0:	movw %ax, (%edi)
0x0061f0f3:	addl %edi, $0x2<UINT8>
0x0061f0f6:	jmp 0x0061f0da
0x0061f0f8:	movl %ebp, 0x226c90(%esi)
0x0061f0fe:	leal %edi, -4096(%esi)
0x0061f104:	movl %ebx, $0x1000<UINT32>
0x0061f109:	pushl %eax
0x0061f10a:	pushl %esp
0x0061f10b:	pushl $0x4<UINT8>
0x0061f10d:	pushl %ebx
0x0061f10e:	pushl %edi
0x0061f10f:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0061f111:	leal %eax, 0x237(%edi)
0x0061f117:	andb (%eax), $0x7f<UINT8>
0x0061f11a:	andb 0x28(%eax), $0x7f<UINT8>
0x0061f11e:	popl %eax
0x0061f11f:	pushl %eax
0x0061f120:	pushl %esp
0x0061f121:	pushl %eax
0x0061f122:	pushl %ebx
0x0061f123:	pushl %edi
0x0061f124:	call VirtualProtect@kernel32.dll
0x0061f126:	popl %eax
0x0061f127:	popa
0x0061f128:	leal %eax, -128(%esp)
0x0061f12c:	pushl $0x0<UINT8>
0x0061f12e:	cmpl %esp, %eax
0x0061f130:	jne 0x0061f12c
0x0061f132:	subl %esp, $0xffffff80<UINT8>
0x0061f135:	jmp 0x004755cb
0x004755cb:	call 0x00480584
0x00480584:	pushl %ebp
0x00480585:	movl %ebp, %esp
0x00480587:	subl %esp, $0x14<UINT8>
0x0048058a:	andl -12(%ebp), $0x0<UINT8>
0x0048058e:	andl -8(%ebp), $0x0<UINT8>
0x00480592:	movl %eax, 0x4bc1dc
0x00480597:	pushl %esi
0x00480598:	pushl %edi
0x00480599:	movl %edi, $0xbb40e64e<UINT32>
0x0048059e:	movl %esi, $0xffff0000<UINT32>
0x004805a3:	cmpl %eax, %edi
0x004805a5:	je 0x004805b4
0x004805b4:	leal %eax, -12(%ebp)
0x004805b7:	pushl %eax
0x004805b8:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x004805be:	movl %eax, -8(%ebp)
0x004805c1:	xorl %eax, -12(%ebp)
0x004805c4:	movl -4(%ebp), %eax
0x004805c7:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x004805cd:	xorl -4(%ebp), %eax
0x004805d0:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x004805d6:	xorl -4(%ebp), %eax
0x004805d9:	leal %eax, -20(%ebp)
0x004805dc:	pushl %eax
0x004805dd:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x004805e3:	movl %ecx, -16(%ebp)
0x004805e6:	leal %eax, -4(%ebp)
0x004805e9:	xorl %ecx, -20(%ebp)
0x004805ec:	xorl %ecx, -4(%ebp)
0x004805ef:	xorl %ecx, %eax
0x004805f1:	cmpl %ecx, %edi
0x004805f3:	jne 0x004805fc
0x004805fc:	testl %esi, %ecx
0x004805fe:	jne 0x0048060c
0x0048060c:	movl 0x4bc1dc, %ecx
0x00480612:	notl %ecx
0x00480614:	movl 0x4bc1e0, %ecx
0x0048061a:	popl %edi
0x0048061b:	popl %esi
0x0048061c:	movl %esp, %ebp
0x0048061e:	popl %ebp
0x0048061f:	ret

0x004755d0:	jmp 0x00475454
0x00475454:	pushl $0x14<UINT8>
0x00475456:	pushl $0x4b9278<UINT32>
0x0047545b:	call 0x004795f0
0x004795f0:	pushl $0x4752c0<UINT32>
0x004795f5:	pushl %fs:0
0x004795fc:	movl %eax, 0x10(%esp)
0x00479600:	movl 0x10(%esp), %ebp
0x00479604:	leal %ebp, 0x10(%esp)
0x00479608:	subl %esp, %eax
0x0047960a:	pushl %ebx
0x0047960b:	pushl %esi
0x0047960c:	pushl %edi
0x0047960d:	movl %eax, 0x4bc1dc
0x00479612:	xorl -4(%ebp), %eax
0x00479615:	xorl %eax, %ebp
0x00479617:	pushl %eax
0x00479618:	movl -24(%ebp), %esp
0x0047961b:	pushl -8(%ebp)
0x0047961e:	movl %eax, -4(%ebp)
0x00479621:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00479628:	movl -8(%ebp), %eax
0x0047962b:	leal %eax, -16(%ebp)
0x0047962e:	movl %fs:0, %eax
0x00479634:	ret

0x00475460:	call 0x00479a5a
0x00479a5a:	pushl %ebp
0x00479a5b:	movl %ebp, %esp
0x00479a5d:	subl %esp, $0x44<UINT8>
0x00479a60:	leal %eax, -68(%ebp)
0x00479a63:	pushl %eax
0x00479a64:	call GetStartupInfoW@KERNEL32.DLL
GetStartupInfoW@KERNEL32.DLL: API Node	
0x00479a6a:	testb -24(%ebp), $0x1<UINT8>
0x00479a6e:	je 0x00479a76
0x00479a76:	pushl $0xa<UINT8>
0x00479a78:	popl %eax
0x00479a79:	movl %esp, %ebp
0x00479a7b:	popl %ebp
0x00479a7c:	ret

0x00475465:	movzwl %esi, %ax
0x00475468:	pushl $0x2<UINT8>
0x0047546a:	call 0x00480537
0x00480537:	pushl %ebp
0x00480538:	movl %ebp, %esp
0x0048053a:	movl %eax, 0x8(%ebp)
0x0048053d:	movl 0x4c3cd8, %eax
0x00480542:	popl %ebp
0x00480543:	ret

0x0047546f:	popl %ecx
0x00475470:	movl %eax, $0x5a4d<UINT32>
0x00475475:	cmpw 0x400000, %ax
0x0047547c:	je 0x00475482
0x00475482:	movl %eax, 0x40003c
0x00475487:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00475491:	jne -21
0x00475493:	movl %ecx, $0x10b<UINT32>
0x00475498:	cmpw 0x400018(%eax), %cx
0x0047549f:	jne -35
0x004754a1:	xorl %ebx, %ebx
0x004754a3:	cmpl 0x400074(%eax), $0xe<UINT8>
0x004754aa:	jbe 9
0x004754ac:	cmpl 0x4000e8(%eax), %ebx
0x004754b2:	setne %bl
0x004754b5:	movl -28(%ebp), %ebx
0x004754b8:	call 0x0047a442
0x0047a442:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x0047a448:	xorl %ecx, %ecx
0x0047a44a:	movl 0x4c4328, %eax
0x0047a44f:	testl %eax, %eax
0x0047a451:	setne %cl
0x0047a454:	movl %eax, %ecx
0x0047a456:	ret

0x004754bd:	testl %eax, %eax
0x004754bf:	jne 0x004754c9
0x004754c9:	call 0x00476a2e
0x00476a2e:	call 0x00471927
0x00471927:	pushl %esi
0x00471928:	pushl $0x0<UINT8>
0x0047192a:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00471930:	movl %esi, %eax
0x00471932:	pushl %esi
0x00471933:	call 0x00473397
0x00473397:	pushl %ebp
0x00473398:	movl %ebp, %esp
0x0047339a:	movl %eax, 0x8(%ebp)
0x0047339d:	movl 0x4c3804, %eax
0x004733a2:	popl %ebp
0x004733a3:	ret

0x00471938:	pushl %esi
0x00471939:	call 0x00475a14
0x00475a14:	pushl %ebp
0x00475a15:	movl %ebp, %esp
0x00475a17:	movl %eax, 0x8(%ebp)
0x00475a1a:	movl 0x4c3b40, %eax
0x00475a1f:	popl %ebp
0x00475a20:	ret

0x0047193e:	pushl %esi
0x0047193f:	call 0x00479487
0x00479487:	pushl %ebp
0x00479488:	movl %ebp, %esp
0x0047948a:	movl %eax, 0x8(%ebp)
0x0047948d:	movl 0x4c3b74, %eax
0x00479492:	popl %ebp
0x00479493:	ret

0x00471944:	pushl %esi
0x00471945:	call 0x0047a14d
0x0047a14d:	pushl %ebp
0x0047a14e:	movl %ebp, %esp
0x0047a150:	movl %eax, 0x8(%ebp)
0x0047a153:	movl 0x4c4308, %eax
0x0047a158:	movl 0x4c430c, %eax
0x0047a15d:	movl 0x4c4310, %eax
0x0047a162:	movl 0x4c4314, %eax
0x0047a167:	popl %ebp
0x0047a168:	ret

0x0047194a:	pushl %esi
0x0047194b:	call 0x0047864b
0x0047864b:	pushl $0x478604<UINT32>
0x00478650:	call EncodePointer@KERNEL32.DLL
0x00478656:	movl 0x4c3b6c, %eax
0x0047865b:	ret

0x00471950:	pushl %esi
0x00471951:	call 0x0047a35e
0x0047a35e:	pushl %ebp
0x0047a35f:	movl %ebp, %esp
0x0047a361:	movl %eax, 0x8(%ebp)
0x0047a364:	movl 0x4c431c, %eax
0x0047a369:	popl %ebp
0x0047a36a:	ret

0x00471956:	addl %esp, $0x18<UINT8>
0x00471959:	popl %esi
0x0047195a:	jmp 0x00479aeb
0x00479aeb:	pushl %esi
0x00479aec:	pushl %edi
0x00479aed:	pushl $0x49d59c<UINT32>
0x00479af2:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00479af8:	movl %esi, 0x490358
0x00479afe:	movl %edi, %eax
0x00479b00:	pushl $0x4ac1f0<UINT32>
0x00479b05:	pushl %edi
0x00479b06:	call GetProcAddress@KERNEL32.DLL
0x00479b08:	xorl %eax, 0x4bc1dc
0x00479b0e:	pushl $0x4ac1fc<UINT32>
0x00479b13:	pushl %edi
0x00479b14:	movl 0x4c56e0, %eax
0x00479b19:	call GetProcAddress@KERNEL32.DLL
0x00479b1b:	xorl %eax, 0x4bc1dc
0x00479b21:	pushl $0x4ac204<UINT32>
0x00479b26:	pushl %edi
0x00479b27:	movl 0x4c56e4, %eax
0x00479b2c:	call GetProcAddress@KERNEL32.DLL
0x00479b2e:	xorl %eax, 0x4bc1dc
0x00479b34:	pushl $0x4ac210<UINT32>
0x00479b39:	pushl %edi
0x00479b3a:	movl 0x4c56e8, %eax
0x00479b3f:	call GetProcAddress@KERNEL32.DLL
0x00479b41:	xorl %eax, 0x4bc1dc
0x00479b47:	pushl $0x4ac21c<UINT32>
0x00479b4c:	pushl %edi
0x00479b4d:	movl 0x4c56ec, %eax
0x00479b52:	call GetProcAddress@KERNEL32.DLL
0x00479b54:	xorl %eax, 0x4bc1dc
0x00479b5a:	pushl $0x4ac238<UINT32>
0x00479b5f:	pushl %edi
0x00479b60:	movl 0x4c56f0, %eax
0x00479b65:	call GetProcAddress@KERNEL32.DLL
0x00479b67:	xorl %eax, 0x4bc1dc
0x00479b6d:	pushl $0x4ac248<UINT32>
0x00479b72:	pushl %edi
0x00479b73:	movl 0x4c56f4, %eax
0x00479b78:	call GetProcAddress@KERNEL32.DLL
0x00479b7a:	xorl %eax, 0x4bc1dc
0x00479b80:	pushl $0x4ac25c<UINT32>
0x00479b85:	pushl %edi
0x00479b86:	movl 0x4c56f8, %eax
0x00479b8b:	call GetProcAddress@KERNEL32.DLL
0x00479b8d:	xorl %eax, 0x4bc1dc
0x00479b93:	pushl $0x4ac274<UINT32>
0x00479b98:	pushl %edi
0x00479b99:	movl 0x4c56fc, %eax
0x00479b9e:	call GetProcAddress@KERNEL32.DLL
0x00479ba0:	xorl %eax, 0x4bc1dc
0x00479ba6:	pushl $0x4ac28c<UINT32>
0x00479bab:	pushl %edi
0x00479bac:	movl 0x4c5700, %eax
0x00479bb1:	call GetProcAddress@KERNEL32.DLL
0x00479bb3:	xorl %eax, 0x4bc1dc
0x00479bb9:	pushl $0x4ac2a0<UINT32>
0x00479bbe:	pushl %edi
0x00479bbf:	movl 0x4c5704, %eax
0x00479bc4:	call GetProcAddress@KERNEL32.DLL
0x00479bc6:	xorl %eax, 0x4bc1dc
0x00479bcc:	pushl $0x4ac2c0<UINT32>
0x00479bd1:	pushl %edi
0x00479bd2:	movl 0x4c5708, %eax
0x00479bd7:	call GetProcAddress@KERNEL32.DLL
0x00479bd9:	xorl %eax, 0x4bc1dc
0x00479bdf:	pushl $0x4ac2d8<UINT32>
0x00479be4:	pushl %edi
0x00479be5:	movl 0x4c570c, %eax
0x00479bea:	call GetProcAddress@KERNEL32.DLL
0x00479bec:	xorl %eax, 0x4bc1dc
0x00479bf2:	pushl $0x4ac2f0<UINT32>
0x00479bf7:	pushl %edi
0x00479bf8:	movl 0x4c5710, %eax
0x00479bfd:	call GetProcAddress@KERNEL32.DLL
0x00479bff:	xorl %eax, 0x4bc1dc
0x00479c05:	pushl $0x4ac304<UINT32>
0x00479c0a:	pushl %edi
0x00479c0b:	movl 0x4c5714, %eax
0x00479c10:	call GetProcAddress@KERNEL32.DLL
0x00479c12:	xorl %eax, 0x4bc1dc
0x00479c18:	movl 0x4c5718, %eax
0x00479c1d:	pushl $0x4ac318<UINT32>
0x00479c22:	pushl %edi
0x00479c23:	call GetProcAddress@KERNEL32.DLL
0x00479c25:	xorl %eax, 0x4bc1dc
0x00479c2b:	pushl $0x4ac334<UINT32>
0x00479c30:	pushl %edi
0x00479c31:	movl 0x4c571c, %eax
0x00479c36:	call GetProcAddress@KERNEL32.DLL
0x00479c38:	xorl %eax, 0x4bc1dc
0x00479c3e:	pushl $0x4ac354<UINT32>
0x00479c43:	pushl %edi
0x00479c44:	movl 0x4c5720, %eax
0x00479c49:	call GetProcAddress@KERNEL32.DLL
0x00479c4b:	xorl %eax, 0x4bc1dc
0x00479c51:	pushl $0x4ac370<UINT32>
0x00479c56:	pushl %edi
0x00479c57:	movl 0x4c5724, %eax
0x00479c5c:	call GetProcAddress@KERNEL32.DLL
0x00479c5e:	xorl %eax, 0x4bc1dc
0x00479c64:	pushl $0x4ac390<UINT32>
0x00479c69:	pushl %edi
0x00479c6a:	movl 0x4c5728, %eax
0x00479c6f:	call GetProcAddress@KERNEL32.DLL
0x00479c71:	xorl %eax, 0x4bc1dc
0x00479c77:	pushl $0x4ac3a4<UINT32>
0x00479c7c:	pushl %edi
0x00479c7d:	movl 0x4c572c, %eax
0x00479c82:	call GetProcAddress@KERNEL32.DLL
0x00479c84:	xorl %eax, 0x4bc1dc
0x00479c8a:	pushl $0x4ac3c0<UINT32>
0x00479c8f:	pushl %edi
0x00479c90:	movl 0x4c5730, %eax
0x00479c95:	call GetProcAddress@KERNEL32.DLL
0x00479c97:	xorl %eax, 0x4bc1dc
0x00479c9d:	pushl $0x4ac3d4<UINT32>
0x00479ca2:	pushl %edi
0x00479ca3:	movl 0x4c5738, %eax
0x00479ca8:	call GetProcAddress@KERNEL32.DLL
0x00479caa:	xorl %eax, 0x4bc1dc
0x00479cb0:	pushl $0x4ac3e4<UINT32>
0x00479cb5:	pushl %edi
0x00479cb6:	movl 0x4c5734, %eax
0x00479cbb:	call GetProcAddress@KERNEL32.DLL
0x00479cbd:	xorl %eax, 0x4bc1dc
0x00479cc3:	pushl $0x4ac3f4<UINT32>
0x00479cc8:	pushl %edi
0x00479cc9:	movl 0x4c573c, %eax
0x00479cce:	call GetProcAddress@KERNEL32.DLL
0x00479cd0:	xorl %eax, 0x4bc1dc
0x00479cd6:	pushl $0x4ac404<UINT32>
0x00479cdb:	pushl %edi
0x00479cdc:	movl 0x4c5740, %eax
0x00479ce1:	call GetProcAddress@KERNEL32.DLL
0x00479ce3:	xorl %eax, 0x4bc1dc
0x00479ce9:	pushl $0x4ac414<UINT32>
0x00479cee:	pushl %edi
0x00479cef:	movl 0x4c5744, %eax
0x00479cf4:	call GetProcAddress@KERNEL32.DLL
0x00479cf6:	xorl %eax, 0x4bc1dc
0x00479cfc:	pushl $0x4ac430<UINT32>
0x00479d01:	pushl %edi
0x00479d02:	movl 0x4c5748, %eax
0x00479d07:	call GetProcAddress@KERNEL32.DLL
0x00479d09:	xorl %eax, 0x4bc1dc
0x00479d0f:	pushl $0x4ac444<UINT32>
0x00479d14:	pushl %edi
0x00479d15:	movl 0x4c574c, %eax
0x00479d1a:	call GetProcAddress@KERNEL32.DLL
0x00479d1c:	xorl %eax, 0x4bc1dc
0x00479d22:	pushl $0x4ac454<UINT32>
0x00479d27:	pushl %edi
0x00479d28:	movl 0x4c5750, %eax
0x00479d2d:	call GetProcAddress@KERNEL32.DLL
0x00479d2f:	xorl %eax, 0x4bc1dc
0x00479d35:	pushl $0x4ac468<UINT32>
0x00479d3a:	pushl %edi
0x00479d3b:	movl 0x4c5754, %eax
0x00479d40:	call GetProcAddress@KERNEL32.DLL
0x00479d42:	xorl %eax, 0x4bc1dc
0x00479d48:	movl 0x4c5758, %eax
0x00479d4d:	pushl $0x4ac478<UINT32>
0x00479d52:	pushl %edi
0x00479d53:	call GetProcAddress@KERNEL32.DLL
0x00479d55:	xorl %eax, 0x4bc1dc
0x00479d5b:	pushl $0x4ac498<UINT32>
0x00479d60:	pushl %edi
0x00479d61:	movl 0x4c575c, %eax
0x00479d66:	call GetProcAddress@KERNEL32.DLL
0x00479d68:	xorl %eax, 0x4bc1dc
0x00479d6e:	popl %edi
0x00479d6f:	movl 0x4c5760, %eax
0x00479d74:	popl %esi
0x00479d75:	ret

0x00476a33:	call 0x0047998e
0x0047998e:	pushl %esi
0x0047998f:	pushl %edi
0x00479990:	movl %esi, $0x4bcb00<UINT32>
0x00479995:	movl %edi, $0x4c3b88<UINT32>
0x0047999a:	cmpl 0x4(%esi), $0x1<UINT8>
0x0047999e:	jne 22
0x004799a0:	pushl $0x0<UINT8>
0x004799a2:	movl (%esi), %edi
0x004799a4:	addl %edi, $0x18<UINT8>
0x004799a7:	pushl $0xfa0<UINT32>
0x004799ac:	pushl (%esi)
0x004799ae:	call 0x00479a7d
0x00479a7d:	pushl %ebp
0x00479a7e:	movl %ebp, %esp
0x00479a80:	movl %eax, 0x4c56f0
0x00479a85:	xorl %eax, 0x4bc1dc
0x00479a8b:	je 13
0x00479a8d:	pushl 0x10(%ebp)
0x00479a90:	pushl 0xc(%ebp)
0x00479a93:	pushl 0x8(%ebp)
0x00479a96:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x00479a98:	popl %ebp
0x00479a99:	ret

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
