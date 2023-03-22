0x004229a0:	pusha
0x004229a1:	movl %esi, $0x417000<UINT32>
0x004229a6:	leal %edi, -90112(%esi)
0x004229ac:	pushl %edi
0x004229ad:	jmp 0x004229ba
0x004229ba:	movl %ebx, (%esi)
0x004229bc:	subl %esi, $0xfffffffc<UINT8>
0x004229bf:	adcl %ebx, %ebx
0x004229c1:	jb 0x004229b0
0x004229b0:	movb %al, (%esi)
0x004229b2:	incl %esi
0x004229b3:	movb (%edi), %al
0x004229b5:	incl %edi
0x004229b6:	addl %ebx, %ebx
0x004229b8:	jne 0x004229c1
0x004229c3:	movl %eax, $0x1<UINT32>
0x004229c8:	addl %ebx, %ebx
0x004229ca:	jne 0x004229d3
0x004229d3:	adcl %eax, %eax
0x004229d5:	addl %ebx, %ebx
0x004229d7:	jae 0x004229c8
0x004229d9:	jne 0x004229e4
0x004229e4:	xorl %ecx, %ecx
0x004229e6:	subl %eax, $0x3<UINT8>
0x004229e9:	jb 0x004229f8
0x004229eb:	shll %eax, $0x8<UINT8>
0x004229ee:	movb %al, (%esi)
0x004229f0:	incl %esi
0x004229f1:	xorl %eax, $0xffffffff<UINT8>
0x004229f4:	je 0x00422a6a
0x004229f6:	movl %ebp, %eax
0x004229f8:	addl %ebx, %ebx
0x004229fa:	jne 0x00422a03
0x00422a03:	adcl %ecx, %ecx
0x00422a05:	addl %ebx, %ebx
0x00422a07:	jne 0x00422a10
0x00422a10:	adcl %ecx, %ecx
0x00422a12:	jne 0x00422a34
0x00422a34:	cmpl %ebp, $0xfffff300<UINT32>
0x00422a3a:	adcl %ecx, $0x1<UINT8>
0x00422a3d:	leal %edx, (%edi,%ebp)
0x00422a40:	cmpl %ebp, $0xfffffffc<UINT8>
0x00422a43:	jbe 0x00422a54
0x00422a54:	movl %eax, (%edx)
0x00422a56:	addl %edx, $0x4<UINT8>
0x00422a59:	movl (%edi), %eax
0x00422a5b:	addl %edi, $0x4<UINT8>
0x00422a5e:	subl %ecx, $0x4<UINT8>
0x00422a61:	ja 0x00422a54
0x00422a63:	addl %edi, %ecx
0x00422a65:	jmp 0x004229b6
0x00422a45:	movb %al, (%edx)
0x00422a47:	incl %edx
0x00422a48:	movb (%edi), %al
0x00422a4a:	incl %edi
0x00422a4b:	decl %ecx
0x00422a4c:	jne 0x00422a45
0x00422a4e:	jmp 0x004229b6
0x004229fc:	movl %ebx, (%esi)
0x004229fe:	subl %esi, $0xfffffffc<UINT8>
0x00422a01:	adcl %ebx, %ebx
0x00422a09:	movl %ebx, (%esi)
0x00422a0b:	subl %esi, $0xfffffffc<UINT8>
0x00422a0e:	adcl %ebx, %ebx
0x004229cc:	movl %ebx, (%esi)
0x004229ce:	subl %esi, $0xfffffffc<UINT8>
0x004229d1:	adcl %ebx, %ebx
0x00422a14:	incl %ecx
0x00422a15:	addl %ebx, %ebx
0x00422a17:	jne 0x00422a20
0x00422a19:	movl %ebx, (%esi)
0x00422a1b:	subl %esi, $0xfffffffc<UINT8>
0x00422a1e:	adcl %ebx, %ebx
0x00422a20:	adcl %ecx, %ecx
0x00422a22:	addl %ebx, %ebx
0x00422a24:	jae 0x00422a15
0x00422a26:	jne 0x00422a31
0x00422a31:	addl %ecx, $0x2<UINT8>
0x00422a28:	movl %ebx, (%esi)
0x00422a2a:	subl %esi, $0xfffffffc<UINT8>
0x00422a2d:	adcl %ebx, %ebx
0x00422a2f:	jae 0x00422a15
0x004229db:	movl %ebx, (%esi)
0x004229dd:	subl %esi, $0xfffffffc<UINT8>
0x004229e0:	adcl %ebx, %ebx
0x004229e2:	jae 0x004229c8
0x00422a6a:	popl %esi
0x00422a6b:	movl %edi, %esi
0x00422a6d:	movl %ecx, $0x4f1<UINT32>
0x00422a72:	movb %al, (%edi)
0x00422a74:	incl %edi
0x00422a75:	subb %al, $0xffffffe8<UINT8>
0x00422a77:	cmpb %al, $0x1<UINT8>
0x00422a79:	ja 0x00422a72
0x00422a7b:	cmpb (%edi), $0x5<UINT8>
0x00422a7e:	jne 0x00422a72
0x00422a80:	movl %eax, (%edi)
0x00422a82:	movb %bl, 0x4(%edi)
0x00422a85:	shrw %ax, $0x8<UINT8>
0x00422a89:	roll %eax, $0x10<UINT8>
0x00422a8c:	xchgb %ah, %al
0x00422a8e:	subl %eax, %edi
0x00422a90:	subb %bl, $0xffffffe8<UINT8>
0x00422a93:	addl %eax, %esi
0x00422a95:	movl (%edi), %eax
0x00422a97:	addl %edi, $0x5<UINT8>
0x00422a9a:	movb %al, %bl
0x00422a9c:	loop 0x00422a77
0x00422a9e:	leal %edi, 0x1f000(%esi)
0x00422aa4:	movl %eax, (%edi)
0x00422aa6:	orl %eax, %eax
0x00422aa8:	je 0x00422ae6
0x00422aaa:	movl %ebx, 0x4(%edi)
0x00422aad:	leal %eax, 0x22e5c(%eax,%esi)
0x00422ab4:	addl %ebx, %esi
0x00422ab6:	pushl %eax
0x00422ab7:	addl %edi, $0x8<UINT8>
0x00422aba:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00422ac0:	xchgl %ebp, %eax
0x00422ac1:	movb %al, (%edi)
0x00422ac3:	incl %edi
0x00422ac4:	orb %al, %al
0x00422ac6:	je 0x00422aa4
0x00422ac8:	movl %ecx, %edi
0x00422aca:	pushl %edi
0x00422acb:	decl %eax
0x00422acc:	repn scasb %al, %es:(%edi)
0x00422ace:	pushl %ebp
0x00422acf:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00422ad5:	orl %eax, %eax
0x00422ad7:	je 7
0x00422ad9:	movl (%ebx), %eax
0x00422adb:	addl %ebx, $0x4<UINT8>
0x00422ade:	jmp 0x00422ac1
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x00422ae6:	addl %edi, $0x4<UINT8>
0x00422ae9:	leal %ebx, -4(%esi)
0x00422aec:	xorl %eax, %eax
0x00422aee:	movb %al, (%edi)
0x00422af0:	incl %edi
0x00422af1:	orl %eax, %eax
0x00422af3:	je 0x00422b17
0x00422af5:	cmpb %al, $0xffffffef<UINT8>
0x00422af7:	ja 0x00422b0a
0x00422af9:	addl %ebx, %eax
0x00422afb:	movl %eax, (%ebx)
0x00422afd:	xchgb %ah, %al
0x00422aff:	roll %eax, $0x10<UINT8>
0x00422b02:	xchgb %ah, %al
0x00422b04:	addl %eax, %esi
0x00422b06:	movl (%ebx), %eax
0x00422b08:	jmp 0x00422aec
0x00422b0a:	andb %al, $0xf<UINT8>
0x00422b0c:	shll %eax, $0x10<UINT8>
0x00422b0f:	movw %ax, (%edi)
0x00422b12:	addl %edi, $0x2<UINT8>
0x00422b15:	jmp 0x00422af9
0x00422b17:	movl %ebp, 0x22f0c(%esi)
0x00422b1d:	leal %edi, -4096(%esi)
0x00422b23:	movl %ebx, $0x1000<UINT32>
0x00422b28:	pushl %eax
0x00422b29:	pushl %esp
0x00422b2a:	pushl $0x4<UINT8>
0x00422b2c:	pushl %ebx
0x00422b2d:	pushl %edi
0x00422b2e:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00422b30:	leal %eax, 0x1ff(%edi)
0x00422b36:	andb (%eax), $0x7f<UINT8>
0x00422b39:	andb 0x28(%eax), $0x7f<UINT8>
0x00422b3d:	popl %eax
0x00422b3e:	pushl %eax
0x00422b3f:	pushl %esp
0x00422b40:	pushl %eax
0x00422b41:	pushl %ebx
0x00422b42:	pushl %edi
0x00422b43:	call VirtualProtect@kernel32.dll
0x00422b45:	popl %eax
0x00422b46:	popa
0x00422b47:	leal %eax, -128(%esp)
0x00422b4b:	pushl $0x0<UINT8>
0x00422b4d:	cmpl %esp, %eax
0x00422b4f:	jne 0x00422b4b
0x00422b51:	subl %esp, $0xffffff80<UINT8>
0x00422b54:	jmp 0x004046c6
0x004046c6:	call 0x004089c4
0x004089c4:	movl %edi, %edi
0x004089c6:	pushl %ebp
0x004089c7:	movl %ebp, %esp
0x004089c9:	subl %esp, $0x10<UINT8>
0x004089cc:	movl %eax, 0x418004
0x004089d1:	andl -8(%ebp), $0x0<UINT8>
0x004089d5:	andl -4(%ebp), $0x0<UINT8>
0x004089d9:	pushl %ebx
0x004089da:	pushl %edi
0x004089db:	movl %edi, $0xbb40e64e<UINT32>
0x004089e0:	movl %ebx, $0xffff0000<UINT32>
0x004089e5:	cmpl %eax, %edi
0x004089e7:	je 0x004089f6
0x004089f6:	pushl %esi
0x004089f7:	leal %eax, -8(%ebp)
0x004089fa:	pushl %eax
0x004089fb:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x00408a01:	movl %esi, -4(%ebp)
0x00408a04:	xorl %esi, -8(%ebp)
0x00408a07:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x00408a0d:	xorl %esi, %eax
0x00408a0f:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x00408a15:	xorl %esi, %eax
0x00408a17:	call GetTickCount@KERNEL32.DLL
GetTickCount@KERNEL32.DLL: API Node	
0x00408a1d:	xorl %esi, %eax
0x00408a1f:	leal %eax, -16(%ebp)
0x00408a22:	pushl %eax
0x00408a23:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x00408a29:	movl %eax, -12(%ebp)
0x00408a2c:	xorl %eax, -16(%ebp)
0x00408a2f:	xorl %esi, %eax
0x00408a31:	cmpl %esi, %edi
0x00408a33:	jne 0x00408a3c
0x00408a3c:	testl %ebx, %esi
0x00408a3e:	jne 0x00408a47
0x00408a47:	movl 0x418004, %esi
0x00408a4d:	notl %esi
0x00408a4f:	movl 0x418008, %esi
0x00408a55:	popl %esi
0x00408a56:	popl %edi
0x00408a57:	popl %ebx
0x00408a58:	leave
0x00408a59:	ret

0x004046cb:	jmp 0x00404548
0x00404548:	pushl $0x58<UINT8>
0x0040454a:	pushl $0x4163b0<UINT32>
0x0040454f:	call 0x00406534
0x00406534:	pushl $0x406590<UINT32>
0x00406539:	pushl %fs:0
0x00406540:	movl %eax, 0x10(%esp)
0x00406544:	movl 0x10(%esp), %ebp
0x00406548:	leal %ebp, 0x10(%esp)
0x0040654c:	subl %esp, %eax
0x0040654e:	pushl %ebx
0x0040654f:	pushl %esi
0x00406550:	pushl %edi
0x00406551:	movl %eax, 0x418004
0x00406556:	xorl -4(%ebp), %eax
0x00406559:	xorl %eax, %ebp
0x0040655b:	pushl %eax
0x0040655c:	movl -24(%ebp), %esp
0x0040655f:	pushl -8(%ebp)
0x00406562:	movl %eax, -4(%ebp)
0x00406565:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040656c:	movl -8(%ebp), %eax
0x0040656f:	leal %eax, -16(%ebp)
0x00406572:	movl %fs:0, %eax
0x00406578:	ret

0x00404554:	xorl %esi, %esi
0x00404556:	movl -4(%ebp), %esi
0x00404559:	leal %eax, -104(%ebp)
0x0040455c:	pushl %eax
0x0040455d:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x00404563:	pushl $0xfffffffe<UINT8>
0x00404565:	popl %edi
0x00404566:	movl -4(%ebp), %edi
0x00404569:	movl %eax, $0x5a4d<UINT32>
0x0040456e:	cmpw 0x400000, %ax
0x00404575:	jne 56
0x00404577:	movl %eax, 0x40003c
0x0040457c:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00404586:	jne 39
0x00404588:	movl %ecx, $0x10b<UINT32>
0x0040458d:	cmpw 0x400018(%eax), %cx
0x00404594:	jne 25
0x00404596:	cmpl 0x400074(%eax), $0xe<UINT8>
0x0040459d:	jbe 16
0x0040459f:	xorl %ecx, %ecx
0x004045a1:	cmpl 0x4000e8(%eax), %esi
0x004045a7:	setne %cl
0x004045aa:	movl -28(%ebp), %ecx
0x004045ad:	jmp 0x004045b2
0x004045b2:	xorl %ebx, %ebx
0x004045b4:	incl %ebx
0x004045b5:	pushl %ebx
0x004045b6:	call 0x0040588f
0x0040588f:	movl %edi, %edi
0x00405891:	pushl %ebp
0x00405892:	movl %ebp, %esp
0x00405894:	xorl %eax, %eax
0x00405896:	cmpl 0x8(%ebp), %eax
0x00405899:	pushl $0x0<UINT8>
0x0040589b:	sete %al
0x0040589e:	pushl $0x1000<UINT32>
0x004058a3:	pushl %eax
0x004058a4:	call HeapCreate@KERNEL32.DLL
HeapCreate@KERNEL32.DLL: API Node	
0x004058aa:	movl 0x419678, %eax
0x004058af:	testl %eax, %eax
0x004058b1:	jne 0x004058b5
0x004058b5:	xorl %eax, %eax
0x004058b7:	incl %eax
0x004058b8:	movl 0x41afd0, %eax
0x004058bd:	popl %ebp
0x004058be:	ret

0x004045bb:	popl %ecx
0x004045bc:	testl %eax, %eax
0x004045be:	jne 0x004045c8
0x004045c8:	call 0x00406bd7
0x00406bd7:	movl %edi, %edi
0x00406bd9:	pushl %esi
0x00406bda:	pushl %edi
0x00406bdb:	movl %esi, $0x412354<UINT32>
0x00406be0:	pushl %esi
0x00406be1:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00406be7:	testl %eax, %eax
0x00406be9:	jne 0x00406bf2
0x00406bf2:	movl %edi, %eax
0x00406bf4:	testl %edi, %edi
0x00406bf6:	je 350
0x00406bfc:	movl %esi, 0x412158
0x00406c02:	pushl $0x4123a0<UINT32>
0x00406c07:	pushl %edi
0x00406c08:	call GetProcAddress@KERNEL32.DLL
0x00406c0a:	pushl $0x412394<UINT32>
0x00406c0f:	pushl %edi
0x00406c10:	movl 0x4197d4, %eax
0x00406c15:	call GetProcAddress@KERNEL32.DLL
0x00406c17:	pushl $0x412388<UINT32>
0x00406c1c:	pushl %edi
0x00406c1d:	movl 0x4197d8, %eax
0x00406c22:	call GetProcAddress@KERNEL32.DLL
0x00406c24:	pushl $0x412380<UINT32>
0x00406c29:	pushl %edi
0x00406c2a:	movl 0x4197dc, %eax
0x00406c2f:	call GetProcAddress@KERNEL32.DLL
0x00406c31:	cmpl 0x4197d4, $0x0<UINT8>
0x00406c38:	movl %esi, 0x412114
0x00406c3e:	movl 0x4197e0, %eax
0x00406c43:	je 22
0x00406c45:	cmpl 0x4197d8, $0x0<UINT8>
0x00406c4c:	je 13
0x00406c4e:	cmpl 0x4197dc, $0x0<UINT8>
0x00406c55:	je 4
0x00406c57:	testl %eax, %eax
0x00406c59:	jne 0x00406c7f
0x00406c7f:	call TlsAlloc@KERNEL32.DLL
TlsAlloc@KERNEL32.DLL: API Node	
0x00406c85:	movl 0x4182ac, %eax
0x00406c8a:	cmpl %eax, $0xffffffff<UINT8>
0x00406c8d:	je 204
0x00406c93:	pushl 0x4197d8
0x00406c99:	pushl %eax
0x00406c9a:	call TlsSetValue@KERNEL32.DLL
TlsSetValue@KERNEL32.DLL: API Node	
0x00406c9c:	testl %eax, %eax
0x00406c9e:	je 187
0x00406ca4:	call 0x004071a8
0x004071a8:	movl %edi, %edi
0x004071aa:	pushl %esi
0x004071ab:	call 0x0040678e
0x0040678e:	pushl $0x0<UINT8>
0x00406790:	call 0x0040671c
0x0040671c:	movl %edi, %edi
0x0040671e:	pushl %ebp
0x0040671f:	movl %ebp, %esp
0x00406721:	pushl %esi
0x00406722:	pushl 0x4182ac
0x00406728:	movl %esi, 0x41211c
0x0040672e:	call TlsGetValue@KERNEL32.DLL
TlsGetValue@KERNEL32.DLL: API Node	
0x00406730:	testl %eax, %eax
0x00406732:	je 33
0x00406734:	movl %eax, 0x4182a8
0x00406739:	cmpl %eax, $0xffffffff<UINT8>
0x0040673c:	je 0x00406755
0x00406755:	movl %esi, $0x412354<UINT32>
0x0040675a:	pushl %esi
0x0040675b:	call GetModuleHandleW@KERNEL32.DLL
0x00406761:	testl %eax, %eax
0x00406763:	jne 0x00406770
0x00406770:	pushl $0x412344<UINT32>
0x00406775:	pushl %eax
0x00406776:	call GetProcAddress@KERNEL32.DLL
0x0040677c:	testl %eax, %eax
0x0040677e:	je 8
0x00406780:	pushl 0x8(%ebp)
0x00406783:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00406785:	movl 0x8(%ebp), %eax
0x00406788:	movl %eax, 0x8(%ebp)
0x0040678b:	popl %esi
0x0040678c:	popl %ebp
0x0040678d:	ret

0x00406795:	popl %ecx
0x00406796:	ret

0x004071b0:	movl %esi, %eax
0x004071b2:	pushl %esi
0x004071b3:	call 0x004081d4
0x004081d4:	movl %edi, %edi
0x004081d6:	pushl %ebp
0x004081d7:	movl %ebp, %esp
0x004081d9:	movl %eax, 0x8(%ebp)
0x004081dc:	movl 0x419b74, %eax
0x004081e1:	popl %ebp
0x004081e2:	ret

0x004071b8:	pushl %esi
0x004071b9:	call 0x0040a790
0x0040a790:	movl %edi, %edi
0x0040a792:	pushl %ebp
0x0040a793:	movl %ebp, %esp
0x0040a795:	movl %eax, 0x8(%ebp)
0x0040a798:	movl 0x419c94, %eax
0x0040a79d:	popl %ebp
0x0040a79e:	ret

0x004071be:	pushl %esi
0x004071bf:	call 0x00405524
0x00405524:	movl %edi, %edi
0x00405526:	pushl %ebp
0x00405527:	movl %ebp, %esp
0x00405529:	movl %eax, 0x8(%ebp)
0x0040552c:	movl 0x419674, %eax
0x00405531:	popl %ebp
0x00405532:	ret

0x004071c4:	pushl %esi
0x004071c5:	call 0x0040af26
0x0040af26:	movl %edi, %edi
0x0040af28:	pushl %ebp
0x0040af29:	movl %ebp, %esp
0x0040af2b:	movl %eax, 0x8(%ebp)
0x0040af2e:	movl 0x419cbc, %eax
0x0040af33:	popl %ebp
0x0040af34:	ret

0x004071ca:	pushl %esi
0x004071cb:	call 0x0040af17
0x0040af17:	movl %edi, %edi
0x0040af19:	pushl %ebp
0x0040af1a:	movl %ebp, %esp
0x0040af1c:	movl %eax, 0x8(%ebp)
0x0040af1f:	movl 0x419cb0, %eax
0x0040af24:	popl %ebp
0x0040af25:	ret

0x004071d0:	pushl %esi
0x004071d1:	call 0x0040ad05
0x0040ad05:	movl %edi, %edi
0x0040ad07:	pushl %ebp
0x0040ad08:	movl %ebp, %esp
0x0040ad0a:	movl %eax, 0x8(%ebp)
0x0040ad0d:	movl 0x419c9c, %eax
0x0040ad12:	movl 0x419ca0, %eax
0x0040ad17:	movl 0x419ca4, %eax
0x0040ad1c:	movl 0x419ca8, %eax
0x0040ad21:	popl %ebp
0x0040ad22:	ret

0x004071d6:	pushl %esi
0x004071d7:	call 0x004071f6
0x004071f6:	ret

0x004071dc:	pushl %esi
0x004071dd:	call 0x0040acf4
0x0040acf4:	pushl $0x40acbb<UINT32>
0x0040acf9:	call 0x0040671c
0x0040acfe:	popl %ecx
0x0040acff:	movl 0x419c98, %eax
0x0040ad04:	ret

0x004071e2:	pushl $0x407174<UINT32>
0x004071e7:	call 0x0040671c
0x004071ec:	addl %esp, $0x24<UINT8>
0x004071ef:	movl 0x4182b0, %eax
0x004071f4:	popl %esi
0x004071f5:	ret

0x00406ca9:	pushl 0x4197d4
0x00406caf:	call 0x0040671c
0x00406cb4:	pushl 0x4197d8
0x00406cba:	movl 0x4197d4, %eax
0x00406cbf:	call 0x0040671c
0x00406cc4:	pushl 0x4197dc
0x00406cca:	movl 0x4197d8, %eax
0x00406ccf:	call 0x0040671c
0x00406cd4:	pushl 0x4197e0
0x00406cda:	movl 0x4197dc, %eax
0x00406cdf:	call 0x0040671c
0x00406ce4:	addl %esp, $0x10<UINT8>
0x00406ce7:	movl 0x4197e0, %eax
0x00406cec:	call 0x004058bf
0x004058bf:	movl %edi, %edi
0x004058c1:	pushl %esi
0x004058c2:	pushl %edi
0x004058c3:	xorl %esi, %esi
0x004058c5:	movl %edi, $0x419680<UINT32>
0x004058ca:	cmpl 0x41818c(,%esi,8), $0x1<UINT8>
0x004058d2:	jne 0x004058f2
0x004058d4:	leal %eax, 0x418188(,%esi,8)
0x004058db:	movl (%eax), %edi
0x004058dd:	pushl $0xfa0<UINT32>
0x004058e2:	pushl (%eax)
0x004058e4:	addl %edi, $0x18<UINT8>
0x004058e7:	call 0x0040a79f
0x0040a79f:	pushl $0x10<UINT8>
0x0040a7a1:	pushl $0x416568<UINT32>
0x0040a7a6:	call 0x00406534
0x0040a7ab:	andl -4(%ebp), $0x0<UINT8>
0x0040a7af:	pushl 0xc(%ebp)
0x0040a7b2:	pushl 0x8(%ebp)
0x0040a7b5:	call InitializeCriticalSectionAndSpinCount@KERNEL32.DLL
InitializeCriticalSectionAndSpinCount@KERNEL32.DLL: API Node	
0x0040a7bb:	movl -28(%ebp), %eax
0x0040a7be:	jmp 0x0040a7ef
0x0040a7ef:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040a7f6:	movl %eax, -28(%ebp)
0x0040a7f9:	call 0x00406579
0x00406579:	movl %ecx, -16(%ebp)
0x0040657c:	movl %fs:0, %ecx
0x00406583:	popl %ecx
0x00406584:	popl %edi
0x00406585:	popl %edi
0x00406586:	popl %esi
0x00406587:	popl %ebx
0x00406588:	movl %esp, %ebp
0x0040658a:	popl %ebp
0x0040658b:	pushl %ecx
0x0040658c:	ret

0x0040a7fe:	ret

0x004058ec:	popl %ecx
0x004058ed:	popl %ecx
0x004058ee:	testl %eax, %eax
0x004058f0:	je 12
0x004058f2:	incl %esi
0x004058f3:	cmpl %esi, $0x24<UINT8>
0x004058f6:	jl 0x004058ca
0x004058f8:	xorl %eax, %eax
0x004058fa:	incl %eax
0x004058fb:	popl %edi
0x004058fc:	popl %esi
0x004058fd:	ret

0x00406cf1:	testl %eax, %eax
0x00406cf3:	je 101
0x00406cf5:	pushl $0x406a3a<UINT32>
0x00406cfa:	pushl 0x4197d4
0x00406d00:	call 0x00406797
0x00406797:	movl %edi, %edi
0x00406799:	pushl %ebp
0x0040679a:	movl %ebp, %esp
0x0040679c:	pushl %esi
0x0040679d:	pushl 0x4182ac
0x004067a3:	movl %esi, 0x41211c
0x004067a9:	call TlsGetValue@KERNEL32.DLL
0x004067ab:	testl %eax, %eax
0x004067ad:	je 33
0x004067af:	movl %eax, 0x4182a8
0x004067b4:	cmpl %eax, $0xffffffff<UINT8>
0x004067b7:	je 0x004067d0
0x004067d0:	movl %esi, $0x412354<UINT32>
0x004067d5:	pushl %esi
0x004067d6:	call GetModuleHandleW@KERNEL32.DLL
0x004067dc:	testl %eax, %eax
0x004067de:	jne 0x004067eb
0x004067eb:	pushl $0x412370<UINT32>
0x004067f0:	pushl %eax
0x004067f1:	call GetProcAddress@KERNEL32.DLL
0x004067f7:	testl %eax, %eax
0x004067f9:	je 8
0x004067fb:	pushl 0x8(%ebp)
0x004067fe:	call DecodePointer@KERNEL32.DLL
DecodePointer@KERNEL32.DLL: API Node	
0x00406800:	movl 0x8(%ebp), %eax
0x00406803:	movl %eax, 0x8(%ebp)
0x00406806:	popl %esi
0x00406807:	popl %ebp
0x00406808:	ret

0x00406d05:	popl %ecx
0x00406d06:	call FlsAlloc@KERNEL32.DLL
FlsAlloc@KERNEL32.DLL: API Node	
0x00406d08:	movl 0x4182a8, %eax
0x00406d0d:	cmpl %eax, $0xffffffff<UINT8>
0x00406d10:	je 72
0x00406d12:	pushl $0x214<UINT32>
0x00406d17:	pushl $0x1<UINT8>
0x00406d19:	call 0x0040739c
0x0040739c:	movl %edi, %edi
0x0040739e:	pushl %ebp
0x0040739f:	movl %ebp, %esp
0x004073a1:	pushl %esi
0x004073a2:	pushl %edi
0x004073a3:	xorl %esi, %esi
0x004073a5:	pushl $0x0<UINT8>
0x004073a7:	pushl 0xc(%ebp)
0x004073aa:	pushl 0x8(%ebp)
0x004073ad:	call 0x0040af35
0x0040af35:	pushl $0xc<UINT8>
0x0040af37:	pushl $0x4165c8<UINT32>
0x0040af3c:	call 0x00406534
0x0040af41:	movl %ecx, 0x8(%ebp)
0x0040af44:	xorl %edi, %edi
0x0040af46:	cmpl %ecx, %edi
0x0040af48:	jbe 46
0x0040af4a:	pushl $0xffffffe0<UINT8>
0x0040af4c:	popl %eax
0x0040af4d:	xorl %edx, %edx
0x0040af4f:	divl %eax, %ecx
0x0040af51:	cmpl %eax, 0xc(%ebp)
0x0040af54:	sbbl %eax, %eax
0x0040af56:	incl %eax
0x0040af57:	jne 0x0040af78
0x0040af78:	imull %ecx, 0xc(%ebp)
0x0040af7c:	movl %esi, %ecx
0x0040af7e:	movl 0x8(%ebp), %esi
0x0040af81:	cmpl %esi, %edi
0x0040af83:	jne 0x0040af88
0x0040af88:	xorl %ebx, %ebx
0x0040af8a:	movl -28(%ebp), %ebx
0x0040af8d:	cmpl %esi, $0xffffffe0<UINT8>
0x0040af90:	ja 105
0x0040af92:	cmpl 0x41afd0, $0x3<UINT8>
0x0040af99:	jne 0x0040afe6
0x0040afe6:	cmpl %ebx, %edi
0x0040afe8:	jne 97
0x0040afea:	pushl %esi
0x0040afeb:	pushl $0x8<UINT8>
0x0040afed:	pushl 0x419678
0x0040aff3:	call HeapAlloc@KERNEL32.DLL
HeapAlloc@KERNEL32.DLL: API Node	
0x0040aff9:	movl %ebx, %eax
0x0040affb:	cmpl %ebx, %edi
0x0040affd:	jne 0x0040b04b
0x0040b04b:	movl %eax, %ebx
0x0040b04d:	call 0x00406579
0x0040b052:	ret

0x004073b2:	movl %edi, %eax
0x004073b4:	addl %esp, $0xc<UINT8>
0x004073b7:	testl %edi, %edi
0x004073b9:	jne 0x004073e2
0x004073e2:	movl %eax, %edi
0x004073e4:	popl %edi
0x004073e5:	popl %esi
0x004073e6:	popl %ebp
0x004073e7:	ret

0x00406d1e:	movl %esi, %eax
0x00406d20:	popl %ecx
0x00406d21:	popl %ecx
0x00406d22:	testl %esi, %esi
0x00406d24:	je 52
0x00406d26:	pushl %esi
0x00406d27:	pushl 0x4182a8
0x00406d2d:	pushl 0x4197dc
0x00406d33:	call 0x00406797
0x004067b9:	pushl %eax
0x004067ba:	pushl 0x4182ac
0x004067c0:	call TlsGetValue@KERNEL32.DLL
0x004067c2:	call FlsGetValue@KERNEL32.DLL
FlsGetValue@KERNEL32.DLL: API Node	
0x004067c4:	testl %eax, %eax
0x004067c6:	je 0x004067d0
0x00406d38:	popl %ecx
0x00406d39:	call FlsSetValue@KERNEL32.DLL
FlsSetValue@KERNEL32.DLL: API Node	
0x00406d3b:	testl %eax, %eax
0x00406d3d:	je 27
0x00406d3f:	pushl $0x0<UINT8>
0x00406d41:	pushl %esi
0x00406d42:	call 0x004068c0
0x004068c0:	pushl $0xc<UINT8>
0x004068c2:	pushl $0x4163f8<UINT32>
0x004068c7:	call 0x00406534
0x004068cc:	movl %esi, $0x412354<UINT32>
0x004068d1:	pushl %esi
0x004068d2:	call GetModuleHandleW@KERNEL32.DLL
0x004068d8:	testl %eax, %eax
0x004068da:	jne 0x004068e3
0x004068e3:	movl -28(%ebp), %eax
0x004068e6:	movl %esi, 0x8(%ebp)
0x004068e9:	movl 0x5c(%esi), $0x4123d8<UINT32>
0x004068f0:	xorl %edi, %edi
0x004068f2:	incl %edi
0x004068f3:	movl 0x14(%esi), %edi
0x004068f6:	testl %eax, %eax
0x004068f8:	je 36
0x004068fa:	pushl $0x412344<UINT32>
0x004068ff:	pushl %eax
0x00406900:	movl %ebx, 0x412158
0x00406906:	call GetProcAddress@KERNEL32.DLL
0x00406908:	movl 0x1f8(%esi), %eax
0x0040690e:	pushl $0x412370<UINT32>
0x00406913:	pushl -28(%ebp)
0x00406916:	call GetProcAddress@KERNEL32.DLL
0x00406918:	movl 0x1fc(%esi), %eax
0x0040691e:	movl 0x70(%esi), %edi
0x00406921:	movb 0xc8(%esi), $0x43<UINT8>
0x00406928:	movb 0x14b(%esi), $0x43<UINT8>
0x0040692f:	movl 0x68(%esi), $0x4182c8<UINT32>
0x00406936:	pushl $0xd<UINT8>
0x00406938:	call 0x00405a3b
0x00405a3b:	movl %edi, %edi
0x00405a3d:	pushl %ebp
0x00405a3e:	movl %ebp, %esp
0x00405a40:	movl %eax, 0x8(%ebp)
0x00405a43:	pushl %esi
0x00405a44:	leal %esi, 0x418188(,%eax,8)
0x00405a4b:	cmpl (%esi), $0x0<UINT8>
0x00405a4e:	jne 0x00405a63
0x00405a63:	pushl (%esi)
0x00405a65:	call EnterCriticalSection@KERNEL32.DLL
EnterCriticalSection@KERNEL32.DLL: API Node	
0x00405a6b:	popl %esi
0x00405a6c:	popl %ebp
0x00405a6d:	ret

0x0040693d:	popl %ecx
0x0040693e:	andl -4(%ebp), $0x0<UINT8>
0x00406942:	pushl 0x68(%esi)
0x00406945:	call InterlockedIncrement@KERNEL32.DLL
InterlockedIncrement@KERNEL32.DLL: API Node	
0x0040694b:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00406952:	call 0x00406995
0x00406995:	pushl $0xd<UINT8>
0x00406997:	call 0x00405961
0x00405961:	movl %edi, %edi
0x00405963:	pushl %ebp
0x00405964:	movl %ebp, %esp
0x00405966:	movl %eax, 0x8(%ebp)
0x00405969:	pushl 0x418188(,%eax,8)
0x00405970:	call LeaveCriticalSection@KERNEL32.DLL
LeaveCriticalSection@KERNEL32.DLL: API Node	
0x00405976:	popl %ebp
0x00405977:	ret

0x0040699c:	popl %ecx
0x0040699d:	ret

0x00406957:	pushl $0xc<UINT8>
0x00406959:	call 0x00405a3b
0x0040695e:	popl %ecx
0x0040695f:	movl -4(%ebp), %edi
0x00406962:	movl %eax, 0xc(%ebp)
0x00406965:	movl 0x6c(%esi), %eax
0x00406968:	testl %eax, %eax
0x0040696a:	jne 8
0x0040696c:	movl %eax, 0x4188d0
0x00406971:	movl 0x6c(%esi), %eax
0x00406974:	pushl 0x6c(%esi)
0x00406977:	call 0x00407d5f
0x00407d5f:	movl %edi, %edi
0x00407d61:	pushl %ebp
0x00407d62:	movl %ebp, %esp
0x00407d64:	pushl %ebx
0x00407d65:	pushl %esi
0x00407d66:	movl %esi, 0x41210c
0x00407d6c:	pushl %edi
0x00407d6d:	movl %edi, 0x8(%ebp)
0x00407d70:	pushl %edi
0x00407d71:	call InterlockedIncrement@KERNEL32.DLL
0x00407d73:	movl %eax, 0xb0(%edi)
0x00407d79:	testl %eax, %eax
0x00407d7b:	je 0x00407d80
0x00407d80:	movl %eax, 0xb8(%edi)
0x00407d86:	testl %eax, %eax
0x00407d88:	je 0x00407d8d
0x00407d8d:	movl %eax, 0xb4(%edi)
0x00407d93:	testl %eax, %eax
0x00407d95:	je 0x00407d9a
0x00407d9a:	movl %eax, 0xc0(%edi)
0x00407da0:	testl %eax, %eax
0x00407da2:	je 0x00407da7
0x00407da7:	leal %ebx, 0x50(%edi)
0x00407daa:	movl 0x8(%ebp), $0x6<UINT32>
0x00407db1:	cmpl -8(%ebx), $0x4187f0<UINT32>
0x00407db8:	je 0x00407dc3
0x00407dba:	movl %eax, (%ebx)
0x00407dbc:	testl %eax, %eax
0x00407dbe:	je 0x00407dc3
0x00407dc3:	cmpl -4(%ebx), $0x0<UINT8>
0x00407dc7:	je 0x00407dd3
0x00407dd3:	addl %ebx, $0x10<UINT8>
0x00407dd6:	decl 0x8(%ebp)
0x00407dd9:	jne 0x00407db1
0x00407ddb:	movl %eax, 0xd4(%edi)
0x00407de1:	addl %eax, $0xb4<UINT32>
0x00407de6:	pushl %eax
0x00407de7:	call InterlockedIncrement@KERNEL32.DLL
0x00407de9:	popl %edi
0x00407dea:	popl %esi
0x00407deb:	popl %ebx
0x00407dec:	popl %ebp
0x00407ded:	ret

0x0040697c:	popl %ecx
0x0040697d:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00406984:	call 0x0040699e
0x0040699e:	pushl $0xc<UINT8>
0x004069a0:	call 0x00405961
0x004069a5:	popl %ecx
0x004069a6:	ret

0x00406989:	call 0x00406579
0x0040698e:	ret

0x00406d47:	popl %ecx
0x00406d48:	popl %ecx
0x00406d49:	call GetCurrentThreadId@KERNEL32.DLL
0x00406d4f:	orl 0x4(%esi), $0xffffffff<UINT8>
0x00406d53:	movl (%esi), %eax
0x00406d55:	xorl %eax, %eax
0x00406d57:	incl %eax
0x00406d58:	jmp 0x00406d61
0x00406d61:	popl %edi
0x00406d62:	popl %esi
0x00406d63:	ret

0x004045cd:	testl %eax, %eax
0x004045cf:	jne 0x004045d9
0x004045d9:	call 0x00408978
0x00408978:	movl %edi, %edi
0x0040897a:	pushl %esi
0x0040897b:	movl %eax, $0x416320<UINT32>
0x00408980:	movl %esi, $0x416320<UINT32>
0x00408985:	pushl %edi
0x00408986:	movl %edi, %eax
0x00408988:	cmpl %eax, %esi
0x0040898a:	jae 0x0040899b
0x0040899b:	popl %edi
0x0040899c:	popl %esi
0x0040899d:	ret

0x004045de:	movl -4(%ebp), %ebx
0x004045e1:	call 0x00408724
0x00408724:	pushl $0x54<UINT8>
0x00408726:	pushl $0x416508<UINT32>
0x0040872b:	call 0x00406534
0x00408730:	xorl %edi, %edi
0x00408732:	movl -4(%ebp), %edi
0x00408735:	leal %eax, -100(%ebp)
0x00408738:	pushl %eax
0x00408739:	call GetStartupInfoA@KERNEL32.DLL
0x0040873f:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00408746:	pushl $0x40<UINT8>
0x00408748:	pushl $0x20<UINT8>
0x0040874a:	popl %esi
0x0040874b:	pushl %esi
0x0040874c:	call 0x0040739c
0x00408751:	popl %ecx
0x00408752:	popl %ecx
0x00408753:	cmpl %eax, %edi
0x00408755:	je 532
0x0040875b:	movl 0x41aea0, %eax
0x00408760:	movl 0x41ae88, %esi
0x00408766:	leal %ecx, 0x800(%eax)
0x0040876c:	jmp 0x0040879e
0x0040879e:	cmpl %eax, %ecx
0x004087a0:	jb 0x0040876e
0x0040876e:	movb 0x4(%eax), $0x0<UINT8>
0x00408772:	orl (%eax), $0xffffffff<UINT8>
0x00408775:	movb 0x5(%eax), $0xa<UINT8>
0x00408779:	movl 0x8(%eax), %edi
0x0040877c:	movb 0x24(%eax), $0x0<UINT8>
0x00408780:	movb 0x25(%eax), $0xa<UINT8>
0x00408784:	movb 0x26(%eax), $0xa<UINT8>
0x00408788:	movl 0x38(%eax), %edi
0x0040878b:	movb 0x34(%eax), $0x0<UINT8>
0x0040878f:	addl %eax, $0x40<UINT8>
0x00408792:	movl %ecx, 0x41aea0
0x00408798:	addl %ecx, $0x800<UINT32>
0x004087a2:	cmpw -50(%ebp), %di
0x004087a6:	je 266
0x004087ac:	movl %eax, -48(%ebp)
0x004087af:	cmpl %eax, %edi
0x004087b1:	je 255
0x004087b7:	movl %edi, (%eax)
0x004087b9:	leal %ebx, 0x4(%eax)
0x004087bc:	leal %eax, (%ebx,%edi)
0x004087bf:	movl -28(%ebp), %eax
0x004087c2:	movl %esi, $0x800<UINT32>
0x004087c7:	cmpl %edi, %esi
0x004087c9:	jl 0x004087cd
0x004087cd:	movl -32(%ebp), $0x1<UINT32>
0x004087d4:	jmp 0x00408831
0x00408831:	cmpl 0x41ae88, %edi
0x00408837:	jl -99
0x00408839:	jmp 0x00408841
0x00408841:	andl -32(%ebp), $0x0<UINT8>
0x00408845:	testl %edi, %edi
0x00408847:	jle 0x004088b6
0x004088b6:	xorl %ebx, %ebx
0x004088b8:	movl %esi, %ebx
0x004088ba:	shll %esi, $0x6<UINT8>
0x004088bd:	addl %esi, 0x41aea0
0x004088c3:	movl %eax, (%esi)
0x004088c5:	cmpl %eax, $0xffffffff<UINT8>
0x004088c8:	je 0x004088d5
0x004088d5:	movb 0x4(%esi), $0xffffff81<UINT8>
0x004088d9:	testl %ebx, %ebx
0x004088db:	jne 0x004088e2
0x004088dd:	pushl $0xfffffff6<UINT8>
0x004088df:	popl %eax
0x004088e0:	jmp 0x004088ec
0x004088ec:	pushl %eax
0x004088ed:	call GetStdHandle@KERNEL32.DLL
GetStdHandle@KERNEL32.DLL: API Node	
0x004088f3:	movl %edi, %eax
0x004088f5:	cmpl %edi, $0xffffffff<UINT8>
0x004088f8:	je 67
0x004088fa:	testl %edi, %edi
0x004088fc:	je 63
0x004088fe:	pushl %edi
0x004088ff:	call GetFileType@KERNEL32.DLL
GetFileType@KERNEL32.DLL: API Node	
0x00408905:	testl %eax, %eax
0x00408907:	je 52
0x00408909:	movl (%esi), %edi
0x0040890b:	andl %eax, $0xff<UINT32>
0x00408910:	cmpl %eax, $0x2<UINT8>
0x00408913:	jne 6
0x00408915:	orb 0x4(%esi), $0x40<UINT8>
0x00408919:	jmp 0x00408924
0x00408924:	pushl $0xfa0<UINT32>
0x00408929:	leal %eax, 0xc(%esi)
0x0040892c:	pushl %eax
0x0040892d:	call 0x0040a79f
0x00408932:	popl %ecx
0x00408933:	popl %ecx
0x00408934:	testl %eax, %eax
0x00408936:	je 55
0x00408938:	incl 0x8(%esi)
0x0040893b:	jmp 0x00408947
0x00408947:	incl %ebx
0x00408948:	cmpl %ebx, $0x3<UINT8>
0x0040894b:	jl 0x004088b8
0x004088e2:	movl %eax, %ebx
0x004088e4:	decl %eax
0x004088e5:	negl %eax
0x004088e7:	sbbl %eax, %eax
0x004088e9:	addl %eax, $0xfffffff5<UINT8>
0x00408951:	pushl 0x41ae88
0x00408957:	call SetHandleCount@KERNEL32.DLL
SetHandleCount@KERNEL32.DLL: API Node	
0x0040895d:	xorl %eax, %eax
0x0040895f:	jmp 0x00408972
0x00408972:	call 0x00406579
0x00408977:	ret

0x004045e6:	testl %eax, %eax
0x004045e8:	jnl 0x004045f2
0x004045f2:	call GetCommandLineA@KERNEL32.DLL
GetCommandLineA@KERNEL32.DLL: API Node	
0x004045f8:	movl 0x41afd4, %eax
0x004045fd:	call 0x004085ed
0x004085ed:	movl %edi, %edi
0x004085ef:	pushl %ebp
0x004085f0:	movl %ebp, %esp
0x004085f2:	movl %eax, 0x419c88
0x004085f7:	subl %esp, $0xc<UINT8>
0x004085fa:	pushl %ebx
0x004085fb:	pushl %esi
0x004085fc:	movl %esi, 0x4120c8
0x00408602:	pushl %edi
0x00408603:	xorl %ebx, %ebx
0x00408605:	xorl %edi, %edi
0x00408607:	cmpl %eax, %ebx
0x00408609:	jne 46
0x0040860b:	call GetEnvironmentStringsW@KERNEL32.DLL
GetEnvironmentStringsW@KERNEL32.DLL: API Node	
0x0040860d:	movl %edi, %eax
0x0040860f:	cmpl %edi, %ebx
0x00408611:	je 12
0x00408613:	movl 0x419c88, $0x1<UINT32>
0x0040861d:	jmp 0x00408642
0x00408642:	cmpl %edi, %ebx
0x00408644:	jne 0x00408655
0x00408655:	movl %eax, %edi
0x00408657:	cmpw (%edi), %bx
0x0040865a:	je 14
0x0040865c:	incl %eax
0x0040865d:	incl %eax
0x0040865e:	cmpw (%eax), %bx
0x00408661:	jne 0x0040865c
0x00408663:	incl %eax
0x00408664:	incl %eax
0x00408665:	cmpw (%eax), %bx
0x00408668:	jne 0x0040865c
0x0040866a:	movl %esi, 0x41213c
0x00408670:	pushl %ebx
0x00408671:	pushl %ebx
0x00408672:	pushl %ebx
0x00408673:	subl %eax, %edi
0x00408675:	pushl %ebx
0x00408676:	sarl %eax
0x00408678:	incl %eax
0x00408679:	pushl %eax
0x0040867a:	pushl %edi
0x0040867b:	pushl %ebx
0x0040867c:	pushl %ebx
0x0040867d:	movl -12(%ebp), %eax
0x00408680:	call WideCharToMultiByte@KERNEL32.DLL
WideCharToMultiByte@KERNEL32.DLL: API Node	
0x00408682:	movl -8(%ebp), %eax
0x00408685:	cmpl %eax, %ebx
0x00408687:	je 47
0x00408689:	pushl %eax
0x0040868a:	call 0x00407357
0x00407357:	movl %edi, %edi
0x00407359:	pushl %ebp
0x0040735a:	movl %ebp, %esp
0x0040735c:	pushl %esi
0x0040735d:	pushl %edi
0x0040735e:	xorl %esi, %esi
0x00407360:	pushl 0x8(%ebp)
0x00407363:	call 0x00404455
0x00404455:	movl %edi, %edi
0x00404457:	pushl %ebp
0x00404458:	movl %ebp, %esp
0x0040445a:	pushl %esi
0x0040445b:	movl %esi, 0x8(%ebp)
0x0040445e:	cmpl %esi, $0xffffffe0<UINT8>
0x00404461:	ja 161
0x00404467:	pushl %ebx
0x00404468:	pushl %edi
0x00404469:	movl %edi, 0x412198
0x0040446f:	cmpl 0x419678, $0x0<UINT8>
0x00404476:	jne 0x00404490
0x00404490:	movl %eax, 0x41afd0
0x00404495:	cmpl %eax, $0x1<UINT8>
0x00404498:	jne 14
0x0040449a:	testl %esi, %esi
0x0040449c:	je 4
0x0040449e:	movl %eax, %esi
0x004044a0:	jmp 0x004044a5
0x004044a5:	pushl %eax
0x004044a6:	jmp 0x004044c4
0x004044c4:	pushl $0x0<UINT8>
0x004044c6:	pushl 0x419678
0x004044cc:	call HeapAlloc@KERNEL32.DLL
0x004044ce:	movl %ebx, %eax
0x004044d0:	testl %ebx, %ebx
0x004044d2:	jne 0x00404502
0x00404502:	popl %edi
0x00404503:	movl %eax, %ebx
0x00404505:	popl %ebx
0x00404506:	jmp 0x0040451c
0x0040451c:	popl %esi
0x0040451d:	popl %ebp
0x0040451e:	ret

0x00407368:	movl %edi, %eax
0x0040736a:	popl %ecx
0x0040736b:	testl %edi, %edi
0x0040736d:	jne 0x00407396
0x00407396:	movl %eax, %edi
0x00407398:	popl %edi
0x00407399:	popl %esi
0x0040739a:	popl %ebp
0x0040739b:	ret

0x0040868f:	popl %ecx
0x00408690:	movl -4(%ebp), %eax
0x00408693:	cmpl %eax, %ebx
0x00408695:	je 33
0x00408697:	pushl %ebx
0x00408698:	pushl %ebx
0x00408699:	pushl -8(%ebp)
0x0040869c:	pushl %eax
0x0040869d:	pushl -12(%ebp)
0x004086a0:	pushl %edi
0x004086a1:	pushl %ebx
0x004086a2:	pushl %ebx
0x004086a3:	call WideCharToMultiByte@KERNEL32.DLL
0x004086a5:	testl %eax, %eax
0x004086a7:	jne 0x004086b5
0x004086b5:	movl %ebx, -4(%ebp)
0x004086b8:	pushl %edi
0x004086b9:	call FreeEnvironmentStringsW@KERNEL32.DLL
FreeEnvironmentStringsW@KERNEL32.DLL: API Node	
0x004086bf:	movl %eax, %ebx
0x004086c1:	jmp 0x0040871f
0x0040871f:	popl %edi
0x00408720:	popl %esi
0x00408721:	popl %ebx
0x00408722:	leave
0x00408723:	ret

0x00404602:	movl 0x419340, %eax
0x00404607:	call 0x00408532
0x00408532:	movl %edi, %edi
0x00408534:	pushl %ebp
0x00408535:	movl %ebp, %esp
0x00408537:	subl %esp, $0xc<UINT8>
0x0040853a:	pushl %ebx
0x0040853b:	xorl %ebx, %ebx
0x0040853d:	pushl %esi
0x0040853e:	pushl %edi
0x0040853f:	cmpl 0x41afac, %ebx
0x00408545:	jne 5
0x00408547:	call 0x00407bf8
0x00407bf8:	cmpl 0x41afac, $0x0<UINT8>
0x00407bff:	jne 0x00407c13
0x00407c01:	pushl $0xfffffffd<UINT8>
0x00407c03:	call 0x00407a5e
0x00407a5e:	pushl $0x14<UINT8>
0x00407a60:	pushl $0x4164c8<UINT32>
0x00407a65:	call 0x00406534
0x00407a6a:	orl -32(%ebp), $0xffffffff<UINT8>
0x00407a6e:	call 0x00406a20
0x00406a20:	movl %edi, %edi
0x00406a22:	pushl %esi
0x00406a23:	call 0x004069a7
0x004069a7:	movl %edi, %edi
0x004069a9:	pushl %esi
0x004069aa:	pushl %edi
0x004069ab:	call GetLastError@KERNEL32.DLL
GetLastError@KERNEL32.DLL: API Node	
0x004069b1:	pushl 0x4182a8
0x004069b7:	movl %edi, %eax
0x004069b9:	call 0x00406832
0x00406832:	movl %edi, %edi
0x00406834:	pushl %esi
0x00406835:	pushl 0x4182ac
0x0040683b:	call TlsGetValue@KERNEL32.DLL
0x00406841:	movl %esi, %eax
0x00406843:	testl %esi, %esi
0x00406845:	jne 0x00406862
0x00406862:	movl %eax, %esi
0x00406864:	popl %esi
0x00406865:	ret

0x004069be:	call FlsGetValue@KERNEL32.DLL
0x004069c0:	movl %esi, %eax
0x004069c2:	testl %esi, %esi
0x004069c4:	jne 0x00406a14
0x00406a14:	pushl %edi
0x00406a15:	call SetLastError@KERNEL32.DLL
SetLastError@KERNEL32.DLL: API Node	
0x00406a1b:	popl %edi
0x00406a1c:	movl %eax, %esi
0x00406a1e:	popl %esi
0x00406a1f:	ret

0x00406a28:	movl %esi, %eax
0x00406a2a:	testl %esi, %esi
0x00406a2c:	jne 0x00406a36
0x00406a36:	movl %eax, %esi
0x00406a38:	popl %esi
0x00406a39:	ret

0x00407a73:	movl %edi, %eax
0x00407a75:	movl -36(%ebp), %edi
0x00407a78:	call 0x00407759
0x00407759:	pushl $0xc<UINT8>
0x0040775b:	pushl $0x4164a8<UINT32>
0x00407760:	call 0x00406534
0x00407765:	call 0x00406a20
0x0040776a:	movl %edi, %eax
0x0040776c:	movl %eax, 0x4187ec
0x00407771:	testl 0x70(%edi), %eax
0x00407774:	je 0x00407793
0x00407793:	pushl $0xd<UINT8>
0x00407795:	call 0x00405a3b
0x0040779a:	popl %ecx
0x0040779b:	andl -4(%ebp), $0x0<UINT8>
0x0040779f:	movl %esi, 0x68(%edi)
0x004077a2:	movl -28(%ebp), %esi
0x004077a5:	cmpl %esi, 0x4186f0
0x004077ab:	je 0x004077e3
0x004077e3:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004077ea:	call 0x004077f4
0x004077f4:	pushl $0xd<UINT8>
0x004077f6:	call 0x00405961
0x004077fb:	popl %ecx
0x004077fc:	ret

0x004077ef:	jmp 0x0040777f
0x0040777f:	testl %esi, %esi
0x00407781:	jne 0x0040778b
0x0040778b:	movl %eax, %esi
0x0040778d:	call 0x00406579
0x00407792:	ret

0x00407a7d:	movl %ebx, 0x68(%edi)
0x00407a80:	movl %esi, 0x8(%ebp)
0x00407a83:	call 0x004077fd
0x004077fd:	movl %edi, %edi
0x004077ff:	pushl %ebp
0x00407800:	movl %ebp, %esp
0x00407802:	subl %esp, $0x10<UINT8>
0x00407805:	pushl %ebx
0x00407806:	xorl %ebx, %ebx
0x00407808:	pushl %ebx
0x00407809:	leal %ecx, -16(%ebp)
0x0040780c:	call 0x004041db
0x004041db:	movl %edi, %edi
0x004041dd:	pushl %ebp
0x004041de:	movl %ebp, %esp
0x004041e0:	movl %eax, 0x8(%ebp)
0x004041e3:	pushl %esi
0x004041e4:	movl %esi, %ecx
0x004041e6:	movb 0xc(%esi), $0x0<UINT8>
0x004041ea:	testl %eax, %eax
0x004041ec:	jne 99
0x004041ee:	call 0x00406a20
0x004041f3:	movl 0x8(%esi), %eax
0x004041f6:	movl %ecx, 0x6c(%eax)
0x004041f9:	movl (%esi), %ecx
0x004041fb:	movl %ecx, 0x68(%eax)
0x004041fe:	movl 0x4(%esi), %ecx
0x00404201:	movl %ecx, (%esi)
0x00404203:	cmpl %ecx, 0x4188d0
0x00404209:	je 0x0040421d
0x0040421d:	movl %eax, 0x4(%esi)
0x00404220:	cmpl %eax, 0x4186f0
0x00404226:	je 0x0040423e
0x0040423e:	movl %eax, 0x8(%esi)
0x00404241:	testb 0x70(%eax), $0x2<UINT8>
0x00404245:	jne 20
0x00404247:	orl 0x70(%eax), $0x2<UINT8>
0x0040424b:	movb 0xc(%esi), $0x1<UINT8>
0x0040424f:	jmp 0x0040425b
0x0040425b:	movl %eax, %esi
0x0040425d:	popl %esi
0x0040425e:	popl %ebp
0x0040425f:	ret $0x4<UINT16>

0x00407811:	movl 0x41981c, %ebx
0x00407817:	cmpl %esi, $0xfffffffe<UINT8>
0x0040781a:	jne 0x0040783a
0x0040783a:	cmpl %esi, $0xfffffffd<UINT8>
0x0040783d:	jne 0x00407851
0x0040783f:	movl 0x41981c, $0x1<UINT32>
0x00407849:	call GetACP@KERNEL32.DLL
GetACP@KERNEL32.DLL: API Node	
0x0040784f:	jmp 0x0040782c
0x0040782c:	cmpb -4(%ebp), %bl
0x0040782f:	je 69
0x00407831:	movl %ecx, -8(%ebp)
0x00407834:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00407838:	jmp 0x00407876
0x00407876:	popl %ebx
0x00407877:	leave
0x00407878:	ret

0x00407a88:	movl 0x8(%ebp), %eax
0x00407a8b:	cmpl %eax, 0x4(%ebx)
0x00407a8e:	je 343
0x00407a94:	pushl $0x220<UINT32>
0x00407a99:	call 0x00407357
0x00407a9e:	popl %ecx
0x00407a9f:	movl %ebx, %eax
0x00407aa1:	testl %ebx, %ebx
0x00407aa3:	je 326
0x00407aa9:	movl %ecx, $0x88<UINT32>
0x00407aae:	movl %esi, 0x68(%edi)
0x00407ab1:	movl %edi, %ebx
0x00407ab3:	rep movsl %es:(%edi), %ds:(%esi)
0x00407ab5:	andl (%ebx), $0x0<UINT8>
0x00407ab8:	pushl %ebx
0x00407ab9:	pushl 0x8(%ebp)
0x00407abc:	call 0x00407879
0x00407879:	movl %edi, %edi
0x0040787b:	pushl %ebp
0x0040787c:	movl %ebp, %esp
0x0040787e:	subl %esp, $0x20<UINT8>
0x00407881:	movl %eax, 0x418004
0x00407886:	xorl %eax, %ebp
0x00407888:	movl -4(%ebp), %eax
0x0040788b:	pushl %ebx
0x0040788c:	movl %ebx, 0xc(%ebp)
0x0040788f:	pushl %esi
0x00407890:	movl %esi, 0x8(%ebp)
0x00407893:	pushl %edi
0x00407894:	call 0x004077fd
0x00407851:	cmpl %esi, $0xfffffffc<UINT8>
0x00407854:	jne 0x00407868
0x00407868:	cmpb -4(%ebp), %bl
0x0040786b:	je 7
0x0040786d:	movl %eax, -8(%ebp)
0x00407870:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x00407874:	movl %eax, %esi
0x00407899:	movl %edi, %eax
0x0040789b:	xorl %esi, %esi
0x0040789d:	movl 0x8(%ebp), %edi
0x004078a0:	cmpl %edi, %esi
0x004078a2:	jne 0x004078b2
0x004078b2:	movl -28(%ebp), %esi
0x004078b5:	xorl %eax, %eax
0x004078b7:	cmpl 0x4186f8(%eax), %edi
0x004078bd:	je 145
0x004078c3:	incl -28(%ebp)
0x004078c6:	addl %eax, $0x30<UINT8>
0x004078c9:	cmpl %eax, $0xf0<UINT32>
0x004078ce:	jb 0x004078b7
0x004078d0:	cmpl %edi, $0xfde8<UINT32>
0x004078d6:	je 368
0x004078dc:	cmpl %edi, $0xfde9<UINT32>
0x004078e2:	je 356
0x004078e8:	movzwl %eax, %di
0x004078eb:	pushl %eax
0x004078ec:	call IsValidCodePage@KERNEL32.DLL
IsValidCodePage@KERNEL32.DLL: API Node	
0x004078f2:	testl %eax, %eax
0x004078f4:	je 338
0x004078fa:	leal %eax, -24(%ebp)
0x004078fd:	pushl %eax
0x004078fe:	pushl %edi
0x004078ff:	call GetCPInfo@KERNEL32.DLL
GetCPInfo@KERNEL32.DLL: API Node	
0x00407905:	testl %eax, %eax
0x00407907:	je 307
0x0040790d:	pushl $0x101<UINT32>
0x00407912:	leal %eax, 0x1c(%ebx)
0x00407915:	pushl %esi
0x00407916:	pushl %eax
0x00407917:	call 0x00409b20
0x00409b20:	movl %edx, 0xc(%esp)
0x00409b24:	movl %ecx, 0x4(%esp)
0x00409b28:	testl %edx, %edx
0x00409b2a:	je 105
0x00409b2c:	xorl %eax, %eax
0x00409b2e:	movb %al, 0x8(%esp)
0x00409b32:	testb %al, %al
0x00409b34:	jne 22
0x00409b36:	cmpl %edx, $0x100<UINT32>
0x00409b3c:	jb 14
0x00409b3e:	cmpl 0x419e78, $0x0<UINT8>
0x00409b45:	je 0x00409b4c
0x00409b4c:	pushl %edi
0x00409b4d:	movl %edi, %ecx
0x00409b4f:	cmpl %edx, $0x4<UINT8>
0x00409b52:	jb 49
0x00409b54:	negl %ecx
0x00409b56:	andl %ecx, $0x3<UINT8>
0x00409b59:	je 0x00409b67
0x00409b67:	movl %ecx, %eax
0x00409b69:	shll %eax, $0x8<UINT8>
0x00409b6c:	addl %eax, %ecx
0x00409b6e:	movl %ecx, %eax
0x00409b70:	shll %eax, $0x10<UINT8>
0x00409b73:	addl %eax, %ecx
0x00409b75:	movl %ecx, %edx
0x00409b77:	andl %edx, $0x3<UINT8>
0x00409b7a:	shrl %ecx, $0x2<UINT8>
0x00409b7d:	je 6
0x00409b7f:	rep stosl %es:(%edi), %eax
0x00409b81:	testl %edx, %edx
0x00409b83:	je 0x00409b8f
0x00409b85:	movb (%edi), %al
0x00409b87:	addl %edi, $0x1<UINT8>
0x00409b8a:	subl %edx, $0x1<UINT8>
0x00409b8d:	jne -10
0x00409b8f:	movl %eax, 0x8(%esp)
0x00409b93:	popl %edi
0x00409b94:	ret

0x0040791c:	xorl %edx, %edx
0x0040791e:	incl %edx
0x0040791f:	addl %esp, $0xc<UINT8>
0x00407922:	movl 0x4(%ebx), %edi
0x00407925:	movl 0xc(%ebx), %esi
0x00407928:	cmpl -24(%ebp), %edx
0x0040792b:	jbe 248
0x00407931:	cmpb -18(%ebp), $0x0<UINT8>
0x00407935:	je 0x00407a0a
0x00407a0a:	leal %eax, 0x1e(%ebx)
0x00407a0d:	movl %ecx, $0xfe<UINT32>
0x00407a12:	orb (%eax), $0x8<UINT8>
0x00407a15:	incl %eax
0x00407a16:	decl %ecx
0x00407a17:	jne 0x00407a12
0x00407a19:	movl %eax, 0x4(%ebx)
0x00407a1c:	call 0x00407533
0x00407533:	subl %eax, $0x3a4<UINT32>
0x00407538:	je 34
0x0040753a:	subl %eax, $0x4<UINT8>
0x0040753d:	je 23
0x0040753f:	subl %eax, $0xd<UINT8>
0x00407542:	je 12
0x00407544:	decl %eax
0x00407545:	je 3
0x00407547:	xorl %eax, %eax
0x00407549:	ret

0x00407a21:	movl 0xc(%ebx), %eax
0x00407a24:	movl 0x8(%ebx), %edx
0x00407a27:	jmp 0x00407a2c
0x00407a2c:	xorl %eax, %eax
0x00407a2e:	movzwl %ecx, %ax
0x00407a31:	movl %eax, %ecx
0x00407a33:	shll %ecx, $0x10<UINT8>
0x00407a36:	orl %eax, %ecx
0x00407a38:	leal %edi, 0x10(%ebx)
0x00407a3b:	stosl %es:(%edi), %eax
0x00407a3c:	stosl %es:(%edi), %eax
0x00407a3d:	stosl %es:(%edi), %eax
0x00407a3e:	jmp 0x004079e8
0x004079e8:	movl %esi, %ebx
0x004079ea:	call 0x004075c6
0x004075c6:	movl %edi, %edi
0x004075c8:	pushl %ebp
0x004075c9:	movl %ebp, %esp
0x004075cb:	subl %esp, $0x51c<UINT32>
0x004075d1:	movl %eax, 0x418004
0x004075d6:	xorl %eax, %ebp
0x004075d8:	movl -4(%ebp), %eax
0x004075db:	pushl %ebx
0x004075dc:	pushl %edi
0x004075dd:	leal %eax, -1304(%ebp)
0x004075e3:	pushl %eax
0x004075e4:	pushl 0x4(%esi)
0x004075e7:	call GetCPInfo@KERNEL32.DLL
0x004075ed:	movl %edi, $0x100<UINT32>
0x004075f2:	testl %eax, %eax
0x004075f4:	je 251
0x004075fa:	xorl %eax, %eax
0x004075fc:	movb -260(%ebp,%eax), %al
0x00407603:	incl %eax
0x00407604:	cmpl %eax, %edi
0x00407606:	jb 0x004075fc
0x00407608:	movb %al, -1298(%ebp)
0x0040760e:	movb -260(%ebp), $0x20<UINT8>
0x00407615:	testb %al, %al
0x00407617:	je 0x00407647
0x00407647:	pushl $0x0<UINT8>
0x00407649:	pushl 0xc(%esi)
0x0040764c:	leal %eax, -1284(%ebp)
0x00407652:	pushl 0x4(%esi)
0x00407655:	pushl %eax
0x00407656:	pushl %edi
0x00407657:	leal %eax, -260(%ebp)
0x0040765d:	pushl %eax
0x0040765e:	pushl $0x1<UINT8>
0x00407660:	pushl $0x0<UINT8>
0x00407662:	call 0x0040b832
0x0040b832:	movl %edi, %edi
0x0040b834:	pushl %ebp
0x0040b835:	movl %ebp, %esp
0x0040b837:	subl %esp, $0x10<UINT8>
0x0040b83a:	pushl 0x8(%ebp)
0x0040b83d:	leal %ecx, -16(%ebp)
0x0040b840:	call 0x004041db
0x0040b845:	pushl 0x24(%ebp)
0x0040b848:	leal %ecx, -16(%ebp)
0x0040b84b:	pushl 0x20(%ebp)
0x0040b84e:	pushl 0x1c(%ebp)
0x0040b851:	pushl 0x18(%ebp)
0x0040b854:	pushl 0x14(%ebp)
0x0040b857:	pushl 0x10(%ebp)
0x0040b85a:	pushl 0xc(%ebp)
0x0040b85d:	call 0x0040b678
0x0040b678:	movl %edi, %edi
0x0040b67a:	pushl %ebp
0x0040b67b:	movl %ebp, %esp
0x0040b67d:	pushl %ecx
0x0040b67e:	pushl %ecx
0x0040b67f:	movl %eax, 0x418004
0x0040b684:	xorl %eax, %ebp
0x0040b686:	movl -4(%ebp), %eax
0x0040b689:	movl %eax, 0x419cc4
0x0040b68e:	pushl %ebx
0x0040b68f:	pushl %esi
0x0040b690:	xorl %ebx, %ebx
0x0040b692:	pushl %edi
0x0040b693:	movl %edi, %ecx
0x0040b695:	cmpl %eax, %ebx
0x0040b697:	jne 58
0x0040b699:	leal %eax, -8(%ebp)
0x0040b69c:	pushl %eax
0x0040b69d:	xorl %esi, %esi
0x0040b69f:	incl %esi
0x0040b6a0:	pushl %esi
0x0040b6a1:	pushl $0x412b0c<UINT32>
0x0040b6a6:	pushl %esi
0x0040b6a7:	call GetStringTypeW@KERNEL32.DLL
GetStringTypeW@KERNEL32.DLL: API Node	
0x0040b6ad:	testl %eax, %eax
0x0040b6af:	je 8
0x0040b6b1:	movl 0x419cc4, %esi
0x0040b6b7:	jmp 0x0040b6ed
0x0040b6ed:	movl -8(%ebp), %ebx
0x0040b6f0:	cmpl 0x18(%ebp), %ebx
0x0040b6f3:	jne 0x0040b6fd
0x0040b6fd:	movl %esi, 0x4120a0
0x0040b703:	xorl %eax, %eax
0x0040b705:	cmpl 0x20(%ebp), %ebx
0x0040b708:	pushl %ebx
0x0040b709:	pushl %ebx
0x0040b70a:	pushl 0x10(%ebp)
0x0040b70d:	setne %al
0x0040b710:	pushl 0xc(%ebp)
0x0040b713:	leal %eax, 0x1(,%eax,8)
0x0040b71a:	pushl %eax
0x0040b71b:	pushl 0x18(%ebp)
0x0040b71e:	call MultiByteToWideChar@KERNEL32.DLL
MultiByteToWideChar@KERNEL32.DLL: API Node	
0x0040b720:	movl %edi, %eax
0x0040b722:	cmpl %edi, %ebx
0x0040b724:	je 171
0x0040b72a:	jle 60
0x0040b72c:	cmpl %edi, $0x7ffffff0<UINT32>
0x0040b732:	ja 52
0x0040b734:	leal %eax, 0x8(%edi,%edi)
0x0040b738:	cmpl %eax, $0x400<UINT32>
0x0040b73d:	ja 19
0x0040b73f:	call 0x0040d3d0
0x0040d3d0:	pushl %ecx
0x0040d3d1:	leal %ecx, 0x8(%esp)
0x0040d3d5:	subl %ecx, %eax
0x0040d3d7:	andl %ecx, $0xf<UINT8>
0x0040d3da:	addl %eax, %ecx
0x0040d3dc:	sbbl %ecx, %ecx
0x0040d3de:	orl %eax, %ecx
0x0040d3e0:	popl %ecx
0x0040d3e1:	jmp 0x0040c690
0x0040c690:	pushl %ecx
0x0040c691:	leal %ecx, 0x4(%esp)
0x0040c695:	subl %ecx, %eax
0x0040c697:	sbbl %eax, %eax
0x0040c699:	notl %eax
0x0040c69b:	andl %ecx, %eax
0x0040c69d:	movl %eax, %esp
0x0040c69f:	andl %eax, $0xfffff000<UINT32>
0x0040c6a4:	cmpl %ecx, %eax
0x0040c6a6:	jb 10
0x0040c6a8:	movl %eax, %ecx
0x0040c6aa:	popl %ecx
0x0040c6ab:	xchgl %esp, %eax
0x0040c6ac:	movl %eax, (%eax)
0x0040c6ae:	movl (%esp), %eax
0x0040c6b1:	ret

0x0040b744:	movl %eax, %esp
0x0040b746:	cmpl %eax, %ebx
0x0040b748:	je 28
0x0040b74a:	movl (%eax), $0xcccc<UINT32>
0x0040b750:	jmp 0x0040b763
0x0040b763:	addl %eax, $0x8<UINT8>
0x0040b766:	movl %ebx, %eax
0x0040b768:	testl %ebx, %ebx
0x0040b76a:	je 105
0x0040b76c:	leal %eax, (%edi,%edi)
0x0040b76f:	pushl %eax
0x0040b770:	pushl $0x0<UINT8>
0x0040b772:	pushl %ebx
0x0040b773:	call 0x00409b20
0x0040b778:	addl %esp, $0xc<UINT8>
0x0040b77b:	pushl %edi
0x0040b77c:	pushl %ebx
0x0040b77d:	pushl 0x10(%ebp)
0x0040b780:	pushl 0xc(%ebp)
0x0040b783:	pushl $0x1<UINT8>
0x0040b785:	pushl 0x18(%ebp)
0x0040b788:	call MultiByteToWideChar@KERNEL32.DLL
0x0040b78a:	testl %eax, %eax
0x0040b78c:	je 17
0x0040b78e:	pushl 0x14(%ebp)
0x0040b791:	pushl %eax
0x0040b792:	pushl %ebx
0x0040b793:	pushl 0x8(%ebp)
0x0040b796:	call GetStringTypeW@KERNEL32.DLL
0x0040b79c:	movl -8(%ebp), %eax
0x0040b79f:	pushl %ebx
0x0040b7a0:	call 0x0040b26e
0x0040b26e:	movl %edi, %edi
0x0040b270:	pushl %ebp
0x0040b271:	movl %ebp, %esp
0x0040b273:	movl %eax, 0x8(%ebp)
0x0040b276:	testl %eax, %eax
0x0040b278:	je 18
0x0040b27a:	subl %eax, $0x8<UINT8>
0x0040b27d:	cmpl (%eax), $0xdddd<UINT32>
0x0040b283:	jne 0x0040b28c
0x0040b28c:	popl %ebp
0x0040b28d:	ret

0x0040b7a5:	movl %eax, -8(%ebp)
0x0040b7a8:	popl %ecx
0x0040b7a9:	jmp 0x0040b820
0x0040b820:	leal %esp, -20(%ebp)
0x0040b823:	popl %edi
0x0040b824:	popl %esi
0x0040b825:	popl %ebx
0x0040b826:	movl %ecx, -4(%ebp)
0x0040b829:	xorl %ecx, %ebp
0x0040b82b:	call 0x00403c4c
0x00403c4c:	cmpl %ecx, 0x418004
0x00403c52:	jne 2
0x00403c54:	rep ret

0x0040b830:	leave
0x0040b831:	ret

0x0040b862:	addl %esp, $0x1c<UINT8>
0x0040b865:	cmpb -4(%ebp), $0x0<UINT8>
0x0040b869:	je 7
0x0040b86b:	movl %ecx, -8(%ebp)
0x0040b86e:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0040b872:	leave
0x0040b873:	ret

0x00407667:	xorl %ebx, %ebx
0x00407669:	pushl %ebx
0x0040766a:	pushl 0x4(%esi)
0x0040766d:	leal %eax, -516(%ebp)
0x00407673:	pushl %edi
0x00407674:	pushl %eax
0x00407675:	pushl %edi
0x00407676:	leal %eax, -260(%ebp)
0x0040767c:	pushl %eax
0x0040767d:	pushl %edi
0x0040767e:	pushl 0xc(%esi)
0x00407681:	pushl %ebx
0x00407682:	call 0x0040b633
0x0040b633:	movl %edi, %edi
0x0040b635:	pushl %ebp
0x0040b636:	movl %ebp, %esp
0x0040b638:	subl %esp, $0x10<UINT8>
0x0040b63b:	pushl 0x8(%ebp)
0x0040b63e:	leal %ecx, -16(%ebp)
0x0040b641:	call 0x004041db
0x0040b646:	pushl 0x28(%ebp)
0x0040b649:	leal %ecx, -16(%ebp)
0x0040b64c:	pushl 0x24(%ebp)
0x0040b64f:	pushl 0x20(%ebp)
0x0040b652:	pushl 0x1c(%ebp)
0x0040b655:	pushl 0x18(%ebp)
0x0040b658:	pushl 0x14(%ebp)
0x0040b65b:	pushl 0x10(%ebp)
0x0040b65e:	pushl 0xc(%ebp)
0x0040b661:	call 0x0040b28e
0x0040b28e:	movl %edi, %edi
0x0040b290:	pushl %ebp
0x0040b291:	movl %ebp, %esp
0x0040b293:	subl %esp, $0x14<UINT8>
0x0040b296:	movl %eax, 0x418004
0x0040b29b:	xorl %eax, %ebp
0x0040b29d:	movl -4(%ebp), %eax
0x0040b2a0:	pushl %ebx
0x0040b2a1:	pushl %esi
0x0040b2a2:	xorl %ebx, %ebx
0x0040b2a4:	pushl %edi
0x0040b2a5:	movl %esi, %ecx
0x0040b2a7:	cmpl 0x419cc0, %ebx
0x0040b2ad:	jne 0x0040b2e7
0x0040b2af:	pushl %ebx
0x0040b2b0:	pushl %ebx
0x0040b2b1:	xorl %edi, %edi
0x0040b2b3:	incl %edi
0x0040b2b4:	pushl %edi
0x0040b2b5:	pushl $0x412b0c<UINT32>
0x0040b2ba:	pushl $0x100<UINT32>
0x0040b2bf:	pushl %ebx
0x0040b2c0:	call LCMapStringW@KERNEL32.DLL
LCMapStringW@KERNEL32.DLL: API Node	
0x0040b2c6:	testl %eax, %eax
0x0040b2c8:	je 8
0x0040b2ca:	movl 0x419cc0, %edi
0x0040b2d0:	jmp 0x0040b2e7
0x0040b2e7:	cmpl 0x14(%ebp), %ebx
0x0040b2ea:	jle 0x0040b30e
0x0040b30e:	movl %eax, 0x419cc0
0x0040b313:	cmpl %eax, $0x2<UINT8>
0x0040b316:	je 428
0x0040b31c:	cmpl %eax, %ebx
0x0040b31e:	je 420
0x0040b324:	cmpl %eax, $0x1<UINT8>
0x0040b327:	jne 460
0x0040b32d:	movl -8(%ebp), %ebx
0x0040b330:	cmpl 0x20(%ebp), %ebx
0x0040b333:	jne 0x0040b33d
0x0040b33d:	movl %esi, 0x4120a0
0x0040b343:	xorl %eax, %eax
0x0040b345:	cmpl 0x24(%ebp), %ebx
0x0040b348:	pushl %ebx
0x0040b349:	pushl %ebx
0x0040b34a:	pushl 0x14(%ebp)
0x0040b34d:	setne %al
0x0040b350:	pushl 0x10(%ebp)
0x0040b353:	leal %eax, 0x1(,%eax,8)
0x0040b35a:	pushl %eax
0x0040b35b:	pushl 0x20(%ebp)
0x0040b35e:	call MultiByteToWideChar@KERNEL32.DLL
0x0040b360:	movl %edi, %eax
0x0040b362:	cmpl %edi, %ebx
0x0040b364:	je 0x0040b4f9
0x0040b4f9:	xorl %eax, %eax
0x0040b4fb:	jmp 0x0040b621
0x0040b621:	leal %esp, -32(%ebp)
0x0040b624:	popl %edi
0x0040b625:	popl %esi
0x0040b626:	popl %ebx
0x0040b627:	movl %ecx, -4(%ebp)
0x0040b62a:	xorl %ecx, %ebp
0x0040b62c:	call 0x00403c4c
0x0040b631:	leave
0x0040b632:	ret

0x0040b666:	addl %esp, $0x20<UINT8>
0x0040b669:	cmpb -4(%ebp), $0x0<UINT8>
0x0040b66d:	je 7
0x0040b66f:	movl %ecx, -8(%ebp)
0x0040b672:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0040b676:	leave
0x0040b677:	ret

0x00407687:	addl %esp, $0x44<UINT8>
0x0040768a:	pushl %ebx
0x0040768b:	pushl 0x4(%esi)
0x0040768e:	leal %eax, -772(%ebp)
0x00407694:	pushl %edi
0x00407695:	pushl %eax
0x00407696:	pushl %edi
0x00407697:	leal %eax, -260(%ebp)
0x0040769d:	pushl %eax
0x0040769e:	pushl $0x200<UINT32>
0x004076a3:	pushl 0xc(%esi)
0x004076a6:	pushl %ebx
0x004076a7:	call 0x0040b633
0x004076ac:	addl %esp, $0x24<UINT8>
0x004076af:	xorl %eax, %eax
0x004076b1:	movzwl %ecx, -1284(%ebp,%eax,2)
0x004076b9:	testb %cl, $0x1<UINT8>
0x004076bc:	je 0x004076cc
0x004076cc:	testb %cl, $0x2<UINT8>
0x004076cf:	je 0x004076e6
0x004076e6:	movb 0x11d(%esi,%eax), $0x0<UINT8>
0x004076ee:	incl %eax
0x004076ef:	cmpl %eax, %edi
0x004076f1:	jb -66
0x004076f3:	jmp 0x0040774b
0x0040774b:	movl %ecx, -4(%ebp)
0x0040774e:	popl %edi
0x0040774f:	xorl %ecx, %ebp
0x00407751:	popl %ebx
0x00407752:	call 0x00403c4c
0x00407757:	leave
0x00407758:	ret

0x004079ef:	jmp 0x004078ab
0x004078ab:	xorl %eax, %eax
0x004078ad:	jmp 0x00407a4f
0x00407a4f:	movl %ecx, -4(%ebp)
0x00407a52:	popl %edi
0x00407a53:	popl %esi
0x00407a54:	xorl %ecx, %ebp
0x00407a56:	popl %ebx
0x00407a57:	call 0x00403c4c
0x00407a5c:	leave
0x00407a5d:	ret

0x00407ac1:	popl %ecx
0x00407ac2:	popl %ecx
0x00407ac3:	movl -32(%ebp), %eax
0x00407ac6:	testl %eax, %eax
0x00407ac8:	jne 252
0x00407ace:	movl %esi, -36(%ebp)
0x00407ad1:	pushl 0x68(%esi)
0x00407ad4:	call InterlockedDecrement@KERNEL32.DLL
InterlockedDecrement@KERNEL32.DLL: API Node	
0x00407ada:	testl %eax, %eax
0x00407adc:	jne 17
0x00407ade:	movl %eax, 0x68(%esi)
0x00407ae1:	cmpl %eax, $0x4182c8<UINT32>
0x00407ae6:	je 0x00407aef
0x00407aef:	movl 0x68(%esi), %ebx
0x00407af2:	pushl %ebx
0x00407af3:	movl %edi, 0x41210c
0x00407af9:	call InterlockedIncrement@KERNEL32.DLL
0x00407afb:	testb 0x70(%esi), $0x2<UINT8>
0x00407aff:	jne 234
0x00407b05:	testb 0x4187ec, $0x1<UINT8>
0x00407b0c:	jne 221
0x00407b12:	pushl $0xd<UINT8>
0x00407b14:	call 0x00405a3b
0x00407b19:	popl %ecx
0x00407b1a:	andl -4(%ebp), $0x0<UINT8>
0x00407b1e:	movl %eax, 0x4(%ebx)
0x00407b21:	movl 0x41982c, %eax
0x00407b26:	movl %eax, 0x8(%ebx)
0x00407b29:	movl 0x419830, %eax
0x00407b2e:	movl %eax, 0xc(%ebx)
0x00407b31:	movl 0x419834, %eax
0x00407b36:	xorl %eax, %eax
0x00407b38:	movl -28(%ebp), %eax
0x00407b3b:	cmpl %eax, $0x5<UINT8>
0x00407b3e:	jnl 0x00407b50
0x00407b40:	movw %cx, 0x10(%ebx,%eax,2)
0x00407b45:	movw 0x419820(,%eax,2), %cx
0x00407b4d:	incl %eax
0x00407b4e:	jmp 0x00407b38
0x00407b50:	xorl %eax, %eax
0x00407b52:	movl -28(%ebp), %eax
0x00407b55:	cmpl %eax, $0x101<UINT32>
0x00407b5a:	jnl 0x00407b69
0x00407b5c:	movb %cl, 0x1c(%eax,%ebx)
0x00407b60:	movb 0x4184e8(%eax), %cl
0x00407b66:	incl %eax
0x00407b67:	jmp 0x00407b52
0x00407b69:	xorl %eax, %eax
0x00407b6b:	movl -28(%ebp), %eax
0x00407b6e:	cmpl %eax, $0x100<UINT32>
0x00407b73:	jnl 0x00407b85
0x00407b75:	movb %cl, 0x11d(%eax,%ebx)
0x00407b7c:	movb 0x4185f0(%eax), %cl
0x00407b82:	incl %eax
0x00407b83:	jmp 0x00407b6b
0x00407b85:	pushl 0x4186f0
0x00407b8b:	call InterlockedDecrement@KERNEL32.DLL
0x00407b91:	testl %eax, %eax
0x00407b93:	jne 0x00407ba8
0x00407ba8:	movl 0x4186f0, %ebx
0x00407bae:	pushl %ebx
0x00407baf:	call InterlockedIncrement@KERNEL32.DLL
0x00407bb1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00407bb8:	call 0x00407bbf
0x00407bbf:	pushl $0xd<UINT8>
0x00407bc1:	call 0x00405961
0x00407bc6:	popl %ecx
0x00407bc7:	ret

0x00407bbd:	jmp 0x00407bef
0x00407bef:	movl %eax, -32(%ebp)
0x00407bf2:	call 0x00406579
0x00407bf7:	ret

0x00407c08:	popl %ecx
0x00407c09:	movl 0x41afac, $0x1<UINT32>
0x00407c13:	xorl %eax, %eax
0x00407c15:	ret

0x0040854c:	pushl $0x104<UINT32>
0x00408551:	movl %esi, $0x419b80<UINT32>
0x00408556:	pushl %esi
0x00408557:	pushl %ebx
0x00408558:	movb 0x419c84, %bl
0x0040855e:	call GetModuleFileNameA@KERNEL32.DLL
GetModuleFileNameA@KERNEL32.DLL: API Node	
0x00408564:	movl %eax, 0x41afd4
0x00408569:	movl 0x419804, %esi
0x0040856f:	cmpl %eax, %ebx
0x00408571:	je 7
0x00408573:	movl -4(%ebp), %eax
0x00408576:	cmpb (%eax), %bl
0x00408578:	jne 0x0040857d
0x0040857d:	movl %edx, -4(%ebp)
0x00408580:	leal %eax, -8(%ebp)
0x00408583:	pushl %eax
0x00408584:	pushl %ebx
0x00408585:	pushl %ebx
0x00408586:	leal %edi, -12(%ebp)
0x00408589:	call 0x00408398
0x00408398:	movl %edi, %edi
0x0040839a:	pushl %ebp
0x0040839b:	movl %ebp, %esp
0x0040839d:	pushl %ecx
0x0040839e:	movl %ecx, 0x10(%ebp)
0x004083a1:	pushl %ebx
0x004083a2:	xorl %eax, %eax
0x004083a4:	pushl %esi
0x004083a5:	movl (%edi), %eax
0x004083a7:	movl %esi, %edx
0x004083a9:	movl %edx, 0xc(%ebp)
0x004083ac:	movl (%ecx), $0x1<UINT32>
0x004083b2:	cmpl 0x8(%ebp), %eax
0x004083b5:	je 0x004083c0
0x004083c0:	movl -4(%ebp), %eax
0x004083c3:	cmpb (%esi), $0x22<UINT8>
0x004083c6:	jne 0x004083d8
0x004083c8:	xorl %eax, %eax
0x004083ca:	cmpl -4(%ebp), %eax
0x004083cd:	movb %bl, $0x22<UINT8>
0x004083cf:	sete %al
0x004083d2:	incl %esi
0x004083d3:	movl -4(%ebp), %eax
0x004083d6:	jmp 0x00408414
0x00408414:	cmpl -4(%ebp), $0x0<UINT8>
0x00408418:	jne 0x004083c3
0x004083d8:	incl (%edi)
0x004083da:	testl %edx, %edx
0x004083dc:	je 0x004083e6
0x004083e6:	movb %bl, (%esi)
0x004083e8:	movzbl %eax, %bl
0x004083eb:	pushl %eax
0x004083ec:	incl %esi
0x004083ed:	call 0x0040c3e8
0x0040c3e8:	movl %edi, %edi
0x0040c3ea:	pushl %ebp
0x0040c3eb:	movl %ebp, %esp
0x0040c3ed:	pushl $0x4<UINT8>
0x0040c3ef:	pushl $0x0<UINT8>
0x0040c3f1:	pushl 0x8(%ebp)
0x0040c3f4:	pushl $0x0<UINT8>
0x0040c3f6:	call 0x0040c395
0x0040c395:	movl %edi, %edi
0x0040c397:	pushl %ebp
0x0040c398:	movl %ebp, %esp
0x0040c39a:	subl %esp, $0x10<UINT8>
0x0040c39d:	pushl 0x8(%ebp)
0x0040c3a0:	leal %ecx, -16(%ebp)
0x0040c3a3:	call 0x004041db
0x0040c3a8:	movzbl %eax, 0xc(%ebp)
0x0040c3ac:	movl %ecx, -12(%ebp)
0x0040c3af:	movb %dl, 0x14(%ebp)
0x0040c3b2:	testb 0x1d(%ecx,%eax), %dl
0x0040c3b6:	jne 30
0x0040c3b8:	cmpl 0x10(%ebp), $0x0<UINT8>
0x0040c3bc:	je 0x0040c3d0
0x0040c3d0:	xorl %eax, %eax
0x0040c3d2:	testl %eax, %eax
0x0040c3d4:	je 0x0040c3d9
0x0040c3d9:	cmpb -4(%ebp), $0x0<UINT8>
0x0040c3dd:	je 7
0x0040c3df:	movl %ecx, -8(%ebp)
0x0040c3e2:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0040c3e6:	leave
0x0040c3e7:	ret

0x0040c3fb:	addl %esp, $0x10<UINT8>
0x0040c3fe:	popl %ebp
0x0040c3ff:	ret

0x004083f2:	popl %ecx
0x004083f3:	testl %eax, %eax
0x004083f5:	je 0x0040840a
0x0040840a:	movl %edx, 0xc(%ebp)
0x0040840d:	movl %ecx, 0x10(%ebp)
0x00408410:	testb %bl, %bl
0x00408412:	je 0x00408446
0x0040841a:	cmpb %bl, $0x20<UINT8>
0x0040841d:	je 5
0x0040841f:	cmpb %bl, $0x9<UINT8>
0x00408422:	jne 0x004083c3
0x00408446:	decl %esi
0x00408447:	jmp 0x0040842c
0x0040842c:	andl -4(%ebp), $0x0<UINT8>
0x00408430:	cmpb (%esi), $0x0<UINT8>
0x00408433:	je 0x00408522
0x00408522:	movl %eax, 0x8(%ebp)
0x00408525:	popl %esi
0x00408526:	popl %ebx
0x00408527:	testl %eax, %eax
0x00408529:	je 0x0040852e
0x0040852e:	incl (%ecx)
0x00408530:	leave
0x00408531:	ret

0x0040858e:	movl %eax, -8(%ebp)
0x00408591:	addl %esp, $0xc<UINT8>
0x00408594:	cmpl %eax, $0x3fffffff<UINT32>
0x00408599:	jae 74
0x0040859b:	movl %ecx, -12(%ebp)
0x0040859e:	cmpl %ecx, $0xffffffff<UINT8>
0x004085a1:	jae 66
0x004085a3:	movl %edi, %eax
0x004085a5:	shll %edi, $0x2<UINT8>
0x004085a8:	leal %eax, (%edi,%ecx)
0x004085ab:	cmpl %eax, %ecx
0x004085ad:	jb 54
0x004085af:	pushl %eax
0x004085b0:	call 0x00407357
0x004085b5:	movl %esi, %eax
0x004085b7:	popl %ecx
0x004085b8:	cmpl %esi, %ebx
0x004085ba:	je 41
0x004085bc:	movl %edx, -4(%ebp)
0x004085bf:	leal %eax, -8(%ebp)
0x004085c2:	pushl %eax
0x004085c3:	addl %edi, %esi
0x004085c5:	pushl %edi
0x004085c6:	pushl %esi
0x004085c7:	leal %edi, -12(%ebp)
0x004085ca:	call 0x00408398
0x004083b7:	movl %ebx, 0x8(%ebp)
0x004083ba:	addl 0x8(%ebp), $0x4<UINT8>
0x004083be:	movl (%ebx), %edx
0x004083de:	movb %al, (%esi)
0x004083e0:	movb (%edx), %al
0x004083e2:	incl %edx
0x004083e3:	movl 0xc(%ebp), %edx
0x0040852b:	andl (%eax), $0x0<UINT8>
0x004085cf:	movl %eax, -8(%ebp)
0x004085d2:	addl %esp, $0xc<UINT8>
0x004085d5:	decl %eax
0x004085d6:	movl 0x4197e8, %eax
0x004085db:	movl 0x4197ec, %esi
0x004085e1:	xorl %eax, %eax
0x004085e3:	jmp 0x004085e8
0x004085e8:	popl %edi
0x004085e9:	popl %esi
0x004085ea:	popl %ebx
0x004085eb:	leave
0x004085ec:	ret

0x0040460c:	testl %eax, %eax
0x0040460e:	jnl 0x00404618
0x00404618:	call 0x004082ba
0x004082ba:	cmpl 0x41afac, $0x0<UINT8>
0x004082c1:	jne 0x004082c8
0x004082c8:	pushl %esi
0x004082c9:	movl %esi, 0x419340
0x004082cf:	pushl %edi
0x004082d0:	xorl %edi, %edi
0x004082d2:	testl %esi, %esi
0x004082d4:	jne 0x004082ee
0x004082ee:	movb %al, (%esi)
0x004082f0:	testb %al, %al
0x004082f2:	jne 0x004082de
0x004082de:	cmpb %al, $0x3d<UINT8>
0x004082e0:	je 0x004082e3
0x004082e3:	pushl %esi
0x004082e4:	call 0x00409870
0x00409870:	movl %ecx, 0x4(%esp)
0x00409874:	testl %ecx, $0x3<UINT32>
0x0040987a:	je 0x004098a0
0x004098a0:	movl %eax, (%ecx)
0x004098a2:	movl %edx, $0x7efefeff<UINT32>
0x004098a7:	addl %edx, %eax
0x004098a9:	xorl %eax, $0xffffffff<UINT8>
0x004098ac:	xorl %eax, %edx
0x004098ae:	addl %ecx, $0x4<UINT8>
0x004098b1:	testl %eax, $0x81010100<UINT32>
0x004098b6:	je 0x004098a0
0x004098b8:	movl %eax, -4(%ecx)
0x004098bb:	testb %al, %al
0x004098bd:	je 50
0x004098bf:	testb %ah, %ah
0x004098c1:	je 36
0x004098c3:	testl %eax, $0xff0000<UINT32>
0x004098c8:	je 19
0x004098ca:	testl %eax, $0xff000000<UINT32>
0x004098cf:	je 0x004098d3
0x004098d3:	leal %eax, -1(%ecx)
0x004098d6:	movl %ecx, 0x4(%esp)
0x004098da:	subl %eax, %ecx
0x004098dc:	ret

0x004082e9:	popl %ecx
0x004082ea:	leal %esi, 0x1(%esi,%eax)
0x004082f4:	pushl $0x4<UINT8>
0x004082f6:	incl %edi
0x004082f7:	pushl %edi
0x004082f8:	call 0x0040739c
0x004082fd:	movl %edi, %eax
0x004082ff:	popl %ecx
0x00408300:	popl %ecx
0x00408301:	movl 0x4197f4, %edi
0x00408307:	testl %edi, %edi
0x00408309:	je -53
0x0040830b:	movl %esi, 0x419340
0x00408311:	pushl %ebx
0x00408312:	jmp 0x00408356
0x00408356:	cmpb (%esi), $0x0<UINT8>
0x00408359:	jne 0x00408314
0x00408314:	pushl %esi
0x00408315:	call 0x00409870
0x0040831a:	movl %ebx, %eax
0x0040831c:	incl %ebx
0x0040831d:	cmpb (%esi), $0x3d<UINT8>
0x00408320:	popl %ecx
0x00408321:	je 0x00408354
0x00408354:	addl %esi, %ebx
0x0040835b:	pushl 0x419340
0x00408361:	call 0x00403d11
0x00403d11:	pushl $0xc<UINT8>
0x00403d13:	pushl $0x416330<UINT32>
0x00403d18:	call 0x00406534
0x00403d1d:	movl %esi, 0x8(%ebp)
0x00403d20:	testl %esi, %esi
0x00403d22:	je 117
0x00403d24:	cmpl 0x41afd0, $0x3<UINT8>
0x00403d2b:	jne 0x00403d70
0x00403d70:	pushl %esi
0x00403d71:	pushl $0x0<UINT8>
0x00403d73:	pushl 0x419678
0x00403d79:	call HeapFree@KERNEL32.DLL
HeapFree@KERNEL32.DLL: API Node	
0x00403d7f:	testl %eax, %eax
0x00403d81:	jne 0x00403d99
0x00403d99:	call 0x00406579
0x00403d9e:	ret

0x00408366:	andl 0x419340, $0x0<UINT8>
0x0040836d:	andl (%edi), $0x0<UINT8>
0x00408370:	movl 0x41afa0, $0x1<UINT32>
0x0040837a:	xorl %eax, %eax
0x0040837c:	popl %ecx
0x0040837d:	popl %ebx
0x0040837e:	popl %edi
0x0040837f:	popl %esi
0x00408380:	ret

0x0040461d:	testl %eax, %eax
0x0040461f:	jnl 0x00404629
0x00404629:	pushl %ebx
0x0040462a:	call 0x00406fad
0x00406fad:	movl %edi, %edi
0x00406faf:	pushl %ebp
0x00406fb0:	movl %ebp, %esp
0x00406fb2:	cmpl 0x416210, $0x0<UINT8>
0x00406fb9:	je 25
0x00406fbb:	pushl $0x416210<UINT32>
0x00406fc0:	call 0x00406e00
0x00406e00:	movl %edi, %edi
0x00406e02:	pushl %ebp
0x00406e03:	movl %ebp, %esp
0x00406e05:	pushl $0xfffffffe<UINT8>
0x00406e07:	pushl $0x416448<UINT32>
0x00406e0c:	pushl $0x406590<UINT32>
0x00406e11:	movl %eax, %fs:0
0x00406e17:	pushl %eax
0x00406e18:	subl %esp, $0x8<UINT8>
0x00406e1b:	pushl %ebx
0x00406e1c:	pushl %esi
0x00406e1d:	pushl %edi
0x00406e1e:	movl %eax, 0x418004
0x00406e23:	xorl -8(%ebp), %eax
0x00406e26:	xorl %eax, %ebp
0x00406e28:	pushl %eax
0x00406e29:	leal %eax, -16(%ebp)
0x00406e2c:	movl %fs:0, %eax
0x00406e32:	movl -24(%ebp), %esp
0x00406e35:	movl -4(%ebp), $0x0<UINT32>
0x00406e3c:	pushl $0x400000<UINT32>
0x00406e41:	call 0x00406d70
0x00406d70:	movl %edi, %edi
0x00406d72:	pushl %ebp
0x00406d73:	movl %ebp, %esp
0x00406d75:	movl %ecx, 0x8(%ebp)
0x00406d78:	movl %eax, $0x5a4d<UINT32>
0x00406d7d:	cmpw (%ecx), %ax
0x00406d80:	je 0x00406d86
0x00406d86:	movl %eax, 0x3c(%ecx)
0x00406d89:	addl %eax, %ecx
0x00406d8b:	cmpl (%eax), $0x4550<UINT32>
0x00406d91:	jne -17
0x00406d93:	xorl %edx, %edx
0x00406d95:	movl %ecx, $0x10b<UINT32>
0x00406d9a:	cmpw 0x18(%eax), %cx
0x00406d9e:	sete %dl
0x00406da1:	movl %eax, %edx
0x00406da3:	popl %ebp
0x00406da4:	ret

0x00406e46:	addl %esp, $0x4<UINT8>
0x00406e49:	testl %eax, %eax
0x00406e4b:	je 85
0x00406e4d:	movl %eax, 0x8(%ebp)
0x00406e50:	subl %eax, $0x400000<UINT32>
0x00406e55:	pushl %eax
0x00406e56:	pushl $0x400000<UINT32>
0x00406e5b:	call 0x00406db0
0x00406db0:	movl %edi, %edi
0x00406db2:	pushl %ebp
0x00406db3:	movl %ebp, %esp
0x00406db5:	movl %eax, 0x8(%ebp)
0x00406db8:	movl %ecx, 0x3c(%eax)
0x00406dbb:	addl %ecx, %eax
0x00406dbd:	movzwl %eax, 0x14(%ecx)
0x00406dc1:	pushl %ebx
0x00406dc2:	pushl %esi
0x00406dc3:	movzwl %esi, 0x6(%ecx)
0x00406dc7:	xorl %edx, %edx
0x00406dc9:	pushl %edi
0x00406dca:	leal %eax, 0x18(%eax,%ecx)
0x00406dce:	testl %esi, %esi
0x00406dd0:	jbe 27
0x00406dd2:	movl %edi, 0xc(%ebp)
0x00406dd5:	movl %ecx, 0xc(%eax)
0x00406dd8:	cmpl %edi, %ecx
0x00406dda:	jb 9
0x00406ddc:	movl %ebx, 0x8(%eax)
0x00406ddf:	addl %ebx, %ecx
0x00406de1:	cmpl %edi, %ebx
0x00406de3:	jb 0x00406def
0x00406def:	popl %edi
0x00406df0:	popl %esi
0x00406df1:	popl %ebx
0x00406df2:	popl %ebp
0x00406df3:	ret

0x00406e60:	addl %esp, $0x8<UINT8>
0x00406e63:	testl %eax, %eax
0x00406e65:	je 59
0x00406e67:	movl %eax, 0x24(%eax)
0x00406e6a:	shrl %eax, $0x1f<UINT8>
0x00406e6d:	notl %eax
0x00406e6f:	andl %eax, $0x1<UINT8>
0x00406e72:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00406e79:	movl %ecx, -16(%ebp)
0x00406e7c:	movl %fs:0, %ecx
0x00406e83:	popl %ecx
0x00406e84:	popl %edi
0x00406e85:	popl %esi
0x00406e86:	popl %ebx
0x00406e87:	movl %esp, %ebp
0x00406e89:	popl %ebp
0x00406e8a:	ret

0x00406fc5:	popl %ecx
0x00406fc6:	testl %eax, %eax
0x00406fc8:	je 10
0x00406fca:	pushl 0x8(%ebp)
0x00406fcd:	call 0x0040de44
0x0040de44:	movl %edi, %edi
0x0040de46:	pushl %ebp
0x0040de47:	movl %ebp, %esp
0x0040de49:	call 0x0040dde4
0x0040dde4:	movl %eax, $0x40e9d3<UINT32>
0x0040dde9:	movl 0x418c60, %eax
0x0040ddee:	movl 0x418c64, $0x40e0ba<UINT32>
0x0040ddf8:	movl 0x418c68, $0x40e06e<UINT32>
0x0040de02:	movl 0x418c6c, $0x40e0a7<UINT32>
0x0040de0c:	movl 0x418c70, $0x40e010<UINT32>
0x0040de16:	movl 0x418c74, %eax
0x0040de1b:	movl 0x418c78, $0x40e94b<UINT32>
0x0040de25:	movl 0x418c7c, $0x40e02c<UINT32>
0x0040de2f:	movl 0x418c80, $0x40df8e<UINT32>
0x0040de39:	movl 0x418c84, $0x40df1b<UINT32>
0x0040de43:	ret

0x0040de4e:	call 0x0040ea5f
0x0040ea5f:	pushl $0x416254<UINT32>
0x0040ea64:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x0040ea6a:	testl %eax, %eax
0x0040ea6c:	je 21
0x0040ea6e:	pushl $0x416238<UINT32>
0x0040ea73:	pushl %eax
0x0040ea74:	call GetProcAddress@KERNEL32.DLL
0x0040ea7a:	testl %eax, %eax
0x0040ea7c:	je 5
0x0040ea7e:	pushl $0x0<UINT8>
0x0040ea80:	call IsProcessorFeaturePresent@KERNEL32
IsProcessorFeaturePresent@KERNEL32: API Node	
0x0040ea82:	ret

0x0040de53:	cmpl 0x8(%ebp), $0x0<UINT8>
0x0040de57:	movl 0x419e70, %eax
0x0040de5c:	je 5
0x0040de5e:	call 0x0040e9f6
0x0040e9f6:	movl %edi, %edi
0x0040e9f8:	pushl %esi
0x0040e9f9:	pushl $0x30000<UINT32>
0x0040e9fe:	pushl $0x10000<UINT32>
0x0040ea03:	xorl %esi, %esi
0x0040ea05:	pushl %esi
0x0040ea06:	call 0x0040ef1f
0x0040ef1f:	movl %edi, %edi
0x0040ef21:	pushl %ebp
0x0040ef22:	movl %ebp, %esp
0x0040ef24:	movl %eax, 0x10(%ebp)
0x0040ef27:	movl %ecx, 0xc(%ebp)
0x0040ef2a:	andl %eax, $0xfff7ffff<UINT32>
0x0040ef2f:	andl %ecx, %eax
0x0040ef31:	pushl %esi
0x0040ef32:	testl %ecx, $0xfcf0fce0<UINT32>
0x0040ef38:	je 0x0040ef6b
0x0040ef6b:	movl %esi, 0x8(%ebp)
0x0040ef6e:	pushl %eax
0x0040ef6f:	pushl 0xc(%ebp)
0x0040ef72:	testl %esi, %esi
0x0040ef74:	je 0x0040ef7f
0x0040ef7f:	call 0x00410b60
0x00410b60:	movl %edi, %edi
0x00410b62:	pushl %ebp
0x00410b63:	movl %ebp, %esp
0x00410b65:	subl %esp, $0x14<UINT8>
0x00410b68:	pushl %ebx
0x00410b69:	pushl %esi
0x00410b6a:	pushl %edi
0x00410b6b:	fwait
0x00410b6c:	fnstcw -8(%ebp)
0x00410b6f:	movl %ebx, -8(%ebp)
0x00410b72:	xorl %edx, %edx
0x00410b74:	testb %bl, $0x1<UINT8>
0x00410b77:	je 0x00410b7c
0x00410b7c:	testb %bl, $0x4<UINT8>
0x00410b7f:	je 3
0x00410b81:	orl %edx, $0x8<UINT8>
0x00410b84:	testb %bl, $0x8<UINT8>
0x00410b87:	je 3
0x00410b89:	orl %edx, $0x4<UINT8>
0x00410b8c:	testb %bl, $0x10<UINT8>
0x00410b8f:	je 0x00410b94
0x00410b94:	testb %bl, $0x20<UINT8>
0x00410b97:	je 3
0x00410b99:	orl %edx, $0x1<UINT8>
0x00410b9c:	testb %bl, $0x2<UINT8>
0x00410b9f:	je 0x00410ba7
0x00410ba7:	movzwl %ecx, %bx
0x00410baa:	movl %eax, %ecx
0x00410bac:	movl %esi, $0xc00<UINT32>
0x00410bb1:	andl %eax, %esi
0x00410bb3:	movl %edi, $0x300<UINT32>
0x00410bb8:	je 36
0x00410bba:	cmpl %eax, $0x400<UINT32>
0x00410bbf:	je 23
0x00410bc1:	cmpl %eax, $0x800<UINT32>
0x00410bc6:	je 8
0x00410bc8:	cmpl %eax, %esi
0x00410bca:	jne 18
0x00410bcc:	orl %edx, %edi
0x00410bce:	jmp 0x00410bde
0x00410bde:	andl %ecx, %edi
0x00410be0:	je 16
0x00410be2:	cmpl %ecx, $0x200<UINT32>
0x00410be8:	jne 14
0x00410bea:	orl %edx, $0x10000<UINT32>
0x00410bf0:	jmp 0x00410bf8
0x00410bf8:	testl %ebx, $0x1000<UINT32>
0x00410bfe:	je 6
0x00410c00:	orl %edx, $0x40000<UINT32>
0x00410c06:	movl %edi, 0xc(%ebp)
0x00410c09:	movl %ecx, 0x8(%ebp)
0x00410c0c:	movl %eax, %edi
0x00410c0e:	notl %eax
0x00410c10:	andl %eax, %edx
0x00410c12:	andl %ecx, %edi
0x00410c14:	orl %eax, %ecx
0x00410c16:	movl 0xc(%ebp), %eax
0x00410c19:	cmpl %eax, %edx
0x00410c1b:	je 0x00410ccf
0x00410ccf:	xorl %esi, %esi
0x00410cd1:	cmpl 0x419e78, %esi
0x00410cd7:	je 0x00410e6a
0x00410e6a:	popl %edi
0x00410e6b:	popl %esi
0x00410e6c:	popl %ebx
0x00410e6d:	leave
0x00410e6e:	ret

0x0040ef84:	popl %ecx
0x0040ef85:	popl %ecx
0x0040ef86:	xorl %eax, %eax
0x0040ef88:	popl %esi
0x0040ef89:	popl %ebp
0x0040ef8a:	ret

0x0040ea0b:	addl %esp, $0xc<UINT8>
0x0040ea0e:	testl %eax, %eax
0x0040ea10:	je 0x0040ea1f
0x0040ea1f:	popl %esi
0x0040ea20:	ret

0x0040de63:	fnclex
0x0040de65:	popl %ebp
0x0040de66:	ret

0x00406fd3:	popl %ecx
0x00406fd4:	call 0x0040982a
0x0040982a:	movl %edi, %edi
0x0040982c:	pushl %esi
0x0040982d:	pushl %edi
0x0040982e:	xorl %edi, %edi
0x00409830:	leal %esi, 0x418c60(%edi)
0x00409836:	pushl (%esi)
0x00409838:	call 0x0040671c
0x0040673e:	pushl %eax
0x0040673f:	pushl 0x4182ac
0x00406745:	call TlsGetValue@KERNEL32.DLL
0x00406747:	call FlsGetValue@KERNEL32.DLL
0x00406749:	testl %eax, %eax
0x0040674b:	je 8
0x0040674d:	movl %eax, 0x1f8(%eax)
0x00406753:	jmp 0x0040677c
0x0040983d:	addl %edi, $0x4<UINT8>
0x00409840:	popl %ecx
0x00409841:	movl (%esi), %eax
0x00409843:	cmpl %edi, $0x28<UINT8>
0x00409846:	jb 0x00409830
0x00409848:	popl %edi
0x00409849:	popl %esi
0x0040984a:	ret

0x00406fd9:	pushl $0x4122f8<UINT32>
0x00406fde:	pushl $0x4122e0<UINT32>
0x00406fe3:	call 0x00406f88
0x00406f88:	movl %edi, %edi
0x00406f8a:	pushl %ebp
0x00406f8b:	movl %ebp, %esp
0x00406f8d:	pushl %esi
0x00406f8e:	movl %esi, 0x8(%ebp)
0x00406f91:	xorl %eax, %eax
0x00406f93:	jmp 0x00406fa4
0x00406fa4:	cmpl %esi, 0xc(%ebp)
0x00406fa7:	jb 0x00406f95
0x00406f95:	testl %eax, %eax
0x00406f97:	jne 16
0x00406f99:	movl %ecx, (%esi)
0x00406f9b:	testl %ecx, %ecx
0x00406f9d:	je 0x00406fa1
0x00406fa1:	addl %esi, $0x4<UINT8>
0x00406f9f:	call 0x0040824d
0x00404013:	movl %edi, %edi
0x00404015:	pushl %esi
0x00404016:	pushl $0x4<UINT8>
0x00404018:	pushl $0x20<UINT8>
0x0040401a:	call 0x0040739c
0x0040401f:	movl %esi, %eax
0x00404021:	pushl %esi
0x00404022:	call 0x0040671c
0x00404027:	addl %esp, $0xc<UINT8>
0x0040402a:	movl 0x41afa8, %eax
0x0040402f:	movl 0x41afa4, %eax
0x00404034:	testl %esi, %esi
0x00404036:	jne 0x0040403d
0x0040403d:	andl (%esi), $0x0<UINT8>
0x00404040:	xorl %eax, %eax
0x00404042:	popl %esi
0x00404043:	ret

0x004094c2:	movl %eax, 0x41ae80
0x004094c7:	pushl %esi
0x004094c8:	pushl $0x14<UINT8>
0x004094ca:	popl %esi
0x004094cb:	testl %eax, %eax
0x004094cd:	jne 7
0x004094cf:	movl %eax, $0x200<UINT32>
0x004094d4:	jmp 0x004094dc
0x004094dc:	movl 0x41ae80, %eax
0x004094e1:	pushl $0x4<UINT8>
0x004094e3:	pushl %eax
0x004094e4:	call 0x0040739c
0x004094e9:	popl %ecx
0x004094ea:	popl %ecx
0x004094eb:	movl 0x419e7c, %eax
0x004094f0:	testl %eax, %eax
0x004094f2:	jne 0x00409512
0x00409512:	xorl %edx, %edx
0x00409514:	movl %ecx, $0x4189d8<UINT32>
0x00409519:	jmp 0x00409520
0x00409520:	movl (%edx,%eax), %ecx
0x00409523:	addl %ecx, $0x20<UINT8>
0x00409526:	addl %edx, $0x4<UINT8>
0x00409529:	cmpl %ecx, $0x418c58<UINT32>
0x0040952f:	jl 0x0040951b
0x0040951b:	movl %eax, 0x419e7c
0x00409531:	pushl $0xfffffffe<UINT8>
0x00409533:	popl %esi
0x00409534:	xorl %edx, %edx
0x00409536:	movl %ecx, $0x4189e8<UINT32>
0x0040953b:	pushl %edi
0x0040953c:	movl %eax, %edx
0x0040953e:	sarl %eax, $0x5<UINT8>
0x00409541:	movl %eax, 0x41aea0(,%eax,4)
0x00409548:	movl %edi, %edx
0x0040954a:	andl %edi, $0x1f<UINT8>
0x0040954d:	shll %edi, $0x6<UINT8>
0x00409550:	movl %eax, (%edi,%eax)
0x00409553:	cmpl %eax, $0xffffffff<UINT8>
0x00409556:	je 8
0x00409558:	cmpl %eax, %esi
0x0040955a:	je 4
0x0040955c:	testl %eax, %eax
0x0040955e:	jne 0x00409562
0x00409562:	addl %ecx, $0x20<UINT8>
0x00409565:	incl %edx
0x00409566:	cmpl %ecx, $0x418a48<UINT32>
0x0040956c:	jl 0x0040953c
0x0040956e:	popl %edi
0x0040956f:	xorl %eax, %eax
0x00409571:	popl %esi
0x00409572:	ret

0x0040cd8b:	call 0x0040cd29
0x0040cd29:	movl %edi, %edi
0x0040cd2b:	pushl %ebp
0x0040cd2c:	movl %ebp, %esp
0x0040cd2e:	subl %esp, $0x18<UINT8>
0x0040cd31:	xorl %eax, %eax
0x0040cd33:	pushl %ebx
0x0040cd34:	movl -4(%ebp), %eax
0x0040cd37:	movl -12(%ebp), %eax
0x0040cd3a:	movl -8(%ebp), %eax
0x0040cd3d:	pushl %ebx
0x0040cd3e:	pushfl
0x0040cd3f:	popl %eax
0x0040cd40:	movl %ecx, %eax
0x0040cd42:	xorl %eax, $0x200000<UINT32>
0x0040cd47:	pushl %eax
0x0040cd48:	popfl
0x0040cd49:	pushfl
0x0040cd4a:	popl %edx
0x0040cd4b:	subl %edx, %ecx
0x0040cd4d:	je 0x0040cd6e
0x0040cd6e:	popl %ebx
0x0040cd6f:	testl -4(%ebp), $0x4000000<UINT32>
0x0040cd76:	je 0x0040cd86
0x0040cd86:	xorl %eax, %eax
0x0040cd88:	popl %ebx
0x0040cd89:	leave
0x0040cd8a:	ret

0x0040cd90:	movl 0x419e78, %eax
0x0040cd95:	xorl %eax, %eax
0x0040cd97:	ret

0x0040824d:	pushl $0x40820b<UINT32>
0x00408252:	call SetUnhandledExceptionFilter@KERNEL32.DLL
SetUnhandledExceptionFilter@KERNEL32.DLL: API Node	
0x00408258:	xorl %eax, %eax
0x0040825a:	ret

0x00406fa9:	popl %esi
0x00406faa:	popl %ebp
0x00406fab:	ret

0x00406fe8:	popl %ecx
0x00406fe9:	popl %ecx
0x00406fea:	testl %eax, %eax
0x00406fec:	jne 66
0x00406fee:	pushl $0x40899e<UINT32>
0x00406ff3:	call 0x00404080
0x00404080:	movl %edi, %edi
0x00404082:	pushl %ebp
0x00404083:	movl %ebp, %esp
0x00404085:	pushl 0x8(%ebp)
0x00404088:	call 0x00404044
0x00404044:	pushl $0xc<UINT8>
0x00404046:	pushl $0x416370<UINT32>
0x0040404b:	call 0x00406534
0x00404050:	call 0x00406f59
0x00406f59:	pushl $0x8<UINT8>
0x00406f5b:	call 0x00405a3b
0x00406f60:	popl %ecx
0x00406f61:	ret

0x00404055:	andl -4(%ebp), $0x0<UINT8>
0x00404059:	pushl 0x8(%ebp)
0x0040405c:	call 0x00403f59
0x00403f59:	movl %edi, %edi
0x00403f5b:	pushl %ebp
0x00403f5c:	movl %ebp, %esp
0x00403f5e:	pushl %ecx
0x00403f5f:	pushl %ebx
0x00403f60:	pushl %esi
0x00403f61:	pushl %edi
0x00403f62:	pushl 0x41afa8
0x00403f68:	call 0x00406797
0x004067c8:	movl %eax, 0x1fc(%eax)
0x004067ce:	jmp 0x004067f7
0x00403f6d:	pushl 0x41afa4
0x00403f73:	movl %edi, %eax
0x00403f75:	movl -4(%ebp), %edi
0x00403f78:	call 0x00406797
0x00403f7d:	movl %esi, %eax
0x00403f7f:	popl %ecx
0x00403f80:	popl %ecx
0x00403f81:	cmpl %esi, %edi
0x00403f83:	jb 131
0x00403f89:	movl %ebx, %esi
0x00403f8b:	subl %ebx, %edi
0x00403f8d:	leal %eax, 0x4(%ebx)
0x00403f90:	cmpl %eax, $0x4<UINT8>
0x00403f93:	jb 119
0x00403f95:	pushl %edi
0x00403f96:	call 0x00407436
0x00407436:	pushl $0x10<UINT8>
0x00407438:	pushl $0x416488<UINT32>
0x0040743d:	call 0x00406534
0x00407442:	xorl %eax, %eax
0x00407444:	movl %ebx, 0x8(%ebp)
0x00407447:	xorl %edi, %edi
0x00407449:	cmpl %ebx, %edi
0x0040744b:	setne %al
0x0040744e:	cmpl %eax, %edi
0x00407450:	jne 0x0040746f
0x0040746f:	cmpl 0x41afd0, $0x3<UINT8>
0x00407476:	jne 0x004074b0
0x004074b0:	pushl %ebx
0x004074b1:	pushl %edi
0x004074b2:	pushl 0x419678
0x004074b8:	call HeapSize@KERNEL32.DLL
HeapSize@KERNEL32.DLL: API Node	
0x004074be:	movl %esi, %eax
0x004074c0:	movl %eax, %esi
0x004074c2:	call 0x00406579
0x004074c7:	ret

0x00403f9b:	movl %edi, %eax
0x00403f9d:	leal %eax, 0x4(%ebx)
0x00403fa0:	popl %ecx
0x00403fa1:	cmpl %edi, %eax
0x00403fa3:	jae 0x00403fed
0x00403fed:	pushl 0x8(%ebp)
0x00403ff0:	call 0x0040671c
0x00403ff5:	movl (%esi), %eax
0x00403ff7:	addl %esi, $0x4<UINT8>
0x00403ffa:	pushl %esi
0x00403ffb:	call 0x0040671c
0x00404000:	popl %ecx
0x00404001:	movl 0x41afa4, %eax
0x00404006:	movl %eax, 0x8(%ebp)
0x00404009:	popl %ecx
0x0040400a:	jmp 0x0040400e
0x0040400e:	popl %edi
0x0040400f:	popl %esi
0x00404010:	popl %ebx
0x00404011:	leave
0x00404012:	ret

0x00404061:	popl %ecx
0x00404062:	movl -28(%ebp), %eax
0x00404065:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040406c:	call 0x0040407a
0x0040407a:	call 0x00406f62
0x00406f62:	pushl $0x8<UINT8>
0x00406f64:	call 0x00405961
0x00406f69:	popl %ecx
0x00406f6a:	ret

0x0040407f:	ret

0x00404071:	movl %eax, -28(%ebp)
0x00404074:	call 0x00406579
0x00404079:	ret

0x0040408d:	negl %eax
0x0040408f:	sbbl %eax, %eax
0x00404091:	negl %eax
0x00404093:	popl %ecx
0x00404094:	decl %eax
0x00404095:	popl %ebp
0x00404096:	ret

0x00406ff8:	movl %eax, $0x4122cc<UINT32>
0x00406ffd:	movl (%esp), $0x4122dc<UINT32>
0x00407004:	call 0x00406f6b
0x00406f6b:	movl %edi, %edi
0x00406f6d:	pushl %ebp
0x00406f6e:	movl %ebp, %esp
0x00406f70:	pushl %esi
0x00406f71:	movl %esi, %eax
0x00406f73:	jmp 0x00406f80
0x00406f80:	cmpl %esi, 0x8(%ebp)
0x00406f83:	jb 0x00406f75
0x00406f75:	movl %eax, (%esi)
0x00406f77:	testl %eax, %eax
0x00406f79:	je 0x00406f7d
0x00406f7d:	addl %esi, $0x4<UINT8>
0x00406f7b:	call 0x00411120
0x004110b0:	pushl $0x413640<UINT32>
0x004110b5:	call RegisterWindowMessageW@USER32.dll
RegisterWindowMessageW@USER32.dll: API Node	
0x004110bb:	movl 0x419e4c, %eax
0x004110c0:	ret

0x004110d0:	pushl %ecx
0x004110d1:	movzbl %eax, 0x419dac
0x004110d8:	movl %ecx, 0x418fb0
0x004110de:	movl (%esp), %eax
0x004110e1:	fildl (%esp)
0x004110e4:	fstpl 0x418fd8
0x004110ea:	fildl 0x418fb0
0x004110f0:	testl %ecx, %ecx
0x004110f2:	jnl 0x004110fa
0x004110fa:	movzbl %edx, 0x419dad
0x00411101:	fstpl 0x418ff0
0x00411107:	movl (%esp), %edx
0x0041110a:	fildl (%esp)
0x0041110d:	fstpl 0x419008
0x00411113:	popl %ecx
0x00411114:	ret

0x00411120:	pushl $0x41375c<UINT32>
0x00411125:	call 0x00404183
0x00404183:	movl %edi, %edi
0x00404185:	pushl %ebp
0x00404186:	movl %ebp, %esp
0x00404188:	pushl %ebx
0x00404189:	xorl %ebx, %ebx
0x0040418b:	cmpl 0x8(%ebp), %ebx
0x0040418e:	jne 0x00404194
0x00404194:	pushl %esi
0x00404195:	pushl %edi
0x00404196:	pushl 0x8(%ebp)
0x00404199:	call 0x00407519
0x00407519:	movl %edi, %edi
0x0040751b:	pushl %ebp
0x0040751c:	movl %ebp, %esp
0x0040751e:	movl %eax, 0x8(%ebp)
0x00407521:	movw %cx, (%eax)
0x00407524:	incl %eax
0x00407525:	incl %eax
0x00407526:	testw %cx, %cx
0x00407529:	jne 0x00407521
0x0040752b:	subl %eax, 0x8(%ebp)
0x0040752e:	sarl %eax
0x00407530:	decl %eax
0x00407531:	popl %ebp
0x00407532:	ret

0x0040419e:	movl %esi, %eax
0x004041a0:	incl %esi
0x004041a1:	pushl $0x2<UINT8>
0x004041a3:	pushl %esi
0x004041a4:	call 0x004074d9
0x004074d9:	movl %edi, %edi
0x004074db:	pushl %ebp
0x004074dc:	movl %ebp, %esp
0x004074de:	pushl %ecx
0x004074df:	andl -4(%ebp), $0x0<UINT8>
0x004074e3:	pushl %esi
0x004074e4:	leal %eax, -4(%ebp)
0x004074e7:	pushl %eax
0x004074e8:	pushl 0xc(%ebp)
0x004074eb:	pushl 0x8(%ebp)
0x004074ee:	call 0x0040af35
0x004074f3:	movl %esi, %eax
0x004074f5:	addl %esp, $0xc<UINT8>
0x004074f8:	testl %esi, %esi
0x004074fa:	jne 0x00407514
0x00407514:	movl %eax, %esi
0x00407516:	popl %esi
0x00407517:	leave
0x00407518:	ret

0x004041a9:	movl %edi, %eax
0x004041ab:	addl %esp, $0xc<UINT8>
0x004041ae:	cmpl %edi, %ebx
0x004041b0:	je 34
0x004041b2:	pushl 0x8(%ebp)
0x004041b5:	pushl %esi
0x004041b6:	pushl %edi
0x004041b7:	call 0x00404114
0x00404114:	movl %edi, %edi
0x00404116:	pushl %ebp
0x00404117:	movl %ebp, %esp
0x00404119:	movl %edx, 0x8(%ebp)
0x0040411c:	pushl %ebx
0x0040411d:	pushl %esi
0x0040411e:	pushl %edi
0x0040411f:	xorl %edi, %edi
0x00404121:	cmpl %edx, %edi
0x00404123:	je 7
0x00404125:	movl %ebx, 0xc(%ebp)
0x00404128:	cmpl %ebx, %edi
0x0040412a:	ja 0x0040414a
0x0040414a:	movl %esi, 0x10(%ebp)
0x0040414d:	cmpl %esi, %edi
0x0040414f:	jne 0x00404158
0x00404158:	movl %ecx, %edx
0x0040415a:	movzwl %eax, (%esi)
0x0040415d:	movw (%ecx), %ax
0x00404160:	incl %ecx
0x00404161:	incl %ecx
0x00404162:	incl %esi
0x00404163:	incl %esi
0x00404164:	cmpw %ax, %di
0x00404167:	je 0x0040416c
0x00404169:	decl %ebx
0x0040416a:	jne 0x0040415a
0x0040416c:	xorl %eax, %eax
0x0040416e:	cmpl %ebx, %edi
0x00404170:	jne 0x00404145
0x00404145:	popl %edi
0x00404146:	popl %esi
0x00404147:	popl %ebx
0x00404148:	popl %ebp
0x00404149:	ret

0x004041bc:	addl %esp, $0xc<UINT8>
0x004041bf:	testl %eax, %eax
0x004041c1:	je 0x004041d0
0x004041d0:	movl %eax, %edi
0x004041d2:	jmp 0x004041d6
0x004041d6:	popl %edi
0x004041d7:	popl %esi
0x004041d8:	popl %ebx
0x004041d9:	popl %ebp
0x004041da:	ret

0x0041112a:	pushl $0x411140<UINT32>
0x0041112f:	movl 0x419e44, %eax
0x00411134:	call 0x00404080
0x00411139:	addl %esp, $0x8<UINT8>
0x0041113c:	ret

0x00406f85:	popl %esi
0x00406f86:	popl %ebp
0x00406f87:	ret

0x00407009:	cmpl 0x41afb0, $0x0<UINT8>
0x00407010:	popl %ecx
0x00407011:	je 0x0040702e
0x0040702e:	xorl %eax, %eax
0x00407030:	popl %ebp
0x00407031:	ret

0x0040462f:	popl %ecx
0x00404630:	cmpl %eax, %esi
0x00404632:	je 0x0040463b
0x0040463b:	call 0x0040825b
0x0040825b:	movl %edi, %edi
0x0040825d:	pushl %esi
0x0040825e:	pushl %edi
0x0040825f:	xorl %edi, %edi
0x00408261:	cmpl 0x41afac, %edi
0x00408267:	jne 0x0040826e
0x0040826e:	movl %esi, 0x41afd4
0x00408274:	testl %esi, %esi
0x00408276:	jne 0x0040827d
0x0040827d:	movb %al, (%esi)
0x0040827f:	cmpb %al, $0x20<UINT8>
0x00408281:	ja 0x0040828b
0x0040828b:	cmpb %al, $0x22<UINT8>
0x0040828d:	jne 0x00408298
0x0040828f:	xorl %ecx, %ecx
0x00408291:	testl %edi, %edi
0x00408293:	sete %cl
0x00408296:	movl %edi, %ecx
0x00408298:	movzbl %eax, %al
0x0040829b:	pushl %eax
0x0040829c:	call 0x0040c3e8
0x004082a1:	popl %ecx
0x004082a2:	testl %eax, %eax
0x004082a4:	je 0x004082a7
0x004082a7:	incl %esi
0x004082a8:	jmp 0x0040827d
0x00408283:	testb %al, %al
0x00408285:	je 0x004082b5
0x004082b5:	popl %edi
0x004082b6:	movl %eax, %esi
0x004082b8:	popl %esi
0x004082b9:	ret

0x00404640:	testb -60(%ebp), %bl
0x00404643:	je 0x0040464b
0x0040464b:	pushl $0xa<UINT8>
0x0040464d:	popl %ecx
0x0040464e:	pushl %ecx
0x0040464f:	pushl %eax
0x00404650:	pushl %esi
0x00404651:	pushl $0x400000<UINT32>
0x00404656:	call 0x00403040
0x00403040:	pushl %ebp
0x00403041:	movl %ebp, %esp
0x00403043:	andl %esp, $0xfffffff8<UINT8>
0x00403046:	subl %esp, $0x2c<UINT8>
0x00403049:	pushl %ebx
0x0040304a:	pushl %esi
0x0040304b:	pushl %edi
0x0040304c:	call 0x00403b80
0x00403b80:	pushl %ebx
0x00403b81:	pushl %esi
0x00403b82:	pushl $0x4161ac<UINT32>
0x00403b87:	pushl $0x4161c0<UINT32>
0x00403b8c:	xorl %ebx, %ebx
0x00403b8e:	call LoadLibraryW@KERNEL32.DLL
LoadLibraryW@KERNEL32.DLL: API Node	
0x00403b94:	pushl %eax
0x00403b95:	call GetProcAddress@KERNEL32.DLL
0x00403b9b:	movl %esi, %eax
0x00403b9d:	testl %esi, %esi
0x00403b9f:	je 133
0x00403ba5:	pushl %edi
0x00403ba6:	pushl $0x419da4<UINT32>
0x00403bab:	call GetCommandLineW@KERNEL32.DLL
GetCommandLineW@KERNEL32.DLL: API Node	
0x00403bb1:	pushl %eax
0x00403bb2:	call CommandLineToArgvW@Shell32.dll
CommandLineToArgvW@Shell32.dll: API Node	
0x00403bb4:	xorl %esi, %esi
0x00403bb6:	cmpl 0x419da4, %ebx
0x00403bbc:	movl %edi, %eax
0x00403bbe:	jle 0x00403c29
0x00403c29:	popl %edi
0x00403c2a:	pushl %ebx
0x00403c2b:	call 0x00403780
0x00403780:	subl %esp, $0x214<UINT32>
0x00403786:	movl %eax, 0x418004
0x0040378b:	xorl %eax, %esp
0x0040378d:	movl 0x210(%esp), %eax
0x00403794:	pushl $0x4137ac<UINT32>
0x00403799:	leal %eax, 0xc(%esp)
0x0040379d:	pushl $0x416020<UINT32>
0x004037a2:	pushl %eax
0x004037a3:	movl 0xc(%esp), $0x0<UINT32>
0x004037ab:	call 0x00403c5b
0x00403c5b:	movl %edi, %edi
0x00403c5d:	pushl %ebp
0x00403c5e:	movl %ebp, %esp
0x00403c60:	subl %esp, $0x20<UINT8>
0x00403c63:	pushl %ebx
0x00403c64:	xorl %ebx, %ebx
0x00403c66:	cmpl 0xc(%ebp), %ebx
0x00403c69:	jne 0x00403c88
0x00403c88:	movl %eax, 0x8(%ebp)
0x00403c8b:	cmpl %eax, %ebx
0x00403c8d:	je -36
0x00403c8f:	pushl %esi
0x00403c90:	movl -24(%ebp), %eax
0x00403c93:	movl -32(%ebp), %eax
0x00403c96:	leal %eax, 0x10(%ebp)
0x00403c99:	pushl %eax
0x00403c9a:	pushl %ebx
0x00403c9b:	pushl 0xc(%ebp)
0x00403c9e:	leal %eax, -32(%ebp)
0x00403ca1:	pushl %eax
0x00403ca2:	movl -20(%ebp), $0x42<UINT32>
0x00403ca9:	movl -28(%ebp), $0x7fffffff<UINT32>
0x00403cb0:	call 0x0040498c
0x0040498c:	movl %edi, %edi
0x0040498e:	pushl %ebp
0x0040498f:	movl %ebp, %esp
0x00404991:	subl %esp, $0x474<UINT32>
0x00404997:	movl %eax, 0x418004
0x0040499c:	xorl %eax, %ebp
0x0040499e:	movl -4(%ebp), %eax
0x004049a1:	movl %eax, 0x8(%ebp)
0x004049a4:	pushl %ebx
0x004049a5:	movl %ebx, 0x14(%ebp)
0x004049a8:	pushl %esi
0x004049a9:	movl %esi, 0xc(%ebp)
0x004049ac:	pushl %edi
0x004049ad:	pushl 0x10(%ebp)
0x004049b0:	xorl %edi, %edi
0x004049b2:	leal %ecx, -1112(%ebp)
0x004049b8:	movl -1072(%ebp), %eax
0x004049be:	movl -1052(%ebp), %ebx
0x004049c4:	movl -1096(%ebp), %edi
0x004049ca:	movl -1032(%ebp), %edi
0x004049d0:	movl -1068(%ebp), %edi
0x004049d6:	movl -1036(%ebp), %edi
0x004049dc:	movl -1060(%ebp), %edi
0x004049e2:	movl -1084(%ebp), %edi
0x004049e8:	movl -1064(%ebp), %edi
0x004049ee:	call 0x004041db
0x004049f3:	cmpl -1072(%ebp), %edi
0x004049f9:	jne 0x00404a2e
0x00404a2e:	cmpl %esi, %edi
0x00404a30:	je -55
0x00404a32:	movzwl %edx, (%esi)
0x00404a35:	xorl %ecx, %ecx
0x00404a37:	movl -1056(%ebp), %edi
0x00404a3d:	movl -1044(%ebp), %edi
0x00404a43:	movl -1092(%ebp), %edi
0x00404a49:	movl -1048(%ebp), %edx
0x00404a4f:	cmpw %dx, %di
0x00404a52:	je 2689
0x00404a58:	pushl $0x2<UINT8>
0x00404a5a:	popl %edi
0x00404a5b:	addl %esi, %edi
0x00404a5d:	cmpl -1056(%ebp), $0x0<UINT8>
0x00404a64:	movl -1088(%ebp), %esi
0x00404a6a:	jl 2665
0x00404a70:	leal %eax, -32(%edx)
0x00404a73:	cmpw %ax, $0x58<UINT8>
0x00404a77:	ja 0x00404a88
0x00404a79:	movzwl %eax, %dx
0x00404a7c:	movsbl %eax, 0x412a90(%eax)
0x00404a83:	andl %eax, $0xf<UINT8>
0x00404a86:	jmp 0x00404a8a
0x00404a8a:	movsbl %eax, 0x412ab0(%ecx,%eax,8)
0x00404a92:	pushl $0x7<UINT8>
0x00404a94:	sarl %eax, $0x4<UINT8>
0x00404a97:	popl %ecx
0x00404a98:	movl -1116(%ebp), %eax
0x00404a9e:	cmpl %eax, %ecx
0x00404aa0:	ja 2549
0x00404aa6:	jmp 0x00404cec
0x00404ccb:	movl %eax, -1072(%ebp)
0x00404cd1:	pushl %edx
0x00404cd2:	leal %esi, -1056(%ebp)
0x00404cd8:	movl -1064(%ebp), $0x1<UINT32>
0x00404ce2:	call 0x00409b9a
0x00409b9a:	movl %edi, %edi
0x00409b9c:	pushl %ebp
0x00409b9d:	movl %ebp, %esp
0x00409b9f:	testb 0xc(%eax), $0x40<UINT8>
0x00409ba3:	je 6
0x00409ba5:	cmpl 0x8(%eax), $0x0<UINT8>
0x00409ba9:	je 26
0x00409bab:	pushl %eax
0x00409bac:	pushl 0x8(%ebp)
0x00409baf:	call 0x004096a3
0x004096a3:	movl %edi, %edi
0x004096a5:	pushl %ebp
0x004096a6:	movl %ebp, %esp
0x004096a8:	subl %esp, $0x10<UINT8>
0x004096ab:	movl %eax, 0x418004
0x004096b0:	xorl %eax, %ebp
0x004096b2:	movl -4(%ebp), %eax
0x004096b5:	pushl %ebx
0x004096b6:	pushl %esi
0x004096b7:	movl %esi, 0xc(%ebp)
0x004096ba:	testb 0xc(%esi), $0x40<UINT8>
0x004096be:	pushl %edi
0x004096bf:	jne 0x004097fb
0x004097fb:	addl 0x4(%esi), $0xfffffffe<UINT8>
0x004097ff:	js 13
0x00409801:	movl %ecx, (%esi)
0x00409803:	movl %eax, 0x8(%ebp)
0x00409806:	movw (%ecx), %ax
0x00409809:	addl (%esi), $0x2<UINT8>
0x0040980c:	jmp 0x0040981b
0x0040981b:	movl %ecx, -4(%ebp)
0x0040981e:	popl %edi
0x0040981f:	popl %esi
0x00409820:	xorl %ecx, %ebp
0x00409822:	popl %ebx
0x00409823:	call 0x00403c4c
0x00409828:	leave
0x00409829:	ret

0x00409bb4:	popl %ecx
0x00409bb5:	popl %ecx
0x00409bb6:	movl %ecx, $0xffff<UINT32>
0x00409bbb:	cmpw %ax, %cx
0x00409bbe:	jne 0x00409bc5
0x00409bc5:	incl (%esi)
0x00409bc7:	popl %ebp
0x00409bc8:	ret

0x00404ce7:	jmp 0x0040549a
0x0040549a:	popl %ecx
0x0040549b:	movl %esi, -1088(%ebp)
0x004054a1:	movzwl %eax, (%esi)
0x004054a4:	movl -1048(%ebp), %eax
0x004054aa:	testw %ax, %ax
0x004054ad:	je 0x004054d9
0x004054af:	movl %ecx, -1116(%ebp)
0x004054b5:	movl %ebx, -1052(%ebp)
0x004054bb:	movl %edx, %eax
0x004054bd:	jmp 0x00404a58
0x00404a88:	xorl %eax, %eax
0x00404aad:	xorl %eax, %eax
0x00404aaf:	orl -1036(%ebp), $0xffffffff<UINT8>
0x00404ab6:	movl -1120(%ebp), %eax
0x00404abc:	movl -1084(%ebp), %eax
0x00404ac2:	movl -1068(%ebp), %eax
0x00404ac8:	movl -1060(%ebp), %eax
0x00404ace:	movl -1032(%ebp), %eax
0x00404ad4:	movl -1064(%ebp), %eax
0x00404ada:	jmp 0x0040549b
0x00404cec:	movzwl %eax, %dx
0x00404cef:	cmpl %eax, $0x64<UINT8>
0x00404cf2:	jg 0x00404f27
0x00404f27:	cmpl %eax, $0x70<UINT8>
0x00404f2a:	jg 0x0040512a
0x0040512a:	subl %eax, $0x73<UINT8>
0x0040512d:	je 0x00404d9a
0x00404d9a:	movl %edi, -1036(%ebp)
0x00404da0:	cmpl %edi, $0xffffffff<UINT8>
0x00404da3:	jne 5
0x00404da5:	movl %edi, $0x7fffffff<UINT32>
0x00404daa:	addl %ebx, $0x4<UINT8>
0x00404dad:	testb -1032(%ebp), $0x20<UINT8>
0x00404db4:	movl -1052(%ebp), %ebx
0x00404dba:	movl %ebx, -4(%ebx)
0x00404dbd:	movl -1040(%ebp), %ebx
0x00404dc3:	je 0x004052d1
0x004052d1:	testl %ebx, %ebx
0x004052d3:	jne 0x004052e0
0x004052e0:	movl %eax, -1040(%ebp)
0x004052e6:	movl -1064(%ebp), $0x1<UINT32>
0x004052f0:	jmp 0x004052fb
0x004052fb:	testl %edi, %edi
0x004052fd:	jne 0x004052f2
0x004052f2:	decl %edi
0x004052f3:	cmpw (%eax), $0x0<UINT8>
0x004052f7:	je 0x004052ff
0x004052f9:	incl %eax
0x004052fa:	incl %eax
0x004052ff:	subl %eax, -1040(%ebp)
0x00405305:	sarl %eax
0x00405307:	movl -1044(%ebp), %eax
0x0040530d:	cmpl -1084(%ebp), $0x0<UINT8>
0x00405314:	jne 357
0x0040531a:	movl %eax, -1032(%ebp)
0x00405320:	testb %al, $0x40<UINT8>
0x00405322:	je 0x0040534f
0x0040534f:	movl %ebx, -1068(%ebp)
0x00405355:	movl %esi, -1044(%ebp)
0x0040535b:	subl %ebx, %esi
0x0040535d:	subl %ebx, -1060(%ebp)
0x00405363:	testb -1032(%ebp), $0xc<UINT8>
0x0040536a:	jne 23
0x0040536c:	pushl -1072(%ebp)
0x00405372:	leal %eax, -1056(%ebp)
0x00405378:	pushl %ebx
0x00405379:	pushl $0x20<UINT8>
0x0040537b:	call 0x00409bc9
0x00409bc9:	movl %edi, %edi
0x00409bcb:	pushl %ebp
0x00409bcc:	movl %ebp, %esp
0x00409bce:	pushl %esi
0x00409bcf:	movl %esi, %eax
0x00409bd1:	jmp 0x00409be7
0x00409be7:	cmpl 0xc(%ebp), $0x0<UINT8>
0x00409beb:	jg -26
0x00409bed:	popl %esi
0x00409bee:	popl %ebp
0x00409bef:	ret

0x00405380:	addl %esp, $0xc<UINT8>
0x00405383:	pushl -1060(%ebp)
0x00405389:	movl %edi, -1072(%ebp)
0x0040538f:	leal %eax, -1056(%ebp)
0x00405395:	leal %ecx, -1080(%ebp)
0x0040539b:	call 0x0040493a
0x0040493a:	movl %edi, %edi
0x0040493c:	pushl %ebp
0x0040493d:	movl %ebp, %esp
0x0040493f:	testb 0xc(%edi), $0x40<UINT8>
0x00404943:	pushl %ebx
0x00404944:	pushl %esi
0x00404945:	movl %esi, %eax
0x00404947:	movl %ebx, %ecx
0x00404949:	je 55
0x0040494b:	cmpl 0x8(%edi), $0x0<UINT8>
0x0040494f:	jne 0x00404982
0x00404982:	cmpl 0x8(%ebp), $0x0<UINT8>
0x00404986:	jg 0x00404958
0x00404988:	popl %esi
0x00404989:	popl %ebx
0x0040498a:	popl %ebp
0x0040498b:	ret

0x004053a0:	testb -1032(%ebp), $0x8<UINT8>
0x004053a7:	popl %ecx
0x004053a8:	je 0x004053c5
0x004053c5:	cmpl -1064(%ebp), $0x0<UINT8>
0x004053cc:	jne 0x00405443
0x00405443:	movl %ecx, -1040(%ebp)
0x00405449:	pushl %esi
0x0040544a:	leal %eax, -1056(%ebp)
0x00405450:	call 0x0040493a
0x00404958:	movzwl %eax, (%ebx)
0x0040495b:	decl 0x8(%ebp)
0x0040495e:	pushl %eax
0x0040495f:	movl %eax, %edi
0x00404961:	call 0x00409b9a
0x00404966:	incl %ebx
0x00404967:	incl %ebx
0x00404968:	cmpl (%esi), $0xffffffff<UINT8>
0x0040496b:	popl %ecx
0x0040496c:	jne 0x00404982
0x00405455:	popl %ecx
0x00405456:	cmpl -1056(%ebp), $0x0<UINT8>
0x0040545d:	jl 32
0x0040545f:	testb -1032(%ebp), $0x4<UINT8>
0x00405466:	je 0x0040547f
0x0040547f:	cmpl -1092(%ebp), $0x0<UINT8>
0x00405486:	je 0x0040549b
0x004054d9:	cmpb -1100(%ebp), $0x0<UINT8>
0x004054e0:	je 10
0x004054e2:	movl %eax, -1104(%ebp)
0x004054e8:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x004054ec:	movl %eax, -1056(%ebp)
0x004054f2:	movl %ecx, -4(%ebp)
0x004054f5:	popl %edi
0x004054f6:	popl %esi
0x004054f7:	xorl %ecx, %ebp
0x004054f9:	popl %ebx
0x004054fa:	call 0x00403c4c
0x004054ff:	leave
0x00405500:	ret

0x00403cb5:	addl %esp, $0x10<UINT8>
0x00403cb8:	decl -28(%ebp)
0x00403cbb:	movl %esi, %eax
0x00403cbd:	js 10
0x00403cbf:	movl %eax, -32(%ebp)
0x00403cc2:	movb (%eax), %bl
0x00403cc4:	incl -32(%ebp)
0x00403cc7:	jmp 0x00403cd5
0x00403cd5:	decl -28(%ebp)
0x00403cd8:	js 7
0x00403cda:	movl %eax, -32(%ebp)
0x00403cdd:	movb (%eax), %bl
0x00403cdf:	jmp 0x00403ced
0x00403ced:	movl %eax, %esi
0x00403cef:	popl %esi
0x00403cf0:	popl %ebx
0x00403cf1:	leave
0x00403cf2:	ret

0x004037b0:	addl %esp, $0xc<UINT8>
0x004037b3:	leal %ecx, (%esp)
0x004037b6:	pushl %ecx
0x004037b7:	leal %edx, 0xc(%esp)
0x004037bb:	pushl %edx
0x004037bc:	pushl $0x80000001<UINT32>
0x004037c1:	call RegCreateKeyW@ADVAPI32.dll
RegCreateKeyW@ADVAPI32.dll: API Node	
0x004037c7:	testl %eax, %eax
0x004037c9:	jne 40
0x004037cb:	movl %edx, (%esp)
0x004037ce:	leal %eax, 0x4(%esp)
0x004037d2:	pushl %eax
0x004037d3:	leal %ecx, 0x21c(%esp)
0x004037da:	pushl %ecx
0x004037db:	pushl $0x0<UINT8>
0x004037dd:	pushl $0x0<UINT8>
0x004037df:	pushl $0x416054<UINT32>
0x004037e4:	pushl %edx
0x004037e5:	movl 0x1c(%esp), $0x4<UINT32>
0x004037ed:	call RegQueryValueExW@ADVAPI32.dll
RegQueryValueExW@ADVAPI32.dll: API Node	
0x004037f3:	cmpl 0x218(%esp), $0x0<UINT8>
0x004037fb:	jne 822
0x00403801:	pushl %ebx
0x00403802:	pushl %esi
0x00403803:	pushl %edi
0x00403804:	pushl $0x3e8<UINT32>
0x00403809:	pushl $0x40<UINT8>
0x0040380b:	call LocalAlloc@KERNEL32.DLL
LocalAlloc@KERNEL32.DLL: API Node	
0x00403811:	movl %esi, %eax
0x00403813:	pushl $0x416070<UINT32>
0x00403818:	leal %edi, 0x12(%esi)
0x0040381b:	call LoadLibraryW@KERNEL32.DLL
0x00403821:	xorl %eax, %eax
0x00403823:	movw 0xa(%esi), %ax
0x00406590:	movl %edi, %edi
0x00406592:	pushl %ebp
0x00406593:	movl %ebp, %esp
0x00406595:	subl %esp, $0x18<UINT8>
0x00406598:	pushl %ebx
0x00406599:	movl %ebx, 0xc(%ebp)
0x0040659c:	pushl %esi
0x0040659d:	movl %esi, 0x8(%ebx)
0x004065a0:	xorl %esi, 0x418004
0x004065a6:	pushl %edi
0x004065a7:	movl %eax, (%esi)
0x004065a9:	movb -1(%ebp), $0x0<UINT8>
0x004065ad:	movl -12(%ebp), $0x1<UINT32>
0x004065b4:	leal %edi, 0x10(%ebx)
0x004065b7:	cmpl %eax, $0xfffffffe<UINT8>
0x004065ba:	je 0x004065c9
0x004065c9:	movl %ecx, 0xc(%esi)
0x004065cc:	movl %eax, 0x8(%esi)
0x004065cf:	addl %ecx, %edi
0x004065d1:	xorl %ecx, (%eax,%edi)
0x004065d4:	call 0x00403c4c
0x004065d9:	movl %eax, 0x8(%ebp)
0x004065dc:	testb 0x4(%eax), $0x66<UINT8>
0x004065e0:	jne 278
0x004065e6:	movl %ecx, 0x10(%ebp)
0x004065e9:	leal %edx, -24(%ebp)
0x004065ec:	movl -4(%ebx), %edx
0x004065ef:	movl %ebx, 0xc(%ebx)
0x004065f2:	movl -24(%ebp), %eax
0x004065f5:	movl -20(%ebp), %ecx
0x004065f8:	cmpl %ebx, $0xfffffffe<UINT8>
0x004065fb:	je 95
0x004065fd:	leal %ecx, (%ecx)
0x00406600:	leal %eax, (%ebx,%ebx,2)
0x00406603:	movl %ecx, 0x14(%esi,%eax,4)
0x00406607:	leal %eax, 0x10(%esi,%eax,4)
0x0040660b:	movl -16(%ebp), %eax
0x0040660e:	movl %eax, (%eax)
0x00406610:	movl -8(%ebp), %eax
0x00406613:	testl %ecx, %ecx
0x00406615:	je 20
0x00406617:	movl %edx, %edi
0x00406619:	call 0x0040ac5a
0x0040ac5a:	pushl %ebp
0x0040ac5b:	pushl %esi
0x0040ac5c:	pushl %edi
0x0040ac5d:	pushl %ebx
0x0040ac5e:	movl %ebp, %edx
0x0040ac60:	xorl %eax, %eax
0x0040ac62:	xorl %ebx, %ebx
0x0040ac64:	xorl %edx, %edx
0x0040ac66:	xorl %esi, %esi
0x0040ac68:	xorl %edi, %edi
0x0040ac6a:	call 0x00404673
0x00404673:	movl %eax, -20(%ebp)
0x00404676:	movl %ecx, (%eax)
0x00404678:	movl %ecx, (%ecx)
0x0040467a:	movl -36(%ebp), %ecx
0x0040467d:	pushl %eax
0x0040467e:	pushl %ecx
0x0040467f:	call 0x004071f7
0x004071f7:	movl %edi, %edi
0x004071f9:	pushl %ebp
0x004071fa:	movl %ebp, %esp
0x004071fc:	pushl %ecx
0x004071fd:	pushl %ecx
0x004071fe:	pushl %esi
0x004071ff:	call 0x004069a7
0x00407204:	movl %esi, %eax
0x00407206:	testl %esi, %esi
0x00407208:	je 326
0x0040720e:	movl %edx, 0x5c(%esi)
0x00407211:	movl %eax, 0x4182c0
0x00407216:	pushl %edi
0x00407217:	movl %edi, 0x8(%ebp)
0x0040721a:	movl %ecx, %edx
0x0040721c:	pushl %ebx
0x0040721d:	cmpl (%ecx), %edi
0x0040721f:	je 0x0040722f
0x0040722f:	imull %eax, %eax, $0xc<UINT8>
0x00407232:	addl %eax, %edx
0x00407234:	cmpl %ecx, %eax
0x00407236:	jae 8
0x00407238:	cmpl (%ecx), %edi
0x0040723a:	jne 4
0x0040723c:	movl %eax, %ecx
0x0040723e:	jmp 0x00407242
0x00407242:	testl %eax, %eax
0x00407244:	je 10
0x00407246:	movl %ebx, 0x8(%eax)
0x00407249:	movl -4(%ebp), %ebx
0x0040724c:	testl %ebx, %ebx
0x0040724e:	jne 7
0x00407250:	xorl %eax, %eax
0x00407252:	jmp 0x00407352
0x00407352:	popl %ebx
0x00407353:	popl %edi
0x00407354:	popl %esi
0x00407355:	leave
0x00407356:	ret

0x00404684:	popl %ecx
0x00404685:	popl %ecx
0x00404686:	ret

0x0040ac6c:	popl %ebx
0x0040ac6d:	popl %edi
0x0040ac6e:	popl %esi
0x0040ac6f:	popl %ebp
0x0040ac70:	ret

0x0040661e:	movb -1(%ebp), $0x1<UINT8>
0x00406622:	testl %eax, %eax
0x00406624:	jl 64
0x00406626:	jg 71
0x00406628:	movl %eax, -8(%ebp)
0x0040662b:	movl %ebx, %eax
0x0040662d:	cmpl %eax, $0xfffffffe<UINT8>
0x00406630:	jne -50
0x00406632:	cmpb -1(%ebp), $0x0<UINT8>
0x00406636:	je 36
0x00406638:	movl %eax, (%esi)
0x0040663a:	cmpl %eax, $0xfffffffe<UINT8>
0x0040663d:	je 0x0040664c
0x0040664c:	movl %ecx, 0xc(%esi)
0x0040664f:	movl %edx, 0x8(%esi)
0x00406652:	addl %ecx, %edi
0x00406654:	xorl %ecx, (%edx,%edi)
0x00406657:	call 0x00403c4c
0x0040665c:	movl %eax, -12(%ebp)
0x0040665f:	popl %edi
0x00406660:	popl %esi
0x00406661:	popl %ebx
0x00406662:	movl %esp, %ebp
0x00406664:	popl %ebp
0x00406665:	ret

0x00403827:	movl %edx, $0x138<UINT32>
0x0040382c:	movw 0xe(%esi), %dx
0x00403830:	xorl %ecx, %ecx
0x00403832:	movl %eax, $0xb4<UINT32>
0x00403837:	movw 0x10(%esi), %ax
0x0040383b:	xorl %edx, %edx
0x0040383d:	movl (%esi), $0x80c808d0<UINT32>
0x00403843:	movw 0xc(%esi), %cx
0x00403847:	movw 0x8(%esi), %cx
0x0040384b:	movw (%edi), %dx
0x0040384e:	addl %edi, $0x2<UINT8>
0x00403851:	xorl %eax, %eax
0x00403853:	movw (%edi), %ax
0x00403856:	addl %edi, $0x2<UINT8>
0x00403859:	movl %eax, $0x41608c<UINT32>
0x0040385e:	movl %edx, %edi
0x00403860:	subl %edx, %eax
0x00403862:	movzwl %ecx, (%eax)
0x00403865:	movw (%edx,%eax), %cx
0x00403869:	addl %eax, $0x2<UINT8>
0x0040386c:	testw %cx, %cx
0x0040386f:	jne 0x00403862
0x00403871:	addl %edi, $0x24<UINT8>
0x00403874:	movl %ecx, $0x8<UINT32>
0x00403879:	movw (%edi), %cx
0x0040387c:	addl %edi, $0x2<UINT8>
0x0040387f:	movl %eax, $0x4160b0<UINT32>
0x00403884:	movl %edx, %edi
0x00403886:	subl %edx, %eax
0x00403888:	jmp 0x00403890
0x00403890:	movzwl %ecx, (%eax)
0x00403893:	movw (%edx,%eax), %cx
0x00403897:	addl %eax, $0x2<UINT8>
0x0040389a:	testw %cx, %cx
0x0040389d:	jne 0x00403890
0x0040389f:	leal %eax, 0x1d(%edi)
0x004038a2:	andl %eax, $0xfffffffc<UINT8>
0x004038a5:	movl %edx, $0x7<UINT32>
0x004038aa:	movw 0x8(%eax), %dx
0x004038ae:	movl %ecx, $0x3<UINT32>
0x004038b3:	movw 0xa(%eax), %cx
0x004038b7:	movl %edx, $0x12a<UINT32>
0x004038bc:	movw 0xc(%eax), %dx
0x004038c0:	movl (%eax), $0x50000000<UINT32>
0x004038c6:	movl %ecx, $0xe<UINT32>
0x004038cb:	movw 0xe(%eax), %cx
0x004038cf:	movl %edx, $0x1f6<UINT32>
0x004038d4:	movw 0x10(%eax), %dx
0x004038d8:	addl %eax, $0x12<UINT8>
0x004038db:	movl %ecx, $0xffff<UINT32>
0x004038e0:	movw (%eax), %cx
0x004038e3:	addl %eax, $0x2<UINT8>
0x004038e6:	movl %edx, $0x82<UINT32>
0x004038eb:	movw (%eax), %dx
0x004038ee:	addl %eax, $0x2<UINT8>
0x004038f1:	movl %ecx, $0x4160d0<UINT32>
0x004038f6:	movl %edx, %eax
0x004038f8:	subl %edx, %ecx
0x004038fa:	leal %ebx, (%ebx)
0x00403900:	movzwl %edi, (%ecx)
0x00403903:	movw (%edx,%ecx), %di
0x00403907:	addl %ecx, $0x2<UINT8>
0x0040390a:	testw %di, %di
0x0040390d:	jne 0x00403900
0x0040390f:	addl %eax, $0x92<UINT32>
0x00403914:	xorl %ecx, %ecx
0x00403916:	movw (%eax), %cx
0x00403919:	addl %eax, $0x5<UINT8>
0x0040391c:	andl %eax, $0xfffffffc<UINT8>
0x0040391f:	movl %ebx, $0x1<UINT32>
0x00403924:	addw 0x8(%esi), %bx
0x00403928:	movl %edx, $0xc9<UINT32>
0x0040392d:	movw 0x8(%eax), %dx
0x00403931:	movl %ecx, $0x9f<UINT32>
0x00403936:	movw 0xa(%eax), %cx
0x0040393a:	movl %edx, $0x32<UINT32>
0x0040393f:	movw 0xc(%eax), %dx
0x00403943:	movl (%eax), $0x50010000<UINT32>
0x00403949:	movl %ecx, $0xe<UINT32>
0x0040394e:	movw 0xe(%eax), %cx
0x00403952:	movl %edx, %ebx
0x00403954:	movw 0x10(%eax), %dx
0x00403958:	addl %eax, $0x12<UINT8>
0x0040395b:	movl %ecx, $0xffff<UINT32>
0x00403960:	movw (%eax), %cx
0x00403963:	addl %eax, $0x2<UINT8>
0x00403966:	movl %edx, $0x80<UINT32>
0x0040396b:	movw (%eax), %dx
0x0040396e:	addl %eax, $0x2<UINT8>
0x00403971:	movl %ecx, $0x416164<UINT32>
0x00403976:	movl %edx, %eax
0x00403978:	subl %edx, %ecx
0x0040397a:	leal %ebx, (%ebx)
0x00403980:	movzwl %edi, (%ecx)
0x00403983:	movw (%edx,%ecx), %di
0x00403987:	addl %ecx, $0x2<UINT8>
0x0040398a:	testw %di, %di
0x0040398d:	jne 0x00403980
0x0040398f:	addl %eax, $0xe<UINT8>
0x00403992:	xorl %ecx, %ecx
0x00403994:	movw (%eax), %cx
0x00403997:	addw 0x8(%esi), %bx
0x0040399b:	addl %eax, $0x5<UINT8>
0x0040399e:	andl %eax, $0xfffffffc<UINT8>
0x004039a1:	movl %edx, $0xff<UINT32>
0x004039a6:	movw 0x8(%eax), %dx
0x004039aa:	movl %ecx, $0x9f<UINT32>
0x004039af:	movw 0xa(%eax), %cx
0x004039b3:	movl %edx, $0x32<UINT32>
0x004039b8:	movw 0xc(%eax), %dx
0x004039bc:	movl %edx, $0x2<UINT32>
0x004039c1:	movw 0x10(%eax), %dx
0x004039c5:	movl (%eax), $0x50010000<UINT32>
0x004039cb:	movl %ecx, $0xe<UINT32>
0x004039d0:	movw 0xe(%eax), %cx
0x004039d4:	addl %eax, $0x12<UINT8>
0x004039d7:	movl %ecx, $0xffff<UINT32>
0x004039dc:	movw (%eax), %cx
0x004039df:	addl %eax, %edx
0x004039e1:	movl %edx, $0x80<UINT32>
0x004039e6:	movw (%eax), %dx
0x004039e9:	addl %eax, $0x2<UINT8>
0x004039ec:	movl %ecx, $0x416174<UINT32>
0x004039f1:	movl %edx, %eax
0x004039f3:	subl %edx, %ecx
0x004039f5:	movzwl %edi, (%ecx)
0x004039f8:	movw (%edx,%ecx), %di
0x004039fc:	addl %ecx, $0x2<UINT8>
0x004039ff:	testw %di, %di
0x00403a02:	jne 0x004039f5
0x00403a04:	addl %eax, $0x12<UINT8>
0x00403a07:	xorl %ecx, %ecx
0x00403a09:	movw (%eax), %cx
0x00403a0c:	addw 0x8(%esi), %bx
0x00403a10:	addl %eax, $0x5<UINT8>
0x00403a13:	andl %eax, $0xfffffffc<UINT8>
0x00403a16:	movl %edx, $0x7<UINT32>
0x00403a1b:	movw 0x8(%eax), %dx
0x00403a1f:	movl %ecx, $0x9f<UINT32>
0x00403a24:	movw 0xa(%eax), %cx
0x00403a28:	movl %edx, $0x32<UINT32>
0x00403a2d:	movw 0xc(%eax), %dx
0x00403a31:	movl (%eax), $0x50010000<UINT32>
0x00403a37:	movl %ecx, $0xe<UINT32>
0x00403a3c:	movw 0xe(%eax), %cx
0x00403a40:	movl %edx, $0x1f5<UINT32>
0x00403a45:	movw 0x10(%eax), %dx
0x00403a49:	addl %eax, $0x12<UINT8>
0x00403a4c:	movl %ecx, $0xffff<UINT32>
0x00403a51:	movw (%eax), %cx
0x00403a54:	addl %eax, $0x2<UINT8>
0x00403a57:	movl %edx, $0x80<UINT32>
0x00403a5c:	movw (%eax), %dx
0x00403a5f:	addl %eax, $0x2<UINT8>
0x00403a62:	movl %ecx, $0x416188<UINT32>
0x00403a67:	movl %edx, %eax
0x00403a69:	subl %edx, %ecx
0x00403a6b:	jmp 0x00403a70
0x00403a70:	movzwl %edi, (%ecx)
0x00403a73:	movw (%edx,%ecx), %di
0x00403a77:	addl %ecx, $0x2<UINT8>
0x00403a7a:	testw %di, %di
0x00403a7d:	jne 0x00403a70
0x00403a7f:	addl %eax, $0xe<UINT8>
0x00403a82:	xorl %ecx, %ecx
0x00403a84:	movw (%eax), %cx
0x00403a87:	addw 0x8(%esi), %bx
0x00403a8b:	addl %eax, $0x5<UINT8>
0x00403a8e:	andl %eax, $0xfffffffc<UINT8>
0x00403a91:	movl %edx, $0x7<UINT32>
0x00403a96:	movw 0x8(%eax), %dx
0x00403a9a:	movl %ecx, $0xe<UINT32>
0x00403a9f:	movw 0xa(%eax), %cx
0x00403aa3:	movl %edx, $0x12a<UINT32>
0x00403aa8:	movw 0xc(%eax), %dx
0x00403aac:	movl %ecx, $0x8c<UINT32>
0x00403ab1:	movw 0xe(%eax), %cx
0x00403ab5:	movl %edx, $0x1f4<UINT32>
0x00403aba:	leal %edi, 0x12(%eax)
0x00403abd:	movw 0x10(%eax), %dx
0x00403ac1:	movl (%eax), $0x50a11844<UINT32>
0x00403ac7:	movl %eax, $0x416198<UINT32>
0x00403acc:	movl %ecx, %edi
0x00403ace:	subl %ecx, %eax
0x00403ad0:	movzwl %edx, (%eax)
0x00403ad3:	movw (%ecx,%eax), %dx
0x00403ad7:	addl %eax, $0x2<UINT8>
0x00403ada:	testw %dx, %dx
0x00403add:	jne 0x00403ad0
0x00403adf:	addl %edi, $0x12<UINT8>
0x00403ae2:	movl %eax, $0x416174<UINT32>
0x00403ae7:	movl %edx, %edi
0x00403ae9:	subl %edx, %eax
0x00403aeb:	jmp 0x00403af0
0x00403af0:	movzwl %ecx, (%eax)
0x00403af3:	movw (%edx,%eax), %cx
0x00403af7:	addl %eax, $0x2<UINT8>
0x00403afa:	testw %cx, %cx
0x00403afd:	jne 0x00403af0
0x00403aff:	pushl $0x4137ac<UINT32>
0x00403b04:	xorl %eax, %eax
0x00403b06:	pushl $0x403620<UINT32>
0x00403b0b:	pushl %eax
0x00403b0c:	pushl %esi
0x00403b0d:	movw 0x12(%edi), %ax
0x00403b11:	addw 0x8(%esi), %bx
0x00403b15:	pushl %eax
0x00403b16:	call DialogBoxIndirectParamW@USER32.dll
DialogBoxIndirectParamW@USER32.dll: API Node	
0x00403b1c:	pushl %esi
0x00403b1d:	movl 0x228(%esp), %eax
0x00403b24:	call LocalFree@KERNEL32.DLL
LocalFree@KERNEL32.DLL: API Node	
0x00403b2a:	cmpl 0x224(%esp), $0x0<UINT8>
0x00403b32:	popl %edi
0x00403b33:	popl %esi
0x00403b34:	popl %ebx
0x00403b35:	je 29
