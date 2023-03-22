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
0x00407bff:	jne 18
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
0x00409b83:	je 10
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
