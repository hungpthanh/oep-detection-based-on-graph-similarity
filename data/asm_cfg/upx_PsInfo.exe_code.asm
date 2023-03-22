0x00456a80:	pusha
0x00456a81:	movl %esi, $0x43e000<UINT32>
0x00456a86:	leal %edi, -249856(%esi)
0x00456a8c:	pushl %edi
0x00456a8d:	jmp 0x00456a9a
0x00456a9a:	movl %ebx, (%esi)
0x00456a9c:	subl %esi, $0xfffffffc<UINT8>
0x00456a9f:	adcl %ebx, %ebx
0x00456aa1:	jb 0x00456a90
0x00456a90:	movb %al, (%esi)
0x00456a92:	incl %esi
0x00456a93:	movb (%edi), %al
0x00456a95:	incl %edi
0x00456a96:	addl %ebx, %ebx
0x00456a98:	jne 0x00456aa1
0x00456aa3:	movl %eax, $0x1<UINT32>
0x00456aa8:	addl %ebx, %ebx
0x00456aaa:	jne 0x00456ab3
0x00456ab3:	adcl %eax, %eax
0x00456ab5:	addl %ebx, %ebx
0x00456ab7:	jae 0x00456ac4
0x00456ab9:	jne 0x00456ae3
0x00456ae3:	xorl %ecx, %ecx
0x00456ae5:	subl %eax, $0x3<UINT8>
0x00456ae8:	jb 0x00456afb
0x00456aea:	shll %eax, $0x8<UINT8>
0x00456aed:	movb %al, (%esi)
0x00456aef:	incl %esi
0x00456af0:	xorl %eax, $0xffffffff<UINT8>
0x00456af3:	je 0x00456b6a
0x00456af5:	sarl %eax
0x00456af7:	movl %ebp, %eax
0x00456af9:	jmp 0x00456b06
0x00456b06:	jb 0x00456ad4
0x00456ad4:	addl %ebx, %ebx
0x00456ad6:	jne 0x00456adf
0x00456adf:	adcl %ecx, %ecx
0x00456ae1:	jmp 0x00456b35
0x00456b35:	cmpl %ebp, $0xfffffb00<UINT32>
0x00456b3b:	adcl %ecx, $0x2<UINT8>
0x00456b3e:	leal %edx, (%edi,%ebp)
0x00456b41:	cmpl %ebp, $0xfffffffc<UINT8>
0x00456b44:	jbe 0x00456b54
0x00456b54:	movl %eax, (%edx)
0x00456b56:	addl %edx, $0x4<UINT8>
0x00456b59:	movl (%edi), %eax
0x00456b5b:	addl %edi, $0x4<UINT8>
0x00456b5e:	subl %ecx, $0x4<UINT8>
0x00456b61:	ja 0x00456b54
0x00456b63:	addl %edi, %ecx
0x00456b65:	jmp 0x00456a96
0x00456b46:	movb %al, (%edx)
0x00456b48:	incl %edx
0x00456b49:	movb (%edi), %al
0x00456b4b:	incl %edi
0x00456b4c:	decl %ecx
0x00456b4d:	jne 0x00456b46
0x00456b4f:	jmp 0x00456a96
0x00456b08:	incl %ecx
0x00456b09:	addl %ebx, %ebx
0x00456b0b:	jne 0x00456b14
0x00456b14:	jb 0x00456ad4
0x00456b16:	addl %ebx, %ebx
0x00456b18:	jne 0x00456b21
0x00456b21:	adcl %ecx, %ecx
0x00456b23:	addl %ebx, %ebx
0x00456b25:	jae 0x00456b16
0x00456b27:	jne 0x00456b32
0x00456b32:	addl %ecx, $0x2<UINT8>
0x00456ad8:	movl %ebx, (%esi)
0x00456ada:	subl %esi, $0xfffffffc<UINT8>
0x00456add:	adcl %ebx, %ebx
0x00456afb:	addl %ebx, %ebx
0x00456afd:	jne 0x00456b06
0x00456ac4:	decl %eax
0x00456ac5:	addl %ebx, %ebx
0x00456ac7:	jne 0x00456ad0
0x00456ad0:	adcl %eax, %eax
0x00456ad2:	jmp 0x00456aa8
0x00456aac:	movl %ebx, (%esi)
0x00456aae:	subl %esi, $0xfffffffc<UINT8>
0x00456ab1:	adcl %ebx, %ebx
0x00456b29:	movl %ebx, (%esi)
0x00456b2b:	subl %esi, $0xfffffffc<UINT8>
0x00456b2e:	adcl %ebx, %ebx
0x00456b30:	jae 0x00456b16
0x00456abb:	movl %ebx, (%esi)
0x00456abd:	subl %esi, $0xfffffffc<UINT8>
0x00456ac0:	adcl %ebx, %ebx
0x00456ac2:	jb 0x00456ae3
0x00456aff:	movl %ebx, (%esi)
0x00456b01:	subl %esi, $0xfffffffc<UINT8>
0x00456b04:	adcl %ebx, %ebx
0x00456b0d:	movl %ebx, (%esi)
0x00456b0f:	subl %esi, $0xfffffffc<UINT8>
0x00456b12:	adcl %ebx, %ebx
0x00456b1a:	movl %ebx, (%esi)
0x00456b1c:	subl %esi, $0xfffffffc<UINT8>
0x00456b1f:	adcl %ebx, %ebx
0x00456ac9:	movl %ebx, (%esi)
0x00456acb:	subl %esi, $0xfffffffc<UINT8>
0x00456ace:	adcl %ebx, %ebx
0x00456b6a:	popl %esi
0x00456b6b:	movl %edi, %esi
0x00456b6d:	movl %ecx, $0x916<UINT32>
0x00456b72:	movb %al, (%edi)
0x00456b74:	incl %edi
0x00456b75:	subb %al, $0xffffffe8<UINT8>
0x00456b77:	cmpb %al, $0x1<UINT8>
0x00456b79:	ja 0x00456b72
0x00456b7b:	cmpb (%edi), $0x9<UINT8>
0x00456b7e:	jne 0x00456b72
0x00456b80:	movl %eax, (%edi)
0x00456b82:	movb %bl, 0x4(%edi)
0x00456b85:	shrw %ax, $0x8<UINT8>
0x00456b89:	roll %eax, $0x10<UINT8>
0x00456b8c:	xchgb %ah, %al
0x00456b8e:	subl %eax, %edi
0x00456b90:	subb %bl, $0xffffffe8<UINT8>
0x00456b93:	addl %eax, %esi
0x00456b95:	movl (%edi), %eax
0x00456b97:	addl %edi, $0x5<UINT8>
0x00456b9a:	movb %al, %bl
0x00456b9c:	loop 0x00456b77
0x00456b9e:	leal %edi, 0x54000(%esi)
0x00456ba4:	movl %eax, (%edi)
0x00456ba6:	orl %eax, %eax
0x00456ba8:	je 0x00456bef
0x00456baa:	movl %ebx, 0x4(%edi)
0x00456bad:	leal %eax, 0x565e0(%eax,%esi)
0x00456bb4:	addl %ebx, %esi
0x00456bb6:	pushl %eax
0x00456bb7:	addl %edi, $0x8<UINT8>
0x00456bba:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x00456bc0:	xchgl %ebp, %eax
0x00456bc1:	movb %al, (%edi)
0x00456bc3:	incl %edi
0x00456bc4:	orb %al, %al
0x00456bc6:	je 0x00456ba4
0x00456bc8:	movl %ecx, %edi
0x00456bca:	jns 0x00456bd3
0x00456bd3:	pushl %edi
0x00456bd4:	decl %eax
0x00456bd5:	repn scasb %al, %es:(%edi)
0x00456bd7:	pushl %ebp
0x00456bd8:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00456bde:	orl %eax, %eax
0x00456be0:	je 7
0x00456be2:	movl (%ebx), %eax
0x00456be4:	addl %ebx, $0x4<UINT8>
0x00456be7:	jmp 0x00456bc1
GetProcAddress@KERNEL32.DLL: API Node	
0x00456bcc:	movzwl %eax, (%edi)
0x00456bcf:	incl %edi
0x00456bd0:	pushl %eax
0x00456bd1:	incl %edi
0x00456bd2:	movl %ecx, $0xaef24857<UINT32>
0x00456bef:	movl %ebp, 0x566d8(%esi)
0x00456bf5:	leal %edi, -4096(%esi)
0x00456bfb:	movl %ebx, $0x1000<UINT32>
0x00456c00:	pushl %eax
0x00456c01:	pushl %esp
0x00456c02:	pushl $0x4<UINT8>
0x00456c04:	pushl %ebx
0x00456c05:	pushl %edi
0x00456c06:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00456c08:	leal %eax, 0x217(%edi)
0x00456c0e:	andb (%eax), $0x7f<UINT8>
0x00456c11:	andb 0x28(%eax), $0x7f<UINT8>
0x00456c15:	popl %eax
0x00456c16:	pushl %eax
0x00456c17:	pushl %esp
0x00456c18:	pushl %eax
0x00456c19:	pushl %ebx
0x00456c1a:	pushl %edi
0x00456c1b:	call VirtualProtect@kernel32.dll
0x00456c1d:	popl %eax
0x00456c1e:	popa
0x00456c1f:	leal %eax, -128(%esp)
0x00456c23:	pushl $0x0<UINT8>
0x00456c25:	cmpl %esp, %eax
0x00456c27:	jne 0x00456c23
0x00456c29:	subl %esp, $0xffffff80<UINT8>
0x00456c2c:	jmp 0x0040a0cf
0x0040a0cf:	call 0x004138aa
0x004138aa:	pushl %ebp
0x004138ab:	movl %ebp, %esp
0x004138ad:	subl %esp, $0x14<UINT8>
0x004138b0:	andl -12(%ebp), $0x0<UINT8>
0x004138b4:	andl -8(%ebp), $0x0<UINT8>
0x004138b8:	movl %eax, 0x42b190
0x004138bd:	pushl %esi
0x004138be:	pushl %edi
0x004138bf:	movl %edi, $0xbb40e64e<UINT32>
0x004138c4:	movl %esi, $0xffff0000<UINT32>
0x004138c9:	cmpl %eax, %edi
0x004138cb:	je 0x004138da
0x004138da:	leal %eax, -12(%ebp)
0x004138dd:	pushl %eax
0x004138de:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x004138e4:	movl %eax, -8(%ebp)
0x004138e7:	xorl %eax, -12(%ebp)
0x004138ea:	movl -4(%ebp), %eax
0x004138ed:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x004138f3:	xorl -4(%ebp), %eax
0x004138f6:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x004138fc:	xorl -4(%ebp), %eax
0x004138ff:	leal %eax, -20(%ebp)
0x00413902:	pushl %eax
0x00413903:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x00413909:	movl %ecx, -16(%ebp)
0x0041390c:	leal %eax, -4(%ebp)
0x0041390f:	xorl %ecx, -20(%ebp)
0x00413912:	xorl %ecx, -4(%ebp)
0x00413915:	xorl %ecx, %eax
0x00413917:	cmpl %ecx, %edi
0x00413919:	jne 0x00413922
0x00413922:	testl %esi, %ecx
0x00413924:	jne 0x00413932
0x00413932:	movl 0x42b190, %ecx
0x00413938:	notl %ecx
0x0041393a:	movl 0x42b194, %ecx
0x00413940:	popl %edi
0x00413941:	popl %esi
0x00413942:	movl %esp, %ebp
0x00413944:	popl %ebp
0x00413945:	ret

0x0040a0d4:	jmp 0x00409f54
0x00409f54:	pushl $0x14<UINT8>
0x00409f56:	pushl $0x429940<UINT32>
0x00409f5b:	call 0x0040bfa0
0x0040bfa0:	pushl $0x409030<UINT32>
0x0040bfa5:	pushl %fs:0
0x0040bfac:	movl %eax, 0x10(%esp)
0x0040bfb0:	movl 0x10(%esp), %ebp
0x0040bfb4:	leal %ebp, 0x10(%esp)
0x0040bfb8:	subl %esp, %eax
0x0040bfba:	pushl %ebx
0x0040bfbb:	pushl %esi
0x0040bfbc:	pushl %edi
0x0040bfbd:	movl %eax, 0x42b190
0x0040bfc2:	xorl -4(%ebp), %eax
0x0040bfc5:	xorl %eax, %ebp
0x0040bfc7:	pushl %eax
0x0040bfc8:	movl -24(%ebp), %esp
0x0040bfcb:	pushl -8(%ebp)
0x0040bfce:	movl %eax, -4(%ebp)
0x0040bfd1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040bfd8:	movl -8(%ebp), %eax
0x0040bfdb:	leal %eax, -16(%ebp)
0x0040bfde:	movl %fs:0, %eax
0x0040bfe4:	ret

0x00409f60:	pushl $0x1<UINT8>
0x00409f62:	call 0x0041385d
0x0041385d:	pushl %ebp
0x0041385e:	movl %ebp, %esp
0x00413860:	movl %eax, 0x8(%ebp)
0x00413863:	movl 0x433d68, %eax
0x00413868:	popl %ebp
0x00413869:	ret

0x00409f67:	popl %ecx
0x00409f68:	movl %eax, $0x5a4d<UINT32>
0x00409f6d:	cmpw 0x400000, %ax
0x00409f74:	je 0x00409f7a
0x00409f7a:	movl %eax, 0x40003c
0x00409f7f:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00409f89:	jne -21
0x00409f8b:	movl %ecx, $0x10b<UINT32>
0x00409f90:	cmpw 0x400018(%eax), %cx
0x00409f97:	jne -35
0x00409f99:	xorl %ebx, %ebx
0x00409f9b:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00409fa2:	jbe 9
0x00409fa4:	cmpl 0x4000e8(%eax), %ebx
0x00409faa:	setne %bl
0x00409fad:	movl -28(%ebp), %ebx
0x00409fb0:	call 0x0040c0d0
0x0040c0d0:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x0040c0d6:	xorl %ecx, %ecx
0x0040c0d8:	movl 0x4343c8, %eax
0x0040c0dd:	testl %eax, %eax
0x0040c0df:	setne %cl
0x0040c0e2:	movl %eax, %ecx
0x0040c0e4:	ret

0x00409fb5:	testl %eax, %eax
0x00409fb7:	jne 0x00409fc1
0x00409fc1:	call 0x0040b017
0x0040b017:	call 0x00406e14
0x00406e14:	pushl %esi
0x00406e15:	pushl $0x0<UINT8>
0x00406e17:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00406e1d:	movl %esi, %eax
0x00406e1f:	pushl %esi
0x00406e20:	call 0x0040bd52
0x0040bd52:	pushl %ebp
0x0040bd53:	movl %ebp, %esp
0x0040bd55:	movl %eax, 0x8(%ebp)
0x0040bd58:	movl 0x4343a0, %eax
0x0040bd5d:	popl %ebp
0x0040bd5e:	ret

0x00406e25:	pushl %esi
0x00406e26:	call 0x0040a1fe
0x0040a1fe:	pushl %ebp
0x0040a1ff:	movl %ebp, %esp
0x0040a201:	movl %eax, 0x8(%ebp)
0x0040a204:	movl 0x433bf4, %eax
0x0040a209:	popl %ebp
0x0040a20a:	ret

0x00406e2b:	pushl %esi
0x00406e2c:	call 0x0040bd5f
0x0040bd5f:	pushl %ebp
0x0040bd60:	movl %ebp, %esp
0x0040bd62:	movl %eax, 0x8(%ebp)
0x0040bd65:	movl 0x4343a4, %eax
0x0040bd6a:	popl %ebp
0x0040bd6b:	ret

0x00406e31:	pushl %esi
0x00406e32:	call 0x0040bd79
0x0040bd79:	pushl %ebp
0x0040bd7a:	movl %ebp, %esp
0x0040bd7c:	movl %eax, 0x8(%ebp)
0x0040bd7f:	movl 0x4343a8, %eax
0x0040bd84:	movl 0x4343ac, %eax
0x0040bd89:	movl 0x4343b0, %eax
0x0040bd8e:	movl 0x4343b4, %eax
0x0040bd93:	popl %ebp
0x0040bd94:	ret

0x00406e37:	pushl %esi
0x00406e38:	call 0x0040bd1b
0x0040bd1b:	pushl $0x40bce7<UINT32>
0x0040bd20:	call EncodePointer@KERNEL32.DLL
0x0040bd26:	movl 0x43439c, %eax
0x0040bd2b:	ret

0x00406e3d:	pushl %esi
0x00406e3e:	call 0x0040bf8a
0x0040bf8a:	pushl %ebp
0x0040bf8b:	movl %ebp, %esp
0x0040bf8d:	movl %eax, 0x8(%ebp)
0x0040bf90:	movl 0x4343bc, %eax
0x0040bf95:	popl %ebp
0x0040bf96:	ret

0x00406e43:	addl %esp, $0x18<UINT8>
0x00406e46:	popl %esi
0x00406e47:	jmp 0x0040b42f
0x0040b42f:	pushl %esi
0x0040b430:	pushl %edi
0x0040b431:	pushl $0x425d68<UINT32>
0x0040b436:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0040b43c:	movl %esi, 0x41b0f8
0x0040b442:	movl %edi, %eax
0x0040b444:	pushl $0x425d84<UINT32>
0x0040b449:	pushl %edi
0x0040b44a:	call GetProcAddress@KERNEL32.DLL
0x0040b44c:	xorl %eax, 0x42b190
0x0040b452:	pushl $0x425d90<UINT32>
0x0040b457:	pushl %edi
0x0040b458:	movl 0x434a40, %eax
0x0040b45d:	call GetProcAddress@KERNEL32.DLL
0x0040b45f:	xorl %eax, 0x42b190
0x0040b465:	pushl $0x425d98<UINT32>
0x0040b46a:	pushl %edi
0x0040b46b:	movl 0x434a44, %eax
0x0040b470:	call GetProcAddress@KERNEL32.DLL
0x0040b472:	xorl %eax, 0x42b190
0x0040b478:	pushl $0x425da4<UINT32>
0x0040b47d:	pushl %edi
0x0040b47e:	movl 0x434a48, %eax
0x0040b483:	call GetProcAddress@KERNEL32.DLL
0x0040b485:	xorl %eax, 0x42b190
0x0040b48b:	pushl $0x425db0<UINT32>
0x0040b490:	pushl %edi
0x0040b491:	movl 0x434a4c, %eax
0x0040b496:	call GetProcAddress@KERNEL32.DLL
0x0040b498:	xorl %eax, 0x42b190
0x0040b49e:	pushl $0x425dcc<UINT32>
0x0040b4a3:	pushl %edi
0x0040b4a4:	movl 0x434a50, %eax
0x0040b4a9:	call GetProcAddress@KERNEL32.DLL
0x0040b4ab:	xorl %eax, 0x42b190
0x0040b4b1:	pushl $0x425ddc<UINT32>
0x0040b4b6:	pushl %edi
0x0040b4b7:	movl 0x434a54, %eax
0x0040b4bc:	call GetProcAddress@KERNEL32.DLL
0x0040b4be:	xorl %eax, 0x42b190
0x0040b4c4:	pushl $0x425df0<UINT32>
0x0040b4c9:	pushl %edi
0x0040b4ca:	movl 0x434a58, %eax
0x0040b4cf:	call GetProcAddress@KERNEL32.DLL
0x0040b4d1:	xorl %eax, 0x42b190
0x0040b4d7:	pushl $0x425e08<UINT32>
0x0040b4dc:	pushl %edi
0x0040b4dd:	movl 0x434a5c, %eax
0x0040b4e2:	call GetProcAddress@KERNEL32.DLL
0x0040b4e4:	xorl %eax, 0x42b190
0x0040b4ea:	pushl $0x425e20<UINT32>
0x0040b4ef:	pushl %edi
0x0040b4f0:	movl 0x434a60, %eax
0x0040b4f5:	call GetProcAddress@KERNEL32.DLL
0x0040b4f7:	xorl %eax, 0x42b190
0x0040b4fd:	pushl $0x425e34<UINT32>
0x0040b502:	pushl %edi
0x0040b503:	movl 0x434a64, %eax
0x0040b508:	call GetProcAddress@KERNEL32.DLL
0x0040b50a:	xorl %eax, 0x42b190
0x0040b510:	pushl $0x425e54<UINT32>
0x0040b515:	pushl %edi
0x0040b516:	movl 0x434a68, %eax
0x0040b51b:	call GetProcAddress@KERNEL32.DLL
0x0040b51d:	xorl %eax, 0x42b190
0x0040b523:	pushl $0x425e6c<UINT32>
0x0040b528:	pushl %edi
0x0040b529:	movl 0x434a6c, %eax
0x0040b52e:	call GetProcAddress@KERNEL32.DLL
0x0040b530:	xorl %eax, 0x42b190
0x0040b536:	pushl $0x425e84<UINT32>
0x0040b53b:	pushl %edi
0x0040b53c:	movl 0x434a70, %eax
0x0040b541:	call GetProcAddress@KERNEL32.DLL
0x0040b543:	xorl %eax, 0x42b190
0x0040b549:	pushl $0x425e98<UINT32>
0x0040b54e:	pushl %edi
0x0040b54f:	movl 0x434a74, %eax
0x0040b554:	call GetProcAddress@KERNEL32.DLL
0x0040b556:	xorl %eax, 0x42b190
0x0040b55c:	movl 0x434a78, %eax
0x0040b561:	pushl $0x425eac<UINT32>
0x0040b566:	pushl %edi
0x0040b567:	call GetProcAddress@KERNEL32.DLL
0x0040b569:	xorl %eax, 0x42b190
0x0040b56f:	pushl $0x425ec8<UINT32>
0x0040b574:	pushl %edi
0x0040b575:	movl 0x434a7c, %eax
0x0040b57a:	call GetProcAddress@KERNEL32.DLL
0x0040b57c:	xorl %eax, 0x42b190
0x0040b582:	pushl $0x425ee8<UINT32>
0x0040b587:	pushl %edi
0x0040b588:	movl 0x434a80, %eax
0x0040b58d:	call GetProcAddress@KERNEL32.DLL
0x0040b58f:	xorl %eax, 0x42b190
0x0040b595:	pushl $0x425f04<UINT32>
0x0040b59a:	pushl %edi
0x0040b59b:	movl 0x434a84, %eax
0x0040b5a0:	call GetProcAddress@KERNEL32.DLL
0x0040b5a2:	xorl %eax, 0x42b190
0x0040b5a8:	pushl $0x425f24<UINT32>
0x0040b5ad:	pushl %edi
0x0040b5ae:	movl 0x434a88, %eax
0x0040b5b3:	call GetProcAddress@KERNEL32.DLL
0x0040b5b5:	xorl %eax, 0x42b190
0x0040b5bb:	pushl $0x425f38<UINT32>
0x0040b5c0:	pushl %edi
0x0040b5c1:	movl 0x434a8c, %eax
0x0040b5c6:	call GetProcAddress@KERNEL32.DLL
0x0040b5c8:	xorl %eax, 0x42b190
0x0040b5ce:	pushl $0x425f54<UINT32>
0x0040b5d3:	pushl %edi
0x0040b5d4:	movl 0x434a90, %eax
0x0040b5d9:	call GetProcAddress@KERNEL32.DLL
0x0040b5db:	xorl %eax, 0x42b190
0x0040b5e1:	pushl $0x425f68<UINT32>
0x0040b5e6:	pushl %edi
0x0040b5e7:	movl 0x434a98, %eax
0x0040b5ec:	call GetProcAddress@KERNEL32.DLL
0x0040b5ee:	xorl %eax, 0x42b190
0x0040b5f4:	pushl $0x425f78<UINT32>
0x0040b5f9:	pushl %edi
0x0040b5fa:	movl 0x434a94, %eax
0x0040b5ff:	call GetProcAddress@KERNEL32.DLL
0x0040b601:	xorl %eax, 0x42b190
0x0040b607:	pushl $0x425f88<UINT32>
0x0040b60c:	pushl %edi
0x0040b60d:	movl 0x434a9c, %eax
0x0040b612:	call GetProcAddress@KERNEL32.DLL
0x0040b614:	xorl %eax, 0x42b190
0x0040b61a:	pushl $0x425f98<UINT32>
0x0040b61f:	pushl %edi
0x0040b620:	movl 0x434aa0, %eax
0x0040b625:	call GetProcAddress@KERNEL32.DLL
0x0040b627:	xorl %eax, 0x42b190
0x0040b62d:	pushl $0x425fa8<UINT32>
0x0040b632:	pushl %edi
0x0040b633:	movl 0x434aa4, %eax
0x0040b638:	call GetProcAddress@KERNEL32.DLL
0x0040b63a:	xorl %eax, 0x42b190
0x0040b640:	pushl $0x425fc4<UINT32>
0x0040b645:	pushl %edi
0x0040b646:	movl 0x434aa8, %eax
0x0040b64b:	call GetProcAddress@KERNEL32.DLL
0x0040b64d:	xorl %eax, 0x42b190
0x0040b653:	pushl $0x425fd8<UINT32>
0x0040b658:	pushl %edi
0x0040b659:	movl 0x434aac, %eax
0x0040b65e:	call GetProcAddress@KERNEL32.DLL
0x0040b660:	xorl %eax, 0x42b190
0x0040b666:	pushl $0x425fe8<UINT32>
0x0040b66b:	pushl %edi
0x0040b66c:	movl 0x434ab0, %eax
0x0040b671:	call GetProcAddress@KERNEL32.DLL
0x0040b673:	xorl %eax, 0x42b190
0x0040b679:	pushl $0x425ffc<UINT32>
0x0040b67e:	pushl %edi
0x0040b67f:	movl 0x434ab4, %eax
0x0040b684:	call GetProcAddress@KERNEL32.DLL
0x0040b686:	xorl %eax, 0x42b190
0x0040b68c:	movl 0x434ab8, %eax
0x0040b691:	pushl $0x42600c<UINT32>
0x0040b696:	pushl %edi
0x0040b697:	call GetProcAddress@KERNEL32.DLL
0x0040b699:	xorl %eax, 0x42b190
0x0040b69f:	pushl $0x42602c<UINT32>
0x0040b6a4:	pushl %edi
0x0040b6a5:	movl 0x434abc, %eax
0x0040b6aa:	call GetProcAddress@KERNEL32.DLL
0x0040b6ac:	xorl %eax, 0x42b190
0x0040b6b2:	popl %edi
0x0040b6b3:	movl 0x434ac0, %eax
0x0040b6b8:	popl %esi
0x0040b6b9:	ret

0x0040b01c:	call 0x0040b2f5
0x0040b2f5:	pushl %esi
0x0040b2f6:	pushl %edi
0x0040b2f7:	movl %esi, $0x42bcf0<UINT32>
0x0040b2fc:	movl %edi, $0x433c18<UINT32>
0x0040b301:	cmpl 0x4(%esi), $0x1<UINT8>
0x0040b305:	jne 22
0x0040b307:	pushl $0x0<UINT8>
0x0040b309:	movl (%esi), %edi
0x0040b30b:	addl %edi, $0x18<UINT8>
0x0040b30e:	pushl $0xfa0<UINT32>
0x0040b313:	pushl (%esi)
0x0040b315:	call 0x0040b3c1
0x0040b3c1:	pushl %ebp
0x0040b3c2:	movl %ebp, %esp
0x0040b3c4:	movl %eax, 0x434a50
0x0040b3c9:	xorl %eax, 0x42b190
0x0040b3cf:	je 13
0x0040b3d1:	pushl 0x10(%ebp)
0x0040b3d4:	pushl 0xc(%ebp)
0x0040b3d7:	pushl 0x8(%ebp)
0x0040b3da:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x0040b3dc:	popl %ebp
0x0040b3dd:	ret

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
