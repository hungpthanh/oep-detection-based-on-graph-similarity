0x004dd7e0:	pusha
0x004dd7e1:	movl %esi, $0x4b8000<UINT32>
0x004dd7e6:	leal %edi, -749568(%esi)
0x004dd7ec:	pushl %edi
0x004dd7ed:	orl %ebp, $0xffffffff<UINT8>
0x004dd7f0:	jmp 0x004dd802
0x004dd802:	movl %ebx, (%esi)
0x004dd804:	subl %esi, $0xfffffffc<UINT8>
0x004dd807:	adcl %ebx, %ebx
0x004dd809:	jb 0x004dd7f8
0x004dd7f8:	movb %al, (%esi)
0x004dd7fa:	incl %esi
0x004dd7fb:	movb (%edi), %al
0x004dd7fd:	incl %edi
0x004dd7fe:	addl %ebx, %ebx
0x004dd800:	jne 0x004dd809
0x004dd80b:	movl %eax, $0x1<UINT32>
0x004dd810:	addl %ebx, %ebx
0x004dd812:	jne 0x004dd81b
0x004dd81b:	adcl %eax, %eax
0x004dd81d:	addl %ebx, %ebx
0x004dd81f:	jae 0x004dd82c
0x004dd821:	jne 0x004dd84b
0x004dd84b:	xorl %ecx, %ecx
0x004dd84d:	subl %eax, $0x3<UINT8>
0x004dd850:	jb 0x004dd863
0x004dd863:	addl %ebx, %ebx
0x004dd865:	jne 0x004dd86e
0x004dd86e:	jb 0x004dd83c
0x004dd83c:	addl %ebx, %ebx
0x004dd83e:	jne 0x004dd847
0x004dd847:	adcl %ecx, %ecx
0x004dd849:	jmp 0x004dd89d
0x004dd89d:	cmpl %ebp, $0xfffffb00<UINT32>
0x004dd8a3:	adcl %ecx, $0x2<UINT8>
0x004dd8a6:	leal %edx, (%edi,%ebp)
0x004dd8a9:	cmpl %ebp, $0xfffffffc<UINT8>
0x004dd8ac:	jbe 0x004dd8bc
0x004dd8ae:	movb %al, (%edx)
0x004dd8b0:	incl %edx
0x004dd8b1:	movb (%edi), %al
0x004dd8b3:	incl %edi
0x004dd8b4:	decl %ecx
0x004dd8b5:	jne 0x004dd8ae
0x004dd8b7:	jmp 0x004dd7fe
0x004dd852:	shll %eax, $0x8<UINT8>
0x004dd855:	movb %al, (%esi)
0x004dd857:	incl %esi
0x004dd858:	xorl %eax, $0xffffffff<UINT8>
0x004dd85b:	je 0x004dd8d2
0x004dd85d:	sarl %eax
0x004dd85f:	movl %ebp, %eax
0x004dd861:	jmp 0x004dd86e
0x004dd8bc:	movl %eax, (%edx)
0x004dd8be:	addl %edx, $0x4<UINT8>
0x004dd8c1:	movl (%edi), %eax
0x004dd8c3:	addl %edi, $0x4<UINT8>
0x004dd8c6:	subl %ecx, $0x4<UINT8>
0x004dd8c9:	ja 0x004dd8bc
0x004dd8cb:	addl %edi, %ecx
0x004dd8cd:	jmp 0x004dd7fe
0x004dd823:	movl %ebx, (%esi)
0x004dd825:	subl %esi, $0xfffffffc<UINT8>
0x004dd828:	adcl %ebx, %ebx
0x004dd82a:	jb 0x004dd84b
0x004dd870:	incl %ecx
0x004dd871:	addl %ebx, %ebx
0x004dd873:	jne 0x004dd87c
0x004dd87c:	jb 0x004dd83c
0x004dd87e:	addl %ebx, %ebx
0x004dd880:	jne 0x004dd889
0x004dd889:	adcl %ecx, %ecx
0x004dd88b:	addl %ebx, %ebx
0x004dd88d:	jae 0x004dd87e
0x004dd882:	movl %ebx, (%esi)
0x004dd884:	subl %esi, $0xfffffffc<UINT8>
0x004dd887:	adcl %ebx, %ebx
0x004dd88f:	jne 0x004dd89a
0x004dd89a:	addl %ecx, $0x2<UINT8>
0x004dd82c:	decl %eax
0x004dd82d:	addl %ebx, %ebx
0x004dd82f:	jne 0x004dd838
0x004dd838:	adcl %eax, %eax
0x004dd83a:	jmp 0x004dd810
0x004dd814:	movl %ebx, (%esi)
0x004dd816:	subl %esi, $0xfffffffc<UINT8>
0x004dd819:	adcl %ebx, %ebx
0x004dd840:	movl %ebx, (%esi)
0x004dd842:	subl %esi, $0xfffffffc<UINT8>
0x004dd845:	adcl %ebx, %ebx
0x004dd867:	movl %ebx, (%esi)
0x004dd869:	subl %esi, $0xfffffffc<UINT8>
0x004dd86c:	adcl %ebx, %ebx
0x004dd891:	movl %ebx, (%esi)
0x004dd893:	subl %esi, $0xfffffffc<UINT8>
0x004dd896:	adcl %ebx, %ebx
0x004dd898:	jae 0x004dd87e
0x004dd875:	movl %ebx, (%esi)
0x004dd877:	subl %esi, $0xfffffffc<UINT8>
0x004dd87a:	adcl %ebx, %ebx
0x004dd831:	movl %ebx, (%esi)
0x004dd833:	subl %esi, $0xfffffffc<UINT8>
0x004dd836:	adcl %ebx, %ebx
0x004dd8d2:	popl %esi
0x004dd8d3:	movl %edi, %esi
0x004dd8d5:	movl %ecx, $0xfc2<UINT32>
0x004dd8da:	movb %al, (%edi)
0x004dd8dc:	incl %edi
0x004dd8dd:	subb %al, $0xffffffe8<UINT8>
0x004dd8df:	cmpb %al, $0x1<UINT8>
0x004dd8e1:	ja 0x004dd8da
0x004dd8e3:	cmpb (%edi), $0x11<UINT8>
0x004dd8e6:	jne 0x004dd8da
0x004dd8e8:	movl %eax, (%edi)
0x004dd8ea:	movb %bl, 0x4(%edi)
0x004dd8ed:	shrw %ax, $0x8<UINT8>
0x004dd8f1:	roll %eax, $0x10<UINT8>
0x004dd8f4:	xchgb %ah, %al
0x004dd8f6:	subl %eax, %edi
0x004dd8f8:	subb %bl, $0xffffffe8<UINT8>
0x004dd8fb:	addl %eax, %esi
0x004dd8fd:	movl (%edi), %eax
0x004dd8ff:	addl %edi, $0x5<UINT8>
0x004dd902:	movb %al, %bl
0x004dd904:	loop 0x004dd8df
0x004dd906:	leal %edi, 0xda000(%esi)
0x004dd90c:	movl %eax, (%edi)
0x004dd90e:	orl %eax, %eax
0x004dd910:	je 0x004dd957
0x004dd912:	movl %ebx, 0x4(%edi)
0x004dd915:	leal %eax, 0xde214(%eax,%esi)
0x004dd91c:	addl %ebx, %esi
0x004dd91e:	pushl %eax
0x004dd91f:	addl %edi, $0x8<UINT8>
0x004dd922:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x004dd928:	xchgl %ebp, %eax
0x004dd929:	movb %al, (%edi)
0x004dd92b:	incl %edi
0x004dd92c:	orb %al, %al
0x004dd92e:	je 0x004dd90c
0x004dd930:	movl %ecx, %edi
0x004dd932:	jns 0x004dd93b
0x004dd93b:	pushl %edi
0x004dd93c:	decl %eax
0x004dd93d:	repn scasb %al, %es:(%edi)
0x004dd93f:	pushl %ebp
0x004dd940:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x004dd946:	orl %eax, %eax
0x004dd948:	je 7
0x004dd94a:	movl (%ebx), %eax
0x004dd94c:	addl %ebx, $0x4<UINT8>
0x004dd94f:	jmp 0x004dd929
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x004dd934:	movzwl %eax, (%edi)
0x004dd937:	incl %edi
0x004dd938:	pushl %eax
0x004dd939:	incl %edi
0x004dd93a:	movl %ecx, $0xaef24857<UINT32>
0x004dd957:	movl %ebp, 0xde308(%esi)
0x004dd95d:	leal %edi, -4096(%esi)
0x004dd963:	movl %ebx, $0x1000<UINT32>
0x004dd968:	pushl %eax
0x004dd969:	pushl %esp
0x004dd96a:	pushl $0x4<UINT8>
0x004dd96c:	pushl %ebx
0x004dd96d:	pushl %edi
0x004dd96e:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x004dd970:	leal %eax, 0x1ff(%edi)
0x004dd976:	andb (%eax), $0x7f<UINT8>
0x004dd979:	andb 0x28(%eax), $0x7f<UINT8>
0x004dd97d:	popl %eax
0x004dd97e:	pushl %eax
0x004dd97f:	pushl %esp
0x004dd980:	pushl %eax
0x004dd981:	pushl %ebx
0x004dd982:	pushl %edi
0x004dd983:	call VirtualProtect@kernel32.dll
0x004dd985:	popl %eax
0x004dd986:	popa
0x004dd987:	leal %eax, -128(%esp)
0x004dd98b:	pushl $0x0<UINT8>
0x004dd98d:	cmpl %esp, %eax
0x004dd98f:	jne 0x004dd98b
0x004dd991:	subl %esp, $0xffffff80<UINT8>
0x004dd994:	jmp 0x00413b0e
0x00413b0e:	call 0x0041f959
0x0041f959:	movl %edi, %edi
0x0041f95b:	pushl %ebp
0x0041f95c:	movl %ebp, %esp
0x0041f95e:	subl %esp, $0x10<UINT8>
0x0041f961:	movl %eax, 0x43b810
0x0041f966:	andl -8(%ebp), $0x0<UINT8>
0x0041f96a:	andl -4(%ebp), $0x0<UINT8>
0x0041f96e:	pushl %ebx
0x0041f96f:	pushl %edi
0x0041f970:	movl %edi, $0xbb40e64e<UINT32>
0x0041f975:	movl %ebx, $0xffff0000<UINT32>
0x0041f97a:	cmpl %eax, %edi
0x0041f97c:	je 0x0041f98b
0x0041f98b:	pushl %esi
0x0041f98c:	leal %eax, -8(%ebp)
0x0041f98f:	pushl %eax
0x0041f990:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0041f996:	movl %esi, -4(%ebp)
0x0041f999:	xorl %esi, -8(%ebp)
0x0041f99c:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0041f9a2:	xorl %esi, %eax
0x0041f9a4:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0041f9aa:	xorl %esi, %eax
0x0041f9ac:	call GetTickCount@KERNEL32.DLL
GetTickCount@KERNEL32.DLL: API Node	
0x0041f9b2:	xorl %esi, %eax
0x0041f9b4:	leal %eax, -16(%ebp)
0x0041f9b7:	pushl %eax
0x0041f9b8:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0041f9be:	movl %eax, -12(%ebp)
0x0041f9c1:	xorl %eax, -16(%ebp)
0x0041f9c4:	xorl %esi, %eax
0x0041f9c6:	cmpl %esi, %edi
0x0041f9c8:	jne 0x0041f9d1
0x0041f9d1:	testl %ebx, %esi
0x0041f9d3:	jne 0x0041f9dc
0x0041f9dc:	movl 0x43b810, %esi
0x0041f9e2:	notl %esi
0x0041f9e4:	movl 0x43b814, %esi
0x0041f9ea:	popl %esi
0x0041f9eb:	popl %edi
0x0041f9ec:	popl %ebx
0x0041f9ed:	leave
0x0041f9ee:	ret

0x00413b13:	jmp 0x00413990
0x00413990:	pushl $0x58<UINT8>
0x00413992:	pushl $0x434318<UINT32>
0x00413997:	call 0x00414d00
0x00414d00:	pushl $0x414d90<UINT32>
0x00414d05:	pushl %fs:0
0x00414d0c:	movl %eax, 0x10(%esp)
0x00414d10:	movl 0x10(%esp), %ebp
0x00414d14:	leal %ebp, 0x10(%esp)
0x00414d18:	subl %esp, %eax
0x00414d1a:	pushl %ebx
0x00414d1b:	pushl %esi
0x00414d1c:	pushl %edi
0x00414d1d:	movl %eax, 0x43b810
0x00414d22:	xorl -4(%ebp), %eax
0x00414d25:	xorl %eax, %ebp
0x00414d27:	pushl %eax
0x00414d28:	movl -24(%ebp), %esp
0x00414d2b:	pushl -8(%ebp)
0x00414d2e:	movl %eax, -4(%ebp)
0x00414d31:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00414d38:	movl -8(%ebp), %eax
0x00414d3b:	leal %eax, -16(%ebp)
0x00414d3e:	movl %fs:0, %eax
0x00414d44:	ret

0x0041399c:	xorl %esi, %esi
0x0041399e:	movl -4(%ebp), %esi
0x004139a1:	leal %eax, -104(%ebp)
0x004139a4:	pushl %eax
0x004139a5:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x004139ab:	pushl $0xfffffffe<UINT8>
0x004139ad:	popl %edi
0x004139ae:	movl -4(%ebp), %edi
0x004139b1:	movl %eax, $0x5a4d<UINT32>
0x004139b6:	cmpw 0x400000, %ax
0x004139bd:	jne 56
0x004139bf:	movl %eax, 0x40003c
0x004139c4:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x004139ce:	jne 39
0x004139d0:	movl %ecx, $0x10b<UINT32>
0x004139d5:	cmpw 0x400018(%eax), %cx
0x004139dc:	jne 25
0x004139de:	cmpl 0x400074(%eax), $0xe<UINT8>
0x004139e5:	jbe 16
0x004139e7:	xorl %ecx, %ecx
0x004139e9:	cmpl 0x4000e8(%eax), %esi
0x004139ef:	setne %cl
0x004139f2:	movl -28(%ebp), %ecx
0x004139f5:	jmp 0x004139fa
0x004139fa:	xorl %ebx, %ebx
0x004139fc:	incl %ebx
0x004139fd:	pushl %ebx
0x004139fe:	call 0x00414f20
0x00414f20:	movl %edi, %edi
0x00414f22:	pushl %ebp
0x00414f23:	movl %ebp, %esp
0x00414f25:	xorl %eax, %eax
0x00414f27:	cmpl 0x8(%ebp), %eax
0x00414f2a:	pushl $0x0<UINT8>
0x00414f2c:	sete %al
0x00414f2f:	pushl $0x1000<UINT32>
0x00414f34:	pushl %eax
0x00414f35:	call HeapCreate@KERNEL32.DLL
HeapCreate@KERNEL32.DLL: API Node	
0x00414f3b:	movl 0x443004, %eax
0x00414f40:	testl %eax, %eax
0x00414f42:	jne 0x00414f46
0x00414f46:	xorl %eax, %eax
0x00414f48:	incl %eax
0x00414f49:	movl 0x4a8fa4, %eax
0x00414f4e:	popl %ebp
0x00414f4f:	ret

0x00413a03:	popl %ecx
0x00413a04:	testl %eax, %eax
0x00413a06:	jne 0x00413a10
0x00413a10:	call 0x00418e48
0x00418e48:	movl %edi, %edi
0x00418e4a:	pushl %esi
0x00418e4b:	pushl %edi
0x00418e4c:	movl %esi, $0x432cec<UINT32>
0x00418e51:	pushl %esi
0x00418e52:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00418e58:	testl %eax, %eax
0x00418e5a:	jne 0x00418e63
0x00418e63:	movl %edi, %eax
0x00418e65:	testl %edi, %edi
0x00418e67:	je 350
0x00418e6d:	movl %esi, 0x432280
0x00418e73:	pushl $0x432d38<UINT32>
0x00418e78:	pushl %edi
0x00418e79:	call GetProcAddress@KERNEL32.DLL
0x00418e7b:	pushl $0x432d2c<UINT32>
0x00418e80:	pushl %edi
0x00418e81:	movl 0x4436c4, %eax
0x00418e86:	call GetProcAddress@KERNEL32.DLL
0x00418e88:	pushl $0x432d20<UINT32>
0x00418e8d:	pushl %edi
0x00418e8e:	movl 0x4436c8, %eax
0x00418e93:	call GetProcAddress@KERNEL32.DLL
0x00418e95:	pushl $0x432d18<UINT32>
0x00418e9a:	pushl %edi
0x00418e9b:	movl 0x4436cc, %eax
0x00418ea0:	call GetProcAddress@KERNEL32.DLL
0x00418ea2:	cmpl 0x4436c4, $0x0<UINT8>
0x00418ea9:	movl %esi, 0x4321b0
0x00418eaf:	movl 0x4436d0, %eax
0x00418eb4:	je 22
0x00418eb6:	cmpl 0x4436c8, $0x0<UINT8>
0x00418ebd:	je 13
0x00418ebf:	cmpl 0x4436cc, $0x0<UINT8>
0x00418ec6:	je 4
0x00418ec8:	testl %eax, %eax
0x00418eca:	jne 0x00418ef0
0x00418ef0:	call TlsAlloc@KERNEL32.DLL
TlsAlloc@KERNEL32.DLL: API Node	
0x00418ef6:	movl 0x43c1ac, %eax
0x00418efb:	cmpl %eax, $0xffffffff<UINT8>
0x00418efe:	je 204
0x00418f04:	pushl 0x4436c8
0x00418f0a:	pushl %eax
0x00418f0b:	call TlsSetValue@KERNEL32.DLL
TlsSetValue@KERNEL32.DLL: API Node	
0x00418f0d:	testl %eax, %eax
0x00418f0f:	je 187
0x00418f15:	call 0x0041532c
0x0041532c:	movl %edi, %edi
0x0041532e:	pushl %esi
0x0041532f:	call 0x004189f3
0x004189f3:	pushl $0x0<UINT8>
0x004189f5:	call 0x00418981
0x00418981:	movl %edi, %edi
0x00418983:	pushl %ebp
0x00418984:	movl %ebp, %esp
0x00418986:	pushl %esi
0x00418987:	pushl 0x43c1ac
0x0041898d:	movl %esi, 0x4321b8
0x00418993:	call TlsGetValue@KERNEL32.DLL
TlsGetValue@KERNEL32.DLL: API Node	
0x00418995:	testl %eax, %eax
0x00418997:	je 33
0x00418999:	movl %eax, 0x43c1a8
0x0041899e:	cmpl %eax, $0xffffffff<UINT8>
0x004189a1:	je 0x004189ba
0x004189ba:	movl %esi, $0x432cec<UINT32>
0x004189bf:	pushl %esi
0x004189c0:	call GetModuleHandleW@KERNEL32.DLL
0x004189c6:	testl %eax, %eax
0x004189c8:	jne 0x004189d5
0x004189d5:	pushl $0x432cdc<UINT32>
0x004189da:	pushl %eax
0x004189db:	call GetProcAddress@KERNEL32.DLL
0x004189e1:	testl %eax, %eax
0x004189e3:	je 8
0x004189e5:	pushl 0x8(%ebp)
0x004189e8:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x004189ea:	movl 0x8(%ebp), %eax
0x004189ed:	movl %eax, 0x8(%ebp)
0x004189f0:	popl %esi
0x004189f1:	popl %ebp
0x004189f2:	ret

0x004189fa:	popl %ecx
0x004189fb:	ret

0x00415334:	movl %esi, %eax
0x00415336:	pushl %esi
0x00415337:	call 0x004156d3
0x004156d3:	movl %edi, %edi
0x004156d5:	pushl %ebp
0x004156d6:	movl %ebp, %esp
0x004156d8:	movl %eax, 0x8(%ebp)
0x004156db:	movl 0x443354, %eax
0x004156e0:	popl %ebp
0x004156e1:	ret

0x0041533c:	pushl %esi
0x0041533d:	call 0x0041f9ef
0x0041f9ef:	movl %edi, %edi
0x0041f9f1:	pushl %ebp
0x0041f9f2:	movl %ebp, %esp
0x0041f9f4:	movl %eax, 0x8(%ebp)
0x0041f9f7:	movl 0x4437f4, %eax
0x0041f9fc:	popl %ebp
0x0041f9fd:	ret

0x00415342:	pushl %esi
0x00415343:	call 0x0041675b
0x0041675b:	movl %edi, %edi
0x0041675d:	pushl %ebp
0x0041675e:	movl %ebp, %esp
0x00416760:	movl %eax, 0x8(%ebp)
0x00416763:	movl 0x44335c, %eax
0x00416768:	popl %ebp
0x00416769:	ret

0x00415348:	pushl %esi
0x00415349:	call 0x0042072a
0x0042072a:	movl %edi, %edi
0x0042072c:	pushl %ebp
0x0042072d:	movl %ebp, %esp
0x0042072f:	movl %eax, 0x8(%ebp)
0x00420732:	movl 0x44381c, %eax
0x00420737:	popl %ebp
0x00420738:	ret

0x0041534e:	pushl %esi
0x0041534f:	call 0x00420494
0x00420494:	movl %edi, %edi
0x00420496:	pushl %ebp
0x00420497:	movl %ebp, %esp
0x00420499:	movl %eax, 0x8(%ebp)
0x0042049c:	movl 0x443810, %eax
0x004204a1:	popl %ebp
0x004204a2:	ret

0x00415354:	pushl %esi
0x00415355:	call 0x0041ff98
0x0041ff98:	movl %edi, %edi
0x0041ff9a:	pushl %ebp
0x0041ff9b:	movl %ebp, %esp
0x0041ff9d:	movl %eax, 0x8(%ebp)
0x0041ffa0:	movl 0x4437fc, %eax
0x0041ffa5:	movl 0x443800, %eax
0x0041ffaa:	movl 0x443804, %eax
0x0041ffaf:	movl 0x443808, %eax
0x0041ffb4:	popl %ebp
0x0041ffb5:	ret

0x0041535a:	pushl %esi
0x0041535b:	call 0x004195fd
0x004195fd:	ret

0x00415360:	pushl %esi
0x00415361:	call 0x0041ff87
0x0041ff87:	pushl $0x41ff03<UINT32>
0x0041ff8c:	call 0x00418981
0x0041ff91:	popl %ecx
0x0041ff92:	movl 0x4437f8, %eax
0x0041ff97:	ret

0x00415366:	pushl $0x4152f8<UINT32>
0x0041536b:	call 0x00418981
0x00415370:	addl %esp, $0x24<UINT8>
0x00415373:	movl 0x43b95c, %eax
0x00415378:	popl %esi
0x00415379:	ret

0x00418f1a:	pushl 0x4436c4
0x00418f20:	call 0x00418981
0x00418f25:	pushl 0x4436c8
0x00418f2b:	movl 0x4436c4, %eax
0x00418f30:	call 0x00418981
0x00418f35:	pushl 0x4436cc
0x00418f3b:	movl 0x4436c8, %eax
0x00418f40:	call 0x00418981
0x00418f45:	pushl 0x4436d0
0x00418f4b:	movl 0x4436cc, %eax
0x00418f50:	call 0x00418981
0x00418f55:	addl %esp, $0x10<UINT8>
0x00418f58:	movl 0x4436d0, %eax
0x00418f5d:	call 0x00413b18
0x00413b18:	movl %edi, %edi
0x00413b1a:	pushl %esi
0x00413b1b:	pushl %edi
0x00413b1c:	xorl %esi, %esi
0x00413b1e:	movl %edi, $0x442eb0<UINT32>
0x00413b23:	cmpl 0x43b83c(,%esi,8), $0x1<UINT8>
0x00413b2b:	jne 0x00413b4b
0x00413b2d:	leal %eax, 0x43b838(,%esi,8)
0x00413b34:	movl (%eax), %edi
0x00413b36:	pushl $0xfa0<UINT32>
0x00413b3b:	pushl (%eax)
0x00413b3d:	addl %edi, $0x18<UINT8>
0x00413b40:	call 0x0041f9fe
0x0041f9fe:	pushl $0x10<UINT8>
0x0041fa00:	pushl $0x4345f8<UINT32>
0x0041fa05:	call 0x00414d00
0x0041fa0a:	andl -4(%ebp), $0x0<UINT8>
0x0041fa0e:	pushl 0xc(%ebp)
0x0041fa11:	pushl 0x8(%ebp)
0x0041fa14:	call InitializeCriticalSectionAndSpinCount@KERNEL32.DLL
InitializeCriticalSectionAndSpinCount@KERNEL32.DLL: API Node	
0x0041fa1a:	movl -28(%ebp), %eax
0x0041fa1d:	jmp 0x0041fa4e
0x0041fa4e:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0041fa55:	movl %eax, -28(%ebp)
0x0041fa58:	call 0x00414d45
0x00414d45:	movl %ecx, -16(%ebp)
0x00414d48:	movl %fs:0, %ecx
0x00414d4f:	popl %ecx
0x00414d50:	popl %edi
0x00414d51:	popl %edi
0x00414d52:	popl %esi
0x00414d53:	popl %ebx
0x00414d54:	movl %esp, %ebp
0x00414d56:	popl %ebp
0x00414d57:	pushl %ecx
0x00414d58:	ret

0x0041fa5d:	ret

0x00413b45:	popl %ecx
0x00413b46:	popl %ecx
0x00413b47:	testl %eax, %eax
0x00413b49:	je 12
0x00413b4b:	incl %esi
0x00413b4c:	cmpl %esi, $0x24<UINT8>
0x00413b4f:	jl 0x00413b23
0x00413b51:	xorl %eax, %eax
0x00413b53:	incl %eax
0x00413b54:	popl %edi
0x00413b55:	popl %esi
0x00413b56:	ret

0x00418f62:	testl %eax, %eax
0x00418f64:	je 101
0x00418f66:	pushl $0x418c9f<UINT32>
0x00418f6b:	pushl 0x4436c4
0x00418f71:	call 0x004189fc
0x004189fc:	movl %edi, %edi
0x004189fe:	pushl %ebp
0x004189ff:	movl %ebp, %esp
0x00418a01:	pushl %esi
0x00418a02:	pushl 0x43c1ac
0x00418a08:	movl %esi, 0x4321b8
0x00418a0e:	call TlsGetValue@KERNEL32.DLL
0x00418a10:	testl %eax, %eax
0x00418a12:	je 33
0x00418a14:	movl %eax, 0x43c1a8
0x00418a19:	cmpl %eax, $0xffffffff<UINT8>
0x00418a1c:	je 0x00418a35
0x00418a35:	movl %esi, $0x432cec<UINT32>
0x00418a3a:	pushl %esi
0x00418a3b:	call GetModuleHandleW@KERNEL32.DLL
0x00418a41:	testl %eax, %eax
0x00418a43:	jne 0x00418a50
0x00418a50:	pushl $0x432d08<UINT32>
0x00418a55:	pushl %eax
0x00418a56:	call GetProcAddress@KERNEL32.DLL
0x00418a5c:	testl %eax, %eax
0x00418a5e:	je 8
0x00418a60:	pushl 0x8(%ebp)
0x00418a63:	call DecodePointer@KERNEL32.DLL
DecodePointer@KERNEL32.DLL: API Node	
0x00418a65:	movl 0x8(%ebp), %eax
0x00418a68:	movl %eax, 0x8(%ebp)
0x00418a6b:	popl %esi
0x00418a6c:	popl %ebp
0x00418a6d:	ret

0x00418f76:	popl %ecx
0x00418f77:	call FlsAlloc@KERNEL32.DLL
FlsAlloc@KERNEL32.DLL: API Node	
0x00418f79:	movl 0x43c1a8, %eax
0x00418f7e:	cmpl %eax, $0xffffffff<UINT8>
0x00418f81:	je 72
0x00418f83:	pushl $0x214<UINT32>
0x00418f88:	pushl $0x1<UINT8>
0x00418f8a:	call 0x00419833
0x00419833:	movl %edi, %edi
0x00419835:	pushl %ebp
0x00419836:	movl %ebp, %esp
0x00419838:	pushl %esi
0x00419839:	pushl %edi
0x0041983a:	xorl %esi, %esi
0x0041983c:	pushl $0x0<UINT8>
0x0041983e:	pushl 0xc(%ebp)
0x00419841:	pushl 0x8(%ebp)
0x00419844:	call 0x00428ffc
0x00428ffc:	pushl $0xc<UINT8>
0x00428ffe:	pushl $0x434718<UINT32>
0x00429003:	call 0x00414d00
0x00429008:	movl %ecx, 0x8(%ebp)
0x0042900b:	xorl %edi, %edi
0x0042900d:	cmpl %ecx, %edi
0x0042900f:	jbe 46
0x00429011:	pushl $0xffffffe0<UINT8>
0x00429013:	popl %eax
0x00429014:	xorl %edx, %edx
0x00429016:	divl %eax, %ecx
0x00429018:	cmpl %eax, 0xc(%ebp)
0x0042901b:	sbbl %eax, %eax
0x0042901d:	incl %eax
0x0042901e:	jne 0x0042903f
0x0042903f:	imull %ecx, 0xc(%ebp)
0x00429043:	movl %esi, %ecx
0x00429045:	movl 0x8(%ebp), %esi
0x00429048:	cmpl %esi, %edi
0x0042904a:	jne 0x0042904f
0x0042904f:	xorl %ebx, %ebx
0x00429051:	movl -28(%ebp), %ebx
0x00429054:	cmpl %esi, $0xffffffe0<UINT8>
0x00429057:	ja 105
0x00429059:	cmpl 0x4a8fa4, $0x3<UINT8>
0x00429060:	jne 0x004290ad
0x004290ad:	cmpl %ebx, %edi
0x004290af:	jne 97
0x004290b1:	pushl %esi
0x004290b2:	pushl $0x8<UINT8>
0x004290b4:	pushl 0x443004
0x004290ba:	call HeapAlloc@KERNEL32.DLL
HeapAlloc@KERNEL32.DLL: API Node	
0x004290c0:	movl %ebx, %eax
0x004290c2:	cmpl %ebx, %edi
0x004290c4:	jne 0x00429112
0x00429112:	movl %eax, %ebx
0x00429114:	call 0x00414d45
0x00429119:	ret

0x00419849:	movl %edi, %eax
0x0041984b:	addl %esp, $0xc<UINT8>
0x0041984e:	testl %edi, %edi
0x00419850:	jne 0x00419879
0x00419879:	movl %eax, %edi
0x0041987b:	popl %edi
0x0041987c:	popl %esi
0x0041987d:	popl %ebp
0x0041987e:	ret

0x00418f8f:	movl %esi, %eax
0x00418f91:	popl %ecx
0x00418f92:	popl %ecx
0x00418f93:	testl %esi, %esi
0x00418f95:	je 52
0x00418f97:	pushl %esi
0x00418f98:	pushl 0x43c1a8
0x00418f9e:	pushl 0x4436cc
0x00418fa4:	call 0x004189fc
0x00418a1e:	pushl %eax
0x00418a1f:	pushl 0x43c1ac
0x00418a25:	call TlsGetValue@KERNEL32.DLL
0x00418a27:	call FlsGetValue@KERNEL32.DLL
FlsGetValue@KERNEL32.DLL: API Node	
0x00418a29:	testl %eax, %eax
0x00418a2b:	je 0x00418a35
0x00418fa9:	popl %ecx
0x00418faa:	call FlsSetValue@KERNEL32.DLL
FlsSetValue@KERNEL32.DLL: API Node	
0x00418fac:	testl %eax, %eax
0x00418fae:	je 27
0x00418fb0:	pushl $0x0<UINT8>
0x00418fb2:	pushl %esi
0x00418fb3:	call 0x00418b25
0x00418b25:	pushl $0xc<UINT8>
0x00418b27:	pushl $0x434488<UINT32>
0x00418b2c:	call 0x00414d00
0x00418b31:	movl %esi, $0x432cec<UINT32>
0x00418b36:	pushl %esi
0x00418b37:	call GetModuleHandleW@KERNEL32.DLL
0x00418b3d:	testl %eax, %eax
0x00418b3f:	jne 0x00418b48
0x00418b48:	movl -28(%ebp), %eax
0x00418b4b:	movl %esi, 0x8(%ebp)
0x00418b4e:	movl 0x5c(%esi), $0x432d48<UINT32>
0x00418b55:	xorl %edi, %edi
0x00418b57:	incl %edi
0x00418b58:	movl 0x14(%esi), %edi
0x00418b5b:	testl %eax, %eax
0x00418b5d:	je 36
0x00418b5f:	pushl $0x432cdc<UINT32>
0x00418b64:	pushl %eax
0x00418b65:	movl %ebx, 0x432280
0x00418b6b:	call GetProcAddress@KERNEL32.DLL
0x00418b6d:	movl 0x1f8(%esi), %eax
0x00418b73:	pushl $0x432d08<UINT32>
0x00418b78:	pushl -28(%ebp)
0x00418b7b:	call GetProcAddress@KERNEL32.DLL
0x00418b7d:	movl 0x1fc(%esi), %eax
0x00418b83:	movl 0x70(%esi), %edi
0x00418b86:	movb 0xc8(%esi), $0x43<UINT8>
0x00418b8d:	movb 0x14b(%esi), $0x43<UINT8>
0x00418b94:	movl 0x68(%esi), $0x43bb90<UINT32>
0x00418b9b:	pushl $0xd<UINT8>
0x00418b9d:	call 0x00413cac
0x00413cac:	movl %edi, %edi
0x00413cae:	pushl %ebp
0x00413caf:	movl %ebp, %esp
0x00413cb1:	movl %eax, 0x8(%ebp)
0x00413cb4:	pushl %esi
0x00413cb5:	leal %esi, 0x43b838(,%eax,8)
0x00413cbc:	cmpl (%esi), $0x0<UINT8>
0x00413cbf:	jne 0x00413cd4
0x00413cd4:	pushl (%esi)
0x00413cd6:	call EnterCriticalSection@KERNEL32.DLL
EnterCriticalSection@KERNEL32.DLL: API Node	
0x00413cdc:	popl %esi
0x00413cdd:	popl %ebp
0x00413cde:	ret

0x00418ba2:	popl %ecx
0x00418ba3:	andl -4(%ebp), $0x0<UINT8>
0x00418ba7:	pushl 0x68(%esi)
0x00418baa:	call InterlockedIncrement@KERNEL32.DLL
InterlockedIncrement@KERNEL32.DLL: API Node	
0x00418bb0:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00418bb7:	call 0x00418bfa
0x00418bfa:	pushl $0xd<UINT8>
0x00418bfc:	call 0x00413bba
0x00413bba:	movl %edi, %edi
0x00413bbc:	pushl %ebp
0x00413bbd:	movl %ebp, %esp
0x00413bbf:	movl %eax, 0x8(%ebp)
0x00413bc2:	pushl 0x43b838(,%eax,8)
0x00413bc9:	call LeaveCriticalSection@KERNEL32.DLL
LeaveCriticalSection@KERNEL32.DLL: API Node	
0x00413bcf:	popl %ebp
0x00413bd0:	ret

0x00418c01:	popl %ecx
0x00418c02:	ret

0x00418bbc:	pushl $0xc<UINT8>
0x00418bbe:	call 0x00413cac
0x00418bc3:	popl %ecx
0x00418bc4:	movl -4(%ebp), %edi
0x00418bc7:	movl %eax, 0xc(%ebp)
0x00418bca:	movl 0x6c(%esi), %eax
0x00418bcd:	testl %eax, %eax
0x00418bcf:	jne 8
0x00418bd1:	movl %eax, 0x43c198
0x00418bd6:	movl 0x6c(%esi), %eax
0x00418bd9:	pushl 0x6c(%esi)
0x00418bdc:	call 0x00417813
0x00417813:	movl %edi, %edi
0x00417815:	pushl %ebp
0x00417816:	movl %ebp, %esp
0x00417818:	pushl %ebx
0x00417819:	pushl %esi
0x0041781a:	movl %esi, 0x4321cc
0x00417820:	pushl %edi
0x00417821:	movl %edi, 0x8(%ebp)
0x00417824:	pushl %edi
0x00417825:	call InterlockedIncrement@KERNEL32.DLL
0x00417827:	movl %eax, 0xb0(%edi)
0x0041782d:	testl %eax, %eax
0x0041782f:	je 0x00417834
0x00417834:	movl %eax, 0xb8(%edi)
0x0041783a:	testl %eax, %eax
0x0041783c:	je 0x00417841
0x00417841:	movl %eax, 0xb4(%edi)
0x00417847:	testl %eax, %eax
0x00417849:	je 0x0041784e
0x0041784e:	movl %eax, 0xc0(%edi)
0x00417854:	testl %eax, %eax
0x00417856:	je 0x0041785b
0x0041785b:	leal %ebx, 0x50(%edi)
0x0041785e:	movl 0x8(%ebp), $0x6<UINT32>
0x00417865:	cmpl -8(%ebx), $0x43c0b8<UINT32>
0x0041786c:	je 0x00417877
0x0041786e:	movl %eax, (%ebx)
0x00417870:	testl %eax, %eax
0x00417872:	je 0x00417877
0x00417877:	cmpl -4(%ebx), $0x0<UINT8>
0x0041787b:	je 0x00417887
0x00417887:	addl %ebx, $0x10<UINT8>
0x0041788a:	decl 0x8(%ebp)
0x0041788d:	jne 0x00417865
0x0041788f:	movl %eax, 0xd4(%edi)
0x00417895:	addl %eax, $0xb4<UINT32>
0x0041789a:	pushl %eax
0x0041789b:	call InterlockedIncrement@KERNEL32.DLL
0x0041789d:	popl %edi
0x0041789e:	popl %esi
0x0041789f:	popl %ebx
0x004178a0:	popl %ebp
0x004178a1:	ret

0x00418be1:	popl %ecx
0x00418be2:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00418be9:	call 0x00418c03
0x00418c03:	pushl $0xc<UINT8>
0x00418c05:	call 0x00413bba
0x00418c0a:	popl %ecx
0x00418c0b:	ret

0x00418bee:	call 0x00414d45
0x00418bf3:	ret

0x00418fb8:	popl %ecx
0x00418fb9:	popl %ecx
0x00418fba:	call GetCurrentThreadId@KERNEL32.DLL
0x00418fc0:	orl 0x4(%esi), $0xffffffff<UINT8>
0x00418fc4:	movl (%esi), %eax
0x00418fc6:	xorl %eax, %eax
0x00418fc8:	incl %eax
0x00418fc9:	jmp 0x00418fd2
0x00418fd2:	popl %edi
0x00418fd3:	popl %esi
0x00418fd4:	ret

0x00413a15:	testl %eax, %eax
0x00413a17:	jne 0x00413a21
0x00413a21:	call 0x0041f90d
0x0041f90d:	movl %edi, %edi
0x0041f90f:	pushl %esi
0x0041f910:	movl %eax, $0x434180<UINT32>
0x0041f915:	movl %esi, $0x434180<UINT32>
0x0041f91a:	pushl %edi
0x0041f91b:	movl %edi, %eax
0x0041f91d:	cmpl %eax, %esi
0x0041f91f:	jae 0x0041f930
0x0041f930:	popl %edi
0x0041f931:	popl %esi
0x0041f932:	ret

0x00413a26:	movl -4(%ebp), %ebx
0x00413a29:	call 0x0041b79d
0x0041b79d:	pushl $0x54<UINT8>
0x0041b79f:	pushl $0x434598<UINT32>
0x0041b7a4:	call 0x00414d00
0x0041b7a9:	xorl %edi, %edi
0x0041b7ab:	movl -4(%ebp), %edi
0x0041b7ae:	leal %eax, -100(%ebp)
0x0041b7b1:	pushl %eax
0x0041b7b2:	call GetStartupInfoA@KERNEL32.DLL
0x0041b7b8:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0041b7bf:	pushl $0x40<UINT8>
0x0041b7c1:	pushl $0x20<UINT8>
0x0041b7c3:	popl %esi
0x0041b7c4:	pushl %esi
0x0041b7c5:	call 0x00419833
0x0041b7ca:	popl %ecx
0x0041b7cb:	popl %ecx
0x0041b7cc:	cmpl %eax, %edi
0x0041b7ce:	je 532
0x0041b7d4:	movl 0x4a7e60, %eax
0x0041b7d9:	movl 0x4a7e4c, %esi
0x0041b7df:	leal %ecx, 0x800(%eax)
0x0041b7e5:	jmp 0x0041b817
0x0041b817:	cmpl %eax, %ecx
0x0041b819:	jb 0x0041b7e7
0x0041b7e7:	movb 0x4(%eax), $0x0<UINT8>
0x0041b7eb:	orl (%eax), $0xffffffff<UINT8>
0x0041b7ee:	movb 0x5(%eax), $0xa<UINT8>
0x0041b7f2:	movl 0x8(%eax), %edi
0x0041b7f5:	movb 0x24(%eax), $0x0<UINT8>
0x0041b7f9:	movb 0x25(%eax), $0xa<UINT8>
0x0041b7fd:	movb 0x26(%eax), $0xa<UINT8>
0x0041b801:	movl 0x38(%eax), %edi
0x0041b804:	movb 0x34(%eax), $0x0<UINT8>
0x0041b808:	addl %eax, $0x40<UINT8>
0x0041b80b:	movl %ecx, 0x4a7e60
0x0041b811:	addl %ecx, $0x800<UINT32>
0x0041b81b:	cmpw -50(%ebp), %di
0x0041b81f:	je 266
0x0041b825:	movl %eax, -48(%ebp)
0x0041b828:	cmpl %eax, %edi
0x0041b82a:	je 255
0x0041b830:	movl %edi, (%eax)
0x0041b832:	leal %ebx, 0x4(%eax)
0x0041b835:	leal %eax, (%ebx,%edi)
0x0041b838:	movl -28(%ebp), %eax
0x0041b83b:	movl %esi, $0x800<UINT32>
0x0041b840:	cmpl %edi, %esi
0x0041b842:	jl 0x0041b846
0x0041b846:	movl -32(%ebp), $0x1<UINT32>
0x0041b84d:	jmp 0x0041b8aa
0x0041b8aa:	cmpl 0x4a7e4c, %edi
0x0041b8b0:	jl -99
0x0041b8b2:	jmp 0x0041b8ba
0x0041b8ba:	andl -32(%ebp), $0x0<UINT8>
0x0041b8be:	testl %edi, %edi
0x0041b8c0:	jle 0x0041b92f
0x0041b92f:	xorl %ebx, %ebx
0x0041b931:	movl %esi, %ebx
0x0041b933:	shll %esi, $0x6<UINT8>
0x0041b936:	addl %esi, 0x4a7e60
0x0041b93c:	movl %eax, (%esi)
0x0041b93e:	cmpl %eax, $0xffffffff<UINT8>
0x0041b941:	je 0x0041b94e
0x0041b94e:	movb 0x4(%esi), $0xffffff81<UINT8>
0x0041b952:	testl %ebx, %ebx
0x0041b954:	jne 0x0041b95b
0x0041b956:	pushl $0xfffffff6<UINT8>
0x0041b958:	popl %eax
0x0041b959:	jmp 0x0041b965
0x0041b965:	pushl %eax
0x0041b966:	call GetStdHandle@KERNEL32.DLL
GetStdHandle@KERNEL32.DLL: API Node	
0x0041b96c:	movl %edi, %eax
0x0041b96e:	cmpl %edi, $0xffffffff<UINT8>
0x0041b971:	je 67
0x0041b973:	testl %edi, %edi
0x0041b975:	je 63
0x0041b977:	pushl %edi
0x0041b978:	call GetFileType@KERNEL32.DLL
GetFileType@KERNEL32.DLL: API Node	
0x0041b97e:	testl %eax, %eax
0x0041b980:	je 52
0x0041b982:	movl (%esi), %edi
0x0041b984:	andl %eax, $0xff<UINT32>
0x0041b989:	cmpl %eax, $0x2<UINT8>
0x0041b98c:	jne 6
0x0041b98e:	orb 0x4(%esi), $0x40<UINT8>
0x0041b992:	jmp 0x0041b99d
0x0041b99d:	pushl $0xfa0<UINT32>
0x0041b9a2:	leal %eax, 0xc(%esi)
0x0041b9a5:	pushl %eax
0x0041b9a6:	call 0x0041f9fe
0x0041b9ab:	popl %ecx
0x0041b9ac:	popl %ecx
0x0041b9ad:	testl %eax, %eax
0x0041b9af:	je 55
0x0041b9b1:	incl 0x8(%esi)
0x0041b9b4:	jmp 0x0041b9c0
0x0041b9c0:	incl %ebx
0x0041b9c1:	cmpl %ebx, $0x3<UINT8>
0x0041b9c4:	jl 0x0041b931
0x0041b95b:	movl %eax, %ebx
0x0041b95d:	decl %eax
0x0041b95e:	negl %eax
0x0041b960:	sbbl %eax, %eax
0x0041b962:	addl %eax, $0xfffffff5<UINT8>
0x0041b9ca:	pushl 0x4a7e4c
0x0041b9d0:	call SetHandleCount@KERNEL32.DLL
SetHandleCount@KERNEL32.DLL: API Node	
0x0041b9d6:	xorl %eax, %eax
0x0041b9d8:	jmp 0x0041b9eb
0x0041b9eb:	call 0x00414d45
0x0041b9f0:	ret

0x00413a2e:	testl %eax, %eax
0x00413a30:	jnl 0x00413a3a
0x00413a3a:	call GetCommandLineA@KERNEL32.DLL
GetCommandLineA@KERNEL32.DLL: API Node	
0x00413a40:	movl 0x4a8fc8, %eax
0x00413a45:	call 0x0041f7d6
0x0041f7d6:	movl %edi, %edi
0x0041f7d8:	pushl %ebp
0x0041f7d9:	movl %ebp, %esp
0x0041f7db:	movl %eax, 0x4437f0
0x0041f7e0:	subl %esp, $0xc<UINT8>
0x0041f7e3:	pushl %ebx
0x0041f7e4:	pushl %esi
0x0041f7e5:	movl %esi, 0x432170
0x0041f7eb:	pushl %edi
0x0041f7ec:	xorl %ebx, %ebx
0x0041f7ee:	xorl %edi, %edi
0x0041f7f0:	cmpl %eax, %ebx
0x0041f7f2:	jne 46
0x0041f7f4:	call GetEnvironmentStringsW@KERNEL32.DLL
GetEnvironmentStringsW@KERNEL32.DLL: API Node	
0x0041f7f6:	movl %edi, %eax
0x0041f7f8:	cmpl %edi, %ebx
0x0041f7fa:	je 12
0x0041f7fc:	movl 0x4437f0, $0x1<UINT32>
0x0041f806:	jmp 0x0041f82b
0x0041f82b:	cmpl %edi, %ebx
0x0041f82d:	jne 0x0041f83e
0x0041f83e:	movl %eax, %edi
0x0041f840:	cmpw (%edi), %bx
0x0041f843:	je 14
0x0041f845:	incl %eax
0x0041f846:	incl %eax
0x0041f847:	cmpw (%eax), %bx
0x0041f84a:	jne 0x0041f845
0x0041f84c:	incl %eax
0x0041f84d:	incl %eax
0x0041f84e:	cmpw (%eax), %bx
0x0041f851:	jne 0x0041f845
0x0041f853:	movl %esi, 0x4321a0
0x0041f859:	pushl %ebx
0x0041f85a:	pushl %ebx
0x0041f85b:	pushl %ebx
0x0041f85c:	subl %eax, %edi
0x0041f85e:	pushl %ebx
0x0041f85f:	sarl %eax
0x0041f861:	incl %eax
0x0041f862:	pushl %eax
0x0041f863:	pushl %edi
0x0041f864:	pushl %ebx
0x0041f865:	pushl %ebx
0x0041f866:	movl -12(%ebp), %eax
0x0041f869:	call WideCharToMultiByte@KERNEL32.DLL
WideCharToMultiByte@KERNEL32.DLL: API Node	
0x0041f86b:	movl -8(%ebp), %eax
0x0041f86e:	cmpl %eax, %ebx
0x0041f870:	je 47
0x0041f872:	pushl %eax
0x0041f873:	call 0x004197ee
0x004197ee:	movl %edi, %edi
0x004197f0:	pushl %ebp
0x004197f1:	movl %ebp, %esp
0x004197f3:	pushl %esi
0x004197f4:	pushl %edi
0x004197f5:	xorl %esi, %esi
0x004197f7:	pushl 0x8(%ebp)
0x004197fa:	call 0x004109f1
0x004109f1:	movl %edi, %edi
0x004109f3:	pushl %ebp
0x004109f4:	movl %ebp, %esp
0x004109f6:	pushl %esi
0x004109f7:	movl %esi, 0x8(%ebp)
0x004109fa:	cmpl %esi, $0xffffffe0<UINT8>
0x004109fd:	ja 161
0x00410a03:	pushl %ebx
0x00410a04:	pushl %edi
0x00410a05:	movl %edi, 0x432114
0x00410a0b:	cmpl 0x443004, $0x0<UINT8>
0x00410a12:	jne 0x00410a2c
0x00410a2c:	movl %eax, 0x4a8fa4
0x00410a31:	cmpl %eax, $0x1<UINT8>
0x00410a34:	jne 14
0x00410a36:	testl %esi, %esi
0x00410a38:	je 4
0x00410a3a:	movl %eax, %esi
0x00410a3c:	jmp 0x00410a41
0x00410a41:	pushl %eax
0x00410a42:	jmp 0x00410a60
0x00410a60:	pushl $0x0<UINT8>
0x00410a62:	pushl 0x443004
0x00410a68:	call HeapAlloc@KERNEL32.DLL
0x00410a6a:	movl %ebx, %eax
0x00410a6c:	testl %ebx, %ebx
0x00410a6e:	jne 0x00410a9e
0x00410a9e:	popl %edi
0x00410a9f:	movl %eax, %ebx
0x00410aa1:	popl %ebx
0x00410aa2:	jmp 0x00410ab8
0x00410ab8:	popl %esi
0x00410ab9:	popl %ebp
0x00410aba:	ret

0x004197ff:	movl %edi, %eax
0x00419801:	popl %ecx
0x00419802:	testl %edi, %edi
0x00419804:	jne 0x0041982d
0x0041982d:	movl %eax, %edi
0x0041982f:	popl %edi
0x00419830:	popl %esi
0x00419831:	popl %ebp
0x00419832:	ret

0x0041f878:	popl %ecx
0x0041f879:	movl -4(%ebp), %eax
0x0041f87c:	cmpl %eax, %ebx
0x0041f87e:	je 33
0x0041f880:	pushl %ebx
0x0041f881:	pushl %ebx
0x0041f882:	pushl -8(%ebp)
0x0041f885:	pushl %eax
0x0041f886:	pushl -12(%ebp)
0x0041f889:	pushl %edi
0x0041f88a:	pushl %ebx
0x0041f88b:	pushl %ebx
0x0041f88c:	call WideCharToMultiByte@KERNEL32.DLL
0x0041f88e:	testl %eax, %eax
0x0041f890:	jne 0x0041f89e
0x0041f89e:	movl %ebx, -4(%ebp)
0x0041f8a1:	pushl %edi
0x0041f8a2:	call FreeEnvironmentStringsW@KERNEL32.DLL
FreeEnvironmentStringsW@KERNEL32.DLL: API Node	
0x0041f8a8:	movl %eax, %ebx
0x0041f8aa:	jmp 0x0041f908
0x0041f908:	popl %edi
0x0041f909:	popl %esi
0x0041f90a:	popl %ebx
0x0041f90b:	leave
0x0041f90c:	ret

0x00413a4a:	movl 0x442ea0, %eax
0x00413a4f:	call 0x0041f71b
0x0041f71b:	movl %edi, %edi
0x0041f71d:	pushl %ebp
0x0041f71e:	movl %ebp, %esp
0x0041f720:	subl %esp, $0xc<UINT8>
0x0041f723:	pushl %ebx
0x0041f724:	xorl %ebx, %ebx
0x0041f726:	pushl %esi
0x0041f727:	pushl %edi
0x0041f728:	cmpl 0x4a8f9c, %ebx
0x0041f72e:	jne 5
0x0041f730:	call 0x004176a0
0x004176a0:	cmpl 0x4a8f9c, $0x0<UINT8>
0x004176a7:	jne 0x004176bb
0x004176a9:	pushl $0xfffffffd<UINT8>
0x004176ab:	call 0x00417506
0x00417506:	pushl $0x14<UINT8>
0x00417508:	pushl $0x4343c0<UINT32>
0x0041750d:	call 0x00414d00
0x00417512:	orl -32(%ebp), $0xffffffff<UINT8>
0x00417516:	call 0x00418c85
0x00418c85:	movl %edi, %edi
0x00418c87:	pushl %esi
0x00418c88:	call 0x00418c0c
0x00418c0c:	movl %edi, %edi
0x00418c0e:	pushl %esi
0x00418c0f:	pushl %edi
0x00418c10:	call GetLastError@KERNEL32.DLL
GetLastError@KERNEL32.DLL: API Node	
0x00418c16:	pushl 0x43c1a8
0x00418c1c:	movl %edi, %eax
0x00418c1e:	call 0x00418a97
0x00418a97:	movl %edi, %edi
0x00418a99:	pushl %esi
0x00418a9a:	pushl 0x43c1ac
0x00418aa0:	call TlsGetValue@KERNEL32.DLL
0x00418aa6:	movl %esi, %eax
0x00418aa8:	testl %esi, %esi
0x00418aaa:	jne 0x00418ac7
0x00418ac7:	movl %eax, %esi
0x00418ac9:	popl %esi
0x00418aca:	ret

0x00418c23:	call FlsGetValue@KERNEL32.DLL
0x00418c25:	movl %esi, %eax
0x00418c27:	testl %esi, %esi
0x00418c29:	jne 0x00418c79
0x00418c79:	pushl %edi
0x00418c7a:	call SetLastError@KERNEL32.DLL
SetLastError@KERNEL32.DLL: API Node	
0x00418c80:	popl %edi
0x00418c81:	movl %eax, %esi
0x00418c83:	popl %esi
0x00418c84:	ret

0x00418c8d:	movl %esi, %eax
0x00418c8f:	testl %esi, %esi
0x00418c91:	jne 0x00418c9b
0x00418c9b:	movl %eax, %esi
0x00418c9d:	popl %esi
0x00418c9e:	ret

0x0041751b:	movl %edi, %eax
0x0041751d:	movl -36(%ebp), %edi
0x00417520:	call 0x004171c3
0x004171c3:	pushl $0xc<UINT8>
0x004171c5:	pushl $0x4343a0<UINT32>
0x004171ca:	call 0x00414d00
0x004171cf:	call 0x00418c85
0x004171d4:	movl %edi, %eax
0x004171d6:	movl %eax, 0x43c0b4
0x004171db:	testl 0x70(%edi), %eax
0x004171de:	je 0x004171fd
0x004171fd:	pushl $0xd<UINT8>
0x004171ff:	call 0x00413cac
0x00417204:	popl %ecx
0x00417205:	andl -4(%ebp), $0x0<UINT8>
0x00417209:	movl %esi, 0x68(%edi)
0x0041720c:	movl -28(%ebp), %esi
0x0041720f:	cmpl %esi, 0x43bfb8
0x00417215:	je 0x0041724d
0x0041724d:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00417254:	call 0x0041725e
0x0041725e:	pushl $0xd<UINT8>
0x00417260:	call 0x00413bba
0x00417265:	popl %ecx
0x00417266:	ret

0x00417259:	jmp 0x004171e9
0x004171e9:	testl %esi, %esi
0x004171eb:	jne 0x004171f5
0x004171f5:	movl %eax, %esi
0x004171f7:	call 0x00414d45
0x004171fc:	ret

0x00417525:	movl %ebx, 0x68(%edi)
0x00417528:	movl %esi, 0x8(%ebp)
0x0041752b:	call 0x00417267
0x00417267:	movl %edi, %edi
0x00417269:	pushl %ebp
0x0041726a:	movl %ebp, %esp
0x0041726c:	subl %esp, $0x10<UINT8>
0x0041726f:	pushl %ebx
0x00417270:	xorl %ebx, %ebx
0x00417272:	pushl %ebx
0x00417273:	leal %ecx, -16(%ebp)
0x00417276:	call 0x004111f1
0x004111f1:	movl %edi, %edi
0x004111f3:	pushl %ebp
0x004111f4:	movl %ebp, %esp
0x004111f6:	movl %eax, 0x8(%ebp)
0x004111f9:	pushl %esi
0x004111fa:	movl %esi, %ecx
0x004111fc:	movb 0xc(%esi), $0x0<UINT8>
0x00411200:	testl %eax, %eax
0x00411202:	jne 0x00411267
0x00411204:	call 0x00418c85
0x00411209:	movl 0x8(%esi), %eax
0x0041120c:	movl %ecx, 0x6c(%eax)
0x0041120f:	movl (%esi), %ecx
0x00411211:	movl %ecx, 0x68(%eax)
0x00411214:	movl 0x4(%esi), %ecx
0x00411217:	movl %ecx, (%esi)
0x00411219:	cmpl %ecx, 0x43c198
0x0041121f:	je 0x00411233
0x00411233:	movl %eax, 0x4(%esi)
0x00411236:	cmpl %eax, 0x43bfb8
0x0041123c:	je 0x00411254
0x00411254:	movl %eax, 0x8(%esi)
0x00411257:	testb 0x70(%eax), $0x2<UINT8>
0x0041125b:	jne 20
0x0041125d:	orl 0x70(%eax), $0x2<UINT8>
0x00411261:	movb 0xc(%esi), $0x1<UINT8>
0x00411265:	jmp 0x00411271
0x00411271:	movl %eax, %esi
0x00411273:	popl %esi
0x00411274:	popl %ebp
0x00411275:	ret $0x4<UINT16>

0x0041727b:	movl 0x443684, %ebx
0x00417281:	cmpl %esi, $0xfffffffe<UINT8>
0x00417284:	jne 0x004172a4
0x004172a4:	cmpl %esi, $0xfffffffd<UINT8>
0x004172a7:	jne 0x004172bb
0x004172a9:	movl 0x443684, $0x1<UINT32>
0x004172b3:	call GetACP@KERNEL32.DLL
GetACP@KERNEL32.DLL: API Node	
0x004172b9:	jmp 0x00417296
0x00417296:	cmpb -4(%ebp), %bl
0x00417299:	je 69
0x0041729b:	movl %ecx, -8(%ebp)
0x0041729e:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x004172a2:	jmp 0x004172e0
0x004172e0:	popl %ebx
0x004172e1:	leave
0x004172e2:	ret

0x00417530:	movl 0x8(%ebp), %eax
0x00417533:	cmpl %eax, 0x4(%ebx)
0x00417536:	je 343
0x0041753c:	pushl $0x220<UINT32>
0x00417541:	call 0x004197ee
0x00417546:	popl %ecx
0x00417547:	movl %ebx, %eax
0x00417549:	testl %ebx, %ebx
0x0041754b:	je 326
0x00417551:	movl %ecx, $0x88<UINT32>
0x00417556:	movl %esi, 0x68(%edi)
0x00417559:	movl %edi, %ebx
0x0041755b:	rep movsl %es:(%edi), %ds:(%esi)
0x0041755d:	andl (%ebx), $0x0<UINT8>
0x00417560:	pushl %ebx
0x00417561:	pushl 0x8(%ebp)
0x00417564:	call 0x004172e3
0x004172e3:	movl %edi, %edi
0x004172e5:	pushl %ebp
0x004172e6:	movl %ebp, %esp
0x004172e8:	subl %esp, $0x20<UINT8>
0x004172eb:	movl %eax, 0x43b810
0x004172f0:	xorl %eax, %ebp
0x004172f2:	movl -4(%ebp), %eax
0x004172f5:	pushl %ebx
0x004172f6:	movl %ebx, 0xc(%ebp)
0x004172f9:	pushl %esi
0x004172fa:	movl %esi, 0x8(%ebp)
0x004172fd:	pushl %edi
0x004172fe:	call 0x00417267
0x004172bb:	cmpl %esi, $0xfffffffc<UINT8>
0x004172be:	jne 0x004172d2
0x004172d2:	cmpb -4(%ebp), %bl
0x004172d5:	je 7
0x004172d7:	movl %eax, -8(%ebp)
0x004172da:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x004172de:	movl %eax, %esi
0x00417303:	movl %edi, %eax
0x00417305:	xorl %esi, %esi
0x00417307:	movl 0x8(%ebp), %edi
0x0041730a:	cmpl %edi, %esi
0x0041730c:	jne 0x0041731c
0x0041731c:	movl -28(%ebp), %esi
0x0041731f:	xorl %eax, %eax
0x00417321:	cmpl 0x43bfc0(%eax), %edi
0x00417327:	je 145
0x0041732d:	incl -28(%ebp)
0x00417330:	addl %eax, $0x30<UINT8>
0x00417333:	cmpl %eax, $0xf0<UINT32>
0x00417338:	jb 0x00417321
0x0041733a:	cmpl %edi, $0xfde8<UINT32>
0x00417340:	je 368
0x00417346:	cmpl %edi, $0xfde9<UINT32>
0x0041734c:	je 356
0x00417352:	movzwl %eax, %di
0x00417355:	pushl %eax
0x00417356:	call IsValidCodePage@KERNEL32.DLL
IsValidCodePage@KERNEL32.DLL: API Node	
0x0041735c:	testl %eax, %eax
0x0041735e:	je 338
0x00417364:	leal %eax, -24(%ebp)
0x00417367:	pushl %eax
0x00417368:	pushl %edi
0x00417369:	call GetCPInfo@KERNEL32.DLL
GetCPInfo@KERNEL32.DLL: API Node	
0x0041736f:	testl %eax, %eax
0x00417371:	je 307
0x00417377:	pushl $0x101<UINT32>
0x0041737c:	leal %eax, 0x1c(%ebx)
0x0041737f:	pushl %esi
0x00417380:	pushl %eax
0x00417381:	call 0x00411110
0x00411110:	movl %edx, 0xc(%esp)
0x00411114:	movl %ecx, 0x4(%esp)
0x00411118:	testl %edx, %edx
0x0041111a:	je 105
0x0041111c:	xorl %eax, %eax
0x0041111e:	movb %al, 0x8(%esp)
0x00411122:	testb %al, %al
0x00411124:	jne 22
0x00411126:	cmpl %edx, $0x100<UINT32>
0x0041112c:	jb 14
0x0041112e:	cmpl 0x4a8f8c, $0x0<UINT8>
0x00411135:	je 0x0041113c
0x0041113c:	pushl %edi
0x0041113d:	movl %edi, %ecx
0x0041113f:	cmpl %edx, $0x4<UINT8>
0x00411142:	jb 49
0x00411144:	negl %ecx
0x00411146:	andl %ecx, $0x3<UINT8>
0x00411149:	je 0x00411157
0x00411157:	movl %ecx, %eax
0x00411159:	shll %eax, $0x8<UINT8>
0x0041115c:	addl %eax, %ecx
0x0041115e:	movl %ecx, %eax
0x00411160:	shll %eax, $0x10<UINT8>
0x00411163:	addl %eax, %ecx
0x00411165:	movl %ecx, %edx
0x00411167:	andl %edx, $0x3<UINT8>
0x0041116a:	shrl %ecx, $0x2<UINT8>
0x0041116d:	je 6
0x0041116f:	rep stosl %es:(%edi), %eax
0x00411171:	testl %edx, %edx
0x00411173:	je 0x0041117f
0x00411175:	movb (%edi), %al
0x00411177:	addl %edi, $0x1<UINT8>
0x0041117a:	subl %edx, $0x1<UINT8>
0x0041117d:	jne -10
0x0041117f:	movl %eax, 0x8(%esp)
0x00411183:	popl %edi
0x00411184:	ret

0x00417386:	xorl %edx, %edx
0x00417388:	incl %edx
0x00417389:	addl %esp, $0xc<UINT8>
0x0041738c:	movl 0x4(%ebx), %edi
0x0041738f:	movl 0xc(%ebx), %esi
0x00417392:	cmpl -24(%ebp), %edx
0x00417395:	jbe 248
0x0041739b:	cmpb -18(%ebp), $0x0<UINT8>
0x0041739f:	je 0x00417474
0x00417474:	leal %eax, 0x1e(%ebx)
0x00417477:	movl %ecx, $0xfe<UINT32>
0x0041747c:	orb (%eax), $0x8<UINT8>
0x0041747f:	incl %eax
0x00417480:	decl %ecx
0x00417481:	jne 0x0041747c
0x00417483:	movl %eax, 0x4(%ebx)
0x00417486:	call 0x00416f9d
0x00416f9d:	subl %eax, $0x3a4<UINT32>
0x00416fa2:	je 34
0x00416fa4:	subl %eax, $0x4<UINT8>
0x00416fa7:	je 23
0x00416fa9:	subl %eax, $0xd<UINT8>
0x00416fac:	je 12
0x00416fae:	decl %eax
0x00416faf:	je 3
0x00416fb1:	xorl %eax, %eax
0x00416fb3:	ret

0x0041748b:	movl 0xc(%ebx), %eax
0x0041748e:	movl 0x8(%ebx), %edx
0x00417491:	jmp 0x00417496
0x00417496:	xorl %eax, %eax
0x00417498:	movzwl %ecx, %ax
0x0041749b:	movl %eax, %ecx
0x0041749d:	shll %ecx, $0x10<UINT8>
0x004174a0:	orl %eax, %ecx
0x004174a2:	leal %edi, 0x10(%ebx)
0x004174a5:	stosl %es:(%edi), %eax
0x004174a6:	stosl %es:(%edi), %eax
0x004174a7:	stosl %es:(%edi), %eax
0x004174a8:	jmp 0x00417452
0x00417452:	movl %esi, %ebx
0x00417454:	call 0x00417030
0x00417030:	movl %edi, %edi
0x00417032:	pushl %ebp
0x00417033:	movl %ebp, %esp
0x00417035:	subl %esp, $0x51c<UINT32>
0x0041703b:	movl %eax, 0x43b810
0x00417040:	xorl %eax, %ebp
0x00417042:	movl -4(%ebp), %eax
0x00417045:	pushl %ebx
0x00417046:	pushl %edi
0x00417047:	leal %eax, -1304(%ebp)
0x0041704d:	pushl %eax
0x0041704e:	pushl 0x4(%esi)
0x00417051:	call GetCPInfo@KERNEL32.DLL
0x00417057:	movl %edi, $0x100<UINT32>
0x0041705c:	testl %eax, %eax
0x0041705e:	je 251
0x00417064:	xorl %eax, %eax
0x00417066:	movb -260(%ebp,%eax), %al
0x0041706d:	incl %eax
0x0041706e:	cmpl %eax, %edi
0x00417070:	jb 0x00417066
0x00417072:	movb %al, -1298(%ebp)
0x00417078:	movb -260(%ebp), $0x20<UINT8>
0x0041707f:	testb %al, %al
0x00417081:	je 0x004170b1
0x004170b1:	pushl $0x0<UINT8>
0x004170b3:	pushl 0xc(%esi)
0x004170b6:	leal %eax, -1284(%ebp)
0x004170bc:	pushl 0x4(%esi)
0x004170bf:	pushl %eax
0x004170c0:	pushl %edi
0x004170c1:	leal %eax, -260(%ebp)
0x004170c7:	pushl %eax
0x004170c8:	pushl $0x1<UINT8>
0x004170ca:	pushl $0x0<UINT8>
0x004170cc:	call 0x00423653
0x00423653:	movl %edi, %edi
0x00423655:	pushl %ebp
0x00423656:	movl %ebp, %esp
0x00423658:	subl %esp, $0x10<UINT8>
0x0042365b:	pushl 0x8(%ebp)
0x0042365e:	leal %ecx, -16(%ebp)
0x00423661:	call 0x004111f1
0x00423666:	pushl 0x24(%ebp)
0x00423669:	leal %ecx, -16(%ebp)
0x0042366c:	pushl 0x20(%ebp)
0x0042366f:	pushl 0x1c(%ebp)
0x00423672:	pushl 0x18(%ebp)
0x00423675:	pushl 0x14(%ebp)
0x00423678:	pushl 0x10(%ebp)
0x0042367b:	pushl 0xc(%ebp)
0x0042367e:	call 0x00423499
0x00423499:	movl %edi, %edi
0x0042349b:	pushl %ebp
0x0042349c:	movl %ebp, %esp
0x0042349e:	pushl %ecx
0x0042349f:	pushl %ecx
0x004234a0:	movl %eax, 0x43b810
0x004234a5:	xorl %eax, %ebp
0x004234a7:	movl -4(%ebp), %eax
0x004234aa:	movl %eax, 0x443838
0x004234af:	pushl %ebx
0x004234b0:	pushl %esi
0x004234b1:	xorl %ebx, %ebx
0x004234b3:	pushl %edi
0x004234b4:	movl %edi, %ecx
0x004234b6:	cmpl %eax, %ebx
0x004234b8:	jne 58
0x004234ba:	leal %eax, -8(%ebp)
0x004234bd:	pushl %eax
0x004234be:	xorl %esi, %esi
0x004234c0:	incl %esi
0x004234c1:	pushl %esi
0x004234c2:	pushl $0x432d44<UINT32>
0x004234c7:	pushl %esi
0x004234c8:	call GetStringTypeW@KERNEL32.DLL
GetStringTypeW@KERNEL32.DLL: API Node	
0x004234ce:	testl %eax, %eax
0x004234d0:	je 8
0x004234d2:	movl 0x443838, %esi
0x004234d8:	jmp 0x0042350e
0x0042350e:	movl -8(%ebp), %ebx
0x00423511:	cmpl 0x18(%ebp), %ebx
0x00423514:	jne 0x0042351e
0x0042351e:	movl %esi, 0x43219c
0x00423524:	xorl %eax, %eax
0x00423526:	cmpl 0x20(%ebp), %ebx
0x00423529:	pushl %ebx
0x0042352a:	pushl %ebx
0x0042352b:	pushl 0x10(%ebp)
0x0042352e:	setne %al
0x00423531:	pushl 0xc(%ebp)
0x00423534:	leal %eax, 0x1(,%eax,8)
0x0042353b:	pushl %eax
0x0042353c:	pushl 0x18(%ebp)
0x0042353f:	call MultiByteToWideChar@KERNEL32.DLL
MultiByteToWideChar@KERNEL32.DLL: API Node	
0x00423541:	movl %edi, %eax
0x00423543:	cmpl %edi, %ebx
0x00423545:	je 171
0x0042354b:	jle 60
0x0042354d:	cmpl %edi, $0x7ffffff0<UINT32>
0x00423553:	ja 52
0x00423555:	leal %eax, 0x8(%edi,%edi)
0x00423559:	cmpl %eax, $0x400<UINT32>
0x0042355e:	ja 19
0x00423560:	call 0x0041b5c0
0x0041b5c0:	pushl %ecx
0x0041b5c1:	leal %ecx, 0x8(%esp)
0x0041b5c5:	subl %ecx, %eax
0x0041b5c7:	andl %ecx, $0xf<UINT8>
0x0041b5ca:	addl %eax, %ecx
0x0041b5cc:	sbbl %ecx, %ecx
0x0041b5ce:	orl %eax, %ecx
0x0041b5d0:	popl %ecx
0x0041b5d1:	jmp 0x00411670
0x00411670:	pushl %ecx
0x00411671:	leal %ecx, 0x4(%esp)
0x00411675:	subl %ecx, %eax
0x00411677:	sbbl %eax, %eax
0x00411679:	notl %eax
0x0041167b:	andl %ecx, %eax
0x0041167d:	movl %eax, %esp
0x0041167f:	andl %eax, $0xfffff000<UINT32>
0x00411684:	cmpl %ecx, %eax
0x00411686:	jb 10
0x00411688:	movl %eax, %ecx
0x0041168a:	popl %ecx
0x0041168b:	xchgl %esp, %eax
0x0041168c:	movl %eax, (%eax)
0x0041168e:	movl (%esp), %eax
0x00411691:	ret

0x00423565:	movl %eax, %esp
0x00423567:	cmpl %eax, %ebx
0x00423569:	je 28
0x0042356b:	movl (%eax), $0xcccc<UINT32>
0x00423571:	jmp 0x00423584
0x00423584:	addl %eax, $0x8<UINT8>
0x00423587:	movl %ebx, %eax
0x00423589:	testl %ebx, %ebx
0x0042358b:	je 105
0x0042358d:	leal %eax, (%edi,%edi)
0x00423590:	pushl %eax
0x00423591:	pushl $0x0<UINT8>
0x00423593:	pushl %ebx
0x00423594:	call 0x00411110
0x00423599:	addl %esp, $0xc<UINT8>
0x0042359c:	pushl %edi
0x0042359d:	pushl %ebx
0x0042359e:	pushl 0x10(%ebp)
0x004235a1:	pushl 0xc(%ebp)
0x004235a4:	pushl $0x1<UINT8>
0x004235a6:	pushl 0x18(%ebp)
0x004235a9:	call MultiByteToWideChar@KERNEL32.DLL
0x004235ab:	testl %eax, %eax
0x004235ad:	je 17
0x004235af:	pushl 0x14(%ebp)
0x004235b2:	pushl %eax
0x004235b3:	pushl %ebx
0x004235b4:	pushl 0x8(%ebp)
0x004235b7:	call GetStringTypeW@KERNEL32.DLL
0x004235bd:	movl -8(%ebp), %eax
0x004235c0:	pushl %ebx
0x004235c1:	call 0x004125c4
0x004125c4:	movl %edi, %edi
0x004125c6:	pushl %ebp
0x004125c7:	movl %ebp, %esp
0x004125c9:	movl %eax, 0x8(%ebp)
0x004125cc:	testl %eax, %eax
0x004125ce:	je 18
0x004125d0:	subl %eax, $0x8<UINT8>
0x004125d3:	cmpl (%eax), $0xdddd<UINT32>
0x004125d9:	jne 0x004125e2
0x004125e2:	popl %ebp
0x004125e3:	ret

0x004235c6:	movl %eax, -8(%ebp)
0x004235c9:	popl %ecx
0x004235ca:	jmp 0x00423641
0x00423641:	leal %esp, -20(%ebp)
0x00423644:	popl %edi
0x00423645:	popl %esi
0x00423646:	popl %ebx
0x00423647:	movl %ecx, -4(%ebp)
0x0042364a:	xorl %ecx, %ebp
0x0042364c:	call 0x00411067
0x00411067:	cmpl %ecx, 0x43b810
0x0041106d:	jne 2
0x0041106f:	rep ret

0x00423651:	leave
0x00423652:	ret

0x00423683:	addl %esp, $0x1c<UINT8>
0x00423686:	cmpb -4(%ebp), $0x0<UINT8>
0x0042368a:	je 7
0x0042368c:	movl %ecx, -8(%ebp)
0x0042368f:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00423693:	leave
0x00423694:	ret

0x004170d1:	xorl %ebx, %ebx
0x004170d3:	pushl %ebx
0x004170d4:	pushl 0x4(%esi)
0x004170d7:	leal %eax, -516(%ebp)
0x004170dd:	pushl %edi
0x004170de:	pushl %eax
0x004170df:	pushl %edi
0x004170e0:	leal %eax, -260(%ebp)
0x004170e6:	pushl %eax
0x004170e7:	pushl %edi
0x004170e8:	pushl 0xc(%esi)
0x004170eb:	pushl %ebx
0x004170ec:	call 0x00419460
0x00419460:	movl %edi, %edi
0x00419462:	pushl %ebp
0x00419463:	movl %ebp, %esp
0x00419465:	subl %esp, $0x10<UINT8>
0x00419468:	pushl 0x8(%ebp)
0x0041946b:	leal %ecx, -16(%ebp)
0x0041946e:	call 0x004111f1
0x00419473:	pushl 0x28(%ebp)
0x00419476:	leal %ecx, -16(%ebp)
0x00419479:	pushl 0x24(%ebp)
0x0041947c:	pushl 0x20(%ebp)
0x0041947f:	pushl 0x1c(%ebp)
0x00419482:	pushl 0x18(%ebp)
0x00419485:	pushl 0x14(%ebp)
0x00419488:	pushl 0x10(%ebp)
0x0041948b:	pushl 0xc(%ebp)
0x0041948e:	call 0x004190bb
0x004190bb:	movl %edi, %edi
0x004190bd:	pushl %ebp
0x004190be:	movl %ebp, %esp
0x004190c0:	subl %esp, $0x14<UINT8>
0x004190c3:	movl %eax, 0x43b810
0x004190c8:	xorl %eax, %ebp
0x004190ca:	movl -4(%ebp), %eax
0x004190cd:	pushl %ebx
0x004190ce:	pushl %esi
0x004190cf:	xorl %ebx, %ebx
0x004190d1:	pushl %edi
0x004190d2:	movl %esi, %ecx
0x004190d4:	cmpl 0x4436d4, %ebx
0x004190da:	jne 0x00419114
0x004190dc:	pushl %ebx
0x004190dd:	pushl %ebx
0x004190de:	xorl %edi, %edi
0x004190e0:	incl %edi
0x004190e1:	pushl %edi
0x004190e2:	pushl $0x432d44<UINT32>
0x004190e7:	pushl $0x100<UINT32>
0x004190ec:	pushl %ebx
0x004190ed:	call LCMapStringW@KERNEL32.DLL
LCMapStringW@KERNEL32.DLL: API Node	
0x004190f3:	testl %eax, %eax
0x004190f5:	je 8
0x004190f7:	movl 0x4436d4, %edi
0x004190fd:	jmp 0x00419114
0x00419114:	cmpl 0x14(%ebp), %ebx
0x00419117:	jle 0x0041913b
0x0041913b:	movl %eax, 0x4436d4
0x00419140:	cmpl %eax, $0x2<UINT8>
0x00419143:	je 428
0x00419149:	cmpl %eax, %ebx
0x0041914b:	je 420
0x00419151:	cmpl %eax, $0x1<UINT8>
0x00419154:	jne 460
0x0041915a:	movl -8(%ebp), %ebx
0x0041915d:	cmpl 0x20(%ebp), %ebx
0x00419160:	jne 0x0041916a
0x0041916a:	movl %esi, 0x43219c
0x00419170:	xorl %eax, %eax
0x00419172:	cmpl 0x24(%ebp), %ebx
0x00419175:	pushl %ebx
0x00419176:	pushl %ebx
0x00419177:	pushl 0x14(%ebp)
0x0041917a:	setne %al
0x0041917d:	pushl 0x10(%ebp)
0x00419180:	leal %eax, 0x1(,%eax,8)
0x00419187:	pushl %eax
0x00419188:	pushl 0x20(%ebp)
0x0041918b:	call MultiByteToWideChar@KERNEL32.DLL
0x0041918d:	movl %edi, %eax
0x0041918f:	cmpl %edi, %ebx
0x00419191:	je 0x00419326
0x00419326:	xorl %eax, %eax
0x00419328:	jmp 0x0041944e
0x0041944e:	leal %esp, -32(%ebp)
0x00419451:	popl %edi
0x00419452:	popl %esi
0x00419453:	popl %ebx
0x00419454:	movl %ecx, -4(%ebp)
0x00419457:	xorl %ecx, %ebp
0x00419459:	call 0x00411067
0x0041945e:	leave
0x0041945f:	ret

0x00419493:	addl %esp, $0x20<UINT8>
0x00419496:	cmpb -4(%ebp), $0x0<UINT8>
0x0041949a:	je 7
0x0041949c:	movl %ecx, -8(%ebp)
0x0041949f:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x004194a3:	leave
0x004194a4:	ret

0x004170f1:	addl %esp, $0x44<UINT8>
0x004170f4:	pushl %ebx
0x004170f5:	pushl 0x4(%esi)
0x004170f8:	leal %eax, -772(%ebp)
0x004170fe:	pushl %edi
0x004170ff:	pushl %eax
0x00417100:	pushl %edi
0x00417101:	leal %eax, -260(%ebp)
0x00417107:	pushl %eax
0x00417108:	pushl $0x200<UINT32>
0x0041710d:	pushl 0xc(%esi)
0x00417110:	pushl %ebx
0x00417111:	call 0x00419460
0x00417116:	addl %esp, $0x24<UINT8>
0x00417119:	xorl %eax, %eax
0x0041711b:	movzwl %ecx, -1284(%ebp,%eax,2)
0x00417123:	testb %cl, $0x1<UINT8>
0x00417126:	je 0x00417136
0x00417136:	testb %cl, $0x2<UINT8>
0x00417139:	je 0x00417150
0x00417150:	movb 0x11d(%esi,%eax), $0x0<UINT8>
0x00417158:	incl %eax
0x00417159:	cmpl %eax, %edi
0x0041715b:	jb -66
0x0041715d:	jmp 0x004171b5
0x004171b5:	movl %ecx, -4(%ebp)
0x004171b8:	popl %edi
0x004171b9:	xorl %ecx, %ebp
0x004171bb:	popl %ebx
0x004171bc:	call 0x00411067
0x004171c1:	leave
0x004171c2:	ret

0x00417459:	jmp 0x00417315
0x00417315:	xorl %eax, %eax
0x00417317:	jmp 0x004174b9
0x004174b9:	movl %ecx, -4(%ebp)
0x004174bc:	popl %edi
0x004174bd:	popl %esi
0x004174be:	xorl %ecx, %ebp
0x004174c0:	popl %ebx
0x004174c1:	call 0x00411067
0x004174c6:	leave
0x004174c7:	ret

0x00417569:	popl %ecx
0x0041756a:	popl %ecx
0x0041756b:	movl -32(%ebp), %eax
0x0041756e:	testl %eax, %eax
0x00417570:	jne 252
0x00417576:	movl %esi, -36(%ebp)
0x00417579:	pushl 0x68(%esi)
0x0041757c:	call InterlockedDecrement@KERNEL32.DLL
InterlockedDecrement@KERNEL32.DLL: API Node	
0x00417582:	testl %eax, %eax
0x00417584:	jne 17
0x00417586:	movl %eax, 0x68(%esi)
0x00417589:	cmpl %eax, $0x43bb90<UINT32>
0x0041758e:	je 0x00417597
0x00417597:	movl 0x68(%esi), %ebx
0x0041759a:	pushl %ebx
0x0041759b:	movl %edi, 0x4321cc
0x004175a1:	call InterlockedIncrement@KERNEL32.DLL
0x004175a3:	testb 0x70(%esi), $0x2<UINT8>
0x004175a7:	jne 234
0x004175ad:	testb 0x43c0b4, $0x1<UINT8>
0x004175b4:	jne 221
0x004175ba:	pushl $0xd<UINT8>
0x004175bc:	call 0x00413cac
0x004175c1:	popl %ecx
0x004175c2:	andl -4(%ebp), $0x0<UINT8>
0x004175c6:	movl %eax, 0x4(%ebx)
0x004175c9:	movl 0x443694, %eax
0x004175ce:	movl %eax, 0x8(%ebx)
0x004175d1:	movl 0x443698, %eax
0x004175d6:	movl %eax, 0xc(%ebx)
0x004175d9:	movl 0x44369c, %eax
0x004175de:	xorl %eax, %eax
0x004175e0:	movl -28(%ebp), %eax
0x004175e3:	cmpl %eax, $0x5<UINT8>
0x004175e6:	jnl 0x004175f8
0x004175e8:	movw %cx, 0x10(%ebx,%eax,2)
0x004175ed:	movw 0x443688(,%eax,2), %cx
0x004175f5:	incl %eax
0x004175f6:	jmp 0x004175e0
0x004175f8:	xorl %eax, %eax
0x004175fa:	movl -28(%ebp), %eax
0x004175fd:	cmpl %eax, $0x101<UINT32>
0x00417602:	jnl 0x00417611
0x00417604:	movb %cl, 0x1c(%eax,%ebx)
0x00417608:	movb 0x43bdb0(%eax), %cl
0x0041760e:	incl %eax
0x0041760f:	jmp 0x004175fa
0x00417611:	xorl %eax, %eax
0x00417613:	movl -28(%ebp), %eax
0x00417616:	cmpl %eax, $0x100<UINT32>
0x0041761b:	jnl 0x0041762d
0x0041761d:	movb %cl, 0x11d(%eax,%ebx)
0x00417624:	movb 0x43beb8(%eax), %cl
0x0041762a:	incl %eax
0x0041762b:	jmp 0x00417613
0x0041762d:	pushl 0x43bfb8
0x00417633:	call InterlockedDecrement@KERNEL32.DLL
0x00417639:	testl %eax, %eax
0x0041763b:	jne 0x00417650
0x00417650:	movl 0x43bfb8, %ebx
0x00417656:	pushl %ebx
0x00417657:	call InterlockedIncrement@KERNEL32.DLL
0x00417659:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00417660:	call 0x00417667
0x00417667:	pushl $0xd<UINT8>
0x00417669:	call 0x00413bba
0x0041766e:	popl %ecx
0x0041766f:	ret

0x00417665:	jmp 0x00417697
0x00417697:	movl %eax, -32(%ebp)
0x0041769a:	call 0x00414d45
0x0041769f:	ret

0x004176b0:	popl %ecx
0x004176b1:	movl 0x4a8f9c, $0x1<UINT32>
0x004176bb:	xorl %eax, %eax
0x004176bd:	ret

0x0041f735:	pushl $0x104<UINT32>
0x0041f73a:	movl %esi, $0x4436e8<UINT32>
0x0041f73f:	pushl %esi
0x0041f740:	pushl %ebx
0x0041f741:	movb 0x4437ec, %bl
0x0041f747:	call GetModuleFileNameA@KERNEL32.DLL
GetModuleFileNameA@KERNEL32.DLL: API Node	
0x0041f74d:	movl %eax, 0x4a8fc8
0x0041f752:	movl 0x443028, %esi
0x0041f758:	cmpl %eax, %ebx
0x0041f75a:	je 7
0x0041f75c:	movl -4(%ebp), %eax
0x0041f75f:	cmpb (%eax), %bl
0x0041f761:	jne 0x0041f766
0x0041f766:	movl %edx, -4(%ebp)
0x0041f769:	leal %eax, -8(%ebp)
0x0041f76c:	pushl %eax
0x0041f76d:	pushl %ebx
0x0041f76e:	pushl %ebx
0x0041f76f:	leal %edi, -12(%ebp)
0x0041f772:	call 0x0041f581
0x0041f581:	movl %edi, %edi
0x0041f583:	pushl %ebp
0x0041f584:	movl %ebp, %esp
0x0041f586:	pushl %ecx
0x0041f587:	movl %ecx, 0x10(%ebp)
0x0041f58a:	pushl %ebx
0x0041f58b:	xorl %eax, %eax
0x0041f58d:	pushl %esi
0x0041f58e:	movl (%edi), %eax
0x0041f590:	movl %esi, %edx
0x0041f592:	movl %edx, 0xc(%ebp)
0x0041f595:	movl (%ecx), $0x1<UINT32>
0x0041f59b:	cmpl 0x8(%ebp), %eax
0x0041f59e:	je 0x0041f5a9
0x0041f5a9:	movl -4(%ebp), %eax
0x0041f5ac:	cmpb (%esi), $0x22<UINT8>
0x0041f5af:	jne 0x0041f5c1
0x0041f5b1:	xorl %eax, %eax
0x0041f5b3:	cmpl -4(%ebp), %eax
0x0041f5b6:	movb %bl, $0x22<UINT8>
0x0041f5b8:	sete %al
0x0041f5bb:	incl %esi
0x0041f5bc:	movl -4(%ebp), %eax
0x0041f5bf:	jmp 0x0041f5fd
0x0041f5fd:	cmpl -4(%ebp), $0x0<UINT8>
0x0041f601:	jne 0x0041f5ac
0x0041f5c1:	incl (%edi)
0x0041f5c3:	testl %edx, %edx
0x0041f5c5:	je 0x0041f5cf
0x0041f5cf:	movb %bl, (%esi)
0x0041f5d1:	movzbl %eax, %bl
0x0041f5d4:	pushl %eax
0x0041f5d5:	incl %esi
0x0041f5d6:	call 0x0042b233
0x0042b233:	movl %edi, %edi
0x0042b235:	pushl %ebp
0x0042b236:	movl %ebp, %esp
0x0042b238:	pushl $0x4<UINT8>
0x0042b23a:	pushl $0x0<UINT8>
0x0042b23c:	pushl 0x8(%ebp)
0x0042b23f:	pushl $0x0<UINT8>
0x0042b241:	call 0x0042b027
0x0042b027:	movl %edi, %edi
0x0042b029:	pushl %ebp
0x0042b02a:	movl %ebp, %esp
0x0042b02c:	subl %esp, $0x10<UINT8>
0x0042b02f:	pushl 0x8(%ebp)
0x0042b032:	leal %ecx, -16(%ebp)
0x0042b035:	call 0x004111f1
0x0042b03a:	movzbl %eax, 0xc(%ebp)
0x0042b03e:	movl %ecx, -12(%ebp)
0x0042b041:	movb %dl, 0x14(%ebp)
0x0042b044:	testb 0x1d(%ecx,%eax), %dl
0x0042b048:	jne 30
0x0042b04a:	cmpl 0x10(%ebp), $0x0<UINT8>
0x0042b04e:	je 0x0042b062
0x0042b062:	xorl %eax, %eax
0x0042b064:	testl %eax, %eax
0x0042b066:	je 0x0042b06b
0x0042b06b:	cmpb -4(%ebp), $0x0<UINT8>
0x0042b06f:	je 7
0x0042b071:	movl %ecx, -8(%ebp)
0x0042b074:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0042b078:	leave
0x0042b079:	ret

0x0042b246:	addl %esp, $0x10<UINT8>
0x0042b249:	popl %ebp
0x0042b24a:	ret

0x0041f5db:	popl %ecx
0x0041f5dc:	testl %eax, %eax
0x0041f5de:	je 0x0041f5f3
0x0041f5f3:	movl %edx, 0xc(%ebp)
0x0041f5f6:	movl %ecx, 0x10(%ebp)
0x0041f5f9:	testb %bl, %bl
0x0041f5fb:	je 0x0041f62f
0x0041f603:	cmpb %bl, $0x20<UINT8>
0x0041f606:	je 5
0x0041f608:	cmpb %bl, $0x9<UINT8>
0x0041f60b:	jne 0x0041f5ac
0x0041f62f:	decl %esi
0x0041f630:	jmp 0x0041f615
0x0041f615:	andl -4(%ebp), $0x0<UINT8>
0x0041f619:	cmpb (%esi), $0x0<UINT8>
0x0041f61c:	je 0x0041f70b
0x0041f70b:	movl %eax, 0x8(%ebp)
0x0041f70e:	popl %esi
0x0041f70f:	popl %ebx
0x0041f710:	testl %eax, %eax
0x0041f712:	je 0x0041f717
0x0041f717:	incl (%ecx)
0x0041f719:	leave
0x0041f71a:	ret

0x0041f777:	movl %eax, -8(%ebp)
0x0041f77a:	addl %esp, $0xc<UINT8>
0x0041f77d:	cmpl %eax, $0x3fffffff<UINT32>
0x0041f782:	jae 74
0x0041f784:	movl %ecx, -12(%ebp)
0x0041f787:	cmpl %ecx, $0xffffffff<UINT8>
0x0041f78a:	jae 66
0x0041f78c:	movl %edi, %eax
0x0041f78e:	shll %edi, $0x2<UINT8>
0x0041f791:	leal %eax, (%edi,%ecx)
0x0041f794:	cmpl %eax, %ecx
0x0041f796:	jb 54
0x0041f798:	pushl %eax
0x0041f799:	call 0x004197ee
0x0041f79e:	movl %esi, %eax
0x0041f7a0:	popl %ecx
0x0041f7a1:	cmpl %esi, %ebx
0x0041f7a3:	je 41
0x0041f7a5:	movl %edx, -4(%ebp)
0x0041f7a8:	leal %eax, -8(%ebp)
0x0041f7ab:	pushl %eax
0x0041f7ac:	addl %edi, %esi
0x0041f7ae:	pushl %edi
0x0041f7af:	pushl %esi
0x0041f7b0:	leal %edi, -12(%ebp)
0x0041f7b3:	call 0x0041f581
0x0041f5a0:	movl %ebx, 0x8(%ebp)
0x0041f5a3:	addl 0x8(%ebp), $0x4<UINT8>
0x0041f5a7:	movl (%ebx), %edx
0x0041f5c7:	movb %al, (%esi)
0x0041f5c9:	movb (%edx), %al
0x0041f5cb:	incl %edx
0x0041f5cc:	movl 0xc(%ebp), %edx
0x0041f714:	andl (%eax), $0x0<UINT8>
0x0041f7b8:	movl %eax, -8(%ebp)
0x0041f7bb:	addl %esp, $0xc<UINT8>
0x0041f7be:	decl %eax
0x0041f7bf:	movl 0x44300c, %eax
0x0041f7c4:	movl 0x443010, %esi
0x0041f7ca:	xorl %eax, %eax
0x0041f7cc:	jmp 0x0041f7d1
0x0041f7d1:	popl %edi
0x0041f7d2:	popl %esi
0x0041f7d3:	popl %ebx
0x0041f7d4:	leave
0x0041f7d5:	ret

0x00413a54:	testl %eax, %eax
0x00413a56:	jnl 0x00413a60
0x00413a60:	call 0x0041f494
0x0041f494:	cmpl 0x4a8f9c, $0x0<UINT8>
0x0041f49b:	jne 0x0041f4a2
0x0041f4a2:	pushl %esi
0x0041f4a3:	movl %esi, 0x442ea0
0x0041f4a9:	pushl %edi
0x0041f4aa:	xorl %edi, %edi
0x0041f4ac:	testl %esi, %esi
0x0041f4ae:	jne 0x0041f4c8
0x0041f4c8:	movb %al, (%esi)
0x0041f4ca:	testb %al, %al
0x0041f4cc:	jne 0x0041f4b8
0x0041f4b8:	cmpb %al, $0x3d<UINT8>
0x0041f4ba:	je 0x0041f4bd
0x0041f4bd:	pushl %esi
0x0041f4be:	call 0x00410ac0
0x00410ac0:	movl %ecx, 0x4(%esp)
0x00410ac4:	testl %ecx, $0x3<UINT32>
0x00410aca:	je 0x00410af0
0x00410af0:	movl %eax, (%ecx)
0x00410af2:	movl %edx, $0x7efefeff<UINT32>
0x00410af7:	addl %edx, %eax
0x00410af9:	xorl %eax, $0xffffffff<UINT8>
0x00410afc:	xorl %eax, %edx
0x00410afe:	addl %ecx, $0x4<UINT8>
0x00410b01:	testl %eax, $0x81010100<UINT32>
0x00410b06:	je 0x00410af0
0x00410b08:	movl %eax, -4(%ecx)
0x00410b0b:	testb %al, %al
0x00410b0d:	je 50
0x00410b0f:	testb %ah, %ah
0x00410b11:	je 36
0x00410b13:	testl %eax, $0xff0000<UINT32>
0x00410b18:	je 19
0x00410b1a:	testl %eax, $0xff000000<UINT32>
0x00410b1f:	je 0x00410b23
0x00410b23:	leal %eax, -1(%ecx)
0x00410b26:	movl %ecx, 0x4(%esp)
0x00410b2a:	subl %eax, %ecx
0x00410b2c:	ret

0x0041f4c3:	popl %ecx
0x0041f4c4:	leal %esi, 0x1(%esi,%eax)
0x0041f4ce:	pushl $0x4<UINT8>
0x0041f4d0:	incl %edi
0x0041f4d1:	pushl %edi
0x0041f4d2:	call 0x00419833
0x0041f4d7:	movl %edi, %eax
0x0041f4d9:	popl %ecx
0x0041f4da:	popl %ecx
0x0041f4db:	movl 0x443018, %edi
0x0041f4e1:	testl %edi, %edi
0x0041f4e3:	je -53
0x0041f4e5:	movl %esi, 0x442ea0
0x0041f4eb:	pushl %ebx
0x0041f4ec:	jmp 0x0041f530
0x0041f530:	cmpb (%esi), $0x0<UINT8>
0x0041f533:	jne 0x0041f4ee
0x0041f4ee:	pushl %esi
0x0041f4ef:	call 0x00410ac0
0x0041f4f4:	movl %ebx, %eax
0x0041f4f6:	incl %ebx
0x0041f4f7:	cmpb (%esi), $0x3d<UINT8>
0x0041f4fa:	popl %ecx
0x0041f4fb:	je 0x0041f52e
0x0041f52e:	addl %esi, %ebx
0x0041f535:	pushl 0x442ea0
0x0041f53b:	call 0x00411076
0x00411076:	pushl $0xc<UINT8>
0x00411078:	pushl $0x4341b0<UINT32>
0x0041107d:	call 0x00414d00
0x00411082:	movl %esi, 0x8(%ebp)
0x00411085:	testl %esi, %esi
0x00411087:	je 117
0x00411089:	cmpl 0x4a8fa4, $0x3<UINT8>
0x00411090:	jne 0x004110d5
0x004110d5:	pushl %esi
0x004110d6:	pushl $0x0<UINT8>
0x004110d8:	pushl 0x443004
0x004110de:	call HeapFree@KERNEL32.DLL
HeapFree@KERNEL32.DLL: API Node	
0x004110e4:	testl %eax, %eax
0x004110e6:	jne 0x004110fe
0x004110fe:	call 0x00414d45
0x00411103:	ret

0x0041f540:	andl 0x442ea0, $0x0<UINT8>
0x0041f547:	andl (%edi), $0x0<UINT8>
0x0041f54a:	movl 0x4a8f90, $0x1<UINT32>
0x0041f554:	xorl %eax, %eax
0x0041f556:	popl %ecx
0x0041f557:	popl %ebx
0x0041f558:	popl %edi
0x0041f559:	popl %esi
0x0041f55a:	ret

0x00413a65:	testl %eax, %eax
0x00413a67:	jnl 0x00413a71
0x00413a71:	pushl %ebx
0x00413a72:	call 0x00415131
0x00415131:	movl %edi, %edi
0x00415133:	pushl %ebp
0x00415134:	movl %ebp, %esp
0x00415136:	cmpl 0x43253c, $0x0<UINT8>
0x0041513d:	je 25
0x0041513f:	pushl $0x43253c<UINT32>
0x00415144:	call 0x00419540
0x00419540:	movl %edi, %edi
0x00419542:	pushl %ebp
0x00419543:	movl %ebp, %esp
0x00419545:	pushl $0xfffffffe<UINT8>
0x00419547:	pushl $0x4344d8<UINT32>
0x0041954c:	pushl $0x414d90<UINT32>
0x00419551:	movl %eax, %fs:0
0x00419557:	pushl %eax
0x00419558:	subl %esp, $0x8<UINT8>
0x0041955b:	pushl %ebx
0x0041955c:	pushl %esi
0x0041955d:	pushl %edi
0x0041955e:	movl %eax, 0x43b810
0x00419563:	xorl -8(%ebp), %eax
0x00419566:	xorl %eax, %ebp
0x00419568:	pushl %eax
0x00419569:	leal %eax, -16(%ebp)
0x0041956c:	movl %fs:0, %eax
0x00419572:	movl -24(%ebp), %esp
0x00419575:	movl -4(%ebp), $0x0<UINT32>
0x0041957c:	pushl $0x400000<UINT32>
0x00419581:	call 0x004194b0
0x004194b0:	movl %edi, %edi
0x004194b2:	pushl %ebp
0x004194b3:	movl %ebp, %esp
0x004194b5:	movl %ecx, 0x8(%ebp)
0x004194b8:	movl %eax, $0x5a4d<UINT32>
0x004194bd:	cmpw (%ecx), %ax
0x004194c0:	je 0x004194c6
0x004194c6:	movl %eax, 0x3c(%ecx)
0x004194c9:	addl %eax, %ecx
0x004194cb:	cmpl (%eax), $0x4550<UINT32>
0x004194d1:	jne -17
0x004194d3:	xorl %edx, %edx
0x004194d5:	movl %ecx, $0x10b<UINT32>
0x004194da:	cmpw 0x18(%eax), %cx
0x004194de:	sete %dl
0x004194e1:	movl %eax, %edx
0x004194e3:	popl %ebp
0x004194e4:	ret

0x00419586:	addl %esp, $0x4<UINT8>
0x00419589:	testl %eax, %eax
0x0041958b:	je 85
0x0041958d:	movl %eax, 0x8(%ebp)
0x00419590:	subl %eax, $0x400000<UINT32>
0x00419595:	pushl %eax
0x00419596:	pushl $0x400000<UINT32>
0x0041959b:	call 0x004194f0
0x004194f0:	movl %edi, %edi
0x004194f2:	pushl %ebp
0x004194f3:	movl %ebp, %esp
0x004194f5:	movl %eax, 0x8(%ebp)
0x004194f8:	movl %ecx, 0x3c(%eax)
0x004194fb:	addl %ecx, %eax
0x004194fd:	movzwl %eax, 0x14(%ecx)
0x00419501:	pushl %ebx
0x00419502:	pushl %esi
0x00419503:	movzwl %esi, 0x6(%ecx)
0x00419507:	xorl %edx, %edx
0x00419509:	pushl %edi
0x0041950a:	leal %eax, 0x18(%eax,%ecx)
0x0041950e:	testl %esi, %esi
0x00419510:	jbe 27
0x00419512:	movl %edi, 0xc(%ebp)
0x00419515:	movl %ecx, 0xc(%eax)
0x00419518:	cmpl %edi, %ecx
0x0041951a:	jb 9
0x0041951c:	movl %ebx, 0x8(%eax)
0x0041951f:	addl %ebx, %ecx
0x00419521:	cmpl %edi, %ebx
0x00419523:	jb 0x0041952f
0x0041952f:	popl %edi
0x00419530:	popl %esi
0x00419531:	popl %ebx
0x00419532:	popl %ebp
0x00419533:	ret

0x004195a0:	addl %esp, $0x8<UINT8>
0x004195a3:	testl %eax, %eax
0x004195a5:	je 59
0x004195a7:	movl %eax, 0x24(%eax)
0x004195aa:	shrl %eax, $0x1f<UINT8>
0x004195ad:	notl %eax
0x004195af:	andl %eax, $0x1<UINT8>
0x004195b2:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004195b9:	movl %ecx, -16(%ebp)
0x004195bc:	movl %fs:0, %ecx
0x004195c3:	popl %ecx
0x004195c4:	popl %edi
0x004195c5:	popl %esi
0x004195c6:	popl %ebx
0x004195c7:	movl %esp, %ebp
0x004195c9:	popl %ebp
0x004195ca:	ret

0x00415149:	popl %ecx
0x0041514a:	testl %eax, %eax
0x0041514c:	je 10
0x0041514e:	pushl 0x8(%ebp)
0x00415151:	call 0x00412d3e
0x00412d3e:	movl %edi, %edi
0x00412d40:	pushl %ebp
0x00412d41:	movl %ebp, %esp
0x00412d43:	call 0x00412cc9
0x00412cc9:	movl %eax, $0x41c737<UINT32>
0x00412cce:	movl 0x43c480, %eax
0x00412cd3:	movl 0x43c484, $0x41bdc1<UINT32>
0x00412cdd:	movl 0x43c488, $0x41bd75<UINT32>
0x00412ce7:	movl 0x43c48c, $0x41bdae<UINT32>
0x00412cf1:	movl 0x43c490, $0x41bd17<UINT32>
0x00412cfb:	movl 0x43c494, %eax
0x00412d00:	movl 0x43c498, $0x41c6af<UINT32>
0x00412d0a:	movl 0x43c49c, $0x41bd33<UINT32>
0x00412d14:	movl 0x43c4a0, $0x41bc95<UINT32>
0x00412d1e:	movl 0x43c4a4, $0x41bc22<UINT32>
0x00412d28:	ret

0x00412d48:	call 0x0041c7e4
0x0041c7e4:	pushl $0x432e24<UINT32>
0x0041c7e9:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x0041c7ef:	testl %eax, %eax
0x0041c7f1:	je 21
0x0041c7f3:	pushl $0x432e08<UINT32>
0x0041c7f8:	pushl %eax
0x0041c7f9:	call GetProcAddress@KERNEL32.DLL
0x0041c7ff:	testl %eax, %eax
0x0041c801:	je 5
0x0041c803:	pushl $0x0<UINT8>
0x0041c805:	call IsProcessorFeaturePresent@KERNEL32
IsProcessorFeaturePresent@KERNEL32: API Node	
0x0041c807:	ret

0x00412d4d:	cmpl 0x8(%ebp), $0x0<UINT8>
0x00412d51:	movl 0x442e9c, %eax
0x00412d56:	je 5
0x00412d58:	call 0x0041c77b
0x0041c77b:	movl %edi, %edi
0x0041c77d:	pushl %esi
0x0041c77e:	pushl $0x30000<UINT32>
0x0041c783:	pushl $0x10000<UINT32>
0x0041c788:	xorl %esi, %esi
0x0041c78a:	pushl %esi
0x0041c78b:	call 0x0042ae58
0x0042ae58:	movl %edi, %edi
0x0042ae5a:	pushl %ebp
0x0042ae5b:	movl %ebp, %esp
0x0042ae5d:	movl %eax, 0x10(%ebp)
0x0042ae60:	movl %ecx, 0xc(%ebp)
0x0042ae63:	andl %eax, $0xfff7ffff<UINT32>
0x0042ae68:	andl %ecx, %eax
0x0042ae6a:	pushl %esi
0x0042ae6b:	testl %ecx, $0xfcf0fce0<UINT32>
0x0042ae71:	je 0x0042aea4
0x0042aea4:	movl %esi, 0x8(%ebp)
0x0042aea7:	pushl %eax
0x0042aea8:	pushl 0xc(%ebp)
0x0042aeab:	testl %esi, %esi
0x0042aead:	je 0x0042aeb8
0x0042aeb8:	call 0x0042ff60
0x0042ff60:	movl %edi, %edi
0x0042ff62:	pushl %ebp
0x0042ff63:	movl %ebp, %esp
0x0042ff65:	subl %esp, $0x14<UINT8>
0x0042ff68:	pushl %ebx
0x0042ff69:	pushl %esi
0x0042ff6a:	pushl %edi
0x0042ff6b:	fwait
0x0042ff6c:	fnstcw -8(%ebp)
0x0042ff6f:	movl %ebx, -8(%ebp)
0x0042ff72:	xorl %edx, %edx
0x0042ff74:	testb %bl, $0x1<UINT8>
0x0042ff77:	je 0x0042ff7c
0x0042ff7c:	testb %bl, $0x4<UINT8>
0x0042ff7f:	je 3
0x0042ff81:	orl %edx, $0x8<UINT8>
0x0042ff84:	testb %bl, $0x8<UINT8>
0x0042ff87:	je 3
0x0042ff89:	orl %edx, $0x4<UINT8>
0x0042ff8c:	testb %bl, $0x10<UINT8>
0x0042ff8f:	je 0x0042ff94
0x0042ff94:	testb %bl, $0x20<UINT8>
0x0042ff97:	je 3
0x0042ff99:	orl %edx, $0x1<UINT8>
0x0042ff9c:	testb %bl, $0x2<UINT8>
0x0042ff9f:	je 0x0042ffa7
0x0042ffa7:	movzwl %ecx, %bx
0x0042ffaa:	movl %eax, %ecx
0x0042ffac:	movl %esi, $0xc00<UINT32>
0x0042ffb1:	andl %eax, %esi
0x0042ffb3:	movl %edi, $0x300<UINT32>
0x0042ffb8:	je 36
0x0042ffba:	cmpl %eax, $0x400<UINT32>
0x0042ffbf:	je 23
0x0042ffc1:	cmpl %eax, $0x800<UINT32>
0x0042ffc6:	je 8
0x0042ffc8:	cmpl %eax, %esi
0x0042ffca:	jne 18
0x0042ffcc:	orl %edx, %edi
0x0042ffce:	jmp 0x0042ffde
0x0042ffde:	andl %ecx, %edi
0x0042ffe0:	je 16
0x0042ffe2:	cmpl %ecx, $0x200<UINT32>
0x0042ffe8:	jne 14
0x0042ffea:	orl %edx, $0x10000<UINT32>
0x0042fff0:	jmp 0x0042fff8
0x0042fff8:	testl %ebx, $0x1000<UINT32>
0x0042fffe:	je 6
0x00430000:	orl %edx, $0x40000<UINT32>
0x00430006:	movl %edi, 0xc(%ebp)
0x00430009:	movl %ecx, 0x8(%ebp)
0x0043000c:	movl %eax, %edi
0x0043000e:	notl %eax
0x00430010:	andl %eax, %edx
0x00430012:	andl %ecx, %edi
0x00430014:	orl %eax, %ecx
0x00430016:	movl 0xc(%ebp), %eax
0x00430019:	cmpl %eax, %edx
0x0043001b:	je 0x004300cf
0x004300cf:	xorl %esi, %esi
0x004300d1:	cmpl 0x4a8f8c, %esi
0x004300d7:	je 0x0043026a
0x0043026a:	popl %edi
0x0043026b:	popl %esi
0x0043026c:	popl %ebx
0x0043026d:	leave
0x0043026e:	ret

0x0042aebd:	popl %ecx
0x0042aebe:	popl %ecx
0x0042aebf:	xorl %eax, %eax
0x0042aec1:	popl %esi
0x0042aec2:	popl %ebp
0x0042aec3:	ret

0x0041c790:	addl %esp, $0xc<UINT8>
0x0041c793:	testl %eax, %eax
0x0041c795:	je 0x0041c7a4
0x0041c7a4:	popl %esi
0x0041c7a5:	ret

0x00412d5d:	fnclex
0x00412d5f:	popl %ebp
0x00412d60:	ret

0x00415157:	popl %ecx
0x00415158:	call 0x0041c75a
0x0041c75a:	movl %edi, %edi
0x0041c75c:	pushl %esi
0x0041c75d:	pushl %edi
0x0041c75e:	xorl %edi, %edi
0x0041c760:	leal %esi, 0x43c480(%edi)
0x0041c766:	pushl (%esi)
0x0041c768:	call 0x00418981
0x004189a3:	pushl %eax
0x004189a4:	pushl 0x43c1ac
0x004189aa:	call TlsGetValue@KERNEL32.DLL
0x004189ac:	call FlsGetValue@KERNEL32.DLL
0x004189ae:	testl %eax, %eax
0x004189b0:	je 8
0x004189b2:	movl %eax, 0x1f8(%eax)
0x004189b8:	jmp 0x004189e1
0x0041c76d:	addl %edi, $0x4<UINT8>
0x0041c770:	popl %ecx
0x0041c771:	movl (%esi), %eax
0x0041c773:	cmpl %edi, $0x28<UINT8>
0x0041c776:	jb 0x0041c760
0x0041c778:	popl %edi
0x0041c779:	popl %esi
0x0041c77a:	ret

0x0041515d:	pushl $0x4324d0<UINT32>
0x00415162:	pushl $0x4324b8<UINT32>
0x00415167:	call 0x00415095
0x00415095:	movl %edi, %edi
0x00415097:	pushl %ebp
0x00415098:	movl %ebp, %esp
0x0041509a:	pushl %esi
0x0041509b:	movl %esi, 0x8(%ebp)
0x0041509e:	xorl %eax, %eax
0x004150a0:	jmp 0x004150b1
0x004150b1:	cmpl %esi, 0xc(%ebp)
0x004150b4:	jb 0x004150a2
0x004150a2:	testl %eax, %eax
0x004150a4:	jne 16
0x004150a6:	movl %ecx, (%esi)
0x004150a8:	testl %ecx, %ecx
0x004150aa:	je 0x004150ae
0x004150ae:	addl %esi, $0x4<UINT8>
0x004150ac:	call 0x0041f427
0x00415972:	call 0x00415910
0x00415910:	movl %edi, %edi
0x00415912:	pushl %ebp
0x00415913:	movl %ebp, %esp
0x00415915:	subl %esp, $0x18<UINT8>
0x00415918:	xorl %eax, %eax
0x0041591a:	pushl %ebx
0x0041591b:	movl -4(%ebp), %eax
0x0041591e:	movl -12(%ebp), %eax
0x00415921:	movl -8(%ebp), %eax
0x00415924:	pushl %ebx
0x00415925:	pushfl
0x00415926:	popl %eax
0x00415927:	movl %ecx, %eax
0x00415929:	xorl %eax, $0x200000<UINT32>
0x0041592e:	pushl %eax
0x0041592f:	popfl
0x00415930:	pushfl
0x00415931:	popl %edx
0x00415932:	subl %edx, %ecx
0x00415934:	je 0x00415955
0x00415955:	popl %ebx
0x00415956:	testl -4(%ebp), $0x4000000<UINT32>
0x0041595d:	je 0x0041596d
0x0041596d:	xorl %eax, %eax
0x0041596f:	popl %ebx
0x00415970:	leave
0x00415971:	ret

0x00415977:	movl 0x4a8f8c, %eax
0x0041597c:	xorl %eax, %eax
0x0041597e:	ret

0x0041a2a3:	movl %eax, 0x4a8f80
0x0041a2a8:	pushl %esi
0x0041a2a9:	pushl $0x14<UINT8>
0x0041a2ab:	popl %esi
0x0041a2ac:	testl %eax, %eax
0x0041a2ae:	jne 7
0x0041a2b0:	movl %eax, $0x200<UINT32>
0x0041a2b5:	jmp 0x0041a2bd
0x0041a2bd:	movl 0x4a8f80, %eax
0x0041a2c2:	pushl $0x4<UINT8>
0x0041a2c4:	pushl %eax
0x0041a2c5:	call 0x00419833
0x0041a2ca:	popl %ecx
0x0041a2cb:	popl %ecx
0x0041a2cc:	movl 0x4a7f60, %eax
0x0041a2d1:	testl %eax, %eax
0x0041a2d3:	jne 0x0041a2f3
0x0041a2f3:	xorl %edx, %edx
0x0041a2f5:	movl %ecx, $0x43c1c0<UINT32>
0x0041a2fa:	jmp 0x0041a301
0x0041a301:	movl (%edx,%eax), %ecx
0x0041a304:	addl %ecx, $0x20<UINT8>
0x0041a307:	addl %edx, $0x4<UINT8>
0x0041a30a:	cmpl %ecx, $0x43c440<UINT32>
0x0041a310:	jl 0x0041a2fc
0x0041a2fc:	movl %eax, 0x4a7f60
0x0041a312:	pushl $0xfffffffe<UINT8>
0x0041a314:	popl %esi
0x0041a315:	xorl %edx, %edx
0x0041a317:	movl %ecx, $0x43c1d0<UINT32>
0x0041a31c:	pushl %edi
0x0041a31d:	movl %eax, %edx
0x0041a31f:	sarl %eax, $0x5<UINT8>
0x0041a322:	movl %eax, 0x4a7e60(,%eax,4)
0x0041a329:	movl %edi, %edx
0x0041a32b:	andl %edi, $0x1f<UINT8>
0x0041a32e:	shll %edi, $0x6<UINT8>
0x0041a331:	movl %eax, (%edi,%eax)
0x0041a334:	cmpl %eax, $0xffffffff<UINT8>
0x0041a337:	je 8
0x0041a339:	cmpl %eax, %esi
0x0041a33b:	je 4
0x0041a33d:	testl %eax, %eax
0x0041a33f:	jne 0x0041a343
0x0041a343:	addl %ecx, $0x20<UINT8>
0x0041a346:	incl %edx
0x0041a347:	cmpl %ecx, $0x43c230<UINT32>
0x0041a34d:	jl 0x0041a31d
0x0041a34f:	popl %edi
0x0041a350:	xorl %eax, %eax
0x0041a352:	popl %esi
0x0041a353:	ret

0x0041fe7f:	movl %edi, %edi
0x0041fe81:	pushl %esi
0x0041fe82:	pushl $0x4<UINT8>
0x0041fe84:	pushl $0x20<UINT8>
0x0041fe86:	call 0x00419833
0x0041fe8b:	movl %esi, %eax
0x0041fe8d:	pushl %esi
0x0041fe8e:	call 0x00418981
0x0041fe93:	addl %esp, $0xc<UINT8>
0x0041fe96:	movl 0x4a8f98, %eax
0x0041fe9b:	movl 0x4a8f94, %eax
0x0041fea0:	testl %esi, %esi
0x0041fea2:	jne 0x0041fea9
0x0041fea9:	andl (%esi), $0x0<UINT8>
0x0041feac:	xorl %eax, %eax
0x0041feae:	popl %esi
0x0041feaf:	ret

0x0041f427:	pushl $0x41f3e5<UINT32>
0x0041f42c:	call SetUnhandledExceptionFilter@KERNEL32.DLL
SetUnhandledExceptionFilter@KERNEL32.DLL: API Node	
0x0041f432:	xorl %eax, %eax
0x0041f434:	ret

0x004150b6:	popl %esi
0x004150b7:	popl %ebp
0x004150b8:	ret

0x0041516c:	popl %ecx
0x0041516d:	popl %ecx
0x0041516e:	testl %eax, %eax
0x00415170:	jne 66
0x00415172:	pushl $0x41f933<UINT32>
0x00415177:	call 0x0041feec
0x0041feec:	movl %edi, %edi
0x0041feee:	pushl %ebp
0x0041feef:	movl %ebp, %esp
0x0041fef1:	pushl 0x8(%ebp)
0x0041fef4:	call 0x0041feb0
0x0041feb0:	pushl $0xc<UINT8>
0x0041feb2:	pushl $0x434618<UINT32>
0x0041feb7:	call 0x00414d00
0x0041febc:	call 0x00415066
0x00415066:	pushl $0x8<UINT8>
0x00415068:	call 0x00413cac
0x0041506d:	popl %ecx
0x0041506e:	ret

0x0041fec1:	andl -4(%ebp), $0x0<UINT8>
0x0041fec5:	pushl 0x8(%ebp)
0x0041fec8:	call 0x0041fdc5
0x0041fdc5:	movl %edi, %edi
0x0041fdc7:	pushl %ebp
0x0041fdc8:	movl %ebp, %esp
0x0041fdca:	pushl %ecx
0x0041fdcb:	pushl %ebx
0x0041fdcc:	pushl %esi
0x0041fdcd:	pushl %edi
0x0041fdce:	pushl 0x4a8f98
0x0041fdd4:	call 0x004189fc
0x00418a2d:	movl %eax, 0x1fc(%eax)
0x00418a33:	jmp 0x00418a5c
0x0041fdd9:	pushl 0x4a8f94
0x0041fddf:	movl %edi, %eax
0x0041fde1:	movl -4(%ebp), %edi
0x0041fde4:	call 0x004189fc
0x0041fde9:	movl %esi, %eax
0x0041fdeb:	popl %ecx
0x0041fdec:	popl %ecx
0x0041fded:	cmpl %esi, %edi
0x0041fdef:	jb 131
0x0041fdf5:	movl %ebx, %esi
0x0041fdf7:	subl %ebx, %edi
0x0041fdf9:	leal %eax, 0x4(%ebx)
0x0041fdfc:	cmpl %eax, $0x4<UINT8>
0x0041fdff:	jb 119
0x0041fe01:	pushl %edi
0x0041fe02:	call 0x0042b2e4
0x0042b2e4:	pushl $0x10<UINT8>
0x0042b2e6:	pushl $0x434880<UINT32>
0x0042b2eb:	call 0x00414d00
0x0042b2f0:	xorl %eax, %eax
0x0042b2f2:	movl %ebx, 0x8(%ebp)
0x0042b2f5:	xorl %edi, %edi
0x0042b2f7:	cmpl %ebx, %edi
0x0042b2f9:	setne %al
0x0042b2fc:	cmpl %eax, %edi
0x0042b2fe:	jne 0x0042b31d
0x0042b31d:	cmpl 0x4a8fa4, $0x3<UINT8>
0x0042b324:	jne 0x0042b35e
0x0042b35e:	pushl %ebx
0x0042b35f:	pushl %edi
0x0042b360:	pushl 0x443004
0x0042b366:	call HeapSize@KERNEL32.DLL
HeapSize@KERNEL32.DLL: API Node	
0x0042b36c:	movl %esi, %eax
0x0042b36e:	movl %eax, %esi
0x0042b370:	call 0x00414d45
0x0042b375:	ret

0x0041fe07:	movl %edi, %eax
0x0041fe09:	leal %eax, 0x4(%ebx)
0x0041fe0c:	popl %ecx
0x0041fe0d:	cmpl %edi, %eax
0x0041fe0f:	jae 0x0041fe59
0x0041fe59:	pushl 0x8(%ebp)
0x0041fe5c:	call 0x00418981
0x0041fe61:	movl (%esi), %eax
0x0041fe63:	addl %esi, $0x4<UINT8>
0x0041fe66:	pushl %esi
0x0041fe67:	call 0x00418981
0x0041fe6c:	popl %ecx
0x0041fe6d:	movl 0x4a8f94, %eax
0x0041fe72:	movl %eax, 0x8(%ebp)
0x0041fe75:	popl %ecx
0x0041fe76:	jmp 0x0041fe7a
0x0041fe7a:	popl %edi
0x0041fe7b:	popl %esi
0x0041fe7c:	popl %ebx
0x0041fe7d:	leave
0x0041fe7e:	ret

0x0041fecd:	popl %ecx
0x0041fece:	movl -28(%ebp), %eax
0x0041fed1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0041fed8:	call 0x0041fee6
0x0041fee6:	call 0x0041506f
0x0041506f:	pushl $0x8<UINT8>
0x00415071:	call 0x00413bba
0x00415076:	popl %ecx
0x00415077:	ret

0x0041feeb:	ret

0x0041fedd:	movl %eax, -28(%ebp)
0x0041fee0:	call 0x00414d45
0x0041fee5:	ret

0x0041fef9:	negl %eax
0x0041fefb:	sbbl %eax, %eax
0x0041fefd:	negl %eax
0x0041feff:	popl %ecx
0x0041ff00:	decl %eax
0x0041ff01:	popl %ebp
0x0041ff02:	ret

0x0041517c:	movl %eax, $0x4324b0<UINT32>
0x00415181:	movl (%esp), $0x4324b4<UINT32>
0x00415188:	call 0x00415078
0x00415078:	movl %edi, %edi
0x0041507a:	pushl %ebp
0x0041507b:	movl %ebp, %esp
0x0041507d:	pushl %esi
0x0041507e:	movl %esi, %eax
0x00415080:	jmp 0x0041508d
0x0041508d:	cmpl %esi, 0x8(%ebp)
0x00415090:	jb 0x00415082
0x00415082:	movl %eax, (%esi)
0x00415084:	testl %eax, %eax
0x00415086:	je 0x0041508a
0x0041508a:	addl %esi, $0x4<UINT8>
0x00415092:	popl %esi
0x00415093:	popl %ebp
0x00415094:	ret

0x0041518d:	cmpl 0x4a8fa0, $0x0<UINT8>
0x00415194:	popl %ecx
0x00415195:	je 0x004151b2
0x004151b2:	xorl %eax, %eax
0x004151b4:	popl %ebp
0x004151b5:	ret

0x00413a77:	popl %ecx
0x00413a78:	cmpl %eax, %esi
0x00413a7a:	je 0x00413a83
0x00413a83:	call 0x0041f435
0x0041f435:	movl %edi, %edi
0x0041f437:	pushl %esi
0x0041f438:	pushl %edi
0x0041f439:	xorl %edi, %edi
0x0041f43b:	cmpl 0x4a8f9c, %edi
0x0041f441:	jne 0x0041f448
0x0041f448:	movl %esi, 0x4a8fc8
0x0041f44e:	testl %esi, %esi
0x0041f450:	jne 0x0041f457
0x0041f457:	movb %al, (%esi)
0x0041f459:	cmpb %al, $0x20<UINT8>
0x0041f45b:	ja 0x0041f465
0x0041f465:	cmpb %al, $0x22<UINT8>
0x0041f467:	jne 0x0041f472
0x0041f469:	xorl %ecx, %ecx
0x0041f46b:	testl %edi, %edi
0x0041f46d:	sete %cl
0x0041f470:	movl %edi, %ecx
0x0041f472:	movzbl %eax, %al
0x0041f475:	pushl %eax
0x0041f476:	call 0x0042b233
0x0041f47b:	popl %ecx
0x0041f47c:	testl %eax, %eax
0x0041f47e:	je 0x0041f481
0x0041f481:	incl %esi
0x0041f482:	jmp 0x0041f457
0x0041f45d:	testb %al, %al
0x0041f45f:	je 0x0041f48f
0x0041f48f:	popl %edi
0x0041f490:	movl %eax, %esi
0x0041f492:	popl %esi
0x0041f493:	ret

0x00413a88:	testb -60(%ebp), %bl
0x00413a8b:	je 0x00413a93
0x00413a93:	pushl $0xa<UINT8>
0x00413a95:	popl %ecx
0x00413a96:	pushl %ecx
0x00413a97:	pushl %eax
0x00413a98:	pushl %esi
0x00413a99:	pushl $0x400000<UINT32>
0x00413a9e:	call 0x0040ffe0
0x0040ffe0:	pushl %ebp
0x0040ffe1:	movl %ebp, %esp
0x0040ffe3:	subl %esp, $0x150<UINT32>
0x0040ffe9:	movl %eax, 0x43b810
0x0040ffee:	xorl %eax, %ebp
0x0040fff0:	movl -72(%ebp), %eax
0x0040fff3:	movb -9(%ebp), $0x1<UINT8>
0x0040fff7:	movl -8(%ebp), $0x0<UINT32>
0x0040fffe:	leal %eax, -8(%ebp)
0x00410001:	pushl %eax
0x00410002:	call GetCommandLineW@KERNEL32.DLL
GetCommandLineW@KERNEL32.DLL: API Node	
0x00410008:	pushl %eax
0x00410009:	call CommandLineToArgvW@SHELL32.dll
CommandLineToArgvW@SHELL32.dll: API Node	
0x0041000f:	movl -28(%ebp), %eax
0x00410012:	movl %ecx, -28(%ebp)
0x00410015:	pushl %ecx
0x00410016:	leal %edx, -8(%ebp)
0x00410019:	pushl %edx
0x0041001a:	pushl $0x43b6d0<UINT32>
0x0041001f:	call 0x00401c80
0x00401c80:	pushl %ebp
0x00401c81:	movl %ebp, %esp
0x00401c83:	subl %esp, $0x14<UINT8>
0x00401c86:	pushl %esi
0x00401c87:	movl -8(%ebp), $0x0<UINT32>
0x00401c8e:	movl -12(%ebp), $0x0<UINT32>
0x00401c95:	cmpl 0xc(%ebp), $0x0<UINT8>
0x00401c99:	je 6
0x00401c9b:	cmpl 0x10(%ebp), $0x0<UINT8>
0x00401c9f:	jne 0x00401ce2
0x00401ce2:	cmpl 0xc(%ebp), $0x0<UINT8>
0x00401ce6:	je 179
0x00401cec:	movl -4(%ebp), $0x0<UINT32>
0x00401cf3:	jmp 0x00401cfe
0x00401cfe:	movl %edx, 0xc(%ebp)
0x00401d01:	movl %eax, -4(%ebp)
0x00401d04:	cmpl %eax, (%edx)
0x00401d06:	jge 0x00401d9f
0x00401d9f:	movl %edx, -12(%ebp)
0x00401da2:	pushl %edx
0x00401da3:	movl %eax, 0x8(%ebp)
0x00401da6:	pushl %eax
0x00401da7:	call 0x00401130
0x00401130:	pushl %ebp
0x00401131:	movl %ebp, %esp
0x00401133:	subl %esp, $0x124<UINT32>
0x00401139:	movl %eax, 0x43b810
0x0040113e:	xorl %eax, %ebp
0x00401140:	movl -12(%ebp), %eax
0x00401143:	movl -8(%ebp), $0x0<UINT32>
0x0040114a:	movl %eax, 0x8(%ebp)
0x0040114d:	pushl %eax
0x0040114e:	pushl $0x4393e0<UINT32>
0x00401153:	leal %ecx, -280(%ebp)
0x00401159:	pushl %ecx
0x0040115a:	call 0x00410eb5
0x00410eb5:	movl %edi, %edi
0x00410eb7:	pushl %ebp
0x00410eb8:	movl %ebp, %esp
0x00410eba:	subl %esp, $0x20<UINT8>
0x00410ebd:	pushl %ebx
0x00410ebe:	xorl %ebx, %ebx
0x00410ec0:	cmpl 0xc(%ebp), %ebx
0x00410ec3:	jne 0x00410ee2
0x00410ee2:	movl %eax, 0x8(%ebp)
0x00410ee5:	cmpl %eax, %ebx
0x00410ee7:	je -36
0x00410ee9:	pushl %esi
0x00410eea:	movl -24(%ebp), %eax
0x00410eed:	movl -32(%ebp), %eax
0x00410ef0:	leal %eax, 0x10(%ebp)
0x00410ef3:	pushl %eax
0x00410ef4:	pushl %ebx
0x00410ef5:	pushl 0xc(%ebp)
0x00410ef8:	leal %eax, -32(%ebp)
0x00410efb:	pushl %eax
0x00410efc:	movl -28(%ebp), $0x7fffffff<UINT32>
0x00410f03:	movl -20(%ebp), $0x42<UINT32>
0x00410f0a:	call 0x00415bc3
0x00415bc3:	movl %edi, %edi
0x00415bc5:	pushl %ebp
0x00415bc6:	movl %ebp, %esp
0x00415bc8:	subl %esp, $0x278<UINT32>
0x00415bce:	movl %eax, 0x43b810
0x00415bd3:	xorl %eax, %ebp
0x00415bd5:	movl -4(%ebp), %eax
0x00415bd8:	pushl %ebx
0x00415bd9:	movl %ebx, 0xc(%ebp)
0x00415bdc:	pushl %esi
0x00415bdd:	movl %esi, 0x8(%ebp)
0x00415be0:	xorl %eax, %eax
0x00415be2:	pushl %edi
0x00415be3:	movl %edi, 0x14(%ebp)
0x00415be6:	pushl 0x10(%ebp)
0x00415be9:	leal %ecx, -604(%ebp)
0x00415bef:	movl -588(%ebp), %esi
0x00415bf5:	movl -548(%ebp), %edi
0x00415bfb:	movl -584(%ebp), %eax
0x00415c01:	movl -528(%ebp), %eax
0x00415c07:	movl -564(%ebp), %eax
0x00415c0d:	movl -536(%ebp), %eax
0x00415c13:	movl -560(%ebp), %eax
0x00415c19:	movl -576(%ebp), %eax
0x00415c1f:	movl -568(%ebp), %eax
0x00415c25:	call 0x004111f1
0x00415c2a:	testl %esi, %esi
0x00415c2c:	jne 0x00415c63
0x00415c63:	testb 0xc(%esi), $0x40<UINT8>
0x00415c67:	jne 0x00415cc7
0x00415cc7:	xorl %ecx, %ecx
0x00415cc9:	cmpl %ebx, %ecx
0x00415ccb:	je -163
0x00415cd1:	movb %dl, (%ebx)
0x00415cd3:	movl -552(%ebp), %ecx
0x00415cd9:	movl -544(%ebp), %ecx
0x00415cdf:	movl -580(%ebp), %ecx
0x00415ce5:	movb -529(%ebp), %dl
0x00415ceb:	testb %dl, %dl
0x00415ced:	je 2591
0x00415cf3:	incl %ebx
0x00415cf4:	cmpl -552(%ebp), $0x0<UINT8>
0x00415cfb:	movl -572(%ebp), %ebx
0x00415d01:	jl 2571
0x00415d07:	movb %al, %dl
0x00415d09:	subb %al, $0x20<UINT8>
0x00415d0b:	cmpb %al, $0x58<UINT8>
0x00415d0d:	ja 0x00415d20
0x00415d0f:	movsbl %eax, %dl
0x00415d12:	movsbl %eax, 0x432b30(%eax)
0x00415d19:	andl %eax, $0xf<UINT8>
0x00415d1c:	xorl %esi, %esi
0x00415d1e:	jmp 0x00415d24
0x00415d24:	movsbl %eax, 0x432b50(%ecx,%eax,8)
0x00415d2c:	pushl $0x7<UINT8>
0x00415d2e:	sarl %eax, $0x4<UINT8>
0x00415d31:	popl %ecx
0x00415d32:	movl -620(%ebp), %eax
0x00415d38:	cmpl %eax, %ecx
0x00415d3a:	ja 2477
0x00415d40:	jmp 0x00415fa0
0x00415f46:	leal %eax, -604(%ebp)
0x00415f4c:	pushl %eax
0x00415f4d:	movzbl %eax, %dl
0x00415f50:	pushl %eax
0x00415f51:	movl -568(%ebp), %esi
0x00415f57:	call 0x00420fec
0x00420fec:	movl %edi, %edi
0x00420fee:	pushl %ebp
0x00420fef:	movl %ebp, %esp
0x00420ff1:	subl %esp, $0x10<UINT8>
0x00420ff4:	pushl 0xc(%ebp)
0x00420ff7:	leal %ecx, -16(%ebp)
0x00420ffa:	call 0x004111f1
0x00411267:	movl %ecx, (%eax)
0x00411269:	movl (%esi), %ecx
0x0041126b:	movl %eax, 0x4(%eax)
0x0041126e:	movl 0x4(%esi), %eax
0x00420fff:	movzbl %eax, 0x8(%ebp)
0x00421003:	movl %ecx, -16(%ebp)
0x00421006:	movl %ecx, 0xc8(%ecx)
0x0042100c:	movzwl %eax, (%ecx,%eax,2)
0x00421010:	andl %eax, $0x8000<UINT32>
0x00421015:	cmpb -4(%ebp), $0x0<UINT8>
0x00421019:	je 0x00421022
0x00421022:	leave
0x00421023:	ret

0x00415f5c:	popl %ecx
0x00415f5d:	testl %eax, %eax
0x00415f5f:	movb %al, -529(%ebp)
0x00415f65:	popl %ecx
0x00415f66:	je 0x00415f8a
0x00415f8a:	movl %ecx, -588(%ebp)
0x00415f90:	leal %esi, -552(%ebp)
0x00415f96:	call 0x00415ae3
0x00415ae3:	testb 0xc(%ecx), $0x40<UINT8>
0x00415ae7:	je 6
0x00415ae9:	cmpl 0x8(%ecx), $0x0<UINT8>
0x00415aed:	je 36
0x00415aef:	decl 0x4(%ecx)
0x00415af2:	js 11
0x00415af4:	movl %edx, (%ecx)
0x00415af6:	movb (%edx), %al
0x00415af8:	incl (%ecx)
0x00415afa:	movzbl %eax, %al
0x00415afd:	jmp 0x00415b0b
0x00415b0b:	cmpl %eax, $0xffffffff<UINT8>
0x00415b0e:	jne 0x00415b13
0x00415b13:	incl (%esi)
0x00415b15:	ret

0x00415f9b:	jmp 0x004166ed
0x004166ed:	movl %ebx, -572(%ebp)
0x004166f3:	movb %al, (%ebx)
0x004166f5:	movb -529(%ebp), %al
0x004166fb:	testb %al, %al
0x004166fd:	je 0x00416712
0x004166ff:	movl %ecx, -620(%ebp)
0x00416705:	movl %edi, -548(%ebp)
0x0041670b:	movb %dl, %al
0x0041670d:	jmp 0x00415cf3
0x00415d20:	xorl %esi, %esi
0x00415d22:	xorl %eax, %eax
0x00415d47:	orl -536(%ebp), $0xffffffff<UINT8>
0x00415d4e:	movl -624(%ebp), %esi
0x00415d54:	movl -576(%ebp), %esi
0x00415d5a:	movl -564(%ebp), %esi
0x00415d60:	movl -560(%ebp), %esi
0x00415d66:	movl -528(%ebp), %esi
0x00415d6c:	movl -568(%ebp), %esi
0x00415d72:	jmp 0x004166ed
0x00415fa0:	movsbl %eax, %dl
0x00415fa3:	cmpl %eax, $0x64<UINT8>
0x00415fa6:	jg 0x00416194
0x00416194:	cmpl %eax, $0x70<UINT8>
0x00416197:	jg 0x00416398
0x00416398:	subl %eax, $0x73<UINT8>
0x0041639b:	je 0x00416057
0x00416057:	movl %ecx, -536(%ebp)
0x0041605d:	cmpl %ecx, $0xffffffff<UINT8>
0x00416060:	jne 5
0x00416062:	movl %ecx, $0x7fffffff<UINT32>
0x00416067:	addl %edi, $0x4<UINT8>
0x0041606a:	testl -528(%ebp), $0x810<UINT32>
0x00416074:	movl -548(%ebp), %edi
0x0041607a:	movl %edi, -4(%edi)
0x0041607d:	movl -540(%ebp), %edi
0x00416083:	je 0x0041653a
0x0041653a:	cmpl %edi, %esi
0x0041653c:	jne 0x00416549
0x00416549:	movl %eax, -540(%ebp)
0x0041654f:	jmp 0x00416558
0x00416558:	cmpl %ecx, %esi
0x0041655a:	jne 0x00416551
0x00416551:	decl %ecx
0x00416552:	cmpb (%eax), $0x0<UINT8>
0x00416555:	je 0x0041655c
0x00416557:	incl %eax
0x0041655c:	subl %eax, -540(%ebp)
0x00416562:	movl -544(%ebp), %eax
0x00416568:	cmpl -576(%ebp), $0x0<UINT8>
0x0041656f:	jne 348
0x00416575:	movl %eax, -528(%ebp)
0x0041657b:	testb %al, $0x40<UINT8>
0x0041657d:	je 0x004165b1
0x004165b1:	movl %ebx, -564(%ebp)
0x004165b7:	subl %ebx, -544(%ebp)
0x004165bd:	subl %ebx, -560(%ebp)
0x004165c3:	testb -528(%ebp), $0xc<UINT8>
0x004165ca:	jne 23
0x004165cc:	pushl -588(%ebp)
0x004165d2:	leal %eax, -552(%ebp)
0x004165d8:	pushl %ebx
0x004165d9:	pushl $0x20<UINT8>
0x004165db:	call 0x00415b16
0x00415b16:	movl %edi, %edi
0x00415b18:	pushl %ebp
0x00415b19:	movl %ebp, %esp
0x00415b1b:	pushl %esi
0x00415b1c:	movl %esi, %eax
0x00415b1e:	jmp 0x00415b33
0x00415b33:	cmpl 0xc(%ebp), $0x0<UINT8>
0x00415b37:	jg -25
0x00415b39:	popl %esi
0x00415b3a:	popl %ebp
0x00415b3b:	ret

0x004165e0:	addl %esp, $0xc<UINT8>
0x004165e3:	pushl -560(%ebp)
0x004165e9:	movl %edi, -588(%ebp)
0x004165ef:	leal %eax, -552(%ebp)
0x004165f5:	leal %ecx, -556(%ebp)
0x004165fb:	call 0x00415b3c
0x00415b3c:	movl %edi, %edi
0x00415b3e:	pushl %ebp
0x00415b3f:	movl %ebp, %esp
0x00415b41:	testb 0xc(%edi), $0x40<UINT8>
0x00415b45:	pushl %ebx
0x00415b46:	pushl %esi
0x00415b47:	movl %esi, %eax
0x00415b49:	movl %ebx, %ecx
0x00415b4b:	je 50
0x00415b4d:	cmpl 0x8(%edi), $0x0<UINT8>
0x00415b51:	jne 0x00415b7f
0x00415b7f:	cmpl 0x8(%ebp), $0x0<UINT8>
0x00415b83:	jg 0x00415b5a
0x00415b85:	popl %esi
0x00415b86:	popl %ebx
0x00415b87:	popl %ebp
0x00415b88:	ret

0x00416600:	testb -528(%ebp), $0x8<UINT8>
0x00416607:	popl %ecx
0x00416608:	je 0x00416625
0x00416625:	cmpl -568(%ebp), $0x0<UINT8>
0x0041662c:	movl %eax, -544(%ebp)
0x00416632:	je 0x0041669a
0x0041669a:	movl %ecx, -540(%ebp)
0x004166a0:	pushl %eax
0x004166a1:	leal %eax, -552(%ebp)
0x004166a7:	call 0x00415b3c
0x00415b5a:	movb %al, (%ebx)
0x00415b5c:	decl 0x8(%ebp)
0x00415b5f:	movl %ecx, %edi
0x00415b61:	call 0x00415ae3
0x00415b66:	incl %ebx
0x00415b67:	cmpl (%esi), $0xffffffff<UINT8>
0x00415b6a:	jne 0x00415b7f
0x004166ac:	popl %ecx
0x004166ad:	cmpl -552(%ebp), $0x0<UINT8>
0x004166b4:	jl 27
0x004166b6:	testb -528(%ebp), $0x4<UINT8>
0x004166bd:	je 0x004166d1
0x004166d1:	cmpl -580(%ebp), $0x0<UINT8>
0x004166d8:	je 0x004166ed
0x00416712:	cmpb -592(%ebp), $0x0<UINT8>
0x00416719:	je 10
0x0041671b:	movl %eax, -596(%ebp)
0x00416721:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x00416725:	movl %eax, -552(%ebp)
0x0041672b:	movl %ecx, -4(%ebp)
0x0041672e:	popl %edi
0x0041672f:	popl %esi
0x00416730:	xorl %ecx, %ebp
0x00416732:	popl %ebx
0x00416733:	call 0x00411067
0x00416738:	leave
0x00416739:	ret

0x00410f0f:	addl %esp, $0x10<UINT8>
0x00410f12:	decl -28(%ebp)
0x00410f15:	movl %esi, %eax
0x00410f17:	js 7
0x00410f19:	movl %eax, -32(%ebp)
0x00410f1c:	movb (%eax), %bl
0x00410f1e:	jmp 0x00410f2c
0x00410f2c:	movl %eax, %esi
0x00410f2e:	popl %esi
0x00410f2f:	popl %ebx
0x00410f30:	leave
0x00410f31:	ret

0x0040115f:	addl %esp, $0xc<UINT8>
0x00401162:	leal %edx, -8(%ebp)
0x00401165:	pushl %edx
0x00401166:	leal %eax, -280(%ebp)
0x0040116c:	pushl %eax
0x0040116d:	pushl $0x80000001<UINT32>
0x00401172:	call RegCreateKeyA@ADVAPI32.dll
RegCreateKeyA@ADVAPI32.dll: API Node	
0x00401178:	testl %eax, %eax
0x0040117a:	jne 34
0x0040117c:	movl -4(%ebp), $0x4<UINT32>
0x00401183:	leal %ecx, -4(%ebp)
0x00401186:	pushl %ecx
0x00401187:	leal %edx, 0xc(%ebp)
0x0040118a:	pushl %edx
0x0040118b:	pushl $0x0<UINT8>
0x0040118d:	pushl $0x0<UINT8>
0x0040118f:	pushl $0x4393fc<UINT32>
0x00401194:	movl %eax, -8(%ebp)
0x00401197:	pushl %eax
0x00401198:	call RegQueryValueExA@ADVAPI32.dll
RegQueryValueExA@ADVAPI32.dll: API Node	
0x0040119e:	cmpl 0xc(%ebp), $0x0<UINT8>
0x004011a2:	jne 1623
0x004011a8:	pushl $0x3e8<UINT32>
0x004011ad:	pushl $0x40<UINT8>
0x004011af:	call LocalAlloc@KERNEL32.DLL
LocalAlloc@KERNEL32.DLL: API Node	
0x004011b5:	movl -288(%ebp), %eax
0x004011bb:	movl %ecx, -288(%ebp)
0x004011c1:	addl %ecx, $0x12<UINT8>
0x004011c4:	movl -284(%ebp), %ecx
0x004011ca:	pushl $0x43940c<UINT32>
0x004011cf:	call LoadLibraryA@KERNEL32.DLL
0x004011d5:	movl %edx, -288(%ebp)
0x004011db:	movl (%edx), $0x80c808d0<UINT32>
0x00414d90:	movl %edi, %edi
0x00414d92:	pushl %ebp
0x00414d93:	movl %ebp, %esp
0x00414d95:	subl %esp, $0x18<UINT8>
0x00414d98:	pushl %ebx
0x00414d99:	movl %ebx, 0xc(%ebp)
0x00414d9c:	pushl %esi
0x00414d9d:	movl %esi, 0x8(%ebx)
0x00414da0:	xorl %esi, 0x43b810
0x00414da6:	pushl %edi
0x00414da7:	movl %eax, (%esi)
0x00414da9:	movb -1(%ebp), $0x0<UINT8>
0x00414dad:	movl -12(%ebp), $0x1<UINT32>
0x00414db4:	leal %edi, 0x10(%ebx)
0x00414db7:	cmpl %eax, $0xfffffffe<UINT8>
0x00414dba:	je 0x00414dc9
0x00414dc9:	movl %ecx, 0xc(%esi)
0x00414dcc:	movl %eax, 0x8(%esi)
0x00414dcf:	addl %ecx, %edi
0x00414dd1:	xorl %ecx, (%eax,%edi)
0x00414dd4:	call 0x00411067
0x00414dd9:	movl %eax, 0x8(%ebp)
0x00414ddc:	testb 0x4(%eax), $0x66<UINT8>
0x00414de0:	jne 278
0x00414de6:	movl %ecx, 0x10(%ebp)
0x00414de9:	leal %edx, -24(%ebp)
0x00414dec:	movl -4(%ebx), %edx
0x00414def:	movl %ebx, 0xc(%ebx)
0x00414df2:	movl -24(%ebp), %eax
0x00414df5:	movl -20(%ebp), %ecx
0x00414df8:	cmpl %ebx, $0xfffffffe<UINT8>
0x00414dfb:	je 95
0x00414dfd:	leal %ecx, (%ecx)
0x00414e00:	leal %eax, (%ebx,%ebx,2)
0x00414e03:	movl %ecx, 0x14(%esi,%eax,4)
0x00414e07:	leal %eax, 0x10(%esi,%eax,4)
0x00414e0b:	movl -16(%ebp), %eax
0x00414e0e:	movl %eax, (%eax)
0x00414e10:	movl -8(%ebp), %eax
0x00414e13:	testl %ecx, %ecx
0x00414e15:	je 20
0x00414e17:	movl %edx, %edi
0x00414e19:	call 0x0041a976
0x0041a976:	pushl %ebp
0x0041a977:	pushl %esi
0x0041a978:	pushl %edi
0x0041a979:	pushl %ebx
0x0041a97a:	movl %ebp, %edx
0x0041a97c:	xorl %eax, %eax
0x0041a97e:	xorl %ebx, %ebx
0x0041a980:	xorl %edx, %edx
0x0041a982:	xorl %esi, %esi
0x0041a984:	xorl %edi, %edi
0x0041a986:	call 0x00413abb
0x00413abb:	movl %eax, -20(%ebp)
0x00413abe:	movl %ecx, (%eax)
0x00413ac0:	movl %ecx, (%ecx)
0x00413ac2:	movl -36(%ebp), %ecx
0x00413ac5:	pushl %eax
0x00413ac6:	pushl %ecx
0x00413ac7:	call 0x00419633
0x00419633:	movl %edi, %edi
0x00419635:	pushl %ebp
0x00419636:	movl %ebp, %esp
0x00419638:	pushl %ecx
0x00419639:	pushl %ecx
0x0041963a:	pushl %esi
0x0041963b:	call 0x00418c0c
0x00419640:	movl %esi, %eax
0x00419642:	testl %esi, %esi
0x00419644:	je 326
0x0041964a:	movl %edx, 0x5c(%esi)
0x0041964d:	movl %eax, 0x43c1bc
0x00419652:	pushl %edi
0x00419653:	movl %edi, 0x8(%ebp)
0x00419656:	movl %ecx, %edx
0x00419658:	pushl %ebx
0x00419659:	cmpl (%ecx), %edi
0x0041965b:	je 0x0041966b
0x0041966b:	imull %eax, %eax, $0xc<UINT8>
0x0041966e:	addl %eax, %edx
0x00419670:	cmpl %ecx, %eax
0x00419672:	jae 8
0x00419674:	cmpl (%ecx), %edi
0x00419676:	jne 4
0x00419678:	movl %eax, %ecx
0x0041967a:	jmp 0x0041967e
0x0041967e:	testl %eax, %eax
0x00419680:	je 10
0x00419682:	movl %ebx, 0x8(%eax)
0x00419685:	movl -4(%ebp), %ebx
0x00419688:	testl %ebx, %ebx
0x0041968a:	jne 7
0x0041968c:	xorl %eax, %eax
0x0041968e:	jmp 0x0041978e
0x0041978e:	popl %ebx
0x0041978f:	popl %edi
0x00419790:	popl %esi
0x00419791:	leave
0x00419792:	ret

0x00413acc:	popl %ecx
0x00413acd:	popl %ecx
0x00413ace:	ret

0x0041a988:	popl %ebx
0x0041a989:	popl %edi
0x0041a98a:	popl %esi
0x0041a98b:	popl %ebp
0x0041a98c:	ret

0x00414e1e:	movb -1(%ebp), $0x1<UINT8>
0x00414e22:	testl %eax, %eax
0x00414e24:	jl 64
0x00414e26:	jg 71
0x00414e28:	movl %eax, -8(%ebp)
0x00414e2b:	movl %ebx, %eax
0x00414e2d:	cmpl %eax, $0xfffffffe<UINT8>
0x00414e30:	jne -50
0x00414e32:	cmpb -1(%ebp), $0x0<UINT8>
0x00414e36:	je 36
0x00414e38:	movl %eax, (%esi)
0x00414e3a:	cmpl %eax, $0xfffffffe<UINT8>
0x00414e3d:	je 0x00414e4c
0x00414e4c:	movl %ecx, 0xc(%esi)
0x00414e4f:	movl %edx, 0x8(%esi)
0x00414e52:	addl %ecx, %edi
0x00414e54:	xorl %ecx, (%edx,%edi)
0x00414e57:	call 0x00411067
0x00414e5c:	movl %eax, -12(%ebp)
0x00414e5f:	popl %edi
0x00414e60:	popl %esi
0x00414e61:	popl %ebx
0x00414e62:	movl %esp, %ebp
0x00414e64:	popl %ebp
0x00414e65:	ret

0x004011e1:	xorl %eax, %eax
0x004011e3:	movl %ecx, -288(%ebp)
0x004011e9:	movw 0xa(%ecx), %ax
0x004011ed:	xorl %edx, %edx
0x004011ef:	movl %eax, -288(%ebp)
0x004011f5:	movw 0xc(%eax), %dx
0x004011f9:	movl %ecx, $0x138<UINT32>
0x004011fe:	movl %edx, -288(%ebp)
0x00401204:	movw 0xe(%edx), %cx
0x00401208:	movl %eax, $0xb4<UINT32>
0x0040120d:	movl %ecx, -288(%ebp)
0x00401213:	movw 0x10(%ecx), %ax
0x00401217:	xorl %edx, %edx
0x00401219:	movl %eax, -288(%ebp)
0x0040121f:	movw 0x8(%eax), %dx
0x00401223:	xorl %ecx, %ecx
0x00401225:	movl %edx, -284(%ebp)
0x0040122b:	movw (%edx), %cx
0x0040122e:	movl %eax, -284(%ebp)
0x00401234:	addl %eax, $0x2<UINT8>
0x00401237:	movl -284(%ebp), %eax
0x0040123d:	xorl %ecx, %ecx
0x0040123f:	movl %edx, -284(%ebp)
0x00401245:	movw (%edx), %cx
0x00401248:	movl %eax, -284(%ebp)
0x0040124e:	addl %eax, $0x2<UINT8>
0x00401251:	movl -284(%ebp), %eax
0x00401257:	pushl $0x43941c<UINT32>
0x0040125c:	movl %ecx, -284(%ebp)
0x00401262:	pushl %ecx
0x00401263:	call 0x00401c50
0x00401c50:	pushl %ebp
0x00401c51:	movl %ebp, %esp
0x00401c53:	pushl %ecx
0x00401c54:	movl %eax, 0xc(%ebp)
0x00401c57:	pushl %eax
0x00401c58:	call 0x004111d7
0x004111d7:	movl %edi, %edi
0x004111d9:	pushl %ebp
0x004111da:	movl %ebp, %esp
0x004111dc:	movl %eax, 0x8(%ebp)
0x004111df:	movw %cx, (%eax)
0x004111e2:	incl %eax
0x004111e3:	incl %eax
0x004111e4:	testw %cx, %cx
0x004111e7:	jne 0x004111df
0x004111e9:	subl %eax, 0x8(%ebp)
0x004111ec:	sarl %eax
0x004111ee:	decl %eax
0x004111ef:	popl %ebp
0x004111f0:	ret

0x00401c5d:	addl %esp, $0x4<UINT8>
0x00401c60:	addl %eax, $0x1<UINT8>
0x00401c63:	movl -4(%ebp), %eax
0x00401c66:	movl %ecx, 0xc(%ebp)
0x00401c69:	pushl %ecx
0x00401c6a:	movl %edx, 0x8(%ebp)
0x00401c6d:	pushl %edx
0x00401c6e:	call 0x004111b8
0x004111b8:	movl %edi, %edi
0x004111ba:	pushl %ebp
0x004111bb:	movl %ebp, %esp
0x004111bd:	movl %ecx, 0x8(%ebp)
0x004111c0:	movl %edx, 0xc(%ebp)
0x004111c3:	movzwl %eax, (%edx)
0x004111c6:	movw (%ecx), %ax
0x004111c9:	incl %ecx
0x004111ca:	incl %ecx
0x004111cb:	incl %edx
0x004111cc:	incl %edx
0x004111cd:	testw %ax, %ax
0x004111d0:	jne 0x004111c3
0x004111d2:	movl %eax, 0x8(%ebp)
0x004111d5:	popl %ebp
0x004111d6:	ret

0x00401c73:	addl %esp, $0x8<UINT8>
0x00401c76:	movl %eax, -4(%ebp)
0x00401c79:	movl %esp, %ebp
0x00401c7b:	popl %ebp
0x00401c7c:	ret

0x00401268:	addl %esp, $0x8<UINT8>
0x0040126b:	movl %edx, -284(%ebp)
0x00401271:	leal %eax, (%edx,%eax,2)
0x00401274:	movl -284(%ebp), %eax
0x0040127a:	movl %ecx, $0x8<UINT32>
0x0040127f:	movl %edx, -284(%ebp)
0x00401285:	movw (%edx), %cx
0x00401288:	movl %eax, -284(%ebp)
0x0040128e:	addl %eax, $0x2<UINT8>
0x00401291:	movl -284(%ebp), %eax
0x00401297:	pushl $0x439440<UINT32>
0x0040129c:	movl %ecx, -284(%ebp)
0x004012a2:	pushl %ecx
0x004012a3:	call 0x00401c50
0x004012a8:	addl %esp, $0x8<UINT8>
0x004012ab:	movl %edx, -284(%ebp)
0x004012b1:	leal %eax, (%edx,%eax,2)
0x004012b4:	movl -284(%ebp), %eax
0x004012ba:	movl %ecx, -284(%ebp)
0x004012c0:	pushl %ecx
0x004012c1:	call 0x00401c40
0x00401c40:	pushl %ebp
0x00401c41:	movl %ebp, %esp
0x00401c43:	movl %eax, 0x8(%ebp)
0x00401c46:	addl %eax, $0x3<UINT8>
0x00401c49:	andl %eax, $0xfffffffc<UINT8>
0x00401c4c:	popl %ebp
0x00401c4d:	ret

0x004012c6:	addl %esp, $0x4<UINT8>
0x004012c9:	movl -292(%ebp), %eax
0x004012cf:	movl %edx, $0x7<UINT32>
0x004012d4:	movl %eax, -292(%ebp)
0x004012da:	movw 0x8(%eax), %dx
0x004012de:	movl %ecx, $0x3<UINT32>
0x004012e3:	movl %edx, -292(%ebp)
0x004012e9:	movw 0xa(%edx), %cx
0x004012ed:	movl %eax, $0x12a<UINT32>
0x004012f2:	movl %ecx, -292(%ebp)
0x004012f8:	movw 0xc(%ecx), %ax
0x004012fc:	movl %edx, $0xe<UINT32>
0x00401301:	movl %eax, -292(%ebp)
0x00401307:	movw 0xe(%eax), %dx
0x0040130b:	movl %ecx, $0x1f6<UINT32>
0x00401310:	movl %edx, -292(%ebp)
0x00401316:	movw 0x10(%edx), %cx
0x0040131a:	movl %eax, -292(%ebp)
0x00401320:	movl (%eax), $0x50000000<UINT32>
0x00401326:	movl %ecx, -292(%ebp)
0x0040132c:	addl %ecx, $0x12<UINT8>
0x0040132f:	movl -284(%ebp), %ecx
0x00401335:	movl %edx, $0xffff<UINT32>
0x0040133a:	movl %eax, -284(%ebp)
0x00401340:	movw (%eax), %dx
0x00401343:	movl %ecx, -284(%ebp)
0x00401349:	addl %ecx, $0x2<UINT8>
0x0040134c:	movl -284(%ebp), %ecx
0x00401352:	movl %edx, $0x82<UINT32>
0x00401357:	movl %eax, -284(%ebp)
0x0040135d:	movw (%eax), %dx
0x00401360:	movl %ecx, -284(%ebp)
0x00401366:	addl %ecx, $0x2<UINT8>
0x00401369:	movl -284(%ebp), %ecx
0x0040136f:	pushl $0x439460<UINT32>
0x00401374:	movl %edx, -284(%ebp)
0x0040137a:	pushl %edx
0x0040137b:	call 0x00401c50
0x00401380:	addl %esp, $0x8<UINT8>
0x00401383:	movl %ecx, -284(%ebp)
0x00401389:	leal %edx, (%ecx,%eax,2)
0x0040138c:	movl -284(%ebp), %edx
0x00401392:	xorl %eax, %eax
0x00401394:	movl %ecx, -284(%ebp)
0x0040139a:	movw (%ecx), %ax
0x0040139d:	movl %edx, -284(%ebp)
0x004013a3:	addl %edx, $0x2<UINT8>
0x004013a6:	movl -284(%ebp), %edx
0x004013ac:	movl %eax, -288(%ebp)
0x004013b2:	movw %cx, 0x8(%eax)
0x004013b6:	addw %cx, $0x1<UINT8>
0x004013ba:	movl %edx, -288(%ebp)
0x004013c0:	movw 0x8(%edx), %cx
0x004013c4:	movl %eax, -284(%ebp)
0x004013ca:	pushl %eax
0x004013cb:	call 0x00401c40
0x004013d0:	addl %esp, $0x4<UINT8>
0x004013d3:	movl -292(%ebp), %eax
0x004013d9:	movl %ecx, $0xc9<UINT32>
0x004013de:	movl %edx, -292(%ebp)
0x004013e4:	movw 0x8(%edx), %cx
0x004013e8:	movl %eax, $0x9f<UINT32>
0x004013ed:	movl %ecx, -292(%ebp)
0x004013f3:	movw 0xa(%ecx), %ax
0x004013f7:	movl %edx, $0x32<UINT32>
0x004013fc:	movl %eax, -292(%ebp)
0x00401402:	movw 0xc(%eax), %dx
0x00401406:	movl %ecx, $0xe<UINT32>
0x0040140b:	movl %edx, -292(%ebp)
0x00401411:	movw 0xe(%edx), %cx
0x00401415:	movl %eax, $0x1<UINT32>
0x0040141a:	movl %ecx, -292(%ebp)
0x00401420:	movw 0x10(%ecx), %ax
0x00401424:	movl %edx, -292(%ebp)
0x0040142a:	movl (%edx), $0x50010000<UINT32>
0x00401430:	movl %eax, -292(%ebp)
0x00401436:	addl %eax, $0x12<UINT8>
0x00401439:	movl -284(%ebp), %eax
0x0040143f:	movl %ecx, $0xffff<UINT32>
0x00401444:	movl %edx, -284(%ebp)
0x0040144a:	movw (%edx), %cx
0x0040144d:	movl %eax, -284(%ebp)
0x00401453:	addl %eax, $0x2<UINT8>
0x00401456:	movl -284(%ebp), %eax
0x0040145c:	movl %ecx, $0x80<UINT32>
0x00401461:	movl %edx, -284(%ebp)
0x00401467:	movw (%edx), %cx
0x0040146a:	movl %eax, -284(%ebp)
0x00401470:	addl %eax, $0x2<UINT8>
0x00401473:	movl -284(%ebp), %eax
0x00401479:	pushl $0x4394f4<UINT32>
0x0040147e:	movl %ecx, -284(%ebp)
0x00401484:	pushl %ecx
0x00401485:	call 0x00401c50
0x0040148a:	addl %esp, $0x8<UINT8>
0x0040148d:	movl %edx, -284(%ebp)
0x00401493:	leal %eax, (%edx,%eax,2)
0x00401496:	movl -284(%ebp), %eax
0x0040149c:	xorl %ecx, %ecx
0x0040149e:	movl %edx, -284(%ebp)
0x004014a4:	movw (%edx), %cx
0x004014a7:	movl %eax, -284(%ebp)
0x004014ad:	addl %eax, $0x2<UINT8>
0x004014b0:	movl -284(%ebp), %eax
0x004014b6:	movl %ecx, -288(%ebp)
0x004014bc:	movw %dx, 0x8(%ecx)
0x004014c0:	addw %dx, $0x1<UINT8>
0x004014c4:	movl %eax, -288(%ebp)
0x004014ca:	movw 0x8(%eax), %dx
0x004014ce:	movl %ecx, -284(%ebp)
0x004014d4:	pushl %ecx
0x004014d5:	call 0x00401c40
0x004014da:	addl %esp, $0x4<UINT8>
0x004014dd:	movl -292(%ebp), %eax
0x004014e3:	movl %edx, $0xff<UINT32>
0x004014e8:	movl %eax, -292(%ebp)
0x004014ee:	movw 0x8(%eax), %dx
0x004014f2:	movl %ecx, $0x9f<UINT32>
0x004014f7:	movl %edx, -292(%ebp)
0x004014fd:	movw 0xa(%edx), %cx
0x00401501:	movl %eax, $0x32<UINT32>
0x00401506:	movl %ecx, -292(%ebp)
0x0040150c:	movw 0xc(%ecx), %ax
0x00401510:	movl %edx, $0xe<UINT32>
0x00401515:	movl %eax, -292(%ebp)
0x0040151b:	movw 0xe(%eax), %dx
0x0040151f:	movl %ecx, $0x2<UINT32>
0x00401524:	movl %edx, -292(%ebp)
0x0040152a:	movw 0x10(%edx), %cx
0x0040152e:	movl %eax, -292(%ebp)
0x00401534:	movl (%eax), $0x50010000<UINT32>
0x0040153a:	movl %ecx, -292(%ebp)
0x00401540:	addl %ecx, $0x12<UINT8>
0x00401543:	movl -284(%ebp), %ecx
0x00401549:	movl %edx, $0xffff<UINT32>
0x0040154e:	movl %eax, -284(%ebp)
0x00401554:	movw (%eax), %dx
0x00401557:	movl %ecx, -284(%ebp)
0x0040155d:	addl %ecx, $0x2<UINT8>
0x00401560:	movl -284(%ebp), %ecx
0x00401566:	movl %edx, $0x80<UINT32>
0x0040156b:	movl %eax, -284(%ebp)
0x00401571:	movw (%eax), %dx
0x00401574:	movl %ecx, -284(%ebp)
0x0040157a:	addl %ecx, $0x2<UINT8>
0x0040157d:	movl -284(%ebp), %ecx
0x00401583:	pushl $0x439504<UINT32>
0x00401588:	movl %edx, -284(%ebp)
0x0040158e:	pushl %edx
0x0040158f:	call 0x00401c50
0x00401594:	addl %esp, $0x8<UINT8>
0x00401597:	movl %ecx, -284(%ebp)
0x0040159d:	leal %edx, (%ecx,%eax,2)
0x004015a0:	movl -284(%ebp), %edx
0x004015a6:	xorl %eax, %eax
0x004015a8:	movl %ecx, -284(%ebp)
0x004015ae:	movw (%ecx), %ax
0x004015b1:	movl %edx, -284(%ebp)
0x004015b7:	addl %edx, $0x2<UINT8>
0x004015ba:	movl -284(%ebp), %edx
0x004015c0:	movl %eax, -288(%ebp)
0x004015c6:	movw %cx, 0x8(%eax)
0x004015ca:	addw %cx, $0x1<UINT8>
0x004015ce:	movl %edx, -288(%ebp)
0x004015d4:	movw 0x8(%edx), %cx
0x004015d8:	movl %eax, -284(%ebp)
0x004015de:	pushl %eax
0x004015df:	call 0x00401c40
0x004015e4:	addl %esp, $0x4<UINT8>
0x004015e7:	movl -292(%ebp), %eax
0x004015ed:	movl %ecx, $0x7<UINT32>
0x004015f2:	movl %edx, -292(%ebp)
0x004015f8:	movw 0x8(%edx), %cx
0x004015fc:	movl %eax, $0x9f<UINT32>
0x00401601:	movl %ecx, -292(%ebp)
0x00401607:	movw 0xa(%ecx), %ax
0x0040160b:	movl %edx, $0x32<UINT32>
0x00401610:	movl %eax, -292(%ebp)
0x00401616:	movw 0xc(%eax), %dx
0x0040161a:	movl %ecx, $0xe<UINT32>
0x0040161f:	movl %edx, -292(%ebp)
0x00401625:	movw 0xe(%edx), %cx
0x00401629:	movl %eax, $0x1f5<UINT32>
0x0040162e:	movl %ecx, -292(%ebp)
0x00401634:	movw 0x10(%ecx), %ax
0x00401638:	movl %edx, -292(%ebp)
0x0040163e:	movl (%edx), $0x50010000<UINT32>
0x00401644:	movl %eax, -292(%ebp)
0x0040164a:	addl %eax, $0x12<UINT8>
0x0040164d:	movl -284(%ebp), %eax
0x00401653:	movl %ecx, $0xffff<UINT32>
0x00401658:	movl %edx, -284(%ebp)
0x0040165e:	movw (%edx), %cx
0x00401661:	movl %eax, -284(%ebp)
0x00401667:	addl %eax, $0x2<UINT8>
0x0040166a:	movl -284(%ebp), %eax
0x00401670:	movl %ecx, $0x80<UINT32>
0x00401675:	movl %edx, -284(%ebp)
0x0040167b:	movw (%edx), %cx
0x0040167e:	movl %eax, -284(%ebp)
0x00401684:	addl %eax, $0x2<UINT8>
0x00401687:	movl -284(%ebp), %eax
0x0040168d:	pushl $0x439518<UINT32>
0x00401692:	movl %ecx, -284(%ebp)
0x00401698:	pushl %ecx
0x00401699:	call 0x00401c50
0x0040169e:	addl %esp, $0x8<UINT8>
0x004016a1:	movl %edx, -284(%ebp)
0x004016a7:	leal %eax, (%edx,%eax,2)
0x004016aa:	movl -284(%ebp), %eax
0x004016b0:	xorl %ecx, %ecx
0x004016b2:	movl %edx, -284(%ebp)
0x004016b8:	movw (%edx), %cx
0x004016bb:	movl %eax, -284(%ebp)
0x004016c1:	addl %eax, $0x2<UINT8>
0x004016c4:	movl -284(%ebp), %eax
0x004016ca:	movl %ecx, -288(%ebp)
0x004016d0:	movw %dx, 0x8(%ecx)
0x004016d4:	addw %dx, $0x1<UINT8>
0x004016d8:	movl %eax, -288(%ebp)
0x004016de:	movw 0x8(%eax), %dx
0x004016e2:	movl %ecx, -284(%ebp)
0x004016e8:	pushl %ecx
0x004016e9:	call 0x00401c40
0x004016ee:	addl %esp, $0x4<UINT8>
0x004016f1:	movl -292(%ebp), %eax
0x004016f7:	movl %edx, $0x7<UINT32>
0x004016fc:	movl %eax, -292(%ebp)
0x00401702:	movw 0x8(%eax), %dx
0x00401706:	movl %ecx, $0xe<UINT32>
0x0040170b:	movl %edx, -292(%ebp)
0x00401711:	movw 0xa(%edx), %cx
0x00401715:	movl %eax, $0x12a<UINT32>
0x0040171a:	movl %ecx, -292(%ebp)
0x00401720:	movw 0xc(%ecx), %ax
0x00401724:	movl %edx, $0x8c<UINT32>
0x00401729:	movl %eax, -292(%ebp)
0x0040172f:	movw 0xe(%eax), %dx
0x00401733:	movl %ecx, $0x1f4<UINT32>
0x00401738:	movl %edx, -292(%ebp)
0x0040173e:	movw 0x10(%edx), %cx
0x00401742:	movl %eax, -292(%ebp)
0x00401748:	movl (%eax), $0x50a11844<UINT32>
0x0040174e:	movl %ecx, -292(%ebp)
0x00401754:	addl %ecx, $0x12<UINT8>
0x00401757:	movl -284(%ebp), %ecx
0x0040175d:	pushl $0x439528<UINT32>
0x00401762:	movl %edx, -284(%ebp)
0x00401768:	pushl %edx
0x00401769:	call 0x00401c50
0x0040176e:	addl %esp, $0x8<UINT8>
0x00401771:	movl %ecx, -284(%ebp)
0x00401777:	leal %edx, (%ecx,%eax,2)
0x0040177a:	movl -284(%ebp), %edx
0x00401780:	pushl $0x43953c<UINT32>
0x00401785:	movl %eax, -284(%ebp)
0x0040178b:	pushl %eax
0x0040178c:	call 0x00401c50
0x00401791:	addl %esp, $0x8<UINT8>
0x00401794:	movl %ecx, -284(%ebp)
0x0040179a:	leal %edx, (%ecx,%eax,2)
0x0040179d:	movl -284(%ebp), %edx
0x004017a3:	xorl %eax, %eax
0x004017a5:	movl %ecx, -284(%ebp)
0x004017ab:	movw (%ecx), %ax
0x004017ae:	movl %edx, -284(%ebp)
0x004017b4:	addl %edx, $0x2<UINT8>
0x004017b7:	movl -284(%ebp), %edx
0x004017bd:	movl %eax, -288(%ebp)
0x004017c3:	movw %cx, 0x8(%eax)
0x004017c7:	addw %cx, $0x1<UINT8>
0x004017cb:	movl %edx, -288(%ebp)
0x004017d1:	movw 0x8(%edx), %cx
0x004017d5:	movl %eax, 0x8(%ebp)
0x004017d8:	pushl %eax
0x004017d9:	pushl $0x401840<UINT32>
0x004017de:	pushl $0x0<UINT8>
0x004017e0:	movl %ecx, -288(%ebp)
0x004017e6:	pushl %ecx
0x004017e7:	pushl $0x0<UINT8>
0x004017e9:	call DialogBoxIndirectParamA@USER32.dll
DialogBoxIndirectParamA@USER32.dll: API Node	
0x004017ef:	movl 0xc(%ebp), %eax
0x004017f2:	movl %edx, -288(%ebp)
0x004017f8:	pushl %edx
0x004017f9:	call LocalFree@KERNEL32.DLL
LocalFree@KERNEL32.DLL: API Node	
0x004017ff:	cmpl 0xc(%ebp), $0x0<UINT8>
0x00401803:	je 25
