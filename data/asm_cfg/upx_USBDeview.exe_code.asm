0x00422c60:	pusha
0x00422c61:	movl %esi, $0x416000<UINT32>
0x00422c66:	leal %edi, -86016(%esi)
0x00422c6c:	pushl %edi
0x00422c6d:	jmp 0x00422c7a
0x00422c7a:	movl %ebx, (%esi)
0x00422c7c:	subl %esi, $0xfffffffc<UINT8>
0x00422c7f:	adcl %ebx, %ebx
0x00422c81:	jb 0x00422c70
0x00422c70:	movb %al, (%esi)
0x00422c72:	incl %esi
0x00422c73:	movb (%edi), %al
0x00422c75:	incl %edi
0x00422c76:	addl %ebx, %ebx
0x00422c78:	jne 0x00422c81
0x00422c83:	movl %eax, $0x1<UINT32>
0x00422c88:	addl %ebx, %ebx
0x00422c8a:	jne 0x00422c93
0x00422c93:	adcl %eax, %eax
0x00422c95:	addl %ebx, %ebx
0x00422c97:	jae 0x00422c88
0x00422c99:	jne 0x00422ca4
0x00422ca4:	xorl %ecx, %ecx
0x00422ca6:	subl %eax, $0x3<UINT8>
0x00422ca9:	jb 0x00422cb8
0x00422cab:	shll %eax, $0x8<UINT8>
0x00422cae:	movb %al, (%esi)
0x00422cb0:	incl %esi
0x00422cb1:	xorl %eax, $0xffffffff<UINT8>
0x00422cb4:	je 0x00422d2a
0x00422cb6:	movl %ebp, %eax
0x00422cb8:	addl %ebx, %ebx
0x00422cba:	jne 0x00422cc3
0x00422cc3:	adcl %ecx, %ecx
0x00422cc5:	addl %ebx, %ebx
0x00422cc7:	jne 0x00422cd0
0x00422cd0:	adcl %ecx, %ecx
0x00422cd2:	jne 0x00422cf4
0x00422cf4:	cmpl %ebp, $0xfffff300<UINT32>
0x00422cfa:	adcl %ecx, $0x1<UINT8>
0x00422cfd:	leal %edx, (%edi,%ebp)
0x00422d00:	cmpl %ebp, $0xfffffffc<UINT8>
0x00422d03:	jbe 0x00422d14
0x00422d14:	movl %eax, (%edx)
0x00422d16:	addl %edx, $0x4<UINT8>
0x00422d19:	movl (%edi), %eax
0x00422d1b:	addl %edi, $0x4<UINT8>
0x00422d1e:	subl %ecx, $0x4<UINT8>
0x00422d21:	ja 0x00422d14
0x00422d23:	addl %edi, %ecx
0x00422d25:	jmp 0x00422c76
0x00422cbc:	movl %ebx, (%esi)
0x00422cbe:	subl %esi, $0xfffffffc<UINT8>
0x00422cc1:	adcl %ebx, %ebx
0x00422cc9:	movl %ebx, (%esi)
0x00422ccb:	subl %esi, $0xfffffffc<UINT8>
0x00422cce:	adcl %ebx, %ebx
0x00422cd4:	incl %ecx
0x00422cd5:	addl %ebx, %ebx
0x00422cd7:	jne 0x00422ce0
0x00422ce0:	adcl %ecx, %ecx
0x00422ce2:	addl %ebx, %ebx
0x00422ce4:	jae 0x00422cd5
0x00422ce6:	jne 0x00422cf1
0x00422cf1:	addl %ecx, $0x2<UINT8>
0x00422c9b:	movl %ebx, (%esi)
0x00422c9d:	subl %esi, $0xfffffffc<UINT8>
0x00422ca0:	adcl %ebx, %ebx
0x00422ca2:	jae 0x00422c88
0x00422c8c:	movl %ebx, (%esi)
0x00422c8e:	subl %esi, $0xfffffffc<UINT8>
0x00422c91:	adcl %ebx, %ebx
0x00422ce8:	movl %ebx, (%esi)
0x00422cea:	subl %esi, $0xfffffffc<UINT8>
0x00422ced:	adcl %ebx, %ebx
0x00422cef:	jae 0x00422cd5
0x00422cd9:	movl %ebx, (%esi)
0x00422cdb:	subl %esi, $0xfffffffc<UINT8>
0x00422cde:	adcl %ebx, %ebx
0x00422d05:	movb %al, (%edx)
0x00422d07:	incl %edx
0x00422d08:	movb (%edi), %al
0x00422d0a:	incl %edi
0x00422d0b:	decl %ecx
0x00422d0c:	jne 0x00422d05
0x00422d0e:	jmp 0x00422c76
0x00422d2a:	popl %esi
0x00422d2b:	movl %edi, %esi
0x00422d2d:	movl %ecx, $0x868<UINT32>
0x00422d32:	movb %al, (%edi)
0x00422d34:	incl %edi
0x00422d35:	subb %al, $0xffffffe8<UINT8>
0x00422d37:	cmpb %al, $0x1<UINT8>
0x00422d39:	ja 0x00422d32
0x00422d3b:	cmpb (%edi), $0x2<UINT8>
0x00422d3e:	jne 0x00422d32
0x00422d40:	movl %eax, (%edi)
0x00422d42:	movb %bl, 0x4(%edi)
0x00422d45:	shrw %ax, $0x8<UINT8>
0x00422d49:	roll %eax, $0x10<UINT8>
0x00422d4c:	xchgb %ah, %al
0x00422d4e:	subl %eax, %edi
0x00422d50:	subb %bl, $0xffffffe8<UINT8>
0x00422d53:	addl %eax, %esi
0x00422d55:	movl (%edi), %eax
0x00422d57:	addl %edi, $0x5<UINT8>
0x00422d5a:	movb %al, %bl
0x00422d5c:	loop 0x00422d37
0x00422d5e:	leal %edi, 0x20000(%esi)
0x00422d64:	movl %eax, (%edi)
0x00422d66:	orl %eax, %eax
0x00422d68:	je 0x00422daf
0x00422d6a:	movl %ebx, 0x4(%edi)
0x00422d6d:	leal %eax, 0x23388(%eax,%esi)
0x00422d74:	addl %ebx, %esi
0x00422d76:	pushl %eax
0x00422d77:	addl %edi, $0x8<UINT8>
0x00422d7a:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00422d80:	xchgl %ebp, %eax
0x00422d81:	movb %al, (%edi)
0x00422d83:	incl %edi
0x00422d84:	orb %al, %al
0x00422d86:	je 0x00422d64
0x00422d88:	movl %ecx, %edi
0x00422d8a:	jns 0x00422d93
0x00422d93:	pushl %edi
0x00422d94:	decl %eax
0x00422d95:	repn scasb %al, %es:(%edi)
0x00422d97:	pushl %ebp
0x00422d98:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00422d9e:	orl %eax, %eax
0x00422da0:	je 7
0x00422da2:	movl (%ebx), %eax
0x00422da4:	addl %ebx, $0x4<UINT8>
0x00422da7:	jmp 0x00422d81
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x00422d8c:	movzwl %eax, (%edi)
0x00422d8f:	incl %edi
0x00422d90:	pushl %eax
0x00422d91:	incl %edi
0x00422d92:	movl %ecx, $0xaef24857<UINT32>
0x00422daf:	movl %ebp, 0x2347c(%esi)
0x00422db5:	leal %edi, -4096(%esi)
0x00422dbb:	movl %ebx, $0x1000<UINT32>
0x00422dc0:	pushl %eax
0x00422dc1:	pushl %esp
0x00422dc2:	pushl $0x4<UINT8>
0x00422dc4:	pushl %ebx
0x00422dc5:	pushl %edi
0x00422dc6:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00422dc8:	leal %eax, 0x20f(%edi)
0x00422dce:	andb (%eax), $0x7f<UINT8>
0x00422dd1:	andb 0x28(%eax), $0x7f<UINT8>
0x00422dd5:	popl %eax
0x00422dd6:	pushl %eax
0x00422dd7:	pushl %esp
0x00422dd8:	pushl %eax
0x00422dd9:	pushl %ebx
0x00422dda:	pushl %edi
0x00422ddb:	call VirtualProtect@kernel32.dll
0x00422ddd:	popl %eax
0x00422dde:	popa
0x00422ddf:	leal %eax, -128(%esp)
0x00422de3:	pushl $0x0<UINT8>
0x00422de5:	cmpl %esp, %eax
0x00422de7:	jne 0x00422de3
0x00422de9:	subl %esp, $0xffffff80<UINT8>
0x00422dec:	jmp 0x00413738
0x00413738:	pushl $0x70<UINT8>
0x0041373a:	pushl $0x414480<UINT32>
0x0041373f:	call 0x00413928
0x00413928:	pushl $0x413978<UINT32>
0x0041392d:	movl %eax, %fs:0
0x00413933:	pushl %eax
0x00413934:	movl %fs:0, %esp
0x0041393b:	movl %eax, 0x10(%esp)
0x0041393f:	movl 0x10(%esp), %ebp
0x00413943:	leal %ebp, 0x10(%esp)
0x00413947:	subl %esp, %eax
0x00413949:	pushl %ebx
0x0041394a:	pushl %esi
0x0041394b:	pushl %edi
0x0041394c:	movl %eax, -8(%ebp)
0x0041394f:	movl -24(%ebp), %esp
0x00413952:	pushl %eax
0x00413953:	movl %eax, -4(%ebp)
0x00413956:	movl -4(%ebp), $0xffffffff<UINT32>
0x0041395d:	movl -8(%ebp), %eax
0x00413960:	ret

0x00413744:	xorl %ebx, %ebx
0x00413746:	pushl %ebx
0x00413747:	movl %edi, 0x4140a8
0x0041374d:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x0041374f:	cmpw (%eax), $0x5a4d<UINT16>
0x00413754:	jne 31
0x00413756:	movl %ecx, 0x3c(%eax)
0x00413759:	addl %ecx, %eax
0x0041375b:	cmpl (%ecx), $0x4550<UINT32>
0x00413761:	jne 18
0x00413763:	movzwl %eax, 0x18(%ecx)
0x00413767:	cmpl %eax, $0x10b<UINT32>
0x0041376c:	je 0x0041378d
0x0041378d:	cmpl 0x74(%ecx), $0xe<UINT8>
0x00413791:	jbe -30
0x00413793:	xorl %eax, %eax
0x00413795:	cmpl 0xe8(%ecx), %ebx
0x0041379b:	setne %al
0x0041379e:	movl -28(%ebp), %eax
0x004137a1:	movl -4(%ebp), %ebx
0x004137a4:	pushl $0x2<UINT8>
0x004137a6:	call __set_app_type@msvcrt.dll
__set_app_type@msvcrt.dll: API Node	
0x004137ac:	popl %ecx
0x004137ad:	orl 0x419338, $0xffffffff<UINT8>
0x004137b4:	orl 0x41933c, $0xffffffff<UINT8>
0x004137bb:	call __p__fmode@msvcrt.dll
__p__fmode@msvcrt.dll: API Node	
0x004137c1:	movl %ecx, 0x4185fc
0x004137c7:	movl (%eax), %ecx
0x004137c9:	call __p__commode@msvcrt.dll
__p__commode@msvcrt.dll: API Node	
0x004137cf:	movl %ecx, 0x4185f8
0x004137d5:	movl (%eax), %ecx
0x004137d7:	movl %eax, 0x414340
0x004137dc:	movl %eax, (%eax)
0x004137de:	movl 0x419334, %eax
0x004137e3:	call 0x00413922
0x00413922:	xorl %eax, %eax
0x00413924:	ret

0x004137e8:	cmpl 0x418000, %ebx
0x004137ee:	jne 0x004137fc
0x004137fc:	call 0x00413910
0x00413910:	pushl $0x30000<UINT32>
0x00413915:	pushl $0x10000<UINT32>
0x0041391a:	call 0x00413972
0x00413972:	jmp _controlfp@msvcrt.dll
_controlfp@msvcrt.dll: API Node	
0x0041391f:	popl %ecx
0x00413920:	popl %ecx
0x00413921:	ret

0x00413801:	pushl $0x414450<UINT32>
0x00413806:	pushl $0x41444c<UINT32>
0x0041380b:	call 0x0041390a
0x0041390a:	jmp _initterm@msvcrt.dll
_initterm@msvcrt.dll: API Node	
0x00413810:	movl %eax, 0x4185f4
0x00413815:	movl -32(%ebp), %eax
0x00413818:	leal %eax, -32(%ebp)
0x0041381b:	pushl %eax
0x0041381c:	pushl 0x4185f0
0x00413822:	leal %eax, -36(%ebp)
0x00413825:	pushl %eax
0x00413826:	leal %eax, -40(%ebp)
0x00413829:	pushl %eax
0x0041382a:	leal %eax, -44(%ebp)
0x0041382d:	pushl %eax
0x0041382e:	call __getmainargs@msvcrt.dll
__getmainargs@msvcrt.dll: API Node	
0x00413834:	movl -48(%ebp), %eax
0x00413837:	pushl $0x414448<UINT32>
0x0041383c:	pushl $0x414418<UINT32>
0x00413841:	call 0x0041390a
0x00413846:	addl %esp, $0x24<UINT8>
0x00413849:	movl %eax, 0x414350
0x0041384e:	movl %esi, (%eax)
0x00413850:	movl -52(%ebp), %esi
0x00413853:	cmpb (%esi), $0x22<UINT8>
0x00413856:	jne 58
0x00413858:	incl %esi
0x00413859:	movl -52(%ebp), %esi
0x0041385c:	movb %al, (%esi)
0x0041385e:	cmpb %al, %bl
0x00413860:	je 4
0x00413862:	cmpb %al, $0x22<UINT8>
0x00413864:	jne 0x00413858
0x00413866:	cmpb (%esi), $0x22<UINT8>
0x00413869:	jne 4
0x0041386b:	incl %esi
0x0041386c:	movl -52(%ebp), %esi
0x0041386f:	movb %al, (%esi)
0x00413871:	cmpb %al, %bl
0x00413873:	je 4
0x00413875:	cmpb %al, $0x20<UINT8>
0x00413877:	jbe 0x0041386b
0x00413879:	movl -76(%ebp), %ebx
0x0041387c:	leal %eax, -120(%ebp)
0x0041387f:	pushl %eax
0x00413880:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x00413886:	testb -76(%ebp), $0x1<UINT8>
0x0041388a:	je 0x0041389d
0x0041389d:	pushl $0xa<UINT8>
0x0041389f:	popl %eax
0x004138a0:	pushl %eax
0x004138a1:	pushl %esi
0x004138a2:	pushl %ebx
0x004138a3:	pushl %ebx
0x004138a4:	call GetModuleHandleA@KERNEL32.DLL
0x004138a6:	pushl %eax
0x004138a7:	call 0x0040d4ec
0x0040d4ec:	pushl %ebp
0x0040d4ed:	movl %ebp, %esp
0x0040d4ef:	andl %esp, $0xfffffff8<UINT8>
0x0040d4f2:	subl %esp, $0xac4<UINT32>
0x0040d4f8:	pushl %ebx
0x0040d4f9:	pushl %esi
0x0040d4fa:	pushl %edi
0x0040d4fb:	call 0x0040ff7c
0x0040ff7c:	cmpl 0x418f98, $0x0<UINT8>
0x0040ff83:	jne 37
0x0040ff85:	pushl $0x415950<UINT32>
0x0040ff8a:	call LoadLibraryA@KERNEL32.DLL
0x0040ff90:	testl %eax, %eax
0x0040ff92:	movl 0x418f98, %eax
0x0040ff97:	je 17
0x0040ff99:	pushl $0x41595c<UINT32>
0x0040ff9e:	pushl %eax
0x0040ff9f:	call GetProcAddress@KERNEL32.DLL
0x0040ffa5:	movl 0x418f94, %eax
0x0040ffaa:	ret

0x0040d500:	xorl %esi, %esi
0x0040d502:	pushl $0x415320<UINT32>
0x0040d507:	leal %eax, 0x18(%esp)
0x0040d50b:	movl 0x18(%esp), %esi
0x0040d50f:	call 0x0040e90c
0x0040e90c:	pushl %ebp
0x0040e90d:	movl %ebp, %esp
0x0040e90f:	subl %esp, $0x20<UINT8>
0x0040e912:	pushl %ebx
0x0040e913:	pushl %esi
0x0040e914:	pushl %edi
0x0040e915:	movl %esi, %eax
0x0040e917:	call GetCurrentProcess@KERNEL32.DLL
GetCurrentProcess@KERNEL32.DLL: API Node	
0x0040e91d:	movl -12(%ebp), %eax
0x0040e920:	call 0x0040e8ec
0x0040e8ec:	cmpl (%esi), $0x0<UINT8>
0x0040e8ef:	jne 0x0040e908
0x0040e8f1:	pushl $0x4155b8<UINT32>
0x0040e8f6:	call LoadLibraryA@KERNEL32.DLL
0x0040e8fc:	xorl %ecx, %ecx
0x0040e8fe:	testl %eax, %eax
0x0040e900:	setne %cl
0x0040e903:	movl (%esi), %eax
0x0040e905:	movl %eax, %ecx
0x0040e907:	ret

0x0040e925:	testl %eax, %eax
0x0040e927:	je 36
0x0040e929:	movl %edi, 0x414114
0x0040e92f:	pushl $0x4155c8<UINT32>
0x0040e934:	pushl (%esi)
0x0040e936:	call GetProcAddress@KERNEL32.DLL
0x0040e938:	xorl %ebx, %ebx
0x0040e93a:	cmpl %eax, %ebx
0x0040e93c:	je 15
0x0040e93e:	leal %ecx, -8(%ebp)
0x0040e941:	pushl %ecx
0x0040e942:	pushl $0x28<UINT8>
0x0040e944:	pushl -12(%ebp)
0x0040e947:	call OpenProcessToken@advapi32.dll
OpenProcessToken@advapi32.dll: API Node	
0x0040e949:	cmpl %eax, %ebx
0x0040e94b:	jne 0x0040e955
0x0040e955:	call 0x0040e8ec
0x0040e908:	xorl %eax, %eax
0x0040e90a:	incl %eax
0x0040e90b:	ret

0x0040e95a:	testl %eax, %eax
0x0040e95c:	je 23
0x0040e95e:	pushl $0x4155dc<UINT32>
0x0040e963:	pushl (%esi)
0x0040e965:	call GetProcAddress@KERNEL32.DLL
0x0040e967:	cmpl %eax, %ebx
0x0040e969:	je 10
0x0040e96b:	leal %ecx, -24(%ebp)
0x0040e96e:	pushl %ecx
0x0040e96f:	pushl 0x8(%ebp)
0x0040e972:	pushl %ebx
0x0040e973:	call LookupPrivilegeValueA@advapi32.dll
LookupPrivilegeValueA@advapi32.dll: API Node	
0x0040e975:	movl %eax, -8(%ebp)
0x0040e978:	movl -28(%ebp), $0x1<UINT32>
0x0040e97f:	movl -16(%ebp), $0x2<UINT32>
0x0040e986:	movl 0x8(%ebp), %eax
0x0040e989:	call 0x0040e8ec
0x0040e98e:	testl %eax, %eax
0x0040e990:	je 26
0x0040e992:	pushl $0x4155f4<UINT32>
0x0040e997:	pushl (%esi)
0x0040e999:	call GetProcAddress@KERNEL32.DLL
0x0040e99b:	cmpl %eax, %ebx
0x0040e99d:	je 13
0x0040e99f:	pushl %ebx
0x0040e9a0:	pushl %ebx
0x0040e9a1:	pushl %ebx
0x0040e9a2:	leal %ecx, -28(%ebp)
0x0040e9a5:	pushl %ecx
0x0040e9a6:	pushl %ebx
0x0040e9a7:	pushl 0x8(%ebp)
0x0040e9aa:	call AdjustTokenPrivileges@advapi32.dll
AdjustTokenPrivileges@advapi32.dll: API Node	
0x0040e9ac:	call GetLastError@KERNEL32.DLL
GetLastError@KERNEL32.DLL: API Node	
0x0040e9b2:	pushl -8(%ebp)
0x0040e9b5:	movl %esi, %eax
0x0040e9b7:	call CloseHandle@KERNEL32.DLL
CloseHandle@KERNEL32.DLL: API Node	
0x0040e9bd:	movl %eax, %esi
0x0040e9bf:	popl %edi
0x0040e9c0:	popl %esi
0x0040e9c1:	popl %ebx
0x0040e9c2:	leave
0x0040e9c3:	ret $0x4<UINT16>

0x0040d514:	pushl $0x415338<UINT32>
0x0040d519:	leal %eax, 0x18(%esp)
0x0040d51d:	call 0x0040e90c
0x0040d522:	pushl $0x41534c<UINT32>
0x0040d527:	leal %eax, 0x18(%esp)
0x0040d52b:	call 0x0040e90c
0x0040d530:	pushl $0x8001<UINT32>
0x0040d535:	movl %edi, %eax
0x0040d537:	call SetErrorMode@KERNEL32.DLL
SetErrorMode@KERNEL32.DLL: API Node	
0x0040d53d:	leal %eax, 0x50(%esp)
0x0040d541:	call 0x004064db
0x004064db:	xorl %ecx, %ecx
0x004064dd:	movl 0x14(%eax), $0x400<UINT32>
0x004064e4:	movl 0x18(%eax), $0x100<UINT32>
0x004064eb:	movl (%eax), %ecx
0x004064ed:	movl 0x4(%eax), %ecx
0x004064f0:	movl 0xc(%eax), %ecx
0x004064f3:	movl 0x10(%eax), %ecx
0x004064f6:	movl 0x1c(%eax), %ecx
0x004064f9:	movl 0x8(%eax), %ecx
0x004064fc:	ret

0x0040d546:	leal %ebx, 0x2f0(%esp)
0x0040d54d:	movl 0x78(%esp), $0x20<UINT32>
0x0040d555:	movl 0x70(%esp), %esi
0x0040d559:	movl 0x7c(%esp), %esi
0x0040d55d:	movl 0x74(%esp), %esi
0x0040d561:	movl 0x80(%esp), %esi
0x0040d568:	call 0x0040d0c9
0x0040d0c9:	movl (%ebx), $0x415490<UINT32>
0x0040d0cf:	pushl %ebp
0x0040d0d0:	xorl %ebp, %ebp
0x0040d0d2:	movl 0x140(%ebx), %ebp
0x0040d0d8:	leal %eax, 0x174(%ebx)
0x0040d0de:	movl (%eax), $0x415aec<UINT32>
0x0040d0e4:	movl 0x4(%eax), %ebp
0x0040d0e7:	movl 0x8(%eax), %ebp
0x0040d0ea:	movl 0x10(%eax), %ebp
0x0040d0ed:	movl 0x19c(%ebx), %ebp
0x0040d0f3:	leal %eax, 0x3c0(%ebx)
0x0040d0f9:	pushl %esi
0x0040d0fa:	movl 0x3ac(%ebx), %ebp
0x0040d100:	pushl %edi
0x0040d101:	pushl $0xbc0<UINT32>
0x0040d106:	movl 0xc(%eax), %ebp
0x0040d109:	movl (%eax), %ebp
0x0040d10b:	movl 0x4(%eax), %ebp
0x0040d10e:	movl 0x10(%eax), $0x100<UINT32>
0x0040d115:	movl 0x8(%eax), %ebp
0x0040d118:	call 0x0041369c
0x0041369c:	jmp ??2@YAPAXI@Z@msvcrt.dll
??2@YAPAXI@Z@msvcrt.dll: API Node	
0x0040d11d:	cmpl %eax, %ebp
0x0040d11f:	popl %ecx
0x0040d120:	je 9
0x0040d122:	movl %esi, %eax
0x0040d124:	call 0x00401dda
0x00401dda:	pushl %ebx
0x00401ddb:	xorl %ebx, %ebx
0x00401ddd:	pushl $0x3c<UINT8>
0x00401ddf:	leal %eax, 0xb80(%esi)
0x00401de5:	pushl %ebx
0x00401de6:	pushl %eax
0x00401de7:	movl 0x418b78, %esi
0x00401ded:	movb 0x864(%esi), %bl
0x00401df3:	movb 0x969(%esi), %bl
0x00401df9:	movb 0xa6e(%esi), %bl
0x00401dff:	movl 0xb78(%esi), %ebx
0x00401e05:	movl 0xb74(%esi), $0x1<UINT32>
0x00401e0f:	call 0x00413672
0x00413672:	jmp memset@msvcrt.dll
memset@msvcrt.dll: API Node	
0x00401e14:	addl %esp, $0xc<UINT8>
0x00401e17:	movl 0xbbc(%esi), %ebx
0x00401e1d:	movl 0x58(%esi), $0x64<UINT32>
0x00401e24:	movl %eax, %esi
0x00401e26:	popl %ebx
0x00401e27:	ret

0x0018fed8:	jl -1
0x0018feda:	sbbb (%eax), %al
0x0018fedc:	lodsb %al, %ds:(%esi)
0x0018fedd:	cmpb (%ecx), %al
0x0018fee0:	addb (%eax), %al
0x0018fee2:	incl %eax
0x0018fee3:	addb (%eax), %al
0x0018fee5:	addb (%eax), %al
0x0018fee7:	addb 0x33(%esi), %bl
0x0018feea:	subb %al, (%eax)
0x0018feec:	orb %al, (%eax)
0x0018feee:	addb (%eax), %al
0x00413978:	jmp _except_handler3@msvcrt.dll
_except_handler3@msvcrt.dll: API Node	
0x7c9032a8:	addb (%eax), %al
0x7c9032aa:	addb (%eax), %al
0x7c9032ac:	addb (%eax), %al
0x7c9032ae:	addb (%eax), %al
0x7c9032b0:	addb (%eax), %al
0x7c9032b2:	addb (%eax), %al
0x7c9032b4:	addb (%eax), %al
0x7c9032b6:	addb (%eax), %al
0x7c9032b8:	addb (%eax), %al
0x7c9032ba:	addb (%eax), %al
0x7c9032bc:	addb (%eax), %al
0x7c9032be:	addb (%eax), %al
0x7c9032c0:	addb (%eax), %al
0x7c9032c2:	addb (%eax), %al
0x7c9032c4:	addb (%eax), %al
0x7c9032c6:	addb (%eax), %al
0x7c9032c8:	addb (%eax), %al
0x7c9032ca:	addb (%eax), %al
0x7c9032cc:	addb (%eax), %al
0x7c9032ce:	addb (%eax), %al
0x7c9032d0:	addb (%eax), %al
0x7c9032d2:	addb (%eax), %al
0x7c9032d4:	addb (%eax), %al
0x7c9032d6:	addb (%eax), %al
0x7c9032d8:	addb (%eax), %al
0x7c9032da:	addb (%eax), %al
0x7c9032dc:	addb (%eax), %al
0x7c9032de:	addb (%eax), %al
0x7c9032e0:	addb (%eax), %al
0x7c9032e2:	addb (%eax), %al
0x7c9032e4:	addb (%eax), %al
0x7c9032e6:	addb (%eax), %al
0x7c9032e8:	addb (%eax), %al
0x7c9032ea:	addb (%eax), %al
0x7c9032ec:	addb (%eax), %al
0x7c9032ee:	addb (%eax), %al
0x7c9032f0:	addb (%eax), %al
0x7c9032f2:	addb (%eax), %al
0x7c9032f4:	addb (%eax), %al
0x7c9032f6:	addb (%eax), %al
0x7c9032f8:	addb (%eax), %al
0x7c9032fa:	addb (%eax), %al
0x7c9032fc:	addb (%eax), %al
0x7c9032fe:	addb (%eax), %al
0x7c903300:	addb (%eax), %al
0x7c903302:	addb (%eax), %al
0x7c903304:	addb (%eax), %al
0x7c903306:	addb (%eax), %al
