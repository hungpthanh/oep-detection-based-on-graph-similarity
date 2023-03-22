0x0104f860:	pusha
0x0104f861:	movl %esi, $0x100d000<UINT32>
0x0104f866:	leal %edi, -49152(%esi)
0x0104f86c:	pushl %edi
0x0104f86d:	jmp 0x0104f87a
0x0104f87a:	movl %ebx, (%esi)
0x0104f87c:	subl %esi, $0xfffffffc<UINT8>
0x0104f87f:	adcl %ebx, %ebx
0x0104f881:	jb 0x0104f870
0x0104f870:	movb %al, (%esi)
0x0104f872:	incl %esi
0x0104f873:	movb (%edi), %al
0x0104f875:	incl %edi
0x0104f876:	addl %ebx, %ebx
0x0104f878:	jne 0x0104f881
0x0104f883:	movl %eax, $0x1<UINT32>
0x0104f888:	addl %ebx, %ebx
0x0104f88a:	jne 0x0104f893
0x0104f893:	adcl %eax, %eax
0x0104f895:	addl %ebx, %ebx
0x0104f897:	jae 0x0104f8a4
0x0104f899:	jne 0x0104f8c3
0x0104f8c3:	xorl %ecx, %ecx
0x0104f8c5:	subl %eax, $0x3<UINT8>
0x0104f8c8:	jb 0x0104f8db
0x0104f8ca:	shll %eax, $0x8<UINT8>
0x0104f8cd:	movb %al, (%esi)
0x0104f8cf:	incl %esi
0x0104f8d0:	xorl %eax, $0xffffffff<UINT8>
0x0104f8d3:	je 0x0104f94a
0x0104f8d5:	sarl %eax
0x0104f8d7:	movl %ebp, %eax
0x0104f8d9:	jmp 0x0104f8e6
0x0104f8e6:	jb 0x0104f8b4
0x0104f8b4:	addl %ebx, %ebx
0x0104f8b6:	jne 0x0104f8bf
0x0104f8bf:	adcl %ecx, %ecx
0x0104f8c1:	jmp 0x0104f915
0x0104f915:	cmpl %ebp, $0xfffffb00<UINT32>
0x0104f91b:	adcl %ecx, $0x2<UINT8>
0x0104f91e:	leal %edx, (%edi,%ebp)
0x0104f921:	cmpl %ebp, $0xfffffffc<UINT8>
0x0104f924:	jbe 0x0104f934
0x0104f934:	movl %eax, (%edx)
0x0104f936:	addl %edx, $0x4<UINT8>
0x0104f939:	movl (%edi), %eax
0x0104f93b:	addl %edi, $0x4<UINT8>
0x0104f93e:	subl %ecx, $0x4<UINT8>
0x0104f941:	ja 0x0104f934
0x0104f943:	addl %edi, %ecx
0x0104f945:	jmp 0x0104f876
0x0104f8db:	addl %ebx, %ebx
0x0104f8dd:	jne 0x0104f8e6
0x0104f8b8:	movl %ebx, (%esi)
0x0104f8ba:	subl %esi, $0xfffffffc<UINT8>
0x0104f8bd:	adcl %ebx, %ebx
0x0104f8e8:	incl %ecx
0x0104f8e9:	addl %ebx, %ebx
0x0104f8eb:	jne 0x0104f8f4
0x0104f8f4:	jb 0x0104f8b4
0x0104f926:	movb %al, (%edx)
0x0104f928:	incl %edx
0x0104f929:	movb (%edi), %al
0x0104f92b:	incl %edi
0x0104f92c:	decl %ecx
0x0104f92d:	jne 0x0104f926
0x0104f92f:	jmp 0x0104f876
0x0104f8ed:	movl %ebx, (%esi)
0x0104f8ef:	subl %esi, $0xfffffffc<UINT8>
0x0104f8f2:	adcl %ebx, %ebx
0x0104f8f6:	addl %ebx, %ebx
0x0104f8f8:	jne 0x0104f901
0x0104f901:	adcl %ecx, %ecx
0x0104f903:	addl %ebx, %ebx
0x0104f905:	jae 0x0104f8f6
0x0104f907:	jne 0x0104f912
0x0104f912:	addl %ecx, $0x2<UINT8>
0x0104f89b:	movl %ebx, (%esi)
0x0104f89d:	subl %esi, $0xfffffffc<UINT8>
0x0104f8a0:	adcl %ebx, %ebx
0x0104f8a2:	jb 0x0104f8c3
0x0104f88c:	movl %ebx, (%esi)
0x0104f88e:	subl %esi, $0xfffffffc<UINT8>
0x0104f891:	adcl %ebx, %ebx
0x0104f8df:	movl %ebx, (%esi)
0x0104f8e1:	subl %esi, $0xfffffffc<UINT8>
0x0104f8e4:	adcl %ebx, %ebx
0x0104f8a4:	decl %eax
0x0104f8a5:	addl %ebx, %ebx
0x0104f8a7:	jne 0x0104f8b0
0x0104f8b0:	adcl %eax, %eax
0x0104f8b2:	jmp 0x0104f888
0x0104f8a9:	movl %ebx, (%esi)
0x0104f8ab:	subl %esi, $0xfffffffc<UINT8>
0x0104f8ae:	adcl %ebx, %ebx
0x0104f909:	movl %ebx, (%esi)
0x0104f90b:	subl %esi, $0xfffffffc<UINT8>
0x0104f90e:	adcl %ebx, %ebx
0x0104f910:	jae 0x0104f8f6
0x0104f8fa:	movl %ebx, (%esi)
0x0104f8fc:	subl %esi, $0xfffffffc<UINT8>
0x0104f8ff:	adcl %ebx, %ebx
0x0104f94a:	popl %esi
0x0104f94b:	movl %edi, %esi
0x0104f94d:	movl %ecx, $0x1bc<UINT32>
0x0104f952:	movb %al, (%edi)
0x0104f954:	incl %edi
0x0104f955:	subb %al, $0xffffffe8<UINT8>
0x0104f957:	cmpb %al, $0x1<UINT8>
0x0104f959:	ja 0x0104f952
0x0104f95b:	cmpb (%edi), $0x7<UINT8>
0x0104f95e:	jne 0x0104f952
0x0104f960:	movl %eax, (%edi)
0x0104f962:	movb %bl, 0x4(%edi)
0x0104f965:	shrw %ax, $0x8<UINT8>
0x0104f969:	roll %eax, $0x10<UINT8>
0x0104f96c:	xchgb %ah, %al
0x0104f96e:	subl %eax, %edi
0x0104f970:	subb %bl, $0xffffffe8<UINT8>
0x0104f973:	addl %eax, %esi
0x0104f975:	movl (%edi), %eax
0x0104f977:	addl %edi, $0x5<UINT8>
0x0104f97a:	movb %al, %bl
0x0104f97c:	loop 0x0104f957
0x0104f97e:	leal %edi, 0x48000(%esi)
0x0104f984:	movl %eax, (%edi)
0x0104f986:	orl %eax, %eax
0x0104f988:	je 0x0104f9cf
0x0104f98a:	movl %ebx, 0x4(%edi)
0x0104f98d:	leal %eax, 0x4ff58(%eax,%esi)
0x0104f994:	addl %ebx, %esi
0x0104f996:	pushl %eax
0x0104f997:	addl %edi, $0x8<UINT8>
0x0104f99a:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x0104f9a0:	xchgl %ebp, %eax
0x0104f9a1:	movb %al, (%edi)
0x0104f9a3:	incl %edi
0x0104f9a4:	orb %al, %al
0x0104f9a6:	je 0x0104f984
0x0104f9a8:	movl %ecx, %edi
0x0104f9aa:	jns 0x0104f9b3
0x0104f9b3:	pushl %edi
0x0104f9b4:	decl %eax
0x0104f9b5:	repn scasb %al, %es:(%edi)
0x0104f9b7:	pushl %ebp
0x0104f9b8:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0104f9be:	orl %eax, %eax
0x0104f9c0:	je 7
0x0104f9c2:	movl (%ebx), %eax
0x0104f9c4:	addl %ebx, $0x4<UINT8>
0x0104f9c7:	jmp 0x0104f9a1
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x0104f9ac:	movzwl %eax, (%edi)
0x0104f9af:	incl %edi
0x0104f9b0:	pushl %eax
0x0104f9b1:	incl %edi
0x0104f9b2:	movl %ecx, $0xaef24857<UINT32>
0x0104f9cf:	movl %ebp, 0x50008(%esi)
0x0104f9d5:	leal %edi, -4096(%esi)
0x0104f9db:	movl %ebx, $0x1000<UINT32>
0x0104f9e0:	pushl %eax
0x0104f9e1:	pushl %esp
0x0104f9e2:	pushl $0x4<UINT8>
0x0104f9e4:	pushl %ebx
0x0104f9e5:	pushl %edi
0x0104f9e6:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0104f9e8:	leal %eax, 0x1e7(%edi)
0x0104f9ee:	andb (%eax), $0x7f<UINT8>
0x0104f9f1:	andb 0x28(%eax), $0x7f<UINT8>
0x0104f9f5:	popl %eax
0x0104f9f6:	pushl %eax
0x0104f9f7:	pushl %esp
0x0104f9f8:	pushl %eax
0x0104f9f9:	pushl %ebx
0x0104f9fa:	pushl %edi
0x0104f9fb:	call VirtualProtect@kernel32.dll
0x0104f9fd:	popl %eax
0x0104f9fe:	popa
0x0104f9ff:	leal %eax, -128(%esp)
0x0104fa03:	pushl $0x0<UINT8>
0x0104fa05:	cmpl %esp, %eax
0x0104fa07:	jne 0x0104fa03
0x0104fa09:	subl %esp, $0xffffff80<UINT8>
0x0104fa0c:	jmp 0x01005a5e
0x01005a5e:	pushl %ebp
0x01005a5f:	movl %ebp, %esp
0x01005a61:	subl %esp, $0x44<UINT8>
0x01005a64:	pushl %esi
0x01005a65:	call GetCommandLineA@KERNEL32.DLL
GetCommandLineA@KERNEL32.DLL: API Node	
0x01005a6b:	movl %esi, %eax
0x01005a6d:	movb %al, (%esi)
0x01005a6f:	cmpb %al, $0x22<UINT8>
0x01005a71:	jne 18
0x01005a73:	incl %esi
0x01005a74:	movb %al, (%esi)
0x01005a76:	testb %al, %al
0x01005a78:	je 4
0x01005a7a:	cmpb %al, $0x22<UINT8>
0x01005a7c:	jne 0x01005a73
0x01005a7e:	cmpb (%esi), $0x22<UINT8>
0x01005a81:	jne 19
0x01005a83:	jmp 0x01005a95
0x01005a95:	incl %esi
0x01005a96:	movb %al, (%esi)
0x01005a98:	testb %al, %al
0x01005a9a:	jne -11
0x01005a9c:	andl -24(%ebp), $0x0<UINT8>
0x01005aa0:	leal %eax, -68(%ebp)
0x01005aa3:	pushl %eax
0x01005aa4:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x01005aaa:	testb -24(%ebp), $0x1<UINT8>
0x01005aae:	je 0x01005ab6
0x01005ab6:	pushl $0xa<UINT8>
0x01005ab8:	popl %eax
0x01005ab9:	pushl %eax
0x01005aba:	pushl %esi
0x01005abb:	pushl $0x0<UINT8>
0x01005abd:	pushl $0x0<UINT8>
0x01005abf:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x01005ac5:	pushl %eax
0x01005ac6:	call 0x01005a00
0x01005a00:	pushl 0x10(%esp)
0x01005a04:	andl 0x100aa5c, $0x0<UINT8>
0x01005a0b:	pushl 0x10(%esp)
0x01005a0f:	pushl 0xc(%esp)
0x01005a13:	call 0x01004c18
0x01004c18:	pushl %ebp
0x01004c19:	movl %ebp, %esp
0x01004c1b:	subl %esp, $0x108<UINT32>
0x01004c21:	movl %eax, 0x8(%ebp)
0x01004c24:	pushl %ebx
0x01004c25:	pushl %esi
0x01004c26:	pushl %edi
0x01004c27:	movl 0x100b4a4, %eax
0x01004c2c:	xorl %eax, %eax
0x01004c2e:	movl %ecx, $0x23f<UINT32>
0x01004c33:	movl %edi, $0x100aba0<UINT32>
0x01004c38:	rep stosl %es:(%edi), %eax
0x01004c3a:	pushl $0x41<UINT8>
0x01004c3c:	movl %ecx, $0xcb<UINT32>
0x01004c41:	movl %edi, $0x100b880<UINT32>
0x01004c46:	rep stosl %es:(%edi), %eax
0x01004c48:	popl %ecx
0x01004c49:	movl %edi, $0x100aa80<UINT32>
0x01004c4e:	rep stosl %es:(%edi), %eax
0x01004c50:	pushl $0x7f<UINT8>
0x01004c52:	movl %esi, $0x100abb4<UINT32>
0x01004c57:	xorl %edi, %edi
0x01004c59:	pushl %esi
0x01004c5a:	xorl %ebx, %ebx
0x01004c5c:	incl %edi
0x01004c5d:	pushl $0x100142c<UINT32>
0x01004c62:	movl -4(%ebp), %ebx
0x01004c65:	movl 0x100ae4c, %edi
0x01004c6b:	call 0x01002a34
0x01002a34:	pushl %ebp
0x01002a35:	movl %ebp, %esp
0x01002a37:	pushl %ebx
0x01002a38:	pushl %esi
0x01002a39:	movl %esi, 0x10010e0
0x01002a3f:	pushl %edi
0x01002a40:	pushl $0xa<UINT8>
0x01002a42:	pushl 0x8(%ebp)
0x01002a45:	xorl %edi, %edi
0x01002a47:	pushl %edi
0x01002a48:	call FindResourceA@KERNEL32.DLL
FindResourceA@KERNEL32.DLL: API Node	
0x01002a4a:	pushl %eax
0x01002a4b:	pushl %edi
0x01002a4c:	call SizeofResource@KERNEL32.DLL
SizeofResource@KERNEL32.DLL: API Node	
0x01002a52:	movl %ebx, %eax
0x01002a54:	cmpl %ebx, 0x10(%ebp)
0x01002a57:	ja 68
0x01002a59:	cmpl 0xc(%ebp), %edi
0x01002a5c:	je 63
0x01002a5e:	cmpl %ebx, %edi
0x01002a60:	je 0x01002a7d
0x01002a7d:	xorl %eax, %eax
0x01002a7f:	jmp 0x01002a9f
0x01002a9f:	popl %edi
0x01002aa0:	popl %esi
0x01002aa1:	popl %ebx
0x01002aa2:	popl %ebp
0x01002aa3:	ret $0xc<UINT16>

0x01004c70:	cmpl %eax, %ebx
0x01004c72:	je 0x01004e3d
0x01004e3d:	pushl %ebx
0x01004e3e:	pushl $0x10<UINT8>
0x01004e40:	pushl %ebx
0x01004e41:	pushl %ebx
0x01004e42:	pushl $0x4b1<UINT32>
0x01004e47:	pushl %ebx
0x01004e48:	call 0x010038cc
0x010038cc:	pushl %ebp
0x010038cd:	movl %ebp, %esp
0x010038cf:	subl %esp, $0x238<UINT32>
0x010038d5:	testb 0x100b898, $0x1<UINT8>
0x010038dc:	pushl %esi
0x010038dd:	pushl %edi
0x010038de:	pushl $0xd<UINT8>
0x010038e0:	popl %ecx
0x010038e1:	movl %esi, $0x1001360<UINT32>
0x010038e6:	leal %edi, -56(%ebp)
0x010038e9:	rep movsl %es:(%edi), %ds:(%esi)
0x010038eb:	movsb %es:(%edi), %ds:(%esi)
0x010038ec:	jne 383
0x010038f2:	pushl $0x200<UINT32>
0x010038f7:	leal %eax, -568(%ebp)
0x010038fd:	pushl %eax
0x010038fe:	pushl 0xc(%ebp)
0x01003901:	call 0x01002aa6
0x01002aa6:	pushl %esi
0x01002aa7:	movl %esi, 0xc(%esp)
0x01002aab:	testl %esi, %esi
0x01002aad:	je 24
0x01002aaf:	pushl 0x10(%esp)
0x01002ab3:	andb (%esi), $0x0<UINT8>
0x01002ab6:	pushl %esi
0x01002ab7:	pushl 0x10(%esp)
0x01002abb:	pushl 0x100b4a4
0x01002ac1:	call LoadStringA@USER32.dll
LoadStringA@USER32.dll: API Node	
0x01002ac7:	movl %eax, %esi
0x01002ac9:	popl %esi
0x01002aca:	ret $0xc<UINT16>

0x01003906:	cmpb -568(%ebp), $0x0<UINT8>
0x0100390d:	jne 69
0x0100390f:	call 0x01005d22
0x01005d22:	pushl %ebp
0x01005d23:	leal %ebp, -120(%esp)
0x01005d27:	subl %esp, $0xb0<UINT32>
0x01005d2d:	andl 0x74(%ebp), $0x0<UINT8>
0x01005d31:	cmpl 0x100a2cc, $0xfffffffe<UINT8>
0x01005d38:	movl 0x6c(%ebp), $0xc<UINT32>
0x01005d3f:	jne 196
0x01005d45:	andl 0x100a2cc, $0x0<UINT8>
0x01005d4c:	leal %eax, -56(%ebp)
0x01005d4f:	pushl %eax
0x01005d50:	movl -56(%ebp), $0x94<UINT32>
0x01005d57:	call GetVersionExA@KERNEL32.DLL
GetVersionExA@KERNEL32.DLL: API Node	
0x01005d5d:	testl %eax, %eax
0x01005d5f:	je 164
0x01005d65:	cmpl -40(%ebp), $0x1<UINT8>
0x01005d69:	jne 0x01005e09
0x01005e09:	movl %eax, 0x100a2cc
0x01005e0e:	addl %ebp, $0x78<UINT8>
0x01005e11:	leave
0x01005e12:	ret

0x01003914:	testl %eax, %eax
0x01003916:	je 0x01003932
0x01003932:	xorl %eax, %eax
0x01003934:	orl %eax, $0x10010<UINT32>
0x01003939:	pushl %eax
0x0100393a:	pushl $0x100abb4<UINT32>
0x0100393f:	leal %eax, -56(%ebp)
0x01003942:	pushl %eax
0x01003943:	pushl 0x8(%ebp)
0x01003946:	call MessageBoxA@USER32.dll
MessageBoxA@USER32.dll: API Node	
0x0100394c:	orl %eax, $0xffffffff<UINT8>
0x0100394f:	jmp 0x01003a74
0x01003a74:	popl %edi
0x01003a75:	popl %esi
0x01003a76:	leave
0x01003a77:	ret $0x18<UINT16>

0x01004e4d:	xorl %eax, %eax
0x01004e4f:	popl %edi
0x01004e50:	popl %esi
0x01004e51:	popl %ebx
0x01004e52:	leave
0x01004e53:	ret $0xc<UINT16>

0x01005a18:	testl %eax, %eax
0x01005a1a:	je 0x01005a46
0x01005a46:	movl %eax, 0x100aa54
0x01005a4b:	testl %eax, %eax
0x01005a4d:	je 0x01005a56
0x01005a56:	movl %eax, 0x100aa5c
0x01005a5b:	ret $0x10<UINT16>

0x01005acb:	pushl %eax
0x01005acc:	call ExitProcess@KERNEL32.DLL
ExitProcess@KERNEL32.DLL: Exit Node	
