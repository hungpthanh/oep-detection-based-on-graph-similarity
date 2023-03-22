0x00419030:	pusha
0x00419031:	movl %esi, $0x410000<UINT32>
0x00419036:	leal %edi, -61440(%esi)
0x0041903c:	pushl %edi
0x0041903d:	orl %ebp, $0xffffffff<UINT8>
0x00419040:	jmp 0x00419052
0x00419052:	movl %ebx, (%esi)
0x00419054:	subl %esi, $0xfffffffc<UINT8>
0x00419057:	adcl %ebx, %ebx
0x00419059:	jb 0x00419048
0x00419048:	movb %al, (%esi)
0x0041904a:	incl %esi
0x0041904b:	movb (%edi), %al
0x0041904d:	incl %edi
0x0041904e:	addl %ebx, %ebx
0x00419050:	jne 0x00419059
0x0041905b:	movl %eax, $0x1<UINT32>
0x00419060:	addl %ebx, %ebx
0x00419062:	jne 0x0041906b
0x0041906b:	adcl %eax, %eax
0x0041906d:	addl %ebx, %ebx
0x0041906f:	jae 0x00419060
0x00419071:	jne 0x0041907c
0x0041907c:	xorl %ecx, %ecx
0x0041907e:	subl %eax, $0x3<UINT8>
0x00419081:	jb 0x00419090
0x00419090:	addl %ebx, %ebx
0x00419092:	jne 0x0041909b
0x0041909b:	adcl %ecx, %ecx
0x0041909d:	addl %ebx, %ebx
0x0041909f:	jne 0x004190a8
0x004190a8:	adcl %ecx, %ecx
0x004190aa:	jne 0x004190cc
0x004190cc:	cmpl %ebp, $0xfffff300<UINT32>
0x004190d2:	adcl %ecx, $0x1<UINT8>
0x004190d5:	leal %edx, (%edi,%ebp)
0x004190d8:	cmpl %ebp, $0xfffffffc<UINT8>
0x004190db:	jbe 0x004190ec
0x004190dd:	movb %al, (%edx)
0x004190df:	incl %edx
0x004190e0:	movb (%edi), %al
0x004190e2:	incl %edi
0x004190e3:	decl %ecx
0x004190e4:	jne 0x004190dd
0x004190e6:	jmp 0x0041904e
0x00419083:	shll %eax, $0x8<UINT8>
0x00419086:	movb %al, (%esi)
0x00419088:	incl %esi
0x00419089:	xorl %eax, $0xffffffff<UINT8>
0x0041908c:	je 0x00419102
0x0041908e:	movl %ebp, %eax
0x004190ec:	movl %eax, (%edx)
0x004190ee:	addl %edx, $0x4<UINT8>
0x004190f1:	movl (%edi), %eax
0x004190f3:	addl %edi, $0x4<UINT8>
0x004190f6:	subl %ecx, $0x4<UINT8>
0x004190f9:	ja 0x004190ec
0x004190fb:	addl %edi, %ecx
0x004190fd:	jmp 0x0041904e
0x004190a1:	movl %ebx, (%esi)
0x004190a3:	subl %esi, $0xfffffffc<UINT8>
0x004190a6:	adcl %ebx, %ebx
0x00419094:	movl %ebx, (%esi)
0x00419096:	subl %esi, $0xfffffffc<UINT8>
0x00419099:	adcl %ebx, %ebx
0x004190ac:	incl %ecx
0x004190ad:	addl %ebx, %ebx
0x004190af:	jne 0x004190b8
0x004190b8:	adcl %ecx, %ecx
0x004190ba:	addl %ebx, %ebx
0x004190bc:	jae 0x004190ad
0x004190be:	jne 0x004190c9
0x004190c9:	addl %ecx, $0x2<UINT8>
0x00419064:	movl %ebx, (%esi)
0x00419066:	subl %esi, $0xfffffffc<UINT8>
0x00419069:	adcl %ebx, %ebx
0x00419073:	movl %ebx, (%esi)
0x00419075:	subl %esi, $0xfffffffc<UINT8>
0x00419078:	adcl %ebx, %ebx
0x0041907a:	jae 0x00419060
0x004190c0:	movl %ebx, (%esi)
0x004190c2:	subl %esi, $0xfffffffc<UINT8>
0x004190c5:	adcl %ebx, %ebx
0x004190c7:	jae 0x004190ad
0x004190b1:	movl %ebx, (%esi)
0x004190b3:	subl %esi, $0xfffffffc<UINT8>
0x004190b6:	adcl %ebx, %ebx
0x00419102:	popl %esi
0x00419103:	movl %edi, %esi
0x00419105:	movl %ecx, $0x487<UINT32>
0x0041910a:	movb %al, (%edi)
0x0041910c:	incl %edi
0x0041910d:	subb %al, $0xffffffe8<UINT8>
0x0041910f:	cmpb %al, $0x1<UINT8>
0x00419111:	ja 0x0041910a
0x00419113:	cmpb (%edi), $0x5<UINT8>
0x00419116:	jne 0x0041910a
0x00419118:	movl %eax, (%edi)
0x0041911a:	movb %bl, 0x4(%edi)
0x0041911d:	shrw %ax, $0x8<UINT8>
0x00419121:	roll %eax, $0x10<UINT8>
0x00419124:	xchgb %ah, %al
0x00419126:	subl %eax, %edi
0x00419128:	subb %bl, $0xffffffe8<UINT8>
0x0041912b:	addl %eax, %esi
0x0041912d:	movl (%edi), %eax
0x0041912f:	addl %edi, $0x5<UINT8>
0x00419132:	movb %al, %bl
0x00419134:	loop 0x0041910f
0x00419136:	leal %edi, 0x17000(%esi)
0x0041913c:	movl %eax, (%edi)
0x0041913e:	orl %eax, %eax
0x00419140:	je 0x00419187
0x00419142:	movl %ebx, 0x4(%edi)
0x00419145:	leal %eax, 0x1a0e4(%eax,%esi)
0x0041914c:	addl %ebx, %esi
0x0041914e:	pushl %eax
0x0041914f:	addl %edi, $0x8<UINT8>
0x00419152:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00419158:	xchgl %ebp, %eax
0x00419159:	movb %al, (%edi)
0x0041915b:	incl %edi
0x0041915c:	orb %al, %al
0x0041915e:	je 0x0041913c
0x00419160:	movl %ecx, %edi
0x00419162:	jns 0x0041916b
0x0041916b:	pushl %edi
0x0041916c:	decl %eax
0x0041916d:	repn scasb %al, %es:(%edi)
0x0041916f:	pushl %ebp
0x00419170:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00419176:	orl %eax, %eax
0x00419178:	je 7
0x0041917a:	movl (%ebx), %eax
0x0041917c:	addl %ebx, $0x4<UINT8>
0x0041917f:	jmp 0x00419159
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x00419164:	movzwl %eax, (%edi)
0x00419167:	incl %edi
0x00419168:	pushl %eax
0x00419169:	incl %edi
0x0041916a:	movl %ecx, $0xaef24857<UINT32>
0x00419187:	movl %ebp, 0x1a1ec(%esi)
0x0041918d:	leal %edi, -4096(%esi)
0x00419193:	movl %ebx, $0x1000<UINT32>
0x00419198:	pushl %eax
0x00419199:	pushl %esp
0x0041919a:	pushl $0x4<UINT8>
0x0041919c:	pushl %ebx
0x0041919d:	pushl %edi
0x0041919e:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x004191a0:	leal %eax, 0x20f(%edi)
0x004191a6:	andb (%eax), $0x7f<UINT8>
0x004191a9:	andb 0x28(%eax), $0x7f<UINT8>
0x004191ad:	popl %eax
0x004191ae:	pushl %eax
0x004191af:	pushl %esp
0x004191b0:	pushl %eax
0x004191b1:	pushl %ebx
0x004191b2:	pushl %edi
0x004191b3:	call VirtualProtect@kernel32.dll
0x004191b5:	popl %eax
0x004191b6:	popa
0x004191b7:	leal %eax, -128(%esp)
0x004191bb:	pushl $0x0<UINT8>
0x004191bd:	cmpl %esp, %eax
0x004191bf:	jne 0x004191bb
0x004191c1:	subl %esp, $0xffffff80<UINT8>
0x004191c4:	jmp 0x00403ba0
0x00403ba0:	call 0x00407acc
0x00407acc:	pushl %ebp
0x00407acd:	movl %ebp, %esp
0x00407acf:	subl %esp, $0x10<UINT8>
0x00407ad2:	movl %eax, 0x413004
0x00407ad7:	andl -8(%ebp), $0x0<UINT8>
0x00407adb:	andl -4(%ebp), $0x0<UINT8>
0x00407adf:	pushl %ebx
0x00407ae0:	pushl %edi
0x00407ae1:	movl %edi, $0xbb40e64e<UINT32>
0x00407ae6:	cmpl %eax, %edi
0x00407ae8:	movl %ebx, $0xffff0000<UINT32>
0x00407aed:	je 0x00407afc
0x00407afc:	pushl %esi
0x00407afd:	leal %eax, -8(%ebp)
0x00407b00:	pushl %eax
0x00407b01:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x00407b07:	movl %esi, -4(%ebp)
0x00407b0a:	xorl %esi, -8(%ebp)
0x00407b0d:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x00407b13:	xorl %esi, %eax
0x00407b15:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x00407b1b:	xorl %esi, %eax
0x00407b1d:	call GetTickCount@KERNEL32.DLL
GetTickCount@KERNEL32.DLL: API Node	
0x00407b23:	xorl %esi, %eax
0x00407b25:	leal %eax, -16(%ebp)
0x00407b28:	pushl %eax
0x00407b29:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x00407b2f:	movl %eax, -12(%ebp)
0x00407b32:	xorl %eax, -16(%ebp)
0x00407b35:	xorl %esi, %eax
0x00407b37:	cmpl %esi, %edi
0x00407b39:	jne 0x00407b42
0x00407b42:	testl %ebx, %esi
0x00407b44:	jne 0x00407b4d
0x00407b4d:	movl 0x413004, %esi
0x00407b53:	notl %esi
0x00407b55:	movl 0x413008, %esi
0x00407b5b:	popl %esi
0x00407b5c:	popl %edi
0x00407b5d:	popl %ebx
0x00407b5e:	leave
0x00407b5f:	ret

0x00403ba5:	jmp 0x004039c0
0x004039c0:	pushl $0x60<UINT8>
0x004039c2:	pushl $0x4119f0<UINT32>
0x004039c7:	call 0x00404a88
0x00404a88:	pushl $0x404af0<UINT32>
0x00404a8d:	pushl %fs:0
0x00404a94:	movl %eax, 0x10(%esp)
0x00404a98:	movl 0x10(%esp), %ebp
0x00404a9c:	leal %ebp, 0x10(%esp)
0x00404aa0:	subl %esp, %eax
0x00404aa2:	pushl %ebx
0x00404aa3:	pushl %esi
0x00404aa4:	pushl %edi
0x00404aa5:	movl %eax, 0x413004
0x00404aaa:	xorl -4(%ebp), %eax
0x00404aad:	xorl %eax, %ebp
0x00404aaf:	pushl %eax
0x00404ab0:	movl -24(%ebp), %esp
0x00404ab3:	pushl -8(%ebp)
0x00404ab6:	movl %eax, -4(%ebp)
0x00404ab9:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00404ac0:	movl -8(%ebp), %eax
0x00404ac3:	leal %eax, -16(%ebp)
0x00404ac6:	movl %fs:0, %eax
0x00404acc:	ret

0x004039cc:	andl -4(%ebp), $0x0<UINT8>
0x004039d0:	leal %eax, -112(%ebp)
0x004039d3:	pushl %eax
0x004039d4:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x004039da:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004039e1:	movl %edi, $0x94<UINT32>
0x004039e6:	pushl %edi
0x004039e7:	pushl $0x0<UINT8>
0x004039e9:	movl %ebx, 0x40d138
0x004039ef:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x004039f1:	pushl %eax
0x004039f2:	call HeapAlloc@KERNEL32.DLL
HeapAlloc@KERNEL32.DLL: API Node	
0x004039f8:	movl %esi, %eax
0x004039fa:	testl %esi, %esi
0x004039fc:	jne 0x00403a0b
0x00403a0b:	movl (%esi), %edi
0x00403a0d:	pushl %esi
0x00403a0e:	call GetVersionExA@KERNEL32.DLL
GetVersionExA@KERNEL32.DLL: API Node	
0x00403a14:	pushl %esi
0x00403a15:	pushl $0x0<UINT8>
0x00403a17:	testl %eax, %eax
0x00403a19:	jne 0x00403a29
0x00403a29:	movl %eax, 0x10(%esi)
0x00403a2c:	movl -32(%ebp), %eax
0x00403a2f:	movl %eax, 0x4(%esi)
0x00403a32:	movl -36(%ebp), %eax
0x00403a35:	movl %eax, 0x8(%esi)
0x00403a38:	movl -40(%ebp), %eax
0x00403a3b:	movl %edi, 0xc(%esi)
0x00403a3e:	andl %edi, $0x7fff<UINT32>
0x00403a44:	call GetProcessHeap@KERNEL32.DLL
0x00403a46:	pushl %eax
0x00403a47:	call HeapFree@KERNEL32.DLL
HeapFree@KERNEL32.DLL: API Node	
0x00403a4d:	movl %esi, -32(%ebp)
0x00403a50:	cmpl %esi, $0x2<UINT8>
0x00403a53:	je 0x00403a5b
0x00403a5b:	movl %ecx, -36(%ebp)
0x00403a5e:	movl %eax, %ecx
0x00403a60:	shll %eax, $0x8<UINT8>
0x00403a63:	movl %edx, -40(%ebp)
0x00403a66:	addl %eax, %edx
0x00403a68:	movl 0x414504, %esi
0x00403a6e:	movl 0x41450c, %eax
0x00403a73:	movl 0x414510, %ecx
0x00403a79:	movl 0x414514, %edx
0x00403a7f:	movl 0x414508, %edi
0x00403a85:	call 0x0040397f
0x0040397f:	cmpw 0x400000, $0x5a4d<UINT16>
0x00403988:	jne 51
0x0040398a:	movl %eax, 0x40003c
0x0040398f:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00403999:	jne 34
0x0040399b:	cmpw 0x400018(%eax), $0x10b<UINT16>
0x004039a4:	jne 23
0x004039a6:	cmpl 0x400074(%eax), $0xe<UINT8>
0x004039ad:	jbe 14
0x004039af:	xorl %ecx, %ecx
0x004039b1:	cmpl 0x4000e8(%eax), %ecx
0x004039b7:	setne %cl
0x004039ba:	movl %eax, %ecx
0x004039bc:	ret

0x00403a8a:	movl -32(%ebp), %eax
0x00403a8d:	xorl %ebx, %ebx
0x00403a8f:	incl %ebx
0x00403a90:	pushl %ebx
0x00403a91:	call 0x00403d88
0x00403d88:	xorl %eax, %eax
0x00403d8a:	cmpl 0x4(%esp), %eax
0x00403d8e:	pushl $0x0<UINT8>
0x00403d90:	sete %al
0x00403d93:	pushl $0x1000<UINT32>
0x00403d98:	pushl %eax
0x00403d99:	call HeapCreate@KERNEL32.DLL
HeapCreate@KERNEL32.DLL: API Node	
0x00403d9f:	testl %eax, %eax
0x00403da1:	movl 0x414354, %eax
0x00403da6:	jne 0x00403dab
0x00403dab:	call 0x00403d2d
0x00403d2d:	pushl %ebp
0x00403d2e:	movl %ebp, %esp
0x00403d30:	pushl %ecx
0x00403d31:	pushl %ecx
0x00403d32:	pushl %esi
0x00403d33:	leal %eax, -4(%ebp)
0x00403d36:	xorl %esi, %esi
0x00403d38:	pushl %eax
0x00403d39:	movl -4(%ebp), %esi
0x00403d3c:	movl -8(%ebp), %esi
0x00403d3f:	call 0x00406a72
0x00406a72:	movl %ecx, 0x4(%esp)
0x00406a76:	pushl %esi
0x00406a77:	xorl %esi, %esi
0x00406a79:	cmpl %ecx, %esi
0x00406a7b:	jne 0x00406a9a
0x00406a9a:	movl %eax, 0x414504
0x00406a9f:	cmpl %eax, %esi
0x00406aa1:	je -38
0x00406aa3:	movl (%ecx), %eax
0x00406aa5:	xorl %eax, %eax
0x00406aa7:	popl %esi
0x00406aa8:	ret

0x00403d44:	testl %eax, %eax
0x00403d46:	popl %ecx
0x00403d47:	je 0x00403d56
0x00403d56:	leal %eax, -8(%ebp)
0x00403d59:	pushl %eax
0x00403d5a:	call 0x00406aa9
0x00406aa9:	movl %eax, 0x4(%esp)
0x00406aad:	pushl %esi
0x00406aae:	xorl %esi, %esi
0x00406ab0:	cmpl %eax, %esi
0x00406ab2:	jne 0x00406ad1
0x00406ad1:	cmpl 0x414504, %esi
0x00406ad7:	je -37
0x00406ad9:	movl %ecx, 0x414510
0x00406adf:	movl (%eax), %ecx
0x00406ae1:	xorl %eax, %eax
0x00406ae3:	popl %esi
0x00406ae4:	ret

0x00403d5f:	testl %eax, %eax
0x00403d61:	popl %ecx
0x00403d62:	je 0x00403d71
0x00403d71:	cmpl -4(%ebp), $0x2<UINT8>
0x00403d75:	popl %esi
0x00403d76:	jne 11
0x00403d78:	cmpl -8(%ebp), $0x5<UINT8>
0x00403d7c:	jb 5
0x00403d7e:	xorl %eax, %eax
0x00403d80:	incl %eax
0x00403d81:	leave
0x00403d82:	ret

0x00403db0:	cmpl %eax, $0x3<UINT8>
0x00403db3:	movl 0x415c14, %eax
0x00403db8:	jne 0x00403dde
0x00403dde:	xorl %eax, %eax
0x00403de0:	incl %eax
0x00403de1:	ret

0x00403a96:	popl %ecx
0x00403a97:	testl %eax, %eax
0x00403a99:	jne 0x00403aa3
0x00403aa3:	call 0x00406798
0x00406798:	pushl %edi
0x00406799:	pushl $0x40d3b0<UINT32>
0x0040679e:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x004067a4:	movl %edi, %eax
0x004067a6:	testl %edi, %edi
0x004067a8:	jne 0x004067b3
0x004067b3:	pushl %esi
0x004067b4:	movl %esi, 0x40d0b8
0x004067ba:	pushl $0x40d3f0<UINT32>
0x004067bf:	pushl %edi
0x004067c0:	call GetProcAddress@KERNEL32.DLL
0x004067c2:	pushl $0x40d3e4<UINT32>
0x004067c7:	pushl %edi
0x004067c8:	movl 0x4144f0, %eax
0x004067cd:	call GetProcAddress@KERNEL32.DLL
0x004067cf:	pushl $0x40d3d8<UINT32>
0x004067d4:	pushl %edi
0x004067d5:	movl 0x4144f4, %eax
0x004067da:	call GetProcAddress@KERNEL32.DLL
0x004067dc:	pushl $0x40d3d0<UINT32>
0x004067e1:	pushl %edi
0x004067e2:	movl 0x4144f8, %eax
0x004067e7:	call GetProcAddress@KERNEL32.DLL
0x004067e9:	cmpl 0x4144f0, $0x0<UINT8>
0x004067f0:	movl %esi, 0x40d194
0x004067f6:	movl 0x4144fc, %eax
0x004067fb:	je 22
0x004067fd:	cmpl 0x4144f4, $0x0<UINT8>
0x00406804:	je 13
0x00406806:	cmpl 0x4144f8, $0x0<UINT8>
0x0040680d:	je 4
0x0040680f:	testl %eax, %eax
0x00406811:	jne 0x00406837
0x00406837:	call TlsAlloc@KERNEL32.DLL
TlsAlloc@KERNEL32.DLL: API Node	
0x0040683d:	cmpl %eax, $0xffffffff<UINT8>
0x00406840:	movl 0x4138c4, %eax
0x00406845:	je 204
0x0040684b:	pushl 0x4144f4
0x00406851:	pushl %eax
0x00406852:	call TlsSetValue@KERNEL32.DLL
TlsSetValue@KERNEL32.DLL: API Node	
0x00406854:	testl %eax, %eax
0x00406856:	je 187
0x0040685c:	call 0x00406c99
0x00406c99:	pushl %esi
0x00406c9a:	call 0x0040643a
0x0040643a:	pushl $0x0<UINT8>
0x0040643c:	call 0x004063cc
0x004063cc:	pushl %esi
0x004063cd:	pushl 0x4138c4
0x004063d3:	movl %esi, 0x40d18c
0x004063d9:	call TlsGetValue@KERNEL32.DLL
TlsGetValue@KERNEL32.DLL: API Node	
0x004063db:	testl %eax, %eax
0x004063dd:	je 33
0x004063df:	movl %eax, 0x4138c0
0x004063e4:	cmpl %eax, $0xffffffff<UINT8>
0x004063e7:	je 0x00406400
0x00406400:	pushl $0x40d3b0<UINT32>
0x00406405:	call GetModuleHandleA@KERNEL32.DLL
0x0040640b:	movl %esi, %eax
0x0040640d:	testl %esi, %esi
0x0040640f:	je 35
0x00406411:	call 0x00406360
0x00406360:	pushl %ebp
0x00406361:	movl %ebp, %esp
0x00406363:	pushl %ecx
0x00406364:	pushl %ecx
0x00406365:	pushl %ebx
0x00406366:	pushl %esi
0x00406367:	xorl %esi, %esi
0x00406369:	leal %eax, -4(%ebp)
0x0040636c:	incl %esi
0x0040636d:	xorl %ebx, %ebx
0x0040636f:	pushl %eax
0x00406370:	movl -8(%ebp), %esi
0x00406373:	movl -4(%ebp), %ebx
0x00406376:	call 0x00406aa9
0x0040637b:	cmpl -4(%ebp), $0x5<UINT8>
0x0040637f:	popl %ecx
0x00406380:	jle 4
0x00406382:	movl %eax, %esi
0x00406384:	jmp 0x004063c8
0x004063c8:	popl %esi
0x004063c9:	popl %ebx
0x004063ca:	leave
0x004063cb:	ret

0x00406416:	testl %eax, %eax
0x00406418:	je 26
0x0040641a:	pushl $0x40d3a0<UINT32>
0x0040641f:	pushl %esi
0x00406420:	call GetProcAddress@KERNEL32.DLL
0x00406426:	testl %eax, %eax
0x00406428:	je 10
0x0040642a:	pushl 0x8(%esp)
0x0040642e:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00406430:	movl 0x8(%esp), %eax
0x00406434:	movl %eax, 0x8(%esp)
0x00406438:	popl %esi
0x00406439:	ret

0x00406441:	popl %ecx
0x00406442:	ret

0x00406c9f:	movl %esi, %eax
0x00406ca1:	pushl %esi
0x00406ca2:	call 0x00406ebe
0x00406ebe:	movl %eax, 0x4(%esp)
0x00406ec2:	movl 0x41485c, %eax
0x00406ec7:	ret

0x00406ca7:	pushl %esi
0x00406ca8:	call 0x00407b68
0x00407b68:	movl %eax, 0x4(%esp)
0x00407b6c:	movl 0x414974, %eax
0x00407b71:	ret

0x00406cad:	pushl %esi
0x00406cae:	call 0x004056f6
0x004056f6:	movl %eax, 0x4(%esp)
0x004056fa:	movl 0x4144ac, %eax
0x004056ff:	ret

0x00406cb3:	pushl %esi
0x00406cb4:	call 0x0040af16
0x0040af16:	movl %eax, 0x4(%esp)
0x0040af1a:	movl 0x4149b4, %eax
0x0040af1f:	ret

0x00406cb9:	pushl %esi
0x00406cba:	call 0x0040af0c
0x0040af0c:	movl %eax, 0x4(%esp)
0x0040af10:	movl 0x4149a8, %eax
0x0040af15:	ret

0x00406cbf:	pushl %esi
0x00406cc0:	call 0x0040ad02
0x0040ad02:	movl %eax, 0x4(%esp)
0x0040ad06:	movl 0x414994, %eax
0x0040ad0b:	movl 0x414998, %eax
0x0040ad10:	movl 0x41499c, %eax
0x0040ad15:	movl 0x4149a0, %eax
0x0040ad1a:	ret

0x00406cc5:	pushl %esi
0x00406cc6:	call 0x00407227
0x00407227:	ret

0x00406ccb:	pushl %esi
0x00406ccc:	call 0x0040acf1
0x0040acf1:	pushl $0x40acb8<UINT32>
0x0040acf6:	call 0x004063cc
0x0040acfb:	popl %ecx
0x0040acfc:	movl 0x414990, %eax
0x0040ad01:	ret

0x00406cd1:	pushl $0x406c6a<UINT32>
0x00406cd6:	call 0x004063cc
0x00406cdb:	addl %esp, $0x24<UINT8>
0x00406cde:	movl 0x4138c8, %eax
0x00406ce3:	popl %esi
0x00406ce4:	ret

0x00406861:	pushl 0x4144f0
0x00406867:	call 0x004063cc
0x0040686c:	pushl 0x4144f4
0x00406872:	movl 0x4144f0, %eax
0x00406877:	call 0x004063cc
0x0040687c:	pushl 0x4144f8
0x00406882:	movl 0x4144f4, %eax
0x00406887:	call 0x004063cc
0x0040688c:	pushl 0x4144fc
0x00406892:	movl 0x4144f8, %eax
0x00406897:	call 0x004063cc
0x0040689c:	addl %esp, $0x10<UINT8>
0x0040689f:	movl 0x4144fc, %eax
0x004068a4:	call 0x00403de2
0x00403de2:	pushl %esi
0x00403de3:	pushl %edi
0x00403de4:	xorl %esi, %esi
0x00403de6:	movl %edi, $0x414358<UINT32>
0x00403deb:	cmpl 0x41318c(,%esi,8), $0x1<UINT8>
0x00403df3:	jne 0x00403e13
0x00403df5:	leal %eax, 0x413188(,%esi,8)
0x00403dfc:	movl (%eax), %edi
0x00403dfe:	pushl $0xfa0<UINT32>
0x00403e03:	pushl (%eax)
0x00403e05:	addl %edi, $0x18<UINT8>
0x00403e08:	call 0x00407b82
0x00407b82:	pushl $0x14<UINT8>
0x00407b84:	pushl $0x411b20<UINT32>
0x00407b89:	call 0x00404a88
0x00407b8e:	xorl %edi, %edi
0x00407b90:	movl -28(%ebp), %edi
0x00407b93:	pushl 0x414974
0x00407b99:	call 0x00406443
0x00406443:	pushl %esi
0x00406444:	pushl 0x4138c4
0x0040644a:	movl %esi, 0x40d18c
0x00406450:	call TlsGetValue@KERNEL32.DLL
0x00406452:	testl %eax, %eax
0x00406454:	je 33
0x00406456:	movl %eax, 0x4138c0
0x0040645b:	cmpl %eax, $0xffffffff<UINT8>
0x0040645e:	je 0x00406477
0x00406477:	pushl $0x40d3b0<UINT32>
0x0040647c:	call GetModuleHandleA@KERNEL32.DLL
0x00406482:	movl %esi, %eax
0x00406484:	testl %esi, %esi
0x00406486:	je 35
0x00406488:	call 0x00406360
0x0040648d:	testl %eax, %eax
0x0040648f:	je 26
0x00406491:	pushl $0x40d3c0<UINT32>
0x00406496:	pushl %esi
0x00406497:	call GetProcAddress@KERNEL32.DLL
0x0040649d:	testl %eax, %eax
0x0040649f:	je 10
0x004064a1:	pushl 0x8(%esp)
0x004064a5:	call DecodePointer@KERNEL32.DLL
DecodePointer@KERNEL32.DLL: API Node	
0x004064a7:	movl 0x8(%esp), %eax
0x004064ab:	movl %eax, 0x8(%esp)
0x004064af:	popl %esi
0x004064b0:	ret

0x00407b9e:	popl %ecx
0x00407b9f:	movl %esi, %eax
0x00407ba1:	cmpl %esi, %edi
0x00407ba3:	jne 0x00407bf8
0x00407ba5:	leal %eax, -28(%ebp)
0x00407ba8:	pushl %eax
0x00407ba9:	call 0x00406a72
0x00407bae:	popl %ecx
0x00407baf:	cmpl %eax, %edi
0x00407bb1:	je 0x00407bc0
0x00407bc0:	cmpl -28(%ebp), $0x1<UINT8>
0x00407bc4:	je 33
0x00407bc6:	pushl $0x40da08<UINT32>
0x00407bcb:	call GetModuleHandleA@KERNEL32.DLL
0x00407bd1:	cmpl %eax, %edi
0x00407bd3:	je 18
0x00407bd5:	pushl $0x40d9e0<UINT32>
0x00407bda:	pushl %eax
0x00407bdb:	call GetProcAddress@KERNEL32.DLL
0x00407be1:	movl %esi, %eax
0x00407be3:	cmpl %esi, %edi
0x00407be5:	jne 0x00407bec
0x00407bec:	pushl %esi
0x00407bed:	call 0x004063cc
0x00407bf2:	popl %ecx
0x00407bf3:	movl 0x414974, %eax
0x00407bf8:	movl -4(%ebp), %edi
0x00407bfb:	pushl 0xc(%ebp)
0x00407bfe:	pushl 0x8(%ebp)
0x00407c01:	call InitializeCriticalSectionAndSpinCount@kernel32.dll
InitializeCriticalSectionAndSpinCount@kernel32.dll: API Node	
0x00407c03:	movl -32(%ebp), %eax
0x00407c06:	jmp 0x00407c37
0x00407c37:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00407c3e:	movl %eax, -32(%ebp)
0x00407c41:	call 0x00404acd
0x00404acd:	movl %ecx, -16(%ebp)
0x00404ad0:	movl %fs:0, %ecx
0x00404ad7:	popl %ecx
0x00404ad8:	popl %edi
0x00404ad9:	popl %edi
0x00404ada:	popl %esi
0x00404adb:	popl %ebx
0x00404adc:	movl %esp, %ebp
0x00404ade:	popl %ebp
0x00404adf:	pushl %ecx
0x00404ae0:	ret

0x00407c46:	ret

0x00403e0d:	testl %eax, %eax
0x00403e0f:	popl %ecx
0x00403e10:	popl %ecx
0x00403e11:	je 12
0x00403e13:	incl %esi
0x00403e14:	cmpl %esi, $0x24<UINT8>
0x00403e17:	jl 0x00403deb
0x00403e19:	xorl %eax, %eax
0x00403e1b:	incl %eax
0x00403e1c:	popl %edi
0x00403e1d:	popl %esi
0x00403e1e:	ret

0x004068a9:	testl %eax, %eax
0x004068ab:	je 101
0x004068ad:	pushl $0x406677<UINT32>
0x004068b2:	pushl 0x4144f0
0x004068b8:	call 0x00406443
0x004068bd:	popl %ecx
0x004068be:	call FlsAlloc@KERNEL32.DLL
FlsAlloc@KERNEL32.DLL: API Node	
0x004068c0:	cmpl %eax, $0xffffffff<UINT8>
0x004068c3:	movl 0x4138c0, %eax
0x004068c8:	je 72
0x004068ca:	pushl $0x214<UINT32>
0x004068cf:	pushl $0x1<UINT8>
0x004068d1:	call 0x00407c87
0x00407c87:	pushl %esi
0x00407c88:	pushl %edi
0x00407c89:	xorl %esi, %esi
0x00407c8b:	pushl $0x0<UINT8>
0x00407c8d:	pushl 0x14(%esp)
0x00407c91:	pushl 0x14(%esp)
0x00407c95:	call 0x0040b3af
0x0040b3af:	pushl $0xc<UINT8>
0x0040b3b1:	pushl $0x411c00<UINT32>
0x0040b3b6:	call 0x00404a88
0x0040b3bb:	movl %ecx, 0x8(%ebp)
0x0040b3be:	xorl %edi, %edi
0x0040b3c0:	cmpl %ecx, %edi
0x0040b3c2:	jbe 46
0x0040b3c4:	pushl $0xffffffe0<UINT8>
0x0040b3c6:	popl %eax
0x0040b3c7:	xorl %edx, %edx
0x0040b3c9:	divl %eax, %ecx
0x0040b3cb:	cmpl %eax, 0xc(%ebp)
0x0040b3ce:	sbbl %eax, %eax
0x0040b3d0:	incl %eax
0x0040b3d1:	jne 0x0040b3f2
0x0040b3f2:	imull %ecx, 0xc(%ebp)
0x0040b3f6:	movl %esi, %ecx
0x0040b3f8:	movl 0x8(%ebp), %esi
0x0040b3fb:	cmpl %esi, %edi
0x0040b3fd:	jne 0x0040b402
0x0040b402:	xorl %ebx, %ebx
0x0040b404:	movl -28(%ebp), %ebx
0x0040b407:	cmpl %esi, $0xffffffe0<UINT8>
0x0040b40a:	ja 105
0x0040b40c:	cmpl 0x415c14, $0x3<UINT8>
0x0040b413:	jne 0x0040b460
0x0040b460:	cmpl %ebx, %edi
0x0040b462:	jne 97
0x0040b464:	pushl %esi
0x0040b465:	pushl $0x8<UINT8>
0x0040b467:	pushl 0x414354
0x0040b46d:	call HeapAlloc@KERNEL32.DLL
0x0040b473:	movl %ebx, %eax
0x0040b475:	cmpl %ebx, %edi
0x0040b477:	jne 0x0040b4c5
0x0040b4c5:	movl %eax, %ebx
0x0040b4c7:	call 0x00404acd
0x0040b4cc:	ret

0x00407c9a:	movl %edi, %eax
0x00407c9c:	addl %esp, $0xc<UINT8>
0x00407c9f:	testl %edi, %edi
0x00407ca1:	jne 0x00407cca
0x00407cca:	movl %eax, %edi
0x00407ccc:	popl %edi
0x00407ccd:	popl %esi
0x00407cce:	ret

0x004068d6:	movl %esi, %eax
0x004068d8:	testl %esi, %esi
0x004068da:	popl %ecx
0x004068db:	popl %ecx
0x004068dc:	je 52
0x004068de:	pushl %esi
0x004068df:	pushl 0x4138c0
0x004068e5:	pushl 0x4144f8
0x004068eb:	call 0x00406443
0x00406460:	pushl %eax
0x00406461:	pushl 0x4138c4
0x00406467:	call TlsGetValue@KERNEL32.DLL
0x00406469:	call FlsGetValue@KERNEL32.DLL
FlsGetValue@KERNEL32.DLL: API Node	
0x0040646b:	testl %eax, %eax
0x0040646d:	je 0x00406477
0x004068f0:	popl %ecx
0x004068f1:	call FlsSetValue@KERNEL32.DLL
FlsSetValue@KERNEL32.DLL: API Node	
0x004068f3:	testl %eax, %eax
0x004068f5:	je 27
0x004068f7:	pushl $0x0<UINT8>
0x004068f9:	pushl %esi
0x004068fa:	call 0x00406529
0x00406529:	pushl $0xc<UINT8>
0x0040652b:	pushl $0x411a98<UINT32>
0x00406530:	call 0x00404a88
0x00406535:	pushl $0x40d3b0<UINT32>
0x0040653a:	call GetModuleHandleA@KERNEL32.DLL
0x00406540:	movl -28(%ebp), %eax
0x00406543:	movl %esi, 0x8(%ebp)
0x00406546:	movl 0x5c(%esi), $0x413990<UINT32>
0x0040654d:	xorl %edi, %edi
0x0040654f:	incl %edi
0x00406550:	movl 0x14(%esi), %edi
0x00406553:	testl %eax, %eax
0x00406555:	je 47
0x00406557:	call 0x00406360
0x0040655c:	testl %eax, %eax
0x0040655e:	je 38
0x00406560:	pushl $0x40d3a0<UINT32>
0x00406565:	pushl -28(%ebp)
0x00406568:	movl %ebx, 0x40d0b8
0x0040656e:	call GetProcAddress@KERNEL32.DLL
0x00406570:	movl 0x1f8(%esi), %eax
0x00406576:	pushl $0x40d3c0<UINT32>
0x0040657b:	pushl -28(%ebp)
0x0040657e:	call GetProcAddress@KERNEL32.DLL
0x00406580:	movl 0x1fc(%esi), %eax
0x00406586:	movl 0x70(%esi), %edi
0x00406589:	movb 0xc8(%esi), $0x43<UINT8>
0x00406590:	movb 0x14b(%esi), $0x43<UINT8>
0x00406597:	movl %eax, $0x4132a8<UINT32>
0x0040659c:	movl 0x68(%esi), %eax
0x0040659f:	pushl %eax
0x004065a0:	call InterlockedIncrement@KERNEL32.DLL
InterlockedIncrement@KERNEL32.DLL: API Node	
0x004065a6:	pushl $0xc<UINT8>
0x004065a8:	call 0x00403f58
0x00403f58:	pushl %ebp
0x00403f59:	movl %ebp, %esp
0x00403f5b:	movl %eax, 0x8(%ebp)
0x00403f5e:	pushl %esi
0x00403f5f:	leal %esi, 0x413188(,%eax,8)
0x00403f66:	cmpl (%esi), $0x0<UINT8>
0x00403f69:	jne 0x00403f7e
0x00403f7e:	pushl (%esi)
0x00403f80:	call EnterCriticalSection@KERNEL32.DLL
EnterCriticalSection@KERNEL32.DLL: API Node	
0x00403f86:	popl %esi
0x00403f87:	popl %ebp
0x00403f88:	ret

0x004065ad:	popl %ecx
0x004065ae:	andl -4(%ebp), $0x0<UINT8>
0x004065b2:	movl %eax, 0xc(%ebp)
0x004065b5:	movl 0x6c(%esi), %eax
0x004065b8:	testl %eax, %eax
0x004065ba:	jne 8
0x004065bc:	movl %eax, 0x4138b0
0x004065c1:	movl 0x6c(%esi), %eax
0x004065c4:	pushl 0x6c(%esi)
0x004065c7:	call 0x0040619a
0x0040619a:	pushl %ebx
0x0040619b:	pushl %ebp
0x0040619c:	pushl %esi
0x0040619d:	movl %esi, 0x10(%esp)
0x004061a1:	pushl %edi
0x004061a2:	movl %edi, 0x40d174
0x004061a8:	pushl %esi
0x004061a9:	call InterlockedIncrement@KERNEL32.DLL
0x004061ab:	movl %eax, 0xb0(%esi)
0x004061b1:	testl %eax, %eax
0x004061b3:	je 0x004061b8
0x004061b8:	movl %eax, 0xb8(%esi)
0x004061be:	testl %eax, %eax
0x004061c0:	je 0x004061c5
0x004061c5:	movl %eax, 0xb4(%esi)
0x004061cb:	testl %eax, %eax
0x004061cd:	je 0x004061d2
0x004061d2:	movl %eax, 0xc0(%esi)
0x004061d8:	testl %eax, %eax
0x004061da:	je 0x004061df
0x004061df:	pushl $0x6<UINT8>
0x004061e1:	leal %ebx, 0x50(%esi)
0x004061e4:	popl %ebp
0x004061e5:	cmpl -8(%ebx), $0x4137d0<UINT32>
0x004061ec:	je 0x004061f7
0x004061ee:	movl %eax, (%ebx)
0x004061f0:	testl %eax, %eax
0x004061f2:	je 0x004061f7
0x004061f7:	cmpl -4(%ebx), $0x0<UINT8>
0x004061fb:	je 0x00406207
0x00406207:	addl %ebx, $0x10<UINT8>
0x0040620a:	decl %ebp
0x0040620b:	jne 0x004061e5
0x0040620d:	movl %eax, 0xd4(%esi)
0x00406213:	addl %eax, $0xb4<UINT32>
0x00406218:	pushl %eax
0x00406219:	call InterlockedIncrement@KERNEL32.DLL
0x0040621b:	popl %edi
0x0040621c:	popl %esi
0x0040621d:	popl %ebp
0x0040621e:	popl %ebx
0x0040621f:	ret

0x004065cc:	popl %ecx
0x004065cd:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004065d4:	call 0x004065df
0x004065df:	pushl $0xc<UINT8>
0x004065e1:	call 0x00403e80
0x00403e80:	pushl %ebp
0x00403e81:	movl %ebp, %esp
0x00403e83:	movl %eax, 0x8(%ebp)
0x00403e86:	pushl 0x413188(,%eax,8)
0x00403e8d:	call LeaveCriticalSection@KERNEL32.DLL
LeaveCriticalSection@KERNEL32.DLL: API Node	
0x00403e93:	popl %ebp
0x00403e94:	ret

0x004065e6:	popl %ecx
0x004065e7:	ret

0x004065d9:	call 0x00404acd
0x004065de:	ret

0x004068ff:	popl %ecx
0x00406900:	popl %ecx
0x00406901:	call GetCurrentThreadId@KERNEL32.DLL
0x00406907:	orl 0x4(%esi), $0xffffffff<UINT8>
0x0040690b:	movl (%esi), %eax
0x0040690d:	xorl %eax, %eax
0x0040690f:	incl %eax
0x00406910:	jmp 0x00406919
0x00406919:	popl %esi
0x0040691a:	popl %edi
0x0040691b:	ret

0x00403aa8:	testl %eax, %eax
0x00403aaa:	jne 0x00403ab4
0x00403ab4:	call 0x00407a84
0x00407a84:	pushl %esi
0x00407a85:	pushl %edi
0x00407a86:	movl %eax, $0x4119a0<UINT32>
0x00407a8b:	movl %edi, $0x4119a0<UINT32>
0x00407a90:	cmpl %eax, %edi
0x00407a92:	movl %esi, %eax
0x00407a94:	jae 0x00407aa5
0x00407aa5:	popl %edi
0x00407aa6:	popl %esi
0x00407aa7:	ret

0x00403ab9:	movl -4(%ebp), %ebx
0x00403abc:	call 0x00407844
0x00407844:	pushl $0x54<UINT8>
0x00407846:	pushl $0x411b00<UINT32>
0x0040784b:	call 0x00404a88
0x00407850:	xorl %edi, %edi
0x00407852:	movl -4(%ebp), %edi
0x00407855:	leal %eax, -100(%ebp)
0x00407858:	pushl %eax
0x00407859:	call GetStartupInfoA@KERNEL32.DLL
0x0040785f:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00407866:	pushl $0x38<UINT8>
0x00407868:	pushl $0x20<UINT8>
0x0040786a:	popl %esi
0x0040786b:	pushl %esi
0x0040786c:	call 0x00407c87
0x00407871:	popl %ecx
0x00407872:	popl %ecx
0x00407873:	cmpl %eax, %edi
0x00407875:	je 512
0x0040787b:	movl 0x415ae0, %eax
0x00407880:	movl 0x415ac8, %esi
0x00407886:	leal %ecx, 0x700(%eax)
0x0040788c:	jmp 0x004078b7
0x004078b7:	cmpl %eax, %ecx
0x004078b9:	jb 0x0040788e
0x0040788e:	movb 0x4(%eax), $0x0<UINT8>
0x00407892:	orl (%eax), $0xffffffff<UINT8>
0x00407895:	movb 0x5(%eax), $0xa<UINT8>
0x00407899:	movl 0x8(%eax), %edi
0x0040789c:	movb 0x24(%eax), $0x0<UINT8>
0x004078a0:	movb 0x25(%eax), $0xa<UINT8>
0x004078a4:	movb 0x26(%eax), $0xa<UINT8>
0x004078a8:	addl %eax, $0x38<UINT8>
0x004078ab:	movl %ecx, 0x415ae0
0x004078b1:	addl %ecx, $0x700<UINT32>
0x004078bb:	cmpw -50(%ebp), %di
0x004078bf:	je 253
0x004078c5:	movl %eax, -48(%ebp)
0x004078c8:	cmpl %eax, %edi
0x004078ca:	je 242
0x004078d0:	movl %edi, (%eax)
0x004078d2:	leal %ebx, 0x4(%eax)
0x004078d5:	leal %eax, (%ebx,%edi)
0x004078d8:	movl -28(%ebp), %eax
0x004078db:	movl %eax, $0x800<UINT32>
0x004078e0:	cmpl %edi, %eax
0x004078e2:	jl 0x004078e6
0x004078e6:	xorl %esi, %esi
0x004078e8:	incl %esi
0x004078e9:	jmp 0x0040793d
0x0040793d:	cmpl 0x415ac8, %edi
0x00407943:	jl -90
0x00407945:	jmp 0x0040794d
0x0040794d:	andl -32(%ebp), $0x0<UINT8>
0x00407951:	testl %edi, %edi
0x00407953:	jle 0x004079c2
0x004079c2:	xorl %ebx, %ebx
0x004079c4:	movl %esi, %ebx
0x004079c6:	imull %esi, %esi, $0x38<UINT8>
0x004079c9:	addl %esi, 0x415ae0
0x004079cf:	movl %eax, (%esi)
0x004079d1:	cmpl %eax, $0xffffffff<UINT8>
0x004079d4:	je 0x004079e1
0x004079e1:	movb 0x4(%esi), $0xffffff81<UINT8>
0x004079e5:	testl %ebx, %ebx
0x004079e7:	jne 0x004079ee
0x004079e9:	pushl $0xfffffff6<UINT8>
0x004079eb:	popl %eax
0x004079ec:	jmp 0x004079f8
0x004079f8:	pushl %eax
0x004079f9:	call GetStdHandle@KERNEL32.DLL
GetStdHandle@KERNEL32.DLL: API Node	
0x004079ff:	movl %edi, %eax
0x00407a01:	cmpl %edi, $0xffffffff<UINT8>
0x00407a04:	je 67
0x00407a06:	testl %edi, %edi
0x00407a08:	je 63
0x00407a0a:	pushl %edi
0x00407a0b:	call GetFileType@KERNEL32.DLL
GetFileType@KERNEL32.DLL: API Node	
0x00407a11:	testl %eax, %eax
0x00407a13:	je 52
0x00407a15:	movl (%esi), %edi
0x00407a17:	andl %eax, $0xff<UINT32>
0x00407a1c:	cmpl %eax, $0x2<UINT8>
0x00407a1f:	jne 6
0x00407a21:	orb 0x4(%esi), $0x40<UINT8>
0x00407a25:	jmp 0x00407a30
0x00407a30:	pushl $0xfa0<UINT32>
0x00407a35:	leal %eax, 0xc(%esi)
0x00407a38:	pushl %eax
0x00407a39:	call 0x00407b82
0x0040646f:	movl %eax, 0x1fc(%eax)
0x00406475:	jmp 0x0040649d
0x00407a3e:	popl %ecx
0x00407a3f:	popl %ecx
0x00407a40:	testl %eax, %eax
0x00407a42:	je 55
0x00407a44:	incl 0x8(%esi)
0x00407a47:	jmp 0x00407a53
0x00407a53:	incl %ebx
0x00407a54:	cmpl %ebx, $0x3<UINT8>
0x00407a57:	jl 0x004079c4
0x004079ee:	movl %eax, %ebx
0x004079f0:	decl %eax
0x004079f1:	negl %eax
0x004079f3:	sbbl %eax, %eax
0x004079f5:	addl %eax, $0xfffffff5<UINT8>
0x00407a5d:	pushl 0x415ac8
0x00407a63:	call SetHandleCount@KERNEL32.DLL
SetHandleCount@KERNEL32.DLL: API Node	
0x00407a69:	xorl %eax, %eax
0x00407a6b:	jmp 0x00407a7e
0x00407a7e:	call 0x00404acd
0x00407a83:	ret

0x00403ac1:	testl %eax, %eax
0x00403ac3:	jnl 0x00403acd
0x00403acd:	call GetCommandLineA@KERNEL32.DLL
GetCommandLineA@KERNEL32.DLL: API Node	
0x00403ad3:	movl 0x415c18, %eax
0x00403ad8:	call 0x0040770f
0x0040770f:	pushl %ecx
0x00407710:	pushl %ecx
0x00407711:	movl %eax, 0x414970
0x00407716:	pushl %ebx
0x00407717:	pushl %ebp
0x00407718:	pushl %esi
0x00407719:	pushl %edi
0x0040771a:	movl %edi, 0x40d0a0
0x00407720:	xorl %ebx, %ebx
0x00407722:	xorl %esi, %esi
0x00407724:	cmpl %eax, %ebx
0x00407726:	pushl $0x2<UINT8>
0x00407728:	popl %ebp
0x00407729:	jne 45
0x0040772b:	call GetEnvironmentStringsW@KERNEL32.DLL
GetEnvironmentStringsW@KERNEL32.DLL: API Node	
0x0040772d:	movl %esi, %eax
0x0040772f:	cmpl %esi, %ebx
0x00407731:	je 12
0x00407733:	movl 0x414970, $0x1<UINT32>
0x0040773d:	jmp 0x00407761
0x00407761:	cmpl %esi, %ebx
0x00407763:	jne 0x00407774
0x00407774:	cmpw (%esi), %bx
0x00407777:	movl %eax, %esi
0x00407779:	je 14
0x0040777b:	addl %eax, %ebp
0x0040777d:	cmpw (%eax), %bx
0x00407780:	jne 0x0040777b
0x00407782:	addl %eax, %ebp
0x00407784:	cmpw (%eax), %bx
0x00407787:	jne 0x0040777b
0x00407789:	movl %edi, 0x40d120
0x0040778f:	pushl %ebx
0x00407790:	pushl %ebx
0x00407791:	pushl %ebx
0x00407792:	subl %eax, %esi
0x00407794:	pushl %ebx
0x00407795:	sarl %eax
0x00407797:	incl %eax
0x00407798:	pushl %eax
0x00407799:	pushl %esi
0x0040779a:	pushl %ebx
0x0040779b:	pushl %ebx
0x0040779c:	movl 0x34(%esp), %eax
0x004077a0:	call WideCharToMultiByte@KERNEL32.DLL
WideCharToMultiByte@KERNEL32.DLL: API Node	
0x004077a2:	movl %ebp, %eax
0x004077a4:	cmpl %ebp, %ebx
0x004077a6:	je 50
0x004077a8:	pushl %ebp
0x004077a9:	call 0x00407c47
0x00407c47:	pushl %esi
0x00407c48:	pushl %edi
0x00407c49:	xorl %esi, %esi
0x00407c4b:	pushl 0xc(%esp)
0x00407c4f:	call 0x0040354a
0x0040354a:	pushl %ebp
0x0040354b:	movl %ebp, 0x8(%esp)
0x0040354f:	cmpl %ebp, $0xffffffe0<UINT8>
0x00403552:	ja 159
0x00403558:	pushl %ebx
0x00403559:	movl %ebx, 0x40d12c
0x0040355f:	pushl %esi
0x00403560:	pushl %edi
0x00403561:	xorl %esi, %esi
0x00403563:	cmpl 0x414354, %esi
0x00403569:	movl %edi, %ebp
0x0040356b:	jne 0x00403585
0x00403585:	movl %eax, 0x415c14
0x0040358a:	cmpl %eax, $0x1<UINT8>
0x0040358d:	jne 14
0x0040358f:	cmpl %ebp, %esi
0x00403591:	je 4
0x00403593:	movl %eax, %ebp
0x00403595:	jmp 0x0040359a
0x0040359a:	pushl %eax
0x0040359b:	jmp 0x004035bb
0x004035bb:	pushl %esi
0x004035bc:	pushl 0x414354
0x004035c2:	call HeapAlloc@KERNEL32.DLL
0x004035c4:	movl %esi, %eax
0x004035c6:	testl %esi, %esi
0x004035c8:	jne 0x004035f0
0x004035f0:	popl %edi
0x004035f1:	movl %eax, %esi
0x004035f3:	popl %esi
0x004035f4:	popl %ebx
0x004035f5:	popl %ebp
0x004035f6:	ret

0x00407c54:	movl %edi, %eax
0x00407c56:	testl %edi, %edi
0x00407c58:	popl %ecx
0x00407c59:	jne 0x00407c82
0x00407c82:	movl %eax, %edi
0x00407c84:	popl %edi
0x00407c85:	popl %esi
0x00407c86:	ret

0x004077ae:	cmpl %eax, %ebx
0x004077b0:	popl %ecx
0x004077b1:	movl 0x10(%esp), %eax
0x004077b5:	je 35
0x004077b7:	pushl %ebx
0x004077b8:	pushl %ebx
0x004077b9:	pushl %ebp
0x004077ba:	pushl %eax
0x004077bb:	pushl 0x24(%esp)
0x004077bf:	pushl %esi
0x004077c0:	pushl %ebx
0x004077c1:	pushl %ebx
0x004077c2:	call WideCharToMultiByte@KERNEL32.DLL
0x004077c4:	testl %eax, %eax
0x004077c6:	jne 0x004077d6
0x004077d6:	movl %ebx, 0x10(%esp)
0x004077da:	pushl %esi
0x004077db:	call FreeEnvironmentStringsW@KERNEL32.DLL
FreeEnvironmentStringsW@KERNEL32.DLL: API Node	
0x004077e1:	movl %eax, %ebx
0x004077e3:	jmp 0x0040783d
0x0040783d:	popl %edi
0x0040783e:	popl %esi
0x0040783f:	popl %ebp
0x00407840:	popl %ebx
0x00407841:	popl %ecx
0x00407842:	popl %ecx
0x00407843:	ret

0x00403add:	movl 0x414020, %eax
0x00403ae2:	call 0x00407656
0x00407656:	pushl %ebp
0x00407657:	movl %ebp, %esp
0x00407659:	subl %esp, $0xc<UINT8>
0x0040765c:	pushl %ebx
0x0040765d:	xorl %ebx, %ebx
0x0040765f:	cmpl 0x415bec, %ebx
0x00407665:	pushl %esi
0x00407666:	pushl %edi
0x00407667:	jne 5
0x00407669:	call 0x0040603c
0x0040603c:	cmpl 0x415bec, $0x0<UINT8>
0x00406043:	jne 0x00406057
0x00406045:	pushl $0xfffffffd<UINT8>
0x00406047:	call 0x00405ea2
0x00405ea2:	pushl $0x14<UINT8>
0x00405ea4:	pushl $0x411a58<UINT32>
0x00405ea9:	call 0x00404a88
0x00405eae:	orl -32(%ebp), $0xffffffff<UINT8>
0x00405eb2:	call 0x0040665f
0x0040665f:	pushl %esi
0x00406660:	call 0x004065e8
0x004065e8:	pushl %esi
0x004065e9:	pushl %edi
0x004065ea:	call GetLastError@KERNEL32.DLL
GetLastError@KERNEL32.DLL: API Node	
0x004065f0:	pushl 0x4138c0
0x004065f6:	movl %edi, %eax
0x004065f8:	call 0x004064ba
0x004064ba:	pushl %esi
0x004064bb:	pushl 0x4138c4
0x004064c1:	call TlsGetValue@KERNEL32.DLL
0x004064c7:	movl %esi, %eax
0x004064c9:	testl %esi, %esi
0x004064cb:	jne 0x004064e8
0x004064e8:	movl %eax, %esi
0x004064ea:	popl %esi
0x004064eb:	ret

0x004065fd:	call FlsGetValue@KERNEL32.DLL
0x004065ff:	movl %esi, %eax
0x00406601:	testl %esi, %esi
0x00406603:	jne 0x00406653
0x00406653:	pushl %edi
0x00406654:	call SetLastError@KERNEL32.DLL
SetLastError@KERNEL32.DLL: API Node	
0x0040665a:	popl %edi
0x0040665b:	movl %eax, %esi
0x0040665d:	popl %esi
0x0040665e:	ret

0x00406665:	movl %esi, %eax
0x00406667:	testl %esi, %esi
0x00406669:	jne 0x00406673
0x00406673:	movl %eax, %esi
0x00406675:	popl %esi
0x00406676:	ret

0x00405eb7:	movl %edi, %eax
0x00405eb9:	movl -36(%ebp), %edi
0x00405ebc:	call 0x00405bab
0x00405bab:	pushl $0xc<UINT8>
0x00405bad:	pushl $0x411a38<UINT32>
0x00405bb2:	call 0x00404a88
0x00405bb7:	call 0x0040665f
0x00405bbc:	movl %edi, %eax
0x00405bbe:	movl %eax, 0x4137cc
0x00405bc3:	testl 0x70(%edi), %eax
0x00405bc6:	je 0x00405be5
0x00405be5:	pushl $0xd<UINT8>
0x00405be7:	call 0x00403f58
0x00405bec:	popl %ecx
0x00405bed:	andl -4(%ebp), $0x0<UINT8>
0x00405bf1:	movl %esi, 0x68(%edi)
0x00405bf4:	movl -28(%ebp), %esi
0x00405bf7:	cmpl %esi, 0x4136d0
0x00405bfd:	je 0x00405c35
0x00405c35:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00405c3c:	call 0x00405c46
0x00405c46:	pushl $0xd<UINT8>
0x00405c48:	call 0x00403e80
0x00405c4d:	popl %ecx
0x00405c4e:	ret

0x00405c41:	jmp 0x00405bd1
0x00405bd1:	testl %esi, %esi
0x00405bd3:	jne 0x00405bdd
0x00405bdd:	movl %eax, %esi
0x00405bdf:	call 0x00404acd
0x00405be4:	ret

0x00405ec1:	movl %ebx, 0x68(%edi)
0x00405ec4:	movl %esi, 0x8(%ebp)
0x00405ec7:	call 0x00405c4f
0x00405c4f:	pushl %ebp
0x00405c50:	movl %ebp, %esp
0x00405c52:	subl %esp, $0x10<UINT8>
0x00405c55:	pushl %ebx
0x00405c56:	xorl %ebx, %ebx
0x00405c58:	pushl %ebx
0x00405c59:	leal %ecx, -16(%ebp)
0x00405c5c:	call 0x004032d9
0x004032d9:	movl %eax, 0x4(%esp)
0x004032dd:	testl %eax, %eax
0x004032df:	pushl %esi
0x004032e0:	movl %esi, %ecx
0x004032e2:	movb 0xc(%esi), $0x0<UINT8>
0x004032e6:	jne 99
0x004032e8:	call 0x0040665f
0x004032ed:	movl 0x8(%esi), %eax
0x004032f0:	movl %ecx, 0x6c(%eax)
0x004032f3:	movl (%esi), %ecx
0x004032f5:	movl %ecx, 0x68(%eax)
0x004032f8:	movl 0x4(%esi), %ecx
0x004032fb:	movl %ecx, (%esi)
0x004032fd:	cmpl %ecx, 0x4138b0
0x00403303:	je 0x00403317
0x00403317:	movl %eax, 0x4(%esi)
0x0040331a:	cmpl %eax, 0x4136d0
0x00403320:	je 0x00403338
0x00403338:	movl %eax, 0x8(%esi)
0x0040333b:	testb 0x70(%eax), $0x2<UINT8>
0x0040333f:	jne 20
0x00403341:	orl 0x70(%eax), $0x2<UINT8>
0x00403345:	movb 0xc(%esi), $0x1<UINT8>
0x00403349:	jmp 0x00403355
0x00403355:	movl %eax, %esi
0x00403357:	popl %esi
0x00403358:	ret $0x4<UINT16>

0x00405c61:	cmpl %esi, $0xfffffffe<UINT8>
0x00405c64:	movl 0x4144b0, %ebx
0x00405c6a:	jne 0x00405c8a
0x00405c8a:	cmpl %esi, $0xfffffffd<UINT8>
0x00405c8d:	jne 0x00405ca1
0x00405c8f:	movl 0x4144b0, $0x1<UINT32>
0x00405c99:	call GetACP@KERNEL32.DLL
GetACP@KERNEL32.DLL: API Node	
0x00405c9f:	jmp 0x00405c7c
0x00405c7c:	cmpb -4(%ebp), %bl
0x00405c7f:	je 69
0x00405c81:	movl %ecx, -8(%ebp)
0x00405c84:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00405c88:	jmp 0x00405cc6
0x00405cc6:	popl %ebx
0x00405cc7:	leave
0x00405cc8:	ret

0x00405ecc:	movl 0x8(%ebp), %eax
0x00405ecf:	cmpl %eax, 0x4(%ebx)
0x00405ed2:	je 343
0x00405ed8:	pushl $0x220<UINT32>
0x00405edd:	call 0x00407c47
0x00405ee2:	popl %ecx
0x00405ee3:	movl %ebx, %eax
0x00405ee5:	testl %ebx, %ebx
0x00405ee7:	je 326
0x00405eed:	movl %ecx, $0x88<UINT32>
0x00405ef2:	movl %esi, 0x68(%edi)
0x00405ef5:	movl %edi, %ebx
0x00405ef7:	rep movsl %es:(%edi), %ds:(%esi)
0x00405ef9:	andl (%ebx), $0x0<UINT8>
0x00405efc:	pushl %ebx
0x00405efd:	pushl 0x8(%ebp)
0x00405f00:	call 0x00405cc9
0x00405cc9:	pushl %ebp
0x00405cca:	movl %ebp, %esp
0x00405ccc:	subl %esp, $0x20<UINT8>
0x00405ccf:	movl %eax, 0x413004
0x00405cd4:	xorl %eax, %ebp
0x00405cd6:	movl -4(%ebp), %eax
0x00405cd9:	pushl %ebx
0x00405cda:	movl %ebx, 0xc(%ebp)
0x00405cdd:	pushl %esi
0x00405cde:	movl %esi, 0x8(%ebp)
0x00405ce1:	pushl %edi
0x00405ce2:	call 0x00405c4f
0x00405ca1:	cmpl %esi, $0xfffffffc<UINT8>
0x00405ca4:	jne 0x00405cb8
0x00405cb8:	cmpb -4(%ebp), %bl
0x00405cbb:	je 7
0x00405cbd:	movl %eax, -8(%ebp)
0x00405cc0:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x00405cc4:	movl %eax, %esi
0x00405ce7:	movl %edi, %eax
0x00405ce9:	xorl %esi, %esi
0x00405ceb:	cmpl %edi, %esi
0x00405ced:	movl 0x8(%ebp), %edi
0x00405cf0:	jne 0x00405d00
0x00405d00:	movl -28(%ebp), %esi
0x00405d03:	xorl %eax, %eax
0x00405d05:	cmpl 0x4136d8(%eax), %edi
0x00405d0b:	je 145
0x00405d11:	incl -28(%ebp)
0x00405d14:	addl %eax, $0x30<UINT8>
0x00405d17:	cmpl %eax, $0xf0<UINT32>
0x00405d1c:	jb 0x00405d05
0x00405d1e:	cmpl %edi, $0xfde8<UINT32>
0x00405d24:	je 358
0x00405d2a:	cmpl %edi, $0xfde9<UINT32>
0x00405d30:	je 346
0x00405d36:	movzwl %eax, %di
0x00405d39:	pushl %eax
0x00405d3a:	call IsValidCodePage@KERNEL32.DLL
IsValidCodePage@KERNEL32.DLL: API Node	
0x00405d40:	testl %eax, %eax
0x00405d42:	je 328
0x00405d48:	leal %eax, -24(%ebp)
0x00405d4b:	pushl %eax
0x00405d4c:	pushl %edi
0x00405d4d:	call GetCPInfo@KERNEL32.DLL
GetCPInfo@KERNEL32.DLL: API Node	
0x00405d53:	testl %eax, %eax
0x00405d55:	je 297
0x00405d5b:	pushl $0x101<UINT32>
0x00405d60:	leal %eax, 0x1c(%ebx)
0x00405d63:	pushl %esi
0x00405d64:	pushl %eax
0x00405d65:	call 0x00409280
0x00409280:	movl %edx, 0xc(%esp)
0x00409284:	movl %ecx, 0x4(%esp)
0x00409288:	testl %edx, %edx
0x0040928a:	je 105
0x0040928c:	xorl %eax, %eax
0x0040928e:	movb %al, 0x8(%esp)
0x00409292:	testb %al, %al
0x00409294:	jne 22
0x00409296:	cmpl %edx, $0x100<UINT32>
0x0040929c:	jb 0x004092ac
0x0040929e:	cmpl 0x414ab0, $0x0<UINT8>
0x004092a5:	je 0x004092ac
0x004092ac:	pushl %edi
0x004092ad:	movl %edi, %ecx
0x004092af:	cmpl %edx, $0x4<UINT8>
0x004092b2:	jb 49
0x004092b4:	negl %ecx
0x004092b6:	andl %ecx, $0x3<UINT8>
0x004092b9:	je 0x004092c7
0x004092c7:	movl %ecx, %eax
0x004092c9:	shll %eax, $0x8<UINT8>
0x004092cc:	addl %eax, %ecx
0x004092ce:	movl %ecx, %eax
0x004092d0:	shll %eax, $0x10<UINT8>
0x004092d3:	addl %eax, %ecx
0x004092d5:	movl %ecx, %edx
0x004092d7:	andl %edx, $0x3<UINT8>
0x004092da:	shrl %ecx, $0x2<UINT8>
0x004092dd:	je 6
0x004092df:	rep stosl %es:(%edi), %eax
0x004092e1:	testl %edx, %edx
0x004092e3:	je 0x004092ef
0x004092e5:	movb (%edi), %al
0x004092e7:	addl %edi, $0x1<UINT8>
0x004092ea:	subl %edx, $0x1<UINT8>
0x004092ed:	jne 0x004092e5
0x004092ef:	movl %eax, 0x8(%esp)
0x004092f3:	popl %edi
0x004092f4:	ret

0x00405d6a:	xorl %edx, %edx
0x00405d6c:	incl %edx
0x00405d6d:	addl %esp, $0xc<UINT8>
0x00405d70:	cmpl -24(%ebp), %edx
0x00405d73:	movl 0x4(%ebx), %edi
0x00405d76:	movl 0xc(%ebx), %esi
0x00405d79:	jbe 248
0x00405d7f:	cmpb -18(%ebp), $0x0<UINT8>
0x00405d83:	je 0x00405e58
0x00405e58:	leal %eax, 0x1e(%ebx)
0x00405e5b:	movl %ecx, $0xfe<UINT32>
0x00405e60:	orb (%eax), $0x8<UINT8>
0x00405e63:	incl %eax
0x00405e64:	decl %ecx
0x00405e65:	jne 0x00405e60
0x00405e67:	movl %eax, 0x4(%ebx)
0x00405e6a:	call 0x0040599d
0x0040599d:	subl %eax, $0x3a4<UINT32>
0x004059a2:	je 34
0x004059a4:	subl %eax, $0x4<UINT8>
0x004059a7:	je 23
0x004059a9:	subl %eax, $0xd<UINT8>
0x004059ac:	je 12
0x004059ae:	decl %eax
0x004059af:	je 3
0x004059b1:	xorl %eax, %eax
0x004059b3:	ret

0x00405e6f:	movl 0xc(%ebx), %eax
0x00405e72:	movl 0x8(%ebx), %edx
0x00405e75:	jmp 0x00405e7a
0x00405e7a:	xorl %eax, %eax
0x00405e7c:	leal %edi, 0x10(%ebx)
0x00405e7f:	stosl %es:(%edi), %eax
0x00405e80:	stosl %es:(%edi), %eax
0x00405e81:	stosl %es:(%edi), %eax
0x00405e82:	jmp 0x00405e36
0x00405e36:	movl %esi, %ebx
0x00405e38:	call 0x00405a21
0x00405a21:	pushl %ebp
0x00405a22:	leal %ebp, -1180(%esp)
0x00405a29:	subl %esp, $0x51c<UINT32>
0x00405a2f:	movl %eax, 0x413004
0x00405a34:	xorl %eax, %ebp
0x00405a36:	movl 0x498(%ebp), %eax
0x00405a3c:	pushl %ebx
0x00405a3d:	pushl %edi
0x00405a3e:	leal %eax, -124(%ebp)
0x00405a41:	pushl %eax
0x00405a42:	pushl 0x4(%esi)
0x00405a45:	call GetCPInfo@KERNEL32.DLL
0x00405a4b:	testl %eax, %eax
0x00405a4d:	movl %edi, $0x100<UINT32>
0x00405a52:	je 239
0x00405a58:	xorl %eax, %eax
0x00405a5a:	movb 0x398(%ebp,%eax), %al
0x00405a61:	incl %eax
0x00405a62:	cmpl %eax, %edi
0x00405a64:	jb 0x00405a5a
0x00405a66:	movb %al, -118(%ebp)
0x00405a69:	testb %al, %al
0x00405a6b:	movb 0x398(%ebp), $0x20<UINT8>
0x00405a72:	je 0x00405a9f
0x00405a9f:	pushl $0x0<UINT8>
0x00405aa1:	pushl 0xc(%esi)
0x00405aa4:	leal %eax, -104(%ebp)
0x00405aa7:	pushl 0x4(%esi)
0x00405aaa:	pushl %eax
0x00405aab:	pushl %edi
0x00405aac:	leal %eax, 0x398(%ebp)
0x00405ab2:	pushl %eax
0x00405ab3:	pushl $0x1<UINT8>
0x00405ab5:	pushl $0x0<UINT8>
0x00405ab7:	call 0x0040a24c
0x0040a24c:	pushl %ebp
0x0040a24d:	movl %ebp, %esp
0x0040a24f:	subl %esp, $0x10<UINT8>
0x0040a252:	pushl 0x8(%ebp)
0x0040a255:	leal %ecx, -16(%ebp)
0x0040a258:	call 0x004032d9
0x0040a25d:	pushl 0x24(%ebp)
0x0040a260:	leal %ecx, -16(%ebp)
0x0040a263:	pushl 0x20(%ebp)
0x0040a266:	pushl 0x1c(%ebp)
0x0040a269:	pushl 0x18(%ebp)
0x0040a26c:	pushl 0x14(%ebp)
0x0040a26f:	pushl 0x10(%ebp)
0x0040a272:	pushl 0xc(%ebp)
0x0040a275:	call 0x0040a094
0x0040a094:	pushl %ebp
0x0040a095:	movl %ebp, %esp
0x0040a097:	pushl %ecx
0x0040a098:	pushl %ecx
0x0040a099:	movl %eax, 0x413004
0x0040a09e:	xorl %eax, %ebp
0x0040a0a0:	movl -4(%ebp), %eax
0x0040a0a3:	movl %eax, 0x414988
0x0040a0a8:	pushl %ebx
0x0040a0a9:	pushl %esi
0x0040a0aa:	xorl %ebx, %ebx
0x0040a0ac:	cmpl %eax, %ebx
0x0040a0ae:	pushl %edi
0x0040a0af:	movl %edi, %ecx
0x0040a0b1:	jne 58
0x0040a0b3:	leal %eax, -8(%ebp)
0x0040a0b6:	pushl %eax
0x0040a0b7:	xorl %esi, %esi
0x0040a0b9:	incl %esi
0x0040a0ba:	pushl %esi
0x0040a0bb:	pushl $0x40d9dc<UINT32>
0x0040a0c0:	pushl %esi
0x0040a0c1:	call GetStringTypeW@KERNEL32.DLL
GetStringTypeW@KERNEL32.DLL: API Node	
0x0040a0c7:	testl %eax, %eax
0x0040a0c9:	je 8
0x0040a0cb:	movl 0x414988, %esi
0x0040a0d1:	jmp 0x0040a107
0x0040a107:	cmpl 0x18(%ebp), %ebx
0x0040a10a:	movl -8(%ebp), %ebx
0x0040a10d:	jne 0x0040a117
0x0040a117:	movl %esi, 0x40d1a4
0x0040a11d:	xorl %eax, %eax
0x0040a11f:	cmpl 0x20(%ebp), %ebx
0x0040a122:	pushl %ebx
0x0040a123:	pushl %ebx
0x0040a124:	pushl 0x10(%ebp)
0x0040a127:	setne %al
0x0040a12a:	pushl 0xc(%ebp)
0x0040a12d:	leal %eax, 0x1(,%eax,8)
0x0040a134:	pushl %eax
0x0040a135:	pushl 0x18(%ebp)
0x0040a138:	call MultiByteToWideChar@KERNEL32.DLL
MultiByteToWideChar@KERNEL32.DLL: API Node	
0x0040a13a:	movl %edi, %eax
0x0040a13c:	cmpl %edi, %ebx
0x0040a13e:	je 171
0x0040a144:	jle 60
0x0040a146:	cmpl %edi, $0x7ffffff0<UINT32>
0x0040a14c:	ja 52
0x0040a14e:	leal %eax, 0x8(%edi,%edi)
0x0040a152:	cmpl %eax, $0x400<UINT32>
0x0040a157:	ja 19
0x0040a159:	call 0x004071b0
0x004071b0:	pushl %ecx
0x004071b1:	leal %ecx, 0x8(%esp)
0x004071b5:	subl %ecx, %eax
0x004071b7:	andl %ecx, $0xf<UINT8>
0x004071ba:	addl %eax, %ecx
0x004071bc:	sbbl %ecx, %ecx
0x004071be:	orl %eax, %ecx
0x004071c0:	popl %ecx
0x004071c1:	jmp 0x0040b320
0x0040b320:	pushl %ecx
0x0040b321:	leal %ecx, 0x4(%esp)
0x0040b325:	subl %ecx, %eax
0x0040b327:	sbbl %eax, %eax
0x0040b329:	notl %eax
0x0040b32b:	andl %ecx, %eax
0x0040b32d:	movl %eax, %esp
0x0040b32f:	andl %eax, $0xfffff000<UINT32>
0x0040b334:	cmpl %ecx, %eax
0x0040b336:	jb 10
0x0040b338:	movl %eax, %ecx
0x0040b33a:	popl %ecx
0x0040b33b:	xchgl %esp, %eax
0x0040b33c:	movl %eax, (%eax)
0x0040b33e:	movl (%esp), %eax
0x0040b341:	ret

0x0040a15e:	movl %eax, %esp
0x0040a160:	cmpl %eax, %ebx
0x0040a162:	je 28
0x0040a164:	movl (%eax), $0xcccc<UINT32>
0x0040a16a:	jmp 0x0040a17d
0x0040a17d:	addl %eax, $0x8<UINT8>
0x0040a180:	movl %ebx, %eax
0x0040a182:	testl %ebx, %ebx
0x0040a184:	je 105
0x0040a186:	leal %eax, (%edi,%edi)
0x0040a189:	pushl %eax
0x0040a18a:	pushl $0x0<UINT8>
0x0040a18c:	pushl %ebx
0x0040a18d:	call 0x00409280
0x0040a192:	addl %esp, $0xc<UINT8>
0x0040a195:	pushl %edi
0x0040a196:	pushl %ebx
0x0040a197:	pushl 0x10(%ebp)
0x0040a19a:	pushl 0xc(%ebp)
0x0040a19d:	pushl $0x1<UINT8>
0x0040a19f:	pushl 0x18(%ebp)
0x0040a1a2:	call MultiByteToWideChar@KERNEL32.DLL
0x0040a1a4:	testl %eax, %eax
0x0040a1a6:	je 17
0x0040a1a8:	pushl 0x14(%ebp)
0x0040a1ab:	pushl %eax
0x0040a1ac:	pushl %ebx
0x0040a1ad:	pushl 0x8(%ebp)
0x0040a1b0:	call GetStringTypeW@KERNEL32.DLL
0x0040a1b6:	movl -8(%ebp), %eax
0x0040a1b9:	pushl %ebx
0x0040a1ba:	call 0x00403751
0x00403751:	movl %eax, 0x4(%esp)
0x00403755:	testl %eax, %eax
0x00403757:	je 18
0x00403759:	subl %eax, $0x8<UINT8>
0x0040375c:	cmpl (%eax), $0xdddd<UINT32>
0x00403762:	jne 0x0040376b
0x0040376b:	ret

0x0040a1bf:	movl %eax, -8(%ebp)
0x0040a1c2:	popl %ecx
0x0040a1c3:	jmp 0x0040a23a
0x0040a23a:	leal %esp, -20(%ebp)
0x0040a23d:	popl %edi
0x0040a23e:	popl %esi
0x0040a23f:	popl %ebx
0x0040a240:	movl %ecx, -4(%ebp)
0x0040a243:	xorl %ecx, %ebp
0x0040a245:	call 0x0040318a
0x0040318a:	cmpl %ecx, 0x413004
0x00403190:	jne 2
0x00403192:	rep ret

0x0040a24a:	leave
0x0040a24b:	ret

0x0040a27a:	addl %esp, $0x1c<UINT8>
0x0040a27d:	cmpb -4(%ebp), $0x0<UINT8>
0x0040a281:	je 7
0x0040a283:	movl %ecx, -8(%ebp)
0x0040a286:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0040a28a:	leave
0x0040a28b:	ret

0x00405abc:	xorl %ebx, %ebx
0x00405abe:	pushl %ebx
0x00405abf:	pushl 0x4(%esi)
0x00405ac2:	leal %eax, 0x298(%ebp)
0x00405ac8:	pushl %edi
0x00405ac9:	pushl %eax
0x00405aca:	pushl %edi
0x00405acb:	leal %eax, 0x398(%ebp)
0x00405ad1:	pushl %eax
0x00405ad2:	pushl %edi
0x00405ad3:	pushl 0xc(%esi)
0x00405ad6:	pushl %ebx
0x00405ad7:	call 0x0040a051
0x0040a051:	pushl %ebp
0x0040a052:	movl %ebp, %esp
0x0040a054:	subl %esp, $0x10<UINT8>
0x0040a057:	pushl 0x8(%ebp)
0x0040a05a:	leal %ecx, -16(%ebp)
0x0040a05d:	call 0x004032d9
0x0040a062:	pushl 0x28(%ebp)
0x0040a065:	leal %ecx, -16(%ebp)
0x0040a068:	pushl 0x24(%ebp)
0x0040a06b:	pushl 0x20(%ebp)
0x0040a06e:	pushl 0x1c(%ebp)
0x0040a071:	pushl 0x18(%ebp)
0x0040a074:	pushl 0x14(%ebp)
0x0040a077:	pushl 0x10(%ebp)
0x0040a07a:	pushl 0xc(%ebp)
0x0040a07d:	call 0x00409caf
0x00409caf:	pushl %ebp
0x00409cb0:	movl %ebp, %esp
0x00409cb2:	subl %esp, $0x14<UINT8>
0x00409cb5:	movl %eax, 0x413004
0x00409cba:	xorl %eax, %ebp
0x00409cbc:	movl -4(%ebp), %eax
0x00409cbf:	pushl %ebx
0x00409cc0:	pushl %esi
0x00409cc1:	xorl %ebx, %ebx
0x00409cc3:	cmpl 0x414984, %ebx
0x00409cc9:	pushl %edi
0x00409cca:	movl %esi, %ecx
0x00409ccc:	jne 0x00409d06
0x00409cce:	pushl %ebx
0x00409ccf:	pushl %ebx
0x00409cd0:	xorl %edi, %edi
0x00409cd2:	incl %edi
0x00409cd3:	pushl %edi
0x00409cd4:	pushl $0x40d9dc<UINT32>
0x00409cd9:	pushl $0x100<UINT32>
0x00409cde:	pushl %ebx
0x00409cdf:	call LCMapStringW@KERNEL32.DLL
LCMapStringW@KERNEL32.DLL: API Node	
0x00409ce5:	testl %eax, %eax
0x00409ce7:	je 8
0x00409ce9:	movl 0x414984, %edi
0x00409cef:	jmp 0x00409d06
0x00409d06:	cmpl 0x14(%ebp), %ebx
0x00409d09:	jle 34
0x00409d0b:	movl %ecx, 0x14(%ebp)
0x00409d0e:	movl %eax, 0x10(%ebp)
0x00409d11:	decl %ecx
0x00409d12:	cmpb (%eax), %bl
0x00409d14:	je 8
0x00409d16:	incl %eax
0x00409d17:	cmpl %ecx, %ebx
0x00409d19:	jne 0x00409d11
0x00409d1b:	orl %ecx, $0xffffffff<UINT8>
0x00409d1e:	movl %eax, 0x14(%ebp)
0x00409d21:	subl %eax, %ecx
0x00409d23:	decl %eax
0x00409d24:	cmpl %eax, 0x14(%ebp)
0x00409d27:	jnl 0x00409d2a
0x00409d2a:	movl 0x14(%ebp), %eax
0x00409d2d:	movl %eax, 0x414984
0x00409d32:	cmpl %eax, $0x2<UINT8>
0x00409d35:	je 427
0x00409d3b:	cmpl %eax, %ebx
0x00409d3d:	je 419
0x00409d43:	cmpl %eax, $0x1<UINT8>
0x00409d46:	jne 459
0x00409d4c:	cmpl 0x20(%ebp), %ebx
0x00409d4f:	movl -8(%ebp), %ebx
0x00409d52:	jne 0x00409d5c
0x00409d5c:	movl %esi, 0x40d1a4
0x00409d62:	xorl %eax, %eax
0x00409d64:	cmpl 0x24(%ebp), %ebx
0x00409d67:	pushl %ebx
0x00409d68:	pushl %ebx
0x00409d69:	pushl 0x14(%ebp)
0x00409d6c:	setne %al
0x00409d6f:	pushl 0x10(%ebp)
0x00409d72:	leal %eax, 0x1(,%eax,8)
0x00409d79:	pushl %eax
0x00409d7a:	pushl 0x20(%ebp)
0x00409d7d:	call MultiByteToWideChar@KERNEL32.DLL
0x00409d7f:	movl %edi, %eax
0x00409d81:	cmpl %edi, %ebx
0x00409d83:	je 398
0x00409d89:	jle 67
0x00409d8b:	pushl $0xffffffe0<UINT8>
0x00409d8d:	xorl %edx, %edx
0x00409d8f:	popl %eax
0x00409d90:	divl %eax, %edi
0x00409d92:	cmpl %eax, $0x2<UINT8>
0x00409d95:	jb 55
0x00409d97:	leal %eax, 0x8(%edi,%edi)
0x00409d9b:	cmpl %eax, $0x400<UINT32>
0x00409da0:	ja 19
0x00409da2:	call 0x004071b0
0x00409da7:	movl %eax, %esp
0x00409da9:	cmpl %eax, %ebx
0x00409dab:	je 28
0x00409dad:	movl (%eax), $0xcccc<UINT32>
0x00409db3:	jmp 0x00409dc6
0x00409dc6:	addl %eax, $0x8<UINT8>
0x00409dc9:	movl -12(%ebp), %eax
0x00409dcc:	jmp 0x00409dd1
0x00409dd1:	cmpl -12(%ebp), %ebx
0x00409dd4:	je 317
0x00409dda:	pushl %edi
0x00409ddb:	pushl -12(%ebp)
0x00409dde:	pushl 0x14(%ebp)
0x00409de1:	pushl 0x10(%ebp)
0x00409de4:	pushl $0x1<UINT8>
0x00409de6:	pushl 0x20(%ebp)
0x00409de9:	call MultiByteToWideChar@KERNEL32.DLL
0x00409deb:	testl %eax, %eax
0x00409ded:	je 226
0x00409df3:	movl %esi, 0x40d11c
0x00409df9:	pushl %ebx
0x00409dfa:	pushl %ebx
0x00409dfb:	pushl %edi
0x00409dfc:	pushl -12(%ebp)
0x00409dff:	pushl 0xc(%ebp)
0x00409e02:	pushl 0x8(%ebp)
0x00409e05:	call LCMapStringW@KERNEL32.DLL
0x00409e07:	movl %ecx, %eax
0x00409e09:	cmpl %ecx, %ebx
0x00409e0b:	movl -8(%ebp), %ecx
0x00409e0e:	je 193
0x00409e14:	testw 0xc(%ebp), $0x400<UINT16>
0x00409e1a:	je 0x00409e45
0x00409e45:	cmpl %ecx, %ebx
0x00409e47:	jle 69
0x00409e49:	pushl $0xffffffe0<UINT8>
0x00409e4b:	xorl %edx, %edx
0x00409e4d:	popl %eax
0x00409e4e:	divl %eax, %ecx
0x00409e50:	cmpl %eax, $0x2<UINT8>
0x00409e53:	jb 57
0x00409e55:	leal %eax, 0x8(%ecx,%ecx)
0x00409e59:	cmpl %eax, $0x400<UINT32>
0x00409e5e:	ja 22
0x00409e60:	call 0x004071b0
0x00409e65:	movl %esi, %esp
0x00409e67:	cmpl %esi, %ebx
0x00409e69:	je 106
0x00409e6b:	movl (%esi), $0xcccc<UINT32>
0x00409e71:	addl %esi, $0x8<UINT8>
0x00409e74:	jmp 0x00409e90
0x00409e90:	cmpl %esi, %ebx
0x00409e92:	je 65
0x00409e94:	pushl -8(%ebp)
0x00409e97:	pushl %esi
0x00409e98:	pushl %edi
0x00409e99:	pushl -12(%ebp)
0x00409e9c:	pushl 0xc(%ebp)
0x00409e9f:	pushl 0x8(%ebp)
0x00409ea2:	call LCMapStringW@KERNEL32.DLL
0x00409ea8:	testl %eax, %eax
0x00409eaa:	je 34
0x00409eac:	cmpl 0x1c(%ebp), %ebx
0x00409eaf:	pushl %ebx
0x00409eb0:	pushl %ebx
0x00409eb1:	jne 0x00409eb7
0x00409eb7:	pushl 0x1c(%ebp)
0x00409eba:	pushl 0x18(%ebp)
0x00409ebd:	pushl -8(%ebp)
0x00409ec0:	pushl %esi
0x00409ec1:	pushl %ebx
0x00409ec2:	pushl 0x20(%ebp)
0x00409ec5:	call WideCharToMultiByte@KERNEL32.DLL
0x00409ecb:	movl -8(%ebp), %eax
0x00409ece:	pushl %esi
0x00409ecf:	call 0x00403751
0x00409ed4:	popl %ecx
0x00409ed5:	pushl -12(%ebp)
0x00409ed8:	call 0x00403751
0x00409edd:	movl %eax, -8(%ebp)
0x00409ee0:	popl %ecx
0x00409ee1:	jmp 0x0040a03f
0x0040a03f:	leal %esp, -32(%ebp)
0x0040a042:	popl %edi
0x0040a043:	popl %esi
0x0040a044:	popl %ebx
0x0040a045:	movl %ecx, -4(%ebp)
0x0040a048:	xorl %ecx, %ebp
0x0040a04a:	call 0x0040318a
0x0040a04f:	leave
0x0040a050:	ret

0x0040a082:	addl %esp, $0x20<UINT8>
0x0040a085:	cmpb -4(%ebp), $0x0<UINT8>
0x0040a089:	je 7
0x0040a08b:	movl %ecx, -8(%ebp)
0x0040a08e:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0040a092:	leave
0x0040a093:	ret

0x00405adc:	addl %esp, $0x44<UINT8>
0x00405adf:	pushl %ebx
0x00405ae0:	pushl 0x4(%esi)
0x00405ae3:	leal %eax, 0x198(%ebp)
0x00405ae9:	pushl %edi
0x00405aea:	pushl %eax
0x00405aeb:	pushl %edi
0x00405aec:	leal %eax, 0x398(%ebp)
0x00405af2:	pushl %eax
0x00405af3:	pushl $0x200<UINT32>
0x00405af8:	pushl 0xc(%esi)
0x00405afb:	pushl %ebx
0x00405afc:	call 0x0040a051
0x00405b01:	addl %esp, $0x24<UINT8>
0x00405b04:	xorl %eax, %eax
0x00405b06:	movzwl %ecx, -104(%ebp,%eax,2)
0x00405b0b:	testb %cl, $0x1<UINT8>
0x00405b0e:	je 0x00405b1e
0x00405b1e:	testb %cl, $0x2<UINT8>
0x00405b21:	je 0x00405b38
0x00405b38:	movb 0x11d(%esi,%eax), $0x0<UINT8>
0x00405b40:	incl %eax
0x00405b41:	cmpl %eax, %edi
0x00405b43:	jb 0x00405b06
0x00405b10:	orb 0x1d(%esi,%eax), $0x10<UINT8>
0x00405b15:	movb %cl, 0x298(%ebp,%eax)
0x00405b1c:	jmp 0x00405b2f
0x00405b2f:	movb 0x11d(%esi,%eax), %cl
0x00405b36:	jmp 0x00405b40
0x00405b23:	orb 0x1d(%esi,%eax), $0x20<UINT8>
0x00405b28:	movb %cl, 0x198(%ebp,%eax)
0x00405b45:	jmp 0x00405b94
0x00405b94:	movl %ecx, 0x498(%ebp)
0x00405b9a:	popl %edi
0x00405b9b:	xorl %ecx, %ebp
0x00405b9d:	popl %ebx
0x00405b9e:	call 0x0040318a
0x00405ba3:	addl %ebp, $0x49c<UINT32>
0x00405ba9:	leave
0x00405baa:	ret

0x00405e3d:	jmp 0x00405cf9
0x00405cf9:	xorl %eax, %eax
0x00405cfb:	jmp 0x00405e93
0x00405e93:	movl %ecx, -4(%ebp)
0x00405e96:	popl %edi
0x00405e97:	popl %esi
0x00405e98:	xorl %ecx, %ebp
0x00405e9a:	popl %ebx
0x00405e9b:	call 0x0040318a
0x00405ea0:	leave
0x00405ea1:	ret

0x00405f05:	popl %ecx
0x00405f06:	popl %ecx
0x00405f07:	movl -32(%ebp), %eax
0x00405f0a:	testl %eax, %eax
0x00405f0c:	jne 252
0x00405f12:	movl %esi, -36(%ebp)
0x00405f15:	pushl 0x68(%esi)
0x00405f18:	call InterlockedDecrement@KERNEL32.DLL
InterlockedDecrement@KERNEL32.DLL: API Node	
0x00405f1e:	testl %eax, %eax
0x00405f20:	jne 17
0x00405f22:	movl %eax, 0x68(%esi)
0x00405f25:	cmpl %eax, $0x4132a8<UINT32>
0x00405f2a:	je 0x00405f33
0x00405f33:	movl 0x68(%esi), %ebx
0x00405f36:	pushl %ebx
0x00405f37:	movl %edi, 0x40d174
0x00405f3d:	call InterlockedIncrement@KERNEL32.DLL
0x00405f3f:	testb 0x70(%esi), $0x2<UINT8>
0x00405f43:	jne 234
0x00405f49:	testb 0x4137cc, $0x1<UINT8>
0x00405f50:	jne 221
0x00405f56:	pushl $0xd<UINT8>
0x00405f58:	call 0x00403f58
0x00405f5d:	popl %ecx
0x00405f5e:	andl -4(%ebp), $0x0<UINT8>
0x00405f62:	movl %eax, 0x4(%ebx)
0x00405f65:	movl 0x4144c0, %eax
0x00405f6a:	movl %eax, 0x8(%ebx)
0x00405f6d:	movl 0x4144c4, %eax
0x00405f72:	movl %eax, 0xc(%ebx)
0x00405f75:	movl 0x4144c8, %eax
0x00405f7a:	xorl %eax, %eax
0x00405f7c:	movl -28(%ebp), %eax
0x00405f7f:	cmpl %eax, $0x5<UINT8>
0x00405f82:	jnl 0x00405f94
0x00405f84:	movw %cx, 0x10(%ebx,%eax,2)
0x00405f89:	movw 0x4144b4(,%eax,2), %cx
0x00405f91:	incl %eax
0x00405f92:	jmp 0x00405f7c
0x00405f94:	xorl %eax, %eax
0x00405f96:	movl -28(%ebp), %eax
0x00405f99:	cmpl %eax, $0x101<UINT32>
0x00405f9e:	jnl 0x00405fad
0x00405fa0:	movb %cl, 0x1c(%eax,%ebx)
0x00405fa4:	movb 0x4134c8(%eax), %cl
0x00405faa:	incl %eax
0x00405fab:	jmp 0x00405f96
0x00405fad:	xorl %eax, %eax
0x00405faf:	movl -28(%ebp), %eax
0x00405fb2:	cmpl %eax, $0x100<UINT32>
0x00405fb7:	jnl 0x00405fc9
0x00405fb9:	movb %cl, 0x11d(%eax,%ebx)
0x00405fc0:	movb 0x4135d0(%eax), %cl
0x00405fc6:	incl %eax
0x00405fc7:	jmp 0x00405faf
0x00405fc9:	pushl 0x4136d0
0x00405fcf:	call InterlockedDecrement@KERNEL32.DLL
0x00405fd5:	testl %eax, %eax
0x00405fd7:	jne 0x00405fec
0x00405fec:	movl 0x4136d0, %ebx
0x00405ff2:	pushl %ebx
0x00405ff3:	call InterlockedIncrement@KERNEL32.DLL
0x00405ff5:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00405ffc:	call 0x00406003
0x00406003:	pushl $0xd<UINT8>
0x00406005:	call 0x00403e80
0x0040600a:	popl %ecx
0x0040600b:	ret

0x00406001:	jmp 0x00406033
0x00406033:	movl %eax, -32(%ebp)
0x00406036:	call 0x00404acd
0x0040603b:	ret

0x0040604c:	popl %ecx
0x0040604d:	movl 0x415bec, $0x1<UINT32>
0x00406057:	xorl %eax, %eax
0x00406059:	ret

0x0040766e:	pushl $0x104<UINT32>
0x00407673:	movl %esi, $0x414868<UINT32>
0x00407678:	pushl %esi
0x00407679:	pushl %ebx
0x0040767a:	movb 0x41496c, %bl
0x00407680:	call GetModuleFileNameA@KERNEL32.DLL
GetModuleFileNameA@KERNEL32.DLL: API Node	
0x00407686:	movl %eax, 0x415c18
0x0040768b:	cmpl %eax, %ebx
0x0040768d:	movl 0x414534, %esi
0x00407693:	je 7
0x00407695:	cmpb (%eax), %bl
0x00407697:	movl -4(%ebp), %eax
0x0040769a:	jne 0x0040769f
0x0040769f:	movl %edx, -4(%ebp)
0x004076a2:	leal %eax, -8(%ebp)
0x004076a5:	pushl %eax
0x004076a6:	pushl %ebx
0x004076a7:	pushl %ebx
0x004076a8:	leal %edi, -12(%ebp)
0x004076ab:	call 0x004074be
0x004074be:	pushl %ebp
0x004074bf:	movl %ebp, %esp
0x004074c1:	pushl %ecx
0x004074c2:	movl %ecx, 0x10(%ebp)
0x004074c5:	pushl %ebx
0x004074c6:	xorl %eax, %eax
0x004074c8:	cmpl 0x8(%ebp), %eax
0x004074cb:	pushl %esi
0x004074cc:	movl (%edi), %eax
0x004074ce:	movl %esi, %edx
0x004074d0:	movl %edx, 0xc(%ebp)
0x004074d3:	movl (%ecx), $0x1<UINT32>
0x004074d9:	je 0x004074e4
0x004074e4:	movl -4(%ebp), %eax
0x004074e7:	cmpb (%esi), $0x22<UINT8>
0x004074ea:	jne 0x004074fc
0x004074ec:	xorl %eax, %eax
0x004074ee:	cmpl -4(%ebp), %eax
0x004074f1:	movb %bl, $0x22<UINT8>
0x004074f3:	sete %al
0x004074f6:	incl %esi
0x004074f7:	movl -4(%ebp), %eax
0x004074fa:	jmp 0x00407538
0x00407538:	cmpl -4(%ebp), $0x0<UINT8>
0x0040753c:	jne 0x004074e7
0x004074fc:	incl (%edi)
0x004074fe:	testl %edx, %edx
0x00407500:	je 0x0040750a
0x0040750a:	movb %bl, (%esi)
0x0040750c:	movzbl %eax, %bl
0x0040750f:	pushl %eax
0x00407510:	incl %esi
0x00407511:	call 0x0040b39c
0x0040b39c:	pushl $0x4<UINT8>
0x0040b39e:	pushl $0x0<UINT8>
0x0040b3a0:	pushl 0xc(%esp)
0x0040b3a4:	pushl $0x0<UINT8>
0x0040b3a6:	call 0x0040b34b
0x0040b34b:	pushl %ebp
0x0040b34c:	movl %ebp, %esp
0x0040b34e:	subl %esp, $0x10<UINT8>
0x0040b351:	pushl 0x8(%ebp)
0x0040b354:	leal %ecx, -16(%ebp)
0x0040b357:	call 0x004032d9
0x0040b35c:	movzbl %eax, 0xc(%ebp)
0x0040b360:	movl %ecx, -12(%ebp)
0x0040b363:	movb %dl, 0x14(%ebp)
0x0040b366:	testb 0x1d(%ecx,%eax), %dl
0x0040b36a:	jne 30
0x0040b36c:	cmpl 0x10(%ebp), $0x0<UINT8>
0x0040b370:	je 0x0040b384
0x0040b384:	xorl %eax, %eax
0x0040b386:	testl %eax, %eax
0x0040b388:	je 0x0040b38d
0x0040b38d:	cmpb -4(%ebp), $0x0<UINT8>
0x0040b391:	je 7
0x0040b393:	movl %ecx, -8(%ebp)
0x0040b396:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0040b39a:	leave
0x0040b39b:	ret

0x0040b3ab:	addl %esp, $0x10<UINT8>
0x0040b3ae:	ret

0x00407516:	testl %eax, %eax
0x00407518:	popl %ecx
0x00407519:	je 0x0040752e
0x0040752e:	testb %bl, %bl
0x00407530:	movl %edx, 0xc(%ebp)
0x00407533:	movl %ecx, 0x10(%ebp)
0x00407536:	je 0x0040756a
0x0040753e:	cmpb %bl, $0x20<UINT8>
0x00407541:	je 5
0x00407543:	cmpb %bl, $0x9<UINT8>
0x00407546:	jne 0x004074e7
0x0040756a:	decl %esi
0x0040756b:	jmp 0x00407550
0x00407550:	andl -4(%ebp), $0x0<UINT8>
0x00407554:	cmpb (%esi), $0x0<UINT8>
0x00407557:	je 0x00407646
0x00407646:	movl %eax, 0x8(%ebp)
0x00407649:	testl %eax, %eax
0x0040764b:	popl %esi
0x0040764c:	popl %ebx
0x0040764d:	je 0x00407652
0x00407652:	incl (%ecx)
0x00407654:	leave
0x00407655:	ret

0x004076b0:	movl %eax, -8(%ebp)
0x004076b3:	addl %esp, $0xc<UINT8>
0x004076b6:	cmpl %eax, $0x3fffffff<UINT32>
0x004076bb:	jae 74
0x004076bd:	movl %ecx, -12(%ebp)
0x004076c0:	cmpl %ecx, $0xffffffff<UINT8>
0x004076c3:	jae 66
0x004076c5:	movl %edi, %eax
0x004076c7:	shll %edi, $0x2<UINT8>
0x004076ca:	leal %eax, (%edi,%ecx)
0x004076cd:	cmpl %eax, %ecx
0x004076cf:	jb 54
0x004076d1:	pushl %eax
0x004076d2:	call 0x00407c47
0x004076d7:	movl %esi, %eax
0x004076d9:	cmpl %esi, %ebx
0x004076db:	popl %ecx
0x004076dc:	je 41
0x004076de:	movl %edx, -4(%ebp)
0x004076e1:	leal %eax, -8(%ebp)
0x004076e4:	pushl %eax
0x004076e5:	addl %edi, %esi
0x004076e7:	pushl %edi
0x004076e8:	pushl %esi
0x004076e9:	leal %edi, -12(%ebp)
0x004076ec:	call 0x004074be
0x004074db:	movl %ebx, 0x8(%ebp)
0x004074de:	addl 0x8(%ebp), $0x4<UINT8>
0x004074e2:	movl (%ebx), %edx
0x00407502:	movb %al, (%esi)
0x00407504:	movb (%edx), %al
0x00407506:	incl %edx
0x00407507:	movl 0xc(%ebp), %edx
0x0040764f:	andl (%eax), $0x0<UINT8>
0x004076f1:	movl %eax, -8(%ebp)
0x004076f4:	addl %esp, $0xc<UINT8>
0x004076f7:	decl %eax
0x004076f8:	movl 0x414518, %eax
0x004076fd:	movl 0x41451c, %esi
0x00407703:	xorl %eax, %eax
0x00407705:	jmp 0x0040770a
0x0040770a:	popl %edi
0x0040770b:	popl %esi
0x0040770c:	popl %ebx
0x0040770d:	leave
0x0040770e:	ret

0x00403ae7:	testl %eax, %eax
0x00403ae9:	jnl 0x00403af3
0x00403af3:	call 0x004073e3
0x004073e3:	pushl %ebx
0x004073e4:	xorl %ebx, %ebx
0x004073e6:	cmpl 0x415bec, %ebx
0x004073ec:	pushl %esi
0x004073ed:	pushl %edi
0x004073ee:	jne 0x004073f5
0x004073f5:	movl %esi, 0x414020
0x004073fb:	xorl %edi, %edi
0x004073fd:	cmpl %esi, %ebx
0x004073ff:	jne 0x00407419
0x00407419:	movb %al, (%esi)
0x0040741b:	cmpb %al, %bl
0x0040741d:	jne 0x00407409
0x00407409:	cmpb %al, $0x3d<UINT8>
0x0040740b:	je 0x0040740e
0x0040740e:	pushl %esi
0x0040740f:	call 0x00408fe0
0x00408fe0:	movl %ecx, 0x4(%esp)
0x00408fe4:	testl %ecx, $0x3<UINT32>
0x00408fea:	je 0x00409010
0x00409010:	movl %eax, (%ecx)
0x00409012:	movl %edx, $0x7efefeff<UINT32>
0x00409017:	addl %edx, %eax
0x00409019:	xorl %eax, $0xffffffff<UINT8>
0x0040901c:	xorl %eax, %edx
0x0040901e:	addl %ecx, $0x4<UINT8>
0x00409021:	testl %eax, $0x81010100<UINT32>
0x00409026:	je 0x00409010
0x00409028:	movl %eax, -4(%ecx)
0x0040902b:	testb %al, %al
0x0040902d:	je 50
0x0040902f:	testb %ah, %ah
0x00409031:	je 36
0x00409033:	testl %eax, $0xff0000<UINT32>
0x00409038:	je 19
0x0040903a:	testl %eax, $0xff000000<UINT32>
0x0040903f:	je 0x00409043
0x00409043:	leal %eax, -1(%ecx)
0x00409046:	movl %ecx, 0x4(%esp)
0x0040904a:	subl %eax, %ecx
0x0040904c:	ret

0x00407414:	popl %ecx
0x00407415:	leal %esi, 0x1(%esi,%eax)
0x0040741f:	pushl $0x4<UINT8>
0x00407421:	incl %edi
0x00407422:	pushl %edi
0x00407423:	call 0x00407c87
0x00407428:	movl %edi, %eax
0x0040742a:	cmpl %edi, %ebx
0x0040742c:	popl %ecx
0x0040742d:	popl %ecx
0x0040742e:	movl 0x414524, %edi
0x00407434:	je -53
0x00407436:	movl %esi, 0x414020
0x0040743c:	pushl %ebp
0x0040743d:	jmp 0x0040747f
0x0040747f:	cmpb (%esi), %bl
0x00407481:	jne 0x0040743f
0x0040743f:	pushl %esi
0x00407440:	call 0x00408fe0
0x00407445:	movl %ebp, %eax
0x00407447:	incl %ebp
0x00407448:	cmpb (%esi), $0x3d<UINT8>
0x0040744b:	popl %ecx
0x0040744c:	je 0x0040747d
0x0040747d:	addl %esi, %ebp
0x00407483:	pushl 0x414020
0x00407489:	call 0x00403199
0x00403199:	pushl $0xc<UINT8>
0x0040319b:	pushl $0x4119b0<UINT32>
0x004031a0:	call 0x00404a88
0x004031a5:	movl %esi, 0x8(%ebp)
0x004031a8:	testl %esi, %esi
0x004031aa:	je 117
0x004031ac:	cmpl 0x415c14, $0x3<UINT8>
0x004031b3:	jne 0x004031f8
0x004031f8:	pushl %esi
0x004031f9:	pushl $0x0<UINT8>
0x004031fb:	pushl 0x414354
0x00403201:	call HeapFree@KERNEL32.DLL
0x00403207:	testl %eax, %eax
0x00403209:	jne 0x00403221
0x00403221:	call 0x00404acd
0x00403226:	ret

0x0040748e:	movl 0x414020, %ebx
0x00407494:	movl (%edi), %ebx
0x00407496:	movl 0x415be0, $0x1<UINT32>
0x004074a0:	xorl %eax, %eax
0x004074a2:	popl %ecx
0x004074a3:	popl %ebp
0x004074a4:	popl %edi
0x004074a5:	popl %esi
0x004074a6:	popl %ebx
0x004074a7:	ret

0x00403af8:	testl %eax, %eax
0x00403afa:	jnl 0x00403b04
0x00403b04:	pushl %ebx
0x00403b05:	call 0x00406ae5
0x00406ae5:	cmpl 0x415bf0, $0x0<UINT8>
0x00406aec:	je 0x00406b08
0x00406b08:	call 0x00408fa7
0x00408fa7:	pushl %esi
0x00408fa8:	pushl %edi
0x00408fa9:	xorl %edi, %edi
0x00408fab:	leal %esi, 0x413cd8(%edi)
0x00408fb1:	pushl (%esi)
0x00408fb3:	call 0x004063cc
0x004063e9:	pushl %eax
0x004063ea:	pushl 0x4138c4
0x004063f0:	call TlsGetValue@KERNEL32.DLL
0x004063f2:	call FlsGetValue@KERNEL32.DLL
0x004063f4:	testl %eax, %eax
0x004063f6:	je 8
0x004063f8:	movl %eax, 0x1f8(%eax)
0x004063fe:	jmp 0x00406426
0x00408fb8:	addl %edi, $0x4<UINT8>
0x00408fbb:	cmpl %edi, $0x28<UINT8>
0x00408fbe:	popl %ecx
0x00408fbf:	movl (%esi), %eax
0x00408fc1:	jb 0x00408fab
0x00408fc3:	popl %edi
0x00408fc4:	popl %esi
0x00408fc5:	ret

0x00406b0d:	pushl $0x40d288<UINT32>
0x00406b12:	pushl $0x40d26c<UINT32>
0x00406b17:	call 0x00406a52
0x00406a52:	pushl %esi
0x00406a53:	movl %esi, 0x8(%esp)
0x00406a57:	xorl %eax, %eax
0x00406a59:	jmp 0x00406a6a
0x00406a6a:	cmpl %esi, 0xc(%esp)
0x00406a6e:	jb 0x00406a5b
0x00406a5b:	testl %eax, %eax
0x00406a5d:	jne 17
0x00406a5f:	movl %ecx, (%esi)
0x00406a61:	testl %ecx, %ecx
0x00406a63:	je 0x00406a67
0x00406a67:	addl %esi, $0x4<UINT8>
0x00406a65:	call 0x00407219
0x00408c01:	movl %eax, 0x415ac0
0x00408c06:	testl %eax, %eax
0x00408c08:	pushl %esi
0x00408c09:	pushl $0x14<UINT8>
0x00408c0b:	popl %esi
0x00408c0c:	jne 7
0x00408c0e:	movl %eax, $0x200<UINT32>
0x00408c13:	jmp 0x00408c1b
0x00408c1b:	movl 0x415ac0, %eax
0x00408c20:	pushl $0x4<UINT8>
0x00408c22:	pushl %eax
0x00408c23:	call 0x00407c87
0x00408c28:	testl %eax, %eax
0x00408c2a:	popl %ecx
0x00408c2b:	popl %ecx
0x00408c2c:	movl 0x414ab4, %eax
0x00408c31:	jne 0x00408c51
0x00408c51:	xorl %edx, %edx
0x00408c53:	movl %ecx, $0x413a50<UINT32>
0x00408c58:	jmp 0x00408c5f
0x00408c5f:	movl (%edx,%eax), %ecx
0x00408c62:	addl %ecx, $0x20<UINT8>
0x00408c65:	addl %edx, $0x4<UINT8>
0x00408c68:	cmpl %ecx, $0x413cd0<UINT32>
0x00408c6e:	jl 0x00408c5a
0x00408c5a:	movl %eax, 0x414ab4
0x00408c70:	pushl $0xfffffffe<UINT8>
0x00408c72:	popl %esi
0x00408c73:	xorl %edx, %edx
0x00408c75:	movl %ecx, $0x413a60<UINT32>
0x00408c7a:	pushl %edi
0x00408c7b:	movl %edi, %edx
0x00408c7d:	andl %edi, $0x1f<UINT8>
0x00408c80:	imull %edi, %edi, $0x38<UINT8>
0x00408c83:	movl %eax, %edx
0x00408c85:	sarl %eax, $0x5<UINT8>
0x00408c88:	movl %eax, 0x415ae0(,%eax,4)
0x00408c8f:	movl %eax, (%edi,%eax)
0x00408c92:	cmpl %eax, $0xffffffff<UINT8>
0x00408c95:	je 8
0x00408c97:	cmpl %eax, %esi
0x00408c99:	je 4
0x00408c9b:	testl %eax, %eax
0x00408c9d:	jne 0x00408ca1
0x00408ca1:	addl %ecx, $0x20<UINT8>
0x00408ca4:	incl %edx
0x00408ca5:	cmpl %ecx, $0x413ac0<UINT32>
0x00408cab:	jl 0x00408c7b
0x00408cad:	popl %edi
0x00408cae:	xorl %eax, %eax
0x00408cb0:	popl %esi
0x00408cb1:	ret

0x0040ac3b:	pushl %esi
0x0040ac3c:	pushl $0x4<UINT8>
0x0040ac3e:	pushl $0x20<UINT8>
0x0040ac40:	call 0x00407c87
0x0040ac45:	movl %esi, %eax
0x0040ac47:	pushl %esi
0x0040ac48:	call 0x004063cc
0x0040ac4d:	addl %esp, $0xc<UINT8>
0x0040ac50:	testl %esi, %esi
0x0040ac52:	movl 0x415be8, %eax
0x0040ac57:	movl 0x415be4, %eax
0x0040ac5c:	jne 0x0040ac63
0x0040ac63:	andl (%esi), $0x0<UINT8>
0x0040ac66:	xorl %eax, %eax
0x0040ac68:	popl %esi
0x0040ac69:	ret

0x0040b852:	andl 0x414aac, $0x0<UINT8>
0x0040b859:	call 0x0040c66d
0x0040c66d:	pushl %ebp
0x0040c66e:	movl %ebp, %esp
0x0040c670:	subl %esp, $0x18<UINT8>
0x0040c673:	xorl %eax, %eax
0x0040c675:	pushl %ebx
0x0040c676:	movl -4(%ebp), %eax
0x0040c679:	movl -12(%ebp), %eax
0x0040c67c:	movl -8(%ebp), %eax
0x0040c67f:	pushl %ebx
0x0040c680:	pushfl
0x0040c681:	popl %eax
0x0040c682:	movl %ecx, %eax
0x0040c684:	xorl %eax, $0x200000<UINT32>
0x0040c689:	pushl %eax
0x0040c68a:	popfl
0x0040c68b:	pushfl
0x0040c68c:	popl %edx
0x0040c68d:	subl %edx, %ecx
0x0040c68f:	je 0x0040c6b0
0x0040c6b0:	popl %ebx
0x0040c6b1:	testl -4(%ebp), $0x4000000<UINT32>
0x0040c6b8:	je 0x0040c6c8
0x0040c6c8:	xorl %eax, %eax
0x0040c6ca:	popl %ebx
0x0040c6cb:	leave
0x0040c6cc:	ret

0x0040b85e:	movl 0x414aac, %eax
0x0040b863:	xorl %eax, %eax
0x0040b865:	ret

0x0040c6cd:	call 0x0040c66d
0x0040c6d2:	movl 0x414ab0, %eax
0x0040c6d7:	xorl %eax, %eax
0x0040c6d9:	ret

0x00407219:	pushl $0x4071dc<UINT32>
0x0040721e:	call SetUnhandledExceptionFilter@KERNEL32.DLL
SetUnhandledExceptionFilter@KERNEL32.DLL: API Node	
0x00407224:	xorl %eax, %eax
0x00407226:	ret

0x00406a70:	popl %esi
0x00406a71:	ret

0x00406b1c:	testl %eax, %eax
0x00406b1e:	popl %ecx
0x00406b1f:	popl %ecx
0x00406b20:	jne 84
0x00406b22:	pushl %esi
0x00406b23:	pushl %edi
0x00406b24:	pushl $0x407aa8<UINT32>
0x00406b29:	call 0x0040aca6
0x0040aca6:	pushl 0x4(%esp)
0x0040acaa:	call 0x0040ac6a
0x0040ac6a:	pushl $0xc<UINT8>
0x0040ac6c:	pushl $0x411ba0<UINT32>
0x0040ac71:	call 0x00404a88
0x0040ac76:	call 0x00406a28
0x00406a28:	pushl $0x8<UINT8>
0x00406a2a:	call 0x00403f58
0x00406a2f:	popl %ecx
0x00406a30:	ret

0x0040ac7b:	andl -4(%ebp), $0x0<UINT8>
0x0040ac7f:	pushl 0x8(%ebp)
0x0040ac82:	call 0x0040ab82
0x0040ab82:	pushl %ecx
0x0040ab83:	pushl %ebx
0x0040ab84:	pushl %ebp
0x0040ab85:	pushl %esi
0x0040ab86:	pushl %edi
0x0040ab87:	pushl 0x415be8
0x0040ab8d:	call 0x00406443
0x0040ab92:	pushl 0x415be4
0x0040ab98:	movl %esi, %eax
0x0040ab9a:	movl 0x18(%esp), %esi
0x0040ab9e:	call 0x00406443
0x0040aba3:	movl %edi, %eax
0x0040aba5:	cmpl %edi, %esi
0x0040aba7:	popl %ecx
0x0040aba8:	popl %ecx
0x0040aba9:	jb 132
0x0040abaf:	movl %ebx, %edi
0x0040abb1:	subl %ebx, %esi
0x0040abb3:	leal %ebp, 0x4(%ebx)
0x0040abb6:	cmpl %ebp, $0x4<UINT8>
0x0040abb9:	jb 120
0x0040abbb:	pushl %esi
0x0040abbc:	call 0x0040c487
0x0040c487:	pushl $0x10<UINT8>
0x0040c489:	pushl $0x411ca8<UINT32>
0x0040c48e:	call 0x00404a88
0x0040c493:	xorl %eax, %eax
0x0040c495:	movl %ebx, 0x8(%ebp)
0x0040c498:	xorl %edi, %edi
0x0040c49a:	cmpl %ebx, %edi
0x0040c49c:	setne %al
0x0040c49f:	cmpl %eax, %edi
0x0040c4a1:	jne 0x0040c4c0
0x0040c4c0:	cmpl 0x415c14, $0x3<UINT8>
0x0040c4c7:	jne 0x0040c501
0x0040c501:	pushl %ebx
0x0040c502:	pushl %edi
0x0040c503:	pushl 0x414354
0x0040c509:	call HeapSize@KERNEL32.DLL
HeapSize@KERNEL32.DLL: API Node	
0x0040c50f:	movl %esi, %eax
0x0040c511:	movl %eax, %esi
0x0040c513:	call 0x00404acd
0x0040c518:	ret

0x0040abc1:	movl %esi, %eax
0x0040abc3:	cmpl %esi, %ebp
0x0040abc5:	popl %ecx
0x0040abc6:	jae 0x0040ac12
0x0040ac12:	pushl 0x18(%esp)
0x0040ac16:	call 0x004063cc
0x0040ac1b:	movl (%edi), %eax
0x0040ac1d:	addl %edi, $0x4<UINT8>
0x0040ac20:	pushl %edi
0x0040ac21:	call 0x004063cc
0x0040ac26:	popl %ecx
0x0040ac27:	movl 0x415be4, %eax
0x0040ac2c:	movl %eax, 0x1c(%esp)
0x0040ac30:	popl %ecx
0x0040ac31:	jmp 0x0040ac35
0x0040ac35:	popl %edi
0x0040ac36:	popl %esi
0x0040ac37:	popl %ebp
0x0040ac38:	popl %ebx
0x0040ac39:	popl %ecx
0x0040ac3a:	ret

0x0040ac87:	popl %ecx
0x0040ac88:	movl -28(%ebp), %eax
0x0040ac8b:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040ac92:	call 0x0040aca0
0x0040aca0:	call 0x00406a31
0x00406a31:	pushl $0x8<UINT8>
0x00406a33:	call 0x00403e80
0x00406a38:	popl %ecx
0x00406a39:	ret

0x0040aca5:	ret

0x0040ac97:	movl %eax, -28(%ebp)
0x0040ac9a:	call 0x00404acd
0x0040ac9f:	ret

0x0040acaf:	negl %eax
0x0040acb1:	sbbl %eax, %eax
0x0040acb3:	negl %eax
0x0040acb5:	popl %ecx
0x0040acb6:	decl %eax
0x0040acb7:	ret

0x00406b2e:	movl %esi, $0x40d264<UINT32>
0x00406b33:	movl %eax, %esi
0x00406b35:	movl %edi, $0x40d268<UINT32>
0x00406b3a:	cmpl %eax, %edi
0x00406b3c:	popl %ecx
0x00406b3d:	jae 15
0x00406b3f:	movl %eax, (%esi)
0x00406b41:	testl %eax, %eax
0x00406b43:	je 0x00406b47
0x00406b47:	addl %esi, $0x4<UINT8>
0x00406b4a:	cmpl %esi, %edi
0x00406b4c:	jb -15
0x00406b4e:	cmpl 0x415bf4, $0x0<UINT8>
0x00406b55:	popl %edi
0x00406b56:	popl %esi
0x00406b57:	je 0x00406b74
0x00406b74:	xorl %eax, %eax
0x00406b76:	ret

0x00403b0a:	popl %ecx
0x00403b0b:	testl %eax, %eax
0x00403b0d:	je 0x00403b16
0x00403b16:	call 0x00407386
0x00407386:	pushl %esi
0x00407387:	pushl %edi
0x00407388:	xorl %edi, %edi
0x0040738a:	cmpl 0x415bec, %edi
0x00407390:	jne 0x00407397
0x00407397:	movl %esi, 0x415c18
0x0040739d:	testl %esi, %esi
0x0040739f:	jne 0x004073a6
0x004073a6:	movb %al, (%esi)
0x004073a8:	cmpb %al, $0x20<UINT8>
0x004073aa:	ja 0x004073b4
0x004073b4:	cmpb %al, $0x22<UINT8>
0x004073b6:	jne 0x004073c1
0x004073b8:	xorl %ecx, %ecx
0x004073ba:	testl %edi, %edi
0x004073bc:	sete %cl
0x004073bf:	movl %edi, %ecx
0x004073c1:	movzbl %eax, %al
0x004073c4:	pushl %eax
0x004073c5:	call 0x0040b39c
0x004073ca:	testl %eax, %eax
0x004073cc:	popl %ecx
0x004073cd:	je 0x004073d0
0x004073d0:	incl %esi
0x004073d1:	jmp 0x004073a6
0x004073ac:	testb %al, %al
0x004073ae:	je 0x004073de
0x004073de:	popl %edi
0x004073df:	movl %eax, %esi
0x004073e1:	popl %esi
0x004073e2:	ret

0x00403b1b:	testb -68(%ebp), %bl
0x00403b1e:	je 0x00403b26
0x00403b26:	pushl $0xa<UINT8>
0x00403b28:	popl %ecx
0x00403b29:	pushl %ecx
0x00403b2a:	pushl %eax
0x00403b2b:	pushl $0x0<UINT8>
0x00403b2d:	pushl $0x400000<UINT32>
0x00403b32:	call 0x00402990
0x00402990:	pushl %ecx
0x00402991:	leal %eax, (%esp)
0x00402994:	pushl %eax
0x00402995:	call GetCommandLineW@KERNEL32.DLL
GetCommandLineW@KERNEL32.DLL: API Node	
0x0040299b:	pushl %eax
0x0040299c:	call CommandLineToArgvW@SHELL32.dll
CommandLineToArgvW@SHELL32.dll: API Node	
0x004029a2:	movl %ecx, (%esp)
0x004029a5:	pushl %ecx
0x004029a6:	movl %ecx, 0xc(%esp)
0x004029aa:	movl %edx, %eax
0x004029ac:	call 0x00402050
0x00402050:	pushl %ebp
0x00402051:	movl %ebp, %esp
0x00402053:	andl %esp, $0xfffffff8<UINT8>
0x00402056:	subl %esp, $0xff4<UINT32>
0x0040205c:	movl %eax, 0x413004
0x00402061:	xorl %eax, %esp
0x00402063:	movl 0xff0(%esp), %eax
0x0040206a:	pushl %ebx
0x0040206b:	pushl %esi
0x0040206c:	pushl %edi
0x0040206d:	xorl %ebx, %ebx
0x0040206f:	pushl $0x2a2<UINT32>
0x00402074:	leal %eax, 0x53e(%esp)
0x0040207b:	movl %edi, %edx
0x0040207d:	pushl %ebx
0x0040207e:	pushl %eax
0x0040207f:	movl %esi, %ecx
0x00402081:	movl 0x20(%esp), %edi
0x00402085:	movl 0x18(%esp), %ebx
0x00402089:	movw 0x544(%esp), %bx
0x00402091:	call 0x00409280
0x004092bb:	subl %edx, %ecx
0x004092bd:	movb (%edi), %al
0x004092bf:	addl %edi, $0x1<UINT8>
0x004092c2:	subl %ecx, $0x1<UINT8>
0x004092c5:	jne 0x004092bd
0x00402096:	addl %esp, $0xc<UINT8>
0x00402099:	pushl $0x402<UINT32>
0x0040209e:	leal %ecx, 0x7e6(%esp)
0x004020a5:	pushl %ebx
0x004020a6:	pushl %ecx
0x004020a7:	movw 0x7ec(%esp), %bx
0x004020af:	call 0x00409280
0x004020b4:	addl %esp, $0xc<UINT8>
0x004020b7:	pushl $0x200<UINT32>
0x004020bc:	leal %edx, 0x336(%esp)
0x004020c3:	pushl %ebx
0x004020c4:	pushl %edx
0x004020c5:	movw 0x33c(%esp), %bx
0x004020cd:	call 0x00409280
0x004020d2:	addl %esp, $0xc<UINT8>
0x004020d5:	pushl $0x206<UINT32>
0x004020da:	leal %eax, 0x12e(%esp)
0x004020e1:	pushl %ebx
0x004020e2:	pushl %eax
0x004020e3:	movw 0x134(%esp), %bx
0x004020eb:	call 0x00409280
0x004020f0:	addl %esp, $0xc<UINT8>
0x004020f3:	pushl $0x40<UINT8>
0x004020f5:	leal %ecx, 0xa0(%esp)
0x004020fc:	pushl %ebx
0x004020fd:	pushl %ecx
0x004020fe:	movl 0xa4(%esp), %ebx
0x00402105:	call 0x00409280
0x0040210a:	xorl %eax, %eax
0x0040210c:	movl 0x34(%esp), %ebx
0x00402110:	movl 0x2c(%esp), %ebx
0x00402114:	movl 0x44(%esp), %ebx
0x00402118:	movb 0x28(%esp), %bl
0x0040211c:	movb 0x1f(%esp), %bl
0x00402120:	movb 0x27(%esp), %bl
0x00402124:	movl %ebx, %edi
0x00402126:	addl %esp, $0xc<UINT8>
0x00402129:	leal %edi, 0x8(%ebp)
0x0040212c:	movl 0x2c(%esp), %eax
0x00402130:	movl 0x30(%esp), %eax
0x00402134:	movl 0x34(%esp), %eax
0x00402138:	call 0x00401800
0x00401800:	pushl %ebp
0x00401801:	xorl %ebp, %ebp
0x00401803:	testl %edi, %edi
0x00401805:	je 94
0x00401807:	pushl %esi
0x00401808:	xorl %esi, %esi
0x0040180a:	cmpl (%edi), %esi
0x0040180c:	jle 86
0x0040180e:	movl %edi, %edi
0x00401810:	movl %eax, (%ebx,%esi,4)
0x00401813:	pushl $0x4109cc<UINT32>
0x00401818:	pushl %eax
0x00401819:	call 0x0040346a
0x0040346a:	pushl %esi
0x0040346b:	xorl %esi, %esi
0x0040346d:	cmpl 0x4144cc, %esi
0x00403473:	pushl %edi
0x00403474:	jne 113
0x00403476:	movl %edi, 0xc(%esp)
0x0040347a:	cmpl %edi, %esi
0x0040347c:	jne 0x0040349d
0x0040349d:	movl %edx, 0x10(%esp)
0x004034a1:	cmpl %edx, %esi
0x004034a3:	je -39
0x004034a5:	movzwl %eax, (%edi)
0x004034a8:	cmpw %ax, $0x41<UINT16>
0x004034ac:	jb 0x004034b7
0x004034b7:	movzwl %ecx, %ax
0x004034ba:	movzwl %eax, (%edx)
0x004034bd:	cmpw %ax, $0x41<UINT16>
0x004034c1:	jb 0x004034cc
0x004034cc:	incl %edi
0x004034cd:	incl %edi
0x004034ce:	incl %edx
0x004034cf:	incl %edx
0x004034d0:	cmpw %cx, %si
0x004034d3:	movzwl %eax, %ax
0x004034d6:	je 0x004034dd
0x004034dd:	movzwl %edx, %ax
0x004034e0:	movzwl %eax, %cx
0x004034e3:	subl %eax, %edx
0x004034e5:	jmp 0x004034f8
0x004034f8:	popl %edi
0x004034f9:	popl %esi
0x004034fa:	ret

0x0040181e:	addl %esp, $0x8<UINT8>
0x00401821:	testl %eax, %eax
0x00401823:	je 30
0x00401825:	movl %ecx, (%ebx,%esi,4)
0x00401828:	pushl $0x4109e4<UINT32>
0x0040182d:	pushl %ecx
0x0040182e:	call 0x0040346a
0x00401833:	addl %esp, $0x8<UINT8>
0x00401836:	testl %eax, %eax
0x00401838:	je 9
0x0040183a:	addl %esi, $0x1<UINT8>
0x0040183d:	cmpl %esi, (%edi)
0x0040183f:	jl 0x00401810
0x00401841:	jmp 0x00401864
0x00401864:	popl %esi
0x00401865:	pushl %ebp
0x00401866:	call 0x00401470
0x00401470:	subl %esp, $0x214<UINT32>
0x00401476:	movl %eax, 0x413004
0x0040147b:	xorl %eax, %esp
0x0040147d:	movl 0x210(%esp), %eax
0x00401484:	pushl %ebp
0x00401485:	pushl $0x410a18<UINT32>
0x0040148a:	leal %eax, 0x10(%esp)
0x0040148e:	pushl $0x410840<UINT32>
0x00401493:	xorl %ebp, %ebp
0x00401495:	pushl %eax
0x00401496:	movl 0x10(%esp), %ebp
0x0040149a:	call 0x00403227
0x00403227:	pushl %ebp
0x00403228:	movl %ebp, %esp
0x0040322a:	subl %esp, $0x20<UINT8>
0x0040322d:	pushl %ebx
0x0040322e:	xorl %ebx, %ebx
0x00403230:	cmpl 0xc(%ebp), %ebx
0x00403233:	jne 0x00403252
0x00403252:	movl %eax, 0x8(%ebp)
0x00403255:	cmpl %eax, %ebx
0x00403257:	je -36
0x00403259:	pushl %esi
0x0040325a:	movl -24(%ebp), %eax
0x0040325d:	movl -32(%ebp), %eax
0x00403260:	leal %eax, 0x10(%ebp)
0x00403263:	pushl %eax
0x00403264:	pushl %ebx
0x00403265:	pushl 0xc(%ebp)
0x00403268:	leal %eax, -32(%ebp)
0x0040326b:	pushl %eax
0x0040326c:	movl -20(%ebp), $0x42<UINT32>
0x00403273:	movl -28(%ebp), $0x7fffffff<UINT32>
0x0040327a:	call 0x00404de6
0x00404de6:	pushl %ebp
0x00404de7:	leal %ebp, -1012(%esp)
0x00404dee:	subl %esp, $0x474<UINT32>
0x00404df4:	movl %eax, 0x413004
0x00404df9:	xorl %eax, %ebp
0x00404dfb:	movl 0x3f0(%ebp), %eax
0x00404e01:	movl %eax, 0x3fc(%ebp)
0x00404e07:	pushl %ebx
0x00404e08:	movl %ebx, 0x408(%ebp)
0x00404e0e:	pushl %esi
0x00404e0f:	movl %esi, 0x400(%ebp)
0x00404e15:	pushl %edi
0x00404e16:	pushl 0x404(%ebp)
0x00404e1c:	xorl %edi, %edi
0x00404e1e:	leal %ecx, -100(%ebp)
0x00404e21:	movl -60(%ebp), %eax
0x00404e24:	movl -40(%ebp), %ebx
0x00404e27:	movl -84(%ebp), %edi
0x00404e2a:	movl -20(%ebp), %edi
0x00404e2d:	movl -56(%ebp), %edi
0x00404e30:	movl -24(%ebp), %edi
0x00404e33:	movl -48(%ebp), %edi
0x00404e36:	movl -72(%ebp), %edi
0x00404e39:	movl -52(%ebp), %edi
0x00404e3c:	call 0x004032d9
0x00404e41:	cmpl -60(%ebp), %edi
0x00404e44:	jne 0x00404e73
0x00404e73:	cmpl %esi, %edi
0x00404e75:	je -49
0x00404e77:	movzwl %edx, (%esi)
0x00404e7a:	xorl %ecx, %ecx
0x00404e7c:	cmpw %dx, %di
0x00404e7f:	movl -44(%ebp), %edi
0x00404e82:	movl -32(%ebp), %edi
0x00404e85:	movl -80(%ebp), %edi
0x00404e88:	movl -36(%ebp), %edx
0x00404e8b:	je 2077
0x00404e91:	pushl $0x2<UINT8>
0x00404e93:	popl %edi
0x00404e94:	addl %esi, %edi
0x00404e96:	cmpl -44(%ebp), $0x0<UINT8>
0x00404e9a:	movl -76(%ebp), %esi
0x00404e9d:	jl 2059
0x00404ea3:	leal %eax, -32(%edx)
0x00404ea6:	cmpw %ax, $0x58<UINT16>
0x00404eaa:	ja 0x00404ebb
0x00404eac:	movzwl %eax, %dx
0x00404eaf:	movzbl %eax, 0x40da10(%eax)
0x00404eb6:	andl %eax, $0xf<UINT8>
0x00404eb9:	jmp 0x00404ebd
0x00404ebd:	movsbl %eax, 0x40da30(%ecx,%eax,8)
0x00404ec5:	pushl $0x7<UINT8>
0x00404ec7:	sarl %eax, $0x4<UINT8>
0x00404eca:	popl %ecx
0x00404ecb:	cmpl %eax, %ecx
0x00404ecd:	movl -104(%ebp), %eax
0x00404ed0:	ja 1958
0x00404ed6:	jmp 0x004050ad
0x00405095:	movl %eax, -60(%ebp)
0x00405098:	pushl %edx
0x00405099:	leal %esi, -44(%ebp)
0x0040509c:	movl -52(%ebp), $0x1<UINT32>
0x004050a3:	call 0x004092fa
0x004092fa:	testb 0xc(%eax), $0x40<UINT8>
0x004092fe:	je 6
0x00409300:	cmpl 0x8(%eax), $0x0<UINT8>
0x00409304:	je 22
0x00409306:	pushl %eax
0x00409307:	pushl 0x8(%esp)
0x0040930b:	call 0x00408dc9
0x00408dc9:	pushl %ebp
0x00408dca:	movl %ebp, %esp
0x00408dcc:	subl %esp, $0x10<UINT8>
0x00408dcf:	movl %eax, 0x413004
0x00408dd4:	xorl %eax, %ebp
0x00408dd6:	movl -4(%ebp), %eax
0x00408dd9:	pushl %ebx
0x00408dda:	pushl %esi
0x00408ddb:	movl %esi, 0xc(%ebp)
0x00408dde:	testb 0xc(%esi), $0x40<UINT8>
0x00408de2:	pushl %edi
0x00408de3:	jne 0x00408f78
0x00408f78:	addl 0x4(%esi), $0xfffffffe<UINT8>
0x00408f7c:	js 13
0x00408f7e:	movl %ecx, (%esi)
0x00408f80:	movl %eax, 0x8(%ebp)
0x00408f83:	movw (%ecx), %ax
0x00408f86:	addl (%esi), $0x2<UINT8>
0x00408f89:	jmp 0x00408f98
0x00408f98:	movl %ecx, -4(%ebp)
0x00408f9b:	popl %edi
0x00408f9c:	popl %esi
0x00408f9d:	xorl %ecx, %ebp
0x00408f9f:	popl %ebx
0x00408fa0:	call 0x0040318a
0x00408fa5:	leave
0x00408fa6:	ret

0x00409310:	cmpw %ax, $0xffffffff<UINT16>
0x00409314:	popl %ecx
0x00409315:	popl %ecx
0x00409316:	jne 0x0040931c
0x0040931c:	incl (%esi)
0x0040931e:	ret

0x004050a8:	jmp 0x0040567b
0x0040567b:	popl %ecx
0x0040567c:	movl %esi, -76(%ebp)
0x0040567f:	movzwl %eax, (%esi)
0x00405682:	testw %ax, %ax
0x00405685:	movl -36(%ebp), %eax
0x00405688:	je 0x004056ae
0x0040568a:	movl %ecx, -104(%ebp)
0x0040568d:	movl %ebx, -40(%ebp)
0x00405690:	movl %edx, %eax
0x00405692:	jmp 0x00404e91
0x00404ebb:	xorl %eax, %eax
0x00404edd:	xorl %eax, %eax
0x00404edf:	orl -24(%ebp), $0xffffffff<UINT8>
0x00404ee3:	movl -108(%ebp), %eax
0x00404ee6:	movl -72(%ebp), %eax
0x00404ee9:	movl -56(%ebp), %eax
0x00404eec:	movl -48(%ebp), %eax
0x00404eef:	movl -20(%ebp), %eax
0x00404ef2:	movl -52(%ebp), %eax
0x00404ef5:	jmp 0x0040567c
0x004050ad:	movzwl %eax, %dx
0x004050b0:	cmpl %eax, $0x64<UINT8>
0x004050b3:	jg 0x00405260
0x00405260:	cmpl %eax, $0x70<UINT8>
0x00405263:	jg 0x004053f0
0x004053f0:	subl %eax, $0x73<UINT8>
0x004053f3:	je 0x00405135
0x00405135:	movl %edi, -24(%ebp)
0x00405138:	cmpl %edi, $0xffffffff<UINT8>
0x0040513b:	jne 5
0x0040513d:	movl %edi, $0x7fffffff<UINT32>
0x00405142:	addl %ebx, $0x4<UINT8>
0x00405145:	testb -20(%ebp), $0x20<UINT8>
0x00405149:	movl -40(%ebp), %ebx
0x0040514c:	movl %ebx, -4(%ebx)
0x0040514f:	movl -28(%ebp), %ebx
0x00405152:	je 0x00405533
0x00405533:	testl %ebx, %ebx
0x00405535:	jne 0x0040553f
0x0040553f:	movl %eax, -28(%ebp)
0x00405542:	movl -52(%ebp), $0x1<UINT32>
0x00405549:	jmp 0x00405554
0x00405554:	testl %edi, %edi
0x00405556:	jne 0x0040554b
0x0040554b:	decl %edi
0x0040554c:	cmpw (%eax), $0x0<UINT8>
0x00405550:	je 0x00405558
0x00405552:	incl %eax
0x00405553:	incl %eax
0x00405558:	subl %eax, -28(%ebp)
0x0040555b:	sarl %eax
0x0040555d:	movl -32(%ebp), %eax
0x00405560:	cmpl -72(%ebp), $0x0<UINT8>
0x00405564:	jne 255
0x0040556a:	movl %eax, -20(%ebp)
0x0040556d:	testb %al, $0x40<UINT8>
0x0040556f:	je 0x0040559c
0x0040559c:	movl %ebx, -56(%ebp)
0x0040559f:	movl %esi, -32(%ebp)
0x004055a2:	subl %ebx, %esi
0x004055a4:	subl %ebx, -48(%ebp)
0x004055a7:	testb -20(%ebp), $0xc<UINT8>
0x004055ab:	jne 17
0x004055ad:	pushl -60(%ebp)
0x004055b0:	leal %eax, -44(%ebp)
0x004055b3:	pushl %ebx
0x004055b4:	pushl $0x20<UINT8>
0x004055b6:	call 0x0040931f
0x0040931f:	pushl %ebp
0x00409320:	movl %ebp, %esp
0x00409322:	pushl %esi
0x00409323:	movl %esi, %eax
0x00409325:	jmp 0x0040933b
0x0040933b:	cmpl 0xc(%ebp), $0x0<UINT8>
0x0040933f:	jg -26
0x00409341:	popl %esi
0x00409342:	popl %ebp
0x00409343:	ret

0x004055bb:	addl %esp, $0xc<UINT8>
0x004055be:	pushl -48(%ebp)
0x004055c1:	movl %edi, -60(%ebp)
0x004055c4:	leal %eax, -44(%ebp)
0x004055c7:	leal %ecx, -68(%ebp)
0x004055ca:	call 0x00409344
0x00409344:	testb 0xc(%edi), $0x40<UINT8>
0x00409348:	pushl %ebx
0x00409349:	pushl %esi
0x0040934a:	movl %esi, %eax
0x0040934c:	movl %ebx, %ecx
0x0040934e:	je 57
0x00409350:	cmpl 0x8(%edi), $0x0<UINT8>
0x00409354:	jne 0x00409389
0x00409389:	cmpl 0xc(%esp), $0x0<UINT8>
0x0040938e:	jg 0x0040935e
0x00409390:	popl %esi
0x00409391:	popl %ebx
0x00409392:	ret

0x004055cf:	testb -20(%ebp), $0x8<UINT8>
0x004055d3:	popl %ecx
0x004055d4:	je 0x004055eb
0x004055eb:	cmpl -52(%ebp), $0x0<UINT8>
0x004055ef:	jne 0x0040563f
0x0040563f:	movl %ecx, -28(%ebp)
0x00405642:	pushl %esi
0x00405643:	leal %eax, -44(%ebp)
0x00405646:	call 0x00409344
0x0040935e:	movzwl %eax, (%ebx)
0x00409361:	decl 0xc(%esp)
0x00409365:	pushl %eax
0x00409366:	movl %eax, %edi
0x00409368:	call 0x004092fa
0x0040936d:	incl %ebx
0x0040936e:	incl %ebx
0x0040936f:	cmpl (%esi), $0xffffffff<UINT8>
0x00409372:	popl %ecx
0x00409373:	jne 0x00409389
0x0040564b:	popl %ecx
0x0040564c:	cmpl -44(%ebp), $0x0<UINT8>
0x00405650:	jl 23
0x00405652:	testb -20(%ebp), $0x4<UINT8>
0x00405656:	je 0x00405669
0x00405669:	cmpl -80(%ebp), $0x0<UINT8>
0x0040566d:	je 0x0040567c
0x004056ae:	cmpb -88(%ebp), $0x0<UINT8>
0x004056b2:	je 7
0x004056b4:	movl %eax, -92(%ebp)
0x004056b7:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x004056bb:	movl %eax, -44(%ebp)
0x004056be:	movl %ecx, 0x3f0(%ebp)
0x004056c4:	popl %edi
0x004056c5:	popl %esi
0x004056c6:	xorl %ecx, %ebp
0x004056c8:	popl %ebx
0x004056c9:	call 0x0040318a
0x004056ce:	addl %ebp, $0x3f4<UINT32>
0x004056d4:	leave
0x004056d5:	ret

0x0040327f:	addl %esp, $0x10<UINT8>
0x00403282:	decl -28(%ebp)
0x00403285:	movl %esi, %eax
0x00403287:	js 10
0x00403289:	movl %eax, -32(%ebp)
0x0040328c:	movb (%eax), %bl
0x0040328e:	incl -32(%ebp)
0x00403291:	jmp 0x0040329f
0x0040329f:	decl -28(%ebp)
0x004032a2:	js 7
0x004032a4:	movl %eax, -32(%ebp)
0x004032a7:	movb (%eax), %bl
0x004032a9:	jmp 0x004032b7
0x004032b7:	movl %eax, %esi
0x004032b9:	popl %esi
0x004032ba:	popl %ebx
0x004032bb:	leave
0x004032bc:	ret

0x0040149f:	addl %esp, $0xc<UINT8>
0x004014a2:	leal %ecx, 0x4(%esp)
0x004014a6:	pushl %ecx
0x004014a7:	leal %edx, 0x10(%esp)
0x004014ab:	pushl %edx
0x004014ac:	pushl $0x80000001<UINT32>
0x004014b1:	call RegCreateKeyW@ADVAPI32.dll
RegCreateKeyW@ADVAPI32.dll: API Node	
0x004014b7:	testl %eax, %eax
0x004014b9:	jne 39
0x004014bb:	movl %edx, 0x4(%esp)
0x004014bf:	leal %eax, 0x8(%esp)
0x004014c3:	pushl %eax
0x004014c4:	leal %ecx, 0x220(%esp)
0x004014cb:	pushl %ecx
0x004014cc:	pushl %ebp
0x004014cd:	pushl %ebp
0x004014ce:	pushl $0x410874<UINT32>
0x004014d3:	pushl %edx
0x004014d4:	movl 0x20(%esp), $0x4<UINT32>
0x004014dc:	call RegQueryValueExW@ADVAPI32.dll
RegQueryValueExW@ADVAPI32.dll: API Node	
0x004014e2:	cmpl 0x21c(%esp), %ebp
0x004014e9:	jne 696
0x004014ef:	pushl %esi
0x004014f0:	pushl %edi
0x004014f1:	pushl $0x3e8<UINT32>
0x004014f6:	pushl $0x40<UINT8>
0x004014f8:	call LocalAlloc@KERNEL32.DLL
LocalAlloc@KERNEL32.DLL: API Node	
0x004014fe:	movl %esi, %eax
0x00401500:	pushl $0x410890<UINT32>
0x00401505:	leal %edi, 0x12(%esi)
0x00401508:	call LoadLibraryW@KERNEL32.DLL
LoadLibraryW@KERNEL32.DLL: API Node	
0x0040150e:	movl (%esi), $0x80c808d0<UINT32>
0x00404af0:	subl %esp, $0x14<UINT8>
0x00404af3:	pushl %ebx
0x00404af4:	movl %ebx, 0x20(%esp)
0x00404af8:	pushl %ebp
0x00404af9:	pushl %esi
0x00404afa:	movl %esi, 0x8(%ebx)
0x00404afd:	xorl %esi, 0x413004
0x00404b03:	pushl %edi
0x00404b04:	movl %eax, (%esi)
0x00404b06:	cmpl %eax, $0xfffffffe<UINT8>
0x00404b09:	movb 0x13(%esp), $0x0<UINT8>
0x00404b0e:	movl 0x18(%esp), $0x1<UINT32>
0x00404b16:	leal %edi, 0x10(%ebx)
0x00404b19:	je 0x00404b28
0x00404b28:	movl %ecx, 0xc(%esi)
0x00404b2b:	movl %eax, 0x8(%esi)
0x00404b2e:	addl %ecx, %edi
0x00404b30:	xorl %ecx, (%eax,%edi)
0x00404b33:	call 0x0040318a
0x00404b38:	movl %eax, 0x28(%esp)
0x00404b3c:	testb 0x4(%eax), $0x66<UINT8>
0x00404b40:	jne 287
0x00404b46:	movl %ebp, 0xc(%ebx)
0x00404b49:	cmpl %ebp, $0xfffffffe<UINT8>
0x00404b4c:	movl %ecx, 0x30(%esp)
0x00404b50:	leal %edx, 0x1c(%esp)
0x00404b54:	movl 0x1c(%esp), %eax
0x00404b58:	movl 0x20(%esp), %ecx
0x00404b5c:	movl -4(%ebx), %edx
0x00404b5f:	je 94
0x00404b61:	leal %eax, (%ebp,%ebp,2)
0x00404b65:	movl %ecx, 0x14(%esi,%eax,4)
0x00404b69:	testl %ecx, %ecx
0x00404b6b:	leal %ebx, 0x10(%esi,%eax,4)
0x00404b6f:	movl %eax, (%ebx)
0x00404b71:	movl 0x14(%esp), %eax
0x00404b75:	je 22
0x00404b77:	movl %edx, %edi
0x00404b79:	call 0x0040817a
0x0040817a:	pushl %ebp
0x0040817b:	pushl %esi
0x0040817c:	pushl %edi
0x0040817d:	pushl %ebx
0x0040817e:	movl %ebp, %edx
0x00408180:	xorl %eax, %eax
0x00408182:	xorl %ebx, %ebx
0x00408184:	xorl %edx, %edx
0x00408186:	xorl %esi, %esi
0x00408188:	xorl %edi, %edi
0x0040818a:	call 0x00403b4d
0x00403b4d:	movl %eax, -20(%ebp)
0x00403b50:	movl %ecx, (%eax)
0x00403b52:	movl %ecx, (%ecx)
0x00403b54:	movl -44(%ebp), %ecx
0x00403b57:	pushl %eax
0x00403b58:	pushl %ecx
0x00403b59:	call 0x00407228
0x00407228:	pushl %ebp
0x00407229:	movl %ebp, %esp
0x0040722b:	pushl %ecx
0x0040722c:	pushl %ecx
0x0040722d:	pushl %esi
0x0040722e:	call 0x004065e8
0x00407233:	movl %esi, %eax
0x00407235:	testl %esi, %esi
0x00407237:	je 326
0x0040723d:	movl %edx, 0x5c(%esi)
0x00407240:	movl %eax, 0x413a14
0x00407245:	pushl %edi
0x00407246:	movl %edi, 0x8(%ebp)
0x00407249:	movl %ecx, %edx
0x0040724b:	pushl %ebx
0x0040724c:	cmpl (%ecx), %edi
0x0040724e:	je 0x0040725e
0x0040725e:	imull %eax, %eax, $0xc<UINT8>
0x00407261:	addl %eax, %edx
0x00407263:	cmpl %ecx, %eax
0x00407265:	jae 8
0x00407267:	cmpl (%ecx), %edi
0x00407269:	jne 4
0x0040726b:	movl %eax, %ecx
0x0040726d:	jmp 0x00407271
0x00407271:	testl %eax, %eax
0x00407273:	je 10
0x00407275:	movl %ebx, 0x8(%eax)
0x00407278:	testl %ebx, %ebx
0x0040727a:	movl -4(%ebp), %ebx
0x0040727d:	jne 7
0x0040727f:	xorl %eax, %eax
0x00407281:	jmp 0x00407381
0x00407381:	popl %ebx
0x00407382:	popl %edi
0x00407383:	popl %esi
0x00407384:	leave
0x00407385:	ret

0x00403b5e:	popl %ecx
0x00403b5f:	popl %ecx
0x00403b60:	ret

0x0040818c:	popl %ebx
0x0040818d:	popl %edi
0x0040818e:	popl %esi
0x0040818f:	popl %ebp
0x00408190:	ret

0x00404b7e:	testl %eax, %eax
0x00404b80:	movb 0x13(%esp), $0x1<UINT8>
0x00404b85:	jl 68
0x00404b87:	jg 76
0x00404b89:	movl %eax, 0x14(%esp)
0x00404b8d:	cmpl %eax, $0xfffffffe<UINT8>
0x00404b90:	movl %ebp, %eax
0x00404b92:	jne -51
0x00404b94:	cmpb 0x13(%esp), $0x0<UINT8>
0x00404b99:	je 36
0x00404b9b:	movl %eax, (%esi)
0x00404b9d:	cmpl %eax, $0xfffffffe<UINT8>
0x00404ba0:	je 0x00404baf
0x00404baf:	movl %ecx, 0xc(%esi)
0x00404bb2:	movl %eax, 0x8(%esi)
0x00404bb5:	addl %ecx, %edi
0x00404bb7:	xorl %ecx, (%eax,%edi)
0x00404bba:	call 0x0040318a
0x00404bbf:	movl %eax, 0x18(%esp)
0x00404bc3:	popl %edi
0x00404bc4:	popl %esi
0x00404bc5:	popl %ebp
0x00404bc6:	popl %ebx
0x00404bc7:	addl %esp, $0x14<UINT8>
0x00404bca:	ret

0x00401514:	movw 0xa(%esi), %bp
0x00401518:	movw 0xc(%esi), %bp
0x0040151c:	movw 0xe(%esi), $0x138<UINT16>
0x00401522:	movw 0x10(%esi), $0xb4<UINT16>
0x00401528:	movw 0x8(%esi), %bp
0x0040152c:	movw (%edi), %bp
0x0040152f:	addl %edi, $0x2<UINT8>
0x00401532:	movw (%edi), %bp
0x00401535:	addl %edi, $0x2<UINT8>
0x00401538:	movl %eax, $0x4108ac<UINT32>
0x0040153d:	movl %edx, %edi
0x0040153f:	subl %edx, %eax
0x00401541:	movzwl %ecx, (%eax)
0x00401544:	movw (%edx,%eax), %cx
0x00401548:	addl %eax, $0x2<UINT8>
0x0040154b:	cmpw %cx, %bp
0x0040154e:	jne 0x00401541
0x00401550:	addl %edi, $0x24<UINT8>
0x00401553:	movw (%edi), $0x8<UINT16>
0x00401558:	addl %edi, $0x2<UINT8>
0x0040155b:	movl %eax, $0x4108d0<UINT32>
0x00401560:	movl %edx, %edi
0x00401562:	subl %edx, %eax
0x00401564:	movzwl %ecx, (%eax)
0x00401567:	movw (%edx,%eax), %cx
0x0040156b:	addl %eax, $0x2<UINT8>
0x0040156e:	cmpw %cx, %bp
0x00401571:	jne 0x00401564
0x00401573:	leal %eax, 0x1d(%edi)
0x00401576:	andl %eax, $0xfffffffc<UINT8>
0x00401579:	movw 0x8(%eax), $0x7<UINT16>
0x0040157f:	movw 0xa(%eax), $0x3<UINT16>
0x00401585:	movw 0xc(%eax), $0x12a<UINT16>
0x0040158b:	movw 0x10(%eax), $0x1f6<UINT16>
0x00401591:	movl (%eax), $0x50000000<UINT32>
0x00401597:	pushl %ebx
0x00401598:	movl %ebx, $0xe<UINT32>
0x0040159d:	movw 0xe(%eax), %bx
0x004015a1:	addl %eax, $0x12<UINT8>
0x004015a4:	movw (%eax), $0xffffffff<UINT16>
0x004015a9:	addl %eax, $0x2<UINT8>
0x004015ac:	movw (%eax), $0x82<UINT16>
0x004015b1:	addl %eax, $0x2<UINT8>
0x004015b4:	movl %ecx, $0x4108f0<UINT32>
0x004015b9:	movl %edx, %eax
0x004015bb:	subl %edx, %ecx
0x004015bd:	leal %ecx, (%ecx)
0x004015c0:	movzwl %edi, (%ecx)
0x004015c3:	movw (%edx,%ecx), %di
0x004015c7:	addl %ecx, $0x2<UINT8>
0x004015ca:	cmpw %di, %bp
0x004015cd:	jne 0x004015c0
0x004015cf:	movw 0x92(%eax), %bp
0x004015d6:	addl %eax, $0x92<UINT32>
0x004015db:	addl %eax, $0x5<UINT8>
0x004015de:	andl %eax, $0xfffffffc<UINT8>
0x004015e1:	movl %ecx, $0x1<UINT32>
0x004015e6:	addw 0x8(%esi), %cx
0x004015ea:	movw 0x10(%eax), %cx
0x004015ee:	movw 0x8(%eax), $0xc9<UINT16>
0x004015f4:	movw 0xa(%eax), $0x9f<UINT16>
0x004015fa:	movw 0xe(%eax), %bx
0x004015fe:	movl (%eax), $0x50010000<UINT32>
0x00401604:	movl %ebp, $0x32<UINT32>
0x00401609:	movw 0xc(%eax), %bp
0x0040160d:	addl %eax, $0x12<UINT8>
0x00401610:	movw (%eax), $0xffffffff<UINT16>
0x00401615:	addl %eax, $0x2<UINT8>
0x00401618:	movw (%eax), $0x80<UINT16>
0x0040161d:	addl %eax, $0x2<UINT8>
0x00401620:	movl %ecx, $0x410984<UINT32>
0x00401625:	movl %edx, %eax
0x00401627:	subl %edx, %ecx
0x00401629:	leal %esp, (%esp)
0x00401630:	movzwl %edi, (%ecx)
0x00401633:	movw (%edx,%ecx), %di
0x00401637:	addl %ecx, $0x2<UINT8>
0x0040163a:	testw %di, %di
0x0040163d:	jne 0x00401630
0x0040163f:	movw (%eax,%ebx), %di
0x00401643:	addw 0x8(%esi), $0x1<UINT8>
0x00401648:	addl %eax, %ebx
0x0040164a:	addl %eax, $0x5<UINT8>
0x0040164d:	andl %eax, $0xfffffffc<UINT8>
0x00401650:	movw 0x8(%eax), $0xff<UINT16>
0x00401656:	movw 0xa(%eax), $0x9f<UINT16>
0x0040165c:	movw 0xc(%eax), %bp
0x00401660:	movw 0xe(%eax), %bx
0x00401664:	movw 0x10(%eax), $0x2<UINT16>
0x0040166a:	movl (%eax), $0x50010000<UINT32>
0x00401670:	addl %eax, $0x12<UINT8>
0x00401673:	movw (%eax), $0xffffffff<UINT16>
0x00401678:	addl %eax, $0x2<UINT8>
0x0040167b:	movw (%eax), $0x80<UINT16>
0x00401680:	addl %eax, $0x2<UINT8>
0x00401683:	movl %ecx, $0x410994<UINT32>
0x00401688:	movl %edx, %eax
0x0040168a:	subl %edx, %ecx
0x0040168c:	leal %esp, (%esp)
0x00401690:	movzwl %edi, (%ecx)
0x00401693:	movw (%edx,%ecx), %di
0x00401697:	addl %ecx, $0x2<UINT8>
0x0040169a:	testw %di, %di
0x0040169d:	jne 0x00401690
0x0040169f:	movw 0x12(%eax), %di
0x004016a3:	addw 0x8(%esi), $0x1<UINT8>
0x004016a8:	addl %eax, $0x12<UINT8>
0x004016ab:	addl %eax, $0x5<UINT8>
0x004016ae:	andl %eax, $0xfffffffc<UINT8>
0x004016b1:	movw 0x8(%eax), $0x7<UINT16>
0x004016b7:	movw 0xa(%eax), $0x9f<UINT16>
0x004016bd:	movw 0xc(%eax), %bp
0x004016c1:	movw 0xe(%eax), %bx
0x004016c5:	movw 0x10(%eax), $0x1f5<UINT16>
0x004016cb:	movl (%eax), $0x50010000<UINT32>
0x004016d1:	addl %eax, $0x12<UINT8>
0x004016d4:	movw (%eax), $0xffffffff<UINT16>
0x004016d9:	addl %eax, $0x2<UINT8>
0x004016dc:	movw (%eax), $0x80<UINT16>
0x004016e1:	addl %eax, $0x2<UINT8>
0x004016e4:	movl %ecx, $0x4109a8<UINT32>
0x004016e9:	movl %edx, %eax
0x004016eb:	subl %edx, %ecx
0x004016ed:	leal %ecx, (%ecx)
0x004016f0:	movzwl %edi, (%ecx)
0x004016f3:	movw (%edx,%ecx), %di
0x004016f7:	addl %ecx, $0x2<UINT8>
0x004016fa:	testw %di, %di
0x004016fd:	jne 0x004016f0
0x004016ff:	movw (%eax,%ebx), %di
0x00401703:	addl %eax, %ebx
0x00401705:	addl %eax, $0x5<UINT8>
0x00401708:	andl %eax, $0xfffffffc<UINT8>
0x0040170b:	movl %ebp, $0x1<UINT32>
0x00401710:	addw 0x8(%esi), %bp
0x00401714:	leal %edx, 0x12(%eax)
0x00401717:	movw 0xa(%eax), %bx
0x0040171b:	movw 0x8(%eax), $0x7<UINT16>
0x00401721:	movw 0xc(%eax), $0x12a<UINT16>
0x00401727:	movw 0xe(%eax), $0x8c<UINT16>
0x0040172d:	movw 0x10(%eax), $0x1f4<UINT16>
0x00401733:	movl (%eax), $0x50a11844<UINT32>
0x00401739:	movl %eax, $0x4109b8<UINT32>
0x0040173e:	movl %ecx, %edx
0x00401740:	subl %ecx, %eax
0x00401742:	popl %ebx
0x00401743:	movzwl %edi, (%eax)
0x00401746:	movw (%ecx,%eax), %di
0x0040174a:	addl %eax, $0x2<UINT8>
0x0040174d:	testw %di, %di
0x00401750:	jne 0x00401743
0x00401752:	addl %edx, $0x12<UINT8>
0x00401755:	movl %eax, $0x410994<UINT32>
0x0040175a:	movl %edi, %edx
0x0040175c:	subl %edi, %eax
0x0040175e:	movl %edi, %edi
0x00401760:	movzwl %ecx, (%eax)
0x00401763:	movw (%edi,%eax), %cx
0x00401767:	addl %eax, $0x2<UINT8>
0x0040176a:	testw %cx, %cx
0x0040176d:	jne 0x00401760
0x0040176f:	pushl $0x410a18<UINT32>
0x00401774:	pushl $0x401310<UINT32>
0x00401779:	pushl $0x0<UINT8>
0x0040177b:	pushl %esi
0x0040177c:	movw 0x12(%edx), %cx
0x00401780:	addw 0x8(%esi), %bp
0x00401784:	pushl $0x0<UINT8>
0x00401786:	call DialogBoxIndirectParamW@USER32.dll
DialogBoxIndirectParamW@USER32.dll: API Node	
0x0040178c:	pushl %esi
0x0040178d:	movl 0x228(%esp), %eax
0x00401794:	call LocalFree@KERNEL32.DLL
LocalFree@KERNEL32.DLL: API Node	
0x0040179a:	xorl %ebp, %ebp
0x0040179c:	cmpl 0x224(%esp), %ebp
0x004017a3:	popl %edi
0x004017a4:	popl %esi
0x004017a5:	je 29
