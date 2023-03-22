0x004439c0:	pusha
0x004439c1:	movl %esi, $0x42d000<UINT32>
0x004439c6:	leal %edi, -180224(%esi)
0x004439cc:	pushl %edi
0x004439cd:	orl %ebp, $0xffffffff<UINT8>
0x004439d0:	jmp 0x004439e2
0x004439e2:	movl %ebx, (%esi)
0x004439e4:	subl %esi, $0xfffffffc<UINT8>
0x004439e7:	adcl %ebx, %ebx
0x004439e9:	jb 0x004439d8
0x004439d8:	movb %al, (%esi)
0x004439da:	incl %esi
0x004439db:	movb (%edi), %al
0x004439dd:	incl %edi
0x004439de:	addl %ebx, %ebx
0x004439e0:	jne 0x004439e9
0x004439eb:	movl %eax, $0x1<UINT32>
0x004439f0:	addl %ebx, %ebx
0x004439f2:	jne 0x004439fb
0x004439fb:	adcl %eax, %eax
0x004439fd:	addl %ebx, %ebx
0x004439ff:	jae 0x004439f0
0x00443a01:	jne 0x00443a0c
0x00443a0c:	xorl %ecx, %ecx
0x00443a0e:	subl %eax, $0x3<UINT8>
0x00443a11:	jb 0x00443a20
0x00443a20:	addl %ebx, %ebx
0x00443a22:	jne 0x00443a2b
0x00443a2b:	adcl %ecx, %ecx
0x00443a2d:	addl %ebx, %ebx
0x00443a2f:	jne 0x00443a38
0x00443a38:	adcl %ecx, %ecx
0x00443a3a:	jne 0x00443a5c
0x00443a5c:	cmpl %ebp, $0xfffff300<UINT32>
0x00443a62:	adcl %ecx, $0x1<UINT8>
0x00443a65:	leal %edx, (%edi,%ebp)
0x00443a68:	cmpl %ebp, $0xfffffffc<UINT8>
0x00443a6b:	jbe 0x00443a7c
0x00443a6d:	movb %al, (%edx)
0x00443a6f:	incl %edx
0x00443a70:	movb (%edi), %al
0x00443a72:	incl %edi
0x00443a73:	decl %ecx
0x00443a74:	jne 0x00443a6d
0x00443a76:	jmp 0x004439de
0x00443a3c:	incl %ecx
0x00443a3d:	addl %ebx, %ebx
0x00443a3f:	jne 0x00443a48
0x00443a48:	adcl %ecx, %ecx
0x00443a4a:	addl %ebx, %ebx
0x00443a4c:	jae 0x00443a3d
0x00443a41:	movl %ebx, (%esi)
0x00443a43:	subl %esi, $0xfffffffc<UINT8>
0x00443a46:	adcl %ebx, %ebx
0x00443a4e:	jne 0x00443a59
0x00443a59:	addl %ecx, $0x2<UINT8>
0x00443a13:	shll %eax, $0x8<UINT8>
0x00443a16:	movb %al, (%esi)
0x00443a18:	incl %esi
0x00443a19:	xorl %eax, $0xffffffff<UINT8>
0x00443a1c:	je 0x00443a92
0x00443a1e:	movl %ebp, %eax
0x00443a7c:	movl %eax, (%edx)
0x00443a7e:	addl %edx, $0x4<UINT8>
0x00443a81:	movl (%edi), %eax
0x00443a83:	addl %edi, $0x4<UINT8>
0x00443a86:	subl %ecx, $0x4<UINT8>
0x00443a89:	ja 0x00443a7c
0x00443a8b:	addl %edi, %ecx
0x00443a8d:	jmp 0x004439de
0x00443a31:	movl %ebx, (%esi)
0x00443a33:	subl %esi, $0xfffffffc<UINT8>
0x00443a36:	adcl %ebx, %ebx
0x00443a50:	movl %ebx, (%esi)
0x00443a52:	subl %esi, $0xfffffffc<UINT8>
0x00443a55:	adcl %ebx, %ebx
0x00443a57:	jae 0x00443a3d
0x004439f4:	movl %ebx, (%esi)
0x004439f6:	subl %esi, $0xfffffffc<UINT8>
0x004439f9:	adcl %ebx, %ebx
0x00443a03:	movl %ebx, (%esi)
0x00443a05:	subl %esi, $0xfffffffc<UINT8>
0x00443a08:	adcl %ebx, %ebx
0x00443a0a:	jae 0x004439f0
0x00443a24:	movl %ebx, (%esi)
0x00443a26:	subl %esi, $0xfffffffc<UINT8>
0x00443a29:	adcl %ebx, %ebx
0x00443a92:	popl %esi
0x00443a93:	movl %edi, %esi
0x00443a95:	movl %ecx, $0xe81<UINT32>
0x00443a9a:	movb %al, (%edi)
0x00443a9c:	incl %edi
0x00443a9d:	subb %al, $0xffffffe8<UINT8>
0x00443a9f:	cmpb %al, $0x1<UINT8>
0x00443aa1:	ja 0x00443a9a
0x00443aa3:	cmpb (%edi), $0x9<UINT8>
0x00443aa6:	jne 0x00443a9a
0x00443aa8:	movl %eax, (%edi)
0x00443aaa:	movb %bl, 0x4(%edi)
0x00443aad:	shrw %ax, $0x8<UINT8>
0x00443ab1:	roll %eax, $0x10<UINT8>
0x00443ab4:	xchgb %ah, %al
0x00443ab6:	subl %eax, %edi
0x00443ab8:	subb %bl, $0xffffffe8<UINT8>
0x00443abb:	addl %eax, %esi
0x00443abd:	movl (%edi), %eax
0x00443abf:	addl %edi, $0x5<UINT8>
0x00443ac2:	movb %al, %bl
0x00443ac4:	loop 0x00443a9f
0x00443ac6:	leal %edi, 0x40000(%esi)
0x00443acc:	movl %eax, (%edi)
0x00443ace:	orl %eax, %eax
0x00443ad0:	je 0x00443b17
0x00443ad2:	movl %ebx, 0x4(%edi)
0x00443ad5:	leal %eax, 0x4358c(%eax,%esi)
0x00443adc:	addl %ebx, %esi
0x00443ade:	pushl %eax
0x00443adf:	addl %edi, $0x8<UINT8>
0x00443ae2:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x00443ae8:	xchgl %ebp, %eax
0x00443ae9:	movb %al, (%edi)
0x00443aeb:	incl %edi
0x00443aec:	orb %al, %al
0x00443aee:	je 0x00443acc
0x00443af0:	movl %ecx, %edi
0x00443af2:	jns 0x00443afb
0x00443afb:	pushl %edi
0x00443afc:	decl %eax
0x00443afd:	repn scasb %al, %es:(%edi)
0x00443aff:	pushl %ebp
0x00443b00:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00443b06:	orl %eax, %eax
0x00443b08:	je 7
0x00443b0a:	movl (%ebx), %eax
0x00443b0c:	addl %ebx, $0x4<UINT8>
0x00443b0f:	jmp 0x00443ae9
GetProcAddress@KERNEL32.DLL: API Node	
0x00443af4:	movzwl %eax, (%edi)
0x00443af7:	incl %edi
0x00443af8:	pushl %eax
0x00443af9:	incl %edi
0x00443afa:	movl %ecx, $0xaef24857<UINT32>
0x00443b17:	addl %edi, $0x4<UINT8>
0x00443b1a:	leal %ebx, -4(%esi)
0x00443b1d:	xorl %eax, %eax
0x00443b1f:	movb %al, (%edi)
0x00443b21:	incl %edi
0x00443b22:	orl %eax, %eax
0x00443b24:	je 0x00443b48
0x00443b26:	cmpb %al, $0xffffffef<UINT8>
0x00443b28:	ja 0x00443b3b
0x00443b3b:	andb %al, $0xf<UINT8>
0x00443b3d:	shll %eax, $0x10<UINT8>
0x00443b40:	movw %ax, (%edi)
0x00443b43:	addl %edi, $0x2<UINT8>
0x00443b46:	jmp 0x00443b2a
0x00443b2a:	addl %ebx, %eax
0x00443b2c:	movl %eax, (%ebx)
0x00443b2e:	xchgb %ah, %al
0x00443b30:	roll %eax, $0x10<UINT8>
0x00443b33:	xchgb %ah, %al
0x00443b35:	addl %eax, %esi
0x00443b37:	movl (%ebx), %eax
0x00443b39:	jmp 0x00443b1d
0x00443b48:	movl %ebp, 0x43678(%esi)
0x00443b4e:	leal %edi, -4096(%esi)
0x00443b54:	movl %ebx, $0x1000<UINT32>
0x00443b59:	pushl %eax
0x00443b5a:	pushl %esp
0x00443b5b:	pushl $0x4<UINT8>
0x00443b5d:	pushl %ebx
0x00443b5e:	pushl %edi
0x00443b5f:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00443b61:	leal %eax, 0x21f(%edi)
0x00443b67:	andb (%eax), $0x7f<UINT8>
0x00443b6a:	andb 0x28(%eax), $0x7f<UINT8>
0x00443b6e:	popl %eax
0x00443b6f:	pushl %eax
0x00443b70:	pushl %esp
0x00443b71:	pushl %eax
0x00443b72:	pushl %ebx
0x00443b73:	pushl %edi
0x00443b74:	call VirtualProtect@kernel32.dll
0x00443b76:	popl %eax
0x00443b77:	popa
0x00443b78:	leal %eax, -128(%esp)
0x00443b7c:	pushl $0x0<UINT8>
0x00443b7e:	cmpl %esp, %eax
0x00443b80:	jne 0x00443b7c
0x00443b82:	subl %esp, $0xffffff80<UINT8>
0x00443b85:	jmp 0x004115cc
0x004115cc:	call 0x004198bf
0x004198bf:	pushl %ebp
0x004198c0:	movl %ebp, %esp
0x004198c2:	subl %esp, $0x14<UINT8>
0x004198c5:	andl -12(%ebp), $0x0<UINT8>
0x004198c9:	andl -8(%ebp), $0x0<UINT8>
0x004198cd:	movl %eax, 0x431290
0x004198d2:	pushl %esi
0x004198d3:	pushl %edi
0x004198d4:	movl %edi, $0xbb40e64e<UINT32>
0x004198d9:	movl %esi, $0xffff0000<UINT32>
0x004198de:	cmpl %eax, %edi
0x004198e0:	je 0x004198ef
0x004198ef:	leal %eax, -12(%ebp)
0x004198f2:	pushl %eax
0x004198f3:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x004198f9:	movl %eax, -8(%ebp)
0x004198fc:	xorl %eax, -12(%ebp)
0x004198ff:	movl -4(%ebp), %eax
0x00419902:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x00419908:	xorl -4(%ebp), %eax
0x0041990b:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x00419911:	xorl -4(%ebp), %eax
0x00419914:	leal %eax, -20(%ebp)
0x00419917:	pushl %eax
0x00419918:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0041991e:	movl %ecx, -16(%ebp)
0x00419921:	leal %eax, -4(%ebp)
0x00419924:	xorl %ecx, -20(%ebp)
0x00419927:	xorl %ecx, -4(%ebp)
0x0041992a:	xorl %ecx, %eax
0x0041992c:	cmpl %ecx, %edi
0x0041992e:	jne 0x00419937
0x00419937:	testl %esi, %ecx
0x00419939:	jne 0x00419947
0x00419947:	movl 0x431290, %ecx
0x0041994d:	notl %ecx
0x0041994f:	movl 0x431294, %ecx
0x00419955:	popl %edi
0x00419956:	popl %esi
0x00419957:	movl %esp, %ebp
0x00419959:	popl %ebp
0x0041995a:	ret

0x004115d1:	jmp 0x00411451
0x00411451:	pushl $0x14<UINT8>
0x00411453:	pushl $0x42efd8<UINT32>
0x00411458:	call 0x004137b0
0x004137b0:	pushl $0x413810<UINT32>
0x004137b5:	pushl %fs:0
0x004137bc:	movl %eax, 0x10(%esp)
0x004137c0:	movl 0x10(%esp), %ebp
0x004137c4:	leal %ebp, 0x10(%esp)
0x004137c8:	subl %esp, %eax
0x004137ca:	pushl %ebx
0x004137cb:	pushl %esi
0x004137cc:	pushl %edi
0x004137cd:	movl %eax, 0x431290
0x004137d2:	xorl -4(%ebp), %eax
0x004137d5:	xorl %eax, %ebp
0x004137d7:	pushl %eax
0x004137d8:	movl -24(%ebp), %esp
0x004137db:	pushl -8(%ebp)
0x004137de:	movl %eax, -4(%ebp)
0x004137e1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004137e8:	movl -8(%ebp), %eax
0x004137eb:	leal %eax, -16(%ebp)
0x004137ee:	movl %fs:0, %eax
0x004137f4:	ret

0x0041145d:	pushl $0x1<UINT8>
0x0041145f:	call 0x00419872
0x00419872:	pushl %ebp
0x00419873:	movl %ebp, %esp
0x00419875:	movl %eax, 0x8(%ebp)
0x00419878:	movl 0x439fe8, %eax
0x0041987d:	popl %ebp
0x0041987e:	ret

0x00411464:	popl %ecx
0x00411465:	movl %eax, $0x5a4d<UINT32>
0x0041146a:	cmpw 0x400000, %ax
0x00411471:	je 0x00411477
0x00411477:	movl %eax, 0x40003c
0x0041147c:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00411486:	jne -21
0x00411488:	movl %ecx, $0x10b<UINT32>
0x0041148d:	cmpw 0x400018(%eax), %cx
0x00411494:	jne -35
0x00411496:	xorl %ebx, %ebx
0x00411498:	cmpl 0x400074(%eax), $0xe<UINT8>
0x0041149f:	jbe 9
0x004114a1:	cmpl 0x4000e8(%eax), %ebx
0x004114a7:	setne %bl
0x004114aa:	movl -28(%ebp), %ebx
0x004114ad:	call 0x00412932
0x00412932:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x00412938:	xorl %ecx, %ecx
0x0041293a:	movl 0x439fd4, %eax
0x0041293f:	testl %eax, %eax
0x00412941:	setne %cl
0x00412944:	movl %eax, %ecx
0x00412946:	ret

0x004114b2:	testl %eax, %eax
0x004114b4:	jne 0x004114be
0x004114be:	call 0x004127c5
0x004127c5:	call 0x0040fb3d
0x0040fb3d:	pushl %esi
0x0040fb3e:	pushl $0x0<UINT8>
0x0040fb40:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x0040fb46:	movl %esi, %eax
0x0040fb48:	pushl %esi
0x0040fb49:	call 0x00413c8b
0x00413c8b:	pushl %ebp
0x00413c8c:	movl %ebp, %esp
0x00413c8e:	movl %eax, 0x8(%ebp)
0x00413c91:	movl 0x439fe0, %eax
0x00413c96:	popl %ebp
0x00413c97:	ret

0x0040fb4e:	pushl %esi
0x0040fb4f:	call 0x004119ac
0x004119ac:	pushl %ebp
0x004119ad:	movl %ebp, %esp
0x004119af:	movl %eax, 0x8(%ebp)
0x004119b2:	movl 0x439fb0, %eax
0x004119b7:	popl %ebp
0x004119b8:	ret

0x0040fb54:	pushl %esi
0x0040fb55:	call 0x00415397
0x00415397:	pushl %ebp
0x00415398:	movl %ebp, %esp
0x0041539a:	movl %eax, 0x8(%ebp)
0x0041539d:	movl 0x43a774, %eax
0x004153a2:	popl %ebp
0x004153a3:	ret

0x0040fb5a:	pushl %esi
0x0040fb5b:	call 0x004153b1
0x004153b1:	pushl %ebp
0x004153b2:	movl %ebp, %esp
0x004153b4:	movl %eax, 0x8(%ebp)
0x004153b7:	movl 0x43a778, %eax
0x004153bc:	movl 0x43a77c, %eax
0x004153c1:	movl 0x43a780, %eax
0x004153c6:	movl 0x43a784, %eax
0x004153cb:	popl %ebp
0x004153cc:	ret

0x0040fb60:	pushl %esi
0x0040fb61:	call 0x004113a4
0x004113a4:	pushl $0x41135d<UINT32>
0x004113a9:	call EncodePointer@KERNEL32.DLL
0x004113af:	movl 0x439c7c, %eax
0x004113b4:	ret

0x0040fb66:	pushl %esi
0x0040fb67:	call 0x004155c2
0x004155c2:	pushl %ebp
0x004155c3:	movl %ebp, %esp
0x004155c5:	movl %eax, 0x8(%ebp)
0x004155c8:	movl 0x43a78c, %eax
0x004155cd:	popl %ebp
0x004155ce:	ret

0x0040fb6c:	addl %esp, $0x18<UINT8>
0x0040fb6f:	popl %esi
0x0040fb70:	jmp 0x00414e3a
0x00414e3a:	pushl %esi
0x00414e3b:	pushl %edi
0x00414e3c:	pushl $0x42561c<UINT32>
0x00414e41:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00414e47:	movl %esi, 0x424084
0x00414e4d:	movl %edi, %eax
0x00414e4f:	pushl $0x425638<UINT32>
0x00414e54:	pushl %edi
0x00414e55:	call GetProcAddress@KERNEL32.DLL
0x00414e57:	xorl %eax, 0x431290
0x00414e5d:	pushl $0x425644<UINT32>
0x00414e62:	pushl %edi
0x00414e63:	movl 0x43b320, %eax
0x00414e68:	call GetProcAddress@KERNEL32.DLL
0x00414e6a:	xorl %eax, 0x431290
0x00414e70:	pushl $0x42564c<UINT32>
0x00414e75:	pushl %edi
0x00414e76:	movl 0x43b324, %eax
0x00414e7b:	call GetProcAddress@KERNEL32.DLL
0x00414e7d:	xorl %eax, 0x431290
0x00414e83:	pushl $0x425658<UINT32>
0x00414e88:	pushl %edi
0x00414e89:	movl 0x43b328, %eax
0x00414e8e:	call GetProcAddress@KERNEL32.DLL
0x00414e90:	xorl %eax, 0x431290
0x00414e96:	pushl $0x425664<UINT32>
0x00414e9b:	pushl %edi
0x00414e9c:	movl 0x43b32c, %eax
0x00414ea1:	call GetProcAddress@KERNEL32.DLL
0x00414ea3:	xorl %eax, 0x431290
0x00414ea9:	pushl $0x425680<UINT32>
0x00414eae:	pushl %edi
0x00414eaf:	movl 0x43b330, %eax
0x00414eb4:	call GetProcAddress@KERNEL32.DLL
0x00414eb6:	xorl %eax, 0x431290
0x00414ebc:	pushl $0x425690<UINT32>
0x00414ec1:	pushl %edi
0x00414ec2:	movl 0x43b334, %eax
0x00414ec7:	call GetProcAddress@KERNEL32.DLL
0x00414ec9:	xorl %eax, 0x431290
0x00414ecf:	pushl $0x4256a4<UINT32>
0x00414ed4:	pushl %edi
0x00414ed5:	movl 0x43b338, %eax
0x00414eda:	call GetProcAddress@KERNEL32.DLL
0x00414edc:	xorl %eax, 0x431290
0x00414ee2:	pushl $0x4256bc<UINT32>
0x00414ee7:	pushl %edi
0x00414ee8:	movl 0x43b33c, %eax
0x00414eed:	call GetProcAddress@KERNEL32.DLL
0x00414eef:	xorl %eax, 0x431290
0x00414ef5:	pushl $0x4256d4<UINT32>
0x00414efa:	pushl %edi
0x00414efb:	movl 0x43b340, %eax
0x00414f00:	call GetProcAddress@KERNEL32.DLL
0x00414f02:	xorl %eax, 0x431290
0x00414f08:	pushl $0x4256e8<UINT32>
0x00414f0d:	pushl %edi
0x00414f0e:	movl 0x43b344, %eax
0x00414f13:	call GetProcAddress@KERNEL32.DLL
0x00414f15:	xorl %eax, 0x431290
0x00414f1b:	pushl $0x425708<UINT32>
0x00414f20:	pushl %edi
0x00414f21:	movl 0x43b348, %eax
0x00414f26:	call GetProcAddress@KERNEL32.DLL
0x00414f28:	xorl %eax, 0x431290
0x00414f2e:	pushl $0x425720<UINT32>
0x00414f33:	pushl %edi
0x00414f34:	movl 0x43b34c, %eax
0x00414f39:	call GetProcAddress@KERNEL32.DLL
0x00414f3b:	xorl %eax, 0x431290
0x00414f41:	pushl $0x425738<UINT32>
0x00414f46:	pushl %edi
0x00414f47:	movl 0x43b350, %eax
0x00414f4c:	call GetProcAddress@KERNEL32.DLL
0x00414f4e:	xorl %eax, 0x431290
0x00414f54:	pushl $0x42574c<UINT32>
0x00414f59:	pushl %edi
0x00414f5a:	movl 0x43b354, %eax
0x00414f5f:	call GetProcAddress@KERNEL32.DLL
0x00414f61:	xorl %eax, 0x431290
0x00414f67:	movl 0x43b358, %eax
0x00414f6c:	pushl $0x425760<UINT32>
0x00414f71:	pushl %edi
0x00414f72:	call GetProcAddress@KERNEL32.DLL
0x00414f74:	xorl %eax, 0x431290
0x00414f7a:	pushl $0x42577c<UINT32>
0x00414f7f:	pushl %edi
0x00414f80:	movl 0x43b35c, %eax
0x00414f85:	call GetProcAddress@KERNEL32.DLL
0x00414f87:	xorl %eax, 0x431290
0x00414f8d:	pushl $0x42579c<UINT32>
0x00414f92:	pushl %edi
0x00414f93:	movl 0x43b360, %eax
0x00414f98:	call GetProcAddress@KERNEL32.DLL
0x00414f9a:	xorl %eax, 0x431290
0x00414fa0:	pushl $0x4257b8<UINT32>
0x00414fa5:	pushl %edi
0x00414fa6:	movl 0x43b364, %eax
0x00414fab:	call GetProcAddress@KERNEL32.DLL
0x00414fad:	xorl %eax, 0x431290
0x00414fb3:	pushl $0x4257d8<UINT32>
0x00414fb8:	pushl %edi
0x00414fb9:	movl 0x43b368, %eax
0x00414fbe:	call GetProcAddress@KERNEL32.DLL
0x00414fc0:	xorl %eax, 0x431290
0x00414fc6:	pushl $0x4257ec<UINT32>
0x00414fcb:	pushl %edi
0x00414fcc:	movl 0x43b36c, %eax
0x00414fd1:	call GetProcAddress@KERNEL32.DLL
0x00414fd3:	xorl %eax, 0x431290
0x00414fd9:	pushl $0x425808<UINT32>
0x00414fde:	pushl %edi
0x00414fdf:	movl 0x43b370, %eax
0x00414fe4:	call GetProcAddress@KERNEL32.DLL
0x00414fe6:	xorl %eax, 0x431290
0x00414fec:	pushl $0x42581c<UINT32>
0x00414ff1:	pushl %edi
0x00414ff2:	movl 0x43b378, %eax
0x00414ff7:	call GetProcAddress@KERNEL32.DLL
0x00414ff9:	xorl %eax, 0x431290
0x00414fff:	pushl $0x42582c<UINT32>
0x00415004:	pushl %edi
0x00415005:	movl 0x43b374, %eax
0x0041500a:	call GetProcAddress@KERNEL32.DLL
0x0041500c:	xorl %eax, 0x431290
0x00415012:	pushl $0x42583c<UINT32>
0x00415017:	pushl %edi
0x00415018:	movl 0x43b37c, %eax
0x0041501d:	call GetProcAddress@KERNEL32.DLL
0x0041501f:	xorl %eax, 0x431290
0x00415025:	pushl $0x42584c<UINT32>
0x0041502a:	pushl %edi
0x0041502b:	movl 0x43b380, %eax
0x00415030:	call GetProcAddress@KERNEL32.DLL
0x00415032:	xorl %eax, 0x431290
0x00415038:	pushl $0x42585c<UINT32>
0x0041503d:	pushl %edi
0x0041503e:	movl 0x43b384, %eax
0x00415043:	call GetProcAddress@KERNEL32.DLL
0x00415045:	xorl %eax, 0x431290
0x0041504b:	pushl $0x425878<UINT32>
0x00415050:	pushl %edi
0x00415051:	movl 0x43b388, %eax
0x00415056:	call GetProcAddress@KERNEL32.DLL
0x00415058:	xorl %eax, 0x431290
0x0041505e:	pushl $0x42588c<UINT32>
0x00415063:	pushl %edi
0x00415064:	movl 0x43b38c, %eax
0x00415069:	call GetProcAddress@KERNEL32.DLL
0x0041506b:	xorl %eax, 0x431290
0x00415071:	pushl $0x42589c<UINT32>
0x00415076:	pushl %edi
0x00415077:	movl 0x43b390, %eax
0x0041507c:	call GetProcAddress@KERNEL32.DLL
0x0041507e:	xorl %eax, 0x431290
0x00415084:	pushl $0x4258b0<UINT32>
0x00415089:	pushl %edi
0x0041508a:	movl 0x43b394, %eax
0x0041508f:	call GetProcAddress@KERNEL32.DLL
0x00415091:	xorl %eax, 0x431290
0x00415097:	movl 0x43b398, %eax
0x0041509c:	pushl $0x4258c0<UINT32>
0x004150a1:	pushl %edi
0x004150a2:	call GetProcAddress@KERNEL32.DLL
0x004150a4:	xorl %eax, 0x431290
0x004150aa:	pushl $0x4258e0<UINT32>
0x004150af:	pushl %edi
0x004150b0:	movl 0x43b39c, %eax
0x004150b5:	call GetProcAddress@KERNEL32.DLL
0x004150b7:	xorl %eax, 0x431290
0x004150bd:	popl %edi
0x004150be:	movl 0x43b3a0, %eax
0x004150c3:	popl %esi
0x004150c4:	ret

0x004127ca:	call 0x00414c4f
0x00414c4f:	pushl %esi
0x00414c50:	pushl %edi
0x00414c51:	movl %esi, $0x431b78<UINT32>
0x00414c56:	movl %edi, $0x43a620<UINT32>
0x00414c5b:	cmpl 0x4(%esi), $0x1<UINT8>
0x00414c5f:	jne 22
0x00414c61:	pushl $0x0<UINT8>
0x00414c63:	movl (%esi), %edi
0x00414c65:	addl %edi, $0x18<UINT8>
0x00414c68:	pushl $0xfa0<UINT32>
0x00414c6d:	pushl (%esi)
0x00414c6f:	call 0x00414dca
0x00414dca:	pushl %ebp
0x00414dcb:	movl %ebp, %esp
0x00414dcd:	movl %eax, 0x43b330
0x00414dd2:	xorl %eax, 0x431290
0x00414dd8:	je 13
0x00414dda:	pushl 0x10(%ebp)
0x00414ddd:	pushl 0xc(%ebp)
0x00414de0:	pushl 0x8(%ebp)
0x00414de3:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x00414de5:	popl %ebp
0x00414de6:	ret

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
