0x00ad49a0:	pusha
0x00ad49a1:	movl %esi, $0xa38000<UINT32>
0x00ad49a6:	leal %edi, -6516736(%esi)
0x00ad49ac:	pushl %edi
0x00ad49ad:	jmp 0x00ad49ba
0x00ad49ba:	movl %ebx, (%esi)
0x00ad49bc:	subl %esi, $0xfffffffc<UINT8>
0x00ad49bf:	adcl %ebx, %ebx
0x00ad49c1:	jb 0x00ad49b0
0x00ad49b0:	movb %al, (%esi)
0x00ad49b2:	incl %esi
0x00ad49b3:	movb (%edi), %al
0x00ad49b5:	incl %edi
0x00ad49b6:	addl %ebx, %ebx
0x00ad49b8:	jne 0x00ad49c1
0x00ad49c3:	movl %eax, $0x1<UINT32>
0x00ad49c8:	addl %ebx, %ebx
0x00ad49ca:	jne 0x00ad49d3
0x00ad49d3:	adcl %eax, %eax
0x00ad49d5:	addl %ebx, %ebx
0x00ad49d7:	jae 0x00ad49e4
0x00ad49d9:	jne 0x00ad4a03
0x00ad4a03:	xorl %ecx, %ecx
0x00ad4a05:	subl %eax, $0x3<UINT8>
0x00ad4a08:	jb 0x00ad4a1b
0x00ad4a0a:	shll %eax, $0x8<UINT8>
0x00ad4a0d:	movb %al, (%esi)
0x00ad4a0f:	incl %esi
0x00ad4a10:	xorl %eax, $0xffffffff<UINT8>
0x00ad4a13:	je 0x00ad4a8a
0x00ad4a15:	sarl %eax
0x00ad4a17:	movl %ebp, %eax
0x00ad4a19:	jmp 0x00ad4a26
0x00ad4a26:	jb 0x00ad49f4
0x00ad49f4:	addl %ebx, %ebx
0x00ad49f6:	jne 0x00ad49ff
0x00ad49ff:	adcl %ecx, %ecx
0x00ad4a01:	jmp 0x00ad4a55
0x00ad4a55:	cmpl %ebp, $0xfffffb00<UINT32>
0x00ad4a5b:	adcl %ecx, $0x2<UINT8>
0x00ad4a5e:	leal %edx, (%edi,%ebp)
0x00ad4a61:	cmpl %ebp, $0xfffffffc<UINT8>
0x00ad4a64:	jbe 0x00ad4a74
0x00ad4a74:	movl %eax, (%edx)
0x00ad4a76:	addl %edx, $0x4<UINT8>
0x00ad4a79:	movl (%edi), %eax
0x00ad4a7b:	addl %edi, $0x4<UINT8>
0x00ad4a7e:	subl %ecx, $0x4<UINT8>
0x00ad4a81:	ja 0x00ad4a74
0x00ad4a83:	addl %edi, %ecx
0x00ad4a85:	jmp 0x00ad49b6
0x00ad4a66:	movb %al, (%edx)
0x00ad4a68:	incl %edx
0x00ad4a69:	movb (%edi), %al
0x00ad4a6b:	incl %edi
0x00ad4a6c:	decl %ecx
0x00ad4a6d:	jne 0x00ad4a66
0x00ad4a6f:	jmp 0x00ad49b6
0x00ad49cc:	movl %ebx, (%esi)
0x00ad49ce:	subl %esi, $0xfffffffc<UINT8>
0x00ad49d1:	adcl %ebx, %ebx
0x00ad4a1b:	addl %ebx, %ebx
0x00ad4a1d:	jne 0x00ad4a26
0x00ad4a28:	incl %ecx
0x00ad4a29:	addl %ebx, %ebx
0x00ad4a2b:	jne 0x00ad4a34
0x00ad4a34:	jb 0x00ad49f4
0x00ad4a36:	addl %ebx, %ebx
0x00ad4a38:	jne 0x00ad4a41
0x00ad4a41:	adcl %ecx, %ecx
0x00ad4a43:	addl %ebx, %ebx
0x00ad4a45:	jae 0x00ad4a36
0x00ad4a47:	jne 0x00ad4a52
0x00ad4a52:	addl %ecx, $0x2<UINT8>
0x00ad49f8:	movl %ebx, (%esi)
0x00ad49fa:	subl %esi, $0xfffffffc<UINT8>
0x00ad49fd:	adcl %ebx, %ebx
0x00ad49e4:	decl %eax
0x00ad49e5:	addl %ebx, %ebx
0x00ad49e7:	jne 0x00ad49f0
0x00ad49f0:	adcl %eax, %eax
0x00ad49f2:	jmp 0x00ad49c8
0x00ad49db:	movl %ebx, (%esi)
0x00ad49dd:	subl %esi, $0xfffffffc<UINT8>
0x00ad49e0:	adcl %ebx, %ebx
0x00ad49e2:	jb 0x00ad4a03
0x00ad49e9:	movl %ebx, (%esi)
0x00ad49eb:	subl %esi, $0xfffffffc<UINT8>
0x00ad49ee:	adcl %ebx, %ebx
0x00ad4a3a:	movl %ebx, (%esi)
0x00ad4a3c:	subl %esi, $0xfffffffc<UINT8>
0x00ad4a3f:	adcl %ebx, %ebx
0x00ad4a49:	movl %ebx, (%esi)
0x00ad4a4b:	subl %esi, $0xfffffffc<UINT8>
0x00ad4a4e:	adcl %ebx, %ebx
0x00ad4a50:	jae 0x00ad4a36
0x00ad4a2d:	movl %ebx, (%esi)
0x00ad4a2f:	subl %esi, $0xfffffffc<UINT8>
0x00ad4a32:	adcl %ebx, %ebx
0x00ad4a1f:	movl %ebx, (%esi)
0x00ad4a21:	subl %esi, $0xfffffffc<UINT8>
0x00ad4a24:	adcl %ebx, %ebx
0x00ad4a8a:	popl %esi
0x00ad4a8b:	movl %edi, %esi
0x00ad4a8d:	movl %ecx, $0x1c37<UINT32>
0x00ad4a92:	movb %al, (%edi)
0x00ad4a94:	incl %edi
0x00ad4a95:	subb %al, $0xffffffe8<UINT8>
0x00ad4a97:	cmpb %al, $0x1<UINT8>
0x00ad4a99:	ja 0x00ad4a92
0x00ad4a9b:	cmpb (%edi), $0x11<UINT8>
0x00ad4a9e:	jne 0x00ad4a92
0x00ad4aa0:	movl %eax, (%edi)
0x00ad4aa2:	movb %bl, 0x4(%edi)
0x00ad4aa5:	shrw %ax, $0x8<UINT8>
0x00ad4aa9:	roll %eax, $0x10<UINT8>
0x00ad4aac:	xchgb %ah, %al
0x00ad4aae:	subl %eax, %edi
0x00ad4ab0:	subb %bl, $0xffffffe8<UINT8>
0x00ad4ab3:	addl %eax, %esi
0x00ad4ab5:	movl (%edi), %eax
0x00ad4ab7:	addl %edi, $0x5<UINT8>
0x00ad4aba:	movb %al, %bl
0x00ad4abc:	loop 0x00ad4a97
0x00ad4abe:	leal %edi, 0x6d0000(%esi)
0x00ad4ac4:	movl %eax, (%edi)
0x00ad4ac6:	orl %eax, %eax
0x00ad4ac8:	je 0x00ad4b0f
0x00ad4aca:	movl %ebx, 0x4(%edi)
0x00ad4acd:	leal %eax, 0x6da234(%eax,%esi)
0x00ad4ad4:	addl %ebx, %esi
0x00ad4ad6:	pushl %eax
0x00ad4ad7:	addl %edi, $0x8<UINT8>
0x00ad4ada:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00ad4ae0:	xchgl %ebp, %eax
0x00ad4ae1:	movb %al, (%edi)
0x00ad4ae3:	incl %edi
0x00ad4ae4:	orb %al, %al
0x00ad4ae6:	je 0x00ad4ac4
0x00ad4ae8:	movl %ecx, %edi
0x00ad4aea:	jns 0x00ad4af3
0x00ad4af3:	pushl %edi
0x00ad4af4:	decl %eax
0x00ad4af5:	repn scasb %al, %es:(%edi)
0x00ad4af7:	pushl %ebp
0x00ad4af8:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00ad4afe:	orl %eax, %eax
0x00ad4b00:	je 7
0x00ad4b02:	movl (%ebx), %eax
0x00ad4b04:	addl %ebx, $0x4<UINT8>
0x00ad4b07:	jmp 0x00ad4ae1
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x00ad4aec:	movzwl %eax, (%edi)
0x00ad4aef:	incl %edi
0x00ad4af0:	pushl %eax
0x00ad4af1:	incl %edi
0x00ad4af2:	movl %ecx, $0xaef24857<UINT32>
0x00ad4b0f:	addl %edi, $0x4<UINT8>
0x00ad4b12:	leal %ebx, -4(%esi)
0x00ad4b15:	xorl %eax, %eax
0x00ad4b17:	movb %al, (%edi)
0x00ad4b19:	incl %edi
0x00ad4b1a:	orl %eax, %eax
0x00ad4b1c:	je 0x00ad4b49
0x00ad4b1e:	cmpb %al, $0xffffffef<UINT8>
0x00ad4b20:	ja 0x00ad4b33
0x00ad4b22:	addl %ebx, %eax
0x00ad4b24:	movl %eax, (%ebx)
0x00ad4b26:	xchgb %ah, %al
0x00ad4b28:	roll %eax, $0x10<UINT8>
0x00ad4b2b:	xchgb %ah, %al
0x00ad4b2d:	addl %eax, %esi
0x00ad4b2f:	movl (%ebx), %eax
0x00ad4b31:	jmp 0x00ad4b15
0x00ad4b33:	andb %al, $0xf<UINT8>
0x00ad4b35:	shll %eax, $0x10<UINT8>
0x00ad4b38:	movw %ax, (%edi)
0x00ad4b3b:	addl %edi, $0x2<UINT8>
0x00ad4b3e:	orl %eax, %eax
0x00ad4b40:	jne 0x00ad4b22
0x00ad4b42:	movl %eax, (%edi)
0x00ad4b44:	addl %edi, $0x4<UINT8>
0x00ad4b47:	jmp 0x00ad4b22
0x00ad4b49:	movl %ebp, 0x6da394(%esi)
0x00ad4b4f:	leal %edi, -4096(%esi)
0x00ad4b55:	movl %ebx, $0x1000<UINT32>
0x00ad4b5a:	pushl %eax
0x00ad4b5b:	pushl %esp
0x00ad4b5c:	pushl $0x4<UINT8>
0x00ad4b5e:	pushl %ebx
0x00ad4b5f:	pushl %edi
0x00ad4b60:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00ad4b62:	leal %eax, 0x20f(%edi)
0x00ad4b68:	andb (%eax), $0x7f<UINT8>
0x00ad4b6b:	andb 0x28(%eax), $0x7f<UINT8>
0x00ad4b6f:	popl %eax
0x00ad4b70:	pushl %eax
0x00ad4b71:	pushl %esp
0x00ad4b72:	pushl %eax
0x00ad4b73:	pushl %ebx
0x00ad4b74:	pushl %edi
0x00ad4b75:	call VirtualProtect@kernel32.dll
0x00ad4b77:	popl %eax
0x00ad4b78:	popa
0x00ad4b79:	leal %eax, -128(%esp)
0x00ad4b7d:	pushl $0x0<UINT8>
0x00ad4b7f:	cmpl %esp, %eax
0x00ad4b81:	jne 0x00ad4b7d
0x00ad4b83:	subl %esp, $0xffffff80<UINT8>
0x00ad4b86:	jmp 0x0042bf34
0x0042bf34:	call 0x00433d51
0x00433d51:	movl %edi, %edi
0x00433d53:	pushl %ebp
0x00433d54:	movl %ebp, %esp
0x00433d56:	subl %esp, $0x10<UINT8>
0x00433d59:	movl %eax, 0x5512b4
0x00433d5e:	andl -8(%ebp), $0x0<UINT8>
0x00433d62:	andl -4(%ebp), $0x0<UINT8>
0x00433d66:	pushl %ebx
0x00433d67:	pushl %edi
0x00433d68:	movl %edi, $0xbb40e64e<UINT32>
0x00433d6d:	movl %ebx, $0xffff0000<UINT32>
0x00433d72:	cmpl %eax, %edi
0x00433d74:	je 0x00433d83
0x00433d83:	pushl %esi
0x00433d84:	leal %eax, -8(%ebp)
0x00433d87:	pushl %eax
0x00433d88:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x00433d8e:	movl %esi, -4(%ebp)
0x00433d91:	xorl %esi, -8(%ebp)
0x00433d94:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x00433d9a:	xorl %esi, %eax
0x00433d9c:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x00433da2:	xorl %esi, %eax
0x00433da4:	call GetTickCount@KERNEL32.DLL
GetTickCount@KERNEL32.DLL: API Node	
0x00433daa:	xorl %esi, %eax
0x00433dac:	leal %eax, -16(%ebp)
0x00433daf:	pushl %eax
0x00433db0:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x00433db6:	movl %eax, -12(%ebp)
0x00433db9:	xorl %eax, -16(%ebp)
0x00433dbc:	xorl %esi, %eax
0x00433dbe:	cmpl %esi, %edi
0x00433dc0:	jne 0x00433dc9
0x00433dc9:	testl %ebx, %esi
0x00433dcb:	jne 0x00433dd4
0x00433dd4:	movl 0x5512b4, %esi
0x00433dda:	notl %esi
0x00433ddc:	movl 0x5512b8, %esi
0x00433de2:	popl %esi
0x00433de3:	popl %edi
0x00433de4:	popl %ebx
0x00433de5:	leave
0x00433de6:	ret

0x0042bf39:	jmp 0x0042bdb6
0x0042bdb6:	pushl $0x58<UINT8>
0x0042bdb8:	pushl $0x54bd18<UINT32>
0x0042bdbd:	call 0x0042da90
0x0042da90:	pushl $0x42daf0<UINT32>
0x0042da95:	pushl %fs:0
0x0042da9c:	movl %eax, 0x10(%esp)
0x0042daa0:	movl 0x10(%esp), %ebp
0x0042daa4:	leal %ebp, 0x10(%esp)
0x0042daa8:	subl %esp, %eax
0x0042daaa:	pushl %ebx
0x0042daab:	pushl %esi
0x0042daac:	pushl %edi
0x0042daad:	movl %eax, 0x5512b4
0x0042dab2:	xorl -4(%ebp), %eax
0x0042dab5:	xorl %eax, %ebp
0x0042dab7:	pushl %eax
0x0042dab8:	movl -24(%ebp), %esp
0x0042dabb:	pushl -8(%ebp)
0x0042dabe:	movl %eax, -4(%ebp)
0x0042dac1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0042dac8:	movl -8(%ebp), %eax
0x0042dacb:	leal %eax, -16(%ebp)
0x0042dace:	movl %fs:0, %eax
0x0042dad4:	ret

0x0042bdc2:	xorl %esi, %esi
0x0042bdc4:	movl -4(%ebp), %esi
0x0042bdc7:	leal %eax, -104(%ebp)
0x0042bdca:	pushl %eax
0x0042bdcb:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x0042bdd1:	pushl $0xfffffffe<UINT8>
0x0042bdd3:	popl %edi
0x0042bdd4:	movl -4(%ebp), %edi
0x0042bdd7:	movl %eax, $0x5a4d<UINT32>
0x0042bddc:	cmpw 0x400000, %ax
0x0042bde3:	jne 56
0x0042bde5:	movl %eax, 0x40003c
0x0042bdea:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x0042bdf4:	jne 39
0x0042bdf6:	movl %ecx, $0x10b<UINT32>
0x0042bdfb:	cmpw 0x400018(%eax), %cx
0x0042be02:	jne 25
0x0042be04:	cmpl 0x400074(%eax), $0xe<UINT8>
0x0042be0b:	jbe 16
0x0042be0d:	xorl %ecx, %ecx
0x0042be0f:	cmpl 0x4000e8(%eax), %esi
0x0042be15:	setne %cl
0x0042be18:	movl -28(%ebp), %ecx
0x0042be1b:	jmp 0x0042be20
0x0042be20:	xorl %ebx, %ebx
0x0042be22:	incl %ebx
0x0042be23:	pushl %ebx
0x0042be24:	call 0x0042dc7c
0x0042dc7c:	movl %edi, %edi
0x0042dc7e:	pushl %ebp
0x0042dc7f:	movl %ebp, %esp
0x0042dc81:	xorl %eax, %eax
0x0042dc83:	cmpl 0x8(%ebp), %eax
0x0042dc86:	pushl $0x0<UINT8>
0x0042dc88:	sete %al
0x0042dc8b:	pushl $0x1000<UINT32>
0x0042dc90:	pushl %eax
0x0042dc91:	call HeapCreate@KERNEL32.DLL
HeapCreate@KERNEL32.DLL: API Node	
0x0042dc97:	movl 0x557c64, %eax
0x0042dc9c:	testl %eax, %eax
0x0042dc9e:	jne 0x0042dca2
0x0042dca2:	xorl %eax, %eax
0x0042dca4:	incl %eax
0x0042dca5:	movl 0x558a60, %eax
0x0042dcaa:	popl %ebp
0x0042dcab:	ret

0x0042be29:	popl %ecx
0x0042be2a:	testl %eax, %eax
0x0042be2c:	jne 0x0042be36
0x0042be36:	call 0x0042ff25
0x0042ff25:	movl %edi, %edi
0x0042ff27:	pushl %esi
0x0042ff28:	pushl %edi
0x0042ff29:	movl %esi, $0x43eb74<UINT32>
0x0042ff2e:	pushl %esi
0x0042ff2f:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0042ff35:	testl %eax, %eax
0x0042ff37:	jne 0x0042ff40
0x0042ff40:	movl %edi, %eax
0x0042ff42:	testl %edi, %edi
0x0042ff44:	je 350
0x0042ff4a:	movl %esi, 0x43e220
0x0042ff50:	pushl $0x43ebc0<UINT32>
0x0042ff55:	pushl %edi
0x0042ff56:	call GetProcAddress@KERNEL32.DLL
0x0042ff58:	pushl $0x43ebb4<UINT32>
0x0042ff5d:	pushl %edi
0x0042ff5e:	movl 0x557f90, %eax
0x0042ff63:	call GetProcAddress@KERNEL32.DLL
0x0042ff65:	pushl $0x43eba8<UINT32>
0x0042ff6a:	pushl %edi
0x0042ff6b:	movl 0x557f94, %eax
0x0042ff70:	call GetProcAddress@KERNEL32.DLL
0x0042ff72:	pushl $0x43eba0<UINT32>
0x0042ff77:	pushl %edi
0x0042ff78:	movl 0x557f98, %eax
0x0042ff7d:	call GetProcAddress@KERNEL32.DLL
0x0042ff7f:	cmpl 0x557f90, $0x0<UINT8>
0x0042ff86:	movl %esi, 0x43e1b0
0x0042ff8c:	movl 0x557f9c, %eax
0x0042ff91:	je 22
0x0042ff93:	cmpl 0x557f94, $0x0<UINT8>
0x0042ff9a:	je 13
0x0042ff9c:	cmpl 0x557f98, $0x0<UINT8>
0x0042ffa3:	je 4
0x0042ffa5:	testl %eax, %eax
0x0042ffa7:	jne 0x0042ffcd
0x0042ffcd:	call TlsAlloc@KERNEL32.DLL
TlsAlloc@KERNEL32.DLL: API Node	
0x0042ffd3:	movl 0x55165c, %eax
0x0042ffd8:	cmpl %eax, $0xffffffff<UINT8>
0x0042ffdb:	je 204
0x0042ffe1:	pushl 0x557f94
0x0042ffe7:	pushl %eax
0x0042ffe8:	call TlsSetValue@KERNEL32.DLL
TlsSetValue@KERNEL32.DLL: API Node	
0x0042ffea:	testl %eax, %eax
0x0042ffec:	je 187
0x0042fff2:	call 0x00429f4c
0x00429f4c:	movl %edi, %edi
0x00429f4e:	pushl %esi
0x00429f4f:	call 0x0042fadc
0x0042fadc:	pushl $0x0<UINT8>
0x0042fade:	call 0x0042fa6a
0x0042fa6a:	movl %edi, %edi
0x0042fa6c:	pushl %ebp
0x0042fa6d:	movl %ebp, %esp
0x0042fa6f:	pushl %esi
0x0042fa70:	pushl 0x55165c
0x0042fa76:	movl %esi, 0x43e1b8
0x0042fa7c:	call TlsGetValue@KERNEL32.DLL
TlsGetValue@KERNEL32.DLL: API Node	
0x0042fa7e:	testl %eax, %eax
0x0042fa80:	je 33
0x0042fa82:	movl %eax, 0x551658
0x0042fa87:	cmpl %eax, $0xffffffff<UINT8>
0x0042fa8a:	je 0x0042faa3
0x0042faa3:	movl %esi, $0x43eb74<UINT32>
0x0042faa8:	pushl %esi
0x0042faa9:	call GetModuleHandleW@KERNEL32.DLL
0x0042faaf:	testl %eax, %eax
0x0042fab1:	jne 0x0042fabe
0x0042fabe:	pushl $0x43eb64<UINT32>
0x0042fac3:	pushl %eax
0x0042fac4:	call GetProcAddress@KERNEL32.DLL
0x0042faca:	testl %eax, %eax
0x0042facc:	je 8
0x0042face:	pushl 0x8(%ebp)
0x0042fad1:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x0042fad3:	movl 0x8(%ebp), %eax
0x0042fad6:	movl %eax, 0x8(%ebp)
0x0042fad9:	popl %esi
0x0042fada:	popl %ebp
0x0042fadb:	ret

0x0042fae3:	popl %ecx
0x0042fae4:	ret

0x00429f54:	movl %esi, %eax
0x00429f56:	pushl %esi
0x00429f57:	call 0x0042de90
0x0042de90:	movl %edi, %edi
0x0042de92:	pushl %ebp
0x0042de93:	movl %ebp, %esp
0x0042de95:	movl %eax, 0x8(%ebp)
0x0042de98:	movl 0x557f7c, %eax
0x0042de9d:	popl %ebp
0x0042de9e:	ret

0x00429f5c:	pushl %esi
0x00429f5d:	call 0x00430693
0x00430693:	movl %edi, %edi
0x00430695:	pushl %ebp
0x00430696:	movl %ebp, %esp
0x00430698:	movl %eax, 0x8(%ebp)
0x0043069b:	movl 0x557fc8, %eax
0x004306a0:	popl %ebp
0x004306a1:	ret

0x00429f62:	pushl %esi
0x00429f63:	call 0x0042a434
0x0042a434:	movl %edi, %edi
0x0042a436:	pushl %ebp
0x0042a437:	movl %ebp, %esp
0x0042a439:	movl %eax, 0x8(%ebp)
0x0042a43c:	movl 0x5577c8, %eax
0x0042a441:	popl %ebp
0x0042a442:	ret

0x00429f68:	pushl %esi
0x00429f69:	call 0x00430684
0x00430684:	movl %edi, %edi
0x00430686:	pushl %ebp
0x00430687:	movl %ebp, %esp
0x00430689:	movl %eax, 0x8(%ebp)
0x0043068c:	movl 0x557fc4, %eax
0x00430691:	popl %ebp
0x00430692:	ret

0x00429f6e:	pushl %esi
0x00429f6f:	call 0x00430675
0x00430675:	movl %edi, %edi
0x00430677:	pushl %ebp
0x00430678:	movl %ebp, %esp
0x0043067a:	movl %eax, 0x8(%ebp)
0x0043067d:	movl 0x557fb8, %eax
0x00430682:	popl %ebp
0x00430683:	ret

0x00429f74:	pushl %esi
0x00429f75:	call 0x00430463
0x00430463:	movl %edi, %edi
0x00430465:	pushl %ebp
0x00430466:	movl %ebp, %esp
0x00430468:	movl %eax, 0x8(%ebp)
0x0043046b:	movl 0x557fa4, %eax
0x00430470:	movl 0x557fa8, %eax
0x00430475:	movl 0x557fac, %eax
0x0043047a:	movl 0x557fb0, %eax
0x0043047f:	popl %ebp
0x00430480:	ret

0x00429f7a:	pushl %esi
0x00429f7b:	call 0x00430302
0x00430302:	ret

0x00429f80:	pushl %esi
0x00429f81:	call 0x004302f1
0x004302f1:	pushl $0x43026d<UINT32>
0x004302f6:	call 0x0042fa6a
0x004302fb:	popl %ecx
0x004302fc:	movl 0x557fa0, %eax
0x00430301:	ret

0x00429f86:	pushl $0x429f18<UINT32>
0x00429f8b:	call 0x0042fa6a
0x00429f90:	addl %esp, $0x24<UINT8>
0x00429f93:	movl 0x551280, %eax
0x00429f98:	popl %esi
0x00429f99:	ret

0x0042fff7:	pushl 0x557f90
0x0042fffd:	call 0x0042fa6a
0x00430002:	pushl 0x557f94
0x00430008:	movl 0x557f90, %eax
0x0043000d:	call 0x0042fa6a
0x00430012:	pushl 0x557f98
0x00430018:	movl 0x557f94, %eax
0x0043001d:	call 0x0042fa6a
0x00430022:	pushl 0x557f9c
0x00430028:	movl 0x557f98, %eax
0x0043002d:	call 0x0042fa6a
0x00430032:	addl %esp, $0x10<UINT8>
0x00430035:	movl 0x557f9c, %eax
0x0043003a:	call 0x0042ce1d
0x0042ce1d:	movl %edi, %edi
0x0042ce1f:	pushl %esi
0x0042ce20:	pushl %edi
0x0042ce21:	xorl %esi, %esi
0x0042ce23:	movl %edi, $0x557b10<UINT32>
0x0042ce28:	cmpl 0x551434(,%esi,8), $0x1<UINT8>
0x0042ce30:	jne 0x0042ce50
0x0042ce32:	leal %eax, 0x551430(,%esi,8)
0x0042ce39:	movl (%eax), %edi
0x0042ce3b:	pushl $0xfa0<UINT32>
0x0042ce40:	pushl (%eax)
0x0042ce42:	addl %edi, $0x18<UINT8>
0x0042ce45:	call 0x004306a2
0x004306a2:	pushl $0x10<UINT8>
0x004306a4:	pushl $0x54beb0<UINT32>
0x004306a9:	call 0x0042da90
0x004306ae:	andl -4(%ebp), $0x0<UINT8>
0x004306b2:	pushl 0xc(%ebp)
0x004306b5:	pushl 0x8(%ebp)
0x004306b8:	call InitializeCriticalSectionAndSpinCount@KERNEL32.DLL
InitializeCriticalSectionAndSpinCount@KERNEL32.DLL: API Node	
0x004306be:	movl -28(%ebp), %eax
0x004306c1:	jmp 0x004306f2
0x004306f2:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004306f9:	movl %eax, -28(%ebp)
0x004306fc:	call 0x0042dad5
0x0042dad5:	movl %ecx, -16(%ebp)
0x0042dad8:	movl %fs:0, %ecx
0x0042dadf:	popl %ecx
0x0042dae0:	popl %edi
0x0042dae1:	popl %edi
0x0042dae2:	popl %esi
0x0042dae3:	popl %ebx
0x0042dae4:	movl %esp, %ebp
0x0042dae6:	popl %ebp
0x0042dae7:	pushl %ecx
0x0042dae8:	ret

0x00430701:	ret

0x0042ce4a:	popl %ecx
0x0042ce4b:	popl %ecx
0x0042ce4c:	testl %eax, %eax
0x0042ce4e:	je 12
0x0042ce50:	incl %esi
0x0042ce51:	cmpl %esi, $0x24<UINT8>
0x0042ce54:	jl 0x0042ce28
0x0042ce56:	xorl %eax, %eax
0x0042ce58:	incl %eax
0x0042ce59:	popl %edi
0x0042ce5a:	popl %esi
0x0042ce5b:	ret

0x0043003f:	testl %eax, %eax
0x00430041:	je 101
0x00430043:	pushl $0x42fd88<UINT32>
0x00430048:	pushl 0x557f90
0x0043004e:	call 0x0042fae5
0x0042fae5:	movl %edi, %edi
0x0042fae7:	pushl %ebp
0x0042fae8:	movl %ebp, %esp
0x0042faea:	pushl %esi
0x0042faeb:	pushl 0x55165c
0x0042faf1:	movl %esi, 0x43e1b8
0x0042faf7:	call TlsGetValue@KERNEL32.DLL
0x0042faf9:	testl %eax, %eax
0x0042fafb:	je 33
0x0042fafd:	movl %eax, 0x551658
0x0042fb02:	cmpl %eax, $0xffffffff<UINT8>
0x0042fb05:	je 0x0042fb1e
0x0042fb1e:	movl %esi, $0x43eb74<UINT32>
0x0042fb23:	pushl %esi
0x0042fb24:	call GetModuleHandleW@KERNEL32.DLL
0x0042fb2a:	testl %eax, %eax
0x0042fb2c:	jne 0x0042fb39
0x0042fb39:	pushl $0x43eb90<UINT32>
0x0042fb3e:	pushl %eax
0x0042fb3f:	call GetProcAddress@KERNEL32.DLL
0x0042fb45:	testl %eax, %eax
0x0042fb47:	je 8
0x0042fb49:	pushl 0x8(%ebp)
0x0042fb4c:	call DecodePointer@KERNEL32.DLL
DecodePointer@KERNEL32.DLL: API Node	
0x0042fb4e:	movl 0x8(%ebp), %eax
0x0042fb51:	movl %eax, 0x8(%ebp)
0x0042fb54:	popl %esi
0x0042fb55:	popl %ebp
0x0042fb56:	ret

0x00430053:	popl %ecx
0x00430054:	call FlsAlloc@KERNEL32.DLL
FlsAlloc@KERNEL32.DLL: API Node	
0x00430056:	movl 0x551658, %eax
0x0043005b:	cmpl %eax, $0xffffffff<UINT8>
0x0043005e:	je 72
0x00430060:	pushl $0x214<UINT32>
0x00430065:	pushl $0x1<UINT8>
0x00430067:	call 0x0042e160
0x0042e160:	movl %edi, %edi
0x0042e162:	pushl %ebp
0x0042e163:	movl %ebp, %esp
0x0042e165:	pushl %esi
0x0042e166:	pushl %edi
0x0042e167:	xorl %esi, %esi
0x0042e169:	pushl $0x0<UINT8>
0x0042e16b:	pushl 0xc(%ebp)
0x0042e16e:	pushl 0x8(%ebp)
0x0042e171:	call 0x004344f2
0x004344f2:	pushl $0xc<UINT8>
0x004344f4:	pushl $0x54bfd0<UINT32>
0x004344f9:	call 0x0042da90
0x004344fe:	movl %ecx, 0x8(%ebp)
0x00434501:	xorl %edi, %edi
0x00434503:	cmpl %ecx, %edi
0x00434505:	jbe 46
0x00434507:	pushl $0xffffffe0<UINT8>
0x00434509:	popl %eax
0x0043450a:	xorl %edx, %edx
0x0043450c:	divl %eax, %ecx
0x0043450e:	cmpl %eax, 0xc(%ebp)
0x00434511:	sbbl %eax, %eax
0x00434513:	incl %eax
0x00434514:	jne 0x00434535
0x00434535:	imull %ecx, 0xc(%ebp)
0x00434539:	movl %esi, %ecx
0x0043453b:	movl 0x8(%ebp), %esi
0x0043453e:	cmpl %esi, %edi
0x00434540:	jne 0x00434545
0x00434545:	xorl %ebx, %ebx
0x00434547:	movl -28(%ebp), %ebx
0x0043454a:	cmpl %esi, $0xffffffe0<UINT8>
0x0043454d:	ja 105
0x0043454f:	cmpl 0x558a60, $0x3<UINT8>
0x00434556:	jne 0x004345a3
0x004345a3:	cmpl %ebx, %edi
0x004345a5:	jne 97
0x004345a7:	pushl %esi
0x004345a8:	pushl $0x8<UINT8>
0x004345aa:	pushl 0x557c64
0x004345b0:	call HeapAlloc@KERNEL32.DLL
HeapAlloc@KERNEL32.DLL: API Node	
0x004345b6:	movl %ebx, %eax
0x004345b8:	cmpl %ebx, %edi
0x004345ba:	jne 0x00434608
0x00434608:	movl %eax, %ebx
0x0043460a:	call 0x0042dad5
0x0043460f:	ret

0x0042e176:	movl %edi, %eax
0x0042e178:	addl %esp, $0xc<UINT8>
0x0042e17b:	testl %edi, %edi
0x0042e17d:	jne 0x0042e1a6
0x0042e1a6:	movl %eax, %edi
0x0042e1a8:	popl %edi
0x0042e1a9:	popl %esi
0x0042e1aa:	popl %ebp
0x0042e1ab:	ret

0x0043006c:	movl %esi, %eax
0x0043006e:	popl %ecx
0x0043006f:	popl %ecx
0x00430070:	testl %esi, %esi
0x00430072:	je 52
0x00430074:	pushl %esi
0x00430075:	pushl 0x551658
0x0043007b:	pushl 0x557f98
0x00430081:	call 0x0042fae5
0x0042fb07:	pushl %eax
0x0042fb08:	pushl 0x55165c
0x0042fb0e:	call TlsGetValue@KERNEL32.DLL
0x0042fb10:	call FlsGetValue@KERNEL32.DLL
FlsGetValue@KERNEL32.DLL: API Node	
0x0042fb12:	testl %eax, %eax
0x0042fb14:	je 0x0042fb1e
0x00430086:	popl %ecx
0x00430087:	call FlsSetValue@KERNEL32.DLL
FlsSetValue@KERNEL32.DLL: API Node	
0x00430089:	testl %eax, %eax
0x0043008b:	je 27
0x0043008d:	pushl $0x0<UINT8>
0x0043008f:	pushl %esi
0x00430090:	call 0x0042fc0e
0x0042fc0e:	pushl $0xc<UINT8>
0x0042fc10:	pushl $0x54bde0<UINT32>
0x0042fc15:	call 0x0042da90
0x0042fc1a:	movl %esi, $0x43eb74<UINT32>
0x0042fc1f:	pushl %esi
0x0042fc20:	call GetModuleHandleW@KERNEL32.DLL
0x0042fc26:	testl %eax, %eax
0x0042fc28:	jne 0x0042fc31
0x0042fc31:	movl -28(%ebp), %eax
0x0042fc34:	movl %esi, 0x8(%ebp)
0x0042fc37:	movl 0x5c(%esi), $0x43ebd0<UINT32>
0x0042fc3e:	xorl %edi, %edi
0x0042fc40:	incl %edi
0x0042fc41:	movl 0x14(%esi), %edi
0x0042fc44:	testl %eax, %eax
0x0042fc46:	je 36
0x0042fc48:	pushl $0x43eb64<UINT32>
0x0042fc4d:	pushl %eax
0x0042fc4e:	movl %ebx, 0x43e220
0x0042fc54:	call GetProcAddress@KERNEL32.DLL
0x0042fc56:	movl 0x1f8(%esi), %eax
0x0042fc5c:	pushl $0x43eb90<UINT32>
0x0042fc61:	pushl -28(%ebp)
0x0042fc64:	call GetProcAddress@KERNEL32.DLL
0x0042fc66:	movl 0x1fc(%esi), %eax
0x0042fc6c:	movl 0x70(%esi), %edi
0x0042fc6f:	movb 0xc8(%esi), $0x43<UINT8>
0x0042fc76:	movb 0x14b(%esi), $0x43<UINT8>
0x0042fc7d:	movl 0x68(%esi), $0x551698<UINT32>
0x0042fc84:	pushl $0xd<UINT8>
0x0042fc86:	call 0x0042cf99
0x0042cf99:	movl %edi, %edi
0x0042cf9b:	pushl %ebp
0x0042cf9c:	movl %ebp, %esp
0x0042cf9e:	movl %eax, 0x8(%ebp)
0x0042cfa1:	pushl %esi
0x0042cfa2:	leal %esi, 0x551430(,%eax,8)
0x0042cfa9:	cmpl (%esi), $0x0<UINT8>
0x0042cfac:	jne 0x0042cfc1
0x0042cfc1:	pushl (%esi)
0x0042cfc3:	call EnterCriticalSection@KERNEL32.DLL
EnterCriticalSection@KERNEL32.DLL: API Node	
0x0042cfc9:	popl %esi
0x0042cfca:	popl %ebp
0x0042cfcb:	ret

0x0042fc8b:	popl %ecx
0x0042fc8c:	andl -4(%ebp), $0x0<UINT8>
0x0042fc90:	pushl 0x68(%esi)
0x0042fc93:	call InterlockedIncrement@KERNEL32.DLL
InterlockedIncrement@KERNEL32.DLL: API Node	
0x0042fc99:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0042fca0:	call 0x0042fce3
0x0042fce3:	pushl $0xd<UINT8>
0x0042fce5:	call 0x0042cebf
0x0042cebf:	movl %edi, %edi
0x0042cec1:	pushl %ebp
0x0042cec2:	movl %ebp, %esp
0x0042cec4:	movl %eax, 0x8(%ebp)
0x0042cec7:	pushl 0x551430(,%eax,8)
0x0042cece:	call LeaveCriticalSection@KERNEL32.DLL
LeaveCriticalSection@KERNEL32.DLL: API Node	
0x0042ced4:	popl %ebp
0x0042ced5:	ret

0x0042fcea:	popl %ecx
0x0042fceb:	ret

0x0042fca5:	pushl $0xc<UINT8>
0x0042fca7:	call 0x0042cf99
0x0042fcac:	popl %ecx
0x0042fcad:	movl -4(%ebp), %edi
0x0042fcb0:	movl %eax, 0xc(%ebp)
0x0042fcb3:	movl 0x6c(%esi), %eax
0x0042fcb6:	testl %eax, %eax
0x0042fcb8:	jne 8
0x0042fcba:	movl %eax, 0x551ca0
0x0042fcbf:	movl 0x6c(%esi), %eax
0x0042fcc2:	pushl 0x6c(%esi)
0x0042fcc5:	call 0x00430f2e
0x00430f2e:	movl %edi, %edi
0x00430f30:	pushl %ebp
0x00430f31:	movl %ebp, %esp
0x00430f33:	pushl %ebx
0x00430f34:	pushl %esi
0x00430f35:	movl %esi, 0x43e0b0
0x00430f3b:	pushl %edi
0x00430f3c:	movl %edi, 0x8(%ebp)
0x00430f3f:	pushl %edi
0x00430f40:	call InterlockedIncrement@KERNEL32.DLL
0x00430f42:	movl %eax, 0xb0(%edi)
0x00430f48:	testl %eax, %eax
0x00430f4a:	je 0x00430f4f
0x00430f4f:	movl %eax, 0xb8(%edi)
0x00430f55:	testl %eax, %eax
0x00430f57:	je 0x00430f5c
0x00430f5c:	movl %eax, 0xb4(%edi)
0x00430f62:	testl %eax, %eax
0x00430f64:	je 0x00430f69
0x00430f69:	movl %eax, 0xc0(%edi)
0x00430f6f:	testl %eax, %eax
0x00430f71:	je 0x00430f76
0x00430f76:	leal %ebx, 0x50(%edi)
0x00430f79:	movl 0x8(%ebp), $0x6<UINT32>
0x00430f80:	cmpl -8(%ebx), $0x551bc0<UINT32>
0x00430f87:	je 0x00430f92
0x00430f89:	movl %eax, (%ebx)
0x00430f8b:	testl %eax, %eax
0x00430f8d:	je 0x00430f92
0x00430f92:	cmpl -4(%ebx), $0x0<UINT8>
0x00430f96:	je 0x00430fa2
0x00430fa2:	addl %ebx, $0x10<UINT8>
0x00430fa5:	decl 0x8(%ebp)
0x00430fa8:	jne 0x00430f80
0x00430faa:	movl %eax, 0xd4(%edi)
0x00430fb0:	addl %eax, $0xb4<UINT32>
0x00430fb5:	pushl %eax
0x00430fb6:	call InterlockedIncrement@KERNEL32.DLL
0x00430fb8:	popl %edi
0x00430fb9:	popl %esi
0x00430fba:	popl %ebx
0x00430fbb:	popl %ebp
0x00430fbc:	ret

0x0042fcca:	popl %ecx
0x0042fccb:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0042fcd2:	call 0x0042fcec
0x0042fcec:	pushl $0xc<UINT8>
0x0042fcee:	call 0x0042cebf
0x0042fcf3:	popl %ecx
0x0042fcf4:	ret

0x0042fcd7:	call 0x0042dad5
0x0042fcdc:	ret

0x00430095:	popl %ecx
0x00430096:	popl %ecx
0x00430097:	call GetCurrentThreadId@KERNEL32.DLL
0x0043009d:	orl 0x4(%esi), $0xffffffff<UINT8>
0x004300a1:	movl (%esi), %eax
0x004300a3:	xorl %eax, %eax
0x004300a5:	incl %eax
0x004300a6:	jmp 0x004300af
0x004300af:	popl %edi
0x004300b0:	popl %esi
0x004300b1:	ret

0x0042be3b:	testl %eax, %eax
0x0042be3d:	jne 0x0042be47
0x0042be47:	call 0x004300b2
0x004300b2:	movl %edi, %edi
0x004300b4:	pushl %esi
0x004300b5:	movl %eax, $0x54bb64<UINT32>
0x004300ba:	movl %esi, $0x54bb64<UINT32>
0x004300bf:	pushl %edi
0x004300c0:	movl %edi, %eax
0x004300c2:	cmpl %eax, %esi
0x004300c4:	jae 0x004300d5
0x004300d5:	popl %edi
0x004300d6:	popl %esi
0x004300d7:	ret

0x0042be4c:	movl -4(%ebp), %ebx
0x0042be4f:	call 0x0042dec7
0x0042dec7:	pushl $0x54<UINT8>
0x0042dec9:	pushl $0x54bd60<UINT32>
0x0042dece:	call 0x0042da90
0x0042ded3:	xorl %edi, %edi
0x0042ded5:	movl -4(%ebp), %edi
0x0042ded8:	leal %eax, -100(%ebp)
0x0042dedb:	pushl %eax
0x0042dedc:	call GetStartupInfoA@KERNEL32.DLL
0x0042dee2:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0042dee9:	pushl $0x40<UINT8>
0x0042deeb:	pushl $0x20<UINT8>
0x0042deed:	popl %esi
0x0042deee:	pushl %esi
0x0042deef:	call 0x0042e160
0x0042def4:	popl %ecx
0x0042def5:	popl %ecx
0x0042def6:	cmpl %eax, %edi
0x0042def8:	je 532
0x0042defe:	movl 0x558960, %eax
0x0042df03:	movl 0x558948, %esi
0x0042df09:	leal %ecx, 0x800(%eax)
0x0042df0f:	jmp 0x0042df41
0x0042df41:	cmpl %eax, %ecx
0x0042df43:	jb 0x0042df11
0x0042df11:	movb 0x4(%eax), $0x0<UINT8>
0x0042df15:	orl (%eax), $0xffffffff<UINT8>
0x0042df18:	movb 0x5(%eax), $0xa<UINT8>
0x0042df1c:	movl 0x8(%eax), %edi
0x0042df1f:	movb 0x24(%eax), $0x0<UINT8>
0x0042df23:	movb 0x25(%eax), $0xa<UINT8>
0x0042df27:	movb 0x26(%eax), $0xa<UINT8>
0x0042df2b:	movl 0x38(%eax), %edi
0x0042df2e:	movb 0x34(%eax), $0x0<UINT8>
0x0042df32:	addl %eax, $0x40<UINT8>
0x0042df35:	movl %ecx, 0x558960
0x0042df3b:	addl %ecx, $0x800<UINT32>
0x0042df45:	cmpw -50(%ebp), %di
0x0042df49:	je 266
0x0042df4f:	movl %eax, -48(%ebp)
0x0042df52:	cmpl %eax, %edi
0x0042df54:	je 255
0x0042df5a:	movl %edi, (%eax)
0x0042df5c:	leal %ebx, 0x4(%eax)
0x0042df5f:	leal %eax, (%ebx,%edi)
0x0042df62:	movl -28(%ebp), %eax
0x0042df65:	movl %esi, $0x800<UINT32>
0x0042df6a:	cmpl %edi, %esi
0x0042df6c:	jl 0x0042df70
0x0042df70:	movl -32(%ebp), $0x1<UINT32>
0x0042df77:	jmp 0x0042dfd4
0x0042dfd4:	cmpl 0x558948, %edi
0x0042dfda:	jl -99
0x0042dfdc:	jmp 0x0042dfe4
0x0042dfe4:	andl -32(%ebp), $0x0<UINT8>
0x0042dfe8:	testl %edi, %edi
0x0042dfea:	jle 0x0042e059
0x0042e059:	xorl %ebx, %ebx
0x0042e05b:	movl %esi, %ebx
0x0042e05d:	shll %esi, $0x6<UINT8>
0x0042e060:	addl %esi, 0x558960
0x0042e066:	movl %eax, (%esi)
0x0042e068:	cmpl %eax, $0xffffffff<UINT8>
0x0042e06b:	je 0x0042e078
0x0042e078:	movb 0x4(%esi), $0xffffff81<UINT8>
0x0042e07c:	testl %ebx, %ebx
0x0042e07e:	jne 0x0042e085
0x0042e080:	pushl $0xfffffff6<UINT8>
0x0042e082:	popl %eax
0x0042e083:	jmp 0x0042e08f
0x0042e08f:	pushl %eax
0x0042e090:	call GetStdHandle@KERNEL32.DLL
GetStdHandle@KERNEL32.DLL: API Node	
0x0042e096:	movl %edi, %eax
0x0042e098:	cmpl %edi, $0xffffffff<UINT8>
0x0042e09b:	je 67
0x0042e09d:	testl %edi, %edi
0x0042e09f:	je 63
0x0042e0a1:	pushl %edi
0x0042e0a2:	call GetFileType@KERNEL32.DLL
GetFileType@KERNEL32.DLL: API Node	
0x0042e0a8:	testl %eax, %eax
0x0042e0aa:	je 52
0x0042e0ac:	movl (%esi), %edi
0x0042e0ae:	andl %eax, $0xff<UINT32>
0x0042e0b3:	cmpl %eax, $0x2<UINT8>
0x0042e0b6:	jne 6
0x0042e0b8:	orb 0x4(%esi), $0x40<UINT8>
0x0042e0bc:	jmp 0x0042e0c7
0x0042e0c7:	pushl $0xfa0<UINT32>
0x0042e0cc:	leal %eax, 0xc(%esi)
0x0042e0cf:	pushl %eax
0x0042e0d0:	call 0x004306a2
0x0042e0d5:	popl %ecx
0x0042e0d6:	popl %ecx
0x0042e0d7:	testl %eax, %eax
0x0042e0d9:	je 55
0x0042e0db:	incl 0x8(%esi)
0x0042e0de:	jmp 0x0042e0ea
0x0042e0ea:	incl %ebx
0x0042e0eb:	cmpl %ebx, $0x3<UINT8>
0x0042e0ee:	jl 0x0042e05b
0x0042e085:	movl %eax, %ebx
0x0042e087:	decl %eax
0x0042e088:	negl %eax
0x0042e08a:	sbbl %eax, %eax
0x0042e08c:	addl %eax, $0xfffffff5<UINT8>
0x0042e0f4:	pushl 0x558948
0x0042e0fa:	call SetHandleCount@KERNEL32.DLL
SetHandleCount@KERNEL32.DLL: API Node	
0x0042e100:	xorl %eax, %eax
0x0042e102:	jmp 0x0042e115
0x0042e115:	call 0x0042dad5
0x0042e11a:	ret

0x0042be54:	testl %eax, %eax
0x0042be56:	jnl 0x0042be60
0x0042be60:	call GetCommandLineA@KERNEL32.DLL
GetCommandLineA@KERNEL32.DLL: API Node	
0x0042be66:	movl 0x558a7c, %eax
0x0042be6b:	call 0x00433c1a
0x00433c1a:	movl %edi, %edi
0x00433c1c:	pushl %ebp
0x00433c1d:	movl %ebp, %esp
0x00433c1f:	movl %eax, 0x558120
0x00433c24:	subl %esp, $0xc<UINT8>
0x00433c27:	pushl %ebx
0x00433c28:	pushl %esi
0x00433c29:	movl %esi, 0x43e170
0x00433c2f:	pushl %edi
0x00433c30:	xorl %ebx, %ebx
0x00433c32:	xorl %edi, %edi
0x00433c34:	cmpl %eax, %ebx
0x00433c36:	jne 46
0x00433c38:	call GetEnvironmentStringsW@KERNEL32.DLL
GetEnvironmentStringsW@KERNEL32.DLL: API Node	
0x00433c3a:	movl %edi, %eax
0x00433c3c:	cmpl %edi, %ebx
0x00433c3e:	je 12
0x00433c40:	movl 0x558120, $0x1<UINT32>
0x00433c4a:	jmp 0x00433c6f
0x00433c6f:	cmpl %edi, %ebx
0x00433c71:	jne 0x00433c82
0x00433c82:	movl %eax, %edi
0x00433c84:	cmpw (%edi), %bx
0x00433c87:	je 14
0x00433c89:	incl %eax
0x00433c8a:	incl %eax
0x00433c8b:	cmpw (%eax), %bx
0x00433c8e:	jne 0x00433c89
0x00433c90:	incl %eax
0x00433c91:	incl %eax
0x00433c92:	cmpw (%eax), %bx
0x00433c95:	jne 0x00433c89
0x00433c97:	movl %esi, 0x43e250
0x00433c9d:	pushl %ebx
0x00433c9e:	pushl %ebx
0x00433c9f:	pushl %ebx
0x00433ca0:	subl %eax, %edi
0x00433ca2:	pushl %ebx
0x00433ca3:	sarl %eax
0x00433ca5:	incl %eax
0x00433ca6:	pushl %eax
0x00433ca7:	pushl %edi
0x00433ca8:	pushl %ebx
0x00433ca9:	pushl %ebx
0x00433caa:	movl -12(%ebp), %eax
0x00433cad:	call WideCharToMultiByte@KERNEL32.DLL
WideCharToMultiByte@KERNEL32.DLL: API Node	
0x00433caf:	movl -8(%ebp), %eax
0x00433cb2:	cmpl %eax, %ebx
0x00433cb4:	je 47
0x00433cb6:	pushl %eax
0x00433cb7:	call 0x0042e11b
0x0042e11b:	movl %edi, %edi
0x0042e11d:	pushl %ebp
0x0042e11e:	movl %ebp, %esp
0x0042e120:	pushl %esi
0x0042e121:	pushl %edi
0x0042e122:	xorl %esi, %esi
0x0042e124:	pushl 0x8(%ebp)
0x0042e127:	call 0x00429734
0x00429734:	movl %edi, %edi
0x00429736:	pushl %ebp
0x00429737:	movl %ebp, %esp
0x00429739:	pushl %esi
0x0042973a:	movl %esi, 0x8(%ebp)
0x0042973d:	cmpl %esi, $0xffffffe0<UINT8>
0x00429740:	ja 161
0x00429746:	pushl %ebx
0x00429747:	pushl %edi
0x00429748:	movl %edi, 0x43e274
0x0042974e:	cmpl 0x557c64, $0x0<UINT8>
0x00429755:	jne 0x0042976f
0x0042976f:	movl %eax, 0x558a60
0x00429774:	cmpl %eax, $0x1<UINT8>
0x00429777:	jne 14
0x00429779:	testl %esi, %esi
0x0042977b:	je 4
0x0042977d:	movl %eax, %esi
0x0042977f:	jmp 0x00429784
0x00429784:	pushl %eax
0x00429785:	jmp 0x004297a3
0x004297a3:	pushl $0x0<UINT8>
0x004297a5:	pushl 0x557c64
0x004297ab:	call HeapAlloc@KERNEL32.DLL
0x004297ad:	movl %ebx, %eax
0x004297af:	testl %ebx, %ebx
0x004297b1:	jne 0x004297e1
0x004297e1:	popl %edi
0x004297e2:	movl %eax, %ebx
0x004297e4:	popl %ebx
0x004297e5:	jmp 0x004297fb
0x004297fb:	popl %esi
0x004297fc:	popl %ebp
0x004297fd:	ret

0x0042e12c:	movl %edi, %eax
0x0042e12e:	popl %ecx
0x0042e12f:	testl %edi, %edi
0x0042e131:	jne 0x0042e15a
0x0042e15a:	movl %eax, %edi
0x0042e15c:	popl %edi
0x0042e15d:	popl %esi
0x0042e15e:	popl %ebp
0x0042e15f:	ret

0x00433cbc:	popl %ecx
0x00433cbd:	movl -4(%ebp), %eax
0x00433cc0:	cmpl %eax, %ebx
0x00433cc2:	je 33
0x00433cc4:	pushl %ebx
0x00433cc5:	pushl %ebx
0x00433cc6:	pushl -8(%ebp)
0x00433cc9:	pushl %eax
0x00433cca:	pushl -12(%ebp)
0x00433ccd:	pushl %edi
0x00433cce:	pushl %ebx
0x00433ccf:	pushl %ebx
0x00433cd0:	call WideCharToMultiByte@KERNEL32.DLL
0x00433cd2:	testl %eax, %eax
0x00433cd4:	jne 0x00433ce2
0x00433ce2:	movl %ebx, -4(%ebp)
0x00433ce5:	pushl %edi
0x00433ce6:	call FreeEnvironmentStringsW@KERNEL32.DLL
FreeEnvironmentStringsW@KERNEL32.DLL: API Node	
0x00433cec:	movl %eax, %ebx
0x00433cee:	jmp 0x00433d4c
0x00433d4c:	popl %edi
0x00433d4d:	popl %esi
0x00433d4e:	popl %ebx
0x00433d4f:	leave
0x00433d50:	ret

0x0042be70:	movl 0x5577dc, %eax
0x0042be75:	call 0x00433b5f
0x00433b5f:	movl %edi, %edi
0x00433b61:	pushl %ebp
0x00433b62:	movl %ebp, %esp
0x00433b64:	subl %esp, $0xc<UINT8>
0x00433b67:	pushl %ebx
0x00433b68:	xorl %ebx, %ebx
0x00433b6a:	pushl %esi
0x00433b6b:	pushl %edi
0x00433b6c:	cmpl 0x558a8c, %ebx
0x00433b72:	jne 5
0x00433b74:	call 0x00430dc7
0x00430dc7:	cmpl 0x558a8c, $0x0<UINT8>
0x00430dce:	jne 0x00430de2
0x00430dd0:	pushl $0xfffffffd<UINT8>
0x00430dd2:	call 0x00430c2d
0x00430c2d:	pushl $0x14<UINT8>
0x00430c2f:	pushl $0x54bef0<UINT32>
0x00430c34:	call 0x0042da90
0x00430c39:	orl -32(%ebp), $0xffffffff<UINT8>
0x00430c3d:	call 0x0042fd6e
0x0042fd6e:	movl %edi, %edi
0x0042fd70:	pushl %esi
0x0042fd71:	call 0x0042fcf5
0x0042fcf5:	movl %edi, %edi
0x0042fcf7:	pushl %esi
0x0042fcf8:	pushl %edi
0x0042fcf9:	call GetLastError@KERNEL32.DLL
GetLastError@KERNEL32.DLL: API Node	
0x0042fcff:	pushl 0x551658
0x0042fd05:	movl %edi, %eax
0x0042fd07:	call 0x0042fb80
0x0042fb80:	movl %edi, %edi
0x0042fb82:	pushl %esi
0x0042fb83:	pushl 0x55165c
0x0042fb89:	call TlsGetValue@KERNEL32.DLL
0x0042fb8f:	movl %esi, %eax
0x0042fb91:	testl %esi, %esi
0x0042fb93:	jne 0x0042fbb0
0x0042fbb0:	movl %eax, %esi
0x0042fbb2:	popl %esi
0x0042fbb3:	ret

0x0042fd0c:	call FlsGetValue@KERNEL32.DLL
0x0042fd0e:	movl %esi, %eax
0x0042fd10:	testl %esi, %esi
0x0042fd12:	jne 0x0042fd62
0x0042fd62:	pushl %edi
0x0042fd63:	call SetLastError@KERNEL32.DLL
SetLastError@KERNEL32.DLL: API Node	
0x0042fd69:	popl %edi
0x0042fd6a:	movl %eax, %esi
0x0042fd6c:	popl %esi
0x0042fd6d:	ret

0x0042fd76:	movl %esi, %eax
0x0042fd78:	testl %esi, %esi
0x0042fd7a:	jne 0x0042fd84
0x0042fd84:	movl %eax, %esi
0x0042fd86:	popl %esi
0x0042fd87:	ret

0x00430c42:	movl %edi, %eax
0x00430c44:	movl -36(%ebp), %edi
0x00430c47:	call 0x00430928
0x00430928:	pushl $0xc<UINT8>
0x0043092a:	pushl $0x54bed0<UINT32>
0x0043092f:	call 0x0042da90
0x00430934:	call 0x0042fd6e
0x00430939:	movl %edi, %eax
0x0043093b:	movl %eax, 0x551bbc
0x00430940:	testl 0x70(%edi), %eax
0x00430943:	je 0x00430962
0x00430962:	pushl $0xd<UINT8>
0x00430964:	call 0x0042cf99
0x00430969:	popl %ecx
0x0043096a:	andl -4(%ebp), $0x0<UINT8>
0x0043096e:	movl %esi, 0x68(%edi)
0x00430971:	movl -28(%ebp), %esi
0x00430974:	cmpl %esi, 0x551ac0
0x0043097a:	je 0x004309b2
0x004309b2:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004309b9:	call 0x004309c3
0x004309c3:	pushl $0xd<UINT8>
0x004309c5:	call 0x0042cebf
0x004309ca:	popl %ecx
0x004309cb:	ret

0x004309be:	jmp 0x0043094e
0x0043094e:	testl %esi, %esi
0x00430950:	jne 0x0043095a
0x0043095a:	movl %eax, %esi
0x0043095c:	call 0x0042dad5
0x00430961:	ret

0x00430c4c:	movl %ebx, 0x68(%edi)
0x00430c4f:	movl %esi, 0x8(%ebp)
0x00430c52:	call 0x004309cc
0x004309cc:	movl %edi, %edi
0x004309ce:	pushl %ebp
0x004309cf:	movl %ebp, %esp
0x004309d1:	subl %esp, $0x10<UINT8>
0x004309d4:	pushl %ebx
0x004309d5:	xorl %ebx, %ebx
0x004309d7:	pushl %ebx
0x004309d8:	leal %ecx, -16(%ebp)
0x004309db:	call 0x00429f9a
0x00429f9a:	movl %edi, %edi
0x00429f9c:	pushl %ebp
0x00429f9d:	movl %ebp, %esp
0x00429f9f:	movl %eax, 0x8(%ebp)
0x00429fa2:	pushl %esi
0x00429fa3:	movl %esi, %ecx
0x00429fa5:	movb 0xc(%esi), $0x0<UINT8>
0x00429fa9:	testl %eax, %eax
0x00429fab:	jne 99
0x00429fad:	call 0x0042fd6e
0x00429fb2:	movl 0x8(%esi), %eax
0x00429fb5:	movl %ecx, 0x6c(%eax)
0x00429fb8:	movl (%esi), %ecx
0x00429fba:	movl %ecx, 0x68(%eax)
0x00429fbd:	movl 0x4(%esi), %ecx
0x00429fc0:	movl %ecx, (%esi)
0x00429fc2:	cmpl %ecx, 0x551ca0
0x00429fc8:	je 0x00429fdc
0x00429fdc:	movl %eax, 0x4(%esi)
0x00429fdf:	cmpl %eax, 0x551ac0
0x00429fe5:	je 0x00429ffd
0x00429ffd:	movl %eax, 0x8(%esi)
0x0042a000:	testb 0x70(%eax), $0x2<UINT8>
0x0042a004:	jne 20
0x0042a006:	orl 0x70(%eax), $0x2<UINT8>
0x0042a00a:	movb 0xc(%esi), $0x1<UINT8>
0x0042a00e:	jmp 0x0042a01a
0x0042a01a:	movl %eax, %esi
0x0042a01c:	popl %esi
0x0042a01d:	popl %ebp
0x0042a01e:	ret $0x4<UINT16>

0x004309e0:	movl 0x557fcc, %ebx
0x004309e6:	cmpl %esi, $0xfffffffe<UINT8>
0x004309e9:	jne 0x00430a09
0x00430a09:	cmpl %esi, $0xfffffffd<UINT8>
0x00430a0c:	jne 0x00430a20
0x00430a0e:	movl 0x557fcc, $0x1<UINT32>
0x00430a18:	call GetACP@KERNEL32.DLL
GetACP@KERNEL32.DLL: API Node	
0x00430a1e:	jmp 0x004309fb
0x004309fb:	cmpb -4(%ebp), %bl
0x004309fe:	je 69
0x00430a00:	movl %ecx, -8(%ebp)
0x00430a03:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00430a07:	jmp 0x00430a45
0x00430a45:	popl %ebx
0x00430a46:	leave
0x00430a47:	ret

0x00430c57:	movl 0x8(%ebp), %eax
0x00430c5a:	cmpl %eax, 0x4(%ebx)
0x00430c5d:	je 343
0x00430c63:	pushl $0x220<UINT32>
0x00430c68:	call 0x0042e11b
0x00430c6d:	popl %ecx
0x00430c6e:	movl %ebx, %eax
0x00430c70:	testl %ebx, %ebx
0x00430c72:	je 326
0x00430c78:	movl %ecx, $0x88<UINT32>
0x00430c7d:	movl %esi, 0x68(%edi)
0x00430c80:	movl %edi, %ebx
0x00430c82:	rep movsl %es:(%edi), %ds:(%esi)
0x00430c84:	andl (%ebx), $0x0<UINT8>
0x00430c87:	pushl %ebx
0x00430c88:	pushl 0x8(%ebp)
0x00430c8b:	call 0x00430a48
0x00430a48:	movl %edi, %edi
0x00430a4a:	pushl %ebp
0x00430a4b:	movl %ebp, %esp
0x00430a4d:	subl %esp, $0x20<UINT8>
0x00430a50:	movl %eax, 0x5512b4
0x00430a55:	xorl %eax, %ebp
0x00430a57:	movl -4(%ebp), %eax
0x00430a5a:	pushl %ebx
0x00430a5b:	movl %ebx, 0xc(%ebp)
0x00430a5e:	pushl %esi
0x00430a5f:	movl %esi, 0x8(%ebp)
0x00430a62:	pushl %edi
0x00430a63:	call 0x004309cc
0x00430a20:	cmpl %esi, $0xfffffffc<UINT8>
0x00430a23:	jne 0x00430a37
0x00430a37:	cmpb -4(%ebp), %bl
0x00430a3a:	je 7
0x00430a3c:	movl %eax, -8(%ebp)
0x00430a3f:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x00430a43:	movl %eax, %esi
0x00430a68:	movl %edi, %eax
0x00430a6a:	xorl %esi, %esi
0x00430a6c:	movl 0x8(%ebp), %edi
0x00430a6f:	cmpl %edi, %esi
0x00430a71:	jne 0x00430a81
0x00430a81:	movl -28(%ebp), %esi
0x00430a84:	xorl %eax, %eax
0x00430a86:	cmpl 0x551ac8(%eax), %edi
0x00430a8c:	je 145
0x00430a92:	incl -28(%ebp)
0x00430a95:	addl %eax, $0x30<UINT8>
0x00430a98:	cmpl %eax, $0xf0<UINT32>
0x00430a9d:	jb 0x00430a86
0x00430a9f:	cmpl %edi, $0xfde8<UINT32>
0x00430aa5:	je 368
0x00430aab:	cmpl %edi, $0xfde9<UINT32>
0x00430ab1:	je 356
0x00430ab7:	movzwl %eax, %di
0x00430aba:	pushl %eax
0x00430abb:	call IsValidCodePage@KERNEL32.DLL
IsValidCodePage@KERNEL32.DLL: API Node	
0x00430ac1:	testl %eax, %eax
0x00430ac3:	je 338
0x00430ac9:	leal %eax, -24(%ebp)
0x00430acc:	pushl %eax
0x00430acd:	pushl %edi
0x00430ace:	call GetCPInfo@KERNEL32.DLL
GetCPInfo@KERNEL32.DLL: API Node	
0x00430ad4:	testl %eax, %eax
0x00430ad6:	je 307
0x00430adc:	pushl $0x101<UINT32>
0x00430ae1:	leal %eax, 0x1c(%ebx)
0x00430ae4:	pushl %esi
0x00430ae5:	pushl %eax
0x00430ae6:	call 0x004316c0
0x004316c0:	movl %edx, 0xc(%esp)
0x004316c4:	movl %ecx, 0x4(%esp)
0x004316c8:	testl %edx, %edx
0x004316ca:	je 105
0x004316cc:	xorl %eax, %eax
0x004316ce:	movb %al, 0x8(%esp)
0x004316d2:	testb %al, %al
0x004316d4:	jne 22
0x004316d6:	cmpl %edx, $0x100<UINT32>
0x004316dc:	jb 14
0x004316de:	cmpl 0x558940, $0x0<UINT8>
0x004316e5:	je 0x004316ec
0x004316ec:	pushl %edi
0x004316ed:	movl %edi, %ecx
0x004316ef:	cmpl %edx, $0x4<UINT8>
0x004316f2:	jb 49
0x004316f4:	negl %ecx
0x004316f6:	andl %ecx, $0x3<UINT8>
0x004316f9:	je 0x00431707
0x00431707:	movl %ecx, %eax
0x00431709:	shll %eax, $0x8<UINT8>
0x0043170c:	addl %eax, %ecx
0x0043170e:	movl %ecx, %eax
0x00431710:	shll %eax, $0x10<UINT8>
0x00431713:	addl %eax, %ecx
0x00431715:	movl %ecx, %edx
0x00431717:	andl %edx, $0x3<UINT8>
0x0043171a:	shrl %ecx, $0x2<UINT8>
0x0043171d:	je 6
0x0043171f:	rep stosl %es:(%edi), %eax
0x00431721:	testl %edx, %edx
0x00431723:	je 0x0043172f
0x00431725:	movb (%edi), %al
0x00431727:	addl %edi, $0x1<UINT8>
0x0043172a:	subl %edx, $0x1<UINT8>
0x0043172d:	jne -10
0x0043172f:	movl %eax, 0x8(%esp)
0x00431733:	popl %edi
0x00431734:	ret

0x00430aeb:	xorl %edx, %edx
0x00430aed:	incl %edx
0x00430aee:	addl %esp, $0xc<UINT8>
0x00430af1:	movl 0x4(%ebx), %edi
0x00430af4:	movl 0xc(%ebx), %esi
0x00430af7:	cmpl -24(%ebp), %edx
0x00430afa:	jbe 248
0x00430b00:	cmpb -18(%ebp), $0x0<UINT8>
0x00430b04:	je 0x00430bd9
0x00430bd9:	leal %eax, 0x1e(%ebx)
0x00430bdc:	movl %ecx, $0xfe<UINT32>
0x00430be1:	orb (%eax), $0x8<UINT8>
0x00430be4:	incl %eax
0x00430be5:	decl %ecx
0x00430be6:	jne 0x00430be1
0x00430be8:	movl %eax, 0x4(%ebx)
0x00430beb:	call 0x00430702
0x00430702:	subl %eax, $0x3a4<UINT32>
0x00430707:	je 34
0x00430709:	subl %eax, $0x4<UINT8>
0x0043070c:	je 23
0x0043070e:	subl %eax, $0xd<UINT8>
0x00430711:	je 12
0x00430713:	decl %eax
0x00430714:	je 3
0x00430716:	xorl %eax, %eax
0x00430718:	ret

0x00430bf0:	movl 0xc(%ebx), %eax
0x00430bf3:	movl 0x8(%ebx), %edx
0x00430bf6:	jmp 0x00430bfb
0x00430bfb:	xorl %eax, %eax
0x00430bfd:	movzwl %ecx, %ax
0x00430c00:	movl %eax, %ecx
0x00430c02:	shll %ecx, $0x10<UINT8>
0x00430c05:	orl %eax, %ecx
0x00430c07:	leal %edi, 0x10(%ebx)
0x00430c0a:	stosl %es:(%edi), %eax
0x00430c0b:	stosl %es:(%edi), %eax
0x00430c0c:	stosl %es:(%edi), %eax
0x00430c0d:	jmp 0x00430bb7
0x00430bb7:	movl %esi, %ebx
0x00430bb9:	call 0x00430795
0x00430795:	movl %edi, %edi
0x00430797:	pushl %ebp
0x00430798:	movl %ebp, %esp
0x0043079a:	subl %esp, $0x51c<UINT32>
0x004307a0:	movl %eax, 0x5512b4
0x004307a5:	xorl %eax, %ebp
0x004307a7:	movl -4(%ebp), %eax
0x004307aa:	pushl %ebx
0x004307ab:	pushl %edi
0x004307ac:	leal %eax, -1304(%ebp)
0x004307b2:	pushl %eax
0x004307b3:	pushl 0x4(%esi)
0x004307b6:	call GetCPInfo@KERNEL32.DLL
0x004307bc:	movl %edi, $0x100<UINT32>
0x004307c1:	testl %eax, %eax
0x004307c3:	je 251
0x004307c9:	xorl %eax, %eax
0x004307cb:	movb -260(%ebp,%eax), %al
0x004307d2:	incl %eax
0x004307d3:	cmpl %eax, %edi
0x004307d5:	jb 0x004307cb
0x004307d7:	movb %al, -1298(%ebp)
0x004307dd:	movb -260(%ebp), $0x20<UINT8>
0x004307e4:	testb %al, %al
0x004307e6:	je 0x00430816
0x00430816:	pushl $0x0<UINT8>
0x00430818:	pushl 0xc(%esi)
0x0043081b:	leal %eax, -1284(%ebp)
0x00430821:	pushl 0x4(%esi)
0x00430824:	pushl %eax
0x00430825:	pushl %edi
0x00430826:	leal %eax, -260(%ebp)
0x0043082c:	pushl %eax
0x0043082d:	pushl $0x1<UINT8>
0x0043082f:	pushl $0x0<UINT8>
0x00430831:	call 0x00434faa
0x00434faa:	movl %edi, %edi
0x00434fac:	pushl %ebp
0x00434fad:	movl %ebp, %esp
0x00434faf:	subl %esp, $0x10<UINT8>
0x00434fb2:	pushl 0x8(%ebp)
0x00434fb5:	leal %ecx, -16(%ebp)
0x00434fb8:	call 0x00429f9a
0x00434fbd:	pushl 0x24(%ebp)
0x00434fc0:	leal %ecx, -16(%ebp)
0x00434fc3:	pushl 0x20(%ebp)
0x00434fc6:	pushl 0x1c(%ebp)
0x00434fc9:	pushl 0x18(%ebp)
0x00434fcc:	pushl 0x14(%ebp)
0x00434fcf:	pushl 0x10(%ebp)
0x00434fd2:	pushl 0xc(%ebp)
0x00434fd5:	call 0x00434df0
0x00434df0:	movl %edi, %edi
0x00434df2:	pushl %ebp
0x00434df3:	movl %ebp, %esp
0x00434df5:	pushl %ecx
0x00434df6:	pushl %ecx
0x00434df7:	movl %eax, 0x5512b4
0x00434dfc:	xorl %eax, %ebp
0x00434dfe:	movl -4(%ebp), %eax
0x00434e01:	movl %eax, 0x55813c
0x00434e06:	pushl %ebx
0x00434e07:	pushl %esi
0x00434e08:	xorl %ebx, %ebx
0x00434e0a:	pushl %edi
0x00434e0b:	movl %edi, %ecx
0x00434e0d:	cmpl %eax, %ebx
0x00434e0f:	jne 58
0x00434e11:	leal %eax, -8(%ebp)
0x00434e14:	pushl %eax
0x00434e15:	xorl %esi, %esi
0x00434e17:	incl %esi
0x00434e18:	pushl %esi
0x00434e19:	pushl $0x43ed24<UINT32>
0x00434e1e:	pushl %esi
0x00434e1f:	call GetStringTypeW@KERNEL32.DLL
GetStringTypeW@KERNEL32.DLL: API Node	
0x00434e25:	testl %eax, %eax
0x00434e27:	je 8
0x00434e29:	movl 0x55813c, %esi
0x00434e2f:	jmp 0x00434e65
0x00434e65:	movl -8(%ebp), %ebx
0x00434e68:	cmpl 0x18(%ebp), %ebx
0x00434e6b:	jne 0x00434e75
0x00434e75:	movl %esi, 0x43e184
0x00434e7b:	xorl %eax, %eax
0x00434e7d:	cmpl 0x20(%ebp), %ebx
0x00434e80:	pushl %ebx
0x00434e81:	pushl %ebx
0x00434e82:	pushl 0x10(%ebp)
0x00434e85:	setne %al
0x00434e88:	pushl 0xc(%ebp)
0x00434e8b:	leal %eax, 0x1(,%eax,8)
0x00434e92:	pushl %eax
0x00434e93:	pushl 0x18(%ebp)
0x00434e96:	call MultiByteToWideChar@KERNEL32.DLL
MultiByteToWideChar@KERNEL32.DLL: API Node	
0x00434e98:	movl %edi, %eax
0x00434e9a:	cmpl %edi, %ebx
0x00434e9c:	je 171
0x00434ea2:	jle 60
0x00434ea4:	cmpl %edi, $0x7ffffff0<UINT32>
0x00434eaa:	ja 52
0x00434eac:	leal %eax, 0x8(%edi,%edi)
0x00434eb0:	cmpl %eax, $0x400<UINT32>
0x00434eb5:	ja 19
0x00434eb7:	call 0x004368e0
0x004368e0:	pushl %ecx
0x004368e1:	leal %ecx, 0x8(%esp)
0x004368e5:	subl %ecx, %eax
0x004368e7:	andl %ecx, $0xf<UINT8>
0x004368ea:	addl %eax, %ecx
0x004368ec:	sbbl %ecx, %ecx
0x004368ee:	orl %eax, %ecx
0x004368f0:	popl %ecx
0x004368f1:	jmp 0x004346e0
0x004346e0:	pushl %ecx
0x004346e1:	leal %ecx, 0x4(%esp)
0x004346e5:	subl %ecx, %eax
0x004346e7:	sbbl %eax, %eax
0x004346e9:	notl %eax
0x004346eb:	andl %ecx, %eax
0x004346ed:	movl %eax, %esp
0x004346ef:	andl %eax, $0xfffff000<UINT32>
0x004346f4:	cmpl %ecx, %eax
0x004346f6:	jb 10
0x004346f8:	movl %eax, %ecx
0x004346fa:	popl %ecx
0x004346fb:	xchgl %esp, %eax
0x004346fc:	movl %eax, (%eax)
0x004346fe:	movl (%esp), %eax
0x00434701:	ret

0x00434ebc:	movl %eax, %esp
0x00434ebe:	cmpl %eax, %ebx
0x00434ec0:	je 28
0x00434ec2:	movl (%eax), $0xcccc<UINT32>
0x00434ec8:	jmp 0x00434edb
0x00434edb:	addl %eax, $0x8<UINT8>
0x00434ede:	movl %ebx, %eax
0x00434ee0:	testl %ebx, %ebx
0x00434ee2:	je 105
0x00434ee4:	leal %eax, (%edi,%edi)
0x00434ee7:	pushl %eax
0x00434ee8:	pushl $0x0<UINT8>
0x00434eea:	pushl %ebx
0x00434eeb:	call 0x004316c0
0x00434ef0:	addl %esp, $0xc<UINT8>
0x00434ef3:	pushl %edi
0x00434ef4:	pushl %ebx
0x00434ef5:	pushl 0x10(%ebp)
0x00434ef8:	pushl 0xc(%ebp)
0x00434efb:	pushl $0x1<UINT8>
0x00434efd:	pushl 0x18(%ebp)
0x00434f00:	call MultiByteToWideChar@KERNEL32.DLL
0x00434f02:	testl %eax, %eax
0x00434f04:	je 17
0x00434f06:	pushl 0x14(%ebp)
0x00434f09:	pushl %eax
0x00434f0a:	pushl %ebx
0x00434f0b:	pushl 0x8(%ebp)
0x00434f0e:	call GetStringTypeW@KERNEL32.DLL
0x00434f14:	movl -8(%ebp), %eax
0x00434f17:	pushl %ebx
0x00434f18:	call 0x00433064
0x00433064:	movl %edi, %edi
0x00433066:	pushl %ebp
0x00433067:	movl %ebp, %esp
0x00433069:	movl %eax, 0x8(%ebp)
0x0043306c:	testl %eax, %eax
0x0043306e:	je 18
0x00433070:	subl %eax, $0x8<UINT8>
0x00433073:	cmpl (%eax), $0xdddd<UINT32>
0x00433079:	jne 0x00433082
0x00433082:	popl %ebp
0x00433083:	ret

0x00434f1d:	movl %eax, -8(%ebp)
0x00434f20:	popl %ecx
0x00434f21:	jmp 0x00434f98
0x00434f98:	leal %esp, -20(%ebp)
0x00434f9b:	popl %edi
0x00434f9c:	popl %esi
0x00434f9d:	popl %ebx
0x00434f9e:	movl %ecx, -4(%ebp)
0x00434fa1:	xorl %ecx, %ebp
0x00434fa3:	call 0x00429620
0x00429620:	cmpl %ecx, 0x5512b4
0x00429626:	jne 2
0x00429628:	rep ret

0x00434fa8:	leave
0x00434fa9:	ret

0x00434fda:	addl %esp, $0x1c<UINT8>
0x00434fdd:	cmpb -4(%ebp), $0x0<UINT8>
0x00434fe1:	je 7
0x00434fe3:	movl %ecx, -8(%ebp)
0x00434fe6:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00434fea:	leave
0x00434feb:	ret

0x00430836:	xorl %ebx, %ebx
0x00430838:	pushl %ebx
0x00430839:	pushl 0x4(%esi)
0x0043083c:	leal %eax, -516(%ebp)
0x00430842:	pushl %edi
0x00430843:	pushl %eax
0x00430844:	pushl %edi
0x00430845:	leal %eax, -260(%ebp)
0x0043084b:	pushl %eax
0x0043084c:	pushl %edi
0x0043084d:	pushl 0xc(%esi)
0x00430850:	pushl %ebx
0x00430851:	call 0x00433429
0x00433429:	movl %edi, %edi
0x0043342b:	pushl %ebp
0x0043342c:	movl %ebp, %esp
0x0043342e:	subl %esp, $0x10<UINT8>
0x00433431:	pushl 0x8(%ebp)
0x00433434:	leal %ecx, -16(%ebp)
0x00433437:	call 0x00429f9a
0x0043343c:	pushl 0x28(%ebp)
0x0043343f:	leal %ecx, -16(%ebp)
0x00433442:	pushl 0x24(%ebp)
0x00433445:	pushl 0x20(%ebp)
0x00433448:	pushl 0x1c(%ebp)
0x0043344b:	pushl 0x18(%ebp)
0x0043344e:	pushl 0x14(%ebp)
0x00433451:	pushl 0x10(%ebp)
0x00433454:	pushl 0xc(%ebp)
0x00433457:	call 0x00433084
0x00433084:	movl %edi, %edi
0x00433086:	pushl %ebp
0x00433087:	movl %ebp, %esp
0x00433089:	subl %esp, $0x14<UINT8>
0x0043308c:	movl %eax, 0x5512b4
0x00433091:	xorl %eax, %ebp
0x00433093:	movl -4(%ebp), %eax
0x00433096:	pushl %ebx
0x00433097:	pushl %esi
0x00433098:	xorl %ebx, %ebx
0x0043309a:	pushl %edi
0x0043309b:	movl %esi, %ecx
0x0043309d:	cmpl 0x558014, %ebx
0x004330a3:	jne 0x004330dd
0x004330a5:	pushl %ebx
0x004330a6:	pushl %ebx
0x004330a7:	xorl %edi, %edi
0x004330a9:	incl %edi
0x004330aa:	pushl %edi
0x004330ab:	pushl $0x43ed24<UINT32>
0x004330b0:	pushl $0x100<UINT32>
0x004330b5:	pushl %ebx
0x004330b6:	call LCMapStringW@KERNEL32.DLL
LCMapStringW@KERNEL32.DLL: API Node	
0x004330bc:	testl %eax, %eax
0x004330be:	je 8
0x004330c0:	movl 0x558014, %edi
0x004330c6:	jmp 0x004330dd
0x004330dd:	cmpl 0x14(%ebp), %ebx
0x004330e0:	jle 0x00433104
0x00433104:	movl %eax, 0x558014
0x00433109:	cmpl %eax, $0x2<UINT8>
0x0043310c:	je 428
0x00433112:	cmpl %eax, %ebx
0x00433114:	je 420
0x0043311a:	cmpl %eax, $0x1<UINT8>
0x0043311d:	jne 460
0x00433123:	movl -8(%ebp), %ebx
0x00433126:	cmpl 0x20(%ebp), %ebx
0x00433129:	jne 0x00433133
0x00433133:	movl %esi, 0x43e184
0x00433139:	xorl %eax, %eax
0x0043313b:	cmpl 0x24(%ebp), %ebx
0x0043313e:	pushl %ebx
0x0043313f:	pushl %ebx
0x00433140:	pushl 0x14(%ebp)
0x00433143:	setne %al
0x00433146:	pushl 0x10(%ebp)
0x00433149:	leal %eax, 0x1(,%eax,8)
0x00433150:	pushl %eax
0x00433151:	pushl 0x20(%ebp)
0x00433154:	call MultiByteToWideChar@KERNEL32.DLL
0x00433156:	movl %edi, %eax
0x00433158:	cmpl %edi, %ebx
0x0043315a:	je 0x004332ef
0x004332ef:	xorl %eax, %eax
0x004332f1:	jmp 0x00433417
0x00433417:	leal %esp, -32(%ebp)
0x0043341a:	popl %edi
0x0043341b:	popl %esi
0x0043341c:	popl %ebx
0x0043341d:	movl %ecx, -4(%ebp)
0x00433420:	xorl %ecx, %ebp
0x00433422:	call 0x00429620
0x00433427:	leave
0x00433428:	ret

0x0043345c:	addl %esp, $0x20<UINT8>
0x0043345f:	cmpb -4(%ebp), $0x0<UINT8>
0x00433463:	je 7
0x00433465:	movl %ecx, -8(%ebp)
0x00433468:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0043346c:	leave
0x0043346d:	ret

0x00430856:	addl %esp, $0x44<UINT8>
0x00430859:	pushl %ebx
0x0043085a:	pushl 0x4(%esi)
0x0043085d:	leal %eax, -772(%ebp)
0x00430863:	pushl %edi
0x00430864:	pushl %eax
0x00430865:	pushl %edi
0x00430866:	leal %eax, -260(%ebp)
0x0043086c:	pushl %eax
0x0043086d:	pushl $0x200<UINT32>
0x00430872:	pushl 0xc(%esi)
0x00430875:	pushl %ebx
0x00430876:	call 0x00433429
0x0043087b:	addl %esp, $0x24<UINT8>
0x0043087e:	xorl %eax, %eax
0x00430880:	movzwl %ecx, -1284(%ebp,%eax,2)
0x00430888:	testb %cl, $0x1<UINT8>
0x0043088b:	je 0x0043089b
0x0043089b:	testb %cl, $0x2<UINT8>
0x0043089e:	je 0x004308b5
0x004308b5:	movb 0x11d(%esi,%eax), $0x0<UINT8>
0x004308bd:	incl %eax
0x004308be:	cmpl %eax, %edi
0x004308c0:	jb -66
0x004308c2:	jmp 0x0043091a
0x0043091a:	movl %ecx, -4(%ebp)
0x0043091d:	popl %edi
0x0043091e:	xorl %ecx, %ebp
0x00430920:	popl %ebx
0x00430921:	call 0x00429620
0x00430926:	leave
0x00430927:	ret

0x00430bbe:	jmp 0x00430a7a
0x00430a7a:	xorl %eax, %eax
0x00430a7c:	jmp 0x00430c1e
0x00430c1e:	movl %ecx, -4(%ebp)
0x00430c21:	popl %edi
0x00430c22:	popl %esi
0x00430c23:	xorl %ecx, %ebp
0x00430c25:	popl %ebx
0x00430c26:	call 0x00429620
0x00430c2b:	leave
0x00430c2c:	ret

0x00430c90:	popl %ecx
0x00430c91:	popl %ecx
0x00430c92:	movl -32(%ebp), %eax
0x00430c95:	testl %eax, %eax
0x00430c97:	jne 252
0x00430c9d:	movl %esi, -36(%ebp)
0x00430ca0:	pushl 0x68(%esi)
0x00430ca3:	call InterlockedDecrement@KERNEL32.DLL
InterlockedDecrement@KERNEL32.DLL: API Node	
0x00430ca9:	testl %eax, %eax
0x00430cab:	jne 17
0x00430cad:	movl %eax, 0x68(%esi)
0x00430cb0:	cmpl %eax, $0x551698<UINT32>
0x00430cb5:	je 0x00430cbe
0x00430cbe:	movl 0x68(%esi), %ebx
0x00430cc1:	pushl %ebx
0x00430cc2:	movl %edi, 0x43e0b0
0x00430cc8:	call InterlockedIncrement@KERNEL32.DLL
0x00430cca:	testb 0x70(%esi), $0x2<UINT8>
0x00430cce:	jne 234
0x00430cd4:	testb 0x551bbc, $0x1<UINT8>
0x00430cdb:	jne 221
0x00430ce1:	pushl $0xd<UINT8>
0x00430ce3:	call 0x0042cf99
0x00430ce8:	popl %ecx
0x00430ce9:	andl -4(%ebp), $0x0<UINT8>
0x00430ced:	movl %eax, 0x4(%ebx)
0x00430cf0:	movl 0x557fdc, %eax
0x00430cf5:	movl %eax, 0x8(%ebx)
0x00430cf8:	movl 0x557fe0, %eax
0x00430cfd:	movl %eax, 0xc(%ebx)
0x00430d00:	movl 0x557fe4, %eax
0x00430d05:	xorl %eax, %eax
0x00430d07:	movl -28(%ebp), %eax
0x00430d0a:	cmpl %eax, $0x5<UINT8>
0x00430d0d:	jnl 0x00430d1f
0x00430d0f:	movw %cx, 0x10(%ebx,%eax,2)
0x00430d14:	movw 0x557fd0(,%eax,2), %cx
0x00430d1c:	incl %eax
0x00430d1d:	jmp 0x00430d07
0x00430d1f:	xorl %eax, %eax
0x00430d21:	movl -28(%ebp), %eax
0x00430d24:	cmpl %eax, $0x101<UINT32>
0x00430d29:	jnl 0x00430d38
0x00430d2b:	movb %cl, 0x1c(%eax,%ebx)
0x00430d2f:	movb 0x5518b8(%eax), %cl
0x00430d35:	incl %eax
0x00430d36:	jmp 0x00430d21
0x00430d38:	xorl %eax, %eax
0x00430d3a:	movl -28(%ebp), %eax
0x00430d3d:	cmpl %eax, $0x100<UINT32>
0x00430d42:	jnl 0x00430d54
0x00430d44:	movb %cl, 0x11d(%eax,%ebx)
0x00430d4b:	movb 0x5519c0(%eax), %cl
0x00430d51:	incl %eax
0x00430d52:	jmp 0x00430d3a
0x00430d54:	pushl 0x551ac0
0x00430d5a:	call InterlockedDecrement@KERNEL32.DLL
0x00430d60:	testl %eax, %eax
0x00430d62:	jne 0x00430d77
0x00430d77:	movl 0x551ac0, %ebx
0x00430d7d:	pushl %ebx
0x00430d7e:	call InterlockedIncrement@KERNEL32.DLL
0x00430d80:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00430d87:	call 0x00430d8e
0x00430d8e:	pushl $0xd<UINT8>
0x00430d90:	call 0x0042cebf
0x00430d95:	popl %ecx
0x00430d96:	ret

0x00430d8c:	jmp 0x00430dbe
0x00430dbe:	movl %eax, -32(%ebp)
0x00430dc1:	call 0x0042dad5
0x00430dc6:	ret

0x00430dd7:	popl %ecx
0x00430dd8:	movl 0x558a8c, $0x1<UINT32>
0x00430de2:	xorl %eax, %eax
0x00430de4:	ret

0x00433b79:	pushl $0x104<UINT32>
0x00433b7e:	movl %esi, $0x558018<UINT32>
0x00433b83:	pushl %esi
0x00433b84:	pushl %ebx
0x00433b85:	movb 0x55811c, %bl
0x00433b8b:	call GetModuleFileNameA@KERNEL32.DLL
GetModuleFileNameA@KERNEL32.DLL: API Node	
0x00433b91:	movl %eax, 0x558a7c
0x00433b96:	movl 0x5577b4, %esi
0x00433b9c:	cmpl %eax, %ebx
0x00433b9e:	je 7
0x00433ba0:	movl -4(%ebp), %eax
0x00433ba3:	cmpb (%eax), %bl
0x00433ba5:	jne 0x00433baa
0x00433baa:	movl %edx, -4(%ebp)
0x00433bad:	leal %eax, -8(%ebp)
0x00433bb0:	pushl %eax
0x00433bb1:	pushl %ebx
0x00433bb2:	pushl %ebx
0x00433bb3:	leal %edi, -12(%ebp)
0x00433bb6:	call 0x004339c5
0x004339c5:	movl %edi, %edi
0x004339c7:	pushl %ebp
0x004339c8:	movl %ebp, %esp
0x004339ca:	pushl %ecx
0x004339cb:	movl %ecx, 0x10(%ebp)
0x004339ce:	pushl %ebx
0x004339cf:	xorl %eax, %eax
0x004339d1:	pushl %esi
0x004339d2:	movl (%edi), %eax
0x004339d4:	movl %esi, %edx
0x004339d6:	movl %edx, 0xc(%ebp)
0x004339d9:	movl (%ecx), $0x1<UINT32>
0x004339df:	cmpl 0x8(%ebp), %eax
0x004339e2:	je 0x004339ed
0x004339ed:	movl -4(%ebp), %eax
0x004339f0:	cmpb (%esi), $0x22<UINT8>
0x004339f3:	jne 0x00433a05
0x004339f5:	xorl %eax, %eax
0x004339f7:	cmpl -4(%ebp), %eax
0x004339fa:	movb %bl, $0x22<UINT8>
0x004339fc:	sete %al
0x004339ff:	incl %esi
0x00433a00:	movl -4(%ebp), %eax
0x00433a03:	jmp 0x00433a41
0x00433a41:	cmpl -4(%ebp), $0x0<UINT8>
0x00433a45:	jne 0x004339f0
0x00433a05:	incl (%edi)
0x00433a07:	testl %edx, %edx
0x00433a09:	je 0x00433a13
0x00433a13:	movb %bl, (%esi)
0x00433a15:	movzbl %eax, %bl
0x00433a18:	pushl %eax
0x00433a19:	incl %esi
0x00433a1a:	call 0x0043695f
0x0043695f:	movl %edi, %edi
0x00436961:	pushl %ebp
0x00436962:	movl %ebp, %esp
0x00436964:	pushl $0x4<UINT8>
0x00436966:	pushl $0x0<UINT8>
0x00436968:	pushl 0x8(%ebp)
0x0043696b:	pushl $0x0<UINT8>
0x0043696d:	call 0x0043690c
0x0043690c:	movl %edi, %edi
0x0043690e:	pushl %ebp
0x0043690f:	movl %ebp, %esp
0x00436911:	subl %esp, $0x10<UINT8>
0x00436914:	pushl 0x8(%ebp)
0x00436917:	leal %ecx, -16(%ebp)
0x0043691a:	call 0x00429f9a
0x0043691f:	movzbl %eax, 0xc(%ebp)
0x00436923:	movl %ecx, -12(%ebp)
0x00436926:	movb %dl, 0x14(%ebp)
0x00436929:	testb 0x1d(%ecx,%eax), %dl
0x0043692d:	jne 30
0x0043692f:	cmpl 0x10(%ebp), $0x0<UINT8>
0x00436933:	je 0x00436947
0x00436947:	xorl %eax, %eax
0x00436949:	testl %eax, %eax
0x0043694b:	je 0x00436950
0x00436950:	cmpb -4(%ebp), $0x0<UINT8>
0x00436954:	je 7
0x00436956:	movl %ecx, -8(%ebp)
0x00436959:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0043695d:	leave
0x0043695e:	ret

0x00436972:	addl %esp, $0x10<UINT8>
0x00436975:	popl %ebp
0x00436976:	ret

0x00433a1f:	popl %ecx
0x00433a20:	testl %eax, %eax
0x00433a22:	je 0x00433a37
0x00433a37:	movl %edx, 0xc(%ebp)
0x00433a3a:	movl %ecx, 0x10(%ebp)
0x00433a3d:	testb %bl, %bl
0x00433a3f:	je 0x00433a73
0x00433a47:	cmpb %bl, $0x20<UINT8>
0x00433a4a:	je 5
0x00433a4c:	cmpb %bl, $0x9<UINT8>
0x00433a4f:	jne 0x004339f0
0x00433a73:	decl %esi
0x00433a74:	jmp 0x00433a59
0x00433a59:	andl -4(%ebp), $0x0<UINT8>
0x00433a5d:	cmpb (%esi), $0x0<UINT8>
0x00433a60:	je 0x00433b4f
0x00433b4f:	movl %eax, 0x8(%ebp)
0x00433b52:	popl %esi
0x00433b53:	popl %ebx
0x00433b54:	testl %eax, %eax
0x00433b56:	je 0x00433b5b
0x00433b5b:	incl (%ecx)
0x00433b5d:	leave
0x00433b5e:	ret

0x00433bbb:	movl %eax, -8(%ebp)
0x00433bbe:	addl %esp, $0xc<UINT8>
0x00433bc1:	cmpl %eax, $0x3fffffff<UINT32>
0x00433bc6:	jae 74
0x00433bc8:	movl %ecx, -12(%ebp)
0x00433bcb:	cmpl %ecx, $0xffffffff<UINT8>
0x00433bce:	jae 66
0x00433bd0:	movl %edi, %eax
0x00433bd2:	shll %edi, $0x2<UINT8>
0x00433bd5:	leal %eax, (%edi,%ecx)
0x00433bd8:	cmpl %eax, %ecx
0x00433bda:	jb 54
0x00433bdc:	pushl %eax
0x00433bdd:	call 0x0042e11b
0x00433be2:	movl %esi, %eax
0x00433be4:	popl %ecx
0x00433be5:	cmpl %esi, %ebx
0x00433be7:	je 41
0x00433be9:	movl %edx, -4(%ebp)
0x00433bec:	leal %eax, -8(%ebp)
0x00433bef:	pushl %eax
0x00433bf0:	addl %edi, %esi
0x00433bf2:	pushl %edi
0x00433bf3:	pushl %esi
0x00433bf4:	leal %edi, -12(%ebp)
0x00433bf7:	call 0x004339c5
0x004339e4:	movl %ebx, 0x8(%ebp)
0x004339e7:	addl 0x8(%ebp), $0x4<UINT8>
0x004339eb:	movl (%ebx), %edx
0x00433a0b:	movb %al, (%esi)
0x00433a0d:	movb (%edx), %al
0x00433a0f:	incl %edx
0x00433a10:	movl 0xc(%ebp), %edx
0x00433b58:	andl (%eax), $0x0<UINT8>
0x00433bfc:	movl %eax, -8(%ebp)
0x00433bff:	addl %esp, $0xc<UINT8>
0x00433c02:	decl %eax
0x00433c03:	movl 0x557798, %eax
0x00433c08:	movl 0x55779c, %esi
0x00433c0e:	xorl %eax, %eax
0x00433c10:	jmp 0x00433c15
0x00433c15:	popl %edi
0x00433c16:	popl %esi
0x00433c17:	popl %ebx
0x00433c18:	leave
0x00433c19:	ret

0x0042be7a:	testl %eax, %eax
0x0042be7c:	jnl 0x0042be86
0x0042be86:	call 0x004338e7
0x004338e7:	cmpl 0x558a8c, $0x0<UINT8>
0x004338ee:	jne 0x004338f5
0x004338f5:	pushl %esi
0x004338f6:	movl %esi, 0x5577dc
0x004338fc:	pushl %edi
0x004338fd:	xorl %edi, %edi
0x004338ff:	testl %esi, %esi
0x00433901:	jne 0x0043391b
0x0043391b:	movb %al, (%esi)
0x0043391d:	testb %al, %al
0x0043391f:	jne 0x0043390b
0x0043390b:	cmpb %al, $0x3d<UINT8>
0x0043390d:	je 0x00433910
0x00433910:	pushl %esi
0x00433911:	call 0x00431620
0x00431620:	movl %ecx, 0x4(%esp)
0x00431624:	testl %ecx, $0x3<UINT32>
0x0043162a:	je 0x00431650
0x00431650:	movl %eax, (%ecx)
0x00431652:	movl %edx, $0x7efefeff<UINT32>
0x00431657:	addl %edx, %eax
0x00431659:	xorl %eax, $0xffffffff<UINT8>
0x0043165c:	xorl %eax, %edx
0x0043165e:	addl %ecx, $0x4<UINT8>
0x00431661:	testl %eax, $0x81010100<UINT32>
0x00431666:	je 0x00431650
0x00431668:	movl %eax, -4(%ecx)
0x0043166b:	testb %al, %al
0x0043166d:	je 50
0x0043166f:	testb %ah, %ah
0x00431671:	je 36
0x00431673:	testl %eax, $0xff0000<UINT32>
0x00431678:	je 19
0x0043167a:	testl %eax, $0xff000000<UINT32>
0x0043167f:	je 0x00431683
0x00431683:	leal %eax, -1(%ecx)
0x00431686:	movl %ecx, 0x4(%esp)
0x0043168a:	subl %eax, %ecx
0x0043168c:	ret

0x00433916:	popl %ecx
0x00433917:	leal %esi, 0x1(%esi,%eax)
0x00433921:	pushl $0x4<UINT8>
0x00433923:	incl %edi
0x00433924:	pushl %edi
0x00433925:	call 0x0042e160
0x0043392a:	movl %edi, %eax
0x0043392c:	popl %ecx
0x0043392d:	popl %ecx
0x0043392e:	movl 0x5577a4, %edi
0x00433934:	testl %edi, %edi
0x00433936:	je -53
0x00433938:	movl %esi, 0x5577dc
0x0043393e:	pushl %ebx
0x0043393f:	jmp 0x00433983
0x00433983:	cmpb (%esi), $0x0<UINT8>
0x00433986:	jne 0x00433941
0x00433941:	pushl %esi
0x00433942:	call 0x00431620
0x00433947:	movl %ebx, %eax
0x00433949:	incl %ebx
0x0043394a:	cmpb (%esi), $0x3d<UINT8>
0x0043394d:	popl %ecx
0x0043394e:	je 0x00433981
0x00433981:	addl %esi, %ebx
0x00433988:	pushl 0x5577dc
0x0043398e:	call 0x0042a181
0x0042a181:	pushl $0xc<UINT8>
0x0042a183:	pushl $0x54bbf8<UINT32>
0x0042a188:	call 0x0042da90
0x0042a18d:	movl %esi, 0x8(%ebp)
0x0042a190:	testl %esi, %esi
0x0042a192:	je 117
0x0042a194:	cmpl 0x558a60, $0x3<UINT8>
0x0042a19b:	jne 0x0042a1e0
0x0042a1e0:	pushl %esi
0x0042a1e1:	pushl $0x0<UINT8>
0x0042a1e3:	pushl 0x557c64
0x0042a1e9:	call HeapFree@KERNEL32.DLL
HeapFree@KERNEL32.DLL: API Node	
0x0042a1ef:	testl %eax, %eax
0x0042a1f1:	jne 0x0042a209
0x0042a209:	call 0x0042dad5
0x0042a20e:	ret

0x00433993:	andl 0x5577dc, $0x0<UINT8>
0x0043399a:	andl (%edi), $0x0<UINT8>
0x0043399d:	movl 0x558a80, $0x1<UINT32>
0x004339a7:	xorl %eax, %eax
0x004339a9:	popl %ecx
0x004339aa:	popl %ebx
0x004339ab:	popl %edi
0x004339ac:	popl %esi
0x004339ad:	ret

0x0042be8b:	testl %eax, %eax
0x0042be8d:	jnl 0x0042be97
0x0042be97:	pushl %ebx
0x0042be98:	call 0x00429d51
0x00429d51:	movl %edi, %edi
0x00429d53:	pushl %ebp
0x00429d54:	movl %ebp, %esp
0x00429d56:	cmpl 0x43fee0, $0x0<UINT8>
0x00429d5d:	je 25
0x00429d5f:	pushl $0x43fee0<UINT32>
0x00429d64:	call 0x004301b0
0x004301b0:	movl %edi, %edi
0x004301b2:	pushl %ebp
0x004301b3:	movl %ebp, %esp
0x004301b5:	pushl $0xfffffffe<UINT8>
0x004301b7:	pushl $0x54be30<UINT32>
0x004301bc:	pushl $0x42daf0<UINT32>
0x004301c1:	movl %eax, %fs:0
0x004301c7:	pushl %eax
0x004301c8:	subl %esp, $0x8<UINT8>
0x004301cb:	pushl %ebx
0x004301cc:	pushl %esi
0x004301cd:	pushl %edi
0x004301ce:	movl %eax, 0x5512b4
0x004301d3:	xorl -8(%ebp), %eax
0x004301d6:	xorl %eax, %ebp
0x004301d8:	pushl %eax
0x004301d9:	leal %eax, -16(%ebp)
0x004301dc:	movl %fs:0, %eax
0x004301e2:	movl -24(%ebp), %esp
0x004301e5:	movl -4(%ebp), $0x0<UINT32>
0x004301ec:	pushl $0x400000<UINT32>
0x004301f1:	call 0x00430120
0x00430120:	movl %edi, %edi
0x00430122:	pushl %ebp
0x00430123:	movl %ebp, %esp
0x00430125:	movl %ecx, 0x8(%ebp)
0x00430128:	movl %eax, $0x5a4d<UINT32>
0x0043012d:	cmpw (%ecx), %ax
0x00430130:	je 0x00430136
0x00430136:	movl %eax, 0x3c(%ecx)
0x00430139:	addl %eax, %ecx
0x0043013b:	cmpl (%eax), $0x4550<UINT32>
0x00430141:	jne -17
0x00430143:	xorl %edx, %edx
0x00430145:	movl %ecx, $0x10b<UINT32>
0x0043014a:	cmpw 0x18(%eax), %cx
0x0043014e:	sete %dl
0x00430151:	movl %eax, %edx
0x00430153:	popl %ebp
0x00430154:	ret

0x004301f6:	addl %esp, $0x4<UINT8>
0x004301f9:	testl %eax, %eax
0x004301fb:	je 85
0x004301fd:	movl %eax, 0x8(%ebp)
0x00430200:	subl %eax, $0x400000<UINT32>
0x00430205:	pushl %eax
0x00430206:	pushl $0x400000<UINT32>
0x0043020b:	call 0x00430160
0x00430160:	movl %edi, %edi
0x00430162:	pushl %ebp
0x00430163:	movl %ebp, %esp
0x00430165:	movl %eax, 0x8(%ebp)
0x00430168:	movl %ecx, 0x3c(%eax)
0x0043016b:	addl %ecx, %eax
0x0043016d:	movzwl %eax, 0x14(%ecx)
0x00430171:	pushl %ebx
0x00430172:	pushl %esi
0x00430173:	movzwl %esi, 0x6(%ecx)
0x00430177:	xorl %edx, %edx
0x00430179:	pushl %edi
0x0043017a:	leal %eax, 0x18(%eax,%ecx)
0x0043017e:	testl %esi, %esi
0x00430180:	jbe 27
0x00430182:	movl %edi, 0xc(%ebp)
0x00430185:	movl %ecx, 0xc(%eax)
0x00430188:	cmpl %edi, %ecx
0x0043018a:	jb 9
0x0043018c:	movl %ebx, 0x8(%eax)
0x0043018f:	addl %ebx, %ecx
0x00430191:	cmpl %edi, %ebx
0x00430193:	jb 0x0043019f
0x0043019f:	popl %edi
0x004301a0:	popl %esi
0x004301a1:	popl %ebx
0x004301a2:	popl %ebp
0x004301a3:	ret

0x00430210:	addl %esp, $0x8<UINT8>
0x00430213:	testl %eax, %eax
0x00430215:	je 59
0x00430217:	movl %eax, 0x24(%eax)
0x0043021a:	shrl %eax, $0x1f<UINT8>
0x0043021d:	notl %eax
0x0043021f:	andl %eax, $0x1<UINT8>
0x00430222:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00430229:	movl %ecx, -16(%ebp)
0x0043022c:	movl %fs:0, %ecx
0x00430233:	popl %ecx
0x00430234:	popl %edi
0x00430235:	popl %esi
0x00430236:	popl %ebx
0x00430237:	movl %esp, %ebp
0x00430239:	popl %ebp
0x0043023a:	ret

0x00429d69:	popl %ecx
0x00429d6a:	testl %eax, %eax
0x00429d6c:	je 10
0x00429d6e:	pushl 0x8(%ebp)
0x00429d71:	call 0x00437945
0x00437945:	movl %edi, %edi
0x00437947:	pushl %ebp
0x00437948:	movl %ebp, %esp
0x0043794a:	call 0x004378e5
0x004378e5:	movl %eax, $0x439134<UINT32>
0x004378ea:	movl 0x551660, %eax
0x004378ef:	movl 0x551664, $0x43881b<UINT32>
0x004378f9:	movl 0x551668, $0x4387cf<UINT32>
0x00437903:	movl 0x55166c, $0x438808<UINT32>
0x0043790d:	movl 0x551670, $0x438771<UINT32>
0x00437917:	movl 0x551674, %eax
0x0043791c:	movl 0x551678, $0x4390ac<UINT32>
0x00437926:	movl 0x55167c, $0x43878d<UINT32>
0x00437930:	movl 0x551680, $0x4386ef<UINT32>
0x0043793a:	movl 0x551684, $0x43867c<UINT32>
0x00437944:	ret

0x0043794f:	call 0x004391c0
0x004391c0:	pushl $0x43ff44<UINT32>
0x004391c5:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x004391cb:	testl %eax, %eax
0x004391cd:	je 21
0x004391cf:	pushl $0x43ff28<UINT32>
0x004391d4:	pushl %eax
0x004391d5:	call GetProcAddress@KERNEL32.DLL
0x004391db:	testl %eax, %eax
0x004391dd:	je 5
0x004391df:	pushl $0x0<UINT8>
0x004391e1:	call IsProcessorFeaturePresent@KERNEL32
IsProcessorFeaturePresent@KERNEL32: API Node	
0x004391e3:	ret

0x00437954:	cmpl 0x8(%ebp), $0x0<UINT8>
0x00437958:	movl 0x558248, %eax
0x0043795d:	je 5
0x0043795f:	call 0x00439157
0x00439157:	movl %edi, %edi
0x00439159:	pushl %esi
0x0043915a:	pushl $0x30000<UINT32>
0x0043915f:	pushl $0x10000<UINT32>
0x00439164:	xorl %esi, %esi
0x00439166:	pushl %esi
0x00439167:	call 0x0043968f
0x0043968f:	movl %edi, %edi
0x00439691:	pushl %ebp
0x00439692:	movl %ebp, %esp
0x00439694:	movl %eax, 0x10(%ebp)
0x00439697:	movl %ecx, 0xc(%ebp)
0x0043969a:	andl %eax, $0xfff7ffff<UINT32>
0x0043969f:	andl %ecx, %eax
0x004396a1:	pushl %esi
0x004396a2:	testl %ecx, $0xfcf0fce0<UINT32>
0x004396a8:	je 0x004396db
0x004396db:	movl %esi, 0x8(%ebp)
0x004396de:	pushl %eax
0x004396df:	pushl 0xc(%ebp)
0x004396e2:	testl %esi, %esi
0x004396e4:	je 0x004396ef
0x004396ef:	call 0x0043b2d0
0x0043b2d0:	movl %edi, %edi
0x0043b2d2:	pushl %ebp
0x0043b2d3:	movl %ebp, %esp
0x0043b2d5:	subl %esp, $0x14<UINT8>
0x0043b2d8:	pushl %ebx
0x0043b2d9:	pushl %esi
0x0043b2da:	pushl %edi
0x0043b2db:	fwait
0x0043b2dc:	fnstcw -8(%ebp)
0x0043b2df:	movl %ebx, -8(%ebp)
0x0043b2e2:	xorl %edx, %edx
0x0043b2e4:	testb %bl, $0x1<UINT8>
0x0043b2e7:	je 0x0043b2ec
0x0043b2ec:	testb %bl, $0x4<UINT8>
0x0043b2ef:	je 3
0x0043b2f1:	orl %edx, $0x8<UINT8>
0x0043b2f4:	testb %bl, $0x8<UINT8>
0x0043b2f7:	je 3
0x0043b2f9:	orl %edx, $0x4<UINT8>
0x0043b2fc:	testb %bl, $0x10<UINT8>
0x0043b2ff:	je 0x0043b304
0x0043b304:	testb %bl, $0x20<UINT8>
0x0043b307:	je 3
0x0043b309:	orl %edx, $0x1<UINT8>
0x0043b30c:	testb %bl, $0x2<UINT8>
0x0043b30f:	je 0x0043b317
0x0043b317:	movzwl %ecx, %bx
0x0043b31a:	movl %eax, %ecx
0x0043b31c:	movl %esi, $0xc00<UINT32>
0x0043b321:	andl %eax, %esi
0x0043b323:	movl %edi, $0x300<UINT32>
0x0043b328:	je 36
0x0043b32a:	cmpl %eax, $0x400<UINT32>
0x0043b32f:	je 23
0x0043b331:	cmpl %eax, $0x800<UINT32>
0x0043b336:	je 8
0x0043b338:	cmpl %eax, %esi
0x0043b33a:	jne 18
0x0043b33c:	orl %edx, %edi
0x0043b33e:	jmp 0x0043b34e
0x0043b34e:	andl %ecx, %edi
0x0043b350:	je 16
0x0043b352:	cmpl %ecx, $0x200<UINT32>
0x0043b358:	jne 14
0x0043b35a:	orl %edx, $0x10000<UINT32>
0x0043b360:	jmp 0x0043b368
0x0043b368:	testl %ebx, $0x1000<UINT32>
0x0043b36e:	je 6
0x0043b370:	orl %edx, $0x40000<UINT32>
0x0043b376:	movl %edi, 0xc(%ebp)
0x0043b379:	movl %ecx, 0x8(%ebp)
0x0043b37c:	movl %eax, %edi
0x0043b37e:	notl %eax
0x0043b380:	andl %eax, %edx
0x0043b382:	andl %ecx, %edi
0x0043b384:	orl %eax, %ecx
0x0043b386:	movl 0xc(%ebp), %eax
0x0043b389:	cmpl %eax, %edx
0x0043b38b:	je 0x0043b43f
0x0043b43f:	xorl %esi, %esi
0x0043b441:	cmpl 0x558940, %esi
0x0043b447:	je 0x0043b5da
0x0043b5da:	popl %edi
0x0043b5db:	popl %esi
0x0043b5dc:	popl %ebx
0x0043b5dd:	leave
0x0043b5de:	ret

0x004396f4:	popl %ecx
0x004396f5:	popl %ecx
0x004396f6:	xorl %eax, %eax
0x004396f8:	popl %esi
0x004396f9:	popl %ebp
0x004396fa:	ret

0x0043916c:	addl %esp, $0xc<UINT8>
0x0043916f:	testl %eax, %eax
0x00439171:	je 0x00439180
0x00439180:	popl %esi
0x00439181:	ret

0x00437964:	fnclex
0x00437966:	popl %ebp
0x00437967:	ret

0x00429d77:	popl %ecx
0x00429d78:	call 0x004300fe
0x004300fe:	movl %edi, %edi
0x00430100:	pushl %esi
0x00430101:	pushl %edi
0x00430102:	xorl %edi, %edi
0x00430104:	leal %esi, 0x551660(%edi)
0x0043010a:	pushl (%esi)
0x0043010c:	call 0x0042fa6a
0x0042fa8c:	pushl %eax
0x0042fa8d:	pushl 0x55165c
0x0042fa93:	call TlsGetValue@KERNEL32.DLL
0x0042fa95:	call FlsGetValue@KERNEL32.DLL
0x0042fa97:	testl %eax, %eax
0x0042fa99:	je 8
0x0042fa9b:	movl %eax, 0x1f8(%eax)
0x0042faa1:	jmp 0x0042faca
0x00430111:	addl %edi, $0x4<UINT8>
0x00430114:	popl %ecx
0x00430115:	movl (%esi), %eax
0x00430117:	cmpl %edi, $0x28<UINT8>
0x0043011a:	jb 0x00430104
0x0043011c:	popl %edi
0x0043011d:	popl %esi
0x0043011e:	ret

0x00429d7d:	pushl $0x43e40c<UINT32>
0x00429d82:	pushl $0x43e3f4<UINT32>
0x00429d87:	call 0x00429d2d
0x00429d2d:	movl %edi, %edi
0x00429d2f:	pushl %ebp
0x00429d30:	movl %ebp, %esp
0x00429d32:	pushl %esi
0x00429d33:	movl %esi, 0x8(%ebp)
0x00429d36:	xorl %eax, %eax
0x00429d38:	jmp 0x00429d49
0x00429d49:	cmpl %esi, 0xc(%ebp)
0x00429d4c:	jb 0x00429d3a
0x00429d3a:	testl %eax, %eax
0x00429d3c:	jne 16
0x00429d3e:	movl %ecx, (%esi)
0x00429d40:	testl %ecx, %ecx
0x00429d42:	je 0x00429d46
0x00429d46:	addl %esi, $0x4<UINT8>
0x00429d44:	call 0x0043387a
0x00429804:	movl %eax, 0x559aa0
0x00429809:	pushl %esi
0x0042980a:	pushl $0x14<UINT8>
0x0042980c:	popl %esi
0x0042980d:	testl %eax, %eax
0x0042980f:	jne 7
0x00429811:	movl %eax, $0x200<UINT32>
0x00429816:	jmp 0x0042981e
0x0042981e:	movl 0x559aa0, %eax
0x00429823:	pushl $0x4<UINT8>
0x00429825:	pushl %eax
0x00429826:	call 0x0042e160
0x0042982b:	popl %ecx
0x0042982c:	popl %ecx
0x0042982d:	movl 0x558a94, %eax
0x00429832:	testl %eax, %eax
0x00429834:	jne 0x00429854
0x00429854:	xorl %edx, %edx
0x00429856:	movl %ecx, $0x551000<UINT32>
0x0042985b:	jmp 0x00429862
0x00429862:	movl (%edx,%eax), %ecx
0x00429865:	addl %ecx, $0x20<UINT8>
0x00429868:	addl %edx, $0x4<UINT8>
0x0042986b:	cmpl %ecx, $0x551280<UINT32>
0x00429871:	jl 0x0042985d
0x0042985d:	movl %eax, 0x558a94
0x00429873:	pushl $0xfffffffe<UINT8>
0x00429875:	popl %esi
0x00429876:	xorl %edx, %edx
0x00429878:	movl %ecx, $0x551010<UINT32>
0x0042987d:	pushl %edi
0x0042987e:	movl %eax, %edx
0x00429880:	sarl %eax, $0x5<UINT8>
0x00429883:	movl %eax, 0x558960(,%eax,4)
0x0042988a:	movl %edi, %edx
0x0042988c:	andl %edi, $0x1f<UINT8>
0x0042988f:	shll %edi, $0x6<UINT8>
0x00429892:	movl %eax, (%edi,%eax)
0x00429895:	cmpl %eax, $0xffffffff<UINT8>
0x00429898:	je 8
0x0042989a:	cmpl %eax, %esi
0x0042989c:	je 4
0x0042989e:	testl %eax, %eax
0x004298a0:	jne 0x004298a4
0x004298a4:	addl %ecx, $0x20<UINT8>
0x004298a7:	incl %edx
0x004298a8:	cmpl %ecx, $0x551070<UINT32>
0x004298ae:	jl 0x0042987e
0x004298b0:	popl %edi
0x004298b1:	xorl %eax, %eax
0x004298b3:	popl %esi
0x004298b4:	ret

0x0042b08b:	movl %edi, %edi
0x0042b08d:	pushl %esi
0x0042b08e:	pushl $0x4<UINT8>
0x0042b090:	pushl $0x20<UINT8>
0x0042b092:	call 0x0042e160
0x0042b097:	movl %esi, %eax
0x0042b099:	pushl %esi
0x0042b09a:	call 0x0042fa6a
0x0042b09f:	addl %esp, $0xc<UINT8>
0x0042b0a2:	movl 0x558a88, %eax
0x0042b0a7:	movl 0x558a84, %eax
0x0042b0ac:	testl %esi, %esi
0x0042b0ae:	jne 0x0042b0b5
0x0042b0b5:	andl (%esi), $0x0<UINT8>
0x0042b0b8:	xorl %eax, %eax
0x0042b0ba:	popl %esi
0x0042b0bb:	ret

0x0043550c:	call 0x004354aa
0x004354aa:	movl %edi, %edi
0x004354ac:	pushl %ebp
0x004354ad:	movl %ebp, %esp
0x004354af:	subl %esp, $0x18<UINT8>
0x004354b2:	xorl %eax, %eax
0x004354b4:	pushl %ebx
0x004354b5:	movl -4(%ebp), %eax
0x004354b8:	movl -12(%ebp), %eax
0x004354bb:	movl -8(%ebp), %eax
0x004354be:	pushl %ebx
0x004354bf:	pushfl
0x004354c0:	popl %eax
0x004354c1:	movl %ecx, %eax
0x004354c3:	xorl %eax, $0x200000<UINT32>
0x004354c8:	pushl %eax
0x004354c9:	popfl
0x004354ca:	pushfl
0x004354cb:	popl %edx
0x004354cc:	subl %edx, %ecx
0x004354ce:	je 0x004354ef
0x004354ef:	popl %ebx
0x004354f0:	testl -4(%ebp), $0x4000000<UINT32>
0x004354f7:	je 0x00435507
0x00435507:	xorl %eax, %eax
0x00435509:	popl %ebx
0x0043550a:	leave
0x0043550b:	ret

0x00435511:	movl 0x558940, %eax
0x00435516:	xorl %eax, %eax
0x00435518:	ret

0x0043387a:	pushl $0x433838<UINT32>
0x0043387f:	call SetUnhandledExceptionFilter@KERNEL32.DLL
SetUnhandledExceptionFilter@KERNEL32.DLL: API Node	
0x00433885:	xorl %eax, %eax
0x00433887:	ret

0x00429d4e:	popl %esi
0x00429d4f:	popl %ebp
0x00429d50:	ret

0x00429d8c:	popl %ecx
0x00429d8d:	popl %ecx
0x00429d8e:	testl %eax, %eax
0x00429d90:	jne 66
0x00429d92:	pushl $0x4300d8<UINT32>
0x00429d97:	call 0x0042b0f8
0x0042b0f8:	movl %edi, %edi
0x0042b0fa:	pushl %ebp
0x0042b0fb:	movl %ebp, %esp
0x0042b0fd:	pushl 0x8(%ebp)
0x0042b100:	call 0x0042b0bc
0x0042b0bc:	pushl $0xc<UINT8>
0x0042b0be:	pushl $0x54bc38<UINT32>
0x0042b0c3:	call 0x0042da90
0x0042b0c8:	call 0x00429cfe
0x00429cfe:	pushl $0x8<UINT8>
0x00429d00:	call 0x0042cf99
0x00429d05:	popl %ecx
0x00429d06:	ret

0x0042b0cd:	andl -4(%ebp), $0x0<UINT8>
0x0042b0d1:	pushl 0x8(%ebp)
0x0042b0d4:	call 0x0042afd1
0x0042afd1:	movl %edi, %edi
0x0042afd3:	pushl %ebp
0x0042afd4:	movl %ebp, %esp
0x0042afd6:	pushl %ecx
0x0042afd7:	pushl %ebx
0x0042afd8:	pushl %esi
0x0042afd9:	pushl %edi
0x0042afda:	pushl 0x558a88
0x0042afe0:	call 0x0042fae5
0x0042fb16:	movl %eax, 0x1fc(%eax)
0x0042fb1c:	jmp 0x0042fb45
0x0042afe5:	pushl 0x558a84
0x0042afeb:	movl %edi, %eax
0x0042afed:	movl -4(%ebp), %edi
0x0042aff0:	call 0x0042fae5
0x0042aff5:	movl %esi, %eax
0x0042aff7:	popl %ecx
0x0042aff8:	popl %ecx
0x0042aff9:	cmpl %esi, %edi
0x0042affb:	jb 131
0x0042b001:	movl %ebx, %esi
0x0042b003:	subl %ebx, %edi
0x0042b005:	leal %eax, 0x4(%ebx)
0x0042b008:	cmpl %eax, $0x4<UINT8>
0x0042b00b:	jb 119
0x0042b00d:	pushl %edi
0x0042b00e:	call 0x00432e96
0x00432e96:	pushl $0x10<UINT8>
0x00432e98:	pushl $0x54bf70<UINT32>
0x00432e9d:	call 0x0042da90
0x00432ea2:	xorl %eax, %eax
0x00432ea4:	movl %ebx, 0x8(%ebp)
0x00432ea7:	xorl %edi, %edi
0x00432ea9:	cmpl %ebx, %edi
0x00432eab:	setne %al
0x00432eae:	cmpl %eax, %edi
0x00432eb0:	jne 0x00432ecf
0x00432ecf:	cmpl 0x558a60, $0x3<UINT8>
0x00432ed6:	jne 0x00432f10
0x00432f10:	pushl %ebx
0x00432f11:	pushl %edi
0x00432f12:	pushl 0x557c64
0x00432f18:	call HeapSize@KERNEL32.DLL
HeapSize@KERNEL32.DLL: API Node	
0x00432f1e:	movl %esi, %eax
0x00432f20:	movl %eax, %esi
0x00432f22:	call 0x0042dad5
0x00432f27:	ret

0x0042b013:	movl %edi, %eax
0x0042b015:	leal %eax, 0x4(%ebx)
0x0042b018:	popl %ecx
0x0042b019:	cmpl %edi, %eax
0x0042b01b:	jae 0x0042b065
0x0042b065:	pushl 0x8(%ebp)
0x0042b068:	call 0x0042fa6a
0x0042b06d:	movl (%esi), %eax
0x0042b06f:	addl %esi, $0x4<UINT8>
0x0042b072:	pushl %esi
0x0042b073:	call 0x0042fa6a
0x0042b078:	popl %ecx
0x0042b079:	movl 0x558a84, %eax
0x0042b07e:	movl %eax, 0x8(%ebp)
0x0042b081:	popl %ecx
0x0042b082:	jmp 0x0042b086
0x0042b086:	popl %edi
0x0042b087:	popl %esi
0x0042b088:	popl %ebx
0x0042b089:	leave
0x0042b08a:	ret

0x0042b0d9:	popl %ecx
0x0042b0da:	movl -28(%ebp), %eax
0x0042b0dd:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0042b0e4:	call 0x0042b0f2
0x0042b0f2:	call 0x00429d07
0x00429d07:	pushl $0x8<UINT8>
0x00429d09:	call 0x0042cebf
0x00429d0e:	popl %ecx
0x00429d0f:	ret

0x0042b0f7:	ret

0x0042b0e9:	movl %eax, -28(%ebp)
0x0042b0ec:	call 0x0042dad5
0x0042b0f1:	ret

0x0042b105:	negl %eax
0x0042b107:	sbbl %eax, %eax
0x0042b109:	negl %eax
0x0042b10b:	popl %ecx
0x0042b10c:	decl %eax
0x0042b10d:	popl %ebp
0x0042b10e:	ret

0x00429d9c:	movl %eax, $0x43e3d4<UINT32>
0x00429da1:	movl (%esp), $0x43e3f0<UINT32>
0x00429da8:	call 0x00429d10
0x00429d10:	movl %edi, %edi
0x00429d12:	pushl %ebp
0x00429d13:	movl %ebp, %esp
0x00429d15:	pushl %esi
0x00429d16:	movl %esi, %eax
0x00429d18:	jmp 0x00429d25
0x00429d25:	cmpl %esi, 0x8(%ebp)
0x00429d28:	jb 0x00429d1a
0x00429d1a:	movl %eax, (%esi)
0x00429d1c:	testl %eax, %eax
0x00429d1e:	je 0x00429d22
0x00429d22:	addl %esi, $0x4<UINT8>
0x00429d20:	call 0x0043da90
0x0043dab0:	pushl $0x43db00<UINT32>
0x0043dab5:	call 0x0042b0f8
0x0043daba:	popl %ecx
0x0043dabb:	ret

0x0043d9b0:	pushl %ebp
0x0043d9b1:	movl %ebp, %esp
0x0043d9b3:	pushl $0x547bc8<UINT32>
0x0043d9b8:	pushl $0x547bdc<UINT32>
0x0043d9bd:	call LoadLibraryW@KERNEL32.DLL
LoadLibraryW@KERNEL32.DLL: API Node	
0x0043d9c3:	pushl %eax
0x0043d9c4:	call GetProcAddress@KERNEL32.DLL
0x0043d9ca:	movl 0x5588b4, %eax
0x0043d9cf:	popl %ebp
0x0043d9d0:	ret

0x0043d9e0:	pushl %ebp
0x0043d9e1:	movl %ebp, %esp
0x0043d9e3:	pushl $0x547bf8<UINT32>
0x0043d9e8:	pushl $0x547c08<UINT32>
0x0043d9ed:	call LoadLibraryW@KERNEL32.DLL
0x0043d9f3:	pushl %eax
0x0043d9f4:	call GetProcAddress@KERNEL32.DLL
0x0043d9fa:	movl 0x5588b0, %eax
0x0043d9ff:	popl %ebp
0x0043da00:	ret

0x0043da10:	pushl %ebp
0x0043da11:	movl %ebp, %esp
0x0043da13:	pushl $0x547c24<UINT32>
0x0043da18:	pushl $0x547c34<UINT32>
0x0043da1d:	call LoadLibraryW@KERNEL32.DLL
0x0043da23:	pushl %eax
0x0043da24:	call GetProcAddress@KERNEL32.DLL
0x0043da2a:	movl 0x5588b8, %eax
0x0043da2f:	popl %ebp
0x0043da30:	ret

0x0043da40:	pushl %ebp
0x0043da41:	movl %ebp, %esp
0x0043da43:	pushl %ecx
0x0043da44:	movzbl %eax, 0x5586a0
0x0043da4b:	movl -4(%ebp), %eax
0x0043da4e:	fildl -4(%ebp)
0x0043da51:	fstpl 0x557638
0x0043da57:	movl 0x557640, $0x0<UINT32>
0x0043da61:	movl 0x557644, $0x0<UINT32>
0x0043da6b:	movl 0x557648, $0x0<UINT32>
0x0043da75:	movl 0x55764c, $0x0<UINT32>
0x0043da7f:	fldz
0x0043da81:	fstpl 0x557650
0x0043da87:	movl %esp, %ebp
0x0043da89:	popl %ebp
0x0043da8a:	ret

0x0043da90:	pushl %ebp
0x0043da91:	movl %ebp, %esp
0x0043da93:	pushl $0x10<UINT8>
0x0043da95:	movl %ecx, $0x5588bc<UINT32>
0x0043da9a:	call 0x00418f60
0x00418f60:	pushl %ebp
0x00418f61:	movl %ebp, %esp
0x00418f63:	pushl $0xffffffff<UINT8>
0x00418f65:	pushl $0x43bdeb<UINT32>
0x00418f6a:	movl %eax, %fs:0
0x00418f70:	pushl %eax
0x00418f71:	subl %esp, $0x10<UINT8>
0x00418f74:	movl %eax, 0x5512b4
0x00418f79:	xorl %eax, %ebp
0x00418f7b:	pushl %eax
0x00418f7c:	leal %eax, -12(%ebp)
0x00418f7f:	movl %fs:0, %eax
0x00418f85:	movl -28(%ebp), %ecx
0x00418f88:	movl %ecx, -28(%ebp)
0x00418f8b:	addl %ecx, $0x4<UINT8>
0x00418f8e:	call 0x00418b80
0x00418b80:	pushl %ebp
0x00418b81:	movl %ebp, %esp
0x00418b83:	pushl %ecx
0x00418b84:	movl -4(%ebp), %ecx
0x00418b87:	movl %eax, -4(%ebp)
0x00418b8a:	pushl %eax
0x00418b8b:	call InitializeCriticalSection@KERNEL32.DLL
InitializeCriticalSection@KERNEL32.DLL: API Node	
0x00418b91:	movl %eax, -4(%ebp)
0x00418b94:	movl %esp, %ebp
0x00418b96:	popl %ebp
0x00418b97:	ret

0x00418f93:	movl -4(%ebp), $0x0<UINT32>
0x00418f9a:	movl %eax, -28(%ebp)
0x00418f9d:	movl 0x1c(%eax), $0x0<UINT32>
0x00418fa4:	movl %ecx, -28(%ebp)
0x00418fa7:	movl %edx, 0x8(%ebp)
0x00418faa:	movl 0x20(%ecx), %edx
0x00418fad:	movl %eax, -28(%ebp)
0x00418fb0:	movl 0x24(%eax), $0x0<UINT32>
0x00418fb7:	pushl $0x0<UINT8>
0x00418fb9:	movl %ecx, 0x8(%ebp)
0x00418fbc:	pushl %ecx
0x00418fbd:	pushl $0x0<UINT8>
0x00418fbf:	pushl $0x0<UINT8>
0x00418fc1:	call CreateSemaphoreW@KERNEL32.DLL
CreateSemaphoreW@KERNEL32.DLL: API Node	
0x00418fc7:	movl %edx, -28(%ebp)
0x00418fca:	movl (%edx), %eax
0x00418fcc:	movl -16(%ebp), $0x0<UINT32>
0x00418fd3:	jmp 0x00418fde
0x00418fde:	movl %ecx, -16(%ebp)
0x00418fe1:	cmpl %ecx, 0x8(%ebp)
0x00418fe4:	jnl 0x0041902e
0x00418fe6:	pushl $0x30<UINT8>
0x00418fe8:	call 0x0042a68a
0x0042a68a:	movl %edi, %edi
0x0042a68c:	pushl %ebp
0x0042a68d:	movl %ebp, %esp
0x0042a68f:	subl %esp, $0xc<UINT8>
0x0042a692:	jmp 0x0042a6a1
0x0042a6a1:	pushl 0x8(%ebp)
0x0042a6a4:	call 0x00429734
0x0042a6a9:	popl %ecx
0x0042a6aa:	testl %eax, %eax
0x0042a6ac:	je -26
0x0042a6ae:	leave
0x0042a6af:	ret

0x00418fed:	addl %esp, $0x4<UINT8>
0x00418ff0:	movl -24(%ebp), %eax
0x00418ff3:	movl %edx, -24(%ebp)
0x00418ff6:	movl -20(%ebp), %edx
0x00418ff9:	movl %eax, -20(%ebp)
0x00418ffc:	movl 0x24(%eax), $0x0<UINT32>
0x00419003:	pushl $0x0<UINT8>
0x00419005:	pushl $0x0<UINT8>
0x00419007:	pushl $0x1<UINT8>
0x00419009:	pushl $0x0<UINT8>
0x0041900b:	call CreateEventW@KERNEL32.DLL
CreateEventW@KERNEL32.DLL: API Node	
0x00419011:	movl %ecx, -20(%ebp)
0x00419014:	movl 0x10(%ecx), %eax
0x00419017:	movl %edx, -20(%ebp)
0x0041901a:	movl %eax, -28(%ebp)
0x0041901d:	movl 0x2c(%edx), %eax
0x00419020:	movl %ecx, -20(%ebp)
0x00419023:	pushl %ecx
0x00419024:	movl %ecx, -28(%ebp)
0x00419027:	call 0x00418d50
0x00418d50:	pushl %ebp
0x00418d51:	movl %ebp, %esp
0x00418d53:	subl %esp, $0x8<UINT8>
0x00418d56:	movl -8(%ebp), %ecx
0x00418d59:	movl %eax, -8(%ebp)
0x00418d5c:	addl %eax, $0x4<UINT8>
0x00418d5f:	pushl %eax
0x00418d60:	leal %ecx, -4(%ebp)
0x00418d63:	call 0x00418c00
0x00418c00:	pushl %ebp
0x00418c01:	movl %ebp, %esp
0x00418c03:	pushl %ecx
0x00418c04:	movl -4(%ebp), %ecx
0x00418c07:	movl %eax, -4(%ebp)
0x00418c0a:	movl %ecx, 0x8(%ebp)
0x00418c0d:	movl (%eax), %ecx
0x00418c0f:	movl %edx, -4(%ebp)
0x00418c12:	movl %ecx, (%edx)
0x00418c14:	call 0x00418bc0
0x00418bc0:	pushl %ebp
0x00418bc1:	movl %ebp, %esp
0x00418bc3:	pushl %ecx
0x00418bc4:	movl -4(%ebp), %ecx
0x00418bc7:	movl %eax, -4(%ebp)
0x00418bca:	pushl %eax
0x00418bcb:	call EnterCriticalSection@KERNEL32.DLL
0x00418bd1:	movl %esp, %ebp
0x00418bd3:	popl %ebp
0x00418bd4:	ret

0x00418c19:	movl %eax, -4(%ebp)
0x00418c1c:	movl %esp, %ebp
0x00418c1e:	popl %ebp
0x00418c1f:	ret $0x4<UINT16>

0x00418d68:	movl %ecx, 0x8(%ebp)
0x00418d6b:	movl %edx, -8(%ebp)
0x00418d6e:	movl %eax, 0x1c(%edx)
0x00418d71:	movl 0x28(%ecx), %eax
0x00418d74:	movl %ecx, -8(%ebp)
0x00418d77:	movl %edx, 0x8(%ebp)
0x00418d7a:	movl 0x1c(%ecx), %edx
0x00418d7d:	movl %eax, -8(%ebp)
0x00418d80:	movl %ecx, 0x20(%eax)
0x00418d83:	subl %ecx, $0x1<UINT8>
0x00418d86:	movl %edx, -8(%ebp)
0x00418d89:	movl 0x20(%edx), %ecx
0x00418d8c:	pushl $0x0<UINT8>
0x00418d8e:	pushl $0x1<UINT8>
0x00418d90:	movl %eax, -8(%ebp)
0x00418d93:	movl %ecx, (%eax)
0x00418d95:	pushl %ecx
0x00418d96:	call ReleaseSemaphore@KERNEL32.DLL
ReleaseSemaphore@KERNEL32.DLL: API Node	
0x00418d9c:	leal %ecx, -4(%ebp)
0x00418d9f:	call 0x00418c30
0x00418c30:	pushl %ebp
0x00418c31:	movl %ebp, %esp
0x00418c33:	pushl %ecx
0x00418c34:	movl -4(%ebp), %ecx
0x00418c37:	movl %eax, -4(%ebp)
0x00418c3a:	movl %ecx, (%eax)
0x00418c3c:	call 0x00418be0
0x00418be0:	pushl %ebp
0x00418be1:	movl %ebp, %esp
0x00418be3:	pushl %ecx
0x00418be4:	movl -4(%ebp), %ecx
0x00418be7:	movl %eax, -4(%ebp)
0x00418bea:	pushl %eax
0x00418beb:	call LeaveCriticalSection@KERNEL32.DLL
0x00418bf1:	movl %esp, %ebp
0x00418bf3:	popl %ebp
0x00418bf4:	ret

0x00418c41:	movl %esp, %ebp
0x00418c43:	popl %ebp
0x00418c44:	ret

0x00418da4:	movl %esp, %ebp
0x00418da6:	popl %ebp
0x00418da7:	ret $0x4<UINT16>

0x0041902c:	jmp 0x00418fd5
0x00418fd5:	movl %eax, -16(%ebp)
0x00418fd8:	addl %eax, $0x1<UINT8>
0x00418fdb:	movl -16(%ebp), %eax
0x0041902e:	movl -4(%ebp), $0xffffffff<UINT32>
0x00419035:	movl %eax, -28(%ebp)
0x00419038:	movl %ecx, -12(%ebp)
0x0041903b:	movl %fs:0, %ecx
0x00419042:	popl %ecx
0x00419043:	movl %esp, %ebp
0x00419045:	popl %ebp
0x00419046:	ret $0x4<UINT16>

0x0043da9f:	pushl $0x43dad0<UINT32>
0x0043daa4:	call 0x0042b0f8
0x0043daa9:	addl %esp, $0x4<UINT8>
0x0043daac:	popl %ebp
0x0043daad:	ret

0x00429d2a:	popl %esi
0x00429d2b:	popl %ebp
0x00429d2c:	ret

0x00429dad:	cmpl 0x558a90, $0x0<UINT8>
0x00429db4:	popl %ecx
0x00429db5:	je 0x00429dd2
0x00429dd2:	xorl %eax, %eax
0x00429dd4:	popl %ebp
0x00429dd5:	ret

0x0042be9d:	popl %ecx
0x0042be9e:	cmpl %eax, %esi
0x0042bea0:	je 0x0042bea9
0x0042bea9:	call 0x00433888
0x00433888:	movl %edi, %edi
0x0043388a:	pushl %esi
0x0043388b:	pushl %edi
0x0043388c:	xorl %edi, %edi
0x0043388e:	cmpl 0x558a8c, %edi
0x00433894:	jne 0x0043389b
0x0043389b:	movl %esi, 0x558a7c
0x004338a1:	testl %esi, %esi
0x004338a3:	jne 0x004338aa
0x004338aa:	movb %al, (%esi)
0x004338ac:	cmpb %al, $0x20<UINT8>
0x004338ae:	ja 0x004338b8
0x004338b8:	cmpb %al, $0x22<UINT8>
0x004338ba:	jne 0x004338c5
0x004338bc:	xorl %ecx, %ecx
0x004338be:	testl %edi, %edi
0x004338c0:	sete %cl
0x004338c3:	movl %edi, %ecx
0x004338c5:	movzbl %eax, %al
0x004338c8:	pushl %eax
0x004338c9:	call 0x0043695f
0x004338ce:	popl %ecx
0x004338cf:	testl %eax, %eax
0x004338d1:	je 0x004338d4
0x004338d4:	incl %esi
0x004338d5:	jmp 0x004338aa
0x004338b0:	testb %al, %al
0x004338b2:	je 0x004338e2
0x004338e2:	popl %edi
0x004338e3:	movl %eax, %esi
0x004338e5:	popl %esi
0x004338e6:	ret

0x0042beae:	testb -60(%ebp), %bl
0x0042beb1:	je 0x0042beb9
0x0042beb9:	pushl $0xa<UINT8>
0x0042bebb:	popl %ecx
0x0042bebc:	pushl %ecx
0x0042bebd:	pushl %eax
0x0042bebe:	pushl %esi
0x0042bebf:	pushl $0x400000<UINT32>
0x0042bec4:	call 0x0040eab0
0x0040eab0:	pushl %ebp
0x0040eab1:	movl %ebp, %esp
0x0040eab3:	subl %esp, $0x3bc<UINT32>
0x0040eab9:	movl %eax, 0x5512b4
0x0040eabe:	xorl %eax, %ebp
0x0040eac0:	movl -108(%ebp), %eax
0x0040eac3:	movl -8(%ebp), $0x0<UINT32>
0x0040eaca:	movb -21(%ebp), $0x1<UINT8>
0x0040eace:	movl -392(%ebp), $0x0<UINT32>
0x0040ead8:	pushl $0x110<UINT32>
0x0040eadd:	pushl $0x0<UINT8>
0x0040eadf:	leal %eax, -388(%ebp)
0x0040eae5:	pushl %eax
0x0040eae6:	call 0x004316c0
0x0040eaeb:	addl %esp, $0xc<UINT8>
0x0040eaee:	call GetCommandLineW@KERNEL32.DLL
GetCommandLineW@KERNEL32.DLL: API Node	
0x0040eaf4:	movl -56(%ebp), %eax
0x0040eaf7:	leal %ecx, -8(%ebp)
0x0040eafa:	pushl %ecx
0x0040eafb:	call GetCommandLineW@KERNEL32.DLL
0x0040eb01:	pushl %eax
0x0040eb02:	call CommandLineToArgvW@SHELL32.dll
CommandLineToArgvW@SHELL32.dll: API Node	
0x0040eb08:	movl -20(%ebp), %eax
0x0040eb0b:	movl %edx, -20(%ebp)
0x0040eb0e:	pushl %edx
0x0040eb0f:	leal %eax, -8(%ebp)
0x0040eb12:	pushl %eax
0x0040eb13:	pushl $0x5490d0<UINT32>
0x0040eb18:	call 0x00413960
0x00413960:	pushl %ebp
0x00413961:	movl %ebp, %esp
0x00413963:	subl %esp, $0x14<UINT8>
0x00413966:	pushl %esi
0x00413967:	movl -8(%ebp), $0x0<UINT32>
0x0041396e:	movl -12(%ebp), $0x0<UINT32>
0x00413975:	cmpl 0xc(%ebp), $0x0<UINT8>
0x00413979:	je 6
0x0041397b:	cmpl 0x10(%ebp), $0x0<UINT8>
0x0041397f:	jne 0x004139c2
0x004139c2:	cmpl 0xc(%ebp), $0x0<UINT8>
0x004139c6:	je 179
0x004139cc:	movl -4(%ebp), $0x0<UINT32>
0x004139d3:	jmp 0x004139de
0x004139de:	movl %edx, 0xc(%ebp)
0x004139e1:	movl %eax, -4(%ebp)
0x004139e4:	cmpl %eax, (%edx)
0x004139e6:	jge 0x00413a7f
0x00413a7f:	movl %edx, -12(%ebp)
0x00413a82:	pushl %edx
0x00413a83:	movl %eax, 0x8(%ebp)
0x00413a86:	pushl %eax
0x00413a87:	call 0x00413250
0x00413250:	pushl %ebp
0x00413251:	movl %ebp, %esp
0x00413253:	subl %esp, $0x224<UINT32>
0x00413259:	movl %eax, 0x5512b4
0x0041325e:	xorl %eax, %ebp
0x00413260:	movl -12(%ebp), %eax
0x00413263:	movl -8(%ebp), $0x0<UINT32>
0x0041326a:	movl %eax, 0x8(%ebp)
0x0041326d:	pushl %eax
0x0041326e:	pushl $0x5573bc<UINT32>
0x00413273:	leal %ecx, -536(%ebp)
0x00413279:	pushl %ecx
0x0041327a:	call 0x0042962f
0x0042962f:	movl %edi, %edi
0x00429631:	pushl %ebp
0x00429632:	movl %ebp, %esp
0x00429634:	subl %esp, $0x20<UINT8>
0x00429637:	pushl %ebx
0x00429638:	xorl %ebx, %ebx
0x0042963a:	cmpl 0xc(%ebp), %ebx
0x0042963d:	jne 0x0042965c
0x0042965c:	movl %eax, 0x8(%ebp)
0x0042965f:	cmpl %eax, %ebx
0x00429661:	je -36
0x00429663:	pushl %esi
0x00429664:	movl -24(%ebp), %eax
0x00429667:	movl -32(%ebp), %eax
0x0042966a:	leal %eax, 0x10(%ebp)
0x0042966d:	pushl %eax
0x0042966e:	pushl %ebx
0x0042966f:	pushl 0xc(%ebp)
0x00429672:	leal %eax, -32(%ebp)
0x00429675:	pushl %eax
0x00429676:	movl -20(%ebp), $0x42<UINT32>
0x0042967d:	movl -28(%ebp), $0x7fffffff<UINT32>
0x00429684:	call 0x0042c1fa
0x0042c1fa:	movl %edi, %edi
0x0042c1fc:	pushl %ebp
0x0042c1fd:	movl %ebp, %esp
0x0042c1ff:	subl %esp, $0x474<UINT32>
0x0042c205:	movl %eax, 0x5512b4
0x0042c20a:	xorl %eax, %ebp
0x0042c20c:	movl -4(%ebp), %eax
0x0042c20f:	movl %eax, 0x8(%ebp)
0x0042c212:	pushl %ebx
0x0042c213:	movl %ebx, 0x14(%ebp)
0x0042c216:	pushl %esi
0x0042c217:	movl %esi, 0xc(%ebp)
0x0042c21a:	pushl %edi
0x0042c21b:	pushl 0x10(%ebp)
0x0042c21e:	xorl %edi, %edi
0x0042c220:	leal %ecx, -1112(%ebp)
0x0042c226:	movl -1072(%ebp), %eax
0x0042c22c:	movl -1052(%ebp), %ebx
0x0042c232:	movl -1096(%ebp), %edi
0x0042c238:	movl -1032(%ebp), %edi
0x0042c23e:	movl -1068(%ebp), %edi
0x0042c244:	movl -1036(%ebp), %edi
0x0042c24a:	movl -1060(%ebp), %edi
0x0042c250:	movl -1084(%ebp), %edi
0x0042c256:	movl -1064(%ebp), %edi
0x0042c25c:	call 0x00429f9a
0x0042c261:	cmpl -1072(%ebp), %edi
0x0042c267:	jne 0x0042c29c
0x0042c29c:	cmpl %esi, %edi
0x0042c29e:	je -55
0x0042c2a0:	movzwl %edx, (%esi)
0x0042c2a3:	xorl %ecx, %ecx
0x0042c2a5:	movl -1056(%ebp), %edi
0x0042c2ab:	movl -1044(%ebp), %edi
0x0042c2b1:	movl -1092(%ebp), %edi
0x0042c2b7:	movl -1048(%ebp), %edx
0x0042c2bd:	cmpw %dx, %di
0x0042c2c0:	je 2689
0x0042c2c6:	pushl $0x2<UINT8>
0x0042c2c8:	popl %edi
0x0042c2c9:	addl %esi, %edi
0x0042c2cb:	cmpl -1056(%ebp), $0x0<UINT8>
0x0042c2d2:	movl -1088(%ebp), %esi
0x0042c2d8:	jl 2665
0x0042c2de:	leal %eax, -32(%edx)
0x0042c2e1:	cmpw %ax, $0x58<UINT8>
0x0042c2e5:	ja 0x0042c2f6
0x0042c2e7:	movzwl %eax, %dx
0x0042c2ea:	movsbl %eax, 0x43eae8(%eax)
0x0042c2f1:	andl %eax, $0xf<UINT8>
0x0042c2f4:	jmp 0x0042c2f8
0x0042c2f8:	movsbl %eax, 0x43eb08(%ecx,%eax,8)
0x0042c300:	pushl $0x7<UINT8>
0x0042c302:	sarl %eax, $0x4<UINT8>
0x0042c305:	popl %ecx
0x0042c306:	movl -1116(%ebp), %eax
0x0042c30c:	cmpl %eax, %ecx
0x0042c30e:	ja 2549
0x0042c314:	jmp 0x0042c55a
0x0042c539:	movl %eax, -1072(%ebp)
0x0042c53f:	pushl %edx
0x0042c540:	leal %esi, -1056(%ebp)
0x0042c546:	movl -1064(%ebp), $0x1<UINT32>
0x0042c550:	call 0x004322a0
0x004322a0:	movl %edi, %edi
0x004322a2:	pushl %ebp
0x004322a3:	movl %ebp, %esp
0x004322a5:	testb 0xc(%eax), $0x40<UINT8>
0x004322a9:	je 6
0x004322ab:	cmpl 0x8(%eax), $0x0<UINT8>
0x004322af:	je 26
0x004322b1:	pushl %eax
0x004322b2:	pushl 0x8(%ebp)
0x004322b5:	call 0x0042f8c9
0x0042f8c9:	movl %edi, %edi
0x0042f8cb:	pushl %ebp
0x0042f8cc:	movl %ebp, %esp
0x0042f8ce:	subl %esp, $0x10<UINT8>
0x0042f8d1:	movl %eax, 0x5512b4
0x0042f8d6:	xorl %eax, %ebp
0x0042f8d8:	movl -4(%ebp), %eax
0x0042f8db:	pushl %ebx
0x0042f8dc:	pushl %esi
0x0042f8dd:	movl %esi, 0xc(%ebp)
0x0042f8e0:	testb 0xc(%esi), $0x40<UINT8>
0x0042f8e4:	pushl %edi
0x0042f8e5:	jne 0x0042fa21
0x0042fa21:	addl 0x4(%esi), $0xfffffffe<UINT8>
0x0042fa25:	js 13
0x0042fa27:	movl %ecx, (%esi)
0x0042fa29:	movl %eax, 0x8(%ebp)
0x0042fa2c:	movw (%ecx), %ax
0x0042fa2f:	addl (%esi), $0x2<UINT8>
0x0042fa32:	jmp 0x0042fa41
0x0042fa41:	movl %ecx, -4(%ebp)
0x0042fa44:	popl %edi
0x0042fa45:	popl %esi
0x0042fa46:	xorl %ecx, %ebp
0x0042fa48:	popl %ebx
0x0042fa49:	call 0x00429620
0x0042fa4e:	leave
0x0042fa4f:	ret

0x004322ba:	popl %ecx
0x004322bb:	popl %ecx
0x004322bc:	movl %ecx, $0xffff<UINT32>
0x004322c1:	cmpw %ax, %cx
0x004322c4:	jne 0x004322cb
0x004322cb:	incl (%esi)
0x004322cd:	popl %ebp
0x004322ce:	ret

0x0042c555:	jmp 0x0042cd08
0x0042cd08:	popl %ecx
0x0042cd09:	movl %esi, -1088(%ebp)
0x0042cd0f:	movzwl %eax, (%esi)
0x0042cd12:	movl -1048(%ebp), %eax
0x0042cd18:	testw %ax, %ax
0x0042cd1b:	je 0x0042cd47
0x0042cd1d:	movl %ecx, -1116(%ebp)
0x0042cd23:	movl %ebx, -1052(%ebp)
0x0042cd29:	movl %edx, %eax
0x0042cd2b:	jmp 0x0042c2c6
0x0042c2f6:	xorl %eax, %eax
0x0042c31b:	xorl %eax, %eax
0x0042c31d:	orl -1036(%ebp), $0xffffffff<UINT8>
0x0042c324:	movl -1120(%ebp), %eax
0x0042c32a:	movl -1084(%ebp), %eax
0x0042c330:	movl -1068(%ebp), %eax
0x0042c336:	movl -1060(%ebp), %eax
0x0042c33c:	movl -1032(%ebp), %eax
0x0042c342:	movl -1064(%ebp), %eax
0x0042c348:	jmp 0x0042cd09
0x0042c55a:	movzwl %eax, %dx
0x0042c55d:	cmpl %eax, $0x64<UINT8>
0x0042c560:	jg 0x0042c795
0x0042c795:	cmpl %eax, $0x70<UINT8>
0x0042c798:	jg 0x0042c998
0x0042c998:	subl %eax, $0x73<UINT8>
0x0042c99b:	je 0x0042c608
0x0042c608:	movl %edi, -1036(%ebp)
0x0042c60e:	cmpl %edi, $0xffffffff<UINT8>
0x0042c611:	jne 5
0x0042c613:	movl %edi, $0x7fffffff<UINT32>
0x0042c618:	addl %ebx, $0x4<UINT8>
0x0042c61b:	testb -1032(%ebp), $0x20<UINT8>
0x0042c622:	movl -1052(%ebp), %ebx
0x0042c628:	movl %ebx, -4(%ebx)
0x0042c62b:	movl -1040(%ebp), %ebx
0x0042c631:	je 0x0042cb3f
0x0042cb3f:	testl %ebx, %ebx
0x0042cb41:	jne 0x0042cb4e
0x0042cb4e:	movl %eax, -1040(%ebp)
0x0042cb54:	movl -1064(%ebp), $0x1<UINT32>
0x0042cb5e:	jmp 0x0042cb69
0x0042cb69:	testl %edi, %edi
0x0042cb6b:	jne 0x0042cb60
0x0042cb60:	decl %edi
0x0042cb61:	cmpw (%eax), $0x0<UINT8>
0x0042cb65:	je 0x0042cb6d
0x0042cb67:	incl %eax
0x0042cb68:	incl %eax
0x0042cb6d:	subl %eax, -1040(%ebp)
0x0042cb73:	sarl %eax
0x0042cb75:	movl -1044(%ebp), %eax
0x0042cb7b:	cmpl -1084(%ebp), $0x0<UINT8>
0x0042cb82:	jne 357
0x0042cb88:	movl %eax, -1032(%ebp)
0x0042cb8e:	testb %al, $0x40<UINT8>
0x0042cb90:	je 0x0042cbbd
0x0042cbbd:	movl %ebx, -1068(%ebp)
0x0042cbc3:	movl %esi, -1044(%ebp)
0x0042cbc9:	subl %ebx, %esi
0x0042cbcb:	subl %ebx, -1060(%ebp)
0x0042cbd1:	testb -1032(%ebp), $0xc<UINT8>
0x0042cbd8:	jne 23
0x0042cbda:	pushl -1072(%ebp)
0x0042cbe0:	leal %eax, -1056(%ebp)
0x0042cbe6:	pushl %ebx
0x0042cbe7:	pushl $0x20<UINT8>
0x0042cbe9:	call 0x004322cf
0x004322cf:	movl %edi, %edi
0x004322d1:	pushl %ebp
0x004322d2:	movl %ebp, %esp
0x004322d4:	pushl %esi
0x004322d5:	movl %esi, %eax
0x004322d7:	jmp 0x004322ed
0x004322ed:	cmpl 0xc(%ebp), $0x0<UINT8>
0x004322f1:	jg -26
0x004322f3:	popl %esi
0x004322f4:	popl %ebp
0x004322f5:	ret

0x0042cbee:	addl %esp, $0xc<UINT8>
0x0042cbf1:	pushl -1060(%ebp)
0x0042cbf7:	movl %edi, -1072(%ebp)
0x0042cbfd:	leal %eax, -1056(%ebp)
0x0042cc03:	leal %ecx, -1080(%ebp)
0x0042cc09:	call 0x0042c1a8
0x0042c1a8:	movl %edi, %edi
0x0042c1aa:	pushl %ebp
0x0042c1ab:	movl %ebp, %esp
0x0042c1ad:	testb 0xc(%edi), $0x40<UINT8>
0x0042c1b1:	pushl %ebx
0x0042c1b2:	pushl %esi
0x0042c1b3:	movl %esi, %eax
0x0042c1b5:	movl %ebx, %ecx
0x0042c1b7:	je 55
0x0042c1b9:	cmpl 0x8(%edi), $0x0<UINT8>
0x0042c1bd:	jne 0x0042c1f0
0x0042c1f0:	cmpl 0x8(%ebp), $0x0<UINT8>
0x0042c1f4:	jg 0x0042c1c6
0x0042c1f6:	popl %esi
0x0042c1f7:	popl %ebx
0x0042c1f8:	popl %ebp
0x0042c1f9:	ret

0x0042cc0e:	testb -1032(%ebp), $0x8<UINT8>
0x0042cc15:	popl %ecx
0x0042cc16:	je 0x0042cc33
0x0042cc33:	cmpl -1064(%ebp), $0x0<UINT8>
0x0042cc3a:	jne 0x0042ccb1
0x0042ccb1:	movl %ecx, -1040(%ebp)
0x0042ccb7:	pushl %esi
0x0042ccb8:	leal %eax, -1056(%ebp)
0x0042ccbe:	call 0x0042c1a8
0x0042c1c6:	movzwl %eax, (%ebx)
0x0042c1c9:	decl 0x8(%ebp)
0x0042c1cc:	pushl %eax
0x0042c1cd:	movl %eax, %edi
0x0042c1cf:	call 0x004322a0
0x0042c1d4:	incl %ebx
0x0042c1d5:	incl %ebx
0x0042c1d6:	cmpl (%esi), $0xffffffff<UINT8>
0x0042c1d9:	popl %ecx
0x0042c1da:	jne 0x0042c1f0
0x0042ccc3:	popl %ecx
0x0042ccc4:	cmpl -1056(%ebp), $0x0<UINT8>
0x0042cccb:	jl 32
0x0042cccd:	testb -1032(%ebp), $0x4<UINT8>
0x0042ccd4:	je 0x0042cced
0x0042cced:	cmpl -1092(%ebp), $0x0<UINT8>
0x0042ccf4:	je 0x0042cd09
0x0042cd47:	cmpb -1100(%ebp), $0x0<UINT8>
0x0042cd4e:	je 10
0x0042cd50:	movl %eax, -1104(%ebp)
0x0042cd56:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x0042cd5a:	movl %eax, -1056(%ebp)
0x0042cd60:	movl %ecx, -4(%ebp)
0x0042cd63:	popl %edi
0x0042cd64:	popl %esi
0x0042cd65:	xorl %ecx, %ebp
0x0042cd67:	popl %ebx
0x0042cd68:	call 0x00429620
0x0042cd6d:	leave
0x0042cd6e:	ret

0x00429689:	addl %esp, $0x10<UINT8>
0x0042968c:	decl -28(%ebp)
0x0042968f:	movl %esi, %eax
0x00429691:	js 10
0x00429693:	movl %eax, -32(%ebp)
0x00429696:	movb (%eax), %bl
0x00429698:	incl -32(%ebp)
0x0042969b:	jmp 0x004296a9
0x004296a9:	decl -28(%ebp)
0x004296ac:	js 7
0x004296ae:	movl %eax, -32(%ebp)
0x004296b1:	movb (%eax), %bl
0x004296b3:	jmp 0x004296c1
0x004296c1:	movl %eax, %esi
0x004296c3:	popl %esi
0x004296c4:	popl %ebx
0x004296c5:	leave
0x004296c6:	ret

0x0041327f:	addl %esp, $0xc<UINT8>
0x00413282:	leal %edx, -8(%ebp)
0x00413285:	pushl %edx
0x00413286:	leal %eax, -536(%ebp)
0x0041328c:	pushl %eax
0x0041328d:	pushl $0x80000001<UINT32>
0x00413292:	call RegCreateKeyW@ADVAPI32.dll
RegCreateKeyW@ADVAPI32.dll: API Node	
0x00413298:	testl %eax, %eax
0x0041329a:	jne 34
0x0041329c:	movl -4(%ebp), $0x4<UINT32>
0x004132a3:	leal %ecx, -4(%ebp)
0x004132a6:	pushl %ecx
0x004132a7:	leal %edx, 0xc(%ebp)
0x004132aa:	pushl %edx
0x004132ab:	pushl $0x0<UINT8>
0x004132ad:	pushl $0x0<UINT8>
0x004132af:	pushl $0x5573f0<UINT32>
0x004132b4:	movl %eax, -8(%ebp)
0x004132b7:	pushl %eax
0x004132b8:	call RegQueryValueExW@ADVAPI32.dll
RegQueryValueExW@ADVAPI32.dll: API Node	
0x004132be:	cmpl 0xc(%ebp), $0x0<UINT8>
0x004132c2:	jne 1623
0x004132c8:	pushl $0x3e8<UINT32>
0x004132cd:	pushl $0x40<UINT8>
0x004132cf:	call LocalAlloc@KERNEL32.DLL
LocalAlloc@KERNEL32.DLL: API Node	
0x004132d5:	movl -544(%ebp), %eax
0x004132db:	movl %ecx, -544(%ebp)
0x004132e1:	addl %ecx, $0x12<UINT8>
0x004132e4:	movl -540(%ebp), %ecx
0x004132ea:	pushl $0x55740c<UINT32>
0x004132ef:	call LoadLibraryW@KERNEL32.DLL
0x004132f5:	movl %edx, -544(%ebp)
0x004132fb:	movl (%edx), $0x80c808d0<UINT32>
0x0042daf0:	movl %edi, %edi
0x0042daf2:	pushl %ebp
0x0042daf3:	movl %ebp, %esp
0x0042daf5:	subl %esp, $0x18<UINT8>
0x0042daf8:	pushl %ebx
0x0042daf9:	movl %ebx, 0xc(%ebp)
0x0042dafc:	pushl %esi
0x0042dafd:	movl %esi, 0x8(%ebx)
0x0042db00:	xorl %esi, 0x5512b4
0x0042db06:	pushl %edi
0x0042db07:	movl %eax, (%esi)
0x0042db09:	movb -1(%ebp), $0x0<UINT8>
0x0042db0d:	movl -12(%ebp), $0x1<UINT32>
0x0042db14:	leal %edi, 0x10(%ebx)
0x0042db17:	cmpl %eax, $0xfffffffe<UINT8>
0x0042db1a:	je 0x0042db29
0x0042db29:	movl %ecx, 0xc(%esi)
0x0042db2c:	movl %eax, 0x8(%esi)
0x0042db2f:	addl %ecx, %edi
0x0042db31:	xorl %ecx, (%eax,%edi)
0x0042db34:	call 0x00429620
0x0042db39:	movl %eax, 0x8(%ebp)
0x0042db3c:	testb 0x4(%eax), $0x66<UINT8>
0x0042db40:	jne 278
0x0042db46:	movl %ecx, 0x10(%ebp)
0x0042db49:	leal %edx, -24(%ebp)
0x0042db4c:	movl -4(%ebx), %edx
0x0042db4f:	movl %ebx, 0xc(%ebx)
0x0042db52:	movl -24(%ebp), %eax
0x0042db55:	movl -20(%ebp), %ecx
0x0042db58:	cmpl %ebx, $0xfffffffe<UINT8>
0x0042db5b:	je 95
0x0042db5d:	leal %ecx, (%ecx)
0x0042db60:	leal %eax, (%ebx,%ebx,2)
0x0042db63:	movl %ecx, 0x14(%esi,%eax,4)
0x0042db67:	leal %eax, 0x10(%esi,%eax,4)
0x0042db6b:	movl -16(%ebp), %eax
0x0042db6e:	movl %eax, (%eax)
0x0042db70:	movl -8(%ebp), %eax
0x0042db73:	testl %ecx, %ecx
0x0042db75:	je 20
0x0042db77:	movl %edx, %edi
0x0042db79:	call 0x004320d2
0x004320d2:	pushl %ebp
0x004320d3:	pushl %esi
0x004320d4:	pushl %edi
0x004320d5:	pushl %ebx
0x004320d6:	movl %ebp, %edx
0x004320d8:	xorl %eax, %eax
0x004320da:	xorl %ebx, %ebx
0x004320dc:	xorl %edx, %edx
0x004320de:	xorl %esi, %esi
0x004320e0:	xorl %edi, %edi
0x004320e2:	call 0x0042bee1
0x0042bee1:	movl %eax, -20(%ebp)
0x0042bee4:	movl %ecx, (%eax)
0x0042bee6:	movl %ecx, (%ecx)
0x0042bee8:	movl -36(%ebp), %ecx
0x0042beeb:	pushl %eax
0x0042beec:	pushl %ecx
0x0042beed:	call 0x00430303
0x00430303:	movl %edi, %edi
0x00430305:	pushl %ebp
0x00430306:	movl %ebp, %esp
0x00430308:	pushl %ecx
0x00430309:	pushl %ecx
0x0043030a:	pushl %esi
0x0043030b:	call 0x0042fcf5
0x00430310:	movl %esi, %eax
0x00430312:	testl %esi, %esi
0x00430314:	je 326
0x0043031a:	movl %edx, 0x5c(%esi)
0x0043031d:	movl %eax, 0x551694
0x00430322:	pushl %edi
0x00430323:	movl %edi, 0x8(%ebp)
0x00430326:	movl %ecx, %edx
0x00430328:	pushl %ebx
0x00430329:	cmpl (%ecx), %edi
0x0043032b:	je 0x0043033b
0x0043033b:	imull %eax, %eax, $0xc<UINT8>
0x0043033e:	addl %eax, %edx
0x00430340:	cmpl %ecx, %eax
0x00430342:	jae 8
0x00430344:	cmpl (%ecx), %edi
0x00430346:	jne 4
0x00430348:	movl %eax, %ecx
0x0043034a:	jmp 0x0043034e
0x0043034e:	testl %eax, %eax
0x00430350:	je 10
0x00430352:	movl %ebx, 0x8(%eax)
0x00430355:	movl -4(%ebp), %ebx
0x00430358:	testl %ebx, %ebx
0x0043035a:	jne 7
0x0043035c:	xorl %eax, %eax
0x0043035e:	jmp 0x0043045e
0x0043045e:	popl %ebx
0x0043045f:	popl %edi
0x00430460:	popl %esi
0x00430461:	leave
0x00430462:	ret

0x0042bef2:	popl %ecx
0x0042bef3:	popl %ecx
0x0042bef4:	ret

0x004320e4:	popl %ebx
0x004320e5:	popl %edi
0x004320e6:	popl %esi
0x004320e7:	popl %ebp
0x004320e8:	ret

0x0042db7e:	movb -1(%ebp), $0x1<UINT8>
0x0042db82:	testl %eax, %eax
0x0042db84:	jl 64
0x0042db86:	jg 71
0x0042db88:	movl %eax, -8(%ebp)
0x0042db8b:	movl %ebx, %eax
0x0042db8d:	cmpl %eax, $0xfffffffe<UINT8>
0x0042db90:	jne -50
0x0042db92:	cmpb -1(%ebp), $0x0<UINT8>
0x0042db96:	je 36
0x0042db98:	movl %eax, (%esi)
0x0042db9a:	cmpl %eax, $0xfffffffe<UINT8>
0x0042db9d:	je 0x0042dbac
0x0042dbac:	movl %ecx, 0xc(%esi)
0x0042dbaf:	movl %edx, 0x8(%esi)
0x0042dbb2:	addl %ecx, %edi
0x0042dbb4:	xorl %ecx, (%edx,%edi)
0x0042dbb7:	call 0x00429620
0x0042dbbc:	movl %eax, -12(%ebp)
0x0042dbbf:	popl %edi
0x0042dbc0:	popl %esi
0x0042dbc1:	popl %ebx
0x0042dbc2:	movl %esp, %ebp
0x0042dbc4:	popl %ebp
0x0042dbc5:	ret

0x00413301:	xorl %eax, %eax
0x00413303:	movl %ecx, -544(%ebp)
0x00413309:	movw 0xa(%ecx), %ax
0x0041330d:	xorl %edx, %edx
0x0041330f:	movl %eax, -544(%ebp)
0x00413315:	movw 0xc(%eax), %dx
0x00413319:	movl %ecx, $0x138<UINT32>
0x0041331e:	movl %edx, -544(%ebp)
0x00413324:	movw 0xe(%edx), %cx
0x00413328:	movl %eax, $0xb4<UINT32>
0x0041332d:	movl %ecx, -544(%ebp)
0x00413333:	movw 0x10(%ecx), %ax
0x00413337:	xorl %edx, %edx
0x00413339:	movl %eax, -544(%ebp)
0x0041333f:	movw 0x8(%eax), %dx
0x00413343:	xorl %ecx, %ecx
0x00413345:	movl %edx, -540(%ebp)
0x0041334b:	movw (%edx), %cx
0x0041334e:	movl %eax, -540(%ebp)
0x00413354:	addl %eax, $0x2<UINT8>
0x00413357:	movl -540(%ebp), %eax
0x0041335d:	xorl %ecx, %ecx
0x0041335f:	movl %edx, -540(%ebp)
0x00413365:	movw (%edx), %cx
0x00413368:	movl %eax, -540(%ebp)
0x0041336e:	addl %eax, $0x2<UINT8>
0x00413371:	movl -540(%ebp), %eax
0x00413377:	pushl $0x557428<UINT32>
0x0041337c:	movl %ecx, -540(%ebp)
0x00413382:	pushl %ecx
0x00413383:	call 0x004131c0
0x004131c0:	pushl %ebp
0x004131c1:	movl %ebp, %esp
0x004131c3:	subl %esp, $0x24<UINT8>
0x004131c6:	movl %eax, 0xc(%ebp)
0x004131c9:	movl -8(%ebp), %eax
0x004131cc:	movl %ecx, -8(%ebp)
0x004131cf:	addl %ecx, $0x2<UINT8>
0x004131d2:	movl -12(%ebp), %ecx
0x004131d5:	movl %edx, -8(%ebp)
0x004131d8:	movw %ax, (%edx)
0x004131db:	movw -14(%ebp), %ax
0x004131df:	addl -8(%ebp), $0x2<UINT8>
0x004131e3:	cmpw -14(%ebp), $0x0<UINT8>
0x004131e8:	jne 0x004131d5
0x004131ea:	movl %ecx, -8(%ebp)
0x004131ed:	subl %ecx, -12(%ebp)
0x004131f0:	sarl %ecx
0x004131f2:	movl -20(%ebp), %ecx
0x004131f5:	movl %edx, -20(%ebp)
0x004131f8:	addl %edx, $0x1<UINT8>
0x004131fb:	movl -4(%ebp), %edx
0x004131fe:	movl %eax, 0xc(%ebp)
0x00413201:	movl -24(%ebp), %eax
0x00413204:	movl %ecx, 0x8(%ebp)
0x00413207:	movl -28(%ebp), %ecx
0x0041320a:	movl %edx, -28(%ebp)
0x0041320d:	movl -32(%ebp), %edx
0x00413210:	movl %eax, -24(%ebp)
0x00413213:	movw %cx, (%eax)
0x00413216:	movw -34(%ebp), %cx
0x0041321a:	movl %edx, -28(%ebp)
0x0041321d:	movw %ax, -34(%ebp)
0x00413221:	movw (%edx), %ax
0x00413224:	movl %ecx, -24(%ebp)
0x00413227:	addl %ecx, $0x2<UINT8>
0x0041322a:	movl -24(%ebp), %ecx
0x0041322d:	movl %edx, -28(%ebp)
0x00413230:	addl %edx, $0x2<UINT8>
0x00413233:	movl -28(%ebp), %edx
0x00413236:	cmpw -34(%ebp), $0x0<UINT8>
0x0041323b:	jne 0x00413210
0x0041323d:	movl %eax, -4(%ebp)
0x00413240:	movl %esp, %ebp
0x00413242:	popl %ebp
0x00413243:	ret

0x00413388:	addl %esp, $0x8<UINT8>
0x0041338b:	movl %edx, -540(%ebp)
0x00413391:	leal %eax, (%edx,%eax,2)
0x00413394:	movl -540(%ebp), %eax
0x0041339a:	movl %ecx, $0x8<UINT32>
0x0041339f:	movl %edx, -540(%ebp)
0x004133a5:	movw (%edx), %cx
0x004133a8:	movl %eax, -540(%ebp)
0x004133ae:	addl %eax, $0x2<UINT8>
0x004133b1:	movl -540(%ebp), %eax
0x004133b7:	pushl $0x55744c<UINT32>
0x004133bc:	movl %ecx, -540(%ebp)
0x004133c2:	pushl %ecx
0x004133c3:	call 0x004131c0
0x004133c8:	addl %esp, $0x8<UINT8>
0x004133cb:	movl %edx, -540(%ebp)
0x004133d1:	leal %eax, (%edx,%eax,2)
0x004133d4:	movl -540(%ebp), %eax
0x004133da:	movl %ecx, -540(%ebp)
0x004133e0:	pushl %ecx
0x004133e1:	call 0x004131b0
0x004131b0:	pushl %ebp
0x004131b1:	movl %ebp, %esp
0x004131b3:	movl %eax, 0x8(%ebp)
0x004131b6:	addl %eax, $0x3<UINT8>
0x004131b9:	andl %eax, $0xfffffffc<UINT8>
0x004131bc:	popl %ebp
0x004131bd:	ret

0x004133e6:	addl %esp, $0x4<UINT8>
0x004133e9:	movl -548(%ebp), %eax
0x004133ef:	movl %edx, $0x7<UINT32>
0x004133f4:	movl %eax, -548(%ebp)
0x004133fa:	movw 0x8(%eax), %dx
0x004133fe:	movl %ecx, $0x3<UINT32>
0x00413403:	movl %edx, -548(%ebp)
0x00413409:	movw 0xa(%edx), %cx
0x0041340d:	movl %eax, $0x12a<UINT32>
0x00413412:	movl %ecx, -548(%ebp)
0x00413418:	movw 0xc(%ecx), %ax
0x0041341c:	movl %edx, $0xe<UINT32>
0x00413421:	movl %eax, -548(%ebp)
0x00413427:	movw 0xe(%eax), %dx
0x0041342b:	movl %ecx, $0x1f6<UINT32>
0x00413430:	movl %edx, -548(%ebp)
0x00413436:	movw 0x10(%edx), %cx
0x0041343a:	movl %eax, -548(%ebp)
0x00413440:	movl (%eax), $0x50000000<UINT32>
0x00413446:	movl %ecx, -548(%ebp)
0x0041344c:	addl %ecx, $0x12<UINT8>
0x0041344f:	movl -540(%ebp), %ecx
0x00413455:	movl %edx, $0xffff<UINT32>
0x0041345a:	movl %eax, -540(%ebp)
0x00413460:	movw (%eax), %dx
0x00413463:	movl %ecx, -540(%ebp)
0x00413469:	addl %ecx, $0x2<UINT8>
0x0041346c:	movl -540(%ebp), %ecx
0x00413472:	movl %edx, $0x82<UINT32>
0x00413477:	movl %eax, -540(%ebp)
0x0041347d:	movw (%eax), %dx
0x00413480:	movl %ecx, -540(%ebp)
0x00413486:	addl %ecx, $0x2<UINT8>
0x00413489:	movl -540(%ebp), %ecx
0x0041348f:	pushl $0x557468<UINT32>
0x00413494:	movl %edx, -540(%ebp)
0x0041349a:	pushl %edx
0x0041349b:	call 0x004131c0
0x004134a0:	addl %esp, $0x8<UINT8>
0x004134a3:	movl %ecx, -540(%ebp)
0x004134a9:	leal %edx, (%ecx,%eax,2)
0x004134ac:	movl -540(%ebp), %edx
0x004134b2:	xorl %eax, %eax
0x004134b4:	movl %ecx, -540(%ebp)
0x004134ba:	movw (%ecx), %ax
0x004134bd:	movl %edx, -540(%ebp)
0x004134c3:	addl %edx, $0x2<UINT8>
0x004134c6:	movl -540(%ebp), %edx
0x004134cc:	movl %eax, -544(%ebp)
0x004134d2:	movw %cx, 0x8(%eax)
0x004134d6:	addw %cx, $0x1<UINT8>
0x004134da:	movl %edx, -544(%ebp)
0x004134e0:	movw 0x8(%edx), %cx
0x004134e4:	movl %eax, -540(%ebp)
0x004134ea:	pushl %eax
0x004134eb:	call 0x004131b0
0x004134f0:	addl %esp, $0x4<UINT8>
0x004134f3:	movl -548(%ebp), %eax
0x004134f9:	movl %ecx, $0xc9<UINT32>
0x004134fe:	movl %edx, -548(%ebp)
0x00413504:	movw 0x8(%edx), %cx
0x00413508:	movl %eax, $0x9f<UINT32>
0x0041350d:	movl %ecx, -548(%ebp)
0x00413513:	movw 0xa(%ecx), %ax
0x00413517:	movl %edx, $0x32<UINT32>
0x0041351c:	movl %eax, -548(%ebp)
0x00413522:	movw 0xc(%eax), %dx
0x00413526:	movl %ecx, $0xe<UINT32>
0x0041352b:	movl %edx, -548(%ebp)
0x00413531:	movw 0xe(%edx), %cx
0x00413535:	movl %eax, $0x1<UINT32>
0x0041353a:	movl %ecx, -548(%ebp)
0x00413540:	movw 0x10(%ecx), %ax
0x00413544:	movl %edx, -548(%ebp)
0x0041354a:	movl (%edx), $0x50010000<UINT32>
0x00413550:	movl %eax, -548(%ebp)
0x00413556:	addl %eax, $0x12<UINT8>
0x00413559:	movl -540(%ebp), %eax
0x0041355f:	movl %ecx, $0xffff<UINT32>
0x00413564:	movl %edx, -540(%ebp)
0x0041356a:	movw (%edx), %cx
0x0041356d:	movl %eax, -540(%ebp)
0x00413573:	addl %eax, $0x2<UINT8>
0x00413576:	movl -540(%ebp), %eax
0x0041357c:	movl %ecx, $0x80<UINT32>
0x00413581:	movl %edx, -540(%ebp)
0x00413587:	movw (%edx), %cx
0x0041358a:	movl %eax, -540(%ebp)
0x00413590:	addl %eax, $0x2<UINT8>
0x00413593:	movl -540(%ebp), %eax
0x00413599:	pushl $0x5574fc<UINT32>
0x0041359e:	movl %ecx, -540(%ebp)
0x004135a4:	pushl %ecx
0x004135a5:	call 0x004131c0
0x004135aa:	addl %esp, $0x8<UINT8>
0x004135ad:	movl %edx, -540(%ebp)
0x004135b3:	leal %eax, (%edx,%eax,2)
0x004135b6:	movl -540(%ebp), %eax
0x004135bc:	xorl %ecx, %ecx
0x004135be:	movl %edx, -540(%ebp)
0x004135c4:	movw (%edx), %cx
0x004135c7:	movl %eax, -540(%ebp)
0x004135cd:	addl %eax, $0x2<UINT8>
0x004135d0:	movl -540(%ebp), %eax
0x004135d6:	movl %ecx, -544(%ebp)
0x004135dc:	movw %dx, 0x8(%ecx)
0x004135e0:	addw %dx, $0x1<UINT8>
0x004135e4:	movl %eax, -544(%ebp)
0x004135ea:	movw 0x8(%eax), %dx
0x004135ee:	movl %ecx, -540(%ebp)
0x004135f4:	pushl %ecx
0x004135f5:	call 0x004131b0
0x004135fa:	addl %esp, $0x4<UINT8>
0x004135fd:	movl -548(%ebp), %eax
0x00413603:	movl %edx, $0xff<UINT32>
0x00413608:	movl %eax, -548(%ebp)
0x0041360e:	movw 0x8(%eax), %dx
0x00413612:	movl %ecx, $0x9f<UINT32>
0x00413617:	movl %edx, -548(%ebp)
0x0041361d:	movw 0xa(%edx), %cx
0x00413621:	movl %eax, $0x32<UINT32>
0x00413626:	movl %ecx, -548(%ebp)
0x0041362c:	movw 0xc(%ecx), %ax
0x00413630:	movl %edx, $0xe<UINT32>
0x00413635:	movl %eax, -548(%ebp)
0x0041363b:	movw 0xe(%eax), %dx
0x0041363f:	movl %ecx, $0x2<UINT32>
0x00413644:	movl %edx, -548(%ebp)
0x0041364a:	movw 0x10(%edx), %cx
0x0041364e:	movl %eax, -548(%ebp)
0x00413654:	movl (%eax), $0x50010000<UINT32>
0x0041365a:	movl %ecx, -548(%ebp)
0x00413660:	addl %ecx, $0x12<UINT8>
0x00413663:	movl -540(%ebp), %ecx
0x00413669:	movl %edx, $0xffff<UINT32>
0x0041366e:	movl %eax, -540(%ebp)
0x00413674:	movw (%eax), %dx
0x00413677:	movl %ecx, -540(%ebp)
0x0041367d:	addl %ecx, $0x2<UINT8>
0x00413680:	movl -540(%ebp), %ecx
0x00413686:	movl %edx, $0x80<UINT32>
0x0041368b:	movl %eax, -540(%ebp)
0x00413691:	movw (%eax), %dx
0x00413694:	movl %ecx, -540(%ebp)
0x0041369a:	addl %ecx, $0x2<UINT8>
0x0041369d:	movl -540(%ebp), %ecx
0x004136a3:	pushl $0x55750c<UINT32>
0x004136a8:	movl %edx, -540(%ebp)
0x004136ae:	pushl %edx
0x004136af:	call 0x004131c0
0x004136b4:	addl %esp, $0x8<UINT8>
0x004136b7:	movl %ecx, -540(%ebp)
0x004136bd:	leal %edx, (%ecx,%eax,2)
0x004136c0:	movl -540(%ebp), %edx
0x004136c6:	xorl %eax, %eax
0x004136c8:	movl %ecx, -540(%ebp)
0x004136ce:	movw (%ecx), %ax
0x004136d1:	movl %edx, -540(%ebp)
0x004136d7:	addl %edx, $0x2<UINT8>
0x004136da:	movl -540(%ebp), %edx
0x004136e0:	movl %eax, -544(%ebp)
0x004136e6:	movw %cx, 0x8(%eax)
0x004136ea:	addw %cx, $0x1<UINT8>
0x004136ee:	movl %edx, -544(%ebp)
0x004136f4:	movw 0x8(%edx), %cx
0x004136f8:	movl %eax, -540(%ebp)
0x004136fe:	pushl %eax
0x004136ff:	call 0x004131b0
0x00413704:	addl %esp, $0x4<UINT8>
0x00413707:	movl -548(%ebp), %eax
0x0041370d:	movl %ecx, $0x7<UINT32>
0x00413712:	movl %edx, -548(%ebp)
0x00413718:	movw 0x8(%edx), %cx
0x0041371c:	movl %eax, $0x9f<UINT32>
0x00413721:	movl %ecx, -548(%ebp)
0x00413727:	movw 0xa(%ecx), %ax
0x0041372b:	movl %edx, $0x32<UINT32>
0x00413730:	movl %eax, -548(%ebp)
0x00413736:	movw 0xc(%eax), %dx
0x0041373a:	movl %ecx, $0xe<UINT32>
0x0041373f:	movl %edx, -548(%ebp)
0x00413745:	movw 0xe(%edx), %cx
0x00413749:	movl %eax, $0x1f5<UINT32>
0x0041374e:	movl %ecx, -548(%ebp)
0x00413754:	movw 0x10(%ecx), %ax
0x00413758:	movl %edx, -548(%ebp)
0x0041375e:	movl (%edx), $0x50010000<UINT32>
0x00413764:	movl %eax, -548(%ebp)
0x0041376a:	addl %eax, $0x12<UINT8>
0x0041376d:	movl -540(%ebp), %eax
0x00413773:	movl %ecx, $0xffff<UINT32>
0x00413778:	movl %edx, -540(%ebp)
0x0041377e:	movw (%edx), %cx
0x00413781:	movl %eax, -540(%ebp)
0x00413787:	addl %eax, $0x2<UINT8>
0x0041378a:	movl -540(%ebp), %eax
0x00413790:	movl %ecx, $0x80<UINT32>
0x00413795:	movl %edx, -540(%ebp)
0x0041379b:	movw (%edx), %cx
0x0041379e:	movl %eax, -540(%ebp)
0x004137a4:	addl %eax, $0x2<UINT8>
0x004137a7:	movl -540(%ebp), %eax
0x004137ad:	pushl $0x557520<UINT32>
0x004137b2:	movl %ecx, -540(%ebp)
0x004137b8:	pushl %ecx
0x004137b9:	call 0x004131c0
0x004137be:	addl %esp, $0x8<UINT8>
0x004137c1:	movl %edx, -540(%ebp)
0x004137c7:	leal %eax, (%edx,%eax,2)
0x004137ca:	movl -540(%ebp), %eax
0x004137d0:	xorl %ecx, %ecx
0x004137d2:	movl %edx, -540(%ebp)
0x004137d8:	movw (%edx), %cx
0x004137db:	movl %eax, -540(%ebp)
0x004137e1:	addl %eax, $0x2<UINT8>
0x004137e4:	movl -540(%ebp), %eax
0x004137ea:	movl %ecx, -544(%ebp)
0x004137f0:	movw %dx, 0x8(%ecx)
0x004137f4:	addw %dx, $0x1<UINT8>
0x004137f8:	movl %eax, -544(%ebp)
0x004137fe:	movw 0x8(%eax), %dx
0x00413802:	movl %ecx, -540(%ebp)
0x00413808:	pushl %ecx
0x00413809:	call 0x004131b0
0x0041380e:	addl %esp, $0x4<UINT8>
0x00413811:	movl -548(%ebp), %eax
0x00413817:	movl %edx, $0x7<UINT32>
0x0041381c:	movl %eax, -548(%ebp)
0x00413822:	movw 0x8(%eax), %dx
0x00413826:	movl %ecx, $0xe<UINT32>
0x0041382b:	movl %edx, -548(%ebp)
0x00413831:	movw 0xa(%edx), %cx
0x00413835:	movl %eax, $0x12a<UINT32>
0x0041383a:	movl %ecx, -548(%ebp)
0x00413840:	movw 0xc(%ecx), %ax
0x00413844:	movl %edx, $0x8c<UINT32>
0x00413849:	movl %eax, -548(%ebp)
0x0041384f:	movw 0xe(%eax), %dx
0x00413853:	movl %ecx, $0x1f4<UINT32>
0x00413858:	movl %edx, -548(%ebp)
0x0041385e:	movw 0x10(%edx), %cx
0x00413862:	movl %eax, -548(%ebp)
0x00413868:	movl (%eax), $0x50a11844<UINT32>
0x0041386e:	movl %ecx, -548(%ebp)
0x00413874:	addl %ecx, $0x12<UINT8>
0x00413877:	movl -540(%ebp), %ecx
0x0041387d:	pushl $0x557530<UINT32>
0x00413882:	movl %edx, -540(%ebp)
0x00413888:	pushl %edx
0x00413889:	call 0x004131c0
0x0041388e:	addl %esp, $0x8<UINT8>
0x00413891:	movl %ecx, -540(%ebp)
0x00413897:	leal %edx, (%ecx,%eax,2)
0x0041389a:	movl -540(%ebp), %edx
0x004138a0:	pushl $0x557544<UINT32>
0x004138a5:	movl %eax, -540(%ebp)
0x004138ab:	pushl %eax
0x004138ac:	call 0x004131c0
0x004138b1:	addl %esp, $0x8<UINT8>
0x004138b4:	movl %ecx, -540(%ebp)
0x004138ba:	leal %edx, (%ecx,%eax,2)
0x004138bd:	movl -540(%ebp), %edx
0x004138c3:	xorl %eax, %eax
0x004138c5:	movl %ecx, -540(%ebp)
0x004138cb:	movw (%ecx), %ax
0x004138ce:	movl %edx, -540(%ebp)
0x004138d4:	addl %edx, $0x2<UINT8>
0x004138d7:	movl -540(%ebp), %edx
0x004138dd:	movl %eax, -544(%ebp)
0x004138e3:	movw %cx, 0x8(%eax)
0x004138e7:	addw %cx, $0x1<UINT8>
0x004138eb:	movl %edx, -544(%ebp)
0x004138f1:	movw 0x8(%edx), %cx
0x004138f5:	movl %eax, 0x8(%ebp)
0x004138f8:	pushl %eax
0x004138f9:	pushl $0x412ff0<UINT32>
0x004138fe:	pushl $0x0<UINT8>
0x00413900:	movl %ecx, -544(%ebp)
0x00413906:	pushl %ecx
0x00413907:	pushl $0x0<UINT8>
0x00413909:	call DialogBoxIndirectParamW@USER32.dll
DialogBoxIndirectParamW@USER32.dll: API Node	
0x0041390f:	movl 0xc(%ebp), %eax
0x00413912:	movl %edx, -544(%ebp)
0x00413918:	pushl %edx
0x00413919:	call LocalFree@KERNEL32.DLL
LocalFree@KERNEL32.DLL: API Node	
0x0041391f:	cmpl 0xc(%ebp), $0x0<UINT8>
0x00413923:	je 25
