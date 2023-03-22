0x004a1dd0:	pusha
0x004a1dd1:	movl %esi, $0x464000<UINT32>
0x004a1dd6:	leal %edi, -405504(%esi)
0x004a1ddc:	pushl %edi
0x004a1ddd:	jmp 0x004a1dea
0x004a1dea:	movl %ebx, (%esi)
0x004a1dec:	subl %esi, $0xfffffffc<UINT8>
0x004a1def:	adcl %ebx, %ebx
0x004a1df1:	jb 0x004a1de0
0x004a1de0:	movb %al, (%esi)
0x004a1de2:	incl %esi
0x004a1de3:	movb (%edi), %al
0x004a1de5:	incl %edi
0x004a1de6:	addl %ebx, %ebx
0x004a1de8:	jne 0x004a1df1
0x004a1df3:	movl %eax, $0x1<UINT32>
0x004a1df8:	addl %ebx, %ebx
0x004a1dfa:	jne 0x004a1e03
0x004a1e03:	adcl %eax, %eax
0x004a1e05:	addl %ebx, %ebx
0x004a1e07:	jae 0x004a1e14
0x004a1e09:	jne 0x004a1e33
0x004a1e33:	xorl %ecx, %ecx
0x004a1e35:	subl %eax, $0x3<UINT8>
0x004a1e38:	jb 0x004a1e4b
0x004a1e3a:	shll %eax, $0x8<UINT8>
0x004a1e3d:	movb %al, (%esi)
0x004a1e3f:	incl %esi
0x004a1e40:	xorl %eax, $0xffffffff<UINT8>
0x004a1e43:	je 0x004a1eba
0x004a1e45:	sarl %eax
0x004a1e47:	movl %ebp, %eax
0x004a1e49:	jmp 0x004a1e56
0x004a1e56:	jb 0x004a1e24
0x004a1e24:	addl %ebx, %ebx
0x004a1e26:	jne 0x004a1e2f
0x004a1e2f:	adcl %ecx, %ecx
0x004a1e31:	jmp 0x004a1e85
0x004a1e85:	cmpl %ebp, $0xfffffb00<UINT32>
0x004a1e8b:	adcl %ecx, $0x2<UINT8>
0x004a1e8e:	leal %edx, (%edi,%ebp)
0x004a1e91:	cmpl %ebp, $0xfffffffc<UINT8>
0x004a1e94:	jbe 0x004a1ea4
0x004a1ea4:	movl %eax, (%edx)
0x004a1ea6:	addl %edx, $0x4<UINT8>
0x004a1ea9:	movl (%edi), %eax
0x004a1eab:	addl %edi, $0x4<UINT8>
0x004a1eae:	subl %ecx, $0x4<UINT8>
0x004a1eb1:	ja 0x004a1ea4
0x004a1eb3:	addl %edi, %ecx
0x004a1eb5:	jmp 0x004a1de6
0x004a1e0b:	movl %ebx, (%esi)
0x004a1e0d:	subl %esi, $0xfffffffc<UINT8>
0x004a1e10:	adcl %ebx, %ebx
0x004a1e12:	jb 0x004a1e33
0x004a1e58:	incl %ecx
0x004a1e59:	addl %ebx, %ebx
0x004a1e5b:	jne 0x004a1e64
0x004a1e64:	jb 0x004a1e24
0x004a1e66:	addl %ebx, %ebx
0x004a1e68:	jne 0x004a1e71
0x004a1e71:	adcl %ecx, %ecx
0x004a1e73:	addl %ebx, %ebx
0x004a1e75:	jae 0x004a1e66
0x004a1e77:	jne 0x004a1e82
0x004a1e82:	addl %ecx, $0x2<UINT8>
0x004a1e4b:	addl %ebx, %ebx
0x004a1e4d:	jne 0x004a1e56
0x004a1e6a:	movl %ebx, (%esi)
0x004a1e6c:	subl %esi, $0xfffffffc<UINT8>
0x004a1e6f:	adcl %ebx, %ebx
0x004a1dfc:	movl %ebx, (%esi)
0x004a1dfe:	subl %esi, $0xfffffffc<UINT8>
0x004a1e01:	adcl %ebx, %ebx
0x004a1e79:	movl %ebx, (%esi)
0x004a1e7b:	subl %esi, $0xfffffffc<UINT8>
0x004a1e7e:	adcl %ebx, %ebx
0x004a1e80:	jae 0x004a1e66
0x004a1e14:	decl %eax
0x004a1e15:	addl %ebx, %ebx
0x004a1e17:	jne 0x004a1e20
0x004a1e20:	adcl %eax, %eax
0x004a1e22:	jmp 0x004a1df8
0x004a1e96:	movb %al, (%edx)
0x004a1e98:	incl %edx
0x004a1e99:	movb (%edi), %al
0x004a1e9b:	incl %edi
0x004a1e9c:	decl %ecx
0x004a1e9d:	jne 0x004a1e96
0x004a1e9f:	jmp 0x004a1de6
0x004a1e5d:	movl %ebx, (%esi)
0x004a1e5f:	subl %esi, $0xfffffffc<UINT8>
0x004a1e62:	adcl %ebx, %ebx
0x004a1e4f:	movl %ebx, (%esi)
0x004a1e51:	subl %esi, $0xfffffffc<UINT8>
0x004a1e54:	adcl %ebx, %ebx
0x004a1e28:	movl %ebx, (%esi)
0x004a1e2a:	subl %esi, $0xfffffffc<UINT8>
0x004a1e2d:	adcl %ebx, %ebx
0x004a1e19:	movl %ebx, (%esi)
0x004a1e1b:	subl %esi, $0xfffffffc<UINT8>
0x004a1e1e:	adcl %ebx, %ebx
0x004a1eba:	popl %esi
0x004a1ebb:	movl %edi, %esi
0x004a1ebd:	movl %ecx, $0x1024<UINT32>
0x004a1ec2:	movb %al, (%edi)
0x004a1ec4:	incl %edi
0x004a1ec5:	subb %al, $0xffffffe8<UINT8>
0x004a1ec7:	cmpb %al, $0x1<UINT8>
0x004a1ec9:	ja 0x004a1ec2
0x004a1ecb:	cmpb (%edi), $0x9<UINT8>
0x004a1ece:	jne 0x004a1ec2
0x004a1ed0:	movl %eax, (%edi)
0x004a1ed2:	movb %bl, 0x4(%edi)
0x004a1ed5:	shrw %ax, $0x8<UINT8>
0x004a1ed9:	roll %eax, $0x10<UINT8>
0x004a1edc:	xchgb %ah, %al
0x004a1ede:	subl %eax, %edi
0x004a1ee0:	subb %bl, $0xffffffe8<UINT8>
0x004a1ee3:	addl %eax, %esi
0x004a1ee5:	movl (%edi), %eax
0x004a1ee7:	addl %edi, $0x5<UINT8>
0x004a1eea:	movb %al, %bl
0x004a1eec:	loop 0x004a1ec7
0x004a1eee:	leal %edi, 0x9d000(%esi)
0x004a1ef4:	movl %eax, (%edi)
0x004a1ef6:	orl %eax, %eax
0x004a1ef8:	je 0x004a1f3f
0x004a1efa:	movl %ebx, 0x4(%edi)
0x004a1efd:	leal %eax, 0xa2cd0(%eax,%esi)
0x004a1f04:	addl %ebx, %esi
0x004a1f06:	pushl %eax
0x004a1f07:	addl %edi, $0x8<UINT8>
0x004a1f0a:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004a1f10:	xchgl %ebp, %eax
0x004a1f11:	movb %al, (%edi)
0x004a1f13:	incl %edi
0x004a1f14:	orb %al, %al
0x004a1f16:	je 0x004a1ef4
0x004a1f18:	movl %ecx, %edi
0x004a1f1a:	jns 0x004a1f23
0x004a1f23:	pushl %edi
0x004a1f24:	decl %eax
0x004a1f25:	repn scasb %al, %es:(%edi)
0x004a1f27:	pushl %ebp
0x004a1f28:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x004a1f2e:	orl %eax, %eax
0x004a1f30:	je 7
0x004a1f32:	movl (%ebx), %eax
0x004a1f34:	addl %ebx, $0x4<UINT8>
0x004a1f37:	jmp 0x004a1f11
GetProcAddress@KERNEL32.DLL: API Node	
0x004a1f1c:	movzwl %eax, (%edi)
0x004a1f1f:	incl %edi
0x004a1f20:	pushl %eax
0x004a1f21:	incl %edi
0x004a1f22:	movl %ecx, $0xaef24857<UINT32>
0x004a1f3f:	addl %edi, $0x4<UINT8>
0x004a1f42:	leal %ebx, -4(%esi)
0x004a1f45:	xorl %eax, %eax
0x004a1f47:	movb %al, (%edi)
0x004a1f49:	incl %edi
0x004a1f4a:	orl %eax, %eax
0x004a1f4c:	je 0x004a1f70
0x004a1f4e:	cmpb %al, $0xffffffef<UINT8>
0x004a1f50:	ja 0x004a1f63
0x004a1f52:	addl %ebx, %eax
0x004a1f54:	movl %eax, (%ebx)
0x004a1f56:	xchgb %ah, %al
0x004a1f58:	roll %eax, $0x10<UINT8>
0x004a1f5b:	xchgb %ah, %al
0x004a1f5d:	addl %eax, %esi
0x004a1f5f:	movl (%ebx), %eax
0x004a1f61:	jmp 0x004a1f45
0x004a1f63:	andb %al, $0xf<UINT8>
0x004a1f65:	shll %eax, $0x10<UINT8>
0x004a1f68:	movw %ax, (%edi)
0x004a1f6b:	addl %edi, $0x2<UINT8>
0x004a1f6e:	jmp 0x004a1f52
0x004a1f70:	movl %ebp, 0xa2dd8(%esi)
0x004a1f76:	leal %edi, -4096(%esi)
0x004a1f7c:	movl %ebx, $0x1000<UINT32>
0x004a1f81:	pushl %eax
0x004a1f82:	pushl %esp
0x004a1f83:	pushl $0x4<UINT8>
0x004a1f85:	pushl %ebx
0x004a1f86:	pushl %edi
0x004a1f87:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x004a1f89:	leal %eax, 0x20f(%edi)
0x004a1f8f:	andb (%eax), $0x7f<UINT8>
0x004a1f92:	andb 0x28(%eax), $0x7f<UINT8>
0x004a1f96:	popl %eax
0x004a1f97:	pushl %eax
0x004a1f98:	pushl %esp
0x004a1f99:	pushl %eax
0x004a1f9a:	pushl %ebx
0x004a1f9b:	pushl %edi
0x004a1f9c:	call VirtualProtect@kernel32.dll
0x004a1f9e:	popl %eax
0x004a1f9f:	popa
0x004a1fa0:	leal %eax, -128(%esp)
0x004a1fa4:	pushl $0x0<UINT8>
0x004a1fa6:	cmpl %esp, %eax
0x004a1fa8:	jne 0x004a1fa4
0x004a1faa:	subl %esp, $0xffffff80<UINT8>
0x004a1fad:	jmp 0x0041ab3f
0x0041ab3f:	call 0x00423ec8
0x00423ec8:	pushl %ebp
0x00423ec9:	movl %ebp, %esp
0x00423ecb:	subl %esp, $0x14<UINT8>
0x00423ece:	andl -12(%ebp), $0x0<UINT8>
0x00423ed2:	andl -8(%ebp), $0x0<UINT8>
0x00423ed6:	movl %eax, 0x43e0d0
0x00423edb:	pushl %esi
0x00423edc:	pushl %edi
0x00423edd:	movl %edi, $0xbb40e64e<UINT32>
0x00423ee2:	movl %esi, $0xffff0000<UINT32>
0x00423ee7:	cmpl %eax, %edi
0x00423ee9:	je 0x00423ef8
0x00423ef8:	leal %eax, -12(%ebp)
0x00423efb:	pushl %eax
0x00423efc:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x00423f02:	movl %eax, -8(%ebp)
0x00423f05:	xorl %eax, -12(%ebp)
0x00423f08:	movl -4(%ebp), %eax
0x00423f0b:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x00423f11:	xorl -4(%ebp), %eax
0x00423f14:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x00423f1a:	xorl -4(%ebp), %eax
0x00423f1d:	leal %eax, -20(%ebp)
0x00423f20:	pushl %eax
0x00423f21:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x00423f27:	movl %ecx, -16(%ebp)
0x00423f2a:	leal %eax, -4(%ebp)
0x00423f2d:	xorl %ecx, -20(%ebp)
0x00423f30:	xorl %ecx, -4(%ebp)
0x00423f33:	xorl %ecx, %eax
0x00423f35:	cmpl %ecx, %edi
0x00423f37:	jne 0x00423f40
0x00423f40:	testl %esi, %ecx
0x00423f42:	jne 0x00423f50
0x00423f50:	movl 0x43e0d0, %ecx
0x00423f56:	notl %ecx
0x00423f58:	movl 0x43e0d4, %ecx
0x00423f5e:	popl %edi
0x00423f5f:	popl %esi
0x00423f60:	movl %esp, %ebp
0x00423f62:	popl %ebp
0x00423f63:	ret

0x0041ab44:	jmp 0x0041ab49
0x0041ab49:	pushl $0x14<UINT8>
0x0041ab4b:	pushl $0x43be10<UINT32>
0x0041ab50:	call 0x0041b680
0x0041b680:	pushl $0x419060<UINT32>
0x0041b685:	pushl %fs:0
0x0041b68c:	movl %eax, 0x10(%esp)
0x0041b690:	movl 0x10(%esp), %ebp
0x0041b694:	leal %ebp, 0x10(%esp)
0x0041b698:	subl %esp, %eax
0x0041b69a:	pushl %ebx
0x0041b69b:	pushl %esi
0x0041b69c:	pushl %edi
0x0041b69d:	movl %eax, 0x43e0d0
0x0041b6a2:	xorl -4(%ebp), %eax
0x0041b6a5:	xorl %eax, %ebp
0x0041b6a7:	pushl %eax
0x0041b6a8:	movl -24(%ebp), %esp
0x0041b6ab:	pushl -8(%ebp)
0x0041b6ae:	movl %eax, -4(%ebp)
0x0041b6b1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0041b6b8:	movl -8(%ebp), %eax
0x0041b6bb:	leal %eax, -16(%ebp)
0x0041b6be:	movl %fs:0, %eax
0x0041b6c4:	ret

0x0041ab55:	call 0x00420670
0x00420670:	pushl %ebp
0x00420671:	movl %ebp, %esp
0x00420673:	subl %esp, $0x44<UINT8>
0x00420676:	leal %eax, -68(%ebp)
0x00420679:	pushl %eax
0x0042067a:	call GetStartupInfoW@KERNEL32.DLL
GetStartupInfoW@KERNEL32.DLL: API Node	
0x00420680:	testb -24(%ebp), $0x1<UINT8>
0x00420684:	je 0x0042068c
0x0042068c:	pushl $0xa<UINT8>
0x0042068e:	popl %eax
0x0042068f:	movl %esp, %ebp
0x00420691:	popl %ebp
0x00420692:	ret

0x0041ab5a:	movzwl %esi, %ax
0x0041ab5d:	pushl $0x2<UINT8>
0x0041ab5f:	call 0x00423e7b
0x00423e7b:	pushl %ebp
0x00423e7c:	movl %ebp, %esp
0x00423e7e:	movl %eax, 0x8(%ebp)
0x00423e81:	movl 0x440110, %eax
0x00423e86:	popl %ebp
0x00423e87:	ret

0x0041ab64:	popl %ecx
0x0041ab65:	movl %eax, $0x5a4d<UINT32>
0x0041ab6a:	cmpw 0x400000, %ax
0x0041ab71:	je 0x0041ab77
0x0041ab77:	movl %eax, 0x40003c
0x0041ab7c:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x0041ab86:	jne -21
0x0041ab88:	movl %ecx, $0x10b<UINT32>
0x0041ab8d:	cmpw 0x400018(%eax), %cx
0x0041ab94:	jne -35
0x0041ab96:	xorl %ebx, %ebx
0x0041ab98:	cmpl 0x400074(%eax), $0xe<UINT8>
0x0041ab9f:	jbe 9
0x0041aba1:	cmpl 0x4000e8(%eax), %ebx
0x0041aba7:	setne %bl
0x0041abaa:	movl -28(%ebp), %ebx
0x0041abad:	call 0x00421105
0x00421105:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x0042110b:	xorl %ecx, %ecx
0x0042110d:	movl 0x440768, %eax
0x00421112:	testl %eax, %eax
0x00421114:	setne %cl
0x00421117:	movl %eax, %ecx
0x00421119:	ret

0x0041abb2:	testl %eax, %eax
0x0041abb4:	jne 0x0041abbe
0x0041abbe:	call 0x0042034e
0x0042034e:	call 0x00417f66
0x00417f66:	pushl %esi
0x00417f67:	pushl $0x0<UINT8>
0x00417f69:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00417f6f:	movl %esi, %eax
0x00417f71:	pushl %esi
0x00417f72:	call 0x00420ec0
0x00420ec0:	pushl %ebp
0x00420ec1:	movl %ebp, %esp
0x00420ec3:	movl %eax, 0x8(%ebp)
0x00420ec6:	movl 0x440748, %eax
0x00420ecb:	popl %ebp
0x00420ecc:	ret

0x00417f77:	pushl %esi
0x00417f78:	call 0x0041af31
0x0041af31:	pushl %ebp
0x0041af32:	movl %ebp, %esp
0x0041af34:	movl %eax, 0x8(%ebp)
0x0041af37:	movl 0x43ff88, %eax
0x0041af3c:	popl %ebp
0x0041af3d:	ret

0x00417f7d:	pushl %esi
0x00417f7e:	call 0x00420ecd
0x00420ecd:	pushl %ebp
0x00420ece:	movl %ebp, %esp
0x00420ed0:	movl %eax, 0x8(%ebp)
0x00420ed3:	movl 0x44074c, %eax
0x00420ed8:	popl %ebp
0x00420ed9:	ret

0x00417f83:	pushl %esi
0x00417f84:	call 0x00420ee7
0x00420ee7:	pushl %ebp
0x00420ee8:	movl %ebp, %esp
0x00420eea:	movl %eax, 0x8(%ebp)
0x00420eed:	movl 0x440750, %eax
0x00420ef2:	movl 0x440754, %eax
0x00420ef7:	movl 0x440758, %eax
0x00420efc:	movl 0x44075c, %eax
0x00420f01:	popl %ebp
0x00420f02:	ret

0x00417f89:	pushl %esi
0x00417f8a:	call 0x00420e89
0x00420e89:	pushl $0x420e42<UINT32>
0x00420e8e:	call EncodePointer@KERNEL32.DLL
0x00420e94:	movl 0x440744, %eax
0x00420e99:	ret

0x00417f8f:	pushl %esi
0x00417f90:	call 0x004210f8
0x004210f8:	pushl %ebp
0x004210f9:	movl %ebp, %esp
0x004210fb:	movl %eax, 0x8(%ebp)
0x004210fe:	movl 0x440764, %eax
0x00421103:	popl %ebp
0x00421104:	ret

0x00417f95:	addl %esp, $0x18<UINT8>
0x00417f98:	popl %esi
0x00417f99:	jmp 0x00420701
0x00420701:	pushl %esi
0x00420702:	pushl %edi
0x00420703:	pushl $0x42c520<UINT32>
0x00420708:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0042070e:	movl %esi, 0x42c1f0
0x00420714:	movl %edi, %eax
0x00420716:	pushl $0x435498<UINT32>
0x0042071b:	pushl %edi
0x0042071c:	call GetProcAddress@KERNEL32.DLL
0x0042071e:	xorl %eax, 0x43e0d0
0x00420724:	pushl $0x4354a4<UINT32>
0x00420729:	pushl %edi
0x0042072a:	movl 0x440a40, %eax
0x0042072f:	call GetProcAddress@KERNEL32.DLL
0x00420731:	xorl %eax, 0x43e0d0
0x00420737:	pushl $0x4354ac<UINT32>
0x0042073c:	pushl %edi
0x0042073d:	movl 0x440a44, %eax
0x00420742:	call GetProcAddress@KERNEL32.DLL
0x00420744:	xorl %eax, 0x43e0d0
0x0042074a:	pushl $0x4354b8<UINT32>
0x0042074f:	pushl %edi
0x00420750:	movl 0x440a48, %eax
0x00420755:	call GetProcAddress@KERNEL32.DLL
0x00420757:	xorl %eax, 0x43e0d0
0x0042075d:	pushl $0x4354c4<UINT32>
0x00420762:	pushl %edi
0x00420763:	movl 0x440a4c, %eax
0x00420768:	call GetProcAddress@KERNEL32.DLL
0x0042076a:	xorl %eax, 0x43e0d0
0x00420770:	pushl $0x4354e0<UINT32>
0x00420775:	pushl %edi
0x00420776:	movl 0x440a50, %eax
0x0042077b:	call GetProcAddress@KERNEL32.DLL
0x0042077d:	xorl %eax, 0x43e0d0
0x00420783:	pushl $0x4354f0<UINT32>
0x00420788:	pushl %edi
0x00420789:	movl 0x440a54, %eax
0x0042078e:	call GetProcAddress@KERNEL32.DLL
0x00420790:	xorl %eax, 0x43e0d0
0x00420796:	pushl $0x435504<UINT32>
0x0042079b:	pushl %edi
0x0042079c:	movl 0x440a58, %eax
0x004207a1:	call GetProcAddress@KERNEL32.DLL
0x004207a3:	xorl %eax, 0x43e0d0
0x004207a9:	pushl $0x43551c<UINT32>
0x004207ae:	pushl %edi
0x004207af:	movl 0x440a5c, %eax
0x004207b4:	call GetProcAddress@KERNEL32.DLL
0x004207b6:	xorl %eax, 0x43e0d0
0x004207bc:	pushl $0x435534<UINT32>
0x004207c1:	pushl %edi
0x004207c2:	movl 0x440a60, %eax
0x004207c7:	call GetProcAddress@KERNEL32.DLL
0x004207c9:	xorl %eax, 0x43e0d0
0x004207cf:	pushl $0x435548<UINT32>
0x004207d4:	pushl %edi
0x004207d5:	movl 0x440a64, %eax
0x004207da:	call GetProcAddress@KERNEL32.DLL
0x004207dc:	xorl %eax, 0x43e0d0
0x004207e2:	pushl $0x435568<UINT32>
0x004207e7:	pushl %edi
0x004207e8:	movl 0x440a68, %eax
0x004207ed:	call GetProcAddress@KERNEL32.DLL
0x004207ef:	xorl %eax, 0x43e0d0
0x004207f5:	pushl $0x435580<UINT32>
0x004207fa:	pushl %edi
0x004207fb:	movl 0x440a6c, %eax
0x00420800:	call GetProcAddress@KERNEL32.DLL
0x00420802:	xorl %eax, 0x43e0d0
0x00420808:	pushl $0x435598<UINT32>
0x0042080d:	pushl %edi
0x0042080e:	movl 0x440a70, %eax
0x00420813:	call GetProcAddress@KERNEL32.DLL
0x00420815:	xorl %eax, 0x43e0d0
0x0042081b:	pushl $0x4355ac<UINT32>
0x00420820:	pushl %edi
0x00420821:	movl 0x440a74, %eax
0x00420826:	call GetProcAddress@KERNEL32.DLL
0x00420828:	xorl %eax, 0x43e0d0
0x0042082e:	movl 0x440a78, %eax
0x00420833:	pushl $0x4355c0<UINT32>
0x00420838:	pushl %edi
0x00420839:	call GetProcAddress@KERNEL32.DLL
0x0042083b:	xorl %eax, 0x43e0d0
0x00420841:	pushl $0x4355dc<UINT32>
0x00420846:	pushl %edi
0x00420847:	movl 0x440a7c, %eax
0x0042084c:	call GetProcAddress@KERNEL32.DLL
0x0042084e:	xorl %eax, 0x43e0d0
0x00420854:	pushl $0x4355fc<UINT32>
0x00420859:	pushl %edi
0x0042085a:	movl 0x440a80, %eax
0x0042085f:	call GetProcAddress@KERNEL32.DLL
0x00420861:	xorl %eax, 0x43e0d0
0x00420867:	pushl $0x435618<UINT32>
0x0042086c:	pushl %edi
0x0042086d:	movl 0x440a84, %eax
0x00420872:	call GetProcAddress@KERNEL32.DLL
0x00420874:	xorl %eax, 0x43e0d0
0x0042087a:	pushl $0x435638<UINT32>
0x0042087f:	pushl %edi
0x00420880:	movl 0x440a88, %eax
0x00420885:	call GetProcAddress@KERNEL32.DLL
0x00420887:	xorl %eax, 0x43e0d0
0x0042088d:	pushl $0x43564c<UINT32>
0x00420892:	pushl %edi
0x00420893:	movl 0x440a8c, %eax
0x00420898:	call GetProcAddress@KERNEL32.DLL
0x0042089a:	xorl %eax, 0x43e0d0
0x004208a0:	pushl $0x435668<UINT32>
0x004208a5:	pushl %edi
0x004208a6:	movl 0x440a90, %eax
0x004208ab:	call GetProcAddress@KERNEL32.DLL
0x004208ad:	xorl %eax, 0x43e0d0
0x004208b3:	pushl $0x43567c<UINT32>
0x004208b8:	pushl %edi
0x004208b9:	movl 0x440a98, %eax
0x004208be:	call GetProcAddress@KERNEL32.DLL
0x004208c0:	xorl %eax, 0x43e0d0
0x004208c6:	pushl $0x43568c<UINT32>
0x004208cb:	pushl %edi
0x004208cc:	movl 0x440a94, %eax
0x004208d1:	call GetProcAddress@KERNEL32.DLL
0x004208d3:	xorl %eax, 0x43e0d0
0x004208d9:	pushl $0x43569c<UINT32>
0x004208de:	pushl %edi
0x004208df:	movl 0x440a9c, %eax
0x004208e4:	call GetProcAddress@KERNEL32.DLL
0x004208e6:	xorl %eax, 0x43e0d0
0x004208ec:	pushl $0x4356ac<UINT32>
0x004208f1:	pushl %edi
0x004208f2:	movl 0x440aa0, %eax
0x004208f7:	call GetProcAddress@KERNEL32.DLL
0x004208f9:	xorl %eax, 0x43e0d0
0x004208ff:	pushl $0x4356bc<UINT32>
0x00420904:	pushl %edi
0x00420905:	movl 0x440aa4, %eax
0x0042090a:	call GetProcAddress@KERNEL32.DLL
0x0042090c:	xorl %eax, 0x43e0d0
0x00420912:	pushl $0x4356d8<UINT32>
0x00420917:	pushl %edi
0x00420918:	movl 0x440aa8, %eax
0x0042091d:	call GetProcAddress@KERNEL32.DLL
0x0042091f:	xorl %eax, 0x43e0d0
0x00420925:	pushl $0x4356ec<UINT32>
0x0042092a:	pushl %edi
0x0042092b:	movl 0x440aac, %eax
0x00420930:	call GetProcAddress@KERNEL32.DLL
0x00420932:	xorl %eax, 0x43e0d0
0x00420938:	pushl $0x4356fc<UINT32>
0x0042093d:	pushl %edi
0x0042093e:	movl 0x440ab0, %eax
0x00420943:	call GetProcAddress@KERNEL32.DLL
0x00420945:	xorl %eax, 0x43e0d0
0x0042094b:	pushl $0x435710<UINT32>
0x00420950:	pushl %edi
0x00420951:	movl 0x440ab4, %eax
0x00420956:	call GetProcAddress@KERNEL32.DLL
0x00420958:	xorl %eax, 0x43e0d0
0x0042095e:	movl 0x440ab8, %eax
0x00420963:	pushl $0x435720<UINT32>
0x00420968:	pushl %edi
0x00420969:	call GetProcAddress@KERNEL32.DLL
0x0042096b:	xorl %eax, 0x43e0d0
0x00420971:	pushl $0x435740<UINT32>
0x00420976:	pushl %edi
0x00420977:	movl 0x440abc, %eax
0x0042097c:	call GetProcAddress@KERNEL32.DLL
0x0042097e:	xorl %eax, 0x43e0d0
0x00420984:	popl %edi
0x00420985:	movl 0x440ac0, %eax
0x0042098a:	popl %esi
0x0042098b:	ret

0x00420353:	call 0x004205a4
0x004205a4:	pushl %esi
0x004205a5:	pushl %edi
0x004205a6:	movl %esi, $0x43edc0<UINT32>
0x004205ab:	movl %edi, $0x43ffc0<UINT32>
0x004205b0:	cmpl 0x4(%esi), $0x1<UINT8>
0x004205b4:	jne 22
0x004205b6:	pushl $0x0<UINT8>
0x004205b8:	movl (%esi), %edi
0x004205ba:	addl %edi, $0x18<UINT8>
0x004205bd:	pushl $0xfa0<UINT32>
0x004205c2:	pushl (%esi)
0x004205c4:	call 0x00420693
0x00420693:	pushl %ebp
0x00420694:	movl %ebp, %esp
0x00420696:	movl %eax, 0x440a50
0x0042069b:	xorl %eax, 0x43e0d0
0x004206a1:	je 13
0x004206a3:	pushl 0x10(%ebp)
0x004206a6:	pushl 0xc(%ebp)
0x004206a9:	pushl 0x8(%ebp)
0x004206ac:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x004206ae:	popl %ebp
0x004206af:	ret

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
