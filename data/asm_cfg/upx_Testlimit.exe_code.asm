0x0043cba0:	pusha
0x0043cba1:	movl %esi, $0x428000<UINT32>
0x0043cba6:	leal %edi, -159744(%esi)
0x0043cbac:	pushl %edi
0x0043cbad:	jmp 0x0043cbba
0x0043cbba:	movl %ebx, (%esi)
0x0043cbbc:	subl %esi, $0xfffffffc<UINT8>
0x0043cbbf:	adcl %ebx, %ebx
0x0043cbc1:	jb 0x0043cbb0
0x0043cbb0:	movb %al, (%esi)
0x0043cbb2:	incl %esi
0x0043cbb3:	movb (%edi), %al
0x0043cbb5:	incl %edi
0x0043cbb6:	addl %ebx, %ebx
0x0043cbb8:	jne 0x0043cbc1
0x0043cbc3:	movl %eax, $0x1<UINT32>
0x0043cbc8:	addl %ebx, %ebx
0x0043cbca:	jne 0x0043cbd3
0x0043cbd3:	adcl %eax, %eax
0x0043cbd5:	addl %ebx, %ebx
0x0043cbd7:	jae 0x0043cbc8
0x0043cbd9:	jne 0x0043cbe4
0x0043cbe4:	xorl %ecx, %ecx
0x0043cbe6:	subl %eax, $0x3<UINT8>
0x0043cbe9:	jb 0x0043cbf8
0x0043cbeb:	shll %eax, $0x8<UINT8>
0x0043cbee:	movb %al, (%esi)
0x0043cbf0:	incl %esi
0x0043cbf1:	xorl %eax, $0xffffffff<UINT8>
0x0043cbf4:	je 0x0043cc6a
0x0043cbf6:	movl %ebp, %eax
0x0043cbf8:	addl %ebx, %ebx
0x0043cbfa:	jne 0x0043cc03
0x0043cc03:	adcl %ecx, %ecx
0x0043cc05:	addl %ebx, %ebx
0x0043cc07:	jne 0x0043cc10
0x0043cc10:	adcl %ecx, %ecx
0x0043cc12:	jne 0x0043cc34
0x0043cc34:	cmpl %ebp, $0xfffff300<UINT32>
0x0043cc3a:	adcl %ecx, $0x1<UINT8>
0x0043cc3d:	leal %edx, (%edi,%ebp)
0x0043cc40:	cmpl %ebp, $0xfffffffc<UINT8>
0x0043cc43:	jbe 0x0043cc54
0x0043cc54:	movl %eax, (%edx)
0x0043cc56:	addl %edx, $0x4<UINT8>
0x0043cc59:	movl (%edi), %eax
0x0043cc5b:	addl %edi, $0x4<UINT8>
0x0043cc5e:	subl %ecx, $0x4<UINT8>
0x0043cc61:	ja 0x0043cc54
0x0043cc63:	addl %edi, %ecx
0x0043cc65:	jmp 0x0043cbb6
0x0043cc09:	movl %ebx, (%esi)
0x0043cc0b:	subl %esi, $0xfffffffc<UINT8>
0x0043cc0e:	adcl %ebx, %ebx
0x0043cc45:	movb %al, (%edx)
0x0043cc47:	incl %edx
0x0043cc48:	movb (%edi), %al
0x0043cc4a:	incl %edi
0x0043cc4b:	decl %ecx
0x0043cc4c:	jne 0x0043cc45
0x0043cc4e:	jmp 0x0043cbb6
0x0043cbfc:	movl %ebx, (%esi)
0x0043cbfe:	subl %esi, $0xfffffffc<UINT8>
0x0043cc01:	adcl %ebx, %ebx
0x0043cc14:	incl %ecx
0x0043cc15:	addl %ebx, %ebx
0x0043cc17:	jne 0x0043cc20
0x0043cc20:	adcl %ecx, %ecx
0x0043cc22:	addl %ebx, %ebx
0x0043cc24:	jae 0x0043cc15
0x0043cc26:	jne 0x0043cc31
0x0043cc31:	addl %ecx, $0x2<UINT8>
0x0043cbcc:	movl %ebx, (%esi)
0x0043cbce:	subl %esi, $0xfffffffc<UINT8>
0x0043cbd1:	adcl %ebx, %ebx
0x0043cc28:	movl %ebx, (%esi)
0x0043cc2a:	subl %esi, $0xfffffffc<UINT8>
0x0043cc2d:	adcl %ebx, %ebx
0x0043cc2f:	jae 0x0043cc15
0x0043cc19:	movl %ebx, (%esi)
0x0043cc1b:	subl %esi, $0xfffffffc<UINT8>
0x0043cc1e:	adcl %ebx, %ebx
0x0043cbdb:	movl %ebx, (%esi)
0x0043cbdd:	subl %esi, $0xfffffffc<UINT8>
0x0043cbe0:	adcl %ebx, %ebx
0x0043cbe2:	jae 0x0043cbc8
0x0043cc6a:	popl %esi
0x0043cc6b:	movl %edi, %esi
0x0043cc6d:	movl %ecx, $0xbdb<UINT32>
0x0043cc72:	movb %al, (%edi)
0x0043cc74:	incl %edi
0x0043cc75:	subb %al, $0xffffffe8<UINT8>
0x0043cc77:	cmpb %al, $0x1<UINT8>
0x0043cc79:	ja 0x0043cc72
0x0043cc7b:	cmpb (%edi), $0xc<UINT8>
0x0043cc7e:	jne 0x0043cc72
0x0043cc80:	movl %eax, (%edi)
0x0043cc82:	movb %bl, 0x4(%edi)
0x0043cc85:	shrw %ax, $0x8<UINT8>
0x0043cc89:	roll %eax, $0x10<UINT8>
0x0043cc8c:	xchgb %ah, %al
0x0043cc8e:	subl %eax, %edi
0x0043cc90:	subb %bl, $0xffffffe8<UINT8>
0x0043cc93:	addl %eax, %esi
0x0043cc95:	movl (%edi), %eax
0x0043cc97:	addl %edi, $0x5<UINT8>
0x0043cc9a:	movb %al, %bl
0x0043cc9c:	loop 0x0043cc77
0x0043cc9e:	leal %edi, 0x39000(%esi)
0x0043cca4:	movl %eax, (%edi)
0x0043cca6:	orl %eax, %eax
0x0043cca8:	je 0x0043cce6
0x0043ccaa:	movl %ebx, 0x4(%edi)
0x0043ccad:	leal %eax, 0x3c550(%eax,%esi)
0x0043ccb4:	addl %ebx, %esi
0x0043ccb6:	pushl %eax
0x0043ccb7:	addl %edi, $0x8<UINT8>
0x0043ccba:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x0043ccc0:	xchgl %ebp, %eax
0x0043ccc1:	movb %al, (%edi)
0x0043ccc3:	incl %edi
0x0043ccc4:	orb %al, %al
0x0043ccc6:	je 0x0043cca4
0x0043ccc8:	movl %ecx, %edi
0x0043ccca:	pushl %edi
0x0043cccb:	decl %eax
0x0043cccc:	repn scasb %al, %es:(%edi)
0x0043ccce:	pushl %ebp
0x0043cccf:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0043ccd5:	orl %eax, %eax
0x0043ccd7:	je 7
0x0043ccd9:	movl (%ebx), %eax
0x0043ccdb:	addl %ebx, $0x4<UINT8>
0x0043ccde:	jmp 0x0043ccc1
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x0043cce6:	addl %edi, $0x4<UINT8>
0x0043cce9:	leal %ebx, -4(%esi)
0x0043ccec:	xorl %eax, %eax
0x0043ccee:	movb %al, (%edi)
0x0043ccf0:	incl %edi
0x0043ccf1:	orl %eax, %eax
0x0043ccf3:	je 0x0043cd17
0x0043ccf5:	cmpb %al, $0xffffffef<UINT8>
0x0043ccf7:	ja 0x0043cd0a
0x0043ccf9:	addl %ebx, %eax
0x0043ccfb:	movl %eax, (%ebx)
0x0043ccfd:	xchgb %ah, %al
0x0043ccff:	roll %eax, $0x10<UINT8>
0x0043cd02:	xchgb %ah, %al
0x0043cd04:	addl %eax, %esi
0x0043cd06:	movl (%ebx), %eax
0x0043cd08:	jmp 0x0043ccec
0x0043cd0a:	andb %al, $0xf<UINT8>
0x0043cd0c:	shll %eax, $0x10<UINT8>
0x0043cd0f:	movw %ax, (%edi)
0x0043cd12:	addl %edi, $0x2<UINT8>
0x0043cd15:	jmp 0x0043ccf9
0x0043cd17:	movl %ebp, 0x3c5ec(%esi)
0x0043cd1d:	leal %edi, -4096(%esi)
0x0043cd23:	movl %ebx, $0x1000<UINT32>
0x0043cd28:	pushl %eax
0x0043cd29:	pushl %esp
0x0043cd2a:	pushl $0x4<UINT8>
0x0043cd2c:	pushl %ebx
0x0043cd2d:	pushl %edi
0x0043cd2e:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0043cd30:	leal %eax, 0x207(%edi)
0x0043cd36:	andb (%eax), $0x7f<UINT8>
0x0043cd39:	andb 0x28(%eax), $0x7f<UINT8>
0x0043cd3d:	popl %eax
0x0043cd3e:	pushl %eax
0x0043cd3f:	pushl %esp
0x0043cd40:	pushl %eax
0x0043cd41:	pushl %ebx
0x0043cd42:	pushl %edi
0x0043cd43:	call VirtualProtect@kernel32.dll
0x0043cd45:	popl %eax
0x0043cd46:	popa
0x0043cd47:	leal %eax, -128(%esp)
0x0043cd4b:	pushl $0x0<UINT8>
0x0043cd4d:	cmpl %esp, %eax
0x0043cd4f:	jne 0x0043cd4b
0x0043cd51:	subl %esp, $0xffffff80<UINT8>
0x0043cd54:	jmp 0x0040561e
0x0040561e:	call 0x0040faa7
0x0040faa7:	pushl %ebp
0x0040faa8:	movl %ebp, %esp
0x0040faaa:	subl %esp, $0x14<UINT8>
0x0040faad:	andl -12(%ebp), $0x0<UINT8>
0x0040fab1:	andl -8(%ebp), $0x0<UINT8>
0x0040fab5:	movl %eax, 0x4330d0
0x0040faba:	pushl %esi
0x0040fabb:	pushl %edi
0x0040fabc:	movl %edi, $0xbb40e64e<UINT32>
0x0040fac1:	movl %esi, $0xffff0000<UINT32>
0x0040fac6:	cmpl %eax, %edi
0x0040fac8:	je 0x0040fad7
0x0040fad7:	leal %eax, -12(%ebp)
0x0040fada:	pushl %eax
0x0040fadb:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040fae1:	movl %eax, -8(%ebp)
0x0040fae4:	xorl %eax, -12(%ebp)
0x0040fae7:	movl -4(%ebp), %eax
0x0040faea:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040faf0:	xorl -4(%ebp), %eax
0x0040faf3:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040faf9:	xorl -4(%ebp), %eax
0x0040fafc:	leal %eax, -20(%ebp)
0x0040faff:	pushl %eax
0x0040fb00:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040fb06:	movl %ecx, -16(%ebp)
0x0040fb09:	leal %eax, -4(%ebp)
0x0040fb0c:	xorl %ecx, -20(%ebp)
0x0040fb0f:	xorl %ecx, -4(%ebp)
0x0040fb12:	xorl %ecx, %eax
0x0040fb14:	cmpl %ecx, %edi
0x0040fb16:	jne 0x0040fb1f
0x0040fb1f:	testl %esi, %ecx
0x0040fb21:	jne 0x0040fb2f
0x0040fb2f:	movl 0x4330d0, %ecx
0x0040fb35:	notl %ecx
0x0040fb37:	movl 0x4330d4, %ecx
0x0040fb3d:	popl %edi
0x0040fb3e:	popl %esi
0x0040fb3f:	movl %esp, %ebp
0x0040fb41:	popl %ebp
0x0040fb42:	ret

0x00405623:	jmp 0x0040545d
0x0040545d:	pushl $0x14<UINT8>
0x0040545f:	pushl $0x4313e8<UINT32>
0x00405464:	call 0x00409190
0x00409190:	pushl $0x409230<UINT32>
0x00409195:	pushl %fs:0
0x0040919c:	movl %eax, 0x10(%esp)
0x004091a0:	movl 0x10(%esp), %ebp
0x004091a4:	leal %ebp, 0x10(%esp)
0x004091a8:	subl %esp, %eax
0x004091aa:	pushl %ebx
0x004091ab:	pushl %esi
0x004091ac:	pushl %edi
0x004091ad:	movl %eax, 0x4330d0
0x004091b2:	xorl -4(%ebp), %eax
0x004091b5:	xorl %eax, %ebp
0x004091b7:	pushl %eax
0x004091b8:	movl -24(%ebp), %esp
0x004091bb:	pushl -8(%ebp)
0x004091be:	movl %eax, -4(%ebp)
0x004091c1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004091c8:	movl -8(%ebp), %eax
0x004091cb:	leal %eax, -16(%ebp)
0x004091ce:	movl %fs:0, %eax
0x004091d4:	ret

0x00405469:	pushl $0x1<UINT8>
0x0040546b:	call 0x0040fa5a
0x0040fa5a:	pushl %ebp
0x0040fa5b:	movl %ebp, %esp
0x0040fa5d:	movl %eax, 0x8(%ebp)
0x0040fa60:	movl 0x434460, %eax
0x0040fa65:	popl %ebp
0x0040fa66:	ret

0x00405470:	popl %ecx
0x00405471:	movl %eax, $0x5a4d<UINT32>
0x00405476:	cmpw 0x400000, %ax
0x0040547d:	je 0x00405483
0x00405483:	movl %eax, 0x40003c
0x00405488:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00405492:	jne -21
0x00405494:	movl %ecx, $0x10b<UINT32>
0x00405499:	cmpw 0x400018(%eax), %cx
0x004054a0:	jne -35
0x004054a2:	xorl %ebx, %ebx
0x004054a4:	cmpl 0x400074(%eax), $0xe<UINT8>
0x004054ab:	jbe 9
0x004054ad:	cmpl 0x4000e8(%eax), %ebx
0x004054b3:	setne %bl
0x004054b6:	movl -28(%ebp), %ebx
0x004054b9:	call 0x004094a1
0x004094a1:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x004094a7:	xorl %ecx, %ecx
0x004094a9:	movl 0x434ac0, %eax
0x004094ae:	testl %eax, %eax
0x004094b0:	setne %cl
0x004094b3:	movl %eax, %ecx
0x004094b5:	ret

0x004054be:	testl %eax, %eax
0x004054c0:	jne 0x004054ca
0x004054ca:	call 0x0040661e
0x0040661e:	call 0x00403947
0x00403947:	pushl %esi
0x00403948:	pushl $0x0<UINT8>
0x0040394a:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00403950:	movl %esi, %eax
0x00403952:	pushl %esi
0x00403953:	call 0x0040894f
0x0040894f:	pushl %ebp
0x00408950:	movl %ebp, %esp
0x00408952:	movl %eax, 0x8(%ebp)
0x00408955:	movl 0x434a98, %eax
0x0040895a:	popl %ebp
0x0040895b:	ret

0x00403958:	pushl %esi
0x00403959:	call 0x00405777
0x00405777:	pushl %ebp
0x00405778:	movl %ebp, %esp
0x0040577a:	movl %eax, 0x8(%ebp)
0x0040577d:	movl 0x4342e8, %eax
0x00405782:	popl %ebp
0x00405783:	ret

0x0040395e:	pushl %esi
0x0040395f:	call 0x00408b35
0x00408b35:	pushl %ebp
0x00408b36:	movl %ebp, %esp
0x00408b38:	movl %eax, 0x8(%ebp)
0x00408b3b:	movl 0x434a9c, %eax
0x00408b40:	popl %ebp
0x00408b41:	ret

0x00403964:	pushl %esi
0x00403965:	call 0x00408b61
0x00408b61:	pushl %ebp
0x00408b62:	movl %ebp, %esp
0x00408b64:	movl %eax, 0x8(%ebp)
0x00408b67:	movl 0x434aa0, %eax
0x00408b6c:	movl 0x434aa4, %eax
0x00408b71:	movl 0x434aa8, %eax
0x00408b76:	movl 0x434aac, %eax
0x00408b7b:	popl %ebp
0x00408b7c:	ret

0x0040396a:	pushl %esi
0x0040396b:	call 0x004088cd
0x004088cd:	pushl $0x408886<UINT32>
0x004088d2:	call EncodePointer@KERNEL32.DLL
0x004088d8:	movl 0x434a94, %eax
0x004088dd:	ret

0x00403970:	pushl %esi
0x00403971:	call 0x00409071
0x00409071:	pushl %ebp
0x00409072:	movl %ebp, %esp
0x00409074:	movl %eax, 0x8(%ebp)
0x00409077:	movl 0x434ab4, %eax
0x0040907c:	popl %ebp
0x0040907d:	ret

0x00403976:	addl %esp, $0x18<UINT8>
0x00403979:	popl %esi
0x0040397a:	jmp 0x00407ebb
0x00407ebb:	pushl %esi
0x00407ebc:	pushl %edi
0x00407ebd:	pushl $0x42cbdc<UINT32>
0x00407ec2:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00407ec8:	movl %esi, 0x4250e4
0x00407ece:	movl %edi, %eax
0x00407ed0:	pushl $0x42cbf8<UINT32>
0x00407ed5:	pushl %edi
0x00407ed6:	call GetProcAddress@KERNEL32.DLL
0x00407ed8:	xorl %eax, 0x4330d0
0x00407ede:	pushl $0x42cc04<UINT32>
0x00407ee3:	pushl %edi
0x00407ee4:	movl 0x435040, %eax
0x00407ee9:	call GetProcAddress@KERNEL32.DLL
0x00407eeb:	xorl %eax, 0x4330d0
0x00407ef1:	pushl $0x42cc0c<UINT32>
0x00407ef6:	pushl %edi
0x00407ef7:	movl 0x435044, %eax
0x00407efc:	call GetProcAddress@KERNEL32.DLL
0x00407efe:	xorl %eax, 0x4330d0
0x00407f04:	pushl $0x42cc18<UINT32>
0x00407f09:	pushl %edi
0x00407f0a:	movl 0x435048, %eax
0x00407f0f:	call GetProcAddress@KERNEL32.DLL
0x00407f11:	xorl %eax, 0x4330d0
0x00407f17:	pushl $0x42cc24<UINT32>
0x00407f1c:	pushl %edi
0x00407f1d:	movl 0x43504c, %eax
0x00407f22:	call GetProcAddress@KERNEL32.DLL
0x00407f24:	xorl %eax, 0x4330d0
0x00407f2a:	pushl $0x42cc40<UINT32>
0x00407f2f:	pushl %edi
0x00407f30:	movl 0x435050, %eax
0x00407f35:	call GetProcAddress@KERNEL32.DLL
0x00407f37:	xorl %eax, 0x4330d0
0x00407f3d:	pushl $0x42cc50<UINT32>
0x00407f42:	pushl %edi
0x00407f43:	movl 0x435054, %eax
0x00407f48:	call GetProcAddress@KERNEL32.DLL
0x00407f4a:	xorl %eax, 0x4330d0
0x00407f50:	pushl $0x42cc64<UINT32>
0x00407f55:	pushl %edi
0x00407f56:	movl 0x435058, %eax
0x00407f5b:	call GetProcAddress@KERNEL32.DLL
0x00407f5d:	xorl %eax, 0x4330d0
0x00407f63:	pushl $0x42cc7c<UINT32>
0x00407f68:	pushl %edi
0x00407f69:	movl 0x43505c, %eax
0x00407f6e:	call GetProcAddress@KERNEL32.DLL
0x00407f70:	xorl %eax, 0x4330d0
0x00407f76:	pushl $0x42cc94<UINT32>
0x00407f7b:	pushl %edi
0x00407f7c:	movl 0x435060, %eax
0x00407f81:	call GetProcAddress@KERNEL32.DLL
0x00407f83:	xorl %eax, 0x4330d0
0x00407f89:	pushl $0x42cca8<UINT32>
0x00407f8e:	pushl %edi
0x00407f8f:	movl 0x435064, %eax
0x00407f94:	call GetProcAddress@KERNEL32.DLL
0x00407f96:	xorl %eax, 0x4330d0
0x00407f9c:	pushl $0x42ccc8<UINT32>
0x00407fa1:	pushl %edi
0x00407fa2:	movl 0x435068, %eax
0x00407fa7:	call GetProcAddress@KERNEL32.DLL
0x00407fa9:	xorl %eax, 0x4330d0
0x00407faf:	pushl $0x42cce0<UINT32>
0x00407fb4:	pushl %edi
0x00407fb5:	movl 0x43506c, %eax
0x00407fba:	call GetProcAddress@KERNEL32.DLL
0x00407fbc:	xorl %eax, 0x4330d0
0x00407fc2:	pushl $0x42ccf8<UINT32>
0x00407fc7:	pushl %edi
0x00407fc8:	movl 0x435070, %eax
0x00407fcd:	call GetProcAddress@KERNEL32.DLL
0x00407fcf:	xorl %eax, 0x4330d0
0x00407fd5:	pushl $0x42cd0c<UINT32>
0x00407fda:	pushl %edi
0x00407fdb:	movl 0x435074, %eax
0x00407fe0:	call GetProcAddress@KERNEL32.DLL
0x00407fe2:	xorl %eax, 0x4330d0
0x00407fe8:	movl 0x435078, %eax
0x00407fed:	pushl $0x42cd20<UINT32>
0x00407ff2:	pushl %edi
0x00407ff3:	call GetProcAddress@KERNEL32.DLL
0x00407ff5:	xorl %eax, 0x4330d0
0x00407ffb:	pushl $0x42cd3c<UINT32>
0x00408000:	pushl %edi
0x00408001:	movl 0x43507c, %eax
0x00408006:	call GetProcAddress@KERNEL32.DLL
0x00408008:	xorl %eax, 0x4330d0
0x0040800e:	pushl $0x42cd5c<UINT32>
0x00408013:	pushl %edi
0x00408014:	movl 0x435080, %eax
0x00408019:	call GetProcAddress@KERNEL32.DLL
0x0040801b:	xorl %eax, 0x4330d0
0x00408021:	pushl $0x42cd78<UINT32>
0x00408026:	pushl %edi
0x00408027:	movl 0x435084, %eax
0x0040802c:	call GetProcAddress@KERNEL32.DLL
0x0040802e:	xorl %eax, 0x4330d0
0x00408034:	pushl $0x42cd98<UINT32>
0x00408039:	pushl %edi
0x0040803a:	movl 0x435088, %eax
0x0040803f:	call GetProcAddress@KERNEL32.DLL
0x00408041:	xorl %eax, 0x4330d0
0x00408047:	pushl $0x42cdac<UINT32>
0x0040804c:	pushl %edi
0x0040804d:	movl 0x43508c, %eax
0x00408052:	call GetProcAddress@KERNEL32.DLL
0x00408054:	xorl %eax, 0x4330d0
0x0040805a:	pushl $0x42cdc8<UINT32>
0x0040805f:	pushl %edi
0x00408060:	movl 0x435090, %eax
0x00408065:	call GetProcAddress@KERNEL32.DLL
0x00408067:	xorl %eax, 0x4330d0
0x0040806d:	pushl $0x42cddc<UINT32>
0x00408072:	pushl %edi
0x00408073:	movl 0x435098, %eax
0x00408078:	call GetProcAddress@KERNEL32.DLL
0x0040807a:	xorl %eax, 0x4330d0
0x00408080:	pushl $0x42cdec<UINT32>
0x00408085:	pushl %edi
0x00408086:	movl 0x435094, %eax
0x0040808b:	call GetProcAddress@KERNEL32.DLL
0x0040808d:	xorl %eax, 0x4330d0
0x00408093:	pushl $0x42cdfc<UINT32>
0x00408098:	pushl %edi
0x00408099:	movl 0x43509c, %eax
0x0040809e:	call GetProcAddress@KERNEL32.DLL
0x004080a0:	xorl %eax, 0x4330d0
0x004080a6:	pushl $0x42ce0c<UINT32>
0x004080ab:	pushl %edi
0x004080ac:	movl 0x4350a0, %eax
0x004080b1:	call GetProcAddress@KERNEL32.DLL
0x004080b3:	xorl %eax, 0x4330d0
0x004080b9:	pushl $0x42ce1c<UINT32>
0x004080be:	pushl %edi
0x004080bf:	movl 0x4350a4, %eax
0x004080c4:	call GetProcAddress@KERNEL32.DLL
0x004080c6:	xorl %eax, 0x4330d0
0x004080cc:	pushl $0x42ce38<UINT32>
0x004080d1:	pushl %edi
0x004080d2:	movl 0x4350a8, %eax
0x004080d7:	call GetProcAddress@KERNEL32.DLL
0x004080d9:	xorl %eax, 0x4330d0
0x004080df:	pushl $0x42ce4c<UINT32>
0x004080e4:	pushl %edi
0x004080e5:	movl 0x4350ac, %eax
0x004080ea:	call GetProcAddress@KERNEL32.DLL
0x004080ec:	xorl %eax, 0x4330d0
0x004080f2:	pushl $0x42ce5c<UINT32>
0x004080f7:	pushl %edi
0x004080f8:	movl 0x4350b0, %eax
0x004080fd:	call GetProcAddress@KERNEL32.DLL
0x004080ff:	xorl %eax, 0x4330d0
0x00408105:	pushl $0x42ce70<UINT32>
0x0040810a:	pushl %edi
0x0040810b:	movl 0x4350b4, %eax
0x00408110:	call GetProcAddress@KERNEL32.DLL
0x00408112:	xorl %eax, 0x4330d0
0x00408118:	movl 0x4350b8, %eax
0x0040811d:	pushl $0x42ce80<UINT32>
0x00408122:	pushl %edi
0x00408123:	call GetProcAddress@KERNEL32.DLL
0x00408125:	xorl %eax, 0x4330d0
0x0040812b:	pushl $0x42cea0<UINT32>
0x00408130:	pushl %edi
0x00408131:	movl 0x4350bc, %eax
0x00408136:	call GetProcAddress@KERNEL32.DLL
0x00408138:	xorl %eax, 0x4330d0
0x0040813e:	popl %edi
0x0040813f:	movl 0x4350c0, %eax
0x00408144:	popl %esi
0x00408145:	ret

0x00406623:	call 0x00407b7d
0x00407b7d:	pushl %esi
0x00407b7e:	pushl %edi
0x00407b7f:	movl %esi, $0x433c30<UINT32>
0x00407b84:	movl %edi, $0x434310<UINT32>
0x00407b89:	cmpl 0x4(%esi), $0x1<UINT8>
0x00407b8d:	jne 22
0x00407b8f:	pushl $0x0<UINT8>
0x00407b91:	movl (%esi), %edi
0x00407b93:	addl %edi, $0x18<UINT8>
0x00407b96:	pushl $0xfa0<UINT32>
0x00407b9b:	pushl (%esi)
0x00407b9d:	call 0x00407e4d
0x00407e4d:	pushl %ebp
0x00407e4e:	movl %ebp, %esp
0x00407e50:	movl %eax, 0x435050
0x00407e55:	xorl %eax, 0x4330d0
0x00407e5b:	je 13
0x00407e5d:	pushl 0x10(%ebp)
0x00407e60:	pushl 0xc(%ebp)
0x00407e63:	pushl 0x8(%ebp)
0x00407e66:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x00407e68:	popl %ebp
0x00407e69:	ret

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
