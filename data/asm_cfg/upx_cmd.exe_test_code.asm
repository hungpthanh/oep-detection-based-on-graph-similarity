0x4ad4ee70:	pusha
0x4ad4ee71:	movl %esi, $0x4ad3c000<UINT32>
0x4ad4ee76:	leal %edi, -241664(%esi)
0x4ad4ee7c:	pushl %edi
0x4ad4ee7d:	jmp 0x4ad4ee8a
0x4ad4ee8a:	movl %ebx, (%esi)
0x4ad4ee8c:	subl %esi, $0xfffffffc<UINT8>
0x4ad4ee8f:	adcl %ebx, %ebx
0x4ad4ee91:	jb 0x4ad4ee80
0x4ad4ee80:	movb %al, (%esi)
0x4ad4ee82:	incl %esi
0x4ad4ee83:	movb (%edi), %al
0x4ad4ee85:	incl %edi
0x4ad4ee86:	addl %ebx, %ebx
0x4ad4ee88:	jne 0x4ad4ee91
0x4ad4ee93:	movl %eax, $0x1<UINT32>
0x4ad4ee98:	addl %ebx, %ebx
0x4ad4ee9a:	jne 0x4ad4eea3
0x4ad4eea3:	adcl %eax, %eax
0x4ad4eea5:	addl %ebx, %ebx
0x4ad4eea7:	jae 0x4ad4eeb4
0x4ad4eea9:	jne 0x4ad4eed3
0x4ad4eed3:	xorl %ecx, %ecx
0x4ad4eed5:	subl %eax, $0x3<UINT8>
0x4ad4eed8:	jb 0x4ad4eeeb
0x4ad4eeda:	shll %eax, $0x8<UINT8>
0x4ad4eedd:	movb %al, (%esi)
0x4ad4eedf:	incl %esi
0x4ad4eee0:	xorl %eax, $0xffffffff<UINT8>
0x4ad4eee3:	je 0x4ad4ef5a
0x4ad4eee5:	sarl %eax
0x4ad4eee7:	movl %ebp, %eax
0x4ad4eee9:	jmp 0x4ad4eef6
0x4ad4eef6:	jb 0x4ad4eec4
0x4ad4eec4:	addl %ebx, %ebx
0x4ad4eec6:	jne 0x4ad4eecf
0x4ad4eecf:	adcl %ecx, %ecx
0x4ad4eed1:	jmp 0x4ad4ef25
0x4ad4ef25:	cmpl %ebp, $0xfffffb00<UINT32>
0x4ad4ef2b:	adcl %ecx, $0x2<UINT8>
0x4ad4ef2e:	leal %edx, (%edi,%ebp)
0x4ad4ef31:	cmpl %ebp, $0xfffffffc<UINT8>
0x4ad4ef34:	jbe 0x4ad4ef44
0x4ad4ef44:	movl %eax, (%edx)
0x4ad4ef46:	addl %edx, $0x4<UINT8>
0x4ad4ef49:	movl (%edi), %eax
0x4ad4ef4b:	addl %edi, $0x4<UINT8>
0x4ad4ef4e:	subl %ecx, $0x4<UINT8>
0x4ad4ef51:	ja 0x4ad4ef44
0x4ad4ef53:	addl %edi, %ecx
0x4ad4ef55:	jmp 0x4ad4ee86
0x4ad4eeeb:	addl %ebx, %ebx
0x4ad4eeed:	jne 0x4ad4eef6
0x4ad4eec8:	movl %ebx, (%esi)
0x4ad4eeca:	subl %esi, $0xfffffffc<UINT8>
0x4ad4eecd:	adcl %ebx, %ebx
0x4ad4eeab:	movl %ebx, (%esi)
0x4ad4eead:	subl %esi, $0xfffffffc<UINT8>
0x4ad4eeb0:	adcl %ebx, %ebx
0x4ad4eeb2:	jb 0x4ad4eed3
0x4ad4eeef:	movl %ebx, (%esi)
0x4ad4eef1:	subl %esi, $0xfffffffc<UINT8>
0x4ad4eef4:	adcl %ebx, %ebx
0x4ad4ee9c:	movl %ebx, (%esi)
0x4ad4ee9e:	subl %esi, $0xfffffffc<UINT8>
0x4ad4eea1:	adcl %ebx, %ebx
0x4ad4eef8:	incl %ecx
0x4ad4eef9:	addl %ebx, %ebx
0x4ad4eefb:	jne 0x4ad4ef04
0x4ad4ef04:	jb 0x4ad4eec4
0x4ad4ef36:	movb %al, (%edx)
0x4ad4ef38:	incl %edx
0x4ad4ef39:	movb (%edi), %al
0x4ad4ef3b:	incl %edi
0x4ad4ef3c:	decl %ecx
0x4ad4ef3d:	jne 0x4ad4ef36
0x4ad4ef3f:	jmp 0x4ad4ee86
0x4ad4ef06:	addl %ebx, %ebx
0x4ad4ef08:	jne 0x4ad4ef11
0x4ad4ef11:	adcl %ecx, %ecx
0x4ad4ef13:	addl %ebx, %ebx
0x4ad4ef15:	jae 0x4ad4ef06
0x4ad4ef17:	jne 0x4ad4ef22
0x4ad4ef22:	addl %ecx, $0x2<UINT8>
0x4ad4eeb4:	decl %eax
0x4ad4eeb5:	addl %ebx, %ebx
0x4ad4eeb7:	jne 0x4ad4eec0
0x4ad4eec0:	adcl %eax, %eax
0x4ad4eec2:	jmp 0x4ad4ee98
0x4ad4eefd:	movl %ebx, (%esi)
0x4ad4eeff:	subl %esi, $0xfffffffc<UINT8>
0x4ad4ef02:	adcl %ebx, %ebx
0x4ad4ef19:	movl %ebx, (%esi)
0x4ad4ef1b:	subl %esi, $0xfffffffc<UINT8>
0x4ad4ef1e:	adcl %ebx, %ebx
0x4ad4ef20:	jae 0x4ad4ef06
0x4ad4eeb9:	movl %ebx, (%esi)
0x4ad4eebb:	subl %esi, $0xfffffffc<UINT8>
0x4ad4eebe:	adcl %ebx, %ebx
0x4ad4ef0a:	movl %ebx, (%esi)
0x4ad4ef0c:	subl %esi, $0xfffffffc<UINT8>
0x4ad4ef0f:	adcl %ebx, %ebx
0x4ad4ef5a:	popl %esi
0x4ad4ef5b:	movl %edi, %esi
0x4ad4ef5d:	movl %ecx, $0xf3c<UINT32>
0x4ad4ef62:	movb %al, (%edi)
0x4ad4ef64:	incl %edi
0x4ad4ef65:	subb %al, $0xffffffe8<UINT8>
0x4ad4ef67:	cmpb %al, $0x1<UINT8>
0x4ad4ef69:	ja 0x4ad4ef62
0x4ad4ef6b:	cmpb (%edi), $0xb<UINT8>
0x4ad4ef6e:	jne 0x4ad4ef62
0x4ad4ef70:	movl %eax, (%edi)
0x4ad4ef72:	movb %bl, 0x4(%edi)
0x4ad4ef75:	shrw %ax, $0x8<UINT8>
0x4ad4ef79:	roll %eax, $0x10<UINT8>
0x4ad4ef7c:	xchgb %ah, %al
0x4ad4ef7e:	subl %eax, %edi
0x4ad4ef80:	subb %bl, $0xffffffe8<UINT8>
0x4ad4ef83:	addl %eax, %esi
0x4ad4ef85:	movl (%edi), %eax
0x4ad4ef87:	addl %edi, $0x5<UINT8>
0x4ad4ef8a:	movb %al, %bl
0x4ad4ef8c:	loop 0x4ad4ef67
0x4ad4ef8e:	leal %edi, 0x4b000(%esi)
0x4ad4ef94:	movl %eax, (%edi)
0x4ad4ef96:	orl %eax, %eax
0x4ad4ef98:	je 0x4ad4efd6
0x4ad4ef9a:	movl %ebx, 0x4(%edi)
0x4ad4ef9d:	leal %eax, 0x573a0(%eax,%esi)
0x4ad4efa4:	addl %ebx, %esi
0x4ad4efa6:	pushl %eax
0x4ad4efa7:	addl %edi, $0x8<UINT8>
0x4ad4efaa:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x4ad4efb0:	xchgl %ebp, %eax
0x4ad4efb1:	movb %al, (%edi)
0x4ad4efb3:	incl %edi
0x4ad4efb4:	orb %al, %al
0x4ad4efb6:	je 0x4ad4ef94
0x4ad4efb8:	movl %ecx, %edi
0x4ad4efba:	pushl %edi
0x4ad4efbb:	decl %eax
0x4ad4efbc:	repn scasb %al, %es:(%edi)
0x4ad4efbe:	pushl %ebp
0x4ad4efbf:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x4ad4efc5:	orl %eax, %eax
0x4ad4efc7:	je 7
0x4ad4efc9:	movl (%ebx), %eax
0x4ad4efcb:	addl %ebx, $0x4<UINT8>
0x4ad4efce:	jmp 0x4ad4efb1
GetProcAddress@KERNEL32.DLL: API Node	
0x4ad4efd6:	addl %edi, $0x4<UINT8>
0x4ad4efd9:	leal %ebx, -4(%esi)
0x4ad4efdc:	xorl %eax, %eax
0x4ad4efde:	movb %al, (%edi)
0x4ad4efe0:	incl %edi
0x4ad4efe1:	orl %eax, %eax
0x4ad4efe3:	je 0x4ad4f007
0x4ad4efe5:	cmpb %al, $0xffffffef<UINT8>
0x4ad4efe7:	ja 0x4ad4effa
0x4ad4effa:	andb %al, $0xf<UINT8>
0x4ad4effc:	shll %eax, $0x10<UINT8>
0x4ad4efff:	movw %ax, (%edi)
0x4ad4f002:	addl %edi, $0x2<UINT8>
0x4ad4f005:	jmp 0x4ad4efe9
0x4ad4efe9:	addl %ebx, %eax
0x4ad4efeb:	movl %eax, (%ebx)
0x4ad4efed:	xchgb %ah, %al
0x4ad4efef:	roll %eax, $0x10<UINT8>
0x4ad4eff2:	xchgb %ah, %al
0x4ad4eff4:	addl %eax, %esi
0x4ad4eff6:	movl (%ebx), %eax
0x4ad4eff8:	jmp 0x4ad4efdc
0x4ad4f007:	movl %ebp, 0x57410(%esi)
0x4ad4f00d:	leal %edi, -4096(%esi)
0x4ad4f013:	movl %ebx, $0x1000<UINT32>
0x4ad4f018:	pushl %eax
0x4ad4f019:	pushl %esp
0x4ad4f01a:	pushl $0x4<UINT8>
0x4ad4f01c:	pushl %ebx
0x4ad4f01d:	pushl %edi
0x4ad4f01e:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x4ad4f020:	leal %eax, 0x207(%edi)
0x4ad4f026:	andb (%eax), $0x7f<UINT8>
0x4ad4f029:	andb 0x28(%eax), $0x7f<UINT8>
0x4ad4f02d:	popl %eax
0x4ad4f02e:	pushl %eax
0x4ad4f02f:	pushl %esp
0x4ad4f030:	pushl %eax
0x4ad4f031:	pushl %ebx
0x4ad4f032:	pushl %edi
0x4ad4f033:	call VirtualProtect@kernel32.dll
0x4ad4f035:	popl %eax
0x4ad4f036:	popa
0x4ad4f037:	leal %eax, -128(%esp)
0x4ad4f03b:	pushl $0x0<UINT8>
0x4ad4f03d:	cmpl %esp, %eax
0x4ad4f03f:	jne 0x4ad4f03b
0x4ad4f041:	subl %esp, $0xffffff80<UINT8>
0x4ad4f044:	jmp 0x4ad0829a
0x4ad0829a:	call 0x4ad07c89
0x4ad07c89:	movl %edi, %edi
0x4ad07c8b:	pushl %ebp
0x4ad07c8c:	movl %ebp, %esp
0x4ad07c8e:	subl %esp, $0x10<UINT8>
0x4ad07c91:	movl %eax, 0x4ad240ac
0x4ad07c96:	andl -8(%ebp), $0x0<UINT8>
0x4ad07c9a:	andl -4(%ebp), $0x0<UINT8>
0x4ad07c9e:	pushl %ebx
0x4ad07c9f:	pushl %edi
0x4ad07ca0:	movl %edi, $0xbb40e64e<UINT32>
0x4ad07ca5:	movl %ebx, $0xffff0000<UINT32>
0x4ad07caa:	cmpl %eax, %edi
0x4ad07cac:	jne 81882
0x4ad07cb2:	pushl %esi
0x4ad07cb3:	leal %eax, -8(%ebp)
0x4ad07cb6:	pushl %eax
0x4ad07cb7:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x4ad07cbd:	movl %esi, -4(%ebp)
0x4ad07cc0:	xorl %esi, -8(%ebp)
0x4ad07cc3:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x4ad07cc9:	xorl %esi, %eax
0x4ad07ccb:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x4ad07cd1:	xorl %esi, %eax
0x4ad07cd3:	call GetTickCount@KERNEL32.DLL
GetTickCount@KERNEL32.DLL: API Node	
0x4ad07cd9:	xorl %esi, %eax
0x4ad07cdb:	leal %eax, -16(%ebp)
0x4ad07cde:	pushl %eax
0x4ad07cdf:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x4ad07ce5:	movl %eax, -12(%ebp)
0x4ad07ce8:	xorl %eax, -16(%ebp)
0x4ad07ceb:	xorl %esi, %eax
0x4ad07ced:	cmpl %esi, %edi
0x4ad07cef:	je 27
0x4ad07cf1:	testl 0x4ad240ac, %ebx
0x4ad07cf7:	je 19
0x4ad07cf9:	movl 0x4ad240ac, %esi
0x4ad07cff:	notl %esi
0x4ad07d01:	movl 0x4ad240b0, %esi
0x4ad07d07:	popl %esi
0x4ad07d08:	popl %edi
0x4ad07d09:	popl %ebx
0x4ad07d0a:	leave
0x4ad07d0b:	ret

0x4ad0829f:	pushl $0x10<UINT8>
0x4ad082a1:	pushl $0x4ad08388<UINT32>
0x4ad082a6:	call 0x4ad0264a
0x4ad0264a:	pushl $0x4ad22171<UINT32>
0x4ad0264f:	pushl %fs:0
0x4ad02656:	movl %eax, 0x10(%esp)
0x4ad0265a:	movl 0x10(%esp), %ebp
0x4ad0265e:	leal %ebp, 0x10(%esp)
0x4ad02662:	subl %esp, %eax
0x4ad02664:	pushl %ebx
0x4ad02665:	pushl %esi
0x4ad02666:	pushl %edi
0x4ad02667:	movl %eax, 0x4ad240ac
0x4ad0266c:	xorl -4(%ebp), %eax
0x4ad0266f:	xorl %eax, %ebp
0x4ad02671:	pushl %eax
0x4ad02672:	movl -24(%ebp), %esp
0x4ad02675:	pushl -8(%ebp)
0x4ad02678:	movl %eax, -4(%ebp)
0x4ad0267b:	movl -4(%ebp), $0xfffffffe<UINT32>
0x4ad02682:	movl -8(%ebp), %eax
0x4ad02685:	leal %eax, -16(%ebp)
0x4ad02688:	movl %fs:0, %eax
0x4ad0268e:	ret

0x4ad082ab:	xorl %ebx, %ebx
0x4ad082ad:	movl -4(%ebp), %ebx
0x4ad082b0:	movl %eax, %fs:0x18
0x4ad082b6:	movl %esi, 0x4(%eax)
0x4ad082b9:	movl -28(%ebp), %ebx
0x4ad082bc:	movl %edi, $0x4ad24204<UINT32>
0x4ad082c1:	pushl %ebx
0x4ad082c2:	pushl %esi
0x4ad082c3:	pushl %edi
0x4ad082c4:	call InterlockedCompareExchange@KERNEL32.DLL
InterlockedCompareExchange@KERNEL32.DLL: API Node	
0x4ad082ca:	cmpl %eax, %ebx
0x4ad082cc:	jne 0x4ad083a4
0x4ad083a4:	cmpl %eax, %esi
0x4ad083a6:	jne 0x4ad083b3
0x4ad083b3:	pushl $0x3e8<UINT32>
0x4ad083b8:	call Sleep@KERNEL32.DLL
Sleep@KERNEL32.DLL: API Node	
0x4ad083be:	jmp 0x4ad082c1
