0x0061ef50:	pusha
0x0061ef51:	movl %esi, $0x567000<UINT32>
0x0061ef56:	leal %edi, -1466368(%esi)
0x0061ef5c:	pushl %edi
0x0061ef5d:	orl %ebp, $0xffffffff<UINT8>
0x0061ef60:	jmp 0x0061ef72
0x0061ef72:	movl %ebx, (%esi)
0x0061ef74:	subl %esi, $0xfffffffc<UINT8>
0x0061ef77:	adcl %ebx, %ebx
0x0061ef79:	jb 0x0061ef68
0x0061ef68:	movb %al, (%esi)
0x0061ef6a:	incl %esi
0x0061ef6b:	movb (%edi), %al
0x0061ef6d:	incl %edi
0x0061ef6e:	addl %ebx, %ebx
0x0061ef70:	jne 0x0061ef79
0x0061ef7b:	movl %eax, $0x1<UINT32>
0x0061ef80:	addl %ebx, %ebx
0x0061ef82:	jne 0x0061ef8b
0x0061ef8b:	adcl %eax, %eax
0x0061ef8d:	addl %ebx, %ebx
0x0061ef8f:	jae 0x0061ef9c
0x0061ef91:	jne 0x0061efbb
0x0061efbb:	xorl %ecx, %ecx
0x0061efbd:	subl %eax, $0x3<UINT8>
0x0061efc0:	jb 0x0061efd3
0x0061efd3:	addl %ebx, %ebx
0x0061efd5:	jne 0x0061efde
0x0061efde:	jb 0x0061efac
0x0061efac:	addl %ebx, %ebx
0x0061efae:	jne 0x0061efb7
0x0061efb7:	adcl %ecx, %ecx
0x0061efb9:	jmp 0x0061f00d
0x0061f00d:	cmpl %ebp, $0xfffffb00<UINT32>
0x0061f013:	adcl %ecx, $0x2<UINT8>
0x0061f016:	leal %edx, (%edi,%ebp)
0x0061f019:	cmpl %ebp, $0xfffffffc<UINT8>
0x0061f01c:	jbe 0x0061f02c
0x0061f01e:	movb %al, (%edx)
0x0061f020:	incl %edx
0x0061f021:	movb (%edi), %al
0x0061f023:	incl %edi
0x0061f024:	decl %ecx
0x0061f025:	jne 0x0061f01e
0x0061f027:	jmp 0x0061ef6e
0x0061efc2:	shll %eax, $0x8<UINT8>
0x0061efc5:	movb %al, (%esi)
0x0061efc7:	incl %esi
0x0061efc8:	xorl %eax, $0xffffffff<UINT8>
0x0061efcb:	je 0x0061f042
0x0061efcd:	sarl %eax
0x0061efcf:	movl %ebp, %eax
0x0061efd1:	jmp 0x0061efde
0x0061f02c:	movl %eax, (%edx)
0x0061f02e:	addl %edx, $0x4<UINT8>
0x0061f031:	movl (%edi), %eax
0x0061f033:	addl %edi, $0x4<UINT8>
0x0061f036:	subl %ecx, $0x4<UINT8>
0x0061f039:	ja 0x0061f02c
0x0061f03b:	addl %edi, %ecx
0x0061f03d:	jmp 0x0061ef6e
0x0061efb0:	movl %ebx, (%esi)
0x0061efb2:	subl %esi, $0xfffffffc<UINT8>
0x0061efb5:	adcl %ebx, %ebx
0x0061efe0:	incl %ecx
0x0061efe1:	addl %ebx, %ebx
0x0061efe3:	jne 0x0061efec
0x0061efec:	jb 0x0061efac
0x0061ef9c:	decl %eax
0x0061ef9d:	addl %ebx, %ebx
0x0061ef9f:	jne 0x0061efa8
0x0061efa8:	adcl %eax, %eax
0x0061efaa:	jmp 0x0061ef80
0x0061efee:	addl %ebx, %ebx
0x0061eff0:	jne 0x0061eff9
0x0061eff9:	adcl %ecx, %ecx
0x0061effb:	addl %ebx, %ebx
0x0061effd:	jae 0x0061efee
0x0061efff:	jne 0x0061f00a
0x0061f00a:	addl %ecx, $0x2<UINT8>
0x0061ef84:	movl %ebx, (%esi)
0x0061ef86:	subl %esi, $0xfffffffc<UINT8>
0x0061ef89:	adcl %ebx, %ebx
0x0061ef93:	movl %ebx, (%esi)
0x0061ef95:	subl %esi, $0xfffffffc<UINT8>
0x0061ef98:	adcl %ebx, %ebx
0x0061ef9a:	jb 0x0061efbb
0x0061efe5:	movl %ebx, (%esi)
0x0061efe7:	subl %esi, $0xfffffffc<UINT8>
0x0061efea:	adcl %ebx, %ebx
0x0061efd7:	movl %ebx, (%esi)
0x0061efd9:	subl %esi, $0xfffffffc<UINT8>
0x0061efdc:	adcl %ebx, %ebx
0x0061eff2:	movl %ebx, (%esi)
0x0061eff4:	subl %esi, $0xfffffffc<UINT8>
0x0061eff7:	adcl %ebx, %ebx
0x0061efa1:	movl %ebx, (%esi)
0x0061efa3:	subl %esi, $0xfffffffc<UINT8>
0x0061efa6:	adcl %ebx, %ebx
0x0061f001:	movl %ebx, (%esi)
0x0061f003:	subl %esi, $0xfffffffc<UINT8>
0x0061f006:	adcl %ebx, %ebx
0x0061f008:	jae 0x0061efee
0x0061f042:	popl %esi
0x0061f043:	movl %edi, %esi
0x0061f045:	movl %ecx, $0x3c72<UINT32>
0x0061f04a:	movb %al, (%edi)
0x0061f04c:	incl %edi
0x0061f04d:	subb %al, $0xffffffe8<UINT8>
0x0061f04f:	cmpb %al, $0x1<UINT8>
0x0061f051:	ja 0x0061f04a
0x0061f053:	cmpb (%edi), $0x12<UINT8>
0x0061f056:	jne 0x0061f04a
0x0061f058:	movl %eax, (%edi)
0x0061f05a:	movb %bl, 0x4(%edi)
0x0061f05d:	shrw %ax, $0x8<UINT8>
0x0061f061:	roll %eax, $0x10<UINT8>
0x0061f064:	xchgb %ah, %al
0x0061f066:	subl %eax, %edi
0x0061f068:	subb %bl, $0xffffffe8<UINT8>
0x0061f06b:	addl %eax, %esi
0x0061f06d:	movl (%edi), %eax
0x0061f06f:	addl %edi, $0x5<UINT8>
0x0061f072:	movb %al, %bl
0x0061f074:	loop 0x0061f04f
0x0061f076:	leal %edi, 0x216000(%esi)
0x0061f07c:	movl %eax, (%edi)
0x0061f07e:	orl %eax, %eax
0x0061f080:	je 69
0x0061f082:	movl %ebx, 0x4(%edi)
0x0061f085:	leal %eax, 0x226b44(%eax,%esi)
0x0061f08c:	addl %ebx, %esi
0x0061f08e:	pushl %eax
0x0061f08f:	addl %edi, $0x8<UINT8>
0x0061f092:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x0061f098:	xchgl %ebp, %eax
0x0061f099:	movb %al, (%edi)
0x0061f09b:	incl %edi
0x0061f09c:	orb %al, %al
0x0061f09e:	je 0x0061f07c
0x0061f0a0:	movl %ecx, %edi
0x0061f0a2:	jns 0x0061f0ab
0x0061f0ab:	pushl %edi
0x0061f0ac:	decl %eax
0x0061f0ad:	repn scasb %al, %es:(%edi)
0x0061f0af:	pushl %ebp
0x0061f0b0:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0061f0b6:	orl %eax, %eax
0x0061f0b8:	je 7
0x0061f0ba:	movl (%ebx), %eax
0x0061f0bc:	addl %ebx, $0x4<UINT8>
0x0061f0bf:	jmp 0x0061f099
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
