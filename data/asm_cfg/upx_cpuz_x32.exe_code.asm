0x00711cf0:	pusha
0x00711cf1:	movl %esi, $0x60c000<UINT32>
0x00711cf6:	leal %edi, -2142208(%esi)
0x00711cfc:	pushl %edi
0x00711cfd:	orl %ebp, $0xffffffff<UINT8>
0x00711d00:	jmp 0x00711d12
0x00711d12:	movl %ebx, (%esi)
0x00711d14:	subl %esi, $0xfffffffc<UINT8>
0x00711d17:	adcl %ebx, %ebx
0x00711d19:	jb 0x00711d08
0x00711d08:	movb %al, (%esi)
0x00711d0a:	incl %esi
0x00711d0b:	movb (%edi), %al
0x00711d0d:	incl %edi
0x00711d0e:	addl %ebx, %ebx
0x00711d10:	jne 0x00711d19
0x00711d1b:	movl %eax, $0x1<UINT32>
0x00711d20:	addl %ebx, %ebx
0x00711d22:	jne 0x00711d2b
0x00711d2b:	adcl %eax, %eax
0x00711d2d:	addl %ebx, %ebx
0x00711d2f:	jae 0x00711d3c
0x00711d31:	jne 0x00711d5b
0x00711d5b:	xorl %ecx, %ecx
0x00711d5d:	subl %eax, $0x3<UINT8>
0x00711d60:	jb 0x00711d73
0x00711d73:	addl %ebx, %ebx
0x00711d75:	jne 0x00711d7e
0x00711d7e:	jb 0x00711d4c
0x00711d80:	incl %ecx
0x00711d81:	addl %ebx, %ebx
0x00711d83:	jne 0x00711d8c
0x00711d8c:	jb 0x00711d4c
0x00711d8e:	addl %ebx, %ebx
0x00711d90:	jne 0x00711d99
0x00711d99:	adcl %ecx, %ecx
0x00711d9b:	addl %ebx, %ebx
0x00711d9d:	jae 0x00711d8e
0x00711d9f:	jne 0x00711daa
0x00711daa:	addl %ecx, $0x2<UINT8>
0x00711dad:	cmpl %ebp, $0xfffffb00<UINT32>
0x00711db3:	adcl %ecx, $0x2<UINT8>
0x00711db6:	leal %edx, (%edi,%ebp)
0x00711db9:	cmpl %ebp, $0xfffffffc<UINT8>
0x00711dbc:	jbe 0x00711dcc
0x00711dbe:	movb %al, (%edx)
0x00711dc0:	incl %edx
0x00711dc1:	movb (%edi), %al
0x00711dc3:	incl %edi
0x00711dc4:	decl %ecx
0x00711dc5:	jne 0x00711dbe
0x00711dc7:	jmp 0x00711d0e
0x00711d4c:	addl %ebx, %ebx
0x00711d4e:	jne 0x00711d57
0x00711d57:	adcl %ecx, %ecx
0x00711d59:	jmp 0x00711dad
0x00711d62:	shll %eax, $0x8<UINT8>
0x00711d65:	movb %al, (%esi)
0x00711d67:	incl %esi
0x00711d68:	xorl %eax, $0xffffffff<UINT8>
0x00711d6b:	je 0x00711de2
0x00711d6d:	sarl %eax
0x00711d6f:	movl %ebp, %eax
0x00711d71:	jmp 0x00711d7e
0x00711dcc:	movl %eax, (%edx)
0x00711dce:	addl %edx, $0x4<UINT8>
0x00711dd1:	movl (%edi), %eax
0x00711dd3:	addl %edi, $0x4<UINT8>
0x00711dd6:	subl %ecx, $0x4<UINT8>
0x00711dd9:	ja 0x00711dcc
0x00711ddb:	addl %edi, %ecx
0x00711ddd:	jmp 0x00711d0e
0x00711d24:	movl %ebx, (%esi)
0x00711d26:	subl %esi, $0xfffffffc<UINT8>
0x00711d29:	adcl %ebx, %ebx
0x00711da1:	movl %ebx, (%esi)
0x00711da3:	subl %esi, $0xfffffffc<UINT8>
0x00711da6:	adcl %ebx, %ebx
0x00711da8:	jae 0x00711d8e
0x00711d77:	movl %ebx, (%esi)
0x00711d79:	subl %esi, $0xfffffffc<UINT8>
0x00711d7c:	adcl %ebx, %ebx
0x00711d3c:	decl %eax
0x00711d3d:	addl %ebx, %ebx
0x00711d3f:	jne 0x00711d48
0x00711d48:	adcl %eax, %eax
0x00711d4a:	jmp 0x00711d20
0x00711d33:	movl %ebx, (%esi)
0x00711d35:	subl %esi, $0xfffffffc<UINT8>
0x00711d38:	adcl %ebx, %ebx
0x00711d3a:	jb 0x00711d5b
0x00711d50:	movl %ebx, (%esi)
0x00711d52:	subl %esi, $0xfffffffc<UINT8>
0x00711d55:	adcl %ebx, %ebx
0x00711d85:	movl %ebx, (%esi)
0x00711d87:	subl %esi, $0xfffffffc<UINT8>
0x00711d8a:	adcl %ebx, %ebx
0x00711d92:	movl %ebx, (%esi)
0x00711d94:	subl %esi, $0xfffffffc<UINT8>
0x00711d97:	adcl %ebx, %ebx
0x00711d41:	movl %ebx, (%esi)
0x00711d43:	subl %esi, $0xfffffffc<UINT8>
0x00711d46:	adcl %ebx, %ebx
0x00711de2:	popl %esi
0x00711de3:	movl %edi, %esi
0x00711de5:	movl %ecx, $0x8cb3<UINT32>
0x00711dea:	movb %al, (%edi)
0x00711dec:	incl %edi
0x00711ded:	subb %al, $0xffffffe8<UINT8>
0x00711def:	cmpb %al, $0x1<UINT8>
0x00711df1:	ja 0x00711dea
0x00711df3:	cmpb (%edi), $0x47<UINT8>
0x00711df6:	jne 0x00711dea
0x00711df8:	movl %eax, (%edi)
0x00711dfa:	movb %bl, 0x4(%edi)
0x00711dfd:	shrw %ax, $0x8<UINT8>
0x00711e01:	roll %eax, $0x10<UINT8>
0x00711e04:	xchgb %ah, %al
0x00711e06:	subl %eax, %edi
0x00711e08:	subb %bl, $0xffffffe8<UINT8>
0x00711e0b:	addl %eax, %esi
0x00711e0d:	movl (%edi), %eax
0x00711e0f:	addl %edi, $0x5<UINT8>
0x00711e12:	movb %al, %bl
0x00711e14:	loop 0x00711def
0x00711e16:	leal %edi, 0x30e000(%esi)
0x00711e1c:	movl %eax, (%edi)
0x00711e1e:	orl %eax, %eax
0x00711e20:	je 69
0x00711e22:	movl %ebx, 0x4(%edi)
0x00711e25:	leal %eax, 0x330474(%eax,%esi)
0x00711e2c:	addl %ebx, %esi
0x00711e2e:	pushl %eax
0x00711e2f:	addl %edi, $0x8<UINT8>
0x00711e32:	call 0x00000000
Unknown Node: Unknown Node	
