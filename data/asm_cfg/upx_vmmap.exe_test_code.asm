0x00544d20:	pusha
0x00544d21:	movl %esi, $0x4da000<UINT32>
0x00544d26:	leal %edi, -888832(%esi)
0x00544d2c:	pushl %edi
0x00544d2d:	orl %ebp, $0xffffffff<UINT8>
0x00544d30:	jmp 0x00544d42
0x00544d42:	movl %ebx, (%esi)
0x00544d44:	subl %esi, $0xfffffffc<UINT8>
0x00544d47:	adcl %ebx, %ebx
0x00544d49:	jb 0x00544d38
0x00544d38:	movb %al, (%esi)
0x00544d3a:	incl %esi
0x00544d3b:	movb (%edi), %al
0x00544d3d:	incl %edi
0x00544d3e:	addl %ebx, %ebx
0x00544d40:	jne 0x00544d49
0x00544d4b:	movl %eax, $0x1<UINT32>
0x00544d50:	addl %ebx, %ebx
0x00544d52:	jne 0x00544d5b
0x00544d5b:	adcl %eax, %eax
0x00544d5d:	addl %ebx, %ebx
0x00544d5f:	jae 0x00544d6c
0x00544d61:	jne 0x00544d8b
0x00544d8b:	xorl %ecx, %ecx
0x00544d8d:	subl %eax, $0x3<UINT8>
0x00544d90:	jb 0x00544da3
0x00544da3:	addl %ebx, %ebx
0x00544da5:	jne 0x00544dae
0x00544dae:	jb 0x00544d7c
0x00544d7c:	addl %ebx, %ebx
0x00544d7e:	jne 0x00544d87
0x00544d87:	adcl %ecx, %ecx
0x00544d89:	jmp 0x00544ddd
0x00544ddd:	cmpl %ebp, $0xfffffb00<UINT32>
0x00544de3:	adcl %ecx, $0x2<UINT8>
0x00544de6:	leal %edx, (%edi,%ebp)
0x00544de9:	cmpl %ebp, $0xfffffffc<UINT8>
0x00544dec:	jbe 0x00544dfc
0x00544dee:	movb %al, (%edx)
0x00544df0:	incl %edx
0x00544df1:	movb (%edi), %al
0x00544df3:	incl %edi
0x00544df4:	decl %ecx
0x00544df5:	jne 0x00544dee
0x00544df7:	jmp 0x00544d3e
0x00544d92:	shll %eax, $0x8<UINT8>
0x00544d95:	movb %al, (%esi)
0x00544d97:	incl %esi
0x00544d98:	xorl %eax, $0xffffffff<UINT8>
0x00544d9b:	je 117
0x00544d9d:	sarl %eax
0x00544d9f:	movl %ebp, %eax
0x00544da1:	jmp 0x00544dae
0x00544dfc:	movl %eax, (%edx)
0x00544dfe:	addl %edx, $0x4<UINT8>
0x00544e01:	movl (%edi), %eax
0x00544e03:	addl %edi, $0x4<UINT8>
0x00544e06:	subl %ecx, $0x4<UINT8>
0x00544e09:	ja 0x00544dfc
0x00544e0b:	addl %edi, %ecx
0x00544e0d:	jmp 0x00544d3e
0x00544db0:	incl %ecx
0x00544db1:	addl %ebx, %ebx
0x00544db3:	jne 0x00544dbc
0x00544dbc:	jb 0x00544d7c
0x00544dbe:	addl %ebx, %ebx
0x00544dc0:	jne 0x00544dc9
0x00544dc9:	adcl %ecx, %ecx
0x00544dcb:	addl %ebx, %ebx
0x00544dcd:	jae 0x00544dbe
0x00544dcf:	jne 0x00544dda
0x00544dda:	addl %ecx, $0x2<UINT8>
0x00544d63:	movl %ebx, (%esi)
0x00544d65:	subl %esi, $0xfffffffc<UINT8>
0x00544d68:	adcl %ebx, %ebx
0x00544d6a:	jb 0x00544d8b
0x00544d54:	movl %ebx, (%esi)
0x00544d56:	subl %esi, $0xfffffffc<UINT8>
0x00544d59:	adcl %ebx, %ebx
0x00544d6c:	decl %eax
0x00544d6d:	addl %ebx, %ebx
0x00544d6f:	jne 0x00544d78
0x00544d78:	adcl %eax, %eax
0x00544d7a:	jmp 0x00544d50
0x00544da7:	movl %ebx, (%esi)
0x00544da9:	subl %esi, $0xfffffffc<UINT8>
0x00544dac:	adcl %ebx, %ebx
0x00544d71:	movl %ebx, (%esi)
0x00544d73:	subl %esi, $0xfffffffc<UINT8>
0x00544d76:	adcl %ebx, %ebx
0x00544db5:	movl %ebx, (%esi)
0x00544db7:	subl %esi, $0xfffffffc<UINT8>
0x00544dba:	adcl %ebx, %ebx
0x00544d80:	movl %ebx, (%esi)
0x00544d82:	subl %esi, $0xfffffffc<UINT8>
0x00544d85:	adcl %ebx, %ebx
0x00544dc2:	movl %ebx, (%esi)
0x00544dc4:	subl %esi, $0xfffffffc<UINT8>
0x00544dc7:	adcl %ebx, %ebx
0x00544dd1:	movl %ebx, (%esi)
0x00544dd3:	subl %esi, $0xfffffffc<UINT8>
0x00544dd6:	adcl %ebx, %ebx
0x00544dd8:	jae 0x00544dbe
