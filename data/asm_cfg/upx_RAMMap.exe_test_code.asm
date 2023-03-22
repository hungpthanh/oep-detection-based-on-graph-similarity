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
0x004a1e43:	je 117
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
