0x005e0cc0:	pusha
0x005e0cc1:	movl %esi, $0x4cc000<UINT32>
0x005e0cc6:	leal %edi, -831488(%esi)
0x005e0ccc:	pushl %edi
0x005e0ccd:	jmp 0x005e0cda
0x005e0cda:	movl %ebx, (%esi)
0x005e0cdc:	subl %esi, $0xfffffffc<UINT8>
0x005e0cdf:	adcl %ebx, %ebx
0x005e0ce1:	jb 0x005e0cd0
0x005e0cd0:	movb %al, (%esi)
0x005e0cd2:	incl %esi
0x005e0cd3:	movb (%edi), %al
0x005e0cd5:	incl %edi
0x005e0cd6:	addl %ebx, %ebx
0x005e0cd8:	jne 0x005e0ce1
0x005e0ce3:	movl %eax, $0x1<UINT32>
0x005e0ce8:	addl %ebx, %ebx
0x005e0cea:	jne 0x005e0cf3
0x005e0cf3:	adcl %eax, %eax
0x005e0cf5:	addl %ebx, %ebx
0x005e0cf7:	jae 0x005e0d04
0x005e0cf9:	jne 0x005e0d23
0x005e0d23:	xorl %ecx, %ecx
0x005e0d25:	subl %eax, $0x3<UINT8>
0x005e0d28:	jb 0x005e0d3b
0x005e0d2a:	shll %eax, $0x8<UINT8>
0x005e0d2d:	movb %al, (%esi)
0x005e0d2f:	incl %esi
0x005e0d30:	xorl %eax, $0xffffffff<UINT8>
0x005e0d33:	je 117
0x005e0d35:	sarl %eax
0x005e0d37:	movl %ebp, %eax
0x005e0d39:	jmp 0x005e0d46
0x005e0d46:	jb 0x005e0d14
0x005e0d14:	addl %ebx, %ebx
0x005e0d16:	jne 0x005e0d1f
0x005e0d1f:	adcl %ecx, %ecx
0x005e0d21:	jmp 0x005e0d75
0x005e0d75:	cmpl %ebp, $0xfffffb00<UINT32>
0x005e0d7b:	adcl %ecx, $0x2<UINT8>
0x005e0d7e:	leal %edx, (%edi,%ebp)
0x005e0d81:	cmpl %ebp, $0xfffffffc<UINT8>
0x005e0d84:	jbe 0x005e0d94
0x005e0d86:	movb %al, (%edx)
0x005e0d88:	incl %edx
0x005e0d89:	movb (%edi), %al
0x005e0d8b:	incl %edi
0x005e0d8c:	decl %ecx
0x005e0d8d:	jne 0x005e0d86
0x005e0d8f:	jmp 0x005e0cd6
0x005e0d3b:	addl %ebx, %ebx
0x005e0d3d:	jne 0x005e0d46
0x005e0cec:	movl %ebx, (%esi)
0x005e0cee:	subl %esi, $0xfffffffc<UINT8>
0x005e0cf1:	adcl %ebx, %ebx
0x005e0d48:	incl %ecx
0x005e0d49:	addl %ebx, %ebx
0x005e0d4b:	jne 0x005e0d54
0x005e0d54:	jb 0x005e0d14
0x005e0d94:	movl %eax, (%edx)
0x005e0d96:	addl %edx, $0x4<UINT8>
0x005e0d99:	movl (%edi), %eax
0x005e0d9b:	addl %edi, $0x4<UINT8>
0x005e0d9e:	subl %ecx, $0x4<UINT8>
0x005e0da1:	ja 0x005e0d94
0x005e0da3:	addl %edi, %ecx
0x005e0da5:	jmp 0x005e0cd6
0x005e0d18:	movl %ebx, (%esi)
0x005e0d1a:	subl %esi, $0xfffffffc<UINT8>
0x005e0d1d:	adcl %ebx, %ebx
0x005e0d56:	addl %ebx, %ebx
0x005e0d58:	jne 0x005e0d61
0x005e0d5a:	movl %ebx, (%esi)
0x005e0d5c:	subl %esi, $0xfffffffc<UINT8>
0x005e0d5f:	adcl %ebx, %ebx
0x005e0d61:	adcl %ecx, %ecx
0x005e0d63:	addl %ebx, %ebx
0x005e0d65:	jae 0x005e0d56
0x005e0d67:	jne 0x005e0d72
0x005e0d72:	addl %ecx, $0x2<UINT8>
0x005e0cfb:	movl %ebx, (%esi)
0x005e0cfd:	subl %esi, $0xfffffffc<UINT8>
0x005e0d00:	adcl %ebx, %ebx
0x005e0d02:	jb 0x005e0d23
0x005e0d04:	decl %eax
0x005e0d05:	addl %ebx, %ebx
0x005e0d07:	jne 0x005e0d10
0x005e0d10:	adcl %eax, %eax
0x005e0d12:	jmp 0x005e0ce8
0x005e0d4d:	movl %ebx, (%esi)
0x005e0d4f:	subl %esi, $0xfffffffc<UINT8>
0x005e0d52:	adcl %ebx, %ebx
0x005e0d69:	movl %ebx, (%esi)
0x005e0d6b:	subl %esi, $0xfffffffc<UINT8>
0x005e0d6e:	adcl %ebx, %ebx
0x005e0d70:	jae 0x005e0d56
0x005e0d3f:	movl %ebx, (%esi)
0x005e0d41:	subl %esi, $0xfffffffc<UINT8>
0x005e0d44:	adcl %ebx, %ebx
0x005e0d09:	movl %ebx, (%esi)
0x005e0d0b:	subl %esi, $0xfffffffc<UINT8>
0x005e0d0e:	adcl %ebx, %ebx
