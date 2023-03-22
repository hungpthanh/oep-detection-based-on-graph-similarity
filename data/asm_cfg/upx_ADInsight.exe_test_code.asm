0x0082abc0:	pusha
0x0082abc1:	movl %esi, $0x795000<UINT32>
0x0082abc6:	leal %edi, -3751936(%esi)
0x0082abcc:	pushl %edi
0x0082abcd:	orl %ebp, $0xffffffff<UINT8>
0x0082abd0:	jmp 0x0082abe2
0x0082abe2:	movl %ebx, (%esi)
0x0082abe4:	subl %esi, $0xfffffffc<UINT8>
0x0082abe7:	adcl %ebx, %ebx
0x0082abe9:	jb 0x0082abd8
0x0082abd8:	movb %al, (%esi)
0x0082abda:	incl %esi
0x0082abdb:	movb (%edi), %al
0x0082abdd:	incl %edi
0x0082abde:	addl %ebx, %ebx
0x0082abe0:	jne 0x0082abe9
0x0082abeb:	movl %eax, $0x1<UINT32>
0x0082abf0:	addl %ebx, %ebx
0x0082abf2:	jne 0x0082abfb
0x0082abfb:	adcl %eax, %eax
0x0082abfd:	addl %ebx, %ebx
0x0082abff:	jae 0x0082ac0c
0x0082ac01:	jne 0x0082ac2b
0x0082ac2b:	xorl %ecx, %ecx
0x0082ac2d:	subl %eax, $0x3<UINT8>
0x0082ac30:	jb 0x0082ac43
0x0082ac43:	addl %ebx, %ebx
0x0082ac45:	jne 0x0082ac4e
0x0082ac4e:	jb 0x0082ac1c
0x0082ac1c:	addl %ebx, %ebx
0x0082ac1e:	jne 0x0082ac27
0x0082ac27:	adcl %ecx, %ecx
0x0082ac29:	jmp 0x0082ac7d
0x0082ac7d:	cmpl %ebp, $0xfffffb00<UINT32>
0x0082ac83:	adcl %ecx, $0x2<UINT8>
0x0082ac86:	leal %edx, (%edi,%ebp)
0x0082ac89:	cmpl %ebp, $0xfffffffc<UINT8>
0x0082ac8c:	jbe 0x0082ac9c
0x0082ac8e:	movb %al, (%edx)
0x0082ac90:	incl %edx
0x0082ac91:	movb (%edi), %al
0x0082ac93:	incl %edi
0x0082ac94:	decl %ecx
0x0082ac95:	jne 0x0082ac8e
0x0082ac97:	jmp 0x0082abde
0x0082ac32:	shll %eax, $0x8<UINT8>
0x0082ac35:	movb %al, (%esi)
0x0082ac37:	incl %esi
0x0082ac38:	xorl %eax, $0xffffffff<UINT8>
0x0082ac3b:	je 117
0x0082ac3d:	sarl %eax
0x0082ac3f:	movl %ebp, %eax
0x0082ac41:	jmp 0x0082ac4e
0x0082ac9c:	movl %eax, (%edx)
0x0082ac9e:	addl %edx, $0x4<UINT8>
0x0082aca1:	movl (%edi), %eax
0x0082aca3:	addl %edi, $0x4<UINT8>
0x0082aca6:	subl %ecx, $0x4<UINT8>
0x0082aca9:	ja 0x0082ac9c
0x0082acab:	addl %edi, %ecx
0x0082acad:	jmp 0x0082abde
0x0082ac20:	movl %ebx, (%esi)
0x0082ac22:	subl %esi, $0xfffffffc<UINT8>
0x0082ac25:	adcl %ebx, %ebx
0x0082ac50:	incl %ecx
0x0082ac51:	addl %ebx, %ebx
0x0082ac53:	jne 0x0082ac5c
0x0082ac5c:	jb 0x0082ac1c
0x0082ac0c:	decl %eax
0x0082ac0d:	addl %ebx, %ebx
0x0082ac0f:	jne 0x0082ac18
0x0082ac18:	adcl %eax, %eax
0x0082ac1a:	jmp 0x0082abf0
0x0082abf4:	movl %ebx, (%esi)
0x0082abf6:	subl %esi, $0xfffffffc<UINT8>
0x0082abf9:	adcl %ebx, %ebx
0x0082ac5e:	addl %ebx, %ebx
0x0082ac60:	jne 0x0082ac69
0x0082ac69:	adcl %ecx, %ecx
0x0082ac6b:	addl %ebx, %ebx
0x0082ac6d:	jae 0x0082ac5e
0x0082ac6f:	jne 0x0082ac7a
0x0082ac7a:	addl %ecx, $0x2<UINT8>
0x0082ac55:	movl %ebx, (%esi)
0x0082ac57:	subl %esi, $0xfffffffc<UINT8>
0x0082ac5a:	adcl %ebx, %ebx
0x0082ac03:	movl %ebx, (%esi)
0x0082ac05:	subl %esi, $0xfffffffc<UINT8>
0x0082ac08:	adcl %ebx, %ebx
0x0082ac0a:	jb 0x0082ac2b
0x0082ac71:	movl %ebx, (%esi)
0x0082ac73:	subl %esi, $0xfffffffc<UINT8>
0x0082ac76:	adcl %ebx, %ebx
0x0082ac78:	jae 0x0082ac5e
0x0082ac62:	movl %ebx, (%esi)
0x0082ac64:	subl %esi, $0xfffffffc<UINT8>
0x0082ac67:	adcl %ebx, %ebx
0x0082ac11:	movl %ebx, (%esi)
0x0082ac13:	subl %esi, $0xfffffffc<UINT8>
0x0082ac16:	adcl %ebx, %ebx
0x0082ac47:	movl %ebx, (%esi)
0x0082ac49:	subl %esi, $0xfffffffc<UINT8>
0x0082ac4c:	adcl %ebx, %ebx
