0x00437b30:	pusha
0x00437b31:	movl %esi, $0x420000<UINT32>
0x00437b36:	leal %edi, -126976(%esi)
0x00437b3c:	pushl %edi
0x00437b3d:	orl %ebp, $0xffffffff<UINT8>
0x00437b40:	jmp 0x00437b52
0x00437b52:	movl %ebx, (%esi)
0x00437b54:	subl %esi, $0xfffffffc<UINT8>
0x00437b57:	adcl %ebx, %ebx
0x00437b59:	jb 0x00437b48
0x00437b48:	movb %al, (%esi)
0x00437b4a:	incl %esi
0x00437b4b:	movb (%edi), %al
0x00437b4d:	incl %edi
0x00437b4e:	addl %ebx, %ebx
0x00437b50:	jne 0x00437b59
0x00437b5b:	movl %eax, $0x1<UINT32>
0x00437b60:	addl %ebx, %ebx
0x00437b62:	jne 0x00437b6b
0x00437b6b:	adcl %eax, %eax
0x00437b6d:	addl %ebx, %ebx
0x00437b6f:	jae 0x00437b60
0x00437b71:	jne 0x00437b7c
0x00437b7c:	xorl %ecx, %ecx
0x00437b7e:	subl %eax, $0x3<UINT8>
0x00437b81:	jb 0x00437b90
0x00437b90:	addl %ebx, %ebx
0x00437b92:	jne 0x00437b9b
0x00437b9b:	adcl %ecx, %ecx
0x00437b9d:	addl %ebx, %ebx
0x00437b9f:	jne 0x00437ba8
0x00437ba8:	adcl %ecx, %ecx
0x00437baa:	jne 0x00437bcc
0x00437bcc:	cmpl %ebp, $0xfffff300<UINT32>
0x00437bd2:	adcl %ecx, $0x1<UINT8>
0x00437bd5:	leal %edx, (%edi,%ebp)
0x00437bd8:	cmpl %ebp, $0xfffffffc<UINT8>
0x00437bdb:	jbe 0x00437bec
0x00437bdd:	movb %al, (%edx)
0x00437bdf:	incl %edx
0x00437be0:	movb (%edi), %al
0x00437be2:	incl %edi
0x00437be3:	decl %ecx
0x00437be4:	jne 0x00437bdd
0x00437be6:	jmp 0x00437b4e
0x00437b83:	shll %eax, $0x8<UINT8>
0x00437b86:	movb %al, (%esi)
0x00437b88:	incl %esi
0x00437b89:	xorl %eax, $0xffffffff<UINT8>
0x00437b8c:	je 0x00437c02
0x00437b8e:	movl %ebp, %eax
0x00437bec:	movl %eax, (%edx)
0x00437bee:	addl %edx, $0x4<UINT8>
0x00437bf1:	movl (%edi), %eax
0x00437bf3:	addl %edi, $0x4<UINT8>
0x00437bf6:	subl %ecx, $0x4<UINT8>
0x00437bf9:	ja 0x00437bec
0x00437bfb:	addl %edi, %ecx
0x00437bfd:	jmp 0x00437b4e
0x00437b94:	movl %ebx, (%esi)
0x00437b96:	subl %esi, $0xfffffffc<UINT8>
0x00437b99:	adcl %ebx, %ebx
0x00437b73:	movl %ebx, (%esi)
0x00437b75:	subl %esi, $0xfffffffc<UINT8>
0x00437b78:	adcl %ebx, %ebx
0x00437b7a:	jae 0x00437b60
0x00437bac:	incl %ecx
0x00437bad:	addl %ebx, %ebx
0x00437baf:	jne 0x00437bb8
0x00437bb8:	adcl %ecx, %ecx
0x00437bba:	addl %ebx, %ebx
0x00437bbc:	jae 0x00437bad
0x00437bbe:	jne 0x00437bc9
0x00437bc9:	addl %ecx, $0x2<UINT8>
0x00437b64:	movl %ebx, (%esi)
0x00437b66:	subl %esi, $0xfffffffc<UINT8>
0x00437b69:	adcl %ebx, %ebx
0x00437bc0:	movl %ebx, (%esi)
0x00437bc2:	subl %esi, $0xfffffffc<UINT8>
0x00437bc5:	adcl %ebx, %ebx
0x00437bc7:	jae 0x00437bad
0x00437ba1:	movl %ebx, (%esi)
0x00437ba3:	subl %esi, $0xfffffffc<UINT8>
0x00437ba6:	adcl %ebx, %ebx
0x00437bb1:	movl %ebx, (%esi)
0x00437bb3:	subl %esi, $0xfffffffc<UINT8>
0x00437bb6:	adcl %ebx, %ebx
0x00437c02:	popl %esi
0x00437c03:	movl %edi, %esi
0x00437c05:	movl %ecx, $0xcfe<UINT32>
0x00437c0a:	movb %al, (%edi)
0x00437c0c:	incl %edi
0x00437c0d:	subb %al, $0xffffffe8<UINT8>
0x00437c0f:	cmpb %al, $0x1<UINT8>
0x00437c11:	ja 0x00437c0a
0x00437c13:	cmpb (%edi), $0x11<UINT8>
0x00437c16:	jne 0x00437c0a
0x00437c18:	movl %eax, (%edi)
0x00437c1a:	movb %bl, 0x4(%edi)
0x00437c1d:	shrw %ax, $0x8<UINT8>
0x00437c21:	roll %eax, $0x10<UINT8>
0x00437c24:	xchgb %ah, %al
0x00437c26:	subl %eax, %edi
0x00437c28:	subb %bl, $0xffffffe8<UINT8>
0x00437c2b:	addl %eax, %esi
0x00437c2d:	movl (%edi), %eax
0x00437c2f:	addl %edi, $0x5<UINT8>
0x00437c32:	movb %al, %bl
0x00437c34:	loop 0x00437c0f
0x00437c36:	leal %edi, 0x35000(%esi)
0x00437c3c:	movl %eax, (%edi)
0x00437c3e:	orl %eax, %eax
0x00437c40:	je 60
0x00437c42:	movl %ebx, 0x4(%edi)
0x00437c45:	leal %eax, 0x372d8(%eax,%esi)
0x00437c4c:	addl %ebx, %esi
0x00437c4e:	pushl %eax
0x00437c4f:	addl %edi, $0x8<UINT8>
0x00437c52:	call 0x00000000
Unknown Node: Unknown Node	
