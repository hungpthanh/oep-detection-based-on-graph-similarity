0x006c0a90:	pusha
0x006c0a91:	movl %esi, $0x60d000<UINT32>
0x006c0a96:	leal %edi, -2146304(%esi)
0x006c0a9c:	pushl %edi
0x006c0a9d:	jmp 0x006c0aaa
0x006c0aaa:	movl %ebx, (%esi)
0x006c0aac:	subl %esi, $0xfffffffc<UINT8>
0x006c0aaf:	adcl %ebx, %ebx
0x006c0ab1:	jb 0x006c0aa0
0x006c0aa0:	movb %al, (%esi)
0x006c0aa2:	incl %esi
0x006c0aa3:	movb (%edi), %al
0x006c0aa5:	incl %edi
0x006c0aa6:	addl %ebx, %ebx
0x006c0aa8:	jne 0x006c0ab1
0x006c0ab3:	movl %eax, $0x1<UINT32>
0x006c0ab8:	addl %ebx, %ebx
0x006c0aba:	jne 0x006c0ac3
0x006c0ac3:	adcl %eax, %eax
0x006c0ac5:	addl %ebx, %ebx
0x006c0ac7:	jae 0x006c0ad4
0x006c0ac9:	jne 0x006c0af3
0x006c0af3:	xorl %ecx, %ecx
0x006c0af5:	subl %eax, $0x3<UINT8>
0x006c0af8:	jb 0x006c0b0b
0x006c0afa:	shll %eax, $0x8<UINT8>
0x006c0afd:	movb %al, (%esi)
0x006c0aff:	incl %esi
0x006c0b00:	xorl %eax, $0xffffffff<UINT8>
0x006c0b03:	je 0x006c0b7a
0x006c0b05:	sarl %eax
0x006c0b07:	movl %ebp, %eax
0x006c0b09:	jmp 0x006c0b16
0x006c0b16:	jb 0x006c0ae4
0x006c0ae4:	addl %ebx, %ebx
0x006c0ae6:	jne 0x006c0aef
0x006c0aef:	adcl %ecx, %ecx
0x006c0af1:	jmp 0x006c0b45
0x006c0b45:	cmpl %ebp, $0xfffffb00<UINT32>
0x006c0b4b:	adcl %ecx, $0x2<UINT8>
0x006c0b4e:	leal %edx, (%edi,%ebp)
0x006c0b51:	cmpl %ebp, $0xfffffffc<UINT8>
0x006c0b54:	jbe 0x006c0b64
0x006c0b56:	movb %al, (%edx)
0x006c0b58:	incl %edx
0x006c0b59:	movb (%edi), %al
0x006c0b5b:	incl %edi
0x006c0b5c:	decl %ecx
0x006c0b5d:	jne 0x006c0b56
0x006c0b5f:	jmp 0x006c0aa6
0x006c0b64:	movl %eax, (%edx)
0x006c0b66:	addl %edx, $0x4<UINT8>
0x006c0b69:	movl (%edi), %eax
0x006c0b6b:	addl %edi, $0x4<UINT8>
0x006c0b6e:	subl %ecx, $0x4<UINT8>
0x006c0b71:	ja 0x006c0b64
0x006c0b73:	addl %edi, %ecx
0x006c0b75:	jmp 0x006c0aa6
0x006c0b18:	incl %ecx
0x006c0b19:	addl %ebx, %ebx
0x006c0b1b:	jne 0x006c0b24
0x006c0b24:	jb 0x006c0ae4
0x006c0b26:	addl %ebx, %ebx
0x006c0b28:	jne 0x006c0b31
0x006c0b31:	adcl %ecx, %ecx
0x006c0b33:	addl %ebx, %ebx
0x006c0b35:	jae 0x006c0b26
0x006c0b37:	jne 0x006c0b42
0x006c0b42:	addl %ecx, $0x2<UINT8>
0x006c0b0b:	addl %ebx, %ebx
0x006c0b0d:	jne 0x006c0b16
0x006c0acb:	movl %ebx, (%esi)
0x006c0acd:	subl %esi, $0xfffffffc<UINT8>
0x006c0ad0:	adcl %ebx, %ebx
0x006c0ad2:	jb 0x006c0af3
0x006c0b1d:	movl %ebx, (%esi)
0x006c0b1f:	subl %esi, $0xfffffffc<UINT8>
0x006c0b22:	adcl %ebx, %ebx
0x006c0b2a:	movl %ebx, (%esi)
0x006c0b2c:	subl %esi, $0xfffffffc<UINT8>
0x006c0b2f:	adcl %ebx, %ebx
0x006c0ae8:	movl %ebx, (%esi)
0x006c0aea:	subl %esi, $0xfffffffc<UINT8>
0x006c0aed:	adcl %ebx, %ebx
0x006c0b0f:	movl %ebx, (%esi)
0x006c0b11:	subl %esi, $0xfffffffc<UINT8>
0x006c0b14:	adcl %ebx, %ebx
0x006c0ad4:	decl %eax
0x006c0ad5:	addl %ebx, %ebx
0x006c0ad7:	jne 0x006c0ae0
0x006c0ae0:	adcl %eax, %eax
0x006c0ae2:	jmp 0x006c0ab8
0x006c0abc:	movl %ebx, (%esi)
0x006c0abe:	subl %esi, $0xfffffffc<UINT8>
0x006c0ac1:	adcl %ebx, %ebx
0x006c0ad9:	movl %ebx, (%esi)
0x006c0adb:	subl %esi, $0xfffffffc<UINT8>
0x006c0ade:	adcl %ebx, %ebx
0x006c0b39:	movl %ebx, (%esi)
0x006c0b3b:	subl %esi, $0xfffffffc<UINT8>
0x006c0b3e:	adcl %ebx, %ebx
0x006c0b40:	jae 0x006c0b26
0x006c0b7a:	popl %esi
0x006c0b7b:	movl %edi, %esi
0x006c0b7d:	movl %ecx, $0x376b<UINT32>
0x006c0b82:	movb %al, (%edi)
0x006c0b84:	incl %edi
0x006c0b85:	subb %al, $0xffffffe8<UINT8>
0x006c0b87:	cmpb %al, $0x1<UINT8>
0x006c0b89:	ja 0x006c0b82
0x006c0b8b:	cmpb (%edi), $0x16<UINT8>
0x006c0b8e:	jne 0x006c0b82
0x006c0b90:	movl %eax, (%edi)
0x006c0b92:	movb %bl, 0x4(%edi)
0x006c0b95:	shrw %ax, $0x8<UINT8>
0x006c0b99:	roll %eax, $0x10<UINT8>
0x006c0b9c:	xchgb %ah, %al
0x006c0b9e:	subl %eax, %edi
0x006c0ba0:	subb %bl, $0xffffffe8<UINT8>
0x006c0ba3:	addl %eax, %esi
0x006c0ba5:	movl (%edi), %eax
0x006c0ba7:	addl %edi, $0x5<UINT8>
0x006c0baa:	movb %al, %bl
0x006c0bac:	loop 0x006c0b87
