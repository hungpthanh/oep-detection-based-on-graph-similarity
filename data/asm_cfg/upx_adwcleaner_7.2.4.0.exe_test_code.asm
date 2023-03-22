0x01693d00:	pusha
0x01693d01:	movl %esi, $0xe6a000<UINT32>
0x01693d06:	leal %edi, -10915840(%esi)
0x01693d0c:	pushl %edi
0x01693d0d:	jmp 0x01693d1a
0x01693d1a:	movl %ebx, (%esi)
0x01693d1c:	subl %esi, $0xfffffffc<UINT8>
0x01693d1f:	adcl %ebx, %ebx
0x01693d21:	jb 0x01693d10
0x01693d10:	movb %al, (%esi)
0x01693d12:	incl %esi
0x01693d13:	movb (%edi), %al
0x01693d15:	incl %edi
0x01693d16:	addl %ebx, %ebx
0x01693d18:	jne 0x01693d21
0x01693d23:	movl %eax, $0x1<UINT32>
0x01693d28:	addl %ebx, %ebx
0x01693d2a:	jne 0x01693d33
0x01693d33:	adcl %eax, %eax
0x01693d35:	addl %ebx, %ebx
0x01693d37:	jae 0x01693d44
0x01693d39:	jne 0x01693d63
0x01693d63:	xorl %ecx, %ecx
0x01693d65:	subl %eax, $0x3<UINT8>
0x01693d68:	jb 0x01693d7b
0x01693d6a:	shll %eax, $0x8<UINT8>
0x01693d6d:	movb %al, (%esi)
0x01693d6f:	incl %esi
0x01693d70:	xorl %eax, $0xffffffff<UINT8>
0x01693d73:	je 0x01693dea
0x01693d75:	sarl %eax
0x01693d77:	movl %ebp, %eax
0x01693d79:	jmp 0x01693d86
0x01693d86:	jb 0x01693d54
0x01693d88:	incl %ecx
0x01693d89:	addl %ebx, %ebx
0x01693d8b:	jne 0x01693d94
0x01693d94:	jb 0x01693d54
0x01693d96:	addl %ebx, %ebx
0x01693d98:	jne 0x01693da1
0x01693da1:	adcl %ecx, %ecx
0x01693da3:	addl %ebx, %ebx
0x01693da5:	jae 0x01693d96
0x01693da7:	jne 0x01693db2
0x01693db2:	addl %ecx, $0x2<UINT8>
0x01693db5:	cmpl %ebp, $0xfffffb00<UINT32>
0x01693dbb:	adcl %ecx, $0x2<UINT8>
0x01693dbe:	leal %edx, (%edi,%ebp)
0x01693dc1:	cmpl %ebp, $0xfffffffc<UINT8>
0x01693dc4:	jbe 0x01693dd4
0x01693dd4:	movl %eax, (%edx)
0x01693dd6:	addl %edx, $0x4<UINT8>
0x01693dd9:	movl (%edi), %eax
0x01693ddb:	addl %edi, $0x4<UINT8>
0x01693dde:	subl %ecx, $0x4<UINT8>
0x01693de1:	ja 0x01693dd4
0x01693de3:	addl %edi, %ecx
0x01693de5:	jmp 0x01693d16
0x01693d54:	addl %ebx, %ebx
0x01693d56:	jne 0x01693d5f
0x01693d5f:	adcl %ecx, %ecx
0x01693d61:	jmp 0x01693db5
0x01693d7b:	addl %ebx, %ebx
0x01693d7d:	jne 0x01693d86
0x01693d2c:	movl %ebx, (%esi)
0x01693d2e:	subl %esi, $0xfffffffc<UINT8>
0x01693d31:	adcl %ebx, %ebx
0x01693d8d:	movl %ebx, (%esi)
0x01693d8f:	subl %esi, $0xfffffffc<UINT8>
0x01693d92:	adcl %ebx, %ebx
0x01693d9a:	movl %ebx, (%esi)
0x01693d9c:	subl %esi, $0xfffffffc<UINT8>
0x01693d9f:	adcl %ebx, %ebx
0x01693d7f:	movl %ebx, (%esi)
0x01693d81:	subl %esi, $0xfffffffc<UINT8>
0x01693d84:	adcl %ebx, %ebx
0x01693d58:	movl %ebx, (%esi)
0x01693d5a:	subl %esi, $0xfffffffc<UINT8>
0x01693d5d:	adcl %ebx, %ebx
0x01693d44:	decl %eax
0x01693d45:	addl %ebx, %ebx
0x01693d47:	jne 0x01693d50
0x01693d50:	adcl %eax, %eax
0x01693d52:	jmp 0x01693d28
0x01693dc6:	movb %al, (%edx)
0x01693dc8:	incl %edx
0x01693dc9:	movb (%edi), %al
0x01693dcb:	incl %edi
0x01693dcc:	decl %ecx
0x01693dcd:	jne 0x01693dc6
0x01693dcf:	jmp 0x01693d16
0x01693da9:	movl %ebx, (%esi)
0x01693dab:	subl %esi, $0xfffffffc<UINT8>
0x01693dae:	adcl %ebx, %ebx
0x01693db0:	jae 0x01693d96
0x01693d3b:	movl %ebx, (%esi)
0x01693d3d:	subl %esi, $0xfffffffc<UINT8>
0x01693d40:	adcl %ebx, %ebx
0x01693d42:	jb 0x01693d63
0x01693d49:	movl %ebx, (%esi)
0x01693d4b:	subl %esi, $0xfffffffc<UINT8>
0x01693d4e:	adcl %ebx, %ebx
0x01693dea:	popl %esi
0x01693deb:	movl %edi, %esi
0x01693ded:	movl %ecx, $0x5c75b<UINT32>
0x01693df2:	movb %al, (%edi)
0x01693df4:	incl %edi
0x01693df5:	subb %al, $0xffffffe8<UINT8>
0x01693df7:	cmpb %al, $0x1<UINT8>
0x01693df9:	ja 0x01693df2
0x01693dfb:	movl %eax, (%edi)
0x01693dfd:	movb %bl, 0x4(%edi)
0x01693e00:	xchgb %ah, %al
0x01693e02:	roll %eax, $0x10<UINT8>
0x01693e05:	xchgb %ah, %al
0x01693e07:	subl %eax, %edi
0x01693e09:	subb %bl, $0xffffffe8<UINT8>
0x01693e0c:	addl %eax, %esi
0x01693e0e:	movl (%edi), %eax
0x01693e10:	addl %edi, $0x5<UINT8>
0x01693e13:	movb %al, %bl
0x01693e15:	loop 0x01693df7
