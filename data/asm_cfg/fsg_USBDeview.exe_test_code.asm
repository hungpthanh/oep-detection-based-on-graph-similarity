0x00430000:	movl %ebx, $0x4001d0<UINT32>
0x00430005:	movl %edi, $0x401000<UINT32>
0x0043000a:	movl %esi, $0x4220a8<UINT32>
0x0043000f:	pushl %ebx
0x00430010:	call 0x0043001f
0x0043001f:	cld
0x00430020:	movb %dl, $0xffffff80<UINT8>
0x00430022:	movsb %es:(%edi), %ds:(%esi)
0x00430023:	pushl $0x2<UINT8>
0x00430025:	popl %ebx
0x00430026:	call 0x00430015
0x00430015:	addb %dl, %dl
0x00430017:	jne 0x0043001e
0x00430019:	movb %dl, (%esi)
0x0043001b:	incl %esi
0x0043001c:	adcb %dl, %dl
0x0043001e:	ret

0x00430029:	jae 0x00430022
0x0043002b:	xorl %ecx, %ecx
0x0043002d:	call 0x00430015
0x00430030:	jae 0x0043004a
0x00430032:	xorl %eax, %eax
0x00430034:	call 0x00430015
0x00430037:	jae 0x0043005a
0x00430039:	movb %bl, $0x2<UINT8>
0x0043003b:	incl %ecx
0x0043003c:	movb %al, $0x10<UINT8>
0x0043003e:	call 0x00430015
0x00430041:	adcb %al, %al
0x00430043:	jae 0x0043003e
0x00430045:	jne 0x00430086
0x00430086:	pushl %esi
0x00430087:	movl %esi, %edi
0x00430089:	subl %esi, %eax
0x0043008b:	rep movsb %es:(%edi), %ds:(%esi)
0x0043008d:	popl %esi
0x0043008e:	jmp 0x00430026
0x00430047:	stosb %es:(%edi), %al
0x00430048:	jmp 0x00430026
0x0043005a:	lodsb %al, %ds:(%esi)
0x0043005b:	shrl %eax
0x0043005d:	je 0x004300a0
0x0043005f:	adcl %ecx, %ecx
0x00430061:	jmp 0x0043007f
0x0043007f:	incl %ecx
0x00430080:	incl %ecx
0x00430081:	xchgl %ebp, %eax
0x00430082:	movl %eax, %ebp
0x00430084:	movb %bl, $0x1<UINT8>
0x0043004a:	call 0x00430092
0x00430092:	incl %ecx
0x00430093:	call 0x00430015
0x00430097:	adcl %ecx, %ecx
0x00430099:	call 0x00430015
0x0043009d:	jb 0x00430093
0x0043009f:	ret

0x0043004f:	subl %ecx, %ebx
0x00430051:	jne 0x00430063
0x00430053:	call 0x00430090
0x00430090:	xorl %ecx, %ecx
0x00430058:	jmp 0x00430082
0x00430063:	xchgl %ecx, %eax
0x00430064:	decl %eax
0x00430065:	shll %eax, $0x8<UINT8>
0x00430068:	lodsb %al, %ds:(%esi)
0x00430069:	call 0x00430090
0x0043006e:	cmpl %eax, $0x7d00<UINT32>
0x00430073:	jae 0x0043007f
0x00430075:	cmpb %ah, $0x5<UINT8>
0x00430078:	jae 0x00430080
0x0043007a:	cmpl %eax, $0x7f<UINT8>
0x0043007d:	ja 0x00430081
0x004300a0:	popl %edi
0x004300a1:	popl %ebx
0x004300a2:	movzwl %edi, (%ebx)
0x004300a5:	decl %edi
0x004300a6:	je 0x004300b0
0x004300a8:	decl %edi
0x004300a9:	je 19
0x004300ab:	shll %edi, $0xc<UINT8>
0x004300ae:	jmp 0x004300b7
0x004300b7:	incl %ebx
0x004300b8:	incl %ebx
0x004300b9:	jmp 0x0043000f
0x004300b0:	movl %edi, 0x2(%ebx)
0x004300b3:	pushl %edi
0x004300b4:	addl %ebx, $0x4<UINT8>