0x00424000:	movl %ebx, $0x4001d0<UINT32>
0x00424005:	movl %edi, $0x401000<UINT32>
0x0042400a:	movl %esi, $0x419b46<UINT32>
0x0042400f:	pushl %ebx
0x00424010:	call 0x0042401f
0x0042401f:	cld
0x00424020:	movb %dl, $0xffffff80<UINT8>
0x00424022:	movsb %es:(%edi), %ds:(%esi)
0x00424023:	pushl $0x2<UINT8>
0x00424025:	popl %ebx
0x00424026:	call 0x00424015
0x00424015:	addb %dl, %dl
0x00424017:	jne 0x0042401e
0x00424019:	movb %dl, (%esi)
0x0042401b:	incl %esi
0x0042401c:	adcb %dl, %dl
0x0042401e:	ret

0x00424029:	jae 0x00424022
0x0042402b:	xorl %ecx, %ecx
0x0042402d:	call 0x00424015
0x00424030:	jae 0x0042404a
0x00424032:	xorl %eax, %eax
0x00424034:	call 0x00424015
0x00424037:	jae 0x0042405a
0x00424039:	movb %bl, $0x2<UINT8>
0x0042403b:	incl %ecx
0x0042403c:	movb %al, $0x10<UINT8>
0x0042403e:	call 0x00424015
0x00424041:	adcb %al, %al
0x00424043:	jae 0x0042403e
0x00424045:	jne 0x00424086
0x00424086:	pushl %esi
0x00424087:	movl %esi, %edi
0x00424089:	subl %esi, %eax
0x0042408b:	rep movsb %es:(%edi), %ds:(%esi)
0x0042408d:	popl %esi
0x0042408e:	jmp 0x00424026
0x00424047:	stosb %es:(%edi), %al
0x00424048:	jmp 0x00424026
0x0042405a:	lodsb %al, %ds:(%esi)
0x0042405b:	shrl %eax
0x0042405d:	je 0x004240a0
0x0042405f:	adcl %ecx, %ecx
0x00424061:	jmp 0x0042407f
0x0042407f:	incl %ecx
0x00424080:	incl %ecx
0x00424081:	xchgl %ebp, %eax
0x00424082:	movl %eax, %ebp
0x00424084:	movb %bl, $0x1<UINT8>
0x0042404a:	call 0x00424092
0x00424092:	incl %ecx
0x00424093:	call 0x00424015
0x00424097:	adcl %ecx, %ecx
0x00424099:	call 0x00424015
0x0042409d:	jb 0x00424093
0x0042409f:	ret

0x0042404f:	subl %ecx, %ebx
0x00424051:	jne 0x00424063
0x00424063:	xchgl %ecx, %eax
0x00424064:	decl %eax
0x00424065:	shll %eax, $0x8<UINT8>
0x00424068:	lodsb %al, %ds:(%esi)
0x00424069:	call 0x00424090
0x00424090:	xorl %ecx, %ecx
0x0042406e:	cmpl %eax, $0x7d00<UINT32>
0x00424073:	jae 0x0042407f
0x00424075:	cmpb %ah, $0x5<UINT8>
0x00424078:	jae 0x00424080
0x0042407a:	cmpl %eax, $0x7f<UINT8>
0x0042407d:	ja 0x00424081
0x00424053:	call 0x00424090
0x00424058:	jmp 0x00424082
0x004240a0:	popl %edi
0x004240a1:	popl %ebx
0x004240a2:	movzwl %edi, (%ebx)
0x004240a5:	decl %edi
0x004240a6:	je 0x004240b0
0x004240a8:	decl %edi
0x004240a9:	je 19
0x004240ab:	shll %edi, $0xc<UINT8>
0x004240ae:	jmp 0x004240b7
0x004240b7:	incl %ebx
0x004240b8:	incl %ebx
0x004240b9:	jmp 0x0042400f
0x004240b0:	movl %edi, 0x2(%ebx)
0x004240b3:	pushl %edi
0x004240b4:	addl %ebx, $0x4<UINT8>
