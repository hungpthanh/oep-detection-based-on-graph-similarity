0x0044f000:	movl %ebx, $0x4001d0<UINT32>
0x0044f005:	movl %edi, $0x401000<UINT32>
0x0044f00a:	movl %esi, $0x43821d<UINT32>
0x0044f00f:	pushl %ebx
0x0044f010:	call 0x0044f01f
0x0044f01f:	cld
0x0044f020:	movb %dl, $0xffffff80<UINT8>
0x0044f022:	movsb %es:(%edi), %ds:(%esi)
0x0044f023:	pushl $0x2<UINT8>
0x0044f025:	popl %ebx
0x0044f026:	call 0x0044f015
0x0044f015:	addb %dl, %dl
0x0044f017:	jne 0x0044f01e
0x0044f019:	movb %dl, (%esi)
0x0044f01b:	incl %esi
0x0044f01c:	adcb %dl, %dl
0x0044f01e:	ret

0x0044f029:	jae 0x0044f022
0x0044f02b:	xorl %ecx, %ecx
0x0044f02d:	call 0x0044f015
0x0044f030:	jae 0x0044f04a
0x0044f032:	xorl %eax, %eax
0x0044f034:	call 0x0044f015
0x0044f037:	jae 0x0044f05a
0x0044f039:	movb %bl, $0x2<UINT8>
0x0044f03b:	incl %ecx
0x0044f03c:	movb %al, $0x10<UINT8>
0x0044f03e:	call 0x0044f015
0x0044f041:	adcb %al, %al
0x0044f043:	jae 0x0044f03e
0x0044f045:	jne 0x0044f086
0x0044f086:	pushl %esi
0x0044f087:	movl %esi, %edi
0x0044f089:	subl %esi, %eax
0x0044f08b:	rep movsb %es:(%edi), %ds:(%esi)
0x0044f08d:	popl %esi
0x0044f08e:	jmp 0x0044f026
0x0044f04a:	call 0x0044f092
0x0044f092:	incl %ecx
0x0044f093:	call 0x0044f015
0x0044f097:	adcl %ecx, %ecx
0x0044f099:	call 0x0044f015
0x0044f09d:	jb 0x0044f093
0x0044f09f:	ret

0x0044f04f:	subl %ecx, %ebx
0x0044f051:	jne 0x0044f063
0x0044f063:	xchgl %ecx, %eax
0x0044f064:	decl %eax
0x0044f065:	shll %eax, $0x8<UINT8>
0x0044f068:	lodsb %al, %ds:(%esi)
0x0044f069:	call 0x0044f090
0x0044f090:	xorl %ecx, %ecx
0x0044f06e:	cmpl %eax, $0x7d00<UINT32>
0x0044f073:	jae 0x0044f07f
0x0044f075:	cmpb %ah, $0x5<UINT8>
0x0044f078:	jae 0x0044f080
0x0044f07a:	cmpl %eax, $0x7f<UINT8>
0x0044f07d:	ja 0x0044f081
0x0044f07f:	incl %ecx
0x0044f080:	incl %ecx
0x0044f081:	xchgl %ebp, %eax
0x0044f082:	movl %eax, %ebp
0x0044f084:	movb %bl, $0x1<UINT8>
0x0044f047:	stosb %es:(%edi), %al
0x0044f048:	jmp 0x0044f026
0x0044f05a:	lodsb %al, %ds:(%esi)
0x0044f05b:	shrl %eax
0x0044f05d:	je 0x0044f0a0
0x0044f05f:	adcl %ecx, %ecx
0x0044f061:	jmp 0x0044f07f
0x0044f053:	call 0x0044f090
0x0044f058:	jmp 0x0044f082
0x0044f0a0:	popl %edi
0x0044f0a1:	popl %ebx
0x0044f0a2:	movzwl %edi, (%ebx)
0x0044f0a5:	decl %edi
0x0044f0a6:	je 0x0044f0b0
0x0044f0a8:	decl %edi
0x0044f0a9:	je 19
0x0044f0ab:	shll %edi, $0xc<UINT8>
0x0044f0ae:	jmp 0x0044f0b7
0x0044f0b7:	incl %ebx
0x0044f0b8:	incl %ebx
0x0044f0b9:	jmp 0x0044f00f
0x0044f0b0:	movl %edi, 0x2(%ebx)
0x0044f0b3:	pushl %edi
0x0044f0b4:	addl %ebx, $0x4<UINT8>
