0x0051e000:	movl %ebx, $0x4001d0<UINT32>
0x0051e005:	movl %edi, $0x401000<UINT32>
0x0051e00a:	movl %esi, $0x50bb05<UINT32>
0x0051e00f:	pushl %ebx
0x0051e010:	call 0x0051e01f
0x0051e01f:	cld
0x0051e020:	movb %dl, $0xffffff80<UINT8>
0x0051e022:	movsb %es:(%edi), %ds:(%esi)
0x0051e023:	pushl $0x2<UINT8>
0x0051e025:	popl %ebx
0x0051e026:	call 0x0051e015
0x0051e015:	addb %dl, %dl
0x0051e017:	jne 0x0051e01e
0x0051e019:	movb %dl, (%esi)
0x0051e01b:	incl %esi
0x0051e01c:	adcb %dl, %dl
0x0051e01e:	ret

0x0051e029:	jae 0x0051e022
0x0051e02b:	xorl %ecx, %ecx
0x0051e02d:	call 0x0051e015
0x0051e030:	jae 0x0051e04a
0x0051e04a:	call 0x0051e092
0x0051e092:	incl %ecx
0x0051e093:	call 0x0051e015
0x0051e097:	adcl %ecx, %ecx
0x0051e099:	call 0x0051e015
0x0051e09d:	jb 0x0051e093
0x0051e09f:	ret

0x0051e04f:	subl %ecx, %ebx
0x0051e051:	jne 0x0051e063
0x0051e063:	xchgl %ecx, %eax
0x0051e064:	decl %eax
0x0051e065:	shll %eax, $0x8<UINT8>
0x0051e068:	lodsb %al, %ds:(%esi)
0x0051e069:	call 0x0051e090
0x0051e090:	xorl %ecx, %ecx
0x0051e06e:	cmpl %eax, $0x7d00<UINT32>
0x0051e073:	jae 0x0051e07f
0x0051e075:	cmpb %ah, $0x5<UINT8>
0x0051e078:	jae 0x0051e080
0x0051e07a:	cmpl %eax, $0x7f<UINT8>
0x0051e07d:	ja 0x0051e081
0x0051e07f:	incl %ecx
0x0051e080:	incl %ecx
0x0051e081:	xchgl %ebp, %eax
0x0051e082:	movl %eax, %ebp
0x0051e084:	movb %bl, $0x1<UINT8>
0x0051e086:	pushl %esi
0x0051e087:	movl %esi, %edi
0x0051e089:	subl %esi, %eax
0x0051e08b:	rep movsb %es:(%edi), %ds:(%esi)
0x0051e08d:	popl %esi
0x0051e08e:	jmp 0x0051e026
0x0051e032:	xorl %eax, %eax
0x0051e034:	call 0x0051e015
0x0051e037:	jae 0x0051e05a
0x0051e039:	movb %bl, $0x2<UINT8>
0x0051e03b:	incl %ecx
0x0051e03c:	movb %al, $0x10<UINT8>
0x0051e03e:	call 0x0051e015
0x0051e041:	adcb %al, %al
0x0051e043:	jae 0x0051e03e
0x0051e045:	jne 0x0051e086
0x0051e047:	stosb %es:(%edi), %al
0x0051e048:	jmp 0x0051e026
0x0051e05a:	lodsb %al, %ds:(%esi)
0x0051e05b:	shrl %eax
0x0051e05d:	je 0x0051e0a0
0x0051e05f:	adcl %ecx, %ecx
0x0051e061:	jmp 0x0051e07f
0x0051e053:	call 0x0051e090
0x0051e058:	jmp 0x0051e082
0x0051e0a0:	popl %edi
0x0051e0a1:	popl %ebx
0x0051e0a2:	movzwl %edi, (%ebx)
0x0051e0a5:	decl %edi
0x0051e0a6:	je 8
0x0051e0a8:	decl %edi
0x0051e0a9:	je 19
0x0051e0ab:	shll %edi, $0xc<UINT8>
0x0051e0ae:	jmp 0x0051e0b7
0x0051e0b7:	incl %ebx
0x0051e0b8:	incl %ebx
0x0051e0b9:	jmp 0x0051e00f
0x0051e08d:	addb (%eax), %al
0x0051e08f:	addb (%eax), %al
0x0051e091:	addb (%eax), %al
0x0051e093:	addb (%eax), %al
0x0051e095:	addb (%eax), %al
0x0051e097:	addb (%eax), %al
0x0051e099:	addb (%eax), %al
0x0051e09b:	addb (%eax), %al
0x0051e09d:	addb (%eax), %al
0x0051e09f:	addb (%eax), %al
0x0051e0a1:	addb (%eax), %al
0x0051e0a3:	addb (%eax), %al
0x0051e0a5:	addb (%eax), %al
0x0051e0a7:	addb (%eax), %al
0x0051e0a9:	addb (%eax), %al
0x0051e0ab:	addb (%eax), %al
0x0051e0ad:	addb (%eax), %al
0x0051e0af:	addb (%eax), %al
0x0051e0b1:	addb (%eax), %al
0x0051e0b3:	addb (%eax), %al
0x0051e0b5:	addb (%eax), %al
0x0051e0b7:	addb (%eax), %al
0x0051e0b9:	addb (%eax), %al
0x0051e0bb:	addb (%eax), %al
0x0051e0bd:	addb (%eax), %al
0x0051e0bf:	addb (%eax), %al
0x0051e0c1:	addb (%eax), %al
0x0051e0c3:	addb (%eax), %al
0x0051e0c5:	addb (%eax), %al
0x0051e0c7:	addb (%eax), %al
0x0051e0c9:	addb (%eax), %al
0x0051e0cb:	addb (%eax), %al
0x0051e0cd:	addb (%eax), %al
0x0051e0cf:	addb (%eax), %al
0x0051e0d1:	addb (%eax), %al
0x0051e0d3:	addb (%eax), %al
0x0051e0d5:	addb (%eax), %al
0x0051e0d7:	addb (%eax), %al
0x0051e0d9:	addb (%eax), %al
0x0051e0db:	addb (%eax), %al
0x0051e0dd:	addb (%eax), %al
0x0051e0df:	addb (%eax), %al
0x0051e0e1:	addb (%eax), %al
0x0051e0e3:	addb (%eax), %al
0x0051e0e5:	addb (%eax), %al
0x0051e0e7:	addb (%eax), %al
0x0051e0e9:	addb (%eax), %al
0x0051e0eb:	addb (%eax), %al
0x0051e0ed:	addb (%eax), %al
0x0051e0ef:	addb (%eax), %al
0x0051e0f1:	addb (%eax), %al
0x0051e0f3:	addb (%eax), %al
