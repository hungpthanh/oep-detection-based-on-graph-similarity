0x00416000:	movl %ebx, $0x4001d0<UINT32>
0x00416005:	movl %edi, $0x401000<UINT32>
0x0041600a:	movl %esi, $0x412c51<UINT32>
0x0041600f:	pushl %ebx
0x00416010:	call 0x0041601f
0x0041601f:	cld
0x00416020:	movb %dl, $0xffffff80<UINT8>
0x00416022:	movsb %es:(%edi), %ds:(%esi)
0x00416023:	pushl $0x2<UINT8>
0x00416025:	popl %ebx
0x00416026:	call 0x00416015
0x00416015:	addb %dl, %dl
0x00416017:	jne 0x0041601e
0x00416019:	movb %dl, (%esi)
0x0041601b:	incl %esi
0x0041601c:	adcb %dl, %dl
0x0041601e:	ret

0x00416029:	jae 0x00416022
0x0041602b:	xorl %ecx, %ecx
0x0041602d:	call 0x00416015
0x00416030:	jae 0x0041604a
0x00416032:	xorl %eax, %eax
0x00416034:	call 0x00416015
0x00416037:	jae 0x0041605a
0x00416039:	movb %bl, $0x2<UINT8>
0x0041603b:	incl %ecx
0x0041603c:	movb %al, $0x10<UINT8>
0x0041603e:	call 0x00416015
0x00416041:	adcb %al, %al
0x00416043:	jae 0x0041603e
0x00416045:	jne 0x00416086
0x00416086:	pushl %esi
0x00416087:	movl %esi, %edi
0x00416089:	subl %esi, %eax
0x0041608b:	rep movsb %es:(%edi), %ds:(%esi)
0x0041608d:	popl %esi
0x0041608e:	jmp 0x00416026
0x00416047:	stosb %es:(%edi), %al
0x00416048:	jmp 0x00416026
0x0041605a:	lodsb %al, %ds:(%esi)
0x0041605b:	shrl %eax
0x0041605d:	je 0x004160a0
0x0041605f:	adcl %ecx, %ecx
0x00416061:	jmp 0x0041607f
0x0041607f:	incl %ecx
0x00416080:	incl %ecx
0x00416081:	xchgl %ebp, %eax
0x00416082:	movl %eax, %ebp
0x00416084:	movb %bl, $0x1<UINT8>
0x0041604a:	call 0x00416092
0x00416092:	incl %ecx
0x00416093:	call 0x00416015
0x00416097:	adcl %ecx, %ecx
0x00416099:	call 0x00416015
0x0041609d:	jb 0x00416093
0x0041609f:	ret

0x0041604f:	subl %ecx, %ebx
0x00416051:	jne 0x00416063
0x00416063:	xchgl %ecx, %eax
0x00416064:	decl %eax
0x00416065:	shll %eax, $0x8<UINT8>
0x00416068:	lodsb %al, %ds:(%esi)
0x00416069:	call 0x00416090
0x00416090:	xorl %ecx, %ecx
0x0041606e:	cmpl %eax, $0x7d00<UINT32>
0x00416073:	jae 10
0x00416075:	cmpb %ah, $0x5<UINT8>
0x00416078:	jae 0x00416080
0x0041607a:	cmpl %eax, $0x7f<UINT8>
0x0041607d:	ja 0x00416081
0x00416053:	call 0x00416090
0x00416058:	jmp 0x00416082
0x004160a0:	popl %edi
0x004160a1:	popl %ebx
0x004160a2:	movzwl %edi, (%ebx)
0x004160a5:	decl %edi
0x004160a6:	je 0x004160b0
0x004160a8:	decl %edi
0x004160a9:	je 19
0x004160ab:	shll %edi, $0xc<UINT8>
0x004160ae:	jmp 0x004160b7
0x004160b7:	incl %ebx
0x004160b8:	incl %ebx
0x004160b9:	jmp 0x0041600f
0x004160b0:	movl %edi, 0x2(%ebx)
0x004160b3:	pushl %edi
0x004160b4:	addl %ebx, $0x4<UINT8>
