0x00805000:	movl %ebx, $0x4001d0<UINT32>
0x00805005:	movl %edi, $0x401000<UINT32>
0x0080500a:	movl %esi, $0x6c5dda<UINT32>
0x0080500f:	pushl %ebx
0x00805010:	call 0x0080501f
0x0080501f:	cld
0x00805020:	movb %dl, $0xffffff80<UINT8>
0x00805022:	movsb %es:(%edi), %ds:(%esi)
0x00805023:	pushl $0x2<UINT8>
0x00805025:	popl %ebx
0x00805026:	call 0x00805015
0x00805015:	addb %dl, %dl
0x00805017:	jne 0x0080501e
0x00805019:	movb %dl, (%esi)
0x0080501b:	incl %esi
0x0080501c:	adcb %dl, %dl
0x0080501e:	ret

0x00805029:	jae 0x00805022
0x0080502b:	xorl %ecx, %ecx
0x0080502d:	call 0x00805015
0x00805030:	jae 0x0080504a
0x00805032:	xorl %eax, %eax
0x00805034:	call 0x00805015
0x00805037:	jae 0x0080505a
0x00805039:	movb %bl, $0x2<UINT8>
0x0080503b:	incl %ecx
0x0080503c:	movb %al, $0x10<UINT8>
0x0080503e:	call 0x00805015
0x00805041:	adcb %al, %al
0x00805043:	jae 0x0080503e
0x00805045:	jne 0x00805086
0x00805047:	stosb %es:(%edi), %al
0x00805048:	jmp 0x00805026
0x0080505a:	lodsb %al, %ds:(%esi)
0x0080505b:	shrl %eax
0x0080505d:	je 0x008050a0
0x0080505f:	adcl %ecx, %ecx
0x00805061:	jmp 0x0080507f
0x0080507f:	incl %ecx
0x00805080:	incl %ecx
0x00805081:	xchgl %ebp, %eax
0x00805082:	movl %eax, %ebp
0x00805084:	movb %bl, $0x1<UINT8>
0x00805086:	pushl %esi
0x00805087:	movl %esi, %edi
0x00805089:	subl %esi, %eax
0x0080508b:	rep movsb %es:(%edi), %ds:(%esi)
0x0080508d:	popl %esi
0x0080508e:	jmp 0x00805026
0x0080504a:	call 0x00805092
0x00805092:	incl %ecx
0x00805093:	call 0x00805015
0x00805097:	adcl %ecx, %ecx
0x00805099:	call 0x00805015
0x0080509d:	jb 0x00805093
0x0080509f:	ret

0x0080504f:	subl %ecx, %ebx
0x00805051:	jne 0x00805063
0x00805063:	xchgl %ecx, %eax
0x00805064:	decl %eax
0x00805065:	shll %eax, $0x8<UINT8>
0x00805068:	lodsb %al, %ds:(%esi)
0x00805069:	call 0x00805090
0x00805090:	xorl %ecx, %ecx
0x0080506e:	cmpl %eax, $0x7d00<UINT32>
0x00805073:	jae 0x0080507f
0x00805075:	cmpb %ah, $0x5<UINT8>
0x00805078:	jae 0x00805080
0x0080507a:	cmpl %eax, $0x7f<UINT8>
0x0080507d:	ja 0x00805081
0x00805053:	call 0x00805090
0x00805058:	jmp 0x00805082
0x008050a0:	popl %edi
0x008050a1:	popl %ebx
0x008050a2:	movzwl %edi, (%ebx)
0x008050a5:	decl %edi
0x008050a6:	je 0x008050b0
0x008050a8:	decl %edi
0x008050a9:	je 19
0x008050ab:	shll %edi, $0xc<UINT8>
0x008050ae:	jmp 0x008050b7
0x008050b7:	incl %ebx
0x008050b8:	incl %ebx
0x008050b9:	jmp 0x0080500f
0x008050b0:	movl %edi, 0x2(%ebx)
0x008050b3:	pushl %edi
0x008050b4:	addl %ebx, $0x4<UINT8>