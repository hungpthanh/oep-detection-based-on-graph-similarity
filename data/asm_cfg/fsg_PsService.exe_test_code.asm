0x00443000:	movl %ebx, $0x4001d0<UINT32>
0x00443005:	movl %edi, $0x401000<UINT32>
0x0044300a:	movl %esi, $0x43021d<UINT32>
0x0044300f:	pushl %ebx
0x00443010:	call 0x0044301f
0x0044301f:	cld
0x00443020:	movb %dl, $0xffffff80<UINT8>
0x00443022:	movsb %es:(%edi), %ds:(%esi)
0x00443023:	pushl $0x2<UINT8>
0x00443025:	popl %ebx
0x00443026:	call 0x00443015
0x00443015:	addb %dl, %dl
0x00443017:	jne 0x0044301e
0x00443019:	movb %dl, (%esi)
0x0044301b:	incl %esi
0x0044301c:	adcb %dl, %dl
0x0044301e:	ret

0x00443029:	jae 0x00443022
0x0044302b:	xorl %ecx, %ecx
0x0044302d:	call 0x00443015
0x00443030:	jae 0x0044304a
0x00443032:	xorl %eax, %eax
0x00443034:	call 0x00443015
0x00443037:	jae 0x0044305a
0x00443039:	movb %bl, $0x2<UINT8>
0x0044303b:	incl %ecx
0x0044303c:	movb %al, $0x10<UINT8>
0x0044303e:	call 0x00443015
0x00443041:	adcb %al, %al
0x00443043:	jae 0x0044303e
0x00443045:	jne 0x00443086
0x00443086:	pushl %esi
0x00443087:	movl %esi, %edi
0x00443089:	subl %esi, %eax
0x0044308b:	rep movsb %es:(%edi), %ds:(%esi)
0x0044308d:	popl %esi
0x0044308e:	jmp 0x00443026
0x00443047:	stosb %es:(%edi), %al
0x00443048:	jmp 0x00443026
0x0044305a:	lodsb %al, %ds:(%esi)
0x0044305b:	shrl %eax
0x0044305d:	je 0x004430a0
0x0044305f:	adcl %ecx, %ecx
0x00443061:	jmp 0x0044307f
0x0044307f:	incl %ecx
0x00443080:	incl %ecx
0x00443081:	xchgl %ebp, %eax
0x00443082:	movl %eax, %ebp
0x00443084:	movb %bl, $0x1<UINT8>
0x0044304a:	call 0x00443092
0x00443092:	incl %ecx
0x00443093:	call 0x00443015
0x00443097:	adcl %ecx, %ecx
0x00443099:	call 0x00443015
0x0044309d:	jb 0x00443093
0x0044309f:	ret

0x0044304f:	subl %ecx, %ebx
0x00443051:	jne 0x00443063
0x00443063:	xchgl %ecx, %eax
0x00443064:	decl %eax
0x00443065:	shll %eax, $0x8<UINT8>
0x00443068:	lodsb %al, %ds:(%esi)
0x00443069:	call 0x00443090
0x00443090:	xorl %ecx, %ecx
0x0044306e:	cmpl %eax, $0x7d00<UINT32>
0x00443073:	jae 0x0044307f
0x00443075:	cmpb %ah, $0x5<UINT8>
0x00443078:	jae 0x00443080
0x0044307a:	cmpl %eax, $0x7f<UINT8>
0x0044307d:	ja 0x00443081
0x00443053:	call 0x00443090
0x00443058:	jmp 0x00443082
0x004430a0:	popl %edi
0x004430a1:	popl %ebx
0x004430a2:	movzwl %edi, (%ebx)
0x004430a5:	decl %edi
0x004430a6:	je 0x004430b0
0x004430a8:	decl %edi
0x004430a9:	je 19
0x004430ab:	shll %edi, $0xc<UINT8>
0x004430ae:	jmp 0x004430b7
0x004430b7:	incl %ebx
0x004430b8:	incl %ebx
0x004430b9:	jmp 0x0044300f
0x004430b0:	movl %edi, 0x2(%ebx)
0x004430b3:	pushl %edi
0x004430b4:	addl %ebx, $0x4<UINT8>