0x005a9000:	movl %ebx, $0x4001d0<UINT32>
0x005a9005:	movl %edi, $0x401000<UINT32>
0x005a900a:	movl %esi, $0x520ba8<UINT32>
0x005a900f:	pushl %ebx
0x005a9010:	call 0x005a901f
0x005a901f:	cld
0x005a9020:	movb %dl, $0xffffff80<UINT8>
0x005a9022:	movsb %es:(%edi), %ds:(%esi)
0x005a9023:	pushl $0x2<UINT8>
0x005a9025:	popl %ebx
0x005a9026:	call 0x005a9015
0x005a9015:	addb %dl, %dl
0x005a9017:	jne 0x005a901e
0x005a9019:	movb %dl, (%esi)
0x005a901b:	incl %esi
0x005a901c:	adcb %dl, %dl
0x005a901e:	ret

0x005a9029:	jae 0x005a9022
0x005a902b:	xorl %ecx, %ecx
0x005a902d:	call 0x005a9015
0x005a9030:	jae 0x005a904a
0x005a904a:	call 0x005a9092
0x005a9092:	incl %ecx
0x005a9093:	call 0x005a9015
0x005a9097:	adcl %ecx, %ecx
0x005a9099:	call 0x005a9015
0x005a909d:	jb 0x005a9093
0x005a909f:	ret

0x005a904f:	subl %ecx, %ebx
0x005a9051:	jne 0x005a9063
0x005a9063:	xchgl %ecx, %eax
0x005a9064:	decl %eax
0x005a9065:	shll %eax, $0x8<UINT8>
0x005a9068:	lodsb %al, %ds:(%esi)
0x005a9069:	call 0x005a9090
0x005a9090:	xorl %ecx, %ecx
0x005a906e:	cmpl %eax, $0x7d00<UINT32>
0x005a9073:	jae 0x005a907f
0x005a9075:	cmpb %ah, $0x5<UINT8>
0x005a9078:	jae 0x005a9080
0x005a907a:	cmpl %eax, $0x7f<UINT8>
0x005a907d:	ja 0x005a9081
0x005a907f:	incl %ecx
0x005a9080:	incl %ecx
0x005a9081:	xchgl %ebp, %eax
0x005a9082:	movl %eax, %ebp
0x005a9084:	movb %bl, $0x1<UINT8>
0x005a9086:	pushl %esi
0x005a9087:	movl %esi, %edi
0x005a9089:	subl %esi, %eax
0x005a908b:	rep movsb %es:(%edi), %ds:(%esi)
0x005a908d:	popl %esi
0x005a908e:	jmp 0x005a9026
0x005a9032:	xorl %eax, %eax
0x005a9034:	call 0x005a9015
0x005a9037:	jae 0x005a905a
0x005a9039:	movb %bl, $0x2<UINT8>
0x005a903b:	incl %ecx
0x005a903c:	movb %al, $0x10<UINT8>
0x005a903e:	call 0x005a9015
0x005a9041:	adcb %al, %al
0x005a9043:	jae 0x005a903e
0x005a9045:	jne 0x005a9086
0x005a9047:	stosb %es:(%edi), %al
0x005a9048:	jmp 0x005a9026
0x005a905a:	lodsb %al, %ds:(%esi)
0x005a905b:	shrl %eax
0x005a905d:	je 0x005a90a0
0x005a905f:	adcl %ecx, %ecx
0x005a9061:	jmp 0x005a907f
0x005a9053:	call 0x005a9090
0x005a9058:	jmp 0x005a9082
0x005a90a0:	popl %edi
0x005a90a1:	popl %ebx
0x005a90a2:	movzwl %edi, (%ebx)
0x005a90a5:	decl %edi
0x005a90a6:	je 0x005a90b0
0x005a90a8:	decl %edi
0x005a90a9:	je 19
0x005a90ab:	shll %edi, $0xc<UINT8>
0x005a90ae:	jmp 0x005a90b7
0x005a90b7:	incl %ebx
0x005a90b8:	incl %ebx
0x005a90b9:	jmp 0x005a900f
0x005a90b0:	movl %edi, 0x2(%ebx)
0x005a90b3:	pushl %edi
0x005a90b4:	addl %ebx, $0x4<UINT8>
