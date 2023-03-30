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
0x005a90a9:	je 0x005a90be
0x005a90ab:	shll %edi, $0xc<UINT8>
0x005a90ae:	jmp 0x005a90b7
0x005a90b7:	incl %ebx
0x005a90b8:	incl %ebx
0x005a90b9:	jmp 0x005a900f
0x005a90b0:	movl %edi, 0x2(%ebx)
0x005a90b3:	pushl %edi
0x005a90b4:	addl %ebx, $0x4<UINT8>
0x005a90be:	popl %edi
0x005a90bf:	movl %ebx, $0x5a9128<UINT32>
0x005a90c4:	incl %edi
0x005a90c5:	movl %esi, (%edi)
0x005a90c7:	scasl %eax, %es:(%edi)
0x005a90c8:	pushl %edi
0x005a90c9:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x005a90cb:	xchgl %ebp, %eax
0x005a90cc:	xorl %eax, %eax
0x005a90ce:	scasb %al, %es:(%edi)
0x005a90cf:	jne 0x005a90ce
0x005a90d1:	decb (%edi)
0x005a90d3:	je 0x005a90c4
0x005a90d5:	decb (%edi)
0x005a90d7:	jne 0x005a90df
0x005a90df:	decb (%edi)
0x005a90e1:	je -1263685
0x005a90e7:	pushl %edi
0x005a90e8:	pushl %ebp
0x005a90e9:	call GetProcAddress@kernel32.dll
GetProcAddress@kernel32.dll: API Node	
0x005a90ec:	orl (%esi), %eax
0x005a90ee:	lodsl %eax, %ds:(%esi)
0x005a90ef:	jne 0x005a90cc
0x005a90d9:	incl %edi
0x005a90da:	pushl (%edi)
0x005a90dc:	scasl %eax, %es:(%edi)
0x005a90dd:	jmp 0x005a90e8
0x005a90f1:	movl %ebp, %esp
0x005a90f3:	ret

0x7c8000c0:	addb (%eax), %al
0x7c8000c2:	addb (%eax), %al
0x7c8000c4:	addb (%eax), %al
0x7c8000c6:	addb (%eax), %al
0x7c8000c8:	addb (%eax), %al
0x7c8000ca:	addb (%eax), %al
0x7c8000cc:	addb (%eax), %al
0x7c8000ce:	addb (%eax), %al
0x7c8000d0:	addb (%eax), %al
0x7c8000d2:	addb (%eax), %al
0x7c8000d4:	addb (%eax), %al
0x7c8000d6:	addb (%eax), %al
0x7c8000d8:	addb (%eax), %al
0x7c8000da:	addb (%eax), %al
0x7c8000dc:	addb (%eax), %al
0x7c8000de:	addb (%eax), %al
0x7c8000e0:	addb (%eax), %al
0x7c8000e2:	addb (%eax), %al
0x7c8000e4:	addb (%eax), %al
0x7c8000e6:	addb (%eax), %al
0x7c8000e8:	addb (%eax), %al
0x7c8000ea:	addb (%eax), %al
0x7c8000ec:	addb (%eax), %al
0x7c8000ee:	addb (%eax), %al
0x7c8000f0:	addb (%eax), %al
0x7c8000f2:	addb (%eax), %al
0x7c8000f4:	addb (%eax), %al
0x7c8000f6:	addb (%eax), %al
0x7c8000f8:	addb (%eax), %al
0x7c8000fa:	addb (%eax), %al
0x7c8000fc:	addb (%eax), %al
0x7c8000fe:	addb (%eax), %al
0x7c800100:	addb (%eax), %al
0x7c800102:	addb (%eax), %al
0x7c800104:	addb (%eax), %al
0x7c800106:	addb (%eax), %al
0x7c800108:	addb (%eax), %al
0x7c80010a:	addb (%eax), %al
0x7c80010c:	addb (%eax), %al
0x7c80010e:	addb (%eax), %al
0x7c800110:	addb (%eax), %al
0x7c800112:	addb (%eax), %al
0x7c800114:	addb (%eax), %al
0x7c800116:	addb (%eax), %al
0x7c800118:	addb (%eax), %al
0x7c80011a:	addb (%eax), %al
0x7c80011c:	addb (%eax), %al
0x7c80011e:	addb (%eax), %al
0x7c800120:	addb (%eax), %al
0x7c800122:	addb (%eax), %al
0x7c800124:	addb (%eax), %al
0x7c800126:	addb (%eax), %al
