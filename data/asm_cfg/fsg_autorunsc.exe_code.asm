0x004d7000:	movl %ebx, $0x4001d0<UINT32>
0x004d7005:	movl %edi, $0x401000<UINT32>
0x004d700a:	movl %esi, $0x49dc9c<UINT32>
0x004d700f:	pushl %ebx
0x004d7010:	call 0x004d701f
0x004d701f:	cld
0x004d7020:	movb %dl, $0xffffff80<UINT8>
0x004d7022:	movsb %es:(%edi), %ds:(%esi)
0x004d7023:	pushl $0x2<UINT8>
0x004d7025:	popl %ebx
0x004d7026:	call 0x004d7015
0x004d7015:	addb %dl, %dl
0x004d7017:	jne 0x004d701e
0x004d7019:	movb %dl, (%esi)
0x004d701b:	incl %esi
0x004d701c:	adcb %dl, %dl
0x004d701e:	ret

0x004d7029:	jae 0x004d7022
0x004d702b:	xorl %ecx, %ecx
0x004d702d:	call 0x004d7015
0x004d7030:	jae 0x004d704a
0x004d7032:	xorl %eax, %eax
0x004d7034:	call 0x004d7015
0x004d7037:	jae 0x004d705a
0x004d7039:	movb %bl, $0x2<UINT8>
0x004d703b:	incl %ecx
0x004d703c:	movb %al, $0x10<UINT8>
0x004d703e:	call 0x004d7015
0x004d7041:	adcb %al, %al
0x004d7043:	jae 0x004d703e
0x004d7045:	jne 0x004d7086
0x004d7047:	stosb %es:(%edi), %al
0x004d7048:	jmp 0x004d7026
0x004d7086:	pushl %esi
0x004d7087:	movl %esi, %edi
0x004d7089:	subl %esi, %eax
0x004d708b:	rep movsb %es:(%edi), %ds:(%esi)
0x004d708d:	popl %esi
0x004d708e:	jmp 0x004d7026
0x004d705a:	lodsb %al, %ds:(%esi)
0x004d705b:	shrl %eax
0x004d705d:	je 0x004d70a0
0x004d705f:	adcl %ecx, %ecx
0x004d7061:	jmp 0x004d707f
0x004d707f:	incl %ecx
0x004d7080:	incl %ecx
0x004d7081:	xchgl %ebp, %eax
0x004d7082:	movl %eax, %ebp
0x004d7084:	movb %bl, $0x1<UINT8>
0x004d704a:	call 0x004d7092
0x004d7092:	incl %ecx
0x004d7093:	call 0x004d7015
0x004d7097:	adcl %ecx, %ecx
0x004d7099:	call 0x004d7015
0x004d709d:	jb 0x004d7093
0x004d709f:	ret

0x004d704f:	subl %ecx, %ebx
0x004d7051:	jne 0x004d7063
0x004d7053:	call 0x004d7090
0x004d7090:	xorl %ecx, %ecx
0x004d7058:	jmp 0x004d7082
0x004d7063:	xchgl %ecx, %eax
0x004d7064:	decl %eax
0x004d7065:	shll %eax, $0x8<UINT8>
0x004d7068:	lodsb %al, %ds:(%esi)
0x004d7069:	call 0x004d7090
0x004d706e:	cmpl %eax, $0x7d00<UINT32>
0x004d7073:	jae 0x004d707f
0x004d7075:	cmpb %ah, $0x5<UINT8>
0x004d7078:	jae 0x004d7080
0x004d707a:	cmpl %eax, $0x7f<UINT8>
0x004d707d:	ja 0x004d7081
0x004d70a0:	popl %edi
0x004d70a1:	popl %ebx
0x004d70a2:	movzwl %edi, (%ebx)
0x004d70a5:	decl %edi
0x004d70a6:	je 0x004d70b0
0x004d70a8:	decl %edi
0x004d70a9:	je 0x004d70be
0x004d70ab:	shll %edi, $0xc<UINT8>
0x004d70ae:	jmp 0x004d70b7
0x004d70b7:	incl %ebx
0x004d70b8:	incl %ebx
0x004d70b9:	jmp 0x004d700f
0x004d70b0:	movl %edi, 0x2(%ebx)
0x004d70b3:	pushl %edi
0x004d70b4:	addl %ebx, $0x4<UINT8>
0x004d70be:	popl %edi
0x004d70bf:	movl %ebx, $0x4d7128<UINT32>
0x004d70c4:	incl %edi
0x004d70c5:	movl %esi, (%edi)
0x004d70c7:	scasl %eax, %es:(%edi)
0x004d70c8:	pushl %edi
0x004d70c9:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004d70cb:	xchgl %ebp, %eax
0x004d70cc:	xorl %eax, %eax
0x004d70ce:	scasb %al, %es:(%edi)
0x004d70cf:	jne 0x004d70ce
0x004d70d1:	decb (%edi)
0x004d70d3:	je 0x004d70c4
0x004d70d5:	decb (%edi)
0x004d70d7:	jne 0x004d70df
0x004d70df:	decb (%edi)
0x004d70e1:	je -616458
0x004d70e7:	pushl %edi
0x004d70e8:	pushl %ebp
0x004d70e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x004d70ec:	orl (%esi), %eax
0x004d70ee:	lodsl %eax, %ds:(%esi)
0x004d70ef:	jne 0x004d70cc
GetProcAddress@KERNEL32.dll: API Node	
0x004d70d9:	incl %edi
0x004d70da:	pushl (%edi)
0x004d70dc:	scasl %eax, %es:(%edi)
0x004d70dd:	jmp 0x004d70e8
0x004d70f1:	movl %ebp, %esp
0x004d70f3:	ret

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
