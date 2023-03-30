0x0041c000:	movl %ebx, $0x4001d0<UINT32>
0x0041c005:	movl %edi, $0x401000<UINT32>
0x0041c00a:	movl %esi, $0x414610<UINT32>
0x0041c00f:	pushl %ebx
0x0041c010:	call 0x0041c01f
0x0041c01f:	cld
0x0041c020:	movb %dl, $0xffffff80<UINT8>
0x0041c022:	movsb %es:(%edi), %ds:(%esi)
0x0041c023:	pushl $0x2<UINT8>
0x0041c025:	popl %ebx
0x0041c026:	call 0x0041c015
0x0041c015:	addb %dl, %dl
0x0041c017:	jne 0x0041c01e
0x0041c019:	movb %dl, (%esi)
0x0041c01b:	incl %esi
0x0041c01c:	adcb %dl, %dl
0x0041c01e:	ret

0x0041c029:	jae 0x0041c022
0x0041c02b:	xorl %ecx, %ecx
0x0041c02d:	call 0x0041c015
0x0041c030:	jae 0x0041c04a
0x0041c032:	xorl %eax, %eax
0x0041c034:	call 0x0041c015
0x0041c037:	jae 0x0041c05a
0x0041c039:	movb %bl, $0x2<UINT8>
0x0041c03b:	incl %ecx
0x0041c03c:	movb %al, $0x10<UINT8>
0x0041c03e:	call 0x0041c015
0x0041c041:	adcb %al, %al
0x0041c043:	jae 0x0041c03e
0x0041c045:	jne 0x0041c086
0x0041c047:	stosb %es:(%edi), %al
0x0041c048:	jmp 0x0041c026
0x0041c05a:	lodsb %al, %ds:(%esi)
0x0041c05b:	shrl %eax
0x0041c05d:	je 0x0041c0a0
0x0041c05f:	adcl %ecx, %ecx
0x0041c061:	jmp 0x0041c07f
0x0041c07f:	incl %ecx
0x0041c080:	incl %ecx
0x0041c081:	xchgl %ebp, %eax
0x0041c082:	movl %eax, %ebp
0x0041c084:	movb %bl, $0x1<UINT8>
0x0041c086:	pushl %esi
0x0041c087:	movl %esi, %edi
0x0041c089:	subl %esi, %eax
0x0041c08b:	rep movsb %es:(%edi), %ds:(%esi)
0x0041c08d:	popl %esi
0x0041c08e:	jmp 0x0041c026
0x0041c04a:	call 0x0041c092
0x0041c092:	incl %ecx
0x0041c093:	call 0x0041c015
0x0041c097:	adcl %ecx, %ecx
0x0041c099:	call 0x0041c015
0x0041c09d:	jb 0x0041c093
0x0041c09f:	ret

0x0041c04f:	subl %ecx, %ebx
0x0041c051:	jne 0x0041c063
0x0041c063:	xchgl %ecx, %eax
0x0041c064:	decl %eax
0x0041c065:	shll %eax, $0x8<UINT8>
0x0041c068:	lodsb %al, %ds:(%esi)
0x0041c069:	call 0x0041c090
0x0041c090:	xorl %ecx, %ecx
0x0041c06e:	cmpl %eax, $0x7d00<UINT32>
0x0041c073:	jae 0x0041c07f
0x0041c075:	cmpb %ah, $0x5<UINT8>
0x0041c078:	jae 0x0041c080
0x0041c07a:	cmpl %eax, $0x7f<UINT8>
0x0041c07d:	ja 0x0041c081
0x0041c053:	call 0x0041c090
0x0041c058:	jmp 0x0041c082
0x0041c0a0:	popl %edi
0x0041c0a1:	popl %ebx
0x0041c0a2:	movzwl %edi, (%ebx)
0x0041c0a5:	decl %edi
0x0041c0a6:	je 0x0041c0b0
0x0041c0a8:	decl %edi
0x0041c0a9:	je 0x0041c0be
0x0041c0ab:	shll %edi, $0xc<UINT8>
0x0041c0ae:	jmp 0x0041c0b7
0x0041c0b7:	incl %ebx
0x0041c0b8:	incl %ebx
0x0041c0b9:	jmp 0x0041c00f
0x0041c0b0:	movl %edi, 0x2(%ebx)
0x0041c0b3:	pushl %edi
0x0041c0b4:	addl %ebx, $0x4<UINT8>
0x0041c0be:	popl %edi
0x0041c0bf:	movl %ebx, $0x41c128<UINT32>
0x0041c0c4:	incl %edi
0x0041c0c5:	movl %esi, (%edi)
0x0041c0c7:	scasl %eax, %es:(%edi)
0x0041c0c8:	pushl %edi
0x0041c0c9:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0041c0cb:	xchgl %ebp, %eax
0x0041c0cc:	xorl %eax, %eax
0x0041c0ce:	scasb %al, %es:(%edi)
0x0041c0cf:	jne 0x0041c0ce
0x0041c0d1:	decb (%edi)
0x0041c0d3:	je -17
0x0041c0d5:	decb (%edi)
0x0041c0d7:	jne 6
0x0041c0d9:	incl %edi
0x0041c0da:	pushl (%edi)
0x0041c0dc:	scasl %eax, %es:(%edi)
0x0041c0dd:	jmp 0x0041c0e8
0x0041c0e8:	pushl %ebp
0x0041c0e9:	call GetProcAddress@kernel32.dll
GetProcAddress@kernel32.dll: API Node	
0x0041c0ec:	orl (%esi), %eax
0x0041c0ee:	lodsl %eax, %ds:(%esi)
0x0041c0ef:	jne -37
0x0041c0f1:	movl %ebp, %esp
0x0041c0f3:	ret

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
