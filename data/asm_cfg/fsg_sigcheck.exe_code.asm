0x0047f000:	movl %ebx, $0x4001d0<UINT32>
0x0047f005:	movl %edi, $0x401000<UINT32>
0x0047f00a:	movl %esi, $0x45a71f<UINT32>
0x0047f00f:	pushl %ebx
0x0047f010:	call 0x0047f01f
0x0047f01f:	cld
0x0047f020:	movb %dl, $0xffffff80<UINT8>
0x0047f022:	movsb %es:(%edi), %ds:(%esi)
0x0047f023:	pushl $0x2<UINT8>
0x0047f025:	popl %ebx
0x0047f026:	call 0x0047f015
0x0047f015:	addb %dl, %dl
0x0047f017:	jne 0x0047f01e
0x0047f019:	movb %dl, (%esi)
0x0047f01b:	incl %esi
0x0047f01c:	adcb %dl, %dl
0x0047f01e:	ret

0x0047f029:	jae 0x0047f022
0x0047f02b:	xorl %ecx, %ecx
0x0047f02d:	call 0x0047f015
0x0047f030:	jae 0x0047f04a
0x0047f032:	xorl %eax, %eax
0x0047f034:	call 0x0047f015
0x0047f037:	jae 0x0047f05a
0x0047f039:	movb %bl, $0x2<UINT8>
0x0047f03b:	incl %ecx
0x0047f03c:	movb %al, $0x10<UINT8>
0x0047f03e:	call 0x0047f015
0x0047f041:	adcb %al, %al
0x0047f043:	jae 0x0047f03e
0x0047f045:	jne 0x0047f086
0x0047f047:	stosb %es:(%edi), %al
0x0047f048:	jmp 0x0047f026
0x0047f086:	pushl %esi
0x0047f087:	movl %esi, %edi
0x0047f089:	subl %esi, %eax
0x0047f08b:	rep movsb %es:(%edi), %ds:(%esi)
0x0047f08d:	popl %esi
0x0047f08e:	jmp 0x0047f026
0x0047f05a:	lodsb %al, %ds:(%esi)
0x0047f05b:	shrl %eax
0x0047f05d:	je 0x0047f0a0
0x0047f05f:	adcl %ecx, %ecx
0x0047f061:	jmp 0x0047f07f
0x0047f07f:	incl %ecx
0x0047f080:	incl %ecx
0x0047f081:	xchgl %ebp, %eax
0x0047f082:	movl %eax, %ebp
0x0047f084:	movb %bl, $0x1<UINT8>
0x0047f04a:	call 0x0047f092
0x0047f092:	incl %ecx
0x0047f093:	call 0x0047f015
0x0047f097:	adcl %ecx, %ecx
0x0047f099:	call 0x0047f015
0x0047f09d:	jb 0x0047f093
0x0047f09f:	ret

0x0047f04f:	subl %ecx, %ebx
0x0047f051:	jne 0x0047f063
0x0047f053:	call 0x0047f090
0x0047f090:	xorl %ecx, %ecx
0x0047f058:	jmp 0x0047f082
0x0047f063:	xchgl %ecx, %eax
0x0047f064:	decl %eax
0x0047f065:	shll %eax, $0x8<UINT8>
0x0047f068:	lodsb %al, %ds:(%esi)
0x0047f069:	call 0x0047f090
0x0047f06e:	cmpl %eax, $0x7d00<UINT32>
0x0047f073:	jae 0x0047f07f
0x0047f075:	cmpb %ah, $0x5<UINT8>
0x0047f078:	jae 0x0047f080
0x0047f07a:	cmpl %eax, $0x7f<UINT8>
0x0047f07d:	ja 0x0047f081
0x0047f0a0:	popl %edi
0x0047f0a1:	popl %ebx
0x0047f0a2:	movzwl %edi, (%ebx)
0x0047f0a5:	decl %edi
0x0047f0a6:	je 0x0047f0b0
0x0047f0a8:	decl %edi
0x0047f0a9:	je 0x0047f0be
0x0047f0ab:	shll %edi, $0xc<UINT8>
0x0047f0ae:	jmp 0x0047f0b7
0x0047f0b7:	incl %ebx
0x0047f0b8:	incl %ebx
0x0047f0b9:	jmp 0x0047f00f
0x0047f0b0:	movl %edi, 0x2(%ebx)
0x0047f0b3:	pushl %edi
0x0047f0b4:	addl %ebx, $0x4<UINT8>
0x0047f0be:	popl %edi
0x0047f0bf:	movl %ebx, $0x47f128<UINT32>
0x0047f0c4:	incl %edi
0x0047f0c5:	movl %esi, (%edi)
0x0047f0c7:	scasl %eax, %es:(%edi)
0x0047f0c8:	pushl %edi
0x0047f0c9:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0047f0cb:	xchgl %ebp, %eax
0x0047f0cc:	xorl %eax, %eax
0x0047f0ce:	scasb %al, %es:(%edi)
0x0047f0cf:	jne 0x0047f0ce
0x0047f0d1:	decb (%edi)
0x0047f0d3:	je 0x0047f0c4
0x0047f0d5:	decb (%edi)
0x0047f0d7:	jne 0x0047f0df
0x0047f0df:	decb (%edi)
0x0047f0e1:	je -407836
0x0047f0e7:	pushl %edi
0x0047f0e8:	pushl %ebp
0x0047f0e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x0047f0ec:	orl (%esi), %eax
0x0047f0ee:	lodsl %eax, %ds:(%esi)
0x0047f0ef:	jne 0x0047f0cc
GetProcAddress@KERNEL32.dll: API Node	
0x0047f0d9:	incl %edi
0x0047f0da:	pushl (%edi)
0x0047f0dc:	scasl %eax, %es:(%edi)
0x0047f0dd:	jmp 0x0047f0e8
0x0047f0f1:	movl %ebp, %esp
0x0047f0f3:	ret

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
