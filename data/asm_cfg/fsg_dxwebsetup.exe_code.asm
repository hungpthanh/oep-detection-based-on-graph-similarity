0x0108e000:	movl %ebx, $0x4001d0<UINT32>
0x0108e005:	movl %edi, $0x401000<UINT32>
0x0108e00a:	movl %esi, $0x104c8b6<UINT32>
0x0108e00f:	pushl %ebx
0x0108e010:	call 0x0108e01f
0x0108e01f:	cld
0x0108e020:	movb %dl, $0xffffff80<UINT8>
0x0108e022:	movsb %es:(%edi), %ds:(%esi)
0x0108e023:	pushl $0x2<UINT8>
0x0108e025:	popl %ebx
0x0108e026:	call 0x0108e015
0x0108e015:	addb %dl, %dl
0x0108e017:	jne 0x0108e01e
0x0108e019:	movb %dl, (%esi)
0x0108e01b:	incl %esi
0x0108e01c:	adcb %dl, %dl
0x0108e01e:	ret

0x0108e029:	jae 0x0108e022
0x0108e02b:	xorl %ecx, %ecx
0x0108e02d:	call 0x0108e015
0x0108e030:	jae 0x0108e04a
0x0108e04a:	call 0x0108e092
0x0108e092:	incl %ecx
0x0108e093:	call 0x0108e015
0x0108e097:	adcl %ecx, %ecx
0x0108e099:	call 0x0108e015
0x0108e09d:	jb 0x0108e093
0x0108e09f:	ret

0x0108e04f:	subl %ecx, %ebx
0x0108e051:	jne 0x0108e063
0x0108e063:	xchgl %ecx, %eax
0x0108e064:	decl %eax
0x0108e065:	shll %eax, $0x8<UINT8>
0x0108e068:	lodsb %al, %ds:(%esi)
0x0108e069:	call 0x0108e090
0x0108e090:	xorl %ecx, %ecx
0x0108e06e:	cmpl %eax, $0x7d00<UINT32>
0x0108e073:	jae 0x0108e07f
0x0108e075:	cmpb %ah, $0x5<UINT8>
0x0108e078:	jae 0x0108e080
0x0108e07a:	cmpl %eax, $0x7f<UINT8>
0x0108e07d:	ja 0x0108e081
0x0108e07f:	incl %ecx
0x0108e080:	incl %ecx
0x0108e081:	xchgl %ebp, %eax
0x0108e082:	movl %eax, %ebp
0x0108e084:	movb %bl, $0x1<UINT8>
0x0108e086:	pushl %esi
0x0108e087:	movl %esi, %edi
0x0108e089:	subl %esi, %eax
0x0108e08b:	rep movsb %es:(%edi), %ds:(%esi)
0x0108e08d:	popl %esi
0x0108e08e:	jmp 0x0108e026
0x0108e032:	xorl %eax, %eax
0x0108e034:	call 0x0108e015
0x0108e037:	jae 0x0108e05a
0x0108e039:	movb %bl, $0x2<UINT8>
0x0108e03b:	incl %ecx
0x0108e03c:	movb %al, $0x10<UINT8>
0x0108e03e:	call 0x0108e015
0x0108e041:	adcb %al, %al
0x0108e043:	jae 0x0108e03e
0x0108e045:	jne 0x0108e086
0x0108e047:	stosb %es:(%edi), %al
0x0108e048:	jmp 0x0108e026
0x0108e053:	call 0x0108e090
0x0108e058:	jmp 0x0108e082
0x0108e05a:	lodsb %al, %ds:(%esi)
0x0108e05b:	shrl %eax
0x0108e05d:	je 0x0108e0a0
0x0108e05f:	adcl %ecx, %ecx
0x0108e061:	jmp 0x0108e07f
0x0108e0a0:	popl %edi
0x0108e0a1:	popl %ebx
0x0108e0a2:	movzwl %edi, (%ebx)
0x0108e0a5:	decl %edi
0x0108e0a6:	je 8
0x0108e0a8:	decl %edi
0x0108e0a9:	je 0x0108e0be
0x0108e0ab:	shll %edi, $0xc<UINT8>
0x0108e0ae:	jmp 0x0108e0b7
0x0108e0b7:	incl %ebx
0x0108e0b8:	incl %ebx
0x0108e0b9:	jmp 0x0108e00f
0x0108e0be:	popl %edi
0x0108e0bf:	movl %ebx, $0x108e128<UINT32>
0x0108e0c4:	incl %edi
0x0108e0c5:	movl %esi, (%edi)
0x0108e0c7:	scasl %eax, %es:(%edi)
0x0108e0c8:	pushl %edi
0x0108e0c9:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0108e0cb:	xchgl %ebp, %eax
0x0108e0cc:	xorl %eax, %eax
0x0108e0ce:	scasb %al, %es:(%edi)
0x0108e0cf:	jne 0x0108e0ce
0x0108e0d1:	decb (%edi)
0x0108e0d3:	je -17
0x0108e0d5:	decb (%edi)
0x0108e0d7:	jne 0x0108e0df
0x0108e0df:	decb (%edi)
0x0108e0e1:	je -558729
0x0108e0e7:	pushl %edi
0x0108e0e8:	pushl %ebp
0x0108e0e9:	call GetProcAddress@kernel32.dll
GetProcAddress@kernel32.dll: API Node	
0x0108e0ec:	orl (%esi), %eax
0x0108e0ee:	lodsl %eax, %ds:(%esi)
0x0108e0ef:	jne -37
0x0108e0f1:	movl %ebp, %esp
0x0108e0f3:	ret

0x0108e04a:	call 0x0205e092
0x0205e092:	addl %edx, %edi
0x0205e094:	addb %al, $0xffffffed<UINT8>
0x0205e096:	andl (%eax), %eax
0x0205e098:	addb 0, %al
0x0205e09e:	addb (%eax), %al
0x0205e0a0:	addb (%eax), %al
0x0205e0a2:	addb (%eax), %al
0x0205e0a4:	addb (%ecx), %al
0x0205e0a6:	incl (%ecx,%eax,8)
0x0205e0a9:	andb %al, (%eax)
0x0205e0ab:	addb 0, %al
0x0205e0b1:	addb (%eax), %al
0x0205e0b3:	addb (%eax), %al
0x0205e0b5:	addb (%eax), %al
0x0205e0b7:	addb (%ecx), %al
0x0205e0b9:	orb %al, $0xffffffd4<UINT8>
0x0205e0bb:	andb %al, (%eax)
0x0205e0bd:	addb 0, %al
0x0205e0c3:	addb (%eax), %al
0x0205e0c5:	addb (%eax), %al
0x0205e0c7:	addb (%eax), %al
0x0205e0c9:	addb (%ecx), %al
Unknown Node: Unknown Node	
