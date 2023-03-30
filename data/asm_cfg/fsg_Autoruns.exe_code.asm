0x004f3000:	movl %ebx, $0x4001d0<UINT32>
0x004f3005:	movl %edi, $0x401000<UINT32>
0x004f300a:	movl %esi, $0x4b0c9c<UINT32>
0x004f300f:	pushl %ebx
0x004f3010:	call 0x004f301f
0x004f301f:	cld
0x004f3020:	movb %dl, $0xffffff80<UINT8>
0x004f3022:	movsb %es:(%edi), %ds:(%esi)
0x004f3023:	pushl $0x2<UINT8>
0x004f3025:	popl %ebx
0x004f3026:	call 0x004f3015
0x004f3015:	addb %dl, %dl
0x004f3017:	jne 0x004f301e
0x004f3019:	movb %dl, (%esi)
0x004f301b:	incl %esi
0x004f301c:	adcb %dl, %dl
0x004f301e:	ret

0x004f3029:	jae 0x004f3022
0x004f302b:	xorl %ecx, %ecx
0x004f302d:	call 0x004f3015
0x004f3030:	jae 0x004f304a
0x004f3032:	xorl %eax, %eax
0x004f3034:	call 0x004f3015
0x004f3037:	jae 0x004f305a
0x004f3039:	movb %bl, $0x2<UINT8>
0x004f303b:	incl %ecx
0x004f303c:	movb %al, $0x10<UINT8>
0x004f303e:	call 0x004f3015
0x004f3041:	adcb %al, %al
0x004f3043:	jae 0x004f303e
0x004f3045:	jne 0x004f3086
0x004f3086:	pushl %esi
0x004f3087:	movl %esi, %edi
0x004f3089:	subl %esi, %eax
0x004f308b:	rep movsb %es:(%edi), %ds:(%esi)
0x004f308d:	popl %esi
0x004f308e:	jmp 0x004f3026
0x004f305a:	lodsb %al, %ds:(%esi)
0x004f305b:	shrl %eax
0x004f305d:	je 0x004f30a0
0x004f305f:	adcl %ecx, %ecx
0x004f3061:	jmp 0x004f307f
0x004f307f:	incl %ecx
0x004f3080:	incl %ecx
0x004f3081:	xchgl %ebp, %eax
0x004f3082:	movl %eax, %ebp
0x004f3084:	movb %bl, $0x1<UINT8>
0x004f3047:	stosb %es:(%edi), %al
0x004f3048:	jmp 0x004f3026
0x004f304a:	call 0x004f3092
0x004f3092:	incl %ecx
0x004f3093:	call 0x004f3015
0x004f3097:	adcl %ecx, %ecx
0x004f3099:	call 0x004f3015
0x004f309d:	jb 0x004f3093
0x004f309f:	ret

0x004f304f:	subl %ecx, %ebx
0x004f3051:	jne 0x004f3063
0x004f3063:	xchgl %ecx, %eax
0x004f3064:	decl %eax
0x004f3065:	shll %eax, $0x8<UINT8>
0x004f3068:	lodsb %al, %ds:(%esi)
0x004f3069:	call 0x004f3090
0x004f3090:	xorl %ecx, %ecx
0x004f306e:	cmpl %eax, $0x7d00<UINT32>
0x004f3073:	jae 0x004f307f
0x004f3075:	cmpb %ah, $0x5<UINT8>
0x004f3078:	jae 0x004f3080
0x004f307a:	cmpl %eax, $0x7f<UINT8>
0x004f307d:	ja 0x004f3081
0x004f3053:	call 0x004f3090
0x004f3058:	jmp 0x004f3082
0x004f30a0:	popl %edi
0x004f30a1:	popl %ebx
0x004f30a2:	movzwl %edi, (%ebx)
0x004f30a5:	decl %edi
0x004f30a6:	je 0x004f30b0
0x004f30a8:	decl %edi
0x004f30a9:	je 0x004f30be
0x004f30ab:	shll %edi, $0xc<UINT8>
0x004f30ae:	jmp 0x004f30b7
0x004f30b7:	incl %ebx
0x004f30b8:	incl %ebx
0x004f30b9:	jmp 0x004f300f
0x004f30b0:	movl %edi, 0x2(%ebx)
0x004f30b3:	pushl %edi
0x004f30b4:	addl %ebx, $0x4<UINT8>
0x004f30be:	popl %edi
0x004f30bf:	movl %ebx, $0x4f3128<UINT32>
0x004f30c4:	incl %edi
0x004f30c5:	movl %esi, (%edi)
0x004f30c7:	scasl %eax, %es:(%edi)
0x004f30c8:	pushl %edi
0x004f30c9:	call LoadLibraryA@KERNEL32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004f30cb:	xchgl %ebp, %eax
0x004f30cc:	xorl %eax, %eax
0x004f30ce:	scasb %al, %es:(%edi)
0x004f30cf:	jne 0x004f30ce
0x004f30d1:	decb (%edi)
0x004f30d3:	je 0x004f30c4
0x004f30d5:	decb (%edi)
0x004f30d7:	jne 0x004f30df
0x004f30df:	decb (%edi)
0x004f30e1:	je -660893
0x004f30e7:	pushl %edi
0x004f30e8:	pushl %ebp
0x004f30e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x004f30ec:	orl (%esi), %eax
0x004f30ee:	lodsl %eax, %ds:(%esi)
0x004f30ef:	jne 0x004f30cc
0x004f30d9:	incl %edi
0x004f30da:	pushl (%edi)
0x004f30dc:	scasl %eax, %es:(%edi)
0x004f30dd:	jmp 0x004f30e8
GetProcAddress@KERNEL32.dll: API Node	
LoadLibraryA@KERNEL32.dll: API Node	
0x004f30f1:	movl %ebp, %esp
0x004f30f3:	ret

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
