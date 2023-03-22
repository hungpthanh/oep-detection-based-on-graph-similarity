0x00706160:	pusha
0x00706161:	movl %esi, $0x5f6000<UINT32>
0x00706166:	leal %edi, -2052096(%esi)
0x0070616c:	pushl %edi
0x0070616d:	jmp 0x0070617a
0x0070617a:	movl %ebx, (%esi)
0x0070617c:	subl %esi, $0xfffffffc<UINT8>
0x0070617f:	adcl %ebx, %ebx
0x00706181:	jb 0x00706170
0x00706170:	movb %al, (%esi)
0x00706172:	incl %esi
0x00706173:	movb (%edi), %al
0x00706175:	incl %edi
0x00706176:	addl %ebx, %ebx
0x00706178:	jne 0x00706181
0x00706183:	movl %eax, $0x1<UINT32>
0x00706188:	addl %ebx, %ebx
0x0070618a:	jne 0x00706193
0x00706193:	adcl %eax, %eax
0x00706195:	addl %ebx, %ebx
0x00706197:	jae 0x007061a4
0x00706199:	jne 0x007061c3
0x007061c3:	xorl %ecx, %ecx
0x007061c5:	subl %eax, $0x3<UINT8>
0x007061c8:	jb 0x007061db
0x007061ca:	shll %eax, $0x8<UINT8>
0x007061cd:	movb %al, (%esi)
0x007061cf:	incl %esi
0x007061d0:	xorl %eax, $0xffffffff<UINT8>
0x007061d3:	je 0x0070624a
0x007061d5:	sarl %eax
0x007061d7:	movl %ebp, %eax
0x007061d9:	jmp 0x007061e6
0x007061e6:	jb 0x007061b4
0x007061b4:	addl %ebx, %ebx
0x007061b6:	jne 0x007061bf
0x007061bf:	adcl %ecx, %ecx
0x007061c1:	jmp 0x00706215
0x00706215:	cmpl %ebp, $0xfffffb00<UINT32>
0x0070621b:	adcl %ecx, $0x2<UINT8>
0x0070621e:	leal %edx, (%edi,%ebp)
0x00706221:	cmpl %ebp, $0xfffffffc<UINT8>
0x00706224:	jbe 0x00706234
0x00706234:	movl %eax, (%edx)
0x00706236:	addl %edx, $0x4<UINT8>
0x00706239:	movl (%edi), %eax
0x0070623b:	addl %edi, $0x4<UINT8>
0x0070623e:	subl %ecx, $0x4<UINT8>
0x00706241:	ja 0x00706234
0x00706243:	addl %edi, %ecx
0x00706245:	jmp 0x00706176
0x007061e8:	incl %ecx
0x007061e9:	addl %ebx, %ebx
0x007061eb:	jne 0x007061f4
0x007061ed:	movl %ebx, (%esi)
0x007061ef:	subl %esi, $0xfffffffc<UINT8>
0x007061f2:	adcl %ebx, %ebx
0x007061f4:	jb 0x007061b4
0x007061db:	addl %ebx, %ebx
0x007061dd:	jne 0x007061e6
0x007061f6:	addl %ebx, %ebx
0x007061f8:	jne 0x00706201
0x00706201:	adcl %ecx, %ecx
0x00706203:	addl %ebx, %ebx
0x00706205:	jae 0x007061f6
0x00706207:	jne 0x00706212
0x00706212:	addl %ecx, $0x2<UINT8>
0x0070618c:	movl %ebx, (%esi)
0x0070618e:	subl %esi, $0xfffffffc<UINT8>
0x00706191:	adcl %ebx, %ebx
0x007061df:	movl %ebx, (%esi)
0x007061e1:	subl %esi, $0xfffffffc<UINT8>
0x007061e4:	adcl %ebx, %ebx
0x007061b8:	movl %ebx, (%esi)
0x007061ba:	subl %esi, $0xfffffffc<UINT8>
0x007061bd:	adcl %ebx, %ebx
0x007061a4:	decl %eax
0x007061a5:	addl %ebx, %ebx
0x007061a7:	jne 0x007061b0
0x007061b0:	adcl %eax, %eax
0x007061b2:	jmp 0x00706188
0x007061fa:	movl %ebx, (%esi)
0x007061fc:	subl %esi, $0xfffffffc<UINT8>
0x007061ff:	adcl %ebx, %ebx
0x0070619b:	movl %ebx, (%esi)
0x0070619d:	subl %esi, $0xfffffffc<UINT8>
0x007061a0:	adcl %ebx, %ebx
0x007061a2:	jb 0x007061c3
0x00706209:	movl %ebx, (%esi)
0x0070620b:	subl %esi, $0xfffffffc<UINT8>
0x0070620e:	adcl %ebx, %ebx
0x00706210:	jae 0x007061f6
0x007061a9:	movl %ebx, (%esi)
0x007061ab:	subl %esi, $0xfffffffc<UINT8>
0x007061ae:	adcl %ebx, %ebx
0x00706226:	movb %al, (%edx)
0x00706228:	incl %edx
0x00706229:	movb (%edi), %al
0x0070622b:	incl %edi
0x0070622c:	decl %ecx
0x0070622d:	jne 0x00706226
0x0070622f:	jmp 0x00706176
0x0070624a:	popl %esi
0x0070624b:	movl %edi, %esi
0x0070624d:	movl %ecx, $0x1155d<UINT32>
0x00706252:	movb %al, (%edi)
0x00706254:	incl %edi
0x00706255:	subb %al, $0xffffffe8<UINT8>
0x00706257:	cmpb %al, $0x1<UINT8>
0x00706259:	ja 0x00706252
0x0070625b:	cmpb (%edi), $0x4b<UINT8>
0x0070625e:	jne 0x00706252
0x00706260:	movl %eax, (%edi)
0x00706262:	movb %bl, 0x4(%edi)
0x00706265:	shrw %ax, $0x8<UINT8>
0x00706269:	roll %eax, $0x10<UINT8>
0x0070626c:	xchgb %ah, %al
0x0070626e:	subl %eax, %edi
0x00706270:	subb %bl, $0xffffffe8<UINT8>
0x00706273:	addl %eax, %esi
0x00706275:	movl (%edi), %eax
0x00706277:	addl %edi, $0x5<UINT8>
0x0070627a:	movb %al, %bl
0x0070627c:	loop 0x00706257
