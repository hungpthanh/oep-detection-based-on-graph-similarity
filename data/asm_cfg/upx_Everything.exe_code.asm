0x0059a210:	pusha
0x0059a211:	movl %esi, $0x512000<UINT32>
0x0059a216:	leal %edi, -1118208(%esi)
0x0059a21c:	pushl %edi
0x0059a21d:	jmp 0x0059a22a
0x0059a22a:	movl %ebx, (%esi)
0x0059a22c:	subl %esi, $0xfffffffc<UINT8>
0x0059a22f:	adcl %ebx, %ebx
0x0059a231:	jb 0x0059a220
0x0059a220:	movb %al, (%esi)
0x0059a222:	incl %esi
0x0059a223:	movb (%edi), %al
0x0059a225:	incl %edi
0x0059a226:	addl %ebx, %ebx
0x0059a228:	jne 0x0059a231
0x0059a233:	movl %eax, $0x1<UINT32>
0x0059a238:	addl %ebx, %ebx
0x0059a23a:	jne 0x0059a243
0x0059a243:	adcl %eax, %eax
0x0059a245:	addl %ebx, %ebx
0x0059a247:	jae 0x0059a254
0x0059a249:	jne 0x0059a273
0x0059a273:	xorl %ecx, %ecx
0x0059a275:	subl %eax, $0x3<UINT8>
0x0059a278:	jb 0x0059a28b
0x0059a27a:	shll %eax, $0x8<UINT8>
0x0059a27d:	movb %al, (%esi)
0x0059a27f:	incl %esi
0x0059a280:	xorl %eax, $0xffffffff<UINT8>
0x0059a283:	je 0x0059a2fa
0x0059a285:	sarl %eax
0x0059a287:	movl %ebp, %eax
0x0059a289:	jmp 0x0059a296
0x0059a296:	jb 0x0059a264
0x0059a298:	incl %ecx
0x0059a299:	addl %ebx, %ebx
0x0059a29b:	jne 0x0059a2a4
0x0059a2a4:	jb 0x0059a264
0x0059a2a6:	addl %ebx, %ebx
0x0059a2a8:	jne 0x0059a2b1
0x0059a2b1:	adcl %ecx, %ecx
0x0059a2b3:	addl %ebx, %ebx
0x0059a2b5:	jae 0x0059a2a6
0x0059a2b7:	jne 0x0059a2c2
0x0059a2c2:	addl %ecx, $0x2<UINT8>
0x0059a2c5:	cmpl %ebp, $0xfffffb00<UINT32>
0x0059a2cb:	adcl %ecx, $0x2<UINT8>
0x0059a2ce:	leal %edx, (%edi,%ebp)
0x0059a2d1:	cmpl %ebp, $0xfffffffc<UINT8>
0x0059a2d4:	jbe 0x0059a2e4
0x0059a2d6:	movb %al, (%edx)
0x0059a2d8:	incl %edx
0x0059a2d9:	movb (%edi), %al
0x0059a2db:	incl %edi
0x0059a2dc:	decl %ecx
0x0059a2dd:	jne 0x0059a2d6
0x0059a2df:	jmp 0x0059a226
0x0059a264:	addl %ebx, %ebx
0x0059a266:	jne 0x0059a26f
0x0059a26f:	adcl %ecx, %ecx
0x0059a271:	jmp 0x0059a2c5
0x0059a2e4:	movl %eax, (%edx)
0x0059a2e6:	addl %edx, $0x4<UINT8>
0x0059a2e9:	movl (%edi), %eax
0x0059a2eb:	addl %edi, $0x4<UINT8>
0x0059a2ee:	subl %ecx, $0x4<UINT8>
0x0059a2f1:	ja 0x0059a2e4
0x0059a2f3:	addl %edi, %ecx
0x0059a2f5:	jmp 0x0059a226
0x0059a28b:	addl %ebx, %ebx
0x0059a28d:	jne 0x0059a296
0x0059a268:	movl %ebx, (%esi)
0x0059a26a:	subl %esi, $0xfffffffc<UINT8>
0x0059a26d:	adcl %ebx, %ebx
0x0059a24b:	movl %ebx, (%esi)
0x0059a24d:	subl %esi, $0xfffffffc<UINT8>
0x0059a250:	adcl %ebx, %ebx
0x0059a252:	jb 0x0059a273
0x0059a254:	decl %eax
0x0059a255:	addl %ebx, %ebx
0x0059a257:	jne 0x0059a260
0x0059a260:	adcl %eax, %eax
0x0059a262:	jmp 0x0059a238
0x0059a23c:	movl %ebx, (%esi)
0x0059a23e:	subl %esi, $0xfffffffc<UINT8>
0x0059a241:	adcl %ebx, %ebx
0x0059a29d:	movl %ebx, (%esi)
0x0059a29f:	subl %esi, $0xfffffffc<UINT8>
0x0059a2a2:	adcl %ebx, %ebx
0x0059a2aa:	movl %ebx, (%esi)
0x0059a2ac:	subl %esi, $0xfffffffc<UINT8>
0x0059a2af:	adcl %ebx, %ebx
0x0059a2b9:	movl %ebx, (%esi)
0x0059a2bb:	subl %esi, $0xfffffffc<UINT8>
0x0059a2be:	adcl %ebx, %ebx
0x0059a2c0:	jae 0x0059a2a6
0x0059a259:	movl %ebx, (%esi)
0x0059a25b:	subl %esi, $0xfffffffc<UINT8>
0x0059a25e:	adcl %ebx, %ebx
0x0059a28f:	movl %ebx, (%esi)
0x0059a291:	subl %esi, $0xfffffffc<UINT8>
0x0059a294:	adcl %ebx, %ebx
0x0059a2fa:	popl %esi
0x0059a2fb:	movl %edi, %esi
0x0059a2fd:	movl %ecx, $0x735c<UINT32>
0x0059a302:	movb %al, (%edi)
0x0059a304:	incl %edi
0x0059a305:	subb %al, $0xffffffe8<UINT8>
0x0059a307:	cmpb %al, $0x1<UINT8>
0x0059a309:	ja 0x0059a302
0x0059a30b:	cmpb (%edi), $0x2a<UINT8>
0x0059a30e:	jne 0x0059a302
0x0059a310:	movl %eax, (%edi)
0x0059a312:	movb %bl, 0x4(%edi)
0x0059a315:	shrw %ax, $0x8<UINT8>
0x0059a319:	roll %eax, $0x10<UINT8>
0x0059a31c:	xchgb %ah, %al
0x0059a31e:	subl %eax, %edi
0x0059a320:	subb %bl, $0xffffffe8<UINT8>
0x0059a323:	addl %eax, %esi
0x0059a325:	movl (%edi), %eax
0x0059a327:	addl %edi, $0x5<UINT8>
0x0059a32a:	movb %al, %bl
0x0059a32c:	loop 0x0059a307
0x0059a32e:	leal %edi, 0x197000(%esi)
0x0059a334:	movl %eax, (%edi)
0x0059a336:	orl %eax, %eax
0x0059a338:	je 69
0x0059a33a:	movl %ebx, 0x4(%edi)
0x0059a33d:	leal %eax, 0x1a1b48(%eax,%esi)
0x0059a344:	addl %ebx, %esi
0x0059a346:	pushl %eax
0x0059a347:	addl %edi, $0x8<UINT8>
0x0059a34a:	call 0x00000000
Unknown Node: Unknown Node	
