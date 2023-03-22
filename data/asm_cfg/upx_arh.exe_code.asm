0x004195a0:	pusha
0x004195a1:	movl %esi, $0x411000<UINT32>
0x004195a6:	leal %edi, -65536(%esi)
0x004195ac:	pushl %edi
0x004195ad:	orl %ebp, $0xffffffff<UINT8>
0x004195b0:	jmp 0x004195c2
0x004195c2:	movl %ebx, (%esi)
0x004195c4:	subl %esi, $0xfffffffc<UINT8>
0x004195c7:	adcl %ebx, %ebx
0x004195c9:	jb 0x004195b8
0x004195b8:	movb %al, (%esi)
0x004195ba:	incl %esi
0x004195bb:	movb (%edi), %al
0x004195bd:	incl %edi
0x004195be:	addl %ebx, %ebx
0x004195c0:	jne 0x004195c9
0x004195cb:	movl %eax, $0x1<UINT32>
0x004195d0:	addl %ebx, %ebx
0x004195d2:	jne 0x004195db
0x004195db:	adcl %eax, %eax
0x004195dd:	addl %ebx, %ebx
0x004195df:	jae 0x004195d0
0x004195e1:	jne 0x004195ec
0x004195ec:	xorl %ecx, %ecx
0x004195ee:	subl %eax, $0x3<UINT8>
0x004195f1:	jb 0x00419600
0x00419600:	addl %ebx, %ebx
0x00419602:	jne 0x0041960b
0x0041960b:	adcl %ecx, %ecx
0x0041960d:	addl %ebx, %ebx
0x0041960f:	jne 0x00419618
0x00419618:	adcl %ecx, %ecx
0x0041961a:	jne 0x0041963c
0x0041963c:	cmpl %ebp, $0xfffff300<UINT32>
0x00419642:	adcl %ecx, $0x1<UINT8>
0x00419645:	leal %edx, (%edi,%ebp)
0x00419648:	cmpl %ebp, $0xfffffffc<UINT8>
0x0041964b:	jbe 0x0041965c
0x0041964d:	movb %al, (%edx)
0x0041964f:	incl %edx
0x00419650:	movb (%edi), %al
0x00419652:	incl %edi
0x00419653:	decl %ecx
0x00419654:	jne 0x0041964d
0x00419656:	jmp 0x004195be
0x004195d4:	movl %ebx, (%esi)
0x004195d6:	subl %esi, $0xfffffffc<UINT8>
0x004195d9:	adcl %ebx, %ebx
0x004195f3:	shll %eax, $0x8<UINT8>
0x004195f6:	movb %al, (%esi)
0x004195f8:	incl %esi
0x004195f9:	xorl %eax, $0xffffffff<UINT8>
0x004195fc:	je 0x00419672
0x004195fe:	movl %ebp, %eax
0x0041965c:	movl %eax, (%edx)
0x0041965e:	addl %edx, $0x4<UINT8>
0x00419661:	movl (%edi), %eax
0x00419663:	addl %edi, $0x4<UINT8>
0x00419666:	subl %ecx, $0x4<UINT8>
0x00419669:	ja 0x0041965c
0x0041966b:	addl %edi, %ecx
0x0041966d:	jmp 0x004195be
0x0041961c:	incl %ecx
0x0041961d:	addl %ebx, %ebx
0x0041961f:	jne 0x00419628
0x00419628:	adcl %ecx, %ecx
0x0041962a:	addl %ebx, %ebx
0x0041962c:	jae 0x0041961d
0x0041962e:	jne 0x00419639
0x00419630:	movl %ebx, (%esi)
0x00419632:	subl %esi, $0xfffffffc<UINT8>
0x00419635:	adcl %ebx, %ebx
0x00419637:	jae 0x0041961d
0x00419639:	addl %ecx, $0x2<UINT8>
0x00419621:	movl %ebx, (%esi)
0x00419623:	subl %esi, $0xfffffffc<UINT8>
0x00419626:	adcl %ebx, %ebx
0x004195e3:	movl %ebx, (%esi)
0x004195e5:	subl %esi, $0xfffffffc<UINT8>
0x004195e8:	adcl %ebx, %ebx
0x004195ea:	jae 0x004195d0
0x00419611:	movl %ebx, (%esi)
0x00419613:	subl %esi, $0xfffffffc<UINT8>
0x00419616:	adcl %ebx, %ebx
0x00419604:	movl %ebx, (%esi)
0x00419606:	subl %esi, $0xfffffffc<UINT8>
0x00419609:	adcl %ebx, %ebx
0x00419672:	popl %esi
0x00419673:	movl %edi, %esi
0x00419675:	movl %ecx, $0x582<UINT32>
0x0041967a:	movb %al, (%edi)
0x0041967c:	incl %edi
0x0041967d:	subb %al, $0xffffffe8<UINT8>
0x0041967f:	cmpb %al, $0x1<UINT8>
0x00419681:	ja 0x0041967a
0x00419683:	cmpb (%edi), $0x5<UINT8>
0x00419686:	jne 0x0041967a
0x00419688:	movl %eax, (%edi)
0x0041968a:	movb %bl, 0x4(%edi)
0x0041968d:	shrw %ax, $0x8<UINT8>
0x00419691:	roll %eax, $0x10<UINT8>
0x00419694:	xchgb %ah, %al
0x00419696:	subl %eax, %edi
0x00419698:	subb %bl, $0xffffffe8<UINT8>
0x0041969b:	addl %eax, %esi
0x0041969d:	movl (%edi), %eax
0x0041969f:	addl %edi, $0x5<UINT8>
0x004196a2:	movb %al, %bl
0x004196a4:	loop 0x0041967f
0x004196a6:	leal %edi, 0x17000(%esi)
0x004196ac:	movl %eax, (%edi)
0x004196ae:	orl %eax, %eax
0x004196b0:	je 69
0x004196b2:	movl %ebx, 0x4(%edi)
0x004196b5:	leal %eax, 0x194f8(%eax,%esi)
0x004196bc:	addl %ebx, %esi
0x004196be:	pushl %eax
0x004196bf:	addl %edi, $0x8<UINT8>
0x004196c2:	call 0x00000000
Unknown Node: Unknown Node	
