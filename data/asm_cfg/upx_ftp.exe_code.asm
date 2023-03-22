0x01013480:	pusha
0x01013481:	movl %esi, $0x100f000<UINT32>
0x01013486:	leal %edi, -57344(%esi)
0x0101348c:	pushl %edi
0x0101348d:	jmp 0x0101349a
0x0101349a:	movl %ebx, (%esi)
0x0101349c:	subl %esi, $0xfffffffc<UINT8>
0x0101349f:	adcl %ebx, %ebx
0x010134a1:	jb 0x01013490
0x01013490:	movb %al, (%esi)
0x01013492:	incl %esi
0x01013493:	movb (%edi), %al
0x01013495:	incl %edi
0x01013496:	addl %ebx, %ebx
0x01013498:	jne 0x010134a1
0x010134a3:	movl %eax, $0x1<UINT32>
0x010134a8:	addl %ebx, %ebx
0x010134aa:	jne 0x010134b3
0x010134b3:	adcl %eax, %eax
0x010134b5:	addl %ebx, %ebx
0x010134b7:	jae 0x010134a8
0x010134b9:	jne 0x010134c4
0x010134c4:	xorl %ecx, %ecx
0x010134c6:	subl %eax, $0x3<UINT8>
0x010134c9:	jb 0x010134d8
0x010134cb:	shll %eax, $0x8<UINT8>
0x010134ce:	movb %al, (%esi)
0x010134d0:	incl %esi
0x010134d1:	xorl %eax, $0xffffffff<UINT8>
0x010134d4:	je 0x0101354a
0x010134d6:	movl %ebp, %eax
0x010134d8:	addl %ebx, %ebx
0x010134da:	jne 0x010134e3
0x010134e3:	adcl %ecx, %ecx
0x010134e5:	addl %ebx, %ebx
0x010134e7:	jne 0x010134f0
0x010134f0:	adcl %ecx, %ecx
0x010134f2:	jne 0x01013514
0x01013514:	cmpl %ebp, $0xfffff300<UINT32>
0x0101351a:	adcl %ecx, $0x1<UINT8>
0x0101351d:	leal %edx, (%edi,%ebp)
0x01013520:	cmpl %ebp, $0xfffffffc<UINT8>
0x01013523:	jbe 0x01013534
0x01013534:	movl %eax, (%edx)
0x01013536:	addl %edx, $0x4<UINT8>
0x01013539:	movl (%edi), %eax
0x0101353b:	addl %edi, $0x4<UINT8>
0x0101353e:	subl %ecx, $0x4<UINT8>
0x01013541:	ja 0x01013534
0x01013543:	addl %edi, %ecx
0x01013545:	jmp 0x01013496
0x01013525:	movb %al, (%edx)
0x01013527:	incl %edx
0x01013528:	movb (%edi), %al
0x0101352a:	incl %edi
0x0101352b:	decl %ecx
0x0101352c:	jne 0x01013525
0x0101352e:	jmp 0x01013496
0x010134e9:	movl %ebx, (%esi)
0x010134eb:	subl %esi, $0xfffffffc<UINT8>
0x010134ee:	adcl %ebx, %ebx
0x010134ac:	movl %ebx, (%esi)
0x010134ae:	subl %esi, $0xfffffffc<UINT8>
0x010134b1:	adcl %ebx, %ebx
0x010134bb:	movl %ebx, (%esi)
0x010134bd:	subl %esi, $0xfffffffc<UINT8>
0x010134c0:	adcl %ebx, %ebx
0x010134c2:	jae 0x010134a8
0x010134f4:	incl %ecx
0x010134f5:	addl %ebx, %ebx
0x010134f7:	jne 0x01013500
0x01013500:	adcl %ecx, %ecx
0x01013502:	addl %ebx, %ebx
0x01013504:	jae 0x010134f5
0x01013506:	jne 0x01013511
0x01013511:	addl %ecx, $0x2<UINT8>
0x010134f9:	movl %ebx, (%esi)
0x010134fb:	subl %esi, $0xfffffffc<UINT8>
0x010134fe:	adcl %ebx, %ebx
0x010134dc:	movl %ebx, (%esi)
0x010134de:	subl %esi, $0xfffffffc<UINT8>
0x010134e1:	adcl %ebx, %ebx
0x01013508:	movl %ebx, (%esi)
0x0101350a:	subl %esi, $0xfffffffc<UINT8>
0x0101350d:	adcl %ebx, %ebx
0x0101350f:	jae 0x010134f5
0x0101354a:	popl %esi
0x0101354b:	movl %edi, %esi
0x0101354d:	movl %ecx, $0x232<UINT32>
0x01013552:	movb %al, (%edi)
0x01013554:	incl %edi
0x01013555:	subb %al, $0xffffffe8<UINT8>
0x01013557:	cmpb %al, $0x1<UINT8>
0x01013559:	ja 0x01013552
0x0101355b:	cmpb (%edi), $0x2<UINT8>
0x0101355e:	jne 0x01013552
0x01013560:	movl %eax, (%edi)
0x01013562:	movb %bl, 0x4(%edi)
0x01013565:	shrw %ax, $0x8<UINT8>
0x01013569:	roll %eax, $0x10<UINT8>
0x0101356c:	xchgb %ah, %al
0x0101356e:	subl %eax, %edi
0x01013570:	subb %bl, $0xffffffe8<UINT8>
0x01013573:	addl %eax, %esi
0x01013575:	movl (%edi), %eax
0x01013577:	addl %edi, $0x5<UINT8>
0x0101357a:	movb %al, %bl
0x0101357c:	loop 0x01013557
0x0101357e:	leal %edi, 0x11000(%esi)
0x01013584:	movl %eax, (%edi)
0x01013586:	orl %eax, %eax
0x01013588:	je 69
0x0101358a:	movl %ebx, 0x4(%edi)
0x0101358d:	leal %eax, 0x13700(%eax,%esi)
0x01013594:	addl %ebx, %esi
0x01013596:	pushl %eax
0x01013597:	addl %edi, $0x8<UINT8>
0x0101359a:	call 0x00000000
Unknown Node: Unknown Node	
