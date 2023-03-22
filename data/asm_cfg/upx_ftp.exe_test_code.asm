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
0x01013588:	je 0x010135cf
0x0101358a:	movl %ebx, 0x4(%edi)
0x0101358d:	leal %eax, 0x13700(%eax,%esi)
0x01013594:	addl %ebx, %esi
0x01013596:	pushl %eax
0x01013597:	addl %edi, $0x8<UINT8>
0x0101359a:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x010135a0:	xchgl %ebp, %eax
0x010135a1:	movb %al, (%edi)
0x010135a3:	incl %edi
0x010135a4:	orb %al, %al
0x010135a6:	je 0x01013584
0x010135a8:	movl %ecx, %edi
0x010135aa:	jns 0x010135b3
0x010135b3:	pushl %edi
0x010135b4:	decl %eax
0x010135b5:	repn scasb %al, %es:(%edi)
0x010135b7:	pushl %ebp
0x010135b8:	call GetProcAddress@kernel32.dll
GetProcAddress@kernel32.dll: API Node	
0x010135be:	orl %eax, %eax
0x010135c0:	je 7
0x010135c2:	movl (%ebx), %eax
0x010135c4:	addl %ebx, $0x4<UINT8>
0x010135c7:	jmp 0x010135a1
0x010135ac:	movzwl %eax, (%edi)
0x010135af:	incl %edi
0x010135b0:	pushl %eax
0x010135b1:	incl %edi
0x010135b2:	movl %ecx, $0xaef24857<UINT32>
0x010135cf:	addl %edi, $0x4<UINT8>
0x010135d2:	leal %ebx, -4(%esi)
0x010135d5:	xorl %eax, %eax
0x010135d7:	movb %al, (%edi)
0x010135d9:	incl %edi
0x010135da:	orl %eax, %eax
0x010135dc:	je 0x01013600
0x010135de:	cmpb %al, $0xffffffef<UINT8>
0x010135e0:	ja 0x010135f3
0x010135f3:	andb %al, $0xf<UINT8>
0x010135f5:	shll %eax, $0x10<UINT8>
0x010135f8:	movw %ax, (%edi)
0x010135fb:	addl %edi, $0x2<UINT8>
0x010135fe:	jmp 0x010135e2
0x010135e2:	addl %ebx, %eax
0x010135e4:	movl %eax, (%ebx)
0x010135e6:	xchgb %ah, %al
0x010135e8:	roll %eax, $0x10<UINT8>
0x010135eb:	xchgb %ah, %al
0x010135ed:	addl %eax, %esi
0x010135ef:	movl (%ebx), %eax
0x010135f1:	jmp 0x010135d5
0x01013600:	movl %ebp, 0x137a0(%esi)
0x01013606:	leal %edi, -4096(%esi)
0x0101360c:	movl %ebx, $0x1000<UINT32>
0x01013611:	pushl %eax
0x01013612:	pushl %esp
0x01013613:	pushl $0x4<UINT8>
0x01013615:	pushl %ebx
0x01013616:	pushl %edi
0x01013617:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x01013619:	leal %eax, 0x1f7(%edi)
0x0101361f:	andb (%eax), $0x7f<UINT8>
0x01013622:	andb 0x28(%eax), $0x7f<UINT8>
0x01013626:	popl %eax
0x01013627:	pushl %eax
0x01013628:	pushl %esp
0x01013629:	pushl %eax
0x0101362a:	pushl %ebx
0x0101362b:	pushl %edi
0x0101362c:	call VirtualProtect@kernel32.dll
0x0101362e:	popl %eax
0x0101362f:	popa
0x01013630:	leal %eax, -128(%esp)
0x01013634:	pushl $0x0<UINT8>
0x01013636:	cmpl %esp, %eax
0x01013638:	jne 0x01013634
0x0101363a:	subl %esp, $0xffffff80<UINT8>
0x0101363d:	jmp 0x0100834d
0x0100834d:	call 0x01008681
0x01008681:	movl %edi, %edi
0x01008683:	pushl %ebp
0x01008684:	movl %ebp, %esp
0x01008686:	subl %esp, $0x10<UINT8>
0x01008689:	movl %eax, 0x100a370
0x0100868e:	andl -8(%ebp), $0x0<UINT8>
0x01008692:	andl -4(%ebp), $0x0<UINT8>
0x01008696:	pushl %ebx
0x01008697:	pushl %edi
0x01008698:	movl %edi, $0xbb40e64e<UINT32>
0x0100869d:	movl %ebx, $0xffff0000<UINT32>
0x010086a2:	cmpl %eax, %edi
0x010086a4:	je 0x010086b3
0x010086b3:	pushl %esi
0x010086b4:	leal %eax, -8(%ebp)
0x010086b7:	pushl %eax
0x010086b8:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x010086be:	movl %esi, -4(%ebp)
0x010086c1:	xorl %esi, -8(%ebp)
0x010086c4:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x010086ca:	xorl %esi, %eax
0x010086cc:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x010086d2:	xorl %esi, %eax
0x010086d4:	call GetTickCount@KERNEL32.DLL
GetTickCount@KERNEL32.DLL: API Node	
0x010086da:	xorl %esi, %eax
0x010086dc:	leal %eax, -16(%ebp)
0x010086df:	pushl %eax
0x010086e0:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x010086e6:	movl %eax, -12(%ebp)
0x010086e9:	xorl %eax, -16(%ebp)
0x010086ec:	xorl %esi, %eax
0x010086ee:	cmpl %esi, %edi
0x010086f0:	je 8
0x010086f2:	testl 0x100a370, %ebx
0x010086f8:	jne 0x010086ff
0x010086ff:	movl 0x100a370, %esi
0x01008705:	notl %esi
0x01008707:	movl 0x100a374, %esi
0x0100870d:	popl %esi
0x0100870e:	popl %edi
0x0100870f:	popl %ebx
0x01008710:	leave
0x01008711:	ret

0x01008352:	jmp 0x0100811a
0x0100811a:	pushl $0x10<UINT8>
0x0100811c:	pushl $0x1008928<UINT32>
0x01008121:	call 0x01008534
0x01008534:	pushl $0x1008592<UINT32>
0x01008539:	pushl %fs:0
0x01008540:	movl %eax, 0x10(%esp)
0x01008544:	movl 0x10(%esp), %ebp
0x01008548:	leal %ebp, 0x10(%esp)
0x0100854c:	subl %esp, %eax
0x0100854e:	pushl %ebx
0x0100854f:	pushl %esi
0x01008550:	pushl %edi
0x01008551:	movl %eax, 0x100a370
0x01008556:	xorl -4(%ebp), %eax
0x01008559:	xorl %eax, %ebp
0x0100855b:	pushl %eax
0x0100855c:	movl -24(%ebp), %esp
0x0100855f:	pushl -8(%ebp)
0x01008562:	movl %eax, -4(%ebp)
0x01008565:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0100856c:	movl -8(%ebp), %eax
0x0100856f:	leal %eax, -16(%ebp)
0x01008572:	movl %fs:0, %eax
0x01008578:	ret

0x01008126:	xorl %ebx, %ebx
0x01008128:	movl -4(%ebp), %ebx
0x0100812b:	movl %eax, %fs:0x18
0x01008131:	movl %esi, 0x4(%eax)
0x01008134:	movl -28(%ebp), %ebx
0x01008137:	movl %edi, $0x100f190<UINT32>
0x0100813c:	pushl %ebx
0x0100813d:	pushl %esi
0x0100813e:	pushl %edi
0x0100813f:	call InterlockedCompareExchange@KERNEL32.DLL
InterlockedCompareExchange@KERNEL32.DLL: API Node	
0x01008145:	cmpl %eax, %ebx
0x01008147:	je 25
0x01008149:	cmpl %eax, %esi
0x0100814b:	jne 0x01008155
0x01008155:	pushl $0x3e8<UINT32>
0x0100815a:	call Sleep@KERNEL32.DLL
Sleep@KERNEL32.DLL: API Node	
0x01008160:	jmp 0x0100813c
