0x0041a3f0:	pusha
0x0041a3f1:	movl %esi, $0x411000<UINT32>
0x0041a3f6:	leal %edi, -65536(%esi)
0x0041a3fc:	pushl %edi
0x0041a3fd:	orl %ebp, $0xffffffff<UINT8>
0x0041a400:	jmp 0x0041a412
0x0041a412:	movl %ebx, (%esi)
0x0041a414:	subl %esi, $0xfffffffc<UINT8>
0x0041a417:	adcl %ebx, %ebx
0x0041a419:	jb 0x0041a408
0x0041a408:	movb %al, (%esi)
0x0041a40a:	incl %esi
0x0041a40b:	movb (%edi), %al
0x0041a40d:	incl %edi
0x0041a40e:	addl %ebx, %ebx
0x0041a410:	jne 0x0041a419
0x0041a41b:	movl %eax, $0x1<UINT32>
0x0041a420:	addl %ebx, %ebx
0x0041a422:	jne 0x0041a42b
0x0041a42b:	adcl %eax, %eax
0x0041a42d:	addl %ebx, %ebx
0x0041a42f:	jae 0x0041a420
0x0041a431:	jne 0x0041a43c
0x0041a43c:	xorl %ecx, %ecx
0x0041a43e:	subl %eax, $0x3<UINT8>
0x0041a441:	jb 0x0041a450
0x0041a450:	addl %ebx, %ebx
0x0041a452:	jne 0x0041a45b
0x0041a45b:	adcl %ecx, %ecx
0x0041a45d:	addl %ebx, %ebx
0x0041a45f:	jne 0x0041a468
0x0041a468:	adcl %ecx, %ecx
0x0041a46a:	jne 0x0041a48c
0x0041a48c:	cmpl %ebp, $0xfffff300<UINT32>
0x0041a492:	adcl %ecx, $0x1<UINT8>
0x0041a495:	leal %edx, (%edi,%ebp)
0x0041a498:	cmpl %ebp, $0xfffffffc<UINT8>
0x0041a49b:	jbe 0x0041a4ac
0x0041a49d:	movb %al, (%edx)
0x0041a49f:	incl %edx
0x0041a4a0:	movb (%edi), %al
0x0041a4a2:	incl %edi
0x0041a4a3:	decl %ecx
0x0041a4a4:	jne 0x0041a49d
0x0041a4a6:	jmp 0x0041a40e
0x0041a443:	shll %eax, $0x8<UINT8>
0x0041a446:	movb %al, (%esi)
0x0041a448:	incl %esi
0x0041a449:	xorl %eax, $0xffffffff<UINT8>
0x0041a44c:	je 0x0041a4c2
0x0041a44e:	movl %ebp, %eax
0x0041a4ac:	movl %eax, (%edx)
0x0041a4ae:	addl %edx, $0x4<UINT8>
0x0041a4b1:	movl (%edi), %eax
0x0041a4b3:	addl %edi, $0x4<UINT8>
0x0041a4b6:	subl %ecx, $0x4<UINT8>
0x0041a4b9:	ja 0x0041a4ac
0x0041a4bb:	addl %edi, %ecx
0x0041a4bd:	jmp 0x0041a40e
0x0041a424:	movl %ebx, (%esi)
0x0041a426:	subl %esi, $0xfffffffc<UINT8>
0x0041a429:	adcl %ebx, %ebx
0x0041a433:	movl %ebx, (%esi)
0x0041a435:	subl %esi, $0xfffffffc<UINT8>
0x0041a438:	adcl %ebx, %ebx
0x0041a43a:	jae 0x0041a420
0x0041a461:	movl %ebx, (%esi)
0x0041a463:	subl %esi, $0xfffffffc<UINT8>
0x0041a466:	adcl %ebx, %ebx
0x0041a46c:	incl %ecx
0x0041a46d:	addl %ebx, %ebx
0x0041a46f:	jne 0x0041a478
0x0041a478:	adcl %ecx, %ecx
0x0041a47a:	addl %ebx, %ebx
0x0041a47c:	jae 0x0041a46d
0x0041a47e:	jne 0x0041a489
0x0041a489:	addl %ecx, $0x2<UINT8>
0x0041a471:	movl %ebx, (%esi)
0x0041a473:	subl %esi, $0xfffffffc<UINT8>
0x0041a476:	adcl %ebx, %ebx
0x0041a480:	movl %ebx, (%esi)
0x0041a482:	subl %esi, $0xfffffffc<UINT8>
0x0041a485:	adcl %ebx, %ebx
0x0041a487:	jae 0x0041a46d
0x0041a454:	movl %ebx, (%esi)
0x0041a456:	subl %esi, $0xfffffffc<UINT8>
0x0041a459:	adcl %ebx, %ebx
0x0041a4c2:	popl %esi
0x0041a4c3:	movl %edi, %esi
0x0041a4c5:	movl %ecx, $0x4fe<UINT32>
0x0041a4ca:	movb %al, (%edi)
0x0041a4cc:	incl %edi
0x0041a4cd:	subb %al, $0xffffffe8<UINT8>
0x0041a4cf:	cmpb %al, $0x1<UINT8>
0x0041a4d1:	ja 0x0041a4ca
0x0041a4d3:	cmpb (%edi), $0x1<UINT8>
0x0041a4d6:	jne 0x0041a4ca
0x0041a4d8:	movl %eax, (%edi)
0x0041a4da:	movb %bl, 0x4(%edi)
0x0041a4dd:	shrw %ax, $0x8<UINT8>
0x0041a4e1:	roll %eax, $0x10<UINT8>
0x0041a4e4:	xchgb %ah, %al
0x0041a4e6:	subl %eax, %edi
0x0041a4e8:	subb %bl, $0xffffffe8<UINT8>
0x0041a4eb:	addl %eax, %esi
0x0041a4ed:	movl (%edi), %eax
0x0041a4ef:	addl %edi, $0x5<UINT8>
0x0041a4f2:	movb %al, %bl
0x0041a4f4:	loop 0x0041a4cf
0x0041a4f6:	leal %edi, 0x18000(%esi)
0x0041a4fc:	movl %eax, (%edi)
0x0041a4fe:	orl %eax, %eax
0x0041a500:	je 0x0041a547
0x0041a502:	movl %ebx, 0x4(%edi)
0x0041a505:	leal %eax, 0x1c42c(%eax,%esi)
0x0041a50c:	addl %ebx, %esi
0x0041a50e:	pushl %eax
0x0041a50f:	addl %edi, $0x8<UINT8>
0x0041a512:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0041a518:	xchgl %ebp, %eax
0x0041a519:	movb %al, (%edi)
0x0041a51b:	incl %edi
0x0041a51c:	orb %al, %al
0x0041a51e:	je 0x0041a4fc
0x0041a520:	movl %ecx, %edi
0x0041a522:	jns 0x0041a52b
0x0041a52b:	pushl %edi
0x0041a52c:	decl %eax
0x0041a52d:	repn scasb %al, %es:(%edi)
0x0041a52f:	pushl %ebp
0x0041a530:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0041a536:	orl %eax, %eax
0x0041a538:	je 7
0x0041a53a:	movl (%ebx), %eax
0x0041a53c:	addl %ebx, $0x4<UINT8>
0x0041a53f:	jmp 0x0041a519
GetProcAddress@KERNEL32.DLL: API Node	
0x0041a524:	movzwl %eax, (%edi)
0x0041a527:	incl %edi
0x0041a528:	pushl %eax
0x0041a529:	incl %edi
0x0041a52a:	movl %ecx, $0xaef24857<UINT32>
0x0041a547:	movl %ebp, 0x1c520(%esi)
0x0041a54d:	leal %edi, -4096(%esi)
0x0041a553:	movl %ebx, $0x1000<UINT32>
0x0041a558:	pushl %eax
0x0041a559:	pushl %esp
0x0041a55a:	pushl $0x4<UINT8>
0x0041a55c:	pushl %ebx
0x0041a55d:	pushl %edi
0x0041a55e:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0041a560:	leal %eax, 0x20f(%edi)
0x0041a566:	andb (%eax), $0x7f<UINT8>
0x0041a569:	andb 0x28(%eax), $0x7f<UINT8>
0x0041a56d:	popl %eax
0x0041a56e:	pushl %eax
0x0041a56f:	pushl %esp
0x0041a570:	pushl %eax
0x0041a571:	pushl %ebx
0x0041a572:	pushl %edi
0x0041a573:	call VirtualProtect@kernel32.dll
0x0041a575:	popl %eax
0x0041a576:	popa
0x0041a577:	leal %eax, -128(%esp)
0x0041a57b:	pushl $0x0<UINT8>
0x0041a57d:	cmpl %esp, %eax
0x0041a57f:	jne 0x0041a57b
0x0041a581:	subl %esp, $0xffffff80<UINT8>
0x0041a584:	jmp 0x0040d42a
0x0040d42a:	pushl $0x70<UINT8>
0x0040d42c:	pushl $0x40e410<UINT32>
0x0040d431:	call 0x0040d63c
0x0040d63c:	pushl $0x40d68c<UINT32>
0x0040d641:	movl %eax, %fs:0
0x0040d647:	pushl %eax
0x0040d648:	movl %fs:0, %esp
0x0040d64f:	movl %eax, 0x10(%esp)
0x0040d653:	movl 0x10(%esp), %ebp
0x0040d657:	leal %ebp, 0x10(%esp)
0x0040d65b:	subl %esp, %eax
0x0040d65d:	pushl %ebx
0x0040d65e:	pushl %esi
0x0040d65f:	pushl %edi
0x0040d660:	movl %eax, -8(%ebp)
0x0040d663:	movl -24(%ebp), %esp
0x0040d666:	pushl %eax
0x0040d667:	movl %eax, -4(%ebp)
0x0040d66a:	movl -4(%ebp), $0xffffffff<UINT32>
0x0040d671:	movl -8(%ebp), %eax
0x0040d674:	ret

0x0040d436:	xorl %edi, %edi
0x0040d438:	pushl %edi
0x0040d439:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x0040d43f:	cmpw (%eax), $0x5a4d<UINT16>
0x0040d444:	jne 31
0x0040d446:	movl %ecx, 0x3c(%eax)
0x0040d449:	addl %ecx, %eax
0x0040d44b:	cmpl (%ecx), $0x4550<UINT32>
0x0040d451:	jne 18
0x0040d453:	movzwl %eax, 0x18(%ecx)
0x0040d457:	cmpl %eax, $0x10b<UINT32>
0x0040d45c:	je 0x0040d47d
0x0040d47d:	cmpl 0x74(%ecx), $0xe<UINT8>
0x0040d481:	jbe -30
0x0040d483:	xorl %eax, %eax
0x0040d485:	cmpl 0xe8(%ecx), %edi
0x0040d48b:	setne %al
0x0040d48e:	movl -28(%ebp), %eax
0x0040d491:	movl -4(%ebp), %edi
0x0040d494:	pushl $0x2<UINT8>
0x0040d496:	popl %ebx
0x0040d497:	pushl %ebx
0x0040d498:	call __set_app_type@msvcrt.dll
__set_app_type@msvcrt.dll: API Node	
0x0040d49e:	popl %ecx
0x0040d49f:	orl 0x412aec, $0xffffffff<UINT8>
0x0040d4a6:	orl 0x412af0, $0xffffffff<UINT8>
0x0040d4ad:	call __p__fmode@msvcrt.dll
__p__fmode@msvcrt.dll: API Node	
0x0040d4b3:	movl %ecx, 0x4116ec
0x0040d4b9:	movl (%eax), %ecx
0x0040d4bb:	call __p__commode@msvcrt.dll
__p__commode@msvcrt.dll: API Node	
0x0040d4c1:	movl %ecx, 0x4116e8
0x0040d4c7:	movl (%eax), %ecx
0x0040d4c9:	movl %eax, 0x40e304
0x0040d4ce:	movl %eax, (%eax)
0x0040d4d0:	movl 0x412ae8, %eax
0x0040d4d5:	call 0x0040d638
0x0040d638:	xorl %eax, %eax
0x0040d63a:	ret

0x0040d4da:	cmpl 0x411000, %edi
0x0040d4e0:	jne 0x0040d4ee
0x0040d4ee:	call 0x0040d626
0x0040d626:	pushl $0x30000<UINT32>
0x0040d62b:	pushl $0x10000<UINT32>
0x0040d630:	call 0x0040d686
0x0040d686:	jmp _controlfp@msvcrt.dll
_controlfp@msvcrt.dll: API Node	
0x0040d635:	popl %ecx
0x0040d636:	popl %ecx
0x0040d637:	ret

0x0040d4f3:	pushl $0x40e3e0<UINT32>
0x0040d4f8:	pushl $0x40e3dc<UINT32>
0x0040d4fd:	call 0x0040d620
0x0040d620:	jmp _initterm@msvcrt.dll
_initterm@msvcrt.dll: API Node	
0x0040d502:	movl %eax, 0x4116e4
0x0040d507:	movl -32(%ebp), %eax
0x0040d50a:	leal %eax, -32(%ebp)
0x0040d50d:	pushl %eax
0x0040d50e:	pushl 0x4116e0
0x0040d514:	leal %eax, -36(%ebp)
0x0040d517:	pushl %eax
0x0040d518:	leal %eax, -40(%ebp)
0x0040d51b:	pushl %eax
0x0040d51c:	leal %eax, -44(%ebp)
0x0040d51f:	pushl %eax
0x0040d520:	call __wgetmainargs@msvcrt.dll
__wgetmainargs@msvcrt.dll: API Node	
0x0040d526:	movl -48(%ebp), %eax
0x0040d529:	pushl $0x40e3d8<UINT32>
0x0040d52e:	pushl $0x40e3b4<UINT32>
0x0040d533:	call 0x0040d620
0x0040d538:	addl %esp, $0x24<UINT8>
0x0040d53b:	movl %eax, 0x40e314
0x0040d540:	movl %esi, (%eax)
0x0040d542:	cmpl %esi, %edi
0x0040d544:	jne 0x0040d554
0x0040d554:	movl -52(%ebp), %esi
0x0040d557:	cmpw (%esi), $0x22<UINT8>
0x0040d55b:	jne 69
0x0040d55d:	addl %esi, %ebx
0x0040d55f:	movl -52(%ebp), %esi
0x0040d562:	movw %ax, (%esi)
0x0040d565:	cmpw %ax, %di
0x0040d568:	je 6
0x0040d56a:	cmpw %ax, $0x22<UINT16>
0x0040d56e:	jne 0x0040d55d
0x0040d570:	cmpw (%esi), $0x22<UINT8>
0x0040d574:	jne 5
0x0040d576:	addl %esi, %ebx
0x0040d578:	movl -52(%ebp), %esi
0x0040d57b:	movw %ax, (%esi)
0x0040d57e:	cmpw %ax, %di
0x0040d581:	je 6
0x0040d583:	cmpw %ax, $0x20<UINT16>
0x0040d587:	jbe 0x0040d576
0x0040d589:	movl -76(%ebp), %edi
0x0040d58c:	leal %eax, -120(%ebp)
0x0040d58f:	pushl %eax
0x0040d590:	call GetStartupInfoW@KERNEL32.DLL
GetStartupInfoW@KERNEL32.DLL: API Node	
0x0040d596:	testb -76(%ebp), $0x1<UINT8>
0x0040d59a:	je 0x0040d5af
0x0040d5af:	pushl $0xa<UINT8>
0x0040d5b1:	popl %eax
0x0040d5b2:	pushl %eax
0x0040d5b3:	pushl %esi
0x0040d5b4:	pushl %edi
0x0040d5b5:	pushl %edi
0x0040d5b6:	call GetModuleHandleA@KERNEL32.DLL
0x0040d5bc:	pushl %eax
0x0040d5bd:	call 0x0040aa34
0x0040aa34:	pushl %ebp
0x0040aa35:	movl %ebp, %esp
0x0040aa37:	subl %esp, $0x7ac<UINT32>
0x0040aa3d:	call 0x0040230a
0x0040230a:	pushl %ebp
0x0040230b:	movl %ebp, %esp
0x0040230d:	pushl %ecx
0x0040230e:	pushl %ecx
0x0040230f:	pushl %ebx
0x00402310:	pushl %esi
0x00402311:	pushl %edi
0x00402312:	pushl $0x40e720<UINT32>
0x00402317:	movl -8(%ebp), $0x8<UINT32>
0x0040231e:	movl -4(%ebp), $0xff<UINT32>
0x00402325:	xorl %ebx, %ebx
0x00402327:	xorl %edi, %edi
0x00402329:	call LoadLibraryW@KERNEL32.DLL
LoadLibraryW@KERNEL32.DLL: API Node	
0x0040232f:	movl %esi, %eax
0x00402331:	testl %esi, %esi
0x00402333:	je 40
0x00402335:	pushl $0x40e73c<UINT32>
0x0040233a:	pushl %esi
0x0040233b:	call GetProcAddress@KERNEL32.DLL
0x00402341:	testl %eax, %eax
0x00402343:	je 9
0x00402345:	leal %ecx, -8(%ebp)
0x00402348:	pushl %ecx
0x00402349:	incl %edi
0x0040234a:	call InitCommonControlsEx@comctl32.dll
InitCommonControlsEx@comctl32.dll: API Node	
0x0040234c:	movl %ebx, %eax
0x0040234e:	pushl %esi
0x0040234f:	call FreeLibrary@KERNEL32.DLL
FreeLibrary@KERNEL32.DLL: API Node	
0x00402355:	testl %edi, %edi
0x00402357:	je 4
0x00402359:	movl %eax, %ebx
0x0040235b:	jmp 0x00402366
0x00402366:	testl %eax, %eax
0x00402368:	popl %edi
0x00402369:	popl %esi
0x0040236a:	popl %ebx
0x0040236b:	jne 0x00402384
0x0040236d:	pushl $0x30<UINT8>
0x00402384:	xorl %eax, %eax
0x00402386:	incl %eax
0x00402387:	leave
0x00402388:	ret

0x0040aa42:	testl %eax, %eax
0x0040aa44:	jne 0x0040aa4c
0x0040aa4c:	pushl %ebx
0x0040aa4d:	pushl %esi
0x0040aa4e:	call 0x0040ccbd
0x0040ccbd:	cmpl 0x4125c8, $0x0<UINT8>
0x0040ccc4:	jne 37
0x0040ccc6:	pushl $0x40f910<UINT32>
0x0040cccb:	call LoadLibraryW@KERNEL32.DLL
0x0040ccd1:	testl %eax, %eax
0x0040ccd3:	movl 0x4125c8, %eax
0x0040ccd8:	je 17
0x0040ccda:	pushl $0x40f928<UINT32>
0x0040ccdf:	pushl %eax
0x0040cce0:	call GetProcAddress@KERNEL32.DLL
0x0040cce6:	movl 0x4125c4, %eax
0x0040cceb:	ret

0x0040aa53:	pushl $0x8001<UINT32>
0x0040aa58:	call SetErrorMode@KERNEL32.DLL
SetErrorMode@KERNEL32.DLL: API Node	
0x0040aa5e:	xorl %ebx, %ebx
0x0040aa60:	pushl %ebx
0x0040aa61:	pushl $0x40cca2<UINT32>
0x0040aa66:	pushl %ebx
0x0040aa67:	movl 0x411e70, $0x11223344<UINT32>
0x0040aa71:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0040aa77:	pushl %eax
0x0040aa78:	call EnumResourceTypesW@KERNEL32.DLL
EnumResourceTypesW@KERNEL32.DLL: API Node	
0x0040aa7e:	leal %eax, -1964(%ebp)
0x0040aa84:	pushl %eax
0x0040aa85:	movl -32(%ebp), $0x400<UINT32>
0x0040aa8c:	movl -28(%ebp), $0x100<UINT32>
0x0040aa93:	movl -52(%ebp), %ebx
0x0040aa96:	movl -48(%ebp), %ebx
0x0040aa99:	movl -40(%ebp), %ebx
0x0040aa9c:	movl -36(%ebp), %ebx
0x0040aa9f:	movl -24(%ebp), %ebx
0x0040aaa2:	movl -44(%ebp), %ebx
0x0040aaa5:	movl -12(%ebp), $0x20<UINT32>
0x0040aaac:	movl -20(%ebp), %ebx
0x0040aaaf:	movl -8(%ebp), %ebx
0x0040aab2:	movl -16(%ebp), %ebx
0x0040aab5:	movl -4(%ebp), %ebx
0x0040aab8:	call 0x0040a67a
0x0040a67a:	pushl %ebx
0x0040a67b:	pushl %ebp
0x0040a67c:	movl %ebp, 0xc(%esp)
0x0040a680:	pushl %esi
0x0040a681:	xorl %ebx, %ebx
0x0040a683:	pushl %edi
0x0040a684:	leal %edi, 0x6b8(%ebp)
0x0040a68a:	movl 0x208(%ebp), %ebx
0x0040a690:	movl 0x244(%ebp), %ebx
0x0040a696:	movl 0x274(%ebp), %ebx
0x0040a69c:	movl 0x240(%ebp), %ebx
0x0040a6a2:	movl (%ebp), $0x40f5cc<UINT32>
0x0040a6a9:	movl %esi, %edi
0x0040a6ab:	movl 0x694(%ebp), %ebx
0x0040a6b1:	call 0x00401312
0x00401312:	andl 0x10(%esi), $0x0<UINT8>
0x00401316:	pushl $0x2c<UINT8>
0x00401318:	leal %eax, 0x14(%esi)
0x0040131b:	pushl $0x0<UINT8>
0x0040131d:	pushl %eax
0x0040131e:	movl (%esi), $0x40e484<UINT32>
0x00401324:	call 0x0040d39a
0x0040d39a:	jmp memset@msvcrt.dll
memset@msvcrt.dll: API Node	
0x00401329:	addl %esp, $0xc<UINT8>
0x0040132c:	movl %eax, %esi
0x0040132e:	ret

0x0018fed8:	jl -1
0x0018feda:	sbbb (%eax), %al
0x0018fedc:	ret $0x40d5<UINT16>

0x00000000:	addb (%eax), %al
0x00000002:	addb (%eax), %al
0x00000004:	addb (%eax), %al
0x00000006:	addb (%eax), %al
0x00000008:	addb (%eax), %al
0x0000000a:	addb (%eax), %al
0x0000000c:	addb (%eax), %al
0x0000000e:	addb (%eax), %al
0x00000010:	addb (%eax), %al
0x00000012:	addb (%eax), %al
0x00000014:	addb (%eax), %al
0x00000016:	addb (%eax), %al
0x00000018:	addb (%eax), %al
0x0000001a:	addb (%eax), %al
0x0000001c:	addb (%eax), %al
0x0000001e:	addb (%eax), %al
0x00000020:	addb (%eax), %al
0x00000022:	addb (%eax), %al
0x00000024:	addb (%eax), %al
0x00000026:	addb (%eax), %al
0x00000028:	addb (%eax), %al
0x0000002a:	addb (%eax), %al
0x0000002c:	addb (%eax), %al
0x0000002e:	addb (%eax), %al
0x00000030:	addb (%eax), %al
0x00000032:	addb (%eax), %al
0x00000034:	addb (%eax), %al
0x00000036:	addb (%eax), %al
0x00000038:	addb (%eax), %al
0x0000003a:	addb (%eax), %al
0x0000003c:	addb (%eax), %al
0x0000003e:	addb (%eax), %al
0x00000040:	addb (%eax), %al
0x00000042:	addb (%eax), %al
0x00000044:	addb (%eax), %al
0x00000046:	addb (%eax), %al
0x00000048:	addb (%eax), %al
0x0000004a:	addb (%eax), %al
0x0000004c:	addb (%eax), %al
0x0000004e:	addb (%eax), %al
0x00000050:	addb (%eax), %al
0x00000052:	addb (%eax), %al
0x00000054:	addb (%eax), %al
0x00000056:	addb (%eax), %al
0x00000058:	addb (%eax), %al
0x0000005a:	addb (%eax), %al
0x0000005c:	addb (%eax), %al
0x0000005e:	addb (%eax), %al
0x00000060:	addb (%eax), %al
0x00000062:	addb (%eax), %al
0x00000064:	addb (%eax), %al
0x00000066:	addb (%eax), %al
0x0040236f:	pushl $0x40e754<UINT32>
0x00402374:	pushl $0x40e760<UINT32>
0x00402379:	pushl %eax
0x0040237a:	call MessageBoxW@USER32.dll
MessageBoxW@USER32.dll: API Node	
0x00402380:	xorl %eax, %eax
0x00402382:	leave
0x00402383:	ret

0x0040aa46:	incl %eax
0x0040aa47:	jmp 0x0040ac3d
0x0040ac3d:	leave
0x0040ac3e:	ret $0x10<UINT16>

0x0040d5c2:	movl %esi, %eax
0x0040d5c4:	movl -124(%ebp), %esi
0x0040d5c7:	cmpl -28(%ebp), %edi
0x0040d5ca:	jne 7
0x0040d5cc:	pushl %esi
0x0040d5cd:	call exit@msvcrt.dll
exit@msvcrt.dll: Exit Node	
