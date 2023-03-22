0x004344a0:	pusha
0x004344a1:	movl %esi, $0x424000<UINT32>
0x004344a6:	leal %edi, -143360(%esi)
0x004344ac:	pushl %edi
0x004344ad:	jmp 0x004344ba
0x004344ba:	movl %ebx, (%esi)
0x004344bc:	subl %esi, $0xfffffffc<UINT8>
0x004344bf:	adcl %ebx, %ebx
0x004344c1:	jb 0x004344b0
0x004344b0:	movb %al, (%esi)
0x004344b2:	incl %esi
0x004344b3:	movb (%edi), %al
0x004344b5:	incl %edi
0x004344b6:	addl %ebx, %ebx
0x004344b8:	jne 0x004344c1
0x004344c3:	movl %eax, $0x1<UINT32>
0x004344c8:	addl %ebx, %ebx
0x004344ca:	jne 0x004344d3
0x004344d3:	adcl %eax, %eax
0x004344d5:	addl %ebx, %ebx
0x004344d7:	jae 0x004344c8
0x004344d9:	jne 0x004344e4
0x004344e4:	xorl %ecx, %ecx
0x004344e6:	subl %eax, $0x3<UINT8>
0x004344e9:	jb 0x004344f8
0x004344eb:	shll %eax, $0x8<UINT8>
0x004344ee:	movb %al, (%esi)
0x004344f0:	incl %esi
0x004344f1:	xorl %eax, $0xffffffff<UINT8>
0x004344f4:	je 0x0043456a
0x004344f6:	movl %ebp, %eax
0x004344f8:	addl %ebx, %ebx
0x004344fa:	jne 0x00434503
0x00434503:	adcl %ecx, %ecx
0x00434505:	addl %ebx, %ebx
0x00434507:	jne 0x00434510
0x00434510:	adcl %ecx, %ecx
0x00434512:	jne 0x00434534
0x00434534:	cmpl %ebp, $0xfffff300<UINT32>
0x0043453a:	adcl %ecx, $0x1<UINT8>
0x0043453d:	leal %edx, (%edi,%ebp)
0x00434540:	cmpl %ebp, $0xfffffffc<UINT8>
0x00434543:	jbe 0x00434554
0x00434554:	movl %eax, (%edx)
0x00434556:	addl %edx, $0x4<UINT8>
0x00434559:	movl (%edi), %eax
0x0043455b:	addl %edi, $0x4<UINT8>
0x0043455e:	subl %ecx, $0x4<UINT8>
0x00434561:	ja 0x00434554
0x00434563:	addl %edi, %ecx
0x00434565:	jmp 0x004344b6
0x00434514:	incl %ecx
0x00434515:	addl %ebx, %ebx
0x00434517:	jne 0x00434520
0x00434520:	adcl %ecx, %ecx
0x00434522:	addl %ebx, %ebx
0x00434524:	jae 0x00434515
0x00434526:	jne 0x00434531
0x00434531:	addl %ecx, $0x2<UINT8>
0x00434545:	movb %al, (%edx)
0x00434547:	incl %edx
0x00434548:	movb (%edi), %al
0x0043454a:	incl %edi
0x0043454b:	decl %ecx
0x0043454c:	jne 0x00434545
0x0043454e:	jmp 0x004344b6
0x00434528:	movl %ebx, (%esi)
0x0043452a:	subl %esi, $0xfffffffc<UINT8>
0x0043452d:	adcl %ebx, %ebx
0x0043452f:	jae 0x00434515
0x004344fc:	movl %ebx, (%esi)
0x004344fe:	subl %esi, $0xfffffffc<UINT8>
0x00434501:	adcl %ebx, %ebx
0x004344cc:	movl %ebx, (%esi)
0x004344ce:	subl %esi, $0xfffffffc<UINT8>
0x004344d1:	adcl %ebx, %ebx
0x004344db:	movl %ebx, (%esi)
0x004344dd:	subl %esi, $0xfffffffc<UINT8>
0x004344e0:	adcl %ebx, %ebx
0x004344e2:	jae 0x004344c8
0x00434509:	movl %ebx, (%esi)
0x0043450b:	subl %esi, $0xfffffffc<UINT8>
0x0043450e:	adcl %ebx, %ebx
0x00434519:	movl %ebx, (%esi)
0x0043451b:	subl %esi, $0xfffffffc<UINT8>
0x0043451e:	adcl %ebx, %ebx
0x0043456a:	popl %esi
0x0043456b:	movl %edi, %esi
0x0043456d:	movl %ecx, $0x719<UINT32>
0x00434572:	movb %al, (%edi)
0x00434574:	incl %edi
0x00434575:	subb %al, $0xffffffe8<UINT8>
0x00434577:	cmpb %al, $0x1<UINT8>
0x00434579:	ja 0x00434572
0x0043457b:	cmpb (%edi), $0x5<UINT8>
0x0043457e:	jne 0x00434572
0x00434580:	movl %eax, (%edi)
0x00434582:	movb %bl, 0x4(%edi)
0x00434585:	shrw %ax, $0x8<UINT8>
0x00434589:	roll %eax, $0x10<UINT8>
0x0043458c:	xchgb %ah, %al
0x0043458e:	subl %eax, %edi
0x00434590:	subb %bl, $0xffffffe8<UINT8>
0x00434593:	addl %eax, %esi
0x00434595:	movl (%edi), %eax
0x00434597:	addl %edi, $0x5<UINT8>
0x0043459a:	movb %al, %bl
0x0043459c:	loop 0x00434577
0x0043459e:	leal %edi, 0x32000(%esi)
0x004345a4:	movl %eax, (%edi)
0x004345a6:	orl %eax, %eax
0x004345a8:	je 0x004345ef
0x004345aa:	movl %ebx, 0x4(%edi)
0x004345ad:	leal %eax, 0x3457c(%eax,%esi)
0x004345b4:	addl %ebx, %esi
0x004345b6:	pushl %eax
0x004345b7:	addl %edi, $0x8<UINT8>
0x004345ba:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x004345c0:	xchgl %ebp, %eax
0x004345c1:	movb %al, (%edi)
0x004345c3:	incl %edi
0x004345c4:	orb %al, %al
0x004345c6:	je 0x004345a4
0x004345c8:	movl %ecx, %edi
0x004345ca:	jns 0x004345d3
0x004345d3:	pushl %edi
0x004345d4:	decl %eax
0x004345d5:	repn scasb %al, %es:(%edi)
0x004345d7:	pushl %ebp
0x004345d8:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x004345de:	orl %eax, %eax
0x004345e0:	je 7
0x004345e2:	movl (%ebx), %eax
0x004345e4:	addl %ebx, $0x4<UINT8>
0x004345e7:	jmp 0x004345c1
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x004345cc:	movzwl %eax, (%edi)
0x004345cf:	incl %edi
0x004345d0:	pushl %eax
0x004345d1:	incl %edi
0x004345d2:	movl %ecx, $0xaef24857<UINT32>
0x004345ef:	movl %ebp, 0x34668(%esi)
0x004345f5:	leal %edi, -4096(%esi)
0x004345fb:	movl %ebx, $0x1000<UINT32>
0x00434600:	pushl %eax
0x00434601:	pushl %esp
0x00434602:	pushl $0x4<UINT8>
0x00434604:	pushl %ebx
0x00434605:	pushl %edi
0x00434606:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00434608:	leal %eax, 0x1f7(%edi)
0x0043460e:	andb (%eax), $0x7f<UINT8>
0x00434611:	andb 0x28(%eax), $0x7f<UINT8>
0x00434615:	popl %eax
0x00434616:	pushl %eax
0x00434617:	pushl %esp
0x00434618:	pushl %eax
0x00434619:	pushl %ebx
0x0043461a:	pushl %edi
0x0043461b:	call VirtualProtect@kernel32.dll
0x0043461d:	popl %eax
0x0043461e:	popa
0x0043461f:	leal %eax, -128(%esp)
0x00434623:	pushl $0x0<UINT8>
0x00434625:	cmpl %esp, %eax
0x00434627:	jne 0x00434623
0x00434629:	subl %esp, $0xffffff80<UINT8>
0x0043462c:	jmp 0x0040677f
0x0040677f:	call 0x0040d869
0x0040d869:	pushl %ebp
0x0040d86a:	movl %ebp, %esp
0x0040d86c:	subl %esp, $0x10<UINT8>
0x0040d86f:	movl %eax, 0x4190c0
0x0040d874:	andl -8(%ebp), $0x0<UINT8>
0x0040d878:	andl -4(%ebp), $0x0<UINT8>
0x0040d87c:	pushl %ebx
0x0040d87d:	pushl %edi
0x0040d87e:	movl %edi, $0xbb40e64e<UINT32>
0x0040d883:	cmpl %eax, %edi
0x0040d885:	movl %ebx, $0xffff0000<UINT32>
0x0040d88a:	je 0x0040d899
0x0040d899:	pushl %esi
0x0040d89a:	leal %eax, -8(%ebp)
0x0040d89d:	pushl %eax
0x0040d89e:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040d8a4:	movl %esi, -4(%ebp)
0x0040d8a7:	xorl %esi, -8(%ebp)
0x0040d8aa:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040d8b0:	xorl %esi, %eax
0x0040d8b2:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040d8b8:	xorl %esi, %eax
0x0040d8ba:	call GetTickCount@KERNEL32.DLL
GetTickCount@KERNEL32.DLL: API Node	
0x0040d8c0:	xorl %esi, %eax
0x0040d8c2:	leal %eax, -16(%ebp)
0x0040d8c5:	pushl %eax
0x0040d8c6:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040d8cc:	movl %eax, -12(%ebp)
0x0040d8cf:	xorl %eax, -16(%ebp)
0x0040d8d2:	xorl %esi, %eax
0x0040d8d4:	cmpl %esi, %edi
0x0040d8d6:	jne 0x0040d8df
0x0040d8df:	testl %ebx, %esi
0x0040d8e1:	jne 0x0040d8ea
0x0040d8ea:	movl 0x4190c0, %esi
0x0040d8f0:	notl %esi
0x0040d8f2:	movl 0x4190c4, %esi
0x0040d8f8:	popl %esi
0x0040d8f9:	popl %edi
0x0040d8fa:	popl %ebx
0x0040d8fb:	leave
0x0040d8fc:	ret

0x00406784:	jmp 0x004065c9
0x004065c9:	pushl $0x1c<UINT8>
0x004065cb:	pushl $0x417708<UINT32>
0x004065d0:	call 0x00408a1c
0x00408a1c:	pushl $0x405790<UINT32>
0x00408a21:	pushl %fs:0
0x00408a28:	movl %eax, 0x10(%esp)
0x00408a2c:	movl 0x10(%esp), %ebp
0x00408a30:	leal %ebp, 0x10(%esp)
0x00408a34:	subl %esp, %eax
0x00408a36:	pushl %ebx
0x00408a37:	pushl %esi
0x00408a38:	pushl %edi
0x00408a39:	movl %eax, 0x4190c0
0x00408a3e:	xorl -4(%ebp), %eax
0x00408a41:	xorl %eax, %ebp
0x00408a43:	pushl %eax
0x00408a44:	movl -24(%ebp), %esp
0x00408a47:	pushl -8(%ebp)
0x00408a4a:	movl %eax, -4(%ebp)
0x00408a4d:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00408a54:	movl -8(%ebp), %eax
0x00408a57:	leal %eax, -16(%ebp)
0x00408a5a:	movl %fs:0, %eax
0x00408a60:	ret

0x004065d5:	movl %edi, $0x94<UINT32>
0x004065da:	pushl %edi
0x004065db:	pushl $0x0<UINT8>
0x004065dd:	movl %ebx, 0x412158
0x004065e3:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x004065e5:	pushl %eax
0x004065e6:	call HeapAlloc@KERNEL32.DLL
HeapAlloc@KERNEL32.DLL: API Node	
0x004065ec:	movl %esi, %eax
0x004065ee:	testl %esi, %esi
0x004065f0:	jne 0x00406604
0x00406604:	movl (%esi), %edi
0x00406606:	pushl %esi
0x00406607:	call GetVersionExA@KERNEL32.DLL
GetVersionExA@KERNEL32.DLL: API Node	
0x0040660d:	pushl %esi
0x0040660e:	pushl $0x0<UINT8>
0x00406610:	testl %eax, %eax
0x00406612:	jne 0x0040661f
0x0040661f:	movl %eax, 0x10(%esi)
0x00406622:	movl -32(%ebp), %eax
0x00406625:	movl %eax, 0x4(%esi)
0x00406628:	movl -36(%ebp), %eax
0x0040662b:	movl %eax, 0x8(%esi)
0x0040662e:	movl -40(%ebp), %eax
0x00406631:	movl %edi, 0xc(%esi)
0x00406634:	andl %edi, $0x7fff<UINT32>
0x0040663a:	call GetProcessHeap@KERNEL32.DLL
0x0040663c:	pushl %eax
0x0040663d:	call HeapFree@KERNEL32.DLL
HeapFree@KERNEL32.DLL: API Node	
0x00406643:	movl %esi, -32(%ebp)
0x00406646:	cmpl %esi, $0x2<UINT8>
0x00406649:	je 0x00406651
0x00406651:	movl %ecx, -36(%ebp)
0x00406654:	movl %eax, %ecx
0x00406656:	shll %eax, $0x8<UINT8>
0x00406659:	movl %edx, -40(%ebp)
0x0040665c:	addl %eax, %edx
0x0040665e:	movl 0x41aa50, %esi
0x00406664:	movl 0x41aa58, %eax
0x00406669:	movl 0x41aa5c, %ecx
0x0040666f:	movl 0x41aa60, %edx
0x00406675:	movl 0x41aa54, %edi
0x0040667b:	call 0x00406588
0x00406588:	cmpw 0x400000, $0x5a4d<UINT16>
0x00406591:	jne 51
0x00406593:	movl %eax, 0x40003c
0x00406598:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x004065a2:	jne 34
0x004065a4:	cmpw 0x400018(%eax), $0x10b<UINT16>
0x004065ad:	jne 23
0x004065af:	cmpl 0x400074(%eax), $0xe<UINT8>
0x004065b6:	jbe 14
0x004065b8:	xorl %ecx, %ecx
0x004065ba:	cmpl 0x4000e8(%eax), %ecx
0x004065c0:	setne %cl
0x004065c3:	movl %eax, %ecx
0x004065c5:	ret

0x00406680:	movl -32(%ebp), %eax
0x00406683:	pushl $0x1<UINT8>
0x00406685:	call 0x00408ad0
0x00408ad0:	xorl %eax, %eax
0x00408ad2:	cmpl 0x4(%esp), %eax
0x00408ad6:	pushl $0x0<UINT8>
0x00408ad8:	sete %al
0x00408adb:	pushl $0x1000<UINT32>
0x00408ae0:	pushl %eax
0x00408ae1:	call HeapCreate@KERNEL32.DLL
HeapCreate@KERNEL32.DLL: API Node	
0x00408ae7:	testl %eax, %eax
0x00408ae9:	movl 0x41ac4c, %eax
0x00408aee:	jne 0x00408af3
0x00408af3:	call 0x00408a75
0x00408a75:	pushl %ebp
0x00408a76:	movl %ebp, %esp
0x00408a78:	pushl %ecx
0x00408a79:	pushl %ecx
0x00408a7a:	pushl %esi
0x00408a7b:	leal %eax, -4(%ebp)
0x00408a7e:	xorl %esi, %esi
0x00408a80:	pushl %eax
0x00408a81:	movl -4(%ebp), %esi
0x00408a84:	movl -8(%ebp), %esi
0x00408a87:	call 0x004059cf
0x004059cf:	movl %ecx, 0x4(%esp)
0x004059d3:	pushl %esi
0x004059d4:	xorl %esi, %esi
0x004059d6:	cmpl %ecx, %esi
0x004059d8:	jne 0x004059f7
0x004059f7:	movl %eax, 0x41aa50
0x004059fc:	cmpl %eax, %esi
0x004059fe:	je -38
0x00405a00:	movl (%ecx), %eax
0x00405a02:	xorl %eax, %eax
0x00405a04:	popl %esi
0x00405a05:	ret

0x00408a8c:	testl %eax, %eax
0x00408a8e:	popl %ecx
0x00408a8f:	je 0x00408a9e
0x00408a9e:	leal %eax, -8(%ebp)
0x00408aa1:	pushl %eax
0x00408aa2:	call 0x00405a06
0x00405a06:	movl %eax, 0x4(%esp)
0x00405a0a:	pushl %esi
0x00405a0b:	xorl %esi, %esi
0x00405a0d:	cmpl %eax, %esi
0x00405a0f:	jne 0x00405a2e
0x00405a2e:	cmpl 0x41aa50, %esi
0x00405a34:	je -37
0x00405a36:	movl %ecx, 0x41aa5c
0x00405a3c:	movl (%eax), %ecx
0x00405a3e:	xorl %eax, %eax
0x00405a40:	popl %esi
0x00405a41:	ret

0x00408aa7:	testl %eax, %eax
0x00408aa9:	popl %ecx
0x00408aaa:	je 0x00408ab9
0x00408ab9:	cmpl -4(%ebp), $0x2<UINT8>
0x00408abd:	popl %esi
0x00408abe:	jne 11
0x00408ac0:	cmpl -8(%ebp), $0x5<UINT8>
0x00408ac4:	jb 5
0x00408ac6:	xorl %eax, %eax
0x00408ac8:	incl %eax
0x00408ac9:	leave
0x00408aca:	ret

0x00408af8:	cmpl %eax, $0x3<UINT8>
0x00408afb:	movl 0x41b800, %eax
0x00408b00:	jne 0x00408b26
0x00408b26:	xorl %eax, %eax
0x00408b28:	incl %eax
0x00408b29:	ret

0x0040668a:	popl %ecx
0x0040668b:	testl %eax, %eax
0x0040668d:	jne 0x00406697
0x00406697:	call 0x0040756a
0x0040756a:	pushl %edi
0x0040756b:	pushl $0x416360<UINT32>
0x00407570:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x00407576:	movl %edi, %eax
0x00407578:	testl %edi, %edi
0x0040757a:	jne 0x00407585
0x00407585:	pushl %esi
0x00407586:	movl %esi, 0x412100
0x0040758c:	pushl $0x4163a0<UINT32>
0x00407591:	pushl %edi
0x00407592:	call GetProcAddress@KERNEL32.DLL
0x00407594:	pushl $0x416394<UINT32>
0x00407599:	pushl %edi
0x0040759a:	movl 0x41aae0, %eax
0x0040759f:	call GetProcAddress@KERNEL32.DLL
0x004075a1:	pushl $0x416388<UINT32>
0x004075a6:	pushl %edi
0x004075a7:	movl 0x41aae4, %eax
0x004075ac:	call GetProcAddress@KERNEL32.DLL
0x004075ae:	pushl $0x416380<UINT32>
0x004075b3:	pushl %edi
0x004075b4:	movl 0x41aae8, %eax
0x004075b9:	call GetProcAddress@KERNEL32.DLL
0x004075bb:	cmpl 0x41aae0, $0x0<UINT8>
0x004075c2:	movl %esi, 0x412178
0x004075c8:	movl 0x41aaec, %eax
0x004075cd:	je 22
0x004075cf:	cmpl 0x41aae4, $0x0<UINT8>
0x004075d6:	je 13
0x004075d8:	cmpl 0x41aae8, $0x0<UINT8>
0x004075df:	je 4
0x004075e1:	testl %eax, %eax
0x004075e3:	jne 0x00407609
0x00407609:	call TlsAlloc@KERNEL32.DLL
TlsAlloc@KERNEL32.DLL: API Node	
0x0040760f:	cmpl %eax, $0xffffffff<UINT8>
0x00407612:	movl 0x419974, %eax
0x00407617:	je 204
0x0040761d:	pushl 0x41aae4
0x00407623:	pushl %eax
0x00407624:	call TlsSetValue@KERNEL32.DLL
TlsSetValue@KERNEL32.DLL: API Node	
0x00407626:	testl %eax, %eax
0x00407628:	je 187
0x0040762e:	call 0x00405be2
0x00405be2:	pushl %esi
0x00405be3:	call 0x00407181
0x00407181:	pushl $0x0<UINT8>
0x00407183:	call 0x0040711e
0x0040711e:	pushl %esi
0x0040711f:	pushl 0x419974
0x00407125:	movl %esi, 0x412170
0x0040712b:	call TlsGetValue@KERNEL32.DLL
TlsGetValue@KERNEL32.DLL: API Node	
0x0040712d:	testl %eax, %eax
0x0040712f:	je 33
0x00407131:	movl %eax, 0x419970
0x00407136:	cmpl %eax, $0xffffffff<UINT8>
0x00407139:	je 0x00407152
0x00407152:	pushl $0x416360<UINT32>
0x00407157:	call GetModuleHandleA@KERNEL32.DLL
0x0040715d:	testl %eax, %eax
0x0040715f:	je 26
0x00407161:	pushl $0x416350<UINT32>
0x00407166:	pushl %eax
0x00407167:	call GetProcAddress@KERNEL32.DLL
0x0040716d:	testl %eax, %eax
0x0040716f:	je 10
0x00407171:	pushl 0x8(%esp)
0x00407175:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00407177:	movl 0x8(%esp), %eax
0x0040717b:	movl %eax, 0x8(%esp)
0x0040717f:	popl %esi
0x00407180:	ret

0x00407188:	popl %ecx
0x00407189:	ret

0x00405be8:	movl %esi, %eax
0x00405bea:	pushl %esi
0x00405beb:	call 0x00408d03
0x00408d03:	movl %eax, 0x4(%esp)
0x00408d07:	movl 0x41af64, %eax
0x00408d0c:	ret

0x00405bf0:	pushl %esi
0x00405bf1:	call 0x0040b726
0x0040b726:	movl %eax, 0x4(%esp)
0x0040b72a:	movl 0x41b2c8, %eax
0x0040b72f:	ret

0x00405bf6:	pushl %esi
0x00405bf7:	call 0x00407ad3
0x00407ad3:	movl %eax, 0x4(%esp)
0x00407ad7:	movl 0x41aaf4, %eax
0x00407adc:	ret

0x00405bfc:	pushl %esi
0x00405bfd:	call 0x0040b71c
0x0040b71c:	movl %eax, 0x4(%esp)
0x0040b720:	movl 0x41b2c4, %eax
0x0040b725:	ret

0x00405c02:	pushl %esi
0x00405c03:	call 0x0040b712
0x0040b712:	movl %eax, 0x4(%esp)
0x0040b716:	movl 0x41b2b8, %eax
0x0040b71b:	ret

0x00405c08:	pushl %esi
0x00405c09:	call 0x0040b508
0x0040b508:	movl %eax, 0x4(%esp)
0x0040b50c:	movl 0x41b2a4, %eax
0x0040b511:	movl 0x41b2a8, %eax
0x0040b516:	movl 0x41b2ac, %eax
0x0040b51b:	movl 0x41b2b0, %eax
0x0040b520:	ret

0x00405c0e:	pushl %esi
0x00405c0f:	call 0x0040af1e
0x0040af1e:	ret

0x00405c14:	pushl %esi
0x00405c15:	call 0x0040b4f7
0x0040b4f7:	pushl $0x40b4be<UINT32>
0x0040b4fc:	call 0x0040711e
0x0040b501:	popl %ecx
0x0040b502:	movl 0x41b2a0, %eax
0x0040b507:	ret

0x00405c1a:	pushl $0x405bb3<UINT32>
0x00405c1f:	call 0x0040711e
0x00405c24:	addl %esp, $0x24<UINT8>
0x00405c27:	movl 0x41934c, %eax
0x00405c2c:	popl %esi
0x00405c2d:	ret

0x00407633:	pushl 0x41aae0
0x00407639:	call 0x0040711e
0x0040763e:	pushl 0x41aae4
0x00407644:	movl 0x41aae0, %eax
0x00407649:	call 0x0040711e
0x0040764e:	pushl 0x41aae8
0x00407654:	movl 0x41aae4, %eax
0x00407659:	call 0x0040711e
0x0040765e:	pushl 0x41aaec
0x00407664:	movl 0x41aae8, %eax
0x00407669:	call 0x0040711e
0x0040766e:	addl %esp, $0x10<UINT8>
0x00407671:	movl 0x41aaec, %eax
0x00407676:	call 0x00407d76
0x00407d76:	pushl %esi
0x00407d77:	pushl %edi
0x00407d78:	xorl %esi, %esi
0x00407d7a:	movl %edi, $0x41aaf8<UINT32>
0x00407d7f:	cmpl 0x419aec(,%esi,8), $0x1<UINT8>
0x00407d87:	jne 0x00407da7
0x00407d89:	leal %eax, 0x419ae8(,%esi,8)
0x00407d90:	movl (%eax), %edi
0x00407d92:	pushl $0xfa0<UINT32>
0x00407d97:	pushl (%eax)
0x00407d99:	addl %edi, $0x18<UINT8>
0x00407d9c:	call 0x0040b740
0x0040b740:	pushl $0x14<UINT8>
0x0040b742:	pushl $0x417930<UINT32>
0x0040b747:	call 0x00408a1c
0x0040b74c:	xorl %edi, %edi
0x0040b74e:	movl -28(%ebp), %edi
0x0040b751:	pushl 0x41b2c8
0x0040b757:	call 0x0040718a
0x0040718a:	pushl %esi
0x0040718b:	pushl 0x419974
0x00407191:	movl %esi, 0x412170
0x00407197:	call TlsGetValue@KERNEL32.DLL
0x00407199:	testl %eax, %eax
0x0040719b:	je 33
0x0040719d:	movl %eax, 0x419970
0x004071a2:	cmpl %eax, $0xffffffff<UINT8>
0x004071a5:	je 0x004071be
0x004071be:	pushl $0x416360<UINT32>
0x004071c3:	call GetModuleHandleA@KERNEL32.DLL
0x004071c9:	testl %eax, %eax
0x004071cb:	je 26
0x004071cd:	pushl $0x416370<UINT32>
0x004071d2:	pushl %eax
0x004071d3:	call GetProcAddress@KERNEL32.DLL
0x004071d9:	testl %eax, %eax
0x004071db:	je 10
0x004071dd:	pushl 0x8(%esp)
0x004071e1:	call DecodePointer@KERNEL32.DLL
DecodePointer@KERNEL32.DLL: API Node	
0x004071e3:	movl 0x8(%esp), %eax
0x004071e7:	movl %eax, 0x8(%esp)
0x004071eb:	popl %esi
0x004071ec:	ret

0x0040b75c:	popl %ecx
0x0040b75d:	movl %esi, %eax
0x0040b75f:	cmpl %esi, %edi
0x0040b761:	jne 0x0040b7b6
0x0040b763:	leal %eax, -28(%ebp)
0x0040b766:	pushl %eax
0x0040b767:	call 0x004059cf
0x0040b76c:	popl %ecx
0x0040b76d:	cmpl %eax, %edi
0x0040b76f:	je 0x0040b77e
0x0040b77e:	cmpl -28(%ebp), $0x1<UINT8>
0x0040b782:	je 33
0x0040b784:	pushl $0x416a40<UINT32>
0x0040b789:	call GetModuleHandleA@KERNEL32.DLL
0x0040b78f:	cmpl %eax, %edi
0x0040b791:	je 18
0x0040b793:	pushl $0x416a18<UINT32>
0x0040b798:	pushl %eax
0x0040b799:	call GetProcAddress@KERNEL32.DLL
0x0040b79f:	movl %esi, %eax
0x0040b7a1:	cmpl %esi, %edi
0x0040b7a3:	jne 0x0040b7aa
0x0040b7aa:	pushl %esi
0x0040b7ab:	call 0x0040711e
0x0040b7b0:	popl %ecx
0x0040b7b1:	movl 0x41b2c8, %eax
0x0040b7b6:	movl -4(%ebp), %edi
0x0040b7b9:	pushl 0xc(%ebp)
0x0040b7bc:	pushl 0x8(%ebp)
0x0040b7bf:	call InitializeCriticalSectionAndSpinCount@kernel32.dll
InitializeCriticalSectionAndSpinCount@kernel32.dll: API Node	
0x0040b7c1:	movl -32(%ebp), %eax
0x0040b7c4:	jmp 0x0040b7f5
0x0040b7f5:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040b7fc:	movl %eax, -32(%ebp)
0x0040b7ff:	call 0x00408a61
0x00408a61:	movl %ecx, -16(%ebp)
0x00408a64:	movl %fs:0, %ecx
0x00408a6b:	popl %ecx
0x00408a6c:	popl %edi
0x00408a6d:	popl %edi
0x00408a6e:	popl %esi
0x00408a6f:	popl %ebx
0x00408a70:	movl %esp, %ebp
0x00408a72:	popl %ebp
0x00408a73:	pushl %ecx
0x00408a74:	ret

0x0040b804:	ret

0x00407da1:	testl %eax, %eax
0x00407da3:	popl %ecx
0x00407da4:	popl %ecx
0x00407da5:	je 12
0x00407da7:	incl %esi
0x00407da8:	cmpl %esi, $0x24<UINT8>
0x00407dab:	jl 0x00407d7f
0x00407dad:	xorl %eax, %eax
0x00407daf:	incl %eax
0x00407db0:	popl %edi
0x00407db1:	popl %esi
0x00407db2:	ret

0x0040767b:	testl %eax, %eax
0x0040767d:	je 101
0x0040767f:	pushl $0x4073e0<UINT32>
0x00407684:	pushl 0x41aae0
0x0040768a:	call 0x0040718a
0x0040768f:	popl %ecx
0x00407690:	call FlsAlloc@KERNEL32.DLL
FlsAlloc@KERNEL32.DLL: API Node	
0x00407692:	cmpl %eax, $0xffffffff<UINT8>
0x00407695:	movl 0x419970, %eax
0x0040769a:	je 72
0x0040769c:	pushl $0x214<UINT32>
0x004076a1:	pushl $0x1<UINT8>
0x004076a3:	call 0x00409f6a
0x00409f6a:	pushl %esi
0x00409f6b:	pushl %edi
0x00409f6c:	xorl %esi, %esi
0x00409f6e:	pushl $0x0<UINT8>
0x00409f70:	pushl 0x14(%esp)
0x00409f74:	pushl 0x14(%esp)
0x00409f78:	call 0x0040ec25
0x0040ec25:	pushl $0xc<UINT8>
0x0040ec27:	pushl $0x417990<UINT32>
0x0040ec2c:	call 0x00408a1c
0x0040ec31:	movl %ecx, 0x8(%ebp)
0x0040ec34:	xorl %edi, %edi
0x0040ec36:	cmpl %ecx, %edi
0x0040ec38:	jbe 46
0x0040ec3a:	pushl $0xffffffe0<UINT8>
0x0040ec3c:	popl %eax
0x0040ec3d:	xorl %edx, %edx
0x0040ec3f:	divl %eax, %ecx
0x0040ec41:	cmpl %eax, 0xc(%ebp)
0x0040ec44:	sbbl %eax, %eax
0x0040ec46:	incl %eax
0x0040ec47:	jne 0x0040ec68
0x0040ec68:	imull %ecx, 0xc(%ebp)
0x0040ec6c:	movl %esi, %ecx
0x0040ec6e:	movl 0x8(%ebp), %esi
0x0040ec71:	cmpl %esi, %edi
0x0040ec73:	jne 0x0040ec78
0x0040ec78:	xorl %ebx, %ebx
0x0040ec7a:	movl -28(%ebp), %ebx
0x0040ec7d:	cmpl %esi, $0xffffffe0<UINT8>
0x0040ec80:	ja 105
0x0040ec82:	cmpl 0x41b800, $0x3<UINT8>
0x0040ec89:	jne 0x0040ecd6
0x0040ecd6:	cmpl %ebx, %edi
0x0040ecd8:	jne 97
0x0040ecda:	pushl %esi
0x0040ecdb:	pushl $0x8<UINT8>
0x0040ecdd:	pushl 0x41ac4c
0x0040ece3:	call HeapAlloc@KERNEL32.DLL
0x0040ece9:	movl %ebx, %eax
0x0040eceb:	cmpl %ebx, %edi
0x0040eced:	jne 0x0040ed3b
0x0040ed3b:	movl %eax, %ebx
0x0040ed3d:	call 0x00408a61
0x0040ed42:	ret

0x00409f7d:	movl %edi, %eax
0x00409f7f:	addl %esp, $0xc<UINT8>
0x00409f82:	testl %edi, %edi
0x00409f84:	jne 0x00409fad
0x00409fad:	movl %eax, %edi
0x00409faf:	popl %edi
0x00409fb0:	popl %esi
0x00409fb1:	ret

0x004076a8:	movl %esi, %eax
0x004076aa:	testl %esi, %esi
0x004076ac:	popl %ecx
0x004076ad:	popl %ecx
0x004076ae:	je 52
0x004076b0:	pushl %esi
0x004076b1:	pushl 0x419970
0x004076b7:	pushl 0x41aae8
0x004076bd:	call 0x0040718a
0x004071a7:	pushl %eax
0x004071a8:	pushl 0x419974
0x004071ae:	call TlsGetValue@KERNEL32.DLL
0x004071b0:	call FlsGetValue@KERNEL32.DLL
FlsGetValue@KERNEL32.DLL: API Node	
0x004071b2:	testl %eax, %eax
0x004071b4:	je 0x004071be
0x004076c2:	popl %ecx
0x004076c3:	call FlsSetValue@KERNEL32.DLL
FlsSetValue@KERNEL32.DLL: API Node	
0x004076c5:	testl %eax, %eax
0x004076c7:	je 27
0x004076c9:	pushl $0x0<UINT8>
0x004076cb:	pushl %esi
0x004076cc:	call 0x00407291
0x00407291:	pushl $0xc<UINT8>
0x00407293:	pushl $0x417788<UINT32>
0x00407298:	call 0x00408a1c
0x0040729d:	pushl $0x416360<UINT32>
0x004072a2:	call GetModuleHandleA@KERNEL32.DLL
0x004072a8:	movl -28(%ebp), %eax
0x004072ab:	movl %esi, 0x8(%ebp)
0x004072ae:	movl 0x5c(%esi), $0x419cf8<UINT32>
0x004072b5:	xorl %edi, %edi
0x004072b7:	incl %edi
0x004072b8:	movl 0x14(%esi), %edi
0x004072bb:	testl %eax, %eax
0x004072bd:	je 36
0x004072bf:	pushl $0x416350<UINT32>
0x004072c4:	pushl %eax
0x004072c5:	movl %ebx, 0x412100
0x004072cb:	call GetProcAddress@KERNEL32.DLL
0x004072cd:	movl 0x1f8(%esi), %eax
0x004072d3:	pushl $0x416370<UINT32>
0x004072d8:	pushl -28(%ebp)
0x004072db:	call GetProcAddress@KERNEL32.DLL
0x004072dd:	movl 0x1fc(%esi), %eax
0x004072e3:	movl 0x70(%esi), %edi
0x004072e6:	movb 0xc8(%esi), $0x43<UINT8>
0x004072ed:	movb 0x14b(%esi), $0x43<UINT8>
0x004072f4:	movl %eax, $0x419358<UINT32>
0x004072f9:	movl 0x68(%esi), %eax
0x004072fc:	pushl %eax
0x004072fd:	call InterlockedIncrement@KERNEL32.DLL
InterlockedIncrement@KERNEL32.DLL: API Node	
0x00407303:	pushl $0xc<UINT8>
0x00407305:	call 0x00407eec
0x00407eec:	pushl %ebp
0x00407eed:	movl %ebp, %esp
0x00407eef:	movl %eax, 0x8(%ebp)
0x00407ef2:	pushl %esi
0x00407ef3:	leal %esi, 0x419ae8(,%eax,8)
0x00407efa:	cmpl (%esi), $0x0<UINT8>
0x00407efd:	jne 0x00407f12
0x00407f12:	pushl (%esi)
0x00407f14:	call EnterCriticalSection@KERNEL32.DLL
EnterCriticalSection@KERNEL32.DLL: API Node	
0x00407f1a:	popl %esi
0x00407f1b:	popl %ebp
0x00407f1c:	ret

0x0040730a:	popl %ecx
0x0040730b:	andl -4(%ebp), $0x0<UINT8>
0x0040730f:	movl %eax, 0xc(%ebp)
0x00407312:	movl 0x6c(%esi), %eax
0x00407315:	testl %eax, %eax
0x00407317:	jne 8
0x00407319:	movl %eax, 0x419960
0x0040731e:	movl 0x6c(%esi), %eax
0x00407321:	pushl 0x6c(%esi)
0x00407324:	call 0x00406f58
0x00406f58:	pushl %ebx
0x00406f59:	pushl %ebp
0x00406f5a:	pushl %esi
0x00406f5b:	movl %esi, 0x10(%esp)
0x00406f5f:	pushl %edi
0x00406f60:	movl %edi, 0x412160
0x00406f66:	pushl %esi
0x00406f67:	call InterlockedIncrement@KERNEL32.DLL
0x00406f69:	movl %eax, 0xb0(%esi)
0x00406f6f:	testl %eax, %eax
0x00406f71:	je 0x00406f76
0x00406f76:	movl %eax, 0xb8(%esi)
0x00406f7c:	testl %eax, %eax
0x00406f7e:	je 0x00406f83
0x00406f83:	movl %eax, 0xb4(%esi)
0x00406f89:	testl %eax, %eax
0x00406f8b:	je 0x00406f90
0x00406f90:	movl %eax, 0xc0(%esi)
0x00406f96:	testl %eax, %eax
0x00406f98:	je 0x00406f9d
0x00406f9d:	pushl $0x6<UINT8>
0x00406f9f:	leal %ebx, 0x50(%esi)
0x00406fa2:	popl %ebp
0x00406fa3:	cmpl -8(%ebx), $0x419880<UINT32>
0x00406faa:	je 0x00406fb5
0x00406fac:	movl %eax, (%ebx)
0x00406fae:	testl %eax, %eax
0x00406fb0:	je 0x00406fb5
0x00406fb5:	cmpl -4(%ebx), $0x0<UINT8>
0x00406fb9:	je 0x00406fc5
0x00406fc5:	addl %ebx, $0x10<UINT8>
0x00406fc8:	decl %ebp
0x00406fc9:	jne 0x00406fa3
0x00406fcb:	movl %eax, 0xd4(%esi)
0x00406fd1:	addl %eax, $0xb4<UINT32>
0x00406fd6:	pushl %eax
0x00406fd7:	call InterlockedIncrement@KERNEL32.DLL
0x00406fd9:	popl %edi
0x00406fda:	popl %esi
0x00406fdb:	popl %ebp
0x00406fdc:	popl %ebx
0x00406fdd:	ret

0x00407329:	popl %ecx
0x0040732a:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00407331:	call 0x0040733c
0x0040733c:	pushl $0xc<UINT8>
0x0040733e:	call 0x00407e14
0x00407e14:	pushl %ebp
0x00407e15:	movl %ebp, %esp
0x00407e17:	movl %eax, 0x8(%ebp)
0x00407e1a:	pushl 0x419ae8(,%eax,8)
0x00407e21:	call LeaveCriticalSection@KERNEL32.DLL
LeaveCriticalSection@KERNEL32.DLL: API Node	
0x00407e27:	popl %ebp
0x00407e28:	ret

0x00407343:	popl %ecx
0x00407344:	ret

0x00407336:	call 0x00408a61
0x0040733b:	ret

0x004076d1:	popl %ecx
0x004076d2:	popl %ecx
0x004076d3:	call GetCurrentThreadId@KERNEL32.DLL
0x004076d9:	orl 0x4(%esi), $0xffffffff<UINT8>
0x004076dd:	movl (%esi), %eax
0x004076df:	xorl %eax, %eax
0x004076e1:	incl %eax
0x004076e2:	jmp 0x004076eb
0x004076eb:	popl %esi
0x004076ec:	popl %edi
0x004076ed:	ret

0x0040669c:	testl %eax, %eax
0x0040669e:	jne 0x004066a8
0x004066a8:	call 0x0040b457
0x0040b457:	pushl %esi
0x0040b458:	pushl %edi
0x0040b459:	movl %eax, $0x4174f0<UINT32>
0x0040b45e:	movl %edi, $0x4174f0<UINT32>
0x0040b463:	cmpl %eax, %edi
0x0040b465:	movl %esi, %eax
0x0040b467:	jae 0x0040b478
0x0040b478:	popl %edi
0x0040b479:	popl %esi
0x0040b47a:	ret

0x004066ad:	andl -4(%ebp), $0x0<UINT8>
0x004066b1:	call 0x00409cbd
0x00409cbd:	pushl $0x54<UINT8>
0x00409cbf:	pushl $0x4177f0<UINT32>
0x00409cc4:	call 0x00408a1c
0x00409cc9:	xorl %edi, %edi
0x00409ccb:	movl -4(%ebp), %edi
0x00409cce:	leal %eax, -100(%ebp)
0x00409cd1:	pushl %eax
0x00409cd2:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x00409cd8:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00409cdf:	pushl $0x28<UINT8>
0x00409ce1:	pushl $0x20<UINT8>
0x00409ce3:	popl %esi
0x00409ce4:	pushl %esi
0x00409ce5:	call 0x00409f6a
0x00409cea:	popl %ecx
0x00409ceb:	popl %ecx
0x00409cec:	cmpl %eax, %edi
0x00409cee:	je 512
0x00409cf4:	movl 0x41b700, %eax
0x00409cf9:	movl 0x41b6ec, %esi
0x00409cff:	leal %ecx, 0x500(%eax)
0x00409d05:	jmp 0x00409d30
0x00409d30:	cmpl %eax, %ecx
0x00409d32:	jb 0x00409d07
0x00409d07:	movb 0x4(%eax), $0x0<UINT8>
0x00409d0b:	orl (%eax), $0xffffffff<UINT8>
0x00409d0e:	movb 0x5(%eax), $0xa<UINT8>
0x00409d12:	movl 0x8(%eax), %edi
0x00409d15:	movb 0x24(%eax), $0x0<UINT8>
0x00409d19:	movb 0x25(%eax), $0xa<UINT8>
0x00409d1d:	movb 0x26(%eax), $0xa<UINT8>
0x00409d21:	addl %eax, $0x28<UINT8>
0x00409d24:	movl %ecx, 0x41b700
0x00409d2a:	addl %ecx, $0x500<UINT32>
0x00409d34:	cmpw -50(%ebp), %di
0x00409d38:	je 253
0x00409d3e:	movl %eax, -48(%ebp)
0x00409d41:	cmpl %eax, %edi
0x00409d43:	je 242
0x00409d49:	movl %edi, (%eax)
0x00409d4b:	leal %ebx, 0x4(%eax)
0x00409d4e:	leal %eax, (%ebx,%edi)
0x00409d51:	movl -28(%ebp), %eax
0x00409d54:	movl %eax, $0x800<UINT32>
0x00409d59:	cmpl %edi, %eax
0x00409d5b:	jl 0x00409d5f
0x00409d5f:	xorl %esi, %esi
0x00409d61:	incl %esi
0x00409d62:	jmp 0x00409db6
0x00409db6:	cmpl 0x41b6ec, %edi
0x00409dbc:	jl -90
0x00409dbe:	jmp 0x00409dc6
0x00409dc6:	andl -32(%ebp), $0x0<UINT8>
0x00409dca:	testl %edi, %edi
0x00409dcc:	jle 0x00409e3b
0x00409e3b:	xorl %ebx, %ebx
0x00409e3d:	movl %esi, %ebx
0x00409e3f:	imull %esi, %esi, $0x28<UINT8>
0x00409e42:	addl %esi, 0x41b700
0x00409e48:	movl %eax, (%esi)
0x00409e4a:	cmpl %eax, $0xffffffff<UINT8>
0x00409e4d:	je 0x00409e5a
0x00409e5a:	movb 0x4(%esi), $0xffffff81<UINT8>
0x00409e5e:	testl %ebx, %ebx
0x00409e60:	jne 0x00409e67
0x00409e62:	pushl $0xfffffff6<UINT8>
0x00409e64:	popl %eax
0x00409e65:	jmp 0x00409e71
0x00409e71:	pushl %eax
0x00409e72:	call GetStdHandle@KERNEL32.DLL
GetStdHandle@KERNEL32.DLL: API Node	
0x00409e78:	movl %edi, %eax
0x00409e7a:	cmpl %edi, $0xffffffff<UINT8>
0x00409e7d:	je 67
0x00409e7f:	testl %edi, %edi
0x00409e81:	je 63
0x00409e83:	pushl %edi
0x00409e84:	call GetFileType@KERNEL32.DLL
GetFileType@KERNEL32.DLL: API Node	
0x00409e8a:	testl %eax, %eax
0x00409e8c:	je 52
0x00409e8e:	movl (%esi), %edi
0x00409e90:	andl %eax, $0xff<UINT32>
0x00409e95:	cmpl %eax, $0x2<UINT8>
0x00409e98:	jne 6
0x00409e9a:	orb 0x4(%esi), $0x40<UINT8>
0x00409e9e:	jmp 0x00409ea9
0x00409ea9:	pushl $0xfa0<UINT32>
0x00409eae:	leal %eax, 0xc(%esi)
0x00409eb1:	pushl %eax
0x00409eb2:	call 0x0040b740
0x004071b6:	movl %eax, 0x1fc(%eax)
0x004071bc:	jmp 0x004071d9
0x00409eb7:	popl %ecx
0x00409eb8:	popl %ecx
0x00409eb9:	testl %eax, %eax
0x00409ebb:	je 55
0x00409ebd:	incl 0x8(%esi)
0x00409ec0:	jmp 0x00409ecc
0x00409ecc:	incl %ebx
0x00409ecd:	cmpl %ebx, $0x3<UINT8>
0x00409ed0:	jl 0x00409e3d
0x00409e67:	movl %eax, %ebx
0x00409e69:	decl %eax
0x00409e6a:	negl %eax
0x00409e6c:	sbbl %eax, %eax
0x00409e6e:	addl %eax, $0xfffffff5<UINT8>
0x00409ed6:	pushl 0x41b6ec
0x00409edc:	call SetHandleCount@KERNEL32.DLL
SetHandleCount@KERNEL32.DLL: API Node	
0x00409ee2:	xorl %eax, %eax
0x00409ee4:	jmp 0x00409ef7
0x00409ef7:	call 0x00408a61
0x00409efc:	ret

0x004066b6:	testl %eax, %eax
0x004066b8:	jnl 0x004066c2
0x004066c2:	call GetCommandLineA@KERNEL32.DLL
GetCommandLineA@KERNEL32.DLL: API Node	
0x004066c8:	movl 0x41b824, %eax
0x004066cd:	call 0x0040d734
0x0040d734:	pushl %ecx
0x0040d735:	pushl %ecx
0x0040d736:	movl %eax, 0x41b3d8
0x0040d73b:	pushl %ebx
0x0040d73c:	pushl %ebp
0x0040d73d:	pushl %esi
0x0040d73e:	pushl %edi
0x0040d73f:	movl %edi, 0x4120d0
0x0040d745:	xorl %ebx, %ebx
0x0040d747:	xorl %esi, %esi
0x0040d749:	cmpl %eax, %ebx
0x0040d74b:	pushl $0x2<UINT8>
0x0040d74d:	popl %ebp
0x0040d74e:	jne 45
0x0040d750:	call GetEnvironmentStringsW@KERNEL32.DLL
GetEnvironmentStringsW@KERNEL32.DLL: API Node	
0x0040d752:	movl %esi, %eax
0x0040d754:	cmpl %esi, %ebx
0x0040d756:	je 12
0x0040d758:	movl 0x41b3d8, $0x1<UINT32>
0x0040d762:	jmp 0x0040d786
0x0040d786:	cmpl %esi, %ebx
0x0040d788:	jne 0x0040d799
0x0040d799:	cmpw (%esi), %bx
0x0040d79c:	movl %eax, %esi
0x0040d79e:	je 14
0x0040d7a0:	addl %eax, %ebp
0x0040d7a2:	cmpw (%eax), %bx
0x0040d7a5:	jne 0x0040d7a0
0x0040d7a7:	addl %eax, %ebp
0x0040d7a9:	cmpw (%eax), %bx
0x0040d7ac:	jne 0x0040d7a0
0x0040d7ae:	movl %edi, 0x4120a4
0x0040d7b4:	pushl %ebx
0x0040d7b5:	pushl %ebx
0x0040d7b6:	pushl %ebx
0x0040d7b7:	subl %eax, %esi
0x0040d7b9:	pushl %ebx
0x0040d7ba:	sarl %eax
0x0040d7bc:	incl %eax
0x0040d7bd:	pushl %eax
0x0040d7be:	pushl %esi
0x0040d7bf:	pushl %ebx
0x0040d7c0:	pushl %ebx
0x0040d7c1:	movl 0x34(%esp), %eax
0x0040d7c5:	call WideCharToMultiByte@KERNEL32.DLL
WideCharToMultiByte@KERNEL32.DLL: API Node	
0x0040d7c7:	movl %ebp, %eax
0x0040d7c9:	cmpl %ebp, %ebx
0x0040d7cb:	je 50
0x0040d7cd:	pushl %ebp
0x0040d7ce:	call 0x00409f2a
0x00409f2a:	pushl %esi
0x00409f2b:	pushl %edi
0x00409f2c:	xorl %esi, %esi
0x00409f2e:	pushl 0xc(%esp)
0x00409f32:	call 0x004041a9
0x004041a9:	pushl %ebp
0x004041aa:	movl %ebp, 0x8(%esp)
0x004041ae:	cmpl %ebp, $0xffffffe0<UINT8>
0x004041b1:	ja 0x00404256
0x004041b7:	pushl %ebx
0x004041b8:	movl %ebx, 0x412124
0x004041be:	pushl %esi
0x004041bf:	pushl %edi
0x004041c0:	xorl %esi, %esi
0x004041c2:	cmpl 0x41ac4c, %esi
0x004041c8:	movl %edi, %ebp
0x004041ca:	jne 0x004041e4
0x004041e4:	movl %eax, 0x41b800
0x004041e9:	cmpl %eax, $0x1<UINT8>
0x004041ec:	jne 14
0x004041ee:	cmpl %ebp, %esi
0x004041f0:	je 0x004041f6
0x004041f2:	movl %eax, %ebp
0x004041f4:	jmp 0x004041f9
0x004041f9:	pushl %eax
0x004041fa:	jmp 0x0040421a
0x0040421a:	pushl %esi
0x0040421b:	pushl 0x41ac4c
0x00404221:	call HeapAlloc@KERNEL32.DLL
0x00404223:	movl %esi, %eax
0x00404225:	testl %esi, %esi
0x00404227:	jne 0x0040424f
0x0040424f:	popl %edi
0x00404250:	movl %eax, %esi
0x00404252:	popl %esi
0x00404253:	popl %ebx
0x00404254:	popl %ebp
0x00404255:	ret

0x00409f37:	movl %edi, %eax
0x00409f39:	testl %edi, %edi
0x00409f3b:	popl %ecx
0x00409f3c:	jne 0x00409f65
0x00409f65:	movl %eax, %edi
0x00409f67:	popl %edi
0x00409f68:	popl %esi
0x00409f69:	ret

0x0040d7d3:	cmpl %eax, %ebx
0x0040d7d5:	popl %ecx
0x0040d7d6:	movl 0x10(%esp), %eax
0x0040d7da:	je 35
0x0040d7dc:	pushl %ebx
0x0040d7dd:	pushl %ebx
0x0040d7de:	pushl %ebp
0x0040d7df:	pushl %eax
0x0040d7e0:	pushl 0x24(%esp)
0x0040d7e4:	pushl %esi
0x0040d7e5:	pushl %ebx
0x0040d7e6:	pushl %ebx
0x0040d7e7:	call WideCharToMultiByte@KERNEL32.DLL
0x0040d7e9:	testl %eax, %eax
0x0040d7eb:	jne 0x0040d7fb
0x0040d7fb:	movl %ebx, 0x10(%esp)
0x0040d7ff:	pushl %esi
0x0040d800:	call FreeEnvironmentStringsW@KERNEL32.DLL
FreeEnvironmentStringsW@KERNEL32.DLL: API Node	
0x0040d806:	movl %eax, %ebx
0x0040d808:	jmp 0x0040d862
0x0040d862:	popl %edi
0x0040d863:	popl %esi
0x0040d864:	popl %ebp
0x0040d865:	popl %ebx
0x0040d866:	popl %ecx
0x0040d867:	popl %ecx
0x0040d868:	ret

0x004066d2:	movl 0x41aa94, %eax
0x004066d7:	call 0x0040d67b
0x0040d67b:	pushl %ebp
0x0040d67c:	movl %ebp, %esp
0x0040d67e:	subl %esp, $0xc<UINT8>
0x0040d681:	pushl %ebx
0x0040d682:	xorl %ebx, %ebx
0x0040d684:	cmpl 0x41b834, %ebx
0x0040d68a:	pushl %esi
0x0040d68b:	pushl %edi
0x0040d68c:	jne 5
0x0040d68e:	call 0x00406dfa
0x00406dfa:	cmpl 0x41b834, $0x0<UINT8>
0x00406e01:	jne 0x00406e15
0x00406e03:	pushl $0xfffffffd<UINT8>
0x00406e05:	call 0x00406c60
0x00406c60:	pushl $0x14<UINT8>
0x00406c62:	pushl $0x417748<UINT32>
0x00406c67:	call 0x00408a1c
0x00406c6c:	orl -32(%ebp), $0xffffffff<UINT8>
0x00406c70:	call 0x004073c8
0x004073c8:	pushl %esi
0x004073c9:	call 0x00407345
0x00407345:	pushl %esi
0x00407346:	pushl %edi
0x00407347:	call GetLastError@KERNEL32.DLL
GetLastError@KERNEL32.DLL: API Node	
0x0040734d:	movl %edi, %eax
0x0040734f:	call 0x00407211
0x00407211:	pushl 0x419974
0x00407217:	call TlsGetValue@KERNEL32.DLL
0x0040721d:	testl %eax, %eax
0x0040721f:	jne 0x0040723a
0x0040723a:	ret

0x00407354:	pushl 0x419970
0x0040735a:	pushl 0x419974
0x00407360:	call TlsGetValue@KERNEL32.DLL
0x00407366:	call FlsGetValue@KERNEL32.DLL
0x00407368:	movl %esi, %eax
0x0040736a:	testl %esi, %esi
0x0040736c:	jne 0x004073bc
0x004073bc:	pushl %edi
0x004073bd:	call SetLastError@KERNEL32.DLL
SetLastError@KERNEL32.DLL: API Node	
0x004073c3:	popl %edi
0x004073c4:	movl %eax, %esi
0x004073c6:	popl %esi
0x004073c7:	ret

0x004073ce:	movl %esi, %eax
0x004073d0:	testl %esi, %esi
0x004073d2:	jne 0x004073dc
0x004073dc:	movl %eax, %esi
0x004073de:	popl %esi
0x004073df:	ret

0x00406c75:	movl %edi, %eax
0x00406c77:	movl -36(%ebp), %edi
0x00406c7a:	call 0x00406997
0x00406997:	pushl $0xc<UINT8>
0x00406999:	pushl $0x417728<UINT32>
0x0040699e:	call 0x00408a1c
0x004069a3:	call 0x004073c8
0x004069a8:	movl %edi, %eax
0x004069aa:	movl %eax, 0x41987c
0x004069af:	testl 0x70(%edi), %eax
0x004069b2:	je 0x004069d1
0x004069d1:	pushl $0xd<UINT8>
0x004069d3:	call 0x00407eec
0x004069d8:	popl %ecx
0x004069d9:	andl -4(%ebp), $0x0<UINT8>
0x004069dd:	movl %esi, 0x68(%edi)
0x004069e0:	movl -28(%ebp), %esi
0x004069e3:	cmpl %esi, 0x419780
0x004069e9:	je 0x00406a21
0x00406a21:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00406a28:	call 0x00406a32
0x00406a32:	pushl $0xd<UINT8>
0x00406a34:	call 0x00407e14
0x00406a39:	popl %ecx
0x00406a3a:	ret

0x00406a2d:	jmp 0x004069bd
0x004069bd:	testl %esi, %esi
0x004069bf:	jne 0x004069c9
0x004069c9:	movl %eax, %esi
0x004069cb:	call 0x00408a61
0x004069d0:	ret

0x00406c7f:	movl %ebx, 0x68(%edi)
0x00406c82:	movl %esi, 0x8(%ebp)
0x00406c85:	call 0x00406a3b
0x00406a3b:	pushl %ebp
0x00406a3c:	movl %ebp, %esp
0x00406a3e:	subl %esp, $0x10<UINT8>
0x00406a41:	pushl %ebx
0x00406a42:	xorl %ebx, %ebx
0x00406a44:	pushl %ebx
0x00406a45:	leal %ecx, -16(%ebp)
0x00406a48:	call 0x00403e2a
0x00403e2a:	movl %eax, 0x4(%esp)
0x00403e2e:	testl %eax, %eax
0x00403e30:	pushl %esi
0x00403e31:	movl %esi, %ecx
0x00403e33:	movb 0xc(%esi), $0x0<UINT8>
0x00403e37:	jne 0x00403e9c
0x00403e39:	call 0x004073c8
0x00403e3e:	movl 0x8(%esi), %eax
0x00403e41:	movl %ecx, 0x6c(%eax)
0x00403e44:	movl (%esi), %ecx
0x00403e46:	movl %ecx, 0x68(%eax)
0x00403e49:	movl 0x4(%esi), %ecx
0x00403e4c:	movl %ecx, (%esi)
0x00403e4e:	cmpl %ecx, 0x419960
0x00403e54:	je 0x00403e68
0x00403e68:	movl %eax, 0x4(%esi)
0x00403e6b:	cmpl %eax, 0x419780
0x00403e71:	je 0x00403e89
0x00403e89:	movl %eax, 0x8(%esi)
0x00403e8c:	testb 0x70(%eax), $0x2<UINT8>
0x00403e90:	jne 20
0x00403e92:	orl 0x70(%eax), $0x2<UINT8>
0x00403e96:	movb 0xc(%esi), $0x1<UINT8>
0x00403e9a:	jmp 0x00403ea6
0x00403ea6:	movl %eax, %esi
0x00403ea8:	popl %esi
0x00403ea9:	ret $0x4<UINT16>

0x00406a4d:	cmpl %esi, $0xfffffffe<UINT8>
0x00406a50:	movl 0x41aaa0, %ebx
0x00406a56:	jne 0x00406a76
0x00406a76:	cmpl %esi, $0xfffffffd<UINT8>
0x00406a79:	jne 0x00406a8d
0x00406a7b:	movl 0x41aaa0, $0x1<UINT32>
0x00406a85:	call GetACP@KERNEL32.DLL
GetACP@KERNEL32.DLL: API Node	
0x00406a8b:	jmp 0x00406a68
0x00406a68:	cmpb -4(%ebp), %bl
0x00406a6b:	je 69
0x00406a6d:	movl %ecx, -8(%ebp)
0x00406a70:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00406a74:	jmp 0x00406ab2
0x00406ab2:	popl %ebx
0x00406ab3:	leave
0x00406ab4:	ret

0x00406c8a:	movl 0x8(%ebp), %eax
0x00406c8d:	cmpl %eax, 0x4(%ebx)
0x00406c90:	je 343
0x00406c96:	pushl $0x220<UINT32>
0x00406c9b:	call 0x00409f2a
0x00406ca0:	popl %ecx
0x00406ca1:	movl %ebx, %eax
0x00406ca3:	testl %ebx, %ebx
0x00406ca5:	je 326
0x00406cab:	movl %ecx, $0x88<UINT32>
0x00406cb0:	movl %esi, 0x68(%edi)
0x00406cb3:	movl %edi, %ebx
0x00406cb5:	rep movsl %es:(%edi), %ds:(%esi)
0x00406cb7:	andl (%ebx), $0x0<UINT8>
0x00406cba:	pushl %ebx
0x00406cbb:	pushl 0x8(%ebp)
0x00406cbe:	call 0x00406ab5
0x00406ab5:	pushl %ebp
0x00406ab6:	movl %ebp, %esp
0x00406ab8:	subl %esp, $0x20<UINT8>
0x00406abb:	movl %eax, 0x4190c0
0x00406ac0:	xorl %eax, %ebp
0x00406ac2:	movl -4(%ebp), %eax
0x00406ac5:	pushl %ebx
0x00406ac6:	movl %ebx, 0xc(%ebp)
0x00406ac9:	pushl %esi
0x00406aca:	movl %esi, 0x8(%ebp)
0x00406acd:	pushl %edi
0x00406ace:	call 0x00406a3b
0x00406a8d:	cmpl %esi, $0xfffffffc<UINT8>
0x00406a90:	jne 0x00406aa4
0x00406aa4:	cmpb -4(%ebp), %bl
0x00406aa7:	je 7
0x00406aa9:	movl %eax, -8(%ebp)
0x00406aac:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x00406ab0:	movl %eax, %esi
0x00406ad3:	movl %edi, %eax
0x00406ad5:	xorl %esi, %esi
0x00406ad7:	cmpl %edi, %esi
0x00406ad9:	movl 0x8(%ebp), %edi
0x00406adc:	jne 0x00406aec
0x00406aec:	movl -28(%ebp), %esi
0x00406aef:	xorl %eax, %eax
0x00406af1:	cmpl 0x419788(%eax), %edi
0x00406af7:	je 103
0x00406af9:	incl -28(%ebp)
0x00406afc:	addl %eax, $0x30<UINT8>
0x00406aff:	cmpl %eax, $0xf0<UINT32>
0x00406b04:	jb 0x00406af1
0x00406b06:	leal %eax, -24(%ebp)
0x00406b09:	pushl %eax
0x00406b0a:	pushl %edi
0x00406b0b:	call GetCPInfo@KERNEL32.DLL
GetCPInfo@KERNEL32.DLL: API Node	
0x00406b11:	testl %eax, %eax
0x00406b13:	je 297
0x00406b19:	pushl $0x101<UINT32>
0x00406b1e:	leal %eax, 0x1c(%ebx)
0x00406b21:	pushl %esi
0x00406b22:	pushl %eax
0x00406b23:	call 0x004040e0
0x004040e0:	movl %edx, 0xc(%esp)
0x004040e4:	movl %ecx, 0x4(%esp)
0x004040e8:	testl %edx, %edx
0x004040ea:	je 105
0x004040ec:	xorl %eax, %eax
0x004040ee:	movb %al, 0x8(%esp)
0x004040f2:	testb %al, %al
0x004040f4:	jne 22
0x004040f6:	cmpl %edx, $0x100<UINT32>
0x004040fc:	jb 0x0040410c
0x004040fe:	cmpl 0x41b820, $0x0<UINT8>
0x00404105:	je 0x0040410c
0x0040410c:	pushl %edi
0x0040410d:	movl %edi, %ecx
0x0040410f:	cmpl %edx, $0x4<UINT8>
0x00404112:	jb 49
0x00404114:	negl %ecx
0x00404116:	andl %ecx, $0x3<UINT8>
0x00404119:	je 0x00404127
0x00404127:	movl %ecx, %eax
0x00404129:	shll %eax, $0x8<UINT8>
0x0040412c:	addl %eax, %ecx
0x0040412e:	movl %ecx, %eax
0x00404130:	shll %eax, $0x10<UINT8>
0x00404133:	addl %eax, %ecx
0x00404135:	movl %ecx, %edx
0x00404137:	andl %edx, $0x3<UINT8>
0x0040413a:	shrl %ecx, $0x2<UINT8>
0x0040413d:	je 6
0x0040413f:	rep stosl %es:(%edi), %eax
0x00404141:	testl %edx, %edx
0x00404143:	je 0x0040414f
0x00404145:	movb (%edi), %al
0x00404147:	addl %edi, $0x1<UINT8>
0x0040414a:	subl %edx, $0x1<UINT8>
0x0040414d:	jne -10
0x0040414f:	movl %eax, 0x8(%esp)
0x00404153:	popl %edi
0x00404154:	ret

0x00406b28:	xorl %edx, %edx
0x00406b2a:	incl %edx
0x00406b2b:	addl %esp, $0xc<UINT8>
0x00406b2e:	cmpl -24(%ebp), %edx
0x00406b31:	movl 0x4(%ebx), %edi
0x00406b34:	movl 0xc(%ebx), %esi
0x00406b37:	jbe 248
0x00406b3d:	cmpb -18(%ebp), $0x0<UINT8>
0x00406b41:	je 0x00406c16
0x00406c16:	leal %eax, 0x1e(%ebx)
0x00406c19:	movl %ecx, $0xfe<UINT32>
0x00406c1e:	orb (%eax), $0x8<UINT8>
0x00406c21:	incl %eax
0x00406c22:	decl %ecx
0x00406c23:	jne 0x00406c1e
0x00406c25:	movl %eax, 0x4(%ebx)
0x00406c28:	call 0x00406789
0x00406789:	subl %eax, $0x3a4<UINT32>
0x0040678e:	je 34
0x00406790:	subl %eax, $0x4<UINT8>
0x00406793:	je 23
0x00406795:	subl %eax, $0xd<UINT8>
0x00406798:	je 12
0x0040679a:	decl %eax
0x0040679b:	je 3
0x0040679d:	xorl %eax, %eax
0x0040679f:	ret

0x00406c2d:	movl 0xc(%ebx), %eax
0x00406c30:	movl 0x8(%ebx), %edx
0x00406c33:	jmp 0x00406c38
0x00406c38:	xorl %eax, %eax
0x00406c3a:	leal %edi, 0x10(%ebx)
0x00406c3d:	stosl %es:(%edi), %eax
0x00406c3e:	stosl %es:(%edi), %eax
0x00406c3f:	stosl %es:(%edi), %eax
0x00406c40:	jmp 0x00406bf4
0x00406bf4:	movl %esi, %ebx
0x00406bf6:	call 0x0040680d
0x0040680d:	pushl %ebp
0x0040680e:	leal %ebp, -1180(%esp)
0x00406815:	subl %esp, $0x51c<UINT32>
0x0040681b:	movl %eax, 0x4190c0
0x00406820:	xorl %eax, %ebp
0x00406822:	movl 0x498(%ebp), %eax
0x00406828:	pushl %ebx
0x00406829:	pushl %edi
0x0040682a:	leal %eax, -124(%ebp)
0x0040682d:	pushl %eax
0x0040682e:	pushl 0x4(%esi)
0x00406831:	call GetCPInfo@KERNEL32.DLL
0x00406837:	testl %eax, %eax
0x00406839:	movl %edi, $0x100<UINT32>
0x0040683e:	je 239
0x00406844:	xorl %eax, %eax
0x00406846:	movb 0x398(%ebp,%eax), %al
0x0040684d:	incl %eax
0x0040684e:	cmpl %eax, %edi
0x00406850:	jb 0x00406846
0x00406852:	movb %al, -118(%ebp)
0x00406855:	testb %al, %al
0x00406857:	movb 0x398(%ebp), $0x20<UINT8>
0x0040685e:	je 0x0040688b
0x0040688b:	pushl $0x0<UINT8>
0x0040688d:	pushl 0xc(%esi)
0x00406890:	leal %eax, -104(%ebp)
0x00406893:	pushl 0x4(%esi)
0x00406896:	pushl %eax
0x00406897:	pushl %edi
0x00406898:	leal %eax, 0x398(%ebp)
0x0040689e:	pushl %eax
0x0040689f:	pushl $0x1<UINT8>
0x004068a1:	pushl $0x0<UINT8>
0x004068a3:	call 0x0040dab5
0x0040dab5:	pushl %ebp
0x0040dab6:	movl %ebp, %esp
0x0040dab8:	subl %esp, $0x10<UINT8>
0x0040dabb:	pushl 0x8(%ebp)
0x0040dabe:	leal %ecx, -16(%ebp)
0x0040dac1:	call 0x00403e2a
0x0040dac6:	pushl 0x24(%ebp)
0x0040dac9:	leal %ecx, -16(%ebp)
0x0040dacc:	pushl 0x20(%ebp)
0x0040dacf:	pushl 0x1c(%ebp)
0x0040dad2:	pushl 0x18(%ebp)
0x0040dad5:	pushl 0x14(%ebp)
0x0040dad8:	pushl 0x10(%ebp)
0x0040dadb:	pushl 0xc(%ebp)
0x0040dade:	call 0x0040d8fd
0x0040d8fd:	pushl %ebp
0x0040d8fe:	movl %ebp, %esp
0x0040d900:	pushl %ecx
0x0040d901:	pushl %ecx
0x0040d902:	movl %eax, 0x4190c0
0x0040d907:	xorl %eax, %ebp
0x0040d909:	movl -4(%ebp), %eax
0x0040d90c:	movl %eax, 0x41b3dc
0x0040d911:	pushl %ebx
0x0040d912:	pushl %esi
0x0040d913:	xorl %ebx, %ebx
0x0040d915:	cmpl %eax, %ebx
0x0040d917:	pushl %edi
0x0040d918:	movl %edi, %ecx
0x0040d91a:	jne 58
0x0040d91c:	leal %eax, -8(%ebp)
0x0040d91f:	pushl %eax
0x0040d920:	xorl %esi, %esi
0x0040d922:	incl %esi
0x0040d923:	pushl %esi
0x0040d924:	pushl $0x4163ac<UINT32>
0x0040d929:	pushl %esi
0x0040d92a:	call GetStringTypeW@KERNEL32.DLL
GetStringTypeW@KERNEL32.DLL: API Node	
0x0040d930:	testl %eax, %eax
0x0040d932:	je 8
0x0040d934:	movl 0x41b3dc, %esi
0x0040d93a:	jmp 0x0040d970
0x0040d970:	cmpl 0x18(%ebp), %ebx
0x0040d973:	movl -8(%ebp), %ebx
0x0040d976:	jne 0x0040d980
0x0040d980:	movl %esi, 0x412184
0x0040d986:	xorl %eax, %eax
0x0040d988:	cmpl 0x20(%ebp), %ebx
0x0040d98b:	pushl %ebx
0x0040d98c:	pushl %ebx
0x0040d98d:	pushl 0x10(%ebp)
0x0040d990:	setne %al
0x0040d993:	pushl 0xc(%ebp)
0x0040d996:	leal %eax, 0x1(,%eax,8)
0x0040d99d:	pushl %eax
0x0040d99e:	pushl 0x18(%ebp)
0x0040d9a1:	call MultiByteToWideChar@KERNEL32.DLL
MultiByteToWideChar@KERNEL32.DLL: API Node	
0x0040d9a3:	movl %edi, %eax
0x0040d9a5:	cmpl %edi, %ebx
0x0040d9a7:	je 171
0x0040d9ad:	jle 60
0x0040d9af:	cmpl %edi, $0x7ffffff0<UINT32>
0x0040d9b5:	ja 52
0x0040d9b7:	leal %eax, 0x8(%edi,%edi)
0x0040d9bb:	cmpl %eax, $0x400<UINT32>
0x0040d9c0:	ja 19
0x0040d9c2:	call 0x0040b100
0x0040b100:	pushl %ecx
0x0040b101:	leal %ecx, 0x8(%esp)
0x0040b105:	subl %ecx, %eax
0x0040b107:	andl %ecx, $0xf<UINT8>
0x0040b10a:	addl %eax, %ecx
0x0040b10c:	sbbl %ecx, %ecx
0x0040b10e:	orl %eax, %ecx
0x0040b110:	popl %ecx
0x0040b111:	jmp 0x0040ff50
0x0040ff50:	pushl %ecx
0x0040ff51:	leal %ecx, 0x4(%esp)
0x0040ff55:	subl %ecx, %eax
0x0040ff57:	sbbl %eax, %eax
0x0040ff59:	notl %eax
0x0040ff5b:	andl %ecx, %eax
0x0040ff5d:	movl %eax, %esp
0x0040ff5f:	andl %eax, $0xfffff000<UINT32>
0x0040ff64:	cmpl %ecx, %eax
0x0040ff66:	jb 10
0x0040ff68:	movl %eax, %ecx
0x0040ff6a:	popl %ecx
0x0040ff6b:	xchgl %esp, %eax
0x0040ff6c:	movl %eax, (%eax)
0x0040ff6e:	movl (%esp), %eax
0x0040ff71:	ret

0x0040d9c7:	movl %eax, %esp
0x0040d9c9:	cmpl %eax, %ebx
0x0040d9cb:	je 28
0x0040d9cd:	movl (%eax), $0xcccc<UINT32>
0x0040d9d3:	jmp 0x0040d9e6
0x0040d9e6:	addl %eax, $0x8<UINT8>
0x0040d9e9:	movl %ebx, %eax
0x0040d9eb:	testl %ebx, %ebx
0x0040d9ed:	je 105
0x0040d9ef:	leal %eax, (%edi,%edi)
0x0040d9f2:	pushl %eax
0x0040d9f3:	pushl $0x0<UINT8>
0x0040d9f5:	pushl %ebx
0x0040d9f6:	call 0x004040e0
0x0040d9fb:	addl %esp, $0xc<UINT8>
0x0040d9fe:	pushl %edi
0x0040d9ff:	pushl %ebx
0x0040da00:	pushl 0x10(%ebp)
0x0040da03:	pushl 0xc(%ebp)
0x0040da06:	pushl $0x1<UINT8>
0x0040da08:	pushl 0x18(%ebp)
0x0040da0b:	call MultiByteToWideChar@KERNEL32.DLL
0x0040da0d:	testl %eax, %eax
0x0040da0f:	je 17
0x0040da11:	pushl 0x14(%ebp)
0x0040da14:	pushl %eax
0x0040da15:	pushl %ebx
0x0040da16:	pushl 0x8(%ebp)
0x0040da19:	call GetStringTypeW@KERNEL32.DLL
0x0040da1f:	movl -8(%ebp), %eax
0x0040da22:	pushl %ebx
0x0040da23:	call 0x0040519b
0x0040519b:	movl %eax, 0x4(%esp)
0x0040519f:	testl %eax, %eax
0x004051a1:	je 18
0x004051a3:	subl %eax, $0x8<UINT8>
0x004051a6:	cmpl (%eax), $0xdddd<UINT32>
0x004051ac:	jne 0x004051b5
0x004051b5:	ret

0x0040da28:	movl %eax, -8(%ebp)
0x0040da2b:	popl %ecx
0x0040da2c:	jmp 0x0040daa3
0x0040daa3:	leal %esp, -20(%ebp)
0x0040daa6:	popl %edi
0x0040daa7:	popl %esi
0x0040daa8:	popl %ebx
0x0040daa9:	movl %ecx, -4(%ebp)
0x0040daac:	xorl %ecx, %ebp
0x0040daae:	call 0x004046de
0x004046de:	cmpl %ecx, 0x4190c0
0x004046e4:	jne 2
0x004046e6:	rep ret

0x0040dab3:	leave
0x0040dab4:	ret

0x0040dae3:	addl %esp, $0x1c<UINT8>
0x0040dae6:	cmpb -4(%ebp), $0x0<UINT8>
0x0040daea:	je 7
0x0040daec:	movl %ecx, -8(%ebp)
0x0040daef:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0040daf3:	leave
0x0040daf4:	ret

0x004068a8:	xorl %ebx, %ebx
0x004068aa:	pushl %ebx
0x004068ab:	pushl 0x4(%esi)
0x004068ae:	leal %eax, 0x298(%ebp)
0x004068b4:	pushl %edi
0x004068b5:	pushl %eax
0x004068b6:	pushl %edi
0x004068b7:	leal %eax, 0x398(%ebp)
0x004068bd:	pushl %eax
0x004068be:	pushl %edi
0x004068bf:	pushl 0xc(%esi)
0x004068c2:	pushl %ebx
0x004068c3:	call 0x00407a90
0x00407a90:	pushl %ebp
0x00407a91:	movl %ebp, %esp
0x00407a93:	subl %esp, $0x10<UINT8>
0x00407a96:	pushl 0x8(%ebp)
0x00407a99:	leal %ecx, -16(%ebp)
0x00407a9c:	call 0x00403e2a
0x00407aa1:	pushl 0x28(%ebp)
0x00407aa4:	leal %ecx, -16(%ebp)
0x00407aa7:	pushl 0x24(%ebp)
0x00407aaa:	pushl 0x20(%ebp)
0x00407aad:	pushl 0x1c(%ebp)
0x00407ab0:	pushl 0x18(%ebp)
0x00407ab3:	pushl 0x14(%ebp)
0x00407ab6:	pushl 0x10(%ebp)
0x00407ab9:	pushl 0xc(%ebp)
0x00407abc:	call 0x004076ee
0x004076ee:	pushl %ebp
0x004076ef:	movl %ebp, %esp
0x004076f1:	subl %esp, $0x14<UINT8>
0x004076f4:	movl %eax, 0x4190c0
0x004076f9:	xorl %eax, %ebp
0x004076fb:	movl -4(%ebp), %eax
0x004076fe:	pushl %ebx
0x004076ff:	pushl %esi
0x00407700:	xorl %ebx, %ebx
0x00407702:	cmpl 0x41aaf0, %ebx
0x00407708:	pushl %edi
0x00407709:	movl %esi, %ecx
0x0040770b:	jne 0x00407745
0x0040770d:	pushl %ebx
0x0040770e:	pushl %ebx
0x0040770f:	xorl %edi, %edi
0x00407711:	incl %edi
0x00407712:	pushl %edi
0x00407713:	pushl $0x4163ac<UINT32>
0x00407718:	pushl $0x100<UINT32>
0x0040771d:	pushl %ebx
0x0040771e:	call LCMapStringW@KERNEL32.DLL
LCMapStringW@KERNEL32.DLL: API Node	
0x00407724:	testl %eax, %eax
0x00407726:	je 8
0x00407728:	movl 0x41aaf0, %edi
0x0040772e:	jmp 0x00407745
0x00407745:	cmpl 0x14(%ebp), %ebx
0x00407748:	jle 34
0x0040774a:	movl %ecx, 0x14(%ebp)
0x0040774d:	movl %eax, 0x10(%ebp)
0x00407750:	decl %ecx
0x00407751:	cmpb (%eax), %bl
0x00407753:	je 8
0x00407755:	incl %eax
0x00407756:	cmpl %ecx, %ebx
0x00407758:	jne 0x00407750
0x0040775a:	orl %ecx, $0xffffffff<UINT8>
0x0040775d:	movl %eax, 0x14(%ebp)
0x00407760:	subl %eax, %ecx
0x00407762:	decl %eax
0x00407763:	cmpl %eax, 0x14(%ebp)
0x00407766:	jnl 0x00407769
0x00407769:	movl 0x14(%ebp), %eax
0x0040776c:	movl %eax, 0x41aaf0
0x00407771:	cmpl %eax, $0x2<UINT8>
0x00407774:	je 427
0x0040777a:	cmpl %eax, %ebx
0x0040777c:	je 419
0x00407782:	cmpl %eax, $0x1<UINT8>
0x00407785:	jne 459
0x0040778b:	cmpl 0x20(%ebp), %ebx
0x0040778e:	movl -8(%ebp), %ebx
0x00407791:	jne 0x0040779b
0x0040779b:	movl %esi, 0x412184
0x004077a1:	xorl %eax, %eax
0x004077a3:	cmpl 0x24(%ebp), %ebx
0x004077a6:	pushl %ebx
0x004077a7:	pushl %ebx
0x004077a8:	pushl 0x14(%ebp)
0x004077ab:	setne %al
0x004077ae:	pushl 0x10(%ebp)
0x004077b1:	leal %eax, 0x1(,%eax,8)
0x004077b8:	pushl %eax
0x004077b9:	pushl 0x20(%ebp)
0x004077bc:	call MultiByteToWideChar@KERNEL32.DLL
0x004077be:	movl %edi, %eax
0x004077c0:	cmpl %edi, %ebx
0x004077c2:	je 398
0x004077c8:	jle 67
0x004077ca:	pushl $0xffffffe0<UINT8>
0x004077cc:	xorl %edx, %edx
0x004077ce:	popl %eax
0x004077cf:	divl %eax, %edi
0x004077d1:	cmpl %eax, $0x2<UINT8>
0x004077d4:	jb 55
0x004077d6:	leal %eax, 0x8(%edi,%edi)
0x004077da:	cmpl %eax, $0x400<UINT32>
0x004077df:	ja 19
0x004077e1:	call 0x0040b100
0x004077e6:	movl %eax, %esp
0x004077e8:	cmpl %eax, %ebx
0x004077ea:	je 28
0x004077ec:	movl (%eax), $0xcccc<UINT32>
0x004077f2:	jmp 0x00407805
0x00407805:	addl %eax, $0x8<UINT8>
0x00407808:	movl -12(%ebp), %eax
0x0040780b:	jmp 0x00407810
0x00407810:	cmpl -12(%ebp), %ebx
0x00407813:	je 317
0x00407819:	pushl %edi
0x0040781a:	pushl -12(%ebp)
0x0040781d:	pushl 0x14(%ebp)
0x00407820:	pushl 0x10(%ebp)
0x00407823:	pushl $0x1<UINT8>
0x00407825:	pushl 0x20(%ebp)
0x00407828:	call MultiByteToWideChar@KERNEL32.DLL
0x0040782a:	testl %eax, %eax
0x0040782c:	je 226
0x00407832:	movl %esi, 0x412188
0x00407838:	pushl %ebx
0x00407839:	pushl %ebx
0x0040783a:	pushl %edi
0x0040783b:	pushl -12(%ebp)
0x0040783e:	pushl 0xc(%ebp)
0x00407841:	pushl 0x8(%ebp)
0x00407844:	call LCMapStringW@KERNEL32.DLL
0x00407846:	movl %ecx, %eax
0x00407848:	cmpl %ecx, %ebx
0x0040784a:	movl -8(%ebp), %ecx
0x0040784d:	je 193
0x00407853:	testw 0xc(%ebp), $0x400<UINT16>
0x00407859:	je 0x00407884
0x00407884:	cmpl %ecx, %ebx
0x00407886:	jle 69
0x00407888:	pushl $0xffffffe0<UINT8>
0x0040788a:	xorl %edx, %edx
0x0040788c:	popl %eax
0x0040788d:	divl %eax, %ecx
0x0040788f:	cmpl %eax, $0x2<UINT8>
0x00407892:	jb 57
0x00407894:	leal %eax, 0x8(%ecx,%ecx)
0x00407898:	cmpl %eax, $0x400<UINT32>
0x0040789d:	ja 22
0x0040789f:	call 0x0040b100
0x004078a4:	movl %esi, %esp
0x004078a6:	cmpl %esi, %ebx
0x004078a8:	je 106
0x004078aa:	movl (%esi), $0xcccc<UINT32>
0x004078b0:	addl %esi, $0x8<UINT8>
0x004078b3:	jmp 0x004078cf
0x004078cf:	cmpl %esi, %ebx
0x004078d1:	je 65
0x004078d3:	pushl -8(%ebp)
0x004078d6:	pushl %esi
0x004078d7:	pushl %edi
0x004078d8:	pushl -12(%ebp)
0x004078db:	pushl 0xc(%ebp)
0x004078de:	pushl 0x8(%ebp)
0x004078e1:	call LCMapStringW@KERNEL32.DLL
0x004078e7:	testl %eax, %eax
0x004078e9:	je 34
0x004078eb:	cmpl 0x1c(%ebp), %ebx
0x004078ee:	pushl %ebx
0x004078ef:	pushl %ebx
0x004078f0:	jne 0x004078f6
0x004078f6:	pushl 0x1c(%ebp)
0x004078f9:	pushl 0x18(%ebp)
0x004078fc:	pushl -8(%ebp)
0x004078ff:	pushl %esi
0x00407900:	pushl %ebx
0x00407901:	pushl 0x20(%ebp)
0x00407904:	call WideCharToMultiByte@KERNEL32.DLL
0x0040790a:	movl -8(%ebp), %eax
0x0040790d:	pushl %esi
0x0040790e:	call 0x0040519b
0x00407913:	popl %ecx
0x00407914:	pushl -12(%ebp)
0x00407917:	call 0x0040519b
0x0040791c:	movl %eax, -8(%ebp)
0x0040791f:	popl %ecx
0x00407920:	jmp 0x00407a7e
0x00407a7e:	leal %esp, -32(%ebp)
0x00407a81:	popl %edi
0x00407a82:	popl %esi
0x00407a83:	popl %ebx
0x00407a84:	movl %ecx, -4(%ebp)
0x00407a87:	xorl %ecx, %ebp
0x00407a89:	call 0x004046de
0x00407a8e:	leave
0x00407a8f:	ret

0x00407ac1:	addl %esp, $0x20<UINT8>
0x00407ac4:	cmpb -4(%ebp), $0x0<UINT8>
0x00407ac8:	je 7
0x00407aca:	movl %ecx, -8(%ebp)
0x00407acd:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00407ad1:	leave
0x00407ad2:	ret

0x004068c8:	addl %esp, $0x44<UINT8>
0x004068cb:	pushl %ebx
0x004068cc:	pushl 0x4(%esi)
0x004068cf:	leal %eax, 0x198(%ebp)
0x004068d5:	pushl %edi
0x004068d6:	pushl %eax
0x004068d7:	pushl %edi
0x004068d8:	leal %eax, 0x398(%ebp)
0x004068de:	pushl %eax
0x004068df:	pushl $0x200<UINT32>
0x004068e4:	pushl 0xc(%esi)
0x004068e7:	pushl %ebx
0x004068e8:	call 0x00407a90
0x004068ed:	addl %esp, $0x24<UINT8>
0x004068f0:	xorl %eax, %eax
0x004068f2:	movzwl %ecx, -104(%ebp,%eax,2)
0x004068f7:	testb %cl, $0x1<UINT8>
0x004068fa:	je 0x0040690a
0x0040690a:	testb %cl, $0x2<UINT8>
0x0040690d:	je 0x00406924
0x00406924:	movb 0x11d(%esi,%eax), $0x0<UINT8>
0x0040692c:	incl %eax
0x0040692d:	cmpl %eax, %edi
0x0040692f:	jb 0x004068f2
0x004068fc:	orb 0x1d(%esi,%eax), $0x10<UINT8>
0x00406901:	movb %cl, 0x298(%ebp,%eax)
0x00406908:	jmp 0x0040691b
0x0040691b:	movb 0x11d(%esi,%eax), %cl
0x00406922:	jmp 0x0040692c
0x0040690f:	orb 0x1d(%esi,%eax), $0x20<UINT8>
0x00406914:	movb %cl, 0x198(%ebp,%eax)
0x00406931:	jmp 0x00406980
0x00406980:	movl %ecx, 0x498(%ebp)
0x00406986:	popl %edi
0x00406987:	xorl %ecx, %ebp
0x00406989:	popl %ebx
0x0040698a:	call 0x004046de
0x0040698f:	addl %ebp, $0x49c<UINT32>
0x00406995:	leave
0x00406996:	ret

0x00406bfb:	jmp 0x00406ae5
0x00406ae5:	xorl %eax, %eax
0x00406ae7:	jmp 0x00406c51
0x00406c51:	movl %ecx, -4(%ebp)
0x00406c54:	popl %edi
0x00406c55:	popl %esi
0x00406c56:	xorl %ecx, %ebp
0x00406c58:	popl %ebx
0x00406c59:	call 0x004046de
0x00406c5e:	leave
0x00406c5f:	ret

0x00406cc3:	popl %ecx
0x00406cc4:	popl %ecx
0x00406cc5:	movl -32(%ebp), %eax
0x00406cc8:	testl %eax, %eax
0x00406cca:	jne 252
0x00406cd0:	movl %esi, -36(%ebp)
0x00406cd3:	pushl 0x68(%esi)
0x00406cd6:	call InterlockedDecrement@KERNEL32.DLL
InterlockedDecrement@KERNEL32.DLL: API Node	
0x00406cdc:	testl %eax, %eax
0x00406cde:	jne 17
0x00406ce0:	movl %eax, 0x68(%esi)
0x00406ce3:	cmpl %eax, $0x419358<UINT32>
0x00406ce8:	je 0x00406cf1
0x00406cf1:	movl 0x68(%esi), %ebx
0x00406cf4:	pushl %ebx
0x00406cf5:	movl %edi, 0x412160
0x00406cfb:	call InterlockedIncrement@KERNEL32.DLL
0x00406cfd:	testb 0x70(%esi), $0x2<UINT8>
0x00406d01:	jne 234
0x00406d07:	testb 0x41987c, $0x1<UINT8>
0x00406d0e:	jne 221
0x00406d14:	pushl $0xd<UINT8>
0x00406d16:	call 0x00407eec
0x00406d1b:	popl %ecx
0x00406d1c:	andl -4(%ebp), $0x0<UINT8>
0x00406d20:	movl %eax, 0x4(%ebx)
0x00406d23:	movl 0x41aab0, %eax
0x00406d28:	movl %eax, 0x8(%ebx)
0x00406d2b:	movl 0x41aab4, %eax
0x00406d30:	movl %eax, 0xc(%ebx)
0x00406d33:	movl 0x41aab8, %eax
0x00406d38:	xorl %eax, %eax
0x00406d3a:	movl -28(%ebp), %eax
0x00406d3d:	cmpl %eax, $0x5<UINT8>
0x00406d40:	jnl 0x00406d52
0x00406d42:	movw %cx, 0x10(%ebx,%eax,2)
0x00406d47:	movw 0x41aaa4(,%eax,2), %cx
0x00406d4f:	incl %eax
0x00406d50:	jmp 0x00406d3a
0x00406d52:	xorl %eax, %eax
0x00406d54:	movl -28(%ebp), %eax
0x00406d57:	cmpl %eax, $0x101<UINT32>
0x00406d5c:	jnl 0x00406d6b
0x00406d5e:	movb %cl, 0x1c(%eax,%ebx)
0x00406d62:	movb 0x419578(%eax), %cl
0x00406d68:	incl %eax
0x00406d69:	jmp 0x00406d54
0x00406d6b:	xorl %eax, %eax
0x00406d6d:	movl -28(%ebp), %eax
0x00406d70:	cmpl %eax, $0x100<UINT32>
0x00406d75:	jnl 0x00406d87
0x00406d77:	movb %cl, 0x11d(%eax,%ebx)
0x00406d7e:	movb 0x419680(%eax), %cl
0x00406d84:	incl %eax
0x00406d85:	jmp 0x00406d6d
0x00406d87:	pushl 0x419780
0x00406d8d:	call InterlockedDecrement@KERNEL32.DLL
0x00406d93:	testl %eax, %eax
0x00406d95:	jne 0x00406daa
0x00406daa:	movl 0x419780, %ebx
0x00406db0:	pushl %ebx
0x00406db1:	call InterlockedIncrement@KERNEL32.DLL
0x00406db3:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00406dba:	call 0x00406dc1
0x00406dc1:	pushl $0xd<UINT8>
0x00406dc3:	call 0x00407e14
0x00406dc8:	popl %ecx
0x00406dc9:	ret

0x00406dbf:	jmp 0x00406df1
0x00406df1:	movl %eax, -32(%ebp)
0x00406df4:	call 0x00408a61
0x00406df9:	ret

0x00406e0a:	popl %ecx
0x00406e0b:	movl 0x41b834, $0x1<UINT32>
0x00406e15:	xorl %eax, %eax
0x00406e17:	ret

0x0040d693:	pushl $0x104<UINT32>
0x0040d698:	movl %esi, $0x41b2d0<UINT32>
0x0040d69d:	pushl %esi
0x0040d69e:	pushl %ebx
0x0040d69f:	movb 0x41b3d4, %bl
0x0040d6a5:	call GetModuleFileNameA@KERNEL32.DLL
GetModuleFileNameA@KERNEL32.DLL: API Node	
0x0040d6ab:	movl %eax, 0x41b824
0x0040d6b0:	cmpl %eax, %ebx
0x0040d6b2:	movl 0x41aa80, %esi
0x0040d6b8:	je 7
0x0040d6ba:	cmpb (%eax), %bl
0x0040d6bc:	movl -4(%ebp), %eax
0x0040d6bf:	jne 0x0040d6c4
0x0040d6c4:	movl %edx, -4(%ebp)
0x0040d6c7:	leal %eax, -8(%ebp)
0x0040d6ca:	pushl %eax
0x0040d6cb:	pushl %ebx
0x0040d6cc:	pushl %ebx
0x0040d6cd:	leal %edi, -12(%ebp)
0x0040d6d0:	call 0x0040d4e3
0x0040d4e3:	pushl %ebp
0x0040d4e4:	movl %ebp, %esp
0x0040d4e6:	pushl %ecx
0x0040d4e7:	movl %ecx, 0x10(%ebp)
0x0040d4ea:	pushl %ebx
0x0040d4eb:	xorl %eax, %eax
0x0040d4ed:	cmpl 0x8(%ebp), %eax
0x0040d4f0:	pushl %esi
0x0040d4f1:	movl (%edi), %eax
0x0040d4f3:	movl %esi, %edx
0x0040d4f5:	movl %edx, 0xc(%ebp)
0x0040d4f8:	movl (%ecx), $0x1<UINT32>
0x0040d4fe:	je 0x0040d509
0x0040d509:	movl -4(%ebp), %eax
0x0040d50c:	cmpb (%esi), $0x22<UINT8>
0x0040d50f:	jne 0x0040d521
0x0040d511:	xorl %eax, %eax
0x0040d513:	cmpl -4(%ebp), %eax
0x0040d516:	movb %bl, $0x22<UINT8>
0x0040d518:	sete %al
0x0040d51b:	incl %esi
0x0040d51c:	movl -4(%ebp), %eax
0x0040d51f:	jmp 0x0040d55d
0x0040d55d:	cmpl -4(%ebp), $0x0<UINT8>
0x0040d561:	jne 0x0040d50c
0x0040d521:	incl (%edi)
0x0040d523:	testl %edx, %edx
0x0040d525:	je 0x0040d52f
0x0040d52f:	movb %bl, (%esi)
0x0040d531:	movzbl %eax, %bl
0x0040d534:	pushl %eax
0x0040d535:	incl %esi
0x0040d536:	call 0x00410c93
0x00410c93:	pushl $0x4<UINT8>
0x00410c95:	pushl $0x0<UINT8>
0x00410c97:	pushl 0xc(%esp)
0x00410c9b:	pushl $0x0<UINT8>
0x00410c9d:	call 0x00410c42
0x00410c42:	pushl %ebp
0x00410c43:	movl %ebp, %esp
0x00410c45:	subl %esp, $0x10<UINT8>
0x00410c48:	pushl 0x8(%ebp)
0x00410c4b:	leal %ecx, -16(%ebp)
0x00410c4e:	call 0x00403e2a
0x00410c53:	movzbl %eax, 0xc(%ebp)
0x00410c57:	movl %ecx, -12(%ebp)
0x00410c5a:	movb %dl, 0x14(%ebp)
0x00410c5d:	testb 0x1d(%ecx,%eax), %dl
0x00410c61:	jne 30
0x00410c63:	cmpl 0x10(%ebp), $0x0<UINT8>
0x00410c67:	je 0x00410c7b
0x00410c7b:	xorl %eax, %eax
0x00410c7d:	testl %eax, %eax
0x00410c7f:	je 0x00410c84
0x00410c84:	cmpb -4(%ebp), $0x0<UINT8>
0x00410c88:	je 7
0x00410c8a:	movl %ecx, -8(%ebp)
0x00410c8d:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00410c91:	leave
0x00410c92:	ret

0x00410ca2:	addl %esp, $0x10<UINT8>
0x00410ca5:	ret

0x0040d53b:	testl %eax, %eax
0x0040d53d:	popl %ecx
0x0040d53e:	je 0x0040d553
0x0040d553:	testb %bl, %bl
0x0040d555:	movl %edx, 0xc(%ebp)
0x0040d558:	movl %ecx, 0x10(%ebp)
0x0040d55b:	je 0x0040d58f
0x0040d563:	cmpb %bl, $0x20<UINT8>
0x0040d566:	je 5
0x0040d568:	cmpb %bl, $0x9<UINT8>
0x0040d56b:	jne 0x0040d50c
0x0040d58f:	decl %esi
0x0040d590:	jmp 0x0040d575
0x0040d575:	andl -4(%ebp), $0x0<UINT8>
0x0040d579:	cmpb (%esi), $0x0<UINT8>
0x0040d57c:	je 0x0040d66b
0x0040d66b:	movl %eax, 0x8(%ebp)
0x0040d66e:	testl %eax, %eax
0x0040d670:	popl %esi
0x0040d671:	popl %ebx
0x0040d672:	je 0x0040d677
0x0040d677:	incl (%ecx)
0x0040d679:	leave
0x0040d67a:	ret

0x0040d6d5:	movl %eax, -8(%ebp)
0x0040d6d8:	addl %esp, $0xc<UINT8>
0x0040d6db:	cmpl %eax, $0x3fffffff<UINT32>
0x0040d6e0:	jae 74
0x0040d6e2:	movl %ecx, -12(%ebp)
0x0040d6e5:	cmpl %ecx, $0xffffffff<UINT8>
0x0040d6e8:	jae 66
0x0040d6ea:	movl %edi, %eax
0x0040d6ec:	shll %edi, $0x2<UINT8>
0x0040d6ef:	leal %eax, (%edi,%ecx)
0x0040d6f2:	cmpl %eax, %ecx
0x0040d6f4:	jb 54
0x0040d6f6:	pushl %eax
0x0040d6f7:	call 0x00409f2a
0x0040d6fc:	movl %esi, %eax
0x0040d6fe:	cmpl %esi, %ebx
0x0040d700:	popl %ecx
0x0040d701:	je 41
0x0040d703:	movl %edx, -4(%ebp)
0x0040d706:	leal %eax, -8(%ebp)
0x0040d709:	pushl %eax
0x0040d70a:	addl %edi, %esi
0x0040d70c:	pushl %edi
0x0040d70d:	pushl %esi
0x0040d70e:	leal %edi, -12(%ebp)
0x0040d711:	call 0x0040d4e3
0x0040d500:	movl %ebx, 0x8(%ebp)
0x0040d503:	addl 0x8(%ebp), $0x4<UINT8>
0x0040d507:	movl (%ebx), %edx
0x0040d527:	movb %al, (%esi)
0x0040d529:	movb (%edx), %al
0x0040d52b:	incl %edx
0x0040d52c:	movl 0xc(%ebp), %edx
0x0040d674:	andl (%eax), $0x0<UINT8>
0x0040d716:	movl %eax, -8(%ebp)
0x0040d719:	addl %esp, $0xc<UINT8>
0x0040d71c:	decl %eax
0x0040d71d:	movl 0x41aa64, %eax
0x0040d722:	movl 0x41aa68, %esi
0x0040d728:	xorl %eax, %eax
0x0040d72a:	jmp 0x0040d72f
0x0040d72f:	popl %edi
0x0040d730:	popl %esi
0x0040d731:	popl %ebx
0x0040d732:	leave
0x0040d733:	ret

0x004066dc:	testl %eax, %eax
0x004066de:	jnl 0x004066e8
0x004066e8:	call 0x0040d408
0x0040d408:	pushl %ebx
0x0040d409:	xorl %ebx, %ebx
0x0040d40b:	cmpl 0x41b834, %ebx
0x0040d411:	pushl %esi
0x0040d412:	pushl %edi
0x0040d413:	jne 0x0040d41a
0x0040d41a:	movl %esi, 0x41aa94
0x0040d420:	xorl %edi, %edi
0x0040d422:	cmpl %esi, %ebx
0x0040d424:	jne 0x0040d43e
0x0040d43e:	movb %al, (%esi)
0x0040d440:	cmpb %al, %bl
0x0040d442:	jne 0x0040d42e
0x0040d42e:	cmpb %al, $0x3d<UINT8>
0x0040d430:	je 0x0040d433
0x0040d433:	pushl %esi
0x0040d434:	call 0x0040b810
0x0040b810:	movl %ecx, 0x4(%esp)
0x0040b814:	testl %ecx, $0x3<UINT32>
0x0040b81a:	je 0x0040b840
0x0040b840:	movl %eax, (%ecx)
0x0040b842:	movl %edx, $0x7efefeff<UINT32>
0x0040b847:	addl %edx, %eax
0x0040b849:	xorl %eax, $0xffffffff<UINT8>
0x0040b84c:	xorl %eax, %edx
0x0040b84e:	addl %ecx, $0x4<UINT8>
0x0040b851:	testl %eax, $0x81010100<UINT32>
0x0040b856:	je 0x0040b840
0x0040b858:	movl %eax, -4(%ecx)
0x0040b85b:	testb %al, %al
0x0040b85d:	je 50
0x0040b85f:	testb %ah, %ah
0x0040b861:	je 0x0040b887
0x0040b863:	testl %eax, $0xff0000<UINT32>
0x0040b868:	je 19
0x0040b86a:	testl %eax, $0xff000000<UINT32>
0x0040b86f:	je 0x0040b873
0x0040b873:	leal %eax, -1(%ecx)
0x0040b876:	movl %ecx, 0x4(%esp)
0x0040b87a:	subl %eax, %ecx
0x0040b87c:	ret

0x0040d439:	popl %ecx
0x0040d43a:	leal %esi, 0x1(%esi,%eax)
0x0040d444:	pushl $0x4<UINT8>
0x0040d446:	incl %edi
0x0040d447:	pushl %edi
0x0040d448:	call 0x00409f6a
0x0040d44d:	movl %edi, %eax
0x0040d44f:	cmpl %edi, %ebx
0x0040d451:	popl %ecx
0x0040d452:	popl %ecx
0x0040d453:	movl 0x41aa70, %edi
0x0040d459:	je -53
0x0040d45b:	movl %esi, 0x41aa94
0x0040d461:	pushl %ebp
0x0040d462:	jmp 0x0040d4a4
0x0040d4a4:	cmpb (%esi), %bl
0x0040d4a6:	jne 0x0040d464
0x0040d464:	pushl %esi
0x0040d465:	call 0x0040b810
0x0040d46a:	movl %ebp, %eax
0x0040d46c:	incl %ebp
0x0040d46d:	cmpb (%esi), $0x3d<UINT8>
0x0040d470:	popl %ecx
0x0040d471:	je 0x0040d4a2
0x0040d4a2:	addl %esi, %ebp
0x0040d4a8:	pushl 0x41aa94
0x0040d4ae:	call 0x004045d5
0x004045d5:	pushl $0xc<UINT8>
0x004045d7:	pushl $0x417540<UINT32>
0x004045dc:	call 0x00408a1c
0x004045e1:	movl %esi, 0x8(%ebp)
0x004045e4:	testl %esi, %esi
0x004045e6:	je 117
0x004045e8:	cmpl 0x41b800, $0x3<UINT8>
0x004045ef:	jne 0x00404634
0x00404634:	pushl %esi
0x00404635:	pushl $0x0<UINT8>
0x00404637:	pushl 0x41ac4c
0x0040463d:	call HeapFree@KERNEL32.DLL
0x00404643:	testl %eax, %eax
0x00404645:	jne 0x0040465d
0x0040465d:	call 0x00408a61
0x00404662:	ret

0x0040d4b3:	movl 0x41aa94, %ebx
0x0040d4b9:	movl (%edi), %ebx
0x0040d4bb:	movl 0x41b828, $0x1<UINT32>
0x0040d4c5:	xorl %eax, %eax
0x0040d4c7:	popl %ecx
0x0040d4c8:	popl %ebp
0x0040d4c9:	popl %edi
0x0040d4ca:	popl %esi
0x0040d4cb:	popl %ebx
0x0040d4cc:	ret

0x004066ed:	testl %eax, %eax
0x004066ef:	jnl 0x004066f9
0x004066f9:	pushl $0x1<UINT8>
0x004066fb:	call 0x00405a42
0x00405a42:	cmpl 0x41b838, $0x0<UINT8>
0x00405a49:	je 0x00405a65
0x00405a65:	call 0x0040b49f
0x0040b49f:	pushl %esi
0x0040b4a0:	pushl %edi
0x0040b4a1:	xorl %edi, %edi
0x0040b4a3:	leal %esi, 0x419d90(%edi)
0x0040b4a9:	pushl (%esi)
0x0040b4ab:	call 0x0040711e
0x0040713b:	pushl %eax
0x0040713c:	pushl 0x419974
0x00407142:	call TlsGetValue@KERNEL32.DLL
0x00407144:	call FlsGetValue@KERNEL32.DLL
0x00407146:	testl %eax, %eax
0x00407148:	je 8
0x0040714a:	movl %eax, 0x1f8(%eax)
0x00407150:	jmp 0x0040716d
0x0040b4b0:	addl %edi, $0x4<UINT8>
0x0040b4b3:	cmpl %edi, $0x28<UINT8>
0x0040b4b6:	popl %ecx
0x0040b4b7:	movl (%esi), %eax
0x0040b4b9:	jb 0x0040b4a3
0x0040b4bb:	popl %edi
0x0040b4bc:	popl %esi
0x0040b4bd:	ret

0x00405a6a:	pushl $0x412264<UINT32>
0x00405a6f:	pushl $0x41224c<UINT32>
0x00405a74:	call 0x004059af
0x004059af:	pushl %esi
0x004059b0:	movl %esi, 0x8(%esp)
0x004059b4:	xorl %eax, %eax
0x004059b6:	jmp 0x004059c7
0x004059c7:	cmpl %esi, 0xc(%esp)
0x004059cb:	jb 0x004059b8
0x004059b8:	testl %eax, %eax
0x004059ba:	jne 17
0x004059bc:	movl %ecx, (%esi)
0x004059be:	testl %ecx, %ecx
0x004059c0:	je 0x004059c4
0x004059c4:	addl %esi, $0x4<UINT8>
0x004059c2:	call 0x0040e271
0x00404b11:	movl %eax, 0x41c860
0x00404b16:	testl %eax, %eax
0x00404b18:	pushl %esi
0x00404b19:	pushl $0x14<UINT8>
0x00404b1b:	popl %esi
0x00404b1c:	jne 7
0x00404b1e:	movl %eax, $0x200<UINT32>
0x00404b23:	jmp 0x00404b2b
0x00404b2b:	movl 0x41c860, %eax
0x00404b30:	pushl $0x4<UINT8>
0x00404b32:	pushl %eax
0x00404b33:	call 0x00409f6a
0x00404b38:	testl %eax, %eax
0x00404b3a:	popl %ecx
0x00404b3b:	popl %ecx
0x00404b3c:	movl 0x41b84c, %eax
0x00404b41:	jne 0x00404b61
0x00404b61:	xorl %edx, %edx
0x00404b63:	movl %ecx, $0x4190c8<UINT32>
0x00404b68:	jmp 0x00404b6f
0x00404b6f:	movl (%edx,%eax), %ecx
0x00404b72:	addl %ecx, $0x20<UINT8>
0x00404b75:	addl %edx, $0x4<UINT8>
0x00404b78:	cmpl %ecx, $0x419348<UINT32>
0x00404b7e:	jl 0x00404b6a
0x00404b6a:	movl %eax, 0x41b84c
0x00404b80:	pushl $0xfffffffe<UINT8>
0x00404b82:	popl %esi
0x00404b83:	xorl %edx, %edx
0x00404b85:	movl %ecx, $0x4190d8<UINT32>
0x00404b8a:	pushl %edi
0x00404b8b:	movl %edi, %edx
0x00404b8d:	andl %edi, $0x1f<UINT8>
0x00404b90:	imull %edi, %edi, $0x28<UINT8>
0x00404b93:	movl %eax, %edx
0x00404b95:	sarl %eax, $0x5<UINT8>
0x00404b98:	movl %eax, 0x41b700(,%eax,4)
0x00404b9f:	movl %eax, (%edi,%eax)
0x00404ba2:	cmpl %eax, $0xffffffff<UINT8>
0x00404ba5:	je 8
0x00404ba7:	cmpl %eax, %esi
0x00404ba9:	je 4
0x00404bab:	testl %eax, %eax
0x00404bad:	jne 0x00404bb1
0x00404bb1:	addl %ecx, $0x20<UINT8>
0x00404bb4:	incl %edx
0x00404bb5:	cmpl %ecx, $0x419138<UINT32>
0x00404bbb:	jl 0x00404b8b
0x00404bbd:	popl %edi
0x00404bbe:	xorl %eax, %eax
0x00404bc0:	popl %esi
0x00404bc1:	ret

0x00407d62:	andl 0x41b81c, $0x0<UINT8>
0x00407d69:	call 0x0040e211
0x0040e211:	pushl %ebp
0x0040e212:	movl %ebp, %esp
0x0040e214:	subl %esp, $0x18<UINT8>
0x0040e217:	xorl %eax, %eax
0x0040e219:	pushl %ebx
0x0040e21a:	movl -4(%ebp), %eax
0x0040e21d:	movl -12(%ebp), %eax
0x0040e220:	movl -8(%ebp), %eax
0x0040e223:	pushl %ebx
0x0040e224:	pushfl
0x0040e225:	popl %eax
0x0040e226:	movl %ecx, %eax
0x0040e228:	xorl %eax, $0x200000<UINT32>
0x0040e22d:	pushl %eax
0x0040e22e:	popfl
0x0040e22f:	pushfl
0x0040e230:	popl %edx
0x0040e231:	subl %edx, %ecx
0x0040e233:	je 0x0040e254
0x0040e254:	popl %ebx
0x0040e255:	testl -4(%ebp), $0x4000000<UINT32>
0x0040e25c:	je 0x0040e26c
0x0040e26c:	xorl %eax, %eax
0x0040e26e:	popl %ebx
0x0040e26f:	leave
0x0040e270:	ret

0x00407d6e:	movl 0x41b81c, %eax
0x00407d73:	xorl %eax, %eax
0x00407d75:	ret

0x0040b3da:	pushl %esi
0x0040b3db:	pushl $0x4<UINT8>
0x0040b3dd:	pushl $0x20<UINT8>
0x0040b3df:	call 0x00409f6a
0x0040b3e4:	movl %esi, %eax
0x0040b3e6:	pushl %esi
0x0040b3e7:	call 0x0040711e
0x0040b3ec:	addl %esp, $0xc<UINT8>
0x0040b3ef:	testl %esi, %esi
0x0040b3f1:	movl 0x41b830, %eax
0x0040b3f6:	movl 0x41b82c, %eax
0x0040b3fb:	jne 0x0040b402
0x0040b402:	andl (%esi), $0x0<UINT8>
0x0040b405:	xorl %eax, %eax
0x0040b407:	popl %esi
0x0040b408:	ret

0x0040e271:	call 0x0040e211
0x0040e276:	movl 0x41b820, %eax
0x0040e27b:	xorl %eax, %eax
0x0040e27d:	ret

0x004059cd:	popl %esi
0x004059ce:	ret

0x00405a79:	testl %eax, %eax
0x00405a7b:	popl %ecx
0x00405a7c:	popl %ecx
0x00405a7d:	jne 84
0x00405a7f:	pushl %esi
0x00405a80:	pushl %edi
0x00405a81:	pushl $0x40b47b<UINT32>
0x00405a86:	call 0x0040b445
0x0040b445:	pushl 0x4(%esp)
0x0040b449:	call 0x0040b409
0x0040b409:	pushl $0xc<UINT8>
0x0040b40b:	pushl $0x4178d0<UINT32>
0x0040b410:	call 0x00408a1c
0x0040b415:	call 0x00405985
0x00405985:	pushl $0x8<UINT8>
0x00405987:	call 0x00407eec
0x0040598c:	popl %ecx
0x0040598d:	ret

0x0040b41a:	andl -4(%ebp), $0x0<UINT8>
0x0040b41e:	pushl 0x8(%ebp)
0x0040b421:	call 0x0040b32d
0x0040b32d:	pushl %ecx
0x0040b32e:	pushl %ebx
0x0040b32f:	pushl %ebp
0x0040b330:	pushl %esi
0x0040b331:	pushl %edi
0x0040b332:	pushl 0x41b830
0x0040b338:	call 0x0040718a
0x0040b33d:	pushl 0x41b82c
0x0040b343:	movl %esi, %eax
0x0040b345:	movl 0x18(%esp), %esi
0x0040b349:	call 0x0040718a
0x0040b34e:	movl %edi, %eax
0x0040b350:	cmpl %edi, %esi
0x0040b352:	popl %ecx
0x0040b353:	popl %ecx
0x0040b354:	jb 124
0x0040b356:	movl %ebx, %edi
0x0040b358:	subl %ebx, %esi
0x0040b35a:	leal %ebp, 0x4(%ebx)
0x0040b35d:	cmpl %ebp, $0x4<UINT8>
0x0040b360:	jb 112
0x0040b362:	pushl %esi
0x0040b363:	call 0x004105f9
0x004105f9:	pushl $0x10<UINT8>
0x004105fb:	pushl $0x417a58<UINT32>
0x00410600:	call 0x00408a1c
0x00410605:	xorl %eax, %eax
0x00410607:	movl %ebx, 0x8(%ebp)
0x0041060a:	xorl %edi, %edi
0x0041060c:	cmpl %ebx, %edi
0x0041060e:	setne %al
0x00410611:	cmpl %eax, %edi
0x00410613:	jne 0x00410632
0x00410632:	cmpl 0x41b800, $0x3<UINT8>
0x00410639:	jne 0x00410673
0x00410673:	pushl %ebx
0x00410674:	pushl %edi
0x00410675:	pushl 0x41ac4c
0x0041067b:	call HeapSize@KERNEL32.DLL
HeapSize@KERNEL32.DLL: API Node	
0x00410681:	movl %esi, %eax
0x00410683:	movl %eax, %esi
0x00410685:	call 0x00408a61
0x0041068a:	ret

0x0040b368:	movl %esi, %eax
0x0040b36a:	cmpl %esi, %ebp
0x0040b36c:	popl %ecx
0x0040b36d:	jae 0x0040b3b9
0x0040b3b9:	movl %esi, 0x18(%esp)
0x0040b3bd:	movl (%edi), %esi
0x0040b3bf:	addl %edi, $0x4<UINT8>
0x0040b3c2:	pushl %edi
0x0040b3c3:	call 0x0040711e
0x0040b3c8:	movl 0x41b82c, %eax
0x0040b3cd:	popl %ecx
0x0040b3ce:	movl %eax, %esi
0x0040b3d0:	jmp 0x0040b3d4
0x0040b3d4:	popl %edi
0x0040b3d5:	popl %esi
0x0040b3d6:	popl %ebp
0x0040b3d7:	popl %ebx
0x0040b3d8:	popl %ecx
0x0040b3d9:	ret

0x0040b426:	popl %ecx
0x0040b427:	movl -28(%ebp), %eax
0x0040b42a:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040b431:	call 0x0040b43f
0x0040b43f:	call 0x0040598e
0x0040598e:	pushl $0x8<UINT8>
0x00405990:	call 0x00407e14
0x00405995:	popl %ecx
0x00405996:	ret

0x0040b444:	ret

0x0040b436:	movl %eax, -28(%ebp)
0x0040b439:	call 0x00408a61
0x0040b43e:	ret

0x0040b44e:	negl %eax
0x0040b450:	sbbl %eax, %eax
0x0040b452:	negl %eax
0x0040b454:	popl %ecx
0x0040b455:	decl %eax
0x0040b456:	ret

0x00405a8b:	movl %esi, $0x412244<UINT32>
0x00405a90:	movl %eax, %esi
0x00405a92:	movl %edi, $0x412248<UINT32>
0x00405a97:	cmpl %eax, %edi
0x00405a99:	popl %ecx
0x00405a9a:	jae 15
0x00405a9c:	movl %eax, (%esi)
0x00405a9e:	testl %eax, %eax
0x00405aa0:	je 0x00405aa4
0x00405aa4:	addl %esi, $0x4<UINT8>
0x00405aa7:	cmpl %esi, %edi
0x00405aa9:	jb -15
0x00405aab:	cmpl 0x41b83c, $0x0<UINT8>
0x00405ab2:	popl %edi
0x00405ab3:	popl %esi
0x00405ab4:	je 0x00405ad1
0x00405ad1:	xorl %eax, %eax
0x00405ad3:	ret

0x00406700:	popl %ecx
0x00406701:	testl %eax, %eax
0x00406703:	je 0x0040670c
0x0040670c:	movl %eax, 0x41aa70
0x00406711:	movl 0x41aa74, %eax
0x00406716:	pushl %eax
0x00406717:	pushl 0x41aa68
0x0040671d:	pushl 0x41aa64
0x00406723:	call 0x00403d20
0x00403d20:	pushl %esi
0x00403d21:	movl %esi, 0xc(%esp)
0x00403d25:	leal %eax, 0x8(%esp)
0x00403d29:	pushl %esi
0x00403d2a:	pushl %eax
0x00403d2b:	call 0x00402ac0
0x00402ac0:	subl %esp, $0x110<UINT32>
0x00402ac6:	movl %eax, 0x4190c0
0x00402acb:	xorl %eax, %esp
0x00402acd:	movl 0x10c(%esp), %eax
0x00402ad4:	movl %eax, 0x118(%esp)
0x00402adb:	pushl %ebx
0x00402adc:	pushl %ebp
0x00402add:	movl %ebp, 0x11c(%esp)
0x00402ae4:	pushl %esi
0x00402ae5:	pushl %edi
0x00402ae6:	pushl $0x104<UINT32>
0x00402aeb:	leal %ecx, 0x1c(%esp)
0x00402aef:	pushl %ecx
0x00402af0:	pushl $0x0<UINT8>
0x00402af2:	movl 0x1c(%esp), %eax
0x00402af6:	call GetModuleFileNameA@KERNEL32.DLL
0x00402afc:	leal %edx, 0x14(%esp)
0x00402b00:	pushl %edx
0x00402b01:	leal %eax, 0x1c(%esp)
0x00402b05:	pushl %eax
0x00402b06:	call 0x00403df4
0x00403df4:	jmp GetFileVersionInfoSizeA@VERSION.dll
GetFileVersionInfoSizeA@VERSION.dll: API Node	
0x00402b0b:	movl %edi, %eax
0x00402b0d:	pushl %edi
0x00402b0e:	call 0x004041a9
0x00404256:	pushl %ebp
0x00404257:	call 0x00408d0d
0x00408d0d:	pushl 0x41af64
0x00408d13:	call 0x0040718a
0x00408d18:	testl %eax, %eax
0x00408d1a:	popl %ecx
0x00408d1b:	je 0x00408d2c
0x00408d2c:	xorl %eax, %eax
0x00408d2e:	ret

0x0040425c:	popl %ecx
0x0040425d:	call 0x00407c38
0x00407c38:	call 0x00407345
0x00407c3d:	testl %eax, %eax
0x00407c3f:	jne 0x00407c47
0x00407c47:	addl %eax, $0x8<UINT8>
0x00407c4a:	ret

0x00404262:	movl (%eax), $0xc<UINT32>
0x00404268:	xorl %eax, %eax
0x0040426a:	popl %ebp
0x0040426b:	ret

0x00402b13:	addl %esp, $0x4<UINT8>
0x00402b16:	movl %esi, %eax
0x00402b18:	pushl %esi
0x00402b19:	pushl %edi
0x00402b1a:	pushl $0x0<UINT8>
0x00402b1c:	leal %ecx, 0x24(%esp)
0x00402b20:	pushl %ecx
0x00402b21:	call 0x00403dee
0x00403dee:	jmp GetFileVersionInfoA@VERSION.dll
GetFileVersionInfoA@VERSION.dll: API Node	
0x00402b26:	pushl $0x414af8<UINT32>
0x00402b2b:	pushl %esi
0x00402b2c:	call 0x00402a70
0x00402a70:	subl %esp, $0xc<UINT8>
0x00402a73:	pushl %esi
0x00402a74:	movl %esi, 0x14(%esp)
0x00402a78:	leal %ecx, 0xc(%esp)
0x00402a7c:	pushl %ecx
0x00402a7d:	leal %edx, 0x8(%esp)
0x00402a81:	pushl %edx
0x00402a82:	pushl $0x414a5c<UINT32>
0x00402a87:	leal %eax, 0x14(%esp)
0x00402a8b:	pushl %esi
0x00402a8c:	movw 0x18(%esp), $0x400<UINT16>
0x00402a93:	movl 0x14(%esp), %eax
0x00402a97:	call 0x00403de8
0x00403de8:	jmp VerQueryValueA@VERSION.dll
VerQueryValueA@VERSION.dll: API Node	
0x00402a9c:	movl %eax, 0x18(%esp)
0x00402aa0:	pushl %eax
0x00402aa1:	movl %eax, 0x8(%esp)
0x00402aa5:	movzwl %ecx, 0x2(%eax)
0x00402aa9:	movzwl %edx, (%eax)
0x00402aac:	pushl %ecx
0x00402aad:	pushl %edx
0x00402aae:	pushl %esi
0x00402aaf:	call 0x004029a0
0x004029a0:	pushl %ebp
0x004029a1:	movl %ebp, %esp
0x004029a3:	pushl $0xfffffffe<UINT8>
0x004029a5:	pushl $0x417500<UINT32>
0x004029aa:	pushl $0x405790<UINT32>
0x004029af:	movl %eax, %fs:0
0x004029b5:	pushl %eax
0x004029b6:	subl %esp, $0x118<UINT32>
0x004029bc:	movl %eax, 0x4190c0
0x004029c1:	xorl -8(%ebp), %eax
0x004029c4:	xorl %eax, %ebp
0x004029c6:	movl -28(%ebp), %eax
0x004029c9:	pushl %ebx
0x004029ca:	pushl %esi
0x004029cb:	pushl %edi
0x004029cc:	pushl %eax
0x004029cd:	leal %eax, -16(%ebp)
0x004029d0:	movl %fs:0, %eax
0x004029d6:	movl -24(%ebp), %esp
0x004029d9:	movl %esi, 0x8(%ebp)
0x004029dc:	movl %eax, 0x14(%ebp)
0x004029df:	xorl %edi, %edi
0x004029e1:	movl -288(%ebp), %edi
0x004029e7:	pushl %eax
0x004029e8:	movzwl %eax, 0x10(%ebp)
0x004029ec:	pushl %eax
0x004029ed:	movzwl %ecx, 0xc(%ebp)
0x004029f1:	pushl %ecx
0x004029f2:	pushl $0x414a40<UINT32>
0x004029f7:	leal %edx, -284(%ebp)
0x004029fd:	pushl %edx
0x004029fe:	call 0x00404663
0x00404663:	pushl %ebp
0x00404664:	movl %ebp, %esp
0x00404666:	subl %esp, $0x20<UINT8>
0x00404669:	pushl %ebx
0x0040466a:	xorl %ebx, %ebx
0x0040466c:	cmpl 0xc(%ebp), %ebx
0x0040466f:	jne 0x0040468e
0x0040468e:	movl %eax, 0x8(%ebp)
0x00404691:	cmpl %eax, %ebx
0x00404693:	je -36
0x00404695:	pushl %esi
0x00404696:	movl -24(%ebp), %eax
0x00404699:	movl -32(%ebp), %eax
0x0040469c:	leal %eax, 0x10(%ebp)
0x0040469f:	pushl %eax
0x004046a0:	pushl %ebx
0x004046a1:	pushl 0xc(%ebp)
0x004046a4:	leal %eax, -32(%ebp)
0x004046a7:	pushl %eax
0x004046a8:	movl -28(%ebp), $0x7fffffff<UINT32>
0x004046af:	movl -20(%ebp), $0x42<UINT32>
0x004046b6:	call 0x0040909a
0x0040909a:	pushl %ebp
0x0040909b:	leal %ebp, -504(%esp)
0x004090a2:	subl %esp, $0x278<UINT32>
0x004090a8:	movl %eax, 0x4190c0
0x004090ad:	xorl %eax, %ebp
0x004090af:	movl 0x1f4(%ebp), %eax
0x004090b5:	movl %eax, 0x200(%ebp)
0x004090bb:	pushl %ebx
0x004090bc:	movl %ebx, 0x204(%ebp)
0x004090c2:	pushl %esi
0x004090c3:	xorl %esi, %esi
0x004090c5:	pushl %edi
0x004090c6:	movl %edi, 0x20c(%ebp)
0x004090cc:	pushl 0x208(%ebp)
0x004090d2:	leal %ecx, -100(%ebp)
0x004090d5:	movl -48(%ebp), %eax
0x004090d8:	movl -44(%ebp), %edi
0x004090db:	movl -76(%ebp), %esi
0x004090de:	movl -24(%ebp), %esi
0x004090e1:	movl -64(%ebp), %esi
0x004090e4:	movl -32(%ebp), %esi
0x004090e7:	movl -60(%ebp), %esi
0x004090ea:	movl -80(%ebp), %esi
0x004090ed:	movl -68(%ebp), %esi
0x004090f0:	call 0x00403e2a
0x004090f5:	cmpl -48(%ebp), %esi
0x004090f8:	jne 0x00409127
0x00409127:	movl %eax, -48(%ebp)
0x0040912a:	testb 0xc(%eax), $0x40<UINT8>
0x0040912e:	jne 0x004091d8
0x004091d8:	cmpl %ebx, %esi
0x004091da:	je -230
0x004091e0:	movb %dl, (%ebx)
0x004091e2:	xorl %ecx, %ecx
0x004091e4:	testb %dl, %dl
0x004091e6:	movl -52(%ebp), %esi
0x004091e9:	movl -40(%ebp), %esi
0x004091ec:	movl -84(%ebp), %esi
0x004091ef:	movb -25(%ebp), %dl
0x004091f2:	je 2031
0x004091f8:	incl %ebx
0x004091f9:	cmpl -52(%ebp), $0x0<UINT8>
0x004091fd:	movl -72(%ebp), %ebx
0x00409200:	jl 2017
0x00409206:	movb %al, %dl
0x00409208:	subb %al, $0x20<UINT8>
0x0040920a:	cmpb %al, $0x58<UINT8>
0x0040920c:	ja 17
0x0040920e:	movsbl %eax, %dl
0x00409211:	movzbl %eax, 0x416960(%eax)
0x00409218:	andl %eax, $0xf<UINT8>
0x0040921b:	xorl %esi, %esi
0x0040921d:	jmp 0x00409223
0x00409223:	movsbl %eax, 0x416980(%ecx,%eax,8)
0x0040922b:	pushl $0x7<UINT8>
0x0040922d:	sarl %eax, $0x4<UINT8>
0x00409230:	popl %ecx
0x00409231:	cmpl %eax, %ecx
0x00409233:	movl -116(%ebp), %eax
0x00409236:	ja 1915
0x0040923c:	jmp 0x0040941e
0x004093dc:	leal %eax, -100(%ebp)
0x004093df:	pushl %eax
0x004093e0:	movzbl %eax, %dl
0x004093e3:	pushl %eax
0x004093e4:	movl -68(%ebp), %esi
0x004093e7:	call 0x0040d30e
0x0040d30e:	pushl %ebp
0x0040d30f:	movl %ebp, %esp
0x0040d311:	subl %esp, $0x10<UINT8>
0x0040d314:	pushl 0xc(%ebp)
0x0040d317:	leal %ecx, -16(%ebp)
0x0040d31a:	call 0x00403e2a
0x00403e9c:	movl %ecx, (%eax)
0x00403e9e:	movl (%esi), %ecx
0x00403ea0:	movl %eax, 0x4(%eax)
0x00403ea3:	movl 0x4(%esi), %eax
0x0040d31f:	movzbl %eax, 0x8(%ebp)
0x0040d323:	movl %ecx, -16(%ebp)
0x0040d326:	movl %ecx, 0xc8(%ecx)
0x0040d32c:	movzwl %eax, (%ecx,%eax,2)
0x0040d330:	andl %eax, $0x8000<UINT32>
0x0040d335:	cmpb -4(%ebp), $0x0<UINT8>
0x0040d339:	je 0x0040d342
0x0040d342:	leave
0x0040d343:	ret

0x004093ec:	popl %ecx
0x004093ed:	testl %eax, %eax
0x004093ef:	movb %al, -25(%ebp)
0x004093f2:	popl %ecx
0x004093f3:	je 0x0040940e
0x0040940e:	movl %ecx, -48(%ebp)
0x00409411:	leal %esi, -52(%ebp)
0x00409414:	call 0x00408ff9
0x00408ff9:	testb 0xc(%ecx), $0x40<UINT8>
0x00408ffd:	je 6
0x00408fff:	cmpl 0x8(%ecx), $0x0<UINT8>
0x00409003:	je 36
0x00409005:	decl 0x4(%ecx)
0x00409008:	js 11
0x0040900a:	movl %edx, (%ecx)
0x0040900c:	movb (%edx), %al
0x0040900e:	incl (%ecx)
0x00409010:	movzbl %eax, %al
0x00409013:	jmp 0x00409021
0x00409021:	cmpl %eax, $0xffffffff<UINT8>
0x00409024:	jne 0x00409029
0x00409029:	incl (%esi)
0x0040902b:	ret

0x00409419:	jmp 0x004099b7
0x004099b7:	movl %ebx, -72(%ebp)
0x004099ba:	movb %al, (%ebx)
0x004099bc:	testb %al, %al
0x004099be:	movb -25(%ebp), %al
0x004099c1:	je 0x004099e7
0x004099c3:	movl %ecx, -116(%ebp)
0x004099c6:	movl %edi, -44(%ebp)
0x004099c9:	movb %dl, %al
0x004099cb:	jmp 0x004091f8
0x00409243:	orl -32(%ebp), $0xffffffff<UINT8>
0x00409247:	movl -120(%ebp), %esi
0x0040924a:	movl -80(%ebp), %esi
0x0040924d:	movl -64(%ebp), %esi
0x00409250:	movl -60(%ebp), %esi
0x00409253:	movl -24(%ebp), %esi
0x00409256:	movl -68(%ebp), %esi
0x00409259:	jmp 0x004099b7
0x0040925e:	movsbl %eax, %dl
0x00409261:	subl %eax, $0x20<UINT8>
0x00409264:	je 62
0x00409266:	subl %eax, $0x3<UINT8>
0x00409269:	je 45
0x0040926b:	subl %eax, $0x8<UINT8>
0x0040926e:	je 31
0x00409270:	decl %eax
0x00409271:	decl %eax
0x00409272:	je 18
0x00409274:	subl %eax, $0x3<UINT8>
0x00409277:	jne 1850
0x0040927d:	orl -24(%ebp), $0x8<UINT8>
0x00409281:	jmp 0x004099b7
0x004092ad:	cmpb %dl, $0x2a<UINT8>
0x004092b0:	jne 0x004092d2
0x004092d2:	movl %eax, -64(%ebp)
0x004092d5:	imull %eax, %eax, $0xa<UINT8>
0x004092d8:	movsbl %ecx, %dl
0x004092db:	leal %eax, -48(%eax,%ecx)
0x004092df:	movl -64(%ebp), %eax
0x004092e2:	jmp 0x004099b7
0x0040941e:	movsbl %eax, %dl
0x00409421:	cmpl %eax, $0x64<UINT8>
0x00409424:	jg 0x0040959c
0x0040942a:	je 491
0x00409430:	cmpl %eax, $0x53<UINT8>
0x00409433:	jg 0x004094e4
0x004094e4:	subl %eax, $0x58<UINT8>
0x004094e7:	je 0x00409726
0x00409726:	movl -76(%ebp), %ecx
0x00409729:	jmp 0x0040974c
0x0040974c:	testb -24(%ebp), $0xffffff80<UINT8>
0x00409750:	movl -40(%ebp), $0x10<UINT32>
0x00409757:	je 0x00409626
0x00409626:	movl %ecx, -24(%ebp)
0x00409629:	testw %cx, %cx
0x0040962c:	jns 0x00409775
0x00409775:	testw %cx, $0x1000<UINT16>
0x0040977a:	jne -334
0x00409780:	addl %edi, $0x4<UINT8>
0x00409783:	testb %cl, $0x20<UINT8>
0x00409786:	je 0x0040979d
0x0040979d:	testb %cl, $0x40<UINT8>
0x004097a0:	movl %eax, -4(%edi)
0x004097a3:	je 0x004097a8
0x004097a8:	xorl %edx, %edx
0x004097aa:	movl -44(%ebp), %edi
0x004097ad:	testb %cl, $0x40<UINT8>
0x004097b0:	je 0x004097ca
0x004097ca:	testw -24(%ebp), $0xffff9000<UINT16>
0x004097d0:	movl %ebx, %edx
0x004097d2:	movl %edi, %eax
0x004097d4:	jne 2
0x004097d6:	xorl %ebx, %ebx
0x004097d8:	cmpl -32(%ebp), $0x0<UINT8>
0x004097dc:	jnl 9
0x004097de:	movl -32(%ebp), $0x1<UINT32>
0x004097e5:	jmp 0x004097f8
0x004097f8:	movl %eax, %edi
0x004097fa:	orl %eax, %ebx
0x004097fc:	jne 0x00409802
0x00409802:	leal %esi, 0x1eb(%ebp)
0x00409808:	movl %eax, -32(%ebp)
0x0040980b:	decl -32(%ebp)
0x0040980e:	testl %eax, %eax
0x00409810:	jg 0x00409818
0x00409818:	movl %eax, -40(%ebp)
0x0040981b:	cltd
0x0040981c:	pushl %edx
0x0040981d:	pushl %eax
0x0040981e:	pushl %ebx
0x0040981f:	pushl %edi
0x00409820:	call 0x0040eb90
0x0040eb90:	pushl %esi
0x0040eb91:	movl %eax, 0x14(%esp)
0x0040eb95:	orl %eax, %eax
0x0040eb97:	jne 40
0x0040eb99:	movl %ecx, 0x10(%esp)
0x0040eb9d:	movl %eax, 0xc(%esp)
0x0040eba1:	xorl %edx, %edx
0x0040eba3:	divl %eax, %ecx
0x0040eba5:	movl %ebx, %eax
0x0040eba7:	movl %eax, 0x8(%esp)
0x0040ebab:	divl %eax, %ecx
0x0040ebad:	movl %esi, %eax
0x0040ebaf:	movl %eax, %ebx
0x0040ebb1:	mull %eax, 0x10(%esp)
0x0040ebb5:	movl %ecx, %eax
0x0040ebb7:	movl %eax, %esi
0x0040ebb9:	mull %eax, 0x10(%esp)
0x0040ebbd:	addl %edx, %ecx
0x0040ebbf:	jmp 0x0040ec08
0x0040ec08:	subl %eax, 0x8(%esp)
0x0040ec0c:	sbbl %edx, 0xc(%esp)
0x0040ec10:	negl %edx
0x0040ec12:	negl %eax
0x0040ec14:	sbbl %edx, $0x0<UINT8>
0x0040ec17:	movl %ecx, %edx
0x0040ec19:	movl %edx, %ebx
0x0040ec1b:	movl %ebx, %ecx
0x0040ec1d:	movl %ecx, %eax
0x0040ec1f:	movl %eax, %esi
0x0040ec21:	popl %esi
0x0040ec22:	ret $0x10<UINT16>

0x00409825:	addl %ecx, $0x30<UINT8>
0x00409828:	cmpl %ecx, $0x39<UINT8>
0x0040982b:	movl -104(%ebp), %ebx
0x0040982e:	movl %edi, %eax
0x00409830:	movl %ebx, %edx
0x00409832:	jle 0x00409837
0x00409837:	movb (%esi), %cl
0x00409839:	decl %esi
0x0040983a:	jmp 0x00409808
0x00409812:	movl %eax, %edi
0x00409814:	orl %eax, %ebx
0x00409816:	je 0x0040983c
0x0040983c:	leal %eax, 0x1eb(%ebp)
0x00409842:	subl %eax, %esi
0x00409844:	incl %esi
0x00409845:	testw -24(%ebp), $0x200<UINT16>
0x0040984b:	movl -40(%ebp), %eax
0x0040984e:	movl -36(%ebp), %esi
0x00409851:	je 0x0040989f
0x0040989f:	cmpl -80(%ebp), $0x0<UINT8>
0x004098a3:	jne 251
0x004098a9:	movl %eax, -24(%ebp)
0x004098ac:	testb %al, $0x40<UINT8>
0x004098ae:	je 0x004098d5
0x004098d5:	movl %ebx, -64(%ebp)
0x004098d8:	subl %ebx, -40(%ebp)
0x004098db:	subl %ebx, -60(%ebp)
0x004098de:	testb -24(%ebp), $0xc<UINT8>
0x004098e2:	jne 0x004098f5
0x004098f5:	pushl -60(%ebp)
0x004098f8:	movl %edi, -48(%ebp)
0x004098fb:	leal %eax, -52(%ebp)
0x004098fe:	leal %ecx, -56(%ebp)
0x00409901:	call 0x00409050
0x00409050:	testb 0xc(%edi), $0x40<UINT8>
0x00409054:	pushl %ebx
0x00409055:	pushl %esi
0x00409056:	movl %esi, %eax
0x00409058:	movl %ebx, %ecx
0x0040905a:	je 52
0x0040905c:	cmpl 0x8(%edi), $0x0<UINT8>
0x00409060:	jne 0x00409090
0x00409090:	cmpl 0xc(%esp), $0x0<UINT8>
0x00409095:	jg 0x0040906a
0x00409097:	popl %esi
0x00409098:	popl %ebx
0x00409099:	ret

0x00409906:	testb -24(%ebp), $0x8<UINT8>
0x0040990a:	popl %ecx
0x0040990b:	je 0x00409922
0x0040990d:	testb -24(%ebp), $0x4<UINT8>
0x00409911:	jne 15
0x00409913:	pushl %edi
0x00409914:	pushl %ebx
0x00409915:	pushl $0x30<UINT8>
0x00409917:	leal %eax, -52(%ebp)
0x0040991a:	call 0x0040902c
0x0040902c:	pushl %ebp
0x0040902d:	movl %ebp, %esp
0x0040902f:	pushl %esi
0x00409030:	movl %esi, %eax
0x00409032:	jmp 0x00409047
0x00409047:	cmpl 0xc(%ebp), $0x0<UINT8>
0x0040904b:	jg 0x00409034
0x00409034:	movl %ecx, 0x10(%ebp)
0x00409037:	movb %al, 0x8(%ebp)
0x0040903a:	decl 0xc(%ebp)
0x0040903d:	call 0x00408ff9
0x00409042:	cmpl (%esi), $0xffffffff<UINT8>
0x00409045:	je 6
0x0040904d:	popl %esi
0x0040904e:	popl %ebp
0x0040904f:	ret

0x0040991f:	addl %esp, $0xc<UINT8>
0x00409922:	cmpl -68(%ebp), $0x0<UINT8>
0x00409926:	movl %eax, -40(%ebp)
0x00409929:	je 0x0040997c
0x0040997c:	movl %ecx, -36(%ebp)
0x0040997f:	pushl %eax
0x00409980:	leal %eax, -52(%ebp)
0x00409983:	call 0x00409050
0x0040906a:	movb %al, (%ebx)
0x0040906c:	decl 0xc(%esp)
0x00409070:	movl %ecx, %edi
0x00409072:	call 0x00408ff9
0x00409077:	incl %ebx
0x00409078:	cmpl (%esi), $0xffffffff<UINT8>
0x0040907b:	jne 0x00409090
0x00409988:	popl %ecx
0x00409989:	cmpl -52(%ebp), $0x0<UINT8>
0x0040998d:	jl 21
0x0040998f:	testb -24(%ebp), $0x4<UINT8>
0x00409993:	je 0x004099a4
0x004099a4:	cmpl -84(%ebp), $0x0<UINT8>
0x004099a8:	je 0x004099b7
0x0040959c:	cmpl %eax, $0x70<UINT8>
0x0040959f:	jg 0x0040972b
0x0040972b:	subl %eax, $0x73<UINT8>
0x0040972e:	je 0x004094a4
0x004094a4:	movl %ecx, -32(%ebp)
0x004094a7:	cmpl %ecx, $0xffffffff<UINT8>
0x004094aa:	jne 5
0x004094ac:	movl %ecx, $0x7fffffff<UINT32>
0x004094b1:	addl %edi, $0x4<UINT8>
0x004094b4:	testw -24(%ebp), $0x810<UINT16>
0x004094ba:	movl -44(%ebp), %edi
0x004094bd:	movl %edi, -4(%edi)
0x004094c0:	movl -36(%ebp), %edi
0x004094c3:	je 0x0040987d
0x0040987d:	cmpl %edi, %esi
0x0040987f:	jne 0x00409889
0x00409889:	movl %eax, -36(%ebp)
0x0040988c:	jmp 0x00409895
0x00409895:	cmpl %ecx, %esi
0x00409897:	jne 0x0040988e
0x0040988e:	decl %ecx
0x0040988f:	cmpb (%eax), $0x0<UINT8>
0x00409892:	je 0x00409899
0x00409894:	incl %eax
0x00409899:	subl %eax, -36(%ebp)
0x0040989c:	movl -40(%ebp), %eax
0x004098e4:	pushl -48(%ebp)
0x004098e7:	leal %eax, -52(%ebp)
0x004098ea:	pushl %ebx
0x004098eb:	pushl $0x20<UINT8>
0x004098ed:	call 0x0040902c
0x004098f2:	addl %esp, $0xc<UINT8>
0x004099e7:	cmpb -88(%ebp), $0x0<UINT8>
0x004099eb:	je 7
0x004099ed:	movl %eax, -92(%ebp)
0x004099f0:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x004099f4:	movl %eax, -52(%ebp)
0x004099f7:	movl %ecx, 0x1f4(%ebp)
0x004099fd:	popl %edi
0x004099fe:	popl %esi
0x004099ff:	xorl %ecx, %ebp
0x00409a01:	popl %ebx
0x00409a02:	call 0x004046de
0x00409a07:	addl %ebp, $0x1f8<UINT32>
0x00409a0d:	leave
0x00409a0e:	ret

0x004046bb:	addl %esp, $0x10<UINT8>
0x004046be:	decl -28(%ebp)
0x004046c1:	movl %esi, %eax
0x004046c3:	js 7
0x004046c5:	movl %eax, -32(%ebp)
0x004046c8:	movb (%eax), %bl
0x004046ca:	jmp 0x004046d8
0x004046d8:	movl %eax, %esi
0x004046da:	popl %esi
0x004046db:	popl %ebx
0x004046dc:	leave
0x004046dd:	ret

0x00402a03:	addl %esp, $0x14<UINT8>
0x00402a06:	movl -4(%ebp), %edi
0x00402a09:	leal %eax, -296(%ebp)
0x00402a0f:	pushl %eax
0x00402a10:	leal %ecx, -292(%ebp)
0x00402a16:	pushl %ecx
0x00402a17:	leal %edx, -284(%ebp)
0x00402a1d:	pushl %edx
0x00402a1e:	pushl %esi
0x00402a1f:	call 0x00403de8
0x00402a24:	movl -288(%ebp), %eax
0x00402a2a:	jmp 0x00402a35
0x00402a35:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00402a3c:	movl %eax, -288(%ebp)
0x00402a42:	negl %eax
0x00402a44:	sbbl %eax, %eax
0x00402a46:	andl %eax, -292(%ebp)
0x00402a4c:	movl %ecx, -16(%ebp)
0x00402a4f:	movl %fs:0, %ecx
0x00402a56:	popl %ecx
0x00402a57:	popl %edi
0x00402a58:	popl %esi
0x00402a59:	popl %ebx
0x00402a5a:	movl %ecx, -28(%ebp)
0x00402a5d:	xorl %ecx, %ebp
0x00402a5f:	call 0x004046de
0x00402a64:	movl %esp, %ebp
0x00402a66:	popl %ebp
0x00402a67:	ret

0x00402ab4:	addl %esp, $0x10<UINT8>
0x00402ab7:	popl %esi
0x00402ab8:	addl %esp, $0xc<UINT8>
0x00402abb:	ret

0x00402b31:	movl %edi, %eax
0x00402b33:	call 0x00404b0b
0x00404b0b:	movl %eax, $0x4190c8<UINT32>
0x00404b10:	ret

0x00402b38:	addl %eax, $0x40<UINT8>
0x00402b3b:	pushl %eax
0x00402b3c:	pushl $0x4149d0<UINT32>
0x00402b41:	call 0x00405c2e
0x00405c2e:	pushl $0x10<UINT8>
0x00405c30:	pushl $0x4176c8<UINT32>
0x00405c35:	call 0x00408a1c
0x00405c3a:	xorl %eax, %eax
0x00405c3c:	xorl %ebx, %ebx
0x00405c3e:	cmpl 0x8(%ebp), %ebx
0x00405c41:	setne %al
0x00405c44:	cmpl %eax, %ebx
0x00405c46:	jne 0x00405c68
0x00405c68:	xorl %eax, %eax
0x00405c6a:	movl %esi, 0xc(%ebp)
0x00405c6d:	cmpl %esi, %ebx
0x00405c6f:	setne %al
0x00405c72:	cmpl %eax, %ebx
0x00405c74:	je -46
0x00405c76:	testb 0xc(%esi), $0x40<UINT8>
0x00405c7a:	jne 142
0x00405c80:	pushl %esi
0x00405c81:	call 0x00409efd
0x00409efd:	movl %eax, 0x4(%esp)
0x00409f01:	pushl %esi
0x00409f02:	xorl %esi, %esi
0x00409f04:	cmpl %eax, %esi
0x00409f06:	jne 0x00409f25
0x00409f25:	movl %eax, 0x10(%eax)
0x00409f28:	popl %esi
0x00409f29:	ret

0x00405c86:	popl %ecx
0x00405c87:	cmpl %eax, $0xffffffff<UINT8>
0x00405c8a:	je 46
0x00405c8c:	pushl %esi
0x00405c8d:	call 0x00409efd
0x00405c92:	popl %ecx
0x00405c93:	cmpl %eax, $0xfffffffe<UINT8>
0x00405c96:	je 34
0x00405c98:	pushl %esi
0x00405c99:	call 0x00409efd
0x00405c9e:	sarl %eax, $0x5<UINT8>
0x00405ca1:	leal %edi, 0x41b700(,%eax,4)
0x00405ca8:	pushl %esi
0x00405ca9:	call 0x00409efd
0x00405cae:	popl %ecx
0x00405caf:	popl %ecx
0x00405cb0:	andl %eax, $0x1f<UINT8>
0x00405cb3:	imull %eax, %eax, $0x28<UINT8>
0x00405cb6:	addl %eax, (%edi)
0x00405cb8:	jmp 0x00405cbf
0x00405cbf:	testb 0x24(%eax), $0x7f<UINT8>
0x00405cc3:	jne -125
0x00405cc5:	pushl %esi
0x00405cc6:	call 0x00409efd
0x00405ccb:	popl %ecx
0x00405ccc:	cmpl %eax, $0xffffffff<UINT8>
0x00405ccf:	je 46
0x00405cd1:	pushl %esi
0x00405cd2:	call 0x00409efd
0x00405cd7:	popl %ecx
0x00405cd8:	cmpl %eax, $0xfffffffe<UINT8>
0x00405cdb:	je 34
0x00405cdd:	pushl %esi
0x00405cde:	call 0x00409efd
0x00405ce3:	sarl %eax, $0x5<UINT8>
0x00405ce6:	leal %edi, 0x41b700(,%eax,4)
0x00405ced:	pushl %esi
0x00405cee:	call 0x00409efd
0x00405cf3:	popl %ecx
0x00405cf4:	popl %ecx
0x00405cf5:	andl %eax, $0x1f<UINT8>
0x00405cf8:	imull %eax, %eax, $0x28<UINT8>
0x00405cfb:	addl %eax, (%edi)
0x00405cfd:	jmp 0x00405d04
0x00405d04:	testb 0x24(%eax), $0xffffff80<UINT8>
0x00405d08:	jne -198
0x00405d0e:	pushl 0x8(%ebp)
0x00405d11:	call 0x0040b810
0x0040b887:	leal %eax, -3(%ecx)
0x0040b88a:	movl %ecx, 0x4(%esp)
0x0040b88e:	subl %eax, %ecx
0x0040b890:	ret

0x00405d16:	movl -28(%ebp), %eax
0x00405d19:	pushl %esi
0x00405d1a:	call 0x00404be2
0x00404be2:	movl %eax, 0x4(%esp)
0x00404be6:	movl %ecx, $0x4190c8<UINT32>
0x00404beb:	cmpl %eax, %ecx
0x00404bed:	jb 23
0x00404bef:	cmpl %eax, $0x419328<UINT32>
0x00404bf4:	ja 16
0x00404bf6:	subl %eax, %ecx
0x00404bf8:	sarl %eax, $0x5<UINT8>
0x00404bfb:	addl %eax, $0x10<UINT8>
0x00404bfe:	pushl %eax
0x00404bff:	call 0x00407eec
0x00404c04:	popl %ecx
0x00404c05:	ret

0x00405d1f:	popl %ecx
0x00405d20:	popl %ecx
0x00405d21:	movl -4(%ebp), %ebx
0x00405d24:	pushl %esi
0x00405d25:	call 0x00409bf8
0x00409bf8:	pushl %esi
0x00409bf9:	movl %esi, 0x8(%esp)
0x00409bfd:	pushl %esi
0x00409bfe:	call 0x00409efd
0x00409c03:	pushl %eax
0x00409c04:	call 0x0040e9a9
0x0040e9a9:	movl %eax, 0x4(%esp)
0x0040e9ad:	cmpl %eax, $0xfffffffe<UINT8>
0x0040e9b0:	jne 0x0040e9c0
0x0040e9c0:	pushl %esi
0x0040e9c1:	xorl %esi, %esi
0x0040e9c3:	cmpl %eax, %esi
0x0040e9c5:	jl 8
0x0040e9c7:	cmpl %eax, 0x41b6ec
0x0040e9cd:	jb 0x0040e9eb
0x0040e9eb:	movl %ecx, %eax
0x0040e9ed:	andl %eax, $0x1f<UINT8>
0x0040e9f0:	imull %eax, %eax, $0x28<UINT8>
0x0040e9f3:	sarl %ecx, $0x5<UINT8>
0x0040e9f6:	movl %ecx, 0x41b700(,%ecx,4)
0x0040e9fd:	movzbl %eax, 0x4(%ecx,%eax)
0x0040ea02:	andl %eax, $0x40<UINT8>
0x0040ea05:	popl %esi
0x0040ea06:	ret

0x00409c09:	testl %eax, %eax
0x00409c0b:	popl %ecx
0x00409c0c:	popl %ecx
0x00409c0d:	je 123
0x00409c0f:	call 0x00404b0b
0x00409c14:	addl %eax, $0x20<UINT8>
0x00409c17:	cmpl %esi, %eax
0x00409c19:	jne 0x00409c1f
0x00409c1f:	call 0x00404b0b
0x00409c24:	addl %eax, $0x40<UINT8>
0x00409c27:	cmpl %esi, %eax
0x00409c29:	jne 95
0x00409c2b:	xorl %eax, %eax
0x00409c2d:	incl %eax
0x00409c2e:	incl 0x41aa44
0x00409c34:	testw 0xc(%esi), $0x10c<UINT16>
0x00409c3a:	jne 78
0x00409c3c:	pushl %ebx
0x00409c3d:	pushl %edi
0x00409c3e:	leal %edi, 0x41b294(,%eax,4)
0x00409c45:	cmpl (%edi), $0x0<UINT8>
0x00409c48:	movl %ebx, $0x1000<UINT32>
0x00409c4d:	jne 32
0x00409c4f:	pushl %ebx
0x00409c50:	call 0x00409f2a
0x00409c55:	testl %eax, %eax
0x00409c57:	popl %ecx
0x00409c58:	movl (%edi), %eax
0x00409c5a:	jne 0x00409c6f
0x00409c6f:	movl %edi, (%edi)
0x00409c71:	movl 0x8(%esi), %edi
0x00409c74:	movl (%esi), %edi
0x00409c76:	movl 0x18(%esi), %ebx
0x00409c79:	movl 0x4(%esi), %ebx
0x00409c7c:	orl 0xc(%esi), $0x1102<UINT32>
0x00409c83:	popl %edi
0x00409c84:	xorl %eax, %eax
0x00409c86:	popl %ebx
0x00409c87:	incl %eax
0x00409c88:	popl %esi
0x00409c89:	ret

0x00405d2a:	movl %edi, %eax
0x00405d2c:	pushl %esi
0x00405d2d:	pushl -28(%ebp)
0x00405d30:	pushl $0x1<UINT8>
0x00405d32:	pushl 0x8(%ebp)
0x00405d35:	call 0x00404d75
0x00404d75:	pushl %ebp
0x00404d76:	movl %ebp, %esp
0x00404d78:	pushl %ecx
0x00404d79:	pushl %ecx
0x00404d7a:	movl %eax, 0x8(%ebp)
0x00404d7d:	movl 0x8(%ebp), %eax
0x00404d80:	movl %eax, 0xc(%ebp)
0x00404d83:	imull %eax, 0x10(%ebp)
0x00404d87:	testl %eax, %eax
0x00404d89:	pushl %ebx
0x00404d8a:	movl -8(%ebp), %eax
0x00404d8d:	movl %ebx, %eax
0x00404d8f:	je 241
0x00404d95:	pushl %esi
0x00404d96:	movl %esi, 0x14(%ebp)
0x00404d99:	testw 0xc(%esi), $0x10c<UINT16>
0x00404d9f:	je 8
0x00404da1:	movl %ecx, 0x18(%esi)
0x00404da4:	movl -4(%ebp), %ecx
0x00404da7:	jmp 0x00404db0
0x00404db0:	pushl %edi
0x00404db1:	jmp 0x00404db6
0x00404db6:	movl %ecx, 0xc(%esi)
0x00404db9:	andl %ecx, $0x108<UINT32>
0x00404dbf:	je 48
0x00404dc1:	movl %edi, 0x4(%esi)
0x00404dc4:	testl %edi, %edi
0x00404dc6:	je 41
0x00404dc8:	jl 187
0x00404dce:	cmpl %ebx, %edi
0x00404dd0:	jae 2
0x00404dd2:	movl %edi, %ebx
0x00404dd4:	pushl %edi
0x00404dd5:	pushl 0x8(%ebp)
0x00404dd8:	pushl (%esi)
0x00404dda:	call 0x00404270
0x00404270:	pushl %ebp
0x00404271:	movl %ebp, %esp
0x00404273:	pushl %edi
0x00404274:	pushl %esi
0x00404275:	movl %esi, 0xc(%ebp)
0x00404278:	movl %ecx, 0x10(%ebp)
0x0040427b:	movl %edi, 0x8(%ebp)
0x0040427e:	movl %eax, %ecx
0x00404280:	movl %edx, %ecx
0x00404282:	addl %eax, %esi
0x00404284:	cmpl %edi, %esi
0x00404286:	jbe 8
0x00404288:	cmpl %edi, %eax
0x0040428a:	jb 420
0x00404290:	cmpl %ecx, $0x100<UINT32>
0x00404296:	jb 0x004042b7
0x004042b7:	testl %edi, $0x3<UINT32>
0x004042bd:	jne 21
0x004042bf:	shrl %ecx, $0x2<UINT8>
0x004042c2:	andl %edx, $0x3<UINT8>
0x004042c5:	cmpl %ecx, $0x8<UINT8>
0x004042c8:	jb 0x004042f4
0x004042f4:	jmp 0x004043db
0x004043db:	jmp 0x004043fc
0x004043fc:	movb %al, (%esi)
0x004043fe:	movb (%edi), %al
0x00404400:	movl %eax, 0x8(%ebp)
0x00404403:	popl %esi
0x00404404:	popl %edi
0x00404405:	leave
0x00404406:	ret

0x00404ddf:	subl 0x4(%esi), %edi
0x00404de2:	addl (%esi), %edi
0x00404de4:	addl %esp, $0xc<UINT8>
0x00404de7:	subl %ebx, %edi
0x00404de9:	addl 0x8(%ebp), %edi
0x00404dec:	jmp 0x00404e79
0x00404e79:	testl %ebx, %ebx
0x00404e7b:	jne -206
0x00404e81:	movl %eax, 0x10(%ebp)
0x00404e84:	popl %edi
0x00404e85:	popl %esi
0x00404e86:	popl %ebx
0x00404e87:	leave
0x00404e88:	ret

0x00405d3a:	movl -32(%ebp), %eax
0x00405d3d:	pushl %esi
0x00405d3e:	pushl %edi
0x00405d3f:	call 0x00409c8e
0x00409c8e:	cmpl 0x4(%esp), $0x0<UINT8>
0x00409c93:	je 39
0x00409c95:	pushl %esi
0x00409c96:	movl %esi, 0xc(%esp)
0x00409c9a:	testw 0xc(%esi), $0x1000<UINT16>
0x00409ca0:	je 25
0x00409ca2:	pushl %esi
0x00409ca3:	call 0x00405364
0x00405364:	pushl %ebx
0x00405365:	pushl %esi
0x00405366:	movl %esi, 0xc(%esp)
0x0040536a:	movl %eax, 0xc(%esi)
0x0040536d:	movl %ecx, %eax
0x0040536f:	andb %cl, $0x3<UINT8>
0x00405372:	xorl %ebx, %ebx
0x00405374:	cmpb %cl, $0x2<UINT8>
0x00405377:	jne 63
0x00405379:	testw %ax, $0x108<UINT16>
0x0040537d:	je 57
0x0040537f:	movl %eax, 0x8(%esi)
0x00405382:	pushl %edi
0x00405383:	movl %edi, (%esi)
0x00405385:	subl %edi, %eax
0x00405387:	testl %edi, %edi
0x00405389:	jle 44
0x0040538b:	pushl %edi
0x0040538c:	pushl %eax
0x0040538d:	pushl %esi
0x0040538e:	call 0x00409efd
0x00405393:	popl %ecx
0x00405394:	pushl %eax
0x00405395:	call 0x0040a83f
0x0040a83f:	pushl $0x10<UINT8>
0x0040a841:	pushl $0x417850<UINT32>
0x0040a846:	call 0x00408a1c
0x0040a84b:	movl %eax, 0x8(%ebp)
0x0040a84e:	cmpl %eax, $0xfffffffe<UINT8>
0x0040a851:	jne 0x0040a86e
0x0040a86e:	xorl %edi, %edi
0x0040a870:	cmpl %eax, %edi
0x0040a872:	jl 8
0x0040a874:	cmpl %eax, 0x41b6ec
0x0040a87a:	jb 0x0040a89d
0x0040a89d:	movl %ecx, %eax
0x0040a89f:	sarl %ecx, $0x5<UINT8>
0x0040a8a2:	leal %ebx, 0x41b700(,%ecx,4)
0x0040a8a9:	movl %esi, %eax
0x0040a8ab:	andl %esi, $0x1f<UINT8>
0x0040a8ae:	imull %esi, %esi, $0x28<UINT8>
0x0040a8b1:	movl %ecx, (%ebx)
0x0040a8b3:	movzbl %ecx, 0x4(%ecx,%esi)
0x0040a8b8:	andl %ecx, $0x1<UINT8>
0x0040a8bb:	je -65
0x0040a8bd:	pushl %eax
0x0040a8be:	call 0x0040f114
0x0040f114:	pushl $0xc<UINT8>
0x0040f116:	pushl $0x4179d0<UINT32>
0x0040f11b:	call 0x00408a1c
0x0040f120:	movl %edi, 0x8(%ebp)
0x0040f123:	movl %eax, %edi
0x0040f125:	sarl %eax, $0x5<UINT8>
0x0040f128:	movl %esi, %edi
0x0040f12a:	andl %esi, $0x1f<UINT8>
0x0040f12d:	imull %esi, %esi, $0x28<UINT8>
0x0040f130:	addl %esi, 0x41b700(,%eax,4)
0x0040f137:	movl -28(%ebp), $0x1<UINT32>
0x0040f13e:	xorl %ebx, %ebx
0x0040f140:	cmpl 0x8(%esi), %ebx
0x0040f143:	jne 0x0040f17b
0x0040f17b:	cmpl -28(%ebp), %ebx
0x0040f17e:	je 29
0x0040f180:	movl %eax, %edi
0x0040f182:	sarl %eax, $0x5<UINT8>
0x0040f185:	andl %edi, $0x1f<UINT8>
0x0040f188:	imull %edi, %edi, $0x28<UINT8>
0x0040f18b:	movl %eax, 0x41b700(,%eax,4)
0x0040f192:	leal %eax, 0xc(%eax,%edi)
0x0040f196:	pushl %eax
0x0040f197:	call EnterCriticalSection@KERNEL32.DLL
0x0040f19d:	movl %eax, -28(%ebp)
0x0040f1a0:	call 0x00408a61
0x0040f1a5:	ret

0x0040a8c3:	popl %ecx
0x0040a8c4:	movl -4(%ebp), %edi
0x0040a8c7:	movl %eax, (%ebx)
0x0040a8c9:	testb 0x4(%eax,%esi), $0x1<UINT8>
0x0040a8ce:	je 22
0x0040a8d0:	pushl 0x10(%ebp)
0x0040a8d3:	pushl 0xc(%ebp)
0x0040a8d6:	pushl 0x8(%ebp)
0x0040a8d9:	call 0x0040a279
0x0040a279:	pushl %ebp
0x0040a27a:	leal %ebp, -1304(%esp)
0x0040a281:	subl %esp, $0x594<UINT32>
0x0040a287:	movl %eax, 0x4190c0
0x0040a28c:	xorl %eax, %ebp
0x0040a28e:	movl 0x514(%ebp), %eax
0x0040a294:	movl %eax, 0x524(%ebp)
0x0040a29a:	pushl %esi
0x0040a29b:	xorl %esi, %esi
0x0040a29d:	cmpl 0x528(%ebp), %esi
0x0040a2a3:	movl -100(%ebp), %eax
0x0040a2a6:	movl -96(%ebp), %esi
0x0040a2a9:	movl -104(%ebp), %esi
0x0040a2ac:	jne 0x0040a2b5
0x0040a2b5:	cmpl %eax, %esi
0x0040a2b7:	jne 0x0040a2e0
0x0040a2e0:	movl %esi, 0x520(%ebp)
0x0040a2e6:	pushl %ebx
0x0040a2e7:	movl %ebx, %esi
0x0040a2e9:	andl %ebx, $0x1f<UINT8>
0x0040a2ec:	imull %ebx, %ebx, $0x28<UINT8>
0x0040a2ef:	movl %eax, %esi
0x0040a2f1:	sarl %eax, $0x5<UINT8>
0x0040a2f4:	pushl %edi
0x0040a2f5:	leal %edi, 0x41b700(,%eax,4)
0x0040a2fc:	movl %eax, (%edi)
0x0040a2fe:	addl %eax, %ebx
0x0040a300:	movb %cl, 0x24(%eax)
0x0040a303:	addb %cl, %cl
0x0040a305:	sarb %cl
0x0040a307:	cmpb %cl, $0x2<UINT8>
0x0040a30a:	movl -112(%ebp), %edi
0x0040a30d:	movb -85(%ebp), %cl
0x0040a310:	je 5
0x0040a312:	cmpb %cl, $0x1<UINT8>
0x0040a315:	jne 0x0040a34a
0x0040a34a:	testb 0x4(%eax), $0x20<UINT8>
0x0040a34e:	je 0x0040a35f
0x0040a35f:	pushl %esi
0x0040a360:	call 0x0040e9a9
0x0040a365:	testl %eax, %eax
0x0040a367:	popl %ecx
0x0040a368:	je 502
0x0040a36e:	movl %eax, (%edi)
0x0040a370:	testb 0x4(%ebx,%eax), $0xffffff80<UINT8>
0x0040a375:	je 489
0x0040a37b:	call 0x004073c8
0x0040a380:	movl %eax, 0x6c(%eax)
0x0040a383:	xorl %ecx, %ecx
0x0040a385:	cmpl 0x14(%eax), %ecx
0x0040a388:	leal %eax, -124(%ebp)
0x0040a38b:	sete %cl
0x0040a38e:	pushl %eax
0x0040a38f:	movl %eax, (%edi)
0x0040a391:	pushl (%ebx,%eax)
0x0040a394:	movl %esi, %ecx
0x0040a396:	call GetConsoleMode@KERNEL32.DLL
GetConsoleMode@KERNEL32.DLL: API Node	
0x0040a39c:	testl %eax, %eax
0x0040a39e:	je 0x0040a564
0x0040a564:	movl %eax, (%edi)
0x0040a566:	addl %eax, %ebx
0x0040a568:	testb 0x4(%eax), $0xffffff80<UINT8>
0x0040a56c:	je 549
0x0040a572:	movl %eax, -100(%ebp)
0x0040a575:	xorl %esi, %esi
0x0040a577:	cmpb -85(%ebp), $0x0<UINT8>
0x0040a57b:	movl -84(%ebp), %esi
0x0040a57e:	jne 145
0x0040a584:	cmpl 0x528(%ebp), %esi
0x0040a58a:	movl -80(%ebp), %eax
0x0040a58d:	jbe 613
0x0040a593:	movl %ecx, -80(%ebp)
0x0040a596:	andl -92(%ebp), $0x0<UINT8>
0x0040a59a:	subl %ecx, -100(%ebp)
0x0040a59d:	leal %eax, -76(%ebp)
0x0040a5a0:	cmpl %ecx, 0x528(%ebp)
0x0040a5a6:	jae 0x0040a5cf
0x0040a5a8:	movl %edx, -80(%ebp)
0x0040a5ab:	incl -80(%ebp)
0x0040a5ae:	movb %dl, (%edx)
0x0040a5b0:	incl %ecx
0x0040a5b1:	cmpb %dl, $0xa<UINT8>
0x0040a5b4:	jne 10
0x0040a5b6:	incl -104(%ebp)
0x0040a5b9:	movb (%eax), $0xd<UINT8>
0x0040a5bc:	incl %eax
0x0040a5bd:	incl -92(%ebp)
0x0040a5c0:	movb (%eax), %dl
0x0040a5c2:	incl %eax
0x0040a5c3:	incl -92(%ebp)
0x0040a5c6:	cmpl -92(%ebp), $0x400<UINT32>
0x0040a5cd:	jb 0x0040a5a0
0x0040a5cf:	movl %esi, %eax
0x0040a5d1:	leal %eax, -76(%ebp)
0x0040a5d4:	subl %esi, %eax
0x0040a5d6:	pushl $0x0<UINT8>
0x0040a5d8:	leal %eax, -108(%ebp)
0x0040a5db:	pushl %eax
0x0040a5dc:	pushl %esi
0x0040a5dd:	leal %eax, -76(%ebp)
0x0040a5e0:	pushl %eax
0x0040a5e1:	movl %eax, (%edi)
0x0040a5e3:	pushl (%ebx,%eax)
0x0040a5e6:	call WriteFile@KERNEL32.DLL
WriteFile@KERNEL32.DLL: API Node	
0x0040a5ec:	testl %eax, %eax
0x0040a5ee:	je 458
0x0040a5f4:	movl %eax, -108(%ebp)
0x0040a5f7:	addl -96(%ebp), %eax
0x0040a5fa:	cmpl %eax, %esi
0x0040a5fc:	jl 453
0x0040a602:	movl %eax, -80(%ebp)
0x0040a605:	subl %eax, -100(%ebp)
0x0040a608:	cmpl %eax, 0x528(%ebp)
0x0040a60e:	jb -125
0x0040a610:	jmp 0x0040a7c7
0x0040a7c7:	movl %eax, -96(%ebp)
0x0040a7ca:	testl %eax, %eax
0x0040a7cc:	jne 0x0040a824
0x0040a824:	subl %eax, -104(%ebp)
0x0040a827:	popl %edi
0x0040a828:	popl %ebx
0x0040a829:	movl %ecx, 0x514(%ebp)
0x0040a82f:	xorl %ecx, %ebp
0x0040a831:	popl %esi
0x0040a832:	call 0x004046de
0x0040a837:	addl %ebp, $0x518<UINT32>
0x0040a83d:	leave
0x0040a83e:	ret

0x0040a8de:	addl %esp, $0xc<UINT8>
0x0040a8e1:	movl -28(%ebp), %eax
0x0040a8e4:	jmp 0x0040a8fc
0x0040a8fc:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040a903:	call 0x0040a911
0x0040a911:	pushl 0x8(%ebp)
0x0040a914:	call 0x0040f1b4
0x0040f1b4:	movl %eax, 0x4(%esp)
0x0040f1b8:	movl %ecx, %eax
0x0040f1ba:	andl %eax, $0x1f<UINT8>
0x0040f1bd:	imull %eax, %eax, $0x28<UINT8>
0x0040f1c0:	sarl %ecx, $0x5<UINT8>
0x0040f1c3:	movl %ecx, 0x41b700(,%ecx,4)
0x0040f1ca:	leal %eax, 0xc(%ecx,%eax)
0x0040f1ce:	pushl %eax
0x0040f1cf:	call LeaveCriticalSection@KERNEL32.DLL
0x0040f1d5:	ret

0x0040a919:	popl %ecx
0x0040a91a:	ret

0x0040a908:	movl %eax, -28(%ebp)
0x0040a90b:	call 0x00408a61
0x0040a910:	ret

0x0040539a:	addl %esp, $0xc<UINT8>
0x0040539d:	cmpl %eax, %edi
0x0040539f:	jne 0x004053b0
0x004053b0:	orl 0xc(%esi), $0x20<UINT8>
0x004053b4:	orl %ebx, $0xffffffff<UINT8>
0x004053b7:	popl %edi
0x004053b8:	movl %eax, 0x8(%esi)
0x004053bb:	andl 0x4(%esi), $0x0<UINT8>
0x004053bf:	movl (%esi), %eax
0x004053c1:	popl %esi
0x004053c2:	movl %eax, %ebx
0x004053c4:	popl %ebx
0x004053c5:	ret

0x00409ca8:	andl 0xc(%esi), $0xffffeeff<UINT32>
0x00409caf:	andl 0x18(%esi), $0x0<UINT8>
0x00409cb3:	andl (%esi), $0x0<UINT8>
0x00409cb6:	andl 0x8(%esi), $0x0<UINT8>
0x00409cba:	popl %ecx
0x00409cbb:	popl %esi
0x00409cbc:	ret

0x00405d44:	addl %esp, $0x1c<UINT8>
0x00405d47:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00405d4e:	call 0x00405d68
0x00405d68:	pushl %esi
0x00405d69:	call 0x00404c34
0x00404c34:	movl %eax, 0x4(%esp)
0x00404c38:	movl %ecx, $0x4190c8<UINT32>
0x00404c3d:	cmpl %eax, %ecx
0x00404c3f:	jb 23
0x00404c41:	cmpl %eax, $0x419328<UINT32>
0x00404c46:	ja 16
0x00404c48:	subl %eax, %ecx
0x00404c4a:	sarl %eax, $0x5<UINT8>
0x00404c4d:	addl %eax, $0x10<UINT8>
0x00404c50:	pushl %eax
0x00404c51:	call 0x00407e14
0x00404c56:	popl %ecx
0x00404c57:	ret

0x00405d6e:	popl %ecx
0x00405d6f:	ret

0x00405d53:	xorl %eax, %eax
0x00405d55:	movl %ecx, -28(%ebp)
0x00405d58:	cmpl -32(%ebp), %ecx
0x00405d5b:	sete %al
0x00405d5e:	decl %eax
0x00405d5f:	call 0x00408a61
0x00405d64:	ret

0x00402b46:	call 0x00404b0b
0x00402b4b:	addl %eax, $0x40<UINT8>
0x00402b4e:	pushl %eax
0x00402b4f:	pushl %edi
0x00402b50:	call 0x00405c2e
0x00405c48:	call 0x00407c38
0x00405c4d:	movl (%eax), $0x16<UINT32>
0x00405c53:	pushl %ebx
0x00405c54:	pushl %ebx
0x00405c55:	pushl %ebx
0x00405c56:	pushl %ebx
0x00405c57:	pushl %ebx
0x00405c58:	call 0x00407bd9
0x00407bd9:	pushl %ebp
0x00407bda:	movl %ebp, %esp
0x00407bdc:	pushl 0x41aaf4
0x00407be2:	call 0x0040718a
0x00407be7:	testl %eax, %eax
0x00407be9:	popl %ecx
0x00407bea:	je 0x00407bef
0x00407bef:	pushl $0x2<UINT8>
0x00407bf1:	call 0x0040e1b9
0x0040e1b9:	andl 0x41b6e8, $0x0<UINT8>
0x0040e1c0:	ret

0x00407bf6:	popl %ecx
0x00407bf7:	popl %ebp
0x00407bf8:	jmp 0x00407add
0x00407add:	pushl %ebp
0x00407ade:	leal %ebp, -680(%esp)
0x00407ae5:	subl %esp, $0x328<UINT32>
0x00407aeb:	movl %eax, 0x4190c0
0x00407af0:	xorl %eax, %ebp
0x00407af2:	movl 0x2a4(%ebp), %eax
0x00407af8:	pushl %esi
0x00407af9:	movl 0x88(%ebp), %eax
0x00407aff:	movl 0x84(%ebp), %ecx
0x00407b05:	movl 0x80(%ebp), %edx
0x00407b0b:	movl 0x7c(%ebp), %ebx
0x00407b0e:	movl 0x78(%ebp), %esi
0x00407b11:	movl 0x74(%ebp), %edi
0x00407b14:	movw 0xa0(%ebp), %ss
0x00407b1b:	movw 0x94(%ebp), %cs
0x00407b22:	movw 0x70(%ebp), %ds
0x00407b26:	movw 0x6c(%ebp), %es
0x00407b2a:	movw 0x68(%ebp), %fs
0x00407b2e:	movw 0x64(%ebp), %gs
0x00407b32:	pushfl
0x00407b33:	popl 0x98(%ebp)
0x00407b39:	movl %esi, 0x2ac(%ebp)
0x00407b3f:	leal %eax, 0x2ac(%ebp)
0x00407b45:	movl 0x9c(%ebp), %eax
0x00407b4b:	movl -40(%ebp), $0x10001<UINT32>
0x00407b52:	movl 0x90(%ebp), %esi
0x00407b58:	movl %eax, -4(%eax)
0x00407b5b:	pushl $0x50<UINT8>
0x00407b5d:	movl 0x8c(%ebp), %eax
0x00407b63:	leal %eax, -128(%ebp)
0x00407b66:	pushl $0x0<UINT8>
0x00407b68:	pushl %eax
0x00407b69:	call 0x004040e0
0x00407b6e:	leal %eax, -128(%ebp)
0x00407b71:	movl -48(%ebp), %eax
0x00407b74:	leal %eax, -40(%ebp)
0x00407b77:	addl %esp, $0xc<UINT8>
0x00407b7a:	movl -128(%ebp), $0xc000000d<UINT32>
0x00407b81:	movl -116(%ebp), %esi
0x00407b84:	movl -44(%ebp), %eax
0x00407b87:	call IsDebuggerPresent@KERNEL32.DLL
IsDebuggerPresent@KERNEL32.DLL: API Node	
0x00407b8d:	pushl $0x0<UINT8>
0x00407b8f:	movl %esi, %eax
0x00407b91:	call SetUnhandledExceptionFilter@KERNEL32.DLL
SetUnhandledExceptionFilter@KERNEL32.DLL: API Node	
0x00407b97:	leal %eax, -48(%ebp)
0x00407b9a:	pushl %eax
0x00407b9b:	call UnhandledExceptionFilter@KERNEL32.DLL
UnhandledExceptionFilter@KERNEL32.DLL: API Node	
0x00407ba1:	testl %eax, %eax
0x00407ba3:	jne 0x00407bb1
0x00407bb1:	pushl $0xc000000d<UINT32>
0x00407bb6:	call GetCurrentProcess@KERNEL32.DLL
GetCurrentProcess@KERNEL32.DLL: API Node	
0x00407bbc:	pushl %eax
0x00407bbd:	call TerminateProcess@KERNEL32.DLL
TerminateProcess@KERNEL32.DLL: API Node	
0x00407bc3:	movl %ecx, 0x2a4(%ebp)
0x004041f6:	xorl %eax, %eax
0x004041f8:	incl %eax
