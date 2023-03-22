0x00423610:	pusha
0x00423611:	movl %esi, $0x417000<UINT32>
0x00423616:	leal %edi, -90112(%esi)
0x0042361c:	pushl %edi
0x0042361d:	jmp 0x0042362a
0x0042362a:	movl %ebx, (%esi)
0x0042362c:	subl %esi, $0xfffffffc<UINT8>
0x0042362f:	adcl %ebx, %ebx
0x00423631:	jb 0x00423620
0x00423620:	movb %al, (%esi)
0x00423622:	incl %esi
0x00423623:	movb (%edi), %al
0x00423625:	incl %edi
0x00423626:	addl %ebx, %ebx
0x00423628:	jne 0x00423631
0x00423633:	movl %eax, $0x1<UINT32>
0x00423638:	addl %ebx, %ebx
0x0042363a:	jne 0x00423643
0x00423643:	adcl %eax, %eax
0x00423645:	addl %ebx, %ebx
0x00423647:	jae 0x00423638
0x00423649:	jne 0x00423654
0x00423654:	xorl %ecx, %ecx
0x00423656:	subl %eax, $0x3<UINT8>
0x00423659:	jb 0x00423668
0x0042365b:	shll %eax, $0x8<UINT8>
0x0042365e:	movb %al, (%esi)
0x00423660:	incl %esi
0x00423661:	xorl %eax, $0xffffffff<UINT8>
0x00423664:	je 0x004236da
0x00423666:	movl %ebp, %eax
0x00423668:	addl %ebx, %ebx
0x0042366a:	jne 0x00423673
0x00423673:	adcl %ecx, %ecx
0x00423675:	addl %ebx, %ebx
0x00423677:	jne 0x00423680
0x00423679:	movl %ebx, (%esi)
0x0042367b:	subl %esi, $0xfffffffc<UINT8>
0x0042367e:	adcl %ebx, %ebx
0x00423680:	adcl %ecx, %ecx
0x00423682:	jne 0x004236a4
0x004236a4:	cmpl %ebp, $0xfffff300<UINT32>
0x004236aa:	adcl %ecx, $0x1<UINT8>
0x004236ad:	leal %edx, (%edi,%ebp)
0x004236b0:	cmpl %ebp, $0xfffffffc<UINT8>
0x004236b3:	jbe 0x004236c4
0x004236c4:	movl %eax, (%edx)
0x004236c6:	addl %edx, $0x4<UINT8>
0x004236c9:	movl (%edi), %eax
0x004236cb:	addl %edi, $0x4<UINT8>
0x004236ce:	subl %ecx, $0x4<UINT8>
0x004236d1:	ja 0x004236c4
0x004236d3:	addl %edi, %ecx
0x004236d5:	jmp 0x00423626
0x00423684:	incl %ecx
0x00423685:	addl %ebx, %ebx
0x00423687:	jne 0x00423690
0x00423690:	adcl %ecx, %ecx
0x00423692:	addl %ebx, %ebx
0x00423694:	jae 0x00423685
0x00423696:	jne 0x004236a1
0x004236a1:	addl %ecx, $0x2<UINT8>
0x004236b5:	movb %al, (%edx)
0x004236b7:	incl %edx
0x004236b8:	movb (%edi), %al
0x004236ba:	incl %edi
0x004236bb:	decl %ecx
0x004236bc:	jne 0x004236b5
0x004236be:	jmp 0x00423626
0x0042363c:	movl %ebx, (%esi)
0x0042363e:	subl %esi, $0xfffffffc<UINT8>
0x00423641:	adcl %ebx, %ebx
0x0042364b:	movl %ebx, (%esi)
0x0042364d:	subl %esi, $0xfffffffc<UINT8>
0x00423650:	adcl %ebx, %ebx
0x00423652:	jae 0x00423638
0x00423698:	movl %ebx, (%esi)
0x0042369a:	subl %esi, $0xfffffffc<UINT8>
0x0042369d:	adcl %ebx, %ebx
0x0042369f:	jae 0x00423685
0x0042366c:	movl %ebx, (%esi)
0x0042366e:	subl %esi, $0xfffffffc<UINT8>
0x00423671:	adcl %ebx, %ebx
0x00423689:	movl %ebx, (%esi)
0x0042368b:	subl %esi, $0xfffffffc<UINT8>
0x0042368e:	adcl %ebx, %ebx
0x004236da:	popl %esi
0x004236db:	movl %edi, %esi
0x004236dd:	movl %ecx, $0x597<UINT32>
0x004236e2:	movb %al, (%edi)
0x004236e4:	incl %edi
0x004236e5:	subb %al, $0xffffffe8<UINT8>
0x004236e7:	cmpb %al, $0x1<UINT8>
0x004236e9:	ja 0x004236e2
0x004236eb:	cmpb (%edi), $0x5<UINT8>
0x004236ee:	jne 0x004236e2
0x004236f0:	movl %eax, (%edi)
0x004236f2:	movb %bl, 0x4(%edi)
0x004236f5:	shrw %ax, $0x8<UINT8>
0x004236f9:	roll %eax, $0x10<UINT8>
0x004236fc:	xchgb %ah, %al
0x004236fe:	subl %eax, %edi
0x00423700:	subb %bl, $0xffffffe8<UINT8>
0x00423703:	addl %eax, %esi
0x00423705:	movl (%edi), %eax
0x00423707:	addl %edi, $0x5<UINT8>
0x0042370a:	movb %al, %bl
0x0042370c:	loop 0x004236e7
0x0042370e:	leal %edi, 0x21000(%esi)
0x00423714:	movl %eax, (%edi)
0x00423716:	orl %eax, %eax
0x00423718:	je 0x00423756
0x0042371a:	movl %ebx, 0x4(%edi)
0x0042371d:	leal %eax, 0x23564(%eax,%esi)
0x00423724:	addl %ebx, %esi
0x00423726:	pushl %eax
0x00423727:	addl %edi, $0x8<UINT8>
0x0042372a:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x00423730:	xchgl %ebp, %eax
0x00423731:	movb %al, (%edi)
0x00423733:	incl %edi
0x00423734:	orb %al, %al
0x00423736:	je 0x00423714
0x00423738:	movl %ecx, %edi
0x0042373a:	pushl %edi
0x0042373b:	decl %eax
0x0042373c:	repn scasb %al, %es:(%edi)
0x0042373e:	pushl %ebp
0x0042373f:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00423745:	orl %eax, %eax
0x00423747:	je 7
0x00423749:	movl (%ebx), %eax
0x0042374b:	addl %ebx, $0x4<UINT8>
0x0042374e:	jmp 0x00423731
GetProcAddress@KERNEL32.DLL: API Node	
0x00423756:	movl %ebp, 0x23614(%esi)
0x0042375c:	leal %edi, -4096(%esi)
0x00423762:	movl %ebx, $0x1000<UINT32>
0x00423767:	pushl %eax
0x00423768:	pushl %esp
0x00423769:	pushl $0x4<UINT8>
0x0042376b:	pushl %ebx
0x0042376c:	pushl %edi
0x0042376d:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0042376f:	leal %eax, 0x217(%edi)
0x00423775:	andb (%eax), $0x7f<UINT8>
0x00423778:	andb 0x28(%eax), $0x7f<UINT8>
0x0042377c:	popl %eax
0x0042377d:	pushl %eax
0x0042377e:	pushl %esp
0x0042377f:	pushl %eax
0x00423780:	pushl %ebx
0x00423781:	pushl %edi
0x00423782:	call VirtualProtect@kernel32.dll
0x00423784:	popl %eax
0x00423785:	popa
0x00423786:	leal %eax, -128(%esp)
0x0042378a:	pushl $0x0<UINT8>
0x0042378c:	cmpl %esp, %eax
0x0042378e:	jne 0x0042378a
0x00423790:	subl %esp, $0xffffff80<UINT8>
0x00423793:	jmp 0x00404a16
0x00404a16:	call 0x0040a24b
0x0040a24b:	pushl %ebp
0x0040a24c:	movl %ebp, %esp
0x0040a24e:	subl %esp, $0x14<UINT8>
0x0040a251:	andl -12(%ebp), $0x0<UINT8>
0x0040a255:	andl -8(%ebp), $0x0<UINT8>
0x0040a259:	movl %eax, 0x41d350
0x0040a25e:	pushl %esi
0x0040a25f:	pushl %edi
0x0040a260:	movl %edi, $0xbb40e64e<UINT32>
0x0040a265:	movl %esi, $0xffff0000<UINT32>
0x0040a26a:	cmpl %eax, %edi
0x0040a26c:	je 0x0040a27b
0x0040a27b:	leal %eax, -12(%ebp)
0x0040a27e:	pushl %eax
0x0040a27f:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040a285:	movl %eax, -8(%ebp)
0x0040a288:	xorl %eax, -12(%ebp)
0x0040a28b:	movl -4(%ebp), %eax
0x0040a28e:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040a294:	xorl -4(%ebp), %eax
0x0040a297:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040a29d:	xorl -4(%ebp), %eax
0x0040a2a0:	leal %eax, -20(%ebp)
0x0040a2a3:	pushl %eax
0x0040a2a4:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040a2aa:	movl %ecx, -16(%ebp)
0x0040a2ad:	leal %eax, -4(%ebp)
0x0040a2b0:	xorl %ecx, -20(%ebp)
0x0040a2b3:	xorl %ecx, -4(%ebp)
0x0040a2b6:	xorl %ecx, %eax
0x0040a2b8:	cmpl %ecx, %edi
0x0040a2ba:	jne 0x0040a2c3
0x0040a2c3:	testl %esi, %ecx
0x0040a2c5:	jne 0x0040a2d3
0x0040a2d3:	movl 0x41d350, %ecx
0x0040a2d9:	notl %ecx
0x0040a2db:	movl 0x41d354, %ecx
0x0040a2e1:	popl %edi
0x0040a2e2:	popl %esi
0x0040a2e3:	movl %esp, %ebp
0x0040a2e5:	popl %ebp
0x0040a2e6:	ret

0x00404a1b:	jmp 0x0040489b
0x0040489b:	pushl $0x14<UINT8>
0x0040489d:	pushl $0x41bd28<UINT32>
0x004048a2:	call 0x00405760
0x00405760:	pushl $0x4057c0<UINT32>
0x00405765:	pushl %fs:0
0x0040576c:	movl %eax, 0x10(%esp)
0x00405770:	movl 0x10(%esp), %ebp
0x00405774:	leal %ebp, 0x10(%esp)
0x00405778:	subl %esp, %eax
0x0040577a:	pushl %ebx
0x0040577b:	pushl %esi
0x0040577c:	pushl %edi
0x0040577d:	movl %eax, 0x41d350
0x00405782:	xorl -4(%ebp), %eax
0x00405785:	xorl %eax, %ebp
0x00405787:	pushl %eax
0x00405788:	movl -24(%ebp), %esp
0x0040578b:	pushl -8(%ebp)
0x0040578e:	movl %eax, -4(%ebp)
0x00405791:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00405798:	movl -8(%ebp), %eax
0x0040579b:	leal %eax, -16(%ebp)
0x0040579e:	movl %fs:0, %eax
0x004057a4:	ret

0x004048a7:	pushl $0x1<UINT8>
0x004048a9:	call 0x0040a1fe
0x0040a1fe:	pushl %ebp
0x0040a1ff:	movl %ebp, %esp
0x0040a201:	movl %eax, 0x8(%ebp)
0x0040a204:	movl 0x41e880, %eax
0x0040a209:	popl %ebp
0x0040a20a:	ret

0x004048ae:	popl %ecx
0x004048af:	movl %eax, $0x5a4d<UINT32>
0x004048b4:	cmpw 0x400000, %ax
0x004048bb:	je 0x004048c1
0x004048c1:	movl %eax, 0x40003c
0x004048c6:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x004048d0:	jne -21
0x004048d2:	movl %ecx, $0x10b<UINT32>
0x004048d7:	cmpw 0x400018(%eax), %cx
0x004048de:	jne -35
0x004048e0:	xorl %ebx, %ebx
0x004048e2:	cmpl 0x400074(%eax), $0xe<UINT8>
0x004048e9:	jbe 9
0x004048eb:	cmpl 0x4000e8(%eax), %ebx
0x004048f1:	setne %bl
0x004048f4:	movl -28(%ebp), %ebx
0x004048f7:	call 0x00408539
0x00408539:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x0040853f:	xorl %ecx, %ecx
0x00408541:	movl 0x41eed8, %eax
0x00408546:	testl %eax, %eax
0x00408548:	setne %cl
0x0040854b:	movl %eax, %ecx
0x0040854d:	ret

0x004048fc:	testl %eax, %eax
0x004048fe:	jne 0x00404908
0x00404908:	call 0x00408421
0x00408421:	call 0x00403876
0x00403876:	pushl %esi
0x00403877:	pushl $0x0<UINT8>
0x00403879:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x0040387f:	movl %esi, %eax
0x00403881:	pushl %esi
0x00403882:	call 0x0040852c
0x0040852c:	pushl %ebp
0x0040852d:	movl %ebp, %esp
0x0040852f:	movl %eax, 0x8(%ebp)
0x00408532:	movl 0x41eed0, %eax
0x00408537:	popl %ebp
0x00408538:	ret

0x00403887:	pushl %esi
0x00403888:	call 0x00405a79
0x00405a79:	pushl %ebp
0x00405a7a:	movl %ebp, %esp
0x00405a7c:	movl %eax, 0x8(%ebp)
0x00405a7f:	movl 0x41e76c, %eax
0x00405a84:	popl %ebp
0x00405a85:	ret

0x0040388d:	pushl %esi
0x0040388e:	call 0x00408875
0x00408875:	pushl %ebp
0x00408876:	movl %ebp, %esp
0x00408878:	movl %eax, 0x8(%ebp)
0x0040887b:	movl 0x41eee0, %eax
0x00408880:	popl %ebp
0x00408881:	ret

0x00403893:	pushl %esi
0x00403894:	call 0x0040888f
0x0040888f:	pushl %ebp
0x00408890:	movl %ebp, %esp
0x00408892:	movl %eax, 0x8(%ebp)
0x00408895:	movl 0x41eee4, %eax
0x0040889a:	movl 0x41eee8, %eax
0x0040889f:	movl 0x41eeec, %eax
0x004088a4:	movl 0x41eef0, %eax
0x004088a9:	popl %ebp
0x004088aa:	ret

0x00403899:	pushl %esi
0x0040389a:	call 0x00408864
0x00408864:	pushl $0x408830<UINT32>
0x00408869:	call EncodePointer@KERNEL32.DLL
0x0040886f:	movl 0x41eedc, %eax
0x00408874:	ret

0x0040389f:	pushl %esi
0x004038a0:	call 0x00408aa0
0x00408aa0:	pushl %ebp
0x00408aa1:	movl %ebp, %esp
0x00408aa3:	movl %eax, 0x8(%ebp)
0x00408aa6:	movl 0x41eef8, %eax
0x00408aab:	popl %ebp
0x00408aac:	ret

0x004038a5:	addl %esp, $0x18<UINT8>
0x004038a8:	popl %esi
0x004038a9:	jmp 0x004071cb
0x004071cb:	pushl %esi
0x004071cc:	pushl %edi
0x004071cd:	pushl $0x417f70<UINT32>
0x004071d2:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x004071d8:	movl %esi, 0x41109c
0x004071de:	movl %edi, %eax
0x004071e0:	pushl $0x417f8c<UINT32>
0x004071e5:	pushl %edi
0x004071e6:	call GetProcAddress@KERNEL32.DLL
0x004071e8:	xorl %eax, 0x41d350
0x004071ee:	pushl $0x417f98<UINT32>
0x004071f3:	pushl %edi
0x004071f4:	movl 0x41f160, %eax
0x004071f9:	call GetProcAddress@KERNEL32.DLL
0x004071fb:	xorl %eax, 0x41d350
0x00407201:	pushl $0x417fa0<UINT32>
0x00407206:	pushl %edi
0x00407207:	movl 0x41f164, %eax
0x0040720c:	call GetProcAddress@KERNEL32.DLL
0x0040720e:	xorl %eax, 0x41d350
0x00407214:	pushl $0x417fac<UINT32>
0x00407219:	pushl %edi
0x0040721a:	movl 0x41f168, %eax
0x0040721f:	call GetProcAddress@KERNEL32.DLL
0x00407221:	xorl %eax, 0x41d350
0x00407227:	pushl $0x417fb8<UINT32>
0x0040722c:	pushl %edi
0x0040722d:	movl 0x41f16c, %eax
0x00407232:	call GetProcAddress@KERNEL32.DLL
0x00407234:	xorl %eax, 0x41d350
0x0040723a:	pushl $0x417fd4<UINT32>
0x0040723f:	pushl %edi
0x00407240:	movl 0x41f170, %eax
0x00407245:	call GetProcAddress@KERNEL32.DLL
0x00407247:	xorl %eax, 0x41d350
0x0040724d:	pushl $0x417fe4<UINT32>
0x00407252:	pushl %edi
0x00407253:	movl 0x41f174, %eax
0x00407258:	call GetProcAddress@KERNEL32.DLL
0x0040725a:	xorl %eax, 0x41d350
0x00407260:	pushl $0x417ff8<UINT32>
0x00407265:	pushl %edi
0x00407266:	movl 0x41f178, %eax
0x0040726b:	call GetProcAddress@KERNEL32.DLL
0x0040726d:	xorl %eax, 0x41d350
0x00407273:	pushl $0x418010<UINT32>
0x00407278:	pushl %edi
0x00407279:	movl 0x41f17c, %eax
0x0040727e:	call GetProcAddress@KERNEL32.DLL
0x00407280:	xorl %eax, 0x41d350
0x00407286:	pushl $0x418028<UINT32>
0x0040728b:	pushl %edi
0x0040728c:	movl 0x41f180, %eax
0x00407291:	call GetProcAddress@KERNEL32.DLL
0x00407293:	xorl %eax, 0x41d350
0x00407299:	pushl $0x41803c<UINT32>
0x0040729e:	pushl %edi
0x0040729f:	movl 0x41f184, %eax
0x004072a4:	call GetProcAddress@KERNEL32.DLL
0x004072a6:	xorl %eax, 0x41d350
0x004072ac:	pushl $0x41805c<UINT32>
0x004072b1:	pushl %edi
0x004072b2:	movl 0x41f188, %eax
0x004072b7:	call GetProcAddress@KERNEL32.DLL
0x004072b9:	xorl %eax, 0x41d350
0x004072bf:	pushl $0x418074<UINT32>
0x004072c4:	pushl %edi
0x004072c5:	movl 0x41f18c, %eax
0x004072ca:	call GetProcAddress@KERNEL32.DLL
0x004072cc:	xorl %eax, 0x41d350
0x004072d2:	pushl $0x41808c<UINT32>
0x004072d7:	pushl %edi
0x004072d8:	movl 0x41f190, %eax
0x004072dd:	call GetProcAddress@KERNEL32.DLL
0x004072df:	xorl %eax, 0x41d350
0x004072e5:	pushl $0x4180a0<UINT32>
0x004072ea:	pushl %edi
0x004072eb:	movl 0x41f194, %eax
0x004072f0:	call GetProcAddress@KERNEL32.DLL
0x004072f2:	xorl %eax, 0x41d350
0x004072f8:	movl 0x41f198, %eax
0x004072fd:	pushl $0x4180b4<UINT32>
0x00407302:	pushl %edi
0x00407303:	call GetProcAddress@KERNEL32.DLL
0x00407305:	xorl %eax, 0x41d350
0x0040730b:	pushl $0x4180d0<UINT32>
0x00407310:	pushl %edi
0x00407311:	movl 0x41f19c, %eax
0x00407316:	call GetProcAddress@KERNEL32.DLL
0x00407318:	xorl %eax, 0x41d350
0x0040731e:	pushl $0x4180f0<UINT32>
0x00407323:	pushl %edi
0x00407324:	movl 0x41f1a0, %eax
0x00407329:	call GetProcAddress@KERNEL32.DLL
0x0040732b:	xorl %eax, 0x41d350
0x00407331:	pushl $0x41810c<UINT32>
0x00407336:	pushl %edi
0x00407337:	movl 0x41f1a4, %eax
0x0040733c:	call GetProcAddress@KERNEL32.DLL
0x0040733e:	xorl %eax, 0x41d350
0x00407344:	pushl $0x41812c<UINT32>
0x00407349:	pushl %edi
0x0040734a:	movl 0x41f1a8, %eax
0x0040734f:	call GetProcAddress@KERNEL32.DLL
0x00407351:	xorl %eax, 0x41d350
0x00407357:	pushl $0x418140<UINT32>
0x0040735c:	pushl %edi
0x0040735d:	movl 0x41f1ac, %eax
0x00407362:	call GetProcAddress@KERNEL32.DLL
0x00407364:	xorl %eax, 0x41d350
0x0040736a:	pushl $0x41815c<UINT32>
0x0040736f:	pushl %edi
0x00407370:	movl 0x41f1b0, %eax
0x00407375:	call GetProcAddress@KERNEL32.DLL
0x00407377:	xorl %eax, 0x41d350
0x0040737d:	pushl $0x418170<UINT32>
0x00407382:	pushl %edi
0x00407383:	movl 0x41f1b8, %eax
0x00407388:	call GetProcAddress@KERNEL32.DLL
0x0040738a:	xorl %eax, 0x41d350
0x00407390:	pushl $0x418180<UINT32>
0x00407395:	pushl %edi
0x00407396:	movl 0x41f1b4, %eax
0x0040739b:	call GetProcAddress@KERNEL32.DLL
0x0040739d:	xorl %eax, 0x41d350
0x004073a3:	pushl $0x418190<UINT32>
0x004073a8:	pushl %edi
0x004073a9:	movl 0x41f1bc, %eax
0x004073ae:	call GetProcAddress@KERNEL32.DLL
0x004073b0:	xorl %eax, 0x41d350
0x004073b6:	pushl $0x4181a0<UINT32>
0x004073bb:	pushl %edi
0x004073bc:	movl 0x41f1c0, %eax
0x004073c1:	call GetProcAddress@KERNEL32.DLL
0x004073c3:	xorl %eax, 0x41d350
0x004073c9:	pushl $0x4181b0<UINT32>
0x004073ce:	pushl %edi
0x004073cf:	movl 0x41f1c4, %eax
0x004073d4:	call GetProcAddress@KERNEL32.DLL
0x004073d6:	xorl %eax, 0x41d350
0x004073dc:	pushl $0x4181cc<UINT32>
0x004073e1:	pushl %edi
0x004073e2:	movl 0x41f1c8, %eax
0x004073e7:	call GetProcAddress@KERNEL32.DLL
0x004073e9:	xorl %eax, 0x41d350
0x004073ef:	pushl $0x4181e0<UINT32>
0x004073f4:	pushl %edi
0x004073f5:	movl 0x41f1cc, %eax
0x004073fa:	call GetProcAddress@KERNEL32.DLL
0x004073fc:	xorl %eax, 0x41d350
0x00407402:	pushl $0x4181f0<UINT32>
0x00407407:	pushl %edi
0x00407408:	movl 0x41f1d0, %eax
0x0040740d:	call GetProcAddress@KERNEL32.DLL
0x0040740f:	xorl %eax, 0x41d350
0x00407415:	pushl $0x418204<UINT32>
0x0040741a:	pushl %edi
0x0040741b:	movl 0x41f1d4, %eax
0x00407420:	call GetProcAddress@KERNEL32.DLL
0x00407422:	xorl %eax, 0x41d350
0x00407428:	movl 0x41f1d8, %eax
0x0040742d:	pushl $0x418214<UINT32>
0x00407432:	pushl %edi
0x00407433:	call GetProcAddress@KERNEL32.DLL
0x00407435:	xorl %eax, 0x41d350
0x0040743b:	pushl $0x418234<UINT32>
0x00407440:	pushl %edi
0x00407441:	movl 0x41f1dc, %eax
0x00407446:	call GetProcAddress@KERNEL32.DLL
0x00407448:	xorl %eax, 0x41d350
0x0040744e:	popl %edi
0x0040744f:	movl 0x41f1e0, %eax
0x00407454:	popl %esi
0x00407455:	ret

0x00408426:	call 0x00404bee
0x00404bee:	pushl %esi
0x00404bef:	pushl %edi
0x00404bf0:	movl %esi, $0x41d360<UINT32>
0x00404bf5:	movl %edi, $0x41e618<UINT32>
0x00404bfa:	cmpl 0x4(%esi), $0x1<UINT8>
0x00404bfe:	jne 22
0x00404c00:	pushl $0x0<UINT8>
0x00404c02:	movl (%esi), %edi
0x00404c04:	addl %edi, $0x18<UINT8>
0x00404c07:	pushl $0xfa0<UINT32>
0x00404c0c:	pushl (%esi)
0x00404c0e:	call 0x0040715d
0x0040715d:	pushl %ebp
0x0040715e:	movl %ebp, %esp
0x00407160:	movl %eax, 0x41f170
0x00407165:	xorl %eax, 0x41d350
0x0040716b:	je 13
0x0040716d:	pushl 0x10(%ebp)
0x00407170:	pushl 0xc(%ebp)
0x00407173:	pushl 0x8(%ebp)
0x00407176:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x00407178:	popl %ebp
0x00407179:	ret

0x00000fa0:	addb (%eax), %al
0x00000fa2:	addb (%eax), %al
0x00000fa4:	addb (%eax), %al
0x00000fa6:	addb (%eax), %al
0x00000fa8:	addb (%eax), %al
0x00000faa:	addb (%eax), %al
0x00000fac:	addb (%eax), %al
0x00000fae:	addb (%eax), %al
0x00000fb0:	addb (%eax), %al
0x00000fb2:	addb (%eax), %al
0x00000fb4:	addb (%eax), %al
0x00000fb6:	addb (%eax), %al
0x00000fb8:	addb (%eax), %al
0x00000fba:	addb (%eax), %al
0x00000fbc:	addb (%eax), %al
0x00000fbe:	addb (%eax), %al
0x00000fc0:	addb (%eax), %al
0x00000fc2:	addb (%eax), %al
0x00000fc4:	addb (%eax), %al
0x00000fc6:	addb (%eax), %al
0x00000fc8:	addb (%eax), %al
0x00000fca:	addb (%eax), %al
0x00000fcc:	addb (%eax), %al
0x00000fce:	addb (%eax), %al
0x00000fd0:	addb (%eax), %al
0x00000fd2:	addb (%eax), %al
0x00000fd4:	addb (%eax), %al
0x00000fd6:	addb (%eax), %al
0x00000fd8:	addb (%eax), %al
0x00000fda:	addb (%eax), %al
0x00000fdc:	addb (%eax), %al
0x00000fde:	addb (%eax), %al
0x00000fe0:	addb (%eax), %al
0x00000fe2:	addb (%eax), %al
0x00000fe4:	addb (%eax), %al
0x00000fe6:	addb (%eax), %al
0x00000fe8:	addb (%eax), %al
0x00000fea:	addb (%eax), %al
0x00000fec:	addb (%eax), %al
0x00000fee:	addb (%eax), %al
0x00000ff0:	addb (%eax), %al
0x00000ff2:	addb (%eax), %al
0x00000ff4:	addb (%eax), %al
0x00000ff6:	addb (%eax), %al
0x00000ff8:	addb (%eax), %al
0x00000ffa:	addb (%eax), %al
0x00000ffc:	addb (%eax), %al
0x00000ffe:	addb (%eax), %al
0x00001000:	addb (%eax), %al
0x00001002:	addb (%eax), %al
0x00001004:	addb (%eax), %al
0x00001006:	addb (%eax), %al
