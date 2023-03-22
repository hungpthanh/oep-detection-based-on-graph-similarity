0x00425570:	pusha
0x00425571:	movl %esi, $0x419000<UINT32>
0x00425576:	leal %edi, -98304(%esi)
0x0042557c:	pushl %edi
0x0042557d:	jmp 0x0042558a
0x0042558a:	movl %ebx, (%esi)
0x0042558c:	subl %esi, $0xfffffffc<UINT8>
0x0042558f:	adcl %ebx, %ebx
0x00425591:	jb 0x00425580
0x00425580:	movb %al, (%esi)
0x00425582:	incl %esi
0x00425583:	movb (%edi), %al
0x00425585:	incl %edi
0x00425586:	addl %ebx, %ebx
0x00425588:	jne 0x00425591
0x00425593:	movl %eax, $0x1<UINT32>
0x00425598:	addl %ebx, %ebx
0x0042559a:	jne 0x004255a3
0x004255a3:	adcl %eax, %eax
0x004255a5:	addl %ebx, %ebx
0x004255a7:	jae 0x00425598
0x004255a9:	jne 0x004255b4
0x004255b4:	xorl %ecx, %ecx
0x004255b6:	subl %eax, $0x3<UINT8>
0x004255b9:	jb 0x004255c8
0x004255bb:	shll %eax, $0x8<UINT8>
0x004255be:	movb %al, (%esi)
0x004255c0:	incl %esi
0x004255c1:	xorl %eax, $0xffffffff<UINT8>
0x004255c4:	je 0x0042563a
0x004255c6:	movl %ebp, %eax
0x004255c8:	addl %ebx, %ebx
0x004255ca:	jne 0x004255d3
0x004255d3:	adcl %ecx, %ecx
0x004255d5:	addl %ebx, %ebx
0x004255d7:	jne 0x004255e0
0x004255d9:	movl %ebx, (%esi)
0x004255db:	subl %esi, $0xfffffffc<UINT8>
0x004255de:	adcl %ebx, %ebx
0x004255e0:	adcl %ecx, %ecx
0x004255e2:	jne 0x00425604
0x00425604:	cmpl %ebp, $0xfffff300<UINT32>
0x0042560a:	adcl %ecx, $0x1<UINT8>
0x0042560d:	leal %edx, (%edi,%ebp)
0x00425610:	cmpl %ebp, $0xfffffffc<UINT8>
0x00425613:	jbe 0x00425624
0x00425624:	movl %eax, (%edx)
0x00425626:	addl %edx, $0x4<UINT8>
0x00425629:	movl (%edi), %eax
0x0042562b:	addl %edi, $0x4<UINT8>
0x0042562e:	subl %ecx, $0x4<UINT8>
0x00425631:	ja 0x00425624
0x00425633:	addl %edi, %ecx
0x00425635:	jmp 0x00425586
0x004255e4:	incl %ecx
0x004255e5:	addl %ebx, %ebx
0x004255e7:	jne 0x004255f0
0x004255f0:	adcl %ecx, %ecx
0x004255f2:	addl %ebx, %ebx
0x004255f4:	jae 0x004255e5
0x004255f6:	jne 0x00425601
0x00425601:	addl %ecx, $0x2<UINT8>
0x004255cc:	movl %ebx, (%esi)
0x004255ce:	subl %esi, $0xfffffffc<UINT8>
0x004255d1:	adcl %ebx, %ebx
0x00425615:	movb %al, (%edx)
0x00425617:	incl %edx
0x00425618:	movb (%edi), %al
0x0042561a:	incl %edi
0x0042561b:	decl %ecx
0x0042561c:	jne 0x00425615
0x0042561e:	jmp 0x00425586
0x004255ab:	movl %ebx, (%esi)
0x004255ad:	subl %esi, $0xfffffffc<UINT8>
0x004255b0:	adcl %ebx, %ebx
0x004255b2:	jae 0x00425598
0x004255e9:	movl %ebx, (%esi)
0x004255eb:	subl %esi, $0xfffffffc<UINT8>
0x004255ee:	adcl %ebx, %ebx
0x004255f8:	movl %ebx, (%esi)
0x004255fa:	subl %esi, $0xfffffffc<UINT8>
0x004255fd:	adcl %ebx, %ebx
0x004255ff:	jae 0x004255e5
0x0042559c:	movl %ebx, (%esi)
0x0042559e:	subl %esi, $0xfffffffc<UINT8>
0x004255a1:	adcl %ebx, %ebx
0x0042563a:	popl %esi
0x0042563b:	movl %edi, %esi
0x0042563d:	movl %ecx, $0x5a3<UINT32>
0x00425642:	movb %al, (%edi)
0x00425644:	incl %edi
0x00425645:	subb %al, $0xffffffe8<UINT8>
0x00425647:	cmpb %al, $0x1<UINT8>
0x00425649:	ja 0x00425642
0x0042564b:	cmpb (%edi), $0x5<UINT8>
0x0042564e:	jne 0x00425642
0x00425650:	movl %eax, (%edi)
0x00425652:	movb %bl, 0x4(%edi)
0x00425655:	shrw %ax, $0x8<UINT8>
0x00425659:	roll %eax, $0x10<UINT8>
0x0042565c:	xchgb %ah, %al
0x0042565e:	subl %eax, %edi
0x00425660:	subb %bl, $0xffffffe8<UINT8>
0x00425663:	addl %eax, %esi
0x00425665:	movl (%edi), %eax
0x00425667:	addl %edi, $0x5<UINT8>
0x0042566a:	movb %al, %bl
0x0042566c:	loop 0x00425647
0x0042566e:	leal %edi, 0x22000(%esi)
0x00425674:	movl %eax, (%edi)
0x00425676:	orl %eax, %eax
0x00425678:	je 0x004256b6
0x0042567a:	movl %ebx, 0x4(%edi)
0x0042567d:	leal %eax, 0x25528(%eax,%esi)
0x00425684:	addl %ebx, %esi
0x00425686:	pushl %eax
0x00425687:	addl %edi, $0x8<UINT8>
0x0042568a:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00425690:	xchgl %ebp, %eax
0x00425691:	movb %al, (%edi)
0x00425693:	incl %edi
0x00425694:	orb %al, %al
0x00425696:	je 0x00425674
0x00425698:	movl %ecx, %edi
0x0042569a:	pushl %edi
0x0042569b:	decl %eax
0x0042569c:	repn scasb %al, %es:(%edi)
0x0042569e:	pushl %ebp
0x0042569f:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x004256a5:	orl %eax, %eax
0x004256a7:	je 7
0x004256a9:	movl (%ebx), %eax
0x004256ab:	addl %ebx, $0x4<UINT8>
0x004256ae:	jmp 0x00425691
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x004256b6:	addl %edi, $0x4<UINT8>
0x004256b9:	leal %ebx, -4(%esi)
0x004256bc:	xorl %eax, %eax
0x004256be:	movb %al, (%edi)
0x004256c0:	incl %edi
0x004256c1:	orl %eax, %eax
0x004256c3:	je 0x004256e7
0x004256c5:	cmpb %al, $0xffffffef<UINT8>
0x004256c7:	ja 0x004256da
0x004256c9:	addl %ebx, %eax
0x004256cb:	movl %eax, (%ebx)
0x004256cd:	xchgb %ah, %al
0x004256cf:	roll %eax, $0x10<UINT8>
0x004256d2:	xchgb %ah, %al
0x004256d4:	addl %eax, %esi
0x004256d6:	movl (%ebx), %eax
0x004256d8:	jmp 0x004256bc
0x004256da:	andb %al, $0xf<UINT8>
0x004256dc:	shll %eax, $0x10<UINT8>
0x004256df:	movw %ax, (%edi)
0x004256e2:	addl %edi, $0x2<UINT8>
0x004256e5:	jmp 0x004256c9
0x004256e7:	movl %ebp, 0x255d8(%esi)
0x004256ed:	leal %edi, -4096(%esi)
0x004256f3:	movl %ebx, $0x1000<UINT32>
0x004256f8:	pushl %eax
0x004256f9:	pushl %esp
0x004256fa:	pushl $0x4<UINT8>
0x004256fc:	pushl %ebx
0x004256fd:	pushl %edi
0x004256fe:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00425700:	leal %eax, 0x20f(%edi)
0x00425706:	andb (%eax), $0x7f<UINT8>
0x00425709:	andb 0x28(%eax), $0x7f<UINT8>
0x0042570d:	popl %eax
0x0042570e:	pushl %eax
0x0042570f:	pushl %esp
0x00425710:	pushl %eax
0x00425711:	pushl %ebx
0x00425712:	pushl %edi
0x00425713:	call VirtualProtect@kernel32.dll
0x00425715:	popl %eax
0x00425716:	popa
0x00425717:	leal %eax, -128(%esp)
0x0042571b:	pushl $0x0<UINT8>
0x0042571d:	cmpl %esp, %eax
0x0042571f:	jne 0x0042571b
0x00425721:	subl %esp, $0xffffff80<UINT8>
0x00425724:	jmp 0x00404002
0x00404002:	call 0x0040a529
0x0040a529:	pushl %ebp
0x0040a52a:	movl %ebp, %esp
0x0040a52c:	subl %esp, $0x14<UINT8>
0x0040a52f:	andl -12(%ebp), $0x0<UINT8>
0x0040a533:	andl -8(%ebp), $0x0<UINT8>
0x0040a537:	movl %eax, 0x41d348
0x0040a53c:	pushl %esi
0x0040a53d:	pushl %edi
0x0040a53e:	movl %edi, $0xbb40e64e<UINT32>
0x0040a543:	movl %esi, $0xffff0000<UINT32>
0x0040a548:	cmpl %eax, %edi
0x0040a54a:	je 0x0040a559
0x0040a559:	leal %eax, -12(%ebp)
0x0040a55c:	pushl %eax
0x0040a55d:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040a563:	movl %eax, -8(%ebp)
0x0040a566:	xorl %eax, -12(%ebp)
0x0040a569:	movl -4(%ebp), %eax
0x0040a56c:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040a572:	xorl -4(%ebp), %eax
0x0040a575:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040a57b:	xorl -4(%ebp), %eax
0x0040a57e:	leal %eax, -20(%ebp)
0x0040a581:	pushl %eax
0x0040a582:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040a588:	movl %ecx, -16(%ebp)
0x0040a58b:	leal %eax, -4(%ebp)
0x0040a58e:	xorl %ecx, -20(%ebp)
0x0040a591:	xorl %ecx, -4(%ebp)
0x0040a594:	xorl %ecx, %eax
0x0040a596:	cmpl %ecx, %edi
0x0040a598:	jne 0x0040a5a1
0x0040a5a1:	testl %esi, %ecx
0x0040a5a3:	jne 0x0040a5b1
0x0040a5b1:	movl 0x41d348, %ecx
0x0040a5b7:	notl %ecx
0x0040a5b9:	movl 0x41d34c, %ecx
0x0040a5bf:	popl %edi
0x0040a5c0:	popl %esi
0x0040a5c1:	movl %esp, %ebp
0x0040a5c3:	popl %ebp
0x0040a5c4:	ret

0x00404007:	jmp 0x00403e87
0x00403e87:	pushl $0x14<UINT8>
0x00403e89:	pushl $0x41b8c8<UINT32>
0x00403e8e:	call 0x00404d40
0x00404d40:	pushl $0x404da0<UINT32>
0x00404d45:	pushl %fs:0
0x00404d4c:	movl %eax, 0x10(%esp)
0x00404d50:	movl 0x10(%esp), %ebp
0x00404d54:	leal %ebp, 0x10(%esp)
0x00404d58:	subl %esp, %eax
0x00404d5a:	pushl %ebx
0x00404d5b:	pushl %esi
0x00404d5c:	pushl %edi
0x00404d5d:	movl %eax, 0x41d348
0x00404d62:	xorl -4(%ebp), %eax
0x00404d65:	xorl %eax, %ebp
0x00404d67:	pushl %eax
0x00404d68:	movl -24(%ebp), %esp
0x00404d6b:	pushl -8(%ebp)
0x00404d6e:	movl %eax, -4(%ebp)
0x00404d71:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00404d78:	movl -8(%ebp), %eax
0x00404d7b:	leal %eax, -16(%ebp)
0x00404d7e:	movl %fs:0, %eax
0x00404d84:	ret

0x00403e93:	pushl $0x1<UINT8>
0x00403e95:	call 0x0040a4dc
0x0040a4dc:	pushl %ebp
0x0040a4dd:	movl %ebp, %esp
0x0040a4df:	movl %eax, 0x8(%ebp)
0x0040a4e2:	movl 0x41e558, %eax
0x0040a4e7:	popl %ebp
0x0040a4e8:	ret

0x00403e9a:	popl %ecx
0x00403e9b:	movl %eax, $0x5a4d<UINT32>
0x00403ea0:	cmpw 0x400000, %ax
0x00403ea7:	je 0x00403ead
0x00403ead:	movl %eax, 0x40003c
0x00403eb2:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00403ebc:	jne -21
0x00403ebe:	movl %ecx, $0x10b<UINT32>
0x00403ec3:	cmpw 0x400018(%eax), %cx
0x00403eca:	jne -35
0x00403ecc:	xorl %ebx, %ebx
0x00403ece:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00403ed5:	jbe 9
0x00403ed7:	cmpl 0x4000e8(%eax), %ebx
0x00403edd:	setne %bl
0x00403ee0:	movl -28(%ebp), %ebx
0x00403ee3:	call 0x0040789f
0x0040789f:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x004078a5:	xorl %ecx, %ecx
0x004078a7:	movl 0x41eb90, %eax
0x004078ac:	testl %eax, %eax
0x004078ae:	setne %cl
0x004078b1:	movl %eax, %ecx
0x004078b3:	ret

0x00403ee8:	testl %eax, %eax
0x00403eea:	jne 0x00403ef4
0x00403ef4:	call 0x00408885
0x00408885:	call 0x00403196
0x00403196:	pushl %esi
0x00403197:	pushl $0x0<UINT8>
0x00403199:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x0040319f:	movl %esi, %eax
0x004031a1:	pushl %esi
0x004031a2:	call 0x00407892
0x00407892:	pushl %ebp
0x00407893:	movl %ebp, %esp
0x00407895:	movl %eax, 0x8(%ebp)
0x00407898:	movl 0x41eb88, %eax
0x0040789d:	popl %ebp
0x0040789e:	ret

0x004031a7:	pushl %esi
0x004031a8:	call 0x00405059
0x00405059:	pushl %ebp
0x0040505a:	movl %ebp, %esp
0x0040505c:	movl %eax, 0x8(%ebp)
0x0040505f:	movl 0x41e444, %eax
0x00405064:	popl %ebp
0x00405065:	ret

0x004031ad:	pushl %esi
0x004031ae:	call 0x00408fd5
0x00408fd5:	pushl %ebp
0x00408fd6:	movl %ebp, %esp
0x00408fd8:	movl %eax, 0x8(%ebp)
0x00408fdb:	movl 0x41eed8, %eax
0x00408fe0:	popl %ebp
0x00408fe1:	ret

0x004031b3:	pushl %esi
0x004031b4:	call 0x00408fef
0x00408fef:	pushl %ebp
0x00408ff0:	movl %ebp, %esp
0x00408ff2:	movl %eax, 0x8(%ebp)
0x00408ff5:	movl 0x41eedc, %eax
0x00408ffa:	movl 0x41eee0, %eax
0x00408fff:	movl 0x41eee4, %eax
0x00409004:	movl 0x41eee8, %eax
0x00409009:	popl %ebp
0x0040900a:	ret

0x004031b9:	pushl %esi
0x004031ba:	call 0x00408fc4
0x00408fc4:	pushl $0x408f90<UINT32>
0x00408fc9:	call EncodePointer@KERNEL32.DLL
0x00408fcf:	movl 0x41eed4, %eax
0x00408fd4:	ret

0x004031bf:	pushl %esi
0x004031c0:	call 0x00409200
0x00409200:	pushl %ebp
0x00409201:	movl %ebp, %esp
0x00409203:	movl %eax, 0x8(%ebp)
0x00409206:	movl 0x41eef0, %eax
0x0040920b:	popl %ebp
0x0040920c:	ret

0x004031c5:	addl %esp, $0x18<UINT8>
0x004031c8:	popl %esi
0x004031c9:	jmp 0x00407380
0x00407380:	pushl %esi
0x00407381:	pushl %edi
0x00407382:	pushl $0x417b84<UINT32>
0x00407387:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0040738d:	movl %esi, 0x411064
0x00407393:	movl %edi, %eax
0x00407395:	pushl $0x417ba0<UINT32>
0x0040739a:	pushl %edi
0x0040739b:	call GetProcAddress@KERNEL32.DLL
0x0040739d:	xorl %eax, 0x41d348
0x004073a3:	pushl $0x417bac<UINT32>
0x004073a8:	pushl %edi
0x004073a9:	movl 0x41f040, %eax
0x004073ae:	call GetProcAddress@KERNEL32.DLL
0x004073b0:	xorl %eax, 0x41d348
0x004073b6:	pushl $0x417bb4<UINT32>
0x004073bb:	pushl %edi
0x004073bc:	movl 0x41f044, %eax
0x004073c1:	call GetProcAddress@KERNEL32.DLL
0x004073c3:	xorl %eax, 0x41d348
0x004073c9:	pushl $0x417bc0<UINT32>
0x004073ce:	pushl %edi
0x004073cf:	movl 0x41f048, %eax
0x004073d4:	call GetProcAddress@KERNEL32.DLL
0x004073d6:	xorl %eax, 0x41d348
0x004073dc:	pushl $0x417bcc<UINT32>
0x004073e1:	pushl %edi
0x004073e2:	movl 0x41f04c, %eax
0x004073e7:	call GetProcAddress@KERNEL32.DLL
0x004073e9:	xorl %eax, 0x41d348
0x004073ef:	pushl $0x417be8<UINT32>
0x004073f4:	pushl %edi
0x004073f5:	movl 0x41f050, %eax
0x004073fa:	call GetProcAddress@KERNEL32.DLL
0x004073fc:	xorl %eax, 0x41d348
0x00407402:	pushl $0x417bf8<UINT32>
0x00407407:	pushl %edi
0x00407408:	movl 0x41f054, %eax
0x0040740d:	call GetProcAddress@KERNEL32.DLL
0x0040740f:	xorl %eax, 0x41d348
0x00407415:	pushl $0x417c0c<UINT32>
0x0040741a:	pushl %edi
0x0040741b:	movl 0x41f058, %eax
0x00407420:	call GetProcAddress@KERNEL32.DLL
0x00407422:	xorl %eax, 0x41d348
0x00407428:	pushl $0x417c24<UINT32>
0x0040742d:	pushl %edi
0x0040742e:	movl 0x41f05c, %eax
0x00407433:	call GetProcAddress@KERNEL32.DLL
0x00407435:	xorl %eax, 0x41d348
0x0040743b:	pushl $0x417c3c<UINT32>
0x00407440:	pushl %edi
0x00407441:	movl 0x41f060, %eax
0x00407446:	call GetProcAddress@KERNEL32.DLL
0x00407448:	xorl %eax, 0x41d348
0x0040744e:	pushl $0x417c50<UINT32>
0x00407453:	pushl %edi
0x00407454:	movl 0x41f064, %eax
0x00407459:	call GetProcAddress@KERNEL32.DLL
0x0040745b:	xorl %eax, 0x41d348
0x00407461:	pushl $0x417c70<UINT32>
0x00407466:	pushl %edi
0x00407467:	movl 0x41f068, %eax
0x0040746c:	call GetProcAddress@KERNEL32.DLL
0x0040746e:	xorl %eax, 0x41d348
0x00407474:	pushl $0x417c88<UINT32>
0x00407479:	pushl %edi
0x0040747a:	movl 0x41f06c, %eax
0x0040747f:	call GetProcAddress@KERNEL32.DLL
0x00407481:	xorl %eax, 0x41d348
0x00407487:	pushl $0x417ca0<UINT32>
0x0040748c:	pushl %edi
0x0040748d:	movl 0x41f070, %eax
0x00407492:	call GetProcAddress@KERNEL32.DLL
0x00407494:	xorl %eax, 0x41d348
0x0040749a:	pushl $0x417cb4<UINT32>
0x0040749f:	pushl %edi
0x004074a0:	movl 0x41f074, %eax
0x004074a5:	call GetProcAddress@KERNEL32.DLL
0x004074a7:	xorl %eax, 0x41d348
0x004074ad:	movl 0x41f078, %eax
0x004074b2:	pushl $0x417cc8<UINT32>
0x004074b7:	pushl %edi
0x004074b8:	call GetProcAddress@KERNEL32.DLL
0x004074ba:	xorl %eax, 0x41d348
0x004074c0:	pushl $0x417ce4<UINT32>
0x004074c5:	pushl %edi
0x004074c6:	movl 0x41f07c, %eax
0x004074cb:	call GetProcAddress@KERNEL32.DLL
0x004074cd:	xorl %eax, 0x41d348
0x004074d3:	pushl $0x417d04<UINT32>
0x004074d8:	pushl %edi
0x004074d9:	movl 0x41f080, %eax
0x004074de:	call GetProcAddress@KERNEL32.DLL
0x004074e0:	xorl %eax, 0x41d348
0x004074e6:	pushl $0x417d20<UINT32>
0x004074eb:	pushl %edi
0x004074ec:	movl 0x41f084, %eax
0x004074f1:	call GetProcAddress@KERNEL32.DLL
0x004074f3:	xorl %eax, 0x41d348
0x004074f9:	pushl $0x417d40<UINT32>
0x004074fe:	pushl %edi
0x004074ff:	movl 0x41f088, %eax
0x00407504:	call GetProcAddress@KERNEL32.DLL
0x00407506:	xorl %eax, 0x41d348
0x0040750c:	pushl $0x417d54<UINT32>
0x00407511:	pushl %edi
0x00407512:	movl 0x41f08c, %eax
0x00407517:	call GetProcAddress@KERNEL32.DLL
0x00407519:	xorl %eax, 0x41d348
0x0040751f:	pushl $0x417d70<UINT32>
0x00407524:	pushl %edi
0x00407525:	movl 0x41f090, %eax
0x0040752a:	call GetProcAddress@KERNEL32.DLL
0x0040752c:	xorl %eax, 0x41d348
0x00407532:	pushl $0x417d84<UINT32>
0x00407537:	pushl %edi
0x00407538:	movl 0x41f098, %eax
0x0040753d:	call GetProcAddress@KERNEL32.DLL
0x0040753f:	xorl %eax, 0x41d348
0x00407545:	pushl $0x417d94<UINT32>
0x0040754a:	pushl %edi
0x0040754b:	movl 0x41f094, %eax
0x00407550:	call GetProcAddress@KERNEL32.DLL
0x00407552:	xorl %eax, 0x41d348
0x00407558:	pushl $0x417da4<UINT32>
0x0040755d:	pushl %edi
0x0040755e:	movl 0x41f09c, %eax
0x00407563:	call GetProcAddress@KERNEL32.DLL
0x00407565:	xorl %eax, 0x41d348
0x0040756b:	pushl $0x417db4<UINT32>
0x00407570:	pushl %edi
0x00407571:	movl 0x41f0a0, %eax
0x00407576:	call GetProcAddress@KERNEL32.DLL
0x00407578:	xorl %eax, 0x41d348
0x0040757e:	pushl $0x417dc4<UINT32>
0x00407583:	pushl %edi
0x00407584:	movl 0x41f0a4, %eax
0x00407589:	call GetProcAddress@KERNEL32.DLL
0x0040758b:	xorl %eax, 0x41d348
0x00407591:	pushl $0x417de0<UINT32>
0x00407596:	pushl %edi
0x00407597:	movl 0x41f0a8, %eax
0x0040759c:	call GetProcAddress@KERNEL32.DLL
0x0040759e:	xorl %eax, 0x41d348
0x004075a4:	pushl $0x417df4<UINT32>
0x004075a9:	pushl %edi
0x004075aa:	movl 0x41f0ac, %eax
0x004075af:	call GetProcAddress@KERNEL32.DLL
0x004075b1:	xorl %eax, 0x41d348
0x004075b7:	pushl $0x417e04<UINT32>
0x004075bc:	pushl %edi
0x004075bd:	movl 0x41f0b0, %eax
0x004075c2:	call GetProcAddress@KERNEL32.DLL
0x004075c4:	xorl %eax, 0x41d348
0x004075ca:	pushl $0x417e18<UINT32>
0x004075cf:	pushl %edi
0x004075d0:	movl 0x41f0b4, %eax
0x004075d5:	call GetProcAddress@KERNEL32.DLL
0x004075d7:	xorl %eax, 0x41d348
0x004075dd:	movl 0x41f0b8, %eax
0x004075e2:	pushl $0x417e28<UINT32>
0x004075e7:	pushl %edi
0x004075e8:	call GetProcAddress@KERNEL32.DLL
0x004075ea:	xorl %eax, 0x41d348
0x004075f0:	pushl $0x417e48<UINT32>
0x004075f5:	pushl %edi
0x004075f6:	movl 0x41f0bc, %eax
0x004075fb:	call GetProcAddress@KERNEL32.DLL
0x004075fd:	xorl %eax, 0x41d348
0x00407603:	popl %edi
0x00407604:	movl 0x41f0c0, %eax
0x00407609:	popl %esi
0x0040760a:	ret

0x0040888a:	call 0x004041da
0x004041da:	pushl %esi
0x004041db:	pushl %edi
0x004041dc:	movl %esi, $0x41d368<UINT32>
0x004041e1:	movl %edi, $0x41e2f0<UINT32>
0x004041e6:	cmpl 0x4(%esi), $0x1<UINT8>
0x004041ea:	jne 22
0x004041ec:	pushl $0x0<UINT8>
0x004041ee:	movl (%esi), %edi
0x004041f0:	addl %edi, $0x18<UINT8>
0x004041f3:	pushl $0xfa0<UINT32>
0x004041f8:	pushl (%esi)
0x004041fa:	call 0x00407312
0x00407312:	pushl %ebp
0x00407313:	movl %ebp, %esp
0x00407315:	movl %eax, 0x41f050
0x0040731a:	xorl %eax, 0x41d348
0x00407320:	je 13
0x00407322:	pushl 0x10(%ebp)
0x00407325:	pushl 0xc(%ebp)
0x00407328:	pushl 0x8(%ebp)
0x0040732b:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x0040732d:	popl %ebp
0x0040732e:	ret

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
