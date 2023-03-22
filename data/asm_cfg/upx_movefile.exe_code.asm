0x00425610:	pusha
0x00425611:	movl %esi, $0x419000<UINT32>
0x00425616:	leal %edi, -98304(%esi)
0x0042561c:	pushl %edi
0x0042561d:	jmp 0x0042562a
0x0042562a:	movl %ebx, (%esi)
0x0042562c:	subl %esi, $0xfffffffc<UINT8>
0x0042562f:	adcl %ebx, %ebx
0x00425631:	jb 0x00425620
0x00425620:	movb %al, (%esi)
0x00425622:	incl %esi
0x00425623:	movb (%edi), %al
0x00425625:	incl %edi
0x00425626:	addl %ebx, %ebx
0x00425628:	jne 0x00425631
0x00425633:	movl %eax, $0x1<UINT32>
0x00425638:	addl %ebx, %ebx
0x0042563a:	jne 0x00425643
0x00425643:	adcl %eax, %eax
0x00425645:	addl %ebx, %ebx
0x00425647:	jae 0x00425638
0x00425649:	jne 0x00425654
0x00425654:	xorl %ecx, %ecx
0x00425656:	subl %eax, $0x3<UINT8>
0x00425659:	jb 0x00425668
0x0042565b:	shll %eax, $0x8<UINT8>
0x0042565e:	movb %al, (%esi)
0x00425660:	incl %esi
0x00425661:	xorl %eax, $0xffffffff<UINT8>
0x00425664:	je 0x004256da
0x00425666:	movl %ebp, %eax
0x00425668:	addl %ebx, %ebx
0x0042566a:	jne 0x00425673
0x00425673:	adcl %ecx, %ecx
0x00425675:	addl %ebx, %ebx
0x00425677:	jne 0x00425680
0x00425679:	movl %ebx, (%esi)
0x0042567b:	subl %esi, $0xfffffffc<UINT8>
0x0042567e:	adcl %ebx, %ebx
0x00425680:	adcl %ecx, %ecx
0x00425682:	jne 0x004256a4
0x004256a4:	cmpl %ebp, $0xfffff300<UINT32>
0x004256aa:	adcl %ecx, $0x1<UINT8>
0x004256ad:	leal %edx, (%edi,%ebp)
0x004256b0:	cmpl %ebp, $0xfffffffc<UINT8>
0x004256b3:	jbe 0x004256c4
0x004256c4:	movl %eax, (%edx)
0x004256c6:	addl %edx, $0x4<UINT8>
0x004256c9:	movl (%edi), %eax
0x004256cb:	addl %edi, $0x4<UINT8>
0x004256ce:	subl %ecx, $0x4<UINT8>
0x004256d1:	ja 0x004256c4
0x004256d3:	addl %edi, %ecx
0x004256d5:	jmp 0x00425626
0x00425684:	incl %ecx
0x00425685:	addl %ebx, %ebx
0x00425687:	jne 0x00425690
0x00425690:	adcl %ecx, %ecx
0x00425692:	addl %ebx, %ebx
0x00425694:	jae 0x00425685
0x00425696:	jne 0x004256a1
0x004256a1:	addl %ecx, $0x2<UINT8>
0x0042566c:	movl %ebx, (%esi)
0x0042566e:	subl %esi, $0xfffffffc<UINT8>
0x00425671:	adcl %ebx, %ebx
0x004256b5:	movb %al, (%edx)
0x004256b7:	incl %edx
0x004256b8:	movb (%edi), %al
0x004256ba:	incl %edi
0x004256bb:	decl %ecx
0x004256bc:	jne 0x004256b5
0x004256be:	jmp 0x00425626
0x0042564b:	movl %ebx, (%esi)
0x0042564d:	subl %esi, $0xfffffffc<UINT8>
0x00425650:	adcl %ebx, %ebx
0x00425652:	jae 0x00425638
0x00425689:	movl %ebx, (%esi)
0x0042568b:	subl %esi, $0xfffffffc<UINT8>
0x0042568e:	adcl %ebx, %ebx
0x00425698:	movl %ebx, (%esi)
0x0042569a:	subl %esi, $0xfffffffc<UINT8>
0x0042569d:	adcl %ebx, %ebx
0x0042569f:	jae 0x00425685
0x0042563c:	movl %ebx, (%esi)
0x0042563e:	subl %esi, $0xfffffffc<UINT8>
0x00425641:	adcl %ebx, %ebx
0x004256da:	popl %esi
0x004256db:	movl %edi, %esi
0x004256dd:	movl %ecx, $0x5a5<UINT32>
0x004256e2:	movb %al, (%edi)
0x004256e4:	incl %edi
0x004256e5:	subb %al, $0xffffffe8<UINT8>
0x004256e7:	cmpb %al, $0x1<UINT8>
0x004256e9:	ja 0x004256e2
0x004256eb:	cmpb (%edi), $0x5<UINT8>
0x004256ee:	jne 0x004256e2
0x004256f0:	movl %eax, (%edi)
0x004256f2:	movb %bl, 0x4(%edi)
0x004256f5:	shrw %ax, $0x8<UINT8>
0x004256f9:	roll %eax, $0x10<UINT8>
0x004256fc:	xchgb %ah, %al
0x004256fe:	subl %eax, %edi
0x00425700:	subb %bl, $0xffffffe8<UINT8>
0x00425703:	addl %eax, %esi
0x00425705:	movl (%edi), %eax
0x00425707:	addl %edi, $0x5<UINT8>
0x0042570a:	movb %al, %bl
0x0042570c:	loop 0x004256e7
0x0042570e:	leal %edi, 0x22000(%esi)
0x00425714:	movl %eax, (%edi)
0x00425716:	orl %eax, %eax
0x00425718:	je 0x00425756
0x0042571a:	movl %ebx, 0x4(%edi)
0x0042571d:	leal %eax, 0x25554(%eax,%esi)
0x00425724:	addl %ebx, %esi
0x00425726:	pushl %eax
0x00425727:	addl %edi, $0x8<UINT8>
0x0042572a:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00425730:	xchgl %ebp, %eax
0x00425731:	movb %al, (%edi)
0x00425733:	incl %edi
0x00425734:	orb %al, %al
0x00425736:	je 0x00425714
0x00425738:	movl %ecx, %edi
0x0042573a:	pushl %edi
0x0042573b:	decl %eax
0x0042573c:	repn scasb %al, %es:(%edi)
0x0042573e:	pushl %ebp
0x0042573f:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00425745:	orl %eax, %eax
0x00425747:	je 7
0x00425749:	movl (%ebx), %eax
0x0042574b:	addl %ebx, $0x4<UINT8>
0x0042574e:	jmp 0x00425731
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x00425756:	addl %edi, $0x4<UINT8>
0x00425759:	leal %ebx, -4(%esi)
0x0042575c:	xorl %eax, %eax
0x0042575e:	movb %al, (%edi)
0x00425760:	incl %edi
0x00425761:	orl %eax, %eax
0x00425763:	je 0x00425787
0x00425765:	cmpb %al, $0xffffffef<UINT8>
0x00425767:	ja 0x0042577a
0x00425769:	addl %ebx, %eax
0x0042576b:	movl %eax, (%ebx)
0x0042576d:	xchgb %ah, %al
0x0042576f:	roll %eax, $0x10<UINT8>
0x00425772:	xchgb %ah, %al
0x00425774:	addl %eax, %esi
0x00425776:	movl (%ebx), %eax
0x00425778:	jmp 0x0042575c
0x0042577a:	andb %al, $0xf<UINT8>
0x0042577c:	shll %eax, $0x10<UINT8>
0x0042577f:	movw %ax, (%edi)
0x00425782:	addl %edi, $0x2<UINT8>
0x00425785:	jmp 0x00425769
0x00425787:	movl %ebp, 0x25604(%esi)
0x0042578d:	leal %edi, -4096(%esi)
0x00425793:	movl %ebx, $0x1000<UINT32>
0x00425798:	pushl %eax
0x00425799:	pushl %esp
0x0042579a:	pushl $0x4<UINT8>
0x0042579c:	pushl %ebx
0x0042579d:	pushl %edi
0x0042579e:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x004257a0:	leal %eax, 0x20f(%edi)
0x004257a6:	andb (%eax), $0x7f<UINT8>
0x004257a9:	andb 0x28(%eax), $0x7f<UINT8>
0x004257ad:	popl %eax
0x004257ae:	pushl %eax
0x004257af:	pushl %esp
0x004257b0:	pushl %eax
0x004257b1:	pushl %ebx
0x004257b2:	pushl %edi
0x004257b3:	call VirtualProtect@kernel32.dll
0x004257b5:	popl %eax
0x004257b6:	popa
0x004257b7:	leal %eax, -128(%esp)
0x004257bb:	pushl $0x0<UINT8>
0x004257bd:	cmpl %esp, %eax
0x004257bf:	jne 0x004257bb
0x004257c1:	subl %esp, $0xffffff80<UINT8>
0x004257c4:	jmp 0x00403f4b
0x00403f4b:	call 0x00409a84
0x00409a84:	pushl %ebp
0x00409a85:	movl %ebp, %esp
0x00409a87:	subl %esp, $0x14<UINT8>
0x00409a8a:	andl -12(%ebp), $0x0<UINT8>
0x00409a8e:	andl -8(%ebp), $0x0<UINT8>
0x00409a92:	movl %eax, 0x41d348
0x00409a97:	pushl %esi
0x00409a98:	pushl %edi
0x00409a99:	movl %edi, $0xbb40e64e<UINT32>
0x00409a9e:	movl %esi, $0xffff0000<UINT32>
0x00409aa3:	cmpl %eax, %edi
0x00409aa5:	je 0x00409ab4
0x00409ab4:	leal %eax, -12(%ebp)
0x00409ab7:	pushl %eax
0x00409ab8:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x00409abe:	movl %eax, -8(%ebp)
0x00409ac1:	xorl %eax, -12(%ebp)
0x00409ac4:	movl -4(%ebp), %eax
0x00409ac7:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x00409acd:	xorl -4(%ebp), %eax
0x00409ad0:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x00409ad6:	xorl -4(%ebp), %eax
0x00409ad9:	leal %eax, -20(%ebp)
0x00409adc:	pushl %eax
0x00409add:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x00409ae3:	movl %ecx, -16(%ebp)
0x00409ae6:	leal %eax, -4(%ebp)
0x00409ae9:	xorl %ecx, -20(%ebp)
0x00409aec:	xorl %ecx, -4(%ebp)
0x00409aef:	xorl %ecx, %eax
0x00409af1:	cmpl %ecx, %edi
0x00409af3:	jne 0x00409afc
0x00409afc:	testl %esi, %ecx
0x00409afe:	jne 0x00409b0c
0x00409b0c:	movl 0x41d348, %ecx
0x00409b12:	notl %ecx
0x00409b14:	movl 0x41d34c, %ecx
0x00409b1a:	popl %edi
0x00409b1b:	popl %esi
0x00409b1c:	movl %esp, %ebp
0x00409b1e:	popl %ebp
0x00409b1f:	ret

0x00403f50:	jmp 0x00403dd0
0x00403dd0:	pushl $0x14<UINT8>
0x00403dd2:	pushl $0x41b938<UINT32>
0x00403dd7:	call 0x00404c90
0x00404c90:	pushl $0x404cf0<UINT32>
0x00404c95:	pushl %fs:0
0x00404c9c:	movl %eax, 0x10(%esp)
0x00404ca0:	movl 0x10(%esp), %ebp
0x00404ca4:	leal %ebp, 0x10(%esp)
0x00404ca8:	subl %esp, %eax
0x00404caa:	pushl %ebx
0x00404cab:	pushl %esi
0x00404cac:	pushl %edi
0x00404cad:	movl %eax, 0x41d348
0x00404cb2:	xorl -4(%ebp), %eax
0x00404cb5:	xorl %eax, %ebp
0x00404cb7:	pushl %eax
0x00404cb8:	movl -24(%ebp), %esp
0x00404cbb:	pushl -8(%ebp)
0x00404cbe:	movl %eax, -4(%ebp)
0x00404cc1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00404cc8:	movl -8(%ebp), %eax
0x00404ccb:	leal %eax, -16(%ebp)
0x00404cce:	movl %fs:0, %eax
0x00404cd4:	ret

0x00403ddc:	pushl $0x1<UINT8>
0x00403dde:	call 0x00409a37
0x00409a37:	pushl %ebp
0x00409a38:	movl %ebp, %esp
0x00409a3a:	movl %eax, 0x8(%ebp)
0x00409a3d:	movl 0x41e550, %eax
0x00409a42:	popl %ebp
0x00409a43:	ret

0x00403de3:	popl %ecx
0x00403de4:	movl %eax, $0x5a4d<UINT32>
0x00403de9:	cmpw 0x400000, %ax
0x00403df0:	je 0x00403df6
0x00403df6:	movl %eax, 0x40003c
0x00403dfb:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00403e05:	jne -21
0x00403e07:	movl %ecx, $0x10b<UINT32>
0x00403e0c:	cmpw 0x400018(%eax), %cx
0x00403e13:	jne -35
0x00403e15:	xorl %ebx, %ebx
0x00403e17:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00403e1e:	jbe 9
0x00403e20:	cmpl 0x4000e8(%eax), %ebx
0x00403e26:	setne %bl
0x00403e29:	movl -28(%ebp), %ebx
0x00403e2c:	call 0x004078c8
0x004078c8:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x004078ce:	xorl %ecx, %ecx
0x004078d0:	movl 0x41eb88, %eax
0x004078d5:	testl %eax, %eax
0x004078d7:	setne %cl
0x004078da:	movl %eax, %ecx
0x004078dc:	ret

0x00403e31:	testl %eax, %eax
0x00403e33:	jne 0x00403e3d
0x00403e3d:	call 0x004088ae
0x004088ae:	call 0x00403152
0x00403152:	pushl %esi
0x00403153:	pushl $0x0<UINT8>
0x00403155:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x0040315b:	movl %esi, %eax
0x0040315d:	pushl %esi
0x0040315e:	call 0x004078bb
0x004078bb:	pushl %ebp
0x004078bc:	movl %ebp, %esp
0x004078be:	movl %eax, 0x8(%ebp)
0x004078c1:	movl 0x41eb80, %eax
0x004078c6:	popl %ebp
0x004078c7:	ret

0x00403163:	pushl %esi
0x00403164:	call 0x00404fa9
0x00404fa9:	pushl %ebp
0x00404faa:	movl %ebp, %esp
0x00404fac:	movl %eax, 0x8(%ebp)
0x00404faf:	movl 0x41e43c, %eax
0x00404fb4:	popl %ebp
0x00404fb5:	ret

0x00403169:	pushl %esi
0x0040316a:	call 0x00408ff5
0x00408ff5:	pushl %ebp
0x00408ff6:	movl %ebp, %esp
0x00408ff8:	movl %eax, 0x8(%ebp)
0x00408ffb:	movl 0x41eed0, %eax
0x00409000:	popl %ebp
0x00409001:	ret

0x0040316f:	pushl %esi
0x00403170:	call 0x0040900f
0x0040900f:	pushl %ebp
0x00409010:	movl %ebp, %esp
0x00409012:	movl %eax, 0x8(%ebp)
0x00409015:	movl 0x41eed4, %eax
0x0040901a:	movl 0x41eed8, %eax
0x0040901f:	movl 0x41eedc, %eax
0x00409024:	movl 0x41eee0, %eax
0x00409029:	popl %ebp
0x0040902a:	ret

0x00403175:	pushl %esi
0x00403176:	call 0x00408fe4
0x00408fe4:	pushl $0x408fb0<UINT32>
0x00408fe9:	call EncodePointer@KERNEL32.DLL
0x00408fef:	movl 0x41eecc, %eax
0x00408ff4:	ret

0x0040317b:	pushl %esi
0x0040317c:	call 0x00409220
0x00409220:	pushl %ebp
0x00409221:	movl %ebp, %esp
0x00409223:	movl %eax, 0x8(%ebp)
0x00409226:	movl 0x41eee8, %eax
0x0040922b:	popl %ebp
0x0040922c:	ret

0x00403181:	addl %esp, $0x18<UINT8>
0x00403184:	popl %esi
0x00403185:	jmp 0x004073a9
0x004073a9:	pushl %esi
0x004073aa:	pushl %edi
0x004073ab:	pushl $0x417bec<UINT32>
0x004073b0:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x004073b6:	movl %esi, 0x411078
0x004073bc:	movl %edi, %eax
0x004073be:	pushl $0x417c08<UINT32>
0x004073c3:	pushl %edi
0x004073c4:	call GetProcAddress@KERNEL32.DLL
0x004073c6:	xorl %eax, 0x41d348
0x004073cc:	pushl $0x417c14<UINT32>
0x004073d1:	pushl %edi
0x004073d2:	movl 0x41f040, %eax
0x004073d7:	call GetProcAddress@KERNEL32.DLL
0x004073d9:	xorl %eax, 0x41d348
0x004073df:	pushl $0x417c1c<UINT32>
0x004073e4:	pushl %edi
0x004073e5:	movl 0x41f044, %eax
0x004073ea:	call GetProcAddress@KERNEL32.DLL
0x004073ec:	xorl %eax, 0x41d348
0x004073f2:	pushl $0x417c28<UINT32>
0x004073f7:	pushl %edi
0x004073f8:	movl 0x41f048, %eax
0x004073fd:	call GetProcAddress@KERNEL32.DLL
0x004073ff:	xorl %eax, 0x41d348
0x00407405:	pushl $0x417c34<UINT32>
0x0040740a:	pushl %edi
0x0040740b:	movl 0x41f04c, %eax
0x00407410:	call GetProcAddress@KERNEL32.DLL
0x00407412:	xorl %eax, 0x41d348
0x00407418:	pushl $0x417c50<UINT32>
0x0040741d:	pushl %edi
0x0040741e:	movl 0x41f050, %eax
0x00407423:	call GetProcAddress@KERNEL32.DLL
0x00407425:	xorl %eax, 0x41d348
0x0040742b:	pushl $0x417c60<UINT32>
0x00407430:	pushl %edi
0x00407431:	movl 0x41f054, %eax
0x00407436:	call GetProcAddress@KERNEL32.DLL
0x00407438:	xorl %eax, 0x41d348
0x0040743e:	pushl $0x417c74<UINT32>
0x00407443:	pushl %edi
0x00407444:	movl 0x41f058, %eax
0x00407449:	call GetProcAddress@KERNEL32.DLL
0x0040744b:	xorl %eax, 0x41d348
0x00407451:	pushl $0x417c8c<UINT32>
0x00407456:	pushl %edi
0x00407457:	movl 0x41f05c, %eax
0x0040745c:	call GetProcAddress@KERNEL32.DLL
0x0040745e:	xorl %eax, 0x41d348
0x00407464:	pushl $0x417ca4<UINT32>
0x00407469:	pushl %edi
0x0040746a:	movl 0x41f060, %eax
0x0040746f:	call GetProcAddress@KERNEL32.DLL
0x00407471:	xorl %eax, 0x41d348
0x00407477:	pushl $0x417cb8<UINT32>
0x0040747c:	pushl %edi
0x0040747d:	movl 0x41f064, %eax
0x00407482:	call GetProcAddress@KERNEL32.DLL
0x00407484:	xorl %eax, 0x41d348
0x0040748a:	pushl $0x417cd8<UINT32>
0x0040748f:	pushl %edi
0x00407490:	movl 0x41f068, %eax
0x00407495:	call GetProcAddress@KERNEL32.DLL
0x00407497:	xorl %eax, 0x41d348
0x0040749d:	pushl $0x417cf0<UINT32>
0x004074a2:	pushl %edi
0x004074a3:	movl 0x41f06c, %eax
0x004074a8:	call GetProcAddress@KERNEL32.DLL
0x004074aa:	xorl %eax, 0x41d348
0x004074b0:	pushl $0x417d08<UINT32>
0x004074b5:	pushl %edi
0x004074b6:	movl 0x41f070, %eax
0x004074bb:	call GetProcAddress@KERNEL32.DLL
0x004074bd:	xorl %eax, 0x41d348
0x004074c3:	pushl $0x417d1c<UINT32>
0x004074c8:	pushl %edi
0x004074c9:	movl 0x41f074, %eax
0x004074ce:	call GetProcAddress@KERNEL32.DLL
0x004074d0:	xorl %eax, 0x41d348
0x004074d6:	movl 0x41f078, %eax
0x004074db:	pushl $0x417d30<UINT32>
0x004074e0:	pushl %edi
0x004074e1:	call GetProcAddress@KERNEL32.DLL
0x004074e3:	xorl %eax, 0x41d348
0x004074e9:	pushl $0x417d4c<UINT32>
0x004074ee:	pushl %edi
0x004074ef:	movl 0x41f07c, %eax
0x004074f4:	call GetProcAddress@KERNEL32.DLL
0x004074f6:	xorl %eax, 0x41d348
0x004074fc:	pushl $0x417d6c<UINT32>
0x00407501:	pushl %edi
0x00407502:	movl 0x41f080, %eax
0x00407507:	call GetProcAddress@KERNEL32.DLL
0x00407509:	xorl %eax, 0x41d348
0x0040750f:	pushl $0x417d88<UINT32>
0x00407514:	pushl %edi
0x00407515:	movl 0x41f084, %eax
0x0040751a:	call GetProcAddress@KERNEL32.DLL
0x0040751c:	xorl %eax, 0x41d348
0x00407522:	pushl $0x417da8<UINT32>
0x00407527:	pushl %edi
0x00407528:	movl 0x41f088, %eax
0x0040752d:	call GetProcAddress@KERNEL32.DLL
0x0040752f:	xorl %eax, 0x41d348
0x00407535:	pushl $0x417dbc<UINT32>
0x0040753a:	pushl %edi
0x0040753b:	movl 0x41f08c, %eax
0x00407540:	call GetProcAddress@KERNEL32.DLL
0x00407542:	xorl %eax, 0x41d348
0x00407548:	pushl $0x417dd8<UINT32>
0x0040754d:	pushl %edi
0x0040754e:	movl 0x41f090, %eax
0x00407553:	call GetProcAddress@KERNEL32.DLL
0x00407555:	xorl %eax, 0x41d348
0x0040755b:	pushl $0x417dec<UINT32>
0x00407560:	pushl %edi
0x00407561:	movl 0x41f098, %eax
0x00407566:	call GetProcAddress@KERNEL32.DLL
0x00407568:	xorl %eax, 0x41d348
0x0040756e:	pushl $0x417dfc<UINT32>
0x00407573:	pushl %edi
0x00407574:	movl 0x41f094, %eax
0x00407579:	call GetProcAddress@KERNEL32.DLL
0x0040757b:	xorl %eax, 0x41d348
0x00407581:	pushl $0x417e0c<UINT32>
0x00407586:	pushl %edi
0x00407587:	movl 0x41f09c, %eax
0x0040758c:	call GetProcAddress@KERNEL32.DLL
0x0040758e:	xorl %eax, 0x41d348
0x00407594:	pushl $0x417e1c<UINT32>
0x00407599:	pushl %edi
0x0040759a:	movl 0x41f0a0, %eax
0x0040759f:	call GetProcAddress@KERNEL32.DLL
0x004075a1:	xorl %eax, 0x41d348
0x004075a7:	pushl $0x417e2c<UINT32>
0x004075ac:	pushl %edi
0x004075ad:	movl 0x41f0a4, %eax
0x004075b2:	call GetProcAddress@KERNEL32.DLL
0x004075b4:	xorl %eax, 0x41d348
0x004075ba:	pushl $0x417e48<UINT32>
0x004075bf:	pushl %edi
0x004075c0:	movl 0x41f0a8, %eax
0x004075c5:	call GetProcAddress@KERNEL32.DLL
0x004075c7:	xorl %eax, 0x41d348
0x004075cd:	pushl $0x417e5c<UINT32>
0x004075d2:	pushl %edi
0x004075d3:	movl 0x41f0ac, %eax
0x004075d8:	call GetProcAddress@KERNEL32.DLL
0x004075da:	xorl %eax, 0x41d348
0x004075e0:	pushl $0x417e6c<UINT32>
0x004075e5:	pushl %edi
0x004075e6:	movl 0x41f0b0, %eax
0x004075eb:	call GetProcAddress@KERNEL32.DLL
0x004075ed:	xorl %eax, 0x41d348
0x004075f3:	pushl $0x417e80<UINT32>
0x004075f8:	pushl %edi
0x004075f9:	movl 0x41f0b4, %eax
0x004075fe:	call GetProcAddress@KERNEL32.DLL
0x00407600:	xorl %eax, 0x41d348
0x00407606:	movl 0x41f0b8, %eax
0x0040760b:	pushl $0x417e90<UINT32>
0x00407610:	pushl %edi
0x00407611:	call GetProcAddress@KERNEL32.DLL
0x00407613:	xorl %eax, 0x41d348
0x00407619:	pushl $0x417eb0<UINT32>
0x0040761e:	pushl %edi
0x0040761f:	movl 0x41f0bc, %eax
0x00407624:	call GetProcAddress@KERNEL32.DLL
0x00407626:	xorl %eax, 0x41d348
0x0040762c:	popl %edi
0x0040762d:	movl 0x41f0c0, %eax
0x00407632:	popl %esi
0x00407633:	ret

0x004088b3:	call 0x00404123
0x00404123:	pushl %esi
0x00404124:	pushl %edi
0x00404125:	movl %esi, $0x41d360<UINT32>
0x0040412a:	movl %edi, $0x41e2e8<UINT32>
0x0040412f:	cmpl 0x4(%esi), $0x1<UINT8>
0x00404133:	jne 22
0x00404135:	pushl $0x0<UINT8>
0x00404137:	movl (%esi), %edi
0x00404139:	addl %edi, $0x18<UINT8>
0x0040413c:	pushl $0xfa0<UINT32>
0x00404141:	pushl (%esi)
0x00404143:	call 0x0040733b
0x0040733b:	pushl %ebp
0x0040733c:	movl %ebp, %esp
0x0040733e:	movl %eax, 0x41f050
0x00407343:	xorl %eax, 0x41d348
0x00407349:	je 13
0x0040734b:	pushl 0x10(%ebp)
0x0040734e:	pushl 0xc(%ebp)
0x00407351:	pushl 0x8(%ebp)
0x00407354:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x00407356:	popl %ebp
0x00407357:	ret

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
