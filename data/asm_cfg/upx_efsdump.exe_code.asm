0x00425710:	pusha
0x00425711:	movl %esi, $0x41e000<UINT32>
0x00425716:	leal %edi, -118784(%esi)
0x0042571c:	pushl %edi
0x0042571d:	jmp 0x0042572a
0x0042572a:	movl %ebx, (%esi)
0x0042572c:	subl %esi, $0xfffffffc<UINT8>
0x0042572f:	adcl %ebx, %ebx
0x00425731:	jb 0x00425720
0x00425720:	movb %al, (%esi)
0x00425722:	incl %esi
0x00425723:	movb (%edi), %al
0x00425725:	incl %edi
0x00425726:	addl %ebx, %ebx
0x00425728:	jne 0x00425731
0x00425733:	movl %eax, $0x1<UINT32>
0x00425738:	addl %ebx, %ebx
0x0042573a:	jne 0x00425743
0x00425743:	adcl %eax, %eax
0x00425745:	addl %ebx, %ebx
0x00425747:	jae 0x00425738
0x00425749:	jne 0x00425754
0x00425754:	xorl %ecx, %ecx
0x00425756:	subl %eax, $0x3<UINT8>
0x00425759:	jb 0x00425768
0x0042575b:	shll %eax, $0x8<UINT8>
0x0042575e:	movb %al, (%esi)
0x00425760:	incl %esi
0x00425761:	xorl %eax, $0xffffffff<UINT8>
0x00425764:	je 0x004257da
0x00425766:	movl %ebp, %eax
0x00425768:	addl %ebx, %ebx
0x0042576a:	jne 0x00425773
0x0042576c:	movl %ebx, (%esi)
0x0042576e:	subl %esi, $0xfffffffc<UINT8>
0x00425771:	adcl %ebx, %ebx
0x00425773:	adcl %ecx, %ecx
0x00425775:	addl %ebx, %ebx
0x00425777:	jne 0x00425780
0x00425780:	adcl %ecx, %ecx
0x00425782:	jne 0x004257a4
0x004257a4:	cmpl %ebp, $0xfffff300<UINT32>
0x004257aa:	adcl %ecx, $0x1<UINT8>
0x004257ad:	leal %edx, (%edi,%ebp)
0x004257b0:	cmpl %ebp, $0xfffffffc<UINT8>
0x004257b3:	jbe 0x004257c4
0x004257c4:	movl %eax, (%edx)
0x004257c6:	addl %edx, $0x4<UINT8>
0x004257c9:	movl (%edi), %eax
0x004257cb:	addl %edi, $0x4<UINT8>
0x004257ce:	subl %ecx, $0x4<UINT8>
0x004257d1:	ja 0x004257c4
0x004257d3:	addl %edi, %ecx
0x004257d5:	jmp 0x00425726
0x00425784:	incl %ecx
0x00425785:	addl %ebx, %ebx
0x00425787:	jne 0x00425790
0x00425790:	adcl %ecx, %ecx
0x00425792:	addl %ebx, %ebx
0x00425794:	jae 0x00425785
0x00425796:	jne 0x004257a1
0x004257a1:	addl %ecx, $0x2<UINT8>
0x004257b5:	movb %al, (%edx)
0x004257b7:	incl %edx
0x004257b8:	movb (%edi), %al
0x004257ba:	incl %edi
0x004257bb:	decl %ecx
0x004257bc:	jne 0x004257b5
0x004257be:	jmp 0x00425726
0x0042574b:	movl %ebx, (%esi)
0x0042574d:	subl %esi, $0xfffffffc<UINT8>
0x00425750:	adcl %ebx, %ebx
0x00425752:	jae 0x00425738
0x00425779:	movl %ebx, (%esi)
0x0042577b:	subl %esi, $0xfffffffc<UINT8>
0x0042577e:	adcl %ebx, %ebx
0x00425789:	movl %ebx, (%esi)
0x0042578b:	subl %esi, $0xfffffffc<UINT8>
0x0042578e:	adcl %ebx, %ebx
0x00425798:	movl %ebx, (%esi)
0x0042579a:	subl %esi, $0xfffffffc<UINT8>
0x0042579d:	adcl %ebx, %ebx
0x0042579f:	jae 0x00425785
0x0042573c:	movl %ebx, (%esi)
0x0042573e:	subl %esi, $0xfffffffc<UINT8>
0x00425741:	adcl %ebx, %ebx
0x004257da:	popl %esi
0x004257db:	movl %edi, %esi
0x004257dd:	movl %ecx, $0x120<UINT32>
0x004257e2:	movb %al, (%edi)
0x004257e4:	incl %edi
0x004257e5:	subb %al, $0xffffffe8<UINT8>
0x004257e7:	cmpb %al, $0x1<UINT8>
0x004257e9:	ja 0x004257e2
0x004257eb:	cmpb (%edi), $0x1<UINT8>
0x004257ee:	jne 0x004257e2
0x004257f0:	movl %eax, (%edi)
0x004257f2:	movb %bl, 0x4(%edi)
0x004257f5:	shrw %ax, $0x8<UINT8>
0x004257f9:	roll %eax, $0x10<UINT8>
0x004257fc:	xchgb %ah, %al
0x004257fe:	subl %eax, %edi
0x00425800:	subb %bl, $0xffffffe8<UINT8>
0x00425803:	addl %eax, %esi
0x00425805:	movl (%edi), %eax
0x00425807:	addl %edi, $0x5<UINT8>
0x0042580a:	movb %al, %bl
0x0042580c:	loop 0x004257e7
0x0042580e:	leal %edi, 0x23000(%esi)
0x00425814:	movl %eax, (%edi)
0x00425816:	orl %eax, %eax
0x00425818:	je 0x00425856
0x0042581a:	movl %ebx, 0x4(%edi)
0x0042581d:	leal %eax, 0x25000(%eax,%esi)
0x00425824:	addl %ebx, %esi
0x00425826:	pushl %eax
0x00425827:	addl %edi, $0x8<UINT8>
0x0042582a:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00425830:	xchgl %ebp, %eax
0x00425831:	movb %al, (%edi)
0x00425833:	incl %edi
0x00425834:	orb %al, %al
0x00425836:	je 0x00425814
0x00425838:	movl %ecx, %edi
0x0042583a:	pushl %edi
0x0042583b:	decl %eax
0x0042583c:	repn scasb %al, %es:(%edi)
0x0042583e:	pushl %ebp
0x0042583f:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00425845:	orl %eax, %eax
0x00425847:	je 7
0x00425849:	movl (%ebx), %eax
0x0042584b:	addl %ebx, $0x4<UINT8>
0x0042584e:	jmp 0x00425831
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x00425856:	movl %ebp, 0x2509c(%esi)
0x0042585c:	leal %edi, -4096(%esi)
0x00425862:	movl %ebx, $0x1000<UINT32>
0x00425867:	pushl %eax
0x00425868:	pushl %esp
0x00425869:	pushl $0x4<UINT8>
0x0042586b:	pushl %ebx
0x0042586c:	pushl %edi
0x0042586d:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0042586f:	leal %eax, 0x1f7(%edi)
0x00425875:	andb (%eax), $0x7f<UINT8>
0x00425878:	andb 0x28(%eax), $0x7f<UINT8>
0x0042587c:	popl %eax
0x0042587d:	pushl %eax
0x0042587e:	pushl %esp
0x0042587f:	pushl %eax
0x00425880:	pushl %ebx
0x00425881:	pushl %edi
0x00425882:	call VirtualProtect@kernel32.dll
0x00425884:	popl %eax
0x00425885:	popa
0x00425886:	leal %eax, -128(%esp)
0x0042588a:	pushl $0x0<UINT8>
0x0042588c:	cmpl %esp, %eax
0x0042588e:	jne 0x0042588a
0x00425890:	subl %esp, $0xffffff80<UINT8>
0x00425893:	jmp 0x00402138
0x00402138:	pushl %ebp
0x00402139:	movl %ebp, %esp
0x0040213b:	pushl $0xffffffff<UINT8>
0x0040213d:	pushl $0x406138<UINT32>
0x00402142:	pushl $0x403fa4<UINT32>
0x00402147:	movl %eax, %fs:0
0x0040214d:	pushl %eax
0x0040214e:	movl %fs:0, %esp
0x00402155:	subl %esp, $0x10<UINT8>
0x00402158:	pushl %ebx
0x00402159:	pushl %esi
0x0040215a:	pushl %edi
0x0040215b:	movl -24(%ebp), %esp
0x0040215e:	call GetVersion@KERNEL32.DLL
GetVersion@KERNEL32.DLL: API Node	
0x00402164:	xorl %edx, %edx
0x00402166:	movb %dl, %ah
0x00402168:	movl 0x421e44, %edx
0x0040216e:	movl %ecx, %eax
0x00402170:	andl %ecx, $0xff<UINT32>
0x00402176:	movl 0x421e40, %ecx
0x0040217c:	shll %ecx, $0x8<UINT8>
0x0040217f:	addl %ecx, %edx
0x00402181:	movl 0x421e3c, %ecx
0x00402187:	shrl %eax, $0x10<UINT8>
0x0040218a:	movl 0x421e38, %eax
0x0040218f:	pushl $0x0<UINT8>
0x00402191:	call 0x00402d06
0x00402d06:	xorl %eax, %eax
0x00402d08:	pushl $0x0<UINT8>
0x00402d0a:	cmpl 0x8(%esp), %eax
0x00402d0e:	pushl $0x1000<UINT32>
0x00402d13:	sete %al
0x00402d16:	pushl %eax
0x00402d17:	call HeapCreate@KERNEL32.DLL
HeapCreate@KERNEL32.DLL: API Node	
0x00402d1d:	testl %eax, %eax
0x00402d1f:	movl 0x42220c, %eax
0x00402d24:	je 21
0x00402d26:	call 0x00402d42
0x00402d42:	pushl $0x140<UINT32>
0x00402d47:	pushl $0x0<UINT8>
0x00402d49:	pushl 0x42220c
0x00402d4f:	call HeapAlloc@KERNEL32.DLL
HeapAlloc@KERNEL32.DLL: API Node	
0x00402d55:	testl %eax, %eax
0x00402d57:	movl 0x422208, %eax
0x00402d5c:	jne 0x00402d5f
0x00402d5f:	andl 0x422200, $0x0<UINT8>
0x00402d66:	andl 0x422204, $0x0<UINT8>
0x00402d6d:	pushl $0x1<UINT8>
0x00402d6f:	movl 0x4221fc, %eax
0x00402d74:	movl 0x4221f4, $0x10<UINT32>
0x00402d7e:	popl %eax
0x00402d7f:	ret

0x00402d2b:	testl %eax, %eax
0x00402d2d:	jne 0x00402d3e
0x00402d3e:	pushl $0x1<UINT8>
0x00402d40:	popl %eax
0x00402d41:	ret

0x00402196:	popl %ecx
0x00402197:	testl %eax, %eax
0x00402199:	jne 0x004021a3
0x004021a3:	andl -4(%ebp), $0x0<UINT8>
0x004021a7:	call 0x00403d00
0x00403d00:	subl %esp, $0x44<UINT8>
0x00403d03:	pushl %ebx
0x00403d04:	pushl %ebp
0x00403d05:	pushl %esi
0x00403d06:	pushl %edi
0x00403d07:	pushl $0x100<UINT32>
0x00403d0c:	call 0x00402078
0x00402078:	pushl 0x421e24
0x0040207e:	pushl 0x8(%esp)
0x00402082:	call 0x0040208a
0x0040208a:	cmpl 0x4(%esp), $0xffffffe0<UINT8>
0x0040208f:	ja 34
0x00402091:	pushl 0x4(%esp)
0x00402095:	call 0x004020b6
0x004020b6:	pushl %esi
0x004020b7:	movl %esi, 0x8(%esp)
0x004020bb:	cmpl %esi, 0x42192c
0x004020c1:	ja 0x004020ce
0x004020c3:	pushl %esi
0x004020c4:	call 0x004030d6
0x004030d6:	pushl %ebp
0x004030d7:	movl %ebp, %esp
0x004030d9:	subl %esp, $0x14<UINT8>
0x004030dc:	movl %eax, 0x422204
0x004030e1:	movl %edx, 0x422208
0x004030e7:	pushl %ebx
0x004030e8:	pushl %esi
0x004030e9:	leal %eax, (%eax,%eax,4)
0x004030ec:	pushl %edi
0x004030ed:	leal %edi, (%edx,%eax,4)
0x004030f0:	movl %eax, 0x8(%ebp)
0x004030f3:	movl -4(%ebp), %edi
0x004030f6:	leal %ecx, 0x17(%eax)
0x004030f9:	andl %ecx, $0xfffffff0<UINT8>
0x004030fc:	movl -16(%ebp), %ecx
0x004030ff:	sarl %ecx, $0x4<UINT8>
0x00403102:	decl %ecx
0x00403103:	cmpl %ecx, $0x20<UINT8>
0x00403106:	jnl 0x00403116
0x00403108:	orl %esi, $0xffffffff<UINT8>
0x0040310b:	shrl %esi, %cl
0x0040310d:	orl -8(%ebp), $0xffffffff<UINT8>
0x00403111:	movl -12(%ebp), %esi
0x00403114:	jmp 0x00403126
0x00403126:	movl %eax, 0x4221fc
0x0040312b:	movl %ebx, %eax
0x0040312d:	cmpl %ebx, %edi
0x0040312f:	movl 0x8(%ebp), %ebx
0x00403132:	jae 0x0040314d
0x0040314d:	cmpl %ebx, -4(%ebp)
0x00403150:	jne 0x004031cb
0x00403152:	movl %ebx, %edx
0x00403154:	cmpl %ebx, %eax
0x00403156:	movl 0x8(%ebp), %ebx
0x00403159:	jae 0x00403170
0x00403170:	jne 89
0x00403172:	cmpl %ebx, -4(%ebp)
0x00403175:	jae 0x00403188
0x00403188:	jne 38
0x0040318a:	movl %ebx, %edx
0x0040318c:	cmpl %ebx, %eax
0x0040318e:	movl 0x8(%ebp), %ebx
0x00403191:	jae 0x004031a0
0x004031a0:	jne 14
0x004031a2:	call 0x004033df
0x004033df:	movl %eax, 0x422204
0x004033e4:	movl %ecx, 0x4221f4
0x004033ea:	pushl %esi
0x004033eb:	pushl %edi
0x004033ec:	xorl %edi, %edi
0x004033ee:	cmpl %eax, %ecx
0x004033f0:	jne 0x00403422
0x00403422:	movl %ecx, 0x422208
0x00403428:	pushl $0x41c4<UINT32>
0x0040342d:	pushl $0x8<UINT8>
0x0040342f:	leal %eax, (%eax,%eax,4)
0x00403432:	pushl 0x42220c
0x00403438:	leal %esi, (%ecx,%eax,4)
0x0040343b:	call HeapAlloc@KERNEL32.DLL
0x00403441:	cmpl %eax, %edi
0x00403443:	movl 0x10(%esi), %eax
0x00403446:	je 42
0x00403448:	pushl $0x4<UINT8>
0x0040344a:	pushl $0x2000<UINT32>
0x0040344f:	pushl $0x100000<UINT32>
0x00403454:	pushl %edi
0x00403455:	call VirtualAlloc@KERNEL32.DLL
VirtualAlloc@KERNEL32.DLL: API Node	
0x0040345b:	cmpl %eax, %edi
0x0040345d:	movl 0xc(%esi), %eax
0x00403460:	jne 0x00403476
0x00403476:	orl 0x8(%esi), $0xffffffff<UINT8>
0x0040347a:	movl (%esi), %edi
0x0040347c:	movl 0x4(%esi), %edi
0x0040347f:	incl 0x422204
0x00403485:	movl %eax, 0x10(%esi)
0x00403488:	orl (%eax), $0xffffffff<UINT8>
0x0040348b:	movl %eax, %esi
0x0040348d:	popl %edi
0x0040348e:	popl %esi
0x0040348f:	ret

0x004031a7:	movl %ebx, %eax
0x004031a9:	testl %ebx, %ebx
0x004031ab:	movl 0x8(%ebp), %ebx
0x004031ae:	je 20
0x004031b0:	pushl %ebx
0x004031b1:	call 0x00403490
0x00403490:	pushl %ebp
0x00403491:	movl %ebp, %esp
0x00403493:	pushl %ecx
0x00403494:	movl %ecx, 0x8(%ebp)
0x00403497:	pushl %ebx
0x00403498:	pushl %esi
0x00403499:	pushl %edi
0x0040349a:	movl %esi, 0x10(%ecx)
0x0040349d:	movl %eax, 0x8(%ecx)
0x004034a0:	xorl %ebx, %ebx
0x004034a2:	testl %eax, %eax
0x004034a4:	jl 0x004034ab
0x004034ab:	movl %eax, %ebx
0x004034ad:	pushl $0x3f<UINT8>
0x004034af:	imull %eax, %eax, $0x204<UINT32>
0x004034b5:	popl %edx
0x004034b6:	leal %eax, 0x144(%eax,%esi)
0x004034bd:	movl -4(%ebp), %eax
0x004034c0:	movl 0x8(%eax), %eax
0x004034c3:	movl 0x4(%eax), %eax
0x004034c6:	addl %eax, $0x8<UINT8>
0x004034c9:	decl %edx
0x004034ca:	jne 0x004034c0
0x004034cc:	movl %edi, %ebx
0x004034ce:	pushl $0x4<UINT8>
0x004034d0:	shll %edi, $0xf<UINT8>
0x004034d3:	addl %edi, 0xc(%ecx)
0x004034d6:	pushl $0x1000<UINT32>
0x004034db:	pushl $0x8000<UINT32>
0x004034e0:	pushl %edi
0x004034e1:	call VirtualAlloc@KERNEL32.DLL
0x004034e7:	testl %eax, %eax
0x004034e9:	jne 0x004034f3
0x004034f3:	leal %edx, 0x7000(%edi)
0x004034f9:	cmpl %edi, %edx
0x004034fb:	ja 60
0x004034fd:	leal %eax, 0x10(%edi)
0x00403500:	orl -8(%eax), $0xffffffff<UINT8>
0x00403504:	orl 0xfec(%eax), $0xffffffff<UINT8>
0x0040350b:	leal %ecx, 0xffc(%eax)
0x00403511:	movl -4(%eax), $0xff0<UINT32>
0x00403518:	movl (%eax), %ecx
0x0040351a:	leal %ecx, -4100(%eax)
0x00403520:	movl 0x4(%eax), %ecx
0x00403523:	movl 0xfe8(%eax), $0xff0<UINT32>
0x0040352d:	addl %eax, $0x1000<UINT32>
0x00403532:	leal %ecx, -16(%eax)
0x00403535:	cmpl %ecx, %edx
0x00403537:	jbe 0x00403500
0x00403539:	movl %eax, -4(%ebp)
0x0040353c:	leal %ecx, 0xc(%edi)
0x0040353f:	addl %eax, $0x1f8<UINT32>
0x00403544:	pushl $0x1<UINT8>
0x00403546:	popl %edi
0x00403547:	movl 0x4(%eax), %ecx
0x0040354a:	movl 0x8(%ecx), %eax
0x0040354d:	leal %ecx, 0xc(%edx)
0x00403550:	movl 0x8(%eax), %ecx
0x00403553:	movl 0x4(%ecx), %eax
0x00403556:	andl 0x44(%esi,%ebx,4), $0x0<UINT8>
0x0040355b:	movl 0xc4(%esi,%ebx,4), %edi
0x00403562:	movb %al, 0x43(%esi)
0x00403565:	movb %cl, %al
0x00403567:	incb %cl
0x00403569:	testb %al, %al
0x0040356b:	movl %eax, 0x8(%ebp)
0x0040356e:	movb 0x43(%esi), %cl
0x00403571:	jne 3
0x00403573:	orl 0x4(%eax), %edi
0x00403576:	movl %edx, $0x80000000<UINT32>
0x0040357b:	movl %ecx, %ebx
0x0040357d:	shrl %edx, %cl
0x0040357f:	notl %edx
0x00403581:	andl 0x8(%eax), %edx
0x00403584:	movl %eax, %ebx
0x00403586:	popl %edi
0x00403587:	popl %esi
0x00403588:	popl %ebx
0x00403589:	leave
0x0040358a:	ret

0x004031b6:	popl %ecx
0x004031b7:	movl %ecx, 0x10(%ebx)
0x004031ba:	movl (%ecx), %eax
0x004031bc:	movl %eax, 0x10(%ebx)
0x004031bf:	cmpl (%eax), $0xffffffff<UINT8>
0x004031c2:	jne 0x004031cb
0x004031cb:	movl 0x4221fc, %ebx
0x004031d1:	movl %eax, 0x10(%ebx)
0x004031d4:	movl %edx, (%eax)
0x004031d6:	cmpl %edx, $0xffffffff<UINT8>
0x004031d9:	movl -4(%ebp), %edx
0x004031dc:	je 20
0x004031de:	movl %ecx, 0xc4(%eax,%edx,4)
0x004031e5:	movl %edi, 0x44(%eax,%edx,4)
0x004031e9:	andl %ecx, -8(%ebp)
0x004031ec:	andl %edi, %esi
0x004031ee:	orl %ecx, %edi
0x004031f0:	jne 0x00403229
0x00403229:	movl %ecx, %edx
0x0040322b:	xorl %edi, %edi
0x0040322d:	imull %ecx, %ecx, $0x204<UINT32>
0x00403233:	leal %ecx, 0x144(%ecx,%eax)
0x0040323a:	movl -12(%ebp), %ecx
0x0040323d:	movl %ecx, 0x44(%eax,%edx,4)
0x00403241:	andl %ecx, %esi
0x00403243:	jne 0x00403252
0x00403245:	movl %ecx, 0xc4(%eax,%edx,4)
0x0040324c:	pushl $0x20<UINT8>
0x0040324e:	andl %ecx, -8(%ebp)
0x00403251:	popl %edi
0x00403252:	testl %ecx, %ecx
0x00403254:	jl 0x0040325b
0x00403256:	shll %ecx
0x00403258:	incl %edi
0x00403259:	jmp 0x00403252
0x0040325b:	movl %ecx, -12(%ebp)
0x0040325e:	movl %edx, 0x4(%ecx,%edi,8)
0x00403262:	movl %ecx, (%edx)
0x00403264:	subl %ecx, -16(%ebp)
0x00403267:	movl %esi, %ecx
0x00403269:	movl -8(%ebp), %ecx
0x0040326c:	sarl %esi, $0x4<UINT8>
0x0040326f:	decl %esi
0x00403270:	cmpl %esi, $0x3f<UINT8>
0x00403273:	jle 0x00403278
0x00403275:	pushl $0x3f<UINT8>
0x00403277:	popl %esi
0x00403278:	cmpl %esi, %edi
0x0040327a:	je 0x0040338d
0x0040338d:	testl %ecx, %ecx
0x0040338f:	je 11
0x00403391:	movl (%edx), %ecx
0x00403393:	movl -4(%ecx,%edx), %ecx
0x00403397:	jmp 0x0040339c
0x0040339c:	movl %esi, -16(%ebp)
0x0040339f:	addl %edx, %ecx
0x004033a1:	leal %ecx, 0x1(%esi)
0x004033a4:	movl (%edx), %ecx
0x004033a6:	movl -4(%edx,%esi), %ecx
0x004033aa:	movl %esi, -12(%ebp)
0x004033ad:	movl %ecx, (%esi)
0x004033af:	testl %ecx, %ecx
0x004033b1:	leal %edi, 0x1(%ecx)
0x004033b4:	movl (%esi), %edi
0x004033b6:	jne 0x004033d2
0x004033b8:	cmpl %ebx, 0x422200
0x004033be:	jne 0x004033d2
0x004033d2:	movl %ecx, -4(%ebp)
0x004033d5:	movl (%eax), %ecx
0x004033d7:	leal %eax, 0x4(%edx)
0x004033da:	popl %edi
0x004033db:	popl %esi
0x004033dc:	popl %ebx
0x004033dd:	leave
0x004033de:	ret

0x004020c9:	testl %eax, %eax
0x004020cb:	popl %ecx
0x004020cc:	jne 0x004020ea
0x004020ea:	popl %esi
0x004020eb:	ret

0x0040209a:	testl %eax, %eax
0x0040209c:	popl %ecx
0x0040209d:	jne 0x004020b5
0x004020b5:	ret

0x00402087:	popl %ecx
0x00402088:	popl %ecx
0x00402089:	ret

0x00403d11:	movl %esi, %eax
0x00403d13:	popl %ecx
0x00403d14:	testl %esi, %esi
0x00403d16:	jne 0x00403d20
0x00403d20:	movl 0x4220e0, %esi
0x00403d26:	movl 0x4221e0, $0x20<UINT32>
0x00403d30:	leal %eax, 0x100(%esi)
0x00403d36:	cmpl %esi, %eax
0x00403d38:	jae 0x00403d54
0x00403d3a:	andb 0x4(%esi), $0x0<UINT8>
0x00403d3e:	orl (%esi), $0xffffffff<UINT8>
0x00403d41:	movb 0x5(%esi), $0xa<UINT8>
0x00403d45:	movl %eax, 0x4220e0
0x00403d4a:	addl %esi, $0x8<UINT8>
0x00403d4d:	addl %eax, $0x100<UINT32>
0x00403d52:	jmp 0x00403d36
0x00403d54:	leal %eax, 0x10(%esp)
0x00403d58:	pushl %eax
0x00403d59:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x00403d5f:	cmpw 0x42(%esp), $0x0<UINT8>
0x00403d65:	je 197
0x00403d6b:	movl %eax, 0x44(%esp)
0x00403d6f:	testl %eax, %eax
0x00403d71:	je 185
0x00403d77:	movl %esi, (%eax)
0x00403d79:	leal %ebp, 0x4(%eax)
0x00403d7c:	movl %eax, $0x800<UINT32>
0x00403d81:	cmpl %esi, %eax
0x00403d83:	leal %ebx, (%esi,%ebp)
0x00403d86:	jl 0x00403d8a
0x00403d8a:	cmpl 0x4221e0, %esi
0x00403d90:	jnl 0x00403de4
0x00403de4:	xorl %edi, %edi
0x00403de6:	testl %esi, %esi
0x00403de8:	jle 0x00403e30
0x00403e30:	xorl %ebx, %ebx
0x00403e32:	movl %eax, 0x4220e0
0x00403e37:	cmpl (%eax,%ebx,8), $0xffffffff<UINT8>
0x00403e3b:	leal %esi, (%eax,%ebx,8)
0x00403e3e:	jne 77
0x00403e40:	testl %ebx, %ebx
0x00403e42:	movb 0x4(%esi), $0xffffff81<UINT8>
0x00403e46:	jne 0x00403e4d
0x00403e48:	pushl $0xfffffff6<UINT8>
0x00403e4a:	popl %eax
0x00403e4b:	jmp 0x00403e57
0x00403e57:	pushl %eax
0x00403e58:	call GetStdHandle@KERNEL32.DLL
GetStdHandle@KERNEL32.DLL: API Node	
0x00403e5e:	movl %edi, %eax
0x00403e60:	cmpl %edi, $0xffffffff<UINT8>
0x00403e63:	je 23
0x00403e65:	pushl %edi
0x00403e66:	call GetFileType@KERNEL32.DLL
GetFileType@KERNEL32.DLL: API Node	
0x00403e6c:	testl %eax, %eax
0x00403e6e:	je 12
0x00403e70:	andl %eax, $0xff<UINT32>
0x00403e75:	movl (%esi), %edi
0x00403e77:	cmpl %eax, $0x2<UINT8>
0x00403e7a:	jne 6
0x00403e7c:	orb 0x4(%esi), $0x40<UINT8>
0x00403e80:	jmp 0x00403e91
0x00403e91:	incl %ebx
0x00403e92:	cmpl %ebx, $0x3<UINT8>
0x00403e95:	jl 0x00403e32
0x00403e4d:	movl %eax, %ebx
0x00403e4f:	decl %eax
0x00403e50:	negl %eax
0x00403e52:	sbbl %eax, %eax
0x00403e54:	addl %eax, $0xfffffff5<UINT8>
0x00403e97:	pushl 0x4221e0
0x00403e9d:	call SetHandleCount@KERNEL32.DLL
SetHandleCount@KERNEL32.DLL: API Node	
0x00403ea3:	popl %edi
0x00403ea4:	popl %esi
0x00403ea5:	popl %ebp
0x00403ea6:	popl %ebx
0x00403ea7:	addl %esp, $0x44<UINT8>
0x00403eaa:	ret

0x004021ac:	call 0x00403c5f
0x00403c5f:	movl %eax, 0x422088
0x00403c64:	pushl %ebx
0x00403c65:	pushl %ebp
0x00403c66:	pushl %esi
0x00403c67:	movl %esi, 0x4060e0
0x00403c6d:	pushl %edi
0x00403c6e:	movl %edi, 0x4060dc
0x00403c74:	testl %eax, %eax
0x00403c76:	jne 36
0x00403c78:	call GetCommandLineW@KERNEL32.DLL
GetCommandLineW@KERNEL32.DLL: API Node	
0x00403c7a:	testl %eax, %eax
0x00403c7c:	je 12
0x00403c7e:	movl 0x422088, $0x1<UINT32>
0x00403c88:	jmp 0x00403ca1
0x00403ca1:	call GetCommandLineW@KERNEL32.DLL
0x00403ca3:	jmp 0x00403cf7
0x00403cf7:	popl %edi
0x00403cf8:	popl %esi
0x00403cf9:	popl %ebp
0x00403cfa:	popl %ebx
0x00403cfb:	ret

0x004021b1:	movl 0x423224, %eax
0x004021b6:	call 0x00403af2
0x00403af2:	pushl %ecx
0x00403af3:	movl %eax, 0x422084
0x00403af8:	pushl %ebx
0x00403af9:	movl %ebx, 0x4060d8
0x00403aff:	pushl %ebp
0x00403b00:	pushl %esi
0x00403b01:	xorl %esi, %esi
0x00403b03:	xorl %ebp, %ebp
0x00403b05:	pushl %edi
0x00403b06:	movl %edi, 0x4060d4
0x00403b0c:	testl %eax, %eax
0x00403b0e:	jne 44
0x00403b10:	call GetEnvironmentStringsW@KERNEL32.DLL
GetEnvironmentStringsW@KERNEL32.DLL: API Node	
0x00403b12:	movl %esi, %eax
0x00403b14:	testl %esi, %esi
0x00403b16:	je 12
0x00403b18:	movl 0x422084, $0x1<UINT32>
0x00403b22:	jmp 0x00403b41
0x00403b41:	testl %esi, %esi
0x00403b43:	jne 0x00403b51
0x00403b51:	xorl %ecx, %ecx
0x00403b53:	movl %eax, %esi
0x00403b55:	cmpw (%esi), %cx
0x00403b58:	je 14
0x00403b5a:	incl %eax
0x00403b5b:	incl %eax
0x00403b5c:	cmpw (%eax), %cx
0x00403b5f:	jne 0x00403b5a
0x00403b61:	incl %eax
0x00403b62:	incl %eax
0x00403b63:	cmpw (%eax), %cx
0x00403b66:	jne 0x00403b5a
0x00403b68:	subl %eax, %esi
0x00403b6a:	incl %eax
0x00403b6b:	incl %eax
0x00403b6c:	movl %ebx, %eax
0x00403b6e:	pushl %ebx
0x00403b6f:	call 0x00402078
0x004020ce:	testl %esi, %esi
0x004020d0:	jne 0x004020d5
0x004020d5:	addl %esi, $0xf<UINT8>
0x004020d8:	andl %esi, $0xfffffff0<UINT8>
0x004020db:	pushl %esi
0x004020dc:	pushl $0x0<UINT8>
0x004020de:	pushl 0x42220c
0x004020e4:	call HeapAlloc@KERNEL32.DLL
0x00403b74:	movl %edi, %eax
0x00403b76:	popl %ecx
0x00403b77:	testl %edi, %edi
0x00403b79:	jne 0x00403b86
0x00403b86:	pushl %ebx
0x00403b87:	pushl %esi
0x00403b88:	pushl %edi
0x00403b89:	call 0x00404d10
0x00404d10:	pushl %ebp
0x00404d11:	movl %ebp, %esp
0x00404d13:	pushl %edi
0x00404d14:	pushl %esi
0x00404d15:	movl %esi, 0xc(%ebp)
0x00404d18:	movl %ecx, 0x10(%ebp)
0x00404d1b:	movl %edi, 0x8(%ebp)
0x00404d1e:	movl %eax, %ecx
0x00404d20:	movl %edx, %ecx
0x00404d22:	addl %eax, %esi
0x00404d24:	cmpl %edi, %esi
0x00404d26:	jbe 0x00404d30
0x00404d30:	testl %edi, $0x3<UINT32>
0x00404d36:	jne 20
0x00404d38:	shrl %ecx, $0x2<UINT8>
0x00404d3b:	andl %edx, $0x3<UINT8>
0x00404d3e:	cmpl %ecx, $0x8<UINT8>
0x00404d41:	jb 41
0x00404d43:	rep movsl %es:(%edi), %ds:(%esi)
0x00404d45:	jmp 0x00404e7c
0x00404e7c:	movb %al, (%esi)
0x00404e7e:	movb (%edi), %al
0x00404e80:	movb %al, 0x1(%esi)
0x00404e83:	movb 0x1(%edi), %al
0x00404e86:	movl %eax, 0x8(%ebp)
0x00404e89:	popl %esi
0x00404e8a:	popl %edi
0x00404e8b:	leave
0x00404e8c:	ret

0x00403b8e:	addl %esp, $0xc<UINT8>
0x00403b91:	jmp 0x00403b7b
0x00403b7b:	pushl %esi
0x00403b7c:	call FreeEnvironmentStringsW@KERNEL32.DLL
FreeEnvironmentStringsW@KERNEL32.DLL: API Node	
0x00403b82:	movl %eax, %edi
0x00403b84:	jmp 0x00403bf7
0x00403bf7:	popl %edi
0x00403bf8:	popl %esi
0x00403bf9:	popl %ebp
0x00403bfa:	popl %ebx
0x00403bfb:	popl %ecx
0x00403bfc:	ret

0x004021bb:	movl 0x421e10, %eax
0x004021c0:	call 0x004038c9
0x004038c9:	pushl %ebp
0x004038ca:	movl %ebp, %esp
0x004038cc:	pushl %ecx
0x004038cd:	pushl %ecx
0x004038ce:	pushl %esi
0x004038cf:	pushl %edi
0x004038d0:	movl %esi, $0x421e7c<UINT32>
0x004038d5:	pushl $0x104<UINT32>
0x004038da:	pushl %esi
0x004038db:	pushl $0x0<UINT8>
0x004038dd:	call GetModuleFileNameW@KERNEL32.DLL
GetModuleFileNameW@KERNEL32.DLL: API Node	
0x004038e3:	movl %eax, 0x423224
0x004038e8:	movl 0x421e68, %esi
0x004038ee:	movl %edi, %esi
0x004038f0:	cmpw (%eax), $0x0<UINT8>
0x004038f4:	je 2
0x004038f6:	movl %edi, %eax
0x004038f8:	leal %eax, -8(%ebp)
0x004038fb:	pushl %eax
0x004038fc:	leal %eax, -4(%ebp)
0x004038ff:	pushl %eax
0x00403900:	pushl $0x0<UINT8>
0x00403902:	pushl $0x0<UINT8>
0x00403904:	pushl %edi
0x00403905:	call 0x00403958
0x00403958:	pushl %ebp
0x00403959:	movl %ebp, %esp
0x0040395b:	movl %eax, 0x14(%ebp)
0x0040395e:	movl %edx, 0x10(%ebp)
0x00403961:	pushl %ebx
0x00403962:	pushl %esi
0x00403963:	movl %esi, 0x18(%ebp)
0x00403966:	pushl %edi
0x00403967:	andl (%esi), $0x0<UINT8>
0x0040396a:	cmpl 0xc(%ebp), $0x0<UINT8>
0x0040396e:	movl (%eax), $0x1<UINT32>
0x00403974:	movl %eax, 0x8(%ebp)
0x00403977:	je 0x00403982
0x00403982:	pushl $0x22<UINT8>
0x00403984:	popl %ebx
0x00403985:	cmpw (%eax), %bx
0x00403988:	jne 63
0x0040398a:	movw %cx, 0x2(%eax)
0x0040398e:	addl %eax, $0x2<UINT8>
0x00403991:	pushl $0x2<UINT8>
0x00403993:	popl %edi
0x00403994:	cmpw %cx, %bx
0x00403997:	je 0x004039b4
0x00403999:	testw %cx, %cx
0x0040399c:	je 22
0x0040399e:	incl (%esi)
0x004039a0:	testl %edx, %edx
0x004039a2:	je 0x004039ac
0x004039ac:	movw %cx, (%eax,%edi)
0x004039b0:	addl %eax, %edi
0x004039b2:	jmp 0x00403994
0x004039b4:	incl (%esi)
0x004039b6:	testl %edx, %edx
0x004039b8:	je 0x004039c0
0x004039c0:	cmpw (%eax), %bx
0x004039c3:	jne 61
0x004039c5:	addl %eax, %edi
0x004039c7:	jmp 0x00403a02
0x00403a02:	andl 0x18(%ebp), $0x0<UINT8>
0x00403a06:	cmpw (%eax), $0x0<UINT8>
0x00403a0a:	je 0x00403a1f
0x00403a1f:	xorl %ecx, %ecx
0x00403a21:	cmpw (%eax), %cx
0x00403a24:	je 0x00403adf
0x00403adf:	movl %eax, 0xc(%ebp)
0x00403ae2:	popl %edi
0x00403ae3:	popl %esi
0x00403ae4:	cmpl %eax, %ecx
0x00403ae6:	popl %ebx
0x00403ae7:	je 0x00403aeb
0x00403aeb:	movl %eax, 0x14(%ebp)
0x00403aee:	incl (%eax)
0x00403af0:	popl %ebp
0x00403af1:	ret

0x0040390a:	movl %eax, -8(%ebp)
0x0040390d:	movl %ecx, -4(%ebp)
0x00403910:	leal %eax, (%eax,%ecx,2)
0x00403913:	shll %eax
0x00403915:	pushl %eax
0x00403916:	call 0x00402078
0x00403134:	movl %ecx, 0x4(%ebx)
0x00403137:	movl %edi, (%ebx)
0x00403139:	andl %ecx, -8(%ebp)
0x0040313c:	andl %edi, %esi
0x0040313e:	orl %ecx, %edi
0x00403140:	jne 0x0040314d
0x0040391b:	movl %esi, %eax
0x0040391d:	addl %esp, $0x18<UINT8>
0x00403920:	testl %esi, %esi
0x00403922:	jne 0x0040392c
0x0040392c:	leal %eax, -8(%ebp)
0x0040392f:	pushl %eax
0x00403930:	leal %eax, -4(%ebp)
0x00403933:	pushl %eax
0x00403934:	movl %eax, -4(%ebp)
0x00403937:	leal %eax, (%esi,%eax,4)
0x0040393a:	pushl %eax
0x0040393b:	pushl %esi
0x0040393c:	pushl %edi
0x0040393d:	call 0x00403958
0x00403979:	movl %ecx, 0xc(%ebp)
0x0040397c:	addl 0xc(%ebp), $0x4<UINT8>
0x00403980:	movl (%ecx), %edx
0x004039a4:	movw %cx, (%eax)
0x004039a7:	movw (%edx), %cx
0x004039aa:	addl %edx, %edi
0x004039ba:	andw (%edx), $0x0<UINT8>
0x004039be:	addl %edx, %edi
0x00403ae9:	movl (%eax), %ecx
0x00403942:	movl %eax, -4(%ebp)
0x00403945:	addl %esp, $0x14<UINT8>
0x00403948:	decl %eax
0x00403949:	movl 0x421e50, %esi
0x0040394f:	popl %edi
0x00403950:	movl 0x421e48, %eax
0x00403955:	popl %esi
0x00403956:	leave
0x00403957:	ret

0x004021c5:	call 0x00403811
0x00403811:	pushl %esi
0x00403812:	movl %esi, 0x421e10
0x00403818:	pushl %edi
0x00403819:	xorl %edi, %edi
0x0040381b:	movw %ax, (%esi)
0x0040381e:	testw %ax, %ax
0x00403821:	je 0x00403837
0x00403823:	cmpw %ax, $0x3d<UINT16>
0x00403827:	je 0x0040382a
0x0040382a:	pushl %esi
0x0040382b:	call 0x0040211b
0x0040211b:	movl %ecx, 0x4(%esp)
0x0040211f:	cmpw (%ecx), $0x0<UINT8>
0x00402123:	leal %eax, 0x2(%ecx)
0x00402126:	je 10
0x00402128:	movw %dx, (%eax)
0x0040212b:	incl %eax
0x0040212c:	incl %eax
0x0040212d:	testw %dx, %dx
0x00402130:	jne 0x00402128
0x00402132:	subl %eax, %ecx
0x00402134:	sarl %eax
0x00402136:	decl %eax
0x00402137:	ret

0x00403830:	popl %ecx
0x00403831:	leal %esi, 0x2(%esi,%eax,2)
0x00403835:	jmp 0x0040381b
0x00403829:	incl %edi
0x00403837:	leal %eax, 0x4(,%edi,4)
0x0040383e:	pushl %eax
0x0040383f:	call 0x00402078
0x00403844:	movl %edi, %eax
0x00403846:	popl %ecx
0x00403847:	testl %edi, %edi
0x00403849:	movl 0x421e5c, %edi
0x0040384f:	jne 0x00403859
0x00403859:	movl %esi, 0x421e10
0x0040385f:	cmpw (%esi), $0x0<UINT8>
0x00403863:	je 65
0x00403865:	pushl %ebx
0x00403866:	pushl %esi
0x00403867:	call 0x0040211b
0x0040386c:	movl %ebx, %eax
0x0040386e:	popl %ecx
0x0040386f:	incl %ebx
0x00403870:	cmpw (%esi), $0x3d<UINT8>
0x00403874:	je 0x0040389b
0x0040389b:	cmpw (%esi,%ebx,2), $0x0<UINT8>
0x004038a0:	leal %esi, (%esi,%ebx,2)
0x004038a3:	jne 0x00403866
0x00403876:	leal %eax, (%ebx,%ebx)
0x00403879:	pushl %eax
0x0040387a:	call 0x00402078
0x0040387f:	testl %eax, %eax
0x00403881:	popl %ecx
0x00403882:	movl (%edi), %eax
0x00403884:	jne 0x0040388e
0x0040388e:	pushl %esi
0x0040388f:	pushl (%edi)
0x00403891:	call 0x00401fa4
0x00401fa4:	movl %ecx, 0x8(%esp)
0x00401fa8:	movl %eax, 0x4(%esp)
0x00401fac:	pushl %esi
0x00401fad:	movw %dx, (%ecx)
0x00401fb0:	leal %esi, 0x2(%eax)
0x00401fb3:	movw (%eax), %dx
0x00401fb6:	incl %ecx
0x00401fb7:	incl %ecx
0x00401fb8:	testw %dx, %dx
0x00401fbb:	je 0x00401fc7
0x00401fbd:	movw %dx, (%ecx)
0x00401fc0:	movw (%esi), %dx
0x00401fc3:	incl %esi
0x00401fc4:	incl %esi
0x00401fc5:	jmp 0x00401fb6
0x00401fc7:	popl %esi
0x00401fc8:	ret

0x00403896:	popl %ecx
0x00403897:	addl %edi, $0x4<UINT8>
0x0040389a:	popl %ecx
0x00403280:	movl %ecx, 0x4(%edx)
0x00403283:	cmpl %ecx, 0x8(%edx)
0x00403286:	jne 0x004032e9
0x004032e9:	movl %ecx, 0x8(%edx)
0x004032ec:	movl %edi, 0x4(%edx)
0x004032ef:	cmpl -8(%ebp), $0x0<UINT8>
0x004032f3:	movl 0x4(%ecx), %edi
0x004032f6:	movl %ecx, 0x4(%edx)
0x004032f9:	movl %edi, 0x8(%edx)
0x004032fc:	movl 0x8(%ecx), %edi
0x004032ff:	je 0x00403399
0x00403305:	movl %ecx, -12(%ebp)
0x00403308:	movl %edi, 0x4(%ecx,%esi,8)
0x0040330c:	leal %ecx, (%ecx,%esi,8)
0x0040330f:	movl 0x4(%edx), %edi
0x00403312:	movl 0x8(%edx), %ecx
0x00403315:	movl 0x4(%ecx), %edx
0x00403318:	movl %ecx, 0x4(%edx)
0x0040331b:	movl 0x8(%ecx), %edx
0x0040331e:	movl %ecx, 0x4(%edx)
0x00403321:	cmpl %ecx, 0x8(%edx)
0x00403324:	jne 100
0x00403326:	movb %cl, 0x4(%esi,%eax)
0x0040332a:	cmpl %esi, $0x20<UINT8>
0x0040332d:	movb 0xb(%ebp), %cl
0x00403330:	jnl 0x0040335b
0x0040335b:	incb %cl
0x0040335d:	cmpb 0xb(%ebp), $0x0<UINT8>
0x00403361:	movb 0x4(%esi,%eax), %cl
0x00403365:	jne 13
0x00403367:	leal %ecx, -32(%esi)
0x0040336a:	movl %edi, $0x80000000<UINT32>
0x0040336f:	shrl %edi, %cl
0x00403371:	orl 0x4(%ebx), %edi
0x00403374:	movl %ecx, -4(%ebp)
0x00403377:	leal %edi, 0xc4(%eax,%ecx,4)
0x0040337e:	leal %ecx, -32(%esi)
0x00403381:	movl %esi, $0x80000000<UINT32>
0x00403386:	shrl %esi, %cl
0x00403388:	orl (%edi), %esi
0x0040338a:	movl %ecx, -8(%ebp)
0x00403288:	cmpl %edi, $0x20<UINT8>
0x0040328b:	jnl 0x004032b8
0x004032b8:	leal %ecx, -32(%edi)
0x004032bb:	movl %ebx, $0x80000000<UINT32>
0x004032c0:	shrl %ebx, %cl
0x004032c2:	movl %ecx, -4(%ebp)
0x004032c5:	leal %edi, 0x4(%eax,%edi)
0x004032c9:	leal %ecx, 0xc4(%eax,%ecx,4)
0x004032d0:	notl %ebx
0x004032d2:	andl (%ecx), %ebx
0x004032d4:	decb (%edi)
0x004032d6:	movl -20(%ebp), %ebx
0x004032d9:	jne 11
0x004032db:	movl %ebx, 0x8(%ebp)
0x004032de:	movl %ecx, -20(%ebp)
0x004032e1:	andl 0x4(%ebx), %ecx
0x004032e4:	jmp 0x004032e9
0x00403332:	incb %cl
0x00403334:	cmpb 0xb(%ebp), $0x0<UINT8>
0x00403338:	movb 0x4(%esi,%eax), %cl
0x0040333c:	jne 11
0x0040333e:	movl %edi, $0x80000000<UINT32>
0x00403343:	movl %ecx, %esi
0x00403345:	shrl %edi, %cl
0x00403347:	orl (%ebx), %edi
0x00403349:	movl %edi, $0x80000000<UINT32>
0x0040334e:	movl %ecx, %esi
0x00403350:	shrl %edi, %cl
0x00403352:	movl %ecx, -4(%ebp)
0x00403355:	orl 0x44(%eax,%ecx,4), %edi
0x00403359:	jmp 0x0040338a
0x0040328d:	movl %ebx, $0x80000000<UINT32>
0x00403292:	movl %ecx, %edi
0x00403294:	shrl %ebx, %cl
0x00403296:	movl %ecx, -4(%ebp)
0x00403299:	leal %edi, 0x4(%eax,%edi)
0x0040329d:	notl %ebx
0x0040329f:	movl -20(%ebp), %ebx
0x004032a2:	andl %ebx, 0x44(%eax,%ecx,4)
0x004032a6:	movl 0x44(%eax,%ecx,4), %ebx
0x004032aa:	decb (%edi)
0x004032ac:	jne 56
0x004032ae:	movl %ebx, 0x8(%ebp)
0x004032b1:	movl %ecx, -20(%ebp)
0x004032b4:	andl (%ebx), %ecx
0x004032b6:	jmp 0x004032e9
0x00403116:	addl %ecx, $0xffffffe0<UINT8>
0x00403119:	orl %eax, $0xffffffff<UINT8>
0x0040311c:	xorl %esi, %esi
0x0040311e:	shrl %eax, %cl
0x00403120:	movl -12(%ebp), %esi
0x00403123:	movl -8(%ebp), %eax
0x00403399:	movl %ecx, -8(%ebp)
0x004038a5:	popl %ebx
0x004038a6:	pushl 0x421e10
0x004038ac:	call 0x004020ec
0x004020ec:	pushl %esi
0x004020ed:	movl %esi, 0x8(%esp)
0x004020f1:	testl %esi, %esi
0x004020f3:	je 36
0x004020f5:	pushl %esi
0x004020f6:	call 0x00402d80
0x00402d80:	movl %eax, 0x422204
0x00402d85:	leal %ecx, (%eax,%eax,4)
0x00402d88:	movl %eax, 0x422208
0x00402d8d:	leal %ecx, (%eax,%ecx,4)
0x00402d90:	cmpl %eax, %ecx
0x00402d92:	jae 0x00402da8
0x00402d94:	movl %edx, 0x4(%esp)
0x00402d98:	subl %edx, 0xc(%eax)
0x00402d9b:	cmpl %edx, $0x100000<UINT32>
0x00402da1:	jb 7
0x00402da3:	addl %eax, $0x14<UINT8>
0x00402da6:	jmp 0x00402d90
0x00402da8:	xorl %eax, %eax
0x00402daa:	ret

0x004020fb:	popl %ecx
0x004020fc:	testl %eax, %eax
0x004020fe:	pushl %esi
0x004020ff:	je 0x0040210b
0x0040210b:	pushl $0x0<UINT8>
0x0040210d:	pushl 0x42220c
0x00402113:	call HeapFree@KERNEL32.DLL
HeapFree@KERNEL32.DLL: API Node	
0x00402119:	popl %esi
0x0040211a:	ret

0x004038b1:	andl 0x421e10, $0x0<UINT8>
0x004038b8:	andl (%edi), $0x0<UINT8>
0x004038bb:	popl %ecx
0x004038bc:	popl %edi
0x004038bd:	movl 0x4221e4, $0x1<UINT32>
0x004038c7:	popl %esi
0x004038c8:	ret

0x004021ca:	call 0x0040358b
0x0040358b:	movl %eax, 0x4221f0
0x00403590:	testl %eax, %eax
0x00403592:	je 0x00403596
0x00403596:	pushl $0x407010<UINT32>
0x0040359b:	pushl $0x407008<UINT32>
0x004035a0:	call 0x00403673
0x00403673:	pushl %esi
0x00403674:	movl %esi, 0x8(%esp)
0x00403678:	cmpl %esi, 0xc(%esp)
0x0040367c:	jae 0x0040368b
0x0040367e:	movl %eax, (%esi)
0x00403680:	testl %eax, %eax
0x00403682:	je 0x00403686
0x00403686:	addl %esi, $0x4<UINT8>
0x00403689:	jmp 0x00403678
0x00403684:	call 0x00402b1d
0x00402b1d:	movl %eax, 0x423220
0x00402b22:	pushl %esi
0x00402b23:	pushl $0x14<UINT8>
0x00402b25:	testl %eax, %eax
0x00402b27:	popl %esi
0x00402b28:	jne 7
0x00402b2a:	movl %eax, $0x200<UINT32>
0x00402b2f:	jmp 0x00402b37
0x00402b37:	movl 0x423220, %eax
0x00402b3c:	pushl $0x4<UINT8>
0x00402b3e:	pushl %eax
0x00402b3f:	call 0x0040466a
0x0040466a:	pushl %ebx
0x0040466b:	pushl %esi
0x0040466c:	movl %esi, 0xc(%esp)
0x00404670:	pushl %edi
0x00404671:	imull %esi, 0x14(%esp)
0x00404676:	cmpl %esi, $0xffffffe0<UINT8>
0x00404679:	movl %ebx, %esi
0x0040467b:	ja 13
0x0040467d:	testl %esi, %esi
0x0040467f:	jne 0x00404684
0x00404684:	addl %esi, $0xf<UINT8>
0x00404687:	andl %esi, $0xfffffff0<UINT8>
0x0040468a:	xorl %edi, %edi
0x0040468c:	cmpl %esi, $0xffffffe0<UINT8>
0x0040468f:	ja 42
0x00404691:	cmpl %ebx, 0x42192c
0x00404697:	ja 0x004046a6
0x004046a6:	pushl %esi
0x004046a7:	pushl $0x8<UINT8>
0x004046a9:	pushl 0x42220c
0x004046af:	call HeapAlloc@KERNEL32.DLL
0x004046b5:	movl %edi, %eax
0x004046b7:	testl %edi, %edi
0x004046b9:	jne 0x004046dd
0x004046dd:	movl %eax, %edi
0x004046df:	popl %edi
0x004046e0:	popl %esi
0x004046e1:	popl %ebx
0x004046e2:	ret

0x00402b44:	popl %ecx
0x00402b45:	movl 0x422210, %eax
0x00402b4a:	testl %eax, %eax
0x00402b4c:	popl %ecx
0x00402b4d:	jne 0x00402b70
0x00402b70:	xorl %ecx, %ecx
0x00402b72:	movl %eax, $0x4216a8<UINT32>
0x00402b77:	movl %edx, 0x422210
0x00402b7d:	movl (%ecx,%edx), %eax
0x00402b80:	addl %eax, $0x20<UINT8>
0x00402b83:	addl %ecx, $0x4<UINT8>
0x00402b86:	cmpl %eax, $0x421928<UINT32>
0x00402b8b:	jl 0x00402b77
0x00402b8d:	xorl %edx, %edx
0x00402b8f:	movl %ecx, $0x4216b8<UINT32>
0x00402b94:	movl %eax, %edx
0x00402b96:	movl %esi, %edx
0x00402b98:	sarl %eax, $0x5<UINT8>
0x00402b9b:	andl %esi, $0x1f<UINT8>
0x00402b9e:	movl %eax, 0x4220e0(,%eax,4)
0x00402ba5:	movl %eax, (%eax,%esi,8)
0x00402ba8:	cmpl %eax, $0xffffffff<UINT8>
0x00402bab:	je 4
0x00402bad:	testl %eax, %eax
0x00402baf:	jne 0x00402bb4
0x00402bb4:	addl %ecx, $0x20<UINT8>
0x00402bb7:	incl %edx
0x00402bb8:	cmpl %ecx, $0x421718<UINT32>
0x00402bbe:	jl 0x00402b94
0x00402bc0:	popl %esi
0x00402bc1:	ret

0x0040368b:	popl %esi
0x0040368c:	ret

0x004035a5:	pushl $0x407004<UINT32>
0x004035aa:	pushl $0x407000<UINT32>
0x004035af:	call 0x00403673
0x004035b4:	addl %esp, $0x10<UINT8>
0x004035b7:	ret

0x004021cf:	movl %eax, 0x421e5c
0x004021d4:	movl 0x421e60, %eax
0x004021d9:	pushl %eax
0x004021da:	pushl 0x421e50
0x004021e0:	pushl 0x421e48
0x004021e6:	call 0x00401640
0x00401640:	subl %esp, $0x414<UINT32>
0x00401646:	pushl %ebx
0x00401647:	pushl %ebp
0x00401648:	pushl %esi
0x00401649:	pushl %edi
0x0040164a:	pushl $0x407334<UINT32>
0x0040164f:	call 0x00401f00
0x00401f00:	pushl %ebx
0x00401f01:	pushl %esi
0x00401f02:	movl %esi, $0x4216c8<UINT32>
0x00401f07:	pushl %edi
0x00401f08:	pushl %esi
0x00401f09:	call 0x0040225f
0x0040225f:	pushl %esi
0x00402260:	movl %esi, 0x8(%esp)
0x00402264:	pushl 0x10(%esi)
0x00402267:	call 0x00404208
0x00404208:	movl %eax, 0x4(%esp)
0x0040420c:	cmpl %eax, 0x4221e0
0x00404212:	jb 0x00404217
0x00404217:	movl %ecx, %eax
0x00404219:	andl %eax, $0x1f<UINT8>
0x0040421c:	sarl %ecx, $0x5<UINT8>
0x0040421f:	movl %ecx, 0x4220e0(,%ecx,4)
0x00404226:	movb %al, 0x4(%ecx,%eax,8)
0x0040422a:	andl %eax, $0x40<UINT8>
0x0040422d:	ret

0x0040226c:	testl %eax, %eax
0x0040226e:	popl %ecx
0x0040226f:	je 119
0x00402271:	cmpl %esi, $0x4216c8<UINT32>
0x00402277:	jne 4
0x00402279:	xorl %eax, %eax
0x0040227b:	jmp 0x00402288
0x00402288:	incl 0x421e20
0x0040228e:	testw 0xc(%esi), $0x10c<UINT16>
0x00402294:	jne 82
0x00402296:	cmpl 0x421e18(,%eax,4), $0x0<UINT8>
0x0040229e:	pushl %ebx
0x0040229f:	pushl %edi
0x004022a0:	leal %edi, 0x421e18(,%eax,4)
0x004022a7:	movl %ebx, $0x1000<UINT32>
0x004022ac:	jne 0x004022ce
0x004022ae:	pushl %ebx
0x004022af:	call 0x00402078
0x004022b4:	testl %eax, %eax
0x004022b6:	popl %ecx
0x004022b7:	movl (%edi), %eax
0x004022b9:	jne 0x004022ce
0x004022ce:	movl %edi, (%edi)
0x004022d0:	movl 0x18(%esi), %ebx
0x004022d3:	movl 0x8(%esi), %edi
0x004022d6:	movl (%esi), %edi
0x004022d8:	movl 0x4(%esi), %ebx
0x004022db:	orw 0xc(%esi), $0x1102<UINT16>
0x004022e1:	pushl $0x1<UINT8>
0x004022e3:	popl %eax
0x004022e4:	popl %edi
0x004022e5:	popl %ebx
0x004022e6:	popl %esi
0x004022e7:	ret

0x00401f0e:	movl %edi, %eax
0x00401f10:	leal %eax, 0x18(%esp)
0x00401f14:	pushl %eax
0x00401f15:	pushl 0x18(%esp)
0x00401f19:	pushl %esi
0x00401f1a:	call 0x00402329
0x00402329:	pushl %ebp
0x0040232a:	movl %ebp, %esp
0x0040232c:	subl %esp, $0x450<UINT32>
0x00402332:	movl %eax, 0xc(%ebp)
0x00402335:	addl 0xc(%ebp), $0x2<UINT8>
0x00402339:	pushl %ebx
0x0040233a:	xorl %ecx, %ecx
0x0040233c:	movw %bx, (%eax)
0x0040233f:	pushl %esi
0x00402340:	cmpw %bx, %cx
0x00402343:	pushl %edi
0x00402344:	movl -8(%ebp), %ecx
0x00402347:	movl -20(%ebp), %ecx
0x0040234a:	je 1790
0x00402350:	xorl %esi, %esi
0x00402352:	jmp 0x00402357
0x00402357:	cmpl -20(%ebp), %esi
0x0040235a:	jl 1774
0x00402360:	pushl $0x20<UINT8>
0x00402362:	popl %edi
0x00402363:	cmpw %bx, %di
0x00402366:	jb 0x0040237c
0x0040237c:	xorl %eax, %eax
0x0040237e:	movsbl %eax, 0x406434(%ecx,%eax,8)
0x00402386:	pushl $0x7<UINT8>
0x00402388:	sarl %eax, $0x4<UINT8>
0x0040238b:	popl %ecx
0x0040238c:	movl -56(%ebp), %eax
0x0040238f:	cmpl %eax, %ecx
0x00402391:	ja 1698
0x00402397:	jmp 0x004024e0
0x004024c4:	leal %eax, -20(%ebp)
0x004024c7:	movl -28(%ebp), $0x1<UINT32>
0x004024ce:	pushl %eax
0x004024cf:	pushl 0x8(%ebp)
0x004024d2:	pushl %ebx
0x004024d3:	call 0x00402a76
0x00402a76:	pushl 0x8(%esp)
0x00402a7a:	pushl 0x8(%esp)
0x00402a7e:	call 0x00404575
0x00404575:	pushl %ebp
0x00404576:	movl %ebp, %esp
0x00404578:	pushl %esi
0x00404579:	movl %esi, 0xc(%ebp)
0x0040457c:	testb 0xc(%esi), $0x40<UINT8>
0x00404580:	jne 0x00404647
0x00404586:	movl %eax, 0x10(%esi)
0x00404589:	cmpl %eax, $0xffffffff<UINT8>
0x0040458c:	je 20
0x0040458e:	movl %ecx, %eax
0x00404590:	sarl %ecx, $0x5<UINT8>
0x00404593:	andl %eax, $0x1f<UINT8>
0x00404596:	movl %ecx, 0x4220e0(,%ecx,4)
0x0040459d:	leal %eax, (%ecx,%eax,8)
0x004045a0:	jmp 0x004045a7
0x004045a7:	testb 0x4(%eax), $0xffffff80<UINT8>
0x004045ab:	je 150
0x004045b1:	pushl 0x8(%ebp)
0x004045b4:	leal %eax, 0xc(%ebp)
0x004045b7:	pushl %eax
0x004045b8:	call 0x00405315
0x00405315:	pushl %ebp
0x00405316:	movl %ebp, %esp
0x00405318:	movl %eax, 0x8(%ebp)
0x0040531b:	testl %eax, %eax
0x0040531d:	jne 0x00405321
0x00405321:	cmpl 0x422098, $0x0<UINT8>
0x00405328:	jne 18
0x0040532a:	movw %cx, 0xc(%ebp)
0x0040532e:	cmpw %cx, $0xff<UINT16>
0x00405333:	ja 57
0x00405335:	pushl $0x1<UINT8>
0x00405337:	movb (%eax), %cl
0x00405339:	popl %eax
0x0040533a:	popl %ebp
0x0040533b:	ret

0x004045bd:	popl %ecx
0x004045be:	cmpl %eax, $0xffffffff<UINT8>
0x004045c1:	popl %ecx
0x004045c2:	jne 0x004045d7
0x004045d7:	cmpl %eax, $0x1<UINT8>
0x004045da:	jne 44
0x004045dc:	decl 0x4(%esi)
0x004045df:	js 15
0x004045e1:	movl %eax, (%esi)
0x004045e3:	movb %cl, 0xc(%ebp)
0x004045e6:	movb (%eax), %cl
0x004045e8:	movzbl %eax, 0xc(%ebp)
0x004045ec:	incl (%esi)
0x004045ee:	jmp 0x004045fd
0x004045fd:	cmpl %eax, $0xffffffff<UINT8>
0x00404600:	je -52
0x00404602:	movw %ax, 0x8(%ebp)
0x00404606:	jmp 0x00404667
0x00404667:	popl %esi
0x00404668:	popl %ebp
0x00404669:	ret

0x00402a83:	popl %ecx
0x00402a84:	cmpw %ax, $0xffffffff<UINT16>
0x00402a88:	movl %eax, 0x10(%esp)
0x00402a8c:	popl %ecx
0x00402a8d:	jne 0x00402a93
0x00402a93:	incl (%eax)
0x00402a95:	ret

0x004024d8:	addl %esp, $0xc<UINT8>
0x004024db:	jmp 0x00402a39
0x00402a39:	movl %eax, 0xc(%ebp)
0x00402a3c:	addl 0xc(%ebp), $0x2<UINT8>
0x00402a40:	xorl %esi, %esi
0x00402a42:	movw %bx, (%eax)
0x00402a45:	cmpw %bx, %si
0x00402a48:	jne 0x00402354
0x00402354:	movl %ecx, -56(%ebp)
0x00402368:	cmpw %bx, $0x78<UINT8>
0x0040236c:	ja 0x0040237c
0x0040236e:	movzwl %eax, %bx
0x00402371:	movb %al, 0x406414(%eax)
0x00402377:	andl %eax, $0xf<UINT8>
0x0040237a:	jmp 0x0040237e
0x00402a4e:	movl %eax, -20(%ebp)
0x00402a51:	popl %edi
0x00402a52:	popl %esi
0x00402a53:	popl %ebx
0x00402a54:	leave
0x00402a55:	ret

0x00401f1f:	pushl %esi
0x00401f20:	pushl %edi
0x00401f21:	movl %ebx, %eax
0x00401f23:	call 0x004022ec
0x004022ec:	cmpl 0x4(%esp), $0x0<UINT8>
0x004022f1:	pushl %esi
0x004022f2:	je 34
0x004022f4:	movl %esi, 0xc(%esp)
0x004022f8:	testb 0xd(%esi), $0x10<UINT8>
0x004022fc:	je 41
0x004022fe:	pushl %esi
0x004022ff:	call 0x00404269
0x00404269:	pushl %ebx
0x0040426a:	pushl %esi
0x0040426b:	movl %esi, 0xc(%esp)
0x0040426f:	xorl %ebx, %ebx
0x00404271:	pushl %edi
0x00404272:	movl %eax, 0xc(%esi)
0x00404275:	movl %ecx, %eax
0x00404277:	andl %ecx, $0x3<UINT8>
0x0040427a:	cmpb %cl, $0x2<UINT8>
0x0040427d:	jne 55
0x0040427f:	testw %ax, $0x108<UINT16>
0x00404283:	je 49
0x00404285:	movl %eax, 0x8(%esi)
0x00404288:	movl %edi, (%esi)
0x0040428a:	subl %edi, %eax
0x0040428c:	testl %edi, %edi
0x0040428e:	jle 38
0x00404290:	pushl %edi
0x00404291:	pushl %eax
0x00404292:	pushl 0x10(%esi)
0x00404295:	call 0x004047d9
0x004047d9:	pushl %ebp
0x004047da:	movl %ebp, %esp
0x004047dc:	subl %esp, $0x414<UINT32>
0x004047e2:	movl %ecx, 0x8(%ebp)
0x004047e5:	pushl %ebx
0x004047e6:	cmpl %ecx, 0x4221e0
0x004047ec:	pushl %esi
0x004047ed:	pushl %edi
0x004047ee:	jae 377
0x004047f4:	movl %eax, %ecx
0x004047f6:	movl %esi, %ecx
0x004047f8:	sarl %eax, $0x5<UINT8>
0x004047fb:	andl %esi, $0x1f<UINT8>
0x004047fe:	leal %ebx, 0x4220e0(,%eax,4)
0x00404805:	shll %esi, $0x3<UINT8>
0x00404808:	movl %eax, (%ebx)
0x0040480a:	movb %al, 0x4(%eax,%esi)
0x0040480e:	testb %al, $0x1<UINT8>
0x00404810:	je 343
0x00404816:	xorl %edi, %edi
0x00404818:	cmpl 0x10(%ebp), %edi
0x0040481b:	movl -8(%ebp), %edi
0x0040481e:	movl -16(%ebp), %edi
0x00404821:	jne 0x0040482a
0x0040482a:	testb %al, $0x20<UINT8>
0x0040482c:	je 0x0040483a
0x0040483a:	movl %eax, (%ebx)
0x0040483c:	addl %eax, %esi
0x0040483e:	testb 0x4(%eax), $0xffffff80<UINT8>
0x00404842:	je 193
0x00404848:	movl %eax, 0xc(%ebp)
0x0040484b:	cmpl 0x10(%ebp), %edi
0x0040484e:	movl -4(%ebp), %eax
0x00404851:	movl 0x8(%ebp), %edi
0x00404854:	jbe 231
0x0040485a:	leal %eax, -1044(%ebp)
0x00404860:	movl %ecx, -4(%ebp)
0x00404863:	subl %ecx, 0xc(%ebp)
0x00404866:	cmpl %ecx, 0x10(%ebp)
0x00404869:	jae 0x00404894
0x0040486b:	movl %ecx, -4(%ebp)
0x0040486e:	incl -4(%ebp)
0x00404871:	movb %cl, (%ecx)
0x00404873:	cmpb %cl, $0xa<UINT8>
0x00404876:	jne 0x0040487f
0x00404878:	incl -16(%ebp)
0x0040487b:	movb (%eax), $0xd<UINT8>
0x0040487e:	incl %eax
0x0040487f:	movb (%eax), %cl
0x00404881:	incl %eax
0x00404882:	movl %ecx, %eax
0x00404884:	leal %edx, -1044(%ebp)
0x0040488a:	subl %ecx, %edx
0x0040488c:	cmpl %ecx, $0x400<UINT32>
0x00404892:	jl 0x00404860
0x00404894:	movl %edi, %eax
0x00404896:	leal %eax, -1044(%ebp)
0x0040489c:	subl %edi, %eax
0x0040489e:	leal %eax, -12(%ebp)
0x004048a1:	pushl $0x0<UINT8>
0x004048a3:	pushl %eax
0x004048a4:	leal %eax, -1044(%ebp)
0x004048aa:	pushl %edi
0x004048ab:	pushl %eax
0x004048ac:	movl %eax, (%ebx)
0x004048ae:	pushl (%eax,%esi)
0x004048b1:	call WriteFile@KERNEL32.DLL
WriteFile@KERNEL32.DLL: API Node	
0x004048b7:	testl %eax, %eax
0x004048b9:	je 67
0x004048bb:	movl %eax, -12(%ebp)
0x004048be:	addl -8(%ebp), %eax
0x004048c1:	cmpl %eax, %edi
0x004048c3:	jl 0x004048d0
0x004048d0:	xorl %edi, %edi
0x004048d2:	movl %eax, -8(%ebp)
0x004048d5:	cmpl %eax, %edi
0x004048d7:	jne 0x00404968
0x004048dd:	cmpl 0x8(%ebp), %edi
0x004048e0:	je 0x00404941
0x00404941:	movl %eax, (%ebx)
0x00404943:	testb 0x4(%eax,%esi), $0x40<UINT8>
0x00404948:	je 12
0x0040494a:	movl %eax, 0xc(%ebp)
0x0040494d:	cmpb (%eax), $0x1a<UINT8>
0x00404950:	je -307
0x00404956:	movl 0x421e2c, $0x1c<UINT32>
0x00404960:	movl 0x421e30, %edi
0x00404966:	jmp 0x0040497e
0x0040497e:	orl %eax, $0xffffffff<UINT8>
0x00404981:	popl %edi
0x00404982:	popl %esi
0x00404983:	popl %ebx
0x00404984:	leave
0x00404985:	ret

0x0040429a:	addl %esp, $0xc<UINT8>
0x0040429d:	cmpl %eax, %edi
0x0040429f:	jne 0x004042af
0x004042af:	orl 0xc(%esi), $0x20<UINT8>
0x004042b3:	orl %ebx, $0xffffffff<UINT8>
0x004042b6:	movl %eax, 0x8(%esi)
0x004042b9:	andl 0x4(%esi), $0x0<UINT8>
0x004042bd:	movl (%esi), %eax
0x004042bf:	popl %edi
0x004042c0:	movl %eax, %ebx
0x004042c2:	popl %esi
0x004042c3:	popl %ebx
0x004042c4:	ret

0x00402304:	andb 0xd(%esi), $0xffffffee<UINT8>
0x00402308:	andl 0x18(%esi), $0x0<UINT8>
0x0040230c:	andl (%esi), $0x0<UINT8>
0x0040230f:	andl 0x8(%esi), $0x0<UINT8>
0x00402313:	popl %ecx
0x00402314:	popl %esi
0x00402315:	ret

0x00401f28:	addl %esp, $0x18<UINT8>
0x00401f2b:	movl %eax, %ebx
0x00401f2d:	popl %edi
0x00401f2e:	popl %esi
0x00401f2f:	popl %ebx
0x00401f30:	ret

0x00401654:	pushl $0x4072e8<UINT32>
0x00401659:	call 0x00401f00
0x00404968:	subl %eax, -16(%ebp)
0x0040496b:	jmp 0x00404981
0x0040165e:	pushl $0x407284<UINT32>
0x00401663:	call 0x00401f00
0x00401668:	pushl $0x407274<UINT32>
0x0040166d:	call 0x00401890
0x00401890:	subl %esp, $0x214<UINT32>
0x00401896:	movl %eax, 0x218(%esp)
0x0040189d:	pushl %ebx
0x0040189e:	pushl %eax
0x0040189f:	leal %ecx, 0x14(%esp)
0x004018a3:	xorl %ebx, %ebx
0x004018a5:	pushl $0x42160c<UINT32>
0x004018aa:	pushl %ecx
0x004018ab:	movl 0x14(%esp), %ebx
0x004018af:	movl 0x10(%esp), %ebx
0x004018b3:	call 0x00401fc9
0x00401fc9:	pushl %ebp
0x00401fca:	movl %ebp, %esp
0x00401fcc:	subl %esp, $0x20<UINT8>
0x00401fcf:	movl %eax, 0x8(%ebp)
0x00401fd2:	pushl %esi
0x00401fd3:	movl -24(%ebp), %eax
0x00401fd6:	movl -32(%ebp), %eax
0x00401fd9:	leal %eax, 0x10(%ebp)
0x00401fdc:	movl -20(%ebp), $0x42<UINT32>
0x00401fe3:	pushl %eax
0x00401fe4:	leal %eax, -32(%ebp)
0x00401fe7:	pushl 0xc(%ebp)
0x00401fea:	movl -28(%ebp), $0x7fffffff<UINT32>
0x00401ff1:	pushl %eax
0x00401ff2:	call 0x00402329
0x00404647:	addl 0x4(%esi), $0xfffffffe<UINT8>
0x0040464b:	js 13
0x0040464d:	movl %ecx, (%esi)
0x0040464f:	movl %eax, 0x8(%ebp)
0x00404652:	movw (%ecx), %ax
0x00404655:	addl (%esi), $0x2<UINT8>
0x00404658:	jmp 0x00404667
0x0040239e:	orl -16(%ebp), $0xffffffff<UINT8>
0x004023a2:	movl -52(%ebp), %esi
0x004023a5:	movl -48(%ebp), %esi
0x004023a8:	movl -40(%ebp), %esi
0x004023ab:	movl -24(%ebp), %esi
0x004023ae:	movl -4(%ebp), %esi
0x004023b1:	movl -28(%ebp), %esi
0x004023b4:	jmp 0x00402a39
0x004024e0:	movzwl %eax, %bx
0x004024e3:	cmpl %eax, $0x67<UINT8>
0x004024e6:	jg 0x00402725
0x00402725:	subl %eax, $0x69<UINT8>
0x00402728:	je 213
0x0040272e:	subl %eax, $0x5<UINT8>
0x00402731:	je 162
0x00402737:	decl %eax
0x00402738:	je 136
0x0040273e:	decl %eax
0x0040273f:	je 85
0x00402741:	subl %eax, $0x3<UINT8>
0x00402744:	je 0x0040252e
0x0040252e:	movl %esi, -16(%ebp)
0x00402531:	cmpl %esi, $0xffffffff<UINT8>
0x00402534:	jne 5
0x00402536:	movl %esi, $0x7fffffff<UINT32>
0x0040253b:	leal %eax, 0x10(%ebp)
0x0040253e:	pushl %eax
0x0040253f:	call 0x00402b00
0x00402b00:	movl %eax, 0x4(%esp)
0x00402b04:	addl (%eax), $0x4<UINT8>
0x00402b07:	movl %eax, (%eax)
0x00402b09:	movl %eax, -4(%eax)
0x00402b0c:	ret

0x00402544:	testb -4(%ebp), $0x20<UINT8>
0x00402548:	popl %ecx
0x00402549:	movl %ecx, %eax
0x0040254b:	movl -12(%ebp), %ecx
0x0040254e:	je 0x00402766
0x00402766:	testl %ecx, %ecx
0x00402768:	jne 0x00402773
0x00402773:	movl -28(%ebp), $0x1<UINT32>
0x0040277a:	movl %eax, %ecx
0x0040277c:	movl %edx, %esi
0x0040277e:	decl %esi
0x0040277f:	testl %edx, %edx
0x00402781:	je 10
0x00402783:	cmpw (%eax), $0x0<UINT8>
0x00402787:	je 0x0040278d
0x00402789:	incl %eax
0x0040278a:	incl %eax
0x0040278b:	jmp 0x0040277c
0x0040278d:	subl %eax, %ecx
0x0040278f:	sarl %eax
0x00402791:	jmp 0x00402677
0x00402677:	movl -8(%ebp), %eax
0x0040267a:	jmp 0x0040292f
0x0040292f:	cmpl -48(%ebp), $0x0<UINT8>
0x00402933:	jne 256
0x00402939:	movl %ebx, -4(%ebp)
0x0040293c:	testb %bl, $0x40<UINT8>
0x0040293f:	je 0x0040296d
0x0040296d:	movl %esi, -40(%ebp)
0x00402970:	subl %esi, -24(%ebp)
0x00402973:	subl %esi, -8(%ebp)
0x00402976:	testb %bl, $0xc<UINT8>
0x00402979:	jne 18
0x0040297b:	leal %eax, -20(%ebp)
0x0040297e:	pushl %eax
0x0040297f:	pushl 0x8(%ebp)
0x00402982:	pushl %esi
0x00402983:	pushl $0x20<UINT8>
0x00402985:	call 0x00402a96
0x00402a96:	pushl %esi
0x00402a97:	pushl %edi
0x00402a98:	movl %edi, 0x10(%esp)
0x00402a9c:	movl %eax, %edi
0x00402a9e:	decl %edi
0x00402a9f:	testl %eax, %eax
0x00402aa1:	jle 0x00402ac4
0x00402ac4:	popl %edi
0x00402ac5:	popl %esi
0x00402ac6:	ret

0x0040298a:	addl %esp, $0x10<UINT8>
0x0040298d:	leal %eax, -20(%ebp)
0x00402990:	pushl %eax
0x00402991:	leal %eax, -32(%ebp)
0x00402994:	pushl 0x8(%ebp)
0x00402997:	pushl -24(%ebp)
0x0040299a:	pushl %eax
0x0040299b:	call 0x00402ac7
0x00402ac7:	pushl %ebx
0x00402ac8:	movl %ebx, 0xc(%esp)
0x00402acc:	movl %eax, %ebx
0x00402ace:	decl %ebx
0x00402acf:	pushl %esi
0x00402ad0:	pushl %edi
0x00402ad1:	testl %eax, %eax
0x00402ad3:	jle 0x00402afc
0x00402afc:	popl %edi
0x00402afd:	popl %esi
0x00402afe:	popl %ebx
0x00402aff:	ret

0x004029a0:	addl %esp, $0x10<UINT8>
0x004029a3:	testb %bl, $0x8<UINT8>
0x004029a6:	je 0x004029bf
0x004029bf:	cmpl -28(%ebp), $0x0<UINT8>
0x004029c3:	jne 0x00402a0c
0x00402a0c:	leal %eax, -20(%ebp)
0x00402a0f:	pushl %eax
0x00402a10:	pushl 0x8(%ebp)
0x00402a13:	pushl -8(%ebp)
0x00402a16:	pushl -12(%ebp)
0x00402a19:	call 0x00402ac7
0x00402ad5:	movl %edi, 0x1c(%esp)
0x00402ad9:	movl %esi, 0x10(%esp)
0x00402add:	movw %ax, (%esi)
0x00402ae0:	pushl %edi
0x00402ae1:	pushl 0x1c(%esp)
0x00402ae5:	incl %esi
0x00402ae6:	incl %esi
0x00402ae7:	pushl %eax
0x00402ae8:	call 0x00402a76
0x00402aed:	addl %esp, $0xc<UINT8>
0x00402af0:	cmpl (%edi), $0xffffffff<UINT8>
0x00402af3:	je 7
0x00402af5:	movl %eax, %ebx
0x00402af7:	decl %ebx
0x00402af8:	testl %eax, %eax
0x00402afa:	jg 0x00402add
0x00402a1e:	addl %esp, $0x10<UINT8>
0x00402a21:	testb -4(%ebp), $0x4<UINT8>
0x00402a25:	je 0x00402a39
0x00401ff7:	addl %esp, $0xc<UINT8>
0x00401ffa:	decl -28(%ebp)
0x00401ffd:	movl %esi, %eax
0x00401fff:	js 11
0x00402001:	movl %eax, -32(%ebp)
0x00402004:	andb (%eax), $0x0<UINT8>
0x00402007:	incl -32(%ebp)
0x0040200a:	jmp 0x00402019
0x00402019:	decl -28(%ebp)
0x0040201c:	js 8
0x0040201e:	movl %eax, -32(%ebp)
0x00402021:	andb (%eax), $0x0<UINT8>
0x00402024:	jmp 0x00402033
0x00402033:	movl %eax, %esi
0x00402035:	popl %esi
0x00402036:	leave
0x00402037:	ret

0x004018b8:	addl %esp, $0xc<UINT8>
0x004018bb:	leal %edx, 0x8(%esp)
0x004018bf:	leal %eax, 0x10(%esp)
0x004018c3:	pushl %edx
0x004018c4:	pushl %eax
0x004018c5:	pushl $0x80000001<UINT32>
0x004018ca:	call RegCreateKeyW@ADVAPI32.dll
RegCreateKeyW@ADVAPI32.dll: API Node	
0x004018d0:	testl %eax, %eax
0x004018d2:	jne 36
0x004018d4:	movl %eax, 0x8(%esp)
0x004018d8:	leal %ecx, 0xc(%esp)
0x004018dc:	leal %edx, 0x4(%esp)
0x004018e0:	pushl %ecx
0x004018e1:	pushl %edx
0x004018e2:	pushl %ebx
0x004018e3:	pushl %ebx
0x004018e4:	pushl $0x4215f0<UINT32>
0x004018e9:	pushl %eax
0x004018ea:	movl 0x24(%esp), $0x4<UINT32>
0x004018f2:	call RegQueryValueExW@ADVAPI32.dll
RegQueryValueExW@ADVAPI32.dll: API Node	
0x004018f8:	cmpl 0x4(%esp), %ebx
0x004018fc:	jne 511
0x00401902:	pushl %esi
0x00401903:	pushl %edi
0x00401904:	pushl $0x3e8<UINT32>
0x00401909:	pushl $0x40<UINT8>
0x0040190b:	call LocalAlloc@KERNEL32.DLL
LocalAlloc@KERNEL32.DLL: API Node	
0x00401911:	movl %esi, %eax
0x00401913:	pushl $0x4215d4<UINT32>
0x00401918:	leal %edi, 0x12(%esi)
0x0040191b:	call LoadLibraryW@KERNEL32.DLL
LoadLibraryW@KERNEL32.DLL: API Node	
0x00401921:	movl (%esi), $0x80c808d0<UINT32>
0x00401927:	movw 0xa(%esi), %bx
0x0040192b:	movw 0xc(%esi), %bx
0x0040192f:	movw 0xe(%esi), $0x138<UINT16>
0x00401935:	movw 0x10(%esi), $0xb4<UINT16>
0x0040193b:	movw 0x8(%esi), $0x4<UINT16>
0x00401941:	movw (%edi), %bx
0x00401944:	addl %edi, $0x2<UINT8>
0x00401947:	pushl $0x4215b0<UINT32>
0x0040194c:	movw (%edi), %bx
0x0040194f:	addl %edi, $0x2<UINT8>
0x00401952:	pushl %edi
0x00401953:	call 0x00401ed0
0x00401ed0:	pushl %esi
0x00401ed1:	pushl %edi
0x00401ed2:	movl %edi, 0x10(%esp)
0x00401ed6:	pushl %edi
0x00401ed7:	call 0x0040211b
0x00401edc:	movl %esi, %eax
0x00401ede:	movl %eax, 0x10(%esp)
0x00401ee2:	pushl %edi
0x00401ee3:	pushl %eax
0x00401ee4:	incl %esi
0x00401ee5:	call 0x00401fa4
0x00401eea:	addl %esp, $0xc<UINT8>
0x00401eed:	movl %eax, %esi
0x00401eef:	popl %edi
0x00401ef0:	popl %esi
0x00401ef1:	ret

0x00401958:	leal %edi, (%edi,%eax,2)
0x0040195b:	pushl $0x421594<UINT32>
0x00401960:	movw (%edi), $0x8<UINT16>
0x00401965:	addl %edi, $0x2<UINT8>
0x00401968:	pushl %edi
0x00401969:	call 0x00401ed0
0x0040196e:	leal %eax, (%edi,%eax,2)
0x00401971:	pushl %eax
0x00401972:	call 0x00401ec0
0x00401ec0:	movl %eax, 0x4(%esp)
0x00401ec4:	addl %eax, $0x3<UINT8>
0x00401ec7:	andb %al, $0xfffffffc<UINT8>
0x00401ec9:	ret

0x00401977:	leal %edi, 0x12(%eax)
0x0040197a:	movw 0x8(%eax), $0xc9<UINT16>
0x00401980:	movw 0xa(%eax), $0x9f<UINT16>
0x00401986:	movw 0xc(%eax), $0x32<UINT16>
0x0040198c:	movw 0xe(%eax), $0xe<UINT16>
0x00401992:	movw 0x10(%eax), $0x1<UINT16>
0x00401998:	movl (%eax), $0x50010000<UINT32>
0x0040199e:	movw (%edi), $0xffffffff<UINT16>
0x004019a3:	addl %edi, $0x2<UINT8>
0x004019a6:	pushl $0x421584<UINT32>
0x004019ab:	movw (%edi), $0x80<UINT16>
0x004019b0:	addl %edi, $0x2<UINT8>
0x004019b3:	pushl %edi
0x004019b4:	call 0x00401ed0
0x004019b9:	leal %eax, (%edi,%eax,2)
0x004019bc:	movw (%eax), %bx
0x004019bf:	addl %eax, $0x2<UINT8>
0x004019c2:	pushl %eax
0x004019c3:	call 0x00401ec0
0x004019c8:	leal %edi, 0x12(%eax)
0x004019cb:	movw 0x8(%eax), $0xff<UINT16>
0x004019d1:	movw 0xa(%eax), $0x9f<UINT16>
0x004019d7:	movw 0xc(%eax), $0x32<UINT16>
0x004019dd:	movw 0xe(%eax), $0xe<UINT16>
0x004019e3:	movw 0x10(%eax), $0x2<UINT16>
0x004019e9:	movl (%eax), $0x50010000<UINT32>
0x004019ef:	movw (%edi), $0xffffffff<UINT16>
0x004019f4:	addl %edi, $0x2<UINT8>
0x004019f7:	pushl $0x421570<UINT32>
0x004019fc:	movw (%edi), $0x80<UINT16>
0x00401a01:	addl %edi, $0x2<UINT8>
0x00401a04:	pushl %edi
0x00401a05:	call 0x00401ed0
0x00401a0a:	leal %eax, (%edi,%eax,2)
0x00401a0d:	movw (%eax), %bx
0x00401a10:	addl %eax, $0x2<UINT8>
0x00401a13:	pushl %eax
0x00401a14:	call 0x00401ec0
0x00401a19:	movl %ebx, $0x7<UINT32>
0x00401a1e:	leal %edi, 0x12(%eax)
0x00401a21:	movw 0x8(%eax), %bx
0x00401a25:	movw 0xa(%eax), $0x9f<UINT16>
0x00401a2b:	movw 0xc(%eax), $0x32<UINT16>
0x00401a31:	movw 0xe(%eax), $0xe<UINT16>
0x00401a37:	movw 0x10(%eax), $0x1f5<UINT16>
0x00401a3d:	movl (%eax), $0x50010000<UINT32>
0x00401a43:	movw (%edi), $0xffffffff<UINT16>
0x00401a48:	addl %edi, $0x2<UINT8>
0x00401a4b:	movw (%edi), $0x80<UINT16>
0x00401a50:	addl %edi, $0x2<UINT8>
0x00401a53:	pushl $0x421560<UINT32>
0x00401a58:	pushl %edi
0x00401a59:	call 0x00401ed0
0x00401a5e:	leal %eax, (%edi,%eax,2)
0x00401a61:	movw (%eax), $0x0<UINT16>
0x00401a66:	addl %eax, $0x2<UINT8>
0x00401a69:	pushl %eax
0x00401a6a:	call 0x00401ec0
0x00401a6f:	leal %edi, 0x12(%eax)
0x00401a72:	pushl $0x42154c<UINT32>
0x00401a77:	pushl %edi
0x00401a78:	movw 0x8(%eax), %bx
0x00401a7c:	movw 0xa(%eax), %bx
0x00401a80:	movw 0xc(%eax), $0x12a<UINT16>
0x00401a86:	movw 0xe(%eax), $0x90<UINT16>
0x00401a8c:	movw 0x10(%eax), $0x1f4<UINT16>
0x00401a92:	movl (%eax), $0x50a11844<UINT32>
0x00401a98:	call 0x00401ed0
0x00401a9d:	addl %esp, $0x40<UINT8>
0x00401aa0:	leal %edi, (%edi,%eax,2)
0x00401aa3:	pushl $0x421570<UINT32>
0x00401aa8:	pushl %edi
0x00401aa9:	call 0x00401ed0
0x00401aae:	movl %ecx, 0x22c(%esp)
0x00401ab5:	addl %esp, $0x8<UINT8>
0x00401ab8:	movw (%edi,%eax,2), $0x0<UINT16>
0x00401abe:	pushl %ecx
0x00401abf:	pushl $0x401b20<UINT32>
0x00401ac4:	pushl $0x0<UINT8>
0x00401ac6:	pushl %esi
0x00401ac7:	pushl $0x0<UINT8>
0x00401ac9:	call DialogBoxIndirectParamW@USER32.dll
DialogBoxIndirectParamW@USER32.dll: API Node	
0x00401acf:	pushl %esi
0x00401ad0:	movl 0x10(%esp), %eax
0x00401ad4:	call LocalFree@KERNEL32.DLL
LocalFree@KERNEL32.DLL: API Node	
0x00401ada:	movl %eax, 0xc(%esp)
0x00401ade:	popl %edi
0x00401adf:	testl %eax, %eax
0x00401ae1:	popl %esi
0x00401ae2:	je 27
