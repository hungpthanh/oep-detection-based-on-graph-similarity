0x0042a5f0:	pusha
0x0042a5f1:	movl %esi, $0x41c000<UINT32>
0x0042a5f6:	leal %edi, -110592(%esi)
0x0042a5fc:	pushl %edi
0x0042a5fd:	orl %ebp, $0xffffffff<UINT8>
0x0042a600:	jmp 0x0042a612
0x0042a612:	movl %ebx, (%esi)
0x0042a614:	subl %esi, $0xfffffffc<UINT8>
0x0042a617:	adcl %ebx, %ebx
0x0042a619:	jb 0x0042a608
0x0042a608:	movb %al, (%esi)
0x0042a60a:	incl %esi
0x0042a60b:	movb (%edi), %al
0x0042a60d:	incl %edi
0x0042a60e:	addl %ebx, %ebx
0x0042a610:	jne 0x0042a619
0x0042a61b:	movl %eax, $0x1<UINT32>
0x0042a620:	addl %ebx, %ebx
0x0042a622:	jne 0x0042a62b
0x0042a62b:	adcl %eax, %eax
0x0042a62d:	addl %ebx, %ebx
0x0042a62f:	jae 0x0042a620
0x0042a631:	jne 0x0042a63c
0x0042a63c:	xorl %ecx, %ecx
0x0042a63e:	subl %eax, $0x3<UINT8>
0x0042a641:	jb 0x0042a650
0x0042a650:	addl %ebx, %ebx
0x0042a652:	jne 0x0042a65b
0x0042a65b:	adcl %ecx, %ecx
0x0042a65d:	addl %ebx, %ebx
0x0042a65f:	jne 0x0042a668
0x0042a668:	adcl %ecx, %ecx
0x0042a66a:	jne 0x0042a68c
0x0042a68c:	cmpl %ebp, $0xfffff300<UINT32>
0x0042a692:	adcl %ecx, $0x1<UINT8>
0x0042a695:	leal %edx, (%edi,%ebp)
0x0042a698:	cmpl %ebp, $0xfffffffc<UINT8>
0x0042a69b:	jbe 0x0042a6ac
0x0042a69d:	movb %al, (%edx)
0x0042a69f:	incl %edx
0x0042a6a0:	movb (%edi), %al
0x0042a6a2:	incl %edi
0x0042a6a3:	decl %ecx
0x0042a6a4:	jne 0x0042a69d
0x0042a6a6:	jmp 0x0042a60e
0x0042a643:	shll %eax, $0x8<UINT8>
0x0042a646:	movb %al, (%esi)
0x0042a648:	incl %esi
0x0042a649:	xorl %eax, $0xffffffff<UINT8>
0x0042a64c:	je 0x0042a6c2
0x0042a64e:	movl %ebp, %eax
0x0042a6ac:	movl %eax, (%edx)
0x0042a6ae:	addl %edx, $0x4<UINT8>
0x0042a6b1:	movl (%edi), %eax
0x0042a6b3:	addl %edi, $0x4<UINT8>
0x0042a6b6:	subl %ecx, $0x4<UINT8>
0x0042a6b9:	ja 0x0042a6ac
0x0042a6bb:	addl %edi, %ecx
0x0042a6bd:	jmp 0x0042a60e
0x0042a654:	movl %ebx, (%esi)
0x0042a656:	subl %esi, $0xfffffffc<UINT8>
0x0042a659:	adcl %ebx, %ebx
0x0042a66c:	incl %ecx
0x0042a66d:	addl %ebx, %ebx
0x0042a66f:	jne 0x0042a678
0x0042a678:	adcl %ecx, %ecx
0x0042a67a:	addl %ebx, %ebx
0x0042a67c:	jae 0x0042a66d
0x0042a67e:	jne 0x0042a689
0x0042a689:	addl %ecx, $0x2<UINT8>
0x0042a661:	movl %ebx, (%esi)
0x0042a663:	subl %esi, $0xfffffffc<UINT8>
0x0042a666:	adcl %ebx, %ebx
0x0042a633:	movl %ebx, (%esi)
0x0042a635:	subl %esi, $0xfffffffc<UINT8>
0x0042a638:	adcl %ebx, %ebx
0x0042a63a:	jae 0x0042a620
0x0042a624:	movl %ebx, (%esi)
0x0042a626:	subl %esi, $0xfffffffc<UINT8>
0x0042a629:	adcl %ebx, %ebx
0x0042a680:	movl %ebx, (%esi)
0x0042a682:	subl %esi, $0xfffffffc<UINT8>
0x0042a685:	adcl %ebx, %ebx
0x0042a687:	jae 0x0042a66d
0x0042a671:	movl %ebx, (%esi)
0x0042a673:	subl %esi, $0xfffffffc<UINT8>
0x0042a676:	adcl %ebx, %ebx
0x0042a6c2:	popl %esi
0x0042a6c3:	movl %edi, %esi
0x0042a6c5:	movl %ecx, $0x62c<UINT32>
0x0042a6ca:	movb %al, (%edi)
0x0042a6cc:	incl %edi
0x0042a6cd:	subb %al, $0xffffffe8<UINT8>
0x0042a6cf:	cmpb %al, $0x1<UINT8>
0x0042a6d1:	ja 0x0042a6ca
0x0042a6d3:	cmpb (%edi), $0x9<UINT8>
0x0042a6d6:	jne 0x0042a6ca
0x0042a6d8:	movl %eax, (%edi)
0x0042a6da:	movb %bl, 0x4(%edi)
0x0042a6dd:	shrw %ax, $0x8<UINT8>
0x0042a6e1:	roll %eax, $0x10<UINT8>
0x0042a6e4:	xchgb %ah, %al
0x0042a6e6:	subl %eax, %edi
0x0042a6e8:	subb %bl, $0xffffffe8<UINT8>
0x0042a6eb:	addl %eax, %esi
0x0042a6ed:	movl (%edi), %eax
0x0042a6ef:	addl %edi, $0x5<UINT8>
0x0042a6f2:	movb %al, %bl
0x0042a6f4:	loop 0x0042a6cf
0x0042a6f6:	leal %edi, 0x27000(%esi)
0x0042a6fc:	movl %eax, (%edi)
0x0042a6fe:	orl %eax, %eax
0x0042a700:	je 0x0042a73e
0x0042a702:	movl %ebx, 0x4(%edi)
0x0042a705:	leal %eax, 0x2a54c(%eax,%esi)
0x0042a70c:	addl %ebx, %esi
0x0042a70e:	pushl %eax
0x0042a70f:	addl %edi, $0x8<UINT8>
0x0042a712:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0042a718:	xchgl %ebp, %eax
0x0042a719:	movb %al, (%edi)
0x0042a71b:	incl %edi
0x0042a71c:	orb %al, %al
0x0042a71e:	je 0x0042a6fc
0x0042a720:	movl %ecx, %edi
0x0042a722:	pushl %edi
0x0042a723:	decl %eax
0x0042a724:	repn scasb %al, %es:(%edi)
0x0042a726:	pushl %ebp
0x0042a727:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0042a72d:	orl %eax, %eax
0x0042a72f:	je 7
0x0042a731:	movl (%ebx), %eax
0x0042a733:	addl %ebx, $0x4<UINT8>
0x0042a736:	jmp 0x0042a719
GetProcAddress@KERNEL32.DLL: API Node	
0x0042a73e:	addl %edi, $0x4<UINT8>
0x0042a741:	leal %ebx, -4(%esi)
0x0042a744:	xorl %eax, %eax
0x0042a746:	movb %al, (%edi)
0x0042a748:	incl %edi
0x0042a749:	orl %eax, %eax
0x0042a74b:	je 0x0042a76f
0x0042a74d:	cmpb %al, $0xffffffef<UINT8>
0x0042a74f:	ja 0x0042a762
0x0042a751:	addl %ebx, %eax
0x0042a753:	movl %eax, (%ebx)
0x0042a755:	xchgb %ah, %al
0x0042a757:	roll %eax, $0x10<UINT8>
0x0042a75a:	xchgb %ah, %al
0x0042a75c:	addl %eax, %esi
0x0042a75e:	movl (%ebx), %eax
0x0042a760:	jmp 0x0042a744
0x0042a762:	andb %al, $0xf<UINT8>
0x0042a764:	shll %eax, $0x10<UINT8>
0x0042a767:	movw %ax, (%edi)
0x0042a76a:	addl %edi, $0x2<UINT8>
0x0042a76d:	jmp 0x0042a751
0x0042a76f:	movl %ebp, 0x2a5fc(%esi)
0x0042a775:	leal %edi, -4096(%esi)
0x0042a77b:	movl %ebx, $0x1000<UINT32>
0x0042a780:	pushl %eax
0x0042a781:	pushl %esp
0x0042a782:	pushl $0x4<UINT8>
0x0042a784:	pushl %ebx
0x0042a785:	pushl %edi
0x0042a786:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0042a788:	leal %eax, 0x21f(%edi)
0x0042a78e:	andb (%eax), $0x7f<UINT8>
0x0042a791:	andb 0x28(%eax), $0x7f<UINT8>
0x0042a795:	popl %eax
0x0042a796:	pushl %eax
0x0042a797:	pushl %esp
0x0042a798:	pushl %eax
0x0042a799:	pushl %ebx
0x0042a79a:	pushl %edi
0x0042a79b:	call VirtualProtect@kernel32.dll
0x0042a79d:	popl %eax
0x0042a79e:	popa
0x0042a79f:	leal %eax, -128(%esp)
0x0042a7a3:	pushl $0x0<UINT8>
0x0042a7a5:	cmpl %esp, %eax
0x0042a7a7:	jne 0x0042a7a3
0x0042a7a9:	subl %esp, $0xffffff80<UINT8>
0x0042a7ac:	jmp 0x0040699f
0x0040699f:	call 0x0040d4ea
0x0040d4ea:	pushl %ebp
0x0040d4eb:	movl %ebp, %esp
0x0040d4ed:	subl %esp, $0x14<UINT8>
0x0040d4f0:	andl -12(%ebp), $0x0<UINT8>
0x0040d4f4:	andl -8(%ebp), $0x0<UINT8>
0x0040d4f8:	movl %eax, 0x421368
0x0040d4fd:	pushl %esi
0x0040d4fe:	pushl %edi
0x0040d4ff:	movl %edi, $0xbb40e64e<UINT32>
0x0040d504:	movl %esi, $0xffff0000<UINT32>
0x0040d509:	cmpl %eax, %edi
0x0040d50b:	je 0x0040d51a
0x0040d51a:	leal %eax, -12(%ebp)
0x0040d51d:	pushl %eax
0x0040d51e:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040d524:	movl %eax, -8(%ebp)
0x0040d527:	xorl %eax, -12(%ebp)
0x0040d52a:	movl -4(%ebp), %eax
0x0040d52d:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040d533:	xorl -4(%ebp), %eax
0x0040d536:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040d53c:	xorl -4(%ebp), %eax
0x0040d53f:	leal %eax, -20(%ebp)
0x0040d542:	pushl %eax
0x0040d543:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040d549:	movl %ecx, -16(%ebp)
0x0040d54c:	leal %eax, -4(%ebp)
0x0040d54f:	xorl %ecx, -20(%ebp)
0x0040d552:	xorl %ecx, -4(%ebp)
0x0040d555:	xorl %ecx, %eax
0x0040d557:	cmpl %ecx, %edi
0x0040d559:	jne 0x0040d562
0x0040d562:	testl %esi, %ecx
0x0040d564:	jne 0x0040d572
0x0040d572:	movl 0x421368, %ecx
0x0040d578:	notl %ecx
0x0040d57a:	movl 0x42136c, %ecx
0x0040d580:	popl %edi
0x0040d581:	popl %esi
0x0040d582:	movl %esp, %ebp
0x0040d584:	popl %ebp
0x0040d585:	ret

0x004069a4:	jmp 0x00406824
0x00406824:	pushl $0x14<UINT8>
0x00406826:	pushl $0x41fd38<UINT32>
0x0040682b:	call 0x004076e0
0x004076e0:	pushl $0x407740<UINT32>
0x004076e5:	pushl %fs:0
0x004076ec:	movl %eax, 0x10(%esp)
0x004076f0:	movl 0x10(%esp), %ebp
0x004076f4:	leal %ebp, 0x10(%esp)
0x004076f8:	subl %esp, %eax
0x004076fa:	pushl %ebx
0x004076fb:	pushl %esi
0x004076fc:	pushl %edi
0x004076fd:	movl %eax, 0x421368
0x00407702:	xorl -4(%ebp), %eax
0x00407705:	xorl %eax, %ebp
0x00407707:	pushl %eax
0x00407708:	movl -24(%ebp), %esp
0x0040770b:	pushl -8(%ebp)
0x0040770e:	movl %eax, -4(%ebp)
0x00407711:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00407718:	movl -8(%ebp), %eax
0x0040771b:	leal %eax, -16(%ebp)
0x0040771e:	movl %fs:0, %eax
0x00407724:	ret

0x00406830:	pushl $0x1<UINT8>
0x00406832:	call 0x0040d49d
0x0040d49d:	pushl %ebp
0x0040d49e:	movl %ebp, %esp
0x0040d4a0:	movl %eax, 0x8(%ebp)
0x0040d4a3:	movl 0x4226c0, %eax
0x0040d4a8:	popl %ebp
0x0040d4a9:	ret

0x00406837:	popl %ecx
0x00406838:	movl %eax, $0x5a4d<UINT32>
0x0040683d:	cmpw 0x400000, %ax
0x00406844:	je 0x0040684a
0x0040684a:	movl %eax, 0x40003c
0x0040684f:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00406859:	jne -21
0x0040685b:	movl %ecx, $0x10b<UINT32>
0x00406860:	cmpw 0x400018(%eax), %cx
0x00406867:	jne -35
0x00406869:	xorl %ebx, %ebx
0x0040686b:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00406872:	jbe 9
0x00406874:	cmpl 0x4000e8(%eax), %ebx
0x0040687a:	setne %bl
0x0040687d:	movl -28(%ebp), %ebx
0x00406880:	call 0x0040a32d
0x0040a32d:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x0040a333:	xorl %ecx, %ecx
0x0040a335:	movl 0x422d18, %eax
0x0040a33a:	testl %eax, %eax
0x0040a33c:	setne %cl
0x0040a33f:	movl %eax, %ecx
0x0040a341:	ret

0x00406885:	testl %eax, %eax
0x00406887:	jne 0x00406891
0x00406891:	call 0x0040a215
0x0040a215:	call 0x004053ec
0x004053ec:	pushl %esi
0x004053ed:	pushl $0x0<UINT8>
0x004053ef:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x004053f5:	movl %esi, %eax
0x004053f7:	pushl %esi
0x004053f8:	call 0x0040a320
0x0040a320:	pushl %ebp
0x0040a321:	movl %ebp, %esp
0x0040a323:	movl %eax, 0x8(%ebp)
0x0040a326:	movl 0x422d10, %eax
0x0040a32b:	popl %ebp
0x0040a32c:	ret

0x004053fd:	pushl %esi
0x004053fe:	call 0x004079f9
0x004079f9:	pushl %ebp
0x004079fa:	movl %ebp, %esp
0x004079fc:	movl %eax, 0x8(%ebp)
0x004079ff:	movl 0x4225ac, %eax
0x00407a04:	popl %ebp
0x00407a05:	ret

0x00405403:	pushl %esi
0x00405404:	call 0x0040a7a5
0x0040a7a5:	pushl %ebp
0x0040a7a6:	movl %ebp, %esp
0x0040a7a8:	movl %eax, 0x8(%ebp)
0x0040a7ab:	movl 0x423044, %eax
0x0040a7b0:	popl %ebp
0x0040a7b1:	ret

0x00405409:	pushl %esi
0x0040540a:	call 0x0040a7bf
0x0040a7bf:	pushl %ebp
0x0040a7c0:	movl %ebp, %esp
0x0040a7c2:	movl %eax, 0x8(%ebp)
0x0040a7c5:	movl 0x423048, %eax
0x0040a7ca:	movl 0x42304c, %eax
0x0040a7cf:	movl 0x423050, %eax
0x0040a7d4:	movl 0x423054, %eax
0x0040a7d9:	popl %ebp
0x0040a7da:	ret

0x0040540f:	pushl %esi
0x00405410:	call 0x0040a794
0x0040a794:	pushl $0x40a760<UINT32>
0x0040a799:	call EncodePointer@KERNEL32.DLL
0x0040a79f:	movl 0x423040, %eax
0x0040a7a4:	ret

0x00405415:	pushl %esi
0x00405416:	call 0x0040a9d0
0x0040a9d0:	pushl %ebp
0x0040a9d1:	movl %ebp, %esp
0x0040a9d3:	movl %eax, 0x8(%ebp)
0x0040a9d6:	movl 0x42305c, %eax
0x0040a9db:	popl %ebp
0x0040a9dc:	ret

0x0040541b:	addl %esp, $0x18<UINT8>
0x0040541e:	popl %esi
0x0040541f:	jmp 0x00409070
0x00409070:	pushl %esi
0x00409071:	pushl %edi
0x00409072:	pushl $0x41aab0<UINT32>
0x00409077:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0040907d:	movl %esi, 0x4140cc
0x00409083:	movl %edi, %eax
0x00409085:	pushl $0x41bec8<UINT32>
0x0040908a:	pushl %edi
0x0040908b:	call GetProcAddress@KERNEL32.DLL
0x0040908d:	xorl %eax, 0x421368
0x00409093:	pushl $0x41bed4<UINT32>
0x00409098:	pushl %edi
0x00409099:	movl 0x4232c0, %eax
0x0040909e:	call GetProcAddress@KERNEL32.DLL
0x004090a0:	xorl %eax, 0x421368
0x004090a6:	pushl $0x41bedc<UINT32>
0x004090ab:	pushl %edi
0x004090ac:	movl 0x4232c4, %eax
0x004090b1:	call GetProcAddress@KERNEL32.DLL
0x004090b3:	xorl %eax, 0x421368
0x004090b9:	pushl $0x41bee8<UINT32>
0x004090be:	pushl %edi
0x004090bf:	movl 0x4232c8, %eax
0x004090c4:	call GetProcAddress@KERNEL32.DLL
0x004090c6:	xorl %eax, 0x421368
0x004090cc:	pushl $0x41bef4<UINT32>
0x004090d1:	pushl %edi
0x004090d2:	movl 0x4232cc, %eax
0x004090d7:	call GetProcAddress@KERNEL32.DLL
0x004090d9:	xorl %eax, 0x421368
0x004090df:	pushl $0x41bf10<UINT32>
0x004090e4:	pushl %edi
0x004090e5:	movl 0x4232d0, %eax
0x004090ea:	call GetProcAddress@KERNEL32.DLL
0x004090ec:	xorl %eax, 0x421368
0x004090f2:	pushl $0x41bf20<UINT32>
0x004090f7:	pushl %edi
0x004090f8:	movl 0x4232d4, %eax
0x004090fd:	call GetProcAddress@KERNEL32.DLL
0x004090ff:	xorl %eax, 0x421368
0x00409105:	pushl $0x41bf34<UINT32>
0x0040910a:	pushl %edi
0x0040910b:	movl 0x4232d8, %eax
0x00409110:	call GetProcAddress@KERNEL32.DLL
0x00409112:	xorl %eax, 0x421368
0x00409118:	pushl $0x41bf4c<UINT32>
0x0040911d:	pushl %edi
0x0040911e:	movl 0x4232dc, %eax
0x00409123:	call GetProcAddress@KERNEL32.DLL
0x00409125:	xorl %eax, 0x421368
0x0040912b:	pushl $0x41bf64<UINT32>
0x00409130:	pushl %edi
0x00409131:	movl 0x4232e0, %eax
0x00409136:	call GetProcAddress@KERNEL32.DLL
0x00409138:	xorl %eax, 0x421368
0x0040913e:	pushl $0x41bf78<UINT32>
0x00409143:	pushl %edi
0x00409144:	movl 0x4232e4, %eax
0x00409149:	call GetProcAddress@KERNEL32.DLL
0x0040914b:	xorl %eax, 0x421368
0x00409151:	pushl $0x41bf98<UINT32>
0x00409156:	pushl %edi
0x00409157:	movl 0x4232e8, %eax
0x0040915c:	call GetProcAddress@KERNEL32.DLL
0x0040915e:	xorl %eax, 0x421368
0x00409164:	pushl $0x41bfb0<UINT32>
0x00409169:	pushl %edi
0x0040916a:	movl 0x4232ec, %eax
0x0040916f:	call GetProcAddress@KERNEL32.DLL
0x00409171:	xorl %eax, 0x421368
0x00409177:	pushl $0x41bfc8<UINT32>
0x0040917c:	pushl %edi
0x0040917d:	movl 0x4232f0, %eax
0x00409182:	call GetProcAddress@KERNEL32.DLL
0x00409184:	xorl %eax, 0x421368
0x0040918a:	pushl $0x41bfdc<UINT32>
0x0040918f:	pushl %edi
0x00409190:	movl 0x4232f4, %eax
0x00409195:	call GetProcAddress@KERNEL32.DLL
0x00409197:	xorl %eax, 0x421368
0x0040919d:	movl 0x4232f8, %eax
0x004091a2:	pushl $0x41bff0<UINT32>
0x004091a7:	pushl %edi
0x004091a8:	call GetProcAddress@KERNEL32.DLL
0x004091aa:	xorl %eax, 0x421368
0x004091b0:	pushl $0x41c00c<UINT32>
0x004091b5:	pushl %edi
0x004091b6:	movl 0x4232fc, %eax
0x004091bb:	call GetProcAddress@KERNEL32.DLL
0x004091bd:	xorl %eax, 0x421368
0x004091c3:	pushl $0x41c02c<UINT32>
0x004091c8:	pushl %edi
0x004091c9:	movl 0x423300, %eax
0x004091ce:	call GetProcAddress@KERNEL32.DLL
0x004091d0:	xorl %eax, 0x421368
0x004091d6:	pushl $0x41c048<UINT32>
0x004091db:	pushl %edi
0x004091dc:	movl 0x423304, %eax
0x004091e1:	call GetProcAddress@KERNEL32.DLL
0x004091e3:	xorl %eax, 0x421368
0x004091e9:	pushl $0x41c068<UINT32>
0x004091ee:	pushl %edi
0x004091ef:	movl 0x423308, %eax
0x004091f4:	call GetProcAddress@KERNEL32.DLL
0x004091f6:	xorl %eax, 0x421368
0x004091fc:	pushl $0x41c07c<UINT32>
0x00409201:	pushl %edi
0x00409202:	movl 0x42330c, %eax
0x00409207:	call GetProcAddress@KERNEL32.DLL
0x00409209:	xorl %eax, 0x421368
0x0040920f:	pushl $0x41c098<UINT32>
0x00409214:	pushl %edi
0x00409215:	movl 0x423310, %eax
0x0040921a:	call GetProcAddress@KERNEL32.DLL
0x0040921c:	xorl %eax, 0x421368
0x00409222:	pushl $0x41c0ac<UINT32>
0x00409227:	pushl %edi
0x00409228:	movl 0x423318, %eax
0x0040922d:	call GetProcAddress@KERNEL32.DLL
0x0040922f:	xorl %eax, 0x421368
0x00409235:	pushl $0x41c0bc<UINT32>
0x0040923a:	pushl %edi
0x0040923b:	movl 0x423314, %eax
0x00409240:	call GetProcAddress@KERNEL32.DLL
0x00409242:	xorl %eax, 0x421368
0x00409248:	pushl $0x41c0cc<UINT32>
0x0040924d:	pushl %edi
0x0040924e:	movl 0x42331c, %eax
0x00409253:	call GetProcAddress@KERNEL32.DLL
0x00409255:	xorl %eax, 0x421368
0x0040925b:	pushl $0x41c0dc<UINT32>
0x00409260:	pushl %edi
0x00409261:	movl 0x423320, %eax
0x00409266:	call GetProcAddress@KERNEL32.DLL
0x00409268:	xorl %eax, 0x421368
0x0040926e:	pushl $0x41c0ec<UINT32>
0x00409273:	pushl %edi
0x00409274:	movl 0x423324, %eax
0x00409279:	call GetProcAddress@KERNEL32.DLL
0x0040927b:	xorl %eax, 0x421368
0x00409281:	pushl $0x41c108<UINT32>
0x00409286:	pushl %edi
0x00409287:	movl 0x423328, %eax
0x0040928c:	call GetProcAddress@KERNEL32.DLL
0x0040928e:	xorl %eax, 0x421368
0x00409294:	pushl $0x41c11c<UINT32>
0x00409299:	pushl %edi
0x0040929a:	movl 0x42332c, %eax
0x0040929f:	call GetProcAddress@KERNEL32.DLL
0x004092a1:	xorl %eax, 0x421368
0x004092a7:	pushl $0x41c12c<UINT32>
0x004092ac:	pushl %edi
0x004092ad:	movl 0x423330, %eax
0x004092b2:	call GetProcAddress@KERNEL32.DLL
0x004092b4:	xorl %eax, 0x421368
0x004092ba:	pushl $0x41c140<UINT32>
0x004092bf:	pushl %edi
0x004092c0:	movl 0x423334, %eax
0x004092c5:	call GetProcAddress@KERNEL32.DLL
0x004092c7:	xorl %eax, 0x421368
0x004092cd:	movl 0x423338, %eax
0x004092d2:	pushl $0x41c150<UINT32>
0x004092d7:	pushl %edi
0x004092d8:	call GetProcAddress@KERNEL32.DLL
0x004092da:	xorl %eax, 0x421368
0x004092e0:	pushl $0x41c170<UINT32>
0x004092e5:	pushl %edi
0x004092e6:	movl 0x42333c, %eax
0x004092eb:	call GetProcAddress@KERNEL32.DLL
0x004092ed:	xorl %eax, 0x421368
0x004092f3:	popl %edi
0x004092f4:	movl 0x423340, %eax
0x004092f9:	popl %esi
0x004092fa:	ret

0x0040a21a:	call 0x00406b77
0x00406b77:	pushl %esi
0x00406b78:	pushl %edi
0x00406b79:	movl %esi, $0x421388<UINT32>
0x00406b7e:	movl %edi, $0x422458<UINT32>
0x00406b83:	cmpl 0x4(%esi), $0x1<UINT8>
0x00406b87:	jne 22
0x00406b89:	pushl $0x0<UINT8>
0x00406b8b:	movl (%esi), %edi
0x00406b8d:	addl %edi, $0x18<UINT8>
0x00406b90:	pushl $0xfa0<UINT32>
0x00406b95:	pushl (%esi)
0x00406b97:	call 0x00409002
0x00409002:	pushl %ebp
0x00409003:	movl %ebp, %esp
0x00409005:	movl %eax, 0x4232d0
0x0040900a:	xorl %eax, 0x421368
0x00409010:	je 13
0x00409012:	pushl 0x10(%ebp)
0x00409015:	pushl 0xc(%ebp)
0x00409018:	pushl 0x8(%ebp)
0x0040901b:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x0040901d:	popl %ebp
0x0040901e:	ret

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
