0x00593780:	pusha
0x00593781:	movl %esi, $0x557000<UINT32>
0x00593786:	leal %edi, -1400832(%esi)
0x0059378c:	pushl %edi
0x0059378d:	orl %ebp, $0xffffffff<UINT8>
0x00593790:	jmp 0x005937a2
0x005937a2:	movl %ebx, (%esi)
0x005937a4:	subl %esi, $0xfffffffc<UINT8>
0x005937a7:	adcl %ebx, %ebx
0x005937a9:	jb 0x00593798
0x00593798:	movb %al, (%esi)
0x0059379a:	incl %esi
0x0059379b:	movb (%edi), %al
0x0059379d:	incl %edi
0x0059379e:	addl %ebx, %ebx
0x005937a0:	jne 0x005937a9
0x005937ab:	movl %eax, $0x1<UINT32>
0x005937b0:	addl %ebx, %ebx
0x005937b2:	jne 0x005937bb
0x005937bb:	adcl %eax, %eax
0x005937bd:	addl %ebx, %ebx
0x005937bf:	jae 0x005937cc
0x005937c1:	jne 0x005937eb
0x005937eb:	xorl %ecx, %ecx
0x005937ed:	subl %eax, $0x3<UINT8>
0x005937f0:	jb 0x00593803
0x00593803:	addl %ebx, %ebx
0x00593805:	jne 0x0059380e
0x0059380e:	jb 0x005937dc
0x00593810:	incl %ecx
0x00593811:	addl %ebx, %ebx
0x00593813:	jne 0x0059381c
0x0059381c:	jb 0x005937dc
0x0059381e:	addl %ebx, %ebx
0x00593820:	jne 0x00593829
0x00593829:	adcl %ecx, %ecx
0x0059382b:	addl %ebx, %ebx
0x0059382d:	jae 0x0059381e
0x0059382f:	jne 0x0059383a
0x0059383a:	addl %ecx, $0x2<UINT8>
0x0059383d:	cmpl %ebp, $0xfffffb00<UINT32>
0x00593843:	adcl %ecx, $0x2<UINT8>
0x00593846:	leal %edx, (%edi,%ebp)
0x00593849:	cmpl %ebp, $0xfffffffc<UINT8>
0x0059384c:	jbe 0x0059385c
0x0059384e:	movb %al, (%edx)
0x00593850:	incl %edx
0x00593851:	movb (%edi), %al
0x00593853:	incl %edi
0x00593854:	decl %ecx
0x00593855:	jne 0x0059384e
0x00593857:	jmp 0x0059379e
0x005937f2:	shll %eax, $0x8<UINT8>
0x005937f5:	movb %al, (%esi)
0x005937f7:	incl %esi
0x005937f8:	xorl %eax, $0xffffffff<UINT8>
0x005937fb:	je 0x00593872
0x005937fd:	sarl %eax
0x005937ff:	movl %ebp, %eax
0x00593801:	jmp 0x0059380e
0x005937dc:	addl %ebx, %ebx
0x005937de:	jne 0x005937e7
0x005937e7:	adcl %ecx, %ecx
0x005937e9:	jmp 0x0059383d
0x0059385c:	movl %eax, (%edx)
0x0059385e:	addl %edx, $0x4<UINT8>
0x00593861:	movl (%edi), %eax
0x00593863:	addl %edi, $0x4<UINT8>
0x00593866:	subl %ecx, $0x4<UINT8>
0x00593869:	ja 0x0059385c
0x0059386b:	addl %edi, %ecx
0x0059386d:	jmp 0x0059379e
0x005937e0:	movl %ebx, (%esi)
0x005937e2:	subl %esi, $0xfffffffc<UINT8>
0x005937e5:	adcl %ebx, %ebx
0x005937b4:	movl %ebx, (%esi)
0x005937b6:	subl %esi, $0xfffffffc<UINT8>
0x005937b9:	adcl %ebx, %ebx
0x005937cc:	decl %eax
0x005937cd:	addl %ebx, %ebx
0x005937cf:	jne 0x005937d8
0x005937d8:	adcl %eax, %eax
0x005937da:	jmp 0x005937b0
0x005937c3:	movl %ebx, (%esi)
0x005937c5:	subl %esi, $0xfffffffc<UINT8>
0x005937c8:	adcl %ebx, %ebx
0x005937ca:	jb 0x005937eb
0x00593815:	movl %ebx, (%esi)
0x00593817:	subl %esi, $0xfffffffc<UINT8>
0x0059381a:	adcl %ebx, %ebx
0x005937d1:	movl %ebx, (%esi)
0x005937d3:	subl %esi, $0xfffffffc<UINT8>
0x005937d6:	adcl %ebx, %ebx
0x00593831:	movl %ebx, (%esi)
0x00593833:	subl %esi, $0xfffffffc<UINT8>
0x00593836:	adcl %ebx, %ebx
0x00593838:	jae 0x0059381e
0x00593822:	movl %ebx, (%esi)
0x00593824:	subl %esi, $0xfffffffc<UINT8>
0x00593827:	adcl %ebx, %ebx
0x00593807:	movl %ebx, (%esi)
0x00593809:	subl %esi, $0xfffffffc<UINT8>
0x0059380c:	adcl %ebx, %ebx
0x00593872:	popl %esi
0x00593873:	movl %edi, %esi
0x00593875:	movl %ecx, $0x11fb<UINT32>
0x0059387a:	movb %al, (%edi)
0x0059387c:	incl %edi
0x0059387d:	subb %al, $0xffffffe8<UINT8>
0x0059387f:	cmpb %al, $0x1<UINT8>
0x00593881:	ja 0x0059387a
0x00593883:	cmpb (%edi), $0x16<UINT8>
0x00593886:	jne 0x0059387a
0x00593888:	movl %eax, (%edi)
0x0059388a:	movb %bl, 0x4(%edi)
0x0059388d:	shrw %ax, $0x8<UINT8>
0x00593891:	roll %eax, $0x10<UINT8>
0x00593894:	xchgb %ah, %al
0x00593896:	subl %eax, %edi
0x00593898:	subb %bl, $0xffffffe8<UINT8>
0x0059389b:	addl %eax, %esi
0x0059389d:	movl (%edi), %eax
0x0059389f:	addl %edi, $0x5<UINT8>
0x005938a2:	movb %al, %bl
0x005938a4:	loop 0x0059387f
0x005938a6:	leal %edi, 0x190000(%esi)
0x005938ac:	movl %eax, (%edi)
0x005938ae:	orl %eax, %eax
0x005938b0:	je 0x005938f7
0x005938b2:	movl %ebx, 0x4(%edi)
0x005938b5:	leal %eax, 0x194708(%eax,%esi)
0x005938bc:	addl %ebx, %esi
0x005938be:	pushl %eax
0x005938bf:	addl %edi, $0x8<UINT8>
0x005938c2:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x005938c8:	xchgl %ebp, %eax
0x005938c9:	movb %al, (%edi)
0x005938cb:	incl %edi
0x005938cc:	orb %al, %al
0x005938ce:	je 0x005938ac
0x005938d0:	movl %ecx, %edi
0x005938d2:	jns 0x005938db
0x005938db:	pushl %edi
0x005938dc:	decl %eax
0x005938dd:	repn scasb %al, %es:(%edi)
0x005938df:	pushl %ebp
0x005938e0:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x005938e6:	orl %eax, %eax
0x005938e8:	je 7
0x005938ea:	movl (%ebx), %eax
0x005938ec:	addl %ebx, $0x4<UINT8>
0x005938ef:	jmp 0x005938c9
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x005938d4:	movzwl %eax, (%edi)
0x005938d7:	incl %edi
0x005938d8:	pushl %eax
0x005938d9:	incl %edi
0x005938da:	movl %ecx, $0xaef24857<UINT32>
0x005938f7:	movl %ebp, 0x1947fc(%esi)
0x005938fd:	leal %edi, -4096(%esi)
0x00593903:	movl %ebx, $0x1000<UINT32>
0x00593908:	pushl %eax
0x00593909:	pushl %esp
0x0059390a:	pushl $0x4<UINT8>
0x0059390c:	pushl %ebx
0x0059390d:	pushl %edi
0x0059390e:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00593910:	leal %eax, 0x207(%edi)
0x00593916:	andb (%eax), $0x7f<UINT8>
0x00593919:	andb 0x28(%eax), $0x7f<UINT8>
0x0059391d:	popl %eax
0x0059391e:	pushl %eax
0x0059391f:	pushl %esp
0x00593920:	pushl %eax
0x00593921:	pushl %ebx
0x00593922:	pushl %edi
0x00593923:	call VirtualProtect@kernel32.dll
0x00593925:	popl %eax
0x00593926:	popa
0x00593927:	leal %eax, -128(%esp)
0x0059392b:	pushl $0x0<UINT8>
0x0059392d:	cmpl %esp, %eax
0x0059392f:	jne 0x0059392b
0x00593931:	subl %esp, $0xffffff80<UINT8>
0x00593934:	jmp 0x0040c983
0x0040c983:	call 0x00417557
0x00417557:	movl %edi, %edi
0x00417559:	pushl %ebp
0x0041755a:	movl %ebp, %esp
0x0041755c:	subl %esp, $0x10<UINT8>
0x0041755f:	movl %eax, 0x43d1b0
0x00417564:	andl -8(%ebp), $0x0<UINT8>
0x00417568:	andl -4(%ebp), $0x0<UINT8>
0x0041756c:	pushl %ebx
0x0041756d:	pushl %edi
0x0041756e:	movl %edi, $0xbb40e64e<UINT32>
0x00417573:	movl %ebx, $0xffff0000<UINT32>
0x00417578:	cmpl %eax, %edi
0x0041757a:	je 0x00417589
0x00417589:	pushl %esi
0x0041758a:	leal %eax, -8(%ebp)
0x0041758d:	pushl %eax
0x0041758e:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x00417594:	movl %esi, -4(%ebp)
0x00417597:	xorl %esi, -8(%ebp)
0x0041759a:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x004175a0:	xorl %esi, %eax
0x004175a2:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x004175a8:	xorl %esi, %eax
0x004175aa:	call GetTickCount@KERNEL32.DLL
GetTickCount@KERNEL32.DLL: API Node	
0x004175b0:	xorl %esi, %eax
0x004175b2:	leal %eax, -16(%ebp)
0x004175b5:	pushl %eax
0x004175b6:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x004175bc:	movl %eax, -12(%ebp)
0x004175bf:	xorl %eax, -16(%ebp)
0x004175c2:	xorl %esi, %eax
0x004175c4:	cmpl %esi, %edi
0x004175c6:	jne 0x004175cf
0x004175cf:	testl %ebx, %esi
0x004175d1:	jne 0x004175da
0x004175da:	movl 0x43d1b0, %esi
0x004175e0:	notl %esi
0x004175e2:	movl 0x43d1b4, %esi
0x004175e8:	popl %esi
0x004175e9:	popl %edi
0x004175ea:	popl %ebx
0x004175eb:	leave
0x004175ec:	ret

0x0040c988:	jmp 0x0040c805
0x0040c805:	pushl $0x58<UINT8>
0x0040c807:	pushl $0x43aaa8<UINT32>
0x0040c80c:	call 0x0040d020
0x0040d020:	pushl $0x40d0b0<UINT32>
0x0040d025:	pushl %fs:0
0x0040d02c:	movl %eax, 0x10(%esp)
0x0040d030:	movl 0x10(%esp), %ebp
0x0040d034:	leal %ebp, 0x10(%esp)
0x0040d038:	subl %esp, %eax
0x0040d03a:	pushl %ebx
0x0040d03b:	pushl %esi
0x0040d03c:	pushl %edi
0x0040d03d:	movl %eax, 0x43d1b0
0x0040d042:	xorl -4(%ebp), %eax
0x0040d045:	xorl %eax, %ebp
0x0040d047:	pushl %eax
0x0040d048:	movl -24(%ebp), %esp
0x0040d04b:	pushl -8(%ebp)
0x0040d04e:	movl %eax, -4(%ebp)
0x0040d051:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040d058:	movl -8(%ebp), %eax
0x0040d05b:	leal %eax, -16(%ebp)
0x0040d05e:	movl %fs:0, %eax
0x0040d064:	ret

0x0040c811:	xorl %esi, %esi
0x0040c813:	movl -4(%ebp), %esi
0x0040c816:	leal %eax, -104(%ebp)
0x0040c819:	pushl %eax
0x0040c81a:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x0040c820:	pushl $0xfffffffe<UINT8>
0x0040c822:	popl %edi
0x0040c823:	movl -4(%ebp), %edi
0x0040c826:	movl %eax, $0x5a4d<UINT32>
0x0040c82b:	cmpw 0x400000, %ax
0x0040c832:	jne 56
0x0040c834:	movl %eax, 0x40003c
0x0040c839:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x0040c843:	jne 39
0x0040c845:	movl %ecx, $0x10b<UINT32>
0x0040c84a:	cmpw 0x400018(%eax), %cx
0x0040c851:	jne 25
0x0040c853:	cmpl 0x400074(%eax), $0xe<UINT8>
0x0040c85a:	jbe 16
0x0040c85c:	xorl %ecx, %ecx
0x0040c85e:	cmpl 0x4000e8(%eax), %esi
0x0040c864:	setne %cl
0x0040c867:	movl -28(%ebp), %ecx
0x0040c86a:	jmp 0x0040c86f
0x0040c86f:	xorl %ebx, %ebx
0x0040c871:	incl %ebx
0x0040c872:	pushl %ebx
0x0040c873:	call 0x00412045
0x00412045:	movl %edi, %edi
0x00412047:	pushl %ebp
0x00412048:	movl %ebp, %esp
0x0041204a:	xorl %eax, %eax
0x0041204c:	cmpl 0x8(%ebp), %eax
0x0041204f:	pushl $0x0<UINT8>
0x00412051:	sete %al
0x00412054:	pushl $0x1000<UINT32>
0x00412059:	pushl %eax
0x0041205a:	call HeapCreate@KERNEL32.DLL
HeapCreate@KERNEL32.DLL: API Node	
0x00412060:	movl 0x53ece8, %eax
0x00412065:	testl %eax, %eax
0x00412067:	jne 0x0041206b
0x0041206b:	xorl %eax, %eax
0x0041206d:	incl %eax
0x0041206e:	movl 0x53f41c, %eax
0x00412073:	popl %ebp
0x00412074:	ret

0x0040c878:	popl %ecx
0x0040c879:	testl %eax, %eax
0x0040c87b:	jne 0x0040c885
0x0040c885:	call 0x00411c03
0x00411c03:	movl %edi, %edi
0x00411c05:	pushl %esi
0x00411c06:	pushl %edi
0x00411c07:	movl %esi, $0x437a7c<UINT32>
0x00411c0c:	pushl %esi
0x00411c0d:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00411c13:	testl %eax, %eax
0x00411c15:	jne 0x00411c1e
0x00411c1e:	movl %edi, %eax
0x00411c20:	testl %edi, %edi
0x00411c22:	je 350
0x00411c28:	movl %esi, 0x434260
0x00411c2e:	pushl $0x437ac8<UINT32>
0x00411c33:	pushl %edi
0x00411c34:	call GetProcAddress@KERNEL32.DLL
0x00411c36:	pushl $0x437abc<UINT32>
0x00411c3b:	pushl %edi
0x00411c3c:	movl 0x53eb84, %eax
0x00411c41:	call GetProcAddress@KERNEL32.DLL
0x00411c43:	pushl $0x437ab0<UINT32>
0x00411c48:	pushl %edi
0x00411c49:	movl 0x53eb88, %eax
0x00411c4e:	call GetProcAddress@KERNEL32.DLL
0x00411c50:	pushl $0x437aa8<UINT32>
0x00411c55:	pushl %edi
0x00411c56:	movl 0x53eb8c, %eax
0x00411c5b:	call GetProcAddress@KERNEL32.DLL
0x00411c5d:	cmpl 0x53eb84, $0x0<UINT8>
0x00411c64:	movl %esi, 0x4341a4
0x00411c6a:	movl 0x53eb90, %eax
0x00411c6f:	je 22
0x00411c71:	cmpl 0x53eb88, $0x0<UINT8>
0x00411c78:	je 13
0x00411c7a:	cmpl 0x53eb8c, $0x0<UINT8>
0x00411c81:	je 4
0x00411c83:	testl %eax, %eax
0x00411c85:	jne 0x00411cab
0x00411cab:	call TlsAlloc@KERNEL32.DLL
TlsAlloc@KERNEL32.DLL: API Node	
0x00411cb1:	movl 0x43dc8c, %eax
0x00411cb6:	cmpl %eax, $0xffffffff<UINT8>
0x00411cb9:	je 204
0x00411cbf:	pushl 0x53eb88
0x00411cc5:	pushl %eax
0x00411cc6:	call TlsSetValue@KERNEL32.DLL
TlsSetValue@KERNEL32.DLL: API Node	
0x00411cc8:	testl %eax, %eax
0x00411cca:	je 187
0x00411cd0:	call 0x00415b13
0x00415b13:	movl %edi, %edi
0x00415b15:	pushl %esi
0x00415b16:	call 0x004117ae
0x004117ae:	pushl $0x0<UINT8>
0x004117b0:	call 0x0041173c
0x0041173c:	movl %edi, %edi
0x0041173e:	pushl %ebp
0x0041173f:	movl %ebp, %esp
0x00411741:	pushl %esi
0x00411742:	pushl 0x43dc8c
0x00411748:	movl %esi, 0x4341ac
0x0041174e:	call TlsGetValue@KERNEL32.DLL
TlsGetValue@KERNEL32.DLL: API Node	
0x00411750:	testl %eax, %eax
0x00411752:	je 33
0x00411754:	movl %eax, 0x43dc88
0x00411759:	cmpl %eax, $0xffffffff<UINT8>
0x0041175c:	je 0x00411775
0x00411775:	movl %esi, $0x437a7c<UINT32>
0x0041177a:	pushl %esi
0x0041177b:	call GetModuleHandleW@KERNEL32.DLL
0x00411781:	testl %eax, %eax
0x00411783:	jne 0x00411790
0x00411790:	pushl $0x437a6c<UINT32>
0x00411795:	pushl %eax
0x00411796:	call GetProcAddress@KERNEL32.DLL
0x0041179c:	testl %eax, %eax
0x0041179e:	je 8
0x004117a0:	pushl 0x8(%ebp)
0x004117a3:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x004117a5:	movl 0x8(%ebp), %eax
0x004117a8:	movl %eax, 0x8(%ebp)
0x004117ab:	popl %esi
0x004117ac:	popl %ebp
0x004117ad:	ret

0x004117b5:	popl %ecx
0x004117b6:	ret

0x00415b1b:	movl %esi, %eax
0x00415b1d:	pushl %esi
0x00415b1e:	call 0x0040c712
0x0040c712:	movl %edi, %edi
0x0040c714:	pushl %ebp
0x0040c715:	movl %ebp, %esp
0x0040c717:	movl %eax, 0x8(%ebp)
0x0040c71a:	movl 0x53e800, %eax
0x0040c71f:	popl %ebp
0x0040c720:	ret

0x00415b23:	pushl %esi
0x00415b24:	call 0x00418f2e
0x00418f2e:	movl %edi, %edi
0x00418f30:	pushl %ebp
0x00418f31:	movl %ebp, %esp
0x00418f33:	movl %eax, 0x8(%ebp)
0x00418f36:	movl 0x53f158, %eax
0x00418f3b:	popl %ebp
0x00418f3c:	ret

0x00415b29:	pushl %esi
0x00415b2a:	call 0x0040b63e
0x0040b63e:	movl %edi, %edi
0x0040b640:	pushl %ebp
0x0040b641:	movl %ebp, %esp
0x0040b643:	movl %eax, 0x8(%ebp)
0x0040b646:	movl 0x53e7f4, %eax
0x0040b64b:	popl %ebp
0x0040b64c:	ret

0x00415b2f:	pushl %esi
0x00415b30:	call 0x0042952d
0x0042952d:	movl %edi, %edi
0x0042952f:	pushl %ebp
0x00429530:	movl %ebp, %esp
0x00429532:	movl %eax, 0x8(%ebp)
0x00429535:	movl 0x53f1fc, %eax
0x0042953a:	popl %ebp
0x0042953b:	ret

0x00415b35:	pushl %esi
0x00415b36:	call 0x00429297
0x00429297:	movl %edi, %edi
0x00429299:	pushl %ebp
0x0042929a:	movl %ebp, %esp
0x0042929c:	movl %eax, 0x8(%ebp)
0x0042929f:	movl 0x53f1f0, %eax
0x004292a4:	popl %ebp
0x004292a5:	ret

0x00415b3b:	pushl %esi
0x00415b3c:	call 0x00428d9b
0x00428d9b:	movl %edi, %edi
0x00428d9d:	pushl %ebp
0x00428d9e:	movl %ebp, %esp
0x00428da0:	movl %eax, 0x8(%ebp)
0x00428da3:	movl 0x53f1dc, %eax
0x00428da8:	movl 0x53f1e0, %eax
0x00428dad:	movl 0x53f1e4, %eax
0x00428db2:	movl 0x53f1e8, %eax
0x00428db7:	popl %ebp
0x00428db8:	ret

0x00415b41:	pushl %esi
0x00415b42:	call 0x00416e2d
0x00416e2d:	ret

0x00415b47:	pushl %esi
0x00415b48:	call 0x00414379
0x00414379:	pushl $0x4142f5<UINT32>
0x0041437e:	call 0x0041173c
0x00414383:	popl %ecx
0x00414384:	movl 0x53ecf0, %eax
0x00414389:	ret

0x00415b4d:	pushl $0x415adf<UINT32>
0x00415b52:	call 0x0041173c
0x00415b57:	addl %esp, $0x24<UINT8>
0x00415b5a:	movl 0x43de28, %eax
0x00415b5f:	popl %esi
0x00415b60:	ret

0x00411cd5:	pushl 0x53eb84
0x00411cdb:	call 0x0041173c
0x00411ce0:	pushl 0x53eb88
0x00411ce6:	movl 0x53eb84, %eax
0x00411ceb:	call 0x0041173c
0x00411cf0:	pushl 0x53eb8c
0x00411cf6:	movl 0x53eb88, %eax
0x00411cfb:	call 0x0041173c
0x00411d00:	pushl 0x53eb90
0x00411d06:	movl 0x53eb8c, %eax
0x00411d0b:	call 0x0041173c
0x00411d10:	addl %esp, $0x10<UINT8>
0x00411d13:	movl 0x53eb90, %eax
0x00411d18:	call 0x00411e7a
0x00411e7a:	movl %edi, %edi
0x00411e7c:	pushl %esi
0x00411e7d:	pushl %edi
0x00411e7e:	xorl %esi, %esi
0x00411e80:	movl %edi, $0x53eb98<UINT32>
0x00411e85:	cmpl 0x43dc94(,%esi,8), $0x1<UINT8>
0x00411e8d:	jne 0x00411ead
0x00411e8f:	leal %eax, 0x43dc90(,%esi,8)
0x00411e96:	movl (%eax), %edi
0x00411e98:	pushl $0xfa0<UINT32>
0x00411e9d:	pushl (%eax)
0x00411e9f:	addl %edi, $0x18<UINT8>
0x00411ea2:	call 0x00418f3d
0x00418f3d:	pushl $0x10<UINT8>
0x00418f3f:	pushl $0x43b178<UINT32>
0x00418f44:	call 0x0040d020
0x00418f49:	andl -4(%ebp), $0x0<UINT8>
0x00418f4d:	pushl 0xc(%ebp)
0x00418f50:	pushl 0x8(%ebp)
0x00418f53:	call InitializeCriticalSectionAndSpinCount@KERNEL32.DLL
InitializeCriticalSectionAndSpinCount@KERNEL32.DLL: API Node	
0x00418f59:	movl -28(%ebp), %eax
0x00418f5c:	jmp 0x00418f8d
0x00418f8d:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00418f94:	movl %eax, -28(%ebp)
0x00418f97:	call 0x0040d065
0x0040d065:	movl %ecx, -16(%ebp)
0x0040d068:	movl %fs:0, %ecx
0x0040d06f:	popl %ecx
0x0040d070:	popl %edi
0x0040d071:	popl %edi
0x0040d072:	popl %esi
0x0040d073:	popl %ebx
0x0040d074:	movl %esp, %ebp
0x0040d076:	popl %ebp
0x0040d077:	pushl %ecx
0x0040d078:	ret

0x00418f9c:	ret

0x00411ea7:	popl %ecx
0x00411ea8:	popl %ecx
0x00411ea9:	testl %eax, %eax
0x00411eab:	je 12
0x00411ead:	incl %esi
0x00411eae:	cmpl %esi, $0x24<UINT8>
0x00411eb1:	jl 0x00411e85
0x00411eb3:	xorl %eax, %eax
0x00411eb5:	incl %eax
0x00411eb6:	popl %edi
0x00411eb7:	popl %esi
0x00411eb8:	ret

0x00411d1d:	testl %eax, %eax
0x00411d1f:	je 101
0x00411d21:	pushl $0x411a5a<UINT32>
0x00411d26:	pushl 0x53eb84
0x00411d2c:	call 0x004117b7
0x004117b7:	movl %edi, %edi
0x004117b9:	pushl %ebp
0x004117ba:	movl %ebp, %esp
0x004117bc:	pushl %esi
0x004117bd:	pushl 0x43dc8c
0x004117c3:	movl %esi, 0x4341ac
0x004117c9:	call TlsGetValue@KERNEL32.DLL
0x004117cb:	testl %eax, %eax
0x004117cd:	je 33
0x004117cf:	movl %eax, 0x43dc88
0x004117d4:	cmpl %eax, $0xffffffff<UINT8>
0x004117d7:	je 0x004117f0
0x004117f0:	movl %esi, $0x437a7c<UINT32>
0x004117f5:	pushl %esi
0x004117f6:	call GetModuleHandleW@KERNEL32.DLL
0x004117fc:	testl %eax, %eax
0x004117fe:	jne 0x0041180b
0x0041180b:	pushl $0x437a98<UINT32>
0x00411810:	pushl %eax
0x00411811:	call GetProcAddress@KERNEL32.DLL
0x00411817:	testl %eax, %eax
0x00411819:	je 8
0x0041181b:	pushl 0x8(%ebp)
0x0041181e:	call DecodePointer@KERNEL32.DLL
DecodePointer@KERNEL32.DLL: API Node	
0x00411820:	movl 0x8(%ebp), %eax
0x00411823:	movl %eax, 0x8(%ebp)
0x00411826:	popl %esi
0x00411827:	popl %ebp
0x00411828:	ret

0x00411d31:	popl %ecx
0x00411d32:	call FlsAlloc@KERNEL32.DLL
FlsAlloc@KERNEL32.DLL: API Node	
0x00411d34:	movl 0x43dc88, %eax
0x00411d39:	cmpl %eax, $0xffffffff<UINT8>
0x00411d3c:	je 72
0x00411d3e:	pushl $0x214<UINT32>
0x00411d43:	pushl $0x1<UINT8>
0x00411d45:	call 0x00415deb
0x00415deb:	movl %edi, %edi
0x00415ded:	pushl %ebp
0x00415dee:	movl %ebp, %esp
0x00415df0:	pushl %esi
0x00415df1:	pushl %edi
0x00415df2:	xorl %esi, %esi
0x00415df4:	pushl $0x0<UINT8>
0x00415df6:	pushl 0xc(%ebp)
0x00415df9:	pushl 0x8(%ebp)
0x00415dfc:	call 0x00429705
0x00429705:	pushl $0xc<UINT8>
0x00429707:	pushl $0x43b278<UINT32>
0x0042970c:	call 0x0040d020
0x00429711:	movl %ecx, 0x8(%ebp)
0x00429714:	xorl %edi, %edi
0x00429716:	cmpl %ecx, %edi
0x00429718:	jbe 46
0x0042971a:	pushl $0xffffffe0<UINT8>
0x0042971c:	popl %eax
0x0042971d:	xorl %edx, %edx
0x0042971f:	divl %eax, %ecx
0x00429721:	cmpl %eax, 0xc(%ebp)
0x00429724:	sbbl %eax, %eax
0x00429726:	incl %eax
0x00429727:	jne 0x00429748
0x00429748:	imull %ecx, 0xc(%ebp)
0x0042974c:	movl %esi, %ecx
0x0042974e:	movl 0x8(%ebp), %esi
0x00429751:	cmpl %esi, %edi
0x00429753:	jne 0x00429758
0x00429758:	xorl %ebx, %ebx
0x0042975a:	movl -28(%ebp), %ebx
0x0042975d:	cmpl %esi, $0xffffffe0<UINT8>
0x00429760:	ja 105
0x00429762:	cmpl 0x53f41c, $0x3<UINT8>
0x00429769:	jne 0x004297b6
0x004297b6:	cmpl %ebx, %edi
0x004297b8:	jne 97
0x004297ba:	pushl %esi
0x004297bb:	pushl $0x8<UINT8>
0x004297bd:	pushl 0x53ece8
0x004297c3:	call HeapAlloc@KERNEL32.DLL
HeapAlloc@KERNEL32.DLL: API Node	
0x004297c9:	movl %ebx, %eax
0x004297cb:	cmpl %ebx, %edi
0x004297cd:	jne 0x0042981b
0x0042981b:	movl %eax, %ebx
0x0042981d:	call 0x0040d065
0x00429822:	ret

0x00415e01:	movl %edi, %eax
0x00415e03:	addl %esp, $0xc<UINT8>
0x00415e06:	testl %edi, %edi
0x00415e08:	jne 0x00415e31
0x00415e31:	movl %eax, %edi
0x00415e33:	popl %edi
0x00415e34:	popl %esi
0x00415e35:	popl %ebp
0x00415e36:	ret

0x00411d4a:	movl %esi, %eax
0x00411d4c:	popl %ecx
0x00411d4d:	popl %ecx
0x00411d4e:	testl %esi, %esi
0x00411d50:	je 52
0x00411d52:	pushl %esi
0x00411d53:	pushl 0x43dc88
0x00411d59:	pushl 0x53eb8c
0x00411d5f:	call 0x004117b7
0x004117d9:	pushl %eax
0x004117da:	pushl 0x43dc8c
0x004117e0:	call TlsGetValue@KERNEL32.DLL
0x004117e2:	call FlsGetValue@KERNEL32.DLL
FlsGetValue@KERNEL32.DLL: API Node	
0x004117e4:	testl %eax, %eax
0x004117e6:	je 0x004117f0
0x00411d64:	popl %ecx
0x00411d65:	call FlsSetValue@KERNEL32.DLL
FlsSetValue@KERNEL32.DLL: API Node	
0x00411d67:	testl %eax, %eax
0x00411d69:	je 27
0x00411d6b:	pushl $0x0<UINT8>
0x00411d6d:	pushl %esi
0x00411d6e:	call 0x004118e0
0x004118e0:	pushl $0xc<UINT8>
0x004118e2:	pushl $0x43ad20<UINT32>
0x004118e7:	call 0x0040d020
0x004118ec:	movl %esi, $0x437a7c<UINT32>
0x004118f1:	pushl %esi
0x004118f2:	call GetModuleHandleW@KERNEL32.DLL
0x004118f8:	testl %eax, %eax
0x004118fa:	jne 0x00411903
0x00411903:	movl -28(%ebp), %eax
0x00411906:	movl %esi, 0x8(%ebp)
0x00411909:	movl 0x5c(%esi), $0x438198<UINT32>
0x00411910:	xorl %edi, %edi
0x00411912:	incl %edi
0x00411913:	movl 0x14(%esi), %edi
0x00411916:	testl %eax, %eax
0x00411918:	je 36
0x0041191a:	pushl $0x437a6c<UINT32>
0x0041191f:	pushl %eax
0x00411920:	movl %ebx, 0x434260
0x00411926:	call GetProcAddress@KERNEL32.DLL
0x00411928:	movl 0x1f8(%esi), %eax
0x0041192e:	pushl $0x437a98<UINT32>
0x00411933:	pushl -28(%ebp)
0x00411936:	call GetProcAddress@KERNEL32.DLL
0x00411938:	movl 0x1fc(%esi), %eax
0x0041193e:	movl 0x70(%esi), %edi
0x00411941:	movb 0xc8(%esi), $0x43<UINT8>
0x00411948:	movb 0x14b(%esi), $0x43<UINT8>
0x0041194f:	movl 0x68(%esi), $0x43d670<UINT32>
0x00411956:	pushl $0xd<UINT8>
0x00411958:	call 0x0041200e
0x0041200e:	movl %edi, %edi
0x00412010:	pushl %ebp
0x00412011:	movl %ebp, %esp
0x00412013:	movl %eax, 0x8(%ebp)
0x00412016:	pushl %esi
0x00412017:	leal %esi, 0x43dc90(,%eax,8)
0x0041201e:	cmpl (%esi), $0x0<UINT8>
0x00412021:	jne 0x00412036
0x00412036:	pushl (%esi)
0x00412038:	call EnterCriticalSection@KERNEL32.DLL
EnterCriticalSection@KERNEL32.DLL: API Node	
0x0041203e:	popl %esi
0x0041203f:	popl %ebp
0x00412040:	ret

0x0041195d:	popl %ecx
0x0041195e:	andl -4(%ebp), $0x0<UINT8>
0x00411962:	pushl 0x68(%esi)
0x00411965:	call InterlockedIncrement@KERNEL32.DLL
InterlockedIncrement@KERNEL32.DLL: API Node	
0x0041196b:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00411972:	call 0x004119b5
0x004119b5:	pushl $0xd<UINT8>
0x004119b7:	call 0x00411f1c
0x00411f1c:	movl %edi, %edi
0x00411f1e:	pushl %ebp
0x00411f1f:	movl %ebp, %esp
0x00411f21:	movl %eax, 0x8(%ebp)
0x00411f24:	pushl 0x43dc90(,%eax,8)
0x00411f2b:	call LeaveCriticalSection@KERNEL32.DLL
LeaveCriticalSection@KERNEL32.DLL: API Node	
0x00411f31:	popl %ebp
0x00411f32:	ret

0x004119bc:	popl %ecx
0x004119bd:	ret

0x00411977:	pushl $0xc<UINT8>
0x00411979:	call 0x0041200e
0x0041197e:	popl %ecx
0x0041197f:	movl -4(%ebp), %edi
0x00411982:	movl %eax, 0xc(%ebp)
0x00411985:	movl 0x6c(%esi), %eax
0x00411988:	testl %eax, %eax
0x0041198a:	jne 8
0x0041198c:	movl %eax, 0x43dc78
0x00411991:	movl 0x6c(%esi), %eax
0x00411994:	pushl 0x6c(%esi)
0x00411997:	call 0x004105ce
0x004105ce:	movl %edi, %edi
0x004105d0:	pushl %ebp
0x004105d1:	movl %ebp, %esp
0x004105d3:	pushl %ebx
0x004105d4:	pushl %esi
0x004105d5:	movl %esi, 0x434230
0x004105db:	pushl %edi
0x004105dc:	movl %edi, 0x8(%ebp)
0x004105df:	pushl %edi
0x004105e0:	call InterlockedIncrement@KERNEL32.DLL
0x004105e2:	movl %eax, 0xb0(%edi)
0x004105e8:	testl %eax, %eax
0x004105ea:	je 0x004105ef
0x004105ef:	movl %eax, 0xb8(%edi)
0x004105f5:	testl %eax, %eax
0x004105f7:	je 0x004105fc
0x004105fc:	movl %eax, 0xb4(%edi)
0x00410602:	testl %eax, %eax
0x00410604:	je 0x00410609
0x00410609:	movl %eax, 0xc0(%edi)
0x0041060f:	testl %eax, %eax
0x00410611:	je 0x00410616
0x00410616:	leal %ebx, 0x50(%edi)
0x00410619:	movl 0x8(%ebp), $0x6<UINT32>
0x00410620:	cmpl -8(%ebx), $0x43db98<UINT32>
0x00410627:	je 0x00410632
0x00410629:	movl %eax, (%ebx)
0x0041062b:	testl %eax, %eax
0x0041062d:	je 0x00410632
0x00410632:	cmpl -4(%ebx), $0x0<UINT8>
0x00410636:	je 0x00410642
0x00410642:	addl %ebx, $0x10<UINT8>
0x00410645:	decl 0x8(%ebp)
0x00410648:	jne 0x00410620
0x0041064a:	movl %eax, 0xd4(%edi)
0x00410650:	addl %eax, $0xb4<UINT32>
0x00410655:	pushl %eax
0x00410656:	call InterlockedIncrement@KERNEL32.DLL
0x00410658:	popl %edi
0x00410659:	popl %esi
0x0041065a:	popl %ebx
0x0041065b:	popl %ebp
0x0041065c:	ret

0x0041199c:	popl %ecx
0x0041199d:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004119a4:	call 0x004119be
0x004119be:	pushl $0xc<UINT8>
0x004119c0:	call 0x00411f1c
0x004119c5:	popl %ecx
0x004119c6:	ret

0x004119a9:	call 0x0040d065
0x004119ae:	ret

0x00411d73:	popl %ecx
0x00411d74:	popl %ecx
0x00411d75:	call GetCurrentThreadId@KERNEL32.DLL
0x00411d7b:	orl 0x4(%esi), $0xffffffff<UINT8>
0x00411d7f:	movl (%esi), %eax
0x00411d81:	xorl %eax, %eax
0x00411d83:	incl %eax
0x00411d84:	jmp 0x00411d8d
0x00411d8d:	popl %edi
0x00411d8e:	popl %esi
0x00411d8f:	ret

0x0040c88a:	testl %eax, %eax
0x0040c88c:	jne 0x0040c896
0x0040c896:	call 0x0041750b
0x0041750b:	movl %edi, %edi
0x0041750d:	pushl %esi
0x0041750e:	movl %eax, $0x43a4fc<UINT32>
0x00417513:	movl %esi, $0x43a4fc<UINT32>
0x00417518:	pushl %edi
0x00417519:	movl %edi, %eax
0x0041751b:	cmpl %eax, %esi
0x0041751d:	jae 0x0041752e
0x0041752e:	popl %edi
0x0041752f:	popl %esi
0x00417530:	ret

0x0040c89b:	movl -4(%ebp), %ebx
0x0040c89e:	call 0x004150fd
0x004150fd:	pushl $0x54<UINT8>
0x004150ff:	pushl $0x43af90<UINT32>
0x00415104:	call 0x0040d020
0x00415109:	xorl %edi, %edi
0x0041510b:	movl -4(%ebp), %edi
0x0041510e:	leal %eax, -100(%ebp)
0x00415111:	pushl %eax
0x00415112:	call GetStartupInfoA@KERNEL32.DLL
0x00415118:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0041511f:	pushl $0x40<UINT8>
0x00415121:	pushl $0x20<UINT8>
0x00415123:	popl %esi
0x00415124:	pushl %esi
0x00415125:	call 0x00415deb
0x0041512a:	popl %ecx
0x0041512b:	popl %ecx
0x0041512c:	cmpl %eax, %edi
0x0041512e:	je 532
0x00415134:	movl 0x53f300, %eax
0x00415139:	movl 0x53f2f4, %esi
0x0041513f:	leal %ecx, 0x800(%eax)
0x00415145:	jmp 0x00415177
0x00415177:	cmpl %eax, %ecx
0x00415179:	jb 0x00415147
0x00415147:	movb 0x4(%eax), $0x0<UINT8>
0x0041514b:	orl (%eax), $0xffffffff<UINT8>
0x0041514e:	movb 0x5(%eax), $0xa<UINT8>
0x00415152:	movl 0x8(%eax), %edi
0x00415155:	movb 0x24(%eax), $0x0<UINT8>
0x00415159:	movb 0x25(%eax), $0xa<UINT8>
0x0041515d:	movb 0x26(%eax), $0xa<UINT8>
0x00415161:	movl 0x38(%eax), %edi
0x00415164:	movb 0x34(%eax), $0x0<UINT8>
0x00415168:	addl %eax, $0x40<UINT8>
0x0041516b:	movl %ecx, 0x53f300
0x00415171:	addl %ecx, $0x800<UINT32>
0x0041517b:	cmpw -50(%ebp), %di
0x0041517f:	je 266
0x00415185:	movl %eax, -48(%ebp)
0x00415188:	cmpl %eax, %edi
0x0041518a:	je 255
0x00415190:	movl %edi, (%eax)
0x00415192:	leal %ebx, 0x4(%eax)
0x00415195:	leal %eax, (%ebx,%edi)
0x00415198:	movl -28(%ebp), %eax
0x0041519b:	movl %esi, $0x800<UINT32>
0x004151a0:	cmpl %edi, %esi
0x004151a2:	jl 0x004151a6
0x004151a6:	movl -32(%ebp), $0x1<UINT32>
0x004151ad:	jmp 0x0041520a
0x0041520a:	cmpl 0x53f2f4, %edi
0x00415210:	jl -99
0x00415212:	jmp 0x0041521a
0x0041521a:	andl -32(%ebp), $0x0<UINT8>
0x0041521e:	testl %edi, %edi
0x00415220:	jle 0x0041528f
0x0041528f:	xorl %ebx, %ebx
0x00415291:	movl %esi, %ebx
0x00415293:	shll %esi, $0x6<UINT8>
0x00415296:	addl %esi, 0x53f300
0x0041529c:	movl %eax, (%esi)
0x0041529e:	cmpl %eax, $0xffffffff<UINT8>
0x004152a1:	je 0x004152ae
0x004152ae:	movb 0x4(%esi), $0xffffff81<UINT8>
0x004152b2:	testl %ebx, %ebx
0x004152b4:	jne 0x004152bb
0x004152b6:	pushl $0xfffffff6<UINT8>
0x004152b8:	popl %eax
0x004152b9:	jmp 0x004152c5
0x004152c5:	pushl %eax
0x004152c6:	call GetStdHandle@KERNEL32.DLL
GetStdHandle@KERNEL32.DLL: API Node	
0x004152cc:	movl %edi, %eax
0x004152ce:	cmpl %edi, $0xffffffff<UINT8>
0x004152d1:	je 67
0x004152d3:	testl %edi, %edi
0x004152d5:	je 63
0x004152d7:	pushl %edi
0x004152d8:	call GetFileType@KERNEL32.DLL
GetFileType@KERNEL32.DLL: API Node	
0x004152de:	testl %eax, %eax
0x004152e0:	je 52
0x004152e2:	movl (%esi), %edi
0x004152e4:	andl %eax, $0xff<UINT32>
0x004152e9:	cmpl %eax, $0x2<UINT8>
0x004152ec:	jne 6
0x004152ee:	orb 0x4(%esi), $0x40<UINT8>
0x004152f2:	jmp 0x004152fd
0x004152fd:	pushl $0xfa0<UINT32>
0x00415302:	leal %eax, 0xc(%esi)
0x00415305:	pushl %eax
0x00415306:	call 0x00418f3d
0x0041530b:	popl %ecx
0x0041530c:	popl %ecx
0x0041530d:	testl %eax, %eax
0x0041530f:	je 55
0x00415311:	incl 0x8(%esi)
0x00415314:	jmp 0x00415320
0x00415320:	incl %ebx
0x00415321:	cmpl %ebx, $0x3<UINT8>
0x00415324:	jl 0x00415291
0x004152bb:	movl %eax, %ebx
0x004152bd:	decl %eax
0x004152be:	negl %eax
0x004152c0:	sbbl %eax, %eax
0x004152c2:	addl %eax, $0xfffffff5<UINT8>
0x0041532a:	pushl 0x53f2f4
0x00415330:	call SetHandleCount@KERNEL32.DLL
SetHandleCount@KERNEL32.DLL: API Node	
0x00415336:	xorl %eax, %eax
0x00415338:	jmp 0x0041534b
0x0041534b:	call 0x0040d065
0x00415350:	ret

0x0040c8a3:	testl %eax, %eax
0x0040c8a5:	jnl 0x0040c8af
0x0040c8af:	call GetCommandLineA@KERNEL32.DLL
GetCommandLineA@KERNEL32.DLL: API Node	
0x0040c8b5:	movl 0x540444, %eax
0x0040c8ba:	call 0x004173d4
0x004173d4:	movl %edi, %edi
0x004173d6:	pushl %ebp
0x004173d7:	movl %ebp, %esp
0x004173d9:	movl %eax, 0x53f150
0x004173de:	subl %esp, $0xc<UINT8>
0x004173e1:	pushl %ebx
0x004173e2:	pushl %esi
0x004173e3:	movl %esi, 0x43414c
0x004173e9:	pushl %edi
0x004173ea:	xorl %ebx, %ebx
0x004173ec:	xorl %edi, %edi
0x004173ee:	cmpl %eax, %ebx
0x004173f0:	jne 46
0x004173f2:	call GetEnvironmentStringsW@KERNEL32.DLL
GetEnvironmentStringsW@KERNEL32.DLL: API Node	
0x004173f4:	movl %edi, %eax
0x004173f6:	cmpl %edi, %ebx
0x004173f8:	je 12
0x004173fa:	movl 0x53f150, $0x1<UINT32>
0x00417404:	jmp 0x00417429
0x00417429:	cmpl %edi, %ebx
0x0041742b:	jne 0x0041743c
0x0041743c:	movl %eax, %edi
0x0041743e:	cmpw (%edi), %bx
0x00417441:	je 14
0x00417443:	incl %eax
0x00417444:	incl %eax
0x00417445:	cmpw (%eax), %bx
0x00417448:	jne 0x00417443
0x0041744a:	incl %eax
0x0041744b:	incl %eax
0x0041744c:	cmpw (%eax), %bx
0x0041744f:	jne 0x00417443
0x00417451:	movl %esi, 0x434090
0x00417457:	pushl %ebx
0x00417458:	pushl %ebx
0x00417459:	pushl %ebx
0x0041745a:	subl %eax, %edi
0x0041745c:	pushl %ebx
0x0041745d:	sarl %eax
0x0041745f:	incl %eax
0x00417460:	pushl %eax
0x00417461:	pushl %edi
0x00417462:	pushl %ebx
0x00417463:	pushl %ebx
0x00417464:	movl -12(%ebp), %eax
0x00417467:	call WideCharToMultiByte@KERNEL32.DLL
WideCharToMultiByte@KERNEL32.DLL: API Node	
0x00417469:	movl -8(%ebp), %eax
0x0041746c:	cmpl %eax, %ebx
0x0041746e:	je 47
0x00417470:	pushl %eax
0x00417471:	call 0x00415da6
0x00415da6:	movl %edi, %edi
0x00415da8:	pushl %ebp
0x00415da9:	movl %ebp, %esp
0x00415dab:	pushl %esi
0x00415dac:	pushl %edi
0x00415dad:	xorl %esi, %esi
0x00415daf:	pushl 0x8(%ebp)
0x00415db2:	call 0x0040be1e
0x0040be1e:	movl %edi, %edi
0x0040be20:	pushl %ebp
0x0040be21:	movl %ebp, %esp
0x0040be23:	pushl %esi
0x0040be24:	movl %esi, 0x8(%ebp)
0x0040be27:	cmpl %esi, $0xffffffe0<UINT8>
0x0040be2a:	ja 161
0x0040be30:	pushl %ebx
0x0040be31:	pushl %edi
0x0040be32:	movl %edi, 0x4340b0
0x0040be38:	cmpl 0x53ece8, $0x0<UINT8>
0x0040be3f:	jne 0x0040be59
0x0040be59:	movl %eax, 0x53f41c
0x0040be5e:	cmpl %eax, $0x1<UINT8>
0x0040be61:	jne 14
0x0040be63:	testl %esi, %esi
0x0040be65:	je 4
0x0040be67:	movl %eax, %esi
0x0040be69:	jmp 0x0040be6e
0x0040be6e:	pushl %eax
0x0040be6f:	jmp 0x0040be8d
0x0040be8d:	pushl $0x0<UINT8>
0x0040be8f:	pushl 0x53ece8
0x0040be95:	call HeapAlloc@KERNEL32.DLL
0x0040be97:	movl %ebx, %eax
0x0040be99:	testl %ebx, %ebx
0x0040be9b:	jne 0x0040becb
0x0040becb:	popl %edi
0x0040becc:	movl %eax, %ebx
0x0040bece:	popl %ebx
0x0040becf:	jmp 0x0040bee5
0x0040bee5:	popl %esi
0x0040bee6:	popl %ebp
0x0040bee7:	ret

0x00415db7:	movl %edi, %eax
0x00415db9:	popl %ecx
0x00415dba:	testl %edi, %edi
0x00415dbc:	jne 0x00415de5
0x00415de5:	movl %eax, %edi
0x00415de7:	popl %edi
0x00415de8:	popl %esi
0x00415de9:	popl %ebp
0x00415dea:	ret

0x00417476:	popl %ecx
0x00417477:	movl -4(%ebp), %eax
0x0041747a:	cmpl %eax, %ebx
0x0041747c:	je 33
0x0041747e:	pushl %ebx
0x0041747f:	pushl %ebx
0x00417480:	pushl -8(%ebp)
0x00417483:	pushl %eax
0x00417484:	pushl -12(%ebp)
0x00417487:	pushl %edi
0x00417488:	pushl %ebx
0x00417489:	pushl %ebx
0x0041748a:	call WideCharToMultiByte@KERNEL32.DLL
0x0041748c:	testl %eax, %eax
0x0041748e:	jne 0x0041749c
0x0041749c:	movl %ebx, -4(%ebp)
0x0041749f:	pushl %edi
0x004174a0:	call FreeEnvironmentStringsW@KERNEL32.DLL
FreeEnvironmentStringsW@KERNEL32.DLL: API Node	
0x004174a6:	movl %eax, %ebx
0x004174a8:	jmp 0x00417506
0x00417506:	popl %edi
0x00417507:	popl %esi
0x00417508:	popl %ebx
0x00417509:	leave
0x0041750a:	ret

0x0040c8bf:	movl 0x53e804, %eax
0x0040c8c4:	call 0x00417319
0x00417319:	movl %edi, %edi
0x0041731b:	pushl %ebp
0x0041731c:	movl %ebp, %esp
0x0041731e:	subl %esp, $0xc<UINT8>
0x00417321:	pushl %ebx
0x00417322:	xorl %ebx, %ebx
0x00417324:	pushl %esi
0x00417325:	pushl %edi
0x00417326:	cmpl 0x53f2e8, %ebx
0x0041732c:	jne 5
0x0041732e:	call 0x0041045b
0x0041045b:	cmpl 0x53f2e8, $0x0<UINT8>
0x00410462:	jne 0x00410476
0x00410464:	pushl $0xfffffffd<UINT8>
0x00410466:	call 0x004102c1
0x004102c1:	pushl $0x14<UINT8>
0x004102c3:	pushl $0x43ac58<UINT32>
0x004102c8:	call 0x0040d020
0x004102cd:	orl -32(%ebp), $0xffffffff<UINT8>
0x004102d1:	call 0x00411a40
0x00411a40:	movl %edi, %edi
0x00411a42:	pushl %esi
0x00411a43:	call 0x004119c7
0x004119c7:	movl %edi, %edi
0x004119c9:	pushl %esi
0x004119ca:	pushl %edi
0x004119cb:	call GetLastError@KERNEL32.DLL
GetLastError@KERNEL32.DLL: API Node	
0x004119d1:	pushl 0x43dc88
0x004119d7:	movl %edi, %eax
0x004119d9:	call 0x00411852
0x00411852:	movl %edi, %edi
0x00411854:	pushl %esi
0x00411855:	pushl 0x43dc8c
0x0041185b:	call TlsGetValue@KERNEL32.DLL
0x00411861:	movl %esi, %eax
0x00411863:	testl %esi, %esi
0x00411865:	jne 0x00411882
0x00411882:	movl %eax, %esi
0x00411884:	popl %esi
0x00411885:	ret

0x004119de:	call FlsGetValue@KERNEL32.DLL
0x004119e0:	movl %esi, %eax
0x004119e2:	testl %esi, %esi
0x004119e4:	jne 0x00411a34
0x00411a34:	pushl %edi
0x00411a35:	call SetLastError@KERNEL32.DLL
SetLastError@KERNEL32.DLL: API Node	
0x00411a3b:	popl %edi
0x00411a3c:	movl %eax, %esi
0x00411a3e:	popl %esi
0x00411a3f:	ret

0x00411a48:	movl %esi, %eax
0x00411a4a:	testl %esi, %esi
0x00411a4c:	jne 0x00411a56
0x00411a56:	movl %eax, %esi
0x00411a58:	popl %esi
0x00411a59:	ret

0x004102d6:	movl %edi, %eax
0x004102d8:	movl -36(%ebp), %edi
0x004102db:	call 0x0040ff7e
0x0040ff7e:	pushl $0xc<UINT8>
0x0040ff80:	pushl $0x43ac38<UINT32>
0x0040ff85:	call 0x0040d020
0x0040ff8a:	call 0x00411a40
0x0040ff8f:	movl %edi, %eax
0x0040ff91:	movl %eax, 0x43db94
0x0040ff96:	testl 0x70(%edi), %eax
0x0040ff99:	je 0x0040ffb8
0x0040ffb8:	pushl $0xd<UINT8>
0x0040ffba:	call 0x0041200e
0x0040ffbf:	popl %ecx
0x0040ffc0:	andl -4(%ebp), $0x0<UINT8>
0x0040ffc4:	movl %esi, 0x68(%edi)
0x0040ffc7:	movl -28(%ebp), %esi
0x0040ffca:	cmpl %esi, 0x43da98
0x0040ffd0:	je 0x00410008
0x00410008:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0041000f:	call 0x00410019
0x00410019:	pushl $0xd<UINT8>
0x0041001b:	call 0x00411f1c
0x00410020:	popl %ecx
0x00410021:	ret

0x00410014:	jmp 0x0040ffa4
0x0040ffa4:	testl %esi, %esi
0x0040ffa6:	jne 0x0040ffb0
0x0040ffb0:	movl %eax, %esi
0x0040ffb2:	call 0x0040d065
0x0040ffb7:	ret

0x004102e0:	movl %ebx, 0x68(%edi)
0x004102e3:	movl %esi, 0x8(%ebp)
0x004102e6:	call 0x00410022
0x00410022:	movl %edi, %edi
0x00410024:	pushl %ebp
0x00410025:	movl %ebp, %esp
0x00410027:	subl %esp, $0x10<UINT8>
0x0041002a:	pushl %ebx
0x0041002b:	xorl %ebx, %ebx
0x0041002d:	pushl %ebx
0x0041002e:	leal %ecx, -16(%ebp)
0x00410031:	call 0x0040a674
0x0040a674:	movl %edi, %edi
0x0040a676:	pushl %ebp
0x0040a677:	movl %ebp, %esp
0x0040a679:	movl %eax, 0x8(%ebp)
0x0040a67c:	pushl %esi
0x0040a67d:	movl %esi, %ecx
0x0040a67f:	movb 0xc(%esi), $0x0<UINT8>
0x0040a683:	testl %eax, %eax
0x0040a685:	jne 99
0x0040a687:	call 0x00411a40
0x0040a68c:	movl 0x8(%esi), %eax
0x0040a68f:	movl %ecx, 0x6c(%eax)
0x0040a692:	movl (%esi), %ecx
0x0040a694:	movl %ecx, 0x68(%eax)
0x0040a697:	movl 0x4(%esi), %ecx
0x0040a69a:	movl %ecx, (%esi)
0x0040a69c:	cmpl %ecx, 0x43dc78
0x0040a6a2:	je 0x0040a6b6
0x0040a6b6:	movl %eax, 0x4(%esi)
0x0040a6b9:	cmpl %eax, 0x43da98
0x0040a6bf:	je 0x0040a6d7
0x0040a6d7:	movl %eax, 0x8(%esi)
0x0040a6da:	testb 0x70(%eax), $0x2<UINT8>
0x0040a6de:	jne 20
0x0040a6e0:	orl 0x70(%eax), $0x2<UINT8>
0x0040a6e4:	movb 0xc(%esi), $0x1<UINT8>
0x0040a6e8:	jmp 0x0040a6f4
0x0040a6f4:	movl %eax, %esi
0x0040a6f6:	popl %esi
0x0040a6f7:	popl %ebp
0x0040a6f8:	ret $0x4<UINT16>

0x00410036:	movl 0x53eb44, %ebx
0x0041003c:	cmpl %esi, $0xfffffffe<UINT8>
0x0041003f:	jne 0x0041005f
0x0041005f:	cmpl %esi, $0xfffffffd<UINT8>
0x00410062:	jne 0x00410076
0x00410064:	movl 0x53eb44, $0x1<UINT32>
0x0041006e:	call GetACP@KERNEL32.DLL
GetACP@KERNEL32.DLL: API Node	
0x00410074:	jmp 0x00410051
0x00410051:	cmpb -4(%ebp), %bl
0x00410054:	je 69
0x00410056:	movl %ecx, -8(%ebp)
0x00410059:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0041005d:	jmp 0x0041009b
0x0041009b:	popl %ebx
0x0041009c:	leave
0x0041009d:	ret

0x004102eb:	movl 0x8(%ebp), %eax
0x004102ee:	cmpl %eax, 0x4(%ebx)
0x004102f1:	je 343
0x004102f7:	pushl $0x220<UINT32>
0x004102fc:	call 0x00415da6
0x00410301:	popl %ecx
0x00410302:	movl %ebx, %eax
0x00410304:	testl %ebx, %ebx
0x00410306:	je 326
0x0041030c:	movl %ecx, $0x88<UINT32>
0x00410311:	movl %esi, 0x68(%edi)
0x00410314:	movl %edi, %ebx
0x00410316:	rep movsl %es:(%edi), %ds:(%esi)
0x00410318:	andl (%ebx), $0x0<UINT8>
0x0041031b:	pushl %ebx
0x0041031c:	pushl 0x8(%ebp)
0x0041031f:	call 0x0041009e
0x0041009e:	movl %edi, %edi
0x004100a0:	pushl %ebp
0x004100a1:	movl %ebp, %esp
0x004100a3:	subl %esp, $0x20<UINT8>
0x004100a6:	movl %eax, 0x43d1b0
0x004100ab:	xorl %eax, %ebp
0x004100ad:	movl -4(%ebp), %eax
0x004100b0:	pushl %ebx
0x004100b1:	movl %ebx, 0xc(%ebp)
0x004100b4:	pushl %esi
0x004100b5:	movl %esi, 0x8(%ebp)
0x004100b8:	pushl %edi
0x004100b9:	call 0x00410022
0x00410076:	cmpl %esi, $0xfffffffc<UINT8>
0x00410079:	jne 0x0041008d
0x0041008d:	cmpb -4(%ebp), %bl
0x00410090:	je 7
0x00410092:	movl %eax, -8(%ebp)
0x00410095:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x00410099:	movl %eax, %esi
0x004100be:	movl %edi, %eax
0x004100c0:	xorl %esi, %esi
0x004100c2:	movl 0x8(%ebp), %edi
0x004100c5:	cmpl %edi, %esi
0x004100c7:	jne 0x004100d7
0x004100d7:	movl -28(%ebp), %esi
0x004100da:	xorl %eax, %eax
0x004100dc:	cmpl 0x43daa0(%eax), %edi
0x004100e2:	je 145
0x004100e8:	incl -28(%ebp)
0x004100eb:	addl %eax, $0x30<UINT8>
0x004100ee:	cmpl %eax, $0xf0<UINT32>
0x004100f3:	jb 0x004100dc
0x004100f5:	cmpl %edi, $0xfde8<UINT32>
0x004100fb:	je 368
0x00410101:	cmpl %edi, $0xfde9<UINT32>
0x00410107:	je 356
0x0041010d:	movzwl %eax, %di
0x00410110:	pushl %eax
0x00410111:	call IsValidCodePage@KERNEL32.DLL
IsValidCodePage@KERNEL32.DLL: API Node	
0x00410117:	testl %eax, %eax
0x00410119:	je 338
0x0041011f:	leal %eax, -24(%ebp)
0x00410122:	pushl %eax
0x00410123:	pushl %edi
0x00410124:	call GetCPInfo@KERNEL32.DLL
GetCPInfo@KERNEL32.DLL: API Node	
0x0041012a:	testl %eax, %eax
0x0041012c:	je 307
0x00410132:	pushl $0x101<UINT32>
0x00410137:	leal %eax, 0x1c(%ebx)
0x0041013a:	pushl %esi
0x0041013b:	pushl %eax
0x0041013c:	call 0x00409ec0
0x00409ec0:	movl %edx, 0xc(%esp)
0x00409ec4:	movl %ecx, 0x4(%esp)
0x00409ec8:	testl %edx, %edx
0x00409eca:	je 105
0x00409ecc:	xorl %eax, %eax
0x00409ece:	movb %al, 0x8(%esp)
0x00409ed2:	testb %al, %al
0x00409ed4:	jne 22
0x00409ed6:	cmpl %edx, $0x100<UINT32>
0x00409edc:	jb 14
0x00409ede:	cmpl 0x53f428, $0x0<UINT8>
0x00409ee5:	je 0x00409eec
0x00409eec:	pushl %edi
0x00409eed:	movl %edi, %ecx
0x00409eef:	cmpl %edx, $0x4<UINT8>
0x00409ef2:	jb 49
0x00409ef4:	negl %ecx
0x00409ef6:	andl %ecx, $0x3<UINT8>
0x00409ef9:	je 0x00409f07
0x00409f07:	movl %ecx, %eax
0x00409f09:	shll %eax, $0x8<UINT8>
0x00409f0c:	addl %eax, %ecx
0x00409f0e:	movl %ecx, %eax
0x00409f10:	shll %eax, $0x10<UINT8>
0x00409f13:	addl %eax, %ecx
0x00409f15:	movl %ecx, %edx
0x00409f17:	andl %edx, $0x3<UINT8>
0x00409f1a:	shrl %ecx, $0x2<UINT8>
0x00409f1d:	je 6
0x00409f1f:	rep stosl %es:(%edi), %eax
0x00409f21:	testl %edx, %edx
0x00409f23:	je 0x00409f2f
0x00409f25:	movb (%edi), %al
0x00409f27:	addl %edi, $0x1<UINT8>
0x00409f2a:	subl %edx, $0x1<UINT8>
0x00409f2d:	jne -10
0x00409f2f:	movl %eax, 0x8(%esp)
0x00409f33:	popl %edi
0x00409f34:	ret

0x00410141:	xorl %edx, %edx
0x00410143:	incl %edx
0x00410144:	addl %esp, $0xc<UINT8>
0x00410147:	movl 0x4(%ebx), %edi
0x0041014a:	movl 0xc(%ebx), %esi
0x0041014d:	cmpl -24(%ebp), %edx
0x00410150:	jbe 248
0x00410156:	cmpb -18(%ebp), $0x0<UINT8>
0x0041015a:	je 0x0041022f
0x0041022f:	leal %eax, 0x1e(%ebx)
0x00410232:	movl %ecx, $0xfe<UINT32>
0x00410237:	orb (%eax), $0x8<UINT8>
0x0041023a:	incl %eax
0x0041023b:	decl %ecx
0x0041023c:	jne 0x00410237
0x0041023e:	movl %eax, 0x4(%ebx)
0x00410241:	call 0x0040fd58
0x0040fd58:	subl %eax, $0x3a4<UINT32>
0x0040fd5d:	je 34
0x0040fd5f:	subl %eax, $0x4<UINT8>
0x0040fd62:	je 23
0x0040fd64:	subl %eax, $0xd<UINT8>
0x0040fd67:	je 12
0x0040fd69:	decl %eax
0x0040fd6a:	je 3
0x0040fd6c:	xorl %eax, %eax
0x0040fd6e:	ret

0x00410246:	movl 0xc(%ebx), %eax
0x00410249:	movl 0x8(%ebx), %edx
0x0041024c:	jmp 0x00410251
0x00410251:	xorl %eax, %eax
0x00410253:	movzwl %ecx, %ax
0x00410256:	movl %eax, %ecx
0x00410258:	shll %ecx, $0x10<UINT8>
0x0041025b:	orl %eax, %ecx
0x0041025d:	leal %edi, 0x10(%ebx)
0x00410260:	stosl %es:(%edi), %eax
0x00410261:	stosl %es:(%edi), %eax
0x00410262:	stosl %es:(%edi), %eax
0x00410263:	jmp 0x0041020d
0x0041020d:	movl %esi, %ebx
0x0041020f:	call 0x0040fdeb
0x0040fdeb:	movl %edi, %edi
0x0040fded:	pushl %ebp
0x0040fdee:	movl %ebp, %esp
0x0040fdf0:	subl %esp, $0x51c<UINT32>
0x0040fdf6:	movl %eax, 0x43d1b0
0x0040fdfb:	xorl %eax, %ebp
0x0040fdfd:	movl -4(%ebp), %eax
0x0040fe00:	pushl %ebx
0x0040fe01:	pushl %edi
0x0040fe02:	leal %eax, -1304(%ebp)
0x0040fe08:	pushl %eax
0x0040fe09:	pushl 0x4(%esi)
0x0040fe0c:	call GetCPInfo@KERNEL32.DLL
0x0040fe12:	movl %edi, $0x100<UINT32>
0x0040fe17:	testl %eax, %eax
0x0040fe19:	je 251
0x0040fe1f:	xorl %eax, %eax
0x0040fe21:	movb -260(%ebp,%eax), %al
0x0040fe28:	incl %eax
0x0040fe29:	cmpl %eax, %edi
0x0040fe2b:	jb 0x0040fe21
0x0040fe2d:	movb %al, -1298(%ebp)
0x0040fe33:	movb -260(%ebp), $0x20<UINT8>
0x0040fe3a:	testb %al, %al
0x0040fe3c:	je 0x0040fe6c
0x0040fe6c:	pushl $0x0<UINT8>
0x0040fe6e:	pushl 0xc(%esi)
0x0040fe71:	leal %eax, -1284(%ebp)
0x0040fe77:	pushl 0x4(%esi)
0x0040fe7a:	pushl %eax
0x0040fe7b:	pushl %edi
0x0040fe7c:	leal %eax, -260(%ebp)
0x0040fe82:	pushl %eax
0x0040fe83:	pushl $0x1<UINT8>
0x0040fe85:	pushl $0x0<UINT8>
0x0040fe87:	call 0x00420f1d
0x00420f1d:	movl %edi, %edi
0x00420f1f:	pushl %ebp
0x00420f20:	movl %ebp, %esp
0x00420f22:	subl %esp, $0x10<UINT8>
0x00420f25:	pushl 0x8(%ebp)
0x00420f28:	leal %ecx, -16(%ebp)
0x00420f2b:	call 0x0040a674
0x00420f30:	pushl 0x24(%ebp)
0x00420f33:	leal %ecx, -16(%ebp)
0x00420f36:	pushl 0x20(%ebp)
0x00420f39:	pushl 0x1c(%ebp)
0x00420f3c:	pushl 0x18(%ebp)
0x00420f3f:	pushl 0x14(%ebp)
0x00420f42:	pushl 0x10(%ebp)
0x00420f45:	pushl 0xc(%ebp)
0x00420f48:	call 0x00420d63
0x00420d63:	movl %edi, %edi
0x00420d65:	pushl %ebp
0x00420d66:	movl %ebp, %esp
0x00420d68:	pushl %ecx
0x00420d69:	pushl %ecx
0x00420d6a:	movl %eax, 0x43d1b0
0x00420d6f:	xorl %eax, %ebp
0x00420d71:	movl -4(%ebp), %eax
0x00420d74:	movl %eax, 0x53f1d4
0x00420d79:	pushl %ebx
0x00420d7a:	pushl %esi
0x00420d7b:	xorl %ebx, %ebx
0x00420d7d:	pushl %edi
0x00420d7e:	movl %edi, %ecx
0x00420d80:	cmpl %eax, %ebx
0x00420d82:	jne 58
0x00420d84:	leal %eax, -8(%ebp)
0x00420d87:	pushl %eax
0x00420d88:	xorl %esi, %esi
0x00420d8a:	incl %esi
0x00420d8b:	pushl %esi
0x00420d8c:	pushl $0x438cb0<UINT32>
0x00420d91:	pushl %esi
0x00420d92:	call GetStringTypeW@KERNEL32.DLL
GetStringTypeW@KERNEL32.DLL: API Node	
0x00420d98:	testl %eax, %eax
0x00420d9a:	je 8
0x00420d9c:	movl 0x53f1d4, %esi
0x00420da2:	jmp 0x00420dd8
0x00420dd8:	movl -8(%ebp), %ebx
0x00420ddb:	cmpl 0x18(%ebp), %ebx
0x00420dde:	jne 0x00420de8
0x00420de8:	movl %esi, 0x434094
0x00420dee:	xorl %eax, %eax
0x00420df0:	cmpl 0x20(%ebp), %ebx
0x00420df3:	pushl %ebx
0x00420df4:	pushl %ebx
0x00420df5:	pushl 0x10(%ebp)
0x00420df8:	setne %al
0x00420dfb:	pushl 0xc(%ebp)
0x00420dfe:	leal %eax, 0x1(,%eax,8)
0x00420e05:	pushl %eax
0x00420e06:	pushl 0x18(%ebp)
0x00420e09:	call MultiByteToWideChar@KERNEL32.DLL
MultiByteToWideChar@KERNEL32.DLL: API Node	
0x00420e0b:	movl %edi, %eax
0x00420e0d:	cmpl %edi, %ebx
0x00420e0f:	je 171
0x00420e15:	jle 60
0x00420e17:	cmpl %edi, $0x7ffffff0<UINT32>
0x00420e1d:	ja 52
0x00420e1f:	leal %eax, 0x8(%edi,%edi)
0x00420e23:	cmpl %eax, $0x400<UINT32>
0x00420e28:	ja 19
0x00420e2a:	call 0x00416c50
0x00416c50:	pushl %ecx
0x00416c51:	leal %ecx, 0x8(%esp)
0x00416c55:	subl %ecx, %eax
0x00416c57:	andl %ecx, $0xf<UINT8>
0x00416c5a:	addl %eax, %ecx
0x00416c5c:	sbbl %ecx, %ecx
0x00416c5e:	orl %eax, %ecx
0x00416c60:	popl %ecx
0x00416c61:	jmp 0x0040af70
0x0040af70:	pushl %ecx
0x0040af71:	leal %ecx, 0x4(%esp)
0x0040af75:	subl %ecx, %eax
0x0040af77:	sbbl %eax, %eax
0x0040af79:	notl %eax
0x0040af7b:	andl %ecx, %eax
0x0040af7d:	movl %eax, %esp
0x0040af7f:	andl %eax, $0xfffff000<UINT32>
0x0040af84:	cmpl %ecx, %eax
0x0040af86:	jb 10
0x0040af88:	movl %eax, %ecx
0x0040af8a:	popl %ecx
0x0040af8b:	xchgl %esp, %eax
0x0040af8c:	movl %eax, (%eax)
0x0040af8e:	movl (%esp), %eax
0x0040af91:	ret

0x00420e2f:	movl %eax, %esp
0x00420e31:	cmpl %eax, %ebx
0x00420e33:	je 28
0x00420e35:	movl (%eax), $0xcccc<UINT32>
0x00420e3b:	jmp 0x00420e4e
0x00420e4e:	addl %eax, $0x8<UINT8>
0x00420e51:	movl %ebx, %eax
0x00420e53:	testl %ebx, %ebx
0x00420e55:	je 105
0x00420e57:	leal %eax, (%edi,%edi)
0x00420e5a:	pushl %eax
0x00420e5b:	pushl $0x0<UINT8>
0x00420e5d:	pushl %ebx
0x00420e5e:	call 0x00409ec0
0x00420e63:	addl %esp, $0xc<UINT8>
0x00420e66:	pushl %edi
0x00420e67:	pushl %ebx
0x00420e68:	pushl 0x10(%ebp)
0x00420e6b:	pushl 0xc(%ebp)
0x00420e6e:	pushl $0x1<UINT8>
0x00420e70:	pushl 0x18(%ebp)
0x00420e73:	call MultiByteToWideChar@KERNEL32.DLL
0x00420e75:	testl %eax, %eax
0x00420e77:	je 17
0x00420e79:	pushl 0x14(%ebp)
0x00420e7c:	pushl %eax
0x00420e7d:	pushl %ebx
0x00420e7e:	pushl 0x8(%ebp)
0x00420e81:	call GetStringTypeW@KERNEL32.DLL
0x00420e87:	movl -8(%ebp), %eax
0x00420e8a:	pushl %ebx
0x00420e8b:	call 0x0040c211
0x0040c211:	movl %edi, %edi
0x0040c213:	pushl %ebp
0x0040c214:	movl %ebp, %esp
0x0040c216:	movl %eax, 0x8(%ebp)
0x0040c219:	testl %eax, %eax
0x0040c21b:	je 18
0x0040c21d:	subl %eax, $0x8<UINT8>
0x0040c220:	cmpl (%eax), $0xdddd<UINT32>
0x0040c226:	jne 0x0040c22f
0x0040c22f:	popl %ebp
0x0040c230:	ret

0x00420e90:	movl %eax, -8(%ebp)
0x00420e93:	popl %ecx
0x00420e94:	jmp 0x00420f0b
0x00420f0b:	leal %esp, -20(%ebp)
0x00420f0e:	popl %edi
0x00420f0f:	popl %esi
0x00420f10:	popl %ebx
0x00420f11:	movl %ecx, -4(%ebp)
0x00420f14:	xorl %ecx, %ebp
0x00420f16:	call 0x00409eab
0x00409eab:	cmpl %ecx, 0x43d1b0
0x00409eb1:	jne 2
0x00409eb3:	rep ret

0x00420f1b:	leave
0x00420f1c:	ret

0x00420f4d:	addl %esp, $0x1c<UINT8>
0x00420f50:	cmpb -4(%ebp), $0x0<UINT8>
0x00420f54:	je 7
0x00420f56:	movl %ecx, -8(%ebp)
0x00420f59:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00420f5d:	leave
0x00420f5e:	ret

0x0040fe8c:	xorl %ebx, %ebx
0x0040fe8e:	pushl %ebx
0x0040fe8f:	pushl 0x4(%esi)
0x0040fe92:	leal %eax, -516(%ebp)
0x0040fe98:	pushl %edi
0x0040fe99:	pushl %eax
0x0040fe9a:	pushl %edi
0x0040fe9b:	leal %eax, -260(%ebp)
0x0040fea1:	pushl %eax
0x0040fea2:	pushl %edi
0x0040fea3:	pushl 0xc(%esi)
0x0040fea6:	pushl %ebx
0x0040fea7:	call 0x00420d1e
0x00420d1e:	movl %edi, %edi
0x00420d20:	pushl %ebp
0x00420d21:	movl %ebp, %esp
0x00420d23:	subl %esp, $0x10<UINT8>
0x00420d26:	pushl 0x8(%ebp)
0x00420d29:	leal %ecx, -16(%ebp)
0x00420d2c:	call 0x0040a674
0x00420d31:	pushl 0x28(%ebp)
0x00420d34:	leal %ecx, -16(%ebp)
0x00420d37:	pushl 0x24(%ebp)
0x00420d3a:	pushl 0x20(%ebp)
0x00420d3d:	pushl 0x1c(%ebp)
0x00420d40:	pushl 0x18(%ebp)
0x00420d43:	pushl 0x14(%ebp)
0x00420d46:	pushl 0x10(%ebp)
0x00420d49:	pushl 0xc(%ebp)
0x00420d4c:	call 0x00420979
0x00420979:	movl %edi, %edi
0x0042097b:	pushl %ebp
0x0042097c:	movl %ebp, %esp
0x0042097e:	subl %esp, $0x14<UINT8>
0x00420981:	movl %eax, 0x43d1b0
0x00420986:	xorl %eax, %ebp
0x00420988:	movl -4(%ebp), %eax
0x0042098b:	pushl %ebx
0x0042098c:	pushl %esi
0x0042098d:	xorl %ebx, %ebx
0x0042098f:	pushl %edi
0x00420990:	movl %esi, %ecx
0x00420992:	cmpl 0x53f1d0, %ebx
0x00420998:	jne 0x004209d2
0x0042099a:	pushl %ebx
0x0042099b:	pushl %ebx
0x0042099c:	xorl %edi, %edi
0x0042099e:	incl %edi
0x0042099f:	pushl %edi
0x004209a0:	pushl $0x438cb0<UINT32>
0x004209a5:	pushl $0x100<UINT32>
0x004209aa:	pushl %ebx
0x004209ab:	call LCMapStringW@KERNEL32.DLL
LCMapStringW@KERNEL32.DLL: API Node	
0x004209b1:	testl %eax, %eax
0x004209b3:	je 8
0x004209b5:	movl 0x53f1d0, %edi
0x004209bb:	jmp 0x004209d2
0x004209d2:	cmpl 0x14(%ebp), %ebx
0x004209d5:	jle 0x004209f9
0x004209f9:	movl %eax, 0x53f1d0
0x004209fe:	cmpl %eax, $0x2<UINT8>
0x00420a01:	je 428
0x00420a07:	cmpl %eax, %ebx
0x00420a09:	je 420
0x00420a0f:	cmpl %eax, $0x1<UINT8>
0x00420a12:	jne 460
0x00420a18:	movl -8(%ebp), %ebx
0x00420a1b:	cmpl 0x20(%ebp), %ebx
0x00420a1e:	jne 0x00420a28
0x00420a28:	movl %esi, 0x434094
0x00420a2e:	xorl %eax, %eax
0x00420a30:	cmpl 0x24(%ebp), %ebx
0x00420a33:	pushl %ebx
0x00420a34:	pushl %ebx
0x00420a35:	pushl 0x14(%ebp)
0x00420a38:	setne %al
0x00420a3b:	pushl 0x10(%ebp)
0x00420a3e:	leal %eax, 0x1(,%eax,8)
0x00420a45:	pushl %eax
0x00420a46:	pushl 0x20(%ebp)
0x00420a49:	call MultiByteToWideChar@KERNEL32.DLL
0x00420a4b:	movl %edi, %eax
0x00420a4d:	cmpl %edi, %ebx
0x00420a4f:	je 0x00420be4
0x00420be4:	xorl %eax, %eax
0x00420be6:	jmp 0x00420d0c
0x00420d0c:	leal %esp, -32(%ebp)
0x00420d0f:	popl %edi
0x00420d10:	popl %esi
0x00420d11:	popl %ebx
0x00420d12:	movl %ecx, -4(%ebp)
0x00420d15:	xorl %ecx, %ebp
0x00420d17:	call 0x00409eab
0x00420d1c:	leave
0x00420d1d:	ret

0x00420d51:	addl %esp, $0x20<UINT8>
0x00420d54:	cmpb -4(%ebp), $0x0<UINT8>
0x00420d58:	je 7
0x00420d5a:	movl %ecx, -8(%ebp)
0x00420d5d:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00420d61:	leave
0x00420d62:	ret

0x0040feac:	addl %esp, $0x44<UINT8>
0x0040feaf:	pushl %ebx
0x0040feb0:	pushl 0x4(%esi)
0x0040feb3:	leal %eax, -772(%ebp)
0x0040feb9:	pushl %edi
0x0040feba:	pushl %eax
0x0040febb:	pushl %edi
0x0040febc:	leal %eax, -260(%ebp)
0x0040fec2:	pushl %eax
0x0040fec3:	pushl $0x200<UINT32>
0x0040fec8:	pushl 0xc(%esi)
0x0040fecb:	pushl %ebx
0x0040fecc:	call 0x00420d1e
0x0040fed1:	addl %esp, $0x24<UINT8>
0x0040fed4:	xorl %eax, %eax
0x0040fed6:	movzwl %ecx, -1284(%ebp,%eax,2)
0x0040fede:	testb %cl, $0x1<UINT8>
0x0040fee1:	je 0x0040fef1
0x0040fef1:	testb %cl, $0x2<UINT8>
0x0040fef4:	je 0x0040ff0b
0x0040ff0b:	movb 0x11d(%esi,%eax), $0x0<UINT8>
0x0040ff13:	incl %eax
0x0040ff14:	cmpl %eax, %edi
0x0040ff16:	jb -66
0x0040ff18:	jmp 0x0040ff70
0x0040ff70:	movl %ecx, -4(%ebp)
0x0040ff73:	popl %edi
0x0040ff74:	xorl %ecx, %ebp
0x0040ff76:	popl %ebx
0x0040ff77:	call 0x00409eab
0x0040ff7c:	leave
0x0040ff7d:	ret

0x00410214:	jmp 0x004100d0
0x004100d0:	xorl %eax, %eax
0x004100d2:	jmp 0x00410274
0x00410274:	movl %ecx, -4(%ebp)
0x00410277:	popl %edi
0x00410278:	popl %esi
0x00410279:	xorl %ecx, %ebp
0x0041027b:	popl %ebx
0x0041027c:	call 0x00409eab
0x00410281:	leave
0x00410282:	ret

0x00410324:	popl %ecx
0x00410325:	popl %ecx
0x00410326:	movl -32(%ebp), %eax
0x00410329:	testl %eax, %eax
0x0041032b:	jne 252
0x00410331:	movl %esi, -36(%ebp)
0x00410334:	pushl 0x68(%esi)
0x00410337:	call InterlockedDecrement@KERNEL32.DLL
InterlockedDecrement@KERNEL32.DLL: API Node	
0x0041033d:	testl %eax, %eax
0x0041033f:	jne 17
0x00410341:	movl %eax, 0x68(%esi)
0x00410344:	cmpl %eax, $0x43d670<UINT32>
0x00410349:	je 0x00410352
0x00410352:	movl 0x68(%esi), %ebx
0x00410355:	pushl %ebx
0x00410356:	movl %edi, 0x434230
0x0041035c:	call InterlockedIncrement@KERNEL32.DLL
0x0041035e:	testb 0x70(%esi), $0x2<UINT8>
0x00410362:	jne 234
0x00410368:	testb 0x43db94, $0x1<UINT8>
0x0041036f:	jne 221
0x00410375:	pushl $0xd<UINT8>
0x00410377:	call 0x0041200e
0x0041037c:	popl %ecx
0x0041037d:	andl -4(%ebp), $0x0<UINT8>
0x00410381:	movl %eax, 0x4(%ebx)
0x00410384:	movl 0x53eb54, %eax
0x00410389:	movl %eax, 0x8(%ebx)
0x0041038c:	movl 0x53eb58, %eax
0x00410391:	movl %eax, 0xc(%ebx)
0x00410394:	movl 0x53eb5c, %eax
0x00410399:	xorl %eax, %eax
0x0041039b:	movl -28(%ebp), %eax
0x0041039e:	cmpl %eax, $0x5<UINT8>
0x004103a1:	jnl 0x004103b3
0x004103a3:	movw %cx, 0x10(%ebx,%eax,2)
0x004103a8:	movw 0x53eb48(,%eax,2), %cx
0x004103b0:	incl %eax
0x004103b1:	jmp 0x0041039b
0x004103b3:	xorl %eax, %eax
0x004103b5:	movl -28(%ebp), %eax
0x004103b8:	cmpl %eax, $0x101<UINT32>
0x004103bd:	jnl 0x004103cc
0x004103bf:	movb %cl, 0x1c(%eax,%ebx)
0x004103c3:	movb 0x43d890(%eax), %cl
0x004103c9:	incl %eax
0x004103ca:	jmp 0x004103b5
0x004103cc:	xorl %eax, %eax
0x004103ce:	movl -28(%ebp), %eax
0x004103d1:	cmpl %eax, $0x100<UINT32>
0x004103d6:	jnl 0x004103e8
0x004103d8:	movb %cl, 0x11d(%eax,%ebx)
0x004103df:	movb 0x43d998(%eax), %cl
0x004103e5:	incl %eax
0x004103e6:	jmp 0x004103ce
0x004103e8:	pushl 0x43da98
0x004103ee:	call InterlockedDecrement@KERNEL32.DLL
0x004103f4:	testl %eax, %eax
0x004103f6:	jne 0x0041040b
0x0041040b:	movl 0x43da98, %ebx
0x00410411:	pushl %ebx
0x00410412:	call InterlockedIncrement@KERNEL32.DLL
0x00410414:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0041041b:	call 0x00410422
0x00410422:	pushl $0xd<UINT8>
0x00410424:	call 0x00411f1c
0x00410429:	popl %ecx
0x0041042a:	ret

0x00410420:	jmp 0x00410452
0x00410452:	movl %eax, -32(%ebp)
0x00410455:	call 0x0040d065
0x0041045a:	ret

0x0041046b:	popl %ecx
0x0041046c:	movl 0x53f2e8, $0x1<UINT32>
0x00410476:	xorl %eax, %eax
0x00410478:	ret

0x00417333:	pushl $0x104<UINT32>
0x00417338:	movl %esi, $0x53f048<UINT32>
0x0041733d:	pushl %esi
0x0041733e:	pushl %ebx
0x0041733f:	movb 0x53f14c, %bl
0x00417345:	call GetModuleFileNameA@KERNEL32.DLL
GetModuleFileNameA@KERNEL32.DLL: API Node	
0x0041734b:	movl %eax, 0x540444
0x00417350:	movl 0x53ed1c, %esi
0x00417356:	cmpl %eax, %ebx
0x00417358:	je 7
0x0041735a:	movl -4(%ebp), %eax
0x0041735d:	cmpb (%eax), %bl
0x0041735f:	jne 0x00417364
0x00417364:	movl %edx, -4(%ebp)
0x00417367:	leal %eax, -8(%ebp)
0x0041736a:	pushl %eax
0x0041736b:	pushl %ebx
0x0041736c:	pushl %ebx
0x0041736d:	leal %edi, -12(%ebp)
0x00417370:	call 0x0041717f
0x0041717f:	movl %edi, %edi
0x00417181:	pushl %ebp
0x00417182:	movl %ebp, %esp
0x00417184:	pushl %ecx
0x00417185:	movl %ecx, 0x10(%ebp)
0x00417188:	pushl %ebx
0x00417189:	xorl %eax, %eax
0x0041718b:	pushl %esi
0x0041718c:	movl (%edi), %eax
0x0041718e:	movl %esi, %edx
0x00417190:	movl %edx, 0xc(%ebp)
0x00417193:	movl (%ecx), $0x1<UINT32>
0x00417199:	cmpl 0x8(%ebp), %eax
0x0041719c:	je 0x004171a7
0x004171a7:	movl -4(%ebp), %eax
0x004171aa:	cmpb (%esi), $0x22<UINT8>
0x004171ad:	jne 0x004171bf
0x004171af:	xorl %eax, %eax
0x004171b1:	cmpl -4(%ebp), %eax
0x004171b4:	movb %bl, $0x22<UINT8>
0x004171b6:	sete %al
0x004171b9:	incl %esi
0x004171ba:	movl -4(%ebp), %eax
0x004171bd:	jmp 0x004171fb
0x004171fb:	cmpl -4(%ebp), $0x0<UINT8>
0x004171ff:	jne 0x004171aa
0x004171bf:	incl (%edi)
0x004171c1:	testl %edx, %edx
0x004171c3:	je 0x004171cd
0x004171cd:	movb %bl, (%esi)
0x004171cf:	movzbl %eax, %bl
0x004171d2:	pushl %eax
0x004171d3:	incl %esi
0x004171d4:	call 0x0042a230
0x0042a230:	movl %edi, %edi
0x0042a232:	pushl %ebp
0x0042a233:	movl %ebp, %esp
0x0042a235:	pushl $0x4<UINT8>
0x0042a237:	pushl $0x0<UINT8>
0x0042a239:	pushl 0x8(%ebp)
0x0042a23c:	pushl $0x0<UINT8>
0x0042a23e:	call 0x0042a024
0x0042a024:	movl %edi, %edi
0x0042a026:	pushl %ebp
0x0042a027:	movl %ebp, %esp
0x0042a029:	subl %esp, $0x10<UINT8>
0x0042a02c:	pushl 0x8(%ebp)
0x0042a02f:	leal %ecx, -16(%ebp)
0x0042a032:	call 0x0040a674
0x0042a037:	movzbl %eax, 0xc(%ebp)
0x0042a03b:	movl %ecx, -12(%ebp)
0x0042a03e:	movb %dl, 0x14(%ebp)
0x0042a041:	testb 0x1d(%ecx,%eax), %dl
0x0042a045:	jne 30
0x0042a047:	cmpl 0x10(%ebp), $0x0<UINT8>
0x0042a04b:	je 0x0042a05f
0x0042a05f:	xorl %eax, %eax
0x0042a061:	testl %eax, %eax
0x0042a063:	je 0x0042a068
0x0042a068:	cmpb -4(%ebp), $0x0<UINT8>
0x0042a06c:	je 7
0x0042a06e:	movl %ecx, -8(%ebp)
0x0042a071:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0042a075:	leave
0x0042a076:	ret

0x0042a243:	addl %esp, $0x10<UINT8>
0x0042a246:	popl %ebp
0x0042a247:	ret

0x004171d9:	popl %ecx
0x004171da:	testl %eax, %eax
0x004171dc:	je 0x004171f1
0x004171f1:	movl %edx, 0xc(%ebp)
0x004171f4:	movl %ecx, 0x10(%ebp)
0x004171f7:	testb %bl, %bl
0x004171f9:	je 0x0041722d
0x00417201:	cmpb %bl, $0x20<UINT8>
0x00417204:	je 5
0x00417206:	cmpb %bl, $0x9<UINT8>
0x00417209:	jne 0x004171aa
0x0041722d:	decl %esi
0x0041722e:	jmp 0x00417213
0x00417213:	andl -4(%ebp), $0x0<UINT8>
0x00417217:	cmpb (%esi), $0x0<UINT8>
0x0041721a:	je 0x00417309
0x00417309:	movl %eax, 0x8(%ebp)
0x0041730c:	popl %esi
0x0041730d:	popl %ebx
0x0041730e:	testl %eax, %eax
0x00417310:	je 0x00417315
0x00417315:	incl (%ecx)
0x00417317:	leave
0x00417318:	ret

0x00417375:	movl %eax, -8(%ebp)
0x00417378:	addl %esp, $0xc<UINT8>
0x0041737b:	cmpl %eax, $0x3fffffff<UINT32>
0x00417380:	jae 74
0x00417382:	movl %ecx, -12(%ebp)
0x00417385:	cmpl %ecx, $0xffffffff<UINT8>
0x00417388:	jae 66
0x0041738a:	movl %edi, %eax
0x0041738c:	shll %edi, $0x2<UINT8>
0x0041738f:	leal %eax, (%edi,%ecx)
0x00417392:	cmpl %eax, %ecx
0x00417394:	jb 54
0x00417396:	pushl %eax
0x00417397:	call 0x00415da6
0x0041739c:	movl %esi, %eax
0x0041739e:	popl %ecx
0x0041739f:	cmpl %esi, %ebx
0x004173a1:	je 41
0x004173a3:	movl %edx, -4(%ebp)
0x004173a6:	leal %eax, -8(%ebp)
0x004173a9:	pushl %eax
0x004173aa:	addl %edi, %esi
0x004173ac:	pushl %edi
0x004173ad:	pushl %esi
0x004173ae:	leal %edi, -12(%ebp)
0x004173b1:	call 0x0041717f
0x0041719e:	movl %ebx, 0x8(%ebp)
0x004171a1:	addl 0x8(%ebp), $0x4<UINT8>
0x004171a5:	movl (%ebx), %edx
0x004171c5:	movb %al, (%esi)
0x004171c7:	movb (%edx), %al
0x004171c9:	incl %edx
0x004171ca:	movl 0xc(%ebp), %edx
0x00417312:	andl (%eax), $0x0<UINT8>
0x004173b6:	movl %eax, -8(%ebp)
0x004173b9:	addl %esp, $0xc<UINT8>
0x004173bc:	decl %eax
0x004173bd:	movl 0x53ed00, %eax
0x004173c2:	movl 0x53ed04, %esi
0x004173c8:	xorl %eax, %eax
0x004173ca:	jmp 0x004173cf
0x004173cf:	popl %edi
0x004173d0:	popl %esi
0x004173d1:	popl %ebx
0x004173d2:	leave
0x004173d3:	ret

0x0040c8c9:	testl %eax, %eax
0x0040c8cb:	jnl 0x0040c8d5
0x0040c8d5:	call 0x00417092
0x00417092:	cmpl 0x53f2e8, $0x0<UINT8>
0x00417099:	jne 0x004170a0
0x004170a0:	pushl %esi
0x004170a1:	movl %esi, 0x53e804
0x004170a7:	pushl %edi
0x004170a8:	xorl %edi, %edi
0x004170aa:	testl %esi, %esi
0x004170ac:	jne 0x004170c6
0x004170c6:	movb %al, (%esi)
0x004170c8:	testb %al, %al
0x004170ca:	jne 0x004170b6
0x004170b6:	cmpb %al, $0x3d<UINT8>
0x004170b8:	je 0x004170bb
0x004170bb:	pushl %esi
0x004170bc:	call 0x0040e770
0x0040e770:	movl %ecx, 0x4(%esp)
0x0040e774:	testl %ecx, $0x3<UINT32>
0x0040e77a:	je 0x0040e7a0
0x0040e7a0:	movl %eax, (%ecx)
0x0040e7a2:	movl %edx, $0x7efefeff<UINT32>
0x0040e7a7:	addl %edx, %eax
0x0040e7a9:	xorl %eax, $0xffffffff<UINT8>
0x0040e7ac:	xorl %eax, %edx
0x0040e7ae:	addl %ecx, $0x4<UINT8>
0x0040e7b1:	testl %eax, $0x81010100<UINT32>
0x0040e7b6:	je 0x0040e7a0
0x0040e7b8:	movl %eax, -4(%ecx)
0x0040e7bb:	testb %al, %al
0x0040e7bd:	je 50
0x0040e7bf:	testb %ah, %ah
0x0040e7c1:	je 36
0x0040e7c3:	testl %eax, $0xff0000<UINT32>
0x0040e7c8:	je 19
0x0040e7ca:	testl %eax, $0xff000000<UINT32>
0x0040e7cf:	je 0x0040e7d3
0x0040e7d3:	leal %eax, -1(%ecx)
0x0040e7d6:	movl %ecx, 0x4(%esp)
0x0040e7da:	subl %eax, %ecx
0x0040e7dc:	ret

0x004170c1:	popl %ecx
0x004170c2:	leal %esi, 0x1(%esi,%eax)
0x004170cc:	pushl $0x4<UINT8>
0x004170ce:	incl %edi
0x004170cf:	pushl %edi
0x004170d0:	call 0x00415deb
0x004170d5:	movl %edi, %eax
0x004170d7:	popl %ecx
0x004170d8:	popl %ecx
0x004170d9:	movl 0x53ed0c, %edi
0x004170df:	testl %edi, %edi
0x004170e1:	je -53
0x004170e3:	movl %esi, 0x53e804
0x004170e9:	pushl %ebx
0x004170ea:	jmp 0x0041712e
0x0041712e:	cmpb (%esi), $0x0<UINT8>
0x00417131:	jne 0x004170ec
0x004170ec:	pushl %esi
0x004170ed:	call 0x0040e770
0x004170f2:	movl %ebx, %eax
0x004170f4:	incl %ebx
0x004170f5:	cmpb (%esi), $0x3d<UINT8>
0x004170f8:	popl %ecx
0x004170f9:	je 0x0041712c
0x0041712c:	addl %esi, %ebx
0x00417133:	pushl 0x53e804
0x00417139:	call 0x0040bee8
0x0040bee8:	pushl $0xc<UINT8>
0x0040beea:	pushl $0x43aa48<UINT32>
0x0040beef:	call 0x0040d020
0x0040bef4:	movl %esi, 0x8(%ebp)
0x0040bef7:	testl %esi, %esi
0x0040bef9:	je 117
0x0040befb:	cmpl 0x53f41c, $0x3<UINT8>
0x0040bf02:	jne 0x0040bf47
0x0040bf47:	pushl %esi
0x0040bf48:	pushl $0x0<UINT8>
0x0040bf4a:	pushl 0x53ece8
0x0040bf50:	call HeapFree@KERNEL32.DLL
HeapFree@KERNEL32.DLL: API Node	
0x0040bf56:	testl %eax, %eax
0x0040bf58:	jne 0x0040bf70
0x0040bf70:	call 0x0040d065
0x0040bf75:	ret

0x0041713e:	andl 0x53e804, $0x0<UINT8>
0x00417145:	andl (%edi), $0x0<UINT8>
0x00417148:	movl 0x53f2dc, $0x1<UINT32>
0x00417152:	xorl %eax, %eax
0x00417154:	popl %ecx
0x00417155:	popl %ebx
0x00417156:	popl %edi
0x00417157:	popl %esi
0x00417158:	ret

0x0040c8da:	testl %eax, %eax
0x0040c8dc:	jnl 0x0040c8e6
0x0040c8e6:	pushl %ebx
0x0040c8e7:	call 0x00415918
0x00415918:	movl %edi, %edi
0x0041591a:	pushl %ebp
0x0041591b:	movl %ebp, %esp
0x0041591d:	cmpl 0x4378fc, $0x0<UINT8>
0x00415924:	je 25
0x00415926:	pushl $0x4378fc<UINT32>
0x0041592b:	call 0x00416d70
0x00416d70:	movl %edi, %edi
0x00416d72:	pushl %ebp
0x00416d73:	movl %ebp, %esp
0x00416d75:	pushl $0xfffffffe<UINT8>
0x00416d77:	pushl $0x43b010<UINT32>
0x00416d7c:	pushl $0x40d0b0<UINT32>
0x00416d81:	movl %eax, %fs:0
0x00416d87:	pushl %eax
0x00416d88:	subl %esp, $0x8<UINT8>
0x00416d8b:	pushl %ebx
0x00416d8c:	pushl %esi
0x00416d8d:	pushl %edi
0x00416d8e:	movl %eax, 0x43d1b0
0x00416d93:	xorl -8(%ebp), %eax
0x00416d96:	xorl %eax, %ebp
0x00416d98:	pushl %eax
0x00416d99:	leal %eax, -16(%ebp)
0x00416d9c:	movl %fs:0, %eax
0x00416da2:	movl -24(%ebp), %esp
0x00416da5:	movl -4(%ebp), $0x0<UINT32>
0x00416dac:	pushl $0x400000<UINT32>
0x00416db1:	call 0x00416ce0
0x00416ce0:	movl %edi, %edi
0x00416ce2:	pushl %ebp
0x00416ce3:	movl %ebp, %esp
0x00416ce5:	movl %ecx, 0x8(%ebp)
0x00416ce8:	movl %eax, $0x5a4d<UINT32>
0x00416ced:	cmpw (%ecx), %ax
0x00416cf0:	je 0x00416cf6
0x00416cf6:	movl %eax, 0x3c(%ecx)
0x00416cf9:	addl %eax, %ecx
0x00416cfb:	cmpl (%eax), $0x4550<UINT32>
0x00416d01:	jne -17
0x00416d03:	xorl %edx, %edx
0x00416d05:	movl %ecx, $0x10b<UINT32>
0x00416d0a:	cmpw 0x18(%eax), %cx
0x00416d0e:	sete %dl
0x00416d11:	movl %eax, %edx
0x00416d13:	popl %ebp
0x00416d14:	ret

0x00416db6:	addl %esp, $0x4<UINT8>
0x00416db9:	testl %eax, %eax
0x00416dbb:	je 85
0x00416dbd:	movl %eax, 0x8(%ebp)
0x00416dc0:	subl %eax, $0x400000<UINT32>
0x00416dc5:	pushl %eax
0x00416dc6:	pushl $0x400000<UINT32>
0x00416dcb:	call 0x00416d20
0x00416d20:	movl %edi, %edi
0x00416d22:	pushl %ebp
0x00416d23:	movl %ebp, %esp
0x00416d25:	movl %eax, 0x8(%ebp)
0x00416d28:	movl %ecx, 0x3c(%eax)
0x00416d2b:	addl %ecx, %eax
0x00416d2d:	movzwl %eax, 0x14(%ecx)
0x00416d31:	pushl %ebx
0x00416d32:	pushl %esi
0x00416d33:	movzwl %esi, 0x6(%ecx)
0x00416d37:	xorl %edx, %edx
0x00416d39:	pushl %edi
0x00416d3a:	leal %eax, 0x18(%eax,%ecx)
0x00416d3e:	testl %esi, %esi
0x00416d40:	jbe 27
0x00416d42:	movl %edi, 0xc(%ebp)
0x00416d45:	movl %ecx, 0xc(%eax)
0x00416d48:	cmpl %edi, %ecx
0x00416d4a:	jb 9
0x00416d4c:	movl %ebx, 0x8(%eax)
0x00416d4f:	addl %ebx, %ecx
0x00416d51:	cmpl %edi, %ebx
0x00416d53:	jb 0x00416d5f
0x00416d5f:	popl %edi
0x00416d60:	popl %esi
0x00416d61:	popl %ebx
0x00416d62:	popl %ebp
0x00416d63:	ret

0x00416dd0:	addl %esp, $0x8<UINT8>
0x00416dd3:	testl %eax, %eax
0x00416dd5:	je 59
0x00416dd7:	movl %eax, 0x24(%eax)
0x00416dda:	shrl %eax, $0x1f<UINT8>
0x00416ddd:	notl %eax
0x00416ddf:	andl %eax, $0x1<UINT8>
0x00416de2:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00416de9:	movl %ecx, -16(%ebp)
0x00416dec:	movl %fs:0, %ecx
0x00416df3:	popl %ecx
0x00416df4:	popl %edi
0x00416df5:	popl %esi
0x00416df6:	popl %ebx
0x00416df7:	movl %esp, %ebp
0x00416df9:	popl %ebp
0x00416dfa:	ret

0x00415930:	popl %ecx
0x00415931:	testl %eax, %eax
0x00415933:	je 10
0x00415935:	pushl 0x8(%ebp)
0x00415938:	call 0x0040c12a
0x0040c12a:	movl %edi, %edi
0x0040c12c:	pushl %ebp
0x0040c12d:	movl %ebp, %esp
0x0040c12f:	call 0x0040c0b5
0x0040c0b5:	movl %eax, $0x416a9a<UINT32>
0x0040c0ba:	movl 0x43dee8, %eax
0x0040c0bf:	movl 0x43deec, $0x416124<UINT32>
0x0040c0c9:	movl 0x43def0, $0x4160d8<UINT32>
0x0040c0d3:	movl 0x43def4, $0x416111<UINT32>
0x0040c0dd:	movl 0x43def8, $0x41607a<UINT32>
0x0040c0e7:	movl 0x43defc, %eax
0x0040c0ec:	movl 0x43df00, $0x416a12<UINT32>
0x0040c0f6:	movl 0x43df04, $0x416096<UINT32>
0x0040c100:	movl 0x43df08, $0x415ff8<UINT32>
0x0040c10a:	movl 0x43df0c, $0x415f85<UINT32>
0x0040c114:	ret

0x0040c134:	call 0x00416b47
0x00416b47:	pushl $0x43818c<UINT32>
0x00416b4c:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x00416b52:	testl %eax, %eax
0x00416b54:	je 21
0x00416b56:	pushl $0x438170<UINT32>
0x00416b5b:	pushl %eax
0x00416b5c:	call GetProcAddress@KERNEL32.DLL
0x00416b62:	testl %eax, %eax
0x00416b64:	je 5
0x00416b66:	pushl $0x0<UINT8>
0x00416b68:	call IsProcessorFeaturePresent@KERNEL32
IsProcessorFeaturePresent@KERNEL32: API Node	
0x00416b6a:	ret

0x0040c139:	cmpl 0x8(%ebp), $0x0<UINT8>
0x0040c13d:	movl 0x53e7fc, %eax
0x0040c142:	je 5
0x0040c144:	call 0x00416ade
0x00416ade:	movl %edi, %edi
0x00416ae0:	pushl %esi
0x00416ae1:	pushl $0x30000<UINT32>
0x00416ae6:	pushl $0x10000<UINT32>
0x00416aeb:	xorl %esi, %esi
0x00416aed:	pushl %esi
0x00416aee:	call 0x00429fb8
0x00429fb8:	movl %edi, %edi
0x00429fba:	pushl %ebp
0x00429fbb:	movl %ebp, %esp
0x00429fbd:	movl %eax, 0x10(%ebp)
0x00429fc0:	movl %ecx, 0xc(%ebp)
0x00429fc3:	andl %eax, $0xfff7ffff<UINT32>
0x00429fc8:	andl %ecx, %eax
0x00429fca:	pushl %esi
0x00429fcb:	testl %ecx, $0xfcf0fce0<UINT32>
0x00429fd1:	je 0x0042a004
0x0042a004:	movl %esi, 0x8(%ebp)
0x0042a007:	pushl %eax
0x0042a008:	pushl 0xc(%ebp)
0x0042a00b:	testl %esi, %esi
0x0042a00d:	je 0x0042a018
0x0042a018:	call 0x00430081
0x00430081:	movl %edi, %edi
0x00430083:	pushl %ebp
0x00430084:	movl %ebp, %esp
0x00430086:	subl %esp, $0x14<UINT8>
0x00430089:	pushl %ebx
0x0043008a:	pushl %esi
0x0043008b:	pushl %edi
0x0043008c:	fwait
0x0043008d:	fnstcw -8(%ebp)
0x00430090:	movl %ebx, -8(%ebp)
0x00430093:	xorl %edx, %edx
0x00430095:	testb %bl, $0x1<UINT8>
0x00430098:	je 0x0043009d
0x0043009d:	testb %bl, $0x4<UINT8>
0x004300a0:	je 3
0x004300a2:	orl %edx, $0x8<UINT8>
0x004300a5:	testb %bl, $0x8<UINT8>
0x004300a8:	je 3
0x004300aa:	orl %edx, $0x4<UINT8>
0x004300ad:	testb %bl, $0x10<UINT8>
0x004300b0:	je 0x004300b5
0x004300b5:	testb %bl, $0x20<UINT8>
0x004300b8:	je 3
0x004300ba:	orl %edx, $0x1<UINT8>
0x004300bd:	testb %bl, $0x2<UINT8>
0x004300c0:	je 0x004300c8
0x004300c8:	movzwl %ecx, %bx
0x004300cb:	movl %eax, %ecx
0x004300cd:	movl %esi, $0xc00<UINT32>
0x004300d2:	andl %eax, %esi
0x004300d4:	movl %edi, $0x300<UINT32>
0x004300d9:	je 36
0x004300db:	cmpl %eax, $0x400<UINT32>
0x004300e0:	je 23
0x004300e2:	cmpl %eax, $0x800<UINT32>
0x004300e7:	je 8
0x004300e9:	cmpl %eax, %esi
0x004300eb:	jne 18
0x004300ed:	orl %edx, %edi
0x004300ef:	jmp 0x004300ff
0x004300ff:	andl %ecx, %edi
0x00430101:	je 16
0x00430103:	cmpl %ecx, $0x200<UINT32>
0x00430109:	jne 14
0x0043010b:	orl %edx, $0x10000<UINT32>
0x00430111:	jmp 0x00430119
0x00430119:	testl %ebx, $0x1000<UINT32>
0x0043011f:	je 6
0x00430121:	orl %edx, $0x40000<UINT32>
0x00430127:	movl %edi, 0xc(%ebp)
0x0043012a:	movl %ecx, 0x8(%ebp)
0x0043012d:	movl %eax, %edi
0x0043012f:	notl %eax
0x00430131:	andl %eax, %edx
0x00430133:	andl %ecx, %edi
0x00430135:	orl %eax, %ecx
0x00430137:	movl 0xc(%ebp), %eax
0x0043013a:	cmpl %eax, %edx
0x0043013c:	je 0x004301f0
0x004301f0:	xorl %esi, %esi
0x004301f2:	cmpl 0x53f428, %esi
0x004301f8:	je 0x0043038b
0x0043038b:	popl %edi
0x0043038c:	popl %esi
0x0043038d:	popl %ebx
0x0043038e:	leave
0x0043038f:	ret

0x0042a01d:	popl %ecx
0x0042a01e:	popl %ecx
0x0042a01f:	xorl %eax, %eax
0x0042a021:	popl %esi
0x0042a022:	popl %ebp
0x0042a023:	ret

0x00416af3:	addl %esp, $0xc<UINT8>
0x00416af6:	testl %eax, %eax
0x00416af8:	je 0x00416b07
0x00416b07:	popl %esi
0x00416b08:	ret

0x0040c149:	fnclex
0x0040c14b:	popl %ebp
0x0040c14c:	ret

0x0041593e:	popl %ecx
0x0041593f:	call 0x00416abd
0x00416abd:	movl %edi, %edi
0x00416abf:	pushl %esi
0x00416ac0:	pushl %edi
0x00416ac1:	xorl %edi, %edi
0x00416ac3:	leal %esi, 0x43dee8(%edi)
0x00416ac9:	pushl (%esi)
0x00416acb:	call 0x0041173c
0x0041175e:	pushl %eax
0x0041175f:	pushl 0x43dc8c
0x00411765:	call TlsGetValue@KERNEL32.DLL
0x00411767:	call FlsGetValue@KERNEL32.DLL
0x00411769:	testl %eax, %eax
0x0041176b:	je 8
0x0041176d:	movl %eax, 0x1f8(%eax)
0x00411773:	jmp 0x0041179c
0x00416ad0:	addl %edi, $0x4<UINT8>
0x00416ad3:	popl %ecx
0x00416ad4:	movl (%esi), %eax
0x00416ad6:	cmpl %edi, $0x28<UINT8>
0x00416ad9:	jb 0x00416ac3
0x00416adb:	popl %edi
0x00416adc:	popl %esi
0x00416add:	ret

0x00415944:	pushl $0x434448<UINT32>
0x00415949:	pushl $0x434430<UINT32>
0x0041594e:	call 0x0041587c
0x0041587c:	movl %edi, %edi
0x0041587e:	pushl %ebp
0x0041587f:	movl %ebp, %esp
0x00415881:	pushl %esi
0x00415882:	movl %esi, 0x8(%ebp)
0x00415885:	xorl %eax, %eax
0x00415887:	jmp 0x00415898
0x00415898:	cmpl %esi, 0xc(%ebp)
0x0041589b:	jb 0x00415889
0x00415889:	testl %eax, %eax
0x0041588b:	jne 16
0x0041588d:	movl %ecx, (%esi)
0x0041588f:	testl %ecx, %ecx
0x00415891:	je 0x00415895
0x00415895:	addl %esi, $0x4<UINT8>
0x00415893:	call 0x00417025
0x0040c030:	movl %edi, %edi
0x0040c032:	pushl %esi
0x0040c033:	pushl $0x4<UINT8>
0x0040c035:	pushl $0x20<UINT8>
0x0040c037:	call 0x00415deb
0x0040c03c:	movl %esi, %eax
0x0040c03e:	pushl %esi
0x0040c03f:	call 0x0041173c
0x0040c044:	addl %esp, $0xc<UINT8>
0x0040c047:	movl 0x53f2e4, %eax
0x0040c04c:	movl 0x53f2e0, %eax
0x0040c051:	testl %esi, %esi
0x0040c053:	jne 0x0040c05a
0x0040c05a:	andl (%esi), $0x0<UINT8>
0x0040c05d:	xorl %eax, %eax
0x0040c05f:	popl %esi
0x0040c060:	ret

0x0040ce70:	movl %eax, 0x540440
0x0040ce75:	pushl %esi
0x0040ce76:	pushl $0x14<UINT8>
0x0040ce78:	popl %esi
0x0040ce79:	testl %eax, %eax
0x0040ce7b:	jne 7
0x0040ce7d:	movl %eax, $0x200<UINT32>
0x0040ce82:	jmp 0x0040ce8a
0x0040ce8a:	movl 0x540440, %eax
0x0040ce8f:	pushl $0x4<UINT8>
0x0040ce91:	pushl %eax
0x0040ce92:	call 0x00415deb
0x0040ce97:	popl %ecx
0x0040ce98:	popl %ecx
0x0040ce99:	movl 0x53f42c, %eax
0x0040ce9e:	testl %eax, %eax
0x0040cea0:	jne 0x0040cec0
0x0040cec0:	xorl %edx, %edx
0x0040cec2:	movl %ecx, $0x43d3d8<UINT32>
0x0040cec7:	jmp 0x0040cece
0x0040cece:	movl (%edx,%eax), %ecx
0x0040ced1:	addl %ecx, $0x20<UINT8>
0x0040ced4:	addl %edx, $0x4<UINT8>
0x0040ced7:	cmpl %ecx, $0x43d658<UINT32>
0x0040cedd:	jl 0x0040cec9
0x0040cec9:	movl %eax, 0x53f42c
0x0040cedf:	pushl $0xfffffffe<UINT8>
0x0040cee1:	popl %esi
0x0040cee2:	xorl %edx, %edx
0x0040cee4:	movl %ecx, $0x43d3e8<UINT32>
0x0040cee9:	pushl %edi
0x0040ceea:	movl %eax, %edx
0x0040ceec:	sarl %eax, $0x5<UINT8>
0x0040ceef:	movl %eax, 0x53f300(,%eax,4)
0x0040cef6:	movl %edi, %edx
0x0040cef8:	andl %edi, $0x1f<UINT8>
0x0040cefb:	shll %edi, $0x6<UINT8>
0x0040cefe:	movl %eax, (%edi,%eax)
0x0040cf01:	cmpl %eax, $0xffffffff<UINT8>
0x0040cf04:	je 8
0x0040cf06:	cmpl %eax, %esi
0x0040cf08:	je 4
0x0040cf0a:	testl %eax, %eax
0x0040cf0c:	jne 0x0040cf10
0x0040cf10:	addl %ecx, $0x20<UINT8>
0x0040cf13:	incl %edx
0x0040cf14:	cmpl %ecx, $0x43d448<UINT32>
0x0040cf1a:	jl 0x0040ceea
0x0040cf1c:	popl %edi
0x0040cf1d:	xorl %eax, %eax
0x0040cf1f:	popl %esi
0x0040cf20:	ret

0x0040e38d:	call 0x0040e32b
0x0040e32b:	movl %edi, %edi
0x0040e32d:	pushl %ebp
0x0040e32e:	movl %ebp, %esp
0x0040e330:	subl %esp, $0x18<UINT8>
0x0040e333:	xorl %eax, %eax
0x0040e335:	pushl %ebx
0x0040e336:	movl -4(%ebp), %eax
0x0040e339:	movl -12(%ebp), %eax
0x0040e33c:	movl -8(%ebp), %eax
0x0040e33f:	pushl %ebx
0x0040e340:	pushfl
0x0040e341:	popl %eax
0x0040e342:	movl %ecx, %eax
0x0040e344:	xorl %eax, $0x200000<UINT32>
0x0040e349:	pushl %eax
0x0040e34a:	popfl
0x0040e34b:	pushfl
0x0040e34c:	popl %edx
0x0040e34d:	subl %edx, %ecx
0x0040e34f:	je 0x0040e370
0x0040e370:	popl %ebx
0x0040e371:	testl -4(%ebp), $0x4000000<UINT32>
0x0040e378:	je 0x0040e388
0x0040e388:	xorl %eax, %eax
0x0040e38a:	popl %ebx
0x0040e38b:	leave
0x0040e38c:	ret

0x0040e392:	movl 0x53f428, %eax
0x0040e397:	xorl %eax, %eax
0x0040e399:	ret

0x00417025:	pushl $0x416fe3<UINT32>
0x0041702a:	call SetUnhandledExceptionFilter@KERNEL32.DLL
SetUnhandledExceptionFilter@KERNEL32.DLL: API Node	
0x00417030:	xorl %eax, %eax
0x00417032:	ret

0x0041589d:	popl %esi
0x0041589e:	popl %ebp
0x0041589f:	ret

0x00415953:	popl %ecx
0x00415954:	popl %ecx
0x00415955:	testl %eax, %eax
0x00415957:	jne 66
0x00415959:	pushl $0x417531<UINT32>
0x0041595e:	call 0x0040c09d
0x0040c09d:	movl %edi, %edi
0x0040c09f:	pushl %ebp
0x0040c0a0:	movl %ebp, %esp
0x0040c0a2:	pushl 0x8(%ebp)
0x0040c0a5:	call 0x0040c061
0x0040c061:	pushl $0xc<UINT8>
0x0040c063:	pushl $0x43aa68<UINT32>
0x0040c068:	call 0x0040d020
0x0040c06d:	call 0x0041584d
0x0041584d:	pushl $0x8<UINT8>
0x0041584f:	call 0x0041200e
0x00415854:	popl %ecx
0x00415855:	ret

0x0040c072:	andl -4(%ebp), $0x0<UINT8>
0x0040c076:	pushl 0x8(%ebp)
0x0040c079:	call 0x0040bf76
0x0040bf76:	movl %edi, %edi
0x0040bf78:	pushl %ebp
0x0040bf79:	movl %ebp, %esp
0x0040bf7b:	pushl %ecx
0x0040bf7c:	pushl %ebx
0x0040bf7d:	pushl %esi
0x0040bf7e:	pushl %edi
0x0040bf7f:	pushl 0x53f2e4
0x0040bf85:	call 0x004117b7
0x004117e8:	movl %eax, 0x1fc(%eax)
0x004117ee:	jmp 0x00411817
0x0040bf8a:	pushl 0x53f2e0
0x0040bf90:	movl %edi, %eax
0x0040bf92:	movl -4(%ebp), %edi
0x0040bf95:	call 0x004117b7
0x0040bf9a:	movl %esi, %eax
0x0040bf9c:	popl %ecx
0x0040bf9d:	popl %ecx
0x0040bf9e:	cmpl %esi, %edi
0x0040bfa0:	jb 131
0x0040bfa6:	movl %ebx, %esi
0x0040bfa8:	subl %ebx, %edi
0x0040bfaa:	leal %eax, 0x4(%ebx)
0x0040bfad:	cmpl %eax, $0x4<UINT8>
0x0040bfb0:	jb 119
0x0040bfb2:	pushl %edi
0x0040bfb3:	call 0x00415ed7
0x00415ed7:	pushl $0x10<UINT8>
0x00415ed9:	pushl $0x43aff0<UINT32>
0x00415ede:	call 0x0040d020
0x00415ee3:	xorl %eax, %eax
0x00415ee5:	movl %ebx, 0x8(%ebp)
0x00415ee8:	xorl %edi, %edi
0x00415eea:	cmpl %ebx, %edi
0x00415eec:	setne %al
0x00415eef:	cmpl %eax, %edi
0x00415ef1:	jne 0x00415f10
0x00415f10:	cmpl 0x53f41c, $0x3<UINT8>
0x00415f17:	jne 0x00415f51
0x00415f51:	pushl %ebx
0x00415f52:	pushl %edi
0x00415f53:	pushl 0x53ece8
0x00415f59:	call HeapSize@KERNEL32.DLL
HeapSize@KERNEL32.DLL: API Node	
0x00415f5f:	movl %esi, %eax
0x00415f61:	movl %eax, %esi
0x00415f63:	call 0x0040d065
0x00415f68:	ret

0x0040bfb8:	movl %edi, %eax
0x0040bfba:	leal %eax, 0x4(%ebx)
0x0040bfbd:	popl %ecx
0x0040bfbe:	cmpl %edi, %eax
0x0040bfc0:	jae 0x0040c00a
0x0040c00a:	pushl 0x8(%ebp)
0x0040c00d:	call 0x0041173c
0x0040c012:	movl (%esi), %eax
0x0040c014:	addl %esi, $0x4<UINT8>
0x0040c017:	pushl %esi
0x0040c018:	call 0x0041173c
0x0040c01d:	popl %ecx
0x0040c01e:	movl 0x53f2e0, %eax
0x0040c023:	movl %eax, 0x8(%ebp)
0x0040c026:	popl %ecx
0x0040c027:	jmp 0x0040c02b
0x0040c02b:	popl %edi
0x0040c02c:	popl %esi
0x0040c02d:	popl %ebx
0x0040c02e:	leave
0x0040c02f:	ret

0x0040c07e:	popl %ecx
0x0040c07f:	movl -28(%ebp), %eax
0x0040c082:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040c089:	call 0x0040c097
0x0040c097:	call 0x00415856
0x00415856:	pushl $0x8<UINT8>
0x00415858:	call 0x00411f1c
0x0041585d:	popl %ecx
0x0041585e:	ret

0x0040c09c:	ret

0x0040c08e:	movl %eax, -28(%ebp)
0x0040c091:	call 0x0040d065
0x0040c096:	ret

0x0040c0aa:	negl %eax
0x0040c0ac:	sbbl %eax, %eax
0x0040c0ae:	negl %eax
0x0040c0b0:	popl %ecx
0x0040c0b1:	decl %eax
0x0040c0b2:	popl %ebp
0x0040c0b3:	ret

0x00415963:	movl %eax, $0x4343fc<UINT32>
0x00415968:	movl (%esp), $0x43442c<UINT32>
0x0041596f:	call 0x0041585f
0x0041585f:	movl %edi, %edi
0x00415861:	pushl %ebp
0x00415862:	movl %ebp, %esp
0x00415864:	pushl %esi
0x00415865:	movl %esi, %eax
0x00415867:	jmp 0x00415874
0x00415874:	cmpl %esi, 0x8(%ebp)
0x00415877:	jb 0x00415869
0x00415869:	movl %eax, (%esi)
0x0041586b:	testl %eax, %eax
0x0041586d:	je 0x00415871
0x00415871:	addl %esi, $0x4<UINT8>
0x0041586f:	call 0x00433360
0x00433220:	pushl $0x434c3c<UINT32>
0x00433225:	pushl $0x434c28<UINT32>
0x0043322a:	call GetModuleHandleW@KERNEL32.DLL
0x00433230:	pushl %eax
0x00433231:	call GetProcAddress@KERNEL32.DLL
0x00433237:	movl 0x43e638, %eax
0x0043323c:	ret

0x00433240:	pushl $0x434c4c<UINT32>
0x00433245:	pushl $0x434c28<UINT32>
0x0043324a:	call GetModuleHandleW@KERNEL32.DLL
0x00433250:	pushl %eax
0x00433251:	call GetProcAddress@KERNEL32.DLL
0x00433257:	movl 0x43e634, %eax
0x0043325c:	ret

0x00433260:	pushl $0x43e61c<UINT32>
0x00433265:	call InitializeCriticalSection@KERNEL32.DLL
InitializeCriticalSection@KERNEL32.DLL: API Node	
0x0043326b:	pushl $0x433380<UINT32>
0x00433270:	call 0x0040c09d
0x00433275:	popl %ecx
0x00433276:	ret

0x00433280:	pushl $0xff<UINT32>
0x00433285:	call CreateSolidBrush@GDI32.dll
CreateSolidBrush@GDI32.dll: API Node	
0x0043328b:	pushl $0x433390<UINT32>
0x00433290:	movl 0x43d00c, %eax
0x00433295:	call 0x0040c09d
0x0043329a:	popl %ecx
0x0043329b:	ret

0x004332a0:	pushl $0xff00<UINT32>
0x004332a5:	call CreateSolidBrush@GDI32.dll
0x004332ab:	pushl $0x4333a0<UINT32>
0x004332b0:	movl 0x43d014, %eax
0x004332b5:	call 0x0040c09d
0x004332ba:	popl %ecx
0x004332bb:	ret

0x004332c0:	pushl $0xff0000<UINT32>
0x004332c5:	call CreateSolidBrush@GDI32.dll
0x004332cb:	pushl $0x4333b0<UINT32>
0x004332d0:	movl 0x43d01c, %eax
0x004332d5:	call 0x0040c09d
0x004332da:	popl %ecx
0x004332db:	ret

0x004332e0:	pushl $0x408000<UINT32>
0x004332e5:	call CreateSolidBrush@GDI32.dll
0x004332eb:	pushl $0x4333c0<UINT32>
0x004332f0:	movl 0x43d024, %eax
0x004332f5:	call 0x0040c09d
0x004332fa:	popl %ecx
0x004332fb:	ret

0x00433300:	pushl $0x804000<UINT32>
0x00433305:	call CreateSolidBrush@GDI32.dll
0x0043330b:	pushl $0x4333d0<UINT32>
0x00433310:	movl 0x43d02c, %eax
0x00433315:	call 0x0040c09d
0x0043331a:	popl %ecx
0x0043331b:	ret

0x00433320:	pushl $0xffffff<UINT32>
0x00433325:	call CreateSolidBrush@GDI32.dll
0x0043332b:	pushl $0x4333e0<UINT32>
0x00433330:	movl 0x43d034, %eax
0x00433335:	call 0x0040c09d
0x0043333a:	popl %ecx
0x0043333b:	ret

0x00433340:	pushl $0xffff<UINT32>
0x00433345:	call CreateSolidBrush@GDI32.dll
0x0043334b:	pushl $0x4333f0<UINT32>
0x00433350:	movl 0x43d03c, %eax
0x00433355:	call 0x0040c09d
0x0043335a:	popl %ecx
0x0043335b:	ret

0x00433360:	pushl $0xdcffdc<UINT32>
0x00433365:	call CreateSolidBrush@GDI32.dll
0x0043336b:	pushl $0x433400<UINT32>
0x00433370:	movl 0x43d044, %eax
0x00433375:	call 0x0040c09d
0x0043337a:	popl %ecx
0x0043337b:	ret

0x00415879:	popl %esi
0x0041587a:	popl %ebp
0x0041587b:	ret

0x00415974:	cmpl 0x53f2ec, $0x0<UINT8>
0x0041597b:	popl %ecx
0x0041597c:	je 0x00415999
0x00415999:	xorl %eax, %eax
0x0041599b:	popl %ebp
0x0041599c:	ret

0x0040c8ec:	popl %ecx
0x0040c8ed:	cmpl %eax, %esi
0x0040c8ef:	je 0x0040c8f8
0x0040c8f8:	call 0x00417033
0x00417033:	movl %edi, %edi
0x00417035:	pushl %esi
0x00417036:	pushl %edi
0x00417037:	xorl %edi, %edi
0x00417039:	cmpl 0x53f2e8, %edi
0x0041703f:	jne 0x00417046
0x00417046:	movl %esi, 0x540444
0x0041704c:	testl %esi, %esi
0x0041704e:	jne 0x00417055
0x00417055:	movb %al, (%esi)
0x00417057:	cmpb %al, $0x20<UINT8>
0x00417059:	ja 0x00417063
0x00417063:	cmpb %al, $0x22<UINT8>
0x00417065:	jne 0x00417070
0x00417067:	xorl %ecx, %ecx
0x00417069:	testl %edi, %edi
0x0041706b:	sete %cl
0x0041706e:	movl %edi, %ecx
0x00417070:	movzbl %eax, %al
0x00417073:	pushl %eax
0x00417074:	call 0x0042a230
0x00417079:	popl %ecx
0x0041707a:	testl %eax, %eax
0x0041707c:	je 0x0041707f
0x0041707f:	incl %esi
0x00417080:	jmp 0x00417055
0x0041705b:	testb %al, %al
0x0041705d:	je 0x0041708d
0x0041708d:	popl %edi
0x0041708e:	movl %eax, %esi
0x00417090:	popl %esi
0x00417091:	ret

0x0040c8fd:	testb -60(%ebp), %bl
0x0040c900:	je 0x0040c908
0x0040c908:	pushl $0xa<UINT8>
0x0040c90a:	popl %ecx
0x0040c90b:	pushl %ecx
0x0040c90c:	pushl %eax
0x0040c90d:	pushl %esi
0x0040c90e:	pushl $0x400000<UINT32>
0x0040c913:	call 0x00408280
0x00408280:	subl %esp, $0x60<UINT8>
0x00408283:	pushl %ebx
0x00408284:	pushl %ebp
0x00408285:	pushl %esi
0x00408286:	pushl %edi
0x00408287:	call 0x004010a0
0x004010a0:	pushl %ecx
0x004010a1:	pushl %esi
0x004010a2:	pushl $0x4344c0<UINT32>
0x004010a7:	pushl $0x4344a4<UINT32>
0x004010ac:	movl 0xc(%esp), $0x0<UINT32>
0x004010b4:	call GetModuleHandleW@KERNEL32.DLL
0x004010ba:	pushl %eax
0x004010bb:	call GetProcAddress@KERNEL32.DLL
0x004010c1:	movl %esi, %eax
0x004010c3:	testl %esi, %esi
0x004010c5:	je 14
0x004010c7:	leal %eax, 0x4(%esp)
0x004010cb:	pushl %eax
0x004010cc:	call GetCurrentProcess@KERNEL32.DLL
GetCurrentProcess@KERNEL32.DLL: API Node	
0x004010d2:	pushl %eax
0x004010d3:	call IsWow64Process@kernel32.dll
IsWow64Process@kernel32.dll: API Node	
0x004010d5:	movl %eax, 0x4(%esp)
0x004010d9:	popl %esi
0x004010da:	popl %ecx
0x004010db:	ret

0x0040828c:	testl %eax, %eax
0x0040828e:	je 0x00408465
0x00408465:	leal %edx, 0x1c(%esp)
0x00408469:	pushl %edx
0x0040846a:	call GetCommandLineW@KERNEL32.DLL
GetCommandLineW@KERNEL32.DLL: API Node	
0x00408470:	pushl %eax
0x00408471:	call CommandLineToArgvW@SHELL32.dll
CommandLineToArgvW@SHELL32.dll: API Node	
0x00408477:	pushl %eax
0x00408478:	leal %eax, 0x20(%esp)
0x0040847c:	pushl %eax
0x0040847d:	pushl $0x4346d0<UINT32>
0x00408482:	call 0x00408f20
0x00408f20:	pushl %ebx
0x00408f21:	movl %ebx, 0xc(%esp)
0x00408f25:	pushl %ebp
0x00408f26:	pushl %esi
0x00408f27:	xorl %ebp, %ebp
0x00408f29:	pushl %edi
0x00408f2a:	testl %ebx, %ebx
0x00408f2c:	je 8
0x00408f2e:	movl %edi, 0x1c(%esp)
0x00408f32:	testl %edi, %edi
0x00408f34:	jne 0x00408f64
0x00408f64:	xorl %esi, %esi
0x00408f66:	cmpl (%ebx), %ebp
0x00408f68:	jle 0x00408fc1
0x00408fc1:	movl %edx, 0x14(%esp)
0x00408fc5:	pushl %ebp
0x00408fc6:	pushl %edx
0x00408fc7:	call 0x00408b90
0x00408b90:	subl %esp, $0x214<UINT32>
0x00408b96:	movl %eax, 0x43d1b0
0x00408b9b:	xorl %eax, %esp
0x00408b9d:	movl 0x210(%esp), %eax
0x00408ba4:	pushl %ebp
0x00408ba5:	movl %ebp, 0x21c(%esp)
0x00408bac:	pushl %ebp
0x00408bad:	leal %eax, 0x10(%esp)
0x00408bb1:	pushl $0x437724<UINT32>
0x00408bb6:	pushl %eax
0x00408bb7:	movl 0x10(%esp), $0x0<UINT32>
0x00408bbf:	call 0x0040a46f
0x0040a46f:	movl %edi, %edi
0x0040a471:	pushl %ebp
0x0040a472:	movl %ebp, %esp
0x0040a474:	subl %esp, $0x20<UINT8>
0x0040a477:	pushl %ebx
0x0040a478:	xorl %ebx, %ebx
0x0040a47a:	cmpl 0xc(%ebp), %ebx
0x0040a47d:	jne 0x0040a49c
0x0040a49c:	movl %eax, 0x8(%ebp)
0x0040a49f:	cmpl %eax, %ebx
0x0040a4a1:	je -36
0x0040a4a3:	pushl %esi
0x0040a4a4:	movl -24(%ebp), %eax
0x0040a4a7:	movl -32(%ebp), %eax
0x0040a4aa:	leal %eax, 0x10(%ebp)
0x0040a4ad:	pushl %eax
0x0040a4ae:	pushl %ebx
0x0040a4af:	pushl 0xc(%ebp)
0x0040a4b2:	leal %eax, -32(%ebp)
0x0040a4b5:	pushl %eax
0x0040a4b6:	movl -20(%ebp), $0x42<UINT32>
0x0040a4bd:	movl -28(%ebp), $0x7fffffff<UINT32>
0x0040a4c4:	call 0x0040ecc7
0x0040ecc7:	movl %edi, %edi
0x0040ecc9:	pushl %ebp
0x0040ecca:	movl %ebp, %esp
0x0040eccc:	subl %esp, $0x474<UINT32>
0x0040ecd2:	movl %eax, 0x43d1b0
0x0040ecd7:	xorl %eax, %ebp
0x0040ecd9:	movl -4(%ebp), %eax
0x0040ecdc:	movl %eax, 0x8(%ebp)
0x0040ecdf:	pushl %ebx
0x0040ece0:	movl %ebx, 0x14(%ebp)
0x0040ece3:	pushl %esi
0x0040ece4:	movl %esi, 0xc(%ebp)
0x0040ece7:	pushl %edi
0x0040ece8:	pushl 0x10(%ebp)
0x0040eceb:	xorl %edi, %edi
0x0040eced:	leal %ecx, -1112(%ebp)
0x0040ecf3:	movl -1072(%ebp), %eax
0x0040ecf9:	movl -1052(%ebp), %ebx
0x0040ecff:	movl -1096(%ebp), %edi
0x0040ed05:	movl -1032(%ebp), %edi
0x0040ed0b:	movl -1068(%ebp), %edi
0x0040ed11:	movl -1036(%ebp), %edi
0x0040ed17:	movl -1060(%ebp), %edi
0x0040ed1d:	movl -1084(%ebp), %edi
0x0040ed23:	movl -1064(%ebp), %edi
0x0040ed29:	call 0x0040a674
0x0040ed2e:	cmpl -1072(%ebp), %edi
0x0040ed34:	jne 0x0040ed69
0x0040ed69:	cmpl %esi, %edi
0x0040ed6b:	je -55
0x0040ed6d:	movzwl %edx, (%esi)
0x0040ed70:	xorl %ecx, %ecx
0x0040ed72:	movl -1056(%ebp), %edi
0x0040ed78:	movl -1044(%ebp), %edi
0x0040ed7e:	movl -1092(%ebp), %edi
0x0040ed84:	movl -1048(%ebp), %edx
0x0040ed8a:	cmpw %dx, %di
0x0040ed8d:	je 2689
0x0040ed93:	pushl $0x2<UINT8>
0x0040ed95:	popl %edi
0x0040ed96:	addl %esi, %edi
0x0040ed98:	cmpl -1056(%ebp), $0x0<UINT8>
0x0040ed9f:	movl -1088(%ebp), %esi
0x0040eda5:	jl 2665
0x0040edab:	leal %eax, -32(%edx)
0x0040edae:	cmpw %ax, $0x58<UINT8>
0x0040edb2:	ja 0x0040edc3
0x0040edb4:	movzwl %eax, %dx
0x0040edb7:	movsbl %eax, 0x437af0(%eax)
0x0040edbe:	andl %eax, $0xf<UINT8>
0x0040edc1:	jmp 0x0040edc5
0x0040edc5:	movsbl %eax, 0x437b10(%ecx,%eax,8)
0x0040edcd:	pushl $0x7<UINT8>
0x0040edcf:	sarl %eax, $0x4<UINT8>
0x0040edd2:	popl %ecx
0x0040edd3:	movl -1116(%ebp), %eax
0x0040edd9:	cmpl %eax, %ecx
0x0040eddb:	ja 2549
0x0040ede1:	jmp 0x0040f027
0x0040f006:	movl %eax, -1072(%ebp)
0x0040f00c:	pushl %edx
0x0040f00d:	leal %esi, -1056(%ebp)
0x0040f013:	movl -1064(%ebp), $0x1<UINT32>
0x0040f01d:	call 0x0040ebf8
0x0040ebf8:	movl %edi, %edi
0x0040ebfa:	pushl %ebp
0x0040ebfb:	movl %ebp, %esp
0x0040ebfd:	testb 0xc(%eax), $0x40<UINT8>
0x0040ec01:	je 6
0x0040ec03:	cmpl 0x8(%eax), $0x0<UINT8>
0x0040ec07:	je 26
0x0040ec09:	pushl %eax
0x0040ec0a:	pushl 0x8(%ebp)
0x0040ec0d:	call 0x0041e449
0x0041e449:	movl %edi, %edi
0x0041e44b:	pushl %ebp
0x0041e44c:	movl %ebp, %esp
0x0041e44e:	subl %esp, $0x10<UINT8>
0x0041e451:	movl %eax, 0x43d1b0
0x0041e456:	xorl %eax, %ebp
0x0041e458:	movl -4(%ebp), %eax
0x0041e45b:	pushl %ebx
0x0041e45c:	pushl %esi
0x0041e45d:	movl %esi, 0xc(%ebp)
0x0041e460:	testb 0xc(%esi), $0x40<UINT8>
0x0041e464:	pushl %edi
0x0041e465:	jne 0x0041e5a1
0x0041e5a1:	addl 0x4(%esi), $0xfffffffe<UINT8>
0x0041e5a5:	js 13
0x0041e5a7:	movl %ecx, (%esi)
0x0041e5a9:	movl %eax, 0x8(%ebp)
0x0041e5ac:	movw (%ecx), %ax
0x0041e5af:	addl (%esi), $0x2<UINT8>
0x0041e5b2:	jmp 0x0041e5c1
0x0041e5c1:	movl %ecx, -4(%ebp)
0x0041e5c4:	popl %edi
0x0041e5c5:	popl %esi
0x0041e5c6:	xorl %ecx, %ebp
0x0041e5c8:	popl %ebx
0x0041e5c9:	call 0x00409eab
0x0041e5ce:	leave
0x0041e5cf:	ret

0x0040ec12:	popl %ecx
0x0040ec13:	popl %ecx
0x0040ec14:	movl %ecx, $0xffff<UINT32>
0x0040ec19:	cmpw %ax, %cx
0x0040ec1c:	jne 0x0040ec23
0x0040ec23:	incl (%esi)
0x0040ec25:	popl %ebp
0x0040ec26:	ret

0x0040f022:	jmp 0x0040f7d5
0x0040f7d5:	popl %ecx
0x0040f7d6:	movl %esi, -1088(%ebp)
0x0040f7dc:	movzwl %eax, (%esi)
0x0040f7df:	movl -1048(%ebp), %eax
0x0040f7e5:	testw %ax, %ax
0x0040f7e8:	je 0x0040f814
0x0040f7ea:	movl %ecx, -1116(%ebp)
0x0040f7f0:	movl %ebx, -1052(%ebp)
0x0040f7f6:	movl %edx, %eax
0x0040f7f8:	jmp 0x0040ed93
0x0040edc3:	xorl %eax, %eax
0x0040ede8:	xorl %eax, %eax
0x0040edea:	orl -1036(%ebp), $0xffffffff<UINT8>
0x0040edf1:	movl -1120(%ebp), %eax
0x0040edf7:	movl -1084(%ebp), %eax
0x0040edfd:	movl -1068(%ebp), %eax
0x0040ee03:	movl -1060(%ebp), %eax
0x0040ee09:	movl -1032(%ebp), %eax
0x0040ee0f:	movl -1064(%ebp), %eax
0x0040ee15:	jmp 0x0040f7d6
0x0040f027:	movzwl %eax, %dx
0x0040f02a:	cmpl %eax, $0x64<UINT8>
0x0040f02d:	jg 0x0040f262
0x0040f262:	cmpl %eax, $0x70<UINT8>
0x0040f265:	jg 0x0040f465
0x0040f465:	subl %eax, $0x73<UINT8>
0x0040f468:	je 0x0040f0d5
0x0040f0d5:	movl %edi, -1036(%ebp)
0x0040f0db:	cmpl %edi, $0xffffffff<UINT8>
0x0040f0de:	jne 5
0x0040f0e0:	movl %edi, $0x7fffffff<UINT32>
0x0040f0e5:	addl %ebx, $0x4<UINT8>
0x0040f0e8:	testb -1032(%ebp), $0x20<UINT8>
0x0040f0ef:	movl -1052(%ebp), %ebx
0x0040f0f5:	movl %ebx, -4(%ebx)
0x0040f0f8:	movl -1040(%ebp), %ebx
0x0040f0fe:	je 0x0040f60c
0x0040f60c:	testl %ebx, %ebx
0x0040f60e:	jne 0x0040f61b
0x0040f61b:	movl %eax, -1040(%ebp)
0x0040f621:	movl -1064(%ebp), $0x1<UINT32>
0x0040f62b:	jmp 0x0040f636
0x0040f636:	testl %edi, %edi
0x0040f638:	jne 0x0040f62d
0x0040f62d:	decl %edi
0x0040f62e:	cmpw (%eax), $0x0<UINT8>
0x0040f632:	je 0x0040f63a
0x0040f634:	incl %eax
0x0040f635:	incl %eax
0x0040f63a:	subl %eax, -1040(%ebp)
0x0040f640:	sarl %eax
0x0040f642:	movl -1044(%ebp), %eax
0x0040f648:	cmpl -1084(%ebp), $0x0<UINT8>
0x0040f64f:	jne 357
0x0040f655:	movl %eax, -1032(%ebp)
0x0040f65b:	testb %al, $0x40<UINT8>
0x0040f65d:	je 0x0040f68a
0x0040f68a:	movl %ebx, -1068(%ebp)
0x0040f690:	movl %esi, -1044(%ebp)
0x0040f696:	subl %ebx, %esi
0x0040f698:	subl %ebx, -1060(%ebp)
0x0040f69e:	testb -1032(%ebp), $0xc<UINT8>
0x0040f6a5:	jne 23
0x0040f6a7:	pushl -1072(%ebp)
0x0040f6ad:	leal %eax, -1056(%ebp)
0x0040f6b3:	pushl %ebx
0x0040f6b4:	pushl $0x20<UINT8>
0x0040f6b6:	call 0x0040ec27
0x0040ec27:	movl %edi, %edi
0x0040ec29:	pushl %ebp
0x0040ec2a:	movl %ebp, %esp
0x0040ec2c:	pushl %esi
0x0040ec2d:	movl %esi, %eax
0x0040ec2f:	jmp 0x0040ec45
0x0040ec45:	cmpl 0xc(%ebp), $0x0<UINT8>
0x0040ec49:	jg -26
0x0040ec4b:	popl %esi
0x0040ec4c:	popl %ebp
0x0040ec4d:	ret

0x0040f6bb:	addl %esp, $0xc<UINT8>
0x0040f6be:	pushl -1060(%ebp)
0x0040f6c4:	movl %edi, -1072(%ebp)
0x0040f6ca:	leal %eax, -1056(%ebp)
0x0040f6d0:	leal %ecx, -1080(%ebp)
0x0040f6d6:	call 0x0040ec4e
0x0040ec4e:	movl %edi, %edi
0x0040ec50:	pushl %ebp
0x0040ec51:	movl %ebp, %esp
0x0040ec53:	testb 0xc(%edi), $0x40<UINT8>
0x0040ec57:	pushl %ebx
0x0040ec58:	pushl %esi
0x0040ec59:	movl %esi, %eax
0x0040ec5b:	movl %ebx, %ecx
0x0040ec5d:	je 55
0x0040ec5f:	cmpl 0x8(%edi), $0x0<UINT8>
0x0040ec63:	jne 0x0040ec96
0x0040ec96:	cmpl 0x8(%ebp), $0x0<UINT8>
0x0040ec9a:	jg 0x0040ec6c
0x0040ec9c:	popl %esi
0x0040ec9d:	popl %ebx
0x0040ec9e:	popl %ebp
0x0040ec9f:	ret

0x0040f6db:	testb -1032(%ebp), $0x8<UINT8>
0x0040f6e2:	popl %ecx
0x0040f6e3:	je 0x0040f700
0x0040f700:	cmpl -1064(%ebp), $0x0<UINT8>
0x0040f707:	jne 0x0040f77e
0x0040f77e:	movl %ecx, -1040(%ebp)
0x0040f784:	pushl %esi
0x0040f785:	leal %eax, -1056(%ebp)
0x0040f78b:	call 0x0040ec4e
0x0040ec6c:	movzwl %eax, (%ebx)
0x0040ec6f:	decl 0x8(%ebp)
0x0040ec72:	pushl %eax
0x0040ec73:	movl %eax, %edi
0x0040ec75:	call 0x0040ebf8
0x0040ec7a:	incl %ebx
0x0040ec7b:	incl %ebx
0x0040ec7c:	cmpl (%esi), $0xffffffff<UINT8>
0x0040ec7f:	popl %ecx
0x0040ec80:	jne 0x0040ec96
0x0040f790:	popl %ecx
0x0040f791:	cmpl -1056(%ebp), $0x0<UINT8>
0x0040f798:	jl 32
0x0040f79a:	testb -1032(%ebp), $0x4<UINT8>
0x0040f7a1:	je 0x0040f7ba
0x0040f7ba:	cmpl -1092(%ebp), $0x0<UINT8>
0x0040f7c1:	je 0x0040f7d6
0x0040f814:	cmpb -1100(%ebp), $0x0<UINT8>
0x0040f81b:	je 10
0x0040f81d:	movl %eax, -1104(%ebp)
0x0040f823:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x0040f827:	movl %eax, -1056(%ebp)
0x0040f82d:	movl %ecx, -4(%ebp)
0x0040f830:	popl %edi
0x0040f831:	popl %esi
0x0040f832:	xorl %ecx, %ebp
0x0040f834:	popl %ebx
0x0040f835:	call 0x00409eab
0x0040f83a:	leave
0x0040f83b:	ret

0x0040a4c9:	addl %esp, $0x10<UINT8>
0x0040a4cc:	decl -28(%ebp)
0x0040a4cf:	movl %esi, %eax
0x0040a4d1:	js 10
0x0040a4d3:	movl %eax, -32(%ebp)
0x0040a4d6:	movb (%eax), %bl
0x0040a4d8:	incl -32(%ebp)
0x0040a4db:	jmp 0x0040a4e9
0x0040a4e9:	decl -28(%ebp)
0x0040a4ec:	js 7
0x0040a4ee:	movl %eax, -32(%ebp)
0x0040a4f1:	movb (%eax), %bl
0x0040a4f3:	jmp 0x0040a501
0x0040a501:	movl %eax, %esi
0x0040a503:	popl %esi
0x0040a504:	popl %ebx
0x0040a505:	leave
0x0040a506:	ret

0x00408bc4:	addl %esp, $0xc<UINT8>
0x00408bc7:	leal %ecx, 0x4(%esp)
0x00408bcb:	pushl %ecx
0x00408bcc:	leal %edx, 0x10(%esp)
0x00408bd0:	pushl %edx
0x00408bd1:	pushl $0x80000001<UINT32>
0x00408bd6:	call RegCreateKeyW@ADVAPI32.dll
RegCreateKeyW@ADVAPI32.dll: API Node	
0x00408bdc:	testl %eax, %eax
0x00408bde:	jne 41
0x00408be0:	movl %edx, 0x4(%esp)
0x00408be4:	leal %eax, 0x8(%esp)
0x00408be8:	pushl %eax
0x00408be9:	leal %ecx, 0x224(%esp)
0x00408bf0:	pushl %ecx
0x00408bf1:	pushl $0x0<UINT8>
0x00408bf3:	pushl $0x0<UINT8>
0x00408bf5:	pushl $0x437708<UINT32>
0x00408bfa:	pushl %edx
0x00408bfb:	movl 0x20(%esp), $0x4<UINT32>
0x00408c03:	call RegQueryValueExW@ADVAPI32.dll
RegQueryValueExW@ADVAPI32.dll: API Node	
0x00408c09:	cmpl 0x220(%esp), $0x0<UINT8>
0x00408c11:	jne 694
0x00408c17:	pushl %ebx
0x00408c18:	pushl %esi
0x00408c19:	pushl %edi
0x00408c1a:	pushl $0x3e8<UINT32>
0x00408c1f:	pushl $0x40<UINT8>
0x00408c21:	call LocalAlloc@KERNEL32.DLL
LocalAlloc@KERNEL32.DLL: API Node	
0x00408c27:	movl %esi, %eax
0x00408c29:	pushl $0x4376ec<UINT32>
0x00408c2e:	leal %edi, 0x12(%esi)
0x00408c31:	call LoadLibraryW@KERNEL32.DLL
LoadLibraryW@KERNEL32.DLL: API Node	
0x00408c37:	xorl %eax, %eax
0x00408c39:	movw 0xa(%esi), %ax
0x0040d0b0:	movl %edi, %edi
0x0040d0b2:	pushl %ebp
0x0040d0b3:	movl %ebp, %esp
0x0040d0b5:	subl %esp, $0x18<UINT8>
0x0040d0b8:	pushl %ebx
0x0040d0b9:	movl %ebx, 0xc(%ebp)
0x0040d0bc:	pushl %esi
0x0040d0bd:	movl %esi, 0x8(%ebx)
0x0040d0c0:	xorl %esi, 0x43d1b0
0x0040d0c6:	pushl %edi
0x0040d0c7:	movl %eax, (%esi)
0x0040d0c9:	movb -1(%ebp), $0x0<UINT8>
0x0040d0cd:	movl -12(%ebp), $0x1<UINT32>
0x0040d0d4:	leal %edi, 0x10(%ebx)
0x0040d0d7:	cmpl %eax, $0xfffffffe<UINT8>
0x0040d0da:	je 0x0040d0e9
0x0040d0e9:	movl %ecx, 0xc(%esi)
0x0040d0ec:	movl %eax, 0x8(%esi)
0x0040d0ef:	addl %ecx, %edi
0x0040d0f1:	xorl %ecx, (%eax,%edi)
0x0040d0f4:	call 0x00409eab
0x0040d0f9:	movl %eax, 0x8(%ebp)
0x0040d0fc:	testb 0x4(%eax), $0x66<UINT8>
0x0040d100:	jne 278
0x0040d106:	movl %ecx, 0x10(%ebp)
0x0040d109:	leal %edx, -24(%ebp)
0x0040d10c:	movl -4(%ebx), %edx
0x0040d10f:	movl %ebx, 0xc(%ebx)
0x0040d112:	movl -24(%ebp), %eax
0x0040d115:	movl -20(%ebp), %ecx
0x0040d118:	cmpl %ebx, $0xfffffffe<UINT8>
0x0040d11b:	je 95
0x0040d11d:	leal %ecx, (%ecx)
0x0040d120:	leal %eax, (%ebx,%ebx,2)
0x0040d123:	movl %ecx, 0x14(%esi,%eax,4)
0x0040d127:	leal %eax, 0x10(%esi,%eax,4)
0x0040d12b:	movl -16(%ebp), %eax
0x0040d12e:	movl %eax, (%eax)
0x0040d130:	movl -8(%ebp), %eax
0x0040d133:	testl %ecx, %ecx
0x0040d135:	je 20
0x0040d137:	movl %edx, %edi
0x0040d139:	call 0x0040e08e
0x0040e08e:	pushl %ebp
0x0040e08f:	pushl %esi
0x0040e090:	pushl %edi
0x0040e091:	pushl %ebx
0x0040e092:	movl %ebp, %edx
0x0040e094:	xorl %eax, %eax
0x0040e096:	xorl %ebx, %ebx
0x0040e098:	xorl %edx, %edx
0x0040e09a:	xorl %esi, %esi
0x0040e09c:	xorl %edi, %edi
0x0040e09e:	call 0x0040c930
0x0040c930:	movl %eax, -20(%ebp)
0x0040c933:	movl %ecx, (%eax)
0x0040c935:	movl %ecx, (%ecx)
0x0040c937:	movl -36(%ebp), %ecx
0x0040c93a:	pushl %eax
0x0040c93b:	pushl %ecx
0x0040c93c:	call 0x00416e63
0x00416e63:	movl %edi, %edi
0x00416e65:	pushl %ebp
0x00416e66:	movl %ebp, %esp
0x00416e68:	pushl %ecx
0x00416e69:	pushl %ecx
0x00416e6a:	pushl %esi
0x00416e6b:	call 0x004119c7
0x00416e70:	movl %esi, %eax
0x00416e72:	testl %esi, %esi
0x00416e74:	je 326
0x00416e7a:	movl %edx, 0x5c(%esi)
0x00416e7d:	movl %eax, 0x43df1c
0x00416e82:	pushl %edi
0x00416e83:	movl %edi, 0x8(%ebp)
0x00416e86:	movl %ecx, %edx
0x00416e88:	pushl %ebx
0x00416e89:	cmpl (%ecx), %edi
0x00416e8b:	je 0x00416e9b
0x00416e9b:	imull %eax, %eax, $0xc<UINT8>
0x00416e9e:	addl %eax, %edx
0x00416ea0:	cmpl %ecx, %eax
0x00416ea2:	jae 8
0x00416ea4:	cmpl (%ecx), %edi
0x00416ea6:	jne 4
0x00416ea8:	movl %eax, %ecx
0x00416eaa:	jmp 0x00416eae
0x00416eae:	testl %eax, %eax
0x00416eb0:	je 10
0x00416eb2:	movl %ebx, 0x8(%eax)
0x00416eb5:	movl -4(%ebp), %ebx
0x00416eb8:	testl %ebx, %ebx
0x00416eba:	jne 7
0x00416ebc:	xorl %eax, %eax
0x00416ebe:	jmp 0x00416fbe
0x00416fbe:	popl %ebx
0x00416fbf:	popl %edi
0x00416fc0:	popl %esi
0x00416fc1:	leave
0x00416fc2:	ret

0x0040c941:	popl %ecx
0x0040c942:	popl %ecx
0x0040c943:	ret

0x0040e0a0:	popl %ebx
0x0040e0a1:	popl %edi
0x0040e0a2:	popl %esi
0x0040e0a3:	popl %ebp
0x0040e0a4:	ret

0x0040d13e:	movb -1(%ebp), $0x1<UINT8>
0x0040d142:	testl %eax, %eax
0x0040d144:	jl 64
0x0040d146:	jg 71
0x0040d148:	movl %eax, -8(%ebp)
0x0040d14b:	movl %ebx, %eax
0x0040d14d:	cmpl %eax, $0xfffffffe<UINT8>
0x0040d150:	jne -50
0x0040d152:	cmpb -1(%ebp), $0x0<UINT8>
0x0040d156:	je 36
0x0040d158:	movl %eax, (%esi)
0x0040d15a:	cmpl %eax, $0xfffffffe<UINT8>
0x0040d15d:	je 0x0040d16c
0x0040d16c:	movl %ecx, 0xc(%esi)
0x0040d16f:	movl %edx, 0x8(%esi)
0x0040d172:	addl %ecx, %edi
0x0040d174:	xorl %ecx, (%edx,%edi)
0x0040d177:	call 0x00409eab
0x0040d17c:	movl %eax, -12(%ebp)
0x0040d17f:	popl %edi
0x0040d180:	popl %esi
0x0040d181:	popl %ebx
0x0040d182:	movl %esp, %ebp
0x0040d184:	popl %ebp
0x0040d185:	ret

0x00408c3d:	xorl %ecx, %ecx
0x00408c3f:	movl %edx, $0x138<UINT32>
0x00408c44:	movw 0xe(%esi), %dx
0x00408c48:	movw 0xc(%esi), %cx
0x00408c4c:	movl %eax, $0xb4<UINT32>
0x00408c51:	movw 0x10(%esi), %ax
0x00408c55:	movw 0x8(%esi), %cx
0x00408c59:	movl (%esi), $0x80c808d0<UINT32>
0x00408c5f:	xorl %edx, %edx
0x00408c61:	movw (%edi), %dx
0x00408c64:	addl %edi, $0x2<UINT8>
0x00408c67:	xorl %eax, %eax
0x00408c69:	movw (%edi), %ax
0x00408c6c:	addl %edi, $0x2<UINT8>
0x00408c6f:	pushl %edi
0x00408c70:	movl %ecx, $0x4376c8<UINT32>
0x00408c75:	call 0x00408b50
0x00408b50:	movl %eax, %ecx
0x00408b52:	pushl %esi
0x00408b53:	leal %esi, 0x2(%eax)
0x00408b56:	movw %dx, (%eax)
0x00408b59:	addl %eax, $0x2<UINT8>
0x00408b5c:	testw %dx, %dx
0x00408b5f:	jne 0x00408b56
0x00408b61:	subl %eax, %esi
0x00408b63:	movl %esi, 0x8(%esp)
0x00408b67:	sarl %eax
0x00408b69:	incl %eax
0x00408b6a:	subl %esi, %ecx
0x00408b6c:	leal %esp, (%esp)
0x00408b70:	movzwl %edx, (%ecx)
0x00408b73:	movw (%esi,%ecx), %dx
0x00408b77:	addl %ecx, $0x2<UINT8>
0x00408b7a:	testw %dx, %dx
0x00408b7d:	jne 0x00408b70
0x00408b7f:	popl %esi
0x00408b80:	ret

0x00408c7a:	leal %edi, (%edi,%eax,2)
0x00408c7d:	movl %ecx, $0x8<UINT32>
0x00408c82:	movw (%edi), %cx
0x00408c85:	addl %edi, $0x2<UINT8>
0x00408c88:	pushl %edi
0x00408c89:	movl %ecx, $0x4376ac<UINT32>
0x00408c8e:	call 0x00408b50
0x00408c93:	leal %eax, (%edi,%eax,2)
0x00408c96:	call 0x00408b40
0x00408b40:	addl %eax, $0x3<UINT8>
0x00408b43:	andl %eax, $0xfffffffc<UINT8>
0x00408b46:	ret

0x00408c9b:	movl %edx, $0x7<UINT32>
0x00408ca0:	movw 0x8(%eax), %dx
0x00408ca4:	movl %ecx, $0x3<UINT32>
0x00408ca9:	movw 0xa(%eax), %cx
0x00408cad:	movl %edx, $0x12a<UINT32>
0x00408cb2:	movw 0xc(%eax), %dx
0x00408cb6:	movl %ecx, $0xe<UINT32>
0x00408cbb:	movw 0xe(%eax), %cx
0x00408cbf:	movl %edx, $0x1f6<UINT32>
0x00408cc4:	movw 0x10(%eax), %dx
0x00408cc8:	movl (%eax), $0x50000000<UINT32>
0x00408cce:	leal %edi, 0x12(%eax)
0x00408cd1:	movl %eax, $0xffff<UINT32>
0x00408cd6:	movw (%edi), %ax
0x00408cd9:	addl %edi, $0x2<UINT8>
0x00408cdc:	movl %ecx, $0x82<UINT32>
0x00408ce1:	movw (%edi), %cx
0x00408ce4:	addl %edi, $0x2<UINT8>
0x00408ce7:	pushl %edi
0x00408ce8:	movl %ecx, $0x437618<UINT32>
0x00408ced:	call 0x00408b50
0x00408cf2:	leal %eax, (%edi,%eax,2)
0x00408cf5:	xorl %edx, %edx
0x00408cf7:	movw (%eax), %dx
0x00408cfa:	movl %ebx, $0x1<UINT32>
0x00408cff:	addw 0x8(%esi), %bx
0x00408d03:	addl %eax, $0x2<UINT8>
0x00408d06:	call 0x00408b40
0x00408d0b:	movl %ecx, $0xc9<UINT32>
0x00408d10:	movw 0x8(%eax), %cx
0x00408d14:	movl %edx, $0x9f<UINT32>
0x00408d19:	movw 0xa(%eax), %dx
0x00408d1d:	movl %ecx, $0x32<UINT32>
0x00408d22:	movl %edx, $0xe<UINT32>
0x00408d27:	movw 0xc(%eax), %cx
0x00408d2b:	movw 0xe(%eax), %dx
0x00408d2f:	movl %ecx, %ebx
0x00408d31:	leal %edi, 0x12(%eax)
0x00408d34:	movl %edx, $0xffff<UINT32>
0x00408d39:	movw 0x10(%eax), %cx
0x00408d3d:	movl (%eax), $0x50010000<UINT32>
0x00408d43:	movw (%edi), %dx
0x00408d46:	addl %edi, $0x2<UINT8>
0x00408d49:	movl %eax, $0x80<UINT32>
0x00408d4e:	movw (%edi), %ax
0x00408d51:	addl %edi, $0x2<UINT8>
0x00408d54:	pushl %edi
0x00408d55:	movl %ecx, $0x437608<UINT32>
0x00408d5a:	call 0x00408b50
0x00408d5f:	leal %eax, (%edi,%eax,2)
0x00408d62:	xorl %ecx, %ecx
0x00408d64:	movw (%eax), %cx
0x00408d67:	addw 0x8(%esi), %bx
0x00408d6b:	addl %eax, $0x2<UINT8>
0x00408d6e:	call 0x00408b40
0x00408d73:	movl %edx, $0xff<UINT32>
0x00408d78:	movw 0x8(%eax), %dx
0x00408d7c:	movl %ecx, $0x9f<UINT32>
0x00408d81:	movw 0xa(%eax), %cx
0x00408d85:	movl %edx, $0x32<UINT32>
0x00408d8a:	movw 0xc(%eax), %dx
0x00408d8e:	movl %edx, $0x2<UINT32>
0x00408d93:	movl %ecx, $0xe<UINT32>
0x00408d98:	movw 0xe(%eax), %cx
0x00408d9c:	movw 0x10(%eax), %dx
0x00408da0:	movl (%eax), $0x50010000<UINT32>
0x00408da6:	leal %edi, 0x12(%eax)
0x00408da9:	movl %eax, $0xffff<UINT32>
0x00408dae:	movw (%edi), %ax
0x00408db1:	addl %edi, %edx
0x00408db3:	movl %ecx, $0x80<UINT32>
0x00408db8:	movw (%edi), %cx
0x00408dbb:	addl %edi, %edx
0x00408dbd:	pushl %edi
0x00408dbe:	movl %ecx, $0x4375f4<UINT32>
0x00408dc3:	call 0x00408b50
0x00408dc8:	leal %eax, (%edi,%eax,2)
0x00408dcb:	xorl %edx, %edx
0x00408dcd:	movw (%eax), %dx
0x00408dd0:	addw 0x8(%esi), %bx
0x00408dd4:	addl %eax, $0x2<UINT8>
0x00408dd7:	call 0x00408b40
0x00408ddc:	movl %ecx, $0x7<UINT32>
0x00408de1:	movw 0x8(%eax), %cx
0x00408de5:	movl %edx, $0x9f<UINT32>
0x00408dea:	movw 0xa(%eax), %dx
0x00408dee:	movl %ecx, $0x32<UINT32>
0x00408df3:	movw 0xc(%eax), %cx
0x00408df7:	movl %edx, $0xe<UINT32>
0x00408dfc:	movw 0xe(%eax), %dx
0x00408e00:	leal %edi, 0x12(%eax)
0x00408e03:	movl %ecx, $0x1f5<UINT32>
0x00408e08:	movw 0x10(%eax), %cx
0x00408e0c:	movl (%eax), $0x50010000<UINT32>
0x00408e12:	movl %edx, $0xffff<UINT32>
0x00408e17:	movw (%edi), %dx
0x00408e1a:	addl %edi, $0x2<UINT8>
0x00408e1d:	movl %eax, $0x80<UINT32>
0x00408e22:	movw (%edi), %ax
0x00408e25:	addl %edi, $0x2<UINT8>
0x00408e28:	pushl %edi
0x00408e29:	movl %ecx, $0x4375e4<UINT32>
0x00408e2e:	call 0x00408b50
0x00408e33:	leal %eax, (%edi,%eax,2)
0x00408e36:	xorl %ecx, %ecx
0x00408e38:	movw (%eax), %cx
0x00408e3b:	addw 0x8(%esi), %bx
0x00408e3f:	addl %eax, $0x2<UINT8>
0x00408e42:	call 0x00408b40
0x00408e47:	movl %edx, $0x7<UINT32>
0x00408e4c:	movw 0x8(%eax), %dx
0x00408e50:	movl %ecx, $0xe<UINT32>
0x00408e55:	movw 0xa(%eax), %cx
0x00408e59:	movl %edx, $0x12a<UINT32>
0x00408e5e:	movl %ecx, $0x8c<UINT32>
0x00408e63:	movw 0xc(%eax), %dx
0x00408e67:	leal %edi, 0x12(%eax)
0x00408e6a:	movw 0xe(%eax), %cx
0x00408e6e:	movl %edx, $0x1f4<UINT32>
0x00408e73:	pushl %edi
0x00408e74:	movl %ecx, $0x4375d0<UINT32>
0x00408e79:	movw 0x10(%eax), %dx
0x00408e7d:	movl (%eax), $0x50a11844<UINT32>
0x00408e83:	call 0x00408b50
0x00408e88:	leal %edi, (%edi,%eax,2)
0x00408e8b:	pushl %edi
0x00408e8c:	movl %ecx, $0x4375f4<UINT32>
0x00408e91:	call 0x00408b50
0x00408e96:	addl %esp, $0x20<UINT8>
0x00408e99:	pushl %ebp
0x00408e9a:	xorl %ecx, %ecx
0x00408e9c:	pushl $0x4089e0<UINT32>
0x00408ea1:	pushl %ecx
0x00408ea2:	pushl %esi
0x00408ea3:	movw (%edi,%eax,2), %cx
0x00408ea7:	addw 0x8(%esi), %bx
0x00408eab:	pushl %ecx
0x00408eac:	call DialogBoxIndirectParamW@USER32.dll
DialogBoxIndirectParamW@USER32.dll: API Node	
0x00408eb2:	pushl %esi
0x00408eb3:	movl 0x230(%esp), %eax
0x00408eba:	call LocalFree@KERNEL32.DLL
LocalFree@KERNEL32.DLL: API Node	
0x00408ec0:	cmpl 0x22c(%esp), $0x0<UINT8>
0x00408ec8:	popl %edi
0x00408ec9:	popl %esi
0x00408eca:	popl %ebx
0x00408ecb:	je 30
