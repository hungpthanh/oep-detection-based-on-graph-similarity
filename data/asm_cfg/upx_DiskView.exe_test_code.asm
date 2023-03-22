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
0x00410462:	jne 18
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
0x00409f23:	je 10
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
