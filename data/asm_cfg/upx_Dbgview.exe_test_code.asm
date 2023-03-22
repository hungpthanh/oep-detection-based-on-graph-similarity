0x0048b6f0:	pusha
0x0048b6f1:	movl %esi, $0x463000<UINT32>
0x0048b6f6:	leal %edi, -401408(%esi)
0x0048b6fc:	pushl %edi
0x0048b6fd:	jmp 0x0048b70a
0x0048b70a:	movl %ebx, (%esi)
0x0048b70c:	subl %esi, $0xfffffffc<UINT8>
0x0048b70f:	adcl %ebx, %ebx
0x0048b711:	jb 0x0048b700
0x0048b700:	movb %al, (%esi)
0x0048b702:	incl %esi
0x0048b703:	movb (%edi), %al
0x0048b705:	incl %edi
0x0048b706:	addl %ebx, %ebx
0x0048b708:	jne 0x0048b711
0x0048b713:	movl %eax, $0x1<UINT32>
0x0048b718:	addl %ebx, %ebx
0x0048b71a:	jne 0x0048b723
0x0048b723:	adcl %eax, %eax
0x0048b725:	addl %ebx, %ebx
0x0048b727:	jae 0x0048b734
0x0048b729:	jne 0x0048b753
0x0048b753:	xorl %ecx, %ecx
0x0048b755:	subl %eax, $0x3<UINT8>
0x0048b758:	jb 0x0048b76b
0x0048b75a:	shll %eax, $0x8<UINT8>
0x0048b75d:	movb %al, (%esi)
0x0048b75f:	incl %esi
0x0048b760:	xorl %eax, $0xffffffff<UINT8>
0x0048b763:	je 0x0048b7da
0x0048b765:	sarl %eax
0x0048b767:	movl %ebp, %eax
0x0048b769:	jmp 0x0048b776
0x0048b776:	jb 0x0048b744
0x0048b744:	addl %ebx, %ebx
0x0048b746:	jne 0x0048b74f
0x0048b74f:	adcl %ecx, %ecx
0x0048b751:	jmp 0x0048b7a5
0x0048b7a5:	cmpl %ebp, $0xfffffb00<UINT32>
0x0048b7ab:	adcl %ecx, $0x2<UINT8>
0x0048b7ae:	leal %edx, (%edi,%ebp)
0x0048b7b1:	cmpl %ebp, $0xfffffffc<UINT8>
0x0048b7b4:	jbe 0x0048b7c4
0x0048b7c4:	movl %eax, (%edx)
0x0048b7c6:	addl %edx, $0x4<UINT8>
0x0048b7c9:	movl (%edi), %eax
0x0048b7cb:	addl %edi, $0x4<UINT8>
0x0048b7ce:	subl %ecx, $0x4<UINT8>
0x0048b7d1:	ja 0x0048b7c4
0x0048b7d3:	addl %edi, %ecx
0x0048b7d5:	jmp 0x0048b706
0x0048b7b6:	movb %al, (%edx)
0x0048b7b8:	incl %edx
0x0048b7b9:	movb (%edi), %al
0x0048b7bb:	incl %edi
0x0048b7bc:	decl %ecx
0x0048b7bd:	jne 0x0048b7b6
0x0048b7bf:	jmp 0x0048b706
0x0048b71c:	movl %ebx, (%esi)
0x0048b71e:	subl %esi, $0xfffffffc<UINT8>
0x0048b721:	adcl %ebx, %ebx
0x0048b778:	incl %ecx
0x0048b779:	addl %ebx, %ebx
0x0048b77b:	jne 0x0048b784
0x0048b784:	jb 0x0048b744
0x0048b76b:	addl %ebx, %ebx
0x0048b76d:	jne 0x0048b776
0x0048b748:	movl %ebx, (%esi)
0x0048b74a:	subl %esi, $0xfffffffc<UINT8>
0x0048b74d:	adcl %ebx, %ebx
0x0048b72b:	movl %ebx, (%esi)
0x0048b72d:	subl %esi, $0xfffffffc<UINT8>
0x0048b730:	adcl %ebx, %ebx
0x0048b732:	jb 0x0048b753
0x0048b786:	addl %ebx, %ebx
0x0048b788:	jne 0x0048b791
0x0048b791:	adcl %ecx, %ecx
0x0048b793:	addl %ebx, %ebx
0x0048b795:	jae 0x0048b786
0x0048b797:	jne 0x0048b7a2
0x0048b7a2:	addl %ecx, $0x2<UINT8>
0x0048b734:	decl %eax
0x0048b735:	addl %ebx, %ebx
0x0048b737:	jne 0x0048b740
0x0048b740:	adcl %eax, %eax
0x0048b742:	jmp 0x0048b718
0x0048b77d:	movl %ebx, (%esi)
0x0048b77f:	subl %esi, $0xfffffffc<UINT8>
0x0048b782:	adcl %ebx, %ebx
0x0048b78a:	movl %ebx, (%esi)
0x0048b78c:	subl %esi, $0xfffffffc<UINT8>
0x0048b78f:	adcl %ebx, %ebx
0x0048b76f:	movl %ebx, (%esi)
0x0048b771:	subl %esi, $0xfffffffc<UINT8>
0x0048b774:	adcl %ebx, %ebx
0x0048b799:	movl %ebx, (%esi)
0x0048b79b:	subl %esi, $0xfffffffc<UINT8>
0x0048b79e:	adcl %ebx, %ebx
0x0048b7a0:	jae 0x0048b786
0x0048b739:	movl %ebx, (%esi)
0x0048b73b:	subl %esi, $0xfffffffc<UINT8>
0x0048b73e:	adcl %ebx, %ebx
0x0048b7da:	popl %esi
0x0048b7db:	movl %edi, %esi
0x0048b7dd:	movl %ecx, $0xfa5<UINT32>
0x0048b7e2:	movb %al, (%edi)
0x0048b7e4:	incl %edi
0x0048b7e5:	subb %al, $0xffffffe8<UINT8>
0x0048b7e7:	cmpb %al, $0x1<UINT8>
0x0048b7e9:	ja 0x0048b7e2
0x0048b7eb:	cmpb (%edi), $0x11<UINT8>
0x0048b7ee:	jne 0x0048b7e2
0x0048b7f0:	movl %eax, (%edi)
0x0048b7f2:	movb %bl, 0x4(%edi)
0x0048b7f5:	shrw %ax, $0x8<UINT8>
0x0048b7f9:	roll %eax, $0x10<UINT8>
0x0048b7fc:	xchgb %ah, %al
0x0048b7fe:	subl %eax, %edi
0x0048b800:	subb %bl, $0xffffffe8<UINT8>
0x0048b803:	addl %eax, %esi
0x0048b805:	movl (%edi), %eax
0x0048b807:	addl %edi, $0x5<UINT8>
0x0048b80a:	movb %al, %bl
0x0048b80c:	loop 0x0048b7e7
0x0048b80e:	leal %edi, 0x88000(%esi)
0x0048b814:	movl %eax, (%edi)
0x0048b816:	orl %eax, %eax
0x0048b818:	je 0x0048b85f
0x0048b81a:	movl %ebx, 0x4(%edi)
0x0048b81d:	leal %eax, 0x8c584(%eax,%esi)
0x0048b824:	addl %ebx, %esi
0x0048b826:	pushl %eax
0x0048b827:	addl %edi, $0x8<UINT8>
0x0048b82a:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x0048b830:	xchgl %ebp, %eax
0x0048b831:	movb %al, (%edi)
0x0048b833:	incl %edi
0x0048b834:	orb %al, %al
0x0048b836:	je 0x0048b814
0x0048b838:	movl %ecx, %edi
0x0048b83a:	jns 0x0048b843
0x0048b843:	pushl %edi
0x0048b844:	decl %eax
0x0048b845:	repn scasb %al, %es:(%edi)
0x0048b847:	pushl %ebp
0x0048b848:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0048b84e:	orl %eax, %eax
0x0048b850:	je 7
0x0048b852:	movl (%ebx), %eax
0x0048b854:	addl %ebx, $0x4<UINT8>
0x0048b857:	jmp 0x0048b831
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x0048b83c:	movzwl %eax, (%edi)
0x0048b83f:	incl %edi
0x0048b840:	pushl %eax
0x0048b841:	incl %edi
0x0048b842:	movl %ecx, $0xaef24857<UINT32>
0x0048b85f:	movl %ebp, 0x8c678(%esi)
0x0048b865:	leal %edi, -4096(%esi)
0x0048b86b:	movl %ebx, $0x1000<UINT32>
0x0048b870:	pushl %eax
0x0048b871:	pushl %esp
0x0048b872:	pushl $0x4<UINT8>
0x0048b874:	pushl %ebx
0x0048b875:	pushl %edi
0x0048b876:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0048b878:	leal %eax, 0x1ff(%edi)
0x0048b87e:	andb (%eax), $0x7f<UINT8>
0x0048b881:	andb 0x28(%eax), $0x7f<UINT8>
0x0048b885:	popl %eax
0x0048b886:	pushl %eax
0x0048b887:	pushl %esp
0x0048b888:	pushl %eax
0x0048b889:	pushl %ebx
0x0048b88a:	pushl %edi
0x0048b88b:	call VirtualProtect@kernel32.dll
0x0048b88d:	popl %eax
0x0048b88e:	popa
0x0048b88f:	leal %eax, -128(%esp)
0x0048b893:	pushl $0x0<UINT8>
0x0048b895:	cmpl %esp, %eax
0x0048b897:	jne 0x0048b893
0x0048b899:	subl %esp, $0xffffff80<UINT8>
0x0048b89c:	jmp 0x00415757
0x00415757:	call 0x00421820
0x00421820:	movl %edi, %edi
0x00421822:	pushl %ebp
0x00421823:	movl %ebp, %esp
0x00421825:	subl %esp, $0x10<UINT8>
0x00421828:	movl %eax, 0x43d68c
0x0042182d:	andl -8(%ebp), $0x0<UINT8>
0x00421831:	andl -4(%ebp), $0x0<UINT8>
0x00421835:	pushl %ebx
0x00421836:	pushl %edi
0x00421837:	movl %edi, $0xbb40e64e<UINT32>
0x0042183c:	movl %ebx, $0xffff0000<UINT32>
0x00421841:	cmpl %eax, %edi
0x00421843:	je 0x00421852
0x00421852:	pushl %esi
0x00421853:	leal %eax, -8(%ebp)
0x00421856:	pushl %eax
0x00421857:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0042185d:	movl %esi, -4(%ebp)
0x00421860:	xorl %esi, -8(%ebp)
0x00421863:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x00421869:	xorl %esi, %eax
0x0042186b:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x00421871:	xorl %esi, %eax
0x00421873:	call GetTickCount@KERNEL32.DLL
GetTickCount@KERNEL32.DLL: API Node	
0x00421879:	xorl %esi, %eax
0x0042187b:	leal %eax, -16(%ebp)
0x0042187e:	pushl %eax
0x0042187f:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x00421885:	movl %eax, -12(%ebp)
0x00421888:	xorl %eax, -16(%ebp)
0x0042188b:	xorl %esi, %eax
0x0042188d:	cmpl %esi, %edi
0x0042188f:	jne 0x00421898
0x00421898:	testl %ebx, %esi
0x0042189a:	jne 0x004218a3
0x004218a3:	movl 0x43d68c, %esi
0x004218a9:	notl %esi
0x004218ab:	movl 0x43d690, %esi
0x004218b1:	popl %esi
0x004218b2:	popl %edi
0x004218b3:	popl %ebx
0x004218b4:	leave
0x004218b5:	ret

0x0041575c:	jmp 0x004155d9
0x004155d9:	pushl $0x58<UINT8>
0x004155db:	pushl $0x43ac58<UINT32>
0x004155e0:	call 0x0041a9a0
0x0041a9a0:	pushl $0x412720<UINT32>
0x0041a9a5:	pushl %fs:0
0x0041a9ac:	movl %eax, 0x10(%esp)
0x0041a9b0:	movl 0x10(%esp), %ebp
0x0041a9b4:	leal %ebp, 0x10(%esp)
0x0041a9b8:	subl %esp, %eax
0x0041a9ba:	pushl %ebx
0x0041a9bb:	pushl %esi
0x0041a9bc:	pushl %edi
0x0041a9bd:	movl %eax, 0x43d68c
0x0041a9c2:	xorl -4(%ebp), %eax
0x0041a9c5:	xorl %eax, %ebp
0x0041a9c7:	pushl %eax
0x0041a9c8:	movl -24(%ebp), %esp
0x0041a9cb:	pushl -8(%ebp)
0x0041a9ce:	movl %eax, -4(%ebp)
0x0041a9d1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0041a9d8:	movl -8(%ebp), %eax
0x0041a9db:	leal %eax, -16(%ebp)
0x0041a9de:	movl %fs:0, %eax
0x0041a9e4:	ret

0x004155e5:	xorl %esi, %esi
0x004155e7:	movl -4(%ebp), %esi
0x004155ea:	leal %eax, -104(%ebp)
0x004155ed:	pushl %eax
0x004155ee:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x004155f4:	pushl $0xfffffffe<UINT8>
0x004155f6:	popl %edi
0x004155f7:	movl -4(%ebp), %edi
0x004155fa:	movl %eax, $0x5a4d<UINT32>
0x004155ff:	cmpw 0x400000, %ax
0x00415606:	jne 56
0x00415608:	movl %eax, 0x40003c
0x0041560d:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00415617:	jne 39
0x00415619:	movl %ecx, $0x10b<UINT32>
0x0041561e:	cmpw 0x400018(%eax), %cx
0x00415625:	jne 25
0x00415627:	cmpl 0x400074(%eax), $0xe<UINT8>
0x0041562e:	jbe 16
0x00415630:	xorl %ecx, %ecx
0x00415632:	cmpl 0x4000e8(%eax), %esi
0x00415638:	setne %cl
0x0041563b:	movl -28(%ebp), %ecx
0x0041563e:	jmp 0x00415643
0x00415643:	xorl %ebx, %ebx
0x00415645:	incl %ebx
0x00415646:	pushl %ebx
0x00415647:	call 0x00419710
0x00419710:	movl %edi, %edi
0x00419712:	pushl %ebp
0x00419713:	movl %ebp, %esp
0x00419715:	xorl %eax, %eax
0x00419717:	cmpl 0x8(%ebp), %eax
0x0041971a:	pushl $0x0<UINT8>
0x0041971c:	sete %al
0x0041971f:	pushl $0x1000<UINT32>
0x00419724:	pushl %eax
0x00419725:	call HeapCreate@KERNEL32.DLL
HeapCreate@KERNEL32.DLL: API Node	
0x0041972b:	movl 0x447990, %eax
0x00419730:	testl %eax, %eax
0x00419732:	jne 0x00419736
0x00419736:	xorl %eax, %eax
0x00419738:	incl %eax
0x00419739:	movl 0x454894, %eax
0x0041973e:	popl %ebp
0x0041973f:	ret

0x0041564c:	popl %ecx
0x0041564d:	testl %eax, %eax
0x0041564f:	jne 0x00415659
0x00415659:	call 0x004190bd
0x004190bd:	movl %edi, %edi
0x004190bf:	pushl %esi
0x004190c0:	pushl %edi
0x004190c1:	movl %esi, $0x438fdc<UINT32>
0x004190c6:	pushl %esi
0x004190c7:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x004190cd:	testl %eax, %eax
0x004190cf:	jne 0x004190d8
0x004190d8:	movl %edi, %eax
0x004190da:	testl %edi, %edi
0x004190dc:	je 350
0x004190e2:	movl %esi, 0x4342d4
0x004190e8:	pushl $0x439028<UINT32>
0x004190ed:	pushl %edi
0x004190ee:	call GetProcAddress@KERNEL32.DLL
0x004190f0:	pushl $0x43901c<UINT32>
0x004190f5:	pushl %edi
0x004190f6:	movl 0x44797c, %eax
0x004190fb:	call GetProcAddress@KERNEL32.DLL
0x004190fd:	pushl $0x439010<UINT32>
0x00419102:	pushl %edi
0x00419103:	movl 0x447980, %eax
0x00419108:	call GetProcAddress@KERNEL32.DLL
0x0041910a:	pushl $0x439008<UINT32>
0x0041910f:	pushl %edi
0x00419110:	movl 0x447984, %eax
0x00419115:	call GetProcAddress@KERNEL32.DLL
0x00419117:	cmpl 0x44797c, $0x0<UINT8>
0x0041911e:	movl %esi, 0x434200
0x00419124:	movl 0x447988, %eax
0x00419129:	je 22
0x0041912b:	cmpl 0x447980, $0x0<UINT8>
0x00419132:	je 13
0x00419134:	cmpl 0x447984, $0x0<UINT8>
0x0041913b:	je 4
0x0041913d:	testl %eax, %eax
0x0041913f:	jne 0x00419165
0x00419165:	call TlsAlloc@KERNEL32.DLL
TlsAlloc@KERNEL32.DLL: API Node	
0x0041916b:	movl 0x43de4c, %eax
0x00419170:	cmpl %eax, $0xffffffff<UINT8>
0x00419173:	je 204
0x00419179:	pushl 0x447980
0x0041917f:	pushl %eax
0x00419180:	call TlsSetValue@KERNEL32.DLL
TlsSetValue@KERNEL32.DLL: API Node	
0x00419182:	testl %eax, %eax
0x00419184:	je 187
0x0041918a:	call 0x0041ad5b
0x0041ad5b:	movl %edi, %edi
0x0041ad5d:	pushl %esi
0x0041ad5e:	call 0x00418c68
0x00418c68:	pushl $0x0<UINT8>
0x00418c6a:	call 0x00418bf6
0x00418bf6:	movl %edi, %edi
0x00418bf8:	pushl %ebp
0x00418bf9:	movl %ebp, %esp
0x00418bfb:	pushl %esi
0x00418bfc:	pushl 0x43de4c
0x00418c02:	movl %esi, 0x434208
0x00418c08:	call TlsGetValue@KERNEL32.DLL
TlsGetValue@KERNEL32.DLL: API Node	
0x00418c0a:	testl %eax, %eax
0x00418c0c:	je 33
0x00418c0e:	movl %eax, 0x43de48
0x00418c13:	cmpl %eax, $0xffffffff<UINT8>
0x00418c16:	je 0x00418c2f
0x00418c2f:	movl %esi, $0x438fdc<UINT32>
0x00418c34:	pushl %esi
0x00418c35:	call GetModuleHandleW@KERNEL32.DLL
0x00418c3b:	testl %eax, %eax
0x00418c3d:	jne 0x00418c4a
0x00418c4a:	pushl $0x438fcc<UINT32>
0x00418c4f:	pushl %eax
0x00418c50:	call GetProcAddress@KERNEL32.DLL
0x00418c56:	testl %eax, %eax
0x00418c58:	je 8
0x00418c5a:	pushl 0x8(%ebp)
0x00418c5d:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00418c5f:	movl 0x8(%ebp), %eax
0x00418c62:	movl %eax, 0x8(%ebp)
0x00418c65:	popl %esi
0x00418c66:	popl %ebp
0x00418c67:	ret

0x00418c6f:	popl %ecx
0x00418c70:	ret

0x0041ad63:	movl %esi, %eax
0x0041ad65:	pushl %esi
0x0041ad66:	call 0x0041afb3
0x0041afb3:	movl %edi, %edi
0x0041afb5:	pushl %ebp
0x0041afb6:	movl %ebp, %esp
0x0041afb8:	movl %eax, 0x8(%ebp)
0x0041afbb:	movl 0x447e34, %eax
0x0041afc0:	popl %ebp
0x0041afc1:	ret

0x0041ad6b:	pushl %esi
0x0041ad6c:	call 0x00429ccd
0x00429ccd:	movl %edi, %edi
0x00429ccf:	pushl %ebp
0x00429cd0:	movl %ebp, %esp
0x00429cd2:	movl %eax, 0x8(%ebp)
0x00429cd5:	movl 0x447f68, %eax
0x00429cda:	popl %ebp
0x00429cdb:	ret

0x0041ad71:	pushl %esi
0x0041ad72:	call 0x0041653d
0x0041653d:	movl %edi, %edi
0x0041653f:	pushl %ebp
0x00416540:	movl %ebp, %esp
0x00416542:	movl %eax, 0x8(%ebp)
0x00416545:	movl 0x447614, %eax
0x0041654a:	popl %ebp
0x0041654b:	ret

0x0041ad77:	pushl %esi
0x0041ad78:	call 0x0042aa0a
0x0042aa0a:	movl %edi, %edi
0x0042aa0c:	pushl %ebp
0x0042aa0d:	movl %ebp, %esp
0x0042aa0f:	movl %eax, 0x8(%ebp)
0x0042aa12:	movl 0x447f90, %eax
0x0042aa17:	popl %ebp
0x0042aa18:	ret

0x0041ad7d:	pushl %esi
0x0041ad7e:	call 0x0042a774
0x0042a774:	movl %edi, %edi
0x0042a776:	pushl %ebp
0x0042a777:	movl %ebp, %esp
0x0042a779:	movl %eax, 0x8(%ebp)
0x0042a77c:	movl 0x447f84, %eax
0x0042a781:	popl %ebp
0x0042a782:	ret

0x0041ad83:	pushl %esi
0x0041ad84:	call 0x0042a278
0x0042a278:	movl %edi, %edi
0x0042a27a:	pushl %ebp
0x0042a27b:	movl %ebp, %esp
0x0042a27d:	movl %eax, 0x8(%ebp)
0x0042a280:	movl 0x447f70, %eax
0x0042a285:	movl 0x447f74, %eax
0x0042a28a:	movl 0x447f78, %eax
0x0042a28f:	movl 0x447f7c, %eax
0x0042a294:	popl %ebp
0x0042a295:	ret

0x0041ad89:	pushl %esi
0x0041ad8a:	call 0x0041c01f
0x0041c01f:	ret

0x0041ad8f:	pushl %esi
0x0041ad90:	call 0x0042a267
0x0042a267:	pushl $0x42a1e3<UINT32>
0x0042a26c:	call 0x00418bf6
0x0042a271:	popl %ecx
0x0042a272:	movl 0x447f6c, %eax
0x0042a277:	ret

0x0041ad95:	pushl $0x41ad27<UINT32>
0x0041ad9a:	call 0x00418bf6
0x0041ad9f:	addl %esp, $0x24<UINT8>
0x0041ada2:	movl 0x43df78, %eax
0x0041ada7:	popl %esi
0x0041ada8:	ret

0x0041918f:	pushl 0x44797c
0x00419195:	call 0x00418bf6
0x0041919a:	pushl 0x447980
0x004191a0:	movl 0x44797c, %eax
0x004191a5:	call 0x00418bf6
0x004191aa:	pushl 0x447984
0x004191b0:	movl 0x447980, %eax
0x004191b5:	call 0x00418bf6
0x004191ba:	pushl 0x447988
0x004191c0:	movl 0x447984, %eax
0x004191c5:	call 0x00418bf6
0x004191ca:	addl %esp, $0x10<UINT8>
0x004191cd:	movl 0x447988, %eax
0x004191d2:	call 0x004197ba
0x004197ba:	movl %edi, %edi
0x004197bc:	pushl %esi
0x004197bd:	pushl %edi
0x004197be:	xorl %esi, %esi
0x004197c0:	movl %edi, $0x447998<UINT32>
0x004197c5:	cmpl 0x43de5c(,%esi,8), $0x1<UINT8>
0x004197cd:	jne 0x004197ed
0x004197cf:	leal %eax, 0x43de58(,%esi,8)
0x004197d6:	movl (%eax), %edi
0x004197d8:	pushl $0xfa0<UINT32>
0x004197dd:	pushl (%eax)
0x004197df:	addl %edi, $0x18<UINT8>
0x004197e2:	call 0x00429cdc
0x00429cdc:	pushl $0x10<UINT8>
0x00429cde:	pushl $0x43af98<UINT32>
0x00429ce3:	call 0x0041a9a0
0x00429ce8:	andl -4(%ebp), $0x0<UINT8>
0x00429cec:	pushl 0xc(%ebp)
0x00429cef:	pushl 0x8(%ebp)
0x00429cf2:	call InitializeCriticalSectionAndSpinCount@KERNEL32.DLL
InitializeCriticalSectionAndSpinCount@KERNEL32.DLL: API Node	
0x00429cf8:	movl -28(%ebp), %eax
0x00429cfb:	jmp 0x00429d2c
0x00429d2c:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00429d33:	movl %eax, -28(%ebp)
0x00429d36:	call 0x0041a9e5
0x0041a9e5:	movl %ecx, -16(%ebp)
0x0041a9e8:	movl %fs:0, %ecx
0x0041a9ef:	popl %ecx
0x0041a9f0:	popl %edi
0x0041a9f1:	popl %edi
0x0041a9f2:	popl %esi
0x0041a9f3:	popl %ebx
0x0041a9f4:	movl %esp, %ebp
0x0041a9f6:	popl %ebp
0x0041a9f7:	pushl %ecx
0x0041a9f8:	ret

0x00429d3b:	ret

0x004197e7:	popl %ecx
0x004197e8:	popl %ecx
0x004197e9:	testl %eax, %eax
0x004197eb:	je 12
0x004197ed:	incl %esi
0x004197ee:	cmpl %esi, $0x24<UINT8>
0x004197f1:	jl 0x004197c5
0x004197f3:	xorl %eax, %eax
0x004197f5:	incl %eax
0x004197f6:	popl %edi
0x004197f7:	popl %esi
0x004197f8:	ret

0x004191d7:	testl %eax, %eax
0x004191d9:	je 101
0x004191db:	pushl $0x418f14<UINT32>
0x004191e0:	pushl 0x44797c
0x004191e6:	call 0x00418c71
0x00418c71:	movl %edi, %edi
0x00418c73:	pushl %ebp
0x00418c74:	movl %ebp, %esp
0x00418c76:	pushl %esi
0x00418c77:	pushl 0x43de4c
0x00418c7d:	movl %esi, 0x434208
0x00418c83:	call TlsGetValue@KERNEL32.DLL
0x00418c85:	testl %eax, %eax
0x00418c87:	je 33
0x00418c89:	movl %eax, 0x43de48
0x00418c8e:	cmpl %eax, $0xffffffff<UINT8>
0x00418c91:	je 0x00418caa
0x00418caa:	movl %esi, $0x438fdc<UINT32>
0x00418caf:	pushl %esi
0x00418cb0:	call GetModuleHandleW@KERNEL32.DLL
0x00418cb6:	testl %eax, %eax
0x00418cb8:	jne 0x00418cc5
0x00418cc5:	pushl $0x438ff8<UINT32>
0x00418cca:	pushl %eax
0x00418ccb:	call GetProcAddress@KERNEL32.DLL
0x00418cd1:	testl %eax, %eax
0x00418cd3:	je 8
0x00418cd5:	pushl 0x8(%ebp)
0x00418cd8:	call DecodePointer@KERNEL32.DLL
DecodePointer@KERNEL32.DLL: API Node	
0x00418cda:	movl 0x8(%ebp), %eax
0x00418cdd:	movl %eax, 0x8(%ebp)
0x00418ce0:	popl %esi
0x00418ce1:	popl %ebp
0x00418ce2:	ret

0x004191eb:	popl %ecx
0x004191ec:	call FlsAlloc@KERNEL32.DLL
FlsAlloc@KERNEL32.DLL: API Node	
0x004191ee:	movl 0x43de48, %eax
0x004191f3:	cmpl %eax, $0xffffffff<UINT8>
0x004191f6:	je 72
0x004191f8:	pushl $0x214<UINT32>
0x004191fd:	pushl $0x1<UINT8>
0x004191ff:	call 0x0041c255
0x0041c255:	movl %edi, %edi
0x0041c257:	pushl %ebp
0x0041c258:	movl %ebp, %esp
0x0041c25a:	pushl %esi
0x0041c25b:	pushl %edi
0x0041c25c:	xorl %esi, %esi
0x0041c25e:	pushl $0x0<UINT8>
0x0041c260:	pushl 0xc(%ebp)
0x0041c263:	pushl 0x8(%ebp)
0x0041c266:	call 0x0042be32
0x0042be32:	pushl $0xc<UINT8>
0x0042be34:	pushl $0x43b140<UINT32>
0x0042be39:	call 0x0041a9a0
0x0042be3e:	movl %ecx, 0x8(%ebp)
0x0042be41:	xorl %edi, %edi
0x0042be43:	cmpl %ecx, %edi
0x0042be45:	jbe 46
0x0042be47:	pushl $0xffffffe0<UINT8>
0x0042be49:	popl %eax
0x0042be4a:	xorl %edx, %edx
0x0042be4c:	divl %eax, %ecx
0x0042be4e:	cmpl %eax, 0xc(%ebp)
0x0042be51:	sbbl %eax, %eax
0x0042be53:	incl %eax
0x0042be54:	jne 0x0042be75
0x0042be75:	imull %ecx, 0xc(%ebp)
0x0042be79:	movl %esi, %ecx
0x0042be7b:	movl 0x8(%ebp), %esi
0x0042be7e:	cmpl %esi, %edi
0x0042be80:	jne 0x0042be85
0x0042be85:	xorl %ebx, %ebx
0x0042be87:	movl -28(%ebp), %ebx
0x0042be8a:	cmpl %esi, $0xffffffe0<UINT8>
0x0042be8d:	ja 105
0x0042be8f:	cmpl 0x454894, $0x3<UINT8>
0x0042be96:	jne 0x0042bee3
0x0042bee3:	cmpl %ebx, %edi
0x0042bee5:	jne 97
0x0042bee7:	pushl %esi
0x0042bee8:	pushl $0x8<UINT8>
0x0042beea:	pushl 0x447990
0x0042bef0:	call HeapAlloc@KERNEL32.DLL
HeapAlloc@KERNEL32.DLL: API Node	
0x0042bef6:	movl %ebx, %eax
0x0042bef8:	cmpl %ebx, %edi
0x0042befa:	jne 0x0042bf48
0x0042bf48:	movl %eax, %ebx
0x0042bf4a:	call 0x0041a9e5
0x0042bf4f:	ret

0x0041c26b:	movl %edi, %eax
0x0041c26d:	addl %esp, $0xc<UINT8>
0x0041c270:	testl %edi, %edi
0x0041c272:	jne 0x0041c29b
0x0041c29b:	movl %eax, %edi
0x0041c29d:	popl %edi
0x0041c29e:	popl %esi
0x0041c29f:	popl %ebp
0x0041c2a0:	ret

0x00419204:	movl %esi, %eax
0x00419206:	popl %ecx
0x00419207:	popl %ecx
0x00419208:	testl %esi, %esi
0x0041920a:	je 52
0x0041920c:	pushl %esi
0x0041920d:	pushl 0x43de48
0x00419213:	pushl 0x447984
0x00419219:	call 0x00418c71
0x00418c93:	pushl %eax
0x00418c94:	pushl 0x43de4c
0x00418c9a:	call TlsGetValue@KERNEL32.DLL
0x00418c9c:	call FlsGetValue@KERNEL32.DLL
FlsGetValue@KERNEL32.DLL: API Node	
0x00418c9e:	testl %eax, %eax
0x00418ca0:	je 0x00418caa
0x0041921e:	popl %ecx
0x0041921f:	call FlsSetValue@KERNEL32.DLL
FlsSetValue@KERNEL32.DLL: API Node	
0x00419221:	testl %eax, %eax
0x00419223:	je 27
0x00419225:	pushl $0x0<UINT8>
0x00419227:	pushl %esi
0x00419228:	call 0x00418d9a
0x00418d9a:	pushl $0xc<UINT8>
0x00418d9c:	pushl $0x43ada8<UINT32>
0x00418da1:	call 0x0041a9a0
0x00418da6:	movl %esi, $0x438fdc<UINT32>
0x00418dab:	pushl %esi
0x00418dac:	call GetModuleHandleW@KERNEL32.DLL
0x00418db2:	testl %eax, %eax
0x00418db4:	jne 0x00418dbd
0x00418dbd:	movl -28(%ebp), %eax
0x00418dc0:	movl %esi, 0x8(%ebp)
0x00418dc3:	movl 0x5c(%esi), $0x439640<UINT32>
0x00418dca:	xorl %edi, %edi
0x00418dcc:	incl %edi
0x00418dcd:	movl 0x14(%esi), %edi
0x00418dd0:	testl %eax, %eax
0x00418dd2:	je 36
0x00418dd4:	pushl $0x438fcc<UINT32>
0x00418dd9:	pushl %eax
0x00418dda:	movl %ebx, 0x4342d4
0x00418de0:	call GetProcAddress@KERNEL32.DLL
0x00418de2:	movl 0x1f8(%esi), %eax
0x00418de8:	pushl $0x438ff8<UINT32>
0x00418ded:	pushl -28(%ebp)
0x00418df0:	call GetProcAddress@KERNEL32.DLL
0x00418df2:	movl 0x1fc(%esi), %eax
0x00418df8:	movl 0x70(%esi), %edi
0x00418dfb:	movb 0xc8(%esi), $0x43<UINT8>
0x00418e02:	movb 0x14b(%esi), $0x43<UINT8>
0x00418e09:	movl 0x68(%esi), $0x43d830<UINT32>
0x00418e10:	pushl $0xd<UINT8>
0x00418e12:	call 0x0041994e
0x0041994e:	movl %edi, %edi
0x00419950:	pushl %ebp
0x00419951:	movl %ebp, %esp
0x00419953:	movl %eax, 0x8(%ebp)
0x00419956:	pushl %esi
0x00419957:	leal %esi, 0x43de58(,%eax,8)
0x0041995e:	cmpl (%esi), $0x0<UINT8>
0x00419961:	jne 0x00419976
0x00419976:	pushl (%esi)
0x00419978:	call EnterCriticalSection@KERNEL32.DLL
EnterCriticalSection@KERNEL32.DLL: API Node	
0x0041997e:	popl %esi
0x0041997f:	popl %ebp
0x00419980:	ret

0x00418e17:	popl %ecx
0x00418e18:	andl -4(%ebp), $0x0<UINT8>
0x00418e1c:	pushl 0x68(%esi)
0x00418e1f:	call InterlockedIncrement@KERNEL32.DLL
InterlockedIncrement@KERNEL32.DLL: API Node	
0x00418e25:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00418e2c:	call 0x00418e6f
0x00418e6f:	pushl $0xd<UINT8>
0x00418e71:	call 0x0041985c
0x0041985c:	movl %edi, %edi
0x0041985e:	pushl %ebp
0x0041985f:	movl %ebp, %esp
0x00419861:	movl %eax, 0x8(%ebp)
0x00419864:	pushl 0x43de58(,%eax,8)
0x0041986b:	call LeaveCriticalSection@KERNEL32.DLL
LeaveCriticalSection@KERNEL32.DLL: API Node	
0x00419871:	popl %ebp
0x00419872:	ret

0x00418e76:	popl %ecx
0x00418e77:	ret

0x00418e31:	pushl $0xc<UINT8>
0x00418e33:	call 0x0041994e
0x00418e38:	popl %ecx
0x00418e39:	movl -4(%ebp), %edi
0x00418e3c:	movl %eax, 0xc(%ebp)
0x00418e3f:	movl 0x6c(%esi), %eax
0x00418e42:	testl %eax, %eax
0x00418e44:	jne 8
0x00418e46:	movl %eax, 0x43de38
0x00418e4b:	movl 0x6c(%esi), %eax
0x00418e4e:	pushl 0x6c(%esi)
0x00418e51:	call 0x00417a88
0x00417a88:	movl %edi, %edi
0x00417a8a:	pushl %ebp
0x00417a8b:	movl %ebp, %esp
0x00417a8d:	pushl %ebx
0x00417a8e:	pushl %esi
0x00417a8f:	movl %esi, 0x4342b4
0x00417a95:	pushl %edi
0x00417a96:	movl %edi, 0x8(%ebp)
0x00417a99:	pushl %edi
0x00417a9a:	call InterlockedIncrement@KERNEL32.DLL
0x00417a9c:	movl %eax, 0xb0(%edi)
0x00417aa2:	testl %eax, %eax
0x00417aa4:	je 0x00417aa9
0x00417aa9:	movl %eax, 0xb8(%edi)
0x00417aaf:	testl %eax, %eax
0x00417ab1:	je 0x00417ab6
0x00417ab6:	movl %eax, 0xb4(%edi)
0x00417abc:	testl %eax, %eax
0x00417abe:	je 0x00417ac3
0x00417ac3:	movl %eax, 0xc0(%edi)
0x00417ac9:	testl %eax, %eax
0x00417acb:	je 0x00417ad0
0x00417ad0:	leal %ebx, 0x50(%edi)
0x00417ad3:	movl 0x8(%ebp), $0x6<UINT32>
0x00417ada:	cmpl -8(%ebx), $0x43dd58<UINT32>
0x00417ae1:	je 0x00417aec
0x00417ae3:	movl %eax, (%ebx)
0x00417ae5:	testl %eax, %eax
0x00417ae7:	je 0x00417aec
0x00417aec:	cmpl -4(%ebx), $0x0<UINT8>
0x00417af0:	je 0x00417afc
0x00417afc:	addl %ebx, $0x10<UINT8>
0x00417aff:	decl 0x8(%ebp)
0x00417b02:	jne 0x00417ada
0x00417b04:	movl %eax, 0xd4(%edi)
0x00417b0a:	addl %eax, $0xb4<UINT32>
0x00417b0f:	pushl %eax
0x00417b10:	call InterlockedIncrement@KERNEL32.DLL
0x00417b12:	popl %edi
0x00417b13:	popl %esi
0x00417b14:	popl %ebx
0x00417b15:	popl %ebp
0x00417b16:	ret

0x00418e56:	popl %ecx
0x00418e57:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00418e5e:	call 0x00418e78
0x00418e78:	pushl $0xc<UINT8>
0x00418e7a:	call 0x0041985c
0x00418e7f:	popl %ecx
0x00418e80:	ret

0x00418e63:	call 0x0041a9e5
0x00418e68:	ret

0x0041922d:	popl %ecx
0x0041922e:	popl %ecx
0x0041922f:	call GetCurrentThreadId@KERNEL32.DLL
0x00419235:	orl 0x4(%esi), $0xffffffff<UINT8>
0x00419239:	movl (%esi), %eax
0x0041923b:	xorl %eax, %eax
0x0041923d:	incl %eax
0x0041923e:	jmp 0x00419247
0x00419247:	popl %edi
0x00419248:	popl %esi
0x00419249:	ret

0x0041565e:	testl %eax, %eax
0x00415660:	jne 0x0041566a
0x0041566a:	call 0x004217d4
0x004217d4:	movl %edi, %edi
0x004217d6:	pushl %esi
0x004217d7:	movl %eax, $0x43aa40<UINT32>
0x004217dc:	movl %esi, $0x43aa40<UINT32>
0x004217e1:	pushl %edi
0x004217e2:	movl %edi, %eax
0x004217e4:	cmpl %eax, %esi
0x004217e6:	jae 0x004217f7
0x004217f7:	popl %edi
0x004217f8:	popl %esi
0x004217f9:	ret

0x0041566f:	movl -4(%ebp), %ebx
0x00415672:	call 0x0041e4ee
0x0041e4ee:	pushl $0x54<UINT8>
0x0041e4f0:	pushl $0x43aeb8<UINT32>
0x0041e4f5:	call 0x0041a9a0
0x0041e4fa:	xorl %edi, %edi
0x0041e4fc:	movl -4(%ebp), %edi
0x0041e4ff:	leal %eax, -100(%ebp)
0x0041e502:	pushl %eax
0x0041e503:	call GetStartupInfoA@KERNEL32.DLL
0x0041e509:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0041e510:	pushl $0x40<UINT8>
0x0041e512:	pushl $0x20<UINT8>
0x0041e514:	popl %esi
0x0041e515:	pushl %esi
0x0041e516:	call 0x0041c255
0x0041e51b:	popl %ecx
0x0041e51c:	popl %ecx
0x0041e51d:	cmpl %eax, %edi
0x0041e51f:	je 532
0x0041e525:	movl 0x453740, %eax
0x0041e52a:	movl 0x45372c, %esi
0x0041e530:	leal %ecx, 0x800(%eax)
0x0041e536:	jmp 0x0041e568
0x0041e568:	cmpl %eax, %ecx
0x0041e56a:	jb 0x0041e538
0x0041e538:	movb 0x4(%eax), $0x0<UINT8>
0x0041e53c:	orl (%eax), $0xffffffff<UINT8>
0x0041e53f:	movb 0x5(%eax), $0xa<UINT8>
0x0041e543:	movl 0x8(%eax), %edi
0x0041e546:	movb 0x24(%eax), $0x0<UINT8>
0x0041e54a:	movb 0x25(%eax), $0xa<UINT8>
0x0041e54e:	movb 0x26(%eax), $0xa<UINT8>
0x0041e552:	movl 0x38(%eax), %edi
0x0041e555:	movb 0x34(%eax), $0x0<UINT8>
0x0041e559:	addl %eax, $0x40<UINT8>
0x0041e55c:	movl %ecx, 0x453740
0x0041e562:	addl %ecx, $0x800<UINT32>
0x0041e56c:	cmpw -50(%ebp), %di
0x0041e570:	je 266
0x0041e576:	movl %eax, -48(%ebp)
0x0041e579:	cmpl %eax, %edi
0x0041e57b:	je 255
0x0041e581:	movl %edi, (%eax)
0x0041e583:	leal %ebx, 0x4(%eax)
0x0041e586:	leal %eax, (%ebx,%edi)
0x0041e589:	movl -28(%ebp), %eax
0x0041e58c:	movl %esi, $0x800<UINT32>
0x0041e591:	cmpl %edi, %esi
0x0041e593:	jl 0x0041e597
0x0041e597:	movl -32(%ebp), $0x1<UINT32>
0x0041e59e:	jmp 0x0041e5fb
0x0041e5fb:	cmpl 0x45372c, %edi
0x0041e601:	jl -99
0x0041e603:	jmp 0x0041e60b
0x0041e60b:	andl -32(%ebp), $0x0<UINT8>
0x0041e60f:	testl %edi, %edi
0x0041e611:	jle 0x0041e680
0x0041e680:	xorl %ebx, %ebx
0x0041e682:	movl %esi, %ebx
0x0041e684:	shll %esi, $0x6<UINT8>
0x0041e687:	addl %esi, 0x453740
0x0041e68d:	movl %eax, (%esi)
0x0041e68f:	cmpl %eax, $0xffffffff<UINT8>
0x0041e692:	je 0x0041e69f
0x0041e69f:	movb 0x4(%esi), $0xffffff81<UINT8>
0x0041e6a3:	testl %ebx, %ebx
0x0041e6a5:	jne 0x0041e6ac
0x0041e6a7:	pushl $0xfffffff6<UINT8>
0x0041e6a9:	popl %eax
0x0041e6aa:	jmp 0x0041e6b6
0x0041e6b6:	pushl %eax
0x0041e6b7:	call GetStdHandle@KERNEL32.DLL
GetStdHandle@KERNEL32.DLL: API Node	
0x0041e6bd:	movl %edi, %eax
0x0041e6bf:	cmpl %edi, $0xffffffff<UINT8>
0x0041e6c2:	je 67
0x0041e6c4:	testl %edi, %edi
0x0041e6c6:	je 63
0x0041e6c8:	pushl %edi
0x0041e6c9:	call GetFileType@KERNEL32.DLL
GetFileType@KERNEL32.DLL: API Node	
0x0041e6cf:	testl %eax, %eax
0x0041e6d1:	je 52
0x0041e6d3:	movl (%esi), %edi
0x0041e6d5:	andl %eax, $0xff<UINT32>
0x0041e6da:	cmpl %eax, $0x2<UINT8>
0x0041e6dd:	jne 6
0x0041e6df:	orb 0x4(%esi), $0x40<UINT8>
0x0041e6e3:	jmp 0x0041e6ee
0x0041e6ee:	pushl $0xfa0<UINT32>
0x0041e6f3:	leal %eax, 0xc(%esi)
0x0041e6f6:	pushl %eax
0x0041e6f7:	call 0x00429cdc
0x0041e6fc:	popl %ecx
0x0041e6fd:	popl %ecx
0x0041e6fe:	testl %eax, %eax
0x0041e700:	je 55
0x0041e702:	incl 0x8(%esi)
0x0041e705:	jmp 0x0041e711
0x0041e711:	incl %ebx
0x0041e712:	cmpl %ebx, $0x3<UINT8>
0x0041e715:	jl 0x0041e682
0x0041e6ac:	movl %eax, %ebx
0x0041e6ae:	decl %eax
0x0041e6af:	negl %eax
0x0041e6b1:	sbbl %eax, %eax
0x0041e6b3:	addl %eax, $0xfffffff5<UINT8>
0x0041e71b:	pushl 0x45372c
0x0041e721:	call SetHandleCount@KERNEL32.DLL
SetHandleCount@KERNEL32.DLL: API Node	
0x0041e727:	xorl %eax, %eax
0x0041e729:	jmp 0x0041e73c
0x0041e73c:	call 0x0041a9e5
0x0041e741:	ret

0x00415677:	testl %eax, %eax
0x00415679:	jnl 0x00415683
0x00415683:	call GetCommandLineA@KERNEL32.DLL
GetCommandLineA@KERNEL32.DLL: API Node	
0x00415689:	movl 0x4548a4, %eax
0x0041568e:	call 0x0042169d
0x0042169d:	movl %edi, %edi
0x0042169f:	pushl %ebp
0x004216a0:	movl %ebp, %esp
0x004216a2:	movl %eax, 0x447f58
0x004216a7:	subl %esp, $0xc<UINT8>
0x004216aa:	pushl %ebx
0x004216ab:	pushl %esi
0x004216ac:	movl %esi, 0x43419c
0x004216b2:	pushl %edi
0x004216b3:	xorl %ebx, %ebx
0x004216b5:	xorl %edi, %edi
0x004216b7:	cmpl %eax, %ebx
0x004216b9:	jne 46
0x004216bb:	call GetEnvironmentStringsW@KERNEL32.DLL
GetEnvironmentStringsW@KERNEL32.DLL: API Node	
0x004216bd:	movl %edi, %eax
0x004216bf:	cmpl %edi, %ebx
0x004216c1:	je 12
0x004216c3:	movl 0x447f58, $0x1<UINT32>
0x004216cd:	jmp 0x004216f2
0x004216f2:	cmpl %edi, %ebx
0x004216f4:	jne 0x00421705
0x00421705:	movl %eax, %edi
0x00421707:	cmpw (%edi), %bx
0x0042170a:	je 14
0x0042170c:	incl %eax
0x0042170d:	incl %eax
0x0042170e:	cmpw (%eax), %bx
0x00421711:	jne 0x0042170c
0x00421713:	incl %eax
0x00421714:	incl %eax
0x00421715:	cmpw (%eax), %bx
0x00421718:	jne 0x0042170c
0x0042171a:	movl %esi, 0x4341f0
0x00421720:	pushl %ebx
0x00421721:	pushl %ebx
0x00421722:	pushl %ebx
0x00421723:	subl %eax, %edi
0x00421725:	pushl %ebx
0x00421726:	sarl %eax
0x00421728:	incl %eax
0x00421729:	pushl %eax
0x0042172a:	pushl %edi
0x0042172b:	pushl %ebx
0x0042172c:	pushl %ebx
0x0042172d:	movl -12(%ebp), %eax
0x00421730:	call WideCharToMultiByte@KERNEL32.DLL
WideCharToMultiByte@KERNEL32.DLL: API Node	
0x00421732:	movl -8(%ebp), %eax
0x00421735:	cmpl %eax, %ebx
0x00421737:	je 47
0x00421739:	pushl %eax
0x0042173a:	call 0x0041c210
0x0041c210:	movl %edi, %edi
0x0041c212:	pushl %ebp
0x0041c213:	movl %ebp, %esp
0x0041c215:	pushl %esi
0x0041c216:	pushl %edi
0x0041c217:	xorl %esi, %esi
0x0041c219:	pushl 0x8(%ebp)
0x0041c21c:	call 0x00412dc9
0x00412dc9:	movl %edi, %edi
0x00412dcb:	pushl %ebp
0x00412dcc:	movl %ebp, %esp
0x00412dce:	pushl %esi
0x00412dcf:	movl %esi, 0x8(%ebp)
0x00412dd2:	cmpl %esi, $0xffffffe0<UINT8>
0x00412dd5:	ja 161
0x00412ddb:	pushl %ebx
0x00412ddc:	pushl %edi
0x00412ddd:	movl %edi, 0x434164
0x00412de3:	cmpl 0x447990, $0x0<UINT8>
0x00412dea:	jne 0x00412e04
0x00412e04:	movl %eax, 0x454894
0x00412e09:	cmpl %eax, $0x1<UINT8>
0x00412e0c:	jne 14
0x00412e0e:	testl %esi, %esi
0x00412e10:	je 4
0x00412e12:	movl %eax, %esi
0x00412e14:	jmp 0x00412e19
0x00412e19:	pushl %eax
0x00412e1a:	jmp 0x00412e38
0x00412e38:	pushl $0x0<UINT8>
0x00412e3a:	pushl 0x447990
0x00412e40:	call HeapAlloc@KERNEL32.DLL
0x00412e42:	movl %ebx, %eax
0x00412e44:	testl %ebx, %ebx
0x00412e46:	jne 0x00412e76
0x00412e76:	popl %edi
0x00412e77:	movl %eax, %ebx
0x00412e79:	popl %ebx
0x00412e7a:	jmp 0x00412e90
0x00412e90:	popl %esi
0x00412e91:	popl %ebp
0x00412e92:	ret

0x0041c221:	movl %edi, %eax
0x0041c223:	popl %ecx
0x0041c224:	testl %edi, %edi
0x0041c226:	jne 0x0041c24f
0x0041c24f:	movl %eax, %edi
0x0041c251:	popl %edi
0x0041c252:	popl %esi
0x0041c253:	popl %ebp
0x0041c254:	ret

0x0042173f:	popl %ecx
0x00421740:	movl -4(%ebp), %eax
0x00421743:	cmpl %eax, %ebx
0x00421745:	je 33
0x00421747:	pushl %ebx
0x00421748:	pushl %ebx
0x00421749:	pushl -8(%ebp)
0x0042174c:	pushl %eax
0x0042174d:	pushl -12(%ebp)
0x00421750:	pushl %edi
0x00421751:	pushl %ebx
0x00421752:	pushl %ebx
0x00421753:	call WideCharToMultiByte@KERNEL32.DLL
0x00421755:	testl %eax, %eax
0x00421757:	jne 0x00421765
0x00421765:	movl %ebx, -4(%ebp)
0x00421768:	pushl %edi
0x00421769:	call FreeEnvironmentStringsW@KERNEL32.DLL
FreeEnvironmentStringsW@KERNEL32.DLL: API Node	
0x0042176f:	movl %eax, %ebx
0x00421771:	jmp 0x004217cf
0x004217cf:	popl %edi
0x004217d0:	popl %esi
0x004217d1:	popl %ebx
0x004217d2:	leave
0x004217d3:	ret

0x00415693:	movl 0x447608, %eax
0x00415698:	call 0x004215e2
0x004215e2:	movl %edi, %edi
0x004215e4:	pushl %ebp
0x004215e5:	movl %ebp, %esp
0x004215e7:	subl %esp, $0xc<UINT8>
0x004215ea:	pushl %ebx
0x004215eb:	xorl %ebx, %ebx
0x004215ed:	pushl %esi
0x004215ee:	pushl %edi
0x004215ef:	cmpl 0x454870, %ebx
0x004215f5:	jne 5
0x004215f7:	call 0x00417915
0x00417915:	cmpl 0x454870, $0x0<UINT8>
0x0041791c:	jne 18
0x0041791e:	pushl $0xfffffffd<UINT8>
0x00417920:	call 0x0041777b
0x0041777b:	pushl $0x14<UINT8>
0x0041777d:	pushl $0x43ace0<UINT32>
0x00417782:	call 0x0041a9a0
0x00417787:	orl -32(%ebp), $0xffffffff<UINT8>
0x0041778b:	call 0x00418efa
0x00418efa:	movl %edi, %edi
0x00418efc:	pushl %esi
0x00418efd:	call 0x00418e81
0x00418e81:	movl %edi, %edi
0x00418e83:	pushl %esi
0x00418e84:	pushl %edi
0x00418e85:	call GetLastError@KERNEL32.DLL
GetLastError@KERNEL32.DLL: API Node	
0x00418e8b:	pushl 0x43de48
0x00418e91:	movl %edi, %eax
0x00418e93:	call 0x00418d0c
0x00418d0c:	movl %edi, %edi
0x00418d0e:	pushl %esi
0x00418d0f:	pushl 0x43de4c
0x00418d15:	call TlsGetValue@KERNEL32.DLL
0x00418d1b:	movl %esi, %eax
0x00418d1d:	testl %esi, %esi
0x00418d1f:	jne 0x00418d3c
0x00418d3c:	movl %eax, %esi
0x00418d3e:	popl %esi
0x00418d3f:	ret

0x00418e98:	call FlsGetValue@KERNEL32.DLL
0x00418e9a:	movl %esi, %eax
0x00418e9c:	testl %esi, %esi
0x00418e9e:	jne 0x00418eee
0x00418eee:	pushl %edi
0x00418eef:	call SetLastError@KERNEL32.DLL
SetLastError@KERNEL32.DLL: API Node	
0x00418ef5:	popl %edi
0x00418ef6:	movl %eax, %esi
0x00418ef8:	popl %esi
0x00418ef9:	ret

0x00418f02:	movl %esi, %eax
0x00418f04:	testl %esi, %esi
0x00418f06:	jne 0x00418f10
0x00418f10:	movl %eax, %esi
0x00418f12:	popl %esi
0x00418f13:	ret

0x00417790:	movl %edi, %eax
0x00417792:	movl -36(%ebp), %edi
0x00417795:	call 0x00417438
0x00417438:	pushl $0xc<UINT8>
0x0041743a:	pushl $0x43acc0<UINT32>
0x0041743f:	call 0x0041a9a0
0x00417444:	call 0x00418efa
0x00417449:	movl %edi, %eax
0x0041744b:	movl %eax, 0x43dd54
0x00417450:	testl 0x70(%edi), %eax
0x00417453:	je 0x00417472
0x00417472:	pushl $0xd<UINT8>
0x00417474:	call 0x0041994e
0x00417479:	popl %ecx
0x0041747a:	andl -4(%ebp), $0x0<UINT8>
0x0041747e:	movl %esi, 0x68(%edi)
0x00417481:	movl -28(%ebp), %esi
0x00417484:	cmpl %esi, 0x43dc58
0x0041748a:	je 0x004174c2
0x004174c2:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004174c9:	call 0x004174d3
0x004174d3:	pushl $0xd<UINT8>
0x004174d5:	call 0x0041985c
0x004174da:	popl %ecx
0x004174db:	ret

0x004174ce:	jmp 0x0041745e
0x0041745e:	testl %esi, %esi
0x00417460:	jne 0x0041746a
0x0041746a:	movl %eax, %esi
0x0041746c:	call 0x0041a9e5
0x00417471:	ret

0x0041779a:	movl %ebx, 0x68(%edi)
0x0041779d:	movl %esi, 0x8(%ebp)
0x004177a0:	call 0x004174dc
0x004174dc:	movl %edi, %edi
0x004174de:	pushl %ebp
0x004174df:	movl %ebp, %esp
0x004174e1:	subl %esp, $0x10<UINT8>
0x004174e4:	pushl %ebx
0x004174e5:	xorl %ebx, %ebx
0x004174e7:	pushl %ebx
0x004174e8:	leal %ecx, -16(%ebp)
0x004174eb:	call 0x00412991
0x00412991:	movl %edi, %edi
0x00412993:	pushl %ebp
0x00412994:	movl %ebp, %esp
0x00412996:	movl %eax, 0x8(%ebp)
0x00412999:	pushl %esi
0x0041299a:	movl %esi, %ecx
0x0041299c:	movb 0xc(%esi), $0x0<UINT8>
0x004129a0:	testl %eax, %eax
0x004129a2:	jne 99
0x004129a4:	call 0x00418efa
0x004129a9:	movl 0x8(%esi), %eax
0x004129ac:	movl %ecx, 0x6c(%eax)
0x004129af:	movl (%esi), %ecx
0x004129b1:	movl %ecx, 0x68(%eax)
0x004129b4:	movl 0x4(%esi), %ecx
0x004129b7:	movl %ecx, (%esi)
0x004129b9:	cmpl %ecx, 0x43de38
0x004129bf:	je 0x004129d3
0x004129d3:	movl %eax, 0x4(%esi)
0x004129d6:	cmpl %eax, 0x43dc58
0x004129dc:	je 0x004129f4
0x004129f4:	movl %eax, 0x8(%esi)
0x004129f7:	testb 0x70(%eax), $0x2<UINT8>
0x004129fb:	jne 20
0x004129fd:	orl 0x70(%eax), $0x2<UINT8>
0x00412a01:	movb 0xc(%esi), $0x1<UINT8>
0x00412a05:	jmp 0x00412a11
0x00412a11:	movl %eax, %esi
0x00412a13:	popl %esi
0x00412a14:	popl %ebp
0x00412a15:	ret $0x4<UINT16>

0x004174f0:	movl 0x44793c, %ebx
0x004174f6:	cmpl %esi, $0xfffffffe<UINT8>
0x004174f9:	jne 0x00417519
0x00417519:	cmpl %esi, $0xfffffffd<UINT8>
0x0041751c:	jne 0x00417530
0x0041751e:	movl 0x44793c, $0x1<UINT32>
0x00417528:	call GetACP@KERNEL32.DLL
GetACP@KERNEL32.DLL: API Node	
0x0041752e:	jmp 0x0041750b
0x0041750b:	cmpb -4(%ebp), %bl
0x0041750e:	je 69
0x00417510:	movl %ecx, -8(%ebp)
0x00417513:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00417517:	jmp 0x00417555
0x00417555:	popl %ebx
0x00417556:	leave
0x00417557:	ret

0x004177a5:	movl 0x8(%ebp), %eax
0x004177a8:	cmpl %eax, 0x4(%ebx)
0x004177ab:	je 343
0x004177b1:	pushl $0x220<UINT32>
0x004177b6:	call 0x0041c210
0x004177bb:	popl %ecx
0x004177bc:	movl %ebx, %eax
0x004177be:	testl %ebx, %ebx
0x004177c0:	je 326
0x004177c6:	movl %ecx, $0x88<UINT32>
0x004177cb:	movl %esi, 0x68(%edi)
0x004177ce:	movl %edi, %ebx
0x004177d0:	rep movsl %es:(%edi), %ds:(%esi)
0x004177d2:	andl (%ebx), $0x0<UINT8>
0x004177d5:	pushl %ebx
0x004177d6:	pushl 0x8(%ebp)
0x004177d9:	call 0x00417558
0x00417558:	movl %edi, %edi
0x0041755a:	pushl %ebp
0x0041755b:	movl %ebp, %esp
0x0041755d:	subl %esp, $0x20<UINT8>
0x00417560:	movl %eax, 0x43d68c
0x00417565:	xorl %eax, %ebp
0x00417567:	movl -4(%ebp), %eax
0x0041756a:	pushl %ebx
0x0041756b:	movl %ebx, 0xc(%ebp)
0x0041756e:	pushl %esi
0x0041756f:	movl %esi, 0x8(%ebp)
0x00417572:	pushl %edi
0x00417573:	call 0x004174dc
0x00417530:	cmpl %esi, $0xfffffffc<UINT8>
0x00417533:	jne 0x00417547
0x00417547:	cmpb -4(%ebp), %bl
0x0041754a:	je 7
0x0041754c:	movl %eax, -8(%ebp)
0x0041754f:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x00417553:	movl %eax, %esi
0x00417578:	movl %edi, %eax
0x0041757a:	xorl %esi, %esi
0x0041757c:	movl 0x8(%ebp), %edi
0x0041757f:	cmpl %edi, %esi
0x00417581:	jne 0x00417591
0x00417591:	movl -28(%ebp), %esi
0x00417594:	xorl %eax, %eax
0x00417596:	cmpl 0x43dc60(%eax), %edi
0x0041759c:	je 145
0x004175a2:	incl -28(%ebp)
0x004175a5:	addl %eax, $0x30<UINT8>
0x004175a8:	cmpl %eax, $0xf0<UINT32>
0x004175ad:	jb 0x00417596
0x004175af:	cmpl %edi, $0xfde8<UINT32>
0x004175b5:	je 368
0x004175bb:	cmpl %edi, $0xfde9<UINT32>
0x004175c1:	je 356
0x004175c7:	movzwl %eax, %di
0x004175ca:	pushl %eax
0x004175cb:	call IsValidCodePage@KERNEL32.DLL
IsValidCodePage@KERNEL32.DLL: API Node	
0x004175d1:	testl %eax, %eax
0x004175d3:	je 338
0x004175d9:	leal %eax, -24(%ebp)
0x004175dc:	pushl %eax
0x004175dd:	pushl %edi
0x004175de:	call GetCPInfo@KERNEL32.DLL
GetCPInfo@KERNEL32.DLL: API Node	
0x004175e4:	testl %eax, %eax
0x004175e6:	je 307
0x004175ec:	pushl $0x101<UINT32>
0x004175f1:	leal %eax, 0x1c(%ebx)
0x004175f4:	pushl %esi
0x004175f5:	pushl %eax
0x004175f6:	call 0x004128b0
0x004128b0:	movl %edx, 0xc(%esp)
0x004128b4:	movl %ecx, 0x4(%esp)
0x004128b8:	testl %edx, %edx
0x004128ba:	je 105
0x004128bc:	xorl %eax, %eax
0x004128be:	movb %al, 0x8(%esp)
0x004128c2:	testb %al, %al
0x004128c4:	jne 22
0x004128c6:	cmpl %edx, $0x100<UINT32>
0x004128cc:	jb 14
0x004128ce:	cmpl 0x4548a0, $0x0<UINT8>
0x004128d5:	je 0x004128dc
0x004128dc:	pushl %edi
0x004128dd:	movl %edi, %ecx
0x004128df:	cmpl %edx, $0x4<UINT8>
0x004128e2:	jb 49
0x004128e4:	negl %ecx
0x004128e6:	andl %ecx, $0x3<UINT8>
0x004128e9:	je 0x004128f7
0x004128f7:	movl %ecx, %eax
0x004128f9:	shll %eax, $0x8<UINT8>
0x004128fc:	addl %eax, %ecx
0x004128fe:	movl %ecx, %eax
0x00412900:	shll %eax, $0x10<UINT8>
0x00412903:	addl %eax, %ecx
0x00412905:	movl %ecx, %edx
0x00412907:	andl %edx, $0x3<UINT8>
0x0041290a:	shrl %ecx, $0x2<UINT8>
0x0041290d:	je 6
0x0041290f:	rep stosl %es:(%edi), %eax
0x00412911:	testl %edx, %edx
0x00412913:	je 10
0x00412915:	movb (%edi), %al
0x00412917:	addl %edi, $0x1<UINT8>
0x0041291a:	subl %edx, $0x1<UINT8>
0x0041291d:	jne -10
0x0041291f:	movl %eax, 0x8(%esp)
0x00412923:	popl %edi
0x00412924:	ret

0x004175fb:	xorl %edx, %edx
0x004175fd:	incl %edx
0x004175fe:	addl %esp, $0xc<UINT8>
0x00417601:	movl 0x4(%ebx), %edi
0x00417604:	movl 0xc(%ebx), %esi
0x00417607:	cmpl -24(%ebp), %edx
0x0041760a:	jbe 248
0x00417610:	cmpb -18(%ebp), $0x0<UINT8>
0x00417614:	je 0x004176e9
0x004176e9:	leal %eax, 0x1e(%ebx)
0x004176ec:	movl %ecx, $0xfe<UINT32>
0x004176f1:	orb (%eax), $0x8<UINT8>
0x004176f4:	incl %eax
0x004176f5:	decl %ecx
0x004176f6:	jne 0x004176f1
0x004176f8:	movl %eax, 0x4(%ebx)
0x004176fb:	call 0x00417212
0x00417212:	subl %eax, $0x3a4<UINT32>
0x00417217:	je 34
0x00417219:	subl %eax, $0x4<UINT8>
0x0041721c:	je 23
0x0041721e:	subl %eax, $0xd<UINT8>
0x00417221:	je 12
0x00417223:	decl %eax
0x00417224:	je 3
0x00417226:	xorl %eax, %eax
0x00417228:	ret

0x00417700:	movl 0xc(%ebx), %eax
0x00417703:	movl 0x8(%ebx), %edx
0x00417706:	jmp 0x0041770b
0x0041770b:	xorl %eax, %eax
0x0041770d:	movzwl %ecx, %ax
0x00417710:	movl %eax, %ecx
0x00417712:	shll %ecx, $0x10<UINT8>
0x00417715:	orl %eax, %ecx
0x00417717:	leal %edi, 0x10(%ebx)
0x0041771a:	stosl %es:(%edi), %eax
0x0041771b:	stosl %es:(%edi), %eax
0x0041771c:	stosl %es:(%edi), %eax
0x0041771d:	jmp 0x004176c7
0x004176c7:	movl %esi, %ebx
0x004176c9:	call 0x004172a5
0x004172a5:	movl %edi, %edi
0x004172a7:	pushl %ebp
0x004172a8:	movl %ebp, %esp
0x004172aa:	subl %esp, $0x51c<UINT32>
0x004172b0:	movl %eax, 0x43d68c
0x004172b5:	xorl %eax, %ebp
0x004172b7:	movl -4(%ebp), %eax
0x004172ba:	pushl %ebx
0x004172bb:	pushl %edi
0x004172bc:	leal %eax, -1304(%ebp)
0x004172c2:	pushl %eax
0x004172c3:	pushl 0x4(%esi)
0x004172c6:	call GetCPInfo@KERNEL32.DLL
0x004172cc:	movl %edi, $0x100<UINT32>
0x004172d1:	testl %eax, %eax
0x004172d3:	je 251
0x004172d9:	xorl %eax, %eax
0x004172db:	movb -260(%ebp,%eax), %al
0x004172e2:	incl %eax
0x004172e3:	cmpl %eax, %edi
0x004172e5:	jb 0x004172db
0x004172e7:	movb %al, -1298(%ebp)
0x004172ed:	movb -260(%ebp), $0x20<UINT8>
0x004172f4:	testb %al, %al
0x004172f6:	je 0x00417326
0x00417326:	pushl $0x0<UINT8>
0x00417328:	pushl 0xc(%esi)
0x0041732b:	leal %eax, -1284(%ebp)
0x00417331:	pushl 0x4(%esi)
0x00417334:	pushl %eax
0x00417335:	pushl %edi
0x00417336:	leal %eax, -260(%ebp)
0x0041733c:	pushl %eax
0x0041733d:	pushl $0x1<UINT8>
0x0041733f:	pushl $0x0<UINT8>
0x00417341:	call 0x0042432d
0x0042432d:	movl %edi, %edi
0x0042432f:	pushl %ebp
0x00424330:	movl %ebp, %esp
0x00424332:	subl %esp, $0x10<UINT8>
0x00424335:	pushl 0x8(%ebp)
0x00424338:	leal %ecx, -16(%ebp)
0x0042433b:	call 0x00412991
0x00424340:	pushl 0x24(%ebp)
0x00424343:	leal %ecx, -16(%ebp)
0x00424346:	pushl 0x20(%ebp)
0x00424349:	pushl 0x1c(%ebp)
0x0042434c:	pushl 0x18(%ebp)
0x0042434f:	pushl 0x14(%ebp)
0x00424352:	pushl 0x10(%ebp)
0x00424355:	pushl 0xc(%ebp)
0x00424358:	call 0x00424173
0x00424173:	movl %edi, %edi
0x00424175:	pushl %ebp
0x00424176:	movl %ebp, %esp
0x00424178:	pushl %ecx
0x00424179:	pushl %ecx
0x0042417a:	movl %eax, 0x43d68c
0x0042417f:	xorl %eax, %ebp
0x00424181:	movl -4(%ebp), %eax
0x00424184:	movl %eax, 0x447f60
0x00424189:	pushl %ebx
0x0042418a:	pushl %esi
0x0042418b:	xorl %ebx, %ebx
0x0042418d:	pushl %edi
0x0042418e:	movl %edi, %ecx
0x00424190:	cmpl %eax, %ebx
0x00424192:	jne 58
0x00424194:	leal %eax, -8(%ebp)
0x00424197:	pushl %eax
0x00424198:	xorl %esi, %esi
0x0042419a:	incl %esi
0x0042419b:	pushl %esi
0x0042419c:	pushl $0x439034<UINT32>
0x004241a1:	pushl %esi
0x004241a2:	call GetStringTypeW@KERNEL32.DLL
GetStringTypeW@KERNEL32.DLL: API Node	
0x004241a8:	testl %eax, %eax
0x004241aa:	je 8
0x004241ac:	movl 0x447f60, %esi
0x004241b2:	jmp 0x004241e8
0x004241e8:	movl -8(%ebp), %ebx
0x004241eb:	cmpl 0x18(%ebp), %ebx
0x004241ee:	jne 0x004241f8
0x004241f8:	movl %esi, 0x4341ec
0x004241fe:	xorl %eax, %eax
0x00424200:	cmpl 0x20(%ebp), %ebx
0x00424203:	pushl %ebx
0x00424204:	pushl %ebx
0x00424205:	pushl 0x10(%ebp)
0x00424208:	setne %al
0x0042420b:	pushl 0xc(%ebp)
0x0042420e:	leal %eax, 0x1(,%eax,8)
0x00424215:	pushl %eax
0x00424216:	pushl 0x18(%ebp)
0x00424219:	call MultiByteToWideChar@KERNEL32.DLL
MultiByteToWideChar@KERNEL32.DLL: API Node	
0x0042421b:	movl %edi, %eax
0x0042421d:	cmpl %edi, %ebx
0x0042421f:	je 171
0x00424225:	jle 60
0x00424227:	cmpl %edi, $0x7ffffff0<UINT32>
0x0042422d:	ja 52
0x0042422f:	leal %eax, 0x8(%edi,%edi)
0x00424233:	cmpl %eax, $0x400<UINT32>
0x00424238:	ja 19
0x0042423a:	call 0x004196e0
0x004196e0:	pushl %ecx
0x004196e1:	leal %ecx, 0x8(%esp)
0x004196e5:	subl %ecx, %eax
0x004196e7:	andl %ecx, $0xf<UINT8>
0x004196ea:	addl %eax, %ecx
0x004196ec:	sbbl %ecx, %ecx
0x004196ee:	orl %eax, %ecx
0x004196f0:	popl %ecx
0x004196f1:	jmp 0x00412930
0x00412930:	pushl %ecx
0x00412931:	leal %ecx, 0x4(%esp)
0x00412935:	subl %ecx, %eax
0x00412937:	sbbl %eax, %eax
0x00412939:	notl %eax
0x0041293b:	andl %ecx, %eax
0x0041293d:	movl %eax, %esp
0x0041293f:	andl %eax, $0xfffff000<UINT32>
0x00412944:	cmpl %ecx, %eax
0x00412946:	jb 10
0x00412948:	movl %eax, %ecx
0x0041294a:	popl %ecx
0x0041294b:	xchgl %esp, %eax
0x0041294c:	movl %eax, (%eax)
0x0041294e:	movl (%esp), %eax
0x00412951:	ret

0x0042423f:	movl %eax, %esp
0x00424241:	cmpl %eax, %ebx
0x00424243:	je 28
0x00424245:	movl (%eax), $0xcccc<UINT32>
0x0042424b:	jmp 0x0042425e
0x0042425e:	addl %eax, $0x8<UINT8>
0x00424261:	movl %ebx, %eax
0x00424263:	testl %ebx, %ebx
0x00424265:	je 105
0x00424267:	leal %eax, (%edi,%edi)
0x0042426a:	pushl %eax
0x0042426b:	pushl $0x0<UINT8>
0x0042426d:	pushl %ebx
0x0042426e:	call 0x004128b0
