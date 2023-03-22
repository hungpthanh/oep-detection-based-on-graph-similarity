0x00429800:	pusha
0x00429801:	movl %esi, $0x41c000<UINT32>
0x00429806:	leal %edi, -110592(%esi)
0x0042980c:	pushl %edi
0x0042980d:	jmp 0x0042981a
0x0042981a:	movl %ebx, (%esi)
0x0042981c:	subl %esi, $0xfffffffc<UINT8>
0x0042981f:	adcl %ebx, %ebx
0x00429821:	jb 0x00429810
0x00429810:	movb %al, (%esi)
0x00429812:	incl %esi
0x00429813:	movb (%edi), %al
0x00429815:	incl %edi
0x00429816:	addl %ebx, %ebx
0x00429818:	jne 0x00429821
0x00429823:	movl %eax, $0x1<UINT32>
0x00429828:	addl %ebx, %ebx
0x0042982a:	jne 0x00429833
0x00429833:	adcl %eax, %eax
0x00429835:	addl %ebx, %ebx
0x00429837:	jae 0x00429828
0x00429839:	jne 0x00429844
0x00429844:	xorl %ecx, %ecx
0x00429846:	subl %eax, $0x3<UINT8>
0x00429849:	jb 0x00429858
0x0042984b:	shll %eax, $0x8<UINT8>
0x0042984e:	movb %al, (%esi)
0x00429850:	incl %esi
0x00429851:	xorl %eax, $0xffffffff<UINT8>
0x00429854:	je 0x004298ca
0x00429856:	movl %ebp, %eax
0x00429858:	addl %ebx, %ebx
0x0042985a:	jne 0x00429863
0x00429863:	adcl %ecx, %ecx
0x00429865:	addl %ebx, %ebx
0x00429867:	jne 0x00429870
0x00429870:	adcl %ecx, %ecx
0x00429872:	jne 0x00429894
0x00429894:	cmpl %ebp, $0xfffff300<UINT32>
0x0042989a:	adcl %ecx, $0x1<UINT8>
0x0042989d:	leal %edx, (%edi,%ebp)
0x004298a0:	cmpl %ebp, $0xfffffffc<UINT8>
0x004298a3:	jbe 0x004298b4
0x004298b4:	movl %eax, (%edx)
0x004298b6:	addl %edx, $0x4<UINT8>
0x004298b9:	movl (%edi), %eax
0x004298bb:	addl %edi, $0x4<UINT8>
0x004298be:	subl %ecx, $0x4<UINT8>
0x004298c1:	ja 0x004298b4
0x004298c3:	addl %edi, %ecx
0x004298c5:	jmp 0x00429816
0x004298a5:	movb %al, (%edx)
0x004298a7:	incl %edx
0x004298a8:	movb (%edi), %al
0x004298aa:	incl %edi
0x004298ab:	decl %ecx
0x004298ac:	jne 0x004298a5
0x004298ae:	jmp 0x00429816
0x00429874:	incl %ecx
0x00429875:	addl %ebx, %ebx
0x00429877:	jne 0x00429880
0x00429880:	adcl %ecx, %ecx
0x00429882:	addl %ebx, %ebx
0x00429884:	jae 0x00429875
0x00429886:	jne 0x00429891
0x00429891:	addl %ecx, $0x2<UINT8>
0x0042983b:	movl %ebx, (%esi)
0x0042983d:	subl %esi, $0xfffffffc<UINT8>
0x00429840:	adcl %ebx, %ebx
0x00429842:	jae 0x00429828
0x0042985c:	movl %ebx, (%esi)
0x0042985e:	subl %esi, $0xfffffffc<UINT8>
0x00429861:	adcl %ebx, %ebx
0x00429869:	movl %ebx, (%esi)
0x0042986b:	subl %esi, $0xfffffffc<UINT8>
0x0042986e:	adcl %ebx, %ebx
0x0042982c:	movl %ebx, (%esi)
0x0042982e:	subl %esi, $0xfffffffc<UINT8>
0x00429831:	adcl %ebx, %ebx
0x00429888:	movl %ebx, (%esi)
0x0042988a:	subl %esi, $0xfffffffc<UINT8>
0x0042988d:	adcl %ebx, %ebx
0x0042988f:	jae 0x00429875
0x00429879:	movl %ebx, (%esi)
0x0042987b:	subl %esi, $0xfffffffc<UINT8>
0x0042987e:	adcl %ebx, %ebx
0x004298ca:	popl %esi
0x004298cb:	movl %edi, %esi
0x004298cd:	movl %ecx, $0x680<UINT32>
0x004298d2:	movb %al, (%edi)
0x004298d4:	incl %edi
0x004298d5:	subb %al, $0xffffffe8<UINT8>
0x004298d7:	cmpb %al, $0x1<UINT8>
0x004298d9:	ja 0x004298d2
0x004298db:	cmpb (%edi), $0x5<UINT8>
0x004298de:	jne 0x004298d2
0x004298e0:	movl %eax, (%edi)
0x004298e2:	movb %bl, 0x4(%edi)
0x004298e5:	shrw %ax, $0x8<UINT8>
0x004298e9:	roll %eax, $0x10<UINT8>
0x004298ec:	xchgb %ah, %al
0x004298ee:	subl %eax, %edi
0x004298f0:	subb %bl, $0xffffffe8<UINT8>
0x004298f3:	addl %eax, %esi
0x004298f5:	movl (%edi), %eax
0x004298f7:	addl %edi, $0x5<UINT8>
0x004298fa:	movb %al, %bl
0x004298fc:	loop 0x004298d7
0x004298fe:	leal %edi, 0x26000(%esi)
0x00429904:	movl %eax, (%edi)
0x00429906:	orl %eax, %eax
0x00429908:	je 0x00429946
0x0042990a:	movl %ebx, 0x4(%edi)
0x0042990d:	leal %eax, 0x2956c(%eax,%esi)
0x00429914:	addl %ebx, %esi
0x00429916:	pushl %eax
0x00429917:	addl %edi, $0x8<UINT8>
0x0042991a:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00429920:	xchgl %ebp, %eax
0x00429921:	movb %al, (%edi)
0x00429923:	incl %edi
0x00429924:	orb %al, %al
0x00429926:	je 0x00429904
0x00429928:	movl %ecx, %edi
0x0042992a:	pushl %edi
0x0042992b:	decl %eax
0x0042992c:	repn scasb %al, %es:(%edi)
0x0042992e:	pushl %ebp
0x0042992f:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00429935:	orl %eax, %eax
0x00429937:	je 7
0x00429939:	movl (%ebx), %eax
0x0042993b:	addl %ebx, $0x4<UINT8>
0x0042993e:	jmp 0x00429921
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x00429946:	addl %edi, $0x4<UINT8>
0x00429949:	leal %ebx, -4(%esi)
0x0042994c:	xorl %eax, %eax
0x0042994e:	movb %al, (%edi)
0x00429950:	incl %edi
0x00429951:	orl %eax, %eax
0x00429953:	je 0x00429977
0x00429955:	cmpb %al, $0xffffffef<UINT8>
0x00429957:	ja 0x0042996a
0x00429959:	addl %ebx, %eax
0x0042995b:	movl %eax, (%ebx)
0x0042995d:	xchgb %ah, %al
0x0042995f:	roll %eax, $0x10<UINT8>
0x00429962:	xchgb %ah, %al
0x00429964:	addl %eax, %esi
0x00429966:	movl (%ebx), %eax
0x00429968:	jmp 0x0042994c
0x0042996a:	andb %al, $0xf<UINT8>
0x0042996c:	shll %eax, $0x10<UINT8>
0x0042996f:	movw %ax, (%edi)
0x00429972:	addl %edi, $0x2<UINT8>
0x00429975:	jmp 0x00429959
0x00429977:	movl %ebp, 0x2961c(%esi)
0x0042997d:	leal %edi, -4096(%esi)
0x00429983:	movl %ebx, $0x1000<UINT32>
0x00429988:	pushl %eax
0x00429989:	pushl %esp
0x0042998a:	pushl $0x4<UINT8>
0x0042998c:	pushl %ebx
0x0042998d:	pushl %edi
0x0042998e:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00429990:	leal %eax, 0x21f(%edi)
0x00429996:	andb (%eax), $0x7f<UINT8>
0x00429999:	andb 0x28(%eax), $0x7f<UINT8>
0x0042999d:	popl %eax
0x0042999e:	pushl %eax
0x0042999f:	pushl %esp
0x004299a0:	pushl %eax
0x004299a1:	pushl %ebx
0x004299a2:	pushl %edi
0x004299a3:	call VirtualProtect@kernel32.dll
0x004299a5:	popl %eax
0x004299a6:	popa
0x004299a7:	leal %eax, -128(%esp)
0x004299ab:	pushl $0x0<UINT8>
0x004299ad:	cmpl %esp, %eax
0x004299af:	jne 0x004299ab
0x004299b1:	subl %esp, $0xffffff80<UINT8>
0x004299b4:	jmp 0x004047af
0x004047af:	call 0x0040b7c1
0x0040b7c1:	pushl %ebp
0x0040b7c2:	movl %ebp, %esp
0x0040b7c4:	subl %esp, $0x14<UINT8>
0x0040b7c7:	andl -12(%ebp), $0x0<UINT8>
0x0040b7cb:	andl -8(%ebp), $0x0<UINT8>
0x0040b7cf:	movl %eax, 0x4200d0
0x0040b7d4:	pushl %esi
0x0040b7d5:	pushl %edi
0x0040b7d6:	movl %edi, $0xbb40e64e<UINT32>
0x0040b7db:	movl %esi, $0xffff0000<UINT32>
0x0040b7e0:	cmpl %eax, %edi
0x0040b7e2:	je 0x0040b7f1
0x0040b7f1:	leal %eax, -12(%ebp)
0x0040b7f4:	pushl %eax
0x0040b7f5:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040b7fb:	movl %eax, -8(%ebp)
0x0040b7fe:	xorl %eax, -12(%ebp)
0x0040b801:	movl -4(%ebp), %eax
0x0040b804:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040b80a:	xorl -4(%ebp), %eax
0x0040b80d:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040b813:	xorl -4(%ebp), %eax
0x0040b816:	leal %eax, -20(%ebp)
0x0040b819:	pushl %eax
0x0040b81a:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040b820:	movl %ecx, -16(%ebp)
0x0040b823:	leal %eax, -4(%ebp)
0x0040b826:	xorl %ecx, -20(%ebp)
0x0040b829:	xorl %ecx, -4(%ebp)
0x0040b82c:	xorl %ecx, %eax
0x0040b82e:	cmpl %ecx, %edi
0x0040b830:	jne 0x0040b839
0x0040b839:	testl %esi, %ecx
0x0040b83b:	jne 0x0040b849
0x0040b849:	movl 0x4200d0, %ecx
0x0040b84f:	notl %ecx
0x0040b851:	movl 0x4200d4, %ecx
0x0040b857:	popl %edi
0x0040b858:	popl %esi
0x0040b859:	movl %esp, %ebp
0x0040b85b:	popl %ebp
0x0040b85c:	ret

0x004047b4:	jmp 0x00404634
0x00404634:	pushl $0x14<UINT8>
0x00404636:	pushl $0x41e9d8<UINT32>
0x0040463b:	call 0x004067b0
0x004067b0:	pushl $0x406810<UINT32>
0x004067b5:	pushl %fs:0
0x004067bc:	movl %eax, 0x10(%esp)
0x004067c0:	movl 0x10(%esp), %ebp
0x004067c4:	leal %ebp, 0x10(%esp)
0x004067c8:	subl %esp, %eax
0x004067ca:	pushl %ebx
0x004067cb:	pushl %esi
0x004067cc:	pushl %edi
0x004067cd:	movl %eax, 0x4200d0
0x004067d2:	xorl -4(%ebp), %eax
0x004067d5:	xorl %eax, %ebp
0x004067d7:	pushl %eax
0x004067d8:	movl -24(%ebp), %esp
0x004067db:	pushl -8(%ebp)
0x004067de:	movl %eax, -4(%ebp)
0x004067e1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004067e8:	movl -8(%ebp), %eax
0x004067eb:	leal %eax, -16(%ebp)
0x004067ee:	movl %fs:0, %eax
0x004067f4:	ret

0x00404640:	pushl $0x1<UINT8>
0x00404642:	call 0x0040b774
0x0040b774:	pushl %ebp
0x0040b775:	movl %ebp, %esp
0x0040b777:	movl %eax, 0x8(%ebp)
0x0040b77a:	movl 0x421440, %eax
0x0040b77f:	popl %ebp
0x0040b780:	ret

0x00404647:	popl %ecx
0x00404648:	movl %eax, $0x5a4d<UINT32>
0x0040464d:	cmpw 0x400000, %ax
0x00404654:	je 0x0040465a
0x0040465a:	movl %eax, 0x40003c
0x0040465f:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00404669:	jne -21
0x0040466b:	movl %ecx, $0x10b<UINT32>
0x00404670:	cmpw 0x400018(%eax), %cx
0x00404677:	jne -35
0x00404679:	xorl %ebx, %ebx
0x0040467b:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00404682:	jbe 9
0x00404684:	cmpl 0x4000e8(%eax), %ebx
0x0040468a:	setne %bl
0x0040468d:	movl -28(%ebp), %ebx
0x00404690:	call 0x00406a7b
0x00406a7b:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x00406a81:	xorl %ecx, %ecx
0x00406a83:	movl 0x421aa0, %eax
0x00406a88:	testl %eax, %eax
0x00406a8a:	setne %cl
0x00406a8d:	movl %eax, %ecx
0x00406a8f:	ret

0x00404695:	testl %eax, %eax
0x00404697:	jne 0x004046a1
0x004046a1:	call 0x00405779
0x00405779:	call 0x00402b3b
0x00402b3b:	pushl %esi
0x00402b3c:	pushl $0x0<UINT8>
0x00402b3e:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00402b44:	movl %esi, %eax
0x00402b46:	pushl %esi
0x00402b47:	call 0x00406562
0x00406562:	pushl %ebp
0x00406563:	movl %ebp, %esp
0x00406565:	movl %eax, 0x8(%ebp)
0x00406568:	movl 0x421a78, %eax
0x0040656d:	popl %ebp
0x0040656e:	ret

0x00402b4c:	pushl %esi
0x00402b4d:	call 0x004048de
0x004048de:	pushl %ebp
0x004048df:	movl %ebp, %esp
0x004048e1:	movl %eax, 0x8(%ebp)
0x004048e4:	movl 0x4212c8, %eax
0x004048e9:	popl %ebp
0x004048ea:	ret

0x00402b52:	pushl %esi
0x00402b53:	call 0x0040656f
0x0040656f:	pushl %ebp
0x00406570:	movl %ebp, %esp
0x00406572:	movl %eax, 0x8(%ebp)
0x00406575:	movl 0x421a7c, %eax
0x0040657a:	popl %ebp
0x0040657b:	ret

0x00402b58:	pushl %esi
0x00402b59:	call 0x00406589
0x00406589:	pushl %ebp
0x0040658a:	movl %ebp, %esp
0x0040658c:	movl %eax, 0x8(%ebp)
0x0040658f:	movl 0x421a80, %eax
0x00406594:	movl 0x421a84, %eax
0x00406599:	movl 0x421a88, %eax
0x0040659e:	movl 0x421a8c, %eax
0x004065a3:	popl %ebp
0x004065a4:	ret

0x00402b5e:	pushl %esi
0x00402b5f:	call 0x0040652b
0x0040652b:	pushl $0x4064f7<UINT32>
0x00406530:	call EncodePointer@KERNEL32.DLL
0x00406536:	movl 0x421a74, %eax
0x0040653b:	ret

0x00402b64:	pushl %esi
0x00402b65:	call 0x0040679a
0x0040679a:	pushl %ebp
0x0040679b:	movl %ebp, %esp
0x0040679d:	movl %eax, 0x8(%ebp)
0x004067a0:	movl 0x421a94, %eax
0x004067a5:	popl %ebp
0x004067a6:	ret

0x00402b6a:	addl %esp, $0x18<UINT8>
0x00402b6d:	popl %esi
0x00402b6e:	jmp 0x00405c42
0x00405c42:	pushl %esi
0x00405c43:	pushl %edi
0x00405c44:	pushl $0x41b028<UINT32>
0x00405c49:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00405c4f:	movl %esi, 0x414080
0x00405c55:	movl %edi, %eax
0x00405c57:	pushl $0x41b044<UINT32>
0x00405c5c:	pushl %edi
0x00405c5d:	call GetProcAddress@KERNEL32.DLL
0x00405c5f:	xorl %eax, 0x4200d0
0x00405c65:	pushl $0x41b050<UINT32>
0x00405c6a:	pushl %edi
0x00405c6b:	movl 0x422020, %eax
0x00405c70:	call GetProcAddress@KERNEL32.DLL
0x00405c72:	xorl %eax, 0x4200d0
0x00405c78:	pushl $0x41b058<UINT32>
0x00405c7d:	pushl %edi
0x00405c7e:	movl 0x422024, %eax
0x00405c83:	call GetProcAddress@KERNEL32.DLL
0x00405c85:	xorl %eax, 0x4200d0
0x00405c8b:	pushl $0x41b064<UINT32>
0x00405c90:	pushl %edi
0x00405c91:	movl 0x422028, %eax
0x00405c96:	call GetProcAddress@KERNEL32.DLL
0x00405c98:	xorl %eax, 0x4200d0
0x00405c9e:	pushl $0x41b070<UINT32>
0x00405ca3:	pushl %edi
0x00405ca4:	movl 0x42202c, %eax
0x00405ca9:	call GetProcAddress@KERNEL32.DLL
0x00405cab:	xorl %eax, 0x4200d0
0x00405cb1:	pushl $0x41b08c<UINT32>
0x00405cb6:	pushl %edi
0x00405cb7:	movl 0x422030, %eax
0x00405cbc:	call GetProcAddress@KERNEL32.DLL
0x00405cbe:	xorl %eax, 0x4200d0
0x00405cc4:	pushl $0x41b09c<UINT32>
0x00405cc9:	pushl %edi
0x00405cca:	movl 0x422034, %eax
0x00405ccf:	call GetProcAddress@KERNEL32.DLL
0x00405cd1:	xorl %eax, 0x4200d0
0x00405cd7:	pushl $0x41b0b0<UINT32>
0x00405cdc:	pushl %edi
0x00405cdd:	movl 0x422038, %eax
0x00405ce2:	call GetProcAddress@KERNEL32.DLL
0x00405ce4:	xorl %eax, 0x4200d0
0x00405cea:	pushl $0x41b0c8<UINT32>
0x00405cef:	pushl %edi
0x00405cf0:	movl 0x42203c, %eax
0x00405cf5:	call GetProcAddress@KERNEL32.DLL
0x00405cf7:	xorl %eax, 0x4200d0
0x00405cfd:	pushl $0x41b0e0<UINT32>
0x00405d02:	pushl %edi
0x00405d03:	movl 0x422040, %eax
0x00405d08:	call GetProcAddress@KERNEL32.DLL
0x00405d0a:	xorl %eax, 0x4200d0
0x00405d10:	pushl $0x41b0f4<UINT32>
0x00405d15:	pushl %edi
0x00405d16:	movl 0x422044, %eax
0x00405d1b:	call GetProcAddress@KERNEL32.DLL
0x00405d1d:	xorl %eax, 0x4200d0
0x00405d23:	pushl $0x41b114<UINT32>
0x00405d28:	pushl %edi
0x00405d29:	movl 0x422048, %eax
0x00405d2e:	call GetProcAddress@KERNEL32.DLL
0x00405d30:	xorl %eax, 0x4200d0
0x00405d36:	pushl $0x41b12c<UINT32>
0x00405d3b:	pushl %edi
0x00405d3c:	movl 0x42204c, %eax
0x00405d41:	call GetProcAddress@KERNEL32.DLL
0x00405d43:	xorl %eax, 0x4200d0
0x00405d49:	pushl $0x41b144<UINT32>
0x00405d4e:	pushl %edi
0x00405d4f:	movl 0x422050, %eax
0x00405d54:	call GetProcAddress@KERNEL32.DLL
0x00405d56:	xorl %eax, 0x4200d0
0x00405d5c:	pushl $0x41b158<UINT32>
0x00405d61:	pushl %edi
0x00405d62:	movl 0x422054, %eax
0x00405d67:	call GetProcAddress@KERNEL32.DLL
0x00405d69:	xorl %eax, 0x4200d0
0x00405d6f:	movl 0x422058, %eax
0x00405d74:	pushl $0x41b16c<UINT32>
0x00405d79:	pushl %edi
0x00405d7a:	call GetProcAddress@KERNEL32.DLL
0x00405d7c:	xorl %eax, 0x4200d0
0x00405d82:	pushl $0x41b188<UINT32>
0x00405d87:	pushl %edi
0x00405d88:	movl 0x42205c, %eax
0x00405d8d:	call GetProcAddress@KERNEL32.DLL
0x00405d8f:	xorl %eax, 0x4200d0
0x00405d95:	pushl $0x41b1a8<UINT32>
0x00405d9a:	pushl %edi
0x00405d9b:	movl 0x422060, %eax
0x00405da0:	call GetProcAddress@KERNEL32.DLL
0x00405da2:	xorl %eax, 0x4200d0
0x00405da8:	pushl $0x41b1c4<UINT32>
0x00405dad:	pushl %edi
0x00405dae:	movl 0x422064, %eax
0x00405db3:	call GetProcAddress@KERNEL32.DLL
0x00405db5:	xorl %eax, 0x4200d0
0x00405dbb:	pushl $0x41b1e4<UINT32>
0x00405dc0:	pushl %edi
0x00405dc1:	movl 0x422068, %eax
0x00405dc6:	call GetProcAddress@KERNEL32.DLL
0x00405dc8:	xorl %eax, 0x4200d0
0x00405dce:	pushl $0x41b1f8<UINT32>
0x00405dd3:	pushl %edi
0x00405dd4:	movl 0x42206c, %eax
0x00405dd9:	call GetProcAddress@KERNEL32.DLL
0x00405ddb:	xorl %eax, 0x4200d0
0x00405de1:	pushl $0x41b214<UINT32>
0x00405de6:	pushl %edi
0x00405de7:	movl 0x422070, %eax
0x00405dec:	call GetProcAddress@KERNEL32.DLL
0x00405dee:	xorl %eax, 0x4200d0
0x00405df4:	pushl $0x41b228<UINT32>
0x00405df9:	pushl %edi
0x00405dfa:	movl 0x422078, %eax
0x00405dff:	call GetProcAddress@KERNEL32.DLL
0x00405e01:	xorl %eax, 0x4200d0
0x00405e07:	pushl $0x41b238<UINT32>
0x00405e0c:	pushl %edi
0x00405e0d:	movl 0x422074, %eax
0x00405e12:	call GetProcAddress@KERNEL32.DLL
0x00405e14:	xorl %eax, 0x4200d0
0x00405e1a:	pushl $0x41b248<UINT32>
0x00405e1f:	pushl %edi
0x00405e20:	movl 0x42207c, %eax
0x00405e25:	call GetProcAddress@KERNEL32.DLL
0x00405e27:	xorl %eax, 0x4200d0
0x00405e2d:	pushl $0x41b258<UINT32>
0x00405e32:	pushl %edi
0x00405e33:	movl 0x422080, %eax
0x00405e38:	call GetProcAddress@KERNEL32.DLL
0x00405e3a:	xorl %eax, 0x4200d0
0x00405e40:	pushl $0x41b268<UINT32>
0x00405e45:	pushl %edi
0x00405e46:	movl 0x422084, %eax
0x00405e4b:	call GetProcAddress@KERNEL32.DLL
0x00405e4d:	xorl %eax, 0x4200d0
0x00405e53:	pushl $0x41b284<UINT32>
0x00405e58:	pushl %edi
0x00405e59:	movl 0x422088, %eax
0x00405e5e:	call GetProcAddress@KERNEL32.DLL
0x00405e60:	xorl %eax, 0x4200d0
0x00405e66:	pushl $0x41b298<UINT32>
0x00405e6b:	pushl %edi
0x00405e6c:	movl 0x42208c, %eax
0x00405e71:	call GetProcAddress@KERNEL32.DLL
0x00405e73:	xorl %eax, 0x4200d0
0x00405e79:	pushl $0x41b2a8<UINT32>
0x00405e7e:	pushl %edi
0x00405e7f:	movl 0x422090, %eax
0x00405e84:	call GetProcAddress@KERNEL32.DLL
0x00405e86:	xorl %eax, 0x4200d0
0x00405e8c:	pushl $0x41b2bc<UINT32>
0x00405e91:	pushl %edi
0x00405e92:	movl 0x422094, %eax
0x00405e97:	call GetProcAddress@KERNEL32.DLL
0x00405e99:	xorl %eax, 0x4200d0
0x00405e9f:	movl 0x422098, %eax
0x00405ea4:	pushl $0x41b2cc<UINT32>
0x00405ea9:	pushl %edi
0x00405eaa:	call GetProcAddress@KERNEL32.DLL
0x00405eac:	xorl %eax, 0x4200d0
0x00405eb2:	pushl $0x41b2ec<UINT32>
0x00405eb7:	pushl %edi
0x00405eb8:	movl 0x42209c, %eax
0x00405ebd:	call GetProcAddress@KERNEL32.DLL
0x00405ebf:	xorl %eax, 0x4200d0
0x00405ec5:	popl %edi
0x00405ec6:	movl 0x4220a0, %eax
0x00405ecb:	popl %esi
0x00405ecc:	ret

0x0040577e:	call 0x00405b08
0x00405b08:	pushl %esi
0x00405b09:	pushl %edi
0x00405b0a:	movl %esi, $0x420c20<UINT32>
0x00405b0f:	movl %edi, $0x4212f0<UINT32>
0x00405b14:	cmpl 0x4(%esi), $0x1<UINT8>
0x00405b18:	jne 22
0x00405b1a:	pushl $0x0<UINT8>
0x00405b1c:	movl (%esi), %edi
0x00405b1e:	addl %edi, $0x18<UINT8>
0x00405b21:	pushl $0xfa0<UINT32>
0x00405b26:	pushl (%esi)
0x00405b28:	call 0x00405bd4
0x00405bd4:	pushl %ebp
0x00405bd5:	movl %ebp, %esp
0x00405bd7:	movl %eax, 0x422030
0x00405bdc:	xorl %eax, 0x4200d0
0x00405be2:	je 13
0x00405be4:	pushl 0x10(%ebp)
0x00405be7:	pushl 0xc(%ebp)
0x00405bea:	pushl 0x8(%ebp)
0x00405bed:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x00405bef:	popl %ebp
0x00405bf0:	ret

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
