0x00435000:	movl %ebx, $0x4001d0<UINT32>
0x00435005:	movl %edi, $0x401000<UINT32>
0x0043500a:	movl %esi, $0x42437e<UINT32>
0x0043500f:	pushl %ebx
0x00435010:	call 0x0043501f
0x0043501f:	cld
0x00435020:	movb %dl, $0xffffff80<UINT8>
0x00435022:	movsb %es:(%edi), %ds:(%esi)
0x00435023:	pushl $0x2<UINT8>
0x00435025:	popl %ebx
0x00435026:	call 0x00435015
0x00435015:	addb %dl, %dl
0x00435017:	jne 0x0043501e
0x00435019:	movb %dl, (%esi)
0x0043501b:	incl %esi
0x0043501c:	adcb %dl, %dl
0x0043501e:	ret

0x00435029:	jae 0x00435022
0x0043502b:	xorl %ecx, %ecx
0x0043502d:	call 0x00435015
0x00435030:	jae 0x0043504a
0x00435032:	xorl %eax, %eax
0x00435034:	call 0x00435015
0x00435037:	jae 0x0043505a
0x0043505a:	lodsb %al, %ds:(%esi)
0x0043505b:	shrl %eax
0x0043505d:	je 0x004350a0
0x0043505f:	adcl %ecx, %ecx
0x00435061:	jmp 0x0043507f
0x0043507f:	incl %ecx
0x00435080:	incl %ecx
0x00435081:	xchgl %ebp, %eax
0x00435082:	movl %eax, %ebp
0x00435084:	movb %bl, $0x1<UINT8>
0x00435086:	pushl %esi
0x00435087:	movl %esi, %edi
0x00435089:	subl %esi, %eax
0x0043508b:	rep movsb %es:(%edi), %ds:(%esi)
0x0043508d:	popl %esi
0x0043508e:	jmp 0x00435026
0x00435039:	movb %bl, $0x2<UINT8>
0x0043503b:	incl %ecx
0x0043503c:	movb %al, $0x10<UINT8>
0x0043503e:	call 0x00435015
0x00435041:	adcb %al, %al
0x00435043:	jae 0x0043503e
0x00435045:	jne 0x00435086
0x00435047:	stosb %es:(%edi), %al
0x00435048:	jmp 0x00435026
0x0043504a:	call 0x00435092
0x00435092:	incl %ecx
0x00435093:	call 0x00435015
0x00435097:	adcl %ecx, %ecx
0x00435099:	call 0x00435015
0x0043509d:	jb 0x00435093
0x0043509f:	ret

0x0043504f:	subl %ecx, %ebx
0x00435051:	jne 0x00435063
0x00435053:	call 0x00435090
0x00435090:	xorl %ecx, %ecx
0x00435058:	jmp 0x00435082
0x00435063:	xchgl %ecx, %eax
0x00435064:	decl %eax
0x00435065:	shll %eax, $0x8<UINT8>
0x00435068:	lodsb %al, %ds:(%esi)
0x00435069:	call 0x00435090
0x0043506e:	cmpl %eax, $0x7d00<UINT32>
0x00435073:	jae 0x0043507f
0x00435075:	cmpb %ah, $0x5<UINT8>
0x00435078:	jae 0x00435080
0x0043507a:	cmpl %eax, $0x7f<UINT8>
0x0043507d:	ja 0x00435081
0x004350a0:	popl %edi
0x004350a1:	popl %ebx
0x004350a2:	movzwl %edi, (%ebx)
0x004350a5:	decl %edi
0x004350a6:	je 0x004350b0
0x004350a8:	decl %edi
0x004350a9:	je 0x004350be
0x004350ab:	shll %edi, $0xc<UINT8>
0x004350ae:	jmp 0x004350b7
0x004350b7:	incl %ebx
0x004350b8:	incl %ebx
0x004350b9:	jmp 0x0043500f
0x004350b0:	movl %edi, 0x2(%ebx)
0x004350b3:	pushl %edi
0x004350b4:	addl %ebx, $0x4<UINT8>
0x004350be:	popl %edi
0x004350bf:	movl %ebx, $0x435128<UINT32>
0x004350c4:	incl %edi
0x004350c5:	movl %esi, (%edi)
0x004350c7:	scasl %eax, %es:(%edi)
0x004350c8:	pushl %edi
0x004350c9:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004350cb:	xchgl %ebp, %eax
0x004350cc:	xorl %eax, %eax
0x004350ce:	scasb %al, %es:(%edi)
0x004350cf:	jne 0x004350ce
0x004350d1:	decb (%edi)
0x004350d3:	je 0x004350c4
0x004350d5:	decb (%edi)
0x004350d7:	jne 0x004350df
0x004350df:	decb (%edi)
0x004350e1:	je 0x0040849b
0x004350e7:	pushl %edi
0x004350e8:	pushl %ebp
0x004350e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x004350ec:	orl (%esi), %eax
0x004350ee:	lodsl %eax, %ds:(%esi)
0x004350ef:	jne 0x004350cc
GetProcAddress@KERNEL32.dll: API Node	
0x004350d9:	incl %edi
0x004350da:	pushl (%edi)
0x004350dc:	scasl %eax, %es:(%edi)
0x004350dd:	jmp 0x004350e8
0x0040849b:	call 0x0040888a
0x0040888a:	pushl %ebp
0x0040888b:	movl %ebp, %esp
0x0040888d:	subl %esp, $0x14<UINT8>
0x00408890:	andl -12(%ebp), $0x0<UINT8>
0x00408894:	andl -8(%ebp), $0x0<UINT8>
0x00408898:	movl %eax, 0x420018
0x0040889d:	pushl %esi
0x0040889e:	pushl %edi
0x0040889f:	movl %edi, $0xbb40e64e<UINT32>
0x004088a4:	movl %esi, $0xffff0000<UINT32>
0x004088a9:	cmpl %eax, %edi
0x004088ab:	je 0x004088ba
0x004088ba:	leal %eax, -12(%ebp)
0x004088bd:	pushl %eax
0x004088be:	call GetSystemTimeAsFileTime@KERNEL32.dll
GetSystemTimeAsFileTime@KERNEL32.dll: API Node	
0x004088c4:	movl %eax, -8(%ebp)
0x004088c7:	xorl %eax, -12(%ebp)
0x004088ca:	movl -4(%ebp), %eax
0x004088cd:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x004088d3:	xorl -4(%ebp), %eax
0x004088d6:	call GetCurrentProcessId@KERNEL32.dll
GetCurrentProcessId@KERNEL32.dll: API Node	
0x004088dc:	xorl -4(%ebp), %eax
0x004088df:	leal %eax, -20(%ebp)
0x004088e2:	pushl %eax
0x004088e3:	call QueryPerformanceCounter@KERNEL32.dll
QueryPerformanceCounter@KERNEL32.dll: API Node	
0x004088e9:	movl %ecx, -16(%ebp)
0x004088ec:	leal %eax, -4(%ebp)
0x004088ef:	xorl %ecx, -20(%ebp)
0x004088f2:	xorl %ecx, -4(%ebp)
0x004088f5:	xorl %ecx, %eax
0x004088f7:	cmpl %ecx, %edi
0x004088f9:	jne 0x00408902
0x00408902:	testl %esi, %ecx
0x00408904:	jne 0x00408912
0x00408912:	movl 0x420018, %ecx
0x00408918:	notl %ecx
0x0040891a:	movl 0x420014, %ecx
0x00408920:	popl %edi
0x00408921:	popl %esi
0x00408922:	movl %esp, %ebp
0x00408924:	popl %ebp
0x00408925:	ret

0x004084a0:	jmp 0x0040832d
0x0040832d:	pushl $0x14<UINT8>
0x0040832f:	pushl $0x41ea68<UINT32>
0x00408334:	call 0x004084b0
0x004084b0:	pushl $0x408ec0<UINT32>
0x004084b5:	pushl %fs:0
0x004084bc:	movl %eax, 0x10(%esp)
0x004084c0:	movl 0x10(%esp), %ebp
0x004084c4:	leal %ebp, 0x10(%esp)
0x004084c8:	subl %esp, %eax
0x004084ca:	pushl %ebx
0x004084cb:	pushl %esi
0x004084cc:	pushl %edi
0x004084cd:	movl %eax, 0x420018
0x004084d2:	xorl -4(%ebp), %eax
0x004084d5:	xorl %eax, %ebp
0x004084d7:	pushl %eax
0x004084d8:	movl -24(%ebp), %esp
0x004084db:	pushl -8(%ebp)
0x004084de:	movl %eax, -4(%ebp)
0x004084e1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004084e8:	movl -8(%ebp), %eax
0x004084eb:	leal %eax, -16(%ebp)
0x004084ee:	movl %fs:0, %eax
0x004084f4:	repn ret

0x00408339:	pushl $0x1<UINT8>
0x0040833b:	call 0x004085af
0x004085af:	pushl %ebp
0x004085b0:	movl %ebp, %esp
0x004085b2:	cmpl 0x8(%ebp), $0x0<UINT8>
0x004085b6:	jne 0x004085bf
0x004085bf:	call 0x00408bac
0x00408bac:	pushl %ebp
0x00408bad:	movl %ebp, %esp
0x00408baf:	andl 0x4208dc, $0x0<UINT8>
0x00408bb6:	subl %esp, $0x24<UINT8>
0x00408bb9:	pushl %ebx
0x00408bba:	xorl %ebx, %ebx
0x00408bbc:	incl %ebx
0x00408bbd:	orl 0x420020, %ebx
0x00408bc3:	pushl $0xa<UINT8>
0x00408bc5:	call 0x0041ce34
0x0041ce34:	jmp IsProcessorFeaturePresent@KERNEL32.dll
IsProcessorFeaturePresent@KERNEL32.dll: API Node	
0x00408bca:	testl %eax, %eax
0x00408bcc:	je 370
0x00408bd2:	andl -16(%ebp), $0x0<UINT8>
0x00408bd6:	xorl %eax, %eax
0x00408bd8:	orl 0x420020, $0x2<UINT8>
0x00408bdf:	xorl %ecx, %ecx
0x00408be1:	pushl %esi
0x00408be2:	pushl %edi
0x00408be3:	movl 0x4208dc, %ebx
0x00408be9:	leal %edi, -36(%ebp)
0x00408bec:	pushl %ebx
0x00408bed:	cpuid
0x00408bef:	movl %esi, %ebx
0x00408bf1:	popl %ebx
0x00408bf2:	movl (%edi), %eax
0x00408bf4:	movl 0x4(%edi), %esi
0x00408bf7:	movl 0x8(%edi), %ecx
0x00408bfa:	xorl %ecx, %ecx
0x00408bfc:	movl 0xc(%edi), %edx
0x00408bff:	movl %eax, -36(%ebp)
0x00408c02:	movl %edi, -32(%ebp)
0x00408c05:	movl -12(%ebp), %eax
0x00408c08:	xorl %edi, $0x756e6547<UINT32>
0x00408c0e:	movl %eax, -24(%ebp)
0x00408c11:	xorl %eax, $0x49656e69<UINT32>
0x00408c16:	movl -8(%ebp), %eax
0x00408c19:	movl %eax, -28(%ebp)
0x00408c1c:	xorl %eax, $0x6c65746e<UINT32>
0x00408c21:	movl -4(%ebp), %eax
0x00408c24:	xorl %eax, %eax
0x00408c26:	incl %eax
0x00408c27:	pushl %ebx
0x00408c28:	cpuid
0x00408c2a:	movl %esi, %ebx
0x00408c2c:	popl %ebx
0x00408c2d:	leal %ebx, -36(%ebp)
0x00408c30:	movl (%ebx), %eax
0x00408c32:	movl %eax, -4(%ebp)
0x00408c35:	orl %eax, -8(%ebp)
0x00408c38:	orl %eax, %edi
0x00408c3a:	movl 0x4(%ebx), %esi
0x00408c3d:	movl 0x8(%ebx), %ecx
0x00408c40:	movl 0xc(%ebx), %edx
0x00408c43:	jne 67
0x00408c45:	movl %eax, -36(%ebp)
0x00408c48:	andl %eax, $0xfff3ff0<UINT32>
0x00408c4d:	cmpl %eax, $0x106c0<UINT32>
0x00408c52:	je 35
0x00408c54:	cmpl %eax, $0x20660<UINT32>
0x00408c59:	je 28
0x00408c5b:	cmpl %eax, $0x20670<UINT32>
0x00408c60:	je 21
0x00408c62:	cmpl %eax, $0x30650<UINT32>
0x00408c67:	je 14
0x00408c69:	cmpl %eax, $0x30660<UINT32>
0x00408c6e:	je 7
0x00408c70:	cmpl %eax, $0x30670<UINT32>
0x00408c75:	jne 0x00408c88
0x00408c88:	movl %edi, 0x4208e0
0x00408c8e:	cmpl -12(%ebp), $0x7<UINT8>
0x00408c92:	movl %eax, -28(%ebp)
0x00408c95:	movl -4(%ebp), %eax
0x00408c98:	jl 0x00408ccc
0x00408ccc:	movl %ebx, -16(%ebp)
0x00408ccf:	popl %edi
0x00408cd0:	popl %esi
0x00408cd1:	testl %eax, $0x100000<UINT32>
0x00408cd6:	je 0x00408d44
0x00408d44:	xorl %eax, %eax
0x00408d46:	popl %ebx
0x00408d47:	movl %esp, %ebp
0x00408d49:	popl %ebp
0x00408d4a:	ret

0x004085c4:	call 0x004093fc
0x004093fc:	call 0x0040a9e3
0x0040a9e3:	movl %eax, 0x420018
0x0040a9e8:	andl %eax, $0x1f<UINT8>
0x0040a9eb:	pushl $0x20<UINT8>
0x0040a9ed:	popl %ecx
0x0040a9ee:	subl %ecx, %eax
0x0040a9f0:	xorl %eax, %eax
0x0040a9f2:	rorl %eax, %cl
0x0040a9f4:	xorl %eax, 0x420018
0x0040a9fa:	movl 0x420c6c, %eax
0x0040a9ff:	ret

0x00409401:	call 0x0040a977
0x0040a977:	movl %eax, 0x420018
0x0040a97c:	movl %edx, $0x420c6c<UINT32>
0x0040a981:	pushl %esi
0x0040a982:	andl %eax, $0x1f<UINT8>
0x0040a985:	xorl %esi, %esi
0x0040a987:	pushl $0x20<UINT8>
0x0040a989:	popl %ecx
0x0040a98a:	subl %ecx, %eax
0x0040a98c:	movl %eax, $0x420c58<UINT32>
0x0040a991:	rorl %esi, %cl
0x0040a993:	xorl %ecx, %ecx
0x0040a995:	xorl %esi, 0x420018
0x0040a99b:	cmpl %edx, %eax
0x0040a99d:	sbbl %edx, %edx
0x0040a99f:	andl %edx, $0xfffffffb<UINT8>
0x0040a9a2:	addl %edx, $0x5<UINT8>
0x0040a9a5:	incl %ecx
0x0040a9a6:	movl (%eax), %esi
0x0040a9a8:	leal %eax, 0x4(%eax)
0x0040a9ab:	cmpl %ecx, %edx
0x0040a9ad:	jne 0x0040a9a5
0x0040a9af:	popl %esi
0x0040a9b0:	ret

0x00409406:	call 0x0040a695
0x0040a695:	pushl %esi
0x0040a696:	pushl %edi
0x0040a697:	movl %edi, $0x420c30<UINT32>
0x0040a69c:	xorl %esi, %esi
0x0040a69e:	pushl $0x0<UINT8>
0x0040a6a0:	pushl $0xfa0<UINT32>
0x0040a6a5:	pushl %edi
0x0040a6a6:	call 0x0040a931
0x0040a931:	pushl %ebp
0x0040a932:	movl %ebp, %esp
0x0040a934:	pushl %esi
0x0040a935:	pushl $0x40247c<UINT32>
0x0040a93a:	pushl $0x402474<UINT32>
0x0040a93f:	pushl $0x40247c<UINT32>
0x0040a944:	pushl $0x4<UINT8>
0x0040a946:	call 0x0040a7c6
0x0040a7c6:	pushl %ebp
0x0040a7c7:	movl %ebp, %esp
0x0040a7c9:	movl %eax, 0x8(%ebp)
0x0040a7cc:	pushl %ebx
0x0040a7cd:	pushl %edi
0x0040a7ce:	leal %ebx, 0x420c58(,%eax,4)
0x0040a7d5:	movl %eax, (%ebx)
0x0040a7d7:	movl %edx, 0x420018
0x0040a7dd:	orl %edi, $0xffffffff<UINT8>
0x0040a7e0:	movl %ecx, %edx
0x0040a7e2:	xorl %edx, %eax
0x0040a7e4:	andl %ecx, $0x1f<UINT8>
0x0040a7e7:	rorl %edx, %cl
0x0040a7e9:	cmpl %edx, %edi
0x0040a7eb:	jne 0x0040a7f1
0x0040a7f1:	testl %edx, %edx
0x0040a7f3:	je 0x0040a7f9
0x0040a7f9:	pushl %esi
0x0040a7fa:	pushl 0x14(%ebp)
0x0040a7fd:	pushl 0x10(%ebp)
0x0040a800:	call 0x0040a700
0x0040a700:	pushl %ebp
0x0040a701:	movl %ebp, %esp
0x0040a703:	pushl %ecx
0x0040a704:	pushl %ebx
0x0040a705:	pushl %esi
0x0040a706:	pushl %edi
0x0040a707:	movl %edi, 0x8(%ebp)
0x0040a70a:	jmp 0x0040a7b0
0x0040a7b0:	cmpl %edi, 0xc(%ebp)
0x0040a7b3:	jne 0x0040a70f
0x0040a70f:	movl %ebx, (%edi)
0x0040a711:	leal %eax, 0x420c4c(,%ebx,4)
0x0040a718:	movl %esi, (%eax)
0x0040a71a:	movl -4(%ebp), %eax
0x0040a71d:	testl %esi, %esi
0x0040a71f:	je 0x0040a72c
0x0040a72c:	movl %ebx, 0x402370(,%ebx,4)
0x0040a733:	pushl $0x800<UINT32>
0x0040a738:	pushl $0x0<UINT8>
0x0040a73a:	pushl %ebx
0x0040a73b:	call LoadLibraryExW@KERNEL32.dll
LoadLibraryExW@KERNEL32.dll: API Node	
0x0040a741:	movl %esi, %eax
0x0040a743:	testl %esi, %esi
0x0040a745:	jne 0x0040a797
0x0040a797:	movl %ecx, -4(%ebp)
0x0040a79a:	movl %eax, %esi
0x0040a79c:	xchgl (%ecx), %eax
0x0040a79e:	testl %eax, %eax
0x0040a7a0:	je 0x0040a7a9
0x0040a7a9:	testl %esi, %esi
0x0040a7ab:	jne 0x0040a7c2
0x0040a7c2:	movl %eax, %esi
0x0040a7c4:	jmp 0x0040a7bb
0x0040a7bb:	popl %edi
0x0040a7bc:	popl %esi
0x0040a7bd:	popl %ebx
0x0040a7be:	movl %esp, %ebp
0x0040a7c0:	popl %ebp
0x0040a7c1:	ret

0x0040a805:	popl %ecx
0x0040a806:	popl %ecx
0x0040a807:	testl %eax, %eax
0x0040a809:	je 29
0x0040a80b:	pushl 0xc(%ebp)
0x0040a80e:	pushl %eax
0x0040a80f:	call GetProcAddress@KERNEL32.dll
0x0040a815:	movl %esi, %eax
0x0040a817:	testl %esi, %esi
0x0040a819:	je 0x0040a828
0x0040a828:	movl %eax, 0x420018
0x0040a82d:	pushl $0x20<UINT8>
0x0040a82f:	andl %eax, $0x1f<UINT8>
0x0040a832:	popl %ecx
0x0040a833:	subl %ecx, %eax
0x0040a835:	rorl %edi, %cl
0x0040a837:	xorl %edi, 0x420018
0x0040a83d:	xchgl (%ebx), %edi
0x0040a83f:	xorl %eax, %eax
0x0040a841:	popl %esi
0x0040a842:	popl %edi
0x0040a843:	popl %ebx
0x0040a844:	popl %ebp
0x0040a845:	ret

0x0040a94b:	movl %esi, %eax
0x0040a94d:	addl %esp, $0x10<UINT8>
0x0040a950:	testl %esi, %esi
0x0040a952:	je 0x0040a968
0x0040a968:	pushl 0xc(%ebp)
0x0040a96b:	pushl 0x8(%ebp)
0x0040a96e:	call InitializeCriticalSectionAndSpinCount@KERNEL32.dll
InitializeCriticalSectionAndSpinCount@KERNEL32.dll: API Node	
0x0040a974:	popl %esi
0x0040a975:	popl %ebp
0x0040a976:	ret

0x0040a6ab:	addl %esp, $0xc<UINT8>
0x0040a6ae:	testl %eax, %eax
0x0040a6b0:	je 21
0x0040a6b2:	incl 0x420c48
0x0040a6b8:	addl %esi, $0x18<UINT8>
0x0040a6bb:	addl %edi, $0x18<UINT8>
0x0040a6be:	cmpl %esi, $0x18<UINT8>
0x0040a6c1:	jb -37
0x0040a6c3:	movb %al, $0x1<UINT8>
0x0040a6c5:	jmp 0x0040a6ce
0x0040a6ce:	popl %edi
0x0040a6cf:	popl %esi
0x0040a6d0:	ret

0x0040940b:	testb %al, %al
0x0040940d:	jne 0x00409412
0x00409412:	call 0x00409857
0x00409857:	pushl $0x40979b<UINT32>
0x0040985c:	call 0x0040a846
0x0040a846:	pushl %ebp
0x0040a847:	movl %ebp, %esp
0x0040a849:	pushl %esi
0x0040a84a:	pushl $0x402430<UINT32>
0x0040a84f:	pushl $0x402428<UINT32>
0x0040a854:	pushl $0x402430<UINT32>
0x0040a859:	pushl $0x0<UINT8>
0x0040a85b:	call 0x0040a7c6
0x0040a747:	call GetLastError@KERNEL32.dll
GetLastError@KERNEL32.dll: API Node	
0x0040a74d:	cmpl %eax, $0x57<UINT8>
0x0040a750:	jne 0x0040a787
0x0040a787:	xorl %esi, %esi
0x0040a789:	testl %esi, %esi
0x0040a78b:	jne 10
0x0040a78d:	movl %ecx, -4(%ebp)
0x0040a790:	orl %eax, $0xffffffff<UINT8>
0x0040a793:	xchgl (%ecx), %eax
0x0040a795:	jmp 0x0040a7ad
0x0040a7ad:	addl %edi, $0x4<UINT8>
0x0040a81b:	pushl %esi
0x0040a81c:	call 0x00408519
0x00408519:	pushl %ebp
0x0040851a:	movl %ebp, %esp
0x0040851c:	movl %eax, 0x420018
0x00408521:	andl %eax, $0x1f<UINT8>
0x00408524:	pushl $0x20<UINT8>
0x00408526:	popl %ecx
0x00408527:	subl %ecx, %eax
0x00408529:	movl %eax, 0x8(%ebp)
0x0040852c:	rorl %eax, %cl
0x0040852e:	xorl %eax, 0x420018
0x00408534:	popl %ebp
0x00408535:	ret

0x0040a821:	popl %ecx
0x0040a822:	xchgl (%ebx), %eax
0x0040a824:	movl %eax, %esi
0x0040a826:	jmp 0x0040a841
0x0040a860:	movl %esi, %eax
0x0040a862:	addl %esp, $0x10<UINT8>
0x0040a865:	testl %esi, %esi
0x0040a867:	je 15
0x0040a869:	pushl 0x8(%ebp)
0x0040a86c:	movl %ecx, %esi
0x0040a86e:	call 0x00408ba6
0x00408ba6:	jmp 0x00408960
0x00408960:	ret

0x0040a873:	call FlsAlloc@kernel32.dll
FlsAlloc@kernel32.dll: API Node	
0x0040a875:	popl %esi
0x0040a876:	popl %ebp
0x0040a877:	ret

0x00409861:	movl 0x420030, %eax
0x00409866:	popl %ecx
0x00409867:	cmpl %eax, $0xffffffff<UINT8>
0x0040986a:	jne 0x0040986f
0x0040986f:	pushl $0x420c04<UINT32>
0x00409874:	pushl %eax
0x00409875:	call 0x0040a8f4
0x0040a8f4:	pushl %ebp
0x0040a8f5:	movl %ebp, %esp
0x0040a8f7:	pushl %esi
0x0040a8f8:	pushl $0x402468<UINT32>
0x0040a8fd:	pushl $0x402460<UINT32>
0x0040a902:	pushl $0x402468<UINT32>
0x0040a907:	pushl $0x3<UINT8>
0x0040a909:	call 0x0040a7c6
0x0040a721:	cmpl %esi, $0xffffffff<UINT8>
0x0040a724:	je 0x0040a7ad
0x0040a72a:	jmp 0x0040a7a9
0x0040a90e:	addl %esp, $0x10<UINT8>
0x0040a911:	movl %esi, %eax
0x0040a913:	pushl 0xc(%ebp)
0x0040a916:	pushl 0x8(%ebp)
0x0040a919:	testl %esi, %esi
0x0040a91b:	je 11
0x0040a91d:	movl %ecx, %esi
0x0040a91f:	call 0x00408ba6
0x0040a924:	call FlsSetValue@kernel32.dll
FlsSetValue@kernel32.dll: API Node	
0x0040a926:	jmp 0x0040a92e
0x0040a92e:	popl %esi
0x0040a92f:	popl %ebp
0x0040a930:	ret

0x0040987a:	popl %ecx
0x0040987b:	popl %ecx
0x0040987c:	testl %eax, %eax
0x0040987e:	jne 0x00409887
0x00409887:	movb %al, $0x1<UINT8>
0x00409889:	ret

0x00409417:	testb %al, %al
0x00409419:	jne 0x00409422
0x00409422:	movb %al, $0x1<UINT8>
0x00409424:	ret

0x004085c9:	testb %al, %al
0x004085cb:	jne 0x004085d1
0x004085d1:	call 0x0040e423
0x0040e423:	pushl $0x402e48<UINT32>
0x0040e428:	pushl $0x402dd0<UINT32>
0x0040e42d:	call 0x0041309c
0x0041309c:	movl %edi, %edi
0x0041309e:	pushl %ebp
0x0041309f:	movl %ebp, %esp
0x004130a1:	pushl %ecx
0x004130a2:	movl %eax, 0x420018
0x004130a7:	xorl %eax, %ebp
0x004130a9:	movl -4(%ebp), %eax
0x004130ac:	pushl %edi
0x004130ad:	movl %edi, 0x8(%ebp)
0x004130b0:	cmpl %edi, 0xc(%ebp)
0x004130b3:	jne 0x004130b9
0x004130b9:	pushl %esi
0x004130ba:	movl %esi, %edi
0x004130bc:	pushl %ebx
0x004130bd:	movl %ebx, (%esi)
0x004130bf:	testl %ebx, %ebx
0x004130c1:	je 0x004130d1
0x004130c3:	movl %ecx, %ebx
0x004130c5:	call 0x00408960
0x004130cb:	call 0x0040e341
0x0040e32f:	pushl $0x420140<UINT32>
0x0040e334:	movl %ecx, $0x421210<UINT32>
0x0040e339:	call 0x0040d432
0x0040d432:	movl %edi, %edi
0x0040d434:	pushl %ebp
0x0040d435:	movl %ebp, %esp
0x0040d437:	leal %eax, 0x4(%ecx)
0x0040d43a:	movl %edx, %eax
0x0040d43c:	subl %edx, %ecx
0x0040d43e:	addl %edx, $0x3<UINT8>
0x0040d441:	pushl %esi
0x0040d442:	xorl %esi, %esi
0x0040d444:	shrl %edx, $0x2<UINT8>
0x0040d447:	cmpl %eax, %ecx
0x0040d449:	sbbl %eax, %eax
0x0040d44b:	notl %eax
0x0040d44d:	andl %eax, %edx
0x0040d44f:	je 13
0x0040d451:	movl %edx, 0x8(%ebp)
0x0040d454:	incl %esi
0x0040d455:	movl (%ecx), %edx
0x0040d457:	leal %ecx, 0x4(%ecx)
0x0040d45a:	cmpl %esi, %eax
0x0040d45c:	jne -10
0x0040d45e:	popl %esi
0x0040d45f:	popl %ebp
0x0040d460:	ret $0x4<UINT16>

0x0040e33e:	movb %al, $0x1<UINT8>
0x0040e340:	ret

0x004130cd:	testb %al, %al
0x004130cf:	je 8
0x004130d1:	addl %esi, $0x8<UINT8>
0x004130d4:	cmpl %esi, 0xc(%ebp)
0x004130d7:	jne 0x004130bd
0x0040e366:	movl %eax, 0x420018
0x0040e36b:	pushl %esi
0x0040e36c:	pushl $0x20<UINT8>
0x0040e36e:	andl %eax, $0x1f<UINT8>
0x0040e371:	xorl %esi, %esi
0x0040e373:	popl %ecx
0x0040e374:	subl %ecx, %eax
0x0040e376:	rorl %esi, %cl
0x0040e378:	xorl %esi, 0x420018
0x0040e37e:	pushl %esi
0x0040e37f:	call 0x0040efaf
0x0040efaf:	movl %edi, %edi
0x0040efb1:	pushl %ebp
0x0040efb2:	movl %ebp, %esp
0x0040efb4:	pushl 0x8(%ebp)
0x0040efb7:	movl %ecx, $0x420f24<UINT32>
0x0040efbc:	call 0x0040d432
0x0040efc1:	popl %ebp
0x0040efc2:	ret

0x0040e384:	pushl %esi
0x0040e385:	call 0x0041316c
0x0041316c:	movl %edi, %edi
0x0041316e:	pushl %ebp
0x0041316f:	movl %ebp, %esp
0x00413171:	pushl 0x8(%ebp)
0x00413174:	movl %ecx, $0x421384<UINT32>
0x00413179:	call 0x0040d432
0x0041317e:	popl %ebp
0x0041317f:	ret

0x0040e38a:	pushl %esi
0x0040e38b:	call 0x00413319
0x00413319:	movl %edi, %edi
0x0041331b:	pushl %ebp
0x0041331c:	movl %ebp, %esp
0x0041331e:	pushl 0x8(%ebp)
0x00413321:	movl %ecx, $0x421388<UINT32>
0x00413326:	call 0x0040d432
0x0041332b:	pushl 0x8(%ebp)
0x0041332e:	movl %ecx, $0x42138c<UINT32>
0x00413333:	call 0x0040d432
0x00413338:	pushl 0x8(%ebp)
0x0041333b:	movl %ecx, $0x421390<UINT32>
0x00413340:	call 0x0040d432
0x00413345:	pushl 0x8(%ebp)
0x00413348:	movl %ecx, $0x421394<UINT32>
0x0041334d:	call 0x0040d432
0x00413352:	popl %ebp
0x00413353:	ret

0x0040e390:	pushl %esi
0x0040e391:	call 0x0040d47c
0x0040d47c:	movl %edi, %edi
0x0040d47e:	pushl %ebp
0x0040d47f:	movl %ebp, %esp
0x0040d481:	pushl 0x8(%ebp)
0x0040d484:	movl %ecx, $0x420cbc<UINT32>
0x0040d489:	call 0x0040d432
0x0040d48e:	popl %ebp
0x0040d48f:	ret

0x0040e396:	pushl %esi
0x0040e397:	call 0x0040dd5b
0x0040dd5b:	movl %edi, %edi
0x0040dd5d:	pushl %ebp
0x0040dd5e:	movl %ebp, %esp
0x0040dd60:	movl %eax, 0x8(%ebp)
0x0040dd63:	movl 0x420ee0, %eax
0x0040dd68:	popl %ebp
0x0040dd69:	ret

0x0040e39c:	addl %esp, $0x14<UINT8>
0x0040e39f:	movb %al, $0x1<UINT8>
0x0040e3a1:	popl %esi
0x0040e3a2:	ret

0x0040f553:	movl %eax, 0x420018
0x0040f558:	pushl %edi
0x0040f559:	pushl $0x20<UINT8>
0x0040f55b:	andl %eax, $0x1f<UINT8>
0x0040f55e:	movl %edi, $0x420f78<UINT32>
0x0040f563:	popl %ecx
0x0040f564:	subl %ecx, %eax
0x0040f566:	xorl %eax, %eax
0x0040f568:	rorl %eax, %cl
0x0040f56a:	xorl %eax, 0x420018
0x0040f570:	pushl $0x20<UINT8>
0x0040f572:	popl %ecx
0x0040f573:	rep stosl %es:(%edi), %eax
0x0040f575:	movb %al, $0x1<UINT8>
0x0040f577:	popl %edi
0x0040f578:	ret

0x0040e363:	movb %al, $0x1<UINT8>
0x0040e365:	ret

0x00412521:	movl %edi, %edi
0x00412523:	pushl %esi
0x00412524:	pushl %edi
0x00412525:	movl %edi, $0x421238<UINT32>
0x0041252a:	xorl %esi, %esi
0x0041252c:	pushl $0x0<UINT8>
0x0041252e:	pushl $0xfa0<UINT32>
0x00412533:	pushl %edi
0x00412534:	call 0x0040f40d
0x0040f40d:	movl %edi, %edi
0x0040f40f:	pushl %ebp
0x0040f410:	movl %ebp, %esp
0x0040f412:	pushl %ecx
0x0040f413:	movl %eax, 0x420018
0x0040f418:	xorl %eax, %ebp
0x0040f41a:	movl -4(%ebp), %eax
0x0040f41d:	pushl %esi
0x0040f41e:	pushl $0x4034c0<UINT32>
0x0040f423:	pushl $0x4034b8<UINT32>
0x0040f428:	pushl $0x40247c<UINT32>
0x0040f42d:	pushl $0x14<UINT8>
0x0040f42f:	call 0x0040f127
0x0040f127:	movl %edi, %edi
0x0040f129:	pushl %ebp
0x0040f12a:	movl %ebp, %esp
0x0040f12c:	movl %eax, 0x8(%ebp)
0x0040f12f:	pushl %ebx
0x0040f130:	pushl %esi
0x0040f131:	pushl %edi
0x0040f132:	leal %ebx, 0x420f78(,%eax,4)
0x0040f139:	movl %eax, (%ebx)
0x0040f13b:	movl %edx, 0x420018
0x0040f141:	orl %edi, $0xffffffff<UINT8>
0x0040f144:	movl %ecx, %edx
0x0040f146:	movl %esi, %edx
0x0040f148:	andl %ecx, $0x1f<UINT8>
0x0040f14b:	xorl %esi, %eax
0x0040f14d:	rorl %esi, %cl
0x0040f14f:	cmpl %esi, %edi
0x0040f151:	je 0x0040f1bc
0x0040f153:	testl %esi, %esi
0x0040f155:	je 0x0040f15b
0x0040f15b:	movl %esi, 0x10(%ebp)
0x0040f15e:	cmpl %esi, 0x14(%ebp)
0x0040f161:	je 26
0x0040f163:	pushl (%esi)
0x0040f165:	call 0x0040f1c3
0x0040f1c3:	movl %edi, %edi
0x0040f1c5:	pushl %ebp
0x0040f1c6:	movl %ebp, %esp
0x0040f1c8:	movl %eax, 0x8(%ebp)
0x0040f1cb:	pushl %edi
0x0040f1cc:	leal %edi, 0x420f28(,%eax,4)
0x0040f1d3:	movl %ecx, (%edi)
0x0040f1d5:	testl %ecx, %ecx
0x0040f1d7:	je 0x0040f1e4
0x0040f1e4:	pushl %ebx
0x0040f1e5:	movl %ebx, 0x402fb0(,%eax,4)
0x0040f1ec:	pushl %esi
0x0040f1ed:	pushl $0x800<UINT32>
0x0040f1f2:	pushl $0x0<UINT8>
0x0040f1f4:	pushl %ebx
0x0040f1f5:	call LoadLibraryExW@KERNEL32.dll
0x0040f1fb:	movl %esi, %eax
0x0040f1fd:	testl %esi, %esi
0x0040f1ff:	jne 0x0040f228
0x0040f228:	movl %eax, %esi
0x0040f22a:	xchgl (%edi), %eax
0x0040f22c:	testl %eax, %eax
0x0040f22e:	je 0x0040f237
0x0040f237:	movl %eax, %esi
0x0040f239:	popl %esi
0x0040f23a:	popl %ebx
0x0040f23b:	popl %edi
0x0040f23c:	popl %ebp
0x0040f23d:	ret

0x0040f16a:	popl %ecx
0x0040f16b:	testl %eax, %eax
0x0040f16d:	jne 0x0040f19e
0x0040f19e:	movl %edx, 0x420018
0x0040f1a4:	jmp 0x0040f17f
0x0040f17f:	testl %eax, %eax
0x0040f181:	je 41
0x0040f183:	pushl 0xc(%ebp)
0x0040f186:	pushl %eax
0x0040f187:	call GetProcAddress@KERNEL32.dll
0x0040f18d:	movl %esi, %eax
0x0040f18f:	testl %esi, %esi
0x0040f191:	je 0x0040f1a6
0x0040f1a6:	movl %edx, 0x420018
0x0040f1ac:	movl %eax, %edx
0x0040f1ae:	pushl $0x20<UINT8>
0x0040f1b0:	andl %eax, $0x1f<UINT8>
0x0040f1b3:	popl %ecx
0x0040f1b4:	subl %ecx, %eax
0x0040f1b6:	rorl %edi, %cl
0x0040f1b8:	xorl %edi, %edx
0x0040f1ba:	xchgl (%ebx), %edi
0x0040f1bc:	xorl %eax, %eax
0x0040f1be:	popl %edi
0x0040f1bf:	popl %esi
0x0040f1c0:	popl %ebx
0x0040f1c1:	popl %ebp
0x0040f1c2:	ret

0x0040f434:	movl %esi, %eax
0x0040f436:	addl %esp, $0x10<UINT8>
0x0040f439:	testl %esi, %esi
0x0040f43b:	je 0x0040f452
0x0040f452:	pushl 0xc(%ebp)
0x0040f455:	pushl 0x8(%ebp)
0x0040f458:	call InitializeCriticalSectionAndSpinCount@KERNEL32.dll
0x0040f45e:	movl %ecx, -4(%ebp)
0x0040f461:	xorl %ecx, %ebp
0x0040f463:	popl %esi
0x0040f464:	call 0x004087b1
0x004087b1:	cmpl %ecx, 0x420018
0x004087b7:	repn jne 2
0x004087ba:	repn ret

0x0040f469:	movl %esp, %ebp
0x0040f46b:	popl %ebp
0x0040f46c:	ret $0xc<UINT16>

0x00412539:	testl %eax, %eax
0x0041253b:	je 24
0x0041253d:	incl 0x421370
0x00412543:	addl %esi, $0x18<UINT8>
0x00412546:	addl %edi, $0x18<UINT8>
0x00412549:	cmpl %esi, $0x138<UINT32>
0x0041254f:	jb 0x0041252c
0x00412551:	movb %al, $0x1<UINT8>
0x00412553:	jmp 0x0041255f
0x0041255f:	popl %edi
0x00412560:	popl %esi
0x00412561:	ret

0x00413081:	call GetProcessHeap@KERNEL32.dll
GetProcessHeap@KERNEL32.dll: API Node	
0x00413087:	testl %eax, %eax
0x00413089:	movl 0x421380, %eax
0x0041308e:	setne %al
0x00413091:	ret

0x00410571:	pushl $0x410353<UINT32>
0x00410576:	call 0x0040f2b2
0x0040f2b2:	movl %edi, %edi
0x0040f2b4:	pushl %ebp
0x0040f2b5:	movl %ebp, %esp
0x0040f2b7:	pushl %ecx
0x0040f2b8:	movl %eax, 0x420018
0x0040f2bd:	xorl %eax, %ebp
0x0040f2bf:	movl -4(%ebp), %eax
0x0040f2c2:	pushl %esi
0x0040f2c3:	pushl $0x403484<UINT32>
0x0040f2c8:	pushl $0x40347c<UINT32>
0x0040f2cd:	pushl $0x402430<UINT32>
0x0040f2d2:	pushl $0x3<UINT8>
0x0040f2d4:	call 0x0040f127
0x0040f201:	call GetLastError@KERNEL32.dll
0x0040f207:	cmpl %eax, $0x57<UINT8>
0x0040f20a:	jne 0x0040f219
0x0040f219:	xorl %esi, %esi
0x0040f21b:	testl %esi, %esi
0x0040f21d:	jne 9
0x0040f21f:	orl %eax, $0xffffffff<UINT8>
0x0040f222:	xchgl (%edi), %eax
0x0040f224:	xorl %eax, %eax
0x0040f226:	jmp 0x0040f239
0x0040f16f:	addl %esi, $0x4<UINT8>
0x0040f172:	cmpl %esi, 0x14(%ebp)
0x0040f175:	jne 0x0040f163
0x0040f193:	pushl %esi
0x0040f194:	call 0x00408519
0x0040f199:	popl %ecx
0x0040f19a:	xchgl (%ebx), %eax
0x0040f19c:	jmp 0x0040f157
0x0040f157:	movl %eax, %esi
0x0040f159:	jmp 0x0040f1be
0x0040f2d9:	movl %esi, %eax
0x0040f2db:	addl %esp, $0x10<UINT8>
0x0040f2de:	testl %esi, %esi
0x0040f2e0:	je 15
0x0040f2e2:	pushl 0x8(%ebp)
0x0040f2e5:	movl %ecx, %esi
0x0040f2e7:	call 0x00408960
0x0040f2ed:	call FlsAlloc@kernel32.dll
0x0040f2ef:	jmp 0x0040f2f7
0x0040f2f7:	movl %ecx, -4(%ebp)
0x0040f2fa:	xorl %ecx, %ebp
0x0040f2fc:	popl %esi
0x0040f2fd:	call 0x004087b1
0x0040f302:	movl %esp, %ebp
0x0040f304:	popl %ebp
0x0040f305:	ret $0x4<UINT16>

0x0041057b:	movl 0x420138, %eax
0x00410580:	cmpl %eax, $0xffffffff<UINT8>
0x00410583:	jne 0x00410588
0x00410588:	call 0x004104ec
0x004104ec:	movl %edi, %edi
0x004104ee:	pushl %ebx
0x004104ef:	pushl %esi
0x004104f0:	pushl %edi
0x004104f1:	call GetLastError@KERNEL32.dll
0x004104f7:	movl %esi, %eax
0x004104f9:	xorl %ebx, %ebx
0x004104fb:	movl %eax, 0x420138
0x00410500:	cmpl %eax, $0xffffffff<UINT8>
0x00410503:	je 12
0x00410505:	pushl %eax
0x00410506:	call 0x0040f35e
0x0040f35e:	movl %edi, %edi
0x0040f360:	pushl %ebp
0x0040f361:	movl %ebp, %esp
0x0040f363:	pushl %ecx
0x0040f364:	movl %eax, 0x420018
0x0040f369:	xorl %eax, %ebp
0x0040f36b:	movl -4(%ebp), %eax
0x0040f36e:	pushl %esi
0x0040f36f:	pushl $0x403494<UINT32>
0x0040f374:	pushl $0x40348c<UINT32>
0x0040f379:	pushl $0x402454<UINT32>
0x0040f37e:	pushl $0x5<UINT8>
0x0040f380:	call 0x0040f127
0x0040f1d9:	leal %eax, 0x1(%ecx)
0x0040f1dc:	negl %eax
0x0040f1de:	sbbl %eax, %eax
0x0040f1e0:	andl %eax, %ecx
0x0040f1e2:	jmp 0x0040f23b
0x0040f385:	addl %esp, $0x10<UINT8>
0x0040f388:	movl %esi, %eax
0x0040f38a:	pushl 0x8(%ebp)
0x0040f38d:	testl %esi, %esi
0x0040f38f:	je 12
0x0040f391:	movl %ecx, %esi
0x0040f393:	call 0x00408960
0x0040f399:	call FlsGetValue@kernel32.dll
FlsGetValue@kernel32.dll: API Node	
0x0040f39b:	jmp 0x0040f3a3
0x0040f3a3:	movl %ecx, -4(%ebp)
0x0040f3a6:	xorl %ecx, %ebp
0x0040f3a8:	popl %esi
0x0040f3a9:	call 0x004087b1
0x0040f3ae:	movl %esp, %ebp
0x0040f3b0:	popl %ebp
0x0040f3b1:	ret $0x4<UINT16>

0x0041050b:	movl %edi, %eax
0x0041050d:	testl %edi, %edi
0x0041050f:	jne 0x00410562
0x00410511:	pushl $0x364<UINT32>
0x00410516:	pushl $0x1<UINT8>
0x00410518:	call 0x0040e607
0x0040e607:	movl %edi, %edi
0x0040e609:	pushl %ebp
0x0040e60a:	movl %ebp, %esp
0x0040e60c:	pushl %esi
0x0040e60d:	movl %esi, 0x8(%ebp)
0x0040e610:	testl %esi, %esi
0x0040e612:	je 12
0x0040e614:	pushl $0xffffffe0<UINT8>
0x0040e616:	xorl %edx, %edx
0x0040e618:	popl %eax
0x0040e619:	divl %eax, %esi
0x0040e61b:	cmpl %eax, 0xc(%ebp)
0x0040e61e:	jb 52
0x0040e620:	imull %esi, 0xc(%ebp)
0x0040e624:	testl %esi, %esi
0x0040e626:	jne 0x0040e63f
0x0040e63f:	pushl %esi
0x0040e640:	pushl $0x8<UINT8>
0x0040e642:	pushl 0x421380
0x0040e648:	call HeapAlloc@KERNEL32.dll
HeapAlloc@KERNEL32.dll: API Node	
0x0040e64e:	testl %eax, %eax
0x0040e650:	je -39
0x0040e652:	jmp 0x0040e661
0x0040e661:	popl %esi
0x0040e662:	popl %ebp
0x0040e663:	ret

0x0041051d:	movl %edi, %eax
0x0041051f:	popl %ecx
0x00410520:	popl %ecx
0x00410521:	testl %edi, %edi
0x00410523:	jne 0x0041052e
0x0041052e:	pushl %edi
0x0041052f:	pushl 0x420138
0x00410535:	call 0x0040f3b4
0x0040f3b4:	movl %edi, %edi
0x0040f3b6:	pushl %ebp
0x0040f3b7:	movl %ebp, %esp
0x0040f3b9:	pushl %ecx
0x0040f3ba:	movl %eax, 0x420018
0x0040f3bf:	xorl %eax, %ebp
0x0040f3c1:	movl -4(%ebp), %eax
0x0040f3c4:	pushl %esi
0x0040f3c5:	pushl $0x40349c<UINT32>
0x0040f3ca:	pushl $0x403494<UINT32>
0x0040f3cf:	pushl $0x402468<UINT32>
0x0040f3d4:	pushl $0x6<UINT8>
0x0040f3d6:	call 0x0040f127
0x0040f3db:	addl %esp, $0x10<UINT8>
0x0040f3de:	movl %esi, %eax
0x0040f3e0:	pushl 0xc(%ebp)
0x0040f3e3:	pushl 0x8(%ebp)
0x0040f3e6:	testl %esi, %esi
0x0040f3e8:	je 12
0x0040f3ea:	movl %ecx, %esi
0x0040f3ec:	call 0x00408960
0x0040f3f2:	call FlsSetValue@kernel32.dll
0x0040f3f4:	jmp 0x0040f3fc
0x0040f3fc:	movl %ecx, -4(%ebp)
0x0040f3ff:	xorl %ecx, %ebp
0x0040f401:	popl %esi
0x0040f402:	call 0x004087b1
0x0040f407:	movl %esp, %ebp
0x0040f409:	popl %ebp
0x0040f40a:	ret $0x8<UINT16>

0x0041053a:	testl %eax, %eax
0x0041053c:	jne 0x00410541
0x00410541:	pushl $0x421210<UINT32>
0x00410546:	pushl %edi
0x00410547:	call 0x004102da
0x004102da:	movl %edi, %edi
0x004102dc:	pushl %ebp
0x004102dd:	movl %ebp, %esp
0x004102df:	pushl %ecx
0x004102e0:	pushl %ecx
0x004102e1:	movl %eax, 0x8(%ebp)
0x004102e4:	xorl %ecx, %ecx
0x004102e6:	incl %ecx
0x004102e7:	pushl $0x43<UINT8>
0x004102e9:	movl 0x18(%eax), %ecx
0x004102ec:	movl %eax, 0x8(%ebp)
0x004102ef:	movl (%eax), $0x402d08<UINT32>
0x004102f5:	movl %eax, 0x8(%ebp)
0x004102f8:	movl 0x350(%eax), %ecx
0x004102fe:	movl %eax, 0x8(%ebp)
0x00410301:	popl %ecx
0x00410302:	movl 0x48(%eax), $0x420500<UINT32>
0x00410309:	movl %eax, 0x8(%ebp)
0x0041030c:	movw 0x6c(%eax), %cx
0x00410310:	movl %eax, 0x8(%ebp)
0x00410313:	movw 0x172(%eax), %cx
0x0041031a:	movl %eax, 0x8(%ebp)
0x0041031d:	andl 0x34c(%eax), $0x0<UINT8>
0x00410324:	leal %eax, 0x8(%ebp)
0x00410327:	movl -4(%ebp), %eax
0x0041032a:	leal %eax, -4(%ebp)
0x0041032d:	pushl %eax
0x0041032e:	pushl $0x5<UINT8>
0x00410330:	call 0x004102b2
0x004102b2:	movl %edi, %edi
0x004102b4:	pushl %ebp
0x004102b5:	movl %ebp, %esp
0x004102b7:	subl %esp, $0xc<UINT8>
0x004102ba:	movl %eax, 0x8(%ebp)
0x004102bd:	leal %ecx, -1(%ebp)
0x004102c0:	movl -8(%ebp), %eax
0x004102c3:	movl -12(%ebp), %eax
0x004102c6:	leal %eax, -8(%ebp)
0x004102c9:	pushl %eax
0x004102ca:	pushl 0xc(%ebp)
0x004102cd:	leal %eax, -12(%ebp)
0x004102d0:	pushl %eax
0x004102d1:	call 0x004101f2
0x004101f2:	pushl $0x8<UINT8>
0x004101f4:	pushl $0x41ed30<UINT32>
0x004101f9:	call 0x004084b0
0x004101fe:	movl %eax, 0x8(%ebp)
0x00410201:	pushl (%eax)
0x00410203:	call 0x00412562
0x00412562:	movl %edi, %edi
0x00412564:	pushl %ebp
0x00412565:	movl %ebp, %esp
0x00412567:	imull %eax, 0x8(%ebp), $0x18<UINT8>
0x0041256b:	addl %eax, $0x421238<UINT32>
0x00412570:	pushl %eax
0x00412571:	call EnterCriticalSection@KERNEL32.dll
EnterCriticalSection@KERNEL32.dll: API Node	
0x00412577:	popl %ebp
0x00412578:	ret

0x00410208:	popl %ecx
0x00410209:	andl -4(%ebp), $0x0<UINT8>
0x0041020d:	movl %eax, 0xc(%ebp)
0x00410210:	movl %eax, (%eax)
0x00410212:	movl %eax, (%eax)
0x00410214:	movl %eax, 0x48(%eax)
0x00410217:	incl (%eax)
0x0041021a:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00410221:	call 0x0041022e
0x0041022e:	movl %eax, 0x10(%ebp)
0x00410231:	pushl (%eax)
0x00410233:	call 0x004125aa
0x004125aa:	movl %edi, %edi
0x004125ac:	pushl %ebp
0x004125ad:	movl %ebp, %esp
0x004125af:	imull %eax, 0x8(%ebp), $0x18<UINT8>
0x004125b3:	addl %eax, $0x421238<UINT32>
0x004125b8:	pushl %eax
0x004125b9:	call LeaveCriticalSection@KERNEL32.dll
LeaveCriticalSection@KERNEL32.dll: API Node	
0x004125bf:	popl %ebp
0x004125c0:	ret

0x00410238:	popl %ecx
0x00410239:	ret

0x00410226:	call 0x004084f6
0x004084f6:	movl %ecx, -16(%ebp)
0x004084f9:	movl %fs:0, %ecx
0x00408500:	popl %ecx
0x00408501:	popl %edi
0x00408502:	popl %edi
0x00408503:	popl %esi
0x00408504:	popl %ebx
0x00408505:	movl %esp, %ebp
0x00408507:	popl %ebp
0x00408508:	pushl %ecx
0x00408509:	repn ret

0x0041022b:	ret $0xc<UINT16>

0x004102d6:	movl %esp, %ebp
0x004102d8:	popl %ebp
0x004102d9:	ret

0x00410335:	leal %eax, 0x8(%ebp)
0x00410338:	movl -8(%ebp), %eax
0x0041033b:	leal %eax, 0xc(%ebp)
0x0041033e:	movl -4(%ebp), %eax
0x00410341:	leal %eax, -8(%ebp)
0x00410344:	pushl %eax
0x00410345:	pushl $0x4<UINT8>
0x00410347:	call 0x00410262
0x00410262:	movl %edi, %edi
0x00410264:	pushl %ebp
0x00410265:	movl %ebp, %esp
0x00410267:	subl %esp, $0xc<UINT8>
0x0041026a:	movl %eax, 0x8(%ebp)
0x0041026d:	leal %ecx, -1(%ebp)
0x00410270:	movl -8(%ebp), %eax
0x00410273:	movl -12(%ebp), %eax
0x00410276:	leal %eax, -8(%ebp)
0x00410279:	pushl %eax
0x0041027a:	pushl 0xc(%ebp)
0x0041027d:	leal %eax, -12(%ebp)
0x00410280:	pushl %eax
0x00410281:	call 0x004100f6
0x004100f6:	pushl $0x8<UINT8>
0x004100f8:	pushl $0x41ed50<UINT32>
0x004100fd:	call 0x004084b0
0x00410102:	movl %eax, 0x8(%ebp)
0x00410105:	pushl (%eax)
0x00410107:	call 0x00412562
0x0041010c:	popl %ecx
0x0041010d:	andl -4(%ebp), $0x0<UINT8>
0x00410111:	movl %ecx, 0xc(%ebp)
0x00410114:	movl %eax, 0x4(%ecx)
0x00410117:	movl %eax, (%eax)
0x00410119:	pushl (%eax)
0x0041011b:	movl %eax, (%ecx)
0x0041011d:	pushl (%eax)
0x0041011f:	call 0x0041041d
0x0041041d:	movl %edi, %edi
0x0041041f:	pushl %ebp
0x00410420:	movl %ebp, %esp
0x00410422:	pushl %esi
0x00410423:	movl %esi, 0x8(%ebp)
0x00410426:	cmpl 0x4c(%esi), $0x0<UINT8>
0x0041042a:	je 0x00410454
0x00410454:	movl %eax, 0xc(%ebp)
0x00410457:	movl 0x4c(%esi), %eax
0x0041045a:	popl %esi
0x0041045b:	testl %eax, %eax
0x0041045d:	je 7
0x0041045f:	pushl %eax
0x00410460:	call 0x00412c78
0x00412c78:	movl %edi, %edi
0x00412c7a:	pushl %ebp
0x00412c7b:	movl %ebp, %esp
0x00412c7d:	movl %eax, 0x8(%ebp)
0x00412c80:	incl 0xc(%eax)
0x00412c84:	movl %ecx, 0x7c(%eax)
0x00412c87:	testl %ecx, %ecx
0x00412c89:	je 0x00412c8e
0x00412c8e:	movl %ecx, 0x84(%eax)
0x00412c94:	testl %ecx, %ecx
0x00412c96:	je 0x00412c9b
0x00412c9b:	movl %ecx, 0x80(%eax)
0x00412ca1:	testl %ecx, %ecx
0x00412ca3:	je 0x00412ca8
0x00412ca8:	movl %ecx, 0x8c(%eax)
0x00412cae:	testl %ecx, %ecx
0x00412cb0:	je 0x00412cb5
0x00412cb5:	pushl %esi
0x00412cb6:	pushl $0x6<UINT8>
0x00412cb8:	leal %ecx, 0x28(%eax)
0x00412cbb:	popl %esi
0x00412cbc:	cmpl -8(%ecx), $0x420200<UINT32>
0x00412cc3:	je 0x00412cce
0x00412cc5:	movl %edx, (%ecx)
0x00412cc7:	testl %edx, %edx
0x00412cc9:	je 0x00412cce
0x00412cce:	cmpl -12(%ecx), $0x0<UINT8>
0x00412cd2:	je 0x00412cde
0x00412cde:	addl %ecx, $0x10<UINT8>
0x00412ce1:	subl %esi, $0x1<UINT8>
0x00412ce4:	jne 0x00412cbc
0x00412ce6:	pushl 0x9c(%eax)
0x00412cec:	call 0x00412e3f
0x00412e3f:	movl %edi, %edi
0x00412e41:	pushl %ebp
0x00412e42:	movl %ebp, %esp
0x00412e44:	movl %ecx, 0x8(%ebp)
0x00412e47:	testl %ecx, %ecx
0x00412e49:	je 22
0x00412e4b:	cmpl %ecx, $0x403890<UINT32>
0x00412e51:	je 0x00412e61
0x00412e61:	movl %eax, $0x7fffffff<UINT32>
0x00412e66:	popl %ebp
0x00412e67:	ret

0x00412cf1:	popl %ecx
0x00412cf2:	popl %esi
0x00412cf3:	popl %ebp
0x00412cf4:	ret

0x00410465:	popl %ecx
0x00410466:	popl %ebp
0x00410467:	ret

0x00410124:	popl %ecx
0x00410125:	popl %ecx
0x00410126:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0041012d:	call 0x0041013a
0x0041013a:	movl %eax, 0x10(%ebp)
0x0041013d:	pushl (%eax)
0x0041013f:	call 0x004125aa
0x00410144:	popl %ecx
0x00410145:	ret

0x00410132:	call 0x004084f6
0x00410137:	ret $0xc<UINT16>

0x00410286:	movl %esp, %ebp
0x00410288:	popl %ebp
0x00410289:	ret

0x0041034c:	addl %esp, $0x10<UINT8>
0x0041034f:	movl %esp, %ebp
0x00410351:	popl %ebp
0x00410352:	ret

0x0041054c:	pushl %ebx
0x0041054d:	call 0x0040e4e2
0x0040e4e2:	movl %edi, %edi
0x0040e4e4:	pushl %ebp
0x0040e4e5:	movl %ebp, %esp
0x0040e4e7:	cmpl 0x8(%ebp), $0x0<UINT8>
0x0040e4eb:	je 0x0040e51a
0x0040e51a:	popl %ebp
0x0040e51b:	ret

0x00410552:	addl %esp, $0xc<UINT8>
0x00410555:	testl %edi, %edi
0x00410557:	jne 0x00410562
0x00410562:	pushl %esi
0x00410563:	call SetLastError@KERNEL32.dll
SetLastError@KERNEL32.dll: API Node	
0x00410569:	movl %ebx, %edi
0x0041056b:	popl %edi
0x0041056c:	popl %esi
0x0041056d:	movl %eax, %ebx
0x0041056f:	popl %ebx
0x00410570:	ret

0x0041058d:	testl %eax, %eax
0x0041058f:	jne 0x0041059a
0x0041059a:	movb %al, $0x1<UINT8>
0x0041059c:	ret

0x0040fa0e:	pushl $0xc<UINT8>
0x0040fa10:	pushl $0x41ed10<UINT32>
0x0040fa15:	call 0x004084b0
0x0040fa1a:	pushl $0x7<UINT8>
0x0040fa1c:	call 0x00412562
0x0040fa21:	popl %ecx
0x0040fa22:	xorl %ebx, %ebx
0x0040fa24:	movb -25(%ebp), %bl
0x0040fa27:	movl -4(%ebp), %ebx
0x0040fa2a:	pushl %ebx
0x0040fa2b:	call 0x00412670
0x00412670:	pushl $0x14<UINT8>
0x00412672:	pushl $0x41edf0<UINT32>
0x00412677:	call 0x004084b0
0x0041267c:	cmpl 0x8(%ebp), $0x2000<UINT32>
0x00412683:	sbbl %eax, %eax
0x00412685:	negl %eax
0x00412687:	jne 0x004126a0
0x004126a0:	xorl %esi, %esi
0x004126a2:	movl -28(%ebp), %esi
0x004126a5:	pushl $0x7<UINT8>
0x004126a7:	call 0x00412562
0x004126ac:	popl %ecx
0x004126ad:	movl -4(%ebp), %esi
0x004126b0:	movl %edi, %esi
0x004126b2:	movl %eax, 0x421200
0x004126b7:	movl -32(%ebp), %edi
0x004126ba:	cmpl 0x8(%ebp), %eax
0x004126bd:	jl 0x004126de
0x004126bf:	cmpl 0x421000(,%edi,4), %esi
0x004126c6:	jne 49
0x004126c8:	call 0x004125c1
0x004125c1:	movl %edi, %edi
0x004125c3:	pushl %ebp
0x004125c4:	movl %ebp, %esp
0x004125c6:	pushl %ecx
0x004125c7:	pushl %ecx
0x004125c8:	pushl %ebx
0x004125c9:	pushl %edi
0x004125ca:	pushl $0x30<UINT8>
0x004125cc:	pushl $0x40<UINT8>
0x004125ce:	call 0x0040e607
0x004125d3:	movl %edi, %eax
0x004125d5:	xorl %ebx, %ebx
0x004125d7:	movl -8(%ebp), %edi
0x004125da:	popl %ecx
0x004125db:	popl %ecx
0x004125dc:	testl %edi, %edi
0x004125de:	jne 0x004125e4
0x004125e4:	leal %eax, 0xc00(%edi)
0x004125ea:	cmpl %edi, %eax
0x004125ec:	je 62
0x004125ee:	pushl %esi
0x004125ef:	leal %esi, 0x20(%edi)
0x004125f2:	movl %edi, %eax
0x004125f4:	pushl %ebx
0x004125f5:	pushl $0xfa0<UINT32>
0x004125fa:	leal %eax, -32(%esi)
0x004125fd:	pushl %eax
0x004125fe:	call 0x0040f40d
0x00412603:	orl -8(%esi), $0xffffffff<UINT8>
0x00412607:	movl (%esi), %ebx
0x00412609:	leal %esi, 0x30(%esi)
0x0041260c:	movl -44(%esi), %ebx
0x0041260f:	leal %eax, -32(%esi)
0x00412612:	movl -40(%esi), $0xa0a0000<UINT32>
0x00412619:	movb -36(%esi), $0xa<UINT8>
0x0041261d:	andb -35(%esi), $0xfffffff8<UINT8>
0x00412621:	movb -34(%esi), %bl
0x00412624:	cmpl %eax, %edi
0x00412626:	jne 0x004125f4
0x00412628:	movl %edi, -8(%ebp)
0x0041262b:	popl %esi
0x0041262c:	pushl %ebx
0x0041262d:	call 0x0040e4e2
0x00412632:	popl %ecx
0x00412633:	movl %eax, %edi
0x00412635:	popl %edi
0x00412636:	popl %ebx
0x00412637:	movl %esp, %ebp
0x00412639:	popl %ebp
0x0041263a:	ret

0x004126cd:	movl 0x421000(,%edi,4), %eax
0x004126d4:	testl %eax, %eax
0x004126d6:	jne 0x004126ec
0x004126ec:	movl %eax, 0x421200
0x004126f1:	addl %eax, $0x40<UINT8>
0x004126f4:	movl 0x421200, %eax
0x004126f9:	incl %edi
0x004126fa:	jmp 0x004126b7
0x004126de:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004126e5:	call 0x004126ff
0x004126ff:	pushl $0x7<UINT8>
0x00412701:	call 0x004125aa
0x00412706:	popl %ecx
0x00412707:	ret

0x004126ea:	jmp 0x00412698
0x00412698:	movl %eax, %esi
0x0041269a:	call 0x004084f6
0x0041269f:	ret

0x0040fa30:	popl %ecx
0x0040fa31:	testl %eax, %eax
0x0040fa33:	jne 15
0x0040fa35:	call 0x0040f8a2
0x0040f8a2:	movl %edi, %edi
0x0040f8a4:	pushl %ebp
0x0040f8a5:	movl %ebp, %esp
0x0040f8a7:	subl %esp, $0x48<UINT8>
0x0040f8aa:	leal %eax, -72(%ebp)
0x0040f8ad:	pushl %eax
0x0040f8ae:	call GetStartupInfoW@KERNEL32.dll
GetStartupInfoW@KERNEL32.dll: API Node	
0x0040f8b4:	cmpw -22(%ebp), $0x0<UINT8>
0x0040f8b9:	je 149
0x0040f8bf:	movl %eax, -20(%ebp)
0x0040f8c2:	testl %eax, %eax
0x0040f8c4:	je 138
0x0040f8ca:	pushl %ebx
0x0040f8cb:	pushl %esi
0x0040f8cc:	movl %esi, (%eax)
0x0040f8ce:	leal %ebx, 0x4(%eax)
0x0040f8d1:	leal %eax, (%ebx,%esi)
0x0040f8d4:	movl -4(%ebp), %eax
0x0040f8d7:	movl %eax, $0x2000<UINT32>
0x0040f8dc:	cmpl %esi, %eax
0x0040f8de:	jl 0x0040f8e2
0x0040f8e2:	pushl %esi
0x0040f8e3:	call 0x00412670
0x0040f8e8:	movl %eax, 0x421200
0x0040f8ed:	popl %ecx
0x0040f8ee:	cmpl %esi, %eax
0x0040f8f0:	jle 0x0040f8f4
0x0040f8f4:	pushl %edi
0x0040f8f5:	xorl %edi, %edi
0x0040f8f7:	testl %esi, %esi
0x0040f8f9:	je 0x0040f951
0x0040f951:	popl %edi
0x0040f952:	popl %esi
0x0040f953:	popl %ebx
0x0040f954:	movl %esp, %ebp
0x0040f956:	popl %ebp
0x0040f957:	ret

0x0040fa3a:	call 0x0040f958
0x0040f958:	movl %edi, %edi
0x0040f95a:	pushl %ebx
0x0040f95b:	pushl %esi
0x0040f95c:	pushl %edi
0x0040f95d:	xorl %edi, %edi
0x0040f95f:	movl %eax, %edi
0x0040f961:	movl %ecx, %edi
0x0040f963:	andl %eax, $0x3f<UINT8>
0x0040f966:	sarl %ecx, $0x6<UINT8>
0x0040f969:	imull %esi, %eax, $0x30<UINT8>
0x0040f96c:	addl %esi, 0x421000(,%ecx,4)
0x0040f973:	cmpl 0x18(%esi), $0xffffffff<UINT8>
0x0040f977:	je 0x0040f985
0x0040f985:	movl %eax, %edi
0x0040f987:	movb 0x28(%esi), $0xffffff81<UINT8>
0x0040f98b:	subl %eax, $0x0<UINT8>
0x0040f98e:	je 0x0040f9a0
0x0040f9a0:	pushl $0xfffffff6<UINT8>
0x0040f9a2:	popl %eax
0x0040f9a3:	pushl %eax
0x0040f9a4:	call GetStdHandle@KERNEL32.dll
GetStdHandle@KERNEL32.dll: API Node	
0x0040f9aa:	movl %ebx, %eax
0x0040f9ac:	cmpl %ebx, $0xffffffff<UINT8>
0x0040f9af:	je 13
0x0040f9b1:	testl %ebx, %ebx
0x0040f9b3:	je 9
0x0040f9b5:	pushl %ebx
0x0040f9b6:	call GetFileType@KERNEL32.dll
GetFileType@KERNEL32.dll: API Node	
0x0040f9bc:	jmp 0x0040f9c0
0x0040f9c0:	testl %eax, %eax
0x0040f9c2:	je 30
0x0040f9c4:	andl %eax, $0xff<UINT32>
0x0040f9c9:	movl 0x18(%esi), %ebx
0x0040f9cc:	cmpl %eax, $0x2<UINT8>
0x0040f9cf:	jne 6
0x0040f9d1:	orb 0x28(%esi), $0x40<UINT8>
0x0040f9d5:	jmp 0x0040fa00
0x0040fa00:	incl %edi
0x0040fa01:	cmpl %edi, $0x3<UINT8>
0x0040fa04:	jne 0x0040f95f
0x0040f990:	subl %eax, $0x1<UINT8>
0x0040f993:	je 0x0040f99c
0x0040f99c:	pushl $0xfffffff5<UINT8>
0x0040f99e:	jmp 0x0040f9a2
0x0040f995:	pushl $0xfffffff4<UINT8>
0x0040f997:	subl %eax, $0x1<UINT8>
0x0040f99a:	jmp 0x0040f9a2
0x0040fa0a:	popl %edi
0x0040fa0b:	popl %esi
0x0040fa0c:	popl %ebx
0x0040fa0d:	ret

0x0040fa3f:	movb %bl, $0x1<UINT8>
0x0040fa41:	movb -25(%ebp), %bl
0x0040fa44:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040fa4b:	call 0x0040fa5b
0x0040fa5b:	pushl $0x7<UINT8>
0x0040fa5d:	call 0x004125aa
0x0040fa62:	popl %ecx
0x0040fa63:	ret

0x0040fa50:	movb %al, %bl
0x0040fa52:	call 0x004084f6
0x0040fa57:	ret

0x0040de29:	call GetCommandLineA@KERNEL32.dll
GetCommandLineA@KERNEL32.dll: API Node	
0x0040de2f:	movl 0x420ef4, %eax
0x0040de34:	call GetCommandLineW@KERNEL32.dll
GetCommandLineW@KERNEL32.dll: API Node	
0x0040de3a:	movl 0x420ef8, %eax
0x0040de3f:	movb %al, $0x1<UINT8>
0x0040de41:	ret

0x00411e0b:	cmpb 0x421230, $0x0<UINT8>
0x00411e12:	jne 0x00411e26
0x00411e14:	pushl $0x1<UINT8>
0x00411e16:	pushl $0xfffffffd<UINT8>
0x00411e18:	call 0x00411d0a
0x00411d0a:	movl %edi, %edi
0x00411d0c:	pushl %ebp
0x00411d0d:	movl %ebp, %esp
0x00411d0f:	subl %esp, $0xc<UINT8>
0x00411d12:	call 0x00410468
0x00410468:	movl %edi, %edi
0x0041046a:	pushl %esi
0x0041046b:	pushl %edi
0x0041046c:	call GetLastError@KERNEL32.dll
0x00410472:	movl %esi, %eax
0x00410474:	movl %eax, 0x420138
0x00410479:	cmpl %eax, $0xffffffff<UINT8>
0x0041047c:	je 12
0x0041047e:	pushl %eax
0x0041047f:	call 0x0040f35e
0x00410484:	movl %edi, %eax
0x00410486:	testl %edi, %edi
0x00410488:	jne 0x004104d3
0x004104d3:	pushl %esi
0x004104d4:	call SetLastError@KERNEL32.dll
0x004104da:	movl %eax, %edi
0x004104dc:	popl %edi
0x004104dd:	popl %esi
0x004104de:	ret

0x00411d17:	movl -4(%ebp), %eax
0x00411d1a:	call 0x00411e29
0x00411e29:	pushl $0xc<UINT8>
0x00411e2b:	pushl $0x41edb0<UINT32>
0x00411e30:	call 0x004084b0
0x00411e35:	xorl %esi, %esi
0x00411e37:	movl -28(%ebp), %esi
0x00411e3a:	call 0x00410468
0x00411e3f:	movl %edi, %eax
0x00411e41:	movl %ecx, 0x420780
0x00411e47:	testl 0x350(%edi), %ecx
0x00411e4d:	je 0x00411e60
0x00411e60:	pushl $0x5<UINT8>
0x00411e62:	call 0x00412562
0x00411e67:	popl %ecx
0x00411e68:	movl -4(%ebp), %esi
0x00411e6b:	movl %esi, 0x48(%edi)
0x00411e6e:	movl -28(%ebp), %esi
0x00411e71:	cmpl %esi, 0x420720
0x00411e77:	je 0x00411ea9
0x00411ea9:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00411eb0:	call 0x00411eba
0x00411eba:	pushl $0x5<UINT8>
0x00411ebc:	call 0x004125aa
0x00411ec1:	popl %ecx
0x00411ec2:	ret

0x00411eb5:	jmp 0x00411e57
0x00411e57:	testl %esi, %esi
0x00411e59:	jne 0x00411ec3
0x00411ec3:	movl %eax, %esi
0x00411ec5:	call 0x004084f6
0x00411eca:	ret

0x00411d1f:	pushl 0x8(%ebp)
0x00411d22:	call 0x00411a9e
0x00411a9e:	movl %edi, %edi
0x00411aa0:	pushl %ebp
0x00411aa1:	movl %ebp, %esp
0x00411aa3:	subl %esp, $0x10<UINT8>
0x00411aa6:	leal %ecx, -16(%ebp)
0x00411aa9:	pushl $0x0<UINT8>
0x00411aab:	call 0x0040ba34
0x0040ba34:	movl %edi, %edi
0x0040ba36:	pushl %ebp
0x0040ba37:	movl %ebp, %esp
0x0040ba39:	pushl %edi
0x0040ba3a:	movl %edi, %ecx
0x0040ba3c:	movl %ecx, 0x8(%ebp)
0x0040ba3f:	movb 0xc(%edi), $0x0<UINT8>
0x0040ba43:	testl %ecx, %ecx
0x0040ba45:	je 0x0040ba51
0x0040ba51:	movl %eax, 0x420f00
0x0040ba56:	testl %eax, %eax
0x0040ba58:	jne 18
0x0040ba5a:	movl %eax, 0x4201f8
0x0040ba5f:	movl 0x4(%edi), %eax
0x0040ba62:	movl %eax, 0x4201fc
0x0040ba67:	movl 0x8(%edi), %eax
0x0040ba6a:	jmp 0x0040bab0
0x0040bab0:	movl %eax, %edi
0x0040bab2:	popl %edi
0x0040bab3:	popl %ebp
0x0040bab4:	ret $0x4<UINT16>

0x00411ab0:	andl 0x42122c, $0x0<UINT8>
0x00411ab7:	movl %eax, 0x8(%ebp)
0x00411aba:	cmpl %eax, $0xfffffffe<UINT8>
0x00411abd:	jne 0x00411ad1
0x00411ad1:	cmpl %eax, $0xfffffffd<UINT8>
0x00411ad4:	jne 0x00411ae8
0x00411ad6:	movl 0x42122c, $0x1<UINT32>
0x00411ae0:	call GetACP@KERNEL32.dll
GetACP@KERNEL32.dll: API Node	
0x00411ae6:	jmp 0x00411afd
0x00411afd:	cmpb -4(%ebp), $0x0<UINT8>
0x00411b01:	je 0x00411b0d
0x00411b0d:	movl %esp, %ebp
0x00411b0f:	popl %ebp
0x00411b10:	ret

0x00411d27:	popl %ecx
0x00411d28:	movl %ecx, -4(%ebp)
0x00411d2b:	movl -12(%ebp), %eax
0x00411d2e:	movl %ecx, 0x48(%ecx)
0x00411d31:	cmpl %eax, 0x4(%ecx)
0x00411d34:	jne 0x00411d3a
0x00411d3a:	pushl %ebx
0x00411d3b:	pushl %esi
0x00411d3c:	pushl %edi
0x00411d3d:	pushl $0x220<UINT32>
0x00411d42:	call 0x0040e51c
0x0040e51c:	movl %edi, %edi
0x0040e51e:	pushl %ebp
0x0040e51f:	movl %ebp, %esp
0x0040e521:	pushl %esi
0x0040e522:	movl %esi, 0x8(%ebp)
0x0040e525:	cmpl %esi, $0xffffffe0<UINT8>
0x0040e528:	ja 48
0x0040e52a:	testl %esi, %esi
0x0040e52c:	jne 0x0040e545
0x0040e545:	pushl %esi
0x0040e546:	pushl $0x0<UINT8>
0x0040e548:	pushl 0x421380
0x0040e54e:	call HeapAlloc@KERNEL32.dll
0x0040e554:	testl %eax, %eax
0x0040e556:	je -39
0x0040e558:	jmp 0x0040e567
0x0040e567:	popl %esi
0x0040e568:	popl %ebp
0x0040e569:	ret

0x00411d47:	movl %edi, %eax
0x00411d49:	orl %ebx, $0xffffffff<UINT8>
0x00411d4c:	popl %ecx
0x00411d4d:	testl %edi, %edi
0x00411d4f:	je 46
0x00411d51:	movl %esi, -4(%ebp)
0x00411d54:	movl %ecx, $0x88<UINT32>
0x00411d59:	movl %esi, 0x48(%esi)
0x00411d5c:	rep movsl %es:(%edi), %ds:(%esi)
0x00411d5e:	movl %edi, %eax
0x00411d60:	pushl %edi
0x00411d61:	pushl -12(%ebp)
0x00411d64:	andl (%edi), $0x0<UINT8>
0x00411d67:	call 0x00411ecb
0x00411ecb:	movl %edi, %edi
0x00411ecd:	pushl %ebp
0x00411ece:	movl %ebp, %esp
0x00411ed0:	subl %esp, $0x20<UINT8>
0x00411ed3:	movl %eax, 0x420018
0x00411ed8:	xorl %eax, %ebp
0x00411eda:	movl -4(%ebp), %eax
0x00411edd:	pushl %ebx
0x00411ede:	pushl %esi
0x00411edf:	pushl 0x8(%ebp)
0x00411ee2:	movl %esi, 0xc(%ebp)
0x00411ee5:	call 0x00411a9e
0x00411ae8:	cmpl %eax, $0xfffffffc<UINT8>
0x00411aeb:	jne 0x00411afd
0x00411eea:	movl %ebx, %eax
0x00411eec:	popl %ecx
0x00411eed:	testl %ebx, %ebx
0x00411eef:	jne 0x00411eff
0x00411eff:	pushl %edi
0x00411f00:	xorl %edi, %edi
0x00411f02:	movl %ecx, %edi
0x00411f04:	movl %eax, %edi
0x00411f06:	movl -28(%ebp), %ecx
0x00411f09:	cmpl 0x420208(%eax), %ebx
0x00411f0f:	je 234
0x00411f15:	incl %ecx
0x00411f16:	addl %eax, $0x30<UINT8>
0x00411f19:	movl -28(%ebp), %ecx
0x00411f1c:	cmpl %eax, $0xf0<UINT32>
0x00411f21:	jb 0x00411f09
0x00411f23:	cmpl %ebx, $0xfde8<UINT32>
0x00411f29:	je 200
0x00411f2f:	cmpl %ebx, $0xfde9<UINT32>
0x00411f35:	je 188
0x00411f3b:	movzwl %eax, %bx
0x00411f3e:	pushl %eax
0x00411f3f:	call IsValidCodePage@KERNEL32.dll
IsValidCodePage@KERNEL32.dll: API Node	
0x00411f45:	testl %eax, %eax
0x00411f47:	je 170
0x00411f4d:	leal %eax, -24(%ebp)
0x00411f50:	pushl %eax
0x00411f51:	pushl %ebx
0x00411f52:	call GetCPInfo@KERNEL32.dll
GetCPInfo@KERNEL32.dll: API Node	
0x00411f58:	testl %eax, %eax
0x00411f5a:	je 132
0x00411f60:	pushl $0x101<UINT32>
0x00411f65:	leal %eax, 0x18(%esi)
0x00411f68:	pushl %edi
0x00411f69:	pushl %eax
0x00411f6a:	call 0x00409480
0x00409480:	movl %ecx, 0xc(%esp)
0x00409484:	movzbl %eax, 0x8(%esp)
0x00409489:	movl %edx, %edi
0x0040948b:	movl %edi, 0x4(%esp)
0x0040948f:	testl %ecx, %ecx
0x00409491:	je 316
0x00409497:	imull %eax, %eax, $0x1010101<UINT32>
0x0040949d:	cmpl %ecx, $0x20<UINT8>
0x004094a0:	jle 0x00409585
0x004094a6:	cmpl %ecx, $0x80<UINT32>
0x004094ac:	jl 139
0x004094b2:	btl 0x4208e0, $0x1<UINT8>
0x004094ba:	jae 0x004094c5
0x004094c5:	btl 0x420020, $0x1<UINT8>
0x004094cd:	jae 178
0x004094d3:	movd %xmm0, %eax
0x004094d7:	pshufd %xmm0, %xmm0, $0x0<UINT8>
0x004094dc:	addl %ecx, %edi
0x004094de:	movups (%edi), %xmm0
0x004094e1:	addl %edi, $0x10<UINT8>
0x004094e4:	andl %edi, $0xfffffff0<UINT8>
0x004094e7:	subl %ecx, %edi
0x004094e9:	cmpl %ecx, $0x80<UINT32>
0x004094ef:	jle 0x0040953d
0x004094f1:	leal %esp, (%esp)
0x004094f8:	leal %esp, (%esp)
0x004094ff:	nop
0x00409500:	movdqa (%edi), %xmm0
0x00409504:	movdqa 0x10(%edi), %xmm0
0x00409509:	movdqa 0x20(%edi), %xmm0
0x0040950e:	movdqa 0x30(%edi), %xmm0
0x00409513:	movdqa 0x40(%edi), %xmm0
0x00409518:	movdqa 0x50(%edi), %xmm0
0x0040951d:	movdqa 0x60(%edi), %xmm0
0x00409522:	movdqa 0x70(%edi), %xmm0
0x00409527:	leal %edi, 0x80(%edi)
0x0040952d:	subl %ecx, $0x80<UINT32>
0x00409533:	testl %ecx, $0xffffff00<UINT32>
0x00409539:	jne 0x00409500
0x0040953b:	jmp 0x00409550
0x00409550:	cmpl %ecx, $0x20<UINT8>
0x00409553:	jb 28
0x00409555:	movdqu (%edi), %xmm0
0x00409559:	movdqu 0x10(%edi), %xmm0
0x0040955e:	addl %edi, $0x20<UINT8>
0x00409561:	subl %ecx, $0x20<UINT8>
0x00409564:	cmpl %ecx, $0x20<UINT8>
0x00409567:	jae 0x00409555
0x00409569:	testl %ecx, $0x1f<UINT32>
0x0040956f:	je 98
0x00409571:	leal %edi, -32(%ecx,%edi)
0x00409575:	movdqu (%edi), %xmm0
0x00409579:	movdqu 0x10(%edi), %xmm0
0x0040957e:	movl %eax, 0x4(%esp)
0x00409582:	movl %edi, %edx
0x00409584:	ret

0x00411f6f:	movl 0x4(%esi), %ebx
0x00411f72:	addl %esp, $0xc<UINT8>
0x00411f75:	xorl %ebx, %ebx
0x00411f77:	movl 0x21c(%esi), %edi
0x00411f7d:	incl %ebx
0x00411f7e:	cmpl -24(%ebp), %ebx
0x00411f81:	jbe 81
0x00411f83:	cmpb -18(%ebp), $0x0<UINT8>
0x00411f87:	leal %eax, -18(%ebp)
0x00411f8a:	je 0x00411fad
0x00411fad:	leal %eax, 0x1a(%esi)
0x00411fb0:	movl %ecx, $0xfe<UINT32>
0x00411fb5:	orb (%eax), $0x8<UINT8>
0x00411fb8:	incl %eax
0x00411fb9:	subl %ecx, $0x1<UINT8>
0x00411fbc:	jne 0x00411fb5
0x00411fbe:	pushl 0x4(%esi)
0x00411fc1:	call 0x00411a60
0x00411a60:	movl %edi, %edi
0x00411a62:	pushl %ebp
0x00411a63:	movl %ebp, %esp
0x00411a65:	movl %eax, 0x8(%ebp)
0x00411a68:	subl %eax, $0x3a4<UINT32>
0x00411a6d:	je 40
0x00411a6f:	subl %eax, $0x4<UINT8>
0x00411a72:	je 28
0x00411a74:	subl %eax, $0xd<UINT8>
0x00411a77:	je 16
0x00411a79:	subl %eax, $0x1<UINT8>
0x00411a7c:	je 4
0x00411a7e:	xorl %eax, %eax
0x00411a80:	popl %ebp
0x00411a81:	ret

0x00411fc6:	addl %esp, $0x4<UINT8>
0x00411fc9:	movl 0x21c(%esi), %eax
0x00411fcf:	movl 0x8(%esi), %ebx
0x00411fd2:	jmp 0x00411fd7
0x00411fd7:	xorl %eax, %eax
0x00411fd9:	leal %edi, 0xc(%esi)
0x00411fdc:	stosl %es:(%edi), %eax
0x00411fdd:	stosl %es:(%edi), %eax
0x00411fde:	stosl %es:(%edi), %eax
0x00411fdf:	jmp 0x004120a2
0x004120a2:	pushl %esi
0x004120a3:	call 0x00411b76
0x00411b76:	movl %edi, %edi
0x00411b78:	pushl %ebp
0x00411b79:	movl %ebp, %esp
0x00411b7b:	subl %esp, $0x720<UINT32>
0x00411b81:	movl %eax, 0x420018
0x00411b86:	xorl %eax, %ebp
0x00411b88:	movl -4(%ebp), %eax
0x00411b8b:	pushl %ebx
0x00411b8c:	pushl %esi
0x00411b8d:	movl %esi, 0x8(%ebp)
0x00411b90:	leal %eax, -1816(%ebp)
0x00411b96:	pushl %edi
0x00411b97:	pushl %eax
0x00411b98:	pushl 0x4(%esi)
0x00411b9b:	call GetCPInfo@KERNEL32.dll
0x00411ba1:	xorl %ebx, %ebx
0x00411ba3:	movl %edi, $0x100<UINT32>
0x00411ba8:	testl %eax, %eax
0x00411baa:	je 240
0x00411bb0:	movl %eax, %ebx
0x00411bb2:	movb -260(%ebp,%eax), %al
0x00411bb9:	incl %eax
0x00411bba:	cmpl %eax, %edi
0x00411bbc:	jb 0x00411bb2
0x00411bbe:	movb %al, -1810(%ebp)
0x00411bc4:	leal %ecx, -1810(%ebp)
0x00411bca:	movb -260(%ebp), $0x20<UINT8>
0x00411bd1:	jmp 0x00411bf2
0x00411bf2:	testb %al, %al
0x00411bf4:	jne -35
0x00411bf6:	pushl %ebx
0x00411bf7:	pushl 0x4(%esi)
0x00411bfa:	leal %eax, -1796(%ebp)
0x00411c00:	pushl %eax
0x00411c01:	pushl %edi
0x00411c02:	leal %eax, -260(%ebp)
0x00411c08:	pushl %eax
0x00411c09:	pushl $0x1<UINT8>
0x00411c0b:	pushl %ebx
0x00411c0c:	call 0x00412b3b
0x00412b3b:	movl %edi, %edi
0x00412b3d:	pushl %ebp
0x00412b3e:	movl %ebp, %esp
0x00412b40:	subl %esp, $0x18<UINT8>
0x00412b43:	movl %eax, 0x420018
0x00412b48:	xorl %eax, %ebp
0x00412b4a:	movl -4(%ebp), %eax
0x00412b4d:	pushl %ebx
0x00412b4e:	pushl %esi
0x00412b4f:	pushl %edi
0x00412b50:	pushl 0x8(%ebp)
0x00412b53:	leal %ecx, -24(%ebp)
0x00412b56:	call 0x0040ba34
0x00412b5b:	movl %ecx, 0x1c(%ebp)
0x00412b5e:	testl %ecx, %ecx
0x00412b60:	jne 0x00412b6d
0x00412b6d:	xorl %eax, %eax
0x00412b6f:	xorl %edi, %edi
0x00412b71:	cmpl 0x20(%ebp), %eax
0x00412b74:	pushl %edi
0x00412b75:	pushl %edi
0x00412b76:	pushl 0x14(%ebp)
0x00412b79:	setne %al
0x00412b7c:	pushl 0x10(%ebp)
0x00412b7f:	leal %eax, 0x1(,%eax,8)
0x00412b86:	pushl %eax
0x00412b87:	pushl %ecx
0x00412b88:	call MultiByteToWideChar@KERNEL32.dll
MultiByteToWideChar@KERNEL32.dll: API Node	
0x00412b8e:	movl -8(%ebp), %eax
0x00412b91:	testl %eax, %eax
0x00412b93:	je 153
0x00412b99:	leal %ebx, (%eax,%eax)
0x00412b9c:	leal %ecx, 0x8(%ebx)
0x00412b9f:	cmpl %ebx, %ecx
0x00412ba1:	sbbl %eax, %eax
0x00412ba3:	testl %ecx, %eax
0x00412ba5:	je 74
0x00412ba7:	leal %ecx, 0x8(%ebx)
0x00412baa:	cmpl %ebx, %ecx
0x00412bac:	sbbl %eax, %eax
0x00412bae:	andl %eax, %ecx
0x00412bb0:	leal %ecx, 0x8(%ebx)
0x00412bb3:	cmpl %eax, $0x400<UINT32>
0x00412bb8:	ja 25
0x00412bba:	cmpl %ebx, %ecx
0x00412bbc:	sbbl %eax, %eax
0x00412bbe:	andl %eax, %ecx
0x00412bc0:	call 0x0041d1f0
0x0041d1f0:	pushl %ecx
0x0041d1f1:	leal %ecx, 0x8(%esp)
0x0041d1f5:	subl %ecx, %eax
0x0041d1f7:	andl %ecx, $0xf<UINT8>
0x0041d1fa:	addl %eax, %ecx
0x0041d1fc:	sbbl %ecx, %ecx
0x0041d1fe:	orl %eax, %ecx
0x0041d200:	popl %ecx
0x0041d201:	jmp 0x0041d220
0x0041d220:	pushl %ecx
0x0041d221:	leal %ecx, 0x4(%esp)
0x0041d225:	subl %ecx, %eax
0x0041d227:	sbbl %eax, %eax
0x0041d229:	notl %eax
0x0041d22b:	andl %ecx, %eax
0x0041d22d:	movl %eax, %esp
0x0041d22f:	andl %eax, $0xfffff000<UINT32>
0x0041d234:	cmpl %ecx, %eax
0x0041d236:	repn jb 11
0x0041d239:	movl %eax, %ecx
0x0041d23b:	popl %ecx
0x0041d23c:	xchgl %esp, %eax
0x0041d23d:	movl %eax, (%eax)
0x0041d23f:	movl (%esp), %eax
0x0041d242:	repn ret

0x00412bc5:	movl %esi, %esp
0x00412bc7:	testl %esi, %esi
0x00412bc9:	je 96
0x00412bcb:	movl (%esi), $0xcccc<UINT32>
0x00412bd1:	jmp 0x00412bec
0x00412bec:	addl %esi, $0x8<UINT8>
0x00412bef:	jmp 0x00412bf3
0x00412bf3:	testl %esi, %esi
0x00412bf5:	je 52
0x00412bf7:	pushl %ebx
0x00412bf8:	pushl %edi
0x00412bf9:	pushl %esi
0x00412bfa:	call 0x00409480
0x00412bff:	addl %esp, $0xc<UINT8>
0x00412c02:	pushl -8(%ebp)
0x00412c05:	pushl %esi
0x00412c06:	pushl 0x14(%ebp)
0x00412c09:	pushl 0x10(%ebp)
0x00412c0c:	pushl $0x1<UINT8>
0x00412c0e:	pushl 0x1c(%ebp)
0x00412c11:	call MultiByteToWideChar@KERNEL32.dll
0x00412c17:	testl %eax, %eax
0x00412c19:	je 16
0x00412c1b:	pushl 0x18(%ebp)
0x00412c1e:	pushl %eax
0x00412c1f:	pushl %esi
0x00412c20:	pushl 0xc(%ebp)
0x00412c23:	call GetStringTypeW@KERNEL32.dll
GetStringTypeW@KERNEL32.dll: API Node	
0x00412c29:	movl %edi, %eax
0x00412c2b:	pushl %esi
0x00412c2c:	call 0x00412c58
0x00412c58:	movl %edi, %edi
0x00412c5a:	pushl %ebp
0x00412c5b:	movl %ebp, %esp
0x00412c5d:	movl %eax, 0x8(%ebp)
0x00412c60:	testl %eax, %eax
0x00412c62:	je 0x00412c76
0x00412c64:	subl %eax, $0x8<UINT8>
0x00412c67:	cmpl (%eax), $0xdddd<UINT32>
0x00412c6d:	jne 0x00412c76
0x00412c76:	popl %ebp
0x00412c77:	ret

0x00412c31:	popl %ecx
0x00412c32:	cmpb -12(%ebp), $0x0<UINT8>
0x00412c36:	je 0x00412c42
0x00412c42:	movl %eax, %edi
0x00412c44:	leal %esp, -36(%ebp)
0x00412c47:	popl %edi
0x00412c48:	popl %esi
0x00412c49:	popl %ebx
0x00412c4a:	movl %ecx, -4(%ebp)
0x00412c4d:	xorl %ecx, %ebp
0x00412c4f:	call 0x004087b1
0x00412c54:	movl %esp, %ebp
0x00412c56:	popl %ebp
0x00412c57:	ret

0x00411c11:	pushl %ebx
0x00411c12:	pushl 0x4(%esi)
0x00411c15:	leal %eax, -516(%ebp)
0x00411c1b:	pushl %edi
0x00411c1c:	pushl %eax
0x00411c1d:	pushl %edi
0x00411c1e:	leal %eax, -260(%ebp)
0x00411c24:	pushl %eax
0x00411c25:	pushl %edi
0x00411c26:	pushl 0x21c(%esi)
0x00411c2c:	pushl %ebx
0x00411c2d:	call 0x004149a4
0x004149a4:	movl %edi, %edi
0x004149a6:	pushl %ebp
0x004149a7:	movl %ebp, %esp
0x004149a9:	subl %esp, $0x10<UINT8>
0x004149ac:	pushl 0x8(%ebp)
0x004149af:	leal %ecx, -16(%ebp)
0x004149b2:	call 0x0040ba34
0x004149b7:	pushl 0x28(%ebp)
0x004149ba:	leal %eax, -12(%ebp)
0x004149bd:	pushl 0x24(%ebp)
0x004149c0:	pushl 0x20(%ebp)
0x004149c3:	pushl 0x1c(%ebp)
0x004149c6:	pushl 0x18(%ebp)
0x004149c9:	pushl 0x14(%ebp)
0x004149cc:	pushl 0x10(%ebp)
0x004149cf:	pushl 0xc(%ebp)
0x004149d2:	pushl %eax
0x004149d3:	call 0x00414787
0x00414787:	movl %edi, %edi
0x00414789:	pushl %ebp
0x0041478a:	movl %ebp, %esp
0x0041478c:	pushl %ecx
0x0041478d:	pushl %ecx
0x0041478e:	movl %eax, 0x420018
0x00414793:	xorl %eax, %ebp
0x00414795:	movl -4(%ebp), %eax
0x00414798:	pushl %ebx
0x00414799:	pushl %esi
0x0041479a:	movl %esi, 0x18(%ebp)
0x0041479d:	pushl %edi
0x0041479e:	testl %esi, %esi
0x004147a0:	jle 20
0x004147a2:	pushl %esi
0x004147a3:	pushl 0x14(%ebp)
0x004147a6:	call 0x0041755d
0x0041755d:	movl %edi, %edi
0x0041755f:	pushl %ebp
0x00417560:	movl %ebp, %esp
0x00417562:	movl %ecx, 0x8(%ebp)
0x00417565:	xorl %eax, %eax
0x00417567:	cmpb (%ecx), %al
0x00417569:	je 12
0x0041756b:	cmpl %eax, 0xc(%ebp)
0x0041756e:	je 0x00417577
0x00417570:	incl %eax
0x00417571:	cmpb (%eax,%ecx), $0x0<UINT8>
0x00417575:	jne 0x0041756b
0x00417577:	popl %ebp
0x00417578:	ret

0x004147ab:	popl %ecx
0x004147ac:	cmpl %eax, %esi
0x004147ae:	popl %ecx
0x004147af:	leal %esi, 0x1(%eax)
0x004147b2:	jl 2
0x004147b4:	movl %esi, %eax
0x004147b6:	movl %edi, 0x24(%ebp)
0x004147b9:	testl %edi, %edi
0x004147bb:	jne 0x004147c8
0x004147c8:	xorl %eax, %eax
0x004147ca:	cmpl 0x28(%ebp), %eax
0x004147cd:	pushl $0x0<UINT8>
0x004147cf:	pushl $0x0<UINT8>
0x004147d1:	pushl %esi
0x004147d2:	pushl 0x14(%ebp)
0x004147d5:	setne %al
0x004147d8:	leal %eax, 0x1(,%eax,8)
0x004147df:	pushl %eax
0x004147e0:	pushl %edi
0x004147e1:	call MultiByteToWideChar@KERNEL32.dll
0x004147e7:	movl -8(%ebp), %eax
0x004147ea:	testl %eax, %eax
0x004147ec:	je 397
0x004147f2:	leal %edx, (%eax,%eax)
0x004147f5:	leal %ecx, 0x8(%edx)
0x004147f8:	cmpl %edx, %ecx
0x004147fa:	sbbl %eax, %eax
0x004147fc:	testl %ecx, %eax
0x004147fe:	je 82
0x00414800:	leal %ecx, 0x8(%edx)
0x00414803:	cmpl %edx, %ecx
0x00414805:	sbbl %eax, %eax
0x00414807:	andl %eax, %ecx
0x00414809:	leal %ecx, 0x8(%edx)
0x0041480c:	cmpl %eax, $0x400<UINT32>
0x00414811:	ja 29
0x00414813:	cmpl %edx, %ecx
0x00414815:	sbbl %eax, %eax
0x00414817:	andl %eax, %ecx
0x00414819:	call 0x0041d1f0
0x0041481e:	movl %ebx, %esp
0x00414820:	testl %ebx, %ebx
0x00414822:	je 332
0x00414828:	movl (%ebx), $0xcccc<UINT32>
0x0041482e:	jmp 0x0041484d
0x0041484d:	addl %ebx, $0x8<UINT8>
0x00414850:	jmp 0x00414854
0x00414854:	testl %ebx, %ebx
0x00414856:	je 280
0x0041485c:	pushl -8(%ebp)
0x0041485f:	pushl %ebx
0x00414860:	pushl %esi
0x00414861:	pushl 0x14(%ebp)
0x00414864:	pushl $0x1<UINT8>
0x00414866:	pushl %edi
0x00414867:	call MultiByteToWideChar@KERNEL32.dll
0x0041486d:	testl %eax, %eax
0x0041486f:	je 255
0x00414875:	movl %edi, -8(%ebp)
0x00414878:	xorl %eax, %eax
0x0041487a:	pushl %eax
0x0041487b:	pushl %eax
0x0041487c:	pushl %eax
0x0041487d:	pushl %eax
0x0041487e:	pushl %eax
0x0041487f:	pushl %edi
0x00414880:	pushl %ebx
0x00414881:	pushl 0x10(%ebp)
0x00414884:	pushl 0xc(%ebp)
0x00414887:	call 0x0040f46f
0x0040f46f:	movl %edi, %edi
0x0040f471:	pushl %ebp
0x0040f472:	movl %ebp, %esp
0x0040f474:	pushl %ecx
0x0040f475:	movl %eax, 0x420018
0x0040f47a:	xorl %eax, %ebp
0x0040f47c:	movl -4(%ebp), %eax
0x0040f47f:	pushl %esi
0x0040f480:	pushl $0x4034c8<UINT32>
0x0040f485:	pushl $0x4034c0<UINT32>
0x0040f48a:	pushl $0x4034c8<UINT32>
0x0040f48f:	pushl $0x16<UINT8>
0x0040f491:	call 0x0040f127
0x0040f496:	movl %esi, %eax
0x0040f498:	addl %esp, $0x10<UINT8>
0x0040f49b:	testl %esi, %esi
0x0040f49d:	je 39
0x0040f49f:	pushl 0x28(%ebp)
0x0040f4a2:	movl %ecx, %esi
0x0040f4a4:	pushl 0x24(%ebp)
0x0040f4a7:	pushl 0x20(%ebp)
0x0040f4aa:	pushl 0x1c(%ebp)
0x0040f4ad:	pushl 0x18(%ebp)
0x0040f4b0:	pushl 0x14(%ebp)
0x0040f4b3:	pushl 0x10(%ebp)
0x0040f4b6:	pushl 0xc(%ebp)
0x0040f4b9:	pushl 0x8(%ebp)
0x0040f4bc:	call 0x00408960
0x0040f4c2:	call LCMapStringEx@kernel32.dll
LCMapStringEx@kernel32.dll: API Node	
0x0040f4c4:	jmp 0x0040f4e6
0x0040f4e6:	movl %ecx, -4(%ebp)
0x0040f4e9:	xorl %ecx, %ebp
0x0040f4eb:	popl %esi
0x0040f4ec:	call 0x004087b1
0x0040f4f1:	movl %esp, %ebp
0x0040f4f3:	popl %ebp
0x0040f4f4:	ret $0x24<UINT16>

0x0041488c:	movl %esi, %eax
0x0041488e:	testl %esi, %esi
0x00414890:	je 0x00414974
0x00414896:	testl 0x10(%ebp), $0x400<UINT32>
0x00414974:	xorl %esi, %esi
0x00414976:	pushl %ebx
0x00414977:	call 0x00412c58
0x0041497c:	popl %ecx
0x0041497d:	movl %eax, %esi
0x0041497f:	leal %esp, -20(%ebp)
0x00414982:	popl %edi
0x00414983:	popl %esi
0x00414984:	popl %ebx
0x00414985:	movl %ecx, -4(%ebp)
0x00414988:	xorl %ecx, %ebp
0x0041498a:	call 0x004087b1
0x0041498f:	movl %esp, %ebp
0x00414991:	popl %ebp
0x00414992:	ret

0x004149d8:	addl %esp, $0x24<UINT8>
0x004149db:	cmpb -4(%ebp), $0x0<UINT8>
0x004149df:	je 0x004149eb
0x004149eb:	movl %esp, %ebp
0x004149ed:	popl %ebp
0x004149ee:	ret

0x00411c32:	addl %esp, $0x40<UINT8>
0x00411c35:	leal %eax, -772(%ebp)
0x00411c3b:	pushl %ebx
0x00411c3c:	pushl 0x4(%esi)
0x00411c3f:	pushl %edi
0x00411c40:	pushl %eax
0x00411c41:	pushl %edi
0x00411c42:	leal %eax, -260(%ebp)
0x00411c48:	pushl %eax
0x00411c49:	pushl $0x200<UINT32>
0x00411c4e:	pushl 0x21c(%esi)
0x00411c54:	pushl %ebx
0x00411c55:	call 0x004149a4
0x00411c5a:	addl %esp, $0x24<UINT8>
0x00411c5d:	movl %ecx, %ebx
0x00411c5f:	movzwl %eax, -1796(%ebp,%ecx,2)
0x00411c67:	testb %al, $0x1<UINT8>
0x00411c69:	je 0x00411c79
0x00411c79:	testb %al, $0x2<UINT8>
0x00411c7b:	je 0x00411c92
0x00411c92:	movb 0x119(%esi,%ecx), %bl
0x00411c99:	incl %ecx
0x00411c9a:	cmpl %ecx, %edi
0x00411c9c:	jb 0x00411c5f
0x00411c6b:	orb 0x19(%esi,%ecx), $0x10<UINT8>
0x00411c70:	movb %al, -516(%ebp,%ecx)
0x00411c77:	jmp 0x00411c89
0x00411c89:	movb 0x119(%esi,%ecx), %al
0x00411c90:	jmp 0x00411c99
0x00411c7d:	orb 0x19(%esi,%ecx), $0x20<UINT8>
0x00411c82:	movb %al, -772(%ebp,%ecx)
0x00411c9e:	jmp 0x00411cf9
0x00411cf9:	movl %ecx, -4(%ebp)
0x00411cfc:	popl %edi
0x00411cfd:	popl %esi
0x00411cfe:	xorl %ecx, %ebp
0x00411d00:	popl %ebx
0x00411d01:	call 0x004087b1
0x00411d06:	movl %esp, %ebp
0x00411d08:	popl %ebp
0x00411d09:	ret

0x004120a8:	popl %ecx
0x004120a9:	xorl %eax, %eax
0x004120ab:	popl %edi
0x004120ac:	movl %ecx, -4(%ebp)
0x004120af:	popl %esi
0x004120b0:	xorl %ecx, %ebp
0x004120b2:	popl %ebx
0x004120b3:	call 0x004087b1
0x004120b8:	movl %esp, %ebp
0x004120ba:	popl %ebp
0x004120bb:	ret

0x00411d6c:	movl %esi, %eax
0x00411d6e:	popl %ecx
0x00411d6f:	popl %ecx
0x00411d70:	cmpl %esi, %ebx
0x00411d72:	jne 0x00411d91
0x00411d91:	cmpb 0xc(%ebp), $0x0<UINT8>
0x00411d95:	jne 0x00411d9c
0x00411d9c:	movl %eax, -4(%ebp)
0x00411d9f:	movl %eax, 0x48(%eax)
0x00411da2:	xaddl (%eax), %ebx
0x00411da6:	decl %ebx
0x00411da7:	jne 21
0x00411da9:	movl %eax, -4(%ebp)
0x00411dac:	cmpl 0x48(%eax), $0x420500<UINT32>
0x00411db3:	je 0x00411dbe
0x00411dbe:	movl (%edi), $0x1<UINT32>
0x00411dc4:	movl %ecx, %edi
0x00411dc6:	movl %eax, -4(%ebp)
0x00411dc9:	xorl %edi, %edi
0x00411dcb:	movl 0x48(%eax), %ecx
0x00411dce:	movl %eax, -4(%ebp)
0x00411dd1:	testb 0x350(%eax), $0x2<UINT8>
0x00411dd8:	jne -89
0x00411dda:	testb 0x420780, $0x1<UINT8>
0x00411de1:	jne -98
0x00411de3:	leal %eax, -4(%ebp)
0x00411de6:	movl -12(%ebp), %eax
0x00411de9:	leal %eax, -12(%ebp)
0x00411dec:	pushl %eax
0x00411ded:	pushl $0x5<UINT8>
0x00411def:	call 0x00411974
0x00411974:	movl %edi, %edi
0x00411976:	pushl %ebp
0x00411977:	movl %ebp, %esp
0x00411979:	subl %esp, $0xc<UINT8>
0x0041197c:	movl %eax, 0x8(%ebp)
0x0041197f:	leal %ecx, -1(%ebp)
0x00411982:	movl -8(%ebp), %eax
0x00411985:	movl -12(%ebp), %eax
0x00411988:	leal %eax, -8(%ebp)
0x0041198b:	pushl %eax
0x0041198c:	pushl 0xc(%ebp)
0x0041198f:	leal %eax, -12(%ebp)
0x00411992:	pushl %eax
0x00411993:	call 0x00411931
0x00411931:	pushl $0x8<UINT8>
0x00411933:	pushl $0x41edd0<UINT32>
0x00411938:	call 0x004084b0
0x0041193d:	movl %eax, 0x8(%ebp)
0x00411940:	pushl (%eax)
0x00411942:	call 0x00412562
0x00411947:	popl %ecx
0x00411948:	andl -4(%ebp), $0x0<UINT8>
0x0041194c:	movl %ecx, 0xc(%ebp)
0x0041194f:	call 0x0041199c
0x0041199c:	movl %edi, %edi
0x0041199e:	pushl %esi
0x0041199f:	movl %esi, %ecx
0x004119a1:	pushl $0xc<UINT8>
0x004119a3:	movl %eax, (%esi)
0x004119a5:	movl %eax, (%eax)
0x004119a7:	movl %eax, 0x48(%eax)
0x004119aa:	movl %eax, 0x4(%eax)
0x004119ad:	movl 0x421218, %eax
0x004119b2:	movl %eax, (%esi)
0x004119b4:	movl %eax, (%eax)
0x004119b6:	movl %eax, 0x48(%eax)
0x004119b9:	movl %eax, 0x8(%eax)
0x004119bc:	movl 0x42121c, %eax
0x004119c1:	movl %eax, (%esi)
0x004119c3:	movl %eax, (%eax)
0x004119c5:	movl %eax, 0x48(%eax)
0x004119c8:	movl %eax, 0x21c(%eax)
0x004119ce:	movl 0x421214, %eax
0x004119d3:	movl %eax, (%esi)
0x004119d5:	movl %eax, (%eax)
0x004119d7:	movl %eax, 0x48(%eax)
0x004119da:	addl %eax, $0xc<UINT8>
0x004119dd:	pushl %eax
0x004119de:	pushl $0xc<UINT8>
0x004119e0:	pushl $0x421220<UINT32>
0x004119e5:	call 0x004120bc
0x004120bc:	movl %edi, %edi
0x004120be:	pushl %ebp
0x004120bf:	movl %ebp, %esp
0x004120c1:	pushl %esi
0x004120c2:	movl %esi, 0x14(%ebp)
0x004120c5:	testl %esi, %esi
0x004120c7:	jne 0x004120cd
0x004120cd:	movl %eax, 0x8(%ebp)
0x004120d0:	testl %eax, %eax
0x004120d2:	jne 0x004120e7
0x004120e7:	pushl %edi
0x004120e8:	movl %edi, 0x10(%ebp)
0x004120eb:	testl %edi, %edi
0x004120ed:	je 20
0x004120ef:	cmpl 0xc(%ebp), %esi
0x004120f2:	jb 15
0x004120f4:	pushl %esi
0x004120f5:	pushl %edi
0x004120f6:	pushl %eax
0x004120f7:	call 0x0041d450
0x0041d450:	pushl %edi
0x0041d451:	pushl %esi
0x0041d452:	movl %esi, 0x10(%esp)
0x0041d456:	movl %ecx, 0x14(%esp)
0x0041d45a:	movl %edi, 0xc(%esp)
0x0041d45e:	movl %eax, %ecx
0x0041d460:	movl %edx, %ecx
0x0041d462:	addl %eax, %esi
0x0041d464:	cmpl %edi, %esi
0x0041d466:	jbe 0x0041d470
0x0041d470:	cmpl %ecx, $0x20<UINT8>
0x0041d473:	jb 0x0041d94b
0x0041d94b:	andl %ecx, $0x1f<UINT8>
0x0041d94e:	je 48
0x0041d950:	movl %eax, %ecx
0x0041d952:	shrl %ecx, $0x2<UINT8>
0x0041d955:	je 15
0x0041d957:	movl %edx, (%esi)
0x0041d959:	movl (%edi), %edx
0x0041d95b:	addl %edi, $0x4<UINT8>
0x0041d95e:	addl %esi, $0x4<UINT8>
0x0041d961:	subl %ecx, $0x1<UINT8>
0x0041d964:	jne 0x0041d957
0x0041d966:	movl %ecx, %eax
0x0041d968:	andl %ecx, $0x3<UINT8>
0x0041d96b:	je 0x0041d980
0x0041d980:	movl %eax, 0xc(%esp)
0x0041d984:	popl %esi
0x0041d985:	popl %edi
0x0041d986:	ret

0x004120fc:	addl %esp, $0xc<UINT8>
0x004120ff:	xorl %eax, %eax
0x00412101:	jmp 0x00412139
0x00412139:	popl %edi
0x0041213a:	popl %esi
0x0041213b:	popl %ebp
0x0041213c:	ret

0x004119ea:	movl %eax, (%esi)
0x004119ec:	movl %ecx, $0x101<UINT32>
0x004119f1:	pushl %ecx
0x004119f2:	movl %eax, (%eax)
0x004119f4:	movl %eax, 0x48(%eax)
0x004119f7:	addl %eax, $0x18<UINT8>
0x004119fa:	pushl %eax
0x004119fb:	pushl %ecx
0x004119fc:	pushl $0x4202f8<UINT32>
0x00411a01:	call 0x004120bc
0x0041d479:	cmpl %ecx, $0x80<UINT32>
0x0041d47f:	jae 0x0041d494
0x0041d494:	btl 0x4208e0, $0x1<UINT8>
0x0041d49c:	jae 0x0041d4a7
0x0041d4a7:	movl %eax, %edi
0x0041d4a9:	xorl %eax, %esi
0x0041d4ab:	testl %eax, $0xf<UINT32>
0x0041d4b0:	jne 0x0041d4c0
0x0041d4b2:	btl 0x420020, $0x1<UINT8>
0x0041d4ba:	jb 0x0041d8a0
0x0041d8a0:	movl %eax, %esi
0x0041d8a2:	andl %eax, $0xf<UINT8>
0x0041d8a5:	testl %eax, %eax
0x0041d8a7:	jne 0x0041d990
0x0041d990:	movl %edx, $0x10<UINT32>
0x0041d995:	subl %edx, %eax
0x0041d997:	subl %ecx, %edx
0x0041d999:	pushl %ecx
0x0041d99a:	movl %eax, %edx
0x0041d99c:	movl %ecx, %eax
0x0041d99e:	andl %ecx, $0x3<UINT8>
0x0041d9a1:	je 0x0041d9ac
0x0041d9ac:	shrl %eax, $0x2<UINT8>
0x0041d9af:	je 13
0x0041d9b1:	movl %edx, (%esi)
0x0041d9b3:	movl (%edi), %edx
0x0041d9b5:	leal %esi, 0x4(%esi)
0x0041d9b8:	leal %edi, 0x4(%edi)
0x0041d9bb:	decl %eax
0x0041d9bc:	jne 0x0041d9b1
0x0041d9be:	popl %ecx
0x0041d9bf:	jmp 0x0041d8ad
0x0041d8ad:	movl %edx, %ecx
0x0041d8af:	andl %ecx, $0x7f<UINT8>
0x0041d8b2:	shrl %edx, $0x7<UINT8>
0x0041d8b5:	je 102
0x0041d8b7:	leal %esp, (%esp)
0x0041d8be:	movl %edi, %edi
0x0041d8c0:	movdqa %xmm0, (%esi)
0x0041d8c4:	movdqa %xmm1, 0x10(%esi)
0x0041d8c9:	movdqa %xmm2, 0x20(%esi)
0x0041d8ce:	movdqa %xmm3, 0x30(%esi)
0x0041d8d3:	movdqa (%edi), %xmm0
0x0041d8d7:	movdqa 0x10(%edi), %xmm1
0x0041d8dc:	movdqa 0x20(%edi), %xmm2
0x0041d8e1:	movdqa 0x30(%edi), %xmm3
0x0041d8e6:	movdqa %xmm4, 0x40(%esi)
0x0041d8eb:	movdqa %xmm5, 0x50(%esi)
0x0041d8f0:	movdqa %xmm6, 0x60(%esi)
0x0041d8f5:	movdqa %xmm7, 0x70(%esi)
0x0041d8fa:	movdqa 0x40(%edi), %xmm4
0x0041d8ff:	movdqa 0x50(%edi), %xmm5
0x0041d904:	movdqa 0x60(%edi), %xmm6
0x0041d909:	movdqa 0x70(%edi), %xmm7
0x0041d90e:	leal %esi, 0x80(%esi)
0x0041d914:	leal %edi, 0x80(%edi)
0x0041d91a:	decl %edx
0x0041d91b:	jne 0x0041d8c0
0x0041d91d:	testl %ecx, %ecx
0x0041d91f:	je 95
0x0041d921:	movl %edx, %ecx
0x0041d923:	shrl %edx, $0x5<UINT8>
0x0041d926:	testl %edx, %edx
0x0041d928:	je 0x0041d94b
0x0041d92a:	leal %ebx, (%ebx)
0x0041d930:	movdqu %xmm0, (%esi)
0x0041d934:	movdqu %xmm1, 0x10(%esi)
0x0041d939:	movdqu (%edi), %xmm0
0x0041d93d:	movdqu 0x10(%edi), %xmm1
0x0041d942:	leal %esi, 0x20(%esi)
0x0041d945:	leal %edi, 0x20(%edi)
0x0041d948:	decl %edx
0x0041d949:	jne 0x0041d930
0x0041d96d:	movb %al, (%esi)
0x0041d96f:	movb (%edi), %al
0x0041d971:	incl %esi
0x0041d972:	incl %edi
0x0041d973:	decl %ecx
0x0041d974:	jne -9
0x0041d976:	leal %esp, (%esp)
0x0041d97d:	leal %ecx, (%ecx)
0x00411a06:	movl %eax, (%esi)
0x00411a08:	movl %ecx, $0x100<UINT32>
0x00411a0d:	pushl %ecx
0x00411a0e:	movl %eax, (%eax)
0x00411a10:	movl %eax, 0x48(%eax)
0x00411a13:	addl %eax, $0x119<UINT32>
0x00411a18:	pushl %eax
0x00411a19:	pushl %ecx
0x00411a1a:	pushl $0x420400<UINT32>
0x00411a1f:	call 0x004120bc
0x0041d4c0:	btl 0x4208e0, $0x0<UINT8>
0x0041d4c8:	jae 0x0041d677
0x0041d677:	testl %edi, $0x3<UINT32>
0x0041d67d:	je 0x0041d692
0x0041d692:	movl %edx, %ecx
0x0041d694:	cmpl %ecx, $0x20<UINT8>
0x0041d697:	jb 686
0x0041d69d:	shrl %ecx, $0x2<UINT8>
0x0041d6a0:	rep movsl %es:(%edi), %ds:(%esi)
0x0041d6a2:	andl %edx, $0x3<UINT8>
0x0041d6a5:	jmp 0x0041d6c4
0x0041d6c4:	movl %eax, 0xc(%esp)
0x0041d6c8:	popl %esi
0x0041d6c9:	popl %edi
0x0041d6ca:	ret

0x00411a24:	movl %eax, 0x420720
0x00411a29:	addl %esp, $0x30<UINT8>
0x00411a2c:	orl %ecx, $0xffffffff<UINT8>
0x00411a2f:	xaddl (%eax), %ecx
0x00411a33:	jne 0x00411a48
0x00411a48:	movl %eax, (%esi)
0x00411a4a:	movl %eax, (%eax)
0x00411a4c:	movl %eax, 0x48(%eax)
0x00411a4f:	movl 0x420720, %eax
0x00411a54:	movl %eax, (%esi)
0x00411a56:	movl %eax, (%eax)
0x00411a58:	movl %eax, 0x48(%eax)
0x00411a5b:	incl (%eax)
0x00411a5e:	popl %esi
0x00411a5f:	ret

0x00411954:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0041195b:	call 0x00411968
0x00411968:	movl %eax, 0x10(%ebp)
0x0041196b:	pushl (%eax)
0x0041196d:	call 0x004125aa
0x00411972:	popl %ecx
0x00411973:	ret

0x00411960:	call 0x004084f6
0x00411965:	ret $0xc<UINT16>

0x00411998:	movl %esp, %ebp
0x0041199a:	popl %ebp
0x0041199b:	ret

0x00411df4:	cmpb 0xc(%ebp), $0x0<UINT8>
0x00411df8:	popl %ecx
0x00411df9:	popl %ecx
0x00411dfa:	je -123
0x00411dfc:	movl %eax, 0x420720
0x00411e01:	movl 0x4201fc, %eax
0x00411e06:	jmp 0x00411d81
0x00411d81:	pushl %edi
0x00411d82:	call 0x0040e4e2
0x00411d87:	popl %ecx
0x00411d88:	popl %edi
0x00411d89:	movl %eax, %esi
0x00411d8b:	popl %esi
0x00411d8c:	popl %ebx
0x00411d8d:	movl %esp, %ebp
0x00411d8f:	popl %ebp
0x00411d90:	ret

0x00411e1d:	popl %ecx
0x00411e1e:	popl %ecx
0x00411e1f:	movb 0x421230, $0x1<UINT8>
0x00411e26:	movb %al, $0x1<UINT8>
0x00411e28:	ret

0x0040e341:	pushl $0x420f0c<UINT32>
0x0040e346:	call 0x0040e2ce
0x0040e2ce:	movl %edi, %edi
0x0040e2d0:	pushl %ebp
0x0040e2d1:	movl %ebp, %esp
0x0040e2d3:	pushl %esi
0x0040e2d4:	movl %esi, 0x8(%ebp)
0x0040e2d7:	testl %esi, %esi
0x0040e2d9:	jne 0x0040e2e0
0x0040e2e0:	movl %eax, (%esi)
0x0040e2e2:	cmpl %eax, 0x8(%esi)
0x0040e2e5:	jne 31
0x0040e2e7:	movl %eax, 0x420018
0x0040e2ec:	andl %eax, $0x1f<UINT8>
0x0040e2ef:	pushl $0x20<UINT8>
0x0040e2f1:	popl %ecx
0x0040e2f2:	subl %ecx, %eax
0x0040e2f4:	xorl %eax, %eax
0x0040e2f6:	rorl %eax, %cl
0x0040e2f8:	xorl %eax, 0x420018
0x0040e2fe:	movl (%esi), %eax
0x0040e300:	movl 0x4(%esi), %eax
0x0040e303:	movl 0x8(%esi), %eax
0x0040e306:	xorl %eax, %eax
0x0040e308:	popl %esi
0x0040e309:	popl %ebp
0x0040e30a:	ret

0x0040e34b:	movl (%esp), $0x420f18<UINT32>
0x0040e352:	call 0x0040e2ce
0x0040e357:	popl %ecx
0x0040e358:	movb %al, $0x1<UINT8>
0x0040e35a:	ret

0x004130d9:	cmpl %esi, 0xc(%ebp)
0x004130dc:	jne 4
0x004130de:	movb %al, $0x1<UINT8>
0x004130e0:	jmp 0x0041310e
0x0041310e:	popl %ebx
0x0041310f:	popl %esi
0x00413110:	movl %ecx, -4(%ebp)
0x00413113:	xorl %ecx, %ebp
0x00413115:	popl %edi
0x00413116:	call 0x004087b1
0x0041311b:	movl %esp, %ebp
0x0041311d:	popl %ebp
0x0041311e:	ret

0x0040e432:	popl %ecx
0x0040e433:	popl %ecx
0x0040e434:	ret

0x004085d6:	testb %al, %al
0x004085d8:	jne 0x004085e4
0x004085e4:	movb %al, $0x1<UINT8>
0x004085e6:	popl %ebp
0x004085e7:	ret

0x00408340:	popl %ecx
0x00408341:	testb %al, %al
0x00408343:	jne 0x0040834c
0x0040834c:	xorb %bl, %bl
0x0040834e:	movb -25(%ebp), %bl
0x00408351:	andl -4(%ebp), $0x0<UINT8>
0x00408355:	call 0x0040857a
0x0040857a:	call 0x00408d4b
0x00408d4b:	xorl %eax, %eax
0x00408d4d:	cmpl 0x4213f0, %eax
0x00408d53:	setne %al
0x00408d56:	ret

0x0040857f:	testl %eax, %eax
0x00408581:	jne 3
0x00408583:	xorb %al, %al
0x00408585:	ret

0x0040835a:	movb -36(%ebp), %al
0x0040835d:	movl %eax, 0x4208a4
0x00408362:	xorl %ecx, %ecx
0x00408364:	incl %ecx
0x00408365:	cmpl %eax, %ecx
0x00408367:	je -36
0x00408369:	testl %eax, %eax
0x0040836b:	jne 73
0x0040836d:	movl 0x4208a4, %ecx
0x00408373:	pushl $0x401038<UINT32>
0x00408378:	pushl $0x40101c<UINT32>
0x0040837d:	call 0x0040db3f
0x0040db3f:	movl %edi, %edi
0x0040db41:	pushl %ebp
0x0040db42:	movl %ebp, %esp
0x0040db44:	pushl %ecx
0x0040db45:	movl %eax, 0x420018
0x0040db4a:	xorl %eax, %ebp
0x0040db4c:	movl -4(%ebp), %eax
0x0040db4f:	pushl %esi
0x0040db50:	movl %esi, 0x8(%ebp)
0x0040db53:	pushl %edi
0x0040db54:	jmp 0x0040db6d
0x0040db6d:	cmpl %esi, 0xc(%ebp)
0x0040db70:	jne 0x0040db56
0x0040db56:	movl %edi, (%esi)
0x0040db58:	testl %edi, %edi
0x0040db5a:	je 0x0040db6a
0x0040db6a:	addl %esi, $0x4<UINT8>
0x0040db5c:	movl %ecx, %edi
0x0040db5e:	call 0x00408960
0x0040db64:	call 0x00419671
0x0040826f:	pushl %esi
0x00408270:	pushl $0x1<UINT8>
0x00408272:	call 0x0040d404
0x0040d404:	movl %edi, %edi
0x0040d406:	pushl %ebp
0x0040d407:	movl %ebp, %esp
0x0040d409:	movl %eax, 0x8(%ebp)
0x0040d40c:	movl 0x420cb8, %eax
0x0040d411:	popl %ebp
0x0040d412:	ret

0x00408277:	call 0x0040892a
0x0040892a:	movl %eax, $0x4000<UINT32>
0x0040892f:	ret

0x0040827c:	pushl %eax
0x0040827d:	call 0x0040ddec
0x0040ddec:	movl %edi, %edi
0x0040ddee:	pushl %ebp
0x0040ddef:	movl %ebp, %esp
0x0040ddf1:	movl %eax, 0x8(%ebp)
0x0040ddf4:	cmpl %eax, $0x4000<UINT32>
0x0040ddf9:	je 0x0040de1e
0x0040de1e:	movl %ecx, $0x421374<UINT32>
0x0040de23:	xchgl (%ecx), %eax
0x0040de25:	xorl %eax, %eax
0x0040de27:	popl %ebp
0x0040de28:	ret

0x00408282:	call 0x0040df42
0x0040df42:	movl %eax, $0x420f08<UINT32>
0x0040df47:	ret

0x00408287:	movl %esi, %eax
0x00408289:	call 0x00408930
0x00408930:	xorl %eax, %eax
0x00408932:	ret

0x0040828e:	pushl $0x1<UINT8>
0x00408290:	movl (%esi), %eax
0x00408292:	call 0x004085e8
0x004085e8:	pushl %ebp
0x004085e9:	movl %ebp, %esp
0x004085eb:	subl %esp, $0xc<UINT8>
0x004085ee:	cmpb 0x4208c4, $0x0<UINT8>
0x004085f5:	je 0x004085fe
0x004085fe:	pushl %esi
0x004085ff:	movl %esi, 0x8(%ebp)
0x00408602:	testl %esi, %esi
0x00408604:	je 5
0x00408606:	cmpl %esi, $0x1<UINT8>
0x00408609:	jne 127
0x0040860b:	call 0x00408d4b
0x00408610:	testl %eax, %eax
0x00408612:	je 0x0040863a
0x0040863a:	movl %eax, 0x420018
0x0040863f:	leal %esi, -12(%ebp)
0x00408642:	pushl %edi
0x00408643:	andl %eax, $0x1f<UINT8>
0x00408646:	movl %edi, $0x4208ac<UINT32>
0x0040864b:	pushl $0x20<UINT8>
0x0040864d:	popl %ecx
0x0040864e:	subl %ecx, %eax
0x00408650:	orl %eax, $0xffffffff<UINT8>
0x00408653:	rorl %eax, %cl
0x00408655:	xorl %eax, 0x420018
0x0040865b:	movl -12(%ebp), %eax
0x0040865e:	movl -8(%ebp), %eax
0x00408661:	movl -4(%ebp), %eax
0x00408664:	movsl %es:(%edi), %ds:(%esi)
0x00408665:	movsl %es:(%edi), %ds:(%esi)
0x00408666:	movsl %es:(%edi), %ds:(%esi)
0x00408667:	movl %edi, $0x4208b8<UINT32>
0x0040866c:	movl -12(%ebp), %eax
0x0040866f:	movl -8(%ebp), %eax
0x00408672:	leal %esi, -12(%ebp)
0x00408675:	movl -4(%ebp), %eax
0x00408678:	movsl %es:(%edi), %ds:(%esi)
0x00408679:	movsl %es:(%edi), %ds:(%esi)
0x0040867a:	movsl %es:(%edi), %ds:(%esi)
0x0040867b:	popl %edi
0x0040867c:	movb 0x4208c4, $0x1<UINT8>
0x00408683:	movb %al, $0x1<UINT8>
0x00408685:	popl %esi
0x00408686:	movl %esp, %ebp
0x00408688:	popl %ebp
0x00408689:	ret

0x00408297:	addl %esp, $0xc<UINT8>
0x0040829a:	popl %esi
0x0040829b:	testb %al, %al
0x0040829d:	je 108
0x0040829f:	fnclex
0x004082a1:	call 0x00408b50
0x00408b50:	pushl %ebx
0x00408b51:	pushl %esi
0x00408b52:	movl %esi, $0x407dc8<UINT32>
0x00408b57:	movl %ebx, $0x407dc8<UINT32>
0x00408b5c:	cmpl %esi, %ebx
0x00408b5e:	jae 0x00408b78
0x00408b78:	popl %esi
0x00408b79:	popl %ebx
0x00408b7a:	ret

0x004082a6:	pushl $0x408b7b<UINT32>
0x004082ab:	call 0x0040879c
0x0040879c:	pushl %ebp
0x0040879d:	movl %ebp, %esp
0x0040879f:	pushl 0x8(%ebp)
0x004087a2:	call 0x00408761
0x00408761:	pushl %ebp
0x00408762:	movl %ebp, %esp
0x00408764:	movl %eax, 0x420018
0x00408769:	movl %ecx, %eax
0x0040876b:	xorl %eax, 0x4208ac
0x00408771:	andl %ecx, $0x1f<UINT8>
0x00408774:	pushl 0x8(%ebp)
0x00408777:	rorl %eax, %cl
0x00408779:	cmpl %eax, $0xffffffff<UINT8>
0x0040877c:	jne 7
0x0040877e:	call 0x0040e29b
0x0040e29b:	movl %edi, %edi
0x0040e29d:	pushl %ebp
0x0040e29e:	movl %ebp, %esp
0x0040e2a0:	pushl 0x8(%ebp)
0x0040e2a3:	pushl $0x420f0c<UINT32>
0x0040e2a8:	call 0x0040e30b
0x0040e30b:	movl %edi, %edi
0x0040e30d:	pushl %ebp
0x0040e30e:	movl %ebp, %esp
0x0040e310:	pushl %ecx
0x0040e311:	pushl %ecx
0x0040e312:	leal %eax, 0x8(%ebp)
0x0040e315:	movl -8(%ebp), %eax
0x0040e318:	leal %eax, 0xc(%ebp)
0x0040e31b:	movl -4(%ebp), %eax
0x0040e31e:	leal %eax, -8(%ebp)
0x0040e321:	pushl %eax
0x0040e322:	pushl $0x2<UINT8>
0x0040e324:	call 0x0040e012
0x0040e012:	movl %edi, %edi
0x0040e014:	pushl %ebp
0x0040e015:	movl %ebp, %esp
0x0040e017:	subl %esp, $0xc<UINT8>
0x0040e01a:	movl %eax, 0x8(%ebp)
0x0040e01d:	leal %ecx, -1(%ebp)
0x0040e020:	movl -8(%ebp), %eax
0x0040e023:	movl -12(%ebp), %eax
0x0040e026:	leal %eax, -8(%ebp)
0x0040e029:	pushl %eax
0x0040e02a:	pushl 0xc(%ebp)
0x0040e02d:	leal %eax, -12(%ebp)
0x0040e030:	pushl %eax
0x0040e031:	call 0x0040df48
0x0040df48:	pushl $0xc<UINT8>
0x0040df4a:	pushl $0x41ec68<UINT32>
0x0040df4f:	call 0x004084b0
0x0040df54:	andl -28(%ebp), $0x0<UINT8>
0x0040df58:	movl %eax, 0x8(%ebp)
0x0040df5b:	pushl (%eax)
0x0040df5d:	call 0x00412562
0x0040df62:	popl %ecx
0x0040df63:	andl -4(%ebp), $0x0<UINT8>
0x0040df67:	movl %ecx, 0xc(%ebp)
0x0040df6a:	call 0x0040e15a
0x0040e15a:	movl %edi, %edi
0x0040e15c:	pushl %ebp
0x0040e15d:	movl %ebp, %esp
0x0040e15f:	subl %esp, $0xc<UINT8>
0x0040e162:	movl %eax, %ecx
0x0040e164:	movl -8(%ebp), %eax
0x0040e167:	pushl %esi
0x0040e168:	movl %eax, (%eax)
0x0040e16a:	movl %esi, (%eax)
0x0040e16c:	testl %esi, %esi
0x0040e16e:	jne 0x0040e178
0x0040e178:	movl %eax, 0x420018
0x0040e17d:	movl %ecx, %eax
0x0040e17f:	pushl %ebx
0x0040e180:	movl %ebx, (%esi)
0x0040e182:	andl %ecx, $0x1f<UINT8>
0x0040e185:	pushl %edi
0x0040e186:	movl %edi, 0x4(%esi)
0x0040e189:	xorl %ebx, %eax
0x0040e18b:	movl %esi, 0x8(%esi)
0x0040e18e:	xorl %edi, %eax
0x0040e190:	xorl %esi, %eax
0x0040e192:	rorl %edi, %cl
0x0040e194:	rorl %esi, %cl
0x0040e196:	rorl %ebx, %cl
0x0040e198:	cmpl %edi, %esi
0x0040e19a:	jne 180
0x0040e1a0:	subl %esi, %ebx
0x0040e1a2:	movl %eax, $0x200<UINT32>
0x0040e1a7:	sarl %esi, $0x2<UINT8>
0x0040e1aa:	cmpl %esi, %eax
0x0040e1ac:	ja 2
0x0040e1ae:	movl %eax, %esi
0x0040e1b0:	leal %edi, (%eax,%esi)
0x0040e1b3:	testl %edi, %edi
0x0040e1b5:	jne 3
0x0040e1b7:	pushl $0x20<UINT8>
0x0040e1b9:	popl %edi
0x0040e1ba:	cmpl %edi, %esi
0x0040e1bc:	jb 29
0x0040e1be:	pushl $0x4<UINT8>
0x0040e1c0:	pushl %edi
0x0040e1c1:	pushl %ebx
0x0040e1c2:	call 0x00413009
0x00413009:	movl %edi, %edi
0x0041300b:	pushl %ebp
0x0041300c:	movl %ebp, %esp
0x0041300e:	popl %ebp
0x0041300f:	jmp 0x00413014
0x00413014:	movl %edi, %edi
0x00413016:	pushl %ebp
0x00413017:	movl %ebp, %esp
0x00413019:	pushl %esi
0x0041301a:	movl %esi, 0xc(%ebp)
0x0041301d:	testl %esi, %esi
0x0041301f:	je 27
0x00413021:	pushl $0xffffffe0<UINT8>
0x00413023:	xorl %edx, %edx
0x00413025:	popl %eax
0x00413026:	divl %eax, %esi
0x00413028:	cmpl %eax, 0x10(%ebp)
0x0041302b:	jae 0x0041303c
0x0041303c:	pushl %ebx
0x0041303d:	movl %ebx, 0x8(%ebp)
0x00413040:	pushl %edi
0x00413041:	testl %ebx, %ebx
0x00413043:	je 0x00413050
0x00413050:	xorl %edi, %edi
0x00413052:	imull %esi, 0x10(%ebp)
0x00413056:	pushl %esi
0x00413057:	pushl %ebx
0x00413058:	call 0x00416fd4
0x00416fd4:	movl %edi, %edi
0x00416fd6:	pushl %ebp
0x00416fd7:	movl %ebp, %esp
0x00416fd9:	pushl %edi
0x00416fda:	movl %edi, 0x8(%ebp)
0x00416fdd:	testl %edi, %edi
0x00416fdf:	jne 11
0x00416fe1:	pushl 0xc(%ebp)
0x00416fe4:	call 0x0040e51c
0x00416fe9:	popl %ecx
0x00416fea:	jmp 0x00417010
0x00417010:	popl %edi
0x00417011:	popl %ebp
0x00417012:	ret

0x0041305d:	movl %ebx, %eax
0x0041305f:	popl %ecx
0x00413060:	popl %ecx
0x00413061:	testl %ebx, %ebx
0x00413063:	je 21
0x00413065:	cmpl %edi, %esi
0x00413067:	jae 17
0x00413069:	subl %esi, %edi
0x0041306b:	leal %eax, (%ebx,%edi)
0x0041306e:	pushl %esi
0x0041306f:	pushl $0x0<UINT8>
0x00413071:	pushl %eax
0x00413072:	call 0x00409480
0x0040953d:	btl 0x420020, $0x1<UINT8>
0x00409545:	jae 62
0x00409547:	movd %xmm0, %eax
0x0040954b:	pshufd %xmm0, %xmm0, $0x0<UINT8>
0x00413077:	addl %esp, $0xc<UINT8>
0x0041307a:	popl %edi
0x0041307b:	movl %eax, %ebx
0x0041307d:	popl %ebx
0x0041307e:	popl %esi
0x0041307f:	popl %ebp
0x00413080:	ret

0x0040e1c7:	pushl $0x0<UINT8>
0x0040e1c9:	movl -4(%ebp), %eax
0x0040e1cc:	call 0x0040e4e2
0x0040e1d1:	movl %ecx, -4(%ebp)
0x0040e1d4:	addl %esp, $0x10<UINT8>
0x0040e1d7:	testl %ecx, %ecx
0x0040e1d9:	jne 0x0040e203
0x0040e203:	leal %eax, (%ecx,%esi,4)
0x0040e206:	movl %ebx, %ecx
0x0040e208:	movl -4(%ebp), %eax
0x0040e20b:	leal %esi, (%ecx,%edi,4)
0x0040e20e:	movl %eax, 0x420018
0x0040e213:	movl %edi, -4(%ebp)
0x0040e216:	andl %eax, $0x1f<UINT8>
0x0040e219:	pushl $0x20<UINT8>
0x0040e21b:	popl %ecx
0x0040e21c:	subl %ecx, %eax
0x0040e21e:	xorl %eax, %eax
0x0040e220:	rorl %eax, %cl
0x0040e222:	movl %ecx, %edi
0x0040e224:	xorl %eax, 0x420018
0x0040e22a:	movl -12(%ebp), %eax
0x0040e22d:	movl %eax, %esi
0x0040e22f:	subl %eax, %edi
0x0040e231:	addl %eax, $0x3<UINT8>
0x0040e234:	shrl %eax, $0x2<UINT8>
0x0040e237:	cmpl %esi, %edi
0x0040e239:	sbbl %edx, %edx
0x0040e23b:	notl %edx
0x0040e23d:	andl %edx, %eax
0x0040e23f:	movl -4(%ebp), %edx
0x0040e242:	je 16
0x0040e244:	movl %edx, -12(%ebp)
0x0040e247:	xorl %eax, %eax
0x0040e249:	incl %eax
0x0040e24a:	movl (%ecx), %edx
0x0040e24c:	leal %ecx, 0x4(%ecx)
0x0040e24f:	cmpl %eax, -4(%ebp)
0x0040e252:	jne 0x0040e249
0x0040e254:	movl %eax, -8(%ebp)
0x0040e257:	movl %eax, 0x4(%eax)
0x0040e25a:	pushl (%eax)
0x0040e25c:	call 0x0040d413
0x0040d413:	movl %edi, %edi
0x0040d415:	pushl %ebp
0x0040d416:	movl %ebp, %esp
0x0040d418:	movl %eax, 0x420018
0x0040d41d:	andl %eax, $0x1f<UINT8>
0x0040d420:	pushl $0x20<UINT8>
0x0040d422:	popl %ecx
0x0040d423:	subl %ecx, %eax
0x0040d425:	movl %eax, 0x8(%ebp)
0x0040d428:	rorl %eax, %cl
0x0040d42a:	xorl %eax, 0x420018
0x0040d430:	popl %ebp
0x0040d431:	ret

0x0040e261:	pushl %ebx
0x0040e262:	movl (%edi), %eax
0x0040e264:	call 0x00408519
0x0040e269:	movl %ebx, -8(%ebp)
0x0040e26c:	movl %ecx, (%ebx)
0x0040e26e:	movl %ecx, (%ecx)
0x0040e270:	movl (%ecx), %eax
0x0040e272:	leal %eax, 0x4(%edi)
0x0040e275:	pushl %eax
0x0040e276:	call 0x00408519
0x0040e27b:	movl %ecx, (%ebx)
0x0040e27d:	pushl %esi
0x0040e27e:	movl %ecx, (%ecx)
0x0040e280:	movl 0x4(%ecx), %eax
0x0040e283:	call 0x00408519
0x0040e288:	movl %ecx, (%ebx)
0x0040e28a:	addl %esp, $0x10<UINT8>
0x0040e28d:	movl %ecx, (%ecx)
0x0040e28f:	movl 0x8(%ecx), %eax
0x0040e292:	xorl %eax, %eax
0x0040e294:	popl %edi
0x0040e295:	popl %ebx
0x0040e296:	popl %esi
0x0040e297:	movl %esp, %ebp
0x0040e299:	popl %ebp
0x0040e29a:	ret

0x0040df6f:	movl %esi, %eax
0x0040df71:	movl -28(%ebp), %esi
0x0040df74:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040df7b:	call 0x0040df8d
0x0040df8d:	movl %eax, 0x10(%ebp)
0x0040df90:	pushl (%eax)
0x0040df92:	call 0x004125aa
0x0040df97:	popl %ecx
0x0040df98:	ret

0x0040df80:	movl %eax, %esi
0x0040df82:	call 0x004084f6
0x0040df87:	ret $0xc<UINT16>

0x0040e036:	movl %esp, %ebp
0x0040e038:	popl %ebp
0x0040e039:	ret

0x0040e329:	popl %ecx
0x0040e32a:	popl %ecx
0x0040e32b:	movl %esp, %ebp
0x0040e32d:	popl %ebp
0x0040e32e:	ret

0x0040e2ad:	popl %ecx
0x0040e2ae:	popl %ecx
0x0040e2af:	popl %ebp
0x0040e2b0:	ret

0x00408783:	jmp 0x00408790
0x00408790:	negl %eax
0x00408792:	popl %ecx
0x00408793:	sbbl %eax, %eax
0x00408795:	notl %eax
0x00408797:	andl %eax, 0x8(%ebp)
0x0040879a:	popl %ebp
0x0040879b:	ret

0x004087a7:	negl %eax
0x004087a9:	popl %ecx
0x004087aa:	sbbl %eax, %eax
0x004087ac:	negl %eax
0x004087ae:	decl %eax
0x004087af:	popl %ebp
0x004087b0:	ret

0x004082b0:	call 0x00408926
0x00408926:	xorl %eax, %eax
0x00408928:	incl %eax
0x00408929:	ret

0x004082b5:	pushl %eax
0x004082b6:	call 0x0040d7e8
0x0040d7e8:	movl %edi, %edi
0x0040d7ea:	pushl %ebp
0x0040d7eb:	movl %ebp, %esp
0x0040d7ed:	popl %ebp
0x0040d7ee:	jmp 0x0040d4ee
0x0040d4ee:	movl %edi, %edi
0x0040d4f0:	pushl %ebp
0x0040d4f1:	movl %ebp, %esp
0x0040d4f3:	subl %esp, $0xc<UINT8>
0x0040d4f6:	cmpl 0x8(%ebp), $0x2<UINT8>
0x0040d4fa:	pushl %esi
0x0040d4fb:	je 28
0x0040d4fd:	cmpl 0x8(%ebp), $0x1<UINT8>
0x0040d501:	je 0x0040d519
0x0040d519:	pushl %ebx
0x0040d51a:	pushl %edi
0x0040d51b:	pushl $0x104<UINT32>
0x0040d520:	movl %esi, $0x420cc0<UINT32>
0x0040d525:	xorl %edi, %edi
0x0040d527:	pushl %esi
0x0040d528:	pushl %edi
0x0040d529:	call GetModuleFileNameW@KERNEL32.dll
GetModuleFileNameW@KERNEL32.dll: API Node	
0x0040d52f:	movl %ebx, 0x420ef8
0x0040d535:	movl 0x420efc, %esi
0x0040d53b:	testl %ebx, %ebx
0x0040d53d:	je 5
0x0040d53f:	cmpw (%ebx), %di
0x0040d542:	jne 0x0040d546
0x0040d546:	leal %eax, -12(%ebp)
0x0040d549:	movl -4(%ebp), %edi
0x0040d54c:	pushl %eax
0x0040d54d:	leal %eax, -4(%ebp)
0x0040d550:	movl -12(%ebp), %edi
0x0040d553:	pushl %eax
0x0040d554:	pushl %edi
0x0040d555:	pushl %edi
0x0040d556:	pushl %ebx
0x0040d557:	call 0x0040d60d
0x0040d60d:	movl %edi, %edi
0x0040d60f:	pushl %ebp
0x0040d610:	movl %ebp, %esp
0x0040d612:	movl %eax, 0x14(%ebp)
0x0040d615:	subl %esp, $0x10<UINT8>
0x0040d618:	movl %ecx, 0x8(%ebp)
0x0040d61b:	movl %edx, 0x10(%ebp)
0x0040d61e:	pushl %ebx
0x0040d61f:	pushl %esi
0x0040d620:	movl %esi, 0xc(%ebp)
0x0040d623:	xorl %ebx, %ebx
0x0040d625:	pushl %edi
0x0040d626:	movl %edi, 0x18(%ebp)
0x0040d629:	movl (%edi), %ebx
0x0040d62b:	movl (%eax), $0x1<UINT32>
0x0040d631:	testl %esi, %esi
0x0040d633:	je 0x0040d63d
0x0040d63d:	movl -8(%ebp), $0x20<UINT32>
0x0040d644:	movl -12(%ebp), $0x9<UINT32>
0x0040d64b:	pushl $0x22<UINT8>
0x0040d64d:	popl %eax
0x0040d64e:	cmpw (%ecx), %ax
0x0040d651:	jne 0x0040d65d
0x0040d653:	testb %bl, %bl
0x0040d655:	sete %bl
0x0040d658:	addl %ecx, $0x2<UINT8>
0x0040d65b:	jmp 0x0040d677
0x0040d677:	testb %bl, %bl
0x0040d679:	jne 0x0040d64b
0x0040d65d:	incl (%edi)
0x0040d65f:	testl %edx, %edx
0x0040d661:	je 0x0040d66c
0x0040d66c:	movzwl %eax, (%ecx)
0x0040d66f:	addl %ecx, $0x2<UINT8>
0x0040d672:	testw %ax, %ax
0x0040d675:	je 0x0040d696
0x0040d67b:	cmpw %ax, -8(%ebp)
0x0040d67f:	je 9
0x0040d681:	cmpw %ax, -12(%ebp)
0x0040d685:	pushl $0x22<UINT8>
0x0040d687:	popl %eax
0x0040d688:	jne 0x0040d64e
0x0040d696:	subl %ecx, $0x2<UINT8>
0x0040d699:	movl %ebx, 0x14(%ebp)
0x0040d69c:	xorl %eax, %eax
0x0040d69e:	movb -1(%ebp), %al
0x0040d6a1:	cmpw (%ecx), %ax
0x0040d6a4:	je 0x0040d784
0x0040d784:	testl %esi, %esi
0x0040d786:	je 0x0040d78a
0x0040d78a:	incl (%ebx)
0x0040d78c:	popl %edi
0x0040d78d:	popl %esi
0x0040d78e:	popl %ebx
0x0040d78f:	movl %esp, %ebp
0x0040d791:	popl %ebp
0x0040d792:	ret

0x0040d55c:	pushl $0x2<UINT8>
0x0040d55e:	pushl -12(%ebp)
0x0040d561:	pushl -4(%ebp)
0x0040d564:	call 0x0040d793
0x0040d793:	movl %edi, %edi
0x0040d795:	pushl %ebp
0x0040d796:	movl %ebp, %esp
0x0040d798:	pushl %esi
0x0040d799:	movl %esi, 0x8(%ebp)
0x0040d79c:	cmpl %esi, $0x3fffffff<UINT32>
0x0040d7a2:	jb 0x0040d7a8
0x0040d7a8:	pushl %edi
0x0040d7a9:	orl %edi, $0xffffffff<UINT8>
0x0040d7ac:	movl %ecx, 0xc(%ebp)
0x0040d7af:	xorl %edx, %edx
0x0040d7b1:	movl %eax, %edi
0x0040d7b3:	divl %eax, 0x10(%ebp)
0x0040d7b6:	cmpl %ecx, %eax
0x0040d7b8:	jae 13
0x0040d7ba:	imull %ecx, 0x10(%ebp)
0x0040d7be:	shll %esi, $0x2<UINT8>
0x0040d7c1:	subl %edi, %esi
0x0040d7c3:	cmpl %edi, %ecx
0x0040d7c5:	ja 0x0040d7cb
0x0040d7cb:	leal %eax, (%ecx,%esi)
0x0040d7ce:	pushl $0x1<UINT8>
0x0040d7d0:	pushl %eax
0x0040d7d1:	call 0x0040e607
0x0040d7d6:	pushl $0x0<UINT8>
0x0040d7d8:	movl %esi, %eax
0x0040d7da:	call 0x0040e4e2
0x0040d7df:	addl %esp, $0xc<UINT8>
0x0040d7e2:	movl %eax, %esi
0x0040d7e4:	popl %edi
0x0040d7e5:	popl %esi
0x0040d7e6:	popl %ebp
0x0040d7e7:	ret

0x0040d569:	movl %esi, %eax
0x0040d56b:	addl %esp, $0x20<UINT8>
0x0040d56e:	testl %esi, %esi
0x0040d570:	jne 0x0040d57e
0x0040d57e:	leal %eax, -12(%ebp)
0x0040d581:	pushl %eax
0x0040d582:	leal %eax, -4(%ebp)
0x0040d585:	pushl %eax
0x0040d586:	movl %eax, -4(%ebp)
0x0040d589:	leal %eax, (%esi,%eax,4)
0x0040d58c:	pushl %eax
0x0040d58d:	pushl %esi
0x0040d58e:	pushl %ebx
0x0040d58f:	call 0x0040d60d
0x0040d635:	movl (%esi), %edx
0x0040d637:	addl %esi, $0x4<UINT8>
0x0040d63a:	movl 0xc(%ebp), %esi
0x0040d663:	movw %ax, (%ecx)
0x0040d666:	movw (%edx), %ax
0x0040d669:	addl %edx, $0x2<UINT8>
0x0040d788:	movl (%esi), %eax
0x0040d594:	addl %esp, $0x14<UINT8>
0x0040d597:	cmpl 0x8(%ebp), $0x1<UINT8>
0x0040d59b:	jne 22
0x0040d59d:	movl %eax, -4(%ebp)
0x0040d5a0:	decl %eax
0x0040d5a1:	movl 0x420ee8, %eax
0x0040d5a6:	movl %eax, %esi
0x0040d5a8:	movl %esi, %edi
0x0040d5aa:	movl 0x420ef0, %eax
0x0040d5af:	movl %ebx, %edi
0x0040d5b1:	jmp 0x0040d5fd
0x0040d5fd:	pushl %esi
0x0040d5fe:	call 0x0040e4e2
0x0040d603:	popl %ecx
0x0040d604:	popl %edi
0x0040d605:	movl %eax, %ebx
0x0040d607:	popl %ebx
0x0040d608:	popl %esi
0x0040d609:	movl %esp, %ebp
0x0040d60b:	popl %ebp
0x0040d60c:	ret

0x004082bb:	popl %ecx
0x004082bc:	popl %ecx
0x004082bd:	testl %eax, %eax
0x004082bf:	jne 74
0x004082c1:	call 0x00408933
0x00408933:	pushl $0x4208c8<UINT32>
0x00408938:	call InitializeSListHead@KERNEL32.dll
InitializeSListHead@KERNEL32.dll: API Node	
0x0040893e:	ret

0x004082c6:	call 0x00408984
0x00408984:	xorl %eax, %eax
0x00408986:	cmpl 0x42001c, %eax
0x0040898c:	sete %al
0x0040898f:	ret

0x004082cb:	testl %eax, %eax
0x004082cd:	je 0x004082da
0x004082da:	call 0x00408960
0x004082df:	call 0x00408960
0x004082e4:	call 0x0040893f
0x0040893f:	pushl $0x30000<UINT32>
0x00408944:	pushl $0x10000<UINT32>
0x00408949:	pushl $0x0<UINT8>
0x0040894b:	call 0x0040e447
0x0040e447:	movl %edi, %edi
0x0040e449:	pushl %ebp
0x0040e44a:	movl %ebp, %esp
0x0040e44c:	movl %ecx, 0x10(%ebp)
0x0040e44f:	movl %eax, 0xc(%ebp)
0x0040e452:	andl %ecx, $0xfff7ffff<UINT32>
0x0040e458:	andl %eax, %ecx
0x0040e45a:	pushl %esi
0x0040e45b:	movl %esi, 0x8(%ebp)
0x0040e45e:	testl %eax, $0xfcf0fce0<UINT32>
0x0040e463:	je 0x0040e489
0x0040e489:	pushl %ecx
0x0040e48a:	pushl 0xc(%ebp)
0x0040e48d:	testl %esi, %esi
0x0040e48f:	je 0x0040e49a
0x0040e49a:	call 0x004136ee
0x004136ee:	movl %edi, %edi
0x004136f0:	pushl %ebp
0x004136f1:	movl %ebp, %esp
0x004136f3:	subl %esp, $0x10<UINT8>
0x004136f6:	fwait
0x004136f7:	fnstcw -8(%ebp)
0x004136fa:	movw %ax, -8(%ebp)
0x004136fe:	xorl %ecx, %ecx
0x00413700:	testb %al, $0x1<UINT8>
0x00413702:	je 0x00413707
0x00413707:	testb %al, $0x4<UINT8>
0x00413709:	je 0x0041370e
0x0041370e:	testb %al, $0x8<UINT8>
0x00413710:	je 3
0x00413712:	orl %ecx, $0x4<UINT8>
0x00413715:	testb %al, $0x10<UINT8>
0x00413717:	je 3
0x00413719:	orl %ecx, $0x2<UINT8>
0x0041371c:	testb %al, $0x20<UINT8>
0x0041371e:	je 0x00413723
0x00413723:	testb %al, $0x2<UINT8>
0x00413725:	je 0x0041372d
0x0041372d:	pushl %ebx
0x0041372e:	pushl %esi
0x0041372f:	movzwl %esi, %ax
0x00413732:	movl %ebx, $0xc00<UINT32>
0x00413737:	movl %edx, %esi
0x00413739:	pushl %edi
0x0041373a:	movl %edi, $0x200<UINT32>
0x0041373f:	andl %edx, %ebx
0x00413741:	je 38
0x00413743:	cmpl %edx, $0x400<UINT32>
0x00413749:	je 24
0x0041374b:	cmpl %edx, $0x800<UINT32>
0x00413751:	je 12
0x00413753:	cmpl %edx, %ebx
0x00413755:	jne 18
0x00413757:	orl %ecx, $0x300<UINT32>
0x0041375d:	jmp 0x00413769
0x00413769:	andl %esi, $0x300<UINT32>
0x0041376f:	je 12
0x00413771:	cmpl %esi, %edi
0x00413773:	jne 0x00413783
0x00413783:	movl %edx, $0x1000<UINT32>
0x00413788:	testw %dx, %ax
0x0041378b:	je 6
0x0041378d:	orl %ecx, $0x40000<UINT32>
0x00413793:	movl %edi, 0xc(%ebp)
0x00413796:	movl %esi, %edi
0x00413798:	movl %eax, 0x8(%ebp)
0x0041379b:	notl %esi
0x0041379d:	andl %esi, %ecx
0x0041379f:	andl %eax, %edi
0x004137a1:	orl %esi, %eax
0x004137a3:	cmpl %esi, %ecx
0x004137a5:	je 166
0x004137ab:	pushl %esi
0x004137ac:	call 0x004139f0
0x004139f0:	movl %edi, %edi
0x004139f2:	pushl %ebp
0x004139f3:	movl %ebp, %esp
0x004139f5:	movl %ecx, 0x8(%ebp)
0x004139f8:	xorl %eax, %eax
0x004139fa:	testb %cl, $0x10<UINT8>
0x004139fd:	je 0x00413a00
0x00413a00:	testb %cl, $0x8<UINT8>
0x00413a03:	je 0x00413a08
0x00413a08:	testb %cl, $0x4<UINT8>
0x00413a0b:	je 3
0x00413a0d:	orl %eax, $0x8<UINT8>
0x00413a10:	testb %cl, $0x2<UINT8>
0x00413a13:	je 3
0x00413a15:	orl %eax, $0x10<UINT8>
0x00413a18:	testb %cl, $0x1<UINT8>
0x00413a1b:	je 0x00413a20
0x00413a20:	testl %ecx, $0x80000<UINT32>
0x00413a26:	je 0x00413a2b
0x00413a2b:	pushl %esi
0x00413a2c:	movl %edx, %ecx
0x00413a2e:	movl %esi, $0x300<UINT32>
0x00413a33:	pushl %edi
0x00413a34:	movl %edi, $0x200<UINT32>
0x00413a39:	andl %edx, %esi
0x00413a3b:	je 35
0x00413a3d:	cmpl %edx, $0x100<UINT32>
0x00413a43:	je 22
0x00413a45:	cmpl %edx, %edi
0x00413a47:	je 11
0x00413a49:	cmpl %edx, %esi
0x00413a4b:	jne 19
0x00413a4d:	orl %eax, $0xc00<UINT32>
0x00413a52:	jmp 0x00413a60
0x00413a60:	movl %edx, %ecx
0x00413a62:	andl %edx, $0x30000<UINT32>
0x00413a68:	je 12
0x00413a6a:	cmpl %edx, $0x10000<UINT32>
0x00413a70:	jne 6
0x00413a72:	orl %eax, %edi
0x00413a74:	jmp 0x00413a78
0x00413a78:	popl %edi
0x00413a79:	popl %esi
0x00413a7a:	testl %ecx, $0x40000<UINT32>
0x00413a80:	je 5
0x00413a82:	orl %eax, $0x1000<UINT32>
0x00413a87:	popl %ebp
0x00413a88:	ret

0x004137b1:	popl %ecx
0x004137b2:	movw -4(%ebp), %ax
0x004137b6:	fldcw -4(%ebp)
0x004137b9:	fwait
0x004137ba:	fnstcw -4(%ebp)
0x004137bd:	movw %ax, -4(%ebp)
0x004137c1:	xorl %esi, %esi
0x004137c3:	testb %al, $0x1<UINT8>
0x004137c5:	je 0x004137ca
0x004137ca:	testb %al, $0x4<UINT8>
0x004137cc:	je 0x004137d1
0x004137d1:	testb %al, $0x8<UINT8>
0x004137d3:	je 3
0x004137d5:	orl %esi, $0x4<UINT8>
0x004137d8:	testb %al, $0x10<UINT8>
0x004137da:	je 3
0x004137dc:	orl %esi, $0x2<UINT8>
0x004137df:	testb %al, $0x20<UINT8>
0x004137e1:	je 0x004137e6
0x004137e6:	testb %al, $0x2<UINT8>
0x004137e8:	je 0x004137f0
0x004137f0:	movzwl %edx, %ax
0x004137f3:	movl %ecx, %edx
0x004137f5:	andl %ecx, %ebx
0x004137f7:	je 42
0x004137f9:	cmpl %ecx, $0x400<UINT32>
0x004137ff:	je 28
0x00413801:	cmpl %ecx, $0x800<UINT32>
0x00413807:	je 12
0x00413809:	cmpl %ecx, %ebx
0x0041380b:	jne 22
0x0041380d:	orl %esi, $0x300<UINT32>
0x00413813:	jmp 0x00413823
0x00413823:	andl %edx, $0x300<UINT32>
0x00413829:	je 16
0x0041382b:	cmpl %edx, $0x200<UINT32>
0x00413831:	jne 14
0x00413833:	orl %esi, $0x10000<UINT32>
0x00413839:	jmp 0x00413841
0x00413841:	movl %edx, $0x1000<UINT32>
0x00413846:	testw %dx, %ax
0x00413849:	je 6
0x0041384b:	orl %esi, $0x40000<UINT32>
0x00413851:	cmpl 0x4208dc, $0x1<UINT8>
0x00413858:	jl 393
0x0041385e:	andl %edi, $0x308031f<UINT32>
0x00413864:	stmxcsr -16(%ebp)
0x00413868:	movl %eax, -16(%ebp)
0x0041386b:	xorl %ecx, %ecx
0x0041386d:	testb %al, %al
0x0041386f:	jns 3
0x00413871:	pushl $0x10<UINT8>
0x00413873:	popl %ecx
0x00413874:	testl %eax, $0x200<UINT32>
0x00413879:	je 0x0041387e
0x0041387e:	testl %eax, $0x400<UINT32>
0x00413883:	je 3
0x00413885:	orl %ecx, $0x4<UINT8>
0x00413888:	testl %eax, $0x800<UINT32>
0x0041388d:	je 3
0x0041388f:	orl %ecx, $0x2<UINT8>
0x00413892:	testl %edx, %eax
0x00413894:	je 0x00413899
0x00413899:	testl %eax, $0x100<UINT32>
0x0041389e:	je 6
0x004138a0:	orl %ecx, $0x80000<UINT32>
0x004138a6:	movl %edx, %eax
0x004138a8:	movl %ebx, $0x6000<UINT32>
0x004138ad:	andl %edx, %ebx
0x004138af:	je 42
0x004138b1:	cmpl %edx, $0x2000<UINT32>
0x004138b7:	je 0x004138d5
0x004138d5:	orl %ecx, $0x100<UINT32>
0x004138db:	pushl $0x40<UINT8>
0x004138dd:	andl %eax, $0x8040<UINT32>
0x004138e2:	popl %ebx
0x004138e3:	subl %eax, %ebx
0x004138e5:	je 0x00413902
0x00413902:	orl %ecx, $0x2000000<UINT32>
0x00413908:	movl %eax, %edi
0x0041390a:	andl %edi, 0x8(%ebp)
0x0041390d:	notl %eax
0x0041390f:	andl %eax, %ecx
0x00413911:	orl %eax, %edi
0x00413913:	cmpl %eax, %ecx
0x00413915:	je 0x004139d0
0x004139d0:	movl %eax, %ecx
0x004139d2:	orl %ecx, %esi
0x004139d4:	xorl %eax, %esi
0x004139d6:	testl %eax, $0x8031f<UINT32>
0x004139db:	je 6
0x004139dd:	orl %ecx, $0x80000000<UINT32>
0x004139e3:	movl %eax, %ecx
0x004139e5:	jmp 0x004139e9
0x004139e9:	popl %edi
0x004139ea:	popl %esi
0x004139eb:	popl %ebx
0x004139ec:	movl %esp, %ebp
0x004139ee:	popl %ebp
0x004139ef:	ret

0x0040e49f:	popl %ecx
0x0040e4a0:	popl %ecx
0x0040e4a1:	xorl %eax, %eax
0x0040e4a3:	popl %esi
0x0040e4a4:	popl %ebp
0x0040e4a5:	ret

0x00408950:	addl %esp, $0xc<UINT8>
0x00408953:	testl %eax, %eax
0x00408955:	jne 1
0x00408957:	ret

0x004082e9:	call 0x00408930
0x004082ee:	pushl %eax
0x004082ef:	call 0x0040deab
0x0040deab:	movl %edi, %edi
0x0040dead:	pushl %ebp
0x0040deae:	movl %ebp, %esp
0x0040deb0:	pushl %esi
0x0040deb1:	call 0x00410468
0x0040deb6:	movl %edx, 0x8(%ebp)
0x0040deb9:	movl %esi, %eax
0x0040debb:	pushl $0x0<UINT8>
0x0040debd:	popl %eax
0x0040debe:	movl %ecx, 0x350(%esi)
0x0040dec4:	testb %cl, $0x2<UINT8>
0x0040dec7:	sete %al
0x0040deca:	incl %eax
0x0040decb:	cmpl %edx, $0xffffffff<UINT8>
0x0040dece:	je 51
0x0040ded0:	testl %edx, %edx
0x0040ded2:	je 0x0040df0a
0x0040df0a:	popl %esi
0x0040df0b:	popl %ebp
0x0040df0c:	ret

0x004082f4:	popl %ecx
0x004082f5:	call 0x0040e363
0x004082fa:	testb %al, %al
0x004082fc:	je 5
0x004082fe:	call 0x0040dade
0x0040dade:	jmp 0x0040d822
0x0040d822:	cmpl 0x420ed0, $0x0<UINT8>
0x0040d829:	je 0x0040d82e
0x0040d82e:	pushl %esi
0x0040d82f:	pushl %edi
0x0040d830:	call 0x00412174
0x00412174:	movl %edi, %edi
0x00412176:	pushl %esi
0x00412177:	pushl %edi
0x00412178:	call GetEnvironmentStringsW@KERNEL32.dll
GetEnvironmentStringsW@KERNEL32.dll: API Node	
0x0041217e:	movl %esi, %eax
0x00412180:	testl %esi, %esi
0x00412182:	jne 0x00412188
0x00412188:	pushl %ebx
0x00412189:	pushl %esi
0x0041218a:	call 0x0041213d
0x0041213d:	movl %edi, %edi
0x0041213f:	pushl %ebp
0x00412140:	movl %ebp, %esp
0x00412142:	movl %edx, 0x8(%ebp)
0x00412145:	pushl %edi
0x00412146:	xorl %edi, %edi
0x00412148:	cmpw (%edx), %di
0x0041214b:	je 33
0x0041214d:	pushl %esi
0x0041214e:	movl %ecx, %edx
0x00412150:	leal %esi, 0x2(%ecx)
0x00412153:	movw %ax, (%ecx)
0x00412156:	addl %ecx, $0x2<UINT8>
0x00412159:	cmpw %ax, %di
0x0041215c:	jne 0x00412153
0x0041215e:	subl %ecx, %esi
0x00412160:	sarl %ecx
0x00412162:	leal %edx, (%edx,%ecx,2)
0x00412165:	addl %edx, $0x2<UINT8>
0x00412168:	cmpw (%edx), %di
0x0041216b:	jne 0x0041214e
0x0041216d:	popl %esi
0x0041216e:	leal %eax, 0x2(%edx)
0x00412171:	popl %edi
0x00412172:	popl %ebp
0x00412173:	ret

0x0041218f:	subl %eax, %esi
0x00412191:	sarl %eax
0x00412193:	leal %ebx, (%eax,%eax)
0x00412196:	pushl %ebx
0x00412197:	call 0x0040e51c
0x0041219c:	movl %edi, %eax
0x0041219e:	popl %ecx
0x0041219f:	popl %ecx
0x004121a0:	testl %edi, %edi
0x004121a2:	je 11
0x004121a4:	pushl %ebx
0x004121a5:	pushl %esi
0x004121a6:	pushl %edi
0x004121a7:	call 0x0041d450
0x0041d468:	cmpl %edi, %eax
0x0041d46a:	jb 660
0x004121ac:	addl %esp, $0xc<UINT8>
0x004121af:	pushl $0x0<UINT8>
0x004121b1:	call 0x0040e4e2
0x004121b6:	popl %ecx
0x004121b7:	pushl %esi
0x004121b8:	call FreeEnvironmentStringsW@KERNEL32.dll
FreeEnvironmentStringsW@KERNEL32.dll: API Node	
0x004121be:	popl %ebx
0x004121bf:	movl %eax, %edi
0x004121c1:	popl %edi
0x004121c2:	popl %esi
0x004121c3:	ret

0x0040d835:	movl %esi, %eax
0x0040d837:	testl %esi, %esi
0x0040d839:	jne 0x0040d840
0x0040d840:	pushl %esi
0x0040d841:	call 0x0040d876
0x0040d876:	movl %edi, %edi
0x0040d878:	pushl %ebp
0x0040d879:	movl %ebp, %esp
0x0040d87b:	pushl %ecx
0x0040d87c:	pushl %ecx
0x0040d87d:	pushl %ebx
0x0040d87e:	movl %ebx, 0x8(%ebp)
0x0040d881:	xorl %eax, %eax
0x0040d883:	movl -8(%ebp), %eax
0x0040d886:	movl %edx, %eax
0x0040d888:	pushl %esi
0x0040d889:	pushl %edi
0x0040d88a:	movzwl %eax, (%ebx)
0x0040d88d:	movl %esi, %ebx
0x0040d88f:	testw %ax, %ax
0x0040d892:	je 47
0x0040d894:	pushl $0x3d<UINT8>
0x0040d896:	popl %ebx
0x0040d897:	cmpw %ax, %bx
0x0040d89a:	je 0x0040d89d
0x0040d89d:	movl %ecx, %esi
0x0040d89f:	leal %edi, 0x2(%ecx)
0x0040d8a2:	movw %ax, (%ecx)
0x0040d8a5:	addl %ecx, $0x2<UINT8>
0x0040d8a8:	cmpw %ax, -8(%ebp)
0x0040d8ac:	jne 0x0040d8a2
0x0040d8ae:	subl %ecx, %edi
0x0040d8b0:	sarl %ecx
0x0040d8b2:	leal %esi, (%esi,%ecx,2)
0x0040d8b5:	addl %esi, $0x2<UINT8>
0x0040d8b8:	movzwl %eax, (%esi)
0x0040d8bb:	testw %ax, %ax
0x0040d8be:	jne -41
0x0040d8c0:	movl %ebx, 0x8(%ebp)
0x0040d8c3:	leal %eax, 0x1(%edx)
0x0040d8c6:	pushl $0x4<UINT8>
0x0040d8c8:	pushl %eax
0x0040d8c9:	call 0x0040e607
0x0040d8ce:	movl %edi, %eax
0x0040d8d0:	xorl %esi, %esi
0x0040d8d2:	popl %ecx
0x0040d8d3:	popl %ecx
0x0040d8d4:	testl %edi, %edi
0x0040d8d6:	je 121
0x0040d8d8:	movl -4(%ebp), %edi
0x0040d8db:	jmp 0x0040d93a
0x0040d93a:	cmpw (%ebx), %si
0x0040d93d:	jne 0x0040d8dd
0x0040d8dd:	movl %ecx, %ebx
0x0040d8df:	leal %edx, 0x2(%ecx)
0x0040d8e2:	movw %ax, (%ecx)
0x0040d8e5:	addl %ecx, $0x2<UINT8>
0x0040d8e8:	cmpw %ax, %si
0x0040d8eb:	jne 0x0040d8e2
0x0040d8ed:	subl %ecx, %edx
0x0040d8ef:	sarl %ecx
0x0040d8f1:	pushl $0x3d<UINT8>
0x0040d8f3:	leal %eax, 0x1(%ecx)
0x0040d8f6:	popl %ecx
0x0040d8f7:	movl -8(%ebp), %eax
0x0040d8fa:	cmpw (%ebx), %cx
0x0040d8fd:	je 0x0040d937
0x0040d937:	leal %ebx, (%ebx,%eax,2)
0x0040d93f:	jmp 0x0040d953
0x0040d953:	pushl %esi
0x0040d954:	call 0x0040e4e2
0x0040d959:	popl %ecx
0x0040d95a:	movl %eax, %edi
0x0040d95c:	popl %edi
0x0040d95d:	popl %esi
0x0040d95e:	popl %ebx
0x0040d95f:	movl %esp, %ebp
0x0040d961:	popl %ebp
0x0040d962:	ret

0x0040d846:	popl %ecx
0x0040d847:	testl %eax, %eax
0x0040d849:	jne 0x0040d850
0x0040d850:	pushl %eax
0x0040d851:	movl %ecx, $0x420ed0<UINT32>
0x0040d856:	movl 0x420ed4, %eax
0x0040d85b:	call 0x0040d432
0x0040d860:	xorl %edi, %edi
0x0040d862:	pushl $0x0<UINT8>
0x0040d864:	call 0x0040e4e2
0x0040d869:	popl %ecx
0x0040d86a:	pushl %esi
0x0040d86b:	call 0x0040e4e2
0x0040e4ed:	pushl 0x8(%ebp)
0x0040e4f0:	pushl $0x0<UINT8>
0x0040e4f2:	pushl 0x421380
0x0040e4f8:	call HeapFree@KERNEL32.dll
HeapFree@KERNEL32.dll: API Node	
0x0040e4fe:	testl %eax, %eax
0x0040e500:	jne 0x0040e51a
0x0040d870:	popl %ecx
0x0040d871:	movl %eax, %edi
0x0040d873:	popl %edi
0x0040d874:	popl %esi
0x0040d875:	ret

0x00408303:	call 0x00408930
0x00408308:	xorl %eax, %eax
0x0040830a:	ret

0x0040db66:	testl %eax, %eax
0x0040db68:	jne 10
0x00408313:	call 0x00408967
0x00408967:	call 0x00407ea2
0x00407ea2:	movl %eax, $0x420868<UINT32>
0x00407ea7:	ret

0x0040896c:	movl %ecx, 0x4(%eax)
0x0040896f:	orl (%eax), $0x4<UINT8>
0x00408972:	movl 0x4(%eax), %ecx
0x00408975:	call 0x00408961
0x00408961:	movl %eax, $0x4208d0<UINT32>
0x00408966:	ret

0x0040897a:	movl %ecx, 0x4(%eax)
0x0040897d:	orl (%eax), $0x2<UINT8>
0x00408980:	movl 0x4(%eax), %ecx
0x00408983:	ret

0x00408318:	xorl %eax, %eax
0x0040831a:	ret

0x0040b1c4:	movl %eax, 0x420cac
0x0040b1c9:	pushl %esi
0x0040b1ca:	pushl $0x3<UINT8>
0x0040b1cc:	popl %esi
0x0040b1cd:	testl %eax, %eax
0x0040b1cf:	jne 7
0x0040b1d1:	movl %eax, $0x200<UINT32>
0x0040b1d6:	jmp 0x0040b1de
0x0040b1de:	movl 0x420cac, %eax
0x0040b1e3:	pushl $0x4<UINT8>
0x0040b1e5:	pushl %eax
0x0040b1e6:	call 0x0040e607
0x0040b1eb:	pushl $0x0<UINT8>
0x0040b1ed:	movl 0x420cb0, %eax
0x0040b1f2:	call 0x0040e4e2
0x0040b1f7:	addl %esp, $0xc<UINT8>
0x0040b1fa:	cmpl 0x420cb0, $0x0<UINT8>
0x0040b201:	jne 0x0040b22e
0x0040b22e:	pushl %edi
0x0040b22f:	xorl %edi, %edi
0x0040b231:	movl %esi, $0x420050<UINT32>
0x0040b236:	pushl $0x0<UINT8>
0x0040b238:	pushl $0xfa0<UINT32>
0x0040b23d:	leal %eax, 0x20(%esi)
0x0040b240:	pushl %eax
0x0040b241:	call 0x0040f40d
0x0040b246:	movl %eax, 0x420cb0
0x0040b24b:	movl %edx, %edi
0x0040b24d:	sarl %edx, $0x6<UINT8>
0x0040b250:	movl (%eax,%edi,4), %esi
0x0040b253:	movl %eax, %edi
0x0040b255:	andl %eax, $0x3f<UINT8>
0x0040b258:	imull %ecx, %eax, $0x30<UINT8>
0x0040b25b:	movl %eax, 0x421000(,%edx,4)
0x0040b262:	movl %eax, 0x18(%eax,%ecx)
0x0040b266:	cmpl %eax, $0xffffffff<UINT8>
0x0040b269:	je 9
0x0040b26b:	cmpl %eax, $0xfffffffe<UINT8>
0x0040b26e:	je 4
0x0040b270:	testl %eax, %eax
0x0040b272:	jne 0x0040b27b
0x0040b27b:	addl %esi, $0x38<UINT8>
0x0040b27e:	incl %edi
0x0040b27f:	cmpl %esi, $0x4200f8<UINT32>
0x0040b285:	jne 0x0040b236
0x0040b287:	popl %edi
0x0040b288:	xorl %eax, %eax
0x0040b28a:	popl %esi
0x0040b28b:	ret

0x00416c20:	call 0x00411e0b
0x00416c25:	xorl %ecx, %ecx
0x00416c27:	testb %al, %al
0x00416c29:	sete %cl
0x00416c2c:	movl %eax, %ecx
0x00416c2e:	ret

0x00417eef:	pushl $0xa<UINT8>
0x00417ef1:	call 0x0041ce34
0x00417ef6:	movl 0x421400, %eax
0x00417efb:	xorl %eax, %eax
0x00417efd:	ret

0x00419671:	call 0x00407ea2
0x00419676:	movl %ecx, 0x4(%eax)
0x00419679:	orl (%eax), $0x4<UINT8>
0x0041967c:	movl 0x4(%eax), %ecx
0x0041967f:	call 0x00408961
0x00419684:	movl %ecx, 0x4(%eax)
0x00419687:	orl (%eax), $0x2<UINT8>
0x0041968a:	movl 0x4(%eax), %ecx
0x0041968d:	xorl %eax, %eax
0x0041968f:	ret

0x0040db72:	xorl %eax, %eax
0x0040db74:	movl %ecx, -4(%ebp)
0x0040db77:	popl %edi
0x0040db78:	xorl %ecx, %ebp
0x0040db7a:	popl %esi
0x0040db7b:	call 0x004087b1
0x0040db80:	movl %esp, %ebp
0x0040db82:	popl %ebp
0x0040db83:	ret

0x00408382:	popl %ecx
0x00408383:	popl %ecx
0x00408384:	testl %eax, %eax
0x00408386:	je 0x00408399
0x00408399:	pushl $0x401018<UINT32>
0x0040839e:	pushl $0x401000<UINT32>
0x004083a3:	call 0x0040dae3
0x0040dae3:	movl %edi, %edi
0x0040dae5:	pushl %ebp
0x0040dae6:	movl %ebp, %esp
0x0040dae8:	pushl %ecx
0x0040dae9:	pushl %ecx
0x0040daea:	movl %eax, 0x420018
0x0040daef:	xorl %eax, %ebp
0x0040daf1:	movl -4(%ebp), %eax
0x0040daf4:	movl %eax, 0xc(%ebp)
0x0040daf7:	pushl %ebx
0x0040daf8:	pushl %esi
0x0040daf9:	movl %esi, 0x8(%ebp)
0x0040dafc:	subl %eax, %esi
0x0040dafe:	addl %eax, $0x3<UINT8>
0x0040db01:	pushl %edi
0x0040db02:	xorl %edi, %edi
0x0040db04:	shrl %eax, $0x2<UINT8>
0x0040db07:	cmpl 0xc(%ebp), %esi
0x0040db0a:	sbbl %ebx, %ebx
0x0040db0c:	notl %ebx
0x0040db0e:	andl %ebx, %eax
0x0040db10:	je 28
0x0040db12:	movl %eax, (%esi)
0x0040db14:	movl -8(%ebp), %eax
0x0040db17:	testl %eax, %eax
0x0040db19:	je 0x0040db26
0x0040db26:	addl %esi, $0x4<UINT8>
0x0040db29:	incl %edi
0x0040db2a:	cmpl %edi, %ebx
0x0040db2c:	jne 0x0040db12
0x0040db1b:	movl %ecx, %eax
0x0040db1d:	call 0x00408960
0x0040db23:	call 0x00407de1
0x0040831b:	call 0x00408afb
0x00408afb:	pushl $0x408b07<UINT32>
0x00408b00:	call SetUnhandledExceptionFilter@KERNEL32.dll
SetUnhandledExceptionFilter@KERNEL32.dll: API Node	
0x00408b06:	ret

0x00408320:	call 0x00408930
0x00408325:	pushl %eax
0x00408326:	call 0x0040df13
0x0040df13:	movl %edi, %edi
0x0040df15:	pushl %ebp
0x0040df16:	movl %ebp, %esp
0x0040df18:	movl %eax, 0x8(%ebp)
0x0040df1b:	testl %eax, %eax
0x0040df1d:	je 0x0040df39
0x0040df39:	movl %ecx, $0x420f04<UINT32>
0x0040df3e:	xchgl (%ecx), %eax
0x0040df40:	popl %ebp
0x0040df41:	ret

0x0040832b:	popl %ecx
0x0040832c:	ret

0x00407de1:	movl %ecx, $0x4213a0<UINT32>
0x00407de6:	call 0x00419690
0x00419690:	pushl %esi
0x00419691:	movl %esi, %ecx
0x00419693:	call 0x004196e3
0x004196e3:	pushl %esi
0x004196e4:	pushl %edi
0x004196e5:	movl %esi, %ecx
0x004196e7:	xorl %edi, %edi
0x004196e9:	pushl $0x18<UINT8>
0x004196eb:	pushl %edi
0x004196ec:	leal %eax, 0x14(%esi)
0x004196ef:	pushl %eax
0x004196f0:	call 0x00409480
0x00409585:	testl %ecx, $0x3<UINT32>
0x0040958b:	je 0x0040959b
0x0040959b:	testl %ecx, $0x4<UINT32>
0x004095a1:	je 0x004095ab
0x004095ab:	testl %ecx, $0xfffffff8<UINT32>
0x004095b1:	je 32
0x004095b3:	leal %esp, (%esp)
0x004095ba:	leal %ebx, (%ebx)
0x004095c0:	movl (%edi), %eax
0x004095c2:	movl 0x4(%edi), %eax
0x004095c5:	addl %edi, $0x8<UINT8>
0x004095c8:	subl %ecx, $0x8<UINT8>
0x004095cb:	testl %ecx, $0xfffffff8<UINT32>
0x004095d1:	jne 0x004095c0
0x004095d3:	movl %eax, 0x4(%esp)
0x004095d7:	movl %edi, %edx
0x004095d9:	ret

0x004196f5:	addl %esp, $0xc<UINT8>
0x004196f8:	movl 0x2c(%esi), %edi
0x004196fb:	movl 0x30(%esi), %edi
0x004196fe:	movl %eax, %esi
0x00419700:	movl 0x34(%esi), %edi
0x00419703:	popl %edi
0x00419704:	popl %esi
0x00419705:	ret

0x00419698:	movl %eax, $0x400000<UINT32>
0x0041969d:	movl (%esi), $0x38<UINT32>
0x004196a3:	leal %ecx, 0x14(%esi)
0x004196a6:	movl 0x8(%esi), %eax
0x004196a9:	movl 0x4(%esi), %eax
0x004196ac:	movl 0xc(%esi), $0xe00<UINT32>
0x004196b3:	movl 0x10(%esi), $0x4066a8<UINT32>
0x004196ba:	call 0x00408197
0x00408197:	pushl %esi
0x00408198:	xorl %esi, %esi
0x0040819a:	pushl %esi
0x0040819b:	pushl %esi
0x0040819c:	pushl %ecx
0x0040819d:	call InitializeCriticalSectionEx@KERNEL32.dll
InitializeCriticalSectionEx@KERNEL32.dll: API Node	
0x004081a3:	testl %eax, %eax
0x004081a5:	jne 0x004081bc
0x004081a7:	call GetLastError@KERNEL32.dll
0x004081ad:	movl %esi, %eax
0x004081af:	testl %esi, %esi
0x004081b1:	jle 0x004081bc
0x004081bc:	movl %eax, %esi
0x004081be:	popl %esi
0x004081bf:	ret

0x00000000:	addb (%eax), %al
0x00408ec0:	pushl %ebp
0x00408ec1:	movl %ebp, %esp
0x00408ec3:	subl %esp, $0x1c<UINT8>
0x00408ec6:	pushl %ebx
0x00408ec7:	pushl %esi
0x00408ec8:	movl %esi, 0xc(%ebp)
0x00408ecb:	pushl %edi
0x00408ecc:	movb -1(%ebp), $0x0<UINT8>
0x00408ed0:	movl -12(%ebp), $0x1<UINT32>
0x00408ed7:	movl %ebx, 0x8(%esi)
0x00408eda:	leal %eax, 0x10(%esi)
0x00408edd:	xorl %ebx, 0x420018
0x00408ee3:	pushl %eax
0x00408ee4:	pushl %ebx
0x00408ee5:	movl -20(%ebp), %eax
0x00408ee8:	movl -8(%ebp), %ebx
0x00408eeb:	call 0x00408e80
0x00408e80:	pushl %ebp
0x00408e81:	movl %ebp, %esp
0x00408e83:	pushl %esi
0x00408e84:	movl %esi, 0x8(%ebp)
0x00408e87:	pushl %edi
0x00408e88:	movl %edi, 0xc(%ebp)
0x00408e8b:	movl %eax, (%esi)
0x00408e8d:	cmpl %eax, $0xfffffffe<UINT8>
0x00408e90:	je 0x00408e9f
0x00408e9f:	movl %eax, 0x8(%esi)
0x00408ea2:	movl %ecx, 0xc(%esi)
0x00408ea5:	addl %ecx, %edi
0x00408ea7:	xorl %ecx, (%eax,%edi)
0x00408eaa:	popl %edi
0x00408eab:	popl %esi
0x00408eac:	popl %ebp
0x00408ead:	jmp 0x004087b1
0x00408ef0:	movl %edi, 0x10(%ebp)
0x00408ef3:	pushl %edi
0x00408ef4:	call 0x0040973e
0x0040973e:	pushl %ebp
0x0040973f:	movl %ebp, %esp
0x00409741:	movl %eax, 0x422190
0x00409746:	cmpl %eax, $0x408960<UINT32>
0x0040974b:	je 0x0040976c
0x0040976c:	popl %ebp
0x0040976d:	ret

0x00408ef9:	movl %eax, 0x8(%ebp)
0x00408efc:	addl %esp, $0xc<UINT8>
0x00408eff:	testb 0x4(%eax), $0x66<UINT8>
0x00408f03:	jne 186
0x00408f09:	movl -28(%ebp), %eax
0x00408f0c:	leal %eax, -28(%ebp)
0x00408f0f:	movl -24(%ebp), %edi
0x00408f12:	movl %edi, 0xc(%esi)
0x00408f15:	movl -4(%esi), %eax
0x00408f18:	cmpl %edi, $0xfffffffe<UINT8>
0x00408f1b:	je 201
0x00408f21:	leal %eax, 0x2(%edi)
0x00408f24:	leal %eax, (%edi,%eax,2)
0x00408f27:	movl %ecx, 0x4(%ebx,%eax,4)
0x00408f2b:	leal %eax, (%ebx,%eax,4)
0x00408f2e:	movl %ebx, (%eax)
0x00408f30:	movl -16(%ebp), %eax
0x00408f33:	testl %ecx, %ecx
0x00408f35:	je 101
0x00408f37:	leal %edx, 0x10(%esi)
0x00408f3a:	call 0x004096de
0x004096de:	pushl %ebp
0x004096df:	pushl %esi
0x004096e0:	pushl %edi
0x004096e1:	pushl %ebx
0x004096e2:	movl %ebp, %edx
0x004096e4:	xorl %eax, %eax
0x004096e6:	xorl %ebx, %ebx
0x004096e8:	xorl %edx, %edx
0x004096ea:	xorl %esi, %esi
0x004096ec:	xorl %edi, %edi
0x004096ee:	call 0x00408458
0x00408458:	movl %ecx, -20(%ebp)
0x0040845b:	movl %eax, (%ecx)
0x0040845d:	movl %eax, (%eax)
0x0040845f:	movl -32(%ebp), %eax
0x00408462:	pushl %ecx
0x00408463:	pushl %eax
0x00408464:	call 0x0040d28b
0x0040d28b:	movl %edi, %edi
0x0040d28d:	pushl %ebp
0x0040d28e:	movl %ebp, %esp
0x0040d290:	pushl %ecx
0x0040d291:	pushl %ecx
0x0040d292:	movl %eax, 0x420018
0x0040d297:	xorl %eax, %ebp
0x0040d299:	movl -4(%ebp), %eax
0x0040d29c:	pushl %esi
0x0040d29d:	call 0x004104ec
0x0040d2a2:	movl %esi, %eax
0x0040d2a4:	testl %esi, %esi
0x0040d2a6:	je 323
0x0040d2ac:	movl %edx, (%esi)
0x0040d2ae:	movl %ecx, %edx
0x0040d2b0:	pushl %ebx
0x0040d2b1:	xorl %ebx, %ebx
0x0040d2b3:	pushl %edi
0x0040d2b4:	leal %eax, 0x90(%edx)
0x0040d2ba:	cmpl %edx, %eax
0x0040d2bc:	je 14
0x0040d2be:	movl %edi, 0x8(%ebp)
0x0040d2c1:	cmpl (%ecx), %edi
0x0040d2c3:	je 9
0x0040d2c5:	addl %ecx, $0xc<UINT8>
0x0040d2c8:	cmpl %ecx, %eax
0x0040d2ca:	jne 0x0040d2c1
0x0040d2cc:	movl %ecx, %ebx
0x0040d2ce:	testl %ecx, %ecx
0x0040d2d0:	je 0x0040d2d9
0x0040d2d9:	xorl %eax, %eax
0x0040d2db:	jmp 0x0040d3ed
0x0040d3ed:	popl %edi
0x0040d3ee:	popl %ebx
0x0040d3ef:	movl %ecx, -4(%ebp)
0x0040d3f2:	xorl %ecx, %ebp
0x0040d3f4:	popl %esi
0x0040d3f5:	call 0x004087b1
0x0040d3fa:	movl %esp, %ebp
0x0040d3fc:	popl %ebp
0x0040d3fd:	ret

0x00408469:	popl %ecx
0x0040846a:	popl %ecx
0x0040846b:	ret

0x004096f0:	popl %ebx
0x004096f1:	popl %edi
0x004096f2:	popl %esi
0x004096f3:	popl %ebp
0x004096f4:	ret

0x00408f3f:	movb %cl, $0x1<UINT8>
0x00408f41:	movb -1(%ebp), %cl
0x00408f44:	testl %eax, %eax
0x00408f46:	js 102
0x00408f48:	jle 0x00408f9f
0x00408f9f:	movl %edi, %ebx
0x00408fa1:	cmpl %ebx, $0xfffffffe<UINT8>
0x00408fa4:	je 0x00408fba
0x00408fba:	testb %cl, %cl
0x00408fbc:	je 44
0x00408fbe:	movl %ebx, -8(%ebp)
0x00408fc1:	jmp 0x00408fde
0x00408fde:	pushl -20(%ebp)
0x00408fe1:	pushl %ebx
0x00408fe2:	call 0x00408e80
0x00408fe7:	addl %esp, $0x8<UINT8>
0x00408fea:	movl %eax, -12(%ebp)
0x00408fed:	popl %edi
0x00408fee:	popl %esi
0x00408fef:	popl %ebx
0x00408ff0:	movl %esp, %ebp
0x00408ff2:	popl %ebp
0x00408ff3:	ret

0x00000002:	addb (%eax), %al
0x00000004:	addb (%eax), %al
0x00000006:	addb (%eax), %al
0x00000008:	addb (%eax), %al
0x0000000a:	addb (%eax), %al
0x0000000c:	addb (%eax), %al
0x0000000e:	addb (%eax), %al
0x00000010:	addb (%eax), %al
0x00000012:	addb (%eax), %al
0x00000014:	addb (%eax), %al
0x00000016:	addb (%eax), %al
0x00000018:	addb (%eax), %al
0x0000001a:	addb (%eax), %al
0x0000001c:	addb (%eax), %al
0x0000001e:	addb (%eax), %al
0x00000020:	addb (%eax), %al
0x00000022:	addb (%eax), %al
0x00000024:	addb (%eax), %al
0x00000026:	addb (%eax), %al
0x00000028:	addb (%eax), %al
0x0000002a:	addb (%eax), %al
0x0000002c:	addb (%eax), %al
0x0000002e:	addb (%eax), %al
0x00000030:	addb (%eax), %al
0x00000032:	addb (%eax), %al
0x00000034:	addb (%eax), %al
0x00000036:	addb (%eax), %al
0x00000038:	addb (%eax), %al
0x0000003a:	addb (%eax), %al
0x0000003c:	addb (%eax), %al
0x0000003e:	addb (%eax), %al
0x00000040:	addb (%eax), %al
0x00000042:	addb (%eax), %al
0x00000044:	addb (%eax), %al
0x00000046:	addb (%eax), %al
0x00000048:	addb (%eax), %al
0x0000004a:	addb (%eax), %al
0x0000004c:	addb (%eax), %al
0x0000004e:	addb (%eax), %al
0x00000050:	addb (%eax), %al
0x00000052:	addb (%eax), %al
0x00000054:	addb (%eax), %al
0x00000056:	addb (%eax), %al
0x00000058:	addb (%eax), %al
0x0000005a:	addb (%eax), %al
0x0000005c:	addb (%eax), %al
0x0000005e:	addb (%eax), %al
0x00000060:	addb (%eax), %al
0x00000062:	addb (%eax), %al
0x00000064:	addb (%eax), %al
0x0041489d:	je 0x004148d7
0x004148d7:	leal %edx, (%esi,%esi)
0x004148da:	leal %ecx, 0x8(%edx)
0x004148dd:	cmpl %edx, %ecx
0x004148df:	sbbl %eax, %eax
0x004148e1:	testl %ecx, %eax
0x004148e3:	je 0x0041492f
0x0041492f:	xorl %edi, %edi
0x00414931:	testl %edi, %edi
0x00414933:	je 0x0041496d
0x0041496d:	pushl %edi
0x0041496e:	call 0x00412c58
0x00414973:	popl %ecx
0x0018ff1c:	jmp 0x0018ff9b
0x0018ff9b:	addb (%eax), %al
0x0018ff9d:	addb (%eax), %al
0x0018ff9f:	addb (%eax), %al
0x0018ffa1:	addb (%eax), %al
0x0018ffa3:	addb (%eax), %al
0x0018ffa5:	addb (%eax), %al
0x0018ffa7:	addb (%eax), %al
0x0018ffa9:	addb (%eax), %al
0x0018ffab:	addb (%eax), %al
0x0018ffad:	addb (%eax), %al
0x0018ffaf:	addb (%eax), %al
0x0018ffb1:	addb (%eax), %al
0x0018ffb3:	addb (%eax), %al
0x0018ffb5:	addb (%eax), %al
0x0018ffb7:	addb (%eax), %al
0x0018ffb9:	addb (%eax), %al
0x0018ffbb:	addb (%eax), %al
0x0018ffbd:	addb (%eax), %al
0x0018ffbf:	addb (%eax), %al
0x0018ffc1:	addb (%eax), %al
0x0018ffc3:	addb (%eax), %al
0x0018ffc5:	addb (%eax), %al
0x0018ffc7:	addb (%eax), %al
0x0018ffc9:	addb (%eax), %al
0x0018ffcb:	addb (%eax), %al
0x0018ffcd:	addb (%eax), %al
0x0018ffcf:	addb (%eax), %al
0x0018ffd1:	addb (%eax), %al
0x0018ffd3:	addb (%eax), %al
0x0018ffd5:	addb (%eax), %al
0x0018ffd7:	addb (%eax), %al
0x0018ffd9:	addb (%eax), %al
0x0018ffdb:	addb (%eax), %al
0x0018ffdd:	addb (%eax), %al
0x0018ffdf:	addb (%eax), %al
0x0018ffe1:	addb (%eax), %al
0x0018ffe3:	addb (%eax), %al
0x0018ffe5:	addb (%eax), %al
0x0018ffe7:	addb (%eax), %al
0x0018ffe9:	addb (%eax), %al
0x0018ffeb:	addb (%eax), %al
0x0018ffed:	addb (%eax), %al
0x0018ffef:	addb (%eax), %al
0x0018fff1:	addb (%eax), %al
0x0018fff3:	addb (%eax), %al
0x0018fff5:	addb (%eax), %al
0x0018fff7:	addb (%eax), %al
0x0018fff9:	addb (%eax), %al
0x0018fffb:	addb (%eax), %al
0x0018fffd:	addb (%eax), %al
0x0018ffff:	addb (%eax), %al
