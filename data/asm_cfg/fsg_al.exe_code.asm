0x00443000:	movl %ebx, $0x4001d0<UINT32>
0x00443005:	movl %edi, $0x401000<UINT32>
0x0044300a:	movl %esi, $0x42e234<UINT32>
0x0044300f:	pushl %ebx
0x00443010:	call 0x0044301f
0x0044301f:	cld
0x00443020:	movb %dl, $0xffffff80<UINT8>
0x00443022:	movsb %es:(%edi), %ds:(%esi)
0x00443023:	pushl $0x2<UINT8>
0x00443025:	popl %ebx
0x00443026:	call 0x00443015
0x00443015:	addb %dl, %dl
0x00443017:	jne 0x0044301e
0x00443019:	movb %dl, (%esi)
0x0044301b:	incl %esi
0x0044301c:	adcb %dl, %dl
0x0044301e:	ret

0x00443029:	jae 0x00443022
0x0044302b:	xorl %ecx, %ecx
0x0044302d:	call 0x00443015
0x00443030:	jae 0x0044304a
0x00443032:	xorl %eax, %eax
0x00443034:	call 0x00443015
0x00443037:	jae 0x0044305a
0x00443039:	movb %bl, $0x2<UINT8>
0x0044303b:	incl %ecx
0x0044303c:	movb %al, $0x10<UINT8>
0x0044303e:	call 0x00443015
0x00443041:	adcb %al, %al
0x00443043:	jae 0x0044303e
0x00443045:	jne 0x00443086
0x00443086:	pushl %esi
0x00443087:	movl %esi, %edi
0x00443089:	subl %esi, %eax
0x0044308b:	rep movsb %es:(%edi), %ds:(%esi)
0x0044308d:	popl %esi
0x0044308e:	jmp 0x00443026
0x00443047:	stosb %es:(%edi), %al
0x00443048:	jmp 0x00443026
0x0044305a:	lodsb %al, %ds:(%esi)
0x0044305b:	shrl %eax
0x0044305d:	je 0x004430a0
0x0044305f:	adcl %ecx, %ecx
0x00443061:	jmp 0x0044307f
0x0044307f:	incl %ecx
0x00443080:	incl %ecx
0x00443081:	xchgl %ebp, %eax
0x00443082:	movl %eax, %ebp
0x00443084:	movb %bl, $0x1<UINT8>
0x0044304a:	call 0x00443092
0x00443092:	incl %ecx
0x00443093:	call 0x00443015
0x00443097:	adcl %ecx, %ecx
0x00443099:	call 0x00443015
0x0044309d:	jb 0x00443093
0x0044309f:	ret

0x0044304f:	subl %ecx, %ebx
0x00443051:	jne 0x00443063
0x00443053:	call 0x00443090
0x00443090:	xorl %ecx, %ecx
0x00443058:	jmp 0x00443082
0x00443063:	xchgl %ecx, %eax
0x00443064:	decl %eax
0x00443065:	shll %eax, $0x8<UINT8>
0x00443068:	lodsb %al, %ds:(%esi)
0x00443069:	call 0x00443090
0x0044306e:	cmpl %eax, $0x7d00<UINT32>
0x00443073:	jae 0x0044307f
0x00443075:	cmpb %ah, $0x5<UINT8>
0x00443078:	jae 0x00443080
0x0044307a:	cmpl %eax, $0x7f<UINT8>
0x0044307d:	ja 0x00443081
0x004430a0:	popl %edi
0x004430a1:	popl %ebx
0x004430a2:	movzwl %edi, (%ebx)
0x004430a5:	decl %edi
0x004430a6:	je 0x004430b0
0x004430a8:	decl %edi
0x004430a9:	je 0x004430be
0x004430ab:	shll %edi, $0xc<UINT8>
0x004430ae:	jmp 0x004430b7
0x004430b7:	incl %ebx
0x004430b8:	incl %ebx
0x004430b9:	jmp 0x0044300f
0x004430b0:	movl %edi, 0x2(%ebx)
0x004430b3:	pushl %edi
0x004430b4:	addl %ebx, $0x4<UINT8>
0x004430be:	popl %edi
0x004430bf:	movl %ebx, $0x443128<UINT32>
0x004430c4:	incl %edi
0x004430c5:	movl %esi, (%edi)
0x004430c7:	scasl %eax, %es:(%edi)
0x004430c8:	pushl %edi
0x004430c9:	call LoadLibraryA@KERNEL32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004430cb:	xchgl %ebp, %eax
0x004430cc:	xorl %eax, %eax
0x004430ce:	scasb %al, %es:(%edi)
0x004430cf:	jne 0x004430ce
0x004430d1:	decb (%edi)
0x004430d3:	je 0x004430c4
0x004430d5:	decb (%edi)
0x004430d7:	jne 0x004430df
0x004430df:	decb (%edi)
0x004430e1:	je 0x00403b4c
0x004430e7:	pushl %edi
0x004430e8:	pushl %ebp
0x004430e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x004430ec:	orl (%esi), %eax
0x004430ee:	lodsl %eax, %ds:(%esi)
0x004430ef:	jne 0x004430cc
GetProcAddress@KERNEL32.dll: API Node	
LoadLibraryA@KERNEL32.dll: API Node	
0x004430d9:	incl %edi
0x004430da:	pushl (%edi)
0x004430dc:	scasl %eax, %es:(%edi)
0x004430dd:	jmp 0x004430e8
0x00403b4c:	call 0x00401000
0x00401000:	pushl %ebp
0x00401001:	movl %ebp, %esp
0x00401003:	subl %esp, $0x14<UINT8>
0x00401006:	movl %eax, 0x427040
0x0040100b:	andl -12(%ebp), $0x0<UINT8>
0x0040100f:	andl -8(%ebp), $0x0<UINT8>
0x00401013:	pushl %esi
0x00401014:	pushl %edi
0x00401015:	movl %edi, $0xbb40e64e<UINT32>
0x0040101a:	movl %esi, $0xffff0000<UINT32>
0x0040101f:	cmpl %eax, %edi
0x00401021:	jne 34516
0x00401027:	leal %eax, -12(%ebp)
0x0040102a:	pushl %eax
0x0040102b:	call GetSystemTimeAsFileTime@KERNEL32.dll
GetSystemTimeAsFileTime@KERNEL32.dll: API Node	
0x00401031:	movl %eax, -8(%ebp)
0x00401034:	xorl %eax, -12(%ebp)
0x00401037:	movl -4(%ebp), %eax
0x0040103a:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x00401040:	xorl -4(%ebp), %eax
0x00401043:	call GetTickCount64@KERNEL32.dll
GetTickCount64@KERNEL32.dll: API Node	
0x00401049:	xorl -4(%ebp), %eax
0x0040104c:	leal %eax, -20(%ebp)
0x0040104f:	pushl %eax
0x00401050:	call QueryPerformanceCounter@KERNEL32.dll
QueryPerformanceCounter@KERNEL32.dll: API Node	
0x00401056:	movl %ecx, -16(%ebp)
0x00401059:	xorl %ecx, -20(%ebp)
0x0040105c:	leal %eax, -4(%ebp)
0x0040105f:	xorl %ecx, -4(%ebp)
0x00401062:	xorl %ecx, %eax
0x00401064:	cmpl %ecx, %edi
0x00401066:	je 34467
0x0040106c:	testl %esi, %ecx
0x0040106e:	je 34469
0x00401074:	movl 0x427040, %ecx
0x0040107a:	notl %ecx
0x0040107c:	movl 0x427044, %ecx
0x00401082:	popl %edi
0x00401083:	popl %esi
0x00401084:	leave
0x00401085:	ret

0x00403b51:	pushl $0x14<UINT8>
0x00403b53:	pushl $0x403b70<UINT32>
0x00403b58:	call 0x004023d0
0x004023d0:	pushl $0x4156ac<UINT32>
0x004023d5:	pushl %fs:0
0x004023dc:	movl %eax, 0x10(%esp)
0x004023e0:	movl 0x10(%esp), %ebp
0x004023e4:	leal %ebp, 0x10(%esp)
0x004023e8:	subl %esp, %eax
0x004023ea:	pushl %ebx
0x004023eb:	pushl %esi
0x004023ec:	pushl %edi
0x004023ed:	movl %eax, 0x427040
0x004023f2:	xorl -4(%ebp), %eax
0x004023f5:	xorl %eax, %ebp
0x004023f7:	pushl %eax
0x004023f8:	movl -24(%ebp), %esp
0x004023fb:	pushl -8(%ebp)
0x004023fe:	movl %eax, -4(%ebp)
0x00402401:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00402408:	movl -8(%ebp), %eax
0x0040240b:	leal %eax, -16(%ebp)
0x0040240e:	movl %fs:0, %eax
0x00402414:	ret

0x00403b5d:	pushl $0x1<UINT8>
0x00403b5f:	call 0x0041565f
0x0041565f:	pushl %ebp
0x00415660:	movl %ebp, %esp
0x00415662:	movl %eax, 0x8(%ebp)
0x00415665:	movl 0x42ac30, %eax
0x0041566a:	popl %ebp
0x0041566b:	ret

0x00403b64:	jmp 0x0040958c
0x0040958c:	popl %ecx
0x0040958d:	movl %eax, $0x5a4d<UINT32>
0x00409592:	cmpw 0x400000, %ax
0x00409599:	je 0x0040959f
0x0040959f:	movl %eax, 0x40003c
0x004095a4:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x004095ae:	jne -21
0x004095b0:	movl %ecx, $0x10b<UINT32>
0x004095b5:	cmpw 0x400018(%eax), %cx
0x004095bc:	jne -35
0x004095be:	xorl %ebx, %ebx
0x004095c0:	cmpl 0x400074(%eax), $0xe<UINT8>
0x004095c7:	jbe 9
0x004095c9:	cmpl 0x4000e8(%eax), %ebx
0x004095cf:	setne %bl
0x004095d2:	movl -28(%ebp), %ebx
0x004095d5:	call 0x0041504a
0x0041504a:	call GetProcessHeap@KERNEL32.dll
GetProcessHeap@KERNEL32.dll: API Node	
0x00415050:	xorl %ecx, %ecx
0x00415052:	testl %eax, %eax
0x00415054:	setne %cl
0x00415057:	movl 0x42b260, %eax
0x0041505c:	movl %eax, %ecx
0x0041505e:	ret

0x004095da:	testl %eax, %eax
0x004095dc:	jne 0x004095e6
0x004095e6:	call 0x004148d0
0x004148d0:	call 0x00414afc
0x00414afc:	pushl %esi
0x00414afd:	pushl $0x0<UINT8>
0x00414aff:	call EncodePointer@KERNEL32.dll
EncodePointer@KERNEL32.dll: API Node	
0x00414b05:	movl %esi, %eax
0x00414b07:	pushl %esi
0x00414b08:	call 0x0041f2c2
0x0041f2c2:	pushl %ebp
0x0041f2c3:	movl %ebp, %esp
0x0041f2c5:	movl %eax, 0x8(%ebp)
0x0041f2c8:	movl 0x42b5cc, %eax
0x0041f2cd:	popl %ebp
0x0041f2ce:	ret

0x00414b0d:	pushl %esi
0x00414b0e:	call 0x00415961
0x00415961:	pushl %ebp
0x00415962:	movl %ebp, %esp
0x00415964:	movl %eax, 0x8(%ebp)
0x00415967:	movl 0x42b378, %eax
0x0041596c:	popl %ebp
0x0041596d:	ret

0x00414b13:	pushl %esi
0x00414b14:	call 0x0041f6d5
0x0041f6d5:	pushl %ebp
0x0041f6d6:	movl %ebp, %esp
0x0041f6d8:	movl %eax, 0x8(%ebp)
0x0041f6db:	movl 0x42b5d8, %eax
0x0041f6e0:	popl %ebp
0x0041f6e1:	ret

0x00414b19:	pushl %esi
0x00414b1a:	call 0x0041f6e2
0x0041f6e2:	pushl %ebp
0x0041f6e3:	movl %ebp, %esp
0x0041f6e5:	movl %eax, 0x8(%ebp)
0x0041f6e8:	movl 0x42b5dc, %eax
0x0041f6ed:	popl %ebp
0x0041f6ee:	ret

0x00414b1f:	pushl %esi
0x00414b20:	call 0x0041f6fc
0x0041f6fc:	pushl %ebp
0x0041f6fd:	movl %ebp, %esp
0x0041f6ff:	movl %eax, 0x8(%ebp)
0x0041f702:	movl 0x42b5e0, %eax
0x0041f707:	movl 0x42b5e4, %eax
0x0041f70c:	movl 0x42b5e8, %eax
0x0041f711:	movl 0x42b5ec, %eax
0x0041f716:	popl %ebp
0x0041f717:	ret

0x00414b25:	pushl %esi
0x00414b26:	call 0x0041f384
0x0041f384:	pushl $0x41f324<UINT32>
0x0041f389:	call EncodePointer@KERNEL32.dll
0x0041f38f:	movl 0x42b5d4, %eax
0x0041f394:	ret

0x00414b2b:	addl %esp, $0x18<UINT8>
0x00414b2e:	popl %esi
0x00414b2f:	ret

0x004148d5:	call 0x00415b24
0x00415b24:	pushl %esi
0x00415b25:	pushl %edi
0x00415b26:	movl %esi, $0x429d38<UINT32>
0x00415b2b:	movl %edi, $0x42b380<UINT32>
0x00415b30:	cmpl 0x4(%esi), $0x1<UINT8>
0x00415b34:	jne 0x00415b48
0x00415b36:	movl (%esi), %edi
0x00415b38:	pushl $0xfa0<UINT32>
0x00415b3d:	pushl (%esi)
0x00415b3f:	addl %edi, $0x18<UINT8>
0x00415b42:	call InitializeCriticalSectionAndSpinCount@KERNEL32.dll
InitializeCriticalSectionAndSpinCount@KERNEL32.dll: API Node	
0x00415b48:	addl %esi, $0x8<UINT8>
0x00415b4b:	cmpl %esi, $0x429e58<UINT32>
0x00415b51:	jl 0x00415b30
0x00415b53:	xorl %eax, %eax
0x00415b55:	popl %edi
0x00415b56:	incl %eax
0x00415b57:	popl %esi
0x00415b58:	ret

0x004148da:	testl %eax, %eax
0x004148dc:	jne 0x004148e6
0x004148e6:	pushl $0x41460c<UINT32>
0x004148eb:	call FlsAlloc@KERNEL32.dll
FlsAlloc@KERNEL32.dll: API Node	
0x004148f1:	movl 0x429cf0, %eax
0x004148f6:	cmpl %eax, $0xffffffff<UINT8>
0x004148f9:	je -29
0x004148fb:	pushl %esi
0x004148fc:	pushl $0x3b4<UINT32>
0x00414901:	pushl $0x1<UINT8>
0x00414903:	call 0x00415b6e
0x00415b6e:	pushl %ebp
0x00415b6f:	movl %ebp, %esp
0x00415b71:	pushl %esi
0x00415b72:	pushl %edi
0x00415b73:	xorl %esi, %esi
0x00415b75:	pushl $0x0<UINT8>
0x00415b77:	pushl 0xc(%ebp)
0x00415b7a:	pushl 0x8(%ebp)
0x00415b7d:	call 0x0041fcc2
0x0041fcc2:	pushl %ebp
0x0041fcc3:	movl %ebp, %esp
0x0041fcc5:	pushl %esi
0x0041fcc6:	movl %esi, 0x8(%ebp)
0x0041fcc9:	testl %esi, %esi
0x0041fccb:	je 27
0x0041fccd:	pushl $0xffffffe0<UINT8>
0x0041fccf:	xorl %edx, %edx
0x0041fcd1:	popl %eax
0x0041fcd2:	divl %eax, %esi
0x0041fcd4:	cmpl %eax, 0xc(%ebp)
0x0041fcd7:	jae 0x0041fce8
0x0041fce8:	imull %esi, 0xc(%ebp)
0x0041fcec:	testl %esi, %esi
0x0041fcee:	jne 0x0041fcf1
0x0041fcf1:	xorl %ecx, %ecx
0x0041fcf3:	cmpl %esi, $0xffffffe0<UINT8>
0x0041fcf6:	ja 21
0x0041fcf8:	pushl %esi
0x0041fcf9:	pushl $0x8<UINT8>
0x0041fcfb:	pushl 0x42b260
0x0041fd01:	call HeapAlloc@KERNEL32.dll
HeapAlloc@KERNEL32.dll: API Node	
0x0041fd07:	movl %ecx, %eax
0x0041fd09:	testl %ecx, %ecx
0x0041fd0b:	jne 0x0041fd37
0x0041fd37:	movl %eax, %ecx
0x0041fd39:	popl %esi
0x0041fd3a:	popl %ebp
0x0041fd3b:	ret

0x00415b82:	movl %edi, %eax
0x00415b84:	addl %esp, $0xc<UINT8>
0x00415b87:	testl %edi, %edi
0x00415b89:	jne 0x00415bb2
0x00415bb2:	movl %eax, %edi
0x00415bb4:	popl %edi
0x00415bb5:	popl %esi
0x00415bb6:	popl %ebp
0x00415bb7:	ret

0x00414908:	movl %esi, %eax
0x0041490a:	popl %ecx
0x0041490b:	popl %ecx
0x0041490c:	testl %esi, %esi
0x0041490e:	je 44
0x00414910:	pushl %esi
0x00414911:	pushl 0x429cf0
0x00414917:	call FlsSetValue@KERNEL32.dll
FlsSetValue@KERNEL32.dll: API Node	
0x0041491d:	testl %eax, %eax
0x0041491f:	je 27
0x00414921:	pushl $0x0<UINT8>
0x00414923:	pushl %esi
0x00414924:	call 0x004147f8
0x004147f8:	pushl $0x8<UINT8>
0x004147fa:	pushl $0x4148a8<UINT32>
0x004147ff:	call 0x004023d0
0x00414804:	movl %esi, 0x8(%ebp)
0x00414807:	movl 0x5c(%esi), $0x409b20<UINT32>
0x0041480e:	andl 0x8(%esi), $0x0<UINT8>
0x00414812:	xorl %edi, %edi
0x00414814:	incl %edi
0x00414815:	movl 0x14(%esi), %edi
0x00414818:	movl 0x70(%esi), %edi
0x0041481b:	pushl $0x43<UINT8>
0x0041481d:	popl %eax
0x0041481e:	movw 0xb8(%esi), %ax
0x00414825:	movw 0x1be(%esi), %ax
0x0041482c:	movl 0x68(%esi), $0x42a398<UINT32>
0x00414833:	pushl $0xd<UINT8>
0x00414835:	call 0x004159d4
0x004159d4:	pushl %ebp
0x004159d5:	movl %ebp, %esp
0x004159d7:	pushl %esi
0x004159d8:	movl %esi, 0x8(%ebp)
0x004159db:	cmpl 0x429d38(,%esi,8), $0x0<UINT8>
0x004159e3:	jne 0x004159fa
0x004159fa:	pushl 0x429d38(,%esi,8)
0x00415a01:	call EnterCriticalSection@KERNEL32.dll
EnterCriticalSection@KERNEL32.dll: API Node	
0x00415a07:	popl %esi
0x00415a08:	popl %ebp
0x00415a09:	ret

0x0041483a:	popl %ecx
0x0041483b:	andl -4(%ebp), $0x0<UINT8>
0x0041483f:	pushl 0x68(%esi)
0x00414842:	call InterlockedIncrement@KERNEL32.dll
InterlockedIncrement@KERNEL32.dll: API Node	
0x00414848:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0041484f:	call 0x00414892
0x00414892:	pushl $0xd<UINT8>
0x00414894:	call 0x00415b59
0x00415b59:	pushl %ebp
0x00415b5a:	movl %ebp, %esp
0x00415b5c:	movl %eax, 0x8(%ebp)
0x00415b5f:	pushl 0x429d38(,%eax,8)
0x00415b66:	call LeaveCriticalSection@KERNEL32.dll
LeaveCriticalSection@KERNEL32.dll: API Node	
0x00415b6c:	popl %ebp
0x00415b6d:	ret

0x00414899:	popl %ecx
0x0041489a:	ret

0x00414854:	pushl $0xc<UINT8>
0x00414856:	call 0x004159d4
0x0041485b:	popl %ecx
0x0041485c:	movl -4(%ebp), %edi
0x0041485f:	movl %eax, 0xc(%ebp)
0x00414862:	movl 0x6c(%esi), %eax
0x00414865:	testl %eax, %eax
0x00414867:	jne 8
0x00414869:	movl %eax, 0x429e58
0x0041486e:	movl 0x6c(%esi), %eax
0x00414871:	pushl 0x6c(%esi)
0x00414874:	call 0x004187a2
0x004187a2:	pushl %ebp
0x004187a3:	movl %ebp, %esp
0x004187a5:	pushl %ebx
0x004187a6:	pushl %esi
0x004187a7:	movl %esi, 0x42c0c0
0x004187ad:	pushl %edi
0x004187ae:	movl %edi, 0x8(%ebp)
0x004187b1:	pushl %edi
0x004187b2:	call InterlockedIncrement@KERNEL32.dll
0x004187b4:	cmpl 0x78(%edi), $0x0<UINT8>
0x004187b8:	je 0x004187bf
0x004187bf:	movl %eax, 0x80(%edi)
0x004187c5:	testl %eax, %eax
0x004187c7:	je 0x004187cc
0x004187cc:	cmpl 0x7c(%edi), $0x0<UINT8>
0x004187d0:	je 0x004187d7
0x004187d7:	movl %eax, 0x88(%edi)
0x004187dd:	testl %eax, %eax
0x004187df:	je 0x004187e4
0x004187e4:	pushl $0x6<UINT8>
0x004187e6:	popl %eax
0x004187e7:	leal %ebx, 0x1c(%edi)
0x004187ea:	movl 0x8(%ebp), %eax
0x004187ed:	cmpl -8(%ebx), $0x429f18<UINT32>
0x004187f4:	je 0x00418802
0x004187f6:	cmpl (%ebx), $0x0<UINT8>
0x004187f9:	je 0x00418802
0x00418802:	cmpl -12(%ebx), $0x0<UINT8>
0x00418806:	je 0x00418816
0x00418816:	addl %ebx, $0x10<UINT8>
0x00418819:	decl %eax
0x0041881a:	movl 0x8(%ebp), %eax
0x0041881d:	jne 0x004187ed
0x0041881f:	movl %eax, 0x9c(%edi)
0x00418825:	addl %eax, $0xb0<UINT32>
0x0041882a:	pushl %eax
0x0041882b:	call InterlockedIncrement@KERNEL32.dll
0x0041882d:	popl %edi
0x0041882e:	popl %esi
0x0041882f:	popl %ebx
0x00418830:	popl %ebp
0x00418831:	ret

0x00414879:	popl %ecx
0x0041487a:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00414881:	call 0x0041489b
0x0041489b:	pushl $0xc<UINT8>
0x0041489d:	call 0x00415b59
0x004148a2:	popl %ecx
0x004148a3:	ret

0x00414886:	call 0x004010d0
0x004010d0:	movl %ecx, -16(%ebp)
0x004010d3:	movl %fs:0, %ecx
0x004010da:	popl %ecx
0x004010db:	popl %edi
0x004010dc:	popl %edi
0x004010dd:	popl %esi
0x004010de:	popl %ebx
0x004010df:	movl %esp, %ebp
0x004010e1:	popl %ebp
0x004010e2:	pushl %ecx
0x004010e3:	ret

0x0041488b:	ret

0x00414929:	popl %ecx
0x0041492a:	popl %ecx
0x0041492b:	call GetCurrentThreadId@KERNEL32.dll
0x00414931:	orl 0x4(%esi), $0xffffffff<UINT8>
0x00414935:	movl (%esi), %eax
0x00414937:	xorl %eax, %eax
0x00414939:	incl %eax
0x0041493a:	popl %esi
0x0041493b:	ret

0x004095eb:	testl %eax, %eax
0x004095ed:	jne 0x004095f7
0x004095f7:	call 0x004010a5
0x004010a5:	pushl %esi
0x004010a6:	pushl %edi
0x004010a7:	movl %esi, $0x4010c0<UINT32>
0x004010ac:	movl %edi, $0x4010c0<UINT32>
0x004010b1:	cmpl %esi, %edi
0x004010b3:	jb 34417
0x004010b9:	popl %edi
0x004010ba:	popl %esi
0x004010bb:	ret

0x004095fc:	andl -4(%ebp), $0x0<UINT8>
0x00409600:	call 0x0041507b
0x0041507b:	pushl $0x100<UINT32>
0x00415080:	pushl $0x0<UINT8>
0x00415082:	pushl $0x42b620<UINT32>
0x00415087:	call 0x0040124a
0x0040124a:	movl %edx, 0xc(%esp)
0x0040124e:	movl %ecx, 0x4(%esp)
0x00401252:	testl %edx, %edx
0x00401254:	je 18949
0x0040125a:	jmp 0x00405be0
0x00405be0:	movzbl %eax, 0x8(%esp)
0x00405be5:	btl 0x42b5c0, $0x1<UINT8>
0x00405bed:	jae 0x00405bfc
0x00405bfc:	movl %edx, 0xc(%esp)
0x00405c00:	cmpl %edx, $0x80<UINT32>
0x00405c06:	jl 14
0x00405c08:	btl 0x42a7e0, $0x1<UINT8>
0x00405c10:	jb 108594
0x00405c16:	pushl %edi
0x00405c17:	movl %edi, %ecx
0x00405c19:	cmpl %edx, $0x4<UINT8>
0x00405c1c:	jb 49
0x00405c1e:	negl %ecx
0x00405c20:	andl %ecx, $0x3<UINT8>
0x00405c23:	je 0x00405c31
0x00405c31:	movl %ecx, %eax
0x00405c33:	shll %eax, $0x8<UINT8>
0x00405c36:	addl %eax, %ecx
0x00405c38:	movl %ecx, %eax
0x00405c3a:	shll %eax, $0x10<UINT8>
0x00405c3d:	addl %eax, %ecx
0x00405c3f:	movl %ecx, %edx
0x00405c41:	andl %edx, $0x3<UINT8>
0x00405c44:	shrl %ecx, $0x2<UINT8>
0x00405c47:	je 6
0x00405c49:	rep stosl %es:(%edi), %eax
0x00405c4b:	testl %edx, %edx
0x00405c4d:	je 0x00405c59
0x00405c59:	movl %eax, 0x8(%esp)
0x00405c5d:	popl %edi
0x00405c5e:	ret

0x0041508c:	addl %esp, $0xc<UINT8>
0x0041508f:	movl 0x42b618, $0x3<UINT32>
0x00415099:	ret

0x00409605:	call GetCommandLineA@KERNEL32.dll
GetCommandLineA@KERNEL32.dll: API Node	
0x0040960b:	movl 0x42b73c, %eax
0x00409610:	call 0x00415384
0x00415384:	pushl %ebp
0x00415385:	movl %ebp, %esp
0x00415387:	pushl %ecx
0x00415388:	pushl %ecx
0x00415389:	cmpl 0x42b730, $0x0<UINT8>
0x00415390:	jne 5
0x00415392:	call 0x00418b0f
0x00418b0f:	cmpl 0x42b730, $0x0<UINT8>
0x00418b16:	jne 18
0x00418b18:	pushl $0xfffffffd<UINT8>
0x00418b1a:	call 0x00418ea4
0x00418ea4:	pushl $0x10<UINT8>
0x00418ea6:	pushl $0x419050<UINT32>
0x00418eab:	call 0x004023d0
0x00418eb0:	orl %edi, $0xffffffff<UINT8>
0x00418eb3:	call 0x00414770
0x00414770:	pushl %esi
0x00414771:	call 0x0041478a
0x0041478a:	pushl %esi
0x0041478b:	pushl %edi
0x0041478c:	call GetLastError@KERNEL32.dll
GetLastError@KERNEL32.dll: API Node	
0x00414792:	pushl 0x429cf0
0x00414798:	movl %edi, %eax
0x0041479a:	call FlsGetValue@KERNEL32.dll
FlsGetValue@KERNEL32.dll: API Node	
0x004147a0:	movl %esi, %eax
0x004147a2:	testl %esi, %esi
0x004147a4:	jne 0x004147ec
0x004147ec:	pushl %edi
0x004147ed:	call SetLastError@KERNEL32.dll
SetLastError@KERNEL32.dll: API Node	
0x004147f3:	popl %edi
0x004147f4:	movl %eax, %esi
0x004147f6:	popl %esi
0x004147f7:	ret

0x00414776:	movl %esi, %eax
0x00414778:	testl %esi, %esi
0x0041477a:	jne 0x00414786
0x00414786:	movl %eax, %esi
0x00414788:	popl %esi
0x00414789:	ret

0x00418eb8:	movl %ebx, %eax
0x00418eba:	movl -28(%ebp), %ebx
0x00418ebd:	call 0x00418ddb
0x00418ddb:	pushl $0xc<UINT8>
0x00418ddd:	pushl $0x418e88<UINT32>
0x00418de2:	call 0x004023d0
0x00418de7:	call 0x00414770
0x00418dec:	movl %edi, %eax
0x00418dee:	movl %ecx, 0x42a5b8
0x00418df4:	testl 0x70(%edi), %ecx
0x00418df7:	je 0x00418e18
0x00418e18:	pushl $0xd<UINT8>
0x00418e1a:	call 0x004159d4
0x00418e1f:	popl %ecx
0x00418e20:	andl -4(%ebp), $0x0<UINT8>
0x00418e24:	movl %esi, 0x68(%edi)
0x00418e27:	movl -28(%ebp), %esi
0x00418e2a:	cmpl %esi, 0x42a09c
0x00418e30:	je 0x00418e68
0x00418e68:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00418e6f:	call 0x00418e79
0x00418e79:	pushl $0xd<UINT8>
0x00418e7b:	call 0x00415b59
0x00418e80:	popl %ecx
0x00418e81:	ret

0x00418e74:	jmp 0x00418e02
0x00418e02:	testl %esi, %esi
0x00418e04:	jne 0x00418e10
0x00418e10:	movl %eax, %esi
0x00418e12:	call 0x004010d0
0x00418e17:	ret

0x00418ec2:	movl %esi, 0x68(%ebx)
0x00418ec5:	pushl 0x8(%ebp)
0x00418ec8:	call 0x00418b78
0x00418b78:	pushl %ebp
0x00418b79:	movl %ebp, %esp
0x00418b7b:	subl %esp, $0x10<UINT8>
0x00418b7e:	leal %ecx, -16(%ebp)
0x00418b81:	pushl $0x0<UINT8>
0x00418b83:	call 0x004113bf
0x004113bf:	pushl %ebp
0x004113c0:	movl %ebp, %esp
0x004113c2:	pushl %esi
0x004113c3:	movl %esi, %ecx
0x004113c5:	movl %ecx, 0x8(%ebp)
0x004113c8:	movb 0xc(%esi), $0x0<UINT8>
0x004113cc:	testl %ecx, %ecx
0x004113ce:	jne 102
0x004113d0:	call 0x00414770
0x004113d5:	movl %edx, %eax
0x004113d7:	movl 0x8(%esi), %edx
0x004113da:	movl %ecx, 0x6c(%edx)
0x004113dd:	movl (%esi), %ecx
0x004113df:	movl %ecx, 0x68(%edx)
0x004113e2:	movl 0x4(%esi), %ecx
0x004113e5:	movl %ecx, (%esi)
0x004113e7:	cmpl %ecx, 0x429e58
0x004113ed:	je 0x00411400
0x00411400:	movl %eax, 0x4(%esi)
0x00411403:	cmpl %eax, 0x42a09c
0x00411409:	je 0x00411420
0x00411420:	movl %ecx, 0x8(%esi)
0x00411423:	movl %eax, 0x70(%ecx)
0x00411426:	testb %al, $0x2<UINT8>
0x00411428:	jne 22
0x0041142a:	orl %eax, $0x2<UINT8>
0x0041142d:	movl 0x70(%ecx), %eax
0x00411430:	movb 0xc(%esi), $0x1<UINT8>
0x00411434:	jmp 0x00411440
0x00411440:	movl %eax, %esi
0x00411442:	popl %esi
0x00411443:	popl %ebp
0x00411444:	ret $0x4<UINT16>

0x00418b88:	movl %eax, 0x8(%ebp)
0x00418b8b:	andl 0x42b4ec, $0x0<UINT8>
0x00418b92:	cmpl %eax, $0xfffffffe<UINT8>
0x00418b95:	jne 0x00418ba9
0x00418ba9:	cmpl %eax, $0xfffffffd<UINT8>
0x00418bac:	jne 0x00418bc0
0x00418bae:	movl 0x42b4ec, $0x1<UINT32>
0x00418bb8:	call GetACP@KERNEL32.dll
GetACP@KERNEL32.dll: API Node	
0x00418bbe:	jmp 0x00418bd5
0x00418bd5:	cmpb -4(%ebp), $0x0<UINT8>
0x00418bd9:	je 7
0x00418bdb:	movl %ecx, -8(%ebp)
0x00418bde:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00418be2:	leave
0x00418be3:	ret

0x00418ecd:	popl %ecx
0x00418ece:	movl 0x8(%ebp), %eax
0x00418ed1:	cmpl %eax, 0x4(%esi)
0x00418ed4:	je 364
0x00418eda:	pushl $0x220<UINT32>
0x00418edf:	call 0x00415bb8
0x00415bb8:	pushl %ebp
0x00415bb9:	movl %ebp, %esp
0x00415bbb:	pushl %ebx
0x00415bbc:	pushl %esi
0x00415bbd:	pushl %edi
0x00415bbe:	movl %edi, 0x42b4d0
0x00415bc4:	xorl %esi, %esi
0x00415bc6:	pushl 0x8(%ebp)
0x00415bc9:	call 0x004143dc
0x004143dc:	pushl %ebp
0x004143dd:	movl %ebp, %esp
0x004143df:	pushl %esi
0x004143e0:	movl %esi, 0x8(%ebp)
0x004143e3:	cmpl %esi, $0xffffffe0<UINT8>
0x004143e6:	ja 113
0x004143e8:	pushl %ebx
0x004143e9:	pushl %edi
0x004143ea:	movl %eax, 0x42b260
0x004143ef:	testl %eax, %eax
0x004143f1:	jne 0x00414412
0x00414412:	testl %esi, %esi
0x00414414:	je 4
0x00414416:	movl %ecx, %esi
0x00414418:	jmp 0x0041441d
0x0041441d:	pushl %ecx
0x0041441e:	pushl $0x0<UINT8>
0x00414420:	pushl %eax
0x00414421:	call HeapAlloc@KERNEL32.dll
0x00414427:	movl %edi, %eax
0x00414429:	testl %edi, %edi
0x0041442b:	jne 0x00414453
0x00414453:	movl %eax, %edi
0x00414455:	popl %edi
0x00414456:	popl %ebx
0x00414457:	jmp 0x0041446d
0x0041446d:	popl %esi
0x0041446e:	popl %ebp
0x0041446f:	ret

0x00415bce:	movl %ebx, %eax
0x00415bd0:	popl %ecx
0x00415bd1:	testl %ebx, %ebx
0x00415bd3:	jne 0x00415bfa
0x00415bfa:	popl %edi
0x00415bfb:	popl %esi
0x00415bfc:	movl %eax, %ebx
0x00415bfe:	popl %ebx
0x00415bff:	popl %ebp
0x00415c00:	ret

0x00418ee4:	popl %ecx
0x00418ee5:	movl %ebx, %eax
0x00418ee7:	testl %ebx, %ebx
0x00418ee9:	je 345
0x00418eef:	movl %ecx, $0x88<UINT32>
0x00418ef4:	movl %eax, -28(%ebp)
0x00418ef7:	movl %esi, 0x68(%eax)
0x00418efa:	movl %edi, %ebx
0x00418efc:	rep movsl %es:(%edi), %ds:(%esi)
0x00418efe:	xorl %esi, %esi
0x00418f00:	movl (%ebx), %esi
0x00418f02:	pushl %ebx
0x00418f03:	pushl 0x8(%ebp)
0x00418f06:	call 0x0041906c
0x0041906c:	pushl %ebp
0x0041906d:	movl %ebp, %esp
0x0041906f:	subl %esp, $0x20<UINT8>
0x00419072:	movl %eax, 0x427040
0x00419077:	xorl %eax, %ebp
0x00419079:	movl -4(%ebp), %eax
0x0041907c:	pushl %ebx
0x0041907d:	pushl %esi
0x0041907e:	pushl 0x8(%ebp)
0x00419081:	movl %esi, 0xc(%ebp)
0x00419084:	call 0x00418b78
0x00418bc0:	cmpl %eax, $0xfffffffc<UINT8>
0x00418bc3:	jne 0x00418bd5
0x00419089:	movl %ebx, %eax
0x0041908b:	popl %ecx
0x0041908c:	movl -32(%ebp), %ebx
0x0041908f:	testl %ebx, %ebx
0x00419091:	jne 0x004190a1
0x004190a1:	pushl %edi
0x004190a2:	xorl %edi, %edi
0x004190a4:	movl %ecx, %edi
0x004190a6:	movl -28(%ebp), %ecx
0x004190a9:	movl %eax, %edi
0x004190ab:	cmpl 0x42a0a0(%eax), %ebx
0x004190b1:	je 242
0x004190b7:	incl %ecx
0x004190b8:	addl %eax, $0x30<UINT8>
0x004190bb:	movl -28(%ebp), %ecx
0x004190be:	cmpl %eax, $0xf0<UINT32>
0x004190c3:	jb 0x004190ab
0x004190c5:	cmpl %ebx, $0xfde8<UINT32>
0x004190cb:	je 208
0x004190d1:	cmpl %ebx, $0xfde9<UINT32>
0x004190d7:	je 196
0x004190dd:	movzwl %eax, %bx
0x004190e0:	pushl %eax
0x004190e1:	call IsValidCodePage@KERNEL32.dll
IsValidCodePage@KERNEL32.dll: API Node	
0x004190e7:	testl %eax, %eax
0x004190e9:	je 178
0x004190ef:	leal %eax, -24(%ebp)
0x004190f2:	pushl %eax
0x004190f3:	pushl %ebx
0x004190f4:	call GetCPInfo@KERNEL32.dll
GetCPInfo@KERNEL32.dll: API Node	
0x004190fa:	testl %eax, %eax
0x004190fc:	je 140
0x00419102:	pushl $0x101<UINT32>
0x00419107:	leal %eax, 0x18(%esi)
0x0041910a:	pushl %edi
0x0041910b:	pushl %eax
0x0041910c:	call 0x0040124a
0x00405c4f:	movb (%edi), %al
0x00405c51:	addl %edi, $0x1<UINT8>
0x00405c54:	subl %edx, $0x1<UINT8>
0x00405c57:	jne -10
0x00419111:	movl 0x4(%esi), %ebx
0x00419114:	xorl %ebx, %ebx
0x00419116:	incl %ebx
0x00419117:	addl %esp, $0xc<UINT8>
0x0041911a:	movl 0x21c(%esi), %edi
0x00419120:	cmpl -24(%ebp), %ebx
0x00419123:	jbe 79
0x00419125:	cmpb -18(%ebp), $0x0<UINT8>
0x00419129:	leal %eax, -18(%ebp)
0x0041912c:	je 0x0041914f
0x0041914f:	leal %eax, 0x1a(%esi)
0x00419152:	movl %ecx, $0xfe<UINT32>
0x00419157:	orb (%eax), $0x8<UINT8>
0x0041915a:	incl %eax
0x0041915b:	decl %ecx
0x0041915c:	jne 0x00419157
0x0041915e:	pushl 0x4(%esi)
0x00419161:	call 0x00418b2d
0x00418b2d:	pushl %ebp
0x00418b2e:	movl %ebp, %esp
0x00418b30:	movl %eax, 0x8(%ebp)
0x00418b33:	subl %eax, $0x3a4<UINT32>
0x00418b38:	je 38
0x00418b3a:	subl %eax, $0x4<UINT8>
0x00418b3d:	je 26
0x00418b3f:	subl %eax, $0xd<UINT8>
0x00418b42:	je 14
0x00418b44:	decl %eax
0x00418b45:	je 4
0x00418b47:	xorl %eax, %eax
0x00418b49:	popl %ebp
0x00418b4a:	ret

0x00419166:	addl %esp, $0x4<UINT8>
0x00419169:	movl 0x21c(%esi), %eax
0x0041916f:	movl 0x8(%esi), %ebx
0x00419172:	jmp 0x00419177
0x00419177:	xorl %eax, %eax
0x00419179:	movzwl %ecx, %ax
0x0041917c:	movl %eax, %ecx
0x0041917e:	shll %ecx, $0x10<UINT8>
0x00419181:	orl %eax, %ecx
0x00419183:	leal %edi, 0xc(%esi)
0x00419186:	stosl %es:(%edi), %eax
0x00419187:	stosl %es:(%edi), %eax
0x00419188:	stosl %es:(%edi), %eax
0x00419189:	jmp 0x00419249
0x00419249:	pushl %esi
0x0041924a:	call 0x00418c4d
0x00418c4d:	pushl %ebp
0x00418c4e:	movl %ebp, %esp
0x00418c50:	subl %esp, $0x520<UINT32>
0x00418c56:	movl %eax, 0x427040
0x00418c5b:	xorl %eax, %ebp
0x00418c5d:	movl -4(%ebp), %eax
0x00418c60:	pushl %ebx
0x00418c61:	pushl %esi
0x00418c62:	movl %esi, 0x8(%ebp)
0x00418c65:	pushl %edi
0x00418c66:	leal %eax, -1304(%ebp)
0x00418c6c:	pushl %eax
0x00418c6d:	pushl 0x4(%esi)
0x00418c70:	call GetCPInfo@KERNEL32.dll
0x00418c76:	xorl %ebx, %ebx
0x00418c78:	movl %edi, $0x100<UINT32>
0x00418c7d:	testl %eax, %eax
0x00418c7f:	je 240
0x00418c85:	movl %eax, %ebx
0x00418c87:	movb -260(%ebp,%eax), %al
0x00418c8e:	incl %eax
0x00418c8f:	cmpl %eax, %edi
0x00418c91:	jb 0x00418c87
0x00418c93:	movb %al, -1298(%ebp)
0x00418c99:	movb -260(%ebp), $0x20<UINT8>
0x00418ca0:	leal %ecx, -1298(%ebp)
0x00418ca6:	jmp 0x00418cc7
0x00418cc7:	testb %al, %al
0x00418cc9:	jne -35
0x00418ccb:	pushl %ebx
0x00418ccc:	pushl 0x4(%esi)
0x00418ccf:	leal %eax, -1284(%ebp)
0x00418cd5:	pushl %eax
0x00418cd6:	pushl %edi
0x00418cd7:	leal %eax, -260(%ebp)
0x00418cdd:	pushl %eax
0x00418cde:	pushl $0x1<UINT8>
0x00418ce0:	pushl %ebx
0x00418ce1:	call 0x0041b710
0x0041b710:	pushl %ebp
0x0041b711:	movl %ebp, %esp
0x0041b713:	subl %esp, $0x10<UINT8>
0x0041b716:	pushl 0x8(%ebp)
0x0041b719:	leal %ecx, -16(%ebp)
0x0041b71c:	call 0x004113bf
0x0041b721:	pushl 0x20(%ebp)
0x0041b724:	leal %eax, -16(%ebp)
0x0041b727:	pushl 0x1c(%ebp)
0x0041b72a:	pushl 0x18(%ebp)
0x0041b72d:	pushl 0x14(%ebp)
0x0041b730:	pushl 0x10(%ebp)
0x0041b733:	pushl 0xc(%ebp)
0x0041b736:	pushl %eax
0x0041b737:	call 0x0041b624
0x0041b624:	pushl %ebp
0x0041b625:	movl %ebp, %esp
0x0041b627:	pushl %ecx
0x0041b628:	movl %eax, 0x427040
0x0041b62d:	xorl %eax, %ebp
0x0041b62f:	movl -4(%ebp), %eax
0x0041b632:	movl %ecx, 0x1c(%ebp)
0x0041b635:	pushl %ebx
0x0041b636:	pushl %esi
0x0041b637:	pushl %edi
0x0041b638:	xorl %edi, %edi
0x0041b63a:	testl %ecx, %ecx
0x0041b63c:	jne 0x0041b64b
0x0041b64b:	xorl %eax, %eax
0x0041b64d:	cmpl 0x20(%ebp), %eax
0x0041b650:	pushl %edi
0x0041b651:	pushl %edi
0x0041b652:	pushl 0x14(%ebp)
0x0041b655:	setne %al
0x0041b658:	pushl 0x10(%ebp)
0x0041b65b:	leal %eax, 0x1(,%eax,8)
0x0041b662:	pushl %eax
0x0041b663:	pushl %ecx
0x0041b664:	call MultiByteToWideChar@KERNEL32.dll
MultiByteToWideChar@KERNEL32.dll: API Node	
0x0041b66a:	movl %ebx, %eax
0x0041b66c:	testl %ebx, %ebx
0x0041b66e:	jne 0x0041b677
0x0041b677:	jle 65
0x0041b679:	cmpl %ebx, $0x7ffffff0<UINT32>
0x0041b67f:	ja 57
0x0041b681:	leal %eax, 0x8(,%ebx,2)
0x0041b688:	cmpl %eax, $0x400<UINT32>
0x0041b68d:	ja 19
0x0041b68f:	call 0x004027f9
0x004027f9:	pushl %ecx
0x004027fa:	leal %ecx, 0x8(%esp)
0x004027fe:	subl %ecx, %eax
0x00402800:	andl %ecx, $0xf<UINT8>
0x00402803:	addl %eax, %ecx
0x00402805:	sbbl %ecx, %ecx
0x00402807:	orl %eax, %ecx
0x00402809:	popl %ecx
0x0040280a:	jmp 0x0040280c
0x0040280c:	pushl %ecx
0x0040280d:	leal %ecx, 0x4(%esp)
0x00402811:	subl %ecx, %eax
0x00402813:	sbbl %eax, %eax
0x00402815:	notl %eax
0x00402817:	andl %ecx, %eax
0x00402819:	movl %eax, %esp
0x0040281b:	andl %eax, $0xfffff000<UINT32>
0x00402820:	cmpl %ecx, %eax
0x00402822:	jb -5631
0x00402828:	movl %eax, %ecx
0x0040282a:	popl %ecx
0x0040282b:	xchgl %esp, %eax
0x0040282c:	movl %eax, (%eax)
0x0040282e:	movl (%esp), %eax
0x00402831:	ret

0x0041b694:	movl %esi, %esp
0x0041b696:	testl %esi, %esi
0x0041b698:	je -42
0x0041b69a:	movl (%esi), $0xcccc<UINT32>
0x0041b6a0:	jmp 0x0041b6b5
0x0041b6b5:	addl %esi, $0x8<UINT8>
0x0041b6b8:	jmp 0x0041b6bc
0x0041b6bc:	testl %esi, %esi
0x0041b6be:	je -80
0x0041b6c0:	leal %eax, (%ebx,%ebx)
0x0041b6c3:	pushl %eax
0x0041b6c4:	pushl %edi
0x0041b6c5:	pushl %esi
0x0041b6c6:	call 0x0040124a
0x0041b6cb:	addl %esp, $0xc<UINT8>
0x0041b6ce:	pushl %ebx
0x0041b6cf:	pushl %esi
0x0041b6d0:	pushl 0x14(%ebp)
0x0041b6d3:	pushl 0x10(%ebp)
0x0041b6d6:	pushl $0x1<UINT8>
0x0041b6d8:	pushl 0x1c(%ebp)
0x0041b6db:	call MultiByteToWideChar@KERNEL32.dll
0x0041b6e1:	testl %eax, %eax
0x0041b6e3:	je 16
0x0041b6e5:	pushl 0x18(%ebp)
0x0041b6e8:	pushl %eax
0x0041b6e9:	pushl %esi
0x0041b6ea:	pushl 0xc(%ebp)
0x0041b6ed:	call GetStringTypeW@KERNEL32.dll
GetStringTypeW@KERNEL32.dll: API Node	
0x0041b6f3:	movl %edi, %eax
0x0041b6f5:	pushl %esi
0x0041b6f6:	call 0x0041339d
0x0041339d:	pushl %ebp
0x0041339e:	movl %ebp, %esp
0x004133a0:	movl %eax, 0x8(%ebp)
0x004133a3:	testl %eax, %eax
0x004133a5:	je 18
0x004133a7:	subl %eax, $0x8<UINT8>
0x004133aa:	cmpl (%eax), $0xdddd<UINT32>
0x004133b0:	jne 0x004133b9
0x004133b9:	popl %ebp
0x004133ba:	ret

0x0041b6fb:	popl %ecx
0x0041b6fc:	movl %eax, %edi
0x0041b6fe:	leal %esp, -16(%ebp)
0x0041b701:	popl %edi
0x0041b702:	popl %esi
0x0041b703:	popl %ebx
0x0041b704:	movl %ecx, -4(%ebp)
0x0041b707:	xorl %ecx, %ebp
0x0041b709:	call 0x00402258
0x00402258:	cmpl %ecx, 0x427040
0x0040225e:	jne 61326
0x00402264:	rep ret

0x0041b70e:	leave
0x0041b70f:	ret

0x0041b73c:	addl %esp, $0x1c<UINT8>
0x0041b73f:	cmpb -4(%ebp), $0x0<UINT8>
0x0041b743:	je 7
0x0041b745:	movl %ecx, -8(%ebp)
0x0041b748:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0041b74c:	leave
0x0041b74d:	ret

0x00418ce6:	pushl %ebx
0x00418ce7:	pushl 0x4(%esi)
0x00418cea:	leal %eax, -516(%ebp)
0x00418cf0:	pushl %edi
0x00418cf1:	pushl %eax
0x00418cf2:	pushl %edi
0x00418cf3:	leal %eax, -260(%ebp)
0x00418cf9:	pushl %eax
0x00418cfa:	pushl %edi
0x00418cfb:	pushl 0x21c(%esi)
0x00418d01:	pushl %ebx
0x00418d02:	call 0x00420404
0x00420404:	pushl %ebp
0x00420405:	movl %ebp, %esp
0x00420407:	subl %esp, $0x10<UINT8>
0x0042040a:	pushl 0x8(%ebp)
0x0042040d:	leal %ecx, -16(%ebp)
0x00420410:	call 0x004113bf
0x00420415:	pushl 0x28(%ebp)
0x00420418:	leal %eax, -16(%ebp)
0x0042041b:	pushl 0x24(%ebp)
0x0042041e:	pushl 0x20(%ebp)
0x00420421:	pushl 0x1c(%ebp)
0x00420424:	pushl 0x18(%ebp)
0x00420427:	pushl 0x14(%ebp)
0x0042042a:	pushl 0x10(%ebp)
0x0042042d:	pushl 0xc(%ebp)
0x00420430:	pushl %eax
0x00420431:	call 0x00420213
0x00420213:	pushl %ebp
0x00420214:	movl %ebp, %esp
0x00420216:	pushl %ecx
0x00420217:	pushl %ecx
0x00420218:	movl %eax, 0x427040
0x0042021d:	xorl %eax, %ebp
0x0042021f:	movl -4(%ebp), %eax
0x00420222:	pushl %ebx
0x00420223:	pushl %esi
0x00420224:	movl %esi, 0x18(%ebp)
0x00420227:	pushl %edi
0x00420228:	testl %esi, %esi
0x0042022a:	jle 33
0x0042022c:	movl %eax, 0x14(%ebp)
0x0042022f:	movl %ecx, %esi
0x00420231:	decl %ecx
0x00420232:	cmpb (%eax), $0x0<UINT8>
0x00420235:	je 8
0x00420237:	incl %eax
0x00420238:	testl %ecx, %ecx
0x0042023a:	jne 0x00420231
0x0042023c:	orl %ecx, $0xffffffff<UINT8>
0x0042023f:	movl %eax, %esi
0x00420241:	subl %eax, %ecx
0x00420243:	decl %eax
0x00420244:	cmpl %eax, %esi
0x00420246:	leal %esi, 0x1(%eax)
0x00420249:	jl 2
0x0042024b:	movl %esi, %eax
0x0042024d:	movl %ecx, 0x24(%ebp)
0x00420250:	xorl %ebx, %ebx
0x00420252:	testl %ecx, %ecx
0x00420254:	jne 0x00420263
0x00420263:	xorl %eax, %eax
0x00420265:	cmpl 0x28(%ebp), %eax
0x00420268:	pushl $0x0<UINT8>
0x0042026a:	setne %al
0x0042026d:	pushl $0x0<UINT8>
0x0042026f:	pushl %esi
0x00420270:	pushl 0x14(%ebp)
0x00420273:	leal %eax, 0x1(,%eax,8)
0x0042027a:	pushl %eax
0x0042027b:	pushl %ecx
0x0042027c:	call MultiByteToWideChar@KERNEL32.dll
0x00420282:	movl %ecx, %eax
0x00420284:	movl -8(%ebp), %ecx
0x00420287:	testl %ecx, %ecx
0x00420289:	jne 0x00420292
0x00420292:	jle 75
0x00420294:	pushl $0xffffffe0<UINT8>
0x00420296:	xorl %edx, %edx
0x00420298:	popl %eax
0x00420299:	divl %eax, %ecx
0x0042029b:	cmpl %eax, $0x2<UINT8>
0x0042029e:	jb 63
0x004202a0:	leal %ecx, 0x8(,%ecx,2)
0x004202a7:	cmpl %ecx, $0x400<UINT32>
0x004202ad:	ja 21
0x004202af:	movl %eax, %ecx
0x004202b1:	call 0x004027f9
0x004202b6:	movl %edi, %esp
0x004202b8:	testl %edi, %edi
0x004202ba:	je 30
0x004202bc:	movl (%edi), $0xcccc<UINT32>
0x004202c2:	jmp 0x004202d7
0x004202d7:	addl %edi, $0x8<UINT8>
0x004202da:	movl %ecx, -8(%ebp)
0x004202dd:	jmp 0x004202e1
0x004202e1:	testl %edi, %edi
0x004202e3:	je -90
0x004202e5:	pushl %ecx
0x004202e6:	pushl %edi
0x004202e7:	pushl %esi
0x004202e8:	pushl 0x14(%ebp)
0x004202eb:	pushl $0x1<UINT8>
0x004202ed:	pushl 0x24(%ebp)
0x004202f0:	call MultiByteToWideChar@KERNEL32.dll
0x004202f6:	testl %eax, %eax
0x004202f8:	je 235
0x004202fe:	movl %esi, -8(%ebp)
0x00420301:	xorl %eax, %eax
0x00420303:	pushl %eax
0x00420304:	pushl %eax
0x00420305:	pushl %eax
0x00420306:	pushl %eax
0x00420307:	pushl %eax
0x00420308:	pushl %esi
0x00420309:	pushl %edi
0x0042030a:	pushl 0x10(%ebp)
0x0042030d:	pushl 0xc(%ebp)
0x00420310:	call LCMapStringEx@KERNEL32.dll
LCMapStringEx@KERNEL32.dll: API Node	
0x00420316:	movl %ebx, %eax
0x00420318:	testl %ebx, %ebx
0x0042031a:	je 0x004203e9
0x00420320:	movl %ecx, $0x400<UINT32>
0x004203e9:	pushl %edi
0x004203ea:	call 0x0041339d
0x004203ef:	popl %ecx
0x004203f0:	movl %eax, %ebx
0x004203f2:	leal %esp, -20(%ebp)
0x004203f5:	popl %edi
0x004203f6:	popl %esi
0x004203f7:	popl %ebx
0x004203f8:	movl %ecx, -4(%ebp)
0x004203fb:	xorl %ecx, %ebp
0x004203fd:	call 0x00402258
0x00420402:	leave
0x00420403:	ret

0x00420436:	addl %esp, $0x24<UINT8>
0x00420439:	cmpb -4(%ebp), $0x0<UINT8>
0x0042043d:	je 7
0x0042043f:	movl %ecx, -8(%ebp)
0x00420442:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00420446:	leave
0x00420447:	ret

0x00418d07:	addl %esp, $0x40<UINT8>
0x00418d0a:	leal %eax, -772(%ebp)
0x00418d10:	pushl %ebx
0x00418d11:	pushl 0x4(%esi)
0x00418d14:	pushl %edi
0x00418d15:	pushl %eax
0x00418d16:	pushl %edi
0x00418d17:	leal %eax, -260(%ebp)
0x00418d1d:	pushl %eax
0x00418d1e:	pushl $0x200<UINT32>
0x00418d23:	pushl 0x21c(%esi)
0x00418d29:	pushl %ebx
0x00418d2a:	call 0x00420404
0x00418d2f:	addl %esp, $0x24<UINT8>
0x00418d32:	movl %ecx, %ebx
0x00418d34:	movzwl %eax, -1284(%ebp,%ecx,2)
0x00418d3c:	testb %al, $0x1<UINT8>
0x00418d3e:	je 0x00418d4e
0x00418d4e:	testb %al, $0x2<UINT8>
0x00418d50:	je 0x00418d67
0x00418d67:	movb 0x119(%esi,%ecx), %bl
0x00418d6e:	incl %ecx
0x00418d6f:	cmpl %ecx, %edi
0x00418d71:	jae 0x00418dcc
0x00418dcc:	movl %ecx, -4(%ebp)
0x00418dcf:	popl %edi
0x00418dd0:	popl %esi
0x00418dd1:	xorl %ecx, %ebp
0x00418dd3:	popl %ebx
0x00418dd4:	call 0x00402258
0x00418dd9:	leave
0x00418dda:	ret

0x0041924f:	popl %ecx
0x00419250:	xorl %eax, %eax
0x00419252:	popl %edi
0x00419253:	movl %ecx, -4(%ebp)
0x00419256:	popl %esi
0x00419257:	xorl %ecx, %ebp
0x00419259:	popl %ebx
0x0041925a:	call 0x00402258
0x0041925f:	leave
0x00419260:	ret

0x00418f0b:	popl %ecx
0x00418f0c:	popl %ecx
0x00418f0d:	movl %edi, %eax
0x00418f0f:	movl 0x8(%ebp), %edi
0x00418f12:	testl %edi, %edi
0x00418f14:	jne 267
0x00418f1a:	movl %eax, -28(%ebp)
0x00418f1d:	pushl 0x68(%eax)
0x00418f20:	call InterlockedDecrement@KERNEL32.dll
InterlockedDecrement@KERNEL32.dll: API Node	
0x00418f26:	testl %eax, %eax
0x00418f28:	movl %eax, -28(%ebp)
0x00418f2b:	jne 21
0x00418f2d:	movl %ecx, 0x68(%eax)
0x00418f30:	cmpl %ecx, $0x42a398<UINT32>
0x00418f36:	je 0x00418f42
0x00418f42:	movl 0x68(%eax), %ebx
0x00418f45:	pushl %ebx
0x00418f46:	call InterlockedIncrement@KERNEL32.dll
0x00418f4c:	movl %eax, -28(%ebp)
0x00418f4f:	testb 0x70(%eax), $0x2<UINT8>
0x00418f53:	jne 239
0x00418f59:	testb 0x42a5b8, $0x1<UINT8>
0x00418f60:	jne 226
0x00418f66:	pushl $0xd<UINT8>
0x00418f68:	call 0x004159d4
0x00418f6d:	popl %ecx
0x00418f6e:	movl -4(%ebp), %esi
0x00418f71:	movl %eax, 0x4(%ebx)
0x00418f74:	movl 0x42b4d8, %eax
0x00418f79:	movl %eax, 0x8(%ebx)
0x00418f7c:	movl 0x42b4dc, %eax
0x00418f81:	movl %eax, 0x21c(%ebx)
0x00418f87:	movl 0x42b4d4, %eax
0x00418f8c:	movl %ecx, %esi
0x00418f8e:	movl -32(%ebp), %ecx
0x00418f91:	cmpl %ecx, $0x5<UINT8>
0x00418f94:	jnl 0x00418fa6
0x00418f96:	movw %ax, 0xc(%ebx,%ecx,2)
0x00418f9b:	movw 0x42b4e0(,%ecx,2), %ax
0x00418fa3:	incl %ecx
0x00418fa4:	jmp 0x00418f8e
0x00418fa6:	movl %ecx, %esi
0x00418fa8:	movl -32(%ebp), %ecx
0x00418fab:	cmpl %ecx, $0x101<UINT32>
0x00418fb1:	jnl 0x00418fc0
0x00418fb3:	movb %al, 0x18(%ecx,%ebx)
0x00418fb7:	movb 0x42a190(%ecx), %al
0x00418fbd:	incl %ecx
0x00418fbe:	jmp 0x00418fa8
0x00418fc0:	movl -32(%ebp), %esi
0x00418fc3:	cmpl %esi, $0x100<UINT32>
0x00418fc9:	jnl 0x00418fdb
0x00418fcb:	movb %al, 0x119(%esi,%ebx)
0x00418fd2:	movb 0x42a298(%esi), %al
0x00418fd8:	incl %esi
0x00418fd9:	jmp 0x00418fc0
0x00418fdb:	pushl 0x42a09c
0x00418fe1:	call InterlockedDecrement@KERNEL32.dll
0x00418fe7:	testl %eax, %eax
0x00418fe9:	jne 0x00418ffe
0x00418ffe:	movl 0x42a09c, %ebx
0x00419004:	pushl %ebx
0x00419005:	call InterlockedIncrement@KERNEL32.dll
0x0041900b:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00419012:	call 0x0041901c
0x0041901c:	pushl $0xd<UINT8>
0x0041901e:	call 0x00415b59
0x00419023:	popl %ecx
0x00419024:	ret

0x00419017:	jmp 0x00419048
0x00419048:	movl %eax, %edi
0x0041904a:	call 0x004010d0
0x0041904f:	ret

0x00418b1f:	popl %ecx
0x00418b20:	movl 0x42b730, $0x1<UINT32>
0x00418b2a:	xorl %eax, %eax
0x00418b2c:	ret

0x00415397:	pushl %ebx
0x00415398:	pushl %esi
0x00415399:	pushl %edi
0x0041539a:	pushl $0x104<UINT32>
0x0041539f:	movl %edi, $0x42b268<UINT32>
0x004153a4:	xorl %ebx, %ebx
0x004153a6:	pushl %edi
0x004153a7:	pushl %ebx
0x004153a8:	movb 0x42b36c, %bl
0x004153ae:	call GetModuleFileNameA@KERNEL32.dll
GetModuleFileNameA@KERNEL32.dll: API Node	
0x004153b4:	movl %esi, 0x42b73c
0x004153ba:	movl 0x42ac20, %edi
0x004153c0:	testl %esi, %esi
0x004153c2:	je 4
0x004153c4:	cmpb (%esi), %bl
0x004153c6:	jne 0x004153ca
0x004153ca:	leal %eax, -8(%ebp)
0x004153cd:	pushl %eax
0x004153ce:	leal %eax, -4(%ebp)
0x004153d1:	pushl %eax
0x004153d2:	pushl %ebx
0x004153d3:	pushl %ebx
0x004153d4:	pushl %esi
0x004153d5:	call 0x00415435
0x00415435:	pushl %ebp
0x00415436:	movl %ebp, %esp
0x00415438:	movl %eax, 0x14(%ebp)
0x0041543b:	pushl %ebx
0x0041543c:	movl %ebx, 0x18(%ebp)
0x0041543f:	pushl %esi
0x00415440:	andl (%ebx), $0x0<UINT8>
0x00415443:	movl %esi, 0x8(%ebp)
0x00415446:	movl (%eax), $0x1<UINT32>
0x0041544c:	movl %eax, 0xc(%ebp)
0x0041544f:	pushl %edi
0x00415450:	movl %edi, 0x10(%ebp)
0x00415453:	testl %eax, %eax
0x00415455:	je 0x0041545f
0x0041545f:	xorl %ecx, %ecx
0x00415461:	movl 0x8(%ebp), %ecx
0x00415464:	cmpb (%esi), $0x22<UINT8>
0x00415467:	jne 0x0041547a
0x00415469:	xorl %eax, %eax
0x0041546b:	testl %ecx, %ecx
0x0041546d:	sete %al
0x00415470:	incl %esi
0x00415471:	movl %ecx, %eax
0x00415473:	movl 0x8(%ebp), %ecx
0x00415476:	movb %al, $0x22<UINT8>
0x00415478:	jmp 0x004154af
0x004154af:	testl %ecx, %ecx
0x004154b1:	jne 0x00415464
0x0041547a:	incl (%ebx)
0x0041547c:	testl %edi, %edi
0x0041547e:	je 0x00415485
0x00415485:	movb %al, (%esi)
0x00415487:	movb 0x1b(%ebp), %al
0x0041548a:	movzbl %eax, %al
0x0041548d:	pushl %eax
0x0041548e:	incl %esi
0x0041548f:	call 0x0041c832
0x0041c832:	pushl %ebp
0x0041c833:	movl %ebp, %esp
0x0041c835:	pushl $0x4<UINT8>
0x0041c837:	pushl $0x0<UINT8>
0x0041c839:	pushl 0x8(%ebp)
0x0041c83c:	pushl $0x0<UINT8>
0x0041c83e:	call 0x0041c7dc
0x0041c7dc:	pushl %ebp
0x0041c7dd:	movl %ebp, %esp
0x0041c7df:	subl %esp, $0x10<UINT8>
0x0041c7e2:	pushl %esi
0x0041c7e3:	pushl 0x8(%ebp)
0x0041c7e6:	leal %ecx, -16(%ebp)
0x0041c7e9:	call 0x004113bf
0x0041c7ee:	movzbl %esi, 0xc(%ebp)
0x0041c7f2:	movl %eax, -12(%ebp)
0x0041c7f5:	movb %cl, 0x14(%ebp)
0x0041c7f8:	testb 0x19(%eax,%esi), %cl
0x0041c7fc:	jne 31
0x0041c7fe:	xorl %edx, %edx
0x0041c800:	cmpl 0x10(%ebp), %edx
0x0041c803:	je 0x0041c817
0x0041c817:	movl %eax, %edx
0x0041c819:	testl %eax, %eax
0x0041c81b:	je 0x0041c820
0x0041c820:	cmpb -4(%ebp), $0x0<UINT8>
0x0041c824:	popl %esi
0x0041c825:	je 7
0x0041c827:	movl %ecx, -8(%ebp)
0x0041c82a:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0041c82e:	movl %eax, %edx
0x0041c830:	leave
0x0041c831:	ret

0x0041c843:	addl %esp, $0x10<UINT8>
0x0041c846:	popl %ebp
0x0041c847:	ret

0x00415494:	popl %ecx
0x00415495:	testl %eax, %eax
0x00415497:	je 0x004154a5
0x004154a5:	movb %al, 0x1b(%ebp)
0x004154a8:	testb %al, %al
0x004154aa:	je 0x004154c5
0x004154ac:	movl %ecx, 0x8(%ebp)
0x004154b3:	cmpb %al, $0x20<UINT8>
0x004154b5:	je 4
0x004154b7:	cmpb %al, $0x9<UINT8>
0x004154b9:	jne 0x00415464
0x004154c5:	decl %esi
0x004154c6:	andl 0x18(%ebp), $0x0<UINT8>
0x004154ca:	cmpb (%esi), $0x0<UINT8>
0x004154cd:	je 0x0041559d
0x0041559d:	movl %edx, 0xc(%ebp)
0x004155a0:	popl %edi
0x004155a1:	popl %esi
0x004155a2:	popl %ebx
0x004155a3:	testl %edx, %edx
0x004155a5:	je 0x004155aa
0x004155aa:	movl %eax, 0x14(%ebp)
0x004155ad:	incl (%eax)
0x004155af:	popl %ebp
0x004155b0:	ret

0x004153da:	movl %ebx, -4(%ebp)
0x004153dd:	addl %esp, $0x14<UINT8>
0x004153e0:	cmpl %ebx, $0x3fffffff<UINT32>
0x004153e6:	jae 69
0x004153e8:	movl %ecx, -8(%ebp)
0x004153eb:	cmpl %ecx, $0xffffffff<UINT8>
0x004153ee:	jae 61
0x004153f0:	leal %edx, (%ecx,%ebx,4)
0x004153f3:	cmpl %edx, %ecx
0x004153f5:	jb 54
0x004153f7:	pushl %edx
0x004153f8:	call 0x00415bb8
0x004153fd:	movl %edi, %eax
0x004153ff:	popl %ecx
0x00415400:	testl %edi, %edi
0x00415402:	je 41
0x00415404:	leal %eax, -8(%ebp)
0x00415407:	pushl %eax
0x00415408:	leal %eax, -4(%ebp)
0x0041540b:	pushl %eax
0x0041540c:	leal %eax, (%edi,%ebx,4)
0x0041540f:	pushl %eax
0x00415410:	pushl %edi
0x00415411:	pushl %esi
0x00415412:	call 0x00415435
0x00415457:	movl (%eax), %edi
0x00415459:	addl %eax, $0x4<UINT8>
0x0041545c:	movl 0xc(%ebp), %eax
0x00415480:	movb %al, (%esi)
0x00415482:	movb (%edi), %al
0x00415484:	incl %edi
0x004155a7:	andl (%edx), $0x0<UINT8>
0x00415417:	movl %eax, -4(%ebp)
0x0041541a:	addl %esp, $0x14<UINT8>
0x0041541d:	decl %eax
0x0041541e:	movl 0x4282d4, %eax
0x00415423:	movl 0x4282d8, %edi
0x00415429:	xorl %eax, %eax
0x0041542b:	jmp 0x00415430
0x00415430:	popl %edi
0x00415431:	popl %esi
0x00415432:	popl %ebx
0x00415433:	leave
0x00415434:	ret

0x00409615:	testl %eax, %eax
0x00409617:	jns 0x00409623
0x00409623:	call 0x004155b1
0x004155b1:	cmpl 0x42b730, $0x0<UINT8>
0x004155b8:	jne 0x004155bf
0x004155bf:	movl %eax, 0x42b370
0x004155c4:	pushl %esi
0x004155c5:	pushl %edi
0x004155c6:	xorl %edi, %edi
0x004155c8:	testl %eax, %eax
0x004155ca:	je 0x004155d3
0x004155d3:	call 0x0041fb8c
0x0041fb8c:	addb (%eax), %al
0x004156ac:	pushl %ebp
0x004156ad:	movl %ebp, %esp
0x004156af:	subl %esp, $0x18<UINT8>
0x004156b2:	pushl %ebx
0x004156b3:	movl %ebx, 0xc(%ebp)
0x004156b6:	pushl %esi
0x004156b7:	pushl %edi
0x004156b8:	movl %edi, 0x8(%ebx)
0x004156bb:	xorl %edi, 0x427040
0x004156c1:	movb -1(%ebp), $0x0<UINT8>
0x004156c5:	movl -12(%ebp), $0x1<UINT32>
0x004156cc:	movl %eax, (%edi)
0x004156ce:	leal %esi, 0x10(%ebx)
0x004156d1:	cmpl %eax, $0xfffffffe<UINT8>
0x004156d4:	je 0x004156e3
0x004156e3:	movl %ecx, 0xc(%edi)
0x004156e6:	movl %eax, 0x8(%edi)
0x004156e9:	addl %ecx, %esi
0x004156eb:	xorl %ecx, (%eax,%esi)
0x004156ee:	call 0x00402258
0x004156f3:	movl %eax, 0x8(%ebp)
0x004156f6:	testb 0x4(%eax), $0x66<UINT8>
0x004156fa:	jne 204
0x00415700:	movl -24(%ebp), %eax
0x00415703:	movl %eax, 0x10(%ebp)
0x00415706:	movl -20(%ebp), %eax
0x00415709:	leal %eax, -24(%ebp)
0x0041570c:	movl -4(%ebx), %eax
0x0041570f:	movl %eax, 0xc(%ebx)
0x00415712:	movl -8(%ebp), %eax
0x00415715:	cmpl %eax, $0xfffffffe<UINT8>
0x00415718:	je 234
0x0041571e:	leal %eax, (%eax,%eax,2)
0x00415721:	leal %eax, 0x4(%eax)
0x00415724:	movl %ecx, 0x4(%edi,%eax,4)
0x00415728:	movl %ebx, (%edi,%eax,4)
0x0041572b:	leal %eax, (%edi,%eax,4)
0x0041572e:	movl -16(%ebp), %eax
0x00415731:	testl %ecx, %ecx
0x00415733:	je 119
0x00415735:	movl %edx, %esi
0x00415737:	call 0x0040664d
0x0040664d:	pushl %ebp
0x0040664e:	pushl %esi
0x0040664f:	pushl %edi
0x00406650:	pushl %ebx
0x00406651:	movl %ebp, %edx
0x00406653:	xorl %eax, %eax
0x00406655:	xorl %ebx, %ebx
0x00406657:	xorl %edx, %edx
0x00406659:	xorl %esi, %esi
0x0040665b:	xorl %edi, %edi
0x0040665d:	call 0x00409668
0x00409668:	movl %ecx, -20(%ebp)
0x0040966b:	movl %eax, (%ecx)
0x0040966d:	movl %eax, (%eax)
0x0040966f:	movl -32(%ebp), %eax
0x00409672:	pushl %ecx
0x00409673:	pushl %eax
0x00409674:	call 0x004144b1
0x004144b1:	pushl %ebp
0x004144b2:	movl %ebp, %esp
0x004144b4:	pushl %esi
0x004144b5:	call 0x0041478a
0x004144ba:	movl %esi, %eax
0x004144bc:	testl %esi, %esi
0x004144be:	je 325
0x004144c4:	movl %edx, 0x5c(%esi)
0x004144c7:	pushl %edi
0x004144c8:	movl %edi, 0x8(%ebp)
0x004144cb:	movl %ecx, %edx
0x004144cd:	cmpl (%ecx), %edi
0x004144cf:	je 0x004144de
0x004144de:	leal %eax, 0x90(%edx)
0x004144e4:	cmpl %ecx, %eax
0x004144e6:	jae 4
0x004144e8:	cmpl (%ecx), %edi
0x004144ea:	je 0x004144ee
0x004144ee:	testl %ecx, %ecx
0x004144f0:	je 272
0x004144f6:	movl %edx, 0x8(%ecx)
0x004144f9:	testl %edx, %edx
0x004144fb:	je 0x00414606
0x00414606:	xorl %eax, %eax
0x00414608:	popl %edi
0x00414609:	popl %esi
0x0041460a:	popl %ebp
0x0041460b:	ret

0x00409679:	popl %ecx
0x0040967a:	popl %ecx
0x0040967b:	ret

0x0040665f:	popl %ebx
0x00406660:	popl %edi
0x00406661:	popl %esi
0x00406662:	popl %ebp
0x00406663:	ret

0x0041573c:	movb %cl, $0x1<UINT8>
0x0041573e:	movb -1(%ebp), %cl
0x00415741:	testl %eax, %eax
0x00415743:	js 126
0x00415745:	jle 0x004157af
0x004157af:	movl %eax, %ebx
0x004157b1:	movl -8(%ebp), %ebx
0x004157b4:	cmpl %ebx, $0xfffffffe<UINT8>
0x004157b7:	jne -159
0x004157bd:	testb %cl, %cl
0x004157bf:	jne 0x004157e4
0x004157e4:	movl %eax, (%edi)
0x004157e6:	cmpl %eax, $0xfffffffe<UINT8>
0x004157e9:	je 0x004157f8
0x004157f8:	movl %ecx, 0xc(%edi)
0x004157fb:	movl %edx, 0x8(%edi)
0x004157fe:	addl %ecx, %esi
0x00415800:	xorl %ecx, (%edx,%esi)
0x00415803:	call 0x00402258
0x00415808:	movl %eax, -12(%ebp)
0x0041580b:	popl %edi
0x0041580c:	popl %esi
0x0041580d:	popl %ebx
0x0041580e:	movl %esp, %ebp
0x00415810:	popl %ebp
0x00415811:	ret

0x0041fb8e:	addb (%eax), %al
0x0041fb90:	addb (%eax), %al
0x0041fb92:	addb (%eax), %al
0x0041fb94:	addb (%eax), %al
0x0041fb96:	addb (%eax), %al
0x0041fb98:	addb (%eax), %al
0x0041fb9a:	addb (%eax), %al
0x0041fb9c:	addb (%eax), %al
0x0041fb9e:	addb (%eax), %al
0x0041fba0:	addb (%eax), %al
0x0041fba2:	addb (%eax), %al
0x0041fba4:	addb (%eax), %al
0x0041fba6:	addb (%eax), %al
0x0041fba8:	addb (%eax), %al
0x0041fbaa:	addb (%eax), %al
0x0041fbac:	addb (%eax), %al
0x0041fbae:	addb (%eax), %al
0x0041fbb0:	addb (%eax), %al
0x0041fbb2:	addb (%eax), %al
0x0041fbb4:	addb (%eax), %al
0x0041fbb6:	addb (%eax), %al
0x0041fbb8:	addb (%eax), %al
0x0041fbba:	addb (%eax), %al
0x0041fbbc:	addb (%eax), %al
0x0041fbbe:	addb (%eax), %al
0x0041fbc0:	addb (%eax), %al
0x0041fbc2:	addb (%eax), %al
0x0041fbc4:	addb (%eax), %al
0x0041fbc6:	addb (%eax), %al
0x0041fbc8:	addb (%eax), %al
0x0041fbca:	addb (%eax), %al
0x0041fbcc:	addb (%eax), %al
0x0041fbce:	addb (%eax), %al
0x0041fbd0:	addb (%eax), %al
0x0041fbd2:	addb (%eax), %al
0x0041fbd4:	addb (%eax), %al
0x0041fbd6:	addb (%eax), %al
0x0041fbd8:	addb (%eax), %al
0x0041fbda:	addb (%eax), %al
0x0041fbdc:	addb (%eax), %al
0x0041fbde:	addb (%eax), %al
0x0041fbe0:	addb (%eax), %al
0x0041fbe2:	addb (%eax), %al
0x0041fbe4:	addb (%eax), %al
0x0041fbe6:	addb (%eax), %al
0x0041fbe8:	addb (%eax), %al
0x0041fbea:	addb (%eax), %al
0x0041fbec:	addb (%eax), %al
0x0041fbee:	addb (%eax), %al
0x0041fbf0:	addb (%eax), %al
0x00420325:	testl 0x10(%ebp), %ecx
0x00420328:	je 0x00420359
0x00420359:	testl %ebx, %ebx
0x0042035b:	jle 0x0042039f
0x0042035d:	pushl $0xffffffe0<UINT8>
0x0042039f:	xorl %esi, %esi
0x004203a1:	testl %esi, %esi
0x004203a3:	je 0x004203e9
0x0042035f:	xorl %edx, %edx
0x00420361:	popl %eax
0x00420362:	divl %eax, %ebx
0x00420364:	cmpl %eax, $0x2<UINT8>
0x00420367:	jb 0x0042039f
0x00420369:	leal %eax, 0x8(,%ebx,2)
0x00420370:	cmpl %eax, %ecx
0x00420372:	ja 19
0x00420374:	call 0x004027f9
