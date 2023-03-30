0x00487000:	movl %ebx, $0x4001d0<UINT32>
0x00487005:	movl %edi, $0x401000<UINT32>
0x0048700a:	movl %esi, $0x472d2d<UINT32>
0x0048700f:	pushl %ebx
0x00487010:	call 0x0048701f
0x0048701f:	cld
0x00487020:	movb %dl, $0xffffff80<UINT8>
0x00487022:	movsb %es:(%edi), %ds:(%esi)
0x00487023:	pushl $0x2<UINT8>
0x00487025:	popl %ebx
0x00487026:	call 0x00487015
0x00487015:	addb %dl, %dl
0x00487017:	jne 0x0048701e
0x00487019:	movb %dl, (%esi)
0x0048701b:	incl %esi
0x0048701c:	adcb %dl, %dl
0x0048701e:	ret

0x00487029:	jae 0x00487022
0x0048702b:	xorl %ecx, %ecx
0x0048702d:	call 0x00487015
0x00487030:	jae 0x0048704a
0x00487032:	xorl %eax, %eax
0x00487034:	call 0x00487015
0x00487037:	jae 0x0048705a
0x00487039:	movb %bl, $0x2<UINT8>
0x0048703b:	incl %ecx
0x0048703c:	movb %al, $0x10<UINT8>
0x0048703e:	call 0x00487015
0x00487041:	adcb %al, %al
0x00487043:	jae 0x0048703e
0x00487045:	jne 0x00487086
0x00487086:	pushl %esi
0x00487087:	movl %esi, %edi
0x00487089:	subl %esi, %eax
0x0048708b:	rep movsb %es:(%edi), %ds:(%esi)
0x0048708d:	popl %esi
0x0048708e:	jmp 0x00487026
0x00487047:	stosb %es:(%edi), %al
0x00487048:	jmp 0x00487026
0x0048705a:	lodsb %al, %ds:(%esi)
0x0048705b:	shrl %eax
0x0048705d:	je 0x004870a0
0x0048705f:	adcl %ecx, %ecx
0x00487061:	jmp 0x0048707f
0x0048707f:	incl %ecx
0x00487080:	incl %ecx
0x00487081:	xchgl %ebp, %eax
0x00487082:	movl %eax, %ebp
0x00487084:	movb %bl, $0x1<UINT8>
0x0048704a:	call 0x00487092
0x00487092:	incl %ecx
0x00487093:	call 0x00487015
0x00487097:	adcl %ecx, %ecx
0x00487099:	call 0x00487015
0x0048709d:	jb 0x00487093
0x0048709f:	ret

0x0048704f:	subl %ecx, %ebx
0x00487051:	jne 0x00487063
0x00487063:	xchgl %ecx, %eax
0x00487064:	decl %eax
0x00487065:	shll %eax, $0x8<UINT8>
0x00487068:	lodsb %al, %ds:(%esi)
0x00487069:	call 0x00487090
0x00487090:	xorl %ecx, %ecx
0x0048706e:	cmpl %eax, $0x7d00<UINT32>
0x00487073:	jae 0x0048707f
0x00487075:	cmpb %ah, $0x5<UINT8>
0x00487078:	jae 0x00487080
0x0048707a:	cmpl %eax, $0x7f<UINT8>
0x0048707d:	ja 0x00487081
0x00487053:	call 0x00487090
0x00487058:	jmp 0x00487082
0x004870a0:	popl %edi
0x004870a1:	popl %ebx
0x004870a2:	movzwl %edi, (%ebx)
0x004870a5:	decl %edi
0x004870a6:	je 0x004870b0
0x004870a8:	decl %edi
0x004870a9:	je 0x004870be
0x004870ab:	shll %edi, $0xc<UINT8>
0x004870ae:	jmp 0x004870b7
0x004870b7:	incl %ebx
0x004870b8:	incl %ebx
0x004870b9:	jmp 0x0048700f
0x004870b0:	movl %edi, 0x2(%ebx)
0x004870b3:	pushl %edi
0x004870b4:	addl %ebx, $0x4<UINT8>
0x004870be:	popl %edi
0x004870bf:	movl %ebx, $0x487128<UINT32>
0x004870c4:	incl %edi
0x004870c5:	movl %esi, (%edi)
0x004870c7:	scasl %eax, %es:(%edi)
0x004870c8:	pushl %edi
0x004870c9:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004870cb:	xchgl %ebp, %eax
0x004870cc:	xorl %eax, %eax
0x004870ce:	scasb %al, %es:(%edi)
0x004870cf:	jne 0x004870ce
0x004870d1:	decb (%edi)
0x004870d3:	je 0x004870c4
0x004870d5:	decb (%edi)
0x004870d7:	jne 0x004870df
0x004870df:	decb (%edi)
0x004870e1:	je 0x0040a0cf
0x004870e7:	pushl %edi
0x004870e8:	pushl %ebp
0x004870e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x004870ec:	orl (%esi), %eax
0x004870ee:	lodsl %eax, %ds:(%esi)
0x004870ef:	jne 0x004870cc
0x004870d9:	incl %edi
0x004870da:	pushl (%edi)
0x004870dc:	scasl %eax, %es:(%edi)
0x004870dd:	jmp 0x004870e8
GetProcAddress@KERNEL32.dll: API Node	
0x0040a0cf:	call 0x004138aa
0x004138aa:	pushl %ebp
0x004138ab:	movl %ebp, %esp
0x004138ad:	subl %esp, $0x14<UINT8>
0x004138b0:	andl -12(%ebp), $0x0<UINT8>
0x004138b4:	andl -8(%ebp), $0x0<UINT8>
0x004138b8:	movl %eax, 0x42b190
0x004138bd:	pushl %esi
0x004138be:	pushl %edi
0x004138bf:	movl %edi, $0xbb40e64e<UINT32>
0x004138c4:	movl %esi, $0xffff0000<UINT32>
0x004138c9:	cmpl %eax, %edi
0x004138cb:	je 0x004138da
0x004138da:	leal %eax, -12(%ebp)
0x004138dd:	pushl %eax
0x004138de:	call GetSystemTimeAsFileTime@KERNEL32.dll
GetSystemTimeAsFileTime@KERNEL32.dll: API Node	
0x004138e4:	movl %eax, -8(%ebp)
0x004138e7:	xorl %eax, -12(%ebp)
0x004138ea:	movl -4(%ebp), %eax
0x004138ed:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x004138f3:	xorl -4(%ebp), %eax
0x004138f6:	call GetCurrentProcessId@KERNEL32.dll
GetCurrentProcessId@KERNEL32.dll: API Node	
0x004138fc:	xorl -4(%ebp), %eax
0x004138ff:	leal %eax, -20(%ebp)
0x00413902:	pushl %eax
0x00413903:	call QueryPerformanceCounter@KERNEL32.dll
QueryPerformanceCounter@KERNEL32.dll: API Node	
0x00413909:	movl %ecx, -16(%ebp)
0x0041390c:	leal %eax, -4(%ebp)
0x0041390f:	xorl %ecx, -20(%ebp)
0x00413912:	xorl %ecx, -4(%ebp)
0x00413915:	xorl %ecx, %eax
0x00413917:	cmpl %ecx, %edi
0x00413919:	jne 0x00413922
0x00413922:	testl %esi, %ecx
0x00413924:	jne 0x00413932
0x00413932:	movl 0x42b190, %ecx
0x00413938:	notl %ecx
0x0041393a:	movl 0x42b194, %ecx
0x00413940:	popl %edi
0x00413941:	popl %esi
0x00413942:	movl %esp, %ebp
0x00413944:	popl %ebp
0x00413945:	ret

0x0040a0d4:	jmp 0x00409f54
0x00409f54:	pushl $0x14<UINT8>
0x00409f56:	pushl $0x429940<UINT32>
0x00409f5b:	call 0x0040bfa0
0x0040bfa0:	pushl $0x409030<UINT32>
0x0040bfa5:	pushl %fs:0
0x0040bfac:	movl %eax, 0x10(%esp)
0x0040bfb0:	movl 0x10(%esp), %ebp
0x0040bfb4:	leal %ebp, 0x10(%esp)
0x0040bfb8:	subl %esp, %eax
0x0040bfba:	pushl %ebx
0x0040bfbb:	pushl %esi
0x0040bfbc:	pushl %edi
0x0040bfbd:	movl %eax, 0x42b190
0x0040bfc2:	xorl -4(%ebp), %eax
0x0040bfc5:	xorl %eax, %ebp
0x0040bfc7:	pushl %eax
0x0040bfc8:	movl -24(%ebp), %esp
0x0040bfcb:	pushl -8(%ebp)
0x0040bfce:	movl %eax, -4(%ebp)
0x0040bfd1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040bfd8:	movl -8(%ebp), %eax
0x0040bfdb:	leal %eax, -16(%ebp)
0x0040bfde:	movl %fs:0, %eax
0x0040bfe4:	ret

0x00409f60:	pushl $0x1<UINT8>
0x00409f62:	call 0x0041385d
0x0041385d:	pushl %ebp
0x0041385e:	movl %ebp, %esp
0x00413860:	movl %eax, 0x8(%ebp)
0x00413863:	movl 0x433d68, %eax
0x00413868:	popl %ebp
0x00413869:	ret

0x00409f67:	popl %ecx
0x00409f68:	movl %eax, $0x5a4d<UINT32>
0x00409f6d:	cmpw 0x400000, %ax
0x00409f74:	je 0x00409f7a
0x00409f7a:	movl %eax, 0x40003c
0x00409f7f:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00409f89:	jne -21
0x00409f8b:	movl %ecx, $0x10b<UINT32>
0x00409f90:	cmpw 0x400018(%eax), %cx
0x00409f97:	jne -35
0x00409f99:	xorl %ebx, %ebx
0x00409f9b:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00409fa2:	jbe 9
0x00409fa4:	cmpl 0x4000e8(%eax), %ebx
0x00409faa:	setne %bl
0x00409fad:	movl -28(%ebp), %ebx
0x00409fb0:	call 0x0040c0d0
0x0040c0d0:	call GetProcessHeap@KERNEL32.dll
GetProcessHeap@KERNEL32.dll: API Node	
0x0040c0d6:	xorl %ecx, %ecx
0x0040c0d8:	movl 0x4343c8, %eax
0x0040c0dd:	testl %eax, %eax
0x0040c0df:	setne %cl
0x0040c0e2:	movl %eax, %ecx
0x0040c0e4:	ret

0x00409fb5:	testl %eax, %eax
0x00409fb7:	jne 0x00409fc1
0x00409fc1:	call 0x0040b017
0x0040b017:	call 0x00406e14
0x00406e14:	pushl %esi
0x00406e15:	pushl $0x0<UINT8>
0x00406e17:	call EncodePointer@KERNEL32.dll
EncodePointer@KERNEL32.dll: API Node	
0x00406e1d:	movl %esi, %eax
0x00406e1f:	pushl %esi
0x00406e20:	call 0x0040bd52
0x0040bd52:	pushl %ebp
0x0040bd53:	movl %ebp, %esp
0x0040bd55:	movl %eax, 0x8(%ebp)
0x0040bd58:	movl 0x4343a0, %eax
0x0040bd5d:	popl %ebp
0x0040bd5e:	ret

0x00406e25:	pushl %esi
0x00406e26:	call 0x0040a1fe
0x0040a1fe:	pushl %ebp
0x0040a1ff:	movl %ebp, %esp
0x0040a201:	movl %eax, 0x8(%ebp)
0x0040a204:	movl 0x433bf4, %eax
0x0040a209:	popl %ebp
0x0040a20a:	ret

0x00406e2b:	pushl %esi
0x00406e2c:	call 0x0040bd5f
0x0040bd5f:	pushl %ebp
0x0040bd60:	movl %ebp, %esp
0x0040bd62:	movl %eax, 0x8(%ebp)
0x0040bd65:	movl 0x4343a4, %eax
0x0040bd6a:	popl %ebp
0x0040bd6b:	ret

0x00406e31:	pushl %esi
0x00406e32:	call 0x0040bd79
0x0040bd79:	pushl %ebp
0x0040bd7a:	movl %ebp, %esp
0x0040bd7c:	movl %eax, 0x8(%ebp)
0x0040bd7f:	movl 0x4343a8, %eax
0x0040bd84:	movl 0x4343ac, %eax
0x0040bd89:	movl 0x4343b0, %eax
0x0040bd8e:	movl 0x4343b4, %eax
0x0040bd93:	popl %ebp
0x0040bd94:	ret

0x00406e37:	pushl %esi
0x00406e38:	call 0x0040bd1b
0x0040bd1b:	pushl $0x40bce7<UINT32>
0x0040bd20:	call EncodePointer@KERNEL32.dll
0x0040bd26:	movl 0x43439c, %eax
0x0040bd2b:	ret

0x00406e3d:	pushl %esi
0x00406e3e:	call 0x0040bf8a
0x0040bf8a:	pushl %ebp
0x0040bf8b:	movl %ebp, %esp
0x0040bf8d:	movl %eax, 0x8(%ebp)
0x0040bf90:	movl 0x4343bc, %eax
0x0040bf95:	popl %ebp
0x0040bf96:	ret

0x00406e43:	addl %esp, $0x18<UINT8>
0x00406e46:	popl %esi
0x00406e47:	jmp 0x0040b42f
0x0040b42f:	pushl %esi
0x0040b430:	pushl %edi
0x0040b431:	pushl $0x425d68<UINT32>
0x0040b436:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x0040b43c:	movl %esi, 0x41b0f8
0x0040b442:	movl %edi, %eax
0x0040b444:	pushl $0x425d84<UINT32>
0x0040b449:	pushl %edi
0x0040b44a:	call GetProcAddress@KERNEL32.dll
0x0040b44c:	xorl %eax, 0x42b190
0x0040b452:	pushl $0x425d90<UINT32>
0x0040b457:	pushl %edi
0x0040b458:	movl 0x434a40, %eax
0x0040b45d:	call GetProcAddress@KERNEL32.dll
0x0040b45f:	xorl %eax, 0x42b190
0x0040b465:	pushl $0x425d98<UINT32>
0x0040b46a:	pushl %edi
0x0040b46b:	movl 0x434a44, %eax
0x0040b470:	call GetProcAddress@KERNEL32.dll
0x0040b472:	xorl %eax, 0x42b190
0x0040b478:	pushl $0x425da4<UINT32>
0x0040b47d:	pushl %edi
0x0040b47e:	movl 0x434a48, %eax
0x0040b483:	call GetProcAddress@KERNEL32.dll
0x0040b485:	xorl %eax, 0x42b190
0x0040b48b:	pushl $0x425db0<UINT32>
0x0040b490:	pushl %edi
0x0040b491:	movl 0x434a4c, %eax
0x0040b496:	call GetProcAddress@KERNEL32.dll
0x0040b498:	xorl %eax, 0x42b190
0x0040b49e:	pushl $0x425dcc<UINT32>
0x0040b4a3:	pushl %edi
0x0040b4a4:	movl 0x434a50, %eax
0x0040b4a9:	call GetProcAddress@KERNEL32.dll
0x0040b4ab:	xorl %eax, 0x42b190
0x0040b4b1:	pushl $0x425ddc<UINT32>
0x0040b4b6:	pushl %edi
0x0040b4b7:	movl 0x434a54, %eax
0x0040b4bc:	call GetProcAddress@KERNEL32.dll
0x0040b4be:	xorl %eax, 0x42b190
0x0040b4c4:	pushl $0x425df0<UINT32>
0x0040b4c9:	pushl %edi
0x0040b4ca:	movl 0x434a58, %eax
0x0040b4cf:	call GetProcAddress@KERNEL32.dll
0x0040b4d1:	xorl %eax, 0x42b190
0x0040b4d7:	pushl $0x425e08<UINT32>
0x0040b4dc:	pushl %edi
0x0040b4dd:	movl 0x434a5c, %eax
0x0040b4e2:	call GetProcAddress@KERNEL32.dll
0x0040b4e4:	xorl %eax, 0x42b190
0x0040b4ea:	pushl $0x425e20<UINT32>
0x0040b4ef:	pushl %edi
0x0040b4f0:	movl 0x434a60, %eax
0x0040b4f5:	call GetProcAddress@KERNEL32.dll
0x0040b4f7:	xorl %eax, 0x42b190
0x0040b4fd:	pushl $0x425e34<UINT32>
0x0040b502:	pushl %edi
0x0040b503:	movl 0x434a64, %eax
0x0040b508:	call GetProcAddress@KERNEL32.dll
0x0040b50a:	xorl %eax, 0x42b190
0x0040b510:	pushl $0x425e54<UINT32>
0x0040b515:	pushl %edi
0x0040b516:	movl 0x434a68, %eax
0x0040b51b:	call GetProcAddress@KERNEL32.dll
0x0040b51d:	xorl %eax, 0x42b190
0x0040b523:	pushl $0x425e6c<UINT32>
0x0040b528:	pushl %edi
0x0040b529:	movl 0x434a6c, %eax
0x0040b52e:	call GetProcAddress@KERNEL32.dll
0x0040b530:	xorl %eax, 0x42b190
0x0040b536:	pushl $0x425e84<UINT32>
0x0040b53b:	pushl %edi
0x0040b53c:	movl 0x434a70, %eax
0x0040b541:	call GetProcAddress@KERNEL32.dll
0x0040b543:	xorl %eax, 0x42b190
0x0040b549:	pushl $0x425e98<UINT32>
0x0040b54e:	pushl %edi
0x0040b54f:	movl 0x434a74, %eax
0x0040b554:	call GetProcAddress@KERNEL32.dll
0x0040b556:	xorl %eax, 0x42b190
0x0040b55c:	movl 0x434a78, %eax
0x0040b561:	pushl $0x425eac<UINT32>
0x0040b566:	pushl %edi
0x0040b567:	call GetProcAddress@KERNEL32.dll
0x0040b569:	xorl %eax, 0x42b190
0x0040b56f:	pushl $0x425ec8<UINT32>
0x0040b574:	pushl %edi
0x0040b575:	movl 0x434a7c, %eax
0x0040b57a:	call GetProcAddress@KERNEL32.dll
0x0040b57c:	xorl %eax, 0x42b190
0x0040b582:	pushl $0x425ee8<UINT32>
0x0040b587:	pushl %edi
0x0040b588:	movl 0x434a80, %eax
0x0040b58d:	call GetProcAddress@KERNEL32.dll
0x0040b58f:	xorl %eax, 0x42b190
0x0040b595:	pushl $0x425f04<UINT32>
0x0040b59a:	pushl %edi
0x0040b59b:	movl 0x434a84, %eax
0x0040b5a0:	call GetProcAddress@KERNEL32.dll
0x0040b5a2:	xorl %eax, 0x42b190
0x0040b5a8:	pushl $0x425f24<UINT32>
0x0040b5ad:	pushl %edi
0x0040b5ae:	movl 0x434a88, %eax
0x0040b5b3:	call GetProcAddress@KERNEL32.dll
0x0040b5b5:	xorl %eax, 0x42b190
0x0040b5bb:	pushl $0x425f38<UINT32>
0x0040b5c0:	pushl %edi
0x0040b5c1:	movl 0x434a8c, %eax
0x0040b5c6:	call GetProcAddress@KERNEL32.dll
0x0040b5c8:	xorl %eax, 0x42b190
0x0040b5ce:	pushl $0x425f54<UINT32>
0x0040b5d3:	pushl %edi
0x0040b5d4:	movl 0x434a90, %eax
0x0040b5d9:	call GetProcAddress@KERNEL32.dll
0x0040b5db:	xorl %eax, 0x42b190
0x0040b5e1:	pushl $0x425f68<UINT32>
0x0040b5e6:	pushl %edi
0x0040b5e7:	movl 0x434a98, %eax
0x0040b5ec:	call GetProcAddress@KERNEL32.dll
0x0040b5ee:	xorl %eax, 0x42b190
0x0040b5f4:	pushl $0x425f78<UINT32>
0x0040b5f9:	pushl %edi
0x0040b5fa:	movl 0x434a94, %eax
0x0040b5ff:	call GetProcAddress@KERNEL32.dll
0x0040b601:	xorl %eax, 0x42b190
0x0040b607:	pushl $0x425f88<UINT32>
0x0040b60c:	pushl %edi
0x0040b60d:	movl 0x434a9c, %eax
0x0040b612:	call GetProcAddress@KERNEL32.dll
0x0040b614:	xorl %eax, 0x42b190
0x0040b61a:	pushl $0x425f98<UINT32>
0x0040b61f:	pushl %edi
0x0040b620:	movl 0x434aa0, %eax
0x0040b625:	call GetProcAddress@KERNEL32.dll
0x0040b627:	xorl %eax, 0x42b190
0x0040b62d:	pushl $0x425fa8<UINT32>
0x0040b632:	pushl %edi
0x0040b633:	movl 0x434aa4, %eax
0x0040b638:	call GetProcAddress@KERNEL32.dll
0x0040b63a:	xorl %eax, 0x42b190
0x0040b640:	pushl $0x425fc4<UINT32>
0x0040b645:	pushl %edi
0x0040b646:	movl 0x434aa8, %eax
0x0040b64b:	call GetProcAddress@KERNEL32.dll
0x0040b64d:	xorl %eax, 0x42b190
0x0040b653:	pushl $0x425fd8<UINT32>
0x0040b658:	pushl %edi
0x0040b659:	movl 0x434aac, %eax
0x0040b65e:	call GetProcAddress@KERNEL32.dll
0x0040b660:	xorl %eax, 0x42b190
0x0040b666:	pushl $0x425fe8<UINT32>
0x0040b66b:	pushl %edi
0x0040b66c:	movl 0x434ab0, %eax
0x0040b671:	call GetProcAddress@KERNEL32.dll
0x0040b673:	xorl %eax, 0x42b190
0x0040b679:	pushl $0x425ffc<UINT32>
0x0040b67e:	pushl %edi
0x0040b67f:	movl 0x434ab4, %eax
0x0040b684:	call GetProcAddress@KERNEL32.dll
0x0040b686:	xorl %eax, 0x42b190
0x0040b68c:	movl 0x434ab8, %eax
0x0040b691:	pushl $0x42600c<UINT32>
0x0040b696:	pushl %edi
0x0040b697:	call GetProcAddress@KERNEL32.dll
0x0040b699:	xorl %eax, 0x42b190
0x0040b69f:	pushl $0x42602c<UINT32>
0x0040b6a4:	pushl %edi
0x0040b6a5:	movl 0x434abc, %eax
0x0040b6aa:	call GetProcAddress@KERNEL32.dll
0x0040b6ac:	xorl %eax, 0x42b190
0x0040b6b2:	popl %edi
0x0040b6b3:	movl 0x434ac0, %eax
0x0040b6b8:	popl %esi
0x0040b6b9:	ret

0x0040b01c:	call 0x0040b2f5
0x0040b2f5:	pushl %esi
0x0040b2f6:	pushl %edi
0x0040b2f7:	movl %esi, $0x42bcf0<UINT32>
0x0040b2fc:	movl %edi, $0x433c18<UINT32>
0x0040b301:	cmpl 0x4(%esi), $0x1<UINT8>
0x0040b305:	jne 22
0x0040b307:	pushl $0x0<UINT8>
0x0040b309:	movl (%esi), %edi
0x0040b30b:	addl %edi, $0x18<UINT8>
0x0040b30e:	pushl $0xfa0<UINT32>
0x0040b313:	pushl (%esi)
0x0040b315:	call 0x0040b3c1
0x0040b3c1:	pushl %ebp
0x0040b3c2:	movl %ebp, %esp
0x0040b3c4:	movl %eax, 0x434a50
0x0040b3c9:	xorl %eax, 0x42b190
0x0040b3cf:	je 13
0x0040b3d1:	pushl 0x10(%ebp)
0x0040b3d4:	pushl 0xc(%ebp)
0x0040b3d7:	pushl 0x8(%ebp)
0x0040b3da:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x0040b3dc:	popl %ebp
0x0040b3dd:	ret

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
