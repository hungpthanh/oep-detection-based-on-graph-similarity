0x00470000:	movl %ebx, $0x4001d0<UINT32>
0x00470005:	movl %edi, $0x401000<UINT32>
0x0047000a:	movl %esi, $0x44d9c6<UINT32>
0x0047000f:	pushl %ebx
0x00470010:	call 0x0047001f
0x0047001f:	cld
0x00470020:	movb %dl, $0xffffff80<UINT8>
0x00470022:	movsb %es:(%edi), %ds:(%esi)
0x00470023:	pushl $0x2<UINT8>
0x00470025:	popl %ebx
0x00470026:	call 0x00470015
0x00470015:	addb %dl, %dl
0x00470017:	jne 0x0047001e
0x00470019:	movb %dl, (%esi)
0x0047001b:	incl %esi
0x0047001c:	adcb %dl, %dl
0x0047001e:	ret

0x00470029:	jae 0x00470022
0x0047002b:	xorl %ecx, %ecx
0x0047002d:	call 0x00470015
0x00470030:	jae 0x0047004a
0x00470032:	xorl %eax, %eax
0x00470034:	call 0x00470015
0x00470037:	jae 0x0047005a
0x00470039:	movb %bl, $0x2<UINT8>
0x0047003b:	incl %ecx
0x0047003c:	movb %al, $0x10<UINT8>
0x0047003e:	call 0x00470015
0x00470041:	adcb %al, %al
0x00470043:	jae 0x0047003e
0x00470045:	jne 0x00470086
0x00470047:	stosb %es:(%edi), %al
0x00470048:	jmp 0x00470026
0x0047004a:	call 0x00470092
0x00470092:	incl %ecx
0x00470093:	call 0x00470015
0x00470097:	adcl %ecx, %ecx
0x00470099:	call 0x00470015
0x0047009d:	jb 0x00470093
0x0047009f:	ret

0x0047004f:	subl %ecx, %ebx
0x00470051:	jne 0x00470063
0x00470063:	xchgl %ecx, %eax
0x00470064:	decl %eax
0x00470065:	shll %eax, $0x8<UINT8>
0x00470068:	lodsb %al, %ds:(%esi)
0x00470069:	call 0x00470090
0x00470090:	xorl %ecx, %ecx
0x0047006e:	cmpl %eax, $0x7d00<UINT32>
0x00470073:	jae 0x0047007f
0x00470075:	cmpb %ah, $0x5<UINT8>
0x00470078:	jae 0x00470080
0x0047007a:	cmpl %eax, $0x7f<UINT8>
0x0047007d:	ja 0x00470081
0x0047007f:	incl %ecx
0x00470080:	incl %ecx
0x00470081:	xchgl %ebp, %eax
0x00470082:	movl %eax, %ebp
0x00470084:	movb %bl, $0x1<UINT8>
0x00470086:	pushl %esi
0x00470087:	movl %esi, %edi
0x00470089:	subl %esi, %eax
0x0047008b:	rep movsb %es:(%edi), %ds:(%esi)
0x0047008d:	popl %esi
0x0047008e:	jmp 0x00470026
0x00470053:	call 0x00470090
0x00470058:	jmp 0x00470082
0x0047005a:	lodsb %al, %ds:(%esi)
0x0047005b:	shrl %eax
0x0047005d:	je 0x004700a0
0x0047005f:	adcl %ecx, %ecx
0x00470061:	jmp 0x0047007f
0x004700a0:	popl %edi
0x004700a1:	popl %ebx
0x004700a2:	movzwl %edi, (%ebx)
0x004700a5:	decl %edi
0x004700a6:	je 0x004700b0
0x004700a8:	decl %edi
0x004700a9:	je 0x004700be
0x004700ab:	shll %edi, $0xc<UINT8>
0x004700ae:	jmp 0x004700b7
0x004700b7:	incl %ebx
0x004700b8:	incl %ebx
0x004700b9:	jmp 0x0047000f
0x004700b0:	movl %edi, 0x2(%ebx)
0x004700b3:	pushl %edi
0x004700b4:	addl %ebx, $0x4<UINT8>
0x004700be:	popl %edi
0x004700bf:	movl %ebx, $0x470128<UINT32>
0x004700c4:	incl %edi
0x004700c5:	movl %esi, (%edi)
0x004700c7:	scasl %eax, %es:(%edi)
0x004700c8:	pushl %edi
0x004700c9:	call LoadLibraryA@KERNEL32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004700cb:	xchgl %ebp, %eax
0x004700cc:	xorl %eax, %eax
0x004700ce:	scasb %al, %es:(%edi)
0x004700cf:	jne 0x004700ce
0x004700d1:	decb (%edi)
0x004700d3:	je 0x004700c4
0x004700d5:	decb (%edi)
0x004700d7:	jne 0x004700df
0x004700df:	decb (%edi)
0x004700e1:	je 0x004149d8
0x004700e7:	pushl %edi
0x004700e8:	pushl %ebp
0x004700e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x004700ec:	orl (%esi), %eax
0x004700ee:	lodsl %eax, %ds:(%esi)
0x004700ef:	jne 0x004700cc
0x004700d9:	incl %edi
0x004700da:	pushl (%edi)
0x004700dc:	scasl %eax, %es:(%edi)
0x004700dd:	jmp 0x004700e8
GetProcAddress@KERNEL32.dll: API Node	
LoadLibraryA@KERNEL32.dll: API Node	
0x004149d8:	call 0x0041f6b3
0x0041f6b3:	movl %edi, %edi
0x0041f6b5:	pushl %ebp
0x0041f6b6:	movl %ebp, %esp
0x0041f6b8:	subl %esp, $0x10<UINT8>
0x0041f6bb:	movl %eax, 0x445654
0x0041f6c0:	andl -8(%ebp), $0x0<UINT8>
0x0041f6c4:	andl -4(%ebp), $0x0<UINT8>
0x0041f6c8:	pushl %ebx
0x0041f6c9:	pushl %edi
0x0041f6ca:	movl %edi, $0xbb40e64e<UINT32>
0x0041f6cf:	movl %ebx, $0xffff0000<UINT32>
0x0041f6d4:	cmpl %eax, %edi
0x0041f6d6:	je 0x0041f6e5
0x0041f6e5:	pushl %esi
0x0041f6e6:	leal %eax, -8(%ebp)
0x0041f6e9:	pushl %eax
0x0041f6ea:	call GetSystemTimeAsFileTime@KERNEL32.dll
GetSystemTimeAsFileTime@KERNEL32.dll: API Node	
0x0041f6f0:	movl %esi, -4(%ebp)
0x0041f6f3:	xorl %esi, -8(%ebp)
0x0041f6f6:	call GetCurrentProcessId@KERNEL32.dll
GetCurrentProcessId@KERNEL32.dll: API Node	
0x0041f6fc:	xorl %esi, %eax
0x0041f6fe:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x0041f704:	xorl %esi, %eax
0x0041f706:	call GetTickCount@KERNEL32.dll
GetTickCount@KERNEL32.dll: API Node	
0x0041f70c:	xorl %esi, %eax
0x0041f70e:	leal %eax, -16(%ebp)
0x0041f711:	pushl %eax
0x0041f712:	call QueryPerformanceCounter@KERNEL32.dll
QueryPerformanceCounter@KERNEL32.dll: API Node	
0x0041f718:	movl %eax, -12(%ebp)
0x0041f71b:	xorl %eax, -16(%ebp)
0x0041f71e:	xorl %esi, %eax
0x0041f720:	cmpl %esi, %edi
0x0041f722:	jne 0x0041f72b
0x0041f72b:	testl %ebx, %esi
0x0041f72d:	jne 0x0041f736
0x0041f736:	movl 0x445654, %esi
0x0041f73c:	notl %esi
0x0041f73e:	movl 0x445658, %esi
0x0041f744:	popl %esi
0x0041f745:	popl %edi
0x0041f746:	popl %ebx
0x0041f747:	leave
0x0041f748:	ret

0x004149dd:	jmp 0x0041485a
0x0041485a:	pushl $0x58<UINT8>
0x0041485c:	pushl $0x442748<UINT32>
0x00414861:	call 0x0041b470
0x0041b470:	pushl $0x413b50<UINT32>
0x0041b475:	pushl %fs:0
0x0041b47c:	movl %eax, 0x10(%esp)
0x0041b480:	movl 0x10(%esp), %ebp
0x0041b484:	leal %ebp, 0x10(%esp)
0x0041b488:	subl %esp, %eax
0x0041b48a:	pushl %ebx
0x0041b48b:	pushl %esi
0x0041b48c:	pushl %edi
0x0041b48d:	movl %eax, 0x445654
0x0041b492:	xorl -4(%ebp), %eax
0x0041b495:	xorl %eax, %ebp
0x0041b497:	pushl %eax
0x0041b498:	movl -24(%ebp), %esp
0x0041b49b:	pushl -8(%ebp)
0x0041b49e:	movl %eax, -4(%ebp)
0x0041b4a1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0041b4a8:	movl -8(%ebp), %eax
0x0041b4ab:	leal %eax, -16(%ebp)
0x0041b4ae:	movl %fs:0, %eax
0x0041b4b4:	ret

0x00414866:	xorl %esi, %esi
0x00414868:	movl -4(%ebp), %esi
0x0041486b:	leal %eax, -104(%ebp)
0x0041486e:	pushl %eax
0x0041486f:	call GetStartupInfoA@KERNEL32.dll
GetStartupInfoA@KERNEL32.dll: API Node	
0x00414875:	pushl $0xfffffffe<UINT8>
0x00414877:	popl %edi
0x00414878:	movl -4(%ebp), %edi
0x0041487b:	movl %eax, $0x5a4d<UINT32>
0x00414880:	cmpw 0x400000, %ax
0x00414887:	jne 56
0x00414889:	movl %eax, 0x40003c
0x0041488e:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00414898:	jne 39
0x0041489a:	movl %ecx, $0x10b<UINT32>
0x0041489f:	cmpw 0x400018(%eax), %cx
0x004148a6:	jne 25
0x004148a8:	cmpl 0x400074(%eax), $0xe<UINT8>
0x004148af:	jbe 16
0x004148b1:	xorl %ecx, %ecx
0x004148b3:	cmpl 0x4000e8(%eax), %esi
0x004148b9:	setne %cl
0x004148bc:	movl -28(%ebp), %ecx
0x004148bf:	jmp 0x004148c4
0x004148c4:	xorl %ebx, %ebx
0x004148c6:	incl %ebx
0x004148c7:	pushl %ebx
0x004148c8:	call 0x0041b4cd
0x0041b4cd:	movl %edi, %edi
0x0041b4cf:	pushl %ebp
0x0041b4d0:	movl %ebp, %esp
0x0041b4d2:	xorl %eax, %eax
0x0041b4d4:	cmpl 0x8(%ebp), %eax
0x0041b4d7:	pushl $0x0<UINT8>
0x0041b4d9:	sete %al
0x0041b4dc:	pushl $0x1000<UINT32>
0x0041b4e1:	pushl %eax
0x0041b4e2:	call HeapCreate@KERNEL32.dll
HeapCreate@KERNEL32.dll: API Node	
0x0041b4e8:	movl 0x447e14, %eax
0x0041b4ed:	testl %eax, %eax
0x0041b4ef:	jne 0x0041b4f3
0x0041b4f3:	xorl %eax, %eax
0x0041b4f5:	incl %eax
0x0041b4f6:	movl 0x449558, %eax
0x0041b4fb:	popl %ebp
0x0041b4fc:	ret

0x004148cd:	popl %ecx
0x004148ce:	testl %eax, %eax
0x004148d0:	jne 0x004148da
0x004148da:	call 0x004186a7
0x004186a7:	movl %edi, %edi
0x004186a9:	pushl %esi
0x004186aa:	pushl %edi
0x004186ab:	movl %esi, $0x43f534<UINT32>
0x004186b0:	pushl %esi
0x004186b1:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x004186b7:	testl %eax, %eax
0x004186b9:	jne 0x004186c2
0x004186c2:	movl %edi, %eax
0x004186c4:	testl %edi, %edi
0x004186c6:	je 350
0x004186cc:	movl %esi, 0x43b20c
0x004186d2:	pushl $0x43f580<UINT32>
0x004186d7:	pushl %edi
0x004186d8:	call GetProcAddress@KERNEL32.dll
0x004186da:	pushl $0x43f574<UINT32>
0x004186df:	pushl %edi
0x004186e0:	movl 0x44797c, %eax
0x004186e5:	call GetProcAddress@KERNEL32.dll
0x004186e7:	pushl $0x43f568<UINT32>
0x004186ec:	pushl %edi
0x004186ed:	movl 0x447980, %eax
0x004186f2:	call GetProcAddress@KERNEL32.dll
0x004186f4:	pushl $0x43f560<UINT32>
0x004186f9:	pushl %edi
0x004186fa:	movl 0x447984, %eax
0x004186ff:	call GetProcAddress@KERNEL32.dll
0x00418701:	cmpl 0x44797c, $0x0<UINT8>
0x00418708:	movl %esi, 0x43b194
0x0041870e:	movl 0x447988, %eax
0x00418713:	je 22
0x00418715:	cmpl 0x447980, $0x0<UINT8>
0x0041871c:	je 13
0x0041871e:	cmpl 0x447984, $0x0<UINT8>
0x00418725:	je 4
0x00418727:	testl %eax, %eax
0x00418729:	jne 0x0041874f
0x0041874f:	call TlsAlloc@KERNEL32.dll
TlsAlloc@KERNEL32.dll: API Node	
0x00418755:	movl 0x445e1c, %eax
0x0041875a:	cmpl %eax, $0xffffffff<UINT8>
0x0041875d:	je 204
0x00418763:	pushl 0x447980
0x00418769:	pushl %eax
0x0041876a:	call TlsSetValue@KERNEL32.dll
TlsSetValue@KERNEL32.dll: API Node	
0x0041876c:	testl %eax, %eax
0x0041876e:	je 187
0x00418774:	call 0x0041b8d9
0x0041b8d9:	movl %edi, %edi
0x0041b8db:	pushl %esi
0x0041b8dc:	call 0x00418252
0x00418252:	pushl $0x0<UINT8>
0x00418254:	call 0x004181e0
0x004181e0:	movl %edi, %edi
0x004181e2:	pushl %ebp
0x004181e3:	movl %ebp, %esp
0x004181e5:	pushl %esi
0x004181e6:	pushl 0x445e1c
0x004181ec:	movl %esi, 0x43b19c
0x004181f2:	call TlsGetValue@KERNEL32.dll
TlsGetValue@KERNEL32.dll: API Node	
0x004181f4:	testl %eax, %eax
0x004181f6:	je 33
0x004181f8:	movl %eax, 0x445e18
0x004181fd:	cmpl %eax, $0xffffffff<UINT8>
0x00418200:	je 0x00418219
0x00418219:	movl %esi, $0x43f534<UINT32>
0x0041821e:	pushl %esi
0x0041821f:	call GetModuleHandleW@KERNEL32.dll
0x00418225:	testl %eax, %eax
0x00418227:	jne 0x00418234
0x00418234:	pushl $0x43f524<UINT32>
0x00418239:	pushl %eax
0x0041823a:	call GetProcAddress@KERNEL32.dll
0x00418240:	testl %eax, %eax
0x00418242:	je 8
0x00418244:	pushl 0x8(%ebp)
0x00418247:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00418249:	movl 0x8(%ebp), %eax
0x0041824c:	movl %eax, 0x8(%ebp)
0x0041824f:	popl %esi
0x00418250:	popl %ebp
0x00418251:	ret

0x00418259:	popl %ecx
0x0041825a:	ret

0x0041b8e1:	movl %esi, %eax
0x0041b8e3:	pushl %esi
0x0041b8e4:	call 0x004154b5
0x004154b5:	movl %edi, %edi
0x004154b7:	pushl %ebp
0x004154b8:	movl %ebp, %esp
0x004154ba:	movl %eax, 0x8(%ebp)
0x004154bd:	movl 0x447938, %eax
0x004154c2:	popl %ebp
0x004154c3:	ret

0x0041b8e9:	pushl %esi
0x0041b8ea:	call 0x0042dcc4
0x0042dcc4:	movl %edi, %edi
0x0042dcc6:	pushl %ebp
0x0042dcc7:	movl %ebp, %esp
0x0042dcc9:	movl %eax, 0x8(%ebp)
0x0042dccc:	movl 0x4482fc, %eax
0x0042dcd1:	popl %ebp
0x0042dcd2:	ret

0x0041b8ef:	pushl %esi
0x0041b8f0:	call 0x00411a82
0x00411a82:	movl %edi, %edi
0x00411a84:	pushl %ebp
0x00411a85:	movl %ebp, %esp
0x00411a87:	movl %eax, 0x8(%ebp)
0x00411a8a:	movl 0x447914, %eax
0x00411a8f:	popl %ebp
0x00411a90:	ret

0x0041b8f5:	pushl %esi
0x0041b8f6:	call 0x0042e4c5
0x0042e4c5:	movl %edi, %edi
0x0042e4c7:	pushl %ebp
0x0042e4c8:	movl %ebp, %esp
0x0042e4ca:	movl %eax, 0x8(%ebp)
0x0042e4cd:	movl 0x448320, %eax
0x0042e4d2:	popl %ebp
0x0042e4d3:	ret

0x0041b8fb:	pushl %esi
0x0041b8fc:	call 0x0042e22f
0x0042e22f:	movl %edi, %edi
0x0042e231:	pushl %ebp
0x0042e232:	movl %ebp, %esp
0x0042e234:	movl %eax, 0x8(%ebp)
0x0042e237:	movl 0x448314, %eax
0x0042e23c:	popl %ebp
0x0042e23d:	ret

0x0041b901:	pushl %esi
0x0041b902:	call 0x0042dd33
0x0042dd33:	movl %edi, %edi
0x0042dd35:	pushl %ebp
0x0042dd36:	movl %ebp, %esp
0x0042dd38:	movl %eax, 0x8(%ebp)
0x0042dd3b:	movl 0x448300, %eax
0x0042dd40:	movl 0x448304, %eax
0x0042dd45:	movl 0x448308, %eax
0x0042dd4a:	movl 0x44830c, %eax
0x0042dd4f:	popl %ebp
0x0042dd50:	ret

0x0041b907:	pushl %esi
0x0041b908:	call 0x0041dcdd
0x0041dcdd:	ret

0x0041b90d:	pushl %esi
0x0041b90e:	call 0x00419c75
0x00419c75:	pushl $0x419bf1<UINT32>
0x00419c7a:	call 0x004181e0
0x00419c7f:	popl %ecx
0x00419c80:	movl 0x447cb4, %eax
0x00419c85:	ret

0x0041b913:	pushl $0x41b8a5<UINT32>
0x0041b918:	call 0x004181e0
0x0041b91d:	addl %esp, $0x24<UINT8>
0x0041b920:	movl 0x445f74, %eax
0x0041b925:	popl %esi
0x0041b926:	ret

0x00418779:	pushl 0x44797c
0x0041877f:	call 0x004181e0
0x00418784:	pushl 0x447980
0x0041878a:	movl 0x44797c, %eax
0x0041878f:	call 0x004181e0
0x00418794:	pushl 0x447984
0x0041879a:	movl 0x447980, %eax
0x0041879f:	call 0x004181e0
0x004187a4:	pushl 0x447988
0x004187aa:	movl 0x447984, %eax
0x004187af:	call 0x004181e0
0x004187b4:	addl %esp, $0x10<UINT8>
0x004187b7:	movl 0x447988, %eax
0x004187bc:	call 0x0041a289
0x0041a289:	movl %edi, %edi
0x0041a28b:	pushl %esi
0x0041a28c:	pushl %edi
0x0041a28d:	xorl %esi, %esi
0x0041a28f:	movl %edi, $0x447cc0<UINT32>
0x0041a294:	cmpl 0x445e54(,%esi,8), $0x1<UINT8>
0x0041a29c:	jne 0x0041a2bc
0x0041a29e:	leal %eax, 0x445e50(,%esi,8)
0x0041a2a5:	movl (%eax), %edi
0x0041a2a7:	pushl $0xfa0<UINT32>
0x0041a2ac:	pushl (%eax)
0x0041a2ae:	addl %edi, $0x18<UINT8>
0x0041a2b1:	call 0x0042dcd3
0x0042dcd3:	pushl $0x10<UINT8>
0x0042dcd5:	pushl $0x442d70<UINT32>
0x0042dcda:	call 0x0041b470
0x0042dcdf:	andl -4(%ebp), $0x0<UINT8>
0x0042dce3:	pushl 0xc(%ebp)
0x0042dce6:	pushl 0x8(%ebp)
0x0042dce9:	call InitializeCriticalSectionAndSpinCount@KERNEL32.dll
InitializeCriticalSectionAndSpinCount@KERNEL32.dll: API Node	
0x0042dcef:	movl -28(%ebp), %eax
0x0042dcf2:	jmp 0x0042dd23
0x0042dd23:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0042dd2a:	movl %eax, -28(%ebp)
0x0042dd2d:	call 0x0041b4b5
0x0041b4b5:	movl %ecx, -16(%ebp)
0x0041b4b8:	movl %fs:0, %ecx
0x0041b4bf:	popl %ecx
0x0041b4c0:	popl %edi
0x0041b4c1:	popl %edi
0x0041b4c2:	popl %esi
0x0041b4c3:	popl %ebx
0x0041b4c4:	movl %esp, %ebp
0x0041b4c6:	popl %ebp
0x0041b4c7:	pushl %ecx
0x0041b4c8:	ret

0x0042dd32:	ret

0x0041a2b6:	popl %ecx
0x0041a2b7:	popl %ecx
0x0041a2b8:	testl %eax, %eax
0x0041a2ba:	je 12
0x0041a2bc:	incl %esi
0x0041a2bd:	cmpl %esi, $0x24<UINT8>
0x0041a2c0:	jl 0x0041a294
0x0041a2c2:	xorl %eax, %eax
0x0041a2c4:	incl %eax
0x0041a2c5:	popl %edi
0x0041a2c6:	popl %esi
0x0041a2c7:	ret

0x004187c1:	testl %eax, %eax
0x004187c3:	je 101
0x004187c5:	pushl $0x4184fe<UINT32>
0x004187ca:	pushl 0x44797c
0x004187d0:	call 0x0041825b
0x0041825b:	movl %edi, %edi
0x0041825d:	pushl %ebp
0x0041825e:	movl %ebp, %esp
0x00418260:	pushl %esi
0x00418261:	pushl 0x445e1c
0x00418267:	movl %esi, 0x43b19c
0x0041826d:	call TlsGetValue@KERNEL32.dll
0x0041826f:	testl %eax, %eax
0x00418271:	je 33
0x00418273:	movl %eax, 0x445e18
0x00418278:	cmpl %eax, $0xffffffff<UINT8>
0x0041827b:	je 0x00418294
0x00418294:	movl %esi, $0x43f534<UINT32>
0x00418299:	pushl %esi
0x0041829a:	call GetModuleHandleW@KERNEL32.dll
0x004182a0:	testl %eax, %eax
0x004182a2:	jne 0x004182af
0x004182af:	pushl $0x43f550<UINT32>
0x004182b4:	pushl %eax
0x004182b5:	call GetProcAddress@KERNEL32.dll
0x004182bb:	testl %eax, %eax
0x004182bd:	je 8
0x004182bf:	pushl 0x8(%ebp)
0x004182c2:	call DecodePointer@KERNEL32.DLL
DecodePointer@KERNEL32.DLL: API Node	
0x004182c4:	movl 0x8(%ebp), %eax
0x004182c7:	movl %eax, 0x8(%ebp)
0x004182ca:	popl %esi
0x004182cb:	popl %ebp
0x004182cc:	ret

0x004187d5:	popl %ecx
0x004187d6:	call FlsAlloc@KERNEL32.DLL
FlsAlloc@KERNEL32.DLL: API Node	
0x004187d8:	movl 0x445e18, %eax
0x004187dd:	cmpl %eax, $0xffffffff<UINT8>
0x004187e0:	je 72
0x004187e2:	pushl $0x214<UINT32>
0x004187e7:	pushl $0x1<UINT8>
0x004187e9:	call 0x0041d9f6
0x0041d9f6:	movl %edi, %edi
0x0041d9f8:	pushl %ebp
0x0041d9f9:	movl %ebp, %esp
0x0041d9fb:	pushl %esi
0x0041d9fc:	pushl %edi
0x0041d9fd:	xorl %esi, %esi
0x0041d9ff:	pushl $0x0<UINT8>
0x0041da01:	pushl 0xc(%ebp)
0x0041da04:	pushl 0x8(%ebp)
0x0041da07:	call 0x00431524
0x00431524:	pushl $0xc<UINT8>
0x00431526:	pushl $0x442df0<UINT32>
0x0043152b:	call 0x0041b470
0x00431530:	movl %ecx, 0x8(%ebp)
0x00431533:	xorl %edi, %edi
0x00431535:	cmpl %ecx, %edi
0x00431537:	jbe 46
0x00431539:	pushl $0xffffffe0<UINT8>
0x0043153b:	popl %eax
0x0043153c:	xorl %edx, %edx
0x0043153e:	divl %eax, %ecx
0x00431540:	cmpl %eax, 0xc(%ebp)
0x00431543:	sbbl %eax, %eax
0x00431545:	incl %eax
0x00431546:	jne 0x00431567
0x00431567:	imull %ecx, 0xc(%ebp)
0x0043156b:	movl %esi, %ecx
0x0043156d:	movl 0x8(%ebp), %esi
0x00431570:	cmpl %esi, %edi
0x00431572:	jne 0x00431577
0x00431577:	xorl %ebx, %ebx
0x00431579:	movl -28(%ebp), %ebx
0x0043157c:	cmpl %esi, $0xffffffe0<UINT8>
0x0043157f:	ja 105
0x00431581:	cmpl 0x449558, $0x3<UINT8>
0x00431588:	jne 0x004315d5
0x004315d5:	cmpl %ebx, %edi
0x004315d7:	jne 97
0x004315d9:	pushl %esi
0x004315da:	pushl $0x8<UINT8>
0x004315dc:	pushl 0x447e14
0x004315e2:	call HeapAlloc@KERNEL32.dll
HeapAlloc@KERNEL32.dll: API Node	
0x004315e8:	movl %ebx, %eax
0x004315ea:	cmpl %ebx, %edi
0x004315ec:	jne 0x0043163a
0x0043163a:	movl %eax, %ebx
0x0043163c:	call 0x0041b4b5
0x00431641:	ret

0x0041da0c:	movl %edi, %eax
0x0041da0e:	addl %esp, $0xc<UINT8>
0x0041da11:	testl %edi, %edi
0x0041da13:	jne 0x0041da3c
0x0041da3c:	movl %eax, %edi
0x0041da3e:	popl %edi
0x0041da3f:	popl %esi
0x0041da40:	popl %ebp
0x0041da41:	ret

0x004187ee:	movl %esi, %eax
0x004187f0:	popl %ecx
0x004187f1:	popl %ecx
0x004187f2:	testl %esi, %esi
0x004187f4:	je 52
0x004187f6:	pushl %esi
0x004187f7:	pushl 0x445e18
0x004187fd:	pushl 0x447984
0x00418803:	call 0x0041825b
0x0041827d:	pushl %eax
0x0041827e:	pushl 0x445e1c
0x00418284:	call TlsGetValue@KERNEL32.dll
0x00418286:	call FlsGetValue@KERNEL32.DLL
FlsGetValue@KERNEL32.DLL: API Node	
0x00418288:	testl %eax, %eax
0x0041828a:	je 0x00418294
0x00418808:	popl %ecx
0x00418809:	call FlsSetValue@KERNEL32.DLL
FlsSetValue@KERNEL32.DLL: API Node	
0x0041880b:	testl %eax, %eax
0x0041880d:	je 27
0x0041880f:	pushl $0x0<UINT8>
0x00418811:	pushl %esi
0x00418812:	call 0x00418384
0x00418384:	pushl $0xc<UINT8>
0x00418386:	pushl $0x4428f8<UINT32>
0x0041838b:	call 0x0041b470
0x00418390:	movl %esi, $0x43f534<UINT32>
0x00418395:	pushl %esi
0x00418396:	call GetModuleHandleW@KERNEL32.dll
0x0041839c:	testl %eax, %eax
0x0041839e:	jne 0x004183a7
0x004183a7:	movl -28(%ebp), %eax
0x004183aa:	movl %esi, 0x8(%ebp)
0x004183ad:	movl 0x5c(%esi), $0x43fc68<UINT32>
0x004183b4:	xorl %edi, %edi
0x004183b6:	incl %edi
0x004183b7:	movl 0x14(%esi), %edi
0x004183ba:	testl %eax, %eax
0x004183bc:	je 36
0x004183be:	pushl $0x43f524<UINT32>
0x004183c3:	pushl %eax
0x004183c4:	movl %ebx, 0x43b20c
0x004183ca:	call GetProcAddress@KERNEL32.dll
0x004183cc:	movl 0x1f8(%esi), %eax
0x004183d2:	pushl $0x43f550<UINT32>
0x004183d7:	pushl -28(%ebp)
0x004183da:	call GetProcAddress@KERNEL32.dll
0x004183dc:	movl 0x1fc(%esi), %eax
0x004183e2:	movl 0x70(%esi), %edi
0x004183e5:	movb 0xc8(%esi), $0x43<UINT8>
0x004183ec:	movb 0x14b(%esi), $0x43<UINT8>
0x004183f3:	movl 0x68(%esi), $0x445800<UINT32>
0x004183fa:	pushl $0xd<UINT8>
0x004183fc:	call 0x0041a41d
0x0041a41d:	movl %edi, %edi
0x0041a41f:	pushl %ebp
0x0041a420:	movl %ebp, %esp
0x0041a422:	movl %eax, 0x8(%ebp)
0x0041a425:	pushl %esi
0x0041a426:	leal %esi, 0x445e50(,%eax,8)
0x0041a42d:	cmpl (%esi), $0x0<UINT8>
0x0041a430:	jne 0x0041a445
0x0041a445:	pushl (%esi)
0x0041a447:	call EnterCriticalSection@KERNEL32.dll
EnterCriticalSection@KERNEL32.dll: API Node	
0x0041a44d:	popl %esi
0x0041a44e:	popl %ebp
0x0041a44f:	ret

0x00418401:	popl %ecx
0x00418402:	andl -4(%ebp), $0x0<UINT8>
0x00418406:	pushl 0x68(%esi)
0x00418409:	call InterlockedIncrement@KERNEL32.dll
InterlockedIncrement@KERNEL32.dll: API Node	
0x0041840f:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00418416:	call 0x00418459
0x00418459:	pushl $0xd<UINT8>
0x0041845b:	call 0x0041a32b
0x0041a32b:	movl %edi, %edi
0x0041a32d:	pushl %ebp
0x0041a32e:	movl %ebp, %esp
0x0041a330:	movl %eax, 0x8(%ebp)
0x0041a333:	pushl 0x445e50(,%eax,8)
0x0041a33a:	call LeaveCriticalSection@KERNEL32.dll
LeaveCriticalSection@KERNEL32.dll: API Node	
0x0041a340:	popl %ebp
0x0041a341:	ret

0x00418460:	popl %ecx
0x00418461:	ret

0x0041841b:	pushl $0xc<UINT8>
0x0041841d:	call 0x0041a41d
0x00418422:	popl %ecx
0x00418423:	movl -4(%ebp), %edi
0x00418426:	movl %eax, 0xc(%ebp)
0x00418429:	movl 0x6c(%esi), %eax
0x0041842c:	testl %eax, %eax
0x0041842e:	jne 8
0x00418430:	movl %eax, 0x445e08
0x00418435:	movl 0x6c(%esi), %eax
0x00418438:	pushl 0x6c(%esi)
0x0041843b:	call 0x00417072
0x00417072:	movl %edi, %edi
0x00417074:	pushl %ebp
0x00417075:	movl %ebp, %esp
0x00417077:	pushl %ebx
0x00417078:	pushl %esi
0x00417079:	movl %esi, 0x43b228
0x0041707f:	pushl %edi
0x00417080:	movl %edi, 0x8(%ebp)
0x00417083:	pushl %edi
0x00417084:	call InterlockedIncrement@KERNEL32.dll
0x00417086:	movl %eax, 0xb0(%edi)
0x0041708c:	testl %eax, %eax
0x0041708e:	je 0x00417093
0x00417093:	movl %eax, 0xb8(%edi)
0x00417099:	testl %eax, %eax
0x0041709b:	je 0x004170a0
0x004170a0:	movl %eax, 0xb4(%edi)
0x004170a6:	testl %eax, %eax
0x004170a8:	je 0x004170ad
0x004170ad:	movl %eax, 0xc0(%edi)
0x004170b3:	testl %eax, %eax
0x004170b5:	je 0x004170ba
0x004170ba:	leal %ebx, 0x50(%edi)
0x004170bd:	movl 0x8(%ebp), $0x6<UINT32>
0x004170c4:	cmpl -8(%ebx), $0x445d28<UINT32>
0x004170cb:	je 0x004170d6
0x004170cd:	movl %eax, (%ebx)
0x004170cf:	testl %eax, %eax
0x004170d1:	je 0x004170d6
0x004170d6:	cmpl -4(%ebx), $0x0<UINT8>
0x004170da:	je 0x004170e6
0x004170e6:	addl %ebx, $0x10<UINT8>
0x004170e9:	decl 0x8(%ebp)
0x004170ec:	jne 0x004170c4
0x004170ee:	movl %eax, 0xd4(%edi)
0x004170f4:	addl %eax, $0xb4<UINT32>
0x004170f9:	pushl %eax
0x004170fa:	call InterlockedIncrement@KERNEL32.dll
0x004170fc:	popl %edi
0x004170fd:	popl %esi
0x004170fe:	popl %ebx
0x004170ff:	popl %ebp
0x00417100:	ret

0x00418440:	popl %ecx
0x00418441:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00418448:	call 0x00418462
0x00418462:	pushl $0xc<UINT8>
0x00418464:	call 0x0041a32b
0x00418469:	popl %ecx
0x0041846a:	ret

0x0041844d:	call 0x0041b4b5
0x00418452:	ret

0x00418817:	popl %ecx
0x00418818:	popl %ecx
0x00418819:	call GetCurrentThreadId@KERNEL32.dll
0x0041881f:	orl 0x4(%esi), $0xffffffff<UINT8>
0x00418823:	movl (%esi), %eax
0x00418825:	xorl %eax, %eax
0x00418827:	incl %eax
0x00418828:	jmp 0x00418831
0x00418831:	popl %edi
0x00418832:	popl %esi
0x00418833:	ret

0x004148df:	testl %eax, %eax
0x004148e1:	jne 0x004148eb
0x004148eb:	call 0x0041f667
0x0041f667:	movl %edi, %edi
0x0041f669:	pushl %esi
0x0041f66a:	movl %eax, $0x441e9c<UINT32>
0x0041f66f:	movl %esi, $0x441e9c<UINT32>
0x0041f674:	pushl %edi
0x0041f675:	movl %edi, %eax
0x0041f677:	cmpl %eax, %esi
0x0041f679:	jae 0x0041f68a
0x0041f68a:	popl %edi
0x0041f68b:	popl %esi
0x0041f68c:	ret

0x004148f0:	movl -4(%ebp), %ebx
0x004148f3:	call 0x0041e618
0x0041e618:	pushl $0x54<UINT8>
0x0041e61a:	pushl $0x442c50<UINT32>
0x0041e61f:	call 0x0041b470
0x0041e624:	xorl %edi, %edi
0x0041e626:	movl -4(%ebp), %edi
0x0041e629:	leal %eax, -100(%ebp)
0x0041e62c:	pushl %eax
0x0041e62d:	call GetStartupInfoA@KERNEL32.dll
0x0041e633:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0041e63a:	pushl $0x40<UINT8>
0x0041e63c:	pushl $0x20<UINT8>
0x0041e63e:	popl %esi
0x0041e63f:	pushl %esi
0x0041e640:	call 0x0041d9f6
0x0041e645:	popl %ecx
0x0041e646:	popl %ecx
0x0041e647:	cmpl %eax, %edi
0x0041e649:	je 532
0x0041e64f:	movl 0x448420, %eax
0x0041e654:	movl 0x448404, %esi
0x0041e65a:	leal %ecx, 0x800(%eax)
0x0041e660:	jmp 0x0041e692
0x0041e692:	cmpl %eax, %ecx
0x0041e694:	jb 0x0041e662
0x0041e662:	movb 0x4(%eax), $0x0<UINT8>
0x0041e666:	orl (%eax), $0xffffffff<UINT8>
0x0041e669:	movb 0x5(%eax), $0xa<UINT8>
0x0041e66d:	movl 0x8(%eax), %edi
0x0041e670:	movb 0x24(%eax), $0x0<UINT8>
0x0041e674:	movb 0x25(%eax), $0xa<UINT8>
0x0041e678:	movb 0x26(%eax), $0xa<UINT8>
0x0041e67c:	movl 0x38(%eax), %edi
0x0041e67f:	movb 0x34(%eax), $0x0<UINT8>
0x0041e683:	addl %eax, $0x40<UINT8>
0x0041e686:	movl %ecx, 0x448420
0x0041e68c:	addl %ecx, $0x800<UINT32>
0x0041e696:	cmpw -50(%ebp), %di
0x0041e69a:	je 266
0x0041e6a0:	movl %eax, -48(%ebp)
0x0041e6a3:	cmpl %eax, %edi
0x0041e6a5:	je 255
0x0041e6ab:	movl %edi, (%eax)
0x0041e6ad:	leal %ebx, 0x4(%eax)
0x0041e6b0:	leal %eax, (%ebx,%edi)
0x0041e6b3:	movl -28(%ebp), %eax
0x0041e6b6:	movl %esi, $0x800<UINT32>
0x0041e6bb:	cmpl %edi, %esi
0x0041e6bd:	jl 0x0041e6c1
0x0041e6c1:	movl -32(%ebp), $0x1<UINT32>
0x0041e6c8:	jmp 0x0041e725
0x0041e725:	cmpl 0x448404, %edi
0x0041e72b:	jl -99
0x0041e72d:	jmp 0x0041e735
0x0041e735:	andl -32(%ebp), $0x0<UINT8>
0x0041e739:	testl %edi, %edi
0x0041e73b:	jle 0x0041e7aa
0x0041e7aa:	xorl %ebx, %ebx
0x0041e7ac:	movl %esi, %ebx
0x0041e7ae:	shll %esi, $0x6<UINT8>
0x0041e7b1:	addl %esi, 0x448420
0x0041e7b7:	movl %eax, (%esi)
0x0041e7b9:	cmpl %eax, $0xffffffff<UINT8>
0x0041e7bc:	je 0x0041e7c9
0x0041e7c9:	movb 0x4(%esi), $0xffffff81<UINT8>
0x0041e7cd:	testl %ebx, %ebx
0x0041e7cf:	jne 0x0041e7d6
0x0041e7d1:	pushl $0xfffffff6<UINT8>
0x0041e7d3:	popl %eax
0x0041e7d4:	jmp 0x0041e7e0
0x0041e7e0:	pushl %eax
0x0041e7e1:	call GetStdHandle@KERNEL32.dll
GetStdHandle@KERNEL32.dll: API Node	
0x0041e7e7:	movl %edi, %eax
0x0041e7e9:	cmpl %edi, $0xffffffff<UINT8>
0x0041e7ec:	je 67
0x0041e7ee:	testl %edi, %edi
0x0041e7f0:	je 63
0x0041e7f2:	pushl %edi
0x0041e7f3:	call GetFileType@KERNEL32.dll
GetFileType@KERNEL32.dll: API Node	
0x0041e7f9:	testl %eax, %eax
0x0041e7fb:	je 52
0x0041e7fd:	movl (%esi), %edi
0x0041e7ff:	andl %eax, $0xff<UINT32>
0x0041e804:	cmpl %eax, $0x2<UINT8>
0x0041e807:	jne 6
0x0041e809:	orb 0x4(%esi), $0x40<UINT8>
0x0041e80d:	jmp 0x0041e818
0x0041e818:	pushl $0xfa0<UINT32>
0x0041e81d:	leal %eax, 0xc(%esi)
0x0041e820:	pushl %eax
0x0041e821:	call 0x0042dcd3
0x0041e826:	popl %ecx
0x0041e827:	popl %ecx
0x0041e828:	testl %eax, %eax
0x0041e82a:	je 55
0x0041e82c:	incl 0x8(%esi)
0x0041e82f:	jmp 0x0041e83b
0x0041e83b:	incl %ebx
0x0041e83c:	cmpl %ebx, $0x3<UINT8>
0x0041e83f:	jl 0x0041e7ac
0x0041e7d6:	movl %eax, %ebx
0x0041e7d8:	decl %eax
0x0041e7d9:	negl %eax
0x0041e7db:	sbbl %eax, %eax
0x0041e7dd:	addl %eax, $0xfffffff5<UINT8>
0x0041e845:	pushl 0x448404
0x0041e84b:	call SetHandleCount@KERNEL32.dll
SetHandleCount@KERNEL32.dll: API Node	
0x0041e851:	xorl %eax, %eax
0x0041e853:	jmp 0x0041e866
0x0041e866:	call 0x0041b4b5
0x0041e86b:	ret

0x004148f8:	testl %eax, %eax
0x004148fa:	jnl 0x00414904
0x00414904:	call GetCommandLineA@KERNEL32.dll
GetCommandLineA@KERNEL32.dll: API Node	
0x0041490a:	movl 0x449588, %eax
0x0041490f:	call 0x0041f530
0x0041f530:	movl %edi, %edi
0x0041f532:	pushl %ebp
0x0041f533:	movl %ebp, %esp
0x0041f535:	movl %eax, 0x448280
0x0041f53a:	subl %esp, $0xc<UINT8>
0x0041f53d:	pushl %ebx
0x0041f53e:	pushl %esi
0x0041f53f:	movl %esi, 0x43b13c
0x0041f545:	pushl %edi
0x0041f546:	xorl %ebx, %ebx
0x0041f548:	xorl %edi, %edi
0x0041f54a:	cmpl %eax, %ebx
0x0041f54c:	jne 46
0x0041f54e:	call GetEnvironmentStringsW@KERNEL32.dll
GetEnvironmentStringsW@KERNEL32.dll: API Node	
0x0041f550:	movl %edi, %eax
0x0041f552:	cmpl %edi, %ebx
0x0041f554:	je 12
0x0041f556:	movl 0x448280, $0x1<UINT32>
0x0041f560:	jmp 0x0041f585
0x0041f585:	cmpl %edi, %ebx
0x0041f587:	jne 0x0041f598
0x0041f598:	movl %eax, %edi
0x0041f59a:	cmpw (%edi), %bx
0x0041f59d:	je 14
0x0041f59f:	incl %eax
0x0041f5a0:	incl %eax
0x0041f5a1:	cmpw (%eax), %bx
0x0041f5a4:	jne 0x0041f59f
0x0041f5a6:	incl %eax
0x0041f5a7:	incl %eax
0x0041f5a8:	cmpw (%eax), %bx
0x0041f5ab:	jne 0x0041f59f
0x0041f5ad:	movl %esi, 0x43b1ec
0x0041f5b3:	pushl %ebx
0x0041f5b4:	pushl %ebx
0x0041f5b5:	pushl %ebx
0x0041f5b6:	subl %eax, %edi
0x0041f5b8:	pushl %ebx
0x0041f5b9:	sarl %eax
0x0041f5bb:	incl %eax
0x0041f5bc:	pushl %eax
0x0041f5bd:	pushl %edi
0x0041f5be:	pushl %ebx
0x0041f5bf:	pushl %ebx
0x0041f5c0:	movl -12(%ebp), %eax
0x0041f5c3:	call WideCharToMultiByte@KERNEL32.dll
WideCharToMultiByte@KERNEL32.dll: API Node	
0x0041f5c5:	movl -8(%ebp), %eax
0x0041f5c8:	cmpl %eax, %ebx
0x0041f5ca:	je 47
0x0041f5cc:	pushl %eax
0x0041f5cd:	call 0x0041d9b1
0x0041d9b1:	movl %edi, %edi
0x0041d9b3:	pushl %ebp
0x0041d9b4:	movl %ebp, %esp
0x0041d9b6:	pushl %esi
0x0041d9b7:	pushl %edi
0x0041d9b8:	xorl %esi, %esi
0x0041d9ba:	pushl 0x8(%ebp)
0x0041d9bd:	call 0x00412493
0x00412493:	movl %edi, %edi
0x00412495:	pushl %ebp
0x00412496:	movl %ebp, %esp
0x00412498:	pushl %esi
0x00412499:	movl %esi, 0x8(%ebp)
0x0041249c:	cmpl %esi, $0xffffffe0<UINT8>
0x0041249f:	ja 161
0x004124a5:	pushl %ebx
0x004124a6:	pushl %edi
0x004124a7:	movl %edi, 0x43b1d0
0x004124ad:	cmpl 0x447e14, $0x0<UINT8>
0x004124b4:	jne 0x004124ce
0x004124ce:	movl %eax, 0x449558
0x004124d3:	cmpl %eax, $0x1<UINT8>
0x004124d6:	jne 14
0x004124d8:	testl %esi, %esi
0x004124da:	je 4
0x004124dc:	movl %eax, %esi
0x004124de:	jmp 0x004124e3
0x004124e3:	pushl %eax
0x004124e4:	jmp 0x00412502
0x00412502:	pushl $0x0<UINT8>
0x00412504:	pushl 0x447e14
0x0041250a:	call HeapAlloc@KERNEL32.dll
0x0041250c:	movl %ebx, %eax
0x0041250e:	testl %ebx, %ebx
0x00412510:	jne 0x00412540
0x00412540:	popl %edi
0x00412541:	movl %eax, %ebx
0x00412543:	popl %ebx
0x00412544:	jmp 0x0041255a
0x0041255a:	popl %esi
0x0041255b:	popl %ebp
0x0041255c:	ret

0x0041d9c2:	movl %edi, %eax
0x0041d9c4:	popl %ecx
0x0041d9c5:	testl %edi, %edi
0x0041d9c7:	jne 0x0041d9f0
0x0041d9f0:	movl %eax, %edi
0x0041d9f2:	popl %edi
0x0041d9f3:	popl %esi
0x0041d9f4:	popl %ebp
0x0041d9f5:	ret

0x0041f5d2:	popl %ecx
0x0041f5d3:	movl -4(%ebp), %eax
0x0041f5d6:	cmpl %eax, %ebx
0x0041f5d8:	je 33
0x0041f5da:	pushl %ebx
0x0041f5db:	pushl %ebx
0x0041f5dc:	pushl -8(%ebp)
0x0041f5df:	pushl %eax
0x0041f5e0:	pushl -12(%ebp)
0x0041f5e3:	pushl %edi
0x0041f5e4:	pushl %ebx
0x0041f5e5:	pushl %ebx
0x0041f5e6:	call WideCharToMultiByte@KERNEL32.dll
0x0041f5e8:	testl %eax, %eax
0x0041f5ea:	jne 0x0041f5f8
0x0041f5f8:	movl %ebx, -4(%ebp)
0x0041f5fb:	pushl %edi
0x0041f5fc:	call FreeEnvironmentStringsW@KERNEL32.dll
FreeEnvironmentStringsW@KERNEL32.dll: API Node	
0x0041f602:	movl %eax, %ebx
0x0041f604:	jmp 0x0041f662
0x0041f662:	popl %edi
0x0041f663:	popl %esi
0x0041f664:	popl %ebx
0x0041f665:	leave
0x0041f666:	ret

0x00414914:	movl 0x447924, %eax
0x00414919:	call 0x0041f475
0x0041f475:	movl %edi, %edi
0x0041f477:	pushl %ebp
0x0041f478:	movl %ebp, %esp
0x0041f47a:	subl %esp, $0xc<UINT8>
0x0041f47d:	pushl %ebx
0x0041f47e:	xorl %ebx, %ebx
0x0041f480:	pushl %esi
0x0041f481:	pushl %edi
0x0041f482:	cmpl 0x449550, %ebx
0x0041f488:	jne 5
0x0041f48a:	call 0x00416eff
0x00416eff:	cmpl 0x449550, $0x0<UINT8>
0x00416f06:	jne 0x00416f1a
0x00416f08:	pushl $0xfffffffd<UINT8>
0x00416f0a:	call 0x00416d65
0x00416d65:	pushl $0x14<UINT8>
0x00416d67:	pushl $0x442830<UINT32>
0x00416d6c:	call 0x0041b470
0x00416d71:	orl -32(%ebp), $0xffffffff<UINT8>
0x00416d75:	call 0x004184e4
0x004184e4:	movl %edi, %edi
0x004184e6:	pushl %esi
0x004184e7:	call 0x0041846b
0x0041846b:	movl %edi, %edi
0x0041846d:	pushl %esi
0x0041846e:	pushl %edi
0x0041846f:	call GetLastError@KERNEL32.dll
GetLastError@KERNEL32.dll: API Node	
0x00418475:	pushl 0x445e18
0x0041847b:	movl %edi, %eax
0x0041847d:	call 0x004182f6
0x004182f6:	movl %edi, %edi
0x004182f8:	pushl %esi
0x004182f9:	pushl 0x445e1c
0x004182ff:	call TlsGetValue@KERNEL32.dll
0x00418305:	movl %esi, %eax
0x00418307:	testl %esi, %esi
0x00418309:	jne 0x00418326
0x00418326:	movl %eax, %esi
0x00418328:	popl %esi
0x00418329:	ret

0x00418482:	call FlsGetValue@KERNEL32.DLL
0x00418484:	movl %esi, %eax
0x00418486:	testl %esi, %esi
0x00418488:	jne 0x004184d8
0x004184d8:	pushl %edi
0x004184d9:	call SetLastError@KERNEL32.dll
SetLastError@KERNEL32.dll: API Node	
0x004184df:	popl %edi
0x004184e0:	movl %eax, %esi
0x004184e2:	popl %esi
0x004184e3:	ret

0x004184ec:	movl %esi, %eax
0x004184ee:	testl %esi, %esi
0x004184f0:	jne 0x004184fa
0x004184fa:	movl %eax, %esi
0x004184fc:	popl %esi
0x004184fd:	ret

0x00416d7a:	movl %edi, %eax
0x00416d7c:	movl -36(%ebp), %edi
0x00416d7f:	call 0x00416a22
0x00416a22:	pushl $0xc<UINT8>
0x00416a24:	pushl $0x442810<UINT32>
0x00416a29:	call 0x0041b470
0x00416a2e:	call 0x004184e4
0x00416a33:	movl %edi, %eax
0x00416a35:	movl %eax, 0x445d24
0x00416a3a:	testl 0x70(%edi), %eax
0x00416a3d:	je 0x00416a5c
0x00416a5c:	pushl $0xd<UINT8>
0x00416a5e:	call 0x0041a41d
0x00416a63:	popl %ecx
0x00416a64:	andl -4(%ebp), $0x0<UINT8>
0x00416a68:	movl %esi, 0x68(%edi)
0x00416a6b:	movl -28(%ebp), %esi
0x00416a6e:	cmpl %esi, 0x445c28
0x00416a74:	je 0x00416aac
0x00416aac:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00416ab3:	call 0x00416abd
0x00416abd:	pushl $0xd<UINT8>
0x00416abf:	call 0x0041a32b
0x00416ac4:	popl %ecx
0x00416ac5:	ret

0x00416ab8:	jmp 0x00416a48
0x00416a48:	testl %esi, %esi
0x00416a4a:	jne 0x00416a54
0x00416a54:	movl %eax, %esi
0x00416a56:	call 0x0041b4b5
0x00416a5b:	ret

0x00416d84:	movl %ebx, 0x68(%edi)
0x00416d87:	movl %esi, 0x8(%ebp)
0x00416d8a:	call 0x00416ac6
0x00416ac6:	movl %edi, %edi
0x00416ac8:	pushl %ebp
0x00416ac9:	movl %ebp, %esp
0x00416acb:	subl %esp, $0x10<UINT8>
0x00416ace:	pushl %ebx
0x00416acf:	xorl %ebx, %ebx
0x00416ad1:	pushl %ebx
0x00416ad2:	leal %ecx, -16(%ebp)
0x00416ad5:	call 0x00411837
0x00411837:	movl %edi, %edi
0x00411839:	pushl %ebp
0x0041183a:	movl %ebp, %esp
0x0041183c:	movl %eax, 0x8(%ebp)
0x0041183f:	pushl %esi
0x00411840:	movl %esi, %ecx
0x00411842:	movb 0xc(%esi), $0x0<UINT8>
0x00411846:	testl %eax, %eax
0x00411848:	jne 0x004118ad
0x0041184a:	call 0x004184e4
0x0041184f:	movl 0x8(%esi), %eax
0x00411852:	movl %ecx, 0x6c(%eax)
0x00411855:	movl (%esi), %ecx
0x00411857:	movl %ecx, 0x68(%eax)
0x0041185a:	movl 0x4(%esi), %ecx
0x0041185d:	movl %ecx, (%esi)
0x0041185f:	cmpl %ecx, 0x445e08
0x00411865:	je 0x00411879
0x00411879:	movl %eax, 0x4(%esi)
0x0041187c:	cmpl %eax, 0x445c28
0x00411882:	je 0x0041189a
0x0041189a:	movl %eax, 0x8(%esi)
0x0041189d:	testb 0x70(%eax), $0x2<UINT8>
0x004118a1:	jne 20
0x004118a3:	orl 0x70(%eax), $0x2<UINT8>
0x004118a7:	movb 0xc(%esi), $0x1<UINT8>
0x004118ab:	jmp 0x004118b7
0x004118b7:	movl %eax, %esi
0x004118b9:	popl %esi
0x004118ba:	popl %ebp
0x004118bb:	ret $0x4<UINT16>

0x00416ada:	movl 0x44793c, %ebx
0x00416ae0:	cmpl %esi, $0xfffffffe<UINT8>
0x00416ae3:	jne 0x00416b03
0x00416b03:	cmpl %esi, $0xfffffffd<UINT8>
0x00416b06:	jne 0x00416b1a
0x00416b08:	movl 0x44793c, $0x1<UINT32>
0x00416b12:	call GetACP@KERNEL32.dll
GetACP@KERNEL32.dll: API Node	
0x00416b18:	jmp 0x00416af5
0x00416af5:	cmpb -4(%ebp), %bl
0x00416af8:	je 69
0x00416afa:	movl %ecx, -8(%ebp)
0x00416afd:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00416b01:	jmp 0x00416b3f
0x00416b3f:	popl %ebx
0x00416b40:	leave
0x00416b41:	ret

0x00416d8f:	movl 0x8(%ebp), %eax
0x00416d92:	cmpl %eax, 0x4(%ebx)
0x00416d95:	je 343
0x00416d9b:	pushl $0x220<UINT32>
0x00416da0:	call 0x0041d9b1
0x00416da5:	popl %ecx
0x00416da6:	movl %ebx, %eax
0x00416da8:	testl %ebx, %ebx
0x00416daa:	je 326
0x00416db0:	movl %ecx, $0x88<UINT32>
0x00416db5:	movl %esi, 0x68(%edi)
0x00416db8:	movl %edi, %ebx
0x00416dba:	rep movsl %es:(%edi), %ds:(%esi)
0x00416dbc:	andl (%ebx), $0x0<UINT8>
0x00416dbf:	pushl %ebx
0x00416dc0:	pushl 0x8(%ebp)
0x00416dc3:	call 0x00416b42
0x00416b42:	movl %edi, %edi
0x00416b44:	pushl %ebp
0x00416b45:	movl %ebp, %esp
0x00416b47:	subl %esp, $0x20<UINT8>
0x00416b4a:	movl %eax, 0x445654
0x00416b4f:	xorl %eax, %ebp
0x00416b51:	movl -4(%ebp), %eax
0x00416b54:	pushl %ebx
0x00416b55:	movl %ebx, 0xc(%ebp)
0x00416b58:	pushl %esi
0x00416b59:	movl %esi, 0x8(%ebp)
0x00416b5c:	pushl %edi
0x00416b5d:	call 0x00416ac6
0x00416b1a:	cmpl %esi, $0xfffffffc<UINT8>
0x00416b1d:	jne 0x00416b31
0x00416b31:	cmpb -4(%ebp), %bl
0x00416b34:	je 7
0x00416b36:	movl %eax, -8(%ebp)
0x00416b39:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x00416b3d:	movl %eax, %esi
0x00416b62:	movl %edi, %eax
0x00416b64:	xorl %esi, %esi
0x00416b66:	movl 0x8(%ebp), %edi
0x00416b69:	cmpl %edi, %esi
0x00416b6b:	jne 0x00416b7b
0x00416b7b:	movl -28(%ebp), %esi
0x00416b7e:	xorl %eax, %eax
0x00416b80:	cmpl 0x445c30(%eax), %edi
0x00416b86:	je 145
0x00416b8c:	incl -28(%ebp)
0x00416b8f:	addl %eax, $0x30<UINT8>
0x00416b92:	cmpl %eax, $0xf0<UINT32>
0x00416b97:	jb 0x00416b80
0x00416b99:	cmpl %edi, $0xfde8<UINT32>
0x00416b9f:	je 368
0x00416ba5:	cmpl %edi, $0xfde9<UINT32>
0x00416bab:	je 356
0x00416bb1:	movzwl %eax, %di
0x00416bb4:	pushl %eax
0x00416bb5:	call IsValidCodePage@KERNEL32.dll
IsValidCodePage@KERNEL32.dll: API Node	
0x00416bbb:	testl %eax, %eax
0x00416bbd:	je 338
0x00416bc3:	leal %eax, -24(%ebp)
0x00416bc6:	pushl %eax
0x00416bc7:	pushl %edi
0x00416bc8:	call GetCPInfo@KERNEL32.dll
GetCPInfo@KERNEL32.dll: API Node	
0x00416bce:	testl %eax, %eax
0x00416bd0:	je 307
0x00416bd6:	pushl $0x101<UINT32>
0x00416bdb:	leal %eax, 0x1c(%ebx)
0x00416bde:	pushl %esi
0x00416bdf:	pushl %eax
0x00416be0:	call 0x00412350
0x00412350:	movl %edx, 0xc(%esp)
0x00412354:	movl %ecx, 0x4(%esp)
0x00412358:	testl %edx, %edx
0x0041235a:	je 105
0x0041235c:	xorl %eax, %eax
0x0041235e:	movb %al, 0x8(%esp)
0x00412362:	testb %al, %al
0x00412364:	jne 22
0x00412366:	cmpl %edx, $0x100<UINT32>
0x0041236c:	jb 14
0x0041236e:	cmpl 0x449578, $0x0<UINT8>
0x00412375:	je 0x0041237c
0x0041237c:	pushl %edi
0x0041237d:	movl %edi, %ecx
0x0041237f:	cmpl %edx, $0x4<UINT8>
0x00412382:	jb 49
0x00412384:	negl %ecx
0x00412386:	andl %ecx, $0x3<UINT8>
0x00412389:	je 0x00412397
0x00412397:	movl %ecx, %eax
0x00412399:	shll %eax, $0x8<UINT8>
0x0041239c:	addl %eax, %ecx
0x0041239e:	movl %ecx, %eax
0x004123a0:	shll %eax, $0x10<UINT8>
0x004123a3:	addl %eax, %ecx
0x004123a5:	movl %ecx, %edx
0x004123a7:	andl %edx, $0x3<UINT8>
0x004123aa:	shrl %ecx, $0x2<UINT8>
0x004123ad:	je 6
0x004123af:	rep stosl %es:(%edi), %eax
0x004123b1:	testl %edx, %edx
0x004123b3:	je 0x004123bf
0x004123b5:	movb (%edi), %al
0x004123b7:	addl %edi, $0x1<UINT8>
0x004123ba:	subl %edx, $0x1<UINT8>
0x004123bd:	jne -10
0x004123bf:	movl %eax, 0x8(%esp)
0x004123c3:	popl %edi
0x004123c4:	ret

0x00416be5:	xorl %edx, %edx
0x00416be7:	incl %edx
0x00416be8:	addl %esp, $0xc<UINT8>
0x00416beb:	movl 0x4(%ebx), %edi
0x00416bee:	movl 0xc(%ebx), %esi
0x00416bf1:	cmpl -24(%ebp), %edx
0x00416bf4:	jbe 248
0x00416bfa:	cmpb -18(%ebp), $0x0<UINT8>
0x00416bfe:	je 0x00416cd3
0x00416cd3:	leal %eax, 0x1e(%ebx)
0x00416cd6:	movl %ecx, $0xfe<UINT32>
0x00416cdb:	orb (%eax), $0x8<UINT8>
0x00416cde:	incl %eax
0x00416cdf:	decl %ecx
0x00416ce0:	jne 0x00416cdb
0x00416ce2:	movl %eax, 0x4(%ebx)
0x00416ce5:	call 0x004167fc
0x004167fc:	subl %eax, $0x3a4<UINT32>
0x00416801:	je 34
0x00416803:	subl %eax, $0x4<UINT8>
0x00416806:	je 23
0x00416808:	subl %eax, $0xd<UINT8>
0x0041680b:	je 12
0x0041680d:	decl %eax
0x0041680e:	je 3
0x00416810:	xorl %eax, %eax
0x00416812:	ret

0x00416cea:	movl 0xc(%ebx), %eax
0x00416ced:	movl 0x8(%ebx), %edx
0x00416cf0:	jmp 0x00416cf5
0x00416cf5:	xorl %eax, %eax
0x00416cf7:	movzwl %ecx, %ax
0x00416cfa:	movl %eax, %ecx
0x00416cfc:	shll %ecx, $0x10<UINT8>
0x00416cff:	orl %eax, %ecx
0x00416d01:	leal %edi, 0x10(%ebx)
0x00416d04:	stosl %es:(%edi), %eax
0x00416d05:	stosl %es:(%edi), %eax
0x00416d06:	stosl %es:(%edi), %eax
0x00416d07:	jmp 0x00416cb1
0x00416cb1:	movl %esi, %ebx
0x00416cb3:	call 0x0041688f
0x0041688f:	movl %edi, %edi
0x00416891:	pushl %ebp
0x00416892:	movl %ebp, %esp
0x00416894:	subl %esp, $0x51c<UINT32>
0x0041689a:	movl %eax, 0x445654
0x0041689f:	xorl %eax, %ebp
0x004168a1:	movl -4(%ebp), %eax
0x004168a4:	pushl %ebx
0x004168a5:	pushl %edi
0x004168a6:	leal %eax, -1304(%ebp)
0x004168ac:	pushl %eax
0x004168ad:	pushl 0x4(%esi)
0x004168b0:	call GetCPInfo@KERNEL32.dll
0x004168b6:	movl %edi, $0x100<UINT32>
0x004168bb:	testl %eax, %eax
0x004168bd:	je 251
0x004168c3:	xorl %eax, %eax
0x004168c5:	movb -260(%ebp,%eax), %al
0x004168cc:	incl %eax
0x004168cd:	cmpl %eax, %edi
0x004168cf:	jb 0x004168c5
0x004168d1:	movb %al, -1298(%ebp)
0x004168d7:	movb -260(%ebp), $0x20<UINT8>
0x004168de:	testb %al, %al
0x004168e0:	je 0x00416910
0x00416910:	pushl $0x0<UINT8>
0x00416912:	pushl 0xc(%esi)
0x00416915:	leal %eax, -1284(%ebp)
0x0041691b:	pushl 0x4(%esi)
0x0041691e:	pushl %eax
0x0041691f:	pushl %edi
0x00416920:	leal %eax, -260(%ebp)
0x00416926:	pushl %eax
0x00416927:	pushl $0x1<UINT8>
0x00416929:	pushl $0x0<UINT8>
0x0041692b:	call 0x00427e95
0x00427e95:	movl %edi, %edi
0x00427e97:	pushl %ebp
0x00427e98:	movl %ebp, %esp
0x00427e9a:	subl %esp, $0x10<UINT8>
0x00427e9d:	pushl 0x8(%ebp)
0x00427ea0:	leal %ecx, -16(%ebp)
0x00427ea3:	call 0x00411837
0x00427ea8:	pushl 0x24(%ebp)
0x00427eab:	leal %ecx, -16(%ebp)
0x00427eae:	pushl 0x20(%ebp)
0x00427eb1:	pushl 0x1c(%ebp)
0x00427eb4:	pushl 0x18(%ebp)
0x00427eb7:	pushl 0x14(%ebp)
0x00427eba:	pushl 0x10(%ebp)
0x00427ebd:	pushl 0xc(%ebp)
0x00427ec0:	call 0x00427cdb
0x00427cdb:	movl %edi, %edi
0x00427cdd:	pushl %ebp
0x00427cde:	movl %ebp, %esp
0x00427ce0:	pushl %ecx
0x00427ce1:	pushl %ecx
0x00427ce2:	movl %eax, 0x445654
0x00427ce7:	xorl %eax, %ebp
0x00427ce9:	movl -4(%ebp), %eax
0x00427cec:	movl %eax, 0x4482f4
0x00427cf1:	pushl %ebx
0x00427cf2:	pushl %esi
0x00427cf3:	xorl %ebx, %ebx
0x00427cf5:	pushl %edi
0x00427cf6:	movl %edi, %ecx
0x00427cf8:	cmpl %eax, %ebx
0x00427cfa:	jne 58
0x00427cfc:	leal %eax, -8(%ebp)
0x00427cff:	pushl %eax
0x00427d00:	xorl %esi, %esi
0x00427d02:	incl %esi
0x00427d03:	pushl %esi
0x00427d04:	pushl $0x43e56c<UINT32>
0x00427d09:	pushl %esi
0x00427d0a:	call GetStringTypeW@KERNEL32.dll
GetStringTypeW@KERNEL32.dll: API Node	
0x00427d10:	testl %eax, %eax
0x00427d12:	je 8
0x00427d14:	movl 0x4482f4, %esi
0x00427d1a:	jmp 0x00427d50
0x00427d50:	movl -8(%ebp), %ebx
0x00427d53:	cmpl 0x18(%ebp), %ebx
0x00427d56:	jne 0x00427d60
0x00427d60:	movl %esi, 0x43b1f4
0x00427d66:	xorl %eax, %eax
0x00427d68:	cmpl 0x20(%ebp), %ebx
0x00427d6b:	pushl %ebx
0x00427d6c:	pushl %ebx
0x00427d6d:	pushl 0x10(%ebp)
0x00427d70:	setne %al
0x00427d73:	pushl 0xc(%ebp)
0x00427d76:	leal %eax, 0x1(,%eax,8)
0x00427d7d:	pushl %eax
0x00427d7e:	pushl 0x18(%ebp)
0x00427d81:	call MultiByteToWideChar@KERNEL32.dll
MultiByteToWideChar@KERNEL32.dll: API Node	
0x00427d83:	movl %edi, %eax
0x00427d85:	cmpl %edi, %ebx
0x00427d87:	je 171
0x00427d8d:	jle 60
0x00427d8f:	cmpl %edi, $0x7ffffff0<UINT32>
0x00427d95:	ja 52
0x00427d97:	leal %eax, 0x8(%edi,%edi)
0x00427d9b:	cmpl %eax, $0x400<UINT32>
0x00427da0:	ja 19
0x00427da2:	call 0x00414b90
0x00414b90:	pushl %ecx
0x00414b91:	leal %ecx, 0x8(%esp)
0x00414b95:	subl %ecx, %eax
0x00414b97:	andl %ecx, $0xf<UINT8>
0x00414b9a:	addl %eax, %ecx
0x00414b9c:	sbbl %ecx, %ecx
0x00414b9e:	orl %eax, %ecx
0x00414ba0:	popl %ecx
0x00414ba1:	jmp 0x00413720
0x00413720:	pushl %ecx
0x00413721:	leal %ecx, 0x4(%esp)
0x00413725:	subl %ecx, %eax
0x00413727:	sbbl %eax, %eax
0x00413729:	notl %eax
0x0041372b:	andl %ecx, %eax
0x0041372d:	movl %eax, %esp
0x0041372f:	andl %eax, $0xfffff000<UINT32>
0x00413734:	cmpl %ecx, %eax
0x00413736:	jb 10
0x00413738:	movl %eax, %ecx
0x0041373a:	popl %ecx
0x0041373b:	xchgl %esp, %eax
0x0041373c:	movl %eax, (%eax)
0x0041373e:	movl (%esp), %eax
0x00413741:	ret

0x00427da7:	movl %eax, %esp
0x00427da9:	cmpl %eax, %ebx
0x00427dab:	je 28
0x00427dad:	movl (%eax), $0xcccc<UINT32>
0x00427db3:	jmp 0x00427dc6
0x00427dc6:	addl %eax, $0x8<UINT8>
0x00427dc9:	movl %ebx, %eax
0x00427dcb:	testl %ebx, %ebx
0x00427dcd:	je 105
0x00427dcf:	leal %eax, (%edi,%edi)
0x00427dd2:	pushl %eax
0x00427dd3:	pushl $0x0<UINT8>
0x00427dd5:	pushl %ebx
0x00427dd6:	call 0x00412350
0x00427ddb:	addl %esp, $0xc<UINT8>
0x00427dde:	pushl %edi
0x00427ddf:	pushl %ebx
0x00427de0:	pushl 0x10(%ebp)
0x00427de3:	pushl 0xc(%ebp)
0x00427de6:	pushl $0x1<UINT8>
0x00427de8:	pushl 0x18(%ebp)
0x00427deb:	call MultiByteToWideChar@KERNEL32.dll
0x00427ded:	testl %eax, %eax
0x00427def:	je 17
0x00427df1:	pushl 0x14(%ebp)
0x00427df4:	pushl %eax
0x00427df5:	pushl %ebx
0x00427df6:	pushl 0x8(%ebp)
0x00427df9:	call GetStringTypeW@KERNEL32.dll
0x00427dff:	movl -8(%ebp), %eax
0x00427e02:	pushl %ebx
0x00427e03:	call 0x00413d6b
0x00413d6b:	movl %edi, %edi
0x00413d6d:	pushl %ebp
0x00413d6e:	movl %ebp, %esp
0x00413d70:	movl %eax, 0x8(%ebp)
0x00413d73:	testl %eax, %eax
0x00413d75:	je 18
0x00413d77:	subl %eax, $0x8<UINT8>
0x00413d7a:	cmpl (%eax), $0xdddd<UINT32>
0x00413d80:	jne 0x00413d89
0x00413d89:	popl %ebp
0x00413d8a:	ret

0x00427e08:	movl %eax, -8(%ebp)
0x00427e0b:	popl %ecx
0x00427e0c:	jmp 0x00427e83
0x00427e83:	leal %esp, -20(%ebp)
0x00427e86:	popl %edi
0x00427e87:	popl %esi
0x00427e88:	popl %ebx
0x00427e89:	movl %ecx, -4(%ebp)
0x00427e8c:	xorl %ecx, %ebp
0x00427e8e:	call 0x00411a73
0x00411a73:	cmpl %ecx, 0x445654
0x00411a79:	jne 2
0x00411a7b:	rep ret

0x00427e93:	leave
0x00427e94:	ret

0x00427ec5:	addl %esp, $0x1c<UINT8>
0x00427ec8:	cmpb -4(%ebp), $0x0<UINT8>
0x00427ecc:	je 7
0x00427ece:	movl %ecx, -8(%ebp)
0x00427ed1:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00427ed5:	leave
0x00427ed6:	ret

0x00416930:	xorl %ebx, %ebx
0x00416932:	pushl %ebx
0x00416933:	pushl 0x4(%esi)
0x00416936:	leal %eax, -516(%ebp)
0x0041693c:	pushl %edi
0x0041693d:	pushl %eax
0x0041693e:	pushl %edi
0x0041693f:	leal %eax, -260(%ebp)
0x00416945:	pushl %eax
0x00416946:	pushl %edi
0x00416947:	pushl 0xc(%esi)
0x0041694a:	pushl %ebx
0x0041694b:	call 0x0041a09f
0x0041a09f:	movl %edi, %edi
0x0041a0a1:	pushl %ebp
0x0041a0a2:	movl %ebp, %esp
0x0041a0a4:	subl %esp, $0x10<UINT8>
0x0041a0a7:	pushl 0x8(%ebp)
0x0041a0aa:	leal %ecx, -16(%ebp)
0x0041a0ad:	call 0x00411837
0x0041a0b2:	pushl 0x28(%ebp)
0x0041a0b5:	leal %ecx, -16(%ebp)
0x0041a0b8:	pushl 0x24(%ebp)
0x0041a0bb:	pushl 0x20(%ebp)
0x0041a0be:	pushl 0x1c(%ebp)
0x0041a0c1:	pushl 0x18(%ebp)
0x0041a0c4:	pushl 0x14(%ebp)
0x0041a0c7:	pushl 0x10(%ebp)
0x0041a0ca:	pushl 0xc(%ebp)
0x0041a0cd:	call 0x00419cfa
0x00419cfa:	movl %edi, %edi
0x00419cfc:	pushl %ebp
0x00419cfd:	movl %ebp, %esp
0x00419cff:	subl %esp, $0x14<UINT8>
0x00419d02:	movl %eax, 0x445654
0x00419d07:	xorl %eax, %ebp
0x00419d09:	movl -4(%ebp), %eax
0x00419d0c:	pushl %ebx
0x00419d0d:	pushl %esi
0x00419d0e:	xorl %ebx, %ebx
0x00419d10:	pushl %edi
0x00419d11:	movl %esi, %ecx
0x00419d13:	cmpl 0x447cb8, %ebx
0x00419d19:	jne 0x00419d53
0x00419d1b:	pushl %ebx
0x00419d1c:	pushl %ebx
0x00419d1d:	xorl %edi, %edi
0x00419d1f:	incl %edi
0x00419d20:	pushl %edi
0x00419d21:	pushl $0x43e56c<UINT32>
0x00419d26:	pushl $0x100<UINT32>
0x00419d2b:	pushl %ebx
0x00419d2c:	call LCMapStringW@KERNEL32.dll
LCMapStringW@KERNEL32.dll: API Node	
0x00419d32:	testl %eax, %eax
0x00419d34:	je 8
0x00419d36:	movl 0x447cb8, %edi
0x00419d3c:	jmp 0x00419d53
0x00419d53:	cmpl 0x14(%ebp), %ebx
0x00419d56:	jle 0x00419d7a
0x00419d7a:	movl %eax, 0x447cb8
0x00419d7f:	cmpl %eax, $0x2<UINT8>
0x00419d82:	je 428
0x00419d88:	cmpl %eax, %ebx
0x00419d8a:	je 420
0x00419d90:	cmpl %eax, $0x1<UINT8>
0x00419d93:	jne 460
0x00419d99:	movl -8(%ebp), %ebx
0x00419d9c:	cmpl 0x20(%ebp), %ebx
0x00419d9f:	jne 0x00419da9
0x00419da9:	movl %esi, 0x43b1f4
0x00419daf:	xorl %eax, %eax
0x00419db1:	cmpl 0x24(%ebp), %ebx
0x00419db4:	pushl %ebx
0x00419db5:	pushl %ebx
0x00419db6:	pushl 0x14(%ebp)
0x00419db9:	setne %al
0x00419dbc:	pushl 0x10(%ebp)
0x00419dbf:	leal %eax, 0x1(,%eax,8)
0x00419dc6:	pushl %eax
0x00419dc7:	pushl 0x20(%ebp)
0x00419dca:	call MultiByteToWideChar@KERNEL32.dll
0x00419dcc:	movl %edi, %eax
0x00419dce:	cmpl %edi, %ebx
0x00419dd0:	je 0x00419f65
0x00419f65:	xorl %eax, %eax
0x00419f67:	jmp 0x0041a08d
0x0041a08d:	leal %esp, -32(%ebp)
0x0041a090:	popl %edi
0x0041a091:	popl %esi
0x0041a092:	popl %ebx
0x0041a093:	movl %ecx, -4(%ebp)
0x0041a096:	xorl %ecx, %ebp
0x0041a098:	call 0x00411a73
0x0041a09d:	leave
0x0041a09e:	ret

0x0041a0d2:	addl %esp, $0x20<UINT8>
0x0041a0d5:	cmpb -4(%ebp), $0x0<UINT8>
0x0041a0d9:	je 7
0x0041a0db:	movl %ecx, -8(%ebp)
0x0041a0de:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0041a0e2:	leave
0x0041a0e3:	ret

0x00416950:	addl %esp, $0x44<UINT8>
0x00416953:	pushl %ebx
0x00416954:	pushl 0x4(%esi)
0x00416957:	leal %eax, -772(%ebp)
0x0041695d:	pushl %edi
0x0041695e:	pushl %eax
0x0041695f:	pushl %edi
0x00416960:	leal %eax, -260(%ebp)
0x00416966:	pushl %eax
0x00416967:	pushl $0x200<UINT32>
0x0041696c:	pushl 0xc(%esi)
0x0041696f:	pushl %ebx
0x00416970:	call 0x0041a09f
0x00416975:	addl %esp, $0x24<UINT8>
0x00416978:	xorl %eax, %eax
0x0041697a:	movzwl %ecx, -1284(%ebp,%eax,2)
0x00416982:	testb %cl, $0x1<UINT8>
0x00416985:	je 0x00416995
0x00416995:	testb %cl, $0x2<UINT8>
0x00416998:	je 0x004169af
0x004169af:	movb 0x11d(%esi,%eax), $0x0<UINT8>
0x004169b7:	incl %eax
0x004169b8:	cmpl %eax, %edi
0x004169ba:	jb -66
0x004169bc:	jmp 0x00416a14
0x00416a14:	movl %ecx, -4(%ebp)
0x00416a17:	popl %edi
0x00416a18:	xorl %ecx, %ebp
0x00416a1a:	popl %ebx
0x00416a1b:	call 0x00411a73
0x00416a20:	leave
0x00416a21:	ret

0x00416cb8:	jmp 0x00416b74
0x00416b74:	xorl %eax, %eax
0x00416b76:	jmp 0x00416d18
0x00416d18:	movl %ecx, -4(%ebp)
0x00416d1b:	popl %edi
0x00416d1c:	popl %esi
0x00416d1d:	xorl %ecx, %ebp
0x00416d1f:	popl %ebx
0x00416d20:	call 0x00411a73
0x00416d25:	leave
0x00416d26:	ret

0x00416dc8:	popl %ecx
0x00416dc9:	popl %ecx
0x00416dca:	movl -32(%ebp), %eax
0x00416dcd:	testl %eax, %eax
0x00416dcf:	jne 252
0x00416dd5:	movl %esi, -36(%ebp)
0x00416dd8:	pushl 0x68(%esi)
0x00416ddb:	call InterlockedDecrement@KERNEL32.dll
InterlockedDecrement@KERNEL32.dll: API Node	
0x00416de1:	testl %eax, %eax
0x00416de3:	jne 17
0x00416de5:	movl %eax, 0x68(%esi)
0x00416de8:	cmpl %eax, $0x445800<UINT32>
0x00416ded:	je 0x00416df6
0x00416df6:	movl 0x68(%esi), %ebx
0x00416df9:	pushl %ebx
0x00416dfa:	movl %edi, 0x43b228
0x00416e00:	call InterlockedIncrement@KERNEL32.dll
0x00416e02:	testb 0x70(%esi), $0x2<UINT8>
0x00416e06:	jne 234
0x00416e0c:	testb 0x445d24, $0x1<UINT8>
0x00416e13:	jne 221
0x00416e19:	pushl $0xd<UINT8>
0x00416e1b:	call 0x0041a41d
0x00416e20:	popl %ecx
0x00416e21:	andl -4(%ebp), $0x0<UINT8>
0x00416e25:	movl %eax, 0x4(%ebx)
0x00416e28:	movl 0x44794c, %eax
0x00416e2d:	movl %eax, 0x8(%ebx)
0x00416e30:	movl 0x447950, %eax
0x00416e35:	movl %eax, 0xc(%ebx)
0x00416e38:	movl 0x447954, %eax
0x00416e3d:	xorl %eax, %eax
0x00416e3f:	movl -28(%ebp), %eax
0x00416e42:	cmpl %eax, $0x5<UINT8>
0x00416e45:	jnl 0x00416e57
0x00416e47:	movw %cx, 0x10(%ebx,%eax,2)
0x00416e4c:	movw 0x447940(,%eax,2), %cx
0x00416e54:	incl %eax
0x00416e55:	jmp 0x00416e3f
0x00416e57:	xorl %eax, %eax
0x00416e59:	movl -28(%ebp), %eax
0x00416e5c:	cmpl %eax, $0x101<UINT32>
0x00416e61:	jnl 0x00416e70
0x00416e63:	movb %cl, 0x1c(%eax,%ebx)
0x00416e67:	movb 0x445a20(%eax), %cl
0x00416e6d:	incl %eax
0x00416e6e:	jmp 0x00416e59
0x00416e70:	xorl %eax, %eax
0x00416e72:	movl -28(%ebp), %eax
0x00416e75:	cmpl %eax, $0x100<UINT32>
0x00416e7a:	jnl 0x00416e8c
0x00416e7c:	movb %cl, 0x11d(%eax,%ebx)
0x00416e83:	movb 0x445b28(%eax), %cl
0x00416e89:	incl %eax
0x00416e8a:	jmp 0x00416e72
0x00416e8c:	pushl 0x445c28
0x00416e92:	call InterlockedDecrement@KERNEL32.dll
0x00416e98:	testl %eax, %eax
0x00416e9a:	jne 0x00416eaf
0x00416eaf:	movl 0x445c28, %ebx
0x00416eb5:	pushl %ebx
0x00416eb6:	call InterlockedIncrement@KERNEL32.dll
0x00416eb8:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00416ebf:	call 0x00416ec6
0x00416ec6:	pushl $0xd<UINT8>
0x00416ec8:	call 0x0041a32b
0x00416ecd:	popl %ecx
0x00416ece:	ret

0x00416ec4:	jmp 0x00416ef6
0x00416ef6:	movl %eax, -32(%ebp)
0x00416ef9:	call 0x0041b4b5
0x00416efe:	ret

0x00416f0f:	popl %ecx
0x00416f10:	movl 0x449550, $0x1<UINT32>
0x00416f1a:	xorl %eax, %eax
0x00416f1c:	ret

0x0041f48f:	pushl $0x104<UINT32>
0x0041f494:	movl %esi, $0x448178<UINT32>
0x0041f499:	pushl %esi
0x0041f49a:	pushl %ebx
0x0041f49b:	movb 0x44827c, %bl
0x0041f4a1:	call GetModuleFileNameA@KERNEL32.dll
GetModuleFileNameA@KERNEL32.dll: API Node	
0x0041f4a7:	movl %eax, 0x449588
0x0041f4ac:	movl 0x447e38, %esi
0x0041f4b2:	cmpl %eax, %ebx
0x0041f4b4:	je 7
0x0041f4b6:	movl -4(%ebp), %eax
0x0041f4b9:	cmpb (%eax), %bl
0x0041f4bb:	jne 0x0041f4c0
0x0041f4c0:	movl %edx, -4(%ebp)
0x0041f4c3:	leal %eax, -8(%ebp)
0x0041f4c6:	pushl %eax
0x0041f4c7:	pushl %ebx
0x0041f4c8:	pushl %ebx
0x0041f4c9:	leal %edi, -12(%ebp)
0x0041f4cc:	call 0x0041f2db
0x0041f2db:	movl %edi, %edi
0x0041f2dd:	pushl %ebp
0x0041f2de:	movl %ebp, %esp
0x0041f2e0:	pushl %ecx
0x0041f2e1:	movl %ecx, 0x10(%ebp)
0x0041f2e4:	pushl %ebx
0x0041f2e5:	xorl %eax, %eax
0x0041f2e7:	pushl %esi
0x0041f2e8:	movl (%edi), %eax
0x0041f2ea:	movl %esi, %edx
0x0041f2ec:	movl %edx, 0xc(%ebp)
0x0041f2ef:	movl (%ecx), $0x1<UINT32>
0x0041f2f5:	cmpl 0x8(%ebp), %eax
0x0041f2f8:	je 0x0041f303
0x0041f303:	movl -4(%ebp), %eax
0x0041f306:	cmpb (%esi), $0x22<UINT8>
0x0041f309:	jne 0x0041f31b
0x0041f30b:	xorl %eax, %eax
0x0041f30d:	cmpl -4(%ebp), %eax
0x0041f310:	movb %bl, $0x22<UINT8>
0x0041f312:	sete %al
0x0041f315:	incl %esi
0x0041f316:	movl -4(%ebp), %eax
0x0041f319:	jmp 0x0041f357
0x0041f357:	cmpl -4(%ebp), $0x0<UINT8>
0x0041f35b:	jne 0x0041f306
0x0041f31b:	incl (%edi)
0x0041f31d:	testl %edx, %edx
0x0041f31f:	je 0x0041f329
0x0041f329:	movb %bl, (%esi)
0x0041f32b:	movzbl %eax, %bl
0x0041f32e:	pushl %eax
0x0041f32f:	incl %esi
0x0041f330:	call 0x00432ce4
0x00432ce4:	movl %edi, %edi
0x00432ce6:	pushl %ebp
0x00432ce7:	movl %ebp, %esp
0x00432ce9:	pushl $0x4<UINT8>
0x00432ceb:	pushl $0x0<UINT8>
0x00432ced:	pushl 0x8(%ebp)
0x00432cf0:	pushl $0x0<UINT8>
0x00432cf2:	call 0x00432ad8
0x00432ad8:	movl %edi, %edi
0x00432ada:	pushl %ebp
0x00432adb:	movl %ebp, %esp
0x00432add:	subl %esp, $0x10<UINT8>
0x00432ae0:	pushl 0x8(%ebp)
0x00432ae3:	leal %ecx, -16(%ebp)
0x00432ae6:	call 0x00411837
0x00432aeb:	movzbl %eax, 0xc(%ebp)
0x00432aef:	movl %ecx, -12(%ebp)
0x00432af2:	movb %dl, 0x14(%ebp)
0x00432af5:	testb 0x1d(%ecx,%eax), %dl
0x00432af9:	jne 30
0x00432afb:	cmpl 0x10(%ebp), $0x0<UINT8>
0x00432aff:	je 0x00432b13
0x00432b13:	xorl %eax, %eax
0x00432b15:	testl %eax, %eax
0x00432b17:	je 0x00432b1c
0x00432b1c:	cmpb -4(%ebp), $0x0<UINT8>
0x00432b20:	je 7
0x00432b22:	movl %ecx, -8(%ebp)
0x00432b25:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00432b29:	leave
0x00432b2a:	ret

0x00432cf7:	addl %esp, $0x10<UINT8>
0x00432cfa:	popl %ebp
0x00432cfb:	ret

0x0041f335:	popl %ecx
0x0041f336:	testl %eax, %eax
0x0041f338:	je 0x0041f34d
0x0041f34d:	movl %edx, 0xc(%ebp)
0x0041f350:	movl %ecx, 0x10(%ebp)
0x0041f353:	testb %bl, %bl
0x0041f355:	je 0x0041f389
0x0041f35d:	cmpb %bl, $0x20<UINT8>
0x0041f360:	je 5
0x0041f362:	cmpb %bl, $0x9<UINT8>
0x0041f365:	jne 0x0041f306
0x0041f389:	decl %esi
0x0041f38a:	jmp 0x0041f36f
0x0041f36f:	andl -4(%ebp), $0x0<UINT8>
0x0041f373:	cmpb (%esi), $0x0<UINT8>
0x0041f376:	je 0x0041f465
0x0041f465:	movl %eax, 0x8(%ebp)
0x0041f468:	popl %esi
0x0041f469:	popl %ebx
0x0041f46a:	testl %eax, %eax
0x0041f46c:	je 0x0041f471
0x0041f471:	incl (%ecx)
0x0041f473:	leave
0x0041f474:	ret

0x0041f4d1:	movl %eax, -8(%ebp)
0x0041f4d4:	addl %esp, $0xc<UINT8>
0x0041f4d7:	cmpl %eax, $0x3fffffff<UINT32>
0x0041f4dc:	jae 74
0x0041f4de:	movl %ecx, -12(%ebp)
0x0041f4e1:	cmpl %ecx, $0xffffffff<UINT8>
0x0041f4e4:	jae 66
0x0041f4e6:	movl %edi, %eax
0x0041f4e8:	shll %edi, $0x2<UINT8>
0x0041f4eb:	leal %eax, (%edi,%ecx)
0x0041f4ee:	cmpl %eax, %ecx
0x0041f4f0:	jb 54
0x0041f4f2:	pushl %eax
0x0041f4f3:	call 0x0041d9b1
0x0041f4f8:	movl %esi, %eax
0x0041f4fa:	popl %ecx
0x0041f4fb:	cmpl %esi, %ebx
0x0041f4fd:	je 41
0x0041f4ff:	movl %edx, -4(%ebp)
0x0041f502:	leal %eax, -8(%ebp)
0x0041f505:	pushl %eax
0x0041f506:	addl %edi, %esi
0x0041f508:	pushl %edi
0x0041f509:	pushl %esi
0x0041f50a:	leal %edi, -12(%ebp)
0x0041f50d:	call 0x0041f2db
0x0041f2fa:	movl %ebx, 0x8(%ebp)
0x0041f2fd:	addl 0x8(%ebp), $0x4<UINT8>
0x0041f301:	movl (%ebx), %edx
0x0041f321:	movb %al, (%esi)
0x0041f323:	movb (%edx), %al
0x0041f325:	incl %edx
0x0041f326:	movl 0xc(%ebp), %edx
0x0041f46e:	andl (%eax), $0x0<UINT8>
0x0041f512:	movl %eax, -8(%ebp)
0x0041f515:	addl %esp, $0xc<UINT8>
0x0041f518:	decl %eax
0x0041f519:	movl 0x447e1c, %eax
0x0041f51e:	movl 0x447e20, %esi
0x0041f524:	xorl %eax, %eax
0x0041f526:	jmp 0x0041f52b
0x0041f52b:	popl %edi
0x0041f52c:	popl %esi
0x0041f52d:	popl %ebx
0x0041f52e:	leave
0x0041f52f:	ret

0x0041491e:	testl %eax, %eax
0x00414920:	jnl 0x0041492a
0x0041492a:	call 0x0041f1ee
0x0041f1ee:	cmpl 0x449550, $0x0<UINT8>
0x0041f1f5:	jne 0x0041f1fc
0x0041f1fc:	pushl %esi
0x0041f1fd:	movl %esi, 0x447924
0x0041f203:	pushl %edi
0x0041f204:	xorl %edi, %edi
0x0041f206:	testl %esi, %esi
0x0041f208:	jne 0x0041f222
0x0041f222:	movb %al, (%esi)
0x0041f224:	testb %al, %al
0x0041f226:	jne 0x0041f212
0x0041f212:	cmpb %al, $0x3d<UINT8>
0x0041f214:	je 0x0041f217
0x0041f217:	pushl %esi
0x0041f218:	call 0x004149f0
0x004149f0:	movl %ecx, 0x4(%esp)
0x004149f4:	testl %ecx, $0x3<UINT32>
0x004149fa:	je 0x00414a20
0x00414a20:	movl %eax, (%ecx)
0x00414a22:	movl %edx, $0x7efefeff<UINT32>
0x00414a27:	addl %edx, %eax
0x00414a29:	xorl %eax, $0xffffffff<UINT8>
0x00414a2c:	xorl %eax, %edx
0x00414a2e:	addl %ecx, $0x4<UINT8>
0x00414a31:	testl %eax, $0x81010100<UINT32>
0x00414a36:	je 0x00414a20
0x00414a38:	movl %eax, -4(%ecx)
0x00414a3b:	testb %al, %al
0x00414a3d:	je 50
0x00414a3f:	testb %ah, %ah
0x00414a41:	je 36
0x00414a43:	testl %eax, $0xff0000<UINT32>
0x00414a48:	je 19
0x00414a4a:	testl %eax, $0xff000000<UINT32>
0x00414a4f:	je 0x00414a53
0x00414a53:	leal %eax, -1(%ecx)
0x00414a56:	movl %ecx, 0x4(%esp)
0x00414a5a:	subl %eax, %ecx
0x00414a5c:	ret

0x0041f21d:	popl %ecx
0x0041f21e:	leal %esi, 0x1(%esi,%eax)
0x0041f228:	pushl $0x4<UINT8>
0x0041f22a:	incl %edi
0x0041f22b:	pushl %edi
0x0041f22c:	call 0x0041d9f6
0x0041f231:	movl %edi, %eax
0x0041f233:	popl %ecx
0x0041f234:	popl %ecx
0x0041f235:	movl 0x447e28, %edi
0x0041f23b:	testl %edi, %edi
0x0041f23d:	je -53
0x0041f23f:	movl %esi, 0x447924
0x0041f245:	pushl %ebx
0x0041f246:	jmp 0x0041f28a
0x0041f28a:	cmpb (%esi), $0x0<UINT8>
0x0041f28d:	jne 0x0041f248
0x0041f248:	pushl %esi
0x0041f249:	call 0x004149f0
0x0041f24e:	movl %ebx, %eax
0x0041f250:	incl %ebx
0x0041f251:	cmpb (%esi), $0x3d<UINT8>
0x0041f254:	popl %ecx
0x0041f255:	je 0x0041f288
0x0041f288:	addl %esi, %ebx
0x0041f28f:	pushl 0x447924
0x0041f295:	call 0x004128c5
0x004128c5:	pushl $0xc<UINT8>
0x004128c7:	pushl $0x442628<UINT32>
0x004128cc:	call 0x0041b470
0x004128d1:	movl %esi, 0x8(%ebp)
0x004128d4:	testl %esi, %esi
0x004128d6:	je 117
0x004128d8:	cmpl 0x449558, $0x3<UINT8>
0x004128df:	jne 0x00412924
0x00412924:	pushl %esi
0x00412925:	pushl $0x0<UINT8>
0x00412927:	pushl 0x447e14
0x0041292d:	call HeapFree@KERNEL32.dll
HeapFree@KERNEL32.dll: API Node	
0x00412933:	testl %eax, %eax
0x00412935:	jne 0x0041294d
0x0041294d:	call 0x0041b4b5
0x00412952:	ret

0x0041f29a:	andl 0x447924, $0x0<UINT8>
0x0041f2a1:	andl (%edi), $0x0<UINT8>
0x0041f2a4:	movl 0x449544, $0x1<UINT32>
0x0041f2ae:	xorl %eax, %eax
0x0041f2b0:	popl %ecx
0x0041f2b1:	popl %ebx
0x0041f2b2:	popl %edi
0x0041f2b3:	popl %esi
0x0041f2b4:	ret

0x0041492f:	testl %eax, %eax
0x00414931:	jnl 0x0041493b
0x0041493b:	pushl %ebx
0x0041493c:	call 0x0041b6de
0x0041b6de:	movl %edi, %edi
0x0041b6e0:	pushl %ebp
0x0041b6e1:	movl %ebp, %esp
0x0041b6e3:	cmpl 0x43f3f0, $0x0<UINT8>
0x0041b6ea:	je 25
0x0041b6ec:	pushl $0x43f3f0<UINT32>
0x0041b6f1:	call 0x0041dc20
0x0041dc20:	movl %edi, %edi
0x0041dc22:	pushl %ebp
0x0041dc23:	movl %ebp, %esp
0x0041dc25:	pushl $0xfffffffe<UINT8>
0x0041dc27:	pushl $0x442bc8<UINT32>
0x0041dc2c:	pushl $0x413b50<UINT32>
0x0041dc31:	movl %eax, %fs:0
0x0041dc37:	pushl %eax
0x0041dc38:	subl %esp, $0x8<UINT8>
0x0041dc3b:	pushl %ebx
0x0041dc3c:	pushl %esi
0x0041dc3d:	pushl %edi
0x0041dc3e:	movl %eax, 0x445654
0x0041dc43:	xorl -8(%ebp), %eax
0x0041dc46:	xorl %eax, %ebp
0x0041dc48:	pushl %eax
0x0041dc49:	leal %eax, -16(%ebp)
0x0041dc4c:	movl %fs:0, %eax
0x0041dc52:	movl -24(%ebp), %esp
0x0041dc55:	movl -4(%ebp), $0x0<UINT32>
0x0041dc5c:	pushl $0x400000<UINT32>
0x0041dc61:	call 0x0041db90
0x0041db90:	movl %edi, %edi
0x0041db92:	pushl %ebp
0x0041db93:	movl %ebp, %esp
0x0041db95:	movl %ecx, 0x8(%ebp)
0x0041db98:	movl %eax, $0x5a4d<UINT32>
0x0041db9d:	cmpw (%ecx), %ax
0x0041dba0:	je 0x0041dba6
0x0041dba6:	movl %eax, 0x3c(%ecx)
0x0041dba9:	addl %eax, %ecx
0x0041dbab:	cmpl (%eax), $0x4550<UINT32>
0x0041dbb1:	jne -17
0x0041dbb3:	xorl %edx, %edx
0x0041dbb5:	movl %ecx, $0x10b<UINT32>
0x0041dbba:	cmpw 0x18(%eax), %cx
0x0041dbbe:	sete %dl
0x0041dbc1:	movl %eax, %edx
0x0041dbc3:	popl %ebp
0x0041dbc4:	ret

0x0041dc66:	addl %esp, $0x4<UINT8>
0x0041dc69:	testl %eax, %eax
0x0041dc6b:	je 85
0x0041dc6d:	movl %eax, 0x8(%ebp)
0x0041dc70:	subl %eax, $0x400000<UINT32>
0x0041dc75:	pushl %eax
0x0041dc76:	pushl $0x400000<UINT32>
0x0041dc7b:	call 0x0041dbd0
0x0041dbd0:	movl %edi, %edi
0x0041dbd2:	pushl %ebp
0x0041dbd3:	movl %ebp, %esp
0x0041dbd5:	movl %eax, 0x8(%ebp)
0x0041dbd8:	movl %ecx, 0x3c(%eax)
0x0041dbdb:	addl %ecx, %eax
0x0041dbdd:	movzwl %eax, 0x14(%ecx)
0x0041dbe1:	pushl %ebx
0x0041dbe2:	pushl %esi
0x0041dbe3:	movzwl %esi, 0x6(%ecx)
0x0041dbe7:	xorl %edx, %edx
0x0041dbe9:	pushl %edi
0x0041dbea:	leal %eax, 0x18(%eax,%ecx)
0x0041dbee:	testl %esi, %esi
0x0041dbf0:	jbe 27
0x0041dbf2:	movl %edi, 0xc(%ebp)
0x0041dbf5:	movl %ecx, 0xc(%eax)
0x0041dbf8:	cmpl %edi, %ecx
0x0041dbfa:	jb 9
0x0041dbfc:	movl %ebx, 0x8(%eax)
0x0041dbff:	addl %ebx, %ecx
0x0041dc01:	cmpl %edi, %ebx
0x0041dc03:	jb 0x0041dc0f
0x0041dc0f:	popl %edi
0x0041dc10:	popl %esi
0x0041dc11:	popl %ebx
0x0041dc12:	popl %ebp
0x0041dc13:	ret

0x0041dc80:	addl %esp, $0x8<UINT8>
0x0041dc83:	testl %eax, %eax
0x0041dc85:	je 59
0x0041dc87:	movl %eax, 0x24(%eax)
0x0041dc8a:	shrl %eax, $0x1f<UINT8>
0x0041dc8d:	notl %eax
0x0041dc8f:	andl %eax, $0x1<UINT8>
0x0041dc92:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0041dc99:	movl %ecx, -16(%ebp)
0x0041dc9c:	movl %fs:0, %ecx
0x0041dca3:	popl %ecx
0x0041dca4:	popl %edi
0x0041dca5:	popl %esi
0x0041dca6:	popl %ebx
0x0041dca7:	movl %esp, %ebp
0x0041dca9:	popl %ebp
0x0041dcaa:	ret

0x0041b6f6:	popl %ecx
0x0041b6f7:	testl %eax, %eax
0x0041b6f9:	je 0x0041b705
0x0041b705:	call 0x0041d8c3
0x0041d8c3:	movl %edi, %edi
0x0041d8c5:	pushl %esi
0x0041d8c6:	pushl %edi
0x0041d8c7:	xorl %edi, %edi
0x0041d8c9:	leal %esi, 0x446038(%edi)
0x0041d8cf:	pushl (%esi)
0x0041d8d1:	call 0x004181e0
0x00418202:	pushl %eax
0x00418203:	pushl 0x445e1c
0x00418209:	call TlsGetValue@KERNEL32.dll
0x0041820b:	call FlsGetValue@KERNEL32.DLL
0x0041820d:	testl %eax, %eax
0x0041820f:	je 8
0x00418211:	movl %eax, 0x1f8(%eax)
0x00418217:	jmp 0x00418240
0x0041d8d6:	addl %edi, $0x4<UINT8>
0x0041d8d9:	popl %ecx
0x0041d8da:	movl (%esi), %eax
0x0041d8dc:	cmpl %edi, $0x28<UINT8>
0x0041d8df:	jb 0x0041d8c9
0x0041d8e1:	popl %edi
0x0041d8e2:	popl %esi
0x0041d8e3:	ret

0x0041b70a:	pushl $0x43b4c4<UINT32>
0x0041b70f:	pushl $0x43b4ac<UINT32>
0x0041b714:	call 0x0041b642
0x0041b642:	movl %edi, %edi
0x0041b644:	pushl %ebp
0x0041b645:	movl %ebp, %esp
0x0041b647:	pushl %esi
0x0041b648:	movl %esi, 0x8(%ebp)
0x0041b64b:	xorl %eax, %eax
0x0041b64d:	jmp 0x0041b65e
0x0041b65e:	cmpl %esi, 0xc(%ebp)
0x0041b661:	jb 0x0041b64f
0x0041b64f:	testl %eax, %eax
0x0041b651:	jne 16
0x0041b653:	movl %ecx, (%esi)
0x0041b655:	testl %ecx, %ecx
0x0041b657:	je 0x0041b65b
0x0041b65b:	addl %esi, $0x4<UINT8>
0x0041b659:	call 0x0041f181
0x00412ff1:	movl %edi, %edi
0x00412ff3:	pushl %esi
0x00412ff4:	pushl $0x4<UINT8>
0x00412ff6:	pushl $0x20<UINT8>
0x00412ff8:	call 0x0041d9f6
0x00412ffd:	movl %esi, %eax
0x00412fff:	pushl %esi
0x00413000:	call 0x004181e0
0x00413005:	addl %esp, $0xc<UINT8>
0x00413008:	movl 0x44954c, %eax
0x0041300d:	movl 0x449548, %eax
0x00413012:	testl %esi, %esi
0x00413014:	jne 0x0041301b
0x0041301b:	andl (%esi), $0x0<UINT8>
0x0041301e:	xorl %eax, %eax
0x00413020:	popl %esi
0x00413021:	ret

0x0041a27c:	call 0x0041a21a
0x0041a21a:	movl %edi, %edi
0x0041a21c:	pushl %ebp
0x0041a21d:	movl %ebp, %esp
0x0041a21f:	subl %esp, $0x18<UINT8>
0x0041a222:	xorl %eax, %eax
0x0041a224:	pushl %ebx
0x0041a225:	movl -4(%ebp), %eax
0x0041a228:	movl -12(%ebp), %eax
0x0041a22b:	movl -8(%ebp), %eax
0x0041a22e:	pushl %ebx
0x0041a22f:	pushfl
0x0041a230:	popl %eax
0x0041a231:	movl %ecx, %eax
0x0041a233:	xorl %eax, $0x200000<UINT32>
0x0041a238:	pushl %eax
0x0041a239:	popfl
0x0041a23a:	pushfl
0x0041a23b:	popl %edx
0x0041a23c:	subl %edx, %ecx
0x0041a23e:	je 0x0041a25f
0x0041a25f:	popl %ebx
0x0041a260:	testl -4(%ebp), $0x4000000<UINT32>
0x0041a267:	je 0x0041a277
0x0041a277:	xorl %eax, %eax
0x0041a279:	popl %ebx
0x0041a27a:	leave
0x0041a27b:	ret

0x0041a281:	movl 0x449578, %eax
0x0041a286:	xorl %eax, %eax
0x0041a288:	ret

0x0041e399:	movl %eax, 0x449540
0x0041e39e:	pushl %esi
0x0041e39f:	pushl $0x14<UINT8>
0x0041e3a1:	popl %esi
0x0041e3a2:	testl %eax, %eax
0x0041e3a4:	jne 7
0x0041e3a6:	movl %eax, $0x200<UINT32>
0x0041e3ab:	jmp 0x0041e3b3
0x0041e3b3:	movl 0x449540, %eax
0x0041e3b8:	pushl $0x4<UINT8>
0x0041e3ba:	pushl %eax
0x0041e3bb:	call 0x0041d9f6
0x0041e3c0:	popl %ecx
0x0041e3c1:	popl %ecx
0x0041e3c2:	movl 0x448520, %eax
0x0041e3c7:	testl %eax, %eax
0x0041e3c9:	jne 0x0041e3e9
0x0041e3e9:	xorl %edx, %edx
0x0041e3eb:	movl %ecx, $0x446070<UINT32>
0x0041e3f0:	jmp 0x0041e3f7
0x0041e3f7:	movl (%edx,%eax), %ecx
0x0041e3fa:	addl %ecx, $0x20<UINT8>
0x0041e3fd:	addl %edx, $0x4<UINT8>
0x0041e400:	cmpl %ecx, $0x4462f0<UINT32>
0x0041e406:	jl 0x0041e3f2
0x0041e3f2:	movl %eax, 0x448520
0x0041e408:	pushl $0xfffffffe<UINT8>
0x0041e40a:	popl %esi
0x0041e40b:	xorl %edx, %edx
0x0041e40d:	movl %ecx, $0x446080<UINT32>
0x0041e412:	pushl %edi
0x0041e413:	movl %eax, %edx
0x0041e415:	sarl %eax, $0x5<UINT8>
0x0041e418:	movl %eax, 0x448420(,%eax,4)
0x0041e41f:	movl %edi, %edx
0x0041e421:	andl %edi, $0x1f<UINT8>
0x0041e424:	shll %edi, $0x6<UINT8>
0x0041e427:	movl %eax, (%edi,%eax)
0x0041e42a:	cmpl %eax, $0xffffffff<UINT8>
0x0041e42d:	je 8
0x0041e42f:	cmpl %eax, %esi
0x0041e431:	je 4
0x0041e433:	testl %eax, %eax
0x0041e435:	jne 0x0041e439
0x0041e439:	addl %ecx, $0x20<UINT8>
0x0041e43c:	incl %edx
0x0041e43d:	cmpl %ecx, $0x4460e0<UINT32>
0x0041e443:	jl 0x0041e413
0x0041e445:	popl %edi
0x0041e446:	xorl %eax, %eax
0x0041e448:	popl %esi
0x0041e449:	ret

0x0041f181:	pushl $0x41f13f<UINT32>
0x0041f186:	call SetUnhandledExceptionFilter@KERNEL32.dll
SetUnhandledExceptionFilter@KERNEL32.dll: API Node	
0x0041f18c:	xorl %eax, %eax
0x0041f18e:	ret

0x0041b663:	popl %esi
0x0041b664:	popl %ebp
0x0041b665:	ret

0x0041b719:	popl %ecx
0x0041b71a:	popl %ecx
0x0041b71b:	testl %eax, %eax
0x0041b71d:	jne 66
0x0041b71f:	pushl $0x41f68d<UINT32>
0x0041b724:	call 0x0041305e
0x0041305e:	movl %edi, %edi
0x00413060:	pushl %ebp
0x00413061:	movl %ebp, %esp
0x00413063:	pushl 0x8(%ebp)
0x00413066:	call 0x00413022
0x00413022:	pushl $0xc<UINT8>
0x00413024:	pushl $0x442648<UINT32>
0x00413029:	call 0x0041b470
0x0041302e:	call 0x0041b613
0x0041b613:	pushl $0x8<UINT8>
0x0041b615:	call 0x0041a41d
0x0041b61a:	popl %ecx
0x0041b61b:	ret

0x00413033:	andl -4(%ebp), $0x0<UINT8>
0x00413037:	pushl 0x8(%ebp)
0x0041303a:	call 0x00412f37
0x00412f37:	movl %edi, %edi
0x00412f39:	pushl %ebp
0x00412f3a:	movl %ebp, %esp
0x00412f3c:	pushl %ecx
0x00412f3d:	pushl %ebx
0x00412f3e:	pushl %esi
0x00412f3f:	pushl %edi
0x00412f40:	pushl 0x44954c
0x00412f46:	call 0x0041825b
0x0041828c:	movl %eax, 0x1fc(%eax)
0x00418292:	jmp 0x004182bb
0x00412f4b:	pushl 0x449548
0x00412f51:	movl %edi, %eax
0x00412f53:	movl -4(%ebp), %edi
0x00412f56:	call 0x0041825b
0x00412f5b:	movl %esi, %eax
0x00412f5d:	popl %ecx
0x00412f5e:	popl %ecx
0x00412f5f:	cmpl %esi, %edi
0x00412f61:	jb 131
0x00412f67:	movl %ebx, %esi
0x00412f69:	subl %ebx, %edi
0x00412f6b:	leal %eax, 0x4(%ebx)
0x00412f6e:	cmpl %eax, $0x4<UINT8>
0x00412f71:	jb 119
0x00412f73:	pushl %edi
0x00412f74:	call 0x0041dae2
0x0041dae2:	pushl $0x10<UINT8>
0x0041dae4:	pushl $0x442ba8<UINT32>
0x0041dae9:	call 0x0041b470
0x0041daee:	xorl %eax, %eax
0x0041daf0:	movl %ebx, 0x8(%ebp)
0x0041daf3:	xorl %edi, %edi
0x0041daf5:	cmpl %ebx, %edi
0x0041daf7:	setne %al
0x0041dafa:	cmpl %eax, %edi
0x0041dafc:	jne 0x0041db1b
0x0041db1b:	cmpl 0x449558, $0x3<UINT8>
0x0041db22:	jne 0x0041db5c
0x0041db5c:	pushl %ebx
0x0041db5d:	pushl %edi
0x0041db5e:	pushl 0x447e14
0x0041db64:	call HeapSize@KERNEL32.dll
HeapSize@KERNEL32.dll: API Node	
0x0041db6a:	movl %esi, %eax
0x0041db6c:	movl %eax, %esi
0x0041db6e:	call 0x0041b4b5
0x0041db73:	ret

0x00412f79:	movl %edi, %eax
0x00412f7b:	leal %eax, 0x4(%ebx)
0x00412f7e:	popl %ecx
0x00412f7f:	cmpl %edi, %eax
0x00412f81:	jae 0x00412fcb
0x00412fcb:	pushl 0x8(%ebp)
0x00412fce:	call 0x004181e0
0x00412fd3:	movl (%esi), %eax
0x00412fd5:	addl %esi, $0x4<UINT8>
0x00412fd8:	pushl %esi
0x00412fd9:	call 0x004181e0
0x00412fde:	popl %ecx
0x00412fdf:	movl 0x449548, %eax
0x00412fe4:	movl %eax, 0x8(%ebp)
0x00412fe7:	popl %ecx
0x00412fe8:	jmp 0x00412fec
0x00412fec:	popl %edi
0x00412fed:	popl %esi
0x00412fee:	popl %ebx
0x00412fef:	leave
0x00412ff0:	ret

0x0041303f:	popl %ecx
0x00413040:	movl -28(%ebp), %eax
0x00413043:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0041304a:	call 0x00413058
0x00413058:	call 0x0041b61c
0x0041b61c:	pushl $0x8<UINT8>
0x0041b61e:	call 0x0041a32b
0x0041b623:	popl %ecx
0x0041b624:	ret

0x0041305d:	ret

0x0041304f:	movl %eax, -28(%ebp)
0x00413052:	call 0x0041b4b5
0x00413057:	ret

0x0041306b:	negl %eax
0x0041306d:	sbbl %eax, %eax
0x0041306f:	negl %eax
0x00413071:	popl %ecx
0x00413072:	decl %eax
0x00413073:	popl %ebp
0x00413074:	ret

0x0041b729:	movl %eax, $0x43b490<UINT32>
0x0041b72e:	movl (%esp), $0x43b4a8<UINT32>
0x0041b735:	call 0x0041b625
0x0041b625:	movl %edi, %edi
0x0041b627:	pushl %ebp
0x0041b628:	movl %ebp, %esp
0x0041b62a:	pushl %esi
0x0041b62b:	movl %esi, %eax
0x0041b62d:	jmp 0x0041b63a
0x0041b63a:	cmpl %esi, 0x8(%ebp)
0x0041b63d:	jb 0x0041b62f
0x0041b62f:	movl %eax, (%esi)
0x0041b631:	testl %eax, %eax
0x0041b633:	je 0x0041b637
0x0041b637:	addl %esi, $0x4<UINT8>
0x0041b635:	call 0x0043ae40
0x0043adb0:	pushl $0x4469c0<UINT32>
0x0043adb5:	call GetSystemTimeAsFileTime@KERNEL32.dll
0x0043adbb:	pushl $0x4469c8<UINT32>
0x0043adc0:	call QueryPerformanceCounter@KERNEL32.dll
0x0043adc6:	pushl $0x4469d0<UINT32>
0x0043adcb:	call QueryPerformanceFrequency@KERNEL32.dll
QueryPerformanceFrequency@KERNEL32.dll: API Node	
0x0043add1:	ret

0x0043ade0:	movl %ecx, $0x4469dc<UINT32>
0x0043ade5:	call 0x00403330
0x00403330:	pushl $0xffffffff<UINT8>
0x00403332:	pushl $0x43a908<UINT32>
0x00403337:	movl %eax, %fs:0
0x0040333d:	pushl %eax
0x0040333e:	pushl %ecx
0x0040333f:	pushl %esi
0x00403340:	movl %eax, 0x445654
0x00403345:	xorl %eax, %esp
0x00403347:	pushl %eax
0x00403348:	leal %eax, 0xc(%esp)
0x0040334c:	movl %fs:0, %eax
0x00403352:	movl %esi, %ecx
0x00403354:	movl 0x8(%esp), %esi
0x00403358:	pushl $0x4<UINT8>
0x0040335a:	call 0x004115fa
0x004115fa:	movl %edi, %edi
0x004115fc:	pushl %ebp
0x004115fd:	movl %ebp, %esp
0x004115ff:	subl %esp, $0xc<UINT8>
0x00411602:	jmp 0x00411611
0x00411611:	pushl 0x8(%ebp)
0x00411614:	call 0x00412493
0x00411619:	popl %ecx
0x0041161a:	testl %eax, %eax
0x0041161c:	je -26
0x0041161e:	leave
0x0041161f:	ret

0x0040335f:	addl %esp, $0x4<UINT8>
0x00403362:	testl %eax, %eax
0x00403364:	je 4
0x00403366:	movl (%eax), %esi
0x00403368:	jmp 0x0040336c
0x0040336c:	movl (%esi), %eax
0x0040336e:	movl %ecx, %esi
0x00403370:	movl 0x14(%esp), $0x0<UINT32>
0x00403378:	call 0x00402460
0x00402460:	pushl $0xc<UINT8>
0x00402462:	call 0x004115fa
0x00402467:	addl %esp, $0x4<UINT8>
0x0040246a:	testl %eax, %eax
0x0040246c:	je 2
0x0040246e:	movl (%eax), %eax
0x00402470:	leal %ecx, 0x4(%eax)
0x00402473:	testl %ecx, %ecx
0x00402475:	je 2
0x00402477:	movl (%ecx), %eax
0x00402479:	ret

0x0040337d:	movl 0x14(%esi), %eax
0x00403380:	movl 0x18(%esi), $0x0<UINT32>
0x00403387:	movl %eax, %esi
0x00403389:	movl %ecx, 0xc(%esp)
0x0040338d:	movl %fs:0, %ecx
0x00403394:	popl %ecx
0x00403395:	popl %esi
0x00403396:	addl %esp, $0x10<UINT8>
0x00403399:	ret

0x0043adea:	pushl $0x43aea0<UINT32>
0x0043adef:	call 0x0041305e
0x0043adf4:	popl %ecx
0x0043adf5:	ret

0x0043ae00:	pushl $0x0<UINT8>
0x0043ae02:	pushl $0x0<UINT8>
0x0043ae04:	pushl $0x1<UINT8>
0x0043ae06:	pushl $0x0<UINT8>
0x0043ae08:	call CreateEventA@KERNEL32.dll
CreateEventA@KERNEL32.dll: API Node	
0x0043ae0e:	movl 0x447324, %eax
0x0043ae13:	movl 0x447328, $0x0<UINT32>
0x0043ae1d:	ret

0x0043ae20:	pushl $0x43ef14<UINT32>
0x0043ae25:	pushl $0x43dce0<UINT32>
0x0043ae2a:	call GetModuleHandleA@KERNEL32.dll
GetModuleHandleA@KERNEL32.dll: API Node	
0x0043ae30:	pushl %eax
0x0043ae31:	call GetProcAddress@KERNEL32.dll
0x0043ae37:	movl 0x447338, %eax
0x0043ae3c:	ret

0x0043ae40:	pushl $0x43aee0<UINT32>
0x0043ae45:	call 0x0041305e
0x0043ae4a:	popl %ecx
0x0043ae4b:	ret

0x0041b63f:	popl %esi
0x0041b640:	popl %ebp
0x0041b641:	ret

0x0041b73a:	cmpl 0x449554, $0x0<UINT8>
0x0041b741:	popl %ecx
0x0041b742:	je 0x0041b75f
0x0041b75f:	xorl %eax, %eax
0x0041b761:	popl %ebp
0x0041b762:	ret

0x00414941:	popl %ecx
0x00414942:	cmpl %eax, %esi
0x00414944:	je 0x0041494d
0x0041494d:	call 0x0041f18f
0x0041f18f:	movl %edi, %edi
0x0041f191:	pushl %esi
0x0041f192:	pushl %edi
0x0041f193:	xorl %edi, %edi
0x0041f195:	cmpl 0x449550, %edi
0x0041f19b:	jne 0x0041f1a2
0x0041f1a2:	movl %esi, 0x449588
0x0041f1a8:	testl %esi, %esi
0x0041f1aa:	jne 0x0041f1b1
0x0041f1b1:	movb %al, (%esi)
0x0041f1b3:	cmpb %al, $0x20<UINT8>
0x0041f1b5:	ja 0x0041f1bf
0x0041f1bf:	cmpb %al, $0x22<UINT8>
0x0041f1c1:	jne 0x0041f1cc
0x0041f1c3:	xorl %ecx, %ecx
0x0041f1c5:	testl %edi, %edi
0x0041f1c7:	sete %cl
0x0041f1ca:	movl %edi, %ecx
0x0041f1cc:	movzbl %eax, %al
0x0041f1cf:	pushl %eax
0x0041f1d0:	call 0x00432ce4
0x0041f1d5:	popl %ecx
0x0041f1d6:	testl %eax, %eax
0x0041f1d8:	je 0x0041f1db
0x0041f1db:	incl %esi
0x0041f1dc:	jmp 0x0041f1b1
0x0041f1b7:	testb %al, %al
0x0041f1b9:	je 0x0041f1e9
0x0041f1e9:	popl %edi
0x0041f1ea:	movl %eax, %esi
0x0041f1ec:	popl %esi
0x0041f1ed:	ret

0x00414952:	testb -60(%ebp), %bl
0x00414955:	je 0x0041495d
0x0041495d:	pushl $0xa<UINT8>
0x0041495f:	popl %ecx
0x00414960:	pushl %ecx
0x00414961:	pushl %eax
0x00414962:	pushl %esi
0x00414963:	pushl $0x400000<UINT32>
0x00414968:	call 0x0040f230
0x0040f230:	subl %esp, $0x1b4<UINT32>
0x0040f236:	movl %eax, 0x445654
0x0040f23b:	xorl %eax, %esp
0x0040f23d:	movl 0x1b0(%esp), %eax
0x0040f244:	pushl %edi
0x0040f245:	movl %edi, 0x1bc(%esp)
0x0040f24c:	leal %eax, 0x4(%esp)
0x0040f250:	pushl %eax
0x0040f251:	movl 0x8(%esp), $0x0<UINT32>
0x0040f259:	call GetCommandLineW@KERNEL32.dll
GetCommandLineW@KERNEL32.dll: API Node	
0x0040f25f:	pushl %eax
0x0040f260:	call CommandLineToArgvW@SHELL32.dll
CommandLineToArgvW@SHELL32.dll: API Node	
0x0040f266:	pushl %eax
0x0040f267:	leal %ecx, 0x8(%esp)
0x0040f26b:	pushl %ecx
0x0040f26c:	pushl $0x43e940<UINT32>
0x0040f271:	call 0x004050c0
0x004050c0:	pushl %ebx
0x004050c1:	movl %ebx, 0xc(%esp)
0x004050c5:	pushl %ebp
0x004050c6:	pushl %esi
0x004050c7:	xorl %ebp, %ebp
0x004050c9:	pushl %edi
0x004050ca:	testl %ebx, %ebx
0x004050cc:	je 8
0x004050ce:	movl %edi, 0x1c(%esp)
0x004050d2:	testl %edi, %edi
0x004050d4:	jne 0x00405104
0x00405104:	xorl %esi, %esi
0x00405106:	cmpl (%ebx), %ebp
0x00405108:	jle 0x00405161
0x00405161:	movl %edx, 0x14(%esp)
0x00405165:	pushl %ebp
0x00405166:	pushl %edx
0x00405167:	call 0x00404d30
0x00404d30:	subl %esp, $0x110<UINT32>
0x00404d36:	movl %eax, 0x445654
0x00404d3b:	xorl %eax, %esp
0x00404d3d:	movl 0x10c(%esp), %eax
0x00404d44:	pushl %ebp
0x00404d45:	movl %ebp, 0x118(%esp)
0x00404d4c:	pushl %ebp
0x00404d4d:	leal %eax, 0x10(%esp)
0x00404d51:	pushl $0x43dc94<UINT32>
0x00404d56:	pushl %eax
0x00404d57:	movl 0x10(%esp), $0x0<UINT32>
0x00404d5f:	call 0x00412953
0x00412953:	movl %edi, %edi
0x00412955:	pushl %ebp
0x00412956:	movl %ebp, %esp
0x00412958:	subl %esp, $0x20<UINT8>
0x0041295b:	pushl %ebx
0x0041295c:	xorl %ebx, %ebx
0x0041295e:	cmpl 0xc(%ebp), %ebx
0x00412961:	jne 0x00412980
0x00412980:	movl %eax, 0x8(%ebp)
0x00412983:	cmpl %eax, %ebx
0x00412985:	je -36
0x00412987:	pushl %esi
0x00412988:	movl -24(%ebp), %eax
0x0041298b:	movl -32(%ebp), %eax
0x0041298e:	leal %eax, 0x10(%ebp)
0x00412991:	pushl %eax
0x00412992:	pushl %ebx
0x00412993:	pushl 0xc(%ebp)
0x00412996:	leal %eax, -32(%ebp)
0x00412999:	pushl %eax
0x0041299a:	movl -28(%ebp), $0x7fffffff<UINT32>
0x004129a1:	movl -20(%ebp), $0x42<UINT32>
0x004129a8:	call 0x0041bd54
0x0041bd54:	movl %edi, %edi
0x0041bd56:	pushl %ebp
0x0041bd57:	movl %ebp, %esp
0x0041bd59:	subl %esp, $0x278<UINT32>
0x0041bd5f:	movl %eax, 0x445654
0x0041bd64:	xorl %eax, %ebp
0x0041bd66:	movl -4(%ebp), %eax
0x0041bd69:	pushl %ebx
0x0041bd6a:	movl %ebx, 0xc(%ebp)
0x0041bd6d:	pushl %esi
0x0041bd6e:	movl %esi, 0x8(%ebp)
0x0041bd71:	xorl %eax, %eax
0x0041bd73:	pushl %edi
0x0041bd74:	movl %edi, 0x14(%ebp)
0x0041bd77:	pushl 0x10(%ebp)
0x0041bd7a:	leal %ecx, -604(%ebp)
0x0041bd80:	movl -588(%ebp), %esi
0x0041bd86:	movl -548(%ebp), %edi
0x0041bd8c:	movl -584(%ebp), %eax
0x0041bd92:	movl -528(%ebp), %eax
0x0041bd98:	movl -564(%ebp), %eax
0x0041bd9e:	movl -536(%ebp), %eax
0x0041bda4:	movl -560(%ebp), %eax
0x0041bdaa:	movl -576(%ebp), %eax
0x0041bdb0:	movl -568(%ebp), %eax
0x0041bdb6:	call 0x00411837
0x0041bdbb:	testl %esi, %esi
0x0041bdbd:	jne 0x0041bdf4
0x0041bdf4:	testb 0xc(%esi), $0x40<UINT8>
0x0041bdf8:	jne 0x0041be58
0x0041be58:	xorl %ecx, %ecx
0x0041be5a:	cmpl %ebx, %ecx
0x0041be5c:	je -163
0x0041be62:	movb %dl, (%ebx)
0x0041be64:	movl -552(%ebp), %ecx
0x0041be6a:	movl -544(%ebp), %ecx
0x0041be70:	movl -580(%ebp), %ecx
0x0041be76:	movb -529(%ebp), %dl
0x0041be7c:	testb %dl, %dl
0x0041be7e:	je 2591
0x0041be84:	incl %ebx
0x0041be85:	cmpl -552(%ebp), $0x0<UINT8>
0x0041be8c:	movl -572(%ebp), %ebx
0x0041be92:	jl 2571
0x0041be98:	movb %al, %dl
0x0041be9a:	subb %al, $0x20<UINT8>
0x0041be9c:	cmpb %al, $0x58<UINT8>
0x0041be9e:	ja 0x0041beb1
0x0041bea0:	movsbl %eax, %dl
0x0041bea3:	movsbl %eax, 0x43fb98(%eax)
0x0041beaa:	andl %eax, $0xf<UINT8>
0x0041bead:	xorl %esi, %esi
0x0041beaf:	jmp 0x0041beb5
0x0041beb5:	movsbl %eax, 0x43fbb8(%ecx,%eax,8)
0x0041bebd:	pushl $0x7<UINT8>
0x0041bebf:	sarl %eax, $0x4<UINT8>
0x0041bec2:	popl %ecx
0x0041bec3:	movl -620(%ebp), %eax
0x0041bec9:	cmpl %eax, %ecx
0x0041becb:	ja 2477
0x0041bed1:	jmp 0x0041c131
0x0041c0d7:	leal %eax, -604(%ebp)
0x0041c0dd:	pushl %eax
0x0041c0de:	movzbl %eax, %dl
0x0041c0e1:	pushl %eax
0x0041c0e2:	movl -568(%ebp), %esi
0x0041c0e8:	call 0x00425851
0x00425851:	movl %edi, %edi
0x00425853:	pushl %ebp
0x00425854:	movl %ebp, %esp
0x00425856:	subl %esp, $0x10<UINT8>
0x00425859:	pushl 0xc(%ebp)
0x0042585c:	leal %ecx, -16(%ebp)
0x0042585f:	call 0x00411837
0x004118ad:	movl %ecx, (%eax)
0x004118af:	movl (%esi), %ecx
0x004118b1:	movl %eax, 0x4(%eax)
0x004118b4:	movl 0x4(%esi), %eax
0x00425864:	movzbl %eax, 0x8(%ebp)
0x00425868:	movl %ecx, -16(%ebp)
0x0042586b:	movl %ecx, 0xc8(%ecx)
0x00425871:	movzwl %eax, (%ecx,%eax,2)
0x00425875:	andl %eax, $0x8000<UINT32>
0x0042587a:	cmpb -4(%ebp), $0x0<UINT8>
0x0042587e:	je 0x00425887
0x00425887:	leave
0x00425888:	ret

0x0041c0ed:	popl %ecx
0x0041c0ee:	testl %eax, %eax
0x0041c0f0:	movb %al, -529(%ebp)
0x0041c0f6:	popl %ecx
0x0041c0f7:	je 0x0041c11b
0x0041c11b:	movl %ecx, -588(%ebp)
0x0041c121:	leal %esi, -552(%ebp)
0x0041c127:	call 0x0041bc9b
0x0041bc9b:	testb 0xc(%ecx), $0x40<UINT8>
0x0041bc9f:	je 6
0x0041bca1:	cmpl 0x8(%ecx), $0x0<UINT8>
0x0041bca5:	je 36
0x0041bca7:	decl 0x4(%ecx)
0x0041bcaa:	js 11
0x0041bcac:	movl %edx, (%ecx)
0x0041bcae:	movb (%edx), %al
0x0041bcb0:	incl (%ecx)
0x0041bcb2:	movzbl %eax, %al
0x0041bcb5:	jmp 0x0041bcc3
0x0041bcc3:	cmpl %eax, $0xffffffff<UINT8>
0x0041bcc6:	jne 0x0041bccb
0x0041bccb:	incl (%esi)
0x0041bccd:	ret

0x0041c12c:	jmp 0x0041c87e
0x0041c87e:	movl %ebx, -572(%ebp)
0x0041c884:	movb %al, (%ebx)
0x0041c886:	movb -529(%ebp), %al
0x0041c88c:	testb %al, %al
0x0041c88e:	je 0x0041c8a3
0x0041c890:	movl %ecx, -620(%ebp)
0x0041c896:	movl %edi, -548(%ebp)
0x0041c89c:	movb %dl, %al
0x0041c89e:	jmp 0x0041be84
0x0041beb1:	xorl %esi, %esi
0x0041beb3:	xorl %eax, %eax
0x0041bed8:	orl -536(%ebp), $0xffffffff<UINT8>
0x0041bedf:	movl -624(%ebp), %esi
0x0041bee5:	movl -576(%ebp), %esi
0x0041beeb:	movl -564(%ebp), %esi
0x0041bef1:	movl -560(%ebp), %esi
0x0041bef7:	movl -528(%ebp), %esi
0x0041befd:	movl -568(%ebp), %esi
0x0041bf03:	jmp 0x0041c87e
0x0041c131:	movsbl %eax, %dl
0x0041c134:	cmpl %eax, $0x64<UINT8>
0x0041c137:	jg 0x0041c325
0x0041c325:	cmpl %eax, $0x70<UINT8>
0x0041c328:	jg 0x0041c529
0x0041c529:	subl %eax, $0x73<UINT8>
0x0041c52c:	je 0x0041c1e8
0x0041c1e8:	movl %ecx, -536(%ebp)
0x0041c1ee:	cmpl %ecx, $0xffffffff<UINT8>
0x0041c1f1:	jne 5
0x0041c1f3:	movl %ecx, $0x7fffffff<UINT32>
0x0041c1f8:	addl %edi, $0x4<UINT8>
0x0041c1fb:	testl -528(%ebp), $0x810<UINT32>
0x0041c205:	movl -548(%ebp), %edi
0x0041c20b:	movl %edi, -4(%edi)
0x0041c20e:	movl -540(%ebp), %edi
0x0041c214:	je 0x0041c6cb
0x0041c6cb:	cmpl %edi, %esi
0x0041c6cd:	jne 0x0041c6da
0x0041c6da:	movl %eax, -540(%ebp)
0x0041c6e0:	jmp 0x0041c6e9
0x0041c6e9:	cmpl %ecx, %esi
0x0041c6eb:	jne 0x0041c6e2
0x0041c6e2:	decl %ecx
0x0041c6e3:	cmpb (%eax), $0x0<UINT8>
0x0041c6e6:	je 0x0041c6ed
0x0041c6e8:	incl %eax
0x0041c6ed:	subl %eax, -540(%ebp)
0x0041c6f3:	movl -544(%ebp), %eax
0x0041c6f9:	cmpl -576(%ebp), $0x0<UINT8>
0x0041c700:	jne 348
0x0041c706:	movl %eax, -528(%ebp)
0x0041c70c:	testb %al, $0x40<UINT8>
0x0041c70e:	je 0x0041c742
0x0041c742:	movl %ebx, -564(%ebp)
0x0041c748:	subl %ebx, -544(%ebp)
0x0041c74e:	subl %ebx, -560(%ebp)
0x0041c754:	testb -528(%ebp), $0xc<UINT8>
0x0041c75b:	jne 23
0x0041c75d:	pushl -588(%ebp)
0x0041c763:	leal %eax, -552(%ebp)
0x0041c769:	pushl %ebx
0x0041c76a:	pushl $0x20<UINT8>
0x0041c76c:	call 0x0041bcce
0x0041bcce:	movl %edi, %edi
0x0041bcd0:	pushl %ebp
0x0041bcd1:	movl %ebp, %esp
0x0041bcd3:	pushl %esi
0x0041bcd4:	movl %esi, %eax
0x0041bcd6:	jmp 0x0041bceb
0x0041bceb:	cmpl 0xc(%ebp), $0x0<UINT8>
0x0041bcef:	jg -25
0x0041bcf1:	popl %esi
0x0041bcf2:	popl %ebp
0x0041bcf3:	ret

0x0041c771:	addl %esp, $0xc<UINT8>
0x0041c774:	pushl -560(%ebp)
0x0041c77a:	movl %edi, -588(%ebp)
0x0041c780:	leal %eax, -552(%ebp)
0x0041c786:	leal %ecx, -556(%ebp)
0x0041c78c:	call 0x0041bcf4
0x0041bcf4:	movl %edi, %edi
0x0041bcf6:	pushl %ebp
0x0041bcf7:	movl %ebp, %esp
0x0041bcf9:	testb 0xc(%edi), $0x40<UINT8>
0x0041bcfd:	pushl %ebx
0x0041bcfe:	pushl %esi
0x0041bcff:	movl %esi, %eax
0x0041bd01:	movl %ebx, %ecx
0x0041bd03:	je 50
0x0041bd05:	cmpl 0x8(%edi), $0x0<UINT8>
0x0041bd09:	jne 0x0041bd37
0x0041bd37:	cmpl 0x8(%ebp), $0x0<UINT8>
0x0041bd3b:	jg 0x0041bd12
0x0041bd3d:	popl %esi
0x0041bd3e:	popl %ebx
0x0041bd3f:	popl %ebp
0x0041bd40:	ret

0x0041c791:	testb -528(%ebp), $0x8<UINT8>
0x0041c798:	popl %ecx
0x0041c799:	je 0x0041c7b6
0x0041c7b6:	cmpl -568(%ebp), $0x0<UINT8>
0x0041c7bd:	movl %eax, -544(%ebp)
0x0041c7c3:	je 0x0041c82b
0x0041c82b:	movl %ecx, -540(%ebp)
0x0041c831:	pushl %eax
0x0041c832:	leal %eax, -552(%ebp)
0x0041c838:	call 0x0041bcf4
0x0041bd12:	movb %al, (%ebx)
0x0041bd14:	decl 0x8(%ebp)
0x0041bd17:	movl %ecx, %edi
0x0041bd19:	call 0x0041bc9b
0x0041bd1e:	incl %ebx
0x0041bd1f:	cmpl (%esi), $0xffffffff<UINT8>
0x0041bd22:	jne 0x0041bd37
0x0041c83d:	popl %ecx
0x0041c83e:	cmpl -552(%ebp), $0x0<UINT8>
0x0041c845:	jl 27
0x0041c847:	testb -528(%ebp), $0x4<UINT8>
0x0041c84e:	je 0x0041c862
0x0041c862:	cmpl -580(%ebp), $0x0<UINT8>
0x0041c869:	je 0x0041c87e
0x0041c8a3:	cmpb -592(%ebp), $0x0<UINT8>
0x0041c8aa:	je 10
0x0041c8ac:	movl %eax, -596(%ebp)
0x0041c8b2:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x0041c8b6:	movl %eax, -552(%ebp)
0x0041c8bc:	movl %ecx, -4(%ebp)
0x0041c8bf:	popl %edi
0x0041c8c0:	popl %esi
0x0041c8c1:	xorl %ecx, %ebp
0x0041c8c3:	popl %ebx
0x0041c8c4:	call 0x00411a73
0x0041c8c9:	leave
0x0041c8ca:	ret

0x004129ad:	addl %esp, $0x10<UINT8>
0x004129b0:	decl -28(%ebp)
0x004129b3:	movl %esi, %eax
0x004129b5:	js 7
0x004129b7:	movl %eax, -32(%ebp)
0x004129ba:	movb (%eax), %bl
0x004129bc:	jmp 0x004129ca
0x004129ca:	movl %eax, %esi
0x004129cc:	popl %esi
0x004129cd:	popl %ebx
0x004129ce:	leave
0x004129cf:	ret

0x00404d64:	addl %esp, $0xc<UINT8>
0x00404d67:	leal %ecx, 0x4(%esp)
0x00404d6b:	pushl %ecx
0x00404d6c:	leal %edx, 0x10(%esp)
0x00404d70:	pushl %edx
0x00404d71:	pushl $0x80000001<UINT32>
0x00404d76:	call RegCreateKeyA@ADVAPI32.dll
RegCreateKeyA@ADVAPI32.dll: API Node	
0x00404d7c:	testl %eax, %eax
0x00404d7e:	jne 41
0x00404d80:	movl %edx, 0x4(%esp)
0x00404d84:	leal %eax, 0x8(%esp)
0x00404d88:	pushl %eax
0x00404d89:	leal %ecx, 0x120(%esp)
0x00404d90:	pushl %ecx
0x00404d91:	pushl $0x0<UINT8>
0x00404d93:	pushl $0x0<UINT8>
0x00404d95:	pushl $0x43dc84<UINT32>
0x00404d9a:	pushl %edx
0x00404d9b:	movl 0x20(%esp), $0x4<UINT32>
0x00404da3:	call RegQueryValueExA@ADVAPI32.dll
RegQueryValueExA@ADVAPI32.dll: API Node	
0x00404da9:	cmpl 0x11c(%esp), $0x0<UINT8>
0x00404db1:	jne 694
0x00404db7:	pushl %ebx
0x00404db8:	pushl %esi
0x00404db9:	pushl %edi
0x00404dba:	pushl $0x3e8<UINT32>
0x00404dbf:	pushl $0x40<UINT8>
0x00404dc1:	call LocalAlloc@KERNEL32.dll
LocalAlloc@KERNEL32.dll: API Node	
0x00404dc7:	movl %esi, %eax
0x00404dc9:	pushl $0x43dc74<UINT32>
0x00404dce:	leal %edi, 0x12(%esi)
0x00404dd1:	call LoadLibraryA@KERNEL32.dll
0x00404dd7:	xorl %eax, %eax
0x00404dd9:	movw 0xa(%esi), %ax
0x00413b50:	movl %edi, %edi
0x00413b52:	pushl %ebp
0x00413b53:	movl %ebp, %esp
0x00413b55:	subl %esp, $0x18<UINT8>
0x00413b58:	pushl %ebx
0x00413b59:	movl %ebx, 0xc(%ebp)
0x00413b5c:	pushl %esi
0x00413b5d:	movl %esi, 0x8(%ebx)
0x00413b60:	xorl %esi, 0x445654
0x00413b66:	pushl %edi
0x00413b67:	movl %eax, (%esi)
0x00413b69:	movb -1(%ebp), $0x0<UINT8>
0x00413b6d:	movl -12(%ebp), $0x1<UINT32>
0x00413b74:	leal %edi, 0x10(%ebx)
0x00413b77:	cmpl %eax, $0xfffffffe<UINT8>
0x00413b7a:	je 0x00413b89
0x00413b89:	movl %ecx, 0xc(%esi)
0x00413b8c:	movl %eax, 0x8(%esi)
0x00413b8f:	addl %ecx, %edi
0x00413b91:	xorl %ecx, (%eax,%edi)
0x00413b94:	call 0x00411a73
0x00413b99:	movl %eax, 0x8(%ebp)
0x00413b9c:	testb 0x4(%eax), $0x66<UINT8>
0x00413ba0:	jne 278
0x00413ba6:	movl %ecx, 0x10(%ebp)
0x00413ba9:	leal %edx, -24(%ebp)
0x00413bac:	movl -4(%ebx), %edx
0x00413baf:	movl %ebx, 0xc(%ebx)
0x00413bb2:	movl -24(%ebp), %eax
0x00413bb5:	movl -20(%ebp), %ecx
0x00413bb8:	cmpl %ebx, $0xfffffffe<UINT8>
0x00413bbb:	je 95
0x00413bbd:	leal %ecx, (%ecx)
0x00413bc0:	leal %eax, (%ebx,%ebx,2)
0x00413bc3:	movl %ecx, 0x14(%esi,%eax,4)
0x00413bc7:	leal %eax, 0x10(%esi,%eax,4)
0x00413bcb:	movl -16(%ebp), %eax
0x00413bce:	movl %eax, (%eax)
0x00413bd0:	movl -8(%ebp), %eax
0x00413bd3:	testl %ecx, %ecx
0x00413bd5:	je 20
0x00413bd7:	movl %edx, %edi
0x00413bd9:	call 0x0041ef86
0x0041ef86:	pushl %ebp
0x0041ef87:	pushl %esi
0x0041ef88:	pushl %edi
0x0041ef89:	pushl %ebx
0x0041ef8a:	movl %ebp, %edx
0x0041ef8c:	xorl %eax, %eax
0x0041ef8e:	xorl %ebx, %ebx
0x0041ef90:	xorl %edx, %edx
0x0041ef92:	xorl %esi, %esi
0x0041ef94:	xorl %edi, %edi
0x0041ef96:	call 0x00414985
0x00414985:	movl %eax, -20(%ebp)
0x00414988:	movl %ecx, (%eax)
0x0041498a:	movl %ecx, (%ecx)
0x0041498c:	movl -36(%ebp), %ecx
0x0041498f:	pushl %eax
0x00414990:	pushl %ecx
0x00414991:	call 0x0041dd13
0x0041dd13:	movl %edi, %edi
0x0041dd15:	pushl %ebp
0x0041dd16:	movl %ebp, %esp
0x0041dd18:	pushl %ecx
0x0041dd19:	pushl %ecx
0x0041dd1a:	pushl %esi
0x0041dd1b:	call 0x0041846b
0x0041dd20:	movl %esi, %eax
0x0041dd22:	testl %esi, %esi
0x0041dd24:	je 326
0x0041dd2a:	movl %edx, 0x5c(%esi)
0x0041dd2d:	movl %eax, 0x44606c
0x0041dd32:	pushl %edi
0x0041dd33:	movl %edi, 0x8(%ebp)
0x0041dd36:	movl %ecx, %edx
0x0041dd38:	pushl %ebx
0x0041dd39:	cmpl (%ecx), %edi
0x0041dd3b:	je 0x0041dd4b
0x0041dd4b:	imull %eax, %eax, $0xc<UINT8>
0x0041dd4e:	addl %eax, %edx
0x0041dd50:	cmpl %ecx, %eax
0x0041dd52:	jae 8
0x0041dd54:	cmpl (%ecx), %edi
0x0041dd56:	jne 4
0x0041dd58:	movl %eax, %ecx
0x0041dd5a:	jmp 0x0041dd5e
0x0041dd5e:	testl %eax, %eax
0x0041dd60:	je 10
0x0041dd62:	movl %ebx, 0x8(%eax)
0x0041dd65:	movl -4(%ebp), %ebx
0x0041dd68:	testl %ebx, %ebx
0x0041dd6a:	jne 7
0x0041dd6c:	xorl %eax, %eax
0x0041dd6e:	jmp 0x0041de6e
0x0041de6e:	popl %ebx
0x0041de6f:	popl %edi
0x0041de70:	popl %esi
0x0041de71:	leave
0x0041de72:	ret

0x00414996:	popl %ecx
0x00414997:	popl %ecx
0x00414998:	ret

0x0041ef98:	popl %ebx
0x0041ef99:	popl %edi
0x0041ef9a:	popl %esi
0x0041ef9b:	popl %ebp
0x0041ef9c:	ret

0x00413bde:	movb -1(%ebp), $0x1<UINT8>
0x00413be2:	testl %eax, %eax
0x00413be4:	jl 64
0x00413be6:	jg 71
0x00413be8:	movl %eax, -8(%ebp)
0x00413beb:	movl %ebx, %eax
0x00413bed:	cmpl %eax, $0xfffffffe<UINT8>
0x00413bf0:	jne -50
0x00413bf2:	cmpb -1(%ebp), $0x0<UINT8>
0x00413bf6:	je 36
0x00413bf8:	movl %eax, (%esi)
0x00413bfa:	cmpl %eax, $0xfffffffe<UINT8>
0x00413bfd:	je 0x00413c0c
0x00413c0c:	movl %ecx, 0xc(%esi)
0x00413c0f:	movl %edx, 0x8(%esi)
0x00413c12:	addl %ecx, %edi
0x00413c14:	xorl %ecx, (%edx,%edi)
0x00413c17:	call 0x00411a73
0x00413c1c:	movl %eax, -12(%ebp)
0x00413c1f:	popl %edi
0x00413c20:	popl %esi
0x00413c21:	popl %ebx
0x00413c22:	movl %esp, %ebp
0x00413c24:	popl %ebp
0x00413c25:	ret

0x00404ddd:	xorl %ecx, %ecx
0x00404ddf:	movl %edx, $0x138<UINT32>
0x00404de4:	movw 0xe(%esi), %dx
0x00404de8:	movw 0xc(%esi), %cx
0x00404dec:	movl %eax, $0xb4<UINT32>
0x00404df1:	movw 0x10(%esi), %ax
0x00404df5:	movw 0x8(%esi), %cx
0x00404df9:	movl (%esi), $0x80c808d0<UINT32>
0x00404dff:	xorl %edx, %edx
0x00404e01:	movw (%edi), %dx
0x00404e04:	addl %edi, $0x2<UINT8>
0x00404e07:	xorl %eax, %eax
0x00404e09:	movw (%edi), %ax
0x00404e0c:	addl %edi, $0x2<UINT8>
0x00404e0f:	pushl %edi
0x00404e10:	movl %ecx, $0x43dc50<UINT32>
0x00404e15:	call 0x00404cf0
0x00404cf0:	movl %eax, %ecx
0x00404cf2:	pushl %esi
0x00404cf3:	leal %esi, 0x2(%eax)
0x00404cf6:	movw %dx, (%eax)
0x00404cf9:	addl %eax, $0x2<UINT8>
0x00404cfc:	testw %dx, %dx
0x00404cff:	jne 0x00404cf6
0x00404d01:	subl %eax, %esi
0x00404d03:	movl %esi, 0x8(%esp)
0x00404d07:	sarl %eax
0x00404d09:	incl %eax
0x00404d0a:	subl %esi, %ecx
0x00404d0c:	leal %esp, (%esp)
0x00404d10:	movzwl %edx, (%ecx)
0x00404d13:	movw (%esi,%ecx), %dx
0x00404d17:	addl %ecx, $0x2<UINT8>
0x00404d1a:	testw %dx, %dx
0x00404d1d:	jne 0x00404d10
0x00404d1f:	popl %esi
0x00404d20:	ret

0x00404e1a:	leal %edi, (%edi,%eax,2)
0x00404e1d:	movl %ecx, $0x8<UINT32>
0x00404e22:	movw (%edi), %cx
0x00404e25:	addl %edi, $0x2<UINT8>
0x00404e28:	pushl %edi
0x00404e29:	movl %ecx, $0x43dc34<UINT32>
0x00404e2e:	call 0x00404cf0
0x00404e33:	leal %eax, (%edi,%eax,2)
0x00404e36:	call 0x00404ce0
0x00404ce0:	addl %eax, $0x3<UINT8>
0x00404ce3:	andl %eax, $0xfffffffc<UINT8>
0x00404ce6:	ret

0x00404e3b:	movl %edx, $0x7<UINT32>
0x00404e40:	movw 0x8(%eax), %dx
0x00404e44:	movl %ecx, $0x3<UINT32>
0x00404e49:	movw 0xa(%eax), %cx
0x00404e4d:	movl %edx, $0x12a<UINT32>
0x00404e52:	movw 0xc(%eax), %dx
0x00404e56:	movl %ecx, $0xe<UINT32>
0x00404e5b:	movw 0xe(%eax), %cx
0x00404e5f:	movl %edx, $0x1f6<UINT32>
0x00404e64:	movw 0x10(%eax), %dx
0x00404e68:	movl (%eax), $0x50000000<UINT32>
0x00404e6e:	leal %edi, 0x12(%eax)
0x00404e71:	movl %eax, $0xffff<UINT32>
0x00404e76:	movw (%edi), %ax
0x00404e79:	addl %edi, $0x2<UINT8>
0x00404e7c:	movl %ecx, $0x82<UINT32>
0x00404e81:	movw (%edi), %cx
0x00404e84:	addl %edi, $0x2<UINT8>
0x00404e87:	pushl %edi
0x00404e88:	movl %ecx, $0x43dba0<UINT32>
0x00404e8d:	call 0x00404cf0
0x00404e92:	leal %eax, (%edi,%eax,2)
0x00404e95:	xorl %edx, %edx
0x00404e97:	movw (%eax), %dx
0x00404e9a:	movl %ebx, $0x1<UINT32>
0x00404e9f:	addw 0x8(%esi), %bx
0x00404ea3:	addl %eax, $0x2<UINT8>
0x00404ea6:	call 0x00404ce0
0x00404eab:	movl %ecx, $0xc9<UINT32>
0x00404eb0:	movw 0x8(%eax), %cx
0x00404eb4:	movl %edx, $0x9f<UINT32>
0x00404eb9:	movw 0xa(%eax), %dx
0x00404ebd:	movl %ecx, $0x32<UINT32>
0x00404ec2:	movl %edx, $0xe<UINT32>
0x00404ec7:	movw 0xc(%eax), %cx
0x00404ecb:	movw 0xe(%eax), %dx
0x00404ecf:	movl %ecx, %ebx
0x00404ed1:	leal %edi, 0x12(%eax)
0x00404ed4:	movl %edx, $0xffff<UINT32>
0x00404ed9:	movw 0x10(%eax), %cx
0x00404edd:	movl (%eax), $0x50010000<UINT32>
0x00404ee3:	movw (%edi), %dx
0x00404ee6:	addl %edi, $0x2<UINT8>
0x00404ee9:	movl %eax, $0x80<UINT32>
0x00404eee:	movw (%edi), %ax
0x00404ef1:	addl %edi, $0x2<UINT8>
0x00404ef4:	pushl %edi
0x00404ef5:	movl %ecx, $0x43db90<UINT32>
0x00404efa:	call 0x00404cf0
0x00404eff:	leal %eax, (%edi,%eax,2)
0x00404f02:	xorl %ecx, %ecx
0x00404f04:	movw (%eax), %cx
0x00404f07:	addw 0x8(%esi), %bx
0x00404f0b:	addl %eax, $0x2<UINT8>
0x00404f0e:	call 0x00404ce0
0x00404f13:	movl %edx, $0xff<UINT32>
0x00404f18:	movw 0x8(%eax), %dx
0x00404f1c:	movl %ecx, $0x9f<UINT32>
0x00404f21:	movw 0xa(%eax), %cx
0x00404f25:	movl %edx, $0x32<UINT32>
0x00404f2a:	movw 0xc(%eax), %dx
0x00404f2e:	movl %edx, $0x2<UINT32>
0x00404f33:	movl %ecx, $0xe<UINT32>
0x00404f38:	movw 0xe(%eax), %cx
0x00404f3c:	movw 0x10(%eax), %dx
0x00404f40:	movl (%eax), $0x50010000<UINT32>
0x00404f46:	leal %edi, 0x12(%eax)
0x00404f49:	movl %eax, $0xffff<UINT32>
0x00404f4e:	movw (%edi), %ax
0x00404f51:	addl %edi, %edx
0x00404f53:	movl %ecx, $0x80<UINT32>
0x00404f58:	movw (%edi), %cx
0x00404f5b:	addl %edi, %edx
0x00404f5d:	pushl %edi
0x00404f5e:	movl %ecx, $0x43db7c<UINT32>
0x00404f63:	call 0x00404cf0
0x00404f68:	leal %eax, (%edi,%eax,2)
0x00404f6b:	xorl %edx, %edx
0x00404f6d:	movw (%eax), %dx
0x00404f70:	addw 0x8(%esi), %bx
0x00404f74:	addl %eax, $0x2<UINT8>
0x00404f77:	call 0x00404ce0
0x00404f7c:	movl %ecx, $0x7<UINT32>
0x00404f81:	movw 0x8(%eax), %cx
0x00404f85:	movl %edx, $0x9f<UINT32>
0x00404f8a:	movw 0xa(%eax), %dx
0x00404f8e:	movl %ecx, $0x32<UINT32>
0x00404f93:	movw 0xc(%eax), %cx
0x00404f97:	movl %edx, $0xe<UINT32>
0x00404f9c:	movw 0xe(%eax), %dx
0x00404fa0:	leal %edi, 0x12(%eax)
0x00404fa3:	movl %ecx, $0x1f5<UINT32>
0x00404fa8:	movw 0x10(%eax), %cx
0x00404fac:	movl (%eax), $0x50010000<UINT32>
0x00404fb2:	movl %edx, $0xffff<UINT32>
0x00404fb7:	movw (%edi), %dx
0x00404fba:	addl %edi, $0x2<UINT8>
0x00404fbd:	movl %eax, $0x80<UINT32>
0x00404fc2:	movw (%edi), %ax
0x00404fc5:	addl %edi, $0x2<UINT8>
0x00404fc8:	pushl %edi
0x00404fc9:	movl %ecx, $0x43db6c<UINT32>
0x00404fce:	call 0x00404cf0
0x00404fd3:	leal %eax, (%edi,%eax,2)
0x00404fd6:	xorl %ecx, %ecx
0x00404fd8:	movw (%eax), %cx
0x00404fdb:	addw 0x8(%esi), %bx
0x00404fdf:	addl %eax, $0x2<UINT8>
0x00404fe2:	call 0x00404ce0
0x00404fe7:	movl %edx, $0x7<UINT32>
0x00404fec:	movw 0x8(%eax), %dx
0x00404ff0:	movl %ecx, $0xe<UINT32>
0x00404ff5:	movw 0xa(%eax), %cx
0x00404ff9:	movl %edx, $0x12a<UINT32>
0x00404ffe:	movl %ecx, $0x8c<UINT32>
0x00405003:	movw 0xc(%eax), %dx
0x00405007:	leal %edi, 0x12(%eax)
0x0040500a:	movw 0xe(%eax), %cx
0x0040500e:	movl %edx, $0x1f4<UINT32>
0x00405013:	pushl %edi
0x00405014:	movl %ecx, $0x43db58<UINT32>
0x00405019:	movw 0x10(%eax), %dx
0x0040501d:	movl (%eax), $0x50a11844<UINT32>
0x00405023:	call 0x00404cf0
0x00405028:	leal %edi, (%edi,%eax,2)
0x0040502b:	pushl %edi
0x0040502c:	movl %ecx, $0x43db7c<UINT32>
0x00405031:	call 0x00404cf0
0x00405036:	addl %esp, $0x20<UINT8>
0x00405039:	pushl %ebp
0x0040503a:	xorl %ecx, %ecx
0x0040503c:	pushl $0x404b80<UINT32>
0x00405041:	pushl %ecx
0x00405042:	pushl %esi
0x00405043:	movw (%edi,%eax,2), %cx
0x00405047:	addw 0x8(%esi), %bx
0x0040504b:	pushl %ecx
0x0040504c:	call DialogBoxIndirectParamA@USER32.dll
DialogBoxIndirectParamA@USER32.dll: API Node	
0x00405052:	pushl %esi
0x00405053:	movl 0x12c(%esp), %eax
0x0040505a:	call LocalFree@KERNEL32.dll
LocalFree@KERNEL32.dll: API Node	
0x00405060:	cmpl 0x128(%esp), $0x0<UINT8>
0x00405068:	popl %edi
0x00405069:	popl %esi
0x0040506a:	popl %ebx
0x0040506b:	je 30
