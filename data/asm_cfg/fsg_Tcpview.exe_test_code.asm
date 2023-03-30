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
0x00416f06:	jne 18
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
0x00411848:	jne 99
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
0x004123b3:	je 10
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
