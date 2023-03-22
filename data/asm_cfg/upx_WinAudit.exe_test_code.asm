0x00709810:	pusha
0x00709811:	movl %esi, $0x62f000<UINT32>
0x00709816:	leal %edi, -2285568(%esi)
0x0070981c:	pushl %edi
0x0070981d:	jmp 0x0070982a
0x0070982a:	movl %ebx, (%esi)
0x0070982c:	subl %esi, $0xfffffffc<UINT8>
0x0070982f:	adcl %ebx, %ebx
0x00709831:	jb 0x00709820
0x00709820:	movb %al, (%esi)
0x00709822:	incl %esi
0x00709823:	movb (%edi), %al
0x00709825:	incl %edi
0x00709826:	addl %ebx, %ebx
0x00709828:	jne 0x00709831
0x00709833:	movl %eax, $0x1<UINT32>
0x00709838:	addl %ebx, %ebx
0x0070983a:	jne 0x00709843
0x00709843:	adcl %eax, %eax
0x00709845:	addl %ebx, %ebx
0x00709847:	jae 0x00709854
0x00709849:	jne 0x00709873
0x00709873:	xorl %ecx, %ecx
0x00709875:	subl %eax, $0x3<UINT8>
0x00709878:	jb 0x0070988b
0x0070987a:	shll %eax, $0x8<UINT8>
0x0070987d:	movb %al, (%esi)
0x0070987f:	incl %esi
0x00709880:	xorl %eax, $0xffffffff<UINT8>
0x00709883:	je 0x007098fa
0x00709885:	sarl %eax
0x00709887:	movl %ebp, %eax
0x00709889:	jmp 0x00709896
0x00709896:	jb 0x00709864
0x00709864:	addl %ebx, %ebx
0x00709866:	jne 0x0070986f
0x0070986f:	adcl %ecx, %ecx
0x00709871:	jmp 0x007098c5
0x007098c5:	cmpl %ebp, $0xfffffb00<UINT32>
0x007098cb:	adcl %ecx, $0x2<UINT8>
0x007098ce:	leal %edx, (%edi,%ebp)
0x007098d1:	cmpl %ebp, $0xfffffffc<UINT8>
0x007098d4:	jbe 0x007098e4
0x007098e4:	movl %eax, (%edx)
0x007098e6:	addl %edx, $0x4<UINT8>
0x007098e9:	movl (%edi), %eax
0x007098eb:	addl %edi, $0x4<UINT8>
0x007098ee:	subl %ecx, $0x4<UINT8>
0x007098f1:	ja 0x007098e4
0x007098f3:	addl %edi, %ecx
0x007098f5:	jmp 0x00709826
0x007098d6:	movb %al, (%edx)
0x007098d8:	incl %edx
0x007098d9:	movb (%edi), %al
0x007098db:	incl %edi
0x007098dc:	decl %ecx
0x007098dd:	jne 0x007098d6
0x007098df:	jmp 0x00709826
0x0070988b:	addl %ebx, %ebx
0x0070988d:	jne 0x00709896
0x00709898:	incl %ecx
0x00709899:	addl %ebx, %ebx
0x0070989b:	jne 0x007098a4
0x007098a4:	jb 0x00709864
0x007098a6:	addl %ebx, %ebx
0x007098a8:	jne 0x007098b1
0x007098b1:	adcl %ecx, %ecx
0x007098b3:	addl %ebx, %ebx
0x007098b5:	jae 0x007098a6
0x007098b7:	jne 0x007098c2
0x007098c2:	addl %ecx, $0x2<UINT8>
0x0070983c:	movl %ebx, (%esi)
0x0070983e:	subl %esi, $0xfffffffc<UINT8>
0x00709841:	adcl %ebx, %ebx
0x00709854:	decl %eax
0x00709855:	addl %ebx, %ebx
0x00709857:	jne 0x00709860
0x00709860:	adcl %eax, %eax
0x00709862:	jmp 0x00709838
0x0070984b:	movl %ebx, (%esi)
0x0070984d:	subl %esi, $0xfffffffc<UINT8>
0x00709850:	adcl %ebx, %ebx
0x00709852:	jb 0x00709873
0x00709868:	movl %ebx, (%esi)
0x0070986a:	subl %esi, $0xfffffffc<UINT8>
0x0070986d:	adcl %ebx, %ebx
0x0070989d:	movl %ebx, (%esi)
0x0070989f:	subl %esi, $0xfffffffc<UINT8>
0x007098a2:	adcl %ebx, %ebx
0x00709859:	movl %ebx, (%esi)
0x0070985b:	subl %esi, $0xfffffffc<UINT8>
0x0070985e:	adcl %ebx, %ebx
0x007098b9:	movl %ebx, (%esi)
0x007098bb:	subl %esi, $0xfffffffc<UINT8>
0x007098be:	adcl %ebx, %ebx
0x007098c0:	jae 0x007098a6
0x0070988f:	movl %ebx, (%esi)
0x00709891:	subl %esi, $0xfffffffc<UINT8>
0x00709894:	adcl %ebx, %ebx
0x007098aa:	movl %ebx, (%esi)
0x007098ac:	subl %esi, $0xfffffffc<UINT8>
0x007098af:	adcl %ebx, %ebx
0x007098fa:	popl %esi
0x007098fb:	movl %edi, %esi
0x007098fd:	movl %ecx, $0xe433<UINT32>
0x00709902:	movb %al, (%edi)
0x00709904:	incl %edi
0x00709905:	subb %al, $0xffffffe8<UINT8>
0x00709907:	cmpb %al, $0x1<UINT8>
0x00709909:	ja 0x00709902
0x0070990b:	cmpb (%edi), $0x3d<UINT8>
0x0070990e:	jne 0x00709902
0x00709910:	movl %eax, (%edi)
0x00709912:	movb %bl, 0x4(%edi)
0x00709915:	shrw %ax, $0x8<UINT8>
0x00709919:	roll %eax, $0x10<UINT8>
0x0070991c:	xchgb %ah, %al
0x0070991e:	subl %eax, %edi
0x00709920:	subb %bl, $0xffffffe8<UINT8>
0x00709923:	addl %eax, %esi
0x00709925:	movl (%edi), %eax
0x00709927:	addl %edi, $0x5<UINT8>
0x0070992a:	movb %al, %bl
0x0070992c:	loop 0x00709907
0x0070992e:	leal %edi, 0x306000(%esi)
0x00709934:	movl %eax, (%edi)
0x00709936:	orl %eax, %eax
0x00709938:	je 0x0070997f
0x0070993a:	movl %ebx, 0x4(%edi)
0x0070993d:	leal %eax, 0x312100(%eax,%esi)
0x00709944:	addl %ebx, %esi
0x00709946:	pushl %eax
0x00709947:	addl %edi, $0x8<UINT8>
0x0070994a:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00709950:	xchgl %ebp, %eax
0x00709951:	movb %al, (%edi)
0x00709953:	incl %edi
0x00709954:	orb %al, %al
0x00709956:	je 0x00709934
0x00709958:	movl %ecx, %edi
0x0070995a:	jns 0x00709963
0x00709963:	pushl %edi
0x00709964:	decl %eax
0x00709965:	repn scasb %al, %es:(%edi)
0x00709967:	pushl %ebp
0x00709968:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0070996e:	orl %eax, %eax
0x00709970:	je 7
0x00709972:	movl (%ebx), %eax
0x00709974:	addl %ebx, $0x4<UINT8>
0x00709977:	jmp 0x00709951
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x0070995c:	movzwl %eax, (%edi)
0x0070995f:	incl %edi
0x00709960:	pushl %eax
0x00709961:	incl %edi
0x00709962:	movl %ecx, $0xaef24857<UINT32>
0x0070997f:	movl %ebp, 0x312228(%esi)
0x00709985:	leal %edi, -4096(%esi)
0x0070998b:	movl %ebx, $0x1000<UINT32>
0x00709990:	pushl %eax
0x00709991:	pushl %esp
0x00709992:	pushl $0x4<UINT8>
0x00709994:	pushl %ebx
0x00709995:	pushl %edi
0x00709996:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00709998:	leal %eax, 0x20f(%edi)
0x0070999e:	andb (%eax), $0x7f<UINT8>
0x007099a1:	andb 0x28(%eax), $0x7f<UINT8>
0x007099a5:	popl %eax
0x007099a6:	pushl %eax
0x007099a7:	pushl %esp
0x007099a8:	pushl %eax
0x007099a9:	pushl %ebx
0x007099aa:	pushl %edi
0x007099ab:	call VirtualProtect@kernel32.dll
0x007099ad:	popl %eax
0x007099ae:	popa
0x007099af:	leal %eax, -128(%esp)
0x007099b3:	pushl $0x0<UINT8>
0x007099b5:	cmpl %esp, %eax
0x007099b7:	jne 0x007099b3
0x007099b9:	subl %esp, $0xffffff80<UINT8>
0x007099bc:	jmp 0x0051b411
0x0051b411:	call 0x00525383
0x00525383:	movl %edi, %edi
0x00525385:	pushl %ebp
0x00525386:	movl %ebp, %esp
0x00525388:	subl %esp, $0x10<UINT8>
0x0052538b:	movl %eax, 0x5be7b0
0x00525390:	andl -8(%ebp), $0x0<UINT8>
0x00525394:	andl -4(%ebp), $0x0<UINT8>
0x00525398:	pushl %ebx
0x00525399:	pushl %edi
0x0052539a:	movl %edi, $0xbb40e64e<UINT32>
0x0052539f:	movl %ebx, $0xffff0000<UINT32>
0x005253a4:	cmpl %eax, %edi
0x005253a6:	je 0x005253b5
0x005253b5:	pushl %esi
0x005253b6:	leal %eax, -8(%ebp)
0x005253b9:	pushl %eax
0x005253ba:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x005253c0:	movl %esi, -4(%ebp)
0x005253c3:	xorl %esi, -8(%ebp)
0x005253c6:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x005253cc:	xorl %esi, %eax
0x005253ce:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x005253d4:	xorl %esi, %eax
0x005253d6:	call GetTickCount@KERNEL32.DLL
GetTickCount@KERNEL32.DLL: API Node	
0x005253dc:	xorl %esi, %eax
0x005253de:	leal %eax, -16(%ebp)
0x005253e1:	pushl %eax
0x005253e2:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x005253e8:	movl %eax, -12(%ebp)
0x005253eb:	xorl %eax, -16(%ebp)
0x005253ee:	xorl %esi, %eax
0x005253f0:	cmpl %esi, %edi
0x005253f2:	jne 0x005253fb
0x005253fb:	testl %ebx, %esi
0x005253fd:	jne 0x00525406
0x00525406:	movl 0x5be7b0, %esi
0x0052540c:	notl %esi
0x0052540e:	movl 0x5be7b4, %esi
0x00525414:	popl %esi
0x00525415:	popl %edi
0x00525416:	popl %ebx
0x00525417:	leave
0x00525418:	ret

0x0051b416:	jmp 0x0051b293
0x0051b293:	pushl $0x58<UINT8>
0x0051b295:	pushl $0x5b8d60<UINT32>
0x0051b29a:	call 0x0052313c
0x0052313c:	pushl $0x5231a0<UINT32>
0x00523141:	pushl %fs:0
0x00523148:	movl %eax, 0x10(%esp)
0x0052314c:	movl 0x10(%esp), %ebp
0x00523150:	leal %ebp, 0x10(%esp)
0x00523154:	subl %esp, %eax
0x00523156:	pushl %ebx
0x00523157:	pushl %esi
0x00523158:	pushl %edi
0x00523159:	movl %eax, 0x5be7b0
0x0052315e:	xorl -4(%ebp), %eax
0x00523161:	xorl %eax, %ebp
0x00523163:	pushl %eax
0x00523164:	movl -24(%ebp), %esp
0x00523167:	pushl -8(%ebp)
0x0052316a:	movl %eax, -4(%ebp)
0x0052316d:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00523174:	movl -8(%ebp), %eax
0x00523177:	leal %eax, -16(%ebp)
0x0052317a:	movl %fs:0, %eax
0x00523180:	ret

0x0051b29f:	xorl %esi, %esi
0x0051b2a1:	movl -4(%ebp), %esi
0x0051b2a4:	leal %eax, -104(%ebp)
0x0051b2a7:	pushl %eax
0x0051b2a8:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x0051b2ae:	pushl $0xfffffffe<UINT8>
0x0051b2b0:	popl %edi
0x0051b2b1:	movl -4(%ebp), %edi
0x0051b2b4:	movl %eax, $0x5a4d<UINT32>
0x0051b2b9:	cmpw 0x400000, %ax
0x0051b2c0:	jne 56
0x0051b2c2:	movl %eax, 0x40003c
0x0051b2c7:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x0051b2d1:	jne 39
0x0051b2d3:	movl %ecx, $0x10b<UINT32>
0x0051b2d8:	cmpw 0x400018(%eax), %cx
0x0051b2df:	jne 25
0x0051b2e1:	cmpl 0x400074(%eax), $0xe<UINT8>
0x0051b2e8:	jbe 16
0x0051b2ea:	xorl %ecx, %ecx
0x0051b2ec:	cmpl 0x4000e8(%eax), %esi
0x0051b2f2:	setne %cl
0x0051b2f5:	movl -28(%ebp), %ecx
0x0051b2f8:	jmp 0x0051b2fd
0x0051b2fd:	xorl %ebx, %ebx
0x0051b2ff:	incl %ebx
0x0051b300:	pushl %ebx
0x0051b301:	call 0x00525353
0x00525353:	movl %edi, %edi
0x00525355:	pushl %ebp
0x00525356:	movl %ebp, %esp
0x00525358:	xorl %eax, %eax
0x0052535a:	cmpl 0x8(%ebp), %eax
0x0052535d:	pushl $0x0<UINT8>
0x0052535f:	sete %al
0x00525362:	pushl $0x1000<UINT32>
0x00525367:	pushl %eax
0x00525368:	call HeapCreate@KERNEL32.DLL
HeapCreate@KERNEL32.DLL: API Node	
0x0052536e:	movl 0x5c0a34, %eax
0x00525373:	testl %eax, %eax
0x00525375:	jne 0x00525379
0x00525379:	xorl %eax, %eax
0x0052537b:	incl %eax
0x0052537c:	movl 0x5c0ce4, %eax
0x00525381:	popl %ebp
0x00525382:	ret

0x0051b306:	popl %ecx
0x0051b307:	testl %eax, %eax
0x0051b309:	jne 0x0051b313
0x0051b313:	call 0x00520eba
0x00520eba:	movl %edi, %edi
0x00520ebc:	pushl %esi
0x00520ebd:	pushl %edi
0x00520ebe:	movl %esi, $0x594520<UINT32>
0x00520ec3:	pushl %esi
0x00520ec4:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00520eca:	testl %eax, %eax
0x00520ecc:	jne 0x00520ed5
0x00520ed5:	movl %edi, %eax
0x00520ed7:	testl %edi, %edi
0x00520ed9:	je 350
0x00520edf:	movl %esi, 0x542418
0x00520ee5:	pushl $0x59456c<UINT32>
0x00520eea:	pushl %edi
0x00520eeb:	call GetProcAddress@KERNEL32.DLL
0x00520eed:	pushl $0x594560<UINT32>
0x00520ef2:	pushl %edi
0x00520ef3:	movl 0x5c0230, %eax
0x00520ef8:	call GetProcAddress@KERNEL32.DLL
0x00520efa:	pushl $0x594554<UINT32>
0x00520eff:	pushl %edi
0x00520f00:	movl 0x5c0234, %eax
0x00520f05:	call GetProcAddress@KERNEL32.DLL
0x00520f07:	pushl $0x59454c<UINT32>
0x00520f0c:	pushl %edi
0x00520f0d:	movl 0x5c0238, %eax
0x00520f12:	call GetProcAddress@KERNEL32.DLL
0x00520f14:	cmpl 0x5c0230, $0x0<UINT8>
0x00520f1b:	movl %esi, 0x54229c
0x00520f21:	movl 0x5c023c, %eax
0x00520f26:	je 22
0x00520f28:	cmpl 0x5c0234, $0x0<UINT8>
0x00520f2f:	je 13
0x00520f31:	cmpl 0x5c0238, $0x0<UINT8>
0x00520f38:	je 4
0x00520f3a:	testl %eax, %eax
0x00520f3c:	jne 0x00520f62
0x00520f62:	call TlsAlloc@KERNEL32.DLL
TlsAlloc@KERNEL32.DLL: API Node	
0x00520f68:	movl 0x5bec88, %eax
0x00520f6d:	cmpl %eax, $0xffffffff<UINT8>
0x00520f70:	je 204
0x00520f76:	pushl 0x5c0234
0x00520f7c:	pushl %eax
0x00520f7d:	call TlsSetValue@KERNEL32.DLL
TlsSetValue@KERNEL32.DLL: API Node	
0x00520f7f:	testl %eax, %eax
0x00520f81:	je 187
0x00520f87:	call 0x00524384
0x00524384:	movl %edi, %edi
0x00524386:	pushl %esi
0x00524387:	call 0x00520b1c
0x00520b1c:	pushl $0x0<UINT8>
0x00520b1e:	call 0x00520aaa
0x00520aaa:	movl %edi, %edi
0x00520aac:	pushl %ebp
0x00520aad:	movl %ebp, %esp
0x00520aaf:	pushl %esi
0x00520ab0:	pushl 0x5bec88
0x00520ab6:	movl %esi, 0x542294
0x00520abc:	call TlsGetValue@KERNEL32.DLL
TlsGetValue@KERNEL32.DLL: API Node	
0x00520abe:	testl %eax, %eax
0x00520ac0:	je 33
0x00520ac2:	movl %eax, 0x5bec84
0x00520ac7:	cmpl %eax, $0xffffffff<UINT8>
0x00520aca:	je 0x00520ae3
0x00520ae3:	movl %esi, $0x594520<UINT32>
0x00520ae8:	pushl %esi
0x00520ae9:	call GetModuleHandleW@KERNEL32.DLL
0x00520aef:	testl %eax, %eax
0x00520af1:	jne 0x00520afe
0x00520afe:	pushl $0x594510<UINT32>
0x00520b03:	pushl %eax
0x00520b04:	call GetProcAddress@KERNEL32.DLL
0x00520b0a:	testl %eax, %eax
0x00520b0c:	je 8
0x00520b0e:	pushl 0x8(%ebp)
0x00520b11:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00520b13:	movl 0x8(%ebp), %eax
0x00520b16:	movl %eax, 0x8(%ebp)
0x00520b19:	popl %esi
0x00520b1a:	popl %ebp
0x00520b1b:	ret

0x00520b23:	popl %ecx
0x00520b24:	ret

0x0052438c:	movl %esi, %eax
0x0052438e:	pushl %esi
0x0052438f:	call 0x0051c50d
0x0051c50d:	movl %edi, %edi
0x0051c50f:	pushl %ebp
0x0051c510:	movl %ebp, %esp
0x0051c512:	movl %eax, 0x8(%ebp)
0x0051c515:	movl 0x5c0220, %eax
0x0051c51a:	popl %ebp
0x0051c51b:	ret

0x00524394:	pushl %esi
0x00524395:	call 0x0052cc9b
0x0052cc9b:	movl %edi, %edi
0x0052cc9d:	pushl %ebp
0x0052cc9e:	movl %ebp, %esp
0x0052cca0:	movl %eax, 0x8(%ebp)
0x0052cca3:	movl 0x5c0bfc, %eax
0x0052cca8:	popl %ebp
0x0052cca9:	ret

0x0052439a:	pushl %esi
0x0052439b:	call 0x0051ae6c
0x0051ae6c:	movl %edi, %edi
0x0051ae6e:	pushl %ebp
0x0051ae6f:	movl %ebp, %esp
0x0051ae71:	movl %eax, 0x8(%ebp)
0x0051ae74:	movl 0x5c0210, %eax
0x0051ae79:	popl %ebp
0x0051ae7a:	ret

0x005243a0:	pushl %esi
0x005243a1:	call 0x00524083
0x00524083:	movl %edi, %edi
0x00524085:	pushl %ebp
0x00524086:	movl %ebp, %esp
0x00524088:	movl %eax, 0x8(%ebp)
0x0052408b:	movl 0x5c08d4, %eax
0x00524090:	popl %ebp
0x00524091:	ret

0x005243a6:	pushl %esi
0x005243a7:	call 0x0052cc8c
0x0052cc8c:	movl %edi, %edi
0x0052cc8e:	pushl %ebp
0x0052cc8f:	movl %ebp, %esp
0x0052cc91:	movl %eax, 0x8(%ebp)
0x0052cc94:	movl 0x5c0bf8, %eax
0x0052cc99:	popl %ebp
0x0052cc9a:	ret

0x005243ac:	pushl %esi
0x005243ad:	call 0x005243d2
0x005243d2:	movl %edi, %edi
0x005243d4:	pushl %ebp
0x005243d5:	movl %ebp, %esp
0x005243d7:	movl %eax, 0x8(%ebp)
0x005243da:	movl 0x5c090c, %eax
0x005243df:	movl 0x5c0910, %eax
0x005243e4:	movl 0x5c0914, %eax
0x005243e9:	movl 0x5c0918, %eax
0x005243ee:	popl %ebp
0x005243ef:	ret

0x005243b2:	pushl %esi
0x005243b3:	call 0x00524a89
0x00524a89:	ret

0x005243b8:	pushl %esi
0x005243b9:	call 0x005210cb
0x005210cb:	pushl $0x521047<UINT32>
0x005210d0:	call 0x00520aaa
0x005210d5:	popl %ecx
0x005210d6:	movl 0x5c0240, %eax
0x005210db:	ret

0x005243be:	pushl $0x524350<UINT32>
0x005243c3:	call 0x00520aaa
0x005243c8:	addl %esp, $0x24<UINT8>
0x005243cb:	movl 0x5bf3a0, %eax
0x005243d0:	popl %esi
0x005243d1:	ret

0x00520f8c:	pushl 0x5c0230
0x00520f92:	call 0x00520aaa
0x00520f97:	pushl 0x5c0234
0x00520f9d:	movl 0x5c0230, %eax
0x00520fa2:	call 0x00520aaa
0x00520fa7:	pushl 0x5c0238
0x00520fad:	movl 0x5c0234, %eax
0x00520fb2:	call 0x00520aaa
0x00520fb7:	pushl 0x5c023c
0x00520fbd:	movl 0x5c0238, %eax
0x00520fc2:	call 0x00520aaa
0x00520fc7:	addl %esp, $0x10<UINT8>
0x00520fca:	movl 0x5c023c, %eax
0x00520fcf:	call 0x00526881
0x00526881:	movl %edi, %edi
0x00526883:	pushl %esi
0x00526884:	pushl %edi
0x00526885:	xorl %esi, %esi
0x00526887:	movl %edi, $0x5c0a38<UINT32>
0x0052688c:	cmpl 0x5bf494(,%esi,8), $0x1<UINT8>
0x00526894:	jne 0x005268b4
0x00526896:	leal %eax, 0x5bf490(,%esi,8)
0x0052689d:	movl (%eax), %edi
0x0052689f:	pushl $0xfa0<UINT32>
0x005268a4:	pushl (%eax)
0x005268a6:	addl %edi, $0x18<UINT8>
0x005268a9:	call 0x0052ccaa
0x0052ccaa:	pushl $0x10<UINT8>
0x0052ccac:	pushl $0x5b9340<UINT32>
0x0052ccb1:	call 0x0052313c
0x0052ccb6:	andl -4(%ebp), $0x0<UINT8>
0x0052ccba:	pushl 0xc(%ebp)
0x0052ccbd:	pushl 0x8(%ebp)
0x0052ccc0:	call InitializeCriticalSectionAndSpinCount@KERNEL32.DLL
InitializeCriticalSectionAndSpinCount@KERNEL32.DLL: API Node	
0x0052ccc6:	movl -28(%ebp), %eax
0x0052ccc9:	jmp 0x0052ccfa
0x0052ccfa:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0052cd01:	movl %eax, -28(%ebp)
0x0052cd04:	call 0x00523181
0x00523181:	movl %ecx, -16(%ebp)
0x00523184:	movl %fs:0, %ecx
0x0052318b:	popl %ecx
0x0052318c:	popl %edi
0x0052318d:	popl %edi
0x0052318e:	popl %esi
0x0052318f:	popl %ebx
0x00523190:	movl %esp, %ebp
0x00523192:	popl %ebp
0x00523193:	pushl %ecx
0x00523194:	ret

0x0052cd09:	ret

0x005268ae:	popl %ecx
0x005268af:	popl %ecx
0x005268b0:	testl %eax, %eax
0x005268b2:	je 12
0x005268b4:	incl %esi
0x005268b5:	cmpl %esi, $0x24<UINT8>
0x005268b8:	jl 0x0052688c
0x005268ba:	xorl %eax, %eax
0x005268bc:	incl %eax
0x005268bd:	popl %edi
0x005268be:	popl %esi
0x005268bf:	ret

0x00520fd4:	testl %eax, %eax
0x00520fd6:	je 101
0x00520fd8:	pushl $0x520d8b<UINT32>
0x00520fdd:	pushl 0x5c0230
0x00520fe3:	call 0x00520b25
0x00520b25:	movl %edi, %edi
0x00520b27:	pushl %ebp
0x00520b28:	movl %ebp, %esp
0x00520b2a:	pushl %esi
0x00520b2b:	pushl 0x5bec88
0x00520b31:	movl %esi, 0x542294
0x00520b37:	call TlsGetValue@KERNEL32.DLL
0x00520b39:	testl %eax, %eax
0x00520b3b:	je 33
0x00520b3d:	movl %eax, 0x5bec84
0x00520b42:	cmpl %eax, $0xffffffff<UINT8>
0x00520b45:	je 0x00520b5e
0x00520b5e:	movl %esi, $0x594520<UINT32>
0x00520b63:	pushl %esi
0x00520b64:	call GetModuleHandleW@KERNEL32.DLL
0x00520b6a:	testl %eax, %eax
0x00520b6c:	jne 0x00520b79
0x00520b79:	pushl $0x59453c<UINT32>
0x00520b7e:	pushl %eax
0x00520b7f:	call GetProcAddress@KERNEL32.DLL
0x00520b85:	testl %eax, %eax
0x00520b87:	je 8
0x00520b89:	pushl 0x8(%ebp)
0x00520b8c:	call DecodePointer@KERNEL32.DLL
DecodePointer@KERNEL32.DLL: API Node	
0x00520b8e:	movl 0x8(%ebp), %eax
0x00520b91:	movl %eax, 0x8(%ebp)
0x00520b94:	popl %esi
0x00520b95:	popl %ebp
0x00520b96:	ret

0x00520fe8:	popl %ecx
0x00520fe9:	call FlsAlloc@KERNEL32.DLL
FlsAlloc@KERNEL32.DLL: API Node	
0x00520feb:	movl 0x5bec84, %eax
0x00520ff0:	cmpl %eax, $0xffffffff<UINT8>
0x00520ff3:	je 72
0x00520ff5:	pushl $0x214<UINT32>
0x00520ffa:	pushl $0x1<UINT8>
0x00520ffc:	call 0x00526a75
0x00526a75:	movl %edi, %edi
0x00526a77:	pushl %ebp
0x00526a78:	movl %ebp, %esp
0x00526a7a:	pushl %esi
0x00526a7b:	pushl %edi
0x00526a7c:	xorl %esi, %esi
0x00526a7e:	pushl $0x0<UINT8>
0x00526a80:	pushl 0xc(%ebp)
0x00526a83:	pushl 0x8(%ebp)
0x00526a86:	call 0x0052e0c1
0x0052e0c1:	pushl $0xc<UINT8>
0x0052e0c3:	pushl $0x5b9360<UINT32>
0x0052e0c8:	call 0x0052313c
0x0052e0cd:	movl %ecx, 0x8(%ebp)
0x0052e0d0:	xorl %edi, %edi
0x0052e0d2:	cmpl %ecx, %edi
0x0052e0d4:	jbe 46
0x0052e0d6:	pushl $0xffffffe0<UINT8>
0x0052e0d8:	popl %eax
0x0052e0d9:	xorl %edx, %edx
0x0052e0db:	divl %eax, %ecx
0x0052e0dd:	cmpl %eax, 0xc(%ebp)
0x0052e0e0:	sbbl %eax, %eax
0x0052e0e2:	incl %eax
0x0052e0e3:	jne 0x0052e104
0x0052e104:	imull %ecx, 0xc(%ebp)
0x0052e108:	movl %esi, %ecx
0x0052e10a:	movl 0x8(%ebp), %esi
0x0052e10d:	cmpl %esi, %edi
0x0052e10f:	jne 0x0052e114
0x0052e114:	xorl %ebx, %ebx
0x0052e116:	movl -28(%ebp), %ebx
0x0052e119:	cmpl %esi, $0xffffffe0<UINT8>
0x0052e11c:	ja 105
0x0052e11e:	cmpl 0x5c0ce4, $0x3<UINT8>
0x0052e125:	jne 0x0052e172
0x0052e172:	cmpl %ebx, %edi
0x0052e174:	jne 97
0x0052e176:	pushl %esi
0x0052e177:	pushl $0x8<UINT8>
0x0052e179:	pushl 0x5c0a34
0x0052e17f:	call HeapAlloc@KERNEL32.DLL
HeapAlloc@KERNEL32.DLL: API Node	
0x0052e185:	movl %ebx, %eax
0x0052e187:	cmpl %ebx, %edi
0x0052e189:	jne 0x0052e1d7
0x0052e1d7:	movl %eax, %ebx
0x0052e1d9:	call 0x00523181
0x0052e1de:	ret

0x00526a8b:	movl %edi, %eax
0x00526a8d:	addl %esp, $0xc<UINT8>
0x00526a90:	testl %edi, %edi
0x00526a92:	jne 0x00526abb
0x00526abb:	movl %eax, %edi
0x00526abd:	popl %edi
0x00526abe:	popl %esi
0x00526abf:	popl %ebp
0x00526ac0:	ret

0x00521001:	movl %esi, %eax
0x00521003:	popl %ecx
0x00521004:	popl %ecx
0x00521005:	testl %esi, %esi
0x00521007:	je 52
0x00521009:	pushl %esi
0x0052100a:	pushl 0x5bec84
0x00521010:	pushl 0x5c0238
0x00521016:	call 0x00520b25
0x00520b47:	pushl %eax
0x00520b48:	pushl 0x5bec88
0x00520b4e:	call TlsGetValue@KERNEL32.DLL
0x00520b50:	call FlsGetValue@KERNEL32.DLL
FlsGetValue@KERNEL32.DLL: API Node	
0x00520b52:	testl %eax, %eax
0x00520b54:	je 0x00520b5e
0x0052101b:	popl %ecx
0x0052101c:	call FlsSetValue@KERNEL32.DLL
FlsSetValue@KERNEL32.DLL: API Node	
0x0052101e:	testl %eax, %eax
0x00521020:	je 27
0x00521022:	pushl $0x0<UINT8>
0x00521024:	pushl %esi
0x00521025:	call 0x00520c11
0x00520c11:	pushl $0xc<UINT8>
0x00520c13:	pushl $0x5b9030<UINT32>
0x00520c18:	call 0x0052313c
0x00520c1d:	movl %esi, $0x594520<UINT32>
0x00520c22:	pushl %esi
0x00520c23:	call GetModuleHandleW@KERNEL32.DLL
0x00520c29:	testl %eax, %eax
0x00520c2b:	jne 0x00520c34
0x00520c34:	movl -28(%ebp), %eax
0x00520c37:	movl %esi, 0x8(%ebp)
0x00520c3a:	movl 0x5c(%esi), $0x594c90<UINT32>
0x00520c41:	xorl %edi, %edi
0x00520c43:	incl %edi
0x00520c44:	movl 0x14(%esi), %edi
0x00520c47:	testl %eax, %eax
0x00520c49:	je 36
0x00520c4b:	pushl $0x594510<UINT32>
0x00520c50:	pushl %eax
0x00520c51:	movl %ebx, 0x542418
0x00520c57:	call GetProcAddress@KERNEL32.DLL
0x00520c59:	movl 0x1f8(%esi), %eax
0x00520c5f:	pushl $0x59453c<UINT32>
0x00520c64:	pushl -28(%ebp)
0x00520c67:	call GetProcAddress@KERNEL32.DLL
0x00520c69:	movl 0x1fc(%esi), %eax
0x00520c6f:	movl 0x70(%esi), %edi
0x00520c72:	movb 0xc8(%esi), $0x43<UINT8>
0x00520c79:	movb 0x14b(%esi), $0x43<UINT8>
0x00520c80:	movl 0x68(%esi), $0x5becc8<UINT32>
0x00520c87:	pushl $0xd<UINT8>
0x00520c89:	call 0x005269fd
0x005269fd:	movl %edi, %edi
0x005269ff:	pushl %ebp
0x00526a00:	movl %ebp, %esp
0x00526a02:	movl %eax, 0x8(%ebp)
0x00526a05:	pushl %esi
0x00526a06:	leal %esi, 0x5bf490(,%eax,8)
0x00526a0d:	cmpl (%esi), $0x0<UINT8>
0x00526a10:	jne 0x00526a25
0x00526a25:	pushl (%esi)
0x00526a27:	call EnterCriticalSection@KERNEL32.DLL
EnterCriticalSection@KERNEL32.DLL: API Node	
0x00526a2d:	popl %esi
0x00526a2e:	popl %ebp
0x00526a2f:	ret

0x00520c8e:	popl %ecx
0x00520c8f:	andl -4(%ebp), $0x0<UINT8>
0x00520c93:	pushl 0x68(%esi)
0x00520c96:	call InterlockedIncrement@KERNEL32.DLL
InterlockedIncrement@KERNEL32.DLL: API Node	
0x00520c9c:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00520ca3:	call 0x00520ce6
0x00520ce6:	pushl $0xd<UINT8>
0x00520ce8:	call 0x00526923
0x00526923:	movl %edi, %edi
0x00526925:	pushl %ebp
0x00526926:	movl %ebp, %esp
0x00526928:	movl %eax, 0x8(%ebp)
0x0052692b:	pushl 0x5bf490(,%eax,8)
0x00526932:	call LeaveCriticalSection@KERNEL32.DLL
LeaveCriticalSection@KERNEL32.DLL: API Node	
0x00526938:	popl %ebp
0x00526939:	ret

0x00520ced:	popl %ecx
0x00520cee:	ret

0x00520ca8:	pushl $0xc<UINT8>
0x00520caa:	call 0x005269fd
0x00520caf:	popl %ecx
0x00520cb0:	movl -4(%ebp), %edi
0x00520cb3:	movl %eax, 0xc(%ebp)
0x00520cb6:	movl 0x6c(%esi), %eax
0x00520cb9:	testl %eax, %eax
0x00520cbb:	jne 8
0x00520cbd:	movl %eax, 0x5bf2d0
0x00520cc2:	movl 0x6c(%esi), %eax
0x00520cc5:	pushl 0x6c(%esi)
0x00520cc8:	call 0x00523b58
0x00523b58:	movl %edi, %edi
0x00523b5a:	pushl %ebp
0x00523b5b:	movl %ebp, %esp
0x00523b5d:	pushl %ebx
0x00523b5e:	pushl %esi
0x00523b5f:	movl %esi, 0x5421d4
0x00523b65:	pushl %edi
0x00523b66:	movl %edi, 0x8(%ebp)
0x00523b69:	pushl %edi
0x00523b6a:	call InterlockedIncrement@KERNEL32.DLL
0x00523b6c:	movl %eax, 0xb0(%edi)
0x00523b72:	testl %eax, %eax
0x00523b74:	je 0x00523b79
0x00523b79:	movl %eax, 0xb8(%edi)
0x00523b7f:	testl %eax, %eax
0x00523b81:	je 0x00523b86
0x00523b86:	movl %eax, 0xb4(%edi)
0x00523b8c:	testl %eax, %eax
0x00523b8e:	je 0x00523b93
0x00523b93:	movl %eax, 0xc0(%edi)
0x00523b99:	testl %eax, %eax
0x00523b9b:	je 0x00523ba0
0x00523ba0:	leal %ebx, 0x50(%edi)
0x00523ba3:	movl 0x8(%ebp), $0x6<UINT32>
0x00523baa:	cmpl -8(%ebx), $0x5bf1f0<UINT32>
0x00523bb1:	je 0x00523bbc
0x00523bb3:	movl %eax, (%ebx)
0x00523bb5:	testl %eax, %eax
0x00523bb7:	je 0x00523bbc
0x00523bbc:	cmpl -4(%ebx), $0x0<UINT8>
0x00523bc0:	je 0x00523bcc
0x00523bcc:	addl %ebx, $0x10<UINT8>
0x00523bcf:	decl 0x8(%ebp)
0x00523bd2:	jne 0x00523baa
0x00523bd4:	movl %eax, 0xd4(%edi)
0x00523bda:	addl %eax, $0xb4<UINT32>
0x00523bdf:	pushl %eax
0x00523be0:	call InterlockedIncrement@KERNEL32.DLL
0x00523be2:	popl %edi
0x00523be3:	popl %esi
0x00523be4:	popl %ebx
0x00523be5:	popl %ebp
0x00523be6:	ret

0x00520ccd:	popl %ecx
0x00520cce:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00520cd5:	call 0x00520cef
0x00520cef:	pushl $0xc<UINT8>
0x00520cf1:	call 0x00526923
0x00520cf6:	popl %ecx
0x00520cf7:	ret

0x00520cda:	call 0x00523181
0x00520cdf:	ret

0x0052102a:	popl %ecx
0x0052102b:	popl %ecx
0x0052102c:	call GetCurrentThreadId@KERNEL32.DLL
0x00521032:	orl 0x4(%esi), $0xffffffff<UINT8>
0x00521036:	movl (%esi), %eax
0x00521038:	xorl %eax, %eax
0x0052103a:	incl %eax
0x0052103b:	jmp 0x00521044
0x00521044:	popl %edi
0x00521045:	popl %esi
0x00521046:	ret

0x0051b318:	testl %eax, %eax
0x0051b31a:	jne 0x0051b324
0x0051b324:	call 0x00525307
0x00525307:	movl %edi, %edi
0x00525309:	pushl %esi
0x0052530a:	movl %eax, $0x5a0d54<UINT32>
0x0052530f:	movl %esi, $0x5a0d54<UINT32>
0x00525314:	pushl %edi
0x00525315:	movl %edi, %eax
0x00525317:	cmpl %eax, %esi
0x00525319:	jae 0x0052532a
0x0052532a:	popl %edi
0x0052532b:	popl %esi
0x0052532c:	ret

0x0051b329:	movl -4(%ebp), %ebx
0x0051b32c:	call 0x005250b3
0x005250b3:	pushl $0x54<UINT8>
0x005250b5:	pushl $0x5b91a0<UINT32>
0x005250ba:	call 0x0052313c
0x005250bf:	xorl %edi, %edi
0x005250c1:	movl -4(%ebp), %edi
0x005250c4:	leal %eax, -100(%ebp)
0x005250c7:	pushl %eax
0x005250c8:	call GetStartupInfoA@KERNEL32.DLL
0x005250ce:	movl -4(%ebp), $0xfffffffe<UINT32>
0x005250d5:	pushl $0x40<UINT8>
0x005250d7:	pushl $0x20<UINT8>
0x005250d9:	popl %esi
0x005250da:	pushl %esi
0x005250db:	call 0x00526a75
0x005250e0:	popl %ecx
0x005250e1:	popl %ecx
0x005250e2:	cmpl %eax, %edi
0x005250e4:	je 532
0x005250ea:	movl 0x5c0d00, %eax
0x005250ef:	movl 0x5c0ce8, %esi
0x005250f5:	leal %ecx, 0x800(%eax)
0x005250fb:	jmp 0x0052512d
0x0052512d:	cmpl %eax, %ecx
0x0052512f:	jb 0x005250fd
0x005250fd:	movb 0x4(%eax), $0x0<UINT8>
0x00525101:	orl (%eax), $0xffffffff<UINT8>
0x00525104:	movb 0x5(%eax), $0xa<UINT8>
0x00525108:	movl 0x8(%eax), %edi
0x0052510b:	movb 0x24(%eax), $0x0<UINT8>
0x0052510f:	movb 0x25(%eax), $0xa<UINT8>
0x00525113:	movb 0x26(%eax), $0xa<UINT8>
0x00525117:	movl 0x38(%eax), %edi
0x0052511a:	movb 0x34(%eax), $0x0<UINT8>
0x0052511e:	addl %eax, $0x40<UINT8>
0x00525121:	movl %ecx, 0x5c0d00
0x00525127:	addl %ecx, $0x800<UINT32>
0x00525131:	cmpw -50(%ebp), %di
0x00525135:	je 266
0x0052513b:	movl %eax, -48(%ebp)
0x0052513e:	cmpl %eax, %edi
0x00525140:	je 255
0x00525146:	movl %edi, (%eax)
0x00525148:	leal %ebx, 0x4(%eax)
0x0052514b:	leal %eax, (%ebx,%edi)
0x0052514e:	movl -28(%ebp), %eax
0x00525151:	movl %esi, $0x800<UINT32>
0x00525156:	cmpl %edi, %esi
0x00525158:	jl 0x0052515c
0x0052515c:	movl -32(%ebp), $0x1<UINT32>
0x00525163:	jmp 0x005251c0
0x005251c0:	cmpl 0x5c0ce8, %edi
0x005251c6:	jl -99
0x005251c8:	jmp 0x005251d0
0x005251d0:	andl -32(%ebp), $0x0<UINT8>
0x005251d4:	testl %edi, %edi
0x005251d6:	jle 0x00525245
0x00525245:	xorl %ebx, %ebx
0x00525247:	movl %esi, %ebx
0x00525249:	shll %esi, $0x6<UINT8>
0x0052524c:	addl %esi, 0x5c0d00
0x00525252:	movl %eax, (%esi)
0x00525254:	cmpl %eax, $0xffffffff<UINT8>
0x00525257:	je 0x00525264
0x00525264:	movb 0x4(%esi), $0xffffff81<UINT8>
0x00525268:	testl %ebx, %ebx
0x0052526a:	jne 0x00525271
0x0052526c:	pushl $0xfffffff6<UINT8>
0x0052526e:	popl %eax
0x0052526f:	jmp 0x0052527b
0x0052527b:	pushl %eax
0x0052527c:	call GetStdHandle@KERNEL32.DLL
GetStdHandle@KERNEL32.DLL: API Node	
0x00525282:	movl %edi, %eax
0x00525284:	cmpl %edi, $0xffffffff<UINT8>
0x00525287:	je 67
0x00525289:	testl %edi, %edi
0x0052528b:	je 63
0x0052528d:	pushl %edi
0x0052528e:	call GetFileType@KERNEL32.DLL
GetFileType@KERNEL32.DLL: API Node	
0x00525294:	testl %eax, %eax
0x00525296:	je 52
0x00525298:	movl (%esi), %edi
0x0052529a:	andl %eax, $0xff<UINT32>
0x0052529f:	cmpl %eax, $0x2<UINT8>
0x005252a2:	jne 6
0x005252a4:	orb 0x4(%esi), $0x40<UINT8>
0x005252a8:	jmp 0x005252b3
0x005252b3:	pushl $0xfa0<UINT32>
0x005252b8:	leal %eax, 0xc(%esi)
0x005252bb:	pushl %eax
0x005252bc:	call 0x0052ccaa
0x005252c1:	popl %ecx
0x005252c2:	popl %ecx
0x005252c3:	testl %eax, %eax
0x005252c5:	je 55
0x005252c7:	incl 0x8(%esi)
0x005252ca:	jmp 0x005252d6
0x005252d6:	incl %ebx
0x005252d7:	cmpl %ebx, $0x3<UINT8>
0x005252da:	jl 0x00525247
0x00525271:	movl %eax, %ebx
0x00525273:	decl %eax
0x00525274:	negl %eax
0x00525276:	sbbl %eax, %eax
0x00525278:	addl %eax, $0xfffffff5<UINT8>
0x005252e0:	pushl 0x5c0ce8
0x005252e6:	call SetHandleCount@KERNEL32.DLL
SetHandleCount@KERNEL32.DLL: API Node	
0x005252ec:	xorl %eax, %eax
0x005252ee:	jmp 0x00525301
0x00525301:	call 0x00523181
0x00525306:	ret

0x0051b331:	testl %eax, %eax
0x0051b333:	jnl 0x0051b33d
0x0051b33d:	call GetCommandLineA@KERNEL32.DLL
GetCommandLineA@KERNEL32.DLL: API Node	
0x0051b343:	movl 0x5c1e24, %eax
0x0051b348:	call 0x00524f7c
0x00524f7c:	movl %edi, %edi
0x00524f7e:	pushl %ebp
0x00524f7f:	movl %ebp, %esp
0x00524f81:	movl %eax, 0x5c0a30
0x00524f86:	subl %esp, $0xc<UINT8>
0x00524f89:	pushl %ebx
0x00524f8a:	pushl %esi
0x00524f8b:	movl %esi, 0x5422c0
0x00524f91:	pushl %edi
0x00524f92:	xorl %ebx, %ebx
0x00524f94:	xorl %edi, %edi
0x00524f96:	cmpl %eax, %ebx
0x00524f98:	jne 46
0x00524f9a:	call GetEnvironmentStringsW@KERNEL32.DLL
GetEnvironmentStringsW@KERNEL32.DLL: API Node	
0x00524f9c:	movl %edi, %eax
0x00524f9e:	cmpl %edi, %ebx
0x00524fa0:	je 12
0x00524fa2:	movl 0x5c0a30, $0x1<UINT32>
0x00524fac:	jmp 0x00524fd1
0x00524fd1:	cmpl %edi, %ebx
0x00524fd3:	jne 0x00524fe4
0x00524fe4:	movl %eax, %edi
0x00524fe6:	cmpw (%edi), %bx
0x00524fe9:	je 14
0x00524feb:	incl %eax
0x00524fec:	incl %eax
0x00524fed:	cmpw (%eax), %bx
0x00524ff0:	jne 0x00524feb
0x00524ff2:	incl %eax
0x00524ff3:	incl %eax
0x00524ff4:	cmpw (%eax), %bx
0x00524ff7:	jne 0x00524feb
0x00524ff9:	movl %esi, 0x542230
0x00524fff:	pushl %ebx
0x00525000:	pushl %ebx
0x00525001:	pushl %ebx
0x00525002:	subl %eax, %edi
0x00525004:	pushl %ebx
0x00525005:	sarl %eax
0x00525007:	incl %eax
0x00525008:	pushl %eax
0x00525009:	pushl %edi
0x0052500a:	pushl %ebx
0x0052500b:	pushl %ebx
0x0052500c:	movl -12(%ebp), %eax
0x0052500f:	call WideCharToMultiByte@KERNEL32.DLL
WideCharToMultiByte@KERNEL32.DLL: API Node	
0x00525011:	movl -8(%ebp), %eax
0x00525014:	cmpl %eax, %ebx
0x00525016:	je 47
0x00525018:	pushl %eax
0x00525019:	call 0x00526a30
0x00526a30:	movl %edi, %edi
0x00526a32:	pushl %ebp
0x00526a33:	movl %ebp, %esp
0x00526a35:	pushl %esi
0x00526a36:	pushl %edi
0x00526a37:	xorl %esi, %esi
0x00526a39:	pushl 0x8(%ebp)
0x00526a3c:	call 0x0051c822
0x0051c822:	movl %edi, %edi
0x0051c824:	pushl %ebp
0x0051c825:	movl %ebp, %esp
0x0051c827:	pushl %esi
0x0051c828:	movl %esi, 0x8(%ebp)
0x0051c82b:	cmpl %esi, $0xffffffe0<UINT8>
0x0051c82e:	ja 161
0x0051c834:	pushl %ebx
0x0051c835:	pushl %edi
0x0051c836:	movl %edi, 0x542244
0x0051c83c:	cmpl 0x5c0a34, $0x0<UINT8>
0x0051c843:	jne 0x0051c85d
0x0051c85d:	movl %eax, 0x5c0ce4
0x0051c862:	cmpl %eax, $0x1<UINT8>
0x0051c865:	jne 14
0x0051c867:	testl %esi, %esi
0x0051c869:	je 0x0051c86f
0x0051c86b:	movl %eax, %esi
0x0051c86d:	jmp 0x0051c872
0x0051c872:	pushl %eax
0x0051c873:	jmp 0x0051c891
0x0051c891:	pushl $0x0<UINT8>
0x0051c893:	pushl 0x5c0a34
0x0051c899:	call HeapAlloc@KERNEL32.DLL
0x0051c89b:	movl %ebx, %eax
0x0051c89d:	testl %ebx, %ebx
0x0051c89f:	jne 0x0051c8cf
0x0051c8cf:	popl %edi
0x0051c8d0:	movl %eax, %ebx
0x0051c8d2:	popl %ebx
0x0051c8d3:	jmp 0x0051c8e9
0x0051c8e9:	popl %esi
0x0051c8ea:	popl %ebp
0x0051c8eb:	ret

0x00526a41:	movl %edi, %eax
0x00526a43:	popl %ecx
0x00526a44:	testl %edi, %edi
0x00526a46:	jne 0x00526a6f
0x00526a6f:	movl %eax, %edi
0x00526a71:	popl %edi
0x00526a72:	popl %esi
0x00526a73:	popl %ebp
0x00526a74:	ret

0x0052501e:	popl %ecx
0x0052501f:	movl -4(%ebp), %eax
0x00525022:	cmpl %eax, %ebx
0x00525024:	je 33
0x00525026:	pushl %ebx
0x00525027:	pushl %ebx
0x00525028:	pushl -8(%ebp)
0x0052502b:	pushl %eax
0x0052502c:	pushl -12(%ebp)
0x0052502f:	pushl %edi
0x00525030:	pushl %ebx
0x00525031:	pushl %ebx
0x00525032:	call WideCharToMultiByte@KERNEL32.DLL
0x00525034:	testl %eax, %eax
0x00525036:	jne 0x00525044
0x00525044:	movl %ebx, -4(%ebp)
0x00525047:	pushl %edi
0x00525048:	call FreeEnvironmentStringsW@KERNEL32.DLL
FreeEnvironmentStringsW@KERNEL32.DLL: API Node	
0x0052504e:	movl %eax, %ebx
0x00525050:	jmp 0x005250ae
0x005250ae:	popl %edi
0x005250af:	popl %esi
0x005250b0:	popl %ebx
0x005250b1:	leave
0x005250b2:	ret

0x0051b34d:	movl 0x5c0214, %eax
0x0051b352:	call 0x00524ec1
0x00524ec1:	movl %edi, %edi
0x00524ec3:	pushl %ebp
0x00524ec4:	movl %ebp, %esp
0x00524ec6:	subl %esp, $0xc<UINT8>
0x00524ec9:	pushl %ebx
0x00524eca:	xorl %ebx, %ebx
0x00524ecc:	pushl %esi
0x00524ecd:	pushl %edi
0x00524ece:	cmpl 0x5c0e0c, %ebx
0x00524ed4:	jne 5
0x00524ed6:	call 0x005239f1
0x005239f1:	cmpl 0x5c0e0c, $0x0<UINT8>
0x005239f8:	jne 0x00523a0c
0x005239fa:	pushl $0xfffffffd<UINT8>
0x005239fc:	call 0x00523857
0x00523857:	pushl $0x14<UINT8>
0x00523859:	pushl $0x5b9120<UINT32>
0x0052385e:	call 0x0052313c
0x00523863:	orl -32(%ebp), $0xffffffff<UINT8>
0x00523867:	call 0x00520d71
0x00520d71:	movl %edi, %edi
0x00520d73:	pushl %esi
0x00520d74:	call 0x00520cf8
0x00520cf8:	movl %edi, %edi
0x00520cfa:	pushl %esi
0x00520cfb:	pushl %edi
0x00520cfc:	call GetLastError@KERNEL32.DLL
GetLastError@KERNEL32.DLL: API Node	
0x00520d02:	pushl 0x5bec84
0x00520d08:	movl %edi, %eax
0x00520d0a:	call 0x00520ba0
0x00520ba0:	movl %edi, %edi
0x00520ba2:	pushl %esi
0x00520ba3:	pushl 0x5bec88
0x00520ba9:	call TlsGetValue@KERNEL32.DLL
0x00520baf:	movl %esi, %eax
0x00520bb1:	testl %esi, %esi
0x00520bb3:	jne 0x00520bd0
0x00520bd0:	movl %eax, %esi
0x00520bd2:	popl %esi
0x00520bd3:	ret

0x00520d0f:	call FlsGetValue@KERNEL32.DLL
0x00520d11:	movl %esi, %eax
0x00520d13:	testl %esi, %esi
0x00520d15:	jne 0x00520d65
0x00520d65:	pushl %edi
0x00520d66:	call SetLastError@KERNEL32.DLL
SetLastError@KERNEL32.DLL: API Node	
0x00520d6c:	popl %edi
0x00520d6d:	movl %eax, %esi
0x00520d6f:	popl %esi
0x00520d70:	ret

0x00520d79:	movl %esi, %eax
0x00520d7b:	testl %esi, %esi
0x00520d7d:	jne 0x00520d87
0x00520d87:	movl %eax, %esi
0x00520d89:	popl %esi
0x00520d8a:	ret

0x0052386c:	movl %edi, %eax
0x0052386e:	movl -36(%ebp), %edi
0x00523871:	call 0x00523552
0x00523552:	pushl $0xc<UINT8>
0x00523554:	pushl $0x5b9100<UINT32>
0x00523559:	call 0x0052313c
0x0052355e:	call 0x00520d71
0x00523563:	movl %edi, %eax
0x00523565:	movl %eax, 0x5bf1ec
0x0052356a:	testl 0x70(%edi), %eax
0x0052356d:	je 0x0052358c
0x0052358c:	pushl $0xd<UINT8>
0x0052358e:	call 0x005269fd
0x00523593:	popl %ecx
0x00523594:	andl -4(%ebp), $0x0<UINT8>
0x00523598:	movl %esi, 0x68(%edi)
0x0052359b:	movl -28(%ebp), %esi
0x0052359e:	cmpl %esi, 0x5bf0f0
0x005235a4:	je 0x005235dc
0x005235dc:	movl -4(%ebp), $0xfffffffe<UINT32>
0x005235e3:	call 0x005235ed
0x005235ed:	pushl $0xd<UINT8>
0x005235ef:	call 0x00526923
0x005235f4:	popl %ecx
0x005235f5:	ret

0x005235e8:	jmp 0x00523578
0x00523578:	testl %esi, %esi
0x0052357a:	jne 0x00523584
0x00523584:	movl %eax, %esi
0x00523586:	call 0x00523181
0x0052358b:	ret

0x00523876:	movl %ebx, 0x68(%edi)
0x00523879:	movl %esi, 0x8(%ebp)
0x0052387c:	call 0x005235f6
0x005235f6:	movl %edi, %edi
0x005235f8:	pushl %ebp
0x005235f9:	movl %ebp, %esp
0x005235fb:	subl %esp, $0x10<UINT8>
0x005235fe:	pushl %ebx
0x005235ff:	xorl %ebx, %ebx
0x00523601:	pushl %ebx
0x00523602:	leal %ecx, -16(%ebp)
0x00523605:	call 0x0051ac40
0x0051ac40:	movl %edi, %edi
0x0051ac42:	pushl %ebp
0x0051ac43:	movl %ebp, %esp
0x0051ac45:	movl %eax, 0x8(%ebp)
0x0051ac48:	pushl %esi
0x0051ac49:	movl %esi, %ecx
0x0051ac4b:	movb 0xc(%esi), $0x0<UINT8>
0x0051ac4f:	testl %eax, %eax
0x0051ac51:	jne 99
0x0051ac53:	call 0x00520d71
0x0051ac58:	movl 0x8(%esi), %eax
0x0051ac5b:	movl %ecx, 0x6c(%eax)
0x0051ac5e:	movl (%esi), %ecx
0x0051ac60:	movl %ecx, 0x68(%eax)
0x0051ac63:	movl 0x4(%esi), %ecx
0x0051ac66:	movl %ecx, (%esi)
0x0051ac68:	cmpl %ecx, 0x5bf2d0
0x0051ac6e:	je 0x0051ac82
0x0051ac82:	movl %eax, 0x4(%esi)
0x0051ac85:	cmpl %eax, 0x5bf0f0
0x0051ac8b:	je 0x0051aca3
0x0051aca3:	movl %eax, 0x8(%esi)
0x0051aca6:	testb 0x70(%eax), $0x2<UINT8>
0x0051acaa:	jne 20
0x0051acac:	orl 0x70(%eax), $0x2<UINT8>
0x0051acb0:	movb 0xc(%esi), $0x1<UINT8>
0x0051acb4:	jmp 0x0051acc0
0x0051acc0:	movl %eax, %esi
0x0051acc2:	popl %esi
0x0051acc3:	popl %ebp
0x0051acc4:	ret $0x4<UINT16>

0x0052360a:	movl 0x5c0574, %ebx
0x00523610:	cmpl %esi, $0xfffffffe<UINT8>
0x00523613:	jne 0x00523633
0x00523633:	cmpl %esi, $0xfffffffd<UINT8>
0x00523636:	jne 0x0052364a
0x00523638:	movl 0x5c0574, $0x1<UINT32>
0x00523642:	call GetACP@KERNEL32.DLL
GetACP@KERNEL32.DLL: API Node	
0x00523648:	jmp 0x00523625
0x00523625:	cmpb -4(%ebp), %bl
0x00523628:	je 69
0x0052362a:	movl %ecx, -8(%ebp)
0x0052362d:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00523631:	jmp 0x0052366f
0x0052366f:	popl %ebx
0x00523670:	leave
0x00523671:	ret

0x00523881:	movl 0x8(%ebp), %eax
0x00523884:	cmpl %eax, 0x4(%ebx)
0x00523887:	je 343
0x0052388d:	pushl $0x220<UINT32>
0x00523892:	call 0x00526a30
0x00523897:	popl %ecx
0x00523898:	movl %ebx, %eax
0x0052389a:	testl %ebx, %ebx
0x0052389c:	je 326
0x005238a2:	movl %ecx, $0x88<UINT32>
0x005238a7:	movl %esi, 0x68(%edi)
0x005238aa:	movl %edi, %ebx
0x005238ac:	rep movsl %es:(%edi), %ds:(%esi)
0x005238ae:	andl (%ebx), $0x0<UINT8>
0x005238b1:	pushl %ebx
0x005238b2:	pushl 0x8(%ebp)
0x005238b5:	call 0x00523672
0x00523672:	movl %edi, %edi
0x00523674:	pushl %ebp
0x00523675:	movl %ebp, %esp
0x00523677:	subl %esp, $0x20<UINT8>
0x0052367a:	movl %eax, 0x5be7b0
0x0052367f:	xorl %eax, %ebp
0x00523681:	movl -4(%ebp), %eax
0x00523684:	pushl %ebx
0x00523685:	movl %ebx, 0xc(%ebp)
0x00523688:	pushl %esi
0x00523689:	movl %esi, 0x8(%ebp)
0x0052368c:	pushl %edi
0x0052368d:	call 0x005235f6
0x0052364a:	cmpl %esi, $0xfffffffc<UINT8>
0x0052364d:	jne 0x00523661
0x00523661:	cmpb -4(%ebp), %bl
0x00523664:	je 7
0x00523666:	movl %eax, -8(%ebp)
0x00523669:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x0052366d:	movl %eax, %esi
0x00523692:	movl %edi, %eax
0x00523694:	xorl %esi, %esi
0x00523696:	movl 0x8(%ebp), %edi
0x00523699:	cmpl %edi, %esi
0x0052369b:	jne 0x005236ab
0x005236ab:	movl -28(%ebp), %esi
0x005236ae:	xorl %eax, %eax
0x005236b0:	cmpl 0x5bf0f8(%eax), %edi
0x005236b6:	je 145
0x005236bc:	incl -28(%ebp)
0x005236bf:	addl %eax, $0x30<UINT8>
0x005236c2:	cmpl %eax, $0xf0<UINT32>
0x005236c7:	jb 0x005236b0
0x005236c9:	cmpl %edi, $0xfde8<UINT32>
0x005236cf:	je 368
0x005236d5:	cmpl %edi, $0xfde9<UINT32>
0x005236db:	je 356
0x005236e1:	movzwl %eax, %di
0x005236e4:	pushl %eax
0x005236e5:	call IsValidCodePage@KERNEL32.DLL
IsValidCodePage@KERNEL32.DLL: API Node	
0x005236eb:	testl %eax, %eax
0x005236ed:	je 338
0x005236f3:	leal %eax, -24(%ebp)
0x005236f6:	pushl %eax
0x005236f7:	pushl %edi
0x005236f8:	call GetCPInfo@KERNEL32.DLL
GetCPInfo@KERNEL32.DLL: API Node	
0x005236fe:	testl %eax, %eax
0x00523700:	je 307
0x00523706:	pushl $0x101<UINT32>
0x0052370b:	leal %eax, 0x1c(%ebx)
0x0052370e:	pushl %esi
0x0052370f:	pushl %eax
0x00523710:	call 0x0051a4f0
0x0051a4f0:	movl %edx, 0xc(%esp)
0x0051a4f4:	movl %ecx, 0x4(%esp)
0x0051a4f8:	testl %edx, %edx
0x0051a4fa:	je 0x0051a565
0x0051a4fc:	xorl %eax, %eax
0x0051a4fe:	movb %al, 0x8(%esp)
0x0051a502:	testb %al, %al
0x0051a504:	jne 0x0051a51c
0x0051a506:	cmpl %edx, $0x100<UINT32>
0x0051a50c:	jb 0x0051a51c
0x0051a50e:	cmpl 0x5c0e18, $0x0<UINT8>
0x0051a515:	je 0x0051a51c
0x0051a51c:	pushl %edi
0x0051a51d:	movl %edi, %ecx
0x0051a51f:	cmpl %edx, $0x4<UINT8>
0x0051a522:	jb 0x0051a555
0x0051a524:	negl %ecx
0x0051a526:	andl %ecx, $0x3<UINT8>
0x0051a529:	je 0x0051a537
0x0051a537:	movl %ecx, %eax
0x0051a539:	shll %eax, $0x8<UINT8>
0x0051a53c:	addl %eax, %ecx
0x0051a53e:	movl %ecx, %eax
0x0051a540:	shll %eax, $0x10<UINT8>
0x0051a543:	addl %eax, %ecx
0x0051a545:	movl %ecx, %edx
0x0051a547:	andl %edx, $0x3<UINT8>
0x0051a54a:	shrl %ecx, $0x2<UINT8>
0x0051a54d:	je 6
0x0051a54f:	rep stosl %es:(%edi), %eax
0x0051a551:	testl %edx, %edx
0x0051a553:	je 0x0051a55f
0x0051a555:	movb (%edi), %al
0x0051a557:	addl %edi, $0x1<UINT8>
0x0051a55a:	subl %edx, $0x1<UINT8>
0x0051a55d:	jne 0x0051a555
0x0051a55f:	movl %eax, 0x8(%esp)
0x0051a563:	popl %edi
0x0051a564:	ret

0x00523715:	xorl %edx, %edx
0x00523717:	incl %edx
0x00523718:	addl %esp, $0xc<UINT8>
0x0052371b:	movl 0x4(%ebx), %edi
0x0052371e:	movl 0xc(%ebx), %esi
0x00523721:	cmpl -24(%ebp), %edx
0x00523724:	jbe 248
0x0052372a:	cmpb -18(%ebp), $0x0<UINT8>
0x0052372e:	je 0x00523803
0x00523803:	leal %eax, 0x1e(%ebx)
0x00523806:	movl %ecx, $0xfe<UINT32>
0x0052380b:	orb (%eax), $0x8<UINT8>
0x0052380e:	incl %eax
0x0052380f:	decl %ecx
0x00523810:	jne 0x0052380b
0x00523812:	movl %eax, 0x4(%ebx)
0x00523815:	call 0x0052332c
0x0052332c:	subl %eax, $0x3a4<UINT32>
0x00523331:	je 34
0x00523333:	subl %eax, $0x4<UINT8>
0x00523336:	je 23
0x00523338:	subl %eax, $0xd<UINT8>
0x0052333b:	je 12
0x0052333d:	decl %eax
0x0052333e:	je 3
0x00523340:	xorl %eax, %eax
0x00523342:	ret

0x0052381a:	movl 0xc(%ebx), %eax
0x0052381d:	movl 0x8(%ebx), %edx
0x00523820:	jmp 0x00523825
0x00523825:	xorl %eax, %eax
0x00523827:	movzwl %ecx, %ax
0x0052382a:	movl %eax, %ecx
0x0052382c:	shll %ecx, $0x10<UINT8>
0x0052382f:	orl %eax, %ecx
0x00523831:	leal %edi, 0x10(%ebx)
0x00523834:	stosl %es:(%edi), %eax
0x00523835:	stosl %es:(%edi), %eax
0x00523836:	stosl %es:(%edi), %eax
0x00523837:	jmp 0x005237e1
0x005237e1:	movl %esi, %ebx
0x005237e3:	call 0x005233bf
0x005233bf:	movl %edi, %edi
0x005233c1:	pushl %ebp
0x005233c2:	movl %ebp, %esp
0x005233c4:	subl %esp, $0x51c<UINT32>
0x005233ca:	movl %eax, 0x5be7b0
0x005233cf:	xorl %eax, %ebp
0x005233d1:	movl -4(%ebp), %eax
0x005233d4:	pushl %ebx
0x005233d5:	pushl %edi
0x005233d6:	leal %eax, -1304(%ebp)
0x005233dc:	pushl %eax
0x005233dd:	pushl 0x4(%esi)
0x005233e0:	call GetCPInfo@KERNEL32.DLL
0x005233e6:	movl %edi, $0x100<UINT32>
0x005233eb:	testl %eax, %eax
0x005233ed:	je 251
0x005233f3:	xorl %eax, %eax
0x005233f5:	movb -260(%ebp,%eax), %al
0x005233fc:	incl %eax
0x005233fd:	cmpl %eax, %edi
0x005233ff:	jb 0x005233f5
0x00523401:	movb %al, -1298(%ebp)
0x00523407:	movb -260(%ebp), $0x20<UINT8>
0x0052340e:	testb %al, %al
0x00523410:	je 0x00523440
0x00523440:	pushl $0x0<UINT8>
0x00523442:	pushl 0xc(%esi)
0x00523445:	leal %eax, -1284(%ebp)
0x0052344b:	pushl 0x4(%esi)
0x0052344e:	pushl %eax
0x0052344f:	pushl %edi
0x00523450:	leal %eax, -260(%ebp)
0x00523456:	pushl %eax
0x00523457:	pushl $0x1<UINT8>
0x00523459:	pushl $0x0<UINT8>
0x0052345b:	call 0x0052bbe7
0x0052bbe7:	movl %edi, %edi
0x0052bbe9:	pushl %ebp
0x0052bbea:	movl %ebp, %esp
0x0052bbec:	subl %esp, $0x10<UINT8>
0x0052bbef:	pushl 0x8(%ebp)
0x0052bbf2:	leal %ecx, -16(%ebp)
0x0052bbf5:	call 0x0051ac40
0x0052bbfa:	pushl 0x24(%ebp)
0x0052bbfd:	leal %ecx, -16(%ebp)
0x0052bc00:	pushl 0x20(%ebp)
0x0052bc03:	pushl 0x1c(%ebp)
0x0052bc06:	pushl 0x18(%ebp)
0x0052bc09:	pushl 0x14(%ebp)
0x0052bc0c:	pushl 0x10(%ebp)
0x0052bc0f:	pushl 0xc(%ebp)
0x0052bc12:	call 0x0052ba2d
0x0052ba2d:	movl %edi, %edi
0x0052ba2f:	pushl %ebp
0x0052ba30:	movl %ebp, %esp
0x0052ba32:	pushl %ecx
0x0052ba33:	pushl %ecx
0x0052ba34:	movl %eax, 0x5be7b0
0x0052ba39:	xorl %eax, %ebp
0x0052ba3b:	movl -4(%ebp), %eax
0x0052ba3e:	movl %eax, 0x5c0be0
0x0052ba43:	pushl %ebx
0x0052ba44:	pushl %esi
0x0052ba45:	xorl %ebx, %ebx
0x0052ba47:	pushl %edi
0x0052ba48:	movl %edi, %ecx
0x0052ba4a:	cmpl %eax, %ebx
0x0052ba4c:	jne 58
0x0052ba4e:	leal %eax, -8(%ebp)
0x0052ba51:	pushl %eax
0x0052ba52:	xorl %esi, %esi
0x0052ba54:	incl %esi
0x0052ba55:	pushl %esi
0x0052ba56:	pushl $0x594c88<UINT32>
0x0052ba5b:	pushl %esi
0x0052ba5c:	call GetStringTypeW@KERNEL32.DLL
GetStringTypeW@KERNEL32.DLL: API Node	
0x0052ba62:	testl %eax, %eax
0x0052ba64:	je 8
0x0052ba66:	movl 0x5c0be0, %esi
0x0052ba6c:	jmp 0x0052baa2
0x0052baa2:	movl -8(%ebp), %ebx
0x0052baa5:	cmpl 0x18(%ebp), %ebx
0x0052baa8:	jne 0x0052bab2
0x0052bab2:	movl %esi, 0x542214
0x0052bab8:	xorl %eax, %eax
0x0052baba:	cmpl 0x20(%ebp), %ebx
0x0052babd:	pushl %ebx
0x0052babe:	pushl %ebx
0x0052babf:	pushl 0x10(%ebp)
0x0052bac2:	setne %al
0x0052bac5:	pushl 0xc(%ebp)
0x0052bac8:	leal %eax, 0x1(,%eax,8)
0x0052bacf:	pushl %eax
0x0052bad0:	pushl 0x18(%ebp)
0x0052bad3:	call MultiByteToWideChar@KERNEL32.DLL
MultiByteToWideChar@KERNEL32.DLL: API Node	
0x0052bad5:	movl %edi, %eax
0x0052bad7:	cmpl %edi, %ebx
0x0052bad9:	je 171
0x0052badf:	jle 60
0x0052bae1:	cmpl %edi, $0x7ffffff0<UINT32>
0x0052bae7:	ja 52
0x0052bae9:	leal %eax, 0x8(%edi,%edi)
0x0052baed:	cmpl %eax, $0x400<UINT32>
0x0052baf2:	ja 19
0x0052baf4:	call 0x0052cf10
0x0052cf10:	pushl %ecx
0x0052cf11:	leal %ecx, 0x8(%esp)
0x0052cf15:	subl %ecx, %eax
0x0052cf17:	andl %ecx, $0xf<UINT8>
0x0052cf1a:	addl %eax, %ecx
0x0052cf1c:	sbbl %ecx, %ecx
0x0052cf1e:	orl %eax, %ecx
0x0052cf20:	popl %ecx
0x0052cf21:	jmp 0x0051aa40
0x0051aa40:	pushl %ecx
0x0051aa41:	leal %ecx, 0x4(%esp)
0x0051aa45:	subl %ecx, %eax
0x0051aa47:	sbbl %eax, %eax
0x0051aa49:	notl %eax
0x0051aa4b:	andl %ecx, %eax
0x0051aa4d:	movl %eax, %esp
0x0051aa4f:	andl %eax, $0xfffff000<UINT32>
0x0051aa54:	cmpl %ecx, %eax
0x0051aa56:	jb 10
0x0051aa58:	movl %eax, %ecx
0x0051aa5a:	popl %ecx
0x0051aa5b:	xchgl %esp, %eax
0x0051aa5c:	movl %eax, (%eax)
0x0051aa5e:	movl (%esp), %eax
0x0051aa61:	ret

0x0052baf9:	movl %eax, %esp
0x0052bafb:	cmpl %eax, %ebx
0x0052bafd:	je 28
0x0052baff:	movl (%eax), $0xcccc<UINT32>
0x0052bb05:	jmp 0x0052bb18
0x0052bb18:	addl %eax, $0x8<UINT8>
0x0052bb1b:	movl %ebx, %eax
0x0052bb1d:	testl %ebx, %ebx
0x0052bb1f:	je 105
0x0052bb21:	leal %eax, (%edi,%edi)
0x0052bb24:	pushl %eax
0x0052bb25:	pushl $0x0<UINT8>
0x0052bb27:	pushl %ebx
0x0052bb28:	call 0x0051a4f0
0x0052bb2d:	addl %esp, $0xc<UINT8>
0x0052bb30:	pushl %edi
0x0052bb31:	pushl %ebx
0x0052bb32:	pushl 0x10(%ebp)
0x0052bb35:	pushl 0xc(%ebp)
0x0052bb38:	pushl $0x1<UINT8>
0x0052bb3a:	pushl 0x18(%ebp)
0x0052bb3d:	call MultiByteToWideChar@KERNEL32.DLL
0x0052bb3f:	testl %eax, %eax
0x0052bb41:	je 17
0x0052bb43:	pushl 0x14(%ebp)
0x0052bb46:	pushl %eax
0x0052bb47:	pushl %ebx
0x0052bb48:	pushl 0x8(%ebp)
0x0052bb4b:	call GetStringTypeW@KERNEL32.DLL
0x0052bb51:	movl -8(%ebp), %eax
0x0052bb54:	pushl %ebx
0x0052bb55:	call 0x005245e4
0x005245e4:	movl %edi, %edi
0x005245e6:	pushl %ebp
0x005245e7:	movl %ebp, %esp
0x005245e9:	movl %eax, 0x8(%ebp)
0x005245ec:	testl %eax, %eax
0x005245ee:	je 18
0x005245f0:	subl %eax, $0x8<UINT8>
0x005245f3:	cmpl (%eax), $0xdddd<UINT32>
0x005245f9:	jne 0x00524602
0x00524602:	popl %ebp
0x00524603:	ret

0x0052bb5a:	movl %eax, -8(%ebp)
0x0052bb5d:	popl %ecx
0x0052bb5e:	jmp 0x0052bbd5
0x0052bbd5:	leal %esp, -20(%ebp)
0x0052bbd8:	popl %edi
0x0052bbd9:	popl %esi
0x0052bbda:	popl %ebx
0x0052bbdb:	movl %ecx, -4(%ebp)
0x0052bbde:	xorl %ecx, %ebp
0x0052bbe0:	call 0x0051a2f8
0x0051a2f8:	cmpl %ecx, 0x5be7b0
0x0051a2fe:	jne 2
0x0051a300:	rep ret

0x0052bbe5:	leave
0x0052bbe6:	ret

0x0052bc17:	addl %esp, $0x1c<UINT8>
0x0052bc1a:	cmpb -4(%ebp), $0x0<UINT8>
0x0052bc1e:	je 7
0x0052bc20:	movl %ecx, -8(%ebp)
0x0052bc23:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0052bc27:	leave
0x0052bc28:	ret

0x00523460:	xorl %ebx, %ebx
0x00523462:	pushl %ebx
0x00523463:	pushl 0x4(%esi)
0x00523466:	leal %eax, -516(%ebp)
0x0052346c:	pushl %edi
0x0052346d:	pushl %eax
0x0052346e:	pushl %edi
0x0052346f:	leal %eax, -260(%ebp)
0x00523475:	pushl %eax
0x00523476:	pushl %edi
0x00523477:	pushl 0xc(%esi)
0x0052347a:	pushl %ebx
0x0052347b:	call 0x005249a9
0x005249a9:	movl %edi, %edi
0x005249ab:	pushl %ebp
0x005249ac:	movl %ebp, %esp
0x005249ae:	subl %esp, $0x10<UINT8>
0x005249b1:	pushl 0x8(%ebp)
0x005249b4:	leal %ecx, -16(%ebp)
0x005249b7:	call 0x0051ac40
0x005249bc:	pushl 0x28(%ebp)
0x005249bf:	leal %ecx, -16(%ebp)
0x005249c2:	pushl 0x24(%ebp)
0x005249c5:	pushl 0x20(%ebp)
0x005249c8:	pushl 0x1c(%ebp)
0x005249cb:	pushl 0x18(%ebp)
0x005249ce:	pushl 0x14(%ebp)
0x005249d1:	pushl 0x10(%ebp)
0x005249d4:	pushl 0xc(%ebp)
0x005249d7:	call 0x00524604
0x00524604:	movl %edi, %edi
0x00524606:	pushl %ebp
0x00524607:	movl %ebp, %esp
0x00524609:	subl %esp, $0x14<UINT8>
0x0052460c:	movl %eax, 0x5be7b0
0x00524611:	xorl %eax, %ebp
0x00524613:	movl -4(%ebp), %eax
0x00524616:	pushl %ebx
0x00524617:	pushl %esi
0x00524618:	xorl %ebx, %ebx
0x0052461a:	pushl %edi
0x0052461b:	movl %esi, %ecx
0x0052461d:	cmpl 0x5c0920, %ebx
0x00524623:	jne 0x0052465d
0x00524625:	pushl %ebx
0x00524626:	pushl %ebx
0x00524627:	xorl %edi, %edi
0x00524629:	incl %edi
0x0052462a:	pushl %edi
0x0052462b:	pushl $0x594c88<UINT32>
0x00524630:	pushl $0x100<UINT32>
0x00524635:	pushl %ebx
0x00524636:	call LCMapStringW@KERNEL32.DLL
LCMapStringW@KERNEL32.DLL: API Node	
0x0052463c:	testl %eax, %eax
0x0052463e:	je 8
0x00524640:	movl 0x5c0920, %edi
0x00524646:	jmp 0x0052465d
0x0052465d:	cmpl 0x14(%ebp), %ebx
0x00524660:	jle 0x00524684
0x00524684:	movl %eax, 0x5c0920
0x00524689:	cmpl %eax, $0x2<UINT8>
0x0052468c:	je 428
0x00524692:	cmpl %eax, %ebx
0x00524694:	je 420
0x0052469a:	cmpl %eax, $0x1<UINT8>
0x0052469d:	jne 460
0x005246a3:	movl -8(%ebp), %ebx
0x005246a6:	cmpl 0x20(%ebp), %ebx
0x005246a9:	jne 0x005246b3
0x005246b3:	movl %esi, 0x542214
0x005246b9:	xorl %eax, %eax
0x005246bb:	cmpl 0x24(%ebp), %ebx
0x005246be:	pushl %ebx
0x005246bf:	pushl %ebx
0x005246c0:	pushl 0x14(%ebp)
0x005246c3:	setne %al
0x005246c6:	pushl 0x10(%ebp)
0x005246c9:	leal %eax, 0x1(,%eax,8)
0x005246d0:	pushl %eax
0x005246d1:	pushl 0x20(%ebp)
0x005246d4:	call MultiByteToWideChar@KERNEL32.DLL
0x005246d6:	movl %edi, %eax
0x005246d8:	cmpl %edi, %ebx
0x005246da:	je 0x0052486f
0x0052486f:	xorl %eax, %eax
0x00524871:	jmp 0x00524997
0x00524997:	leal %esp, -32(%ebp)
0x0052499a:	popl %edi
0x0052499b:	popl %esi
0x0052499c:	popl %ebx
0x0052499d:	movl %ecx, -4(%ebp)
0x005249a0:	xorl %ecx, %ebp
0x005249a2:	call 0x0051a2f8
0x005249a7:	leave
0x005249a8:	ret

0x005249dc:	addl %esp, $0x20<UINT8>
0x005249df:	cmpb -4(%ebp), $0x0<UINT8>
0x005249e3:	je 7
0x005249e5:	movl %ecx, -8(%ebp)
0x005249e8:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x005249ec:	leave
0x005249ed:	ret

0x00523480:	addl %esp, $0x44<UINT8>
0x00523483:	pushl %ebx
0x00523484:	pushl 0x4(%esi)
0x00523487:	leal %eax, -772(%ebp)
0x0052348d:	pushl %edi
0x0052348e:	pushl %eax
0x0052348f:	pushl %edi
0x00523490:	leal %eax, -260(%ebp)
0x00523496:	pushl %eax
0x00523497:	pushl $0x200<UINT32>
0x0052349c:	pushl 0xc(%esi)
0x0052349f:	pushl %ebx
0x005234a0:	call 0x005249a9
0x005234a5:	addl %esp, $0x24<UINT8>
0x005234a8:	xorl %eax, %eax
0x005234aa:	movzwl %ecx, -1284(%ebp,%eax,2)
0x005234b2:	testb %cl, $0x1<UINT8>
0x005234b5:	je 0x005234c5
0x005234c5:	testb %cl, $0x2<UINT8>
0x005234c8:	je 0x005234df
0x005234df:	movb 0x11d(%esi,%eax), $0x0<UINT8>
0x005234e7:	incl %eax
0x005234e8:	cmpl %eax, %edi
0x005234ea:	jb -66
0x005234ec:	jmp 0x00523544
0x00523544:	movl %ecx, -4(%ebp)
0x00523547:	popl %edi
0x00523548:	xorl %ecx, %ebp
0x0052354a:	popl %ebx
0x0052354b:	call 0x0051a2f8
0x00523550:	leave
0x00523551:	ret

0x005237e8:	jmp 0x005236a4
0x005236a4:	xorl %eax, %eax
0x005236a6:	jmp 0x00523848
0x00523848:	movl %ecx, -4(%ebp)
0x0052384b:	popl %edi
0x0052384c:	popl %esi
0x0052384d:	xorl %ecx, %ebp
0x0052384f:	popl %ebx
0x00523850:	call 0x0051a2f8
0x00523855:	leave
0x00523856:	ret

0x005238ba:	popl %ecx
0x005238bb:	popl %ecx
0x005238bc:	movl -32(%ebp), %eax
0x005238bf:	testl %eax, %eax
0x005238c1:	jne 252
0x005238c7:	movl %esi, -36(%ebp)
0x005238ca:	pushl 0x68(%esi)
0x005238cd:	call InterlockedDecrement@KERNEL32.DLL
InterlockedDecrement@KERNEL32.DLL: API Node	
0x005238d3:	testl %eax, %eax
0x005238d5:	jne 17
0x005238d7:	movl %eax, 0x68(%esi)
0x005238da:	cmpl %eax, $0x5becc8<UINT32>
0x005238df:	je 0x005238e8
0x005238e8:	movl 0x68(%esi), %ebx
0x005238eb:	pushl %ebx
0x005238ec:	movl %edi, 0x5421d4
0x005238f2:	call InterlockedIncrement@KERNEL32.DLL
0x005238f4:	testb 0x70(%esi), $0x2<UINT8>
0x005238f8:	jne 234
0x005238fe:	testb 0x5bf1ec, $0x1<UINT8>
0x00523905:	jne 221
0x0052390b:	pushl $0xd<UINT8>
0x0052390d:	call 0x005269fd
0x00523912:	popl %ecx
0x00523913:	andl -4(%ebp), $0x0<UINT8>
0x00523917:	movl %eax, 0x4(%ebx)
0x0052391a:	movl 0x5c0584, %eax
0x0052391f:	movl %eax, 0x8(%ebx)
0x00523922:	movl 0x5c0588, %eax
0x00523927:	movl %eax, 0xc(%ebx)
0x0052392a:	movl 0x5c058c, %eax
0x0052392f:	xorl %eax, %eax
0x00523931:	movl -28(%ebp), %eax
0x00523934:	cmpl %eax, $0x5<UINT8>
0x00523937:	jnl 0x00523949
0x00523939:	movw %cx, 0x10(%ebx,%eax,2)
0x0052393e:	movw 0x5c0578(,%eax,2), %cx
0x00523946:	incl %eax
0x00523947:	jmp 0x00523931
0x00523949:	xorl %eax, %eax
0x0052394b:	movl -28(%ebp), %eax
0x0052394e:	cmpl %eax, $0x101<UINT32>
0x00523953:	jnl 0x00523962
0x00523955:	movb %cl, 0x1c(%eax,%ebx)
0x00523959:	movb 0x5beee8(%eax), %cl
0x0052395f:	incl %eax
0x00523960:	jmp 0x0052394b
0x00523962:	xorl %eax, %eax
0x00523964:	movl -28(%ebp), %eax
0x00523967:	cmpl %eax, $0x100<UINT32>
0x0052396c:	jnl 0x0052397e
0x0052396e:	movb %cl, 0x11d(%eax,%ebx)
0x00523975:	movb 0x5beff0(%eax), %cl
0x0052397b:	incl %eax
0x0052397c:	jmp 0x00523964
0x0052397e:	pushl 0x5bf0f0
0x00523984:	call InterlockedDecrement@KERNEL32.DLL
0x0052398a:	testl %eax, %eax
0x0052398c:	jne 0x005239a1
0x005239a1:	movl 0x5bf0f0, %ebx
0x005239a7:	pushl %ebx
0x005239a8:	call InterlockedIncrement@KERNEL32.DLL
0x005239aa:	movl -4(%ebp), $0xfffffffe<UINT32>
0x005239b1:	call 0x005239b8
0x005239b8:	pushl $0xd<UINT8>
0x005239ba:	call 0x00526923
0x005239bf:	popl %ecx
0x005239c0:	ret

0x005239b6:	jmp 0x005239e8
0x005239e8:	movl %eax, -32(%ebp)
0x005239eb:	call 0x00523181
0x005239f0:	ret

0x00523a01:	popl %ecx
0x00523a02:	movl 0x5c0e0c, $0x1<UINT32>
0x00523a0c:	xorl %eax, %eax
0x00523a0e:	ret

0x00524edb:	pushl $0x104<UINT32>
0x00524ee0:	movl %esi, $0x5c0928<UINT32>
0x00524ee5:	pushl %esi
0x00524ee6:	pushl %ebx
0x00524ee7:	movb 0x5c0a2c, %bl
0x00524eed:	call GetModuleFileNameA@KERNEL32.DLL
GetModuleFileNameA@KERNEL32.DLL: API Node	
0x00524ef3:	movl %eax, 0x5c1e24
0x00524ef8:	movl 0x5c08f8, %esi
0x00524efe:	cmpl %eax, %ebx
0x00524f00:	je 7
0x00524f02:	movl -4(%ebp), %eax
0x00524f05:	cmpb (%eax), %bl
0x00524f07:	jne 0x00524f0c
0x00524f0c:	movl %edx, -4(%ebp)
0x00524f0f:	leal %eax, -8(%ebp)
0x00524f12:	pushl %eax
0x00524f13:	pushl %ebx
0x00524f14:	pushl %ebx
0x00524f15:	leal %edi, -12(%ebp)
0x00524f18:	call 0x00524d27
0x00524d27:	movl %edi, %edi
0x00524d29:	pushl %ebp
0x00524d2a:	movl %ebp, %esp
0x00524d2c:	pushl %ecx
0x00524d2d:	movl %ecx, 0x10(%ebp)
0x00524d30:	pushl %ebx
0x00524d31:	xorl %eax, %eax
0x00524d33:	pushl %esi
0x00524d34:	movl (%edi), %eax
0x00524d36:	movl %esi, %edx
0x00524d38:	movl %edx, 0xc(%ebp)
0x00524d3b:	movl (%ecx), $0x1<UINT32>
0x00524d41:	cmpl 0x8(%ebp), %eax
0x00524d44:	je 0x00524d4f
0x00524d4f:	movl -4(%ebp), %eax
0x00524d52:	cmpb (%esi), $0x22<UINT8>
0x00524d55:	jne 0x00524d67
0x00524d57:	xorl %eax, %eax
0x00524d59:	cmpl -4(%ebp), %eax
0x00524d5c:	movb %bl, $0x22<UINT8>
0x00524d5e:	sete %al
0x00524d61:	incl %esi
0x00524d62:	movl -4(%ebp), %eax
0x00524d65:	jmp 0x00524da3
0x00524da3:	cmpl -4(%ebp), $0x0<UINT8>
0x00524da7:	jne 0x00524d52
0x00524d67:	incl (%edi)
0x00524d69:	testl %edx, %edx
0x00524d6b:	je 0x00524d75
0x00524d75:	movb %bl, (%esi)
0x00524d77:	movzbl %eax, %bl
0x00524d7a:	pushl %eax
0x00524d7b:	incl %esi
0x00524d7c:	call 0x005267e4
0x005267e4:	movl %edi, %edi
0x005267e6:	pushl %ebp
0x005267e7:	movl %ebp, %esp
0x005267e9:	pushl $0x4<UINT8>
0x005267eb:	pushl $0x0<UINT8>
0x005267ed:	pushl 0x8(%ebp)
0x005267f0:	pushl $0x0<UINT8>
0x005267f2:	call 0x00526778
0x00526778:	movl %edi, %edi
0x0052677a:	pushl %ebp
0x0052677b:	movl %ebp, %esp
0x0052677d:	subl %esp, $0x10<UINT8>
0x00526780:	pushl 0x8(%ebp)
0x00526783:	leal %ecx, -16(%ebp)
0x00526786:	call 0x0051ac40
0x0052678b:	movzbl %eax, 0xc(%ebp)
0x0052678f:	movl %ecx, -12(%ebp)
0x00526792:	movb %dl, 0x14(%ebp)
0x00526795:	testb 0x1d(%ecx,%eax), %dl
0x00526799:	jne 30
0x0052679b:	cmpl 0x10(%ebp), $0x0<UINT8>
0x0052679f:	je 0x005267b3
0x005267b3:	xorl %eax, %eax
0x005267b5:	testl %eax, %eax
0x005267b7:	je 0x005267bc
0x005267bc:	cmpb -4(%ebp), $0x0<UINT8>
0x005267c0:	je 7
0x005267c2:	movl %ecx, -8(%ebp)
0x005267c5:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x005267c9:	leave
0x005267ca:	ret

0x005267f7:	addl %esp, $0x10<UINT8>
0x005267fa:	popl %ebp
0x005267fb:	ret

0x00524d81:	popl %ecx
0x00524d82:	testl %eax, %eax
0x00524d84:	je 0x00524d99
0x00524d99:	movl %edx, 0xc(%ebp)
0x00524d9c:	movl %ecx, 0x10(%ebp)
0x00524d9f:	testb %bl, %bl
0x00524da1:	je 0x00524dd5
0x00524da9:	cmpb %bl, $0x20<UINT8>
0x00524dac:	je 5
0x00524dae:	cmpb %bl, $0x9<UINT8>
0x00524db1:	jne 0x00524d52
0x00524dd5:	decl %esi
0x00524dd6:	jmp 0x00524dbb
0x00524dbb:	andl -4(%ebp), $0x0<UINT8>
0x00524dbf:	cmpb (%esi), $0x0<UINT8>
0x00524dc2:	je 0x00524eb1
0x00524eb1:	movl %eax, 0x8(%ebp)
0x00524eb4:	popl %esi
0x00524eb5:	popl %ebx
0x00524eb6:	testl %eax, %eax
0x00524eb8:	je 0x00524ebd
0x00524ebd:	incl (%ecx)
0x00524ebf:	leave
0x00524ec0:	ret

0x00524f1d:	movl %eax, -8(%ebp)
0x00524f20:	addl %esp, $0xc<UINT8>
0x00524f23:	cmpl %eax, $0x3fffffff<UINT32>
0x00524f28:	jae 74
0x00524f2a:	movl %ecx, -12(%ebp)
0x00524f2d:	cmpl %ecx, $0xffffffff<UINT8>
0x00524f30:	jae 66
0x00524f32:	movl %edi, %eax
0x00524f34:	shll %edi, $0x2<UINT8>
0x00524f37:	leal %eax, (%edi,%ecx)
0x00524f3a:	cmpl %eax, %ecx
0x00524f3c:	jb 54
0x00524f3e:	pushl %eax
0x00524f3f:	call 0x00526a30
0x00524f44:	movl %esi, %eax
0x00524f46:	popl %ecx
0x00524f47:	cmpl %esi, %ebx
0x00524f49:	je 41
0x00524f4b:	movl %edx, -4(%ebp)
0x00524f4e:	leal %eax, -8(%ebp)
0x00524f51:	pushl %eax
0x00524f52:	addl %edi, %esi
0x00524f54:	pushl %edi
0x00524f55:	pushl %esi
0x00524f56:	leal %edi, -12(%ebp)
0x00524f59:	call 0x00524d27
0x00524d46:	movl %ebx, 0x8(%ebp)
0x00524d49:	addl 0x8(%ebp), $0x4<UINT8>
0x00524d4d:	movl (%ebx), %edx
0x00524d6d:	movb %al, (%esi)
0x00524d6f:	movb (%edx), %al
0x00524d71:	incl %edx
0x00524d72:	movl 0xc(%ebp), %edx
0x00524eba:	andl (%eax), $0x0<UINT8>
0x00524f5e:	movl %eax, -8(%ebp)
0x00524f61:	addl %esp, $0xc<UINT8>
0x00524f64:	decl %eax
0x00524f65:	movl 0x5c08dc, %eax
0x00524f6a:	movl 0x5c08e0, %esi
0x00524f70:	xorl %eax, %eax
0x00524f72:	jmp 0x00524f77
0x00524f77:	popl %edi
0x00524f78:	popl %esi
0x00524f79:	popl %ebx
0x00524f7a:	leave
0x00524f7b:	ret

0x0051b357:	testl %eax, %eax
0x0051b359:	jnl 0x0051b363
0x0051b363:	call 0x00524c49
0x00524c49:	cmpl 0x5c0e0c, $0x0<UINT8>
0x00524c50:	jne 0x00524c57
0x00524c57:	pushl %esi
0x00524c58:	movl %esi, 0x5c0214
0x00524c5e:	pushl %edi
0x00524c5f:	xorl %edi, %edi
0x00524c61:	testl %esi, %esi
0x00524c63:	jne 0x00524c7d
0x00524c7d:	movb %al, (%esi)
0x00524c7f:	testb %al, %al
0x00524c81:	jne 0x00524c6d
0x00524c6d:	cmpb %al, $0x3d<UINT8>
0x00524c6f:	je 0x00524c72
0x00524c72:	pushl %esi
0x00524c73:	call 0x0051a960
0x0051a960:	movl %ecx, 0x4(%esp)
0x0051a964:	testl %ecx, $0x3<UINT32>
0x0051a96a:	je 0x0051a990
0x0051a990:	movl %eax, (%ecx)
0x0051a992:	movl %edx, $0x7efefeff<UINT32>
0x0051a997:	addl %edx, %eax
0x0051a999:	xorl %eax, $0xffffffff<UINT8>
0x0051a99c:	xorl %eax, %edx
0x0051a99e:	addl %ecx, $0x4<UINT8>
0x0051a9a1:	testl %eax, $0x81010100<UINT32>
0x0051a9a6:	je 0x0051a990
0x0051a9a8:	movl %eax, -4(%ecx)
0x0051a9ab:	testb %al, %al
0x0051a9ad:	je 50
0x0051a9af:	testb %ah, %ah
0x0051a9b1:	je 36
0x0051a9b3:	testl %eax, $0xff0000<UINT32>
0x0051a9b8:	je 19
0x0051a9ba:	testl %eax, $0xff000000<UINT32>
0x0051a9bf:	je 0x0051a9c3
0x0051a9c3:	leal %eax, -1(%ecx)
0x0051a9c6:	movl %ecx, 0x4(%esp)
0x0051a9ca:	subl %eax, %ecx
0x0051a9cc:	ret

0x00524c78:	popl %ecx
0x00524c79:	leal %esi, 0x1(%esi,%eax)
0x00524c83:	pushl $0x4<UINT8>
0x00524c85:	incl %edi
0x00524c86:	pushl %edi
0x00524c87:	call 0x00526a75
0x00524c8c:	movl %edi, %eax
0x00524c8e:	popl %ecx
0x00524c8f:	popl %ecx
0x00524c90:	movl 0x5c08e8, %edi
0x00524c96:	testl %edi, %edi
0x00524c98:	je -53
0x00524c9a:	movl %esi, 0x5c0214
0x00524ca0:	pushl %ebx
0x00524ca1:	jmp 0x00524ce5
0x00524ce5:	cmpb (%esi), $0x0<UINT8>
0x00524ce8:	jne 0x00524ca3
0x00524ca3:	pushl %esi
0x00524ca4:	call 0x0051a960
0x00524ca9:	movl %ebx, %eax
0x00524cab:	incl %ebx
0x00524cac:	cmpb (%esi), $0x3d<UINT8>
0x00524caf:	popl %ecx
0x00524cb0:	je 0x00524ce3
0x00524ce3:	addl %esi, %ebx
0x00524cea:	pushl 0x5c0214
0x00524cf0:	call 0x0051c745
0x0051c745:	pushl $0xc<UINT8>
0x0051c747:	pushl $0x5b8dc8<UINT32>
0x0051c74c:	call 0x0052313c
0x0051c751:	movl %esi, 0x8(%ebp)
0x0051c754:	testl %esi, %esi
0x0051c756:	je 0x0051c7cd
0x0051c758:	cmpl 0x5c0ce4, $0x3<UINT8>
0x0051c75f:	jne 0x0051c7a4
0x0051c7a4:	pushl %esi
0x0051c7a5:	pushl $0x0<UINT8>
0x0051c7a7:	pushl 0x5c0a34
0x0051c7ad:	call HeapFree@KERNEL32.DLL
HeapFree@KERNEL32.DLL: API Node	
0x0051c7b3:	testl %eax, %eax
0x0051c7b5:	jne 0x0051c7cd
0x0051c7cd:	call 0x00523181
0x0051c7d2:	ret

0x00524cf5:	andl 0x5c0214, $0x0<UINT8>
0x00524cfc:	andl (%edi), $0x0<UINT8>
0x00524cff:	movl 0x5c0e00, $0x1<UINT32>
0x00524d09:	xorl %eax, %eax
0x00524d0b:	popl %ecx
0x00524d0c:	popl %ebx
0x00524d0d:	popl %edi
0x00524d0e:	popl %esi
0x00524d0f:	ret

0x0051b368:	testl %eax, %eax
0x0051b36a:	jnl 0x0051b374
0x0051b374:	pushl %ebx
0x0051b375:	call 0x00524189
0x00524189:	movl %edi, %edi
0x0052418b:	pushl %ebp
0x0052418c:	movl %ebp, %esp
0x0052418e:	cmpl 0x594400, $0x0<UINT8>
0x00524195:	je 25
0x00524197:	pushl $0x594400<UINT32>
0x0052419c:	call 0x0052b970
0x0052b970:	movl %edi, %edi
0x0052b972:	pushl %ebp
0x0052b973:	movl %ebp, %esp
0x0052b975:	pushl $0xfffffffe<UINT8>
0x0052b977:	pushl $0x5b9320<UINT32>
0x0052b97c:	pushl $0x5231a0<UINT32>
0x0052b981:	movl %eax, %fs:0
0x0052b987:	pushl %eax
0x0052b988:	subl %esp, $0x8<UINT8>
0x0052b98b:	pushl %ebx
0x0052b98c:	pushl %esi
0x0052b98d:	pushl %edi
0x0052b98e:	movl %eax, 0x5be7b0
0x0052b993:	xorl -8(%ebp), %eax
0x0052b996:	xorl %eax, %ebp
0x0052b998:	pushl %eax
0x0052b999:	leal %eax, -16(%ebp)
0x0052b99c:	movl %fs:0, %eax
0x0052b9a2:	movl -24(%ebp), %esp
0x0052b9a5:	movl -4(%ebp), $0x0<UINT32>
0x0052b9ac:	pushl $0x400000<UINT32>
0x0052b9b1:	call 0x0052b8e0
0x0052b8e0:	movl %edi, %edi
0x0052b8e2:	pushl %ebp
0x0052b8e3:	movl %ebp, %esp
0x0052b8e5:	movl %ecx, 0x8(%ebp)
0x0052b8e8:	movl %eax, $0x5a4d<UINT32>
0x0052b8ed:	cmpw (%ecx), %ax
0x0052b8f0:	je 0x0052b8f6
0x0052b8f6:	movl %eax, 0x3c(%ecx)
0x0052b8f9:	addl %eax, %ecx
0x0052b8fb:	cmpl (%eax), $0x4550<UINT32>
0x0052b901:	jne -17
0x0052b903:	xorl %edx, %edx
0x0052b905:	movl %ecx, $0x10b<UINT32>
0x0052b90a:	cmpw 0x18(%eax), %cx
0x0052b90e:	sete %dl
0x0052b911:	movl %eax, %edx
0x0052b913:	popl %ebp
0x0052b914:	ret

0x0052b9b6:	addl %esp, $0x4<UINT8>
0x0052b9b9:	testl %eax, %eax
0x0052b9bb:	je 85
0x0052b9bd:	movl %eax, 0x8(%ebp)
0x0052b9c0:	subl %eax, $0x400000<UINT32>
0x0052b9c5:	pushl %eax
0x0052b9c6:	pushl $0x400000<UINT32>
0x0052b9cb:	call 0x0052b920
0x0052b920:	movl %edi, %edi
0x0052b922:	pushl %ebp
0x0052b923:	movl %ebp, %esp
0x0052b925:	movl %eax, 0x8(%ebp)
0x0052b928:	movl %ecx, 0x3c(%eax)
0x0052b92b:	addl %ecx, %eax
0x0052b92d:	movzwl %eax, 0x14(%ecx)
0x0052b931:	pushl %ebx
0x0052b932:	pushl %esi
0x0052b933:	movzwl %esi, 0x6(%ecx)
0x0052b937:	xorl %edx, %edx
0x0052b939:	pushl %edi
0x0052b93a:	leal %eax, 0x18(%eax,%ecx)
0x0052b93e:	testl %esi, %esi
0x0052b940:	jbe 27
0x0052b942:	movl %edi, 0xc(%ebp)
0x0052b945:	movl %ecx, 0xc(%eax)
0x0052b948:	cmpl %edi, %ecx
0x0052b94a:	jb 9
0x0052b94c:	movl %ebx, 0x8(%eax)
0x0052b94f:	addl %ebx, %ecx
0x0052b951:	cmpl %edi, %ebx
0x0052b953:	jb 0x0052b95f
0x0052b95f:	popl %edi
0x0052b960:	popl %esi
0x0052b961:	popl %ebx
0x0052b962:	popl %ebp
0x0052b963:	ret

0x0052b9d0:	addl %esp, $0x8<UINT8>
0x0052b9d3:	testl %eax, %eax
0x0052b9d5:	je 59
0x0052b9d7:	movl %eax, 0x24(%eax)
0x0052b9da:	shrl %eax, $0x1f<UINT8>
0x0052b9dd:	notl %eax
0x0052b9df:	andl %eax, $0x1<UINT8>
0x0052b9e2:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0052b9e9:	movl %ecx, -16(%ebp)
0x0052b9ec:	movl %fs:0, %ecx
0x0052b9f3:	popl %ecx
0x0052b9f4:	popl %edi
0x0052b9f5:	popl %esi
0x0052b9f6:	popl %ebx
0x0052b9f7:	movl %esp, %ebp
0x0052b9f9:	popl %ebp
0x0052b9fa:	ret

0x005241a1:	popl %ecx
0x005241a2:	testl %eax, %eax
0x005241a4:	je 10
0x005241a6:	pushl 0x8(%ebp)
0x005241a9:	call 0x0051a4c2
0x0051a4c2:	movl %edi, %edi
0x0051a4c4:	pushl %ebp
0x0051a4c5:	movl %ebp, %esp
0x0051a4c7:	call 0x0051a462
0x0051a462:	movl %eax, $0x521d5a<UINT32>
0x0051a467:	movl 0x5bec94, %eax
0x0051a46c:	movl 0x5bec98, $0x521441<UINT32>
0x0051a476:	movl 0x5bec9c, $0x5213f5<UINT32>
0x0051a480:	movl 0x5beca0, $0x52142e<UINT32>
0x0051a48a:	movl 0x5beca4, $0x521397<UINT32>
0x0051a494:	movl 0x5beca8, %eax
0x0051a499:	movl 0x5becac, $0x521cd2<UINT32>
0x0051a4a3:	movl 0x5becb0, $0x5213b3<UINT32>
0x0051a4ad:	movl 0x5becb4, $0x521315<UINT32>
0x0051a4b7:	movl 0x5becb8, $0x5212a2<UINT32>
0x0051a4c1:	ret

0x0051a4cc:	call 0x00521e07
0x00521e07:	pushl $0x594598<UINT32>
0x00521e0c:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x00521e12:	testl %eax, %eax
0x00521e14:	je 21
0x00521e16:	pushl $0x5563e8<UINT32>
0x00521e1b:	pushl %eax
0x00521e1c:	call GetProcAddress@KERNEL32.DLL
0x00521e22:	testl %eax, %eax
0x00521e24:	je 5
0x00521e26:	pushl $0x0<UINT8>
0x00521e28:	call IsProcessorFeaturePresent@KERNEL32
IsProcessorFeaturePresent@KERNEL32: API Node	
0x00521e2a:	ret

0x0051a4d1:	cmpl 0x8(%ebp), $0x0<UINT8>
0x0051a4d5:	movl 0x5c01fc, %eax
0x0051a4da:	je 5
0x0051a4dc:	call 0x00521d9e
0x00521d9e:	movl %edi, %edi
0x00521da0:	pushl %esi
0x00521da1:	pushl $0x30000<UINT32>
0x00521da6:	pushl $0x10000<UINT32>
0x00521dab:	xorl %esi, %esi
0x00521dad:	pushl %esi
0x00521dae:	call 0x0052b3f8
0x0052b3f8:	movl %edi, %edi
0x0052b3fa:	pushl %ebp
0x0052b3fb:	movl %ebp, %esp
0x0052b3fd:	movl %eax, 0x10(%ebp)
0x0052b400:	movl %ecx, 0xc(%ebp)
0x0052b403:	andl %eax, $0xfff7ffff<UINT32>
0x0052b408:	andl %ecx, %eax
0x0052b40a:	pushl %esi
0x0052b40b:	testl %ecx, $0xfcf0fce0<UINT32>
0x0052b411:	je 0x0052b444
0x0052b444:	movl %esi, 0x8(%ebp)
0x0052b447:	pushl %eax
0x0052b448:	pushl 0xc(%ebp)
0x0052b44b:	testl %esi, %esi
0x0052b44d:	je 0x0052b458
0x0052b458:	call 0x005301c3
0x005301c3:	movl %edi, %edi
0x005301c5:	pushl %ebp
0x005301c6:	movl %ebp, %esp
0x005301c8:	subl %esp, $0x14<UINT8>
0x005301cb:	pushl %ebx
0x005301cc:	pushl %esi
0x005301cd:	pushl %edi
0x005301ce:	fwait
0x005301cf:	fnstcw -8(%ebp)
0x005301d2:	movl %ebx, -8(%ebp)
0x005301d5:	xorl %edx, %edx
0x005301d7:	testb %bl, $0x1<UINT8>
0x005301da:	je 0x005301df
0x005301df:	testb %bl, $0x4<UINT8>
0x005301e2:	je 3
0x005301e4:	orl %edx, $0x8<UINT8>
0x005301e7:	testb %bl, $0x8<UINT8>
0x005301ea:	je 3
0x005301ec:	orl %edx, $0x4<UINT8>
0x005301ef:	testb %bl, $0x10<UINT8>
0x005301f2:	je 0x005301f7
0x005301f7:	testb %bl, $0x20<UINT8>
0x005301fa:	je 3
0x005301fc:	orl %edx, $0x1<UINT8>
0x005301ff:	testb %bl, $0x2<UINT8>
0x00530202:	je 0x0053020a
0x0053020a:	movzwl %ecx, %bx
0x0053020d:	movl %eax, %ecx
0x0053020f:	movl %esi, $0xc00<UINT32>
0x00530214:	andl %eax, %esi
0x00530216:	movl %edi, $0x300<UINT32>
0x0053021b:	je 36
0x0053021d:	cmpl %eax, $0x400<UINT32>
0x00530222:	je 23
0x00530224:	cmpl %eax, $0x800<UINT32>
0x00530229:	je 8
0x0053022b:	cmpl %eax, %esi
0x0053022d:	jne 18
0x0053022f:	orl %edx, %edi
0x00530231:	jmp 0x00530241
0x00530241:	andl %ecx, %edi
0x00530243:	je 16
0x00530245:	cmpl %ecx, $0x200<UINT32>
0x0053024b:	jne 14
0x0053024d:	orl %edx, $0x10000<UINT32>
0x00530253:	jmp 0x0053025b
0x0053025b:	testl %ebx, $0x1000<UINT32>
0x00530261:	je 6
0x00530263:	orl %edx, $0x40000<UINT32>
0x00530269:	movl %edi, 0xc(%ebp)
0x0053026c:	movl %ecx, 0x8(%ebp)
0x0053026f:	movl %eax, %edi
0x00530271:	notl %eax
0x00530273:	andl %eax, %edx
0x00530275:	andl %ecx, %edi
0x00530277:	orl %eax, %ecx
0x00530279:	movl 0xc(%ebp), %eax
0x0053027c:	cmpl %eax, %edx
0x0053027e:	je 0x00530332
0x00530332:	xorl %esi, %esi
0x00530334:	cmpl 0x5c0e18, %esi
0x0053033a:	je 0x005304cd
0x005304cd:	popl %edi
0x005304ce:	popl %esi
0x005304cf:	popl %ebx
0x005304d0:	leave
0x005304d1:	ret

0x0052b45d:	popl %ecx
0x0052b45e:	popl %ecx
0x0052b45f:	xorl %eax, %eax
0x0052b461:	popl %esi
0x0052b462:	popl %ebp
0x0052b463:	ret

0x00521db3:	addl %esp, $0xc<UINT8>
0x00521db6:	testl %eax, %eax
0x00521db8:	je 0x00521dc7
0x00521dc7:	popl %esi
0x00521dc8:	ret

0x0051a4e1:	fnclex
0x0051a4e3:	popl %ebp
0x0051a4e4:	ret

0x005241af:	popl %ecx
0x005241b0:	call 0x00521d7d
0x00521d7d:	movl %edi, %edi
0x00521d7f:	pushl %esi
0x00521d80:	pushl %edi
0x00521d81:	xorl %edi, %edi
0x00521d83:	leal %esi, 0x5bec94(%edi)
0x00521d89:	pushl (%esi)
0x00521d8b:	call 0x00520aaa
0x00520acc:	pushl %eax
0x00520acd:	pushl 0x5bec88
0x00520ad3:	call TlsGetValue@KERNEL32.DLL
0x00520ad5:	call FlsGetValue@KERNEL32.DLL
0x00520ad7:	testl %eax, %eax
0x00520ad9:	je 8
0x00520adb:	movl %eax, 0x1f8(%eax)
0x00520ae1:	jmp 0x00520b0a
0x00521d90:	addl %edi, $0x4<UINT8>
0x00521d93:	popl %ecx
0x00521d94:	movl (%esi), %eax
0x00521d96:	cmpl %edi, $0x28<UINT8>
0x00521d99:	jb 0x00521d83
0x00521d9b:	popl %edi
0x00521d9c:	popl %esi
0x00521d9d:	ret

0x005241b5:	pushl $0x5426f4<UINT32>
0x005241ba:	pushl $0x5426d8<UINT32>
0x005241bf:	call 0x00524165
0x00524165:	movl %edi, %edi
0x00524167:	pushl %ebp
0x00524168:	movl %ebp, %esp
0x0052416a:	pushl %esi
0x0052416b:	movl %esi, 0x8(%ebp)
0x0052416e:	xorl %eax, %eax
0x00524170:	jmp 0x00524181
0x00524181:	cmpl %esi, 0xc(%ebp)
0x00524184:	jb 0x00524172
0x00524172:	testl %eax, %eax
0x00524174:	jne 16
0x00524176:	movl %ecx, (%esi)
0x00524178:	testl %ecx, %ecx
0x0052417a:	je 0x0052417e
0x0052417e:	addl %esi, $0x4<UINT8>
0x0052417c:	call 0x00524a7b
0x0051c634:	movl %edi, %edi
0x0051c636:	pushl %esi
0x0051c637:	pushl $0x4<UINT8>
0x0051c639:	pushl $0x20<UINT8>
0x0051c63b:	call 0x00526a75
0x0051c640:	movl %esi, %eax
0x0051c642:	pushl %esi
0x0051c643:	call 0x00520aaa
0x0051c648:	addl %esp, $0xc<UINT8>
0x0051c64b:	movl 0x5c0e08, %eax
0x0051c650:	movl 0x5c0e04, %eax
0x0051c655:	testl %esi, %esi
0x0051c657:	jne 0x0051c65e
0x0051c65e:	andl (%esi), $0x0<UINT8>
0x0051c661:	xorl %eax, %eax
0x0051c663:	popl %esi
0x0051c664:	ret

0x0051fb90:	movl %eax, 0x5c1e20
0x0051fb95:	pushl %esi
0x0051fb96:	pushl $0x14<UINT8>
0x0051fb98:	popl %esi
0x0051fb99:	testl %eax, %eax
0x0051fb9b:	jne 7
0x0051fb9d:	movl %eax, $0x200<UINT32>
0x0051fba2:	jmp 0x0051fbaa
0x0051fbaa:	movl 0x5c1e20, %eax
0x0051fbaf:	pushl $0x4<UINT8>
0x0051fbb1:	pushl %eax
0x0051fbb2:	call 0x00526a75
0x0051fbb7:	popl %ecx
0x0051fbb8:	popl %ecx
0x0051fbb9:	movl 0x5c0e1c, %eax
0x0051fbbe:	testl %eax, %eax
0x0051fbc0:	jne 0x0051fbe0
0x0051fbe0:	xorl %edx, %edx
0x0051fbe2:	movl %ecx, $0x5be9e0<UINT32>
0x0051fbe7:	jmp 0x0051fbee
0x0051fbee:	movl (%edx,%eax), %ecx
0x0051fbf1:	addl %ecx, $0x20<UINT8>
0x0051fbf4:	addl %edx, $0x4<UINT8>
0x0051fbf7:	cmpl %ecx, $0x5bec60<UINT32>
0x0051fbfd:	jl 0x0051fbe9
0x0051fbe9:	movl %eax, 0x5c0e1c
0x0051fbff:	pushl $0xfffffffe<UINT8>
0x0051fc01:	popl %esi
0x0051fc02:	xorl %edx, %edx
0x0051fc04:	movl %ecx, $0x5be9f0<UINT32>
0x0051fc09:	pushl %edi
0x0051fc0a:	movl %eax, %edx
0x0051fc0c:	sarl %eax, $0x5<UINT8>
0x0051fc0f:	movl %eax, 0x5c0d00(,%eax,4)
0x0051fc16:	movl %edi, %edx
0x0051fc18:	andl %edi, $0x1f<UINT8>
0x0051fc1b:	shll %edi, $0x6<UINT8>
0x0051fc1e:	movl %eax, (%edi,%eax)
0x0051fc21:	cmpl %eax, $0xffffffff<UINT8>
0x0051fc24:	je 8
0x0051fc26:	cmpl %eax, %esi
0x0051fc28:	je 4
0x0051fc2a:	testl %eax, %eax
0x0051fc2c:	jne 0x0051fc30
0x0051fc30:	addl %ecx, $0x20<UINT8>
0x0051fc33:	incl %edx
0x0051fc34:	cmpl %ecx, $0x5bea50<UINT32>
0x0051fc3a:	jl 0x0051fc0a
0x0051fc3c:	popl %edi
0x0051fc3d:	xorl %eax, %eax
0x0051fc3f:	popl %esi
0x0051fc40:	ret

0x00521fc8:	call 0x00521f66
0x00521f66:	movl %edi, %edi
0x00521f68:	pushl %ebp
0x00521f69:	movl %ebp, %esp
0x00521f6b:	subl %esp, $0x18<UINT8>
0x00521f6e:	xorl %eax, %eax
0x00521f70:	pushl %ebx
0x00521f71:	movl -4(%ebp), %eax
0x00521f74:	movl -12(%ebp), %eax
0x00521f77:	movl -8(%ebp), %eax
0x00521f7a:	pushl %ebx
0x00521f7b:	pushfl
0x00521f7c:	popl %eax
0x00521f7d:	movl %ecx, %eax
0x00521f7f:	xorl %eax, $0x200000<UINT32>
0x00521f84:	pushl %eax
0x00521f85:	popfl
0x00521f86:	pushfl
0x00521f87:	popl %edx
0x00521f88:	subl %edx, %ecx
0x00521f8a:	je 0x00521fab
0x00521fab:	popl %ebx
0x00521fac:	testl -4(%ebp), $0x4000000<UINT32>
0x00521fb3:	je 0x00521fc3
0x00521fc3:	xorl %eax, %eax
0x00521fc5:	popl %ebx
0x00521fc6:	leave
0x00521fc7:	ret

0x00521fcd:	movl 0x5c0e18, %eax
0x00521fd2:	xorl %eax, %eax
0x00521fd4:	ret

0x00525419:	andl 0x5c0ce0, $0x0<UINT8>
0x00525420:	call 0x00521f66
0x00525425:	movl 0x5c0ce0, %eax
0x0052542a:	xorl %eax, %eax
0x0052542c:	ret

0x00524a7b:	pushl $0x524a39<UINT32>
0x00524a80:	call SetUnhandledExceptionFilter@KERNEL32.DLL
SetUnhandledExceptionFilter@KERNEL32.DLL: API Node	
0x00524a86:	xorl %eax, %eax
0x00524a88:	ret

0x00524186:	popl %esi
0x00524187:	popl %ebp
0x00524188:	ret

0x005241c4:	popl %ecx
0x005241c5:	popl %ecx
0x005241c6:	testl %eax, %eax
0x005241c8:	jne 66
0x005241ca:	pushl $0x52532d<UINT32>
0x005241cf:	call 0x0051c6a1
0x0051c6a1:	movl %edi, %edi
0x0051c6a3:	pushl %ebp
0x0051c6a4:	movl %ebp, %esp
0x0051c6a6:	pushl 0x8(%ebp)
0x0051c6a9:	call 0x0051c665
0x0051c665:	pushl $0xc<UINT8>
0x0051c667:	pushl $0x5b8d88<UINT32>
0x0051c66c:	call 0x0052313c
0x0051c671:	call 0x00524136
0x00524136:	pushl $0x8<UINT8>
0x00524138:	call 0x005269fd
0x0052413d:	popl %ecx
0x0052413e:	ret

0x0051c676:	andl -4(%ebp), $0x0<UINT8>
0x0051c67a:	pushl 0x8(%ebp)
0x0051c67d:	call 0x0051c57a
0x0051c57a:	movl %edi, %edi
0x0051c57c:	pushl %ebp
0x0051c57d:	movl %ebp, %esp
0x0051c57f:	pushl %ecx
0x0051c580:	pushl %ebx
0x0051c581:	pushl %esi
0x0051c582:	pushl %edi
0x0051c583:	pushl 0x5c0e08
0x0051c589:	call 0x00520b25
0x00520b56:	movl %eax, 0x1fc(%eax)
0x00520b5c:	jmp 0x00520b85
0x0051c58e:	pushl 0x5c0e04
0x0051c594:	movl %edi, %eax
0x0051c596:	movl -4(%ebp), %edi
0x0051c599:	call 0x00520b25
0x0051c59e:	movl %esi, %eax
0x0051c5a0:	popl %ecx
0x0051c5a1:	popl %ecx
0x0051c5a2:	cmpl %esi, %edi
0x0051c5a4:	jb 131
0x0051c5aa:	movl %ebx, %esi
0x0051c5ac:	subl %ebx, %edi
0x0051c5ae:	leal %eax, 0x4(%ebx)
0x0051c5b1:	cmpl %eax, $0x4<UINT8>
0x0051c5b4:	jb 119
0x0051c5b6:	pushl %edi
0x0051c5b7:	call 0x00526b0f
0x00526b0f:	pushl $0x10<UINT8>
0x00526b11:	pushl $0x5b91e0<UINT32>
0x00526b16:	call 0x0052313c
0x00526b1b:	xorl %eax, %eax
0x00526b1d:	movl %ebx, 0x8(%ebp)
0x00526b20:	xorl %edi, %edi
0x00526b22:	cmpl %ebx, %edi
0x00526b24:	setne %al
0x00526b27:	cmpl %eax, %edi
0x00526b29:	jne 0x00526b48
0x00526b48:	cmpl 0x5c0ce4, $0x3<UINT8>
0x00526b4f:	jne 0x00526b89
0x00526b89:	pushl %ebx
0x00526b8a:	pushl %edi
0x00526b8b:	pushl 0x5c0a34
0x00526b91:	call HeapSize@KERNEL32.DLL
HeapSize@KERNEL32.DLL: API Node	
0x00526b97:	movl %esi, %eax
0x00526b99:	movl %eax, %esi
0x00526b9b:	call 0x00523181
0x00526ba0:	ret

0x0051c5bc:	movl %edi, %eax
0x0051c5be:	leal %eax, 0x4(%ebx)
0x0051c5c1:	popl %ecx
0x0051c5c2:	cmpl %edi, %eax
0x0051c5c4:	jae 0x0051c60e
0x0051c60e:	pushl 0x8(%ebp)
0x0051c611:	call 0x00520aaa
0x0051c616:	movl (%esi), %eax
0x0051c618:	addl %esi, $0x4<UINT8>
0x0051c61b:	pushl %esi
0x0051c61c:	call 0x00520aaa
0x0051c621:	popl %ecx
0x0051c622:	movl 0x5c0e04, %eax
0x0051c627:	movl %eax, 0x8(%ebp)
0x0051c62a:	popl %ecx
0x0051c62b:	jmp 0x0051c62f
0x0051c62f:	popl %edi
0x0051c630:	popl %esi
0x0051c631:	popl %ebx
0x0051c632:	leave
0x0051c633:	ret

0x0051c682:	popl %ecx
0x0051c683:	movl -28(%ebp), %eax
0x0051c686:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0051c68d:	call 0x0051c69b
0x0051c69b:	call 0x0052413f
0x0052413f:	pushl $0x8<UINT8>
0x00524141:	call 0x00526923
0x00524146:	popl %ecx
0x00524147:	ret

0x0051c6a0:	ret

0x0051c692:	movl %eax, -28(%ebp)
0x0051c695:	call 0x00523181
0x0051c69a:	ret

0x0051c6ae:	negl %eax
0x0051c6b0:	sbbl %eax, %eax
0x0051c6b2:	negl %eax
0x0051c6b4:	popl %ecx
0x0051c6b5:	decl %eax
0x0051c6b6:	popl %ebp
0x0051c6b7:	ret

0x005241d4:	movl %eax, $0x5426c8<UINT32>
0x005241d9:	movl (%esp), $0x5426d4<UINT32>
0x005241e0:	call 0x00524148
0x00524148:	movl %edi, %edi
0x0052414a:	pushl %ebp
0x0052414b:	movl %ebp, %esp
0x0052414d:	pushl %esi
0x0052414e:	movl %esi, %eax
0x00524150:	jmp 0x0052415d
0x0052415d:	cmpl %esi, 0x8(%ebp)
0x00524160:	jb 0x00524152
0x00524152:	movl %eax, (%esi)
0x00524154:	testl %eax, %eax
0x00524156:	je 0x0052415a
0x0052415a:	addl %esi, $0x4<UINT8>
0x00524158:	call 0x00541d1f
0x00541d1f:	movl %ecx, $0x5bfec0<UINT32>
0x00541d24:	call 0x00482a31
0x00482a31:	pushl $0x8<UINT8>
0x00482a33:	movl %eax, $0x53a2f2<UINT32>
0x00482a38:	call 0x0051a33a
0x0051a33a:	pushl %eax
0x0051a33b:	pushl %fs:0
0x0051a342:	leal %eax, 0xc(%esp)
0x0051a346:	subl %esp, 0xc(%esp)
0x0051a34a:	pushl %ebx
0x0051a34b:	pushl %esi
0x0051a34c:	pushl %edi
0x0051a34d:	movl (%eax), %ebp
0x0051a34f:	movl %ebp, %eax
0x0051a351:	movl %eax, 0x5be7b0
0x0051a356:	xorl %eax, %ebp
0x0051a358:	pushl %eax
0x0051a359:	movl -16(%ebp), %esp
0x0051a35c:	pushl -4(%ebp)
0x0051a35f:	movl -4(%ebp), $0xffffffff<UINT32>
0x0051a366:	leal %eax, -12(%ebp)
0x0051a369:	movl %fs:0, %eax
0x0051a36f:	ret

0x00482a3d:	movl %esi, %ecx
0x00482a3f:	movl -20(%ebp), %esi
0x00482a42:	call 0x00497463
0x00497463:	movl %eax, %ecx
0x00497465:	movl (%eax), $0x57e324<UINT32>
0x0049746b:	ret

0x00482a47:	xorl %ebx, %ebx
0x00482a49:	movl -4(%ebp), %ebx
0x00482a4c:	movl (%esi), $0x573604<UINT32>
0x00482a52:	leal %ecx, 0x20(%esi)
0x00482a55:	call 0x004a9254
0x004a9254:	pushl $0x4<UINT8>
0x004a9256:	movl %eax, $0x53cbed<UINT32>
0x004a925b:	call 0x0051a307
0x0051a307:	pushl %eax
0x0051a308:	pushl %fs:0
0x0051a30f:	leal %eax, 0xc(%esp)
0x0051a313:	subl %esp, 0xc(%esp)
0x0051a317:	pushl %ebx
0x0051a318:	pushl %esi
0x0051a319:	pushl %edi
0x0051a31a:	movl (%eax), %ebp
0x0051a31c:	movl %ebp, %eax
0x0051a31e:	movl %eax, 0x5be7b0
0x0051a323:	xorl %eax, %ebp
0x0051a325:	pushl %eax
0x0051a326:	pushl -4(%ebp)
0x0051a329:	movl -4(%ebp), $0xffffffff<UINT32>
0x0051a330:	leal %eax, -12(%ebp)
0x0051a333:	movl %fs:0, %eax
0x0051a339:	ret

0x004a9260:	movl %esi, %ecx
0x004a9262:	movl -16(%ebp), %esi
0x004a9265:	call 0x00497463
0x004a926a:	xorl %ebx, %ebx
0x004a926c:	movl -4(%ebp), %ebx
0x004a926f:	leal %ecx, 0x1c(%esi)
0x004a9272:	movl (%esi), $0x582310<UINT32>
0x004a9278:	call 0x00485ddc
0x00485ddc:	pushl $0x4<UINT8>
0x00485dde:	movl %eax, $0x53e52b<UINT32>
0x00485de3:	call 0x0051a307
0x00485de8:	movl %esi, %ecx
0x00485dea:	movl -16(%ebp), %esi
0x00485ded:	call 0x00497463
0x00485df2:	andl -4(%ebp), $0x0<UINT8>
0x00485df6:	orl 0x4(%esi), $0xffffffff<UINT8>
0x00485dfa:	movl (%esi), $0x573d1c<UINT32>
0x00485e00:	movb 0x8(%esi), $0x0<UINT8>
0x00485e04:	orl -4(%ebp), $0xffffffff<UINT8>
0x00485e08:	movl %eax, %esi
0x00485e0a:	call 0x0051a3df
0x0051a3df:	movl %ecx, -12(%ebp)
0x0051a3e2:	movl %fs:0, %ecx
0x0051a3e9:	popl %ecx
0x0051a3ea:	popl %edi
0x0051a3eb:	popl %edi
0x0051a3ec:	popl %esi
0x0051a3ed:	popl %ebx
0x0051a3ee:	movl %esp, %ebp
0x0051a3f0:	popl %ebp
0x0051a3f1:	pushl %ecx
0x0051a3f2:	ret

0x00485e0f:	ret

0x004a927d:	movb -4(%ebp), $0x1<UINT8>
0x004a9281:	leal %ecx, 0x28(%esi)
0x004a9284:	call 0x0047e709
0x0047e709:	pushl $0x4<UINT8>
0x0047e70b:	movl %eax, $0x53e52b<UINT32>
0x0047e710:	call 0x0051a307
0x0047e715:	movl %esi, %ecx
0x0047e717:	movl -16(%ebp), %esi
0x0047e71a:	call 0x00497463
0x0047e71f:	xorl %eax, %eax
0x0047e721:	movl -4(%ebp), %eax
0x0047e724:	movl (%esi), $0x571fcc<UINT32>
0x0047e72a:	movl 0x4(%esi), %eax
0x0047e72d:	movl 0x8(%esi), %eax
0x0047e730:	orl -4(%ebp), $0xffffffff<UINT8>
0x0047e734:	movl %eax, %esi
0x0047e736:	call 0x0051a3df
0x0047e73b:	ret

0x004a9289:	movb -4(%ebp), $0x2<UINT8>
0x004a928d:	leal %ecx, 0x34(%esi)
0x004a9290:	call 0x0047e709
0x004a9295:	movb -4(%ebp), $0x3<UINT8>
0x004a9299:	movl 0x8(%esi), %ebx
0x004a929c:	movl 0xc(%esi), %ebx
0x004a929f:	movl 0x10(%esi), %ebx
0x004a92a2:	movl 0x14(%esi), %ebx
0x004a92a5:	movb 0x18(%esi), %bl
0x004a92a8:	movb 0x19(%esi), $0x1<UINT8>
0x004a92ac:	movb 0x1a(%esi), %bl
0x004a92af:	orl -4(%ebp), $0xffffffff<UINT8>
0x004a92b3:	movl %eax, %esi
0x004a92b5:	call 0x0051a3df
0x004a92ba:	ret

0x00482a5a:	movb -4(%ebp), $0x1<UINT8>
0x00482a5e:	leal %ecx, 0x60(%esi)
0x00482a61:	call 0x004a51b6
0x004a51b6:	pushl $0x4<UINT8>
0x004a51b8:	movl %eax, $0x53a8ac<UINT32>
0x004a51bd:	call 0x0051a307
0x004a51c2:	movl %esi, %ecx
0x004a51c4:	movl -16(%ebp), %esi
0x004a51c7:	call 0x00490552
0x00490552:	pushl $0x4<UINT8>
0x00490554:	movl %eax, $0x53e52b<UINT32>
0x00490559:	call 0x0051a307
0x0049055e:	movl %esi, %ecx
0x00490560:	movl -16(%ebp), %esi
0x00490563:	call 0x00497463
0x00490568:	xorl %eax, %eax
0x0049056a:	movl -4(%ebp), %eax
0x0049056d:	movl (%esi), $0x57530c<UINT32>
0x00490573:	movl 0x4(%esi), %eax
0x00490576:	movl 0x8(%esi), %eax
0x00490579:	movl 0xc(%esi), %eax
0x0049057c:	orl -4(%ebp), $0xffffffff<UINT8>
0x00490580:	movl %eax, %esi
0x00490582:	call 0x0051a3df
0x00490587:	ret

0x004a51cc:	andl -4(%ebp), $0x0<UINT8>
0x004a51d0:	movl (%esi), $0x581908<UINT32>
0x004a51d6:	orl -4(%ebp), $0xffffffff<UINT8>
0x004a51da:	movl %eax, %esi
0x004a51dc:	call 0x0051a3df
0x004a51e1:	ret

0x00482a66:	movb -4(%ebp), $0x2<UINT8>
0x00482a6a:	leal %ecx, 0x70(%esi)
0x00482a6d:	call 0x004a51b6
0x00482a72:	movb -4(%ebp), $0x3<UINT8>
0x00482a76:	leal %ecx, 0x80(%esi)
0x00482a7c:	call 0x0047e709
0x00482a81:	movb -4(%ebp), $0x4<UINT8>
0x00482a85:	leal %ecx, 0x8c(%esi)
0x00482a8b:	call 0x0047e709
0x00482a90:	movb -4(%ebp), $0x5<UINT8>
0x00482a94:	leal %ecx, 0x98(%esi)
0x00482a9a:	call 0x0047e709
0x00482a9f:	movb -4(%ebp), $0x6<UINT8>
0x00482aa3:	leal %ecx, 0xa4(%esi)
0x00482aa9:	call 0x0047e709
0x00482aae:	movb -4(%ebp), $0x7<UINT8>
0x00482ab2:	leal %ecx, 0xb0(%esi)
0x00482ab8:	call 0x0047e709
0x00482abd:	movb -4(%ebp), $0x8<UINT8>
0x00482ac1:	leal %ecx, 0xbc(%esi)
0x00482ac7:	call 0x0047e709
0x00482acc:	movb -4(%ebp), $0x9<UINT8>
0x00482ad0:	leal %ecx, 0xc8(%esi)
0x00482ad6:	call 0x0047e709
0x00482adb:	movb -4(%ebp), $0xa<UINT8>
0x00482adf:	leal %ecx, 0xd4(%esi)
0x00482ae5:	call 0x0047e709
0x00482aea:	movb -4(%ebp), $0xb<UINT8>
0x00482aee:	leal %ecx, 0xe0(%esi)
0x00482af4:	call 0x0047e709
0x00482af9:	movb -4(%ebp), $0xc<UINT8>
0x00482afd:	leal %ecx, 0xec(%esi)
0x00482b03:	call 0x0047e709
0x00482b08:	movb -4(%ebp), $0xd<UINT8>
0x00482b0c:	leal %ecx, 0xf8(%esi)
0x00482b12:	call 0x0047e709
0x00482b17:	movb -4(%ebp), $0xe<UINT8>
0x00482b1b:	leal %ecx, 0x104(%esi)
0x00482b21:	call 0x0047e709
0x00482b26:	movb -4(%ebp), $0xf<UINT8>
0x00482b2a:	leal %ecx, 0x110(%esi)
0x00482b30:	call 0x004a91d0
0x004a91d0:	pushl $0x4<UINT8>
0x004a91d2:	movl %eax, $0x53cba9<UINT32>
0x004a91d7:	call 0x0051a307
0x004a91dc:	movl %esi, %ecx
0x004a91de:	movl -16(%ebp), %esi
0x004a91e1:	call 0x00497463
0x004a91e6:	andl -4(%ebp), $0x0<UINT8>
0x004a91ea:	leal %ecx, 0x4(%esi)
0x004a91ed:	movl (%esi), $0x58226c<UINT32>
0x004a91f3:	call 0x0040b403
0x0040b403:	pushl $0x4<UINT8>
0x0040b405:	movl %eax, $0x53e52b<UINT32>
0x0040b40a:	call 0x0051a307
0x0040b40f:	movl %esi, %ecx
0x0040b411:	movl -16(%ebp), %esi
0x0040b414:	call 0x00497463
0x0040b419:	xorl %eax, %eax
0x0040b41b:	movl -4(%ebp), %eax
0x0040b41e:	movl (%esi), $0x544e48<UINT32>
0x0040b424:	movl 0x4(%esi), %eax
0x0040b427:	movl 0x8(%esi), %eax
0x0040b42a:	orl -4(%ebp), $0xffffffff<UINT8>
0x0040b42e:	movl %eax, %esi
0x0040b430:	call 0x0051a3df
0x0040b435:	ret

0x004a91f8:	orl -4(%ebp), $0xffffffff<UINT8>
0x004a91fc:	movl %eax, %esi
0x004a91fe:	call 0x0051a3df
0x004a9203:	ret

0x00482b35:	movb -4(%ebp), $0x10<UINT8>
0x00482b39:	leal %ecx, 0x120(%esi)
0x00482b3f:	call 0x0047e709
0x00482b44:	movb -4(%ebp), $0x11<UINT8>
0x00482b48:	leal %ecx, 0x12c(%esi)
0x00482b4e:	call 0x0047e709
0x00482b53:	movb -4(%ebp), $0x12<UINT8>
0x00482b57:	leal %ecx, 0x138(%esi)
0x00482b5d:	call 0x0047e709
0x00482b62:	movb -4(%ebp), $0x13<UINT8>
0x00482b66:	leal %edi, 0x144(%esi)
0x00482b6c:	movl %ecx, %edi
0x00482b6e:	call 0x00482480
0x00482480:	pushl $0x4<UINT8>
0x00482482:	movl %eax, $0x53e52b<UINT32>
0x00482487:	call 0x0051a307
0x0048248c:	movl %esi, %ecx
0x0048248e:	movl -16(%ebp), %esi
0x00482491:	call 0x00497463
0x00482496:	andl -4(%ebp), $0x0<UINT8>
0x0048249a:	andl 0x4(%esi), $0x0<UINT8>
0x0048249e:	movl (%esi), $0x573588<UINT32>
0x004824a4:	orl -4(%ebp), $0xffffffff<UINT8>
0x004824a8:	movl %eax, %esi
0x004824aa:	call 0x0051a3df
0x004824af:	ret

0x00482b73:	movb -4(%ebp), $0x14<UINT8>
0x00482b77:	orl 0x4(%esi), $0xffffffff<UINT8>
0x00482b7b:	orl 0x8(%esi), $0xffffffff<UINT8>
0x00482b7f:	movl 0xc(%esi), %ebx
0x00482b82:	movl 0x10(%esi), %ebx
0x00482b85:	movb 0x14(%esi), %bl
0x00482b88:	movl 0x1c(%esi), %ebx
0x00482b8b:	movl 0x18(%esi), %ebx
0x00482b8e:	movl 0x14c(%esi), %ebx
0x00482b94:	pushl $0x60<UINT8>
0x00482b96:	pushl $0xffffffff<UINT8>
0x00482b98:	leal %eax, 0x150(%esi)
0x00482b9e:	pushl %eax
0x00482b9f:	call 0x0051a4f0
0x00482ba4:	addl %esp, $0xc<UINT8>
0x00482ba7:	movb -4(%ebp), $0x15<UINT8>
0x00482bab:	pushl $0x549124<UINT32>
0x00482bb0:	movl %ecx, %edi
0x00482bb2:	call 0x0048260a
0x0048260a:	pushl %ebp
0x0048260b:	subl %esp, $0x108<UINT32>
0x00482611:	leal %ebp, -4(%esp)
0x00482615:	movl %eax, 0x5be7b0
0x0048261a:	xorl %eax, %ebp
0x0048261c:	movl 0x108(%ebp), %eax
0x00482622:	pushl $0x40<UINT8>
0x00482624:	movl %eax, $0x53a14d<UINT32>
0x00482629:	call 0x0051a307
0x0048262e:	movl %eax, 0x114(%ebp)
0x00482634:	movl %esi, $0x104<UINT32>
0x00482639:	xorl %ebx, %ebx
0x0048263b:	pushl %esi
0x0048263c:	movl -16(%ebp), %eax
0x0048263f:	leal %eax, 0x1(%ebp)
0x00482642:	pushl %ebx
0x00482643:	pushl %eax
0x00482644:	movl %edi, %ecx
0x00482646:	movb (%ebp), %bl
0x00482649:	call 0x0051a4f0
0x0051a52b:	subl %edx, %ecx
0x0051a52d:	movb (%edi), %al
0x0051a52f:	addl %edi, $0x1<UINT8>
0x0051a532:	subl %ecx, $0x1<UINT8>
0x0051a535:	jne 0x0051a52d
0x0048264e:	addl %esp, $0xc<UINT8>
0x00482651:	leal %ecx, -28(%ebp)
0x00482654:	call 0x0047e709
0x00482659:	movl -4(%ebp), %ebx
0x0048265c:	leal %ecx, -40(%ebp)
0x0048265f:	call 0x0047e709
0x00482664:	movb -4(%ebp), $0x1<UINT8>
0x00482668:	pushl %ebx
0x00482669:	pushl %ebx
0x0048266a:	pushl %ebx
0x0048266b:	pushl -16(%ebp)
0x0048266e:	leal %eax, -40(%ebp)
0x00482671:	pushl %eax
0x00482672:	pushl $0x9b<UINT32>
0x00482677:	movl %ecx, $0x5bfec0<UINT32>
0x0048267c:	call 0x00482f86
0x00482f86:	pushl %ebp
0x00482f87:	subl %esp, $0x200<UINT32>
0x00482f8d:	leal %ebp, -4(%esp)
0x00482f91:	movl %eax, 0x5be7b0
0x00482f96:	xorl %eax, %ebp
0x00482f98:	movl 0x200(%ebp), %eax
0x00482f9e:	pushl $0x50<UINT8>
0x00482fa0:	movl %eax, $0x53a3c9<UINT32>
0x00482fa5:	call 0x0051a33a
0x00482faa:	movl %edi, %ecx
0x00482fac:	movl %esi, 0x210(%ebp)
0x00482fb2:	movl -20(%ebp), %esi
0x00482fb5:	movl %eax, 0x214(%ebp)
0x00482fbb:	movl -28(%ebp), %eax
0x00482fbe:	movl %eax, 0x218(%ebp)
0x00482fc4:	movl -24(%ebp), %eax
0x00482fc7:	movl %eax, 0x21c(%ebp)
0x00482fcd:	movl -32(%ebp), %eax
0x00482fd0:	movl %eax, 0x220(%ebp)
0x00482fd6:	movl -36(%ebp), %eax
0x00482fd9:	leal %ecx, -52(%ebp)
0x00482fdc:	call 0x004a9f8b
0x004a9f8b:	pushl $0x4<UINT8>
0x004a9f8d:	movl %eax, $0x53e52b<UINT32>
0x004a9f92:	call 0x0051a307
0x004a9f97:	movl %esi, %ecx
0x004a9f99:	movl -16(%ebp), %esi
0x004a9f9c:	call 0x00497463
0x004a9fa1:	xorl %eax, %eax
0x004a9fa3:	movl -4(%ebp), %eax
0x004a9fa6:	movl (%esi), $0x582468<UINT32>
0x004a9fac:	movl 0x4(%esi), %eax
0x004a9faf:	movl 0x8(%esi), %eax
0x004a9fb2:	movl 0xc(%esi), %eax
0x004a9fb5:	orl -4(%ebp), $0xffffffff<UINT8>
0x004a9fb9:	movl %eax, %esi
0x004a9fbb:	call 0x0051a3df
0x004a9fc0:	ret

0x00482fe1:	xorl %ebx, %ebx
0x00482fe3:	movl -4(%ebp), %ebx
0x00482fe6:	leal %ecx, -92(%ebp)
0x00482fe9:	call 0x0048c3ec
0x0048c3ec:	pushl $0x4<UINT8>
0x0048c3ee:	movl %eax, $0x53b2a8<UINT32>
0x0048c3f3:	call 0x0051a307
0x0048c3f8:	movl %esi, %ecx
0x0048c3fa:	movl -16(%ebp), %esi
0x0048c3fd:	call 0x00497463
0x0048c402:	andl -4(%ebp), $0x0<UINT8>
0x0048c406:	leal %ecx, 0x4(%esi)
0x0048c409:	movl (%esi), $0x574c38<UINT32>
0x0048c40f:	call 0x0047e709
0x0048c414:	movb -4(%ebp), $0x1<UINT8>
0x0048c418:	leal %ecx, 0x10(%esi)
0x0048c41b:	call 0x00482480
0x0048c420:	movb -4(%ebp), $0x2<UINT8>
0x0048c424:	leal %ecx, 0x1c(%esi)
0x0048c427:	call 0x00482480
0x0048c42c:	movb -4(%ebp), $0x3<UINT8>
0x0048c430:	andl 0x18(%esi), $0x0<UINT8>
0x0048c434:	andl 0x24(%esi), $0x0<UINT8>
0x0048c438:	orl -4(%ebp), $0xffffffff<UINT8>
0x0048c43c:	movl %eax, %esi
0x0048c43e:	call 0x0051a3df
0x0048c443:	ret

0x00482fee:	movb -4(%ebp), $0x1<UINT8>
0x00482ff2:	movb (%ebp), %bl
0x00482ff5:	pushl $0x1ff<UINT32>
0x00482ffa:	pushl %ebx
0x00482ffb:	leal %eax, 0x1(%ebp)
0x00482ffe:	pushl %eax
0x00482fff:	call 0x0051a4f0
0x00483004:	addl %esp, $0xc<UINT8>
0x00483007:	movb -4(%ebp), $0x2<UINT8>
0x0048300b:	leal %eax, 0x8(%edi)
0x0048300e:	pushl %eax
0x0048300f:	leal %eax, 0x4(%edi)
0x00483012:	pushl %eax
0x00483013:	leal %ecx, -52(%ebp)
0x00483016:	call 0x004aa007
0x004aa007:	movl %eax, 0x4(%esp)
0x004aa00b:	pushl %esi
0x004aa00c:	movl %esi, %ecx
0x004aa00e:	movl %ecx, 0xc(%esp)
0x004aa012:	pushl %edi
0x004aa013:	pushl %eax
0x004aa014:	xorl %edi, %edi
0x004aa016:	movl 0x8(%esi), %eax
0x004aa019:	movl 0xc(%esi), %ecx
0x004aa01c:	call InterlockedIncrement@KERNEL32.DLL
0x004aa022:	testl %eax, %eax
0x004aa024:	jne 26
0x004aa026:	call GetCurrentThreadId@KERNEL32.DLL
0x004aa02c:	pushl %eax
0x004aa02d:	pushl 0xc(%esi)
0x004aa030:	call InterlockedExchange@KERNEL32.DLL
InterlockedExchange@KERNEL32.DLL: API Node	
0x004aa036:	xorl %eax, %eax
0x004aa038:	incl %eax
0x004aa039:	movl 0x4(%esi), %eax
0x004aa03c:	movl %edi, %eax
0x004aa03e:	jmp 0x004aa052
0x004aa052:	movl %eax, %edi
0x004aa054:	popl %edi
0x004aa055:	popl %esi
0x004aa056:	ret $0x8<UINT16>

0x0048301b:	testl %eax, %eax
0x0048301d:	je 229
0x00483023:	pushl $0x5735cc<UINT32>
0x00483028:	movl %ecx, %esi
0x0048302a:	call 0x0047ed08
0x0047ed08:	pushl %ebp
0x0047ed09:	movl %ebp, %esp
0x0047ed0b:	pushl %ecx
0x0047ed0c:	pushl %ebx
0x0047ed0d:	movl %ebx, 0x8(%ebp)
0x0047ed10:	pushl %esi
0x0047ed11:	movl %esi, %ecx
0x0047ed13:	cmpl 0x4(%esi), %ebx
0x0047ed16:	je 144
0x0047ed1c:	pushl %edi
0x0047ed1d:	testl %ebx, %ebx
0x0047ed1f:	je 129
0x0047ed25:	pushl %ebx
0x0047ed26:	call lstrlenA@KERNEL32.DLL
lstrlenA@KERNEL32.DLL: API Node	
0x0047ed2c:	movl %edi, %eax
0x0047ed2e:	incl %edi
0x0047ed2f:	cmpl %edi, 0x8(%esi)
0x0047ed32:	jae 0x0047ed4e
0x0047ed4e:	movl %eax, %edi
0x0047ed50:	movl -4(%ebp), %eax
0x0047ed53:	fildl -4(%ebp)
0x0047ed56:	testl %eax, %eax
0x0047ed58:	jnl 0x0047ed60
0x0047ed60:	fmull 0x571fd0
0x0047ed66:	call 0x0051b456
0x0051b456:	pushl %ebp
0x0051b457:	movl %ebp, %esp
0x0051b459:	subl %esp, $0x20<UINT8>
0x0051b45c:	andl %esp, $0xfffffff0<UINT8>
0x0051b45f:	fld %st0
0x0051b461:	fsts 0x18(%esp)
0x0051b465:	fistpll 0x10(%esp)
0x0051b469:	fildll 0x10(%esp)
0x0051b46d:	movl %edx, 0x18(%esp)
0x0051b471:	movl %eax, 0x10(%esp)
0x0051b475:	testl %eax, %eax
0x0051b477:	je 60
0x0051b479:	fsubp %st1, %st0
0x0051b47b:	testl %edx, %edx
0x0051b47d:	jns 0x0051b49d
0x0051b49d:	fstps (%esp)
0x0051b4a0:	movl %ecx, (%esp)
0x0051b4a3:	addl %ecx, $0x7fffffff<UINT32>
0x0051b4a9:	sbbl %eax, $0x0<UINT8>
0x0051b4ac:	movl %edx, 0x14(%esp)
0x0051b4b0:	sbbl %edx, $0x0<UINT8>
0x0051b4b3:	jmp 0x0051b4c9
0x0051b4c9:	leave
0x0051b4ca:	ret

0x0047ed6b:	pushl %eax
0x0047ed6c:	movl -4(%ebp), %eax
0x0047ed6f:	call 0x00519ee8
0x00519ee8:	movl %edi, %edi
0x00519eea:	pushl %ebp
0x00519eeb:	movl %ebp, %esp
0x00519eed:	popl %ebp
0x00519eee:	jmp 0x0051a56a
0x0051a56a:	movl %edi, %edi
0x0051a56c:	pushl %ebp
0x0051a56d:	movl %ebp, %esp
0x0051a56f:	subl %esp, $0xc<UINT8>
0x0051a572:	jmp 0x0051a581
0x0051a581:	pushl 0x8(%ebp)
0x0051a584:	call 0x0051c822
0x0051a589:	popl %ecx
0x0051a58a:	testl %eax, %eax
0x0051a58c:	je -26
0x0051a58e:	leave
0x0051a58f:	ret

0x0047ed74:	movl %ebx, %eax
0x0047ed76:	movl %eax, -4(%ebp)
0x0047ed79:	pushl %eax
0x0047ed7a:	pushl $0x0<UINT8>
0x0047ed7c:	pushl %ebx
0x0047ed7d:	movl 0x8(%esi), %eax
0x0047ed80:	call 0x0051a4f0
0x0047ed85:	addl %esp, $0x10<UINT8>
0x0047ed88:	pushl %edi
0x0047ed89:	pushl 0x8(%ebp)
0x0047ed8c:	pushl %ebx
0x0047ed8d:	call lstrcpynA@KERNEL32.DLL
lstrcpynA@KERNEL32.DLL: API Node	
0x0047ed93:	movb -1(%ebx,%edi), $0x0<UINT8>
0x0047ed98:	pushl 0x4(%esi)
0x0047ed9b:	call 0x0051a955
0x0051a955:	movl %edi, %edi
0x0051a957:	pushl %ebp
0x0051a958:	movl %ebp, %esp
0x0051a95a:	popl %ebp
0x0051a95b:	jmp 0x0051a4e5
0x0051a4e5:	movl %edi, %edi
0x0051a4e7:	pushl %ebp
0x0051a4e8:	movl %ebp, %esp
0x0051a4ea:	popl %ebp
0x0051a4eb:	jmp 0x0051c745
0x0047eda0:	popl %ecx
0x0047eda1:	movl 0x4(%esi), %ebx
0x0047eda4:	jmp 0x0047edab
0x0047edab:	popl %edi
0x0047edac:	movl %eax, %esi
0x0047edae:	popl %esi
0x0047edaf:	popl %ebx
0x0047edb0:	leave
0x0047edb1:	ret $0x4<UINT16>

0x0048302f:	movl %esi, $0x200<UINT32>
0x00483034:	pushl %esi
0x00483035:	pushl %ebx
0x00483036:	leal %eax, (%ebp)
0x00483039:	pushl %eax
0x0048303a:	call 0x0051a4f0
0x0048303f:	addl %esp, $0xc<UINT8>
0x00483042:	leal %ebx, 0x60(%edi)
0x00483045:	movl %ecx, %ebx
0x00483047:	call 0x004905c3
0x004905c3:	movl %eax, 0x4(%ecx)
0x004905c6:	movl 0xc(%ecx), %eax
0x004905c9:	ret

0x0048304c:	movl %ecx, %ebx
0x0048304e:	call 0x004a521d
0x004a521d:	call 0x00490620
0x00490620:	movl %eax, 0xc(%ecx)
0x00490623:	testl %eax, %eax
0x00490625:	je 0x0049062a
0x0049062a:	xorl %eax, %eax
0x0049062c:	ret

0x004a5222:	testl %eax, %eax
0x004a5224:	je 0x004a522a
0x004a522a:	xorl %eax, %eax
0x004a522c:	ret

0x00483053:	movl %ecx, %ebx
0x00483055:	cmpl 0x20c(%ebp), %eax
0x0048305b:	jne 0x0048307b
0x0048307b:	call 0x00490588
0x00490588:	movl %edx, 0xc(%ecx)
0x0049058b:	xorb %al, %al
0x0049058d:	testl %edx, %edx
0x0049058f:	je 0x0049059d
0x0049059d:	ret

0x00483080:	cmpb %al, $0x1<UINT8>
0x00483082:	je -56
0x00483084:	movb 0x1ff(%ebp), $0x0<UINT8>
0x0048308b:	addl %edi, $0x70<UINT8>
0x0048308e:	movl %ecx, %edi
0x00483090:	call 0x004905c3
0x00483095:	movl %ecx, %edi
0x00483097:	call 0x004a521d
0x0048309c:	movl %ecx, %edi
0x0048309e:	cmpl 0x20c(%ebp), %eax
0x004830a4:	jne 0x004830c4
0x004830c4:	call 0x00490588
0x004830c9:	cmpb %al, $0x1<UINT8>
0x004830cb:	je -56
0x004830cd:	movb 0x1ff(%ebp), $0x0<UINT8>
0x004830d4:	pushl -36(%ebp)
0x004830d7:	pushl -32(%ebp)
0x004830da:	pushl -24(%ebp)
0x004830dd:	pushl -28(%ebp)
0x004830e0:	leal %eax, (%ebp)
0x004830e3:	pushl %eax
0x004830e4:	leal %ecx, -92(%ebp)
0x004830e7:	call 0x0048ccc9
0x0048ccc9:	pushl %ebp
0x0048ccca:	movl %ebp, %esp
0x0048cccc:	pushl %ebx
0x0048cccd:	pushl %esi
0x0048ccce:	pushl %edi
0x0048cccf:	pushl 0x8(%ebp)
0x0048ccd2:	leal %esi, 0x4(%ecx)
0x0048ccd5:	movl %ecx, %esi
0x0048ccd7:	call 0x0047ed08
0x0048ccdc:	xorl %ebx, %ebx
0x0048ccde:	movl %edi, $0x574c9c<UINT32>
0x0048cce3:	pushl %ebx
0x0048cce4:	movl %ecx, %esi
0x0048cce6:	cmpl 0xc(%ebp), %ebx
0x0048cce9:	je 5
0x0048cceb:	pushl 0xc(%ebp)
0x0048ccee:	jmp 0x0048ccf1
0x0048ccf1:	pushl $0x574c98<UINT32>
0x0048ccf6:	call 0x0047f746
0x0047f746:	pushl $0x20<UINT8>
0x0047f748:	movl %eax, $0x539e6a<UINT32>
0x0047f74d:	call 0x0051a307
0x0047f752:	movl %esi, %ecx
0x0047f754:	leal %ecx, -44(%ebp)
0x0047f757:	call 0x0040b436
0x0040b436:	pushl $0x4<UINT8>
0x0040b438:	movl %eax, $0x53e52b<UINT32>
0x0040b43d:	call 0x0051a307
0x0040b442:	movl %esi, %ecx
0x0040b444:	movl -16(%ebp), %esi
0x0040b447:	call 0x00497463
0x0040b44c:	xorl %eax, %eax
0x0040b44e:	movl -4(%ebp), %eax
0x0040b451:	movl (%esi), $0x544e8c<UINT32>
0x0040b457:	movl 0x4(%esi), %eax
0x0040b45a:	movl 0x8(%esi), %eax
0x0040b45d:	orl -4(%ebp), $0xffffffff<UINT8>
0x0040b461:	movl %eax, %esi
0x0040b463:	call 0x0051a3df
0x0040b468:	ret

0x0047f75c:	xorl %ebx, %ebx
0x0047f75e:	movl -4(%ebp), %ebx
0x0047f761:	cmpl 0x4(%esi), %ebx
0x0047f764:	jne 0x0047f77c
0x0047f77c:	cmpl 0x8(%ebp), %ebx
0x0047f77f:	je -27
0x0047f781:	cmpl 0xc(%ebp), %ebx
0x0047f784:	je -32
0x0047f786:	pushl 0x8(%ebp)
0x0047f789:	movl %edi, 0x542434
0x0047f78f:	call lstrlenA@KERNEL32.DLL
0x0047f791:	movl -32(%ebp), %eax
0x0047f794:	cmpl %eax, %ebx
0x0047f796:	jne 0x0047f7aa
0x0047f7aa:	leal %eax, -44(%ebp)
0x0047f7ad:	pushl %eax
0x0047f7ae:	pushl 0x10(%ebp)
0x0047f7b1:	movl %ecx, %esi
0x0047f7b3:	pushl 0x8(%ebp)
0x0047f7b6:	call 0x0047f654
0x0047f654:	pushl %ebp
0x0047f655:	movl %ebp, %esp
0x0047f657:	pushl %ecx
0x0047f658:	pushl %ecx
0x0047f659:	pushl %ebx
0x0047f65a:	pushl %esi
0x0047f65b:	movl %esi, %ecx
0x0047f65d:	movl %ecx, 0x10(%ebp)
0x0047f660:	xorl %ebx, %ebx
0x0047f662:	pushl %ebx
0x0047f663:	call 0x004c52d9
0x004c52d9:	pushl %ebx
0x004c52da:	movl %ebx, 0x8(%esp)
0x004c52de:	pushl %esi
0x004c52df:	movl %esi, %ecx
0x004c52e1:	testl %ebx, %ebx
0x004c52e3:	jne 14
0x004c52e5:	pushl 0x4(%esi)
0x004c52e8:	call 0x0051a955
0x004c52ed:	andl 0x4(%esi), %ebx
0x004c52f0:	popl %ecx
0x004c52f1:	jmp 0x004c5356
0x004c5356:	movl 0x8(%esi), %ebx
0x004c5359:	popl %esi
0x004c535a:	popl %ebx
0x004c535b:	ret $0x4<UINT16>

0x0047f668:	cmpl 0x4(%esi), %ebx
0x0047f66b:	jne 0x0047f674
0x0047f674:	cmpl 0x8(%ebp), %ebx
0x0047f677:	je -12
0x0047f679:	pushl %edi
0x0047f67a:	movl %ecx, %esi
0x0047f67c:	call 0x0047e850
0x0047e850:	movl %eax, 0x4(%ecx)
0x0047e853:	pushl %esi
0x0047e854:	xorl %esi, %esi
0x0047e856:	testl %eax, %eax
0x0047e858:	je 13
0x0047e85a:	pushl %eax
0x0047e85b:	call lstrlenA@KERNEL32.DLL
0x0047e861:	testl %eax, %eax
0x0047e863:	jle 0x0047e867
0x0047e867:	movl %eax, %esi
0x0047e869:	popl %esi
0x0047e86a:	ret

0x0047f681:	pushl 0x8(%ebp)
0x0047f684:	movl -8(%ebp), %eax
0x0047f687:	call lstrlenA@KERNEL32.DLL
0x0047f68d:	movl %edi, %eax
0x0047f68f:	cmpl -8(%ebp), %ebx
0x0047f692:	je 0x0047f6de
0x0047f6de:	xorl %eax, %eax
0x0047f6e0:	jmp 0x0047f73f
0x0047f73f:	popl %edi
0x0047f740:	popl %esi
0x0047f741:	popl %ebx
0x0047f742:	leave
0x0047f743:	ret $0xc<UINT16>

0x0047f7bb:	cmpl -36(%ebp), %ebx
0x0047f7be:	jbe 0x0047f8a8
0x0047f8a8:	movl %esi, -36(%ebp)
0x0047f8ab:	jmp 0x0047f79a
0x0047f79a:	orl -4(%ebp), $0xffffffff<UINT8>
0x0047f79e:	leal %ecx, -44(%ebp)
0x0047f7a1:	call 0x0040cd04
0x0040cd04:	pushl $0x4<UINT8>
0x0040cd06:	movl %eax, $0x53e52b<UINT32>
0x0040cd0b:	call 0x0051a307
0x0040cd10:	movl %esi, %ecx
0x0040cd12:	movl -16(%ebp), %esi
0x0040cd15:	movl (%esi), $0x544e8c<UINT32>
0x0040cd1b:	andl -4(%ebp), $0x0<UINT8>
0x0040cd1f:	pushl $0x0<UINT8>
0x0040cd21:	call 0x004c52d9
0x0040cd26:	orl -4(%ebp), $0xffffffff<UINT8>
0x0040cd2a:	movl %ecx, %esi
0x0040cd2c:	call 0x0049746c
0x0049746c:	movl (%ecx), $0x57e324<UINT32>
0x00497472:	ret

0x0040cd31:	call 0x0051a3df
0x0040cd36:	ret

0x0047f7a6:	movl %eax, %esi
0x0047f7a8:	jmp 0x0047f774
0x0047f774:	call 0x0051a3df
0x0047f779:	ret $0xc<UINT16>

0x0048ccfb:	pushl %ebx
0x0048ccfc:	movl %ecx, %esi
0x0048ccfe:	cmpl 0x10(%ebp), %ebx
0x0048cd01:	je 0x0048cd08
0x0048cd08:	pushl %edi
0x0048cd09:	pushl $0x574c94<UINT32>
0x0048cd0e:	call 0x0047f746
0x0048cd13:	pushl %ebx
0x0048cd14:	movl %ecx, %esi
0x0048cd16:	cmpl 0x14(%ebp), %ebx
0x0048cd19:	je 0x0048cd20
0x0048cd20:	pushl %edi
0x0048cd21:	pushl $0x574c90<UINT32>
0x0048cd26:	call 0x0047f746
0x0048cd2b:	pushl %ebx
0x0048cd2c:	movl %ecx, %esi
0x0048cd2e:	cmpl 0x18(%ebp), %ebx
0x0048cd31:	je 0x0048cd38
0x0048cd38:	pushl %edi
0x0048cd39:	pushl $0x574c8c<UINT32>
0x0048cd3e:	call 0x0047f746
0x0048cd43:	popl %edi
0x0048cd44:	movl %eax, %esi
0x0048cd46:	popl %esi
0x0048cd47:	popl %ebx
0x0048cd48:	popl %ebp
0x0048cd49:	ret $0x14<UINT16>

0x004830ec:	pushl %eax
0x004830ed:	movl %ecx, -20(%ebp)
0x004830f0:	call 0x0047f5f2
0x0047f5f2:	movl %eax, 0x4(%esp)
0x0047f5f6:	pushl %esi
0x0047f5f7:	movl %esi, %ecx
0x0047f5f9:	cmpl %esi, %eax
0x0047f5fb:	je 8
0x0047f5fd:	pushl 0x4(%eax)
0x0047f600:	call 0x0047ed08
0x0051c86f:	xorl %eax, %eax
0x0051c871:	incl %eax
0x0051a565:	movl %eax, 0x4(%esp)
0x0051a569:	ret

0x0047f605:	movl %eax, %esi
0x0047f607:	popl %esi
0x0047f608:	ret $0x4<UINT16>

0x004830f5:	pushl $0x3f<UINT8>
0x004830f7:	pushl $0x25<UINT8>
0x004830f9:	movl %ecx, -20(%ebp)
0x004830fc:	call 0x0047e9e1
0x0047e9e1:	pushl %esi
0x0047e9e2:	movl %esi, %ecx
0x0047e9e4:	cmpl 0x4(%esi), $0x0<UINT8>
0x0047e9e8:	je 40
0x0047e9ea:	pushl %edi
0x0047e9eb:	call 0x0047e850
0x0047e9f0:	movl %edi, %eax
0x0047e9f2:	xorl %edx, %edx
0x0047e9f4:	testl %edi, %edi
0x0047e9f6:	jbe 0x0047ea11
0x0047ea11:	popl %edi
0x0047ea12:	movl %eax, %esi
0x0047ea14:	popl %esi
0x0047ea15:	ret $0x8<UINT16>

0x00483101:	movl -4(%ebp), $0x1<UINT32>
0x00483108:	movb -4(%ebp), $0x0<UINT8>
0x0048310c:	leal %ecx, -92(%ebp)
0x0048310f:	call 0x0048c444
0x0048c444:	pushl $0x4<UINT8>
0x0048c446:	movl %eax, $0x53b2a8<UINT32>
0x0048c44b:	call 0x0051a307
0x0048c450:	movl %esi, %ecx
0x0048c452:	movl -16(%ebp), %esi
0x0048c455:	movl (%esi), $0x574c38<UINT32>
0x0048c45b:	movl -4(%ebp), $0x2<UINT32>
0x0048c462:	leal %ecx, 0x1c(%esi)
0x0048c465:	call 0x004824b0
0x004824b0:	pushl $0x4<UINT8>
0x004824b2:	movl %eax, $0x53e52b<UINT32>
0x004824b7:	call 0x0051a307
0x004824bc:	movl %esi, %ecx
0x004824be:	movl -16(%ebp), %esi
0x004824c1:	movl (%esi), $0x573588<UINT32>
0x004824c7:	andl -4(%ebp), $0x0<UINT8>
0x004824cb:	movl %eax, 0x4(%esi)
0x004824ce:	testl %eax, %eax
0x004824d0:	je 0x004824dd
0x004824dd:	orl -4(%ebp), $0xffffffff<UINT8>
0x004824e1:	movl %ecx, %esi
0x004824e3:	call 0x0049746c
0x004824e8:	call 0x0051a3df
0x004824ed:	ret

0x0048c46a:	movb -4(%ebp), $0x1<UINT8>
0x0048c46e:	leal %ecx, 0x10(%esi)
0x0048c471:	call 0x004824b0
0x0048c476:	movb -4(%ebp), $0x0<UINT8>
0x0048c47a:	leal %ecx, 0x4(%esi)
0x0048c47d:	call 0x0047e73c
0x0047e73c:	pushl $0x4<UINT8>
0x0047e73e:	movl %eax, $0x53e52b<UINT32>
0x0047e743:	call 0x0051a307
0x0047e748:	movl %esi, %ecx
0x0047e74a:	movl -16(%ebp), %esi
0x0047e74d:	movl (%esi), $0x571fcc<UINT32>
0x0047e753:	andl -4(%ebp), $0x0<UINT8>
0x0047e757:	movl %eax, 0x4(%esi)
0x0047e75a:	testl %eax, %eax
0x0047e75c:	je 7
0x0047e75e:	pushl %eax
0x0047e75f:	call 0x0051a955
0x0047e764:	popl %ecx
0x0047e765:	andl 0x4(%esi), $0x0<UINT8>
0x0047e769:	andl 0x8(%esi), $0x0<UINT8>
0x0047e76d:	orl -4(%ebp), $0xffffffff<UINT8>
0x0047e771:	movl %ecx, %esi
0x0047e773:	call 0x0049746c
0x0047e778:	call 0x0051a3df
0x0047e77d:	ret

0x0048c482:	orl -4(%ebp), $0xffffffff<UINT8>
0x0048c486:	movl %ecx, %esi
0x0048c488:	call 0x0049746c
0x0048c48d:	call 0x0051a3df
0x0048c492:	ret

0x00483114:	orl -4(%ebp), $0xffffffff<UINT8>
0x00483118:	leal %ecx, -52(%ebp)
0x0048311b:	call 0x004a9fc1
0x004a9fc1:	pushl $0x4<UINT8>
0x004a9fc3:	movl %eax, $0x53e52b<UINT32>
0x004a9fc8:	call 0x0051a307
0x004a9fcd:	movl %esi, %ecx
0x004a9fcf:	movl -16(%ebp), %esi
0x004a9fd2:	movl (%esi), $0x582468<UINT32>
0x004a9fd8:	andl -4(%ebp), $0x0<UINT8>
0x004a9fdc:	cmpl 0x4(%esi), $0x0<UINT8>
0x004a9fe0:	je 20
0x004a9fe2:	movl %edi, 0x542228
0x004a9fe8:	pushl $0xffffffff<UINT8>
0x004a9fea:	pushl 0xc(%esi)
0x004a9fed:	call InterlockedExchange@KERNEL32.DLL
0x004a9fef:	pushl $0xffffffff<UINT8>
0x004a9ff1:	pushl 0x8(%esi)
0x004a9ff4:	call InterlockedExchange@KERNEL32.DLL
0x004a9ff6:	orl -4(%ebp), $0xffffffff<UINT8>
0x004a9ffa:	movl %ecx, %esi
0x004a9ffc:	call 0x0049746c
0x004aa001:	call 0x0051a3df
0x004aa006:	ret

0x00483120:	movl %ecx, -12(%ebp)
0x00483123:	movl %fs:0, %ecx
0x0048312a:	popl %ecx
0x0048312b:	popl %edi
0x0048312c:	popl %esi
0x0048312d:	popl %ebx
0x0048312e:	movl %ecx, 0x200(%ebp)
0x00483134:	xorl %ecx, %ebp
0x00483136:	call 0x0051a2f8
0x0048313b:	addl %ebp, $0x204<UINT32>
0x00483141:	leave
0x00483142:	ret $0x18<UINT16>

0x00482681:	pushl -16(%ebp)
0x00482684:	leal %ecx, -28(%ebp)
0x00482687:	call 0x0047ed08
0x0048268c:	leal %ecx, -28(%ebp)
0x0048268f:	call 0x0047f5df
0x0047f5df:	pushl %esi
0x0047f5e0:	movl %esi, %ecx
0x0047f5e2:	call 0x0047f1b0
0x0047f1b0:	pushl %ebp
0x0047f1b1:	movl %ebp, %esp
0x0047f1b3:	pushl %ecx
0x0047f1b4:	pushl %ebx
0x0047f1b5:	movl %ebx, %ecx
0x0047f1b7:	movl %eax, 0x4(%ebx)
0x0047f1ba:	testl %eax, %eax
0x0047f1bc:	je 84
0x0047f1be:	pushl %esi
0x0047f1bf:	pushl %edi
0x0047f1c0:	pushl %eax
0x0047f1c1:	xorl %esi, %esi
0x0047f1c3:	call lstrlenA@KERNEL32.DLL
0x0047f1c9:	movl %edi, %eax
0x0047f1cb:	xorl %edx, %edx
0x0047f1cd:	cmpl %edi, %edx
0x0047f1cf:	jle 63
0x0047f1d1:	movl %ecx, 0x4(%ebx)
0x0047f1d4:	movb %al, (%ecx,%esi)
0x0047f1d7:	decb %al
0x0047f1d9:	cmpb %al, $0x1f<UINT8>
0x0047f1db:	ja 0x0047f1e2
0x0047f1e2:	cmpl %esi, %edx
0x0047f1e4:	jle 0x0047f210
0x0047f210:	popl %edi
0x0047f211:	popl %esi
0x0047f212:	movl %eax, %ebx
0x0047f214:	popl %ebx
0x0047f215:	leave
0x0047f216:	ret

0x0047f5e7:	movl %ecx, %esi
0x0047f5e9:	call 0x0047f351
0x0047f351:	pushl %esi
0x0047f352:	movl %esi, %ecx
0x0047f354:	movl %eax, 0x4(%esi)
0x0047f357:	testl %eax, %eax
0x0047f359:	je 36
0x0047f35b:	pushl %eax
0x0047f35c:	call lstrlenA@KERNEL32.DLL
0x0047f362:	testl %eax, %eax
0x0047f364:	jle 25
0x0047f366:	jmp 0x0047f37a
0x0047f37a:	decl %eax
0x0047f37b:	testl %eax, %eax
0x0047f37d:	jg 0x0047f368
0x0047f368:	movl %ecx, 0x4(%esi)
0x0047f36b:	leal %edx, (%eax,%ecx)
0x0047f36e:	movb %cl, (%edx)
0x0047f370:	decb %cl
0x0047f372:	cmpb %cl, $0x1f<UINT8>
0x0047f375:	ja 0x0047f37f
0x0047f37f:	movl %eax, %esi
0x0047f381:	popl %esi
0x0047f382:	ret

0x0047f5ee:	movl %eax, %esi
0x0047f5f0:	popl %esi
0x0047f5f1:	ret

0x00482694:	leal %ecx, -28(%ebp)
0x00482697:	call 0x0047e850
0x0047e865:	movl %esi, %eax
0x0048269c:	testl %eax, %eax
0x0048269e:	je 55
0x004826a0:	leal %ecx, -28(%ebp)
0x004826a3:	call 0x0047e850
0x004826a8:	cmpl %eax, %esi
0x004826aa:	ja 43
0x004826ac:	pushl $0x105<UINT32>
0x004826b1:	leal %eax, (%ebp)
0x004826b4:	pushl %ebx
0x004826b5:	pushl %eax
0x004826b6:	call 0x0051a4f0
0x004826bb:	addl %esp, $0xc<UINT8>
0x004826be:	pushl %esi
0x004826bf:	leal %eax, (%ebp)
0x004826c2:	pushl %eax
0x004826c3:	leal %ecx, -28(%ebp)
0x004826c6:	call 0x0047e77e
0x0047e77e:	movl %edx, 0x4(%ecx)
0x0047e781:	testl %edx, %edx
0x0047e783:	je 12
0x0047e785:	movl %eax, 0x8(%ecx)
0x0047e788:	testl %eax, %eax
0x0047e78a:	je 5
0x0047e78c:	movb -1(%eax,%edx), $0x0<UINT8>
0x0047e791:	movl %eax, 0x4(%ecx)
0x0047e794:	ret

0x004826cb:	pushl %eax
0x004826cc:	movl %ecx, %edi
0x004826ce:	call 0x004824ee
0x004824ee:	pushl %ebp
0x004824ef:	leal %ebp, -152(%esp)
0x004824f6:	subl %esp, $0x118<UINT32>
0x004824fc:	movl %eax, 0x5be7b0
0x00482501:	xorl %eax, %ebp
0x00482503:	movl 0x94(%ebp), %eax
0x00482509:	movl %eax, 0xa0(%ebp)
0x0048250f:	pushl %ebx
0x00482510:	pushl %esi
0x00482511:	pushl %edi
0x00482512:	movl %edi, 0xa4(%ebp)
0x00482518:	xorl %ebx, %ebx
0x0048251a:	movl %esi, $0x104<UINT32>
0x0048251f:	pushl %esi
0x00482520:	movl -124(%ebp), %eax
0x00482523:	leal %eax, -115(%ebp)
0x00482526:	pushl %ebx
0x00482527:	pushl %eax
0x00482528:	movb -117(%ebp), %bl
0x0048252b:	movb -116(%ebp), %bl
0x0048252e:	call 0x0051a4f0
0x00482533:	addl %esp, $0xc<UINT8>
0x00482536:	cmpl -124(%ebp), %ebx
0x00482539:	jne 0x00482542
0x00482542:	pushl -124(%ebp)
0x00482545:	call lstrlenA@KERNEL32.DLL
0x0048254b:	testl %eax, %eax
0x0048254d:	je -20
0x0048254f:	cmpl %edi, %ebx
0x00482551:	je -24
0x00482553:	cmpl 0xa8(%ebp), %ebx
0x00482559:	je -32
0x0048255b:	pushl 0xa8(%ebp)
0x00482561:	pushl %ebx
0x00482562:	pushl %edi
0x00482563:	call 0x0051a4f0
0x00482568:	pushl $0x105<UINT32>
0x0048256d:	leal %eax, -116(%ebp)
0x00482570:	pushl %ebx
0x00482571:	pushl %eax
0x00482572:	call 0x0051a4f0
