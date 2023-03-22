0x00425900:	pusha
0x00425901:	movl %esi, $0x41e000<UINT32>
0x00425906:	leal %edi, -118784(%esi)
0x0042590c:	pushl %edi
0x0042590d:	orl %ebp, $0xffffffff<UINT8>
0x00425910:	jmp 0x00425922
0x00425922:	movl %ebx, (%esi)
0x00425924:	subl %esi, $0xfffffffc<UINT8>
0x00425927:	adcl %ebx, %ebx
0x00425929:	jb 0x00425918
0x00425918:	movb %al, (%esi)
0x0042591a:	incl %esi
0x0042591b:	movb (%edi), %al
0x0042591d:	incl %edi
0x0042591e:	addl %ebx, %ebx
0x00425920:	jne 0x00425929
0x0042592b:	movl %eax, $0x1<UINT32>
0x00425930:	addl %ebx, %ebx
0x00425932:	jne 0x0042593b
0x0042593b:	adcl %eax, %eax
0x0042593d:	addl %ebx, %ebx
0x0042593f:	jae 0x00425930
0x00425941:	jne 0x0042594c
0x0042594c:	xorl %ecx, %ecx
0x0042594e:	subl %eax, $0x3<UINT8>
0x00425951:	jb 0x00425960
0x00425960:	addl %ebx, %ebx
0x00425962:	jne 0x0042596b
0x0042596b:	adcl %ecx, %ecx
0x0042596d:	addl %ebx, %ebx
0x0042596f:	jne 0x00425978
0x00425978:	adcl %ecx, %ecx
0x0042597a:	jne 0x0042599c
0x0042597c:	incl %ecx
0x0042597d:	addl %ebx, %ebx
0x0042597f:	jne 0x00425988
0x00425988:	adcl %ecx, %ecx
0x0042598a:	addl %ebx, %ebx
0x0042598c:	jae 0x0042597d
0x0042598e:	jne 0x00425999
0x00425999:	addl %ecx, $0x2<UINT8>
0x0042599c:	cmpl %ebp, $0xfffff300<UINT32>
0x004259a2:	adcl %ecx, $0x1<UINT8>
0x004259a5:	leal %edx, (%edi,%ebp)
0x004259a8:	cmpl %ebp, $0xfffffffc<UINT8>
0x004259ab:	jbe 0x004259bc
0x004259ad:	movb %al, (%edx)
0x004259af:	incl %edx
0x004259b0:	movb (%edi), %al
0x004259b2:	incl %edi
0x004259b3:	decl %ecx
0x004259b4:	jne 0x004259ad
0x004259b6:	jmp 0x0042591e
0x00425953:	shll %eax, $0x8<UINT8>
0x00425956:	movb %al, (%esi)
0x00425958:	incl %esi
0x00425959:	xorl %eax, $0xffffffff<UINT8>
0x0042595c:	je 0x004259d2
0x0042595e:	movl %ebp, %eax
0x004259bc:	movl %eax, (%edx)
0x004259be:	addl %edx, $0x4<UINT8>
0x004259c1:	movl (%edi), %eax
0x004259c3:	addl %edi, $0x4<UINT8>
0x004259c6:	subl %ecx, $0x4<UINT8>
0x004259c9:	ja 0x004259bc
0x004259cb:	addl %edi, %ecx
0x004259cd:	jmp 0x0042591e
0x00425943:	movl %ebx, (%esi)
0x00425945:	subl %esi, $0xfffffffc<UINT8>
0x00425948:	adcl %ebx, %ebx
0x0042594a:	jae 0x00425930
0x00425934:	movl %ebx, (%esi)
0x00425936:	subl %esi, $0xfffffffc<UINT8>
0x00425939:	adcl %ebx, %ebx
0x00425964:	movl %ebx, (%esi)
0x00425966:	subl %esi, $0xfffffffc<UINT8>
0x00425969:	adcl %ebx, %ebx
0x00425971:	movl %ebx, (%esi)
0x00425973:	subl %esi, $0xfffffffc<UINT8>
0x00425976:	adcl %ebx, %ebx
0x00425981:	movl %ebx, (%esi)
0x00425983:	subl %esi, $0xfffffffc<UINT8>
0x00425986:	adcl %ebx, %ebx
0x00425990:	movl %ebx, (%esi)
0x00425992:	subl %esi, $0xfffffffc<UINT8>
0x00425995:	adcl %ebx, %ebx
0x00425997:	jae 0x0042597d
0x004259d2:	popl %esi
0x004259d3:	movl %edi, %esi
0x004259d5:	movl %ecx, $0x114<UINT32>
0x004259da:	movb %al, (%edi)
0x004259dc:	incl %edi
0x004259dd:	subb %al, $0xffffffe8<UINT8>
0x004259df:	cmpb %al, $0x1<UINT8>
0x004259e1:	ja 0x004259da
0x004259e3:	cmpb (%edi), $0x6<UINT8>
0x004259e6:	jne 0x004259da
0x004259e8:	movl %eax, (%edi)
0x004259ea:	movb %bl, 0x4(%edi)
0x004259ed:	shrw %ax, $0x8<UINT8>
0x004259f1:	roll %eax, $0x10<UINT8>
0x004259f4:	xchgb %ah, %al
0x004259f6:	subl %eax, %edi
0x004259f8:	subb %bl, $0xffffffe8<UINT8>
0x004259fb:	addl %eax, %esi
0x004259fd:	movl (%edi), %eax
0x004259ff:	addl %edi, $0x5<UINT8>
0x00425a02:	movb %al, %bl
0x00425a04:	loop 0x004259df
0x00425a06:	leal %edi, 0x23000(%esi)
0x00425a0c:	movl %eax, (%edi)
0x00425a0e:	orl %eax, %eax
0x00425a10:	je 0x00425a4e
0x00425a12:	movl %ebx, 0x4(%edi)
0x00425a15:	leal %eax, 0x25000(%eax,%esi)
0x00425a1c:	addl %ebx, %esi
0x00425a1e:	pushl %eax
0x00425a1f:	addl %edi, $0x8<UINT8>
0x00425a22:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00425a28:	xchgl %ebp, %eax
0x00425a29:	movb %al, (%edi)
0x00425a2b:	incl %edi
0x00425a2c:	orb %al, %al
0x00425a2e:	je 0x00425a0c
0x00425a30:	movl %ecx, %edi
0x00425a32:	pushl %edi
0x00425a33:	decl %eax
0x00425a34:	repn scasb %al, %es:(%edi)
0x00425a36:	pushl %ebp
0x00425a37:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00425a3d:	orl %eax, %eax
0x00425a3f:	je 7
0x00425a41:	movl (%ebx), %eax
0x00425a43:	addl %ebx, $0x4<UINT8>
0x00425a46:	jmp 0x00425a29
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x00425a4e:	movl %ebp, 0x2509c(%esi)
0x00425a54:	leal %edi, -4096(%esi)
0x00425a5a:	movl %ebx, $0x1000<UINT32>
0x00425a5f:	pushl %eax
0x00425a60:	pushl %esp
0x00425a61:	pushl $0x4<UINT8>
0x00425a63:	pushl %ebx
0x00425a64:	pushl %edi
0x00425a65:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00425a67:	leal %eax, 0x207(%edi)
0x00425a6d:	andb (%eax), $0x7f<UINT8>
0x00425a70:	andb 0x28(%eax), $0x7f<UINT8>
0x00425a74:	popl %eax
0x00425a75:	pushl %eax
0x00425a76:	pushl %esp
0x00425a77:	pushl %eax
0x00425a78:	pushl %ebx
0x00425a79:	pushl %edi
0x00425a7a:	call VirtualProtect@kernel32.dll
0x00425a7c:	popl %eax
0x00425a7d:	popa
0x00425a7e:	leal %eax, -128(%esp)
0x00425a82:	pushl $0x0<UINT8>
0x00425a84:	cmpl %esp, %eax
0x00425a86:	jne 0x00425a82
0x00425a88:	subl %esp, $0xffffff80<UINT8>
0x00425a8b:	jmp 0x0040221a
0x0040221a:	pushl %ebp
0x0040221b:	movl %ebp, %esp
0x0040221d:	pushl $0xffffffff<UINT8>
0x0040221f:	pushl $0x406138<UINT32>
0x00402224:	pushl $0x403ee4<UINT32>
0x00402229:	movl %eax, %fs:0
0x0040222f:	pushl %eax
0x00402230:	movl %fs:0, %esp
0x00402237:	subl %esp, $0x10<UINT8>
0x0040223a:	pushl %ebx
0x0040223b:	pushl %esi
0x0040223c:	pushl %edi
0x0040223d:	movl -24(%ebp), %esp
0x00402240:	call GetVersion@KERNEL32.DLL
GetVersion@KERNEL32.DLL: API Node	
0x00402246:	xorl %edx, %edx
0x00402248:	movb %dl, %ah
0x0040224a:	movl 0x422178, %edx
0x00402250:	movl %ecx, %eax
0x00402252:	andl %ecx, $0xff<UINT32>
0x00402258:	movl 0x422174, %ecx
0x0040225e:	shll %ecx, $0x8<UINT8>
0x00402261:	addl %ecx, %edx
0x00402263:	movl 0x422170, %ecx
0x00402269:	shrl %eax, $0x10<UINT8>
0x0040226c:	movl 0x42216c, %eax
0x00402271:	pushl $0x0<UINT8>
0x00402273:	call 0x00402cea
0x00402cea:	xorl %eax, %eax
0x00402cec:	pushl $0x0<UINT8>
0x00402cee:	cmpl 0x8(%esp), %eax
0x00402cf2:	pushl $0x1000<UINT32>
0x00402cf7:	sete %al
0x00402cfa:	pushl %eax
0x00402cfb:	call HeapCreate@KERNEL32.DLL
HeapCreate@KERNEL32.DLL: API Node	
0x00402d01:	testl %eax, %eax
0x00402d03:	movl 0x42267c, %eax
0x00402d08:	je 21
0x00402d0a:	call 0x00402d26
0x00402d26:	pushl $0x140<UINT32>
0x00402d2b:	pushl $0x0<UINT8>
0x00402d2d:	pushl 0x42267c
0x00402d33:	call HeapAlloc@KERNEL32.DLL
HeapAlloc@KERNEL32.DLL: API Node	
0x00402d39:	testl %eax, %eax
0x00402d3b:	movl 0x422678, %eax
0x00402d40:	jne 0x00402d43
0x00402d43:	andl 0x422670, $0x0<UINT8>
0x00402d4a:	andl 0x422674, $0x0<UINT8>
0x00402d51:	pushl $0x1<UINT8>
0x00402d53:	movl 0x42266c, %eax
0x00402d58:	movl 0x422664, $0x10<UINT32>
0x00402d62:	popl %eax
0x00402d63:	ret

0x00402d0f:	testl %eax, %eax
0x00402d11:	jne 0x00402d22
0x00402d22:	pushl $0x1<UINT8>
0x00402d24:	popl %eax
0x00402d25:	ret

0x00402278:	popl %ecx
0x00402279:	testl %eax, %eax
0x0040227b:	jne 0x00402285
0x00402285:	andl -4(%ebp), $0x0<UINT8>
0x00402289:	call 0x00403c40
0x00403c40:	subl %esp, $0x44<UINT8>
0x00403c43:	pushl %ebx
0x00403c44:	pushl %ebp
0x00403c45:	pushl %esi
0x00403c46:	pushl %edi
0x00403c47:	pushl $0x100<UINT32>
0x00403c4c:	call 0x004020e3
0x004020e3:	pushl 0x4221c4
0x004020e9:	pushl 0x8(%esp)
0x004020ed:	call 0x004020f5
0x004020f5:	cmpl 0x4(%esp), $0xffffffe0<UINT8>
0x004020fa:	ja 34
0x004020fc:	pushl 0x4(%esp)
0x00402100:	call 0x00402121
0x00402121:	pushl %esi
0x00402122:	movl %esi, 0x8(%esp)
0x00402126:	cmpl %esi, 0x421b7c
0x0040212c:	ja 0x00402139
0x0040212e:	pushl %esi
0x0040212f:	call 0x004030ba
0x004030ba:	pushl %ebp
0x004030bb:	movl %ebp, %esp
0x004030bd:	subl %esp, $0x14<UINT8>
0x004030c0:	movl %eax, 0x422674
0x004030c5:	movl %edx, 0x422678
0x004030cb:	pushl %ebx
0x004030cc:	pushl %esi
0x004030cd:	leal %eax, (%eax,%eax,4)
0x004030d0:	pushl %edi
0x004030d1:	leal %edi, (%edx,%eax,4)
0x004030d4:	movl %eax, 0x8(%ebp)
0x004030d7:	movl -4(%ebp), %edi
0x004030da:	leal %ecx, 0x17(%eax)
0x004030dd:	andl %ecx, $0xfffffff0<UINT8>
0x004030e0:	movl -16(%ebp), %ecx
0x004030e3:	sarl %ecx, $0x4<UINT8>
0x004030e6:	decl %ecx
0x004030e7:	cmpl %ecx, $0x20<UINT8>
0x004030ea:	jnl 14
0x004030ec:	orl %esi, $0xffffffff<UINT8>
0x004030ef:	shrl %esi, %cl
0x004030f1:	orl -8(%ebp), $0xffffffff<UINT8>
0x004030f5:	movl -12(%ebp), %esi
0x004030f8:	jmp 0x0040310a
0x0040310a:	movl %eax, 0x42266c
0x0040310f:	movl %ebx, %eax
0x00403111:	cmpl %ebx, %edi
0x00403113:	movl 0x8(%ebp), %ebx
0x00403116:	jae 0x00403131
0x00403131:	cmpl %ebx, -4(%ebp)
0x00403134:	jne 0x004031af
0x00403136:	movl %ebx, %edx
0x00403138:	cmpl %ebx, %eax
0x0040313a:	movl 0x8(%ebp), %ebx
0x0040313d:	jae 0x00403154
0x00403154:	jne 89
0x00403156:	cmpl %ebx, -4(%ebp)
0x00403159:	jae 0x0040316c
0x0040316c:	jne 38
0x0040316e:	movl %ebx, %edx
0x00403170:	cmpl %ebx, %eax
0x00403172:	movl 0x8(%ebp), %ebx
0x00403175:	jae 0x00403184
0x00403184:	jne 14
0x00403186:	call 0x004033c3
0x004033c3:	movl %eax, 0x422674
0x004033c8:	movl %ecx, 0x422664
0x004033ce:	pushl %esi
0x004033cf:	pushl %edi
0x004033d0:	xorl %edi, %edi
0x004033d2:	cmpl %eax, %ecx
0x004033d4:	jne 0x00403406
0x00403406:	movl %ecx, 0x422678
0x0040340c:	pushl $0x41c4<UINT32>
0x00403411:	pushl $0x8<UINT8>
0x00403413:	leal %eax, (%eax,%eax,4)
0x00403416:	pushl 0x42267c
0x0040341c:	leal %esi, (%ecx,%eax,4)
0x0040341f:	call HeapAlloc@KERNEL32.DLL
0x00403425:	cmpl %eax, %edi
0x00403427:	movl 0x10(%esi), %eax
0x0040342a:	je 42
0x0040342c:	pushl $0x4<UINT8>
0x0040342e:	pushl $0x2000<UINT32>
0x00403433:	pushl $0x100000<UINT32>
0x00403438:	pushl %edi
0x00403439:	call VirtualAlloc@KERNEL32.DLL
VirtualAlloc@KERNEL32.DLL: API Node	
0x0040343f:	cmpl %eax, %edi
0x00403441:	movl 0xc(%esi), %eax
0x00403444:	jne 0x0040345a
0x0040345a:	orl 0x8(%esi), $0xffffffff<UINT8>
0x0040345e:	movl (%esi), %edi
0x00403460:	movl 0x4(%esi), %edi
0x00403463:	incl 0x422674
0x00403469:	movl %eax, 0x10(%esi)
0x0040346c:	orl (%eax), $0xffffffff<UINT8>
0x0040346f:	movl %eax, %esi
0x00403471:	popl %edi
0x00403472:	popl %esi
0x00403473:	ret

0x0040318b:	movl %ebx, %eax
0x0040318d:	testl %ebx, %ebx
0x0040318f:	movl 0x8(%ebp), %ebx
0x00403192:	je 20
0x00403194:	pushl %ebx
0x00403195:	call 0x00403474
0x00403474:	pushl %ebp
0x00403475:	movl %ebp, %esp
0x00403477:	pushl %ecx
0x00403478:	movl %ecx, 0x8(%ebp)
0x0040347b:	pushl %ebx
0x0040347c:	pushl %esi
0x0040347d:	pushl %edi
0x0040347e:	movl %esi, 0x10(%ecx)
0x00403481:	movl %eax, 0x8(%ecx)
0x00403484:	xorl %ebx, %ebx
0x00403486:	testl %eax, %eax
0x00403488:	jl 0x0040348f
0x0040348f:	movl %eax, %ebx
0x00403491:	pushl $0x3f<UINT8>
0x00403493:	imull %eax, %eax, $0x204<UINT32>
0x00403499:	popl %edx
0x0040349a:	leal %eax, 0x144(%eax,%esi)
0x004034a1:	movl -4(%ebp), %eax
0x004034a4:	movl 0x8(%eax), %eax
0x004034a7:	movl 0x4(%eax), %eax
0x004034aa:	addl %eax, $0x8<UINT8>
0x004034ad:	decl %edx
0x004034ae:	jne 0x004034a4
0x004034b0:	movl %edi, %ebx
0x004034b2:	pushl $0x4<UINT8>
0x004034b4:	shll %edi, $0xf<UINT8>
0x004034b7:	addl %edi, 0xc(%ecx)
0x004034ba:	pushl $0x1000<UINT32>
0x004034bf:	pushl $0x8000<UINT32>
0x004034c4:	pushl %edi
0x004034c5:	call VirtualAlloc@KERNEL32.DLL
0x004034cb:	testl %eax, %eax
0x004034cd:	jne 0x004034d7
0x004034d7:	leal %edx, 0x7000(%edi)
0x004034dd:	cmpl %edi, %edx
0x004034df:	ja 60
0x004034e1:	leal %eax, 0x10(%edi)
0x004034e4:	orl -8(%eax), $0xffffffff<UINT8>
0x004034e8:	orl 0xfec(%eax), $0xffffffff<UINT8>
0x004034ef:	leal %ecx, 0xffc(%eax)
0x004034f5:	movl -4(%eax), $0xff0<UINT32>
0x004034fc:	movl (%eax), %ecx
0x004034fe:	leal %ecx, -4100(%eax)
0x00403504:	movl 0x4(%eax), %ecx
0x00403507:	movl 0xfe8(%eax), $0xff0<UINT32>
0x00403511:	addl %eax, $0x1000<UINT32>
0x00403516:	leal %ecx, -16(%eax)
0x00403519:	cmpl %ecx, %edx
0x0040351b:	jbe 0x004034e4
0x0040351d:	movl %eax, -4(%ebp)
0x00403520:	leal %ecx, 0xc(%edi)
0x00403523:	addl %eax, $0x1f8<UINT32>
0x00403528:	pushl $0x1<UINT8>
0x0040352a:	popl %edi
0x0040352b:	movl 0x4(%eax), %ecx
0x0040352e:	movl 0x8(%ecx), %eax
0x00403531:	leal %ecx, 0xc(%edx)
0x00403534:	movl 0x8(%eax), %ecx
0x00403537:	movl 0x4(%ecx), %eax
0x0040353a:	andl 0x44(%esi,%ebx,4), $0x0<UINT8>
0x0040353f:	movl 0xc4(%esi,%ebx,4), %edi
0x00403546:	movb %al, 0x43(%esi)
0x00403549:	movb %cl, %al
0x0040354b:	incb %cl
0x0040354d:	testb %al, %al
0x0040354f:	movl %eax, 0x8(%ebp)
0x00403552:	movb 0x43(%esi), %cl
0x00403555:	jne 3
0x00403557:	orl 0x4(%eax), %edi
0x0040355a:	movl %edx, $0x80000000<UINT32>
0x0040355f:	movl %ecx, %ebx
0x00403561:	shrl %edx, %cl
0x00403563:	notl %edx
0x00403565:	andl 0x8(%eax), %edx
0x00403568:	movl %eax, %ebx
0x0040356a:	popl %edi
0x0040356b:	popl %esi
0x0040356c:	popl %ebx
0x0040356d:	leave
0x0040356e:	ret

0x0040319a:	popl %ecx
0x0040319b:	movl %ecx, 0x10(%ebx)
0x0040319e:	movl (%ecx), %eax
0x004031a0:	movl %eax, 0x10(%ebx)
0x004031a3:	cmpl (%eax), $0xffffffff<UINT8>
0x004031a6:	jne 0x004031af
0x004031af:	movl 0x42266c, %ebx
0x004031b5:	movl %eax, 0x10(%ebx)
0x004031b8:	movl %edx, (%eax)
0x004031ba:	cmpl %edx, $0xffffffff<UINT8>
0x004031bd:	movl -4(%ebp), %edx
0x004031c0:	je 20
0x004031c2:	movl %ecx, 0xc4(%eax,%edx,4)
0x004031c9:	movl %edi, 0x44(%eax,%edx,4)
0x004031cd:	andl %ecx, -8(%ebp)
0x004031d0:	andl %edi, %esi
0x004031d2:	orl %ecx, %edi
0x004031d4:	jne 0x0040320d
0x0040320d:	movl %ecx, %edx
0x0040320f:	xorl %edi, %edi
0x00403211:	imull %ecx, %ecx, $0x204<UINT32>
0x00403217:	leal %ecx, 0x144(%ecx,%eax)
0x0040321e:	movl -12(%ebp), %ecx
0x00403221:	movl %ecx, 0x44(%eax,%edx,4)
0x00403225:	andl %ecx, %esi
0x00403227:	jne 13
0x00403229:	movl %ecx, 0xc4(%eax,%edx,4)
0x00403230:	pushl $0x20<UINT8>
0x00403232:	andl %ecx, -8(%ebp)
0x00403235:	popl %edi
0x00403236:	testl %ecx, %ecx
0x00403238:	jl 0x0040323f
0x0040323a:	shll %ecx
0x0040323c:	incl %edi
0x0040323d:	jmp 0x00403236
0x0040323f:	movl %ecx, -12(%ebp)
0x00403242:	movl %edx, 0x4(%ecx,%edi,8)
0x00403246:	movl %ecx, (%edx)
0x00403248:	subl %ecx, -16(%ebp)
0x0040324b:	movl %esi, %ecx
0x0040324d:	movl -8(%ebp), %ecx
0x00403250:	sarl %esi, $0x4<UINT8>
0x00403253:	decl %esi
0x00403254:	cmpl %esi, $0x3f<UINT8>
0x00403257:	jle 3
0x00403259:	pushl $0x3f<UINT8>
0x0040325b:	popl %esi
0x0040325c:	cmpl %esi, %edi
0x0040325e:	je 0x00403371
0x00403371:	testl %ecx, %ecx
0x00403373:	je 11
0x00403375:	movl (%edx), %ecx
0x00403377:	movl -4(%ecx,%edx), %ecx
0x0040337b:	jmp 0x00403380
0x00403380:	movl %esi, -16(%ebp)
0x00403383:	addl %edx, %ecx
0x00403385:	leal %ecx, 0x1(%esi)
0x00403388:	movl (%edx), %ecx
0x0040338a:	movl -4(%edx,%esi), %ecx
0x0040338e:	movl %esi, -12(%ebp)
0x00403391:	movl %ecx, (%esi)
0x00403393:	testl %ecx, %ecx
0x00403395:	leal %edi, 0x1(%ecx)
0x00403398:	movl (%esi), %edi
0x0040339a:	jne 0x004033b6
0x0040339c:	cmpl %ebx, 0x422670
0x004033a2:	jne 0x004033b6
0x004033b6:	movl %ecx, -4(%ebp)
0x004033b9:	movl (%eax), %ecx
0x004033bb:	leal %eax, 0x4(%edx)
0x004033be:	popl %edi
0x004033bf:	popl %esi
0x004033c0:	popl %ebx
0x004033c1:	leave
0x004033c2:	ret

0x00402134:	testl %eax, %eax
0x00402136:	popl %ecx
0x00402137:	jne 0x00402155
0x00402155:	popl %esi
0x00402156:	ret

0x00402105:	testl %eax, %eax
0x00402107:	popl %ecx
0x00402108:	jne 0x00402120
0x00402120:	ret

0x004020f2:	popl %ecx
0x004020f3:	popl %ecx
0x004020f4:	ret

0x00403c51:	movl %esi, %eax
0x00403c53:	popl %ecx
0x00403c54:	testl %esi, %esi
0x00403c56:	jne 0x00403c60
0x00403c60:	movl 0x422560, %esi
0x00403c66:	movl 0x422660, $0x20<UINT32>
0x00403c70:	leal %eax, 0x100(%esi)
0x00403c76:	cmpl %esi, %eax
0x00403c78:	jae 0x00403c94
0x00403c7a:	andb 0x4(%esi), $0x0<UINT8>
0x00403c7e:	orl (%esi), $0xffffffff<UINT8>
0x00403c81:	movb 0x5(%esi), $0xa<UINT8>
0x00403c85:	movl %eax, 0x422560
0x00403c8a:	addl %esi, $0x8<UINT8>
0x00403c8d:	addl %eax, $0x100<UINT32>
0x00403c92:	jmp 0x00403c76
0x00403c94:	leal %eax, 0x10(%esp)
0x00403c98:	pushl %eax
0x00403c99:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x00403c9f:	cmpw 0x42(%esp), $0x0<UINT8>
0x00403ca5:	je 197
0x00403cab:	movl %eax, 0x44(%esp)
0x00403caf:	testl %eax, %eax
0x00403cb1:	je 185
0x00403cb7:	movl %esi, (%eax)
0x00403cb9:	leal %ebp, 0x4(%eax)
0x00403cbc:	movl %eax, $0x800<UINT32>
0x00403cc1:	cmpl %esi, %eax
0x00403cc3:	leal %ebx, (%esi,%ebp)
0x00403cc6:	jl 0x00403cca
0x00403cca:	cmpl 0x422660, %esi
0x00403cd0:	jnl 0x00403d24
0x00403d24:	xorl %edi, %edi
0x00403d26:	testl %esi, %esi
0x00403d28:	jle 0x00403d70
0x00403d70:	xorl %ebx, %ebx
0x00403d72:	movl %eax, 0x422560
0x00403d77:	cmpl (%eax,%ebx,8), $0xffffffff<UINT8>
0x00403d7b:	leal %esi, (%eax,%ebx,8)
0x00403d7e:	jne 77
0x00403d80:	testl %ebx, %ebx
0x00403d82:	movb 0x4(%esi), $0xffffff81<UINT8>
0x00403d86:	jne 0x00403d8d
0x00403d88:	pushl $0xfffffff6<UINT8>
0x00403d8a:	popl %eax
0x00403d8b:	jmp 0x00403d97
0x00403d97:	pushl %eax
0x00403d98:	call GetStdHandle@KERNEL32.DLL
GetStdHandle@KERNEL32.DLL: API Node	
0x00403d9e:	movl %edi, %eax
0x00403da0:	cmpl %edi, $0xffffffff<UINT8>
0x00403da3:	je 23
0x00403da5:	pushl %edi
0x00403da6:	call GetFileType@KERNEL32.DLL
GetFileType@KERNEL32.DLL: API Node	
0x00403dac:	testl %eax, %eax
0x00403dae:	je 12
0x00403db0:	andl %eax, $0xff<UINT32>
0x00403db5:	movl (%esi), %edi
0x00403db7:	cmpl %eax, $0x2<UINT8>
0x00403dba:	jne 6
0x00403dbc:	orb 0x4(%esi), $0x40<UINT8>
0x00403dc0:	jmp 0x00403dd1
0x00403dd1:	incl %ebx
0x00403dd2:	cmpl %ebx, $0x3<UINT8>
0x00403dd5:	jl 0x00403d72
0x00403d8d:	movl %eax, %ebx
0x00403d8f:	decl %eax
0x00403d90:	negl %eax
0x00403d92:	sbbl %eax, %eax
0x00403d94:	addl %eax, $0xfffffff5<UINT8>
0x00403dd7:	pushl 0x422660
0x00403ddd:	call SetHandleCount@KERNEL32.DLL
SetHandleCount@KERNEL32.DLL: API Node	
0x00403de3:	popl %edi
0x00403de4:	popl %esi
0x00403de5:	popl %ebp
0x00403de6:	popl %ebx
0x00403de7:	addl %esp, $0x44<UINT8>
0x00403dea:	ret

0x0040228e:	call GetCommandLineA@KERNEL32.DLL
GetCommandLineA@KERNEL32.DLL: API Node	
0x00402294:	movl 0x4236a4, %eax
0x00402299:	call 0x00403b0e
0x00403b0e:	pushl %ecx
0x00403b0f:	pushl %ecx
0x00403b10:	movl %eax, 0x4222d4
0x00403b15:	pushl %ebx
0x00403b16:	pushl %ebp
0x00403b17:	movl %ebp, 0x4060e4
0x00403b1d:	pushl %esi
0x00403b1e:	pushl %edi
0x00403b1f:	xorl %ebx, %ebx
0x00403b21:	xorl %esi, %esi
0x00403b23:	xorl %edi, %edi
0x00403b25:	cmpl %eax, %ebx
0x00403b27:	jne 51
0x00403b29:	call GetEnvironmentStringsW@KERNEL32.DLL
GetEnvironmentStringsW@KERNEL32.DLL: API Node	
0x00403b2b:	movl %esi, %eax
0x00403b2d:	cmpl %esi, %ebx
0x00403b2f:	je 12
0x00403b31:	movl 0x4222d4, $0x1<UINT32>
0x00403b3b:	jmp 0x00403b65
0x00403b65:	cmpl %esi, %ebx
0x00403b67:	jne 0x00403b75
0x00403b75:	cmpw (%esi), %bx
0x00403b78:	movl %eax, %esi
0x00403b7a:	je 14
0x00403b7c:	incl %eax
0x00403b7d:	incl %eax
0x00403b7e:	cmpw (%eax), %bx
0x00403b81:	jne 0x00403b7c
0x00403b83:	incl %eax
0x00403b84:	incl %eax
0x00403b85:	cmpw (%eax), %bx
0x00403b88:	jne 0x00403b7c
0x00403b8a:	subl %eax, %esi
0x00403b8c:	movl %edi, 0x4060dc
0x00403b92:	sarl %eax
0x00403b94:	pushl %ebx
0x00403b95:	pushl %ebx
0x00403b96:	incl %eax
0x00403b97:	pushl %ebx
0x00403b98:	pushl %ebx
0x00403b99:	pushl %eax
0x00403b9a:	pushl %esi
0x00403b9b:	pushl %ebx
0x00403b9c:	pushl %ebx
0x00403b9d:	movl 0x34(%esp), %eax
0x00403ba1:	call WideCharToMultiByte@KERNEL32.DLL
WideCharToMultiByte@KERNEL32.DLL: API Node	
0x00403ba3:	movl %ebp, %eax
0x00403ba5:	cmpl %ebp, %ebx
0x00403ba7:	je 50
0x00403ba9:	pushl %ebp
0x00403baa:	call 0x004020e3
0x00402139:	testl %esi, %esi
0x0040213b:	jne 0x00402140
0x00402140:	addl %esi, $0xf<UINT8>
0x00402143:	andl %esi, $0xfffffff0<UINT8>
0x00402146:	pushl %esi
0x00402147:	pushl $0x0<UINT8>
0x00402149:	pushl 0x42267c
0x0040214f:	call HeapAlloc@KERNEL32.DLL
0x00403baf:	cmpl %eax, %ebx
0x00403bb1:	popl %ecx
0x00403bb2:	movl 0x10(%esp), %eax
0x00403bb6:	je 35
0x00403bb8:	pushl %ebx
0x00403bb9:	pushl %ebx
0x00403bba:	pushl %ebp
0x00403bbb:	pushl %eax
0x00403bbc:	pushl 0x24(%esp)
0x00403bc0:	pushl %esi
0x00403bc1:	pushl %ebx
0x00403bc2:	pushl %ebx
0x00403bc3:	call WideCharToMultiByte@KERNEL32.DLL
0x00403bc5:	testl %eax, %eax
0x00403bc7:	jne 0x00403bd7
0x00403bd7:	movl %ebx, 0x10(%esp)
0x00403bdb:	pushl %esi
0x00403bdc:	call FreeEnvironmentStringsW@KERNEL32.DLL
FreeEnvironmentStringsW@KERNEL32.DLL: API Node	
0x00403be2:	movl %eax, %ebx
0x00403be4:	jmp 0x00403c39
0x00403c39:	popl %edi
0x00403c3a:	popl %esi
0x00403c3b:	popl %ebp
0x00403c3c:	popl %ebx
0x00403c3d:	popl %ecx
0x00403c3e:	popl %ecx
0x00403c3f:	ret

0x0040229e:	movl 0x4221ac, %eax
0x004022a3:	call 0x004038c1
0x004038c1:	pushl %ebp
0x004038c2:	movl %ebp, %esp
0x004038c4:	pushl %ecx
0x004038c5:	pushl %ecx
0x004038c6:	pushl %ebx
0x004038c7:	xorl %ebx, %ebx
0x004038c9:	cmpl 0x4236ac, %ebx
0x004038cf:	pushl %esi
0x004038d0:	pushl %edi
0x004038d1:	jne 5
0x004038d3:	call 0x00404fa4
0x00404fa4:	cmpl 0x4236ac, $0x0<UINT8>
0x00404fab:	jne 0x00404fbf
0x00404fad:	pushl $0xfffffffd<UINT8>
0x00404faf:	call 0x00404be0
0x00404be0:	pushl %ebp
0x00404be1:	movl %ebp, %esp
0x00404be3:	subl %esp, $0x18<UINT8>
0x00404be6:	pushl %ebx
0x00404be7:	pushl %esi
0x00404be8:	pushl %edi
0x00404be9:	pushl 0x8(%ebp)
0x00404bec:	call 0x00404d79
0x00404d79:	movl %eax, 0x4(%esp)
0x00404d7d:	andl 0x4222dc, $0x0<UINT8>
0x00404d84:	cmpl %eax, $0xfffffffe<UINT8>
0x00404d87:	jne 0x00404d99
0x00404d99:	cmpl %eax, $0xfffffffd<UINT8>
0x00404d9c:	jne 16
0x00404d9e:	movl 0x4222dc, $0x1<UINT32>
0x00404da8:	jmp GetACP@KERNEL32.DLL
GetACP@KERNEL32.DLL: API Node	
0x00404bf1:	movl %esi, %eax
0x00404bf3:	popl %ecx
0x00404bf4:	cmpl %esi, 0x422314
0x00404bfa:	movl 0x8(%ebp), %esi
0x00404bfd:	je 362
0x00404c03:	xorl %ebx, %ebx
0x00404c05:	cmpl %esi, %ebx
0x00404c07:	je 342
0x00404c0d:	xorl %edx, %edx
0x00404c0f:	movl %eax, $0x421ee8<UINT32>
0x00404c14:	cmpl (%eax), %esi
0x00404c16:	je 114
0x00404c18:	addl %eax, $0x30<UINT8>
0x00404c1b:	incl %edx
0x00404c1c:	cmpl %eax, $0x421fd8<UINT32>
0x00404c21:	jl 0x00404c14
0x00404c23:	leal %eax, -24(%ebp)
0x00404c26:	pushl %eax
0x00404c27:	pushl %esi
0x00404c28:	call GetCPInfo@KERNEL32.DLL
GetCPInfo@KERNEL32.DLL: API Node	
0x00404c2e:	cmpl %eax, $0x1<UINT8>
0x00404c31:	jne 292
0x00404c37:	pushl $0x40<UINT8>
0x00404c39:	xorl %eax, %eax
0x00404c3b:	popl %ecx
0x00404c3c:	movl %edi, $0x422440<UINT32>
0x00404c41:	cmpl -24(%ebp), $0x1<UINT8>
0x00404c45:	movl 0x422314, %esi
0x00404c4b:	rep stosl %es:(%edi), %eax
0x00404c4d:	stosb %es:(%edi), %al
0x00404c4e:	movl 0x422544, %ebx
0x00404c54:	jbe 239
0x00404c5a:	cmpb -18(%ebp), $0x0<UINT8>
0x00404c5e:	je 0x00404d1f
0x00404d1f:	pushl $0x1<UINT8>
0x00404d21:	popl %eax
0x00404d22:	orb 0x422441(%eax), $0x8<UINT8>
0x00404d29:	incl %eax
0x00404d2a:	cmpl %eax, $0xff<UINT32>
0x00404d2f:	jb 0x00404d22
0x00404d31:	pushl %esi
0x00404d32:	call 0x00404dc3
0x00404dc3:	movl %eax, 0x4(%esp)
0x00404dc7:	subl %eax, $0x3a4<UINT32>
0x00404dcc:	je 34
0x00404dce:	subl %eax, $0x4<UINT8>
0x00404dd1:	je 23
0x00404dd3:	subl %eax, $0xd<UINT8>
0x00404dd6:	je 12
0x00404dd8:	decl %eax
0x00404dd9:	je 3
0x00404ddb:	xorl %eax, %eax
0x00404ddd:	ret

0x00404d37:	popl %ecx
0x00404d38:	movl 0x422544, %eax
0x00404d3d:	movl 0x42232c, $0x1<UINT32>
0x00404d47:	jmp 0x00404d4f
0x00404d4f:	xorl %eax, %eax
0x00404d51:	movl %edi, $0x422320<UINT32>
0x00404d56:	stosl %es:(%edi), %eax
0x00404d57:	stosl %es:(%edi), %eax
0x00404d58:	stosl %es:(%edi), %eax
0x00404d59:	jmp 0x00404d68
0x00404d68:	call 0x00404e1f
0x00404e1f:	pushl %ebp
0x00404e20:	movl %ebp, %esp
0x00404e22:	subl %esp, $0x514<UINT32>
0x00404e28:	leal %eax, -20(%ebp)
0x00404e2b:	pushl %esi
0x00404e2c:	pushl %eax
0x00404e2d:	pushl 0x422314
0x00404e33:	call GetCPInfo@KERNEL32.DLL
0x00404e39:	cmpl %eax, $0x1<UINT8>
0x00404e3c:	jne 278
0x00404e42:	xorl %eax, %eax
0x00404e44:	movl %esi, $0x100<UINT32>
0x00404e49:	movb -276(%ebp,%eax), %al
0x00404e50:	incl %eax
0x00404e51:	cmpl %eax, %esi
0x00404e53:	jb 0x00404e49
0x00404e55:	movb %al, -14(%ebp)
0x00404e58:	movb -276(%ebp), $0x20<UINT8>
0x00404e5f:	testb %al, %al
0x00404e61:	je 0x00404e9a
0x00404e9a:	pushl $0x0<UINT8>
0x00404e9c:	leal %eax, -1300(%ebp)
0x00404ea2:	pushl 0x422544
0x00404ea8:	pushl 0x422314
0x00404eae:	pushl %eax
0x00404eaf:	leal %eax, -276(%ebp)
0x00404eb5:	pushl %esi
0x00404eb6:	pushl %eax
0x00404eb7:	pushl $0x1<UINT8>
0x00404eb9:	call 0x004058fb
0x004058fb:	pushl %ebp
0x004058fc:	movl %ebp, %esp
0x004058fe:	pushl $0xffffffff<UINT8>
0x00405900:	pushl $0x406508<UINT32>
0x00405905:	pushl $0x403ee4<UINT32>
0x0040590a:	movl %eax, %fs:0
0x00405910:	pushl %eax
0x00405911:	movl %fs:0, %esp
0x00405918:	subl %esp, $0x18<UINT8>
0x0040591b:	pushl %ebx
0x0040591c:	pushl %esi
0x0040591d:	pushl %edi
0x0040591e:	movl -24(%ebp), %esp
0x00405921:	movl %eax, 0x422310
0x00405926:	xorl %ebx, %ebx
0x00405928:	cmpl %eax, %ebx
0x0040592a:	jne 62
0x0040592c:	leal %eax, -28(%ebp)
0x0040592f:	pushl %eax
0x00405930:	pushl $0x1<UINT8>
0x00405932:	popl %esi
0x00405933:	pushl %esi
0x00405934:	pushl $0x4064e8<UINT32>
0x00405939:	pushl %esi
0x0040593a:	call GetStringTypeW@KERNEL32.DLL
GetStringTypeW@KERNEL32.DLL: API Node	
0x00405940:	testl %eax, %eax
0x00405942:	je 4
0x00405944:	movl %eax, %esi
0x00405946:	jmp 0x00405965
0x00405965:	movl 0x422310, %eax
0x0040596a:	cmpl %eax, $0x2<UINT8>
0x0040596d:	jne 0x00405993
0x00405993:	cmpl %eax, $0x1<UINT8>
0x00405996:	jne 148
0x0040599c:	cmpl 0x18(%ebp), %ebx
0x0040599f:	jne 0x004059a9
0x004059a9:	pushl %ebx
0x004059aa:	pushl %ebx
0x004059ab:	pushl 0x10(%ebp)
0x004059ae:	pushl 0xc(%ebp)
0x004059b1:	movl %eax, 0x20(%ebp)
0x004059b4:	negl %eax
0x004059b6:	sbbl %eax, %eax
0x004059b8:	andl %eax, $0x8<UINT8>
0x004059bb:	incl %eax
0x004059bc:	pushl %eax
0x004059bd:	pushl 0x18(%ebp)
0x004059c0:	call MultiByteToWideChar@KERNEL32.DLL
MultiByteToWideChar@KERNEL32.DLL: API Node	
0x004059c6:	movl -32(%ebp), %eax
0x004059c9:	cmpl %eax, %ebx
0x004059cb:	je 99
0x004059cd:	movl -4(%ebp), %ebx
0x004059d0:	leal %edi, (%eax,%eax)
0x004059d3:	movl %eax, %edi
0x004059d5:	addl %eax, $0x3<UINT8>
0x004059d8:	andb %al, $0xfffffffc<UINT8>
0x004059da:	call 0x00405b30
0x00405b30:	pushl %ecx
0x00405b31:	cmpl %eax, $0x1000<UINT32>
0x00405b36:	leal %ecx, 0x8(%esp)
0x00405b3a:	jb 0x00405b50
0x00405b50:	subl %ecx, %eax
0x00405b52:	movl %eax, %esp
0x00405b54:	testl (%ecx), %eax
0x00405b56:	movl %esp, %ecx
0x00405b58:	movl %ecx, (%eax)
0x00405b5a:	movl %eax, 0x4(%eax)
0x00405b5d:	pushl %eax
0x00405b5e:	ret

0x004059df:	movl -24(%ebp), %esp
0x004059e2:	movl %esi, %esp
0x004059e4:	movl -36(%ebp), %esi
0x004059e7:	pushl %edi
0x004059e8:	pushl %ebx
0x004059e9:	pushl %esi
0x004059ea:	call 0x004054e0
0x004054e0:	movl %edx, 0xc(%esp)
0x004054e4:	movl %ecx, 0x4(%esp)
0x004054e8:	testl %edx, %edx
0x004054ea:	je 71
0x004054ec:	xorl %eax, %eax
0x004054ee:	movb %al, 0x8(%esp)
0x004054f2:	pushl %edi
0x004054f3:	movl %edi, %ecx
0x004054f5:	cmpl %edx, $0x4<UINT8>
0x004054f8:	jb 45
0x004054fa:	negl %ecx
0x004054fc:	andl %ecx, $0x3<UINT8>
0x004054ff:	je 0x00405509
0x00405509:	movl %ecx, %eax
0x0040550b:	shll %eax, $0x8<UINT8>
0x0040550e:	addl %eax, %ecx
0x00405510:	movl %ecx, %eax
0x00405512:	shll %eax, $0x10<UINT8>
0x00405515:	addl %eax, %ecx
0x00405517:	movl %ecx, %edx
0x00405519:	andl %edx, $0x3<UINT8>
0x0040551c:	shrl %ecx, $0x2<UINT8>
0x0040551f:	je 6
0x00405521:	rep stosl %es:(%edi), %eax
0x00405523:	testl %edx, %edx
0x00405525:	je 0x0040552d
0x0040552d:	movl %eax, 0x8(%esp)
0x00405531:	popl %edi
0x00405532:	ret

0x004059ef:	addl %esp, $0xc<UINT8>
0x004059f2:	jmp 0x004059ff
0x004059ff:	orl -4(%ebp), $0xffffffff<UINT8>
0x00405a03:	cmpl %esi, %ebx
0x00405a05:	je 41
0x00405a07:	pushl -32(%ebp)
0x00405a0a:	pushl %esi
0x00405a0b:	pushl 0x10(%ebp)
0x00405a0e:	pushl 0xc(%ebp)
0x00405a11:	pushl $0x1<UINT8>
0x00405a13:	pushl 0x18(%ebp)
0x00405a16:	call MultiByteToWideChar@KERNEL32.DLL
0x00405a1c:	cmpl %eax, %ebx
0x00405a1e:	je 16
0x00405a20:	pushl 0x14(%ebp)
0x00405a23:	pushl %eax
0x00405a24:	pushl %esi
0x00405a25:	pushl 0x8(%ebp)
0x00405a28:	call GetStringTypeW@KERNEL32.DLL
0x00405a2e:	jmp 0x00405a32
0x00405a32:	leal %esp, -52(%ebp)
0x00405a35:	movl %ecx, -16(%ebp)
0x00405a38:	movl %fs:0, %ecx
0x00405a3f:	popl %edi
0x00405a40:	popl %esi
0x00405a41:	popl %ebx
0x00405a42:	leave
0x00405a43:	ret

0x00404ebe:	pushl $0x0<UINT8>
0x00404ec0:	leal %eax, -532(%ebp)
0x00404ec6:	pushl 0x422314
0x00404ecc:	pushl %esi
0x00404ecd:	pushl %eax
0x00404ece:	leal %eax, -276(%ebp)
0x00404ed4:	pushl %esi
0x00404ed5:	pushl %eax
0x00404ed6:	pushl %esi
0x00404ed7:	pushl 0x422544
0x00404edd:	call 0x004056ac
0x004056ac:	pushl %ebp
0x004056ad:	movl %ebp, %esp
0x004056af:	pushl $0xffffffff<UINT8>
0x004056b1:	pushl $0x4064f0<UINT32>
0x004056b6:	pushl $0x403ee4<UINT32>
0x004056bb:	movl %eax, %fs:0
0x004056c1:	pushl %eax
0x004056c2:	movl %fs:0, %esp
0x004056c9:	subl %esp, $0x1c<UINT8>
0x004056cc:	pushl %ebx
0x004056cd:	pushl %esi
0x004056ce:	pushl %edi
0x004056cf:	movl -24(%ebp), %esp
0x004056d2:	xorl %edi, %edi
0x004056d4:	cmpl 0x42230c, %edi
0x004056da:	jne 0x00405722
0x004056dc:	pushl %edi
0x004056dd:	pushl %edi
0x004056de:	pushl $0x1<UINT8>
0x004056e0:	popl %ebx
0x004056e1:	pushl %ebx
0x004056e2:	pushl $0x4064e8<UINT32>
0x004056e7:	movl %esi, $0x100<UINT32>
0x004056ec:	pushl %esi
0x004056ed:	pushl %edi
0x004056ee:	call LCMapStringW@KERNEL32.DLL
LCMapStringW@KERNEL32.DLL: API Node	
0x004056f4:	testl %eax, %eax
0x004056f6:	je 8
0x004056f8:	movl 0x42230c, %ebx
0x004056fe:	jmp 0x00405722
0x00405722:	cmpl 0x14(%ebp), %edi
0x00405725:	jle 16
0x00405727:	pushl 0x14(%ebp)
0x0040572a:	pushl 0x10(%ebp)
0x0040572d:	call 0x004058d0
0x004058d0:	movl %edx, 0x8(%esp)
0x004058d4:	movl %eax, 0x4(%esp)
0x004058d8:	testl %edx, %edx
0x004058da:	pushl %esi
0x004058db:	leal %ecx, -1(%edx)
0x004058de:	je 13
0x004058e0:	cmpb (%eax), $0x0<UINT8>
0x004058e3:	je 8
0x004058e5:	incl %eax
0x004058e6:	movl %esi, %ecx
0x004058e8:	decl %ecx
0x004058e9:	testl %esi, %esi
0x004058eb:	jne 0x004058e0
0x004058ed:	cmpb (%eax), $0x0<UINT8>
0x004058f0:	popl %esi
0x004058f1:	jne 0x004058f8
0x004058f8:	movl %eax, %edx
0x004058fa:	ret

0x00405732:	popl %ecx
0x00405733:	popl %ecx
0x00405734:	movl 0x14(%ebp), %eax
0x00405737:	movl %eax, 0x42230c
0x0040573c:	cmpl %eax, $0x2<UINT8>
0x0040573f:	jne 0x0040575e
0x0040575e:	cmpl %eax, $0x1<UINT8>
0x00405761:	jne 211
0x00405767:	cmpl 0x20(%ebp), %edi
0x0040576a:	jne 0x00405774
0x00405774:	pushl %edi
0x00405775:	pushl %edi
0x00405776:	pushl 0x14(%ebp)
0x00405779:	pushl 0x10(%ebp)
0x0040577c:	movl %eax, 0x24(%ebp)
0x0040577f:	negl %eax
0x00405781:	sbbl %eax, %eax
0x00405783:	andl %eax, $0x8<UINT8>
0x00405786:	incl %eax
0x00405787:	pushl %eax
0x00405788:	pushl 0x20(%ebp)
0x0040578b:	call MultiByteToWideChar@KERNEL32.DLL
0x00405791:	movl %ebx, %eax
0x00405793:	movl -28(%ebp), %ebx
0x00405796:	cmpl %ebx, %edi
0x00405798:	je 156
0x0040579e:	movl -4(%ebp), %edi
0x004057a1:	leal %eax, (%ebx,%ebx)
0x004057a4:	addl %eax, $0x3<UINT8>
0x004057a7:	andb %al, $0xfffffffc<UINT8>
0x004057a9:	call 0x00405b30
0x004057ae:	movl -24(%ebp), %esp
0x004057b1:	movl %eax, %esp
0x004057b3:	movl -36(%ebp), %eax
0x004057b6:	orl -4(%ebp), $0xffffffff<UINT8>
0x004057ba:	jmp 0x004057cf
0x004057cf:	cmpl -36(%ebp), %edi
0x004057d2:	je 102
0x004057d4:	pushl %ebx
0x004057d5:	pushl -36(%ebp)
0x004057d8:	pushl 0x14(%ebp)
0x004057db:	pushl 0x10(%ebp)
0x004057de:	pushl $0x1<UINT8>
0x004057e0:	pushl 0x20(%ebp)
0x004057e3:	call MultiByteToWideChar@KERNEL32.DLL
0x004057e9:	testl %eax, %eax
0x004057eb:	je 77
0x004057ed:	pushl %edi
0x004057ee:	pushl %edi
0x004057ef:	pushl %ebx
0x004057f0:	pushl -36(%ebp)
0x004057f3:	pushl 0xc(%ebp)
0x004057f6:	pushl 0x8(%ebp)
0x004057f9:	call LCMapStringW@KERNEL32.DLL
0x004057ff:	movl %esi, %eax
0x00405801:	movl -40(%ebp), %esi
0x00405804:	cmpl %esi, %edi
0x00405806:	je 50
0x00405808:	testb 0xd(%ebp), $0x4<UINT8>
0x0040580c:	je 0x0040584e
0x0040584e:	movl -4(%ebp), $0x1<UINT32>
0x00405855:	leal %eax, (%esi,%esi)
0x00405858:	addl %eax, $0x3<UINT8>
0x0040585b:	andb %al, $0xfffffffc<UINT8>
0x0040585d:	call 0x00405b30
0x00405862:	movl -24(%ebp), %esp
0x00405865:	movl %ebx, %esp
0x00405867:	movl -32(%ebp), %ebx
0x0040586a:	orl -4(%ebp), $0xffffffff<UINT8>
0x0040586e:	jmp 0x00405882
0x00405882:	cmpl %ebx, %edi
0x00405884:	je -76
0x00405886:	pushl %esi
0x00405887:	pushl %ebx
0x00405888:	pushl -28(%ebp)
0x0040588b:	pushl -36(%ebp)
0x0040588e:	pushl 0xc(%ebp)
0x00405891:	pushl 0x8(%ebp)
0x00405894:	call LCMapStringW@KERNEL32.DLL
0x0040589a:	testl %eax, %eax
0x0040589c:	je -100
0x0040589e:	cmpl 0x1c(%ebp), %edi
0x004058a1:	pushl %edi
0x004058a2:	pushl %edi
0x004058a3:	jne 0x004058a9
0x004058a9:	pushl 0x1c(%ebp)
0x004058ac:	pushl 0x18(%ebp)
0x004058af:	pushl %esi
0x004058b0:	pushl %ebx
0x004058b1:	pushl $0x220<UINT32>
0x004058b6:	pushl 0x20(%ebp)
0x004058b9:	call WideCharToMultiByte@KERNEL32.DLL
0x004058bf:	movl %esi, %eax
0x004058c1:	cmpl %esi, %edi
0x004058c3:	je -143
0x004058c9:	movl %eax, %esi
0x004058cb:	jmp 0x0040583c
0x0040583c:	leal %esp, -56(%ebp)
0x0040583f:	movl %ecx, -16(%ebp)
0x00405842:	movl %fs:0, %ecx
0x00405849:	popl %edi
0x0040584a:	popl %esi
0x0040584b:	popl %ebx
0x0040584c:	leave
0x0040584d:	ret

0x00404ee2:	pushl $0x0<UINT8>
0x00404ee4:	leal %eax, -788(%ebp)
0x00404eea:	pushl 0x422314
0x00404ef0:	pushl %esi
0x00404ef1:	pushl %eax
0x00404ef2:	leal %eax, -276(%ebp)
0x00404ef8:	pushl %esi
0x00404ef9:	pushl %eax
0x00404efa:	pushl $0x200<UINT32>
0x00404eff:	pushl 0x422544
0x00404f05:	call 0x004056ac
0x00404f0a:	addl %esp, $0x5c<UINT8>
0x00404f0d:	xorl %eax, %eax
0x00404f0f:	leal %ecx, -1300(%ebp)
0x00404f15:	movw %dx, (%ecx)
0x00404f18:	testb %dl, $0x1<UINT8>
0x00404f1b:	je 0x00404f33
0x00404f33:	testb %dl, $0x2<UINT8>
0x00404f36:	je 0x00404f48
0x00404f48:	andb 0x422340(%eax), $0x0<UINT8>
0x00404f4f:	incl %eax
0x00404f50:	incl %ecx
0x00404f51:	incl %ecx
0x00404f52:	cmpl %eax, %esi
0x00404f54:	jb 0x00404f15
0x00404f1d:	orb 0x422441(%eax), $0x10<UINT8>
0x00404f24:	movb %dl, -532(%ebp,%eax)
0x00404f2b:	movb 0x422340(%eax), %dl
0x00404f31:	jmp 0x00404f4f
0x00404f38:	orb 0x422441(%eax), $0x20<UINT8>
0x00404f3f:	movb %dl, -788(%ebp,%eax)
0x00404f46:	jmp 0x00404f2b
0x00404f56:	jmp 0x00404fa1
0x00404fa1:	popl %esi
0x00404fa2:	leave
0x00404fa3:	ret

0x00404d6d:	xorl %eax, %eax
0x00404d6f:	jmp 0x00404d74
0x00404d74:	popl %edi
0x00404d75:	popl %esi
0x00404d76:	popl %ebx
0x00404d77:	leave
0x00404d78:	ret

0x00404fb4:	popl %ecx
0x00404fb5:	movl 0x4236ac, $0x1<UINT32>
0x00404fbf:	ret

0x004038d8:	movl %esi, $0x4221d0<UINT32>
0x004038dd:	pushl $0x104<UINT32>
0x004038e2:	pushl %esi
0x004038e3:	pushl %ebx
0x004038e4:	call GetModuleFileNameA@KERNEL32.DLL
GetModuleFileNameA@KERNEL32.DLL: API Node	
0x004038ea:	movl %eax, 0x4236a4
0x004038ef:	movl 0x422198, %esi
0x004038f5:	movl %edi, %esi
0x004038f7:	cmpb (%eax), %bl
0x004038f9:	je 2
0x004038fb:	movl %edi, %eax
0x004038fd:	leal %eax, -8(%ebp)
0x00403900:	pushl %eax
0x00403901:	leal %eax, -4(%ebp)
0x00403904:	pushl %eax
0x00403905:	pushl %ebx
0x00403906:	pushl %ebx
0x00403907:	pushl %edi
0x00403908:	call 0x0040395a
0x0040395a:	pushl %ebp
0x0040395b:	movl %ebp, %esp
0x0040395d:	movl %ecx, 0x18(%ebp)
0x00403960:	movl %eax, 0x14(%ebp)
0x00403963:	pushl %ebx
0x00403964:	pushl %esi
0x00403965:	andl (%ecx), $0x0<UINT8>
0x00403968:	movl %esi, 0x10(%ebp)
0x0040396b:	pushl %edi
0x0040396c:	movl %edi, 0xc(%ebp)
0x0040396f:	movl (%eax), $0x1<UINT32>
0x00403975:	movl %eax, 0x8(%ebp)
0x00403978:	testl %edi, %edi
0x0040397a:	je 0x00403984
0x00403984:	cmpb (%eax), $0x22<UINT8>
0x00403987:	jne 68
0x00403989:	movb %dl, 0x1(%eax)
0x0040398c:	incl %eax
0x0040398d:	cmpb %dl, $0x22<UINT8>
0x00403990:	je 0x004039bb
0x00403992:	testb %dl, %dl
0x00403994:	je 37
0x00403996:	movzbl %edx, %dl
0x00403999:	testb 0x422441(%edx), $0x4<UINT8>
0x004039a0:	je 0x004039ae
0x004039ae:	incl (%ecx)
0x004039b0:	testl %esi, %esi
0x004039b2:	je 0x00403989
0x004039bb:	incl (%ecx)
0x004039bd:	testl %esi, %esi
0x004039bf:	je 0x004039c5
0x004039c5:	cmpb (%eax), $0x22<UINT8>
0x004039c8:	jne 70
0x004039ca:	incl %eax
0x004039cb:	jmp 0x00403a10
0x00403a10:	andl 0x18(%ebp), $0x0<UINT8>
0x00403a14:	cmpb (%eax), $0x0<UINT8>
0x00403a17:	je 0x00403afd
0x00403afd:	testl %edi, %edi
0x00403aff:	je 0x00403b04
0x00403b04:	movl %eax, 0x14(%ebp)
0x00403b07:	popl %edi
0x00403b08:	popl %esi
0x00403b09:	popl %ebx
0x00403b0a:	incl (%eax)
0x00403b0c:	popl %ebp
0x00403b0d:	ret

0x0040390d:	movl %eax, -8(%ebp)
0x00403910:	movl %ecx, -4(%ebp)
0x00403913:	leal %eax, (%eax,%ecx,4)
0x00403916:	pushl %eax
0x00403917:	call 0x004020e3
0x00403118:	movl %ecx, 0x4(%ebx)
0x0040311b:	movl %edi, (%ebx)
0x0040311d:	andl %ecx, -8(%ebp)
0x00403120:	andl %edi, %esi
0x00403122:	orl %ecx, %edi
0x00403124:	jne 0x00403131
0x0040391c:	movl %esi, %eax
0x0040391e:	addl %esp, $0x18<UINT8>
0x00403921:	cmpl %esi, %ebx
0x00403923:	jne 0x0040392d
0x0040392d:	leal %eax, -8(%ebp)
0x00403930:	pushl %eax
0x00403931:	leal %eax, -4(%ebp)
0x00403934:	pushl %eax
0x00403935:	movl %eax, -4(%ebp)
0x00403938:	leal %eax, (%esi,%eax,4)
0x0040393b:	pushl %eax
0x0040393c:	pushl %esi
0x0040393d:	pushl %edi
0x0040393e:	call 0x0040395a
0x0040397c:	movl (%edi), %esi
0x0040397e:	addl %edi, $0x4<UINT8>
0x00403981:	movl 0xc(%ebp), %edi
0x004039b4:	movb %dl, (%eax)
0x004039b6:	movb (%esi), %dl
0x004039b8:	incl %esi
0x004039b9:	jmp 0x00403989
0x004039c1:	andb (%esi), $0x0<UINT8>
0x004039c4:	incl %esi
0x00403b01:	andl (%edi), $0x0<UINT8>
0x00403943:	movl %eax, -4(%ebp)
0x00403946:	addl %esp, $0x14<UINT8>
0x00403949:	decl %eax
0x0040394a:	movl 0x422180, %esi
0x00403950:	popl %edi
0x00403951:	popl %esi
0x00403952:	movl 0x42217c, %eax
0x00403957:	popl %ebx
0x00403958:	leave
0x00403959:	ret

0x004022a8:	call 0x00403808
0x00403808:	pushl %ebx
0x00403809:	xorl %ebx, %ebx
0x0040380b:	cmpl 0x4236ac, %ebx
0x00403811:	pushl %esi
0x00403812:	pushl %edi
0x00403813:	jne 0x0040381a
0x0040381a:	movl %esi, 0x4221ac
0x00403820:	xorl %edi, %edi
0x00403822:	movb %al, (%esi)
0x00403824:	cmpb %al, %bl
0x00403826:	je 0x0040383a
0x00403828:	cmpb %al, $0x3d<UINT8>
0x0040382a:	je 0x0040382d
0x0040382d:	pushl %esi
0x0040382e:	call 0x00404280
0x00404280:	movl %ecx, 0x4(%esp)
0x00404284:	testl %ecx, $0x3<UINT32>
0x0040428a:	je 0x004042a0
0x004042a0:	movl %eax, (%ecx)
0x004042a2:	movl %edx, $0x7efefeff<UINT32>
0x004042a7:	addl %edx, %eax
0x004042a9:	xorl %eax, $0xffffffff<UINT8>
0x004042ac:	xorl %eax, %edx
0x004042ae:	addl %ecx, $0x4<UINT8>
0x004042b1:	testl %eax, $0x81010100<UINT32>
0x004042b6:	je 0x004042a0
0x004042b8:	movl %eax, -4(%ecx)
0x004042bb:	testb %al, %al
0x004042bd:	je 50
0x004042bf:	testb %ah, %ah
0x004042c1:	je 36
0x004042c3:	testl %eax, $0xff0000<UINT32>
0x004042c8:	je 19
0x004042ca:	testl %eax, $0xff000000<UINT32>
0x004042cf:	je 0x004042d3
0x004042d3:	leal %eax, -1(%ecx)
0x004042d6:	movl %ecx, 0x4(%esp)
0x004042da:	subl %eax, %ecx
0x004042dc:	ret

0x00403833:	popl %ecx
0x00403834:	leal %esi, 0x1(%esi,%eax)
0x00403838:	jmp 0x00403822
0x0040383a:	leal %eax, 0x4(,%edi,4)
0x00403841:	pushl %eax
0x00403842:	call 0x004020e3
0x00403847:	movl %esi, %eax
0x00403849:	popl %ecx
0x0040384a:	cmpl %esi, %ebx
0x0040384c:	movl 0x422188, %esi
0x00403852:	jne 0x0040385c
0x0040385c:	movl %edi, 0x4221ac
0x00403862:	cmpb (%edi), %bl
0x00403864:	je 57
0x00403866:	pushl %ebp
0x00403867:	pushl %edi
0x00403868:	call 0x00404280
0x0040386d:	movl %ebp, %eax
0x0040386f:	popl %ecx
0x00403870:	incl %ebp
0x00403871:	cmpb (%edi), $0x3d<UINT8>
0x00403874:	je 0x00403898
0x00403898:	addl %edi, %ebp
0x0040389a:	cmpb (%edi), %bl
0x0040389c:	jne -55
0x0040389e:	popl %ebp
0x0040389f:	pushl 0x4221ac
0x004038a5:	call 0x004021a9
0x004021a9:	pushl %esi
0x004021aa:	movl %esi, 0x8(%esp)
0x004021ae:	testl %esi, %esi
0x004021b0:	je 36
0x004021b2:	pushl %esi
0x004021b3:	call 0x00402d64
0x00402d64:	movl %eax, 0x422674
0x00402d69:	leal %ecx, (%eax,%eax,4)
0x00402d6c:	movl %eax, 0x422678
0x00402d71:	leal %ecx, (%eax,%ecx,4)
0x00402d74:	cmpl %eax, %ecx
0x00402d76:	jae 0x00402d8c
0x00402d78:	movl %edx, 0x4(%esp)
0x00402d7c:	subl %edx, 0xc(%eax)
0x00402d7f:	cmpl %edx, $0x100000<UINT32>
0x00402d85:	jb 7
0x00402d87:	addl %eax, $0x14<UINT8>
0x00402d8a:	jmp 0x00402d74
0x00402d8c:	xorl %eax, %eax
0x00402d8e:	ret

0x004021b8:	popl %ecx
0x004021b9:	testl %eax, %eax
0x004021bb:	pushl %esi
0x004021bc:	je 0x004021c8
0x004021c8:	pushl $0x0<UINT8>
0x004021ca:	pushl 0x42267c
0x004021d0:	call HeapFree@KERNEL32.DLL
HeapFree@KERNEL32.DLL: API Node	
0x004021d6:	popl %esi
0x004021d7:	ret

0x004038aa:	popl %ecx
0x004038ab:	movl 0x4221ac, %ebx
0x004038b1:	movl (%esi), %ebx
0x004038b3:	popl %edi
0x004038b4:	popl %esi
0x004038b5:	movl 0x4236a8, $0x1<UINT32>
0x004038bf:	popl %ebx
0x004038c0:	ret

0x004022ad:	call 0x00401fe1
0x00401fe1:	movl %eax, 0x4236b8
0x00401fe6:	testl %eax, %eax
0x00401fe8:	je 0x00401fec
0x00401fec:	pushl $0x407014<UINT32>
0x00401ff1:	pushl $0x407008<UINT32>
0x00401ff6:	call 0x004020c9
0x004020c9:	pushl %esi
0x004020ca:	movl %esi, 0x8(%esp)
0x004020ce:	cmpl %esi, 0xc(%esp)
0x004020d2:	jae 0x004020e1
0x004020d4:	movl %eax, (%esi)
0x004020d6:	testl %eax, %eax
0x004020d8:	je 0x004020dc
0x004020dc:	addl %esi, $0x4<UINT8>
0x004020df:	jmp 0x004020ce
0x004020da:	call 0x00404fa4
0x00402c16:	movl %eax, 0x4236a0
0x00402c1b:	pushl %esi
0x00402c1c:	pushl $0x14<UINT8>
0x00402c1e:	testl %eax, %eax
0x00402c20:	popl %esi
0x00402c21:	jne 7
0x00402c23:	movl %eax, $0x200<UINT32>
0x00402c28:	jmp 0x00402c30
0x00402c30:	movl 0x4236a0, %eax
0x00402c35:	pushl $0x4<UINT8>
0x00402c37:	pushl %eax
0x00402c38:	call 0x00404455
0x00404455:	pushl %ebx
0x00404456:	pushl %esi
0x00404457:	movl %esi, 0xc(%esp)
0x0040445b:	pushl %edi
0x0040445c:	imull %esi, 0x14(%esp)
0x00404461:	cmpl %esi, $0xffffffe0<UINT8>
0x00404464:	movl %ebx, %esi
0x00404466:	ja 13
0x00404468:	testl %esi, %esi
0x0040446a:	jne 0x0040446f
0x0040446f:	addl %esi, $0xf<UINT8>
0x00404472:	andl %esi, $0xfffffff0<UINT8>
0x00404475:	xorl %edi, %edi
0x00404477:	cmpl %esi, $0xffffffe0<UINT8>
0x0040447a:	ja 42
0x0040447c:	cmpl %ebx, 0x421b7c
0x00404482:	ja 0x00404491
0x00404491:	pushl %esi
0x00404492:	pushl $0x8<UINT8>
0x00404494:	pushl 0x42267c
0x0040449a:	call HeapAlloc@KERNEL32.DLL
0x004044a0:	movl %edi, %eax
0x004044a2:	testl %edi, %edi
0x004044a4:	jne 0x004044c8
0x004044c8:	movl %eax, %edi
0x004044ca:	popl %edi
0x004044cb:	popl %esi
0x004044cc:	popl %ebx
0x004044cd:	ret

0x00402c3d:	popl %ecx
0x00402c3e:	movl 0x422680, %eax
0x00402c43:	testl %eax, %eax
0x00402c45:	popl %ecx
0x00402c46:	jne 0x00402c69
0x00402c69:	xorl %ecx, %ecx
0x00402c6b:	movl %eax, $0x4218f8<UINT32>
0x00402c70:	movl %edx, 0x422680
0x00402c76:	movl (%ecx,%edx), %eax
0x00402c79:	addl %eax, $0x20<UINT8>
0x00402c7c:	addl %ecx, $0x4<UINT8>
0x00402c7f:	cmpl %eax, $0x421b78<UINT32>
0x00402c84:	jl 0x00402c70
0x00402c86:	xorl %edx, %edx
0x00402c88:	movl %ecx, $0x421908<UINT32>
0x00402c8d:	movl %eax, %edx
0x00402c8f:	movl %esi, %edx
0x00402c91:	sarl %eax, $0x5<UINT8>
0x00402c94:	andl %esi, $0x1f<UINT8>
0x00402c97:	movl %eax, 0x422560(,%eax,4)
0x00402c9e:	movl %eax, (%eax,%esi,8)
0x00402ca1:	cmpl %eax, $0xffffffff<UINT8>
0x00402ca4:	je 4
0x00402ca6:	testl %eax, %eax
0x00402ca8:	jne 0x00402cad
0x00402cad:	addl %ecx, $0x20<UINT8>
0x00402cb0:	incl %edx
0x00402cb1:	cmpl %ecx, $0x421968<UINT32>
0x00402cb7:	jl 0x00402c8d
0x00402cb9:	popl %esi
0x00402cba:	ret

0x004020e1:	popl %esi
0x004020e2:	ret

0x00401ffb:	pushl $0x407004<UINT32>
0x00402000:	pushl $0x407000<UINT32>
0x00402005:	call 0x004020c9
0x0040200a:	addl %esp, $0x10<UINT8>
0x0040200d:	ret

0x004022b2:	movl %eax, 0x422188
0x004022b7:	movl 0x42218c, %eax
0x004022bc:	pushl %eax
0x004022bd:	pushl 0x422180
0x004022c3:	pushl 0x42217c
0x004022c9:	call 0x00401660
0x00401660:	subl %esp, $0x10c<UINT32>
0x00401666:	pushl %ebx
0x00401667:	pushl %ebp
0x00401668:	pushl %esi
0x00401669:	pushl %edi
0x0040166a:	pushl $0x4075f8<UINT32>
0x0040166f:	movl 0x14(%esp), $0x0<UINT32>
0x00401677:	call 0x00401fb0
0x00401fb0:	pushl %ebx
0x00401fb1:	pushl %esi
0x00401fb2:	movl %esi, $0x421918<UINT32>
0x00401fb7:	pushl %edi
0x00401fb8:	pushl %esi
0x00401fb9:	call 0x00402342
0x00402342:	pushl %esi
0x00402343:	movl %esi, 0x8(%esp)
0x00402347:	pushl 0x10(%esi)
0x0040234a:	call 0x00404148
0x00404148:	movl %eax, 0x4(%esp)
0x0040414c:	cmpl %eax, 0x422660
0x00404152:	jb 0x00404157
0x00404157:	movl %ecx, %eax
0x00404159:	andl %eax, $0x1f<UINT8>
0x0040415c:	sarl %ecx, $0x5<UINT8>
0x0040415f:	movl %ecx, 0x422560(,%ecx,4)
0x00404166:	movb %al, 0x4(%ecx,%eax,8)
0x0040416a:	andl %eax, $0x40<UINT8>
0x0040416d:	ret

0x0040234f:	testl %eax, %eax
0x00402351:	popl %ecx
0x00402352:	je 119
0x00402354:	cmpl %esi, $0x421918<UINT32>
0x0040235a:	jne 4
0x0040235c:	xorl %eax, %eax
0x0040235e:	jmp 0x0040236b
0x0040236b:	incl 0x4221c0
0x00402371:	testw 0xc(%esi), $0x10c<UINT16>
0x00402377:	jne 82
0x00402379:	cmpl 0x4221b8(,%eax,4), $0x0<UINT8>
0x00402381:	pushl %ebx
0x00402382:	pushl %edi
0x00402383:	leal %edi, 0x4221b8(,%eax,4)
0x0040238a:	movl %ebx, $0x1000<UINT32>
0x0040238f:	jne 0x004023b1
0x00402391:	pushl %ebx
0x00402392:	call 0x004020e3
0x00402397:	testl %eax, %eax
0x00402399:	popl %ecx
0x0040239a:	movl (%edi), %eax
0x0040239c:	jne 0x004023b1
0x004023b1:	movl %edi, (%edi)
0x004023b3:	movl 0x18(%esi), %ebx
0x004023b6:	movl 0x8(%esi), %edi
0x004023b9:	movl (%esi), %edi
0x004023bb:	movl 0x4(%esi), %ebx
0x004023be:	orw 0xc(%esi), $0x1102<UINT16>
0x004023c4:	pushl $0x1<UINT8>
0x004023c6:	popl %eax
0x004023c7:	popl %edi
0x004023c8:	popl %ebx
0x004023c9:	popl %esi
0x004023ca:	ret

0x00401fbe:	movl %edi, %eax
0x00401fc0:	leal %eax, 0x18(%esp)
0x00401fc4:	pushl %eax
0x00401fc5:	pushl 0x18(%esp)
0x00401fc9:	pushl %esi
0x00401fca:	call 0x0040240c
0x0040240c:	pushl %ebp
0x0040240d:	movl %ebp, %esp
0x0040240f:	subl %esp, $0x248<UINT32>
0x00402415:	pushl %ebx
0x00402416:	pushl %esi
0x00402417:	pushl %edi
0x00402418:	movl %edi, 0xc(%ebp)
0x0040241b:	xorl %esi, %esi
0x0040241d:	movb %bl, (%edi)
0x0040241f:	incl %edi
0x00402420:	testb %bl, %bl
0x00402422:	movl -12(%ebp), %esi
0x00402425:	movl -20(%ebp), %esi
0x00402428:	movl 0xc(%ebp), %edi
0x0040242b:	je 1780
0x00402431:	movl %ecx, -16(%ebp)
0x00402434:	xorl %edx, %edx
0x00402436:	jmp 0x00402440
0x00402440:	cmpl -20(%ebp), %edx
0x00402443:	jl 1756
0x00402449:	cmpb %bl, $0x20<UINT8>
0x0040244c:	jl 0x00402461
0x00402461:	xorl %eax, %eax
0x00402463:	movsbl %eax, 0x406144(%esi,%eax,8)
0x0040246b:	sarl %eax, $0x4<UINT8>
0x0040246e:	cmpl %eax, $0x7<UINT8>
0x00402471:	movl -48(%ebp), %eax
0x00402474:	ja 1690
0x0040247a:	jmp 0x004025ef
0x004025ab:	movl %ecx, 0x421cc8
0x004025b1:	movl -36(%ebp), %edx
0x004025b4:	movzbl %eax, %bl
0x004025b7:	testb 0x1(%ecx,%eax,2), $0xffffff80<UINT8>
0x004025bc:	je 0x004025d7
0x004025d7:	leal %eax, -20(%ebp)
0x004025da:	pushl %eax
0x004025db:	pushl 0x8(%ebp)
0x004025de:	movsbl %eax, %bl
0x004025e1:	pushl %eax
0x004025e2:	call 0x00402b4d
0x00402b4d:	pushl %ebp
0x00402b4e:	movl %ebp, %esp
0x00402b50:	movl %ecx, 0xc(%ebp)
0x00402b53:	decl 0x4(%ecx)
0x00402b56:	js 14
0x00402b58:	movl %edx, (%ecx)
0x00402b5a:	movb %al, 0x8(%ebp)
0x00402b5d:	movb (%edx), %al
0x00402b5f:	incl (%ecx)
0x00402b61:	movzbl %eax, %al
0x00402b64:	jmp 0x00402b71
0x00402b71:	cmpl %eax, $0xffffffff<UINT8>
0x00402b74:	movl %eax, 0x10(%ebp)
0x00402b77:	jne 0x00402b7e
0x00402b7e:	incl (%eax)
0x00402b80:	popl %ebp
0x00402b81:	ret

0x004025e7:	addl %esp, $0xc<UINT8>
0x004025ea:	jmp 0x00402b14
0x00402b14:	movl %edi, 0xc(%ebp)
0x00402b17:	movb %bl, (%edi)
0x00402b19:	incl %edi
0x00402b1a:	testb %bl, %bl
0x00402b1c:	movl 0xc(%ebp), %edi
0x00402b1f:	jne 0x00402438
0x00402438:	movl %ecx, -16(%ebp)
0x0040243b:	movl %esi, -48(%ebp)
0x0040243e:	xorl %edx, %edx
0x0040244e:	cmpb %bl, $0x78<UINT8>
0x00402451:	jg 0x00402461
0x00402453:	movsbl %eax, %bl
0x00402456:	movb %al, 0x406124(%eax)
0x0040245c:	andl %eax, $0xf<UINT8>
0x0040245f:	jmp 0x00402463
0x00402b25:	movl %eax, -20(%ebp)
0x00402b28:	popl %edi
0x00402b29:	popl %esi
0x00402b2a:	popl %ebx
0x00402b2b:	leave
0x00402b2c:	ret

0x00401fcf:	pushl %esi
0x00401fd0:	pushl %edi
0x00401fd1:	movl %ebx, %eax
0x00401fd3:	call 0x004023cf
0x004023cf:	cmpl 0x4(%esp), $0x0<UINT8>
0x004023d4:	pushl %esi
0x004023d5:	je 34
0x004023d7:	movl %esi, 0xc(%esp)
0x004023db:	testb 0xd(%esi), $0x10<UINT8>
0x004023df:	je 41
0x004023e1:	pushl %esi
0x004023e2:	call 0x004041a9
0x004041a9:	pushl %ebx
0x004041aa:	pushl %esi
0x004041ab:	movl %esi, 0xc(%esp)
0x004041af:	xorl %ebx, %ebx
0x004041b1:	pushl %edi
0x004041b2:	movl %eax, 0xc(%esi)
0x004041b5:	movl %ecx, %eax
0x004041b7:	andl %ecx, $0x3<UINT8>
0x004041ba:	cmpb %cl, $0x2<UINT8>
0x004041bd:	jne 55
0x004041bf:	testw %ax, $0x108<UINT16>
0x004041c3:	je 49
0x004041c5:	movl %eax, 0x8(%esi)
0x004041c8:	movl %edi, (%esi)
0x004041ca:	subl %edi, %eax
0x004041cc:	testl %edi, %edi
0x004041ce:	jle 38
0x004041d0:	pushl %edi
0x004041d1:	pushl %eax
0x004041d2:	pushl 0x10(%esi)
0x004041d5:	call 0x004048ff
0x004048ff:	pushl %ebp
0x00404900:	movl %ebp, %esp
0x00404902:	subl %esp, $0x414<UINT32>
0x00404908:	movl %ecx, 0x8(%ebp)
0x0040490b:	pushl %ebx
0x0040490c:	cmpl %ecx, 0x422660
0x00404912:	pushl %esi
0x00404913:	pushl %edi
0x00404914:	jae 377
0x0040491a:	movl %eax, %ecx
0x0040491c:	movl %esi, %ecx
0x0040491e:	sarl %eax, $0x5<UINT8>
0x00404921:	andl %esi, $0x1f<UINT8>
0x00404924:	leal %ebx, 0x422560(,%eax,4)
0x0040492b:	shll %esi, $0x3<UINT8>
0x0040492e:	movl %eax, (%ebx)
0x00404930:	movb %al, 0x4(%eax,%esi)
0x00404934:	testb %al, $0x1<UINT8>
0x00404936:	je 343
0x0040493c:	xorl %edi, %edi
0x0040493e:	cmpl 0x10(%ebp), %edi
0x00404941:	movl -8(%ebp), %edi
0x00404944:	movl -16(%ebp), %edi
0x00404947:	jne 0x00404950
0x00404950:	testb %al, $0x20<UINT8>
0x00404952:	je 0x00404960
0x00404960:	movl %eax, (%ebx)
0x00404962:	addl %eax, %esi
0x00404964:	testb 0x4(%eax), $0xffffff80<UINT8>
0x00404968:	je 193
0x0040496e:	movl %eax, 0xc(%ebp)
0x00404971:	cmpl 0x10(%ebp), %edi
0x00404974:	movl -4(%ebp), %eax
0x00404977:	movl 0x8(%ebp), %edi
0x0040497a:	jbe 231
0x00404980:	leal %eax, -1044(%ebp)
0x00404986:	movl %ecx, -4(%ebp)
0x00404989:	subl %ecx, 0xc(%ebp)
0x0040498c:	cmpl %ecx, 0x10(%ebp)
0x0040498f:	jae 0x004049ba
0x00404991:	movl %ecx, -4(%ebp)
0x00404994:	incl -4(%ebp)
0x00404997:	movb %cl, (%ecx)
0x00404999:	cmpb %cl, $0xa<UINT8>
0x0040499c:	jne 0x004049a5
0x0040499e:	incl -16(%ebp)
0x004049a1:	movb (%eax), $0xd<UINT8>
0x004049a4:	incl %eax
0x004049a5:	movb (%eax), %cl
0x004049a7:	incl %eax
0x004049a8:	movl %ecx, %eax
0x004049aa:	leal %edx, -1044(%ebp)
0x004049b0:	subl %ecx, %edx
0x004049b2:	cmpl %ecx, $0x400<UINT32>
0x004049b8:	jl 0x00404986
0x004049ba:	movl %edi, %eax
0x004049bc:	leal %eax, -1044(%ebp)
0x004049c2:	subl %edi, %eax
0x004049c4:	leal %eax, -12(%ebp)
0x004049c7:	pushl $0x0<UINT8>
0x004049c9:	pushl %eax
0x004049ca:	leal %eax, -1044(%ebp)
0x004049d0:	pushl %edi
0x004049d1:	pushl %eax
0x004049d2:	movl %eax, (%ebx)
0x004049d4:	pushl (%eax,%esi)
0x004049d7:	call WriteFile@KERNEL32.DLL
WriteFile@KERNEL32.DLL: API Node	
0x004049dd:	testl %eax, %eax
0x004049df:	je 67
0x004049e1:	movl %eax, -12(%ebp)
0x004049e4:	addl -8(%ebp), %eax
0x004049e7:	cmpl %eax, %edi
0x004049e9:	jl 0x004049f6
0x004049f6:	xorl %edi, %edi
0x004049f8:	movl %eax, -8(%ebp)
0x004049fb:	cmpl %eax, %edi
0x004049fd:	jne 0x00404a8e
0x00404a8e:	subl %eax, -16(%ebp)
0x00404a91:	jmp 0x00404aa7
0x00404aa7:	popl %edi
0x00404aa8:	popl %esi
0x00404aa9:	popl %ebx
0x00404aaa:	leave
0x00404aab:	ret

0x004041da:	addl %esp, $0xc<UINT8>
0x004041dd:	cmpl %eax, %edi
0x004041df:	jne 0x004041ef
0x004041ef:	orl 0xc(%esi), $0x20<UINT8>
0x004041f3:	orl %ebx, $0xffffffff<UINT8>
0x004041f6:	movl %eax, 0x8(%esi)
0x004041f9:	andl 0x4(%esi), $0x0<UINT8>
0x004041fd:	movl (%esi), %eax
0x004041ff:	popl %edi
0x00404200:	movl %eax, %ebx
0x00404202:	popl %esi
0x00404203:	popl %ebx
0x00404204:	ret

0x004023e7:	andb 0xd(%esi), $0xffffffee<UINT8>
0x004023eb:	andl 0x18(%esi), $0x0<UINT8>
0x004023ef:	andl (%esi), $0x0<UINT8>
0x004023f2:	andl 0x8(%esi), $0x0<UINT8>
0x004023f6:	popl %ecx
0x004023f7:	popl %esi
0x004023f8:	ret

0x00401fd8:	addl %esp, $0x18<UINT8>
0x00401fdb:	movl %eax, %ebx
0x00401fdd:	popl %edi
0x00401fde:	popl %esi
0x00401fdf:	popl %ebx
0x00401fe0:	ret

0x0040167c:	pushl $0x4075cc<UINT32>
0x00401681:	call 0x00401fb0
0x00401686:	pushl $0x4075a4<UINT32>
0x0040168b:	call 0x00401fb0
0x00401690:	pushl $0x407598<UINT32>
0x00401695:	call 0x00401940
0x00401940:	subl %esp, $0x110<UINT32>
0x00401946:	movl %eax, 0x114(%esp)
0x0040194d:	pushl %ebx
0x0040194e:	pushl %eax
0x0040194f:	leal %ecx, 0x14(%esp)
0x00401953:	xorl %ebx, %ebx
0x00401955:	pushl $0x421898<UINT32>
0x0040195a:	pushl %ecx
0x0040195b:	movl 0x14(%esp), %ebx
0x0040195f:	movl 0x10(%esp), %ebx
0x00401963:	call 0x00402157
0x00402157:	pushl %ebp
0x00402158:	movl %ebp, %esp
0x0040215a:	subl %esp, $0x20<UINT8>
0x0040215d:	movl %eax, 0x8(%ebp)
0x00402160:	pushl %esi
0x00402161:	movl -24(%ebp), %eax
0x00402164:	movl -32(%ebp), %eax
0x00402167:	leal %eax, 0x10(%ebp)
0x0040216a:	movl -20(%ebp), $0x42<UINT32>
0x00402171:	pushl %eax
0x00402172:	leal %eax, -32(%ebp)
0x00402175:	pushl 0xc(%ebp)
0x00402178:	movl -28(%ebp), $0x7fffffff<UINT32>
0x0040217f:	pushl %eax
0x00402180:	call 0x0040240c
0x00402481:	orl -16(%ebp), $0xffffffff<UINT8>
0x00402485:	movl -52(%ebp), %edx
0x00402488:	movl -40(%ebp), %edx
0x0040248b:	movl -32(%ebp), %edx
0x0040248e:	movl -28(%ebp), %edx
0x00402491:	movl -4(%ebp), %edx
0x00402494:	movl -36(%ebp), %edx
0x00402497:	jmp 0x00402b14
0x004025ef:	movsbl %eax, %bl
0x004025f2:	cmpl %eax, $0x67<UINT8>
0x004025f5:	jg 0x00402817
0x00402817:	subl %eax, $0x69<UINT8>
0x0040281a:	je 209
0x00402820:	subl %eax, $0x5<UINT8>
0x00402823:	je 158
0x00402829:	decl %eax
0x0040282a:	je 132
0x00402830:	decl %eax
0x00402831:	je 81
0x00402833:	subl %eax, $0x3<UINT8>
0x00402836:	je 0x00402639
0x00402639:	movl %esi, -16(%ebp)
0x0040263c:	cmpl %esi, $0xffffffff<UINT8>
0x0040263f:	jne 5
0x00402641:	movl %esi, $0x7fffffff<UINT32>
0x00402646:	leal %eax, 0x10(%ebp)
0x00402649:	pushl %eax
0x0040264a:	call 0x00402beb
0x00402beb:	movl %eax, 0x4(%esp)
0x00402bef:	addl (%eax), $0x4<UINT8>
0x00402bf2:	movl %eax, (%eax)
0x00402bf4:	movl %eax, -4(%eax)
0x00402bf7:	ret

0x0040264f:	testw -4(%ebp), $0x810<UINT16>
0x00402655:	popl %ecx
0x00402656:	movl %ecx, %eax
0x00402658:	movl -8(%ebp), %ecx
0x0040265b:	je 0x0040285f
0x0040285f:	testl %ecx, %ecx
0x00402861:	jne 0x0040286c
0x0040286c:	movl %eax, %ecx
0x0040286e:	movl %edx, %esi
0x00402870:	decl %esi
0x00402871:	testl %edx, %edx
0x00402873:	je 8
0x00402875:	cmpb (%eax), $0x0<UINT8>
0x00402878:	je 0x0040287d
0x0040287a:	incl %eax
0x0040287b:	jmp 0x0040286e
0x0040287d:	subl %eax, %ecx
0x0040287f:	jmp 0x00402a13
0x00402a13:	movl -12(%ebp), %eax
0x00402a16:	cmpl -40(%ebp), $0x0<UINT8>
0x00402a1a:	jne 244
0x00402a20:	movl %ebx, -4(%ebp)
0x00402a23:	testb %bl, $0x40<UINT8>
0x00402a26:	je 0x00402a4e
0x00402a4e:	movl %esi, -32(%ebp)
0x00402a51:	subl %esi, -28(%ebp)
0x00402a54:	subl %esi, -12(%ebp)
0x00402a57:	testb %bl, $0xc<UINT8>
0x00402a5a:	jne 18
0x00402a5c:	leal %eax, -20(%ebp)
0x00402a5f:	pushl %eax
0x00402a60:	pushl 0x8(%ebp)
0x00402a63:	pushl %esi
0x00402a64:	pushl $0x20<UINT8>
0x00402a66:	call 0x00402b82
0x00402b82:	pushl %esi
0x00402b83:	pushl %edi
0x00402b84:	movl %edi, 0x10(%esp)
0x00402b88:	movl %eax, %edi
0x00402b8a:	decl %edi
0x00402b8b:	testl %eax, %eax
0x00402b8d:	jle 0x00402bb0
0x00402bb0:	popl %edi
0x00402bb1:	popl %esi
0x00402bb2:	ret

0x00402a6b:	addl %esp, $0x10<UINT8>
0x00402a6e:	leal %eax, -20(%ebp)
0x00402a71:	pushl %eax
0x00402a72:	leal %eax, -22(%ebp)
0x00402a75:	pushl 0x8(%ebp)
0x00402a78:	pushl -28(%ebp)
0x00402a7b:	pushl %eax
0x00402a7c:	call 0x00402bb3
0x00402bb3:	pushl %ebx
0x00402bb4:	movl %ebx, 0xc(%esp)
0x00402bb8:	movl %eax, %ebx
0x00402bba:	decl %ebx
0x00402bbb:	pushl %esi
0x00402bbc:	pushl %edi
0x00402bbd:	testl %eax, %eax
0x00402bbf:	jle 0x00402be7
0x00402be7:	popl %edi
0x00402be8:	popl %esi
0x00402be9:	popl %ebx
0x00402bea:	ret

0x00402a81:	addl %esp, $0x10<UINT8>
0x00402a84:	testb %bl, $0x8<UINT8>
0x00402a87:	je 0x00402aa0
0x00402aa0:	cmpl -36(%ebp), $0x0<UINT8>
0x00402aa4:	je 0x00402ae7
0x00402ae7:	leal %eax, -20(%ebp)
0x00402aea:	pushl %eax
0x00402aeb:	pushl 0x8(%ebp)
0x00402aee:	pushl -12(%ebp)
0x00402af1:	pushl -8(%ebp)
0x00402af4:	call 0x00402bb3
0x00402bc1:	movl %edi, 0x1c(%esp)
0x00402bc5:	movl %esi, 0x10(%esp)
0x00402bc9:	movsbl %eax, (%esi)
0x00402bcc:	pushl %edi
0x00402bcd:	incl %esi
0x00402bce:	pushl 0x1c(%esp)
0x00402bd2:	pushl %eax
0x00402bd3:	call 0x00402b4d
0x00402bd8:	addl %esp, $0xc<UINT8>
0x00402bdb:	cmpl (%edi), $0xffffffff<UINT8>
0x00402bde:	je 7
0x00402be0:	movl %eax, %ebx
0x00402be2:	decl %ebx
0x00402be3:	testl %eax, %eax
0x00402be5:	jg 0x00402bc9
0x00402af9:	addl %esp, $0x10<UINT8>
0x00402afc:	testb -4(%ebp), $0x4<UINT8>
0x00402b00:	je 0x00402b14
0x00402185:	addl %esp, $0xc<UINT8>
0x00402188:	decl -28(%ebp)
0x0040218b:	movl %esi, %eax
0x0040218d:	js 8
0x0040218f:	movl %eax, -32(%ebp)
0x00402192:	andb (%eax), $0x0<UINT8>
0x00402195:	jmp 0x004021a4
0x004021a4:	movl %eax, %esi
0x004021a6:	popl %esi
0x004021a7:	leave
0x004021a8:	ret

0x00401968:	addl %esp, $0xc<UINT8>
0x0040196b:	leal %edx, 0x8(%esp)
0x0040196f:	leal %eax, 0x10(%esp)
0x00401973:	pushl %edx
0x00401974:	pushl %eax
0x00401975:	pushl $0x80000001<UINT32>
0x0040197a:	call RegCreateKeyA@ADVAPI32.dll
RegCreateKeyA@ADVAPI32.dll: API Node	
0x00401980:	testl %eax, %eax
0x00401982:	jne 36
0x00401984:	movl %eax, 0x8(%esp)
0x00401988:	leal %ecx, 0xc(%esp)
0x0040198c:	leal %edx, 0x4(%esp)
0x00401990:	pushl %ecx
0x00401991:	pushl %edx
0x00401992:	pushl %ebx
0x00401993:	pushl %ebx
0x00401994:	pushl $0x421888<UINT32>
0x00401999:	pushl %eax
0x0040199a:	movl 0x24(%esp), $0x4<UINT32>
0x004019a2:	call RegQueryValueExA@ADVAPI32.dll
RegQueryValueExA@ADVAPI32.dll: API Node	
0x004019a8:	cmpl 0x4(%esp), %ebx
0x004019ac:	jne 511
0x004019b2:	pushl %esi
0x004019b3:	pushl %edi
0x004019b4:	pushl $0x3e8<UINT32>
0x004019b9:	pushl $0x40<UINT8>
0x004019bb:	call LocalAlloc@KERNEL32.DLL
LocalAlloc@KERNEL32.DLL: API Node	
0x004019c1:	movl %esi, %eax
0x004019c3:	pushl $0x421878<UINT32>
0x004019c8:	leal %edi, 0x12(%esi)
0x004019cb:	call LoadLibraryA@KERNEL32.DLL
0x004019d1:	movl (%esi), $0x80c808d0<UINT32>
0x00403ee4:	pushl %ebp
0x00403ee5:	movl %ebp, %esp
0x00403ee7:	subl %esp, $0x8<UINT8>
0x00403eea:	pushl %ebx
0x00403eeb:	pushl %esi
0x00403eec:	pushl %edi
0x00403eed:	pushl %ebp
0x00403eee:	cld
0x00403eef:	movl %ebx, 0xc(%ebp)
0x00403ef2:	movl %eax, 0x8(%ebp)
0x00403ef5:	testl 0x4(%eax), $0x6<UINT32>
0x00403efc:	jne 130
0x00403f02:	movl -8(%ebp), %eax
0x00403f05:	movl %eax, 0x10(%ebp)
0x00403f08:	movl -4(%ebp), %eax
0x00403f0b:	leal %eax, -8(%ebp)
0x00403f0e:	movl -4(%ebx), %eax
0x00403f11:	movl %esi, 0xc(%ebx)
0x00403f14:	movl %edi, 0x8(%ebx)
0x00403f17:	cmpl %esi, $0xffffffff<UINT8>
0x00403f1a:	je 97
0x00403f1c:	leal %ecx, (%esi,%esi,2)
0x00403f1f:	cmpl 0x4(%edi,%ecx,4), $0x0<UINT8>
0x00403f24:	je 69
0x00403f26:	pushl %esi
0x00403f27:	pushl %ebp
0x00403f28:	leal %ebp, 0x10(%ebx)
0x00403f2b:	call 0x004022da
0x004022da:	movl %eax, -20(%ebp)
0x004022dd:	movl %ecx, (%eax)
0x004022df:	movl %ecx, (%ecx)
0x004022e1:	movl -32(%ebp), %ecx
0x004022e4:	pushl %eax
0x004022e5:	pushl %ecx
0x004022e6:	call 0x00403684
0x00403684:	pushl %ebp
0x00403685:	movl %ebp, %esp
0x00403687:	pushl %ebx
0x00403688:	pushl 0x8(%ebp)
0x0040368b:	call 0x004037c5
0x004037c5:	movl %edx, 0x4(%esp)
0x004037c9:	movl %ecx, 0x421c00
0x004037cf:	cmpl 0x421b80, %edx
0x004037d5:	pushl %esi
0x004037d6:	movl %eax, $0x421b80<UINT32>
0x004037db:	je 0x004037f2
0x004037f2:	leal %ecx, (%ecx,%ecx,2)
0x004037f5:	popl %esi
0x004037f6:	leal %ecx, 0x421b80(,%ecx,4)
0x004037fd:	cmpl %eax, %ecx
0x004037ff:	jae 4
0x00403801:	cmpl (%eax), %edx
0x00403803:	je 0x00403807
0x00403807:	ret

0x00403690:	testl %eax, %eax
0x00403692:	popl %ecx
0x00403693:	je 288
0x00403699:	movl %ebx, 0x8(%eax)
0x0040369c:	testl %ebx, %ebx
0x0040369e:	je 0x004037b9
0x004037b9:	pushl 0xc(%ebp)
0x004037bc:	call UnhandledExceptionFilter@KERNEL32.DLL
UnhandledExceptionFilter@KERNEL32.DLL: API Node	
0x004037c2:	popl %ebx
0x004037c3:	popl %ebp
0x004037c4:	ret

0x004022eb:	popl %ecx
0x004022ec:	popl %ecx
0x004022ed:	ret

0x00403f2f:	popl %ebp
0x00403f30:	popl %esi
0x00403f31:	movl %ebx, 0xc(%ebp)
0x00403f34:	orl %eax, %eax
0x00403f36:	je 51
0x00403f38:	js 60
0x00403f3a:	movl %edi, 0x8(%ebx)
0x00403f3d:	pushl %ebx
0x00403f3e:	call 0x00403dec
0x00403dec:	pushl %ebp
0x00403ded:	movl %ebp, %esp
0x00403def:	pushl %ebx
0x00403df0:	pushl %esi
0x00403df1:	pushl %edi
0x00403df2:	pushl %ebp
0x00403df3:	pushl $0x0<UINT8>
0x00403df5:	pushl $0x0<UINT8>
0x00403df7:	pushl $0x403e04<UINT32>
0x00403dfc:	pushl 0x8(%ebp)
0x00403dff:	call 0x00405b60
0x00405b60:	jmp RtlUnwind@KERNEL32.DLL
RtlUnwind@KERNEL32.DLL: API Node	
0x00403e04:	popl %ebp
0x00403e05:	popl %edi
0x00403e06:	popl %esi
0x00403e07:	popl %ebx
0x00403e08:	movl %esp, %ebp
0x00403e0a:	popl %ebp
0x00403e0b:	ret

0x00403f43:	addl %esp, $0x4<UINT8>
0x00403f46:	leal %ebp, 0x10(%ebx)
0x00403f49:	pushl %esi
0x00403f4a:	pushl %ebx
0x00403f4b:	call 0x00403e2e
0x00403e2e:	pushl %ebx
0x00403e2f:	pushl %esi
0x00403e30:	pushl %edi
0x00403e31:	movl %eax, 0x10(%esp)
0x00403e35:	pushl %eax
0x00403e36:	pushl $0xfffffffe<UINT8>
0x00403e38:	pushl $0x403e0c<UINT32>
0x00403e3d:	pushl %fs:0
0x00403e44:	movl %fs:0, %esp
0x00403e4b:	movl %eax, 0x20(%esp)
0x00403e4f:	movl %ebx, 0x8(%eax)
0x00403e52:	movl %esi, 0xc(%eax)
0x00403e55:	cmpl %esi, $0xffffffff<UINT8>
0x00403e58:	je 46
0x00403e5a:	cmpl %esi, 0x24(%esp)
0x00403e5e:	je 0x00403e88
0x00403e88:	popl %fs:0
0x00403e8f:	addl %esp, $0xc<UINT8>
0x00403e92:	popl %edi
0x00403e93:	popl %esi
0x00403e94:	popl %ebx
0x00403e95:	ret

0x00403f50:	addl %esp, $0x8<UINT8>
0x00403f53:	leal %ecx, (%esi,%esi,2)
0x00403f56:	pushl $0x1<UINT8>
0x00403f58:	movl %eax, 0x8(%edi,%ecx,4)
0x00403f5c:	call 0x00403ec2
0x00403ec2:	pushl %ebx
0x00403ec3:	pushl %ecx
0x00403ec4:	movl %ebx, $0x421c10<UINT32>
0x00403ec9:	movl %ecx, 0x8(%ebp)
0x00403ecc:	movl 0x8(%ebx), %ecx
0x00403ecf:	movl 0x4(%ebx), %eax
0x00403ed2:	movl 0xc(%ebx), %ebp
0x00403ed5:	popl %ecx
0x00403ed6:	popl %ebx
0x00403ed7:	ret $0x4<UINT16>

0x00403f61:	movl %eax, (%edi,%ecx,4)
0x00403f64:	movl 0xc(%ebx), %eax
0x00403f67:	call 0x004022ee
0x004022ee:	movl %esp, -24(%ebp)
0x004022f1:	pushl -32(%ebp)
0x004022f4:	call 0x0040201f
0x0040201f:	pushl $0x0<UINT8>
0x00402021:	pushl $0x1<UINT8>
0x00402023:	pushl 0xc(%esp)
0x00402027:	call 0x00402030
0x00402030:	pushl %edi
0x00402031:	pushl $0x1<UINT8>
0x00402033:	popl %edi
0x00402034:	cmpl 0x4221a8, %edi
0x0040203a:	jne 0x0040204d
0x0040204d:	cmpl 0xc(%esp), $0x0<UINT8>
0x00402052:	pushl %ebx
0x00402053:	movl %ebx, 0x14(%esp)
0x00402057:	movl 0x4221a4, %edi
0x0040205d:	movb 0x4221a0, %bl
0x00402063:	jne 0x004020a1
0x004020a1:	pushl $0x407028<UINT32>
0x004020a6:	pushl $0x407024<UINT32>
0x004020ab:	call 0x004020c9
0x004020b0:	popl %ecx
0x004020b1:	popl %ecx
0x004020b2:	testl %ebx, %ebx
0x004020b4:	popl %ebx
0x004020b5:	jne 16
0x004020b7:	pushl 0x8(%esp)
0x004020bb:	movl 0x4221a8, %edi
0x004020c1:	call ExitProcess@KERNEL32.DLL
ExitProcess@KERNEL32.DLL: Exit Node	
