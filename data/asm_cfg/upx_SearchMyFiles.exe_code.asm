0x0042a650:	pusha
0x0042a651:	movl %esi, $0x419000<UINT32>
0x0042a656:	leal %edi, -98304(%esi)
0x0042a65c:	pushl %edi
0x0042a65d:	orl %ebp, $0xffffffff<UINT8>
0x0042a660:	jmp 0x0042a672
0x0042a672:	movl %ebx, (%esi)
0x0042a674:	subl %esi, $0xfffffffc<UINT8>
0x0042a677:	adcl %ebx, %ebx
0x0042a679:	jb 0x0042a668
0x0042a668:	movb %al, (%esi)
0x0042a66a:	incl %esi
0x0042a66b:	movb (%edi), %al
0x0042a66d:	incl %edi
0x0042a66e:	addl %ebx, %ebx
0x0042a670:	jne 0x0042a679
0x0042a67b:	movl %eax, $0x1<UINT32>
0x0042a680:	addl %ebx, %ebx
0x0042a682:	jne 0x0042a68b
0x0042a68b:	adcl %eax, %eax
0x0042a68d:	addl %ebx, %ebx
0x0042a68f:	jae 0x0042a680
0x0042a691:	jne 0x0042a69c
0x0042a69c:	xorl %ecx, %ecx
0x0042a69e:	subl %eax, $0x3<UINT8>
0x0042a6a1:	jb 0x0042a6b0
0x0042a6b0:	addl %ebx, %ebx
0x0042a6b2:	jne 0x0042a6bb
0x0042a6bb:	adcl %ecx, %ecx
0x0042a6bd:	addl %ebx, %ebx
0x0042a6bf:	jne 0x0042a6c8
0x0042a6c8:	adcl %ecx, %ecx
0x0042a6ca:	jne 0x0042a6ec
0x0042a6ec:	cmpl %ebp, $0xfffff300<UINT32>
0x0042a6f2:	adcl %ecx, $0x1<UINT8>
0x0042a6f5:	leal %edx, (%edi,%ebp)
0x0042a6f8:	cmpl %ebp, $0xfffffffc<UINT8>
0x0042a6fb:	jbe 0x0042a70c
0x0042a6fd:	movb %al, (%edx)
0x0042a6ff:	incl %edx
0x0042a700:	movb (%edi), %al
0x0042a702:	incl %edi
0x0042a703:	decl %ecx
0x0042a704:	jne 0x0042a6fd
0x0042a706:	jmp 0x0042a66e
0x0042a6a3:	shll %eax, $0x8<UINT8>
0x0042a6a6:	movb %al, (%esi)
0x0042a6a8:	incl %esi
0x0042a6a9:	xorl %eax, $0xffffffff<UINT8>
0x0042a6ac:	je 0x0042a722
0x0042a6ae:	movl %ebp, %eax
0x0042a70c:	movl %eax, (%edx)
0x0042a70e:	addl %edx, $0x4<UINT8>
0x0042a711:	movl (%edi), %eax
0x0042a713:	addl %edi, $0x4<UINT8>
0x0042a716:	subl %ecx, $0x4<UINT8>
0x0042a719:	ja 0x0042a70c
0x0042a71b:	addl %edi, %ecx
0x0042a71d:	jmp 0x0042a66e
0x0042a684:	movl %ebx, (%esi)
0x0042a686:	subl %esi, $0xfffffffc<UINT8>
0x0042a689:	adcl %ebx, %ebx
0x0042a6b4:	movl %ebx, (%esi)
0x0042a6b6:	subl %esi, $0xfffffffc<UINT8>
0x0042a6b9:	adcl %ebx, %ebx
0x0042a6cc:	incl %ecx
0x0042a6cd:	addl %ebx, %ebx
0x0042a6cf:	jne 0x0042a6d8
0x0042a6d8:	adcl %ecx, %ecx
0x0042a6da:	addl %ebx, %ebx
0x0042a6dc:	jae 0x0042a6cd
0x0042a6de:	jne 0x0042a6e9
0x0042a6e9:	addl %ecx, $0x2<UINT8>
0x0042a6c1:	movl %ebx, (%esi)
0x0042a6c3:	subl %esi, $0xfffffffc<UINT8>
0x0042a6c6:	adcl %ebx, %ebx
0x0042a693:	movl %ebx, (%esi)
0x0042a695:	subl %esi, $0xfffffffc<UINT8>
0x0042a698:	adcl %ebx, %ebx
0x0042a69a:	jae 0x0042a680
0x0042a6d1:	movl %ebx, (%esi)
0x0042a6d3:	subl %esi, $0xfffffffc<UINT8>
0x0042a6d6:	adcl %ebx, %ebx
0x0042a6e0:	movl %ebx, (%esi)
0x0042a6e2:	subl %esi, $0xfffffffc<UINT8>
0x0042a6e5:	adcl %ebx, %ebx
0x0042a6e7:	jae 0x0042a6cd
0x0042a722:	popl %esi
0x0042a723:	movl %edi, %esi
0x0042a725:	movl %ecx, $0x9ca<UINT32>
0x0042a72a:	movb %al, (%edi)
0x0042a72c:	incl %edi
0x0042a72d:	subb %al, $0xffffffe8<UINT8>
0x0042a72f:	cmpb %al, $0x1<UINT8>
0x0042a731:	ja 0x0042a72a
0x0042a733:	cmpb (%edi), $0x2<UINT8>
0x0042a736:	jne 0x0042a72a
0x0042a738:	movl %eax, (%edi)
0x0042a73a:	movb %bl, 0x4(%edi)
0x0042a73d:	shrw %ax, $0x8<UINT8>
0x0042a741:	roll %eax, $0x10<UINT8>
0x0042a744:	xchgb %ah, %al
0x0042a746:	subl %eax, %edi
0x0042a748:	subb %bl, $0xffffffe8<UINT8>
0x0042a74b:	addl %eax, %esi
0x0042a74d:	movl (%edi), %eax
0x0042a74f:	addl %edi, $0x5<UINT8>
0x0042a752:	movb %al, %bl
0x0042a754:	loop 0x0042a72f
0x0042a756:	leal %edi, 0x27000(%esi)
0x0042a75c:	movl %eax, (%edi)
0x0042a75e:	orl %eax, %eax
0x0042a760:	je 0x0042a7a7
0x0042a762:	movl %ebx, 0x4(%edi)
0x0042a765:	leal %eax, 0x2ba64(%eax,%esi)
0x0042a76c:	addl %ebx, %esi
0x0042a76e:	pushl %eax
0x0042a76f:	addl %edi, $0x8<UINT8>
0x0042a772:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0042a778:	xchgl %ebp, %eax
0x0042a779:	movb %al, (%edi)
0x0042a77b:	incl %edi
0x0042a77c:	orb %al, %al
0x0042a77e:	je 0x0042a75c
0x0042a780:	movl %ecx, %edi
0x0042a782:	jns 0x0042a78b
0x0042a78b:	pushl %edi
0x0042a78c:	decl %eax
0x0042a78d:	repn scasb %al, %es:(%edi)
0x0042a78f:	pushl %ebp
0x0042a790:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0042a796:	orl %eax, %eax
0x0042a798:	je 7
0x0042a79a:	movl (%ebx), %eax
0x0042a79c:	addl %ebx, $0x4<UINT8>
0x0042a79f:	jmp 0x0042a779
GetProcAddress@KERNEL32.DLL: API Node	
0x0042a784:	movzwl %eax, (%edi)
0x0042a787:	incl %edi
0x0042a788:	pushl %eax
0x0042a789:	incl %edi
0x0042a78a:	movl %ecx, $0xaef24857<UINT32>
0x0042a7a7:	movl %ebp, 0x2bb80(%esi)
0x0042a7ad:	leal %edi, -4096(%esi)
0x0042a7b3:	movl %ebx, $0x1000<UINT32>
0x0042a7b8:	pushl %eax
0x0042a7b9:	pushl %esp
0x0042a7ba:	pushl $0x4<UINT8>
0x0042a7bc:	pushl %ebx
0x0042a7bd:	pushl %edi
0x0042a7be:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0042a7c0:	leal %eax, 0x217(%edi)
0x0042a7c6:	andb (%eax), $0x7f<UINT8>
0x0042a7c9:	andb 0x28(%eax), $0x7f<UINT8>
0x0042a7cd:	popl %eax
0x0042a7ce:	pushl %eax
0x0042a7cf:	pushl %esp
0x0042a7d0:	pushl %eax
0x0042a7d1:	pushl %ebx
0x0042a7d2:	pushl %edi
0x0042a7d3:	call VirtualProtect@kernel32.dll
0x0042a7d5:	popl %eax
0x0042a7d6:	popa
0x0042a7d7:	leal %eax, -128(%esp)
0x0042a7db:	pushl $0x0<UINT8>
0x0042a7dd:	cmpl %esp, %eax
0x0042a7df:	jne 0x0042a7db
0x0042a7e1:	subl %esp, $0xffffff80<UINT8>
0x0042a7e4:	jmp 0x00418100
0x00418100:	pushl $0x70<UINT8>
0x00418102:	pushl $0x4194a0<UINT32>
0x00418107:	call 0x00418310
0x00418310:	pushl $0x418360<UINT32>
0x00418315:	movl %eax, %fs:0
0x0041831b:	pushl %eax
0x0041831c:	movl %fs:0, %esp
0x00418323:	movl %eax, 0x10(%esp)
0x00418327:	movl 0x10(%esp), %ebp
0x0041832b:	leal %ebp, 0x10(%esp)
0x0041832f:	subl %esp, %eax
0x00418331:	pushl %ebx
0x00418332:	pushl %esi
0x00418333:	pushl %edi
0x00418334:	movl %eax, -8(%ebp)
0x00418337:	movl -24(%ebp), %esp
0x0041833a:	pushl %eax
0x0041833b:	movl %eax, -4(%ebp)
0x0041833e:	movl -4(%ebp), $0xffffffff<UINT32>
0x00418345:	movl -8(%ebp), %eax
0x00418348:	ret

0x0041810c:	xorl %edi, %edi
0x0041810e:	pushl %edi
0x0041810f:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x00418115:	cmpw (%eax), $0x5a4d<UINT16>
0x0041811a:	jne 31
0x0041811c:	movl %ecx, 0x3c(%eax)
0x0041811f:	addl %ecx, %eax
0x00418121:	cmpl (%ecx), $0x4550<UINT32>
0x00418127:	jne 18
0x00418129:	movzwl %eax, 0x18(%ecx)
0x0041812d:	cmpl %eax, $0x10b<UINT32>
0x00418132:	je 0x00418153
0x00418153:	cmpl 0x74(%ecx), $0xe<UINT8>
0x00418157:	jbe -30
0x00418159:	xorl %eax, %eax
0x0041815b:	cmpl 0xe8(%ecx), %edi
0x00418161:	setne %al
0x00418164:	movl -28(%ebp), %eax
0x00418167:	movl -4(%ebp), %edi
0x0041816a:	pushl $0x2<UINT8>
0x0041816c:	popl %ebx
0x0041816d:	pushl %ebx
0x0041816e:	call __set_app_type@msvcrt.dll
__set_app_type@msvcrt.dll: API Node	
0x00418174:	popl %ecx
0x00418175:	orl 0x421a60, $0xffffffff<UINT8>
0x0041817c:	orl 0x421a64, $0xffffffff<UINT8>
0x00418183:	call __p__fmode@msvcrt.dll
__p__fmode@msvcrt.dll: API Node	
0x00418189:	movl %ecx, 0x42069c
0x0041818f:	movl (%eax), %ecx
0x00418191:	call __p__commode@msvcrt.dll
__p__commode@msvcrt.dll: API Node	
0x00418197:	movl %ecx, 0x420698
0x0041819d:	movl (%eax), %ecx
0x0041819f:	movl %eax, 0x419354
0x004181a4:	movl %eax, (%eax)
0x004181a6:	movl 0x421a5c, %eax
0x004181ab:	call 0x00403932
0x00403932:	xorl %eax, %eax
0x00403934:	ret

0x004181b0:	cmpl 0x420000, %edi
0x004181b6:	jne 0x004181c4
0x004181c4:	call 0x004182fc
0x004182fc:	pushl $0x30000<UINT32>
0x00418301:	pushl $0x10000<UINT32>
0x00418306:	call 0x0041835a
0x0041835a:	jmp _controlfp@msvcrt.dll
_controlfp@msvcrt.dll: API Node	
0x0041830b:	popl %ecx
0x0041830c:	popl %ecx
0x0041830d:	ret

0x004181c9:	pushl $0x419478<UINT32>
0x004181ce:	pushl $0x419474<UINT32>
0x004181d3:	call 0x004182f6
0x004182f6:	jmp _initterm@msvcrt.dll
_initterm@msvcrt.dll: API Node	
0x004181d8:	movl %eax, 0x420694
0x004181dd:	movl -32(%ebp), %eax
0x004181e0:	leal %eax, -32(%ebp)
0x004181e3:	pushl %eax
0x004181e4:	pushl 0x420690
0x004181ea:	leal %eax, -36(%ebp)
0x004181ed:	pushl %eax
0x004181ee:	leal %eax, -40(%ebp)
0x004181f1:	pushl %eax
0x004181f2:	leal %eax, -44(%ebp)
0x004181f5:	pushl %eax
0x004181f6:	call __wgetmainargs@msvcrt.dll
__wgetmainargs@msvcrt.dll: API Node	
0x004181fc:	movl -48(%ebp), %eax
0x004181ff:	pushl $0x419470<UINT32>
0x00418204:	pushl $0x419448<UINT32>
0x00418209:	call 0x004182f6
0x0041820e:	addl %esp, $0x24<UINT8>
0x00418211:	movl %eax, 0x419364
0x00418216:	movl %esi, (%eax)
0x00418218:	cmpl %esi, %edi
0x0041821a:	jne 0x0041822a
0x0041822a:	movl -52(%ebp), %esi
0x0041822d:	cmpw (%esi), $0x22<UINT8>
0x00418231:	jne 69
0x00418233:	addl %esi, %ebx
0x00418235:	movl -52(%ebp), %esi
0x00418238:	movw %ax, (%esi)
0x0041823b:	cmpw %ax, %di
0x0041823e:	je 6
0x00418240:	cmpw %ax, $0x22<UINT16>
0x00418244:	jne 0x00418233
0x00418246:	cmpw (%esi), $0x22<UINT8>
0x0041824a:	jne 5
0x0041824c:	addl %esi, %ebx
0x0041824e:	movl -52(%ebp), %esi
0x00418251:	movw %ax, (%esi)
0x00418254:	cmpw %ax, %di
0x00418257:	je 6
0x00418259:	cmpw %ax, $0x20<UINT16>
0x0041825d:	jbe 0x0041824c
0x0041825f:	movl -76(%ebp), %edi
0x00418262:	leal %eax, -120(%ebp)
0x00418265:	pushl %eax
0x00418266:	call GetStartupInfoW@KERNEL32.DLL
GetStartupInfoW@KERNEL32.DLL: API Node	
0x0041826c:	testb -76(%ebp), $0x1<UINT8>
0x00418270:	je 0x00418285
0x00418285:	pushl $0xa<UINT8>
0x00418287:	popl %eax
0x00418288:	pushl %eax
0x00418289:	pushl %esi
0x0041828a:	pushl %edi
0x0041828b:	pushl %edi
0x0041828c:	call GetModuleHandleA@KERNEL32.DLL
0x00418292:	pushl %eax
0x00418293:	call 0x0040f22d
0x0040f22d:	pushl %ebp
0x0040f22e:	movl %ebp, %esp
0x0040f230:	andl %esp, $0xfffffff8<UINT8>
0x0040f233:	movl %eax, $0xdec4<UINT32>
0x0040f238:	call 0x004183f0
0x004183f0:	cmpl %eax, $0x1000<UINT32>
0x004183f5:	jae 0x00418405
0x00418405:	pushl %ecx
0x00418406:	leal %ecx, 0x8(%esp)
0x0041840a:	subl %ecx, $0x1000<UINT32>
0x00418410:	subl %eax, $0x1000<UINT32>
0x00418415:	testl (%ecx), %eax
0x00418417:	cmpl %eax, $0x1000<UINT32>
0x0041841c:	jae 0x0041840a
0x0041841e:	subl %ecx, %eax
0x00418420:	movl %eax, %esp
0x00418422:	testl (%ecx), %eax
0x00418424:	movl %esp, %ecx
0x00418426:	movl %ecx, (%eax)
0x00418428:	movl %eax, 0x4(%eax)
0x0041842b:	pushl %eax
0x0041842c:	ret

0x0040f23d:	pushl %ebx
0x0040f23e:	pushl %esi
0x0040f23f:	pushl %edi
0x0040f240:	call 0x00403b1a
0x00403b1a:	pushl %ebp
0x00403b1b:	movl %ebp, %esp
0x00403b1d:	pushl %ecx
0x00403b1e:	pushl %ecx
0x00403b1f:	pushl %ebx
0x00403b20:	pushl %esi
0x00403b21:	pushl %edi
0x00403b22:	pushl $0x41a3b8<UINT32>
0x00403b27:	movl -8(%ebp), $0x8<UINT32>
0x00403b2e:	movl -4(%ebp), $0x1ff<UINT32>
0x00403b35:	xorl %ebx, %ebx
0x00403b37:	xorl %edi, %edi
0x00403b39:	call LoadLibraryW@KERNEL32.DLL
LoadLibraryW@KERNEL32.DLL: API Node	
0x00403b3f:	movl %esi, %eax
0x00403b41:	testl %esi, %esi
0x00403b43:	je 40
0x00403b45:	pushl $0x41a3d4<UINT32>
0x00403b4a:	pushl %esi
0x00403b4b:	call GetProcAddress@KERNEL32.DLL
0x00403b51:	testl %eax, %eax
0x00403b53:	je 9
0x00403b55:	leal %ecx, -8(%ebp)
0x00403b58:	pushl %ecx
0x00403b59:	incl %edi
0x00403b5a:	call InitCommonControlsEx@comctl32.dll
InitCommonControlsEx@comctl32.dll: API Node	
0x00403b5c:	movl %ebx, %eax
0x00403b5e:	pushl %esi
0x00403b5f:	call FreeLibrary@KERNEL32.DLL
FreeLibrary@KERNEL32.DLL: API Node	
0x00403b65:	testl %edi, %edi
0x00403b67:	je 4
0x00403b69:	movl %eax, %ebx
0x00403b6b:	jmp 0x00403b76
0x00403b76:	testl %eax, %eax
0x00403b78:	popl %edi
0x00403b79:	popl %esi
0x00403b7a:	popl %ebx
0x00403b7b:	jne 0x00403b94
0x00403b7d:	pushl $0x30<UINT8>
0x00403b94:	xorl %eax, %eax
0x00403b96:	incl %eax
0x00403b97:	leave
0x00403b98:	ret

0x0040f245:	testl %eax, %eax
0x0040f247:	jne 0x0040f24f
0x0040f24f:	call 0x00413a66
0x00413a66:	cmpl 0x42157c, $0x0<UINT8>
0x00413a6d:	jne 37
0x00413a6f:	pushl $0x41b504<UINT32>
0x00413a74:	call LoadLibraryW@KERNEL32.DLL
0x00413a7a:	testl %eax, %eax
0x00413a7c:	movl 0x42157c, %eax
0x00413a81:	je 17
0x00413a83:	pushl $0x41b51c<UINT32>
0x00413a88:	pushl %eax
0x00413a89:	call GetProcAddress@KERNEL32.DLL
0x00413a8f:	movl 0x421578, %eax
0x00413a94:	ret

0x0040f254:	xorl %esi, %esi
0x0040f256:	pushl %esi
0x0040f257:	call OleInitialize@ole32.dll
OleInitialize@ole32.dll: API Node	
0x0040f25d:	pushl $0x8001<UINT32>
0x0040f262:	call SetErrorMode@KERNEL32.DLL
SetErrorMode@KERNEL32.DLL: API Node	
0x0040f268:	movl %ebx, 0x4190d4
0x0040f26e:	pushl %esi
0x0040f26f:	pushl $0x41086a<UINT32>
0x0040f274:	pushl %esi
0x0040f275:	movl 0x420e20, $0x11223344<UINT32>
0x0040f27f:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0040f281:	pushl %eax
0x0040f282:	call EnumResourceTypesW@KERNEL32.DLL
EnumResourceTypesW@KERNEL32.DLL: API Node	
0x0040f288:	leal %eax, 0x10(%esp)
0x0040f28c:	call 0x0040788d
0x0040788d:	xorl %ecx, %ecx
0x0040788f:	movl 0x14(%eax), $0x400<UINT32>
0x00407896:	movl 0x18(%eax), $0x100<UINT32>
0x0040789d:	movl (%eax), %ecx
0x0040789f:	movl 0x4(%eax), %ecx
0x004078a2:	movl 0xc(%eax), %ecx
0x004078a5:	movl 0x10(%eax), %ecx
0x004078a8:	movl 0x1c(%eax), %ecx
0x004078ab:	movl 0x8(%eax), %ecx
0x004078ae:	ret

0x0040f291:	leal %eax, 0x60(%esp)
0x0040f295:	pushl %eax
0x0040f296:	movl 0x3c(%esp), $0x20<UINT32>
0x0040f29e:	movl 0x34(%esp), %esi
0x0040f2a2:	movl 0x40(%esp), %esi
0x0040f2a6:	movl 0x38(%esp), %esi
0x0040f2aa:	movl 0x44(%esp), %esi
0x0040f2ae:	call 0x0040eda9
0x0040eda9:	pushl %ebx
0x0040edaa:	xorl %ebx, %ebx
0x0040edac:	pushl %ebp
0x0040edad:	movl %ebp, 0xc(%esp)
0x0040edb1:	movl 0x240(%ebp), %ebx
0x0040edb7:	movl (%ebp), $0x41b0e0<UINT32>
0x0040edbe:	movl 0x68c(%ebp), %ebx
0x0040edc4:	leal %eax, 0x6a8(%ebp)
0x0040edca:	pushl %esi
0x0040edcb:	movl 0xc(%eax), %ebx
0x0040edce:	movl (%eax), %ebx
0x0040edd0:	movl 0x4(%eax), %ebx
0x0040edd3:	movl 0x10(%eax), $0x100<UINT32>
0x0040edda:	movl 0x8(%eax), %ebx
0x0040eddd:	leal %edx, 0x12e4(%ebp)
0x0040ede3:	pushl %edi
0x0040ede4:	leal %eax, 0x4(%edx)
0x0040ede7:	movl (%edx), $0x41b0b0<UINT32>
0x0040eded:	call 0x0040788d
0x0040edf2:	movl 0x24(%edx), $0x41b094<UINT32>
0x0040edf9:	leal %eax, 0x1318(%ebp)
0x0040edff:	movl 0x1310(%ebp), $0x41b080<UINT32>
0x0040ee09:	call 0x0040788d
0x0040ee0e:	pushl $0x10<UINT8>
0x0040ee10:	leal %eax, 0x134c(%ebp)
0x0040ee16:	pushl %ebx
0x0040ee17:	pushl %eax
0x0040ee18:	movl 0x1348(%ebp), %ebx
0x0040ee1e:	movl 0x1340(%ebp), $0x41a508<UINT32>
0x0040ee28:	call 0x0041801a
0x0041801a:	jmp memset@msvcrt.dll
memset@msvcrt.dll: API Node	
0x0040ee2d:	addl %esp, $0xc<UINT8>
0x0040ee30:	leal %esi, 0x1d74(%ebp)
0x0040ee36:	call 0x00410e33
0x00410e33:	pushl %edi
0x00410e34:	movl %edi, $0x419574<UINT32>
0x00410e39:	pushl %edi
0x00410e3a:	pushl %esi
0x00410e3b:	call 0x00418058
0x00418058:	jmp wcscpy@msvcrt.dll
wcscpy@msvcrt.dll: API Node	
0x00410e40:	leal %eax, 0x2000(%esi)
0x00410e46:	pushl %edi
0x00410e47:	pushl %eax
0x00410e48:	call 0x00418058
0x00410e4d:	xorl %ecx, %ecx
0x00410e4f:	xorl %eax, %eax
0x00410e51:	incl %eax
0x00410e52:	addl %esp, $0x10<UINT8>
0x00410e55:	movw 0x4000(%esi), %cx
0x00418360:	jmp _except_handler3@msvcrt.dll
_except_handler3@msvcrt.dll: API Node	
0x7c9032a8:	addb (%eax), %al
0x7c9032aa:	addb (%eax), %al
0x7c9032ac:	addb (%eax), %al
0x7c9032ae:	addb (%eax), %al
0x7c9032b0:	addb (%eax), %al
0x7c9032b2:	addb (%eax), %al
0x7c9032b4:	addb (%eax), %al
0x7c9032b6:	addb (%eax), %al
0x7c9032b8:	addb (%eax), %al
0x7c9032ba:	addb (%eax), %al
0x7c9032bc:	addb (%eax), %al
0x7c9032be:	addb (%eax), %al
0x7c9032c0:	addb (%eax), %al
0x7c9032c2:	addb (%eax), %al
0x7c9032c4:	addb (%eax), %al
0x7c9032c6:	addb (%eax), %al
0x7c9032c8:	addb (%eax), %al
0x7c9032ca:	addb (%eax), %al
0x7c9032cc:	addb (%eax), %al
0x7c9032ce:	addb (%eax), %al
0x7c9032d0:	addb (%eax), %al
0x7c9032d2:	addb (%eax), %al
0x7c9032d4:	addb (%eax), %al
0x7c9032d6:	addb (%eax), %al
0x7c9032d8:	addb (%eax), %al
0x7c9032da:	addb (%eax), %al
0x7c9032dc:	addb (%eax), %al
0x7c9032de:	addb (%eax), %al
0x7c9032e0:	addb (%eax), %al
0x7c9032e2:	addb (%eax), %al
0x7c9032e4:	addb (%eax), %al
0x7c9032e6:	addb (%eax), %al
0x7c9032e8:	addb (%eax), %al
0x7c9032ea:	addb (%eax), %al
0x7c9032ec:	addb (%eax), %al
0x7c9032ee:	addb (%eax), %al
0x7c9032f0:	addb (%eax), %al
0x7c9032f2:	addb (%eax), %al
0x7c9032f4:	addb (%eax), %al
0x7c9032f6:	addb (%eax), %al
0x7c9032f8:	addb (%eax), %al
0x7c9032fa:	addb (%eax), %al
0x7c9032fc:	addb (%eax), %al
0x7c9032fe:	addb (%eax), %al
0x7c903300:	addb (%eax), %al
0x7c903302:	addb (%eax), %al
0x7c903304:	addb (%eax), %al
0x7c903306:	addb (%eax), %al
0x7c903308:	addb (%eax), %al
0x7c90330a:	addb (%eax), %al
0x7c90330c:	addb (%eax), %al
0x7c90330e:	addb (%eax), %al
0x00403b7f:	pushl $0x41a3ec<UINT32>
0x00403b84:	pushl $0x41a3f8<UINT32>
0x00403b89:	pushl %eax
0x00403b8a:	call MessageBoxW@USER32.dll
MessageBoxW@USER32.dll: API Node	
0x00403b90:	xorl %eax, %eax
0x00403b92:	leave
0x00403b93:	ret

0x0040f249:	incl %eax
0x0040f24a:	jmp 0x0040f458
0x0040f458:	popl %edi
0x0040f459:	popl %esi
0x0040f45a:	popl %ebx
0x0040f45b:	movl %esp, %ebp
0x0040f45d:	popl %ebp
0x0040f45e:	ret $0x10<UINT16>

0x00418298:	movl %esi, %eax
0x0041829a:	movl -124(%ebp), %esi
0x0041829d:	cmpl -28(%ebp), %edi
0x004182a0:	jne 7
0x004182a2:	pushl %esi
0x004182a3:	call exit@msvcrt.dll
exit@msvcrt.dll: Exit Node	
