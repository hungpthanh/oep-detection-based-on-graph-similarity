0x00425000:	movl %ebx, $0x4001d0<UINT32>
0x00425005:	movl %edi, $0x401000<UINT32>
0x0042500a:	movl %esi, $0x41aeea<UINT32>
0x0042500f:	pushl %ebx
0x00425010:	call 0x0042501f
0x0042501f:	cld
0x00425020:	movb %dl, $0xffffff80<UINT8>
0x00425022:	movsb %es:(%edi), %ds:(%esi)
0x00425023:	pushl $0x2<UINT8>
0x00425025:	popl %ebx
0x00425026:	call 0x00425015
0x00425015:	addb %dl, %dl
0x00425017:	jne 0x0042501e
0x00425019:	movb %dl, (%esi)
0x0042501b:	incl %esi
0x0042501c:	adcb %dl, %dl
0x0042501e:	ret

0x00425029:	jae 0x00425022
0x0042502b:	xorl %ecx, %ecx
0x0042502d:	call 0x00425015
0x00425030:	jae 0x0042504a
0x00425032:	xorl %eax, %eax
0x00425034:	call 0x00425015
0x00425037:	jae 0x0042505a
0x00425039:	movb %bl, $0x2<UINT8>
0x0042503b:	incl %ecx
0x0042503c:	movb %al, $0x10<UINT8>
0x0042503e:	call 0x00425015
0x00425041:	adcb %al, %al
0x00425043:	jae 0x0042503e
0x00425045:	jne 0x00425086
0x00425086:	pushl %esi
0x00425087:	movl %esi, %edi
0x00425089:	subl %esi, %eax
0x0042508b:	rep movsb %es:(%edi), %ds:(%esi)
0x0042508d:	popl %esi
0x0042508e:	jmp 0x00425026
0x00425047:	stosb %es:(%edi), %al
0x00425048:	jmp 0x00425026
0x0042505a:	lodsb %al, %ds:(%esi)
0x0042505b:	shrl %eax
0x0042505d:	je 0x004250a0
0x0042505f:	adcl %ecx, %ecx
0x00425061:	jmp 0x0042507f
0x0042507f:	incl %ecx
0x00425080:	incl %ecx
0x00425081:	xchgl %ebp, %eax
0x00425082:	movl %eax, %ebp
0x00425084:	movb %bl, $0x1<UINT8>
0x0042504a:	call 0x00425092
0x00425092:	incl %ecx
0x00425093:	call 0x00425015
0x00425097:	adcl %ecx, %ecx
0x00425099:	call 0x00425015
0x0042509d:	jb 0x00425093
0x0042509f:	ret

0x0042504f:	subl %ecx, %ebx
0x00425051:	jne 0x00425063
0x00425063:	xchgl %ecx, %eax
0x00425064:	decl %eax
0x00425065:	shll %eax, $0x8<UINT8>
0x00425068:	lodsb %al, %ds:(%esi)
0x00425069:	call 0x00425090
0x00425090:	xorl %ecx, %ecx
0x0042506e:	cmpl %eax, $0x7d00<UINT32>
0x00425073:	jae 0x0042507f
0x00425075:	cmpb %ah, $0x5<UINT8>
0x00425078:	jae 0x00425080
0x0042507a:	cmpl %eax, $0x7f<UINT8>
0x0042507d:	ja 0x00425081
0x00425053:	call 0x00425090
0x00425058:	jmp 0x00425082
0x004250a0:	popl %edi
0x004250a1:	popl %ebx
0x004250a2:	movzwl %edi, (%ebx)
0x004250a5:	decl %edi
0x004250a6:	je 0x004250b0
0x004250a8:	decl %edi
0x004250a9:	je 0x004250be
0x004250ab:	shll %edi, $0xc<UINT8>
0x004250ae:	jmp 0x004250b7
0x004250b7:	incl %ebx
0x004250b8:	incl %ebx
0x004250b9:	jmp 0x0042500f
0x004250b0:	movl %edi, 0x2(%ebx)
0x004250b3:	pushl %edi
0x004250b4:	addl %ebx, $0x4<UINT8>
0x004250be:	popl %edi
0x004250bf:	movl %ebx, $0x425128<UINT32>
0x004250c4:	incl %edi
0x004250c5:	movl %esi, (%edi)
0x004250c7:	scasl %eax, %es:(%edi)
0x004250c8:	pushl %edi
0x004250c9:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004250cb:	xchgl %ebp, %eax
0x004250cc:	xorl %eax, %eax
0x004250ce:	scasb %al, %es:(%edi)
0x004250cf:	jne 0x004250ce
0x004250d1:	decb (%edi)
0x004250d3:	je 0x004250c4
0x004250d5:	decb (%edi)
0x004250d7:	jne 0x004250df
0x004250df:	decb (%edi)
0x004250e1:	je 0x0040d42a
0x004250e7:	pushl %edi
0x004250e8:	pushl %ebp
0x004250e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x004250ec:	orl (%esi), %eax
0x004250ee:	lodsl %eax, %ds:(%esi)
0x004250ef:	jne 0x004250cc
0x004250d9:	incl %edi
0x004250da:	pushl (%edi)
0x004250dc:	scasl %eax, %es:(%edi)
0x004250dd:	jmp 0x004250e8
GetProcAddress@KERNEL32.dll: API Node	
0x0040d42a:	pushl $0x70<UINT8>
0x0040d42c:	pushl $0x40e410<UINT32>
0x0040d431:	call 0x0040d63c
0x0040d63c:	pushl $0x40d68c<UINT32>
0x0040d641:	movl %eax, %fs:0
0x0040d647:	pushl %eax
0x0040d648:	movl %fs:0, %esp
0x0040d64f:	movl %eax, 0x10(%esp)
0x0040d653:	movl 0x10(%esp), %ebp
0x0040d657:	leal %ebp, 0x10(%esp)
0x0040d65b:	subl %esp, %eax
0x0040d65d:	pushl %ebx
0x0040d65e:	pushl %esi
0x0040d65f:	pushl %edi
0x0040d660:	movl %eax, -8(%ebp)
0x0040d663:	movl -24(%ebp), %esp
0x0040d666:	pushl %eax
0x0040d667:	movl %eax, -4(%ebp)
0x0040d66a:	movl -4(%ebp), $0xffffffff<UINT32>
0x0040d671:	movl -8(%ebp), %eax
0x0040d674:	ret

0x0040d436:	xorl %edi, %edi
0x0040d438:	pushl %edi
0x0040d439:	call GetModuleHandleA@KERNEL32.dll
GetModuleHandleA@KERNEL32.dll: API Node	
0x0040d43f:	cmpw (%eax), $0x5a4d<UINT16>
0x0040d444:	jne 31
0x0040d446:	movl %ecx, 0x3c(%eax)
0x0040d449:	addl %ecx, %eax
0x0040d44b:	cmpl (%ecx), $0x4550<UINT32>
0x0040d451:	jne 18
0x0040d453:	movzwl %eax, 0x18(%ecx)
0x0040d457:	cmpl %eax, $0x10b<UINT32>
0x0040d45c:	je 0x0040d47d
0x0040d47d:	cmpl 0x74(%ecx), $0xe<UINT8>
0x0040d481:	jbe -30
0x0040d483:	xorl %eax, %eax
0x0040d485:	cmpl 0xe8(%ecx), %edi
0x0040d48b:	setne %al
0x0040d48e:	movl -28(%ebp), %eax
0x0040d491:	movl -4(%ebp), %edi
0x0040d494:	pushl $0x2<UINT8>
0x0040d496:	popl %ebx
0x0040d497:	pushl %ebx
0x0040d498:	call __set_app_type@msvcrt.dll
__set_app_type@msvcrt.dll: API Node	
0x0040d49e:	popl %ecx
0x0040d49f:	orl 0x412aec, $0xffffffff<UINT8>
0x0040d4a6:	orl 0x412af0, $0xffffffff<UINT8>
0x0040d4ad:	call __p__fmode@msvcrt.dll
__p__fmode@msvcrt.dll: API Node	
0x0040d4b3:	movl %ecx, 0x4116ec
0x0040d4b9:	movl (%eax), %ecx
0x0040d4bb:	call __p__commode@msvcrt.dll
__p__commode@msvcrt.dll: API Node	
0x0040d4c1:	movl %ecx, 0x4116e8
0x0040d4c7:	movl (%eax), %ecx
0x0040d4c9:	movl %eax, 0x40e304
0x0040d4ce:	movl %eax, (%eax)
0x0040d4d0:	movl 0x412ae8, %eax
0x0040d4d5:	call 0x0040d638
0x0040d638:	xorl %eax, %eax
0x0040d63a:	ret

0x0040d4da:	cmpl 0x411000, %edi
0x0040d4e0:	jne 0x0040d4ee
0x0040d4ee:	call 0x0040d626
0x0040d626:	pushl $0x30000<UINT32>
0x0040d62b:	pushl $0x10000<UINT32>
0x0040d630:	call 0x0040d686
0x0040d686:	jmp _controlfp@msvcrt.dll
_controlfp@msvcrt.dll: API Node	
0x0040d635:	popl %ecx
0x0040d636:	popl %ecx
0x0040d637:	ret

0x0040d4f3:	pushl $0x40e3e0<UINT32>
0x0040d4f8:	pushl $0x40e3dc<UINT32>
0x0040d4fd:	call 0x0040d620
0x0040d620:	jmp _initterm@msvcrt.dll
_initterm@msvcrt.dll: API Node	
0x0040d502:	movl %eax, 0x4116e4
0x0040d507:	movl -32(%ebp), %eax
0x0040d50a:	leal %eax, -32(%ebp)
0x0040d50d:	pushl %eax
0x0040d50e:	pushl 0x4116e0
0x0040d514:	leal %eax, -36(%ebp)
0x0040d517:	pushl %eax
0x0040d518:	leal %eax, -40(%ebp)
0x0040d51b:	pushl %eax
0x0040d51c:	leal %eax, -44(%ebp)
0x0040d51f:	pushl %eax
0x0040d520:	call __wgetmainargs@msvcrt.dll
__wgetmainargs@msvcrt.dll: API Node	
0x0040d526:	movl -48(%ebp), %eax
0x0040d529:	pushl $0x40e3d8<UINT32>
0x0040d52e:	pushl $0x40e3b4<UINT32>
0x0040d533:	call 0x0040d620
0x0040d538:	addl %esp, $0x24<UINT8>
0x0040d53b:	movl %eax, 0x40e314
0x0040d540:	movl %esi, (%eax)
0x0040d542:	cmpl %esi, %edi
0x0040d544:	jne 0x0040d554
0x0040d554:	movl -52(%ebp), %esi
0x0040d557:	cmpw (%esi), $0x22<UINT8>
0x0040d55b:	jne 69
0x0040d55d:	addl %esi, %ebx
0x0040d55f:	movl -52(%ebp), %esi
0x0040d562:	movw %ax, (%esi)
0x0040d565:	cmpw %ax, %di
0x0040d568:	je 6
0x0040d56a:	cmpw %ax, $0x22<UINT16>
0x0040d56e:	jne 0x0040d55d
0x0040d570:	cmpw (%esi), $0x22<UINT8>
0x0040d574:	jne 5
0x0040d576:	addl %esi, %ebx
0x0040d578:	movl -52(%ebp), %esi
0x0040d57b:	movw %ax, (%esi)
0x0040d57e:	cmpw %ax, %di
0x0040d581:	je 6
0x0040d583:	cmpw %ax, $0x20<UINT16>
0x0040d587:	jbe 0x0040d576
0x0040d589:	movl -76(%ebp), %edi
0x0040d58c:	leal %eax, -120(%ebp)
0x0040d58f:	pushl %eax
0x0040d590:	call GetStartupInfoW@KERNEL32.dll
GetStartupInfoW@KERNEL32.dll: API Node	
0x0040d596:	testb -76(%ebp), $0x1<UINT8>
0x0040d59a:	je 0x0040d5af
0x0040d5af:	pushl $0xa<UINT8>
0x0040d5b1:	popl %eax
0x0040d5b2:	pushl %eax
0x0040d5b3:	pushl %esi
0x0040d5b4:	pushl %edi
0x0040d5b5:	pushl %edi
0x0040d5b6:	call GetModuleHandleA@KERNEL32.dll
0x0040d5bc:	pushl %eax
0x0040d5bd:	call 0x0040aa34
0x0040aa34:	pushl %ebp
0x0040aa35:	movl %ebp, %esp
0x0040aa37:	subl %esp, $0x7ac<UINT32>
0x0040aa3d:	call 0x0040230a
0x0040230a:	pushl %ebp
0x0040230b:	movl %ebp, %esp
0x0040230d:	pushl %ecx
0x0040230e:	pushl %ecx
0x0040230f:	pushl %ebx
0x00402310:	pushl %esi
0x00402311:	pushl %edi
0x00402312:	pushl $0x40e720<UINT32>
0x00402317:	movl -8(%ebp), $0x8<UINT32>
0x0040231e:	movl -4(%ebp), $0xff<UINT32>
0x00402325:	xorl %ebx, %ebx
0x00402327:	xorl %edi, %edi
0x00402329:	call LoadLibraryW@KERNEL32.dll
LoadLibraryW@KERNEL32.dll: API Node	
0x0040232f:	movl %esi, %eax
0x00402331:	testl %esi, %esi
0x00402333:	je 40
0x00402335:	pushl $0x40e73c<UINT32>
0x0040233a:	pushl %esi
0x0040233b:	call GetProcAddress@KERNEL32.dll
0x00402341:	testl %eax, %eax
0x00402343:	je 9
0x00402345:	leal %ecx, -8(%ebp)
0x00402348:	pushl %ecx
0x00402349:	incl %edi
0x0040234a:	call InitCommonControlsEx@comctl32.dll
InitCommonControlsEx@comctl32.dll: API Node	
0x0040234c:	movl %ebx, %eax
0x0040234e:	pushl %esi
0x0040234f:	call FreeLibrary@KERNEL32.dll
FreeLibrary@KERNEL32.dll: API Node	
0x00402355:	testl %edi, %edi
0x00402357:	je 4
0x00402359:	movl %eax, %ebx
0x0040235b:	jmp 0x00402366
0x00402366:	testl %eax, %eax
0x00402368:	popl %edi
0x00402369:	popl %esi
0x0040236a:	popl %ebx
0x0040236b:	jne 0x00402384
0x0040236d:	pushl $0x30<UINT8>
0x00402384:	xorl %eax, %eax
0x00402386:	incl %eax
0x00402387:	leave
0x00402388:	ret

0x0040aa42:	testl %eax, %eax
0x0040aa44:	jne 0x0040aa4c
0x0040aa4c:	pushl %ebx
0x0040aa4d:	pushl %esi
0x0040aa4e:	call 0x0040ccbd
0x0040ccbd:	cmpl 0x4125c8, $0x0<UINT8>
0x0040ccc4:	jne 37
0x0040ccc6:	pushl $0x40f910<UINT32>
0x0040cccb:	call LoadLibraryW@KERNEL32.dll
0x0040ccd1:	testl %eax, %eax
0x0040ccd3:	movl 0x4125c8, %eax
0x0040ccd8:	je 17
0x0040ccda:	pushl $0x40f928<UINT32>
0x0040ccdf:	pushl %eax
0x0040cce0:	call GetProcAddress@KERNEL32.dll
0x0040cce6:	movl 0x4125c4, %eax
0x0040cceb:	ret

0x0040aa53:	pushl $0x8001<UINT32>
0x0040aa58:	call SetErrorMode@KERNEL32.dll
SetErrorMode@KERNEL32.dll: API Node	
0x0040aa5e:	xorl %ebx, %ebx
0x0040aa60:	pushl %ebx
0x0040aa61:	pushl $0x40cca2<UINT32>
0x0040aa66:	pushl %ebx
0x0040aa67:	movl 0x411e70, $0x11223344<UINT32>
0x0040aa71:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x0040aa77:	pushl %eax
0x0040aa78:	call EnumResourceTypesW@KERNEL32.dll
EnumResourceTypesW@KERNEL32.dll: API Node	
0x0040aa7e:	leal %eax, -1964(%ebp)
0x0040aa84:	pushl %eax
0x0040aa85:	movl -32(%ebp), $0x400<UINT32>
0x0040aa8c:	movl -28(%ebp), $0x100<UINT32>
0x0040aa93:	movl -52(%ebp), %ebx
0x0040aa96:	movl -48(%ebp), %ebx
0x0040aa99:	movl -40(%ebp), %ebx
0x0040aa9c:	movl -36(%ebp), %ebx
0x0040aa9f:	movl -24(%ebp), %ebx
0x0040aaa2:	movl -44(%ebp), %ebx
0x0040aaa5:	movl -12(%ebp), $0x20<UINT32>
0x0040aaac:	movl -20(%ebp), %ebx
0x0040aaaf:	movl -8(%ebp), %ebx
0x0040aab2:	movl -16(%ebp), %ebx
0x0040aab5:	movl -4(%ebp), %ebx
0x0040aab8:	call 0x0040a67a
0x0040a67a:	pushl %ebx
0x0040a67b:	pushl %ebp
0x0040a67c:	movl %ebp, 0xc(%esp)
0x0040a680:	pushl %esi
0x0040a681:	xorl %ebx, %ebx
0x0040a683:	pushl %edi
0x0040a684:	leal %edi, 0x6b8(%ebp)
0x0040a68a:	movl 0x208(%ebp), %ebx
0x0040a690:	movl 0x244(%ebp), %ebx
0x0040a696:	movl 0x274(%ebp), %ebx
0x0040a69c:	movl 0x240(%ebp), %ebx
0x0040a6a2:	movl (%ebp), $0x40f5cc<UINT32>
0x0040a6a9:	movl %esi, %edi
0x0040a6ab:	movl 0x694(%ebp), %ebx
0x0040a6b1:	call 0x00401312
0x00401312:	andl 0x10(%esi), $0x0<UINT8>
0x00401316:	pushl $0x2c<UINT8>
0x00401318:	leal %eax, 0x14(%esi)
0x0040131b:	pushl $0x0<UINT8>
0x0040131d:	pushl %eax
0x0040131e:	movl (%esi), $0x40e484<UINT32>
0x00401324:	call 0x0040d39a
0x0040d39a:	jmp memset@msvcrt.dll
memset@msvcrt.dll: API Node	
0x00401329:	addl %esp, $0xc<UINT8>
0x0040132c:	movl %eax, %esi
0x0040132e:	ret

0x0018fed8:	jl -1
0x0018feda:	sbbb (%eax), %al
0x0018fedc:	ret $0x40d5<UINT16>

0x00000000:	addb (%eax), %al
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
0x00000066:	addb (%eax), %al
0x0040236f:	pushl $0x40e754<UINT32>
0x00402374:	pushl $0x40e760<UINT32>
0x00402379:	pushl %eax
0x0040237a:	call MessageBoxW@USER32.dll
MessageBoxW@USER32.dll: API Node	
0x00402380:	xorl %eax, %eax
0x00402382:	leave
0x00402383:	ret

0x0040aa46:	incl %eax
0x0040aa47:	jmp 0x0040ac3d
0x0040ac3d:	leave
0x0040ac3e:	ret $0x10<UINT16>

0x0040d5c2:	movl %esi, %eax
0x0040d5c4:	movl -124(%ebp), %esi
0x0040d5c7:	cmpl -28(%ebp), %edi
0x0040d5ca:	jne 7
0x0040d5cc:	pushl %esi
0x0040d5cd:	call exit@msvcrt.dll
exit@msvcrt.dll: Exit Node	
