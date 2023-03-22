0x00414ed0:	pusha
0x00414ed1:	movl %esi, $0x40e000<UINT32>
0x00414ed6:	leal %edi, -53248(%esi)
0x00414edc:	pushl %edi
0x00414edd:	jmp 0x00414eea
0x00414eea:	movl %ebx, (%esi)
0x00414eec:	subl %esi, $0xfffffffc<UINT8>
0x00414eef:	adcl %ebx, %ebx
0x00414ef1:	jb 0x00414ee0
0x00414ee0:	movb %al, (%esi)
0x00414ee2:	incl %esi
0x00414ee3:	movb (%edi), %al
0x00414ee5:	incl %edi
0x00414ee6:	addl %ebx, %ebx
0x00414ee8:	jne 0x00414ef1
0x00414ef3:	movl %eax, $0x1<UINT32>
0x00414ef8:	addl %ebx, %ebx
0x00414efa:	jne 0x00414f03
0x00414f03:	adcl %eax, %eax
0x00414f05:	addl %ebx, %ebx
0x00414f07:	jae 0x00414ef8
0x00414f09:	jne 0x00414f14
0x00414f14:	xorl %ecx, %ecx
0x00414f16:	subl %eax, $0x3<UINT8>
0x00414f19:	jb 0x00414f28
0x00414f1b:	shll %eax, $0x8<UINT8>
0x00414f1e:	movb %al, (%esi)
0x00414f20:	incl %esi
0x00414f21:	xorl %eax, $0xffffffff<UINT8>
0x00414f24:	je 0x00414f9a
0x00414f26:	movl %ebp, %eax
0x00414f28:	addl %ebx, %ebx
0x00414f2a:	jne 0x00414f33
0x00414f33:	adcl %ecx, %ecx
0x00414f35:	addl %ebx, %ebx
0x00414f37:	jne 0x00414f40
0x00414f40:	adcl %ecx, %ecx
0x00414f42:	jne 0x00414f64
0x00414f64:	cmpl %ebp, $0xfffff300<UINT32>
0x00414f6a:	adcl %ecx, $0x1<UINT8>
0x00414f6d:	leal %edx, (%edi,%ebp)
0x00414f70:	cmpl %ebp, $0xfffffffc<UINT8>
0x00414f73:	jbe 0x00414f84
0x00414f84:	movl %eax, (%edx)
0x00414f86:	addl %edx, $0x4<UINT8>
0x00414f89:	movl (%edi), %eax
0x00414f8b:	addl %edi, $0x4<UINT8>
0x00414f8e:	subl %ecx, $0x4<UINT8>
0x00414f91:	ja 0x00414f84
0x00414f93:	addl %edi, %ecx
0x00414f95:	jmp 0x00414ee6
0x00414f39:	movl %ebx, (%esi)
0x00414f3b:	subl %esi, $0xfffffffc<UINT8>
0x00414f3e:	adcl %ebx, %ebx
0x00414f44:	incl %ecx
0x00414f45:	addl %ebx, %ebx
0x00414f47:	jne 0x00414f50
0x00414f50:	adcl %ecx, %ecx
0x00414f52:	addl %ebx, %ebx
0x00414f54:	jae 0x00414f45
0x00414f56:	jne 0x00414f61
0x00414f61:	addl %ecx, $0x2<UINT8>
0x00414efc:	movl %ebx, (%esi)
0x00414efe:	subl %esi, $0xfffffffc<UINT8>
0x00414f01:	adcl %ebx, %ebx
0x00414f49:	movl %ebx, (%esi)
0x00414f4b:	subl %esi, $0xfffffffc<UINT8>
0x00414f4e:	adcl %ebx, %ebx
0x00414f2c:	movl %ebx, (%esi)
0x00414f2e:	subl %esi, $0xfffffffc<UINT8>
0x00414f31:	adcl %ebx, %ebx
0x00414f0b:	movl %ebx, (%esi)
0x00414f0d:	subl %esi, $0xfffffffc<UINT8>
0x00414f10:	adcl %ebx, %ebx
0x00414f12:	jae 0x00414ef8
0x00414f58:	movl %ebx, (%esi)
0x00414f5a:	subl %esi, $0xfffffffc<UINT8>
0x00414f5d:	adcl %ebx, %ebx
0x00414f5f:	jae 0x00414f45
0x00414f75:	movb %al, (%edx)
0x00414f77:	incl %edx
0x00414f78:	movb (%edi), %al
0x00414f7a:	incl %edi
0x00414f7b:	decl %ecx
0x00414f7c:	jne 0x00414f75
0x00414f7e:	jmp 0x00414ee6
0x00414f9a:	popl %esi
0x00414f9b:	movl %edi, %esi
0x00414f9d:	movl %ecx, $0x3d0<UINT32>
0x00414fa2:	movb %al, (%edi)
0x00414fa4:	incl %edi
0x00414fa5:	subb %al, $0xffffffe8<UINT8>
0x00414fa7:	cmpb %al, $0x1<UINT8>
0x00414fa9:	ja 0x00414fa2
0x00414fab:	cmpb (%edi), $0x2<UINT8>
0x00414fae:	jne 0x00414fa2
0x00414fb0:	movl %eax, (%edi)
0x00414fb2:	movb %bl, 0x4(%edi)
0x00414fb5:	shrw %ax, $0x8<UINT8>
0x00414fb9:	roll %eax, $0x10<UINT8>
0x00414fbc:	xchgb %ah, %al
0x00414fbe:	subl %eax, %edi
0x00414fc0:	subb %bl, $0xffffffe8<UINT8>
0x00414fc3:	addl %eax, %esi
0x00414fc5:	movl (%edi), %eax
0x00414fc7:	addl %edi, $0x5<UINT8>
0x00414fca:	movb %al, %bl
0x00414fcc:	loop 0x00414fa7
0x00414fce:	leal %edi, 0x12000(%esi)
0x00414fd4:	movl %eax, (%edi)
0x00414fd6:	orl %eax, %eax
0x00414fd8:	je 0x0041501f
0x00414fda:	movl %ebx, 0x4(%edi)
0x00414fdd:	leal %eax, 0x16124(%eax,%esi)
0x00414fe4:	addl %ebx, %esi
0x00414fe6:	pushl %eax
0x00414fe7:	addl %edi, $0x8<UINT8>
0x00414fea:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00414ff0:	xchgl %ebp, %eax
0x00414ff1:	movb %al, (%edi)
0x00414ff3:	incl %edi
0x00414ff4:	orb %al, %al
0x00414ff6:	je 0x00414fd4
0x00414ff8:	movl %ecx, %edi
0x00414ffa:	jns 0x00415003
0x00415003:	pushl %edi
0x00415004:	decl %eax
0x00415005:	repn scasb %al, %es:(%edi)
0x00415007:	pushl %ebp
0x00415008:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0041500e:	orl %eax, %eax
0x00415010:	je 7
0x00415012:	movl (%ebx), %eax
0x00415014:	addl %ebx, $0x4<UINT8>
0x00415017:	jmp 0x00414ff1
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x00414ffc:	movzwl %eax, (%edi)
0x00414fff:	incl %edi
0x00415000:	pushl %eax
0x00415001:	incl %edi
0x00415002:	movl %ecx, $0xaef24857<UINT32>
0x0041501f:	movl %ebp, 0x1622c(%esi)
0x00415025:	leal %edi, -4096(%esi)
0x0041502b:	movl %ebx, $0x1000<UINT32>
0x00415030:	pushl %eax
0x00415031:	pushl %esp
0x00415032:	pushl $0x4<UINT8>
0x00415034:	pushl %ebx
0x00415035:	pushl %edi
0x00415036:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00415038:	leal %eax, 0x207(%edi)
0x0041503e:	andb (%eax), $0x7f<UINT8>
0x00415041:	andb 0x28(%eax), $0x7f<UINT8>
0x00415045:	popl %eax
0x00415046:	pushl %eax
0x00415047:	pushl %esp
0x00415048:	pushl %eax
0x00415049:	pushl %ebx
0x0041504a:	pushl %edi
0x0041504b:	call VirtualProtect@kernel32.dll
0x0041504d:	popl %eax
0x0041504e:	popa
0x0041504f:	leal %eax, -128(%esp)
0x00415053:	pushl $0x0<UINT8>
0x00415055:	cmpl %esp, %eax
0x00415057:	jne 0x00415053
0x00415059:	subl %esp, $0xffffff80<UINT8>
0x0041505c:	jmp 0x0040a36a
0x0040a36a:	pushl $0x70<UINT8>
0x0040a36c:	pushl $0x40b390<UINT32>
0x0040a371:	call 0x0040a558
0x0040a558:	pushl $0x40a5a8<UINT32>
0x0040a55d:	movl %eax, %fs:0
0x0040a563:	pushl %eax
0x0040a564:	movl %fs:0, %esp
0x0040a56b:	movl %eax, 0x10(%esp)
0x0040a56f:	movl 0x10(%esp), %ebp
0x0040a573:	leal %ebp, 0x10(%esp)
0x0040a577:	subl %esp, %eax
0x0040a579:	pushl %ebx
0x0040a57a:	pushl %esi
0x0040a57b:	pushl %edi
0x0040a57c:	movl %eax, -8(%ebp)
0x0040a57f:	movl -24(%ebp), %esp
0x0040a582:	pushl %eax
0x0040a583:	movl %eax, -4(%ebp)
0x0040a586:	movl -4(%ebp), $0xffffffff<UINT32>
0x0040a58d:	movl -8(%ebp), %eax
0x0040a590:	ret

0x0040a376:	xorl %ebx, %ebx
0x0040a378:	pushl %ebx
0x0040a379:	movl %edi, 0x40b104
0x0040a37f:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x0040a381:	cmpw (%eax), $0x5a4d<UINT16>
0x0040a386:	jne 31
0x0040a388:	movl %ecx, 0x3c(%eax)
0x0040a38b:	addl %ecx, %eax
0x0040a38d:	cmpl (%ecx), $0x4550<UINT32>
0x0040a393:	jne 18
0x0040a395:	movzwl %eax, 0x18(%ecx)
0x0040a399:	cmpl %eax, $0x10b<UINT32>
0x0040a39e:	je 0x0040a3bf
0x0040a3bf:	cmpl 0x74(%ecx), $0xe<UINT8>
0x0040a3c3:	jbe -30
0x0040a3c5:	xorl %eax, %eax
0x0040a3c7:	cmpl 0xe8(%ecx), %ebx
0x0040a3cd:	setne %al
0x0040a3d0:	movl -28(%ebp), %eax
0x0040a3d3:	movl -4(%ebp), %ebx
0x0040a3d6:	pushl $0x2<UINT8>
0x0040a3d8:	call __set_app_type@msvcrt.dll
__set_app_type@msvcrt.dll: API Node	
0x0040a3de:	popl %ecx
0x0040a3df:	orl 0x40f034, $0xffffffff<UINT8>
0x0040a3e6:	orl 0x40f038, $0xffffffff<UINT8>
0x0040a3ed:	call __p__fmode@msvcrt.dll
__p__fmode@msvcrt.dll: API Node	
0x0040a3f3:	movl %ecx, 0x40e2fc
0x0040a3f9:	movl (%eax), %ecx
0x0040a3fb:	call __p__commode@msvcrt.dll
__p__commode@msvcrt.dll: API Node	
0x0040a401:	movl %ecx, 0x40e2f8
0x0040a407:	movl (%eax), %ecx
0x0040a409:	movl %eax, 0x40b278
0x0040a40e:	movl %eax, (%eax)
0x0040a410:	movl 0x40f030, %eax
0x0040a415:	call 0x0040a554
0x0040a554:	xorl %eax, %eax
0x0040a556:	ret

0x0040a41a:	cmpl 0x40e000, %ebx
0x0040a420:	jne 0x0040a42e
0x0040a42e:	call 0x0040a542
0x0040a542:	pushl $0x30000<UINT32>
0x0040a547:	pushl $0x10000<UINT32>
0x0040a54c:	call 0x0040a5a2
0x0040a5a2:	jmp _controlfp@msvcrt.dll
_controlfp@msvcrt.dll: API Node	
0x0040a551:	popl %ecx
0x0040a552:	popl %ecx
0x0040a553:	ret

0x0040a433:	pushl $0x40b360<UINT32>
0x0040a438:	pushl $0x40b35c<UINT32>
0x0040a43d:	call 0x0040a53c
0x0040a53c:	jmp _initterm@msvcrt.dll
_initterm@msvcrt.dll: API Node	
0x0040a442:	movl %eax, 0x40e2f4
0x0040a447:	movl -32(%ebp), %eax
0x0040a44a:	leal %eax, -32(%ebp)
0x0040a44d:	pushl %eax
0x0040a44e:	pushl 0x40e2f0
0x0040a454:	leal %eax, -36(%ebp)
0x0040a457:	pushl %eax
0x0040a458:	leal %eax, -40(%ebp)
0x0040a45b:	pushl %eax
0x0040a45c:	leal %eax, -44(%ebp)
0x0040a45f:	pushl %eax
0x0040a460:	call __getmainargs@msvcrt.dll
__getmainargs@msvcrt.dll: API Node	
0x0040a466:	movl -48(%ebp), %eax
0x0040a469:	pushl $0x40b358<UINT32>
0x0040a46e:	pushl $0x40b338<UINT32>
0x0040a473:	call 0x0040a53c
0x0040a478:	addl %esp, $0x24<UINT8>
0x0040a47b:	movl %eax, 0x40b288
0x0040a480:	movl %esi, (%eax)
0x0040a482:	movl -52(%ebp), %esi
0x0040a485:	cmpb (%esi), $0x22<UINT8>
0x0040a488:	jne 58
0x0040a48a:	incl %esi
0x0040a48b:	movl -52(%ebp), %esi
0x0040a48e:	movb %al, (%esi)
0x0040a490:	cmpb %al, %bl
0x0040a492:	je 4
0x0040a494:	cmpb %al, $0x22<UINT8>
0x0040a496:	jne 0x0040a48a
0x0040a498:	cmpb (%esi), $0x22<UINT8>
0x0040a49b:	jne 4
0x0040a49d:	incl %esi
0x0040a49e:	movl -52(%ebp), %esi
0x0040a4a1:	movb %al, (%esi)
0x0040a4a3:	cmpb %al, %bl
0x0040a4a5:	je 4
0x0040a4a7:	cmpb %al, $0x20<UINT8>
0x0040a4a9:	jbe 0x0040a49d
0x0040a4ab:	movl -76(%ebp), %ebx
0x0040a4ae:	leal %eax, -120(%ebp)
0x0040a4b1:	pushl %eax
0x0040a4b2:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x0040a4b8:	testb -76(%ebp), $0x1<UINT8>
0x0040a4bc:	je 0x0040a4cf
0x0040a4cf:	pushl $0xa<UINT8>
0x0040a4d1:	popl %eax
0x0040a4d2:	pushl %eax
0x0040a4d3:	pushl %esi
0x0040a4d4:	pushl %ebx
0x0040a4d5:	pushl %ebx
0x0040a4d6:	call GetModuleHandleA@KERNEL32.DLL
0x0040a4d8:	pushl %eax
0x0040a4d9:	call 0x00408ac3
0x00408ac3:	pushl %ebp
0x00408ac4:	movl %ebp, %esp
0x00408ac6:	andl %esp, $0xfffffff8<UINT8>
0x00408ac9:	subl %esp, $0x31c<UINT32>
0x00408acf:	pushl %ebx
0x00408ad0:	pushl %esi
0x00408ad1:	pushl %edi
0x00408ad2:	call 0x00402451
0x00402451:	pushl %ebp
0x00402452:	movl %ebp, %esp
0x00402454:	pushl %ecx
0x00402455:	pushl %ecx
0x00402456:	pushl %ebx
0x00402457:	pushl %esi
0x00402458:	pushl %edi
0x00402459:	pushl $0x40b6d4<UINT32>
0x0040245e:	movl -8(%ebp), $0x8<UINT32>
0x00402465:	movl -4(%ebp), $0xff<UINT32>
0x0040246c:	xorl %ebx, %ebx
0x0040246e:	xorl %edi, %edi
0x00402470:	call LoadLibraryA@KERNEL32.DLL
0x00402476:	movl %esi, %eax
0x00402478:	testl %esi, %esi
0x0040247a:	je 40
0x0040247c:	pushl $0x40b6e4<UINT32>
0x00402481:	pushl %esi
0x00402482:	call 0x4749524f
0x4749524f:	decl %edi
0x47495250:	pushl %edx
0x47495251:	decl %ecx
0x47495252:	incl %edi
0x47495253:	decl %ecx
0x47495254:	decl %esi
0x47495255:	incl %ecx
0x47495256:	decl %esp
0x47495257:	popl %edi
0x47495258:	pushl %esp
0x47495259:	decl %ebp
0x4749525a:	pushl %eax
0x4749525b:	cmpl %eax, $0x552f3a43<UINT32>
0x47495260:	jae 0x474952c7
0x474952c7:	outsb %dx, %ds:(%esi)
0x474952c8:	andb 0x69(%esi), %al
0x0040a5a8:	jmp _except_handler3@msvcrt.dll
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
