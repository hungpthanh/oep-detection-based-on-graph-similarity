0x0041c000:	movl %ebx, $0x4001d0<UINT32>
0x0041c005:	movl %edi, $0x401000<UINT32>
0x0041c00a:	movl %esi, $0x413e3d<UINT32>
0x0041c00f:	pushl %ebx
0x0041c010:	call 0x0041c01f
0x0041c01f:	cld
0x0041c020:	movb %dl, $0xffffff80<UINT8>
0x0041c022:	movsb %es:(%edi), %ds:(%esi)
0x0041c023:	pushl $0x2<UINT8>
0x0041c025:	popl %ebx
0x0041c026:	call 0x0041c015
0x0041c015:	addb %dl, %dl
0x0041c017:	jne 0x0041c01e
0x0041c019:	movb %dl, (%esi)
0x0041c01b:	incl %esi
0x0041c01c:	adcb %dl, %dl
0x0041c01e:	ret

0x0041c029:	jae 0x0041c022
0x0041c02b:	xorl %ecx, %ecx
0x0041c02d:	call 0x0041c015
0x0041c030:	jae 0x0041c04a
0x0041c032:	xorl %eax, %eax
0x0041c034:	call 0x0041c015
0x0041c037:	jae 0x0041c05a
0x0041c039:	movb %bl, $0x2<UINT8>
0x0041c03b:	incl %ecx
0x0041c03c:	movb %al, $0x10<UINT8>
0x0041c03e:	call 0x0041c015
0x0041c041:	adcb %al, %al
0x0041c043:	jae 0x0041c03e
0x0041c045:	jne 0x0041c086
0x0041c086:	pushl %esi
0x0041c087:	movl %esi, %edi
0x0041c089:	subl %esi, %eax
0x0041c08b:	rep movsb %es:(%edi), %ds:(%esi)
0x0041c08d:	popl %esi
0x0041c08e:	jmp 0x0041c026
0x0041c047:	stosb %es:(%edi), %al
0x0041c048:	jmp 0x0041c026
0x0041c05a:	lodsb %al, %ds:(%esi)
0x0041c05b:	shrl %eax
0x0041c05d:	je 0x0041c0a0
0x0041c05f:	adcl %ecx, %ecx
0x0041c061:	jmp 0x0041c07f
0x0041c07f:	incl %ecx
0x0041c080:	incl %ecx
0x0041c081:	xchgl %ebp, %eax
0x0041c082:	movl %eax, %ebp
0x0041c084:	movb %bl, $0x1<UINT8>
0x0041c04a:	call 0x0041c092
0x0041c092:	incl %ecx
0x0041c093:	call 0x0041c015
0x0041c097:	adcl %ecx, %ecx
0x0041c099:	call 0x0041c015
0x0041c09d:	jb 0x0041c093
0x0041c09f:	ret

0x0041c04f:	subl %ecx, %ebx
0x0041c051:	jne 0x0041c063
0x0041c053:	call 0x0041c090
0x0041c090:	xorl %ecx, %ecx
0x0041c058:	jmp 0x0041c082
0x0041c063:	xchgl %ecx, %eax
0x0041c064:	decl %eax
0x0041c065:	shll %eax, $0x8<UINT8>
0x0041c068:	lodsb %al, %ds:(%esi)
0x0041c069:	call 0x0041c090
0x0041c06e:	cmpl %eax, $0x7d00<UINT32>
0x0041c073:	jae 0x0041c07f
0x0041c075:	cmpb %ah, $0x5<UINT8>
0x0041c078:	jae 0x0041c080
0x0041c07a:	cmpl %eax, $0x7f<UINT8>
0x0041c07d:	ja 0x0041c081
0x0041c0a0:	popl %edi
0x0041c0a1:	popl %ebx
0x0041c0a2:	movzwl %edi, (%ebx)
0x0041c0a5:	decl %edi
0x0041c0a6:	je 0x0041c0b0
0x0041c0a8:	decl %edi
0x0041c0a9:	je 0x0041c0be
0x0041c0ab:	shll %edi, $0xc<UINT8>
0x0041c0ae:	jmp 0x0041c0b7
0x0041c0b7:	incl %ebx
0x0041c0b8:	incl %ebx
0x0041c0b9:	jmp 0x0041c00f
0x0041c0b0:	movl %edi, 0x2(%ebx)
0x0041c0b3:	pushl %edi
0x0041c0b4:	addl %ebx, $0x4<UINT8>
0x0041c0be:	popl %edi
0x0041c0bf:	movl %ebx, $0x41c128<UINT32>
0x0041c0c4:	incl %edi
0x0041c0c5:	movl %esi, (%edi)
0x0041c0c7:	scasl %eax, %es:(%edi)
0x0041c0c8:	pushl %edi
0x0041c0c9:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x0041c0cb:	xchgl %ebp, %eax
0x0041c0cc:	xorl %eax, %eax
0x0041c0ce:	scasb %al, %es:(%edi)
0x0041c0cf:	jne 0x0041c0ce
0x0041c0d1:	decb (%edi)
0x0041c0d3:	je 0x0041c0c4
0x0041c0d5:	decb (%edi)
0x0041c0d7:	jne 0x0041c0df
0x0041c0df:	decb (%edi)
0x0041c0e1:	je 0x0040a36a
0x0041c0e7:	pushl %edi
0x0041c0e8:	pushl %ebp
0x0041c0e9:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0041c0ec:	orl (%esi), %eax
0x0041c0ee:	lodsl %eax, %ds:(%esi)
0x0041c0ef:	jne 0x0041c0cc
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x0041c0d9:	incl %edi
0x0041c0da:	pushl (%edi)
0x0041c0dc:	scasl %eax, %es:(%edi)
0x0041c0dd:	jmp 0x0041c0e8
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
0x00402482:	call GetProcAddress@KERNEL32.DLL
0x00402488:	testl %eax, %eax
0x0040248a:	je 9
0x0040248c:	leal %ecx, -8(%ebp)
0x0040248f:	pushl %ecx
0x00402490:	incl %edi
0x00402491:	call InitCommonControlsEx@comctl32.dll
InitCommonControlsEx@comctl32.dll: API Node	
0x00402493:	movl %ebx, %eax
0x00402495:	pushl %esi
0x00402496:	call FreeLibrary@KERNEL32.DLL
FreeLibrary@KERNEL32.DLL: API Node	
0x0040249c:	testl %edi, %edi
0x0040249e:	je 4
0x004024a0:	movl %eax, %ebx
0x004024a2:	jmp 0x004024ad
0x004024ad:	testl %eax, %eax
0x004024af:	popl %edi
0x004024b0:	popl %esi
0x004024b1:	popl %ebx
0x004024b2:	jne 0x004024cb
0x004024b4:	pushl $0x30<UINT8>
0x004024cb:	xorl %eax, %eax
0x004024cd:	incl %eax
0x004024ce:	leave
0x004024cf:	ret

0x00408ad7:	testl %eax, %eax
0x00408ad9:	jne 0x00408ae1
0x00408ae1:	call 0x00409c59
0x00409c59:	cmpl 0x40ec80, $0x0<UINT8>
0x00409c60:	jne 37
0x00409c62:	pushl $0x40bfa8<UINT32>
0x00409c67:	call LoadLibraryA@KERNEL32.DLL
0x00409c6d:	testl %eax, %eax
0x00409c6f:	movl 0x40ec80, %eax
0x00409c74:	je 17
0x00409c76:	pushl $0x40bfb4<UINT32>
0x00409c7b:	pushl %eax
0x00409c7c:	call GetProcAddress@KERNEL32.DLL
0x00409c82:	movl 0x40ec7c, %eax
0x00409c87:	ret

0x00408ae6:	xorl %ebx, %ebx
0x00408ae8:	leal %eax, 0x60(%esp)
0x00408aec:	movl 0x24(%esp), $0x400<UINT32>
0x00408af4:	movl 0x28(%esp), $0x100<UINT32>
0x00408afc:	movl 0x10(%esp), %ebx
0x00408b00:	movl 0x14(%esp), %ebx
0x00408b04:	movl 0x1c(%esp), %ebx
0x00408b08:	movl 0x20(%esp), %ebx
0x00408b0c:	movl 0x2c(%esp), %ebx
0x00408b10:	movl 0x18(%esp), %ebx
0x00408b14:	movl 0x38(%esp), $0x20<UINT32>
0x00408b1c:	movl 0x30(%esp), %ebx
0x00408b20:	movl 0x3c(%esp), %ebx
0x00408b24:	movl 0x34(%esp), %ebx
0x00408b28:	movl 0x40(%esp), %ebx
0x00408b2c:	call 0x00408896
0x00408896:	pushl %ebx
0x00408897:	xorl %ebx, %ebx
0x00408899:	pushl %esi
0x0040889a:	movl %esi, %eax
0x0040889c:	movl 0x140(%esi), %ebx
0x004088a2:	movl (%esi), $0x40bccc<UINT32>
0x004088a8:	leal %eax, 0x294(%esi)
0x004088ae:	movl (%eax), $0x40bc9c<UINT32>
0x004088b4:	movl 0x18(%eax), $0x400<UINT32>
0x004088bb:	movl 0x1c(%eax), $0x100<UINT32>
0x004088c2:	movl 0x4(%eax), %ebx
0x004088c5:	movl 0x8(%eax), %ebx
0x004088c8:	movl 0x10(%eax), %ebx
0x004088cb:	movl 0x14(%eax), %ebx
0x004088ce:	movl 0x20(%eax), %ebx
0x004088d1:	movl 0xc(%eax), %ebx
0x004088d4:	pushl %edi
0x004088d5:	movl 0x24(%eax), $0x40bc80<UINT32>
0x004088dc:	pushl $0x24<UINT8>
0x004088de:	movl 0x2c0(%esi), $0x40bc6c<UINT32>
0x004088e8:	call 0x0040a304
0x0040a304:	jmp ??2@YAPAXI@Z@msvcrt.dll
??2@YAPAXI@Z@msvcrt.dll: API Node	
0x004088ed:	movl %edx, %eax
0x004088ef:	xorl %eax, %eax
0x004088f1:	cmpl %edx, %ebx
0x004088f3:	popl %ecx
0x004088f4:	je 9
0x004088f6:	pushl $0x9<UINT8>
0x004088f8:	popl %ecx
0x004088f9:	movl %edi, %edx
0x004088fb:	rep stosl %es:(%edi), %eax
