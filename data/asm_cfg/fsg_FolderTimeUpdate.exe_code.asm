0x00425000:	movl %ebx, $0x4001d0<UINT32>
0x00425005:	movl %edi, $0x401000<UINT32>
0x0042500a:	movl %esi, $0x41ab4d<UINT32>
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
0x004250e1:	je 0x0040c3a6
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
0x0040c3a6:	pushl $0x70<UINT8>
0x0040c3a8:	pushl $0x40d400<UINT32>
0x0040c3ad:	call 0x0040c5b8
0x0040c5b8:	pushl $0x40c608<UINT32>
0x0040c5bd:	movl %eax, %fs:0
0x0040c5c3:	pushl %eax
0x0040c5c4:	movl %fs:0, %esp
0x0040c5cb:	movl %eax, 0x10(%esp)
0x0040c5cf:	movl 0x10(%esp), %ebp
0x0040c5d3:	leal %ebp, 0x10(%esp)
0x0040c5d7:	subl %esp, %eax
0x0040c5d9:	pushl %ebx
0x0040c5da:	pushl %esi
0x0040c5db:	pushl %edi
0x0040c5dc:	movl %eax, -8(%ebp)
0x0040c5df:	movl -24(%ebp), %esp
0x0040c5e2:	pushl %eax
0x0040c5e3:	movl %eax, -4(%ebp)
0x0040c5e6:	movl -4(%ebp), $0xffffffff<UINT32>
0x0040c5ed:	movl -8(%ebp), %eax
0x0040c5f0:	ret

0x0040c3b2:	xorl %edi, %edi
0x0040c3b4:	pushl %edi
0x0040c3b5:	call GetModuleHandleA@KERNEL32.dll
GetModuleHandleA@KERNEL32.dll: API Node	
0x0040c3bb:	cmpw (%eax), $0x5a4d<UINT16>
0x0040c3c0:	jne 31
0x0040c3c2:	movl %ecx, 0x3c(%eax)
0x0040c3c5:	addl %ecx, %eax
0x0040c3c7:	cmpl (%ecx), $0x4550<UINT32>
0x0040c3cd:	jne 18
0x0040c3cf:	movzwl %eax, 0x18(%ecx)
0x0040c3d3:	cmpl %eax, $0x10b<UINT32>
0x0040c3d8:	je 0x0040c3f9
0x0040c3f9:	cmpl 0x74(%ecx), $0xe<UINT8>
0x0040c3fd:	jbe -30
0x0040c3ff:	xorl %eax, %eax
0x0040c401:	cmpl 0xe8(%ecx), %edi
0x0040c407:	setne %al
0x0040c40a:	movl -28(%ebp), %eax
0x0040c40d:	movl -4(%ebp), %edi
0x0040c410:	pushl $0x2<UINT8>
0x0040c412:	popl %ebx
0x0040c413:	pushl %ebx
0x0040c414:	call __set_app_type@msvcrt.dll
__set_app_type@msvcrt.dll: API Node	
0x0040c41a:	popl %ecx
0x0040c41b:	orl 0x4116c0, $0xffffffff<UINT8>
0x0040c422:	orl 0x4116c4, $0xffffffff<UINT8>
0x0040c429:	call __p__fmode@msvcrt.dll
__p__fmode@msvcrt.dll: API Node	
0x0040c42f:	movl %ecx, 0x4102dc
0x0040c435:	movl (%eax), %ecx
0x0040c437:	call __p__commode@msvcrt.dll
__p__commode@msvcrt.dll: API Node	
0x0040c43d:	movl %ecx, 0x4102d8
0x0040c443:	movl (%eax), %ecx
0x0040c445:	movl %eax, 0x40d2ec
0x0040c44a:	movl %eax, (%eax)
0x0040c44c:	movl 0x4116bc, %eax
0x0040c451:	call 0x0040c5b4
0x0040c5b4:	xorl %eax, %eax
0x0040c5b6:	ret

0x0040c456:	cmpl 0x410000, %edi
0x0040c45c:	jne 0x0040c46a
0x0040c46a:	call 0x0040c5a2
0x0040c5a2:	pushl $0x30000<UINT32>
0x0040c5a7:	pushl $0x10000<UINT32>
0x0040c5ac:	call 0x0040c602
0x0040c602:	jmp _controlfp@msvcrt.dll
_controlfp@msvcrt.dll: API Node	
0x0040c5b1:	popl %ecx
0x0040c5b2:	popl %ecx
0x0040c5b3:	ret

0x0040c46f:	pushl $0x40d3d8<UINT32>
0x0040c474:	pushl $0x40d3d4<UINT32>
0x0040c479:	call 0x0040c59c
0x0040c59c:	jmp _initterm@msvcrt.dll
_initterm@msvcrt.dll: API Node	
0x0040c47e:	movl %eax, 0x4102d4
0x0040c483:	movl -32(%ebp), %eax
0x0040c486:	leal %eax, -32(%ebp)
0x0040c489:	pushl %eax
0x0040c48a:	pushl 0x4102d0
0x0040c490:	leal %eax, -36(%ebp)
0x0040c493:	pushl %eax
0x0040c494:	leal %eax, -40(%ebp)
0x0040c497:	pushl %eax
0x0040c498:	leal %eax, -44(%ebp)
0x0040c49b:	pushl %eax
0x0040c49c:	call __wgetmainargs@msvcrt.dll
__wgetmainargs@msvcrt.dll: API Node	
0x0040c4a2:	movl -48(%ebp), %eax
0x0040c4a5:	pushl $0x40d3d0<UINT32>
0x0040c4aa:	pushl $0x40d3ac<UINT32>
0x0040c4af:	call 0x0040c59c
0x0040c4b4:	addl %esp, $0x24<UINT8>
0x0040c4b7:	movl %eax, 0x40d2fc
0x0040c4bc:	movl %esi, (%eax)
0x0040c4be:	cmpl %esi, %edi
0x0040c4c0:	jne 0x0040c4d0
0x0040c4d0:	movl -52(%ebp), %esi
0x0040c4d3:	cmpw (%esi), $0x22<UINT8>
0x0040c4d7:	jne 69
0x0040c4d9:	addl %esi, %ebx
0x0040c4db:	movl -52(%ebp), %esi
0x0040c4de:	movw %ax, (%esi)
0x0040c4e1:	cmpw %ax, %di
0x0040c4e4:	je 6
0x0040c4e6:	cmpw %ax, $0x22<UINT16>
0x0040c4ea:	jne 0x0040c4d9
0x0040c4ec:	cmpw (%esi), $0x22<UINT8>
0x0040c4f0:	jne 5
0x0040c4f2:	addl %esi, %ebx
0x0040c4f4:	movl -52(%ebp), %esi
0x0040c4f7:	movw %ax, (%esi)
0x0040c4fa:	cmpw %ax, %di
0x0040c4fd:	je 6
0x0040c4ff:	cmpw %ax, $0x20<UINT16>
0x0040c503:	jbe 0x0040c4f2
0x0040c505:	movl -76(%ebp), %edi
0x0040c508:	leal %eax, -120(%ebp)
0x0040c50b:	pushl %eax
0x0040c50c:	call GetStartupInfoW@KERNEL32.dll
GetStartupInfoW@KERNEL32.dll: API Node	
0x0040c512:	testb -76(%ebp), $0x1<UINT8>
0x0040c516:	je 0x0040c52b
0x0040c52b:	pushl $0xa<UINT8>
0x0040c52d:	popl %eax
0x0040c52e:	pushl %eax
0x0040c52f:	pushl %esi
0x0040c530:	pushl %edi
0x0040c531:	pushl %edi
0x0040c532:	call GetModuleHandleA@KERNEL32.dll
0x0040c538:	pushl %eax
0x0040c539:	call 0x0040aa30
0x0040aa30:	pushl %ebp
0x0040aa31:	movl %ebp, %esp
0x0040aa33:	movl %eax, $0x3e5c<UINT32>
0x0040aa38:	call 0x0040c620
0x0040c620:	cmpl %eax, $0x1000<UINT32>
0x0040c625:	jae 0x0040c635
0x0040c635:	pushl %ecx
0x0040c636:	leal %ecx, 0x8(%esp)
0x0040c63a:	subl %ecx, $0x1000<UINT32>
0x0040c640:	subl %eax, $0x1000<UINT32>
0x0040c645:	testl (%ecx), %eax
0x0040c647:	cmpl %eax, $0x1000<UINT32>
0x0040c64c:	jae 0x0040c63a
0x0040c64e:	subl %ecx, %eax
0x0040c650:	movl %eax, %esp
0x0040c652:	testl (%ecx), %eax
0x0040c654:	movl %esp, %ecx
0x0040c656:	movl %ecx, (%eax)
0x0040c658:	movl %eax, 0x4(%eax)
0x0040c65b:	pushl %eax
0x0040c65c:	ret

0x0040aa3d:	call 0x00402262
0x00402262:	pushl %ebp
0x00402263:	movl %ebp, %esp
0x00402265:	pushl %ecx
0x00402266:	pushl %ecx
0x00402267:	pushl %ebx
0x00402268:	pushl %esi
0x00402269:	pushl %edi
0x0040226a:	pushl $0x40d808<UINT32>
0x0040226f:	movl -8(%ebp), $0x8<UINT32>
0x00402276:	movl -4(%ebp), $0x1ff<UINT32>
0x0040227d:	xorl %ebx, %ebx
0x0040227f:	xorl %edi, %edi
0x00402281:	call LoadLibraryW@KERNEL32.dll
LoadLibraryW@KERNEL32.dll: API Node	
0x00402287:	movl %esi, %eax
0x00402289:	testl %esi, %esi
0x0040228b:	je 40
0x0040228d:	pushl $0x40d824<UINT32>
0x00402292:	pushl %esi
0x00402293:	call GetProcAddress@KERNEL32.dll
0x00402299:	testl %eax, %eax
0x0040229b:	je 9
0x0040229d:	leal %ecx, -8(%ebp)
0x004022a0:	pushl %ecx
0x004022a1:	incl %edi
0x004022a2:	call InitCommonControlsEx@comctl32.dll
InitCommonControlsEx@comctl32.dll: API Node	
0x004022a4:	movl %ebx, %eax
0x004022a6:	pushl %esi
0x004022a7:	call FreeLibrary@KERNEL32.dll
FreeLibrary@KERNEL32.dll: API Node	
0x004022ad:	testl %edi, %edi
0x004022af:	je 4
0x004022b1:	movl %eax, %ebx
0x004022b3:	jmp 0x004022be
0x004022be:	testl %eax, %eax
0x004022c0:	popl %edi
0x004022c1:	popl %esi
0x004022c2:	popl %ebx
0x004022c3:	jne 0x004022dc
0x004022c5:	pushl $0x30<UINT8>
0x004022dc:	xorl %eax, %eax
0x004022de:	incl %eax
0x004022df:	leave
0x004022e0:	ret

0x0040aa42:	testl %eax, %eax
0x0040aa44:	jne 0x0040aa4c
0x0040aa4c:	pushl %ebx
0x0040aa4d:	pushl %esi
0x0040aa4e:	pushl %edi
0x0040aa4f:	call 0x0040bd32
0x0040bd32:	cmpl 0x4111b8, $0x0<UINT8>
0x0040bd39:	jne 37
0x0040bd3b:	pushl $0x40e6b0<UINT32>
0x0040bd40:	call LoadLibraryW@KERNEL32.dll
0x0040bd46:	testl %eax, %eax
0x0040bd48:	movl 0x4111b8, %eax
0x0040bd4d:	je 17
0x0040bd4f:	pushl $0x40e6c8<UINT32>
0x0040bd54:	pushl %eax
0x0040bd55:	call GetProcAddress@KERNEL32.dll
0x0040bd5b:	movl 0x4111b4, %eax
0x0040bd60:	ret

0x0040aa54:	xorl %ebx, %ebx
0x0040aa56:	pushl %ebx
0x0040aa57:	call OleInitialize@ole32.dll
OleInitialize@ole32.dll: API Node	
0x0040aa5d:	pushl $0x8001<UINT32>
0x0040aa62:	call SetErrorMode@KERNEL32.dll
SetErrorMode@KERNEL32.dll: API Node	
0x0040aa68:	movl %edi, 0x40d0bc
0x0040aa6e:	pushl %ebx
0x0040aa6f:	pushl $0x40bd17<UINT32>
0x0040aa74:	pushl %ebx
0x0040aa75:	movl 0x410a60, $0x11223344<UINT32>
0x0040aa7f:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x0040aa81:	pushl %eax
0x0040aa82:	call EnumResourceTypesW@KERNEL32.dll
EnumResourceTypesW@KERNEL32.dll: API Node	
0x0040aa88:	leal %eax, -52(%ebp)
0x0040aa8b:	call 0x004051cc
0x004051cc:	xorl %ecx, %ecx
0x004051ce:	movl 0x14(%eax), $0x400<UINT32>
0x004051d5:	movl 0x18(%eax), $0x100<UINT32>
0x004051dc:	movl (%eax), %ecx
0x004051de:	movl 0x4(%eax), %ecx
0x004051e1:	movl 0xc(%eax), %ecx
0x004051e4:	movl 0x10(%eax), %ecx
0x004051e7:	movl 0x1c(%eax), %ecx
0x004051ea:	movl 0x8(%eax), %ecx
0x004051ed:	ret

0x0040aa90:	leal %eax, -15964(%ebp)
0x0040aa96:	pushl %eax
0x0040aa97:	movl -12(%ebp), $0x20<UINT32>
0x0040aa9e:	movl -20(%ebp), %ebx
0x0040aaa1:	movl -8(%ebp), %ebx
0x0040aaa4:	movl -16(%ebp), %ebx
0x0040aaa7:	movl -4(%ebp), %ebx
0x0040aaaa:	call 0x0040a76e
0x0040a76e:	pushl %ebx
0x0040a76f:	pushl %ebp
0x0040a770:	movl %ebp, 0xc(%esp)
0x0040a774:	xorl %ebx, %ebx
0x0040a776:	pushl %esi
0x0040a777:	pushl %edi
0x0040a778:	movl 0x208(%ebp), %ebx
0x0040a77e:	movl 0x244(%ebp), %ebx
0x0040a784:	movl 0x274(%ebp), %ebx
0x0040a78a:	movl 0x240(%ebp), %ebx
0x0040a790:	movl (%ebp), $0x40e3c4<UINT32>
0x0040a797:	leal %edi, 0x6ac(%ebp)
0x0040a79d:	movl 0x694(%ebp), %ebx
0x0040a7a3:	call 0x004036f6
0x004036f6:	pushl %esi
0x004036f7:	leal %esi, 0x4(%edi)
0x004036fa:	movl (%edi), $0x40d8e8<UINT32>
0x00403700:	call 0x0040368d
0x0040368d:	pushl %edi
0x0040368e:	leal %eax, 0x23c(%esi)
0x00403694:	pushl $0x40d578<UINT32>
0x00403699:	xorl %edi, %edi
0x0040369b:	pushl %eax
0x0040369c:	movw (%esi), %di
0x0040369f:	call 0x0040c316
0x0040c316:	jmp wcscpy@msvcrt.dll
wcscpy@msvcrt.dll: API Node	
0x004036a4:	xorl %eax, %eax
0x004036a6:	incl %eax
0x004036a7:	popl %ecx
0x004036a8:	popl %ecx
0x004036a9:	movw 0xa3c(%esi), %di
0x004036b0:	movl 0x20c(%esi), %edi
0x004036b6:	movl 0x210(%esi), %eax
0x004036bc:	movl 0x214(%esi), %eax
0x004036c2:	movl 0x22c(%esi), %edi
0x004036c8:	movl 0x230(%esi), %edi
0x004036ce:	movl 0x234(%esi), %edi
0x004036d4:	movl 0x238(%esi), %edi
0x004036da:	movl 0x21c(%esi), %eax
0x004036e0:	movl 0x220(%esi), %edi
0x004036e6:	movl 0x228(%esi), %edi
0x004036ec:	movl 0x224(%esi), %edi
0x004036f2:	movl %eax, %esi
0x004036f4:	popl %edi
0x004036f5:	ret

0x00403705:	xorl %edx, %edx
0x00403707:	leal %eax, 0x1a74(%edi)
0x0040370d:	movw 0x1248(%edi), %dx
0x00403714:	movl 0x1a48(%edi), %edx
0x0040371a:	movl 0x1a4c(%edi), %edx
0x00403720:	movl 0x1a50(%edi), %edx
0x00403726:	movl 0x1a54(%edi), %edx
0x0040372c:	movl 0x1a58(%edi), %edx
0x00403732:	movl 0x1a5c(%edi), %edx
0x00403738:	movl 0x1a60(%edi), %edx
0x0040373e:	movl 0x1a64(%edi), %edx
0x00403744:	movl 0x1a68(%edi), %edx
0x0040374a:	movl 0x1a6c(%edi), %edx
0x00403750:	movl 0x1a70(%edi), %edx
0x00403756:	call 0x004051cc
0x0040375b:	leal %eax, 0x1a94(%edi)
0x00403761:	call 0x004051cc
0x00403766:	movl 0x1240(%edi), %edx
0x0040376c:	movl 0x1244(%edi), %edx
0x00403772:	movl 0x1ab4(%edi), %edx
0x00403778:	movl %eax, %edi
0x0040377a:	popl %esi
0x0040377b:	ret

0x0040a7a8:	leal %edi, 0x2164(%ebp)
0x0040a7ae:	movl %esi, %edi
0x0040a7b0:	call 0x00401312
0x00401312:	andl 0x10(%esi), $0x0<UINT8>
0x00401316:	pushl $0x2c<UINT8>
0x00401318:	leal %eax, 0x14(%esi)
0x0040131b:	pushl $0x0<UINT8>
0x0040131d:	pushl %eax
0x0040131e:	movl (%esi), $0x40d46c<UINT32>
0x00401324:	call 0x0040c310
0x0040c310:	jmp memset@msvcrt.dll
memset@msvcrt.dll: API Node	
0x00401329:	addl %esp, $0xc<UINT8>
0x0040132c:	movl %eax, %esi
0x0040132e:	ret

0x0018fed8:	jl -1
0x0018feda:	sbbb (%eax), %al
Unknown Node: Unknown Node	
0x004022c7:	pushl $0x40d83c<UINT32>
0x004022cc:	pushl $0x40d848<UINT32>
0x004022d1:	pushl %eax
0x004022d2:	call MessageBoxW@USER32.dll
MessageBoxW@USER32.dll: API Node	
0x004022d8:	xorl %eax, %eax
0x004022da:	leave
0x004022db:	ret

0x0040aa46:	incl %eax
0x0040aa47:	jmp 0x0040ac1a
0x0040ac1a:	leave
0x0040ac1b:	ret $0x10<UINT16>

0x0040c53e:	movl %esi, %eax
0x0040c540:	movl -124(%ebp), %esi
0x0040c543:	cmpl -28(%ebp), %edi
0x0040c546:	jne 7
0x0040c548:	pushl %esi
0x0040c549:	call exit@msvcrt.dll
exit@msvcrt.dll: Exit Node	
