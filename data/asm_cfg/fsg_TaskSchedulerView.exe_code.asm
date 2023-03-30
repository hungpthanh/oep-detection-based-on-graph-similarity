0x00429000:	movl %ebx, $0x4001d0<UINT32>
0x00429005:	movl %edi, $0x401000<UINT32>
0x0042900a:	movl %esi, $0x41dc38<UINT32>
0x0042900f:	pushl %ebx
0x00429010:	call 0x0042901f
0x0042901f:	cld
0x00429020:	movb %dl, $0xffffff80<UINT8>
0x00429022:	movsb %es:(%edi), %ds:(%esi)
0x00429023:	pushl $0x2<UINT8>
0x00429025:	popl %ebx
0x00429026:	call 0x00429015
0x00429015:	addb %dl, %dl
0x00429017:	jne 0x0042901e
0x00429019:	movb %dl, (%esi)
0x0042901b:	incl %esi
0x0042901c:	adcb %dl, %dl
0x0042901e:	ret

0x00429029:	jae 0x00429022
0x0042902b:	xorl %ecx, %ecx
0x0042902d:	call 0x00429015
0x00429030:	jae 0x0042904a
0x00429032:	xorl %eax, %eax
0x00429034:	call 0x00429015
0x00429037:	jae 0x0042905a
0x00429039:	movb %bl, $0x2<UINT8>
0x0042903b:	incl %ecx
0x0042903c:	movb %al, $0x10<UINT8>
0x0042903e:	call 0x00429015
0x00429041:	adcb %al, %al
0x00429043:	jae 0x0042903e
0x00429045:	jne 0x00429086
0x00429086:	pushl %esi
0x00429087:	movl %esi, %edi
0x00429089:	subl %esi, %eax
0x0042908b:	rep movsb %es:(%edi), %ds:(%esi)
0x0042908d:	popl %esi
0x0042908e:	jmp 0x00429026
0x00429047:	stosb %es:(%edi), %al
0x00429048:	jmp 0x00429026
0x0042905a:	lodsb %al, %ds:(%esi)
0x0042905b:	shrl %eax
0x0042905d:	je 0x004290a0
0x0042905f:	adcl %ecx, %ecx
0x00429061:	jmp 0x0042907f
0x0042907f:	incl %ecx
0x00429080:	incl %ecx
0x00429081:	xchgl %ebp, %eax
0x00429082:	movl %eax, %ebp
0x00429084:	movb %bl, $0x1<UINT8>
0x0042904a:	call 0x00429092
0x00429092:	incl %ecx
0x00429093:	call 0x00429015
0x00429097:	adcl %ecx, %ecx
0x00429099:	call 0x00429015
0x0042909d:	jb 0x00429093
0x0042909f:	ret

0x0042904f:	subl %ecx, %ebx
0x00429051:	jne 0x00429063
0x00429053:	call 0x00429090
0x00429090:	xorl %ecx, %ecx
0x00429058:	jmp 0x00429082
0x00429063:	xchgl %ecx, %eax
0x00429064:	decl %eax
0x00429065:	shll %eax, $0x8<UINT8>
0x00429068:	lodsb %al, %ds:(%esi)
0x00429069:	call 0x00429090
0x0042906e:	cmpl %eax, $0x7d00<UINT32>
0x00429073:	jae 0x0042907f
0x00429075:	cmpb %ah, $0x5<UINT8>
0x00429078:	jae 0x00429080
0x0042907a:	cmpl %eax, $0x7f<UINT8>
0x0042907d:	ja 0x00429081
0x004290a0:	popl %edi
0x004290a1:	popl %ebx
0x004290a2:	movzwl %edi, (%ebx)
0x004290a5:	decl %edi
0x004290a6:	je 0x004290b0
0x004290a8:	decl %edi
0x004290a9:	je 0x004290be
0x004290ab:	shll %edi, $0xc<UINT8>
0x004290ae:	jmp 0x004290b7
0x004290b7:	incl %ebx
0x004290b8:	incl %ebx
0x004290b9:	jmp 0x0042900f
0x004290b0:	movl %edi, 0x2(%ebx)
0x004290b3:	pushl %edi
0x004290b4:	addl %ebx, $0x4<UINT8>
0x004290be:	popl %edi
0x004290bf:	movl %ebx, $0x429128<UINT32>
0x004290c4:	incl %edi
0x004290c5:	movl %esi, (%edi)
0x004290c7:	scasl %eax, %es:(%edi)
0x004290c8:	pushl %edi
0x004290c9:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004290cb:	xchgl %ebp, %eax
0x004290cc:	xorl %eax, %eax
0x004290ce:	scasb %al, %es:(%edi)
0x004290cf:	jne 0x004290ce
0x004290d1:	decb (%edi)
0x004290d3:	je 0x004290c4
0x004290d5:	decb (%edi)
0x004290d7:	jne 0x004290df
0x004290df:	decb (%edi)
0x004290e1:	je 0x0040e1d0
0x004290e7:	pushl %edi
0x004290e8:	pushl %ebp
0x004290e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x004290ec:	orl (%esi), %eax
0x004290ee:	lodsl %eax, %ds:(%esi)
0x004290ef:	jne 0x004290cc
0x004290d9:	incl %edi
0x004290da:	pushl (%edi)
0x004290dc:	scasl %eax, %es:(%edi)
0x004290dd:	jmp 0x004290e8
GetProcAddress@KERNEL32.dll: API Node	
0x0040e1d0:	pushl $0x70<UINT8>
0x0040e1d2:	pushl $0x40f420<UINT32>
0x0040e1d7:	call 0x0040e3e4
0x0040e3e4:	pushl $0x40e434<UINT32>
0x0040e3e9:	movl %eax, %fs:0
0x0040e3ef:	pushl %eax
0x0040e3f0:	movl %fs:0, %esp
0x0040e3f7:	movl %eax, 0x10(%esp)
0x0040e3fb:	movl 0x10(%esp), %ebp
0x0040e3ff:	leal %ebp, 0x10(%esp)
0x0040e403:	subl %esp, %eax
0x0040e405:	pushl %ebx
0x0040e406:	pushl %esi
0x0040e407:	pushl %edi
0x0040e408:	movl %eax, -8(%ebp)
0x0040e40b:	movl -24(%ebp), %esp
0x0040e40e:	pushl %eax
0x0040e40f:	movl %eax, -4(%ebp)
0x0040e412:	movl -4(%ebp), $0xffffffff<UINT32>
0x0040e419:	movl -8(%ebp), %eax
0x0040e41c:	ret

0x0040e1dc:	xorl %edi, %edi
0x0040e1de:	pushl %edi
0x0040e1df:	call GetModuleHandleA@KERNEL32.dll
GetModuleHandleA@KERNEL32.dll: API Node	
0x0040e1e5:	cmpw (%eax), $0x5a4d<UINT16>
0x0040e1ea:	jne 31
0x0040e1ec:	movl %ecx, 0x3c(%eax)
0x0040e1ef:	addl %ecx, %eax
0x0040e1f1:	cmpl (%ecx), $0x4550<UINT32>
0x0040e1f7:	jne 18
0x0040e1f9:	movzwl %eax, 0x18(%ecx)
0x0040e1fd:	cmpl %eax, $0x10b<UINT32>
0x0040e202:	je 0x0040e223
0x0040e223:	cmpl 0x74(%ecx), $0xe<UINT8>
0x0040e227:	jbe -30
0x0040e229:	xorl %eax, %eax
0x0040e22b:	cmpl 0xe8(%ecx), %edi
0x0040e231:	setne %al
0x0040e234:	movl -28(%ebp), %eax
0x0040e237:	movl -4(%ebp), %edi
0x0040e23a:	pushl $0x2<UINT8>
0x0040e23c:	popl %ebx
0x0040e23d:	pushl %ebx
0x0040e23e:	call __set_app_type@msvcrt.dll
__set_app_type@msvcrt.dll: API Node	
0x0040e244:	popl %ecx
0x0040e245:	orl 0x414a14, $0xffffffff<UINT8>
0x0040e24c:	orl 0x414a18, $0xffffffff<UINT8>
0x0040e253:	call __p__fmode@msvcrt.dll
__p__fmode@msvcrt.dll: API Node	
0x0040e259:	movl %ecx, 0x4136ac
0x0040e25f:	movl (%eax), %ecx
0x0040e261:	call __p__commode@msvcrt.dll
__p__commode@msvcrt.dll: API Node	
0x0040e267:	movl %ecx, 0x4136a8
0x0040e26d:	movl (%eax), %ecx
0x0040e26f:	movl %eax, 0x40f30c
0x0040e274:	movl %eax, (%eax)
0x0040e276:	movl 0x414a10, %eax
0x0040e27b:	call 0x0040e3de
0x0040e3de:	xorl %eax, %eax
0x0040e3e0:	ret

0x0040e280:	cmpl 0x413000, %edi
0x0040e286:	jne 0x0040e294
0x0040e294:	call 0x0040e3cc
0x0040e3cc:	pushl $0x30000<UINT32>
0x0040e3d1:	pushl $0x10000<UINT32>
0x0040e3d6:	call 0x0040e42e
0x0040e42e:	jmp _controlfp@msvcrt.dll
_controlfp@msvcrt.dll: API Node	
0x0040e3db:	popl %ecx
0x0040e3dc:	popl %ecx
0x0040e3dd:	ret

0x0040e299:	pushl $0x40f3fc<UINT32>
0x0040e29e:	pushl $0x40f3f8<UINT32>
0x0040e2a3:	call 0x0040e3c6
0x0040e3c6:	jmp _initterm@msvcrt.dll
_initterm@msvcrt.dll: API Node	
0x0040e2a8:	movl %eax, 0x4136a4
0x0040e2ad:	movl -32(%ebp), %eax
0x0040e2b0:	leal %eax, -32(%ebp)
0x0040e2b3:	pushl %eax
0x0040e2b4:	pushl 0x4136a0
0x0040e2ba:	leal %eax, -36(%ebp)
0x0040e2bd:	pushl %eax
0x0040e2be:	leal %eax, -40(%ebp)
0x0040e2c1:	pushl %eax
0x0040e2c2:	leal %eax, -44(%ebp)
0x0040e2c5:	pushl %eax
0x0040e2c6:	call __wgetmainargs@msvcrt.dll
__wgetmainargs@msvcrt.dll: API Node	
0x0040e2cc:	movl -48(%ebp), %eax
0x0040e2cf:	pushl $0x40f3f4<UINT32>
0x0040e2d4:	pushl $0x40f3d4<UINT32>
0x0040e2d9:	call 0x0040e3c6
0x0040e2de:	addl %esp, $0x24<UINT8>
0x0040e2e1:	movl %eax, 0x40f34c
0x0040e2e6:	movl %esi, (%eax)
0x0040e2e8:	cmpl %esi, %edi
0x0040e2ea:	jne 0x0040e2fa
0x0040e2fa:	movl -52(%ebp), %esi
0x0040e2fd:	cmpw (%esi), $0x22<UINT8>
0x0040e301:	jne 69
0x0040e303:	addl %esi, %ebx
0x0040e305:	movl -52(%ebp), %esi
0x0040e308:	movw %ax, (%esi)
0x0040e30b:	cmpw %ax, %di
0x0040e30e:	je 6
0x0040e310:	cmpw %ax, $0x22<UINT16>
0x0040e314:	jne 0x0040e303
0x0040e316:	cmpw (%esi), $0x22<UINT8>
0x0040e31a:	jne 5
0x0040e31c:	addl %esi, %ebx
0x0040e31e:	movl -52(%ebp), %esi
0x0040e321:	movw %ax, (%esi)
0x0040e324:	cmpw %ax, %di
0x0040e327:	je 6
0x0040e329:	cmpw %ax, $0x20<UINT16>
0x0040e32d:	jbe 0x0040e31c
0x0040e32f:	movl -76(%ebp), %edi
0x0040e332:	leal %eax, -120(%ebp)
0x0040e335:	pushl %eax
0x0040e336:	call GetStartupInfoW@KERNEL32.dll
GetStartupInfoW@KERNEL32.dll: API Node	
0x0040e33c:	testb -76(%ebp), $0x1<UINT8>
0x0040e340:	je 0x0040e355
0x0040e355:	pushl $0xa<UINT8>
0x0040e357:	popl %eax
0x0040e358:	pushl %eax
0x0040e359:	pushl %esi
0x0040e35a:	pushl %edi
0x0040e35b:	pushl %edi
0x0040e35c:	call GetModuleHandleA@KERNEL32.dll
0x0040e362:	pushl %eax
0x0040e363:	call 0x0040b237
0x0040b237:	pushl %ebp
0x0040b238:	movl %ebp, %esp
0x0040b23a:	movl %eax, $0x3c4c<UINT32>
0x0040b23f:	call 0x0040e450
0x0040e450:	cmpl %eax, $0x1000<UINT32>
0x0040e455:	jae 0x0040e465
0x0040e465:	pushl %ecx
0x0040e466:	leal %ecx, 0x8(%esp)
0x0040e46a:	subl %ecx, $0x1000<UINT32>
0x0040e470:	subl %eax, $0x1000<UINT32>
0x0040e475:	testl (%ecx), %eax
0x0040e477:	cmpl %eax, $0x1000<UINT32>
0x0040e47c:	jae 0x0040e46a
0x0040e47e:	subl %ecx, %eax
0x0040e480:	movl %eax, %esp
0x0040e482:	testl (%ecx), %eax
0x0040e484:	movl %esp, %ecx
0x0040e486:	movl %ecx, (%eax)
0x0040e488:	movl %eax, 0x4(%eax)
0x0040e48b:	pushl %eax
0x0040e48c:	ret

0x0040b244:	call 0x00402ac8
0x00402ac8:	pushl %ebp
0x00402ac9:	movl %ebp, %esp
0x00402acb:	pushl %ecx
0x00402acc:	pushl %ecx
0x00402acd:	pushl %ebx
0x00402ace:	pushl %esi
0x00402acf:	pushl %edi
0x00402ad0:	pushl $0x40f89c<UINT32>
0x00402ad5:	movl -8(%ebp), $0x8<UINT32>
0x00402adc:	movl -4(%ebp), $0xff<UINT32>
0x00402ae3:	xorl %ebx, %ebx
0x00402ae5:	xorl %edi, %edi
0x00402ae7:	call LoadLibraryW@KERNEL32.dll
LoadLibraryW@KERNEL32.dll: API Node	
0x00402aed:	movl %esi, %eax
0x00402aef:	testl %esi, %esi
0x00402af1:	je 40
0x00402af3:	pushl $0x40f8b8<UINT32>
0x00402af8:	pushl %esi
0x00402af9:	call GetProcAddress@KERNEL32.dll
0x00402aff:	testl %eax, %eax
0x00402b01:	je 9
0x00402b03:	leal %ecx, -8(%ebp)
0x00402b06:	pushl %ecx
0x00402b07:	incl %edi
0x00402b08:	call InitCommonControlsEx@comctl32.dll
InitCommonControlsEx@comctl32.dll: API Node	
0x00402b0a:	movl %ebx, %eax
0x00402b0c:	pushl %esi
0x00402b0d:	call FreeLibrary@KERNEL32.dll
FreeLibrary@KERNEL32.dll: API Node	
0x00402b13:	testl %edi, %edi
0x00402b15:	je 4
0x00402b17:	movl %eax, %ebx
0x00402b19:	jmp 0x00402b24
0x00402b24:	testl %eax, %eax
0x00402b26:	popl %edi
0x00402b27:	popl %esi
0x00402b28:	popl %ebx
0x00402b29:	jne 0x00402b42
0x00402b2b:	pushl $0x30<UINT8>
0x00402b42:	xorl %eax, %eax
0x00402b44:	incl %eax
0x00402b45:	leave
0x00402b46:	ret

0x0040b249:	testl %eax, %eax
0x0040b24b:	jne 0x0040b253
0x0040b253:	pushl %ebx
0x0040b254:	xorl %ebx, %ebx
0x0040b256:	pushl %ebx
0x0040b257:	pushl %ebx
0x0040b258:	call CoInitializeEx@ole32.dll
CoInitializeEx@ole32.dll: API Node	
0x0040b25e:	testl %eax, %eax
0x0040b260:	jne 0x0040b274
0x0040b262:	pushl %ebx
0x0040b274:	pushl %esi
0x0040b275:	pushl %edi
0x0040b276:	call 0x0040cb73
0x0040cb73:	cmpl 0x414588, $0x0<UINT8>
0x0040cb7a:	jne 37
0x0040cb7c:	pushl $0x4107fc<UINT32>
0x0040cb81:	call LoadLibraryW@KERNEL32.dll
0x0040cb87:	testl %eax, %eax
0x0040cb89:	movl 0x414588, %eax
0x0040cb8e:	je 17
0x0040cb90:	pushl $0x410814<UINT32>
0x0040cb95:	pushl %eax
0x0040cb96:	call GetProcAddress@KERNEL32.dll
0x0040cb9c:	movl 0x414584, %eax
0x0040cba1:	ret

0x0040b27b:	pushl $0x8001<UINT32>
0x0040b280:	call SetErrorMode@KERNEL32.dll
SetErrorMode@KERNEL32.dll: API Node	
0x0040b286:	movl %edi, 0x40f0c4
0x0040b28c:	pushl %ebx
0x0040b28d:	pushl $0x40cb58<UINT32>
0x0040b292:	pushl %ebx
0x0040b293:	movl 0x413e30, $0x11223344<UINT32>
0x0040b29d:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x0040b29f:	pushl %eax
0x0040b2a0:	call EnumResourceTypesW@KERNEL32.dll
EnumResourceTypesW@KERNEL32.dll: API Node	
0x0040b2a6:	leal %eax, -15436(%ebp)
0x0040b2ac:	pushl %eax
0x0040b2ad:	movl -32(%ebp), $0x400<UINT32>
0x0040b2b4:	movl -28(%ebp), $0x100<UINT32>
0x0040b2bb:	movl -52(%ebp), %ebx
0x0040b2be:	movl -48(%ebp), %ebx
0x0040b2c1:	movl -40(%ebp), %ebx
0x0040b2c4:	movl -36(%ebp), %ebx
0x0040b2c7:	movl -24(%ebp), %ebx
0x0040b2ca:	movl -44(%ebp), %ebx
0x0040b2cd:	movl -12(%ebp), $0x20<UINT32>
0x0040b2d4:	movl -20(%ebp), %ebx
0x0040b2d7:	movl -8(%ebp), %ebx
0x0040b2da:	movl -16(%ebp), %ebx
0x0040b2dd:	movl -4(%ebp), %ebx
0x0040b2e0:	call 0x0040ae8e
0x0040ae8e:	pushl %ebx
0x0040ae8f:	pushl %ebp
0x0040ae90:	movl %ebp, 0xc(%esp)
0x0040ae94:	movl (%ebp), $0x4104c0<UINT32>
0x0040ae9b:	pushl %esi
0x0040ae9c:	pushl %edi
0x0040ae9d:	xorl %edi, %edi
0x0040ae9f:	movl 0x208(%ebp), %edi
0x0040aea5:	movl 0x244(%ebp), %edi
0x0040aeab:	movl 0x274(%ebp), %edi
0x0040aeb1:	movl 0x240(%ebp), %edi
0x0040aeb7:	movl 0x694(%ebp), %edi
0x0040aebd:	movl 0x6b0(%ebp), %edi
0x0040aec3:	leal %eax, 0x6b4(%ebp)
0x0040aec9:	movl 0xc(%eax), %edi
0x0040aecc:	movl (%eax), %edi
0x0040aece:	movl 0x4(%eax), %edi
0x0040aed1:	movl 0x10(%eax), $0x100<UINT32>
0x0040aed8:	movl 0x8(%eax), %edi
0x0040aedb:	leal %eax, 0x6c8(%ebp)
0x0040aee1:	leal %esi, 0x6e4(%ebp)
0x0040aee7:	movl (%eax), $0x410a38<UINT32>
0x0040aeed:	movl 0x4(%eax), %edi
0x0040aef0:	movl 0x8(%eax), %edi
0x0040aef3:	movl 0x10(%eax), %edi
0x0040aef6:	call 0x0040133a
0x0040133a:	andl 0x10(%esi), $0x0<UINT8>
0x0040133e:	pushl $0x2c<UINT8>
0x00401340:	leal %eax, 0x14(%esi)
0x00401343:	pushl $0x0<UINT8>
0x00401345:	pushl %eax
0x00401346:	movl (%esi), $0x40f48c<UINT32>
0x0040134c:	call 0x0040e140
0x0040e140:	jmp memset@msvcrt.dll
memset@msvcrt.dll: API Node	
0x00401351:	addl %esp, $0xc<UINT8>
0x00401354:	movl %eax, %esi
0x00401356:	ret

0x0018fed8:	jl -1
0x0018feda:	sbbb (%eax), %al
0x0018fedc:	pushl $0x40e3<UINT32>
0x0018fee1:	addb (%eax), %al
0x0018fee4:	addb (%eax), %al
0x0018fee6:	addb (%eax), %al
0x0018fee8:	xorl %eax, %ds:(%eax)
0x0018feec:	orb %al, (%eax)
0x0018feee:	addb (%eax), %al
0x0040e434:	jmp _except_handler3@msvcrt.dll
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
0x00402b2d:	pushl $0x40f8d0<UINT32>
0x00402b32:	pushl $0x40f8e0<UINT32>
0x00402b37:	pushl %eax
0x00402b38:	call MessageBoxW@USER32.dll
MessageBoxW@USER32.dll: API Node	
0x00402b3e:	xorl %eax, %eax
0x00402b40:	leave
0x00402b41:	ret

0x0040b24d:	incl %eax
0x0040b24e:	jmp 0x0040b4ad
0x0040b4ad:	leave
0x0040b4ae:	ret $0x10<UINT16>

0x0040e368:	movl %esi, %eax
0x0040e36a:	movl -124(%ebp), %esi
0x0040e36d:	cmpl -28(%ebp), %edi
0x0040e370:	jne 7
0x0040e372:	pushl %esi
0x0040e373:	call exit@msvcrt.dll
exit@msvcrt.dll: Exit Node	
0x0040b263:	pushl %ebx
0x0040b264:	pushl %ebx
0x0040b265:	pushl $0x3<UINT8>
0x0040b267:	pushl $0x6<UINT8>
0x0040b269:	pushl %ebx
0x0040b26a:	pushl %ebx
0x0040b26b:	pushl $0xffffffff<UINT8>
0x0040b26d:	pushl %ebx
0x0040b26e:	call CoInitializeSecurity@ole32.dll
CoInitializeSecurity@ole32.dll: API Node	
0x0018fef0:	imull %ebx, (%edi), $0x41<UINT8>
0x0018fef3:	addb 0x40(%ecx,%esi,8), %ch
0x0018fef7:	addb (%eax), %ch
0x0018fef9:	xchgl %ecx, %eax
0x0018fefa:	incl %edx
0x0018fefb:	addb (%eax), %al
0x0018fefd:	addb (%eax), %al
0x0018feff:	addb (%eax), %al
0x0018ff01:	addb (%eax), %al
0x0018ff03:	addb (%eax,%eax), %al
0x0018ff07:	addb 0x2f(%edx), %cl
0x0018ff0a:	xorl %eax, (%eax)
0x0018ff0c:	subb %ch, (%edi)
0x0018ff0e:	xorl %eax, (%eax)
0x0018ff10:	movb %dl, $0x2e<UINT8>
0x0018ff12:	xorl %eax, (%eax)
0x0018ff14:	addb (%eax), %al
0x0018ff16:	addb (%eax), %al
0x0018ff18:	addb (%eax), %al
0x0018ff1a:	addb (%eax), %al
0x0018ff1c:	addb (%eax), %al
0x0018ff1e:	addb (%eax), %al
0x0018ff20:	addb (%eax), %al
0x0018ff22:	addb (%eax), %al
0x0018ff24:	addb (%eax), %al
0x0018ff26:	addb (%eax), %al
0x0018ff28:	addb (%eax), %al
0x0018ff2a:	addb (%eax), %al
0x0018ff2c:	addb (%eax), %al
0x0018ff2e:	addb (%eax), %al
0x0018ff30:	addb (%ecx), %al
0x0018ff32:	addb (%eax), %al
0x0018ff34:	addb (%eax), %al
0x0018ff36:	insb %es:(%edi), %dx
0x0018ff37:	addb 0x33(%edi,%ebp), %cl
0x0018ff3b:	addb -1476395006(%eax), %ah
0x0018ff41:	addb %al, (%eax)
0x0018ff43:	addb 0x3e000002(%eax), %ch
0x0018ff49:	xorl %eax, %cs:(%eax)
0x0018ff4c:	addb (%eax), %al
0x0018ff4e:	addb (%eax), %al
0x0018ff50:	addb %al, $0x0<UINT8>
0x0018ff52:	addb (%eax), %al
0x0018ff54:	incl %eax
0x0018ff55:	int3
0x0018ff56:	jo 21
0x0018ff58:	popl %eax
0x0018ff59:	ljmp 0x00001570
0x00001570:	addb (%eax), %al
0x00001572:	addb (%eax), %al
0x00001574:	addb (%eax), %al
0x00001576:	addb (%eax), %al
0x00001578:	addb (%eax), %al
0x0000157a:	addb (%eax), %al
0x0000157c:	addb (%eax), %al
0x0000157e:	addb (%eax), %al
0x00001580:	addb (%eax), %al
0x00001582:	addb (%eax), %al
0x00001584:	addb (%eax), %al
0x00001586:	addb (%eax), %al
0x00001588:	addb (%eax), %al
0x0000158a:	addb (%eax), %al
0x0000158c:	addb (%eax), %al
0x0000158e:	addb (%eax), %al
0x00001590:	addb (%eax), %al
0x00001592:	addb (%eax), %al
0x00001594:	addb (%eax), %al
0x00001596:	addb (%eax), %al
0x00001598:	addb (%eax), %al
0x0000159a:	addb (%eax), %al
0x0000159c:	addb (%eax), %al
0x0000159e:	addb (%eax), %al
