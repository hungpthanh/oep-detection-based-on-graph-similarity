0x0041d290:	pusha
0x0041d291:	movl %esi, $0x413000<UINT32>
0x0041d296:	leal %edi, -73728(%esi)
0x0041d29c:	pushl %edi
0x0041d29d:	orl %ebp, $0xffffffff<UINT8>
0x0041d2a0:	jmp 0x0041d2b2
0x0041d2b2:	movl %ebx, (%esi)
0x0041d2b4:	subl %esi, $0xfffffffc<UINT8>
0x0041d2b7:	adcl %ebx, %ebx
0x0041d2b9:	jb 0x0041d2a8
0x0041d2a8:	movb %al, (%esi)
0x0041d2aa:	incl %esi
0x0041d2ab:	movb (%edi), %al
0x0041d2ad:	incl %edi
0x0041d2ae:	addl %ebx, %ebx
0x0041d2b0:	jne 0x0041d2b9
0x0041d2bb:	movl %eax, $0x1<UINT32>
0x0041d2c0:	addl %ebx, %ebx
0x0041d2c2:	jne 0x0041d2cb
0x0041d2cb:	adcl %eax, %eax
0x0041d2cd:	addl %ebx, %ebx
0x0041d2cf:	jae 0x0041d2c0
0x0041d2d1:	jne 0x0041d2dc
0x0041d2dc:	xorl %ecx, %ecx
0x0041d2de:	subl %eax, $0x3<UINT8>
0x0041d2e1:	jb 0x0041d2f0
0x0041d2f0:	addl %ebx, %ebx
0x0041d2f2:	jne 0x0041d2fb
0x0041d2fb:	adcl %ecx, %ecx
0x0041d2fd:	addl %ebx, %ebx
0x0041d2ff:	jne 0x0041d308
0x0041d308:	adcl %ecx, %ecx
0x0041d30a:	jne 0x0041d32c
0x0041d32c:	cmpl %ebp, $0xfffff300<UINT32>
0x0041d332:	adcl %ecx, $0x1<UINT8>
0x0041d335:	leal %edx, (%edi,%ebp)
0x0041d338:	cmpl %ebp, $0xfffffffc<UINT8>
0x0041d33b:	jbe 0x0041d34c
0x0041d33d:	movb %al, (%edx)
0x0041d33f:	incl %edx
0x0041d340:	movb (%edi), %al
0x0041d342:	incl %edi
0x0041d343:	decl %ecx
0x0041d344:	jne 0x0041d33d
0x0041d346:	jmp 0x0041d2ae
0x0041d2e3:	shll %eax, $0x8<UINT8>
0x0041d2e6:	movb %al, (%esi)
0x0041d2e8:	incl %esi
0x0041d2e9:	xorl %eax, $0xffffffff<UINT8>
0x0041d2ec:	je 0x0041d362
0x0041d2ee:	movl %ebp, %eax
0x0041d34c:	movl %eax, (%edx)
0x0041d34e:	addl %edx, $0x4<UINT8>
0x0041d351:	movl (%edi), %eax
0x0041d353:	addl %edi, $0x4<UINT8>
0x0041d356:	subl %ecx, $0x4<UINT8>
0x0041d359:	ja 0x0041d34c
0x0041d35b:	addl %edi, %ecx
0x0041d35d:	jmp 0x0041d2ae
0x0041d301:	movl %ebx, (%esi)
0x0041d303:	subl %esi, $0xfffffffc<UINT8>
0x0041d306:	adcl %ebx, %ebx
0x0041d2d3:	movl %ebx, (%esi)
0x0041d2d5:	subl %esi, $0xfffffffc<UINT8>
0x0041d2d8:	adcl %ebx, %ebx
0x0041d2da:	jae 0x0041d2c0
0x0041d30c:	incl %ecx
0x0041d30d:	addl %ebx, %ebx
0x0041d30f:	jne 0x0041d318
0x0041d318:	adcl %ecx, %ecx
0x0041d31a:	addl %ebx, %ebx
0x0041d31c:	jae 0x0041d30d
0x0041d31e:	jne 0x0041d329
0x0041d329:	addl %ecx, $0x2<UINT8>
0x0041d2c4:	movl %ebx, (%esi)
0x0041d2c6:	subl %esi, $0xfffffffc<UINT8>
0x0041d2c9:	adcl %ebx, %ebx
0x0041d2f4:	movl %ebx, (%esi)
0x0041d2f6:	subl %esi, $0xfffffffc<UINT8>
0x0041d2f9:	adcl %ebx, %ebx
0x0041d311:	movl %ebx, (%esi)
0x0041d313:	subl %esi, $0xfffffffc<UINT8>
0x0041d316:	adcl %ebx, %ebx
0x0041d320:	movl %ebx, (%esi)
0x0041d322:	subl %esi, $0xfffffffc<UINT8>
0x0041d325:	adcl %ebx, %ebx
0x0041d327:	jae 0x0041d30d
0x0041d362:	popl %esi
0x0041d363:	movl %edi, %esi
0x0041d365:	movl %ecx, $0x547<UINT32>
0x0041d36a:	movb %al, (%edi)
0x0041d36c:	incl %edi
0x0041d36d:	subb %al, $0xffffffe8<UINT8>
0x0041d36f:	cmpb %al, $0x1<UINT8>
0x0041d371:	ja 0x0041d36a
0x0041d373:	cmpb (%edi), $0x1<UINT8>
0x0041d376:	jne 0x0041d36a
0x0041d378:	movl %eax, (%edi)
0x0041d37a:	movb %bl, 0x4(%edi)
0x0041d37d:	shrw %ax, $0x8<UINT8>
0x0041d381:	roll %eax, $0x10<UINT8>
0x0041d384:	xchgb %ah, %al
0x0041d386:	subl %eax, %edi
0x0041d388:	subb %bl, $0xffffffe8<UINT8>
0x0041d38b:	addl %eax, %esi
0x0041d38d:	movl (%edi), %eax
0x0041d38f:	addl %edi, $0x5<UINT8>
0x0041d392:	movb %al, %bl
0x0041d394:	loop 0x0041d36f
0x0041d396:	leal %edi, 0x1b000(%esi)
0x0041d39c:	movl %eax, (%edi)
0x0041d39e:	orl %eax, %eax
0x0041d3a0:	je 0x0041d3e7
0x0041d3a2:	movl %ebx, 0x4(%edi)
0x0041d3a5:	leal %eax, 0x1f288(%eax,%esi)
0x0041d3ac:	addl %ebx, %esi
0x0041d3ae:	pushl %eax
0x0041d3af:	addl %edi, $0x8<UINT8>
0x0041d3b2:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0041d3b8:	xchgl %ebp, %eax
0x0041d3b9:	movb %al, (%edi)
0x0041d3bb:	incl %edi
0x0041d3bc:	orb %al, %al
0x0041d3be:	je 0x0041d39c
0x0041d3c0:	movl %ecx, %edi
0x0041d3c2:	jns 0x0041d3cb
0x0041d3cb:	pushl %edi
0x0041d3cc:	decl %eax
0x0041d3cd:	repn scasb %al, %es:(%edi)
0x0041d3cf:	pushl %ebp
0x0041d3d0:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0041d3d6:	orl %eax, %eax
0x0041d3d8:	je 7
0x0041d3da:	movl (%ebx), %eax
0x0041d3dc:	addl %ebx, $0x4<UINT8>
0x0041d3df:	jmp 0x0041d3b9
GetProcAddress@KERNEL32.DLL: API Node	
0x0041d3c4:	movzwl %eax, (%edi)
0x0041d3c7:	incl %edi
0x0041d3c8:	pushl %eax
0x0041d3c9:	incl %edi
0x0041d3ca:	movl %ecx, $0xaef24857<UINT32>
0x0041d3e7:	movl %ebp, 0x1f3a4(%esi)
0x0041d3ed:	leal %edi, -4096(%esi)
0x0041d3f3:	movl %ebx, $0x1000<UINT32>
0x0041d3f8:	pushl %eax
0x0041d3f9:	pushl %esp
0x0041d3fa:	pushl $0x4<UINT8>
0x0041d3fc:	pushl %ebx
0x0041d3fd:	pushl %edi
0x0041d3fe:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0041d400:	leal %eax, 0x20f(%edi)
0x0041d406:	andb (%eax), $0x7f<UINT8>
0x0041d409:	andb 0x28(%eax), $0x7f<UINT8>
0x0041d40d:	popl %eax
0x0041d40e:	pushl %eax
0x0041d40f:	pushl %esp
0x0041d410:	pushl %eax
0x0041d411:	pushl %ebx
0x0041d412:	pushl %edi
0x0041d413:	call VirtualProtect@kernel32.dll
0x0041d415:	popl %eax
0x0041d416:	popa
0x0041d417:	leal %eax, -128(%esp)
0x0041d41b:	pushl $0x0<UINT8>
0x0041d41d:	cmpl %esp, %eax
0x0041d41f:	jne 0x0041d41b
0x0041d421:	subl %esp, $0xffffff80<UINT8>
0x0041d424:	jmp 0x0040e1d0
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
0x0040e1df:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
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
0x0040e336:	call GetStartupInfoW@KERNEL32.DLL
GetStartupInfoW@KERNEL32.DLL: API Node	
0x0040e33c:	testb -76(%ebp), $0x1<UINT8>
0x0040e340:	je 0x0040e355
0x0040e355:	pushl $0xa<UINT8>
0x0040e357:	popl %eax
0x0040e358:	pushl %eax
0x0040e359:	pushl %esi
0x0040e35a:	pushl %edi
0x0040e35b:	pushl %edi
0x0040e35c:	call GetModuleHandleA@KERNEL32.DLL
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
0x00402ae7:	call LoadLibraryW@KERNEL32.DLL
LoadLibraryW@KERNEL32.DLL: API Node	
0x00402aed:	movl %esi, %eax
0x00402aef:	testl %esi, %esi
0x00402af1:	je 40
0x00402af3:	pushl $0x40f8b8<UINT32>
0x00402af8:	pushl %esi
0x00402af9:	call GetProcAddress@KERNEL32.DLL
0x00402aff:	testl %eax, %eax
0x00402b01:	je 9
0x00402b03:	leal %ecx, -8(%ebp)
0x00402b06:	pushl %ecx
0x00402b07:	incl %edi
0x00402b08:	call InitCommonControlsEx@comctl32.dll
InitCommonControlsEx@comctl32.dll: API Node	
0x00402b0a:	movl %ebx, %eax
0x00402b0c:	pushl %esi
0x00402b0d:	call FreeLibrary@KERNEL32.DLL
FreeLibrary@KERNEL32.DLL: API Node	
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
0x0040cb81:	call LoadLibraryW@KERNEL32.DLL
0x0040cb87:	testl %eax, %eax
0x0040cb89:	movl 0x414588, %eax
0x0040cb8e:	je 17
0x0040cb90:	pushl $0x410814<UINT32>
0x0040cb95:	pushl %eax
0x0040cb96:	call GetProcAddress@KERNEL32.DLL
0x0040cb9c:	movl 0x414584, %eax
0x0040cba1:	ret

0x0040b27b:	pushl $0x8001<UINT32>
0x0040b280:	call SetErrorMode@KERNEL32.DLL
SetErrorMode@KERNEL32.DLL: API Node	
0x0040b286:	movl %edi, 0x40f0c4
0x0040b28c:	pushl %ebx
0x0040b28d:	pushl $0x40cb58<UINT32>
0x0040b292:	pushl %ebx
0x0040b293:	movl 0x413e30, $0x11223344<UINT32>
0x0040b29d:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0040b29f:	pushl %eax
0x0040b2a0:	call EnumResourceTypesW@KERNEL32.DLL
EnumResourceTypesW@KERNEL32.DLL: API Node	
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
0x0018fee8:	into
0x0018fee9:	subl %edx, (%esi)
0x0018feeb:	addb (%edx), %cl
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
0x7c903308:	addb (%eax), %al
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
0x0018feed:	addb (%eax), %al
0x0018feef:	addb (%eax), %al
0x0018fef1:	addb (%eax), %al
0x0018fef3:	addb (%eax), %al
0x0018fef5:	addb (%eax), %al
0x0018fef7:	addb (%eax), %al
0x0018fef9:	loopne 0x0018fef8
0x0018fef8:	addb %al, %ah
0x0018fefa:	std
0x0018fefb:	jle 0
0x0018fefd:	addb (%eax), %al
0x0018feff:	addb (%eax), %al
0x0018ff01:	addb (%eax), %al
0x0018ff03:	addb (%eax,%eax), %al
0x0018ff07:	addb %dl, %bl
0x0018ff09:	subb %al, $0x16<UINT8>
0x0018ff0b:	addb 0x4200162c(%edx), %bh
0x0018ff11:	subb %al, $0x16<UINT8>
0x0018ff13:	addb (%eax), %al
0x0018ff15:	addb (%eax), %al
0x0018ff17:	addb (%eax), %al
0x0018ff19:	addb (%eax), %al
0x0018ff1b:	addb (%eax), %al
0x0018ff1d:	addb (%eax), %al
0x0018ff1f:	addb (%eax), %al
0x0018ff21:	addb (%eax), %al
0x0018ff23:	addb (%eax), %al
0x0018ff25:	addb (%eax), %al
0x0018ff27:	addb (%eax), %al
0x0018ff29:	addb (%eax), %al
0x0018ff2b:	addb (%eax), %al
0x0018ff2d:	addb (%eax), %al
0x0018ff2f:	addb (%eax), %al
0x0018ff31:	addl (%eax), %eax
0x0018ff33:	addb (%eax), %al
0x0018ff35:	addb -36(%eax,%eax), %ch
0x0018ff39:	subb %al, $0x16<UINT8>
0x0018ff3b:	addb 0x2ac0000(%edx,%eax), %ah
0x0018ff42:	addb (%eax), %al
0x0018ff44:	lodsb %al, %ds:(%esi)
0x0018ff45:	addb %al, (%eax)
0x0018ff47:	addb %dh, %cl
0x0018ff49:	subl %edx, (%esi)
0x0018ff4b:	addb (%eax), %al
0x0018ff4d:	addb (%eax), %al
0x0018ff4f:	addb (%eax,%eax), %al
0x0018ff52:	addb (%eax), %al
0x0018ff54:	cmpb %ch, $0x2a<UINT8>
0x0018ff57:	addb 0x153259(%eax), %ah
0x0018ff5d:	addb (%eax), %al
0x0018ff5f:	addb (%eax), %al
0x0018ff61:	addb (%eax), %al
0x0018ff63:	addb %al, %dh
Unknown Node: Unknown Node	
