0x004ac2a0:	pusha
0x004ac2a1:	movl %esi, $0x46e000<UINT32>
0x004ac2a6:	leal %edi, -446464(%esi)
0x004ac2ac:	pushl %edi
0x004ac2ad:	orl %ebp, $0xffffffff<UINT8>
0x004ac2b0:	jmp 0x004ac2c2
0x004ac2c2:	movl %ebx, (%esi)
0x004ac2c4:	subl %esi, $0xfffffffc<UINT8>
0x004ac2c7:	adcl %ebx, %ebx
0x004ac2c9:	jb 0x004ac2b8
0x004ac2b8:	movb %al, (%esi)
0x004ac2ba:	incl %esi
0x004ac2bb:	movb (%edi), %al
0x004ac2bd:	incl %edi
0x004ac2be:	addl %ebx, %ebx
0x004ac2c0:	jne 0x004ac2c9
0x004ac2cb:	movl %eax, $0x1<UINT32>
0x004ac2d0:	addl %ebx, %ebx
0x004ac2d2:	jne 0x004ac2db
0x004ac2db:	adcl %eax, %eax
0x004ac2dd:	addl %ebx, %ebx
0x004ac2df:	jae 0x004ac2ec
0x004ac2e1:	jne 0x004ac30b
0x004ac30b:	xorl %ecx, %ecx
0x004ac30d:	subl %eax, $0x3<UINT8>
0x004ac310:	jb 0x004ac323
0x004ac323:	addl %ebx, %ebx
0x004ac325:	jne 0x004ac32e
0x004ac32e:	jb 0x004ac2fc
0x004ac330:	incl %ecx
0x004ac331:	addl %ebx, %ebx
0x004ac333:	jne 0x004ac33c
0x004ac33c:	jb 0x004ac2fc
0x004ac33e:	addl %ebx, %ebx
0x004ac340:	jne 0x004ac349
0x004ac349:	adcl %ecx, %ecx
0x004ac34b:	addl %ebx, %ebx
0x004ac34d:	jae 0x004ac33e
0x004ac34f:	jne 0x004ac35a
0x004ac35a:	addl %ecx, $0x2<UINT8>
0x004ac35d:	cmpl %ebp, $0xfffffb00<UINT32>
0x004ac363:	adcl %ecx, $0x2<UINT8>
0x004ac366:	leal %edx, (%edi,%ebp)
0x004ac369:	cmpl %ebp, $0xfffffffc<UINT8>
0x004ac36c:	jbe 0x004ac37c
0x004ac36e:	movb %al, (%edx)
0x004ac370:	incl %edx
0x004ac371:	movb (%edi), %al
0x004ac373:	incl %edi
0x004ac374:	decl %ecx
0x004ac375:	jne 0x004ac36e
0x004ac377:	jmp 0x004ac2be
0x004ac312:	shll %eax, $0x8<UINT8>
0x004ac315:	movb %al, (%esi)
0x004ac317:	incl %esi
0x004ac318:	xorl %eax, $0xffffffff<UINT8>
0x004ac31b:	je 0x004ac392
0x004ac31d:	sarl %eax
0x004ac31f:	movl %ebp, %eax
0x004ac321:	jmp 0x004ac32e
0x004ac2fc:	addl %ebx, %ebx
0x004ac2fe:	jne 0x004ac307
0x004ac307:	adcl %ecx, %ecx
0x004ac309:	jmp 0x004ac35d
0x004ac37c:	movl %eax, (%edx)
0x004ac37e:	addl %edx, $0x4<UINT8>
0x004ac381:	movl (%edi), %eax
0x004ac383:	addl %edi, $0x4<UINT8>
0x004ac386:	subl %ecx, $0x4<UINT8>
0x004ac389:	ja 0x004ac37c
0x004ac38b:	addl %edi, %ecx
0x004ac38d:	jmp 0x004ac2be
0x004ac2d4:	movl %ebx, (%esi)
0x004ac2d6:	subl %esi, $0xfffffffc<UINT8>
0x004ac2d9:	adcl %ebx, %ebx
0x004ac2ec:	decl %eax
0x004ac2ed:	addl %ebx, %ebx
0x004ac2ef:	jne 0x004ac2f8
0x004ac2f1:	movl %ebx, (%esi)
0x004ac2f3:	subl %esi, $0xfffffffc<UINT8>
0x004ac2f6:	adcl %ebx, %ebx
0x004ac2f8:	adcl %eax, %eax
0x004ac2fa:	jmp 0x004ac2d0
0x004ac300:	movl %ebx, (%esi)
0x004ac302:	subl %esi, $0xfffffffc<UINT8>
0x004ac305:	adcl %ebx, %ebx
0x004ac335:	movl %ebx, (%esi)
0x004ac337:	subl %esi, $0xfffffffc<UINT8>
0x004ac33a:	adcl %ebx, %ebx
0x004ac351:	movl %ebx, (%esi)
0x004ac353:	subl %esi, $0xfffffffc<UINT8>
0x004ac356:	adcl %ebx, %ebx
0x004ac358:	jae 0x004ac33e
0x004ac327:	movl %ebx, (%esi)
0x004ac329:	subl %esi, $0xfffffffc<UINT8>
0x004ac32c:	adcl %ebx, %ebx
0x004ac342:	movl %ebx, (%esi)
0x004ac344:	subl %esi, $0xfffffffc<UINT8>
0x004ac347:	adcl %ebx, %ebx
0x004ac2e3:	movl %ebx, (%esi)
0x004ac2e5:	subl %esi, $0xfffffffc<UINT8>
0x004ac2e8:	adcl %ebx, %ebx
0x004ac2ea:	jb 0x004ac30b
0x004ac392:	popl %esi
0x004ac393:	movl %edi, %esi
0x004ac395:	movl %ecx, $0xa90<UINT32>
0x004ac39a:	movb %al, (%edi)
0x004ac39c:	incl %edi
0x004ac39d:	subb %al, $0xffffffe8<UINT8>
0x004ac39f:	cmpb %al, $0x1<UINT8>
0x004ac3a1:	ja 0x004ac39a
0x004ac3a3:	cmpb (%edi), $0x5<UINT8>
0x004ac3a6:	jne 0x004ac39a
0x004ac3a8:	movl %eax, (%edi)
0x004ac3aa:	movb %bl, 0x4(%edi)
0x004ac3ad:	shrw %ax, $0x8<UINT8>
0x004ac3b1:	roll %eax, $0x10<UINT8>
0x004ac3b4:	xchgb %ah, %al
0x004ac3b6:	subl %eax, %edi
0x004ac3b8:	subb %bl, $0xffffffe8<UINT8>
0x004ac3bb:	addl %eax, %esi
0x004ac3bd:	movl (%edi), %eax
0x004ac3bf:	addl %edi, $0x5<UINT8>
0x004ac3c2:	movb %al, %bl
0x004ac3c4:	loop 0x004ac39f
0x004ac3c6:	leal %edi, 0xa9000(%esi)
0x004ac3cc:	movl %eax, (%edi)
0x004ac3ce:	orl %eax, %eax
0x004ac3d0:	je 0x004ac417
0x004ac3d2:	movl %ebx, 0x4(%edi)
0x004ac3d5:	leal %eax, 0xb5474(%eax,%esi)
0x004ac3dc:	addl %ebx, %esi
0x004ac3de:	pushl %eax
0x004ac3df:	addl %edi, $0x8<UINT8>
0x004ac3e2:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004ac3e8:	xchgl %ebp, %eax
0x004ac3e9:	movb %al, (%edi)
0x004ac3eb:	incl %edi
0x004ac3ec:	orb %al, %al
0x004ac3ee:	je 0x004ac3cc
0x004ac3f0:	movl %ecx, %edi
0x004ac3f2:	jns 0x004ac3fb
0x004ac3fb:	pushl %edi
0x004ac3fc:	decl %eax
0x004ac3fd:	repn scasb %al, %es:(%edi)
0x004ac3ff:	pushl %ebp
0x004ac400:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x004ac406:	orl %eax, %eax
0x004ac408:	je 7
0x004ac40a:	movl (%ebx), %eax
0x004ac40c:	addl %ebx, $0x4<UINT8>
0x004ac40f:	jmp 0x004ac3e9
GetProcAddress@KERNEL32.DLL: API Node	
0x004ac3f4:	movzwl %eax, (%edi)
0x004ac3f7:	incl %edi
0x004ac3f8:	pushl %eax
0x004ac3f9:	incl %edi
0x004ac3fa:	movl %ecx, $0xaef24857<UINT32>
0x004ac417:	addl %edi, $0x4<UINT8>
0x004ac41a:	leal %ebx, -4(%esi)
0x004ac41d:	xorl %eax, %eax
0x004ac41f:	movb %al, (%edi)
0x004ac421:	incl %edi
0x004ac422:	orl %eax, %eax
0x004ac424:	je 0x004ac448
0x004ac426:	cmpb %al, $0xffffffef<UINT8>
0x004ac428:	ja 0x004ac43b
0x004ac42a:	addl %ebx, %eax
0x004ac42c:	movl %eax, (%ebx)
0x004ac42e:	xchgb %ah, %al
0x004ac430:	roll %eax, $0x10<UINT8>
0x004ac433:	xchgb %ah, %al
0x004ac435:	addl %eax, %esi
0x004ac437:	movl (%ebx), %eax
0x004ac439:	jmp 0x004ac41d
0x004ac43b:	andb %al, $0xf<UINT8>
0x004ac43d:	shll %eax, $0x10<UINT8>
0x004ac440:	movw %ax, (%edi)
0x004ac443:	addl %edi, $0x2<UINT8>
0x004ac446:	jmp 0x004ac42a
0x004ac448:	movl %ebp, 0xb5560(%esi)
0x004ac44e:	leal %edi, -4096(%esi)
0x004ac454:	movl %ebx, $0x1000<UINT32>
0x004ac459:	pushl %eax
0x004ac45a:	pushl %esp
0x004ac45b:	pushl $0x4<UINT8>
0x004ac45d:	pushl %ebx
0x004ac45e:	pushl %edi
0x004ac45f:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x004ac461:	leal %eax, 0x207(%edi)
0x004ac467:	andb (%eax), $0x7f<UINT8>
0x004ac46a:	andb 0x28(%eax), $0x7f<UINT8>
0x004ac46e:	popl %eax
0x004ac46f:	pushl %eax
0x004ac470:	pushl %esp
0x004ac471:	pushl %eax
0x004ac472:	pushl %ebx
0x004ac473:	pushl %edi
0x004ac474:	call VirtualProtect@kernel32.dll
0x004ac476:	popl %eax
0x004ac477:	popa
0x004ac478:	leal %eax, -128(%esp)
0x004ac47c:	pushl $0x0<UINT8>
0x004ac47e:	cmpl %esp, %eax
0x004ac480:	jne 0x004ac47c
0x004ac482:	subl %esp, $0xffffff80<UINT8>
0x004ac485:	jmp 0x0041216a
0x0041216a:	call 0x00417c27
0x00417c27:	movl %edi, %edi
0x00417c29:	pushl %ebp
0x00417c2a:	movl %ebp, %esp
0x00417c2c:	subl %esp, $0x10<UINT8>
0x00417c2f:	movl %eax, 0x424308
0x00417c34:	andl -8(%ebp), $0x0<UINT8>
0x00417c38:	andl -4(%ebp), $0x0<UINT8>
0x00417c3c:	pushl %ebx
0x00417c3d:	pushl %edi
0x00417c3e:	movl %edi, $0xbb40e64e<UINT32>
0x00417c43:	movl %ebx, $0xffff0000<UINT32>
0x00417c48:	cmpl %eax, %edi
0x00417c4a:	je 0x00417c59
0x00417c59:	pushl %esi
0x00417c5a:	leal %eax, -8(%ebp)
0x00417c5d:	pushl %eax
0x00417c5e:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x00417c64:	movl %esi, -4(%ebp)
0x00417c67:	xorl %esi, -8(%ebp)
0x00417c6a:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x00417c70:	xorl %esi, %eax
0x00417c72:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x00417c78:	xorl %esi, %eax
0x00417c7a:	call GetTickCount@KERNEL32.DLL
GetTickCount@KERNEL32.DLL: API Node	
0x00417c80:	xorl %esi, %eax
0x00417c82:	leal %eax, -16(%ebp)
0x00417c85:	pushl %eax
0x00417c86:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x00417c8c:	movl %eax, -12(%ebp)
0x00417c8f:	xorl %eax, -16(%ebp)
0x00417c92:	xorl %esi, %eax
0x00417c94:	cmpl %esi, %edi
0x00417c96:	jne 0x00417c9f
0x00417c9f:	testl %ebx, %esi
0x00417ca1:	jne 0x00417caf
0x00417caf:	movl 0x424308, %esi
0x00417cb5:	notl %esi
0x00417cb7:	movl 0x42430c, %esi
0x00417cbd:	popl %esi
0x00417cbe:	popl %edi
0x00417cbf:	popl %ebx
0x00417cc0:	leave
0x00417cc1:	ret

0x0041216f:	jmp 0x00411ffd
0x00411ffd:	pushl $0x58<UINT8>
0x00411fff:	pushl $0x422610<UINT32>
0x00412004:	call 0x00414750
0x00414750:	pushl $0x4147b0<UINT32>
0x00414755:	pushl %fs:0
0x0041475c:	movl %eax, 0x10(%esp)
0x00414760:	movl 0x10(%esp), %ebp
0x00414764:	leal %ebp, 0x10(%esp)
0x00414768:	subl %esp, %eax
0x0041476a:	pushl %ebx
0x0041476b:	pushl %esi
0x0041476c:	pushl %edi
0x0041476d:	movl %eax, 0x424308
0x00414772:	xorl -4(%ebp), %eax
0x00414775:	xorl %eax, %ebp
0x00414777:	pushl %eax
0x00414778:	movl -24(%ebp), %esp
0x0041477b:	pushl -8(%ebp)
0x0041477e:	movl %eax, -4(%ebp)
0x00414781:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00414788:	movl -8(%ebp), %eax
0x0041478b:	leal %eax, -16(%ebp)
0x0041478e:	movl %fs:0, %eax
0x00414794:	ret

0x00412009:	leal %eax, -104(%ebp)
0x0041200c:	pushl %eax
0x0041200d:	call GetStartupInfoW@KERNEL32.DLL
GetStartupInfoW@KERNEL32.DLL: API Node	
0x00412013:	xorl %esi, %esi
0x00412015:	cmpl 0x4266c0, %esi
0x0041201b:	jne 11
0x0041201d:	pushl %esi
0x0041201e:	pushl %esi
0x0041201f:	pushl $0x1<UINT8>
0x00412021:	pushl %esi
0x00412022:	call HeapSetInformation@KERNEL32.DLL
HeapSetInformation@KERNEL32.DLL: API Node	
0x00412028:	movl %eax, $0x5a4d<UINT32>
0x0041202d:	cmpw 0x400000, %ax
0x00412034:	je 0x0041203b
0x0041203b:	movl %eax, 0x40003c
0x00412040:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x0041204a:	jne -22
0x0041204c:	movl %ecx, $0x10b<UINT32>
0x00412051:	cmpw 0x400018(%eax), %cx
0x00412058:	jne -36
0x0041205a:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00412061:	jbe -45
0x00412063:	xorl %ecx, %ecx
0x00412065:	cmpl 0x4000e8(%eax), %esi
0x0041206b:	setne %cl
0x0041206e:	movl -28(%ebp), %ecx
0x00412071:	call 0x00412a01
0x00412a01:	pushl $0x0<UINT8>
0x00412a03:	pushl $0x1000<UINT32>
0x00412a08:	pushl $0x0<UINT8>
0x00412a0a:	call HeapCreate@KERNEL32.DLL
HeapCreate@KERNEL32.DLL: API Node	
0x00412a10:	xorl %ecx, %ecx
0x00412a12:	testl %eax, %eax
0x00412a14:	setne %cl
0x00412a17:	movl 0x425b48, %eax
0x00412a1c:	movl %eax, %ecx
0x00412a1e:	ret

0x00412076:	testl %eax, %eax
0x00412078:	jne 0x00412082
0x00412082:	call 0x00415be3
0x00415be3:	movl %edi, %edi
0x00415be5:	pushl %edi
0x00415be6:	pushl $0x41feb4<UINT32>
0x00415beb:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00415bf1:	movl %edi, %eax
0x00415bf3:	testl %edi, %edi
0x00415bf5:	jne 0x00415c00
0x00415c00:	pushl %esi
0x00415c01:	movl %esi, 0x41e080
0x00415c07:	pushl $0x41fef0<UINT32>
0x00415c0c:	pushl %edi
0x00415c0d:	call GetProcAddress@KERNEL32.DLL
0x00415c0f:	pushl $0x41fee4<UINT32>
0x00415c14:	pushl %edi
0x00415c15:	movl 0x425e84, %eax
0x00415c1a:	call GetProcAddress@KERNEL32.DLL
0x00415c1c:	pushl $0x41fed8<UINT32>
0x00415c21:	pushl %edi
0x00415c22:	movl 0x425e88, %eax
0x00415c27:	call GetProcAddress@KERNEL32.DLL
0x00415c29:	pushl $0x41fed0<UINT32>
0x00415c2e:	pushl %edi
0x00415c2f:	movl 0x425e8c, %eax
0x00415c34:	call GetProcAddress@KERNEL32.DLL
0x00415c36:	cmpl 0x425e84, $0x0<UINT8>
0x00415c3d:	movl %esi, 0x41e164
0x00415c43:	movl 0x425e90, %eax
0x00415c48:	je 22
0x00415c4a:	cmpl 0x425e88, $0x0<UINT8>
0x00415c51:	je 13
0x00415c53:	cmpl 0x425e8c, $0x0<UINT8>
0x00415c5a:	je 4
0x00415c5c:	testl %eax, %eax
0x00415c5e:	jne 0x00415c84
0x00415c84:	call TlsAlloc@KERNEL32.DLL
TlsAlloc@KERNEL32.DLL: API Node	
0x00415c8a:	movl 0x424744, %eax
0x00415c8f:	cmpl %eax, $0xffffffff<UINT8>
0x00415c92:	je 193
0x00415c98:	pushl 0x425e88
0x00415c9e:	pushl %eax
0x00415c9f:	call TlsSetValue@KERNEL32.DLL
TlsSetValue@KERNEL32.DLL: API Node	
0x00415ca1:	testl %eax, %eax
0x00415ca3:	je 176
0x00415ca9:	call 0x0041255d
0x0041255d:	movl %edi, %edi
0x0041255f:	pushl %esi
0x00412560:	call 0x004158ea
0x004158ea:	pushl $0x0<UINT8>
0x004158ec:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x004158f2:	ret

0x00412565:	movl %esi, %eax
0x00412567:	pushl %esi
0x00412568:	call 0x00412aaa
0x00412aaa:	movl %edi, %edi
0x00412aac:	pushl %ebp
0x00412aad:	movl %ebp, %esp
0x00412aaf:	movl %eax, 0x8(%ebp)
0x00412ab2:	movl 0x425b4c, %eax
0x00412ab7:	popl %ebp
0x00412ab8:	ret

0x0041256d:	pushl %esi
0x0041256e:	call 0x0041383c
0x0041383c:	movl %edi, %edi
0x0041383e:	pushl %ebp
0x0041383f:	movl %ebp, %esp
0x00413841:	movl %eax, 0x8(%ebp)
0x00413844:	movl 0x425b54, %eax
0x00413849:	popl %ebp
0x0041384a:	ret

0x00412573:	pushl %esi
0x00412574:	call 0x00417efc
0x00417efc:	movl %edi, %edi
0x00417efe:	pushl %ebp
0x00417eff:	movl %ebp, %esp
0x00417f01:	movl %eax, 0x8(%ebp)
0x00417f04:	movl 0x426224, %eax
0x00417f09:	popl %ebp
0x00417f0a:	ret

0x00412579:	pushl %esi
0x0041257a:	call 0x00418267
0x00418267:	movl %edi, %edi
0x00418269:	pushl %ebp
0x0041826a:	movl %ebp, %esp
0x0041826c:	movl %eax, 0x8(%ebp)
0x0041826f:	movl 0x426278, %eax
0x00418274:	popl %ebp
0x00418275:	ret

0x0041257f:	pushl %esi
0x00412580:	call 0x00418062
0x00418062:	movl %edi, %edi
0x00418064:	pushl %ebp
0x00418065:	movl %ebp, %esp
0x00418067:	movl %eax, 0x8(%ebp)
0x0041806a:	movl 0x426264, %eax
0x0041806f:	movl 0x426268, %eax
0x00418074:	movl 0x42626c, %eax
0x00418079:	movl 0x426270, %eax
0x0041807e:	popl %ebp
0x0041807f:	ret

0x00412585:	pushl %esi
0x00412586:	call 0x00415de2
0x00415de2:	pushl $0x415d5e<UINT32>
0x00415de7:	call EncodePointer@KERNEL32.DLL
0x00415ded:	movl 0x425e94, %eax
0x00415df2:	ret

0x0041258b:	addl %esp, $0x18<UINT8>
0x0041258e:	popl %esi
0x0041258f:	ret

0x00415cae:	pushl 0x425e84
0x00415cb4:	movl %esi, 0x41e0c0
0x00415cba:	call EncodePointer@KERNEL32.DLL
0x00415cbc:	pushl 0x425e88
0x00415cc2:	movl 0x425e84, %eax
0x00415cc7:	call EncodePointer@KERNEL32.DLL
0x00415cc9:	pushl 0x425e8c
0x00415ccf:	movl 0x425e88, %eax
0x00415cd4:	call EncodePointer@KERNEL32.DLL
0x00415cd6:	pushl 0x425e90
0x00415cdc:	movl 0x425e8c, %eax
0x00415ce1:	call EncodePointer@KERNEL32.DLL
0x00415ce3:	movl 0x425e90, %eax
0x00415ce8:	call 0x0041657b
0x0041657b:	movl %edi, %edi
0x0041657d:	pushl %esi
0x0041657e:	pushl %edi
0x0041657f:	xorl %esi, %esi
0x00416581:	movl %edi, $0x425ea0<UINT32>
0x00416586:	cmpl 0x424794(,%esi,8), $0x1<UINT8>
0x0041658e:	jne 0x004165ad
0x00416590:	leal %eax, 0x424790(,%esi,8)
0x00416597:	movl (%eax), %edi
0x00416599:	pushl $0xfa0<UINT32>
0x0041659e:	pushl (%eax)
0x004165a0:	addl %edi, $0x18<UINT8>
0x004165a3:	call InitializeCriticalSectionAndSpinCount@KERNEL32.DLL
InitializeCriticalSectionAndSpinCount@KERNEL32.DLL: API Node	
0x004165a9:	testl %eax, %eax
0x004165ab:	je 12
0x004165ad:	incl %esi
0x004165ae:	cmpl %esi, $0x24<UINT8>
0x004165b1:	jl 0x00416586
0x004165b3:	xorl %eax, %eax
0x004165b5:	incl %eax
0x004165b6:	popl %edi
0x004165b7:	popl %esi
0x004165b8:	ret

0x00415ced:	testl %eax, %eax
0x00415cef:	je 99
0x00415cf1:	movl %edi, 0x41e0bc
0x00415cf7:	pushl $0x415ab4<UINT32>
0x00415cfc:	pushl 0x425e84
0x00415d02:	call DecodePointer@KERNEL32.DLL
DecodePointer@KERNEL32.DLL: API Node	
0x00415d04:	call FlsAlloc@KERNEL32.DLL
FlsAlloc@KERNEL32.DLL: API Node	
0x00415d06:	movl 0x424740, %eax
0x00415d0b:	cmpl %eax, $0xffffffff<UINT8>
0x00415d0e:	je 68
0x00415d10:	pushl $0x214<UINT32>
0x00415d15:	pushl $0x1<UINT8>
0x00415d17:	call 0x004162b2
0x004162b2:	movl %edi, %edi
0x004162b4:	pushl %ebp
0x004162b5:	movl %ebp, %esp
0x004162b7:	pushl %esi
0x004162b8:	pushl %edi
0x004162b9:	xorl %esi, %esi
0x004162bb:	pushl $0x0<UINT8>
0x004162bd:	pushl 0xc(%ebp)
0x004162c0:	pushl 0x8(%ebp)
0x004162c3:	call 0x00419964
0x00419964:	movl %edi, %edi
0x00419966:	pushl %ebp
0x00419967:	movl %ebp, %esp
0x00419969:	movl %ecx, 0x8(%ebp)
0x0041996c:	testl %ecx, %ecx
0x0041996e:	je 27
0x00419970:	pushl $0xffffffe0<UINT8>
0x00419972:	xorl %edx, %edx
0x00419974:	popl %eax
0x00419975:	divl %eax, %ecx
0x00419977:	cmpl %eax, 0xc(%ebp)
0x0041997a:	jae 0x0041998b
0x0041998b:	imull %ecx, 0xc(%ebp)
0x0041998f:	pushl %esi
0x00419990:	movl %esi, %ecx
0x00419992:	testl %esi, %esi
0x00419994:	jne 0x00419997
0x00419997:	xorl %eax, %eax
0x00419999:	cmpl %esi, $0xffffffe0<UINT8>
0x0041999c:	ja 19
0x0041999e:	pushl %esi
0x0041999f:	pushl $0x8<UINT8>
0x004199a1:	pushl 0x425b48
0x004199a7:	call HeapAlloc@KERNEL32.DLL
HeapAlloc@KERNEL32.DLL: API Node	
0x004199ad:	testl %eax, %eax
0x004199af:	jne 0x004199e3
0x004199e3:	popl %esi
0x004199e4:	popl %ebp
0x004199e5:	ret

0x004162c8:	movl %edi, %eax
0x004162ca:	addl %esp, $0xc<UINT8>
0x004162cd:	testl %edi, %edi
0x004162cf:	jne 0x004162f8
0x004162f8:	movl %eax, %edi
0x004162fa:	popl %edi
0x004162fb:	popl %esi
0x004162fc:	popl %ebp
0x004162fd:	ret

0x00415d1c:	movl %esi, %eax
0x00415d1e:	popl %ecx
0x00415d1f:	popl %ecx
0x00415d20:	testl %esi, %esi
0x00415d22:	je 48
0x00415d24:	pushl %esi
0x00415d25:	pushl 0x424740
0x00415d2b:	pushl 0x425e8c
0x00415d31:	call DecodePointer@KERNEL32.DLL
0x00415d33:	call FlsSetValue@KERNEL32.DLL
FlsSetValue@KERNEL32.DLL: API Node	
0x00415d35:	testl %eax, %eax
0x00415d37:	je 27
0x00415d39:	pushl $0x0<UINT8>
0x00415d3b:	pushl %esi
0x00415d3c:	call 0x0041596d
0x0041596d:	pushl $0x8<UINT8>
0x0041596f:	pushl $0x4227b0<UINT32>
0x00415974:	call 0x00414750
0x00415979:	pushl $0x41feb4<UINT32>
0x0041597e:	call GetModuleHandleW@KERNEL32.DLL
0x00415984:	movl %esi, 0x8(%ebp)
0x00415987:	movl 0x5c(%esi), $0x4202f8<UINT32>
0x0041598e:	andl 0x8(%esi), $0x0<UINT8>
0x00415992:	xorl %edi, %edi
0x00415994:	incl %edi
0x00415995:	movl 0x14(%esi), %edi
0x00415998:	movl 0x70(%esi), %edi
0x0041599b:	movb 0xc8(%esi), $0x43<UINT8>
0x004159a2:	movb 0x14b(%esi), $0x43<UINT8>
0x004159a9:	movl 0x68(%esi), $0x4248b0<UINT32>
0x004159b0:	pushl $0xd<UINT8>
0x004159b2:	call 0x004166f5
0x004166f5:	movl %edi, %edi
0x004166f7:	pushl %ebp
0x004166f8:	movl %ebp, %esp
0x004166fa:	movl %eax, 0x8(%ebp)
0x004166fd:	pushl %esi
0x004166fe:	leal %esi, 0x424790(,%eax,8)
0x00416705:	cmpl (%esi), $0x0<UINT8>
0x00416708:	jne 0x0041671d
0x0041671d:	pushl (%esi)
0x0041671f:	call EnterCriticalSection@KERNEL32.DLL
EnterCriticalSection@KERNEL32.DLL: API Node	
0x00416725:	popl %esi
0x00416726:	popl %ebp
0x00416727:	ret

0x004159b7:	popl %ecx
0x004159b8:	andl -4(%ebp), $0x0<UINT8>
0x004159bc:	pushl 0x68(%esi)
0x004159bf:	call InterlockedIncrement@KERNEL32.DLL
InterlockedIncrement@KERNEL32.DLL: API Node	
0x004159c5:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004159cc:	call 0x00415a0f
0x00415a0f:	pushl $0xd<UINT8>
0x00415a11:	call 0x0041661c
0x0041661c:	movl %edi, %edi
0x0041661e:	pushl %ebp
0x0041661f:	movl %ebp, %esp
0x00416621:	movl %eax, 0x8(%ebp)
0x00416624:	pushl 0x424790(,%eax,8)
0x0041662b:	call LeaveCriticalSection@KERNEL32.DLL
LeaveCriticalSection@KERNEL32.DLL: API Node	
0x00416631:	popl %ebp
0x00416632:	ret

0x00415a16:	popl %ecx
0x00415a17:	ret

0x004159d1:	pushl $0xc<UINT8>
0x004159d3:	call 0x004166f5
0x004159d8:	popl %ecx
0x004159d9:	movl -4(%ebp), %edi
0x004159dc:	movl %eax, 0xc(%ebp)
0x004159df:	movl 0x6c(%esi), %eax
0x004159e2:	testl %eax, %eax
0x004159e4:	jne 8
0x004159e6:	movl %eax, 0x425018
0x004159eb:	movl 0x6c(%esi), %eax
0x004159ee:	pushl 0x6c(%esi)
0x004159f1:	call 0x00416f3f
0x00416f3f:	movl %edi, %edi
0x00416f41:	pushl %ebp
0x00416f42:	movl %ebp, %esp
0x00416f44:	pushl %ebx
0x00416f45:	pushl %esi
0x00416f46:	movl %esi, 0x41e088
0x00416f4c:	pushl %edi
0x00416f4d:	movl %edi, 0x8(%ebp)
0x00416f50:	pushl %edi
0x00416f51:	call InterlockedIncrement@KERNEL32.DLL
0x00416f53:	movl %eax, 0xb0(%edi)
0x00416f59:	testl %eax, %eax
0x00416f5b:	je 0x00416f60
0x00416f60:	movl %eax, 0xb8(%edi)
0x00416f66:	testl %eax, %eax
0x00416f68:	je 0x00416f6d
0x00416f6d:	movl %eax, 0xb4(%edi)
0x00416f73:	testl %eax, %eax
0x00416f75:	je 0x00416f7a
0x00416f7a:	movl %eax, 0xc0(%edi)
0x00416f80:	testl %eax, %eax
0x00416f82:	je 0x00416f87
0x00416f87:	leal %ebx, 0x50(%edi)
0x00416f8a:	movl 0x8(%ebp), $0x6<UINT32>
0x00416f91:	cmpl -8(%ebx), $0x424dd4<UINT32>
0x00416f98:	je 0x00416fa3
0x00416f9a:	movl %eax, (%ebx)
0x00416f9c:	testl %eax, %eax
0x00416f9e:	je 0x00416fa3
0x00416fa3:	cmpl -4(%ebx), $0x0<UINT8>
0x00416fa7:	je 0x00416fb3
0x00416fb3:	addl %ebx, $0x10<UINT8>
0x00416fb6:	decl 0x8(%ebp)
0x00416fb9:	jne 0x00416f91
0x00416fbb:	movl %eax, 0xd4(%edi)
0x00416fc1:	addl %eax, $0xb4<UINT32>
0x00416fc6:	pushl %eax
0x00416fc7:	call InterlockedIncrement@KERNEL32.DLL
0x00416fc9:	popl %edi
0x00416fca:	popl %esi
0x00416fcb:	popl %ebx
0x00416fcc:	popl %ebp
0x00416fcd:	ret

0x004159f6:	popl %ecx
0x004159f7:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004159fe:	call 0x00415a18
0x00415a18:	pushl $0xc<UINT8>
0x00415a1a:	call 0x0041661c
0x00415a1f:	popl %ecx
0x00415a20:	ret

0x00415a03:	call 0x00414795
0x00414795:	movl %ecx, -16(%ebp)
0x00414798:	movl %fs:0, %ecx
0x0041479f:	popl %ecx
0x004147a0:	popl %edi
0x004147a1:	popl %edi
0x004147a2:	popl %esi
0x004147a3:	popl %ebx
0x004147a4:	movl %esp, %ebp
0x004147a6:	popl %ebp
0x004147a7:	pushl %ecx
0x004147a8:	ret

0x00415a08:	ret

0x00415d41:	popl %ecx
0x00415d42:	popl %ecx
0x00415d43:	call GetCurrentThreadId@KERNEL32.DLL
0x00415d49:	orl 0x4(%esi), $0xffffffff<UINT8>
0x00415d4d:	movl (%esi), %eax
0x00415d4f:	xorl %eax, %eax
0x00415d51:	incl %eax
0x00415d52:	jmp 0x00415d5b
0x00415d5b:	popl %esi
0x00415d5c:	popl %edi
0x00415d5d:	ret

0x00412087:	testl %eax, %eax
0x00412089:	jne 0x00412093
0x00412093:	call 0x00417bdb
0x00417bdb:	movl %edi, %edi
0x00417bdd:	pushl %esi
0x00417bde:	movl %eax, $0x422324<UINT32>
0x00417be3:	movl %esi, $0x422324<UINT32>
0x00417be8:	pushl %edi
0x00417be9:	movl %edi, %eax
0x00417beb:	cmpl %eax, %esi
0x00417bed:	jae 0x00417bfe
0x00417bfe:	popl %edi
0x00417bff:	popl %esi
0x00417c00:	ret

0x00412098:	movl -4(%ebp), %esi
0x0041209b:	call 0x00416028
0x00416028:	movl %edi, %edi
0x0041602a:	pushl %ebp
0x0041602b:	movl %ebp, %esp
0x0041602d:	subl %esp, $0x4c<UINT8>
0x00416030:	pushl %esi
0x00416031:	leal %eax, -76(%ebp)
0x00416034:	pushl %eax
0x00416035:	call GetStartupInfoW@KERNEL32.DLL
0x0041603b:	pushl $0x40<UINT8>
0x0041603d:	pushl $0x20<UINT8>
0x0041603f:	popl %esi
0x00416040:	pushl %esi
0x00416041:	call 0x004162b2
0x00416046:	popl %ecx
0x00416047:	popl %ecx
0x00416048:	xorl %ecx, %ecx
0x0041604a:	cmpl %eax, %ecx
0x0041604c:	jne 0x00416056
0x00416056:	leal %edx, 0x800(%eax)
0x0041605c:	movl 0x4265a0, %eax
0x00416061:	movl 0x426590, %esi
0x00416067:	cmpl %eax, %edx
0x00416069:	jae 54
0x0041606b:	addl %eax, $0x5<UINT8>
0x0041606e:	orl -5(%eax), $0xffffffff<UINT8>
0x00416072:	movw -1(%eax), $0xa00<UINT16>
0x00416078:	movl 0x3(%eax), %ecx
0x0041607b:	movw 0x1f(%eax), $0xa00<UINT16>
0x00416081:	movb 0x21(%eax), $0xa<UINT8>
0x00416085:	movl 0x33(%eax), %ecx
0x00416088:	movb 0x2f(%eax), %cl
0x0041608b:	movl %esi, 0x4265a0
0x00416091:	addl %eax, $0x40<UINT8>
0x00416094:	leal %edx, -5(%eax)
0x00416097:	addl %esi, $0x800<UINT32>
0x0041609d:	cmpl %edx, %esi
0x0041609f:	jb 0x0041606e
0x004160a1:	pushl %ebx
0x004160a2:	pushl %edi
0x004160a3:	cmpw -26(%ebp), %cx
0x004160a7:	je 270
0x004160ad:	movl %eax, -24(%ebp)
0x004160b0:	cmpl %eax, %ecx
0x004160b2:	je 259
0x004160b8:	movl %ebx, (%eax)
0x004160ba:	addl %eax, $0x4<UINT8>
0x004160bd:	movl -4(%ebp), %eax
0x004160c0:	addl %eax, %ebx
0x004160c2:	movl %esi, $0x800<UINT32>
0x004160c7:	movl -8(%ebp), %eax
0x004160ca:	cmpl %ebx, %esi
0x004160cc:	jl 0x004160d0
0x004160d0:	cmpl 0x426590, %ebx
0x004160d6:	jnl 0x00416143
0x00416143:	xorl %edi, %edi
0x00416145:	testl %ebx, %ebx
0x00416147:	jle 0x004161bb
0x004161bb:	xorl %ebx, %ebx
0x004161bd:	movl %esi, %ebx
0x004161bf:	shll %esi, $0x6<UINT8>
0x004161c2:	addl %esi, 0x4265a0
0x004161c8:	movl %eax, (%esi)
0x004161ca:	cmpl %eax, $0xffffffff<UINT8>
0x004161cd:	je 0x004161da
0x004161da:	movb 0x4(%esi), $0xffffff81<UINT8>
0x004161de:	testl %ebx, %ebx
0x004161e0:	jne 0x004161e7
0x004161e2:	pushl $0xfffffff6<UINT8>
0x004161e4:	popl %eax
0x004161e5:	jmp 0x004161f1
0x004161f1:	pushl %eax
0x004161f2:	call GetStdHandle@KERNEL32.DLL
GetStdHandle@KERNEL32.DLL: API Node	
0x004161f8:	movl %edi, %eax
0x004161fa:	cmpl %edi, $0xffffffff<UINT8>
0x004161fd:	je 66
0x004161ff:	testl %edi, %edi
0x00416201:	je 62
0x00416203:	pushl %edi
0x00416204:	call GetFileType@KERNEL32.DLL
GetFileType@KERNEL32.DLL: API Node	
0x0041620a:	testl %eax, %eax
0x0041620c:	je 51
0x0041620e:	andl %eax, $0xff<UINT32>
0x00416213:	movl (%esi), %edi
0x00416215:	cmpl %eax, $0x2<UINT8>
0x00416218:	jne 6
0x0041621a:	orb 0x4(%esi), $0x40<UINT8>
0x0041621e:	jmp 0x00416229
0x00416229:	pushl $0xfa0<UINT32>
0x0041622e:	leal %eax, 0xc(%esi)
0x00416231:	pushl %eax
0x00416232:	call InitializeCriticalSectionAndSpinCount@KERNEL32.DLL
0x00416238:	testl %eax, %eax
0x0041623a:	je 44
0x0041623c:	incl 0x8(%esi)
0x0041623f:	jmp 0x0041624b
0x0041624b:	incl %ebx
0x0041624c:	cmpl %ebx, $0x3<UINT8>
0x0041624f:	jl 0x004161bd
0x004161e7:	leal %eax, -1(%ebx)
0x004161ea:	negl %eax
0x004161ec:	sbbl %eax, %eax
0x004161ee:	addl %eax, $0xfffffff5<UINT8>
0x00416255:	pushl 0x426590
0x0041625b:	call SetHandleCount@KERNEL32.DLL
SetHandleCount@KERNEL32.DLL: API Node	
0x00416261:	xorl %eax, %eax
0x00416263:	popl %edi
0x00416264:	popl %ebx
0x00416265:	popl %esi
0x00416266:	leave
0x00416267:	ret

0x004120a0:	testl %eax, %eax
0x004120a2:	jns 0x004120ac
0x004120ac:	call GetCommandLineW@KERNEL32.DLL
GetCommandLineW@KERNEL32.DLL: API Node	
0x004120b2:	movl 0x4266bc, %eax
0x004120b7:	call 0x00417b83
0x00417b83:	movl %edi, %edi
0x00417b85:	pushl %esi
0x00417b86:	call GetEnvironmentStringsW@KERNEL32.DLL
GetEnvironmentStringsW@KERNEL32.DLL: API Node	
0x00417b8c:	movl %esi, %eax
0x00417b8e:	xorl %ecx, %ecx
0x00417b90:	cmpl %esi, %ecx
0x00417b92:	jne 0x00417b98
0x00417b98:	cmpw (%esi), %cx
0x00417b9b:	je 16
0x00417b9d:	addl %eax, $0x2<UINT8>
0x00417ba0:	cmpw (%eax), %cx
0x00417ba3:	jne 0x00417b9d
0x00417ba5:	addl %eax, $0x2<UINT8>
0x00417ba8:	cmpw (%eax), %cx
0x00417bab:	jne 0x00417b9d
0x00417bad:	pushl %ebx
0x00417bae:	subl %eax, %esi
0x00417bb0:	leal %ebx, 0x2(%eax)
0x00417bb3:	pushl %edi
0x00417bb4:	pushl %ebx
0x00417bb5:	call 0x0041626d
0x0041626d:	movl %edi, %edi
0x0041626f:	pushl %ebp
0x00416270:	movl %ebp, %esp
0x00416272:	pushl %esi
0x00416273:	pushl %edi
0x00416274:	xorl %esi, %esi
0x00416276:	pushl 0x8(%ebp)
0x00416279:	call 0x0041018b
0x0041018b:	movl %edi, %edi
0x0041018d:	pushl %ebp
0x0041018e:	movl %ebp, %esp
0x00410190:	pushl %ebx
0x00410191:	movl %ebx, 0x8(%ebp)
0x00410194:	cmpl %ebx, $0xffffffe0<UINT8>
0x00410197:	ja 111
0x00410199:	pushl %esi
0x0041019a:	pushl %edi
0x0041019b:	cmpl 0x425b48, $0x0<UINT8>
0x004101a2:	jne 0x004101bc
0x004101bc:	testl %ebx, %ebx
0x004101be:	je 4
0x004101c0:	movl %eax, %ebx
0x004101c2:	jmp 0x004101c7
0x004101c7:	pushl %eax
0x004101c8:	pushl $0x0<UINT8>
0x004101ca:	pushl 0x425b48
0x004101d0:	call HeapAlloc@KERNEL32.DLL
0x004101d6:	movl %edi, %eax
0x004101d8:	testl %edi, %edi
0x004101da:	jne 0x00410202
0x00410202:	movl %eax, %edi
0x00410204:	popl %edi
0x00410205:	popl %esi
0x00410206:	jmp 0x0041021c
0x0041021c:	popl %ebx
0x0041021d:	popl %ebp
0x0041021e:	ret

0x0041627e:	movl %edi, %eax
0x00416280:	popl %ecx
0x00416281:	testl %edi, %edi
0x00416283:	jne 0x004162ac
0x004162ac:	movl %eax, %edi
0x004162ae:	popl %edi
0x004162af:	popl %esi
0x004162b0:	popl %ebp
0x004162b1:	ret

0x00417bba:	movl %edi, %eax
0x00417bbc:	popl %ecx
0x00417bbd:	testl %edi, %edi
0x00417bbf:	jne 0x00417bce
0x00417bce:	pushl %ebx
0x00417bcf:	pushl %esi
0x00417bd0:	pushl %edi
0x00417bd1:	call 0x00410610
0x00410610:	pushl %ebp
0x00410611:	movl %ebp, %esp
0x00410613:	pushl %edi
0x00410614:	pushl %esi
0x00410615:	movl %esi, 0xc(%ebp)
0x00410618:	movl %ecx, 0x10(%ebp)
0x0041061b:	movl %edi, 0x8(%ebp)
0x0041061e:	movl %eax, %ecx
0x00410620:	movl %edx, %ecx
0x00410622:	addl %eax, %esi
0x00410624:	cmpl %edi, %esi
0x00410626:	jbe 8
0x00410628:	cmpl %edi, %eax
0x0041062a:	jb 416
0x00410630:	cmpl %ecx, $0x80<UINT32>
0x00410636:	jb 28
0x00410638:	cmpl 0x4266a0, $0x0<UINT8>
0x0041063f:	je 0x00410654
0x00410654:	testl %edi, $0x3<UINT32>
0x0041065a:	jne 20
0x0041065c:	shrl %ecx, $0x2<UINT8>
0x0041065f:	andl %edx, $0x3<UINT8>
0x00410662:	cmpl %ecx, $0x8<UINT8>
0x00410665:	jb 41
0x00410667:	rep movsl %es:(%edi), %ds:(%esi)
0x00410669:	jmp 0x004107a4
0x004107a4:	movb %al, (%esi)
0x004107a6:	movb (%edi), %al
0x004107a8:	movb %al, 0x1(%esi)
0x004107ab:	movb 0x1(%edi), %al
0x004107ae:	movl %eax, 0x8(%ebp)
0x004107b1:	popl %esi
0x004107b2:	popl %edi
0x004107b3:	leave
0x004107b4:	ret

0x00417bd6:	addl %esp, $0xc<UINT8>
0x00417bd9:	jmp 0x00417bc1
0x00417bc1:	pushl %esi
0x00417bc2:	call FreeEnvironmentStringsW@KERNEL32.DLL
FreeEnvironmentStringsW@KERNEL32.DLL: API Node	
0x00417bc8:	movl %eax, %edi
0x00417bca:	popl %edi
0x00417bcb:	popl %ebx
0x00417bcc:	popl %esi
0x00417bcd:	ret

0x004120bc:	movl 0x4254d8, %eax
0x004120c1:	call 0x00417ad5
0x00417ad5:	movl %edi, %edi
0x00417ad7:	pushl %ebp
0x00417ad8:	movl %ebp, %esp
0x00417ada:	pushl %ecx
0x00417adb:	pushl %ecx
0x00417adc:	pushl %ebx
0x00417add:	pushl %esi
0x00417ade:	pushl %edi
0x00417adf:	pushl $0x104<UINT32>
0x00417ae4:	movl %esi, $0x426018<UINT32>
0x00417ae9:	pushl %esi
0x00417aea:	xorl %eax, %eax
0x00417aec:	xorl %ebx, %ebx
0x00417aee:	pushl %ebx
0x00417aef:	movw 0x426220, %ax
0x00417af5:	call GetModuleFileNameW@KERNEL32.DLL
GetModuleFileNameW@KERNEL32.DLL: API Node	
0x00417afb:	movl %eax, 0x4266bc
0x00417b00:	movl 0x42550c, %esi
0x00417b06:	cmpl %eax, %ebx
0x00417b08:	je 7
0x00417b0a:	movl %edi, %eax
0x00417b0c:	cmpw (%eax), %bx
0x00417b0f:	jne 0x00417b13
0x00417b13:	leal %eax, -4(%ebp)
0x00417b16:	pushl %eax
0x00417b17:	pushl %ebx
0x00417b18:	leal %ebx, -8(%ebp)
0x00417b1b:	xorl %ecx, %ecx
0x00417b1d:	movl %eax, %edi
0x00417b1f:	call 0x0041797f
0x0041797f:	movl %edi, %edi
0x00417981:	pushl %ebp
0x00417982:	movl %ebp, %esp
0x00417984:	pushl %ecx
0x00417985:	pushl %esi
0x00417986:	xorl %edx, %edx
0x00417988:	pushl %edi
0x00417989:	movl %edi, 0xc(%ebp)
0x0041798c:	movl (%ebx), %edx
0x0041798e:	movl %esi, %ecx
0x00417990:	movl (%edi), $0x1<UINT32>
0x00417996:	cmpl 0x8(%ebp), %edx
0x00417999:	je 0x004179a4
0x004179a4:	cmpw (%eax), $0x22<UINT8>
0x004179a8:	jne 0x004179be
0x004179aa:	movl %edi, 0xc(%ebp)
0x004179ad:	xorl %ecx, %ecx
0x004179af:	testl %edx, %edx
0x004179b1:	sete %cl
0x004179b4:	pushl $0x22<UINT8>
0x004179b6:	addl %eax, $0x2<UINT8>
0x004179b9:	movl %edx, %ecx
0x004179bb:	popl %ecx
0x004179bc:	jmp 0x004179d8
0x004179d8:	testl %edx, %edx
0x004179da:	jne 0x004179a4
0x004179be:	incl (%ebx)
0x004179c0:	testl %esi, %esi
0x004179c2:	je 0x004179cd
0x004179cd:	movzwl %ecx, (%eax)
0x004179d0:	addl %eax, $0x2<UINT8>
0x004179d3:	testw %cx, %cx
0x004179d6:	je 0x00417a13
0x004179dc:	cmpw %cx, $0x20<UINT8>
0x004179e0:	je 6
0x004179e2:	cmpw %cx, $0x9<UINT8>
0x004179e6:	jne 0x004179a4
0x00417a13:	subl %eax, $0x2<UINT8>
0x00417a16:	jmp 0x004179f2
0x004179f2:	andl -4(%ebp), $0x0<UINT8>
0x004179f6:	xorl %edx, %edx
0x004179f8:	cmpw (%eax), %dx
0x004179fb:	je 0x00417ac6
0x00417ac6:	movl %eax, 0x8(%ebp)
0x00417ac9:	cmpl %eax, %edx
0x00417acb:	je 0x00417acf
0x00417acf:	incl (%edi)
0x00417ad1:	popl %edi
0x00417ad2:	popl %esi
0x00417ad3:	leave
0x00417ad4:	ret

0x00417b24:	movl %ebx, -4(%ebp)
0x00417b27:	popl %ecx
0x00417b28:	popl %ecx
0x00417b29:	cmpl %ebx, $0x3fffffff<UINT32>
0x00417b2f:	jae 74
0x00417b31:	movl %ecx, -8(%ebp)
0x00417b34:	cmpl %ecx, $0x7fffffff<UINT32>
0x00417b3a:	jae 63
0x00417b3c:	leal %eax, (%ecx,%ebx,2)
0x00417b3f:	addl %eax, %eax
0x00417b41:	addl %ecx, %ecx
0x00417b43:	cmpl %eax, %ecx
0x00417b45:	jb 52
0x00417b47:	pushl %eax
0x00417b48:	call 0x0041626d
0x00417b4d:	movl %esi, %eax
0x00417b4f:	popl %ecx
0x00417b50:	testl %esi, %esi
0x00417b52:	je 39
0x00417b54:	leal %eax, -4(%ebp)
0x00417b57:	pushl %eax
0x00417b58:	leal %ecx, (%esi,%ebx,4)
0x00417b5b:	pushl %esi
0x00417b5c:	leal %ebx, -8(%ebp)
0x00417b5f:	movl %eax, %edi
0x00417b61:	call 0x0041797f
0x0041799b:	movl %ecx, 0x8(%ebp)
0x0041799e:	addl 0x8(%ebp), $0x4<UINT8>
0x004179a2:	movl (%ecx), %esi
0x004179c4:	movw %cx, (%eax)
0x004179c7:	movw (%esi), %cx
0x004179ca:	addl %esi, $0x2<UINT8>
0x00417acd:	movl (%eax), %edx
0x00417b66:	movl %eax, -4(%ebp)
0x00417b69:	decl %eax
0x00417b6a:	popl %ecx
0x00417b6b:	movl 0x4254ec, %eax
0x00417b70:	popl %ecx
0x00417b71:	movl 0x4254f4, %esi
0x00417b77:	xorl %eax, %eax
0x00417b79:	jmp 0x00417b7e
0x00417b7e:	popl %edi
0x00417b7f:	popl %esi
0x00417b80:	popl %ebx
0x00417b81:	leave
0x00417b82:	ret

0x004120c6:	testl %eax, %eax
0x004120c8:	jns 0x004120d2
0x004120d2:	call 0x004178a3
0x004178a3:	movl %edi, %edi
0x004178a5:	pushl %esi
0x004178a6:	movl %esi, 0x4254d8
0x004178ac:	pushl %edi
0x004178ad:	xorl %edi, %edi
0x004178af:	testl %esi, %esi
0x004178b1:	jne 0x004178cd
0x004178cd:	movzwl %eax, (%esi)
0x004178d0:	testw %ax, %ax
0x004178d3:	jne 0x004178bb
0x004178bb:	cmpw %ax, $0x3d<UINT8>
0x004178bf:	je 0x004178c2
0x004178c2:	pushl %esi
0x004178c3:	call 0x004185cd
0x004185cd:	movl %edi, %edi
0x004185cf:	pushl %ebp
0x004185d0:	movl %ebp, %esp
0x004185d2:	movl %eax, 0x8(%ebp)
0x004185d5:	movw %cx, (%eax)
0x004185d8:	addl %eax, $0x2<UINT8>
0x004185db:	testw %cx, %cx
0x004185de:	jne 0x004185d5
0x004185e0:	subl %eax, 0x8(%ebp)
0x004185e3:	sarl %eax
0x004185e5:	decl %eax
0x004185e6:	popl %ebp
0x004185e7:	ret

0x004178c8:	popl %ecx
0x004178c9:	leal %esi, 0x2(%esi,%eax,2)
0x004178c1:	incl %edi
0x004178d5:	pushl %ebx
0x004178d6:	pushl $0x4<UINT8>
0x004178d8:	incl %edi
0x004178d9:	pushl %edi
0x004178da:	call 0x004162b2
0x004178df:	movl %ebx, %eax
0x004178e1:	popl %ecx
0x004178e2:	popl %ecx
0x004178e3:	movl 0x425500, %ebx
0x004178e9:	testl %ebx, %ebx
0x004178eb:	jne 0x004178f2
0x004178f2:	movl %esi, 0x4254d8
0x004178f8:	jmp 0x0041792f
0x0041792f:	cmpw (%esi), $0x0<UINT8>
0x00417933:	jne 0x004178fa
0x004178fa:	pushl %esi
0x004178fb:	call 0x004185cd
0x00417900:	cmpw (%esi), $0x3d<UINT8>
0x00417904:	popl %ecx
0x00417905:	leal %edi, 0x1(%eax)
0x00417908:	je 0x0041792c
0x0041792c:	leal %esi, (%esi,%edi,2)
0x0041790a:	pushl $0x2<UINT8>
0x0041790c:	pushl %edi
0x0041790d:	call 0x004162b2
0x00417912:	popl %ecx
0x00417913:	popl %ecx
0x00417914:	movl (%ebx), %eax
0x00417916:	testl %eax, %eax
0x00417918:	je 65
0x0041791a:	pushl %esi
0x0041791b:	pushl %edi
0x0041791c:	pushl %eax
0x0041791d:	call 0x004185e8
0x004185e8:	movl %edi, %edi
0x004185ea:	pushl %ebp
0x004185eb:	movl %ebp, %esp
0x004185ed:	pushl %esi
0x004185ee:	movl %esi, 0x8(%ebp)
0x004185f1:	pushl %edi
0x004185f2:	testl %esi, %esi
0x004185f4:	je 7
0x004185f6:	movl %edi, 0xc(%ebp)
0x004185f9:	testl %edi, %edi
0x004185fb:	jne 0x00418612
0x00418612:	movl %eax, 0x10(%ebp)
0x00418615:	testl %eax, %eax
0x00418617:	jne 0x0041861e
0x0041861e:	movl %edx, %esi
0x00418620:	subl %edx, %eax
0x00418622:	movzwl %ecx, (%eax)
0x00418625:	movw (%edx,%eax), %cx
0x00418629:	addl %eax, $0x2<UINT8>
0x0041862c:	testw %cx, %cx
0x0041862f:	je 0x00418634
0x00418631:	decl %edi
0x00418632:	jne 0x00418622
0x00418634:	xorl %eax, %eax
0x00418636:	testl %edi, %edi
0x00418638:	jne 0x0041860e
0x0041860e:	popl %edi
0x0041860f:	popl %esi
0x00418610:	popl %ebp
0x00418611:	ret

0x00417922:	addl %esp, $0xc<UINT8>
0x00417925:	testl %eax, %eax
0x00417927:	jne 73
0x00417929:	addl %ebx, $0x4<UINT8>
0x00417935:	pushl 0x4254d8
0x0041793b:	call 0x0041021f
0x0041021f:	movl %edi, %edi
0x00410221:	pushl %ebp
0x00410222:	movl %ebp, %esp
0x00410224:	cmpl 0x8(%ebp), $0x0<UINT8>
0x00410228:	je 45
0x0041022a:	pushl 0x8(%ebp)
0x0041022d:	pushl $0x0<UINT8>
0x0041022f:	pushl 0x425b48
0x00410235:	call HeapFree@KERNEL32.DLL
HeapFree@KERNEL32.DLL: API Node	
0x0041023b:	testl %eax, %eax
0x0041023d:	jne 0x00410257
0x00410257:	popl %ebp
0x00410258:	ret

0x00417940:	andl 0x4254d8, $0x0<UINT8>
0x00417947:	andl (%ebx), $0x0<UINT8>
0x0041794a:	movl 0x4266a4, $0x1<UINT32>
0x00417954:	xorl %eax, %eax
0x00417956:	popl %ecx
0x00417957:	popl %ebx
0x00417958:	popl %edi
0x00417959:	popl %esi
0x0041795a:	ret

0x004120d7:	testl %eax, %eax
0x004120d9:	jns 0x004120e3
0x004120e3:	pushl $0x1<UINT8>
0x004120e5:	call 0x004125b4
0x004125b4:	movl %edi, %edi
0x004125b6:	pushl %ebp
0x004125b7:	movl %ebp, %esp
0x004125b9:	cmpl 0x4266b4, $0x0<UINT8>
0x004125c0:	je 0x004125db
0x004125db:	call 0x00418276
0x00418276:	movl %edi, %edi
0x00418278:	pushl %esi
0x00418279:	pushl %edi
0x0041827a:	xorl %edi, %edi
0x0041827c:	pushl 0x425030(%edi)
0x00418282:	call EncodePointer@KERNEL32.DLL
0x00418288:	movl 0x425030(%edi), %eax
0x0041828e:	addl %edi, $0x4<UINT8>
0x00418291:	cmpl %edi, $0x28<UINT8>
0x00418294:	jb 0x0041827c
0x00418296:	popl %edi
0x00418297:	popl %esi
0x00418298:	ret

0x004125e0:	pushl $0x41e358<UINT32>
0x004125e5:	pushl $0x41e340<UINT32>
0x004125ea:	call 0x00412590
0x00412590:	movl %edi, %edi
0x00412592:	pushl %ebp
0x00412593:	movl %ebp, %esp
0x00412595:	pushl %esi
0x00412596:	movl %esi, 0x8(%ebp)
0x00412599:	xorl %eax, %eax
0x0041259b:	jmp 0x004125ac
0x004125ac:	cmpl %esi, 0xc(%ebp)
0x004125af:	jb 0x0041259d
0x0041259d:	testl %eax, %eax
0x0041259f:	jne 16
0x004125a1:	movl %ecx, (%esi)
0x004125a3:	testl %ecx, %ecx
0x004125a5:	je 0x004125a9
0x004125a9:	addl %esi, $0x4<UINT8>
0x004125a7:	call 0x00417705
0x00411138:	movl %eax, 0x4276e0
0x0041113d:	pushl %esi
0x0041113e:	pushl $0x14<UINT8>
0x00411140:	popl %esi
0x00411141:	testl %eax, %eax
0x00411143:	jne 7
0x00411145:	movl %eax, $0x200<UINT32>
0x0041114a:	jmp 0x00411152
0x00411152:	movl 0x4276e0, %eax
0x00411157:	pushl $0x4<UINT8>
0x00411159:	pushl %eax
0x0041115a:	call 0x004162b2
0x0041115f:	popl %ecx
0x00411160:	popl %ecx
0x00411161:	movl 0x4266c4, %eax
0x00411166:	testl %eax, %eax
0x00411168:	jne 0x00411188
0x00411188:	xorl %edx, %edx
0x0041118a:	movl %ecx, $0x424310<UINT32>
0x0041118f:	jmp 0x00411196
0x00411196:	movl (%edx,%eax), %ecx
0x00411199:	addl %ecx, $0x20<UINT8>
0x0041119c:	addl %edx, $0x4<UINT8>
0x0041119f:	cmpl %ecx, $0x424590<UINT32>
0x004111a5:	jl 0x00411191
0x00411191:	movl %eax, 0x4266c4
0x004111a7:	pushl $0xfffffffe<UINT8>
0x004111a9:	popl %esi
0x004111aa:	xorl %edx, %edx
0x004111ac:	movl %ecx, $0x424320<UINT32>
0x004111b1:	pushl %edi
0x004111b2:	movl %eax, %edx
0x004111b4:	sarl %eax, $0x5<UINT8>
0x004111b7:	movl %eax, 0x4265a0(,%eax,4)
0x004111be:	movl %edi, %edx
0x004111c0:	andl %edi, $0x1f<UINT8>
0x004111c3:	shll %edi, $0x6<UINT8>
0x004111c6:	movl %eax, (%edi,%eax)
0x004111c9:	cmpl %eax, $0xffffffff<UINT8>
0x004111cc:	je 8
0x004111ce:	cmpl %eax, %esi
0x004111d0:	je 4
0x004111d2:	testl %eax, %eax
0x004111d4:	jne 0x004111d8
0x004111d8:	addl %ecx, $0x20<UINT8>
0x004111db:	incl %edx
0x004111dc:	cmpl %ecx, $0x424380<UINT32>
0x004111e2:	jl 0x004111b2
0x004111e4:	popl %edi
0x004111e5:	xorl %eax, %eax
0x004111e7:	popl %esi
0x004111e8:	ret

0x00411c0d:	movl %edi, %edi
0x00411c0f:	pushl %esi
0x00411c10:	pushl $0x4<UINT8>
0x00411c12:	pushl $0x20<UINT8>
0x00411c14:	call 0x004162b2
0x00411c19:	popl %ecx
0x00411c1a:	popl %ecx
0x00411c1b:	movl %esi, %eax
0x00411c1d:	pushl %esi
0x00411c1e:	call EncodePointer@KERNEL32.DLL
0x00411c24:	movl 0x4266ac, %eax
0x00411c29:	movl 0x4266a8, %eax
0x00411c2e:	testl %esi, %esi
0x00411c30:	jne 0x00411c37
0x00411c37:	andl (%esi), $0x0<UINT8>
0x00411c3a:	xorl %eax, %eax
0x00411c3c:	popl %esi
0x00411c3d:	ret

0x00414aff:	pushl $0xa<UINT8>
0x00414b01:	call IsProcessorFeaturePresent@KERNEL32.DLL
IsProcessorFeaturePresent@KERNEL32.DLL: API Node	
0x00414b07:	movl 0x4266a0, %eax
0x00414b0c:	xorl %eax, %eax
0x00414b0e:	ret

0x00416f21:	cmpl 0x4266b0, $0x0<UINT8>
0x00416f28:	jne 18
0x00416f2a:	pushl $0xfffffffd<UINT8>
0x00416f2c:	call 0x00416d87
0x00416d87:	pushl $0x14<UINT8>
0x00416d89:	pushl $0x4228e8<UINT32>
0x00416d8e:	call 0x00414750
0x00416d93:	orl -32(%ebp), $0xffffffff<UINT8>
0x00416d97:	call 0x00415a9a
0x00415a9a:	movl %edi, %edi
0x00415a9c:	pushl %esi
0x00415a9d:	call 0x00415a21
0x00415a21:	movl %edi, %edi
0x00415a23:	pushl %esi
0x00415a24:	pushl %edi
0x00415a25:	call GetLastError@KERNEL32.DLL
GetLastError@KERNEL32.DLL: API Node	
0x00415a2b:	pushl 0x424740
0x00415a31:	movl %edi, %eax
0x00415a33:	call 0x004158fc
0x004158fc:	movl %edi, %edi
0x004158fe:	pushl %esi
0x004158ff:	pushl 0x424744
0x00415905:	call TlsGetValue@KERNEL32.DLL
TlsGetValue@KERNEL32.DLL: API Node	
0x0041590b:	movl %esi, %eax
0x0041590d:	testl %esi, %esi
0x0041590f:	jne 0x0041592c
0x0041592c:	movl %eax, %esi
0x0041592e:	popl %esi
0x0041592f:	ret

0x00415a38:	call FlsGetValue@KERNEL32.DLL
FlsGetValue@KERNEL32.DLL: API Node	
0x00415a3a:	movl %esi, %eax
0x00415a3c:	testl %esi, %esi
0x00415a3e:	jne 0x00415a8e
0x00415a8e:	pushl %edi
0x00415a8f:	call SetLastError@KERNEL32.DLL
SetLastError@KERNEL32.DLL: API Node	
0x00415a95:	popl %edi
0x00415a96:	movl %eax, %esi
0x00415a98:	popl %esi
0x00415a99:	ret

0x00415aa2:	movl %esi, %eax
0x00415aa4:	testl %esi, %esi
0x00415aa6:	jne 0x00415ab0
0x00415ab0:	movl %eax, %esi
0x00415ab2:	popl %esi
0x00415ab3:	ret

0x00416d9c:	movl %edi, %eax
0x00416d9e:	movl -36(%ebp), %edi
0x00416da1:	call 0x00416a7e
0x00416a7e:	pushl $0xc<UINT8>
0x00416a80:	pushl $0x4228c8<UINT32>
0x00416a85:	call 0x00414750
0x00416a8a:	call 0x00415a9a
0x00416a8f:	movl %edi, %eax
0x00416a91:	movl %eax, 0x424dd0
0x00416a96:	testl 0x70(%edi), %eax
0x00416a99:	je 0x00416ab8
0x00416ab8:	pushl $0xd<UINT8>
0x00416aba:	call 0x004166f5
0x00416abf:	popl %ecx
0x00416ac0:	andl -4(%ebp), $0x0<UINT8>
0x00416ac4:	movl %esi, 0x68(%edi)
0x00416ac7:	movl -28(%ebp), %esi
0x00416aca:	cmpl %esi, 0x424cd8
0x00416ad0:	je 0x00416b08
0x00416b08:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00416b0f:	call 0x00416b19
0x00416b19:	pushl $0xd<UINT8>
0x00416b1b:	call 0x0041661c
0x00416b20:	popl %ecx
0x00416b21:	ret

0x00416b14:	jmp 0x00416aa4
0x00416aa4:	testl %esi, %esi
0x00416aa6:	jne 0x00416ab0
0x00416ab0:	movl %eax, %esi
0x00416ab2:	call 0x00414795
0x00416ab7:	ret

0x00416da6:	movl %ebx, 0x68(%edi)
0x00416da9:	movl %esi, 0x8(%ebp)
0x00416dac:	call 0x00416b22
0x00416b22:	movl %edi, %edi
0x00416b24:	pushl %ebp
0x00416b25:	movl %ebp, %esp
0x00416b27:	subl %esp, $0x10<UINT8>
0x00416b2a:	pushl %ebx
0x00416b2b:	xorl %ebx, %ebx
0x00416b2d:	pushl %ebx
0x00416b2e:	leal %ecx, -16(%ebp)
0x00416b31:	call 0x00411942
0x00411942:	movl %edi, %edi
0x00411944:	pushl %ebp
0x00411945:	movl %ebp, %esp
0x00411947:	movl %eax, 0x8(%ebp)
0x0041194a:	pushl %esi
0x0041194b:	movl %esi, %ecx
0x0041194d:	movb 0xc(%esi), $0x0<UINT8>
0x00411951:	testl %eax, %eax
0x00411953:	jne 99
0x00411955:	call 0x00415a9a
0x0041195a:	movl 0x8(%esi), %eax
0x0041195d:	movl %ecx, 0x6c(%eax)
0x00411960:	movl (%esi), %ecx
0x00411962:	movl %ecx, 0x68(%eax)
0x00411965:	movl 0x4(%esi), %ecx
0x00411968:	movl %ecx, (%esi)
0x0041196a:	cmpl %ecx, 0x425018
0x00411970:	je 0x00411984
0x00411984:	movl %eax, 0x4(%esi)
0x00411987:	cmpl %eax, 0x424cd8
0x0041198d:	je 0x004119a5
0x004119a5:	movl %eax, 0x8(%esi)
0x004119a8:	testb 0x70(%eax), $0x2<UINT8>
0x004119ac:	jne 20
0x004119ae:	orl 0x70(%eax), $0x2<UINT8>
0x004119b2:	movb 0xc(%esi), $0x1<UINT8>
0x004119b6:	jmp 0x004119c2
0x004119c2:	movl %eax, %esi
0x004119c4:	popl %esi
0x004119c5:	popl %ebp
0x004119c6:	ret $0x4<UINT16>

0x00416b36:	movl 0x425ff4, %ebx
0x00416b3c:	cmpl %esi, $0xfffffffe<UINT8>
0x00416b3f:	jne 0x00416b5f
0x00416b5f:	cmpl %esi, $0xfffffffd<UINT8>
0x00416b62:	jne 0x00416b76
0x00416b64:	movl 0x425ff4, $0x1<UINT32>
0x00416b6e:	call GetACP@KERNEL32.DLL
GetACP@KERNEL32.DLL: API Node	
0x00416b74:	jmp 0x00416b51
0x00416b51:	cmpb -4(%ebp), %bl
0x00416b54:	je 69
0x00416b56:	movl %ecx, -8(%ebp)
0x00416b59:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00416b5d:	jmp 0x00416b9b
0x00416b9b:	popl %ebx
0x00416b9c:	leave
0x00416b9d:	ret

0x00416db1:	movl 0x8(%ebp), %eax
0x00416db4:	cmpl %eax, 0x4(%ebx)
0x00416db7:	je 343
0x00416dbd:	pushl $0x220<UINT32>
0x00416dc2:	call 0x0041626d
0x00416dc7:	popl %ecx
0x00416dc8:	movl %ebx, %eax
0x00416dca:	testl %ebx, %ebx
0x00416dcc:	je 326
0x00416dd2:	movl %ecx, $0x88<UINT32>
0x00416dd7:	movl %esi, 0x68(%edi)
0x00416dda:	movl %edi, %ebx
0x00416ddc:	rep movsl %es:(%edi), %ds:(%esi)
0x00416dde:	andl (%ebx), $0x0<UINT8>
0x00416de1:	pushl %ebx
0x00416de2:	pushl 0x8(%ebp)
0x00416de5:	call 0x00416b9e
0x00416b9e:	movl %edi, %edi
0x00416ba0:	pushl %ebp
0x00416ba1:	movl %ebp, %esp
0x00416ba3:	subl %esp, $0x20<UINT8>
0x00416ba6:	movl %eax, 0x424308
0x00416bab:	xorl %eax, %ebp
0x00416bad:	movl -4(%ebp), %eax
0x00416bb0:	pushl %ebx
0x00416bb1:	movl %ebx, 0xc(%ebp)
0x00416bb4:	pushl %esi
0x00416bb5:	movl %esi, 0x8(%ebp)
0x00416bb8:	pushl %edi
0x00416bb9:	call 0x00416b22
0x00416b76:	cmpl %esi, $0xfffffffc<UINT8>
0x00416b79:	jne 0x00416b8d
0x00416b8d:	cmpb -4(%ebp), %bl
0x00416b90:	je 7
0x00416b92:	movl %eax, -8(%ebp)
0x00416b95:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x00416b99:	movl %eax, %esi
0x00416bbe:	movl %edi, %eax
0x00416bc0:	xorl %esi, %esi
0x00416bc2:	movl 0x8(%ebp), %edi
0x00416bc5:	cmpl %edi, %esi
0x00416bc7:	jne 0x00416bd7
0x00416bd7:	movl -28(%ebp), %esi
0x00416bda:	xorl %eax, %eax
0x00416bdc:	cmpl 0x424ce0(%eax), %edi
0x00416be2:	je 145
0x00416be8:	incl -28(%ebp)
0x00416beb:	addl %eax, $0x30<UINT8>
0x00416bee:	cmpl %eax, $0xf0<UINT32>
0x00416bf3:	jb 0x00416bdc
0x00416bf5:	cmpl %edi, $0xfde8<UINT32>
0x00416bfb:	je 372
0x00416c01:	cmpl %edi, $0xfde9<UINT32>
0x00416c07:	je 360
0x00416c0d:	movzwl %eax, %di
0x00416c10:	pushl %eax
0x00416c11:	call IsValidCodePage@KERNEL32.DLL
IsValidCodePage@KERNEL32.DLL: API Node	
0x00416c17:	testl %eax, %eax
0x00416c19:	je 342
0x00416c1f:	leal %eax, -24(%ebp)
0x00416c22:	pushl %eax
0x00416c23:	pushl %edi
0x00416c24:	call GetCPInfo@KERNEL32.DLL
GetCPInfo@KERNEL32.DLL: API Node	
0x00416c2a:	testl %eax, %eax
0x00416c2c:	je 311
0x00416c32:	pushl $0x101<UINT32>
0x00416c37:	leal %eax, 0x1c(%ebx)
0x00416c3a:	pushl %esi
0x00416c3b:	pushl %eax
0x00416c3c:	call 0x004104c0
0x004104c0:	movl %edx, 0xc(%esp)
0x004104c4:	movl %ecx, 0x4(%esp)
0x004104c8:	testl %edx, %edx
0x004104ca:	je 105
0x004104cc:	xorl %eax, %eax
0x004104ce:	movb %al, 0x8(%esp)
0x004104d2:	testb %al, %al
0x004104d4:	jne 22
0x004104d6:	cmpl %edx, $0x80<UINT32>
0x004104dc:	jb 0x004104ec
0x004104de:	cmpl 0x4266a0, $0x0<UINT8>
0x004104e5:	je 5
0x004104e7:	jmp 0x00414a45
0x00414a45:	pxor %xmm0, %xmm0
0x00414a49:	pushl %ecx
0x00414a4a:	pushl %ebx
0x00414a4b:	movl %eax, %ecx
0x00414a4d:	andl %eax, $0xf<UINT8>
0x00414a50:	testl %eax, %eax
0x00414a52:	jne 0x00414ad3
0x00414ad3:	movl %ebx, %eax
0x00414ad5:	negl %ebx
0x00414ad7:	addl %ebx, $0x10<UINT8>
0x00414ada:	subl %edx, %ebx
0x00414adc:	xorl %eax, %eax
0x00414ade:	pushl %edx
0x00414adf:	movl %edx, %ebx
0x00414ae1:	andl %edx, $0x3<UINT8>
0x00414ae4:	je 0x00414aec
0x00414aec:	shrl %ebx, $0x2<UINT8>
0x00414aef:	je 8
0x00414af1:	movl (%ecx), %eax
0x00414af3:	leal %ecx, 0x4(%ecx)
0x00414af6:	decl %ebx
0x00414af7:	jne 0x00414af1
0x00414af9:	popl %edx
0x00414afa:	jmp 0x00414a54
0x00414a54:	movl %eax, %edx
0x00414a56:	andl %edx, $0x7f<UINT8>
0x00414a59:	shrl %eax, $0x7<UINT8>
0x00414a5c:	je 55
0x00414a5e:	leal %esp, (%esp)
0x00414a65:	movdqa (%ecx), %xmm0
0x00414a69:	movdqa 0x10(%ecx), %xmm0
0x00414a6e:	movdqa 0x20(%ecx), %xmm0
0x00414a73:	movdqa 0x30(%ecx), %xmm0
0x00414a78:	movdqa 0x40(%ecx), %xmm0
0x00414a7d:	movdqa 0x50(%ecx), %xmm0
0x00414a82:	movdqa 0x60(%ecx), %xmm0
0x00414a87:	movdqa 0x70(%ecx), %xmm0
0x00414a8c:	leal %ecx, 0x80(%ecx)
0x00414a92:	decl %eax
0x00414a93:	jne 0x00414a65
0x00414a95:	testl %edx, %edx
0x00414a97:	je 55
0x00414a99:	movl %eax, %edx
0x00414a9b:	shrl %eax, $0x4<UINT8>
0x00414a9e:	je 15
0x00414aa0:	jmp 0x00414aa5
0x00414aa5:	movdqa (%ecx), %xmm0
0x00414aa9:	leal %ecx, 0x10(%ecx)
0x00414aac:	decl %eax
0x00414aad:	jne 0x00414aa5
0x00414aaf:	andl %edx, $0xf<UINT8>
0x00414ab2:	je 28
0x00414ab4:	movl %eax, %edx
0x00414ab6:	xorl %ebx, %ebx
0x00414ab8:	shrl %edx, $0x2<UINT8>
0x00414abb:	je 8
0x00414abd:	movl (%ecx), %ebx
0x00414abf:	leal %ecx, 0x4(%ecx)
0x00414ac2:	decl %edx
0x00414ac3:	jne 0x00414abd
0x00414ac5:	andl %eax, $0x3<UINT8>
0x00414ac8:	je 0x00414ad0
0x00414aca:	movb (%ecx), %bl
0x00414acc:	incl %ecx
0x00414acd:	decl %eax
0x00414ace:	jne -6
0x00414ad0:	popl %ebx
0x00414ad1:	popl %eax
0x00414ad2:	ret

0x00416c41:	xorl %edx, %edx
0x00416c43:	incl %edx
0x00416c44:	addl %esp, $0xc<UINT8>
0x00416c47:	movl 0x4(%ebx), %edi
0x00416c4a:	movl 0xc(%ebx), %esi
0x00416c4d:	cmpl -24(%ebp), %edx
0x00416c50:	jbe 252
0x00416c56:	cmpb -18(%ebp), $0x0<UINT8>
0x00416c5a:	je 0x00416d33
0x00416d33:	leal %eax, 0x1e(%ebx)
0x00416d36:	movl %ecx, $0xfe<UINT32>
0x00416d3b:	orb (%eax), $0x8<UINT8>
0x00416d3e:	incl %eax
0x00416d3f:	decl %ecx
0x00416d40:	jne 0x00416d3b
0x00416d42:	movl %eax, 0x4(%ebx)
0x00416d45:	call 0x0041685b
0x0041685b:	subl %eax, $0x3a4<UINT32>
0x00416860:	je 34
0x00416862:	subl %eax, $0x4<UINT8>
0x00416865:	je 23
0x00416867:	subl %eax, $0xd<UINT8>
0x0041686a:	je 12
0x0041686c:	decl %eax
0x0041686d:	je 3
0x0041686f:	xorl %eax, %eax
0x00416871:	ret

0x00416d4a:	movl 0xc(%ebx), %eax
0x00416d4d:	movl 0x8(%ebx), %edx
0x00416d50:	jmp 0x00416d55
0x00416d55:	xorl %eax, %eax
0x00416d57:	movzwl %ecx, %ax
0x00416d5a:	movl %eax, %ecx
0x00416d5c:	shll %ecx, $0x10<UINT8>
0x00416d5f:	orl %eax, %ecx
0x00416d61:	leal %edi, 0x10(%ebx)
0x00416d64:	stosl %es:(%edi), %eax
0x00416d65:	stosl %es:(%edi), %eax
0x00416d66:	stosl %es:(%edi), %eax
0x00416d67:	jmp 0x00416d10
0x00416d10:	movl %esi, %ebx
0x00416d12:	call 0x004168ee
0x004168ee:	movl %edi, %edi
0x004168f0:	pushl %ebp
0x004168f1:	movl %ebp, %esp
0x004168f3:	subl %esp, $0x51c<UINT32>
0x004168f9:	movl %eax, 0x424308
0x004168fe:	xorl %eax, %ebp
0x00416900:	movl -4(%ebp), %eax
0x00416903:	pushl %ebx
0x00416904:	pushl %edi
0x00416905:	leal %eax, -1304(%ebp)
0x0041690b:	pushl %eax
0x0041690c:	pushl 0x4(%esi)
0x0041690f:	call GetCPInfo@KERNEL32.DLL
0x00416915:	movl %edi, $0x100<UINT32>
0x0041691a:	testl %eax, %eax
0x0041691c:	je 252
0x00416922:	xorl %eax, %eax
0x00416924:	movb -260(%ebp,%eax), %al
0x0041692b:	incl %eax
0x0041692c:	cmpl %eax, %edi
0x0041692e:	jb 0x00416924
0x00416930:	movb %al, -1298(%ebp)
0x00416936:	movb -260(%ebp), $0x20<UINT8>
0x0041693d:	testb %al, %al
0x0041693f:	je 0x00416971
0x00416971:	pushl $0x0<UINT8>
0x00416973:	pushl 0xc(%esi)
0x00416976:	leal %eax, -1284(%ebp)
0x0041697c:	pushl 0x4(%esi)
0x0041697f:	pushl %eax
0x00416980:	pushl %edi
0x00416981:	leal %eax, -260(%ebp)
0x00416987:	pushl %eax
0x00416988:	pushl $0x1<UINT8>
0x0041698a:	pushl $0x0<UINT8>
0x0041698c:	call 0x00419df3
0x00419df3:	movl %edi, %edi
0x00419df5:	pushl %ebp
0x00419df6:	movl %ebp, %esp
0x00419df8:	subl %esp, $0x10<UINT8>
0x00419dfb:	pushl 0x8(%ebp)
0x00419dfe:	leal %ecx, -16(%ebp)
0x00419e01:	call 0x00411942
0x00419e06:	pushl 0x24(%ebp)
0x00419e09:	leal %eax, -16(%ebp)
0x00419e0c:	pushl 0x1c(%ebp)
0x00419e0f:	pushl 0x18(%ebp)
0x00419e12:	pushl 0x14(%ebp)
0x00419e15:	pushl 0x10(%ebp)
0x00419e18:	pushl 0xc(%ebp)
0x00419e1b:	pushl %eax
0x00419e1c:	call 0x00419d0c
0x00419d0c:	movl %edi, %edi
0x00419d0e:	pushl %ebp
0x00419d0f:	movl %ebp, %esp
0x00419d11:	pushl %ecx
0x00419d12:	pushl %ecx
0x00419d13:	movl %eax, 0x424308
0x00419d18:	xorl %eax, %ebp
0x00419d1a:	movl -4(%ebp), %eax
0x00419d1d:	pushl %ebx
0x00419d1e:	xorl %ebx, %ebx
0x00419d20:	pushl %esi
0x00419d21:	pushl %edi
0x00419d22:	movl -8(%ebp), %ebx
0x00419d25:	cmpl 0x1c(%ebp), %ebx
0x00419d28:	jne 0x00419d35
0x00419d35:	movl %esi, 0x41e098
0x00419d3b:	xorl %eax, %eax
0x00419d3d:	cmpl 0x20(%ebp), %ebx
0x00419d40:	pushl %ebx
0x00419d41:	pushl %ebx
0x00419d42:	pushl 0x14(%ebp)
0x00419d45:	setne %al
0x00419d48:	pushl 0x10(%ebp)
0x00419d4b:	leal %eax, 0x1(,%eax,8)
0x00419d52:	pushl %eax
0x00419d53:	pushl 0x1c(%ebp)
0x00419d56:	call MultiByteToWideChar@KERNEL32.DLL
MultiByteToWideChar@KERNEL32.DLL: API Node	
0x00419d58:	movl %edi, %eax
0x00419d5a:	cmpl %edi, %ebx
0x00419d5c:	jne 0x00419d62
0x00419d62:	jle 60
0x00419d64:	cmpl %edi, $0x7ffffff0<UINT32>
0x00419d6a:	ja 52
0x00419d6c:	leal %eax, 0x8(%edi,%edi)
0x00419d70:	cmpl %eax, $0x400<UINT32>
0x00419d75:	ja 19
0x00419d77:	call 0x0041bfb0
0x0041bfb0:	pushl %ecx
0x0041bfb1:	leal %ecx, 0x8(%esp)
0x0041bfb5:	subl %ecx, %eax
0x0041bfb7:	andl %ecx, $0xf<UINT8>
0x0041bfba:	addl %eax, %ecx
0x0041bfbc:	sbbl %ecx, %ecx
0x0041bfbe:	orl %eax, %ecx
0x0041bfc0:	popl %ecx
0x0041bfc1:	jmp 0x00411eb0
0x00411eb0:	pushl %ecx
0x00411eb1:	leal %ecx, 0x4(%esp)
0x00411eb5:	subl %ecx, %eax
0x00411eb7:	sbbl %eax, %eax
0x00411eb9:	notl %eax
0x00411ebb:	andl %ecx, %eax
0x00411ebd:	movl %eax, %esp
0x00411ebf:	andl %eax, $0xfffff000<UINT32>
0x00411ec4:	cmpl %ecx, %eax
0x00411ec6:	jb 10
0x00411ec8:	movl %eax, %ecx
0x00411eca:	popl %ecx
0x00411ecb:	xchgl %esp, %eax
0x00411ecc:	movl %eax, (%eax)
0x00411ece:	movl (%esp), %eax
0x00411ed1:	ret

0x00419d7c:	movl %eax, %esp
0x00419d7e:	cmpl %eax, %ebx
0x00419d80:	je 28
0x00419d82:	movl (%eax), $0xcccc<UINT32>
0x00419d88:	jmp 0x00419d9b
0x00419d9b:	addl %eax, $0x8<UINT8>
0x00419d9e:	movl %ebx, %eax
0x00419da0:	testl %ebx, %ebx
0x00419da2:	je -70
0x00419da4:	leal %eax, (%edi,%edi)
0x00419da7:	pushl %eax
0x00419da8:	pushl $0x0<UINT8>
0x00419daa:	pushl %ebx
0x00419dab:	call 0x004104c0
0x00419db0:	addl %esp, $0xc<UINT8>
0x00419db3:	pushl %edi
0x00419db4:	pushl %ebx
0x00419db5:	pushl 0x14(%ebp)
0x00419db8:	pushl 0x10(%ebp)
0x00419dbb:	pushl $0x1<UINT8>
0x00419dbd:	pushl 0x1c(%ebp)
0x00419dc0:	call MultiByteToWideChar@KERNEL32.DLL
0x00419dc2:	testl %eax, %eax
0x00419dc4:	je 17
0x00419dc6:	pushl 0x18(%ebp)
0x00419dc9:	pushl %eax
0x00419dca:	pushl %ebx
0x00419dcb:	pushl 0xc(%ebp)
0x00419dce:	call GetStringTypeW@KERNEL32.DLL
GetStringTypeW@KERNEL32.DLL: API Node	
0x00419dd4:	movl -8(%ebp), %eax
0x00419dd7:	pushl %ebx
0x00419dd8:	call 0x00419abf
0x00419abf:	movl %edi, %edi
0x00419ac1:	pushl %ebp
0x00419ac2:	movl %ebp, %esp
0x00419ac4:	movl %eax, 0x8(%ebp)
0x00419ac7:	testl %eax, %eax
0x00419ac9:	je 18
0x00419acb:	subl %eax, $0x8<UINT8>
0x00419ace:	cmpl (%eax), $0xdddd<UINT32>
0x00419ad4:	jne 0x00419add
0x00419add:	popl %ebp
0x00419ade:	ret

0x00419ddd:	movl %eax, -8(%ebp)
0x00419de0:	popl %ecx
0x00419de1:	leal %esp, -20(%ebp)
0x00419de4:	popl %edi
0x00419de5:	popl %esi
0x00419de6:	popl %ebx
0x00419de7:	movl %ecx, -4(%ebp)
0x00419dea:	xorl %ecx, %ebp
0x00419dec:	call 0x004104b1
0x004104b1:	cmpl %ecx, 0x424308
0x004104b7:	jne 2
0x004104b9:	rep ret

0x00419df1:	leave
0x00419df2:	ret

0x00419e21:	addl %esp, $0x1c<UINT8>
0x00419e24:	cmpb -4(%ebp), $0x0<UINT8>
0x00419e28:	je 7
0x00419e2a:	movl %ecx, -8(%ebp)
0x00419e2d:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00419e31:	leave
0x00419e32:	ret

0x00416991:	xorl %ebx, %ebx
0x00416993:	pushl %ebx
0x00416994:	pushl 0x4(%esi)
0x00416997:	leal %eax, -516(%ebp)
0x0041699d:	pushl %edi
0x0041699e:	pushl %eax
0x0041699f:	pushl %edi
0x004169a0:	leal %eax, -260(%ebp)
0x004169a6:	pushl %eax
0x004169a7:	pushl %edi
0x004169a8:	pushl 0xc(%esi)
0x004169ab:	pushl %ebx
0x004169ac:	call 0x00419cc6
0x00419cc6:	movl %edi, %edi
0x00419cc8:	pushl %ebp
0x00419cc9:	movl %ebp, %esp
0x00419ccb:	subl %esp, $0x10<UINT8>
0x00419cce:	pushl 0x8(%ebp)
0x00419cd1:	leal %ecx, -16(%ebp)
0x00419cd4:	call 0x00411942
0x00419cd9:	pushl 0x28(%ebp)
0x00419cdc:	leal %eax, -16(%ebp)
0x00419cdf:	pushl 0x24(%ebp)
0x00419ce2:	pushl 0x20(%ebp)
0x00419ce5:	pushl 0x1c(%ebp)
0x00419ce8:	pushl 0x18(%ebp)
0x00419ceb:	pushl 0x14(%ebp)
0x00419cee:	pushl 0x10(%ebp)
0x00419cf1:	pushl 0xc(%ebp)
0x00419cf4:	pushl %eax
0x00419cf5:	call 0x00419adf
0x00419adf:	movl %edi, %edi
0x00419ae1:	pushl %ebp
0x00419ae2:	movl %ebp, %esp
0x00419ae4:	subl %esp, $0x10<UINT8>
0x00419ae7:	movl %eax, 0x424308
0x00419aec:	xorl %eax, %ebp
0x00419aee:	movl -4(%ebp), %eax
0x00419af1:	movl %edx, 0x18(%ebp)
0x00419af4:	pushl %ebx
0x00419af5:	xorl %ebx, %ebx
0x00419af7:	pushl %esi
0x00419af8:	pushl %edi
0x00419af9:	cmpl %edx, %ebx
0x00419afb:	jle 0x00419b1c
0x00419b1c:	movl -8(%ebp), %ebx
0x00419b1f:	cmpl 0x24(%ebp), %ebx
0x00419b22:	jne 0x00419b2f
0x00419b2f:	movl %esi, 0x41e098
0x00419b35:	xorl %eax, %eax
0x00419b37:	cmpl 0x28(%ebp), %ebx
0x00419b3a:	pushl %ebx
0x00419b3b:	pushl %ebx
0x00419b3c:	pushl 0x18(%ebp)
0x00419b3f:	setne %al
0x00419b42:	pushl 0x14(%ebp)
0x00419b45:	leal %eax, 0x1(,%eax,8)
0x00419b4c:	pushl %eax
0x00419b4d:	pushl 0x24(%ebp)
0x00419b50:	call MultiByteToWideChar@KERNEL32.DLL
0x00419b52:	movl %edi, %eax
0x00419b54:	movl -16(%ebp), %edi
0x00419b57:	cmpl %edi, %ebx
0x00419b59:	jne 7
0x00419b5b:	xorl %eax, %eax
0x00419b5d:	jmp 0x00419cb4
0x00419cb4:	leal %esp, -28(%ebp)
0x00419cb7:	popl %edi
0x00419cb8:	popl %esi
0x00419cb9:	popl %ebx
0x00419cba:	movl %ecx, -4(%ebp)
0x00419cbd:	xorl %ecx, %ebp
0x00419cbf:	call 0x004104b1
0x00419cc4:	leave
0x00419cc5:	ret

0x00419cfa:	addl %esp, $0x24<UINT8>
0x00419cfd:	cmpb -4(%ebp), $0x0<UINT8>
0x00419d01:	je 7
0x00419d03:	movl %ecx, -8(%ebp)
0x00419d06:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00419d0a:	leave
0x00419d0b:	ret

0x004169b1:	addl %esp, $0x44<UINT8>
0x004169b4:	pushl %ebx
0x004169b5:	pushl 0x4(%esi)
0x004169b8:	leal %eax, -772(%ebp)
0x004169be:	pushl %edi
0x004169bf:	pushl %eax
0x004169c0:	pushl %edi
0x004169c1:	leal %eax, -260(%ebp)
0x004169c7:	pushl %eax
0x004169c8:	pushl $0x200<UINT32>
0x004169cd:	pushl 0xc(%esi)
0x004169d0:	pushl %ebx
0x004169d1:	call 0x00419cc6
0x004169d6:	addl %esp, $0x24<UINT8>
0x004169d9:	xorl %eax, %eax
0x004169db:	movzwl %ecx, -1284(%ebp,%eax,2)
0x004169e3:	testb %cl, $0x1<UINT8>
0x004169e6:	je 0x004169f6
0x004169f6:	testb %cl, $0x2<UINT8>
0x004169f9:	je 0x00416a10
0x00416a10:	movb 0x11d(%esi,%eax), %bl
0x00416a17:	incl %eax
0x00416a18:	cmpl %eax, %edi
0x00416a1a:	jb -65
0x00416a1c:	jmp 0x00416a70
0x00416a70:	movl %ecx, -4(%ebp)
0x00416a73:	popl %edi
0x00416a74:	xorl %ecx, %ebp
0x00416a76:	popl %ebx
0x00416a77:	call 0x004104b1
0x00416a7c:	leave
0x00416a7d:	ret

0x00416d17:	jmp 0x00416bd0
0x00416bd0:	xorl %eax, %eax
0x00416bd2:	jmp 0x00416d78
0x00416d78:	movl %ecx, -4(%ebp)
0x00416d7b:	popl %edi
0x00416d7c:	popl %esi
0x00416d7d:	xorl %ecx, %ebp
0x00416d7f:	popl %ebx
0x00416d80:	call 0x004104b1
0x00416d85:	leave
0x00416d86:	ret

0x00416dea:	popl %ecx
0x00416deb:	popl %ecx
0x00416dec:	movl -32(%ebp), %eax
0x00416def:	testl %eax, %eax
0x00416df1:	jne 252
0x00416df7:	movl %esi, -36(%ebp)
0x00416dfa:	pushl 0x68(%esi)
0x00416dfd:	call InterlockedDecrement@KERNEL32.DLL
InterlockedDecrement@KERNEL32.DLL: API Node	
0x00416e03:	testl %eax, %eax
0x00416e05:	jne 17
0x00416e07:	movl %eax, 0x68(%esi)
0x00416e0a:	cmpl %eax, $0x4248b0<UINT32>
0x00416e0f:	je 0x00416e18
0x00416e18:	movl 0x68(%esi), %ebx
0x00416e1b:	pushl %ebx
0x00416e1c:	movl %edi, 0x41e088
0x00416e22:	call InterlockedIncrement@KERNEL32.DLL
0x00416e24:	testb 0x70(%esi), $0x2<UINT8>
0x00416e28:	jne 234
0x00416e2e:	testb 0x424dd0, $0x1<UINT8>
0x00416e35:	jne 221
0x00416e3b:	pushl $0xd<UINT8>
0x00416e3d:	call 0x004166f5
0x00416e42:	popl %ecx
0x00416e43:	andl -4(%ebp), $0x0<UINT8>
0x00416e47:	movl %eax, 0x4(%ebx)
0x00416e4a:	movl 0x426004, %eax
0x00416e4f:	movl %eax, 0x8(%ebx)
0x00416e52:	movl 0x426008, %eax
0x00416e57:	movl %eax, 0xc(%ebx)
0x00416e5a:	movl 0x42600c, %eax
0x00416e5f:	xorl %eax, %eax
0x00416e61:	movl -28(%ebp), %eax
0x00416e64:	cmpl %eax, $0x5<UINT8>
0x00416e67:	jnl 0x00416e79
0x00416e69:	movw %cx, 0x10(%ebx,%eax,2)
0x00416e6e:	movw 0x425ff8(,%eax,2), %cx
0x00416e76:	incl %eax
0x00416e77:	jmp 0x00416e61
0x00416e79:	xorl %eax, %eax
0x00416e7b:	movl -28(%ebp), %eax
0x00416e7e:	cmpl %eax, $0x101<UINT32>
0x00416e83:	jnl 0x00416e92
0x00416e85:	movb %cl, 0x1c(%eax,%ebx)
0x00416e89:	movb 0x424ad0(%eax), %cl
0x00416e8f:	incl %eax
0x00416e90:	jmp 0x00416e7b
0x00416e92:	xorl %eax, %eax
0x00416e94:	movl -28(%ebp), %eax
0x00416e97:	cmpl %eax, $0x100<UINT32>
0x00416e9c:	jnl 0x00416eae
0x00416e9e:	movb %cl, 0x11d(%eax,%ebx)
0x00416ea5:	movb 0x424bd8(%eax), %cl
0x00416eab:	incl %eax
0x00416eac:	jmp 0x00416e94
0x00416eae:	pushl 0x424cd8
0x00416eb4:	call InterlockedDecrement@KERNEL32.DLL
0x00416eba:	testl %eax, %eax
0x00416ebc:	jne 0x00416ed1
0x00416ed1:	movl 0x424cd8, %ebx
0x00416ed7:	pushl %ebx
0x00416ed8:	call InterlockedIncrement@KERNEL32.DLL
0x00416eda:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00416ee1:	call 0x00416ee8
0x00416ee8:	pushl $0xd<UINT8>
0x00416eea:	call 0x0041661c
0x00416eef:	popl %ecx
0x00416ef0:	ret

0x00416ee6:	jmp 0x00416f18
0x00416f18:	movl %eax, -32(%ebp)
0x00416f1b:	call 0x00414795
0x00416f20:	ret

0x00416f31:	popl %ecx
0x00416f32:	movl 0x4266b0, $0x1<UINT32>
0x00416f3c:	xorl %eax, %eax
0x00416f3e:	ret

0x00417705:	pushl $0x4176c3<UINT32>
0x0041770a:	call SetUnhandledExceptionFilter@KERNEL32.DLL
SetUnhandledExceptionFilter@KERNEL32.DLL: API Node	
0x00417710:	xorl %eax, %eax
0x00417712:	ret

0x004125b1:	popl %esi
0x004125b2:	popl %ebp
0x004125b3:	ret

0x004125ef:	popl %ecx
0x004125f0:	popl %ecx
0x004125f1:	testl %eax, %eax
0x004125f3:	jne 84
0x004125f5:	pushl %esi
0x004125f6:	pushl %edi
0x004125f7:	pushl $0x417c01<UINT32>
0x004125fc:	call 0x00411c7a
0x00411c7a:	movl %edi, %edi
0x00411c7c:	pushl %ebp
0x00411c7d:	movl %ebp, %esp
0x00411c7f:	pushl 0x8(%ebp)
0x00411c82:	call 0x00411c3e
0x00411c3e:	pushl $0xc<UINT8>
0x00411c40:	pushl $0x4225d0<UINT32>
0x00411c45:	call 0x00414750
0x00411c4a:	call 0x0041254b
0x0041254b:	pushl $0x8<UINT8>
0x0041254d:	call 0x004166f5
0x00412552:	popl %ecx
0x00412553:	ret

0x00411c4f:	andl -4(%ebp), $0x0<UINT8>
0x00411c53:	pushl 0x8(%ebp)
0x00411c56:	call 0x00411b57
0x00411b57:	movl %edi, %edi
0x00411b59:	pushl %ebp
0x00411b5a:	movl %ebp, %esp
0x00411b5c:	pushl %ecx
0x00411b5d:	pushl %ebx
0x00411b5e:	pushl %esi
0x00411b5f:	movl %esi, 0x41e0bc
0x00411b65:	pushl %edi
0x00411b66:	pushl 0x4266ac
0x00411b6c:	call DecodePointer@KERNEL32.DLL
0x00411b6e:	pushl 0x4266a8
0x00411b74:	movl %ebx, %eax
0x00411b76:	movl -4(%ebp), %ebx
0x00411b79:	call DecodePointer@KERNEL32.DLL
0x00411b7b:	movl %esi, %eax
0x00411b7d:	cmpl %esi, %ebx
0x00411b7f:	jb 129
0x00411b85:	movl %edi, %esi
0x00411b87:	subl %edi, %ebx
0x00411b89:	leal %eax, 0x4(%edi)
0x00411b8c:	cmpl %eax, $0x4<UINT8>
0x00411b8f:	jb 117
0x00411b91:	pushl %ebx
0x00411b92:	call 0x00417318
0x00417318:	movl %edi, %edi
0x0041731a:	pushl %ebp
0x0041731b:	movl %ebp, %esp
0x0041731d:	cmpl 0x8(%ebp), $0x0<UINT8>
0x00417321:	jne 0x00417338
0x00417338:	pushl 0x8(%ebp)
0x0041733b:	pushl $0x0<UINT8>
0x0041733d:	pushl 0x425b48
0x00417343:	call HeapSize@KERNEL32.DLL
HeapSize@KERNEL32.DLL: API Node	
0x00417349:	popl %ebp
0x0041734a:	ret

0x00411b97:	movl %ebx, %eax
0x00411b99:	leal %eax, 0x4(%edi)
0x00411b9c:	popl %ecx
0x00411b9d:	cmpl %ebx, %eax
0x00411b9f:	jae 0x00411be9
0x00411be9:	pushl 0x8(%ebp)
0x00411bec:	movl %edi, 0x41e0c0
0x00411bf2:	call EncodePointer@KERNEL32.DLL
0x00411bf4:	movl (%esi), %eax
0x00411bf6:	addl %esi, $0x4<UINT8>
0x00411bf9:	pushl %esi
0x00411bfa:	call EncodePointer@KERNEL32.DLL
0x00411bfc:	movl 0x4266a8, %eax
0x00411c01:	movl %eax, 0x8(%ebp)
0x00411c04:	jmp 0x00411c08
0x00411c08:	popl %edi
0x00411c09:	popl %esi
0x00411c0a:	popl %ebx
0x00411c0b:	leave
0x00411c0c:	ret

0x00411c5b:	popl %ecx
0x00411c5c:	movl -28(%ebp), %eax
0x00411c5f:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00411c66:	call 0x00411c74
0x00411c74:	call 0x00412554
0x00412554:	pushl $0x8<UINT8>
0x00412556:	call 0x0041661c
0x0041255b:	popl %ecx
0x0041255c:	ret

0x00411c79:	ret

0x00411c6b:	movl %eax, -28(%ebp)
0x00411c6e:	call 0x00414795
0x00411c73:	ret

0x00411c87:	negl %eax
0x00411c89:	sbbl %eax, %eax
0x00411c8b:	negl %eax
0x00411c8d:	popl %ecx
0x00411c8e:	decl %eax
0x00411c8f:	popl %ebp
0x00411c90:	ret

0x00412601:	movl %eax, $0x41e2f4<UINT32>
0x00412606:	movl %esi, $0x41e33c<UINT32>
0x0041260b:	popl %ecx
0x0041260c:	movl %edi, %eax
0x0041260e:	cmpl %eax, %esi
0x00412610:	jae 15
0x00412612:	movl %eax, (%edi)
0x00412614:	testl %eax, %eax
0x00412616:	je 0x0041261a
0x0041261a:	addl %edi, $0x4<UINT8>
0x0041261d:	cmpl %edi, %esi
0x0041261f:	jb 0x00412612
0x00412618:	call 0x0041d376
0x0041d34a:	movl %ecx, $0x42542c<UINT32>
0x0041d34f:	call 0x0040fb80
0x0040fb80:	movl %edi, %edi
0x0040fb82:	pushl %esi
0x0040fb83:	movl %esi, %ecx
0x0040fb85:	call 0x0040fb43
0x0040fb43:	movl %edi, %edi
0x0040fb45:	pushl %esi
0x0040fb46:	movl %esi, %ecx
0x0040fb48:	pushl $0x18<UINT8>
0x0040fb4a:	leal %eax, 0x14(%esi)
0x0040fb4d:	pushl $0x0<UINT8>
0x0040fb4f:	pushl %eax
0x0040fb50:	call 0x004104c0
0x004104ec:	pushl %edi
0x004104ed:	movl %edi, %ecx
0x004104ef:	cmpl %edx, $0x4<UINT8>
0x004104f2:	jb 49
0x004104f4:	negl %ecx
0x004104f6:	andl %ecx, $0x3<UINT8>
0x004104f9:	je 0x00410507
0x00410507:	movl %ecx, %eax
0x00410509:	shll %eax, $0x8<UINT8>
0x0041050c:	addl %eax, %ecx
0x0041050e:	movl %ecx, %eax
0x00410510:	shll %eax, $0x10<UINT8>
0x00410513:	addl %eax, %ecx
0x00410515:	movl %ecx, %edx
0x00410517:	andl %edx, $0x3<UINT8>
0x0041051a:	shrl %ecx, $0x2<UINT8>
0x0041051d:	je 6
0x0041051f:	rep stosl %es:(%edi), %eax
0x00410521:	testl %edx, %edx
0x00410523:	je 0x0041052f
0x0041052f:	movl %eax, 0x8(%esp)
0x00410533:	popl %edi
0x00410534:	ret

0x0040fb55:	andl 0x2c(%esi), $0x0<UINT8>
0x0040fb59:	andl 0x30(%esi), $0x0<UINT8>
0x0040fb5d:	andl 0x34(%esi), $0x0<UINT8>
0x0040fb61:	addl %esp, $0xc<UINT8>
0x0040fb64:	movl %eax, %esi
0x0040fb66:	popl %esi
0x0040fb67:	ret

0x0040fb8a:	movl %eax, $0x400000<UINT32>
0x0040fb8f:	leal %ecx, 0x14(%esi)
0x0040fb92:	movl (%esi), $0x38<UINT32>
0x0040fb98:	movl 0x8(%esi), %eax
0x0040fb9b:	movl 0x4(%esi), %eax
0x0040fb9e:	movl 0xc(%esi), $0xa00<UINT32>
0x0040fba5:	movl 0x10(%esi), $0x41f37c<UINT32>
0x0040fbac:	call 0x0040bf90
0x0040bf90:	pushl %esi
0x0040bf91:	xorl %esi, %esi
0x0040bf93:	pushl %esi
0x0040bf94:	pushl %ecx
0x0040bf95:	call InitializeCriticalSectionAndSpinCount@KERNEL32.DLL
0x0040bf9b:	testl %eax, %eax
0x0040bf9d:	jne 0x0040bfb5
0x0040bfb5:	movl %eax, %esi
0x0040bfb7:	popl %esi
0x0040bfb8:	ret

0x0040fbb1:	testl %eax, %eax
0x0040fbb3:	jns 0x0040fbbc
0x0040fbbc:	movl %eax, %esi
0x0040fbbe:	popl %esi
0x0040fbbf:	ret

0x0041d354:	pushl $0x41d5a7<UINT32>
0x0041d359:	call 0x00411c7a
0x0041d35e:	popl %ecx
0x0041d35f:	ret

0x0041d360:	movl %ecx, $0x425468<UINT32>
0x0041d365:	call 0x0040fdf1
0x0040fdf1:	movl %edi, %edi
0x0040fdf3:	pushl %esi
0x0040fdf4:	movl %esi, %ecx
0x0040fdf6:	call 0x0040fd56
0x0040fd56:	movl %edi, %edi
0x0040fd58:	pushl %esi
0x0040fd59:	movl %esi, %ecx
0x0040fd5b:	pushl $0x18<UINT8>
0x0040fd5d:	leal %eax, 0x4(%esi)
0x0040fd60:	pushl $0x0<UINT8>
0x0040fd62:	pushl %eax
0x0040fd63:	call 0x004104c0
0x0040fd68:	andl 0x20(%esi), $0x0<UINT8>
0x0040fd6c:	andl 0x24(%esi), $0x0<UINT8>
0x0040fd70:	andl 0x28(%esi), $0x0<UINT8>
0x0040fd74:	addl %esp, $0xc<UINT8>
0x0040fd77:	movl %eax, %esi
0x0040fd79:	popl %esi
0x0040fd7a:	ret

0x0040fdfb:	pushl %esi
0x0040fdfc:	movl (%esi), $0x2c<UINT32>
0x0040fe02:	call 0x0040fd0f
0x0040fd0f:	movl %edi, %edi
0x0040fd11:	pushl %ebp
0x0040fd12:	movl %ebp, %esp
0x0040fd14:	movl %eax, 0x8(%ebp)
0x0040fd17:	testl %eax, %eax
0x0040fd19:	jne 0x0040fd22
0x0040fd22:	cmpl (%eax), $0x2c<UINT8>
0x0040fd25:	jne -12
0x0040fd27:	andl 0x1c(%eax), $0x0<UINT8>
0x0040fd2b:	leal %ecx, 0x4(%eax)
0x0040fd2e:	call 0x0040bf90
0x0040fd33:	popl %ebp
0x0040fd34:	ret $0x4<UINT16>

0x0040fe07:	testl %eax, %eax
0x0040fe09:	jns 0x0040fe15
0x0040fe15:	movl %eax, %esi
0x0040fe17:	popl %esi
0x0040fe18:	ret

0x0041d36a:	pushl $0x41d5b1<UINT32>
0x0041d36f:	call 0x00411c7a
0x0041d374:	popl %ecx
0x0041d375:	ret

0x0041d376:	movl %ecx, $0x425494<UINT32>
0x0041d37b:	call 0x0040fe76
0x0040fe76:	movl %edi, %edi
0x0040fe78:	pushl %esi
0x0040fe79:	movl %esi, %ecx
0x0040fe7b:	call 0x0040fe5d
0x0040fe5d:	movl %edi, %edi
0x0040fe5f:	pushl %esi
0x0040fe60:	movl %esi, %ecx
0x0040fe62:	pushl $0x18<UINT8>
0x0040fe64:	leal %eax, 0x10(%esi)
0x0040fe67:	pushl $0x0<UINT8>
0x0040fe69:	pushl %eax
0x0040fe6a:	call 0x004104c0
