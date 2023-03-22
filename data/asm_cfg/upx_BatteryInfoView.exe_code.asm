0x00418370:	pusha
0x00418371:	movl %esi, $0x410000<UINT32>
0x00418376:	leal %edi, -61440(%esi)
0x0041837c:	pushl %edi
0x0041837d:	orl %ebp, $0xffffffff<UINT8>
0x00418380:	jmp 0x00418392
0x00418392:	movl %ebx, (%esi)
0x00418394:	subl %esi, $0xfffffffc<UINT8>
0x00418397:	adcl %ebx, %ebx
0x00418399:	jb 0x00418388
0x00418388:	movb %al, (%esi)
0x0041838a:	incl %esi
0x0041838b:	movb (%edi), %al
0x0041838d:	incl %edi
0x0041838e:	addl %ebx, %ebx
0x00418390:	jne 0x00418399
0x0041839b:	movl %eax, $0x1<UINT32>
0x004183a0:	addl %ebx, %ebx
0x004183a2:	jne 0x004183ab
0x004183ab:	adcl %eax, %eax
0x004183ad:	addl %ebx, %ebx
0x004183af:	jae 0x004183a0
0x004183b1:	jne 0x004183bc
0x004183bc:	xorl %ecx, %ecx
0x004183be:	subl %eax, $0x3<UINT8>
0x004183c1:	jb 0x004183d0
0x004183d0:	addl %ebx, %ebx
0x004183d2:	jne 0x004183db
0x004183db:	adcl %ecx, %ecx
0x004183dd:	addl %ebx, %ebx
0x004183df:	jne 0x004183e8
0x004183e8:	adcl %ecx, %ecx
0x004183ea:	jne 0x0041840c
0x0041840c:	cmpl %ebp, $0xfffff300<UINT32>
0x00418412:	adcl %ecx, $0x1<UINT8>
0x00418415:	leal %edx, (%edi,%ebp)
0x00418418:	cmpl %ebp, $0xfffffffc<UINT8>
0x0041841b:	jbe 0x0041842c
0x0041841d:	movb %al, (%edx)
0x0041841f:	incl %edx
0x00418420:	movb (%edi), %al
0x00418422:	incl %edi
0x00418423:	decl %ecx
0x00418424:	jne 0x0041841d
0x00418426:	jmp 0x0041838e
0x004183c3:	shll %eax, $0x8<UINT8>
0x004183c6:	movb %al, (%esi)
0x004183c8:	incl %esi
0x004183c9:	xorl %eax, $0xffffffff<UINT8>
0x004183cc:	je 0x00418442
0x004183ce:	movl %ebp, %eax
0x0041842c:	movl %eax, (%edx)
0x0041842e:	addl %edx, $0x4<UINT8>
0x00418431:	movl (%edi), %eax
0x00418433:	addl %edi, $0x4<UINT8>
0x00418436:	subl %ecx, $0x4<UINT8>
0x00418439:	ja 0x0041842c
0x0041843b:	addl %edi, %ecx
0x0041843d:	jmp 0x0041838e
0x004183a4:	movl %ebx, (%esi)
0x004183a6:	subl %esi, $0xfffffffc<UINT8>
0x004183a9:	adcl %ebx, %ebx
0x004183b3:	movl %ebx, (%esi)
0x004183b5:	subl %esi, $0xfffffffc<UINT8>
0x004183b8:	adcl %ebx, %ebx
0x004183ba:	jae 0x004183a0
0x004183e1:	movl %ebx, (%esi)
0x004183e3:	subl %esi, $0xfffffffc<UINT8>
0x004183e6:	adcl %ebx, %ebx
0x004183ec:	incl %ecx
0x004183ed:	addl %ebx, %ebx
0x004183ef:	jne 0x004183f8
0x004183f8:	adcl %ecx, %ecx
0x004183fa:	addl %ebx, %ebx
0x004183fc:	jae 0x004183ed
0x004183fe:	jne 0x00418409
0x00418409:	addl %ecx, $0x2<UINT8>
0x004183f1:	movl %ebx, (%esi)
0x004183f3:	subl %esi, $0xfffffffc<UINT8>
0x004183f6:	adcl %ebx, %ebx
0x00418400:	movl %ebx, (%esi)
0x00418402:	subl %esi, $0xfffffffc<UINT8>
0x00418405:	adcl %ebx, %ebx
0x00418407:	jae 0x004183ed
0x004183d4:	movl %ebx, (%esi)
0x004183d6:	subl %esi, $0xfffffffc<UINT8>
0x004183d9:	adcl %ebx, %ebx
0x00418442:	popl %esi
0x00418443:	movl %edi, %esi
0x00418445:	movl %ecx, $0x4a1<UINT32>
0x0041844a:	movb %al, (%edi)
0x0041844c:	incl %edi
0x0041844d:	subb %al, $0xffffffe8<UINT8>
0x0041844f:	cmpb %al, $0x1<UINT8>
0x00418451:	ja 0x0041844a
0x00418453:	cmpb (%edi), $0x1<UINT8>
0x00418456:	jne 0x0041844a
0x00418458:	movl %eax, (%edi)
0x0041845a:	movb %bl, 0x4(%edi)
0x0041845d:	shrw %ax, $0x8<UINT8>
0x00418461:	roll %eax, $0x10<UINT8>
0x00418464:	xchgb %ah, %al
0x00418466:	subl %eax, %edi
0x00418468:	subb %bl, $0xffffffe8<UINT8>
0x0041846b:	addl %eax, %esi
0x0041846d:	movl (%edi), %eax
0x0041846f:	addl %edi, $0x5<UINT8>
0x00418472:	movb %al, %bl
0x00418474:	loop 0x0041844f
0x00418476:	leal %edi, 0x16000(%esi)
0x0041847c:	movl %eax, (%edi)
0x0041847e:	orl %eax, %eax
0x00418480:	je 0x004184c7
0x00418482:	movl %ebx, 0x4(%edi)
0x00418485:	leal %eax, 0x19c68(%eax,%esi)
0x0041848c:	addl %ebx, %esi
0x0041848e:	pushl %eax
0x0041848f:	addl %edi, $0x8<UINT8>
0x00418492:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x00418498:	xchgl %ebp, %eax
0x00418499:	movb %al, (%edi)
0x0041849b:	incl %edi
0x0041849c:	orb %al, %al
0x0041849e:	je 0x0041847c
0x004184a0:	movl %ecx, %edi
0x004184a2:	jns 0x004184ab
0x004184ab:	pushl %edi
0x004184ac:	decl %eax
0x004184ad:	repn scasb %al, %es:(%edi)
0x004184af:	pushl %ebp
0x004184b0:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x004184b6:	orl %eax, %eax
0x004184b8:	je 7
0x004184ba:	movl (%ebx), %eax
0x004184bc:	addl %ebx, $0x4<UINT8>
0x004184bf:	jmp 0x00418499
GetProcAddress@KERNEL32.DLL: API Node	
0x004184a4:	movzwl %eax, (%edi)
0x004184a7:	incl %edi
0x004184a8:	pushl %eax
0x004184a9:	incl %edi
0x004184aa:	movl %ecx, $0xaef24857<UINT32>
0x004184c7:	movl %ebp, 0x19d68(%esi)
0x004184cd:	leal %edi, -4096(%esi)
0x004184d3:	movl %ebx, $0x1000<UINT32>
0x004184d8:	pushl %eax
0x004184d9:	pushl %esp
0x004184da:	pushl $0x4<UINT8>
0x004184dc:	pushl %ebx
0x004184dd:	pushl %edi
0x004184de:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x004184e0:	leal %eax, 0x20f(%edi)
0x004184e6:	andb (%eax), $0x7f<UINT8>
0x004184e9:	andb 0x28(%eax), $0x7f<UINT8>
0x004184ed:	popl %eax
0x004184ee:	pushl %eax
0x004184ef:	pushl %esp
0x004184f0:	pushl %eax
0x004184f1:	pushl %ebx
0x004184f2:	pushl %edi
0x004184f3:	call VirtualProtect@kernel32.dll
0x004184f5:	popl %eax
0x004184f6:	popa
0x004184f7:	leal %eax, -128(%esp)
0x004184fb:	pushl $0x0<UINT8>
0x004184fd:	cmpl %esp, %eax
0x004184ff:	jne 0x004184fb
0x00418501:	subl %esp, $0xffffff80<UINT8>
0x00418504:	jmp 0x0040be9a
0x0040be9a:	pushl $0x70<UINT8>
0x0040be9c:	pushl $0x40d3c0<UINT32>
0x0040bea1:	call 0x0040c0ac
0x0040c0ac:	pushl $0x40c0fc<UINT32>
0x0040c0b1:	movl %eax, %fs:0
0x0040c0b7:	pushl %eax
0x0040c0b8:	movl %fs:0, %esp
0x0040c0bf:	movl %eax, 0x10(%esp)
0x0040c0c3:	movl 0x10(%esp), %ebp
0x0040c0c7:	leal %ebp, 0x10(%esp)
0x0040c0cb:	subl %esp, %eax
0x0040c0cd:	pushl %ebx
0x0040c0ce:	pushl %esi
0x0040c0cf:	pushl %edi
0x0040c0d0:	movl %eax, -8(%ebp)
0x0040c0d3:	movl -24(%ebp), %esp
0x0040c0d6:	pushl %eax
0x0040c0d7:	movl %eax, -4(%ebp)
0x0040c0da:	movl -4(%ebp), $0xffffffff<UINT32>
0x0040c0e1:	movl -8(%ebp), %eax
0x0040c0e4:	ret

0x0040bea6:	xorl %edi, %edi
0x0040bea8:	pushl %edi
0x0040bea9:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x0040beaf:	cmpw (%eax), $0x5a4d<UINT16>
0x0040beb4:	jne 31
0x0040beb6:	movl %ecx, 0x3c(%eax)
0x0040beb9:	addl %ecx, %eax
0x0040bebb:	cmpl (%ecx), $0x4550<UINT32>
0x0040bec1:	jne 18
0x0040bec3:	movzwl %eax, 0x18(%ecx)
0x0040bec7:	cmpl %eax, $0x10b<UINT32>
0x0040becc:	je 0x0040beed
0x0040beed:	cmpl 0x74(%ecx), $0xe<UINT8>
0x0040bef1:	jbe -30
0x0040bef3:	xorl %eax, %eax
0x0040bef5:	cmpl 0xe8(%ecx), %edi
0x0040befb:	setne %al
0x0040befe:	movl -28(%ebp), %eax
0x0040bf01:	movl -4(%ebp), %edi
0x0040bf04:	pushl $0x2<UINT8>
0x0040bf06:	popl %ebx
0x0040bf07:	pushl %ebx
0x0040bf08:	call __set_app_type@msvcrt.dll
__set_app_type@msvcrt.dll: API Node	
0x0040bf0e:	popl %ecx
0x0040bf0f:	orl 0x4116e8, $0xffffffff<UINT8>
0x0040bf16:	orl 0x4116ec, $0xffffffff<UINT8>
0x0040bf1d:	call __p__fmode@msvcrt.dll
__p__fmode@msvcrt.dll: API Node	
0x0040bf23:	movl %ecx, 0x41033c
0x0040bf29:	movl (%eax), %ecx
0x0040bf2b:	call __p__commode@msvcrt.dll
__p__commode@msvcrt.dll: API Node	
0x0040bf31:	movl %ecx, 0x410338
0x0040bf37:	movl (%eax), %ecx
0x0040bf39:	movl %eax, 0x40d2c4
0x0040bf3e:	movl %eax, (%eax)
0x0040bf40:	movl 0x4116e4, %eax
0x0040bf45:	call 0x0040c0a8
0x0040c0a8:	xorl %eax, %eax
0x0040c0aa:	ret

0x0040bf4a:	cmpl 0x410000, %edi
0x0040bf50:	jne 0x0040bf5e
0x0040bf5e:	call 0x0040c096
0x0040c096:	pushl $0x30000<UINT32>
0x0040c09b:	pushl $0x10000<UINT32>
0x0040c0a0:	call 0x0040c0f6
0x0040c0f6:	jmp _controlfp@msvcrt.dll
_controlfp@msvcrt.dll: API Node	
0x0040c0a5:	popl %ecx
0x0040c0a6:	popl %ecx
0x0040c0a7:	ret

0x0040bf63:	pushl $0x40d39c<UINT32>
0x0040bf68:	pushl $0x40d398<UINT32>
0x0040bf6d:	call 0x0040c090
0x0040c090:	jmp _initterm@msvcrt.dll
_initterm@msvcrt.dll: API Node	
0x0040bf72:	movl %eax, 0x410334
0x0040bf77:	movl -32(%ebp), %eax
0x0040bf7a:	leal %eax, -32(%ebp)
0x0040bf7d:	pushl %eax
0x0040bf7e:	pushl 0x410330
0x0040bf84:	leal %eax, -36(%ebp)
0x0040bf87:	pushl %eax
0x0040bf88:	leal %eax, -40(%ebp)
0x0040bf8b:	pushl %eax
0x0040bf8c:	leal %eax, -44(%ebp)
0x0040bf8f:	pushl %eax
0x0040bf90:	call __wgetmainargs@msvcrt.dll
__wgetmainargs@msvcrt.dll: API Node	
0x0040bf96:	movl -48(%ebp), %eax
0x0040bf99:	pushl $0x40d394<UINT32>
0x0040bf9e:	pushl $0x40d380<UINT32>
0x0040bfa3:	call 0x0040c090
0x0040bfa8:	addl %esp, $0x24<UINT8>
0x0040bfab:	movl %eax, 0x40d2d4
0x0040bfb0:	movl %esi, (%eax)
0x0040bfb2:	cmpl %esi, %edi
0x0040bfb4:	jne 0x0040bfc4
0x0040bfc4:	movl -52(%ebp), %esi
0x0040bfc7:	cmpw (%esi), $0x22<UINT8>
0x0040bfcb:	jne 69
0x0040bfcd:	addl %esi, %ebx
0x0040bfcf:	movl -52(%ebp), %esi
0x0040bfd2:	movw %ax, (%esi)
0x0040bfd5:	cmpw %ax, %di
0x0040bfd8:	je 6
0x0040bfda:	cmpw %ax, $0x22<UINT16>
0x0040bfde:	jne 0x0040bfcd
0x0040bfe0:	cmpw (%esi), $0x22<UINT8>
0x0040bfe4:	jne 5
0x0040bfe6:	addl %esi, %ebx
0x0040bfe8:	movl -52(%ebp), %esi
0x0040bfeb:	movw %ax, (%esi)
0x0040bfee:	cmpw %ax, %di
0x0040bff1:	je 6
0x0040bff3:	cmpw %ax, $0x20<UINT16>
0x0040bff7:	jbe 0x0040bfe6
0x0040bff9:	movl -76(%ebp), %edi
0x0040bffc:	leal %eax, -120(%ebp)
0x0040bfff:	pushl %eax
0x0040c000:	call GetStartupInfoW@KERNEL32.DLL
GetStartupInfoW@KERNEL32.DLL: API Node	
0x0040c006:	testb -76(%ebp), $0x1<UINT8>
0x0040c00a:	je 0x0040c01f
0x0040c01f:	pushl $0xa<UINT8>
0x0040c021:	popl %eax
0x0040c022:	pushl %eax
0x0040c023:	pushl %esi
0x0040c024:	pushl %edi
0x0040c025:	pushl %edi
0x0040c026:	call GetModuleHandleA@KERNEL32.DLL
0x0040c02c:	pushl %eax
0x0040c02d:	call 0x0040a34c
0x0040a34c:	pushl %ebp
0x0040a34d:	movl %ebp, %esp
0x0040a34f:	subl %esp, $0x71c<UINT32>
0x0040a355:	call 0x004032bd
0x004032bd:	pushl %ebp
0x004032be:	movl %ebp, %esp
0x004032c0:	pushl %ecx
0x004032c1:	pushl %ecx
0x004032c2:	pushl %ebx
0x004032c3:	pushl %esi
0x004032c4:	pushl %edi
0x004032c5:	pushl $0x40d9f0<UINT32>
0x004032ca:	movl -8(%ebp), $0x8<UINT32>
0x004032d1:	movl -4(%ebp), $0xff<UINT32>
0x004032d8:	xorl %ebx, %ebx
0x004032da:	xorl %edi, %edi
0x004032dc:	call LoadLibraryW@KERNEL32.DLL
LoadLibraryW@KERNEL32.DLL: API Node	
0x004032e2:	movl %esi, %eax
0x004032e4:	testl %esi, %esi
0x004032e6:	je 40
0x004032e8:	pushl $0x40da0c<UINT32>
0x004032ed:	pushl %esi
0x004032ee:	call GetProcAddress@KERNEL32.DLL
0x004032f4:	testl %eax, %eax
0x004032f6:	je 9
0x004032f8:	leal %ecx, -8(%ebp)
0x004032fb:	pushl %ecx
0x004032fc:	incl %edi
0x004032fd:	call InitCommonControlsEx@comctl32.dll
InitCommonControlsEx@comctl32.dll: API Node	
0x004032ff:	movl %ebx, %eax
0x00403301:	pushl %esi
0x00403302:	call FreeLibrary@KERNEL32.DLL
FreeLibrary@KERNEL32.DLL: API Node	
0x00403308:	testl %edi, %edi
0x0040330a:	je 4
0x0040330c:	movl %eax, %ebx
0x0040330e:	jmp 0x00403319
0x00403319:	testl %eax, %eax
0x0040331b:	popl %edi
0x0040331c:	popl %esi
0x0040331d:	popl %ebx
0x0040331e:	jne 0x00403337
0x00403320:	pushl $0x30<UINT8>
0x00403337:	xorl %eax, %eax
0x00403339:	incl %eax
0x0040333a:	leave
0x0040333b:	ret

0x0040a35a:	testl %eax, %eax
0x0040a35c:	jne 0x0040a364
0x0040a364:	pushl %ebx
0x0040a365:	pushl %esi
0x0040a366:	pushl %edi
0x0040a367:	call 0x0040b5a9
0x0040b5a9:	cmpl 0x411218, $0x0<UINT8>
0x0040b5b0:	jne 37
0x0040b5b2:	pushl $0x40e4b0<UINT32>
0x0040b5b7:	call LoadLibraryW@KERNEL32.DLL
0x0040b5bd:	testl %eax, %eax
0x0040b5bf:	movl 0x411218, %eax
0x0040b5c4:	je 17
0x0040b5c6:	pushl $0x40e4c8<UINT32>
0x0040b5cb:	pushl %eax
0x0040b5cc:	call GetProcAddress@KERNEL32.DLL
0x0040b5d2:	movl 0x411214, %eax
0x0040b5d7:	ret

0x0040a36c:	pushl $0x8001<UINT32>
0x0040a371:	call SetErrorMode@KERNEL32.DLL
SetErrorMode@KERNEL32.DLL: API Node	
0x0040a377:	xorl %ebx, %ebx
0x0040a379:	pushl %ebx
0x0040a37a:	pushl $0x40b58e<UINT32>
0x0040a37f:	pushl %ebx
0x0040a380:	movl 0x410ac0, $0x11223344<UINT32>
0x0040a38a:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0040a390:	pushl %eax
0x0040a391:	call EnumResourceTypesW@KERNEL32.DLL
EnumResourceTypesW@KERNEL32.DLL: API Node	
0x0040a397:	leal %eax, -1820(%ebp)
0x0040a39d:	pushl %eax
0x0040a39e:	movl -32(%ebp), $0x400<UINT32>
0x0040a3a5:	movl -28(%ebp), $0x100<UINT32>
0x0040a3ac:	movl -52(%ebp), %ebx
0x0040a3af:	movl -48(%ebp), %ebx
0x0040a3b2:	movl -40(%ebp), %ebx
0x0040a3b5:	movl -36(%ebp), %ebx
0x0040a3b8:	movl -24(%ebp), %ebx
0x0040a3bb:	movl -44(%ebp), %ebx
0x0040a3be:	movl -12(%ebp), $0x20<UINT32>
0x0040a3c5:	movl -20(%ebp), %ebx
0x0040a3c8:	movl -8(%ebp), %ebx
0x0040a3cb:	movl -16(%ebp), %ebx
0x0040a3ce:	movl -4(%ebp), %ebx
0x0040a3d1:	call 0x0040a06a
0x0040a06a:	pushl %ebx
0x0040a06b:	pushl %ebp
0x0040a06c:	movl %ebp, 0xc(%esp)
0x0040a070:	pushl %esi
0x0040a071:	movl (%ebp), $0x40e1c8<UINT32>
0x0040a078:	pushl %edi
0x0040a079:	xorl %edi, %edi
0x0040a07b:	movl 0x240(%ebp), %edi
0x0040a081:	movl 0x270(%ebp), %edi
0x0040a087:	leal %eax, 0x6ac(%ebp)
0x0040a08d:	movl 0x690(%ebp), %edi
0x0040a093:	pushl $0x260<UINT32>
0x0040a098:	movl (%eax), $0x40e7d0<UINT32>
0x0040a09e:	movl 0x4(%eax), %edi
0x0040a0a1:	movl 0x8(%eax), %edi
0x0040a0a4:	movl 0x10(%eax), %edi
0x0040a0a7:	call 0x0040be34
0x0040be34:	jmp ??2@YAPAXI@Z@msvcrt.dll
??2@YAPAXI@Z@msvcrt.dll: API Node	
0x0040a0ac:	cmpl %eax, %edi
0x0040a0ae:	popl %ecx
0x0040a0af:	je 10
0x0040a0b1:	movl 0x24(%eax), %edi
0x0040a0b4:	movl 0x410ac4, %eax
0x0040a0b9:	jmp 0x0040a0bd
0x0040a0bd:	pushl $0x2fc<UINT32>
0x0040a0c2:	movl 0x694(%ebp), %eax
0x0040a0c8:	call 0x0040be34
0x0040a0cd:	movl %esi, %eax
0x0040a0cf:	cmpl %esi, %edi
0x0040a0d1:	popl %ecx
0x0040a0d2:	je 45
0x0040a0d4:	call 0x00406319
0x00406319:	pushl %ebx
0x0040631a:	pushl %edi
0x0040631b:	pushl %esi
0x0040631c:	movl %eax, $0x2dc<UINT32>
0x00406321:	movl (%esi), $0x40df00<UINT32>
0x00406327:	call 0x00404d57
0x00404d57:	addl %eax, $0xfffffffc<UINT8>
0x00404d5a:	pushl %eax
0x00404d5b:	movl %eax, 0x8(%esp)
0x00404d5f:	addl %eax, $0x4<UINT8>
0x00404d62:	pushl $0x0<UINT8>
0x00404d64:	pushl %eax
0x00404d65:	call 0x0040be0a
0x0040be0a:	jmp memset@msvcrt.dll
memset@msvcrt.dll: API Node	
0x00404d6a:	addl %esp, $0xc<UINT8>
0x00404d6d:	ret

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
0x00403322:	pushl $0x40da24<UINT32>
0x00403327:	pushl $0x40da30<UINT32>
0x0040332c:	pushl %eax
0x0040332d:	call MessageBoxW@USER32.dll
MessageBoxW@USER32.dll: API Node	
0x00403333:	xorl %eax, %eax
0x00403335:	leave
0x00403336:	ret

0x0040a35e:	incl %eax
0x0040a35f:	jmp 0x0040a515
0x0040a515:	leave
0x0040a516:	ret $0x10<UINT16>

0x0040c032:	movl %esi, %eax
0x0040c034:	movl -124(%ebp), %esi
0x0040c037:	cmpl -28(%ebp), %edi
0x0040c03a:	jne 7
0x0040c03c:	pushl %esi
0x0040c03d:	call exit@msvcrt.dll
exit@msvcrt.dll: Exit Node	
