0x004152a0:	pusha
0x004152a1:	movl %esi, $0x40e000<UINT32>
0x004152a6:	leal %edi, -53248(%esi)
0x004152ac:	pushl %edi
0x004152ad:	jmp 0x004152ba
0x004152ba:	movl %ebx, (%esi)
0x004152bc:	subl %esi, $0xfffffffc<UINT8>
0x004152bf:	adcl %ebx, %ebx
0x004152c1:	jb 0x004152b0
0x004152b0:	movb %al, (%esi)
0x004152b2:	incl %esi
0x004152b3:	movb (%edi), %al
0x004152b5:	incl %edi
0x004152b6:	addl %ebx, %ebx
0x004152b8:	jne 0x004152c1
0x004152c3:	movl %eax, $0x1<UINT32>
0x004152c8:	addl %ebx, %ebx
0x004152ca:	jne 0x004152d3
0x004152d3:	adcl %eax, %eax
0x004152d5:	addl %ebx, %ebx
0x004152d7:	jae 0x004152c8
0x004152d9:	jne 0x004152e4
0x004152e4:	xorl %ecx, %ecx
0x004152e6:	subl %eax, $0x3<UINT8>
0x004152e9:	jb 0x004152f8
0x004152eb:	shll %eax, $0x8<UINT8>
0x004152ee:	movb %al, (%esi)
0x004152f0:	incl %esi
0x004152f1:	xorl %eax, $0xffffffff<UINT8>
0x004152f4:	je 0x0041536a
0x004152f6:	movl %ebp, %eax
0x004152f8:	addl %ebx, %ebx
0x004152fa:	jne 0x00415303
0x00415303:	adcl %ecx, %ecx
0x00415305:	addl %ebx, %ebx
0x00415307:	jne 0x00415310
0x00415310:	adcl %ecx, %ecx
0x00415312:	jne 0x00415334
0x00415334:	cmpl %ebp, $0xfffff300<UINT32>
0x0041533a:	adcl %ecx, $0x1<UINT8>
0x0041533d:	leal %edx, (%edi,%ebp)
0x00415340:	cmpl %ebp, $0xfffffffc<UINT8>
0x00415343:	jbe 0x00415354
0x00415354:	movl %eax, (%edx)
0x00415356:	addl %edx, $0x4<UINT8>
0x00415359:	movl (%edi), %eax
0x0041535b:	addl %edi, $0x4<UINT8>
0x0041535e:	subl %ecx, $0x4<UINT8>
0x00415361:	ja 0x00415354
0x00415363:	addl %edi, %ecx
0x00415365:	jmp 0x004152b6
0x00415309:	movl %ebx, (%esi)
0x0041530b:	subl %esi, $0xfffffffc<UINT8>
0x0041530e:	adcl %ebx, %ebx
0x004152cc:	movl %ebx, (%esi)
0x004152ce:	subl %esi, $0xfffffffc<UINT8>
0x004152d1:	adcl %ebx, %ebx
0x00415314:	incl %ecx
0x00415315:	addl %ebx, %ebx
0x00415317:	jne 0x00415320
0x00415320:	adcl %ecx, %ecx
0x00415322:	addl %ebx, %ebx
0x00415324:	jae 0x00415315
0x00415326:	jne 0x00415331
0x00415331:	addl %ecx, $0x2<UINT8>
0x004152db:	movl %ebx, (%esi)
0x004152dd:	subl %esi, $0xfffffffc<UINT8>
0x004152e0:	adcl %ebx, %ebx
0x004152e2:	jae 0x004152c8
0x00415319:	movl %ebx, (%esi)
0x0041531b:	subl %esi, $0xfffffffc<UINT8>
0x0041531e:	adcl %ebx, %ebx
0x004152fc:	movl %ebx, (%esi)
0x004152fe:	subl %esi, $0xfffffffc<UINT8>
0x00415301:	adcl %ebx, %ebx
0x00415328:	movl %ebx, (%esi)
0x0041532a:	subl %esi, $0xfffffffc<UINT8>
0x0041532d:	adcl %ebx, %ebx
0x0041532f:	jae 0x00415315
0x00415345:	movb %al, (%edx)
0x00415347:	incl %edx
0x00415348:	movb (%edi), %al
0x0041534a:	incl %edi
0x0041534b:	decl %ecx
0x0041534c:	jne 0x00415345
0x0041534e:	jmp 0x004152b6
0x0041536a:	popl %esi
0x0041536b:	movl %edi, %esi
0x0041536d:	movl %ecx, $0x41c<UINT32>
0x00415372:	movb %al, (%edi)
0x00415374:	incl %edi
0x00415375:	subb %al, $0xffffffe8<UINT8>
0x00415377:	cmpb %al, $0x1<UINT8>
0x00415379:	ja 0x00415372
0x0041537b:	cmpb (%edi), $0x1<UINT8>
0x0041537e:	jne 0x00415372
0x00415380:	movl %eax, (%edi)
0x00415382:	movb %bl, 0x4(%edi)
0x00415385:	shrw %ax, $0x8<UINT8>
0x00415389:	roll %eax, $0x10<UINT8>
0x0041538c:	xchgb %ah, %al
0x0041538e:	subl %eax, %edi
0x00415390:	subb %bl, $0xffffffe8<UINT8>
0x00415393:	addl %eax, %esi
0x00415395:	movl (%edi), %eax
0x00415397:	addl %edi, $0x5<UINT8>
0x0041539a:	movb %al, %bl
0x0041539c:	loop 0x00415377
0x0041539e:	leal %edi, 0x13000(%esi)
0x004153a4:	movl %eax, (%edi)
0x004153a6:	orl %eax, %eax
0x004153a8:	je 0x004153ef
0x004153aa:	movl %ebx, 0x4(%edi)
0x004153ad:	leal %eax, 0x1604c(%eax,%esi)
0x004153b4:	addl %ebx, %esi
0x004153b6:	pushl %eax
0x004153b7:	addl %edi, $0x8<UINT8>
0x004153ba:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x004153c0:	xchgl %ebp, %eax
0x004153c1:	movb %al, (%edi)
0x004153c3:	incl %edi
0x004153c4:	orb %al, %al
0x004153c6:	je 0x004153a4
0x004153c8:	movl %ecx, %edi
0x004153ca:	jns 0x004153d3
0x004153d3:	pushl %edi
0x004153d4:	decl %eax
0x004153d5:	repn scasb %al, %es:(%edi)
0x004153d7:	pushl %ebp
0x004153d8:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x004153de:	orl %eax, %eax
0x004153e0:	je 7
0x004153e2:	movl (%ebx), %eax
0x004153e4:	addl %ebx, $0x4<UINT8>
0x004153e7:	jmp 0x004153c1
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x004153cc:	movzwl %eax, (%edi)
0x004153cf:	incl %edi
0x004153d0:	pushl %eax
0x004153d1:	incl %edi
0x004153d2:	movl %ecx, $0xaef24857<UINT32>
0x004153ef:	movl %ebp, 0x16168(%esi)
0x004153f5:	leal %edi, -4096(%esi)
0x004153fb:	movl %ebx, $0x1000<UINT32>
0x00415400:	pushl %eax
0x00415401:	pushl %esp
0x00415402:	pushl $0x4<UINT8>
0x00415404:	pushl %ebx
0x00415405:	pushl %edi
0x00415406:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00415408:	leal %eax, 0x217(%edi)
0x0041540e:	andb (%eax), $0x7f<UINT8>
0x00415411:	andb 0x28(%eax), $0x7f<UINT8>
0x00415415:	popl %eax
0x00415416:	pushl %eax
0x00415417:	pushl %esp
0x00415418:	pushl %eax
0x00415419:	pushl %ebx
0x0041541a:	pushl %edi
0x0041541b:	call VirtualProtect@kernel32.dll
0x0041541d:	popl %eax
0x0041541e:	popa
0x0041541f:	leal %eax, -128(%esp)
0x00415423:	pushl $0x0<UINT8>
0x00415425:	cmpl %esp, %eax
0x00415427:	jne 0x00415423
0x00415429:	subl %esp, $0xffffff80<UINT8>
0x0041542c:	jmp 0x0040acb2
0x0040acb2:	pushl $0x70<UINT8>
0x0040acb4:	pushl $0x40b378<UINT32>
0x0040acb9:	call 0x0040aea0
0x0040aea0:	pushl $0x40aef0<UINT32>
0x0040aea5:	movl %eax, %fs:0
0x0040aeab:	pushl %eax
0x0040aeac:	movl %fs:0, %esp
0x0040aeb3:	movl %eax, 0x10(%esp)
0x0040aeb7:	movl 0x10(%esp), %ebp
0x0040aebb:	leal %ebp, 0x10(%esp)
0x0040aebf:	subl %esp, %eax
0x0040aec1:	pushl %ebx
0x0040aec2:	pushl %esi
0x0040aec3:	pushl %edi
0x0040aec4:	movl %eax, -8(%ebp)
0x0040aec7:	movl -24(%ebp), %esp
0x0040aeca:	pushl %eax
0x0040aecb:	movl %eax, -4(%ebp)
0x0040aece:	movl -4(%ebp), $0xffffffff<UINT32>
0x0040aed5:	movl -8(%ebp), %eax
0x0040aed8:	ret

0x0040acbe:	xorl %ebx, %ebx
0x0040acc0:	pushl %ebx
0x0040acc1:	movl %edi, 0x40b050
0x0040acc7:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x0040acc9:	cmpw (%eax), $0x5a4d<UINT16>
0x0040acce:	jne 31
0x0040acd0:	movl %ecx, 0x3c(%eax)
0x0040acd3:	addl %ecx, %eax
0x0040acd5:	cmpl (%ecx), $0x4550<UINT32>
0x0040acdb:	jne 18
0x0040acdd:	movzwl %eax, 0x18(%ecx)
0x0040ace1:	cmpl %eax, $0x10b<UINT32>
0x0040ace6:	je 0x0040ad07
0x0040ad07:	cmpl 0x74(%ecx), $0xe<UINT8>
0x0040ad0b:	jbe -30
0x0040ad0d:	xorl %eax, %eax
0x0040ad0f:	cmpl 0xe8(%ecx), %ebx
0x0040ad15:	setne %al
0x0040ad18:	movl -28(%ebp), %eax
0x0040ad1b:	movl -4(%ebp), %ebx
0x0040ad1e:	pushl $0x2<UINT8>
0x0040ad20:	call __set_app_type@msvcrt.dll
__set_app_type@msvcrt.dll: API Node	
0x0040ad26:	popl %ecx
0x0040ad27:	orl 0x40f298, $0xffffffff<UINT8>
0x0040ad2e:	orl 0x40f29c, $0xffffffff<UINT8>
0x0040ad35:	call __p__fmode@msvcrt.dll
__p__fmode@msvcrt.dll: API Node	
0x0040ad3b:	movl %ecx, 0x40e22c
0x0040ad41:	movl (%eax), %ecx
0x0040ad43:	call __p__commode@msvcrt.dll
__p__commode@msvcrt.dll: API Node	
0x0040ad49:	movl %ecx, 0x40e228
0x0040ad4f:	movl (%eax), %ecx
0x0040ad51:	movl %eax, 0x40b2dc
0x0040ad56:	movl %eax, (%eax)
0x0040ad58:	movl 0x40f294, %eax
0x0040ad5d:	call 0x0040ae9c
0x0040ae9c:	xorl %eax, %eax
0x0040ae9e:	ret

0x0040ad62:	cmpl 0x40e000, %ebx
0x0040ad68:	jne 0x0040ad76
0x0040ad76:	call 0x0040ae8a
0x0040ae8a:	pushl $0x30000<UINT32>
0x0040ae8f:	pushl $0x10000<UINT32>
0x0040ae94:	call 0x0040aeea
0x0040aeea:	jmp _controlfp@msvcrt.dll
_controlfp@msvcrt.dll: API Node	
0x0040ae99:	popl %ecx
0x0040ae9a:	popl %ecx
0x0040ae9b:	ret

0x0040ad7b:	pushl $0x40b370<UINT32>
0x0040ad80:	pushl $0x40b36c<UINT32>
0x0040ad85:	call 0x0040ae84
0x0040ae84:	jmp _initterm@msvcrt.dll
_initterm@msvcrt.dll: API Node	
0x0040ad8a:	movl %eax, 0x40e224
0x0040ad8f:	movl -32(%ebp), %eax
0x0040ad92:	leal %eax, -32(%ebp)
0x0040ad95:	pushl %eax
0x0040ad96:	pushl 0x40e220
0x0040ad9c:	leal %eax, -36(%ebp)
0x0040ad9f:	pushl %eax
0x0040ada0:	leal %eax, -40(%ebp)
0x0040ada3:	pushl %eax
0x0040ada4:	leal %eax, -44(%ebp)
0x0040ada7:	pushl %eax
0x0040ada8:	call __getmainargs@msvcrt.dll
__getmainargs@msvcrt.dll: API Node	
0x0040adae:	movl -48(%ebp), %eax
0x0040adb1:	pushl $0x40b368<UINT32>
0x0040adb6:	pushl $0x40b354<UINT32>
0x0040adbb:	call 0x0040ae84
0x0040adc0:	addl %esp, $0x24<UINT8>
0x0040adc3:	movl %eax, 0x40b294
0x0040adc8:	movl %esi, (%eax)
0x0040adca:	movl -52(%ebp), %esi
0x0040adcd:	cmpb (%esi), $0x22<UINT8>
0x0040add0:	jne 58
0x0040add2:	incl %esi
0x0040add3:	movl -52(%ebp), %esi
0x0040add6:	movb %al, (%esi)
0x0040add8:	cmpb %al, %bl
0x0040adda:	je 4
0x0040addc:	cmpb %al, $0x22<UINT8>
0x0040adde:	jne 0x0040add2
0x0040ade0:	cmpb (%esi), $0x22<UINT8>
0x0040ade3:	jne 4
0x0040ade5:	incl %esi
0x0040ade6:	movl -52(%ebp), %esi
0x0040ade9:	movb %al, (%esi)
0x0040adeb:	cmpb %al, %bl
0x0040aded:	je 4
0x0040adef:	cmpb %al, $0x20<UINT8>
0x0040adf1:	jbe 0x0040ade5
0x0040adf3:	movl -76(%ebp), %ebx
0x0040adf6:	leal %eax, -120(%ebp)
0x0040adf9:	pushl %eax
0x0040adfa:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x0040ae00:	testb -76(%ebp), $0x1<UINT8>
0x0040ae04:	je 0x0040ae17
0x0040ae17:	pushl $0xa<UINT8>
0x0040ae19:	popl %eax
0x0040ae1a:	pushl %eax
0x0040ae1b:	pushl %esi
0x0040ae1c:	pushl %ebx
0x0040ae1d:	pushl %ebx
0x0040ae1e:	call GetModuleHandleA@KERNEL32.DLL
0x0040ae20:	pushl %eax
0x0040ae21:	call 0x004087f2
0x004087f2:	pushl %ebp
0x004087f3:	leal %ebp, -104(%esp)
0x004087f7:	subl %esp, $0x274<UINT32>
0x004087fd:	pushl %ebx
0x004087fe:	xorl %ebx, %ebx
0x00408800:	pushl %esi
0x00408801:	leal %eax, -524(%ebp)
0x00408807:	pushl %edi
0x00408808:	pushl %eax
0x00408809:	movl %eax, $0x214<UINT32>
0x0040880e:	movl 0x38(%ebp), $0x400<UINT32>
0x00408815:	movl 0x3c(%ebp), $0x100<UINT32>
0x0040881c:	movl 0x24(%ebp), %ebx
0x0040881f:	movl 0x28(%ebp), %ebx
0x00408822:	movl 0x30(%ebp), %ebx
0x00408825:	movl 0x34(%ebp), %ebx
0x00408828:	movl 0x40(%ebp), %ebx
0x0040882b:	movl 0x2c(%ebp), %ebx
0x0040882e:	movl 0x4c(%ebp), $0x20<UINT32>
0x00408835:	movl 0x44(%ebp), %ebx
0x00408838:	movl 0x50(%ebp), %ebx
0x0040883b:	movl 0x48(%ebp), %ebx
0x0040883e:	movl 0x54(%ebp), %ebx
0x00408841:	movl -524(%ebp), $0x40bad8<UINT32>
0x0040884b:	movl -60(%ebp), %ebx
0x0040884e:	call 0x00403ee2
0x00403ee2:	addl %eax, $0xfffffffc<UINT8>
0x00403ee5:	pushl %eax
0x00403ee6:	movl %eax, 0x8(%esp)
0x00403eea:	addl %eax, $0x4<UINT8>
0x00403eed:	pushl $0x0<UINT8>
0x00403eef:	pushl %eax
0x00403ef0:	call 0x0040ac3a
0x0040ac3a:	jmp memset@msvcrt.dll
memset@msvcrt.dll: API Node	
0x00403ef5:	addl %esp, $0xc<UINT8>
0x00403ef8:	ret

0x0023335e:	subl %eax, $0x2072616a<UINT32>
0x00233363:	boundl %esp, 0x2d(%ebp)
0x00233366:	jo 117
0x00233368:	insl %es:(%edi), %dx
0x00233369:	subl %eax, $0x6a2e3276<UINT32>
0x0023336e:	popa
0x0023336f:	jb 32
0x00233371:	popa
0x00233372:	jae 0x002333e1
0x002333e1:	addb (%ebx), %bh
0x0040aef0:	jmp _except_handler3@msvcrt.dll
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
