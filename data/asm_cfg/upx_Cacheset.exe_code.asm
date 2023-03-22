0x00427480:	pusha
0x00427481:	movl %esi, $0x41f000<UINT32>
0x00427486:	leal %edi, -122880(%esi)
0x0042748c:	pushl %edi
0x0042748d:	jmp 0x0042749a
0x0042749a:	movl %ebx, (%esi)
0x0042749c:	subl %esi, $0xfffffffc<UINT8>
0x0042749f:	adcl %ebx, %ebx
0x004274a1:	jb 0x00427490
0x00427490:	movb %al, (%esi)
0x00427492:	incl %esi
0x00427493:	movb (%edi), %al
0x00427495:	incl %edi
0x00427496:	addl %ebx, %ebx
0x00427498:	jne 0x004274a1
0x004274a3:	movl %eax, $0x1<UINT32>
0x004274a8:	addl %ebx, %ebx
0x004274aa:	jne 0x004274b3
0x004274b3:	adcl %eax, %eax
0x004274b5:	addl %ebx, %ebx
0x004274b7:	jae 0x004274a8
0x004274b9:	jne 0x004274c4
0x004274c4:	xorl %ecx, %ecx
0x004274c6:	subl %eax, $0x3<UINT8>
0x004274c9:	jb 0x004274d8
0x004274cb:	shll %eax, $0x8<UINT8>
0x004274ce:	movb %al, (%esi)
0x004274d0:	incl %esi
0x004274d1:	xorl %eax, $0xffffffff<UINT8>
0x004274d4:	je 0x0042754a
0x004274d6:	movl %ebp, %eax
0x004274d8:	addl %ebx, %ebx
0x004274da:	jne 0x004274e3
0x004274e3:	adcl %ecx, %ecx
0x004274e5:	addl %ebx, %ebx
0x004274e7:	jne 0x004274f0
0x004274f0:	adcl %ecx, %ecx
0x004274f2:	jne 0x00427514
0x00427514:	cmpl %ebp, $0xfffff300<UINT32>
0x0042751a:	adcl %ecx, $0x1<UINT8>
0x0042751d:	leal %edx, (%edi,%ebp)
0x00427520:	cmpl %ebp, $0xfffffffc<UINT8>
0x00427523:	jbe 0x00427534
0x00427534:	movl %eax, (%edx)
0x00427536:	addl %edx, $0x4<UINT8>
0x00427539:	movl (%edi), %eax
0x0042753b:	addl %edi, $0x4<UINT8>
0x0042753e:	subl %ecx, $0x4<UINT8>
0x00427541:	ja 0x00427534
0x00427543:	addl %edi, %ecx
0x00427545:	jmp 0x00427496
0x004274f4:	incl %ecx
0x004274f5:	addl %ebx, %ebx
0x004274f7:	jne 0x00427500
0x00427500:	adcl %ecx, %ecx
0x00427502:	addl %ebx, %ebx
0x00427504:	jae 0x004274f5
0x00427506:	jne 0x00427511
0x00427511:	addl %ecx, $0x2<UINT8>
0x004274dc:	movl %ebx, (%esi)
0x004274de:	subl %esi, $0xfffffffc<UINT8>
0x004274e1:	adcl %ebx, %ebx
0x00427525:	movb %al, (%edx)
0x00427527:	incl %edx
0x00427528:	movb (%edi), %al
0x0042752a:	incl %edi
0x0042752b:	decl %ecx
0x0042752c:	jne 0x00427525
0x0042752e:	jmp 0x00427496
0x004274ac:	movl %ebx, (%esi)
0x004274ae:	subl %esi, $0xfffffffc<UINT8>
0x004274b1:	adcl %ebx, %ebx
0x004274e9:	movl %ebx, (%esi)
0x004274eb:	subl %esi, $0xfffffffc<UINT8>
0x004274ee:	adcl %ebx, %ebx
0x00427508:	movl %ebx, (%esi)
0x0042750a:	subl %esi, $0xfffffffc<UINT8>
0x0042750d:	adcl %ebx, %ebx
0x0042750f:	jae 0x004274f5
0x004274bb:	movl %ebx, (%esi)
0x004274bd:	subl %esi, $0xfffffffc<UINT8>
0x004274c0:	adcl %ebx, %ebx
0x004274c2:	jae 0x004274a8
0x004274f9:	movl %ebx, (%esi)
0x004274fb:	subl %esi, $0xfffffffc<UINT8>
0x004274fe:	adcl %ebx, %ebx
0x0042754a:	popl %esi
0x0042754b:	movl %edi, %esi
0x0042754d:	movl %ecx, $0x13f<UINT32>
0x00427552:	movb %al, (%edi)
0x00427554:	incl %edi
0x00427555:	subb %al, $0xffffffe8<UINT8>
0x00427557:	cmpb %al, $0x1<UINT8>
0x00427559:	ja 0x00427552
0x0042755b:	cmpb (%edi), $0x6<UINT8>
0x0042755e:	jne 0x00427552
0x00427560:	movl %eax, (%edi)
0x00427562:	movb %bl, 0x4(%edi)
0x00427565:	shrw %ax, $0x8<UINT8>
0x00427569:	roll %eax, $0x10<UINT8>
0x0042756c:	xchgb %ah, %al
0x0042756e:	subl %eax, %edi
0x00427570:	subb %bl, $0xffffffe8<UINT8>
0x00427573:	addl %eax, %esi
0x00427575:	movl (%edi), %eax
0x00427577:	addl %edi, $0x5<UINT8>
0x0042757a:	movb %al, %bl
0x0042757c:	loop 0x00427557
0x0042757e:	leal %edi, 0x25000(%esi)
0x00427584:	movl %eax, (%edi)
0x00427586:	orl %eax, %eax
0x00427588:	je 0x004275cf
0x0042758a:	movl %ebx, 0x4(%edi)
0x0042758d:	leal %eax, 0x27460(%eax,%esi)
0x00427594:	addl %ebx, %esi
0x00427596:	pushl %eax
0x00427597:	addl %edi, $0x8<UINT8>
0x0042759a:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x004275a0:	xchgl %ebp, %eax
0x004275a1:	movb %al, (%edi)
0x004275a3:	incl %edi
0x004275a4:	orb %al, %al
0x004275a6:	je 0x00427584
0x004275a8:	movl %ecx, %edi
0x004275aa:	jns 0x004275b3
0x004275b3:	pushl %edi
0x004275b4:	decl %eax
0x004275b5:	repn scasb %al, %es:(%edi)
0x004275b7:	pushl %ebp
0x004275b8:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x004275be:	orl %eax, %eax
0x004275c0:	je 7
0x004275c2:	movl (%ebx), %eax
0x004275c4:	addl %ebx, $0x4<UINT8>
0x004275c7:	jmp 0x004275a1
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x004275ac:	movzwl %eax, (%edi)
0x004275af:	incl %edi
0x004275b0:	pushl %eax
0x004275b1:	incl %edi
0x004275b2:	movl %ecx, $0xaef24857<UINT32>
0x004275cf:	movl %ebp, 0x27518(%esi)
0x004275d5:	leal %edi, -4096(%esi)
0x004275db:	movl %ebx, $0x1000<UINT32>
0x004275e0:	pushl %eax
0x004275e1:	pushl %esp
0x004275e2:	pushl $0x4<UINT8>
0x004275e4:	pushl %ebx
0x004275e5:	pushl %edi
0x004275e6:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x004275e8:	leal %eax, 0x1f7(%edi)
0x004275ee:	andb (%eax), $0x7f<UINT8>
0x004275f1:	andb 0x28(%eax), $0x7f<UINT8>
0x004275f5:	popl %eax
0x004275f6:	pushl %eax
0x004275f7:	pushl %esp
0x004275f8:	pushl %eax
0x004275f9:	pushl %ebx
0x004275fa:	pushl %edi
0x004275fb:	call VirtualProtect@kernel32.dll
0x004275fd:	popl %eax
0x004275fe:	popa
0x004275ff:	leal %eax, -128(%esp)
0x00427603:	pushl $0x0<UINT8>
0x00427605:	cmpl %esp, %eax
0x00427607:	jne 0x00427603
0x00427609:	subl %esp, $0xffffff80<UINT8>
0x0042760c:	jmp 0x004024a2
0x004024a2:	pushl %ebp
0x004024a3:	movl %ebp, %esp
0x004024a5:	pushl $0xffffffff<UINT8>
0x004024a7:	pushl $0x407178<UINT32>
0x004024ac:	pushl $0x404ec8<UINT32>
0x004024b1:	movl %eax, %fs:0
0x004024b7:	pushl %eax
0x004024b8:	movl %fs:0, %esp
0x004024bf:	subl %esp, $0x58<UINT8>
0x004024c2:	pushl %ebx
0x004024c3:	pushl %esi
0x004024c4:	pushl %edi
0x004024c5:	movl -24(%ebp), %esp
0x004024c8:	call GetVersion@KERNEL32.DLL
GetVersion@KERNEL32.DLL: API Node	
0x004024ce:	xorl %edx, %edx
0x004024d0:	movb %dl, %ah
0x004024d2:	movl 0x422df4, %edx
0x004024d8:	movl %ecx, %eax
0x004024da:	andl %ecx, $0xff<UINT32>
0x004024e0:	movl 0x422df0, %ecx
0x004024e6:	shll %ecx, $0x8<UINT8>
0x004024e9:	addl %ecx, %edx
0x004024eb:	movl 0x422dec, %ecx
0x004024f1:	shrl %eax, $0x10<UINT8>
0x004024f4:	movl 0x422de8, %eax
0x004024f9:	xorl %esi, %esi
0x004024fb:	pushl %esi
0x004024fc:	call 0x00403b73
0x00403b73:	xorl %eax, %eax
0x00403b75:	pushl $0x0<UINT8>
0x00403b77:	cmpl 0x8(%esp), %eax
0x00403b7b:	pushl $0x1000<UINT32>
0x00403b80:	sete %al
0x00403b83:	pushl %eax
0x00403b84:	call HeapCreate@KERNEL32.DLL
HeapCreate@KERNEL32.DLL: API Node	
0x00403b8a:	testl %eax, %eax
0x00403b8c:	movl 0x423330, %eax
0x00403b91:	je 21
0x00403b93:	call 0x00403baf
0x00403baf:	pushl $0x140<UINT32>
0x00403bb4:	pushl $0x0<UINT8>
0x00403bb6:	pushl 0x423330
0x00403bbc:	call HeapAlloc@KERNEL32.DLL
HeapAlloc@KERNEL32.DLL: API Node	
0x00403bc2:	testl %eax, %eax
0x00403bc4:	movl 0x42332c, %eax
0x00403bc9:	jne 0x00403bcc
0x00403bcc:	andl 0x423324, $0x0<UINT8>
0x00403bd3:	andl 0x423328, $0x0<UINT8>
0x00403bda:	pushl $0x1<UINT8>
0x00403bdc:	movl 0x423320, %eax
0x00403be1:	movl 0x423318, $0x10<UINT32>
0x00403beb:	popl %eax
0x00403bec:	ret

0x00403b98:	testl %eax, %eax
0x00403b9a:	jne 0x00403bab
0x00403bab:	pushl $0x1<UINT8>
0x00403bad:	popl %eax
0x00403bae:	ret

0x00402501:	popl %ecx
0x00402502:	testl %eax, %eax
0x00402504:	jne 0x0040250e
0x0040250e:	movl -4(%ebp), %esi
0x00402511:	call 0x00404c23
0x00404c23:	subl %esp, $0x44<UINT8>
0x00404c26:	pushl %ebx
0x00404c27:	pushl %ebp
0x00404c28:	pushl %esi
0x00404c29:	pushl %edi
0x00404c2a:	pushl $0x100<UINT32>
0x00404c2f:	call 0x0040236b
0x0040236b:	pushl 0x422dd4
0x00402371:	pushl 0x8(%esp)
0x00402375:	call 0x0040237d
0x0040237d:	cmpl 0x4(%esp), $0xffffffe0<UINT8>
0x00402382:	ja 34
0x00402384:	pushl 0x4(%esp)
0x00402388:	call 0x004023a9
0x004023a9:	pushl %esi
0x004023aa:	movl %esi, 0x8(%esp)
0x004023ae:	cmpl %esi, 0x4229fc
0x004023b4:	ja 0x004023c1
0x004023b6:	pushl %esi
0x004023b7:	call 0x00403f43
0x00403f43:	pushl %ebp
0x00403f44:	movl %ebp, %esp
0x00403f46:	subl %esp, $0x14<UINT8>
0x00403f49:	movl %eax, 0x423328
0x00403f4e:	movl %edx, 0x42332c
0x00403f54:	pushl %ebx
0x00403f55:	pushl %esi
0x00403f56:	leal %eax, (%eax,%eax,4)
0x00403f59:	pushl %edi
0x00403f5a:	leal %edi, (%edx,%eax,4)
0x00403f5d:	movl %eax, 0x8(%ebp)
0x00403f60:	movl -4(%ebp), %edi
0x00403f63:	leal %ecx, 0x17(%eax)
0x00403f66:	andl %ecx, $0xfffffff0<UINT8>
0x00403f69:	movl -16(%ebp), %ecx
0x00403f6c:	sarl %ecx, $0x4<UINT8>
0x00403f6f:	decl %ecx
0x00403f70:	cmpl %ecx, $0x20<UINT8>
0x00403f73:	jnl 14
0x00403f75:	orl %esi, $0xffffffff<UINT8>
0x00403f78:	shrl %esi, %cl
0x00403f7a:	orl -8(%ebp), $0xffffffff<UINT8>
0x00403f7e:	movl -12(%ebp), %esi
0x00403f81:	jmp 0x00403f93
0x00403f93:	movl %eax, 0x423320
0x00403f98:	movl %ebx, %eax
0x00403f9a:	cmpl %ebx, %edi
0x00403f9c:	movl 0x8(%ebp), %ebx
0x00403f9f:	jae 0x00403fba
0x00403fba:	cmpl %ebx, -4(%ebp)
0x00403fbd:	jne 0x00404038
0x00403fbf:	movl %ebx, %edx
0x00403fc1:	cmpl %ebx, %eax
0x00403fc3:	movl 0x8(%ebp), %ebx
0x00403fc6:	jae 0x00403fdd
0x00403fdd:	jne 89
0x00403fdf:	cmpl %ebx, -4(%ebp)
0x00403fe2:	jae 0x00403ff5
0x00403ff5:	jne 38
0x00403ff7:	movl %ebx, %edx
0x00403ff9:	cmpl %ebx, %eax
0x00403ffb:	movl 0x8(%ebp), %ebx
0x00403ffe:	jae 0x0040400d
0x0040400d:	jne 14
0x0040400f:	call 0x0040424c
0x0040424c:	movl %eax, 0x423328
0x00404251:	movl %ecx, 0x423318
0x00404257:	pushl %esi
0x00404258:	pushl %edi
0x00404259:	xorl %edi, %edi
0x0040425b:	cmpl %eax, %ecx
0x0040425d:	jne 0x0040428f
0x0040428f:	movl %ecx, 0x42332c
0x00404295:	pushl $0x41c4<UINT32>
0x0040429a:	pushl $0x8<UINT8>
0x0040429c:	leal %eax, (%eax,%eax,4)
0x0040429f:	pushl 0x423330
0x004042a5:	leal %esi, (%ecx,%eax,4)
0x004042a8:	call HeapAlloc@KERNEL32.DLL
0x004042ae:	cmpl %eax, %edi
0x004042b0:	movl 0x10(%esi), %eax
0x004042b3:	je 42
0x004042b5:	pushl $0x4<UINT8>
0x004042b7:	pushl $0x2000<UINT32>
0x004042bc:	pushl $0x100000<UINT32>
0x004042c1:	pushl %edi
0x004042c2:	call VirtualAlloc@KERNEL32.DLL
VirtualAlloc@KERNEL32.DLL: API Node	
0x004042c8:	cmpl %eax, %edi
0x004042ca:	movl 0xc(%esi), %eax
0x004042cd:	jne 0x004042e3
0x004042e3:	orl 0x8(%esi), $0xffffffff<UINT8>
0x004042e7:	movl (%esi), %edi
0x004042e9:	movl 0x4(%esi), %edi
0x004042ec:	incl 0x423328
0x004042f2:	movl %eax, 0x10(%esi)
0x004042f5:	orl (%eax), $0xffffffff<UINT8>
0x004042f8:	movl %eax, %esi
0x004042fa:	popl %edi
0x004042fb:	popl %esi
0x004042fc:	ret

0x00404014:	movl %ebx, %eax
0x00404016:	testl %ebx, %ebx
0x00404018:	movl 0x8(%ebp), %ebx
0x0040401b:	je 20
0x0040401d:	pushl %ebx
0x0040401e:	call 0x004042fd
0x004042fd:	pushl %ebp
0x004042fe:	movl %ebp, %esp
0x00404300:	pushl %ecx
0x00404301:	movl %ecx, 0x8(%ebp)
0x00404304:	pushl %ebx
0x00404305:	pushl %esi
0x00404306:	pushl %edi
0x00404307:	movl %esi, 0x10(%ecx)
0x0040430a:	movl %eax, 0x8(%ecx)
0x0040430d:	xorl %ebx, %ebx
0x0040430f:	testl %eax, %eax
0x00404311:	jl 0x00404318
0x00404318:	movl %eax, %ebx
0x0040431a:	pushl $0x3f<UINT8>
0x0040431c:	imull %eax, %eax, $0x204<UINT32>
0x00404322:	popl %edx
0x00404323:	leal %eax, 0x144(%eax,%esi)
0x0040432a:	movl -4(%ebp), %eax
0x0040432d:	movl 0x8(%eax), %eax
0x00404330:	movl 0x4(%eax), %eax
0x00404333:	addl %eax, $0x8<UINT8>
0x00404336:	decl %edx
0x00404337:	jne 0x0040432d
0x00404339:	movl %edi, %ebx
0x0040433b:	pushl $0x4<UINT8>
0x0040433d:	shll %edi, $0xf<UINT8>
0x00404340:	addl %edi, 0xc(%ecx)
0x00404343:	pushl $0x1000<UINT32>
0x00404348:	pushl $0x8000<UINT32>
0x0040434d:	pushl %edi
0x0040434e:	call VirtualAlloc@KERNEL32.DLL
0x00404354:	testl %eax, %eax
0x00404356:	jne 0x00404360
0x00404360:	leal %edx, 0x7000(%edi)
0x00404366:	cmpl %edi, %edx
0x00404368:	ja 60
0x0040436a:	leal %eax, 0x10(%edi)
0x0040436d:	orl -8(%eax), $0xffffffff<UINT8>
0x00404371:	orl 0xfec(%eax), $0xffffffff<UINT8>
0x00404378:	leal %ecx, 0xffc(%eax)
0x0040437e:	movl -4(%eax), $0xff0<UINT32>
0x00404385:	movl (%eax), %ecx
0x00404387:	leal %ecx, -4100(%eax)
0x0040438d:	movl 0x4(%eax), %ecx
0x00404390:	movl 0xfe8(%eax), $0xff0<UINT32>
0x0040439a:	addl %eax, $0x1000<UINT32>
0x0040439f:	leal %ecx, -16(%eax)
0x004043a2:	cmpl %ecx, %edx
0x004043a4:	jbe 0x0040436d
0x004043a6:	movl %eax, -4(%ebp)
0x004043a9:	leal %ecx, 0xc(%edi)
0x004043ac:	addl %eax, $0x1f8<UINT32>
0x004043b1:	pushl $0x1<UINT8>
0x004043b3:	popl %edi
0x004043b4:	movl 0x4(%eax), %ecx
0x004043b7:	movl 0x8(%ecx), %eax
0x004043ba:	leal %ecx, 0xc(%edx)
0x004043bd:	movl 0x8(%eax), %ecx
0x004043c0:	movl 0x4(%ecx), %eax
0x004043c3:	andl 0x44(%esi,%ebx,4), $0x0<UINT8>
0x004043c8:	movl 0xc4(%esi,%ebx,4), %edi
0x004043cf:	movb %al, 0x43(%esi)
0x004043d2:	movb %cl, %al
0x004043d4:	incb %cl
0x004043d6:	testb %al, %al
0x004043d8:	movl %eax, 0x8(%ebp)
0x004043db:	movb 0x43(%esi), %cl
0x004043de:	jne 3
0x004043e0:	orl 0x4(%eax), %edi
0x004043e3:	movl %edx, $0x80000000<UINT32>
0x004043e8:	movl %ecx, %ebx
0x004043ea:	shrl %edx, %cl
0x004043ec:	notl %edx
0x004043ee:	andl 0x8(%eax), %edx
0x004043f1:	movl %eax, %ebx
0x004043f3:	popl %edi
0x004043f4:	popl %esi
0x004043f5:	popl %ebx
0x004043f6:	leave
0x004043f7:	ret

0x00404023:	popl %ecx
0x00404024:	movl %ecx, 0x10(%ebx)
0x00404027:	movl (%ecx), %eax
0x00404029:	movl %eax, 0x10(%ebx)
0x0040402c:	cmpl (%eax), $0xffffffff<UINT8>
0x0040402f:	jne 0x00404038
0x00404038:	movl 0x423320, %ebx
0x0040403e:	movl %eax, 0x10(%ebx)
0x00404041:	movl %edx, (%eax)
0x00404043:	cmpl %edx, $0xffffffff<UINT8>
0x00404046:	movl -4(%ebp), %edx
0x00404049:	je 20
0x0040404b:	movl %ecx, 0xc4(%eax,%edx,4)
0x00404052:	movl %edi, 0x44(%eax,%edx,4)
0x00404056:	andl %ecx, -8(%ebp)
0x00404059:	andl %edi, %esi
0x0040405b:	orl %ecx, %edi
0x0040405d:	jne 0x00404096
0x00404096:	movl %ecx, %edx
0x00404098:	xorl %edi, %edi
0x0040409a:	imull %ecx, %ecx, $0x204<UINT32>
0x004040a0:	leal %ecx, 0x144(%ecx,%eax)
0x004040a7:	movl -12(%ebp), %ecx
0x004040aa:	movl %ecx, 0x44(%eax,%edx,4)
0x004040ae:	andl %ecx, %esi
0x004040b0:	jne 13
0x004040b2:	movl %ecx, 0xc4(%eax,%edx,4)
0x004040b9:	pushl $0x20<UINT8>
0x004040bb:	andl %ecx, -8(%ebp)
0x004040be:	popl %edi
0x004040bf:	testl %ecx, %ecx
0x004040c1:	jl 0x004040c8
0x004040c3:	shll %ecx
0x004040c5:	incl %edi
0x004040c6:	jmp 0x004040bf
0x004040c8:	movl %ecx, -12(%ebp)
0x004040cb:	movl %edx, 0x4(%ecx,%edi,8)
0x004040cf:	movl %ecx, (%edx)
0x004040d1:	subl %ecx, -16(%ebp)
0x004040d4:	movl %esi, %ecx
0x004040d6:	movl -8(%ebp), %ecx
0x004040d9:	sarl %esi, $0x4<UINT8>
0x004040dc:	decl %esi
0x004040dd:	cmpl %esi, $0x3f<UINT8>
0x004040e0:	jle 3
0x004040e2:	pushl $0x3f<UINT8>
0x004040e4:	popl %esi
0x004040e5:	cmpl %esi, %edi
0x004040e7:	je 0x004041fa
0x004041fa:	testl %ecx, %ecx
0x004041fc:	je 11
0x004041fe:	movl (%edx), %ecx
0x00404200:	movl -4(%ecx,%edx), %ecx
0x00404204:	jmp 0x00404209
0x00404209:	movl %esi, -16(%ebp)
0x0040420c:	addl %edx, %ecx
0x0040420e:	leal %ecx, 0x1(%esi)
0x00404211:	movl (%edx), %ecx
0x00404213:	movl -4(%edx,%esi), %ecx
0x00404217:	movl %esi, -12(%ebp)
0x0040421a:	movl %ecx, (%esi)
0x0040421c:	testl %ecx, %ecx
0x0040421e:	leal %edi, 0x1(%ecx)
0x00404221:	movl (%esi), %edi
0x00404223:	jne 0x0040423f
0x00404225:	cmpl %ebx, 0x423324
0x0040422b:	jne 0x0040423f
0x0040423f:	movl %ecx, -4(%ebp)
0x00404242:	movl (%eax), %ecx
0x00404244:	leal %eax, 0x4(%edx)
0x00404247:	popl %edi
0x00404248:	popl %esi
0x00404249:	popl %ebx
0x0040424a:	leave
0x0040424b:	ret

0x004023bc:	testl %eax, %eax
0x004023be:	popl %ecx
0x004023bf:	jne 0x004023dd
0x004023dd:	popl %esi
0x004023de:	ret

0x0040238d:	testl %eax, %eax
0x0040238f:	popl %ecx
0x00402390:	jne 0x004023a8
0x004023a8:	ret

0x0040237a:	popl %ecx
0x0040237b:	popl %ecx
0x0040237c:	ret

0x00404c34:	movl %esi, %eax
0x00404c36:	popl %ecx
0x00404c37:	testl %esi, %esi
0x00404c39:	jne 0x00404c43
0x00404c43:	movl 0x423200, %esi
0x00404c49:	movl 0x423300, $0x20<UINT32>
0x00404c53:	leal %eax, 0x100(%esi)
0x00404c59:	cmpl %esi, %eax
0x00404c5b:	jae 0x00404c77
0x00404c5d:	andb 0x4(%esi), $0x0<UINT8>
0x00404c61:	orl (%esi), $0xffffffff<UINT8>
0x00404c64:	movb 0x5(%esi), $0xa<UINT8>
0x00404c68:	movl %eax, 0x423200
0x00404c6d:	addl %esi, $0x8<UINT8>
0x00404c70:	addl %eax, $0x100<UINT32>
0x00404c75:	jmp 0x00404c59
0x00404c77:	leal %eax, 0x10(%esp)
0x00404c7b:	pushl %eax
0x00404c7c:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x00404c82:	cmpw 0x42(%esp), $0x0<UINT8>
0x00404c88:	je 0x00404d53
0x00404d53:	xorl %ebx, %ebx
0x00404d55:	movl %eax, 0x423200
0x00404d5a:	cmpl (%eax,%ebx,8), $0xffffffff<UINT8>
0x00404d5e:	leal %esi, (%eax,%ebx,8)
0x00404d61:	jne 77
0x00404d63:	testl %ebx, %ebx
0x00404d65:	movb 0x4(%esi), $0xffffff81<UINT8>
0x00404d69:	jne 0x00404d70
0x00404d6b:	pushl $0xfffffff6<UINT8>
0x00404d6d:	popl %eax
0x00404d6e:	jmp 0x00404d7a
0x00404d7a:	pushl %eax
0x00404d7b:	call GetStdHandle@KERNEL32.DLL
GetStdHandle@KERNEL32.DLL: API Node	
0x00404d81:	movl %edi, %eax
0x00404d83:	cmpl %edi, $0xffffffff<UINT8>
0x00404d86:	je 23
0x00404d88:	pushl %edi
0x00404d89:	call GetFileType@KERNEL32.DLL
GetFileType@KERNEL32.DLL: API Node	
0x00404d8f:	testl %eax, %eax
0x00404d91:	je 12
0x00404d93:	andl %eax, $0xff<UINT32>
0x00404d98:	movl (%esi), %edi
0x00404d9a:	cmpl %eax, $0x2<UINT8>
0x00404d9d:	jne 6
0x00404d9f:	orb 0x4(%esi), $0x40<UINT8>
0x00404da3:	jmp 0x00404db4
0x00404db4:	incl %ebx
0x00404db5:	cmpl %ebx, $0x3<UINT8>
0x00404db8:	jl 0x00404d55
0x00404d70:	movl %eax, %ebx
0x00404d72:	decl %eax
0x00404d73:	negl %eax
0x00404d75:	sbbl %eax, %eax
0x00404d77:	addl %eax, $0xfffffff5<UINT8>
0x00404dba:	pushl 0x423300
0x00404dc0:	call SetHandleCount@KERNEL32.DLL
SetHandleCount@KERNEL32.DLL: API Node	
0x00404dc6:	popl %edi
0x00404dc7:	popl %esi
0x00404dc8:	popl %ebp
0x00404dc9:	popl %ebx
0x00404dca:	addl %esp, $0x44<UINT8>
0x00404dcd:	ret

0x00402516:	call GetCommandLineA@KERNEL32.DLL
GetCommandLineA@KERNEL32.DLL: API Node	
0x0040251c:	movl 0x424344, %eax
0x00402521:	call 0x00404af1
0x00404af1:	pushl %ecx
0x00404af2:	pushl %ecx
0x00404af3:	movl %eax, 0x422f30
0x00404af8:	pushl %ebx
0x00404af9:	pushl %ebp
0x00404afa:	movl %ebp, 0x407068
0x00404b00:	pushl %esi
0x00404b01:	pushl %edi
0x00404b02:	xorl %ebx, %ebx
0x00404b04:	xorl %esi, %esi
0x00404b06:	xorl %edi, %edi
0x00404b08:	cmpl %eax, %ebx
0x00404b0a:	jne 51
0x00404b0c:	call GetEnvironmentStringsW@KERNEL32.DLL
GetEnvironmentStringsW@KERNEL32.DLL: API Node	
0x00404b0e:	movl %esi, %eax
0x00404b10:	cmpl %esi, %ebx
0x00404b12:	je 12
0x00404b14:	movl 0x422f30, $0x1<UINT32>
0x00404b1e:	jmp 0x00404b48
0x00404b48:	cmpl %esi, %ebx
0x00404b4a:	jne 0x00404b58
0x00404b58:	cmpw (%esi), %bx
0x00404b5b:	movl %eax, %esi
0x00404b5d:	je 14
0x00404b5f:	incl %eax
0x00404b60:	incl %eax
0x00404b61:	cmpw (%eax), %bx
0x00404b64:	jne 0x00404b5f
0x00404b66:	incl %eax
0x00404b67:	incl %eax
0x00404b68:	cmpw (%eax), %bx
0x00404b6b:	jne 0x00404b5f
0x00404b6d:	subl %eax, %esi
0x00404b6f:	movl %edi, 0x407070
0x00404b75:	sarl %eax
0x00404b77:	pushl %ebx
0x00404b78:	pushl %ebx
0x00404b79:	incl %eax
0x00404b7a:	pushl %ebx
0x00404b7b:	pushl %ebx
0x00404b7c:	pushl %eax
0x00404b7d:	pushl %esi
0x00404b7e:	pushl %ebx
0x00404b7f:	pushl %ebx
0x00404b80:	movl 0x34(%esp), %eax
0x00404b84:	call WideCharToMultiByte@KERNEL32.DLL
WideCharToMultiByte@KERNEL32.DLL: API Node	
0x00404b86:	movl %ebp, %eax
0x00404b88:	cmpl %ebp, %ebx
0x00404b8a:	je 50
0x00404b8c:	pushl %ebp
0x00404b8d:	call 0x0040236b
0x004023c1:	testl %esi, %esi
0x004023c3:	jne 0x004023c8
0x004023c8:	addl %esi, $0xf<UINT8>
0x004023cb:	andl %esi, $0xfffffff0<UINT8>
0x004023ce:	pushl %esi
0x004023cf:	pushl $0x0<UINT8>
0x004023d1:	pushl 0x423330
0x004023d7:	call HeapAlloc@KERNEL32.DLL
0x00404b92:	cmpl %eax, %ebx
0x00404b94:	popl %ecx
0x00404b95:	movl 0x10(%esp), %eax
0x00404b99:	je 35
0x00404b9b:	pushl %ebx
0x00404b9c:	pushl %ebx
0x00404b9d:	pushl %ebp
0x00404b9e:	pushl %eax
0x00404b9f:	pushl 0x24(%esp)
0x00404ba3:	pushl %esi
0x00404ba4:	pushl %ebx
0x00404ba5:	pushl %ebx
0x00404ba6:	call WideCharToMultiByte@KERNEL32.DLL
0x00404ba8:	testl %eax, %eax
0x00404baa:	jne 0x00404bba
0x00404bba:	movl %ebx, 0x10(%esp)
0x00404bbe:	pushl %esi
0x00404bbf:	call FreeEnvironmentStringsW@KERNEL32.DLL
FreeEnvironmentStringsW@KERNEL32.DLL: API Node	
0x00404bc5:	movl %eax, %ebx
0x00404bc7:	jmp 0x00404c1c
0x00404c1c:	popl %edi
0x00404c1d:	popl %esi
0x00404c1e:	popl %ebp
0x00404c1f:	popl %ebx
0x00404c20:	popl %ecx
0x00404c21:	popl %ecx
0x00404c22:	ret

0x00402526:	movl 0x422dbc, %eax
0x0040252b:	call 0x004048a4
0x004048a4:	pushl %ebp
0x004048a5:	movl %ebp, %esp
0x004048a7:	pushl %ecx
0x004048a8:	pushl %ecx
0x004048a9:	pushl %ebx
0x004048aa:	xorl %ebx, %ebx
0x004048ac:	cmpl 0x423308, %ebx
0x004048b2:	pushl %esi
0x004048b3:	pushl %edi
0x004048b4:	jne 5
0x004048b6:	call 0x00406256
0x00406256:	cmpl 0x423308, $0x0<UINT8>
0x0040625d:	jne 0x00406271
0x0040625f:	pushl $0xfffffffd<UINT8>
0x00406261:	call 0x00405e92
0x00405e92:	pushl %ebp
0x00405e93:	movl %ebp, %esp
0x00405e95:	subl %esp, $0x18<UINT8>
0x00405e98:	pushl %ebx
0x00405e99:	pushl %esi
0x00405e9a:	pushl %edi
0x00405e9b:	pushl 0x8(%ebp)
0x00405e9e:	call 0x0040602b
0x0040602b:	movl %eax, 0x4(%esp)
0x0040602f:	andl 0x422f3c, $0x0<UINT8>
0x00406036:	cmpl %eax, $0xfffffffe<UINT8>
0x00406039:	jne 0x0040604b
0x0040604b:	cmpl %eax, $0xfffffffd<UINT8>
0x0040604e:	jne 16
0x00406050:	movl 0x422f3c, $0x1<UINT32>
0x0040605a:	jmp GetACP@KERNEL32.DLL
GetACP@KERNEL32.DLL: API Node	
0x00405ea3:	movl %esi, %eax
0x00405ea5:	popl %ecx
0x00405ea6:	cmpl %esi, 0x422fb0
0x00405eac:	movl 0x8(%ebp), %esi
0x00405eaf:	je 362
0x00405eb5:	xorl %ebx, %ebx
0x00405eb7:	cmpl %esi, %ebx
0x00405eb9:	je 342
0x00405ebf:	xorl %edx, %edx
0x00405ec1:	movl %eax, $0x422b58<UINT32>
0x00405ec6:	cmpl (%eax), %esi
0x00405ec8:	je 114
0x00405eca:	addl %eax, $0x30<UINT8>
0x00405ecd:	incl %edx
0x00405ece:	cmpl %eax, $0x422c48<UINT32>
0x00405ed3:	jl 0x00405ec6
0x00405ed5:	leal %eax, -24(%ebp)
0x00405ed8:	pushl %eax
0x00405ed9:	pushl %esi
0x00405eda:	call GetCPInfo@KERNEL32.DLL
GetCPInfo@KERNEL32.DLL: API Node	
0x00405ee0:	cmpl %eax, $0x1<UINT8>
0x00405ee3:	jne 292
0x00405ee9:	pushl $0x40<UINT8>
0x00405eeb:	xorl %eax, %eax
0x00405eed:	popl %ecx
0x00405eee:	movl %edi, $0x4230e0<UINT32>
0x00405ef3:	cmpl -24(%ebp), $0x1<UINT8>
0x00405ef7:	movl 0x422fb0, %esi
0x00405efd:	rep stosl %es:(%edi), %eax
0x00405eff:	stosb %es:(%edi), %al
0x00405f00:	movl 0x4231e4, %ebx
0x00405f06:	jbe 239
0x00405f0c:	cmpb -18(%ebp), $0x0<UINT8>
0x00405f10:	je 0x00405fd1
0x00405fd1:	pushl $0x1<UINT8>
0x00405fd3:	popl %eax
0x00405fd4:	orb 0x4230e1(%eax), $0x8<UINT8>
0x00405fdb:	incl %eax
0x00405fdc:	cmpl %eax, $0xff<UINT32>
0x00405fe1:	jb 0x00405fd4
0x00405fe3:	pushl %esi
0x00405fe4:	call 0x00406075
0x00406075:	movl %eax, 0x4(%esp)
0x00406079:	subl %eax, $0x3a4<UINT32>
0x0040607e:	je 34
0x00406080:	subl %eax, $0x4<UINT8>
0x00406083:	je 23
0x00406085:	subl %eax, $0xd<UINT8>
0x00406088:	je 12
0x0040608a:	decl %eax
0x0040608b:	je 3
0x0040608d:	xorl %eax, %eax
0x0040608f:	ret

0x00405fe9:	popl %ecx
0x00405fea:	movl 0x4231e4, %eax
0x00405fef:	movl 0x422fcc, $0x1<UINT32>
0x00405ff9:	jmp 0x00406001
0x00406001:	xorl %eax, %eax
0x00406003:	movl %edi, $0x422fc0<UINT32>
0x00406008:	stosl %es:(%edi), %eax
0x00406009:	stosl %es:(%edi), %eax
0x0040600a:	stosl %es:(%edi), %eax
0x0040600b:	jmp 0x0040601a
0x0040601a:	call 0x004060d1
0x004060d1:	pushl %ebp
0x004060d2:	movl %ebp, %esp
0x004060d4:	subl %esp, $0x514<UINT32>
0x004060da:	leal %eax, -20(%ebp)
0x004060dd:	pushl %esi
0x004060de:	pushl %eax
0x004060df:	pushl 0x422fb0
0x004060e5:	call GetCPInfo@KERNEL32.DLL
0x004060eb:	cmpl %eax, $0x1<UINT8>
0x004060ee:	jne 278
0x004060f4:	xorl %eax, %eax
0x004060f6:	movl %esi, $0x100<UINT32>
0x004060fb:	movb -276(%ebp,%eax), %al
0x00406102:	incl %eax
0x00406103:	cmpl %eax, %esi
0x00406105:	jb 0x004060fb
0x00406107:	movb %al, -14(%ebp)
0x0040610a:	movb -276(%ebp), $0x20<UINT8>
0x00406111:	testb %al, %al
0x00406113:	je 0x0040614c
0x0040614c:	pushl $0x0<UINT8>
0x0040614e:	leal %eax, -1300(%ebp)
0x00406154:	pushl 0x4231e4
0x0040615a:	pushl 0x422fb0
0x00406160:	pushl %eax
0x00406161:	leal %eax, -276(%ebp)
0x00406167:	pushl %esi
0x00406168:	pushl %eax
0x00406169:	pushl $0x1<UINT8>
0x0040616b:	call 0x0040512c
0x0040512c:	pushl %ebp
0x0040512d:	movl %ebp, %esp
0x0040512f:	pushl $0xffffffff<UINT8>
0x00405131:	pushl $0x4074f0<UINT32>
0x00405136:	pushl $0x404ec8<UINT32>
0x0040513b:	movl %eax, %fs:0
0x00405141:	pushl %eax
0x00405142:	movl %fs:0, %esp
0x00405149:	subl %esp, $0x18<UINT8>
0x0040514c:	pushl %ebx
0x0040514d:	pushl %esi
0x0040514e:	pushl %edi
0x0040514f:	movl -24(%ebp), %esp
0x00405152:	movl %eax, 0x422f38
0x00405157:	xorl %ebx, %ebx
0x00405159:	cmpl %eax, %ebx
0x0040515b:	jne 62
0x0040515d:	leal %eax, -28(%ebp)
0x00405160:	pushl %eax
0x00405161:	pushl $0x1<UINT8>
0x00405163:	popl %esi
0x00405164:	pushl %esi
0x00405165:	pushl $0x4074ec<UINT32>
0x0040516a:	pushl %esi
0x0040516b:	call GetStringTypeW@KERNEL32.DLL
GetStringTypeW@KERNEL32.DLL: API Node	
0x00405171:	testl %eax, %eax
0x00405173:	je 4
0x00405175:	movl %eax, %esi
0x00405177:	jmp 0x00405196
0x00405196:	movl 0x422f38, %eax
0x0040519b:	cmpl %eax, $0x2<UINT8>
0x0040519e:	jne 0x004051c4
0x004051c4:	cmpl %eax, $0x1<UINT8>
0x004051c7:	jne 148
0x004051cd:	cmpl 0x18(%ebp), %ebx
0x004051d0:	jne 0x004051da
0x004051da:	pushl %ebx
0x004051db:	pushl %ebx
0x004051dc:	pushl 0x10(%ebp)
0x004051df:	pushl 0xc(%ebp)
0x004051e2:	movl %eax, 0x20(%ebp)
0x004051e5:	negl %eax
0x004051e7:	sbbl %eax, %eax
0x004051e9:	andl %eax, $0x8<UINT8>
0x004051ec:	incl %eax
0x004051ed:	pushl %eax
0x004051ee:	pushl 0x18(%ebp)
0x004051f1:	call MultiByteToWideChar@KERNEL32.DLL
MultiByteToWideChar@KERNEL32.DLL: API Node	
0x004051f7:	movl -32(%ebp), %eax
0x004051fa:	cmpl %eax, %ebx
0x004051fc:	je 99
0x004051fe:	movl -4(%ebp), %ebx
0x00405201:	leal %edi, (%eax,%eax)
0x00405204:	movl %eax, %edi
0x00405206:	addl %eax, $0x3<UINT8>
0x00405209:	andb %al, $0xfffffffc<UINT8>
0x0040520b:	call 0x00406830
0x00406830:	pushl %ecx
0x00406831:	cmpl %eax, $0x1000<UINT32>
0x00406836:	leal %ecx, 0x8(%esp)
0x0040683a:	jb 0x00406850
0x00406850:	subl %ecx, %eax
0x00406852:	movl %eax, %esp
0x00406854:	testl (%ecx), %eax
0x00406856:	movl %esp, %ecx
0x00406858:	movl %ecx, (%eax)
0x0040685a:	movl %eax, 0x4(%eax)
0x0040685d:	pushl %eax
0x0040685e:	ret

0x00405210:	movl -24(%ebp), %esp
0x00405213:	movl %esi, %esp
0x00405215:	movl -36(%ebp), %esi
0x00405218:	pushl %edi
0x00405219:	pushl %ebx
0x0040521a:	pushl %esi
0x0040521b:	call 0x00405340
0x00405340:	movl %edx, 0xc(%esp)
0x00405344:	movl %ecx, 0x4(%esp)
0x00405348:	testl %edx, %edx
0x0040534a:	je 71
0x0040534c:	xorl %eax, %eax
0x0040534e:	movb %al, 0x8(%esp)
0x00405352:	pushl %edi
0x00405353:	movl %edi, %ecx
0x00405355:	cmpl %edx, $0x4<UINT8>
0x00405358:	jb 45
0x0040535a:	negl %ecx
0x0040535c:	andl %ecx, $0x3<UINT8>
0x0040535f:	je 0x00405369
0x00405369:	movl %ecx, %eax
0x0040536b:	shll %eax, $0x8<UINT8>
0x0040536e:	addl %eax, %ecx
0x00405370:	movl %ecx, %eax
0x00405372:	shll %eax, $0x10<UINT8>
0x00405375:	addl %eax, %ecx
0x00405377:	movl %ecx, %edx
0x00405379:	andl %edx, $0x3<UINT8>
0x0040537c:	shrl %ecx, $0x2<UINT8>
0x0040537f:	je 6
0x00405381:	rep stosl %es:(%edi), %eax
0x00405383:	testl %edx, %edx
0x00405385:	je 0x0040538d
0x0040538d:	movl %eax, 0x8(%esp)
0x00405391:	popl %edi
0x00405392:	ret

0x00405220:	addl %esp, $0xc<UINT8>
0x00405223:	jmp 0x00405230
0x00405230:	orl -4(%ebp), $0xffffffff<UINT8>
0x00405234:	cmpl %esi, %ebx
0x00405236:	je 41
0x00405238:	pushl -32(%ebp)
0x0040523b:	pushl %esi
0x0040523c:	pushl 0x10(%ebp)
0x0040523f:	pushl 0xc(%ebp)
0x00405242:	pushl $0x1<UINT8>
0x00405244:	pushl 0x18(%ebp)
0x00405247:	call MultiByteToWideChar@KERNEL32.DLL
0x0040524d:	cmpl %eax, %ebx
0x0040524f:	je 16
0x00405251:	pushl 0x14(%ebp)
0x00405254:	pushl %eax
0x00405255:	pushl %esi
0x00405256:	pushl 0x8(%ebp)
0x00405259:	call GetStringTypeW@KERNEL32.DLL
0x0040525f:	jmp 0x00405263
0x00405263:	leal %esp, -52(%ebp)
0x00405266:	movl %ecx, -16(%ebp)
0x00405269:	movl %fs:0, %ecx
0x00405270:	popl %edi
0x00405271:	popl %esi
0x00405272:	popl %ebx
0x00405273:	leave
0x00405274:	ret

0x00406170:	pushl $0x0<UINT8>
0x00406172:	leal %eax, -532(%ebp)
0x00406178:	pushl 0x422fb0
0x0040617e:	pushl %esi
0x0040617f:	pushl %eax
0x00406180:	leal %eax, -276(%ebp)
0x00406186:	pushl %esi
0x00406187:	pushl %eax
0x00406188:	pushl %esi
0x00406189:	pushl 0x4231e4
0x0040618f:	call 0x00406c29
0x00406c29:	pushl %ebp
0x00406c2a:	movl %ebp, %esp
0x00406c2c:	pushl $0xffffffff<UINT8>
0x00406c2e:	pushl $0x407538<UINT32>
0x00406c33:	pushl $0x404ec8<UINT32>
0x00406c38:	movl %eax, %fs:0
0x00406c3e:	pushl %eax
0x00406c3f:	movl %fs:0, %esp
0x00406c46:	subl %esp, $0x1c<UINT8>
0x00406c49:	pushl %ebx
0x00406c4a:	pushl %esi
0x00406c4b:	pushl %edi
0x00406c4c:	movl -24(%ebp), %esp
0x00406c4f:	xorl %edi, %edi
0x00406c51:	cmpl 0x422f6c, %edi
0x00406c57:	jne 0x00406c9f
0x00406c59:	pushl %edi
0x00406c5a:	pushl %edi
0x00406c5b:	pushl $0x1<UINT8>
0x00406c5d:	popl %ebx
0x00406c5e:	pushl %ebx
0x00406c5f:	pushl $0x4074ec<UINT32>
0x00406c64:	movl %esi, $0x100<UINT32>
0x00406c69:	pushl %esi
0x00406c6a:	pushl %edi
0x00406c6b:	call LCMapStringW@KERNEL32.DLL
LCMapStringW@KERNEL32.DLL: API Node	
0x00406c71:	testl %eax, %eax
0x00406c73:	je 8
0x00406c75:	movl 0x422f6c, %ebx
0x00406c7b:	jmp 0x00406c9f
0x00406c9f:	cmpl 0x14(%ebp), %edi
0x00406ca2:	jle 16
0x00406ca4:	pushl 0x14(%ebp)
0x00406ca7:	pushl 0x10(%ebp)
0x00406caa:	call 0x00406e4d
0x00406e4d:	movl %edx, 0x8(%esp)
0x00406e51:	movl %eax, 0x4(%esp)
0x00406e55:	testl %edx, %edx
0x00406e57:	pushl %esi
0x00406e58:	leal %ecx, -1(%edx)
0x00406e5b:	je 13
0x00406e5d:	cmpb (%eax), $0x0<UINT8>
0x00406e60:	je 8
0x00406e62:	incl %eax
0x00406e63:	movl %esi, %ecx
0x00406e65:	decl %ecx
0x00406e66:	testl %esi, %esi
0x00406e68:	jne 0x00406e5d
0x00406e6a:	cmpb (%eax), $0x0<UINT8>
0x00406e6d:	popl %esi
0x00406e6e:	jne 0x00406e75
0x00406e75:	movl %eax, %edx
0x00406e77:	ret

0x00406caf:	popl %ecx
0x00406cb0:	popl %ecx
0x00406cb1:	movl 0x14(%ebp), %eax
0x00406cb4:	movl %eax, 0x422f6c
0x00406cb9:	cmpl %eax, $0x2<UINT8>
0x00406cbc:	jne 0x00406cdb
0x00406cdb:	cmpl %eax, $0x1<UINT8>
0x00406cde:	jne 211
0x00406ce4:	cmpl 0x20(%ebp), %edi
0x00406ce7:	jne 0x00406cf1
0x00406cf1:	pushl %edi
0x00406cf2:	pushl %edi
0x00406cf3:	pushl 0x14(%ebp)
0x00406cf6:	pushl 0x10(%ebp)
0x00406cf9:	movl %eax, 0x24(%ebp)
0x00406cfc:	negl %eax
0x00406cfe:	sbbl %eax, %eax
0x00406d00:	andl %eax, $0x8<UINT8>
0x00406d03:	incl %eax
0x00406d04:	pushl %eax
0x00406d05:	pushl 0x20(%ebp)
0x00406d08:	call MultiByteToWideChar@KERNEL32.DLL
0x00406d0e:	movl %ebx, %eax
0x00406d10:	movl -28(%ebp), %ebx
0x00406d13:	cmpl %ebx, %edi
0x00406d15:	je 156
0x00406d1b:	movl -4(%ebp), %edi
0x00406d1e:	leal %eax, (%ebx,%ebx)
0x00406d21:	addl %eax, $0x3<UINT8>
0x00406d24:	andb %al, $0xfffffffc<UINT8>
0x00406d26:	call 0x00406830
0x00406d2b:	movl -24(%ebp), %esp
0x00406d2e:	movl %eax, %esp
0x00406d30:	movl -36(%ebp), %eax
0x00406d33:	orl -4(%ebp), $0xffffffff<UINT8>
0x00406d37:	jmp 0x00406d4c
0x00406d4c:	cmpl -36(%ebp), %edi
0x00406d4f:	je 102
0x00406d51:	pushl %ebx
0x00406d52:	pushl -36(%ebp)
0x00406d55:	pushl 0x14(%ebp)
0x00406d58:	pushl 0x10(%ebp)
0x00406d5b:	pushl $0x1<UINT8>
0x00406d5d:	pushl 0x20(%ebp)
0x00406d60:	call MultiByteToWideChar@KERNEL32.DLL
0x00406d66:	testl %eax, %eax
0x00406d68:	je 77
0x00406d6a:	pushl %edi
0x00406d6b:	pushl %edi
0x00406d6c:	pushl %ebx
0x00406d6d:	pushl -36(%ebp)
0x00406d70:	pushl 0xc(%ebp)
0x00406d73:	pushl 0x8(%ebp)
0x00406d76:	call LCMapStringW@KERNEL32.DLL
0x00406d7c:	movl %esi, %eax
0x00406d7e:	movl -40(%ebp), %esi
0x00406d81:	cmpl %esi, %edi
0x00406d83:	je 50
0x00406d85:	testb 0xd(%ebp), $0x4<UINT8>
0x00406d89:	je 0x00406dcb
0x00406dcb:	movl -4(%ebp), $0x1<UINT32>
0x00406dd2:	leal %eax, (%esi,%esi)
0x00406dd5:	addl %eax, $0x3<UINT8>
0x00406dd8:	andb %al, $0xfffffffc<UINT8>
0x00406dda:	call 0x00406830
0x00406ddf:	movl -24(%ebp), %esp
0x00406de2:	movl %ebx, %esp
0x00406de4:	movl -32(%ebp), %ebx
0x00406de7:	orl -4(%ebp), $0xffffffff<UINT8>
0x00406deb:	jmp 0x00406dff
0x00406dff:	cmpl %ebx, %edi
0x00406e01:	je -76
0x00406e03:	pushl %esi
0x00406e04:	pushl %ebx
0x00406e05:	pushl -28(%ebp)
0x00406e08:	pushl -36(%ebp)
0x00406e0b:	pushl 0xc(%ebp)
0x00406e0e:	pushl 0x8(%ebp)
0x00406e11:	call LCMapStringW@KERNEL32.DLL
0x00406e17:	testl %eax, %eax
0x00406e19:	je -100
0x00406e1b:	cmpl 0x1c(%ebp), %edi
0x00406e1e:	pushl %edi
0x00406e1f:	pushl %edi
0x00406e20:	jne 0x00406e26
0x00406e26:	pushl 0x1c(%ebp)
0x00406e29:	pushl 0x18(%ebp)
0x00406e2c:	pushl %esi
0x00406e2d:	pushl %ebx
0x00406e2e:	pushl $0x220<UINT32>
0x00406e33:	pushl 0x20(%ebp)
0x00406e36:	call WideCharToMultiByte@KERNEL32.DLL
0x00406e3c:	movl %esi, %eax
0x00406e3e:	cmpl %esi, %edi
0x00406e40:	je -143
0x00406e46:	movl %eax, %esi
0x00406e48:	jmp 0x00406db9
0x00406db9:	leal %esp, -56(%ebp)
0x00406dbc:	movl %ecx, -16(%ebp)
0x00406dbf:	movl %fs:0, %ecx
0x00406dc6:	popl %edi
0x00406dc7:	popl %esi
0x00406dc8:	popl %ebx
0x00406dc9:	leave
0x00406dca:	ret

0x00406194:	pushl $0x0<UINT8>
0x00406196:	leal %eax, -788(%ebp)
0x0040619c:	pushl 0x422fb0
0x004061a2:	pushl %esi
0x004061a3:	pushl %eax
0x004061a4:	leal %eax, -276(%ebp)
0x004061aa:	pushl %esi
0x004061ab:	pushl %eax
0x004061ac:	pushl $0x200<UINT32>
0x004061b1:	pushl 0x4231e4
0x004061b7:	call 0x00406c29
0x004061bc:	addl %esp, $0x5c<UINT8>
0x004061bf:	xorl %eax, %eax
0x004061c1:	leal %ecx, -1300(%ebp)
0x004061c7:	movw %dx, (%ecx)
0x004061ca:	testb %dl, $0x1<UINT8>
0x004061cd:	je 0x004061e5
0x004061e5:	testb %dl, $0x2<UINT8>
0x004061e8:	je 0x004061fa
0x004061fa:	andb 0x422fe0(%eax), $0x0<UINT8>
0x00406201:	incl %eax
0x00406202:	incl %ecx
0x00406203:	incl %ecx
0x00406204:	cmpl %eax, %esi
0x00406206:	jb 0x004061c7
0x004061cf:	orb 0x4230e1(%eax), $0x10<UINT8>
0x004061d6:	movb %dl, -532(%ebp,%eax)
0x004061dd:	movb 0x422fe0(%eax), %dl
0x004061e3:	jmp 0x00406201
0x004061ea:	orb 0x4230e1(%eax), $0x20<UINT8>
0x004061f1:	movb %dl, -788(%ebp,%eax)
0x004061f8:	jmp 0x004061dd
0x00406208:	jmp 0x00406253
0x00406253:	popl %esi
0x00406254:	leave
0x00406255:	ret

0x0040601f:	xorl %eax, %eax
0x00406021:	jmp 0x00406026
0x00406026:	popl %edi
0x00406027:	popl %esi
0x00406028:	popl %ebx
0x00406029:	leave
0x0040602a:	ret

0x00406266:	popl %ecx
0x00406267:	movl 0x423308, $0x1<UINT32>
0x00406271:	ret

0x004048bb:	movl %esi, $0x422e2c<UINT32>
0x004048c0:	pushl $0x104<UINT32>
0x004048c5:	pushl %esi
0x004048c6:	pushl %ebx
0x004048c7:	call GetModuleFileNameA@KERNEL32.DLL
GetModuleFileNameA@KERNEL32.DLL: API Node	
0x004048cd:	movl %eax, 0x424344
0x004048d2:	movl 0x422e14, %esi
0x004048d8:	movl %edi, %esi
0x004048da:	cmpb (%eax), %bl
0x004048dc:	je 2
0x004048de:	movl %edi, %eax
0x004048e0:	leal %eax, -8(%ebp)
0x004048e3:	pushl %eax
0x004048e4:	leal %eax, -4(%ebp)
0x004048e7:	pushl %eax
0x004048e8:	pushl %ebx
0x004048e9:	pushl %ebx
0x004048ea:	pushl %edi
0x004048eb:	call 0x0040493d
0x0040493d:	pushl %ebp
0x0040493e:	movl %ebp, %esp
0x00404940:	movl %ecx, 0x18(%ebp)
0x00404943:	movl %eax, 0x14(%ebp)
0x00404946:	pushl %ebx
0x00404947:	pushl %esi
0x00404948:	andl (%ecx), $0x0<UINT8>
0x0040494b:	movl %esi, 0x10(%ebp)
0x0040494e:	pushl %edi
0x0040494f:	movl %edi, 0xc(%ebp)
0x00404952:	movl (%eax), $0x1<UINT32>
0x00404958:	movl %eax, 0x8(%ebp)
0x0040495b:	testl %edi, %edi
0x0040495d:	je 0x00404967
0x00404967:	cmpb (%eax), $0x22<UINT8>
0x0040496a:	jne 68
0x0040496c:	movb %dl, 0x1(%eax)
0x0040496f:	incl %eax
0x00404970:	cmpb %dl, $0x22<UINT8>
0x00404973:	je 0x0040499e
0x00404975:	testb %dl, %dl
0x00404977:	je 37
0x00404979:	movzbl %edx, %dl
0x0040497c:	testb 0x4230e1(%edx), $0x4<UINT8>
0x00404983:	je 0x00404991
0x00404991:	incl (%ecx)
0x00404993:	testl %esi, %esi
0x00404995:	je 0x0040496c
0x0040499e:	incl (%ecx)
0x004049a0:	testl %esi, %esi
0x004049a2:	je 0x004049a8
0x004049a8:	cmpb (%eax), $0x22<UINT8>
0x004049ab:	jne 70
0x004049ad:	incl %eax
0x004049ae:	jmp 0x004049f3
0x004049f3:	andl 0x18(%ebp), $0x0<UINT8>
0x004049f7:	cmpb (%eax), $0x0<UINT8>
0x004049fa:	je 0x00404ae0
0x00404ae0:	testl %edi, %edi
0x00404ae2:	je 0x00404ae7
0x00404ae7:	movl %eax, 0x14(%ebp)
0x00404aea:	popl %edi
0x00404aeb:	popl %esi
0x00404aec:	popl %ebx
0x00404aed:	incl (%eax)
0x00404aef:	popl %ebp
0x00404af0:	ret

0x004048f0:	movl %eax, -8(%ebp)
0x004048f3:	movl %ecx, -4(%ebp)
0x004048f6:	leal %eax, (%eax,%ecx,4)
0x004048f9:	pushl %eax
0x004048fa:	call 0x0040236b
0x00403fa1:	movl %ecx, 0x4(%ebx)
0x00403fa4:	movl %edi, (%ebx)
0x00403fa6:	andl %ecx, -8(%ebp)
0x00403fa9:	andl %edi, %esi
0x00403fab:	orl %ecx, %edi
0x00403fad:	jne 0x00403fba
0x004048ff:	movl %esi, %eax
0x00404901:	addl %esp, $0x18<UINT8>
0x00404904:	cmpl %esi, %ebx
0x00404906:	jne 0x00404910
0x00404910:	leal %eax, -8(%ebp)
0x00404913:	pushl %eax
0x00404914:	leal %eax, -4(%ebp)
0x00404917:	pushl %eax
0x00404918:	movl %eax, -4(%ebp)
0x0040491b:	leal %eax, (%esi,%eax,4)
0x0040491e:	pushl %eax
0x0040491f:	pushl %esi
0x00404920:	pushl %edi
0x00404921:	call 0x0040493d
0x0040495f:	movl (%edi), %esi
0x00404961:	addl %edi, $0x4<UINT8>
0x00404964:	movl 0xc(%ebp), %edi
0x00404997:	movb %dl, (%eax)
0x00404999:	movb (%esi), %dl
0x0040499b:	incl %esi
0x0040499c:	jmp 0x0040496c
0x004049a4:	andb (%esi), $0x0<UINT8>
0x004049a7:	incl %esi
0x00404ae4:	andl (%edi), $0x0<UINT8>
0x00404926:	movl %eax, -4(%ebp)
0x00404929:	addl %esp, $0x14<UINT8>
0x0040492c:	decl %eax
0x0040492d:	movl 0x422dfc, %esi
0x00404933:	popl %edi
0x00404934:	popl %esi
0x00404935:	movl 0x422df8, %eax
0x0040493a:	popl %ebx
0x0040493b:	leave
0x0040493c:	ret

0x00402530:	call 0x004047eb
0x004047eb:	pushl %ebx
0x004047ec:	xorl %ebx, %ebx
0x004047ee:	cmpl 0x423308, %ebx
0x004047f4:	pushl %esi
0x004047f5:	pushl %edi
0x004047f6:	jne 0x004047fd
0x004047fd:	movl %esi, 0x422dbc
0x00404803:	xorl %edi, %edi
0x00404805:	movb %al, (%esi)
0x00404807:	cmpb %al, %bl
0x00404809:	je 0x0040481d
0x0040480b:	cmpb %al, $0x3d<UINT8>
0x0040480d:	je 0x00404810
0x00404810:	pushl %esi
0x00404811:	call 0x00403150
0x00403150:	movl %ecx, 0x4(%esp)
0x00403154:	testl %ecx, $0x3<UINT32>
0x0040315a:	je 0x00403170
0x00403170:	movl %eax, (%ecx)
0x00403172:	movl %edx, $0x7efefeff<UINT32>
0x00403177:	addl %edx, %eax
0x00403179:	xorl %eax, $0xffffffff<UINT8>
0x0040317c:	xorl %eax, %edx
0x0040317e:	addl %ecx, $0x4<UINT8>
0x00403181:	testl %eax, $0x81010100<UINT32>
0x00403186:	je 0x00403170
0x00403188:	movl %eax, -4(%ecx)
0x0040318b:	testb %al, %al
0x0040318d:	je 50
0x0040318f:	testb %ah, %ah
0x00403191:	je 36
0x00403193:	testl %eax, $0xff0000<UINT32>
0x00403198:	je 19
0x0040319a:	testl %eax, $0xff000000<UINT32>
0x0040319f:	je 0x004031a3
0x004031a3:	leal %eax, -1(%ecx)
0x004031a6:	movl %ecx, 0x4(%esp)
0x004031aa:	subl %eax, %ecx
0x004031ac:	ret

0x00404816:	popl %ecx
0x00404817:	leal %esi, 0x1(%esi,%eax)
0x0040481b:	jmp 0x00404805
0x0040481d:	leal %eax, 0x4(,%edi,4)
0x00404824:	pushl %eax
0x00404825:	call 0x0040236b
0x0040482a:	movl %esi, %eax
0x0040482c:	popl %ecx
0x0040482d:	cmpl %esi, %ebx
0x0040482f:	movl 0x422e04, %esi
0x00404835:	jne 0x0040483f
0x0040483f:	movl %edi, 0x422dbc
0x00404845:	cmpb (%edi), %bl
0x00404847:	je 57
0x00404849:	pushl %ebp
0x0040484a:	pushl %edi
0x0040484b:	call 0x00403150
0x00404850:	movl %ebp, %eax
0x00404852:	popl %ecx
0x00404853:	incl %ebp
0x00404854:	cmpb (%edi), $0x3d<UINT8>
0x00404857:	je 0x0040487b
0x0040487b:	addl %edi, %ebp
0x0040487d:	cmpb (%edi), %bl
0x0040487f:	jne -55
0x00404881:	popl %ebp
0x00404882:	pushl 0x422dbc
0x00404888:	call 0x00402431
0x00402431:	pushl %esi
0x00402432:	movl %esi, 0x8(%esp)
0x00402436:	testl %esi, %esi
0x00402438:	je 36
0x0040243a:	pushl %esi
0x0040243b:	call 0x00403bed
0x00403bed:	movl %eax, 0x423328
0x00403bf2:	leal %ecx, (%eax,%eax,4)
0x00403bf5:	movl %eax, 0x42332c
0x00403bfa:	leal %ecx, (%eax,%ecx,4)
0x00403bfd:	cmpl %eax, %ecx
0x00403bff:	jae 0x00403c15
0x00403c01:	movl %edx, 0x4(%esp)
0x00403c05:	subl %edx, 0xc(%eax)
0x00403c08:	cmpl %edx, $0x100000<UINT32>
0x00403c0e:	jb 7
0x00403c10:	addl %eax, $0x14<UINT8>
0x00403c13:	jmp 0x00403bfd
0x00403c15:	xorl %eax, %eax
0x00403c17:	ret

0x00402440:	popl %ecx
0x00402441:	testl %eax, %eax
0x00402443:	pushl %esi
0x00402444:	je 0x00402450
0x00402450:	pushl $0x0<UINT8>
0x00402452:	pushl 0x423330
0x00402458:	call HeapFree@KERNEL32.DLL
HeapFree@KERNEL32.DLL: API Node	
0x0040245e:	popl %esi
0x0040245f:	ret

0x0040488d:	popl %ecx
0x0040488e:	movl 0x422dbc, %ebx
0x00404894:	movl (%esi), %ebx
0x00404896:	popl %edi
0x00404897:	popl %esi
0x00404898:	movl 0x423304, $0x1<UINT32>
0x004048a2:	popl %ebx
0x004048a3:	ret

0x00402535:	call 0x0040450d
0x0040450d:	movl %eax, 0x423314
0x00404512:	testl %eax, %eax
0x00404514:	je 0x00404518
0x00404518:	pushl $0x408014<UINT32>
0x0040451d:	pushl $0x408008<UINT32>
0x00404522:	call 0x004045f5
0x004045f5:	pushl %esi
0x004045f6:	movl %esi, 0x8(%esp)
0x004045fa:	cmpl %esi, 0xc(%esp)
0x004045fe:	jae 0x0040460d
0x00404600:	movl %eax, (%esi)
0x00404602:	testl %eax, %eax
0x00404604:	je 0x00404608
0x00404608:	addl %esi, $0x4<UINT8>
0x0040460b:	jmp 0x004045fa
0x00404606:	call 0x00406256
0x00403a9f:	movl %eax, 0x424340
0x00403aa4:	pushl %esi
0x00403aa5:	pushl $0x14<UINT8>
0x00403aa7:	testl %eax, %eax
0x00403aa9:	popl %esi
0x00403aaa:	jne 7
0x00403aac:	movl %eax, $0x200<UINT32>
0x00403ab1:	jmp 0x00403ab9
0x00403ab9:	movl 0x424340, %eax
0x00403abe:	pushl $0x4<UINT8>
0x00403ac0:	pushl %eax
0x00403ac1:	call 0x004057b5
0x004057b5:	pushl %ebx
0x004057b6:	pushl %esi
0x004057b7:	movl %esi, 0xc(%esp)
0x004057bb:	pushl %edi
0x004057bc:	imull %esi, 0x14(%esp)
0x004057c1:	cmpl %esi, $0xffffffe0<UINT8>
0x004057c4:	movl %ebx, %esi
0x004057c6:	ja 13
0x004057c8:	testl %esi, %esi
0x004057ca:	jne 0x004057cf
0x004057cf:	addl %esi, $0xf<UINT8>
0x004057d2:	andl %esi, $0xfffffff0<UINT8>
0x004057d5:	xorl %edi, %edi
0x004057d7:	cmpl %esi, $0xffffffe0<UINT8>
0x004057da:	ja 42
0x004057dc:	cmpl %ebx, 0x4229fc
0x004057e2:	ja 0x004057f1
0x004057f1:	pushl %esi
0x004057f2:	pushl $0x8<UINT8>
0x004057f4:	pushl 0x423330
0x004057fa:	call HeapAlloc@KERNEL32.DLL
0x00405800:	movl %edi, %eax
0x00405802:	testl %edi, %edi
0x00405804:	jne 0x00405828
0x00405828:	movl %eax, %edi
0x0040582a:	popl %edi
0x0040582b:	popl %esi
0x0040582c:	popl %ebx
0x0040582d:	ret

0x00403ac6:	popl %ecx
0x00403ac7:	movl 0x423334, %eax
0x00403acc:	testl %eax, %eax
0x00403ace:	popl %ecx
0x00403acf:	jne 0x00403af2
0x00403af2:	xorl %ecx, %ecx
0x00403af4:	movl %eax, $0x422778<UINT32>
0x00403af9:	movl %edx, 0x423334
0x00403aff:	movl (%ecx,%edx), %eax
0x00403b02:	addl %eax, $0x20<UINT8>
0x00403b05:	addl %ecx, $0x4<UINT8>
0x00403b08:	cmpl %eax, $0x4229f8<UINT32>
0x00403b0d:	jl 0x00403af9
0x00403b0f:	xorl %edx, %edx
0x00403b11:	movl %ecx, $0x422788<UINT32>
0x00403b16:	movl %eax, %edx
0x00403b18:	movl %esi, %edx
0x00403b1a:	sarl %eax, $0x5<UINT8>
0x00403b1d:	andl %esi, $0x1f<UINT8>
0x00403b20:	movl %eax, 0x423200(,%eax,4)
0x00403b27:	movl %eax, (%eax,%esi,8)
0x00403b2a:	cmpl %eax, $0xffffffff<UINT8>
0x00403b2d:	je 4
0x00403b2f:	testl %eax, %eax
0x00403b31:	jne 0x00403b36
0x00403b36:	addl %ecx, $0x20<UINT8>
0x00403b39:	incl %edx
0x00403b3a:	cmpl %ecx, $0x4227e8<UINT32>
0x00403b40:	jl 0x00403b16
0x00403b42:	popl %esi
0x00403b43:	ret

0x0040460d:	popl %esi
0x0040460e:	ret

0x00404527:	pushl $0x408004<UINT32>
0x0040452c:	pushl $0x408000<UINT32>
0x00404531:	call 0x004045f5
0x00404536:	addl %esp, $0x10<UINT8>
0x00404539:	ret

0x0040253a:	movl -48(%ebp), %esi
0x0040253d:	leal %eax, -92(%ebp)
0x00402540:	pushl %eax
0x00402541:	call GetStartupInfoA@KERNEL32.DLL
0x00402547:	call 0x00404793
0x00404793:	cmpl 0x423308, $0x0<UINT8>
0x0040479a:	jne 0x004047a1
0x004047a1:	pushl %esi
0x004047a2:	movl %esi, 0x424344
0x004047a8:	movb %al, (%esi)
0x004047aa:	cmpb %al, $0x22<UINT8>
0x004047ac:	jne 37
0x004047ae:	movb %al, 0x1(%esi)
0x004047b1:	incl %esi
0x004047b2:	cmpb %al, $0x22<UINT8>
0x004047b4:	je 0x004047cb
0x004047b6:	testb %al, %al
0x004047b8:	je 17
0x004047ba:	movzbl %eax, %al
0x004047bd:	pushl %eax
0x004047be:	call 0x00405e50
0x00405e50:	pushl $0x4<UINT8>
0x00405e52:	pushl $0x0<UINT8>
0x00405e54:	pushl 0xc(%esp)
0x00405e58:	call 0x00405e61
0x00405e61:	movzbl %eax, 0x4(%esp)
0x00405e66:	movb %cl, 0xc(%esp)
0x00405e6a:	testb 0x4230e1(%eax), %cl
0x00405e70:	jne 28
0x00405e72:	cmpl 0x8(%esp), $0x0<UINT8>
0x00405e77:	je 0x00405e87
0x00405e87:	xorl %eax, %eax
0x00405e89:	testl %eax, %eax
0x00405e8b:	jne 1
0x00405e8d:	ret

0x00405e5d:	addl %esp, $0xc<UINT8>
0x00405e60:	ret

0x004047c3:	testl %eax, %eax
0x004047c5:	popl %ecx
0x004047c6:	je 0x004047ae
0x004047cb:	cmpb (%esi), $0x22<UINT8>
0x004047ce:	jne 13
0x004047d0:	incl %esi
0x004047d1:	jmp 0x004047dd
0x004047dd:	movb %al, (%esi)
0x004047df:	testb %al, %al
0x004047e1:	je 0x004047e7
0x004047e7:	movl %eax, %esi
0x004047e9:	popl %esi
0x004047ea:	ret

0x0040254c:	movl -100(%ebp), %eax
0x0040254f:	testb -48(%ebp), $0x1<UINT8>
0x00402553:	je 0x0040255b
0x0040255b:	pushl $0xa<UINT8>
0x0040255d:	popl %eax
0x0040255e:	pushl %eax
0x0040255f:	pushl -100(%ebp)
0x00402562:	pushl %esi
0x00402563:	pushl %esi
0x00402564:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x0040256a:	pushl %eax
0x0040256b:	call 0x00401800
0x00401800:	subl %esp, $0x80<UINT32>
0x00401806:	pushl %ebx
0x00401807:	pushl %esi
0x00401808:	pushl $0x408268<UINT32>
0x0040180d:	call 0x00401c00
0x00401c00:	subl %esp, $0x110<UINT32>
0x00401c06:	movl %eax, 0x114(%esp)
0x00401c0d:	pushl %ebx
0x00401c0e:	pushl %eax
0x00401c0f:	leal %ecx, 0x14(%esp)
0x00401c13:	xorl %ebx, %ebx
0x00401c15:	pushl $0x4224f4<UINT32>
0x00401c1a:	pushl %ecx
0x00401c1b:	movl 0x14(%esp), %ebx
0x00401c1f:	movl 0x10(%esp), %ebx
0x00401c23:	call 0x004023df
0x004023df:	pushl %ebp
0x004023e0:	movl %ebp, %esp
0x004023e2:	subl %esp, $0x20<UINT8>
0x004023e5:	movl %eax, 0x8(%ebp)
0x004023e8:	pushl %esi
0x004023e9:	movl -24(%ebp), %eax
0x004023ec:	movl -32(%ebp), %eax
0x004023ef:	leal %eax, 0x10(%ebp)
0x004023f2:	movl -20(%ebp), $0x42<UINT32>
0x004023f9:	pushl %eax
0x004023fa:	leal %eax, -32(%ebp)
0x004023fd:	pushl 0xc(%ebp)
0x00402400:	movl -28(%ebp), $0x7fffffff<UINT32>
0x00402407:	pushl %eax
0x00402408:	call 0x00403295
0x00403295:	pushl %ebp
0x00403296:	movl %ebp, %esp
0x00403298:	subl %esp, $0x248<UINT32>
0x0040329e:	pushl %ebx
0x0040329f:	pushl %esi
0x004032a0:	pushl %edi
0x004032a1:	movl %edi, 0xc(%ebp)
0x004032a4:	xorl %esi, %esi
0x004032a6:	movb %bl, (%edi)
0x004032a8:	incl %edi
0x004032a9:	testb %bl, %bl
0x004032ab:	movl -12(%ebp), %esi
0x004032ae:	movl -20(%ebp), %esi
0x004032b1:	movl 0xc(%ebp), %edi
0x004032b4:	je 1780
0x004032ba:	movl %ecx, -16(%ebp)
0x004032bd:	xorl %edx, %edx
0x004032bf:	jmp 0x004032c9
0x004032c9:	cmpl -20(%ebp), %edx
0x004032cc:	jl 1756
0x004032d2:	cmpb %bl, $0x20<UINT8>
0x004032d5:	jl 19
0x004032d7:	cmpb %bl, $0x78<UINT8>
0x004032da:	jg 0x004032ea
0x004032dc:	movsbl %eax, %bl
0x004032df:	movb %al, 0x407164(%eax)
0x004032e5:	andl %eax, $0xf<UINT8>
0x004032e8:	jmp 0x004032ec
0x004032ec:	movsbl %eax, 0x407184(%esi,%eax,8)
0x004032f4:	sarl %eax, $0x4<UINT8>
0x004032f7:	cmpl %eax, $0x7<UINT8>
0x004032fa:	movl -48(%ebp), %eax
0x004032fd:	ja 1690
0x00403303:	jmp 0x00403478
0x00403434:	movl %ecx, 0x422548
0x0040343a:	movl -36(%ebp), %edx
0x0040343d:	movzbl %eax, %bl
0x00403440:	testb 0x1(%ecx,%eax,2), $0xffffff80<UINT8>
0x00403445:	je 0x00403460
0x00403460:	leal %eax, -20(%ebp)
0x00403463:	pushl %eax
0x00403464:	pushl 0x8(%ebp)
0x00403467:	movsbl %eax, %bl
0x0040346a:	pushl %eax
0x0040346b:	call 0x004039d6
0x004039d6:	pushl %ebp
0x004039d7:	movl %ebp, %esp
0x004039d9:	movl %ecx, 0xc(%ebp)
0x004039dc:	decl 0x4(%ecx)
0x004039df:	js 14
0x004039e1:	movl %edx, (%ecx)
0x004039e3:	movb %al, 0x8(%ebp)
0x004039e6:	movb (%edx), %al
0x004039e8:	incl (%ecx)
0x004039ea:	movzbl %eax, %al
0x004039ed:	jmp 0x004039fa
0x004039fa:	cmpl %eax, $0xffffffff<UINT8>
0x004039fd:	movl %eax, 0x10(%ebp)
0x00403a00:	jne 0x00403a07
0x00403a07:	incl (%eax)
0x00403a09:	popl %ebp
0x00403a0a:	ret

0x00403470:	addl %esp, $0xc<UINT8>
0x00403473:	jmp 0x0040399d
0x0040399d:	movl %edi, 0xc(%ebp)
0x004039a0:	movb %bl, (%edi)
0x004039a2:	incl %edi
0x004039a3:	testb %bl, %bl
0x004039a5:	movl 0xc(%ebp), %edi
0x004039a8:	jne 0x004032c1
0x004032c1:	movl %ecx, -16(%ebp)
0x004032c4:	movl %esi, -48(%ebp)
0x004032c7:	xorl %edx, %edx
0x004032ea:	xorl %eax, %eax
0x0040330a:	orl -16(%ebp), $0xffffffff<UINT8>
0x0040330e:	movl -52(%ebp), %edx
0x00403311:	movl -40(%ebp), %edx
0x00403314:	movl -32(%ebp), %edx
0x00403317:	movl -28(%ebp), %edx
0x0040331a:	movl -4(%ebp), %edx
0x0040331d:	movl -36(%ebp), %edx
0x00403320:	jmp 0x0040399d
0x00403478:	movsbl %eax, %bl
0x0040347b:	cmpl %eax, $0x67<UINT8>
0x0040347e:	jg 0x004036a0
0x004036a0:	subl %eax, $0x69<UINT8>
0x004036a3:	je 209
0x004036a9:	subl %eax, $0x5<UINT8>
0x004036ac:	je 158
0x004036b2:	decl %eax
0x004036b3:	je 132
0x004036b9:	decl %eax
0x004036ba:	je 81
0x004036bc:	subl %eax, $0x3<UINT8>
0x004036bf:	je 0x004034c2
0x004034c2:	movl %esi, -16(%ebp)
0x004034c5:	cmpl %esi, $0xffffffff<UINT8>
0x004034c8:	jne 5
0x004034ca:	movl %esi, $0x7fffffff<UINT32>
0x004034cf:	leal %eax, 0x10(%ebp)
0x004034d2:	pushl %eax
0x004034d3:	call 0x00403a74
0x00403a74:	movl %eax, 0x4(%esp)
0x00403a78:	addl (%eax), $0x4<UINT8>
0x00403a7b:	movl %eax, (%eax)
0x00403a7d:	movl %eax, -4(%eax)
0x00403a80:	ret

0x004034d8:	testw -4(%ebp), $0x810<UINT16>
0x004034de:	popl %ecx
0x004034df:	movl %ecx, %eax
0x004034e1:	movl -8(%ebp), %ecx
0x004034e4:	je 0x004036e8
0x004036e8:	testl %ecx, %ecx
0x004036ea:	jne 0x004036f5
0x004036f5:	movl %eax, %ecx
0x004036f7:	movl %edx, %esi
0x004036f9:	decl %esi
0x004036fa:	testl %edx, %edx
0x004036fc:	je 8
0x004036fe:	cmpb (%eax), $0x0<UINT8>
0x00403701:	je 0x00403706
0x00403703:	incl %eax
0x00403704:	jmp 0x004036f7
0x00403706:	subl %eax, %ecx
0x00403708:	jmp 0x0040389c
0x0040389c:	movl -12(%ebp), %eax
0x0040389f:	cmpl -40(%ebp), $0x0<UINT8>
0x004038a3:	jne 244
0x004038a9:	movl %ebx, -4(%ebp)
0x004038ac:	testb %bl, $0x40<UINT8>
0x004038af:	je 0x004038d7
0x004038d7:	movl %esi, -32(%ebp)
0x004038da:	subl %esi, -28(%ebp)
0x004038dd:	subl %esi, -12(%ebp)
0x004038e0:	testb %bl, $0xc<UINT8>
0x004038e3:	jne 18
0x004038e5:	leal %eax, -20(%ebp)
0x004038e8:	pushl %eax
0x004038e9:	pushl 0x8(%ebp)
0x004038ec:	pushl %esi
0x004038ed:	pushl $0x20<UINT8>
0x004038ef:	call 0x00403a0b
0x00403a0b:	pushl %esi
0x00403a0c:	pushl %edi
0x00403a0d:	movl %edi, 0x10(%esp)
0x00403a11:	movl %eax, %edi
0x00403a13:	decl %edi
0x00403a14:	testl %eax, %eax
0x00403a16:	jle 0x00403a39
0x00403a39:	popl %edi
0x00403a3a:	popl %esi
0x00403a3b:	ret

0x004038f4:	addl %esp, $0x10<UINT8>
0x004038f7:	leal %eax, -20(%ebp)
0x004038fa:	pushl %eax
0x004038fb:	leal %eax, -22(%ebp)
0x004038fe:	pushl 0x8(%ebp)
0x00403901:	pushl -28(%ebp)
0x00403904:	pushl %eax
0x00403905:	call 0x00403a3c
0x00403a3c:	pushl %ebx
0x00403a3d:	movl %ebx, 0xc(%esp)
0x00403a41:	movl %eax, %ebx
0x00403a43:	decl %ebx
0x00403a44:	pushl %esi
0x00403a45:	pushl %edi
0x00403a46:	testl %eax, %eax
0x00403a48:	jle 0x00403a70
0x00403a70:	popl %edi
0x00403a71:	popl %esi
0x00403a72:	popl %ebx
0x00403a73:	ret

0x0040390a:	addl %esp, $0x10<UINT8>
0x0040390d:	testb %bl, $0x8<UINT8>
0x00403910:	je 0x00403929
0x00403929:	cmpl -36(%ebp), $0x0<UINT8>
0x0040392d:	je 0x00403970
0x00403970:	leal %eax, -20(%ebp)
0x00403973:	pushl %eax
0x00403974:	pushl 0x8(%ebp)
0x00403977:	pushl -12(%ebp)
0x0040397a:	pushl -8(%ebp)
0x0040397d:	call 0x00403a3c
0x00403a4a:	movl %edi, 0x1c(%esp)
0x00403a4e:	movl %esi, 0x10(%esp)
0x00403a52:	movsbl %eax, (%esi)
0x00403a55:	pushl %edi
0x00403a56:	incl %esi
0x00403a57:	pushl 0x1c(%esp)
0x00403a5b:	pushl %eax
0x00403a5c:	call 0x004039d6
0x00403a61:	addl %esp, $0xc<UINT8>
0x00403a64:	cmpl (%edi), $0xffffffff<UINT8>
0x00403a67:	je 7
0x00403a69:	movl %eax, %ebx
0x00403a6b:	decl %ebx
0x00403a6c:	testl %eax, %eax
0x00403a6e:	jg 0x00403a52
0x00403982:	addl %esp, $0x10<UINT8>
0x00403985:	testb -4(%ebp), $0x4<UINT8>
0x00403989:	je 0x0040399d
0x004039ae:	movl %eax, -20(%ebp)
0x004039b1:	popl %edi
0x004039b2:	popl %esi
0x004039b3:	popl %ebx
0x004039b4:	leave
0x004039b5:	ret

0x0040240d:	addl %esp, $0xc<UINT8>
0x00402410:	decl -28(%ebp)
0x00402413:	movl %esi, %eax
0x00402415:	js 8
0x00402417:	movl %eax, -32(%ebp)
0x0040241a:	andb (%eax), $0x0<UINT8>
0x0040241d:	jmp 0x0040242c
0x0040242c:	movl %eax, %esi
0x0040242e:	popl %esi
0x0040242f:	leave
0x00402430:	ret

0x00401c28:	addl %esp, $0xc<UINT8>
0x00401c2b:	leal %edx, 0x8(%esp)
0x00401c2f:	leal %eax, 0x10(%esp)
0x00401c33:	pushl %edx
0x00401c34:	pushl %eax
0x00401c35:	pushl $0x80000001<UINT32>
0x00401c3a:	call RegCreateKeyA@ADVAPI32.dll
RegCreateKeyA@ADVAPI32.dll: API Node	
0x00401c40:	testl %eax, %eax
0x00401c42:	jne 36
0x00401c44:	movl %eax, 0x8(%esp)
0x00401c48:	leal %ecx, 0xc(%esp)
0x00401c4c:	leal %edx, 0x4(%esp)
0x00401c50:	pushl %ecx
0x00401c51:	pushl %edx
0x00401c52:	pushl %ebx
0x00401c53:	pushl %ebx
0x00401c54:	pushl $0x4224e4<UINT32>
0x00401c59:	pushl %eax
0x00401c5a:	movl 0x24(%esp), $0x4<UINT32>
0x00401c62:	call RegQueryValueExA@ADVAPI32.dll
RegQueryValueExA@ADVAPI32.dll: API Node	
0x00401c68:	cmpl 0x4(%esp), %ebx
0x00401c6c:	jne 511
0x00401c72:	pushl %esi
0x00401c73:	pushl %edi
0x00401c74:	pushl $0x3e8<UINT32>
0x00401c79:	pushl $0x40<UINT8>
0x00401c7b:	call LocalAlloc@KERNEL32.DLL
LocalAlloc@KERNEL32.DLL: API Node	
0x00401c81:	movl %esi, %eax
0x00401c83:	pushl $0x4224d4<UINT32>
0x00401c88:	leal %edi, 0x12(%esi)
0x00401c8b:	call LoadLibraryA@KERNEL32.DLL
0x00401c91:	movl (%esi), $0x80c808d0<UINT32>
0x00404ec8:	pushl %ebp
0x00404ec9:	movl %ebp, %esp
0x00404ecb:	subl %esp, $0x8<UINT8>
0x00404ece:	pushl %ebx
0x00404ecf:	pushl %esi
0x00404ed0:	pushl %edi
0x00404ed1:	pushl %ebp
0x00404ed2:	cld
0x00404ed3:	movl %ebx, 0xc(%ebp)
0x00404ed6:	movl %eax, 0x8(%ebp)
0x00404ed9:	testl 0x4(%eax), $0x6<UINT32>
0x00404ee0:	jne 130
0x00404ee6:	movl -8(%ebp), %eax
0x00404ee9:	movl %eax, 0x10(%ebp)
0x00404eec:	movl -4(%ebp), %eax
0x00404eef:	leal %eax, -8(%ebp)
0x00404ef2:	movl -4(%ebx), %eax
0x00404ef5:	movl %esi, 0xc(%ebx)
0x00404ef8:	movl %edi, 0x8(%ebx)
0x00404efb:	cmpl %esi, $0xffffffff<UINT8>
0x00404efe:	je 97
0x00404f00:	leal %ecx, (%esi,%esi,2)
0x00404f03:	cmpl 0x4(%edi,%ecx,4), $0x0<UINT8>
0x00404f08:	je 69
0x00404f0a:	pushl %esi
0x00404f0b:	pushl %ebp
0x00404f0c:	leal %ebp, 0x10(%ebx)
0x00404f0f:	call 0x00402579
0x00402579:	movl %eax, -20(%ebp)
0x0040257c:	movl %ecx, (%eax)
0x0040257e:	movl %ecx, (%ecx)
0x00402580:	movl -104(%ebp), %ecx
0x00402583:	pushl %eax
0x00402584:	pushl %ecx
0x00402585:	call 0x0040460f
0x0040460f:	pushl %ebp
0x00404610:	movl %ebp, %esp
0x00404612:	pushl %ebx
0x00404613:	pushl 0x8(%ebp)
0x00404616:	call 0x00404750
0x00404750:	movl %edx, 0x4(%esp)
0x00404754:	movl %ecx, 0x422a80
0x0040475a:	cmpl 0x422a00, %edx
0x00404760:	pushl %esi
0x00404761:	movl %eax, $0x422a00<UINT32>
0x00404766:	je 0x0040477d
0x0040477d:	leal %ecx, (%ecx,%ecx,2)
0x00404780:	popl %esi
0x00404781:	leal %ecx, 0x422a00(,%ecx,4)
0x00404788:	cmpl %eax, %ecx
0x0040478a:	jae 4
0x0040478c:	cmpl (%eax), %edx
0x0040478e:	je 0x00404792
0x00404792:	ret

0x0040461b:	testl %eax, %eax
0x0040461d:	popl %ecx
0x0040461e:	je 288
0x00404624:	movl %ebx, 0x8(%eax)
0x00404627:	testl %ebx, %ebx
0x00404629:	je 0x00404744
0x00404744:	pushl 0xc(%ebp)
0x00404747:	call UnhandledExceptionFilter@KERNEL32.DLL
UnhandledExceptionFilter@KERNEL32.DLL: API Node	
0x0040474d:	popl %ebx
0x0040474e:	popl %ebp
0x0040474f:	ret

0x0040258a:	popl %ecx
0x0040258b:	popl %ecx
0x0040258c:	ret

0x00404f13:	popl %ebp
0x00404f14:	popl %esi
0x00404f15:	movl %ebx, 0xc(%ebp)
0x00404f18:	orl %eax, %eax
0x00404f1a:	je 51
0x00404f1c:	js 60
0x00404f1e:	movl %edi, 0x8(%ebx)
0x00404f21:	pushl %ebx
0x00404f22:	call 0x00404dd0
0x00404dd0:	pushl %ebp
0x00404dd1:	movl %ebp, %esp
0x00404dd3:	pushl %ebx
0x00404dd4:	pushl %esi
0x00404dd5:	pushl %edi
0x00404dd6:	pushl %ebp
0x00404dd7:	pushl $0x0<UINT8>
0x00404dd9:	pushl $0x0<UINT8>
0x00404ddb:	pushl $0x404de8<UINT32>
0x00404de0:	pushl 0x8(%ebp)
0x00404de3:	call 0x00406f56
0x00406f56:	jmp RtlUnwind@KERNEL32.DLL
RtlUnwind@KERNEL32.DLL: API Node	
0x00404de8:	popl %ebp
0x00404de9:	popl %edi
0x00404dea:	popl %esi
0x00404deb:	popl %ebx
0x00404dec:	movl %esp, %ebp
0x00404dee:	popl %ebp
0x00404def:	ret

0x00404f27:	addl %esp, $0x4<UINT8>
0x00404f2a:	leal %ebp, 0x10(%ebx)
0x00404f2d:	pushl %esi
0x00404f2e:	pushl %ebx
0x00404f2f:	call 0x00404e12
0x00404e12:	pushl %ebx
0x00404e13:	pushl %esi
0x00404e14:	pushl %edi
0x00404e15:	movl %eax, 0x10(%esp)
0x00404e19:	pushl %eax
0x00404e1a:	pushl $0xfffffffe<UINT8>
0x00404e1c:	pushl $0x404df0<UINT32>
0x00404e21:	pushl %fs:0
0x00404e28:	movl %fs:0, %esp
0x00404e2f:	movl %eax, 0x20(%esp)
0x00404e33:	movl %ebx, 0x8(%eax)
0x00404e36:	movl %esi, 0xc(%eax)
0x00404e39:	cmpl %esi, $0xffffffff<UINT8>
0x00404e3c:	je 46
0x00404e3e:	cmpl %esi, 0x24(%esp)
0x00404e42:	je 0x00404e6c
0x00404e6c:	popl %fs:0
0x00404e73:	addl %esp, $0xc<UINT8>
0x00404e76:	popl %edi
0x00404e77:	popl %esi
0x00404e78:	popl %ebx
0x00404e79:	ret

0x00404f34:	addl %esp, $0x8<UINT8>
0x00404f37:	leal %ecx, (%esi,%esi,2)
0x00404f3a:	pushl $0x1<UINT8>
0x00404f3c:	movl %eax, 0x8(%edi,%ecx,4)
0x00404f40:	call 0x00404ea6
0x00404ea6:	pushl %ebx
0x00404ea7:	pushl %ecx
0x00404ea8:	movl %ebx, $0x422a90<UINT32>
0x00404ead:	movl %ecx, 0x8(%ebp)
0x00404eb0:	movl 0x8(%ebx), %ecx
0x00404eb3:	movl 0x4(%ebx), %eax
0x00404eb6:	movl 0xc(%ebx), %ebp
0x00404eb9:	popl %ecx
0x00404eba:	popl %ebx
0x00404ebb:	ret $0x4<UINT16>

0x00404f45:	movl %eax, (%edi,%ecx,4)
0x00404f48:	movl 0xc(%ebx), %eax
0x00404f4b:	call 0x0040258d
0x0040258d:	movl %esp, -24(%ebp)
0x00402590:	pushl -104(%ebp)
0x00402593:	call 0x0040454b
0x0040454b:	pushl $0x0<UINT8>
0x0040454d:	pushl $0x1<UINT8>
0x0040454f:	pushl 0xc(%esp)
0x00404553:	call 0x0040455c
0x0040455c:	pushl %edi
0x0040455d:	pushl $0x1<UINT8>
0x0040455f:	popl %edi
0x00404560:	cmpl 0x422e24, %edi
0x00404566:	jne 0x00404579
0x00404579:	cmpl 0xc(%esp), $0x0<UINT8>
0x0040457e:	pushl %ebx
0x0040457f:	movl %ebx, 0x14(%esp)
0x00404583:	movl 0x422e20, %edi
0x00404589:	movb 0x422e1c, %bl
0x0040458f:	jne 0x004045cd
0x004045cd:	pushl $0x408028<UINT32>
0x004045d2:	pushl $0x408024<UINT32>
0x004045d7:	call 0x004045f5
0x004045dc:	popl %ecx
0x004045dd:	popl %ecx
0x004045de:	testl %ebx, %ebx
0x004045e0:	popl %ebx
0x004045e1:	jne 16
0x004045e3:	pushl 0x8(%esp)
0x004045e7:	movl 0x422e24, %edi
0x004045ed:	call ExitProcess@KERNEL32.DLL
ExitProcess@KERNEL32.DLL: Exit Node	
