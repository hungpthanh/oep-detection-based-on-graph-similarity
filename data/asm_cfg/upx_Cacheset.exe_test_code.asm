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
0x00403fbd:	jne 121
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
0x00404223:	jne 26
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
0x0040625d:	jne 18
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
