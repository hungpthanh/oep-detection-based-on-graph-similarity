0x0042c000:	movl %ebx, $0x4001d0<UINT32>
0x0042c005:	movl %edi, $0x401000<UINT32>
0x0042c00a:	movl %esi, $0x424000<UINT32>
0x0042c00f:	pushl %ebx
0x0042c010:	call 0x0042c01f
0x0042c01f:	cld
0x0042c020:	movb %dl, $0xffffff80<UINT8>
0x0042c022:	movsb %es:(%edi), %ds:(%esi)
0x0042c023:	pushl $0x2<UINT8>
0x0042c025:	popl %ebx
0x0042c026:	call 0x0042c015
0x0042c015:	addb %dl, %dl
0x0042c017:	jne 0x0042c01e
0x0042c019:	movb %dl, (%esi)
0x0042c01b:	incl %esi
0x0042c01c:	adcb %dl, %dl
0x0042c01e:	ret

0x0042c029:	jae 0x0042c022
0x0042c02b:	xorl %ecx, %ecx
0x0042c02d:	call 0x0042c015
0x0042c030:	jae 0x0042c04a
0x0042c032:	xorl %eax, %eax
0x0042c034:	call 0x0042c015
0x0042c037:	jae 0x0042c05a
0x0042c039:	movb %bl, $0x2<UINT8>
0x0042c03b:	incl %ecx
0x0042c03c:	movb %al, $0x10<UINT8>
0x0042c03e:	call 0x0042c015
0x0042c041:	adcb %al, %al
0x0042c043:	jae 0x0042c03e
0x0042c045:	jne 0x0042c086
0x0042c047:	stosb %es:(%edi), %al
0x0042c048:	jmp 0x0042c026
0x0042c086:	pushl %esi
0x0042c087:	movl %esi, %edi
0x0042c089:	subl %esi, %eax
0x0042c08b:	rep movsb %es:(%edi), %ds:(%esi)
0x0042c08d:	popl %esi
0x0042c08e:	jmp 0x0042c026
0x0042c05a:	lodsb %al, %ds:(%esi)
0x0042c05b:	shrl %eax
0x0042c05d:	je 0x0042c0a0
0x0042c05f:	adcl %ecx, %ecx
0x0042c061:	jmp 0x0042c07f
0x0042c07f:	incl %ecx
0x0042c080:	incl %ecx
0x0042c081:	xchgl %ebp, %eax
0x0042c082:	movl %eax, %ebp
0x0042c084:	movb %bl, $0x1<UINT8>
0x0042c04a:	call 0x0042c092
0x0042c092:	incl %ecx
0x0042c093:	call 0x0042c015
0x0042c097:	adcl %ecx, %ecx
0x0042c099:	call 0x0042c015
0x0042c09d:	jb 0x0042c093
0x0042c09f:	ret

0x0042c04f:	subl %ecx, %ebx
0x0042c051:	jne 0x0042c063
0x0042c053:	call 0x0042c090
0x0042c090:	xorl %ecx, %ecx
0x0042c058:	jmp 0x0042c082
0x0042c063:	xchgl %ecx, %eax
0x0042c064:	decl %eax
0x0042c065:	shll %eax, $0x8<UINT8>
0x0042c068:	lodsb %al, %ds:(%esi)
0x0042c069:	call 0x0042c090
0x0042c06e:	cmpl %eax, $0x7d00<UINT32>
0x0042c073:	jae 0x0042c07f
0x0042c075:	cmpb %ah, $0x5<UINT8>
0x0042c078:	jae 0x0042c080
0x0042c07a:	cmpl %eax, $0x7f<UINT8>
0x0042c07d:	ja 0x0042c081
0x0042c0a0:	popl %edi
0x0042c0a1:	popl %ebx
0x0042c0a2:	movzwl %edi, (%ebx)
0x0042c0a5:	decl %edi
0x0042c0a6:	je 0x0042c0b0
0x0042c0a8:	decl %edi
0x0042c0a9:	je 0x0042c0be
0x0042c0ab:	shll %edi, $0xc<UINT8>
0x0042c0ae:	jmp 0x0042c0b7
0x0042c0b7:	incl %ebx
0x0042c0b8:	incl %ebx
0x0042c0b9:	jmp 0x0042c00f
0x0042c0b0:	movl %edi, 0x2(%ebx)
0x0042c0b3:	pushl %edi
0x0042c0b4:	addl %ebx, $0x4<UINT8>
0x0042c0be:	popl %edi
0x0042c0bf:	movl %ebx, $0x42c128<UINT32>
0x0042c0c4:	incl %edi
0x0042c0c5:	movl %esi, (%edi)
0x0042c0c7:	scasl %eax, %es:(%edi)
0x0042c0c8:	pushl %edi
0x0042c0c9:	call LoadLibraryA@KERNEL32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0042c0cb:	xchgl %ebp, %eax
0x0042c0cc:	xorl %eax, %eax
0x0042c0ce:	scasb %al, %es:(%edi)
0x0042c0cf:	jne 0x0042c0ce
0x0042c0d1:	decb (%edi)
0x0042c0d3:	je 0x0042c0c4
0x0042c0d5:	decb (%edi)
0x0042c0d7:	jne 0x0042c0df
0x0042c0df:	decb (%edi)
0x0042c0e1:	je 0x00402138
0x0042c0e7:	pushl %edi
0x0042c0e8:	pushl %ebp
0x0042c0e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x0042c0ec:	orl (%esi), %eax
0x0042c0ee:	lodsl %eax, %ds:(%esi)
0x0042c0ef:	jne 0x0042c0cc
GetProcAddress@KERNEL32.dll: API Node	
LoadLibraryA@KERNEL32.dll: API Node	
0x00402138:	pushl %ebp
0x00402139:	movl %ebp, %esp
0x0040213b:	pushl $0xffffffff<UINT8>
0x0040213d:	pushl $0x406138<UINT32>
0x00402142:	pushl $0x403fa4<UINT32>
0x00402147:	movl %eax, %fs:0
0x0040214d:	pushl %eax
0x0040214e:	movl %fs:0, %esp
0x00402155:	subl %esp, $0x10<UINT8>
0x00402158:	pushl %ebx
0x00402159:	pushl %esi
0x0040215a:	pushl %edi
0x0040215b:	movl -24(%ebp), %esp
0x0040215e:	call GetVersion@KERNEL32.dll
GetVersion@KERNEL32.dll: API Node	
0x00402164:	xorl %edx, %edx
0x00402166:	movb %dl, %ah
0x00402168:	movl 0x421e44, %edx
0x0040216e:	movl %ecx, %eax
0x00402170:	andl %ecx, $0xff<UINT32>
0x00402176:	movl 0x421e40, %ecx
0x0040217c:	shll %ecx, $0x8<UINT8>
0x0040217f:	addl %ecx, %edx
0x00402181:	movl 0x421e3c, %ecx
0x00402187:	shrl %eax, $0x10<UINT8>
0x0040218a:	movl 0x421e38, %eax
0x0040218f:	pushl $0x0<UINT8>
0x00402191:	call 0x00402d06
0x00402d06:	xorl %eax, %eax
0x00402d08:	pushl $0x0<UINT8>
0x00402d0a:	cmpl 0x8(%esp), %eax
0x00402d0e:	pushl $0x1000<UINT32>
0x00402d13:	sete %al
0x00402d16:	pushl %eax
0x00402d17:	call HeapCreate@KERNEL32.dll
HeapCreate@KERNEL32.dll: API Node	
0x00402d1d:	testl %eax, %eax
0x00402d1f:	movl 0x42220c, %eax
0x00402d24:	je 21
0x00402d26:	call 0x00402d42
0x00402d42:	pushl $0x140<UINT32>
0x00402d47:	pushl $0x0<UINT8>
0x00402d49:	pushl 0x42220c
0x00402d4f:	call HeapAlloc@KERNEL32.dll
HeapAlloc@KERNEL32.dll: API Node	
0x00402d55:	testl %eax, %eax
0x00402d57:	movl 0x422208, %eax
0x00402d5c:	jne 0x00402d5f
0x00402d5f:	andl 0x422200, $0x0<UINT8>
0x00402d66:	andl 0x422204, $0x0<UINT8>
0x00402d6d:	pushl $0x1<UINT8>
0x00402d6f:	movl 0x4221fc, %eax
0x00402d74:	movl 0x4221f4, $0x10<UINT32>
0x00402d7e:	popl %eax
0x00402d7f:	ret

0x00402d2b:	testl %eax, %eax
0x00402d2d:	jne 0x00402d3e
0x00402d3e:	pushl $0x1<UINT8>
0x00402d40:	popl %eax
0x00402d41:	ret

0x00402196:	popl %ecx
0x00402197:	testl %eax, %eax
0x00402199:	jne 0x004021a3
0x004021a3:	andl -4(%ebp), $0x0<UINT8>
0x004021a7:	call 0x00403d00
0x00403d00:	subl %esp, $0x44<UINT8>
0x00403d03:	pushl %ebx
0x00403d04:	pushl %ebp
0x00403d05:	pushl %esi
0x00403d06:	pushl %edi
0x00403d07:	pushl $0x100<UINT32>
0x00403d0c:	call 0x00402078
0x00402078:	pushl 0x421e24
0x0040207e:	pushl 0x8(%esp)
0x00402082:	call 0x0040208a
0x0040208a:	cmpl 0x4(%esp), $0xffffffe0<UINT8>
0x0040208f:	ja 34
0x00402091:	pushl 0x4(%esp)
0x00402095:	call 0x004020b6
0x004020b6:	pushl %esi
0x004020b7:	movl %esi, 0x8(%esp)
0x004020bb:	cmpl %esi, 0x42192c
0x004020c1:	ja 0x004020ce
0x004020c3:	pushl %esi
0x004020c4:	call 0x004030d6
0x004030d6:	pushl %ebp
0x004030d7:	movl %ebp, %esp
0x004030d9:	subl %esp, $0x14<UINT8>
0x004030dc:	movl %eax, 0x422204
0x004030e1:	movl %edx, 0x422208
0x004030e7:	pushl %ebx
0x004030e8:	pushl %esi
0x004030e9:	leal %eax, (%eax,%eax,4)
0x004030ec:	pushl %edi
0x004030ed:	leal %edi, (%edx,%eax,4)
0x004030f0:	movl %eax, 0x8(%ebp)
0x004030f3:	movl -4(%ebp), %edi
0x004030f6:	leal %ecx, 0x17(%eax)
0x004030f9:	andl %ecx, $0xfffffff0<UINT8>
0x004030fc:	movl -16(%ebp), %ecx
0x004030ff:	sarl %ecx, $0x4<UINT8>
0x00403102:	decl %ecx
0x00403103:	cmpl %ecx, $0x20<UINT8>
0x00403106:	jnl 14
0x00403108:	orl %esi, $0xffffffff<UINT8>
0x0040310b:	shrl %esi, %cl
0x0040310d:	orl -8(%ebp), $0xffffffff<UINT8>
0x00403111:	movl -12(%ebp), %esi
0x00403114:	jmp 0x00403126
0x00403126:	movl %eax, 0x4221fc
0x0040312b:	movl %ebx, %eax
0x0040312d:	cmpl %ebx, %edi
0x0040312f:	movl 0x8(%ebp), %ebx
0x00403132:	jae 0x0040314d
0x0040314d:	cmpl %ebx, -4(%ebp)
0x00403150:	jne 121
0x00403152:	movl %ebx, %edx
0x00403154:	cmpl %ebx, %eax
0x00403156:	movl 0x8(%ebp), %ebx
0x00403159:	jae 0x00403170
0x00403170:	jne 89
0x00403172:	cmpl %ebx, -4(%ebp)
0x00403175:	jae 0x00403188
0x00403188:	jne 38
0x0040318a:	movl %ebx, %edx
0x0040318c:	cmpl %ebx, %eax
0x0040318e:	movl 0x8(%ebp), %ebx
0x00403191:	jae 0x004031a0
0x004031a0:	jne 14
0x004031a2:	call 0x004033df
0x004033df:	movl %eax, 0x422204
0x004033e4:	movl %ecx, 0x4221f4
0x004033ea:	pushl %esi
0x004033eb:	pushl %edi
0x004033ec:	xorl %edi, %edi
0x004033ee:	cmpl %eax, %ecx
0x004033f0:	jne 0x00403422
0x00403422:	movl %ecx, 0x422208
0x00403428:	pushl $0x41c4<UINT32>
0x0040342d:	pushl $0x8<UINT8>
0x0040342f:	leal %eax, (%eax,%eax,4)
0x00403432:	pushl 0x42220c
0x00403438:	leal %esi, (%ecx,%eax,4)
0x0040343b:	call HeapAlloc@KERNEL32.dll
0x00403441:	cmpl %eax, %edi
0x00403443:	movl 0x10(%esi), %eax
0x00403446:	je 42
0x00403448:	pushl $0x4<UINT8>
0x0040344a:	pushl $0x2000<UINT32>
0x0040344f:	pushl $0x100000<UINT32>
0x00403454:	pushl %edi
0x00403455:	call VirtualAlloc@KERNEL32.dll
VirtualAlloc@KERNEL32.dll: API Node	
0x0040345b:	cmpl %eax, %edi
0x0040345d:	movl 0xc(%esi), %eax
0x00403460:	jne 0x00403476
0x00403476:	orl 0x8(%esi), $0xffffffff<UINT8>
0x0040347a:	movl (%esi), %edi
0x0040347c:	movl 0x4(%esi), %edi
0x0040347f:	incl 0x422204
0x00403485:	movl %eax, 0x10(%esi)
0x00403488:	orl (%eax), $0xffffffff<UINT8>
0x0040348b:	movl %eax, %esi
0x0040348d:	popl %edi
0x0040348e:	popl %esi
0x0040348f:	ret

0x004031a7:	movl %ebx, %eax
0x004031a9:	testl %ebx, %ebx
0x004031ab:	movl 0x8(%ebp), %ebx
0x004031ae:	je 20
0x004031b0:	pushl %ebx
0x004031b1:	call 0x00403490
0x00403490:	pushl %ebp
0x00403491:	movl %ebp, %esp
0x00403493:	pushl %ecx
0x00403494:	movl %ecx, 0x8(%ebp)
0x00403497:	pushl %ebx
0x00403498:	pushl %esi
0x00403499:	pushl %edi
0x0040349a:	movl %esi, 0x10(%ecx)
0x0040349d:	movl %eax, 0x8(%ecx)
0x004034a0:	xorl %ebx, %ebx
0x004034a2:	testl %eax, %eax
0x004034a4:	jl 0x004034ab
0x004034ab:	movl %eax, %ebx
0x004034ad:	pushl $0x3f<UINT8>
0x004034af:	imull %eax, %eax, $0x204<UINT32>
0x004034b5:	popl %edx
0x004034b6:	leal %eax, 0x144(%eax,%esi)
0x004034bd:	movl -4(%ebp), %eax
0x004034c0:	movl 0x8(%eax), %eax
0x004034c3:	movl 0x4(%eax), %eax
0x004034c6:	addl %eax, $0x8<UINT8>
0x004034c9:	decl %edx
0x004034ca:	jne 0x004034c0
0x004034cc:	movl %edi, %ebx
0x004034ce:	pushl $0x4<UINT8>
0x004034d0:	shll %edi, $0xf<UINT8>
0x004034d3:	addl %edi, 0xc(%ecx)
0x004034d6:	pushl $0x1000<UINT32>
0x004034db:	pushl $0x8000<UINT32>
0x004034e0:	pushl %edi
0x004034e1:	call VirtualAlloc@KERNEL32.dll
0x004034e7:	testl %eax, %eax
0x004034e9:	jne 0x004034f3
0x004034f3:	leal %edx, 0x7000(%edi)
0x004034f9:	cmpl %edi, %edx
0x004034fb:	ja 60
0x004034fd:	leal %eax, 0x10(%edi)
0x00403500:	orl -8(%eax), $0xffffffff<UINT8>
0x00403504:	orl 0xfec(%eax), $0xffffffff<UINT8>
0x0040350b:	leal %ecx, 0xffc(%eax)
0x00403511:	movl -4(%eax), $0xff0<UINT32>
0x00403518:	movl (%eax), %ecx
0x0040351a:	leal %ecx, -4100(%eax)
0x00403520:	movl 0x4(%eax), %ecx
0x00403523:	movl 0xfe8(%eax), $0xff0<UINT32>
0x0040352d:	addl %eax, $0x1000<UINT32>
0x00403532:	leal %ecx, -16(%eax)
0x00403535:	cmpl %ecx, %edx
0x00403537:	jbe 0x00403500
0x00403539:	movl %eax, -4(%ebp)
0x0040353c:	leal %ecx, 0xc(%edi)
0x0040353f:	addl %eax, $0x1f8<UINT32>
0x00403544:	pushl $0x1<UINT8>
0x00403546:	popl %edi
0x00403547:	movl 0x4(%eax), %ecx
0x0040354a:	movl 0x8(%ecx), %eax
0x0040354d:	leal %ecx, 0xc(%edx)
0x00403550:	movl 0x8(%eax), %ecx
0x00403553:	movl 0x4(%ecx), %eax
0x00403556:	andl 0x44(%esi,%ebx,4), $0x0<UINT8>
0x0040355b:	movl 0xc4(%esi,%ebx,4), %edi
0x00403562:	movb %al, 0x43(%esi)
0x00403565:	movb %cl, %al
0x00403567:	incb %cl
0x00403569:	testb %al, %al
0x0040356b:	movl %eax, 0x8(%ebp)
0x0040356e:	movb 0x43(%esi), %cl
0x00403571:	jne 3
0x00403573:	orl 0x4(%eax), %edi
0x00403576:	movl %edx, $0x80000000<UINT32>
0x0040357b:	movl %ecx, %ebx
0x0040357d:	shrl %edx, %cl
0x0040357f:	notl %edx
0x00403581:	andl 0x8(%eax), %edx
0x00403584:	movl %eax, %ebx
0x00403586:	popl %edi
0x00403587:	popl %esi
0x00403588:	popl %ebx
0x00403589:	leave
0x0040358a:	ret

0x004031b6:	popl %ecx
0x004031b7:	movl %ecx, 0x10(%ebx)
0x004031ba:	movl (%ecx), %eax
0x004031bc:	movl %eax, 0x10(%ebx)
0x004031bf:	cmpl (%eax), $0xffffffff<UINT8>
0x004031c2:	jne 0x004031cb
0x004031cb:	movl 0x4221fc, %ebx
0x004031d1:	movl %eax, 0x10(%ebx)
0x004031d4:	movl %edx, (%eax)
0x004031d6:	cmpl %edx, $0xffffffff<UINT8>
0x004031d9:	movl -4(%ebp), %edx
0x004031dc:	je 20
0x004031de:	movl %ecx, 0xc4(%eax,%edx,4)
0x004031e5:	movl %edi, 0x44(%eax,%edx,4)
0x004031e9:	andl %ecx, -8(%ebp)
0x004031ec:	andl %edi, %esi
0x004031ee:	orl %ecx, %edi
0x004031f0:	jne 0x00403229
0x00403229:	movl %ecx, %edx
0x0040322b:	xorl %edi, %edi
0x0040322d:	imull %ecx, %ecx, $0x204<UINT32>
0x00403233:	leal %ecx, 0x144(%ecx,%eax)
0x0040323a:	movl -12(%ebp), %ecx
0x0040323d:	movl %ecx, 0x44(%eax,%edx,4)
0x00403241:	andl %ecx, %esi
0x00403243:	jne 13
0x00403245:	movl %ecx, 0xc4(%eax,%edx,4)
0x0040324c:	pushl $0x20<UINT8>
0x0040324e:	andl %ecx, -8(%ebp)
0x00403251:	popl %edi
0x00403252:	testl %ecx, %ecx
0x00403254:	jl 0x0040325b
0x00403256:	shll %ecx
0x00403258:	incl %edi
0x00403259:	jmp 0x00403252
0x0040325b:	movl %ecx, -12(%ebp)
0x0040325e:	movl %edx, 0x4(%ecx,%edi,8)
0x00403262:	movl %ecx, (%edx)
0x00403264:	subl %ecx, -16(%ebp)
0x00403267:	movl %esi, %ecx
0x00403269:	movl -8(%ebp), %ecx
0x0040326c:	sarl %esi, $0x4<UINT8>
0x0040326f:	decl %esi
0x00403270:	cmpl %esi, $0x3f<UINT8>
0x00403273:	jle 3
0x00403275:	pushl $0x3f<UINT8>
0x00403277:	popl %esi
0x00403278:	cmpl %esi, %edi
0x0040327a:	je 0x0040338d
0x0040338d:	testl %ecx, %ecx
0x0040338f:	je 11
0x00403391:	movl (%edx), %ecx
0x00403393:	movl -4(%ecx,%edx), %ecx
0x00403397:	jmp 0x0040339c
0x0040339c:	movl %esi, -16(%ebp)
0x0040339f:	addl %edx, %ecx
0x004033a1:	leal %ecx, 0x1(%esi)
0x004033a4:	movl (%edx), %ecx
0x004033a6:	movl -4(%edx,%esi), %ecx
0x004033aa:	movl %esi, -12(%ebp)
0x004033ad:	movl %ecx, (%esi)
0x004033af:	testl %ecx, %ecx
0x004033b1:	leal %edi, 0x1(%ecx)
0x004033b4:	movl (%esi), %edi
0x004033b6:	jne 26
0x004033b8:	cmpl %ebx, 0x422200
0x004033be:	jne 0x004033d2
0x004033d2:	movl %ecx, -4(%ebp)
0x004033d5:	movl (%eax), %ecx
0x004033d7:	leal %eax, 0x4(%edx)
0x004033da:	popl %edi
0x004033db:	popl %esi
0x004033dc:	popl %ebx
0x004033dd:	leave
0x004033de:	ret

0x004020c9:	testl %eax, %eax
0x004020cb:	popl %ecx
0x004020cc:	jne 0x004020ea
0x004020ea:	popl %esi
0x004020eb:	ret

0x0040209a:	testl %eax, %eax
0x0040209c:	popl %ecx
0x0040209d:	jne 0x004020b5
0x004020b5:	ret

0x00402087:	popl %ecx
0x00402088:	popl %ecx
0x00402089:	ret

0x00403d11:	movl %esi, %eax
0x00403d13:	popl %ecx
0x00403d14:	testl %esi, %esi
0x00403d16:	jne 0x00403d20
0x00403d20:	movl 0x4220e0, %esi
0x00403d26:	movl 0x4221e0, $0x20<UINT32>
0x00403d30:	leal %eax, 0x100(%esi)
0x00403d36:	cmpl %esi, %eax
0x00403d38:	jae 0x00403d54
0x00403d3a:	andb 0x4(%esi), $0x0<UINT8>
0x00403d3e:	orl (%esi), $0xffffffff<UINT8>
0x00403d41:	movb 0x5(%esi), $0xa<UINT8>
0x00403d45:	movl %eax, 0x4220e0
0x00403d4a:	addl %esi, $0x8<UINT8>
0x00403d4d:	addl %eax, $0x100<UINT32>
0x00403d52:	jmp 0x00403d36
0x00403d54:	leal %eax, 0x10(%esp)
0x00403d58:	pushl %eax
0x00403d59:	call GetStartupInfoA@KERNEL32.dll
GetStartupInfoA@KERNEL32.dll: API Node	
0x00403d5f:	cmpw 0x42(%esp), $0x0<UINT8>
0x00403d65:	je 197
0x00403d6b:	movl %eax, 0x44(%esp)
0x00403d6f:	testl %eax, %eax
0x00403d71:	je 185
0x00403d77:	movl %esi, (%eax)
0x00403d79:	leal %ebp, 0x4(%eax)
0x00403d7c:	movl %eax, $0x800<UINT32>
0x00403d81:	cmpl %esi, %eax
0x00403d83:	leal %ebx, (%esi,%ebp)
0x00403d86:	jl 0x00403d8a
0x00403d8a:	cmpl 0x4221e0, %esi
0x00403d90:	jnl 0x00403de4
0x00403de4:	xorl %edi, %edi
0x00403de6:	testl %esi, %esi
0x00403de8:	jle 0x00403e30
0x00403e30:	xorl %ebx, %ebx
0x00403e32:	movl %eax, 0x4220e0
0x00403e37:	cmpl (%eax,%ebx,8), $0xffffffff<UINT8>
0x00403e3b:	leal %esi, (%eax,%ebx,8)
0x00403e3e:	jne 77
0x00403e40:	testl %ebx, %ebx
0x00403e42:	movb 0x4(%esi), $0xffffff81<UINT8>
0x00403e46:	jne 0x00403e4d
0x00403e48:	pushl $0xfffffff6<UINT8>
0x00403e4a:	popl %eax
0x00403e4b:	jmp 0x00403e57
0x00403e57:	pushl %eax
0x00403e58:	call GetStdHandle@KERNEL32.dll
GetStdHandle@KERNEL32.dll: API Node	
0x00403e5e:	movl %edi, %eax
0x00403e60:	cmpl %edi, $0xffffffff<UINT8>
0x00403e63:	je 23
0x00403e65:	pushl %edi
0x00403e66:	call GetFileType@KERNEL32.dll
GetFileType@KERNEL32.dll: API Node	
0x00403e6c:	testl %eax, %eax
0x00403e6e:	je 12
0x00403e70:	andl %eax, $0xff<UINT32>
0x00403e75:	movl (%esi), %edi
0x00403e77:	cmpl %eax, $0x2<UINT8>
0x00403e7a:	jne 6
0x00403e7c:	orb 0x4(%esi), $0x40<UINT8>
0x00403e80:	jmp 0x00403e91
0x00403e91:	incl %ebx
0x00403e92:	cmpl %ebx, $0x3<UINT8>
0x00403e95:	jl 0x00403e32
0x00403e4d:	movl %eax, %ebx
0x00403e4f:	decl %eax
0x00403e50:	negl %eax
0x00403e52:	sbbl %eax, %eax
0x00403e54:	addl %eax, $0xfffffff5<UINT8>
0x00403e97:	pushl 0x4221e0
0x00403e9d:	call SetHandleCount@KERNEL32.dll
SetHandleCount@KERNEL32.dll: API Node	
0x00403ea3:	popl %edi
0x00403ea4:	popl %esi
0x00403ea5:	popl %ebp
0x00403ea6:	popl %ebx
0x00403ea7:	addl %esp, $0x44<UINT8>
0x00403eaa:	ret

0x004021ac:	call 0x00403c5f
0x00403c5f:	movl %eax, 0x422088
0x00403c64:	pushl %ebx
0x00403c65:	pushl %ebp
0x00403c66:	pushl %esi
0x00403c67:	movl %esi, 0x4060e0
0x00403c6d:	pushl %edi
0x00403c6e:	movl %edi, 0x4060dc
0x00403c74:	testl %eax, %eax
0x00403c76:	jne 36
0x00403c78:	call GetCommandLineW@KERNEL32.dll
GetCommandLineW@KERNEL32.dll: API Node	
0x00403c7a:	testl %eax, %eax
0x00403c7c:	je 12
0x00403c7e:	movl 0x422088, $0x1<UINT32>
0x00403c88:	jmp 0x00403ca1
0x00403ca1:	call GetCommandLineW@KERNEL32.dll
0x00403ca3:	jmp 0x00403cf7
0x00403cf7:	popl %edi
0x00403cf8:	popl %esi
0x00403cf9:	popl %ebp
0x00403cfa:	popl %ebx
0x00403cfb:	ret

0x004021b1:	movl 0x423224, %eax
0x004021b6:	call 0x00403af2
0x00403af2:	pushl %ecx
0x00403af3:	movl %eax, 0x422084
0x00403af8:	pushl %ebx
0x00403af9:	movl %ebx, 0x4060d8
0x00403aff:	pushl %ebp
0x00403b00:	pushl %esi
0x00403b01:	xorl %esi, %esi
0x00403b03:	xorl %ebp, %ebp
0x00403b05:	pushl %edi
0x00403b06:	movl %edi, 0x4060d4
0x00403b0c:	testl %eax, %eax
0x00403b0e:	jne 44
0x00403b10:	call GetEnvironmentStringsW@KERNEL32.dll
GetEnvironmentStringsW@KERNEL32.dll: API Node	
0x00403b12:	movl %esi, %eax
0x00403b14:	testl %esi, %esi
0x00403b16:	je 12
0x00403b18:	movl 0x422084, $0x1<UINT32>
0x00403b22:	jmp 0x00403b41
0x00403b41:	testl %esi, %esi
0x00403b43:	jne 0x00403b51
0x00403b51:	xorl %ecx, %ecx
0x00403b53:	movl %eax, %esi
0x00403b55:	cmpw (%esi), %cx
0x00403b58:	je 14
0x00403b5a:	incl %eax
0x00403b5b:	incl %eax
0x00403b5c:	cmpw (%eax), %cx
0x00403b5f:	jne 0x00403b5a
0x00403b61:	incl %eax
0x00403b62:	incl %eax
0x00403b63:	cmpw (%eax), %cx
0x00403b66:	jne 0x00403b5a
0x00403b68:	subl %eax, %esi
0x00403b6a:	incl %eax
0x00403b6b:	incl %eax
0x00403b6c:	movl %ebx, %eax
0x00403b6e:	pushl %ebx
0x00403b6f:	call 0x00402078
0x004020ce:	testl %esi, %esi
0x004020d0:	jne 0x004020d5
0x004020d5:	addl %esi, $0xf<UINT8>
0x004020d8:	andl %esi, $0xfffffff0<UINT8>
0x004020db:	pushl %esi
0x004020dc:	pushl $0x0<UINT8>
0x004020de:	pushl 0x42220c
0x004020e4:	call HeapAlloc@KERNEL32.dll
0x00403b74:	movl %edi, %eax
0x00403b76:	popl %ecx
0x00403b77:	testl %edi, %edi
0x00403b79:	jne 0x00403b86
0x00403b86:	pushl %ebx
0x00403b87:	pushl %esi
0x00403b88:	pushl %edi
0x00403b89:	call 0x00404d10
0x00404d10:	pushl %ebp
0x00404d11:	movl %ebp, %esp
0x00404d13:	pushl %edi
0x00404d14:	pushl %esi
0x00404d15:	movl %esi, 0xc(%ebp)
0x00404d18:	movl %ecx, 0x10(%ebp)
0x00404d1b:	movl %edi, 0x8(%ebp)
0x00404d1e:	movl %eax, %ecx
0x00404d20:	movl %edx, %ecx
0x00404d22:	addl %eax, %esi
0x00404d24:	cmpl %edi, %esi
0x00404d26:	jbe 8
0x00404d28:	cmpl %edi, %eax
0x00404d2a:	jb 376
0x00404d30:	testl %edi, $0x3<UINT32>
0x00404d36:	jne 20
0x00404d38:	shrl %ecx, $0x2<UINT8>
0x00404d3b:	andl %edx, $0x3<UINT8>
0x00404d3e:	cmpl %ecx, $0x8<UINT8>
0x00404d41:	jb 41
0x00404d43:	rep movsl %es:(%edi), %ds:(%esi)
