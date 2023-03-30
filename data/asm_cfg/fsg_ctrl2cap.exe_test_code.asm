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
0x0042c086:	pushl %esi
0x0042c087:	movl %esi, %edi
0x0042c089:	subl %esi, %eax
0x0042c08b:	rep movsb %es:(%edi), %ds:(%esi)
0x0042c08d:	popl %esi
0x0042c08e:	jmp 0x0042c026
0x0042c04a:	call 0x0042c092
0x0042c092:	incl %ecx
0x0042c093:	call 0x0042c015
0x0042c097:	adcl %ecx, %ecx
0x0042c099:	call 0x0042c015
0x0042c09d:	jb 0x0042c093
0x0042c09f:	ret

0x0042c04f:	subl %ecx, %ebx
0x0042c051:	jne 0x0042c063
0x0042c063:	xchgl %ecx, %eax
0x0042c064:	decl %eax
0x0042c065:	shll %eax, $0x8<UINT8>
0x0042c068:	lodsb %al, %ds:(%esi)
0x0042c069:	call 0x0042c090
0x0042c090:	xorl %ecx, %ecx
0x0042c06e:	cmpl %eax, $0x7d00<UINT32>
0x0042c073:	jae 0x0042c07f
0x0042c075:	cmpb %ah, $0x5<UINT8>
0x0042c078:	jae 0x0042c080
0x0042c07a:	cmpl %eax, $0x7f<UINT8>
0x0042c07d:	ja 0x0042c081
0x0042c07f:	incl %ecx
0x0042c080:	incl %ecx
0x0042c081:	xchgl %ebp, %eax
0x0042c082:	movl %eax, %ebp
0x0042c084:	movb %bl, $0x1<UINT8>
0x0042c047:	stosb %es:(%edi), %al
0x0042c048:	jmp 0x0042c026
0x0042c05a:	lodsb %al, %ds:(%esi)
0x0042c05b:	shrl %eax
0x0042c05d:	je 0x0042c0a0
0x0042c05f:	adcl %ecx, %ecx
0x0042c061:	jmp 0x0042c07f
0x0042c053:	call 0x0042c090
0x0042c058:	jmp 0x0042c082
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
0x0042c0e1:	je 0x0040221a
0x0042c0e7:	pushl %edi
0x0042c0e8:	pushl %ebp
0x0042c0e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x0042c0ec:	orl (%esi), %eax
0x0042c0ee:	lodsl %eax, %ds:(%esi)
0x0042c0ef:	jne 0x0042c0cc
GetProcAddress@KERNEL32.dll: API Node	
LoadLibraryA@KERNEL32.dll: API Node	
0x0040221a:	pushl %ebp
0x0040221b:	movl %ebp, %esp
0x0040221d:	pushl $0xffffffff<UINT8>
0x0040221f:	pushl $0x406138<UINT32>
0x00402224:	pushl $0x403ee4<UINT32>
0x00402229:	movl %eax, %fs:0
0x0040222f:	pushl %eax
0x00402230:	movl %fs:0, %esp
0x00402237:	subl %esp, $0x10<UINT8>
0x0040223a:	pushl %ebx
0x0040223b:	pushl %esi
0x0040223c:	pushl %edi
0x0040223d:	movl -24(%ebp), %esp
0x00402240:	call GetVersion@KERNEL32.dll
GetVersion@KERNEL32.dll: API Node	
0x00402246:	xorl %edx, %edx
0x00402248:	movb %dl, %ah
0x0040224a:	movl 0x422178, %edx
0x00402250:	movl %ecx, %eax
0x00402252:	andl %ecx, $0xff<UINT32>
0x00402258:	movl 0x422174, %ecx
0x0040225e:	shll %ecx, $0x8<UINT8>
0x00402261:	addl %ecx, %edx
0x00402263:	movl 0x422170, %ecx
0x00402269:	shrl %eax, $0x10<UINT8>
0x0040226c:	movl 0x42216c, %eax
0x00402271:	pushl $0x0<UINT8>
0x00402273:	call 0x00402cea
0x00402cea:	xorl %eax, %eax
0x00402cec:	pushl $0x0<UINT8>
0x00402cee:	cmpl 0x8(%esp), %eax
0x00402cf2:	pushl $0x1000<UINT32>
0x00402cf7:	sete %al
0x00402cfa:	pushl %eax
0x00402cfb:	call HeapCreate@KERNEL32.dll
HeapCreate@KERNEL32.dll: API Node	
0x00402d01:	testl %eax, %eax
0x00402d03:	movl 0x42267c, %eax
0x00402d08:	je 21
0x00402d0a:	call 0x00402d26
0x00402d26:	pushl $0x140<UINT32>
0x00402d2b:	pushl $0x0<UINT8>
0x00402d2d:	pushl 0x42267c
0x00402d33:	call HeapAlloc@KERNEL32.dll
HeapAlloc@KERNEL32.dll: API Node	
0x00402d39:	testl %eax, %eax
0x00402d3b:	movl 0x422678, %eax
0x00402d40:	jne 0x00402d43
0x00402d43:	andl 0x422670, $0x0<UINT8>
0x00402d4a:	andl 0x422674, $0x0<UINT8>
0x00402d51:	pushl $0x1<UINT8>
0x00402d53:	movl 0x42266c, %eax
0x00402d58:	movl 0x422664, $0x10<UINT32>
0x00402d62:	popl %eax
0x00402d63:	ret

0x00402d0f:	testl %eax, %eax
0x00402d11:	jne 0x00402d22
0x00402d22:	pushl $0x1<UINT8>
0x00402d24:	popl %eax
0x00402d25:	ret

0x00402278:	popl %ecx
0x00402279:	testl %eax, %eax
0x0040227b:	jne 0x00402285
0x00402285:	andl -4(%ebp), $0x0<UINT8>
0x00402289:	call 0x00403c40
0x00403c40:	subl %esp, $0x44<UINT8>
0x00403c43:	pushl %ebx
0x00403c44:	pushl %ebp
0x00403c45:	pushl %esi
0x00403c46:	pushl %edi
0x00403c47:	pushl $0x100<UINT32>
0x00403c4c:	call 0x004020e3
0x004020e3:	pushl 0x4221c4
0x004020e9:	pushl 0x8(%esp)
0x004020ed:	call 0x004020f5
0x004020f5:	cmpl 0x4(%esp), $0xffffffe0<UINT8>
0x004020fa:	ja 34
0x004020fc:	pushl 0x4(%esp)
0x00402100:	call 0x00402121
0x00402121:	pushl %esi
0x00402122:	movl %esi, 0x8(%esp)
0x00402126:	cmpl %esi, 0x421b7c
0x0040212c:	ja 0x00402139
0x0040212e:	pushl %esi
0x0040212f:	call 0x004030ba
0x004030ba:	pushl %ebp
0x004030bb:	movl %ebp, %esp
0x004030bd:	subl %esp, $0x14<UINT8>
0x004030c0:	movl %eax, 0x422674
0x004030c5:	movl %edx, 0x422678
0x004030cb:	pushl %ebx
0x004030cc:	pushl %esi
0x004030cd:	leal %eax, (%eax,%eax,4)
0x004030d0:	pushl %edi
0x004030d1:	leal %edi, (%edx,%eax,4)
0x004030d4:	movl %eax, 0x8(%ebp)
0x004030d7:	movl -4(%ebp), %edi
0x004030da:	leal %ecx, 0x17(%eax)
0x004030dd:	andl %ecx, $0xfffffff0<UINT8>
0x004030e0:	movl -16(%ebp), %ecx
0x004030e3:	sarl %ecx, $0x4<UINT8>
0x004030e6:	decl %ecx
0x004030e7:	cmpl %ecx, $0x20<UINT8>
0x004030ea:	jnl 14
0x004030ec:	orl %esi, $0xffffffff<UINT8>
0x004030ef:	shrl %esi, %cl
0x004030f1:	orl -8(%ebp), $0xffffffff<UINT8>
0x004030f5:	movl -12(%ebp), %esi
0x004030f8:	jmp 0x0040310a
0x0040310a:	movl %eax, 0x42266c
0x0040310f:	movl %ebx, %eax
0x00403111:	cmpl %ebx, %edi
0x00403113:	movl 0x8(%ebp), %ebx
0x00403116:	jae 0x00403131
0x00403131:	cmpl %ebx, -4(%ebp)
0x00403134:	jne 121
0x00403136:	movl %ebx, %edx
0x00403138:	cmpl %ebx, %eax
0x0040313a:	movl 0x8(%ebp), %ebx
0x0040313d:	jae 0x00403154
0x00403154:	jne 89
0x00403156:	cmpl %ebx, -4(%ebp)
0x00403159:	jae 0x0040316c
0x0040316c:	jne 38
0x0040316e:	movl %ebx, %edx
0x00403170:	cmpl %ebx, %eax
0x00403172:	movl 0x8(%ebp), %ebx
0x00403175:	jae 0x00403184
0x00403184:	jne 14
0x00403186:	call 0x004033c3
0x004033c3:	movl %eax, 0x422674
0x004033c8:	movl %ecx, 0x422664
0x004033ce:	pushl %esi
0x004033cf:	pushl %edi
0x004033d0:	xorl %edi, %edi
0x004033d2:	cmpl %eax, %ecx
0x004033d4:	jne 0x00403406
0x00403406:	movl %ecx, 0x422678
0x0040340c:	pushl $0x41c4<UINT32>
0x00403411:	pushl $0x8<UINT8>
0x00403413:	leal %eax, (%eax,%eax,4)
0x00403416:	pushl 0x42267c
0x0040341c:	leal %esi, (%ecx,%eax,4)
0x0040341f:	call HeapAlloc@KERNEL32.dll
0x00403425:	cmpl %eax, %edi
0x00403427:	movl 0x10(%esi), %eax
0x0040342a:	je 42
0x0040342c:	pushl $0x4<UINT8>
0x0040342e:	pushl $0x2000<UINT32>
0x00403433:	pushl $0x100000<UINT32>
0x00403438:	pushl %edi
0x00403439:	call VirtualAlloc@KERNEL32.dll
VirtualAlloc@KERNEL32.dll: API Node	
0x0040343f:	cmpl %eax, %edi
0x00403441:	movl 0xc(%esi), %eax
0x00403444:	jne 0x0040345a
0x0040345a:	orl 0x8(%esi), $0xffffffff<UINT8>
0x0040345e:	movl (%esi), %edi
0x00403460:	movl 0x4(%esi), %edi
0x00403463:	incl 0x422674
0x00403469:	movl %eax, 0x10(%esi)
0x0040346c:	orl (%eax), $0xffffffff<UINT8>
0x0040346f:	movl %eax, %esi
0x00403471:	popl %edi
0x00403472:	popl %esi
0x00403473:	ret

0x0040318b:	movl %ebx, %eax
0x0040318d:	testl %ebx, %ebx
0x0040318f:	movl 0x8(%ebp), %ebx
0x00403192:	je 20
0x00403194:	pushl %ebx
0x00403195:	call 0x00403474
0x00403474:	pushl %ebp
0x00403475:	movl %ebp, %esp
0x00403477:	pushl %ecx
0x00403478:	movl %ecx, 0x8(%ebp)
0x0040347b:	pushl %ebx
0x0040347c:	pushl %esi
0x0040347d:	pushl %edi
0x0040347e:	movl %esi, 0x10(%ecx)
0x00403481:	movl %eax, 0x8(%ecx)
0x00403484:	xorl %ebx, %ebx
0x00403486:	testl %eax, %eax
0x00403488:	jl 0x0040348f
0x0040348f:	movl %eax, %ebx
0x00403491:	pushl $0x3f<UINT8>
0x00403493:	imull %eax, %eax, $0x204<UINT32>
0x00403499:	popl %edx
0x0040349a:	leal %eax, 0x144(%eax,%esi)
0x004034a1:	movl -4(%ebp), %eax
0x004034a4:	movl 0x8(%eax), %eax
0x004034a7:	movl 0x4(%eax), %eax
0x004034aa:	addl %eax, $0x8<UINT8>
0x004034ad:	decl %edx
0x004034ae:	jne 0x004034a4
0x004034b0:	movl %edi, %ebx
0x004034b2:	pushl $0x4<UINT8>
0x004034b4:	shll %edi, $0xf<UINT8>
0x004034b7:	addl %edi, 0xc(%ecx)
0x004034ba:	pushl $0x1000<UINT32>
0x004034bf:	pushl $0x8000<UINT32>
0x004034c4:	pushl %edi
0x004034c5:	call VirtualAlloc@KERNEL32.dll
0x004034cb:	testl %eax, %eax
0x004034cd:	jne 0x004034d7
0x004034d7:	leal %edx, 0x7000(%edi)
0x004034dd:	cmpl %edi, %edx
0x004034df:	ja 60
0x004034e1:	leal %eax, 0x10(%edi)
0x004034e4:	orl -8(%eax), $0xffffffff<UINT8>
0x004034e8:	orl 0xfec(%eax), $0xffffffff<UINT8>
0x004034ef:	leal %ecx, 0xffc(%eax)
0x004034f5:	movl -4(%eax), $0xff0<UINT32>
0x004034fc:	movl (%eax), %ecx
0x004034fe:	leal %ecx, -4100(%eax)
0x00403504:	movl 0x4(%eax), %ecx
0x00403507:	movl 0xfe8(%eax), $0xff0<UINT32>
0x00403511:	addl %eax, $0x1000<UINT32>
0x00403516:	leal %ecx, -16(%eax)
0x00403519:	cmpl %ecx, %edx
0x0040351b:	jbe 0x004034e4
0x0040351d:	movl %eax, -4(%ebp)
0x00403520:	leal %ecx, 0xc(%edi)
0x00403523:	addl %eax, $0x1f8<UINT32>
0x00403528:	pushl $0x1<UINT8>
0x0040352a:	popl %edi
0x0040352b:	movl 0x4(%eax), %ecx
0x0040352e:	movl 0x8(%ecx), %eax
0x00403531:	leal %ecx, 0xc(%edx)
0x00403534:	movl 0x8(%eax), %ecx
0x00403537:	movl 0x4(%ecx), %eax
0x0040353a:	andl 0x44(%esi,%ebx,4), $0x0<UINT8>
0x0040353f:	movl 0xc4(%esi,%ebx,4), %edi
0x00403546:	movb %al, 0x43(%esi)
0x00403549:	movb %cl, %al
0x0040354b:	incb %cl
0x0040354d:	testb %al, %al
0x0040354f:	movl %eax, 0x8(%ebp)
0x00403552:	movb 0x43(%esi), %cl
0x00403555:	jne 3
0x00403557:	orl 0x4(%eax), %edi
0x0040355a:	movl %edx, $0x80000000<UINT32>
0x0040355f:	movl %ecx, %ebx
0x00403561:	shrl %edx, %cl
0x00403563:	notl %edx
0x00403565:	andl 0x8(%eax), %edx
0x00403568:	movl %eax, %ebx
0x0040356a:	popl %edi
0x0040356b:	popl %esi
0x0040356c:	popl %ebx
0x0040356d:	leave
0x0040356e:	ret

0x0040319a:	popl %ecx
0x0040319b:	movl %ecx, 0x10(%ebx)
0x0040319e:	movl (%ecx), %eax
0x004031a0:	movl %eax, 0x10(%ebx)
0x004031a3:	cmpl (%eax), $0xffffffff<UINT8>
0x004031a6:	jne 0x004031af
0x004031af:	movl 0x42266c, %ebx
0x004031b5:	movl %eax, 0x10(%ebx)
0x004031b8:	movl %edx, (%eax)
0x004031ba:	cmpl %edx, $0xffffffff<UINT8>
0x004031bd:	movl -4(%ebp), %edx
0x004031c0:	je 20
0x004031c2:	movl %ecx, 0xc4(%eax,%edx,4)
0x004031c9:	movl %edi, 0x44(%eax,%edx,4)
0x004031cd:	andl %ecx, -8(%ebp)
0x004031d0:	andl %edi, %esi
0x004031d2:	orl %ecx, %edi
0x004031d4:	jne 0x0040320d
0x0040320d:	movl %ecx, %edx
0x0040320f:	xorl %edi, %edi
0x00403211:	imull %ecx, %ecx, $0x204<UINT32>
0x00403217:	leal %ecx, 0x144(%ecx,%eax)
0x0040321e:	movl -12(%ebp), %ecx
0x00403221:	movl %ecx, 0x44(%eax,%edx,4)
0x00403225:	andl %ecx, %esi
0x00403227:	jne 13
0x00403229:	movl %ecx, 0xc4(%eax,%edx,4)
0x00403230:	pushl $0x20<UINT8>
0x00403232:	andl %ecx, -8(%ebp)
0x00403235:	popl %edi
0x00403236:	testl %ecx, %ecx
0x00403238:	jl 0x0040323f
0x0040323a:	shll %ecx
0x0040323c:	incl %edi
0x0040323d:	jmp 0x00403236
0x0040323f:	movl %ecx, -12(%ebp)
0x00403242:	movl %edx, 0x4(%ecx,%edi,8)
0x00403246:	movl %ecx, (%edx)
0x00403248:	subl %ecx, -16(%ebp)
0x0040324b:	movl %esi, %ecx
0x0040324d:	movl -8(%ebp), %ecx
0x00403250:	sarl %esi, $0x4<UINT8>
0x00403253:	decl %esi
0x00403254:	cmpl %esi, $0x3f<UINT8>
0x00403257:	jle 3
0x00403259:	pushl $0x3f<UINT8>
0x0040325b:	popl %esi
0x0040325c:	cmpl %esi, %edi
0x0040325e:	je 0x00403371
0x00403371:	testl %ecx, %ecx
0x00403373:	je 11
0x00403375:	movl (%edx), %ecx
0x00403377:	movl -4(%ecx,%edx), %ecx
0x0040337b:	jmp 0x00403380
0x00403380:	movl %esi, -16(%ebp)
0x00403383:	addl %edx, %ecx
0x00403385:	leal %ecx, 0x1(%esi)
0x00403388:	movl (%edx), %ecx
0x0040338a:	movl -4(%edx,%esi), %ecx
0x0040338e:	movl %esi, -12(%ebp)
0x00403391:	movl %ecx, (%esi)
0x00403393:	testl %ecx, %ecx
0x00403395:	leal %edi, 0x1(%ecx)
0x00403398:	movl (%esi), %edi
0x0040339a:	jne 26
0x0040339c:	cmpl %ebx, 0x422670
0x004033a2:	jne 0x004033b6
0x004033b6:	movl %ecx, -4(%ebp)
0x004033b9:	movl (%eax), %ecx
0x004033bb:	leal %eax, 0x4(%edx)
0x004033be:	popl %edi
0x004033bf:	popl %esi
0x004033c0:	popl %ebx
0x004033c1:	leave
0x004033c2:	ret

0x00402134:	testl %eax, %eax
0x00402136:	popl %ecx
0x00402137:	jne 0x00402155
0x00402155:	popl %esi
0x00402156:	ret

0x00402105:	testl %eax, %eax
0x00402107:	popl %ecx
0x00402108:	jne 0x00402120
0x00402120:	ret

0x004020f2:	popl %ecx
0x004020f3:	popl %ecx
0x004020f4:	ret

0x00403c51:	movl %esi, %eax
0x00403c53:	popl %ecx
0x00403c54:	testl %esi, %esi
0x00403c56:	jne 0x00403c60
0x00403c60:	movl 0x422560, %esi
0x00403c66:	movl 0x422660, $0x20<UINT32>
0x00403c70:	leal %eax, 0x100(%esi)
0x00403c76:	cmpl %esi, %eax
0x00403c78:	jae 0x00403c94
0x00403c7a:	andb 0x4(%esi), $0x0<UINT8>
0x00403c7e:	orl (%esi), $0xffffffff<UINT8>
0x00403c81:	movb 0x5(%esi), $0xa<UINT8>
0x00403c85:	movl %eax, 0x422560
0x00403c8a:	addl %esi, $0x8<UINT8>
0x00403c8d:	addl %eax, $0x100<UINT32>
0x00403c92:	jmp 0x00403c76
0x00403c94:	leal %eax, 0x10(%esp)
0x00403c98:	pushl %eax
0x00403c99:	call GetStartupInfoA@KERNEL32.dll
GetStartupInfoA@KERNEL32.dll: API Node	
0x00403c9f:	cmpw 0x42(%esp), $0x0<UINT8>
0x00403ca5:	je 197
0x00403cab:	movl %eax, 0x44(%esp)
0x00403caf:	testl %eax, %eax
0x00403cb1:	je 185
0x00403cb7:	movl %esi, (%eax)
0x00403cb9:	leal %ebp, 0x4(%eax)
0x00403cbc:	movl %eax, $0x800<UINT32>
0x00403cc1:	cmpl %esi, %eax
0x00403cc3:	leal %ebx, (%esi,%ebp)
0x00403cc6:	jl 0x00403cca
0x00403cca:	cmpl 0x422660, %esi
0x00403cd0:	jnl 0x00403d24
0x00403d24:	xorl %edi, %edi
0x00403d26:	testl %esi, %esi
0x00403d28:	jle 0x00403d70
0x00403d70:	xorl %ebx, %ebx
0x00403d72:	movl %eax, 0x422560
0x00403d77:	cmpl (%eax,%ebx,8), $0xffffffff<UINT8>
0x00403d7b:	leal %esi, (%eax,%ebx,8)
0x00403d7e:	jne 77
0x00403d80:	testl %ebx, %ebx
0x00403d82:	movb 0x4(%esi), $0xffffff81<UINT8>
0x00403d86:	jne 0x00403d8d
0x00403d88:	pushl $0xfffffff6<UINT8>
0x00403d8a:	popl %eax
0x00403d8b:	jmp 0x00403d97
0x00403d97:	pushl %eax
0x00403d98:	call GetStdHandle@KERNEL32.dll
GetStdHandle@KERNEL32.dll: API Node	
0x00403d9e:	movl %edi, %eax
0x00403da0:	cmpl %edi, $0xffffffff<UINT8>
0x00403da3:	je 23
0x00403da5:	pushl %edi
0x00403da6:	call GetFileType@KERNEL32.dll
GetFileType@KERNEL32.dll: API Node	
0x00403dac:	testl %eax, %eax
0x00403dae:	je 12
0x00403db0:	andl %eax, $0xff<UINT32>
0x00403db5:	movl (%esi), %edi
0x00403db7:	cmpl %eax, $0x2<UINT8>
0x00403dba:	jne 6
0x00403dbc:	orb 0x4(%esi), $0x40<UINT8>
0x00403dc0:	jmp 0x00403dd1
0x00403dd1:	incl %ebx
0x00403dd2:	cmpl %ebx, $0x3<UINT8>
0x00403dd5:	jl 0x00403d72
0x00403d8d:	movl %eax, %ebx
0x00403d8f:	decl %eax
0x00403d90:	negl %eax
0x00403d92:	sbbl %eax, %eax
0x00403d94:	addl %eax, $0xfffffff5<UINT8>
0x00403dd7:	pushl 0x422660
0x00403ddd:	call SetHandleCount@KERNEL32.dll
SetHandleCount@KERNEL32.dll: API Node	
0x00403de3:	popl %edi
0x00403de4:	popl %esi
0x00403de5:	popl %ebp
0x00403de6:	popl %ebx
0x00403de7:	addl %esp, $0x44<UINT8>
0x00403dea:	ret

0x0040228e:	call GetCommandLineA@KERNEL32.dll
GetCommandLineA@KERNEL32.dll: API Node	
0x00402294:	movl 0x4236a4, %eax
0x00402299:	call 0x00403b0e
0x00403b0e:	pushl %ecx
0x00403b0f:	pushl %ecx
0x00403b10:	movl %eax, 0x4222d4
0x00403b15:	pushl %ebx
0x00403b16:	pushl %ebp
0x00403b17:	movl %ebp, 0x4060e4
0x00403b1d:	pushl %esi
0x00403b1e:	pushl %edi
0x00403b1f:	xorl %ebx, %ebx
0x00403b21:	xorl %esi, %esi
0x00403b23:	xorl %edi, %edi
0x00403b25:	cmpl %eax, %ebx
0x00403b27:	jne 51
0x00403b29:	call GetEnvironmentStringsW@KERNEL32.dll
GetEnvironmentStringsW@KERNEL32.dll: API Node	
0x00403b2b:	movl %esi, %eax
0x00403b2d:	cmpl %esi, %ebx
0x00403b2f:	je 12
0x00403b31:	movl 0x4222d4, $0x1<UINT32>
0x00403b3b:	jmp 0x00403b65
0x00403b65:	cmpl %esi, %ebx
0x00403b67:	jne 0x00403b75
0x00403b75:	cmpw (%esi), %bx
0x00403b78:	movl %eax, %esi
0x00403b7a:	je 14
0x00403b7c:	incl %eax
0x00403b7d:	incl %eax
0x00403b7e:	cmpw (%eax), %bx
0x00403b81:	jne 0x00403b7c
0x00403b83:	incl %eax
0x00403b84:	incl %eax
0x00403b85:	cmpw (%eax), %bx
0x00403b88:	jne 0x00403b7c
0x00403b8a:	subl %eax, %esi
0x00403b8c:	movl %edi, 0x4060dc
0x00403b92:	sarl %eax
0x00403b94:	pushl %ebx
0x00403b95:	pushl %ebx
0x00403b96:	incl %eax
0x00403b97:	pushl %ebx
0x00403b98:	pushl %ebx
0x00403b99:	pushl %eax
0x00403b9a:	pushl %esi
0x00403b9b:	pushl %ebx
0x00403b9c:	pushl %ebx
0x00403b9d:	movl 0x34(%esp), %eax
0x00403ba1:	call WideCharToMultiByte@KERNEL32.dll
WideCharToMultiByte@KERNEL32.dll: API Node	
0x00403ba3:	movl %ebp, %eax
0x00403ba5:	cmpl %ebp, %ebx
0x00403ba7:	je 50
0x00403ba9:	pushl %ebp
0x00403baa:	call 0x004020e3
0x00402139:	testl %esi, %esi
0x0040213b:	jne 0x00402140
0x00402140:	addl %esi, $0xf<UINT8>
0x00402143:	andl %esi, $0xfffffff0<UINT8>
0x00402146:	pushl %esi
0x00402147:	pushl $0x0<UINT8>
0x00402149:	pushl 0x42267c
0x0040214f:	call HeapAlloc@KERNEL32.dll
0x00403baf:	cmpl %eax, %ebx
0x00403bb1:	popl %ecx
0x00403bb2:	movl 0x10(%esp), %eax
0x00403bb6:	je 35
0x00403bb8:	pushl %ebx
0x00403bb9:	pushl %ebx
0x00403bba:	pushl %ebp
0x00403bbb:	pushl %eax
0x00403bbc:	pushl 0x24(%esp)
0x00403bc0:	pushl %esi
0x00403bc1:	pushl %ebx
0x00403bc2:	pushl %ebx
0x00403bc3:	call WideCharToMultiByte@KERNEL32.dll
0x00403bc5:	testl %eax, %eax
0x00403bc7:	jne 0x00403bd7
0x00403bd7:	movl %ebx, 0x10(%esp)
0x00403bdb:	pushl %esi
0x00403bdc:	call FreeEnvironmentStringsW@KERNEL32.dll
FreeEnvironmentStringsW@KERNEL32.dll: API Node	
0x00403be2:	movl %eax, %ebx
0x00403be4:	jmp 0x00403c39
0x00403c39:	popl %edi
0x00403c3a:	popl %esi
0x00403c3b:	popl %ebp
0x00403c3c:	popl %ebx
0x00403c3d:	popl %ecx
0x00403c3e:	popl %ecx
0x00403c3f:	ret

0x0040229e:	movl 0x4221ac, %eax
0x004022a3:	call 0x004038c1
0x004038c1:	pushl %ebp
0x004038c2:	movl %ebp, %esp
0x004038c4:	pushl %ecx
0x004038c5:	pushl %ecx
0x004038c6:	pushl %ebx
0x004038c7:	xorl %ebx, %ebx
0x004038c9:	cmpl 0x4236ac, %ebx
0x004038cf:	pushl %esi
0x004038d0:	pushl %edi
0x004038d1:	jne 5
0x004038d3:	call 0x00404fa4
0x00404fa4:	cmpl 0x4236ac, $0x0<UINT8>
0x00404fab:	jne 18
0x00404fad:	pushl $0xfffffffd<UINT8>
0x00404faf:	call 0x00404be0
0x00404be0:	pushl %ebp
0x00404be1:	movl %ebp, %esp
0x00404be3:	subl %esp, $0x18<UINT8>
0x00404be6:	pushl %ebx
0x00404be7:	pushl %esi
0x00404be8:	pushl %edi
0x00404be9:	pushl 0x8(%ebp)
0x00404bec:	call 0x00404d79
0x00404d79:	movl %eax, 0x4(%esp)
0x00404d7d:	andl 0x4222dc, $0x0<UINT8>
0x00404d84:	cmpl %eax, $0xfffffffe<UINT8>
0x00404d87:	jne 0x00404d99
0x00404d99:	cmpl %eax, $0xfffffffd<UINT8>
0x00404d9c:	jne 16
0x00404d9e:	movl 0x4222dc, $0x1<UINT32>
0x00404da8:	jmp GetACP@KERNEL32.dll
GetACP@KERNEL32.dll: API Node	
0x00404bf1:	movl %esi, %eax
0x00404bf3:	popl %ecx
0x00404bf4:	cmpl %esi, 0x422314
0x00404bfa:	movl 0x8(%ebp), %esi
0x00404bfd:	je 362
0x00404c03:	xorl %ebx, %ebx
0x00404c05:	cmpl %esi, %ebx
0x00404c07:	je 342
0x00404c0d:	xorl %edx, %edx
0x00404c0f:	movl %eax, $0x421ee8<UINT32>
0x00404c14:	cmpl (%eax), %esi
0x00404c16:	je 114
0x00404c18:	addl %eax, $0x30<UINT8>
0x00404c1b:	incl %edx
0x00404c1c:	cmpl %eax, $0x421fd8<UINT32>
0x00404c21:	jl 0x00404c14
0x00404c23:	leal %eax, -24(%ebp)
0x00404c26:	pushl %eax
0x00404c27:	pushl %esi
0x00404c28:	call GetCPInfo@KERNEL32.dll
GetCPInfo@KERNEL32.dll: API Node	
0x00404c2e:	cmpl %eax, $0x1<UINT8>
0x00404c31:	jne 292
0x00404c37:	pushl $0x40<UINT8>
0x00404c39:	xorl %eax, %eax
0x00404c3b:	popl %ecx
0x00404c3c:	movl %edi, $0x422440<UINT32>
0x00404c41:	cmpl -24(%ebp), $0x1<UINT8>
0x00404c45:	movl 0x422314, %esi
0x00404c4b:	rep stosl %es:(%edi), %eax
0x00404c4d:	stosb %es:(%edi), %al
0x00404c4e:	movl 0x422544, %ebx
0x00404c54:	jbe 239
0x00404c5a:	cmpb -18(%ebp), $0x0<UINT8>
0x00404c5e:	je 0x00404d1f
0x00404d1f:	pushl $0x1<UINT8>
0x00404d21:	popl %eax
0x00404d22:	orb 0x422441(%eax), $0x8<UINT8>
0x00404d29:	incl %eax
0x00404d2a:	cmpl %eax, $0xff<UINT32>
0x00404d2f:	jb 0x00404d22
0x00404d31:	pushl %esi
0x00404d32:	call 0x00404dc3
0x00404dc3:	movl %eax, 0x4(%esp)
0x00404dc7:	subl %eax, $0x3a4<UINT32>
0x00404dcc:	je 34
0x00404dce:	subl %eax, $0x4<UINT8>
0x00404dd1:	je 23
0x00404dd3:	subl %eax, $0xd<UINT8>
0x00404dd6:	je 12
0x00404dd8:	decl %eax
0x00404dd9:	je 3
0x00404ddb:	xorl %eax, %eax
0x00404ddd:	ret

0x00404d37:	popl %ecx
0x00404d38:	movl 0x422544, %eax
0x00404d3d:	movl 0x42232c, $0x1<UINT32>
0x00404d47:	jmp 0x00404d4f
0x00404d4f:	xorl %eax, %eax
0x00404d51:	movl %edi, $0x422320<UINT32>
0x00404d56:	stosl %es:(%edi), %eax
0x00404d57:	stosl %es:(%edi), %eax
0x00404d58:	stosl %es:(%edi), %eax
0x00404d59:	jmp 0x00404d68
0x00404d68:	call 0x00404e1f
0x00404e1f:	pushl %ebp
0x00404e20:	movl %ebp, %esp
0x00404e22:	subl %esp, $0x514<UINT32>
0x00404e28:	leal %eax, -20(%ebp)
0x00404e2b:	pushl %esi
0x00404e2c:	pushl %eax
0x00404e2d:	pushl 0x422314
0x00404e33:	call GetCPInfo@KERNEL32.dll
0x00404e39:	cmpl %eax, $0x1<UINT8>
0x00404e3c:	jne 278
0x00404e42:	xorl %eax, %eax
0x00404e44:	movl %esi, $0x100<UINT32>
0x00404e49:	movb -276(%ebp,%eax), %al
0x00404e50:	incl %eax
0x00404e51:	cmpl %eax, %esi
0x00404e53:	jb 0x00404e49
0x00404e55:	movb %al, -14(%ebp)
0x00404e58:	movb -276(%ebp), $0x20<UINT8>
0x00404e5f:	testb %al, %al
0x00404e61:	je 0x00404e9a
0x00404e9a:	pushl $0x0<UINT8>
0x00404e9c:	leal %eax, -1300(%ebp)
0x00404ea2:	pushl 0x422544
0x00404ea8:	pushl 0x422314
0x00404eae:	pushl %eax
0x00404eaf:	leal %eax, -276(%ebp)
0x00404eb5:	pushl %esi
0x00404eb6:	pushl %eax
0x00404eb7:	pushl $0x1<UINT8>
0x00404eb9:	call 0x004058fb
0x004058fb:	pushl %ebp
0x004058fc:	movl %ebp, %esp
0x004058fe:	pushl $0xffffffff<UINT8>
0x00405900:	pushl $0x406508<UINT32>
0x00405905:	pushl $0x403ee4<UINT32>
0x0040590a:	movl %eax, %fs:0
0x00405910:	pushl %eax
0x00405911:	movl %fs:0, %esp
0x00405918:	subl %esp, $0x18<UINT8>
0x0040591b:	pushl %ebx
0x0040591c:	pushl %esi
0x0040591d:	pushl %edi
0x0040591e:	movl -24(%ebp), %esp
0x00405921:	movl %eax, 0x422310
0x00405926:	xorl %ebx, %ebx
0x00405928:	cmpl %eax, %ebx
0x0040592a:	jne 62
0x0040592c:	leal %eax, -28(%ebp)
0x0040592f:	pushl %eax
0x00405930:	pushl $0x1<UINT8>
0x00405932:	popl %esi
0x00405933:	pushl %esi
0x00405934:	pushl $0x4064e8<UINT32>
0x00405939:	pushl %esi
0x0040593a:	call GetStringTypeW@KERNEL32.dll
GetStringTypeW@KERNEL32.dll: API Node	
0x00405940:	testl %eax, %eax
0x00405942:	je 4
0x00405944:	movl %eax, %esi
0x00405946:	jmp 0x00405965
0x00405965:	movl 0x422310, %eax
0x0040596a:	cmpl %eax, $0x2<UINT8>
0x0040596d:	jne 0x00405993
0x00405993:	cmpl %eax, $0x1<UINT8>
0x00405996:	jne 148
0x0040599c:	cmpl 0x18(%ebp), %ebx
0x0040599f:	jne 0x004059a9
0x004059a9:	pushl %ebx
0x004059aa:	pushl %ebx
0x004059ab:	pushl 0x10(%ebp)
0x004059ae:	pushl 0xc(%ebp)
0x004059b1:	movl %eax, 0x20(%ebp)
0x004059b4:	negl %eax
0x004059b6:	sbbl %eax, %eax
0x004059b8:	andl %eax, $0x8<UINT8>
0x004059bb:	incl %eax
0x004059bc:	pushl %eax
0x004059bd:	pushl 0x18(%ebp)
0x004059c0:	call MultiByteToWideChar@KERNEL32.dll
MultiByteToWideChar@KERNEL32.dll: API Node	
0x004059c6:	movl -32(%ebp), %eax
0x004059c9:	cmpl %eax, %ebx
0x004059cb:	je 99
0x004059cd:	movl -4(%ebp), %ebx
0x004059d0:	leal %edi, (%eax,%eax)
0x004059d3:	movl %eax, %edi
0x004059d5:	addl %eax, $0x3<UINT8>
0x004059d8:	andb %al, $0xfffffffc<UINT8>
0x004059da:	call 0x00405b30
0x00405b30:	pushl %ecx
0x00405b31:	cmpl %eax, $0x1000<UINT32>
0x00405b36:	leal %ecx, 0x8(%esp)
0x00405b3a:	jb 0x00405b50
0x00405b50:	subl %ecx, %eax
0x00405b52:	movl %eax, %esp
0x00405b54:	testl (%ecx), %eax
0x00405b56:	movl %esp, %ecx
0x00405b58:	movl %ecx, (%eax)
0x00405b5a:	movl %eax, 0x4(%eax)
0x00405b5d:	pushl %eax
0x00405b5e:	ret

0x004059df:	movl -24(%ebp), %esp
0x004059e2:	movl %esi, %esp
0x004059e4:	movl -36(%ebp), %esi
0x004059e7:	pushl %edi
0x004059e8:	pushl %ebx
0x004059e9:	pushl %esi
0x004059ea:	call 0x004054e0
0x004054e0:	movl %edx, 0xc(%esp)
0x004054e4:	movl %ecx, 0x4(%esp)
0x004054e8:	testl %edx, %edx
0x004054ea:	je 71
0x004054ec:	xorl %eax, %eax
0x004054ee:	movb %al, 0x8(%esp)
0x004054f2:	pushl %edi
0x004054f3:	movl %edi, %ecx
0x004054f5:	cmpl %edx, $0x4<UINT8>
0x004054f8:	jb 45
0x004054fa:	negl %ecx
0x004054fc:	andl %ecx, $0x3<UINT8>
0x004054ff:	je 0x00405509
0x00405509:	movl %ecx, %eax
0x0040550b:	shll %eax, $0x8<UINT8>
0x0040550e:	addl %eax, %ecx
0x00405510:	movl %ecx, %eax
0x00405512:	shll %eax, $0x10<UINT8>
0x00405515:	addl %eax, %ecx
0x00405517:	movl %ecx, %edx
0x00405519:	andl %edx, $0x3<UINT8>
0x0040551c:	shrl %ecx, $0x2<UINT8>
0x0040551f:	je 6
0x00405521:	rep stosl %es:(%edi), %eax
