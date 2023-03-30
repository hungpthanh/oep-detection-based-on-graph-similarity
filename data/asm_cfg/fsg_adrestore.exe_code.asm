0x0042d000:	movl %ebx, $0x4001d0<UINT32>
0x0042d005:	movl %edi, $0x401000<UINT32>
0x0042d00a:	movl %esi, $0x425000<UINT32>
0x0042d00f:	pushl %ebx
0x0042d010:	call 0x0042d01f
0x0042d01f:	cld
0x0042d020:	movb %dl, $0xffffff80<UINT8>
0x0042d022:	movsb %es:(%edi), %ds:(%esi)
0x0042d023:	pushl $0x2<UINT8>
0x0042d025:	popl %ebx
0x0042d026:	call 0x0042d015
0x0042d015:	addb %dl, %dl
0x0042d017:	jne 0x0042d01e
0x0042d019:	movb %dl, (%esi)
0x0042d01b:	incl %esi
0x0042d01c:	adcb %dl, %dl
0x0042d01e:	ret

0x0042d029:	jae 0x0042d022
0x0042d02b:	xorl %ecx, %ecx
0x0042d02d:	call 0x0042d015
0x0042d030:	jae 0x0042d04a
0x0042d032:	xorl %eax, %eax
0x0042d034:	call 0x0042d015
0x0042d037:	jae 0x0042d05a
0x0042d039:	movb %bl, $0x2<UINT8>
0x0042d03b:	incl %ecx
0x0042d03c:	movb %al, $0x10<UINT8>
0x0042d03e:	call 0x0042d015
0x0042d041:	adcb %al, %al
0x0042d043:	jae 0x0042d03e
0x0042d045:	jne 0x0042d086
0x0042d047:	stosb %es:(%edi), %al
0x0042d048:	jmp 0x0042d026
0x0042d086:	pushl %esi
0x0042d087:	movl %esi, %edi
0x0042d089:	subl %esi, %eax
0x0042d08b:	rep movsb %es:(%edi), %ds:(%esi)
0x0042d08d:	popl %esi
0x0042d08e:	jmp 0x0042d026
0x0042d05a:	lodsb %al, %ds:(%esi)
0x0042d05b:	shrl %eax
0x0042d05d:	je 0x0042d0a0
0x0042d05f:	adcl %ecx, %ecx
0x0042d061:	jmp 0x0042d07f
0x0042d07f:	incl %ecx
0x0042d080:	incl %ecx
0x0042d081:	xchgl %ebp, %eax
0x0042d082:	movl %eax, %ebp
0x0042d084:	movb %bl, $0x1<UINT8>
0x0042d04a:	call 0x0042d092
0x0042d092:	incl %ecx
0x0042d093:	call 0x0042d015
0x0042d097:	adcl %ecx, %ecx
0x0042d099:	call 0x0042d015
0x0042d09d:	jb 0x0042d093
0x0042d09f:	ret

0x0042d04f:	subl %ecx, %ebx
0x0042d051:	jne 0x0042d063
0x0042d063:	xchgl %ecx, %eax
0x0042d064:	decl %eax
0x0042d065:	shll %eax, $0x8<UINT8>
0x0042d068:	lodsb %al, %ds:(%esi)
0x0042d069:	call 0x0042d090
0x0042d090:	xorl %ecx, %ecx
0x0042d06e:	cmpl %eax, $0x7d00<UINT32>
0x0042d073:	jae 0x0042d07f
0x0042d075:	cmpb %ah, $0x5<UINT8>
0x0042d078:	jae 0x0042d080
0x0042d07a:	cmpl %eax, $0x7f<UINT8>
0x0042d07d:	ja 0x0042d081
0x0042d053:	call 0x0042d090
0x0042d058:	jmp 0x0042d082
0x0042d0a0:	popl %edi
0x0042d0a1:	popl %ebx
0x0042d0a2:	movzwl %edi, (%ebx)
0x0042d0a5:	decl %edi
0x0042d0a6:	je 0x0042d0b0
0x0042d0a8:	decl %edi
0x0042d0a9:	je 0x0042d0be
0x0042d0ab:	shll %edi, $0xc<UINT8>
0x0042d0ae:	jmp 0x0042d0b7
0x0042d0b7:	incl %ebx
0x0042d0b8:	incl %ebx
0x0042d0b9:	jmp 0x0042d00f
0x0042d0b0:	movl %edi, 0x2(%ebx)
0x0042d0b3:	pushl %edi
0x0042d0b4:	addl %ebx, $0x4<UINT8>
0x0042d0be:	popl %edi
0x0042d0bf:	movl %ebx, $0x42d128<UINT32>
0x0042d0c4:	incl %edi
0x0042d0c5:	movl %esi, (%edi)
0x0042d0c7:	scasl %eax, %es:(%edi)
0x0042d0c8:	pushl %edi
0x0042d0c9:	call LoadLibraryA@KERNEL32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0042d0cb:	xchgl %ebp, %eax
0x0042d0cc:	xorl %eax, %eax
0x0042d0ce:	scasb %al, %es:(%edi)
0x0042d0cf:	jne 0x0042d0ce
0x0042d0d1:	decb (%edi)
0x0042d0d3:	je 0x0042d0c4
0x0042d0d5:	decb (%edi)
0x0042d0d7:	jne 0x0042d0df
0x0042d0d9:	incl %edi
0x0042d0da:	pushl (%edi)
0x0042d0dc:	scasl %eax, %es:(%edi)
0x0042d0dd:	jmp 0x0042d0e8
0x0042d0e8:	pushl %ebp
0x0042d0e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x0042d0ec:	orl (%esi), %eax
0x0042d0ee:	lodsl %eax, %ds:(%esi)
0x0042d0ef:	jne 0x0042d0cc
0x0042d0df:	decb (%edi)
0x0042d0e1:	je 0x00402471
0x0042d0e7:	pushl %edi
GetProcAddress@KERNEL32.dll: API Node	
LoadLibraryA@KERNEL32.dll: API Node	
0x00402471:	pushl %ebp
0x00402472:	movl %ebp, %esp
0x00402474:	pushl $0xffffffff<UINT8>
0x00402476:	pushl $0x407450<UINT32>
0x0040247b:	pushl $0x405064<UINT32>
0x00402480:	movl %eax, %fs:0
0x00402486:	pushl %eax
0x00402487:	movl %fs:0, %esp
0x0040248e:	subl %esp, $0x10<UINT8>
0x00402491:	pushl %ebx
0x00402492:	pushl %esi
0x00402493:	pushl %edi
0x00402494:	movl -24(%ebp), %esp
0x00402497:	call GetVersion@KERNEL32.dll
GetVersion@KERNEL32.dll: API Node	
0x0040249d:	xorl %edx, %edx
0x0040249f:	movb %dl, %ah
0x004024a1:	movl 0x422f40, %edx
0x004024a7:	movl %ecx, %eax
0x004024a9:	andl %ecx, $0xff<UINT32>
0x004024af:	movl 0x422f3c, %ecx
0x004024b5:	shll %ecx, $0x8<UINT8>
0x004024b8:	addl %ecx, %edx
0x004024ba:	movl 0x422f38, %ecx
0x004024c0:	shrl %eax, $0x10<UINT8>
0x004024c3:	movl 0x422f34, %eax
0x004024c8:	pushl $0x0<UINT8>
0x004024ca:	call 0x00404071
0x00404071:	xorl %eax, %eax
0x00404073:	pushl $0x0<UINT8>
0x00404075:	cmpl 0x8(%esp), %eax
0x00404079:	pushl $0x1000<UINT32>
0x0040407e:	sete %al
0x00404081:	pushl %eax
0x00404082:	call HeapCreate@KERNEL32.dll
HeapCreate@KERNEL32.dll: API Node	
0x00404088:	testl %eax, %eax
0x0040408a:	movl 0x4231c4, %eax
0x0040408f:	je 21
0x00404091:	call 0x004040ad
0x004040ad:	pushl $0x140<UINT32>
0x004040b2:	pushl $0x0<UINT8>
0x004040b4:	pushl 0x4231c4
0x004040ba:	call HeapAlloc@KERNEL32.dll
HeapAlloc@KERNEL32.dll: API Node	
0x004040c0:	testl %eax, %eax
0x004040c2:	movl 0x4231c0, %eax
0x004040c7:	jne 0x004040ca
0x004040ca:	andl 0x4231b8, $0x0<UINT8>
0x004040d1:	andl 0x4231bc, $0x0<UINT8>
0x004040d8:	pushl $0x1<UINT8>
0x004040da:	movl 0x4231b4, %eax
0x004040df:	movl 0x4231ac, $0x10<UINT32>
0x004040e9:	popl %eax
0x004040ea:	ret

0x00404096:	testl %eax, %eax
0x00404098:	jne 0x004040a9
0x004040a9:	pushl $0x1<UINT8>
0x004040ab:	popl %eax
0x004040ac:	ret

0x004024cf:	popl %ecx
0x004024d0:	testl %eax, %eax
0x004024d2:	jne 0x004024dc
0x004024dc:	andl -4(%ebp), $0x0<UINT8>
0x004024e0:	call 0x0040341d
0x0040341d:	subl %esp, $0x44<UINT8>
0x00403420:	pushl %ebx
0x00403421:	pushl %ebp
0x00403422:	pushl %esi
0x00403423:	pushl %edi
0x00403424:	pushl $0x100<UINT32>
0x00403429:	call 0x00402357
0x00402357:	pushl 0x422f7c
0x0040235d:	pushl 0x8(%esp)
0x00402361:	call 0x00402369
0x00402369:	cmpl 0x4(%esp), $0xffffffe0<UINT8>
0x0040236e:	ja 34
0x00402370:	pushl 0x4(%esp)
0x00402374:	call 0x00402395
0x00402395:	pushl %esi
0x00402396:	movl %esi, 0x8(%esp)
0x0040239a:	cmpl %esi, 0x422a14
0x004023a0:	ja 0x004023ad
0x004023a2:	pushl %esi
0x004023a3:	call 0x00404441
0x00404441:	pushl %ebp
0x00404442:	movl %ebp, %esp
0x00404444:	subl %esp, $0x14<UINT8>
0x00404447:	movl %eax, 0x4231bc
0x0040444c:	movl %edx, 0x4231c0
0x00404452:	pushl %ebx
0x00404453:	pushl %esi
0x00404454:	leal %eax, (%eax,%eax,4)
0x00404457:	pushl %edi
0x00404458:	leal %edi, (%edx,%eax,4)
0x0040445b:	movl %eax, 0x8(%ebp)
0x0040445e:	movl -4(%ebp), %edi
0x00404461:	leal %ecx, 0x17(%eax)
0x00404464:	andl %ecx, $0xfffffff0<UINT8>
0x00404467:	movl -16(%ebp), %ecx
0x0040446a:	sarl %ecx, $0x4<UINT8>
0x0040446d:	decl %ecx
0x0040446e:	cmpl %ecx, $0x20<UINT8>
0x00404471:	jnl 0x00404481
0x00404473:	orl %esi, $0xffffffff<UINT8>
0x00404476:	shrl %esi, %cl
0x00404478:	orl -8(%ebp), $0xffffffff<UINT8>
0x0040447c:	movl -12(%ebp), %esi
0x0040447f:	jmp 0x00404491
0x00404491:	movl %eax, 0x4231b4
0x00404496:	movl %ebx, %eax
0x00404498:	cmpl %ebx, %edi
0x0040449a:	movl 0x8(%ebp), %ebx
0x0040449d:	jae 0x004044b8
0x004044b8:	cmpl %ebx, -4(%ebp)
0x004044bb:	jne 0x00404536
0x004044bd:	movl %ebx, %edx
0x004044bf:	cmpl %ebx, %eax
0x004044c1:	movl 0x8(%ebp), %ebx
0x004044c4:	jae 0x004044db
0x004044db:	jne 89
0x004044dd:	cmpl %ebx, -4(%ebp)
0x004044e0:	jae 0x004044f3
0x004044f3:	jne 38
0x004044f5:	movl %ebx, %edx
0x004044f7:	cmpl %ebx, %eax
0x004044f9:	movl 0x8(%ebp), %ebx
0x004044fc:	jae 0x0040450b
0x0040450b:	jne 14
0x0040450d:	call 0x0040474a
0x0040474a:	movl %eax, 0x4231bc
0x0040474f:	movl %ecx, 0x4231ac
0x00404755:	pushl %esi
0x00404756:	pushl %edi
0x00404757:	xorl %edi, %edi
0x00404759:	cmpl %eax, %ecx
0x0040475b:	jne 0x0040478d
0x0040478d:	movl %ecx, 0x4231c0
0x00404793:	pushl $0x41c4<UINT32>
0x00404798:	pushl $0x8<UINT8>
0x0040479a:	leal %eax, (%eax,%eax,4)
0x0040479d:	pushl 0x4231c4
0x004047a3:	leal %esi, (%ecx,%eax,4)
0x004047a6:	call HeapAlloc@KERNEL32.dll
0x004047ac:	cmpl %eax, %edi
0x004047ae:	movl 0x10(%esi), %eax
0x004047b1:	je 42
0x004047b3:	pushl $0x4<UINT8>
0x004047b5:	pushl $0x2000<UINT32>
0x004047ba:	pushl $0x100000<UINT32>
0x004047bf:	pushl %edi
0x004047c0:	call VirtualAlloc@KERNEL32.dll
VirtualAlloc@KERNEL32.dll: API Node	
0x004047c6:	cmpl %eax, %edi
0x004047c8:	movl 0xc(%esi), %eax
0x004047cb:	jne 0x004047e1
0x004047e1:	orl 0x8(%esi), $0xffffffff<UINT8>
0x004047e5:	movl (%esi), %edi
0x004047e7:	movl 0x4(%esi), %edi
0x004047ea:	incl 0x4231bc
0x004047f0:	movl %eax, 0x10(%esi)
0x004047f3:	orl (%eax), $0xffffffff<UINT8>
0x004047f6:	movl %eax, %esi
0x004047f8:	popl %edi
0x004047f9:	popl %esi
0x004047fa:	ret

0x00404512:	movl %ebx, %eax
0x00404514:	testl %ebx, %ebx
0x00404516:	movl 0x8(%ebp), %ebx
0x00404519:	je 20
0x0040451b:	pushl %ebx
0x0040451c:	call 0x004047fb
0x004047fb:	pushl %ebp
0x004047fc:	movl %ebp, %esp
0x004047fe:	pushl %ecx
0x004047ff:	movl %ecx, 0x8(%ebp)
0x00404802:	pushl %ebx
0x00404803:	pushl %esi
0x00404804:	pushl %edi
0x00404805:	movl %esi, 0x10(%ecx)
0x00404808:	movl %eax, 0x8(%ecx)
0x0040480b:	xorl %ebx, %ebx
0x0040480d:	testl %eax, %eax
0x0040480f:	jl 0x00404816
0x00404816:	movl %eax, %ebx
0x00404818:	pushl $0x3f<UINT8>
0x0040481a:	imull %eax, %eax, $0x204<UINT32>
0x00404820:	popl %edx
0x00404821:	leal %eax, 0x144(%eax,%esi)
0x00404828:	movl -4(%ebp), %eax
0x0040482b:	movl 0x8(%eax), %eax
0x0040482e:	movl 0x4(%eax), %eax
0x00404831:	addl %eax, $0x8<UINT8>
0x00404834:	decl %edx
0x00404835:	jne 0x0040482b
0x00404837:	movl %edi, %ebx
0x00404839:	pushl $0x4<UINT8>
0x0040483b:	shll %edi, $0xf<UINT8>
0x0040483e:	addl %edi, 0xc(%ecx)
0x00404841:	pushl $0x1000<UINT32>
0x00404846:	pushl $0x8000<UINT32>
0x0040484b:	pushl %edi
0x0040484c:	call VirtualAlloc@KERNEL32.dll
0x00404852:	testl %eax, %eax
0x00404854:	jne 0x0040485e
0x0040485e:	leal %edx, 0x7000(%edi)
0x00404864:	cmpl %edi, %edx
0x00404866:	ja 60
0x00404868:	leal %eax, 0x10(%edi)
0x0040486b:	orl -8(%eax), $0xffffffff<UINT8>
0x0040486f:	orl 0xfec(%eax), $0xffffffff<UINT8>
0x00404876:	leal %ecx, 0xffc(%eax)
0x0040487c:	movl -4(%eax), $0xff0<UINT32>
0x00404883:	movl (%eax), %ecx
0x00404885:	leal %ecx, -4100(%eax)
0x0040488b:	movl 0x4(%eax), %ecx
0x0040488e:	movl 0xfe8(%eax), $0xff0<UINT32>
0x00404898:	addl %eax, $0x1000<UINT32>
0x0040489d:	leal %ecx, -16(%eax)
0x004048a0:	cmpl %ecx, %edx
0x004048a2:	jbe 0x0040486b
0x004048a4:	movl %eax, -4(%ebp)
0x004048a7:	leal %ecx, 0xc(%edi)
0x004048aa:	addl %eax, $0x1f8<UINT32>
0x004048af:	pushl $0x1<UINT8>
0x004048b1:	popl %edi
0x004048b2:	movl 0x4(%eax), %ecx
0x004048b5:	movl 0x8(%ecx), %eax
0x004048b8:	leal %ecx, 0xc(%edx)
0x004048bb:	movl 0x8(%eax), %ecx
0x004048be:	movl 0x4(%ecx), %eax
0x004048c1:	andl 0x44(%esi,%ebx,4), $0x0<UINT8>
0x004048c6:	movl 0xc4(%esi,%ebx,4), %edi
0x004048cd:	movb %al, 0x43(%esi)
0x004048d0:	movb %cl, %al
0x004048d2:	incb %cl
0x004048d4:	testb %al, %al
0x004048d6:	movl %eax, 0x8(%ebp)
0x004048d9:	movb 0x43(%esi), %cl
0x004048dc:	jne 3
0x004048de:	orl 0x4(%eax), %edi
0x004048e1:	movl %edx, $0x80000000<UINT32>
0x004048e6:	movl %ecx, %ebx
0x004048e8:	shrl %edx, %cl
0x004048ea:	notl %edx
0x004048ec:	andl 0x8(%eax), %edx
0x004048ef:	movl %eax, %ebx
0x004048f1:	popl %edi
0x004048f2:	popl %esi
0x004048f3:	popl %ebx
0x004048f4:	leave
0x004048f5:	ret

0x00404521:	popl %ecx
0x00404522:	movl %ecx, 0x10(%ebx)
0x00404525:	movl (%ecx), %eax
0x00404527:	movl %eax, 0x10(%ebx)
0x0040452a:	cmpl (%eax), $0xffffffff<UINT8>
0x0040452d:	jne 0x00404536
0x00404536:	movl 0x4231b4, %ebx
0x0040453c:	movl %eax, 0x10(%ebx)
0x0040453f:	movl %edx, (%eax)
0x00404541:	cmpl %edx, $0xffffffff<UINT8>
0x00404544:	movl -4(%ebp), %edx
0x00404547:	je 20
0x00404549:	movl %ecx, 0xc4(%eax,%edx,4)
0x00404550:	movl %edi, 0x44(%eax,%edx,4)
0x00404554:	andl %ecx, -8(%ebp)
0x00404557:	andl %edi, %esi
0x00404559:	orl %ecx, %edi
0x0040455b:	jne 0x00404594
0x00404594:	movl %ecx, %edx
0x00404596:	xorl %edi, %edi
0x00404598:	imull %ecx, %ecx, $0x204<UINT32>
0x0040459e:	leal %ecx, 0x144(%ecx,%eax)
0x004045a5:	movl -12(%ebp), %ecx
0x004045a8:	movl %ecx, 0x44(%eax,%edx,4)
0x004045ac:	andl %ecx, %esi
0x004045ae:	jne 0x004045bd
0x004045b0:	movl %ecx, 0xc4(%eax,%edx,4)
0x004045b7:	pushl $0x20<UINT8>
0x004045b9:	andl %ecx, -8(%ebp)
0x004045bc:	popl %edi
0x004045bd:	testl %ecx, %ecx
0x004045bf:	jl 0x004045c6
0x004045c1:	shll %ecx
0x004045c3:	incl %edi
0x004045c4:	jmp 0x004045bd
0x004045c6:	movl %ecx, -12(%ebp)
0x004045c9:	movl %edx, 0x4(%ecx,%edi,8)
0x004045cd:	movl %ecx, (%edx)
0x004045cf:	subl %ecx, -16(%ebp)
0x004045d2:	movl %esi, %ecx
0x004045d4:	movl -8(%ebp), %ecx
0x004045d7:	sarl %esi, $0x4<UINT8>
0x004045da:	decl %esi
0x004045db:	cmpl %esi, $0x3f<UINT8>
0x004045de:	jle 0x004045e3
0x004045e0:	pushl $0x3f<UINT8>
0x004045e2:	popl %esi
0x004045e3:	cmpl %esi, %edi
0x004045e5:	je 0x004046f8
0x004046f8:	testl %ecx, %ecx
0x004046fa:	je 11
0x004046fc:	movl (%edx), %ecx
0x004046fe:	movl -4(%ecx,%edx), %ecx
0x00404702:	jmp 0x00404707
0x00404707:	movl %esi, -16(%ebp)
0x0040470a:	addl %edx, %ecx
0x0040470c:	leal %ecx, 0x1(%esi)
0x0040470f:	movl (%edx), %ecx
0x00404711:	movl -4(%edx,%esi), %ecx
0x00404715:	movl %esi, -12(%ebp)
0x00404718:	movl %ecx, (%esi)
0x0040471a:	testl %ecx, %ecx
0x0040471c:	leal %edi, 0x1(%ecx)
0x0040471f:	movl (%esi), %edi
0x00404721:	jne 0x0040473d
0x00404723:	cmpl %ebx, 0x4231b8
0x00404729:	jne 0x0040473d
0x0040473d:	movl %ecx, -4(%ebp)
0x00404740:	movl (%eax), %ecx
0x00404742:	leal %eax, 0x4(%edx)
0x00404745:	popl %edi
0x00404746:	popl %esi
0x00404747:	popl %ebx
0x00404748:	leave
0x00404749:	ret

0x004023a8:	testl %eax, %eax
0x004023aa:	popl %ecx
0x004023ab:	jne 0x004023c9
0x004023c9:	popl %esi
0x004023ca:	ret

0x00402379:	testl %eax, %eax
0x0040237b:	popl %ecx
0x0040237c:	jne 0x00402394
0x00402394:	ret

0x00402366:	popl %ecx
0x00402367:	popl %ecx
0x00402368:	ret

0x0040342e:	movl %esi, %eax
0x00403430:	popl %ecx
0x00403431:	testl %esi, %esi
0x00403433:	jne 0x0040343d
0x0040343d:	movl 0x4231e0, %esi
0x00403443:	movl 0x4232e0, $0x20<UINT32>
0x0040344d:	leal %eax, 0x100(%esi)
0x00403453:	cmpl %esi, %eax
0x00403455:	jae 0x00403471
0x00403457:	andb 0x4(%esi), $0x0<UINT8>
0x0040345b:	orl (%esi), $0xffffffff<UINT8>
0x0040345e:	movb 0x5(%esi), $0xa<UINT8>
0x00403462:	movl %eax, 0x4231e0
0x00403467:	addl %esi, $0x8<UINT8>
0x0040346a:	addl %eax, $0x100<UINT32>
0x0040346f:	jmp 0x00403453
0x00403471:	leal %eax, 0x10(%esp)
0x00403475:	pushl %eax
0x00403476:	call GetStartupInfoA@KERNEL32.dll
GetStartupInfoA@KERNEL32.dll: API Node	
0x0040347c:	cmpw 0x42(%esp), $0x0<UINT8>
0x00403482:	je 197
0x00403488:	movl %eax, 0x44(%esp)
0x0040348c:	testl %eax, %eax
0x0040348e:	je 185
0x00403494:	movl %esi, (%eax)
0x00403496:	leal %ebp, 0x4(%eax)
0x00403499:	movl %eax, $0x800<UINT32>
0x0040349e:	cmpl %esi, %eax
0x004034a0:	leal %ebx, (%esi,%ebp)
0x004034a3:	jl 0x004034a7
0x004034a7:	cmpl 0x4232e0, %esi
0x004034ad:	jnl 0x00403501
0x00403501:	xorl %edi, %edi
0x00403503:	testl %esi, %esi
0x00403505:	jle 0x0040354d
0x0040354d:	xorl %ebx, %ebx
0x0040354f:	movl %eax, 0x4231e0
0x00403554:	cmpl (%eax,%ebx,8), $0xffffffff<UINT8>
0x00403558:	leal %esi, (%eax,%ebx,8)
0x0040355b:	jne 77
0x0040355d:	testl %ebx, %ebx
0x0040355f:	movb 0x4(%esi), $0xffffff81<UINT8>
0x00403563:	jne 0x0040356a
0x00403565:	pushl $0xfffffff6<UINT8>
0x00403567:	popl %eax
0x00403568:	jmp 0x00403574
0x00403574:	pushl %eax
0x00403575:	call GetStdHandle@KERNEL32.dll
GetStdHandle@KERNEL32.dll: API Node	
0x0040357b:	movl %edi, %eax
0x0040357d:	cmpl %edi, $0xffffffff<UINT8>
0x00403580:	je 23
0x00403582:	pushl %edi
0x00403583:	call GetFileType@KERNEL32.dll
GetFileType@KERNEL32.dll: API Node	
0x00403589:	testl %eax, %eax
0x0040358b:	je 12
0x0040358d:	andl %eax, $0xff<UINT32>
0x00403592:	movl (%esi), %edi
0x00403594:	cmpl %eax, $0x2<UINT8>
0x00403597:	jne 6
0x00403599:	orb 0x4(%esi), $0x40<UINT8>
0x0040359d:	jmp 0x004035ae
0x004035ae:	incl %ebx
0x004035af:	cmpl %ebx, $0x3<UINT8>
0x004035b2:	jl 0x0040354f
0x0040356a:	movl %eax, %ebx
0x0040356c:	decl %eax
0x0040356d:	negl %eax
0x0040356f:	sbbl %eax, %eax
0x00403571:	addl %eax, $0xfffffff5<UINT8>
0x004035b4:	pushl 0x4232e0
0x004035ba:	call SetHandleCount@KERNEL32.dll
SetHandleCount@KERNEL32.dll: API Node	
0x004035c0:	popl %edi
0x004035c1:	popl %esi
0x004035c2:	popl %ebp
0x004035c3:	popl %ebx
0x004035c4:	addl %esp, $0x44<UINT8>
0x004035c7:	ret

0x004024e5:	call 0x00404ec8
0x00404ec8:	movl %eax, 0x423194
0x00404ecd:	pushl %ebx
0x00404ece:	pushl %ebp
0x00404ecf:	pushl %esi
0x00404ed0:	movl %esi, 0x40707c
0x00404ed6:	pushl %edi
0x00404ed7:	movl %edi, 0x407080
0x00404edd:	testl %eax, %eax
0x00404edf:	jne 36
0x00404ee1:	call GetCommandLineW@KERNEL32.dll
GetCommandLineW@KERNEL32.dll: API Node	
0x00404ee3:	testl %eax, %eax
0x00404ee5:	je 12
0x00404ee7:	movl 0x423194, $0x1<UINT32>
0x00404ef1:	jmp 0x00404f0a
0x00404f0a:	call GetCommandLineW@KERNEL32.dll
0x00404f0c:	jmp 0x00404f60
0x00404f60:	popl %edi
0x00404f61:	popl %esi
0x00404f62:	popl %ebp
0x00404f63:	popl %ebx
0x00404f64:	ret

0x004024ea:	movl 0x4232e4, %eax
0x004024ef:	call 0x00404d5b
0x00404d5b:	pushl %ecx
0x00404d5c:	movl %eax, 0x423190
0x00404d61:	pushl %ebx
0x00404d62:	movl %ebx, 0x407088
0x00404d68:	pushl %ebp
0x00404d69:	pushl %esi
0x00404d6a:	xorl %esi, %esi
0x00404d6c:	xorl %ebp, %ebp
0x00404d6e:	pushl %edi
0x00404d6f:	movl %edi, 0x407048
0x00404d75:	testl %eax, %eax
0x00404d77:	jne 44
0x00404d79:	call GetEnvironmentStringsW@KERNEL32.dll
GetEnvironmentStringsW@KERNEL32.dll: API Node	
0x00404d7b:	movl %esi, %eax
0x00404d7d:	testl %esi, %esi
0x00404d7f:	je 12
0x00404d81:	movl 0x423190, $0x1<UINT32>
0x00404d8b:	jmp 0x00404daa
0x00404daa:	testl %esi, %esi
0x00404dac:	jne 0x00404dba
0x00404dba:	xorl %ecx, %ecx
0x00404dbc:	movl %eax, %esi
0x00404dbe:	cmpw (%esi), %cx
0x00404dc1:	je 14
0x00404dc3:	incl %eax
0x00404dc4:	incl %eax
0x00404dc5:	cmpw (%eax), %cx
0x00404dc8:	jne 0x00404dc3
0x00404dca:	incl %eax
0x00404dcb:	incl %eax
0x00404dcc:	cmpw (%eax), %cx
0x00404dcf:	jne 0x00404dc3
0x00404dd1:	subl %eax, %esi
0x00404dd3:	incl %eax
0x00404dd4:	incl %eax
0x00404dd5:	movl %ebx, %eax
0x00404dd7:	pushl %ebx
0x00404dd8:	call 0x00402357
0x004023ad:	testl %esi, %esi
0x004023af:	jne 0x004023b4
0x004023b4:	addl %esi, $0xf<UINT8>
0x004023b7:	andl %esi, $0xfffffff0<UINT8>
0x004023ba:	pushl %esi
0x004023bb:	pushl $0x0<UINT8>
0x004023bd:	pushl 0x4231c4
0x004023c3:	call HeapAlloc@KERNEL32.dll
0x00404ddd:	movl %edi, %eax
0x00404ddf:	popl %ecx
0x00404de0:	testl %edi, %edi
0x00404de2:	jne 0x00404def
0x00404def:	pushl %ebx
0x00404df0:	pushl %esi
0x00404df1:	pushl %edi
0x00404df2:	call 0x004061a0
0x004061a0:	pushl %ebp
0x004061a1:	movl %ebp, %esp
0x004061a3:	pushl %edi
0x004061a4:	pushl %esi
0x004061a5:	movl %esi, 0xc(%ebp)
0x004061a8:	movl %ecx, 0x10(%ebp)
0x004061ab:	movl %edi, 0x8(%ebp)
0x004061ae:	movl %eax, %ecx
0x004061b0:	movl %edx, %ecx
0x004061b2:	addl %eax, %esi
0x004061b4:	cmpl %edi, %esi
0x004061b6:	jbe 8
0x004061b8:	cmpl %edi, %eax
0x004061ba:	jb 376
0x004061c0:	testl %edi, $0x3<UINT32>
0x004061c6:	jne 20
0x004061c8:	shrl %ecx, $0x2<UINT8>
0x004061cb:	andl %edx, $0x3<UINT8>
0x004061ce:	cmpl %ecx, $0x8<UINT8>
0x004061d1:	jb 41
0x004061d3:	rep movsl %es:(%edi), %ds:(%esi)
0x004061d5:	jmp 0x0040630c
0x0040630c:	movb %al, (%esi)
0x0040630e:	movb (%edi), %al
0x00406310:	movb %al, 0x1(%esi)
0x00406313:	movb 0x1(%edi), %al
0x00406316:	movl %eax, 0x8(%ebp)
0x00406319:	popl %esi
0x0040631a:	popl %edi
0x0040631b:	leave
0x0040631c:	ret

0x00404df7:	addl %esp, $0xc<UINT8>
0x00404dfa:	jmp 0x00404de4
0x00404de4:	pushl %esi
0x00404de5:	call FreeEnvironmentStringsW@KERNEL32.dll
FreeEnvironmentStringsW@KERNEL32.dll: API Node	
0x00404deb:	movl %eax, %edi
0x00404ded:	jmp 0x00404e60
0x00404e60:	popl %edi
0x00404e61:	popl %esi
0x00404e62:	popl %ebp
0x00404e63:	popl %ebx
0x00404e64:	popl %ecx
0x00404e65:	ret

0x004024f4:	movl 0x422efc, %eax
0x004024f9:	call 0x00404b32
0x00404b32:	pushl %ebp
0x00404b33:	movl %ebp, %esp
0x00404b35:	pushl %ecx
0x00404b36:	pushl %ecx
0x00404b37:	pushl %esi
0x00404b38:	pushl %edi
0x00404b39:	movl %esi, $0x422f88<UINT32>
0x00404b3e:	pushl $0x104<UINT32>
0x00404b43:	pushl %esi
0x00404b44:	pushl $0x0<UINT8>
0x00404b46:	call GetModuleFileNameW@KERNEL32.dll
GetModuleFileNameW@KERNEL32.dll: API Node	
0x00404b4c:	movl %eax, 0x4232e4
0x00404b51:	movl 0x422f64, %esi
0x00404b57:	movl %edi, %esi
0x00404b59:	cmpw (%eax), $0x0<UINT8>
0x00404b5d:	je 2
0x00404b5f:	movl %edi, %eax
0x00404b61:	leal %eax, -8(%ebp)
0x00404b64:	pushl %eax
0x00404b65:	leal %eax, -4(%ebp)
0x00404b68:	pushl %eax
0x00404b69:	pushl $0x0<UINT8>
0x00404b6b:	pushl $0x0<UINT8>
0x00404b6d:	pushl %edi
0x00404b6e:	call 0x00404bc1
0x00404bc1:	pushl %ebp
0x00404bc2:	movl %ebp, %esp
0x00404bc4:	movl %eax, 0x14(%ebp)
0x00404bc7:	movl %edx, 0x10(%ebp)
0x00404bca:	pushl %ebx
0x00404bcb:	pushl %esi
0x00404bcc:	movl %esi, 0x18(%ebp)
0x00404bcf:	pushl %edi
0x00404bd0:	andl (%esi), $0x0<UINT8>
0x00404bd3:	cmpl 0xc(%ebp), $0x0<UINT8>
0x00404bd7:	movl (%eax), $0x1<UINT32>
0x00404bdd:	movl %eax, 0x8(%ebp)
0x00404be0:	je 0x00404beb
0x00404beb:	pushl $0x22<UINT8>
0x00404bed:	popl %ebx
0x00404bee:	cmpw (%eax), %bx
0x00404bf1:	jne 63
0x00404bf3:	movw %cx, 0x2(%eax)
0x00404bf7:	addl %eax, $0x2<UINT8>
0x00404bfa:	pushl $0x2<UINT8>
0x00404bfc:	popl %edi
0x00404bfd:	cmpw %cx, %bx
0x00404c00:	je 0x00404c1d
0x00404c02:	testw %cx, %cx
0x00404c05:	je 22
0x00404c07:	incl (%esi)
0x00404c09:	testl %edx, %edx
0x00404c0b:	je 0x00404c15
0x00404c15:	movw %cx, (%eax,%edi)
0x00404c19:	addl %eax, %edi
0x00404c1b:	jmp 0x00404bfd
0x00404c1d:	incl (%esi)
0x00404c1f:	testl %edx, %edx
0x00404c21:	je 0x00404c29
0x00404c29:	cmpw (%eax), %bx
0x00404c2c:	jne 61
0x00404c2e:	addl %eax, %edi
0x00404c30:	jmp 0x00404c6b
0x00404c6b:	andl 0x18(%ebp), $0x0<UINT8>
0x00404c6f:	cmpw (%eax), $0x0<UINT8>
0x00404c73:	je 0x00404c88
0x00404c88:	xorl %ecx, %ecx
0x00404c8a:	cmpw (%eax), %cx
0x00404c8d:	je 0x00404d48
0x00404d48:	movl %eax, 0xc(%ebp)
0x00404d4b:	popl %edi
0x00404d4c:	popl %esi
0x00404d4d:	cmpl %eax, %ecx
0x00404d4f:	popl %ebx
0x00404d50:	je 0x00404d54
0x00404d54:	movl %eax, 0x14(%ebp)
0x00404d57:	incl (%eax)
0x00404d59:	popl %ebp
0x00404d5a:	ret

0x00404b73:	movl %eax, -8(%ebp)
0x00404b76:	movl %ecx, -4(%ebp)
0x00404b79:	leal %eax, (%eax,%ecx,2)
0x00404b7c:	shll %eax
0x00404b7e:	pushl %eax
0x00404b7f:	call 0x00402357
0x0040449f:	movl %ecx, 0x4(%ebx)
0x004044a2:	movl %edi, (%ebx)
0x004044a4:	andl %ecx, -8(%ebp)
0x004044a7:	andl %edi, %esi
0x004044a9:	orl %ecx, %edi
0x004044ab:	jne 0x004044b8
0x00404b84:	movl %esi, %eax
0x00404b86:	addl %esp, $0x18<UINT8>
0x00404b89:	testl %esi, %esi
0x00404b8b:	jne 0x00404b95
0x00404b95:	leal %eax, -8(%ebp)
0x00404b98:	pushl %eax
0x00404b99:	leal %eax, -4(%ebp)
0x00404b9c:	pushl %eax
0x00404b9d:	movl %eax, -4(%ebp)
0x00404ba0:	leal %eax, (%esi,%eax,4)
0x00404ba3:	pushl %eax
0x00404ba4:	pushl %esi
0x00404ba5:	pushl %edi
0x00404ba6:	call 0x00404bc1
0x00404be2:	movl %ecx, 0xc(%ebp)
0x00404be5:	addl 0xc(%ebp), $0x4<UINT8>
0x00404be9:	movl (%ecx), %edx
0x00404c0d:	movw %cx, (%eax)
0x00404c10:	movw (%edx), %cx
0x00404c13:	addl %edx, %edi
0x00404c23:	andw (%edx), $0x0<UINT8>
0x00404c27:	addl %edx, %edi
0x00404d52:	movl (%eax), %ecx
0x00404bab:	movl %eax, -4(%ebp)
0x00404bae:	addl %esp, $0x14<UINT8>
0x00404bb1:	decl %eax
0x00404bb2:	movl 0x422f4c, %esi
0x00404bb8:	popl %edi
0x00404bb9:	movl 0x422f44, %eax
0x00404bbe:	popl %esi
0x00404bbf:	leave
0x00404bc0:	ret

0x004024fe:	call 0x00404a7a
0x00404a7a:	pushl %esi
0x00404a7b:	movl %esi, 0x422efc
0x00404a81:	pushl %edi
0x00404a82:	xorl %edi, %edi
0x00404a84:	movw %ax, (%esi)
0x00404a87:	testw %ax, %ax
0x00404a8a:	je 0x00404aa0
0x00404a8c:	cmpw %ax, $0x3d<UINT16>
0x00404a90:	je 0x00404a93
0x00404a93:	pushl %esi
0x00404a94:	call 0x0040205e
0x0040205e:	movl %ecx, 0x4(%esp)
0x00402062:	cmpw (%ecx), $0x0<UINT8>
0x00402066:	leal %eax, 0x2(%ecx)
0x00402069:	je 10
0x0040206b:	movw %dx, (%eax)
0x0040206e:	incl %eax
0x0040206f:	incl %eax
0x00402070:	testw %dx, %dx
0x00402073:	jne 0x0040206b
0x00402075:	subl %eax, %ecx
0x00402077:	sarl %eax
0x00402079:	decl %eax
0x0040207a:	ret

0x00404a99:	popl %ecx
0x00404a9a:	leal %esi, 0x2(%esi,%eax,2)
0x00404a9e:	jmp 0x00404a84
0x00404a92:	incl %edi
0x00404aa0:	leal %eax, 0x4(,%edi,4)
0x00404aa7:	pushl %eax
0x00404aa8:	call 0x00402357
0x00404aad:	movl %edi, %eax
0x00404aaf:	popl %ecx
0x00404ab0:	testl %edi, %edi
0x00404ab2:	movl 0x422f58, %edi
0x00404ab8:	jne 0x00404ac2
0x00404ac2:	movl %esi, 0x422efc
0x00404ac8:	cmpw (%esi), $0x0<UINT8>
0x00404acc:	je 65
0x00404ace:	pushl %ebx
0x00404acf:	pushl %esi
0x00404ad0:	call 0x0040205e
0x00404ad5:	movl %ebx, %eax
0x00404ad7:	popl %ecx
0x00404ad8:	incl %ebx
0x00404ad9:	cmpw (%esi), $0x3d<UINT8>
0x00404add:	je 0x00404b04
0x00404b04:	cmpw (%esi,%ebx,2), $0x0<UINT8>
0x00404b09:	leal %esi, (%esi,%ebx,2)
0x00404b0c:	jne 0x00404acf
0x00404adf:	leal %eax, (%ebx,%ebx)
0x00404ae2:	pushl %eax
0x00404ae3:	call 0x00402357
0x00404ae8:	testl %eax, %eax
0x00404aea:	popl %ecx
0x00404aeb:	movl (%edi), %eax
0x00404aed:	jne 0x00404af7
0x00404af7:	pushl %esi
0x00404af8:	pushl (%edi)
0x00404afa:	call 0x0040244c
0x0040244c:	movl %ecx, 0x8(%esp)
0x00402450:	movl %eax, 0x4(%esp)
0x00402454:	pushl %esi
0x00402455:	movw %dx, (%ecx)
0x00402458:	leal %esi, 0x2(%eax)
0x0040245b:	movw (%eax), %dx
0x0040245e:	incl %ecx
0x0040245f:	incl %ecx
0x00402460:	testw %dx, %dx
0x00402463:	je 0x0040246f
0x00402465:	movw %dx, (%ecx)
0x00402468:	movw (%esi), %dx
0x0040246b:	incl %esi
0x0040246c:	incl %esi
0x0040246d:	jmp 0x0040245e
0x0040246f:	popl %esi
0x00402470:	ret

0x00404aff:	popl %ecx
0x00404b00:	addl %edi, $0x4<UINT8>
0x00404b03:	popl %ecx
0x004045eb:	movl %ecx, 0x4(%edx)
0x004045ee:	cmpl %ecx, 0x8(%edx)
0x004045f1:	jne 0x00404654
0x00404654:	movl %ecx, 0x8(%edx)
0x00404657:	movl %edi, 0x4(%edx)
0x0040465a:	cmpl -8(%ebp), $0x0<UINT8>
0x0040465e:	movl 0x4(%ecx), %edi
0x00404661:	movl %ecx, 0x4(%edx)
0x00404664:	movl %edi, 0x8(%edx)
0x00404667:	movl 0x8(%ecx), %edi
0x0040466a:	je 0x00404704
0x00404670:	movl %ecx, -12(%ebp)
0x00404673:	movl %edi, 0x4(%ecx,%esi,8)
0x00404677:	leal %ecx, (%ecx,%esi,8)
0x0040467a:	movl 0x4(%edx), %edi
0x0040467d:	movl 0x8(%edx), %ecx
0x00404680:	movl 0x4(%ecx), %edx
0x00404683:	movl %ecx, 0x4(%edx)
0x00404686:	movl 0x8(%ecx), %edx
0x00404689:	movl %ecx, 0x4(%edx)
0x0040468c:	cmpl %ecx, 0x8(%edx)
0x0040468f:	jne 100
0x00404691:	movb %cl, 0x4(%esi,%eax)
0x00404695:	cmpl %esi, $0x20<UINT8>
0x00404698:	movb 0xb(%ebp), %cl
0x0040469b:	jnl 0x004046c6
0x004046c6:	incb %cl
0x004046c8:	cmpb 0xb(%ebp), $0x0<UINT8>
0x004046cc:	movb 0x4(%esi,%eax), %cl
0x004046d0:	jne 13
0x004046d2:	leal %ecx, -32(%esi)
0x004046d5:	movl %edi, $0x80000000<UINT32>
0x004046da:	shrl %edi, %cl
0x004046dc:	orl 0x4(%ebx), %edi
0x004046df:	movl %ecx, -4(%ebp)
0x004046e2:	leal %edi, 0xc4(%eax,%ecx,4)
0x004046e9:	leal %ecx, -32(%esi)
0x004046ec:	movl %esi, $0x80000000<UINT32>
0x004046f1:	shrl %esi, %cl
0x004046f3:	orl (%edi), %esi
0x004046f5:	movl %ecx, -8(%ebp)
0x004045f3:	cmpl %edi, $0x20<UINT8>
0x004045f6:	jnl 0x00404623
0x00404623:	leal %ecx, -32(%edi)
0x00404626:	movl %ebx, $0x80000000<UINT32>
0x0040462b:	shrl %ebx, %cl
0x0040462d:	movl %ecx, -4(%ebp)
0x00404630:	leal %edi, 0x4(%eax,%edi)
0x00404634:	leal %ecx, 0xc4(%eax,%ecx,4)
0x0040463b:	notl %ebx
0x0040463d:	andl (%ecx), %ebx
0x0040463f:	decb (%edi)
0x00404641:	movl -20(%ebp), %ebx
0x00404644:	jne 11
0x00404646:	movl %ebx, 0x8(%ebp)
0x00404649:	movl %ecx, -20(%ebp)
0x0040464c:	andl 0x4(%ebx), %ecx
0x0040464f:	jmp 0x00404654
0x0040469d:	incb %cl
0x0040469f:	cmpb 0xb(%ebp), $0x0<UINT8>
0x004046a3:	movb 0x4(%esi,%eax), %cl
0x004046a7:	jne 11
0x004046a9:	movl %edi, $0x80000000<UINT32>
0x004046ae:	movl %ecx, %esi
0x004046b0:	shrl %edi, %cl
0x004046b2:	orl (%ebx), %edi
0x004046b4:	movl %edi, $0x80000000<UINT32>
0x004046b9:	movl %ecx, %esi
0x004046bb:	shrl %edi, %cl
0x004046bd:	movl %ecx, -4(%ebp)
0x004046c0:	orl 0x44(%eax,%ecx,4), %edi
0x004046c4:	jmp 0x004046f5
0x004045f8:	movl %ebx, $0x80000000<UINT32>
0x004045fd:	movl %ecx, %edi
0x004045ff:	shrl %ebx, %cl
0x00404601:	movl %ecx, -4(%ebp)
0x00404604:	leal %edi, 0x4(%eax,%edi)
0x00404608:	notl %ebx
0x0040460a:	movl -20(%ebp), %ebx
0x0040460d:	andl %ebx, 0x44(%eax,%ecx,4)
0x00404611:	movl 0x44(%eax,%ecx,4), %ebx
0x00404615:	decb (%edi)
0x00404617:	jne 56
0x00404619:	movl %ebx, 0x8(%ebp)
0x0040461c:	movl %ecx, -20(%ebp)
0x0040461f:	andl (%ebx), %ecx
0x00404621:	jmp 0x00404654
0x00404481:	addl %ecx, $0xffffffe0<UINT8>
0x00404484:	orl %eax, $0xffffffff<UINT8>
0x00404487:	xorl %esi, %esi
0x00404489:	shrl %eax, %cl
0x0040448b:	movl -12(%ebp), %esi
0x0040448e:	movl -8(%ebp), %eax
0x00404704:	movl %ecx, -8(%ebp)
0x00404b0e:	popl %ebx
0x00404b0f:	pushl 0x422efc
0x00404b15:	call 0x0040241d
0x0040241d:	pushl %esi
0x0040241e:	movl %esi, 0x8(%esp)
0x00402422:	testl %esi, %esi
0x00402424:	je 36
0x00402426:	pushl %esi
0x00402427:	call 0x004040eb
0x004040eb:	movl %eax, 0x4231bc
0x004040f0:	leal %ecx, (%eax,%eax,4)
0x004040f3:	movl %eax, 0x4231c0
0x004040f8:	leal %ecx, (%eax,%ecx,4)
0x004040fb:	cmpl %eax, %ecx
0x004040fd:	jae 0x00404113
0x004040ff:	movl %edx, 0x4(%esp)
0x00404103:	subl %edx, 0xc(%eax)
0x00404106:	cmpl %edx, $0x100000<UINT32>
0x0040410c:	jb 7
0x0040410e:	addl %eax, $0x14<UINT8>
0x00404111:	jmp 0x004040fb
0x00404113:	xorl %eax, %eax
0x00404115:	ret

0x0040242c:	popl %ecx
0x0040242d:	testl %eax, %eax
0x0040242f:	pushl %esi
0x00402430:	je 0x0040243c
0x0040243c:	pushl $0x0<UINT8>
0x0040243e:	pushl 0x4231c4
0x00402444:	call HeapFree@KERNEL32.dll
HeapFree@KERNEL32.dll: API Node	
0x0040244a:	popl %esi
0x0040244b:	ret

0x00404b1a:	andl 0x422efc, $0x0<UINT8>
0x00404b21:	andl (%edi), $0x0<UINT8>
0x00404b24:	popl %ecx
0x00404b25:	popl %edi
0x00404b26:	movl 0x4231c8, $0x1<UINT32>
0x00404b30:	popl %esi
0x00404b31:	ret

0x00402503:	call 0x0040369d
0x0040369d:	movl %eax, 0x4231d4
0x004036a2:	testl %eax, %eax
0x004036a4:	je 0x004036a8
0x004036a8:	pushl $0x408010<UINT32>
0x004036ad:	pushl $0x408008<UINT32>
0x004036b2:	call 0x00403785
0x00403785:	pushl %esi
0x00403786:	movl %esi, 0x8(%esp)
0x0040378a:	cmpl %esi, 0xc(%esp)
0x0040378e:	jae 0x0040379d
0x00403790:	movl %eax, (%esi)
0x00403792:	testl %eax, %eax
0x00403794:	je 0x00403798
0x00403798:	addl %esi, $0x4<UINT8>
0x0040379b:	jmp 0x0040378a
0x00403796:	call 0x0040223c
0x0040223c:	movl %eax, 0x424300
0x00402241:	pushl %esi
0x00402242:	pushl $0x14<UINT8>
0x00402244:	testl %eax, %eax
0x00402246:	popl %esi
0x00402247:	jne 7
0x00402249:	movl %eax, $0x200<UINT32>
0x0040224e:	jmp 0x00402256
0x00402256:	movl 0x424300, %eax
0x0040225b:	pushl $0x4<UINT8>
0x0040225d:	pushl %eax
0x0040225e:	call 0x004035c8
0x004035c8:	pushl %ebx
0x004035c9:	pushl %esi
0x004035ca:	movl %esi, 0xc(%esp)
0x004035ce:	pushl %edi
0x004035cf:	imull %esi, 0x14(%esp)
0x004035d4:	cmpl %esi, $0xffffffe0<UINT8>
0x004035d7:	movl %ebx, %esi
0x004035d9:	ja 13
0x004035db:	testl %esi, %esi
0x004035dd:	jne 0x004035e2
0x004035e2:	addl %esi, $0xf<UINT8>
0x004035e5:	andl %esi, $0xfffffff0<UINT8>
0x004035e8:	xorl %edi, %edi
0x004035ea:	cmpl %esi, $0xffffffe0<UINT8>
0x004035ed:	ja 42
0x004035ef:	cmpl %ebx, 0x422a14
0x004035f5:	ja 0x00403604
0x00403604:	pushl %esi
0x00403605:	pushl $0x8<UINT8>
0x00403607:	pushl 0x4231c4
0x0040360d:	call HeapAlloc@KERNEL32.dll
0x00403613:	movl %edi, %eax
0x00403615:	testl %edi, %edi
0x00403617:	jne 0x0040363b
0x0040363b:	movl %eax, %edi
0x0040363d:	popl %edi
0x0040363e:	popl %esi
0x0040363f:	popl %ebx
0x00403640:	ret

0x00402263:	popl %ecx
0x00402264:	movl 0x4232e8, %eax
0x00402269:	testl %eax, %eax
0x0040226b:	popl %ecx
0x0040226c:	jne 0x0040228f
0x0040228f:	xorl %ecx, %ecx
0x00402291:	movl %eax, $0x422778<UINT32>
0x00402296:	movl %edx, 0x4232e8
0x0040229c:	movl (%ecx,%edx), %eax
0x0040229f:	addl %eax, $0x20<UINT8>
0x004022a2:	addl %ecx, $0x4<UINT8>
0x004022a5:	cmpl %eax, $0x4229f8<UINT32>
0x004022aa:	jl 0x00402296
0x004022ac:	xorl %edx, %edx
0x004022ae:	movl %ecx, $0x422788<UINT32>
0x004022b3:	movl %eax, %edx
0x004022b5:	movl %esi, %edx
0x004022b7:	sarl %eax, $0x5<UINT8>
0x004022ba:	andl %esi, $0x1f<UINT8>
0x004022bd:	movl %eax, 0x4231e0(,%eax,4)
0x004022c4:	movl %eax, (%eax,%esi,8)
0x004022c7:	cmpl %eax, $0xffffffff<UINT8>
0x004022ca:	je 4
0x004022cc:	testl %eax, %eax
0x004022ce:	jne 0x004022d3
0x004022d3:	addl %ecx, $0x20<UINT8>
0x004022d6:	incl %edx
0x004022d7:	cmpl %ecx, $0x4227e8<UINT32>
0x004022dd:	jl 0x004022b3
0x004022df:	popl %esi
0x004022e0:	ret

0x0040379d:	popl %esi
0x0040379e:	ret

0x004036b7:	pushl $0x408004<UINT32>
0x004036bc:	pushl $0x408000<UINT32>
0x004036c1:	call 0x00403785
0x004036c6:	addl %esp, $0x10<UINT8>
0x004036c9:	ret

0x00402508:	movl %eax, 0x422f58
0x0040250d:	movl 0x422f5c, %eax
0x00402512:	pushl %eax
0x00402513:	pushl 0x422f4c
0x00402519:	pushl 0x422f44
0x0040251f:	call 0x004016c0
0x004016c0:	subl %esp, $0x214<UINT32>
0x004016c6:	pushl %ebx
0x004016c7:	pushl %ebp
0x004016c8:	pushl %esi
0x004016c9:	pushl %edi
0x004016ca:	pushl $0x0<UINT8>
0x004016cc:	movl 0x14(%esp), $0x0<UINT32>
0x004016d4:	orl %ebp, $0xffffffff<UINT8>
0x004016d7:	movb 0x18(%esp), $0x0<UINT8>
0x004016dc:	call CoInitialize@ole32.dll
CoInitialize@ole32.dll: API Node	
0x004016e2:	pushl $0x408484<UINT32>
0x004016e7:	call 0x004022f5
0x004022f5:	pushl %ebx
0x004022f6:	pushl %esi
0x004022f7:	movl %esi, $0x422798<UINT32>
0x004022fc:	pushl %edi
0x004022fd:	pushl %esi
0x004022fe:	call 0x0040379f
0x0040379f:	pushl %esi
0x004037a0:	movl %esi, 0x8(%esp)
0x004037a4:	pushl 0x10(%esi)
0x004037a7:	call 0x004053a6
0x004053a6:	movl %eax, 0x4(%esp)
0x004053aa:	cmpl %eax, 0x4232e0
0x004053b0:	jb 0x004053b5
0x004053b5:	movl %ecx, %eax
0x004053b7:	andl %eax, $0x1f<UINT8>
0x004053ba:	sarl %ecx, $0x5<UINT8>
0x004053bd:	movl %ecx, 0x4231e0(,%ecx,4)
0x004053c4:	movb %al, 0x4(%ecx,%eax,8)
0x004053c8:	andl %eax, $0x40<UINT8>
0x004053cb:	ret

0x004037ac:	testl %eax, %eax
0x004037ae:	popl %ecx
0x004037af:	je 119
0x004037b1:	cmpl %esi, $0x422798<UINT32>
0x004037b7:	jne 4
0x004037b9:	xorl %eax, %eax
0x004037bb:	jmp 0x004037c8
0x004037c8:	incl 0x422ef4
0x004037ce:	testw 0xc(%esi), $0x10c<UINT16>
0x004037d4:	jne 82
0x004037d6:	cmpl 0x422f74(,%eax,4), $0x0<UINT8>
0x004037de:	pushl %ebx
0x004037df:	pushl %edi
0x004037e0:	leal %edi, 0x422f74(,%eax,4)
0x004037e7:	movl %ebx, $0x1000<UINT32>
0x004037ec:	jne 0x0040380e
0x004037ee:	pushl %ebx
0x004037ef:	call 0x00402357
0x004037f4:	testl %eax, %eax
0x004037f6:	popl %ecx
0x004037f7:	movl (%edi), %eax
0x004037f9:	jne 0x0040380e
0x0040380e:	movl %edi, (%edi)
0x00403810:	movl 0x18(%esi), %ebx
0x00403813:	movl 0x8(%esi), %edi
0x00403816:	movl (%esi), %edi
0x00403818:	movl 0x4(%esi), %ebx
0x0040381b:	orw 0xc(%esi), $0x1102<UINT16>
0x00403821:	pushl $0x1<UINT8>
0x00403823:	popl %eax
0x00403824:	popl %edi
0x00403825:	popl %ebx
0x00403826:	popl %esi
0x00403827:	ret

0x00402303:	movl %edi, %eax
0x00402305:	leal %eax, 0x18(%esp)
0x00402309:	pushl %eax
0x0040230a:	pushl 0x18(%esp)
0x0040230e:	pushl %esi
0x0040230f:	call 0x004026ad
0x004026ad:	pushl %ebp
0x004026ae:	movl %ebp, %esp
0x004026b0:	subl %esp, $0x450<UINT32>
0x004026b6:	movl %eax, 0xc(%ebp)
0x004026b9:	addl 0xc(%ebp), $0x2<UINT8>
0x004026bd:	pushl %ebx
0x004026be:	xorl %ecx, %ecx
0x004026c0:	movw %bx, (%eax)
0x004026c3:	pushl %esi
0x004026c4:	cmpw %bx, %cx
0x004026c7:	pushl %edi
0x004026c8:	movl -8(%ebp), %ecx
0x004026cb:	movl -20(%ebp), %ecx
0x004026ce:	je 1790
0x004026d4:	xorl %esi, %esi
0x004026d6:	jmp 0x004026db
0x004026db:	cmpl -20(%ebp), %esi
0x004026de:	jl 1774
0x004026e4:	pushl $0x20<UINT8>
0x004026e6:	popl %edi
0x004026e7:	cmpw %bx, %di
0x004026ea:	jb 0x00402700
0x00402700:	xorl %eax, %eax
0x00402702:	movsbl %eax, 0x407480(%ecx,%eax,8)
0x0040270a:	pushl $0x7<UINT8>
0x0040270c:	sarl %eax, $0x4<UINT8>
0x0040270f:	popl %ecx
0x00402710:	movl -56(%ebp), %eax
0x00402713:	cmpl %eax, %ecx
0x00402715:	ja 1698
0x0040271b:	jmp 0x00402848
0x00402848:	leal %eax, -20(%ebp)
0x0040284b:	movl -28(%ebp), $0x1<UINT32>
0x00402852:	pushl %eax
0x00402853:	pushl 0x8(%ebp)
0x00402856:	pushl %ebx
0x00402857:	call 0x00402dfa
0x00402dfa:	pushl 0x8(%esp)
0x00402dfe:	pushl 0x8(%esp)
0x00402e02:	call 0x00405605
0x00405605:	pushl %ebp
0x00405606:	movl %ebp, %esp
0x00405608:	pushl %esi
0x00405609:	movl %esi, 0xc(%ebp)
0x0040560c:	testb 0xc(%esi), $0x40<UINT8>
0x00405610:	jne 193
0x00405616:	movl %eax, 0x10(%esi)
0x00405619:	cmpl %eax, $0xffffffff<UINT8>
0x0040561c:	je 20
0x0040561e:	movl %ecx, %eax
0x00405620:	sarl %ecx, $0x5<UINT8>
0x00405623:	andl %eax, $0x1f<UINT8>
0x00405626:	movl %ecx, 0x4231e0(,%ecx,4)
0x0040562d:	leal %eax, (%ecx,%eax,8)
0x00405630:	jmp 0x00405637
0x00405637:	testb 0x4(%eax), $0xffffff80<UINT8>
0x0040563b:	je 150
0x00405641:	pushl 0x8(%ebp)
0x00405644:	leal %eax, 0xc(%ebp)
0x00405647:	pushl %eax
0x00405648:	call 0x00405dee
0x00405dee:	pushl %ebp
0x00405def:	movl %ebp, %esp
0x00405df1:	movl %eax, 0x8(%ebp)
0x00405df4:	testl %eax, %eax
0x00405df6:	jne 0x00405dfa
0x00405dfa:	cmpl 0x422f10, $0x0<UINT8>
0x00405e01:	jne 18
0x00405e03:	movw %cx, 0xc(%ebp)
0x00405e07:	cmpw %cx, $0xff<UINT16>
0x00405e0c:	ja 57
0x00405e0e:	pushl $0x1<UINT8>
0x00405e10:	movb (%eax), %cl
0x00405e12:	popl %eax
0x00405e13:	popl %ebp
0x00405e14:	ret

0x0040564d:	popl %ecx
0x0040564e:	cmpl %eax, $0xffffffff<UINT8>
0x00405651:	popl %ecx
0x00405652:	jne 0x00405667
0x00405667:	cmpl %eax, $0x1<UINT8>
0x0040566a:	jne 44
0x0040566c:	decl 0x4(%esi)
0x0040566f:	js 15
0x00405671:	movl %eax, (%esi)
0x00405673:	movb %cl, 0xc(%ebp)
0x00405676:	movb (%eax), %cl
0x00405678:	movzbl %eax, 0xc(%ebp)
0x0040567c:	incl (%esi)
0x0040567e:	jmp 0x0040568d
0x0040568d:	cmpl %eax, $0xffffffff<UINT8>
0x00405690:	je -52
0x00405692:	movw %ax, 0x8(%ebp)
0x00405696:	jmp 0x004056f7
0x004056f7:	popl %esi
0x004056f8:	popl %ebp
0x004056f9:	ret

0x00402e07:	popl %ecx
0x00402e08:	cmpw %ax, $0xffffffff<UINT16>
0x00402e0c:	movl %eax, 0x10(%esp)
0x00402e10:	popl %ecx
0x00402e11:	jne 0x00402e17
0x00402e17:	incl (%eax)
0x00402e19:	ret

0x0040285c:	addl %esp, $0xc<UINT8>
0x0040285f:	jmp 0x00402dbd
0x00402dbd:	movl %eax, 0xc(%ebp)
0x00402dc0:	addl 0xc(%ebp), $0x2<UINT8>
0x00402dc4:	xorl %esi, %esi
0x00402dc6:	movw %bx, (%eax)
0x00402dc9:	cmpw %bx, %si
0x00402dcc:	jne 0x004026d8
0x004026d8:	movl %ecx, -56(%ebp)
0x004026ec:	cmpw %bx, $0x78<UINT8>
0x004026f0:	ja 0x00402700
0x004026f2:	movzwl %eax, %bx
0x004026f5:	movb %al, 0x407460(%eax)
0x004026fb:	andl %eax, $0xf<UINT8>
0x004026fe:	jmp 0x00402702
0x00402dd2:	movl %eax, -20(%ebp)
0x00402dd5:	popl %edi
0x00402dd6:	popl %esi
0x00402dd7:	popl %ebx
0x00402dd8:	leave
0x00402dd9:	ret

0x00402314:	pushl %esi
0x00402315:	pushl %edi
0x00402316:	movl %ebx, %eax
0x00402318:	call 0x0040382c
0x0040382c:	cmpl 0x4(%esp), $0x0<UINT8>
0x00403831:	pushl %esi
0x00403832:	je 34
0x00403834:	movl %esi, 0xc(%esp)
0x00403838:	testb 0xd(%esi), $0x10<UINT8>
0x0040383c:	je 41
0x0040383e:	pushl %esi
0x0040383f:	call 0x0040216a
0x0040216a:	pushl %ebx
0x0040216b:	pushl %esi
0x0040216c:	movl %esi, 0xc(%esp)
0x00402170:	xorl %ebx, %ebx
0x00402172:	pushl %edi
0x00402173:	movl %eax, 0xc(%esi)
0x00402176:	movl %ecx, %eax
0x00402178:	andl %ecx, $0x3<UINT8>
0x0040217b:	cmpb %cl, $0x2<UINT8>
0x0040217e:	jne 55
0x00402180:	testw %ax, $0x108<UINT16>
0x00402184:	je 49
0x00402186:	movl %eax, 0x8(%esi)
0x00402189:	movl %edi, (%esi)
0x0040218b:	subl %edi, %eax
0x0040218d:	testl %edi, %edi
0x0040218f:	jle 38
0x00402191:	pushl %edi
0x00402192:	pushl %eax
0x00402193:	pushl 0x10(%esi)
0x00402196:	call 0x00403270
0x00403270:	pushl %ebp
0x00403271:	movl %ebp, %esp
0x00403273:	subl %esp, $0x414<UINT32>
0x00403279:	movl %ecx, 0x8(%ebp)
0x0040327c:	pushl %ebx
0x0040327d:	cmpl %ecx, 0x4232e0
0x00403283:	pushl %esi
0x00403284:	pushl %edi
0x00403285:	jae 377
0x0040328b:	movl %eax, %ecx
0x0040328d:	movl %esi, %ecx
0x0040328f:	sarl %eax, $0x5<UINT8>
0x00403292:	andl %esi, $0x1f<UINT8>
0x00403295:	leal %ebx, 0x4231e0(,%eax,4)
0x0040329c:	shll %esi, $0x3<UINT8>
0x0040329f:	movl %eax, (%ebx)
0x004032a1:	movb %al, 0x4(%eax,%esi)
0x004032a5:	testb %al, $0x1<UINT8>
0x004032a7:	je 343
0x004032ad:	xorl %edi, %edi
0x004032af:	cmpl 0x10(%ebp), %edi
0x004032b2:	movl -8(%ebp), %edi
0x004032b5:	movl -16(%ebp), %edi
0x004032b8:	jne 0x004032c1
0x004032c1:	testb %al, $0x20<UINT8>
0x004032c3:	je 0x004032d1
0x004032d1:	movl %eax, (%ebx)
0x004032d3:	addl %eax, %esi
0x004032d5:	testb 0x4(%eax), $0xffffff80<UINT8>
0x004032d9:	je 193
0x004032df:	movl %eax, 0xc(%ebp)
0x004032e2:	cmpl 0x10(%ebp), %edi
0x004032e5:	movl -4(%ebp), %eax
0x004032e8:	movl 0x8(%ebp), %edi
0x004032eb:	jbe 231
0x004032f1:	leal %eax, -1044(%ebp)
0x004032f7:	movl %ecx, -4(%ebp)
0x004032fa:	subl %ecx, 0xc(%ebp)
0x004032fd:	cmpl %ecx, 0x10(%ebp)
0x00403300:	jae 0x0040332b
0x00403302:	movl %ecx, -4(%ebp)
0x00403305:	incl -4(%ebp)
0x00403308:	movb %cl, (%ecx)
0x0040330a:	cmpb %cl, $0xa<UINT8>
0x0040330d:	jne 0x00403316
0x0040330f:	incl -16(%ebp)
0x00403312:	movb (%eax), $0xd<UINT8>
0x00403315:	incl %eax
0x00403316:	movb (%eax), %cl
0x00403318:	incl %eax
0x00403319:	movl %ecx, %eax
0x0040331b:	leal %edx, -1044(%ebp)
0x00403321:	subl %ecx, %edx
0x00403323:	cmpl %ecx, $0x400<UINT32>
0x00403329:	jl 0x004032f7
0x0040332b:	movl %edi, %eax
0x0040332d:	leal %eax, -1044(%ebp)
0x00403333:	subl %edi, %eax
0x00403335:	leal %eax, -12(%ebp)
0x00403338:	pushl $0x0<UINT8>
0x0040333a:	pushl %eax
0x0040333b:	leal %eax, -1044(%ebp)
0x00403341:	pushl %edi
0x00403342:	pushl %eax
0x00403343:	movl %eax, (%ebx)
0x00403345:	pushl (%eax,%esi)
0x00403348:	call WriteFile@KERNEL32.dll
WriteFile@KERNEL32.dll: API Node	
0x0040334e:	testl %eax, %eax
0x00403350:	je 67
0x00403352:	movl %eax, -12(%ebp)
0x00403355:	addl -8(%ebp), %eax
0x00403358:	cmpl %eax, %edi
0x0040335a:	jl 0x00403367
0x00403367:	xorl %edi, %edi
0x00403369:	movl %eax, -8(%ebp)
0x0040336c:	cmpl %eax, %edi
0x0040336e:	jne 139
0x00403374:	cmpl 0x8(%ebp), %edi
0x00403377:	je 0x004033d8
0x004033d8:	movl %eax, (%ebx)
0x004033da:	testb 0x4(%eax,%esi), $0x40<UINT8>
0x004033df:	je 12
0x004033e1:	movl %eax, 0xc(%ebp)
0x004033e4:	cmpb (%eax), $0x1a<UINT8>
0x004033e7:	je -307
0x004033ed:	movl 0x422f28, $0x1c<UINT32>
0x004033f7:	movl 0x422f2c, %edi
0x004033fd:	jmp 0x00403415
0x00403415:	orl %eax, $0xffffffff<UINT8>
0x00403418:	popl %edi
0x00403419:	popl %esi
0x0040341a:	popl %ebx
0x0040341b:	leave
0x0040341c:	ret

0x0040219b:	addl %esp, $0xc<UINT8>
0x0040219e:	cmpl %eax, %edi
0x004021a0:	jne 0x004021b0
0x004021b0:	orl 0xc(%esi), $0x20<UINT8>
0x004021b4:	orl %ebx, $0xffffffff<UINT8>
0x004021b7:	movl %eax, 0x8(%esi)
0x004021ba:	andl 0x4(%esi), $0x0<UINT8>
0x004021be:	movl (%esi), %eax
0x004021c0:	popl %edi
0x004021c1:	movl %eax, %ebx
0x004021c3:	popl %esi
0x004021c4:	popl %ebx
0x004021c5:	ret

0x00403844:	andb 0xd(%esi), $0xffffffee<UINT8>
0x00403848:	andl 0x18(%esi), $0x0<UINT8>
0x0040384c:	andl (%esi), $0x0<UINT8>
0x0040384f:	andl 0x8(%esi), $0x0<UINT8>
0x00403853:	popl %ecx
0x00403854:	popl %esi
0x00403855:	ret

0x0040231d:	addl %esp, $0x18<UINT8>
0x00402320:	movl %eax, %ebx
0x00402322:	popl %edi
0x00402323:	popl %esi
0x00402324:	popl %ebx
0x00402325:	ret

0x004016ec:	addl %esp, $0x4<UINT8>
0x004016ef:	pushl $0x408458<UINT32>
0x004016f4:	call 0x004022f5
0x004016f9:	addl %esp, $0x4<UINT8>
0x004016fc:	pushl $0x40840c<UINT32>
0x00401701:	call 0x004022f5
0x00401706:	pushl $0x4083f8<UINT32>
0x0040170b:	call 0x00401960
0x00401960:	subl %esp, $0x110<UINT32>
0x00401966:	movl %eax, 0x114(%esp)
0x0040196d:	pushl %ebx
0x0040196e:	pushl %eax
0x0040196f:	leal %ecx, 0x14(%esp)
0x00401973:	xorl %ebx, %ebx
0x00401975:	pushl $0x422728<UINT32>
0x0040197a:	pushl %ecx
0x0040197b:	movl 0x14(%esp), %ebx
0x0040197f:	movl 0x10(%esp), %ebx
0x00401983:	call 0x004023cb
0x004023cb:	pushl %ebp
0x004023cc:	movl %ebp, %esp
0x004023ce:	subl %esp, $0x20<UINT8>
0x004023d1:	movl %eax, 0x8(%ebp)
0x004023d4:	pushl %esi
0x004023d5:	movl -24(%ebp), %eax
0x004023d8:	movl -32(%ebp), %eax
0x004023db:	leal %eax, 0x10(%ebp)
0x004023de:	movl -20(%ebp), $0x42<UINT32>
0x004023e5:	pushl %eax
0x004023e6:	leal %eax, -32(%ebp)
0x004023e9:	pushl 0xc(%ebp)
0x004023ec:	movl -28(%ebp), $0x7fffffff<UINT32>
0x004023f3:	pushl %eax
0x004023f4:	call 0x00403869
0x00403869:	pushl %ebp
0x0040386a:	movl %ebp, %esp
0x0040386c:	subl %esp, $0x248<UINT32>
0x00403872:	pushl %ebx
0x00403873:	pushl %esi
0x00403874:	pushl %edi
0x00403875:	movl %edi, 0xc(%ebp)
0x00403878:	xorl %esi, %esi
0x0040387a:	movb %bl, (%edi)
0x0040387c:	incl %edi
0x0040387d:	testb %bl, %bl
0x0040387f:	movl -12(%ebp), %esi
0x00403882:	movl -20(%ebp), %esi
0x00403885:	movl 0xc(%ebp), %edi
0x00403888:	je 1780
0x0040388e:	movl %ecx, -16(%ebp)
0x00403891:	xorl %edx, %edx
0x00403893:	jmp 0x0040389d
0x0040389d:	cmpl -20(%ebp), %edx
0x004038a0:	jl 1756
0x004038a6:	cmpb %bl, $0x20<UINT8>
0x004038a9:	jl 19
0x004038ab:	cmpb %bl, $0x78<UINT8>
0x004038ae:	jg 0x004038be
0x004038b0:	movsbl %eax, %bl
0x004038b3:	movb %al, 0x407460(%eax)
0x004038b9:	andl %eax, $0xf<UINT8>
0x004038bc:	jmp 0x004038c0
0x004038c0:	movsbl %eax, 0x407480(%esi,%eax,8)
0x004038c8:	sarl %eax, $0x4<UINT8>
0x004038cb:	cmpl %eax, $0x7<UINT8>
0x004038ce:	movl -48(%ebp), %eax
0x004038d1:	ja 1690
0x004038d7:	jmp 0x00403a4c
0x00403a08:	movl %ecx, 0x422b6c
0x00403a0e:	movl -36(%ebp), %edx
0x00403a11:	movzbl %eax, %bl
0x00403a14:	testb 0x1(%ecx,%eax,2), $0xffffff80<UINT8>
0x00403a19:	je 0x00403a34
0x00403a34:	leal %eax, -20(%ebp)
0x00403a37:	pushl %eax
0x00403a38:	pushl 0x8(%ebp)
0x00403a3b:	movsbl %eax, %bl
0x00403a3e:	pushl %eax
0x00403a3f:	call 0x00403faa
0x00403faa:	pushl %ebp
0x00403fab:	movl %ebp, %esp
0x00403fad:	movl %ecx, 0xc(%ebp)
0x00403fb0:	decl 0x4(%ecx)
0x00403fb3:	js 14
0x00403fb5:	movl %edx, (%ecx)
0x00403fb7:	movb %al, 0x8(%ebp)
0x00403fba:	movb (%edx), %al
0x00403fbc:	incl (%ecx)
0x00403fbe:	movzbl %eax, %al
0x00403fc1:	jmp 0x00403fce
0x00403fce:	cmpl %eax, $0xffffffff<UINT8>
0x00403fd1:	movl %eax, 0x10(%ebp)
0x00403fd4:	jne 0x00403fdb
0x00403fdb:	incl (%eax)
0x00403fdd:	popl %ebp
0x00403fde:	ret

0x00403a44:	addl %esp, $0xc<UINT8>
0x00403a47:	jmp 0x00403f71
0x00403f71:	movl %edi, 0xc(%ebp)
0x00403f74:	movb %bl, (%edi)
0x00403f76:	incl %edi
0x00403f77:	testb %bl, %bl
0x00403f79:	movl 0xc(%ebp), %edi
0x00403f7c:	jne 0x00403895
0x00403895:	movl %ecx, -16(%ebp)
0x00403898:	movl %esi, -48(%ebp)
0x0040389b:	xorl %edx, %edx
0x004038be:	xorl %eax, %eax
0x004038de:	orl -16(%ebp), $0xffffffff<UINT8>
0x004038e2:	movl -52(%ebp), %edx
0x004038e5:	movl -40(%ebp), %edx
0x004038e8:	movl -32(%ebp), %edx
0x004038eb:	movl -28(%ebp), %edx
0x004038ee:	movl -4(%ebp), %edx
0x004038f1:	movl -36(%ebp), %edx
0x004038f4:	jmp 0x00403f71
0x00403a4c:	movsbl %eax, %bl
0x00403a4f:	cmpl %eax, $0x67<UINT8>
0x00403a52:	jg 0x00403c74
0x00403c74:	subl %eax, $0x69<UINT8>
0x00403c77:	je 209
0x00403c7d:	subl %eax, $0x5<UINT8>
0x00403c80:	je 158
0x00403c86:	decl %eax
0x00403c87:	je 132
0x00403c8d:	decl %eax
0x00403c8e:	je 81
0x00403c90:	subl %eax, $0x3<UINT8>
0x00403c93:	je 0x00403a96
0x00403a96:	movl %esi, -16(%ebp)
0x00403a99:	cmpl %esi, $0xffffffff<UINT8>
0x00403a9c:	jne 5
0x00403a9e:	movl %esi, $0x7fffffff<UINT32>
0x00403aa3:	leal %eax, 0x10(%ebp)
0x00403aa6:	pushl %eax
0x00403aa7:	call 0x00402e84
0x00402e84:	movl %eax, 0x4(%esp)
0x00402e88:	addl (%eax), $0x4<UINT8>
0x00402e8b:	movl %eax, (%eax)
0x00402e8d:	movl %eax, -4(%eax)
0x00402e90:	ret

0x00403aac:	testw -4(%ebp), $0x810<UINT16>
0x00403ab2:	popl %ecx
0x00403ab3:	movl %ecx, %eax
0x00403ab5:	movl -8(%ebp), %ecx
0x00403ab8:	je 0x00403cbc
0x00403cbc:	testl %ecx, %ecx
0x00403cbe:	jne 0x00403cc9
0x00403cc9:	movl %eax, %ecx
0x00403ccb:	movl %edx, %esi
0x00403ccd:	decl %esi
0x00403cce:	testl %edx, %edx
0x00403cd0:	je 8
0x00403cd2:	cmpb (%eax), $0x0<UINT8>
0x00403cd5:	je 0x00403cda
0x00403cd7:	incl %eax
0x00403cd8:	jmp 0x00403ccb
0x00403cda:	subl %eax, %ecx
0x00403cdc:	jmp 0x00403e70
0x00403e70:	movl -12(%ebp), %eax
0x00403e73:	cmpl -40(%ebp), $0x0<UINT8>
0x00403e77:	jne 244
0x00403e7d:	movl %ebx, -4(%ebp)
0x00403e80:	testb %bl, $0x40<UINT8>
0x00403e83:	je 0x00403eab
0x00403eab:	movl %esi, -32(%ebp)
0x00403eae:	subl %esi, -28(%ebp)
0x00403eb1:	subl %esi, -12(%ebp)
0x00403eb4:	testb %bl, $0xc<UINT8>
0x00403eb7:	jne 18
0x00403eb9:	leal %eax, -20(%ebp)
0x00403ebc:	pushl %eax
0x00403ebd:	pushl 0x8(%ebp)
0x00403ec0:	pushl %esi
0x00403ec1:	pushl $0x20<UINT8>
0x00403ec3:	call 0x00403fdf
0x00403fdf:	pushl %esi
0x00403fe0:	pushl %edi
0x00403fe1:	movl %edi, 0x10(%esp)
0x00403fe5:	movl %eax, %edi
0x00403fe7:	decl %edi
0x00403fe8:	testl %eax, %eax
0x00403fea:	jle 0x0040400d
0x0040400d:	popl %edi
0x0040400e:	popl %esi
0x0040400f:	ret

0x00403ec8:	addl %esp, $0x10<UINT8>
0x00403ecb:	leal %eax, -20(%ebp)
0x00403ece:	pushl %eax
0x00403ecf:	leal %eax, -22(%ebp)
0x00403ed2:	pushl 0x8(%ebp)
0x00403ed5:	pushl -28(%ebp)
0x00403ed8:	pushl %eax
0x00403ed9:	call 0x00404010
0x00404010:	pushl %ebx
0x00404011:	movl %ebx, 0xc(%esp)
0x00404015:	movl %eax, %ebx
0x00404017:	decl %ebx
0x00404018:	pushl %esi
0x00404019:	pushl %edi
0x0040401a:	testl %eax, %eax
0x0040401c:	jle 0x00404044
0x00404044:	popl %edi
0x00404045:	popl %esi
0x00404046:	popl %ebx
0x00404047:	ret

0x00403ede:	addl %esp, $0x10<UINT8>
0x00403ee1:	testb %bl, $0x8<UINT8>
0x00403ee4:	je 0x00403efd
0x00403efd:	cmpl -36(%ebp), $0x0<UINT8>
0x00403f01:	je 0x00403f44
0x00403f44:	leal %eax, -20(%ebp)
0x00403f47:	pushl %eax
0x00403f48:	pushl 0x8(%ebp)
0x00403f4b:	pushl -12(%ebp)
0x00403f4e:	pushl -8(%ebp)
0x00403f51:	call 0x00404010
0x0040401e:	movl %edi, 0x1c(%esp)
0x00404022:	movl %esi, 0x10(%esp)
0x00404026:	movsbl %eax, (%esi)
0x00404029:	pushl %edi
0x0040402a:	incl %esi
0x0040402b:	pushl 0x1c(%esp)
0x0040402f:	pushl %eax
0x00404030:	call 0x00403faa
0x00404035:	addl %esp, $0xc<UINT8>
0x00404038:	cmpl (%edi), $0xffffffff<UINT8>
0x0040403b:	je 7
0x0040403d:	movl %eax, %ebx
0x0040403f:	decl %ebx
0x00404040:	testl %eax, %eax
0x00404042:	jg -30
0x00403f56:	addl %esp, $0x10<UINT8>
0x00403f59:	testb -4(%ebp), $0x4<UINT8>
0x00403f5d:	je 0x00403f71
0x00403f82:	movl %eax, -20(%ebp)
0x00403f85:	popl %edi
0x00403f86:	popl %esi
0x00403f87:	popl %ebx
0x00403f88:	leave
0x00403f89:	ret

0x004023f9:	addl %esp, $0xc<UINT8>
0x004023fc:	decl -28(%ebp)
0x004023ff:	movl %esi, %eax
0x00402401:	js 8
0x00402403:	movl %eax, -32(%ebp)
0x00402406:	andb (%eax), $0x0<UINT8>
0x00402409:	jmp 0x00402418
0x00402418:	movl %eax, %esi
0x0040241a:	popl %esi
0x0040241b:	leave
0x0040241c:	ret

0x00401988:	addl %esp, $0xc<UINT8>
0x0040198b:	leal %edx, 0x8(%esp)
0x0040198f:	leal %eax, 0x10(%esp)
0x00401993:	pushl %edx
0x00401994:	pushl %eax
0x00401995:	pushl $0x80000001<UINT32>
0x0040199a:	call RegCreateKeyA@ADVAPI32.dll
RegCreateKeyA@ADVAPI32.dll: API Node	
0x004019a0:	testl %eax, %eax
0x004019a2:	jne 36
0x004019a4:	movl %eax, 0x8(%esp)
0x004019a8:	leal %ecx, 0xc(%esp)
0x004019ac:	leal %edx, 0x4(%esp)
0x004019b0:	pushl %ecx
0x004019b1:	pushl %edx
0x004019b2:	pushl %ebx
0x004019b3:	pushl %ebx
0x004019b4:	pushl $0x422718<UINT32>
0x004019b9:	pushl %eax
0x004019ba:	movl 0x24(%esp), $0x4<UINT32>
0x004019c2:	call RegQueryValueExA@ADVAPI32.dll
RegQueryValueExA@ADVAPI32.dll: API Node	
0x004019c8:	cmpl 0x4(%esp), %ebx
0x004019cc:	jne 511
0x004019d2:	pushl %esi
0x004019d3:	pushl %edi
0x004019d4:	pushl $0x3e8<UINT32>
0x004019d9:	pushl $0x40<UINT8>
0x004019db:	call LocalAlloc@KERNEL32.dll
LocalAlloc@KERNEL32.dll: API Node	
0x004019e1:	movl %esi, %eax
0x004019e3:	pushl $0x422708<UINT32>
0x004019e8:	leal %edi, 0x12(%esi)
0x004019eb:	call LoadLibraryA@KERNEL32.dll
0x004019f1:	movl (%esi), $0x80c808d0<UINT32>
0x00405064:	pushl %ebp
0x00405065:	movl %ebp, %esp
0x00405067:	subl %esp, $0x8<UINT8>
0x0040506a:	pushl %ebx
0x0040506b:	pushl %esi
0x0040506c:	pushl %edi
0x0040506d:	pushl %ebp
0x0040506e:	cld
0x0040506f:	movl %ebx, 0xc(%ebp)
0x00405072:	movl %eax, 0x8(%ebp)
0x00405075:	testl 0x4(%eax), $0x6<UINT32>
0x0040507c:	jne 130
0x00405082:	movl -8(%ebp), %eax
0x00405085:	movl %eax, 0x10(%ebp)
0x00405088:	movl -4(%ebp), %eax
0x0040508b:	leal %eax, -8(%ebp)
0x0040508e:	movl -4(%ebx), %eax
0x00405091:	movl %esi, 0xc(%ebx)
0x00405094:	movl %edi, 0x8(%ebx)
0x00405097:	cmpl %esi, $0xffffffff<UINT8>
0x0040509a:	je 97
0x0040509c:	leal %ecx, (%esi,%esi,2)
0x0040509f:	cmpl 0x4(%edi,%ecx,4), $0x0<UINT8>
0x004050a4:	je 69
0x004050a6:	pushl %esi
0x004050a7:	pushl %ebp
0x004050a8:	leal %ebp, 0x10(%ebx)
0x004050ab:	call 0x00402530
0x00402530:	movl %eax, -20(%ebp)
0x00402533:	movl %ecx, (%eax)
0x00402535:	movl %ecx, (%ecx)
0x00402537:	movl -32(%ebp), %ecx
0x0040253a:	pushl %eax
0x0040253b:	pushl %ecx
0x0040253c:	call 0x004048f6
0x004048f6:	pushl %ebp
0x004048f7:	movl %ebp, %esp
0x004048f9:	pushl %ebx
0x004048fa:	pushl 0x8(%ebp)
0x004048fd:	call 0x00404a37
0x00404a37:	movl %edx, 0x4(%esp)
0x00404a3b:	movl %ecx, 0x422a98
0x00404a41:	cmpl 0x422a18, %edx
0x00404a47:	pushl %esi
0x00404a48:	movl %eax, $0x422a18<UINT32>
0x00404a4d:	je 0x00404a64
0x00404a64:	leal %ecx, (%ecx,%ecx,2)
0x00404a67:	popl %esi
0x00404a68:	leal %ecx, 0x422a18(,%ecx,4)
0x00404a6f:	cmpl %eax, %ecx
0x00404a71:	jae 4
0x00404a73:	cmpl (%eax), %edx
0x00404a75:	je 0x00404a79
0x00404a79:	ret

0x00404902:	testl %eax, %eax
0x00404904:	popl %ecx
0x00404905:	je 288
0x0040490b:	movl %ebx, 0x8(%eax)
0x0040490e:	testl %ebx, %ebx
0x00404910:	je 0x00404a2b
0x00404a2b:	pushl 0xc(%ebp)
0x00404a2e:	call UnhandledExceptionFilter@KERNEL32.dll
UnhandledExceptionFilter@KERNEL32.dll: API Node	
0x00404a34:	popl %ebx
0x00404a35:	popl %ebp
0x00404a36:	ret

0x00402541:	popl %ecx
0x00402542:	popl %ecx
0x00402543:	ret

0x004050af:	popl %ebp
0x004050b0:	popl %esi
0x004050b1:	movl %ebx, 0xc(%ebp)
0x004050b4:	orl %eax, %eax
0x004050b6:	je 51
0x004050b8:	js 60
0x004050ba:	movl %edi, 0x8(%ebx)
0x004050bd:	pushl %ebx
0x004050be:	call 0x00404f6c
0x00404f6c:	pushl %ebp
0x00404f6d:	movl %ebp, %esp
0x00404f6f:	pushl %ebx
0x00404f70:	pushl %esi
0x00404f71:	pushl %edi
0x00404f72:	pushl %ebp
0x00404f73:	pushl $0x0<UINT8>
0x00404f75:	pushl $0x0<UINT8>
0x00404f77:	pushl $0x404f84<UINT32>
0x00404f7c:	pushl 0x8(%ebp)
0x00404f7f:	call 0x00406a52
0x00406a52:	jmp RtlUnwind@KERNEL32.dll
RtlUnwind@KERNEL32.dll: API Node	
0x00404f84:	popl %ebp
0x00404f85:	popl %edi
0x00404f86:	popl %esi
0x00404f87:	popl %ebx
0x00404f88:	movl %esp, %ebp
0x00404f8a:	popl %ebp
0x00404f8b:	ret

0x004050c3:	addl %esp, $0x4<UINT8>
0x004050c6:	leal %ebp, 0x10(%ebx)
0x004050c9:	pushl %esi
0x004050ca:	pushl %ebx
0x004050cb:	call 0x00404fae
0x00404fae:	pushl %ebx
0x00404faf:	pushl %esi
0x00404fb0:	pushl %edi
0x00404fb1:	movl %eax, 0x10(%esp)
0x00404fb5:	pushl %eax
0x00404fb6:	pushl $0xfffffffe<UINT8>
0x00404fb8:	pushl $0x404f8c<UINT32>
0x00404fbd:	pushl %fs:0
0x00404fc4:	movl %fs:0, %esp
0x00404fcb:	movl %eax, 0x20(%esp)
0x00404fcf:	movl %ebx, 0x8(%eax)
0x00404fd2:	movl %esi, 0xc(%eax)
0x00404fd5:	cmpl %esi, $0xffffffff<UINT8>
0x00404fd8:	je 46
0x00404fda:	cmpl %esi, 0x24(%esp)
0x00404fde:	je 0x00405008
0x00405008:	popl %fs:0
0x0040500f:	addl %esp, $0xc<UINT8>
0x00405012:	popl %edi
0x00405013:	popl %esi
0x00405014:	popl %ebx
0x00405015:	ret

0x004050d0:	addl %esp, $0x8<UINT8>
0x004050d3:	leal %ecx, (%esi,%esi,2)
0x004050d6:	pushl $0x1<UINT8>
0x004050d8:	movl %eax, 0x8(%edi,%ecx,4)
0x004050dc:	call 0x00405042
0x00405042:	pushl %ebx
0x00405043:	pushl %ecx
0x00405044:	movl %ebx, $0x422aa0<UINT32>
0x00405049:	movl %ecx, 0x8(%ebp)
0x0040504c:	movl 0x8(%ebx), %ecx
0x0040504f:	movl 0x4(%ebx), %eax
0x00405052:	movl 0xc(%ebx), %ebp
0x00405055:	popl %ecx
0x00405056:	popl %ebx
0x00405057:	ret $0x4<UINT16>

0x004050e1:	movl %eax, (%edi,%ecx,4)
0x004050e4:	movl 0xc(%ebx), %eax
0x004050e7:	call 0x00402544
0x00402544:	movl %esp, -24(%ebp)
0x00402547:	pushl -32(%ebp)
0x0040254a:	call 0x004036db
0x004036db:	pushl $0x0<UINT8>
0x004036dd:	pushl $0x1<UINT8>
0x004036df:	pushl 0xc(%esp)
0x004036e3:	call 0x004036ec
0x004036ec:	pushl %edi
0x004036ed:	pushl $0x1<UINT8>
0x004036ef:	popl %edi
0x004036f0:	cmpl 0x422f70, %edi
0x004036f6:	jne 0x00403709
0x00403709:	cmpl 0xc(%esp), $0x0<UINT8>
0x0040370e:	pushl %ebx
0x0040370f:	movl %ebx, 0x14(%esp)
0x00403713:	movl 0x422f6c, %edi
0x00403719:	movb 0x422f68, %bl
0x0040371f:	jne 0x0040375d
0x0040375d:	pushl $0x408024<UINT32>
0x00403762:	pushl $0x408020<UINT32>
0x00403767:	call 0x00403785
0x0040376c:	popl %ecx
0x0040376d:	popl %ecx
0x0040376e:	testl %ebx, %ebx
0x00403770:	popl %ebx
0x00403771:	jne 16
0x00403773:	pushl 0x8(%esp)
0x00403777:	movl 0x422f70, %edi
0x0040377d:	call ExitProcess@KERNEL32.dll
ExitProcess@KERNEL32.dll: Exit Node	
