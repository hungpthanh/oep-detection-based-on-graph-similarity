0x00416000:	movl %ebx, $0x4001d0<UINT32>
0x00416005:	movl %edi, $0x401000<UINT32>
0x0041600a:	movl %esi, $0x412c51<UINT32>
0x0041600f:	pushl %ebx
0x00416010:	call 0x0041601f
0x0041601f:	cld
0x00416020:	movb %dl, $0xffffff80<UINT8>
0x00416022:	movsb %es:(%edi), %ds:(%esi)
0x00416023:	pushl $0x2<UINT8>
0x00416025:	popl %ebx
0x00416026:	call 0x00416015
0x00416015:	addb %dl, %dl
0x00416017:	jne 0x0041601e
0x00416019:	movb %dl, (%esi)
0x0041601b:	incl %esi
0x0041601c:	adcb %dl, %dl
0x0041601e:	ret

0x00416029:	jae 0x00416022
0x0041602b:	xorl %ecx, %ecx
0x0041602d:	call 0x00416015
0x00416030:	jae 0x0041604a
0x00416032:	xorl %eax, %eax
0x00416034:	call 0x00416015
0x00416037:	jae 0x0041605a
0x00416039:	movb %bl, $0x2<UINT8>
0x0041603b:	incl %ecx
0x0041603c:	movb %al, $0x10<UINT8>
0x0041603e:	call 0x00416015
0x00416041:	adcb %al, %al
0x00416043:	jae 0x0041603e
0x00416045:	jne 0x00416086
0x00416086:	pushl %esi
0x00416087:	movl %esi, %edi
0x00416089:	subl %esi, %eax
0x0041608b:	rep movsb %es:(%edi), %ds:(%esi)
0x0041608d:	popl %esi
0x0041608e:	jmp 0x00416026
0x00416047:	stosb %es:(%edi), %al
0x00416048:	jmp 0x00416026
0x0041605a:	lodsb %al, %ds:(%esi)
0x0041605b:	shrl %eax
0x0041605d:	je 0x004160a0
0x0041605f:	adcl %ecx, %ecx
0x00416061:	jmp 0x0041607f
0x0041607f:	incl %ecx
0x00416080:	incl %ecx
0x00416081:	xchgl %ebp, %eax
0x00416082:	movl %eax, %ebp
0x00416084:	movb %bl, $0x1<UINT8>
0x0041604a:	call 0x00416092
0x00416092:	incl %ecx
0x00416093:	call 0x00416015
0x00416097:	adcl %ecx, %ecx
0x00416099:	call 0x00416015
0x0041609d:	jb 0x00416093
0x0041609f:	ret

0x0041604f:	subl %ecx, %ebx
0x00416051:	jne 0x00416063
0x00416063:	xchgl %ecx, %eax
0x00416064:	decl %eax
0x00416065:	shll %eax, $0x8<UINT8>
0x00416068:	lodsb %al, %ds:(%esi)
0x00416069:	call 0x00416090
0x00416090:	xorl %ecx, %ecx
0x0041606e:	cmpl %eax, $0x7d00<UINT32>
0x00416073:	jae 10
0x00416075:	cmpb %ah, $0x5<UINT8>
0x00416078:	jae 0x00416080
0x0041607a:	cmpl %eax, $0x7f<UINT8>
0x0041607d:	ja 0x00416081
0x00416053:	call 0x00416090
0x00416058:	jmp 0x00416082
0x004160a0:	popl %edi
0x004160a1:	popl %ebx
0x004160a2:	movzwl %edi, (%ebx)
0x004160a5:	decl %edi
0x004160a6:	je 0x004160b0
0x004160a8:	decl %edi
0x004160a9:	je 0x004160be
0x004160ab:	shll %edi, $0xc<UINT8>
0x004160ae:	jmp 0x004160b7
0x004160b7:	incl %ebx
0x004160b8:	incl %ebx
0x004160b9:	jmp 0x0041600f
0x004160b0:	movl %edi, 0x2(%ebx)
0x004160b3:	pushl %edi
0x004160b4:	addl %ebx, $0x4<UINT8>
0x004160be:	popl %edi
0x004160bf:	movl %ebx, $0x416128<UINT32>
0x004160c4:	incl %edi
0x004160c5:	movl %esi, (%edi)
0x004160c7:	scasl %eax, %es:(%edi)
0x004160c8:	pushl %edi
0x004160c9:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004160cb:	xchgl %ebp, %eax
0x004160cc:	xorl %eax, %eax
0x004160ce:	scasb %al, %es:(%edi)
0x004160cf:	jne 0x004160ce
0x004160d1:	decb (%edi)
0x004160d3:	je 0x004160c4
0x004160d5:	decb (%edi)
0x004160d7:	jne 0x004160df
0x004160df:	decb (%edi)
0x004160e1:	je 0x0040532c
0x004160e7:	pushl %edi
0x004160e8:	pushl %ebp
0x004160e9:	call GetProcAddress@kernel32.dll
GetProcAddress@kernel32.dll: API Node	
0x004160ec:	orl (%esi), %eax
0x004160ee:	lodsl %eax, %ds:(%esi)
0x004160ef:	jne 0x004160cc
0x0040532c:	pushl %ebp
0x0040532d:	movl %ebp, %esp
0x0040532f:	pushl $0xffffffff<UINT8>
0x00405331:	pushl $0x4061a0<UINT32>
0x00405336:	pushl $0x4054c0<UINT32>
0x0040533b:	movl %eax, %fs:0
0x00405341:	pushl %eax
0x00405342:	movl %fs:0, %esp
0x00405349:	subl %esp, $0x68<UINT8>
0x0040534c:	pushl %ebx
0x0040534d:	pushl %esi
0x0040534e:	pushl %edi
0x0040534f:	movl -24(%ebp), %esp
0x00405352:	xorl %ebx, %ebx
0x00405354:	movl -4(%ebp), %ebx
0x00405357:	pushl $0x2<UINT8>
0x00405359:	call __set_app_type@MSVCRT.dll
__set_app_type@MSVCRT.dll: API Node	
0x0040535f:	popl %ecx
0x00405360:	orl 0x40f1b4, $0xffffffff<UINT8>
0x00405367:	orl 0x40f1b8, $0xffffffff<UINT8>
0x0040536e:	call __p__fmode@MSVCRT.dll
__p__fmode@MSVCRT.dll: API Node	
0x00405374:	movl %ecx, 0x40717c
0x0040537a:	movl (%eax), %ecx
0x0040537c:	call __p__commode@MSVCRT.dll
__p__commode@MSVCRT.dll: API Node	
0x00405382:	movl %ecx, 0x407178
0x00405388:	movl (%eax), %ecx
0x0040538a:	movl %eax, 0x4060a4
0x0040538f:	movl %eax, (%eax)
0x00405391:	movl 0x40f1b0, %eax
0x00405396:	call 0x004054b1
0x004054b1:	ret

0x0040539b:	cmpl 0x407020, %ebx
0x004053a1:	jne 0x004053af
0x004053af:	call 0x0040549c
0x0040549c:	pushl $0x30000<UINT32>
0x004054a1:	pushl $0x10000<UINT32>
0x004054a6:	call 0x004054c6
0x004054c6:	jmp _controlfp@MSVCRT.dll
_controlfp@MSVCRT.dll: API Node	
0x004054ab:	popl %ecx
0x004054ac:	popl %ecx
0x004054ad:	ret

0x004053b4:	pushl $0x407014<UINT32>
0x004053b9:	pushl $0x407010<UINT32>
0x004053be:	call 0x00405496
0x00405496:	jmp _initterm@MSVCRT.dll
_initterm@MSVCRT.dll: API Node	
0x004053c3:	movl %eax, 0x407174
0x004053c8:	movl -108(%ebp), %eax
0x004053cb:	leal %eax, -108(%ebp)
0x004053ce:	pushl %eax
0x004053cf:	pushl 0x407170
0x004053d5:	leal %eax, -100(%ebp)
0x004053d8:	pushl %eax
0x004053d9:	leal %eax, -112(%ebp)
0x004053dc:	pushl %eax
0x004053dd:	leal %eax, -96(%ebp)
0x004053e0:	pushl %eax
0x004053e1:	call __getmainargs@MSVCRT.dll
__getmainargs@MSVCRT.dll: API Node	
0x004053e7:	pushl $0x40700c<UINT32>
0x004053ec:	pushl $0x407000<UINT32>
0x004053f1:	call 0x00405496
0x004053f6:	addl %esp, $0x24<UINT8>
0x004053f9:	movl %eax, 0x4060b4
0x004053fe:	movl %esi, (%eax)
0x00405400:	movl -116(%ebp), %esi
0x00405403:	cmpb (%esi), $0x22<UINT8>
0x00405406:	jne 58
0x00405408:	incl %esi
0x00405409:	movl -116(%ebp), %esi
0x0040540c:	movb %al, (%esi)
0x0040540e:	cmpb %al, %bl
0x00405410:	je 4
0x00405412:	cmpb %al, $0x22<UINT8>
0x00405414:	jne 0x00405408
0x00405416:	cmpb (%esi), $0x22<UINT8>
0x00405419:	jne 4
0x0040541b:	incl %esi
0x0040541c:	movl -116(%ebp), %esi
0x0040541f:	movb %al, (%esi)
0x00405421:	cmpb %al, %bl
0x00405423:	je 4
0x00405425:	cmpb %al, $0x20<UINT8>
0x00405427:	jbe 0x0040541b
0x00405429:	movl -48(%ebp), %ebx
0x0040542c:	leal %eax, -92(%ebp)
0x0040542f:	pushl %eax
0x00405430:	call GetStartupInfoA@KERNEL32.dll
GetStartupInfoA@KERNEL32.dll: API Node	
0x00405436:	testb -48(%ebp), $0x1<UINT8>
0x0040543a:	je 0x0040544d
0x0040544d:	pushl $0xa<UINT8>
0x0040544f:	popl %eax
0x00405450:	pushl %eax
0x00405451:	pushl %esi
0x00405452:	pushl %ebx
0x00405453:	pushl %ebx
0x00405454:	call GetModuleHandleA@KERNEL32.dll
GetModuleHandleA@KERNEL32.dll: API Node	
0x0040545a:	pushl %eax
0x0040545b:	call 0x00401390
0x00401390:	movl %eax, 0x4(%esp)
0x00401394:	call 0x004013e0
0x004013e0:	subl %esp, $0x30<UINT8>
0x004013e3:	leal %ecx, (%esp)
0x004013e6:	pushl %ecx
0x004013e7:	movl 0x407194, %eax
0x004013ec:	movl 0x4(%esp), $0x8<UINT32>
0x004013f4:	movl 0x8(%esp), $0x20<UINT32>
0x004013fc:	call InitCommonControlsEx@COMCTL32.dll
InitCommonControlsEx@COMCTL32.dll: API Node	
0x00401402:	leal %edx, 0x8(%esp)
0x00401406:	pushl %edx
0x00401407:	pushl $0x40674c<UINT32>
0x0040140c:	pushl $0x0<UINT8>
0x0040140e:	call GetClassInfoA@USER32.dll
GetClassInfoA@USER32.dll: API Node	
0x00401414:	movl %eax, 0x407194
0x00401419:	pushl $0x66<UINT8>
0x0040141b:	pushl %eax
0x0040141c:	movl 0x20(%esp), %eax
0x00401420:	call LoadIconA@USER32.dll
LoadIconA@USER32.dll: API Node	
0x00401426:	movl 0x1c(%esp), %eax
0x0040142a:	leal %eax, 0x8(%esp)
0x0040142e:	pushl %eax
0x0040142f:	movl 0x30(%esp), $0x40706c<UINT32>
0x00401437:	call RegisterClassA@USER32.dll
RegisterClassA@USER32.dll: API Node	
0x0040143d:	movl %eax, $0x1<UINT32>
0x00401442:	movl 0x40f1a4, %eax
0x00401447:	movl 0x407188, %eax
0x0040144c:	movl 0x40f19c, %eax
0x00401451:	movl 0x407184, %eax
0x00401456:	movl 0x40718c, %eax
0x0040145b:	addl %esp, $0x30<UINT8>
0x0040145e:	ret

0x00407000:	insb %es:(%edi), %dx
0x00407002:	insb %es:(%edi), %dx
0x00407003:	addb 0x61(%eax), %dl
0x004054c0:	jmp _except_handler3@MSVCRT.dll
_except_handler3@MSVCRT.dll: API Node	
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
