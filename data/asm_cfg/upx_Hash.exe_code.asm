0x00413fe0:	pusha
0x00413fe1:	movl %esi, $0x411000<UINT32>
0x00413fe6:	leal %edi, -65536(%esi)
0x00413fec:	pushl %edi
0x00413fed:	jmp 0x00413ffa
0x00413ffa:	movl %ebx, (%esi)
0x00413ffc:	subl %esi, $0xfffffffc<UINT8>
0x00413fff:	adcl %ebx, %ebx
0x00414001:	jb 0x00413ff0
0x00413ff0:	movb %al, (%esi)
0x00413ff2:	incl %esi
0x00413ff3:	movb (%edi), %al
0x00413ff5:	incl %edi
0x00413ff6:	addl %ebx, %ebx
0x00413ff8:	jne 0x00414001
0x00414003:	movl %eax, $0x1<UINT32>
0x00414008:	addl %ebx, %ebx
0x0041400a:	jne 0x00414013
0x0041400c:	movl %ebx, (%esi)
0x0041400e:	subl %esi, $0xfffffffc<UINT8>
0x00414011:	adcl %ebx, %ebx
0x00414013:	adcl %eax, %eax
0x00414015:	addl %ebx, %ebx
0x00414017:	jae 0x00414008
0x00414019:	jne 0x00414024
0x00414024:	xorl %ecx, %ecx
0x00414026:	subl %eax, $0x3<UINT8>
0x00414029:	jb 0x00414038
0x0041402b:	shll %eax, $0x8<UINT8>
0x0041402e:	movb %al, (%esi)
0x00414030:	incl %esi
0x00414031:	xorl %eax, $0xffffffff<UINT8>
0x00414034:	je 0x004140aa
0x00414036:	movl %ebp, %eax
0x00414038:	addl %ebx, %ebx
0x0041403a:	jne 0x00414043
0x00414043:	adcl %ecx, %ecx
0x00414045:	addl %ebx, %ebx
0x00414047:	jne 0x00414050
0x00414050:	adcl %ecx, %ecx
0x00414052:	jne 0x00414074
0x00414074:	cmpl %ebp, $0xfffff300<UINT32>
0x0041407a:	adcl %ecx, $0x1<UINT8>
0x0041407d:	leal %edx, (%edi,%ebp)
0x00414080:	cmpl %ebp, $0xfffffffc<UINT8>
0x00414083:	jbe 0x00414094
0x00414094:	movl %eax, (%edx)
0x00414096:	addl %edx, $0x4<UINT8>
0x00414099:	movl (%edi), %eax
0x0041409b:	addl %edi, $0x4<UINT8>
0x0041409e:	subl %ecx, $0x4<UINT8>
0x004140a1:	ja 0x00414094
0x004140a3:	addl %edi, %ecx
0x004140a5:	jmp 0x00413ff6
0x00414054:	incl %ecx
0x00414055:	addl %ebx, %ebx
0x00414057:	jne 0x00414060
0x00414060:	adcl %ecx, %ecx
0x00414062:	addl %ebx, %ebx
0x00414064:	jae 0x00414055
0x00414066:	jne 0x00414071
0x00414071:	addl %ecx, $0x2<UINT8>
0x00414085:	movb %al, (%edx)
0x00414087:	incl %edx
0x00414088:	movb (%edi), %al
0x0041408a:	incl %edi
0x0041408b:	decl %ecx
0x0041408c:	jne 0x00414085
0x0041408e:	jmp 0x00413ff6
0x00414049:	movl %ebx, (%esi)
0x0041404b:	subl %esi, $0xfffffffc<UINT8>
0x0041404e:	adcl %ebx, %ebx
0x0041403c:	movl %ebx, (%esi)
0x0041403e:	subl %esi, $0xfffffffc<UINT8>
0x00414041:	adcl %ebx, %ebx
0x00414059:	movl %ebx, (%esi)
0x0041405b:	subl %esi, $0xfffffffc<UINT8>
0x0041405e:	adcl %ebx, %ebx
0x0041401b:	movl %ebx, (%esi)
0x0041401d:	subl %esi, $0xfffffffc<UINT8>
0x00414020:	adcl %ebx, %ebx
0x00414022:	jae 0x00414008
0x00414068:	movl %ebx, (%esi)
0x0041406a:	subl %esi, $0xfffffffc<UINT8>
0x0041406d:	adcl %ebx, %ebx
0x0041406f:	jae 0x00414055
0x004140aa:	popl %esi
0x004140ab:	movl %edi, %esi
0x004140ad:	movl %ecx, $0x56<UINT32>
0x004140b2:	movb %al, (%edi)
0x004140b4:	incl %edi
0x004140b5:	subb %al, $0xffffffe8<UINT8>
0x004140b7:	cmpb %al, $0x1<UINT8>
0x004140b9:	ja 0x004140b2
0x004140bb:	cmpb (%edi), $0x1<UINT8>
0x004140be:	jne 0x004140b2
0x004140c0:	movl %eax, (%edi)
0x004140c2:	movb %bl, 0x4(%edi)
0x004140c5:	shrw %ax, $0x8<UINT8>
0x004140c9:	roll %eax, $0x10<UINT8>
0x004140cc:	xchgb %ah, %al
0x004140ce:	subl %eax, %edi
0x004140d0:	subb %bl, $0xffffffe8<UINT8>
0x004140d3:	addl %eax, %esi
0x004140d5:	movl (%edi), %eax
0x004140d7:	addl %edi, $0x5<UINT8>
0x004140da:	movb %al, %bl
0x004140dc:	loop 0x004140b7
0x004140de:	leal %edi, 0x11000(%esi)
0x004140e4:	movl %eax, (%edi)
0x004140e6:	orl %eax, %eax
0x004140e8:	je 0x00414126
0x004140ea:	movl %ebx, 0x4(%edi)
0x004140ed:	leal %eax, 0x14f44(%eax,%esi)
0x004140f4:	addl %ebx, %esi
0x004140f6:	pushl %eax
0x004140f7:	addl %edi, $0x8<UINT8>
0x004140fa:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x00414100:	xchgl %ebp, %eax
0x00414101:	movb %al, (%edi)
0x00414103:	incl %edi
0x00414104:	orb %al, %al
0x00414106:	je 0x004140e4
0x00414108:	movl %ecx, %edi
0x0041410a:	pushl %edi
0x0041410b:	decl %eax
0x0041410c:	repn scasb %al, %es:(%edi)
0x0041410e:	pushl %ebp
0x0041410f:	call GetProcAddress@kernel32.dll
GetProcAddress@kernel32.dll: API Node	
0x00414115:	orl %eax, %eax
0x00414117:	je 7
0x00414119:	movl (%ebx), %eax
0x0041411b:	addl %ebx, $0x4<UINT8>
0x0041411e:	jmp 0x00414101
0x00414126:	movl %ebp, 0x15014(%esi)
0x0041412c:	leal %edi, -4096(%esi)
0x00414132:	movl %ebx, $0x1000<UINT32>
0x00414137:	pushl %eax
0x00414138:	pushl %esp
0x00414139:	pushl $0x4<UINT8>
0x0041413b:	pushl %ebx
0x0041413c:	pushl %edi
0x0041413d:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0041413f:	leal %eax, 0x217(%edi)
0x00414145:	andb (%eax), $0x7f<UINT8>
0x00414148:	andb 0x28(%eax), $0x7f<UINT8>
0x0041414c:	popl %eax
0x0041414d:	pushl %eax
0x0041414e:	pushl %esp
0x0041414f:	pushl %eax
0x00414150:	pushl %ebx
0x00414151:	pushl %edi
0x00414152:	call VirtualProtect@kernel32.dll
0x00414154:	popl %eax
0x00414155:	popa
0x00414156:	leal %eax, -128(%esp)
0x0041415a:	pushl $0x0<UINT8>
0x0041415c:	cmpl %esp, %eax
0x0041415e:	jne 0x0041415a
0x00414160:	subl %esp, $0xffffff80<UINT8>
0x00414163:	jmp 0x0040532c
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
0x00405430:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x00405436:	testb -48(%ebp), $0x1<UINT8>
0x0040543a:	je 0x0040544d
0x0040544d:	pushl $0xa<UINT8>
0x0040544f:	popl %eax
0x00405450:	pushl %eax
0x00405451:	pushl %esi
0x00405452:	pushl %ebx
0x00405453:	pushl %ebx
0x00405454:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
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

0x00407000:	addb (%eax), %al
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
