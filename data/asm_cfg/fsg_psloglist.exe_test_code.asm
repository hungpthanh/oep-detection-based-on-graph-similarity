0x00443000:	movl %ebx, $0x4001d0<UINT32>
0x00443005:	movl %edi, $0x401000<UINT32>
0x0044300a:	movl %esi, $0x42f1fa<UINT32>
0x0044300f:	pushl %ebx
0x00443010:	call 0x0044301f
0x0044301f:	cld
0x00443020:	movb %dl, $0xffffff80<UINT8>
0x00443022:	movsb %es:(%edi), %ds:(%esi)
0x00443023:	pushl $0x2<UINT8>
0x00443025:	popl %ebx
0x00443026:	call 0x00443015
0x00443015:	addb %dl, %dl
0x00443017:	jne 0x0044301e
0x00443019:	movb %dl, (%esi)
0x0044301b:	incl %esi
0x0044301c:	adcb %dl, %dl
0x0044301e:	ret

0x00443029:	jae 0x00443022
0x0044302b:	xorl %ecx, %ecx
0x0044302d:	call 0x00443015
0x00443030:	jae 0x0044304a
0x00443032:	xorl %eax, %eax
0x00443034:	call 0x00443015
0x00443037:	jae 0x0044305a
0x00443039:	movb %bl, $0x2<UINT8>
0x0044303b:	incl %ecx
0x0044303c:	movb %al, $0x10<UINT8>
0x0044303e:	call 0x00443015
0x00443041:	adcb %al, %al
0x00443043:	jae 0x0044303e
0x00443045:	jne 0x00443086
0x00443047:	stosb %es:(%edi), %al
0x00443048:	jmp 0x00443026
0x0044305a:	lodsb %al, %ds:(%esi)
0x0044305b:	shrl %eax
0x0044305d:	je 0x004430a0
0x0044305f:	adcl %ecx, %ecx
0x00443061:	jmp 0x0044307f
0x0044307f:	incl %ecx
0x00443080:	incl %ecx
0x00443081:	xchgl %ebp, %eax
0x00443082:	movl %eax, %ebp
0x00443084:	movb %bl, $0x1<UINT8>
0x00443086:	pushl %esi
0x00443087:	movl %esi, %edi
0x00443089:	subl %esi, %eax
0x0044308b:	rep movsb %es:(%edi), %ds:(%esi)
0x0044308d:	popl %esi
0x0044308e:	jmp 0x00443026
0x0044304a:	call 0x00443092
0x00443092:	incl %ecx
0x00443093:	call 0x00443015
0x00443097:	adcl %ecx, %ecx
0x00443099:	call 0x00443015
0x0044309d:	jb 0x00443093
0x0044309f:	ret

0x0044304f:	subl %ecx, %ebx
0x00443051:	jne 0x00443063
0x00443053:	call 0x00443090
0x00443090:	xorl %ecx, %ecx
0x00443058:	jmp 0x00443082
0x00443063:	xchgl %ecx, %eax
0x00443064:	decl %eax
0x00443065:	shll %eax, $0x8<UINT8>
0x00443068:	lodsb %al, %ds:(%esi)
0x00443069:	call 0x00443090
0x0044306e:	cmpl %eax, $0x7d00<UINT32>
0x00443073:	jae 0x0044307f
0x00443075:	cmpb %ah, $0x5<UINT8>
0x00443078:	jae 0x00443080
0x0044307a:	cmpl %eax, $0x7f<UINT8>
0x0044307d:	ja 0x00443081
0x004430a0:	popl %edi
0x004430a1:	popl %ebx
0x004430a2:	movzwl %edi, (%ebx)
0x004430a5:	decl %edi
0x004430a6:	je 0x004430b0
0x004430a8:	decl %edi
0x004430a9:	je 0x004430be
0x004430ab:	shll %edi, $0xc<UINT8>
0x004430ae:	jmp 0x004430b7
0x004430b7:	incl %ebx
0x004430b8:	incl %ebx
0x004430b9:	jmp 0x0044300f
0x004430b0:	movl %edi, 0x2(%ebx)
0x004430b3:	pushl %edi
0x004430b4:	addl %ebx, $0x4<UINT8>
0x004430be:	popl %edi
0x004430bf:	movl %ebx, $0x443128<UINT32>
0x004430c4:	incl %edi
0x004430c5:	movl %esi, (%edi)
0x004430c7:	scasl %eax, %es:(%edi)
0x004430c8:	pushl %edi
0x004430c9:	call LoadLibraryA@KERNEL32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004430cb:	xchgl %ebp, %eax
0x004430cc:	xorl %eax, %eax
0x004430ce:	scasb %al, %es:(%edi)
0x004430cf:	jne 0x004430ce
0x004430d1:	decb (%edi)
0x004430d3:	je 0x004430c4
0x004430d5:	decb (%edi)
0x004430d7:	jne 0x004430df
0x004430df:	decb (%edi)
0x004430e1:	je 0x00409955
0x004430e7:	pushl %edi
0x004430e8:	pushl %ebp
0x004430e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x004430ec:	orl (%esi), %eax
0x004430ee:	lodsl %eax, %ds:(%esi)
0x004430ef:	jne 0x004430cc
0x004430d9:	incl %edi
0x004430da:	pushl (%edi)
0x004430dc:	scasl %eax, %es:(%edi)
0x004430dd:	jmp 0x004430e8
GetProcAddress@KERNEL32.dll: API Node	
LoadLibraryA@KERNEL32.dll: API Node	
0x00409955:	call 0x00414487
0x00414487:	movl %edi, %edi
0x00414489:	pushl %ebp
0x0041448a:	movl %ebp, %esp
0x0041448c:	subl %esp, $0x10<UINT8>
0x0041448f:	movl %eax, 0x42a1f0
0x00414494:	andl -8(%ebp), $0x0<UINT8>
0x00414498:	andl -4(%ebp), $0x0<UINT8>
0x0041449c:	pushl %ebx
0x0041449d:	pushl %edi
0x0041449e:	movl %edi, $0xbb40e64e<UINT32>
0x004144a3:	movl %ebx, $0xffff0000<UINT32>
0x004144a8:	cmpl %eax, %edi
0x004144aa:	je 0x004144b9
0x004144b9:	pushl %esi
0x004144ba:	leal %eax, -8(%ebp)
0x004144bd:	pushl %eax
0x004144be:	call GetSystemTimeAsFileTime@KERNEL32.dll
GetSystemTimeAsFileTime@KERNEL32.dll: API Node	
0x004144c4:	movl %esi, -4(%ebp)
0x004144c7:	xorl %esi, -8(%ebp)
0x004144ca:	call GetCurrentProcessId@KERNEL32.dll
GetCurrentProcessId@KERNEL32.dll: API Node	
0x004144d0:	xorl %esi, %eax
0x004144d2:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x004144d8:	xorl %esi, %eax
0x004144da:	call GetTickCount@KERNEL32.dll
GetTickCount@KERNEL32.dll: API Node	
0x004144e0:	xorl %esi, %eax
0x004144e2:	leal %eax, -16(%ebp)
0x004144e5:	pushl %eax
0x004144e6:	call QueryPerformanceCounter@KERNEL32.dll
QueryPerformanceCounter@KERNEL32.dll: API Node	
0x004144ec:	movl %eax, -12(%ebp)
0x004144ef:	xorl %eax, -16(%ebp)
0x004144f2:	xorl %esi, %eax
0x004144f4:	cmpl %esi, %edi
0x004144f6:	jne 0x004144ff
0x004144ff:	testl %ebx, %esi
0x00414501:	jne 0x0041450a
0x0041450a:	movl 0x42a1f0, %esi
0x00414510:	notl %esi
0x00414512:	movl 0x42a1f4, %esi
0x00414518:	popl %esi
0x00414519:	popl %edi
0x0041451a:	popl %ebx
0x0041451b:	leave
0x0041451c:	ret

0x0040995a:	jmp 0x00409803
0x00409803:	pushl $0x14<UINT8>
0x00409805:	pushl $0x427dc8<UINT32>
0x0040980a:	call 0x0040e2b8
0x0040e2b8:	pushl $0x406fb0<UINT32>
0x0040e2bd:	pushl %fs:0
0x0040e2c4:	movl %eax, 0x10(%esp)
0x0040e2c8:	movl 0x10(%esp), %ebp
0x0040e2cc:	leal %ebp, 0x10(%esp)
0x0040e2d0:	subl %esp, %eax
0x0040e2d2:	pushl %ebx
0x0040e2d3:	pushl %esi
0x0040e2d4:	pushl %edi
0x0040e2d5:	movl %eax, 0x42a1f0
0x0040e2da:	xorl -4(%ebp), %eax
0x0040e2dd:	xorl %eax, %ebp
0x0040e2df:	pushl %eax
0x0040e2e0:	movl -24(%ebp), %esp
0x0040e2e3:	pushl -8(%ebp)
0x0040e2e6:	movl %eax, -4(%ebp)
0x0040e2e9:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040e2f0:	movl -8(%ebp), %eax
0x0040e2f3:	leal %eax, -16(%ebp)
0x0040e2f6:	movl %fs:0, %eax
0x0040e2fc:	ret

0x0040980f:	movl %eax, $0x5a4d<UINT32>
0x00409814:	cmpw 0x400000, %ax
0x0040981b:	jne 56
0x0040981d:	movl %eax, 0x40003c
0x00409822:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x0040982c:	jne 39
0x0040982e:	movl %ecx, $0x10b<UINT32>
0x00409833:	cmpw 0x400018(%eax), %cx
0x0040983a:	jne 25
0x0040983c:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00409843:	jbe 16
0x00409845:	xorl %ecx, %ecx
0x00409847:	cmpl 0x4000e8(%eax), %ecx
0x0040984d:	setne %cl
0x00409850:	movl -28(%ebp), %ecx
0x00409853:	jmp 0x00409859
0x00409859:	pushl $0x1<UINT8>
0x0040985b:	call 0x0040e315
0x0040e315:	movl %edi, %edi
0x0040e317:	pushl %ebp
0x0040e318:	movl %ebp, %esp
0x0040e31a:	xorl %eax, %eax
0x0040e31c:	cmpl 0x8(%ebp), %eax
0x0040e31f:	pushl $0x0<UINT8>
0x0040e321:	sete %al
0x0040e324:	pushl $0x1000<UINT32>
0x0040e329:	pushl %eax
0x0040e32a:	call HeapCreate@KERNEL32.dll
HeapCreate@KERNEL32.dll: API Node	
0x0040e330:	movl 0x42bf1c, %eax
0x0040e335:	testl %eax, %eax
0x0040e337:	jne 0x0040e33b
0x0040e33b:	xorl %eax, %eax
0x0040e33d:	incl %eax
0x0040e33e:	movl 0x42cc24, %eax
0x0040e343:	popl %ebp
0x0040e344:	ret

0x00409860:	popl %ecx
0x00409861:	testl %eax, %eax
0x00409863:	jne 0x0040986d
0x0040986d:	call 0x0040b82e
0x0040b82e:	movl %edi, %edi
0x0040b830:	pushl %esi
0x0040b831:	pushl %edi
0x0040b832:	movl %esi, $0x4260d8<UINT32>
0x0040b837:	pushl %esi
0x0040b838:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x0040b83e:	testl %eax, %eax
0x0040b840:	jne 0x0040b849
0x0040b849:	movl %edi, %eax
0x0040b84b:	testl %edi, %edi
0x0040b84d:	je 350
0x0040b853:	movl %esi, 0x4220a0
0x0040b859:	pushl $0x426124<UINT32>
0x0040b85e:	pushl %edi
0x0040b85f:	call GetProcAddress@KERNEL32.dll
0x0040b861:	pushl $0x426118<UINT32>
0x0040b866:	pushl %edi
0x0040b867:	movl 0x42bdb4, %eax
0x0040b86c:	call GetProcAddress@KERNEL32.dll
0x0040b86e:	pushl $0x42610c<UINT32>
0x0040b873:	pushl %edi
0x0040b874:	movl 0x42bdb8, %eax
0x0040b879:	call GetProcAddress@KERNEL32.dll
0x0040b87b:	pushl $0x426104<UINT32>
0x0040b880:	pushl %edi
0x0040b881:	movl 0x42bdbc, %eax
0x0040b886:	call GetProcAddress@KERNEL32.dll
0x0040b888:	cmpl 0x42bdb4, $0x0<UINT8>
0x0040b88f:	movl %esi, 0x422210
0x0040b895:	movl 0x42bdc0, %eax
0x0040b89a:	je 22
0x0040b89c:	cmpl 0x42bdb8, $0x0<UINT8>
0x0040b8a3:	je 13
0x0040b8a5:	cmpl 0x42bdbc, $0x0<UINT8>
0x0040b8ac:	je 4
0x0040b8ae:	testl %eax, %eax
0x0040b8b0:	jne 0x0040b8d6
0x0040b8d6:	call TlsAlloc@KERNEL32.dll
TlsAlloc@KERNEL32.dll: API Node	
0x0040b8dc:	movl 0x42aab4, %eax
0x0040b8e1:	cmpl %eax, $0xffffffff<UINT8>
0x0040b8e4:	je 204
0x0040b8ea:	pushl 0x42bdb8
0x0040b8f0:	pushl %eax
0x0040b8f1:	call TlsSetValue@KERNEL32.dll
TlsSetValue@KERNEL32.dll: API Node	
0x0040b8f3:	testl %eax, %eax
0x0040b8f5:	je 187
0x0040b8fb:	call 0x00408444
0x00408444:	movl %edi, %edi
0x00408446:	pushl %esi
0x00408447:	call 0x0040b3d9
0x0040b3d9:	pushl $0x0<UINT8>
0x0040b3db:	call 0x0040b367
0x0040b367:	movl %edi, %edi
0x0040b369:	pushl %ebp
0x0040b36a:	movl %ebp, %esp
0x0040b36c:	pushl %esi
0x0040b36d:	pushl 0x42aab4
0x0040b373:	movl %esi, 0x422208
0x0040b379:	call TlsGetValue@KERNEL32.dll
TlsGetValue@KERNEL32.dll: API Node	
0x0040b37b:	testl %eax, %eax
0x0040b37d:	je 33
0x0040b37f:	movl %eax, 0x42aab0
0x0040b384:	cmpl %eax, $0xffffffff<UINT8>
0x0040b387:	je 0x0040b3a0
0x0040b3a0:	movl %esi, $0x4260d8<UINT32>
0x0040b3a5:	pushl %esi
0x0040b3a6:	call GetModuleHandleW@KERNEL32.dll
0x0040b3ac:	testl %eax, %eax
0x0040b3ae:	jne 0x0040b3bb
0x0040b3bb:	pushl $0x4260c8<UINT32>
0x0040b3c0:	pushl %eax
0x0040b3c1:	call GetProcAddress@KERNEL32.dll
0x0040b3c7:	testl %eax, %eax
0x0040b3c9:	je 8
0x0040b3cb:	pushl 0x8(%ebp)
0x0040b3ce:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x0040b3d0:	movl 0x8(%ebp), %eax
0x0040b3d3:	movl %eax, 0x8(%ebp)
0x0040b3d6:	popl %esi
0x0040b3d7:	popl %ebp
0x0040b3d8:	ret

0x0040b3e0:	popl %ecx
0x0040b3e1:	ret

0x0040844c:	movl %esi, %eax
0x0040844e:	pushl %esi
0x0040844f:	call 0x0040e5c9
0x0040e5c9:	movl %edi, %edi
0x0040e5cb:	pushl %ebp
0x0040e5cc:	movl %ebp, %esp
0x0040e5ce:	movl %eax, 0x8(%ebp)
0x0040e5d1:	movl 0x42c234, %eax
0x0040e5d6:	popl %ebp
0x0040e5d7:	ret

0x00408454:	pushl %esi
0x00408455:	call 0x00413591
0x00413591:	movl %edi, %edi
0x00413593:	pushl %ebp
0x00413594:	movl %ebp, %esp
0x00413596:	movl %eax, 0x8(%ebp)
0x00413599:	movl 0x42c59c, %eax
0x0041359e:	popl %ebp
0x0041359f:	ret

0x0040845a:	pushl %esi
0x0040845b:	call 0x0040bb09
0x0040bb09:	movl %edi, %edi
0x0040bb0b:	pushl %ebp
0x0040bb0c:	movl %ebp, %esp
0x0040bb0e:	movl %eax, 0x8(%ebp)
0x0040bb11:	movl 0x42bdc4, %eax
0x0040bb16:	popl %ebp
0x0040bb17:	ret

0x00408460:	pushl %esi
0x00408461:	call 0x00413582
0x00413582:	movl %edi, %edi
0x00413584:	pushl %ebp
0x00413585:	movl %ebp, %esp
0x00413587:	movl %eax, 0x8(%ebp)
0x0041358a:	movl 0x42c598, %eax
0x0041358f:	popl %ebp
0x00413590:	ret

0x00408466:	pushl %esi
0x00408467:	call 0x004132ec
0x004132ec:	movl %edi, %edi
0x004132ee:	pushl %ebp
0x004132ef:	movl %ebp, %esp
0x004132f1:	movl %eax, 0x8(%ebp)
0x004132f4:	movl 0x42c58c, %eax
0x004132f9:	popl %ebp
0x004132fa:	ret

0x0040846c:	pushl %esi
0x0040846d:	call 0x00412df0
0x00412df0:	movl %edi, %edi
0x00412df2:	pushl %ebp
0x00412df3:	movl %ebp, %esp
0x00412df5:	movl %eax, 0x8(%ebp)
0x00412df8:	movl 0x42c578, %eax
0x00412dfd:	movl 0x42c57c, %eax
0x00412e02:	movl 0x42c580, %eax
0x00412e07:	movl 0x42c584, %eax
0x00412e0c:	popl %ebp
0x00412e0d:	ret

0x00408472:	pushl %esi
0x00408473:	call 0x00412c3a
0x00412c3a:	ret

0x00408478:	pushl %esi
0x00408479:	call 0x00412c29
0x00412c29:	pushl $0x412ba5<UINT32>
0x00412c2e:	call 0x0040b367
0x00412c33:	popl %ecx
0x00412c34:	movl 0x42c574, %eax
0x00412c39:	ret

0x0040847e:	pushl $0x408410<UINT32>
0x00408483:	call 0x0040b367
0x00408488:	addl %esp, $0x24<UINT8>
0x0040848b:	movl 0x42a484, %eax
0x00408490:	popl %esi
0x00408491:	ret

0x0040b900:	pushl 0x42bdb4
0x0040b906:	call 0x0040b367
0x0040b90b:	pushl 0x42bdb8
0x0040b911:	movl 0x42bdb4, %eax
0x0040b916:	call 0x0040b367
0x0040b91b:	pushl 0x42bdbc
0x0040b921:	movl 0x42bdb8, %eax
0x0040b926:	call 0x0040b367
0x0040b92b:	pushl 0x42bdc0
0x0040b931:	movl 0x42bdbc, %eax
0x0040b936:	call 0x0040b367
0x0040b93b:	addl %esp, $0x10<UINT8>
0x0040b93e:	movl 0x42bdc0, %eax
0x0040b943:	call 0x0040d0d1
0x0040d0d1:	movl %edi, %edi
0x0040d0d3:	pushl %esi
0x0040d0d4:	pushl %edi
0x0040d0d5:	xorl %esi, %esi
0x0040d0d7:	movl %edi, $0x42bdc8<UINT32>
0x0040d0dc:	cmpl 0x42ac34(,%esi,8), $0x1<UINT8>
0x0040d0e4:	jne 0x0040d104
0x0040d0e6:	leal %eax, 0x42ac30(,%esi,8)
0x0040d0ed:	movl (%eax), %edi
0x0040d0ef:	pushl $0xfa0<UINT32>
0x0040d0f4:	pushl (%eax)
0x0040d0f6:	addl %edi, $0x18<UINT8>
0x0040d0f9:	call 0x004135a0
0x004135a0:	pushl $0x10<UINT8>
0x004135a2:	pushl $0x428120<UINT32>
0x004135a7:	call 0x0040e2b8
0x004135ac:	andl -4(%ebp), $0x0<UINT8>
0x004135b0:	pushl 0xc(%ebp)
0x004135b3:	pushl 0x8(%ebp)
0x004135b6:	call InitializeCriticalSectionAndSpinCount@KERNEL32.dll
InitializeCriticalSectionAndSpinCount@KERNEL32.dll: API Node	
0x004135bc:	movl -28(%ebp), %eax
0x004135bf:	jmp 0x004135f0
0x004135f0:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004135f7:	movl %eax, -28(%ebp)
0x004135fa:	call 0x0040e2fd
0x0040e2fd:	movl %ecx, -16(%ebp)
0x0040e300:	movl %fs:0, %ecx
0x0040e307:	popl %ecx
0x0040e308:	popl %edi
0x0040e309:	popl %edi
0x0040e30a:	popl %esi
0x0040e30b:	popl %ebx
0x0040e30c:	movl %esp, %ebp
0x0040e30e:	popl %ebp
0x0040e30f:	pushl %ecx
0x0040e310:	ret

0x004135ff:	ret

0x0040d0fe:	popl %ecx
0x0040d0ff:	popl %ecx
0x0040d100:	testl %eax, %eax
0x0040d102:	je 12
0x0040d104:	incl %esi
0x0040d105:	cmpl %esi, $0x24<UINT8>
0x0040d108:	jl 0x0040d0dc
0x0040d10a:	xorl %eax, %eax
0x0040d10c:	incl %eax
0x0040d10d:	popl %edi
0x0040d10e:	popl %esi
0x0040d10f:	ret

0x0040b948:	testl %eax, %eax
0x0040b94a:	je 101
0x0040b94c:	pushl $0x40b685<UINT32>
0x0040b951:	pushl 0x42bdb4
0x0040b957:	call 0x0040b3e2
0x0040b3e2:	movl %edi, %edi
0x0040b3e4:	pushl %ebp
0x0040b3e5:	movl %ebp, %esp
0x0040b3e7:	pushl %esi
0x0040b3e8:	pushl 0x42aab4
0x0040b3ee:	movl %esi, 0x422208
0x0040b3f4:	call TlsGetValue@KERNEL32.dll
0x0040b3f6:	testl %eax, %eax
0x0040b3f8:	je 33
0x0040b3fa:	movl %eax, 0x42aab0
0x0040b3ff:	cmpl %eax, $0xffffffff<UINT8>
0x0040b402:	je 0x0040b41b
0x0040b41b:	movl %esi, $0x4260d8<UINT32>
0x0040b420:	pushl %esi
0x0040b421:	call GetModuleHandleW@KERNEL32.dll
0x0040b427:	testl %eax, %eax
0x0040b429:	jne 0x0040b436
0x0040b436:	pushl $0x4260f4<UINT32>
0x0040b43b:	pushl %eax
0x0040b43c:	call GetProcAddress@KERNEL32.dll
0x0040b442:	testl %eax, %eax
0x0040b444:	je 8
0x0040b446:	pushl 0x8(%ebp)
0x0040b449:	call DecodePointer@KERNEL32.DLL
DecodePointer@KERNEL32.DLL: API Node	
0x0040b44b:	movl 0x8(%ebp), %eax
0x0040b44e:	movl %eax, 0x8(%ebp)
0x0040b451:	popl %esi
0x0040b452:	popl %ebp
0x0040b453:	ret

0x0040b95c:	popl %ecx
0x0040b95d:	call FlsAlloc@KERNEL32.DLL
FlsAlloc@KERNEL32.DLL: API Node	
0x0040b95f:	movl 0x42aab0, %eax
0x0040b964:	cmpl %eax, $0xffffffff<UINT8>
0x0040b967:	je 72
0x0040b969:	pushl $0x214<UINT32>
0x0040b96e:	pushl $0x1<UINT8>
0x0040b970:	call 0x00411b6b
0x00411b6b:	movl %edi, %edi
0x00411b6d:	pushl %ebp
0x00411b6e:	movl %ebp, %esp
0x00411b70:	pushl %esi
0x00411b71:	pushl %edi
0x00411b72:	xorl %esi, %esi
0x00411b74:	pushl $0x0<UINT8>
0x00411b76:	pushl 0xc(%ebp)
0x00411b79:	pushl 0x8(%ebp)
0x00411b7c:	call 0x0041cfb8
0x0041cfb8:	pushl $0xc<UINT8>
0x0041cfba:	pushl $0x4281c0<UINT32>
0x0041cfbf:	call 0x0040e2b8
0x0041cfc4:	movl %ecx, 0x8(%ebp)
0x0041cfc7:	xorl %edi, %edi
0x0041cfc9:	cmpl %ecx, %edi
0x0041cfcb:	jbe 46
0x0041cfcd:	pushl $0xffffffe0<UINT8>
0x0041cfcf:	popl %eax
0x0041cfd0:	xorl %edx, %edx
0x0041cfd2:	divl %eax, %ecx
0x0041cfd4:	cmpl %eax, 0xc(%ebp)
0x0041cfd7:	sbbl %eax, %eax
0x0041cfd9:	incl %eax
0x0041cfda:	jne 0x0041cffb
0x0041cffb:	imull %ecx, 0xc(%ebp)
0x0041cfff:	movl %esi, %ecx
0x0041d001:	movl 0x8(%ebp), %esi
0x0041d004:	cmpl %esi, %edi
0x0041d006:	jne 0x0041d00b
0x0041d00b:	xorl %ebx, %ebx
0x0041d00d:	movl -28(%ebp), %ebx
0x0041d010:	cmpl %esi, $0xffffffe0<UINT8>
0x0041d013:	ja 105
0x0041d015:	cmpl 0x42cc24, $0x3<UINT8>
0x0041d01c:	jne 0x0041d069
0x0041d069:	cmpl %ebx, %edi
0x0041d06b:	jne 97
0x0041d06d:	pushl %esi
0x0041d06e:	pushl $0x8<UINT8>
0x0041d070:	pushl 0x42bf1c
0x0041d076:	call HeapAlloc@KERNEL32.dll
HeapAlloc@KERNEL32.dll: API Node	
0x0041d07c:	movl %ebx, %eax
0x0041d07e:	cmpl %ebx, %edi
0x0041d080:	jne 0x0041d0ce
0x0041d0ce:	movl %eax, %ebx
0x0041d0d0:	call 0x0040e2fd
0x0041d0d5:	ret

0x00411b81:	movl %edi, %eax
0x00411b83:	addl %esp, $0xc<UINT8>
0x00411b86:	testl %edi, %edi
0x00411b88:	jne 0x00411bb1
0x00411bb1:	movl %eax, %edi
0x00411bb3:	popl %edi
0x00411bb4:	popl %esi
0x00411bb5:	popl %ebp
0x00411bb6:	ret

0x0040b975:	movl %esi, %eax
0x0040b977:	popl %ecx
0x0040b978:	popl %ecx
0x0040b979:	testl %esi, %esi
0x0040b97b:	je 52
0x0040b97d:	pushl %esi
0x0040b97e:	pushl 0x42aab0
0x0040b984:	pushl 0x42bdbc
0x0040b98a:	call 0x0040b3e2
0x0040b404:	pushl %eax
0x0040b405:	pushl 0x42aab4
0x0040b40b:	call TlsGetValue@KERNEL32.dll
0x0040b40d:	call FlsGetValue@KERNEL32.DLL
FlsGetValue@KERNEL32.DLL: API Node	
0x0040b40f:	testl %eax, %eax
0x0040b411:	je 0x0040b41b
0x0040b98f:	popl %ecx
0x0040b990:	call FlsSetValue@KERNEL32.DLL
FlsSetValue@KERNEL32.DLL: API Node	
0x0040b992:	testl %eax, %eax
0x0040b994:	je 27
0x0040b996:	pushl $0x0<UINT8>
0x0040b998:	pushl %esi
0x0040b999:	call 0x0040b50b
0x0040b50b:	pushl $0xc<UINT8>
0x0040b50d:	pushl $0x427ed0<UINT32>
0x0040b512:	call 0x0040e2b8
0x0040b517:	movl %esi, $0x4260d8<UINT32>
0x0040b51c:	pushl %esi
0x0040b51d:	call GetModuleHandleW@KERNEL32.dll
0x0040b523:	testl %eax, %eax
0x0040b525:	jne 0x0040b52e
0x0040b52e:	movl -28(%ebp), %eax
0x0040b531:	movl %esi, 0x8(%ebp)
0x0040b534:	movl 0x5c(%esi), $0x426780<UINT32>
0x0040b53b:	xorl %edi, %edi
0x0040b53d:	incl %edi
0x0040b53e:	movl 0x14(%esi), %edi
0x0040b541:	testl %eax, %eax
0x0040b543:	je 36
0x0040b545:	pushl $0x4260c8<UINT32>
0x0040b54a:	pushl %eax
0x0040b54b:	movl %ebx, 0x4220a0
0x0040b551:	call GetProcAddress@KERNEL32.dll
0x0040b553:	movl 0x1f8(%esi), %eax
0x0040b559:	pushl $0x4260f4<UINT32>
0x0040b55e:	pushl -28(%ebp)
0x0040b561:	call GetProcAddress@KERNEL32.dll
0x0040b563:	movl 0x1fc(%esi), %eax
0x0040b569:	movl 0x70(%esi), %edi
0x0040b56c:	movb 0xc8(%esi), $0x43<UINT8>
0x0040b573:	movb 0x14b(%esi), $0x43<UINT8>
0x0040b57a:	movl 0x68(%esi), $0x42a498<UINT32>
0x0040b581:	pushl $0xd<UINT8>
0x0040b583:	call 0x0040d265
0x0040d265:	movl %edi, %edi
0x0040d267:	pushl %ebp
0x0040d268:	movl %ebp, %esp
0x0040d26a:	movl %eax, 0x8(%ebp)
0x0040d26d:	pushl %esi
0x0040d26e:	leal %esi, 0x42ac30(,%eax,8)
0x0040d275:	cmpl (%esi), $0x0<UINT8>
0x0040d278:	jne 0x0040d28d
0x0040d28d:	pushl (%esi)
0x0040d28f:	call EnterCriticalSection@KERNEL32.dll
EnterCriticalSection@KERNEL32.dll: API Node	
0x0040d295:	popl %esi
0x0040d296:	popl %ebp
0x0040d297:	ret

0x0040b588:	popl %ecx
0x0040b589:	andl -4(%ebp), $0x0<UINT8>
0x0040b58d:	pushl 0x68(%esi)
0x0040b590:	call InterlockedIncrement@KERNEL32.dll
InterlockedIncrement@KERNEL32.dll: API Node	
0x0040b596:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040b59d:	call 0x0040b5e0
0x0040b5e0:	pushl $0xd<UINT8>
0x0040b5e2:	call 0x0040d173
0x0040d173:	movl %edi, %edi
0x0040d175:	pushl %ebp
0x0040d176:	movl %ebp, %esp
0x0040d178:	movl %eax, 0x8(%ebp)
0x0040d17b:	pushl 0x42ac30(,%eax,8)
0x0040d182:	call LeaveCriticalSection@KERNEL32.dll
LeaveCriticalSection@KERNEL32.dll: API Node	
0x0040d188:	popl %ebp
0x0040d189:	ret

0x0040b5e7:	popl %ecx
0x0040b5e8:	ret

0x0040b5a2:	pushl $0xc<UINT8>
0x0040b5a4:	call 0x0040d265
0x0040b5a9:	popl %ecx
0x0040b5aa:	movl -4(%ebp), %edi
0x0040b5ad:	movl %eax, 0xc(%ebp)
0x0040b5b0:	movl 0x6c(%esi), %eax
0x0040b5b3:	testl %eax, %eax
0x0040b5b5:	jne 8
0x0040b5b7:	movl %eax, 0x42aaa0
0x0040b5bc:	movl 0x6c(%esi), %eax
0x0040b5bf:	pushl 0x6c(%esi)
0x0040b5c2:	call 0x0040a1f9
0x0040a1f9:	movl %edi, %edi
0x0040a1fb:	pushl %ebp
0x0040a1fc:	movl %ebp, %esp
0x0040a1fe:	pushl %ebx
0x0040a1ff:	pushl %esi
0x0040a200:	movl %esi, 0x4221f4
0x0040a206:	pushl %edi
0x0040a207:	movl %edi, 0x8(%ebp)
0x0040a20a:	pushl %edi
0x0040a20b:	call InterlockedIncrement@KERNEL32.dll
0x0040a20d:	movl %eax, 0xb0(%edi)
0x0040a213:	testl %eax, %eax
0x0040a215:	je 0x0040a21a
0x0040a21a:	movl %eax, 0xb8(%edi)
0x0040a220:	testl %eax, %eax
0x0040a222:	je 0x0040a227
0x0040a227:	movl %eax, 0xb4(%edi)
0x0040a22d:	testl %eax, %eax
0x0040a22f:	je 0x0040a234
0x0040a234:	movl %eax, 0xc0(%edi)
0x0040a23a:	testl %eax, %eax
0x0040a23c:	je 0x0040a241
0x0040a241:	leal %ebx, 0x50(%edi)
0x0040a244:	movl 0x8(%ebp), $0x6<UINT32>
0x0040a24b:	cmpl -8(%ebx), $0x42a9c0<UINT32>
0x0040a252:	je 0x0040a25d
0x0040a254:	movl %eax, (%ebx)
0x0040a256:	testl %eax, %eax
0x0040a258:	je 0x0040a25d
0x0040a25d:	cmpl -4(%ebx), $0x0<UINT8>
0x0040a261:	je 0x0040a26d
0x0040a26d:	addl %ebx, $0x10<UINT8>
0x0040a270:	decl 0x8(%ebp)
0x0040a273:	jne 0x0040a24b
0x0040a275:	movl %eax, 0xd4(%edi)
0x0040a27b:	addl %eax, $0xb4<UINT32>
0x0040a280:	pushl %eax
0x0040a281:	call InterlockedIncrement@KERNEL32.dll
0x0040a283:	popl %edi
0x0040a284:	popl %esi
0x0040a285:	popl %ebx
0x0040a286:	popl %ebp
0x0040a287:	ret

0x0040b5c7:	popl %ecx
0x0040b5c8:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040b5cf:	call 0x0040b5e9
0x0040b5e9:	pushl $0xc<UINT8>
0x0040b5eb:	call 0x0040d173
0x0040b5f0:	popl %ecx
0x0040b5f1:	ret

0x0040b5d4:	call 0x0040e2fd
0x0040b5d9:	ret

0x0040b99e:	popl %ecx
0x0040b99f:	popl %ecx
0x0040b9a0:	call GetCurrentThreadId@KERNEL32.dll
0x0040b9a6:	orl 0x4(%esi), $0xffffffff<UINT8>
0x0040b9aa:	movl (%esi), %eax
0x0040b9ac:	xorl %eax, %eax
0x0040b9ae:	incl %eax
0x0040b9af:	jmp 0x0040b9b8
0x0040b9b8:	popl %edi
0x0040b9b9:	popl %esi
0x0040b9ba:	ret

0x00409872:	testl %eax, %eax
0x00409874:	jne 0x0040987e
0x0040987e:	call 0x00412b38
0x00412b38:	movl %edi, %edi
0x00412b3a:	pushl %esi
0x00412b3b:	movl %eax, $0x427b30<UINT32>
0x00412b40:	movl %esi, $0x427b30<UINT32>
0x00412b45:	pushl %edi
0x00412b46:	movl %edi, %eax
0x00412b48:	cmpl %eax, %esi
0x00412b4a:	jae 0x00412b5b
0x00412b5b:	popl %edi
0x00412b5c:	popl %esi
0x00412b5d:	ret

0x00409883:	andl -4(%ebp), $0x0<UINT8>
0x00409887:	call 0x0041163f
0x0041163f:	pushl $0x54<UINT8>
0x00411641:	pushl $0x427fa0<UINT32>
0x00411646:	call 0x0040e2b8
0x0041164b:	xorl %edi, %edi
0x0041164d:	movl -4(%ebp), %edi
0x00411650:	leal %eax, -100(%ebp)
0x00411653:	pushl %eax
0x00411654:	call GetStartupInfoA@KERNEL32.dll
GetStartupInfoA@KERNEL32.dll: API Node	
0x0041165a:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00411661:	pushl $0x40<UINT8>
0x00411663:	pushl $0x20<UINT8>
0x00411665:	popl %esi
0x00411666:	pushl %esi
0x00411667:	call 0x00411b6b
0x0041166c:	popl %ecx
0x0041166d:	popl %ecx
0x0041166e:	cmpl %eax, %edi
0x00411670:	je 532
0x00411676:	movl 0x42cb20, %eax
0x0041167b:	movl 0x42cb00, %esi
0x00411681:	leal %ecx, 0x800(%eax)
0x00411687:	jmp 0x004116b9
0x004116b9:	cmpl %eax, %ecx
0x004116bb:	jb 0x00411689
0x00411689:	movb 0x4(%eax), $0x0<UINT8>
0x0041168d:	orl (%eax), $0xffffffff<UINT8>
0x00411690:	movb 0x5(%eax), $0xa<UINT8>
0x00411694:	movl 0x8(%eax), %edi
0x00411697:	movb 0x24(%eax), $0x0<UINT8>
0x0041169b:	movb 0x25(%eax), $0xa<UINT8>
0x0041169f:	movb 0x26(%eax), $0xa<UINT8>
0x004116a3:	movl 0x38(%eax), %edi
0x004116a6:	movb 0x34(%eax), $0x0<UINT8>
0x004116aa:	addl %eax, $0x40<UINT8>
0x004116ad:	movl %ecx, 0x42cb20
0x004116b3:	addl %ecx, $0x800<UINT32>
0x004116bd:	cmpw -50(%ebp), %di
0x004116c1:	je 266
0x004116c7:	movl %eax, -48(%ebp)
0x004116ca:	cmpl %eax, %edi
0x004116cc:	je 255
0x004116d2:	movl %edi, (%eax)
0x004116d4:	leal %ebx, 0x4(%eax)
0x004116d7:	leal %eax, (%ebx,%edi)
0x004116da:	movl -28(%ebp), %eax
0x004116dd:	movl %esi, $0x800<UINT32>
0x004116e2:	cmpl %edi, %esi
0x004116e4:	jl 0x004116e8
0x004116e8:	movl -32(%ebp), $0x1<UINT32>
0x004116ef:	jmp 0x0041174c
0x0041174c:	cmpl 0x42cb00, %edi
0x00411752:	jl -99
0x00411754:	jmp 0x0041175c
0x0041175c:	andl -32(%ebp), $0x0<UINT8>
0x00411760:	testl %edi, %edi
0x00411762:	jle 0x004117d1
0x004117d1:	xorl %ebx, %ebx
0x004117d3:	movl %esi, %ebx
0x004117d5:	shll %esi, $0x6<UINT8>
0x004117d8:	addl %esi, 0x42cb20
0x004117de:	movl %eax, (%esi)
0x004117e0:	cmpl %eax, $0xffffffff<UINT8>
0x004117e3:	je 0x004117f0
0x004117f0:	movb 0x4(%esi), $0xffffff81<UINT8>
0x004117f4:	testl %ebx, %ebx
0x004117f6:	jne 0x004117fd
0x004117f8:	pushl $0xfffffff6<UINT8>
0x004117fa:	popl %eax
0x004117fb:	jmp 0x00411807
0x00411807:	pushl %eax
0x00411808:	call GetStdHandle@KERNEL32.dll
GetStdHandle@KERNEL32.dll: API Node	
0x0041180e:	movl %edi, %eax
0x00411810:	cmpl %edi, $0xffffffff<UINT8>
0x00411813:	je 67
0x00411815:	testl %edi, %edi
0x00411817:	je 63
0x00411819:	pushl %edi
0x0041181a:	call GetFileType@KERNEL32.dll
GetFileType@KERNEL32.dll: API Node	
0x00411820:	testl %eax, %eax
0x00411822:	je 52
0x00411824:	movl (%esi), %edi
0x00411826:	andl %eax, $0xff<UINT32>
0x0041182b:	cmpl %eax, $0x2<UINT8>
0x0041182e:	jne 6
0x00411830:	orb 0x4(%esi), $0x40<UINT8>
0x00411834:	jmp 0x0041183f
0x0041183f:	pushl $0xfa0<UINT32>
0x00411844:	leal %eax, 0xc(%esi)
0x00411847:	pushl %eax
0x00411848:	call 0x004135a0
0x0041184d:	popl %ecx
0x0041184e:	popl %ecx
0x0041184f:	testl %eax, %eax
0x00411851:	je 55
0x00411853:	incl 0x8(%esi)
0x00411856:	jmp 0x00411862
0x00411862:	incl %ebx
0x00411863:	cmpl %ebx, $0x3<UINT8>
0x00411866:	jl 0x004117d3
0x004117fd:	movl %eax, %ebx
0x004117ff:	decl %eax
0x00411800:	negl %eax
0x00411802:	sbbl %eax, %eax
0x00411804:	addl %eax, $0xfffffff5<UINT8>
0x0041186c:	pushl 0x42cb00
0x00411872:	call SetHandleCount@KERNEL32.dll
SetHandleCount@KERNEL32.dll: API Node	
0x00411878:	xorl %eax, %eax
0x0041187a:	jmp 0x0041188d
0x0041188d:	call 0x0040e2fd
0x00411892:	ret

0x0040988c:	testl %eax, %eax
0x0040988e:	jnl 0x00409898
0x00409898:	call GetCommandLineA@KERNEL32.dll
GetCommandLineA@KERNEL32.dll: API Node	
0x0040989e:	movl 0x42cc4c, %eax
0x004098a3:	call 0x00414350
0x00414350:	movl %edi, %edi
0x00414352:	pushl %ebp
0x00414353:	movl %ebp, %esp
0x00414355:	movl %eax, 0x42c6a8
0x0041435a:	subl %esp, $0xc<UINT8>
0x0041435d:	pushl %ebx
0x0041435e:	pushl %esi
0x0041435f:	movl %esi, 0x422108
0x00414365:	pushl %edi
0x00414366:	xorl %ebx, %ebx
0x00414368:	xorl %edi, %edi
0x0041436a:	cmpl %eax, %ebx
0x0041436c:	jne 46
0x0041436e:	call GetEnvironmentStringsW@KERNEL32.dll
GetEnvironmentStringsW@KERNEL32.dll: API Node	
0x00414370:	movl %edi, %eax
0x00414372:	cmpl %edi, %ebx
0x00414374:	je 12
0x00414376:	movl 0x42c6a8, $0x1<UINT32>
0x00414380:	jmp 0x004143a5
0x004143a5:	cmpl %edi, %ebx
0x004143a7:	jne 0x004143b8
0x004143b8:	movl %eax, %edi
0x004143ba:	cmpw (%edi), %bx
0x004143bd:	je 14
0x004143bf:	incl %eax
0x004143c0:	incl %eax
0x004143c1:	cmpw (%eax), %bx
0x004143c4:	jne 0x004143bf
0x004143c6:	incl %eax
0x004143c7:	incl %eax
0x004143c8:	cmpw (%eax), %bx
0x004143cb:	jne 0x004143bf
0x004143cd:	movl %esi, 0x4220dc
0x004143d3:	pushl %ebx
0x004143d4:	pushl %ebx
0x004143d5:	pushl %ebx
0x004143d6:	subl %eax, %edi
0x004143d8:	pushl %ebx
0x004143d9:	sarl %eax
0x004143db:	incl %eax
0x004143dc:	pushl %eax
0x004143dd:	pushl %edi
0x004143de:	pushl %ebx
0x004143df:	pushl %ebx
0x004143e0:	movl -12(%ebp), %eax
0x004143e3:	call WideCharToMultiByte@KERNEL32.dll
WideCharToMultiByte@KERNEL32.dll: API Node	
0x004143e5:	movl -8(%ebp), %eax
0x004143e8:	cmpl %eax, %ebx
0x004143ea:	je 47
0x004143ec:	pushl %eax
0x004143ed:	call 0x00411b26
0x00411b26:	movl %edi, %edi
0x00411b28:	pushl %ebp
0x00411b29:	movl %ebp, %esp
0x00411b2b:	pushl %esi
0x00411b2c:	pushl %edi
0x00411b2d:	xorl %esi, %esi
0x00411b2f:	pushl 0x8(%ebp)
0x00411b32:	call 0x004062f7
0x004062f7:	movl %edi, %edi
0x004062f9:	pushl %ebp
0x004062fa:	movl %ebp, %esp
0x004062fc:	pushl %esi
0x004062fd:	movl %esi, 0x8(%ebp)
0x00406300:	cmpl %esi, $0xffffffe0<UINT8>
0x00406303:	ja 0x004063aa
0x00406309:	pushl %ebx
0x0040630a:	pushl %edi
0x0040630b:	movl %edi, 0x4221b0
0x00406311:	cmpl 0x42bf1c, $0x0<UINT8>
0x00406318:	jne 0x00406332
0x00406332:	movl %eax, 0x42cc24
0x00406337:	cmpl %eax, $0x1<UINT8>
0x0040633a:	jne 14
0x0040633c:	testl %esi, %esi
0x0040633e:	je 0x00406344
0x00406340:	movl %eax, %esi
0x00406342:	jmp 0x00406347
0x00406347:	pushl %eax
0x00406348:	jmp 0x00406366
0x00406366:	pushl $0x0<UINT8>
0x00406368:	pushl 0x42bf1c
0x0040636e:	call HeapAlloc@KERNEL32.dll
0x00406370:	movl %ebx, %eax
0x00406372:	testl %ebx, %ebx
0x00406374:	jne 0x004063a4
0x004063a4:	popl %edi
0x004063a5:	movl %eax, %ebx
0x004063a7:	popl %ebx
0x004063a8:	jmp 0x004063be
0x004063be:	popl %esi
0x004063bf:	popl %ebp
0x004063c0:	ret

0x00411b37:	movl %edi, %eax
0x00411b39:	popl %ecx
0x00411b3a:	testl %edi, %edi
0x00411b3c:	jne 0x00411b65
0x00411b65:	movl %eax, %edi
0x00411b67:	popl %edi
0x00411b68:	popl %esi
0x00411b69:	popl %ebp
0x00411b6a:	ret

0x004143f2:	popl %ecx
0x004143f3:	movl -4(%ebp), %eax
0x004143f6:	cmpl %eax, %ebx
0x004143f8:	je 33
0x004143fa:	pushl %ebx
0x004143fb:	pushl %ebx
0x004143fc:	pushl -8(%ebp)
0x004143ff:	pushl %eax
0x00414400:	pushl -12(%ebp)
0x00414403:	pushl %edi
0x00414404:	pushl %ebx
0x00414405:	pushl %ebx
0x00414406:	call WideCharToMultiByte@KERNEL32.dll
0x00414408:	testl %eax, %eax
0x0041440a:	jne 0x00414418
0x00414418:	movl %ebx, -4(%ebp)
0x0041441b:	pushl %edi
0x0041441c:	call FreeEnvironmentStringsW@KERNEL32.dll
FreeEnvironmentStringsW@KERNEL32.dll: API Node	
0x00414422:	movl %eax, %ebx
0x00414424:	jmp 0x00414482
0x00414482:	popl %edi
0x00414483:	popl %esi
0x00414484:	popl %ebx
0x00414485:	leave
0x00414486:	ret

0x004098a8:	movl 0x42bd68, %eax
0x004098ad:	call 0x00414295
0x00414295:	movl %edi, %edi
0x00414297:	pushl %ebp
0x00414298:	movl %ebp, %esp
0x0041429a:	subl %esp, $0xc<UINT8>
0x0041429d:	pushl %ebx
0x0041429e:	xorl %ebx, %ebx
0x004142a0:	pushl %esi
0x004142a1:	pushl %edi
0x004142a2:	cmpl 0x42cc64, %ebx
0x004142a8:	jne 5
0x004142aa:	call 0x0040a062
0x0040a062:	cmpl 0x42cc64, $0x0<UINT8>
0x0040a069:	jne 0x0040a07d
0x0040a06b:	pushl $0xfffffffd<UINT8>
0x0040a06d:	call 0x00409ec8
0x00409ec8:	pushl $0x14<UINT8>
0x00409eca:	pushl $0x427e08<UINT32>
0x00409ecf:	call 0x0040e2b8
0x00409ed4:	orl -32(%ebp), $0xffffffff<UINT8>
0x00409ed8:	call 0x0040b66b
0x0040b66b:	movl %edi, %edi
0x0040b66d:	pushl %esi
0x0040b66e:	call 0x0040b5f2
0x0040b5f2:	movl %edi, %edi
0x0040b5f4:	pushl %esi
0x0040b5f5:	pushl %edi
0x0040b5f6:	call GetLastError@KERNEL32.dll
GetLastError@KERNEL32.dll: API Node	
0x0040b5fc:	pushl 0x42aab0
0x0040b602:	movl %edi, %eax
0x0040b604:	call 0x0040b47d
0x0040b47d:	movl %edi, %edi
0x0040b47f:	pushl %esi
0x0040b480:	pushl 0x42aab4
0x0040b486:	call TlsGetValue@KERNEL32.dll
0x0040b48c:	movl %esi, %eax
0x0040b48e:	testl %esi, %esi
0x0040b490:	jne 0x0040b4ad
0x0040b4ad:	movl %eax, %esi
0x0040b4af:	popl %esi
0x0040b4b0:	ret

0x0040b609:	call FlsGetValue@KERNEL32.DLL
0x0040b60b:	movl %esi, %eax
0x0040b60d:	testl %esi, %esi
0x0040b60f:	jne 0x0040b65f
0x0040b65f:	pushl %edi
0x0040b660:	call SetLastError@KERNEL32.dll
SetLastError@KERNEL32.dll: API Node	
0x0040b666:	popl %edi
0x0040b667:	movl %eax, %esi
0x0040b669:	popl %esi
0x0040b66a:	ret

0x0040b673:	movl %esi, %eax
0x0040b675:	testl %esi, %esi
0x0040b677:	jne 0x0040b681
0x0040b681:	movl %eax, %esi
0x0040b683:	popl %esi
0x0040b684:	ret

0x00409edd:	movl %edi, %eax
0x00409edf:	movl -36(%ebp), %edi
0x00409ee2:	call 0x00409b85
0x00409b85:	pushl $0xc<UINT8>
0x00409b87:	pushl $0x427de8<UINT32>
0x00409b8c:	call 0x0040e2b8
0x00409b91:	call 0x0040b66b
0x00409b96:	movl %edi, %eax
0x00409b98:	movl %eax, 0x42a9bc
0x00409b9d:	testl 0x70(%edi), %eax
0x00409ba0:	je 0x00409bbf
0x00409bbf:	pushl $0xd<UINT8>
0x00409bc1:	call 0x0040d265
0x00409bc6:	popl %ecx
0x00409bc7:	andl -4(%ebp), $0x0<UINT8>
0x00409bcb:	movl %esi, 0x68(%edi)
0x00409bce:	movl -28(%ebp), %esi
0x00409bd1:	cmpl %esi, 0x42a8c0
0x00409bd7:	je 0x00409c0f
0x00409c0f:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00409c16:	call 0x00409c20
0x00409c20:	pushl $0xd<UINT8>
0x00409c22:	call 0x0040d173
0x00409c27:	popl %ecx
0x00409c28:	ret

0x00409c1b:	jmp 0x00409bab
0x00409bab:	testl %esi, %esi
0x00409bad:	jne 0x00409bb7
0x00409bb7:	movl %eax, %esi
0x00409bb9:	call 0x0040e2fd
0x00409bbe:	ret

0x00409ee7:	movl %ebx, 0x68(%edi)
0x00409eea:	movl %esi, 0x8(%ebp)
0x00409eed:	call 0x00409c29
0x00409c29:	movl %edi, %edi
0x00409c2b:	pushl %ebp
0x00409c2c:	movl %ebp, %esp
0x00409c2e:	subl %esp, $0x10<UINT8>
0x00409c31:	pushl %ebx
0x00409c32:	xorl %ebx, %ebx
0x00409c34:	pushl %ebx
0x00409c35:	leal %ecx, -16(%ebp)
0x00409c38:	call 0x00405d34
0x00405d34:	movl %edi, %edi
0x00405d36:	pushl %ebp
0x00405d37:	movl %ebp, %esp
0x00405d39:	movl %eax, 0x8(%ebp)
0x00405d3c:	pushl %esi
0x00405d3d:	movl %esi, %ecx
0x00405d3f:	movb 0xc(%esi), $0x0<UINT8>
0x00405d43:	testl %eax, %eax
0x00405d45:	jne 0x00405daa
0x00405d47:	call 0x0040b66b
0x00405d4c:	movl 0x8(%esi), %eax
0x00405d4f:	movl %ecx, 0x6c(%eax)
0x00405d52:	movl (%esi), %ecx
0x00405d54:	movl %ecx, 0x68(%eax)
0x00405d57:	movl 0x4(%esi), %ecx
0x00405d5a:	movl %ecx, (%esi)
0x00405d5c:	cmpl %ecx, 0x42aaa0
0x00405d62:	je 0x00405d76
0x00405d76:	movl %eax, 0x4(%esi)
0x00405d79:	cmpl %eax, 0x42a8c0
0x00405d7f:	je 0x00405d97
0x00405d97:	movl %eax, 0x8(%esi)
0x00405d9a:	testb 0x70(%eax), $0x2<UINT8>
0x00405d9e:	jne 20
0x00405da0:	orl 0x70(%eax), $0x2<UINT8>
0x00405da4:	movb 0xc(%esi), $0x1<UINT8>
0x00405da8:	jmp 0x00405db4
0x00405db4:	movl %eax, %esi
0x00405db6:	popl %esi
0x00405db7:	popl %ebp
0x00405db8:	ret $0x4<UINT16>

0x00409c3d:	movl 0x42bd74, %ebx
0x00409c43:	cmpl %esi, $0xfffffffe<UINT8>
0x00409c46:	jne 0x00409c66
0x00409c66:	cmpl %esi, $0xfffffffd<UINT8>
0x00409c69:	jne 0x00409c7d
0x00409c6b:	movl 0x42bd74, $0x1<UINT32>
0x00409c75:	call GetACP@KERNEL32.dll
GetACP@KERNEL32.dll: API Node	
0x00409c7b:	jmp 0x00409c58
0x00409c58:	cmpb -4(%ebp), %bl
0x00409c5b:	je 69
0x00409c5d:	movl %ecx, -8(%ebp)
0x00409c60:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00409c64:	jmp 0x00409ca2
0x00409ca2:	popl %ebx
0x00409ca3:	leave
0x00409ca4:	ret

0x00409ef2:	movl 0x8(%ebp), %eax
0x00409ef5:	cmpl %eax, 0x4(%ebx)
0x00409ef8:	je 343
0x00409efe:	pushl $0x220<UINT32>
0x00409f03:	call 0x00411b26
0x00409f08:	popl %ecx
0x00409f09:	movl %ebx, %eax
0x00409f0b:	testl %ebx, %ebx
0x00409f0d:	je 326
0x00409f13:	movl %ecx, $0x88<UINT32>
0x00409f18:	movl %esi, 0x68(%edi)
0x00409f1b:	movl %edi, %ebx
0x00409f1d:	rep movsl %es:(%edi), %ds:(%esi)
0x00409f1f:	andl (%ebx), $0x0<UINT8>
0x00409f22:	pushl %ebx
0x00409f23:	pushl 0x8(%ebp)
0x00409f26:	call 0x00409ca5
0x00409ca5:	movl %edi, %edi
0x00409ca7:	pushl %ebp
0x00409ca8:	movl %ebp, %esp
0x00409caa:	subl %esp, $0x20<UINT8>
0x00409cad:	movl %eax, 0x42a1f0
0x00409cb2:	xorl %eax, %ebp
0x00409cb4:	movl -4(%ebp), %eax
0x00409cb7:	pushl %ebx
0x00409cb8:	movl %ebx, 0xc(%ebp)
0x00409cbb:	pushl %esi
0x00409cbc:	movl %esi, 0x8(%ebp)
0x00409cbf:	pushl %edi
0x00409cc0:	call 0x00409c29
0x00409c7d:	cmpl %esi, $0xfffffffc<UINT8>
0x00409c80:	jne 0x00409c94
0x00409c94:	cmpb -4(%ebp), %bl
0x00409c97:	je 7
0x00409c99:	movl %eax, -8(%ebp)
0x00409c9c:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x00409ca0:	movl %eax, %esi
0x00409cc5:	movl %edi, %eax
0x00409cc7:	xorl %esi, %esi
0x00409cc9:	movl 0x8(%ebp), %edi
0x00409ccc:	cmpl %edi, %esi
0x00409cce:	jne 0x00409cde
0x00409cde:	movl -28(%ebp), %esi
0x00409ce1:	xorl %eax, %eax
0x00409ce3:	cmpl 0x42a8c8(%eax), %edi
0x00409ce9:	je 145
0x00409cef:	incl -28(%ebp)
0x00409cf2:	addl %eax, $0x30<UINT8>
0x00409cf5:	cmpl %eax, $0xf0<UINT32>
0x00409cfa:	jb 0x00409ce3
0x00409cfc:	cmpl %edi, $0xfde8<UINT32>
0x00409d02:	je 368
0x00409d08:	cmpl %edi, $0xfde9<UINT32>
0x00409d0e:	je 356
0x00409d14:	movzwl %eax, %di
0x00409d17:	pushl %eax
0x00409d18:	call IsValidCodePage@KERNEL32.dll
IsValidCodePage@KERNEL32.dll: API Node	
0x00409d1e:	testl %eax, %eax
0x00409d20:	je 338
0x00409d26:	leal %eax, -24(%ebp)
0x00409d29:	pushl %eax
0x00409d2a:	pushl %edi
0x00409d2b:	call GetCPInfo@KERNEL32.dll
GetCPInfo@KERNEL32.dll: API Node	
0x00409d31:	testl %eax, %eax
0x00409d33:	je 307
0x00409d39:	pushl $0x101<UINT32>
0x00409d3e:	leal %eax, 0x1c(%ebx)
0x00409d41:	pushl %esi
0x00409d42:	pushl %eax
0x00409d43:	call 0x00407140
0x00407140:	movl %edx, 0xc(%esp)
0x00407144:	movl %ecx, 0x4(%esp)
0x00407148:	testl %edx, %edx
0x0040714a:	je 105
0x0040714c:	xorl %eax, %eax
0x0040714e:	movb %al, 0x8(%esp)
0x00407152:	testb %al, %al
0x00407154:	jne 22
0x00407156:	cmpl %edx, $0x100<UINT32>
0x0040715c:	jb 0x0040716c
0x0040715e:	cmpl 0x42cc20, $0x0<UINT8>
0x00407165:	je 0x0040716c
0x0040716c:	pushl %edi
0x0040716d:	movl %edi, %ecx
0x0040716f:	cmpl %edx, $0x4<UINT8>
0x00407172:	jb 49
0x00407174:	negl %ecx
0x00407176:	andl %ecx, $0x3<UINT8>
0x00407179:	je 0x00407187
0x00407187:	movl %ecx, %eax
0x00407189:	shll %eax, $0x8<UINT8>
0x0040718c:	addl %eax, %ecx
0x0040718e:	movl %ecx, %eax
0x00407190:	shll %eax, $0x10<UINT8>
0x00407193:	addl %eax, %ecx
0x00407195:	movl %ecx, %edx
0x00407197:	andl %edx, $0x3<UINT8>
0x0040719a:	shrl %ecx, $0x2<UINT8>
0x0040719d:	je 6
0x0040719f:	rep stosl %es:(%edi), %eax
0x004071a1:	testl %edx, %edx
0x004071a3:	je 0x004071af
0x004071a5:	movb (%edi), %al
0x004071a7:	addl %edi, $0x1<UINT8>
0x004071aa:	subl %edx, $0x1<UINT8>
0x004071ad:	jne -10
0x004071af:	movl %eax, 0x8(%esp)
0x004071b3:	popl %edi
0x004071b4:	ret

0x00409d48:	xorl %edx, %edx
0x00409d4a:	incl %edx
0x00409d4b:	addl %esp, $0xc<UINT8>
0x00409d4e:	movl 0x4(%ebx), %edi
0x00409d51:	movl 0xc(%ebx), %esi
0x00409d54:	cmpl -24(%ebp), %edx
0x00409d57:	jbe 248
0x00409d5d:	cmpb -18(%ebp), $0x0<UINT8>
0x00409d61:	je 0x00409e36
0x00409e36:	leal %eax, 0x1e(%ebx)
0x00409e39:	movl %ecx, $0xfe<UINT32>
0x00409e3e:	orb (%eax), $0x8<UINT8>
0x00409e41:	incl %eax
0x00409e42:	decl %ecx
0x00409e43:	jne 0x00409e3e
0x00409e45:	movl %eax, 0x4(%ebx)
0x00409e48:	call 0x0040995f
0x0040995f:	subl %eax, $0x3a4<UINT32>
0x00409964:	je 34
0x00409966:	subl %eax, $0x4<UINT8>
0x00409969:	je 23
0x0040996b:	subl %eax, $0xd<UINT8>
0x0040996e:	je 12
0x00409970:	decl %eax
0x00409971:	je 3
0x00409973:	xorl %eax, %eax
0x00409975:	ret

0x00409e4d:	movl 0xc(%ebx), %eax
0x00409e50:	movl 0x8(%ebx), %edx
0x00409e53:	jmp 0x00409e58
0x00409e58:	xorl %eax, %eax
0x00409e5a:	movzwl %ecx, %ax
0x00409e5d:	movl %eax, %ecx
0x00409e5f:	shll %ecx, $0x10<UINT8>
0x00409e62:	orl %eax, %ecx
0x00409e64:	leal %edi, 0x10(%ebx)
0x00409e67:	stosl %es:(%edi), %eax
0x00409e68:	stosl %es:(%edi), %eax
0x00409e69:	stosl %es:(%edi), %eax
0x00409e6a:	jmp 0x00409e14
0x00409e14:	movl %esi, %ebx
0x00409e16:	call 0x004099f2
0x004099f2:	movl %edi, %edi
0x004099f4:	pushl %ebp
0x004099f5:	movl %ebp, %esp
0x004099f7:	subl %esp, $0x51c<UINT32>
0x004099fd:	movl %eax, 0x42a1f0
0x00409a02:	xorl %eax, %ebp
0x00409a04:	movl -4(%ebp), %eax
0x00409a07:	pushl %ebx
0x00409a08:	pushl %edi
0x00409a09:	leal %eax, -1304(%ebp)
0x00409a0f:	pushl %eax
0x00409a10:	pushl 0x4(%esi)
0x00409a13:	call GetCPInfo@KERNEL32.dll
0x00409a19:	movl %edi, $0x100<UINT32>
0x00409a1e:	testl %eax, %eax
0x00409a20:	je 251
0x00409a26:	xorl %eax, %eax
0x00409a28:	movb -260(%ebp,%eax), %al
0x00409a2f:	incl %eax
0x00409a30:	cmpl %eax, %edi
0x00409a32:	jb 0x00409a28
0x00409a34:	movb %al, -1298(%ebp)
0x00409a3a:	movb -260(%ebp), $0x20<UINT8>
0x00409a41:	testb %al, %al
0x00409a43:	je 0x00409a73
0x00409a73:	pushl $0x0<UINT8>
0x00409a75:	pushl 0xc(%esi)
0x00409a78:	leal %eax, -1284(%ebp)
0x00409a7e:	pushl 0x4(%esi)
0x00409a81:	pushl %eax
0x00409a82:	pushl %edi
0x00409a83:	leal %eax, -260(%ebp)
0x00409a89:	pushl %eax
0x00409a8a:	pushl $0x1<UINT8>
0x00409a8c:	pushl $0x0<UINT8>
0x00409a8e:	call 0x004146d7
0x004146d7:	movl %edi, %edi
0x004146d9:	pushl %ebp
0x004146da:	movl %ebp, %esp
0x004146dc:	subl %esp, $0x10<UINT8>
0x004146df:	pushl 0x8(%ebp)
0x004146e2:	leal %ecx, -16(%ebp)
0x004146e5:	call 0x00405d34
0x004146ea:	pushl 0x24(%ebp)
0x004146ed:	leal %ecx, -16(%ebp)
0x004146f0:	pushl 0x20(%ebp)
0x004146f3:	pushl 0x1c(%ebp)
0x004146f6:	pushl 0x18(%ebp)
0x004146f9:	pushl 0x14(%ebp)
0x004146fc:	pushl 0x10(%ebp)
0x004146ff:	pushl 0xc(%ebp)
0x00414702:	call 0x0041451d
0x0041451d:	movl %edi, %edi
0x0041451f:	pushl %ebp
0x00414520:	movl %ebp, %esp
0x00414522:	pushl %ecx
0x00414523:	pushl %ecx
0x00414524:	movl %eax, 0x42a1f0
0x00414529:	xorl %eax, %ebp
0x0041452b:	movl -4(%ebp), %eax
0x0041452e:	movl %eax, 0x42c6ac
0x00414533:	pushl %ebx
0x00414534:	pushl %esi
0x00414535:	xorl %ebx, %ebx
0x00414537:	pushl %edi
0x00414538:	movl %edi, %ecx
0x0041453a:	cmpl %eax, %ebx
0x0041453c:	jne 58
0x0041453e:	leal %eax, -8(%ebp)
0x00414541:	pushl %eax
0x00414542:	xorl %esi, %esi
0x00414544:	incl %esi
0x00414545:	pushl %esi
0x00414546:	pushl $0x426768<UINT32>
0x0041454b:	pushl %esi
0x0041454c:	call GetStringTypeW@KERNEL32.dll
GetStringTypeW@KERNEL32.dll: API Node	
0x00414552:	testl %eax, %eax
0x00414554:	je 8
0x00414556:	movl 0x42c6ac, %esi
0x0041455c:	jmp 0x00414592
0x00414592:	movl -8(%ebp), %ebx
0x00414595:	cmpl 0x18(%ebp), %ebx
0x00414598:	jne 0x004145a2
0x004145a2:	movl %esi, 0x42224c
0x004145a8:	xorl %eax, %eax
0x004145aa:	cmpl 0x20(%ebp), %ebx
0x004145ad:	pushl %ebx
0x004145ae:	pushl %ebx
0x004145af:	pushl 0x10(%ebp)
0x004145b2:	setne %al
0x004145b5:	pushl 0xc(%ebp)
0x004145b8:	leal %eax, 0x1(,%eax,8)
0x004145bf:	pushl %eax
0x004145c0:	pushl 0x18(%ebp)
0x004145c3:	call MultiByteToWideChar@KERNEL32.dll
MultiByteToWideChar@KERNEL32.dll: API Node	
0x004145c5:	movl %edi, %eax
0x004145c7:	cmpl %edi, %ebx
0x004145c9:	je 171
0x004145cf:	jle 60
0x004145d1:	cmpl %edi, $0x7ffffff0<UINT32>
0x004145d7:	ja 52
0x004145d9:	leal %eax, 0x8(%edi,%edi)
0x004145dd:	cmpl %eax, $0x400<UINT32>
0x004145e2:	ja 19
0x004145e4:	call 0x00409510
0x00409510:	pushl %ecx
0x00409511:	leal %ecx, 0x8(%esp)
0x00409515:	subl %ecx, %eax
0x00409517:	andl %ecx, $0xf<UINT8>
0x0040951a:	addl %eax, %ecx
0x0040951c:	sbbl %ecx, %ecx
0x0040951e:	orl %eax, %ecx
0x00409520:	popl %ecx
0x00409521:	jmp 0x00406f50
0x00406f50:	pushl %ecx
0x00406f51:	leal %ecx, 0x4(%esp)
0x00406f55:	subl %ecx, %eax
0x00406f57:	sbbl %eax, %eax
0x00406f59:	notl %eax
0x00406f5b:	andl %ecx, %eax
0x00406f5d:	movl %eax, %esp
0x00406f5f:	andl %eax, $0xfffff000<UINT32>
0x00406f64:	cmpl %ecx, %eax
0x00406f66:	jb 0x00406f72
0x00406f68:	movl %eax, %ecx
0x00406f6a:	popl %ecx
0x00406f6b:	xchgl %esp, %eax
0x00406f6c:	movl %eax, (%eax)
0x00406f6e:	movl (%esp), %eax
0x00406f71:	ret

0x004145e9:	movl %eax, %esp
0x004145eb:	cmpl %eax, %ebx
0x004145ed:	je 28
0x004145ef:	movl (%eax), $0xcccc<UINT32>
0x004145f5:	jmp 0x00414608
0x00414608:	addl %eax, $0x8<UINT8>
0x0041460b:	movl %ebx, %eax
0x0041460d:	testl %ebx, %ebx
0x0041460f:	je 105
0x00414611:	leal %eax, (%edi,%edi)
0x00414614:	pushl %eax
0x00414615:	pushl $0x0<UINT8>
0x00414617:	pushl %ebx
0x00414618:	call 0x00407140
0x0041461d:	addl %esp, $0xc<UINT8>
0x00414620:	pushl %edi
0x00414621:	pushl %ebx
0x00414622:	pushl 0x10(%ebp)
0x00414625:	pushl 0xc(%ebp)
0x00414628:	pushl $0x1<UINT8>
0x0041462a:	pushl 0x18(%ebp)
0x0041462d:	call MultiByteToWideChar@KERNEL32.dll
0x0041462f:	testl %eax, %eax
0x00414631:	je 17
0x00414633:	pushl 0x14(%ebp)
0x00414636:	pushl %eax
0x00414637:	pushl %ebx
0x00414638:	pushl 0x8(%ebp)
0x0041463b:	call GetStringTypeW@KERNEL32.dll
0x00414641:	movl -8(%ebp), %eax
0x00414644:	pushl %ebx
0x00414645:	call 0x004071d0
0x004071d0:	movl %edi, %edi
0x004071d2:	pushl %ebp
0x004071d3:	movl %ebp, %esp
0x004071d5:	movl %eax, 0x8(%ebp)
0x004071d8:	testl %eax, %eax
0x004071da:	je 18
0x004071dc:	subl %eax, $0x8<UINT8>
0x004071df:	cmpl (%eax), $0xdddd<UINT32>
0x004071e5:	jne 0x004071ee
0x004071ee:	popl %ebp
0x004071ef:	ret

0x0041464a:	movl %eax, -8(%ebp)
0x0041464d:	popl %ecx
0x0041464e:	jmp 0x004146c5
0x004146c5:	leal %esp, -20(%ebp)
0x004146c8:	popl %edi
0x004146c9:	popl %esi
0x004146ca:	popl %ebx
0x004146cb:	movl %ecx, -4(%ebp)
0x004146ce:	xorl %ecx, %ebp
0x004146d0:	call 0x00406f3e
0x00406f3e:	cmpl %ecx, 0x42a1f0
0x00406f44:	jne 2
0x00406f46:	rep ret

0x004146d5:	leave
0x004146d6:	ret

0x00414707:	addl %esp, $0x1c<UINT8>
0x0041470a:	cmpb -4(%ebp), $0x0<UINT8>
0x0041470e:	je 7
0x00414710:	movl %ecx, -8(%ebp)
0x00414713:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00414717:	leave
0x00414718:	ret

0x00409a93:	xorl %ebx, %ebx
0x00409a95:	pushl %ebx
0x00409a96:	pushl 0x4(%esi)
0x00409a99:	leal %eax, -516(%ebp)
0x00409a9f:	pushl %edi
0x00409aa0:	pushl %eax
0x00409aa1:	pushl %edi
0x00409aa2:	leal %eax, -260(%ebp)
0x00409aa8:	pushl %eax
0x00409aa9:	pushl %edi
0x00409aaa:	pushl 0xc(%esi)
0x00409aad:	pushl %ebx
0x00409aae:	call 0x004115dd
0x004115dd:	movl %edi, %edi
0x004115df:	pushl %ebp
0x004115e0:	movl %ebp, %esp
0x004115e2:	subl %esp, $0x10<UINT8>
0x004115e5:	pushl 0x8(%ebp)
0x004115e8:	leal %ecx, -16(%ebp)
0x004115eb:	call 0x00405d34
0x004115f0:	pushl 0x28(%ebp)
0x004115f3:	leal %ecx, -16(%ebp)
0x004115f6:	pushl 0x24(%ebp)
0x004115f9:	pushl 0x20(%ebp)
0x004115fc:	pushl 0x1c(%ebp)
0x004115ff:	pushl 0x18(%ebp)
0x00411602:	pushl 0x14(%ebp)
0x00411605:	pushl 0x10(%ebp)
0x00411608:	pushl 0xc(%ebp)
0x0041160b:	call 0x00411238
0x00411238:	movl %edi, %edi
0x0041123a:	pushl %ebp
0x0041123b:	movl %ebp, %esp
0x0041123d:	subl %esp, $0x14<UINT8>
0x00411240:	movl %eax, 0x42a1f0
0x00411245:	xorl %eax, %ebp
0x00411247:	movl -4(%ebp), %eax
0x0041124a:	pushl %ebx
0x0041124b:	pushl %esi
0x0041124c:	xorl %ebx, %ebx
0x0041124e:	pushl %edi
0x0041124f:	movl %esi, %ecx
0x00411251:	cmpl 0x42c56c, %ebx
0x00411257:	jne 0x00411291
0x00411259:	pushl %ebx
0x0041125a:	pushl %ebx
0x0041125b:	xorl %edi, %edi
0x0041125d:	incl %edi
0x0041125e:	pushl %edi
0x0041125f:	pushl $0x426768<UINT32>
0x00411264:	pushl $0x100<UINT32>
0x00411269:	pushl %ebx
0x0041126a:	call LCMapStringW@KERNEL32.dll
LCMapStringW@KERNEL32.dll: API Node	
0x00411270:	testl %eax, %eax
0x00411272:	je 8
0x00411274:	movl 0x42c56c, %edi
0x0041127a:	jmp 0x00411291
0x00411291:	cmpl 0x14(%ebp), %ebx
0x00411294:	jle 0x004112b8
0x00411296:	movl %ecx, 0x14(%ebp)
0x00411299:	movl %eax, 0x10(%ebp)
0x0041129c:	decl %ecx
0x0041129d:	cmpb (%eax), %bl
0x0041129f:	je 8
0x004112a1:	incl %eax
0x004112a2:	cmpl %ecx, %ebx
0x004112a4:	jne 0x0041129c
0x004112a6:	orl %ecx, $0xffffffff<UINT8>
0x004112a9:	movl %eax, 0x14(%ebp)
0x004112ac:	subl %eax, %ecx
0x004112ae:	decl %eax
0x004112af:	cmpl %eax, 0x14(%ebp)
0x004112b2:	jnl 0x004112b5
0x004112b5:	movl 0x14(%ebp), %eax
0x004112b8:	movl %eax, 0x42c56c
0x004112bd:	cmpl %eax, $0x2<UINT8>
0x004112c0:	je 428
0x004112c6:	cmpl %eax, %ebx
0x004112c8:	je 420
0x004112ce:	cmpl %eax, $0x1<UINT8>
0x004112d1:	jne 460
0x004112d7:	movl -8(%ebp), %ebx
0x004112da:	cmpl 0x20(%ebp), %ebx
0x004112dd:	jne 0x004112e7
0x004112e7:	movl %esi, 0x42224c
0x004112ed:	xorl %eax, %eax
0x004112ef:	cmpl 0x24(%ebp), %ebx
0x004112f2:	pushl %ebx
0x004112f3:	pushl %ebx
0x004112f4:	pushl 0x14(%ebp)
0x004112f7:	setne %al
0x004112fa:	pushl 0x10(%ebp)
0x004112fd:	leal %eax, 0x1(,%eax,8)
0x00411304:	pushl %eax
0x00411305:	pushl 0x20(%ebp)
0x00411308:	call MultiByteToWideChar@KERNEL32.dll
0x0041130a:	movl %edi, %eax
0x0041130c:	cmpl %edi, %ebx
0x0041130e:	je 0x004114a3
0x00411314:	jle 67
0x00411316:	pushl $0xffffffe0<UINT8>
0x00411318:	xorl %edx, %edx
0x0041131a:	popl %eax
0x0041131b:	divl %eax, %edi
0x0041131d:	cmpl %eax, $0x2<UINT8>
0x00411320:	jb 55
0x00411322:	leal %eax, 0x8(%edi,%edi)
0x00411326:	cmpl %eax, $0x400<UINT32>
0x0041132b:	ja 19
0x0041132d:	call 0x00409510
0x00411332:	movl %eax, %esp
0x00411334:	cmpl %eax, %ebx
0x00411336:	je 28
0x00411338:	movl (%eax), $0xcccc<UINT32>
0x0041133e:	jmp 0x00411351
0x00411351:	addl %eax, $0x8<UINT8>
0x00411354:	movl -12(%ebp), %eax
0x00411357:	jmp 0x0041135c
0x0041135c:	cmpl -12(%ebp), %ebx
0x0041135f:	je 318
0x00411365:	pushl %edi
0x00411366:	pushl -12(%ebp)
0x00411369:	pushl 0x14(%ebp)
0x0041136c:	pushl 0x10(%ebp)
0x0041136f:	pushl $0x1<UINT8>
0x00411371:	pushl 0x20(%ebp)
0x00411374:	call MultiByteToWideChar@KERNEL32.dll
0x00411376:	testl %eax, %eax
0x00411378:	je 227
0x0041137e:	movl %esi, 0x422250
0x00411384:	pushl %ebx
0x00411385:	pushl %ebx
0x00411386:	pushl %edi
0x00411387:	pushl -12(%ebp)
0x0041138a:	pushl 0xc(%ebp)
0x0041138d:	pushl 0x8(%ebp)
0x00411390:	call LCMapStringW@KERNEL32.dll
0x00411392:	movl %ecx, %eax
0x00411394:	movl -8(%ebp), %ecx
0x00411397:	cmpl %ecx, %ebx
0x00411399:	je 194
0x0041139f:	testl 0xc(%ebp), $0x400<UINT32>
0x004113a6:	je 0x004113d1
0x004113d1:	cmpl %ecx, %ebx
0x004113d3:	jle 69
0x004113d5:	pushl $0xffffffe0<UINT8>
0x004113d7:	xorl %edx, %edx
0x004113d9:	popl %eax
0x004113da:	divl %eax, %ecx
0x004113dc:	cmpl %eax, $0x2<UINT8>
0x004113df:	jb 57
0x004113e1:	leal %eax, 0x8(%ecx,%ecx)
0x004113e5:	cmpl %eax, $0x400<UINT32>
0x004113ea:	ja 22
0x004113ec:	call 0x00409510
0x004113f1:	movl %esi, %esp
0x004113f3:	cmpl %esi, %ebx
0x004113f5:	je 106
0x004113f7:	movl (%esi), $0xcccc<UINT32>
0x004113fd:	addl %esi, $0x8<UINT8>
0x00411400:	jmp 0x0041141c
0x0041141c:	cmpl %esi, %ebx
0x0041141e:	je 65
0x00411420:	pushl -8(%ebp)
0x00411423:	pushl %esi
0x00411424:	pushl %edi
0x00411425:	pushl -12(%ebp)
0x00411428:	pushl 0xc(%ebp)
0x0041142b:	pushl 0x8(%ebp)
0x0041142e:	call LCMapStringW@KERNEL32.dll
0x00411434:	testl %eax, %eax
0x00411436:	je 34
0x00411438:	pushl %ebx
0x00411439:	pushl %ebx
0x0041143a:	cmpl 0x1c(%ebp), %ebx
0x0041143d:	jne 0x00411443
0x00411443:	pushl 0x1c(%ebp)
0x00411446:	pushl 0x18(%ebp)
0x00411449:	pushl -8(%ebp)
0x0041144c:	pushl %esi
0x0041144d:	pushl %ebx
0x0041144e:	pushl 0x20(%ebp)
0x00411451:	call WideCharToMultiByte@KERNEL32.dll
0x00411457:	movl -8(%ebp), %eax
0x0041145a:	pushl %esi
0x0041145b:	call 0x004071d0
0x00411460:	popl %ecx
0x00411461:	pushl -12(%ebp)
0x00411464:	call 0x004071d0
0x00411469:	movl %eax, -8(%ebp)
0x0041146c:	popl %ecx
0x0041146d:	jmp 0x004115cb
0x004115cb:	leal %esp, -32(%ebp)
0x004115ce:	popl %edi
0x004115cf:	popl %esi
0x004115d0:	popl %ebx
0x004115d1:	movl %ecx, -4(%ebp)
0x004115d4:	xorl %ecx, %ebp
0x004115d6:	call 0x00406f3e
0x004115db:	leave
0x004115dc:	ret

0x00411610:	addl %esp, $0x20<UINT8>
0x00411613:	cmpb -4(%ebp), $0x0<UINT8>
0x00411617:	je 7
0x00411619:	movl %ecx, -8(%ebp)
0x0041161c:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00411620:	leave
0x00411621:	ret

0x00409ab3:	addl %esp, $0x44<UINT8>
0x00409ab6:	pushl %ebx
0x00409ab7:	pushl 0x4(%esi)
0x00409aba:	leal %eax, -772(%ebp)
0x00409ac0:	pushl %edi
0x00409ac1:	pushl %eax
0x00409ac2:	pushl %edi
0x00409ac3:	leal %eax, -260(%ebp)
0x00409ac9:	pushl %eax
0x00409aca:	pushl $0x200<UINT32>
0x00409acf:	pushl 0xc(%esi)
0x00409ad2:	pushl %ebx
0x00409ad3:	call 0x004115dd
0x004114a3:	xorl %eax, %eax
0x004114a5:	jmp 0x004115cb
0x00409ad8:	addl %esp, $0x24<UINT8>
0x00409adb:	xorl %eax, %eax
0x00409add:	movzwl %ecx, -1284(%ebp,%eax,2)
0x00409ae5:	testb %cl, $0x1<UINT8>
0x00409ae8:	je 0x00409af8
0x00409af8:	testb %cl, $0x2<UINT8>
0x00409afb:	je 0x00409b12
0x00409b12:	movb 0x11d(%esi,%eax), $0x0<UINT8>
0x00409b1a:	incl %eax
0x00409b1b:	cmpl %eax, %edi
0x00409b1d:	jb -66
0x00409b1f:	jmp 0x00409b77
0x00409b77:	movl %ecx, -4(%ebp)
0x00409b7a:	popl %edi
0x00409b7b:	xorl %ecx, %ebp
0x00409b7d:	popl %ebx
0x00409b7e:	call 0x00406f3e
0x00409b83:	leave
0x00409b84:	ret

0x00409e1b:	jmp 0x00409cd7
0x00409cd7:	xorl %eax, %eax
0x00409cd9:	jmp 0x00409e7b
0x00409e7b:	movl %ecx, -4(%ebp)
0x00409e7e:	popl %edi
0x00409e7f:	popl %esi
0x00409e80:	xorl %ecx, %ebp
0x00409e82:	popl %ebx
0x00409e83:	call 0x00406f3e
0x00409e88:	leave
0x00409e89:	ret

0x00409f2b:	popl %ecx
0x00409f2c:	popl %ecx
0x00409f2d:	movl -32(%ebp), %eax
0x00409f30:	testl %eax, %eax
0x00409f32:	jne 252
0x00409f38:	movl %esi, -36(%ebp)
0x00409f3b:	pushl 0x68(%esi)
0x00409f3e:	call InterlockedDecrement@KERNEL32.dll
InterlockedDecrement@KERNEL32.dll: API Node	
0x00409f44:	testl %eax, %eax
0x00409f46:	jne 17
0x00409f48:	movl %eax, 0x68(%esi)
0x00409f4b:	cmpl %eax, $0x42a498<UINT32>
0x00409f50:	je 0x00409f59
0x00409f59:	movl 0x68(%esi), %ebx
0x00409f5c:	pushl %ebx
0x00409f5d:	movl %edi, 0x4221f4
0x00409f63:	call InterlockedIncrement@KERNEL32.dll
0x00409f65:	testb 0x70(%esi), $0x2<UINT8>
0x00409f69:	jne 234
0x00409f6f:	testb 0x42a9bc, $0x1<UINT8>
0x00409f76:	jne 221
0x00409f7c:	pushl $0xd<UINT8>
0x00409f7e:	call 0x0040d265
0x00409f83:	popl %ecx
0x00409f84:	andl -4(%ebp), $0x0<UINT8>
0x00409f88:	movl %eax, 0x4(%ebx)
0x00409f8b:	movl 0x42bd84, %eax
0x00409f90:	movl %eax, 0x8(%ebx)
0x00409f93:	movl 0x42bd88, %eax
0x00409f98:	movl %eax, 0xc(%ebx)
0x00409f9b:	movl 0x42bd8c, %eax
0x00409fa0:	xorl %eax, %eax
0x00409fa2:	movl -28(%ebp), %eax
0x00409fa5:	cmpl %eax, $0x5<UINT8>
0x00409fa8:	jnl 0x00409fba
0x00409faa:	movw %cx, 0x10(%ebx,%eax,2)
0x00409faf:	movw 0x42bd78(,%eax,2), %cx
0x00409fb7:	incl %eax
0x00409fb8:	jmp 0x00409fa2
0x00409fba:	xorl %eax, %eax
0x00409fbc:	movl -28(%ebp), %eax
0x00409fbf:	cmpl %eax, $0x101<UINT32>
0x00409fc4:	jnl 0x00409fd3
0x00409fc6:	movb %cl, 0x1c(%eax,%ebx)
0x00409fca:	movb 0x42a6b8(%eax), %cl
0x00409fd0:	incl %eax
0x00409fd1:	jmp 0x00409fbc
0x00409fd3:	xorl %eax, %eax
0x00409fd5:	movl -28(%ebp), %eax
0x00409fd8:	cmpl %eax, $0x100<UINT32>
0x00409fdd:	jnl 0x00409fef
0x00409fdf:	movb %cl, 0x11d(%eax,%ebx)
0x00409fe6:	movb 0x42a7c0(%eax), %cl
0x00409fec:	incl %eax
0x00409fed:	jmp 0x00409fd5
0x00409fef:	pushl 0x42a8c0
0x00409ff5:	call InterlockedDecrement@KERNEL32.dll
0x00409ffb:	testl %eax, %eax
0x00409ffd:	jne 0x0040a012
0x0040a012:	movl 0x42a8c0, %ebx
0x0040a018:	pushl %ebx
0x0040a019:	call InterlockedIncrement@KERNEL32.dll
0x0040a01b:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040a022:	call 0x0040a029
0x0040a029:	pushl $0xd<UINT8>
0x0040a02b:	call 0x0040d173
0x0040a030:	popl %ecx
0x0040a031:	ret

0x0040a027:	jmp 0x0040a059
0x0040a059:	movl %eax, -32(%ebp)
0x0040a05c:	call 0x0040e2fd
0x0040a061:	ret

0x0040a072:	popl %ecx
0x0040a073:	movl 0x42cc64, $0x1<UINT32>
0x0040a07d:	xorl %eax, %eax
0x0040a07f:	ret

0x004142af:	pushl $0x104<UINT32>
0x004142b4:	movl %esi, $0x42c5a0<UINT32>
0x004142b9:	pushl %esi
0x004142ba:	pushl %ebx
0x004142bb:	movb 0x42c6a4, %bl
0x004142c1:	call GetModuleFileNameA@KERNEL32.dll
GetModuleFileNameA@KERNEL32.dll: API Node	
0x004142c7:	movl %eax, 0x42cc4c
0x004142cc:	movl 0x42bd54, %esi
0x004142d2:	cmpl %eax, %ebx
0x004142d4:	je 7
0x004142d6:	movl -4(%ebp), %eax
0x004142d9:	cmpb (%eax), %bl
0x004142db:	jne 0x004142e0
0x004142e0:	movl %edx, -4(%ebp)
0x004142e3:	leal %eax, -8(%ebp)
0x004142e6:	pushl %eax
0x004142e7:	pushl %ebx
0x004142e8:	pushl %ebx
0x004142e9:	leal %edi, -12(%ebp)
0x004142ec:	call 0x004140fb
0x004140fb:	movl %edi, %edi
0x004140fd:	pushl %ebp
0x004140fe:	movl %ebp, %esp
0x00414100:	pushl %ecx
0x00414101:	movl %ecx, 0x10(%ebp)
0x00414104:	pushl %ebx
0x00414105:	xorl %eax, %eax
0x00414107:	pushl %esi
0x00414108:	movl (%edi), %eax
0x0041410a:	movl %esi, %edx
0x0041410c:	movl %edx, 0xc(%ebp)
0x0041410f:	movl (%ecx), $0x1<UINT32>
0x00414115:	cmpl 0x8(%ebp), %eax
0x00414118:	je 0x00414123
0x00414123:	movl -4(%ebp), %eax
0x00414126:	cmpb (%esi), $0x22<UINT8>
0x00414129:	jne 0x0041413b
0x0041412b:	xorl %eax, %eax
0x0041412d:	cmpl -4(%ebp), %eax
0x00414130:	movb %bl, $0x22<UINT8>
0x00414132:	sete %al
0x00414135:	incl %esi
0x00414136:	movl -4(%ebp), %eax
0x00414139:	jmp 0x00414177
0x00414177:	cmpl -4(%ebp), $0x0<UINT8>
0x0041417b:	jne 0x00414126
0x0041413b:	incl (%edi)
0x0041413d:	testl %edx, %edx
0x0041413f:	je 0x00414149
0x00414149:	movb %bl, (%esi)
0x0041414b:	movzbl %eax, %bl
0x0041414e:	pushl %eax
0x0041414f:	incl %esi
0x00414150:	call 0x0041f2e3
0x0041f2e3:	movl %edi, %edi
0x0041f2e5:	pushl %ebp
0x0041f2e6:	movl %ebp, %esp
0x0041f2e8:	pushl $0x4<UINT8>
0x0041f2ea:	pushl $0x0<UINT8>
0x0041f2ec:	pushl 0x8(%ebp)
0x0041f2ef:	pushl $0x0<UINT8>
0x0041f2f1:	call 0x0041f0d7
0x0041f0d7:	movl %edi, %edi
0x0041f0d9:	pushl %ebp
0x0041f0da:	movl %ebp, %esp
0x0041f0dc:	subl %esp, $0x10<UINT8>
0x0041f0df:	pushl 0x8(%ebp)
0x0041f0e2:	leal %ecx, -16(%ebp)
0x0041f0e5:	call 0x00405d34
0x0041f0ea:	movzbl %eax, 0xc(%ebp)
0x0041f0ee:	movl %ecx, -12(%ebp)
0x0041f0f1:	movb %dl, 0x14(%ebp)
0x0041f0f4:	testb 0x1d(%ecx,%eax), %dl
0x0041f0f8:	jne 30
0x0041f0fa:	cmpl 0x10(%ebp), $0x0<UINT8>
0x0041f0fe:	je 0x0041f112
0x0041f112:	xorl %eax, %eax
0x0041f114:	testl %eax, %eax
0x0041f116:	je 0x0041f11b
0x0041f11b:	cmpb -4(%ebp), $0x0<UINT8>
0x0041f11f:	je 7
0x0041f121:	movl %ecx, -8(%ebp)
0x0041f124:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0041f128:	leave
0x0041f129:	ret

0x0041f2f6:	addl %esp, $0x10<UINT8>
0x0041f2f9:	popl %ebp
0x0041f2fa:	ret

0x00414155:	popl %ecx
0x00414156:	testl %eax, %eax
0x00414158:	je 0x0041416d
0x0041416d:	movl %edx, 0xc(%ebp)
0x00414170:	movl %ecx, 0x10(%ebp)
0x00414173:	testb %bl, %bl
0x00414175:	je 0x004141a9
0x0041417d:	cmpb %bl, $0x20<UINT8>
0x00414180:	je 5
0x00414182:	cmpb %bl, $0x9<UINT8>
0x00414185:	jne 0x00414126
0x004141a9:	decl %esi
0x004141aa:	jmp 0x0041418f
0x0041418f:	andl -4(%ebp), $0x0<UINT8>
0x00414193:	cmpb (%esi), $0x0<UINT8>
0x00414196:	je 0x00414285
0x00414285:	movl %eax, 0x8(%ebp)
0x00414288:	popl %esi
0x00414289:	popl %ebx
0x0041428a:	testl %eax, %eax
0x0041428c:	je 0x00414291
0x00414291:	incl (%ecx)
0x00414293:	leave
0x00414294:	ret

0x004142f1:	movl %eax, -8(%ebp)
0x004142f4:	addl %esp, $0xc<UINT8>
0x004142f7:	cmpl %eax, $0x3fffffff<UINT32>
0x004142fc:	jae 74
0x004142fe:	movl %ecx, -12(%ebp)
0x00414301:	cmpl %ecx, $0xffffffff<UINT8>
0x00414304:	jae 66
0x00414306:	movl %edi, %eax
0x00414308:	shll %edi, $0x2<UINT8>
0x0041430b:	leal %eax, (%edi,%ecx)
0x0041430e:	cmpl %eax, %ecx
0x00414310:	jb 54
0x00414312:	pushl %eax
0x00414313:	call 0x00411b26
0x00414318:	movl %esi, %eax
0x0041431a:	popl %ecx
0x0041431b:	cmpl %esi, %ebx
0x0041431d:	je 41
0x0041431f:	movl %edx, -4(%ebp)
0x00414322:	leal %eax, -8(%ebp)
0x00414325:	pushl %eax
0x00414326:	addl %edi, %esi
0x00414328:	pushl %edi
0x00414329:	pushl %esi
0x0041432a:	leal %edi, -12(%ebp)
0x0041432d:	call 0x004140fb
0x0041411a:	movl %ebx, 0x8(%ebp)
0x0041411d:	addl 0x8(%ebp), $0x4<UINT8>
0x00414121:	movl (%ebx), %edx
0x00414141:	movb %al, (%esi)
0x00414143:	movb (%edx), %al
0x00414145:	incl %edx
0x00414146:	movl 0xc(%ebp), %edx
0x0041428e:	andl (%eax), $0x0<UINT8>
0x00414332:	movl %eax, -8(%ebp)
0x00414335:	addl %esp, $0xc<UINT8>
0x00414338:	decl %eax
0x00414339:	movl 0x42bd38, %eax
0x0041433e:	movl 0x42bd3c, %esi
0x00414344:	xorl %eax, %eax
0x00414346:	jmp 0x0041434b
0x0041434b:	popl %edi
0x0041434c:	popl %esi
0x0041434d:	popl %ebx
0x0041434e:	leave
0x0041434f:	ret

0x004098b2:	testl %eax, %eax
0x004098b4:	jnl 0x004098be
0x004098be:	call 0x0041400e
0x0041400e:	cmpl 0x42cc64, $0x0<UINT8>
0x00414015:	jne 0x0041401c
0x0041401c:	pushl %esi
0x0041401d:	movl %esi, 0x42bd68
0x00414023:	pushl %edi
0x00414024:	xorl %edi, %edi
0x00414026:	testl %esi, %esi
0x00414028:	jne 0x00414042
0x00414042:	movb %al, (%esi)
0x00414044:	testb %al, %al
0x00414046:	jne 0x00414032
0x00414032:	cmpb %al, $0x3d<UINT8>
0x00414034:	je 0x00414037
0x00414037:	pushl %esi
0x00414038:	call 0x0040e950
0x0040e950:	movl %ecx, 0x4(%esp)
0x0040e954:	testl %ecx, $0x3<UINT32>
0x0040e95a:	je 0x0040e980
0x0040e980:	movl %eax, (%ecx)
0x0040e982:	movl %edx, $0x7efefeff<UINT32>
0x0040e987:	addl %edx, %eax
0x0040e989:	xorl %eax, $0xffffffff<UINT8>
0x0040e98c:	xorl %eax, %edx
0x0040e98e:	addl %ecx, $0x4<UINT8>
0x0040e991:	testl %eax, $0x81010100<UINT32>
0x0040e996:	je 0x0040e980
0x0040e998:	movl %eax, -4(%ecx)
0x0040e99b:	testb %al, %al
0x0040e99d:	je 50
0x0040e99f:	testb %ah, %ah
0x0040e9a1:	je 0x0040e9c7
0x0040e9a3:	testl %eax, $0xff0000<UINT32>
0x0040e9a8:	je 19
0x0040e9aa:	testl %eax, $0xff000000<UINT32>
0x0040e9af:	je 0x0040e9b3
0x0040e9b3:	leal %eax, -1(%ecx)
0x0040e9b6:	movl %ecx, 0x4(%esp)
0x0040e9ba:	subl %eax, %ecx
0x0040e9bc:	ret

0x0041403d:	popl %ecx
0x0041403e:	leal %esi, 0x1(%esi,%eax)
0x00414048:	pushl $0x4<UINT8>
0x0041404a:	incl %edi
0x0041404b:	pushl %edi
0x0041404c:	call 0x00411b6b
0x00414051:	movl %edi, %eax
0x00414053:	popl %ecx
0x00414054:	popl %ecx
0x00414055:	movl 0x42bd44, %edi
0x0041405b:	testl %edi, %edi
0x0041405d:	je -53
0x0041405f:	movl %esi, 0x42bd68
0x00414065:	pushl %ebx
0x00414066:	jmp 0x004140aa
0x004140aa:	cmpb (%esi), $0x0<UINT8>
0x004140ad:	jne 0x00414068
0x00414068:	pushl %esi
0x00414069:	call 0x0040e950
0x0041406e:	movl %ebx, %eax
0x00414070:	incl %ebx
0x00414071:	cmpb (%esi), $0x3d<UINT8>
0x00414074:	popl %ecx
0x00414075:	je 0x004140a8
0x004140a8:	addl %esi, %ebx
0x004140af:	pushl 0x42bd68
0x004140b5:	call 0x00408a35
0x00408a35:	pushl $0xc<UINT8>
0x00408a37:	pushl $0x427ce8<UINT32>
0x00408a3c:	call 0x0040e2b8
0x00408a41:	movl %esi, 0x8(%ebp)
0x00408a44:	testl %esi, %esi
0x00408a46:	je 117
0x00408a48:	cmpl 0x42cc24, $0x3<UINT8>
0x00408a4f:	jne 0x00408a94
0x00408a94:	pushl %esi
0x00408a95:	pushl $0x0<UINT8>
0x00408a97:	pushl 0x42bf1c
0x00408a9d:	call HeapFree@KERNEL32.dll
HeapFree@KERNEL32.dll: API Node	
0x00408aa3:	testl %eax, %eax
0x00408aa5:	jne 0x00408abd
0x00408abd:	call 0x0040e2fd
0x00408ac2:	ret

0x004140ba:	andl 0x42bd68, $0x0<UINT8>
0x004140c1:	andl (%edi), $0x0<UINT8>
0x004140c4:	movl 0x42cc58, $0x1<UINT32>
0x004140ce:	xorl %eax, %eax
0x004140d0:	popl %ecx
0x004140d1:	popl %ebx
0x004140d2:	popl %edi
0x004140d3:	popl %esi
0x004140d4:	ret

0x004098c3:	testl %eax, %eax
0x004098c5:	jnl 0x004098cf
0x004098cf:	pushl $0x1<UINT8>
0x004098d1:	call 0x00408249
0x00408249:	movl %edi, %edi
0x0040824b:	pushl %ebp
0x0040824c:	movl %ebp, %esp
0x0040824e:	cmpl 0x42cc68, $0x0<UINT8>
0x00408255:	je 0x00408270
0x00408270:	call 0x00412b84
0x00412b84:	movl %edi, %edi
0x00412b86:	pushl %esi
0x00412b87:	pushl %edi
0x00412b88:	xorl %edi, %edi
0x00412b8a:	leal %esi, 0x42ae58(%edi)
0x00412b90:	pushl (%esi)
0x00412b92:	call 0x0040b367
0x0040b389:	pushl %eax
0x0040b38a:	pushl 0x42aab4
0x0040b390:	call TlsGetValue@KERNEL32.dll
0x0040b392:	call FlsGetValue@KERNEL32.DLL
0x0040b394:	testl %eax, %eax
0x0040b396:	je 8
0x0040b398:	movl %eax, 0x1f8(%eax)
0x0040b39e:	jmp 0x0040b3c7
0x00412b97:	addl %edi, $0x4<UINT8>
0x00412b9a:	popl %ecx
0x00412b9b:	movl (%esi), %eax
0x00412b9d:	cmpl %edi, $0x28<UINT8>
0x00412ba0:	jb 0x00412b8a
0x00412ba2:	popl %edi
0x00412ba3:	popl %esi
0x00412ba4:	ret

0x00408275:	pushl $0x422300<UINT32>
0x0040827a:	pushl $0x4222e8<UINT32>
0x0040827f:	call 0x004081ad
0x004081ad:	movl %edi, %edi
0x004081af:	pushl %ebp
0x004081b0:	movl %ebp, %esp
0x004081b2:	pushl %esi
0x004081b3:	movl %esi, 0x8(%ebp)
0x004081b6:	xorl %eax, %eax
0x004081b8:	jmp 0x004081c9
0x004081c9:	cmpl %esi, 0xc(%ebp)
0x004081cc:	jb 0x004081ba
0x004081ba:	testl %eax, %eax
0x004081bc:	jne 16
0x004081be:	movl %ecx, (%esi)
0x004081c0:	testl %ecx, %ecx
0x004081c2:	je 0x004081c6
0x004081c6:	addl %esi, $0x4<UINT8>
0x004081c4:	call 0x00414000
0x004075e5:	movl %eax, 0x42dc80
0x004075ea:	pushl %esi
0x004075eb:	pushl $0x14<UINT8>
0x004075ed:	popl %esi
0x004075ee:	testl %eax, %eax
0x004075f0:	jne 7
0x004075f2:	movl %eax, $0x200<UINT32>
0x004075f7:	jmp 0x004075ff
0x004075ff:	movl 0x42dc80, %eax
0x00407604:	pushl $0x4<UINT8>
0x00407606:	pushl %eax
0x00407607:	call 0x00411b6b
0x0040760c:	popl %ecx
0x0040760d:	popl %ecx
0x0040760e:	movl 0x42cc70, %eax
0x00407613:	testl %eax, %eax
0x00407615:	jne 0x00407635
0x00407635:	xorl %edx, %edx
0x00407637:	movl %ecx, $0x42a200<UINT32>
0x0040763c:	jmp 0x00407643
0x00407643:	movl (%edx,%eax), %ecx
0x00407646:	addl %ecx, $0x20<UINT8>
0x00407649:	addl %edx, $0x4<UINT8>
0x0040764c:	cmpl %ecx, $0x42a480<UINT32>
0x00407652:	jl 0x0040763e
0x0040763e:	movl %eax, 0x42cc70
0x00407654:	pushl $0xfffffffe<UINT8>
0x00407656:	popl %esi
0x00407657:	xorl %edx, %edx
0x00407659:	movl %ecx, $0x42a210<UINT32>
0x0040765e:	pushl %edi
0x0040765f:	movl %eax, %edx
0x00407661:	sarl %eax, $0x5<UINT8>
0x00407664:	movl %eax, 0x42cb20(,%eax,4)
0x0040766b:	movl %edi, %edx
0x0040766d:	andl %edi, $0x1f<UINT8>
0x00407670:	shll %edi, $0x6<UINT8>
0x00407673:	movl %eax, (%edi,%eax)
0x00407676:	cmpl %eax, $0xffffffff<UINT8>
0x00407679:	je 8
0x0040767b:	cmpl %eax, %esi
0x0040767d:	je 4
0x0040767f:	testl %eax, %eax
0x00407681:	jne 0x00407685
0x00407685:	addl %ecx, $0x20<UINT8>
0x00407688:	incl %edx
0x00407689:	cmpl %ecx, $0x42a270<UINT32>
0x0040768f:	jl 0x0040765f
0x00407691:	popl %edi
0x00407692:	xorl %eax, %eax
0x00407694:	popl %esi
0x00407695:	ret

0x004111a5:	call 0x00411143
0x00411143:	movl %edi, %edi
0x00411145:	pushl %ebp
0x00411146:	movl %ebp, %esp
0x00411148:	subl %esp, $0x18<UINT8>
0x0041114b:	xorl %eax, %eax
0x0041114d:	pushl %ebx
0x0041114e:	movl -4(%ebp), %eax
0x00411151:	movl -12(%ebp), %eax
0x00411154:	movl -8(%ebp), %eax
0x00411157:	pushl %ebx
0x00411158:	pushfl
0x00411159:	popl %eax
0x0041115a:	movl %ecx, %eax
0x0041115c:	xorl %eax, $0x200000<UINT32>
0x00411161:	pushl %eax
0x00411162:	popfl
0x00411163:	pushfl
0x00411164:	popl %edx
0x00411165:	subl %edx, %ecx
0x00411167:	je 0x00411188
0x00411188:	popl %ebx
0x00411189:	testl -4(%ebp), $0x4000000<UINT32>
0x00411190:	je 0x004111a0
0x004111a0:	xorl %eax, %eax
0x004111a2:	popl %ebx
0x004111a3:	leave
0x004111a4:	ret

0x004111aa:	movl 0x42cc20, %eax
0x004111af:	xorl %eax, %eax
0x004111b1:	ret

0x00412ab4:	movl %edi, %edi
0x00412ab6:	pushl %esi
0x00412ab7:	pushl $0x4<UINT8>
0x00412ab9:	pushl $0x20<UINT8>
0x00412abb:	call 0x00411b6b
0x00412ac0:	movl %esi, %eax
0x00412ac2:	pushl %esi
0x00412ac3:	call 0x0040b367
0x00412ac8:	addl %esp, $0xc<UINT8>
0x00412acb:	movl 0x42cc60, %eax
0x00412ad0:	movl 0x42cc5c, %eax
0x00412ad5:	testl %esi, %esi
0x00412ad7:	jne 0x00412ade
0x00412ade:	andl (%esi), $0x0<UINT8>
0x00412ae1:	xorl %eax, %eax
0x00412ae3:	popl %esi
0x00412ae4:	ret

0x00414000:	pushl $0x413fbe<UINT32>
0x00414005:	call SetUnhandledExceptionFilter@KERNEL32.dll
SetUnhandledExceptionFilter@KERNEL32.dll: API Node	
0x0041400b:	xorl %eax, %eax
0x0041400d:	ret

0x004081ce:	popl %esi
0x004081cf:	popl %ebp
0x004081d0:	ret

0x00408284:	popl %ecx
0x00408285:	popl %ecx
0x00408286:	testl %eax, %eax
0x00408288:	jne 66
0x0040828a:	pushl $0x412b5e<UINT32>
0x0040828f:	call 0x00412b21
0x00412b21:	movl %edi, %edi
0x00412b23:	pushl %ebp
0x00412b24:	movl %ebp, %esp
0x00412b26:	pushl 0x8(%ebp)
0x00412b29:	call 0x00412ae5
0x00412ae5:	pushl $0xc<UINT8>
0x00412ae7:	pushl $0x428060<UINT32>
0x00412aec:	call 0x0040e2b8
0x00412af1:	call 0x0040817e
0x0040817e:	pushl $0x8<UINT8>
0x00408180:	call 0x0040d265
0x00408185:	popl %ecx
0x00408186:	ret

0x00412af6:	andl -4(%ebp), $0x0<UINT8>
0x00412afa:	pushl 0x8(%ebp)
0x00412afd:	call 0x004129fa
0x004129fa:	movl %edi, %edi
0x004129fc:	pushl %ebp
0x004129fd:	movl %ebp, %esp
0x004129ff:	pushl %ecx
0x00412a00:	pushl %ebx
0x00412a01:	pushl %esi
0x00412a02:	pushl %edi
0x00412a03:	pushl 0x42cc60
0x00412a09:	call 0x0040b3e2
0x0040b413:	movl %eax, 0x1fc(%eax)
0x0040b419:	jmp 0x0040b442
0x00412a0e:	pushl 0x42cc5c
0x00412a14:	movl %edi, %eax
0x00412a16:	movl -4(%ebp), %edi
0x00412a19:	call 0x0040b3e2
0x00412a1e:	movl %esi, %eax
0x00412a20:	popl %ecx
0x00412a21:	popl %ecx
0x00412a22:	cmpl %esi, %edi
0x00412a24:	jb 131
0x00412a2a:	movl %ebx, %esi
0x00412a2c:	subl %ebx, %edi
0x00412a2e:	leal %eax, 0x4(%ebx)
0x00412a31:	cmpl %eax, $0x4<UINT8>
0x00412a34:	jb 119
0x00412a36:	pushl %edi
0x00412a37:	call 0x0041d8fb
0x0041d8fb:	pushl $0x10<UINT8>
0x0041d8fd:	pushl $0x428288<UINT32>
0x0041d902:	call 0x0040e2b8
0x0041d907:	xorl %eax, %eax
0x0041d909:	movl %ebx, 0x8(%ebp)
0x0041d90c:	xorl %edi, %edi
0x0041d90e:	cmpl %ebx, %edi
0x0041d910:	setne %al
0x0041d913:	cmpl %eax, %edi
0x0041d915:	jne 0x0041d934
0x0041d934:	cmpl 0x42cc24, $0x3<UINT8>
0x0041d93b:	jne 0x0041d975
0x0041d975:	pushl %ebx
0x0041d976:	pushl %edi
0x0041d977:	pushl 0x42bf1c
0x0041d97d:	call HeapSize@KERNEL32.dll
HeapSize@KERNEL32.dll: API Node	
0x0041d983:	movl %esi, %eax
0x0041d985:	movl %eax, %esi
0x0041d987:	call 0x0040e2fd
0x0041d98c:	ret

0x00412a3c:	movl %edi, %eax
0x00412a3e:	leal %eax, 0x4(%ebx)
0x00412a41:	popl %ecx
0x00412a42:	cmpl %edi, %eax
0x00412a44:	jae 0x00412a8e
0x00412a8e:	pushl 0x8(%ebp)
0x00412a91:	call 0x0040b367
0x00412a96:	movl (%esi), %eax
0x00412a98:	addl %esi, $0x4<UINT8>
0x00412a9b:	pushl %esi
0x00412a9c:	call 0x0040b367
0x00412aa1:	popl %ecx
0x00412aa2:	movl 0x42cc5c, %eax
0x00412aa7:	movl %eax, 0x8(%ebp)
0x00412aaa:	popl %ecx
0x00412aab:	jmp 0x00412aaf
0x00412aaf:	popl %edi
0x00412ab0:	popl %esi
0x00412ab1:	popl %ebx
0x00412ab2:	leave
0x00412ab3:	ret

0x00412b02:	popl %ecx
0x00412b03:	movl -28(%ebp), %eax
0x00412b06:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00412b0d:	call 0x00412b1b
0x00412b1b:	call 0x00408187
0x00408187:	pushl $0x8<UINT8>
0x00408189:	call 0x0040d173
0x0040818e:	popl %ecx
0x0040818f:	ret

0x00412b20:	ret

0x00412b12:	movl %eax, -28(%ebp)
0x00412b15:	call 0x0040e2fd
0x00412b1a:	ret

0x00412b2e:	negl %eax
0x00412b30:	sbbl %eax, %eax
0x00412b32:	negl %eax
0x00412b34:	popl %ecx
0x00412b35:	decl %eax
0x00412b36:	popl %ebp
0x00412b37:	ret

0x00408294:	movl %eax, $0x4222e0<UINT32>
0x00408299:	movl (%esp), $0x4222e4<UINT32>
0x004082a0:	call 0x00408190
0x00408190:	movl %edi, %edi
0x00408192:	pushl %ebp
0x00408193:	movl %ebp, %esp
0x00408195:	pushl %esi
0x00408196:	movl %esi, %eax
0x00408198:	jmp 0x004081a5
0x004081a5:	cmpl %esi, 0x8(%ebp)
0x004081a8:	jb 0x0040819a
0x0040819a:	movl %eax, (%esi)
0x0040819c:	testl %eax, %eax
0x0040819e:	je 0x004081a2
0x004081a2:	addl %esi, $0x4<UINT8>
0x004081aa:	popl %esi
0x004081ab:	popl %ebp
0x004081ac:	ret

0x004082a5:	cmpl 0x42cc6c, $0x0<UINT8>
0x004082ac:	popl %ecx
0x004082ad:	je 0x004082ca
0x004082ca:	xorl %eax, %eax
0x004082cc:	popl %ebp
0x004082cd:	ret

0x004098d6:	popl %ecx
0x004098d7:	testl %eax, %eax
0x004098d9:	je 0x004098e2
0x004098e2:	movl %eax, 0x42bd44
0x004098e7:	movl 0x42bd48, %eax
0x004098ec:	pushl %eax
0x004098ed:	pushl 0x42bd3c
0x004098f3:	pushl 0x42bd38
0x004098f9:	call 0x00403860
0x00403860:	pushl %ecx
0x00403861:	pushl %esi
0x00403862:	movl %esi, 0x10(%esp)
0x00403866:	leal %eax, 0xc(%esp)
0x0040386a:	pushl %esi
0x0040386b:	pushl %eax
0x0040386c:	call 0x004058a0
0x004058a0:	subl %esp, $0x110<UINT32>
0x004058a6:	movl %eax, 0x42a1f0
0x004058ab:	xorl %eax, %esp
0x004058ad:	movl 0x10c(%esp), %eax
0x004058b4:	movl %eax, 0x118(%esp)
0x004058bb:	pushl %ebx
0x004058bc:	pushl %ebp
0x004058bd:	movl %ebp, 0x11c(%esp)
0x004058c4:	pushl %esi
0x004058c5:	pushl %edi
0x004058c6:	pushl $0x104<UINT32>
0x004058cb:	leal %ecx, 0x1c(%esp)
0x004058cf:	pushl %ecx
0x004058d0:	pushl $0x0<UINT8>
0x004058d2:	movl 0x1c(%esp), %eax
0x004058d6:	call GetModuleFileNameA@KERNEL32.dll
0x004058dc:	leal %edx, 0x14(%esp)
0x004058e0:	pushl %edx
0x004058e1:	leal %eax, 0x1c(%esp)
0x004058e5:	pushl %eax
0x004058e6:	call 0x00405ae8
0x00405ae8:	jmp GetFileVersionInfoSizeA@VERSION.dll
GetFileVersionInfoSizeA@VERSION.dll: API Node	
0x004058eb:	movl %edi, %eax
0x004058ed:	pushl %edi
0x004058ee:	call 0x004062f7
0x004063aa:	pushl %esi
0x004063ab:	call 0x0040e624
0x0040e624:	movl %edi, %edi
0x0040e626:	pushl %ebp
0x0040e627:	movl %ebp, %esp
0x0040e629:	pushl 0x42c234
0x0040e62f:	call 0x0040b3e2
0x0040e634:	popl %ecx
0x0040e635:	testl %eax, %eax
0x0040e637:	je 0x0040e648
0x0040e648:	xorl %eax, %eax
0x0040e64a:	popl %ebp
0x0040e64b:	ret

0x004063b0:	popl %ecx
0x004063b1:	call 0x0040bd02
0x0040bd02:	call 0x0040b5f2
0x0040bd07:	testl %eax, %eax
0x0040bd09:	jne 0x0040bd11
0x0040bd11:	addl %eax, $0x8<UINT8>
0x0040bd14:	ret

0x004063b6:	movl (%eax), $0xc<UINT32>
0x004063bc:	xorl %eax, %eax
0x004058f3:	addl %esp, $0x4<UINT8>
0x004058f6:	movl %esi, %eax
0x004058f8:	pushl %esi
0x004058f9:	pushl %edi
0x004058fa:	pushl $0x0<UINT8>
0x004058fc:	leal %ecx, 0x24(%esp)
0x00405900:	pushl %ecx
0x00405901:	call 0x00405ae2
0x00405ae2:	jmp GetFileVersionInfoA@VERSION.dll
GetFileVersionInfoA@VERSION.dll: API Node	
0x00405906:	pushl $0x425c1c<UINT32>
0x0040590b:	pushl %esi
0x0040590c:	call 0x00405850
0x00405850:	subl %esp, $0xc<UINT8>
0x00405853:	pushl %esi
0x00405854:	movl %esi, 0x14(%esp)
0x00405858:	movl %eax, $0x400<UINT32>
0x0040585d:	leal %edx, 0xc(%esp)
0x00405861:	pushl %edx
0x00405862:	movw 0xc(%esp), %ax
0x00405867:	leal %eax, 0x8(%esp)
0x0040586b:	pushl %eax
0x0040586c:	pushl $0x425b84<UINT32>
0x00405871:	leal %ecx, 0x14(%esp)
0x00405875:	pushl %esi
0x00405876:	movl 0x14(%esp), %ecx
0x0040587a:	call 0x00405adc
0x00405adc:	jmp VerQueryValueA@VERSION.dll
VerQueryValueA@VERSION.dll: API Node	
0x0040587f:	movl %eax, 0x4(%esp)
0x00405883:	movzwl %edx, 0x2(%eax)
0x00405887:	movl %ecx, 0x18(%esp)
0x0040588b:	movzwl %eax, (%eax)
0x0040588e:	pushl %ecx
0x0040588f:	pushl %edx
0x00405890:	pushl %eax
0x00405891:	pushl %esi
0x00405892:	call 0x00405780
0x00405780:	pushl %ebp
0x00405781:	movl %ebp, %esp
0x00405783:	pushl $0xfffffffe<UINT8>
0x00405785:	pushl $0x427b60<UINT32>
0x0040578a:	pushl $0x406fb0<UINT32>
0x0040578f:	movl %eax, %fs:0
0x00405795:	pushl %eax
0x00405796:	subl %esp, $0x118<UINT32>
0x0040579c:	movl %eax, 0x42a1f0
0x004057a1:	xorl -8(%ebp), %eax
0x004057a4:	xorl %eax, %ebp
0x004057a6:	movl -28(%ebp), %eax
0x004057a9:	pushl %ebx
0x004057aa:	pushl %esi
0x004057ab:	pushl %edi
0x004057ac:	pushl %eax
0x004057ad:	leal %eax, -16(%ebp)
0x004057b0:	movl %fs:0, %eax
0x004057b6:	movl -24(%ebp), %esp
0x004057b9:	movl %esi, 0x8(%ebp)
0x004057bc:	movl %eax, 0x14(%ebp)
0x004057bf:	xorl %edi, %edi
0x004057c1:	movl -288(%ebp), %edi
0x004057c7:	pushl %eax
0x004057c8:	movzwl %eax, 0x10(%ebp)
0x004057cc:	pushl %eax
0x004057cd:	movzwl %ecx, 0xc(%ebp)
0x004057d1:	pushl %ecx
0x004057d2:	pushl $0x425b68<UINT32>
0x004057d7:	leal %edx, -284(%ebp)
0x004057dd:	pushl %edx
0x004057de:	call 0x00405f2c
0x00405f2c:	movl %edi, %edi
0x00405f2e:	pushl %ebp
0x00405f2f:	movl %ebp, %esp
0x00405f31:	subl %esp, $0x20<UINT8>
0x00405f34:	pushl %ebx
0x00405f35:	xorl %ebx, %ebx
0x00405f37:	cmpl 0xc(%ebp), %ebx
0x00405f3a:	jne 0x00405f59
0x00405f59:	movl %eax, 0x8(%ebp)
0x00405f5c:	cmpl %eax, %ebx
0x00405f5e:	je -36
0x00405f60:	pushl %esi
0x00405f61:	movl -24(%ebp), %eax
0x00405f64:	movl -32(%ebp), %eax
0x00405f67:	leal %eax, 0x10(%ebp)
0x00405f6a:	pushl %eax
0x00405f6b:	pushl %ebx
0x00405f6c:	pushl 0xc(%ebp)
0x00405f6f:	leal %eax, -32(%ebp)
0x00405f72:	pushl %eax
0x00405f73:	movl -28(%ebp), $0x7fffffff<UINT32>
0x00405f7a:	movl -20(%ebp), $0x42<UINT32>
0x00405f81:	call 0x0040c02f
0x0040c02f:	movl %edi, %edi
0x0040c031:	pushl %ebp
0x0040c032:	movl %ebp, %esp
0x0040c034:	subl %esp, $0x278<UINT32>
0x0040c03a:	movl %eax, 0x42a1f0
0x0040c03f:	xorl %eax, %ebp
0x0040c041:	movl -4(%ebp), %eax
0x0040c044:	pushl %ebx
0x0040c045:	movl %ebx, 0xc(%ebp)
0x0040c048:	pushl %esi
0x0040c049:	movl %esi, 0x8(%ebp)
0x0040c04c:	xorl %eax, %eax
0x0040c04e:	pushl %edi
0x0040c04f:	movl %edi, 0x14(%ebp)
0x0040c052:	pushl 0x10(%ebp)
0x0040c055:	leal %ecx, -604(%ebp)
0x0040c05b:	movl -588(%ebp), %esi
0x0040c061:	movl -548(%ebp), %edi
0x0040c067:	movl -584(%ebp), %eax
0x0040c06d:	movl -528(%ebp), %eax
0x0040c073:	movl -564(%ebp), %eax
0x0040c079:	movl -536(%ebp), %eax
0x0040c07f:	movl -560(%ebp), %eax
0x0040c085:	movl -576(%ebp), %eax
0x0040c08b:	movl -568(%ebp), %eax
0x0040c091:	call 0x00405d34
0x0040c096:	testl %esi, %esi
0x0040c098:	jne 0x0040c0cf
0x0040c0cf:	testb 0xc(%esi), $0x40<UINT8>
0x0040c0d3:	jne 0x0040c133
0x0040c133:	xorl %ecx, %ecx
0x0040c135:	cmpl %ebx, %ecx
0x0040c137:	je -163
0x0040c13d:	movb %dl, (%ebx)
0x0040c13f:	movl -552(%ebp), %ecx
0x0040c145:	movl -544(%ebp), %ecx
0x0040c14b:	movl -580(%ebp), %ecx
0x0040c151:	movb -529(%ebp), %dl
0x0040c157:	testb %dl, %dl
0x0040c159:	je 2591
0x0040c15f:	incl %ebx
0x0040c160:	cmpl -552(%ebp), $0x0<UINT8>
0x0040c167:	movl -572(%ebp), %ebx
0x0040c16d:	jl 2571
0x0040c173:	movb %al, %dl
0x0040c175:	subb %al, $0x20<UINT8>
0x0040c177:	cmpb %al, $0x58<UINT8>
0x0040c179:	ja 17
0x0040c17b:	movsbl %eax, %dl
0x0040c17e:	movsbl %eax, 0x426128(%eax)
0x0040c185:	andl %eax, $0xf<UINT8>
0x0040c188:	xorl %esi, %esi
0x0040c18a:	jmp 0x0040c190
0x0040c190:	movsbl %eax, 0x426148(%ecx,%eax,8)
0x0040c198:	pushl $0x7<UINT8>
0x0040c19a:	sarl %eax, $0x4<UINT8>
0x0040c19d:	popl %ecx
0x0040c19e:	movl -620(%ebp), %eax
0x0040c1a4:	cmpl %eax, %ecx
0x0040c1a6:	ja 2477
0x0040c1ac:	jmp 0x0040c40c
0x0040c3b2:	leal %eax, -604(%ebp)
0x0040c3b8:	pushl %eax
0x0040c3b9:	movzbl %eax, %dl
0x0040c3bc:	pushl %eax
0x0040c3bd:	movl -568(%ebp), %esi
0x0040c3c3:	call 0x004125e6
0x004125e6:	movl %edi, %edi
0x004125e8:	pushl %ebp
0x004125e9:	movl %ebp, %esp
0x004125eb:	subl %esp, $0x10<UINT8>
0x004125ee:	pushl 0xc(%ebp)
0x004125f1:	leal %ecx, -16(%ebp)
0x004125f4:	call 0x00405d34
0x00405daa:	movl %ecx, (%eax)
0x00405dac:	movl (%esi), %ecx
0x00405dae:	movl %eax, 0x4(%eax)
0x00405db1:	movl 0x4(%esi), %eax
0x004125f9:	movzbl %eax, 0x8(%ebp)
0x004125fd:	movl %ecx, -16(%ebp)
0x00412600:	movl %ecx, 0xc8(%ecx)
0x00412606:	movzwl %eax, (%ecx,%eax,2)
0x0041260a:	andl %eax, $0x8000<UINT32>
0x0041260f:	cmpb -4(%ebp), $0x0<UINT8>
0x00412613:	je 0x0041261c
0x0041261c:	leave
0x0041261d:	ret

0x0040c3c8:	popl %ecx
0x0040c3c9:	testl %eax, %eax
0x0040c3cb:	movb %al, -529(%ebp)
0x0040c3d1:	popl %ecx
0x0040c3d2:	je 0x0040c3f6
0x0040c3f6:	movl %ecx, -588(%ebp)
0x0040c3fc:	leal %esi, -552(%ebp)
0x0040c402:	call 0x0040bf4f
0x0040bf4f:	testb 0xc(%ecx), $0x40<UINT8>
0x0040bf53:	je 6
0x0040bf55:	cmpl 0x8(%ecx), $0x0<UINT8>
0x0040bf59:	je 36
0x0040bf5b:	decl 0x4(%ecx)
0x0040bf5e:	js 11
0x0040bf60:	movl %edx, (%ecx)
0x0040bf62:	movb (%edx), %al
0x0040bf64:	incl (%ecx)
0x0040bf66:	movzbl %eax, %al
0x0040bf69:	jmp 0x0040bf77
0x0040bf77:	cmpl %eax, $0xffffffff<UINT8>
0x0040bf7a:	jne 0x0040bf7f
0x0040bf7f:	incl (%esi)
0x0040bf81:	ret

0x0040c407:	jmp 0x0040cb59
0x0040cb59:	movl %ebx, -572(%ebp)
0x0040cb5f:	movb %al, (%ebx)
0x0040cb61:	movb -529(%ebp), %al
0x0040cb67:	testb %al, %al
0x0040cb69:	je 0x0040cb7e
0x0040cb6b:	movl %ecx, -620(%ebp)
0x0040cb71:	movl %edi, -548(%ebp)
0x0040cb77:	movb %dl, %al
0x0040cb79:	jmp 0x0040c15f
0x0040c1b3:	orl -536(%ebp), $0xffffffff<UINT8>
0x0040c1ba:	movl -624(%ebp), %esi
0x0040c1c0:	movl -576(%ebp), %esi
0x0040c1c6:	movl -564(%ebp), %esi
0x0040c1cc:	movl -560(%ebp), %esi
0x0040c1d2:	movl -528(%ebp), %esi
0x0040c1d8:	movl -568(%ebp), %esi
0x0040c1de:	jmp 0x0040cb59
0x0040c1e3:	movsbl %eax, %dl
0x0040c1e6:	subl %eax, $0x20<UINT8>
0x0040c1e9:	je 74
0x0040c1eb:	subl %eax, $0x3<UINT8>
0x0040c1ee:	je 54
0x0040c1f0:	subl %eax, $0x8<UINT8>
0x0040c1f3:	je 37
0x0040c1f5:	decl %eax
0x0040c1f6:	decl %eax
0x0040c1f7:	je 21
0x0040c1f9:	subl %eax, $0x3<UINT8>
0x0040c1fc:	jne 2391
0x0040c202:	orl -528(%ebp), $0x8<UINT8>
0x0040c209:	jmp 0x0040cb59
0x0040c241:	cmpb %dl, $0x2a<UINT8>
0x0040c244:	jne 0x0040c272
0x0040c272:	movl %eax, -564(%ebp)
0x0040c278:	imull %eax, %eax, $0xa<UINT8>
0x0040c27b:	movsbl %ecx, %dl
0x0040c27e:	leal %eax, -48(%eax,%ecx)
0x0040c282:	movl -564(%ebp), %eax
0x0040c288:	jmp 0x0040cb59
0x0040c40c:	movsbl %eax, %dl
0x0040c40f:	cmpl %eax, $0x64<UINT8>
0x0040c412:	jg 0x0040c600
0x0040c418:	je 633
0x0040c41e:	cmpl %eax, $0x53<UINT8>
0x0040c421:	jg 0x0040c519
0x0040c519:	subl %eax, $0x58<UINT8>
0x0040c51c:	je 0x0040c7fc
0x0040c7fc:	movl -584(%ebp), %ecx
0x0040c802:	jmp 0x0040c828
0x0040c828:	testb -528(%ebp), $0xffffff80<UINT8>
0x0040c82f:	movl -544(%ebp), $0x10<UINT32>
0x0040c839:	je 0x0040c6a8
0x0040c6a8:	movl %ecx, -528(%ebp)
0x0040c6ae:	testl %ecx, $0x8000<UINT32>
0x0040c6b4:	je 0x0040c863
0x0040c863:	testl %ecx, $0x1000<UINT32>
0x0040c869:	jne -437
0x0040c86f:	addl %edi, $0x4<UINT8>
0x0040c872:	testb %cl, $0x20<UINT8>
0x0040c875:	je 0x0040c88f
0x0040c88f:	movl %eax, -4(%edi)
0x0040c892:	testb %cl, $0x40<UINT8>
0x0040c895:	je 0x0040c89a
0x0040c89a:	xorl %edx, %edx
0x0040c89c:	movl -548(%ebp), %edi
0x0040c8a2:	testb %cl, $0x40<UINT8>
0x0040c8a5:	je 0x0040c8c2
0x0040c8c2:	testl -528(%ebp), $0x9000<UINT32>
0x0040c8cc:	movl %ebx, %edx
0x0040c8ce:	movl %edi, %eax
0x0040c8d0:	jne 2
0x0040c8d2:	xorl %ebx, %ebx
0x0040c8d4:	cmpl -536(%ebp), $0x0<UINT8>
0x0040c8db:	jnl 12
0x0040c8dd:	movl -536(%ebp), $0x1<UINT32>
0x0040c8e7:	jmp 0x0040c903
0x0040c903:	movl %eax, %edi
0x0040c905:	orl %eax, %ebx
0x0040c907:	jne 0x0040c90f
0x0040c90f:	leal %esi, -13(%ebp)
0x0040c912:	movl %eax, -536(%ebp)
0x0040c918:	decl -536(%ebp)
0x0040c91e:	testl %eax, %eax
0x0040c920:	jg 0x0040c928
0x0040c928:	movl %eax, -544(%ebp)
0x0040c92e:	cltd
0x0040c92f:	pushl %edx
0x0040c930:	pushl %eax
0x0040c931:	pushl %ebx
0x0040c932:	pushl %edi
0x0040c933:	call 0x0041a300
0x0041a300:	pushl %esi
0x0041a301:	movl %eax, 0x14(%esp)
0x0041a305:	orl %eax, %eax
0x0041a307:	jne 40
0x0041a309:	movl %ecx, 0x10(%esp)
0x0041a30d:	movl %eax, 0xc(%esp)
0x0041a311:	xorl %edx, %edx
0x0041a313:	divl %eax, %ecx
0x0041a315:	movl %ebx, %eax
0x0041a317:	movl %eax, 0x8(%esp)
0x0041a31b:	divl %eax, %ecx
0x0041a31d:	movl %esi, %eax
0x0041a31f:	movl %eax, %ebx
0x0041a321:	mull %eax, 0x10(%esp)
0x0041a325:	movl %ecx, %eax
0x0041a327:	movl %eax, %esi
0x0041a329:	mull %eax, 0x10(%esp)
0x0041a32d:	addl %edx, %ecx
0x0041a32f:	jmp 0x0041a378
0x0041a378:	subl %eax, 0x8(%esp)
0x0041a37c:	sbbl %edx, 0xc(%esp)
0x0041a380:	negl %edx
0x0041a382:	negl %eax
0x0041a384:	sbbl %edx, $0x0<UINT8>
0x0041a387:	movl %ecx, %edx
0x0041a389:	movl %edx, %ebx
0x0041a38b:	movl %ebx, %ecx
0x0041a38d:	movl %ecx, %eax
0x0041a38f:	movl %eax, %esi
0x0041a391:	popl %esi
0x0041a392:	ret $0x10<UINT16>

0x0040c938:	addl %ecx, $0x30<UINT8>
0x0040c93b:	cmpl %ecx, $0x39<UINT8>
0x0040c93e:	movl -608(%ebp), %ebx
0x0040c944:	movl %edi, %eax
0x0040c946:	movl %ebx, %edx
0x0040c948:	jle 0x0040c950
0x0040c950:	movb (%esi), %cl
0x0040c952:	decl %esi
0x0040c953:	jmp 0x0040c912
0x0040c922:	movl %eax, %edi
0x0040c924:	orl %eax, %ebx
0x0040c926:	je 0x0040c955
0x0040c955:	leal %eax, -13(%ebp)
0x0040c958:	subl %eax, %esi
0x0040c95a:	incl %esi
0x0040c95b:	testl -528(%ebp), $0x200<UINT32>
0x0040c965:	movl -544(%ebp), %eax
0x0040c96b:	movl -540(%ebp), %esi
0x0040c971:	je 0x0040c9d4
0x0040c9d4:	cmpl -576(%ebp), $0x0<UINT8>
0x0040c9db:	jne 348
0x0040c9e1:	movl %eax, -528(%ebp)
0x0040c9e7:	testb %al, $0x40<UINT8>
0x0040c9e9:	je 0x0040ca1d
0x0040ca1d:	movl %ebx, -564(%ebp)
0x0040ca23:	subl %ebx, -544(%ebp)
0x0040ca29:	subl %ebx, -560(%ebp)
0x0040ca2f:	testb -528(%ebp), $0xc<UINT8>
0x0040ca36:	jne 0x0040ca4f
0x0040ca4f:	pushl -560(%ebp)
0x0040ca55:	movl %edi, -588(%ebp)
0x0040ca5b:	leal %eax, -552(%ebp)
0x0040ca61:	leal %ecx, -556(%ebp)
0x0040ca67:	call 0x0040bfa8
0x0040bfa8:	movl %edi, %edi
0x0040bfaa:	pushl %ebp
0x0040bfab:	movl %ebp, %esp
0x0040bfad:	testb 0xc(%edi), $0x40<UINT8>
0x0040bfb1:	pushl %ebx
0x0040bfb2:	pushl %esi
0x0040bfb3:	movl %esi, %eax
0x0040bfb5:	movl %ebx, %ecx
0x0040bfb7:	je 50
0x0040bfb9:	cmpl 0x8(%edi), $0x0<UINT8>
0x0040bfbd:	jne 0x0040bfeb
0x0040bfeb:	cmpl 0x8(%ebp), $0x0<UINT8>
0x0040bfef:	jg 0x0040bfc6
0x0040bff1:	popl %esi
0x0040bff2:	popl %ebx
0x0040bff3:	popl %ebp
0x0040bff4:	ret

0x0040ca6c:	testb -528(%ebp), $0x8<UINT8>
0x0040ca73:	popl %ecx
0x0040ca74:	je 0x0040ca91
0x0040ca76:	testb -528(%ebp), $0x4<UINT8>
0x0040ca7d:	jne 18
0x0040ca7f:	pushl %edi
0x0040ca80:	pushl %ebx
0x0040ca81:	pushl $0x30<UINT8>
0x0040ca83:	leal %eax, -552(%ebp)
0x0040ca89:	call 0x0040bf82
0x0040bf82:	movl %edi, %edi
0x0040bf84:	pushl %ebp
0x0040bf85:	movl %ebp, %esp
0x0040bf87:	pushl %esi
0x0040bf88:	movl %esi, %eax
0x0040bf8a:	jmp 0x0040bf9f
0x0040bf9f:	cmpl 0xc(%ebp), $0x0<UINT8>
0x0040bfa3:	jg 0x0040bf8c
0x0040bf8c:	movl %ecx, 0x10(%ebp)
0x0040bf8f:	movb %al, 0x8(%ebp)
0x0040bf92:	decl 0xc(%ebp)
0x0040bf95:	call 0x0040bf4f
0x0040bf9a:	cmpl (%esi), $0xffffffff<UINT8>
0x0040bf9d:	je 6
0x0040bfa5:	popl %esi
0x0040bfa6:	popl %ebp
0x0040bfa7:	ret

0x0040ca8e:	addl %esp, $0xc<UINT8>
0x0040ca91:	cmpl -568(%ebp), $0x0<UINT8>
0x0040ca98:	movl %eax, -544(%ebp)
0x0040ca9e:	je 0x0040cb06
0x0040cb06:	movl %ecx, -540(%ebp)
0x0040cb0c:	pushl %eax
0x0040cb0d:	leal %eax, -552(%ebp)
0x0040cb13:	call 0x0040bfa8
0x0040bfc6:	movb %al, (%ebx)
0x0040bfc8:	decl 0x8(%ebp)
0x0040bfcb:	movl %ecx, %edi
0x0040bfcd:	call 0x0040bf4f
0x0040bfd2:	incl %ebx
0x0040bfd3:	cmpl (%esi), $0xffffffff<UINT8>
0x0040bfd6:	jne 0x0040bfeb
0x0040cb18:	popl %ecx
0x0040cb19:	cmpl -552(%ebp), $0x0<UINT8>
0x0040cb20:	jl 27
0x0040cb22:	testb -528(%ebp), $0x4<UINT8>
0x0040cb29:	je 0x0040cb3d
0x0040cb3d:	cmpl -580(%ebp), $0x0<UINT8>
0x0040cb44:	je 0x0040cb59
0x0040c600:	cmpl %eax, $0x70<UINT8>
0x0040c603:	jg 0x0040c804
0x0040c804:	subl %eax, $0x73<UINT8>
0x0040c807:	je 0x0040c4c3
0x0040c4c3:	movl %ecx, -536(%ebp)
0x0040c4c9:	cmpl %ecx, $0xffffffff<UINT8>
0x0040c4cc:	jne 5
0x0040c4ce:	movl %ecx, $0x7fffffff<UINT32>
0x0040c4d3:	addl %edi, $0x4<UINT8>
0x0040c4d6:	testl -528(%ebp), $0x810<UINT32>
0x0040c4e0:	movl -548(%ebp), %edi
0x0040c4e6:	movl %edi, -4(%edi)
0x0040c4e9:	movl -540(%ebp), %edi
0x0040c4ef:	je 0x0040c9a6
0x0040c9a6:	cmpl %edi, %esi
0x0040c9a8:	jne 0x0040c9b5
0x0040c9b5:	movl %eax, -540(%ebp)
0x0040c9bb:	jmp 0x0040c9c4
0x0040c9c4:	cmpl %ecx, %esi
0x0040c9c6:	jne 0x0040c9bd
0x0040c9bd:	decl %ecx
0x0040c9be:	cmpb (%eax), $0x0<UINT8>
0x0040c9c1:	je 0x0040c9c8
0x0040c9c3:	incl %eax
0x0040c9c8:	subl %eax, -540(%ebp)
0x0040c9ce:	movl -544(%ebp), %eax
0x0040ca38:	pushl -588(%ebp)
0x0040ca3e:	leal %eax, -552(%ebp)
0x0040ca44:	pushl %ebx
0x0040ca45:	pushl $0x20<UINT8>
0x0040ca47:	call 0x0040bf82
0x0040ca4c:	addl %esp, $0xc<UINT8>
0x0040cb7e:	cmpb -592(%ebp), $0x0<UINT8>
0x0040cb85:	je 10
0x0040cb87:	movl %eax, -596(%ebp)
0x0040cb8d:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x0040cb91:	movl %eax, -552(%ebp)
0x0040cb97:	movl %ecx, -4(%ebp)
0x0040cb9a:	popl %edi
0x0040cb9b:	popl %esi
0x0040cb9c:	xorl %ecx, %ebp
0x0040cb9e:	popl %ebx
0x0040cb9f:	call 0x00406f3e
0x0040cba4:	leave
0x0040cba5:	ret

0x00405f86:	addl %esp, $0x10<UINT8>
0x00405f89:	decl -28(%ebp)
0x00405f8c:	movl %esi, %eax
0x00405f8e:	js 7
0x00405f90:	movl %eax, -32(%ebp)
0x00405f93:	movb (%eax), %bl
0x00405f95:	jmp 0x00405fa3
0x00405fa3:	movl %eax, %esi
0x00405fa5:	popl %esi
0x00405fa6:	popl %ebx
0x00405fa7:	leave
0x00405fa8:	ret

0x004057e3:	addl %esp, $0x14<UINT8>
0x004057e6:	movl -4(%ebp), %edi
0x004057e9:	leal %eax, -296(%ebp)
0x004057ef:	pushl %eax
0x004057f0:	leal %ecx, -292(%ebp)
0x004057f6:	pushl %ecx
0x004057f7:	leal %edx, -284(%ebp)
0x004057fd:	pushl %edx
0x004057fe:	pushl %esi
0x004057ff:	call 0x00405adc
0x00405804:	movl -288(%ebp), %eax
0x0040580a:	jmp 0x00405815
0x00405815:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040581c:	movl %eax, -288(%ebp)
0x00405822:	negl %eax
0x00405824:	sbbl %eax, %eax
0x00405826:	andl %eax, -292(%ebp)
0x0040582c:	movl %ecx, -16(%ebp)
0x0040582f:	movl %fs:0, %ecx
0x00405836:	popl %ecx
0x00405837:	popl %edi
0x00405838:	popl %esi
0x00405839:	popl %ebx
0x0040583a:	movl %ecx, -28(%ebp)
0x0040583d:	xorl %ecx, %ebp
0x0040583f:	call 0x00406f3e
0x00405844:	movl %esp, %ebp
0x00405846:	popl %ebp
0x00405847:	ret

0x00405897:	addl %esp, $0x10<UINT8>
0x0040589a:	popl %esi
0x0040589b:	addl %esp, $0xc<UINT8>
0x0040589e:	ret

0x00405911:	movl %edi, %eax
0x00405913:	call 0x004075df
0x004075df:	movl %eax, $0x42a200<UINT32>
0x004075e4:	ret

0x00405918:	addl %eax, $0x40<UINT8>
0x0040591b:	pushl %eax
0x0040591c:	pushl $0x4223b8<UINT32>
0x00405921:	call 0x00409684
0x00409684:	pushl $0x10<UINT8>
0x00409686:	pushl $0x427da8<UINT32>
0x0040968b:	call 0x0040e2b8
0x00409690:	xorl %eax, %eax
0x00409692:	xorl %esi, %esi
0x00409694:	cmpl 0x8(%ebp), %esi
0x00409697:	setne %al
0x0040969a:	cmpl %eax, %esi
0x0040969c:	jne 0x004096be
0x004096be:	xorl %eax, %eax
0x004096c0:	movl %edi, 0xc(%ebp)
0x004096c3:	cmpl %edi, %esi
0x004096c5:	setne %al
0x004096c8:	cmpl %eax, %esi
0x004096ca:	je -46
0x004096cc:	testb 0xc(%edi), $0x40<UINT8>
0x004096d0:	jne 95
0x004096d2:	pushl %edi
0x004096d3:	call 0x004118e1
0x004118e1:	movl %edi, %edi
0x004118e3:	pushl %ebp
0x004118e4:	movl %ebp, %esp
0x004118e6:	movl %eax, 0x8(%ebp)
0x004118e9:	pushl %esi
0x004118ea:	xorl %esi, %esi
0x004118ec:	cmpl %eax, %esi
0x004118ee:	jne 0x0041190d
0x0041190d:	movl %eax, 0x10(%eax)
0x00411910:	popl %esi
0x00411911:	popl %ebp
0x00411912:	ret

0x004096d8:	popl %ecx
0x004096d9:	cmpl %eax, $0xffffffff<UINT8>
0x004096dc:	je 27
0x004096de:	cmpl %eax, $0xfffffffe<UINT8>
0x004096e1:	je 22
0x004096e3:	movl %edx, %eax
0x004096e5:	sarl %edx, $0x5<UINT8>
0x004096e8:	movl %ecx, %eax
0x004096ea:	andl %ecx, $0x1f<UINT8>
0x004096ed:	shll %ecx, $0x6<UINT8>
0x004096f0:	addl %ecx, 0x42cb20(,%edx,4)
0x004096f7:	jmp 0x004096fe
0x004096fe:	testb 0x24(%ecx), $0x7f<UINT8>
0x00409702:	jne -102
0x00409704:	cmpl %eax, $0xffffffff<UINT8>
0x00409707:	je 25
0x00409709:	cmpl %eax, $0xfffffffe<UINT8>
0x0040970c:	je 20
0x0040970e:	movl %ecx, %eax
0x00409710:	sarl %ecx, $0x5<UINT8>
0x00409713:	andl %eax, $0x1f<UINT8>
0x00409716:	shll %eax, $0x6<UINT8>
0x00409719:	addl %eax, 0x42cb20(,%ecx,4)
0x00409720:	jmp 0x00409727
0x00409727:	testb 0x24(%eax), $0xffffff80<UINT8>
0x0040972b:	jne -147
0x00409731:	pushl 0x8(%ebp)
0x00409734:	call 0x0040e950
0x0040e9c7:	leal %eax, -3(%ecx)
0x0040e9ca:	movl %ecx, 0x4(%esp)
0x0040e9ce:	subl %eax, %ecx
0x0040e9d0:	ret

0x00409739:	movl -28(%ebp), %eax
0x0040973c:	pushl %edi
0x0040973d:	call 0x004076b6
0x004076b6:	movl %edi, %edi
0x004076b8:	pushl %ebp
0x004076b9:	movl %ebp, %esp
0x004076bb:	pushl %esi
0x004076bc:	movl %esi, 0x8(%ebp)
0x004076bf:	movl %eax, $0x42a200<UINT32>
0x004076c4:	cmpl %esi, %eax
0x004076c6:	jb 34
0x004076c8:	cmpl %esi, $0x42a460<UINT32>
0x004076ce:	ja 26
0x004076d0:	movl %ecx, %esi
0x004076d2:	subl %ecx, %eax
0x004076d4:	sarl %ecx, $0x5<UINT8>
0x004076d7:	addl %ecx, $0x10<UINT8>
0x004076da:	pushl %ecx
0x004076db:	call 0x0040d265
0x004076e0:	orl 0xc(%esi), $0x8000<UINT32>
0x004076e7:	popl %ecx
0x004076e8:	jmp 0x004076f4
0x004076f4:	popl %esi
0x004076f5:	popl %ebp
0x004076f6:	ret

0x00409742:	popl %ecx
0x00409743:	popl %ecx
0x00409744:	movl -4(%ebp), %esi
0x00409747:	pushl %edi
0x00409748:	call 0x0040e736
0x0040e736:	movl %edi, %edi
0x0040e738:	pushl %ebp
0x0040e739:	movl %ebp, %esp
0x0040e73b:	pushl %esi
0x0040e73c:	movl %esi, 0x8(%ebp)
0x0040e73f:	pushl %esi
0x0040e740:	call 0x004118e1
0x0040e745:	pushl %eax
0x0040e746:	call 0x0041a08f
0x0041a08f:	movl %edi, %edi
0x0041a091:	pushl %ebp
0x0041a092:	movl %ebp, %esp
0x0041a094:	movl %eax, 0x8(%ebp)
0x0041a097:	cmpl %eax, $0xfffffffe<UINT8>
0x0041a09a:	jne 0x0041a0ab
0x0041a0ab:	pushl %esi
0x0041a0ac:	xorl %esi, %esi
0x0041a0ae:	cmpl %eax, %esi
0x0041a0b0:	jl 8
0x0041a0b2:	cmpl %eax, 0x42cb00
0x0041a0b8:	jb 0x0041a0d6
0x0041a0d6:	movl %ecx, %eax
0x0041a0d8:	andl %eax, $0x1f<UINT8>
0x0041a0db:	sarl %ecx, $0x5<UINT8>
0x0041a0de:	movl %ecx, 0x42cb20(,%ecx,4)
0x0041a0e5:	shll %eax, $0x6<UINT8>
0x0041a0e8:	movsbl %eax, 0x4(%ecx,%eax)
0x0041a0ed:	andl %eax, $0x40<UINT8>
0x0041a0f0:	popl %esi
0x0041a0f1:	popl %ebp
0x0041a0f2:	ret

0x0040e74b:	popl %ecx
0x0040e74c:	popl %ecx
0x0040e74d:	testl %eax, %eax
0x0040e74f:	je 124
0x0040e751:	call 0x004075df
0x0040e756:	addl %eax, $0x20<UINT8>
0x0040e759:	cmpl %esi, %eax
0x0040e75b:	jne 0x0040e761
0x0040e761:	call 0x004075df
0x0040e766:	addl %eax, $0x40<UINT8>
0x0040e769:	cmpl %esi, %eax
0x0040e76b:	jne 96
0x0040e76d:	xorl %eax, %eax
0x0040e76f:	incl %eax
0x0040e770:	incl 0x42bd30
0x0040e776:	testl 0xc(%esi), $0x10c<UINT32>
0x0040e77d:	jne 78
0x0040e77f:	pushl %ebx
0x0040e780:	pushl %edi
0x0040e781:	leal %edi, 0x42c23c(,%eax,4)
0x0040e788:	cmpl (%edi), $0x0<UINT8>
0x0040e78b:	movl %ebx, $0x1000<UINT32>
0x0040e790:	jne 32
0x0040e792:	pushl %ebx
0x0040e793:	call 0x00411b26
0x0040e798:	popl %ecx
0x0040e799:	movl (%edi), %eax
0x0040e79b:	testl %eax, %eax
0x0040e79d:	jne 0x0040e7b2
0x0040e7b2:	movl %edi, (%edi)
0x0040e7b4:	movl 0x8(%esi), %edi
0x0040e7b7:	movl (%esi), %edi
0x0040e7b9:	movl 0x18(%esi), %ebx
0x0040e7bc:	movl 0x4(%esi), %ebx
0x0040e7bf:	orl 0xc(%esi), $0x1102<UINT32>
0x0040e7c6:	xorl %eax, %eax
0x0040e7c8:	popl %edi
0x0040e7c9:	incl %eax
0x0040e7ca:	popl %ebx
0x0040e7cb:	jmp 0x0040e7cf
0x0040e7cf:	popl %esi
0x0040e7d0:	popl %ebp
0x0040e7d1:	ret

0x0040974d:	movl %esi, %eax
0x0040974f:	pushl %edi
0x00409750:	pushl -28(%ebp)
0x00409753:	pushl $0x1<UINT8>
0x00409755:	pushl 0x8(%ebp)
0x00409758:	call 0x0040903e
0x0040903e:	movl %edi, %edi
0x00409040:	pushl %ebp
0x00409041:	movl %ebp, %esp
0x00409043:	subl %esp, $0xc<UINT8>
0x00409046:	pushl %ebx
0x00409047:	pushl %esi
0x00409048:	pushl %edi
0x00409049:	xorl %edi, %edi
0x0040904b:	cmpl 0xc(%ebp), %edi
0x0040904e:	je 36
0x00409050:	cmpl 0x10(%ebp), %edi
0x00409053:	je 31
0x00409055:	movl %esi, 0x14(%ebp)
0x00409058:	cmpl %esi, %edi
0x0040905a:	jne 0x0040907b
0x0040907b:	movl %ecx, 0x8(%ebp)
0x0040907e:	cmpl %ecx, %edi
0x00409080:	je -38
0x00409082:	orl %eax, $0xffffffff<UINT8>
0x00409085:	xorl %edx, %edx
0x00409087:	divl %eax, 0xc(%ebp)
0x0040908a:	cmpl 0x10(%ebp), %eax
0x0040908d:	ja -51
0x0040908f:	movl %edi, 0xc(%ebp)
0x00409092:	imull %edi, 0x10(%ebp)
0x00409096:	testl 0xc(%esi), $0x10c<UINT32>
0x0040909d:	movl -4(%ebp), %ecx
0x004090a0:	movl -12(%ebp), %edi
0x004090a3:	movl %ebx, %edi
0x004090a5:	je 8
0x004090a7:	movl %eax, 0x18(%esi)
0x004090aa:	movl -8(%ebp), %eax
0x004090ad:	jmp 0x004090b6
0x004090b6:	testl %edi, %edi
0x004090b8:	je 191
0x004090be:	movl %ecx, 0xc(%esi)
0x004090c1:	andl %ecx, $0x108<UINT32>
0x004090c7:	je 47
0x004090c9:	movl %eax, 0x4(%esi)
0x004090cc:	testl %eax, %eax
0x004090ce:	je 40
0x004090d0:	jl 175
0x004090d6:	movl %edi, %ebx
0x004090d8:	cmpl %ebx, %eax
0x004090da:	jb 0x004090de
0x004090de:	pushl %edi
0x004090df:	pushl -4(%ebp)
0x004090e2:	pushl (%esi)
0x004090e4:	call 0x004086d0
0x004086d0:	pushl %ebp
0x004086d1:	movl %ebp, %esp
0x004086d3:	pushl %edi
0x004086d4:	pushl %esi
0x004086d5:	movl %esi, 0xc(%ebp)
0x004086d8:	movl %ecx, 0x10(%ebp)
0x004086db:	movl %edi, 0x8(%ebp)
0x004086de:	movl %eax, %ecx
0x004086e0:	movl %edx, %ecx
0x004086e2:	addl %eax, %esi
0x004086e4:	cmpl %edi, %esi
0x004086e6:	jbe 8
0x004086e8:	cmpl %edi, %eax
0x004086ea:	jb 420
0x004086f0:	cmpl %ecx, $0x100<UINT32>
0x004086f6:	jb 0x00408717
0x00408717:	testl %edi, $0x3<UINT32>
0x0040871d:	jne 21
0x0040871f:	shrl %ecx, $0x2<UINT8>
0x00408722:	andl %edx, $0x3<UINT8>
0x00408725:	cmpl %ecx, $0x8<UINT8>
0x00408728:	jb 0x00408754
0x00408754:	jmp 0x0040883b
0x0040883b:	jmp 0x0040885c
0x0040885c:	movb %al, (%esi)
0x0040885e:	movb (%edi), %al
0x00408860:	movl %eax, 0x8(%ebp)
0x00408863:	popl %esi
0x00408864:	popl %edi
0x00408865:	leave
0x00408866:	ret

0x004090e9:	subl 0x4(%esi), %edi
0x004090ec:	addl (%esi), %edi
0x004090ee:	addl %esp, $0xc<UINT8>
0x004090f1:	subl %ebx, %edi
0x004090f3:	addl -4(%ebp), %edi
0x004090f6:	jmp 0x00409147
0x00409147:	movl %edi, -12(%ebp)
0x0040914a:	jmp 0x00409175
0x00409175:	testl %ebx, %ebx
0x00409177:	jne -191
0x0040917d:	movl %eax, 0x10(%ebp)
0x00409180:	jmp 0x00409076
0x00409076:	popl %edi
0x00409077:	popl %esi
0x00409078:	popl %ebx
0x00409079:	leave
0x0040907a:	ret

0x0040975d:	movl -32(%ebp), %eax
0x00409760:	pushl %edi
0x00409761:	pushl %esi
0x00409762:	call 0x0040e7d2
0x0040e7d2:	movl %edi, %edi
0x0040e7d4:	pushl %ebp
0x0040e7d5:	movl %ebp, %esp
0x0040e7d7:	cmpl 0x8(%ebp), $0x0<UINT8>
0x0040e7db:	je 39
0x0040e7dd:	pushl %esi
0x0040e7de:	movl %esi, 0xc(%ebp)
0x0040e7e1:	testl 0xc(%esi), $0x1000<UINT32>
0x0040e7e8:	je 25
0x0040e7ea:	pushl %esi
0x0040e7eb:	call 0x004079af
0x004079af:	movl %edi, %edi
0x004079b1:	pushl %ebp
0x004079b2:	movl %ebp, %esp
0x004079b4:	pushl %ebx
0x004079b5:	pushl %esi
0x004079b6:	movl %esi, 0x8(%ebp)
0x004079b9:	movl %eax, 0xc(%esi)
0x004079bc:	movl %ecx, %eax
0x004079be:	andb %cl, $0x3<UINT8>
0x004079c1:	xorl %ebx, %ebx
0x004079c3:	cmpb %cl, $0x2<UINT8>
0x004079c6:	jne 64
0x004079c8:	testl %eax, $0x108<UINT32>
0x004079cd:	je 57
0x004079cf:	movl %eax, 0x8(%esi)
0x004079d2:	pushl %edi
0x004079d3:	movl %edi, (%esi)
0x004079d5:	subl %edi, %eax
0x004079d7:	testl %edi, %edi
0x004079d9:	jle 44
0x004079db:	pushl %edi
0x004079dc:	pushl %eax
0x004079dd:	pushl %esi
0x004079de:	call 0x004118e1
0x004079e3:	popl %ecx
0x004079e4:	pushl %eax
0x004079e5:	call 0x00412429
0x00412429:	pushl $0x10<UINT8>
0x0041242b:	pushl $0x428000<UINT32>
0x00412430:	call 0x0040e2b8
0x00412435:	movl %eax, 0x8(%ebp)
0x00412438:	cmpl %eax, $0xfffffffe<UINT8>
0x0041243b:	jne 0x00412458
0x00412458:	xorl %edi, %edi
0x0041245a:	cmpl %eax, %edi
0x0041245c:	jl 8
0x0041245e:	cmpl %eax, 0x42cb00
0x00412464:	jb 0x00412487
0x00412487:	movl %ecx, %eax
0x00412489:	sarl %ecx, $0x5<UINT8>
0x0041248c:	leal %ebx, 0x42cb20(,%ecx,4)
0x00412493:	movl %esi, %eax
0x00412495:	andl %esi, $0x1f<UINT8>
0x00412498:	shll %esi, $0x6<UINT8>
0x0041249b:	movl %ecx, (%ebx)
0x0041249d:	movsbl %ecx, 0x4(%ecx,%esi)
0x004124a2:	andl %ecx, $0x1<UINT8>
0x004124a5:	je -65
0x004124a7:	pushl %eax
0x004124a8:	call 0x0041d479
0x0041d479:	pushl $0xc<UINT8>
0x0041d47b:	pushl $0x428220<UINT32>
0x0041d480:	call 0x0040e2b8
0x0041d485:	movl %edi, 0x8(%ebp)
0x0041d488:	movl %eax, %edi
0x0041d48a:	sarl %eax, $0x5<UINT8>
0x0041d48d:	movl %esi, %edi
0x0041d48f:	andl %esi, $0x1f<UINT8>
0x0041d492:	shll %esi, $0x6<UINT8>
0x0041d495:	addl %esi, 0x42cb20(,%eax,4)
0x0041d49c:	movl -28(%ebp), $0x1<UINT32>
0x0041d4a3:	xorl %ebx, %ebx
0x0041d4a5:	cmpl 0x8(%esi), %ebx
0x0041d4a8:	jne 0x0041d4e0
0x0041d4e0:	cmpl -28(%ebp), %ebx
0x0041d4e3:	je 29
0x0041d4e5:	movl %eax, %edi
0x0041d4e7:	sarl %eax, $0x5<UINT8>
0x0041d4ea:	andl %edi, $0x1f<UINT8>
0x0041d4ed:	shll %edi, $0x6<UINT8>
0x0041d4f0:	movl %eax, 0x42cb20(,%eax,4)
0x0041d4f7:	leal %eax, 0xc(%eax,%edi)
0x0041d4fb:	pushl %eax
0x0041d4fc:	call EnterCriticalSection@KERNEL32.dll
0x0041d502:	movl %eax, -28(%ebp)
0x0041d505:	call 0x0040e2fd
0x0041d50a:	ret

0x004124ad:	popl %ecx
0x004124ae:	movl -4(%ebp), %edi
0x004124b1:	movl %eax, (%ebx)
0x004124b3:	testb 0x4(%eax,%esi), $0x1<UINT8>
0x004124b8:	je 22
0x004124ba:	pushl 0x10(%ebp)
0x004124bd:	pushl 0xc(%ebp)
0x004124c0:	pushl 0x8(%ebp)
0x004124c3:	call 0x00411cf6
0x00411cf6:	movl %edi, %edi
0x00411cf8:	pushl %ebp
0x00411cf9:	movl %ebp, %esp
0x00411cfb:	movl %eax, $0x1ae4<UINT32>
0x00411d00:	call 0x00406f50
0x00406f72:	subl %eax, $0x1000<UINT32>
0x00406f77:	testl (%eax), %eax
0x00406f79:	jmp 0x00406f64
0x00411d05:	movl %eax, 0x42a1f0
0x00411d0a:	xorl %eax, %ebp
0x00411d0c:	movl -4(%ebp), %eax
0x00411d0f:	movl %eax, 0xc(%ebp)
0x00411d12:	pushl %esi
0x00411d13:	xorl %esi, %esi
0x00411d15:	movl -6860(%ebp), %eax
0x00411d1b:	movl -6856(%ebp), %esi
0x00411d21:	movl -6864(%ebp), %esi
0x00411d27:	cmpl 0x10(%ebp), %esi
0x00411d2a:	jne 0x00411d33
0x00411d33:	cmpl %eax, %esi
0x00411d35:	jne 0x00411d5e
0x00411d5e:	pushl %ebx
0x00411d5f:	pushl %edi
0x00411d60:	movl %edi, 0x8(%ebp)
0x00411d63:	movl %eax, %edi
0x00411d65:	sarl %eax, $0x5<UINT8>
0x00411d68:	leal %esi, 0x42cb20(,%eax,4)
0x00411d6f:	movl %eax, (%esi)
0x00411d71:	andl %edi, $0x1f<UINT8>
0x00411d74:	shll %edi, $0x6<UINT8>
0x00411d77:	addl %eax, %edi
0x00411d79:	movb %bl, 0x24(%eax)
0x00411d7c:	addb %bl, %bl
0x00411d7e:	sarb %bl
0x00411d80:	movl -6872(%ebp), %esi
0x00411d86:	movb -6873(%ebp), %bl
0x00411d8c:	cmpb %bl, $0x2<UINT8>
0x00411d8f:	je 5
0x00411d91:	cmpb %bl, $0x1<UINT8>
0x00411d94:	jne 0x00411dc6
0x00411dc6:	testb 0x4(%eax), $0x20<UINT8>
0x00411dca:	je 0x00411ddd
0x00411ddd:	pushl 0x8(%ebp)
0x00411de0:	call 0x0041a08f
0x00411de5:	popl %ecx
0x00411de6:	testl %eax, %eax
0x00411de8:	je 669
0x00411dee:	movl %eax, (%esi)
0x00411df0:	testb 0x4(%edi,%eax), $0xffffff80<UINT8>
0x00411df5:	je 656
0x00411dfb:	call 0x0040b66b
0x00411e00:	movl %eax, 0x6c(%eax)
0x00411e03:	xorl %ecx, %ecx
0x00411e05:	cmpl 0x14(%eax), %ecx
0x00411e08:	leal %eax, -6884(%ebp)
0x00411e0e:	sete %cl
0x00411e11:	pushl %eax
0x00411e12:	movl %eax, (%esi)
0x00411e14:	pushl (%edi,%eax)
0x00411e17:	movl -6880(%ebp), %ecx
0x00411e1d:	call GetConsoleMode@KERNEL32.dll
GetConsoleMode@KERNEL32.dll: API Node	
0x00411e23:	testl %eax, %eax
0x00411e25:	je 0x0041208b
0x0041208b:	xorl %ecx, %ecx
0x0041208d:	movl %eax, (%esi)
0x0041208f:	addl %eax, %edi
0x00412091:	testb 0x4(%eax), $0xffffff80<UINT8>
0x00412095:	je 703
0x0041209b:	movl %eax, -6860(%ebp)
0x004120a1:	movl -6848(%ebp), %ecx
0x004120a7:	testb %bl, %bl
0x004120a9:	jne 202
0x004120af:	movl -6852(%ebp), %eax
0x004120b5:	cmpl 0x10(%ebp), %ecx
0x004120b8:	jbe 800
0x004120be:	jmp 0x004120c6
0x004120c6:	movl %ecx, -6852(%ebp)
0x004120cc:	andl -6844(%ebp), $0x0<UINT8>
0x004120d3:	subl %ecx, -6860(%ebp)
0x004120d9:	leal %eax, -6840(%ebp)
0x004120df:	cmpl %ecx, 0x10(%ebp)
0x004120e2:	jae 0x0041211d
0x004120e4:	movl %edx, -6852(%ebp)
0x004120ea:	incl -6852(%ebp)
0x004120f0:	movb %dl, (%edx)
0x004120f2:	incl %ecx
0x004120f3:	cmpb %dl, $0xa<UINT8>
0x004120f6:	jne 16
0x004120f8:	incl -6864(%ebp)
0x004120fe:	movb (%eax), $0xd<UINT8>
0x00412101:	incl %eax
0x00412102:	incl -6844(%ebp)
0x00412108:	movb (%eax), %dl
0x0041210a:	incl %eax
0x0041210b:	incl -6844(%ebp)
0x00412111:	cmpl -6844(%ebp), $0x13ff<UINT32>
0x0041211b:	jb 0x004120df
0x0041211d:	movl %ebx, %eax
0x0041211f:	leal %eax, -6840(%ebp)
0x00412125:	subl %ebx, %eax
0x00412127:	pushl $0x0<UINT8>
0x00412129:	leal %eax, -6868(%ebp)
0x0041212f:	pushl %eax
0x00412130:	pushl %ebx
0x00412131:	leal %eax, -6840(%ebp)
0x00412137:	pushl %eax
0x00412138:	movl %eax, (%esi)
0x0041213a:	pushl (%edi,%eax)
0x0041213d:	call WriteFile@KERNEL32.dll
WriteFile@KERNEL32.dll: API Node	
0x00412143:	testl %eax, %eax
0x00412145:	je 578
0x0041214b:	movl %eax, -6868(%ebp)
0x00412151:	addl -6856(%ebp), %eax
0x00412157:	cmpl %eax, %ebx
0x00412159:	jl 0x00412399
0x00412399:	cmpl -6856(%ebp), $0x0<UINT8>
0x004123a0:	jne 108
0x004123a2:	cmpl -6848(%ebp), $0x0<UINT8>
0x004123a9:	je 0x004123d8
0x004123d8:	movl %esi, -6872(%ebp)
0x004123de:	movl %eax, (%esi)
0x004123e0:	testb 0x4(%edi,%eax), $0x40<UINT8>
0x004123e5:	je 15
0x004123e7:	movl %eax, -6860(%ebp)
0x004123ed:	cmpb (%eax), $0x1a<UINT8>
0x004123f0:	jne 0x004123f6
0x004123f6:	call 0x0040bd02
0x004123fb:	movl (%eax), $0x1c<UINT32>
0x00412401:	call 0x0040bd15
0x0040bd15:	call 0x0040b5f2
0x0040bd1a:	testl %eax, %eax
0x0040bd1c:	jne 0x0040bd24
0x0040bd24:	addl %eax, $0xc<UINT8>
0x0040bd27:	ret

0x00412406:	andl (%eax), $0x0<UINT8>
0x00412409:	orl %eax, $0xffffffff<UINT8>
0x0041240c:	jmp 0x0041241a
0x0041241a:	popl %edi
0x0041241b:	popl %ebx
0x0041241c:	movl %ecx, -4(%ebp)
0x0041241f:	xorl %ecx, %ebp
0x00412421:	popl %esi
0x00412422:	call 0x00406f3e
0x00412427:	leave
0x00412428:	ret

0x004124c8:	addl %esp, $0xc<UINT8>
0x004124cb:	movl -28(%ebp), %eax
0x004124ce:	jmp 0x004124e6
0x004124e6:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004124ed:	call 0x004124fb
0x004124fb:	pushl 0x8(%ebp)
0x004124fe:	call 0x0041d519
0x0041d519:	movl %edi, %edi
0x0041d51b:	pushl %ebp
0x0041d51c:	movl %ebp, %esp
0x0041d51e:	movl %eax, 0x8(%ebp)
0x0041d521:	movl %ecx, %eax
0x0041d523:	andl %eax, $0x1f<UINT8>
0x0041d526:	sarl %ecx, $0x5<UINT8>
0x0041d529:	movl %ecx, 0x42cb20(,%ecx,4)
0x0041d530:	shll %eax, $0x6<UINT8>
0x0041d533:	leal %eax, 0xc(%ecx,%eax)
0x0041d537:	pushl %eax
0x0041d538:	call LeaveCriticalSection@KERNEL32.dll
0x0041d53e:	popl %ebp
0x0041d53f:	ret

0x00412503:	popl %ecx
0x00412504:	ret

0x004124f2:	movl %eax, -28(%ebp)
0x004124f5:	call 0x0040e2fd
0x004124fa:	ret

0x004079ea:	addl %esp, $0xc<UINT8>
0x004079ed:	cmpl %eax, %edi
0x004079ef:	jne 0x00407a00
0x00407a00:	orl 0xc(%esi), $0x20<UINT8>
0x00407a04:	orl %ebx, $0xffffffff<UINT8>
0x00407a07:	popl %edi
0x00407a08:	movl %eax, 0x8(%esi)
0x00407a0b:	andl 0x4(%esi), $0x0<UINT8>
0x00407a0f:	movl (%esi), %eax
0x00407a11:	popl %esi
0x00407a12:	movl %eax, %ebx
0x00407a14:	popl %ebx
0x00407a15:	popl %ebp
0x00407a16:	ret

0x0040e7f0:	andl 0xc(%esi), $0xffffeeff<UINT32>
0x0040e7f7:	andl 0x18(%esi), $0x0<UINT8>
0x0040e7fb:	andl (%esi), $0x0<UINT8>
0x0040e7fe:	andl 0x8(%esi), $0x0<UINT8>
0x0040e802:	popl %ecx
0x0040e803:	popl %esi
0x0040e804:	popl %ebp
0x0040e805:	ret

0x00409767:	addl %esp, $0x1c<UINT8>
0x0040976a:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00409771:	call 0x0040978b
0x0040978b:	pushl %edi
0x0040978c:	call 0x00407729
0x00407729:	movl %edi, %edi
0x0040772b:	pushl %ebp
0x0040772c:	movl %ebp, %esp
0x0040772e:	movl %eax, 0x8(%ebp)
0x00407731:	movl %ecx, $0x42a200<UINT32>
0x00407736:	cmpl %eax, %ecx
0x00407738:	jb 31
0x0040773a:	cmpl %eax, $0x42a460<UINT32>
0x0040773f:	ja 24
0x00407741:	andl 0xc(%eax), $0xffff7fff<UINT32>
0x00407748:	subl %eax, %ecx
0x0040774a:	sarl %eax, $0x5<UINT8>
0x0040774d:	addl %eax, $0x10<UINT8>
0x00407750:	pushl %eax
0x00407751:	call 0x0040d173
0x00407756:	popl %ecx
0x00407757:	popl %ebp
0x00407758:	ret

0x00409791:	popl %ecx
0x00409792:	ret

0x00409776:	xorl %eax, %eax
0x00409778:	movl %ecx, -28(%ebp)
0x0040977b:	cmpl -32(%ebp), %ecx
0x0040977e:	sete %al
0x00409781:	decl %eax
0x00409782:	call 0x0040e2fd
0x00409787:	ret

0x00405926:	call 0x004075df
0x0040592b:	addl %eax, $0x40<UINT8>
0x0040592e:	pushl %eax
0x0040592f:	pushl %edi
0x00405930:	call 0x00409684
0x0040969e:	call 0x0040bd02
0x004096a3:	movl (%eax), $0x16<UINT32>
0x004096a9:	pushl %esi
0x004096aa:	pushl %esi
0x004096ab:	pushl %esi
0x004096ac:	pushl %esi
0x004096ad:	pushl %esi
0x004096ae:	call 0x0040bc7f
0x0040bc7f:	movl %edi, %edi
0x0040bc81:	pushl %ebp
0x0040bc82:	movl %ebp, %esp
0x0040bc84:	pushl 0x42bdc4
0x0040bc8a:	call 0x0040b3e2
0x0040bc8f:	popl %ecx
0x0040bc90:	testl %eax, %eax
0x0040bc92:	je 0x0040bc97
0x0040bc97:	pushl $0x2<UINT8>
0x0040bc99:	call 0x00419ea0
0x00419ea0:	andl 0x42cafc, $0x0<UINT8>
0x00419ea7:	ret

0x0040bc9e:	popl %ecx
0x0040bc9f:	popl %ebp
0x0040bca0:	jmp 0x0040bb18
0x0040bb18:	movl %edi, %edi
0x0040bb1a:	pushl %ebp
0x0040bb1b:	movl %ebp, %esp
0x0040bb1d:	subl %esp, $0x328<UINT32>
0x0040bb23:	movl %eax, 0x42a1f0
0x0040bb28:	xorl %eax, %ebp
0x0040bb2a:	movl -4(%ebp), %eax
0x0040bb2d:	andl -808(%ebp), $0x0<UINT8>
0x0040bb34:	pushl %ebx
0x0040bb35:	pushl $0x4c<UINT8>
0x0040bb37:	leal %eax, -804(%ebp)
0x0040bb3d:	pushl $0x0<UINT8>
0x0040bb3f:	pushl %eax
0x0040bb40:	call 0x00407140
0x0040bb45:	leal %eax, -808(%ebp)
0x0040bb4b:	movl -728(%ebp), %eax
0x0040bb51:	leal %eax, -720(%ebp)
0x0040bb57:	addl %esp, $0xc<UINT8>
0x0040bb5a:	movl -724(%ebp), %eax
0x0040bb60:	movl -544(%ebp), %eax
0x0040bb66:	movl -548(%ebp), %ecx
0x0040bb6c:	movl -552(%ebp), %edx
0x0040bb72:	movl -556(%ebp), %ebx
0x0040bb78:	movl -560(%ebp), %esi
0x0040bb7e:	movl -564(%ebp), %edi
0x0040bb84:	movw -520(%ebp), %ss
0x0040bb8b:	movw -532(%ebp), %cs
0x0040bb92:	movw -568(%ebp), %ds
0x0040bb99:	movw -572(%ebp), %es
0x0040bba0:	movw -576(%ebp), %fs
0x0040bba7:	movw -580(%ebp), %gs
0x0040bbae:	pushfl
0x0040bbaf:	popl -528(%ebp)
0x0040bbb5:	movl %eax, 0x4(%ebp)
0x0040bbb8:	leal %ecx, 0x4(%ebp)
0x0040bbbb:	movl -720(%ebp), $0x10001<UINT32>
0x0040bbc5:	movl -536(%ebp), %eax
0x0040bbcb:	movl -524(%ebp), %ecx
0x0040bbd1:	movl %ecx, -4(%ecx)
0x0040bbd4:	movl -540(%ebp), %ecx
0x0040bbda:	movl -808(%ebp), $0xc0000417<UINT32>
0x0040bbe4:	movl -804(%ebp), $0x1<UINT32>
0x0040bbee:	movl -796(%ebp), %eax
0x0040bbf4:	call IsDebuggerPresent@KERNEL32.dll
IsDebuggerPresent@KERNEL32.dll: API Node	
0x0040bbfa:	pushl $0x0<UINT8>
0x0040bbfc:	movl %ebx, %eax
0x0040bbfe:	call SetUnhandledExceptionFilter@KERNEL32.dll
0x0040bc04:	leal %eax, -728(%ebp)
0x0040bc0a:	pushl %eax
0x0040bc0b:	call UnhandledExceptionFilter@KERNEL32.dll
UnhandledExceptionFilter@KERNEL32.dll: API Node	
0x0040bc11:	testl %eax, %eax
0x0040bc13:	jne 0x0040bc21
0x0040bc21:	pushl $0xc0000417<UINT32>
0x0040bc26:	call GetCurrentProcess@KERNEL32.dll
GetCurrentProcess@KERNEL32.dll: API Node	
0x0040bc2c:	pushl %eax
0x0040bc2d:	call TerminateProcess@KERNEL32.dll
TerminateProcess@KERNEL32.dll: API Node	
0x0040bc33:	movl %ecx, -4(%ebp)
0x00406344:	xorl %eax, %eax
0x00406346:	incl %eax
