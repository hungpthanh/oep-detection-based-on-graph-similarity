0x0042a200:	pusha
0x0042a201:	movl %esi, $0x41c000<UINT32>
0x0042a206:	leal %edi, -110592(%esi)
0x0042a20c:	pushl %edi
0x0042a20d:	orl %ebp, $0xffffffff<UINT8>
0x0042a210:	jmp 0x0042a222
0x0042a222:	movl %ebx, (%esi)
0x0042a224:	subl %esi, $0xfffffffc<UINT8>
0x0042a227:	adcl %ebx, %ebx
0x0042a229:	jb 0x0042a218
0x0042a218:	movb %al, (%esi)
0x0042a21a:	incl %esi
0x0042a21b:	movb (%edi), %al
0x0042a21d:	incl %edi
0x0042a21e:	addl %ebx, %ebx
0x0042a220:	jne 0x0042a229
0x0042a22b:	movl %eax, $0x1<UINT32>
0x0042a230:	addl %ebx, %ebx
0x0042a232:	jne 0x0042a23b
0x0042a23b:	adcl %eax, %eax
0x0042a23d:	addl %ebx, %ebx
0x0042a23f:	jae 0x0042a230
0x0042a241:	jne 0x0042a24c
0x0042a24c:	xorl %ecx, %ecx
0x0042a24e:	subl %eax, $0x3<UINT8>
0x0042a251:	jb 0x0042a260
0x0042a260:	addl %ebx, %ebx
0x0042a262:	jne 0x0042a26b
0x0042a26b:	adcl %ecx, %ecx
0x0042a26d:	addl %ebx, %ebx
0x0042a26f:	jne 0x0042a278
0x0042a278:	adcl %ecx, %ecx
0x0042a27a:	jne 0x0042a29c
0x0042a29c:	cmpl %ebp, $0xfffff300<UINT32>
0x0042a2a2:	adcl %ecx, $0x1<UINT8>
0x0042a2a5:	leal %edx, (%edi,%ebp)
0x0042a2a8:	cmpl %ebp, $0xfffffffc<UINT8>
0x0042a2ab:	jbe 0x0042a2bc
0x0042a2ad:	movb %al, (%edx)
0x0042a2af:	incl %edx
0x0042a2b0:	movb (%edi), %al
0x0042a2b2:	incl %edi
0x0042a2b3:	decl %ecx
0x0042a2b4:	jne 0x0042a2ad
0x0042a2b6:	jmp 0x0042a21e
0x0042a253:	shll %eax, $0x8<UINT8>
0x0042a256:	movb %al, (%esi)
0x0042a258:	incl %esi
0x0042a259:	xorl %eax, $0xffffffff<UINT8>
0x0042a25c:	je 0x0042a2d2
0x0042a25e:	movl %ebp, %eax
0x0042a2bc:	movl %eax, (%edx)
0x0042a2be:	addl %edx, $0x4<UINT8>
0x0042a2c1:	movl (%edi), %eax
0x0042a2c3:	addl %edi, $0x4<UINT8>
0x0042a2c6:	subl %ecx, $0x4<UINT8>
0x0042a2c9:	ja 0x0042a2bc
0x0042a2cb:	addl %edi, %ecx
0x0042a2cd:	jmp 0x0042a21e
0x0042a264:	movl %ebx, (%esi)
0x0042a266:	subl %esi, $0xfffffffc<UINT8>
0x0042a269:	adcl %ebx, %ebx
0x0042a27c:	incl %ecx
0x0042a27d:	addl %ebx, %ebx
0x0042a27f:	jne 0x0042a288
0x0042a288:	adcl %ecx, %ecx
0x0042a28a:	addl %ebx, %ebx
0x0042a28c:	jae 0x0042a27d
0x0042a28e:	jne 0x0042a299
0x0042a299:	addl %ecx, $0x2<UINT8>
0x0042a271:	movl %ebx, (%esi)
0x0042a273:	subl %esi, $0xfffffffc<UINT8>
0x0042a276:	adcl %ebx, %ebx
0x0042a243:	movl %ebx, (%esi)
0x0042a245:	subl %esi, $0xfffffffc<UINT8>
0x0042a248:	adcl %ebx, %ebx
0x0042a24a:	jae 0x0042a230
0x0042a234:	movl %ebx, (%esi)
0x0042a236:	subl %esi, $0xfffffffc<UINT8>
0x0042a239:	adcl %ebx, %ebx
0x0042a290:	movl %ebx, (%esi)
0x0042a292:	subl %esi, $0xfffffffc<UINT8>
0x0042a295:	adcl %ebx, %ebx
0x0042a297:	jae 0x0042a27d
0x0042a281:	movl %ebx, (%esi)
0x0042a283:	subl %esi, $0xfffffffc<UINT8>
0x0042a286:	adcl %ebx, %ebx
0x0042a2d2:	popl %esi
0x0042a2d3:	movl %edi, %esi
0x0042a2d5:	movl %ecx, $0x6ed<UINT32>
0x0042a2da:	movb %al, (%edi)
0x0042a2dc:	incl %edi
0x0042a2dd:	subb %al, $0xffffffe8<UINT8>
0x0042a2df:	cmpb %al, $0x1<UINT8>
0x0042a2e1:	ja 0x0042a2da
0x0042a2e3:	cmpb (%edi), $0x5<UINT8>
0x0042a2e6:	jne 0x0042a2da
0x0042a2e8:	movl %eax, (%edi)
0x0042a2ea:	movb %bl, 0x4(%edi)
0x0042a2ed:	shrw %ax, $0x8<UINT8>
0x0042a2f1:	roll %eax, $0x10<UINT8>
0x0042a2f4:	xchgb %ah, %al
0x0042a2f6:	subl %eax, %edi
0x0042a2f8:	subb %bl, $0xffffffe8<UINT8>
0x0042a2fb:	addl %eax, %esi
0x0042a2fd:	movl (%edi), %eax
0x0042a2ff:	addl %edi, $0x5<UINT8>
0x0042a302:	movb %al, %bl
0x0042a304:	loop 0x0042a2df
0x0042a306:	leal %edi, 0x27000(%esi)
0x0042a30c:	movl %eax, (%edi)
0x0042a30e:	orl %eax, %eax
0x0042a310:	je 0x0042a357
0x0042a312:	movl %ebx, 0x4(%edi)
0x0042a315:	leal %eax, 0x2a54c(%eax,%esi)
0x0042a31c:	addl %ebx, %esi
0x0042a31e:	pushl %eax
0x0042a31f:	addl %edi, $0x8<UINT8>
0x0042a322:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x0042a328:	xchgl %ebp, %eax
0x0042a329:	movb %al, (%edi)
0x0042a32b:	incl %edi
0x0042a32c:	orb %al, %al
0x0042a32e:	je 0x0042a30c
0x0042a330:	movl %ecx, %edi
0x0042a332:	jns 0x0042a33b
0x0042a33b:	pushl %edi
0x0042a33c:	decl %eax
0x0042a33d:	repn scasb %al, %es:(%edi)
0x0042a33f:	pushl %ebp
0x0042a340:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0042a346:	orl %eax, %eax
0x0042a348:	je 7
0x0042a34a:	movl (%ebx), %eax
0x0042a34c:	addl %ebx, $0x4<UINT8>
0x0042a34f:	jmp 0x0042a329
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x0042a334:	movzwl %eax, (%edi)
0x0042a337:	incl %edi
0x0042a338:	pushl %eax
0x0042a339:	incl %edi
0x0042a33a:	movl %ecx, $0xaef24857<UINT32>
0x0042a357:	addl %edi, $0x4<UINT8>
0x0042a35a:	leal %ebx, -4(%esi)
0x0042a35d:	xorl %eax, %eax
0x0042a35f:	movb %al, (%edi)
0x0042a361:	incl %edi
0x0042a362:	orl %eax, %eax
0x0042a364:	je 0x0042a388
0x0042a366:	cmpb %al, $0xffffffef<UINT8>
0x0042a368:	ja 0x0042a37b
0x0042a36a:	addl %ebx, %eax
0x0042a36c:	movl %eax, (%ebx)
0x0042a36e:	xchgb %ah, %al
0x0042a370:	roll %eax, $0x10<UINT8>
0x0042a373:	xchgb %ah, %al
0x0042a375:	addl %eax, %esi
0x0042a377:	movl (%ebx), %eax
0x0042a379:	jmp 0x0042a35d
0x0042a37b:	andb %al, $0xf<UINT8>
0x0042a37d:	shll %eax, $0x10<UINT8>
0x0042a380:	movw %ax, (%edi)
0x0042a383:	addl %edi, $0x2<UINT8>
0x0042a386:	jmp 0x0042a36a
0x0042a388:	movl %ebp, 0x2a610(%esi)
0x0042a38e:	leal %edi, -4096(%esi)
0x0042a394:	movl %ebx, $0x1000<UINT32>
0x0042a399:	pushl %eax
0x0042a39a:	pushl %esp
0x0042a39b:	pushl $0x4<UINT8>
0x0042a39d:	pushl %ebx
0x0042a39e:	pushl %edi
0x0042a39f:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0042a3a1:	leal %eax, 0x21f(%edi)
0x0042a3a7:	andb (%eax), $0x7f<UINT8>
0x0042a3aa:	andb 0x28(%eax), $0x7f<UINT8>
0x0042a3ae:	popl %eax
0x0042a3af:	pushl %eax
0x0042a3b0:	pushl %esp
0x0042a3b1:	pushl %eax
0x0042a3b2:	pushl %ebx
0x0042a3b3:	pushl %edi
0x0042a3b4:	call VirtualProtect@kernel32.dll
0x0042a3b6:	popl %eax
0x0042a3b7:	popa
0x0042a3b8:	leal %eax, -128(%esp)
0x0042a3bc:	pushl $0x0<UINT8>
0x0042a3be:	cmpl %esp, %eax
0x0042a3c0:	jne 0x0042a3bc
0x0042a3c2:	subl %esp, $0xffffff80<UINT8>
0x0042a3c5:	jmp 0x00405536
0x00405536:	call 0x0040c681
0x0040c681:	pushl %ebp
0x0040c682:	movl %ebp, %esp
0x0040c684:	subl %esp, $0x14<UINT8>
0x0040c687:	andl -12(%ebp), $0x0<UINT8>
0x0040c68b:	andl -8(%ebp), $0x0<UINT8>
0x0040c68f:	movl %eax, 0x421428
0x0040c694:	pushl %esi
0x0040c695:	pushl %edi
0x0040c696:	movl %edi, $0xbb40e64e<UINT32>
0x0040c69b:	movl %esi, $0xffff0000<UINT32>
0x0040c6a0:	cmpl %eax, %edi
0x0040c6a2:	je 0x0040c6b1
0x0040c6b1:	leal %eax, -12(%ebp)
0x0040c6b4:	pushl %eax
0x0040c6b5:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040c6bb:	movl %eax, -8(%ebp)
0x0040c6be:	xorl %eax, -12(%ebp)
0x0040c6c1:	movl -4(%ebp), %eax
0x0040c6c4:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040c6ca:	xorl -4(%ebp), %eax
0x0040c6cd:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040c6d3:	xorl -4(%ebp), %eax
0x0040c6d6:	leal %eax, -20(%ebp)
0x0040c6d9:	pushl %eax
0x0040c6da:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040c6e0:	movl %ecx, -16(%ebp)
0x0040c6e3:	leal %eax, -4(%ebp)
0x0040c6e6:	xorl %ecx, -20(%ebp)
0x0040c6e9:	xorl %ecx, -4(%ebp)
0x0040c6ec:	xorl %ecx, %eax
0x0040c6ee:	cmpl %ecx, %edi
0x0040c6f0:	jne 0x0040c6f9
0x0040c6f9:	testl %esi, %ecx
0x0040c6fb:	jne 0x0040c709
0x0040c709:	movl 0x421428, %ecx
0x0040c70f:	notl %ecx
0x0040c711:	movl 0x42142c, %ecx
0x0040c717:	popl %edi
0x0040c718:	popl %esi
0x0040c719:	movl %esp, %ebp
0x0040c71b:	popl %ebp
0x0040c71c:	ret

0x0040553b:	jmp 0x004053bb
0x004053bb:	pushl $0x14<UINT8>
0x004053bd:	pushl $0x41fa88<UINT32>
0x004053c2:	call 0x004062c0
0x004062c0:	pushl $0x406320<UINT32>
0x004062c5:	pushl %fs:0
0x004062cc:	movl %eax, 0x10(%esp)
0x004062d0:	movl 0x10(%esp), %ebp
0x004062d4:	leal %ebp, 0x10(%esp)
0x004062d8:	subl %esp, %eax
0x004062da:	pushl %ebx
0x004062db:	pushl %esi
0x004062dc:	pushl %edi
0x004062dd:	movl %eax, 0x421428
0x004062e2:	xorl -4(%ebp), %eax
0x004062e5:	xorl %eax, %ebp
0x004062e7:	pushl %eax
0x004062e8:	movl -24(%ebp), %esp
0x004062eb:	pushl -8(%ebp)
0x004062ee:	movl %eax, -4(%ebp)
0x004062f1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004062f8:	movl -8(%ebp), %eax
0x004062fb:	leal %eax, -16(%ebp)
0x004062fe:	movl %fs:0, %eax
0x00406304:	ret

0x004053c7:	pushl $0x1<UINT8>
0x004053c9:	call 0x0040c634
0x0040c634:	pushl %ebp
0x0040c635:	movl %ebp, %esp
0x0040c637:	movl %eax, 0x8(%ebp)
0x0040c63a:	movl 0x422630, %eax
0x0040c63f:	popl %ebp
0x0040c640:	ret

0x004053ce:	popl %ecx
0x004053cf:	movl %eax, $0x5a4d<UINT32>
0x004053d4:	cmpw 0x400000, %ax
0x004053db:	je 0x004053e1
0x004053e1:	movl %eax, 0x40003c
0x004053e6:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x004053f0:	jne -21
0x004053f2:	movl %ecx, $0x10b<UINT32>
0x004053f7:	cmpw 0x400018(%eax), %cx
0x004053fe:	jne -35
0x00405400:	xorl %ebx, %ebx
0x00405402:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00405409:	jbe 9
0x0040540b:	cmpl 0x4000e8(%eax), %ebx
0x00405411:	setne %bl
0x00405414:	movl -28(%ebp), %ebx
0x00405417:	call 0x00408ef9
0x00408ef9:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x00408eff:	xorl %ecx, %ecx
0x00408f01:	movl 0x422c68, %eax
0x00408f06:	testl %eax, %eax
0x00408f08:	setne %cl
0x00408f0b:	movl %eax, %ecx
0x00408f0d:	ret

0x0040541c:	testl %eax, %eax
0x0040541e:	jne 0x00405428
0x00405428:	call 0x00409edf
0x00409edf:	call 0x00403db5
0x00403db5:	pushl %esi
0x00403db6:	pushl $0x0<UINT8>
0x00403db8:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00403dbe:	movl %esi, %eax
0x00403dc0:	pushl %esi
0x00403dc1:	call 0x00408eec
0x00408eec:	pushl %ebp
0x00408eed:	movl %ebp, %esp
0x00408eef:	movl %eax, 0x8(%ebp)
0x00408ef2:	movl 0x422c60, %eax
0x00408ef7:	popl %ebp
0x00408ef8:	ret

0x00403dc6:	pushl %esi
0x00403dc7:	call 0x004065d9
0x004065d9:	pushl %ebp
0x004065da:	movl %ebp, %esp
0x004065dc:	movl %eax, 0x8(%ebp)
0x004065df:	movl 0x42251c, %eax
0x004065e4:	popl %ebp
0x004065e5:	ret

0x00403dcc:	pushl %esi
0x00403dcd:	call 0x0040a4d5
0x0040a4d5:	pushl %ebp
0x0040a4d6:	movl %ebp, %esp
0x0040a4d8:	movl %eax, 0x8(%ebp)
0x0040a4db:	movl 0x422fb0, %eax
0x0040a4e0:	popl %ebp
0x0040a4e1:	ret

0x00403dd2:	pushl %esi
0x00403dd3:	call 0x0040a4ef
0x0040a4ef:	pushl %ebp
0x0040a4f0:	movl %ebp, %esp
0x0040a4f2:	movl %eax, 0x8(%ebp)
0x0040a4f5:	movl 0x422fb4, %eax
0x0040a4fa:	movl 0x422fb8, %eax
0x0040a4ff:	movl 0x422fbc, %eax
0x0040a504:	movl 0x422fc0, %eax
0x0040a509:	popl %ebp
0x0040a50a:	ret

0x00403dd8:	pushl %esi
0x00403dd9:	call 0x0040a4c4
0x0040a4c4:	pushl $0x40a490<UINT32>
0x0040a4c9:	call EncodePointer@KERNEL32.DLL
0x0040a4cf:	movl 0x422fac, %eax
0x0040a4d4:	ret

0x00403dde:	pushl %esi
0x00403ddf:	call 0x0040a700
0x0040a700:	pushl %ebp
0x0040a701:	movl %ebp, %esp
0x0040a703:	movl %eax, 0x8(%ebp)
0x0040a706:	movl 0x422fc8, %eax
0x0040a70b:	popl %ebp
0x0040a70c:	ret

0x00403de4:	addl %esp, $0x18<UINT8>
0x00403de7:	popl %esi
0x00403de8:	jmp 0x004089da
0x004089da:	pushl %esi
0x004089db:	pushl %edi
0x004089dc:	pushl $0x41bd3c<UINT32>
0x004089e1:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x004089e7:	movl %esi, 0x41505c
0x004089ed:	movl %edi, %eax
0x004089ef:	pushl $0x41bd58<UINT32>
0x004089f4:	pushl %edi
0x004089f5:	call GetProcAddress@KERNEL32.DLL
0x004089f7:	xorl %eax, 0x421428
0x004089fd:	pushl $0x41bd64<UINT32>
0x00408a02:	pushl %edi
0x00408a03:	movl 0x423120, %eax
0x00408a08:	call GetProcAddress@KERNEL32.DLL
0x00408a0a:	xorl %eax, 0x421428
0x00408a10:	pushl $0x41bd6c<UINT32>
0x00408a15:	pushl %edi
0x00408a16:	movl 0x423124, %eax
0x00408a1b:	call GetProcAddress@KERNEL32.DLL
0x00408a1d:	xorl %eax, 0x421428
0x00408a23:	pushl $0x41bd78<UINT32>
0x00408a28:	pushl %edi
0x00408a29:	movl 0x423128, %eax
0x00408a2e:	call GetProcAddress@KERNEL32.DLL
0x00408a30:	xorl %eax, 0x421428
0x00408a36:	pushl $0x41bd84<UINT32>
0x00408a3b:	pushl %edi
0x00408a3c:	movl 0x42312c, %eax
0x00408a41:	call GetProcAddress@KERNEL32.DLL
0x00408a43:	xorl %eax, 0x421428
0x00408a49:	pushl $0x41bda0<UINT32>
0x00408a4e:	pushl %edi
0x00408a4f:	movl 0x423130, %eax
0x00408a54:	call GetProcAddress@KERNEL32.DLL
0x00408a56:	xorl %eax, 0x421428
0x00408a5c:	pushl $0x41bdb0<UINT32>
0x00408a61:	pushl %edi
0x00408a62:	movl 0x423134, %eax
0x00408a67:	call GetProcAddress@KERNEL32.DLL
0x00408a69:	xorl %eax, 0x421428
0x00408a6f:	pushl $0x41bdc4<UINT32>
0x00408a74:	pushl %edi
0x00408a75:	movl 0x423138, %eax
0x00408a7a:	call GetProcAddress@KERNEL32.DLL
0x00408a7c:	xorl %eax, 0x421428
0x00408a82:	pushl $0x41bddc<UINT32>
0x00408a87:	pushl %edi
0x00408a88:	movl 0x42313c, %eax
0x00408a8d:	call GetProcAddress@KERNEL32.DLL
0x00408a8f:	xorl %eax, 0x421428
0x00408a95:	pushl $0x41bdf4<UINT32>
0x00408a9a:	pushl %edi
0x00408a9b:	movl 0x423140, %eax
0x00408aa0:	call GetProcAddress@KERNEL32.DLL
0x00408aa2:	xorl %eax, 0x421428
0x00408aa8:	pushl $0x41be08<UINT32>
0x00408aad:	pushl %edi
0x00408aae:	movl 0x423144, %eax
0x00408ab3:	call GetProcAddress@KERNEL32.DLL
0x00408ab5:	xorl %eax, 0x421428
0x00408abb:	pushl $0x41be28<UINT32>
0x00408ac0:	pushl %edi
0x00408ac1:	movl 0x423148, %eax
0x00408ac6:	call GetProcAddress@KERNEL32.DLL
0x00408ac8:	xorl %eax, 0x421428
0x00408ace:	pushl $0x41be40<UINT32>
0x00408ad3:	pushl %edi
0x00408ad4:	movl 0x42314c, %eax
0x00408ad9:	call GetProcAddress@KERNEL32.DLL
0x00408adb:	xorl %eax, 0x421428
0x00408ae1:	pushl $0x41be58<UINT32>
0x00408ae6:	pushl %edi
0x00408ae7:	movl 0x423150, %eax
0x00408aec:	call GetProcAddress@KERNEL32.DLL
0x00408aee:	xorl %eax, 0x421428
0x00408af4:	pushl $0x41be6c<UINT32>
0x00408af9:	pushl %edi
0x00408afa:	movl 0x423154, %eax
0x00408aff:	call GetProcAddress@KERNEL32.DLL
0x00408b01:	xorl %eax, 0x421428
0x00408b07:	movl 0x423158, %eax
0x00408b0c:	pushl $0x41be80<UINT32>
0x00408b11:	pushl %edi
0x00408b12:	call GetProcAddress@KERNEL32.DLL
0x00408b14:	xorl %eax, 0x421428
0x00408b1a:	pushl $0x41be9c<UINT32>
0x00408b1f:	pushl %edi
0x00408b20:	movl 0x42315c, %eax
0x00408b25:	call GetProcAddress@KERNEL32.DLL
0x00408b27:	xorl %eax, 0x421428
0x00408b2d:	pushl $0x41bebc<UINT32>
0x00408b32:	pushl %edi
0x00408b33:	movl 0x423160, %eax
0x00408b38:	call GetProcAddress@KERNEL32.DLL
0x00408b3a:	xorl %eax, 0x421428
0x00408b40:	pushl $0x41bed8<UINT32>
0x00408b45:	pushl %edi
0x00408b46:	movl 0x423164, %eax
0x00408b4b:	call GetProcAddress@KERNEL32.DLL
0x00408b4d:	xorl %eax, 0x421428
0x00408b53:	pushl $0x41bef8<UINT32>
0x00408b58:	pushl %edi
0x00408b59:	movl 0x423168, %eax
0x00408b5e:	call GetProcAddress@KERNEL32.DLL
0x00408b60:	xorl %eax, 0x421428
0x00408b66:	pushl $0x41bf0c<UINT32>
0x00408b6b:	pushl %edi
0x00408b6c:	movl 0x42316c, %eax
0x00408b71:	call GetProcAddress@KERNEL32.DLL
0x00408b73:	xorl %eax, 0x421428
0x00408b79:	pushl $0x41bf28<UINT32>
0x00408b7e:	pushl %edi
0x00408b7f:	movl 0x423170, %eax
0x00408b84:	call GetProcAddress@KERNEL32.DLL
0x00408b86:	xorl %eax, 0x421428
0x00408b8c:	pushl $0x41bf3c<UINT32>
0x00408b91:	pushl %edi
0x00408b92:	movl 0x423178, %eax
0x00408b97:	call GetProcAddress@KERNEL32.DLL
0x00408b99:	xorl %eax, 0x421428
0x00408b9f:	pushl $0x41bf4c<UINT32>
0x00408ba4:	pushl %edi
0x00408ba5:	movl 0x423174, %eax
0x00408baa:	call GetProcAddress@KERNEL32.DLL
0x00408bac:	xorl %eax, 0x421428
0x00408bb2:	pushl $0x41bf5c<UINT32>
0x00408bb7:	pushl %edi
0x00408bb8:	movl 0x42317c, %eax
0x00408bbd:	call GetProcAddress@KERNEL32.DLL
0x00408bbf:	xorl %eax, 0x421428
0x00408bc5:	pushl $0x41bf6c<UINT32>
0x00408bca:	pushl %edi
0x00408bcb:	movl 0x423180, %eax
0x00408bd0:	call GetProcAddress@KERNEL32.DLL
0x00408bd2:	xorl %eax, 0x421428
0x00408bd8:	pushl $0x41bf7c<UINT32>
0x00408bdd:	pushl %edi
0x00408bde:	movl 0x423184, %eax
0x00408be3:	call GetProcAddress@KERNEL32.DLL
0x00408be5:	xorl %eax, 0x421428
0x00408beb:	pushl $0x41bf98<UINT32>
0x00408bf0:	pushl %edi
0x00408bf1:	movl 0x423188, %eax
0x00408bf6:	call GetProcAddress@KERNEL32.DLL
0x00408bf8:	xorl %eax, 0x421428
0x00408bfe:	pushl $0x41bfac<UINT32>
0x00408c03:	pushl %edi
0x00408c04:	movl 0x42318c, %eax
0x00408c09:	call GetProcAddress@KERNEL32.DLL
0x00408c0b:	xorl %eax, 0x421428
0x00408c11:	pushl $0x41bfbc<UINT32>
0x00408c16:	pushl %edi
0x00408c17:	movl 0x423190, %eax
0x00408c1c:	call GetProcAddress@KERNEL32.DLL
0x00408c1e:	xorl %eax, 0x421428
0x00408c24:	pushl $0x41bfd0<UINT32>
0x00408c29:	pushl %edi
0x00408c2a:	movl 0x423194, %eax
0x00408c2f:	call GetProcAddress@KERNEL32.DLL
0x00408c31:	xorl %eax, 0x421428
0x00408c37:	movl 0x423198, %eax
0x00408c3c:	pushl $0x41bfe0<UINT32>
0x00408c41:	pushl %edi
0x00408c42:	call GetProcAddress@KERNEL32.DLL
0x00408c44:	xorl %eax, 0x421428
0x00408c4a:	pushl $0x41c000<UINT32>
0x00408c4f:	pushl %edi
0x00408c50:	movl 0x42319c, %eax
0x00408c55:	call GetProcAddress@KERNEL32.DLL
0x00408c57:	xorl %eax, 0x421428
0x00408c5d:	popl %edi
0x00408c5e:	movl 0x4231a0, %eax
0x00408c63:	popl %esi
0x00408c64:	ret

0x00409ee4:	call 0x0040570e
0x0040570e:	pushl %esi
0x0040570f:	pushl %edi
0x00405710:	movl %esi, $0x421440<UINT32>
0x00405715:	movl %edi, $0x4223c8<UINT32>
0x0040571a:	cmpl 0x4(%esi), $0x1<UINT8>
0x0040571e:	jne 22
0x00405720:	pushl $0x0<UINT8>
0x00405722:	movl (%esi), %edi
0x00405724:	addl %edi, $0x18<UINT8>
0x00405727:	pushl $0xfa0<UINT32>
0x0040572c:	pushl (%esi)
0x0040572e:	call 0x0040896c
0x0040896c:	pushl %ebp
0x0040896d:	movl %ebp, %esp
0x0040896f:	movl %eax, 0x423130
0x00408974:	xorl %eax, 0x421428
0x0040897a:	je 13
0x0040897c:	pushl 0x10(%ebp)
0x0040897f:	pushl 0xc(%ebp)
0x00408982:	pushl 0x8(%ebp)
0x00408985:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x00408987:	popl %ebp
0x00408988:	ret

0x00000fa0:	addb (%eax), %al
0x00000fa2:	addb (%eax), %al
0x00000fa4:	addb (%eax), %al
0x00000fa6:	addb (%eax), %al
0x00000fa8:	addb (%eax), %al
0x00000faa:	addb (%eax), %al
0x00000fac:	addb (%eax), %al
0x00000fae:	addb (%eax), %al
0x00000fb0:	addb (%eax), %al
0x00000fb2:	addb (%eax), %al
0x00000fb4:	addb (%eax), %al
0x00000fb6:	addb (%eax), %al
0x00000fb8:	addb (%eax), %al
0x00000fba:	addb (%eax), %al
0x00000fbc:	addb (%eax), %al
0x00000fbe:	addb (%eax), %al
0x00000fc0:	addb (%eax), %al
0x00000fc2:	addb (%eax), %al
0x00000fc4:	addb (%eax), %al
0x00000fc6:	addb (%eax), %al
0x00000fc8:	addb (%eax), %al
0x00000fca:	addb (%eax), %al
0x00000fcc:	addb (%eax), %al
0x00000fce:	addb (%eax), %al
0x00000fd0:	addb (%eax), %al
0x00000fd2:	addb (%eax), %al
0x00000fd4:	addb (%eax), %al
0x00000fd6:	addb (%eax), %al
0x00000fd8:	addb (%eax), %al
0x00000fda:	addb (%eax), %al
0x00000fdc:	addb (%eax), %al
0x00000fde:	addb (%eax), %al
0x00000fe0:	addb (%eax), %al
0x00000fe2:	addb (%eax), %al
0x00000fe4:	addb (%eax), %al
0x00000fe6:	addb (%eax), %al
0x00000fe8:	addb (%eax), %al
0x00000fea:	addb (%eax), %al
0x00000fec:	addb (%eax), %al
0x00000fee:	addb (%eax), %al
0x00000ff0:	addb (%eax), %al
0x00000ff2:	addb (%eax), %al
0x00000ff4:	addb (%eax), %al
0x00000ff6:	addb (%eax), %al
0x00000ff8:	addb (%eax), %al
0x00000ffa:	addb (%eax), %al
0x00000ffc:	addb (%eax), %al
0x00000ffe:	addb (%eax), %al
0x00001000:	addb (%eax), %al
0x00001002:	addb (%eax), %al
0x00001004:	addb (%eax), %al
0x00001006:	addb (%eax), %al
