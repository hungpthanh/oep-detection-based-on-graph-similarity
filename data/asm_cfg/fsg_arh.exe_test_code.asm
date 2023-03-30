0x0041f000:	movl %ebx, $0x4001d0<UINT32>
0x0041f005:	movl %edi, $0x401000<UINT32>
0x0041f00a:	movl %esi, $0x4161fa<UINT32>
0x0041f00f:	pushl %ebx
0x0041f010:	call 0x0041f01f
0x0041f01f:	cld
0x0041f020:	movb %dl, $0xffffff80<UINT8>
0x0041f022:	movsb %es:(%edi), %ds:(%esi)
0x0041f023:	pushl $0x2<UINT8>
0x0041f025:	popl %ebx
0x0041f026:	call 0x0041f015
0x0041f015:	addb %dl, %dl
0x0041f017:	jne 0x0041f01e
0x0041f019:	movb %dl, (%esi)
0x0041f01b:	incl %esi
0x0041f01c:	adcb %dl, %dl
0x0041f01e:	ret

0x0041f029:	jae 0x0041f022
0x0041f02b:	xorl %ecx, %ecx
0x0041f02d:	call 0x0041f015
0x0041f030:	jae 0x0041f04a
0x0041f032:	xorl %eax, %eax
0x0041f034:	call 0x0041f015
0x0041f037:	jae 0x0041f05a
0x0041f039:	movb %bl, $0x2<UINT8>
0x0041f03b:	incl %ecx
0x0041f03c:	movb %al, $0x10<UINT8>
0x0041f03e:	call 0x0041f015
0x0041f041:	adcb %al, %al
0x0041f043:	jae 0x0041f03e
0x0041f045:	jne 0x0041f086
0x0041f086:	pushl %esi
0x0041f087:	movl %esi, %edi
0x0041f089:	subl %esi, %eax
0x0041f08b:	rep movsb %es:(%edi), %ds:(%esi)
0x0041f08d:	popl %esi
0x0041f08e:	jmp 0x0041f026
0x0041f047:	stosb %es:(%edi), %al
0x0041f048:	jmp 0x0041f026
0x0041f05a:	lodsb %al, %ds:(%esi)
0x0041f05b:	shrl %eax
0x0041f05d:	je 0x0041f0a0
0x0041f05f:	adcl %ecx, %ecx
0x0041f061:	jmp 0x0041f07f
0x0041f07f:	incl %ecx
0x0041f080:	incl %ecx
0x0041f081:	xchgl %ebp, %eax
0x0041f082:	movl %eax, %ebp
0x0041f084:	movb %bl, $0x1<UINT8>
0x0041f04a:	call 0x0041f092
0x0041f092:	incl %ecx
0x0041f093:	call 0x0041f015
0x0041f097:	adcl %ecx, %ecx
0x0041f099:	call 0x0041f015
0x0041f09d:	jb 0x0041f093
0x0041f09f:	ret

0x0041f04f:	subl %ecx, %ebx
0x0041f051:	jne 0x0041f063
0x0041f063:	xchgl %ecx, %eax
0x0041f064:	decl %eax
0x0041f065:	shll %eax, $0x8<UINT8>
0x0041f068:	lodsb %al, %ds:(%esi)
0x0041f069:	call 0x0041f090
0x0041f090:	xorl %ecx, %ecx
0x0041f06e:	cmpl %eax, $0x7d00<UINT32>
0x0041f073:	jae 0x0041f07f
0x0041f075:	cmpb %ah, $0x5<UINT8>
0x0041f078:	jae 0x0041f080
0x0041f07a:	cmpl %eax, $0x7f<UINT8>
0x0041f07d:	ja 0x0041f081
0x0041f053:	call 0x0041f090
0x0041f058:	jmp 0x0041f082
0x0041f0a0:	popl %edi
0x0041f0a1:	popl %ebx
0x0041f0a2:	movzwl %edi, (%ebx)
0x0041f0a5:	decl %edi
0x0041f0a6:	je 0x0041f0b0
0x0041f0a8:	decl %edi
0x0041f0a9:	je 0x0041f0be
0x0041f0ab:	shll %edi, $0xc<UINT8>
0x0041f0ae:	jmp 0x0041f0b7
0x0041f0b7:	incl %ebx
0x0041f0b8:	incl %ebx
0x0041f0b9:	jmp 0x0041f00f
0x0041f0b0:	movl %edi, 0x2(%ebx)
0x0041f0b3:	pushl %edi
0x0041f0b4:	addl %ebx, $0x4<UINT8>
0x0041f0be:	popl %edi
0x0041f0bf:	movl %ebx, $0x41f128<UINT32>
0x0041f0c4:	incl %edi
0x0041f0c5:	movl %esi, (%edi)
0x0041f0c7:	scasl %eax, %es:(%edi)
0x0041f0c8:	pushl %edi
0x0041f0c9:	call LoadLibraryA@KERNEL32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0041f0cb:	xchgl %ebp, %eax
0x0041f0cc:	xorl %eax, %eax
0x0041f0ce:	scasb %al, %es:(%edi)
0x0041f0cf:	jne 0x0041f0ce
0x0041f0d1:	decb (%edi)
0x0041f0d3:	je 0x0041f0c4
0x0041f0d5:	decb (%edi)
0x0041f0d7:	jne 0x0041f0df
0x0041f0df:	decb (%edi)
0x0041f0e1:	je 0x0040333c
0x0041f0e7:	pushl %edi
0x0041f0e8:	pushl %ebp
0x0041f0e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x0041f0ec:	orl (%esi), %eax
0x0041f0ee:	lodsl %eax, %ds:(%esi)
0x0041f0ef:	jne 0x0041f0cc
GetProcAddress@KERNEL32.dll: API Node	
LoadLibraryA@KERNEL32.dll: API Node	
0x0041f0d9:	incl %edi
0x0041f0da:	pushl (%edi)
0x0041f0dc:	scasl %eax, %es:(%edi)
0x0041f0dd:	jmp 0x0041f0e8
0x0040333c:	call 0x00407356
0x00407356:	movl %edi, %edi
0x00407358:	pushl %ebp
0x00407359:	movl %ebp, %esp
0x0040735b:	subl %esp, $0x10<UINT8>
0x0040735e:	movl %eax, 0x412320
0x00407363:	andl -8(%ebp), $0x0<UINT8>
0x00407367:	andl -4(%ebp), $0x0<UINT8>
0x0040736b:	pushl %ebx
0x0040736c:	pushl %edi
0x0040736d:	movl %edi, $0xbb40e64e<UINT32>
0x00407372:	movl %ebx, $0xffff0000<UINT32>
0x00407377:	cmpl %eax, %edi
0x00407379:	je 0x00407388
0x00407388:	pushl %esi
0x00407389:	leal %eax, -8(%ebp)
0x0040738c:	pushl %eax
0x0040738d:	call GetSystemTimeAsFileTime@KERNEL32.dll
GetSystemTimeAsFileTime@KERNEL32.dll: API Node	
0x00407393:	movl %esi, -4(%ebp)
0x00407396:	xorl %esi, -8(%ebp)
0x00407399:	call GetCurrentProcessId@KERNEL32.dll
GetCurrentProcessId@KERNEL32.dll: API Node	
0x0040739f:	xorl %esi, %eax
0x004073a1:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x004073a7:	xorl %esi, %eax
0x004073a9:	call GetTickCount@KERNEL32.dll
GetTickCount@KERNEL32.dll: API Node	
0x004073af:	xorl %esi, %eax
0x004073b1:	leal %eax, -16(%ebp)
0x004073b4:	pushl %eax
0x004073b5:	call QueryPerformanceCounter@KERNEL32.dll
QueryPerformanceCounter@KERNEL32.dll: API Node	
0x004073bb:	movl %eax, -12(%ebp)
0x004073be:	xorl %eax, -16(%ebp)
0x004073c1:	xorl %esi, %eax
0x004073c3:	cmpl %esi, %edi
0x004073c5:	jne 0x004073ce
0x004073ce:	testl %ebx, %esi
0x004073d0:	jne 0x004073d9
0x004073d9:	movl 0x412320, %esi
0x004073df:	notl %esi
0x004073e1:	movl 0x412324, %esi
0x004073e7:	popl %esi
0x004073e8:	popl %edi
0x004073e9:	popl %ebx
0x004073ea:	leave
0x004073eb:	ret

0x00403341:	jmp 0x004031eb
0x004031eb:	pushl $0x14<UINT8>
0x004031ed:	pushl $0x410aa0<UINT32>
0x004031f2:	call 0x00406024
0x00406024:	pushl $0x406080<UINT32>
0x00406029:	pushl %fs:0
0x00406030:	movl %eax, 0x10(%esp)
0x00406034:	movl 0x10(%esp), %ebp
0x00406038:	leal %ebp, 0x10(%esp)
0x0040603c:	subl %esp, %eax
0x0040603e:	pushl %ebx
0x0040603f:	pushl %esi
0x00406040:	pushl %edi
0x00406041:	movl %eax, 0x412320
0x00406046:	xorl -4(%ebp), %eax
0x00406049:	xorl %eax, %ebp
0x0040604b:	pushl %eax
0x0040604c:	movl -24(%ebp), %esp
0x0040604f:	pushl -8(%ebp)
0x00406052:	movl %eax, -4(%ebp)
0x00406055:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040605c:	movl -8(%ebp), %eax
0x0040605f:	leal %eax, -16(%ebp)
0x00406062:	movl %fs:0, %eax
0x00406068:	ret

0x004031f7:	movl %eax, $0x5a4d<UINT32>
0x004031fc:	cmpw 0x400000, %ax
0x00403203:	jne 56
0x00403205:	movl %eax, 0x40003c
0x0040320a:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00403214:	jne 39
0x00403216:	movl %ecx, $0x10b<UINT32>
0x0040321b:	cmpw 0x400018(%eax), %cx
0x00403222:	jne 25
0x00403224:	cmpl 0x400074(%eax), $0xe<UINT8>
0x0040322b:	jbe 16
0x0040322d:	xorl %ecx, %ecx
0x0040322f:	cmpl 0x4000e8(%eax), %ecx
0x00403235:	setne %cl
0x00403238:	movl -28(%ebp), %ecx
0x0040323b:	jmp 0x00403241
0x00403241:	pushl $0x1<UINT8>
0x00403243:	call 0x00407326
0x00407326:	movl %edi, %edi
0x00407328:	pushl %ebp
0x00407329:	movl %ebp, %esp
0x0040732b:	xorl %eax, %eax
0x0040732d:	cmpl 0x8(%ebp), %eax
0x00407330:	pushl $0x0<UINT8>
0x00407332:	sete %al
0x00407335:	pushl $0x1000<UINT32>
0x0040733a:	pushl %eax
0x0040733b:	call HeapCreate@KERNEL32.dll
HeapCreate@KERNEL32.dll: API Node	
0x00407341:	movl 0x413a1c, %eax
0x00407346:	testl %eax, %eax
0x00407348:	jne 0x0040734c
0x0040734c:	xorl %eax, %eax
0x0040734e:	incl %eax
0x0040734f:	movl 0x413bbc, %eax
0x00407354:	popl %ebp
0x00407355:	ret

0x00403248:	popl %ecx
0x00403249:	testl %eax, %eax
0x0040324b:	jne 0x00403255
0x00403255:	call 0x00407199
0x00407199:	movl %edi, %edi
0x0040719b:	pushl %esi
0x0040719c:	pushl %edi
0x0040719d:	movl %esi, $0x40f038<UINT32>
0x004071a2:	pushl %esi
0x004071a3:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x004071a9:	testl %eax, %eax
0x004071ab:	jne 0x004071b4
0x004071b4:	movl %edi, %eax
0x004071b6:	testl %edi, %edi
0x004071b8:	je 350
0x004071be:	movl %esi, 0x40e0a4
0x004071c4:	pushl $0x40f084<UINT32>
0x004071c9:	pushl %edi
0x004071ca:	call GetProcAddress@KERNEL32.dll
0x004071cc:	pushl $0x40f078<UINT32>
0x004071d1:	pushl %edi
0x004071d2:	movl 0x413a0c, %eax
0x004071d7:	call GetProcAddress@KERNEL32.dll
0x004071d9:	pushl $0x40f06c<UINT32>
0x004071de:	pushl %edi
0x004071df:	movl 0x413a10, %eax
0x004071e4:	call GetProcAddress@KERNEL32.dll
0x004071e6:	pushl $0x40f064<UINT32>
0x004071eb:	pushl %edi
0x004071ec:	movl 0x413a14, %eax
0x004071f1:	call GetProcAddress@KERNEL32.dll
0x004071f3:	cmpl 0x413a0c, $0x0<UINT8>
0x004071fa:	movl %esi, 0x40e0cc
0x00407200:	movl 0x413a18, %eax
0x00407205:	je 22
0x00407207:	cmpl 0x413a10, $0x0<UINT8>
0x0040720e:	je 13
0x00407210:	cmpl 0x413a14, $0x0<UINT8>
0x00407217:	je 4
0x00407219:	testl %eax, %eax
0x0040721b:	jne 0x00407241
0x00407241:	call TlsAlloc@KERNEL32.dll
TlsAlloc@KERNEL32.dll: API Node	
0x00407247:	movl 0x4126fc, %eax
0x0040724c:	cmpl %eax, $0xffffffff<UINT8>
0x0040724f:	je 204
0x00407255:	pushl 0x413a10
0x0040725b:	pushl %eax
0x0040725c:	call TlsSetValue@KERNEL32.dll
TlsSetValue@KERNEL32.dll: API Node	
0x0040725e:	testl %eax, %eax
0x00407260:	je 187
0x00407266:	call 0x004042a9
0x004042a9:	movl %edi, %edi
0x004042ab:	pushl %esi
0x004042ac:	call 0x00406dfb
0x00406dfb:	pushl $0x0<UINT8>
0x00406dfd:	call 0x00406d89
0x00406d89:	movl %edi, %edi
0x00406d8b:	pushl %ebp
0x00406d8c:	movl %ebp, %esp
0x00406d8e:	pushl %esi
0x00406d8f:	pushl 0x4126fc
0x00406d95:	movl %esi, 0x40e0c4
0x00406d9b:	call TlsGetValue@KERNEL32.dll
TlsGetValue@KERNEL32.dll: API Node	
0x00406d9d:	testl %eax, %eax
0x00406d9f:	je 33
0x00406da1:	movl %eax, 0x4126f8
0x00406da6:	cmpl %eax, $0xffffffff<UINT8>
0x00406da9:	je 0x00406dc2
0x00406dc2:	movl %esi, $0x40f038<UINT32>
0x00406dc7:	pushl %esi
0x00406dc8:	call GetModuleHandleW@KERNEL32.dll
0x00406dce:	testl %eax, %eax
0x00406dd0:	jne 0x00406ddd
0x00406ddd:	pushl $0x40f028<UINT32>
0x00406de2:	pushl %eax
0x00406de3:	call GetProcAddress@KERNEL32.dll
0x00406de9:	testl %eax, %eax
0x00406deb:	je 8
0x00406ded:	pushl 0x8(%ebp)
0x00406df0:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00406df2:	movl 0x8(%ebp), %eax
0x00406df5:	movl %eax, 0x8(%ebp)
0x00406df8:	popl %esi
0x00406df9:	popl %ebp
0x00406dfa:	ret

0x00406e02:	popl %ecx
0x00406e03:	ret

0x004042b1:	movl %esi, %eax
0x004042b3:	pushl %esi
0x004042b4:	call 0x004065eb
0x004065eb:	movl %edi, %edi
0x004065ed:	pushl %ebp
0x004065ee:	movl %ebp, %esp
0x004065f0:	movl %eax, 0x8(%ebp)
0x004065f3:	movl 0x4134e4, %eax
0x004065f8:	popl %ebp
0x004065f9:	ret

0x004042b9:	pushl %esi
0x004042ba:	call 0x0040a43a
0x0040a43a:	movl %edi, %edi
0x0040a43c:	pushl %ebp
0x0040a43d:	movl %ebp, %esp
0x0040a43f:	movl %eax, 0x8(%ebp)
0x0040a442:	movl 0x413a74, %eax
0x0040a447:	popl %ebp
0x0040a448:	ret

0x004042bf:	pushl %esi
0x004042c0:	call 0x004044a6
0x004044a6:	movl %edi, %edi
0x004044a8:	pushl %ebp
0x004044a9:	movl %ebp, %esp
0x004044ab:	movl %eax, 0x8(%ebp)
0x004044ae:	movl 0x4134b0, %eax
0x004044b3:	popl %ebp
0x004044b4:	ret

0x004042c5:	pushl %esi
0x004042c6:	call 0x0040a380
0x0040a380:	movl %edi, %edi
0x0040a382:	pushl %ebp
0x0040a383:	movl %ebp, %esp
0x0040a385:	movl %eax, 0x8(%ebp)
0x0040a388:	movl 0x413a70, %eax
0x0040a38d:	popl %ebp
0x0040a38e:	ret

0x004042cb:	pushl %esi
0x004042cc:	call 0x0040aa97
0x0040aa97:	movl %edi, %edi
0x0040aa99:	pushl %ebp
0x0040aa9a:	movl %ebp, %esp
0x0040aa9c:	movl %eax, 0x8(%ebp)
0x0040aa9f:	movl 0x413a7c, %eax
0x0040aaa4:	popl %ebp
0x0040aaa5:	ret

0x004042d1:	pushl %esi
0x004042d2:	call 0x00404ada
0x00404ada:	movl %edi, %edi
0x00404adc:	pushl %ebp
0x00404add:	movl %ebp, %esp
0x00404adf:	movl %eax, 0x8(%ebp)
0x00404ae2:	movl 0x4134b4, %eax
0x00404ae7:	movl 0x4134b8, %eax
0x00404aec:	movl 0x4134bc, %eax
0x00404af1:	movl 0x4134c0, %eax
0x00404af6:	popl %ebp
0x00404af7:	ret

0x004042d7:	pushl %esi
0x004042d8:	call 0x004068a2
0x004068a2:	ret

0x004042dd:	pushl %esi
0x004042de:	call 0x0040aa86
0x0040aa86:	pushl $0x40aa4d<UINT32>
0x0040aa8b:	call 0x00406d89
0x0040aa90:	popl %ecx
0x0040aa91:	movl 0x413a78, %eax
0x0040aa96:	ret

0x004042e3:	pushl $0x404275<UINT32>
0x004042e8:	call 0x00406d89
0x004042ed:	addl %esp, $0x24<UINT8>
0x004042f0:	movl 0x412368, %eax
0x004042f5:	popl %esi
0x004042f6:	ret

0x0040726b:	pushl 0x413a0c
0x00407271:	call 0x00406d89
0x00407276:	pushl 0x413a10
0x0040727c:	movl 0x413a0c, %eax
0x00407281:	call 0x00406d89
0x00407286:	pushl 0x413a14
0x0040728c:	movl 0x413a10, %eax
0x00407291:	call 0x00406d89
0x00407296:	pushl 0x413a18
0x0040729c:	movl 0x413a14, %eax
0x004072a1:	call 0x00406d89
0x004072a6:	addl %esp, $0x10<UINT8>
0x004072a9:	movl 0x413a18, %eax
0x004072ae:	call 0x004042f7
0x004042f7:	movl %edi, %edi
0x004042f9:	pushl %esi
0x004042fa:	pushl %edi
0x004042fb:	xorl %esi, %esi
0x004042fd:	movl %edi, $0x413360<UINT32>
0x00404302:	cmpl 0x412374(,%esi,8), $0x1<UINT8>
0x0040430a:	jne 0x0040432a
0x0040430c:	leal %eax, 0x412370(,%esi,8)
0x00404313:	movl (%eax), %edi
0x00404315:	pushl $0xfa0<UINT32>
0x0040431a:	pushl (%eax)
0x0040431c:	addl %edi, $0x18<UINT8>
0x0040431f:	call 0x0040a449
0x0040a449:	pushl $0x10<UINT8>
0x0040a44b:	pushl $0x410d78<UINT32>
0x0040a450:	call 0x00406024
0x0040a455:	andl -4(%ebp), $0x0<UINT8>
0x0040a459:	pushl 0xc(%ebp)
0x0040a45c:	pushl 0x8(%ebp)
0x0040a45f:	call InitializeCriticalSectionAndSpinCount@KERNEL32.dll
InitializeCriticalSectionAndSpinCount@KERNEL32.dll: API Node	
0x0040a465:	movl -28(%ebp), %eax
0x0040a468:	jmp 0x0040a499
0x0040a499:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040a4a0:	movl %eax, -28(%ebp)
0x0040a4a3:	call 0x00406069
0x00406069:	movl %ecx, -16(%ebp)
0x0040606c:	movl %fs:0, %ecx
0x00406073:	popl %ecx
0x00406074:	popl %edi
0x00406075:	popl %edi
0x00406076:	popl %esi
0x00406077:	popl %ebx
0x00406078:	movl %esp, %ebp
0x0040607a:	popl %ebp
0x0040607b:	pushl %ecx
0x0040607c:	ret

0x0040a4a8:	ret

0x00404324:	popl %ecx
0x00404325:	popl %ecx
0x00404326:	testl %eax, %eax
0x00404328:	je 12
0x0040432a:	incl %esi
0x0040432b:	cmpl %esi, $0x24<UINT8>
0x0040432e:	jl 0x00404302
0x00404330:	xorl %eax, %eax
0x00404332:	incl %eax
0x00404333:	popl %edi
0x00404334:	popl %esi
0x00404335:	ret

0x004072b3:	testl %eax, %eax
0x004072b5:	je 101
0x004072b7:	pushl $0x40706a<UINT32>
0x004072bc:	pushl 0x413a0c
0x004072c2:	call 0x00406e04
0x00406e04:	movl %edi, %edi
0x00406e06:	pushl %ebp
0x00406e07:	movl %ebp, %esp
0x00406e09:	pushl %esi
0x00406e0a:	pushl 0x4126fc
0x00406e10:	movl %esi, 0x40e0c4
0x00406e16:	call TlsGetValue@KERNEL32.dll
0x00406e18:	testl %eax, %eax
0x00406e1a:	je 33
0x00406e1c:	movl %eax, 0x4126f8
0x00406e21:	cmpl %eax, $0xffffffff<UINT8>
0x00406e24:	je 0x00406e3d
0x00406e3d:	movl %esi, $0x40f038<UINT32>
0x00406e42:	pushl %esi
0x00406e43:	call GetModuleHandleW@KERNEL32.dll
0x00406e49:	testl %eax, %eax
0x00406e4b:	jne 0x00406e58
0x00406e58:	pushl $0x40f054<UINT32>
0x00406e5d:	pushl %eax
0x00406e5e:	call GetProcAddress@KERNEL32.dll
0x00406e64:	testl %eax, %eax
0x00406e66:	je 8
0x00406e68:	pushl 0x8(%ebp)
0x00406e6b:	call DecodePointer@KERNEL32.DLL
DecodePointer@KERNEL32.DLL: API Node	
0x00406e6d:	movl 0x8(%ebp), %eax
0x00406e70:	movl %eax, 0x8(%ebp)
0x00406e73:	popl %esi
0x00406e74:	popl %ebp
0x00406e75:	ret

0x004072c7:	popl %ecx
0x004072c8:	call FlsAlloc@KERNEL32.DLL
FlsAlloc@KERNEL32.DLL: API Node	
0x004072ca:	movl 0x4126f8, %eax
0x004072cf:	cmpl %eax, $0xffffffff<UINT8>
0x004072d2:	je 72
0x004072d4:	pushl $0x214<UINT32>
0x004072d9:	pushl $0x1<UINT8>
0x004072db:	call 0x00403e86
0x00403e86:	movl %edi, %edi
0x00403e88:	pushl %ebp
0x00403e89:	movl %ebp, %esp
0x00403e8b:	pushl %esi
0x00403e8c:	pushl %edi
0x00403e8d:	xorl %esi, %esi
0x00403e8f:	pushl $0x0<UINT8>
0x00403e91:	pushl 0xc(%ebp)
0x00403e94:	pushl 0x8(%ebp)
0x00403e97:	call 0x0040a4a9
0x0040a4a9:	pushl $0xc<UINT8>
0x0040a4ab:	pushl $0x410d98<UINT32>
0x0040a4b0:	call 0x00406024
0x0040a4b5:	movl %ecx, 0x8(%ebp)
0x0040a4b8:	xorl %edi, %edi
0x0040a4ba:	cmpl %ecx, %edi
0x0040a4bc:	jbe 46
0x0040a4be:	pushl $0xffffffe0<UINT8>
0x0040a4c0:	popl %eax
0x0040a4c1:	xorl %edx, %edx
0x0040a4c3:	divl %eax, %ecx
0x0040a4c5:	cmpl %eax, 0xc(%ebp)
0x0040a4c8:	sbbl %eax, %eax
0x0040a4ca:	incl %eax
0x0040a4cb:	jne 0x0040a4ec
0x0040a4ec:	imull %ecx, 0xc(%ebp)
0x0040a4f0:	movl %esi, %ecx
0x0040a4f2:	movl 0x8(%ebp), %esi
0x0040a4f5:	cmpl %esi, %edi
0x0040a4f7:	jne 0x0040a4fc
0x0040a4fc:	xorl %ebx, %ebx
0x0040a4fe:	movl -28(%ebp), %ebx
0x0040a501:	cmpl %esi, $0xffffffe0<UINT8>
0x0040a504:	ja 105
0x0040a506:	cmpl 0x413bbc, $0x3<UINT8>
0x0040a50d:	jne 0x0040a55a
0x0040a55a:	cmpl %ebx, %edi
0x0040a55c:	jne 97
0x0040a55e:	pushl %esi
0x0040a55f:	pushl $0x8<UINT8>
0x0040a561:	pushl 0x413a1c
0x0040a567:	call HeapAlloc@KERNEL32.dll
HeapAlloc@KERNEL32.dll: API Node	
0x0040a56d:	movl %ebx, %eax
0x0040a56f:	cmpl %ebx, %edi
0x0040a571:	jne 0x0040a5bf
0x0040a5bf:	movl %eax, %ebx
0x0040a5c1:	call 0x00406069
0x0040a5c6:	ret

0x00403e9c:	movl %edi, %eax
0x00403e9e:	addl %esp, $0xc<UINT8>
0x00403ea1:	testl %edi, %edi
0x00403ea3:	jne 0x00403ecc
0x00403ecc:	movl %eax, %edi
0x00403ece:	popl %edi
0x00403ecf:	popl %esi
0x00403ed0:	popl %ebp
0x00403ed1:	ret

0x004072e0:	movl %esi, %eax
0x004072e2:	popl %ecx
0x004072e3:	popl %ecx
0x004072e4:	testl %esi, %esi
0x004072e6:	je 52
0x004072e8:	pushl %esi
0x004072e9:	pushl 0x4126f8
0x004072ef:	pushl 0x413a14
0x004072f5:	call 0x00406e04
0x00406e26:	pushl %eax
0x00406e27:	pushl 0x4126fc
0x00406e2d:	call TlsGetValue@KERNEL32.dll
0x00406e2f:	call FlsGetValue@KERNEL32.DLL
FlsGetValue@KERNEL32.DLL: API Node	
0x00406e31:	testl %eax, %eax
0x00406e33:	je 0x00406e3d
0x004072fa:	popl %ecx
0x004072fb:	call FlsSetValue@KERNEL32.DLL
FlsSetValue@KERNEL32.DLL: API Node	
0x004072fd:	testl %eax, %eax
0x004072ff:	je 27
0x00407301:	pushl $0x0<UINT8>
0x00407303:	pushl %esi
0x00407304:	call 0x00406ef0
0x00406ef0:	pushl $0xc<UINT8>
0x00406ef2:	pushl $0x410c68<UINT32>
0x00406ef7:	call 0x00406024
0x00406efc:	movl %esi, $0x40f038<UINT32>
0x00406f01:	pushl %esi
0x00406f02:	call GetModuleHandleW@KERNEL32.dll
0x00406f08:	testl %eax, %eax
0x00406f0a:	jne 0x00406f13
0x00406f13:	movl -28(%ebp), %eax
0x00406f16:	movl %esi, 0x8(%ebp)
0x00406f19:	movl 0x5c(%esi), $0x40efb0<UINT32>
0x00406f20:	xorl %edi, %edi
0x00406f22:	incl %edi
0x00406f23:	movl 0x14(%esi), %edi
0x00406f26:	testl %eax, %eax
0x00406f28:	je 36
0x00406f2a:	pushl $0x40f028<UINT32>
0x00406f2f:	pushl %eax
0x00406f30:	movl %ebx, 0x40e0a4
0x00406f36:	call GetProcAddress@KERNEL32.dll
0x00406f38:	movl 0x1f8(%esi), %eax
0x00406f3e:	pushl $0x40f054<UINT32>
0x00406f43:	pushl -28(%ebp)
0x00406f46:	call GetProcAddress@KERNEL32.dll
0x00406f48:	movl 0x1fc(%esi), %eax
0x00406f4e:	movl 0x70(%esi), %edi
0x00406f51:	movb 0xc8(%esi), $0x43<UINT8>
0x00406f58:	movb 0x14b(%esi), $0x43<UINT8>
0x00406f5f:	movl 0x68(%esi), $0x412708<UINT32>
0x00406f66:	pushl $0xd<UINT8>
0x00406f68:	call 0x00404473
0x00404473:	movl %edi, %edi
0x00404475:	pushl %ebp
0x00404476:	movl %ebp, %esp
0x00404478:	movl %eax, 0x8(%ebp)
0x0040447b:	pushl %esi
0x0040447c:	leal %esi, 0x412370(,%eax,8)
0x00404483:	cmpl (%esi), $0x0<UINT8>
0x00404486:	jne 0x0040449b
0x0040449b:	pushl (%esi)
0x0040449d:	call EnterCriticalSection@KERNEL32.dll
EnterCriticalSection@KERNEL32.dll: API Node	
0x004044a3:	popl %esi
0x004044a4:	popl %ebp
0x004044a5:	ret

0x00406f6d:	popl %ecx
0x00406f6e:	andl -4(%ebp), $0x0<UINT8>
0x00406f72:	pushl 0x68(%esi)
0x00406f75:	call InterlockedIncrement@KERNEL32.dll
InterlockedIncrement@KERNEL32.dll: API Node	
0x00406f7b:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00406f82:	call 0x00406fc5
0x00406fc5:	pushl $0xd<UINT8>
0x00406fc7:	call 0x00404399
0x00404399:	movl %edi, %edi
0x0040439b:	pushl %ebp
0x0040439c:	movl %ebp, %esp
0x0040439e:	movl %eax, 0x8(%ebp)
0x004043a1:	pushl 0x412370(,%eax,8)
0x004043a8:	call LeaveCriticalSection@KERNEL32.dll
LeaveCriticalSection@KERNEL32.dll: API Node	
0x004043ae:	popl %ebp
0x004043af:	ret

0x00406fcc:	popl %ecx
0x00406fcd:	ret

0x00406f87:	pushl $0xc<UINT8>
0x00406f89:	call 0x00404473
0x00406f8e:	popl %ecx
0x00406f8f:	movl -4(%ebp), %edi
0x00406f92:	movl %eax, 0xc(%ebp)
0x00406f95:	movl 0x6c(%esi), %eax
0x00406f98:	testl %eax, %eax
0x00406f9a:	jne 8
0x00406f9c:	movl %eax, 0x412d10
0x00406fa1:	movl 0x6c(%esi), %eax
0x00406fa4:	pushl 0x6c(%esi)
0x00406fa7:	call 0x00409204
0x00409204:	movl %edi, %edi
0x00409206:	pushl %ebp
0x00409207:	movl %ebp, %esp
0x00409209:	pushl %ebx
0x0040920a:	pushl %esi
0x0040920b:	movl %esi, 0x40e0d4
0x00409211:	pushl %edi
0x00409212:	movl %edi, 0x8(%ebp)
0x00409215:	pushl %edi
0x00409216:	call InterlockedIncrement@KERNEL32.dll
0x00409218:	movl %eax, 0xb0(%edi)
0x0040921e:	testl %eax, %eax
0x00409220:	je 0x00409225
0x00409225:	movl %eax, 0xb8(%edi)
0x0040922b:	testl %eax, %eax
0x0040922d:	je 0x00409232
0x00409232:	movl %eax, 0xb4(%edi)
0x00409238:	testl %eax, %eax
0x0040923a:	je 0x0040923f
0x0040923f:	movl %eax, 0xc0(%edi)
0x00409245:	testl %eax, %eax
0x00409247:	je 0x0040924c
0x0040924c:	leal %ebx, 0x50(%edi)
0x0040924f:	movl 0x8(%ebp), $0x6<UINT32>
0x00409256:	cmpl -8(%ebx), $0x412c30<UINT32>
0x0040925d:	je 0x00409268
0x0040925f:	movl %eax, (%ebx)
0x00409261:	testl %eax, %eax
0x00409263:	je 0x00409268
0x00409268:	cmpl -4(%ebx), $0x0<UINT8>
0x0040926c:	je 0x00409278
0x00409278:	addl %ebx, $0x10<UINT8>
0x0040927b:	decl 0x8(%ebp)
0x0040927e:	jne 0x00409256
0x00409280:	movl %eax, 0xd4(%edi)
0x00409286:	addl %eax, $0xb4<UINT32>
0x0040928b:	pushl %eax
0x0040928c:	call InterlockedIncrement@KERNEL32.dll
0x0040928e:	popl %edi
0x0040928f:	popl %esi
0x00409290:	popl %ebx
0x00409291:	popl %ebp
0x00409292:	ret

0x00406fac:	popl %ecx
0x00406fad:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00406fb4:	call 0x00406fce
0x00406fce:	pushl $0xc<UINT8>
0x00406fd0:	call 0x00404399
0x00406fd5:	popl %ecx
0x00406fd6:	ret

0x00406fb9:	call 0x00406069
0x00406fbe:	ret

0x00407309:	popl %ecx
0x0040730a:	popl %ecx
0x0040730b:	call GetCurrentThreadId@KERNEL32.dll
0x00407311:	orl 0x4(%esi), $0xffffffff<UINT8>
0x00407315:	movl (%esi), %eax
0x00407317:	xorl %eax, %eax
0x00407319:	incl %eax
0x0040731a:	jmp 0x00407323
0x00407323:	popl %edi
0x00407324:	popl %esi
0x00407325:	ret

0x0040325a:	testl %eax, %eax
0x0040325c:	jne 0x00403266
0x00403266:	call 0x00406d3d
0x00406d3d:	movl %edi, %edi
0x00406d3f:	pushl %esi
0x00406d40:	movl %eax, $0x410a00<UINT32>
0x00406d45:	movl %esi, $0x410a00<UINT32>
0x00406d4a:	pushl %edi
0x00406d4b:	movl %edi, %eax
0x00406d4d:	cmpl %eax, %esi
0x00406d4f:	jae 0x00406d60
0x00406d60:	popl %edi
0x00406d61:	popl %esi
0x00406d62:	ret

0x0040326b:	andl -4(%ebp), $0x0<UINT8>
0x0040326f:	call 0x00403bed
0x00403bed:	pushl $0x54<UINT8>
0x00403bef:	pushl $0x410b48<UINT32>
0x00403bf4:	call 0x00406024
0x00403bf9:	xorl %edi, %edi
0x00403bfb:	movl -4(%ebp), %edi
0x00403bfe:	leal %eax, -100(%ebp)
0x00403c01:	pushl %eax
0x00403c02:	call GetStartupInfoA@KERNEL32.dll
GetStartupInfoA@KERNEL32.dll: API Node	
0x00403c08:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00403c0f:	pushl $0x40<UINT8>
0x00403c11:	pushl $0x20<UINT8>
0x00403c13:	popl %esi
0x00403c14:	pushl %esi
0x00403c15:	call 0x00403e86
0x00403c1a:	popl %ecx
0x00403c1b:	popl %ecx
0x00403c1c:	cmpl %eax, %edi
0x00403c1e:	je 532
0x00403c24:	movl 0x413c00, %eax
0x00403c29:	movl 0x413be0, %esi
0x00403c2f:	leal %ecx, 0x800(%eax)
0x00403c35:	jmp 0x00403c67
0x00403c67:	cmpl %eax, %ecx
0x00403c69:	jb 0x00403c37
0x00403c37:	movb 0x4(%eax), $0x0<UINT8>
0x00403c3b:	orl (%eax), $0xffffffff<UINT8>
0x00403c3e:	movb 0x5(%eax), $0xa<UINT8>
0x00403c42:	movl 0x8(%eax), %edi
0x00403c45:	movb 0x24(%eax), $0x0<UINT8>
0x00403c49:	movb 0x25(%eax), $0xa<UINT8>
0x00403c4d:	movb 0x26(%eax), $0xa<UINT8>
0x00403c51:	movl 0x38(%eax), %edi
0x00403c54:	movb 0x34(%eax), $0x0<UINT8>
0x00403c58:	addl %eax, $0x40<UINT8>
0x00403c5b:	movl %ecx, 0x413c00
0x00403c61:	addl %ecx, $0x800<UINT32>
0x00403c6b:	cmpw -50(%ebp), %di
0x00403c6f:	je 266
0x00403c75:	movl %eax, -48(%ebp)
0x00403c78:	cmpl %eax, %edi
0x00403c7a:	je 255
0x00403c80:	movl %edi, (%eax)
0x00403c82:	leal %ebx, 0x4(%eax)
0x00403c85:	leal %eax, (%ebx,%edi)
0x00403c88:	movl -28(%ebp), %eax
0x00403c8b:	movl %esi, $0x800<UINT32>
0x00403c90:	cmpl %edi, %esi
0x00403c92:	jl 0x00403c96
0x00403c96:	movl -32(%ebp), $0x1<UINT32>
0x00403c9d:	jmp 0x00403cfa
0x00403cfa:	cmpl 0x413be0, %edi
0x00403d00:	jl -99
0x00403d02:	jmp 0x00403d0a
0x00403d0a:	andl -32(%ebp), $0x0<UINT8>
0x00403d0e:	testl %edi, %edi
0x00403d10:	jle 0x00403d7f
0x00403d7f:	xorl %ebx, %ebx
0x00403d81:	movl %esi, %ebx
0x00403d83:	shll %esi, $0x6<UINT8>
0x00403d86:	addl %esi, 0x413c00
0x00403d8c:	movl %eax, (%esi)
0x00403d8e:	cmpl %eax, $0xffffffff<UINT8>
0x00403d91:	je 0x00403d9e
0x00403d9e:	movb 0x4(%esi), $0xffffff81<UINT8>
0x00403da2:	testl %ebx, %ebx
0x00403da4:	jne 0x00403dab
0x00403da6:	pushl $0xfffffff6<UINT8>
0x00403da8:	popl %eax
0x00403da9:	jmp 0x00403db5
0x00403db5:	pushl %eax
0x00403db6:	call GetStdHandle@KERNEL32.dll
GetStdHandle@KERNEL32.dll: API Node	
0x00403dbc:	movl %edi, %eax
0x00403dbe:	cmpl %edi, $0xffffffff<UINT8>
0x00403dc1:	je 67
0x00403dc3:	testl %edi, %edi
0x00403dc5:	je 63
0x00403dc7:	pushl %edi
0x00403dc8:	call GetFileType@KERNEL32.dll
GetFileType@KERNEL32.dll: API Node	
0x00403dce:	testl %eax, %eax
0x00403dd0:	je 52
0x00403dd2:	movl (%esi), %edi
0x00403dd4:	andl %eax, $0xff<UINT32>
0x00403dd9:	cmpl %eax, $0x2<UINT8>
0x00403ddc:	jne 6
0x00403dde:	orb 0x4(%esi), $0x40<UINT8>
0x00403de2:	jmp 0x00403ded
0x00403ded:	pushl $0xfa0<UINT32>
0x00403df2:	leal %eax, 0xc(%esi)
0x00403df5:	pushl %eax
0x00403df6:	call 0x0040a449
0x00403dfb:	popl %ecx
0x00403dfc:	popl %ecx
0x00403dfd:	testl %eax, %eax
0x00403dff:	je 55
0x00403e01:	incl 0x8(%esi)
0x00403e04:	jmp 0x00403e10
0x00403e10:	incl %ebx
0x00403e11:	cmpl %ebx, $0x3<UINT8>
0x00403e14:	jl 0x00403d81
0x00403dab:	movl %eax, %ebx
0x00403dad:	decl %eax
0x00403dae:	negl %eax
0x00403db0:	sbbl %eax, %eax
0x00403db2:	addl %eax, $0xfffffff5<UINT8>
0x00403e1a:	pushl 0x413be0
0x00403e20:	call SetHandleCount@KERNEL32.dll
SetHandleCount@KERNEL32.dll: API Node	
0x00403e26:	xorl %eax, %eax
0x00403e28:	jmp 0x00403e3b
0x00403e3b:	call 0x00406069
0x00403e40:	ret

0x00403274:	testl %eax, %eax
0x00403276:	jnl 0x00403280
0x00403280:	call 0x00406d37
0x00406d37:	jmp GetCommandLineW@KERNEL32.dll
GetCommandLineW@KERNEL32.dll: API Node	
0x00403285:	movl 0x413d00, %eax
0x0040328a:	call 0x00406ce0
0x00406ce0:	movl %edi, %edi
0x00406ce2:	pushl %esi
0x00406ce3:	call GetEnvironmentStringsW@KERNEL32.dll
GetEnvironmentStringsW@KERNEL32.dll: API Node	
0x00406ce9:	movl %esi, %eax
0x00406ceb:	xorl %ecx, %ecx
0x00406ced:	cmpl %esi, %ecx
0x00406cef:	jne 0x00406cf5
0x00406cf5:	cmpw (%esi), %cx
0x00406cf8:	je 14
0x00406cfa:	incl %eax
0x00406cfb:	incl %eax
0x00406cfc:	cmpw (%eax), %cx
0x00406cff:	jne 0x00406cfa
0x00406d01:	incl %eax
0x00406d02:	incl %eax
0x00406d03:	cmpw (%eax), %cx
0x00406d06:	jne 0x00406cfa
0x00406d08:	subl %eax, %esi
0x00406d0a:	incl %eax
0x00406d0b:	pushl %ebx
0x00406d0c:	incl %eax
0x00406d0d:	movl %ebx, %eax
0x00406d0f:	pushl %edi
0x00406d10:	pushl %ebx
0x00406d11:	call 0x00403e41
0x00403e41:	movl %edi, %edi
0x00403e43:	pushl %ebp
0x00403e44:	movl %ebp, %esp
0x00403e46:	pushl %esi
0x00403e47:	pushl %edi
0x00403e48:	xorl %esi, %esi
0x00403e4a:	pushl 0x8(%ebp)
0x00403e4d:	call 0x00406521
0x00406521:	movl %edi, %edi
0x00406523:	pushl %ebp
0x00406524:	movl %ebp, %esp
0x00406526:	pushl %esi
0x00406527:	movl %esi, 0x8(%ebp)
0x0040652a:	cmpl %esi, $0xffffffe0<UINT8>
0x0040652d:	ja 161
0x00406533:	pushl %ebx
0x00406534:	pushl %edi
0x00406535:	movl %edi, 0x40e030
0x0040653b:	cmpl 0x413a1c, $0x0<UINT8>
0x00406542:	jne 0x0040655c
0x0040655c:	movl %eax, 0x413bbc
0x00406561:	cmpl %eax, $0x1<UINT8>
0x00406564:	jne 14
0x00406566:	testl %esi, %esi
0x00406568:	je 4
0x0040656a:	movl %eax, %esi
0x0040656c:	jmp 0x00406571
0x00406571:	pushl %eax
0x00406572:	jmp 0x00406590
0x00406590:	pushl $0x0<UINT8>
0x00406592:	pushl 0x413a1c
0x00406598:	call HeapAlloc@KERNEL32.dll
0x0040659a:	movl %ebx, %eax
0x0040659c:	testl %ebx, %ebx
0x0040659e:	jne 0x004065ce
0x004065ce:	popl %edi
0x004065cf:	movl %eax, %ebx
0x004065d1:	popl %ebx
0x004065d2:	jmp 0x004065e8
0x004065e8:	popl %esi
0x004065e9:	popl %ebp
0x004065ea:	ret

0x00403e52:	movl %edi, %eax
0x00403e54:	popl %ecx
0x00403e55:	testl %edi, %edi
0x00403e57:	jne 0x00403e80
0x00403e80:	movl %eax, %edi
0x00403e82:	popl %edi
0x00403e83:	popl %esi
0x00403e84:	popl %ebp
0x00403e85:	ret

0x00406d16:	movl %edi, %eax
0x00406d18:	popl %ecx
0x00406d19:	testl %edi, %edi
0x00406d1b:	jne 0x00406d2a
0x00406d2a:	pushl %ebx
0x00406d2b:	pushl %esi
0x00406d2c:	pushl %edi
0x00406d2d:	call 0x0040b720
0x0040b720:	pushl %ebp
0x0040b721:	movl %ebp, %esp
0x0040b723:	pushl %edi
0x0040b724:	pushl %esi
0x0040b725:	movl %esi, 0xc(%ebp)
0x0040b728:	movl %ecx, 0x10(%ebp)
0x0040b72b:	movl %edi, 0x8(%ebp)
0x0040b72e:	movl %eax, %ecx
0x0040b730:	movl %edx, %ecx
0x0040b732:	addl %eax, %esi
0x0040b734:	cmpl %edi, %esi
0x0040b736:	jbe 0x0040b740
0x0040b740:	cmpl %ecx, $0x100<UINT32>
0x0040b746:	jb 31
0x0040b748:	cmpl 0x413bc0, $0x0<UINT8>
0x0040b74f:	je 0x0040b767
0x0040b767:	testl %edi, $0x3<UINT32>
0x0040b76d:	jne 21
0x0040b76f:	shrl %ecx, $0x2<UINT8>
0x0040b772:	andl %edx, $0x3<UINT8>
0x0040b775:	cmpl %ecx, $0x8<UINT8>
0x0040b778:	jb 42
0x0040b77a:	rep movsl %es:(%edi), %ds:(%esi)
0x0040b77c:	jmp 0x0040b8b8
0x0040b8b8:	movb %al, (%esi)
0x0040b8ba:	movb (%edi), %al
0x0040b8bc:	movb %al, 0x1(%esi)
0x0040b8bf:	movb 0x1(%edi), %al
0x0040b8c2:	movl %eax, 0x8(%ebp)
0x0040b8c5:	popl %esi
0x0040b8c6:	popl %edi
0x0040b8c7:	leave
0x0040b8c8:	ret

0x00406d32:	addl %esp, $0xc<UINT8>
0x00406d35:	jmp 0x00406d1d
0x00406d1d:	pushl %esi
0x00406d1e:	call FreeEnvironmentStringsW@KERNEL32.dll
FreeEnvironmentStringsW@KERNEL32.dll: API Node	
0x00406d24:	movl %eax, %edi
0x00406d26:	popl %edi
0x00406d27:	popl %ebx
0x00406d28:	popl %esi
0x00406d29:	ret

0x0040328f:	movl 0x412ff8, %eax
0x00403294:	call 0x00406c32
0x00406c32:	movl %edi, %edi
0x00406c34:	pushl %ebp
0x00406c35:	movl %ebp, %esp
0x00406c37:	pushl %ecx
0x00406c38:	pushl %ecx
0x00406c39:	pushl %ebx
0x00406c3a:	pushl %esi
0x00406c3b:	pushl %edi
0x00406c3c:	pushl $0x104<UINT32>
0x00406c41:	movl %esi, $0x413800<UINT32>
0x00406c46:	pushl %esi
0x00406c47:	xorl %eax, %eax
0x00406c49:	xorl %ebx, %ebx
0x00406c4b:	pushl %ebx
0x00406c4c:	movw 0x413a08, %ax
0x00406c52:	call GetModuleFileNameW@KERNEL32.dll
GetModuleFileNameW@KERNEL32.dll: API Node	
0x00406c58:	movl %eax, 0x413d00
0x00406c5d:	movl 0x41334c, %esi
0x00406c63:	cmpl %eax, %ebx
0x00406c65:	je 7
0x00406c67:	movl %edi, %eax
0x00406c69:	cmpw (%eax), %bx
0x00406c6c:	jne 0x00406c70
0x00406c70:	leal %eax, -4(%ebp)
0x00406c73:	pushl %eax
0x00406c74:	pushl %ebx
0x00406c75:	leal %ebx, -8(%ebp)
0x00406c78:	xorl %ecx, %ecx
0x00406c7a:	movl %eax, %edi
0x00406c7c:	call 0x00406ae1
0x00406ae1:	movl %edi, %edi
0x00406ae3:	pushl %ebp
0x00406ae4:	movl %ebp, %esp
0x00406ae6:	pushl %ecx
0x00406ae7:	pushl %esi
0x00406ae8:	xorl %edx, %edx
0x00406aea:	pushl %edi
0x00406aeb:	movl %edi, 0xc(%ebp)
0x00406aee:	movl (%ebx), %edx
0x00406af0:	movl %esi, %ecx
0x00406af2:	movl (%edi), $0x1<UINT32>
0x00406af8:	cmpl 0x8(%ebp), %edx
0x00406afb:	je 0x00406b06
0x00406b06:	cmpw (%eax), $0x22<UINT8>
0x00406b0a:	jne 0x00406b1f
0x00406b0c:	movl %edi, 0xc(%ebp)
0x00406b0f:	xorl %ecx, %ecx
0x00406b11:	testl %edx, %edx
0x00406b13:	sete %cl
0x00406b16:	pushl $0x22<UINT8>
0x00406b18:	incl %eax
0x00406b19:	incl %eax
0x00406b1a:	movl %edx, %ecx
0x00406b1c:	popl %ecx
0x00406b1d:	jmp 0x00406b37
0x00406b37:	testl %edx, %edx
0x00406b39:	jne 0x00406b06
0x00406b1f:	incl (%ebx)
0x00406b21:	testl %esi, %esi
0x00406b23:	je 0x00406b2d
0x00406b2d:	movzwl %ecx, (%eax)
0x00406b30:	incl %eax
0x00406b31:	incl %eax
0x00406b32:	testw %cx, %cx
0x00406b35:	je 0x00406b73
0x00406b3b:	cmpw %cx, $0x20<UINT8>
0x00406b3f:	je 6
0x00406b41:	cmpw %cx, $0x9<UINT8>
0x00406b45:	jne 0x00406b06
0x00406b73:	decl %eax
0x00406b74:	decl %eax
0x00406b75:	jmp 0x00406b51
0x00406b51:	andl -4(%ebp), $0x0<UINT8>
0x00406b55:	xorl %edx, %edx
0x00406b57:	cmpw (%eax), %dx
0x00406b5a:	je 0x00406c23
0x00406c23:	movl %eax, 0x8(%ebp)
0x00406c26:	cmpl %eax, %edx
0x00406c28:	je 0x00406c2c
0x00406c2c:	incl (%edi)
0x00406c2e:	popl %edi
0x00406c2f:	popl %esi
0x00406c30:	leave
0x00406c31:	ret

0x00406c81:	movl %ebx, -4(%ebp)
0x00406c84:	popl %ecx
0x00406c85:	popl %ecx
0x00406c86:	cmpl %ebx, $0x3fffffff<UINT32>
0x00406c8c:	jae 74
0x00406c8e:	movl %ecx, -8(%ebp)
0x00406c91:	cmpl %ecx, $0x7fffffff<UINT32>
0x00406c97:	jae 63
0x00406c99:	leal %eax, (%ecx,%ebx,2)
0x00406c9c:	addl %eax, %eax
0x00406c9e:	addl %ecx, %ecx
0x00406ca0:	cmpl %eax, %ecx
0x00406ca2:	jb 52
0x00406ca4:	pushl %eax
0x00406ca5:	call 0x00403e41
0x00406caa:	movl %esi, %eax
0x00406cac:	popl %ecx
0x00406cad:	testl %esi, %esi
0x00406caf:	je 39
0x00406cb1:	leal %eax, -4(%ebp)
0x00406cb4:	pushl %eax
0x00406cb5:	leal %ecx, (%esi,%ebx,4)
0x00406cb8:	pushl %esi
0x00406cb9:	leal %ebx, -8(%ebp)
0x00406cbc:	movl %eax, %edi
0x00406cbe:	call 0x00406ae1
0x00406afd:	movl %ecx, 0x8(%ebp)
0x00406b00:	addl 0x8(%ebp), $0x4<UINT8>
0x00406b04:	movl (%ecx), %esi
0x00406b25:	movw %cx, (%eax)
0x00406b28:	movw (%esi), %cx
0x00406b2b:	incl %esi
0x00406b2c:	incl %esi
0x00406c2a:	movl (%eax), %edx
0x00406cc3:	movl %eax, -4(%ebp)
0x00406cc6:	decl %eax
0x00406cc7:	popl %ecx
0x00406cc8:	movl 0x41332c, %eax
0x00406ccd:	popl %ecx
0x00406cce:	movl 0x413334, %esi
0x00406cd4:	xorl %eax, %eax
0x00406cd6:	jmp 0x00406cdb
0x00406cdb:	popl %edi
0x00406cdc:	popl %esi
0x00406cdd:	popl %ebx
0x00406cde:	leave
0x00406cdf:	ret

0x00403299:	testl %eax, %eax
0x0040329b:	jnl 0x004032a5
0x004032a5:	call 0x00406a03
0x00406a03:	movl %edi, %edi
0x00406a05:	pushl %esi
0x00406a06:	movl %esi, 0x412ff8
0x00406a0c:	pushl %edi
0x00406a0d:	xorl %edi, %edi
0x00406a0f:	testl %esi, %esi
0x00406a11:	jne 0x00406a2d
0x00406a2d:	movzwl %eax, (%esi)
0x00406a30:	testw %ax, %ax
0x00406a33:	jne 0x00406a1b
0x00406a1b:	cmpw %ax, $0x3d<UINT8>
0x00406a1f:	je 0x00406a22
0x00406a22:	pushl %esi
0x00406a23:	call 0x00405138
0x00405138:	movl %edi, %edi
0x0040513a:	pushl %ebp
0x0040513b:	movl %ebp, %esp
0x0040513d:	movl %eax, 0x8(%ebp)
0x00405140:	movw %cx, (%eax)
0x00405143:	incl %eax
0x00405144:	incl %eax
0x00405145:	testw %cx, %cx
0x00405148:	jne 0x00405140
0x0040514a:	subl %eax, 0x8(%ebp)
0x0040514d:	sarl %eax
0x0040514f:	decl %eax
0x00405150:	popl %ebp
0x00405151:	ret

0x00406a28:	popl %ecx
0x00406a29:	leal %esi, 0x2(%esi,%eax,2)
0x00406a21:	incl %edi
0x00406a35:	pushl %ebx
0x00406a36:	pushl $0x4<UINT8>
0x00406a38:	incl %edi
0x00406a39:	pushl %edi
0x00406a3a:	call 0x00403e86
0x00406a3f:	movl %ebx, %eax
0x00406a41:	popl %ecx
0x00406a42:	popl %ecx
0x00406a43:	movl 0x413340, %ebx
0x00406a49:	testl %ebx, %ebx
0x00406a4b:	jne 0x00406a52
0x00406a52:	movl %esi, 0x412ff8
0x00406a58:	jmp 0x00406a9e
0x00406a9e:	cmpw (%esi), $0x0<UINT8>
0x00406aa2:	jne 0x00406a5a
0x00406a5a:	pushl %esi
0x00406a5b:	call 0x00405138
0x00406a60:	movl %edi, %eax
0x00406a62:	incl %edi
0x00406a63:	cmpw (%esi), $0x3d<UINT8>
0x00406a67:	popl %ecx
0x00406a68:	je 0x00406a9b
0x00406a9b:	leal %esi, (%esi,%edi,2)
0x00406a6a:	pushl $0x2<UINT8>
0x00406a6c:	pushl %edi
0x00406a6d:	call 0x00403e86
0x00406a72:	popl %ecx
0x00406a73:	popl %ecx
0x00406a74:	movl (%ebx), %eax
0x00406a76:	testl %eax, %eax
0x00406a78:	je 80
0x00406a7a:	pushl %esi
0x00406a7b:	pushl %edi
0x00406a7c:	pushl %eax
0x00406a7d:	call 0x004051cf
0x004051cf:	movl %edi, %edi
0x004051d1:	pushl %ebp
0x004051d2:	movl %ebp, %esp
0x004051d4:	movl %edx, 0x8(%ebp)
0x004051d7:	pushl %ebx
0x004051d8:	pushl %esi
0x004051d9:	pushl %edi
0x004051da:	xorl %edi, %edi
0x004051dc:	cmpl %edx, %edi
0x004051de:	je 7
0x004051e0:	movl %ebx, 0xc(%ebp)
0x004051e3:	cmpl %ebx, %edi
0x004051e5:	ja 0x00405205
0x00405205:	movl %esi, 0x10(%ebp)
0x00405208:	cmpl %esi, %edi
0x0040520a:	jne 0x00405213
0x00405213:	movl %ecx, %edx
0x00405215:	movzwl %eax, (%esi)
0x00405218:	movw (%ecx), %ax
0x0040521b:	incl %ecx
0x0040521c:	incl %ecx
0x0040521d:	incl %esi
0x0040521e:	incl %esi
0x0040521f:	cmpw %ax, %di
0x00405222:	je 0x00405227
0x00405224:	decl %ebx
0x00405225:	jne 0x00405215
0x00405227:	xorl %eax, %eax
0x00405229:	cmpl %ebx, %edi
0x0040522b:	jne 0x00405200
0x00405200:	popl %edi
0x00405201:	popl %esi
0x00405202:	popl %ebx
0x00405203:	popl %ebp
0x00405204:	ret

0x00406a82:	addl %esp, $0xc<UINT8>
0x00406a85:	testl %eax, %eax
0x00406a87:	je 0x00406a98
0x00406a98:	addl %ebx, $0x4<UINT8>
0x00406aa4:	pushl 0x412ff8
0x00406aaa:	call 0x004038c3
0x004038c3:	pushl $0xc<UINT8>
0x004038c5:	pushl $0x410b08<UINT32>
0x004038ca:	call 0x00406024
0x004038cf:	movl %esi, 0x8(%ebp)
0x004038d2:	testl %esi, %esi
0x004038d4:	je 117
0x004038d6:	cmpl 0x413bbc, $0x3<UINT8>
0x004038dd:	jne 0x00403922
0x00403922:	pushl %esi
0x00403923:	pushl $0x0<UINT8>
0x00403925:	pushl 0x413a1c
0x0040392b:	call HeapFree@KERNEL32.dll
HeapFree@KERNEL32.dll: API Node	
0x00403931:	testl %eax, %eax
0x00403933:	jne 0x0040394b
0x0040394b:	call 0x00406069
0x00403950:	ret

0x00406aaf:	andl 0x412ff8, $0x0<UINT8>
0x00406ab6:	andl (%ebx), $0x0<UINT8>
0x00406ab9:	movl 0x413bc8, $0x1<UINT32>
0x00406ac3:	xorl %eax, %eax
0x00406ac5:	popl %ecx
0x00406ac6:	popl %ebx
0x00406ac7:	popl %edi
0x00406ac8:	popl %esi
0x00406ac9:	ret

0x004032aa:	testl %eax, %eax
0x004032ac:	jnl 0x004032b6
0x004032b6:	pushl $0x1<UINT8>
0x004032b8:	call 0x004040ae
0x004040ae:	movl %edi, %edi
0x004040b0:	pushl %ebp
0x004040b1:	movl %ebp, %esp
0x004040b3:	cmpl 0x413bd8, $0x0<UINT8>
0x004040ba:	je 0x004040d5
0x004040d5:	call 0x0040a8d5
0x0040a8d5:	movl %edi, %edi
0x0040a8d7:	pushl %esi
0x0040a8d8:	pushl %edi
0x0040a8d9:	xorl %edi, %edi
0x0040a8db:	leal %esi, 0x412d20(%edi)
0x0040a8e1:	pushl (%esi)
0x0040a8e3:	call 0x00406d89
0x00406dab:	pushl %eax
0x00406dac:	pushl 0x4126fc
0x00406db2:	call TlsGetValue@KERNEL32.dll
0x00406db4:	call FlsGetValue@KERNEL32.DLL
0x00406db6:	testl %eax, %eax
0x00406db8:	je 8
0x00406dba:	movl %eax, 0x1f8(%eax)
0x00406dc0:	jmp 0x00406de9
0x0040a8e8:	addl %edi, $0x4<UINT8>
0x0040a8eb:	popl %ecx
0x0040a8ec:	movl (%esi), %eax
0x0040a8ee:	cmpl %edi, $0x28<UINT8>
0x0040a8f1:	jb 0x0040a8db
0x0040a8f3:	popl %edi
0x0040a8f4:	popl %esi
0x0040a8f5:	ret

0x004040da:	pushl $0x40e1b8<UINT32>
0x004040df:	pushl $0x40e1a0<UINT32>
0x004040e4:	call 0x0040408a
0x0040408a:	movl %edi, %edi
0x0040408c:	pushl %ebp
0x0040408d:	movl %ebp, %esp
0x0040408f:	pushl %esi
0x00404090:	movl %esi, 0x8(%ebp)
0x00404093:	xorl %eax, %eax
0x00404095:	jmp 0x004040a6
0x004040a6:	cmpl %esi, 0xc(%ebp)
0x004040a9:	jb 0x00404097
0x00404097:	testl %eax, %eax
0x00404099:	jne 16
0x0040409b:	movl %ecx, (%esi)
0x0040409d:	testl %ecx, %ecx
0x0040409f:	je 0x004040a3
0x004040a3:	addl %esi, $0x4<UINT8>
0x004040a1:	call 0x0040909d
0x004024d1:	movl %eax, 0x414d20
0x004024d6:	pushl %esi
0x004024d7:	pushl $0x14<UINT8>
0x004024d9:	popl %esi
0x004024da:	testl %eax, %eax
0x004024dc:	jne 7
0x004024de:	movl %eax, $0x200<UINT32>
0x004024e3:	jmp 0x004024eb
0x004024eb:	movl 0x414d20, %eax
0x004024f0:	pushl $0x4<UINT8>
0x004024f2:	pushl %eax
0x004024f3:	call 0x00403e86
0x004024f8:	popl %ecx
0x004024f9:	popl %ecx
0x004024fa:	movl 0x413d04, %eax
0x004024ff:	testl %eax, %eax
0x00402501:	jne 0x00402521
0x00402521:	xorl %edx, %edx
0x00402523:	movl %ecx, $0x412000<UINT32>
0x00402528:	jmp 0x0040252f
0x0040252f:	movl (%edx,%eax), %ecx
0x00402532:	addl %ecx, $0x20<UINT8>
0x00402535:	addl %edx, $0x4<UINT8>
0x00402538:	cmpl %ecx, $0x412280<UINT32>
0x0040253e:	jl 0x0040252a
0x0040252a:	movl %eax, 0x413d04
0x00402540:	pushl $0xfffffffe<UINT8>
0x00402542:	popl %esi
0x00402543:	xorl %edx, %edx
0x00402545:	movl %ecx, $0x412010<UINT32>
0x0040254a:	pushl %edi
0x0040254b:	movl %eax, %edx
0x0040254d:	sarl %eax, $0x5<UINT8>
0x00402550:	movl %eax, 0x413c00(,%eax,4)
0x00402557:	movl %edi, %edx
0x00402559:	andl %edi, $0x1f<UINT8>
0x0040255c:	shll %edi, $0x6<UINT8>
0x0040255f:	movl %eax, (%edi,%eax)
0x00402562:	cmpl %eax, $0xffffffff<UINT8>
0x00402565:	je 8
0x00402567:	cmpl %eax, %esi
0x00402569:	je 4
0x0040256b:	testl %eax, %eax
0x0040256d:	jne 0x00402571
0x00402571:	addl %ecx, $0x20<UINT8>
0x00402574:	incl %edx
0x00402575:	cmpl %ecx, $0x412070<UINT32>
0x0040257b:	jl 0x0040254b
0x0040257d:	popl %edi
0x0040257e:	xorl %eax, %eax
0x00402580:	popl %esi
0x00402581:	ret

0x00403a63:	movl %edi, %edi
0x00403a65:	pushl %esi
0x00403a66:	pushl $0x4<UINT8>
0x00403a68:	pushl $0x20<UINT8>
0x00403a6a:	call 0x00403e86
0x00403a6f:	movl %esi, %eax
0x00403a71:	pushl %esi
0x00403a72:	call 0x00406d89
0x00403a77:	addl %esp, $0xc<UINT8>
0x00403a7a:	movl 0x413bd0, %eax
0x00403a7f:	movl 0x413bcc, %eax
0x00403a84:	testl %esi, %esi
0x00403a86:	jne 0x00403a8d
0x00403a8d:	andl (%esi), $0x0<UINT8>
0x00403a90:	xorl %eax, %eax
0x00403a92:	popl %esi
0x00403a93:	ret

0x004063a4:	call 0x00406342
0x00406342:	movl %edi, %edi
0x00406344:	pushl %ebp
0x00406345:	movl %ebp, %esp
0x00406347:	subl %esp, $0x18<UINT8>
0x0040634a:	xorl %eax, %eax
0x0040634c:	pushl %ebx
0x0040634d:	movl -4(%ebp), %eax
0x00406350:	movl -12(%ebp), %eax
0x00406353:	movl -8(%ebp), %eax
0x00406356:	pushl %ebx
0x00406357:	pushfl
0x00406358:	popl %eax
0x00406359:	movl %ecx, %eax
0x0040635b:	xorl %eax, $0x200000<UINT32>
0x00406360:	pushl %eax
0x00406361:	popfl
0x00406362:	pushfl
0x00406363:	popl %edx
0x00406364:	subl %edx, %ecx
0x00406366:	je 0x00406387
0x00406387:	popl %ebx
0x00406388:	testl -4(%ebp), $0x4000000<UINT32>
0x0040638f:	je 0x0040639f
0x0040639f:	xorl %eax, %eax
0x004063a1:	popl %ebx
0x004063a2:	leave
0x004063a3:	ret

0x004063a9:	movl 0x413bc0, %eax
0x004063ae:	xorl %eax, %eax
0x004063b0:	ret

0x0040909d:	cmpl 0x413bd4, $0x0<UINT8>
0x004090a4:	jne 18
0x004090a6:	pushl $0xfffffffd<UINT8>
0x004090a8:	call 0x00408f03
0x00408f03:	pushl $0x14<UINT8>
0x00408f05:	pushl $0x410d18<UINT32>
0x00408f0a:	call 0x00406024
0x00408f0f:	orl -32(%ebp), $0xffffffff<UINT8>
0x00408f13:	call 0x00407050
0x00407050:	movl %edi, %edi
0x00407052:	pushl %esi
0x00407053:	call 0x00406fd7
0x00406fd7:	movl %edi, %edi
0x00406fd9:	pushl %esi
0x00406fda:	pushl %edi
0x00406fdb:	call GetLastError@KERNEL32.dll
GetLastError@KERNEL32.dll: API Node	
0x00406fe1:	pushl 0x4126f8
0x00406fe7:	movl %edi, %eax
0x00406fe9:	call 0x00406e7f
0x00406e7f:	movl %edi, %edi
0x00406e81:	pushl %esi
0x00406e82:	pushl 0x4126fc
0x00406e88:	call TlsGetValue@KERNEL32.dll
0x00406e8e:	movl %esi, %eax
0x00406e90:	testl %esi, %esi
0x00406e92:	jne 0x00406eaf
0x00406eaf:	movl %eax, %esi
0x00406eb1:	popl %esi
0x00406eb2:	ret

0x00406fee:	call FlsGetValue@KERNEL32.DLL
0x00406ff0:	movl %esi, %eax
0x00406ff2:	testl %esi, %esi
0x00406ff4:	jne 0x00407044
0x00407044:	pushl %edi
0x00407045:	call SetLastError@KERNEL32.dll
SetLastError@KERNEL32.dll: API Node	
0x0040704b:	popl %edi
0x0040704c:	movl %eax, %esi
0x0040704e:	popl %esi
0x0040704f:	ret

0x00407058:	movl %esi, %eax
0x0040705a:	testl %esi, %esi
0x0040705c:	jne 0x00407066
0x00407066:	movl %eax, %esi
0x00407068:	popl %esi
0x00407069:	ret

0x00408f18:	movl %edi, %eax
0x00408f1a:	movl -36(%ebp), %edi
0x00408f1d:	call 0x00408bfe
0x00408bfe:	pushl $0xc<UINT8>
0x00408c00:	pushl $0x410cf8<UINT32>
0x00408c05:	call 0x00406024
0x00408c0a:	call 0x00407050
0x00408c0f:	movl %edi, %eax
0x00408c11:	movl %eax, 0x412c2c
0x00408c16:	testl 0x70(%edi), %eax
0x00408c19:	je 0x00408c38
0x00408c38:	pushl $0xd<UINT8>
0x00408c3a:	call 0x00404473
0x00408c3f:	popl %ecx
0x00408c40:	andl -4(%ebp), $0x0<UINT8>
0x00408c44:	movl %esi, 0x68(%edi)
0x00408c47:	movl -28(%ebp), %esi
0x00408c4a:	cmpl %esi, 0x412b30
0x00408c50:	je 0x00408c88
0x00408c88:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00408c8f:	call 0x00408c99
0x00408c99:	pushl $0xd<UINT8>
0x00408c9b:	call 0x00404399
0x00408ca0:	popl %ecx
0x00408ca1:	ret

0x00408c94:	jmp 0x00408c24
0x00408c24:	testl %esi, %esi
0x00408c26:	jne 0x00408c30
0x00408c30:	movl %eax, %esi
0x00408c32:	call 0x00406069
0x00408c37:	ret

0x00408f22:	movl %ebx, 0x68(%edi)
0x00408f25:	movl %esi, 0x8(%ebp)
0x00408f28:	call 0x00408ca2
0x00408ca2:	movl %edi, %edi
0x00408ca4:	pushl %ebp
0x00408ca5:	movl %ebp, %esp
0x00408ca7:	subl %esp, $0x10<UINT8>
0x00408caa:	pushl %ebx
0x00408cab:	xorl %ebx, %ebx
0x00408cad:	pushl %ebx
0x00408cae:	leal %ecx, -16(%ebp)
0x00408cb1:	call 0x004035bd
0x004035bd:	movl %edi, %edi
0x004035bf:	pushl %ebp
0x004035c0:	movl %ebp, %esp
0x004035c2:	movl %eax, 0x8(%ebp)
0x004035c5:	pushl %esi
0x004035c6:	movl %esi, %ecx
0x004035c8:	movb 0xc(%esi), $0x0<UINT8>
0x004035cc:	testl %eax, %eax
0x004035ce:	jne 99
0x004035d0:	call 0x00407050
0x004035d5:	movl 0x8(%esi), %eax
0x004035d8:	movl %ecx, 0x6c(%eax)
0x004035db:	movl (%esi), %ecx
0x004035dd:	movl %ecx, 0x68(%eax)
0x004035e0:	movl 0x4(%esi), %ecx
0x004035e3:	movl %ecx, (%esi)
0x004035e5:	cmpl %ecx, 0x412d10
0x004035eb:	je 0x004035ff
0x004035ff:	movl %eax, 0x4(%esi)
0x00403602:	cmpl %eax, 0x412b30
0x00403608:	je 0x00403620
0x00403620:	movl %eax, 0x8(%esi)
0x00403623:	testb 0x70(%eax), $0x2<UINT8>
0x00403627:	jne 20
0x00403629:	orl 0x70(%eax), $0x2<UINT8>
0x0040362d:	movb 0xc(%esi), $0x1<UINT8>
0x00403631:	jmp 0x0040363d
0x0040363d:	movl %eax, %esi
0x0040363f:	popl %esi
0x00403640:	popl %ebp
0x00403641:	ret $0x4<UINT16>

0x00408cb6:	movl 0x413a20, %ebx
0x00408cbc:	cmpl %esi, $0xfffffffe<UINT8>
0x00408cbf:	jne 0x00408cdf
0x00408cdf:	cmpl %esi, $0xfffffffd<UINT8>
0x00408ce2:	jne 0x00408cf6
0x00408ce4:	movl 0x413a20, $0x1<UINT32>
0x00408cee:	call GetACP@KERNEL32.dll
GetACP@KERNEL32.dll: API Node	
0x00408cf4:	jmp 0x00408cd1
0x00408cd1:	cmpb -4(%ebp), %bl
0x00408cd4:	je 69
0x00408cd6:	movl %ecx, -8(%ebp)
0x00408cd9:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00408cdd:	jmp 0x00408d1b
0x00408d1b:	popl %ebx
0x00408d1c:	leave
0x00408d1d:	ret

0x00408f2d:	movl 0x8(%ebp), %eax
0x00408f30:	cmpl %eax, 0x4(%ebx)
0x00408f33:	je 343
0x00408f39:	pushl $0x220<UINT32>
0x00408f3e:	call 0x00403e41
0x00408f43:	popl %ecx
0x00408f44:	movl %ebx, %eax
0x00408f46:	testl %ebx, %ebx
0x00408f48:	je 326
0x00408f4e:	movl %ecx, $0x88<UINT32>
0x00408f53:	movl %esi, 0x68(%edi)
0x00408f56:	movl %edi, %ebx
0x00408f58:	rep movsl %es:(%edi), %ds:(%esi)
0x00408f5a:	andl (%ebx), $0x0<UINT8>
0x00408f5d:	pushl %ebx
0x00408f5e:	pushl 0x8(%ebp)
0x00408f61:	call 0x00408d1e
0x00408d1e:	movl %edi, %edi
0x00408d20:	pushl %ebp
0x00408d21:	movl %ebp, %esp
0x00408d23:	subl %esp, $0x20<UINT8>
0x00408d26:	movl %eax, 0x412320
0x00408d2b:	xorl %eax, %ebp
0x00408d2d:	movl -4(%ebp), %eax
0x00408d30:	pushl %ebx
0x00408d31:	movl %ebx, 0xc(%ebp)
0x00408d34:	pushl %esi
0x00408d35:	movl %esi, 0x8(%ebp)
0x00408d38:	pushl %edi
0x00408d39:	call 0x00408ca2
0x00408cf6:	cmpl %esi, $0xfffffffc<UINT8>
0x00408cf9:	jne 0x00408d0d
0x00408d0d:	cmpb -4(%ebp), %bl
0x00408d10:	je 7
0x00408d12:	movl %eax, -8(%ebp)
0x00408d15:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x00408d19:	movl %eax, %esi
0x00408d3e:	movl %edi, %eax
0x00408d40:	xorl %esi, %esi
0x00408d42:	movl 0x8(%ebp), %edi
0x00408d45:	cmpl %edi, %esi
0x00408d47:	jne 0x00408d57
0x00408d57:	movl -28(%ebp), %esi
0x00408d5a:	xorl %eax, %eax
0x00408d5c:	cmpl 0x412b38(%eax), %edi
0x00408d62:	je 145
0x00408d68:	incl -28(%ebp)
0x00408d6b:	addl %eax, $0x30<UINT8>
0x00408d6e:	cmpl %eax, $0xf0<UINT32>
0x00408d73:	jb 0x00408d5c
0x00408d75:	cmpl %edi, $0xfde8<UINT32>
0x00408d7b:	je 368
0x00408d81:	cmpl %edi, $0xfde9<UINT32>
0x00408d87:	je 356
0x00408d8d:	movzwl %eax, %di
0x00408d90:	pushl %eax
0x00408d91:	call IsValidCodePage@KERNEL32.dll
IsValidCodePage@KERNEL32.dll: API Node	
0x00408d97:	testl %eax, %eax
0x00408d99:	je 338
0x00408d9f:	leal %eax, -24(%ebp)
0x00408da2:	pushl %eax
0x00408da3:	pushl %edi
0x00408da4:	call GetCPInfo@KERNEL32.dll
GetCPInfo@KERNEL32.dll: API Node	
0x00408daa:	testl %eax, %eax
0x00408dac:	je 307
0x00408db2:	pushl $0x101<UINT32>
0x00408db7:	leal %eax, 0x1c(%ebx)
0x00408dba:	pushl %esi
0x00408dbb:	pushl %eax
0x00408dbc:	call 0x00402ec0
0x00402ec0:	movl %edx, 0xc(%esp)
0x00402ec4:	movl %ecx, 0x4(%esp)
0x00402ec8:	testl %edx, %edx
0x00402eca:	je 105
0x00402ecc:	xorl %eax, %eax
0x00402ece:	movb %al, 0x8(%esp)
0x00402ed2:	testb %al, %al
0x00402ed4:	jne 22
0x00402ed6:	cmpl %edx, $0x100<UINT32>
0x00402edc:	jb 14
0x00402ede:	cmpl 0x413bc0, $0x0<UINT8>
0x00402ee5:	je 0x00402eec
0x00402eec:	pushl %edi
0x00402eed:	movl %edi, %ecx
0x00402eef:	cmpl %edx, $0x4<UINT8>
0x00402ef2:	jb 49
0x00402ef4:	negl %ecx
0x00402ef6:	andl %ecx, $0x3<UINT8>
0x00402ef9:	je 0x00402f07
0x00402f07:	movl %ecx, %eax
0x00402f09:	shll %eax, $0x8<UINT8>
0x00402f0c:	addl %eax, %ecx
0x00402f0e:	movl %ecx, %eax
0x00402f10:	shll %eax, $0x10<UINT8>
0x00402f13:	addl %eax, %ecx
0x00402f15:	movl %ecx, %edx
0x00402f17:	andl %edx, $0x3<UINT8>
0x00402f1a:	shrl %ecx, $0x2<UINT8>
0x00402f1d:	je 6
0x00402f1f:	rep stosl %es:(%edi), %eax
0x00402f21:	testl %edx, %edx
0x00402f23:	je 10
0x00402f25:	movb (%edi), %al
0x00402f27:	addl %edi, $0x1<UINT8>
0x00402f2a:	subl %edx, $0x1<UINT8>
0x00402f2d:	jne -10
0x00402f2f:	movl %eax, 0x8(%esp)
0x00402f33:	popl %edi
0x00402f34:	ret

0x00408dc1:	xorl %edx, %edx
0x00408dc3:	incl %edx
0x00408dc4:	addl %esp, $0xc<UINT8>
0x00408dc7:	movl 0x4(%ebx), %edi
0x00408dca:	movl 0xc(%ebx), %esi
0x00408dcd:	cmpl -24(%ebp), %edx
0x00408dd0:	jbe 248
0x00408dd6:	cmpb -18(%ebp), $0x0<UINT8>
0x00408dda:	je 0x00408eaf
0x00408eaf:	leal %eax, 0x1e(%ebx)
0x00408eb2:	movl %ecx, $0xfe<UINT32>
0x00408eb7:	orb (%eax), $0x8<UINT8>
0x00408eba:	incl %eax
0x00408ebb:	decl %ecx
0x00408ebc:	jne 0x00408eb7
0x00408ebe:	movl %eax, 0x4(%ebx)
0x00408ec1:	call 0x004089d8
0x004089d8:	subl %eax, $0x3a4<UINT32>
0x004089dd:	je 34
0x004089df:	subl %eax, $0x4<UINT8>
0x004089e2:	je 23
0x004089e4:	subl %eax, $0xd<UINT8>
0x004089e7:	je 12
0x004089e9:	decl %eax
0x004089ea:	je 3
0x004089ec:	xorl %eax, %eax
0x004089ee:	ret

0x00408ec6:	movl 0xc(%ebx), %eax
0x00408ec9:	movl 0x8(%ebx), %edx
0x00408ecc:	jmp 0x00408ed1
0x00408ed1:	xorl %eax, %eax
0x00408ed3:	movzwl %ecx, %ax
0x00408ed6:	movl %eax, %ecx
0x00408ed8:	shll %ecx, $0x10<UINT8>
0x00408edb:	orl %eax, %ecx
0x00408edd:	leal %edi, 0x10(%ebx)
0x00408ee0:	stosl %es:(%edi), %eax
0x00408ee1:	stosl %es:(%edi), %eax
0x00408ee2:	stosl %es:(%edi), %eax
0x00408ee3:	jmp 0x00408e8d
0x00408e8d:	movl %esi, %ebx
0x00408e8f:	call 0x00408a6b
0x00408a6b:	movl %edi, %edi
0x00408a6d:	pushl %ebp
0x00408a6e:	movl %ebp, %esp
0x00408a70:	subl %esp, $0x51c<UINT32>
0x00408a76:	movl %eax, 0x412320
0x00408a7b:	xorl %eax, %ebp
0x00408a7d:	movl -4(%ebp), %eax
0x00408a80:	pushl %ebx
0x00408a81:	pushl %edi
0x00408a82:	leal %eax, -1304(%ebp)
0x00408a88:	pushl %eax
0x00408a89:	pushl 0x4(%esi)
0x00408a8c:	call GetCPInfo@KERNEL32.dll
0x00408a92:	movl %edi, $0x100<UINT32>
0x00408a97:	testl %eax, %eax
0x00408a99:	je 251
0x00408a9f:	xorl %eax, %eax
0x00408aa1:	movb -260(%ebp,%eax), %al
0x00408aa8:	incl %eax
0x00408aa9:	cmpl %eax, %edi
0x00408aab:	jb 0x00408aa1
0x00408aad:	movb %al, -1298(%ebp)
0x00408ab3:	movb -260(%ebp), $0x20<UINT8>
0x00408aba:	testb %al, %al
0x00408abc:	je 0x00408aec
0x00408aec:	pushl $0x0<UINT8>
0x00408aee:	pushl 0xc(%esi)
0x00408af1:	leal %eax, -1284(%ebp)
0x00408af7:	pushl 0x4(%esi)
0x00408afa:	pushl %eax
0x00408afb:	pushl %edi
0x00408afc:	leal %eax, -260(%ebp)
0x00408b02:	pushl %eax
0x00408b03:	pushl $0x1<UINT8>
0x00408b05:	pushl $0x0<UINT8>
0x00408b07:	call 0x0040ccfa
0x0040ccfa:	movl %edi, %edi
0x0040ccfc:	pushl %ebp
0x0040ccfd:	movl %ebp, %esp
0x0040ccff:	subl %esp, $0x10<UINT8>
0x0040cd02:	pushl 0x8(%ebp)
0x0040cd05:	leal %ecx, -16(%ebp)
0x0040cd08:	call 0x004035bd
0x0040cd0d:	pushl 0x24(%ebp)
0x0040cd10:	leal %ecx, -16(%ebp)
0x0040cd13:	pushl 0x20(%ebp)
0x0040cd16:	pushl 0x1c(%ebp)
0x0040cd19:	pushl 0x18(%ebp)
0x0040cd1c:	pushl 0x14(%ebp)
0x0040cd1f:	pushl 0x10(%ebp)
0x0040cd22:	pushl 0xc(%ebp)
0x0040cd25:	call 0x0040cb40
0x0040cb40:	movl %edi, %edi
0x0040cb42:	pushl %ebp
0x0040cb43:	movl %ebp, %esp
0x0040cb45:	pushl %ecx
0x0040cb46:	pushl %ecx
0x0040cb47:	movl %eax, 0x412320
0x0040cb4c:	xorl %eax, %ebp
0x0040cb4e:	movl -4(%ebp), %eax
0x0040cb51:	movl %eax, 0x413aa0
0x0040cb56:	pushl %ebx
0x0040cb57:	pushl %esi
0x0040cb58:	xorl %ebx, %ebx
0x0040cb5a:	pushl %edi
0x0040cb5b:	movl %edi, %ecx
0x0040cb5d:	cmpl %eax, %ebx
0x0040cb5f:	jne 58
0x0040cb61:	leal %eax, -8(%ebp)
0x0040cb64:	pushl %eax
0x0040cb65:	xorl %esi, %esi
0x0040cb67:	incl %esi
0x0040cb68:	pushl %esi
0x0040cb69:	pushl $0x40f174<UINT32>
0x0040cb6e:	pushl %esi
0x0040cb6f:	call GetStringTypeW@KERNEL32.dll
GetStringTypeW@KERNEL32.dll: API Node	
0x0040cb75:	testl %eax, %eax
0x0040cb77:	je 8
0x0040cb79:	movl 0x413aa0, %esi
0x0040cb7f:	jmp 0x0040cbb5
0x0040cbb5:	movl -8(%ebp), %ebx
0x0040cbb8:	cmpl 0x18(%ebp), %ebx
0x0040cbbb:	jne 0x0040cbc5
0x0040cbc5:	movl %esi, 0x40e050
0x0040cbcb:	xorl %eax, %eax
0x0040cbcd:	cmpl 0x20(%ebp), %ebx
0x0040cbd0:	pushl %ebx
0x0040cbd1:	pushl %ebx
0x0040cbd2:	pushl 0x10(%ebp)
0x0040cbd5:	setne %al
0x0040cbd8:	pushl 0xc(%ebp)
0x0040cbdb:	leal %eax, 0x1(,%eax,8)
0x0040cbe2:	pushl %eax
0x0040cbe3:	pushl 0x18(%ebp)
0x0040cbe6:	call MultiByteToWideChar@KERNEL32.dll
MultiByteToWideChar@KERNEL32.dll: API Node	
0x0040cbe8:	movl %edi, %eax
0x0040cbea:	cmpl %edi, %ebx
0x0040cbec:	je 171
0x0040cbf2:	jle 60
0x0040cbf4:	cmpl %edi, $0x7ffffff0<UINT32>
0x0040cbfa:	ja 52
0x0040cbfc:	leal %eax, 0x8(%edi,%edi)
0x0040cc00:	cmpl %eax, $0x400<UINT32>
0x0040cc05:	ja 19
0x0040cc07:	call 0x00409850
0x00409850:	pushl %ecx
0x00409851:	leal %ecx, 0x8(%esp)
0x00409855:	subl %ecx, %eax
0x00409857:	andl %ecx, $0xf<UINT8>
0x0040985a:	addl %eax, %ecx
0x0040985c:	sbbl %ecx, %ecx
0x0040985e:	orl %eax, %ecx
0x00409860:	popl %ecx
0x00409861:	jmp 0x0040c570
0x0040c570:	pushl %ecx
0x0040c571:	leal %ecx, 0x4(%esp)
0x0040c575:	subl %ecx, %eax
0x0040c577:	sbbl %eax, %eax
0x0040c579:	notl %eax
0x0040c57b:	andl %ecx, %eax
0x0040c57d:	movl %eax, %esp
0x0040c57f:	andl %eax, $0xfffff000<UINT32>
0x0040c584:	cmpl %ecx, %eax
0x0040c586:	jb 10
0x0040c588:	movl %eax, %ecx
0x0040c58a:	popl %ecx
0x0040c58b:	xchgl %esp, %eax
0x0040c58c:	movl %eax, (%eax)
0x0040c58e:	movl (%esp), %eax
0x0040c591:	ret

0x0040cc0c:	movl %eax, %esp
0x0040cc0e:	cmpl %eax, %ebx
0x0040cc10:	je 28
0x0040cc12:	movl (%eax), $0xcccc<UINT32>
0x0040cc18:	jmp 0x0040cc2b
0x0040cc2b:	addl %eax, $0x8<UINT8>
0x0040cc2e:	movl %ebx, %eax
0x0040cc30:	testl %ebx, %ebx
0x0040cc32:	je 105
0x0040cc34:	leal %eax, (%edi,%edi)
0x0040cc37:	pushl %eax
0x0040cc38:	pushl $0x0<UINT8>
0x0040cc3a:	pushl %ebx
0x0040cc3b:	call 0x00402ec0
