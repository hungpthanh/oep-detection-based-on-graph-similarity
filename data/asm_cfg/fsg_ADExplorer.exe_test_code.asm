0x004a7000:	movl %ebx, $0x4001d0<UINT32>
0x004a7005:	movl %edi, $0x401000<UINT32>
0x004a700a:	movl %esi, $0x479500<UINT32>
0x004a700f:	pushl %ebx
0x004a7010:	call 0x004a701f
0x004a701f:	cld
0x004a7020:	movb %dl, $0xffffff80<UINT8>
0x004a7022:	movsb %es:(%edi), %ds:(%esi)
0x004a7023:	pushl $0x2<UINT8>
0x004a7025:	popl %ebx
0x004a7026:	call 0x004a7015
0x004a7015:	addb %dl, %dl
0x004a7017:	jne 0x004a701e
0x004a7019:	movb %dl, (%esi)
0x004a701b:	incl %esi
0x004a701c:	adcb %dl, %dl
0x004a701e:	ret

0x004a7029:	jae 0x004a7022
0x004a702b:	xorl %ecx, %ecx
0x004a702d:	call 0x004a7015
0x004a7030:	jae 0x004a704a
0x004a7032:	xorl %eax, %eax
0x004a7034:	call 0x004a7015
0x004a7037:	jae 0x004a705a
0x004a7039:	movb %bl, $0x2<UINT8>
0x004a703b:	incl %ecx
0x004a703c:	movb %al, $0x10<UINT8>
0x004a703e:	call 0x004a7015
0x004a7041:	adcb %al, %al
0x004a7043:	jae 0x004a703e
0x004a7045:	jne 0x004a7086
0x004a7086:	pushl %esi
0x004a7087:	movl %esi, %edi
0x004a7089:	subl %esi, %eax
0x004a708b:	rep movsb %es:(%edi), %ds:(%esi)
0x004a708d:	popl %esi
0x004a708e:	jmp 0x004a7026
0x004a7047:	stosb %es:(%edi), %al
0x004a7048:	jmp 0x004a7026
0x004a704a:	call 0x004a7092
0x004a7092:	incl %ecx
0x004a7093:	call 0x004a7015
0x004a7097:	adcl %ecx, %ecx
0x004a7099:	call 0x004a7015
0x004a709d:	jb 0x004a7093
0x004a709f:	ret

0x004a704f:	subl %ecx, %ebx
0x004a7051:	jne 0x004a7063
0x004a7063:	xchgl %ecx, %eax
0x004a7064:	decl %eax
0x004a7065:	shll %eax, $0x8<UINT8>
0x004a7068:	lodsb %al, %ds:(%esi)
0x004a7069:	call 0x004a7090
0x004a7090:	xorl %ecx, %ecx
0x004a706e:	cmpl %eax, $0x7d00<UINT32>
0x004a7073:	jae 0x004a707f
0x004a7075:	cmpb %ah, $0x5<UINT8>
0x004a7078:	jae 0x004a7080
0x004a707a:	cmpl %eax, $0x7f<UINT8>
0x004a707d:	ja 0x004a7081
0x004a707f:	incl %ecx
0x004a7080:	incl %ecx
0x004a7081:	xchgl %ebp, %eax
0x004a7082:	movl %eax, %ebp
0x004a7084:	movb %bl, $0x1<UINT8>
0x004a7053:	call 0x004a7090
0x004a7058:	jmp 0x004a7082
0x004a705a:	lodsb %al, %ds:(%esi)
0x004a705b:	shrl %eax
0x004a705d:	je 0x004a70a0
0x004a705f:	adcl %ecx, %ecx
0x004a7061:	jmp 0x004a707f
0x004a70a0:	popl %edi
0x004a70a1:	popl %ebx
0x004a70a2:	movzwl %edi, (%ebx)
0x004a70a5:	decl %edi
0x004a70a6:	je 0x004a70b0
0x004a70a8:	decl %edi
0x004a70a9:	je 0x004a70be
0x004a70ab:	shll %edi, $0xc<UINT8>
0x004a70ae:	jmp 0x004a70b7
0x004a70b7:	incl %ebx
0x004a70b8:	incl %ebx
0x004a70b9:	jmp 0x004a700f
0x004a70b0:	movl %edi, 0x2(%ebx)
0x004a70b3:	pushl %edi
0x004a70b4:	addl %ebx, $0x4<UINT8>
0x004a70be:	popl %edi
0x004a70bf:	movl %ebx, $0x4a7128<UINT32>
0x004a70c4:	incl %edi
0x004a70c5:	movl %esi, (%edi)
0x004a70c7:	scasl %eax, %es:(%edi)
0x004a70c8:	pushl %edi
0x004a70c9:	call LoadLibraryA@KERNEL32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004a70cb:	xchgl %ebp, %eax
0x004a70cc:	xorl %eax, %eax
0x004a70ce:	scasb %al, %es:(%edi)
0x004a70cf:	jne 0x004a70ce
0x004a70d1:	decb (%edi)
0x004a70d3:	je 0x004a70c4
0x004a70d5:	decb (%edi)
0x004a70d7:	jne 0x004a70df
0x004a70df:	decb (%edi)
0x004a70e1:	je 0x004149ec
0x004a70e7:	pushl %edi
0x004a70e8:	pushl %ebp
0x004a70e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x004a70ec:	orl (%esi), %eax
0x004a70ee:	lodsl %eax, %ds:(%esi)
0x004a70ef:	jne 0x004a70cc
GetProcAddress@KERNEL32.dll: API Node	
LoadLibraryA@KERNEL32.dll: API Node	
0x004a70d9:	incl %edi
0x004a70da:	pushl (%edi)
0x004a70dc:	scasl %eax, %es:(%edi)
0x004a70dd:	jmp 0x004a70e8
0x004149ec:	call 0x0041c1ab
0x0041c1ab:	movl %edi, %edi
0x0041c1ad:	pushl %ebp
0x0041c1ae:	movl %ebp, %esp
0x0041c1b0:	subl %esp, $0x10<UINT8>
0x0041c1b3:	movl %eax, 0x460064
0x0041c1b8:	andl -8(%ebp), $0x0<UINT8>
0x0041c1bc:	andl -4(%ebp), $0x0<UINT8>
0x0041c1c0:	pushl %ebx
0x0041c1c1:	pushl %edi
0x0041c1c2:	movl %edi, $0xbb40e64e<UINT32>
0x0041c1c7:	movl %ebx, $0xffff0000<UINT32>
0x0041c1cc:	cmpl %eax, %edi
0x0041c1ce:	je 0x0041c1dd
0x0041c1dd:	pushl %esi
0x0041c1de:	leal %eax, -8(%ebp)
0x0041c1e1:	pushl %eax
0x0041c1e2:	call GetSystemTimeAsFileTime@KERNEL32.dll
GetSystemTimeAsFileTime@KERNEL32.dll: API Node	
0x0041c1e8:	movl %esi, -4(%ebp)
0x0041c1eb:	xorl %esi, -8(%ebp)
0x0041c1ee:	call GetCurrentProcessId@KERNEL32.dll
GetCurrentProcessId@KERNEL32.dll: API Node	
0x0041c1f4:	xorl %esi, %eax
0x0041c1f6:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x0041c1fc:	xorl %esi, %eax
0x0041c1fe:	call GetTickCount@KERNEL32.dll
GetTickCount@KERNEL32.dll: API Node	
0x0041c204:	xorl %esi, %eax
0x0041c206:	leal %eax, -16(%ebp)
0x0041c209:	pushl %eax
0x0041c20a:	call QueryPerformanceCounter@KERNEL32.dll
QueryPerformanceCounter@KERNEL32.dll: API Node	
0x0041c210:	movl %eax, -12(%ebp)
0x0041c213:	xorl %eax, -16(%ebp)
0x0041c216:	xorl %esi, %eax
0x0041c218:	cmpl %esi, %edi
0x0041c21a:	jne 0x0041c223
0x0041c223:	testl %ebx, %esi
0x0041c225:	jne 0x0041c22e
0x0041c22e:	movl 0x460064, %esi
0x0041c234:	notl %esi
0x0041c236:	movl 0x460068, %esi
0x0041c23c:	popl %esi
0x0041c23d:	popl %edi
0x0041c23e:	popl %ebx
0x0041c23f:	leave
0x0041c240:	ret

0x004149f1:	jmp 0x0041486e
0x0041486e:	pushl $0x58<UINT8>
0x00414870:	pushl $0x45b920<UINT32>
0x00414875:	call 0x0041935c
0x0041935c:	pushl $0x414b00<UINT32>
0x00419361:	pushl %fs:0
0x00419368:	movl %eax, 0x10(%esp)
0x0041936c:	movl 0x10(%esp), %ebp
0x00419370:	leal %ebp, 0x10(%esp)
0x00419374:	subl %esp, %eax
0x00419376:	pushl %ebx
0x00419377:	pushl %esi
0x00419378:	pushl %edi
0x00419379:	movl %eax, 0x460064
0x0041937e:	xorl -4(%ebp), %eax
0x00419381:	xorl %eax, %ebp
0x00419383:	pushl %eax
0x00419384:	movl -24(%ebp), %esp
0x00419387:	pushl -8(%ebp)
0x0041938a:	movl %eax, -4(%ebp)
0x0041938d:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00419394:	movl -8(%ebp), %eax
0x00419397:	leal %eax, -16(%ebp)
0x0041939a:	movl %fs:0, %eax
0x004193a0:	ret

0x0041487a:	xorl %esi, %esi
0x0041487c:	movl -4(%ebp), %esi
0x0041487f:	leal %eax, -104(%ebp)
0x00414882:	pushl %eax
0x00414883:	call GetStartupInfoA@KERNEL32.dll
GetStartupInfoA@KERNEL32.dll: API Node	
0x00414889:	pushl $0xfffffffe<UINT8>
0x0041488b:	popl %edi
0x0041488c:	movl -4(%ebp), %edi
0x0041488f:	movl %eax, $0x5a4d<UINT32>
0x00414894:	cmpw 0x400000, %ax
0x0041489b:	jne 56
0x0041489d:	movl %eax, 0x40003c
0x004148a2:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x004148ac:	jne 39
0x004148ae:	movl %ecx, $0x10b<UINT32>
0x004148b3:	cmpw 0x400018(%eax), %cx
0x004148ba:	jne 25
0x004148bc:	cmpl 0x400074(%eax), $0xe<UINT8>
0x004148c3:	jbe 16
0x004148c5:	xorl %ecx, %ecx
0x004148c7:	cmpl 0x4000e8(%eax), %esi
0x004148cd:	setne %cl
0x004148d0:	movl -28(%ebp), %ecx
0x004148d3:	jmp 0x004148d8
0x004148d8:	xorl %ebx, %ebx
0x004148da:	incl %ebx
0x004148db:	pushl %ebx
0x004148dc:	call 0x004186b9
0x004186b9:	movl %edi, %edi
0x004186bb:	pushl %ebp
0x004186bc:	movl %ebp, %esp
0x004186be:	xorl %eax, %eax
0x004186c0:	cmpl 0x8(%ebp), %eax
0x004186c3:	pushl $0x0<UINT8>
0x004186c5:	sete %al
0x004186c8:	pushl $0x1000<UINT32>
0x004186cd:	pushl %eax
0x004186ce:	call HeapCreate@KERNEL32.dll
HeapCreate@KERNEL32.dll: API Node	
0x004186d4:	movl 0x46a6ec, %eax
0x004186d9:	testl %eax, %eax
0x004186db:	jne 0x004186df
0x004186df:	xorl %eax, %eax
0x004186e1:	incl %eax
0x004186e2:	movl 0x46c5b4, %eax
0x004186e7:	popl %ebp
0x004186e8:	ret

0x004148e1:	popl %ecx
0x004148e2:	testl %eax, %eax
0x004148e4:	jne 0x004148ee
0x004148ee:	call 0x00417234
0x00417234:	movl %edi, %edi
0x00417236:	pushl %esi
0x00417237:	pushl %edi
0x00417238:	movl %esi, $0x450784<UINT32>
0x0041723d:	pushl %esi
0x0041723e:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x00417244:	testl %eax, %eax
0x00417246:	jne 0x0041724f
0x0041724f:	movl %edi, %eax
0x00417251:	testl %edi, %edi
0x00417253:	je 350
0x00417259:	movl %esi, 0x450270
0x0041725f:	pushl $0x4507d0<UINT32>
0x00417264:	pushl %edi
0x00417265:	call GetProcAddress@KERNEL32.dll
0x00417267:	pushl $0x4507c4<UINT32>
0x0041726c:	pushl %edi
0x0041726d:	movl 0x46a6dc, %eax
0x00417272:	call GetProcAddress@KERNEL32.dll
0x00417274:	pushl $0x4507b8<UINT32>
0x00417279:	pushl %edi
0x0041727a:	movl 0x46a6e0, %eax
0x0041727f:	call GetProcAddress@KERNEL32.dll
0x00417281:	pushl $0x4507b0<UINT32>
0x00417286:	pushl %edi
0x00417287:	movl 0x46a6e4, %eax
0x0041728c:	call GetProcAddress@KERNEL32.dll
0x0041728e:	cmpl 0x46a6dc, $0x0<UINT8>
0x00417295:	movl %esi, 0x450224
0x0041729b:	movl 0x46a6e8, %eax
0x004172a0:	je 22
0x004172a2:	cmpl 0x46a6e0, $0x0<UINT8>
0x004172a9:	je 13
0x004172ab:	cmpl 0x46a6e4, $0x0<UINT8>
0x004172b2:	je 4
0x004172b4:	testl %eax, %eax
0x004172b6:	jne 0x004172dc
0x004172dc:	call TlsAlloc@KERNEL32.dll
TlsAlloc@KERNEL32.dll: API Node	
0x004172e2:	movl 0x460804, %eax
0x004172e7:	cmpl %eax, $0xffffffff<UINT8>
0x004172ea:	je 204
0x004172f0:	pushl 0x46a6e0
0x004172f6:	pushl %eax
0x004172f7:	call TlsSetValue@KERNEL32.dll
TlsSetValue@KERNEL32.dll: API Node	
0x004172f9:	testl %eax, %eax
0x004172fb:	je 187
0x00417301:	call 0x0041969f
0x0041969f:	movl %edi, %edi
0x004196a1:	pushl %esi
0x004196a2:	call 0x00416deb
0x00416deb:	pushl $0x0<UINT8>
0x00416ded:	call 0x00416d79
0x00416d79:	movl %edi, %edi
0x00416d7b:	pushl %ebp
0x00416d7c:	movl %ebp, %esp
0x00416d7e:	pushl %esi
0x00416d7f:	pushl 0x460804
0x00416d85:	movl %esi, 0x45022c
0x00416d8b:	call TlsGetValue@KERNEL32.dll
TlsGetValue@KERNEL32.dll: API Node	
0x00416d8d:	testl %eax, %eax
0x00416d8f:	je 33
0x00416d91:	movl %eax, 0x460800
0x00416d96:	cmpl %eax, $0xffffffff<UINT8>
0x00416d99:	je 0x00416db2
0x00416db2:	movl %esi, $0x450784<UINT32>
0x00416db7:	pushl %esi
0x00416db8:	call GetModuleHandleW@KERNEL32.dll
0x00416dbe:	testl %eax, %eax
0x00416dc0:	jne 0x00416dcd
0x00416dcd:	pushl $0x450774<UINT32>
0x00416dd2:	pushl %eax
0x00416dd3:	call GetProcAddress@KERNEL32.dll
0x00416dd9:	testl %eax, %eax
0x00416ddb:	je 8
0x00416ddd:	pushl 0x8(%ebp)
0x00416de0:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00416de2:	movl 0x8(%ebp), %eax
0x00416de5:	movl %eax, 0x8(%ebp)
0x00416de8:	popl %esi
0x00416de9:	popl %ebp
0x00416dea:	ret

0x00416df2:	popl %ecx
0x00416df3:	ret

0x004196a7:	movl %esi, %eax
0x004196a9:	pushl %esi
0x004196aa:	call 0x004198d1
0x004198d1:	movl %edi, %edi
0x004198d3:	pushl %ebp
0x004198d4:	movl %ebp, %esp
0x004198d6:	movl %eax, 0x8(%ebp)
0x004198d9:	movl 0x46ab8c, %eax
0x004198de:	popl %ebp
0x004198df:	ret

0x004196af:	pushl %esi
0x004196b0:	call 0x0041fff4
0x0041fff4:	movl %edi, %edi
0x0041fff6:	pushl %ebp
0x0041fff7:	movl %ebp, %esp
0x0041fff9:	movl %eax, 0x8(%ebp)
0x0041fffc:	movl 0x46ace0, %eax
0x00420001:	popl %ebp
0x00420002:	ret

0x004196b5:	pushl %esi
0x004196b6:	call 0x004115c1
0x004115c1:	movl %edi, %edi
0x004115c3:	pushl %ebp
0x004115c4:	movl %ebp, %esp
0x004115c6:	movl %eax, 0x8(%ebp)
0x004115c9:	movl 0x46a340, %eax
0x004115ce:	popl %ebp
0x004115cf:	ret

0x004196bb:	pushl %esi
0x004196bc:	call 0x00419fa4
0x00419fa4:	movl %edi, %edi
0x00419fa6:	pushl %ebp
0x00419fa7:	movl %ebp, %esp
0x00419fa9:	movl %eax, 0x8(%ebp)
0x00419fac:	movl 0x46aba4, %eax
0x00419fb1:	popl %ebp
0x00419fb2:	ret

0x004196c1:	pushl %esi
0x004196c2:	call 0x00420275
0x00420275:	movl %edi, %edi
0x00420277:	pushl %ebp
0x00420278:	movl %ebp, %esp
0x0042027a:	movl %eax, 0x8(%ebp)
0x0042027d:	movl 0x46acf8, %eax
0x00420282:	popl %ebp
0x00420283:	ret

0x004196c7:	pushl %esi
0x004196c8:	call 0x00420063
0x00420063:	movl %edi, %edi
0x00420065:	pushl %ebp
0x00420066:	movl %ebp, %esp
0x00420068:	movl %eax, 0x8(%ebp)
0x0042006b:	movl 0x46ace4, %eax
0x00420070:	movl 0x46ace8, %eax
0x00420075:	movl 0x46acec, %eax
0x0042007a:	movl 0x46acf0, %eax
0x0042007f:	popl %ebp
0x00420080:	ret

0x004196cd:	pushl %esi
0x004196ce:	call 0x00415126
0x00415126:	ret

0x004196d3:	pushl %esi
0x004196d4:	call 0x0041998c
0x0041998c:	pushl $0x419908<UINT32>
0x00419991:	call 0x00416d79
0x00419996:	popl %ecx
0x00419997:	movl 0x46ab94, %eax
0x0041999c:	ret

0x004196d9:	pushl $0x41966b<UINT32>
0x004196de:	call 0x00416d79
0x004196e3:	addl %esp, $0x24<UINT8>
0x004196e6:	movl 0x460930, %eax
0x004196eb:	popl %esi
0x004196ec:	ret

0x00417306:	pushl 0x46a6dc
0x0041730c:	call 0x00416d79
0x00417311:	pushl 0x46a6e0
0x00417317:	movl 0x46a6dc, %eax
0x0041731c:	call 0x00416d79
0x00417321:	pushl 0x46a6e4
0x00417327:	movl 0x46a6e0, %eax
0x0041732c:	call 0x00416d79
0x00417331:	pushl 0x46a6e8
0x00417337:	movl 0x46a6e4, %eax
0x0041733c:	call 0x00416d79
0x00417341:	addl %esp, $0x10<UINT8>
0x00417344:	movl 0x46a6e8, %eax
0x00417349:	call 0x004186e9
0x004186e9:	movl %edi, %edi
0x004186eb:	pushl %esi
0x004186ec:	pushl %edi
0x004186ed:	xorl %esi, %esi
0x004186ef:	movl %edi, $0x46a6f0<UINT32>
0x004186f4:	cmpl 0x460814(,%esi,8), $0x1<UINT8>
0x004186fc:	jne 0x0041871c
0x004186fe:	leal %eax, 0x460810(,%esi,8)
0x00418705:	movl (%eax), %edi
0x00418707:	pushl $0xfa0<UINT32>
0x0041870c:	pushl (%eax)
0x0041870e:	addl %edi, $0x18<UINT8>
0x00418711:	call 0x00420003
0x00420003:	pushl $0x10<UINT8>
0x00420005:	pushl $0x45bd40<UINT32>
0x0042000a:	call 0x0041935c
0x0042000f:	andl -4(%ebp), $0x0<UINT8>
0x00420013:	pushl 0xc(%ebp)
0x00420016:	pushl 0x8(%ebp)
0x00420019:	call InitializeCriticalSectionAndSpinCount@KERNEL32.dll
InitializeCriticalSectionAndSpinCount@KERNEL32.dll: API Node	
0x0042001f:	movl -28(%ebp), %eax
0x00420022:	jmp 0x00420053
0x00420053:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0042005a:	movl %eax, -28(%ebp)
0x0042005d:	call 0x004193a1
0x004193a1:	movl %ecx, -16(%ebp)
0x004193a4:	movl %fs:0, %ecx
0x004193ab:	popl %ecx
0x004193ac:	popl %edi
0x004193ad:	popl %edi
0x004193ae:	popl %esi
0x004193af:	popl %ebx
0x004193b0:	movl %esp, %ebp
0x004193b2:	popl %ebp
0x004193b3:	pushl %ecx
0x004193b4:	ret

0x00420062:	ret

0x00418716:	popl %ecx
0x00418717:	popl %ecx
0x00418718:	testl %eax, %eax
0x0041871a:	je 12
0x0041871c:	incl %esi
0x0041871d:	cmpl %esi, $0x24<UINT8>
0x00418720:	jl 0x004186f4
0x00418722:	xorl %eax, %eax
0x00418724:	incl %eax
0x00418725:	popl %edi
0x00418726:	popl %esi
0x00418727:	ret

0x0041734e:	testl %eax, %eax
0x00417350:	je 101
0x00417352:	pushl $0x417097<UINT32>
0x00417357:	pushl 0x46a6dc
0x0041735d:	call 0x00416df4
0x00416df4:	movl %edi, %edi
0x00416df6:	pushl %ebp
0x00416df7:	movl %ebp, %esp
0x00416df9:	pushl %esi
0x00416dfa:	pushl 0x460804
0x00416e00:	movl %esi, 0x45022c
0x00416e06:	call TlsGetValue@KERNEL32.dll
0x00416e08:	testl %eax, %eax
0x00416e0a:	je 33
0x00416e0c:	movl %eax, 0x460800
0x00416e11:	cmpl %eax, $0xffffffff<UINT8>
0x00416e14:	je 0x00416e2d
0x00416e2d:	movl %esi, $0x450784<UINT32>
0x00416e32:	pushl %esi
0x00416e33:	call GetModuleHandleW@KERNEL32.dll
0x00416e39:	testl %eax, %eax
0x00416e3b:	jne 0x00416e48
0x00416e48:	pushl $0x4507a0<UINT32>
0x00416e4d:	pushl %eax
0x00416e4e:	call GetProcAddress@KERNEL32.dll
0x00416e54:	testl %eax, %eax
0x00416e56:	je 8
0x00416e58:	pushl 0x8(%ebp)
0x00416e5b:	call DecodePointer@KERNEL32.DLL
DecodePointer@KERNEL32.DLL: API Node	
0x00416e5d:	movl 0x8(%ebp), %eax
0x00416e60:	movl %eax, 0x8(%ebp)
0x00416e63:	popl %esi
0x00416e64:	popl %ebp
0x00416e65:	ret

0x00417362:	popl %ecx
0x00417363:	call FlsAlloc@KERNEL32.DLL
FlsAlloc@KERNEL32.DLL: API Node	
0x00417365:	movl 0x460800, %eax
0x0041736a:	cmpl %eax, $0xffffffff<UINT8>
0x0041736d:	je 72
0x0041736f:	pushl $0x214<UINT32>
0x00417374:	pushl $0x1<UINT8>
0x00417376:	call 0x00419c92
0x00419c92:	movl %edi, %edi
0x00419c94:	pushl %ebp
0x00419c95:	movl %ebp, %esp
0x00419c97:	pushl %esi
0x00419c98:	pushl %edi
0x00419c99:	xorl %esi, %esi
0x00419c9b:	pushl $0x0<UINT8>
0x00419c9d:	pushl 0xc(%ebp)
0x00419ca0:	pushl 0x8(%ebp)
0x00419ca3:	call 0x0041aed0
0x0041aed0:	pushl $0xc<UINT8>
0x0041aed2:	pushl $0x45bb60<UINT32>
0x0041aed7:	call 0x0041935c
0x0041aedc:	movl %ecx, 0x8(%ebp)
0x0041aedf:	xorl %edi, %edi
0x0041aee1:	cmpl %ecx, %edi
0x0041aee3:	jbe 46
0x0041aee5:	pushl $0xffffffe0<UINT8>
0x0041aee7:	popl %eax
0x0041aee8:	xorl %edx, %edx
0x0041aeea:	divl %eax, %ecx
0x0041aeec:	cmpl %eax, 0xc(%ebp)
0x0041aeef:	sbbl %eax, %eax
0x0041aef1:	incl %eax
0x0041aef2:	jne 0x0041af13
0x0041af13:	imull %ecx, 0xc(%ebp)
0x0041af17:	movl %esi, %ecx
0x0041af19:	movl 0x8(%ebp), %esi
0x0041af1c:	cmpl %esi, %edi
0x0041af1e:	jne 0x0041af23
0x0041af23:	xorl %ebx, %ebx
0x0041af25:	movl -28(%ebp), %ebx
0x0041af28:	cmpl %esi, $0xffffffe0<UINT8>
0x0041af2b:	ja 105
0x0041af2d:	cmpl 0x46c5b4, $0x3<UINT8>
0x0041af34:	jne 0x0041af81
0x0041af81:	cmpl %ebx, %edi
0x0041af83:	jne 97
0x0041af85:	pushl %esi
0x0041af86:	pushl $0x8<UINT8>
0x0041af88:	pushl 0x46a6ec
0x0041af8e:	call HeapAlloc@KERNEL32.dll
HeapAlloc@KERNEL32.dll: API Node	
0x0041af94:	movl %ebx, %eax
0x0041af96:	cmpl %ebx, %edi
0x0041af98:	jne 0x0041afe6
0x0041afe6:	movl %eax, %ebx
0x0041afe8:	call 0x004193a1
0x0041afed:	ret

0x00419ca8:	movl %edi, %eax
0x00419caa:	addl %esp, $0xc<UINT8>
0x00419cad:	testl %edi, %edi
0x00419caf:	jne 0x00419cd8
0x00419cd8:	movl %eax, %edi
0x00419cda:	popl %edi
0x00419cdb:	popl %esi
0x00419cdc:	popl %ebp
0x00419cdd:	ret

0x0041737b:	movl %esi, %eax
0x0041737d:	popl %ecx
0x0041737e:	popl %ecx
0x0041737f:	testl %esi, %esi
0x00417381:	je 52
0x00417383:	pushl %esi
0x00417384:	pushl 0x460800
0x0041738a:	pushl 0x46a6e4
0x00417390:	call 0x00416df4
0x00416e16:	pushl %eax
0x00416e17:	pushl 0x460804
0x00416e1d:	call TlsGetValue@KERNEL32.dll
0x00416e1f:	call FlsGetValue@KERNEL32.DLL
FlsGetValue@KERNEL32.DLL: API Node	
0x00416e21:	testl %eax, %eax
0x00416e23:	je 0x00416e2d
0x00417395:	popl %ecx
0x00417396:	call FlsSetValue@KERNEL32.DLL
FlsSetValue@KERNEL32.DLL: API Node	
0x00417398:	testl %eax, %eax
0x0041739a:	je 27
0x0041739c:	pushl $0x0<UINT8>
0x0041739e:	pushl %esi
0x0041739f:	call 0x00416f1d
0x00416f1d:	pushl $0xc<UINT8>
0x00416f1f:	pushl $0x45b9c8<UINT32>
0x00416f24:	call 0x0041935c
0x00416f29:	movl %esi, $0x450784<UINT32>
0x00416f2e:	pushl %esi
0x00416f2f:	call GetModuleHandleW@KERNEL32.dll
0x00416f35:	testl %eax, %eax
0x00416f37:	jne 0x00416f40
0x00416f40:	movl -28(%ebp), %eax
0x00416f43:	movl %esi, 0x8(%ebp)
0x00416f46:	movl 0x5c(%esi), $0x450dc8<UINT32>
0x00416f4d:	xorl %edi, %edi
0x00416f4f:	incl %edi
0x00416f50:	movl 0x14(%esi), %edi
0x00416f53:	testl %eax, %eax
0x00416f55:	je 36
0x00416f57:	pushl $0x450774<UINT32>
0x00416f5c:	pushl %eax
0x00416f5d:	movl %ebx, 0x450270
0x00416f63:	call GetProcAddress@KERNEL32.dll
0x00416f65:	movl 0x1f8(%esi), %eax
0x00416f6b:	pushl $0x4507a0<UINT32>
0x00416f70:	pushl -28(%ebp)
0x00416f73:	call GetProcAddress@KERNEL32.dll
0x00416f75:	movl 0x1fc(%esi), %eax
0x00416f7b:	movl 0x70(%esi), %edi
0x00416f7e:	movb 0xc8(%esi), $0x43<UINT8>
0x00416f85:	movb 0x14b(%esi), $0x43<UINT8>
0x00416f8c:	movl 0x68(%esi), $0x4601e8<UINT32>
0x00416f93:	pushl $0xd<UINT8>
0x00416f95:	call 0x00418865
0x00418865:	movl %edi, %edi
0x00418867:	pushl %ebp
0x00418868:	movl %ebp, %esp
0x0041886a:	movl %eax, 0x8(%ebp)
0x0041886d:	pushl %esi
0x0041886e:	leal %esi, 0x460810(,%eax,8)
0x00418875:	cmpl (%esi), $0x0<UINT8>
0x00418878:	jne 0x0041888d
0x0041888d:	pushl (%esi)
0x0041888f:	call EnterCriticalSection@KERNEL32.dll
EnterCriticalSection@KERNEL32.dll: API Node	
0x00418895:	popl %esi
0x00418896:	popl %ebp
0x00418897:	ret

0x00416f9a:	popl %ecx
0x00416f9b:	andl -4(%ebp), $0x0<UINT8>
0x00416f9f:	pushl 0x68(%esi)
0x00416fa2:	call InterlockedIncrement@KERNEL32.dll
InterlockedIncrement@KERNEL32.dll: API Node	
0x00416fa8:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00416faf:	call 0x00416ff2
0x00416ff2:	pushl $0xd<UINT8>
0x00416ff4:	call 0x0041878b
0x0041878b:	movl %edi, %edi
0x0041878d:	pushl %ebp
0x0041878e:	movl %ebp, %esp
0x00418790:	movl %eax, 0x8(%ebp)
0x00418793:	pushl 0x460810(,%eax,8)
0x0041879a:	call LeaveCriticalSection@KERNEL32.dll
LeaveCriticalSection@KERNEL32.dll: API Node	
0x004187a0:	popl %ebp
0x004187a1:	ret

0x00416ff9:	popl %ecx
0x00416ffa:	ret

0x00416fb4:	pushl $0xc<UINT8>
0x00416fb6:	call 0x00418865
0x00416fbb:	popl %ecx
0x00416fbc:	movl -4(%ebp), %edi
0x00416fbf:	movl %eax, 0xc(%ebp)
0x00416fc2:	movl 0x6c(%esi), %eax
0x00416fc5:	testl %eax, %eax
0x00416fc7:	jne 8
0x00416fc9:	movl %eax, 0x4607f0
0x00416fce:	movl 0x6c(%esi), %eax
0x00416fd1:	pushl 0x6c(%esi)
0x00416fd4:	call 0x00416b9d
0x00416b9d:	movl %edi, %edi
0x00416b9f:	pushl %ebp
0x00416ba0:	movl %ebp, %esp
0x00416ba2:	pushl %ebx
0x00416ba3:	pushl %esi
0x00416ba4:	movl %esi, 0x4502a8
0x00416baa:	pushl %edi
0x00416bab:	movl %edi, 0x8(%ebp)
0x00416bae:	pushl %edi
0x00416baf:	call InterlockedIncrement@KERNEL32.dll
0x00416bb1:	movl %eax, 0xb0(%edi)
0x00416bb7:	testl %eax, %eax
0x00416bb9:	je 0x00416bbe
0x00416bbe:	movl %eax, 0xb8(%edi)
0x00416bc4:	testl %eax, %eax
0x00416bc6:	je 0x00416bcb
0x00416bcb:	movl %eax, 0xb4(%edi)
0x00416bd1:	testl %eax, %eax
0x00416bd3:	je 0x00416bd8
0x00416bd8:	movl %eax, 0xc0(%edi)
0x00416bde:	testl %eax, %eax
0x00416be0:	je 0x00416be5
0x00416be5:	leal %ebx, 0x50(%edi)
0x00416be8:	movl 0x8(%ebp), $0x6<UINT32>
0x00416bef:	cmpl -8(%ebx), $0x460710<UINT32>
0x00416bf6:	je 0x00416c01
0x00416bf8:	movl %eax, (%ebx)
0x00416bfa:	testl %eax, %eax
0x00416bfc:	je 0x00416c01
0x00416c01:	cmpl -4(%ebx), $0x0<UINT8>
0x00416c05:	je 0x00416c11
0x00416c11:	addl %ebx, $0x10<UINT8>
0x00416c14:	decl 0x8(%ebp)
0x00416c17:	jne 0x00416bef
0x00416c19:	movl %eax, 0xd4(%edi)
0x00416c1f:	addl %eax, $0xb4<UINT32>
0x00416c24:	pushl %eax
0x00416c25:	call InterlockedIncrement@KERNEL32.dll
0x00416c27:	popl %edi
0x00416c28:	popl %esi
0x00416c29:	popl %ebx
0x00416c2a:	popl %ebp
0x00416c2b:	ret

0x00416fd9:	popl %ecx
0x00416fda:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00416fe1:	call 0x00416ffb
0x00416ffb:	pushl $0xc<UINT8>
0x00416ffd:	call 0x0041878b
0x00417002:	popl %ecx
0x00417003:	ret

0x00416fe6:	call 0x004193a1
0x00416feb:	ret

0x004173a4:	popl %ecx
0x004173a5:	popl %ecx
0x004173a6:	call GetCurrentThreadId@KERNEL32.dll
0x004173ac:	orl 0x4(%esi), $0xffffffff<UINT8>
0x004173b0:	movl (%esi), %eax
0x004173b2:	xorl %eax, %eax
0x004173b4:	incl %eax
0x004173b5:	jmp 0x004173be
0x004173be:	popl %edi
0x004173bf:	popl %esi
0x004173c0:	ret

0x004148f3:	testl %eax, %eax
0x004148f5:	jne 0x004148ff
0x004148ff:	call 0x0041c15f
0x0041c15f:	movl %edi, %edi
0x0041c161:	pushl %esi
0x0041c162:	movl %eax, $0x45b6e8<UINT32>
0x0041c167:	movl %esi, $0x45b6ec<UINT32>
0x0041c16c:	pushl %edi
0x0041c16d:	movl %edi, %eax
0x0041c16f:	cmpl %eax, %esi
0x0041c171:	jae 15
0x0041c173:	movl %eax, (%edi)
0x0041c175:	testl %eax, %eax
0x0041c177:	je 2
0x0041c179:	call 0x00414cbc
0x00414cbc:	xorl %eax, %eax
0x00414cbe:	cmpb 0x46a368, %al
0x00414cc4:	jne 27
0x00414cc6:	pushl %eax
0x00414cc7:	pushl $0x1<UINT8>
0x00414cc9:	pushl %eax
0x00414cca:	pushl %eax
0x00414ccb:	pushl %eax
0x00414ccc:	movb 0x46a368, $0x1<UINT8>
0x00414cd3:	call 0x0041c7f3
0x0041c7f3:	xorl %eax, %eax
0x0041c7f5:	ret

0x00414cd8:	pushl %eax
0x00414cd9:	call 0x0041c7cb
0x0041c7cb:	movl %edi, %edi
0x0041c7cd:	pushl %ebp
0x0041c7ce:	movl %ebp, %esp
0x0041c7d0:	movl %ecx, 0x8(%ebp)
0x0041c7d3:	movl %eax, 0x46accc
0x0041c7d8:	andl 0x46acc8, $0x0<UINT8>
0x0041c7df:	movl 0x46accc, %ecx
0x0041c7e5:	popl %ebp
0x0041c7e6:	ret

0x00414cde:	addl %esp, $0x18<UINT8>
0x00414ce1:	ret

0x0041c17b:	addl %edi, $0x4<UINT8>
0x0041c17e:	cmpl %edi, %esi
0x0041c180:	jb -15
0x0041c182:	popl %edi
0x0041c183:	popl %esi
0x0041c184:	ret

0x00414904:	movl -4(%ebp), %ebx
0x00414907:	call 0x0041a3dd
0x0041a3dd:	pushl $0x54<UINT8>
0x0041a3df:	pushl $0x45bad8<UINT32>
0x0041a3e4:	call 0x0041935c
0x0041a3e9:	xorl %edi, %edi
0x0041a3eb:	movl -4(%ebp), %edi
0x0041a3ee:	leal %eax, -100(%ebp)
0x0041a3f1:	pushl %eax
0x0041a3f2:	call GetStartupInfoA@KERNEL32.dll
0x0041a3f8:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0041a3ff:	pushl $0x40<UINT8>
0x0041a401:	pushl $0x20<UINT8>
0x0041a403:	popl %esi
0x0041a404:	pushl %esi
0x0041a405:	call 0x00419c92
0x0041a40a:	popl %ecx
0x0041a40b:	popl %ecx
0x0041a40c:	cmpl %eax, %edi
0x0041a40e:	je 532
0x0041a414:	movl 0x46b460, %eax
0x0041a419:	movl 0x46b458, %esi
0x0041a41f:	leal %ecx, 0x800(%eax)
0x0041a425:	jmp 0x0041a457
0x0041a457:	cmpl %eax, %ecx
0x0041a459:	jb 0x0041a427
0x0041a427:	movb 0x4(%eax), $0x0<UINT8>
0x0041a42b:	orl (%eax), $0xffffffff<UINT8>
0x0041a42e:	movb 0x5(%eax), $0xa<UINT8>
0x0041a432:	movl 0x8(%eax), %edi
0x0041a435:	movb 0x24(%eax), $0x0<UINT8>
0x0041a439:	movb 0x25(%eax), $0xa<UINT8>
0x0041a43d:	movb 0x26(%eax), $0xa<UINT8>
0x0041a441:	movl 0x38(%eax), %edi
0x0041a444:	movb 0x34(%eax), $0x0<UINT8>
0x0041a448:	addl %eax, $0x40<UINT8>
0x0041a44b:	movl %ecx, 0x46b460
0x0041a451:	addl %ecx, $0x800<UINT32>
0x0041a45b:	cmpw -50(%ebp), %di
0x0041a45f:	je 266
0x0041a465:	movl %eax, -48(%ebp)
0x0041a468:	cmpl %eax, %edi
0x0041a46a:	je 255
0x0041a470:	movl %edi, (%eax)
0x0041a472:	leal %ebx, 0x4(%eax)
0x0041a475:	leal %eax, (%ebx,%edi)
0x0041a478:	movl -28(%ebp), %eax
0x0041a47b:	movl %esi, $0x800<UINT32>
0x0041a480:	cmpl %edi, %esi
0x0041a482:	jl 0x0041a486
0x0041a486:	movl -32(%ebp), $0x1<UINT32>
0x0041a48d:	jmp 0x0041a4ea
0x0041a4ea:	cmpl 0x46b458, %edi
0x0041a4f0:	jl -99
0x0041a4f2:	jmp 0x0041a4fa
0x0041a4fa:	andl -32(%ebp), $0x0<UINT8>
0x0041a4fe:	testl %edi, %edi
0x0041a500:	jle 0x0041a56f
0x0041a56f:	xorl %ebx, %ebx
0x0041a571:	movl %esi, %ebx
0x0041a573:	shll %esi, $0x6<UINT8>
0x0041a576:	addl %esi, 0x46b460
0x0041a57c:	movl %eax, (%esi)
0x0041a57e:	cmpl %eax, $0xffffffff<UINT8>
0x0041a581:	je 0x0041a58e
0x0041a58e:	movb 0x4(%esi), $0xffffff81<UINT8>
0x0041a592:	testl %ebx, %ebx
0x0041a594:	jne 0x0041a59b
0x0041a596:	pushl $0xfffffff6<UINT8>
0x0041a598:	popl %eax
0x0041a599:	jmp 0x0041a5a5
0x0041a5a5:	pushl %eax
0x0041a5a6:	call GetStdHandle@KERNEL32.dll
GetStdHandle@KERNEL32.dll: API Node	
0x0041a5ac:	movl %edi, %eax
0x0041a5ae:	cmpl %edi, $0xffffffff<UINT8>
0x0041a5b1:	je 67
0x0041a5b3:	testl %edi, %edi
0x0041a5b5:	je 63
0x0041a5b7:	pushl %edi
0x0041a5b8:	call GetFileType@KERNEL32.dll
GetFileType@KERNEL32.dll: API Node	
0x0041a5be:	testl %eax, %eax
0x0041a5c0:	je 52
0x0041a5c2:	movl (%esi), %edi
0x0041a5c4:	andl %eax, $0xff<UINT32>
0x0041a5c9:	cmpl %eax, $0x2<UINT8>
0x0041a5cc:	jne 6
0x0041a5ce:	orb 0x4(%esi), $0x40<UINT8>
0x0041a5d2:	jmp 0x0041a5dd
0x0041a5dd:	pushl $0xfa0<UINT32>
0x0041a5e2:	leal %eax, 0xc(%esi)
0x0041a5e5:	pushl %eax
0x0041a5e6:	call 0x00420003
0x0041a5eb:	popl %ecx
0x0041a5ec:	popl %ecx
0x0041a5ed:	testl %eax, %eax
0x0041a5ef:	je 55
0x0041a5f1:	incl 0x8(%esi)
0x0041a5f4:	jmp 0x0041a600
0x0041a600:	incl %ebx
0x0041a601:	cmpl %ebx, $0x3<UINT8>
0x0041a604:	jl 0x0041a571
0x0041a59b:	movl %eax, %ebx
0x0041a59d:	decl %eax
0x0041a59e:	negl %eax
0x0041a5a0:	sbbl %eax, %eax
0x0041a5a2:	addl %eax, $0xfffffff5<UINT8>
0x0041a60a:	pushl 0x46b458
0x0041a610:	call SetHandleCount@KERNEL32.dll
SetHandleCount@KERNEL32.dll: API Node	
0x0041a616:	xorl %eax, %eax
0x0041a618:	jmp 0x0041a62b
0x0041a62b:	call 0x004193a1
0x0041a630:	ret

0x0041490c:	testl %eax, %eax
0x0041490e:	jnl 0x00414918
0x00414918:	call GetCommandLineA@KERNEL32.dll
GetCommandLineA@KERNEL32.dll: API Node	
0x0041491e:	movl 0x46c5bc, %eax
0x00414923:	call 0x0041c028
0x0041c028:	movl %edi, %edi
0x0041c02a:	pushl %ebp
0x0041c02b:	movl %ebp, %esp
0x0041c02d:	movl %eax, 0x46acc0
0x0041c032:	subl %esp, $0xc<UINT8>
0x0041c035:	pushl %ebx
0x0041c036:	pushl %esi
0x0041c037:	movl %esi, 0x450134
0x0041c03d:	pushl %edi
0x0041c03e:	xorl %ebx, %ebx
0x0041c040:	xorl %edi, %edi
0x0041c042:	cmpl %eax, %ebx
0x0041c044:	jne 46
0x0041c046:	call GetEnvironmentStringsW@KERNEL32.dll
GetEnvironmentStringsW@KERNEL32.dll: API Node	
0x0041c048:	movl %edi, %eax
0x0041c04a:	cmpl %edi, %ebx
0x0041c04c:	je 12
0x0041c04e:	movl 0x46acc0, $0x1<UINT32>
0x0041c058:	jmp 0x0041c07d
0x0041c07d:	cmpl %edi, %ebx
0x0041c07f:	jne 0x0041c090
0x0041c090:	movl %eax, %edi
0x0041c092:	cmpw (%edi), %bx
0x0041c095:	je 14
0x0041c097:	incl %eax
0x0041c098:	incl %eax
0x0041c099:	cmpw (%eax), %bx
0x0041c09c:	jne 0x0041c097
0x0041c09e:	incl %eax
0x0041c09f:	incl %eax
0x0041c0a0:	cmpw (%eax), %bx
0x0041c0a3:	jne 0x0041c097
0x0041c0a5:	movl %esi, 0x4501dc
0x0041c0ab:	pushl %ebx
0x0041c0ac:	pushl %ebx
0x0041c0ad:	pushl %ebx
0x0041c0ae:	subl %eax, %edi
0x0041c0b0:	pushl %ebx
0x0041c0b1:	sarl %eax
0x0041c0b3:	incl %eax
0x0041c0b4:	pushl %eax
0x0041c0b5:	pushl %edi
0x0041c0b6:	pushl %ebx
0x0041c0b7:	pushl %ebx
0x0041c0b8:	movl -12(%ebp), %eax
0x0041c0bb:	call WideCharToMultiByte@KERNEL32.dll
WideCharToMultiByte@KERNEL32.dll: API Node	
0x0041c0bd:	movl -8(%ebp), %eax
0x0041c0c0:	cmpl %eax, %ebx
0x0041c0c2:	je 47
0x0041c0c4:	pushl %eax
0x0041c0c5:	call 0x00419c4d
0x00419c4d:	movl %edi, %edi
0x00419c4f:	pushl %ebp
0x00419c50:	movl %ebp, %esp
0x00419c52:	pushl %esi
0x00419c53:	pushl %edi
0x00419c54:	xorl %esi, %esi
0x00419c56:	pushl 0x8(%ebp)
0x00419c59:	call 0x00410ff2
0x00410ff2:	movl %edi, %edi
0x00410ff4:	pushl %ebp
0x00410ff5:	movl %ebp, %esp
0x00410ff7:	pushl %esi
0x00410ff8:	movl %esi, 0x8(%ebp)
0x00410ffb:	cmpl %esi, $0xffffffe0<UINT8>
0x00410ffe:	ja 161
0x00411004:	pushl %ebx
0x00411005:	pushl %edi
0x00411006:	movl %edi, 0x4501bc
0x0041100c:	cmpl 0x46a6ec, $0x0<UINT8>
0x00411013:	jne 0x0041102d
0x0041102d:	movl %eax, 0x46c5b4
0x00411032:	cmpl %eax, $0x1<UINT8>
0x00411035:	jne 14
0x00411037:	testl %esi, %esi
0x00411039:	je 4
0x0041103b:	movl %eax, %esi
0x0041103d:	jmp 0x00411042
0x00411042:	pushl %eax
0x00411043:	jmp 0x00411061
0x00411061:	pushl $0x0<UINT8>
0x00411063:	pushl 0x46a6ec
0x00411069:	call HeapAlloc@KERNEL32.dll
0x0041106b:	movl %ebx, %eax
0x0041106d:	testl %ebx, %ebx
0x0041106f:	jne 0x0041109f
0x0041109f:	popl %edi
0x004110a0:	movl %eax, %ebx
0x004110a2:	popl %ebx
0x004110a3:	jmp 0x004110b9
0x004110b9:	popl %esi
0x004110ba:	popl %ebp
0x004110bb:	ret

0x00419c5e:	movl %edi, %eax
0x00419c60:	popl %ecx
0x00419c61:	testl %edi, %edi
0x00419c63:	jne 0x00419c8c
0x00419c8c:	movl %eax, %edi
0x00419c8e:	popl %edi
0x00419c8f:	popl %esi
0x00419c90:	popl %ebp
0x00419c91:	ret

0x0041c0ca:	popl %ecx
0x0041c0cb:	movl -4(%ebp), %eax
0x0041c0ce:	cmpl %eax, %ebx
0x0041c0d0:	je 33
0x0041c0d2:	pushl %ebx
0x0041c0d3:	pushl %ebx
0x0041c0d4:	pushl -8(%ebp)
0x0041c0d7:	pushl %eax
0x0041c0d8:	pushl -12(%ebp)
0x0041c0db:	pushl %edi
0x0041c0dc:	pushl %ebx
0x0041c0dd:	pushl %ebx
0x0041c0de:	call WideCharToMultiByte@KERNEL32.dll
0x0041c0e0:	testl %eax, %eax
0x0041c0e2:	jne 0x0041c0f0
0x0041c0f0:	movl %ebx, -4(%ebp)
0x0041c0f3:	pushl %edi
0x0041c0f4:	call FreeEnvironmentStringsW@KERNEL32.dll
FreeEnvironmentStringsW@KERNEL32.dll: API Node	
0x0041c0fa:	movl %eax, %ebx
0x0041c0fc:	jmp 0x0041c15a
0x0041c15a:	popl %edi
0x0041c15b:	popl %esi
0x0041c15c:	popl %ebx
0x0041c15d:	leave
0x0041c15e:	ret

0x00414928:	movl 0x46a35c, %eax
0x0041492d:	call 0x0041bf6d
0x0041bf6d:	movl %edi, %edi
0x0041bf6f:	pushl %ebp
0x0041bf70:	movl %ebp, %esp
0x0041bf72:	subl %esp, $0xc<UINT8>
0x0041bf75:	pushl %ebx
0x0041bf76:	xorl %ebx, %ebx
0x0041bf78:	pushl %esi
0x0041bf79:	pushl %edi
0x0041bf7a:	cmpl 0x46c594, %ebx
0x0041bf80:	jne 5
0x0041bf82:	call 0x00416a36
0x00416a36:	cmpl 0x46c594, $0x0<UINT8>
0x00416a3d:	jne 0x00416a51
0x00416a3f:	pushl $0xfffffffd<UINT8>
0x00416a41:	call 0x0041689c
0x0041689c:	pushl $0x14<UINT8>
0x0041689e:	pushl $0x45b988<UINT32>
0x004168a3:	call 0x0041935c
0x004168a8:	orl -32(%ebp), $0xffffffff<UINT8>
0x004168ac:	call 0x0041707d
0x0041707d:	movl %edi, %edi
0x0041707f:	pushl %esi
0x00417080:	call 0x00417004
0x00417004:	movl %edi, %edi
0x00417006:	pushl %esi
0x00417007:	pushl %edi
0x00417008:	call GetLastError@KERNEL32.dll
GetLastError@KERNEL32.dll: API Node	
0x0041700e:	pushl 0x460800
0x00417014:	movl %edi, %eax
0x00417016:	call 0x00416e8f
0x00416e8f:	movl %edi, %edi
0x00416e91:	pushl %esi
0x00416e92:	pushl 0x460804
0x00416e98:	call TlsGetValue@KERNEL32.dll
0x00416e9e:	movl %esi, %eax
0x00416ea0:	testl %esi, %esi
0x00416ea2:	jne 0x00416ebf
0x00416ebf:	movl %eax, %esi
0x00416ec1:	popl %esi
0x00416ec2:	ret

0x0041701b:	call FlsGetValue@KERNEL32.DLL
0x0041701d:	movl %esi, %eax
0x0041701f:	testl %esi, %esi
0x00417021:	jne 0x00417071
0x00417071:	pushl %edi
0x00417072:	call SetLastError@KERNEL32.dll
SetLastError@KERNEL32.dll: API Node	
0x00417078:	popl %edi
0x00417079:	movl %eax, %esi
0x0041707b:	popl %esi
0x0041707c:	ret

0x00417085:	movl %esi, %eax
0x00417087:	testl %esi, %esi
0x00417089:	jne 0x00417093
0x00417093:	movl %eax, %esi
0x00417095:	popl %esi
0x00417096:	ret

0x004168b1:	movl %edi, %eax
0x004168b3:	movl -36(%ebp), %edi
0x004168b6:	call 0x00416597
0x00416597:	pushl $0xc<UINT8>
0x00416599:	pushl $0x45b968<UINT32>
0x0041659e:	call 0x0041935c
0x004165a3:	call 0x0041707d
0x004165a8:	movl %edi, %eax
0x004165aa:	movl %eax, 0x46070c
0x004165af:	testl 0x70(%edi), %eax
0x004165b2:	je 0x004165d1
0x004165d1:	pushl $0xd<UINT8>
0x004165d3:	call 0x00418865
0x004165d8:	popl %ecx
0x004165d9:	andl -4(%ebp), $0x0<UINT8>
0x004165dd:	movl %esi, 0x68(%edi)
0x004165e0:	movl -28(%ebp), %esi
0x004165e3:	cmpl %esi, 0x460610
0x004165e9:	je 0x00416621
0x00416621:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00416628:	call 0x00416632
0x00416632:	pushl $0xd<UINT8>
0x00416634:	call 0x0041878b
0x00416639:	popl %ecx
0x0041663a:	ret

0x0041662d:	jmp 0x004165bd
0x004165bd:	testl %esi, %esi
0x004165bf:	jne 0x004165c9
0x004165c9:	movl %eax, %esi
0x004165cb:	call 0x004193a1
0x004165d0:	ret

0x004168bb:	movl %ebx, 0x68(%edi)
0x004168be:	movl %esi, 0x8(%ebp)
0x004168c1:	call 0x0041663b
0x0041663b:	movl %edi, %edi
0x0041663d:	pushl %ebp
0x0041663e:	movl %ebp, %esp
0x00416640:	subl %esp, $0x10<UINT8>
0x00416643:	pushl %ebx
0x00416644:	xorl %ebx, %ebx
0x00416646:	pushl %ebx
0x00416647:	leal %ecx, -16(%ebp)
0x0041664a:	call 0x004105ee
0x004105ee:	movl %edi, %edi
0x004105f0:	pushl %ebp
0x004105f1:	movl %ebp, %esp
0x004105f3:	movl %eax, 0x8(%ebp)
0x004105f6:	pushl %esi
0x004105f7:	movl %esi, %ecx
0x004105f9:	movb 0xc(%esi), $0x0<UINT8>
0x004105fd:	testl %eax, %eax
0x004105ff:	jne 99
0x00410601:	call 0x0041707d
0x00410606:	movl 0x8(%esi), %eax
0x00410609:	movl %ecx, 0x6c(%eax)
0x0041060c:	movl (%esi), %ecx
0x0041060e:	movl %ecx, 0x68(%eax)
0x00410611:	movl 0x4(%esi), %ecx
0x00410614:	movl %ecx, (%esi)
0x00410616:	cmpl %ecx, 0x4607f0
0x0041061c:	je 0x00410630
0x00410630:	movl %eax, 0x4(%esi)
0x00410633:	cmpl %eax, 0x460610
0x00410639:	je 0x00410651
0x00410651:	movl %eax, 0x8(%esi)
0x00410654:	testb 0x70(%eax), $0x2<UINT8>
0x00410658:	jne 20
0x0041065a:	orl 0x70(%eax), $0x2<UINT8>
0x0041065e:	movb 0xc(%esi), $0x1<UINT8>
0x00410662:	jmp 0x0041066e
0x0041066e:	movl %eax, %esi
0x00410670:	popl %esi
0x00410671:	popl %ebp
0x00410672:	ret $0x4<UINT16>

0x0041664f:	movl 0x46a69c, %ebx
0x00416655:	cmpl %esi, $0xfffffffe<UINT8>
0x00416658:	jne 0x00416678
0x00416678:	cmpl %esi, $0xfffffffd<UINT8>
0x0041667b:	jne 0x0041668f
0x0041667d:	movl 0x46a69c, $0x1<UINT32>
0x00416687:	call GetACP@KERNEL32.dll
GetACP@KERNEL32.dll: API Node	
0x0041668d:	jmp 0x0041666a
0x0041666a:	cmpb -4(%ebp), %bl
0x0041666d:	je 69
0x0041666f:	movl %ecx, -8(%ebp)
0x00416672:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00416676:	jmp 0x004166b4
0x004166b4:	popl %ebx
0x004166b5:	leave
0x004166b6:	ret

0x004168c6:	movl 0x8(%ebp), %eax
0x004168c9:	cmpl %eax, 0x4(%ebx)
0x004168cc:	je 343
0x004168d2:	pushl $0x220<UINT32>
0x004168d7:	call 0x00419c4d
0x004168dc:	popl %ecx
0x004168dd:	movl %ebx, %eax
0x004168df:	testl %ebx, %ebx
0x004168e1:	je 326
0x004168e7:	movl %ecx, $0x88<UINT32>
0x004168ec:	movl %esi, 0x68(%edi)
0x004168ef:	movl %edi, %ebx
0x004168f1:	rep movsl %es:(%edi), %ds:(%esi)
0x004168f3:	andl (%ebx), $0x0<UINT8>
0x004168f6:	pushl %ebx
0x004168f7:	pushl 0x8(%ebp)
0x004168fa:	call 0x004166b7
0x004166b7:	movl %edi, %edi
0x004166b9:	pushl %ebp
0x004166ba:	movl %ebp, %esp
0x004166bc:	subl %esp, $0x20<UINT8>
0x004166bf:	movl %eax, 0x460064
0x004166c4:	xorl %eax, %ebp
0x004166c6:	movl -4(%ebp), %eax
0x004166c9:	pushl %ebx
0x004166ca:	movl %ebx, 0xc(%ebp)
0x004166cd:	pushl %esi
0x004166ce:	movl %esi, 0x8(%ebp)
0x004166d1:	pushl %edi
0x004166d2:	call 0x0041663b
0x0041668f:	cmpl %esi, $0xfffffffc<UINT8>
0x00416692:	jne 0x004166a6
0x004166a6:	cmpb -4(%ebp), %bl
0x004166a9:	je 7
0x004166ab:	movl %eax, -8(%ebp)
0x004166ae:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x004166b2:	movl %eax, %esi
0x004166d7:	movl %edi, %eax
0x004166d9:	xorl %esi, %esi
0x004166db:	movl 0x8(%ebp), %edi
0x004166de:	cmpl %edi, %esi
0x004166e0:	jne 0x004166f0
0x004166f0:	movl -28(%ebp), %esi
0x004166f3:	xorl %eax, %eax
0x004166f5:	cmpl 0x460618(%eax), %edi
0x004166fb:	je 145
0x00416701:	incl -28(%ebp)
0x00416704:	addl %eax, $0x30<UINT8>
0x00416707:	cmpl %eax, $0xf0<UINT32>
0x0041670c:	jb 0x004166f5
0x0041670e:	cmpl %edi, $0xfde8<UINT32>
0x00416714:	je 368
0x0041671a:	cmpl %edi, $0xfde9<UINT32>
0x00416720:	je 356
0x00416726:	movzwl %eax, %di
0x00416729:	pushl %eax
0x0041672a:	call IsValidCodePage@KERNEL32.dll
IsValidCodePage@KERNEL32.dll: API Node	
0x00416730:	testl %eax, %eax
0x00416732:	je 338
0x00416738:	leal %eax, -24(%ebp)
0x0041673b:	pushl %eax
0x0041673c:	pushl %edi
0x0041673d:	call GetCPInfo@KERNEL32.dll
GetCPInfo@KERNEL32.dll: API Node	
0x00416743:	testl %eax, %eax
0x00416745:	je 307
0x0041674b:	pushl $0x101<UINT32>
0x00416750:	leal %eax, 0x1c(%ebx)
0x00416753:	pushl %esi
0x00416754:	pushl %eax
0x00416755:	call 0x00411760
0x00411760:	movl %edx, 0xc(%esp)
0x00411764:	movl %ecx, 0x4(%esp)
0x00411768:	testl %edx, %edx
0x0041176a:	je 105
0x0041176c:	xorl %eax, %eax
0x0041176e:	movb %al, 0x8(%esp)
0x00411772:	testb %al, %al
0x00411774:	jne 22
0x00411776:	cmpl %edx, $0x100<UINT32>
0x0041177c:	jb 0x0041178c
0x0041177e:	cmpl 0x46c5b8, $0x0<UINT8>
0x00411785:	je 0x0041178c
0x0041178c:	pushl %edi
0x0041178d:	movl %edi, %ecx
0x0041178f:	cmpl %edx, $0x4<UINT8>
0x00411792:	jb 49
0x00411794:	negl %ecx
0x00411796:	andl %ecx, $0x3<UINT8>
0x00411799:	je 0x004117a7
0x004117a7:	movl %ecx, %eax
0x004117a9:	shll %eax, $0x8<UINT8>
0x004117ac:	addl %eax, %ecx
0x004117ae:	movl %ecx, %eax
0x004117b0:	shll %eax, $0x10<UINT8>
0x004117b3:	addl %eax, %ecx
0x004117b5:	movl %ecx, %edx
0x004117b7:	andl %edx, $0x3<UINT8>
0x004117ba:	shrl %ecx, $0x2<UINT8>
0x004117bd:	je 6
0x004117bf:	rep stosl %es:(%edi), %eax
0x004117c1:	testl %edx, %edx
0x004117c3:	je 0x004117cf
0x004117c5:	movb (%edi), %al
0x004117c7:	addl %edi, $0x1<UINT8>
0x004117ca:	subl %edx, $0x1<UINT8>
0x004117cd:	jne -10
0x004117cf:	movl %eax, 0x8(%esp)
0x004117d3:	popl %edi
0x004117d4:	ret

0x0041675a:	xorl %edx, %edx
0x0041675c:	incl %edx
0x0041675d:	addl %esp, $0xc<UINT8>
0x00416760:	movl 0x4(%ebx), %edi
0x00416763:	movl 0xc(%ebx), %esi
0x00416766:	cmpl -24(%ebp), %edx
0x00416769:	jbe 248
0x0041676f:	cmpb -18(%ebp), $0x0<UINT8>
0x00416773:	je 0x00416848
0x00416848:	leal %eax, 0x1e(%ebx)
0x0041684b:	movl %ecx, $0xfe<UINT32>
0x00416850:	orb (%eax), $0x8<UINT8>
0x00416853:	incl %eax
0x00416854:	decl %ecx
0x00416855:	jne 0x00416850
0x00416857:	movl %eax, 0x4(%ebx)
0x0041685a:	call 0x00416371
0x00416371:	subl %eax, $0x3a4<UINT32>
0x00416376:	je 34
0x00416378:	subl %eax, $0x4<UINT8>
0x0041637b:	je 23
0x0041637d:	subl %eax, $0xd<UINT8>
0x00416380:	je 12
0x00416382:	decl %eax
0x00416383:	je 3
0x00416385:	xorl %eax, %eax
0x00416387:	ret

0x0041685f:	movl 0xc(%ebx), %eax
0x00416862:	movl 0x8(%ebx), %edx
0x00416865:	jmp 0x0041686a
0x0041686a:	xorl %eax, %eax
0x0041686c:	movzwl %ecx, %ax
0x0041686f:	movl %eax, %ecx
0x00416871:	shll %ecx, $0x10<UINT8>
0x00416874:	orl %eax, %ecx
0x00416876:	leal %edi, 0x10(%ebx)
0x00416879:	stosl %es:(%edi), %eax
0x0041687a:	stosl %es:(%edi), %eax
0x0041687b:	stosl %es:(%edi), %eax
0x0041687c:	jmp 0x00416826
0x00416826:	movl %esi, %ebx
0x00416828:	call 0x00416404
0x00416404:	movl %edi, %edi
0x00416406:	pushl %ebp
0x00416407:	movl %ebp, %esp
0x00416409:	subl %esp, $0x51c<UINT32>
0x0041640f:	movl %eax, 0x460064
0x00416414:	xorl %eax, %ebp
0x00416416:	movl -4(%ebp), %eax
0x00416419:	pushl %ebx
0x0041641a:	pushl %edi
0x0041641b:	leal %eax, -1304(%ebp)
0x00416421:	pushl %eax
0x00416422:	pushl 0x4(%esi)
0x00416425:	call GetCPInfo@KERNEL32.dll
0x0041642b:	movl %edi, $0x100<UINT32>
0x00416430:	testl %eax, %eax
0x00416432:	je 251
0x00416438:	xorl %eax, %eax
0x0041643a:	movb -260(%ebp,%eax), %al
0x00416441:	incl %eax
0x00416442:	cmpl %eax, %edi
0x00416444:	jb 0x0041643a
0x00416446:	movb %al, -1298(%ebp)
0x0041644c:	movb -260(%ebp), $0x20<UINT8>
0x00416453:	testb %al, %al
0x00416455:	je 0x00416485
0x00416485:	pushl $0x0<UINT8>
0x00416487:	pushl 0xc(%esi)
0x0041648a:	leal %eax, -1284(%ebp)
0x00416490:	pushl 0x4(%esi)
0x00416493:	pushl %eax
0x00416494:	pushl %edi
0x00416495:	leal %eax, -260(%ebp)
0x0041649b:	pushl %eax
0x0041649c:	pushl $0x1<UINT8>
0x0041649e:	pushl $0x0<UINT8>
0x004164a0:	call 0x0041f3f9
0x0041f3f9:	movl %edi, %edi
0x0041f3fb:	pushl %ebp
0x0041f3fc:	movl %ebp, %esp
0x0041f3fe:	subl %esp, $0x10<UINT8>
0x0041f401:	pushl 0x8(%ebp)
0x0041f404:	leal %ecx, -16(%ebp)
0x0041f407:	call 0x004105ee
0x0041f40c:	pushl 0x24(%ebp)
0x0041f40f:	leal %ecx, -16(%ebp)
0x0041f412:	pushl 0x20(%ebp)
0x0041f415:	pushl 0x1c(%ebp)
0x0041f418:	pushl 0x18(%ebp)
0x0041f41b:	pushl 0x14(%ebp)
0x0041f41e:	pushl 0x10(%ebp)
0x0041f421:	pushl 0xc(%ebp)
0x0041f424:	call 0x0041f23f
0x0041f23f:	movl %edi, %edi
0x0041f241:	pushl %ebp
0x0041f242:	movl %ebp, %esp
0x0041f244:	pushl %ecx
0x0041f245:	pushl %ecx
0x0041f246:	movl %eax, 0x460064
0x0041f24b:	xorl %eax, %ebp
0x0041f24d:	movl -4(%ebp), %eax
0x0041f250:	movl %eax, 0x46acd8
0x0041f255:	pushl %ebx
0x0041f256:	pushl %esi
0x0041f257:	xorl %ebx, %ebx
0x0041f259:	pushl %edi
0x0041f25a:	movl %edi, %ecx
0x0041f25c:	cmpl %eax, %ebx
0x0041f25e:	jne 58
0x0041f260:	leal %eax, -8(%ebp)
0x0041f263:	pushl %eax
0x0041f264:	xorl %esi, %esi
0x0041f266:	incl %esi
0x0041f267:	pushl %esi
0x0041f268:	pushl $0x4515a4<UINT32>
0x0041f26d:	pushl %esi
0x0041f26e:	call GetStringTypeW@KERNEL32.dll
GetStringTypeW@KERNEL32.dll: API Node	
0x0041f274:	testl %eax, %eax
0x0041f276:	je 8
0x0041f278:	movl 0x46acd8, %esi
0x0041f27e:	jmp 0x0041f2b4
0x0041f2b4:	movl -8(%ebp), %ebx
0x0041f2b7:	cmpl 0x18(%ebp), %ebx
0x0041f2ba:	jne 0x0041f2c4
0x0041f2c4:	movl %esi, 0x450204
0x0041f2ca:	xorl %eax, %eax
0x0041f2cc:	cmpl 0x20(%ebp), %ebx
0x0041f2cf:	pushl %ebx
0x0041f2d0:	pushl %ebx
0x0041f2d1:	pushl 0x10(%ebp)
0x0041f2d4:	setne %al
0x0041f2d7:	pushl 0xc(%ebp)
0x0041f2da:	leal %eax, 0x1(,%eax,8)
0x0041f2e1:	pushl %eax
0x0041f2e2:	pushl 0x18(%ebp)
0x0041f2e5:	call MultiByteToWideChar@KERNEL32.dll
MultiByteToWideChar@KERNEL32.dll: API Node	
0x0041f2e7:	movl %edi, %eax
0x0041f2e9:	cmpl %edi, %ebx
0x0041f2eb:	je 171
0x0041f2f1:	jle 60
0x0041f2f3:	cmpl %edi, $0x7ffffff0<UINT32>
0x0041f2f9:	ja 52
0x0041f2fb:	leal %eax, 0x8(%edi,%edi)
0x0041f2ff:	cmpl %eax, $0x400<UINT32>
0x0041f304:	ja 19
0x0041f306:	call 0x00414c90
0x00414c90:	pushl %ecx
0x00414c91:	leal %ecx, 0x8(%esp)
0x00414c95:	subl %ecx, %eax
0x00414c97:	andl %ecx, $0xf<UINT8>
0x00414c9a:	addl %eax, %ecx
0x00414c9c:	sbbl %ecx, %ecx
0x00414c9e:	orl %eax, %ecx
0x00414ca0:	popl %ecx
0x00414ca1:	jmp 0x0041c7a0
0x0041c7a0:	pushl %ecx
0x0041c7a1:	leal %ecx, 0x4(%esp)
0x0041c7a5:	subl %ecx, %eax
0x0041c7a7:	sbbl %eax, %eax
0x0041c7a9:	notl %eax
0x0041c7ab:	andl %ecx, %eax
0x0041c7ad:	movl %eax, %esp
0x0041c7af:	andl %eax, $0xfffff000<UINT32>
0x0041c7b4:	cmpl %ecx, %eax
0x0041c7b6:	jb 10
0x0041c7b8:	movl %eax, %ecx
0x0041c7ba:	popl %ecx
0x0041c7bb:	xchgl %esp, %eax
0x0041c7bc:	movl %eax, (%eax)
0x0041c7be:	movl (%esp), %eax
0x0041c7c1:	ret

0x0041f30b:	movl %eax, %esp
0x0041f30d:	cmpl %eax, %ebx
0x0041f30f:	je 28
0x0041f311:	movl (%eax), $0xcccc<UINT32>
0x0041f317:	jmp 0x0041f32a
0x0041f32a:	addl %eax, $0x8<UINT8>
0x0041f32d:	movl %ebx, %eax
0x0041f32f:	testl %ebx, %ebx
0x0041f331:	je 105
0x0041f333:	leal %eax, (%edi,%edi)
0x0041f336:	pushl %eax
0x0041f337:	pushl $0x0<UINT8>
0x0041f339:	pushl %ebx
0x0041f33a:	call 0x00411760
0x0041f33f:	addl %esp, $0xc<UINT8>
0x0041f342:	pushl %edi
0x0041f343:	pushl %ebx
0x0041f344:	pushl 0x10(%ebp)
0x0041f347:	pushl 0xc(%ebp)
0x0041f34a:	pushl $0x1<UINT8>
0x0041f34c:	pushl 0x18(%ebp)
0x0041f34f:	call MultiByteToWideChar@KERNEL32.dll
0x0041f351:	testl %eax, %eax
0x0041f353:	je 17
0x0041f355:	pushl 0x14(%ebp)
0x0041f358:	pushl %eax
0x0041f359:	pushl %ebx
0x0041f35a:	pushl 0x8(%ebp)
0x0041f35d:	call GetStringTypeW@KERNEL32.dll
0x0041f363:	movl -8(%ebp), %eax
0x0041f366:	pushl %ebx
0x0041f367:	call 0x004119ed
0x004119ed:	movl %edi, %edi
0x004119ef:	pushl %ebp
0x004119f0:	movl %ebp, %esp
0x004119f2:	movl %eax, 0x8(%ebp)
0x004119f5:	testl %eax, %eax
0x004119f7:	je 18
0x004119f9:	subl %eax, $0x8<UINT8>
0x004119fc:	cmpl (%eax), $0xdddd<UINT32>
0x00411a02:	jne 0x00411a0b
0x00411a0b:	popl %ebp
0x00411a0c:	ret

0x0041f36c:	movl %eax, -8(%ebp)
0x0041f36f:	popl %ecx
0x0041f370:	jmp 0x0041f3e7
0x0041f3e7:	leal %esp, -20(%ebp)
0x0041f3ea:	popl %edi
0x0041f3eb:	popl %esi
0x0041f3ec:	popl %ebx
0x0041f3ed:	movl %ecx, -4(%ebp)
0x0041f3f0:	xorl %ecx, %ebp
0x0041f3f2:	call 0x00410135
0x00410135:	cmpl %ecx, 0x460064
0x0041013b:	jne 2
0x0041013d:	rep ret

0x0041f3f7:	leave
0x0041f3f8:	ret

0x0041f429:	addl %esp, $0x1c<UINT8>
0x0041f42c:	cmpb -4(%ebp), $0x0<UINT8>
0x0041f430:	je 7
0x0041f432:	movl %ecx, -8(%ebp)
0x0041f435:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0041f439:	leave
0x0041f43a:	ret

0x004164a5:	xorl %ebx, %ebx
0x004164a7:	pushl %ebx
0x004164a8:	pushl 0x4(%esi)
0x004164ab:	leal %eax, -516(%ebp)
0x004164b1:	pushl %edi
0x004164b2:	pushl %eax
0x004164b3:	pushl %edi
0x004164b4:	leal %eax, -260(%ebp)
0x004164ba:	pushl %eax
0x004164bb:	pushl %edi
0x004164bc:	pushl 0xc(%esi)
0x004164bf:	pushl %ebx
0x004164c0:	call 0x0041f1fa
0x0041f1fa:	movl %edi, %edi
0x0041f1fc:	pushl %ebp
0x0041f1fd:	movl %ebp, %esp
0x0041f1ff:	subl %esp, $0x10<UINT8>
0x0041f202:	pushl 0x8(%ebp)
0x0041f205:	leal %ecx, -16(%ebp)
0x0041f208:	call 0x004105ee
0x0041f20d:	pushl 0x28(%ebp)
0x0041f210:	leal %ecx, -16(%ebp)
0x0041f213:	pushl 0x24(%ebp)
0x0041f216:	pushl 0x20(%ebp)
0x0041f219:	pushl 0x1c(%ebp)
0x0041f21c:	pushl 0x18(%ebp)
0x0041f21f:	pushl 0x14(%ebp)
0x0041f222:	pushl 0x10(%ebp)
0x0041f225:	pushl 0xc(%ebp)
0x0041f228:	call 0x0041ee55
0x0041ee55:	movl %edi, %edi
0x0041ee57:	pushl %ebp
0x0041ee58:	movl %ebp, %esp
0x0041ee5a:	subl %esp, $0x14<UINT8>
0x0041ee5d:	movl %eax, 0x460064
0x0041ee62:	xorl %eax, %ebp
0x0041ee64:	movl -4(%ebp), %eax
0x0041ee67:	pushl %ebx
0x0041ee68:	pushl %esi
0x0041ee69:	xorl %ebx, %ebx
0x0041ee6b:	pushl %edi
0x0041ee6c:	movl %esi, %ecx
0x0041ee6e:	cmpl 0x46acd4, %ebx
0x0041ee74:	jne 0x0041eeae
0x0041ee76:	pushl %ebx
0x0041ee77:	pushl %ebx
0x0041ee78:	xorl %edi, %edi
0x0041ee7a:	incl %edi
0x0041ee7b:	pushl %edi
0x0041ee7c:	pushl $0x4515a4<UINT32>
0x0041ee81:	pushl $0x100<UINT32>
0x0041ee86:	pushl %ebx
0x0041ee87:	call LCMapStringW@KERNEL32.dll
LCMapStringW@KERNEL32.dll: API Node	
0x0041ee8d:	testl %eax, %eax
0x0041ee8f:	je 8
0x0041ee91:	movl 0x46acd4, %edi
0x0041ee97:	jmp 0x0041eeae
0x0041eeae:	cmpl 0x14(%ebp), %ebx
0x0041eeb1:	jle 0x0041eed5
0x0041eed5:	movl %eax, 0x46acd4
0x0041eeda:	cmpl %eax, $0x2<UINT8>
0x0041eedd:	je 428
0x0041eee3:	cmpl %eax, %ebx
0x0041eee5:	je 420
0x0041eeeb:	cmpl %eax, $0x1<UINT8>
0x0041eeee:	jne 460
0x0041eef4:	movl -8(%ebp), %ebx
0x0041eef7:	cmpl 0x20(%ebp), %ebx
0x0041eefa:	jne 0x0041ef04
0x0041ef04:	movl %esi, 0x450204
0x0041ef0a:	xorl %eax, %eax
0x0041ef0c:	cmpl 0x24(%ebp), %ebx
0x0041ef0f:	pushl %ebx
0x0041ef10:	pushl %ebx
0x0041ef11:	pushl 0x14(%ebp)
0x0041ef14:	setne %al
0x0041ef17:	pushl 0x10(%ebp)
0x0041ef1a:	leal %eax, 0x1(,%eax,8)
0x0041ef21:	pushl %eax
0x0041ef22:	pushl 0x20(%ebp)
0x0041ef25:	call MultiByteToWideChar@KERNEL32.dll
0x0041ef27:	movl %edi, %eax
0x0041ef29:	cmpl %edi, %ebx
0x0041ef2b:	je 0x0041f0c0
0x0041f0c0:	xorl %eax, %eax
0x0041f0c2:	jmp 0x0041f1e8
0x0041f1e8:	leal %esp, -32(%ebp)
0x0041f1eb:	popl %edi
0x0041f1ec:	popl %esi
0x0041f1ed:	popl %ebx
0x0041f1ee:	movl %ecx, -4(%ebp)
0x0041f1f1:	xorl %ecx, %ebp
0x0041f1f3:	call 0x00410135
0x0041f1f8:	leave
0x0041f1f9:	ret

0x0041f22d:	addl %esp, $0x20<UINT8>
0x0041f230:	cmpb -4(%ebp), $0x0<UINT8>
0x0041f234:	je 7
0x0041f236:	movl %ecx, -8(%ebp)
0x0041f239:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0041f23d:	leave
0x0041f23e:	ret

0x004164c5:	addl %esp, $0x44<UINT8>
0x004164c8:	pushl %ebx
0x004164c9:	pushl 0x4(%esi)
0x004164cc:	leal %eax, -772(%ebp)
0x004164d2:	pushl %edi
0x004164d3:	pushl %eax
0x004164d4:	pushl %edi
0x004164d5:	leal %eax, -260(%ebp)
0x004164db:	pushl %eax
0x004164dc:	pushl $0x200<UINT32>
0x004164e1:	pushl 0xc(%esi)
0x004164e4:	pushl %ebx
0x004164e5:	call 0x0041f1fa
0x004164ea:	addl %esp, $0x24<UINT8>
0x004164ed:	xorl %eax, %eax
0x004164ef:	movzwl %ecx, -1284(%ebp,%eax,2)
0x004164f7:	testb %cl, $0x1<UINT8>
0x004164fa:	je 0x0041650a
0x0041650a:	testb %cl, $0x2<UINT8>
0x0041650d:	je 0x00416524
0x00416524:	movb 0x11d(%esi,%eax), $0x0<UINT8>
0x0041652c:	incl %eax
0x0041652d:	cmpl %eax, %edi
0x0041652f:	jb -66
0x00416531:	jmp 0x00416589
0x00416589:	movl %ecx, -4(%ebp)
0x0041658c:	popl %edi
0x0041658d:	xorl %ecx, %ebp
0x0041658f:	popl %ebx
0x00416590:	call 0x00410135
0x00416595:	leave
0x00416596:	ret

0x0041682d:	jmp 0x004166e9
0x004166e9:	xorl %eax, %eax
0x004166eb:	jmp 0x0041688d
0x0041688d:	movl %ecx, -4(%ebp)
0x00416890:	popl %edi
0x00416891:	popl %esi
0x00416892:	xorl %ecx, %ebp
0x00416894:	popl %ebx
0x00416895:	call 0x00410135
0x0041689a:	leave
0x0041689b:	ret

0x004168ff:	popl %ecx
0x00416900:	popl %ecx
0x00416901:	movl -32(%ebp), %eax
0x00416904:	testl %eax, %eax
0x00416906:	jne 252
0x0041690c:	movl %esi, -36(%ebp)
0x0041690f:	pushl 0x68(%esi)
0x00416912:	call InterlockedDecrement@KERNEL32.dll
InterlockedDecrement@KERNEL32.dll: API Node	
0x00416918:	testl %eax, %eax
0x0041691a:	jne 17
0x0041691c:	movl %eax, 0x68(%esi)
0x0041691f:	cmpl %eax, $0x4601e8<UINT32>
0x00416924:	je 0x0041692d
0x0041692d:	movl 0x68(%esi), %ebx
0x00416930:	pushl %ebx
0x00416931:	movl %edi, 0x4502a8
0x00416937:	call InterlockedIncrement@KERNEL32.dll
0x00416939:	testb 0x70(%esi), $0x2<UINT8>
0x0041693d:	jne 234
0x00416943:	testb 0x46070c, $0x1<UINT8>
0x0041694a:	jne 221
0x00416950:	pushl $0xd<UINT8>
0x00416952:	call 0x00418865
0x00416957:	popl %ecx
0x00416958:	andl -4(%ebp), $0x0<UINT8>
0x0041695c:	movl %eax, 0x4(%ebx)
0x0041695f:	movl 0x46a6ac, %eax
0x00416964:	movl %eax, 0x8(%ebx)
0x00416967:	movl 0x46a6b0, %eax
0x0041696c:	movl %eax, 0xc(%ebx)
0x0041696f:	movl 0x46a6b4, %eax
0x00416974:	xorl %eax, %eax
0x00416976:	movl -28(%ebp), %eax
0x00416979:	cmpl %eax, $0x5<UINT8>
0x0041697c:	jnl 0x0041698e
0x0041697e:	movw %cx, 0x10(%ebx,%eax,2)
0x00416983:	movw 0x46a6a0(,%eax,2), %cx
0x0041698b:	incl %eax
0x0041698c:	jmp 0x00416976
0x0041698e:	xorl %eax, %eax
0x00416990:	movl -28(%ebp), %eax
0x00416993:	cmpl %eax, $0x101<UINT32>
0x00416998:	jnl 0x004169a7
0x0041699a:	movb %cl, 0x1c(%eax,%ebx)
0x0041699e:	movb 0x460408(%eax), %cl
0x004169a4:	incl %eax
0x004169a5:	jmp 0x00416990
0x004169a7:	xorl %eax, %eax
0x004169a9:	movl -28(%ebp), %eax
0x004169ac:	cmpl %eax, $0x100<UINT32>
0x004169b1:	jnl 0x004169c3
0x004169b3:	movb %cl, 0x11d(%eax,%ebx)
0x004169ba:	movb 0x460510(%eax), %cl
0x004169c0:	incl %eax
0x004169c1:	jmp 0x004169a9
0x004169c3:	pushl 0x460610
0x004169c9:	call InterlockedDecrement@KERNEL32.dll
0x004169cf:	testl %eax, %eax
0x004169d1:	jne 0x004169e6
0x004169e6:	movl 0x460610, %ebx
0x004169ec:	pushl %ebx
0x004169ed:	call InterlockedIncrement@KERNEL32.dll
0x004169ef:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004169f6:	call 0x004169fd
0x004169fd:	pushl $0xd<UINT8>
0x004169ff:	call 0x0041878b
0x00416a04:	popl %ecx
0x00416a05:	ret

0x004169fb:	jmp 0x00416a2d
0x00416a2d:	movl %eax, -32(%ebp)
0x00416a30:	call 0x004193a1
0x00416a35:	ret

0x00416a46:	popl %ecx
0x00416a47:	movl 0x46c594, $0x1<UINT32>
0x00416a51:	xorl %eax, %eax
0x00416a53:	ret

0x0041bf87:	pushl $0x104<UINT32>
0x0041bf8c:	movl %esi, $0x46abb8<UINT32>
0x0041bf91:	pushl %esi
0x0041bf92:	pushl %ebx
0x0041bf93:	movb 0x46acbc, %bl
0x0041bf99:	call GetModuleFileNameA@KERNEL32.dll
GetModuleFileNameA@KERNEL32.dll: API Node	
0x0041bf9f:	movl %eax, 0x46c5bc
0x0041bfa4:	movl 0x46a864, %esi
0x0041bfaa:	cmpl %eax, %ebx
0x0041bfac:	je 7
0x0041bfae:	movl -4(%ebp), %eax
0x0041bfb1:	cmpb (%eax), %bl
0x0041bfb3:	jne 0x0041bfb8
0x0041bfb8:	movl %edx, -4(%ebp)
0x0041bfbb:	leal %eax, -8(%ebp)
0x0041bfbe:	pushl %eax
0x0041bfbf:	pushl %ebx
0x0041bfc0:	pushl %ebx
0x0041bfc1:	leal %edi, -12(%ebp)
0x0041bfc4:	call 0x0041bdd3
0x0041bdd3:	movl %edi, %edi
0x0041bdd5:	pushl %ebp
0x0041bdd6:	movl %ebp, %esp
0x0041bdd8:	pushl %ecx
0x0041bdd9:	movl %ecx, 0x10(%ebp)
0x0041bddc:	pushl %ebx
0x0041bddd:	xorl %eax, %eax
0x0041bddf:	pushl %esi
0x0041bde0:	movl (%edi), %eax
0x0041bde2:	movl %esi, %edx
0x0041bde4:	movl %edx, 0xc(%ebp)
0x0041bde7:	movl (%ecx), $0x1<UINT32>
0x0041bded:	cmpl 0x8(%ebp), %eax
0x0041bdf0:	je 0x0041bdfb
0x0041bdfb:	movl -4(%ebp), %eax
0x0041bdfe:	cmpb (%esi), $0x22<UINT8>
0x0041be01:	jne 0x0041be13
0x0041be03:	xorl %eax, %eax
0x0041be05:	cmpl -4(%ebp), %eax
0x0041be08:	movb %bl, $0x22<UINT8>
0x0041be0a:	sete %al
0x0041be0d:	incl %esi
0x0041be0e:	movl -4(%ebp), %eax
0x0041be11:	jmp 0x0041be4f
0x0041be4f:	cmpl -4(%ebp), $0x0<UINT8>
0x0041be53:	jne 0x0041bdfe
0x0041be13:	incl (%edi)
0x0041be15:	testl %edx, %edx
0x0041be17:	je 0x0041be21
0x0041be21:	movb %bl, (%esi)
0x0041be23:	movzbl %eax, %bl
0x0041be26:	pushl %eax
0x0041be27:	incl %esi
0x0041be28:	call 0x004213e6
0x004213e6:	movl %edi, %edi
0x004213e8:	pushl %ebp
0x004213e9:	movl %ebp, %esp
0x004213eb:	pushl $0x4<UINT8>
0x004213ed:	pushl $0x0<UINT8>
0x004213ef:	pushl 0x8(%ebp)
0x004213f2:	pushl $0x0<UINT8>
0x004213f4:	call 0x00421393
0x00421393:	movl %edi, %edi
0x00421395:	pushl %ebp
0x00421396:	movl %ebp, %esp
0x00421398:	subl %esp, $0x10<UINT8>
0x0042139b:	pushl 0x8(%ebp)
0x0042139e:	leal %ecx, -16(%ebp)
0x004213a1:	call 0x004105ee
0x004213a6:	movzbl %eax, 0xc(%ebp)
0x004213aa:	movl %ecx, -12(%ebp)
0x004213ad:	movb %dl, 0x14(%ebp)
0x004213b0:	testb 0x1d(%ecx,%eax), %dl
0x004213b4:	jne 30
0x004213b6:	cmpl 0x10(%ebp), $0x0<UINT8>
0x004213ba:	je 0x004213ce
0x004213ce:	xorl %eax, %eax
0x004213d0:	testl %eax, %eax
0x004213d2:	je 0x004213d7
0x004213d7:	cmpb -4(%ebp), $0x0<UINT8>
0x004213db:	je 7
0x004213dd:	movl %ecx, -8(%ebp)
0x004213e0:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x004213e4:	leave
0x004213e5:	ret

0x004213f9:	addl %esp, $0x10<UINT8>
0x004213fc:	popl %ebp
0x004213fd:	ret

0x0041be2d:	popl %ecx
0x0041be2e:	testl %eax, %eax
0x0041be30:	je 0x0041be45
0x0041be45:	movl %edx, 0xc(%ebp)
0x0041be48:	movl %ecx, 0x10(%ebp)
0x0041be4b:	testb %bl, %bl
0x0041be4d:	je 0x0041be81
0x0041be55:	cmpb %bl, $0x20<UINT8>
0x0041be58:	je 5
0x0041be5a:	cmpb %bl, $0x9<UINT8>
0x0041be5d:	jne 0x0041bdfe
0x0041be81:	decl %esi
0x0041be82:	jmp 0x0041be67
0x0041be67:	andl -4(%ebp), $0x0<UINT8>
0x0041be6b:	cmpb (%esi), $0x0<UINT8>
0x0041be6e:	je 0x0041bf5d
0x0041bf5d:	movl %eax, 0x8(%ebp)
0x0041bf60:	popl %esi
0x0041bf61:	popl %ebx
0x0041bf62:	testl %eax, %eax
0x0041bf64:	je 0x0041bf69
0x0041bf69:	incl (%ecx)
0x0041bf6b:	leave
0x0041bf6c:	ret

0x0041bfc9:	movl %eax, -8(%ebp)
0x0041bfcc:	addl %esp, $0xc<UINT8>
0x0041bfcf:	cmpl %eax, $0x3fffffff<UINT32>
0x0041bfd4:	jae 74
0x0041bfd6:	movl %ecx, -12(%ebp)
0x0041bfd9:	cmpl %ecx, $0xffffffff<UINT8>
0x0041bfdc:	jae 66
0x0041bfde:	movl %edi, %eax
0x0041bfe0:	shll %edi, $0x2<UINT8>
0x0041bfe3:	leal %eax, (%edi,%ecx)
0x0041bfe6:	cmpl %eax, %ecx
0x0041bfe8:	jb 54
0x0041bfea:	pushl %eax
0x0041bfeb:	call 0x00419c4d
0x0041bff0:	movl %esi, %eax
0x0041bff2:	popl %ecx
0x0041bff3:	cmpl %esi, %ebx
0x0041bff5:	je 41
0x0041bff7:	movl %edx, -4(%ebp)
0x0041bffa:	leal %eax, -8(%ebp)
0x0041bffd:	pushl %eax
0x0041bffe:	addl %edi, %esi
0x0041c000:	pushl %edi
0x0041c001:	pushl %esi
0x0041c002:	leal %edi, -12(%ebp)
0x0041c005:	call 0x0041bdd3
0x0041bdf2:	movl %ebx, 0x8(%ebp)
0x0041bdf5:	addl 0x8(%ebp), $0x4<UINT8>
0x0041bdf9:	movl (%ebx), %edx
0x0041be19:	movb %al, (%esi)
0x0041be1b:	movb (%edx), %al
0x0041be1d:	incl %edx
0x0041be1e:	movl 0xc(%ebp), %edx
0x0041bf66:	andl (%eax), $0x0<UINT8>
0x0041c00a:	movl %eax, -8(%ebp)
0x0041c00d:	addl %esp, $0xc<UINT8>
0x0041c010:	decl %eax
0x0041c011:	movl 0x46a848, %eax
0x0041c016:	movl 0x46a84c, %esi
0x0041c01c:	xorl %eax, %eax
0x0041c01e:	jmp 0x0041c023
0x0041c023:	popl %edi
0x0041c024:	popl %esi
0x0041c025:	popl %ebx
0x0041c026:	leave
0x0041c027:	ret

0x00414932:	testl %eax, %eax
0x00414934:	jnl 0x0041493e
0x0041493e:	call 0x0041bcf5
0x0041bcf5:	cmpl 0x46c594, $0x0<UINT8>
0x0041bcfc:	jne 0x0041bd03
0x0041bd03:	pushl %esi
0x0041bd04:	movl %esi, 0x46a35c
0x0041bd0a:	pushl %edi
0x0041bd0b:	xorl %edi, %edi
0x0041bd0d:	testl %esi, %esi
0x0041bd0f:	jne 0x0041bd29
0x0041bd29:	movb %al, (%esi)
0x0041bd2b:	testb %al, %al
0x0041bd2d:	jne 0x0041bd19
0x0041bd19:	cmpb %al, $0x3d<UINT8>
0x0041bd1b:	je 0x0041bd1e
0x0041bd1e:	pushl %esi
0x0041bd1f:	call 0x004110c0
0x004110c0:	movl %ecx, 0x4(%esp)
0x004110c4:	testl %ecx, $0x3<UINT32>
0x004110ca:	je 0x004110f0
0x004110f0:	movl %eax, (%ecx)
0x004110f2:	movl %edx, $0x7efefeff<UINT32>
0x004110f7:	addl %edx, %eax
0x004110f9:	xorl %eax, $0xffffffff<UINT8>
0x004110fc:	xorl %eax, %edx
0x004110fe:	addl %ecx, $0x4<UINT8>
0x00411101:	testl %eax, $0x81010100<UINT32>
0x00411106:	je 0x004110f0
0x00411108:	movl %eax, -4(%ecx)
0x0041110b:	testb %al, %al
0x0041110d:	je 50
0x0041110f:	testb %ah, %ah
0x00411111:	je 36
0x00411113:	testl %eax, $0xff0000<UINT32>
0x00411118:	je 19
0x0041111a:	testl %eax, $0xff000000<UINT32>
0x0041111f:	je 0x00411123
0x00411123:	leal %eax, -1(%ecx)
0x00411126:	movl %ecx, 0x4(%esp)
0x0041112a:	subl %eax, %ecx
0x0041112c:	ret

0x0041bd24:	popl %ecx
0x0041bd25:	leal %esi, 0x1(%esi,%eax)
0x0041bd2f:	pushl $0x4<UINT8>
0x0041bd31:	incl %edi
0x0041bd32:	pushl %edi
0x0041bd33:	call 0x00419c92
0x0041bd38:	movl %edi, %eax
0x0041bd3a:	popl %ecx
0x0041bd3b:	popl %ecx
0x0041bd3c:	movl 0x46a854, %edi
0x0041bd42:	testl %edi, %edi
0x0041bd44:	je -53
0x0041bd46:	movl %esi, 0x46a35c
0x0041bd4c:	pushl %ebx
0x0041bd4d:	jmp 0x0041bd91
0x0041bd91:	cmpb (%esi), $0x0<UINT8>
0x0041bd94:	jne 0x0041bd4f
0x0041bd4f:	pushl %esi
0x0041bd50:	call 0x004110c0
0x0041bd55:	movl %ebx, %eax
0x0041bd57:	incl %ebx
0x0041bd58:	cmpb (%esi), $0x3d<UINT8>
0x0041bd5b:	popl %ecx
0x0041bd5c:	je 0x0041bd8f
0x0041bd8f:	addl %esi, %ebx
0x0041bd96:	pushl 0x46a35c
0x0041bd9c:	call 0x00410d85
0x00410d85:	pushl $0xc<UINT8>
0x00410d87:	pushl $0x45b780<UINT32>
0x00410d8c:	call 0x0041935c
0x00410d91:	movl %esi, 0x8(%ebp)
0x00410d94:	testl %esi, %esi
0x00410d96:	je 117
0x00410d98:	cmpl 0x46c5b4, $0x3<UINT8>
0x00410d9f:	jne 0x00410de4
0x00410de4:	pushl %esi
0x00410de5:	pushl $0x0<UINT8>
0x00410de7:	pushl 0x46a6ec
0x00410ded:	call HeapFree@KERNEL32.dll
HeapFree@KERNEL32.dll: API Node	
0x00410df3:	testl %eax, %eax
0x00410df5:	jne 0x00410e0d
0x00410e0d:	call 0x004193a1
0x00410e12:	ret

0x0041bda1:	andl 0x46a35c, $0x0<UINT8>
0x0041bda8:	andl (%edi), $0x0<UINT8>
0x0041bdab:	movl 0x46c588, $0x1<UINT32>
0x0041bdb5:	xorl %eax, %eax
0x0041bdb7:	popl %ecx
0x0041bdb8:	popl %ebx
0x0041bdb9:	popl %edi
0x0041bdba:	popl %esi
0x0041bdbb:	ret

0x00414943:	testl %eax, %eax
0x00414945:	jnl 0x0041494f
0x0041494f:	pushl %ebx
0x00414950:	call 0x004194a4
0x004194a4:	movl %edi, %edi
0x004194a6:	pushl %ebp
0x004194a7:	movl %ebp, %esp
0x004194a9:	cmpl 0x4506dc, $0x0<UINT8>
0x004194b0:	je 25
0x004194b2:	pushl $0x4506dc<UINT32>
0x004194b7:	call 0x00419a30
0x00419a30:	movl %edi, %edi
0x00419a32:	pushl %ebp
0x00419a33:	movl %ebp, %esp
0x00419a35:	pushl $0xfffffffe<UINT8>
0x00419a37:	pushl $0x45ba98<UINT32>
0x00419a3c:	pushl $0x414b00<UINT32>
0x00419a41:	movl %eax, %fs:0
0x00419a47:	pushl %eax
0x00419a48:	subl %esp, $0x8<UINT8>
0x00419a4b:	pushl %ebx
0x00419a4c:	pushl %esi
0x00419a4d:	pushl %edi
0x00419a4e:	movl %eax, 0x460064
0x00419a53:	xorl -8(%ebp), %eax
0x00419a56:	xorl %eax, %ebp
0x00419a58:	pushl %eax
0x00419a59:	leal %eax, -16(%ebp)
0x00419a5c:	movl %fs:0, %eax
0x00419a62:	movl -24(%ebp), %esp
0x00419a65:	movl -4(%ebp), $0x0<UINT32>
0x00419a6c:	pushl $0x400000<UINT32>
0x00419a71:	call 0x004199a0
0x004199a0:	movl %edi, %edi
0x004199a2:	pushl %ebp
0x004199a3:	movl %ebp, %esp
0x004199a5:	movl %ecx, 0x8(%ebp)
0x004199a8:	movl %eax, $0x5a4d<UINT32>
0x004199ad:	cmpw (%ecx), %ax
0x004199b0:	je 0x004199b6
0x004199b6:	movl %eax, 0x3c(%ecx)
0x004199b9:	addl %eax, %ecx
0x004199bb:	cmpl (%eax), $0x4550<UINT32>
0x004199c1:	jne -17
0x004199c3:	xorl %edx, %edx
0x004199c5:	movl %ecx, $0x10b<UINT32>
0x004199ca:	cmpw 0x18(%eax), %cx
0x004199ce:	sete %dl
0x004199d1:	movl %eax, %edx
0x004199d3:	popl %ebp
0x004199d4:	ret

0x00419a76:	addl %esp, $0x4<UINT8>
0x00419a79:	testl %eax, %eax
0x00419a7b:	je 85
0x00419a7d:	movl %eax, 0x8(%ebp)
0x00419a80:	subl %eax, $0x400000<UINT32>
0x00419a85:	pushl %eax
0x00419a86:	pushl $0x400000<UINT32>
0x00419a8b:	call 0x004199e0
0x004199e0:	movl %edi, %edi
0x004199e2:	pushl %ebp
0x004199e3:	movl %ebp, %esp
0x004199e5:	movl %eax, 0x8(%ebp)
0x004199e8:	movl %ecx, 0x3c(%eax)
0x004199eb:	addl %ecx, %eax
0x004199ed:	movzwl %eax, 0x14(%ecx)
0x004199f1:	pushl %ebx
0x004199f2:	pushl %esi
0x004199f3:	movzwl %esi, 0x6(%ecx)
0x004199f7:	xorl %edx, %edx
0x004199f9:	pushl %edi
0x004199fa:	leal %eax, 0x18(%eax,%ecx)
0x004199fe:	testl %esi, %esi
0x00419a00:	jbe 27
0x00419a02:	movl %edi, 0xc(%ebp)
0x00419a05:	movl %ecx, 0xc(%eax)
0x00419a08:	cmpl %edi, %ecx
0x00419a0a:	jb 9
0x00419a0c:	movl %ebx, 0x8(%eax)
0x00419a0f:	addl %ebx, %ecx
0x00419a11:	cmpl %edi, %ebx
0x00419a13:	jb 0x00419a1f
0x00419a1f:	popl %edi
0x00419a20:	popl %esi
0x00419a21:	popl %ebx
0x00419a22:	popl %ebp
0x00419a23:	ret

0x00419a90:	addl %esp, $0x8<UINT8>
0x00419a93:	testl %eax, %eax
0x00419a95:	je 59
0x00419a97:	movl %eax, 0x24(%eax)
0x00419a9a:	shrl %eax, $0x1f<UINT8>
0x00419a9d:	notl %eax
0x00419a9f:	andl %eax, $0x1<UINT8>
0x00419aa2:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00419aa9:	movl %ecx, -16(%ebp)
0x00419aac:	movl %fs:0, %ecx
0x00419ab3:	popl %ecx
0x00419ab4:	popl %edi
0x00419ab5:	popl %esi
0x00419ab6:	popl %ebx
0x00419ab7:	movl %esp, %ebp
0x00419ab9:	popl %ebp
0x00419aba:	ret

0x004194bc:	popl %ecx
0x004194bd:	testl %eax, %eax
0x004194bf:	je 0x004194cb
0x004194cb:	call 0x0041dfd7
0x0041dfd7:	movl %edi, %edi
0x0041dfd9:	pushl %esi
0x0041dfda:	pushl %edi
0x0041dfdb:	xorl %edi, %edi
0x0041dfdd:	leal %esi, 0x460d20(%edi)
0x0041dfe3:	pushl (%esi)
0x0041dfe5:	call 0x00416d79
0x00416d9b:	pushl %eax
0x00416d9c:	pushl 0x460804
0x00416da2:	call TlsGetValue@KERNEL32.dll
0x00416da4:	call FlsGetValue@KERNEL32.DLL
0x00416da6:	testl %eax, %eax
0x00416da8:	je 8
0x00416daa:	movl %eax, 0x1f8(%eax)
0x00416db0:	jmp 0x00416dd9
0x0041dfea:	addl %edi, $0x4<UINT8>
0x0041dfed:	popl %ecx
0x0041dfee:	movl (%esi), %eax
0x0041dff0:	cmpl %edi, $0x28<UINT8>
0x0041dff3:	jb 0x0041dfdd
0x0041dff5:	popl %edi
0x0041dff6:	popl %esi
0x0041dff7:	ret

0x004194d0:	pushl $0x450550<UINT32>
0x004194d5:	pushl $0x450538<UINT32>
0x004194da:	call 0x00419480
0x00419480:	movl %edi, %edi
0x00419482:	pushl %ebp
0x00419483:	movl %ebp, %esp
0x00419485:	pushl %esi
0x00419486:	movl %esi, 0x8(%ebp)
0x00419489:	xorl %eax, %eax
0x0041948b:	jmp 0x0041949c
0x0041949c:	cmpl %esi, 0xc(%ebp)
0x0041949f:	jb 0x0041948d
0x0041948d:	testl %eax, %eax
0x0041948f:	jne 16
0x00419491:	movl %ecx, (%esi)
0x00419493:	testl %ecx, %ecx
0x00419495:	je 0x00419499
0x00419499:	addl %esi, $0x4<UINT8>
0x00419497:	call 0x0041bc88
0x0041153d:	movl %edi, %edi
0x0041153f:	pushl %esi
0x00411540:	pushl $0x4<UINT8>
0x00411542:	pushl $0x20<UINT8>
0x00411544:	call 0x00419c92
0x00411549:	movl %esi, %eax
0x0041154b:	pushl %esi
0x0041154c:	call 0x00416d79
0x00411551:	addl %esp, $0xc<UINT8>
0x00411554:	movl 0x46c590, %eax
0x00411559:	movl 0x46c58c, %eax
0x0041155e:	testl %esi, %esi
0x00411560:	jne 0x00411567
0x00411567:	andl (%esi), $0x0<UINT8>
0x0041156a:	xorl %eax, %eax
0x0041156c:	popl %esi
0x0041156d:	ret

0x00415535:	call 0x004154d3
0x004154d3:	movl %edi, %edi
0x004154d5:	pushl %ebp
0x004154d6:	movl %ebp, %esp
0x004154d8:	subl %esp, $0x18<UINT8>
0x004154db:	xorl %eax, %eax
0x004154dd:	pushl %ebx
0x004154de:	movl -4(%ebp), %eax
0x004154e1:	movl -12(%ebp), %eax
0x004154e4:	movl -8(%ebp), %eax
0x004154e7:	pushl %ebx
0x004154e8:	pushfl
0x004154e9:	popl %eax
0x004154ea:	movl %ecx, %eax
0x004154ec:	xorl %eax, $0x200000<UINT32>
0x004154f1:	pushl %eax
0x004154f2:	popfl
0x004154f3:	pushfl
0x004154f4:	popl %edx
0x004154f5:	subl %edx, %ecx
0x004154f7:	je 0x00415518
0x00415518:	popl %ebx
0x00415519:	testl -4(%ebp), $0x4000000<UINT32>
0x00415520:	je 0x00415530
0x00415530:	xorl %eax, %eax
0x00415532:	popl %ebx
0x00415533:	leave
0x00415534:	ret

0x0041553a:	movl 0x46c5b8, %eax
0x0041553f:	xorl %eax, %eax
0x00415541:	ret

0x0041a22e:	movl %eax, 0x46c580
0x0041a233:	pushl %esi
0x0041a234:	pushl $0x14<UINT8>
0x0041a236:	popl %esi
0x0041a237:	testl %eax, %eax
0x0041a239:	jne 7
0x0041a23b:	movl %eax, $0x200<UINT32>
0x0041a240:	jmp 0x0041a248
0x0041a248:	movl 0x46c580, %eax
0x0041a24d:	pushl $0x4<UINT8>
0x0041a24f:	pushl %eax
0x0041a250:	call 0x00419c92
0x0041a255:	popl %ecx
0x0041a256:	popl %ecx
0x0041a257:	movl 0x46b560, %eax
0x0041a25c:	testl %eax, %eax
0x0041a25e:	jne 0x0041a27e
0x0041a27e:	xorl %edx, %edx
0x0041a280:	movl %ecx, $0x460a10<UINT32>
0x0041a285:	jmp 0x0041a28c
0x0041a28c:	movl (%edx,%eax), %ecx
0x0041a28f:	addl %ecx, $0x20<UINT8>
0x0041a292:	addl %edx, $0x4<UINT8>
0x0041a295:	cmpl %ecx, $0x460c90<UINT32>
0x0041a29b:	jl 0x0041a287
0x0041a287:	movl %eax, 0x46b560
0x0041a29d:	pushl $0xfffffffe<UINT8>
0x0041a29f:	popl %esi
0x0041a2a0:	xorl %edx, %edx
0x0041a2a2:	movl %ecx, $0x460a20<UINT32>
0x0041a2a7:	pushl %edi
0x0041a2a8:	movl %eax, %edx
0x0041a2aa:	sarl %eax, $0x5<UINT8>
0x0041a2ad:	movl %eax, 0x46b460(,%eax,4)
0x0041a2b4:	movl %edi, %edx
0x0041a2b6:	andl %edi, $0x1f<UINT8>
0x0041a2b9:	shll %edi, $0x6<UINT8>
0x0041a2bc:	movl %eax, (%edi,%eax)
0x0041a2bf:	cmpl %eax, $0xffffffff<UINT8>
0x0041a2c2:	je 8
0x0041a2c4:	cmpl %eax, %esi
0x0041a2c6:	je 4
0x0041a2c8:	testl %eax, %eax
0x0041a2ca:	jne 0x0041a2ce
0x0041a2ce:	addl %ecx, $0x20<UINT8>
0x0041a2d1:	incl %edx
0x0041a2d2:	cmpl %ecx, $0x460a80<UINT32>
0x0041a2d8:	jl 0x0041a2a8
0x0041a2da:	popl %edi
0x0041a2db:	xorl %eax, %eax
0x0041a2dd:	popl %esi
0x0041a2de:	ret

0x0041bc88:	pushl $0x41bc46<UINT32>
0x0041bc8d:	call SetUnhandledExceptionFilter@KERNEL32.dll
SetUnhandledExceptionFilter@KERNEL32.dll: API Node	
0x0041bc93:	xorl %eax, %eax
0x0041bc95:	ret

0x004194a1:	popl %esi
0x004194a2:	popl %ebp
0x004194a3:	ret

0x004194df:	popl %ecx
0x004194e0:	popl %ecx
0x004194e1:	testl %eax, %eax
0x004194e3:	jne 66
0x004194e5:	pushl $0x41c185<UINT32>
0x004194ea:	call 0x004115aa
0x004115aa:	movl %edi, %edi
0x004115ac:	pushl %ebp
0x004115ad:	movl %ebp, %esp
0x004115af:	pushl 0x8(%ebp)
0x004115b2:	call 0x0041156e
0x0041156e:	pushl $0xc<UINT8>
0x00411570:	pushl $0x45b840<UINT32>
0x00411575:	call 0x0041935c
0x0041157a:	call 0x00419451
0x00419451:	pushl $0x8<UINT8>
0x00419453:	call 0x00418865
0x00419458:	popl %ecx
0x00419459:	ret

0x0041157f:	andl -4(%ebp), $0x0<UINT8>
0x00411583:	pushl 0x8(%ebp)
0x00411586:	call 0x00411483
0x00411483:	movl %edi, %edi
0x00411485:	pushl %ebp
0x00411486:	movl %ebp, %esp
0x00411488:	pushl %ecx
0x00411489:	pushl %ebx
0x0041148a:	pushl %esi
0x0041148b:	pushl %edi
0x0041148c:	pushl 0x46c590
0x00411492:	call 0x00416df4
0x00416e25:	movl %eax, 0x1fc(%eax)
0x00416e2b:	jmp 0x00416e54
0x00411497:	pushl 0x46c58c
0x0041149d:	movl %edi, %eax
0x0041149f:	movl -4(%ebp), %edi
0x004114a2:	call 0x00416df4
0x004114a7:	movl %esi, %eax
0x004114a9:	popl %ecx
0x004114aa:	popl %ecx
0x004114ab:	cmpl %esi, %edi
0x004114ad:	jb 131
0x004114b3:	movl %ebx, %esi
0x004114b5:	subl %ebx, %edi
0x004114b7:	leal %eax, 0x4(%ebx)
0x004114ba:	cmpl %eax, $0x4<UINT8>
0x004114bd:	jb 119
0x004114bf:	pushl %edi
0x004114c0:	call 0x0041114b
0x0041114b:	pushl $0x10<UINT8>
0x0041114d:	pushl $0x45b7c0<UINT32>
0x00411152:	call 0x0041935c
0x00411157:	xorl %eax, %eax
0x00411159:	movl %ebx, 0x8(%ebp)
0x0041115c:	xorl %edi, %edi
0x0041115e:	cmpl %ebx, %edi
0x00411160:	setne %al
0x00411163:	cmpl %eax, %edi
0x00411165:	jne 0x00411184
0x00411184:	cmpl 0x46c5b4, $0x3<UINT8>
0x0041118b:	jne 0x004111c5
0x004111c5:	pushl %ebx
0x004111c6:	pushl %edi
0x004111c7:	pushl 0x46a6ec
0x004111cd:	call HeapSize@KERNEL32.dll
HeapSize@KERNEL32.dll: API Node	
0x004111d3:	movl %esi, %eax
0x004111d5:	movl %eax, %esi
0x004111d7:	call 0x004193a1
0x004111dc:	ret

0x004114c5:	movl %edi, %eax
0x004114c7:	leal %eax, 0x4(%ebx)
0x004114ca:	popl %ecx
0x004114cb:	cmpl %edi, %eax
0x004114cd:	jae 0x00411517
0x00411517:	pushl 0x8(%ebp)
0x0041151a:	call 0x00416d79
0x0041151f:	movl (%esi), %eax
0x00411521:	addl %esi, $0x4<UINT8>
0x00411524:	pushl %esi
0x00411525:	call 0x00416d79
0x0041152a:	popl %ecx
0x0041152b:	movl 0x46c58c, %eax
0x00411530:	movl %eax, 0x8(%ebp)
0x00411533:	popl %ecx
0x00411534:	jmp 0x00411538
0x00411538:	popl %edi
0x00411539:	popl %esi
0x0041153a:	popl %ebx
0x0041153b:	leave
0x0041153c:	ret

0x0041158b:	popl %ecx
0x0041158c:	movl -28(%ebp), %eax
0x0041158f:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00411596:	call 0x004115a4
0x004115a4:	call 0x0041945a
0x0041945a:	pushl $0x8<UINT8>
0x0041945c:	call 0x0041878b
0x00419461:	popl %ecx
0x00419462:	ret

0x004115a9:	ret

0x0041159b:	movl %eax, -28(%ebp)
0x0041159e:	call 0x004193a1
0x004115a3:	ret

0x004115b7:	negl %eax
0x004115b9:	sbbl %eax, %eax
0x004115bb:	negl %eax
0x004115bd:	popl %ecx
0x004115be:	decl %eax
0x004115bf:	popl %ebp
0x004115c0:	ret

0x004194ef:	movl %eax, $0x450520<UINT32>
0x004194f4:	movl (%esp), $0x450534<UINT32>
0x004194fb:	call 0x00419463
0x00419463:	movl %edi, %edi
0x00419465:	pushl %ebp
0x00419466:	movl %ebp, %esp
0x00419468:	pushl %esi
0x00419469:	movl %esi, %eax
0x0041946b:	jmp 0x00419478
0x00419478:	cmpl %esi, 0x8(%ebp)
0x0041947b:	jb 0x0041946d
0x0041946d:	movl %eax, (%esi)
0x0041946f:	testl %eax, %eax
0x00419471:	je 0x00419475
0x00419475:	addl %esi, $0x4<UINT8>
0x00419473:	call 0x0044fd10
0x0044fd30:	movl %edi, %edi
0x0044fd32:	pushl %ebp
0x0044fd33:	movl %ebp, %esp
0x0044fd35:	pushl $0xa<UINT8>
0x0044fd37:	pushl $0x80020004<UINT32>
0x0044fd3c:	movl %ecx, $0x46a320<UINT32>
0x0044fd41:	call 0x0040bdd0
0x0040bdd0:	pushl %ebp
0x0040bdd1:	movl %ebp, %esp
0x0040bdd3:	pushl %ecx
0x0040bdd4:	movl -4(%ebp), %ecx
0x0040bdd7:	movzwl %eax, 0xc(%ebp)
0x0040bddb:	cmpl %eax, $0x3<UINT8>
0x0040bdde:	je 30
0x0040bde0:	movzwl %ecx, 0xc(%ebp)
0x0040bde4:	cmpl %ecx, $0xa<UINT8>
0x0040bde7:	je 0x0040bdfe
0x0040bdfe:	movzwl %eax, 0xc(%ebp)
0x0040be02:	cmpl %eax, $0xa<UINT8>
0x0040be05:	jne 22
0x0040be07:	movl %ecx, $0xa<UINT32>
0x0040be0c:	movl %edx, -4(%ebp)
0x0040be0f:	movw (%edx), %cx
0x0040be12:	movl %eax, -4(%ebp)
0x0040be15:	movl %ecx, 0x8(%ebp)
0x0040be18:	movl 0x8(%eax), %ecx
0x0040be1b:	jmp 0x0040be55
0x0040be55:	movl %eax, -4(%ebp)
0x0040be58:	movl %esp, %ebp
0x0040be5a:	popl %ebp
0x0040be5b:	ret $0x8<UINT16>

0x0044fd46:	pushl $0x44fea0<UINT32>
0x0044fd4b:	call 0x004115aa
0x0044fd50:	addl %esp, $0x4<UINT8>
0x0044fd53:	cmpl %ebp, %esp
0x0044fd55:	call 0x004149f6
0x004149f6:	jne 1
0x004149f8:	ret

0x0044fd5a:	popl %ebp
0x0044fd5b:	ret

0x0044fce0:	pushl %ebp
0x0044fce1:	movl %ebp, %esp
0x0044fce3:	pushl $0x10<UINT8>
0x0044fce5:	pushl $0x10<UINT8>
0x0044fce7:	movl %ecx, $0x46ae74<UINT32>
0x0044fcec:	call 0x00401a80
0x00401a80:	pushl %ebp
0x00401a81:	movl %ebp, %esp
0x00401a83:	pushl %ecx
0x00401a84:	movl -4(%ebp), %ecx
0x00401a87:	movl %eax, -4(%ebp)
0x00401a8a:	movl 0xc(%eax), $0x0<UINT32>
0x00401a91:	movl %ecx, -4(%ebp)
0x00401a94:	movl 0x10(%ecx), $0x0<UINT32>
0x00401a9b:	movl %edx, -4(%ebp)
0x00401a9e:	movl 0x14(%edx), $0x0<UINT32>
0x00401aa5:	movl %ecx, -4(%ebp)
0x00401aa8:	addl %ecx, $0x18<UINT8>
0x00401aab:	call 0x00401a20
0x00401a20:	pushl %ebp
0x00401a21:	movl %ebp, %esp
0x00401a23:	pushl %ecx
0x00401a24:	movl -4(%ebp), %ecx
0x00401a27:	movl %eax, -4(%ebp)
0x00401a2a:	pushl %eax
0x00401a2b:	call InitializeCriticalSection@KERNEL32.dll
InitializeCriticalSection@KERNEL32.dll: API Node	
0x00401a31:	movl %eax, -4(%ebp)
0x00401a34:	movl %esp, %ebp
0x00401a36:	popl %ebp
0x00401a37:	ret

0x00401ab0:	pushl $0x100<UINT32>
0x00401ab5:	pushl $0x100<UINT32>
0x00401aba:	pushl $0x1<UINT8>
0x00401abc:	movl %eax, 0xc(%ebp)
0x00401abf:	pushl %eax
0x00401ac0:	movl %ecx, 0x8(%ebp)
0x00401ac3:	pushl %ecx
0x00401ac4:	call ImageList_Create@COMCTL32.dll
ImageList_Create@COMCTL32.dll: API Node	
0x00401aca:	movl %edx, -4(%ebp)
0x00401acd:	movl (%edx), %eax
0x00401acf:	movl %eax, -4(%ebp)
0x00401ad2:	movl %esp, %ebp
0x00401ad4:	popl %ebp
0x00401ad5:	ret $0x8<UINT16>

0x0044fcf1:	pushl $0x44fd60<UINT32>
0x0044fcf6:	call 0x004115aa
0x0044fcfb:	addl %esp, $0x4<UINT8>
0x0044fcfe:	popl %ebp
0x0044fcff:	ret

0x0044fd00:	pushl %ebp
0x0044fd01:	movl %ebp, %esp
0x0044fd03:	movl %ecx, $0x46aea4<UINT32>
0x0044fd08:	call 0x00401a20
0x0044fd0d:	popl %ebp
0x0044fd0e:	ret

0x0044fd10:	pushl %ebp
0x0044fd11:	movl %ebp, %esp
0x0044fd13:	movl %ecx, $0x46aebc<UINT32>
0x0044fd18:	call 0x00402530
0x00402530:	pushl %ebp
0x00402531:	movl %ebp, %esp
0x00402533:	pushl %ecx
0x00402534:	movl -4(%ebp), %ecx
0x00402537:	movl %eax, -4(%ebp)
0x0040253a:	movl (%eax), $0x0<UINT32>
0x00402540:	movl %ecx, -4(%ebp)
0x00402543:	movl 0x4(%ecx), $0x0<UINT32>
0x0040254a:	movl %edx, -4(%ebp)
0x0040254d:	movl 0x8(%edx), $0x0<UINT32>
0x00402554:	movl %eax, -4(%ebp)
0x00402557:	movl 0xc(%eax), $0x0<UINT32>
0x0040255e:	movl %eax, -4(%ebp)
0x00402561:	movl %esp, %ebp
0x00402563:	popl %ebp
0x00402564:	ret

0x0044fd1d:	pushl $0x44fe90<UINT32>
0x0044fd22:	call 0x004115aa
0x0044fd27:	addl %esp, $0x4<UINT8>
0x0044fd2a:	popl %ebp
0x0044fd2b:	ret

0x0041947d:	popl %esi
0x0041947e:	popl %ebp
0x0041947f:	ret

0x00419500:	cmpl 0x46c598, $0x0<UINT8>
0x00419507:	popl %ecx
0x00419508:	je 0x00419525
0x00419525:	xorl %eax, %eax
0x00419527:	popl %ebp
0x00419528:	ret

0x00414955:	popl %ecx
0x00414956:	cmpl %eax, %esi
0x00414958:	je 0x00414961
0x00414961:	call 0x0041bc96
0x0041bc96:	movl %edi, %edi
0x0041bc98:	pushl %esi
0x0041bc99:	pushl %edi
0x0041bc9a:	xorl %edi, %edi
0x0041bc9c:	cmpl 0x46c594, %edi
0x0041bca2:	jne 0x0041bca9
0x0041bca9:	movl %esi, 0x46c5bc
0x0041bcaf:	testl %esi, %esi
0x0041bcb1:	jne 0x0041bcb8
0x0041bcb8:	movb %al, (%esi)
0x0041bcba:	cmpb %al, $0x20<UINT8>
0x0041bcbc:	ja 0x0041bcc6
0x0041bcc6:	cmpb %al, $0x22<UINT8>
0x0041bcc8:	jne 0x0041bcd3
0x0041bcca:	xorl %ecx, %ecx
0x0041bccc:	testl %edi, %edi
0x0041bcce:	sete %cl
0x0041bcd1:	movl %edi, %ecx
0x0041bcd3:	movzbl %eax, %al
0x0041bcd6:	pushl %eax
0x0041bcd7:	call 0x004213e6
0x0041bcdc:	popl %ecx
0x0041bcdd:	testl %eax, %eax
0x0041bcdf:	je 0x0041bce2
0x0041bce2:	incl %esi
0x0041bce3:	jmp 0x0041bcb8
0x0041bcbe:	testb %al, %al
0x0041bcc0:	je 0x0041bcf0
0x0041bcf0:	popl %edi
0x0041bcf1:	movl %eax, %esi
0x0041bcf3:	popl %esi
0x0041bcf4:	ret

0x00414966:	testb -60(%ebp), %bl
0x00414969:	je 0x00414971
0x00414971:	pushl $0xa<UINT8>
0x00414973:	popl %ecx
0x00414974:	pushl %ecx
0x00414975:	pushl %eax
0x00414976:	pushl %esi
0x00414977:	pushl $0x400000<UINT32>
0x0041497c:	call 0x0044d610
0x0044d610:	pushl %ebp
0x0044d611:	movl %ebp, %esp
0x0044d613:	subl %esp, $0x1dc<UINT32>
0x0044d619:	movl %eax, 0x460064
0x0044d61e:	xorl %eax, %ebp
0x0044d620:	movl -24(%ebp), %eax
0x0044d623:	movl -304(%ebp), $0x114<UINT32>
0x0044d62d:	movl -300(%ebp), $0x0<UINT32>
0x0044d637:	pushl $0x10c<UINT32>
0x0044d63c:	pushl $0x0<UINT8>
0x0044d63e:	leal %eax, -296(%ebp)
0x0044d644:	pushl %eax
0x0044d645:	call 0x00411760
0x0044d64a:	addl %esp, $0xc<UINT8>
0x0044d64d:	leal %ecx, -304(%ebp)
0x0044d653:	pushl %ecx
0x0044d654:	call GetVersionExW@KERNEL32.dll
GetVersionExW@KERNEL32.dll: API Node	
0x0044d65a:	cmpl -300(%ebp), $0x5<UINT8>
0x0044d661:	ja 0x0044d681
0x0044d681:	movl -476(%ebp), $0x1<UINT32>
0x0044d68b:	movb %dl, -476(%ebp)
0x0044d691:	movb 0x46ae28, %dl
0x0044d697:	pushl $0x0<UINT8>
0x0044d699:	call CoInitialize@ole32.dll
CoInitialize@ole32.dll: API Node	
0x0044d69f:	call 0x00425870
0x00425870:	pushl %ebp
0x00425871:	movl %ebp, %esp
0x00425873:	pushl %ecx
0x00425874:	movl -4(%ebp), $0x0<UINT32>
0x0042587b:	leal %eax, -4(%ebp)
0x0042587e:	pushl %eax
0x0042587f:	pushl $0x20<UINT8>
0x00425881:	call GetCurrentProcess@KERNEL32.dll
GetCurrentProcess@KERNEL32.dll: API Node	
0x00425887:	pushl %eax
0x00425888:	call OpenProcessToken@ADVAPI32.dll
OpenProcessToken@ADVAPI32.dll: API Node	
0x0042588e:	call GetLastError@KERNEL32.dll
0x00425894:	pushl $0x1<UINT8>
0x00425896:	pushl $0x452c3c<UINT32>
0x0042589b:	movl %ecx, -4(%ebp)
0x0042589e:	pushl %ecx
0x0042589f:	call 0x004255b0
0x004255b0:	pushl %ebp
0x004255b1:	movl %ebp, %esp
0x004255b3:	subl %esp, $0x18<UINT8>
0x004255b6:	leal %eax, -8(%ebp)
0x004255b9:	pushl %eax
0x004255ba:	movl %ecx, 0xc(%ebp)
0x004255bd:	pushl %ecx
0x004255be:	pushl $0x0<UINT8>
0x004255c0:	call LookupPrivilegeValueW@ADVAPI32.dll
LookupPrivilegeValueW@ADVAPI32.dll: API Node	
0x004255c6:	testl %eax, %eax
0x004255c8:	jne 0x004255ce
0x004255ce:	movl -24(%ebp), $0x1<UINT32>
0x004255d5:	movl %edx, -8(%ebp)
0x004255d8:	movl -20(%ebp), %edx
0x004255db:	movl %eax, -4(%ebp)
0x004255de:	movl -16(%ebp), %eax
0x004255e1:	cmpl 0x10(%ebp), $0x0<UINT8>
0x004255e5:	je 9
0x004255e7:	movl -12(%ebp), $0x2<UINT32>
0x004255ee:	jmp 0x004255f7
0x004255f7:	pushl $0x0<UINT8>
0x004255f9:	pushl $0x0<UINT8>
0x004255fb:	pushl $0x10<UINT8>
0x004255fd:	leal %ecx, -24(%ebp)
0x00425600:	pushl %ecx
0x00425601:	pushl $0x0<UINT8>
0x00425603:	movl %edx, 0x8(%ebp)
0x00425606:	pushl %edx
0x00425607:	call AdjustTokenPrivileges@ADVAPI32.dll
AdjustTokenPrivileges@ADVAPI32.dll: API Node	
0x0042560d:	call GetLastError@KERNEL32.dll
0x00425613:	negl %eax
0x00425615:	sbbl %eax, %eax
0x00425617:	addl %eax, $0x1<UINT8>
0x0042561a:	movl %esp, %ebp
0x0042561c:	popl %ebp
0x0042561d:	ret

0x004258a4:	addl %esp, $0xc<UINT8>
0x004258a7:	pushl $0x1<UINT8>
0x004258a9:	pushl $0x452c60<UINT32>
0x004258ae:	movl %edx, -4(%ebp)
0x004258b1:	pushl %edx
0x004258b2:	call 0x004255b0
0x004258b7:	addl %esp, $0xc<UINT8>
0x004258ba:	pushl $0x1<UINT8>
0x004258bc:	pushl $0x452c88<UINT32>
0x004258c1:	movl %eax, -4(%ebp)
0x004258c4:	pushl %eax
0x004258c5:	call 0x004255b0
0x004258ca:	addl %esp, $0xc<UINT8>
0x004258cd:	movl %ecx, -4(%ebp)
0x004258d0:	pushl %ecx
0x004258d1:	call CloseHandle@KERNEL32.dll
CloseHandle@KERNEL32.dll: API Node	
0x004258d7:	movb %al, $0x1<UINT8>
0x004258d9:	movl %esp, %ebp
0x004258db:	popl %ebp
0x004258dc:	ret

0x0044d6a4:	movl %eax, 0x8(%ebp)
0x0044d6a7:	movl 0x46ae48, %eax
0x0044d6ac:	pushl $0x46ae40<UINT32>
0x0044d6b1:	pushl $0x45a540<UINT32>
0x0044d6b6:	pushl $0x80000001<UINT32>
0x0044d6bb:	call RegCreateKeyW@ADVAPI32.dll
RegCreateKeyW@ADVAPI32.dll: API Node	
0x0044d6c1:	call InitCommonControls@COMCTL32.dll
InitCommonControls@COMCTL32.dll: API Node	
0x0044d6c7:	leal %ecx, -20(%ebp)
0x0044d6ca:	call 0x004098f0
0x004098f0:	pushl %ebp
0x004098f1:	movl %ebp, %esp
0x004098f3:	pushl %ecx
0x004098f4:	movl -4(%ebp), %ecx
0x004098f7:	movl %eax, -4(%ebp)
0x004098fa:	pushl %eax
0x004098fb:	call GetCommandLineW@KERNEL32.dll
GetCommandLineW@KERNEL32.dll: API Node	
0x00409901:	pushl %eax
0x00409902:	call CommandLineToArgvW@SHELL32.dll
CommandLineToArgvW@SHELL32.dll: API Node	
0x00409908:	movl %ecx, -4(%ebp)
0x0040990b:	movl 0x4(%ecx), %eax
0x0040990e:	movl %eax, -4(%ebp)
0x00409911:	movl %esp, %ebp
0x00409913:	popl %ebp
0x00409914:	ret

0x0044d6cf:	movl %ecx, -16(%ebp)
0x0044d6d2:	pushl %ecx
0x0044d6d3:	leal %edx, -20(%ebp)
0x0044d6d6:	pushl %edx
0x0044d6d7:	pushl $0x45a50c<UINT32>
0x0044d6dc:	call 0x00435780
0x00435780:	pushl %ebp
0x00435781:	movl %ebp, %esp
0x00435783:	subl %esp, $0x14<UINT8>
0x00435786:	pushl %esi
0x00435787:	movl -8(%ebp), $0x0<UINT32>
0x0043578e:	movl -12(%ebp), $0x0<UINT32>
0x00435795:	cmpl 0xc(%ebp), $0x0<UINT8>
0x00435799:	je 6
0x0043579b:	cmpl 0x10(%ebp), $0x0<UINT8>
0x0043579f:	jne 0x004357e2
0x004357e2:	cmpl 0xc(%ebp), $0x0<UINT8>
0x004357e6:	je 179
0x004357ec:	movl -4(%ebp), $0x0<UINT32>
0x004357f3:	jmp 0x004357fe
0x004357fe:	movl %edx, 0xc(%ebp)
0x00435801:	movl %eax, -4(%ebp)
0x00435804:	cmpl %eax, (%edx)
0x00435806:	jge 147
0x0043580c:	pushl $0x469eb8<UINT32>
0x00435811:	movl %ecx, -4(%ebp)
0x00435814:	movl %edx, 0x10(%ebp)
0x00435817:	movl %eax, (%edx,%ecx,4)
0x0043581a:	pushl %eax
0x0043581b:	call 0x00410786
0x00410786:	movl %edi, %edi
0x00410788:	pushl %ebp
0x00410789:	movl %ebp, %esp
0x0041078b:	pushl %esi
0x0041078c:	xorl %esi, %esi
0x0041078e:	pushl %edi
0x0041078f:	cmpl 0x46a6b8, %esi
0x00410795:	jne 111
0x00410797:	movl %edi, 0x8(%ebp)
0x0041079a:	cmpl %edi, %esi
0x0041079c:	jne 0x004107bd
0x004107bd:	movl %edx, 0xc(%ebp)
0x004107c0:	cmpl %edx, %esi
0x004107c2:	je -38
0x004107c4:	movzwl %eax, (%edi)
0x004107c7:	cmpw %ax, $0x41<UINT8>
0x004107cb:	jb 0x004107d6
0x004107cd:	cmpw %ax, $0x5a<UINT8>
0x004107d1:	ja 0x004107d6
0x004107d6:	movzwl %ecx, %ax
0x004107d9:	movzwl %eax, (%edx)
0x004107dc:	cmpw %ax, $0x41<UINT8>
0x004107e0:	jb 0x004107eb
0x004107eb:	incl %edi
0x004107ec:	incl %edi
0x004107ed:	incl %edx
0x004107ee:	incl %edx
0x004107ef:	movzwl %eax, %ax
0x004107f2:	cmpw %cx, %si
0x004107f5:	je 0x004107fc
0x004107f7:	cmpw %cx, %ax
0x004107fa:	je -56
0x004107fc:	movzwl %edx, %ax
0x004107ff:	movzwl %eax, %cx
0x00410802:	subl %eax, %edx
0x00410804:	jmp 0x00410815
0x00410815:	popl %edi
0x00410816:	popl %esi
0x00410817:	popl %ebp
0x00410818:	ret

0x00435820:	addl %esp, $0x8<UINT8>
0x00435823:	testl %eax, %eax
0x00435825:	je 36
0x00435827:	pushl $0x469ed0<UINT32>
0x0043582c:	movl %ecx, -4(%ebp)
0x0043582f:	movl %edx, 0x10(%ebp)
0x00435832:	movl %eax, (%edx,%ecx,4)
0x00435835:	pushl %eax
0x00435836:	call 0x00410786
0x0043583b:	addl %esp, $0x8<UINT8>
0x0043583e:	testl %eax, %eax
0x00435840:	je 9
0x00435842:	movl -20(%ebp), $0x0<UINT32>
0x00435849:	jmp 0x00435852
0x00435852:	movl %ecx, -20(%ebp)
0x00435855:	movl -12(%ebp), %ecx
0x00435858:	cmpl -12(%ebp), $0x0<UINT8>
0x0043585c:	je 0x0043589a
0x0043589a:	jmp 0x004357f5
0x004357f5:	movl %ecx, -4(%ebp)
0x004357f8:	addl %ecx, $0x1<UINT8>
0x004357fb:	movl -4(%ebp), %ecx
0x0041079e:	call 0x00416328
0x00416328:	call 0x00417004
0x0041632d:	testl %eax, %eax
0x0041632f:	jne 0x00416337
0x00416337:	addl %eax, $0x8<UINT8>
0x0041633a:	ret

0x004107a3:	pushl %esi
0x004107a4:	pushl %esi
0x004107a5:	pushl %esi
0x004107a6:	pushl %esi
0x004107a7:	pushl %esi
0x004107a8:	movl (%eax), $0x16<UINT32>
0x004107ae:	call 0x004116f8
0x004116f8:	movl %edi, %edi
0x004116fa:	pushl %ebp
0x004116fb:	movl %ebp, %esp
0x004116fd:	pushl 0x46a340
0x00411703:	call 0x00416df4
0x00411708:	popl %ecx
0x00411709:	testl %eax, %eax
0x0041170b:	je 0x00411710
0x00411710:	pushl $0x2<UINT8>
0x00411712:	call 0x00419d7e
0x00419d7e:	andl 0x46c584, $0x0<UINT8>
0x00419d85:	ret

0x00411717:	popl %ecx
0x00411718:	popl %ebp
0x00411719:	jmp 0x004115d0
0x004115d0:	movl %edi, %edi
0x004115d2:	pushl %ebp
0x004115d3:	movl %ebp, %esp
0x004115d5:	subl %esp, $0x328<UINT32>
0x004115db:	movl %eax, 0x460064
0x004115e0:	xorl %eax, %ebp
0x004115e2:	movl -4(%ebp), %eax
0x004115e5:	andl -808(%ebp), $0x0<UINT8>
0x004115ec:	pushl %ebx
0x004115ed:	pushl $0x4c<UINT8>
0x004115ef:	leal %eax, -804(%ebp)
0x004115f5:	pushl $0x0<UINT8>
0x004115f7:	pushl %eax
0x004115f8:	call 0x00411760
