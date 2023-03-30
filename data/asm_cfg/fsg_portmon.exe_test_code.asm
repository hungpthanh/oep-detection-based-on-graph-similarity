0x00525000:	movl %ebx, $0x4001d0<UINT32>
0x00525005:	movl %edi, $0x401000<UINT32>
0x0052500a:	movl %esi, $0x50886a<UINT32>
0x0052500f:	pushl %ebx
0x00525010:	call 0x0052501f
0x0052501f:	cld
0x00525020:	movb %dl, $0xffffff80<UINT8>
0x00525022:	movsb %es:(%edi), %ds:(%esi)
0x00525023:	pushl $0x2<UINT8>
0x00525025:	popl %ebx
0x00525026:	call 0x00525015
0x00525015:	addb %dl, %dl
0x00525017:	jne 0x0052501e
0x00525019:	movb %dl, (%esi)
0x0052501b:	incl %esi
0x0052501c:	adcb %dl, %dl
0x0052501e:	ret

0x00525029:	jae 0x00525022
0x0052502b:	xorl %ecx, %ecx
0x0052502d:	call 0x00525015
0x00525030:	jae 0x0052504a
0x00525032:	xorl %eax, %eax
0x00525034:	call 0x00525015
0x00525037:	jae 0x0052505a
0x00525039:	movb %bl, $0x2<UINT8>
0x0052503b:	incl %ecx
0x0052503c:	movb %al, $0x10<UINT8>
0x0052503e:	call 0x00525015
0x00525041:	adcb %al, %al
0x00525043:	jae 0x0052503e
0x00525045:	jne 0x00525086
0x00525086:	pushl %esi
0x00525087:	movl %esi, %edi
0x00525089:	subl %esi, %eax
0x0052508b:	rep movsb %es:(%edi), %ds:(%esi)
0x0052508d:	popl %esi
0x0052508e:	jmp 0x00525026
0x00525047:	stosb %es:(%edi), %al
0x00525048:	jmp 0x00525026
0x0052505a:	lodsb %al, %ds:(%esi)
0x0052505b:	shrl %eax
0x0052505d:	je 0x005250a0
0x0052505f:	adcl %ecx, %ecx
0x00525061:	jmp 0x0052507f
0x0052507f:	incl %ecx
0x00525080:	incl %ecx
0x00525081:	xchgl %ebp, %eax
0x00525082:	movl %eax, %ebp
0x00525084:	movb %bl, $0x1<UINT8>
0x0052504a:	call 0x00525092
0x00525092:	incl %ecx
0x00525093:	call 0x00525015
0x00525097:	adcl %ecx, %ecx
0x00525099:	call 0x00525015
0x0052509d:	jb 0x00525093
0x0052509f:	ret

0x0052504f:	subl %ecx, %ebx
0x00525051:	jne 0x00525063
0x00525053:	call 0x00525090
0x00525090:	xorl %ecx, %ecx
0x00525058:	jmp 0x00525082
0x00525063:	xchgl %ecx, %eax
0x00525064:	decl %eax
0x00525065:	shll %eax, $0x8<UINT8>
0x00525068:	lodsb %al, %ds:(%esi)
0x00525069:	call 0x00525090
0x0052506e:	cmpl %eax, $0x7d00<UINT32>
0x00525073:	jae 0x0052507f
0x00525075:	cmpb %ah, $0x5<UINT8>
0x00525078:	jae 0x00525080
0x0052507a:	cmpl %eax, $0x7f<UINT8>
0x0052507d:	ja 0x00525081
0x005250a0:	popl %edi
0x005250a1:	popl %ebx
0x005250a2:	movzwl %edi, (%ebx)
0x005250a5:	decl %edi
0x005250a6:	je 0x005250b0
0x005250a8:	decl %edi
0x005250a9:	je 0x005250be
0x005250ab:	shll %edi, $0xc<UINT8>
0x005250ae:	jmp 0x005250b7
0x005250b7:	incl %ebx
0x005250b8:	incl %ebx
0x005250b9:	jmp 0x0052500f
0x005250b0:	movl %edi, 0x2(%ebx)
0x005250b3:	pushl %edi
0x005250b4:	addl %ebx, $0x4<UINT8>
0x005250be:	popl %edi
0x005250bf:	movl %ebx, $0x525128<UINT32>
0x005250c4:	incl %edi
0x005250c5:	movl %esi, (%edi)
0x005250c7:	scasl %eax, %es:(%edi)
0x005250c8:	pushl %edi
0x005250c9:	call LoadLibraryA@KERNEL32.dll
LoadLibraryA@kernel32.dll: API Node	
0x005250cb:	xchgl %ebp, %eax
0x005250cc:	xorl %eax, %eax
0x005250ce:	scasb %al, %es:(%edi)
0x005250cf:	jne 0x005250ce
0x005250d1:	decb (%edi)
0x005250d3:	je 0x005250c4
0x005250d5:	decb (%edi)
0x005250d7:	jne 0x005250df
0x005250df:	decb (%edi)
0x005250e1:	je 0x00413b0e
0x005250e7:	pushl %edi
0x005250e8:	pushl %ebp
0x005250e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x005250ec:	orl (%esi), %eax
0x005250ee:	lodsl %eax, %ds:(%esi)
0x005250ef:	jne 0x005250cc
0x005250d9:	incl %edi
0x005250da:	pushl (%edi)
0x005250dc:	scasl %eax, %es:(%edi)
0x005250dd:	jmp 0x005250e8
GetProcAddress@KERNEL32.dll: API Node	
LoadLibraryA@KERNEL32.dll: API Node	
0x00413b0e:	call 0x0041f959
0x0041f959:	movl %edi, %edi
0x0041f95b:	pushl %ebp
0x0041f95c:	movl %ebp, %esp
0x0041f95e:	subl %esp, $0x10<UINT8>
0x0041f961:	movl %eax, 0x43b810
0x0041f966:	andl -8(%ebp), $0x0<UINT8>
0x0041f96a:	andl -4(%ebp), $0x0<UINT8>
0x0041f96e:	pushl %ebx
0x0041f96f:	pushl %edi
0x0041f970:	movl %edi, $0xbb40e64e<UINT32>
0x0041f975:	movl %ebx, $0xffff0000<UINT32>
0x0041f97a:	cmpl %eax, %edi
0x0041f97c:	je 0x0041f98b
0x0041f98b:	pushl %esi
0x0041f98c:	leal %eax, -8(%ebp)
0x0041f98f:	pushl %eax
0x0041f990:	call GetSystemTimeAsFileTime@KERNEL32.dll
GetSystemTimeAsFileTime@KERNEL32.dll: API Node	
0x0041f996:	movl %esi, -4(%ebp)
0x0041f999:	xorl %esi, -8(%ebp)
0x0041f99c:	call GetCurrentProcessId@KERNEL32.dll
GetCurrentProcessId@KERNEL32.dll: API Node	
0x0041f9a2:	xorl %esi, %eax
0x0041f9a4:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x0041f9aa:	xorl %esi, %eax
0x0041f9ac:	call GetTickCount@KERNEL32.dll
GetTickCount@KERNEL32.dll: API Node	
0x0041f9b2:	xorl %esi, %eax
0x0041f9b4:	leal %eax, -16(%ebp)
0x0041f9b7:	pushl %eax
0x0041f9b8:	call QueryPerformanceCounter@KERNEL32.dll
QueryPerformanceCounter@KERNEL32.dll: API Node	
0x0041f9be:	movl %eax, -12(%ebp)
0x0041f9c1:	xorl %eax, -16(%ebp)
0x0041f9c4:	xorl %esi, %eax
0x0041f9c6:	cmpl %esi, %edi
0x0041f9c8:	jne 0x0041f9d1
0x0041f9d1:	testl %ebx, %esi
0x0041f9d3:	jne 0x0041f9dc
0x0041f9dc:	movl 0x43b810, %esi
0x0041f9e2:	notl %esi
0x0041f9e4:	movl 0x43b814, %esi
0x0041f9ea:	popl %esi
0x0041f9eb:	popl %edi
0x0041f9ec:	popl %ebx
0x0041f9ed:	leave
0x0041f9ee:	ret

0x00413b13:	jmp 0x00413990
0x00413990:	pushl $0x58<UINT8>
0x00413992:	pushl $0x434318<UINT32>
0x00413997:	call 0x00414d00
0x00414d00:	pushl $0x414d90<UINT32>
0x00414d05:	pushl %fs:0
0x00414d0c:	movl %eax, 0x10(%esp)
0x00414d10:	movl 0x10(%esp), %ebp
0x00414d14:	leal %ebp, 0x10(%esp)
0x00414d18:	subl %esp, %eax
0x00414d1a:	pushl %ebx
0x00414d1b:	pushl %esi
0x00414d1c:	pushl %edi
0x00414d1d:	movl %eax, 0x43b810
0x00414d22:	xorl -4(%ebp), %eax
0x00414d25:	xorl %eax, %ebp
0x00414d27:	pushl %eax
0x00414d28:	movl -24(%ebp), %esp
0x00414d2b:	pushl -8(%ebp)
0x00414d2e:	movl %eax, -4(%ebp)
0x00414d31:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00414d38:	movl -8(%ebp), %eax
0x00414d3b:	leal %eax, -16(%ebp)
0x00414d3e:	movl %fs:0, %eax
0x00414d44:	ret

0x0041399c:	xorl %esi, %esi
0x0041399e:	movl -4(%ebp), %esi
0x004139a1:	leal %eax, -104(%ebp)
0x004139a4:	pushl %eax
0x004139a5:	call GetStartupInfoA@KERNEL32.dll
GetStartupInfoA@KERNEL32.dll: API Node	
0x004139ab:	pushl $0xfffffffe<UINT8>
0x004139ad:	popl %edi
0x004139ae:	movl -4(%ebp), %edi
0x004139b1:	movl %eax, $0x5a4d<UINT32>
0x004139b6:	cmpw 0x400000, %ax
0x004139bd:	jne 56
0x004139bf:	movl %eax, 0x40003c
0x004139c4:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x004139ce:	jne 39
0x004139d0:	movl %ecx, $0x10b<UINT32>
0x004139d5:	cmpw 0x400018(%eax), %cx
0x004139dc:	jne 25
0x004139de:	cmpl 0x400074(%eax), $0xe<UINT8>
0x004139e5:	jbe 16
0x004139e7:	xorl %ecx, %ecx
0x004139e9:	cmpl 0x4000e8(%eax), %esi
0x004139ef:	setne %cl
0x004139f2:	movl -28(%ebp), %ecx
0x004139f5:	jmp 0x004139fa
0x004139fa:	xorl %ebx, %ebx
0x004139fc:	incl %ebx
0x004139fd:	pushl %ebx
0x004139fe:	call 0x00414f20
0x00414f20:	movl %edi, %edi
0x00414f22:	pushl %ebp
0x00414f23:	movl %ebp, %esp
0x00414f25:	xorl %eax, %eax
0x00414f27:	cmpl 0x8(%ebp), %eax
0x00414f2a:	pushl $0x0<UINT8>
0x00414f2c:	sete %al
0x00414f2f:	pushl $0x1000<UINT32>
0x00414f34:	pushl %eax
0x00414f35:	call HeapCreate@KERNEL32.dll
HeapCreate@KERNEL32.dll: API Node	
0x00414f3b:	movl 0x443004, %eax
0x00414f40:	testl %eax, %eax
0x00414f42:	jne 0x00414f46
0x00414f46:	xorl %eax, %eax
0x00414f48:	incl %eax
0x00414f49:	movl 0x4a8fa4, %eax
0x00414f4e:	popl %ebp
0x00414f4f:	ret

0x00413a03:	popl %ecx
0x00413a04:	testl %eax, %eax
0x00413a06:	jne 0x00413a10
0x00413a10:	call 0x00418e48
0x00418e48:	movl %edi, %edi
0x00418e4a:	pushl %esi
0x00418e4b:	pushl %edi
0x00418e4c:	movl %esi, $0x432cec<UINT32>
0x00418e51:	pushl %esi
0x00418e52:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x00418e58:	testl %eax, %eax
0x00418e5a:	jne 0x00418e63
0x00418e63:	movl %edi, %eax
0x00418e65:	testl %edi, %edi
0x00418e67:	je 350
0x00418e6d:	movl %esi, 0x432280
0x00418e73:	pushl $0x432d38<UINT32>
0x00418e78:	pushl %edi
0x00418e79:	call GetProcAddress@KERNEL32.dll
0x00418e7b:	pushl $0x432d2c<UINT32>
0x00418e80:	pushl %edi
0x00418e81:	movl 0x4436c4, %eax
0x00418e86:	call GetProcAddress@KERNEL32.dll
0x00418e88:	pushl $0x432d20<UINT32>
0x00418e8d:	pushl %edi
0x00418e8e:	movl 0x4436c8, %eax
0x00418e93:	call GetProcAddress@KERNEL32.dll
0x00418e95:	pushl $0x432d18<UINT32>
0x00418e9a:	pushl %edi
0x00418e9b:	movl 0x4436cc, %eax
0x00418ea0:	call GetProcAddress@KERNEL32.dll
0x00418ea2:	cmpl 0x4436c4, $0x0<UINT8>
0x00418ea9:	movl %esi, 0x4321b0
0x00418eaf:	movl 0x4436d0, %eax
0x00418eb4:	je 22
0x00418eb6:	cmpl 0x4436c8, $0x0<UINT8>
0x00418ebd:	je 13
0x00418ebf:	cmpl 0x4436cc, $0x0<UINT8>
0x00418ec6:	je 4
0x00418ec8:	testl %eax, %eax
0x00418eca:	jne 0x00418ef0
0x00418ef0:	call TlsAlloc@KERNEL32.dll
TlsAlloc@KERNEL32.dll: API Node	
0x00418ef6:	movl 0x43c1ac, %eax
0x00418efb:	cmpl %eax, $0xffffffff<UINT8>
0x00418efe:	je 204
0x00418f04:	pushl 0x4436c8
0x00418f0a:	pushl %eax
0x00418f0b:	call TlsSetValue@KERNEL32.dll
TlsSetValue@KERNEL32.dll: API Node	
0x00418f0d:	testl %eax, %eax
0x00418f0f:	je 187
0x00418f15:	call 0x0041532c
0x0041532c:	movl %edi, %edi
0x0041532e:	pushl %esi
0x0041532f:	call 0x004189f3
0x004189f3:	pushl $0x0<UINT8>
0x004189f5:	call 0x00418981
0x00418981:	movl %edi, %edi
0x00418983:	pushl %ebp
0x00418984:	movl %ebp, %esp
0x00418986:	pushl %esi
0x00418987:	pushl 0x43c1ac
0x0041898d:	movl %esi, 0x4321b8
0x00418993:	call TlsGetValue@KERNEL32.dll
TlsGetValue@KERNEL32.dll: API Node	
0x00418995:	testl %eax, %eax
0x00418997:	je 33
0x00418999:	movl %eax, 0x43c1a8
0x0041899e:	cmpl %eax, $0xffffffff<UINT8>
0x004189a1:	je 0x004189ba
0x004189ba:	movl %esi, $0x432cec<UINT32>
0x004189bf:	pushl %esi
0x004189c0:	call GetModuleHandleW@KERNEL32.dll
0x004189c6:	testl %eax, %eax
0x004189c8:	jne 0x004189d5
0x004189d5:	pushl $0x432cdc<UINT32>
0x004189da:	pushl %eax
0x004189db:	call GetProcAddress@KERNEL32.dll
0x004189e1:	testl %eax, %eax
0x004189e3:	je 8
0x004189e5:	pushl 0x8(%ebp)
0x004189e8:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x004189ea:	movl 0x8(%ebp), %eax
0x004189ed:	movl %eax, 0x8(%ebp)
0x004189f0:	popl %esi
0x004189f1:	popl %ebp
0x004189f2:	ret

0x004189fa:	popl %ecx
0x004189fb:	ret

0x00415334:	movl %esi, %eax
0x00415336:	pushl %esi
0x00415337:	call 0x004156d3
0x004156d3:	movl %edi, %edi
0x004156d5:	pushl %ebp
0x004156d6:	movl %ebp, %esp
0x004156d8:	movl %eax, 0x8(%ebp)
0x004156db:	movl 0x443354, %eax
0x004156e0:	popl %ebp
0x004156e1:	ret

0x0041533c:	pushl %esi
0x0041533d:	call 0x0041f9ef
0x0041f9ef:	movl %edi, %edi
0x0041f9f1:	pushl %ebp
0x0041f9f2:	movl %ebp, %esp
0x0041f9f4:	movl %eax, 0x8(%ebp)
0x0041f9f7:	movl 0x4437f4, %eax
0x0041f9fc:	popl %ebp
0x0041f9fd:	ret

0x00415342:	pushl %esi
0x00415343:	call 0x0041675b
0x0041675b:	movl %edi, %edi
0x0041675d:	pushl %ebp
0x0041675e:	movl %ebp, %esp
0x00416760:	movl %eax, 0x8(%ebp)
0x00416763:	movl 0x44335c, %eax
0x00416768:	popl %ebp
0x00416769:	ret

0x00415348:	pushl %esi
0x00415349:	call 0x0042072a
0x0042072a:	movl %edi, %edi
0x0042072c:	pushl %ebp
0x0042072d:	movl %ebp, %esp
0x0042072f:	movl %eax, 0x8(%ebp)
0x00420732:	movl 0x44381c, %eax
0x00420737:	popl %ebp
0x00420738:	ret

0x0041534e:	pushl %esi
0x0041534f:	call 0x00420494
0x00420494:	movl %edi, %edi
0x00420496:	pushl %ebp
0x00420497:	movl %ebp, %esp
0x00420499:	movl %eax, 0x8(%ebp)
0x0042049c:	movl 0x443810, %eax
0x004204a1:	popl %ebp
0x004204a2:	ret

0x00415354:	pushl %esi
0x00415355:	call 0x0041ff98
0x0041ff98:	movl %edi, %edi
0x0041ff9a:	pushl %ebp
0x0041ff9b:	movl %ebp, %esp
0x0041ff9d:	movl %eax, 0x8(%ebp)
0x0041ffa0:	movl 0x4437fc, %eax
0x0041ffa5:	movl 0x443800, %eax
0x0041ffaa:	movl 0x443804, %eax
0x0041ffaf:	movl 0x443808, %eax
0x0041ffb4:	popl %ebp
0x0041ffb5:	ret

0x0041535a:	pushl %esi
0x0041535b:	call 0x004195fd
0x004195fd:	ret

0x00415360:	pushl %esi
0x00415361:	call 0x0041ff87
0x0041ff87:	pushl $0x41ff03<UINT32>
0x0041ff8c:	call 0x00418981
0x0041ff91:	popl %ecx
0x0041ff92:	movl 0x4437f8, %eax
0x0041ff97:	ret

0x00415366:	pushl $0x4152f8<UINT32>
0x0041536b:	call 0x00418981
0x00415370:	addl %esp, $0x24<UINT8>
0x00415373:	movl 0x43b95c, %eax
0x00415378:	popl %esi
0x00415379:	ret

0x00418f1a:	pushl 0x4436c4
0x00418f20:	call 0x00418981
0x00418f25:	pushl 0x4436c8
0x00418f2b:	movl 0x4436c4, %eax
0x00418f30:	call 0x00418981
0x00418f35:	pushl 0x4436cc
0x00418f3b:	movl 0x4436c8, %eax
0x00418f40:	call 0x00418981
0x00418f45:	pushl 0x4436d0
0x00418f4b:	movl 0x4436cc, %eax
0x00418f50:	call 0x00418981
0x00418f55:	addl %esp, $0x10<UINT8>
0x00418f58:	movl 0x4436d0, %eax
0x00418f5d:	call 0x00413b18
0x00413b18:	movl %edi, %edi
0x00413b1a:	pushl %esi
0x00413b1b:	pushl %edi
0x00413b1c:	xorl %esi, %esi
0x00413b1e:	movl %edi, $0x442eb0<UINT32>
0x00413b23:	cmpl 0x43b83c(,%esi,8), $0x1<UINT8>
0x00413b2b:	jne 0x00413b4b
0x00413b2d:	leal %eax, 0x43b838(,%esi,8)
0x00413b34:	movl (%eax), %edi
0x00413b36:	pushl $0xfa0<UINT32>
0x00413b3b:	pushl (%eax)
0x00413b3d:	addl %edi, $0x18<UINT8>
0x00413b40:	call 0x0041f9fe
0x0041f9fe:	pushl $0x10<UINT8>
0x0041fa00:	pushl $0x4345f8<UINT32>
0x0041fa05:	call 0x00414d00
0x0041fa0a:	andl -4(%ebp), $0x0<UINT8>
0x0041fa0e:	pushl 0xc(%ebp)
0x0041fa11:	pushl 0x8(%ebp)
0x0041fa14:	call InitializeCriticalSectionAndSpinCount@KERNEL32.dll
InitializeCriticalSectionAndSpinCount@KERNEL32.dll: API Node	
0x0041fa1a:	movl -28(%ebp), %eax
0x0041fa1d:	jmp 0x0041fa4e
0x0041fa4e:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0041fa55:	movl %eax, -28(%ebp)
0x0041fa58:	call 0x00414d45
0x00414d45:	movl %ecx, -16(%ebp)
0x00414d48:	movl %fs:0, %ecx
0x00414d4f:	popl %ecx
0x00414d50:	popl %edi
0x00414d51:	popl %edi
0x00414d52:	popl %esi
0x00414d53:	popl %ebx
0x00414d54:	movl %esp, %ebp
0x00414d56:	popl %ebp
0x00414d57:	pushl %ecx
0x00414d58:	ret

0x0041fa5d:	ret

0x00413b45:	popl %ecx
0x00413b46:	popl %ecx
0x00413b47:	testl %eax, %eax
0x00413b49:	je 12
0x00413b4b:	incl %esi
0x00413b4c:	cmpl %esi, $0x24<UINT8>
0x00413b4f:	jl 0x00413b23
0x00413b51:	xorl %eax, %eax
0x00413b53:	incl %eax
0x00413b54:	popl %edi
0x00413b55:	popl %esi
0x00413b56:	ret

0x00418f62:	testl %eax, %eax
0x00418f64:	je 101
0x00418f66:	pushl $0x418c9f<UINT32>
0x00418f6b:	pushl 0x4436c4
0x00418f71:	call 0x004189fc
0x004189fc:	movl %edi, %edi
0x004189fe:	pushl %ebp
0x004189ff:	movl %ebp, %esp
0x00418a01:	pushl %esi
0x00418a02:	pushl 0x43c1ac
0x00418a08:	movl %esi, 0x4321b8
0x00418a0e:	call TlsGetValue@KERNEL32.dll
0x00418a10:	testl %eax, %eax
0x00418a12:	je 33
0x00418a14:	movl %eax, 0x43c1a8
0x00418a19:	cmpl %eax, $0xffffffff<UINT8>
0x00418a1c:	je 0x00418a35
0x00418a35:	movl %esi, $0x432cec<UINT32>
0x00418a3a:	pushl %esi
0x00418a3b:	call GetModuleHandleW@KERNEL32.dll
0x00418a41:	testl %eax, %eax
0x00418a43:	jne 0x00418a50
0x00418a50:	pushl $0x432d08<UINT32>
0x00418a55:	pushl %eax
0x00418a56:	call GetProcAddress@KERNEL32.dll
0x00418a5c:	testl %eax, %eax
0x00418a5e:	je 8
0x00418a60:	pushl 0x8(%ebp)
0x00418a63:	call DecodePointer@KERNEL32.DLL
DecodePointer@KERNEL32.DLL: API Node	
0x00418a65:	movl 0x8(%ebp), %eax
0x00418a68:	movl %eax, 0x8(%ebp)
0x00418a6b:	popl %esi
0x00418a6c:	popl %ebp
0x00418a6d:	ret

0x00418f76:	popl %ecx
0x00418f77:	call FlsAlloc@KERNEL32.DLL
FlsAlloc@KERNEL32.DLL: API Node	
0x00418f79:	movl 0x43c1a8, %eax
0x00418f7e:	cmpl %eax, $0xffffffff<UINT8>
0x00418f81:	je 72
0x00418f83:	pushl $0x214<UINT32>
0x00418f88:	pushl $0x1<UINT8>
0x00418f8a:	call 0x00419833
0x00419833:	movl %edi, %edi
0x00419835:	pushl %ebp
0x00419836:	movl %ebp, %esp
0x00419838:	pushl %esi
0x00419839:	pushl %edi
0x0041983a:	xorl %esi, %esi
0x0041983c:	pushl $0x0<UINT8>
0x0041983e:	pushl 0xc(%ebp)
0x00419841:	pushl 0x8(%ebp)
0x00419844:	call 0x00428ffc
0x00428ffc:	pushl $0xc<UINT8>
0x00428ffe:	pushl $0x434718<UINT32>
0x00429003:	call 0x00414d00
0x00429008:	movl %ecx, 0x8(%ebp)
0x0042900b:	xorl %edi, %edi
0x0042900d:	cmpl %ecx, %edi
0x0042900f:	jbe 46
0x00429011:	pushl $0xffffffe0<UINT8>
0x00429013:	popl %eax
0x00429014:	xorl %edx, %edx
0x00429016:	divl %eax, %ecx
0x00429018:	cmpl %eax, 0xc(%ebp)
0x0042901b:	sbbl %eax, %eax
0x0042901d:	incl %eax
0x0042901e:	jne 0x0042903f
0x0042903f:	imull %ecx, 0xc(%ebp)
0x00429043:	movl %esi, %ecx
0x00429045:	movl 0x8(%ebp), %esi
0x00429048:	cmpl %esi, %edi
0x0042904a:	jne 0x0042904f
0x0042904f:	xorl %ebx, %ebx
0x00429051:	movl -28(%ebp), %ebx
0x00429054:	cmpl %esi, $0xffffffe0<UINT8>
0x00429057:	ja 105
0x00429059:	cmpl 0x4a8fa4, $0x3<UINT8>
0x00429060:	jne 0x004290ad
0x004290ad:	cmpl %ebx, %edi
0x004290af:	jne 97
0x004290b1:	pushl %esi
0x004290b2:	pushl $0x8<UINT8>
0x004290b4:	pushl 0x443004
0x004290ba:	call HeapAlloc@KERNEL32.dll
HeapAlloc@KERNEL32.dll: API Node	
0x004290c0:	movl %ebx, %eax
0x004290c2:	cmpl %ebx, %edi
0x004290c4:	jne 0x00429112
0x00429112:	movl %eax, %ebx
0x00429114:	call 0x00414d45
0x00429119:	ret

0x00419849:	movl %edi, %eax
0x0041984b:	addl %esp, $0xc<UINT8>
0x0041984e:	testl %edi, %edi
0x00419850:	jne 0x00419879
0x00419879:	movl %eax, %edi
0x0041987b:	popl %edi
0x0041987c:	popl %esi
0x0041987d:	popl %ebp
0x0041987e:	ret

0x00418f8f:	movl %esi, %eax
0x00418f91:	popl %ecx
0x00418f92:	popl %ecx
0x00418f93:	testl %esi, %esi
0x00418f95:	je 52
0x00418f97:	pushl %esi
0x00418f98:	pushl 0x43c1a8
0x00418f9e:	pushl 0x4436cc
0x00418fa4:	call 0x004189fc
0x00418a1e:	pushl %eax
0x00418a1f:	pushl 0x43c1ac
0x00418a25:	call TlsGetValue@KERNEL32.dll
0x00418a27:	call FlsGetValue@KERNEL32.DLL
FlsGetValue@KERNEL32.DLL: API Node	
0x00418a29:	testl %eax, %eax
0x00418a2b:	je 0x00418a35
0x00418fa9:	popl %ecx
0x00418faa:	call FlsSetValue@KERNEL32.DLL
FlsSetValue@KERNEL32.DLL: API Node	
0x00418fac:	testl %eax, %eax
0x00418fae:	je 27
0x00418fb0:	pushl $0x0<UINT8>
0x00418fb2:	pushl %esi
0x00418fb3:	call 0x00418b25
0x00418b25:	pushl $0xc<UINT8>
0x00418b27:	pushl $0x434488<UINT32>
0x00418b2c:	call 0x00414d00
0x00418b31:	movl %esi, $0x432cec<UINT32>
0x00418b36:	pushl %esi
0x00418b37:	call GetModuleHandleW@KERNEL32.dll
0x00418b3d:	testl %eax, %eax
0x00418b3f:	jne 0x00418b48
0x00418b48:	movl -28(%ebp), %eax
0x00418b4b:	movl %esi, 0x8(%ebp)
0x00418b4e:	movl 0x5c(%esi), $0x432d48<UINT32>
0x00418b55:	xorl %edi, %edi
0x00418b57:	incl %edi
0x00418b58:	movl 0x14(%esi), %edi
0x00418b5b:	testl %eax, %eax
0x00418b5d:	je 36
0x00418b5f:	pushl $0x432cdc<UINT32>
0x00418b64:	pushl %eax
0x00418b65:	movl %ebx, 0x432280
0x00418b6b:	call GetProcAddress@KERNEL32.dll
0x00418b6d:	movl 0x1f8(%esi), %eax
0x00418b73:	pushl $0x432d08<UINT32>
0x00418b78:	pushl -28(%ebp)
0x00418b7b:	call GetProcAddress@KERNEL32.dll
0x00418b7d:	movl 0x1fc(%esi), %eax
0x00418b83:	movl 0x70(%esi), %edi
0x00418b86:	movb 0xc8(%esi), $0x43<UINT8>
0x00418b8d:	movb 0x14b(%esi), $0x43<UINT8>
0x00418b94:	movl 0x68(%esi), $0x43bb90<UINT32>
0x00418b9b:	pushl $0xd<UINT8>
0x00418b9d:	call 0x00413cac
0x00413cac:	movl %edi, %edi
0x00413cae:	pushl %ebp
0x00413caf:	movl %ebp, %esp
0x00413cb1:	movl %eax, 0x8(%ebp)
0x00413cb4:	pushl %esi
0x00413cb5:	leal %esi, 0x43b838(,%eax,8)
0x00413cbc:	cmpl (%esi), $0x0<UINT8>
0x00413cbf:	jne 0x00413cd4
0x00413cd4:	pushl (%esi)
0x00413cd6:	call EnterCriticalSection@KERNEL32.dll
EnterCriticalSection@KERNEL32.dll: API Node	
0x00413cdc:	popl %esi
0x00413cdd:	popl %ebp
0x00413cde:	ret

0x00418ba2:	popl %ecx
0x00418ba3:	andl -4(%ebp), $0x0<UINT8>
0x00418ba7:	pushl 0x68(%esi)
0x00418baa:	call InterlockedIncrement@KERNEL32.dll
InterlockedIncrement@KERNEL32.dll: API Node	
0x00418bb0:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00418bb7:	call 0x00418bfa
0x00418bfa:	pushl $0xd<UINT8>
0x00418bfc:	call 0x00413bba
0x00413bba:	movl %edi, %edi
0x00413bbc:	pushl %ebp
0x00413bbd:	movl %ebp, %esp
0x00413bbf:	movl %eax, 0x8(%ebp)
0x00413bc2:	pushl 0x43b838(,%eax,8)
0x00413bc9:	call LeaveCriticalSection@KERNEL32.dll
LeaveCriticalSection@KERNEL32.dll: API Node	
0x00413bcf:	popl %ebp
0x00413bd0:	ret

0x00418c01:	popl %ecx
0x00418c02:	ret

0x00418bbc:	pushl $0xc<UINT8>
0x00418bbe:	call 0x00413cac
0x00418bc3:	popl %ecx
0x00418bc4:	movl -4(%ebp), %edi
0x00418bc7:	movl %eax, 0xc(%ebp)
0x00418bca:	movl 0x6c(%esi), %eax
0x00418bcd:	testl %eax, %eax
0x00418bcf:	jne 8
0x00418bd1:	movl %eax, 0x43c198
0x00418bd6:	movl 0x6c(%esi), %eax
0x00418bd9:	pushl 0x6c(%esi)
0x00418bdc:	call 0x00417813
0x00417813:	movl %edi, %edi
0x00417815:	pushl %ebp
0x00417816:	movl %ebp, %esp
0x00417818:	pushl %ebx
0x00417819:	pushl %esi
0x0041781a:	movl %esi, 0x4321cc
0x00417820:	pushl %edi
0x00417821:	movl %edi, 0x8(%ebp)
0x00417824:	pushl %edi
0x00417825:	call InterlockedIncrement@KERNEL32.dll
0x00417827:	movl %eax, 0xb0(%edi)
0x0041782d:	testl %eax, %eax
0x0041782f:	je 0x00417834
0x00417834:	movl %eax, 0xb8(%edi)
0x0041783a:	testl %eax, %eax
0x0041783c:	je 0x00417841
0x00417841:	movl %eax, 0xb4(%edi)
0x00417847:	testl %eax, %eax
0x00417849:	je 0x0041784e
0x0041784e:	movl %eax, 0xc0(%edi)
0x00417854:	testl %eax, %eax
0x00417856:	je 0x0041785b
0x0041785b:	leal %ebx, 0x50(%edi)
0x0041785e:	movl 0x8(%ebp), $0x6<UINT32>
0x00417865:	cmpl -8(%ebx), $0x43c0b8<UINT32>
0x0041786c:	je 0x00417877
0x0041786e:	movl %eax, (%ebx)
0x00417870:	testl %eax, %eax
0x00417872:	je 0x00417877
0x00417877:	cmpl -4(%ebx), $0x0<UINT8>
0x0041787b:	je 0x00417887
0x00417887:	addl %ebx, $0x10<UINT8>
0x0041788a:	decl 0x8(%ebp)
0x0041788d:	jne 0x00417865
0x0041788f:	movl %eax, 0xd4(%edi)
0x00417895:	addl %eax, $0xb4<UINT32>
0x0041789a:	pushl %eax
0x0041789b:	call InterlockedIncrement@KERNEL32.dll
0x0041789d:	popl %edi
0x0041789e:	popl %esi
0x0041789f:	popl %ebx
0x004178a0:	popl %ebp
0x004178a1:	ret

0x00418be1:	popl %ecx
0x00418be2:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00418be9:	call 0x00418c03
0x00418c03:	pushl $0xc<UINT8>
0x00418c05:	call 0x00413bba
0x00418c0a:	popl %ecx
0x00418c0b:	ret

0x00418bee:	call 0x00414d45
0x00418bf3:	ret

0x00418fb8:	popl %ecx
0x00418fb9:	popl %ecx
0x00418fba:	call GetCurrentThreadId@KERNEL32.dll
0x00418fc0:	orl 0x4(%esi), $0xffffffff<UINT8>
0x00418fc4:	movl (%esi), %eax
0x00418fc6:	xorl %eax, %eax
0x00418fc8:	incl %eax
0x00418fc9:	jmp 0x00418fd2
0x00418fd2:	popl %edi
0x00418fd3:	popl %esi
0x00418fd4:	ret

0x00413a15:	testl %eax, %eax
0x00413a17:	jne 0x00413a21
0x00413a21:	call 0x0041f90d
0x0041f90d:	movl %edi, %edi
0x0041f90f:	pushl %esi
0x0041f910:	movl %eax, $0x434180<UINT32>
0x0041f915:	movl %esi, $0x434180<UINT32>
0x0041f91a:	pushl %edi
0x0041f91b:	movl %edi, %eax
0x0041f91d:	cmpl %eax, %esi
0x0041f91f:	jae 0x0041f930
0x0041f930:	popl %edi
0x0041f931:	popl %esi
0x0041f932:	ret

0x00413a26:	movl -4(%ebp), %ebx
0x00413a29:	call 0x0041b79d
0x0041b79d:	pushl $0x54<UINT8>
0x0041b79f:	pushl $0x434598<UINT32>
0x0041b7a4:	call 0x00414d00
0x0041b7a9:	xorl %edi, %edi
0x0041b7ab:	movl -4(%ebp), %edi
0x0041b7ae:	leal %eax, -100(%ebp)
0x0041b7b1:	pushl %eax
0x0041b7b2:	call GetStartupInfoA@KERNEL32.dll
0x0041b7b8:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0041b7bf:	pushl $0x40<UINT8>
0x0041b7c1:	pushl $0x20<UINT8>
0x0041b7c3:	popl %esi
0x0041b7c4:	pushl %esi
0x0041b7c5:	call 0x00419833
0x0041b7ca:	popl %ecx
0x0041b7cb:	popl %ecx
0x0041b7cc:	cmpl %eax, %edi
0x0041b7ce:	je 532
0x0041b7d4:	movl 0x4a7e60, %eax
0x0041b7d9:	movl 0x4a7e4c, %esi
0x0041b7df:	leal %ecx, 0x800(%eax)
0x0041b7e5:	jmp 0x0041b817
0x0041b817:	cmpl %eax, %ecx
0x0041b819:	jb 0x0041b7e7
0x0041b7e7:	movb 0x4(%eax), $0x0<UINT8>
0x0041b7eb:	orl (%eax), $0xffffffff<UINT8>
0x0041b7ee:	movb 0x5(%eax), $0xa<UINT8>
0x0041b7f2:	movl 0x8(%eax), %edi
0x0041b7f5:	movb 0x24(%eax), $0x0<UINT8>
0x0041b7f9:	movb 0x25(%eax), $0xa<UINT8>
0x0041b7fd:	movb 0x26(%eax), $0xa<UINT8>
0x0041b801:	movl 0x38(%eax), %edi
0x0041b804:	movb 0x34(%eax), $0x0<UINT8>
0x0041b808:	addl %eax, $0x40<UINT8>
0x0041b80b:	movl %ecx, 0x4a7e60
0x0041b811:	addl %ecx, $0x800<UINT32>
0x0041b81b:	cmpw -50(%ebp), %di
0x0041b81f:	je 266
0x0041b825:	movl %eax, -48(%ebp)
0x0041b828:	cmpl %eax, %edi
0x0041b82a:	je 255
0x0041b830:	movl %edi, (%eax)
0x0041b832:	leal %ebx, 0x4(%eax)
0x0041b835:	leal %eax, (%ebx,%edi)
0x0041b838:	movl -28(%ebp), %eax
0x0041b83b:	movl %esi, $0x800<UINT32>
0x0041b840:	cmpl %edi, %esi
0x0041b842:	jl 0x0041b846
0x0041b846:	movl -32(%ebp), $0x1<UINT32>
0x0041b84d:	jmp 0x0041b8aa
0x0041b8aa:	cmpl 0x4a7e4c, %edi
0x0041b8b0:	jl -99
0x0041b8b2:	jmp 0x0041b8ba
0x0041b8ba:	andl -32(%ebp), $0x0<UINT8>
0x0041b8be:	testl %edi, %edi
0x0041b8c0:	jle 0x0041b92f
0x0041b92f:	xorl %ebx, %ebx
0x0041b931:	movl %esi, %ebx
0x0041b933:	shll %esi, $0x6<UINT8>
0x0041b936:	addl %esi, 0x4a7e60
0x0041b93c:	movl %eax, (%esi)
0x0041b93e:	cmpl %eax, $0xffffffff<UINT8>
0x0041b941:	je 0x0041b94e
0x0041b94e:	movb 0x4(%esi), $0xffffff81<UINT8>
0x0041b952:	testl %ebx, %ebx
0x0041b954:	jne 0x0041b95b
0x0041b956:	pushl $0xfffffff6<UINT8>
0x0041b958:	popl %eax
0x0041b959:	jmp 0x0041b965
0x0041b965:	pushl %eax
0x0041b966:	call GetStdHandle@KERNEL32.dll
GetStdHandle@KERNEL32.dll: API Node	
0x0041b96c:	movl %edi, %eax
0x0041b96e:	cmpl %edi, $0xffffffff<UINT8>
0x0041b971:	je 67
0x0041b973:	testl %edi, %edi
0x0041b975:	je 63
0x0041b977:	pushl %edi
0x0041b978:	call GetFileType@KERNEL32.dll
GetFileType@KERNEL32.dll: API Node	
0x0041b97e:	testl %eax, %eax
0x0041b980:	je 52
0x0041b982:	movl (%esi), %edi
0x0041b984:	andl %eax, $0xff<UINT32>
0x0041b989:	cmpl %eax, $0x2<UINT8>
0x0041b98c:	jne 6
0x0041b98e:	orb 0x4(%esi), $0x40<UINT8>
0x0041b992:	jmp 0x0041b99d
0x0041b99d:	pushl $0xfa0<UINT32>
0x0041b9a2:	leal %eax, 0xc(%esi)
0x0041b9a5:	pushl %eax
0x0041b9a6:	call 0x0041f9fe
0x0041b9ab:	popl %ecx
0x0041b9ac:	popl %ecx
0x0041b9ad:	testl %eax, %eax
0x0041b9af:	je 55
0x0041b9b1:	incl 0x8(%esi)
0x0041b9b4:	jmp 0x0041b9c0
0x0041b9c0:	incl %ebx
0x0041b9c1:	cmpl %ebx, $0x3<UINT8>
0x0041b9c4:	jl 0x0041b931
0x0041b95b:	movl %eax, %ebx
0x0041b95d:	decl %eax
0x0041b95e:	negl %eax
0x0041b960:	sbbl %eax, %eax
0x0041b962:	addl %eax, $0xfffffff5<UINT8>
0x0041b9ca:	pushl 0x4a7e4c
0x0041b9d0:	call SetHandleCount@KERNEL32.dll
SetHandleCount@KERNEL32.dll: API Node	
0x0041b9d6:	xorl %eax, %eax
0x0041b9d8:	jmp 0x0041b9eb
0x0041b9eb:	call 0x00414d45
0x0041b9f0:	ret

0x00413a2e:	testl %eax, %eax
0x00413a30:	jnl 0x00413a3a
0x00413a3a:	call GetCommandLineA@KERNEL32.dll
GetCommandLineA@KERNEL32.dll: API Node	
0x00413a40:	movl 0x4a8fc8, %eax
0x00413a45:	call 0x0041f7d6
0x0041f7d6:	movl %edi, %edi
0x0041f7d8:	pushl %ebp
0x0041f7d9:	movl %ebp, %esp
0x0041f7db:	movl %eax, 0x4437f0
0x0041f7e0:	subl %esp, $0xc<UINT8>
0x0041f7e3:	pushl %ebx
0x0041f7e4:	pushl %esi
0x0041f7e5:	movl %esi, 0x432170
0x0041f7eb:	pushl %edi
0x0041f7ec:	xorl %ebx, %ebx
0x0041f7ee:	xorl %edi, %edi
0x0041f7f0:	cmpl %eax, %ebx
0x0041f7f2:	jne 46
0x0041f7f4:	call GetEnvironmentStringsW@KERNEL32.dll
GetEnvironmentStringsW@KERNEL32.dll: API Node	
0x0041f7f6:	movl %edi, %eax
0x0041f7f8:	cmpl %edi, %ebx
0x0041f7fa:	je 12
0x0041f7fc:	movl 0x4437f0, $0x1<UINT32>
0x0041f806:	jmp 0x0041f82b
0x0041f82b:	cmpl %edi, %ebx
0x0041f82d:	jne 0x0041f83e
0x0041f83e:	movl %eax, %edi
0x0041f840:	cmpw (%edi), %bx
0x0041f843:	je 14
0x0041f845:	incl %eax
0x0041f846:	incl %eax
0x0041f847:	cmpw (%eax), %bx
0x0041f84a:	jne 0x0041f845
0x0041f84c:	incl %eax
0x0041f84d:	incl %eax
0x0041f84e:	cmpw (%eax), %bx
0x0041f851:	jne 0x0041f845
0x0041f853:	movl %esi, 0x4321a0
0x0041f859:	pushl %ebx
0x0041f85a:	pushl %ebx
0x0041f85b:	pushl %ebx
0x0041f85c:	subl %eax, %edi
0x0041f85e:	pushl %ebx
0x0041f85f:	sarl %eax
0x0041f861:	incl %eax
0x0041f862:	pushl %eax
0x0041f863:	pushl %edi
0x0041f864:	pushl %ebx
0x0041f865:	pushl %ebx
0x0041f866:	movl -12(%ebp), %eax
0x0041f869:	call WideCharToMultiByte@KERNEL32.dll
WideCharToMultiByte@KERNEL32.dll: API Node	
0x0041f86b:	movl -8(%ebp), %eax
0x0041f86e:	cmpl %eax, %ebx
0x0041f870:	je 47
0x0041f872:	pushl %eax
0x0041f873:	call 0x004197ee
0x004197ee:	movl %edi, %edi
0x004197f0:	pushl %ebp
0x004197f1:	movl %ebp, %esp
0x004197f3:	pushl %esi
0x004197f4:	pushl %edi
0x004197f5:	xorl %esi, %esi
0x004197f7:	pushl 0x8(%ebp)
0x004197fa:	call 0x004109f1
0x004109f1:	movl %edi, %edi
0x004109f3:	pushl %ebp
0x004109f4:	movl %ebp, %esp
0x004109f6:	pushl %esi
0x004109f7:	movl %esi, 0x8(%ebp)
0x004109fa:	cmpl %esi, $0xffffffe0<UINT8>
0x004109fd:	ja 161
0x00410a03:	pushl %ebx
0x00410a04:	pushl %edi
0x00410a05:	movl %edi, 0x432114
0x00410a0b:	cmpl 0x443004, $0x0<UINT8>
0x00410a12:	jne 0x00410a2c
0x00410a2c:	movl %eax, 0x4a8fa4
0x00410a31:	cmpl %eax, $0x1<UINT8>
0x00410a34:	jne 14
0x00410a36:	testl %esi, %esi
0x00410a38:	je 4
0x00410a3a:	movl %eax, %esi
0x00410a3c:	jmp 0x00410a41
0x00410a41:	pushl %eax
0x00410a42:	jmp 0x00410a60
0x00410a60:	pushl $0x0<UINT8>
0x00410a62:	pushl 0x443004
0x00410a68:	call HeapAlloc@KERNEL32.dll
0x00410a6a:	movl %ebx, %eax
0x00410a6c:	testl %ebx, %ebx
0x00410a6e:	jne 0x00410a9e
0x00410a9e:	popl %edi
0x00410a9f:	movl %eax, %ebx
0x00410aa1:	popl %ebx
0x00410aa2:	jmp 0x00410ab8
0x00410ab8:	popl %esi
0x00410ab9:	popl %ebp
0x00410aba:	ret

0x004197ff:	movl %edi, %eax
0x00419801:	popl %ecx
0x00419802:	testl %edi, %edi
0x00419804:	jne 0x0041982d
0x0041982d:	movl %eax, %edi
0x0041982f:	popl %edi
0x00419830:	popl %esi
0x00419831:	popl %ebp
0x00419832:	ret

0x0041f878:	popl %ecx
0x0041f879:	movl -4(%ebp), %eax
0x0041f87c:	cmpl %eax, %ebx
0x0041f87e:	je 33
0x0041f880:	pushl %ebx
0x0041f881:	pushl %ebx
0x0041f882:	pushl -8(%ebp)
0x0041f885:	pushl %eax
0x0041f886:	pushl -12(%ebp)
0x0041f889:	pushl %edi
0x0041f88a:	pushl %ebx
0x0041f88b:	pushl %ebx
0x0041f88c:	call WideCharToMultiByte@KERNEL32.dll
0x0041f88e:	testl %eax, %eax
0x0041f890:	jne 0x0041f89e
0x0041f89e:	movl %ebx, -4(%ebp)
0x0041f8a1:	pushl %edi
0x0041f8a2:	call FreeEnvironmentStringsW@KERNEL32.dll
FreeEnvironmentStringsW@KERNEL32.dll: API Node	
0x0041f8a8:	movl %eax, %ebx
0x0041f8aa:	jmp 0x0041f908
0x0041f908:	popl %edi
0x0041f909:	popl %esi
0x0041f90a:	popl %ebx
0x0041f90b:	leave
0x0041f90c:	ret

0x00413a4a:	movl 0x442ea0, %eax
0x00413a4f:	call 0x0041f71b
0x0041f71b:	movl %edi, %edi
0x0041f71d:	pushl %ebp
0x0041f71e:	movl %ebp, %esp
0x0041f720:	subl %esp, $0xc<UINT8>
0x0041f723:	pushl %ebx
0x0041f724:	xorl %ebx, %ebx
0x0041f726:	pushl %esi
0x0041f727:	pushl %edi
0x0041f728:	cmpl 0x4a8f9c, %ebx
0x0041f72e:	jne 5
0x0041f730:	call 0x004176a0
0x004176a0:	cmpl 0x4a8f9c, $0x0<UINT8>
0x004176a7:	jne 18
0x004176a9:	pushl $0xfffffffd<UINT8>
0x004176ab:	call 0x00417506
0x00417506:	pushl $0x14<UINT8>
0x00417508:	pushl $0x4343c0<UINT32>
0x0041750d:	call 0x00414d00
0x00417512:	orl -32(%ebp), $0xffffffff<UINT8>
0x00417516:	call 0x00418c85
0x00418c85:	movl %edi, %edi
0x00418c87:	pushl %esi
0x00418c88:	call 0x00418c0c
0x00418c0c:	movl %edi, %edi
0x00418c0e:	pushl %esi
0x00418c0f:	pushl %edi
0x00418c10:	call GetLastError@KERNEL32.dll
GetLastError@KERNEL32.dll: API Node	
0x00418c16:	pushl 0x43c1a8
0x00418c1c:	movl %edi, %eax
0x00418c1e:	call 0x00418a97
0x00418a97:	movl %edi, %edi
0x00418a99:	pushl %esi
0x00418a9a:	pushl 0x43c1ac
0x00418aa0:	call TlsGetValue@KERNEL32.dll
0x00418aa6:	movl %esi, %eax
0x00418aa8:	testl %esi, %esi
0x00418aaa:	jne 0x00418ac7
0x00418ac7:	movl %eax, %esi
0x00418ac9:	popl %esi
0x00418aca:	ret

0x00418c23:	call FlsGetValue@KERNEL32.DLL
0x00418c25:	movl %esi, %eax
0x00418c27:	testl %esi, %esi
0x00418c29:	jne 0x00418c79
0x00418c79:	pushl %edi
0x00418c7a:	call SetLastError@KERNEL32.dll
SetLastError@KERNEL32.dll: API Node	
0x00418c80:	popl %edi
0x00418c81:	movl %eax, %esi
0x00418c83:	popl %esi
0x00418c84:	ret

0x00418c8d:	movl %esi, %eax
0x00418c8f:	testl %esi, %esi
0x00418c91:	jne 0x00418c9b
0x00418c9b:	movl %eax, %esi
0x00418c9d:	popl %esi
0x00418c9e:	ret

0x0041751b:	movl %edi, %eax
0x0041751d:	movl -36(%ebp), %edi
0x00417520:	call 0x004171c3
0x004171c3:	pushl $0xc<UINT8>
0x004171c5:	pushl $0x4343a0<UINT32>
0x004171ca:	call 0x00414d00
0x004171cf:	call 0x00418c85
0x004171d4:	movl %edi, %eax
0x004171d6:	movl %eax, 0x43c0b4
0x004171db:	testl 0x70(%edi), %eax
0x004171de:	je 0x004171fd
0x004171fd:	pushl $0xd<UINT8>
0x004171ff:	call 0x00413cac
0x00417204:	popl %ecx
0x00417205:	andl -4(%ebp), $0x0<UINT8>
0x00417209:	movl %esi, 0x68(%edi)
0x0041720c:	movl -28(%ebp), %esi
0x0041720f:	cmpl %esi, 0x43bfb8
0x00417215:	je 0x0041724d
0x0041724d:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00417254:	call 0x0041725e
0x0041725e:	pushl $0xd<UINT8>
0x00417260:	call 0x00413bba
0x00417265:	popl %ecx
0x00417266:	ret

0x00417259:	jmp 0x004171e9
0x004171e9:	testl %esi, %esi
0x004171eb:	jne 0x004171f5
0x004171f5:	movl %eax, %esi
0x004171f7:	call 0x00414d45
0x004171fc:	ret

0x00417525:	movl %ebx, 0x68(%edi)
0x00417528:	movl %esi, 0x8(%ebp)
0x0041752b:	call 0x00417267
0x00417267:	movl %edi, %edi
0x00417269:	pushl %ebp
0x0041726a:	movl %ebp, %esp
0x0041726c:	subl %esp, $0x10<UINT8>
0x0041726f:	pushl %ebx
0x00417270:	xorl %ebx, %ebx
0x00417272:	pushl %ebx
0x00417273:	leal %ecx, -16(%ebp)
0x00417276:	call 0x004111f1
0x004111f1:	movl %edi, %edi
0x004111f3:	pushl %ebp
0x004111f4:	movl %ebp, %esp
0x004111f6:	movl %eax, 0x8(%ebp)
0x004111f9:	pushl %esi
0x004111fa:	movl %esi, %ecx
0x004111fc:	movb 0xc(%esi), $0x0<UINT8>
0x00411200:	testl %eax, %eax
0x00411202:	jne 99
0x00411204:	call 0x00418c85
0x00411209:	movl 0x8(%esi), %eax
0x0041120c:	movl %ecx, 0x6c(%eax)
0x0041120f:	movl (%esi), %ecx
0x00411211:	movl %ecx, 0x68(%eax)
0x00411214:	movl 0x4(%esi), %ecx
0x00411217:	movl %ecx, (%esi)
0x00411219:	cmpl %ecx, 0x43c198
0x0041121f:	je 0x00411233
0x00411233:	movl %eax, 0x4(%esi)
0x00411236:	cmpl %eax, 0x43bfb8
0x0041123c:	je 0x00411254
0x00411254:	movl %eax, 0x8(%esi)
0x00411257:	testb 0x70(%eax), $0x2<UINT8>
0x0041125b:	jne 20
0x0041125d:	orl 0x70(%eax), $0x2<UINT8>
0x00411261:	movb 0xc(%esi), $0x1<UINT8>
0x00411265:	jmp 0x00411271
0x00411271:	movl %eax, %esi
0x00411273:	popl %esi
0x00411274:	popl %ebp
0x00411275:	ret $0x4<UINT16>

0x0041727b:	movl 0x443684, %ebx
0x00417281:	cmpl %esi, $0xfffffffe<UINT8>
0x00417284:	jne 0x004172a4
0x004172a4:	cmpl %esi, $0xfffffffd<UINT8>
0x004172a7:	jne 0x004172bb
0x004172a9:	movl 0x443684, $0x1<UINT32>
0x004172b3:	call GetACP@KERNEL32.dll
GetACP@KERNEL32.dll: API Node	
0x004172b9:	jmp 0x00417296
0x00417296:	cmpb -4(%ebp), %bl
0x00417299:	je 69
0x0041729b:	movl %ecx, -8(%ebp)
0x0041729e:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x004172a2:	jmp 0x004172e0
0x004172e0:	popl %ebx
0x004172e1:	leave
0x004172e2:	ret

0x00417530:	movl 0x8(%ebp), %eax
0x00417533:	cmpl %eax, 0x4(%ebx)
0x00417536:	je 343
0x0041753c:	pushl $0x220<UINT32>
0x00417541:	call 0x004197ee
0x00417546:	popl %ecx
0x00417547:	movl %ebx, %eax
0x00417549:	testl %ebx, %ebx
0x0041754b:	je 326
0x00417551:	movl %ecx, $0x88<UINT32>
0x00417556:	movl %esi, 0x68(%edi)
0x00417559:	movl %edi, %ebx
0x0041755b:	rep movsl %es:(%edi), %ds:(%esi)
0x0041755d:	andl (%ebx), $0x0<UINT8>
0x00417560:	pushl %ebx
0x00417561:	pushl 0x8(%ebp)
0x00417564:	call 0x004172e3
0x004172e3:	movl %edi, %edi
0x004172e5:	pushl %ebp
0x004172e6:	movl %ebp, %esp
0x004172e8:	subl %esp, $0x20<UINT8>
0x004172eb:	movl %eax, 0x43b810
0x004172f0:	xorl %eax, %ebp
0x004172f2:	movl -4(%ebp), %eax
0x004172f5:	pushl %ebx
0x004172f6:	movl %ebx, 0xc(%ebp)
0x004172f9:	pushl %esi
0x004172fa:	movl %esi, 0x8(%ebp)
0x004172fd:	pushl %edi
0x004172fe:	call 0x00417267
0x004172bb:	cmpl %esi, $0xfffffffc<UINT8>
0x004172be:	jne 0x004172d2
0x004172d2:	cmpb -4(%ebp), %bl
0x004172d5:	je 7
0x004172d7:	movl %eax, -8(%ebp)
0x004172da:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x004172de:	movl %eax, %esi
0x00417303:	movl %edi, %eax
0x00417305:	xorl %esi, %esi
0x00417307:	movl 0x8(%ebp), %edi
0x0041730a:	cmpl %edi, %esi
0x0041730c:	jne 0x0041731c
0x0041731c:	movl -28(%ebp), %esi
0x0041731f:	xorl %eax, %eax
0x00417321:	cmpl 0x43bfc0(%eax), %edi
0x00417327:	je 145
0x0041732d:	incl -28(%ebp)
0x00417330:	addl %eax, $0x30<UINT8>
0x00417333:	cmpl %eax, $0xf0<UINT32>
0x00417338:	jb 0x00417321
0x0041733a:	cmpl %edi, $0xfde8<UINT32>
0x00417340:	je 368
0x00417346:	cmpl %edi, $0xfde9<UINT32>
0x0041734c:	je 356
0x00417352:	movzwl %eax, %di
0x00417355:	pushl %eax
0x00417356:	call IsValidCodePage@KERNEL32.dll
IsValidCodePage@KERNEL32.dll: API Node	
0x0041735c:	testl %eax, %eax
0x0041735e:	je 338
0x00417364:	leal %eax, -24(%ebp)
0x00417367:	pushl %eax
0x00417368:	pushl %edi
0x00417369:	call GetCPInfo@KERNEL32.dll
GetCPInfo@KERNEL32.dll: API Node	
0x0041736f:	testl %eax, %eax
0x00417371:	je 307
0x00417377:	pushl $0x101<UINT32>
0x0041737c:	leal %eax, 0x1c(%ebx)
0x0041737f:	pushl %esi
0x00417380:	pushl %eax
0x00417381:	call 0x00411110
0x00411110:	movl %edx, 0xc(%esp)
0x00411114:	movl %ecx, 0x4(%esp)
0x00411118:	testl %edx, %edx
0x0041111a:	je 105
0x0041111c:	xorl %eax, %eax
0x0041111e:	movb %al, 0x8(%esp)
0x00411122:	testb %al, %al
0x00411124:	jne 22
0x00411126:	cmpl %edx, $0x100<UINT32>
0x0041112c:	jb 14
0x0041112e:	cmpl 0x4a8f8c, $0x0<UINT8>
0x00411135:	je 0x0041113c
0x0041113c:	pushl %edi
0x0041113d:	movl %edi, %ecx
0x0041113f:	cmpl %edx, $0x4<UINT8>
0x00411142:	jb 49
0x00411144:	negl %ecx
0x00411146:	andl %ecx, $0x3<UINT8>
0x00411149:	je 0x00411157
0x00411157:	movl %ecx, %eax
0x00411159:	shll %eax, $0x8<UINT8>
0x0041115c:	addl %eax, %ecx
0x0041115e:	movl %ecx, %eax
0x00411160:	shll %eax, $0x10<UINT8>
0x00411163:	addl %eax, %ecx
0x00411165:	movl %ecx, %edx
0x00411167:	andl %edx, $0x3<UINT8>
0x0041116a:	shrl %ecx, $0x2<UINT8>
0x0041116d:	je 6
0x0041116f:	rep stosl %es:(%edi), %eax
0x00411171:	testl %edx, %edx
0x00411173:	je 10
0x00411175:	movb (%edi), %al
0x00411177:	addl %edi, $0x1<UINT8>
0x0041117a:	subl %edx, $0x1<UINT8>
0x0041117d:	jne -10
0x0041117f:	movl %eax, 0x8(%esp)
0x00411183:	popl %edi
0x00411184:	ret

0x00417386:	xorl %edx, %edx
0x00417388:	incl %edx
0x00417389:	addl %esp, $0xc<UINT8>
0x0041738c:	movl 0x4(%ebx), %edi
0x0041738f:	movl 0xc(%ebx), %esi
0x00417392:	cmpl -24(%ebp), %edx
0x00417395:	jbe 248
0x0041739b:	cmpb -18(%ebp), $0x0<UINT8>
0x0041739f:	je 0x00417474
0x00417474:	leal %eax, 0x1e(%ebx)
0x00417477:	movl %ecx, $0xfe<UINT32>
0x0041747c:	orb (%eax), $0x8<UINT8>
0x0041747f:	incl %eax
0x00417480:	decl %ecx
0x00417481:	jne 0x0041747c
0x00417483:	movl %eax, 0x4(%ebx)
0x00417486:	call 0x00416f9d
0x00416f9d:	subl %eax, $0x3a4<UINT32>
0x00416fa2:	je 34
0x00416fa4:	subl %eax, $0x4<UINT8>
0x00416fa7:	je 23
0x00416fa9:	subl %eax, $0xd<UINT8>
0x00416fac:	je 12
0x00416fae:	decl %eax
0x00416faf:	je 3
0x00416fb1:	xorl %eax, %eax
0x00416fb3:	ret

0x0041748b:	movl 0xc(%ebx), %eax
0x0041748e:	movl 0x8(%ebx), %edx
0x00417491:	jmp 0x00417496
0x00417496:	xorl %eax, %eax
0x00417498:	movzwl %ecx, %ax
0x0041749b:	movl %eax, %ecx
0x0041749d:	shll %ecx, $0x10<UINT8>
0x004174a0:	orl %eax, %ecx
0x004174a2:	leal %edi, 0x10(%ebx)
0x004174a5:	stosl %es:(%edi), %eax
0x004174a6:	stosl %es:(%edi), %eax
0x004174a7:	stosl %es:(%edi), %eax
0x004174a8:	jmp 0x00417452
0x00417452:	movl %esi, %ebx
0x00417454:	call 0x00417030
0x00417030:	movl %edi, %edi
0x00417032:	pushl %ebp
0x00417033:	movl %ebp, %esp
0x00417035:	subl %esp, $0x51c<UINT32>
0x0041703b:	movl %eax, 0x43b810
0x00417040:	xorl %eax, %ebp
0x00417042:	movl -4(%ebp), %eax
0x00417045:	pushl %ebx
0x00417046:	pushl %edi
0x00417047:	leal %eax, -1304(%ebp)
0x0041704d:	pushl %eax
0x0041704e:	pushl 0x4(%esi)
0x00417051:	call GetCPInfo@KERNEL32.dll
0x00417057:	movl %edi, $0x100<UINT32>
0x0041705c:	testl %eax, %eax
0x0041705e:	je 251
0x00417064:	xorl %eax, %eax
0x00417066:	movb -260(%ebp,%eax), %al
0x0041706d:	incl %eax
0x0041706e:	cmpl %eax, %edi
0x00417070:	jb 0x00417066
0x00417072:	movb %al, -1298(%ebp)
0x00417078:	movb -260(%ebp), $0x20<UINT8>
0x0041707f:	testb %al, %al
0x00417081:	je 0x004170b1
0x004170b1:	pushl $0x0<UINT8>
0x004170b3:	pushl 0xc(%esi)
0x004170b6:	leal %eax, -1284(%ebp)
0x004170bc:	pushl 0x4(%esi)
0x004170bf:	pushl %eax
0x004170c0:	pushl %edi
0x004170c1:	leal %eax, -260(%ebp)
0x004170c7:	pushl %eax
0x004170c8:	pushl $0x1<UINT8>
0x004170ca:	pushl $0x0<UINT8>
0x004170cc:	call 0x00423653
0x00423653:	movl %edi, %edi
0x00423655:	pushl %ebp
0x00423656:	movl %ebp, %esp
0x00423658:	subl %esp, $0x10<UINT8>
0x0042365b:	pushl 0x8(%ebp)
0x0042365e:	leal %ecx, -16(%ebp)
0x00423661:	call 0x004111f1
0x00423666:	pushl 0x24(%ebp)
0x00423669:	leal %ecx, -16(%ebp)
0x0042366c:	pushl 0x20(%ebp)
0x0042366f:	pushl 0x1c(%ebp)
0x00423672:	pushl 0x18(%ebp)
0x00423675:	pushl 0x14(%ebp)
0x00423678:	pushl 0x10(%ebp)
0x0042367b:	pushl 0xc(%ebp)
0x0042367e:	call 0x00423499
0x00423499:	movl %edi, %edi
0x0042349b:	pushl %ebp
0x0042349c:	movl %ebp, %esp
0x0042349e:	pushl %ecx
0x0042349f:	pushl %ecx
0x004234a0:	movl %eax, 0x43b810
0x004234a5:	xorl %eax, %ebp
0x004234a7:	movl -4(%ebp), %eax
0x004234aa:	movl %eax, 0x443838
0x004234af:	pushl %ebx
0x004234b0:	pushl %esi
0x004234b1:	xorl %ebx, %ebx
0x004234b3:	pushl %edi
0x004234b4:	movl %edi, %ecx
0x004234b6:	cmpl %eax, %ebx
0x004234b8:	jne 58
0x004234ba:	leal %eax, -8(%ebp)
0x004234bd:	pushl %eax
0x004234be:	xorl %esi, %esi
0x004234c0:	incl %esi
0x004234c1:	pushl %esi
0x004234c2:	pushl $0x432d44<UINT32>
0x004234c7:	pushl %esi
0x004234c8:	call GetStringTypeW@KERNEL32.dll
GetStringTypeW@KERNEL32.dll: API Node	
0x004234ce:	testl %eax, %eax
0x004234d0:	je 8
0x004234d2:	movl 0x443838, %esi
0x004234d8:	jmp 0x0042350e
0x0042350e:	movl -8(%ebp), %ebx
0x00423511:	cmpl 0x18(%ebp), %ebx
0x00423514:	jne 0x0042351e
0x0042351e:	movl %esi, 0x43219c
0x00423524:	xorl %eax, %eax
0x00423526:	cmpl 0x20(%ebp), %ebx
0x00423529:	pushl %ebx
0x0042352a:	pushl %ebx
0x0042352b:	pushl 0x10(%ebp)
0x0042352e:	setne %al
0x00423531:	pushl 0xc(%ebp)
0x00423534:	leal %eax, 0x1(,%eax,8)
0x0042353b:	pushl %eax
0x0042353c:	pushl 0x18(%ebp)
0x0042353f:	call MultiByteToWideChar@KERNEL32.dll
MultiByteToWideChar@KERNEL32.dll: API Node	
0x00423541:	movl %edi, %eax
0x00423543:	cmpl %edi, %ebx
0x00423545:	je 171
0x0042354b:	jle 60
0x0042354d:	cmpl %edi, $0x7ffffff0<UINT32>
0x00423553:	ja 52
0x00423555:	leal %eax, 0x8(%edi,%edi)
0x00423559:	cmpl %eax, $0x400<UINT32>
0x0042355e:	ja 19
0x00423560:	call 0x0041b5c0
0x0041b5c0:	pushl %ecx
0x0041b5c1:	leal %ecx, 0x8(%esp)
0x0041b5c5:	subl %ecx, %eax
0x0041b5c7:	andl %ecx, $0xf<UINT8>
0x0041b5ca:	addl %eax, %ecx
0x0041b5cc:	sbbl %ecx, %ecx
0x0041b5ce:	orl %eax, %ecx
0x0041b5d0:	popl %ecx
0x0041b5d1:	jmp 0x00411670
0x00411670:	pushl %ecx
0x00411671:	leal %ecx, 0x4(%esp)
0x00411675:	subl %ecx, %eax
0x00411677:	sbbl %eax, %eax
0x00411679:	notl %eax
0x0041167b:	andl %ecx, %eax
0x0041167d:	movl %eax, %esp
0x0041167f:	andl %eax, $0xfffff000<UINT32>
0x00411684:	cmpl %ecx, %eax
0x00411686:	jb 10
0x00411688:	movl %eax, %ecx
0x0041168a:	popl %ecx
0x0041168b:	xchgl %esp, %eax
0x0041168c:	movl %eax, (%eax)
0x0041168e:	movl (%esp), %eax
0x00411691:	ret

0x00423565:	movl %eax, %esp
0x00423567:	cmpl %eax, %ebx
0x00423569:	je 28
0x0042356b:	movl (%eax), $0xcccc<UINT32>
0x00423571:	jmp 0x00423584
0x00423584:	addl %eax, $0x8<UINT8>
0x00423587:	movl %ebx, %eax
0x00423589:	testl %ebx, %ebx
0x0042358b:	je 105
0x0042358d:	leal %eax, (%edi,%edi)
0x00423590:	pushl %eax
0x00423591:	pushl $0x0<UINT8>
0x00423593:	pushl %ebx
0x00423594:	call 0x00411110
