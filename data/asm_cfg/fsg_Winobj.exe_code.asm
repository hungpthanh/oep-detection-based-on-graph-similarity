0x00530000:	movl %ebx, $0x4001d0<UINT32>
0x00530005:	movl %edi, $0x401000<UINT32>
0x0053000a:	movl %esi, $0x4c0868<UINT32>
0x0053000f:	pushl %ebx
0x00530010:	call 0x0053001f
0x0053001f:	cld
0x00530020:	movb %dl, $0xffffff80<UINT8>
0x00530022:	movsb %es:(%edi), %ds:(%esi)
0x00530023:	pushl $0x2<UINT8>
0x00530025:	popl %ebx
0x00530026:	call 0x00530015
0x00530015:	addb %dl, %dl
0x00530017:	jne 0x0053001e
0x00530019:	movb %dl, (%esi)
0x0053001b:	incl %esi
0x0053001c:	adcb %dl, %dl
0x0053001e:	ret

0x00530029:	jae 0x00530022
0x0053002b:	xorl %ecx, %ecx
0x0053002d:	call 0x00530015
0x00530030:	jae 0x0053004a
0x00530032:	xorl %eax, %eax
0x00530034:	call 0x00530015
0x00530037:	jae 0x0053005a
0x00530039:	movb %bl, $0x2<UINT8>
0x0053003b:	incl %ecx
0x0053003c:	movb %al, $0x10<UINT8>
0x0053003e:	call 0x00530015
0x00530041:	adcb %al, %al
0x00530043:	jae 0x0053003e
0x00530045:	jne 0x00530086
0x00530086:	pushl %esi
0x00530087:	movl %esi, %edi
0x00530089:	subl %esi, %eax
0x0053008b:	rep movsb %es:(%edi), %ds:(%esi)
0x0053008d:	popl %esi
0x0053008e:	jmp 0x00530026
0x00530047:	stosb %es:(%edi), %al
0x00530048:	jmp 0x00530026
0x0053005a:	lodsb %al, %ds:(%esi)
0x0053005b:	shrl %eax
0x0053005d:	je 0x005300a0
0x0053005f:	adcl %ecx, %ecx
0x00530061:	jmp 0x0053007f
0x0053007f:	incl %ecx
0x00530080:	incl %ecx
0x00530081:	xchgl %ebp, %eax
0x00530082:	movl %eax, %ebp
0x00530084:	movb %bl, $0x1<UINT8>
0x0053004a:	call 0x00530092
0x00530092:	incl %ecx
0x00530093:	call 0x00530015
0x00530097:	adcl %ecx, %ecx
0x00530099:	call 0x00530015
0x0053009d:	jb 0x00530093
0x0053009f:	ret

0x0053004f:	subl %ecx, %ebx
0x00530051:	jne 0x00530063
0x00530053:	call 0x00530090
0x00530090:	xorl %ecx, %ecx
0x00530058:	jmp 0x00530082
0x00530063:	xchgl %ecx, %eax
0x00530064:	decl %eax
0x00530065:	shll %eax, $0x8<UINT8>
0x00530068:	lodsb %al, %ds:(%esi)
0x00530069:	call 0x00530090
0x0053006e:	cmpl %eax, $0x7d00<UINT32>
0x00530073:	jae 0x0053007f
0x00530075:	cmpb %ah, $0x5<UINT8>
0x00530078:	jae 0x00530080
0x0053007a:	cmpl %eax, $0x7f<UINT8>
0x0053007d:	ja 0x00530081
0x005300a0:	popl %edi
0x005300a1:	popl %ebx
0x005300a2:	movzwl %edi, (%ebx)
0x005300a5:	decl %edi
0x005300a6:	je 0x005300b0
0x005300a8:	decl %edi
0x005300a9:	je 0x005300be
0x005300ab:	shll %edi, $0xc<UINT8>
0x005300ae:	jmp 0x005300b7
0x005300b7:	incl %ebx
0x005300b8:	incl %ebx
0x005300b9:	jmp 0x0053000f
0x005300b0:	movl %edi, 0x2(%ebx)
0x005300b3:	pushl %edi
0x005300b4:	addl %ebx, $0x4<UINT8>
0x005300be:	popl %edi
0x005300bf:	movl %ebx, $0x530128<UINT32>
0x005300c4:	incl %edi
0x005300c5:	movl %esi, (%edi)
0x005300c7:	scasl %eax, %es:(%edi)
0x005300c8:	pushl %edi
0x005300c9:	call LoadLibraryA@KERNEL32.dll
LoadLibraryA@kernel32.dll: API Node	
0x005300cb:	xchgl %ebp, %eax
0x005300cc:	xorl %eax, %eax
0x005300ce:	scasb %al, %es:(%edi)
0x005300cf:	jne 0x005300ce
0x005300d1:	decb (%edi)
0x005300d3:	je 0x005300c4
0x005300d5:	decb (%edi)
0x005300d7:	jne 0x005300df
0x005300df:	decb (%edi)
0x005300e1:	je 0x00407a69
0x005300e7:	pushl %edi
0x005300e8:	pushl %ebp
0x005300e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x005300ec:	orl (%esi), %eax
0x005300ee:	lodsl %eax, %ds:(%esi)
0x005300ef:	jne 0x005300cc
0x005300d9:	incl %edi
0x005300da:	pushl (%edi)
0x005300dc:	scasl %eax, %es:(%edi)
0x005300dd:	jmp 0x005300e8
GetProcAddress@KERNEL32.dll: API Node	
LoadLibraryA@KERNEL32.dll: API Node	
0x00407a69:	call 0x0040e427
0x0040e427:	movl %edi, %edi
0x0040e429:	pushl %ebp
0x0040e42a:	movl %ebp, %esp
0x0040e42c:	subl %esp, $0x10<UINT8>
0x0040e42f:	movl %eax, 0x42c8e0
0x0040e434:	andl -8(%ebp), $0x0<UINT8>
0x0040e438:	andl -4(%ebp), $0x0<UINT8>
0x0040e43c:	pushl %ebx
0x0040e43d:	pushl %edi
0x0040e43e:	movl %edi, $0xbb40e64e<UINT32>
0x0040e443:	movl %ebx, $0xffff0000<UINT32>
0x0040e448:	cmpl %eax, %edi
0x0040e44a:	je 0x0040e459
0x0040e459:	pushl %esi
0x0040e45a:	leal %eax, -8(%ebp)
0x0040e45d:	pushl %eax
0x0040e45e:	call GetSystemTimeAsFileTime@KERNEL32.dll
GetSystemTimeAsFileTime@KERNEL32.dll: API Node	
0x0040e464:	movl %esi, -4(%ebp)
0x0040e467:	xorl %esi, -8(%ebp)
0x0040e46a:	call GetCurrentProcessId@KERNEL32.dll
GetCurrentProcessId@KERNEL32.dll: API Node	
0x0040e470:	xorl %esi, %eax
0x0040e472:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x0040e478:	xorl %esi, %eax
0x0040e47a:	call GetTickCount@KERNEL32.dll
GetTickCount@KERNEL32.dll: API Node	
0x0040e480:	xorl %esi, %eax
0x0040e482:	leal %eax, -16(%ebp)
0x0040e485:	pushl %eax
0x0040e486:	call QueryPerformanceCounter@KERNEL32.dll
QueryPerformanceCounter@KERNEL32.dll: API Node	
0x0040e48c:	movl %eax, -12(%ebp)
0x0040e48f:	xorl %eax, -16(%ebp)
0x0040e492:	xorl %esi, %eax
0x0040e494:	cmpl %esi, %edi
0x0040e496:	jne 0x0040e49f
0x0040e49f:	testl %ebx, %esi
0x0040e4a1:	jne 0x0040e4aa
0x0040e4aa:	movl 0x42c8e0, %esi
0x0040e4b0:	notl %esi
0x0040e4b2:	movl 0x42c8e4, %esi
0x0040e4b8:	popl %esi
0x0040e4b9:	popl %edi
0x0040e4ba:	popl %ebx
0x0040e4bb:	leave
0x0040e4bc:	ret

0x00407a6e:	jmp 0x004078eb
0x004078eb:	pushl $0x58<UINT8>
0x004078ed:	pushl $0x429f58<UINT32>
0x004078f2:	call 0x004096c4
0x004096c4:	pushl $0x409750<UINT32>
0x004096c9:	pushl %fs:0
0x004096d0:	movl %eax, 0x10(%esp)
0x004096d4:	movl 0x10(%esp), %ebp
0x004096d8:	leal %ebp, 0x10(%esp)
0x004096dc:	subl %esp, %eax
0x004096de:	pushl %ebx
0x004096df:	pushl %esi
0x004096e0:	pushl %edi
0x004096e1:	movl %eax, 0x42c8e0
0x004096e6:	xorl -4(%ebp), %eax
0x004096e9:	xorl %eax, %ebp
0x004096eb:	pushl %eax
0x004096ec:	movl -24(%ebp), %esp
0x004096ef:	pushl -8(%ebp)
0x004096f2:	movl %eax, -4(%ebp)
0x004096f5:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004096fc:	movl -8(%ebp), %eax
0x004096ff:	leal %eax, -16(%ebp)
0x00409702:	movl %fs:0, %eax
0x00409708:	ret

0x004078f7:	xorl %esi, %esi
0x004078f9:	movl -4(%ebp), %esi
0x004078fc:	leal %eax, -104(%ebp)
0x004078ff:	pushl %eax
0x00407900:	call GetStartupInfoA@KERNEL32.dll
GetStartupInfoA@KERNEL32.dll: API Node	
0x00407906:	pushl $0xfffffffe<UINT8>
0x00407908:	popl %edi
0x00407909:	movl -4(%ebp), %edi
0x0040790c:	movl %eax, $0x5a4d<UINT32>
0x00407911:	cmpw 0x400000, %ax
0x00407918:	jne 56
0x0040791a:	movl %eax, 0x40003c
0x0040791f:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00407929:	jne 39
0x0040792b:	movl %ecx, $0x10b<UINT32>
0x00407930:	cmpw 0x400018(%eax), %cx
0x00407937:	jne 25
0x00407939:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00407940:	jbe 16
0x00407942:	xorl %ecx, %ecx
0x00407944:	cmpl 0x4000e8(%eax), %esi
0x0040794a:	setne %cl
0x0040794d:	movl -28(%ebp), %ecx
0x00407950:	jmp 0x00407955
0x00407955:	xorl %ebx, %ebx
0x00407957:	incl %ebx
0x00407958:	pushl %ebx
0x00407959:	call 0x004098e0
0x004098e0:	movl %edi, %edi
0x004098e2:	pushl %ebp
0x004098e3:	movl %ebp, %esp
0x004098e5:	xorl %eax, %eax
0x004098e7:	cmpl 0x8(%ebp), %eax
0x004098ea:	pushl $0x0<UINT8>
0x004098ec:	sete %al
0x004098ef:	pushl $0x1000<UINT32>
0x004098f4:	pushl %eax
0x004098f5:	call HeapCreate@KERNEL32.dll
HeapCreate@KERNEL32.dll: API Node	
0x004098fb:	movl 0x43045c, %eax
0x00409900:	testl %eax, %eax
0x00409902:	jne 0x00409906
0x00409906:	xorl %eax, %eax
0x00409908:	incl %eax
0x00409909:	movl 0x438880, %eax
0x0040990e:	popl %ebp
0x0040990f:	ret

0x0040795e:	popl %ecx
0x0040795f:	testl %eax, %eax
0x00407961:	jne 0x0040796b
0x0040796b:	call 0x0040d5bc
0x0040d5bc:	movl %edi, %edi
0x0040d5be:	pushl %esi
0x0040d5bf:	pushl %edi
0x0040d5c0:	movl %esi, $0x427d94<UINT32>
0x0040d5c5:	pushl %esi
0x0040d5c6:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x0040d5cc:	testl %eax, %eax
0x0040d5ce:	jne 0x0040d5d7
0x0040d5d7:	movl %edi, %eax
0x0040d5d9:	testl %edi, %edi
0x0040d5db:	je 350
0x0040d5e1:	movl %esi, 0x4231e4
0x0040d5e7:	pushl $0x427de0<UINT32>
0x0040d5ec:	pushl %edi
0x0040d5ed:	call GetProcAddress@KERNEL32.dll
0x0040d5ef:	pushl $0x427dd4<UINT32>
0x0040d5f4:	pushl %edi
0x0040d5f5:	movl 0x430b1c, %eax
0x0040d5fa:	call GetProcAddress@KERNEL32.dll
0x0040d5fc:	pushl $0x427dc8<UINT32>
0x0040d601:	pushl %edi
0x0040d602:	movl 0x430b20, %eax
0x0040d607:	call GetProcAddress@KERNEL32.dll
0x0040d609:	pushl $0x427dc0<UINT32>
0x0040d60e:	pushl %edi
0x0040d60f:	movl 0x430b24, %eax
0x0040d614:	call GetProcAddress@KERNEL32.dll
0x0040d616:	cmpl 0x430b1c, $0x0<UINT8>
0x0040d61d:	movl %esi, 0x423164
0x0040d623:	movl 0x430b28, %eax
0x0040d628:	je 22
0x0040d62a:	cmpl 0x430b20, $0x0<UINT8>
0x0040d631:	je 13
0x0040d633:	cmpl 0x430b24, $0x0<UINT8>
0x0040d63a:	je 4
0x0040d63c:	testl %eax, %eax
0x0040d63e:	jne 0x0040d664
0x0040d664:	call TlsAlloc@KERNEL32.dll
TlsAlloc@KERNEL32.dll: API Node	
0x0040d66a:	movl 0x42d2dc, %eax
0x0040d66f:	cmpl %eax, $0xffffffff<UINT8>
0x0040d672:	je 204
0x0040d678:	pushl 0x430b20
0x0040d67e:	pushl %eax
0x0040d67f:	call TlsSetValue@KERNEL32.dll
TlsSetValue@KERNEL32.dll: API Node	
0x0040d681:	testl %eax, %eax
0x0040d683:	je 187
0x0040d689:	call 0x00409cec
0x00409cec:	movl %edi, %edi
0x00409cee:	pushl %esi
0x00409cef:	call 0x0040d167
0x0040d167:	pushl $0x0<UINT8>
0x0040d169:	call 0x0040d0f5
0x0040d0f5:	movl %edi, %edi
0x0040d0f7:	pushl %ebp
0x0040d0f8:	movl %ebp, %esp
0x0040d0fa:	pushl %esi
0x0040d0fb:	pushl 0x42d2dc
0x0040d101:	movl %esi, 0x42316c
0x0040d107:	call TlsGetValue@KERNEL32.dll
TlsGetValue@KERNEL32.dll: API Node	
0x0040d109:	testl %eax, %eax
0x0040d10b:	je 33
0x0040d10d:	movl %eax, 0x42d2d8
0x0040d112:	cmpl %eax, $0xffffffff<UINT8>
0x0040d115:	je 0x0040d12e
0x0040d12e:	movl %esi, $0x427d94<UINT32>
0x0040d133:	pushl %esi
0x0040d134:	call GetModuleHandleW@KERNEL32.dll
0x0040d13a:	testl %eax, %eax
0x0040d13c:	jne 0x0040d149
0x0040d149:	pushl $0x427d84<UINT32>
0x0040d14e:	pushl %eax
0x0040d14f:	call GetProcAddress@KERNEL32.dll
0x0040d155:	testl %eax, %eax
0x0040d157:	je 8
0x0040d159:	pushl 0x8(%ebp)
0x0040d15c:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x0040d15e:	movl 0x8(%ebp), %eax
0x0040d161:	movl %eax, 0x8(%ebp)
0x0040d164:	popl %esi
0x0040d165:	popl %ebp
0x0040d166:	ret

0x0040d16e:	popl %ecx
0x0040d16f:	ret

0x00409cf4:	movl %esi, %eax
0x00409cf6:	pushl %esi
0x00409cf7:	call 0x00408269
0x00408269:	movl %edi, %edi
0x0040826b:	pushl %ebp
0x0040826c:	movl %ebp, %esp
0x0040826e:	movl %eax, 0x8(%ebp)
0x00408271:	movl 0x430300, %eax
0x00408276:	popl %ebp
0x00408277:	ret

0x00409cfc:	pushl %esi
0x00409cfd:	call 0x00413b92
0x00413b92:	movl %edi, %edi
0x00413b94:	pushl %ebp
0x00413b95:	movl %ebp, %esp
0x00413b97:	movl %eax, 0x8(%ebp)
0x00413b9a:	movl 0x430cb0, %eax
0x00413b9f:	popl %ebp
0x00413ba0:	ret

0x00409d02:	pushl %esi
0x00409d03:	call 0x0040afb5
0x0040afb5:	movl %edi, %edi
0x0040afb7:	pushl %ebp
0x0040afb8:	movl %ebp, %esp
0x0040afba:	movl %eax, 0x8(%ebp)
0x0040afbd:	movl 0x4307b0, %eax
0x0040afc2:	popl %ebp
0x0040afc3:	ret

0x00409d08:	pushl %esi
0x00409d09:	call 0x00414915
0x00414915:	movl %edi, %edi
0x00414917:	pushl %ebp
0x00414918:	movl %ebp, %esp
0x0041491a:	movl %eax, 0x8(%ebp)
0x0041491d:	movl 0x430cd8, %eax
0x00414922:	popl %ebp
0x00414923:	ret

0x00409d0e:	pushl %esi
0x00409d0f:	call 0x0041467f
0x0041467f:	movl %edi, %edi
0x00414681:	pushl %ebp
0x00414682:	movl %ebp, %esp
0x00414684:	movl %eax, 0x8(%ebp)
0x00414687:	movl 0x430ccc, %eax
0x0041468c:	popl %ebp
0x0041468d:	ret

0x00409d14:	pushl %esi
0x00409d15:	call 0x00414183
0x00414183:	movl %edi, %edi
0x00414185:	pushl %ebp
0x00414186:	movl %ebp, %esp
0x00414188:	movl %eax, 0x8(%ebp)
0x0041418b:	movl 0x430cb8, %eax
0x00414190:	movl 0x430cbc, %eax
0x00414195:	movl 0x430cc0, %eax
0x0041419a:	movl 0x430cc4, %eax
0x0041419f:	popl %ebp
0x004141a0:	ret

0x00409d1a:	pushl %esi
0x00409d1b:	call 0x0040daab
0x0040daab:	ret

0x00409d20:	pushl %esi
0x00409d21:	call 0x00414172
0x00414172:	pushl $0x4140ee<UINT32>
0x00414177:	call 0x0040d0f5
0x0041417c:	popl %ecx
0x0041417d:	movl 0x430cb4, %eax
0x00414182:	ret

0x00409d26:	pushl $0x409cb8<UINT32>
0x00409d2b:	call 0x0040d0f5
0x00409d30:	addl %esp, $0x24<UINT8>
0x00409d33:	movl 0x42ca8c, %eax
0x00409d38:	popl %esi
0x00409d39:	ret

0x0040d68e:	pushl 0x430b1c
0x0040d694:	call 0x0040d0f5
0x0040d699:	pushl 0x430b20
0x0040d69f:	movl 0x430b1c, %eax
0x0040d6a4:	call 0x0040d0f5
0x0040d6a9:	pushl 0x430b24
0x0040d6af:	movl 0x430b20, %eax
0x0040d6b4:	call 0x0040d0f5
0x0040d6b9:	pushl 0x430b28
0x0040d6bf:	movl 0x430b24, %eax
0x0040d6c4:	call 0x0040d0f5
0x0040d6c9:	addl %esp, $0x10<UINT8>
0x0040d6cc:	movl 0x430b28, %eax
0x0040d6d1:	call 0x004084dd
0x004084dd:	movl %edi, %edi
0x004084df:	pushl %esi
0x004084e0:	pushl %edi
0x004084e1:	xorl %esi, %esi
0x004084e3:	movl %edi, $0x430308<UINT32>
0x004084e8:	cmpl 0x42c96c(,%esi,8), $0x1<UINT8>
0x004084f0:	jne 0x00408510
0x004084f2:	leal %eax, 0x42c968(,%esi,8)
0x004084f9:	movl (%eax), %edi
0x004084fb:	pushl $0xfa0<UINT32>
0x00408500:	pushl (%eax)
0x00408502:	addl %edi, $0x18<UINT8>
0x00408505:	call 0x00413ba1
0x00413ba1:	pushl $0x10<UINT8>
0x00413ba3:	pushl $0x42a258<UINT32>
0x00413ba8:	call 0x004096c4
0x00413bad:	andl -4(%ebp), $0x0<UINT8>
0x00413bb1:	pushl 0xc(%ebp)
0x00413bb4:	pushl 0x8(%ebp)
0x00413bb7:	call InitializeCriticalSectionAndSpinCount@KERNEL32.dll
InitializeCriticalSectionAndSpinCount@KERNEL32.dll: API Node	
0x00413bbd:	movl -28(%ebp), %eax
0x00413bc0:	jmp 0x00413bf1
0x00413bf1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00413bf8:	movl %eax, -28(%ebp)
0x00413bfb:	call 0x00409709
0x00409709:	movl %ecx, -16(%ebp)
0x0040970c:	movl %fs:0, %ecx
0x00409713:	popl %ecx
0x00409714:	popl %edi
0x00409715:	popl %edi
0x00409716:	popl %esi
0x00409717:	popl %ebx
0x00409718:	movl %esp, %ebp
0x0040971a:	popl %ebp
0x0040971b:	pushl %ecx
0x0040971c:	ret

0x00413c00:	ret

0x0040850a:	popl %ecx
0x0040850b:	popl %ecx
0x0040850c:	testl %eax, %eax
0x0040850e:	je 12
0x00408510:	incl %esi
0x00408511:	cmpl %esi, $0x24<UINT8>
0x00408514:	jl 0x004084e8
0x00408516:	xorl %eax, %eax
0x00408518:	incl %eax
0x00408519:	popl %edi
0x0040851a:	popl %esi
0x0040851b:	ret

0x0040d6d6:	testl %eax, %eax
0x0040d6d8:	je 101
0x0040d6da:	pushl $0x40d413<UINT32>
0x0040d6df:	pushl 0x430b1c
0x0040d6e5:	call 0x0040d170
0x0040d170:	movl %edi, %edi
0x0040d172:	pushl %ebp
0x0040d173:	movl %ebp, %esp
0x0040d175:	pushl %esi
0x0040d176:	pushl 0x42d2dc
0x0040d17c:	movl %esi, 0x42316c
0x0040d182:	call TlsGetValue@KERNEL32.dll
0x0040d184:	testl %eax, %eax
0x0040d186:	je 33
0x0040d188:	movl %eax, 0x42d2d8
0x0040d18d:	cmpl %eax, $0xffffffff<UINT8>
0x0040d190:	je 0x0040d1a9
0x0040d1a9:	movl %esi, $0x427d94<UINT32>
0x0040d1ae:	pushl %esi
0x0040d1af:	call GetModuleHandleW@KERNEL32.dll
0x0040d1b5:	testl %eax, %eax
0x0040d1b7:	jne 0x0040d1c4
0x0040d1c4:	pushl $0x427db0<UINT32>
0x0040d1c9:	pushl %eax
0x0040d1ca:	call GetProcAddress@KERNEL32.dll
0x0040d1d0:	testl %eax, %eax
0x0040d1d2:	je 8
0x0040d1d4:	pushl 0x8(%ebp)
0x0040d1d7:	call DecodePointer@KERNEL32.DLL
DecodePointer@KERNEL32.DLL: API Node	
0x0040d1d9:	movl 0x8(%ebp), %eax
0x0040d1dc:	movl %eax, 0x8(%ebp)
0x0040d1df:	popl %esi
0x0040d1e0:	popl %ebp
0x0040d1e1:	ret

0x0040d6ea:	popl %ecx
0x0040d6eb:	call FlsAlloc@KERNEL32.DLL
FlsAlloc@KERNEL32.DLL: API Node	
0x0040d6ed:	movl 0x42d2d8, %eax
0x0040d6f2:	cmpl %eax, $0xffffffff<UINT8>
0x0040d6f5:	je 72
0x0040d6f7:	pushl $0x214<UINT32>
0x0040d6fc:	pushl $0x1<UINT8>
0x0040d6fe:	call 0x00413a03
0x00413a03:	movl %edi, %edi
0x00413a05:	pushl %ebp
0x00413a06:	movl %ebp, %esp
0x00413a08:	pushl %esi
0x00413a09:	pushl %edi
0x00413a0a:	xorl %esi, %esi
0x00413a0c:	pushl $0x0<UINT8>
0x00413a0e:	pushl 0xc(%ebp)
0x00413a11:	pushl 0x8(%ebp)
0x00413a14:	call 0x0041e4cf
0x0041e4cf:	pushl $0xc<UINT8>
0x0041e4d1:	pushl $0x42a398<UINT32>
0x0041e4d6:	call 0x004096c4
0x0041e4db:	movl %ecx, 0x8(%ebp)
0x0041e4de:	xorl %edi, %edi
0x0041e4e0:	cmpl %ecx, %edi
0x0041e4e2:	jbe 46
0x0041e4e4:	pushl $0xffffffe0<UINT8>
0x0041e4e6:	popl %eax
0x0041e4e7:	xorl %edx, %edx
0x0041e4e9:	divl %eax, %ecx
0x0041e4eb:	cmpl %eax, 0xc(%ebp)
0x0041e4ee:	sbbl %eax, %eax
0x0041e4f0:	incl %eax
0x0041e4f1:	jne 0x0041e512
0x0041e512:	imull %ecx, 0xc(%ebp)
0x0041e516:	movl %esi, %ecx
0x0041e518:	movl 0x8(%ebp), %esi
0x0041e51b:	cmpl %esi, %edi
0x0041e51d:	jne 0x0041e522
0x0041e522:	xorl %ebx, %ebx
0x0041e524:	movl -28(%ebp), %ebx
0x0041e527:	cmpl %esi, $0xffffffe0<UINT8>
0x0041e52a:	ja 105
0x0041e52c:	cmpl 0x438880, $0x3<UINT8>
0x0041e533:	jne 0x0041e580
0x0041e580:	cmpl %ebx, %edi
0x0041e582:	jne 97
0x0041e584:	pushl %esi
0x0041e585:	pushl $0x8<UINT8>
0x0041e587:	pushl 0x43045c
0x0041e58d:	call HeapAlloc@KERNEL32.dll
HeapAlloc@KERNEL32.dll: API Node	
0x0041e593:	movl %ebx, %eax
0x0041e595:	cmpl %ebx, %edi
0x0041e597:	jne 0x0041e5e5
0x0041e5e5:	movl %eax, %ebx
0x0041e5e7:	call 0x00409709
0x0041e5ec:	ret

0x00413a19:	movl %edi, %eax
0x00413a1b:	addl %esp, $0xc<UINT8>
0x00413a1e:	testl %edi, %edi
0x00413a20:	jne 0x00413a49
0x00413a49:	movl %eax, %edi
0x00413a4b:	popl %edi
0x00413a4c:	popl %esi
0x00413a4d:	popl %ebp
0x00413a4e:	ret

0x0040d703:	movl %esi, %eax
0x0040d705:	popl %ecx
0x0040d706:	popl %ecx
0x0040d707:	testl %esi, %esi
0x0040d709:	je 52
0x0040d70b:	pushl %esi
0x0040d70c:	pushl 0x42d2d8
0x0040d712:	pushl 0x430b24
0x0040d718:	call 0x0040d170
0x0040d192:	pushl %eax
0x0040d193:	pushl 0x42d2dc
0x0040d199:	call TlsGetValue@KERNEL32.dll
0x0040d19b:	call FlsGetValue@KERNEL32.DLL
FlsGetValue@KERNEL32.DLL: API Node	
0x0040d19d:	testl %eax, %eax
0x0040d19f:	je 0x0040d1a9
0x0040d71d:	popl %ecx
0x0040d71e:	call FlsSetValue@KERNEL32.DLL
FlsSetValue@KERNEL32.DLL: API Node	
0x0040d720:	testl %eax, %eax
0x0040d722:	je 27
0x0040d724:	pushl $0x0<UINT8>
0x0040d726:	pushl %esi
0x0040d727:	call 0x0040d299
0x0040d299:	pushl $0xc<UINT8>
0x0040d29b:	pushl $0x42a188<UINT32>
0x0040d2a0:	call 0x004096c4
0x0040d2a5:	movl %esi, $0x427d94<UINT32>
0x0040d2aa:	pushl %esi
0x0040d2ab:	call GetModuleHandleW@KERNEL32.dll
0x0040d2b1:	testl %eax, %eax
0x0040d2b3:	jne 0x0040d2bc
0x0040d2bc:	movl -28(%ebp), %eax
0x0040d2bf:	movl %esi, 0x8(%ebp)
0x0040d2c2:	movl 0x5c(%esi), $0x427df0<UINT32>
0x0040d2c9:	xorl %edi, %edi
0x0040d2cb:	incl %edi
0x0040d2cc:	movl 0x14(%esi), %edi
0x0040d2cf:	testl %eax, %eax
0x0040d2d1:	je 36
0x0040d2d3:	pushl $0x427d84<UINT32>
0x0040d2d8:	pushl %eax
0x0040d2d9:	movl %ebx, 0x4231e4
0x0040d2df:	call GetProcAddress@KERNEL32.dll
0x0040d2e1:	movl 0x1f8(%esi), %eax
0x0040d2e7:	pushl $0x427db0<UINT32>
0x0040d2ec:	pushl -28(%ebp)
0x0040d2ef:	call GetProcAddress@KERNEL32.dll
0x0040d2f1:	movl 0x1fc(%esi), %eax
0x0040d2f7:	movl 0x70(%esi), %edi
0x0040d2fa:	movb 0xc8(%esi), $0x43<UINT8>
0x0040d301:	movb 0x14b(%esi), $0x43<UINT8>
0x0040d308:	movl 0x68(%esi), $0x42ccc0<UINT32>
0x0040d30f:	pushl $0xd<UINT8>
0x0040d311:	call 0x00408671
0x00408671:	movl %edi, %edi
0x00408673:	pushl %ebp
0x00408674:	movl %ebp, %esp
0x00408676:	movl %eax, 0x8(%ebp)
0x00408679:	pushl %esi
0x0040867a:	leal %esi, 0x42c968(,%eax,8)
0x00408681:	cmpl (%esi), $0x0<UINT8>
0x00408684:	jne 0x00408699
0x00408699:	pushl (%esi)
0x0040869b:	call EnterCriticalSection@KERNEL32.dll
EnterCriticalSection@KERNEL32.dll: API Node	
0x004086a1:	popl %esi
0x004086a2:	popl %ebp
0x004086a3:	ret

0x0040d316:	popl %ecx
0x0040d317:	andl -4(%ebp), $0x0<UINT8>
0x0040d31b:	pushl 0x68(%esi)
0x0040d31e:	call InterlockedIncrement@KERNEL32.dll
InterlockedIncrement@KERNEL32.dll: API Node	
0x0040d324:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040d32b:	call 0x0040d36e
0x0040d36e:	pushl $0xd<UINT8>
0x0040d370:	call 0x0040857f
0x0040857f:	movl %edi, %edi
0x00408581:	pushl %ebp
0x00408582:	movl %ebp, %esp
0x00408584:	movl %eax, 0x8(%ebp)
0x00408587:	pushl 0x42c968(,%eax,8)
0x0040858e:	call LeaveCriticalSection@KERNEL32.dll
LeaveCriticalSection@KERNEL32.dll: API Node	
0x00408594:	popl %ebp
0x00408595:	ret

0x0040d375:	popl %ecx
0x0040d376:	ret

0x0040d330:	pushl $0xc<UINT8>
0x0040d332:	call 0x00408671
0x0040d337:	popl %ecx
0x0040d338:	movl -4(%ebp), %edi
0x0040d33b:	movl %eax, 0xc(%ebp)
0x0040d33e:	movl 0x6c(%esi), %eax
0x0040d341:	testl %eax, %eax
0x0040d343:	jne 8
0x0040d345:	movl %eax, 0x42d2c8
0x0040d34a:	movl 0x6c(%esi), %eax
0x0040d34d:	pushl 0x6c(%esi)
0x0040d350:	call 0x0040bf87
0x0040bf87:	movl %edi, %edi
0x0040bf89:	pushl %ebp
0x0040bf8a:	movl %ebp, %esp
0x0040bf8c:	pushl %ebx
0x0040bf8d:	pushl %esi
0x0040bf8e:	movl %esi, 0x4231c0
0x0040bf94:	pushl %edi
0x0040bf95:	movl %edi, 0x8(%ebp)
0x0040bf98:	pushl %edi
0x0040bf99:	call InterlockedIncrement@KERNEL32.dll
0x0040bf9b:	movl %eax, 0xb0(%edi)
0x0040bfa1:	testl %eax, %eax
0x0040bfa3:	je 0x0040bfa8
0x0040bfa8:	movl %eax, 0xb8(%edi)
0x0040bfae:	testl %eax, %eax
0x0040bfb0:	je 0x0040bfb5
0x0040bfb5:	movl %eax, 0xb4(%edi)
0x0040bfbb:	testl %eax, %eax
0x0040bfbd:	je 0x0040bfc2
0x0040bfc2:	movl %eax, 0xc0(%edi)
0x0040bfc8:	testl %eax, %eax
0x0040bfca:	je 0x0040bfcf
0x0040bfcf:	leal %ebx, 0x50(%edi)
0x0040bfd2:	movl 0x8(%ebp), $0x6<UINT32>
0x0040bfd9:	cmpl -8(%ebx), $0x42d1e8<UINT32>
0x0040bfe0:	je 0x0040bfeb
0x0040bfe2:	movl %eax, (%ebx)
0x0040bfe4:	testl %eax, %eax
0x0040bfe6:	je 0x0040bfeb
0x0040bfeb:	cmpl -4(%ebx), $0x0<UINT8>
0x0040bfef:	je 0x0040bffb
0x0040bffb:	addl %ebx, $0x10<UINT8>
0x0040bffe:	decl 0x8(%ebp)
0x0040c001:	jne 0x0040bfd9
0x0040c003:	movl %eax, 0xd4(%edi)
0x0040c009:	addl %eax, $0xb4<UINT32>
0x0040c00e:	pushl %eax
0x0040c00f:	call InterlockedIncrement@KERNEL32.dll
0x0040c011:	popl %edi
0x0040c012:	popl %esi
0x0040c013:	popl %ebx
0x0040c014:	popl %ebp
0x0040c015:	ret

0x0040d355:	popl %ecx
0x0040d356:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040d35d:	call 0x0040d377
0x0040d377:	pushl $0xc<UINT8>
0x0040d379:	call 0x0040857f
0x0040d37e:	popl %ecx
0x0040d37f:	ret

0x0040d362:	call 0x00409709
0x0040d367:	ret

0x0040d72c:	popl %ecx
0x0040d72d:	popl %ecx
0x0040d72e:	call GetCurrentThreadId@KERNEL32.dll
0x0040d734:	orl 0x4(%esi), $0xffffffff<UINT8>
0x0040d738:	movl (%esi), %eax
0x0040d73a:	xorl %eax, %eax
0x0040d73c:	incl %eax
0x0040d73d:	jmp 0x0040d746
0x0040d746:	popl %edi
0x0040d747:	popl %esi
0x0040d748:	ret

0x00407970:	testl %eax, %eax
0x00407972:	jne 0x0040797c
0x0040797c:	call 0x0040e3db
0x0040e3db:	movl %edi, %edi
0x0040e3dd:	pushl %esi
0x0040e3de:	movl %eax, $0x429eb0<UINT32>
0x0040e3e3:	movl %esi, $0x429eb0<UINT32>
0x0040e3e8:	pushl %edi
0x0040e3e9:	movl %edi, %eax
0x0040e3eb:	cmpl %eax, %esi
0x0040e3ed:	jae 0x0040e3fe
0x0040e3fe:	popl %edi
0x0040e3ff:	popl %esi
0x0040e400:	ret

0x00407981:	movl -4(%ebp), %ebx
0x00407984:	call 0x0040e139
0x0040e139:	pushl $0x54<UINT8>
0x0040e13b:	pushl $0x42a1d8<UINT32>
0x0040e140:	call 0x004096c4
0x0040e145:	xorl %edi, %edi
0x0040e147:	movl -4(%ebp), %edi
0x0040e14a:	leal %eax, -100(%ebp)
0x0040e14d:	pushl %eax
0x0040e14e:	call GetStartupInfoA@KERNEL32.dll
0x0040e154:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040e15b:	pushl $0x40<UINT8>
0x0040e15d:	pushl $0x20<UINT8>
0x0040e15f:	popl %esi
0x0040e160:	pushl %esi
0x0040e161:	call 0x00413a03
0x0040e166:	popl %ecx
0x0040e167:	popl %ecx
0x0040e168:	cmpl %eax, %edi
0x0040e16a:	je 532
0x0040e170:	movl 0x438760, %eax
0x0040e175:	movl 0x438744, %esi
0x0040e17b:	leal %ecx, 0x800(%eax)
0x0040e181:	jmp 0x0040e1b3
0x0040e1b3:	cmpl %eax, %ecx
0x0040e1b5:	jb 0x0040e183
0x0040e183:	movb 0x4(%eax), $0x0<UINT8>
0x0040e187:	orl (%eax), $0xffffffff<UINT8>
0x0040e18a:	movb 0x5(%eax), $0xa<UINT8>
0x0040e18e:	movl 0x8(%eax), %edi
0x0040e191:	movb 0x24(%eax), $0x0<UINT8>
0x0040e195:	movb 0x25(%eax), $0xa<UINT8>
0x0040e199:	movb 0x26(%eax), $0xa<UINT8>
0x0040e19d:	movl 0x38(%eax), %edi
0x0040e1a0:	movb 0x34(%eax), $0x0<UINT8>
0x0040e1a4:	addl %eax, $0x40<UINT8>
0x0040e1a7:	movl %ecx, 0x438760
0x0040e1ad:	addl %ecx, $0x800<UINT32>
0x0040e1b7:	cmpw -50(%ebp), %di
0x0040e1bb:	je 266
0x0040e1c1:	movl %eax, -48(%ebp)
0x0040e1c4:	cmpl %eax, %edi
0x0040e1c6:	je 255
0x0040e1cc:	movl %edi, (%eax)
0x0040e1ce:	leal %ebx, 0x4(%eax)
0x0040e1d1:	leal %eax, (%ebx,%edi)
0x0040e1d4:	movl -28(%ebp), %eax
0x0040e1d7:	movl %esi, $0x800<UINT32>
0x0040e1dc:	cmpl %edi, %esi
0x0040e1de:	jl 0x0040e1e2
0x0040e1e2:	movl -32(%ebp), $0x1<UINT32>
0x0040e1e9:	jmp 0x0040e246
0x0040e246:	cmpl 0x438744, %edi
0x0040e24c:	jl -99
0x0040e24e:	jmp 0x0040e256
0x0040e256:	andl -32(%ebp), $0x0<UINT8>
0x0040e25a:	testl %edi, %edi
0x0040e25c:	jle 0x0040e2cb
0x0040e2cb:	xorl %ebx, %ebx
0x0040e2cd:	movl %esi, %ebx
0x0040e2cf:	shll %esi, $0x6<UINT8>
0x0040e2d2:	addl %esi, 0x438760
0x0040e2d8:	movl %eax, (%esi)
0x0040e2da:	cmpl %eax, $0xffffffff<UINT8>
0x0040e2dd:	je 0x0040e2ea
0x0040e2ea:	movb 0x4(%esi), $0xffffff81<UINT8>
0x0040e2ee:	testl %ebx, %ebx
0x0040e2f0:	jne 0x0040e2f7
0x0040e2f2:	pushl $0xfffffff6<UINT8>
0x0040e2f4:	popl %eax
0x0040e2f5:	jmp 0x0040e301
0x0040e301:	pushl %eax
0x0040e302:	call GetStdHandle@KERNEL32.dll
GetStdHandle@KERNEL32.dll: API Node	
0x0040e308:	movl %edi, %eax
0x0040e30a:	cmpl %edi, $0xffffffff<UINT8>
0x0040e30d:	je 67
0x0040e30f:	testl %edi, %edi
0x0040e311:	je 63
0x0040e313:	pushl %edi
0x0040e314:	call GetFileType@KERNEL32.dll
GetFileType@KERNEL32.dll: API Node	
0x0040e31a:	testl %eax, %eax
0x0040e31c:	je 52
0x0040e31e:	movl (%esi), %edi
0x0040e320:	andl %eax, $0xff<UINT32>
0x0040e325:	cmpl %eax, $0x2<UINT8>
0x0040e328:	jne 6
0x0040e32a:	orb 0x4(%esi), $0x40<UINT8>
0x0040e32e:	jmp 0x0040e339
0x0040e339:	pushl $0xfa0<UINT32>
0x0040e33e:	leal %eax, 0xc(%esi)
0x0040e341:	pushl %eax
0x0040e342:	call 0x00413ba1
0x0040e347:	popl %ecx
0x0040e348:	popl %ecx
0x0040e349:	testl %eax, %eax
0x0040e34b:	je 55
0x0040e34d:	incl 0x8(%esi)
0x0040e350:	jmp 0x0040e35c
0x0040e35c:	incl %ebx
0x0040e35d:	cmpl %ebx, $0x3<UINT8>
0x0040e360:	jl 0x0040e2cd
0x0040e2f7:	movl %eax, %ebx
0x0040e2f9:	decl %eax
0x0040e2fa:	negl %eax
0x0040e2fc:	sbbl %eax, %eax
0x0040e2fe:	addl %eax, $0xfffffff5<UINT8>
0x0040e366:	pushl 0x438744
0x0040e36c:	call SetHandleCount@KERNEL32.dll
SetHandleCount@KERNEL32.dll: API Node	
0x0040e372:	xorl %eax, %eax
0x0040e374:	jmp 0x0040e387
0x0040e387:	call 0x00409709
0x0040e38c:	ret

0x00407989:	testl %eax, %eax
0x0040798b:	jnl 0x00407995
0x00407995:	call GetCommandLineA@KERNEL32.dll
GetCommandLineA@KERNEL32.dll: API Node	
0x0040799b:	movl 0x4388a8, %eax
0x004079a0:	call 0x0040e002
0x0040e002:	movl %edi, %edi
0x0040e004:	pushl %ebp
0x0040e005:	movl %ebp, %esp
0x0040e007:	movl %eax, 0x430c38
0x0040e00c:	subl %esp, $0xc<UINT8>
0x0040e00f:	pushl %ebx
0x0040e010:	pushl %esi
0x0040e011:	movl %esi, 0x423140
0x0040e017:	pushl %edi
0x0040e018:	xorl %ebx, %ebx
0x0040e01a:	xorl %edi, %edi
0x0040e01c:	cmpl %eax, %ebx
0x0040e01e:	jne 46
0x0040e020:	call GetEnvironmentStringsW@KERNEL32.dll
GetEnvironmentStringsW@KERNEL32.dll: API Node	
0x0040e022:	movl %edi, %eax
0x0040e024:	cmpl %edi, %ebx
0x0040e026:	je 12
0x0040e028:	movl 0x430c38, $0x1<UINT32>
0x0040e032:	jmp 0x0040e057
0x0040e057:	cmpl %edi, %ebx
0x0040e059:	jne 0x0040e06a
0x0040e06a:	movl %eax, %edi
0x0040e06c:	cmpw (%edi), %bx
0x0040e06f:	je 14
0x0040e071:	incl %eax
0x0040e072:	incl %eax
0x0040e073:	cmpw (%eax), %bx
0x0040e076:	jne 0x0040e071
0x0040e078:	incl %eax
0x0040e079:	incl %eax
0x0040e07a:	cmpw (%eax), %bx
0x0040e07d:	jne 0x0040e071
0x0040e07f:	movl %esi, 0x423144
0x0040e085:	pushl %ebx
0x0040e086:	pushl %ebx
0x0040e087:	pushl %ebx
0x0040e088:	subl %eax, %edi
0x0040e08a:	pushl %ebx
0x0040e08b:	sarl %eax
0x0040e08d:	incl %eax
0x0040e08e:	pushl %eax
0x0040e08f:	pushl %edi
0x0040e090:	pushl %ebx
0x0040e091:	pushl %ebx
0x0040e092:	movl -12(%ebp), %eax
0x0040e095:	call WideCharToMultiByte@KERNEL32.dll
WideCharToMultiByte@KERNEL32.dll: API Node	
0x0040e097:	movl -8(%ebp), %eax
0x0040e09a:	cmpl %eax, %ebx
0x0040e09c:	je 47
0x0040e09e:	pushl %eax
0x0040e09f:	call 0x004139be
0x004139be:	movl %edi, %edi
0x004139c0:	pushl %ebp
0x004139c1:	movl %ebp, %esp
0x004139c3:	pushl %esi
0x004139c4:	pushl %edi
0x004139c5:	xorl %esi, %esi
0x004139c7:	pushl 0x8(%ebp)
0x004139ca:	call 0x00406cb3
0x00406cb3:	movl %edi, %edi
0x00406cb5:	pushl %ebp
0x00406cb6:	movl %ebp, %esp
0x00406cb8:	pushl %esi
0x00406cb9:	movl %esi, 0x8(%ebp)
0x00406cbc:	cmpl %esi, $0xffffffe0<UINT8>
0x00406cbf:	ja 161
0x00406cc5:	pushl %ebx
0x00406cc6:	pushl %edi
0x00406cc7:	movl %edi, 0x42320c
0x00406ccd:	cmpl 0x43045c, $0x0<UINT8>
0x00406cd4:	jne 0x00406cee
0x00406cee:	movl %eax, 0x438880
0x00406cf3:	cmpl %eax, $0x1<UINT8>
0x00406cf6:	jne 14
0x00406cf8:	testl %esi, %esi
0x00406cfa:	je 4
0x00406cfc:	movl %eax, %esi
0x00406cfe:	jmp 0x00406d03
0x00406d03:	pushl %eax
0x00406d04:	jmp 0x00406d22
0x00406d22:	pushl $0x0<UINT8>
0x00406d24:	pushl 0x43045c
0x00406d2a:	call HeapAlloc@KERNEL32.dll
0x00406d2c:	movl %ebx, %eax
0x00406d2e:	testl %ebx, %ebx
0x00406d30:	jne 0x00406d60
0x00406d60:	popl %edi
0x00406d61:	movl %eax, %ebx
0x00406d63:	popl %ebx
0x00406d64:	jmp 0x00406d7a
0x00406d7a:	popl %esi
0x00406d7b:	popl %ebp
0x00406d7c:	ret

0x004139cf:	movl %edi, %eax
0x004139d1:	popl %ecx
0x004139d2:	testl %edi, %edi
0x004139d4:	jne 0x004139fd
0x004139fd:	movl %eax, %edi
0x004139ff:	popl %edi
0x00413a00:	popl %esi
0x00413a01:	popl %ebp
0x00413a02:	ret

0x0040e0a4:	popl %ecx
0x0040e0a5:	movl -4(%ebp), %eax
0x0040e0a8:	cmpl %eax, %ebx
0x0040e0aa:	je 33
0x0040e0ac:	pushl %ebx
0x0040e0ad:	pushl %ebx
0x0040e0ae:	pushl -8(%ebp)
0x0040e0b1:	pushl %eax
0x0040e0b2:	pushl -12(%ebp)
0x0040e0b5:	pushl %edi
0x0040e0b6:	pushl %ebx
0x0040e0b7:	pushl %ebx
0x0040e0b8:	call WideCharToMultiByte@KERNEL32.dll
0x0040e0ba:	testl %eax, %eax
0x0040e0bc:	jne 0x0040e0ca
0x0040e0ca:	movl %ebx, -4(%ebp)
0x0040e0cd:	pushl %edi
0x0040e0ce:	call FreeEnvironmentStringsW@KERNEL32.dll
FreeEnvironmentStringsW@KERNEL32.dll: API Node	
0x0040e0d4:	movl %eax, %ebx
0x0040e0d6:	jmp 0x0040e134
0x0040e134:	popl %edi
0x0040e135:	popl %esi
0x0040e136:	popl %ebx
0x0040e137:	leave
0x0040e138:	ret

0x004079a5:	movl 0x4302ec, %eax
0x004079aa:	call 0x0040df47
0x0040df47:	movl %edi, %edi
0x0040df49:	pushl %ebp
0x0040df4a:	movl %ebp, %esp
0x0040df4c:	subl %esp, $0xc<UINT8>
0x0040df4f:	pushl %ebx
0x0040df50:	xorl %ebx, %ebx
0x0040df52:	pushl %esi
0x0040df53:	pushl %edi
0x0040df54:	cmpl 0x438874, %ebx
0x0040df5a:	jne 5
0x0040df5c:	call 0x0040be14
0x0040be14:	cmpl 0x438874, $0x0<UINT8>
0x0040be1b:	jne 0x0040be2f
0x0040be1d:	pushl $0xfffffffd<UINT8>
0x0040be1f:	call 0x0040bc7a
0x0040bc7a:	pushl $0x14<UINT8>
0x0040bc7c:	pushl $0x42a0c0<UINT32>
0x0040bc81:	call 0x004096c4
0x0040bc86:	orl -32(%ebp), $0xffffffff<UINT8>
0x0040bc8a:	call 0x0040d3f9
0x0040d3f9:	movl %edi, %edi
0x0040d3fb:	pushl %esi
0x0040d3fc:	call 0x0040d380
0x0040d380:	movl %edi, %edi
0x0040d382:	pushl %esi
0x0040d383:	pushl %edi
0x0040d384:	call GetLastError@KERNEL32.dll
GetLastError@KERNEL32.dll: API Node	
0x0040d38a:	pushl 0x42d2d8
0x0040d390:	movl %edi, %eax
0x0040d392:	call 0x0040d20b
0x0040d20b:	movl %edi, %edi
0x0040d20d:	pushl %esi
0x0040d20e:	pushl 0x42d2dc
0x0040d214:	call TlsGetValue@KERNEL32.dll
0x0040d21a:	movl %esi, %eax
0x0040d21c:	testl %esi, %esi
0x0040d21e:	jne 0x0040d23b
0x0040d23b:	movl %eax, %esi
0x0040d23d:	popl %esi
0x0040d23e:	ret

0x0040d397:	call FlsGetValue@KERNEL32.DLL
0x0040d399:	movl %esi, %eax
0x0040d39b:	testl %esi, %esi
0x0040d39d:	jne 0x0040d3ed
0x0040d3ed:	pushl %edi
0x0040d3ee:	call SetLastError@KERNEL32.dll
SetLastError@KERNEL32.dll: API Node	
0x0040d3f4:	popl %edi
0x0040d3f5:	movl %eax, %esi
0x0040d3f7:	popl %esi
0x0040d3f8:	ret

0x0040d401:	movl %esi, %eax
0x0040d403:	testl %esi, %esi
0x0040d405:	jne 0x0040d40f
0x0040d40f:	movl %eax, %esi
0x0040d411:	popl %esi
0x0040d412:	ret

0x0040bc8f:	movl %edi, %eax
0x0040bc91:	movl -36(%ebp), %edi
0x0040bc94:	call 0x0040b937
0x0040b937:	pushl $0xc<UINT8>
0x0040b939:	pushl $0x42a0a0<UINT32>
0x0040b93e:	call 0x004096c4
0x0040b943:	call 0x0040d3f9
0x0040b948:	movl %edi, %eax
0x0040b94a:	movl %eax, 0x42d1e4
0x0040b94f:	testl 0x70(%edi), %eax
0x0040b952:	je 0x0040b971
0x0040b971:	pushl $0xd<UINT8>
0x0040b973:	call 0x00408671
0x0040b978:	popl %ecx
0x0040b979:	andl -4(%ebp), $0x0<UINT8>
0x0040b97d:	movl %esi, 0x68(%edi)
0x0040b980:	movl -28(%ebp), %esi
0x0040b983:	cmpl %esi, 0x42d0e8
0x0040b989:	je 0x0040b9c1
0x0040b9c1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040b9c8:	call 0x0040b9d2
0x0040b9d2:	pushl $0xd<UINT8>
0x0040b9d4:	call 0x0040857f
0x0040b9d9:	popl %ecx
0x0040b9da:	ret

0x0040b9cd:	jmp 0x0040b95d
0x0040b95d:	testl %esi, %esi
0x0040b95f:	jne 0x0040b969
0x0040b969:	movl %eax, %esi
0x0040b96b:	call 0x00409709
0x0040b970:	ret

0x0040bc99:	movl %ebx, 0x68(%edi)
0x0040bc9c:	movl %esi, 0x8(%ebp)
0x0040bc9f:	call 0x0040b9db
0x0040b9db:	movl %edi, %edi
0x0040b9dd:	pushl %ebp
0x0040b9de:	movl %ebp, %esp
0x0040b9e0:	subl %esp, $0x10<UINT8>
0x0040b9e3:	pushl %ebx
0x0040b9e4:	xorl %ebx, %ebx
0x0040b9e6:	pushl %ebx
0x0040b9e7:	leal %ecx, -16(%ebp)
0x0040b9ea:	call 0x00407334
0x00407334:	movl %edi, %edi
0x00407336:	pushl %ebp
0x00407337:	movl %ebp, %esp
0x00407339:	movl %eax, 0x8(%ebp)
0x0040733c:	pushl %esi
0x0040733d:	movl %esi, %ecx
0x0040733f:	movb 0xc(%esi), $0x0<UINT8>
0x00407343:	testl %eax, %eax
0x00407345:	jne 0x004073aa
0x00407347:	call 0x0040d3f9
0x0040734c:	movl 0x8(%esi), %eax
0x0040734f:	movl %ecx, 0x6c(%eax)
0x00407352:	movl (%esi), %ecx
0x00407354:	movl %ecx, 0x68(%eax)
0x00407357:	movl 0x4(%esi), %ecx
0x0040735a:	movl %ecx, (%esi)
0x0040735c:	cmpl %ecx, 0x42d2c8
0x00407362:	je 0x00407376
0x00407376:	movl %eax, 0x4(%esi)
0x00407379:	cmpl %eax, 0x42d0e8
0x0040737f:	je 0x00407397
0x00407397:	movl %eax, 0x8(%esi)
0x0040739a:	testb 0x70(%eax), $0x2<UINT8>
0x0040739e:	jne 20
0x004073a0:	orl 0x70(%eax), $0x2<UINT8>
0x004073a4:	movb 0xc(%esi), $0x1<UINT8>
0x004073a8:	jmp 0x004073b4
0x004073b4:	movl %eax, %esi
0x004073b6:	popl %esi
0x004073b7:	popl %ebp
0x004073b8:	ret $0x4<UINT16>

0x0040b9ef:	movl 0x430adc, %ebx
0x0040b9f5:	cmpl %esi, $0xfffffffe<UINT8>
0x0040b9f8:	jne 0x0040ba18
0x0040ba18:	cmpl %esi, $0xfffffffd<UINT8>
0x0040ba1b:	jne 0x0040ba2f
0x0040ba1d:	movl 0x430adc, $0x1<UINT32>
0x0040ba27:	call GetACP@KERNEL32.dll
GetACP@KERNEL32.dll: API Node	
0x0040ba2d:	jmp 0x0040ba0a
0x0040ba0a:	cmpb -4(%ebp), %bl
0x0040ba0d:	je 69
0x0040ba0f:	movl %ecx, -8(%ebp)
0x0040ba12:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0040ba16:	jmp 0x0040ba54
0x0040ba54:	popl %ebx
0x0040ba55:	leave
0x0040ba56:	ret

0x0040bca4:	movl 0x8(%ebp), %eax
0x0040bca7:	cmpl %eax, 0x4(%ebx)
0x0040bcaa:	je 343
0x0040bcb0:	pushl $0x220<UINT32>
0x0040bcb5:	call 0x004139be
0x0040bcba:	popl %ecx
0x0040bcbb:	movl %ebx, %eax
0x0040bcbd:	testl %ebx, %ebx
0x0040bcbf:	je 326
0x0040bcc5:	movl %ecx, $0x88<UINT32>
0x0040bcca:	movl %esi, 0x68(%edi)
0x0040bccd:	movl %edi, %ebx
0x0040bccf:	rep movsl %es:(%edi), %ds:(%esi)
0x0040bcd1:	andl (%ebx), $0x0<UINT8>
0x0040bcd4:	pushl %ebx
0x0040bcd5:	pushl 0x8(%ebp)
0x0040bcd8:	call 0x0040ba57
0x0040ba57:	movl %edi, %edi
0x0040ba59:	pushl %ebp
0x0040ba5a:	movl %ebp, %esp
0x0040ba5c:	subl %esp, $0x20<UINT8>
0x0040ba5f:	movl %eax, 0x42c8e0
0x0040ba64:	xorl %eax, %ebp
0x0040ba66:	movl -4(%ebp), %eax
0x0040ba69:	pushl %ebx
0x0040ba6a:	movl %ebx, 0xc(%ebp)
0x0040ba6d:	pushl %esi
0x0040ba6e:	movl %esi, 0x8(%ebp)
0x0040ba71:	pushl %edi
0x0040ba72:	call 0x0040b9db
0x0040ba2f:	cmpl %esi, $0xfffffffc<UINT8>
0x0040ba32:	jne 0x0040ba46
0x0040ba46:	cmpb -4(%ebp), %bl
0x0040ba49:	je 7
0x0040ba4b:	movl %eax, -8(%ebp)
0x0040ba4e:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x0040ba52:	movl %eax, %esi
0x0040ba77:	movl %edi, %eax
0x0040ba79:	xorl %esi, %esi
0x0040ba7b:	movl 0x8(%ebp), %edi
0x0040ba7e:	cmpl %edi, %esi
0x0040ba80:	jne 0x0040ba90
0x0040ba90:	movl -28(%ebp), %esi
0x0040ba93:	xorl %eax, %eax
0x0040ba95:	cmpl 0x42d0f0(%eax), %edi
0x0040ba9b:	je 145
0x0040baa1:	incl -28(%ebp)
0x0040baa4:	addl %eax, $0x30<UINT8>
0x0040baa7:	cmpl %eax, $0xf0<UINT32>
0x0040baac:	jb 0x0040ba95
0x0040baae:	cmpl %edi, $0xfde8<UINT32>
0x0040bab4:	je 368
0x0040baba:	cmpl %edi, $0xfde9<UINT32>
0x0040bac0:	je 356
0x0040bac6:	movzwl %eax, %di
0x0040bac9:	pushl %eax
0x0040baca:	call IsValidCodePage@KERNEL32.dll
IsValidCodePage@KERNEL32.dll: API Node	
0x0040bad0:	testl %eax, %eax
0x0040bad2:	je 338
0x0040bad8:	leal %eax, -24(%ebp)
0x0040badb:	pushl %eax
0x0040badc:	pushl %edi
0x0040badd:	call GetCPInfo@KERNEL32.dll
GetCPInfo@KERNEL32.dll: API Node	
0x0040bae3:	testl %eax, %eax
0x0040bae5:	je 307
0x0040baeb:	pushl $0x101<UINT32>
0x0040baf0:	leal %eax, 0x1c(%ebx)
0x0040baf3:	pushl %esi
0x0040baf4:	pushl %eax
0x0040baf5:	call 0x00406b70
0x00406b70:	movl %edx, 0xc(%esp)
0x00406b74:	movl %ecx, 0x4(%esp)
0x00406b78:	testl %edx, %edx
0x00406b7a:	je 105
0x00406b7c:	xorl %eax, %eax
0x00406b7e:	movb %al, 0x8(%esp)
0x00406b82:	testb %al, %al
0x00406b84:	jne 22
0x00406b86:	cmpl %edx, $0x100<UINT32>
0x00406b8c:	jb 14
0x00406b8e:	cmpl 0x4388a4, $0x0<UINT8>
0x00406b95:	je 0x00406b9c
0x00406b9c:	pushl %edi
0x00406b9d:	movl %edi, %ecx
0x00406b9f:	cmpl %edx, $0x4<UINT8>
0x00406ba2:	jb 49
0x00406ba4:	negl %ecx
0x00406ba6:	andl %ecx, $0x3<UINT8>
0x00406ba9:	je 0x00406bb7
0x00406bb7:	movl %ecx, %eax
0x00406bb9:	shll %eax, $0x8<UINT8>
0x00406bbc:	addl %eax, %ecx
0x00406bbe:	movl %ecx, %eax
0x00406bc0:	shll %eax, $0x10<UINT8>
0x00406bc3:	addl %eax, %ecx
0x00406bc5:	movl %ecx, %edx
0x00406bc7:	andl %edx, $0x3<UINT8>
0x00406bca:	shrl %ecx, $0x2<UINT8>
0x00406bcd:	je 6
0x00406bcf:	rep stosl %es:(%edi), %eax
0x00406bd1:	testl %edx, %edx
0x00406bd3:	je 0x00406bdf
0x00406bd5:	movb (%edi), %al
0x00406bd7:	addl %edi, $0x1<UINT8>
0x00406bda:	subl %edx, $0x1<UINT8>
0x00406bdd:	jne -10
0x00406bdf:	movl %eax, 0x8(%esp)
0x00406be3:	popl %edi
0x00406be4:	ret

0x0040bafa:	xorl %edx, %edx
0x0040bafc:	incl %edx
0x0040bafd:	addl %esp, $0xc<UINT8>
0x0040bb00:	movl 0x4(%ebx), %edi
0x0040bb03:	movl 0xc(%ebx), %esi
0x0040bb06:	cmpl -24(%ebp), %edx
0x0040bb09:	jbe 248
0x0040bb0f:	cmpb -18(%ebp), $0x0<UINT8>
0x0040bb13:	je 0x0040bbe8
0x0040bbe8:	leal %eax, 0x1e(%ebx)
0x0040bbeb:	movl %ecx, $0xfe<UINT32>
0x0040bbf0:	orb (%eax), $0x8<UINT8>
0x0040bbf3:	incl %eax
0x0040bbf4:	decl %ecx
0x0040bbf5:	jne 0x0040bbf0
0x0040bbf7:	movl %eax, 0x4(%ebx)
0x0040bbfa:	call 0x0040b711
0x0040b711:	subl %eax, $0x3a4<UINT32>
0x0040b716:	je 34
0x0040b718:	subl %eax, $0x4<UINT8>
0x0040b71b:	je 23
0x0040b71d:	subl %eax, $0xd<UINT8>
0x0040b720:	je 12
0x0040b722:	decl %eax
0x0040b723:	je 3
0x0040b725:	xorl %eax, %eax
0x0040b727:	ret

0x0040bbff:	movl 0xc(%ebx), %eax
0x0040bc02:	movl 0x8(%ebx), %edx
0x0040bc05:	jmp 0x0040bc0a
0x0040bc0a:	xorl %eax, %eax
0x0040bc0c:	movzwl %ecx, %ax
0x0040bc0f:	movl %eax, %ecx
0x0040bc11:	shll %ecx, $0x10<UINT8>
0x0040bc14:	orl %eax, %ecx
0x0040bc16:	leal %edi, 0x10(%ebx)
0x0040bc19:	stosl %es:(%edi), %eax
0x0040bc1a:	stosl %es:(%edi), %eax
0x0040bc1b:	stosl %es:(%edi), %eax
0x0040bc1c:	jmp 0x0040bbc6
0x0040bbc6:	movl %esi, %ebx
0x0040bbc8:	call 0x0040b7a4
0x0040b7a4:	movl %edi, %edi
0x0040b7a6:	pushl %ebp
0x0040b7a7:	movl %ebp, %esp
0x0040b7a9:	subl %esp, $0x51c<UINT32>
0x0040b7af:	movl %eax, 0x42c8e0
0x0040b7b4:	xorl %eax, %ebp
0x0040b7b6:	movl -4(%ebp), %eax
0x0040b7b9:	pushl %ebx
0x0040b7ba:	pushl %edi
0x0040b7bb:	leal %eax, -1304(%ebp)
0x0040b7c1:	pushl %eax
0x0040b7c2:	pushl 0x4(%esi)
0x0040b7c5:	call GetCPInfo@KERNEL32.dll
0x0040b7cb:	movl %edi, $0x100<UINT32>
0x0040b7d0:	testl %eax, %eax
0x0040b7d2:	je 251
0x0040b7d8:	xorl %eax, %eax
0x0040b7da:	movb -260(%ebp,%eax), %al
0x0040b7e1:	incl %eax
0x0040b7e2:	cmpl %eax, %edi
0x0040b7e4:	jb 0x0040b7da
0x0040b7e6:	movb %al, -1298(%ebp)
0x0040b7ec:	movb -260(%ebp), $0x20<UINT8>
0x0040b7f3:	testb %al, %al
0x0040b7f5:	je 0x0040b825
0x0040b825:	pushl $0x0<UINT8>
0x0040b827:	pushl 0xc(%esi)
0x0040b82a:	leal %eax, -1284(%ebp)
0x0040b830:	pushl 0x4(%esi)
0x0040b833:	pushl %eax
0x0040b834:	pushl %edi
0x0040b835:	leal %eax, -260(%ebp)
0x0040b83b:	pushl %eax
0x0040b83c:	pushl $0x1<UINT8>
0x0040b83e:	pushl $0x0<UINT8>
0x0040b840:	call 0x00418671
0x00418671:	movl %edi, %edi
0x00418673:	pushl %ebp
0x00418674:	movl %ebp, %esp
0x00418676:	subl %esp, $0x10<UINT8>
0x00418679:	pushl 0x8(%ebp)
0x0041867c:	leal %ecx, -16(%ebp)
0x0041867f:	call 0x00407334
0x00418684:	pushl 0x24(%ebp)
0x00418687:	leal %ecx, -16(%ebp)
0x0041868a:	pushl 0x20(%ebp)
0x0041868d:	pushl 0x1c(%ebp)
0x00418690:	pushl 0x18(%ebp)
0x00418693:	pushl 0x14(%ebp)
0x00418696:	pushl 0x10(%ebp)
0x00418699:	pushl 0xc(%ebp)
0x0041869c:	call 0x004184b7
0x004184b7:	movl %edi, %edi
0x004184b9:	pushl %ebp
0x004184ba:	movl %ebp, %esp
0x004184bc:	pushl %ecx
0x004184bd:	pushl %ecx
0x004184be:	movl %eax, 0x42c8e0
0x004184c3:	xorl %eax, %ebp
0x004184c5:	movl -4(%ebp), %eax
0x004184c8:	movl %eax, 0x430cfc
0x004184cd:	pushl %ebx
0x004184ce:	pushl %esi
0x004184cf:	xorl %ebx, %ebx
0x004184d1:	pushl %edi
0x004184d2:	movl %edi, %ecx
0x004184d4:	cmpl %eax, %ebx
0x004184d6:	jne 58
0x004184d8:	leal %eax, -8(%ebp)
0x004184db:	pushl %eax
0x004184dc:	xorl %esi, %esi
0x004184de:	incl %esi
0x004184df:	pushl %esi
0x004184e0:	pushl $0x4289fc<UINT32>
0x004184e5:	pushl %esi
0x004184e6:	call GetStringTypeW@KERNEL32.dll
GetStringTypeW@KERNEL32.dll: API Node	
0x004184ec:	testl %eax, %eax
0x004184ee:	je 8
0x004184f0:	movl 0x430cfc, %esi
0x004184f6:	jmp 0x0041852c
0x0041852c:	movl -8(%ebp), %ebx
0x0041852f:	cmpl 0x18(%ebp), %ebx
0x00418532:	jne 0x0041853c
0x0041853c:	movl %esi, 0x423100
0x00418542:	xorl %eax, %eax
0x00418544:	cmpl 0x20(%ebp), %ebx
0x00418547:	pushl %ebx
0x00418548:	pushl %ebx
0x00418549:	pushl 0x10(%ebp)
0x0041854c:	setne %al
0x0041854f:	pushl 0xc(%ebp)
0x00418552:	leal %eax, 0x1(,%eax,8)
0x00418559:	pushl %eax
0x0041855a:	pushl 0x18(%ebp)
0x0041855d:	call MultiByteToWideChar@KERNEL32.dll
MultiByteToWideChar@KERNEL32.dll: API Node	
0x0041855f:	movl %edi, %eax
0x00418561:	cmpl %edi, %ebx
0x00418563:	je 171
0x00418569:	jle 60
0x0041856b:	cmpl %edi, $0x7ffffff0<UINT32>
0x00418571:	ja 52
0x00418573:	leal %eax, 0x8(%edi,%edi)
0x00418577:	cmpl %eax, $0x400<UINT32>
0x0041857c:	ja 19
0x0041857e:	call 0x004202f0
0x004202f0:	pushl %ecx
0x004202f1:	leal %ecx, 0x8(%esp)
0x004202f5:	subl %ecx, %eax
0x004202f7:	andl %ecx, $0xf<UINT8>
0x004202fa:	addl %eax, %ecx
0x004202fc:	sbbl %ecx, %ecx
0x004202fe:	orl %eax, %ecx
0x00420300:	popl %ecx
0x00420301:	jmp 0x00407850
0x00407850:	pushl %ecx
0x00407851:	leal %ecx, 0x4(%esp)
0x00407855:	subl %ecx, %eax
0x00407857:	sbbl %eax, %eax
0x00407859:	notl %eax
0x0040785b:	andl %ecx, %eax
0x0040785d:	movl %eax, %esp
0x0040785f:	andl %eax, $0xfffff000<UINT32>
0x00407864:	cmpl %ecx, %eax
0x00407866:	jb 10
0x00407868:	movl %eax, %ecx
0x0040786a:	popl %ecx
0x0040786b:	xchgl %esp, %eax
0x0040786c:	movl %eax, (%eax)
0x0040786e:	movl (%esp), %eax
0x00407871:	ret

0x00418583:	movl %eax, %esp
0x00418585:	cmpl %eax, %ebx
0x00418587:	je 28
0x00418589:	movl (%eax), $0xcccc<UINT32>
0x0041858f:	jmp 0x004185a2
0x004185a2:	addl %eax, $0x8<UINT8>
0x004185a5:	movl %ebx, %eax
0x004185a7:	testl %ebx, %ebx
0x004185a9:	je 105
0x004185ab:	leal %eax, (%edi,%edi)
0x004185ae:	pushl %eax
0x004185af:	pushl $0x0<UINT8>
0x004185b1:	pushl %ebx
0x004185b2:	call 0x00406b70
0x004185b7:	addl %esp, $0xc<UINT8>
0x004185ba:	pushl %edi
0x004185bb:	pushl %ebx
0x004185bc:	pushl 0x10(%ebp)
0x004185bf:	pushl 0xc(%ebp)
0x004185c2:	pushl $0x1<UINT8>
0x004185c4:	pushl 0x18(%ebp)
0x004185c7:	call MultiByteToWideChar@KERNEL32.dll
0x004185c9:	testl %eax, %eax
0x004185cb:	je 17
0x004185cd:	pushl 0x14(%ebp)
0x004185d0:	pushl %eax
0x004185d1:	pushl %ebx
0x004185d2:	pushl 0x8(%ebp)
0x004185d5:	call GetStringTypeW@KERNEL32.dll
0x004185db:	movl -8(%ebp), %eax
0x004185de:	pushl %ebx
0x004185df:	call 0x0041808f
0x0041808f:	movl %edi, %edi
0x00418091:	pushl %ebp
0x00418092:	movl %ebp, %esp
0x00418094:	movl %eax, 0x8(%ebp)
0x00418097:	testl %eax, %eax
0x00418099:	je 18
0x0041809b:	subl %eax, $0x8<UINT8>
0x0041809e:	cmpl (%eax), $0xdddd<UINT32>
0x004180a4:	jne 0x004180ad
0x004180ad:	popl %ebp
0x004180ae:	ret

0x004185e4:	movl %eax, -8(%ebp)
0x004185e7:	popl %ecx
0x004185e8:	jmp 0x0041865f
0x0041865f:	leal %esp, -20(%ebp)
0x00418662:	popl %edi
0x00418663:	popl %esi
0x00418664:	popl %ebx
0x00418665:	movl %ecx, -4(%ebp)
0x00418668:	xorl %ecx, %ebp
0x0041866a:	call 0x00407325
0x00407325:	cmpl %ecx, 0x42c8e0
0x0040732b:	jne 2
0x0040732d:	rep ret

0x0041866f:	leave
0x00418670:	ret

0x004186a1:	addl %esp, $0x1c<UINT8>
0x004186a4:	cmpb -4(%ebp), $0x0<UINT8>
0x004186a8:	je 7
0x004186aa:	movl %ecx, -8(%ebp)
0x004186ad:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x004186b1:	leave
0x004186b2:	ret

0x0040b845:	xorl %ebx, %ebx
0x0040b847:	pushl %ebx
0x0040b848:	pushl 0x4(%esi)
0x0040b84b:	leal %eax, -516(%ebp)
0x0040b851:	pushl %edi
0x0040b852:	pushl %eax
0x0040b853:	pushl %edi
0x0040b854:	leal %eax, -260(%ebp)
0x0040b85a:	pushl %eax
0x0040b85b:	pushl %edi
0x0040b85c:	pushl 0xc(%esi)
0x0040b85f:	pushl %ebx
0x0040b860:	call 0x00418472
0x00418472:	movl %edi, %edi
0x00418474:	pushl %ebp
0x00418475:	movl %ebp, %esp
0x00418477:	subl %esp, $0x10<UINT8>
0x0041847a:	pushl 0x8(%ebp)
0x0041847d:	leal %ecx, -16(%ebp)
0x00418480:	call 0x00407334
0x00418485:	pushl 0x28(%ebp)
0x00418488:	leal %ecx, -16(%ebp)
0x0041848b:	pushl 0x24(%ebp)
0x0041848e:	pushl 0x20(%ebp)
0x00418491:	pushl 0x1c(%ebp)
0x00418494:	pushl 0x18(%ebp)
0x00418497:	pushl 0x14(%ebp)
0x0041849a:	pushl 0x10(%ebp)
0x0041849d:	pushl 0xc(%ebp)
0x004184a0:	call 0x004180cd
0x004180cd:	movl %edi, %edi
0x004180cf:	pushl %ebp
0x004180d0:	movl %ebp, %esp
0x004180d2:	subl %esp, $0x14<UINT8>
0x004180d5:	movl %eax, 0x42c8e0
0x004180da:	xorl %eax, %ebp
0x004180dc:	movl -4(%ebp), %eax
0x004180df:	pushl %ebx
0x004180e0:	pushl %esi
0x004180e1:	xorl %ebx, %ebx
0x004180e3:	pushl %edi
0x004180e4:	movl %esi, %ecx
0x004180e6:	cmpl 0x430cf8, %ebx
0x004180ec:	jne 0x00418126
0x004180ee:	pushl %ebx
0x004180ef:	pushl %ebx
0x004180f0:	xorl %edi, %edi
0x004180f2:	incl %edi
0x004180f3:	pushl %edi
0x004180f4:	pushl $0x4289fc<UINT32>
0x004180f9:	pushl $0x100<UINT32>
0x004180fe:	pushl %ebx
0x004180ff:	call LCMapStringW@KERNEL32.dll
LCMapStringW@KERNEL32.dll: API Node	
0x00418105:	testl %eax, %eax
0x00418107:	je 8
0x00418109:	movl 0x430cf8, %edi
0x0041810f:	jmp 0x00418126
0x00418126:	cmpl 0x14(%ebp), %ebx
0x00418129:	jle 0x0041814d
0x0041814d:	movl %eax, 0x430cf8
0x00418152:	cmpl %eax, $0x2<UINT8>
0x00418155:	je 428
0x0041815b:	cmpl %eax, %ebx
0x0041815d:	je 420
0x00418163:	cmpl %eax, $0x1<UINT8>
0x00418166:	jne 460
0x0041816c:	movl -8(%ebp), %ebx
0x0041816f:	cmpl 0x20(%ebp), %ebx
0x00418172:	jne 0x0041817c
0x0041817c:	movl %esi, 0x423100
0x00418182:	xorl %eax, %eax
0x00418184:	cmpl 0x24(%ebp), %ebx
0x00418187:	pushl %ebx
0x00418188:	pushl %ebx
0x00418189:	pushl 0x14(%ebp)
0x0041818c:	setne %al
0x0041818f:	pushl 0x10(%ebp)
0x00418192:	leal %eax, 0x1(,%eax,8)
0x00418199:	pushl %eax
0x0041819a:	pushl 0x20(%ebp)
0x0041819d:	call MultiByteToWideChar@KERNEL32.dll
0x0041819f:	movl %edi, %eax
0x004181a1:	cmpl %edi, %ebx
0x004181a3:	je 0x00418338
0x00418338:	xorl %eax, %eax
0x0041833a:	jmp 0x00418460
0x00418460:	leal %esp, -32(%ebp)
0x00418463:	popl %edi
0x00418464:	popl %esi
0x00418465:	popl %ebx
0x00418466:	movl %ecx, -4(%ebp)
0x00418469:	xorl %ecx, %ebp
0x0041846b:	call 0x00407325
0x00418470:	leave
0x00418471:	ret

0x004184a5:	addl %esp, $0x20<UINT8>
0x004184a8:	cmpb -4(%ebp), $0x0<UINT8>
0x004184ac:	je 7
0x004184ae:	movl %ecx, -8(%ebp)
0x004184b1:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x004184b5:	leave
0x004184b6:	ret

0x0040b865:	addl %esp, $0x44<UINT8>
0x0040b868:	pushl %ebx
0x0040b869:	pushl 0x4(%esi)
0x0040b86c:	leal %eax, -772(%ebp)
0x0040b872:	pushl %edi
0x0040b873:	pushl %eax
0x0040b874:	pushl %edi
0x0040b875:	leal %eax, -260(%ebp)
0x0040b87b:	pushl %eax
0x0040b87c:	pushl $0x200<UINT32>
0x0040b881:	pushl 0xc(%esi)
0x0040b884:	pushl %ebx
0x0040b885:	call 0x00418472
0x0040b88a:	addl %esp, $0x24<UINT8>
0x0040b88d:	xorl %eax, %eax
0x0040b88f:	movzwl %ecx, -1284(%ebp,%eax,2)
0x0040b897:	testb %cl, $0x1<UINT8>
0x0040b89a:	je 0x0040b8aa
0x0040b8aa:	testb %cl, $0x2<UINT8>
0x0040b8ad:	je 0x0040b8c4
0x0040b8c4:	movb 0x11d(%esi,%eax), $0x0<UINT8>
0x0040b8cc:	incl %eax
0x0040b8cd:	cmpl %eax, %edi
0x0040b8cf:	jb -66
0x0040b8d1:	jmp 0x0040b929
0x0040b929:	movl %ecx, -4(%ebp)
0x0040b92c:	popl %edi
0x0040b92d:	xorl %ecx, %ebp
0x0040b92f:	popl %ebx
0x0040b930:	call 0x00407325
0x0040b935:	leave
0x0040b936:	ret

0x0040bbcd:	jmp 0x0040ba89
0x0040ba89:	xorl %eax, %eax
0x0040ba8b:	jmp 0x0040bc2d
0x0040bc2d:	movl %ecx, -4(%ebp)
0x0040bc30:	popl %edi
0x0040bc31:	popl %esi
0x0040bc32:	xorl %ecx, %ebp
0x0040bc34:	popl %ebx
0x0040bc35:	call 0x00407325
0x0040bc3a:	leave
0x0040bc3b:	ret

0x0040bcdd:	popl %ecx
0x0040bcde:	popl %ecx
0x0040bcdf:	movl -32(%ebp), %eax
0x0040bce2:	testl %eax, %eax
0x0040bce4:	jne 252
0x0040bcea:	movl %esi, -36(%ebp)
0x0040bced:	pushl 0x68(%esi)
0x0040bcf0:	call InterlockedDecrement@KERNEL32.dll
InterlockedDecrement@KERNEL32.dll: API Node	
0x0040bcf6:	testl %eax, %eax
0x0040bcf8:	jne 17
0x0040bcfa:	movl %eax, 0x68(%esi)
0x0040bcfd:	cmpl %eax, $0x42ccc0<UINT32>
0x0040bd02:	je 0x0040bd0b
0x0040bd0b:	movl 0x68(%esi), %ebx
0x0040bd0e:	pushl %ebx
0x0040bd0f:	movl %edi, 0x4231c0
0x0040bd15:	call InterlockedIncrement@KERNEL32.dll
0x0040bd17:	testb 0x70(%esi), $0x2<UINT8>
0x0040bd1b:	jne 234
0x0040bd21:	testb 0x42d1e4, $0x1<UINT8>
0x0040bd28:	jne 221
0x0040bd2e:	pushl $0xd<UINT8>
0x0040bd30:	call 0x00408671
0x0040bd35:	popl %ecx
0x0040bd36:	andl -4(%ebp), $0x0<UINT8>
0x0040bd3a:	movl %eax, 0x4(%ebx)
0x0040bd3d:	movl 0x430aec, %eax
0x0040bd42:	movl %eax, 0x8(%ebx)
0x0040bd45:	movl 0x430af0, %eax
0x0040bd4a:	movl %eax, 0xc(%ebx)
0x0040bd4d:	movl 0x430af4, %eax
0x0040bd52:	xorl %eax, %eax
0x0040bd54:	movl -28(%ebp), %eax
0x0040bd57:	cmpl %eax, $0x5<UINT8>
0x0040bd5a:	jnl 0x0040bd6c
0x0040bd5c:	movw %cx, 0x10(%ebx,%eax,2)
0x0040bd61:	movw 0x430ae0(,%eax,2), %cx
0x0040bd69:	incl %eax
0x0040bd6a:	jmp 0x0040bd54
0x0040bd6c:	xorl %eax, %eax
0x0040bd6e:	movl -28(%ebp), %eax
0x0040bd71:	cmpl %eax, $0x101<UINT32>
0x0040bd76:	jnl 0x0040bd85
0x0040bd78:	movb %cl, 0x1c(%eax,%ebx)
0x0040bd7c:	movb 0x42cee0(%eax), %cl
0x0040bd82:	incl %eax
0x0040bd83:	jmp 0x0040bd6e
0x0040bd85:	xorl %eax, %eax
0x0040bd87:	movl -28(%ebp), %eax
0x0040bd8a:	cmpl %eax, $0x100<UINT32>
0x0040bd8f:	jnl 0x0040bda1
0x0040bd91:	movb %cl, 0x11d(%eax,%ebx)
0x0040bd98:	movb 0x42cfe8(%eax), %cl
0x0040bd9e:	incl %eax
0x0040bd9f:	jmp 0x0040bd87
0x0040bda1:	pushl 0x42d0e8
0x0040bda7:	call InterlockedDecrement@KERNEL32.dll
0x0040bdad:	testl %eax, %eax
0x0040bdaf:	jne 0x0040bdc4
0x0040bdc4:	movl 0x42d0e8, %ebx
0x0040bdca:	pushl %ebx
0x0040bdcb:	call InterlockedIncrement@KERNEL32.dll
0x0040bdcd:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040bdd4:	call 0x0040bddb
0x0040bddb:	pushl $0xd<UINT8>
0x0040bddd:	call 0x0040857f
0x0040bde2:	popl %ecx
0x0040bde3:	ret

0x0040bdd9:	jmp 0x0040be0b
0x0040be0b:	movl %eax, -32(%ebp)
0x0040be0e:	call 0x00409709
0x0040be13:	ret

0x0040be24:	popl %ecx
0x0040be25:	movl 0x438874, $0x1<UINT32>
0x0040be2f:	xorl %eax, %eax
0x0040be31:	ret

0x0040df61:	pushl $0x104<UINT32>
0x0040df66:	movl %esi, $0x430b30<UINT32>
0x0040df6b:	pushl %esi
0x0040df6c:	pushl %ebx
0x0040df6d:	movb 0x430c34, %bl
0x0040df73:	call GetModuleFileNameA@KERNEL32.dll
GetModuleFileNameA@KERNEL32.dll: API Node	
0x0040df79:	movl %eax, 0x4388a8
0x0040df7e:	movl 0x430480, %esi
0x0040df84:	cmpl %eax, %ebx
0x0040df86:	je 7
0x0040df88:	movl -4(%ebp), %eax
0x0040df8b:	cmpb (%eax), %bl
0x0040df8d:	jne 0x0040df92
0x0040df92:	movl %edx, -4(%ebp)
0x0040df95:	leal %eax, -8(%ebp)
0x0040df98:	pushl %eax
0x0040df99:	pushl %ebx
0x0040df9a:	pushl %ebx
0x0040df9b:	leal %edi, -12(%ebp)
0x0040df9e:	call 0x0040ddad
0x0040ddad:	movl %edi, %edi
0x0040ddaf:	pushl %ebp
0x0040ddb0:	movl %ebp, %esp
0x0040ddb2:	pushl %ecx
0x0040ddb3:	movl %ecx, 0x10(%ebp)
0x0040ddb6:	pushl %ebx
0x0040ddb7:	xorl %eax, %eax
0x0040ddb9:	pushl %esi
0x0040ddba:	movl (%edi), %eax
0x0040ddbc:	movl %esi, %edx
0x0040ddbe:	movl %edx, 0xc(%ebp)
0x0040ddc1:	movl (%ecx), $0x1<UINT32>
0x0040ddc7:	cmpl 0x8(%ebp), %eax
0x0040ddca:	je 0x0040ddd5
0x0040ddd5:	movl -4(%ebp), %eax
0x0040ddd8:	cmpb (%esi), $0x22<UINT8>
0x0040dddb:	jne 0x0040dded
0x0040dddd:	xorl %eax, %eax
0x0040dddf:	cmpl -4(%ebp), %eax
0x0040dde2:	movb %bl, $0x22<UINT8>
0x0040dde4:	sete %al
0x0040dde7:	incl %esi
0x0040dde8:	movl -4(%ebp), %eax
0x0040ddeb:	jmp 0x0040de29
0x0040de29:	cmpl -4(%ebp), $0x0<UINT8>
0x0040de2d:	jne 0x0040ddd8
0x0040dded:	incl (%edi)
0x0040ddef:	testl %edx, %edx
0x0040ddf1:	je 0x0040ddfb
0x0040ddfb:	movb %bl, (%esi)
0x0040ddfd:	movzbl %eax, %bl
0x0040de00:	pushl %eax
0x0040de01:	incl %esi
0x0040de02:	call 0x0041e1d5
0x0041e1d5:	movl %edi, %edi
0x0041e1d7:	pushl %ebp
0x0041e1d8:	movl %ebp, %esp
0x0041e1da:	pushl $0x4<UINT8>
0x0041e1dc:	pushl $0x0<UINT8>
0x0041e1de:	pushl 0x8(%ebp)
0x0041e1e1:	pushl $0x0<UINT8>
0x0041e1e3:	call 0x0041dfc9
0x0041dfc9:	movl %edi, %edi
0x0041dfcb:	pushl %ebp
0x0041dfcc:	movl %ebp, %esp
0x0041dfce:	subl %esp, $0x10<UINT8>
0x0041dfd1:	pushl 0x8(%ebp)
0x0041dfd4:	leal %ecx, -16(%ebp)
0x0041dfd7:	call 0x00407334
0x0041dfdc:	movzbl %eax, 0xc(%ebp)
0x0041dfe0:	movl %ecx, -12(%ebp)
0x0041dfe3:	movb %dl, 0x14(%ebp)
0x0041dfe6:	testb 0x1d(%ecx,%eax), %dl
0x0041dfea:	jne 30
0x0041dfec:	cmpl 0x10(%ebp), $0x0<UINT8>
0x0041dff0:	je 0x0041e004
0x0041e004:	xorl %eax, %eax
0x0041e006:	testl %eax, %eax
0x0041e008:	je 0x0041e00d
0x0041e00d:	cmpb -4(%ebp), $0x0<UINT8>
0x0041e011:	je 7
0x0041e013:	movl %ecx, -8(%ebp)
0x0041e016:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0041e01a:	leave
0x0041e01b:	ret

0x0041e1e8:	addl %esp, $0x10<UINT8>
0x0041e1eb:	popl %ebp
0x0041e1ec:	ret

0x0040de07:	popl %ecx
0x0040de08:	testl %eax, %eax
0x0040de0a:	je 0x0040de1f
0x0040de1f:	movl %edx, 0xc(%ebp)
0x0040de22:	movl %ecx, 0x10(%ebp)
0x0040de25:	testb %bl, %bl
0x0040de27:	je 0x0040de5b
0x0040de2f:	cmpb %bl, $0x20<UINT8>
0x0040de32:	je 5
0x0040de34:	cmpb %bl, $0x9<UINT8>
0x0040de37:	jne 0x0040ddd8
0x0040de5b:	decl %esi
0x0040de5c:	jmp 0x0040de41
0x0040de41:	andl -4(%ebp), $0x0<UINT8>
0x0040de45:	cmpb (%esi), $0x0<UINT8>
0x0040de48:	je 0x0040df37
0x0040df37:	movl %eax, 0x8(%ebp)
0x0040df3a:	popl %esi
0x0040df3b:	popl %ebx
0x0040df3c:	testl %eax, %eax
0x0040df3e:	je 0x0040df43
0x0040df43:	incl (%ecx)
0x0040df45:	leave
0x0040df46:	ret

0x0040dfa3:	movl %eax, -8(%ebp)
0x0040dfa6:	addl %esp, $0xc<UINT8>
0x0040dfa9:	cmpl %eax, $0x3fffffff<UINT32>
0x0040dfae:	jae 74
0x0040dfb0:	movl %ecx, -12(%ebp)
0x0040dfb3:	cmpl %ecx, $0xffffffff<UINT8>
0x0040dfb6:	jae 66
0x0040dfb8:	movl %edi, %eax
0x0040dfba:	shll %edi, $0x2<UINT8>
0x0040dfbd:	leal %eax, (%edi,%ecx)
0x0040dfc0:	cmpl %eax, %ecx
0x0040dfc2:	jb 54
0x0040dfc4:	pushl %eax
0x0040dfc5:	call 0x004139be
0x0040dfca:	movl %esi, %eax
0x0040dfcc:	popl %ecx
0x0040dfcd:	cmpl %esi, %ebx
0x0040dfcf:	je 41
0x0040dfd1:	movl %edx, -4(%ebp)
0x0040dfd4:	leal %eax, -8(%ebp)
0x0040dfd7:	pushl %eax
0x0040dfd8:	addl %edi, %esi
0x0040dfda:	pushl %edi
0x0040dfdb:	pushl %esi
0x0040dfdc:	leal %edi, -12(%ebp)
0x0040dfdf:	call 0x0040ddad
0x0040ddcc:	movl %ebx, 0x8(%ebp)
0x0040ddcf:	addl 0x8(%ebp), $0x4<UINT8>
0x0040ddd3:	movl (%ebx), %edx
0x0040ddf3:	movb %al, (%esi)
0x0040ddf5:	movb (%edx), %al
0x0040ddf7:	incl %edx
0x0040ddf8:	movl 0xc(%ebp), %edx
0x0040df40:	andl (%eax), $0x0<UINT8>
0x0040dfe4:	movl %eax, -8(%ebp)
0x0040dfe7:	addl %esp, $0xc<UINT8>
0x0040dfea:	decl %eax
0x0040dfeb:	movl 0x430464, %eax
0x0040dff0:	movl 0x430468, %esi
0x0040dff6:	xorl %eax, %eax
0x0040dff8:	jmp 0x0040dffd
0x0040dffd:	popl %edi
0x0040dffe:	popl %esi
0x0040dfff:	popl %ebx
0x0040e000:	leave
0x0040e001:	ret

0x004079af:	testl %eax, %eax
0x004079b1:	jnl 0x004079bb
0x004079bb:	call 0x0040dcc0
0x0040dcc0:	cmpl 0x438874, $0x0<UINT8>
0x0040dcc7:	jne 0x0040dcce
0x0040dcce:	pushl %esi
0x0040dccf:	movl %esi, 0x4302ec
0x0040dcd5:	pushl %edi
0x0040dcd6:	xorl %edi, %edi
0x0040dcd8:	testl %esi, %esi
0x0040dcda:	jne 0x0040dcf4
0x0040dcf4:	movb %al, (%esi)
0x0040dcf6:	testb %al, %al
0x0040dcf8:	jne 0x0040dce4
0x0040dce4:	cmpb %al, $0x3d<UINT8>
0x0040dce6:	je 0x0040dce9
0x0040dce9:	pushl %esi
0x0040dcea:	call 0x0040d9d0
0x0040d9d0:	movl %ecx, 0x4(%esp)
0x0040d9d4:	testl %ecx, $0x3<UINT32>
0x0040d9da:	je 0x0040da00
0x0040da00:	movl %eax, (%ecx)
0x0040da02:	movl %edx, $0x7efefeff<UINT32>
0x0040da07:	addl %edx, %eax
0x0040da09:	xorl %eax, $0xffffffff<UINT8>
0x0040da0c:	xorl %eax, %edx
0x0040da0e:	addl %ecx, $0x4<UINT8>
0x0040da11:	testl %eax, $0x81010100<UINT32>
0x0040da16:	je 0x0040da00
0x0040da18:	movl %eax, -4(%ecx)
0x0040da1b:	testb %al, %al
0x0040da1d:	je 50
0x0040da1f:	testb %ah, %ah
0x0040da21:	je 36
0x0040da23:	testl %eax, $0xff0000<UINT32>
0x0040da28:	je 19
0x0040da2a:	testl %eax, $0xff000000<UINT32>
0x0040da2f:	je 0x0040da33
0x0040da33:	leal %eax, -1(%ecx)
0x0040da36:	movl %ecx, 0x4(%esp)
0x0040da3a:	subl %eax, %ecx
0x0040da3c:	ret

0x0040dcef:	popl %ecx
0x0040dcf0:	leal %esi, 0x1(%esi,%eax)
0x0040dcfa:	pushl $0x4<UINT8>
0x0040dcfc:	incl %edi
0x0040dcfd:	pushl %edi
0x0040dcfe:	call 0x00413a03
0x0040dd03:	movl %edi, %eax
0x0040dd05:	popl %ecx
0x0040dd06:	popl %ecx
0x0040dd07:	movl 0x430470, %edi
0x0040dd0d:	testl %edi, %edi
0x0040dd0f:	je -53
0x0040dd11:	movl %esi, 0x4302ec
0x0040dd17:	pushl %ebx
0x0040dd18:	jmp 0x0040dd5c
0x0040dd5c:	cmpb (%esi), $0x0<UINT8>
0x0040dd5f:	jne 0x0040dd1a
0x0040dd1a:	pushl %esi
0x0040dd1b:	call 0x0040d9d0
0x0040dd20:	movl %ebx, %eax
0x0040dd22:	incl %ebx
0x0040dd23:	cmpb (%esi), $0x3d<UINT8>
0x0040dd26:	popl %ecx
0x0040dd27:	je 0x0040dd5a
0x0040dd5a:	addl %esi, %ebx
0x0040dd61:	pushl 0x4302ec
0x0040dd67:	call 0x004070e5
0x004070e5:	pushl $0xc<UINT8>
0x004070e7:	pushl $0x429f38<UINT32>
0x004070ec:	call 0x004096c4
0x004070f1:	movl %esi, 0x8(%ebp)
0x004070f4:	testl %esi, %esi
0x004070f6:	je 117
0x004070f8:	cmpl 0x438880, $0x3<UINT8>
0x004070ff:	jne 0x00407144
0x00407144:	pushl %esi
0x00407145:	pushl $0x0<UINT8>
0x00407147:	pushl 0x43045c
0x0040714d:	call HeapFree@KERNEL32.dll
HeapFree@KERNEL32.dll: API Node	
0x00407153:	testl %eax, %eax
0x00407155:	jne 0x0040716d
0x0040716d:	call 0x00409709
0x00407172:	ret

0x0040dd6c:	andl 0x4302ec, $0x0<UINT8>
0x0040dd73:	andl (%edi), $0x0<UINT8>
0x0040dd76:	movl 0x438868, $0x1<UINT32>
0x0040dd80:	xorl %eax, %eax
0x0040dd82:	popl %ecx
0x0040dd83:	popl %ebx
0x0040dd84:	popl %edi
0x0040dd85:	popl %esi
0x0040dd86:	ret

0x004079c0:	testl %eax, %eax
0x004079c2:	jnl 0x004079cc
0x004079cc:	pushl %ebx
0x004079cd:	call 0x00409af1
0x00409af1:	movl %edi, %edi
0x00409af3:	pushl %ebp
0x00409af4:	movl %ebp, %esp
0x00409af6:	cmpl 0x438878, $0x0<UINT8>
0x00409afd:	je 0x00409b18
0x00409b18:	call 0x004140cd
0x004140cd:	movl %edi, %edi
0x004140cf:	pushl %esi
0x004140d0:	pushl %edi
0x004140d1:	xorl %edi, %edi
0x004140d3:	leal %esi, 0x42d330(%edi)
0x004140d9:	pushl (%esi)
0x004140db:	call 0x0040d0f5
0x0040d117:	pushl %eax
0x0040d118:	pushl 0x42d2dc
0x0040d11e:	call TlsGetValue@KERNEL32.dll
0x0040d120:	call FlsGetValue@KERNEL32.DLL
0x0040d122:	testl %eax, %eax
0x0040d124:	je 8
0x0040d126:	movl %eax, 0x1f8(%eax)
0x0040d12c:	jmp 0x0040d155
0x004140e0:	addl %edi, $0x4<UINT8>
0x004140e3:	popl %ecx
0x004140e4:	movl (%esi), %eax
0x004140e6:	cmpl %edi, $0x28<UINT8>
0x004140e9:	jb 0x004140d3
0x004140eb:	popl %edi
0x004140ec:	popl %esi
0x004140ed:	ret

0x00409b1d:	pushl $0x423354<UINT32>
0x00409b22:	pushl $0x42333c<UINT32>
0x00409b27:	call 0x00409a55
0x00409a55:	movl %edi, %edi
0x00409a57:	pushl %ebp
0x00409a58:	movl %ebp, %esp
0x00409a5a:	pushl %esi
0x00409a5b:	movl %esi, 0x8(%ebp)
0x00409a5e:	xorl %eax, %eax
0x00409a60:	jmp 0x00409a71
0x00409a71:	cmpl %esi, 0xc(%ebp)
0x00409a74:	jb 0x00409a62
0x00409a62:	testl %eax, %eax
0x00409a64:	jne 16
0x00409a66:	movl %ecx, (%esi)
0x00409a68:	testl %ecx, %ecx
0x00409a6a:	je 0x00409a6e
0x00409a6e:	addl %esi, $0x4<UINT8>
0x00409a6c:	call 0x0040da9d
0x004081e5:	movl %edi, %edi
0x004081e7:	pushl %esi
0x004081e8:	pushl $0x4<UINT8>
0x004081ea:	pushl $0x20<UINT8>
0x004081ec:	call 0x00413a03
0x004081f1:	movl %esi, %eax
0x004081f3:	pushl %esi
0x004081f4:	call 0x0040d0f5
0x004081f9:	addl %esp, $0xc<UINT8>
0x004081fc:	movl 0x438870, %eax
0x00408201:	movl 0x43886c, %eax
0x00408206:	testl %esi, %esi
0x00408208:	jne 0x0040820f
0x0040820f:	andl (%esi), $0x0<UINT8>
0x00408212:	xorl %eax, %eax
0x00408214:	popl %esi
0x00408215:	ret

0x004084d0:	call 0x0040846e
0x0040846e:	movl %edi, %edi
0x00408470:	pushl %ebp
0x00408471:	movl %ebp, %esp
0x00408473:	subl %esp, $0x18<UINT8>
0x00408476:	xorl %eax, %eax
0x00408478:	pushl %ebx
0x00408479:	movl -4(%ebp), %eax
0x0040847c:	movl -12(%ebp), %eax
0x0040847f:	movl -8(%ebp), %eax
0x00408482:	pushl %ebx
0x00408483:	pushfl
0x00408484:	popl %eax
0x00408485:	movl %ecx, %eax
0x00408487:	xorl %eax, $0x200000<UINT32>
0x0040848c:	pushl %eax
0x0040848d:	popfl
0x0040848e:	pushfl
0x0040848f:	popl %edx
0x00408490:	subl %edx, %ecx
0x00408492:	je 0x004084b3
0x004084b3:	popl %ebx
0x004084b4:	testl -4(%ebp), $0x4000000<UINT32>
0x004084bb:	je 0x004084cb
0x004084cb:	xorl %eax, %eax
0x004084cd:	popl %ebx
0x004084ce:	leave
0x004084cf:	ret

0x004084d5:	movl 0x4388a4, %eax
0x004084da:	xorl %eax, %eax
0x004084dc:	ret

0x00415676:	movl %eax, 0x438740
0x0041567b:	pushl %esi
0x0041567c:	pushl $0x14<UINT8>
0x0041567e:	popl %esi
0x0041567f:	testl %eax, %eax
0x00415681:	jne 7
0x00415683:	movl %eax, $0x200<UINT32>
0x00415688:	jmp 0x00415690
0x00415690:	movl 0x438740, %eax
0x00415695:	pushl $0x4<UINT8>
0x00415697:	pushl %eax
0x00415698:	call 0x00413a03
0x0041569d:	popl %ecx
0x0041569e:	popl %ecx
0x0041569f:	movl 0x437730, %eax
0x004156a4:	testl %eax, %eax
0x004156a6:	jne 0x004156c6
0x004156c6:	xorl %edx, %edx
0x004156c8:	movl %ecx, $0x42d358<UINT32>
0x004156cd:	jmp 0x004156d4
0x004156d4:	movl (%edx,%eax), %ecx
0x004156d7:	addl %ecx, $0x20<UINT8>
0x004156da:	addl %edx, $0x4<UINT8>
0x004156dd:	cmpl %ecx, $0x42d5d8<UINT32>
0x004156e3:	jl 0x004156cf
0x004156cf:	movl %eax, 0x437730
0x004156e5:	pushl $0xfffffffe<UINT8>
0x004156e7:	popl %esi
0x004156e8:	xorl %edx, %edx
0x004156ea:	movl %ecx, $0x42d368<UINT32>
0x004156ef:	pushl %edi
0x004156f0:	movl %eax, %edx
0x004156f2:	sarl %eax, $0x5<UINT8>
0x004156f5:	movl %eax, 0x438760(,%eax,4)
0x004156fc:	movl %edi, %edx
0x004156fe:	andl %edi, $0x1f<UINT8>
0x00415701:	shll %edi, $0x6<UINT8>
0x00415704:	movl %eax, (%edi,%eax)
0x00415707:	cmpl %eax, $0xffffffff<UINT8>
0x0041570a:	je 8
0x0041570c:	cmpl %eax, %esi
0x0041570e:	je 4
0x00415710:	testl %eax, %eax
0x00415712:	jne 0x00415716
0x00415716:	addl %ecx, $0x20<UINT8>
0x00415719:	incl %edx
0x0041571a:	cmpl %ecx, $0x42d3c8<UINT32>
0x00415720:	jl 0x004156f0
0x00415722:	popl %edi
0x00415723:	xorl %eax, %eax
0x00415725:	popl %esi
0x00415726:	ret

0x0040da9d:	pushl $0x40da5b<UINT32>
0x0040daa2:	call SetUnhandledExceptionFilter@KERNEL32.dll
SetUnhandledExceptionFilter@KERNEL32.dll: API Node	
0x0040daa8:	xorl %eax, %eax
0x0040daaa:	ret

0x00409a76:	popl %esi
0x00409a77:	popl %ebp
0x00409a78:	ret

0x00409b2c:	popl %ecx
0x00409b2d:	popl %ecx
0x00409b2e:	testl %eax, %eax
0x00409b30:	jne 66
0x00409b32:	pushl $0x40e401<UINT32>
0x00409b37:	call 0x00408252
0x00408252:	movl %edi, %edi
0x00408254:	pushl %ebp
0x00408255:	movl %ebp, %esp
0x00408257:	pushl 0x8(%ebp)
0x0040825a:	call 0x00408216
0x00408216:	pushl $0xc<UINT8>
0x00408218:	pushl $0x42a020<UINT32>
0x0040821d:	call 0x004096c4
0x00408222:	call 0x00409a26
0x00409a26:	pushl $0x8<UINT8>
0x00409a28:	call 0x00408671
0x00409a2d:	popl %ecx
0x00409a2e:	ret

0x00408227:	andl -4(%ebp), $0x0<UINT8>
0x0040822b:	pushl 0x8(%ebp)
0x0040822e:	call 0x0040812b
0x0040812b:	movl %edi, %edi
0x0040812d:	pushl %ebp
0x0040812e:	movl %ebp, %esp
0x00408130:	pushl %ecx
0x00408131:	pushl %ebx
0x00408132:	pushl %esi
0x00408133:	pushl %edi
0x00408134:	pushl 0x438870
0x0040813a:	call 0x0040d170
0x0040d1a1:	movl %eax, 0x1fc(%eax)
0x0040d1a7:	jmp 0x0040d1d0
0x0040813f:	pushl 0x43886c
0x00408145:	movl %edi, %eax
0x00408147:	movl -4(%ebp), %edi
0x0040814a:	call 0x0040d170
0x0040814f:	movl %esi, %eax
0x00408151:	popl %ecx
0x00408152:	popl %ecx
0x00408153:	cmpl %esi, %edi
0x00408155:	jb 131
0x0040815b:	movl %ebx, %esi
0x0040815d:	subl %ebx, %edi
0x0040815f:	leal %eax, 0x4(%ebx)
0x00408162:	cmpl %eax, $0x4<UINT8>
0x00408165:	jb 119
0x00408167:	pushl %edi
0x00408168:	call 0x00413aef
0x00413aef:	pushl $0x10<UINT8>
0x00413af1:	pushl $0x42a238<UINT32>
0x00413af6:	call 0x004096c4
0x00413afb:	xorl %eax, %eax
0x00413afd:	movl %ebx, 0x8(%ebp)
0x00413b00:	xorl %edi, %edi
0x00413b02:	cmpl %ebx, %edi
0x00413b04:	setne %al
0x00413b07:	cmpl %eax, %edi
0x00413b09:	jne 0x00413b28
0x00413b28:	cmpl 0x438880, $0x3<UINT8>
0x00413b2f:	jne 0x00413b69
0x00413b69:	pushl %ebx
0x00413b6a:	pushl %edi
0x00413b6b:	pushl 0x43045c
0x00413b71:	call HeapSize@KERNEL32.dll
HeapSize@KERNEL32.dll: API Node	
0x00413b77:	movl %esi, %eax
0x00413b79:	movl %eax, %esi
0x00413b7b:	call 0x00409709
0x00413b80:	ret

0x0040816d:	movl %edi, %eax
0x0040816f:	leal %eax, 0x4(%ebx)
0x00408172:	popl %ecx
0x00408173:	cmpl %edi, %eax
0x00408175:	jae 0x004081bf
0x004081bf:	pushl 0x8(%ebp)
0x004081c2:	call 0x0040d0f5
0x004081c7:	movl (%esi), %eax
0x004081c9:	addl %esi, $0x4<UINT8>
0x004081cc:	pushl %esi
0x004081cd:	call 0x0040d0f5
0x004081d2:	popl %ecx
0x004081d3:	movl 0x43886c, %eax
0x004081d8:	movl %eax, 0x8(%ebp)
0x004081db:	popl %ecx
0x004081dc:	jmp 0x004081e0
0x004081e0:	popl %edi
0x004081e1:	popl %esi
0x004081e2:	popl %ebx
0x004081e3:	leave
0x004081e4:	ret

0x00408233:	popl %ecx
0x00408234:	movl -28(%ebp), %eax
0x00408237:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040823e:	call 0x0040824c
0x0040824c:	call 0x00409a2f
0x00409a2f:	pushl $0x8<UINT8>
0x00409a31:	call 0x0040857f
0x00409a36:	popl %ecx
0x00409a37:	ret

0x00408251:	ret

0x00408243:	movl %eax, -28(%ebp)
0x00408246:	call 0x00409709
0x0040824b:	ret

0x0040825f:	negl %eax
0x00408261:	sbbl %eax, %eax
0x00408263:	negl %eax
0x00408265:	popl %ecx
0x00408266:	decl %eax
0x00408267:	popl %ebp
0x00408268:	ret

0x00409b3c:	movl %eax, $0x423334<UINT32>
0x00409b41:	movl (%esp), $0x423338<UINT32>
0x00409b48:	call 0x00409a38
0x00409a38:	movl %edi, %edi
0x00409a3a:	pushl %ebp
0x00409a3b:	movl %ebp, %esp
0x00409a3d:	pushl %esi
0x00409a3e:	movl %esi, %eax
0x00409a40:	jmp 0x00409a4d
0x00409a4d:	cmpl %esi, 0x8(%ebp)
0x00409a50:	jb 0x00409a42
0x00409a42:	movl %eax, (%esi)
0x00409a44:	testl %eax, %eax
0x00409a46:	je 0x00409a4a
0x00409a4a:	addl %esi, $0x4<UINT8>
0x00409a52:	popl %esi
0x00409a53:	popl %ebp
0x00409a54:	ret

0x00409b4d:	cmpl 0x43887c, $0x0<UINT8>
0x00409b54:	popl %ecx
0x00409b55:	je 0x00409b72
0x00409b72:	xorl %eax, %eax
0x00409b74:	popl %ebp
0x00409b75:	ret

0x004079d2:	popl %ecx
0x004079d3:	cmpl %eax, %esi
0x004079d5:	je 0x004079de
0x004079de:	call 0x0040dc61
0x0040dc61:	movl %edi, %edi
0x0040dc63:	pushl %esi
0x0040dc64:	pushl %edi
0x0040dc65:	xorl %edi, %edi
0x0040dc67:	cmpl 0x438874, %edi
0x0040dc6d:	jne 0x0040dc74
0x0040dc74:	movl %esi, 0x4388a8
0x0040dc7a:	testl %esi, %esi
0x0040dc7c:	jne 0x0040dc83
0x0040dc83:	movb %al, (%esi)
0x0040dc85:	cmpb %al, $0x20<UINT8>
0x0040dc87:	ja 0x0040dc91
0x0040dc91:	cmpb %al, $0x22<UINT8>
0x0040dc93:	jne 0x0040dc9e
0x0040dc95:	xorl %ecx, %ecx
0x0040dc97:	testl %edi, %edi
0x0040dc99:	sete %cl
0x0040dc9c:	movl %edi, %ecx
0x0040dc9e:	movzbl %eax, %al
0x0040dca1:	pushl %eax
0x0040dca2:	call 0x0041e1d5
0x0040dca7:	popl %ecx
0x0040dca8:	testl %eax, %eax
0x0040dcaa:	je 0x0040dcad
0x0040dcad:	incl %esi
0x0040dcae:	jmp 0x0040dc83
0x0040dc89:	testb %al, %al
0x0040dc8b:	je 0x0040dcbb
0x0040dcbb:	popl %edi
0x0040dcbc:	movl %eax, %esi
0x0040dcbe:	popl %esi
0x0040dcbf:	ret

0x004079e3:	testb -60(%ebp), %bl
0x004079e6:	je 0x004079ee
0x004079ee:	pushl $0xa<UINT8>
0x004079f0:	popl %ecx
0x004079f1:	pushl %ecx
0x004079f2:	pushl %eax
0x004079f3:	pushl %esi
0x004079f4:	pushl $0x400000<UINT32>
0x004079f9:	call 0x00406500
0x00406500:	subl %esp, $0x424<UINT32>
0x00406506:	movl %eax, 0x42c8e0
0x0040650b:	xorl %eax, %esp
0x0040650d:	movl 0x420(%esp), %eax
0x00406514:	pushl %ebp
0x00406515:	movl %ebp, 0x42c(%esp)
0x0040651c:	pushl %esi
0x0040651d:	xorl %esi, %esi
0x0040651f:	pushl %esi
0x00406520:	pushl %esi
0x00406521:	pushl $0x426920<UINT32>
0x00406526:	call 0x00401d60
0x00401d60:	pushl %ebx
0x00401d61:	movl %ebx, 0xc(%esp)
0x00401d65:	pushl %ebp
0x00401d66:	xorl %ebp, %ebp
0x00401d68:	pushl %edi
0x00401d69:	testl %ebx, %ebx
0x00401d6b:	je 0x00401df4
0x00401df4:	popl %edi
0x00401df5:	popl %ebp
0x00401df6:	popl %ebx
0x00401df7:	movl 0xc(%esp), $0x0<UINT32>
0x00401dff:	movl 0x8(%esp), $0x0<UINT32>
0x00401e07:	jmp 0x00401c90
0x00401c90:	pushl %ebx
0x00401c91:	movl %ebx, 0xc(%esp)
0x00401c95:	pushl %ebp
0x00401c96:	pushl %esi
0x00401c97:	xorl %ebp, %ebp
0x00401c99:	pushl %edi
0x00401c9a:	testl %ebx, %ebx
0x00401c9c:	je 0x00401ca6
0x00401ca6:	pushl $0x425a44<UINT32>
0x00401cab:	pushl $0x425a38<UINT32>
0x00401cb0:	call LoadLibraryA@KERNEL32.dll
0x00401cb6:	pushl %eax
0x00401cb7:	call GetProcAddress@KERNEL32.dll
0x00401cbd:	movl %esi, %eax
0x00401cbf:	testl %esi, %esi
0x00401cc1:	je 110
0x00401cc3:	movl %ebx, $0x42d840<UINT32>
0x00401cc8:	pushl %ebx
0x00401cc9:	call GetCommandLineW@KERNEL32.dll
GetCommandLineW@KERNEL32.dll: API Node	
0x00401ccf:	pushl %eax
0x00401cd0:	call CommandLineToArgvW@Shell32.dll
CommandLineToArgvW@Shell32.dll: API Node	
0x00401cd2:	movl %edi, %eax
0x00401cd4:	xorl %esi, %esi
0x00401cd6:	cmpl (%ebx), %ebp
0x00401cd8:	jle 0x00401d31
0x00401d31:	movl %edx, 0x14(%esp)
0x00401d35:	pushl %ebp
0x00401d36:	pushl %edx
0x00401d37:	call 0x00401900
0x00401900:	subl %esp, $0x110<UINT32>
0x00401906:	movl %eax, 0x42c8e0
0x0040190b:	xorl %eax, %esp
0x0040190d:	movl 0x10c(%esp), %eax
0x00401914:	pushl %ebp
0x00401915:	movl %ebp, 0x118(%esp)
0x0040191c:	pushl %ebp
0x0040191d:	leal %eax, 0x10(%esp)
0x00401921:	pushl $0x4259ec<UINT32>
0x00401926:	pushl %eax
0x00401927:	movl 0x10(%esp), $0x0<UINT32>
0x0040192f:	call 0x00407173
0x00407173:	movl %edi, %edi
0x00407175:	pushl %ebp
0x00407176:	movl %ebp, %esp
0x00407178:	subl %esp, $0x20<UINT8>
0x0040717b:	pushl %ebx
0x0040717c:	xorl %ebx, %ebx
0x0040717e:	cmpl 0xc(%ebp), %ebx
0x00407181:	jne 0x004071a0
0x004071a0:	movl %eax, 0x8(%ebp)
0x004071a3:	cmpl %eax, %ebx
0x004071a5:	je -36
0x004071a7:	pushl %esi
0x004071a8:	movl -24(%ebp), %eax
0x004071ab:	movl -32(%ebp), %eax
0x004071ae:	leal %eax, 0x10(%ebp)
0x004071b1:	pushl %eax
0x004071b2:	pushl %ebx
0x004071b3:	pushl 0xc(%ebp)
0x004071b6:	leal %eax, -32(%ebp)
0x004071b9:	pushl %eax
0x004071ba:	movl -28(%ebp), $0x7fffffff<UINT32>
0x004071c1:	movl -20(%ebp), $0x42<UINT32>
0x004071c8:	call 0x0040a41d
0x0040a41d:	movl %edi, %edi
0x0040a41f:	pushl %ebp
0x0040a420:	movl %ebp, %esp
0x0040a422:	subl %esp, $0x278<UINT32>
0x0040a428:	movl %eax, 0x42c8e0
0x0040a42d:	xorl %eax, %ebp
0x0040a42f:	movl -4(%ebp), %eax
0x0040a432:	pushl %ebx
0x0040a433:	movl %ebx, 0xc(%ebp)
0x0040a436:	pushl %esi
0x0040a437:	movl %esi, 0x8(%ebp)
0x0040a43a:	xorl %eax, %eax
0x0040a43c:	pushl %edi
0x0040a43d:	movl %edi, 0x14(%ebp)
0x0040a440:	pushl 0x10(%ebp)
0x0040a443:	leal %ecx, -604(%ebp)
0x0040a449:	movl -588(%ebp), %esi
0x0040a44f:	movl -548(%ebp), %edi
0x0040a455:	movl -584(%ebp), %eax
0x0040a45b:	movl -528(%ebp), %eax
0x0040a461:	movl -564(%ebp), %eax
0x0040a467:	movl -536(%ebp), %eax
0x0040a46d:	movl -560(%ebp), %eax
0x0040a473:	movl -576(%ebp), %eax
0x0040a479:	movl -568(%ebp), %eax
0x0040a47f:	call 0x00407334
0x0040a484:	testl %esi, %esi
0x0040a486:	jne 0x0040a4bd
0x0040a4bd:	testb 0xc(%esi), $0x40<UINT8>
0x0040a4c1:	jne 0x0040a521
0x0040a521:	xorl %ecx, %ecx
0x0040a523:	cmpl %ebx, %ecx
0x0040a525:	je -163
0x0040a52b:	movb %dl, (%ebx)
0x0040a52d:	movl -552(%ebp), %ecx
0x0040a533:	movl -544(%ebp), %ecx
0x0040a539:	movl -580(%ebp), %ecx
0x0040a53f:	movb -529(%ebp), %dl
0x0040a545:	testb %dl, %dl
0x0040a547:	je 2591
0x0040a54d:	incl %ebx
0x0040a54e:	cmpl -552(%ebp), $0x0<UINT8>
0x0040a555:	movl -572(%ebp), %ebx
0x0040a55b:	jl 2571
0x0040a561:	movb %al, %dl
0x0040a563:	subb %al, $0x20<UINT8>
0x0040a565:	cmpb %al, $0x58<UINT8>
0x0040a567:	ja 0x0040a57a
0x0040a569:	movsbl %eax, %dl
0x0040a56c:	movsbl %eax, 0x427bd8(%eax)
0x0040a573:	andl %eax, $0xf<UINT8>
0x0040a576:	xorl %esi, %esi
0x0040a578:	jmp 0x0040a57e
0x0040a57e:	movsbl %eax, 0x427bf8(%ecx,%eax,8)
0x0040a586:	pushl $0x7<UINT8>
0x0040a588:	sarl %eax, $0x4<UINT8>
0x0040a58b:	popl %ecx
0x0040a58c:	movl -620(%ebp), %eax
0x0040a592:	cmpl %eax, %ecx
0x0040a594:	ja 2477
0x0040a59a:	jmp 0x0040a7fa
0x0040a7a0:	leal %eax, -604(%ebp)
0x0040a7a6:	pushl %eax
0x0040a7a7:	movzbl %eax, %dl
0x0040a7aa:	pushl %eax
0x0040a7ab:	movl -568(%ebp), %esi
0x0040a7b1:	call 0x00415bcd
0x00415bcd:	movl %edi, %edi
0x00415bcf:	pushl %ebp
0x00415bd0:	movl %ebp, %esp
0x00415bd2:	subl %esp, $0x10<UINT8>
0x00415bd5:	pushl 0xc(%ebp)
0x00415bd8:	leal %ecx, -16(%ebp)
0x00415bdb:	call 0x00407334
0x004073aa:	movl %ecx, (%eax)
0x004073ac:	movl (%esi), %ecx
0x004073ae:	movl %eax, 0x4(%eax)
0x004073b1:	movl 0x4(%esi), %eax
0x00415be0:	movzbl %eax, 0x8(%ebp)
0x00415be4:	movl %ecx, -16(%ebp)
0x00415be7:	movl %ecx, 0xc8(%ecx)
0x00415bed:	movzwl %eax, (%ecx,%eax,2)
0x00415bf1:	andl %eax, $0x8000<UINT32>
0x00415bf6:	cmpb -4(%ebp), $0x0<UINT8>
0x00415bfa:	je 0x00415c03
0x00415c03:	leave
0x00415c04:	ret

0x0040a7b6:	popl %ecx
0x0040a7b7:	testl %eax, %eax
0x0040a7b9:	movb %al, -529(%ebp)
0x0040a7bf:	popl %ecx
0x0040a7c0:	je 0x0040a7e4
0x0040a7e4:	movl %ecx, -588(%ebp)
0x0040a7ea:	leal %esi, -552(%ebp)
0x0040a7f0:	call 0x0040a33d
0x0040a33d:	testb 0xc(%ecx), $0x40<UINT8>
0x0040a341:	je 6
0x0040a343:	cmpl 0x8(%ecx), $0x0<UINT8>
0x0040a347:	je 36
0x0040a349:	decl 0x4(%ecx)
0x0040a34c:	js 11
0x0040a34e:	movl %edx, (%ecx)
0x0040a350:	movb (%edx), %al
0x0040a352:	incl (%ecx)
0x0040a354:	movzbl %eax, %al
0x0040a357:	jmp 0x0040a365
0x0040a365:	cmpl %eax, $0xffffffff<UINT8>
0x0040a368:	jne 0x0040a36d
0x0040a36d:	incl (%esi)
0x0040a36f:	ret

0x0040a7f5:	jmp 0x0040af47
0x0040af47:	movl %ebx, -572(%ebp)
0x0040af4d:	movb %al, (%ebx)
0x0040af4f:	movb -529(%ebp), %al
0x0040af55:	testb %al, %al
0x0040af57:	je 0x0040af6c
0x0040af59:	movl %ecx, -620(%ebp)
0x0040af5f:	movl %edi, -548(%ebp)
0x0040af65:	movb %dl, %al
0x0040af67:	jmp 0x0040a54d
0x0040a57a:	xorl %esi, %esi
0x0040a57c:	xorl %eax, %eax
0x0040a5a1:	orl -536(%ebp), $0xffffffff<UINT8>
0x0040a5a8:	movl -624(%ebp), %esi
0x0040a5ae:	movl -576(%ebp), %esi
0x0040a5b4:	movl -564(%ebp), %esi
0x0040a5ba:	movl -560(%ebp), %esi
0x0040a5c0:	movl -528(%ebp), %esi
0x0040a5c6:	movl -568(%ebp), %esi
0x0040a5cc:	jmp 0x0040af47
0x0040a7fa:	movsbl %eax, %dl
0x0040a7fd:	cmpl %eax, $0x64<UINT8>
0x0040a800:	jg 0x0040a9ee
0x0040a9ee:	cmpl %eax, $0x70<UINT8>
0x0040a9f1:	jg 0x0040abf2
0x0040abf2:	subl %eax, $0x73<UINT8>
0x0040abf5:	je 0x0040a8b1
0x0040a8b1:	movl %ecx, -536(%ebp)
0x0040a8b7:	cmpl %ecx, $0xffffffff<UINT8>
0x0040a8ba:	jne 5
0x0040a8bc:	movl %ecx, $0x7fffffff<UINT32>
0x0040a8c1:	addl %edi, $0x4<UINT8>
0x0040a8c4:	testl -528(%ebp), $0x810<UINT32>
0x0040a8ce:	movl -548(%ebp), %edi
0x0040a8d4:	movl %edi, -4(%edi)
0x0040a8d7:	movl -540(%ebp), %edi
0x0040a8dd:	je 0x0040ad94
0x0040ad94:	cmpl %edi, %esi
0x0040ad96:	jne 0x0040ada3
0x0040ada3:	movl %eax, -540(%ebp)
0x0040ada9:	jmp 0x0040adb2
0x0040adb2:	cmpl %ecx, %esi
0x0040adb4:	jne 0x0040adab
0x0040adab:	decl %ecx
0x0040adac:	cmpb (%eax), $0x0<UINT8>
0x0040adaf:	je 0x0040adb6
0x0040adb1:	incl %eax
0x0040adb6:	subl %eax, -540(%ebp)
0x0040adbc:	movl -544(%ebp), %eax
0x0040adc2:	cmpl -576(%ebp), $0x0<UINT8>
0x0040adc9:	jne 348
0x0040adcf:	movl %eax, -528(%ebp)
0x0040add5:	testb %al, $0x40<UINT8>
0x0040add7:	je 0x0040ae0b
0x0040ae0b:	movl %ebx, -564(%ebp)
0x0040ae11:	subl %ebx, -544(%ebp)
0x0040ae17:	subl %ebx, -560(%ebp)
0x0040ae1d:	testb -528(%ebp), $0xc<UINT8>
0x0040ae24:	jne 23
0x0040ae26:	pushl -588(%ebp)
0x0040ae2c:	leal %eax, -552(%ebp)
0x0040ae32:	pushl %ebx
0x0040ae33:	pushl $0x20<UINT8>
0x0040ae35:	call 0x0040a370
0x0040a370:	movl %edi, %edi
0x0040a372:	pushl %ebp
0x0040a373:	movl %ebp, %esp
0x0040a375:	pushl %esi
0x0040a376:	movl %esi, %eax
0x0040a378:	jmp 0x0040a38d
0x0040a38d:	cmpl 0xc(%ebp), $0x0<UINT8>
0x0040a391:	jg -25
0x0040a393:	popl %esi
0x0040a394:	popl %ebp
0x0040a395:	ret

0x0040ae3a:	addl %esp, $0xc<UINT8>
0x0040ae3d:	pushl -560(%ebp)
0x0040ae43:	movl %edi, -588(%ebp)
0x0040ae49:	leal %eax, -552(%ebp)
0x0040ae4f:	leal %ecx, -556(%ebp)
0x0040ae55:	call 0x0040a396
0x0040a396:	movl %edi, %edi
0x0040a398:	pushl %ebp
0x0040a399:	movl %ebp, %esp
0x0040a39b:	testb 0xc(%edi), $0x40<UINT8>
0x0040a39f:	pushl %ebx
0x0040a3a0:	pushl %esi
0x0040a3a1:	movl %esi, %eax
0x0040a3a3:	movl %ebx, %ecx
0x0040a3a5:	je 50
0x0040a3a7:	cmpl 0x8(%edi), $0x0<UINT8>
0x0040a3ab:	jne 0x0040a3d9
0x0040a3d9:	cmpl 0x8(%ebp), $0x0<UINT8>
0x0040a3dd:	jg 0x0040a3b4
0x0040a3df:	popl %esi
0x0040a3e0:	popl %ebx
0x0040a3e1:	popl %ebp
0x0040a3e2:	ret

0x0040ae5a:	testb -528(%ebp), $0x8<UINT8>
0x0040ae61:	popl %ecx
0x0040ae62:	je 0x0040ae7f
0x0040ae7f:	cmpl -568(%ebp), $0x0<UINT8>
0x0040ae86:	movl %eax, -544(%ebp)
0x0040ae8c:	je 0x0040aef4
0x0040aef4:	movl %ecx, -540(%ebp)
0x0040aefa:	pushl %eax
0x0040aefb:	leal %eax, -552(%ebp)
0x0040af01:	call 0x0040a396
0x0040a3b4:	movb %al, (%ebx)
0x0040a3b6:	decl 0x8(%ebp)
0x0040a3b9:	movl %ecx, %edi
0x0040a3bb:	call 0x0040a33d
0x0040a3c0:	incl %ebx
0x0040a3c1:	cmpl (%esi), $0xffffffff<UINT8>
0x0040a3c4:	jne 0x0040a3d9
0x0040af06:	popl %ecx
0x0040af07:	cmpl -552(%ebp), $0x0<UINT8>
0x0040af0e:	jl 27
0x0040af10:	testb -528(%ebp), $0x4<UINT8>
0x0040af17:	je 0x0040af2b
0x0040af2b:	cmpl -580(%ebp), $0x0<UINT8>
0x0040af32:	je 0x0040af47
0x0040af6c:	cmpb -592(%ebp), $0x0<UINT8>
0x0040af73:	je 10
0x0040af75:	movl %eax, -596(%ebp)
0x0040af7b:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x0040af7f:	movl %eax, -552(%ebp)
0x0040af85:	movl %ecx, -4(%ebp)
0x0040af88:	popl %edi
0x0040af89:	popl %esi
0x0040af8a:	xorl %ecx, %ebp
0x0040af8c:	popl %ebx
0x0040af8d:	call 0x00407325
0x0040af92:	leave
0x0040af93:	ret

0x004071cd:	addl %esp, $0x10<UINT8>
0x004071d0:	decl -28(%ebp)
0x004071d3:	movl %esi, %eax
0x004071d5:	js 7
0x004071d7:	movl %eax, -32(%ebp)
0x004071da:	movb (%eax), %bl
0x004071dc:	jmp 0x004071ea
0x004071ea:	movl %eax, %esi
0x004071ec:	popl %esi
0x004071ed:	popl %ebx
0x004071ee:	leave
0x004071ef:	ret

0x00401934:	addl %esp, $0xc<UINT8>
0x00401937:	leal %ecx, 0x4(%esp)
0x0040193b:	pushl %ecx
0x0040193c:	leal %edx, 0x10(%esp)
0x00401940:	pushl %edx
0x00401941:	pushl $0x80000001<UINT32>
0x00401946:	call RegCreateKeyA@ADVAPI32.dll
RegCreateKeyA@ADVAPI32.dll: API Node	
0x0040194c:	testl %eax, %eax
0x0040194e:	jne 41
0x00401950:	movl %edx, 0x4(%esp)
0x00401954:	leal %eax, 0x8(%esp)
0x00401958:	pushl %eax
0x00401959:	leal %ecx, 0x120(%esp)
0x00401960:	pushl %ecx
0x00401961:	pushl $0x0<UINT8>
0x00401963:	pushl $0x0<UINT8>
0x00401965:	pushl $0x4259dc<UINT32>
0x0040196a:	pushl %edx
0x0040196b:	movl 0x20(%esp), $0x4<UINT32>
0x00401973:	call RegQueryValueExA@ADVAPI32.dll
RegQueryValueExA@ADVAPI32.dll: API Node	
0x00401979:	cmpl 0x11c(%esp), $0x0<UINT8>
0x00401981:	jne 694
0x00401987:	pushl %ebx
0x00401988:	pushl %esi
0x00401989:	pushl %edi
0x0040198a:	pushl $0x3e8<UINT32>
0x0040198f:	pushl $0x40<UINT8>
0x00401991:	call LocalAlloc@KERNEL32.dll
LocalAlloc@KERNEL32.dll: API Node	
0x00401997:	movl %esi, %eax
0x00401999:	pushl $0x4259cc<UINT32>
0x0040199e:	leal %edi, 0x12(%esi)
0x004019a1:	call LoadLibraryA@KERNEL32.dll
0x004019a7:	xorl %eax, %eax
0x004019a9:	movw 0xa(%esi), %ax
0x00409750:	movl %edi, %edi
0x00409752:	pushl %ebp
0x00409753:	movl %ebp, %esp
0x00409755:	subl %esp, $0x18<UINT8>
0x00409758:	pushl %ebx
0x00409759:	movl %ebx, 0xc(%ebp)
0x0040975c:	pushl %esi
0x0040975d:	movl %esi, 0x8(%ebx)
0x00409760:	xorl %esi, 0x42c8e0
0x00409766:	pushl %edi
0x00409767:	movl %eax, (%esi)
0x00409769:	movb -1(%ebp), $0x0<UINT8>
0x0040976d:	movl -12(%ebp), $0x1<UINT32>
0x00409774:	leal %edi, 0x10(%ebx)
0x00409777:	cmpl %eax, $0xfffffffe<UINT8>
0x0040977a:	je 0x00409789
0x00409789:	movl %ecx, 0xc(%esi)
0x0040978c:	movl %eax, 0x8(%esi)
0x0040978f:	addl %ecx, %edi
0x00409791:	xorl %ecx, (%eax,%edi)
0x00409794:	call 0x00407325
0x00409799:	movl %eax, 0x8(%ebp)
0x0040979c:	testb 0x4(%eax), $0x66<UINT8>
0x004097a0:	jne 278
0x004097a6:	movl %ecx, 0x10(%ebp)
0x004097a9:	leal %edx, -24(%ebp)
0x004097ac:	movl -4(%ebx), %edx
0x004097af:	movl %ebx, 0xc(%ebx)
0x004097b2:	movl -24(%ebp), %eax
0x004097b5:	movl -20(%ebp), %ecx
0x004097b8:	cmpl %ebx, $0xfffffffe<UINT8>
0x004097bb:	je 95
0x004097bd:	leal %ecx, (%ecx)
0x004097c0:	leal %eax, (%ebx,%ebx,2)
0x004097c3:	movl %ecx, 0x14(%esi,%eax,4)
0x004097c7:	leal %eax, 0x10(%esi,%eax,4)
0x004097cb:	movl -16(%ebp), %eax
0x004097ce:	movl %eax, (%eax)
0x004097d0:	movl -8(%ebp), %eax
0x004097d3:	testl %ecx, %ecx
0x004097d5:	je 20
0x004097d7:	movl %edx, %edi
0x004097d9:	call 0x00413922
0x00413922:	pushl %ebp
0x00413923:	pushl %esi
0x00413924:	pushl %edi
0x00413925:	pushl %ebx
0x00413926:	movl %ebp, %edx
0x00413928:	xorl %eax, %eax
0x0041392a:	xorl %ebx, %ebx
0x0041392c:	xorl %edx, %edx
0x0041392e:	xorl %esi, %esi
0x00413930:	xorl %edi, %edi
0x00413932:	call 0x00407a16
0x00407a16:	movl %eax, -20(%ebp)
0x00407a19:	movl %ecx, (%eax)
0x00407a1b:	movl %ecx, (%ecx)
0x00407a1d:	movl -36(%ebp), %ecx
0x00407a20:	pushl %eax
0x00407a21:	pushl %ecx
0x00407a22:	call 0x0040dae1
0x0040dae1:	movl %edi, %edi
0x0040dae3:	pushl %ebp
0x0040dae4:	movl %ebp, %esp
0x0040dae6:	pushl %ecx
0x0040dae7:	pushl %ecx
0x0040dae8:	pushl %esi
0x0040dae9:	call 0x0040d380
0x0040daee:	movl %esi, %eax
0x0040daf0:	testl %esi, %esi
0x0040daf2:	je 326
0x0040daf8:	movl %edx, 0x5c(%esi)
0x0040dafb:	movl %eax, 0x42d2ec
0x0040db00:	pushl %edi
0x0040db01:	movl %edi, 0x8(%ebp)
0x0040db04:	movl %ecx, %edx
0x0040db06:	pushl %ebx
0x0040db07:	cmpl (%ecx), %edi
0x0040db09:	je 0x0040db19
0x0040db19:	imull %eax, %eax, $0xc<UINT8>
0x0040db1c:	addl %eax, %edx
0x0040db1e:	cmpl %ecx, %eax
0x0040db20:	jae 8
0x0040db22:	cmpl (%ecx), %edi
0x0040db24:	jne 4
0x0040db26:	movl %eax, %ecx
0x0040db28:	jmp 0x0040db2c
0x0040db2c:	testl %eax, %eax
0x0040db2e:	je 10
0x0040db30:	movl %ebx, 0x8(%eax)
0x0040db33:	movl -4(%ebp), %ebx
0x0040db36:	testl %ebx, %ebx
0x0040db38:	jne 7
0x0040db3a:	xorl %eax, %eax
0x0040db3c:	jmp 0x0040dc3c
0x0040dc3c:	popl %ebx
0x0040dc3d:	popl %edi
0x0040dc3e:	popl %esi
0x0040dc3f:	leave
0x0040dc40:	ret

0x00407a27:	popl %ecx
0x00407a28:	popl %ecx
0x00407a29:	ret

0x00413934:	popl %ebx
0x00413935:	popl %edi
0x00413936:	popl %esi
0x00413937:	popl %ebp
0x00413938:	ret

0x004097de:	movb -1(%ebp), $0x1<UINT8>
0x004097e2:	testl %eax, %eax
0x004097e4:	jl 64
0x004097e6:	jg 71
0x004097e8:	movl %eax, -8(%ebp)
0x004097eb:	movl %ebx, %eax
0x004097ed:	cmpl %eax, $0xfffffffe<UINT8>
0x004097f0:	jne -50
0x004097f2:	cmpb -1(%ebp), $0x0<UINT8>
0x004097f6:	je 36
0x004097f8:	movl %eax, (%esi)
0x004097fa:	cmpl %eax, $0xfffffffe<UINT8>
0x004097fd:	je 0x0040980c
0x0040980c:	movl %ecx, 0xc(%esi)
0x0040980f:	movl %edx, 0x8(%esi)
0x00409812:	addl %ecx, %edi
0x00409814:	xorl %ecx, (%edx,%edi)
0x00409817:	call 0x00407325
0x0040981c:	movl %eax, -12(%ebp)
0x0040981f:	popl %edi
0x00409820:	popl %esi
0x00409821:	popl %ebx
0x00409822:	movl %esp, %ebp
0x00409824:	popl %ebp
0x00409825:	ret

0x004019ad:	xorl %ecx, %ecx
0x004019af:	movl %edx, $0x138<UINT32>
0x004019b4:	movw 0xe(%esi), %dx
0x004019b8:	movw 0xc(%esi), %cx
0x004019bc:	movl %eax, $0xb4<UINT32>
0x004019c1:	movw 0x10(%esi), %ax
0x004019c5:	movw 0x8(%esi), %cx
0x004019c9:	movl (%esi), $0x80c808d0<UINT32>
0x004019cf:	xorl %edx, %edx
0x004019d1:	movw (%edi), %dx
0x004019d4:	addl %edi, $0x2<UINT8>
0x004019d7:	xorl %eax, %eax
0x004019d9:	movw (%edi), %ax
0x004019dc:	addl %edi, $0x2<UINT8>
0x004019df:	pushl %edi
0x004019e0:	movl %ecx, $0x4259a8<UINT32>
0x004019e5:	call 0x004018c0
0x004018c0:	movl %eax, %ecx
0x004018c2:	pushl %esi
0x004018c3:	leal %esi, 0x2(%eax)
0x004018c6:	movw %dx, (%eax)
0x004018c9:	addl %eax, $0x2<UINT8>
0x004018cc:	testw %dx, %dx
0x004018cf:	jne 0x004018c6
0x004018d1:	subl %eax, %esi
0x004018d3:	movl %esi, 0x8(%esp)
0x004018d7:	sarl %eax
0x004018d9:	incl %eax
0x004018da:	subl %esi, %ecx
0x004018dc:	leal %esp, (%esp)
0x004018e0:	movzwl %edx, (%ecx)
0x004018e3:	movw (%esi,%ecx), %dx
0x004018e7:	addl %ecx, $0x2<UINT8>
0x004018ea:	testw %dx, %dx
0x004018ed:	jne 0x004018e0
0x004018ef:	popl %esi
0x004018f0:	ret

0x004019ea:	leal %edi, (%edi,%eax,2)
0x004019ed:	movl %ecx, $0x8<UINT32>
0x004019f2:	movw (%edi), %cx
0x004019f5:	addl %edi, $0x2<UINT8>
0x004019f8:	pushl %edi
0x004019f9:	movl %ecx, $0x42598c<UINT32>
0x004019fe:	call 0x004018c0
0x00401a03:	leal %eax, (%edi,%eax,2)
0x00401a06:	call 0x004018b0
0x004018b0:	addl %eax, $0x3<UINT8>
0x004018b3:	andl %eax, $0xfffffffc<UINT8>
0x004018b6:	ret

0x00401a0b:	movl %edx, $0x7<UINT32>
0x00401a10:	movw 0x8(%eax), %dx
0x00401a14:	movl %ecx, $0x3<UINT32>
0x00401a19:	movw 0xa(%eax), %cx
0x00401a1d:	movl %edx, $0x12a<UINT32>
0x00401a22:	movw 0xc(%eax), %dx
0x00401a26:	movl %ecx, $0xe<UINT32>
0x00401a2b:	movw 0xe(%eax), %cx
0x00401a2f:	movl %edx, $0x1f6<UINT32>
0x00401a34:	movw 0x10(%eax), %dx
0x00401a38:	movl (%eax), $0x50000000<UINT32>
0x00401a3e:	leal %edi, 0x12(%eax)
0x00401a41:	movl %eax, $0xffff<UINT32>
0x00401a46:	movw (%edi), %ax
0x00401a49:	addl %edi, $0x2<UINT8>
0x00401a4c:	movl %ecx, $0x82<UINT32>
0x00401a51:	movw (%edi), %cx
0x00401a54:	addl %edi, $0x2<UINT8>
0x00401a57:	pushl %edi
0x00401a58:	movl %ecx, $0x4258f8<UINT32>
0x00401a5d:	call 0x004018c0
0x00401a62:	leal %eax, (%edi,%eax,2)
0x00401a65:	xorl %edx, %edx
0x00401a67:	movw (%eax), %dx
0x00401a6a:	movl %ebx, $0x1<UINT32>
0x00401a6f:	addw 0x8(%esi), %bx
0x00401a73:	addl %eax, $0x2<UINT8>
0x00401a76:	call 0x004018b0
0x00401a7b:	movl %ecx, $0xc9<UINT32>
0x00401a80:	movw 0x8(%eax), %cx
0x00401a84:	movl %edx, $0x9f<UINT32>
0x00401a89:	movw 0xa(%eax), %dx
0x00401a8d:	movl %ecx, $0x32<UINT32>
0x00401a92:	movl %edx, $0xe<UINT32>
0x00401a97:	movw 0xc(%eax), %cx
0x00401a9b:	movw 0xe(%eax), %dx
0x00401a9f:	movl %ecx, %ebx
0x00401aa1:	leal %edi, 0x12(%eax)
0x00401aa4:	movl %edx, $0xffff<UINT32>
0x00401aa9:	movw 0x10(%eax), %cx
0x00401aad:	movl (%eax), $0x50010000<UINT32>
0x00401ab3:	movw (%edi), %dx
0x00401ab6:	addl %edi, $0x2<UINT8>
0x00401ab9:	movl %eax, $0x80<UINT32>
0x00401abe:	movw (%edi), %ax
0x00401ac1:	addl %edi, $0x2<UINT8>
0x00401ac4:	pushl %edi
0x00401ac5:	movl %ecx, $0x4258e8<UINT32>
0x00401aca:	call 0x004018c0
0x00401acf:	leal %eax, (%edi,%eax,2)
0x00401ad2:	xorl %ecx, %ecx
0x00401ad4:	movw (%eax), %cx
0x00401ad7:	addw 0x8(%esi), %bx
0x00401adb:	addl %eax, $0x2<UINT8>
0x00401ade:	call 0x004018b0
0x00401ae3:	movl %edx, $0xff<UINT32>
0x00401ae8:	movw 0x8(%eax), %dx
0x00401aec:	movl %ecx, $0x9f<UINT32>
0x00401af1:	movw 0xa(%eax), %cx
0x00401af5:	movl %edx, $0x32<UINT32>
0x00401afa:	movw 0xc(%eax), %dx
0x00401afe:	movl %edx, $0x2<UINT32>
0x00401b03:	movl %ecx, $0xe<UINT32>
0x00401b08:	movw 0xe(%eax), %cx
0x00401b0c:	movw 0x10(%eax), %dx
0x00401b10:	movl (%eax), $0x50010000<UINT32>
0x00401b16:	leal %edi, 0x12(%eax)
0x00401b19:	movl %eax, $0xffff<UINT32>
0x00401b1e:	movw (%edi), %ax
0x00401b21:	addl %edi, %edx
0x00401b23:	movl %ecx, $0x80<UINT32>
0x00401b28:	movw (%edi), %cx
0x00401b2b:	addl %edi, %edx
0x00401b2d:	pushl %edi
0x00401b2e:	movl %ecx, $0x4258d4<UINT32>
0x00401b33:	call 0x004018c0
0x00401b38:	leal %eax, (%edi,%eax,2)
0x00401b3b:	xorl %edx, %edx
0x00401b3d:	movw (%eax), %dx
0x00401b40:	addw 0x8(%esi), %bx
0x00401b44:	addl %eax, $0x2<UINT8>
0x00401b47:	call 0x004018b0
0x00401b4c:	movl %ecx, $0x7<UINT32>
0x00401b51:	movw 0x8(%eax), %cx
0x00401b55:	movl %edx, $0x9f<UINT32>
0x00401b5a:	movw 0xa(%eax), %dx
0x00401b5e:	movl %ecx, $0x32<UINT32>
0x00401b63:	movw 0xc(%eax), %cx
0x00401b67:	movl %edx, $0xe<UINT32>
0x00401b6c:	movw 0xe(%eax), %dx
0x00401b70:	leal %edi, 0x12(%eax)
0x00401b73:	movl %ecx, $0x1f5<UINT32>
0x00401b78:	movw 0x10(%eax), %cx
0x00401b7c:	movl (%eax), $0x50010000<UINT32>
0x00401b82:	movl %edx, $0xffff<UINT32>
0x00401b87:	movw (%edi), %dx
0x00401b8a:	addl %edi, $0x2<UINT8>
0x00401b8d:	movl %eax, $0x80<UINT32>
0x00401b92:	movw (%edi), %ax
0x00401b95:	addl %edi, $0x2<UINT8>
0x00401b98:	pushl %edi
0x00401b99:	movl %ecx, $0x4258c4<UINT32>
0x00401b9e:	call 0x004018c0
0x00401ba3:	leal %eax, (%edi,%eax,2)
0x00401ba6:	xorl %ecx, %ecx
0x00401ba8:	movw (%eax), %cx
0x00401bab:	addw 0x8(%esi), %bx
0x00401baf:	addl %eax, $0x2<UINT8>
0x00401bb2:	call 0x004018b0
0x00401bb7:	movl %edx, $0x7<UINT32>
0x00401bbc:	movw 0x8(%eax), %dx
0x00401bc0:	movl %ecx, $0xe<UINT32>
0x00401bc5:	movw 0xa(%eax), %cx
0x00401bc9:	movl %edx, $0x12a<UINT32>
0x00401bce:	movl %ecx, $0x8c<UINT32>
0x00401bd3:	movw 0xc(%eax), %dx
0x00401bd7:	leal %edi, 0x12(%eax)
0x00401bda:	movw 0xe(%eax), %cx
0x00401bde:	movl %edx, $0x1f4<UINT32>
0x00401be3:	pushl %edi
0x00401be4:	movl %ecx, $0x4258b0<UINT32>
0x00401be9:	movw 0x10(%eax), %dx
0x00401bed:	movl (%eax), $0x50a11844<UINT32>
0x00401bf3:	call 0x004018c0
0x00401bf8:	leal %edi, (%edi,%eax,2)
0x00401bfb:	pushl %edi
0x00401bfc:	movl %ecx, $0x4258d4<UINT32>
0x00401c01:	call 0x004018c0
0x00401c06:	addl %esp, $0x20<UINT8>
0x00401c09:	pushl %ebp
0x00401c0a:	xorl %ecx, %ecx
0x00401c0c:	pushl $0x401750<UINT32>
0x00401c11:	pushl %ecx
0x00401c12:	pushl %esi
0x00401c13:	movw (%edi,%eax,2), %cx
0x00401c17:	addw 0x8(%esi), %bx
0x00401c1b:	pushl %ecx
0x00401c1c:	call DialogBoxIndirectParamA@USER32.dll
DialogBoxIndirectParamA@USER32.dll: API Node	
0x00401c22:	pushl %esi
0x00401c23:	movl 0x12c(%esp), %eax
0x00401c2a:	call LocalFree@KERNEL32.dll
LocalFree@KERNEL32.dll: API Node	
0x00401c30:	cmpl 0x128(%esp), $0x0<UINT8>
0x00401c38:	popl %edi
0x00401c39:	popl %esi
0x00401c3a:	popl %ebx
0x00401c3b:	je 30
