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
0x0040be1b:	jne 18
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
0x00407345:	jne 99
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
0x00406bd3:	je 10
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
