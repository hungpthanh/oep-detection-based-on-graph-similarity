0x0045d000:	movl %ebx, $0x4001d0<UINT32>
0x0045d005:	movl %edi, $0x401000<UINT32>
0x0045d00a:	movl %esi, $0x44205d<UINT32>
0x0045d00f:	pushl %ebx
0x0045d010:	call 0x0045d01f
0x0045d01f:	cld
0x0045d020:	movb %dl, $0xffffff80<UINT8>
0x0045d022:	movsb %es:(%edi), %ds:(%esi)
0x0045d023:	pushl $0x2<UINT8>
0x0045d025:	popl %ebx
0x0045d026:	call 0x0045d015
0x0045d015:	addb %dl, %dl
0x0045d017:	jne 0x0045d01e
0x0045d019:	movb %dl, (%esi)
0x0045d01b:	incl %esi
0x0045d01c:	adcb %dl, %dl
0x0045d01e:	ret

0x0045d029:	jae 0x0045d022
0x0045d02b:	xorl %ecx, %ecx
0x0045d02d:	call 0x0045d015
0x0045d030:	jae 0x0045d04a
0x0045d032:	xorl %eax, %eax
0x0045d034:	call 0x0045d015
0x0045d037:	jae 0x0045d05a
0x0045d039:	movb %bl, $0x2<UINT8>
0x0045d03b:	incl %ecx
0x0045d03c:	movb %al, $0x10<UINT8>
0x0045d03e:	call 0x0045d015
0x0045d041:	adcb %al, %al
0x0045d043:	jae 0x0045d03e
0x0045d045:	jne 0x0045d086
0x0045d086:	pushl %esi
0x0045d087:	movl %esi, %edi
0x0045d089:	subl %esi, %eax
0x0045d08b:	rep movsb %es:(%edi), %ds:(%esi)
0x0045d08d:	popl %esi
0x0045d08e:	jmp 0x0045d026
0x0045d04a:	call 0x0045d092
0x0045d092:	incl %ecx
0x0045d093:	call 0x0045d015
0x0045d097:	adcl %ecx, %ecx
0x0045d099:	call 0x0045d015
0x0045d09d:	jb 0x0045d093
0x0045d09f:	ret

0x0045d04f:	subl %ecx, %ebx
0x0045d051:	jne 0x0045d063
0x0045d063:	xchgl %ecx, %eax
0x0045d064:	decl %eax
0x0045d065:	shll %eax, $0x8<UINT8>
0x0045d068:	lodsb %al, %ds:(%esi)
0x0045d069:	call 0x0045d090
0x0045d090:	xorl %ecx, %ecx
0x0045d06e:	cmpl %eax, $0x7d00<UINT32>
0x0045d073:	jae 0x0045d07f
0x0045d075:	cmpb %ah, $0x5<UINT8>
0x0045d078:	jae 0x0045d080
0x0045d07a:	cmpl %eax, $0x7f<UINT8>
0x0045d07d:	ja 0x0045d081
0x0045d07f:	incl %ecx
0x0045d080:	incl %ecx
0x0045d081:	xchgl %ebp, %eax
0x0045d082:	movl %eax, %ebp
0x0045d084:	movb %bl, $0x1<UINT8>
0x0045d047:	stosb %es:(%edi), %al
0x0045d048:	jmp 0x0045d026
0x0045d05a:	lodsb %al, %ds:(%esi)
0x0045d05b:	shrl %eax
0x0045d05d:	je 0x0045d0a0
0x0045d05f:	adcl %ecx, %ecx
0x0045d061:	jmp 0x0045d07f
0x0045d053:	call 0x0045d090
0x0045d058:	jmp 0x0045d082
0x0045d0a0:	popl %edi
0x0045d0a1:	popl %ebx
0x0045d0a2:	movzwl %edi, (%ebx)
0x0045d0a5:	decl %edi
0x0045d0a6:	je 0x0045d0b0
0x0045d0a8:	decl %edi
0x0045d0a9:	je 0x0045d0be
0x0045d0ab:	shll %edi, $0xc<UINT8>
0x0045d0ae:	jmp 0x0045d0b7
0x0045d0b7:	incl %ebx
0x0045d0b8:	incl %ebx
0x0045d0b9:	jmp 0x0045d00f
0x0045d0b0:	movl %edi, 0x2(%ebx)
0x0045d0b3:	pushl %edi
0x0045d0b4:	addl %ebx, $0x4<UINT8>
0x0045d0be:	popl %edi
0x0045d0bf:	movl %ebx, $0x45d128<UINT32>
0x0045d0c4:	incl %edi
0x0045d0c5:	movl %esi, (%edi)
0x0045d0c7:	scasl %eax, %es:(%edi)
0x0045d0c8:	pushl %edi
0x0045d0c9:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0045d0cb:	xchgl %ebp, %eax
0x0045d0cc:	xorl %eax, %eax
0x0045d0ce:	scasb %al, %es:(%edi)
0x0045d0cf:	jne 0x0045d0ce
0x0045d0d1:	decb (%edi)
0x0045d0d3:	je 0x0045d0c4
0x0045d0d5:	decb (%edi)
0x0045d0d7:	jne 0x0045d0df
0x0045d0df:	decb (%edi)
0x0045d0e1:	je 0x00404f25
0x0045d0e7:	pushl %edi
0x0045d0e8:	pushl %ebp
0x0045d0e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x0045d0ec:	orl (%esi), %eax
0x0045d0ee:	lodsl %eax, %ds:(%esi)
0x0045d0ef:	jne 0x0045d0cc
GetProcAddress@KERNEL32.dll: API Node	
0x00404f25:	call 0x0040ad0e
0x0040ad0e:	pushl %ebp
0x0040ad0f:	movl %ebp, %esp
0x0040ad11:	subl %esp, $0x14<UINT8>
0x0040ad14:	andl -12(%ebp), $0x0<UINT8>
0x0040ad18:	andl -8(%ebp), $0x0<UINT8>
0x0040ad1c:	movl %eax, 0x41f490
0x0040ad21:	pushl %esi
0x0040ad22:	pushl %edi
0x0040ad23:	movl %edi, $0xbb40e64e<UINT32>
0x0040ad28:	movl %esi, $0xffff0000<UINT32>
0x0040ad2d:	cmpl %eax, %edi
0x0040ad2f:	je 0x0040ad3e
0x0040ad3e:	leal %eax, -12(%ebp)
0x0040ad41:	pushl %eax
0x0040ad42:	call GetSystemTimeAsFileTime@KERNEL32.dll
GetSystemTimeAsFileTime@KERNEL32.dll: API Node	
0x0040ad48:	movl %eax, -8(%ebp)
0x0040ad4b:	xorl %eax, -12(%ebp)
0x0040ad4e:	movl -4(%ebp), %eax
0x0040ad51:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x0040ad57:	xorl -4(%ebp), %eax
0x0040ad5a:	call GetCurrentProcessId@KERNEL32.dll
GetCurrentProcessId@KERNEL32.dll: API Node	
0x0040ad60:	xorl -4(%ebp), %eax
0x0040ad63:	leal %eax, -20(%ebp)
0x0040ad66:	pushl %eax
0x0040ad67:	call QueryPerformanceCounter@KERNEL32.dll
QueryPerformanceCounter@KERNEL32.dll: API Node	
0x0040ad6d:	movl %ecx, -16(%ebp)
0x0040ad70:	leal %eax, -4(%ebp)
0x0040ad73:	xorl %ecx, -20(%ebp)
0x0040ad76:	xorl %ecx, -4(%ebp)
0x0040ad79:	xorl %ecx, %eax
0x0040ad7b:	cmpl %ecx, %edi
0x0040ad7d:	jne 0x0040ad86
0x0040ad86:	testl %esi, %ecx
0x0040ad88:	jne 0x0040ad96
0x0040ad96:	movl 0x41f490, %ecx
0x0040ad9c:	notl %ecx
0x0040ad9e:	movl 0x41f494, %ecx
0x0040ada4:	popl %edi
0x0040ada5:	popl %esi
0x0040ada6:	movl %esp, %ebp
0x0040ada8:	popl %ebp
0x0040ada9:	ret

0x00404f2a:	jmp 0x00404f2f
0x00404f2f:	pushl $0x14<UINT8>
0x00404f31:	pushl $0x41df60<UINT32>
0x00404f36:	call 0x00405de0
0x00405de0:	pushl $0x405e40<UINT32>
0x00405de5:	pushl %fs:0
0x00405dec:	movl %eax, 0x10(%esp)
0x00405df0:	movl 0x10(%esp), %ebp
0x00405df4:	leal %ebp, 0x10(%esp)
0x00405df8:	subl %esp, %eax
0x00405dfa:	pushl %ebx
0x00405dfb:	pushl %esi
0x00405dfc:	pushl %edi
0x00405dfd:	movl %eax, 0x41f490
0x00405e02:	xorl -4(%ebp), %eax
0x00405e05:	xorl %eax, %ebp
0x00405e07:	pushl %eax
0x00405e08:	movl -24(%ebp), %esp
0x00405e0b:	pushl -8(%ebp)
0x00405e0e:	movl %eax, -4(%ebp)
0x00405e11:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00405e18:	movl -8(%ebp), %eax
0x00405e1b:	leal %eax, -16(%ebp)
0x00405e1e:	movl %fs:0, %eax
0x00405e24:	ret

0x00404f3b:	call 0x004071f2
0x004071f2:	pushl %ebp
0x004071f3:	movl %ebp, %esp
0x004071f5:	subl %esp, $0x44<UINT8>
0x004071f8:	leal %eax, -68(%ebp)
0x004071fb:	pushl %eax
0x004071fc:	call GetStartupInfoW@KERNEL32.dll
GetStartupInfoW@KERNEL32.dll: API Node	
0x00407202:	testb -24(%ebp), $0x1<UINT8>
0x00407206:	je 0x0040720e
0x0040720e:	pushl $0xa<UINT8>
0x00407210:	popl %eax
0x00407211:	movl %esp, %ebp
0x00407213:	popl %ebp
0x00407214:	ret

0x00404f40:	movzwl %esi, %ax
0x00404f43:	pushl $0x2<UINT8>
0x00404f45:	call 0x0040acc1
0x0040acc1:	pushl %ebp
0x0040acc2:	movl %ebp, %esp
0x0040acc4:	movl %eax, 0x8(%ebp)
0x0040acc7:	movl 0x4206a0, %eax
0x0040accc:	popl %ebp
0x0040accd:	ret

0x00404f4a:	popl %ecx
0x00404f4b:	movl %eax, $0x5a4d<UINT32>
0x00404f50:	cmpw 0x400000, %ax
0x00404f57:	je 0x00404f5d
0x00404f5d:	movl %eax, 0x40003c
0x00404f62:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00404f6c:	jne -21
0x00404f6e:	movl %ecx, $0x10b<UINT32>
0x00404f73:	cmpw 0x400018(%eax), %cx
0x00404f7a:	jne -35
0x00404f7c:	xorl %ebx, %ebx
0x00404f7e:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00404f85:	jbe 9
0x00404f87:	cmpl 0x4000e8(%eax), %ebx
0x00404f8d:	setne %bl
0x00404f90:	movl -28(%ebp), %ebx
0x00404f93:	call 0x0040862d
0x0040862d:	call GetProcessHeap@KERNEL32.dll
GetProcessHeap@KERNEL32.dll: API Node	
0x00408633:	xorl %ecx, %ecx
0x00408635:	movl 0x420cf8, %eax
0x0040863a:	testl %eax, %eax
0x0040863c:	setne %cl
0x0040863f:	movl %eax, %ecx
0x00408641:	ret

0x00404f98:	testl %eax, %eax
0x00404f9a:	jne 0x00404fa4
0x00404fa4:	call 0x00408515
0x00408515:	call 0x00403a3e
0x00403a3e:	pushl %esi
0x00403a3f:	pushl $0x0<UINT8>
0x00403a41:	call EncodePointer@KERNEL32.dll
EncodePointer@KERNEL32.dll: API Node	
0x00403a47:	movl %esi, %eax
0x00403a49:	pushl %esi
0x00403a4a:	call 0x00408620
0x00408620:	pushl %ebp
0x00408621:	movl %ebp, %esp
0x00408623:	movl %eax, 0x8(%ebp)
0x00408626:	movl 0x420cf0, %eax
0x0040862b:	popl %ebp
0x0040862c:	ret

0x00403a4f:	pushl %esi
0x00403a50:	call 0x004060f9
0x004060f9:	pushl %ebp
0x004060fa:	movl %ebp, %esp
0x004060fc:	movl %eax, 0x8(%ebp)
0x004060ff:	movl 0x42058c, %eax
0x00406104:	popl %ebp
0x00406105:	ret

0x00403a55:	pushl %esi
0x00403a56:	call 0x00408aa5
0x00408aa5:	pushl %ebp
0x00408aa6:	movl %ebp, %esp
0x00408aa8:	movl %eax, 0x8(%ebp)
0x00408aab:	movl 0x421024, %eax
0x00408ab0:	popl %ebp
0x00408ab1:	ret

0x00403a5b:	pushl %esi
0x00403a5c:	call 0x00408abf
0x00408abf:	pushl %ebp
0x00408ac0:	movl %ebp, %esp
0x00408ac2:	movl %eax, 0x8(%ebp)
0x00408ac5:	movl 0x421028, %eax
0x00408aca:	movl 0x42102c, %eax
0x00408acf:	movl 0x421030, %eax
0x00408ad4:	movl 0x421034, %eax
0x00408ad9:	popl %ebp
0x00408ada:	ret

0x00403a61:	pushl %esi
0x00403a62:	call 0x00408a94
0x00408a94:	pushl $0x408a60<UINT32>
0x00408a99:	call EncodePointer@KERNEL32.dll
0x00408a9f:	movl 0x421020, %eax
0x00408aa4:	ret

0x00403a67:	pushl %esi
0x00403a68:	call 0x00408cd0
0x00408cd0:	pushl %ebp
0x00408cd1:	movl %ebp, %esp
0x00408cd3:	movl %eax, 0x8(%ebp)
0x00408cd6:	movl 0x42103c, %eax
0x00408cdb:	popl %ebp
0x00408cdc:	ret

0x00403a6d:	addl %esp, $0x18<UINT8>
0x00403a70:	popl %esi
0x00403a71:	jmp 0x00407283
0x00407283:	pushl %esi
0x00407284:	pushl %edi
0x00407285:	pushl $0x41a108<UINT32>
0x0040728a:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x00407290:	movl %esi, 0x413134
0x00407296:	movl %edi, %eax
0x00407298:	pushl $0x41a124<UINT32>
0x0040729d:	pushl %edi
0x0040729e:	call GetProcAddress@KERNEL32.dll
0x004072a0:	xorl %eax, 0x41f490
0x004072a6:	pushl $0x41a130<UINT32>
0x004072ab:	pushl %edi
0x004072ac:	movl 0x4211c0, %eax
0x004072b1:	call GetProcAddress@KERNEL32.dll
0x004072b3:	xorl %eax, 0x41f490
0x004072b9:	pushl $0x41a138<UINT32>
0x004072be:	pushl %edi
0x004072bf:	movl 0x4211c4, %eax
0x004072c4:	call GetProcAddress@KERNEL32.dll
0x004072c6:	xorl %eax, 0x41f490
0x004072cc:	pushl $0x41a144<UINT32>
0x004072d1:	pushl %edi
0x004072d2:	movl 0x4211c8, %eax
0x004072d7:	call GetProcAddress@KERNEL32.dll
0x004072d9:	xorl %eax, 0x41f490
0x004072df:	pushl $0x41a150<UINT32>
0x004072e4:	pushl %edi
0x004072e5:	movl 0x4211cc, %eax
0x004072ea:	call GetProcAddress@KERNEL32.dll
0x004072ec:	xorl %eax, 0x41f490
0x004072f2:	pushl $0x41a16c<UINT32>
0x004072f7:	pushl %edi
0x004072f8:	movl 0x4211d0, %eax
0x004072fd:	call GetProcAddress@KERNEL32.dll
0x004072ff:	xorl %eax, 0x41f490
0x00407305:	pushl $0x41a17c<UINT32>
0x0040730a:	pushl %edi
0x0040730b:	movl 0x4211d4, %eax
0x00407310:	call GetProcAddress@KERNEL32.dll
0x00407312:	xorl %eax, 0x41f490
0x00407318:	pushl $0x41a190<UINT32>
0x0040731d:	pushl %edi
0x0040731e:	movl 0x4211d8, %eax
0x00407323:	call GetProcAddress@KERNEL32.dll
0x00407325:	xorl %eax, 0x41f490
0x0040732b:	pushl $0x41a1a8<UINT32>
0x00407330:	pushl %edi
0x00407331:	movl 0x4211dc, %eax
0x00407336:	call GetProcAddress@KERNEL32.dll
0x00407338:	xorl %eax, 0x41f490
0x0040733e:	pushl $0x41a1c0<UINT32>
0x00407343:	pushl %edi
0x00407344:	movl 0x4211e0, %eax
0x00407349:	call GetProcAddress@KERNEL32.dll
0x0040734b:	xorl %eax, 0x41f490
0x00407351:	pushl $0x41a1d4<UINT32>
0x00407356:	pushl %edi
0x00407357:	movl 0x4211e4, %eax
0x0040735c:	call GetProcAddress@KERNEL32.dll
0x0040735e:	xorl %eax, 0x41f490
0x00407364:	pushl $0x41a1f4<UINT32>
0x00407369:	pushl %edi
0x0040736a:	movl 0x4211e8, %eax
0x0040736f:	call GetProcAddress@KERNEL32.dll
0x00407371:	xorl %eax, 0x41f490
0x00407377:	pushl $0x41a20c<UINT32>
0x0040737c:	pushl %edi
0x0040737d:	movl 0x4211ec, %eax
0x00407382:	call GetProcAddress@KERNEL32.dll
0x00407384:	xorl %eax, 0x41f490
0x0040738a:	pushl $0x41a224<UINT32>
0x0040738f:	pushl %edi
0x00407390:	movl 0x4211f0, %eax
0x00407395:	call GetProcAddress@KERNEL32.dll
0x00407397:	xorl %eax, 0x41f490
0x0040739d:	pushl $0x41a238<UINT32>
0x004073a2:	pushl %edi
0x004073a3:	movl 0x4211f4, %eax
0x004073a8:	call GetProcAddress@KERNEL32.dll
0x004073aa:	xorl %eax, 0x41f490
0x004073b0:	movl 0x4211f8, %eax
0x004073b5:	pushl $0x41a24c<UINT32>
0x004073ba:	pushl %edi
0x004073bb:	call GetProcAddress@KERNEL32.dll
0x004073bd:	xorl %eax, 0x41f490
0x004073c3:	pushl $0x41a268<UINT32>
0x004073c8:	pushl %edi
0x004073c9:	movl 0x4211fc, %eax
0x004073ce:	call GetProcAddress@KERNEL32.dll
0x004073d0:	xorl %eax, 0x41f490
0x004073d6:	pushl $0x41a288<UINT32>
0x004073db:	pushl %edi
0x004073dc:	movl 0x421200, %eax
0x004073e1:	call GetProcAddress@KERNEL32.dll
0x004073e3:	xorl %eax, 0x41f490
0x004073e9:	pushl $0x41a2a4<UINT32>
0x004073ee:	pushl %edi
0x004073ef:	movl 0x421204, %eax
0x004073f4:	call GetProcAddress@KERNEL32.dll
0x004073f6:	xorl %eax, 0x41f490
0x004073fc:	pushl $0x41a2c4<UINT32>
0x00407401:	pushl %edi
0x00407402:	movl 0x421208, %eax
0x00407407:	call GetProcAddress@KERNEL32.dll
0x00407409:	xorl %eax, 0x41f490
0x0040740f:	pushl $0x41a2d8<UINT32>
0x00407414:	pushl %edi
0x00407415:	movl 0x42120c, %eax
0x0040741a:	call GetProcAddress@KERNEL32.dll
0x0040741c:	xorl %eax, 0x41f490
0x00407422:	pushl $0x41a2f4<UINT32>
0x00407427:	pushl %edi
0x00407428:	movl 0x421210, %eax
0x0040742d:	call GetProcAddress@KERNEL32.dll
0x0040742f:	xorl %eax, 0x41f490
0x00407435:	pushl $0x41a308<UINT32>
0x0040743a:	pushl %edi
0x0040743b:	movl 0x421218, %eax
0x00407440:	call GetProcAddress@KERNEL32.dll
0x00407442:	xorl %eax, 0x41f490
0x00407448:	pushl $0x41a318<UINT32>
0x0040744d:	pushl %edi
0x0040744e:	movl 0x421214, %eax
0x00407453:	call GetProcAddress@KERNEL32.dll
0x00407455:	xorl %eax, 0x41f490
0x0040745b:	pushl $0x41a328<UINT32>
0x00407460:	pushl %edi
0x00407461:	movl 0x42121c, %eax
0x00407466:	call GetProcAddress@KERNEL32.dll
0x00407468:	xorl %eax, 0x41f490
0x0040746e:	pushl $0x41a338<UINT32>
0x00407473:	pushl %edi
0x00407474:	movl 0x421220, %eax
0x00407479:	call GetProcAddress@KERNEL32.dll
0x0040747b:	xorl %eax, 0x41f490
0x00407481:	pushl $0x41a348<UINT32>
0x00407486:	pushl %edi
0x00407487:	movl 0x421224, %eax
0x0040748c:	call GetProcAddress@KERNEL32.dll
0x0040748e:	xorl %eax, 0x41f490
0x00407494:	pushl $0x41a364<UINT32>
0x00407499:	pushl %edi
0x0040749a:	movl 0x421228, %eax
0x0040749f:	call GetProcAddress@KERNEL32.dll
0x004074a1:	xorl %eax, 0x41f490
0x004074a7:	pushl $0x41a378<UINT32>
0x004074ac:	pushl %edi
0x004074ad:	movl 0x42122c, %eax
0x004074b2:	call GetProcAddress@KERNEL32.dll
0x004074b4:	xorl %eax, 0x41f490
0x004074ba:	pushl $0x41a388<UINT32>
0x004074bf:	pushl %edi
0x004074c0:	movl 0x421230, %eax
0x004074c5:	call GetProcAddress@KERNEL32.dll
0x004074c7:	xorl %eax, 0x41f490
0x004074cd:	pushl $0x41a39c<UINT32>
0x004074d2:	pushl %edi
0x004074d3:	movl 0x421234, %eax
0x004074d8:	call GetProcAddress@KERNEL32.dll
0x004074da:	xorl %eax, 0x41f490
0x004074e0:	movl 0x421238, %eax
0x004074e5:	pushl $0x41a3ac<UINT32>
0x004074ea:	pushl %edi
0x004074eb:	call GetProcAddress@KERNEL32.dll
0x004074ed:	xorl %eax, 0x41f490
0x004074f3:	pushl $0x41a3cc<UINT32>
0x004074f8:	pushl %edi
0x004074f9:	movl 0x42123c, %eax
0x004074fe:	call GetProcAddress@KERNEL32.dll
0x00407500:	xorl %eax, 0x41f490
0x00407506:	popl %edi
0x00407507:	movl 0x421240, %eax
0x0040750c:	popl %esi
0x0040750d:	ret

0x0040851a:	call 0x00405274
0x00405274:	pushl %esi
0x00405275:	pushl %edi
0x00405276:	movl %esi, $0x41f610<UINT32>
0x0040527b:	movl %edi, $0x420438<UINT32>
0x00405280:	cmpl 0x4(%esi), $0x1<UINT8>
0x00405284:	jne 22
0x00405286:	pushl $0x0<UINT8>
0x00405288:	movl (%esi), %edi
0x0040528a:	addl %edi, $0x18<UINT8>
0x0040528d:	pushl $0xfa0<UINT32>
0x00405292:	pushl (%esi)
0x00405294:	call 0x00407215
0x00407215:	pushl %ebp
0x00407216:	movl %ebp, %esp
0x00407218:	movl %eax, 0x4211d0
0x0040721d:	xorl %eax, 0x41f490
0x00407223:	je 13
0x00407225:	pushl 0x10(%ebp)
0x00407228:	pushl 0xc(%ebp)
0x0040722b:	pushl 0x8(%ebp)
0x0040722e:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x00407230:	popl %ebp
0x00407231:	ret

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
