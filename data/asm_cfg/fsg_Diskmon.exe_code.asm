0x0044c000:	movl %ebx, $0x4001d0<UINT32>
0x0044c005:	movl %edi, $0x401000<UINT32>
0x0044c00a:	movl %esi, $0x43ba11<UINT32>
0x0044c00f:	pushl %ebx
0x0044c010:	call 0x0044c01f
0x0044c01f:	cld
0x0044c020:	movb %dl, $0xffffff80<UINT8>
0x0044c022:	movsb %es:(%edi), %ds:(%esi)
0x0044c023:	pushl $0x2<UINT8>
0x0044c025:	popl %ebx
0x0044c026:	call 0x0044c015
0x0044c015:	addb %dl, %dl
0x0044c017:	jne 0x0044c01e
0x0044c019:	movb %dl, (%esi)
0x0044c01b:	incl %esi
0x0044c01c:	adcb %dl, %dl
0x0044c01e:	ret

0x0044c029:	jae 0x0044c022
0x0044c02b:	xorl %ecx, %ecx
0x0044c02d:	call 0x0044c015
0x0044c030:	jae 0x0044c04a
0x0044c032:	xorl %eax, %eax
0x0044c034:	call 0x0044c015
0x0044c037:	jae 0x0044c05a
0x0044c039:	movb %bl, $0x2<UINT8>
0x0044c03b:	incl %ecx
0x0044c03c:	movb %al, $0x10<UINT8>
0x0044c03e:	call 0x0044c015
0x0044c041:	adcb %al, %al
0x0044c043:	jae 0x0044c03e
0x0044c045:	jne 0x0044c086
0x0044c047:	stosb %es:(%edi), %al
0x0044c048:	jmp 0x0044c026
0x0044c05a:	lodsb %al, %ds:(%esi)
0x0044c05b:	shrl %eax
0x0044c05d:	je 0x0044c0a0
0x0044c05f:	adcl %ecx, %ecx
0x0044c061:	jmp 0x0044c07f
0x0044c07f:	incl %ecx
0x0044c080:	incl %ecx
0x0044c081:	xchgl %ebp, %eax
0x0044c082:	movl %eax, %ebp
0x0044c084:	movb %bl, $0x1<UINT8>
0x0044c086:	pushl %esi
0x0044c087:	movl %esi, %edi
0x0044c089:	subl %esi, %eax
0x0044c08b:	rep movsb %es:(%edi), %ds:(%esi)
0x0044c08d:	popl %esi
0x0044c08e:	jmp 0x0044c026
0x0044c04a:	call 0x0044c092
0x0044c092:	incl %ecx
0x0044c093:	call 0x0044c015
0x0044c097:	adcl %ecx, %ecx
0x0044c099:	call 0x0044c015
0x0044c09d:	jb 0x0044c093
0x0044c09f:	ret

0x0044c04f:	subl %ecx, %ebx
0x0044c051:	jne 0x0044c063
0x0044c053:	call 0x0044c090
0x0044c090:	xorl %ecx, %ecx
0x0044c058:	jmp 0x0044c082
0x0044c063:	xchgl %ecx, %eax
0x0044c064:	decl %eax
0x0044c065:	shll %eax, $0x8<UINT8>
0x0044c068:	lodsb %al, %ds:(%esi)
0x0044c069:	call 0x0044c090
0x0044c06e:	cmpl %eax, $0x7d00<UINT32>
0x0044c073:	jae 0x0044c07f
0x0044c075:	cmpb %ah, $0x5<UINT8>
0x0044c078:	jae 0x0044c080
0x0044c07a:	cmpl %eax, $0x7f<UINT8>
0x0044c07d:	ja 0x0044c081
0x0044c0a0:	popl %edi
0x0044c0a1:	popl %ebx
0x0044c0a2:	movzwl %edi, (%ebx)
0x0044c0a5:	decl %edi
0x0044c0a6:	je 0x0044c0b0
0x0044c0a8:	decl %edi
0x0044c0a9:	je 0x0044c0be
0x0044c0ab:	shll %edi, $0xc<UINT8>
0x0044c0ae:	jmp 0x0044c0b7
0x0044c0b7:	incl %ebx
0x0044c0b8:	incl %ebx
0x0044c0b9:	jmp 0x0044c00f
0x0044c0b0:	movl %edi, 0x2(%ebx)
0x0044c0b3:	pushl %edi
0x0044c0b4:	addl %ebx, $0x4<UINT8>
0x0044c0be:	popl %edi
0x0044c0bf:	movl %ebx, $0x44c128<UINT32>
0x0044c0c4:	incl %edi
0x0044c0c5:	movl %esi, (%edi)
0x0044c0c7:	scasl %eax, %es:(%edi)
0x0044c0c8:	pushl %edi
0x0044c0c9:	call LoadLibraryA@KERNEL32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0044c0cb:	xchgl %ebp, %eax
0x0044c0cc:	xorl %eax, %eax
0x0044c0ce:	scasb %al, %es:(%edi)
0x0044c0cf:	jne 0x0044c0ce
0x0044c0d1:	decb (%edi)
0x0044c0d3:	je 0x0044c0c4
0x0044c0d5:	decb (%edi)
0x0044c0d7:	jne 0x0044c0df
0x0044c0d9:	incl %edi
0x0044c0da:	pushl (%edi)
0x0044c0dc:	scasl %eax, %es:(%edi)
0x0044c0dd:	jmp 0x0044c0e8
0x0044c0e8:	pushl %ebp
0x0044c0e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x0044c0ec:	orl (%esi), %eax
0x0044c0ee:	lodsl %eax, %ds:(%esi)
0x0044c0ef:	jne 0x0044c0cc
0x0044c0df:	decb (%edi)
0x0044c0e1:	je 0x0040b4b8
0x0044c0e7:	pushl %edi
GetProcAddress@KERNEL32.dll: API Node	
LoadLibraryA@KERNEL32.dll: API Node	
0x0040b4b8:	pushl %ebp
0x0040b4b9:	movl %ebp, %esp
0x0040b4bb:	pushl $0xffffffff<UINT8>
0x0040b4bd:	pushl $0x4145b0<UINT32>
0x0040b4c2:	pushl $0x40ae34<UINT32>
0x0040b4c7:	movl %eax, %fs:0
0x0040b4cd:	pushl %eax
0x0040b4ce:	movl %fs:0, %esp
0x0040b4d5:	subl %esp, $0x58<UINT8>
0x0040b4d8:	pushl %ebx
0x0040b4d9:	pushl %esi
0x0040b4da:	pushl %edi
0x0040b4db:	movl -24(%ebp), %esp
0x0040b4de:	call GetVersion@KERNEL32.dll
GetVersion@KERNEL32.dll: API Node	
0x0040b4e4:	xorl %edx, %edx
0x0040b4e6:	movb %dl, %ah
0x0040b4e8:	movl 0x433680, %edx
0x0040b4ee:	movl %ecx, %eax
0x0040b4f0:	andl %ecx, $0xff<UINT32>
0x0040b4f6:	movl 0x43367c, %ecx
0x0040b4fc:	shll %ecx, $0x8<UINT8>
0x0040b4ff:	addl %ecx, %edx
0x0040b501:	movl 0x433678, %ecx
0x0040b507:	shrl %eax, $0x10<UINT8>
0x0040b50a:	movl 0x433674, %eax
0x0040b50f:	pushl $0x1<UINT8>
0x0040b511:	call 0x0040bf36
0x0040bf36:	xorl %eax, %eax
0x0040bf38:	pushl $0x0<UINT8>
0x0040bf3a:	cmpl 0x8(%esp), %eax
0x0040bf3e:	pushl $0x1000<UINT32>
0x0040bf43:	sete %al
0x0040bf46:	pushl %eax
0x0040bf47:	call HeapCreate@KERNEL32.dll
HeapCreate@KERNEL32.dll: API Node	
0x0040bf4d:	testl %eax, %eax
0x0040bf4f:	movl 0x4369dc, %eax
0x0040bf54:	je 21
0x0040bf56:	call 0x0040c011
0x0040c011:	pushl $0x140<UINT32>
0x0040c016:	pushl $0x0<UINT8>
0x0040c018:	pushl 0x4369dc
0x0040c01e:	call HeapAlloc@KERNEL32.dll
HeapAlloc@KERNEL32.dll: API Node	
0x0040c024:	testl %eax, %eax
0x0040c026:	movl 0x4369d8, %eax
0x0040c02b:	jne 0x0040c02e
0x0040c02e:	andl 0x4369d0, $0x0<UINT8>
0x0040c035:	andl 0x4369d4, $0x0<UINT8>
0x0040c03c:	pushl $0x1<UINT8>
0x0040c03e:	movl 0x4369cc, %eax
0x0040c043:	movl 0x4369c4, $0x10<UINT32>
0x0040c04d:	popl %eax
0x0040c04e:	ret

0x0040bf5b:	testl %eax, %eax
0x0040bf5d:	jne 0x0040bf6e
0x0040bf6e:	pushl $0x1<UINT8>
0x0040bf70:	popl %eax
0x0040bf71:	ret

0x0040b516:	popl %ecx
0x0040b517:	testl %eax, %eax
0x0040b519:	jne 0x0040b523
0x0040b523:	call 0x0040ccf9
0x0040ccf9:	pushl %esi
0x0040ccfa:	call 0x0040bf72
0x0040bf72:	pushl %esi
0x0040bf73:	movl %esi, 0x4140a8
0x0040bf79:	pushl 0x431308
0x0040bf7f:	call InitializeCriticalSection@KERNEL32.dll
InitializeCriticalSection@KERNEL32.dll: API Node	
0x0040bf81:	pushl 0x4312f8
0x0040bf87:	call InitializeCriticalSection@KERNEL32.dll
0x0040bf89:	pushl 0x4312e8
0x0040bf8f:	call InitializeCriticalSection@KERNEL32.dll
0x0040bf91:	pushl 0x4312c8
0x0040bf97:	call InitializeCriticalSection@KERNEL32.dll
0x0040bf99:	popl %esi
0x0040bf9a:	ret

0x0040ccff:	call TlsAlloc@KERNEL32.dll
TlsAlloc@KERNEL32.dll: API Node	
0x0040cd05:	cmpl %eax, $0xffffffff<UINT8>
0x0040cd08:	movl 0x4313a0, %eax
0x0040cd0d:	je 58
0x0040cd0f:	pushl $0x74<UINT8>
0x0040cd11:	pushl $0x1<UINT8>
0x0040cd13:	call 0x0040e140
0x0040e140:	pushl %ebx
0x0040e141:	pushl %esi
0x0040e142:	movl %esi, 0xc(%esp)
0x0040e146:	pushl %edi
0x0040e147:	imull %esi, 0x14(%esp)
0x0040e14c:	cmpl %esi, $0xffffffe0<UINT8>
0x0040e14f:	movl %ebx, %esi
0x0040e151:	ja 13
0x0040e153:	testl %esi, %esi
0x0040e155:	jne 0x0040e15a
0x0040e15a:	addl %esi, $0xf<UINT8>
0x0040e15d:	andl %esi, $0xfffffff0<UINT8>
0x0040e160:	xorl %edi, %edi
0x0040e162:	cmpl %esi, $0xffffffe0<UINT8>
0x0040e165:	ja 58
0x0040e167:	cmpl %ebx, 0x431384
0x0040e16d:	ja 0x0040e18c
0x0040e16f:	pushl $0x9<UINT8>
0x0040e171:	call 0x0040bf9b
0x0040bf9b:	pushl %ebp
0x0040bf9c:	movl %ebp, %esp
0x0040bf9e:	movl %eax, 0x8(%ebp)
0x0040bfa1:	pushl %esi
0x0040bfa2:	cmpl 0x4312c4(,%eax,4), $0x0<UINT8>
0x0040bfaa:	leal %esi, 0x4312c4(,%eax,4)
0x0040bfb1:	jne 0x0040bff1
0x0040bff1:	pushl (%esi)
0x0040bff3:	call EnterCriticalSection@KERNEL32.dll
EnterCriticalSection@KERNEL32.dll: API Node	
0x0040bff9:	popl %esi
0x0040bffa:	popl %ebp
0x0040bffb:	ret

0x0040e176:	pushl %ebx
0x0040e177:	call 0x0040c3a5
0x0040c3a5:	pushl %ebp
0x0040c3a6:	movl %ebp, %esp
0x0040c3a8:	subl %esp, $0x14<UINT8>
0x0040c3ab:	movl %eax, 0x4369d4
0x0040c3b0:	movl %edx, 0x4369d8
0x0040c3b6:	pushl %ebx
0x0040c3b7:	pushl %esi
0x0040c3b8:	leal %eax, (%eax,%eax,4)
0x0040c3bb:	pushl %edi
0x0040c3bc:	leal %edi, (%edx,%eax,4)
0x0040c3bf:	movl %eax, 0x8(%ebp)
0x0040c3c2:	movl -4(%ebp), %edi
0x0040c3c5:	leal %ecx, 0x17(%eax)
0x0040c3c8:	andl %ecx, $0xfffffff0<UINT8>
0x0040c3cb:	movl -16(%ebp), %ecx
0x0040c3ce:	sarl %ecx, $0x4<UINT8>
0x0040c3d1:	decl %ecx
0x0040c3d2:	cmpl %ecx, $0x20<UINT8>
0x0040c3d5:	jnl 14
0x0040c3d7:	orl %esi, $0xffffffff<UINT8>
0x0040c3da:	shrl %esi, %cl
0x0040c3dc:	orl -8(%ebp), $0xffffffff<UINT8>
0x0040c3e0:	movl -12(%ebp), %esi
0x0040c3e3:	jmp 0x0040c3f5
0x0040c3f5:	movl %eax, 0x4369cc
0x0040c3fa:	movl %ebx, %eax
0x0040c3fc:	cmpl %ebx, %edi
0x0040c3fe:	movl 0x8(%ebp), %ebx
0x0040c401:	jae 0x0040c41c
0x0040c41c:	cmpl %ebx, -4(%ebp)
0x0040c41f:	jne 0x0040c49a
0x0040c421:	movl %ebx, %edx
0x0040c423:	cmpl %ebx, %eax
0x0040c425:	movl 0x8(%ebp), %ebx
0x0040c428:	jae 0x0040c43f
0x0040c43f:	jne 89
0x0040c441:	cmpl %ebx, -4(%ebp)
0x0040c444:	jae 0x0040c457
0x0040c457:	jne 38
0x0040c459:	movl %ebx, %edx
0x0040c45b:	cmpl %ebx, %eax
0x0040c45d:	movl 0x8(%ebp), %ebx
0x0040c460:	jae 0x0040c46f
0x0040c46f:	jne 14
0x0040c471:	call 0x0040c6ae
0x0040c6ae:	movl %eax, 0x4369d4
0x0040c6b3:	movl %ecx, 0x4369c4
0x0040c6b9:	pushl %esi
0x0040c6ba:	pushl %edi
0x0040c6bb:	xorl %edi, %edi
0x0040c6bd:	cmpl %eax, %ecx
0x0040c6bf:	jne 0x0040c6f1
0x0040c6f1:	movl %ecx, 0x4369d8
0x0040c6f7:	pushl $0x41c4<UINT32>
0x0040c6fc:	pushl $0x8<UINT8>
0x0040c6fe:	leal %eax, (%eax,%eax,4)
0x0040c701:	pushl 0x4369dc
0x0040c707:	leal %esi, (%ecx,%eax,4)
0x0040c70a:	call HeapAlloc@KERNEL32.dll
0x0040c710:	cmpl %eax, %edi
0x0040c712:	movl 0x10(%esi), %eax
0x0040c715:	je 42
0x0040c717:	pushl $0x4<UINT8>
0x0040c719:	pushl $0x2000<UINT32>
0x0040c71e:	pushl $0x100000<UINT32>
0x0040c723:	pushl %edi
0x0040c724:	call VirtualAlloc@KERNEL32.dll
VirtualAlloc@KERNEL32.dll: API Node	
0x0040c72a:	cmpl %eax, %edi
0x0040c72c:	movl 0xc(%esi), %eax
0x0040c72f:	jne 0x0040c745
0x0040c745:	orl 0x8(%esi), $0xffffffff<UINT8>
0x0040c749:	movl (%esi), %edi
0x0040c74b:	movl 0x4(%esi), %edi
0x0040c74e:	incl 0x4369d4
0x0040c754:	movl %eax, 0x10(%esi)
0x0040c757:	orl (%eax), $0xffffffff<UINT8>
0x0040c75a:	movl %eax, %esi
0x0040c75c:	popl %edi
0x0040c75d:	popl %esi
0x0040c75e:	ret

0x0040c476:	movl %ebx, %eax
0x0040c478:	testl %ebx, %ebx
0x0040c47a:	movl 0x8(%ebp), %ebx
0x0040c47d:	je 20
0x0040c47f:	pushl %ebx
0x0040c480:	call 0x0040c75f
0x0040c75f:	pushl %ebp
0x0040c760:	movl %ebp, %esp
0x0040c762:	pushl %ecx
0x0040c763:	movl %ecx, 0x8(%ebp)
0x0040c766:	pushl %ebx
0x0040c767:	pushl %esi
0x0040c768:	pushl %edi
0x0040c769:	movl %esi, 0x10(%ecx)
0x0040c76c:	movl %eax, 0x8(%ecx)
0x0040c76f:	xorl %ebx, %ebx
0x0040c771:	testl %eax, %eax
0x0040c773:	jl 0x0040c77a
0x0040c77a:	movl %eax, %ebx
0x0040c77c:	pushl $0x3f<UINT8>
0x0040c77e:	imull %eax, %eax, $0x204<UINT32>
0x0040c784:	popl %edx
0x0040c785:	leal %eax, 0x144(%eax,%esi)
0x0040c78c:	movl -4(%ebp), %eax
0x0040c78f:	movl 0x8(%eax), %eax
0x0040c792:	movl 0x4(%eax), %eax
0x0040c795:	addl %eax, $0x8<UINT8>
0x0040c798:	decl %edx
0x0040c799:	jne 0x0040c78f
0x0040c79b:	movl %edi, %ebx
0x0040c79d:	pushl $0x4<UINT8>
0x0040c79f:	shll %edi, $0xf<UINT8>
0x0040c7a2:	addl %edi, 0xc(%ecx)
0x0040c7a5:	pushl $0x1000<UINT32>
0x0040c7aa:	pushl $0x8000<UINT32>
0x0040c7af:	pushl %edi
0x0040c7b0:	call VirtualAlloc@KERNEL32.dll
0x0040c7b6:	testl %eax, %eax
0x0040c7b8:	jne 0x0040c7c2
0x0040c7c2:	leal %edx, 0x7000(%edi)
0x0040c7c8:	cmpl %edi, %edx
0x0040c7ca:	ja 60
0x0040c7cc:	leal %eax, 0x10(%edi)
0x0040c7cf:	orl -8(%eax), $0xffffffff<UINT8>
0x0040c7d3:	orl 0xfec(%eax), $0xffffffff<UINT8>
0x0040c7da:	leal %ecx, 0xffc(%eax)
0x0040c7e0:	movl -4(%eax), $0xff0<UINT32>
0x0040c7e7:	movl (%eax), %ecx
0x0040c7e9:	leal %ecx, -4100(%eax)
0x0040c7ef:	movl 0x4(%eax), %ecx
0x0040c7f2:	movl 0xfe8(%eax), $0xff0<UINT32>
0x0040c7fc:	addl %eax, $0x1000<UINT32>
0x0040c801:	leal %ecx, -16(%eax)
0x0040c804:	cmpl %ecx, %edx
0x0040c806:	jbe 0x0040c7cf
0x0040c808:	movl %eax, -4(%ebp)
0x0040c80b:	leal %ecx, 0xc(%edi)
0x0040c80e:	addl %eax, $0x1f8<UINT32>
0x0040c813:	pushl $0x1<UINT8>
0x0040c815:	popl %edi
0x0040c816:	movl 0x4(%eax), %ecx
0x0040c819:	movl 0x8(%ecx), %eax
0x0040c81c:	leal %ecx, 0xc(%edx)
0x0040c81f:	movl 0x8(%eax), %ecx
0x0040c822:	movl 0x4(%ecx), %eax
0x0040c825:	andl 0x44(%esi,%ebx,4), $0x0<UINT8>
0x0040c82a:	movl 0xc4(%esi,%ebx,4), %edi
0x0040c831:	movb %al, 0x43(%esi)
0x0040c834:	movb %cl, %al
0x0040c836:	incb %cl
0x0040c838:	testb %al, %al
0x0040c83a:	movl %eax, 0x8(%ebp)
0x0040c83d:	movb 0x43(%esi), %cl
0x0040c840:	jne 3
0x0040c842:	orl 0x4(%eax), %edi
0x0040c845:	movl %edx, $0x80000000<UINT32>
0x0040c84a:	movl %ecx, %ebx
0x0040c84c:	shrl %edx, %cl
0x0040c84e:	notl %edx
0x0040c850:	andl 0x8(%eax), %edx
0x0040c853:	movl %eax, %ebx
0x0040c855:	popl %edi
0x0040c856:	popl %esi
0x0040c857:	popl %ebx
0x0040c858:	leave
0x0040c859:	ret

0x0040c485:	popl %ecx
0x0040c486:	movl %ecx, 0x10(%ebx)
0x0040c489:	movl (%ecx), %eax
0x0040c48b:	movl %eax, 0x10(%ebx)
0x0040c48e:	cmpl (%eax), $0xffffffff<UINT8>
0x0040c491:	jne 0x0040c49a
0x0040c49a:	movl 0x4369cc, %ebx
0x0040c4a0:	movl %eax, 0x10(%ebx)
0x0040c4a3:	movl %edx, (%eax)
0x0040c4a5:	cmpl %edx, $0xffffffff<UINT8>
0x0040c4a8:	movl -4(%ebp), %edx
0x0040c4ab:	je 20
0x0040c4ad:	movl %ecx, 0xc4(%eax,%edx,4)
0x0040c4b4:	movl %edi, 0x44(%eax,%edx,4)
0x0040c4b8:	andl %ecx, -8(%ebp)
0x0040c4bb:	andl %edi, %esi
0x0040c4bd:	orl %ecx, %edi
0x0040c4bf:	jne 0x0040c4f8
0x0040c4f8:	movl %ecx, %edx
0x0040c4fa:	xorl %edi, %edi
0x0040c4fc:	imull %ecx, %ecx, $0x204<UINT32>
0x0040c502:	leal %ecx, 0x144(%ecx,%eax)
0x0040c509:	movl -12(%ebp), %ecx
0x0040c50c:	movl %ecx, 0x44(%eax,%edx,4)
0x0040c510:	andl %ecx, %esi
0x0040c512:	jne 13
0x0040c514:	movl %ecx, 0xc4(%eax,%edx,4)
0x0040c51b:	pushl $0x20<UINT8>
0x0040c51d:	andl %ecx, -8(%ebp)
0x0040c520:	popl %edi
0x0040c521:	testl %ecx, %ecx
0x0040c523:	jl 0x0040c52a
0x0040c525:	shll %ecx
0x0040c527:	incl %edi
0x0040c528:	jmp 0x0040c521
0x0040c52a:	movl %ecx, -12(%ebp)
0x0040c52d:	movl %edx, 0x4(%ecx,%edi,8)
0x0040c531:	movl %ecx, (%edx)
0x0040c533:	subl %ecx, -16(%ebp)
0x0040c536:	movl %esi, %ecx
0x0040c538:	movl -8(%ebp), %ecx
0x0040c53b:	sarl %esi, $0x4<UINT8>
0x0040c53e:	decl %esi
0x0040c53f:	cmpl %esi, $0x3f<UINT8>
0x0040c542:	jle 3
0x0040c544:	pushl $0x3f<UINT8>
0x0040c546:	popl %esi
0x0040c547:	cmpl %esi, %edi
0x0040c549:	je 0x0040c65c
0x0040c65c:	testl %ecx, %ecx
0x0040c65e:	je 11
0x0040c660:	movl (%edx), %ecx
0x0040c662:	movl -4(%ecx,%edx), %ecx
0x0040c666:	jmp 0x0040c66b
0x0040c66b:	movl %esi, -16(%ebp)
0x0040c66e:	addl %edx, %ecx
0x0040c670:	leal %ecx, 0x1(%esi)
0x0040c673:	movl (%edx), %ecx
0x0040c675:	movl -4(%edx,%esi), %ecx
0x0040c679:	movl %esi, -12(%ebp)
0x0040c67c:	movl %ecx, (%esi)
0x0040c67e:	testl %ecx, %ecx
0x0040c680:	leal %edi, 0x1(%ecx)
0x0040c683:	movl (%esi), %edi
0x0040c685:	jne 0x0040c6a1
0x0040c687:	cmpl %ebx, 0x4369d0
0x0040c68d:	jne 0x0040c6a1
0x0040c6a1:	movl %ecx, -4(%ebp)
0x0040c6a4:	movl (%eax), %ecx
0x0040c6a6:	leal %eax, 0x4(%edx)
0x0040c6a9:	popl %edi
0x0040c6aa:	popl %esi
0x0040c6ab:	popl %ebx
0x0040c6ac:	leave
0x0040c6ad:	ret

0x0040e17c:	pushl $0x9<UINT8>
0x0040e17e:	movl %edi, %eax
0x0040e180:	call 0x0040bffc
0x0040bffc:	pushl %ebp
0x0040bffd:	movl %ebp, %esp
0x0040bfff:	movl %eax, 0x8(%ebp)
0x0040c002:	pushl 0x4312c4(,%eax,4)
0x0040c009:	call LeaveCriticalSection@KERNEL32.dll
LeaveCriticalSection@KERNEL32.dll: API Node	
0x0040c00f:	popl %ebp
0x0040c010:	ret

0x0040e185:	addl %esp, $0xc<UINT8>
0x0040e188:	testl %edi, %edi
0x0040e18a:	jne 0x0040e1b7
0x0040e1b7:	pushl %ebx
0x0040e1b8:	pushl $0x0<UINT8>
0x0040e1ba:	pushl %edi
0x0040e1bb:	call 0x00410510
0x00410510:	movl %edx, 0xc(%esp)
0x00410514:	movl %ecx, 0x4(%esp)
0x00410518:	testl %edx, %edx
0x0041051a:	je 71
0x0041051c:	xorl %eax, %eax
0x0041051e:	movb %al, 0x8(%esp)
0x00410522:	pushl %edi
0x00410523:	movl %edi, %ecx
0x00410525:	cmpl %edx, $0x4<UINT8>
0x00410528:	jb 45
0x0041052a:	negl %ecx
0x0041052c:	andl %ecx, $0x3<UINT8>
0x0041052f:	je 0x00410539
0x00410539:	movl %ecx, %eax
0x0041053b:	shll %eax, $0x8<UINT8>
0x0041053e:	addl %eax, %ecx
0x00410540:	movl %ecx, %eax
0x00410542:	shll %eax, $0x10<UINT8>
0x00410545:	addl %eax, %ecx
0x00410547:	movl %ecx, %edx
0x00410549:	andl %edx, $0x3<UINT8>
0x0041054c:	shrl %ecx, $0x2<UINT8>
0x0041054f:	je 6
0x00410551:	rep stosl %es:(%edi), %eax
0x00410553:	testl %edx, %edx
0x00410555:	je 0x0041055d
0x0041055d:	movl %eax, 0x8(%esp)
0x00410561:	popl %edi
0x00410562:	ret

0x0040e1c0:	addl %esp, $0xc<UINT8>
0x0040e1c3:	movl %eax, %edi
0x0040e1c5:	popl %edi
0x0040e1c6:	popl %esi
0x0040e1c7:	popl %ebx
0x0040e1c8:	ret

0x0040cd18:	movl %esi, %eax
0x0040cd1a:	popl %ecx
0x0040cd1b:	testl %esi, %esi
0x0040cd1d:	popl %ecx
0x0040cd1e:	je 41
0x0040cd20:	pushl %esi
0x0040cd21:	pushl 0x4313a0
0x0040cd27:	call TlsSetValue@KERNEL32.dll
TlsSetValue@KERNEL32.dll: API Node	
0x0040cd2d:	testl %eax, %eax
0x0040cd2f:	je 24
0x0040cd31:	pushl %esi
0x0040cd32:	call 0x0040cd4d
0x0040cd4d:	movl %eax, 0x4(%esp)
0x0040cd51:	movl 0x50(%eax), $0x431760<UINT32>
0x0040cd58:	movl 0x14(%eax), $0x1<UINT32>
0x0040cd5f:	ret

0x0040cd37:	popl %ecx
0x0040cd38:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x0040cd3e:	orl 0x4(%esi), $0xffffffff<UINT8>
0x0040cd42:	pushl $0x1<UINT8>
0x0040cd44:	movl (%esi), %eax
0x0040cd46:	popl %eax
0x0040cd47:	popl %esi
0x0040cd48:	ret

0x0040b528:	testl %eax, %eax
0x0040b52a:	jne 0x0040b534
0x0040b534:	xorl %esi, %esi
0x0040b536:	movl -4(%ebp), %esi
0x0040b539:	call 0x0040df84
0x0040df84:	pushl %ebp
0x0040df85:	movl %ebp, %esp
0x0040df87:	subl %esp, $0x48<UINT8>
0x0040df8a:	pushl %ebx
0x0040df8b:	pushl %esi
0x0040df8c:	pushl %edi
0x0040df8d:	pushl $0x480<UINT32>
0x0040df92:	call 0x0040a837
0x0040a837:	pushl 0x4335fc
0x0040a83d:	pushl 0x8(%esp)
0x0040a841:	call 0x0040a849
0x0040a849:	cmpl 0x4(%esp), $0xffffffe0<UINT8>
0x0040a84e:	ja 34
0x0040a850:	pushl 0x4(%esp)
0x0040a854:	call 0x0040a875
0x0040a875:	pushl %esi
0x0040a876:	movl %esi, 0x8(%esp)
0x0040a87a:	cmpl %esi, 0x431384
0x0040a880:	pushl %edi
0x0040a881:	ja 0x0040a8a4
0x0040a8a4:	testl %esi, %esi
0x0040a8a6:	jne 0x0040a8ab
0x0040a8ab:	addl %esi, $0xf<UINT8>
0x0040a8ae:	andl %esi, $0xfffffff0<UINT8>
0x0040a8b1:	pushl %esi
0x0040a8b2:	pushl $0x0<UINT8>
0x0040a8b4:	pushl 0x4369dc
0x0040a8ba:	call HeapAlloc@KERNEL32.dll
0x0040a8c0:	popl %edi
0x0040a8c1:	popl %esi
0x0040a8c2:	ret

0x0040a859:	testl %eax, %eax
0x0040a85b:	popl %ecx
0x0040a85c:	jne 0x0040a874
0x0040a874:	ret

0x0040a846:	popl %ecx
0x0040a847:	popl %ecx
0x0040a848:	ret

0x0040df97:	movl %esi, %eax
0x0040df99:	popl %ecx
0x0040df9a:	testl %esi, %esi
0x0040df9c:	jne 0x0040dfa6
0x0040dfa6:	movl 0x4368c0, %esi
0x0040dfac:	movl 0x4369c0, $0x20<UINT32>
0x0040dfb6:	leal %eax, 0x480(%esi)
0x0040dfbc:	cmpl %esi, %eax
0x0040dfbe:	jae 0x0040dfde
0x0040dfc0:	andb 0x4(%esi), $0x0<UINT8>
0x0040dfc4:	orl (%esi), $0xffffffff<UINT8>
0x0040dfc7:	andl 0x8(%esi), $0x0<UINT8>
0x0040dfcb:	movb 0x5(%esi), $0xa<UINT8>
0x0040dfcf:	movl %eax, 0x4368c0
0x0040dfd4:	addl %esi, $0x24<UINT8>
0x0040dfd7:	addl %eax, $0x480<UINT32>
0x0040dfdc:	jmp 0x0040dfbc
0x0040dfde:	leal %eax, -72(%ebp)
0x0040dfe1:	pushl %eax
0x0040dfe2:	call GetStartupInfoA@KERNEL32.dll
GetStartupInfoA@KERNEL32.dll: API Node	
0x0040dfe8:	cmpw -22(%ebp), $0x0<UINT8>
0x0040dfed:	je 209
0x0040dff3:	movl %eax, -20(%ebp)
0x0040dff6:	testl %eax, %eax
0x0040dff8:	je 198
0x0040dffe:	movl %edi, (%eax)
0x0040e000:	leal %ebx, 0x4(%eax)
0x0040e003:	leal %eax, (%ebx,%edi)
0x0040e006:	movl -4(%ebp), %eax
0x0040e009:	movl %eax, $0x800<UINT32>
0x0040e00e:	cmpl %edi, %eax
0x0040e010:	jl 0x0040e014
0x0040e014:	cmpl 0x4369c0, %edi
0x0040e01a:	jnl 0x0040e072
0x0040e072:	xorl %esi, %esi
0x0040e074:	testl %edi, %edi
0x0040e076:	jle 0x0040e0c4
0x0040e0c4:	xorl %ebx, %ebx
0x0040e0c6:	movl %ecx, 0x4368c0
0x0040e0cc:	leal %eax, (%ebx,%ebx,8)
0x0040e0cf:	cmpl (%ecx,%eax,4), $0xffffffff<UINT8>
0x0040e0d3:	leal %esi, (%ecx,%eax,4)
0x0040e0d6:	jne 77
0x0040e0d8:	testl %ebx, %ebx
0x0040e0da:	movb 0x4(%esi), $0xffffff81<UINT8>
0x0040e0de:	jne 0x0040e0e5
0x0040e0e0:	pushl $0xfffffff6<UINT8>
0x0040e0e2:	popl %eax
0x0040e0e3:	jmp 0x0040e0ef
0x0040e0ef:	pushl %eax
0x0040e0f0:	call GetStdHandle@KERNEL32.dll
GetStdHandle@KERNEL32.dll: API Node	
0x0040e0f6:	movl %edi, %eax
0x0040e0f8:	cmpl %edi, $0xffffffff<UINT8>
0x0040e0fb:	je 23
0x0040e0fd:	pushl %edi
0x0040e0fe:	call GetFileType@KERNEL32.dll
GetFileType@KERNEL32.dll: API Node	
0x0040e104:	testl %eax, %eax
0x0040e106:	je 12
0x0040e108:	andl %eax, $0xff<UINT32>
0x0040e10d:	movl (%esi), %edi
0x0040e10f:	cmpl %eax, $0x2<UINT8>
0x0040e112:	jne 6
0x0040e114:	orb 0x4(%esi), $0x40<UINT8>
0x0040e118:	jmp 0x0040e129
0x0040e129:	incl %ebx
0x0040e12a:	cmpl %ebx, $0x3<UINT8>
0x0040e12d:	jl 0x0040e0c6
0x0040e0e5:	movl %eax, %ebx
0x0040e0e7:	decl %eax
0x0040e0e8:	negl %eax
0x0040e0ea:	sbbl %eax, %eax
0x0040e0ec:	addl %eax, $0xfffffff5<UINT8>
0x0040e12f:	pushl 0x4369c0
0x0040e135:	call SetHandleCount@KERNEL32.dll
SetHandleCount@KERNEL32.dll: API Node	
0x0040e13b:	popl %edi
0x0040e13c:	popl %esi
0x0040e13d:	popl %ebx
0x0040e13e:	leave
0x0040e13f:	ret

0x0040b53e:	call GetCommandLineA@KERNEL32.dll
GetCommandLineA@KERNEL32.dll: API Node	
0x0040b544:	movl 0x4369e0, %eax
0x0040b549:	call 0x0040f125
0x0040f125:	pushl %ecx
0x0040f126:	pushl %ecx
0x0040f127:	movl %eax, 0x4337e4
0x0040f12c:	pushl %ebx
0x0040f12d:	pushl %ebp
0x0040f12e:	movl %ebp, 0x4140f0
0x0040f134:	pushl %esi
0x0040f135:	pushl %edi
0x0040f136:	xorl %ebx, %ebx
0x0040f138:	xorl %esi, %esi
0x0040f13a:	xorl %edi, %edi
0x0040f13c:	cmpl %eax, %ebx
0x0040f13e:	jne 51
0x0040f140:	call GetEnvironmentStringsW@KERNEL32.dll
GetEnvironmentStringsW@KERNEL32.dll: API Node	
0x0040f142:	movl %esi, %eax
0x0040f144:	cmpl %esi, %ebx
0x0040f146:	je 12
0x0040f148:	movl 0x4337e4, $0x1<UINT32>
0x0040f152:	jmp 0x0040f17c
0x0040f17c:	cmpl %esi, %ebx
0x0040f17e:	jne 0x0040f18c
0x0040f18c:	cmpw (%esi), %bx
0x0040f18f:	movl %eax, %esi
0x0040f191:	je 14
0x0040f193:	incl %eax
0x0040f194:	incl %eax
0x0040f195:	cmpw (%eax), %bx
0x0040f198:	jne 0x0040f193
0x0040f19a:	incl %eax
0x0040f19b:	incl %eax
0x0040f19c:	cmpw (%eax), %bx
0x0040f19f:	jne 0x0040f193
0x0040f1a1:	subl %eax, %esi
0x0040f1a3:	movl %edi, 0x4140ac
0x0040f1a9:	sarl %eax
0x0040f1ab:	pushl %ebx
0x0040f1ac:	pushl %ebx
0x0040f1ad:	incl %eax
0x0040f1ae:	pushl %ebx
0x0040f1af:	pushl %ebx
0x0040f1b0:	pushl %eax
0x0040f1b1:	pushl %esi
0x0040f1b2:	pushl %ebx
0x0040f1b3:	pushl %ebx
0x0040f1b4:	movl 0x34(%esp), %eax
0x0040f1b8:	call WideCharToMultiByte@KERNEL32.dll
WideCharToMultiByte@KERNEL32.dll: API Node	
0x0040f1ba:	movl %ebp, %eax
0x0040f1bc:	cmpl %ebp, %ebx
0x0040f1be:	je 50
0x0040f1c0:	pushl %ebp
0x0040f1c1:	call 0x0040a837
0x0040f1c6:	cmpl %eax, %ebx
0x0040f1c8:	popl %ecx
0x0040f1c9:	movl 0x10(%esp), %eax
0x0040f1cd:	je 35
0x0040f1cf:	pushl %ebx
0x0040f1d0:	pushl %ebx
0x0040f1d1:	pushl %ebp
0x0040f1d2:	pushl %eax
0x0040f1d3:	pushl 0x24(%esp)
0x0040f1d7:	pushl %esi
0x0040f1d8:	pushl %ebx
0x0040f1d9:	pushl %ebx
0x0040f1da:	call WideCharToMultiByte@KERNEL32.dll
0x0040f1dc:	testl %eax, %eax
0x0040f1de:	jne 0x0040f1ee
0x0040f1ee:	movl %ebx, 0x10(%esp)
0x0040f1f2:	pushl %esi
0x0040f1f3:	call FreeEnvironmentStringsW@KERNEL32.dll
FreeEnvironmentStringsW@KERNEL32.dll: API Node	
0x0040f1f9:	movl %eax, %ebx
0x0040f1fb:	jmp 0x0040f250
0x0040f250:	popl %edi
0x0040f251:	popl %esi
0x0040f252:	popl %ebp
0x0040f253:	popl %ebx
0x0040f254:	popl %ecx
0x0040f255:	popl %ecx
0x0040f256:	ret

0x0040b54e:	movl 0x4335f0, %eax
0x0040b553:	call 0x0040eed8
0x0040eed8:	pushl %ebp
0x0040eed9:	movl %ebp, %esp
0x0040eedb:	pushl %ecx
0x0040eedc:	pushl %ecx
0x0040eedd:	pushl %ebx
0x0040eede:	xorl %ebx, %ebx
0x0040eee0:	cmpl 0x4368b4, %ebx
0x0040eee6:	pushl %esi
0x0040eee7:	pushl %edi
0x0040eee8:	jne 5
0x0040eeea:	call 0x00411b9f
0x00411b9f:	cmpl 0x4368b4, $0x0<UINT8>
0x00411ba6:	jne 0x00411bba
0x00411ba8:	pushl $0xfffffffd<UINT8>
0x00411baa:	call 0x004117c7
0x004117c7:	pushl %ebp
0x004117c8:	movl %ebp, %esp
0x004117ca:	subl %esp, $0x18<UINT8>
0x004117cd:	pushl %ebx
0x004117ce:	pushl %esi
0x004117cf:	pushl %edi
0x004117d0:	pushl $0x19<UINT8>
0x004117d2:	call 0x0040bf9b
0x0040bfb3:	pushl %edi
0x0040bfb4:	pushl $0x18<UINT8>
0x0040bfb6:	call 0x0040a837
0x0040a883:	pushl $0x9<UINT8>
0x0040a885:	call 0x0040bf9b
0x0040a88a:	pushl %esi
0x0040a88b:	call 0x0040c3a5
0x0040c403:	movl %ecx, 0x4(%ebx)
0x0040c406:	movl %edi, (%ebx)
0x0040c408:	andl %ecx, -8(%ebp)
0x0040c40b:	andl %edi, %esi
0x0040c40d:	orl %ecx, %edi
0x0040c40f:	jne 0x0040c41c
0x0040a890:	pushl $0x9<UINT8>
0x0040a892:	movl %edi, %eax
0x0040a894:	call 0x0040bffc
0x0040a899:	addl %esp, $0xc<UINT8>
0x0040a89c:	testl %edi, %edi
0x0040a89e:	je 4
0x0040a8a0:	movl %eax, %edi
0x0040a8a2:	jmp 0x0040a8c0
0x0040bfbb:	movl %edi, %eax
0x0040bfbd:	popl %ecx
0x0040bfbe:	testl %edi, %edi
0x0040bfc0:	jne 0x0040bfca
0x0040bfca:	pushl $0x11<UINT8>
0x0040bfcc:	call 0x0040bf9b
0x0040bfd1:	cmpl (%esi), $0x0<UINT8>
0x0040bfd4:	popl %ecx
0x0040bfd5:	pushl %edi
0x0040bfd6:	jne 10
0x0040bfd8:	call InitializeCriticalSection@KERNEL32.dll
0x0040bfde:	movl (%esi), %edi
0x0040bfe0:	jmp 0x0040bfe8
0x0040bfe8:	pushl $0x11<UINT8>
0x0040bfea:	call 0x0040bffc
0x0040bfef:	popl %ecx
0x0040bff0:	popl %edi
0x004117d7:	pushl 0x8(%ebp)
0x004117da:	call 0x00411974
0x00411974:	movl %eax, 0x4(%esp)
0x00411978:	andl 0x43385c, $0x0<UINT8>
0x0041197f:	cmpl %eax, $0xfffffffe<UINT8>
0x00411982:	jne 0x00411994
0x00411994:	cmpl %eax, $0xfffffffd<UINT8>
0x00411997:	jne 16
0x00411999:	movl 0x43385c, $0x1<UINT32>
0x004119a3:	jmp GetACP@KERNEL32.dll
GetACP@KERNEL32.dll: API Node	
0x004117df:	movl %ebx, %eax
0x004117e1:	popl %ecx
0x004117e2:	cmpl %ebx, 0x43667c
0x004117e8:	popl %ecx
0x004117e9:	movl 0x8(%ebp), %ebx
0x004117ec:	jne 0x004117f5
0x004117f5:	testl %ebx, %ebx
0x004117f7:	je 342
0x004117fd:	xorl %edx, %edx
0x004117ff:	movl %eax, $0x4319c8<UINT32>
0x00411804:	cmpl (%eax), %ebx
0x00411806:	je 116
0x00411808:	addl %eax, $0x30<UINT8>
0x0041180b:	incl %edx
0x0041180c:	cmpl %eax, $0x431ab8<UINT32>
0x00411811:	jl 0x00411804
0x00411813:	leal %eax, -24(%ebp)
0x00411816:	pushl %eax
0x00411817:	pushl %ebx
0x00411818:	call GetCPInfo@KERNEL32.dll
GetCPInfo@KERNEL32.dll: API Node	
0x0041181e:	pushl $0x1<UINT8>
0x00411820:	popl %esi
0x00411821:	cmpl %eax, %esi
0x00411823:	jne 289
0x00411829:	pushl $0x40<UINT8>
0x0041182b:	andl 0x4368a4, $0x0<UINT8>
0x00411832:	popl %ecx
0x00411833:	xorl %eax, %eax
0x00411835:	movl %edi, $0x4367a0<UINT32>
0x0041183a:	cmpl -24(%ebp), %esi
0x0041183d:	rep stosl %es:(%edi), %eax
0x0041183f:	stosb %es:(%edi), %al
0x00411840:	movl 0x43667c, %ebx
0x00411846:	jbe 235
0x0041184c:	cmpb -18(%ebp), $0x0<UINT8>
0x00411850:	je 0x00411912
0x00411912:	movl %eax, %esi
0x00411914:	orb 0x4367a1(%eax), $0x8<UINT8>
0x0041191b:	incl %eax
0x0041191c:	cmpl %eax, $0xff<UINT32>
0x00411921:	jb 0x00411914
0x00411923:	pushl %ebx
0x00411924:	call 0x004119be
0x004119be:	movl %eax, 0x4(%esp)
0x004119c2:	subl %eax, $0x3a4<UINT32>
0x004119c7:	je 34
0x004119c9:	subl %eax, $0x4<UINT8>
0x004119cc:	je 23
0x004119ce:	subl %eax, $0xd<UINT8>
0x004119d1:	je 12
0x004119d3:	decl %eax
0x004119d4:	je 3
0x004119d6:	xorl %eax, %eax
0x004119d8:	ret

0x00411929:	popl %ecx
0x0041192a:	movl 0x4368a4, %eax
0x0041192f:	movl 0x43668c, %esi
0x00411935:	jmp 0x0041193e
0x0041193e:	xorl %eax, %eax
0x00411940:	movl %edi, $0x436680<UINT32>
0x00411945:	stosl %es:(%edi), %eax
0x00411946:	stosl %es:(%edi), %eax
0x00411947:	stosl %es:(%edi), %eax
0x00411948:	jmp 0x00411958
0x00411958:	call 0x00411a1a
0x00411a1a:	pushl %ebp
0x00411a1b:	movl %ebp, %esp
0x00411a1d:	subl %esp, $0x514<UINT32>
0x00411a23:	leal %eax, -20(%ebp)
0x00411a26:	pushl %esi
0x00411a27:	pushl %eax
0x00411a28:	pushl 0x43667c
0x00411a2e:	call GetCPInfo@KERNEL32.dll
0x00411a34:	cmpl %eax, $0x1<UINT8>
0x00411a37:	jne 278
0x00411a3d:	xorl %eax, %eax
0x00411a3f:	movl %esi, $0x100<UINT32>
0x00411a44:	movb -276(%ebp,%eax), %al
0x00411a4b:	incl %eax
0x00411a4c:	cmpl %eax, %esi
0x00411a4e:	jb 0x00411a44
0x00411a50:	movb %al, -14(%ebp)
0x00411a53:	movb -276(%ebp), $0x20<UINT8>
0x00411a5a:	testb %al, %al
0x00411a5c:	je 0x00411a95
0x00411a95:	pushl $0x0<UINT8>
0x00411a97:	leal %eax, -1300(%ebp)
0x00411a9d:	pushl 0x4368a4
0x00411aa3:	pushl 0x43667c
0x00411aa9:	pushl %eax
0x00411aaa:	leal %eax, -276(%ebp)
0x00411ab0:	pushl %esi
0x00411ab1:	pushl %eax
0x00411ab2:	pushl $0x1<UINT8>
0x00411ab4:	call 0x00410e6c
0x00410e6c:	pushl %ebp
0x00410e6d:	movl %ebp, %esp
0x00410e6f:	pushl $0xffffffff<UINT8>
0x00410e71:	pushl $0x414978<UINT32>
0x00410e76:	pushl $0x40ae34<UINT32>
0x00410e7b:	movl %eax, %fs:0
0x00410e81:	pushl %eax
0x00410e82:	movl %fs:0, %esp
0x00410e89:	subl %esp, $0x18<UINT8>
0x00410e8c:	pushl %ebx
0x00410e8d:	pushl %esi
0x00410e8e:	pushl %edi
0x00410e8f:	movl -24(%ebp), %esp
0x00410e92:	movl %eax, 0x4337f0
0x00410e97:	xorl %ebx, %ebx
0x00410e99:	cmpl %eax, %ebx
0x00410e9b:	jne 62
0x00410e9d:	leal %eax, -28(%ebp)
0x00410ea0:	pushl %eax
0x00410ea1:	pushl $0x1<UINT8>
0x00410ea3:	popl %esi
0x00410ea4:	pushl %esi
0x00410ea5:	pushl $0x414970<UINT32>
0x00410eaa:	pushl %esi
0x00410eab:	call GetStringTypeW@KERNEL32.dll
GetStringTypeW@KERNEL32.dll: API Node	
0x00410eb1:	testl %eax, %eax
0x00410eb3:	je 4
0x00410eb5:	movl %eax, %esi
0x00410eb7:	jmp 0x00410ed6
0x00410ed6:	movl 0x4337f0, %eax
0x00410edb:	cmpl %eax, $0x2<UINT8>
0x00410ede:	jne 0x00410f04
0x00410f04:	cmpl %eax, $0x1<UINT8>
0x00410f07:	jne 148
0x00410f0d:	cmpl 0x18(%ebp), %ebx
0x00410f10:	jne 0x00410f1a
0x00410f1a:	pushl %ebx
0x00410f1b:	pushl %ebx
0x00410f1c:	pushl 0x10(%ebp)
0x00410f1f:	pushl 0xc(%ebp)
0x00410f22:	movl %eax, 0x20(%ebp)
0x00410f25:	negl %eax
0x00410f27:	sbbl %eax, %eax
0x00410f29:	andl %eax, $0x8<UINT8>
0x00410f2c:	incl %eax
0x00410f2d:	pushl %eax
0x00410f2e:	pushl 0x18(%ebp)
0x00410f31:	call MultiByteToWideChar@KERNEL32.dll
MultiByteToWideChar@KERNEL32.dll: API Node	
0x00410f37:	movl -32(%ebp), %eax
0x00410f3a:	cmpl %eax, %ebx
0x00410f3c:	je 99
0x00410f3e:	movl -4(%ebp), %ebx
0x00410f41:	leal %edi, (%eax,%eax)
0x00410f44:	movl %eax, %edi
0x00410f46:	addl %eax, $0x3<UINT8>
0x00410f49:	andb %al, $0xfffffffc<UINT8>
0x00410f4b:	call 0x0040ab00
0x0040ab00:	pushl %ecx
0x0040ab01:	cmpl %eax, $0x1000<UINT32>
0x0040ab06:	leal %ecx, 0x8(%esp)
0x0040ab0a:	jb 0x0040ab20
0x0040ab20:	subl %ecx, %eax
0x0040ab22:	movl %eax, %esp
0x0040ab24:	testl (%ecx), %eax
0x0040ab26:	movl %esp, %ecx
0x0040ab28:	movl %ecx, (%eax)
0x0040ab2a:	movl %eax, 0x4(%eax)
0x0040ab2d:	pushl %eax
0x0040ab2e:	ret

0x00410f50:	movl -24(%ebp), %esp
0x00410f53:	movl %esi, %esp
0x00410f55:	movl -36(%ebp), %esi
0x00410f58:	pushl %edi
0x00410f59:	pushl %ebx
0x00410f5a:	pushl %esi
0x00410f5b:	call 0x00410510
0x00410f60:	addl %esp, $0xc<UINT8>
0x00410f63:	jmp 0x00410f70
0x00410f70:	orl -4(%ebp), $0xffffffff<UINT8>
0x00410f74:	cmpl %esi, %ebx
0x00410f76:	je 41
0x00410f78:	pushl -32(%ebp)
0x00410f7b:	pushl %esi
0x00410f7c:	pushl 0x10(%ebp)
0x00410f7f:	pushl 0xc(%ebp)
0x00410f82:	pushl $0x1<UINT8>
0x00410f84:	pushl 0x18(%ebp)
0x00410f87:	call MultiByteToWideChar@KERNEL32.dll
0x00410f8d:	cmpl %eax, %ebx
0x00410f8f:	je 16
0x00410f91:	pushl 0x14(%ebp)
0x00410f94:	pushl %eax
0x00410f95:	pushl %esi
0x00410f96:	pushl 0x8(%ebp)
0x00410f99:	call GetStringTypeW@KERNEL32.dll
0x00410f9f:	jmp 0x00410fa3
0x00410fa3:	leal %esp, -52(%ebp)
0x00410fa6:	movl %ecx, -16(%ebp)
0x00410fa9:	movl %fs:0, %ecx
0x00410fb0:	popl %edi
0x00410fb1:	popl %esi
0x00410fb2:	popl %ebx
0x00410fb3:	leave
0x00410fb4:	ret

0x00411ab9:	pushl $0x0<UINT8>
0x00411abb:	leal %eax, -532(%ebp)
0x00411ac1:	pushl 0x43667c
0x00411ac7:	pushl %esi
0x00411ac8:	pushl %eax
0x00411ac9:	leal %eax, -276(%ebp)
0x00411acf:	pushl %esi
0x00411ad0:	pushl %eax
0x00411ad1:	pushl %esi
0x00411ad2:	pushl 0x4368a4
0x00411ad8:	call 0x00411c44
0x00411c44:	pushl %ebp
0x00411c45:	movl %ebp, %esp
0x00411c47:	pushl $0xffffffff<UINT8>
0x00411c49:	pushl $0x4149e0<UINT32>
0x00411c4e:	pushl $0x40ae34<UINT32>
0x00411c53:	movl %eax, %fs:0
0x00411c59:	pushl %eax
0x00411c5a:	movl %fs:0, %esp
0x00411c61:	subl %esp, $0x1c<UINT8>
0x00411c64:	pushl %ebx
0x00411c65:	pushl %esi
0x00411c66:	pushl %edi
0x00411c67:	movl -24(%ebp), %esp
0x00411c6a:	xorl %edi, %edi
0x00411c6c:	cmpl 0x433880, %edi
0x00411c72:	jne 0x00411cba
0x00411c74:	pushl %edi
0x00411c75:	pushl %edi
0x00411c76:	pushl $0x1<UINT8>
0x00411c78:	popl %ebx
0x00411c79:	pushl %ebx
0x00411c7a:	pushl $0x414970<UINT32>
0x00411c7f:	movl %esi, $0x100<UINT32>
0x00411c84:	pushl %esi
0x00411c85:	pushl %edi
0x00411c86:	call LCMapStringW@KERNEL32.dll
LCMapStringW@KERNEL32.dll: API Node	
0x00411c8c:	testl %eax, %eax
0x00411c8e:	je 8
0x00411c90:	movl 0x433880, %ebx
0x00411c96:	jmp 0x00411cba
0x00411cba:	cmpl 0x14(%ebp), %edi
0x00411cbd:	jle 16
0x00411cbf:	pushl 0x14(%ebp)
0x00411cc2:	pushl 0x10(%ebp)
0x00411cc5:	call 0x00411e68
0x00411e68:	movl %edx, 0x8(%esp)
0x00411e6c:	movl %eax, 0x4(%esp)
0x00411e70:	testl %edx, %edx
0x00411e72:	pushl %esi
0x00411e73:	leal %ecx, -1(%edx)
0x00411e76:	je 13
0x00411e78:	cmpb (%eax), $0x0<UINT8>
0x00411e7b:	je 8
0x00411e7d:	incl %eax
0x00411e7e:	movl %esi, %ecx
0x00411e80:	decl %ecx
0x00411e81:	testl %esi, %esi
0x00411e83:	jne 0x00411e78
0x00411e85:	cmpb (%eax), $0x0<UINT8>
0x00411e88:	popl %esi
0x00411e89:	jne 0x00411e90
0x00411e90:	movl %eax, %edx
0x00411e92:	ret

0x00411cca:	popl %ecx
0x00411ccb:	popl %ecx
0x00411ccc:	movl 0x14(%ebp), %eax
0x00411ccf:	movl %eax, 0x433880
0x00411cd4:	cmpl %eax, $0x2<UINT8>
0x00411cd7:	jne 0x00411cf6
0x00411cf6:	cmpl %eax, $0x1<UINT8>
0x00411cf9:	jne 211
0x00411cff:	cmpl 0x20(%ebp), %edi
0x00411d02:	jne 0x00411d0c
0x00411d0c:	pushl %edi
0x00411d0d:	pushl %edi
0x00411d0e:	pushl 0x14(%ebp)
0x00411d11:	pushl 0x10(%ebp)
0x00411d14:	movl %eax, 0x24(%ebp)
0x00411d17:	negl %eax
0x00411d19:	sbbl %eax, %eax
0x00411d1b:	andl %eax, $0x8<UINT8>
0x00411d1e:	incl %eax
0x00411d1f:	pushl %eax
0x00411d20:	pushl 0x20(%ebp)
0x00411d23:	call MultiByteToWideChar@KERNEL32.dll
0x00411d29:	movl %ebx, %eax
0x00411d2b:	movl -28(%ebp), %ebx
0x00411d2e:	cmpl %ebx, %edi
0x00411d30:	je 156
0x00411d36:	movl -4(%ebp), %edi
0x00411d39:	leal %eax, (%ebx,%ebx)
0x00411d3c:	addl %eax, $0x3<UINT8>
0x00411d3f:	andb %al, $0xfffffffc<UINT8>
0x00411d41:	call 0x0040ab00
0x00411d46:	movl -24(%ebp), %esp
0x00411d49:	movl %eax, %esp
0x00411d4b:	movl -36(%ebp), %eax
0x00411d4e:	orl -4(%ebp), $0xffffffff<UINT8>
0x00411d52:	jmp 0x00411d67
0x00411d67:	cmpl -36(%ebp), %edi
0x00411d6a:	je 102
0x00411d6c:	pushl %ebx
0x00411d6d:	pushl -36(%ebp)
0x00411d70:	pushl 0x14(%ebp)
0x00411d73:	pushl 0x10(%ebp)
0x00411d76:	pushl $0x1<UINT8>
0x00411d78:	pushl 0x20(%ebp)
0x00411d7b:	call MultiByteToWideChar@KERNEL32.dll
0x00411d81:	testl %eax, %eax
0x00411d83:	je 77
0x00411d85:	pushl %edi
0x00411d86:	pushl %edi
0x00411d87:	pushl %ebx
0x00411d88:	pushl -36(%ebp)
0x00411d8b:	pushl 0xc(%ebp)
0x00411d8e:	pushl 0x8(%ebp)
0x00411d91:	call LCMapStringW@KERNEL32.dll
0x00411d97:	movl %esi, %eax
0x00411d99:	movl -40(%ebp), %esi
0x00411d9c:	cmpl %esi, %edi
0x00411d9e:	je 50
0x00411da0:	testb 0xd(%ebp), $0x4<UINT8>
0x00411da4:	je 0x00411de6
0x00411de6:	movl -4(%ebp), $0x1<UINT32>
0x00411ded:	leal %eax, (%esi,%esi)
0x00411df0:	addl %eax, $0x3<UINT8>
0x00411df3:	andb %al, $0xfffffffc<UINT8>
0x00411df5:	call 0x0040ab00
0x00411dfa:	movl -24(%ebp), %esp
0x00411dfd:	movl %ebx, %esp
0x00411dff:	movl -32(%ebp), %ebx
0x00411e02:	orl -4(%ebp), $0xffffffff<UINT8>
0x00411e06:	jmp 0x00411e1a
0x00411e1a:	cmpl %ebx, %edi
0x00411e1c:	je -76
0x00411e1e:	pushl %esi
0x00411e1f:	pushl %ebx
0x00411e20:	pushl -28(%ebp)
0x00411e23:	pushl -36(%ebp)
0x00411e26:	pushl 0xc(%ebp)
0x00411e29:	pushl 0x8(%ebp)
0x00411e2c:	call LCMapStringW@KERNEL32.dll
0x00411e32:	testl %eax, %eax
0x00411e34:	je -100
0x00411e36:	cmpl 0x1c(%ebp), %edi
0x00411e39:	pushl %edi
0x00411e3a:	pushl %edi
0x00411e3b:	jne 0x00411e41
0x00411e41:	pushl 0x1c(%ebp)
0x00411e44:	pushl 0x18(%ebp)
0x00411e47:	pushl %esi
0x00411e48:	pushl %ebx
0x00411e49:	pushl $0x220<UINT32>
0x00411e4e:	pushl 0x20(%ebp)
0x00411e51:	call WideCharToMultiByte@KERNEL32.dll
0x00411e57:	movl %esi, %eax
0x00411e59:	cmpl %esi, %edi
0x00411e5b:	je -143
0x00411e61:	movl %eax, %esi
0x00411e63:	jmp 0x00411dd4
0x00411dd4:	leal %esp, -56(%ebp)
0x00411dd7:	movl %ecx, -16(%ebp)
0x00411dda:	movl %fs:0, %ecx
0x00411de1:	popl %edi
0x00411de2:	popl %esi
0x00411de3:	popl %ebx
0x00411de4:	leave
0x00411de5:	ret

0x00411add:	pushl $0x0<UINT8>
0x00411adf:	leal %eax, -788(%ebp)
0x00411ae5:	pushl 0x43667c
0x00411aeb:	pushl %esi
0x00411aec:	pushl %eax
0x00411aed:	leal %eax, -276(%ebp)
0x00411af3:	pushl %esi
0x00411af4:	pushl %eax
0x00411af5:	pushl $0x200<UINT32>
0x00411afa:	pushl 0x4368a4
0x00411b00:	call 0x00411c44
0x00411b05:	addl %esp, $0x5c<UINT8>
0x00411b08:	xorl %eax, %eax
0x00411b0a:	leal %ecx, -1300(%ebp)
0x00411b10:	movw %dx, (%ecx)
0x00411b13:	testb %dl, $0x1<UINT8>
0x00411b16:	je 0x00411b2e
0x00411b2e:	testb %dl, $0x2<UINT8>
0x00411b31:	je 0x00411b43
0x00411b43:	andb 0x4366a0(%eax), $0x0<UINT8>
0x00411b4a:	incl %eax
0x00411b4b:	incl %ecx
0x00411b4c:	incl %ecx
0x00411b4d:	cmpl %eax, %esi
0x00411b4f:	jb 0x00411b10
0x00411b18:	orb 0x4367a1(%eax), $0x10<UINT8>
0x00411b1f:	movb %dl, -532(%ebp,%eax)
0x00411b26:	movb 0x4366a0(%eax), %dl
0x00411b2c:	jmp 0x00411b4a
0x00411b33:	orb 0x4367a1(%eax), $0x20<UINT8>
0x00411b3a:	movb %dl, -788(%ebp,%eax)
0x00411b41:	jmp 0x00411b26
0x00411b51:	jmp 0x00411b9c
0x00411b9c:	popl %esi
0x00411b9d:	leave
0x00411b9e:	ret

0x0041195d:	jmp 0x004117ee
0x004117ee:	xorl %esi, %esi
0x004117f0:	jmp 0x00411965
0x00411965:	pushl $0x19<UINT8>
0x00411967:	call 0x0040bffc
0x0041196c:	popl %ecx
0x0041196d:	movl %eax, %esi
0x0041196f:	popl %edi
0x00411970:	popl %esi
0x00411971:	popl %ebx
0x00411972:	leave
0x00411973:	ret

0x00411baf:	popl %ecx
0x00411bb0:	movl 0x4368b4, $0x1<UINT32>
0x00411bba:	ret

0x0040eeef:	movl %esi, $0x4336e0<UINT32>
0x0040eef4:	pushl $0x104<UINT32>
0x0040eef9:	pushl %esi
0x0040eefa:	pushl %ebx
0x0040eefb:	call GetModuleFileNameA@KERNEL32.dll
GetModuleFileNameA@KERNEL32.dll: API Node	
0x0040ef01:	movl %eax, 0x4369e0
0x0040ef06:	movl 0x4336a0, %esi
0x0040ef0c:	movl %edi, %esi
0x0040ef0e:	cmpb (%eax), %bl
0x0040ef10:	je 2
0x0040ef12:	movl %edi, %eax
0x0040ef14:	leal %eax, -8(%ebp)
0x0040ef17:	pushl %eax
0x0040ef18:	leal %eax, -4(%ebp)
0x0040ef1b:	pushl %eax
0x0040ef1c:	pushl %ebx
0x0040ef1d:	pushl %ebx
0x0040ef1e:	pushl %edi
0x0040ef1f:	call 0x0040ef71
0x0040ef71:	pushl %ebp
0x0040ef72:	movl %ebp, %esp
0x0040ef74:	movl %ecx, 0x18(%ebp)
0x0040ef77:	movl %eax, 0x14(%ebp)
0x0040ef7a:	pushl %ebx
0x0040ef7b:	pushl %esi
0x0040ef7c:	andl (%ecx), $0x0<UINT8>
0x0040ef7f:	movl %esi, 0x10(%ebp)
0x0040ef82:	pushl %edi
0x0040ef83:	movl %edi, 0xc(%ebp)
0x0040ef86:	movl (%eax), $0x1<UINT32>
0x0040ef8c:	movl %eax, 0x8(%ebp)
0x0040ef8f:	testl %edi, %edi
0x0040ef91:	je 0x0040ef9b
0x0040ef9b:	cmpb (%eax), $0x22<UINT8>
0x0040ef9e:	jne 68
0x0040efa0:	movb %dl, 0x1(%eax)
0x0040efa3:	incl %eax
0x0040efa4:	cmpb %dl, $0x22<UINT8>
0x0040efa7:	je 0x0040efd2
0x0040efa9:	testb %dl, %dl
0x0040efab:	je 37
0x0040efad:	movzbl %edx, %dl
0x0040efb0:	testb 0x4367a1(%edx), $0x4<UINT8>
0x0040efb7:	je 0x0040efc5
0x0040efc5:	incl (%ecx)
0x0040efc7:	testl %esi, %esi
0x0040efc9:	je 0x0040efa0
0x0040efd2:	incl (%ecx)
0x0040efd4:	testl %esi, %esi
0x0040efd6:	je 0x0040efdc
0x0040efdc:	cmpb (%eax), $0x22<UINT8>
0x0040efdf:	jne 70
0x0040efe1:	incl %eax
0x0040efe2:	jmp 0x0040f027
0x0040f027:	andl 0x18(%ebp), $0x0<UINT8>
0x0040f02b:	cmpb (%eax), $0x0<UINT8>
0x0040f02e:	je 0x0040f114
0x0040f114:	testl %edi, %edi
0x0040f116:	je 0x0040f11b
0x0040f11b:	movl %eax, 0x14(%ebp)
0x0040f11e:	popl %edi
0x0040f11f:	popl %esi
0x0040f120:	popl %ebx
0x0040f121:	incl (%eax)
0x0040f123:	popl %ebp
0x0040f124:	ret

0x0040ef24:	movl %eax, -8(%ebp)
0x0040ef27:	movl %ecx, -4(%ebp)
0x0040ef2a:	leal %eax, (%eax,%ecx,4)
0x0040ef2d:	pushl %eax
0x0040ef2e:	call 0x0040a837
0x0040ef33:	movl %esi, %eax
0x0040ef35:	addl %esp, $0x18<UINT8>
0x0040ef38:	cmpl %esi, %ebx
0x0040ef3a:	jne 0x0040ef44
0x0040ef44:	leal %eax, -8(%ebp)
0x0040ef47:	pushl %eax
0x0040ef48:	leal %eax, -4(%ebp)
0x0040ef4b:	pushl %eax
0x0040ef4c:	movl %eax, -4(%ebp)
0x0040ef4f:	leal %eax, (%esi,%eax,4)
0x0040ef52:	pushl %eax
0x0040ef53:	pushl %esi
0x0040ef54:	pushl %edi
0x0040ef55:	call 0x0040ef71
0x0040ef93:	movl (%edi), %esi
0x0040ef95:	addl %edi, $0x4<UINT8>
0x0040ef98:	movl 0xc(%ebp), %edi
0x0040efcb:	movb %dl, (%eax)
0x0040efcd:	movb (%esi), %dl
0x0040efcf:	incl %esi
0x0040efd0:	jmp 0x0040efa0
0x0040efd8:	andb (%esi), $0x0<UINT8>
0x0040efdb:	incl %esi
0x0040f118:	andl (%edi), $0x0<UINT8>
0x0040ef5a:	movl %eax, -4(%ebp)
0x0040ef5d:	addl %esp, $0x14<UINT8>
0x0040ef60:	decl %eax
0x0040ef61:	movl 0x433688, %esi
0x0040ef67:	popl %edi
0x0040ef68:	popl %esi
0x0040ef69:	movl 0x433684, %eax
0x0040ef6e:	popl %ebx
0x0040ef6f:	leave
0x0040ef70:	ret

0x0040b558:	call 0x0040ee1f
0x0040ee1f:	pushl %ebx
0x0040ee20:	xorl %ebx, %ebx
0x0040ee22:	cmpl 0x4368b4, %ebx
0x0040ee28:	pushl %esi
0x0040ee29:	pushl %edi
0x0040ee2a:	jne 0x0040ee31
0x0040ee31:	movl %esi, 0x4335f0
0x0040ee37:	xorl %edi, %edi
0x0040ee39:	movb %al, (%esi)
0x0040ee3b:	cmpb %al, %bl
0x0040ee3d:	je 0x0040ee51
0x0040ee3f:	cmpb %al, $0x3d<UINT8>
0x0040ee41:	je 0x0040ee44
0x0040ee44:	pushl %esi
0x0040ee45:	call 0x0040d920
0x0040d920:	movl %ecx, 0x4(%esp)
0x0040d924:	testl %ecx, $0x3<UINT32>
0x0040d92a:	je 0x0040d940
0x0040d940:	movl %eax, (%ecx)
0x0040d942:	movl %edx, $0x7efefeff<UINT32>
0x0040d947:	addl %edx, %eax
0x0040d949:	xorl %eax, $0xffffffff<UINT8>
0x0040d94c:	xorl %eax, %edx
0x0040d94e:	addl %ecx, $0x4<UINT8>
0x0040d951:	testl %eax, $0x81010100<UINT32>
0x0040d956:	je 0x0040d940
0x0040d958:	movl %eax, -4(%ecx)
0x0040d95b:	testb %al, %al
0x0040d95d:	je 50
0x0040d95f:	testb %ah, %ah
0x0040d961:	je 36
0x0040d963:	testl %eax, $0xff0000<UINT32>
0x0040d968:	je 19
0x0040d96a:	testl %eax, $0xff000000<UINT32>
0x0040d96f:	je 0x0040d973
0x0040d973:	leal %eax, -1(%ecx)
0x0040d976:	movl %ecx, 0x4(%esp)
0x0040d97a:	subl %eax, %ecx
0x0040d97c:	ret

0x0040ee4a:	popl %ecx
0x0040ee4b:	leal %esi, 0x1(%esi,%eax)
0x0040ee4f:	jmp 0x0040ee39
0x0040ee51:	leal %eax, 0x4(,%edi,4)
0x0040ee58:	pushl %eax
0x0040ee59:	call 0x0040a837
0x0040ee5e:	movl %esi, %eax
0x0040ee60:	popl %ecx
0x0040ee61:	cmpl %esi, %ebx
0x0040ee63:	movl 0x433690, %esi
0x0040ee69:	jne 0x0040ee73
0x0040ee73:	movl %edi, 0x4335f0
0x0040ee79:	cmpb (%edi), %bl
0x0040ee7b:	je 57
0x0040ee7d:	pushl %ebp
0x0040ee7e:	pushl %edi
0x0040ee7f:	call 0x0040d920
0x0040ee84:	movl %ebp, %eax
0x0040ee86:	popl %ecx
0x0040ee87:	incl %ebp
0x0040ee88:	cmpb (%edi), $0x3d<UINT8>
0x0040ee8b:	je 0x0040eeaf
0x0040eeaf:	addl %edi, %ebp
0x0040eeb1:	cmpb (%edi), %bl
0x0040eeb3:	jne -55
0x0040eeb5:	popl %ebp
0x0040eeb6:	pushl 0x4335f0
0x0040eebc:	call 0x0040a8c3
0x0040a8c3:	pushl %esi
0x0040a8c4:	movl %esi, 0x8(%esp)
0x0040a8c8:	testl %esi, %esi
0x0040a8ca:	je 61
0x0040a8cc:	pushl $0x9<UINT8>
0x0040a8ce:	call 0x0040bf9b
0x0040a8d3:	pushl %esi
0x0040a8d4:	call 0x0040c04f
0x0040c04f:	movl %eax, 0x4369d4
0x0040c054:	leal %ecx, (%eax,%eax,4)
0x0040c057:	movl %eax, 0x4369d8
0x0040c05c:	leal %ecx, (%eax,%ecx,4)
0x0040c05f:	cmpl %eax, %ecx
0x0040c061:	jae 0x0040c077
0x0040c063:	movl %edx, 0x4(%esp)
0x0040c067:	subl %edx, 0xc(%eax)
0x0040c06a:	cmpl %edx, $0x100000<UINT32>
0x0040c070:	jb 7
0x0040c072:	addl %eax, $0x14<UINT8>
0x0040c075:	jmp 0x0040c05f
0x0040c077:	xorl %eax, %eax
0x0040c079:	ret

0x0040a8d9:	popl %ecx
0x0040a8da:	testl %eax, %eax
0x0040a8dc:	popl %ecx
0x0040a8dd:	je 0x0040a8f2
0x0040a8f2:	pushl $0x9<UINT8>
0x0040a8f4:	call 0x0040bffc
0x0040a8f9:	popl %ecx
0x0040a8fa:	pushl %esi
0x0040a8fb:	pushl $0x0<UINT8>
0x0040a8fd:	pushl 0x4369dc
0x0040a903:	call HeapFree@KERNEL32.dll
HeapFree@KERNEL32.dll: API Node	
0x0040a909:	popl %esi
0x0040a90a:	ret

0x0040eec1:	popl %ecx
0x0040eec2:	movl 0x4335f0, %ebx
0x0040eec8:	movl (%esi), %ebx
0x0040eeca:	popl %edi
0x0040eecb:	popl %esi
0x0040eecc:	movl 0x4368b0, $0x1<UINT32>
0x0040eed6:	popl %ebx
0x0040eed7:	ret

0x0040b55d:	call 0x0040e24e
0x0040e24e:	movl %eax, 0x431008
0x0040e253:	testl %eax, %eax
0x0040e255:	je 2
0x0040e257:	call 0x0040a90b
0x0040a90b:	call 0x0040a923
0x0040a923:	movl %eax, $0x40cc83<UINT32>
0x0040a928:	movl 0x43138c, $0x40c92d<UINT32>
0x0040a932:	movl 0x431388, %eax
0x0040a937:	movl 0x431390, $0x40c993<UINT32>
0x0040a941:	movl 0x431394, $0x40c8d3<UINT32>
0x0040a94b:	movl 0x431398, $0x40c97b<UINT32>
0x0040a955:	movl 0x43139c, %eax
0x0040a95a:	ret

0x0040a910:	call 0x0040c8aa
0x0040c8aa:	pushl $0x414664<UINT32>
0x0040c8af:	call GetModuleHandleA@KERNEL32.dll
GetModuleHandleA@KERNEL32.dll: API Node	
0x0040c8b5:	testl %eax, %eax
0x0040c8b7:	je 21
0x0040c8b9:	pushl $0x414648<UINT32>
0x0040c8be:	pushl %eax
0x0040c8bf:	call GetProcAddress@KERNEL32.dll
0x0040c8c5:	testl %eax, %eax
0x0040c8c7:	je 5
0x0040c8c9:	pushl $0x0<UINT8>
0x0040c8cb:	call IsProcessorFeaturePresent@KERNEL32
IsProcessorFeaturePresent@KERNEL32: API Node	
0x0040c8cd:	ret

0x0040a915:	movl 0x4335e8, %eax
0x0040a91a:	call 0x0040c85a
0x0040c85a:	pushl $0x30000<UINT32>
0x0040c85f:	pushl $0x10000<UINT32>
0x0040c864:	call 0x0040fc3a
0x0040fc3a:	movl %eax, 0x8(%esp)
0x0040fc3e:	andl %eax, $0xfff7ffff<UINT32>
0x0040fc43:	pushl %eax
0x0040fc44:	pushl 0x8(%esp)
0x0040fc48:	call 0x0040fc05
0x0040fc05:	pushl %ebp
0x0040fc06:	movl %ebp, %esp
0x0040fc08:	pushl %ecx
0x0040fc09:	pushl %esi
0x0040fc0a:	fwait
0x0040fc0b:	fnstcw -4(%ebp)
0x0040fc0e:	pushl -4(%ebp)
0x0040fc11:	call 0x0040fc50
0x0040fc50:	pushl %ebx
0x0040fc51:	movl %ebx, 0x8(%esp)
0x0040fc55:	xorl %eax, %eax
0x0040fc57:	pushl %ebp
0x0040fc58:	testb %bl, $0x1<UINT8>
0x0040fc5b:	pushl %edi
0x0040fc5c:	je 0x0040fc61
0x0040fc61:	testb %bl, $0x4<UINT8>
0x0040fc64:	je 0x0040fc68
0x0040fc68:	testb %bl, $0x8<UINT8>
0x0040fc6b:	je 0x0040fc6f
0x0040fc6f:	testb %bl, $0x10<UINT8>
0x0040fc72:	je 2
0x0040fc74:	orb %al, $0x2<UINT8>
0x0040fc76:	testb %bl, $0x20<UINT8>
0x0040fc79:	je 2
0x0040fc7b:	orb %al, $0x1<UINT8>
0x0040fc7d:	testb %bl, $0x2<UINT8>
0x0040fc80:	je 0x0040fc87
0x0040fc87:	movzwl %ecx, %bx
0x0040fc8a:	pushl %esi
0x0040fc8b:	movl %edx, %ecx
0x0040fc8d:	movl %esi, $0xc00<UINT32>
0x0040fc92:	movl %edi, $0x300<UINT32>
0x0040fc97:	andl %edx, %esi
0x0040fc99:	movl %ebp, $0x200<UINT32>
0x0040fc9e:	je 31
0x0040fca0:	cmpl %edx, $0x400<UINT32>
0x0040fca6:	je 20
0x0040fca8:	cmpl %edx, $0x800<UINT32>
0x0040fcae:	je 8
0x0040fcb0:	cmpl %edx, %esi
0x0040fcb2:	jne 11
0x0040fcb4:	orl %eax, %edi
0x0040fcb6:	jmp 0x0040fcbf
0x0040fcbf:	andl %ecx, %edi
0x0040fcc1:	popl %esi
0x0040fcc2:	je 11
0x0040fcc4:	cmpl %ecx, %ebp
0x0040fcc6:	jne 0x0040fcd4
0x0040fcd4:	popl %edi
0x0040fcd5:	popl %ebp
0x0040fcd6:	testb %bh, $0x10<UINT8>
0x0040fcd9:	popl %ebx
0x0040fcda:	je 0x0040fce1
0x0040fce1:	ret

0x0040fc16:	movl %esi, %eax
0x0040fc18:	movl %eax, 0xc(%ebp)
0x0040fc1b:	notl %eax
0x0040fc1d:	andl %esi, %eax
0x0040fc1f:	movl %eax, 0x8(%ebp)
0x0040fc22:	andl %eax, 0xc(%ebp)
0x0040fc25:	orl %esi, %eax
0x0040fc27:	pushl %esi
0x0040fc28:	call 0x0040fce2
0x0040fce2:	pushl %ebx
0x0040fce3:	movl %ebx, 0x8(%esp)
0x0040fce7:	xorl %eax, %eax
0x0040fce9:	pushl %esi
0x0040fcea:	testb %bl, $0x10<UINT8>
0x0040fced:	je 0x0040fcf2
0x0040fcf2:	testb %bl, $0x8<UINT8>
0x0040fcf5:	je 0x0040fcf9
0x0040fcf9:	testb %bl, $0x4<UINT8>
0x0040fcfc:	je 0x0040fd00
0x0040fd00:	testb %bl, $0x2<UINT8>
0x0040fd03:	je 2
0x0040fd05:	orb %al, $0x10<UINT8>
0x0040fd07:	testb %bl, $0x1<UINT8>
0x0040fd0a:	je 2
0x0040fd0c:	orb %al, $0x20<UINT8>
0x0040fd0e:	testl %ebx, $0x80000<UINT32>
0x0040fd14:	je 0x0040fd18
0x0040fd18:	movl %ecx, %ebx
0x0040fd1a:	movl %edx, $0x300<UINT32>
0x0040fd1f:	andl %ecx, %edx
0x0040fd21:	movl %esi, $0x200<UINT32>
0x0040fd26:	je 29
0x0040fd28:	cmpl %ecx, $0x100<UINT32>
0x0040fd2e:	je 18
0x0040fd30:	cmpl %ecx, %esi
0x0040fd32:	je 9
0x0040fd34:	cmpl %ecx, %edx
0x0040fd36:	jne 13
0x0040fd38:	orb %ah, $0xc<UINT8>
0x0040fd3b:	jmp 0x0040fd45
0x0040fd45:	movl %ecx, %ebx
0x0040fd47:	andl %ecx, $0x30000<UINT32>
0x0040fd4d:	je 12
0x0040fd4f:	cmpl %ecx, $0x10000<UINT32>
0x0040fd55:	jne 6
0x0040fd57:	orl %eax, %esi
0x0040fd59:	jmp 0x0040fd5d
0x0040fd5d:	popl %esi
0x0040fd5e:	testl %ebx, $0x40000<UINT32>
0x0040fd64:	popl %ebx
0x0040fd65:	je 0x0040fd6a
0x0040fd6a:	ret

0x0040fc2d:	popl %ecx
0x0040fc2e:	movl 0xc(%ebp), %eax
0x0040fc31:	popl %ecx
0x0040fc32:	fldcw 0xc(%ebp)
0x0040fc35:	movl %eax, %esi
0x0040fc37:	popl %esi
0x0040fc38:	leave
0x0040fc39:	ret

0x0040fc4d:	popl %ecx
0x0040fc4e:	popl %ecx
0x0040fc4f:	ret

0x0040c869:	popl %ecx
0x0040c86a:	popl %ecx
0x0040c86b:	ret

0x0040a91f:	fnclex
0x0040a921:	ret

0x0040e259:	pushl $0x416014<UINT32>
0x0040e25e:	pushl $0x416008<UINT32>
0x0040e263:	call 0x0040e354
0x0040e354:	pushl %esi
0x0040e355:	movl %esi, 0x8(%esp)
0x0040e359:	cmpl %esi, 0xc(%esp)
0x0040e35d:	jae 0x0040e36c
0x0040e35f:	movl %eax, (%esi)
0x0040e361:	testl %eax, %eax
0x0040e363:	je 0x0040e367
0x0040e367:	addl %esi, $0x4<UINT8>
0x0040e36a:	jmp 0x0040e359
0x0040e365:	call 0x00411b9f
0x0040af0c:	movl %eax, 0x437a00
0x0040af11:	pushl %esi
0x0040af12:	pushl $0x14<UINT8>
0x0040af14:	testl %eax, %eax
0x0040af16:	popl %esi
0x0040af17:	jne 7
0x0040af19:	movl %eax, $0x200<UINT32>
0x0040af1e:	jmp 0x0040af26
0x0040af26:	movl 0x437a00, %eax
0x0040af2b:	pushl $0x4<UINT8>
0x0040af2d:	pushl %eax
0x0040af2e:	call 0x0040e140
0x0040e18c:	pushl %esi
0x0040e18d:	pushl $0x8<UINT8>
0x0040e18f:	pushl 0x4369dc
0x0040e195:	call HeapAlloc@KERNEL32.dll
0x0040e19b:	movl %edi, %eax
0x0040e19d:	testl %edi, %edi
0x0040e19f:	jne 0x0040e1c3
0x0040af33:	popl %ecx
0x0040af34:	movl 0x4369e4, %eax
0x0040af39:	testl %eax, %eax
0x0040af3b:	popl %ecx
0x0040af3c:	jne 0x0040af5f
0x0040af5f:	xorl %ecx, %ecx
0x0040af61:	movl %eax, $0x431030<UINT32>
0x0040af66:	movl %edx, 0x4369e4
0x0040af6c:	movl (%ecx,%edx), %eax
0x0040af6f:	addl %eax, $0x20<UINT8>
0x0040af72:	addl %ecx, $0x4<UINT8>
0x0040af75:	cmpl %eax, $0x4312b0<UINT32>
0x0040af7a:	jl 0x0040af66
0x0040af7c:	xorl %ecx, %ecx
0x0040af7e:	movl %edx, $0x431040<UINT32>
0x0040af83:	movl %esi, %ecx
0x0040af85:	movl %eax, %ecx
0x0040af87:	sarl %esi, $0x5<UINT8>
0x0040af8a:	andl %eax, $0x1f<UINT8>
0x0040af8d:	movl %esi, 0x4368c0(,%esi,4)
0x0040af94:	leal %eax, (%eax,%eax,8)
0x0040af97:	movl %eax, (%esi,%eax,4)
0x0040af9a:	cmpl %eax, $0xffffffff<UINT8>
0x0040af9d:	je 4
0x0040af9f:	testl %eax, %eax
0x0040afa1:	jne 0x0040afa6
0x0040afa6:	addl %edx, $0x20<UINT8>
0x0040afa9:	incl %ecx
0x0040afaa:	cmpl %edx, $0x4310a0<UINT32>
0x0040afb0:	jl 0x0040af83
0x0040afb2:	popl %esi
0x0040afb3:	ret

0x0040e36c:	popl %esi
0x0040e36d:	ret

0x0040e268:	pushl $0x416004<UINT32>
0x0040e26d:	pushl $0x416000<UINT32>
0x0040e272:	call 0x0040e354
0x0040e277:	addl %esp, $0x10<UINT8>
0x0040e27a:	ret

0x0040b562:	movl -48(%ebp), %esi
0x0040b565:	leal %eax, -92(%ebp)
0x0040b568:	pushl %eax
0x0040b569:	call GetStartupInfoA@KERNEL32.dll
0x0040b56f:	call 0x0040edc7
0x0040edc7:	cmpl 0x4368b4, $0x0<UINT8>
0x0040edce:	jne 0x0040edd5
0x0040edd5:	pushl %esi
0x0040edd6:	movl %esi, 0x4369e0
0x0040eddc:	movb %al, (%esi)
0x0040edde:	cmpb %al, $0x22<UINT8>
0x0040ede0:	jne 37
0x0040ede2:	movb %al, 0x1(%esi)
0x0040ede5:	incl %esi
0x0040ede6:	cmpb %al, $0x22<UINT8>
0x0040ede8:	je 0x0040edff
0x0040edea:	testb %al, %al
0x0040edec:	je 17
0x0040edee:	movzbl %eax, %al
0x0040edf1:	pushl %eax
0x0040edf2:	call 0x00411785
0x00411785:	pushl $0x4<UINT8>
0x00411787:	pushl $0x0<UINT8>
0x00411789:	pushl 0xc(%esp)
0x0041178d:	call 0x00411796
0x00411796:	movzbl %eax, 0x4(%esp)
0x0041179b:	movb %cl, 0xc(%esp)
0x0041179f:	testb 0x4367a1(%eax), %cl
0x004117a5:	jne 28
0x004117a7:	cmpl 0x8(%esp), $0x0<UINT8>
0x004117ac:	je 0x004117bc
0x004117bc:	xorl %eax, %eax
0x004117be:	testl %eax, %eax
0x004117c0:	jne 1
0x004117c2:	ret

0x00411792:	addl %esp, $0xc<UINT8>
0x00411795:	ret

0x0040edf7:	testl %eax, %eax
0x0040edf9:	popl %ecx
0x0040edfa:	je 0x0040ede2
0x0040edff:	cmpb (%esi), $0x22<UINT8>
0x0040ee02:	jne 13
0x0040ee04:	incl %esi
0x0040ee05:	jmp 0x0040ee11
0x0040ee11:	movb %al, (%esi)
0x0040ee13:	testb %al, %al
0x0040ee15:	je 0x0040ee1b
0x0040ee1b:	movl %eax, %esi
0x0040ee1d:	popl %esi
0x0040ee1e:	ret

0x0040b574:	movl -100(%ebp), %eax
0x0040b577:	testb -48(%ebp), $0x1<UINT8>
0x0040b57b:	je 0x0040b583
0x0040b583:	pushl $0xa<UINT8>
0x0040b585:	popl %eax
0x0040b586:	pushl %eax
0x0040b587:	pushl -100(%ebp)
0x0040b58a:	pushl %esi
0x0040b58b:	pushl %esi
0x0040b58c:	call GetModuleHandleA@KERNEL32.dll
0x0040b592:	pushl %eax
0x0040b593:	call 0x00402ef0
0x00402ef0:	subl %esp, $0x120<UINT32>
0x00402ef6:	pushl %esi
0x00402ef7:	pushl %edi
0x00402ef8:	pushl $0x416244<UINT32>
0x00402efd:	call 0x0040a060
0x0040a060:	subl %esp, $0x110<UINT32>
0x0040a066:	movl %eax, 0x114(%esp)
0x0040a06d:	pushl %ebx
0x0040a06e:	pushl %eax
0x0040a06f:	leal %ecx, 0x14(%esp)
0x0040a073:	xorl %ebx, %ebx
0x0040a075:	pushl $0x430fb0<UINT32>
0x0040a07a:	pushl %ecx
0x0040a07b:	movl 0x14(%esp), %ebx
0x0040a07f:	movl 0x10(%esp), %ebx
0x0040a083:	call 0x0040a6e2
0x0040a6e2:	pushl %ebp
0x0040a6e3:	movl %ebp, %esp
0x0040a6e5:	subl %esp, $0x20<UINT8>
0x0040a6e8:	movl %eax, 0x8(%ebp)
0x0040a6eb:	pushl %esi
0x0040a6ec:	movl -24(%ebp), %eax
0x0040a6ef:	movl -32(%ebp), %eax
0x0040a6f2:	leal %eax, 0x10(%ebp)
0x0040a6f5:	movl -20(%ebp), $0x42<UINT32>
0x0040a6fc:	pushl %eax
0x0040a6fd:	leal %eax, -32(%ebp)
0x0040a700:	pushl 0xc(%ebp)
0x0040a703:	movl -28(%ebp), $0x7fffffff<UINT32>
0x0040a70a:	pushl %eax
0x0040a70b:	call 0x0040b721
0x0040b721:	pushl %ebp
0x0040b722:	movl %ebp, %esp
0x0040b724:	subl %esp, $0x248<UINT32>
0x0040b72a:	pushl %ebx
0x0040b72b:	pushl %esi
0x0040b72c:	pushl %edi
0x0040b72d:	movl %edi, 0xc(%ebp)
0x0040b730:	xorl %esi, %esi
0x0040b732:	movb %bl, (%edi)
0x0040b734:	incl %edi
0x0040b735:	testb %bl, %bl
0x0040b737:	movl -12(%ebp), %esi
0x0040b73a:	movl -20(%ebp), %esi
0x0040b73d:	movl 0xc(%ebp), %edi
0x0040b740:	je 1780
0x0040b746:	movl %ecx, -16(%ebp)
0x0040b749:	xorl %edx, %edx
0x0040b74b:	jmp 0x0040b755
0x0040b755:	cmpl -20(%ebp), %edx
0x0040b758:	jl 1756
0x0040b75e:	cmpb %bl, $0x20<UINT8>
0x0040b761:	jl 19
0x0040b763:	cmpb %bl, $0x78<UINT8>
0x0040b766:	jg 0x0040b776
0x0040b768:	movsbl %eax, %bl
0x0040b76b:	movb %al, 0x41459c(%eax)
0x0040b771:	andl %eax, $0xf<UINT8>
0x0040b774:	jmp 0x0040b778
0x0040b778:	movsbl %eax, 0x4145bc(%esi,%eax,8)
0x0040b780:	sarl %eax, $0x4<UINT8>
0x0040b783:	cmpl %eax, $0x7<UINT8>
0x0040b786:	movl -48(%ebp), %eax
0x0040b789:	ja 1690
0x0040b78f:	jmp 0x0040b904
0x0040b8c0:	movl %ecx, 0x4313b0
0x0040b8c6:	movl -36(%ebp), %edx
0x0040b8c9:	movzbl %eax, %bl
0x0040b8cc:	testb 0x1(%ecx,%eax,2), $0xffffff80<UINT8>
0x0040b8d1:	je 0x0040b8ec
0x0040b8ec:	leal %eax, -20(%ebp)
0x0040b8ef:	pushl %eax
0x0040b8f0:	pushl 0x8(%ebp)
0x0040b8f3:	movsbl %eax, %bl
0x0040b8f6:	pushl %eax
0x0040b8f7:	call 0x0040be62
0x0040be62:	pushl %ebp
0x0040be63:	movl %ebp, %esp
0x0040be65:	movl %ecx, 0xc(%ebp)
0x0040be68:	decl 0x4(%ecx)
0x0040be6b:	js 14
0x0040be6d:	movl %edx, (%ecx)
0x0040be6f:	movb %al, 0x8(%ebp)
0x0040be72:	movb (%edx), %al
0x0040be74:	incl (%ecx)
0x0040be76:	movzbl %eax, %al
0x0040be79:	jmp 0x0040be86
0x0040be86:	cmpl %eax, $0xffffffff<UINT8>
0x0040be89:	movl %eax, 0x10(%ebp)
0x0040be8c:	jne 0x0040be93
0x0040be93:	incl (%eax)
0x0040be95:	popl %ebp
0x0040be96:	ret

0x0040b8fc:	addl %esp, $0xc<UINT8>
0x0040b8ff:	jmp 0x0040be29
0x0040be29:	movl %edi, 0xc(%ebp)
0x0040be2c:	movb %bl, (%edi)
0x0040be2e:	incl %edi
0x0040be2f:	testb %bl, %bl
0x0040be31:	movl 0xc(%ebp), %edi
0x0040be34:	jne 0x0040b74d
0x0040b74d:	movl %ecx, -16(%ebp)
0x0040b750:	movl %esi, -48(%ebp)
0x0040b753:	xorl %edx, %edx
0x0040b776:	xorl %eax, %eax
0x0040b796:	orl -16(%ebp), $0xffffffff<UINT8>
0x0040b79a:	movl -52(%ebp), %edx
0x0040b79d:	movl -40(%ebp), %edx
0x0040b7a0:	movl -32(%ebp), %edx
0x0040b7a3:	movl -28(%ebp), %edx
0x0040b7a6:	movl -4(%ebp), %edx
0x0040b7a9:	movl -36(%ebp), %edx
0x0040b7ac:	jmp 0x0040be29
0x0040b904:	movsbl %eax, %bl
0x0040b907:	cmpl %eax, $0x67<UINT8>
0x0040b90a:	jg 0x0040bb2c
0x0040bb2c:	subl %eax, $0x69<UINT8>
0x0040bb2f:	je 209
0x0040bb35:	subl %eax, $0x5<UINT8>
0x0040bb38:	je 158
0x0040bb3e:	decl %eax
0x0040bb3f:	je 132
0x0040bb45:	decl %eax
0x0040bb46:	je 81
0x0040bb48:	subl %eax, $0x3<UINT8>
0x0040bb4b:	je 0x0040b94e
0x0040b94e:	movl %esi, -16(%ebp)
0x0040b951:	cmpl %esi, $0xffffffff<UINT8>
0x0040b954:	jne 5
0x0040b956:	movl %esi, $0x7fffffff<UINT32>
0x0040b95b:	leal %eax, 0x10(%ebp)
0x0040b95e:	pushl %eax
0x0040b95f:	call 0x0040bf00
0x0040bf00:	movl %eax, 0x4(%esp)
0x0040bf04:	addl (%eax), $0x4<UINT8>
0x0040bf07:	movl %eax, (%eax)
0x0040bf09:	movl %eax, -4(%eax)
0x0040bf0c:	ret

0x0040b964:	testw -4(%ebp), $0x810<UINT16>
0x0040b96a:	popl %ecx
0x0040b96b:	movl %ecx, %eax
0x0040b96d:	movl -8(%ebp), %ecx
0x0040b970:	je 0x0040bb74
0x0040bb74:	testl %ecx, %ecx
0x0040bb76:	jne 0x0040bb81
0x0040bb81:	movl %eax, %ecx
0x0040bb83:	movl %edx, %esi
0x0040bb85:	decl %esi
0x0040bb86:	testl %edx, %edx
0x0040bb88:	je 8
0x0040bb8a:	cmpb (%eax), $0x0<UINT8>
0x0040bb8d:	je 0x0040bb92
0x0040bb8f:	incl %eax
0x0040bb90:	jmp 0x0040bb83
0x0040bb92:	subl %eax, %ecx
0x0040bb94:	jmp 0x0040bd28
0x0040bd28:	movl -12(%ebp), %eax
0x0040bd2b:	cmpl -40(%ebp), $0x0<UINT8>
0x0040bd2f:	jne 244
0x0040bd35:	movl %ebx, -4(%ebp)
0x0040bd38:	testb %bl, $0x40<UINT8>
0x0040bd3b:	je 0x0040bd63
0x0040bd63:	movl %esi, -32(%ebp)
0x0040bd66:	subl %esi, -28(%ebp)
0x0040bd69:	subl %esi, -12(%ebp)
0x0040bd6c:	testb %bl, $0xc<UINT8>
0x0040bd6f:	jne 18
0x0040bd71:	leal %eax, -20(%ebp)
0x0040bd74:	pushl %eax
0x0040bd75:	pushl 0x8(%ebp)
0x0040bd78:	pushl %esi
0x0040bd79:	pushl $0x20<UINT8>
0x0040bd7b:	call 0x0040be97
0x0040be97:	pushl %esi
0x0040be98:	pushl %edi
0x0040be99:	movl %edi, 0x10(%esp)
0x0040be9d:	movl %eax, %edi
0x0040be9f:	decl %edi
0x0040bea0:	testl %eax, %eax
0x0040bea2:	jle 0x0040bec5
0x0040bec5:	popl %edi
0x0040bec6:	popl %esi
0x0040bec7:	ret

0x0040bd80:	addl %esp, $0x10<UINT8>
0x0040bd83:	leal %eax, -20(%ebp)
0x0040bd86:	pushl %eax
0x0040bd87:	leal %eax, -22(%ebp)
0x0040bd8a:	pushl 0x8(%ebp)
0x0040bd8d:	pushl -28(%ebp)
0x0040bd90:	pushl %eax
0x0040bd91:	call 0x0040bec8
0x0040bec8:	pushl %ebx
0x0040bec9:	movl %ebx, 0xc(%esp)
0x0040becd:	movl %eax, %ebx
0x0040becf:	decl %ebx
0x0040bed0:	pushl %esi
0x0040bed1:	pushl %edi
0x0040bed2:	testl %eax, %eax
0x0040bed4:	jle 0x0040befc
0x0040befc:	popl %edi
0x0040befd:	popl %esi
0x0040befe:	popl %ebx
0x0040beff:	ret

0x0040bd96:	addl %esp, $0x10<UINT8>
0x0040bd99:	testb %bl, $0x8<UINT8>
0x0040bd9c:	je 0x0040bdb5
0x0040bdb5:	cmpl -36(%ebp), $0x0<UINT8>
0x0040bdb9:	je 0x0040bdfc
0x0040bdfc:	leal %eax, -20(%ebp)
0x0040bdff:	pushl %eax
0x0040be00:	pushl 0x8(%ebp)
0x0040be03:	pushl -12(%ebp)
0x0040be06:	pushl -8(%ebp)
0x0040be09:	call 0x0040bec8
0x0040bed6:	movl %edi, 0x1c(%esp)
0x0040beda:	movl %esi, 0x10(%esp)
0x0040bede:	movsbl %eax, (%esi)
0x0040bee1:	pushl %edi
0x0040bee2:	incl %esi
0x0040bee3:	pushl 0x1c(%esp)
0x0040bee7:	pushl %eax
0x0040bee8:	call 0x0040be62
0x0040beed:	addl %esp, $0xc<UINT8>
0x0040bef0:	cmpl (%edi), $0xffffffff<UINT8>
0x0040bef3:	je 7
0x0040bef5:	movl %eax, %ebx
0x0040bef7:	decl %ebx
0x0040bef8:	testl %eax, %eax
0x0040befa:	jg 0x0040bede
0x0040be0e:	addl %esp, $0x10<UINT8>
0x0040be11:	testb -4(%ebp), $0x4<UINT8>
0x0040be15:	je 0x0040be29
0x0040be3a:	movl %eax, -20(%ebp)
0x0040be3d:	popl %edi
0x0040be3e:	popl %esi
0x0040be3f:	popl %ebx
0x0040be40:	leave
0x0040be41:	ret

0x0040a710:	addl %esp, $0xc<UINT8>
0x0040a713:	decl -28(%ebp)
0x0040a716:	movl %esi, %eax
0x0040a718:	js 8
0x0040a71a:	movl %eax, -32(%ebp)
0x0040a71d:	andb (%eax), $0x0<UINT8>
0x0040a720:	jmp 0x0040a72f
0x0040a72f:	movl %eax, %esi
0x0040a731:	popl %esi
0x0040a732:	leave
0x0040a733:	ret

0x0040a088:	addl %esp, $0xc<UINT8>
0x0040a08b:	leal %edx, 0x8(%esp)
0x0040a08f:	leal %eax, 0x10(%esp)
0x0040a093:	pushl %edx
0x0040a094:	pushl %eax
0x0040a095:	pushl $0x80000001<UINT32>
0x0040a09a:	call RegCreateKeyA@ADVAPI32.dll
RegCreateKeyA@ADVAPI32.dll: API Node	
0x0040a0a0:	testl %eax, %eax
0x0040a0a2:	jne 36
0x0040a0a4:	movl %eax, 0x8(%esp)
0x0040a0a8:	leal %ecx, 0xc(%esp)
0x0040a0ac:	leal %edx, 0x4(%esp)
0x0040a0b0:	pushl %ecx
0x0040a0b1:	pushl %edx
0x0040a0b2:	pushl %ebx
0x0040a0b3:	pushl %ebx
0x0040a0b4:	pushl $0x430fa0<UINT32>
0x0040a0b9:	pushl %eax
0x0040a0ba:	movl 0x24(%esp), $0x4<UINT32>
0x0040a0c2:	call RegQueryValueExA@ADVAPI32.dll
RegQueryValueExA@ADVAPI32.dll: API Node	
0x0040a0c8:	cmpl 0x4(%esp), %ebx
0x0040a0cc:	jne 511
0x0040a0d2:	pushl %esi
0x0040a0d3:	pushl %edi
0x0040a0d4:	pushl $0x3e8<UINT32>
0x0040a0d9:	pushl $0x40<UINT8>
0x0040a0db:	call LocalAlloc@KERNEL32.dll
LocalAlloc@KERNEL32.dll: API Node	
0x0040a0e1:	movl %esi, %eax
0x0040a0e3:	pushl $0x430f90<UINT32>
0x0040a0e8:	leal %edi, 0x12(%esi)
0x0040a0eb:	call LoadLibraryA@KERNEL32.dll
0x0040a0f1:	movl (%esi), $0x80c808d0<UINT32>
0x0040ae34:	pushl %ebp
0x0040ae35:	movl %ebp, %esp
0x0040ae37:	subl %esp, $0x8<UINT8>
0x0040ae3a:	pushl %ebx
0x0040ae3b:	pushl %esi
0x0040ae3c:	pushl %edi
0x0040ae3d:	pushl %ebp
0x0040ae3e:	cld
0x0040ae3f:	movl %ebx, 0xc(%ebp)
0x0040ae42:	movl %eax, 0x8(%ebp)
0x0040ae45:	testl 0x4(%eax), $0x6<UINT32>
0x0040ae4c:	jne 130
0x0040ae52:	movl -8(%ebp), %eax
0x0040ae55:	movl %eax, 0x10(%ebp)
0x0040ae58:	movl -4(%ebp), %eax
0x0040ae5b:	leal %eax, -8(%ebp)
0x0040ae5e:	movl -4(%ebx), %eax
0x0040ae61:	movl %esi, 0xc(%ebx)
0x0040ae64:	movl %edi, 0x8(%ebx)
0x0040ae67:	cmpl %esi, $0xffffffff<UINT8>
0x0040ae6a:	je 97
0x0040ae6c:	leal %ecx, (%esi,%esi,2)
0x0040ae6f:	cmpl 0x4(%edi,%ecx,4), $0x0<UINT8>
0x0040ae74:	je 69
0x0040ae76:	pushl %esi
0x0040ae77:	pushl %ebp
0x0040ae78:	leal %ebp, 0x10(%ebx)
0x0040ae7b:	call 0x0040b5a1
0x0040b5a1:	movl %eax, -20(%ebp)
0x0040b5a4:	movl %ecx, (%eax)
0x0040b5a6:	movl %ecx, (%ecx)
0x0040b5a8:	movl -104(%ebp), %ecx
0x0040b5ab:	pushl %eax
0x0040b5ac:	pushl %ecx
0x0040b5ad:	call 0x0040ebda
0x0040ebda:	pushl %ebp
0x0040ebdb:	movl %ebp, %esp
0x0040ebdd:	pushl %ecx
0x0040ebde:	pushl %ebx
0x0040ebdf:	pushl %esi
0x0040ebe0:	call 0x0040cd60
0x0040cd60:	pushl %esi
0x0040cd61:	pushl %edi
0x0040cd62:	call GetLastError@KERNEL32.dll
GetLastError@KERNEL32.dll: API Node	
0x0040cd68:	pushl 0x4313a0
0x0040cd6e:	movl %edi, %eax
0x0040cd70:	call TlsGetValue@KERNEL32.dll
TlsGetValue@KERNEL32.dll: API Node	
0x0040cd76:	movl %esi, %eax
0x0040cd78:	testl %esi, %esi
0x0040cd7a:	jne 0x0040cdbb
0x0040cdbb:	pushl %edi
0x0040cdbc:	call SetLastError@KERNEL32.dll
SetLastError@KERNEL32.dll: API Node	
0x0040cdc2:	movl %eax, %esi
0x0040cdc4:	popl %edi
0x0040cdc5:	popl %esi
0x0040cdc6:	ret

0x0040ebe5:	movl %esi, %eax
0x0040ebe7:	pushl 0x50(%esi)
0x0040ebea:	pushl 0x8(%ebp)
0x0040ebed:	call 0x0040ed18
0x0040ed18:	movl %edx, 0x8(%esp)
0x0040ed1c:	movl %ecx, 0x4317e4
0x0040ed22:	pushl %esi
0x0040ed23:	movl %esi, 0x8(%esp)
0x0040ed27:	cmpl (%edx), %esi
0x0040ed29:	pushl %edi
0x0040ed2a:	movl %eax, %edx
0x0040ed2c:	je 0x0040ed3f
0x0040ed3f:	leal %ecx, (%ecx,%ecx,2)
0x0040ed42:	leal %ecx, (%edx,%ecx,4)
0x0040ed45:	cmpl %eax, %ecx
0x0040ed47:	jae 4
0x0040ed49:	cmpl (%eax), %esi
0x0040ed4b:	je 0x0040ed4f
0x0040ed4f:	popl %edi
0x0040ed50:	popl %esi
0x0040ed51:	ret

0x0040ebf2:	popl %ecx
0x0040ebf3:	testl %eax, %eax
0x0040ebf5:	popl %ecx
0x0040ebf6:	je 271
0x0040ebfc:	movl %ebx, 0x8(%eax)
0x0040ebff:	testl %ebx, %ebx
0x0040ec01:	movl 0x8(%ebp), %ebx
0x0040ec04:	je 0x0040ed0b
0x0040ed0b:	pushl 0xc(%ebp)
0x0040ed0e:	call UnhandledExceptionFilter@KERNEL32.dll
UnhandledExceptionFilter@KERNEL32.dll: API Node	
0x0040ed14:	popl %esi
0x0040ed15:	popl %ebx
0x0040ed16:	leave
0x0040ed17:	ret

0x0040b5b2:	popl %ecx
0x0040b5b3:	popl %ecx
0x0040b5b4:	ret

0x0040ae7f:	popl %ebp
0x0040ae80:	popl %esi
0x0040ae81:	movl %ebx, 0xc(%ebp)
0x0040ae84:	orl %eax, %eax
0x0040ae86:	je 51
0x0040ae88:	js 60
0x0040ae8a:	movl %edi, 0x8(%ebx)
0x0040ae8d:	pushl %ebx
0x0040ae8e:	call 0x0040ad3c
0x0040ad3c:	pushl %ebp
0x0040ad3d:	movl %ebp, %esp
0x0040ad3f:	pushl %ebx
0x0040ad40:	pushl %esi
0x0040ad41:	pushl %edi
0x0040ad42:	pushl %ebp
0x0040ad43:	pushl $0x0<UINT8>
0x0040ad45:	pushl $0x0<UINT8>
0x0040ad47:	pushl $0x40ad54<UINT32>
0x0040ad4c:	pushl 0x8(%ebp)
0x0040ad4f:	call 0x004132c0
0x004132c0:	jmp RtlUnwind@KERNEL32.dll
RtlUnwind@KERNEL32.dll: API Node	
0x0040ad54:	popl %ebp
0x0040ad55:	popl %edi
0x0040ad56:	popl %esi
0x0040ad57:	popl %ebx
0x0040ad58:	movl %esp, %ebp
0x0040ad5a:	popl %ebp
0x0040ad5b:	ret

0x0040ae93:	addl %esp, $0x4<UINT8>
0x0040ae96:	leal %ebp, 0x10(%ebx)
0x0040ae99:	pushl %esi
0x0040ae9a:	pushl %ebx
0x0040ae9b:	call 0x0040ad7e
0x0040ad7e:	pushl %ebx
0x0040ad7f:	pushl %esi
0x0040ad80:	pushl %edi
0x0040ad81:	movl %eax, 0x10(%esp)
0x0040ad85:	pushl %eax
0x0040ad86:	pushl $0xfffffffe<UINT8>
0x0040ad88:	pushl $0x40ad5c<UINT32>
0x0040ad8d:	pushl %fs:0
0x0040ad94:	movl %fs:0, %esp
0x0040ad9b:	movl %eax, 0x20(%esp)
0x0040ad9f:	movl %ebx, 0x8(%eax)
0x0040ada2:	movl %esi, 0xc(%eax)
0x0040ada5:	cmpl %esi, $0xffffffff<UINT8>
0x0040ada8:	je 46
0x0040adaa:	cmpl %esi, 0x24(%esp)
0x0040adae:	je 0x0040add8
0x0040add8:	popl %fs:0
0x0040addf:	addl %esp, $0xc<UINT8>
0x0040ade2:	popl %edi
0x0040ade3:	popl %esi
0x0040ade4:	popl %ebx
0x0040ade5:	ret

0x0040aea0:	addl %esp, $0x8<UINT8>
0x0040aea3:	leal %ecx, (%esi,%esi,2)
0x0040aea6:	pushl $0x1<UINT8>
0x0040aea8:	movl %eax, 0x8(%edi,%ecx,4)
0x0040aeac:	call 0x0040ae12
0x0040ae12:	pushl %ebx
0x0040ae13:	pushl %ecx
0x0040ae14:	movl %ebx, $0x431020<UINT32>
0x0040ae19:	movl %ecx, 0x8(%ebp)
0x0040ae1c:	movl 0x8(%ebx), %ecx
0x0040ae1f:	movl 0x4(%ebx), %eax
0x0040ae22:	movl 0xc(%ebx), %ebp
0x0040ae25:	popl %ecx
0x0040ae26:	popl %ebx
0x0040ae27:	ret $0x4<UINT16>

0x0040aeb1:	movl %eax, (%edi,%ecx,4)
0x0040aeb4:	movl 0xc(%ebx), %eax
0x0040aeb7:	call 0x0040b5b5
0x0040b5b5:	movl %esp, -24(%ebp)
0x0040b5b8:	pushl -104(%ebp)
0x0040b5bb:	call 0x0040e28c
0x0040e28c:	pushl $0x0<UINT8>
0x0040e28e:	pushl $0x1<UINT8>
0x0040e290:	pushl 0xc(%esp)
0x0040e294:	call 0x0040e29d
0x0040e29d:	pushl %edi
0x0040e29e:	call 0x0040e342
0x0040e342:	pushl $0xd<UINT8>
0x0040e344:	call 0x0040bf9b
0x0040e349:	popl %ecx
0x0040e34a:	ret

0x0040e2a3:	pushl $0x1<UINT8>
0x0040e2a5:	popl %edi
0x0040e2a6:	cmpl 0x4336b0, %edi
0x0040e2ac:	jne 0x0040e2bf
0x0040e2bf:	cmpl 0xc(%esp), $0x0<UINT8>
0x0040e2c4:	pushl %ebx
0x0040e2c5:	movl %ebx, 0x14(%esp)
0x0040e2c9:	movl 0x4336ac, %edi
0x0040e2cf:	movb 0x4336a8, %bl
0x0040e2d5:	jne 0x0040e313
0x0040e313:	pushl $0x416028<UINT32>
0x0040e318:	pushl $0x416024<UINT32>
0x0040e31d:	call 0x0040e354
0x0040e322:	popl %ecx
0x0040e323:	popl %ecx
0x0040e324:	testl %ebx, %ebx
0x0040e326:	popl %ebx
0x0040e327:	je 0x0040e330
0x0040e330:	pushl 0x8(%esp)
0x0040e334:	movl 0x4336b0, %edi
0x0040e33a:	call ExitProcess@KERNEL32.dll
ExitProcess@KERNEL32.dll: Exit Node	
