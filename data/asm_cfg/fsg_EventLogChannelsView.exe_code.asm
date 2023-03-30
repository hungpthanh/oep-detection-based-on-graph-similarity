0x0042a000:	movl %ebx, $0x4001d0<UINT32>
0x0042a005:	movl %edi, $0x401000<UINT32>
0x0042a00a:	movl %esi, $0x41df41<UINT32>
0x0042a00f:	pushl %ebx
0x0042a010:	call 0x0042a01f
0x0042a01f:	cld
0x0042a020:	movb %dl, $0xffffff80<UINT8>
0x0042a022:	movsb %es:(%edi), %ds:(%esi)
0x0042a023:	pushl $0x2<UINT8>
0x0042a025:	popl %ebx
0x0042a026:	call 0x0042a015
0x0042a015:	addb %dl, %dl
0x0042a017:	jne 0x0042a01e
0x0042a019:	movb %dl, (%esi)
0x0042a01b:	incl %esi
0x0042a01c:	adcb %dl, %dl
0x0042a01e:	ret

0x0042a029:	jae 0x0042a022
0x0042a02b:	xorl %ecx, %ecx
0x0042a02d:	call 0x0042a015
0x0042a030:	jae 0x0042a04a
0x0042a032:	xorl %eax, %eax
0x0042a034:	call 0x0042a015
0x0042a037:	jae 0x0042a05a
0x0042a039:	movb %bl, $0x2<UINT8>
0x0042a03b:	incl %ecx
0x0042a03c:	movb %al, $0x10<UINT8>
0x0042a03e:	call 0x0042a015
0x0042a041:	adcb %al, %al
0x0042a043:	jae 0x0042a03e
0x0042a045:	jne 0x0042a086
0x0042a086:	pushl %esi
0x0042a087:	movl %esi, %edi
0x0042a089:	subl %esi, %eax
0x0042a08b:	rep movsb %es:(%edi), %ds:(%esi)
0x0042a08d:	popl %esi
0x0042a08e:	jmp 0x0042a026
0x0042a047:	stosb %es:(%edi), %al
0x0042a048:	jmp 0x0042a026
0x0042a05a:	lodsb %al, %ds:(%esi)
0x0042a05b:	shrl %eax
0x0042a05d:	je 0x0042a0a0
0x0042a05f:	adcl %ecx, %ecx
0x0042a061:	jmp 0x0042a07f
0x0042a07f:	incl %ecx
0x0042a080:	incl %ecx
0x0042a081:	xchgl %ebp, %eax
0x0042a082:	movl %eax, %ebp
0x0042a084:	movb %bl, $0x1<UINT8>
0x0042a04a:	call 0x0042a092
0x0042a092:	incl %ecx
0x0042a093:	call 0x0042a015
0x0042a097:	adcl %ecx, %ecx
0x0042a099:	call 0x0042a015
0x0042a09d:	jb 0x0042a093
0x0042a09f:	ret

0x0042a04f:	subl %ecx, %ebx
0x0042a051:	jne 0x0042a063
0x0042a063:	xchgl %ecx, %eax
0x0042a064:	decl %eax
0x0042a065:	shll %eax, $0x8<UINT8>
0x0042a068:	lodsb %al, %ds:(%esi)
0x0042a069:	call 0x0042a090
0x0042a090:	xorl %ecx, %ecx
0x0042a06e:	cmpl %eax, $0x7d00<UINT32>
0x0042a073:	jae 0x0042a07f
0x0042a075:	cmpb %ah, $0x5<UINT8>
0x0042a078:	jae 0x0042a080
0x0042a07a:	cmpl %eax, $0x7f<UINT8>
0x0042a07d:	ja 0x0042a081
0x0042a053:	call 0x0042a090
0x0042a058:	jmp 0x0042a082
0x0042a0a0:	popl %edi
0x0042a0a1:	popl %ebx
0x0042a0a2:	movzwl %edi, (%ebx)
0x0042a0a5:	decl %edi
0x0042a0a6:	je 0x0042a0b0
0x0042a0a8:	decl %edi
0x0042a0a9:	je 0x0042a0be
0x0042a0ab:	shll %edi, $0xc<UINT8>
0x0042a0ae:	jmp 0x0042a0b7
0x0042a0b7:	incl %ebx
0x0042a0b8:	incl %ebx
0x0042a0b9:	jmp 0x0042a00f
0x0042a0b0:	movl %edi, 0x2(%ebx)
0x0042a0b3:	pushl %edi
0x0042a0b4:	addl %ebx, $0x4<UINT8>
0x0042a0be:	popl %edi
0x0042a0bf:	movl %ebx, $0x42a128<UINT32>
0x0042a0c4:	incl %edi
0x0042a0c5:	movl %esi, (%edi)
0x0042a0c7:	scasl %eax, %es:(%edi)
0x0042a0c8:	pushl %edi
0x0042a0c9:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0042a0cb:	xchgl %ebp, %eax
0x0042a0cc:	xorl %eax, %eax
0x0042a0ce:	scasb %al, %es:(%edi)
0x0042a0cf:	jne 0x0042a0ce
0x0042a0d1:	decb (%edi)
0x0042a0d3:	je 0x0042a0c4
0x0042a0d5:	decb (%edi)
0x0042a0d7:	jne 0x0042a0df
0x0042a0df:	decb (%edi)
0x0042a0e1:	je 0x0040e52e
0x0042a0e7:	pushl %edi
0x0042a0e8:	pushl %ebp
0x0042a0e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x0042a0ec:	orl (%esi), %eax
0x0042a0ee:	lodsl %eax, %ds:(%esi)
0x0042a0ef:	jne 0x0042a0cc
0x0042a0d9:	incl %edi
0x0042a0da:	pushl (%edi)
0x0042a0dc:	scasl %eax, %es:(%edi)
0x0042a0dd:	jmp 0x0042a0e8
GetProcAddress@KERNEL32.dll: API Node	
0x0040e52e:	pushl $0x70<UINT8>
0x0040e530:	pushl $0x40f3f0<UINT32>
0x0040e535:	call 0x0040e740
0x0040e740:	pushl $0x40e790<UINT32>
0x0040e745:	movl %eax, %fs:0
0x0040e74b:	pushl %eax
0x0040e74c:	movl %fs:0, %esp
0x0040e753:	movl %eax, 0x10(%esp)
0x0040e757:	movl 0x10(%esp), %ebp
0x0040e75b:	leal %ebp, 0x10(%esp)
0x0040e75f:	subl %esp, %eax
0x0040e761:	pushl %ebx
0x0040e762:	pushl %esi
0x0040e763:	pushl %edi
0x0040e764:	movl %eax, -8(%ebp)
0x0040e767:	movl -24(%ebp), %esp
0x0040e76a:	pushl %eax
0x0040e76b:	movl %eax, -4(%ebp)
0x0040e76e:	movl -4(%ebp), $0xffffffff<UINT32>
0x0040e775:	movl -8(%ebp), %eax
0x0040e778:	ret

0x0040e53a:	xorl %edi, %edi
0x0040e53c:	pushl %edi
0x0040e53d:	call GetModuleHandleA@KERNEL32.dll
GetModuleHandleA@KERNEL32.dll: API Node	
0x0040e543:	cmpw (%eax), $0x5a4d<UINT16>
0x0040e548:	jne 31
0x0040e54a:	movl %ecx, 0x3c(%eax)
0x0040e54d:	addl %ecx, %eax
0x0040e54f:	cmpl (%ecx), $0x4550<UINT32>
0x0040e555:	jne 18
0x0040e557:	movzwl %eax, 0x18(%ecx)
0x0040e55b:	cmpl %eax, $0x10b<UINT32>
0x0040e560:	je 0x0040e581
0x0040e581:	cmpl 0x74(%ecx), $0xe<UINT8>
0x0040e585:	jbe -30
0x0040e587:	xorl %eax, %eax
0x0040e589:	cmpl 0xe8(%ecx), %edi
0x0040e58f:	setne %al
0x0040e592:	movl -28(%ebp), %eax
0x0040e595:	movl -4(%ebp), %edi
0x0040e598:	pushl $0x2<UINT8>
0x0040e59a:	popl %ebx
0x0040e59b:	pushl %ebx
0x0040e59c:	call __set_app_type@msvcrt.dll
__set_app_type@msvcrt.dll: API Node	
0x0040e5a2:	popl %ecx
0x0040e5a3:	orl 0x413858, $0xffffffff<UINT8>
0x0040e5aa:	orl 0x41385c, $0xffffffff<UINT8>
0x0040e5b1:	call __p__fmode@msvcrt.dll
__p__fmode@msvcrt.dll: API Node	
0x0040e5b7:	movl %ecx, 0x41241c
0x0040e5bd:	movl (%eax), %ecx
0x0040e5bf:	call __p__commode@msvcrt.dll
__p__commode@msvcrt.dll: API Node	
0x0040e5c5:	movl %ecx, 0x412418
0x0040e5cb:	movl (%eax), %ecx
0x0040e5cd:	movl %eax, 0x40f2e4
0x0040e5d2:	movl %eax, (%eax)
0x0040e5d4:	movl 0x413854, %eax
0x0040e5d9:	call 0x0040e73c
0x0040e73c:	xorl %eax, %eax
0x0040e73e:	ret

0x0040e5de:	cmpl 0x412000, %edi
0x0040e5e4:	jne 0x0040e5f2
0x0040e5f2:	call 0x0040e72a
0x0040e72a:	pushl $0x30000<UINT32>
0x0040e72f:	pushl $0x10000<UINT32>
0x0040e734:	call 0x0040e78a
0x0040e78a:	jmp _controlfp@msvcrt.dll
_controlfp@msvcrt.dll: API Node	
0x0040e739:	popl %ecx
0x0040e73a:	popl %ecx
0x0040e73b:	ret

0x0040e5f7:	pushl $0x40f3c4<UINT32>
0x0040e5fc:	pushl $0x40f3c0<UINT32>
0x0040e601:	call 0x0040e724
0x0040e724:	jmp _initterm@msvcrt.dll
_initterm@msvcrt.dll: API Node	
0x0040e606:	movl %eax, 0x412414
0x0040e60b:	movl -32(%ebp), %eax
0x0040e60e:	leal %eax, -32(%ebp)
0x0040e611:	pushl %eax
0x0040e612:	pushl 0x412410
0x0040e618:	leal %eax, -36(%ebp)
0x0040e61b:	pushl %eax
0x0040e61c:	leal %eax, -40(%ebp)
0x0040e61f:	pushl %eax
0x0040e620:	leal %eax, -44(%ebp)
0x0040e623:	pushl %eax
0x0040e624:	call __wgetmainargs@msvcrt.dll
__wgetmainargs@msvcrt.dll: API Node	
0x0040e62a:	movl -48(%ebp), %eax
0x0040e62d:	pushl $0x40f3bc<UINT32>
0x0040e632:	pushl $0x40f398<UINT32>
0x0040e637:	call 0x0040e724
0x0040e63c:	addl %esp, $0x24<UINT8>
0x0040e63f:	movl %eax, 0x40f2f4
0x0040e644:	movl %esi, (%eax)
0x0040e646:	cmpl %esi, %edi
0x0040e648:	jne 0x0040e658
0x0040e658:	movl -52(%ebp), %esi
0x0040e65b:	cmpw (%esi), $0x22<UINT8>
0x0040e65f:	jne 69
0x0040e661:	addl %esi, %ebx
0x0040e663:	movl -52(%ebp), %esi
0x0040e666:	movw %ax, (%esi)
0x0040e669:	cmpw %ax, %di
0x0040e66c:	je 6
0x0040e66e:	cmpw %ax, $0x22<UINT16>
0x0040e672:	jne 0x0040e661
0x0040e674:	cmpw (%esi), $0x22<UINT8>
0x0040e678:	jne 5
0x0040e67a:	addl %esi, %ebx
0x0040e67c:	movl -52(%ebp), %esi
0x0040e67f:	movw %ax, (%esi)
0x0040e682:	cmpw %ax, %di
0x0040e685:	je 6
0x0040e687:	cmpw %ax, $0x20<UINT16>
0x0040e68b:	jbe 0x0040e67a
0x0040e68d:	movl -76(%ebp), %edi
0x0040e690:	leal %eax, -120(%ebp)
0x0040e693:	pushl %eax
0x0040e694:	call GetStartupInfoW@KERNEL32.dll
GetStartupInfoW@KERNEL32.dll: API Node	
0x0040e69a:	testb -76(%ebp), $0x1<UINT8>
0x0040e69e:	je 0x0040e6b3
0x0040e6b3:	pushl $0xa<UINT8>
0x0040e6b5:	popl %eax
0x0040e6b6:	pushl %eax
0x0040e6b7:	pushl %esi
0x0040e6b8:	pushl %edi
0x0040e6b9:	pushl %edi
0x0040e6ba:	call GetModuleHandleA@KERNEL32.dll
0x0040e6c0:	pushl %eax
0x0040e6c1:	call 0x0040af5d
0x0040af5d:	pushl %ebp
0x0040af5e:	movl %ebp, %esp
0x0040af60:	andl %esp, $0xfffffff8<UINT8>
0x0040af63:	movl %eax, $0x285c<UINT32>
0x0040af68:	call 0x0040e7b0
0x0040e7b0:	cmpl %eax, $0x1000<UINT32>
0x0040e7b5:	jae 0x0040e7c5
0x0040e7c5:	pushl %ecx
0x0040e7c6:	leal %ecx, 0x8(%esp)
0x0040e7ca:	subl %ecx, $0x1000<UINT32>
0x0040e7d0:	subl %eax, $0x1000<UINT32>
0x0040e7d5:	testl (%ecx), %eax
0x0040e7d7:	cmpl %eax, $0x1000<UINT32>
0x0040e7dc:	jae 0x0040e7ca
0x0040e7de:	subl %ecx, %eax
0x0040e7e0:	movl %eax, %esp
0x0040e7e2:	testl (%ecx), %eax
0x0040e7e4:	movl %esp, %ecx
0x0040e7e6:	movl %ecx, (%eax)
0x0040e7e8:	movl %eax, 0x4(%eax)
0x0040e7eb:	pushl %eax
0x0040e7ec:	ret

0x0040af6d:	pushl %ebx
0x0040af6e:	pushl %esi
0x0040af6f:	pushl %edi
0x0040af70:	call 0x00402797
0x00402797:	pushl %ebp
0x00402798:	movl %ebp, %esp
0x0040279a:	pushl %ecx
0x0040279b:	pushl %ecx
0x0040279c:	pushl %ebx
0x0040279d:	pushl %esi
0x0040279e:	pushl %edi
0x0040279f:	pushl $0x40f718<UINT32>
0x004027a4:	movl -8(%ebp), $0x8<UINT32>
0x004027ab:	movl -4(%ebp), $0xff<UINT32>
0x004027b2:	xorl %ebx, %ebx
0x004027b4:	xorl %edi, %edi
0x004027b6:	call LoadLibraryW@KERNEL32.dll
LoadLibraryW@KERNEL32.dll: API Node	
0x004027bc:	movl %esi, %eax
0x004027be:	testl %esi, %esi
0x004027c0:	je 40
0x004027c2:	pushl $0x40f734<UINT32>
0x004027c7:	pushl %esi
0x004027c8:	call GetProcAddress@KERNEL32.dll
0x004027ce:	testl %eax, %eax
0x004027d0:	je 9
0x004027d2:	leal %ecx, -8(%ebp)
0x004027d5:	pushl %ecx
0x004027d6:	incl %edi
0x004027d7:	call InitCommonControlsEx@comctl32.dll
InitCommonControlsEx@comctl32.dll: API Node	
0x004027d9:	movl %ebx, %eax
0x004027db:	pushl %esi
0x004027dc:	call FreeLibrary@KERNEL32.dll
FreeLibrary@KERNEL32.dll: API Node	
0x004027e2:	testl %edi, %edi
0x004027e4:	je 4
0x004027e6:	movl %eax, %ebx
0x004027e8:	jmp 0x004027f3
0x004027f3:	testl %eax, %eax
0x004027f5:	popl %edi
0x004027f6:	popl %esi
0x004027f7:	popl %ebx
0x004027f8:	jne 0x00402811
0x004027fa:	pushl $0x30<UINT8>
0x00402811:	xorl %eax, %eax
0x00402813:	incl %eax
0x00402814:	leave
0x00402815:	ret

0x0040af75:	testl %eax, %eax
0x0040af77:	jne 0x0040af7f
0x0040af7f:	call 0x0040c55c
0x0040c55c:	cmpl 0x4132f8, $0x0<UINT8>
0x0040c563:	jne 37
0x0040c565:	pushl $0x410648<UINT32>
0x0040c56a:	call LoadLibraryW@KERNEL32.dll
0x0040c570:	testl %eax, %eax
0x0040c572:	movl 0x4132f8, %eax
0x0040c577:	je 17
0x0040c579:	pushl $0x410660<UINT32>
0x0040c57e:	pushl %eax
0x0040c57f:	call GetProcAddress@KERNEL32.dll
0x0040c585:	movl 0x4132f4, %eax
0x0040c58a:	ret

0x0040af84:	pushl $0x8001<UINT32>
0x0040af89:	call SetErrorMode@KERNEL32.dll
SetErrorMode@KERNEL32.dll: API Node	
0x0040af8f:	movl %ebx, 0x40f0ac
0x0040af95:	xorl %edi, %edi
0x0040af97:	pushl %edi
0x0040af98:	pushl $0x40c541<UINT32>
0x0040af9d:	pushl %edi
0x0040af9e:	movl 0x412ba0, $0x11223344<UINT32>
0x0040afa8:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x0040afaa:	pushl %eax
0x0040afab:	call EnumResourceTypesW@KERNEL32.dll
EnumResourceTypesW@KERNEL32.dll: API Node	
0x0040afb1:	leal %eax, 0x10(%esp)
0x0040afb5:	call 0x00404a8d
0x00404a8d:	xorl %ecx, %ecx
0x00404a8f:	movl 0x14(%eax), $0x400<UINT32>
0x00404a96:	movl 0x18(%eax), $0x100<UINT32>
0x00404a9d:	movl (%eax), %ecx
0x00404a9f:	movl 0x4(%eax), %ecx
0x00404aa2:	movl 0xc(%eax), %ecx
0x00404aa5:	movl 0x10(%eax), %ecx
0x00404aa8:	movl 0x1c(%eax), %ecx
0x00404aab:	movl 0x8(%eax), %ecx
0x00404aae:	ret

0x0040afba:	leal %eax, 0x60(%esp)
0x0040afbe:	pushl %eax
0x0040afbf:	movl 0x3c(%esp), $0x20<UINT32>
0x0040afc7:	movl 0x34(%esp), %edi
0x0040afcb:	movl 0x40(%esp), %edi
0x0040afcf:	movl 0x38(%esp), %edi
0x0040afd3:	movl 0x44(%esp), %edi
0x0040afd7:	call 0x0040abbd
0x0040abbd:	pushl %ebx
0x0040abbe:	xorl %ebx, %ebx
0x0040abc0:	pushl %ebp
0x0040abc1:	movl %ebp, 0xc(%esp)
0x0040abc5:	movl 0x208(%ebp), %ebx
0x0040abcb:	movl 0x244(%ebp), %ebx
0x0040abd1:	movl 0x274(%ebp), %ebx
0x0040abd7:	movl 0x240(%ebp), %ebx
0x0040abdd:	movl (%ebp), $0x410360<UINT32>
0x0040abe4:	pushl %esi
0x0040abe5:	movl 0x694(%ebp), %ebx
0x0040abeb:	leal %eax, 0x6bc(%ebp)
0x0040abf1:	pushl %edi
0x0040abf2:	movl 0x6b8(%ebp), %ebx
0x0040abf8:	leal %edi, 0x6d8(%ebp)
0x0040abfe:	movl %esi, %edi
0x0040ac00:	movl (%eax), $0x41078c<UINT32>
0x0040ac06:	movl 0x4(%eax), %ebx
0x0040ac09:	movl 0x8(%eax), %ebx
0x0040ac0c:	movl 0x10(%eax), %ebx
0x0040ac0f:	call 0x00401312
0x00401312:	andl 0x10(%esi), $0x0<UINT8>
0x00401316:	pushl $0x2c<UINT8>
0x00401318:	leal %eax, 0x14(%esi)
0x0040131b:	pushl $0x0<UINT8>
0x0040131d:	pushl %eax
0x0040131e:	movl (%esi), $0x40f464<UINT32>
0x00401324:	call 0x0040e466
0x0040e466:	jmp memset@msvcrt.dll
memset@msvcrt.dll: API Node	
0x00401329:	addl %esp, $0xc<UINT8>
0x0040132c:	movl %eax, %esi
0x0040132e:	ret

0x0018fed8:	jl -1
0x0018feda:	sbbb (%eax), %al
0x0018fedc:	movb %dh, $0x40<UINT8>
0x0018fedf:	addb (%eax), %al
0x0018fee1:	addb (%eax), %al
0x0018fee4:	addb (%eax), %al
0x0018fee6:	addb (%eax), %al
0x0018fee8:	cmpb %ds:(%eax), %al
0x0018feec:	orb %al, (%eax)
0x0018feee:	addb (%eax), %al
0x0018fef0:	jbe 30
0x0018fef2:	incl %ecx
0x0018fef3:	addb 0x40(%ecx,%esi,8), %bl
0x0040e790:	jmp _except_handler3@msvcrt.dll
_except_handler3@msvcrt.dll: API Node	
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
0x004027fc:	pushl $0x40f74c<UINT32>
0x00402801:	pushl $0x40f758<UINT32>
0x00402806:	pushl %eax
0x00402807:	call MessageBoxW@USER32.dll
MessageBoxW@USER32.dll: API Node	
0x0040280d:	xorl %eax, %eax
0x0040280f:	leave
0x00402810:	ret

0x0040af79:	incl %eax
0x0040af7a:	jmp 0x0040b166
0x0040b166:	popl %edi
0x0040b167:	popl %esi
0x0040b168:	popl %ebx
0x0040b169:	movl %esp, %ebp
0x0040b16b:	popl %ebp
0x0040b16c:	ret $0x10<UINT16>

0x0040e6c6:	movl %esi, %eax
0x0040e6c8:	movl -124(%ebp), %esi
0x0040e6cb:	cmpl -28(%ebp), %edi
0x0040e6ce:	jne 7
0x0040e6d0:	pushl %esi
0x0040e6d1:	call exit@msvcrt.dll
exit@msvcrt.dll: Exit Node	
