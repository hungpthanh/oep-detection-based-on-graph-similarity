0x0042a000:	movl %ebx, $0x4001d0<UINT32>
0x0042a005:	movl %edi, $0x401000<UINT32>
0x0042a00a:	movl %esi, $0x41e44a<UINT32>
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
0x0042a0e1:	je 0x0040e78e
0x0042a0e7:	pushl %edi
0x0042a0e8:	pushl %ebp
0x0042a0e9:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0042a0ec:	orl (%esi), %eax
0x0042a0ee:	lodsl %eax, %ds:(%esi)
0x0042a0ef:	jne 0x0042a0cc
GetProcAddress@KERNEL32.DLL: API Node	
0x0042a0d9:	incl %edi
0x0042a0da:	pushl (%edi)
0x0042a0dc:	scasl %eax, %es:(%edi)
0x0042a0dd:	jmp 0x0042a0e8
0x0040e78e:	pushl $0x70<UINT8>
0x0040e790:	pushl $0x40f410<UINT32>
0x0040e795:	call 0x0040e9a0
0x0040e9a0:	pushl $0x40e9f0<UINT32>
0x0040e9a5:	movl %eax, %fs:0
0x0040e9ab:	pushl %eax
0x0040e9ac:	movl %fs:0, %esp
0x0040e9b3:	movl %eax, 0x10(%esp)
0x0040e9b7:	movl 0x10(%esp), %ebp
0x0040e9bb:	leal %ebp, 0x10(%esp)
0x0040e9bf:	subl %esp, %eax
0x0040e9c1:	pushl %ebx
0x0040e9c2:	pushl %esi
0x0040e9c3:	pushl %edi
0x0040e9c4:	movl %eax, -8(%ebp)
0x0040e9c7:	movl -24(%ebp), %esp
0x0040e9ca:	pushl %eax
0x0040e9cb:	movl %eax, -4(%ebp)
0x0040e9ce:	movl -4(%ebp), $0xffffffff<UINT32>
0x0040e9d5:	movl -8(%ebp), %eax
0x0040e9d8:	ret

0x0040e79a:	xorl %edi, %edi
0x0040e79c:	pushl %edi
0x0040e79d:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x0040e7a3:	cmpw (%eax), $0x5a4d<UINT16>
0x0040e7a8:	jne 31
0x0040e7aa:	movl %ecx, 0x3c(%eax)
0x0040e7ad:	addl %ecx, %eax
0x0040e7af:	cmpl (%ecx), $0x4550<UINT32>
0x0040e7b5:	jne 18
0x0040e7b7:	movzwl %eax, 0x18(%ecx)
0x0040e7bb:	cmpl %eax, $0x10b<UINT32>
0x0040e7c0:	je 0x0040e7e1
0x0040e7e1:	cmpl 0x74(%ecx), $0xe<UINT8>
0x0040e7e5:	jbe -30
0x0040e7e7:	xorl %eax, %eax
0x0040e7e9:	cmpl 0xe8(%ecx), %edi
0x0040e7ef:	setne %al
0x0040e7f2:	movl -28(%ebp), %eax
0x0040e7f5:	movl -4(%ebp), %edi
0x0040e7f8:	pushl $0x2<UINT8>
0x0040e7fa:	popl %ebx
0x0040e7fb:	pushl %ebx
0x0040e7fc:	call __set_app_type@msvcrt.dll
__set_app_type@msvcrt.dll: API Node	
0x0040e802:	popl %ecx
0x0040e803:	orl 0x4162f4, $0xffffffff<UINT8>
0x0040e80a:	orl 0x4162f8, $0xffffffff<UINT8>
0x0040e811:	call __p__fmode@msvcrt.dll
__p__fmode@msvcrt.dll: API Node	
0x0040e817:	movl %ecx, 0x414f3c
0x0040e81d:	movl (%eax), %ecx
0x0040e81f:	call __p__commode@msvcrt.dll
__p__commode@msvcrt.dll: API Node	
0x0040e825:	movl %ecx, 0x414f38
0x0040e82b:	movl (%eax), %ecx
0x0040e82d:	movl %eax, 0x40f314
0x0040e832:	movl %eax, (%eax)
0x0040e834:	movl 0x4162f0, %eax
0x0040e839:	call 0x0040e99c
0x0040e99c:	xorl %eax, %eax
0x0040e99e:	ret

0x0040e83e:	cmpl 0x414000, %edi
0x0040e844:	jne 0x0040e852
0x0040e852:	call 0x0040e98a
0x0040e98a:	pushl $0x30000<UINT32>
0x0040e98f:	pushl $0x10000<UINT32>
0x0040e994:	call 0x0040e9ea
0x0040e9ea:	jmp _controlfp@msvcrt.dll
_controlfp@msvcrt.dll: API Node	
0x0040e999:	popl %ecx
0x0040e99a:	popl %ecx
0x0040e99b:	ret

0x0040e857:	pushl $0x40f3ec<UINT32>
0x0040e85c:	pushl $0x40f3e8<UINT32>
0x0040e861:	call 0x0040e984
0x0040e984:	jmp _initterm@msvcrt.dll
_initterm@msvcrt.dll: API Node	
0x0040e866:	movl %eax, 0x414f34
0x0040e86b:	movl -32(%ebp), %eax
0x0040e86e:	leal %eax, -32(%ebp)
0x0040e871:	pushl %eax
0x0040e872:	pushl 0x414f30
0x0040e878:	leal %eax, -36(%ebp)
0x0040e87b:	pushl %eax
0x0040e87c:	leal %eax, -40(%ebp)
0x0040e87f:	pushl %eax
0x0040e880:	leal %eax, -44(%ebp)
0x0040e883:	pushl %eax
0x0040e884:	call __wgetmainargs@msvcrt.dll
__wgetmainargs@msvcrt.dll: API Node	
0x0040e88a:	movl -48(%ebp), %eax
0x0040e88d:	pushl $0x40f3e4<UINT32>
0x0040e892:	pushl $0x40f3cc<UINT32>
0x0040e897:	call 0x0040e984
0x0040e89c:	addl %esp, $0x24<UINT8>
0x0040e89f:	movl %eax, 0x40f324
0x0040e8a4:	movl %esi, (%eax)
0x0040e8a6:	cmpl %esi, %edi
0x0040e8a8:	jne 0x0040e8b8
0x0040e8b8:	movl -52(%ebp), %esi
0x0040e8bb:	cmpw (%esi), $0x22<UINT8>
0x0040e8bf:	jne 69
0x0040e8c1:	addl %esi, %ebx
0x0040e8c3:	movl -52(%ebp), %esi
0x0040e8c6:	movw %ax, (%esi)
0x0040e8c9:	cmpw %ax, %di
0x0040e8cc:	je 6
0x0040e8ce:	cmpw %ax, $0x22<UINT16>
0x0040e8d2:	jne 0x0040e8c1
0x0040e8d4:	cmpw (%esi), $0x22<UINT8>
0x0040e8d8:	jne 5
0x0040e8da:	addl %esi, %ebx
0x0040e8dc:	movl -52(%ebp), %esi
0x0040e8df:	movw %ax, (%esi)
0x0040e8e2:	cmpw %ax, %di
0x0040e8e5:	je 6
0x0040e8e7:	cmpw %ax, $0x20<UINT16>
0x0040e8eb:	jbe 0x0040e8da
0x0040e8ed:	movl -76(%ebp), %edi
0x0040e8f0:	leal %eax, -120(%ebp)
0x0040e8f3:	pushl %eax
0x0040e8f4:	call GetStartupInfoW@KERNEL32.DLL
GetStartupInfoW@KERNEL32.DLL: API Node	
0x0040e8fa:	testb -76(%ebp), $0x1<UINT8>
0x0040e8fe:	je 0x0040e913
0x0040e913:	pushl $0xa<UINT8>
0x0040e915:	popl %eax
0x0040e916:	pushl %eax
0x0040e917:	pushl %esi
0x0040e918:	pushl %edi
0x0040e919:	pushl %edi
0x0040e91a:	call GetModuleHandleA@KERNEL32.DLL
0x0040e920:	pushl %eax
0x0040e921:	call 0x0040c99f
0x0040c99f:	pushl %ebp
0x0040c9a0:	movl %ebp, %esp
0x0040c9a2:	subl %esp, $0x71c<UINT32>
0x0040c9a8:	call 0x0040312f
0x0040312f:	pushl %ebp
0x00403130:	movl %ebp, %esp
0x00403132:	pushl %ecx
0x00403133:	pushl %ecx
0x00403134:	pushl %ebx
0x00403135:	pushl %esi
0x00403136:	pushl %edi
0x00403137:	pushl $0x40fac4<UINT32>
0x0040313c:	movl -8(%ebp), $0x8<UINT32>
0x00403143:	movl -4(%ebp), $0xff<UINT32>
0x0040314a:	xorl %ebx, %ebx
0x0040314c:	xorl %edi, %edi
0x0040314e:	call LoadLibraryW@KERNEL32.DLL
LoadLibraryW@KERNEL32.DLL: API Node	
0x00403154:	movl %esi, %eax
0x00403156:	testl %esi, %esi
0x00403158:	je 40
0x0040315a:	pushl $0x40fae0<UINT32>
0x0040315f:	pushl %esi
0x00403160:	call GetProcAddress@KERNEL32.DLL
0x00403166:	testl %eax, %eax
0x00403168:	je 9
0x0040316a:	leal %ecx, -8(%ebp)
0x0040316d:	pushl %ecx
0x0040316e:	incl %edi
0x0040316f:	call InitCommonControlsEx@comctl32.dll
InitCommonControlsEx@comctl32.dll: API Node	
0x00403171:	movl %ebx, %eax
0x00403173:	pushl %esi
0x00403174:	call FreeLibrary@KERNEL32.DLL
FreeLibrary@KERNEL32.DLL: API Node	
0x0040317a:	testl %edi, %edi
0x0040317c:	je 4
0x0040317e:	movl %eax, %ebx
0x00403180:	jmp 0x0040318b
0x0040318b:	testl %eax, %eax
0x0040318d:	popl %edi
0x0040318e:	popl %esi
0x0040318f:	popl %ebx
0x00403190:	jne 0x004031a9
0x00403192:	pushl $0x30<UINT8>
0x004031a9:	xorl %eax, %eax
0x004031ab:	incl %eax
0x004031ac:	leave
0x004031ad:	ret

0x0040c9ad:	testl %eax, %eax
0x0040c9af:	jne 0x0040c9b7
0x0040c9b7:	pushl %ebx
0x0040c9b8:	pushl %esi
0x0040c9b9:	pushl %edi
0x0040c9ba:	call 0x0040dcaf
0x0040dcaf:	cmpl 0x415e18, $0x0<UINT8>
0x0040dcb6:	jne 37
0x0040dcb8:	pushl $0x412254<UINT32>
0x0040dcbd:	call LoadLibraryW@KERNEL32.DLL
0x0040dcc3:	testl %eax, %eax
0x0040dcc5:	movl 0x415e18, %eax
0x0040dcca:	je 17
0x0040dccc:	pushl $0x41226c<UINT32>
0x0040dcd1:	pushl %eax
0x0040dcd2:	call GetProcAddress@KERNEL32.DLL
0x0040dcd8:	movl 0x415e14, %eax
0x0040dcdd:	ret

0x0040c9bf:	pushl $0x8001<UINT32>
0x0040c9c4:	call SetErrorMode@KERNEL32.DLL
SetErrorMode@KERNEL32.DLL: API Node	
0x0040c9ca:	xorl %ebx, %ebx
0x0040c9cc:	pushl %ebx
0x0040c9cd:	pushl $0x40dc94<UINT32>
0x0040c9d2:	pushl %ebx
0x0040c9d3:	movl 0x4156c0, $0x11223344<UINT32>
0x0040c9dd:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0040c9e3:	pushl %eax
0x0040c9e4:	call EnumResourceTypesW@KERNEL32.DLL
EnumResourceTypesW@KERNEL32.DLL: API Node	
0x0040c9ea:	leal %eax, -1820(%ebp)
0x0040c9f0:	pushl %eax
0x0040c9f1:	movl -32(%ebp), $0x400<UINT32>
0x0040c9f8:	movl -28(%ebp), $0x100<UINT32>
0x0040c9ff:	movl -52(%ebp), %ebx
0x0040ca02:	movl -48(%ebp), %ebx
0x0040ca05:	movl -40(%ebp), %ebx
0x0040ca08:	movl -36(%ebp), %ebx
0x0040ca0b:	movl -24(%ebp), %ebx
0x0040ca0e:	movl -44(%ebp), %ebx
0x0040ca11:	movl -12(%ebp), $0x20<UINT32>
0x0040ca18:	movl -20(%ebp), %ebx
0x0040ca1b:	movl -8(%ebp), %ebx
0x0040ca1e:	movl -16(%ebp), %ebx
0x0040ca21:	movl -4(%ebp), %ebx
0x0040ca24:	call 0x0040c5d2
0x0040c5d2:	pushl %ebx
0x0040c5d3:	pushl %ebp
0x0040c5d4:	movl %ebp, 0xc(%esp)
0x0040c5d8:	pushl %esi
0x0040c5d9:	pushl %edi
0x0040c5da:	xorl %edi, %edi
0x0040c5dc:	movl 0x240(%ebp), %edi
0x0040c5e2:	movl (%ebp), $0x411f78<UINT32>
0x0040c5e9:	leal %ebx, 0x690(%ebp)
0x0040c5ef:	movl (%ebx), %edi
0x0040c5f1:	movl 0x6b8(%ebp), %edi
0x0040c5f7:	movl 0x6bc(%ebp), %edi
0x0040c5fd:	pushl $0xe4c<UINT32>
0x0040c602:	movl 0x6c4(%ebp), %edi
0x0040c608:	movl 0x6c0(%ebp), %edi
0x0040c60e:	call 0x0040e740
0x0040e740:	jmp ??2@YAPAXI@Z@msvcrt.dll
??2@YAPAXI@Z@msvcrt.dll: API Node	
0x0040c613:	cmpl %eax, %edi
0x0040c615:	popl %ecx
0x0040c616:	je 49
0x0040c618:	movl 0x14(%eax), $0x1<UINT32>
0x0040c61f:	movw 0x222(%eax), %di
0x0040c626:	movw 0x18(%eax), %di
0x0040c62a:	movw 0x42c(%eax), %di
0x0040c631:	movw 0xc2c(%eax), %di
0x0040c638:	movl 0x4156c4, %eax
0x0040c63d:	movl 0xe3c(%eax), $0x3fff<UINT32>
0x0040c647:	jmp 0x0040c64b
0x0040c64b:	pushl $0x2dc<UINT32>
0x0040c650:	movl 0x694(%ebp), %eax
0x0040c656:	call 0x0040e740
0x0040c65b:	movl %esi, %eax
0x0040c65d:	cmpl %esi, %edi
0x0040c65f:	popl %ecx
0x0040c660:	je 13
0x0040c662:	call 0x00407e75
0x00407e75:	pushl %ebx
0x00407e76:	pushl %edi
0x00407e77:	pushl %esi
0x00407e78:	movl %eax, $0x2dc<UINT32>
0x00407e7d:	movl (%esi), $0x411bd0<UINT32>
0x00407e83:	call 0x00406343
0x00406343:	addl %eax, $0xfffffffc<UINT8>
0x00406346:	pushl %eax
0x00406347:	movl %eax, 0x8(%esp)
0x0040634b:	addl %eax, $0x4<UINT8>
0x0040634e:	pushl $0x0<UINT8>
0x00406350:	pushl %eax
0x00406351:	call 0x0040e704
0x0040e704:	jmp memset@msvcrt.dll
memset@msvcrt.dll: API Node	
0x00406356:	addl %esp, $0xc<UINT8>
0x00406359:	ret

0x0018fe4c:	addb (%eax), %al
0x0040e9f0:	jmp _except_handler3@msvcrt.dll
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
0x7c903306:	addb (%eax), %al
0x7c903308:	addb (%eax), %al
0x7c90330a:	addb (%eax), %al
0x7c90330c:	addb (%eax), %al
0x00403194:	pushl $0x40faf8<UINT32>
0x00403199:	pushl $0x40fb08<UINT32>
0x0040319e:	pushl %eax
0x0040319f:	call MessageBoxW@USER32.dll
MessageBoxW@USER32.dll: API Node	
0x004031a5:	xorl %eax, %eax
0x004031a7:	leave
0x004031a8:	ret

0x0040c9b1:	incl %eax
0x0040c9b2:	jmp 0x0040cb88
0x0040cb88:	leave
0x0040cb89:	ret $0x10<UINT16>

0x0040e926:	movl %esi, %eax
0x0040e928:	movl -124(%ebp), %esi
0x0040e92b:	cmpl -28(%ebp), %edi
0x0040e92e:	jne 7
0x0040e930:	pushl %esi
0x0040e931:	call exit@msvcrt.dll
exit@msvcrt.dll: Exit Node	
