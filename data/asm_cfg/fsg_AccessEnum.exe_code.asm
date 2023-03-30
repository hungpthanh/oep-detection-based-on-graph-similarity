0x00435000:	movl %ebx, $0x4001d0<UINT32>
0x00435005:	movl %edi, $0x401000<UINT32>
0x0043500a:	movl %esi, $0x42ab22<UINT32>
0x0043500f:	pushl %ebx
0x00435010:	call 0x0043501f
0x0043501f:	cld
0x00435020:	movb %dl, $0xffffff80<UINT8>
0x00435022:	movsb %es:(%edi), %ds:(%esi)
0x00435023:	pushl $0x2<UINT8>
0x00435025:	popl %ebx
0x00435026:	call 0x00435015
0x00435015:	addb %dl, %dl
0x00435017:	jne 0x0043501e
0x00435019:	movb %dl, (%esi)
0x0043501b:	incl %esi
0x0043501c:	adcb %dl, %dl
0x0043501e:	ret

0x00435029:	jae 0x00435022
0x0043502b:	xorl %ecx, %ecx
0x0043502d:	call 0x00435015
0x00435030:	jae 0x0043504a
0x00435032:	xorl %eax, %eax
0x00435034:	call 0x00435015
0x00435037:	jae 0x0043505a
0x00435039:	movb %bl, $0x2<UINT8>
0x0043503b:	incl %ecx
0x0043503c:	movb %al, $0x10<UINT8>
0x0043503e:	call 0x00435015
0x00435041:	adcb %al, %al
0x00435043:	jae 0x0043503e
0x00435045:	jne 0x00435086
0x00435047:	stosb %es:(%edi), %al
0x00435048:	jmp 0x00435026
0x0043505a:	lodsb %al, %ds:(%esi)
0x0043505b:	shrl %eax
0x0043505d:	je 0x004350a0
0x0043505f:	adcl %ecx, %ecx
0x00435061:	jmp 0x0043507f
0x0043507f:	incl %ecx
0x00435080:	incl %ecx
0x00435081:	xchgl %ebp, %eax
0x00435082:	movl %eax, %ebp
0x00435084:	movb %bl, $0x1<UINT8>
0x00435086:	pushl %esi
0x00435087:	movl %esi, %edi
0x00435089:	subl %esi, %eax
0x0043508b:	rep movsb %es:(%edi), %ds:(%esi)
0x0043508d:	popl %esi
0x0043508e:	jmp 0x00435026
0x0043504a:	call 0x00435092
0x00435092:	incl %ecx
0x00435093:	call 0x00435015
0x00435097:	adcl %ecx, %ecx
0x00435099:	call 0x00435015
0x0043509d:	jb 0x00435093
0x0043509f:	ret

0x0043504f:	subl %ecx, %ebx
0x00435051:	jne 0x00435063
0x00435053:	call 0x00435090
0x00435090:	xorl %ecx, %ecx
0x00435058:	jmp 0x00435082
0x00435063:	xchgl %ecx, %eax
0x00435064:	decl %eax
0x00435065:	shll %eax, $0x8<UINT8>
0x00435068:	lodsb %al, %ds:(%esi)
0x00435069:	call 0x00435090
0x0043506e:	cmpl %eax, $0x7d00<UINT32>
0x00435073:	jae 0x0043507f
0x00435075:	cmpb %ah, $0x5<UINT8>
0x00435078:	jae 0x00435080
0x0043507a:	cmpl %eax, $0x7f<UINT8>
0x0043507d:	ja 0x00435081
0x004350a0:	popl %edi
0x004350a1:	popl %ebx
0x004350a2:	movzwl %edi, (%ebx)
0x004350a5:	decl %edi
0x004350a6:	je 0x004350b0
0x004350a8:	decl %edi
0x004350a9:	je 0x004350be
0x004350ab:	shll %edi, $0xc<UINT8>
0x004350ae:	jmp 0x004350b7
0x004350b7:	incl %ebx
0x004350b8:	incl %ebx
0x004350b9:	jmp 0x0043500f
0x004350b0:	movl %edi, 0x2(%ebx)
0x004350b3:	pushl %edi
0x004350b4:	addl %ebx, $0x4<UINT8>
0x004350be:	popl %edi
0x004350bf:	movl %ebx, $0x435128<UINT32>
0x004350c4:	incl %edi
0x004350c5:	movl %esi, (%edi)
0x004350c7:	scasl %eax, %es:(%edi)
0x004350c8:	pushl %edi
0x004350c9:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004350cb:	xchgl %ebp, %eax
0x004350cc:	xorl %eax, %eax
0x004350ce:	scasb %al, %es:(%edi)
0x004350cf:	jne 0x004350ce
0x004350d1:	decb (%edi)
0x004350d3:	je 0x004350c4
0x004350d5:	decb (%edi)
0x004350d7:	jne 0x004350df
0x004350df:	decb (%edi)
0x004350e1:	je 0x00407a98
0x004350e7:	pushl %edi
0x004350e8:	pushl %ebp
0x004350e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x004350ec:	orl (%esi), %eax
0x004350ee:	lodsl %eax, %ds:(%esi)
0x004350ef:	jne 0x004350cc
GetProcAddress@KERNEL32.dll: API Node	
0x004350d9:	incl %edi
0x004350da:	pushl (%edi)
0x004350dc:	scasl %eax, %es:(%edi)
0x004350dd:	jmp 0x004350e8
0x00407a98:	pushl %ebp
0x00407a99:	movl %ebp, %esp
0x00407a9b:	pushl $0xffffffff<UINT8>
0x00407a9d:	pushl $0x409190<UINT32>
0x00407aa2:	pushl $0x407a3e<UINT32>
0x00407aa7:	movl %eax, %fs:0
0x00407aad:	pushl %eax
0x00407aae:	movl %fs:0, %esp
0x00407ab5:	subl %esp, $0x68<UINT8>
0x00407ab8:	pushl %ebx
0x00407ab9:	pushl %esi
0x00407aba:	pushl %edi
0x00407abb:	movl -24(%ebp), %esp
0x00407abe:	xorl %ebx, %ebx
0x00407ac0:	movl -4(%ebp), %ebx
0x00407ac3:	pushl $0x2<UINT8>
0x00407ac5:	call __set_app_type@MSVCRT.dll
__set_app_type@MSVCRT.dll: API Node	
0x00407acb:	popl %ecx
0x00407acc:	orl 0x426a2c, $0xffffffff<UINT8>
0x00407ad3:	orl 0x426a30, $0xffffffff<UINT8>
0x00407ada:	call __p__fmode@MSVCRT.dll
__p__fmode@MSVCRT.dll: API Node	
0x00407ae0:	movl %ecx, 0x426a24
0x00407ae6:	movl (%eax), %ecx
0x00407ae8:	call __p__commode@MSVCRT.dll
__p__commode@MSVCRT.dll: API Node	
0x00407aee:	movl %ecx, 0x426a20
0x00407af4:	movl (%eax), %ecx
0x00407af6:	movl %eax, 0x408164
0x00407afb:	movl %eax, (%eax)
0x00407afd:	movl 0x426a28, %eax
0x00407b02:	call 0x00407c67
0x00407c67:	ret

0x00407b07:	cmpl 0x425d88, %ebx
0x00407b0d:	jne 0x00407b1b
0x00407b1b:	call 0x00407c4c
0x00407c4c:	pushl $0x30000<UINT32>
0x00407c51:	pushl $0x10000<UINT32>
0x00407c56:	call 0x00407c80
0x00407c80:	jmp _controlfp@MSVCRT.dll
_controlfp@MSVCRT.dll: API Node	
0x00407c5b:	popl %ecx
0x00407c5c:	popl %ecx
0x00407c5d:	ret

0x00407b20:	pushl $0x40b010<UINT32>
0x00407b25:	pushl $0x40b00c<UINT32>
0x00407b2a:	call 0x00407c46
0x00407c46:	jmp _initterm@MSVCRT.dll
_initterm@MSVCRT.dll: API Node	
0x00407b2f:	movl %eax, 0x426a1c
0x00407b34:	movl -108(%ebp), %eax
0x00407b37:	leal %eax, -108(%ebp)
0x00407b3a:	pushl %eax
0x00407b3b:	pushl 0x426a18
0x00407b41:	leal %eax, -100(%ebp)
0x00407b44:	pushl %eax
0x00407b45:	leal %eax, -112(%ebp)
0x00407b48:	pushl %eax
0x00407b49:	leal %eax, -96(%ebp)
0x00407b4c:	pushl %eax
0x00407b4d:	call __getmainargs@MSVCRT.dll
__getmainargs@MSVCRT.dll: API Node	
0x00407b53:	pushl $0x40b008<UINT32>
0x00407b58:	pushl $0x40b000<UINT32>
0x00407b5d:	call 0x00407c46
0x00407b62:	addl %esp, $0x24<UINT8>
0x00407b65:	movl %eax, 0x408174
0x00407b6a:	movl %esi, (%eax)
0x00407b6c:	movl -116(%ebp), %esi
0x00407b6f:	cmpb (%esi), $0x22<UINT8>
0x00407b72:	jne 58
0x00407b74:	incl %esi
0x00407b75:	movl -116(%ebp), %esi
0x00407b78:	movb %al, (%esi)
0x00407b7a:	cmpb %al, %bl
0x00407b7c:	je 4
0x00407b7e:	cmpb %al, $0x22<UINT8>
0x00407b80:	jne 0x00407b74
0x00407b82:	cmpb (%esi), $0x22<UINT8>
0x00407b85:	jne 4
0x00407b87:	incl %esi
0x00407b88:	movl -116(%ebp), %esi
0x00407b8b:	movb %al, (%esi)
0x00407b8d:	cmpb %al, %bl
0x00407b8f:	je 4
0x00407b91:	cmpb %al, $0x20<UINT8>
0x00407b93:	jbe 0x00407b87
0x00407b95:	movl -48(%ebp), %ebx
0x00407b98:	leal %eax, -92(%ebp)
0x00407b9b:	pushl %eax
0x00407b9c:	call GetStartupInfoA@KERNEL32.dll
GetStartupInfoA@KERNEL32.dll: API Node	
0x00407ba2:	testb -48(%ebp), $0x1<UINT8>
0x00407ba6:	je 0x00407bb9
0x00407bb9:	pushl $0xa<UINT8>
0x00407bbb:	popl %eax
0x00407bbc:	pushl %eax
0x00407bbd:	pushl %esi
0x00407bbe:	pushl %ebx
0x00407bbf:	pushl %ebx
0x00407bc0:	call GetModuleHandleA@KERNEL32.dll
GetModuleHandleA@KERNEL32.dll: API Node	
0x00407bc6:	pushl %eax
0x00407bc7:	call 0x00403f99
0x00403f99:	pushl %ebp
0x00403f9a:	movl %ebp, %esp
0x00403f9c:	subl %esp, $0x4c<UINT8>
0x00403f9f:	pushl %ebx
0x00403fa0:	pushl %esi
0x00403fa1:	pushl %edi
0x00403fa2:	pushl $0x40b34c<UINT32>
0x00403fa7:	call 0x00406899
0x00406899:	pushl %ebp
0x0040689a:	movl %ebp, %esp
0x0040689c:	subl %esp, $0x214<UINT32>
0x004068a2:	pushl %ebx
0x004068a3:	leal %eax, -532(%ebp)
0x004068a9:	pushl 0x8(%ebp)
0x004068ac:	xorl %ebx, %ebx
0x004068ae:	movl -8(%ebp), %ebx
0x004068b1:	movl -4(%ebp), %ebx
0x004068b4:	pushl $0x425c94<UINT32>
0x004068b9:	pushl %eax
0x004068ba:	call swprintf@MSVCRT.dll
swprintf@MSVCRT.dll: API Node	
0x004068c0:	addl %esp, $0xc<UINT8>
0x004068c3:	leal %eax, -8(%ebp)
0x004068c6:	pushl %eax
0x004068c7:	leal %eax, -532(%ebp)
0x004068cd:	pushl %eax
0x004068ce:	pushl $0x80000001<UINT32>
0x004068d3:	call RegCreateKeyW@ADVAPI32.dll
RegCreateKeyW@ADVAPI32.dll: API Node	
0x004068d9:	testl %eax, %eax
0x004068db:	jne 31
0x004068dd:	leal %eax, -12(%ebp)
0x004068e0:	movl -12(%ebp), $0x4<UINT32>
0x004068e7:	pushl %eax
0x004068e8:	leal %eax, -4(%ebp)
0x004068eb:	pushl %eax
0x004068ec:	pushl %ebx
0x004068ed:	pushl %ebx
0x004068ee:	pushl $0x425c78<UINT32>
0x004068f3:	pushl -8(%ebp)
0x004068f6:	call RegQueryValueExW@ADVAPI32.dll
RegQueryValueExW@ADVAPI32.dll: API Node	
0x004068fc:	cmpl -4(%ebp), %ebx
0x004068ff:	jne 481
0x00406905:	pushl %esi
0x00406906:	pushl %edi
0x00406907:	pushl $0x3e8<UINT32>
0x0040690c:	pushl $0x40<UINT8>
0x0040690e:	call LocalAlloc@KERNEL32.dll
LocalAlloc@KERNEL32.dll: API Node	
0x00406914:	movl %esi, %eax
0x00406916:	pushl $0x425c5c<UINT32>
0x0040691b:	leal %edi, 0x12(%esi)
0x0040691e:	call LoadLibraryW@KERNEL32.dll
LoadLibraryW@KERNEL32.dll: API Node	
0x00406924:	movl (%esi), $0x80c808d0<UINT32>
0x00407a3e:	jmp _except_handler3@MSVCRT.dll
_except_handler3@MSVCRT.dll: API Node	
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
0x7c90330e:	addb (%eax), %al
