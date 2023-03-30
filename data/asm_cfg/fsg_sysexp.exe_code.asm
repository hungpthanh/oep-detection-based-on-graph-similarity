0x0041d000:	movl %ebx, $0x4001d0<UINT32>
0x0041d005:	movl %edi, $0x401000<UINT32>
0x0041d00a:	movl %esi, $0x414cf2<UINT32>
0x0041d00f:	pushl %ebx
0x0041d010:	call 0x0041d01f
0x0041d01f:	cld
0x0041d020:	movb %dl, $0xffffff80<UINT8>
0x0041d022:	movsb %es:(%edi), %ds:(%esi)
0x0041d023:	pushl $0x2<UINT8>
0x0041d025:	popl %ebx
0x0041d026:	call 0x0041d015
0x0041d015:	addb %dl, %dl
0x0041d017:	jne 0x0041d01e
0x0041d019:	movb %dl, (%esi)
0x0041d01b:	incl %esi
0x0041d01c:	adcb %dl, %dl
0x0041d01e:	ret

0x0041d029:	jae 0x0041d022
0x0041d02b:	xorl %ecx, %ecx
0x0041d02d:	call 0x0041d015
0x0041d030:	jae 0x0041d04a
0x0041d032:	xorl %eax, %eax
0x0041d034:	call 0x0041d015
0x0041d037:	jae 0x0041d05a
0x0041d039:	movb %bl, $0x2<UINT8>
0x0041d03b:	incl %ecx
0x0041d03c:	movb %al, $0x10<UINT8>
0x0041d03e:	call 0x0041d015
0x0041d041:	adcb %al, %al
0x0041d043:	jae 0x0041d03e
0x0041d045:	jne 0x0041d086
0x0041d086:	pushl %esi
0x0041d087:	movl %esi, %edi
0x0041d089:	subl %esi, %eax
0x0041d08b:	rep movsb %es:(%edi), %ds:(%esi)
0x0041d08d:	popl %esi
0x0041d08e:	jmp 0x0041d026
0x0041d047:	stosb %es:(%edi), %al
0x0041d048:	jmp 0x0041d026
0x0041d05a:	lodsb %al, %ds:(%esi)
0x0041d05b:	shrl %eax
0x0041d05d:	je 0x0041d0a0
0x0041d05f:	adcl %ecx, %ecx
0x0041d061:	jmp 0x0041d07f
0x0041d07f:	incl %ecx
0x0041d080:	incl %ecx
0x0041d081:	xchgl %ebp, %eax
0x0041d082:	movl %eax, %ebp
0x0041d084:	movb %bl, $0x1<UINT8>
0x0041d04a:	call 0x0041d092
0x0041d092:	incl %ecx
0x0041d093:	call 0x0041d015
0x0041d097:	adcl %ecx, %ecx
0x0041d099:	call 0x0041d015
0x0041d09d:	jb 0x0041d093
0x0041d09f:	ret

0x0041d04f:	subl %ecx, %ebx
0x0041d051:	jne 0x0041d063
0x0041d053:	call 0x0041d090
0x0041d090:	xorl %ecx, %ecx
0x0041d058:	jmp 0x0041d082
0x0041d063:	xchgl %ecx, %eax
0x0041d064:	decl %eax
0x0041d065:	shll %eax, $0x8<UINT8>
0x0041d068:	lodsb %al, %ds:(%esi)
0x0041d069:	call 0x0041d090
0x0041d06e:	cmpl %eax, $0x7d00<UINT32>
0x0041d073:	jae 0x0041d07f
0x0041d075:	cmpb %ah, $0x5<UINT8>
0x0041d078:	jae 0x0041d080
0x0041d07a:	cmpl %eax, $0x7f<UINT8>
0x0041d07d:	ja 0x0041d081
0x0041d0a0:	popl %edi
0x0041d0a1:	popl %ebx
0x0041d0a2:	movzwl %edi, (%ebx)
0x0041d0a5:	decl %edi
0x0041d0a6:	je 0x0041d0b0
0x0041d0a8:	decl %edi
0x0041d0a9:	je 0x0041d0be
0x0041d0ab:	shll %edi, $0xc<UINT8>
0x0041d0ae:	jmp 0x0041d0b7
0x0041d0b7:	incl %ebx
0x0041d0b8:	incl %ebx
0x0041d0b9:	jmp 0x0041d00f
0x0041d0b0:	movl %edi, 0x2(%ebx)
0x0041d0b3:	pushl %edi
0x0041d0b4:	addl %ebx, $0x4<UINT8>
0x0041d0be:	popl %edi
0x0041d0bf:	movl %ebx, $0x41d128<UINT32>
0x0041d0c4:	incl %edi
0x0041d0c5:	movl %esi, (%edi)
0x0041d0c7:	scasl %eax, %es:(%edi)
0x0041d0c8:	pushl %edi
0x0041d0c9:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x0041d0cb:	xchgl %ebp, %eax
0x0041d0cc:	xorl %eax, %eax
0x0041d0ce:	scasb %al, %es:(%edi)
0x0041d0cf:	jne 0x0041d0ce
0x0041d0d1:	decb (%edi)
0x0041d0d3:	je 0x0041d0c4
0x0041d0d5:	decb (%edi)
0x0041d0d7:	jne 0x0041d0df
0x0041d0df:	decb (%edi)
0x0041d0e1:	je 0x0040acb2
0x0041d0e7:	pushl %edi
0x0041d0e8:	pushl %ebp
0x0041d0e9:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0041d0ec:	orl (%esi), %eax
0x0041d0ee:	lodsl %eax, %ds:(%esi)
0x0041d0ef:	jne 0x0041d0cc
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x0041d0d9:	incl %edi
0x0041d0da:	pushl (%edi)
0x0041d0dc:	scasl %eax, %es:(%edi)
0x0041d0dd:	jmp 0x0041d0e8
0x0040acb2:	pushl $0x70<UINT8>
0x0040acb4:	pushl $0x40b378<UINT32>
0x0040acb9:	call 0x0040aea0
0x0040aea0:	pushl $0x40aef0<UINT32>
0x0040aea5:	movl %eax, %fs:0
0x0040aeab:	pushl %eax
0x0040aeac:	movl %fs:0, %esp
0x0040aeb3:	movl %eax, 0x10(%esp)
0x0040aeb7:	movl 0x10(%esp), %ebp
0x0040aebb:	leal %ebp, 0x10(%esp)
0x0040aebf:	subl %esp, %eax
0x0040aec1:	pushl %ebx
0x0040aec2:	pushl %esi
0x0040aec3:	pushl %edi
0x0040aec4:	movl %eax, -8(%ebp)
0x0040aec7:	movl -24(%ebp), %esp
0x0040aeca:	pushl %eax
0x0040aecb:	movl %eax, -4(%ebp)
0x0040aece:	movl -4(%ebp), $0xffffffff<UINT32>
0x0040aed5:	movl -8(%ebp), %eax
0x0040aed8:	ret

0x0040acbe:	xorl %ebx, %ebx
0x0040acc0:	pushl %ebx
0x0040acc1:	movl %edi, 0x40b050
0x0040acc7:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x0040acc9:	cmpw (%eax), $0x5a4d<UINT16>
0x0040acce:	jne 31
0x0040acd0:	movl %ecx, 0x3c(%eax)
0x0040acd3:	addl %ecx, %eax
0x0040acd5:	cmpl (%ecx), $0x4550<UINT32>
0x0040acdb:	jne 18
0x0040acdd:	movzwl %eax, 0x18(%ecx)
0x0040ace1:	cmpl %eax, $0x10b<UINT32>
0x0040ace6:	je 0x0040ad07
0x0040ad07:	cmpl 0x74(%ecx), $0xe<UINT8>
0x0040ad0b:	jbe -30
0x0040ad0d:	xorl %eax, %eax
0x0040ad0f:	cmpl 0xe8(%ecx), %ebx
0x0040ad15:	setne %al
0x0040ad18:	movl -28(%ebp), %eax
0x0040ad1b:	movl -4(%ebp), %ebx
0x0040ad1e:	pushl $0x2<UINT8>
0x0040ad20:	call __set_app_type@msvcrt.dll
__set_app_type@msvcrt.dll: API Node	
0x0040ad26:	popl %ecx
0x0040ad27:	orl 0x40f298, $0xffffffff<UINT8>
0x0040ad2e:	orl 0x40f29c, $0xffffffff<UINT8>
0x0040ad35:	call __p__fmode@msvcrt.dll
__p__fmode@msvcrt.dll: API Node	
0x0040ad3b:	movl %ecx, 0x40e22c
0x0040ad41:	movl (%eax), %ecx
0x0040ad43:	call __p__commode@msvcrt.dll
__p__commode@msvcrt.dll: API Node	
0x0040ad49:	movl %ecx, 0x40e228
0x0040ad4f:	movl (%eax), %ecx
0x0040ad51:	movl %eax, 0x40b2dc
0x0040ad56:	movl %eax, (%eax)
0x0040ad58:	movl 0x40f294, %eax
0x0040ad5d:	call 0x0040ae9c
0x0040ae9c:	xorl %eax, %eax
0x0040ae9e:	ret

0x0040ad62:	cmpl 0x40e000, %ebx
0x0040ad68:	jne 0x0040ad76
0x0040ad76:	call 0x0040ae8a
0x0040ae8a:	pushl $0x30000<UINT32>
0x0040ae8f:	pushl $0x10000<UINT32>
0x0040ae94:	call 0x0040aeea
0x0040aeea:	jmp _controlfp@msvcrt.dll
_controlfp@msvcrt.dll: API Node	
0x0040ae99:	popl %ecx
0x0040ae9a:	popl %ecx
0x0040ae9b:	ret

0x0040ad7b:	pushl $0x40b370<UINT32>
0x0040ad80:	pushl $0x40b36c<UINT32>
0x0040ad85:	call 0x0040ae84
0x0040ae84:	jmp _initterm@msvcrt.dll
_initterm@msvcrt.dll: API Node	
0x0040ad8a:	movl %eax, 0x40e224
0x0040ad8f:	movl -32(%ebp), %eax
0x0040ad92:	leal %eax, -32(%ebp)
0x0040ad95:	pushl %eax
0x0040ad96:	pushl 0x40e220
0x0040ad9c:	leal %eax, -36(%ebp)
0x0040ad9f:	pushl %eax
0x0040ada0:	leal %eax, -40(%ebp)
0x0040ada3:	pushl %eax
0x0040ada4:	leal %eax, -44(%ebp)
0x0040ada7:	pushl %eax
0x0040ada8:	call __getmainargs@msvcrt.dll
__getmainargs@msvcrt.dll: API Node	
0x0040adae:	movl -48(%ebp), %eax
0x0040adb1:	pushl $0x40b368<UINT32>
0x0040adb6:	pushl $0x40b354<UINT32>
0x0040adbb:	call 0x0040ae84
0x0040adc0:	addl %esp, $0x24<UINT8>
0x0040adc3:	movl %eax, 0x40b294
0x0040adc8:	movl %esi, (%eax)
0x0040adca:	movl -52(%ebp), %esi
0x0040adcd:	cmpb (%esi), $0x22<UINT8>
0x0040add0:	jne 58
0x0040add2:	incl %esi
0x0040add3:	movl -52(%ebp), %esi
0x0040add6:	movb %al, (%esi)
0x0040add8:	cmpb %al, %bl
0x0040adda:	je 4
0x0040addc:	cmpb %al, $0x22<UINT8>
0x0040adde:	jne 0x0040add2
0x0040ade0:	cmpb (%esi), $0x22<UINT8>
0x0040ade3:	jne 4
0x0040ade5:	incl %esi
0x0040ade6:	movl -52(%ebp), %esi
0x0040ade9:	movb %al, (%esi)
0x0040adeb:	cmpb %al, %bl
0x0040aded:	je 4
0x0040adef:	cmpb %al, $0x20<UINT8>
0x0040adf1:	jbe 0x0040ade5
0x0040adf3:	movl -76(%ebp), %ebx
0x0040adf6:	leal %eax, -120(%ebp)
0x0040adf9:	pushl %eax
0x0040adfa:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x0040ae00:	testb -76(%ebp), $0x1<UINT8>
0x0040ae04:	je 0x0040ae17
0x0040ae17:	pushl $0xa<UINT8>
0x0040ae19:	popl %eax
0x0040ae1a:	pushl %eax
0x0040ae1b:	pushl %esi
0x0040ae1c:	pushl %ebx
0x0040ae1d:	pushl %ebx
0x0040ae1e:	call GetModuleHandleA@KERNEL32.DLL
0x0040ae20:	pushl %eax
0x0040ae21:	call 0x004087f2
0x004087f2:	pushl %ebp
0x004087f3:	leal %ebp, -104(%esp)
0x004087f7:	subl %esp, $0x274<UINT32>
0x004087fd:	pushl %ebx
0x004087fe:	xorl %ebx, %ebx
0x00408800:	pushl %esi
0x00408801:	leal %eax, -524(%ebp)
0x00408807:	pushl %edi
0x00408808:	pushl %eax
0x00408809:	movl %eax, $0x214<UINT32>
0x0040880e:	movl 0x38(%ebp), $0x400<UINT32>
0x00408815:	movl 0x3c(%ebp), $0x100<UINT32>
0x0040881c:	movl 0x24(%ebp), %ebx
0x0040881f:	movl 0x28(%ebp), %ebx
0x00408822:	movl 0x30(%ebp), %ebx
0x00408825:	movl 0x34(%ebp), %ebx
0x00408828:	movl 0x40(%ebp), %ebx
0x0040882b:	movl 0x2c(%ebp), %ebx
0x0040882e:	movl 0x4c(%ebp), $0x20<UINT32>
0x00408835:	movl 0x44(%ebp), %ebx
0x00408838:	movl 0x50(%ebp), %ebx
0x0040883b:	movl 0x48(%ebp), %ebx
0x0040883e:	movl 0x54(%ebp), %ebx
0x00408841:	movl -524(%ebp), $0x40bad8<UINT32>
0x0040884b:	movl -60(%ebp), %ebx
0x0040884e:	call 0x00403ee2
0x00403ee2:	addl %eax, $0xfffffffc<UINT8>
0x00403ee5:	pushl %eax
0x00403ee6:	movl %eax, 0x8(%esp)
0x00403eea:	addl %eax, $0x4<UINT8>
0x00403eed:	pushl $0x0<UINT8>
0x00403eef:	pushl %eax
0x00403ef0:	call 0x0040ac3a
0x0040ac3a:	jmp memset@msvcrt.dll
memset@msvcrt.dll: API Node	
0x00403ef5:	addl %esp, $0xc<UINT8>
0x00403ef8:	ret

0x000935ce:	subl %eax, $0x2072616a<UINT32>
0x000935d3:	boundl %esp, 0x2d(%ebp)
0x000935d6:	jo 117
0x000935d8:	insl %es:(%edi), %dx
0x000935d9:	subl %eax, $0x6a2e3276<UINT32>
0x000935de:	popa
0x000935df:	jb 32
0x000935e1:	popa
0x000935e2:	jae 0x00093651
0x00093651:	addb (%ebx), %bh
0x0040aef0:	jmp _except_handler3@msvcrt.dll
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
0x7c90330e:	addb (%eax), %al
