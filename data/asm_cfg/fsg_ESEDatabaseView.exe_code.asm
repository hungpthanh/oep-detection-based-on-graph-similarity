0x0042b000:	movl %ebx, $0x4001d0<UINT32>
0x0042b005:	movl %edi, $0x401000<UINT32>
0x0042b00a:	movl %esi, $0x41e9e2<UINT32>
0x0042b00f:	pushl %ebx
0x0042b010:	call 0x0042b01f
0x0042b01f:	cld
0x0042b020:	movb %dl, $0xffffff80<UINT8>
0x0042b022:	movsb %es:(%edi), %ds:(%esi)
0x0042b023:	pushl $0x2<UINT8>
0x0042b025:	popl %ebx
0x0042b026:	call 0x0042b015
0x0042b015:	addb %dl, %dl
0x0042b017:	jne 0x0042b01e
0x0042b019:	movb %dl, (%esi)
0x0042b01b:	incl %esi
0x0042b01c:	adcb %dl, %dl
0x0042b01e:	ret

0x0042b029:	jae 0x0042b022
0x0042b02b:	xorl %ecx, %ecx
0x0042b02d:	call 0x0042b015
0x0042b030:	jae 0x0042b04a
0x0042b032:	xorl %eax, %eax
0x0042b034:	call 0x0042b015
0x0042b037:	jae 0x0042b05a
0x0042b039:	movb %bl, $0x2<UINT8>
0x0042b03b:	incl %ecx
0x0042b03c:	movb %al, $0x10<UINT8>
0x0042b03e:	call 0x0042b015
0x0042b041:	adcb %al, %al
0x0042b043:	jae 0x0042b03e
0x0042b045:	jne 0x0042b086
0x0042b086:	pushl %esi
0x0042b087:	movl %esi, %edi
0x0042b089:	subl %esi, %eax
0x0042b08b:	rep movsb %es:(%edi), %ds:(%esi)
0x0042b08d:	popl %esi
0x0042b08e:	jmp 0x0042b026
0x0042b047:	stosb %es:(%edi), %al
0x0042b048:	jmp 0x0042b026
0x0042b05a:	lodsb %al, %ds:(%esi)
0x0042b05b:	shrl %eax
0x0042b05d:	je 0x0042b0a0
0x0042b05f:	adcl %ecx, %ecx
0x0042b061:	jmp 0x0042b07f
0x0042b07f:	incl %ecx
0x0042b080:	incl %ecx
0x0042b081:	xchgl %ebp, %eax
0x0042b082:	movl %eax, %ebp
0x0042b084:	movb %bl, $0x1<UINT8>
0x0042b04a:	call 0x0042b092
0x0042b092:	incl %ecx
0x0042b093:	call 0x0042b015
0x0042b097:	adcl %ecx, %ecx
0x0042b099:	call 0x0042b015
0x0042b09d:	jb 0x0042b093
0x0042b09f:	ret

0x0042b04f:	subl %ecx, %ebx
0x0042b051:	jne 0x0042b063
0x0042b063:	xchgl %ecx, %eax
0x0042b064:	decl %eax
0x0042b065:	shll %eax, $0x8<UINT8>
0x0042b068:	lodsb %al, %ds:(%esi)
0x0042b069:	call 0x0042b090
0x0042b090:	xorl %ecx, %ecx
0x0042b06e:	cmpl %eax, $0x7d00<UINT32>
0x0042b073:	jae 0x0042b07f
0x0042b075:	cmpb %ah, $0x5<UINT8>
0x0042b078:	jae 0x0042b080
0x0042b07a:	cmpl %eax, $0x7f<UINT8>
0x0042b07d:	ja 0x0042b081
0x0042b053:	call 0x0042b090
0x0042b058:	jmp 0x0042b082
0x0042b0a0:	popl %edi
0x0042b0a1:	popl %ebx
0x0042b0a2:	movzwl %edi, (%ebx)
0x0042b0a5:	decl %edi
0x0042b0a6:	je 0x0042b0b0
0x0042b0a8:	decl %edi
0x0042b0a9:	je 0x0042b0be
0x0042b0ab:	shll %edi, $0xc<UINT8>
0x0042b0ae:	jmp 0x0042b0b7
0x0042b0b7:	incl %ebx
0x0042b0b8:	incl %ebx
0x0042b0b9:	jmp 0x0042b00f
0x0042b0b0:	movl %edi, 0x2(%ebx)
0x0042b0b3:	pushl %edi
0x0042b0b4:	addl %ebx, $0x4<UINT8>
0x0042b0be:	popl %edi
0x0042b0bf:	movl %ebx, $0x42b128<UINT32>
0x0042b0c4:	incl %edi
0x0042b0c5:	movl %esi, (%edi)
0x0042b0c7:	scasl %eax, %es:(%edi)
0x0042b0c8:	pushl %edi
0x0042b0c9:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0042b0cb:	xchgl %ebp, %eax
0x0042b0cc:	xorl %eax, %eax
0x0042b0ce:	scasb %al, %es:(%edi)
0x0042b0cf:	jne 0x0042b0ce
0x0042b0d1:	decb (%edi)
0x0042b0d3:	je 0x0042b0c4
0x0042b0d5:	decb (%edi)
0x0042b0d7:	jne 0x0042b0df
0x0042b0df:	decb (%edi)
0x0042b0e1:	je 0x0040feea
0x0042b0e7:	pushl %edi
0x0042b0e8:	pushl %ebp
0x0042b0e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x0042b0ec:	orl (%esi), %eax
0x0042b0ee:	lodsl %eax, %ds:(%esi)
0x0042b0ef:	jne 0x0042b0cc
0x0042b0d9:	incl %edi
0x0042b0da:	pushl (%edi)
0x0042b0dc:	scasl %eax, %es:(%edi)
0x0042b0dd:	jmp 0x0042b0e8
GetProcAddress@KERNEL32.dll: API Node	
0x0040feea:	pushl $0x70<UINT8>
0x0040feec:	pushl $0x411440<UINT32>
0x0040fef1:	call 0x004100f8
0x004100f8:	pushl $0x410148<UINT32>
0x004100fd:	movl %eax, %fs:0
0x00410103:	pushl %eax
0x00410104:	movl %fs:0, %esp
0x0041010b:	movl %eax, 0x10(%esp)
0x0041010f:	movl 0x10(%esp), %ebp
0x00410113:	leal %ebp, 0x10(%esp)
0x00410117:	subl %esp, %eax
0x00410119:	pushl %ebx
0x0041011a:	pushl %esi
0x0041011b:	pushl %edi
0x0041011c:	movl %eax, -8(%ebp)
0x0041011f:	movl -24(%ebp), %esp
0x00410122:	pushl %eax
0x00410123:	movl %eax, -4(%ebp)
0x00410126:	movl -4(%ebp), $0xffffffff<UINT32>
0x0041012d:	movl -8(%ebp), %eax
0x00410130:	ret

0x0040fef6:	xorl %edi, %edi
0x0040fef8:	pushl %edi
0x0040fef9:	call GetModuleHandleA@KERNEL32.dll
GetModuleHandleA@KERNEL32.dll: API Node	
0x0040feff:	cmpw (%eax), $0x5a4d<UINT16>
0x0040ff04:	jne 31
0x0040ff06:	movl %ecx, 0x3c(%eax)
0x0040ff09:	addl %ecx, %eax
0x0040ff0b:	cmpl (%ecx), $0x4550<UINT32>
0x0040ff11:	jne 18
0x0040ff13:	movzwl %eax, 0x18(%ecx)
0x0040ff17:	cmpl %eax, $0x10b<UINT32>
0x0040ff1c:	je 0x0040ff3d
0x0040ff3d:	cmpl 0x74(%ecx), $0xe<UINT8>
0x0040ff41:	jbe -30
0x0040ff43:	xorl %eax, %eax
0x0040ff45:	cmpl 0xe8(%ecx), %edi
0x0040ff4b:	setne %al
0x0040ff4e:	movl -28(%ebp), %eax
0x0040ff51:	movl -4(%ebp), %edi
0x0040ff54:	pushl $0x2<UINT8>
0x0040ff56:	popl %ebx
0x0040ff57:	pushl %ebx
0x0040ff58:	call __set_app_type@msvcrt.dll
__set_app_type@msvcrt.dll: API Node	
0x0040ff5e:	popl %ecx
0x0040ff5f:	orl 0x416548, $0xffffffff<UINT8>
0x0040ff66:	orl 0x41654c, $0xffffffff<UINT8>
0x0040ff6d:	call __p__fmode@msvcrt.dll
__p__fmode@msvcrt.dll: API Node	
0x0040ff73:	movl %ecx, 0x4151cc
0x0040ff79:	movl (%eax), %ecx
0x0040ff7b:	call __p__commode@msvcrt.dll
__p__commode@msvcrt.dll: API Node	
0x0040ff81:	movl %ecx, 0x4151c8
0x0040ff87:	movl (%eax), %ecx
0x0040ff89:	movl %eax, 0x41132c
0x0040ff8e:	movl %eax, (%eax)
0x0040ff90:	movl 0x416544, %eax
0x0040ff95:	call 0x00408973
0x00408973:	xorl %eax, %eax
0x00408975:	ret

0x0040ff9a:	cmpl 0x415000, %edi
0x0040ffa0:	jne 0x0040ffae
0x0040ffae:	call 0x004100e6
0x004100e6:	pushl $0x30000<UINT32>
0x004100eb:	pushl $0x10000<UINT32>
0x004100f0:	call 0x00410142
0x00410142:	jmp _controlfp@msvcrt.dll
_controlfp@msvcrt.dll: API Node	
0x004100f5:	popl %ecx
0x004100f6:	popl %ecx
0x004100f7:	ret

0x0040ffb3:	pushl $0x411414<UINT32>
0x0040ffb8:	pushl $0x411410<UINT32>
0x0040ffbd:	call 0x004100e0
0x004100e0:	jmp _initterm@msvcrt.dll
_initterm@msvcrt.dll: API Node	
0x0040ffc2:	movl %eax, 0x4151c4
0x0040ffc7:	movl -32(%ebp), %eax
0x0040ffca:	leal %eax, -32(%ebp)
0x0040ffcd:	pushl %eax
0x0040ffce:	pushl 0x4151c0
0x0040ffd4:	leal %eax, -36(%ebp)
0x0040ffd7:	pushl %eax
0x0040ffd8:	leal %eax, -40(%ebp)
0x0040ffdb:	pushl %eax
0x0040ffdc:	leal %eax, -44(%ebp)
0x0040ffdf:	pushl %eax
0x0040ffe0:	call __wgetmainargs@msvcrt.dll
__wgetmainargs@msvcrt.dll: API Node	
0x0040ffe6:	movl -48(%ebp), %eax
0x0040ffe9:	pushl $0x41140c<UINT32>
0x0040ffee:	pushl $0x4113e4<UINT32>
0x0040fff3:	call 0x004100e0
0x0040fff8:	addl %esp, $0x24<UINT8>
0x0040fffb:	movl %eax, 0x41133c
0x00410000:	movl %esi, (%eax)
0x00410002:	cmpl %esi, %edi
0x00410004:	jne 0x00410014
0x00410014:	movl -52(%ebp), %esi
0x00410017:	cmpw (%esi), $0x22<UINT8>
0x0041001b:	jne 69
0x0041001d:	addl %esi, %ebx
0x0041001f:	movl -52(%ebp), %esi
0x00410022:	movw %ax, (%esi)
0x00410025:	cmpw %ax, %di
0x00410028:	je 6
0x0041002a:	cmpw %ax, $0x22<UINT16>
0x0041002e:	jne 0x0041001d
0x00410030:	cmpw (%esi), $0x22<UINT8>
0x00410034:	jne 5
0x00410036:	addl %esi, %ebx
0x00410038:	movl -52(%ebp), %esi
0x0041003b:	movw %ax, (%esi)
0x0041003e:	cmpw %ax, %di
0x00410041:	je 6
0x00410043:	cmpw %ax, $0x20<UINT16>
0x00410047:	jbe 0x00410036
0x00410049:	movl -76(%edx), %ecx
0x00410148:	jmp _except_handler3@msvcrt.dll
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
