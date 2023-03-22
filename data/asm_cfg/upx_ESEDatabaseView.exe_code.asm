0x0041e060:	pusha
0x0041e061:	movl %esi, $0x413000<UINT32>
0x0041e066:	leal %edi, -73728(%esi)
0x0041e06c:	pushl %edi
0x0041e06d:	orl %ebp, $0xffffffff<UINT8>
0x0041e070:	jmp 0x0041e082
0x0041e082:	movl %ebx, (%esi)
0x0041e084:	subl %esi, $0xfffffffc<UINT8>
0x0041e087:	adcl %ebx, %ebx
0x0041e089:	jb 0x0041e078
0x0041e078:	movb %al, (%esi)
0x0041e07a:	incl %esi
0x0041e07b:	movb (%edi), %al
0x0041e07d:	incl %edi
0x0041e07e:	addl %ebx, %ebx
0x0041e080:	jne 0x0041e089
0x0041e08b:	movl %eax, $0x1<UINT32>
0x0041e090:	addl %ebx, %ebx
0x0041e092:	jne 0x0041e09b
0x0041e09b:	adcl %eax, %eax
0x0041e09d:	addl %ebx, %ebx
0x0041e09f:	jae 0x0041e090
0x0041e0a1:	jne 0x0041e0ac
0x0041e0ac:	xorl %ecx, %ecx
0x0041e0ae:	subl %eax, $0x3<UINT8>
0x0041e0b1:	jb 0x0041e0c0
0x0041e0c0:	addl %ebx, %ebx
0x0041e0c2:	jne 0x0041e0cb
0x0041e0cb:	adcl %ecx, %ecx
0x0041e0cd:	addl %ebx, %ebx
0x0041e0cf:	jne 0x0041e0d8
0x0041e0d8:	adcl %ecx, %ecx
0x0041e0da:	jne 0x0041e0fc
0x0041e0fc:	cmpl %ebp, $0xfffff300<UINT32>
0x0041e102:	adcl %ecx, $0x1<UINT8>
0x0041e105:	leal %edx, (%edi,%ebp)
0x0041e108:	cmpl %ebp, $0xfffffffc<UINT8>
0x0041e10b:	jbe 0x0041e11c
0x0041e10d:	movb %al, (%edx)
0x0041e10f:	incl %edx
0x0041e110:	movb (%edi), %al
0x0041e112:	incl %edi
0x0041e113:	decl %ecx
0x0041e114:	jne 0x0041e10d
0x0041e116:	jmp 0x0041e07e
0x0041e0b3:	shll %eax, $0x8<UINT8>
0x0041e0b6:	movb %al, (%esi)
0x0041e0b8:	incl %esi
0x0041e0b9:	xorl %eax, $0xffffffff<UINT8>
0x0041e0bc:	je 0x0041e132
0x0041e0be:	movl %ebp, %eax
0x0041e11c:	movl %eax, (%edx)
0x0041e11e:	addl %edx, $0x4<UINT8>
0x0041e121:	movl (%edi), %eax
0x0041e123:	addl %edi, $0x4<UINT8>
0x0041e126:	subl %ecx, $0x4<UINT8>
0x0041e129:	ja 0x0041e11c
0x0041e12b:	addl %edi, %ecx
0x0041e12d:	jmp 0x0041e07e
0x0041e094:	movl %ebx, (%esi)
0x0041e096:	subl %esi, $0xfffffffc<UINT8>
0x0041e099:	adcl %ebx, %ebx
0x0041e0a3:	movl %ebx, (%esi)
0x0041e0a5:	subl %esi, $0xfffffffc<UINT8>
0x0041e0a8:	adcl %ebx, %ebx
0x0041e0aa:	jae 0x0041e090
0x0041e0d1:	movl %ebx, (%esi)
0x0041e0d3:	subl %esi, $0xfffffffc<UINT8>
0x0041e0d6:	adcl %ebx, %ebx
0x0041e0dc:	incl %ecx
0x0041e0dd:	addl %ebx, %ebx
0x0041e0df:	jne 0x0041e0e8
0x0041e0e8:	adcl %ecx, %ecx
0x0041e0ea:	addl %ebx, %ebx
0x0041e0ec:	jae 0x0041e0dd
0x0041e0ee:	jne 0x0041e0f9
0x0041e0f9:	addl %ecx, $0x2<UINT8>
0x0041e0e1:	movl %ebx, (%esi)
0x0041e0e3:	subl %esi, $0xfffffffc<UINT8>
0x0041e0e6:	adcl %ebx, %ebx
0x0041e0f0:	movl %ebx, (%esi)
0x0041e0f2:	subl %esi, $0xfffffffc<UINT8>
0x0041e0f5:	adcl %ebx, %ebx
0x0041e0f7:	jae 0x0041e0dd
0x0041e0c4:	movl %ebx, (%esi)
0x0041e0c6:	subl %esi, $0xfffffffc<UINT8>
0x0041e0c9:	adcl %ebx, %ebx
0x0041e132:	popl %esi
0x0041e133:	movl %edi, %esi
0x0041e135:	movl %ecx, $0x655<UINT32>
0x0041e13a:	movb %al, (%edi)
0x0041e13c:	incl %edi
0x0041e13d:	subb %al, $0xffffffe8<UINT8>
0x0041e13f:	cmpb %al, $0x1<UINT8>
0x0041e141:	ja 0x0041e13a
0x0041e143:	cmpb (%edi), $0x1<UINT8>
0x0041e146:	jne 0x0041e13a
0x0041e148:	movl %eax, (%edi)
0x0041e14a:	movb %bl, 0x4(%edi)
0x0041e14d:	shrw %ax, $0x8<UINT8>
0x0041e151:	roll %eax, $0x10<UINT8>
0x0041e154:	xchgb %ah, %al
0x0041e156:	subl %eax, %edi
0x0041e158:	subb %bl, $0xffffffe8<UINT8>
0x0041e15b:	addl %eax, %esi
0x0041e15d:	movl (%edi), %eax
0x0041e15f:	addl %edi, $0x5<UINT8>
0x0041e162:	movb %al, %bl
0x0041e164:	loop 0x0041e13f
0x0041e166:	leal %edi, 0x1c000(%esi)
0x0041e16c:	movl %eax, (%edi)
0x0041e16e:	orl %eax, %eax
0x0041e170:	je 0x0041e1b7
0x0041e172:	movl %ebx, 0x4(%edi)
0x0041e175:	leal %eax, 0x20028(%eax,%esi)
0x0041e17c:	addl %ebx, %esi
0x0041e17e:	pushl %eax
0x0041e17f:	addl %edi, $0x8<UINT8>
0x0041e182:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0041e188:	xchgl %ebp, %eax
0x0041e189:	movb %al, (%edi)
0x0041e18b:	incl %edi
0x0041e18c:	orb %al, %al
0x0041e18e:	je 0x0041e16c
0x0041e190:	movl %ecx, %edi
0x0041e192:	jns 0x0041e19b
0x0041e19b:	pushl %edi
0x0041e19c:	decl %eax
0x0041e19d:	repn scasb %al, %es:(%edi)
0x0041e19f:	pushl %ebp
0x0041e1a0:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0041e1a6:	orl %eax, %eax
0x0041e1a8:	je 7
0x0041e1aa:	movl (%ebx), %eax
0x0041e1ac:	addl %ebx, $0x4<UINT8>
0x0041e1af:	jmp 0x0041e189
GetProcAddress@KERNEL32.DLL: API Node	
0x0041e194:	movzwl %eax, (%edi)
0x0041e197:	incl %edi
0x0041e198:	pushl %eax
0x0041e199:	incl %edi
0x0041e19a:	movl %ecx, $0xaef24857<UINT32>
0x0041e1b7:	movl %ebp, 0x20130(%esi)
0x0041e1bd:	leal %edi, -4096(%esi)
0x0041e1c3:	movl %ebx, $0x1000<UINT32>
0x0041e1c8:	pushl %eax
0x0041e1c9:	pushl %esp
0x0041e1ca:	pushl $0x4<UINT8>
0x0041e1cc:	pushl %ebx
0x0041e1cd:	pushl %edi
0x0041e1ce:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0041e1d0:	leal %eax, 0x207(%edi)
0x0041e1d6:	andb (%eax), $0x7f<UINT8>
0x0041e1d9:	andb 0x28(%eax), $0x7f<UINT8>
0x0041e1dd:	popl %eax
0x0041e1de:	pushl %eax
0x0041e1df:	pushl %esp
0x0041e1e0:	pushl %eax
0x0041e1e1:	pushl %ebx
0x0041e1e2:	pushl %edi
0x0041e1e3:	call VirtualProtect@kernel32.dll
0x0041e1e5:	popl %eax
0x0041e1e6:	popa
0x0041e1e7:	leal %eax, -128(%esp)
0x0041e1eb:	pushl $0x0<UINT8>
0x0041e1ed:	cmpl %esp, %eax
0x0041e1ef:	jne 0x0041e1eb
0x0041e1f1:	subl %esp, $0xffffff80<UINT8>
0x0041e1f4:	jmp 0x0040feea
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
0x0040fef9:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
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
