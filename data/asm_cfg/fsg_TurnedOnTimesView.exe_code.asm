0x0042f000:	movl %ebx, $0x4001d0<UINT32>
0x0042f005:	movl %edi, $0x401000<UINT32>
0x0042f00a:	movl %esi, $0x421bc2<UINT32>
0x0042f00f:	pushl %ebx
0x0042f010:	call 0x0042f01f
0x0042f01f:	cld
0x0042f020:	movb %dl, $0xffffff80<UINT8>
0x0042f022:	movsb %es:(%edi), %ds:(%esi)
0x0042f023:	pushl $0x2<UINT8>
0x0042f025:	popl %ebx
0x0042f026:	call 0x0042f015
0x0042f015:	addb %dl, %dl
0x0042f017:	jne 0x0042f01e
0x0042f019:	movb %dl, (%esi)
0x0042f01b:	incl %esi
0x0042f01c:	adcb %dl, %dl
0x0042f01e:	ret

0x0042f029:	jae 0x0042f022
0x0042f02b:	xorl %ecx, %ecx
0x0042f02d:	call 0x0042f015
0x0042f030:	jae 0x0042f04a
0x0042f032:	xorl %eax, %eax
0x0042f034:	call 0x0042f015
0x0042f037:	jae 0x0042f05a
0x0042f039:	movb %bl, $0x2<UINT8>
0x0042f03b:	incl %ecx
0x0042f03c:	movb %al, $0x10<UINT8>
0x0042f03e:	call 0x0042f015
0x0042f041:	adcb %al, %al
0x0042f043:	jae 0x0042f03e
0x0042f045:	jne 0x0042f086
0x0042f086:	pushl %esi
0x0042f087:	movl %esi, %edi
0x0042f089:	subl %esi, %eax
0x0042f08b:	rep movsb %es:(%edi), %ds:(%esi)
0x0042f08d:	popl %esi
0x0042f08e:	jmp 0x0042f026
0x0042f047:	stosb %es:(%edi), %al
0x0042f048:	jmp 0x0042f026
0x0042f05a:	lodsb %al, %ds:(%esi)
0x0042f05b:	shrl %eax
0x0042f05d:	je 0x0042f0a0
0x0042f05f:	adcl %ecx, %ecx
0x0042f061:	jmp 0x0042f07f
0x0042f07f:	incl %ecx
0x0042f080:	incl %ecx
0x0042f081:	xchgl %ebp, %eax
0x0042f082:	movl %eax, %ebp
0x0042f084:	movb %bl, $0x1<UINT8>
0x0042f04a:	call 0x0042f092
0x0042f092:	incl %ecx
0x0042f093:	call 0x0042f015
0x0042f097:	adcl %ecx, %ecx
0x0042f099:	call 0x0042f015
0x0042f09d:	jb 0x0042f093
0x0042f09f:	ret

0x0042f04f:	subl %ecx, %ebx
0x0042f051:	jne 0x0042f063
0x0042f063:	xchgl %ecx, %eax
0x0042f064:	decl %eax
0x0042f065:	shll %eax, $0x8<UINT8>
0x0042f068:	lodsb %al, %ds:(%esi)
0x0042f069:	call 0x0042f090
0x0042f090:	xorl %ecx, %ecx
0x0042f06e:	cmpl %eax, $0x7d00<UINT32>
0x0042f073:	jae 0x0042f07f
0x0042f075:	cmpb %ah, $0x5<UINT8>
0x0042f078:	jae 0x0042f080
0x0042f07a:	cmpl %eax, $0x7f<UINT8>
0x0042f07d:	ja 0x0042f081
0x0042f053:	call 0x0042f090
0x0042f058:	jmp 0x0042f082
0x0042f0a0:	popl %edi
0x0042f0a1:	popl %ebx
0x0042f0a2:	movzwl %edi, (%ebx)
0x0042f0a5:	decl %edi
0x0042f0a6:	je 0x0042f0b0
0x0042f0a8:	decl %edi
0x0042f0a9:	je 0x0042f0be
0x0042f0ab:	shll %edi, $0xc<UINT8>
0x0042f0ae:	jmp 0x0042f0b7
0x0042f0b7:	incl %ebx
0x0042f0b8:	incl %ebx
0x0042f0b9:	jmp 0x0042f00f
0x0042f0b0:	movl %edi, 0x2(%ebx)
0x0042f0b3:	pushl %edi
0x0042f0b4:	addl %ebx, $0x4<UINT8>
0x0042f0be:	popl %edi
0x0042f0bf:	movl %ebx, $0x42f128<UINT32>
0x0042f0c4:	incl %edi
0x0042f0c5:	movl %esi, (%edi)
0x0042f0c7:	scasl %eax, %es:(%edi)
0x0042f0c8:	pushl %edi
0x0042f0c9:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0042f0cb:	xchgl %ebp, %eax
0x0042f0cc:	xorl %eax, %eax
0x0042f0ce:	scasb %al, %es:(%edi)
0x0042f0cf:	jne 0x0042f0ce
0x0042f0d1:	decb (%edi)
0x0042f0d3:	je 0x0042f0c4
0x0042f0d5:	decb (%edi)
0x0042f0d7:	jne 0x0042f0df
0x0042f0df:	decb (%edi)
0x0042f0e1:	je 0x0040ef42
0x0042f0e7:	pushl %edi
0x0042f0e8:	pushl %ebp
0x0042f0e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x0042f0ec:	orl (%esi), %eax
0x0042f0ee:	lodsl %eax, %ds:(%esi)
0x0042f0ef:	jne 0x0042f0cc
0x0042f0d9:	incl %edi
0x0042f0da:	pushl (%edi)
0x0042f0dc:	scasl %eax, %es:(%edi)
0x0042f0dd:	jmp 0x0042f0e8
GetProcAddress@KERNEL32.dll: API Node	
0x0040ef42:	pushl $0x70<UINT8>
0x0040ef44:	pushl $0x410400<UINT32>
0x0040ef49:	call 0x0040f150
0x0040f150:	pushl $0x40f1a0<UINT32>
0x0040f155:	movl %eax, %fs:0
0x0040f15b:	pushl %eax
0x0040f15c:	movl %fs:0, %esp
0x0040f163:	movl %eax, 0x10(%esp)
0x0040f167:	movl 0x10(%esp), %ebp
0x0040f16b:	leal %ebp, 0x10(%esp)
0x0040f16f:	subl %esp, %eax
0x0040f171:	pushl %ebx
0x0040f172:	pushl %esi
0x0040f173:	pushl %edi
0x0040f174:	movl %eax, -8(%ebp)
0x0040f177:	movl -24(%ebp), %esp
0x0040f17a:	pushl %eax
0x0040f17b:	movl %eax, -4(%ebp)
0x0040f17e:	movl -4(%ebp), $0xffffffff<UINT32>
0x0040f185:	movl -8(%ebp), %eax
0x0040f188:	ret

0x0040ef4e:	xorl %edi, %edi
0x0040ef50:	pushl %edi
0x0040ef51:	call GetModuleHandleA@KERNEL32.dll
GetModuleHandleA@KERNEL32.dll: API Node	
0x0040ef57:	cmpw (%eax), $0x5a4d<UINT16>
0x0040ef5c:	jne 31
0x0040ef5e:	movl %ecx, 0x3c(%eax)
0x0040ef61:	addl %ecx, %eax
0x0040ef63:	cmpl (%ecx), $0x4550<UINT32>
0x0040ef69:	jne 18
0x0040ef6b:	movzwl %eax, 0x18(%ecx)
0x0040ef6f:	cmpl %eax, $0x10b<UINT32>
0x0040ef74:	je 0x0040ef95
0x0040ef95:	cmpl 0x74(%ecx), $0xe<UINT8>
0x0040ef99:	jbe -30
0x0040ef9b:	xorl %eax, %eax
0x0040ef9d:	cmpl 0xe8(%ecx), %edi
0x0040efa3:	setne %al
0x0040efa6:	movl -28(%ebp), %eax
0x0040efa9:	movl -4(%ebp), %edi
0x0040efac:	pushl $0x2<UINT8>
0x0040efae:	popl %ebx
0x0040efaf:	pushl %ebx
0x0040efb0:	call __set_app_type@msvcrt.dll
__set_app_type@msvcrt.dll: API Node	
0x0040efb6:	popl %ecx
0x0040efb7:	orl 0x41728c, $0xffffffff<UINT8>
0x0040efbe:	orl 0x417290, $0xffffffff<UINT8>
0x0040efc5:	call __p__fmode@msvcrt.dll
__p__fmode@msvcrt.dll: API Node	
0x0040efcb:	movl %ecx, 0x415abc
0x0040efd1:	movl (%eax), %ecx
0x0040efd3:	call __p__commode@msvcrt.dll
__p__commode@msvcrt.dll: API Node	
0x0040efd9:	movl %ecx, 0x415ab8
0x0040efdf:	movl (%eax), %ecx
0x0040efe1:	movl %eax, 0x4102ec
0x0040efe6:	movl %eax, (%eax)
0x0040efe8:	movl 0x417288, %eax
0x0040efed:	call 0x00406d70
0x00406d70:	xorl %eax, %eax
0x00406d72:	ret

0x0040eff2:	cmpl 0x415000, %edi
0x0040eff8:	jne 0x0040f006
0x0040f006:	call 0x0040f13e
0x0040f13e:	pushl $0x30000<UINT32>
0x0040f143:	pushl $0x10000<UINT32>
0x0040f148:	call 0x0040f19a
0x0040f19a:	jmp _controlfp@msvcrt.dll
_controlfp@msvcrt.dll: API Node	
0x0040f14d:	popl %ecx
0x0040f14e:	popl %ecx
0x0040f14f:	ret

0x0040f00b:	pushl $0x4103dc<UINT32>
0x0040f010:	pushl $0x4103d8<UINT32>
0x0040f015:	call 0x0040f138
0x0040f138:	jmp _initterm@msvcrt.dll
_initterm@msvcrt.dll: API Node	
0x0040f01a:	movl %eax, 0x415ab4
0x0040f01f:	movl -32(%ebp), %eax
0x0040f022:	leal %eax, -32(%ebp)
0x0040f025:	pushl %eax
0x0040f026:	pushl 0x415ab0
0x0040f02c:	leal %eax, -36(%ebp)
0x0040f02f:	pushl %eax
0x0040f030:	leal %eax, -40(%ebp)
0x0040f033:	pushl %eax
0x0040f034:	leal %eax, -44(%ebp)
0x0040f037:	pushl %eax
0x0040f038:	call __wgetmainargs@msvcrt.dll
__wgetmainargs@msvcrt.dll: API Node	
0x0040f03e:	movl -48(%ebp), %eax
0x0040f041:	pushl $0x4103d4<UINT32>
0x0040f046:	pushl $0x4103b0<UINT32>
0x0040f04b:	call 0x0040f138
0x0040f050:	addl %esp, $0x24<UINT8>
0x0040f053:	movl %eax, 0x4102fc
0x0040f058:	movl %esi, (%eax)
0x0040f05a:	cmpl %esi, %edi
0x0040f05c:	jne 0x0040f06c
0x0040f06c:	movl -52(%ebp), %esi
0x0040f06f:	cmpw (%esi), $0x22<UINT8>
0x0040f073:	jne 69
0x0040f075:	addl %esi, %ebx
0x0040f077:	movl -52(%ebp), %esi
0x0040f07a:	movw %ax, (%esi)
0x0040f07d:	cmpw %ax, %di
0x0040f080:	je 6
0x0040f082:	cmpw %ax, $0x22<UINT16>
0x0040f086:	jne 0x0040f075
0x0040f088:	cmpw (%esi), $0x22<UINT8>
0x0040f08c:	jne 5
0x0040f08e:	addl %esi, %ebx
0x0040f090:	movl -52(%ebp), %esi
0x0040f093:	movw %ax, (%esi)
0x0040f096:	cmpw %ax, %di
0x0040f099:	je 6
0x0040f09b:	cmpw %ax, $0x20<UINT16>
0x0040f09f:	jbe 0x0040f08e
0x0040f0a1:	movl -76(%ebp), %edi
0x0040f0a4:	leal %eax, -120(%ebp)
0x0040f0a7:	pushl %eax
0x0040f0a8:	call GetStartupInfoW@KERNEL32.dll
GetStartupInfoW@KERNEL32.dll: API Node	
0x0040f0ae:	testb -76(%ebp), $0x1<UINT8>
0x0040f0b2:	je 0x0040f0c7
0x0040f0c7:	pushl $0xa<UINT8>
0x0040f0c9:	popl %eax
0x0040f0ca:	pushl %eax
0x0040f0cb:	pushl %esi
0x0040f0cc:	pushl %edi
0x0040f0cd:	pushl %edi
0x0040f0ce:	call GetModuleHandleA@KERNEL32.dll
0x0040f0d4:	pushl %eax
0x0040f0d5:	call 0x0040a231
0x0040a231:	pushl %ebp
0x0040a232:	movl %ebp, %esp
0x0040a234:	subl %esp, $0x704<UINT32>
0x0040a23a:	call 0x004022c1
0x004022c1:	pushl %ebp
0x004022c2:	movl %ebp, %esp
0x004022c4:	pushl %ecx
0x004022c5:	pushl %ecx
0x004022c6:	pushl %ebx
0x004022c7:	pushl %esi
0x004022c8:	pushl %edi
0x004022c9:	pushl $0x410700<UINT32>
0x004022ce:	movl -8(%ebp), $0x8<UINT32>
0x004022d5:	movl -4(%ebp), $0xff<UINT32>
0x004022dc:	xorl %ebx, %ebx
0x004022de:	xorl %edi, %edi
0x004022e0:	call LoadLibraryW@KERNEL32.dll
LoadLibraryW@KERNEL32.dll: API Node	
0x004022e6:	movl %esi, %eax
0x004022e8:	testl %esi, %esi
0x004022ea:	je 40
0x004022ec:	pushl $0x41071c<UINT32>
0x004022f1:	pushl %esi
0x004022f2:	call GetProcAddress@KERNEL32.dll
0x004022f8:	testl %eax, %eax
0x004022fa:	je 9
0x004022fc:	leal %ecx, -8(%ebp)
0x004022ff:	pushl %ecx
0x00402300:	incl %edi
0x00402301:	call InitCommonControlsEx@comctl32.dll
InitCommonControlsEx@comctl32.dll: API Node	
0x00402303:	movl %ebx, %eax
0x00402305:	pushl %esi
0x00402306:	call FreeLibrary@KERNEL32.dll
FreeLibrary@KERNEL32.dll: API Node	
0x0040230c:	testl %edi, %edi
0x0040230e:	je 4
0x00402310:	movl %eax, %ebx
0x00402312:	jmp 0x0040231d
0x0040231d:	testl %eax, %eax
0x0040231f:	popl %edi
0x00402320:	popl %esi
0x00402321:	popl %ebx
0x00402322:	jne 0x0040233b
0x00402324:	pushl $0x30<UINT8>
0x0040233b:	xorl %eax, %eax
0x0040233d:	incl %eax
0x0040233e:	leave
0x0040233f:	ret

0x0040a23f:	testl %eax, %eax
0x0040a241:	jne 0x0040a249
0x0040a249:	pushl %ebx
0x0040a24a:	pushl %esi
0x0040a24b:	call 0x0040b4dc
0x0040b4dc:	cmpl 0x416998, $0x0<UINT8>
0x0040b4e3:	jne 37
0x0040b4e5:	pushl $0x413080<UINT32>
0x0040b4ea:	call LoadLibraryW@KERNEL32.dll
0x0040b4f0:	testl %eax, %eax
0x0040b4f2:	movl 0x416998, %eax
0x0040b4f7:	je 17
0x0040b4f9:	pushl $0x413098<UINT32>
0x0040b4fe:	pushl %eax
0x0040b4ff:	call GetProcAddress@KERNEL32.dll
0x0040b505:	movl 0x416994, %eax
0x0040b50a:	ret

0x0040a250:	pushl $0x8001<UINT32>
0x0040a255:	call SetErrorMode@KERNEL32.dll
SetErrorMode@KERNEL32.dll: API Node	
0x0040a25b:	xorl %ebx, %ebx
0x0040a25d:	pushl %ebx
0x0040a25e:	pushl $0x40b4c1<UINT32>
0x0040a263:	pushl %ebx
0x0040a264:	movl 0x416240, $0x11223344<UINT32>
0x0040a26e:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x0040a274:	pushl %eax
0x0040a275:	call EnumResourceTypesW@KERNEL32.dll
EnumResourceTypesW@KERNEL32.dll: API Node	
0x0040a27b:	leal %eax, -52(%ebp)
0x0040a27e:	call 0x00404afe
0x00404afe:	xorl %ecx, %ecx
0x00404b00:	movl 0x14(%eax), $0x400<UINT32>
0x00404b07:	movl 0x18(%eax), $0x100<UINT32>
0x00404b0e:	movl (%eax), %ecx
0x00404b10:	movl 0x4(%eax), %ecx
0x00404b13:	movl 0xc(%eax), %ecx
0x00404b16:	movl 0x10(%eax), %ecx
0x00404b19:	movl 0x1c(%eax), %ecx
0x00404b1c:	movl 0x8(%eax), %ecx
0x00404b1f:	ret

0x0040a283:	leal %eax, -1796(%ebp)
0x0040a289:	pushl %eax
0x0040a28a:	movl -12(%ebp), $0x20<UINT32>
0x0040a291:	movl -20(%ebp), %ebx
0x0040a294:	movl -8(%ebp), %ebx
0x0040a297:	movl -16(%ebp), %ebx
0x0040a29a:	movl -4(%ebp), %ebx
0x0040a29d:	call 0x00409fd6
0x00409fd6:	pushl %ebx
0x00409fd7:	pushl %ebp
0x00409fd8:	movl %ebp, 0xc(%esp)
0x00409fdc:	pushl %esi
0x00409fdd:	pushl %edi
0x00409fde:	xorl %edi, %edi
0x00409fe0:	movl 0x208(%ebp), %edi
0x00409fe6:	movl 0x244(%ebp), %edi
0x00409fec:	movl 0x274(%ebp), %edi
0x00409ff2:	movl 0x240(%ebp), %edi
0x00409ff8:	movl (%ebp), $0x412d98<UINT32>
0x00409fff:	movl 0x694(%ebp), %edi
0x0040a005:	pushl $0x2390<UINT32>
0x0040a00a:	movl 0x6ac(%ebp), %edi
0x0040a010:	call 0x0040eed0
0x0040eed0:	jmp ??2@YAPAXI@Z@msvcrt.dll
??2@YAPAXI@Z@msvcrt.dll: API Node	
0x0040a015:	movl %esi, %eax
0x0040a017:	cmpl %esi, %edi
0x0040a019:	popl %ecx
0x0040a01a:	je 34
0x0040a01c:	leal %eax, 0x18(%esi)
0x0040a01f:	call 0x00401ab8
0x00401ab8:	xorl %ecx, %ecx
0x00401aba:	incl %ecx
0x00401abb:	xorl %edx, %edx
0x00401abd:	movl (%eax), %ecx
0x00401abf:	movw 0x4(%eax), %dx
0x00401ac3:	movw 0x104(%eax), %dx
0x00401aca:	movw 0x318(%eax), %dx
0x00401ad1:	movl 0x310(%eax), %ecx
0x00401ad7:	movl 0x314(%eax), %ecx
0x00401add:	ret

0x0040a024:	pushl $0x5c<UINT8>
0x0040a026:	leal %eax, 0x2330(%esi)
0x0040a02c:	pushl %edi
0x0040a02d:	pushl %eax
0x0040a02e:	movl 0x416244, %esi
0x0040a034:	call 0x0040eeac
0x0040eeac:	jmp memset@msvcrt.dll
memset@msvcrt.dll: API Node	
0x0040a039:	addl %esp, $0xc<UINT8>
0x0040a03c:	jmp 0x0040a040
0x0040a040:	pushl $0x2f4<UINT32>
0x0040a045:	movl 0x698(%ebp), %esi
0x0040a04b:	call 0x0040eed0
0x0040a050:	movl %esi, %eax
0x0040a052:	cmpl %esi, %edi
0x0040a054:	popl %ecx
0x0040a055:	je 13
0x0040a057:	call 0x00406062
0x00406062:	pushl %ebx
0x00406063:	pushl %edi
0x00406064:	xorl %edi, %edi
0x00406066:	pushl %esi
0x00406067:	movl %eax, $0x2f4<UINT32>
0x0040606c:	movl (%esi), $0x412ae0<UINT32>
0x00406072:	movl 0x2e0(%esi), %edi
0x00406078:	call 0x00404454
0x00404454:	addl %eax, $0xfffffffc<UINT8>
0x00404457:	pushl %eax
0x00404458:	movl %eax, 0x8(%esp)
0x0040445c:	addl %eax, $0x4<UINT8>
0x0040445f:	pushl $0x0<UINT8>
0x00404461:	pushl %eax
0x00404462:	call 0x0040eeac
0x00404467:	addl %esp, $0xc<UINT8>
0x0040446a:	ret

0x00000000:	addb (%eax), %al
0x0040f1a0:	jmp _except_handler3@msvcrt.dll
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
0x00402326:	pushl $0x410734<UINT32>
0x0040232b:	pushl $0x410740<UINT32>
0x00402330:	pushl %eax
0x00402331:	call MessageBoxW@USER32.dll
MessageBoxW@USER32.dll: API Node	
0x00402337:	xorl %eax, %eax
0x00402339:	leave
0x0040233a:	ret

0x0040a243:	incl %eax
0x0040a244:	jmp 0x0040a467
0x0040a467:	leave
0x0040a468:	ret $0x10<UINT16>

0x0040f0da:	movl %esi, %eax
0x0040f0dc:	movl -124(%ebp), %esi
0x0040f0df:	cmpl -28(%ebp), %edi
0x0040f0e2:	jne 7
0x0040f0e4:	pushl %esi
0x0040f0e5:	call exit@msvcrt.dll
exit@msvcrt.dll: Exit Node	
