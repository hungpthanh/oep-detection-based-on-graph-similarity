0x0042e000:	movl %ebx, $0x4001d0<UINT32>
0x0042e005:	movl %edi, $0x401000<UINT32>
0x0042e00a:	movl %esi, $0x421001<UINT32>
0x0042e00f:	pushl %ebx
0x0042e010:	call 0x0042e01f
0x0042e01f:	cld
0x0042e020:	movb %dl, $0xffffff80<UINT8>
0x0042e022:	movsb %es:(%edi), %ds:(%esi)
0x0042e023:	pushl $0x2<UINT8>
0x0042e025:	popl %ebx
0x0042e026:	call 0x0042e015
0x0042e015:	addb %dl, %dl
0x0042e017:	jne 0x0042e01e
0x0042e019:	movb %dl, (%esi)
0x0042e01b:	incl %esi
0x0042e01c:	adcb %dl, %dl
0x0042e01e:	ret

0x0042e029:	jae 0x0042e022
0x0042e02b:	xorl %ecx, %ecx
0x0042e02d:	call 0x0042e015
0x0042e030:	jae 0x0042e04a
0x0042e032:	xorl %eax, %eax
0x0042e034:	call 0x0042e015
0x0042e037:	jae 0x0042e05a
0x0042e039:	movb %bl, $0x2<UINT8>
0x0042e03b:	incl %ecx
0x0042e03c:	movb %al, $0x10<UINT8>
0x0042e03e:	call 0x0042e015
0x0042e041:	adcb %al, %al
0x0042e043:	jae 0x0042e03e
0x0042e045:	jne 0x0042e086
0x0042e086:	pushl %esi
0x0042e087:	movl %esi, %edi
0x0042e089:	subl %esi, %eax
0x0042e08b:	rep movsb %es:(%edi), %ds:(%esi)
0x0042e08d:	popl %esi
0x0042e08e:	jmp 0x0042e026
0x0042e047:	stosb %es:(%edi), %al
0x0042e048:	jmp 0x0042e026
0x0042e05a:	lodsb %al, %ds:(%esi)
0x0042e05b:	shrl %eax
0x0042e05d:	je 0x0042e0a0
0x0042e05f:	adcl %ecx, %ecx
0x0042e061:	jmp 0x0042e07f
0x0042e07f:	incl %ecx
0x0042e080:	incl %ecx
0x0042e081:	xchgl %ebp, %eax
0x0042e082:	movl %eax, %ebp
0x0042e084:	movb %bl, $0x1<UINT8>
0x0042e04a:	call 0x0042e092
0x0042e092:	incl %ecx
0x0042e093:	call 0x0042e015
0x0042e097:	adcl %ecx, %ecx
0x0042e099:	call 0x0042e015
0x0042e09d:	jb 0x0042e093
0x0042e09f:	ret

0x0042e04f:	subl %ecx, %ebx
0x0042e051:	jne 0x0042e063
0x0042e053:	call 0x0042e090
0x0042e090:	xorl %ecx, %ecx
0x0042e058:	jmp 0x0042e082
0x0042e063:	xchgl %ecx, %eax
0x0042e064:	decl %eax
0x0042e065:	shll %eax, $0x8<UINT8>
0x0042e068:	lodsb %al, %ds:(%esi)
0x0042e069:	call 0x0042e090
0x0042e06e:	cmpl %eax, $0x7d00<UINT32>
0x0042e073:	jae 0x0042e07f
0x0042e075:	cmpb %ah, $0x5<UINT8>
0x0042e078:	jae 0x0042e080
0x0042e07a:	cmpl %eax, $0x7f<UINT8>
0x0042e07d:	ja 0x0042e081
0x0042e0a0:	popl %edi
0x0042e0a1:	popl %ebx
0x0042e0a2:	movzwl %edi, (%ebx)
0x0042e0a5:	decl %edi
0x0042e0a6:	je 0x0042e0b0
0x0042e0a8:	decl %edi
0x0042e0a9:	je 0x0042e0be
0x0042e0ab:	shll %edi, $0xc<UINT8>
0x0042e0ae:	jmp 0x0042e0b7
0x0042e0b7:	incl %ebx
0x0042e0b8:	incl %ebx
0x0042e0b9:	jmp 0x0042e00f
0x0042e0b0:	movl %edi, 0x2(%ebx)
0x0042e0b3:	pushl %edi
0x0042e0b4:	addl %ebx, $0x4<UINT8>
0x0042e0be:	popl %edi
0x0042e0bf:	movl %ebx, $0x42e128<UINT32>
0x0042e0c4:	incl %edi
0x0042e0c5:	movl %esi, (%edi)
0x0042e0c7:	scasl %eax, %es:(%edi)
0x0042e0c8:	pushl %edi
0x0042e0c9:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0042e0cb:	xchgl %ebp, %eax
0x0042e0cc:	xorl %eax, %eax
0x0042e0ce:	scasb %al, %es:(%edi)
0x0042e0cf:	jne 0x0042e0ce
0x0042e0d1:	decb (%edi)
0x0042e0d3:	je 0x0042e0c4
0x0042e0d5:	decb (%edi)
0x0042e0d7:	jne 0x0042e0df
0x0042e0df:	decb (%edi)
0x0042e0e1:	je 0x00411228
0x0042e0e7:	pushl %edi
0x0042e0e8:	pushl %ebp
0x0042e0e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x0042e0ec:	orl (%esi), %eax
0x0042e0ee:	lodsl %eax, %ds:(%esi)
0x0042e0ef:	jne 0x0042e0cc
0x0042e0d9:	incl %edi
0x0042e0da:	pushl (%edi)
0x0042e0dc:	scasl %eax, %es:(%edi)
0x0042e0dd:	jmp 0x0042e0e8
GetProcAddress@KERNEL32.dll: API Node	
0x00411228:	pushl $0x70<UINT8>
0x0041122a:	pushl $0x412450<UINT32>
0x0041122f:	call 0x00411438
0x00411438:	pushl $0x411488<UINT32>
0x0041143d:	movl %eax, %fs:0
0x00411443:	pushl %eax
0x00411444:	movl %fs:0, %esp
0x0041144b:	movl %eax, 0x10(%esp)
0x0041144f:	movl 0x10(%esp), %ebp
0x00411453:	leal %ebp, 0x10(%esp)
0x00411457:	subl %esp, %eax
0x00411459:	pushl %ebx
0x0041145a:	pushl %esi
0x0041145b:	pushl %edi
0x0041145c:	movl %eax, -8(%ebp)
0x0041145f:	movl -24(%ebp), %esp
0x00411462:	pushl %eax
0x00411463:	movl %eax, -4(%ebp)
0x00411466:	movl -4(%ebp), $0xffffffff<UINT32>
0x0041146d:	movl -8(%ebp), %eax
0x00411470:	ret

0x00411234:	xorl %edi, %edi
0x00411236:	pushl %edi
0x00411237:	call GetModuleHandleA@KERNEL32.dll
GetModuleHandleA@KERNEL32.dll: API Node	
0x0041123d:	cmpw (%eax), $0x5a4d<UINT16>
0x00411242:	jne 31
0x00411244:	movl %ecx, 0x3c(%eax)
0x00411247:	addl %ecx, %eax
0x00411249:	cmpl (%ecx), $0x4550<UINT32>
0x0041124f:	jne 18
0x00411251:	movzwl %eax, 0x18(%ecx)
0x00411255:	cmpl %eax, $0x10b<UINT32>
0x0041125a:	je 0x0041127b
0x0041127b:	cmpl 0x74(%ecx), $0xe<UINT8>
0x0041127f:	jbe -30
0x00411281:	xorl %eax, %eax
0x00411283:	cmpl 0xe8(%ecx), %edi
0x00411289:	setne %al
0x0041128c:	movl -28(%ebp), %eax
0x0041128f:	movl -4(%ebp), %edi
0x00411292:	pushl $0x2<UINT8>
0x00411294:	popl %ebx
0x00411295:	pushl %ebx
0x00411296:	call __set_app_type@msvcrt.dll
__set_app_type@msvcrt.dll: API Node	
0x0041129c:	popl %ecx
0x0041129d:	orl 0x4178c0, $0xffffffff<UINT8>
0x004112a4:	orl 0x4178c4, $0xffffffff<UINT8>
0x004112ab:	call __p__fmode@msvcrt.dll
__p__fmode@msvcrt.dll: API Node	
0x004112b1:	movl %ecx, 0x4164fc
0x004112b7:	movl (%eax), %ecx
0x004112b9:	call __p__commode@msvcrt.dll
__p__commode@msvcrt.dll: API Node	
0x004112bf:	movl %ecx, 0x4164f8
0x004112c5:	movl (%eax), %ecx
0x004112c7:	movl %eax, 0x412314
0x004112cc:	movl %eax, (%eax)
0x004112ce:	movl 0x4178bc, %eax
0x004112d3:	call 0x00410415
0x00410415:	xorl %eax, %eax
0x00410417:	ret

0x004112d8:	cmpl 0x416000, %edi
0x004112de:	jne 0x004112ec
0x004112ec:	call 0x00411424
0x00411424:	pushl $0x30000<UINT32>
0x00411429:	pushl $0x10000<UINT32>
0x0041142e:	call 0x00411482
0x00411482:	jmp _controlfp@msvcrt.dll
_controlfp@msvcrt.dll: API Node	
0x00411433:	popl %ecx
0x00411434:	popl %ecx
0x00411435:	ret

0x004112f1:	pushl $0x412428<UINT32>
0x004112f6:	pushl $0x412424<UINT32>
0x004112fb:	call 0x0041141e
0x0041141e:	jmp _initterm@msvcrt.dll
_initterm@msvcrt.dll: API Node	
0x00411300:	movl %eax, 0x4164f4
0x00411305:	movl -32(%ebp), %eax
0x00411308:	leal %eax, -32(%ebp)
0x0041130b:	pushl %eax
0x0041130c:	pushl 0x4164f0
0x00411312:	leal %eax, -36(%ebp)
0x00411315:	pushl %eax
0x00411316:	leal %eax, -40(%ebp)
0x00411319:	pushl %eax
0x0041131a:	leal %eax, -44(%ebp)
0x0041131d:	pushl %eax
0x0041131e:	call __wgetmainargs@msvcrt.dll
__wgetmainargs@msvcrt.dll: API Node	
0x00411324:	movl -48(%ebp), %eax
0x00411327:	pushl $0x412420<UINT32>
0x0041132c:	pushl $0x4123d0<UINT32>
0x00411331:	call 0x0041141e
0x00411336:	addl %esp, $0x24<UINT8>
0x00411339:	movl %eax, 0x412324
0x0041133e:	movl %esi, (%eax)
0x00411340:	cmpl %esi, %edi
0x00411342:	jne 0x00411352
0x00411352:	movl -52(%ebp), %esi
0x00411355:	cmpw (%esi), $0x22<UINT8>
0x00411359:	jne 69
0x0041135b:	addl %esi, %ebx
0x0041135d:	movl -52(%ebp), %esi
0x00411360:	movw %ax, (%esi)
0x00411363:	cmpw %ax, %di
0x00411366:	je 6
0x00411368:	cmpw %ax, $0x22<UINT16>
0x0041136c:	jne 0x0041135b
0x0041136e:	cmpw (%esi), $0x22<UINT8>
0x00411372:	jne 5
0x00411374:	addl %esi, %ebx
0x00411376:	movl -52(%ebp), %esi
0x00411379:	movw %ax, (%esi)
0x0041137c:	cmpw %ax, %di
0x0041137f:	je 6
0x00411381:	cmpw %ax, $0x20<UINT16>
0x00411385:	jbe 0x00411374
0x00411387:	movl -76(%ebp), %edi
0x0041138a:	leal %eax, -120(%ebp)
0x0041138d:	pushl %eax
0x0041138e:	call GetStartupInfoW@KERNEL32.dll
GetStartupInfoW@KERNEL32.dll: API Node	
0x00411394:	testb -76(%ebp), $0x1<UINT8>
0x00411398:	je 0x004113ad
0x004113ad:	pushl $0xa<UINT8>
0x004113af:	popl %eax
0x004113b0:	pushl %eax
0x004113b1:	pushl %esi
0x004113b2:	pushl %edi
0x004113b3:	pushl %edi
0x004113b4:	call GetModuleHandleA@KERNEL32.dll
0x004113ba:	pushl %eax
0x004113bb:	call 0x0040ce4b
0x0040ce4b:	pushl %ebp
0x0040ce4c:	movl %ebp, %esp
0x0040ce4e:	movl %eax, $0x2888<UINT32>
0x0040ce53:	call 0x004114b0
0x004114b0:	cmpl %eax, $0x1000<UINT32>
0x004114b5:	jae 0x004114c5
0x004114c5:	pushl %ecx
0x004114c6:	leal %ecx, 0x8(%esp)
0x004114ca:	subl %ecx, $0x1000<UINT32>
0x004114d0:	subl %eax, $0x1000<UINT32>
0x004114d5:	testl (%ecx), %eax
0x004114d7:	cmpl %eax, $0x1000<UINT32>
0x004114dc:	jae 0x004114ca
0x004114de:	subl %ecx, %eax
0x004114e0:	movl %eax, %esp
0x004114e2:	testl (%ecx), %eax
0x004114e4:	movl %esp, %ecx
0x004114e6:	movl %ecx, (%eax)
0x004114e8:	movl %eax, 0x4(%eax)
0x004114eb:	pushl %eax
0x004114ec:	ret

0x0040ce58:	call 0x00403163
0x00403163:	pushl %ebp
0x00403164:	movl %ebp, %esp
0x00403166:	pushl %ecx
0x00403167:	pushl %ecx
0x00403168:	pushl %ebx
0x00403169:	pushl %esi
0x0040316a:	pushl %edi
0x0040316b:	pushl $0x4129ec<UINT32>
0x00403170:	movl -8(%ebp), $0x8<UINT32>
0x00403177:	movl -4(%ebp), $0xff<UINT32>
0x0040317e:	xorl %ebx, %ebx
0x00403180:	xorl %edi, %edi
0x00403182:	call LoadLibraryW@KERNEL32.dll
LoadLibraryW@KERNEL32.dll: API Node	
0x00403188:	movl %esi, %eax
0x0040318a:	testl %esi, %esi
0x0040318c:	je 40
0x0040318e:	pushl $0x412b08<UINT32>
0x00403193:	pushl %esi
0x00403194:	call GetProcAddress@KERNEL32.dll
0x0040319a:	testl %eax, %eax
0x0040319c:	je 9
0x0040319e:	leal %ecx, -8(%ebp)
0x004031a1:	pushl %ecx
0x004031a2:	incl %edi
0x004031a3:	call InitCommonControlsEx@comctl32.dll
InitCommonControlsEx@comctl32.dll: API Node	
0x004031a5:	movl %ebx, %eax
0x004031a7:	pushl %esi
0x004031a8:	call FreeLibrary@KERNEL32.dll
FreeLibrary@KERNEL32.dll: API Node	
0x004031ae:	testl %edi, %edi
0x004031b0:	je 4
0x004031b2:	movl %eax, %ebx
0x004031b4:	jmp 0x004031bf
0x004031bf:	testl %eax, %eax
0x004031c1:	popl %edi
0x004031c2:	popl %esi
0x004031c3:	popl %ebx
0x004031c4:	jne 0x004031dd
0x004031c6:	pushl $0x30<UINT8>
0x004031dd:	xorl %eax, %eax
0x004031df:	incl %eax
0x004031e0:	leave
0x004031e1:	ret

0x0040ce5d:	testl %eax, %eax
0x0040ce5f:	jne 0x0040ce67
0x0040ce67:	pushl %ebx
0x0040ce68:	pushl %esi
0x0040ce69:	pushl %edi
0x0040ce6a:	call 0x0040e4e9
0x0040e4e9:	cmpl 0x4173e0, $0x0<UINT8>
0x0040e4f0:	jne 37
0x0040e4f2:	pushl $0x413b18<UINT32>
0x0040e4f7:	call LoadLibraryW@KERNEL32.dll
0x0040e4fd:	testl %eax, %eax
0x0040e4ff:	movl 0x4173e0, %eax
0x0040e504:	je 17
0x0040e506:	pushl $0x413b30<UINT32>
0x0040e50b:	pushl %eax
0x0040e50c:	call GetProcAddress@KERNEL32.dll
0x0040e512:	movl 0x4173dc, %eax
0x0040e517:	ret

0x0040ce6f:	pushl $0x8001<UINT32>
0x0040ce74:	call SetErrorMode@KERNEL32.dll
SetErrorMode@KERNEL32.dll: API Node	
0x0040ce7a:	movl %edi, 0x4120c8
0x0040ce80:	xorl %ebx, %ebx
0x0040ce82:	pushl %ebx
0x0040ce83:	pushl $0x40e4ce<UINT32>
0x0040ce88:	pushl %ebx
0x0040ce89:	movl 0x416c84, $0x11223344<UINT32>
0x0040ce93:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x0040ce95:	pushl %eax
0x0040ce96:	call EnumResourceTypesW@KERNEL32.dll
EnumResourceTypesW@KERNEL32.dll: API Node	
0x0040ce9c:	leal %eax, -56(%ebp)
0x0040ce9f:	call 0x00405cfb
0x00405cfb:	xorl %ecx, %ecx
0x00405cfd:	movl 0x14(%eax), $0x400<UINT32>
0x00405d04:	movl 0x18(%eax), $0x100<UINT32>
0x00405d0b:	movl (%eax), %ecx
0x00405d0d:	movl 0x4(%eax), %ecx
0x00405d10:	movl 0xc(%eax), %ecx
0x00405d13:	movl 0x10(%eax), %ecx
0x00405d16:	movl 0x1c(%eax), %ecx
0x00405d19:	movl 0x8(%eax), %ecx
0x00405d1c:	ret

0x0040cea4:	leal %eax, -10376(%ebp)
0x0040ceaa:	pushl %eax
0x0040ceab:	movl -16(%ebp), $0x20<UINT32>
0x0040ceb2:	movl -24(%ebp), %ebx
0x0040ceb5:	movl -12(%ebp), %ebx
0x0040ceb8:	movl -20(%ebp), %ebx
0x0040cebb:	movl -8(%ebp), %ebx
0x0040cebe:	call 0x0040c9da
0x0040c9da:	pushl %ebx
0x0040c9db:	xorl %ebx, %ebx
0x0040c9dd:	pushl %ebp
0x0040c9de:	movl %ebp, 0xc(%esp)
0x0040c9e2:	movl 0x208(%ebp), %ebx
0x0040c9e8:	movl 0x244(%ebp), %ebx
0x0040c9ee:	movl 0x274(%ebp), %ebx
0x0040c9f4:	movl 0x240(%ebp), %ebx
0x0040c9fa:	movl (%ebp), $0x413818<UINT32>
0x0040ca01:	movl 0x694(%ebp), %ebx
0x0040ca07:	movl 0x6b4(%ebp), %ebx
0x0040ca0d:	leal %eax, 0x6bc(%ebp)
0x0040ca13:	movl 0xc(%eax), %ebx
0x0040ca16:	movl (%eax), %ebx
0x0040ca18:	movl 0x4(%eax), %ebx
0x0040ca1b:	movl 0x8(%eax), %ebx
0x0040ca1e:	movl %ecx, $0x100<UINT32>
0x0040ca23:	movl 0x10(%eax), %ecx
0x0040ca26:	leal %eax, 0x6d0(%ebp)
0x0040ca2c:	movl 0xc(%eax), %ebx
0x0040ca2f:	movl (%eax), %ebx
0x0040ca31:	movl 0x4(%eax), %ebx
0x0040ca34:	movl 0x10(%eax), %ecx
0x0040ca37:	movl 0x8(%eax), %ebx
0x0040ca3a:	pushl %esi
0x0040ca3b:	leal %eax, 0x6e8(%ebp)
0x0040ca41:	pushl %edi
0x0040ca42:	leal %edi, 0x708(%ebp)
0x0040ca48:	movl (%eax), $0x413c8c<UINT32>
0x0040ca4e:	movl 0x4(%eax), %ebx
0x0040ca51:	movl 0x8(%eax), %ebx
0x0040ca54:	movl 0x10(%eax), %ebx
0x0040ca57:	movl %esi, %edi
0x0040ca59:	movl 0x704(%ebp), %ebx
0x0040ca5f:	call 0x0040133c
0x0040133c:	andl 0x10(%esi), $0x0<UINT8>
0x00401340:	pushl $0x2c<UINT8>
0x00401342:	leal %eax, 0x14(%esi)
0x00401345:	pushl $0x0<UINT8>
0x00401347:	pushl %eax
0x00401348:	movl (%esi), $0x4124bc<UINT32>
0x0040134e:	call 0x00411154
0x00411154:	jmp memset@msvcrt.dll
memset@msvcrt.dll: API Node	
0x00401353:	addl %esp, $0xc<UINT8>
0x00401356:	movl %eax, %esi
0x00401358:	ret

0x0018fed8:	jl -1
0x0018feda:	sbbb (%eax), %al
0x0018fedc:	rclb (%ebx), $0x41<UINT8>
0x0018fedf:	addb (%eax), %al
0x0018fee1:	addb (%eax), %al
0x0018fee4:	addb (%eax), %al
0x0018fee6:	addb (%eax), %al
0x0018fee8:	subb %al, %ds:(%eax)
0x0018feec:	orb %al, (%eax)
0x0018feee:	addb (%eax), %al
0x0018fef0:	cmpb %al, $0x55<UINT8>
0x0018fef2:	incl %ecx
0x0018fef3:	addb 0x21(%eax), %dh
0x0018fef6:	incl %ecx
0x0018fef7:	addb (%eax), %ch
0x0018fef9:	loope 66
0x0018fefb:	addb (%eax), %al
0x0018fefd:	addb (%eax), %al
0x0018feff:	addb (%eax), %al
0x0018ff01:	addb (%eax), %al
0x0018ff03:	addb (%eax,%eax), %al
0x00411488:	jmp _except_handler3@msvcrt.dll
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
0x004031c8:	pushl $0x412b20<UINT32>
0x004031cd:	pushl $0x412b30<UINT32>
0x004031d2:	pushl %eax
0x004031d3:	call MessageBoxW@USER32.dll
MessageBoxW@USER32.dll: API Node	
0x004031d9:	xorl %eax, %eax
0x004031db:	leave
0x004031dc:	ret

0x0040ce61:	incl %eax
0x0040ce62:	jmp 0x0040d080
0x0040d080:	leave
0x0040d081:	ret $0x10<UINT16>

0x004113c0:	movl %esi, %eax
0x004113c2:	movl -124(%ebp), %esi
0x004113c5:	cmpl -28(%ebp), %edi
0x004113c8:	jne 7
0x004113ca:	pushl %esi
0x004113cb:	call exit@msvcrt.dll
exit@msvcrt.dll: Exit Node	
