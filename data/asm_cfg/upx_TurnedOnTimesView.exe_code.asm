0x00421460:	pusha
0x00421461:	movl %esi, $0x415000<UINT32>
0x00421466:	leal %edi, -81920(%esi)
0x0042146c:	pushl %edi
0x0042146d:	orl %ebp, $0xffffffff<UINT8>
0x00421470:	jmp 0x00421482
0x00421482:	movl %ebx, (%esi)
0x00421484:	subl %esi, $0xfffffffc<UINT8>
0x00421487:	adcl %ebx, %ebx
0x00421489:	jb 0x00421478
0x00421478:	movb %al, (%esi)
0x0042147a:	incl %esi
0x0042147b:	movb (%edi), %al
0x0042147d:	incl %edi
0x0042147e:	addl %ebx, %ebx
0x00421480:	jne 0x00421489
0x0042148b:	movl %eax, $0x1<UINT32>
0x00421490:	addl %ebx, %ebx
0x00421492:	jne 0x0042149b
0x0042149b:	adcl %eax, %eax
0x0042149d:	addl %ebx, %ebx
0x0042149f:	jae 0x00421490
0x004214a1:	jne 0x004214ac
0x004214ac:	xorl %ecx, %ecx
0x004214ae:	subl %eax, $0x3<UINT8>
0x004214b1:	jb 0x004214c0
0x004214c0:	addl %ebx, %ebx
0x004214c2:	jne 0x004214cb
0x004214cb:	adcl %ecx, %ecx
0x004214cd:	addl %ebx, %ebx
0x004214cf:	jne 0x004214d8
0x004214d8:	adcl %ecx, %ecx
0x004214da:	jne 0x004214fc
0x004214fc:	cmpl %ebp, $0xfffff300<UINT32>
0x00421502:	adcl %ecx, $0x1<UINT8>
0x00421505:	leal %edx, (%edi,%ebp)
0x00421508:	cmpl %ebp, $0xfffffffc<UINT8>
0x0042150b:	jbe 0x0042151c
0x0042150d:	movb %al, (%edx)
0x0042150f:	incl %edx
0x00421510:	movb (%edi), %al
0x00421512:	incl %edi
0x00421513:	decl %ecx
0x00421514:	jne 0x0042150d
0x00421516:	jmp 0x0042147e
0x004214b3:	shll %eax, $0x8<UINT8>
0x004214b6:	movb %al, (%esi)
0x004214b8:	incl %esi
0x004214b9:	xorl %eax, $0xffffffff<UINT8>
0x004214bc:	je 0x00421532
0x004214be:	movl %ebp, %eax
0x0042151c:	movl %eax, (%edx)
0x0042151e:	addl %edx, $0x4<UINT8>
0x00421521:	movl (%edi), %eax
0x00421523:	addl %edi, $0x4<UINT8>
0x00421526:	subl %ecx, $0x4<UINT8>
0x00421529:	ja 0x0042151c
0x0042152b:	addl %edi, %ecx
0x0042152d:	jmp 0x0042147e
0x00421494:	movl %ebx, (%esi)
0x00421496:	subl %esi, $0xfffffffc<UINT8>
0x00421499:	adcl %ebx, %ebx
0x004214a3:	movl %ebx, (%esi)
0x004214a5:	subl %esi, $0xfffffffc<UINT8>
0x004214a8:	adcl %ebx, %ebx
0x004214aa:	jae 0x00421490
0x004214d1:	movl %ebx, (%esi)
0x004214d3:	subl %esi, $0xfffffffc<UINT8>
0x004214d6:	adcl %ebx, %ebx
0x004214dc:	incl %ecx
0x004214dd:	addl %ebx, %ebx
0x004214df:	jne 0x004214e8
0x004214e8:	adcl %ecx, %ecx
0x004214ea:	addl %ebx, %ebx
0x004214ec:	jae 0x004214dd
0x004214ee:	jne 0x004214f9
0x004214f9:	addl %ecx, $0x2<UINT8>
0x004214e1:	movl %ebx, (%esi)
0x004214e3:	subl %esi, $0xfffffffc<UINT8>
0x004214e6:	adcl %ebx, %ebx
0x004214f0:	movl %ebx, (%esi)
0x004214f2:	subl %esi, $0xfffffffc<UINT8>
0x004214f5:	adcl %ebx, %ebx
0x004214f7:	jae 0x004214dd
0x004214c4:	movl %ebx, (%esi)
0x004214c6:	subl %esi, $0xfffffffc<UINT8>
0x004214c9:	adcl %ebx, %ebx
0x00421532:	popl %esi
0x00421533:	movl %edi, %esi
0x00421535:	movl %ecx, $0x61e<UINT32>
0x0042153a:	movb %al, (%edi)
0x0042153c:	incl %edi
0x0042153d:	subb %al, $0xffffffe8<UINT8>
0x0042153f:	cmpb %al, $0x1<UINT8>
0x00421541:	ja 0x0042153a
0x00421543:	cmpb (%edi), $0x4<UINT8>
0x00421546:	jne 0x0042153a
0x00421548:	movl %eax, (%edi)
0x0042154a:	movb %bl, 0x4(%edi)
0x0042154d:	shrw %ax, $0x8<UINT8>
0x00421551:	roll %eax, $0x10<UINT8>
0x00421554:	xchgb %ah, %al
0x00421556:	subl %eax, %edi
0x00421558:	subb %bl, $0xffffffe8<UINT8>
0x0042155b:	addl %eax, %esi
0x0042155d:	movl (%edi), %eax
0x0042155f:	addl %edi, $0x5<UINT8>
0x00421562:	movb %al, %bl
0x00421564:	loop 0x0042153f
0x00421566:	leal %edi, 0x1f000(%esi)
0x0042156c:	movl %eax, (%edi)
0x0042156e:	orl %eax, %eax
0x00421570:	je 0x004215b7
0x00421572:	movl %ebx, 0x4(%edi)
0x00421575:	leal %eax, 0x23214(%eax,%esi)
0x0042157c:	addl %ebx, %esi
0x0042157e:	pushl %eax
0x0042157f:	addl %edi, $0x8<UINT8>
0x00421582:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x00421588:	xchgl %ebp, %eax
0x00421589:	movb %al, (%edi)
0x0042158b:	incl %edi
0x0042158c:	orb %al, %al
0x0042158e:	je 0x0042156c
0x00421590:	movl %ecx, %edi
0x00421592:	jns 0x0042159b
0x0042159b:	pushl %edi
0x0042159c:	decl %eax
0x0042159d:	repn scasb %al, %es:(%edi)
0x0042159f:	pushl %ebp
0x004215a0:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x004215a6:	orl %eax, %eax
0x004215a8:	je 7
0x004215aa:	movl (%ebx), %eax
0x004215ac:	addl %ebx, $0x4<UINT8>
0x004215af:	jmp 0x00421589
GetProcAddress@KERNEL32.DLL: API Node	
0x00421594:	movzwl %eax, (%edi)
0x00421597:	incl %edi
0x00421598:	pushl %eax
0x00421599:	incl %edi
0x0042159a:	movl %ecx, $0xaef24857<UINT32>
0x004215b7:	movl %ebp, 0x2331c(%esi)
0x004215bd:	leal %edi, -4096(%esi)
0x004215c3:	movl %ebx, $0x1000<UINT32>
0x004215c8:	pushl %eax
0x004215c9:	pushl %esp
0x004215ca:	pushl $0x4<UINT8>
0x004215cc:	pushl %ebx
0x004215cd:	pushl %edi
0x004215ce:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x004215d0:	leal %eax, 0x20f(%edi)
0x004215d6:	andb (%eax), $0x7f<UINT8>
0x004215d9:	andb 0x28(%eax), $0x7f<UINT8>
0x004215dd:	popl %eax
0x004215de:	pushl %eax
0x004215df:	pushl %esp
0x004215e0:	pushl %eax
0x004215e1:	pushl %ebx
0x004215e2:	pushl %edi
0x004215e3:	call VirtualProtect@kernel32.dll
0x004215e5:	popl %eax
0x004215e6:	popa
0x004215e7:	leal %eax, -128(%esp)
0x004215eb:	pushl $0x0<UINT8>
0x004215ed:	cmpl %esp, %eax
0x004215ef:	jne 0x004215eb
0x004215f1:	subl %esp, $0xffffff80<UINT8>
0x004215f4:	jmp 0x0040ef42
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
0x0040ef51:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
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
0x0040f0a8:	call GetStartupInfoW@KERNEL32.DLL
GetStartupInfoW@KERNEL32.DLL: API Node	
0x0040f0ae:	testb -76(%ebp), $0x1<UINT8>
0x0040f0b2:	je 0x0040f0c7
0x0040f0c7:	pushl $0xa<UINT8>
0x0040f0c9:	popl %eax
0x0040f0ca:	pushl %eax
0x0040f0cb:	pushl %esi
0x0040f0cc:	pushl %edi
0x0040f0cd:	pushl %edi
0x0040f0ce:	call GetModuleHandleA@KERNEL32.DLL
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
0x004022e0:	call LoadLibraryW@KERNEL32.DLL
LoadLibraryW@KERNEL32.DLL: API Node	
0x004022e6:	movl %esi, %eax
0x004022e8:	testl %esi, %esi
0x004022ea:	je 40
0x004022ec:	pushl $0x41071c<UINT32>
0x004022f1:	pushl %esi
0x004022f2:	call GetProcAddress@KERNEL32.DLL
0x004022f8:	testl %eax, %eax
0x004022fa:	je 9
0x004022fc:	leal %ecx, -8(%ebp)
0x004022ff:	pushl %ecx
0x00402300:	incl %edi
0x00402301:	call InitCommonControlsEx@comctl32.dll
InitCommonControlsEx@comctl32.dll: API Node	
0x00402303:	movl %ebx, %eax
0x00402305:	pushl %esi
0x00402306:	call FreeLibrary@KERNEL32.DLL
FreeLibrary@KERNEL32.DLL: API Node	
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
0x0040b4ea:	call LoadLibraryW@KERNEL32.DLL
0x0040b4f0:	testl %eax, %eax
0x0040b4f2:	movl 0x416998, %eax
0x0040b4f7:	je 17
0x0040b4f9:	pushl $0x413098<UINT32>
0x0040b4fe:	pushl %eax
0x0040b4ff:	call GetProcAddress@KERNEL32.DLL
0x0040b505:	movl 0x416994, %eax
0x0040b50a:	ret

0x0040a250:	pushl $0x8001<UINT32>
0x0040a255:	call SetErrorMode@KERNEL32.DLL
SetErrorMode@KERNEL32.DLL: API Node	
0x0040a25b:	xorl %ebx, %ebx
0x0040a25d:	pushl %ebx
0x0040a25e:	pushl $0x40b4c1<UINT32>
0x0040a263:	pushl %ebx
0x0040a264:	movl 0x416240, $0x11223344<UINT32>
0x0040a26e:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0040a274:	pushl %eax
0x0040a275:	call EnumResourceTypesW@KERNEL32.DLL
EnumResourceTypesW@KERNEL32.DLL: API Node	
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
