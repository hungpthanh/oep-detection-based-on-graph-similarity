0x004155e0:	pusha
0x004155e1:	movl %esi, $0x40e000<UINT32>
0x004155e6:	leal %edi, -53248(%esi)
0x004155ec:	pushl %edi
0x004155ed:	jmp 0x004155fa
0x004155fa:	movl %ebx, (%esi)
0x004155fc:	subl %esi, $0xfffffffc<UINT8>
0x004155ff:	adcl %ebx, %ebx
0x00415601:	jb 0x004155f0
0x004155f0:	movb %al, (%esi)
0x004155f2:	incl %esi
0x004155f3:	movb (%edi), %al
0x004155f5:	incl %edi
0x004155f6:	addl %ebx, %ebx
0x004155f8:	jne 0x00415601
0x00415603:	movl %eax, $0x1<UINT32>
0x00415608:	addl %ebx, %ebx
0x0041560a:	jne 0x00415613
0x00415613:	adcl %eax, %eax
0x00415615:	addl %ebx, %ebx
0x00415617:	jae 0x00415608
0x00415619:	jne 0x00415624
0x00415624:	xorl %ecx, %ecx
0x00415626:	subl %eax, $0x3<UINT8>
0x00415629:	jb 0x00415638
0x0041562b:	shll %eax, $0x8<UINT8>
0x0041562e:	movb %al, (%esi)
0x00415630:	incl %esi
0x00415631:	xorl %eax, $0xffffffff<UINT8>
0x00415634:	je 0x004156aa
0x00415636:	movl %ebp, %eax
0x00415638:	addl %ebx, %ebx
0x0041563a:	jne 0x00415643
0x00415643:	adcl %ecx, %ecx
0x00415645:	addl %ebx, %ebx
0x00415647:	jne 0x00415650
0x00415650:	adcl %ecx, %ecx
0x00415652:	jne 0x00415674
0x00415674:	cmpl %ebp, $0xfffff300<UINT32>
0x0041567a:	adcl %ecx, $0x1<UINT8>
0x0041567d:	leal %edx, (%edi,%ebp)
0x00415680:	cmpl %ebp, $0xfffffffc<UINT8>
0x00415683:	jbe 0x00415694
0x00415694:	movl %eax, (%edx)
0x00415696:	addl %edx, $0x4<UINT8>
0x00415699:	movl (%edi), %eax
0x0041569b:	addl %edi, $0x4<UINT8>
0x0041569e:	subl %ecx, $0x4<UINT8>
0x004156a1:	ja 0x00415694
0x004156a3:	addl %edi, %ecx
0x004156a5:	jmp 0x004155f6
0x00415649:	movl %ebx, (%esi)
0x0041564b:	subl %esi, $0xfffffffc<UINT8>
0x0041564e:	adcl %ebx, %ebx
0x00415654:	incl %ecx
0x00415655:	addl %ebx, %ebx
0x00415657:	jne 0x00415660
0x00415660:	adcl %ecx, %ecx
0x00415662:	addl %ebx, %ebx
0x00415664:	jae 0x00415655
0x00415666:	jne 0x00415671
0x00415671:	addl %ecx, $0x2<UINT8>
0x0041563c:	movl %ebx, (%esi)
0x0041563e:	subl %esi, $0xfffffffc<UINT8>
0x00415641:	adcl %ebx, %ebx
0x0041560c:	movl %ebx, (%esi)
0x0041560e:	subl %esi, $0xfffffffc<UINT8>
0x00415611:	adcl %ebx, %ebx
0x0041561b:	movl %ebx, (%esi)
0x0041561d:	subl %esi, $0xfffffffc<UINT8>
0x00415620:	adcl %ebx, %ebx
0x00415622:	jae 0x00415608
0x00415668:	movl %ebx, (%esi)
0x0041566a:	subl %esi, $0xfffffffc<UINT8>
0x0041566d:	adcl %ebx, %ebx
0x0041566f:	jae 0x00415655
0x00415685:	movb %al, (%edx)
0x00415687:	incl %edx
0x00415688:	movb (%edi), %al
0x0041568a:	incl %edi
0x0041568b:	decl %ecx
0x0041568c:	jne 0x00415685
0x0041568e:	jmp 0x004155f6
0x00415659:	movl %ebx, (%esi)
0x0041565b:	subl %esi, $0xfffffffc<UINT8>
0x0041565e:	adcl %ebx, %ebx
0x004156aa:	popl %esi
0x004156ab:	movl %edi, %esi
0x004156ad:	movl %ecx, $0x44c<UINT32>
0x004156b2:	movb %al, (%edi)
0x004156b4:	incl %edi
0x004156b5:	subb %al, $0xffffffe8<UINT8>
0x004156b7:	cmpb %al, $0x1<UINT8>
0x004156b9:	ja 0x004156b2
0x004156bb:	cmpb (%edi), $0x2<UINT8>
0x004156be:	jne 0x004156b2
0x004156c0:	movl %eax, (%edi)
0x004156c2:	movb %bl, 0x4(%edi)
0x004156c5:	shrw %ax, $0x8<UINT8>
0x004156c9:	roll %eax, $0x10<UINT8>
0x004156cc:	xchgb %ah, %al
0x004156ce:	subl %eax, %edi
0x004156d0:	subb %bl, $0xffffffe8<UINT8>
0x004156d3:	addl %eax, %esi
0x004156d5:	movl (%edi), %eax
0x004156d7:	addl %edi, $0x5<UINT8>
0x004156da:	movb %al, %bl
0x004156dc:	loop 0x004156b7
0x004156de:	leal %edi, 0x13000(%esi)
0x004156e4:	movl %eax, (%edi)
0x004156e6:	orl %eax, %eax
0x004156e8:	je 0x0041572f
0x004156ea:	movl %ebx, 0x4(%edi)
0x004156ed:	leal %eax, 0x15f68(%eax,%esi)
0x004156f4:	addl %ebx, %esi
0x004156f6:	pushl %eax
0x004156f7:	addl %edi, $0x8<UINT8>
0x004156fa:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00415700:	xchgl %ebp, %eax
0x00415701:	movb %al, (%edi)
0x00415703:	incl %edi
0x00415704:	orb %al, %al
0x00415706:	je 0x004156e4
0x00415708:	movl %ecx, %edi
0x0041570a:	jns 0x00415713
0x00415713:	pushl %edi
0x00415714:	decl %eax
0x00415715:	repn scasb %al, %es:(%edi)
0x00415717:	pushl %ebp
0x00415718:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0041571e:	orl %eax, %eax
0x00415720:	je 7
0x00415722:	movl (%ebx), %eax
0x00415724:	addl %ebx, $0x4<UINT8>
0x00415727:	jmp 0x00415701
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x0041570c:	movzwl %eax, (%edi)
0x0041570f:	incl %edi
0x00415710:	pushl %eax
0x00415711:	incl %edi
0x00415712:	movl %ecx, $0xaef24857<UINT32>
0x0041572f:	movl %ebp, 0x1605c(%esi)
0x00415735:	leal %edi, -4096(%esi)
0x0041573b:	movl %ebx, $0x1000<UINT32>
0x00415740:	pushl %eax
0x00415741:	pushl %esp
0x00415742:	pushl $0x4<UINT8>
0x00415744:	pushl %ebx
0x00415745:	pushl %edi
0x00415746:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00415748:	leal %eax, 0x207(%edi)
0x0041574e:	andb (%eax), $0x7f<UINT8>
0x00415751:	andb 0x28(%eax), $0x7f<UINT8>
0x00415755:	popl %eax
0x00415756:	pushl %eax
0x00415757:	pushl %esp
0x00415758:	pushl %eax
0x00415759:	pushl %ebx
0x0041575a:	pushl %edi
0x0041575b:	call VirtualProtect@kernel32.dll
0x0041575d:	popl %eax
0x0041575e:	popa
0x0041575f:	leal %eax, -128(%esp)
0x00415763:	pushl $0x0<UINT8>
0x00415765:	cmpl %esp, %eax
0x00415767:	jne 0x00415763
0x00415769:	subl %esp, $0xffffff80<UINT8>
0x0041576c:	jmp 0x0040b008
0x0040b008:	pushl $0x70<UINT8>
0x0040b00a:	pushl $0x40c3a0<UINT32>
0x0040b00f:	call 0x0040b1f8
0x0040b1f8:	pushl $0x40b248<UINT32>
0x0040b1fd:	movl %eax, %fs:0
0x0040b203:	pushl %eax
0x0040b204:	movl %fs:0, %esp
0x0040b20b:	movl %eax, 0x10(%esp)
0x0040b20f:	movl 0x10(%esp), %ebp
0x0040b213:	leal %ebp, 0x10(%esp)
0x0040b217:	subl %esp, %eax
0x0040b219:	pushl %ebx
0x0040b21a:	pushl %esi
0x0040b21b:	pushl %edi
0x0040b21c:	movl %eax, -8(%ebp)
0x0040b21f:	movl -24(%ebp), %esp
0x0040b222:	pushl %eax
0x0040b223:	movl %eax, -4(%ebp)
0x0040b226:	movl -4(%ebp), $0xffffffff<UINT32>
0x0040b22d:	movl -8(%ebp), %eax
0x0040b230:	ret

0x0040b014:	xorl %ebx, %ebx
0x0040b016:	pushl %ebx
0x0040b017:	movl %edi, 0x40c08c
0x0040b01d:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x0040b01f:	cmpw (%eax), $0x5a4d<UINT16>
0x0040b024:	jne 31
0x0040b026:	movl %ecx, 0x3c(%eax)
0x0040b029:	addl %ecx, %eax
0x0040b02b:	cmpl (%ecx), $0x4550<UINT32>
0x0040b031:	jne 18
0x0040b033:	movzwl %eax, 0x18(%ecx)
0x0040b037:	cmpl %eax, $0x10b<UINT32>
0x0040b03c:	je 0x0040b05d
0x0040b05d:	cmpl 0x74(%ecx), $0xe<UINT8>
0x0040b061:	jbe -30
0x0040b063:	xorl %eax, %eax
0x0040b065:	cmpl 0xe8(%ecx), %ebx
0x0040b06b:	setne %al
0x0040b06e:	movl -28(%ebp), %eax
0x0040b071:	movl -4(%ebp), %ebx
0x0040b074:	pushl $0x2<UINT8>
0x0040b076:	call __set_app_type@msvcrt.dll
__set_app_type@msvcrt.dll: API Node	
0x0040b07c:	popl %ecx
0x0040b07d:	orl 0x40ff9c, $0xffffffff<UINT8>
0x0040b084:	orl 0x40ffa0, $0xffffffff<UINT8>
0x0040b08b:	call __p__fmode@msvcrt.dll
__p__fmode@msvcrt.dll: API Node	
0x0040b091:	movl %ecx, 0x40f2bc
0x0040b097:	movl (%eax), %ecx
0x0040b099:	call __p__commode@msvcrt.dll
__p__commode@msvcrt.dll: API Node	
0x0040b09f:	movl %ecx, 0x40f2b8
0x0040b0a5:	movl (%eax), %ecx
0x0040b0a7:	movl %eax, 0x40c2ac
0x0040b0ac:	movl %eax, (%eax)
0x0040b0ae:	movl 0x40ff98, %eax
0x0040b0b3:	call 0x0040b1f2
0x0040b1f2:	xorl %eax, %eax
0x0040b1f4:	ret

0x0040b0b8:	cmpl 0x40f000, %ebx
0x0040b0be:	jne 0x0040b0cc
0x0040b0cc:	call 0x0040b1e0
0x0040b1e0:	pushl $0x30000<UINT32>
0x0040b1e5:	pushl $0x10000<UINT32>
0x0040b1ea:	call 0x0040b242
0x0040b242:	jmp _controlfp@msvcrt.dll
_controlfp@msvcrt.dll: API Node	
0x0040b1ef:	popl %ecx
0x0040b1f0:	popl %ecx
0x0040b1f1:	ret

0x0040b0d1:	pushl $0x40c378<UINT32>
0x0040b0d6:	pushl $0x40c374<UINT32>
0x0040b0db:	call 0x0040b1da
0x0040b1da:	jmp _initterm@msvcrt.dll
_initterm@msvcrt.dll: API Node	
0x0040b0e0:	movl %eax, 0x40f2b4
0x0040b0e5:	movl -32(%ebp), %eax
0x0040b0e8:	leal %eax, -32(%ebp)
0x0040b0eb:	pushl %eax
0x0040b0ec:	pushl 0x40f2b0
0x0040b0f2:	leal %eax, -36(%ebp)
0x0040b0f5:	pushl %eax
0x0040b0f6:	leal %eax, -40(%ebp)
0x0040b0f9:	pushl %eax
0x0040b0fa:	leal %eax, -44(%ebp)
0x0040b0fd:	pushl %eax
0x0040b0fe:	call __getmainargs@msvcrt.dll
__getmainargs@msvcrt.dll: API Node	
0x0040b104:	movl -48(%ebp), %eax
0x0040b107:	pushl $0x40c370<UINT32>
0x0040b10c:	pushl $0x40c35c<UINT32>
0x0040b111:	call 0x0040b1da
0x0040b116:	addl %esp, $0x24<UINT8>
0x0040b119:	movl %eax, 0x40c2bc
0x0040b11e:	movl %esi, (%eax)
0x0040b120:	movl -52(%ebp), %esi
0x0040b123:	cmpb (%esi), $0x22<UINT8>
0x0040b126:	jne 58
0x0040b128:	incl %esi
0x0040b129:	movl -52(%ebp), %esi
0x0040b12c:	movb %al, (%esi)
0x0040b12e:	cmpb %al, %bl
0x0040b130:	je 4
0x0040b132:	cmpb %al, $0x22<UINT8>
0x0040b134:	jne 0x0040b128
0x0040b136:	cmpb (%esi), $0x22<UINT8>
0x0040b139:	jne 4
0x0040b13b:	incl %esi
0x0040b13c:	movl -52(%ebp), %esi
0x0040b13f:	movb %al, (%esi)
0x0040b141:	cmpb %al, %bl
0x0040b143:	je 4
0x0040b145:	cmpb %al, $0x20<UINT8>
0x0040b147:	jbe 0x0040b13b
0x0040b149:	movl -76(%ebp), %ebx
0x0040b14c:	leal %eax, -120(%ebp)
0x0040b14f:	pushl %eax
0x0040b150:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x0040b156:	testb -76(%ebp), $0x1<UINT8>
0x0040b15a:	je 0x0040b16d
0x0040b16d:	pushl $0xa<UINT8>
0x0040b16f:	popl %eax
0x0040b170:	pushl %eax
0x0040b171:	pushl %esi
0x0040b172:	pushl %ebx
0x0040b173:	pushl %ebx
0x0040b174:	call GetModuleHandleA@KERNEL32.DLL
0x0040b176:	pushl %eax
0x0040b177:	call 0x0040936b
0x0040936b:	pushl %ebp
0x0040936c:	movl %ebp, %esp
0x0040936e:	andl %esp, $0xfffffff8<UINT8>
0x00409371:	movl %eax, $0x1344<UINT32>
0x00409376:	call 0x0040b260
0x0040b260:	cmpl %eax, $0x1000<UINT32>
0x0040b265:	jae 0x0040b275
0x0040b275:	pushl %ecx
0x0040b276:	leal %ecx, 0x8(%esp)
0x0040b27a:	subl %ecx, $0x1000<UINT32>
0x0040b280:	subl %eax, $0x1000<UINT32>
0x0040b285:	testl (%ecx), %eax
0x0040b287:	cmpl %eax, $0x1000<UINT32>
0x0040b28c:	jae -20
0x0040b28e:	subl %ecx, %eax
0x0040b290:	movl %eax, %esp
0x0040b292:	testl (%ecx), %eax
0x0040b294:	movl %esp, %ecx
0x0040b296:	movl %ecx, (%eax)
0x0040b298:	movl %eax, 0x4(%eax)
0x0040b29b:	pushl %eax
0x0040b29c:	ret

0x0040937b:	pushl %ebx
0x0040937c:	pushl %esi
0x0040937d:	pushl %edi
0x0040937e:	call 0x00402f72
0x00402f72:	pushl %ebp
0x00402f73:	movl %ebp, %esp
0x00402f75:	pushl %ecx
0x00402f76:	pushl %ecx
0x00402f77:	pushl %ebx
0x00402f78:	pushl %esi
0x00402f79:	pushl %edi
0x00402f7a:	pushl $0x40c80c<UINT32>
0x00402f7f:	movl -8(%ebp), $0x8<UINT32>
0x00402f86:	movl -4(%ebp), $0xff<UINT32>
0x00402f8d:	xorl %ebx, %ebx
0x00402f8f:	xorl %edi, %edi
0x00402f91:	call LoadLibraryA@KERNEL32.DLL
0x00402f97:	movl %esi, %eax
0x00402f99:	testl %esi, %esi
0x00402f9b:	je 40
0x00402f9d:	pushl $0x40c81c<UINT32>
0x00402fa2:	pushl %esi
0x00402fa3:	call GetProcAddress@KERNEL32.DLL
0x00402fa9:	testl %eax, %eax
0x00402fab:	je 9
0x00402fad:	leal %ecx, -8(%ebp)
0x00402fb0:	pushl %ecx
0x00402fb1:	incl %edi
0x00402fb2:	call InitCommonControlsEx@comctl32.dll
InitCommonControlsEx@comctl32.dll: API Node	
0x00402fb4:	movl %ebx, %eax
0x00402fb6:	pushl %esi
0x00402fb7:	call FreeLibrary@KERNEL32.DLL
FreeLibrary@KERNEL32.DLL: API Node	
0x00402fbd:	testl %edi, %edi
0x00402fbf:	je 4
0x00402fc1:	movl %eax, %ebx
0x00402fc3:	jmp 0x00402fce
0x00402fce:	testl %eax, %eax
0x00402fd0:	popl %edi
0x00402fd1:	popl %esi
0x00402fd2:	popl %ebx
0x00402fd3:	jne 0x00402fec
0x00402fd5:	pushl $0x30<UINT8>
0x00402fec:	xorl %eax, %eax
0x00402fee:	incl %eax
0x00402fef:	leave
0x00402ff0:	ret

0x00409383:	testl %eax, %eax
0x00409385:	jne 0x0040938d
0x0040938d:	call 0x0040a950
0x0040a950:	cmpl 0x40fc44, $0x0<UINT8>
0x0040a957:	jne 37
0x0040a959:	pushl $0x40cf48<UINT32>
0x0040a95e:	call LoadLibraryA@KERNEL32.DLL
0x0040a964:	testl %eax, %eax
0x0040a966:	movl 0x40fc44, %eax
0x0040a96b:	je 17
0x0040a96d:	pushl $0x40cf54<UINT32>
0x0040a972:	pushl %eax
0x0040a973:	call GetProcAddress@KERNEL32.DLL
0x0040a979:	movl 0x40fc40, %eax
0x0040a97e:	ret

0x00409392:	xorl %edi, %edi
0x00409394:	leal %eax, 0x60(%esp)
0x00409398:	movl 0x24(%esp), $0x400<UINT32>
0x004093a0:	movl 0x28(%esp), $0x100<UINT32>
0x004093a8:	movl 0x10(%esp), %edi
0x004093ac:	movl 0x14(%esp), %edi
0x004093b0:	movl 0x1c(%esp), %edi
0x004093b4:	movl 0x20(%esp), %edi
0x004093b8:	movl 0x2c(%esp), %edi
0x004093bc:	movl 0x18(%esp), %edi
0x004093c0:	movl 0x38(%esp), $0x20<UINT32>
0x004093c8:	movl 0x30(%esp), %edi
0x004093cc:	movl 0x3c(%esp), %edi
0x004093d0:	movl 0x34(%esp), %edi
0x004093d4:	movl 0x40(%esp), %edi
0x004093d8:	call 0x00409137
0x00409137:	pushl %ebx
0x00409138:	pushl %esi
0x00409139:	pushl %edi
0x0040913a:	movl %esi, %eax
0x0040913c:	xorl %ebx, %ebx
0x0040913e:	leal %eax, 0x2a4(%esi)
0x00409144:	movl 0x140(%esi), %ebx
0x0040914a:	movl (%esi), $0x40ccac<UINT32>
0x00409150:	pushl $0x10<UINT8>
0x00409152:	movl 0x298(%esi), $0x40c878<UINT32>
0x0040915c:	pushl %ebx
0x0040915d:	pushl %eax
0x0040915e:	movl 0x1c(%eax), $0x20<UINT32>
0x00409165:	movl 0x14(%eax), %ebx
0x00409168:	movl 0x20(%eax), %ebx
0x0040916b:	movl 0x18(%eax), %ebx
0x0040916e:	call 0x0040af78
0x0040af78:	jmp memset@msvcrt.dll
memset@msvcrt.dll: API Node	
0x00409173:	xorl %edi, %edi
0x00409175:	incl %edi
0x00409176:	movb 0x2e4(%esi), %bl
0x0040917c:	movl 0x12e4(%esi), %edi
0x00409182:	movl 0x12e8(%esi), %edi
0x00409188:	movl 0x12ec(%esi), %edi
0x0040918e:	pushl $0x1028<UINT32>
0x00409193:	movl 0x29c(%esi), $0x72<UINT32>
0x0040919d:	movl 0x2d8(%esi), %ebx
0x004091a3:	movl 0x2dc(%esi), %ebx
0x004091a9:	call 0x0040afa8
0x0040afa8:	jmp ??2@YAPAXI@Z@msvcrt.dll
??2@YAPAXI@Z@msvcrt.dll: API Node	
0x004091ae:	addl %esp, $0x10<UINT8>
0x004091b1:	cmpl %eax, %ebx
0x004091b3:	je 28
0x004091b5:	movb 0x18(%eax), %bl
0x004091b8:	movl 0x1018(%eax), %edi
0x004091be:	movl 0x101c(%eax), %edi
0x004091c4:	movl 0x1020(%eax), %edi
0x004091ca:	movl 0x40f838, %eax
0x004091cf:	jmp 0x004091d3
0x004091d3:	pushl $0x250<UINT32>
0x004091d8:	movl 0x284(%esi), %eax
0x004091de:	call 0x0040afa8
0x004091e3:	cmpl %eax, %ebx
0x004091e5:	popl %ecx
0x004091e6:	je 7
0x004091e8:	call 0x00402bda
0x00402bda:	pushl %esi
0x00402bdb:	movl %esi, %eax
0x00402bdd:	call 0x00405ba5
0x00405ba5:	pushl %ebx
0x00405ba6:	pushl %edi
0x00405ba7:	pushl %esi
0x00405ba8:	movl %eax, $0x214<UINT32>
0x00405bad:	movl (%esi), $0x40cad0<UINT32>
0x00405bb3:	call 0x004046b2
0x004046b2:	addl %eax, $0xfffffffc<UINT8>
0x004046b5:	pushl %eax
0x004046b6:	movl %eax, 0x8(%esp)
0x004046ba:	addl %eax, $0x4<UINT8>
0x004046bd:	pushl $0x0<UINT8>
0x004046bf:	pushl %eax
0x004046c0:	call 0x0040af78
0x004046c5:	addl %esp, $0xc<UINT8>
0x004046c8:	ret

0x00000000:	addb (%eax), %al
0x00000002:	addb (%eax), %al
0x00000004:	addb (%eax), %al
0x00000006:	addb (%eax), %al
0x00000008:	addb (%eax), %al
0x0000000a:	addb (%eax), %al
0x0000000c:	addb (%eax), %al
0x0000000e:	addb (%eax), %al
0x00000010:	addb (%eax), %al
0x00000012:	addb (%eax), %al
0x00000014:	addb (%eax), %al
0x00000016:	addb (%eax), %al
0x00000018:	addb (%eax), %al
0x0000001a:	addb (%eax), %al
0x0000001c:	addb (%eax), %al
0x0000001e:	addb (%eax), %al
0x00000020:	addb (%eax), %al
0x00000022:	addb (%eax), %al
0x00000024:	addb (%eax), %al
0x00000026:	addb (%eax), %al
0x00000028:	addb (%eax), %al
0x0000002a:	addb (%eax), %al
0x0000002c:	addb (%eax), %al
0x0000002e:	addb (%eax), %al
0x00000030:	addb (%eax), %al
0x00000032:	addb (%eax), %al
0x00000034:	addb (%eax), %al
0x00000036:	addb (%eax), %al
0x00000038:	addb (%eax), %al
0x0000003a:	addb (%eax), %al
0x0000003c:	addb (%eax), %al
0x0000003e:	addb (%eax), %al
0x00000040:	addb (%eax), %al
0x00000042:	addb (%eax), %al
0x00000044:	addb (%eax), %al
0x00000046:	addb (%eax), %al
0x00000048:	addb (%eax), %al
0x0000004a:	addb (%eax), %al
0x0000004c:	addb (%eax), %al
0x0000004e:	addb (%eax), %al
0x00000050:	addb (%eax), %al
0x00000052:	addb (%eax), %al
0x00000054:	addb (%eax), %al
0x00000056:	addb (%eax), %al
0x00000058:	addb (%eax), %al
0x0000005a:	addb (%eax), %al
0x0000005c:	addb (%eax), %al
0x0000005e:	addb (%eax), %al
0x00000060:	addb (%eax), %al
0x00000062:	addb (%eax), %al
0x00000064:	addb (%eax), %al
0x00000066:	addb (%eax), %al
0x00402fd7:	pushl $0x40c834<UINT32>
0x00402fdc:	pushl $0x40c83c<UINT32>
0x00402fe1:	pushl %eax
0x00402fe2:	call MessageBoxA@USER32.dll
MessageBoxA@USER32.dll: API Node	
0x00402fe8:	xorl %eax, %eax
0x00402fea:	leave
0x00402feb:	ret

0x00409387:	incl %eax
0x00409388:	jmp 0x004095cf
0x004095cf:	popl %edi
0x004095d0:	popl %esi
0x004095d1:	popl %ebx
0x004095d2:	movl %esp, %ebp
0x004095d4:	popl %ebp
0x004095d5:	ret $0x10<UINT16>

0x0040b17c:	movl %esi, %eax
0x0040b17e:	movl -124(%ebp), %esi
0x0040b181:	cmpl -28(%ebp), %ebx
0x0040b184:	jne 7
0x0040b186:	pushl %esi
0x0040b187:	call exit@msvcrt.dll
exit@msvcrt.dll: Exit Node	
