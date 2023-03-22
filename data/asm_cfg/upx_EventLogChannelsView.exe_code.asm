0x0041df00:	pusha
0x0041df01:	movl %esi, $0x413000<UINT32>
0x0041df06:	leal %edi, -73728(%esi)
0x0041df0c:	pushl %edi
0x0041df0d:	orl %ebp, $0xffffffff<UINT8>
0x0041df10:	jmp 0x0041df22
0x0041df22:	movl %ebx, (%esi)
0x0041df24:	subl %esi, $0xfffffffc<UINT8>
0x0041df27:	adcl %ebx, %ebx
0x0041df29:	jb 0x0041df18
0x0041df18:	movb %al, (%esi)
0x0041df1a:	incl %esi
0x0041df1b:	movb (%edi), %al
0x0041df1d:	incl %edi
0x0041df1e:	addl %ebx, %ebx
0x0041df20:	jne 0x0041df29
0x0041df2b:	movl %eax, $0x1<UINT32>
0x0041df30:	addl %ebx, %ebx
0x0041df32:	jne 0x0041df3b
0x0041df3b:	adcl %eax, %eax
0x0041df3d:	addl %ebx, %ebx
0x0041df3f:	jae 0x0041df30
0x0041df41:	jne 0x0041df4c
0x0041df4c:	xorl %ecx, %ecx
0x0041df4e:	subl %eax, $0x3<UINT8>
0x0041df51:	jb 0x0041df60
0x0041df60:	addl %ebx, %ebx
0x0041df62:	jne 0x0041df6b
0x0041df6b:	adcl %ecx, %ecx
0x0041df6d:	addl %ebx, %ebx
0x0041df6f:	jne 0x0041df78
0x0041df78:	adcl %ecx, %ecx
0x0041df7a:	jne 0x0041df9c
0x0041df9c:	cmpl %ebp, $0xfffff300<UINT32>
0x0041dfa2:	adcl %ecx, $0x1<UINT8>
0x0041dfa5:	leal %edx, (%edi,%ebp)
0x0041dfa8:	cmpl %ebp, $0xfffffffc<UINT8>
0x0041dfab:	jbe 0x0041dfbc
0x0041dfad:	movb %al, (%edx)
0x0041dfaf:	incl %edx
0x0041dfb0:	movb (%edi), %al
0x0041dfb2:	incl %edi
0x0041dfb3:	decl %ecx
0x0041dfb4:	jne 0x0041dfad
0x0041dfb6:	jmp 0x0041df1e
0x0041df53:	shll %eax, $0x8<UINT8>
0x0041df56:	movb %al, (%esi)
0x0041df58:	incl %esi
0x0041df59:	xorl %eax, $0xffffffff<UINT8>
0x0041df5c:	je 0x0041dfd2
0x0041df5e:	movl %ebp, %eax
0x0041dfbc:	movl %eax, (%edx)
0x0041dfbe:	addl %edx, $0x4<UINT8>
0x0041dfc1:	movl (%edi), %eax
0x0041dfc3:	addl %edi, $0x4<UINT8>
0x0041dfc6:	subl %ecx, $0x4<UINT8>
0x0041dfc9:	ja 0x0041dfbc
0x0041dfcb:	addl %edi, %ecx
0x0041dfcd:	jmp 0x0041df1e
0x0041df34:	movl %ebx, (%esi)
0x0041df36:	subl %esi, $0xfffffffc<UINT8>
0x0041df39:	adcl %ebx, %ebx
0x0041df43:	movl %ebx, (%esi)
0x0041df45:	subl %esi, $0xfffffffc<UINT8>
0x0041df48:	adcl %ebx, %ebx
0x0041df4a:	jae 0x0041df30
0x0041df71:	movl %ebx, (%esi)
0x0041df73:	subl %esi, $0xfffffffc<UINT8>
0x0041df76:	adcl %ebx, %ebx
0x0041df7c:	incl %ecx
0x0041df7d:	addl %ebx, %ebx
0x0041df7f:	jne 0x0041df88
0x0041df88:	adcl %ecx, %ecx
0x0041df8a:	addl %ebx, %ebx
0x0041df8c:	jae 0x0041df7d
0x0041df8e:	jne 0x0041df99
0x0041df99:	addl %ecx, $0x2<UINT8>
0x0041df81:	movl %ebx, (%esi)
0x0041df83:	subl %esi, $0xfffffffc<UINT8>
0x0041df86:	adcl %ebx, %ebx
0x0041df90:	movl %ebx, (%esi)
0x0041df92:	subl %esi, $0xfffffffc<UINT8>
0x0041df95:	adcl %ebx, %ebx
0x0041df97:	jae 0x0041df7d
0x0041df64:	movl %ebx, (%esi)
0x0041df66:	subl %esi, $0xfffffffc<UINT8>
0x0041df69:	adcl %ebx, %ebx
0x0041dfd2:	popl %esi
0x0041dfd3:	movl %edi, %esi
0x0041dfd5:	movl %ecx, $0x59a<UINT32>
0x0041dfda:	movb %al, (%edi)
0x0041dfdc:	incl %edi
0x0041dfdd:	subb %al, $0xffffffe8<UINT8>
0x0041dfdf:	cmpb %al, $0x1<UINT8>
0x0041dfe1:	ja 0x0041dfda
0x0041dfe3:	cmpb (%edi), $0x1<UINT8>
0x0041dfe6:	jne 0x0041dfda
0x0041dfe8:	movl %eax, (%edi)
0x0041dfea:	movb %bl, 0x4(%edi)
0x0041dfed:	shrw %ax, $0x8<UINT8>
0x0041dff1:	roll %eax, $0x10<UINT8>
0x0041dff4:	xchgb %ah, %al
0x0041dff6:	subl %eax, %edi
0x0041dff8:	subb %bl, $0xffffffe8<UINT8>
0x0041dffb:	addl %eax, %esi
0x0041dffd:	movl (%edi), %eax
0x0041dfff:	addl %edi, $0x5<UINT8>
0x0041e002:	movb %al, %bl
0x0041e004:	loop 0x0041dfdf
0x0041e006:	leal %edi, 0x1b000(%esi)
0x0041e00c:	movl %eax, (%edi)
0x0041e00e:	orl %eax, %eax
0x0041e010:	je 0x0041e057
0x0041e012:	movl %ebx, 0x4(%edi)
0x0041e015:	leal %eax, 0x205b8(%eax,%esi)
0x0041e01c:	addl %ebx, %esi
0x0041e01e:	pushl %eax
0x0041e01f:	addl %edi, $0x8<UINT8>
0x0041e022:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0041e028:	xchgl %ebp, %eax
0x0041e029:	movb %al, (%edi)
0x0041e02b:	incl %edi
0x0041e02c:	orb %al, %al
0x0041e02e:	je 0x0041e00c
0x0041e030:	movl %ecx, %edi
0x0041e032:	jns 0x0041e03b
0x0041e03b:	pushl %edi
0x0041e03c:	decl %eax
0x0041e03d:	repn scasb %al, %es:(%edi)
0x0041e03f:	pushl %ebp
0x0041e040:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0041e046:	orl %eax, %eax
0x0041e048:	je 7
0x0041e04a:	movl (%ebx), %eax
0x0041e04c:	addl %ebx, $0x4<UINT8>
0x0041e04f:	jmp 0x0041e029
GetProcAddress@KERNEL32.DLL: API Node	
0x0041e034:	movzwl %eax, (%edi)
0x0041e037:	incl %edi
0x0041e038:	pushl %eax
0x0041e039:	incl %edi
0x0041e03a:	movl %ecx, $0xaef24857<UINT32>
0x0041e057:	movl %ebp, 0x20690(%esi)
0x0041e05d:	leal %edi, -4096(%esi)
0x0041e063:	movl %ebx, $0x1000<UINT32>
0x0041e068:	pushl %eax
0x0041e069:	pushl %esp
0x0041e06a:	pushl $0x4<UINT8>
0x0041e06c:	pushl %ebx
0x0041e06d:	pushl %edi
0x0041e06e:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0041e070:	leal %eax, 0x217(%edi)
0x0041e076:	andb (%eax), $0x7f<UINT8>
0x0041e079:	andb 0x28(%eax), $0x7f<UINT8>
0x0041e07d:	popl %eax
0x0041e07e:	pushl %eax
0x0041e07f:	pushl %esp
0x0041e080:	pushl %eax
0x0041e081:	pushl %ebx
0x0041e082:	pushl %edi
0x0041e083:	call VirtualProtect@kernel32.dll
0x0041e085:	popl %eax
0x0041e086:	popa
0x0041e087:	leal %eax, -128(%esp)
0x0041e08b:	pushl $0x0<UINT8>
0x0041e08d:	cmpl %esp, %eax
0x0041e08f:	jne 0x0041e08b
0x0041e091:	subl %esp, $0xffffff80<UINT8>
0x0041e094:	jmp 0x0040e52e
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
0x0040e53d:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
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
0x0040e694:	call GetStartupInfoW@KERNEL32.DLL
GetStartupInfoW@KERNEL32.DLL: API Node	
0x0040e69a:	testb -76(%ebp), $0x1<UINT8>
0x0040e69e:	je 0x0040e6b3
0x0040e6b3:	pushl $0xa<UINT8>
0x0040e6b5:	popl %eax
0x0040e6b6:	pushl %eax
0x0040e6b7:	pushl %esi
0x0040e6b8:	pushl %edi
0x0040e6b9:	pushl %edi
0x0040e6ba:	call GetModuleHandleA@KERNEL32.DLL
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
0x004027b6:	call LoadLibraryW@KERNEL32.DLL
LoadLibraryW@KERNEL32.DLL: API Node	
0x004027bc:	movl %esi, %eax
0x004027be:	testl %esi, %esi
0x004027c0:	je 40
0x004027c2:	pushl $0x40f734<UINT32>
0x004027c7:	pushl %esi
0x004027c8:	call GetProcAddress@KERNEL32.DLL
0x004027ce:	testl %eax, %eax
0x004027d0:	je 9
0x004027d2:	leal %ecx, -8(%ebp)
0x004027d5:	pushl %ecx
0x004027d6:	incl %edi
0x004027d7:	call InitCommonControlsEx@comctl32.dll
InitCommonControlsEx@comctl32.dll: API Node	
0x004027d9:	movl %ebx, %eax
0x004027db:	pushl %esi
0x004027dc:	call FreeLibrary@KERNEL32.DLL
FreeLibrary@KERNEL32.DLL: API Node	
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
0x0040c56a:	call LoadLibraryW@KERNEL32.DLL
0x0040c570:	testl %eax, %eax
0x0040c572:	movl 0x4132f8, %eax
0x0040c577:	je 17
0x0040c579:	pushl $0x410660<UINT32>
0x0040c57e:	pushl %eax
0x0040c57f:	call GetProcAddress@KERNEL32.DLL
0x0040c585:	movl 0x4132f4, %eax
0x0040c58a:	ret

0x0040af84:	pushl $0x8001<UINT32>
0x0040af89:	call SetErrorMode@KERNEL32.DLL
SetErrorMode@KERNEL32.DLL: API Node	
0x0040af8f:	movl %ebx, 0x40f0ac
0x0040af95:	xorl %edi, %edi
0x0040af97:	pushl %edi
0x0040af98:	pushl $0x40c541<UINT32>
0x0040af9d:	pushl %edi
0x0040af9e:	movl 0x412ba0, $0x11223344<UINT32>
0x0040afa8:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0040afaa:	pushl %eax
0x0040afab:	call EnumResourceTypesW@KERNEL32.DLL
EnumResourceTypesW@KERNEL32.DLL: API Node	
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
0x0018fee8:	into
0x0018fee9:	subl %ebx, (%edi)
0x0018feeb:	addb (%edx), %cl
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
0x7c903306:	addb (%eax), %al
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
