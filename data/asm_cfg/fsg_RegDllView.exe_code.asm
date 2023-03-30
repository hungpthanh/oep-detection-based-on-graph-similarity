0x00420000:	movl %ebx, $0x4001d0<UINT32>
0x00420005:	movl %edi, $0x401000<UINT32>
0x0042000a:	movl %esi, $0x416e46<UINT32>
0x0042000f:	pushl %ebx
0x00420010:	call 0x0042001f
0x0042001f:	cld
0x00420020:	movb %dl, $0xffffff80<UINT8>
0x00420022:	movsb %es:(%edi), %ds:(%esi)
0x00420023:	pushl $0x2<UINT8>
0x00420025:	popl %ebx
0x00420026:	call 0x00420015
0x00420015:	addb %dl, %dl
0x00420017:	jne 0x0042001e
0x00420019:	movb %dl, (%esi)
0x0042001b:	incl %esi
0x0042001c:	adcb %dl, %dl
0x0042001e:	ret

0x00420029:	jae 0x00420022
0x0042002b:	xorl %ecx, %ecx
0x0042002d:	call 0x00420015
0x00420030:	jae 0x0042004a
0x00420032:	xorl %eax, %eax
0x00420034:	call 0x00420015
0x00420037:	jae 0x0042005a
0x00420039:	movb %bl, $0x2<UINT8>
0x0042003b:	incl %ecx
0x0042003c:	movb %al, $0x10<UINT8>
0x0042003e:	call 0x00420015
0x00420041:	adcb %al, %al
0x00420043:	jae 0x0042003e
0x00420045:	jne 0x00420086
0x00420086:	pushl %esi
0x00420087:	movl %esi, %edi
0x00420089:	subl %esi, %eax
0x0042008b:	rep movsb %es:(%edi), %ds:(%esi)
0x0042008d:	popl %esi
0x0042008e:	jmp 0x00420026
0x00420047:	stosb %es:(%edi), %al
0x00420048:	jmp 0x00420026
0x0042005a:	lodsb %al, %ds:(%esi)
0x0042005b:	shrl %eax
0x0042005d:	je 0x004200a0
0x0042005f:	adcl %ecx, %ecx
0x00420061:	jmp 0x0042007f
0x0042007f:	incl %ecx
0x00420080:	incl %ecx
0x00420081:	xchgl %ebp, %eax
0x00420082:	movl %eax, %ebp
0x00420084:	movb %bl, $0x1<UINT8>
0x0042004a:	call 0x00420092
0x00420092:	incl %ecx
0x00420093:	call 0x00420015
0x00420097:	adcl %ecx, %ecx
0x00420099:	call 0x00420015
0x0042009d:	jb 0x00420093
0x0042009f:	ret

0x0042004f:	subl %ecx, %ebx
0x00420051:	jne 0x00420063
0x00420063:	xchgl %ecx, %eax
0x00420064:	decl %eax
0x00420065:	shll %eax, $0x8<UINT8>
0x00420068:	lodsb %al, %ds:(%esi)
0x00420069:	call 0x00420090
0x00420090:	xorl %ecx, %ecx
0x0042006e:	cmpl %eax, $0x7d00<UINT32>
0x00420073:	jae 0x0042007f
0x00420075:	cmpb %ah, $0x5<UINT8>
0x00420078:	jae 0x00420080
0x0042007a:	cmpl %eax, $0x7f<UINT8>
0x0042007d:	ja 0x00420081
0x00420053:	call 0x00420090
0x00420058:	jmp 0x00420082
0x004200a0:	popl %edi
0x004200a1:	popl %ebx
0x004200a2:	movzwl %edi, (%ebx)
0x004200a5:	decl %edi
0x004200a6:	je 0x004200b0
0x004200a8:	decl %edi
0x004200a9:	je 0x004200be
0x004200ab:	shll %edi, $0xc<UINT8>
0x004200ae:	jmp 0x004200b7
0x004200b7:	incl %ebx
0x004200b8:	incl %ebx
0x004200b9:	jmp 0x0042000f
0x004200b0:	movl %edi, 0x2(%ebx)
0x004200b3:	pushl %edi
0x004200b4:	addl %ebx, $0x4<UINT8>
0x004200be:	popl %edi
0x004200bf:	movl %ebx, $0x420128<UINT32>
0x004200c4:	incl %edi
0x004200c5:	movl %esi, (%edi)
0x004200c7:	scasl %eax, %es:(%edi)
0x004200c8:	pushl %edi
0x004200c9:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x004200cb:	xchgl %ebp, %eax
0x004200cc:	xorl %eax, %eax
0x004200ce:	scasb %al, %es:(%edi)
0x004200cf:	jne 0x004200ce
0x004200d1:	decb (%edi)
0x004200d3:	je 0x004200c4
0x004200d5:	decb (%edi)
0x004200d7:	jne 0x004200df
0x004200df:	decb (%edi)
0x004200e1:	je 0x0040c80c
0x004200e7:	pushl %edi
0x004200e8:	pushl %ebp
0x004200e9:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x004200ec:	orl (%esi), %eax
0x004200ee:	lodsl %eax, %ds:(%esi)
0x004200ef:	jne 0x004200cc
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x004200d9:	incl %edi
0x004200da:	pushl (%edi)
0x004200dc:	scasl %eax, %es:(%edi)
0x004200dd:	jmp 0x004200e8
0x0040c80c:	pushl $0x70<UINT8>
0x0040c80e:	pushl $0x40d410<UINT32>
0x0040c813:	call 0x0040c9fc
0x0040c9fc:	pushl $0x40ca4c<UINT32>
0x0040ca01:	movl %eax, %fs:0
0x0040ca07:	pushl %eax
0x0040ca08:	movl %fs:0, %esp
0x0040ca0f:	movl %eax, 0x10(%esp)
0x0040ca13:	movl 0x10(%esp), %ebp
0x0040ca17:	leal %ebp, 0x10(%esp)
0x0040ca1b:	subl %esp, %eax
0x0040ca1d:	pushl %ebx
0x0040ca1e:	pushl %esi
0x0040ca1f:	pushl %edi
0x0040ca20:	movl %eax, -8(%ebp)
0x0040ca23:	movl -24(%ebp), %esp
0x0040ca26:	pushl %eax
0x0040ca27:	movl %eax, -4(%ebp)
0x0040ca2a:	movl -4(%ebp), $0xffffffff<UINT32>
0x0040ca31:	movl -8(%ebp), %eax
0x0040ca34:	ret

0x0040c818:	xorl %ebx, %ebx
0x0040c81a:	pushl %ebx
0x0040c81b:	movl %edi, 0x40d0fc
0x0040c821:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x0040c823:	cmpw (%eax), $0x5a4d<UINT16>
0x0040c828:	jne 31
0x0040c82a:	movl %ecx, 0x3c(%eax)
0x0040c82d:	addl %ecx, %eax
0x0040c82f:	cmpl (%ecx), $0x4550<UINT32>
0x0040c835:	jne 18
0x0040c837:	movzwl %eax, 0x18(%ecx)
0x0040c83b:	cmpl %eax, $0x10b<UINT32>
0x0040c840:	je 0x0040c861
0x0040c861:	cmpl 0x74(%ecx), $0xe<UINT8>
0x0040c865:	jbe -30
0x0040c867:	xorl %eax, %eax
0x0040c869:	cmpl 0xe8(%ecx), %ebx
0x0040c86f:	setne %al
0x0040c872:	movl -28(%ebp), %eax
0x0040c875:	movl -4(%ebp), %ebx
0x0040c878:	pushl $0x2<UINT8>
0x0040c87a:	call __set_app_type@msvcrt.dll
__set_app_type@msvcrt.dll: API Node	
0x0040c880:	popl %ecx
0x0040c881:	orl 0x411208, $0xffffffff<UINT8>
0x0040c888:	orl 0x41120c, $0xffffffff<UINT8>
0x0040c88f:	call __p__fmode@msvcrt.dll
__p__fmode@msvcrt.dll: API Node	
0x0040c895:	movl %ecx, 0x4104ec
0x0040c89b:	movl (%eax), %ecx
0x0040c89d:	call __p__commode@msvcrt.dll
__p__commode@msvcrt.dll: API Node	
0x0040c8a3:	movl %ecx, 0x4104e8
0x0040c8a9:	movl (%eax), %ecx
0x0040c8ab:	movl %eax, 0x40d2fc
0x0040c8b0:	movl %eax, (%eax)
0x0040c8b2:	movl 0x411204, %eax
0x0040c8b7:	call 0x0040c9f6
0x0040c9f6:	xorl %eax, %eax
0x0040c9f8:	ret

0x0040c8bc:	cmpl 0x410000, %ebx
0x0040c8c2:	jne 0x0040c8d0
0x0040c8d0:	call 0x0040c9e4
0x0040c9e4:	pushl $0x30000<UINT32>
0x0040c9e9:	pushl $0x10000<UINT32>
0x0040c9ee:	call 0x0040ca46
0x0040ca46:	jmp _controlfp@msvcrt.dll
_controlfp@msvcrt.dll: API Node	
0x0040c9f3:	popl %ecx
0x0040c9f4:	popl %ecx
0x0040c9f5:	ret

0x0040c8d5:	pushl $0x40d3e0<UINT32>
0x0040c8da:	pushl $0x40d3dc<UINT32>
0x0040c8df:	call 0x0040c9de
0x0040c9de:	jmp _initterm@msvcrt.dll
_initterm@msvcrt.dll: API Node	
0x0040c8e4:	movl %eax, 0x4104e4
0x0040c8e9:	movl -32(%ebp), %eax
0x0040c8ec:	leal %eax, -32(%ebp)
0x0040c8ef:	pushl %eax
0x0040c8f0:	pushl 0x4104e0
0x0040c8f6:	leal %eax, -36(%ebp)
0x0040c8f9:	pushl %eax
0x0040c8fa:	leal %eax, -40(%ebp)
0x0040c8fd:	pushl %eax
0x0040c8fe:	leal %eax, -44(%ebp)
0x0040c901:	pushl %eax
0x0040c902:	call __getmainargs@msvcrt.dll
__getmainargs@msvcrt.dll: API Node	
0x0040c908:	movl -48(%ebp), %eax
0x0040c90b:	pushl $0x40d3d8<UINT32>
0x0040c910:	pushl $0x40d3bc<UINT32>
0x0040c915:	call 0x0040c9de
0x0040c91a:	addl %esp, $0x24<UINT8>
0x0040c91d:	movl %eax, 0x40d30c
0x0040c922:	movl %esi, (%eax)
0x0040c924:	movl -52(%ebp), %esi
0x0040c927:	cmpb (%esi), $0x22<UINT8>
0x0040c92a:	jne 58
0x0040c92c:	incl %esi
0x0040c92d:	movl -52(%ebp), %esi
0x0040c930:	movb %al, (%esi)
0x0040c932:	cmpb %al, %bl
0x0040c934:	je 4
0x0040c936:	cmpb %al, $0x22<UINT8>
0x0040c938:	jne 0x0040c92c
0x0040c93a:	cmpb (%esi), $0x22<UINT8>
0x0040c93d:	jne 4
0x0040c93f:	incl %esi
0x0040c940:	movl -52(%ebp), %esi
0x0040c943:	movb %al, (%esi)
0x0040c945:	cmpb %al, %bl
0x0040c947:	je 4
0x0040c949:	cmpb %al, $0x20<UINT8>
0x0040c94b:	jbe 0x0040c93f
0x0040c94d:	movl -76(%ebp), %ebx
0x0040c950:	leal %eax, -120(%ebp)
0x0040c953:	pushl %eax
0x0040c954:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x0040c95a:	testb -76(%ebp), $0x1<UINT8>
0x0040c95e:	je 0x0040c971
0x0040c971:	pushl $0xa<UINT8>
0x0040c973:	popl %eax
0x0040c974:	pushl %eax
0x0040c975:	pushl %esi
0x0040c976:	pushl %ebx
0x0040c977:	pushl %ebx
0x0040c978:	call GetModuleHandleA@KERNEL32.DLL
0x0040c97a:	pushl %eax
0x0040c97b:	call 0x0040a24d
0x0040a24d:	pushl %ebp
0x0040a24e:	movl %ebp, %esp
0x0040a250:	subl %esp, $0x468<UINT32>
0x0040a256:	call 0x0040256f
0x0040256f:	pushl %ebp
0x00402570:	movl %ebp, %esp
0x00402572:	pushl %ecx
0x00402573:	pushl %ecx
0x00402574:	pushl %ebx
0x00402575:	pushl %esi
0x00402576:	pushl %edi
0x00402577:	pushl $0x40d778<UINT32>
0x0040257c:	movl -8(%ebp), $0x8<UINT32>
0x00402583:	movl -4(%ebp), $0xff<UINT32>
0x0040258a:	xorl %ebx, %ebx
0x0040258c:	xorl %edi, %edi
0x0040258e:	call LoadLibraryA@KERNEL32.DLL
0x00402594:	movl %esi, %eax
0x00402596:	testl %esi, %esi
0x00402598:	je 40
0x0040259a:	pushl $0x40d788<UINT32>
0x0040259f:	pushl %esi
0x004025a0:	call GetProcAddress@KERNEL32.DLL
0x004025a6:	testl %eax, %eax
0x004025a8:	je 9
0x004025aa:	leal %ecx, -8(%ebp)
0x004025ad:	pushl %ecx
0x004025ae:	incl %edi
0x004025af:	call InitCommonControlsEx@comctl32.dll
InitCommonControlsEx@comctl32.dll: API Node	
0x004025b1:	movl %ebx, %eax
0x004025b3:	pushl %esi
0x004025b4:	call FreeLibrary@KERNEL32.DLL
FreeLibrary@KERNEL32.DLL: API Node	
0x004025ba:	testl %edi, %edi
0x004025bc:	je 4
0x004025be:	movl %eax, %ebx
0x004025c0:	jmp 0x004025cb
0x004025cb:	testl %eax, %eax
0x004025cd:	popl %edi
0x004025ce:	popl %esi
0x004025cf:	popl %ebx
0x004025d0:	jne 0x004025e9
0x004025d2:	pushl $0x30<UINT8>
0x004025e9:	xorl %eax, %eax
0x004025eb:	incl %eax
0x004025ec:	leave
0x004025ed:	ret

0x0040a25b:	testl %eax, %eax
0x0040a25d:	jne 0x0040a265
0x0040a265:	pushl %ebx
0x0040a266:	pushl %esi
0x0040a267:	pushl %edi
0x0040a268:	call 0x0040be4a
0x0040be4a:	cmpl 0x410e7c, $0x0<UINT8>
0x0040be51:	jne 37
0x0040be53:	pushl $0x40e0f8<UINT32>
0x0040be58:	call LoadLibraryA@KERNEL32.DLL
0x0040be5e:	testl %eax, %eax
0x0040be60:	movl 0x410e7c, %eax
0x0040be65:	je 17
0x0040be67:	pushl $0x40e104<UINT32>
0x0040be6c:	pushl %eax
0x0040be6d:	call GetProcAddress@KERNEL32.DLL
0x0040be73:	movl 0x410e78, %eax
0x0040be78:	ret

0x0040a26d:	pushl $0x8001<UINT32>
0x0040a272:	call SetErrorMode@KERNEL32.DLL
SetErrorMode@KERNEL32.DLL: API Node	
0x0040a278:	xorl %edi, %edi
0x0040a27a:	pushl %edi
0x0040a27b:	pushl $0x40be2f<UINT32>
0x0040a280:	pushl %edi
0x0040a281:	movl 0x410a68, $0x11223344<UINT32>
0x0040a28b:	call GetModuleHandleA@KERNEL32.DLL
0x0040a291:	pushl %eax
0x0040a292:	call EnumResourceTypesA@KERNEL32.DLL
EnumResourceTypesA@KERNEL32.DLL: API Node	
0x0040a298:	leal %eax, -52(%ebp)
0x0040a29b:	call 0x0040482e
0x0040482e:	xorl %ecx, %ecx
0x00404830:	movl 0x14(%eax), $0x400<UINT32>
0x00404837:	movl 0x18(%eax), $0x100<UINT32>
0x0040483e:	movl (%eax), %ecx
0x00404840:	movl 0x4(%eax), %ecx
0x00404843:	movl 0xc(%eax), %ecx
0x00404846:	movl 0x10(%eax), %ecx
0x00404849:	movl 0x1c(%eax), %ecx
0x0040484c:	movl 0x8(%eax), %ecx
0x0040484f:	ret

0x0040a2a0:	leal %ebx, -1128(%ebp)
0x0040a2a6:	movl -12(%ebp), $0x20<UINT32>
0x0040a2ad:	movl -20(%ebp), %edi
0x0040a2b0:	movl -8(%ebp), %edi
0x0040a2b3:	movl -16(%ebp), %edi
0x0040a2b6:	movl -4(%ebp), %edi
0x0040a2b9:	call 0x00409f27
0x00409f27:	pushl %ebp
0x00409f28:	pushl %esi
0x00409f29:	xorl %ebp, %ebp
0x00409f2b:	pushl %edi
0x00409f2c:	leal %eax, 0x178(%ebx)
0x00409f32:	movl 0x140(%ebx), %ebp
0x00409f38:	movl (%ebx), $0x40ddd0<UINT32>
0x00409f3e:	call 0x0040482e
0x00409f43:	leal %eax, 0x198(%ebx)
0x00409f49:	movl 0xc(%eax), %ebp
0x00409f4c:	movl (%eax), %ebp
0x00409f4e:	movl 0x4(%eax), %ebp
0x00409f51:	movl 0x10(%eax), $0x100<UINT32>
0x00409f58:	movl 0x8(%eax), %ebp
0x00409f5b:	leal %eax, 0x3dc(%ebx)
0x00409f61:	movl 0x3c8(%ebx), %ebp
0x00409f67:	call 0x0040482e
0x00409f6c:	pushl $0x30<UINT8>
0x00409f6e:	call 0x0040c7a6
0x0040c7a6:	jmp ??2@YAPAXI@Z@msvcrt.dll
??2@YAPAXI@Z@msvcrt.dll: API Node	
0x00409f73:	cmpl %eax, %ebp
0x00409f75:	popl %ecx
0x00409f76:	je 7
0x00409f78:	movl 0x410a6c, %eax
0x00409f7d:	jmp 0x00409f81
0x00409f81:	pushl $0x220<UINT32>
0x00409f86:	movl 0x3d0(%ebx), %eax
0x00409f8c:	call 0x0040c7a6
0x00409f91:	movl %esi, %eax
0x00409f93:	cmpl %esi, %ebp
0x00409f95:	popl %ecx
0x00409f96:	je 31
0x00409f98:	call 0x00405a92
0x00405a92:	pushl %ebx
0x00405a93:	pushl %edi
0x00405a94:	pushl %esi
0x00405a95:	movl %eax, $0x218<UINT32>
0x00405a9a:	movl (%esi), $0x40dbc8<UINT32>
0x00405aa0:	call 0x00404337
0x00404337:	addl %eax, $0xfffffffc<UINT8>
0x0040433a:	pushl %eax
0x0040433b:	movl %eax, 0x8(%esp)
0x0040433f:	addl %eax, $0x4<UINT8>
0x00404342:	pushl $0x0<UINT8>
0x00404344:	pushl %eax
0x00404345:	call 0x0040c79a
0x0040c79a:	jmp memset@msvcrt.dll
memset@msvcrt.dll: API Node	
0x0040434a:	addl %esp, $0xc<UINT8>
0x0040434d:	ret

0x0018fa70:	rcrb %ch
0x0018fa72:	incl %eax
0x0018fa73:	addb (%eax), %al
0x0018fa75:	addb (%eax), %al
0x0018fa77:	addb (%eax), %al
0x0018fa79:	addb (%eax), %al
0x0018fa7b:	addb (%eax), %al
0x0018fa7d:	addb (%eax), %al
0x0018fa7f:	addb (%eax), %al
0x0018fa81:	addb (%eax), %al
0x0018fa83:	addb (%eax), %al
0x0018fa85:	addb (%eax), %al
0x0018fa87:	addb (%eax), %al
0x0018fa89:	addb (%eax), %al
0x0018fa8b:	addb (%eax), %al
0x0018fa8d:	addb (%eax), %al
0x0018fa8f:	addb (%eax), %al
0x0018fa91:	addb (%eax), %al
0x0018fa93:	addb (%eax), %al
0x0018fa95:	addb (%eax), %al
0x0018fa97:	addb (%eax), %al
0x0018fa99:	addb (%eax), %al
0x0018fa9b:	addb (%eax), %al
0x0018fa9d:	addb (%eax), %al
0x0018fa9f:	addb (%eax), %al
0x0018faa1:	addb (%eax), %al
0x0018faa3:	addb (%eax), %al
0x0018faa5:	addb (%eax), %al
0x0018faa7:	addb (%eax), %al
0x0018faa9:	addb (%eax), %al
0x0018faab:	addb (%eax), %al
0x0018faad:	addb (%eax), %al
0x0018faaf:	addb (%eax), %al
0x0018fab1:	addb (%eax), %al
0x0018fab3:	addb (%eax), %al
0x0018fab5:	addb (%eax), %al
0x0018fab7:	addb (%eax), %al
0x0018fab9:	addb (%eax), %al
0x0018fabb:	addb (%eax), %al
0x0018fabd:	addb (%eax), %al
0x0018fabf:	addb (%eax), %al
0x0018fac1:	addb (%eax), %al
0x0018fac3:	addb (%eax), %al
0x0018fac5:	addb (%eax), %al
0x0018fac7:	addb (%eax), %al
0x0018fac9:	addb (%eax), %al
0x0018facb:	addb (%eax), %al
0x0018facd:	addb (%eax), %al
0x0018facf:	addb (%eax), %al
0x0018fad1:	addb (%eax), %al
0x0018fad3:	addb (%eax), %al
0x0018fad5:	addb (%eax), %al
0x0018fad7:	addb (%eax), %al
0x0018fad9:	addb (%eax), %al
0x004025d4:	pushl $0x40d7a0<UINT32>
0x004025d9:	pushl $0x40d7a8<UINT32>
0x004025de:	pushl %eax
0x004025df:	call MessageBoxA@USER32.dll
MessageBoxA@USER32.dll: API Node	
0x004025e5:	xorl %eax, %eax
0x004025e7:	leave
0x004025e8:	ret

0x0040a25f:	incl %eax
0x0040a260:	jmp 0x0040a47e
0x0040a47e:	leave
0x0040a47f:	ret $0x10<UINT16>

0x0040c980:	movl %esi, %eax
0x0040c982:	movl -124(%ebp), %esi
0x0040c985:	cmpl -28(%ebp), %ebx
0x0040c988:	jne 7
0x0040c98a:	pushl %esi
0x0040c98b:	call exit@msvcrt.dll
exit@msvcrt.dll: Exit Node	
