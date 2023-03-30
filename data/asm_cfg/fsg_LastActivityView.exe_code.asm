0x00440000:	movl %ebx, $0x4001d0<UINT32>
0x00440005:	movl %edi, $0x401000<UINT32>
0x0044000a:	movl %esi, $0x430bd4<UINT32>
0x0044000f:	pushl %ebx
0x00440010:	call 0x0044001f
0x0044001f:	cld
0x00440020:	movb %dl, $0xffffff80<UINT8>
0x00440022:	movsb %es:(%edi), %ds:(%esi)
0x00440023:	pushl $0x2<UINT8>
0x00440025:	popl %ebx
0x00440026:	call 0x00440015
0x00440015:	addb %dl, %dl
0x00440017:	jne 0x0044001e
0x00440019:	movb %dl, (%esi)
0x0044001b:	incl %esi
0x0044001c:	adcb %dl, %dl
0x0044001e:	ret

0x00440029:	jae 0x00440022
0x0044002b:	xorl %ecx, %ecx
0x0044002d:	call 0x00440015
0x00440030:	jae 0x0044004a
0x00440032:	xorl %eax, %eax
0x00440034:	call 0x00440015
0x00440037:	jae 0x0044005a
0x00440039:	movb %bl, $0x2<UINT8>
0x0044003b:	incl %ecx
0x0044003c:	movb %al, $0x10<UINT8>
0x0044003e:	call 0x00440015
0x00440041:	adcb %al, %al
0x00440043:	jae 0x0044003e
0x00440045:	jne 0x00440086
0x00440086:	pushl %esi
0x00440087:	movl %esi, %edi
0x00440089:	subl %esi, %eax
0x0044008b:	rep movsb %es:(%edi), %ds:(%esi)
0x0044008d:	popl %esi
0x0044008e:	jmp 0x00440026
0x00440047:	stosb %es:(%edi), %al
0x00440048:	jmp 0x00440026
0x0044005a:	lodsb %al, %ds:(%esi)
0x0044005b:	shrl %eax
0x0044005d:	je 0x004400a0
0x0044005f:	adcl %ecx, %ecx
0x00440061:	jmp 0x0044007f
0x0044007f:	incl %ecx
0x00440080:	incl %ecx
0x00440081:	xchgl %ebp, %eax
0x00440082:	movl %eax, %ebp
0x00440084:	movb %bl, $0x1<UINT8>
0x0044004a:	call 0x00440092
0x00440092:	incl %ecx
0x00440093:	call 0x00440015
0x00440097:	adcl %ecx, %ecx
0x00440099:	call 0x00440015
0x0044009d:	jb 0x00440093
0x0044009f:	ret

0x0044004f:	subl %ecx, %ebx
0x00440051:	jne 0x00440063
0x00440063:	xchgl %ecx, %eax
0x00440064:	decl %eax
0x00440065:	shll %eax, $0x8<UINT8>
0x00440068:	lodsb %al, %ds:(%esi)
0x00440069:	call 0x00440090
0x00440090:	xorl %ecx, %ecx
0x0044006e:	cmpl %eax, $0x7d00<UINT32>
0x00440073:	jae 0x0044007f
0x00440075:	cmpb %ah, $0x5<UINT8>
0x00440078:	jae 0x00440080
0x0044007a:	cmpl %eax, $0x7f<UINT8>
0x0044007d:	ja 0x00440081
0x00440053:	call 0x00440090
0x00440058:	jmp 0x00440082
0x004400a0:	popl %edi
0x004400a1:	popl %ebx
0x004400a2:	movzwl %edi, (%ebx)
0x004400a5:	decl %edi
0x004400a6:	je 0x004400b0
0x004400a8:	decl %edi
0x004400a9:	je 0x004400be
0x004400ab:	shll %edi, $0xc<UINT8>
0x004400ae:	jmp 0x004400b7
0x004400b7:	incl %ebx
0x004400b8:	incl %ebx
0x004400b9:	jmp 0x0044000f
0x004400b0:	movl %edi, 0x2(%ebx)
0x004400b3:	pushl %edi
0x004400b4:	addl %ebx, $0x4<UINT8>
0x004400be:	popl %edi
0x004400bf:	movl %ebx, $0x440128<UINT32>
0x004400c4:	incl %edi
0x004400c5:	movl %esi, (%edi)
0x004400c7:	scasl %eax, %es:(%edi)
0x004400c8:	pushl %edi
0x004400c9:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004400cb:	xchgl %ebp, %eax
0x004400cc:	xorl %eax, %eax
0x004400ce:	scasb %al, %es:(%edi)
0x004400cf:	jne 0x004400ce
0x004400d1:	decb (%edi)
0x004400d3:	je 0x004400c4
0x004400d5:	decb (%edi)
0x004400d7:	jne 0x004400df
0x004400df:	decb (%edi)
0x004400e1:	je 0x004127f8
0x004400e7:	pushl %edi
0x004400e8:	pushl %ebp
0x004400e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x004400ec:	orl (%esi), %eax
0x004400ee:	lodsl %eax, %ds:(%esi)
0x004400ef:	jne 0x004400cc
0x004400d9:	incl %edi
0x004400da:	pushl (%edi)
0x004400dc:	scasl %eax, %es:(%edi)
0x004400dd:	jmp 0x004400e8
GetProcAddress@KERNEL32.dll: API Node	
0x004127f8:	pushl $0x70<UINT8>
0x004127fa:	pushl $0x413480<UINT32>
0x004127ff:	call 0x00412a08
0x00412a08:	pushl $0x412a58<UINT32>
0x00412a0d:	movl %eax, %fs:0
0x00412a13:	pushl %eax
0x00412a14:	movl %fs:0, %esp
0x00412a1b:	movl %eax, 0x10(%esp)
0x00412a1f:	movl 0x10(%esp), %ebp
0x00412a23:	leal %ebp, 0x10(%esp)
0x00412a27:	subl %esp, %eax
0x00412a29:	pushl %ebx
0x00412a2a:	pushl %esi
0x00412a2b:	pushl %edi
0x00412a2c:	movl %eax, -8(%ebp)
0x00412a2f:	movl -24(%ebp), %esp
0x00412a32:	pushl %eax
0x00412a33:	movl %eax, -4(%ebp)
0x00412a36:	movl -4(%ebp), $0xffffffff<UINT32>
0x00412a3d:	movl -8(%ebp), %eax
0x00412a40:	ret

0x00412804:	xorl %edi, %edi
0x00412806:	pushl %edi
0x00412807:	call GetModuleHandleA@KERNEL32.dll
GetModuleHandleA@KERNEL32.dll: API Node	
0x0041280d:	cmpw (%eax), $0x5a4d<UINT16>
0x00412812:	jne 31
0x00412814:	movl %ecx, 0x3c(%eax)
0x00412817:	addl %ecx, %eax
0x00412819:	cmpl (%ecx), $0x4550<UINT32>
0x0041281f:	jne 18
0x00412821:	movzwl %eax, 0x18(%ecx)
0x00412825:	cmpl %eax, $0x10b<UINT32>
0x0041282a:	je 0x0041284b
0x0041284b:	cmpl 0x74(%ecx), $0xe<UINT8>
0x0041284f:	jbe -30
0x00412851:	xorl %eax, %eax
0x00412853:	cmpl 0xe8(%ecx), %edi
0x00412859:	setne %al
0x0041285c:	movl -28(%ebp), %eax
0x0041285f:	movl -4(%ebp), %edi
0x00412862:	pushl $0x2<UINT8>
0x00412864:	popl %ebx
0x00412865:	pushl %ebx
0x00412866:	call __set_app_type@msvcrt.dll
__set_app_type@msvcrt.dll: API Node	
0x0041286c:	popl %ecx
0x0041286d:	orl 0x4289c0, $0xffffffff<UINT8>
0x00412874:	orl 0x4289c4, $0xffffffff<UINT8>
0x0041287b:	call __p__fmode@msvcrt.dll
__p__fmode@msvcrt.dll: API Node	
0x00412881:	movl %ecx, 0x419aac
0x00412887:	movl (%eax), %ecx
0x00412889:	call __p__commode@msvcrt.dll
__p__commode@msvcrt.dll: API Node	
0x0041288f:	movl %ecx, 0x419aa8
0x00412895:	movl (%eax), %ecx
0x00412897:	movl %eax, 0x413358
0x0041289c:	movl %eax, (%eax)
0x0041289e:	movl 0x4289bc, %eax
0x004128a3:	call 0x00401b34
0x00401b34:	xorl %eax, %eax
0x00401b36:	ret

0x004128a8:	cmpl 0x419000, %edi
0x004128ae:	jne 0x004128bc
0x004128bc:	call 0x004129f4
0x004129f4:	pushl $0x30000<UINT32>
0x004129f9:	pushl $0x10000<UINT32>
0x004129fe:	call 0x00412a52
0x00412a52:	jmp _controlfp@msvcrt.dll
_controlfp@msvcrt.dll: API Node	
0x00412a03:	popl %ecx
0x00412a04:	popl %ecx
0x00412a05:	ret

0x004128c1:	pushl $0x413458<UINT32>
0x004128c6:	pushl $0x413454<UINT32>
0x004128cb:	call 0x004129ee
0x004129ee:	jmp _initterm@msvcrt.dll
_initterm@msvcrt.dll: API Node	
0x004128d0:	movl %eax, 0x419aa4
0x004128d5:	movl -32(%ebp), %eax
0x004128d8:	leal %eax, -32(%ebp)
0x004128db:	pushl %eax
0x004128dc:	pushl 0x419aa0
0x004128e2:	leal %eax, -36(%ebp)
0x004128e5:	pushl %eax
0x004128e6:	leal %eax, -40(%ebp)
0x004128e9:	pushl %eax
0x004128ea:	leal %eax, -44(%ebp)
0x004128ed:	pushl %eax
0x004128ee:	call __wgetmainargs@msvcrt.dll
__wgetmainargs@msvcrt.dll: API Node	
0x004128f4:	movl -48(%ebp), %eax
0x004128f7:	pushl $0x413450<UINT32>
0x004128fc:	pushl $0x413428<UINT32>
0x00412901:	call 0x004129ee
0x00412906:	addl %esp, $0x24<UINT8>
0x00412909:	movl %eax, 0x413398
0x0041290e:	movl %esi, (%eax)
0x00412910:	cmpl %esi, %edi
0x00412912:	jne 0x00412922
0x00412922:	movl -52(%ebp), %esi
0x00412925:	cmpw (%esi), $0x22<UINT8>
0x00412929:	jne 69
0x0041292b:	addl %esi, %ebx
0x0041292d:	movl -52(%ebp), %esi
0x00412930:	movw %ax, (%esi)
0x00412933:	cmpw %ax, %di
0x00412936:	je 6
0x00412938:	cmpw %ax, $0x22<UINT16>
0x0041293c:	jne 0x0041292b
0x0041293e:	cmpw (%esi), $0x22<UINT8>
0x00412942:	jne 5
0x00412944:	addl %esi, %ebx
0x00412946:	movl -52(%ebp), %esi
0x00412949:	movw %ax, (%esi)
0x0041294c:	cmpw %ax, %di
0x0041294f:	je 6
0x00412951:	cmpw %ax, $0x20<UINT16>
0x00412955:	jbe 0x00412944
0x00412957:	movl -76(%ebp), %edi
0x0041295a:	leal %eax, -120(%ebp)
0x0041295d:	pushl %eax
0x0041295e:	call GetStartupInfoW@KERNEL32.dll
GetStartupInfoW@KERNEL32.dll: API Node	
0x00412964:	testb -76(%ebp), $0x1<UINT8>
0x00412968:	je 0x0041297d
0x0041297d:	pushl $0xa<UINT8>
0x0041297f:	popl %eax
0x00412980:	pushl %eax
0x00412981:	pushl %esi
0x00412982:	pushl %edi
0x00412983:	pushl %edi
0x00412984:	call GetModuleHandleA@KERNEL32.dll
0x0041298a:	pushl %eax
0x0041298b:	call 0x0040cec6
0x0040cec6:	pushl %ebp
0x0040cec7:	movl %ebp, %esp
0x0040cec9:	andl %esp, $0xfffffff8<UINT8>
0x0040cecc:	movl %eax, $0x316c<UINT32>
0x0040ced1:	call 0x00412a70
0x00412a70:	cmpl %eax, $0x1000<UINT32>
0x00412a75:	jae 0x00412a85
0x00412a85:	pushl %ecx
0x00412a86:	leal %ecx, 0x8(%esp)
0x00412a8a:	subl %ecx, $0x1000<UINT32>
0x00412a90:	subl %eax, $0x1000<UINT32>
0x00412a95:	testl (%ecx), %eax
0x00412a97:	cmpl %eax, $0x1000<UINT32>
0x00412a9c:	jae 0x00412a8a
0x00412a9e:	subl %ecx, %eax
0x00412aa0:	movl %eax, %esp
0x00412aa2:	testl (%ecx), %eax
0x00412aa4:	movl %esp, %ecx
0x00412aa6:	movl %ecx, (%eax)
0x00412aa8:	movl %eax, 0x4(%eax)
0x00412aab:	pushl %eax
0x00412aac:	ret

0x0040ced6:	pushl %ebx
0x0040ced7:	pushl %esi
0x0040ced8:	pushl %edi
0x0040ced9:	call 0x00402707
0x00402707:	pushl %ebp
0x00402708:	movl %ebp, %esp
0x0040270a:	pushl %ecx
0x0040270b:	pushl %ecx
0x0040270c:	pushl %ebx
0x0040270d:	pushl %esi
0x0040270e:	pushl %edi
0x0040270f:	pushl $0x413a90<UINT32>
0x00402714:	movl -8(%ebp), $0x8<UINT32>
0x0040271b:	movl -4(%ebp), $0xff<UINT32>
0x00402722:	xorl %ebx, %ebx
0x00402724:	xorl %edi, %edi
0x00402726:	call LoadLibraryW@KERNEL32.dll
LoadLibraryW@KERNEL32.dll: API Node	
0x0040272c:	movl %esi, %eax
0x0040272e:	testl %esi, %esi
0x00402730:	je 40
0x00402732:	pushl $0x413aac<UINT32>
0x00402737:	pushl %esi
0x00402738:	call GetProcAddress@KERNEL32.dll
0x0040273e:	testl %eax, %eax
0x00402740:	je 9
0x00402742:	leal %ecx, -8(%ebp)
0x00402745:	pushl %ecx
0x00402746:	incl %edi
0x00402747:	call InitCommonControlsEx@comctl32.dll
InitCommonControlsEx@comctl32.dll: API Node	
0x00402749:	movl %ebx, %eax
0x0040274b:	pushl %esi
0x0040274c:	call FreeLibrary@KERNEL32.dll
FreeLibrary@KERNEL32.dll: API Node	
0x00402752:	testl %edi, %edi
0x00402754:	je 4
0x00402756:	movl %eax, %ebx
0x00402758:	jmp 0x00402763
0x00402763:	testl %eax, %eax
0x00402765:	popl %edi
0x00402766:	popl %esi
0x00402767:	popl %ebx
0x00402768:	jne 0x00402781
0x0040276a:	pushl $0x30<UINT8>
0x00402781:	xorl %eax, %eax
0x00402783:	incl %eax
0x00402784:	leave
0x00402785:	ret

0x0040cede:	testl %eax, %eax
0x0040cee0:	jne 0x0040cee8
0x0040cee8:	call 0x0040f246
0x0040f246:	cmpl 0x41a98c, $0x0<UINT8>
0x0040f24d:	jne 37
0x0040f24f:	pushl $0x41684c<UINT32>
0x0040f254:	call LoadLibraryW@KERNEL32.dll
0x0040f25a:	testl %eax, %eax
0x0040f25c:	movl 0x41a98c, %eax
0x0040f261:	je 17
0x0040f263:	pushl $0x416864<UINT32>
0x0040f268:	pushl %eax
0x0040f269:	call GetProcAddress@KERNEL32.dll
0x0040f26f:	movl 0x41a988, %eax
0x0040f274:	ret

0x0040ceed:	xorl %ebx, %ebx
0x0040ceef:	pushl %ebx
0x0040cef0:	call CoInitialize@ole32.dll
CoInitialize@ole32.dll: API Node	
0x0040cef6:	pushl $0x8001<UINT32>
0x0040cefb:	call SetErrorMode@KERNEL32.dll
SetErrorMode@KERNEL32.dll: API Node	
0x0040cf01:	pushl %ebx
0x0040cf02:	pushl $0x40f22b<UINT32>
0x0040cf07:	pushl %ebx
0x0040cf08:	movl 0x41a230, $0x11223344<UINT32>
0x0040cf12:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x0040cf18:	pushl %eax
0x0040cf19:	call EnumResourceTypesW@KERNEL32.dll
EnumResourceTypesW@KERNEL32.dll: API Node	
0x0040cf1f:	leal %eax, 0x18(%esp)
0x0040cf23:	call 0x00405b39
0x00405b39:	xorl %ecx, %ecx
0x00405b3b:	movl 0x14(%eax), $0x400<UINT32>
0x00405b42:	movl 0x18(%eax), $0x100<UINT32>
0x00405b49:	movl (%eax), %ecx
0x00405b4b:	movl 0x4(%eax), %ecx
0x00405b4e:	movl 0xc(%eax), %ecx
0x00405b51:	movl 0x10(%eax), %ecx
0x00405b54:	movl 0x1c(%eax), %ecx
0x00405b57:	movl 0x8(%eax), %ecx
0x00405b5a:	ret

0x0040cf28:	leal %eax, 0x68(%esp)
0x0040cf2c:	movl 0x40(%esp), $0x20<UINT32>
0x0040cf34:	movl 0x38(%esp), %ebx
0x0040cf38:	movl 0x44(%esp), %ebx
0x0040cf3c:	movl 0x3c(%esp), %ebx
0x0040cf40:	movl 0x48(%esp), %ebx
0x0040cf44:	call 0x0040cbcc
0x0040cbcc:	pushl %ebx
0x0040cbcd:	pushl %ebp
0x0040cbce:	xorl %ebp, %ebp
0x0040cbd0:	pushl %esi
0x0040cbd1:	movl %esi, %eax
0x0040cbd3:	movl 0x240(%esi), %ebp
0x0040cbd9:	movl (%esi), $0x41639c<UINT32>
0x0040cbdf:	movl 0x68c(%esi), %ebp
0x0040cbe5:	leal %eax, 0x6a4(%esi)
0x0040cbeb:	pushl %edi
0x0040cbec:	movl 0xc(%eax), %ebp
0x0040cbef:	movl (%eax), %ebp
0x0040cbf1:	movl 0x4(%eax), %ebp
0x0040cbf4:	movl 0x10(%eax), $0x100<UINT32>
0x0040cbfb:	movl 0x8(%eax), %ebp
0x0040cbfe:	pushl $0x10<UINT8>
0x0040cc00:	leal %eax, 0x6d0(%esi)
0x0040cc06:	pushl %ebp
0x0040cc07:	pushl %eax
0x0040cc08:	movl 0x6cc(%esi), %ebp
0x0040cc0e:	movl 0x6bc(%esi), $0x413b60<UINT32>
0x0040cc18:	call 0x00412724
0x00412724:	jmp memset@msvcrt.dll
memset@msvcrt.dll: API Node	
0x0040cc1d:	xorl %edi, %edi
0x0040cc1f:	incl %edi
0x0040cc20:	movw 0x1104(%esi), %bp
0x0040cc27:	movl 0x3104(%esi), %edi
0x0040cc2d:	movl 0x3108(%esi), %edi
0x0040cc33:	movl 0x310c(%esi), %edi
0x0040cc39:	pushl $0x2040<UINT32>
0x0040cc3e:	movl 0x6c0(%esi), $0x72<UINT32>
0x0040cc48:	movl 0x10f8(%esi), %ebp
0x0040cc4e:	movl 0x10fc(%esi), %ebp
0x0040cc54:	call 0x00412774
0x00412774:	jmp ??2@YAPAXI@Z@msvcrt.dll
??2@YAPAXI@Z@msvcrt.dll: API Node	
0x0040cc59:	addl %esp, $0x10<UINT8>
0x0040cc5c:	cmpl %eax, %ebp
0x0040cc5e:	je 38
0x0040cc60:	movl 0x24(%eax), %edi
0x0040cc63:	movw 0x2c(%eax), %bp
0x0040cc67:	movl 0x202c(%eax), %edi
0x0040cc6d:	movl 0x2030(%eax), %edi
0x0040cc73:	movl 0x2034(%eax), %edi
0x0040cc79:	movl 0x41a238, %eax
0x0040cc7e:	movl 0x2038(%eax), %ebp
0x0040cc84:	jmp 0x0040cc88
0x0040cc88:	pushl $0x5484<UINT32>
0x0040cc8d:	movl 0x690(%esi), %eax
0x0040cc93:	call 0x00412774
0x0040cc98:	cmpl %eax, %ebp
0x0040cc9a:	popl %ecx
0x0040cc9b:	je 7
0x0040cc9d:	call 0x0040226a
0x0040226a:	pushl %ebx
0x0040226b:	pushl %esi
0x0040226c:	movl %esi, %eax
0x0040226e:	call 0x004089e8
0x004089e8:	pushl %ebx
0x004089e9:	pushl %edi
0x004089ea:	xorl %edi, %edi
0x004089ec:	pushl %esi
0x004089ed:	movl %eax, $0x338<UINT32>
0x004089f2:	movl (%esi), $0x416100<UINT32>
0x004089f8:	movl 0x328(%esi), %edi
0x004089fe:	call 0x00405488
0x00405488:	addl %eax, $0xfffffffc<UINT8>
0x0040548b:	pushl %eax
0x0040548c:	movl %eax, 0x8(%esp)
0x00405490:	addl %eax, $0x4<UINT8>
0x00405493:	pushl $0x0<UINT8>
0x00405495:	pushl %eax
0x00405496:	call 0x00412724
0x0040549b:	addl %esp, $0xc<UINT8>
0x0040549e:	ret

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
0x0040276c:	pushl $0x413ac4<UINT32>
0x00402771:	pushl $0x413ad0<UINT32>
0x00402776:	pushl %eax
0x00402777:	call MessageBoxW@USER32.dll
MessageBoxW@USER32.dll: API Node	
0x0040277d:	xorl %eax, %eax
0x0040277f:	leave
0x00402780:	ret

0x0040cee2:	incl %eax
0x0040cee3:	jmp 0x0040d134
0x0040d134:	popl %edi
0x0040d135:	popl %esi
0x0040d136:	popl %ebx
0x0040d137:	movl %esp, %ebp
0x0040d139:	popl %ebp
0x0040d13a:	ret $0x10<UINT16>

0x00412990:	movl %esi, %eax
0x00412992:	movl -124(%ebp), %esi
0x00412995:	cmpl -28(%ebp), %edi
0x00412998:	jne 7
0x0041299a:	pushl %esi
0x0041299b:	call exit@msvcrt.dll
exit@msvcrt.dll: Exit Node	
