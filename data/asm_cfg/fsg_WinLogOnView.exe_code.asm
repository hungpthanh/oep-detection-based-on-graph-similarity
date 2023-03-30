0x00428000:	movl %ebx, $0x4001d0<UINT32>
0x00428005:	movl %edi, $0x401000<UINT32>
0x0042800a:	movl %esi, $0x41ca38<UINT32>
0x0042800f:	pushl %ebx
0x00428010:	call 0x0042801f
0x0042801f:	cld
0x00428020:	movb %dl, $0xffffff80<UINT8>
0x00428022:	movsb %es:(%edi), %ds:(%esi)
0x00428023:	pushl $0x2<UINT8>
0x00428025:	popl %ebx
0x00428026:	call 0x00428015
0x00428015:	addb %dl, %dl
0x00428017:	jne 0x0042801e
0x00428019:	movb %dl, (%esi)
0x0042801b:	incl %esi
0x0042801c:	adcb %dl, %dl
0x0042801e:	ret

0x00428029:	jae 0x00428022
0x0042802b:	xorl %ecx, %ecx
0x0042802d:	call 0x00428015
0x00428030:	jae 0x0042804a
0x00428032:	xorl %eax, %eax
0x00428034:	call 0x00428015
0x00428037:	jae 0x0042805a
0x00428039:	movb %bl, $0x2<UINT8>
0x0042803b:	incl %ecx
0x0042803c:	movb %al, $0x10<UINT8>
0x0042803e:	call 0x00428015
0x00428041:	adcb %al, %al
0x00428043:	jae 0x0042803e
0x00428045:	jne 0x00428086
0x00428086:	pushl %esi
0x00428087:	movl %esi, %edi
0x00428089:	subl %esi, %eax
0x0042808b:	rep movsb %es:(%edi), %ds:(%esi)
0x0042808d:	popl %esi
0x0042808e:	jmp 0x00428026
0x00428047:	stosb %es:(%edi), %al
0x00428048:	jmp 0x00428026
0x0042805a:	lodsb %al, %ds:(%esi)
0x0042805b:	shrl %eax
0x0042805d:	je 0x004280a0
0x0042805f:	adcl %ecx, %ecx
0x00428061:	jmp 0x0042807f
0x0042807f:	incl %ecx
0x00428080:	incl %ecx
0x00428081:	xchgl %ebp, %eax
0x00428082:	movl %eax, %ebp
0x00428084:	movb %bl, $0x1<UINT8>
0x0042804a:	call 0x00428092
0x00428092:	incl %ecx
0x00428093:	call 0x00428015
0x00428097:	adcl %ecx, %ecx
0x00428099:	call 0x00428015
0x0042809d:	jb 0x00428093
0x0042809f:	ret

0x0042804f:	subl %ecx, %ebx
0x00428051:	jne 0x00428063
0x00428063:	xchgl %ecx, %eax
0x00428064:	decl %eax
0x00428065:	shll %eax, $0x8<UINT8>
0x00428068:	lodsb %al, %ds:(%esi)
0x00428069:	call 0x00428090
0x00428090:	xorl %ecx, %ecx
0x0042806e:	cmpl %eax, $0x7d00<UINT32>
0x00428073:	jae 0x0042807f
0x00428075:	cmpb %ah, $0x5<UINT8>
0x00428078:	jae 0x00428080
0x0042807a:	cmpl %eax, $0x7f<UINT8>
0x0042807d:	ja 0x00428081
0x00428053:	call 0x00428090
0x00428058:	jmp 0x00428082
0x004280a0:	popl %edi
0x004280a1:	popl %ebx
0x004280a2:	movzwl %edi, (%ebx)
0x004280a5:	decl %edi
0x004280a6:	je 0x004280b0
0x004280a8:	decl %edi
0x004280a9:	je 0x004280be
0x004280ab:	shll %edi, $0xc<UINT8>
0x004280ae:	jmp 0x004280b7
0x004280b7:	incl %ebx
0x004280b8:	incl %ebx
0x004280b9:	jmp 0x0042800f
0x004280b0:	movl %edi, 0x2(%ebx)
0x004280b3:	pushl %edi
0x004280b4:	addl %ebx, $0x4<UINT8>
0x004280be:	popl %edi
0x004280bf:	movl %ebx, $0x428128<UINT32>
0x004280c4:	incl %edi
0x004280c5:	movl %esi, (%edi)
0x004280c7:	scasl %eax, %es:(%edi)
0x004280c8:	pushl %edi
0x004280c9:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004280cb:	xchgl %ebp, %eax
0x004280cc:	xorl %eax, %eax
0x004280ce:	scasb %al, %es:(%edi)
0x004280cf:	jne 0x004280ce
0x004280d1:	decb (%edi)
0x004280d3:	je 0x004280c4
0x004280d5:	decb (%edi)
0x004280d7:	jne 0x004280df
0x004280df:	decb (%edi)
0x004280e1:	je 0x0040df4a
0x004280e7:	pushl %edi
0x004280e8:	pushl %ebp
0x004280e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x004280ec:	orl (%esi), %eax
0x004280ee:	lodsl %eax, %ds:(%esi)
0x004280ef:	jne 0x004280cc
0x004280d9:	incl %edi
0x004280da:	pushl (%edi)
0x004280dc:	scasl %eax, %es:(%edi)
0x004280dd:	jmp 0x004280e8
GetProcAddress@KERNEL32.dll: API Node	
0x0040df4a:	pushl $0x70<UINT8>
0x0040df4c:	pushl $0x40f3f0<UINT32>
0x0040df51:	call 0x0040e158
0x0040e158:	pushl $0x40e1a8<UINT32>
0x0040e15d:	movl %eax, %fs:0
0x0040e163:	pushl %eax
0x0040e164:	movl %fs:0, %esp
0x0040e16b:	movl %eax, 0x10(%esp)
0x0040e16f:	movl 0x10(%esp), %ebp
0x0040e173:	leal %ebp, 0x10(%esp)
0x0040e177:	subl %esp, %eax
0x0040e179:	pushl %ebx
0x0040e17a:	pushl %esi
0x0040e17b:	pushl %edi
0x0040e17c:	movl %eax, -8(%ebp)
0x0040e17f:	movl -24(%ebp), %esp
0x0040e182:	pushl %eax
0x0040e183:	movl %eax, -4(%ebp)
0x0040e186:	movl -4(%ebp), $0xffffffff<UINT32>
0x0040e18d:	movl -8(%ebp), %eax
0x0040e190:	ret

0x0040df56:	xorl %edi, %edi
0x0040df58:	pushl %edi
0x0040df59:	call GetModuleHandleA@KERNEL32.dll
GetModuleHandleA@KERNEL32.dll: API Node	
0x0040df5f:	cmpw (%eax), $0x5a4d<UINT16>
0x0040df64:	jne 31
0x0040df66:	movl %ecx, 0x3c(%eax)
0x0040df69:	addl %ecx, %eax
0x0040df6b:	cmpl (%ecx), $0x4550<UINT32>
0x0040df71:	jne 18
0x0040df73:	movzwl %eax, 0x18(%ecx)
0x0040df77:	cmpl %eax, $0x10b<UINT32>
0x0040df7c:	je 0x0040df9d
0x0040df9d:	cmpl 0x74(%ecx), $0xe<UINT8>
0x0040dfa1:	jbe -30
0x0040dfa3:	xorl %eax, %eax
0x0040dfa5:	cmpl 0xe8(%ecx), %edi
0x0040dfab:	setne %al
0x0040dfae:	movl -28(%ebp), %eax
0x0040dfb1:	movl -4(%ebp), %edi
0x0040dfb4:	pushl $0x2<UINT8>
0x0040dfb6:	popl %ebx
0x0040dfb7:	pushl %ebx
0x0040dfb8:	call __set_app_type@msvcrt.dll
__set_app_type@msvcrt.dll: API Node	
0x0040dfbe:	popl %ecx
0x0040dfbf:	orl 0x414a9c, $0xffffffff<UINT8>
0x0040dfc6:	orl 0x414aa0, $0xffffffff<UINT8>
0x0040dfcd:	call __p__fmode@msvcrt.dll
__p__fmode@msvcrt.dll: API Node	
0x0040dfd3:	movl %ecx, 0x4132cc
0x0040dfd9:	movl (%eax), %ecx
0x0040dfdb:	call __p__commode@msvcrt.dll
__p__commode@msvcrt.dll: API Node	
0x0040dfe1:	movl %ecx, 0x4132c8
0x0040dfe7:	movl (%eax), %ecx
0x0040dfe9:	movl %eax, 0x40f2d4
0x0040dfee:	movl %eax, (%eax)
0x0040dff0:	movl 0x414a98, %eax
0x0040dff5:	call 0x0040ca03
0x0040ca03:	xorl %eax, %eax
0x0040ca05:	ret

0x0040dffa:	cmpl 0x413000, %edi
0x0040e000:	jne 0x0040e00e
0x0040e00e:	call 0x0040e146
0x0040e146:	pushl $0x30000<UINT32>
0x0040e14b:	pushl $0x10000<UINT32>
0x0040e150:	call 0x0040e1a2
0x0040e1a2:	jmp _controlfp@msvcrt.dll
_controlfp@msvcrt.dll: API Node	
0x0040e155:	popl %ecx
0x0040e156:	popl %ecx
0x0040e157:	ret

0x0040e013:	pushl $0x40f3c4<UINT32>
0x0040e018:	pushl $0x40f3c0<UINT32>
0x0040e01d:	call 0x0040e140
0x0040e140:	jmp _initterm@msvcrt.dll
_initterm@msvcrt.dll: API Node	
0x0040e022:	movl %eax, 0x4132c4
0x0040e027:	movl -32(%ebp), %eax
0x0040e02a:	leal %eax, -32(%ebp)
0x0040e02d:	pushl %eax
0x0040e02e:	pushl 0x4132c0
0x0040e034:	leal %eax, -36(%ebp)
0x0040e037:	pushl %eax
0x0040e038:	leal %eax, -40(%ebp)
0x0040e03b:	pushl %eax
0x0040e03c:	leal %eax, -44(%ebp)
0x0040e03f:	pushl %eax
0x0040e040:	call __wgetmainargs@msvcrt.dll
__wgetmainargs@msvcrt.dll: API Node	
0x0040e046:	movl -48(%ebp), %eax
0x0040e049:	pushl $0x40f3bc<UINT32>
0x0040e04e:	pushl $0x40f398<UINT32>
0x0040e053:	call 0x0040e140
0x0040e058:	addl %esp, $0x24<UINT8>
0x0040e05b:	movl %eax, 0x40f2e4
0x0040e060:	movl %esi, (%eax)
0x0040e062:	cmpl %esi, %edi
0x0040e064:	jne 0x0040e074
0x0040e074:	movl -52(%ebp), %esi
0x0040e077:	cmpw (%esi), $0x22<UINT8>
0x0040e07b:	jne 69
0x0040e07d:	addl %esi, %ebx
0x0040e07f:	movl -52(%ebp), %esi
0x0040e082:	movw %ax, (%esi)
0x0040e085:	cmpw %ax, %di
0x0040e088:	je 6
0x0040e08a:	cmpw %ax, $0x22<UINT16>
0x0040e08e:	jne 0x0040e07d
0x0040e090:	cmpw (%esi), $0x22<UINT8>
0x0040e094:	jne 5
0x0040e096:	addl %esi, %ebx
0x0040e098:	movl -52(%ebp), %esi
0x0040e09b:	movw %ax, (%esi)
0x0040e09e:	cmpw %ax, %di
0x0040e0a1:	je 6
0x0040e0a3:	cmpw %ax, $0x20<UINT16>
0x0040e0a7:	jbe 0x0040e096
0x0040e0a9:	movl -76(%ebp), %edi
0x0040e0ac:	leal %eax, -120(%ebp)
0x0040e0af:	pushl %eax
0x0040e0b0:	call GetStartupInfoW@KERNEL32.dll
GetStartupInfoW@KERNEL32.dll: API Node	
0x0040e0b6:	testb -76(%ebp), $0x1<UINT8>
0x0040e0ba:	je 0x0040e0cf
0x0040e0cf:	pushl $0xa<UINT8>
0x0040e0d1:	popl %eax
0x0040e0d2:	pushl %eax
0x0040e0d3:	pushl %esi
0x0040e0d4:	pushl %edi
0x0040e0d5:	pushl %edi
0x0040e0d6:	call GetModuleHandleA@KERNEL32.dll
0x0040e0dc:	pushl %eax
0x0040e0dd:	call 0x00409a43
0x00409a43:	pushl %ebp
0x00409a44:	movl %ebp, %esp
0x00409a46:	subl %esp, $0x704<UINT32>
0x00409a4c:	call 0x00402146
0x00402146:	pushl %ebp
0x00402147:	movl %ebp, %esp
0x00402149:	pushl %ecx
0x0040214a:	pushl %ecx
0x0040214b:	pushl %ebx
0x0040214c:	pushl %esi
0x0040214d:	pushl %edi
0x0040214e:	pushl $0x40f6c8<UINT32>
0x00402153:	movl -8(%ebp), $0x8<UINT32>
0x0040215a:	movl -4(%ebp), $0xff<UINT32>
0x00402161:	xorl %ebx, %ebx
0x00402163:	xorl %edi, %edi
0x00402165:	call LoadLibraryW@KERNEL32.dll
LoadLibraryW@KERNEL32.dll: API Node	
0x0040216b:	movl %esi, %eax
0x0040216d:	testl %esi, %esi
0x0040216f:	je 40
0x00402171:	pushl $0x40f6e4<UINT32>
0x00402176:	pushl %esi
0x00402177:	call GetProcAddress@KERNEL32.dll
0x0040217d:	testl %eax, %eax
0x0040217f:	je 9
0x00402181:	leal %ecx, -8(%ebp)
0x00402184:	pushl %ecx
0x00402185:	incl %edi
0x00402186:	call InitCommonControlsEx@comctl32.dll
InitCommonControlsEx@comctl32.dll: API Node	
0x00402188:	movl %ebx, %eax
0x0040218a:	pushl %esi
0x0040218b:	call FreeLibrary@KERNEL32.dll
FreeLibrary@KERNEL32.dll: API Node	
0x00402191:	testl %edi, %edi
0x00402193:	je 4
0x00402195:	movl %eax, %ebx
0x00402197:	jmp 0x004021a2
0x004021a2:	testl %eax, %eax
0x004021a4:	popl %edi
0x004021a5:	popl %esi
0x004021a6:	popl %ebx
0x004021a7:	jne 0x004021c0
0x004021a9:	pushl $0x30<UINT8>
0x004021c0:	xorl %eax, %eax
0x004021c2:	incl %eax
0x004021c3:	leave
0x004021c4:	ret

0x00409a51:	testl %eax, %eax
0x00409a53:	jne 0x00409a5b
0x00409a5b:	pushl %ebx
0x00409a5c:	pushl %esi
0x00409a5d:	call 0x0040acee
0x0040acee:	cmpl 0x4141a8, $0x0<UINT8>
0x0040acf5:	jne 37
0x0040acf7:	pushl $0x4105e8<UINT32>
0x0040acfc:	call LoadLibraryW@KERNEL32.dll
0x0040ad02:	testl %eax, %eax
0x0040ad04:	movl 0x4141a8, %eax
0x0040ad09:	je 17
0x0040ad0b:	pushl $0x410600<UINT32>
0x0040ad10:	pushl %eax
0x0040ad11:	call GetProcAddress@KERNEL32.dll
0x0040ad17:	movl 0x4141a4, %eax
0x0040ad1c:	ret

0x00409a62:	pushl $0x8001<UINT32>
0x00409a67:	call SetErrorMode@KERNEL32.dll
SetErrorMode@KERNEL32.dll: API Node	
0x00409a6d:	xorl %ebx, %ebx
0x00409a6f:	pushl %ebx
0x00409a70:	pushl $0x40acd3<UINT32>
0x00409a75:	pushl %ebx
0x00409a76:	movl 0x413a50, $0x11223344<UINT32>
0x00409a80:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x00409a86:	pushl %eax
0x00409a87:	call EnumResourceTypesW@KERNEL32.dll
EnumResourceTypesW@KERNEL32.dll: API Node	
0x00409a8d:	leal %eax, -52(%ebp)
0x00409a90:	call 0x0040457c
0x0040457c:	xorl %ecx, %ecx
0x0040457e:	movl 0x14(%eax), $0x400<UINT32>
0x00404585:	movl 0x18(%eax), $0x100<UINT32>
0x0040458c:	movl (%eax), %ecx
0x0040458e:	movl 0x4(%eax), %ecx
0x00404591:	movl 0xc(%eax), %ecx
0x00404594:	movl 0x10(%eax), %ecx
0x00404597:	movl 0x1c(%eax), %ecx
0x0040459a:	movl 0x8(%eax), %ecx
0x0040459d:	ret

0x00409a95:	leal %eax, -1796(%ebp)
0x00409a9b:	pushl %eax
0x00409a9c:	movl -12(%ebp), $0x20<UINT32>
0x00409aa3:	movl -20(%ebp), %ebx
0x00409aa6:	movl -8(%ebp), %ebx
0x00409aa9:	movl -16(%ebp), %ebx
0x00409aac:	movl -4(%ebp), %ebx
0x00409aaf:	call 0x00409803
0x00409803:	pushl %ebx
0x00409804:	pushl %ebp
0x00409805:	movl %ebp, 0xc(%esp)
0x00409809:	pushl %esi
0x0040980a:	pushl %edi
0x0040980b:	xorl %edi, %edi
0x0040980d:	movl 0x208(%ebp), %edi
0x00409813:	movl 0x244(%ebp), %edi
0x00409819:	movl 0x274(%ebp), %edi
0x0040981f:	movl 0x240(%ebp), %edi
0x00409825:	movl (%ebp), $0x410304<UINT32>
0x0040982c:	movl 0x694(%ebp), %edi
0x00409832:	pushl $0x238c<UINT32>
0x00409837:	movl 0x6ac(%ebp), %edi
0x0040983d:	call 0x0040dee4
0x0040dee4:	jmp ??2@YAPAXI@Z@msvcrt.dll
??2@YAPAXI@Z@msvcrt.dll: API Node	
0x00409842:	cmpl %eax, %edi
0x00409844:	popl %ecx
0x00409845:	je 9
0x00409847:	movl %esi, %eax
0x00409849:	call 0x00401b81
0x00401b81:	xorl %eax, %eax
0x00401b83:	incl %eax
0x00401b84:	xorl %ecx, %ecx
0x00401b86:	pushl $0x5c<UINT8>
0x00401b88:	movl 0x1c(%esi), %eax
0x00401b8b:	movl 0x32c(%esi), %eax
0x00401b91:	pushl %ecx
0x00401b92:	leal %eax, 0x2330(%esi)
0x00401b98:	pushl %eax
0x00401b99:	movw 0x20(%esi), %cx
0x00401b9d:	movw 0x330(%esi), %cx
0x00401ba4:	movw 0x120(%esi), %cx
0x00401bab:	movl 0x413a54, %esi
0x00401bb1:	call 0x0040deb4
0x0040deb4:	jmp memset@msvcrt.dll
memset@msvcrt.dll: API Node	
0x00401bb6:	addl %esp, $0xc<UINT8>
0x00401bb9:	movl %eax, %esi
0x00401bbb:	ret

0x0018fed8:	jl -1
0x0018feda:	sbbb (%eax), %al
0x0018fedc:	loop 0x0018febe
0x0018febe:	addb (%eax), %al
0x0018fec0:	addb (%eax), %al
0x0018fec2:	addb (%eax), %al
0x0018fec4:	addb (%eax), %al
0x0018fec6:	addb (%eax), %al
0x0018fec8:	addb (%eax), %al
0x0018feca:	addb (%eax), %al
0x0018fecc:	andb (%eax), %al
0x0018fece:	addb (%eax), %al
0x0018fed0:	addb (%eax), %al
0x0018fed2:	addb (%eax), %al
0x0018fed4:	addb (%eax), %al
0x0018fed6:	addb (%eax), %al
0x004021ab:	pushl $0x40f6fc<UINT32>
0x004021b0:	pushl $0x40f708<UINT32>
0x004021b5:	pushl %eax
0x004021b6:	call MessageBoxW@USER32.dll
MessageBoxW@USER32.dll: API Node	
0x004021bc:	xorl %eax, %eax
0x004021be:	leave
0x004021bf:	ret

0x00409a55:	incl %eax
0x00409a56:	jmp 0x00409c79
0x00409c79:	leave
0x00409c7a:	ret $0x10<UINT16>

0x0040e0e2:	movl %esi, %eax
0x0040e0e4:	movl -124(%ebp), %esi
0x0040e0e7:	cmpl -28(%ebp), %edi
0x0040e0ea:	jne 7
0x0040e0ec:	pushl %esi
0x0040e0ed:	call exit@msvcrt.dll
exit@msvcrt.dll: Exit Node	
