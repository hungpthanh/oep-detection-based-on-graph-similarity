0x0041f0b0:	pusha
0x0041f0b1:	movl %esi, $0x414000<UINT32>
0x0041f0b6:	leal %edi, -77824(%esi)
0x0041f0bc:	pushl %edi
0x0041f0bd:	orl %ebp, $0xffffffff<UINT8>
0x0041f0c0:	jmp 0x0041f0d2
0x0041f0d2:	movl %ebx, (%esi)
0x0041f0d4:	subl %esi, $0xfffffffc<UINT8>
0x0041f0d7:	adcl %ebx, %ebx
0x0041f0d9:	jb 0x0041f0c8
0x0041f0c8:	movb %al, (%esi)
0x0041f0ca:	incl %esi
0x0041f0cb:	movb (%edi), %al
0x0041f0cd:	incl %edi
0x0041f0ce:	addl %ebx, %ebx
0x0041f0d0:	jne 0x0041f0d9
0x0041f0db:	movl %eax, $0x1<UINT32>
0x0041f0e0:	addl %ebx, %ebx
0x0041f0e2:	jne 0x0041f0eb
0x0041f0eb:	adcl %eax, %eax
0x0041f0ed:	addl %ebx, %ebx
0x0041f0ef:	jae 0x0041f0e0
0x0041f0f1:	jne 0x0041f0fc
0x0041f0fc:	xorl %ecx, %ecx
0x0041f0fe:	subl %eax, $0x3<UINT8>
0x0041f101:	jb 0x0041f110
0x0041f110:	addl %ebx, %ebx
0x0041f112:	jne 0x0041f11b
0x0041f11b:	adcl %ecx, %ecx
0x0041f11d:	addl %ebx, %ebx
0x0041f11f:	jne 0x0041f128
0x0041f128:	adcl %ecx, %ecx
0x0041f12a:	jne 0x0041f14c
0x0041f14c:	cmpl %ebp, $0xfffff300<UINT32>
0x0041f152:	adcl %ecx, $0x1<UINT8>
0x0041f155:	leal %edx, (%edi,%ebp)
0x0041f158:	cmpl %ebp, $0xfffffffc<UINT8>
0x0041f15b:	jbe 0x0041f16c
0x0041f15d:	movb %al, (%edx)
0x0041f15f:	incl %edx
0x0041f160:	movb (%edi), %al
0x0041f162:	incl %edi
0x0041f163:	decl %ecx
0x0041f164:	jne 0x0041f15d
0x0041f166:	jmp 0x0041f0ce
0x0041f103:	shll %eax, $0x8<UINT8>
0x0041f106:	movb %al, (%esi)
0x0041f108:	incl %esi
0x0041f109:	xorl %eax, $0xffffffff<UINT8>
0x0041f10c:	je 0x0041f182
0x0041f10e:	movl %ebp, %eax
0x0041f16c:	movl %eax, (%edx)
0x0041f16e:	addl %edx, $0x4<UINT8>
0x0041f171:	movl (%edi), %eax
0x0041f173:	addl %edi, $0x4<UINT8>
0x0041f176:	subl %ecx, $0x4<UINT8>
0x0041f179:	ja 0x0041f16c
0x0041f17b:	addl %edi, %ecx
0x0041f17d:	jmp 0x0041f0ce
0x0041f0e4:	movl %ebx, (%esi)
0x0041f0e6:	subl %esi, $0xfffffffc<UINT8>
0x0041f0e9:	adcl %ebx, %ebx
0x0041f0f3:	movl %ebx, (%esi)
0x0041f0f5:	subl %esi, $0xfffffffc<UINT8>
0x0041f0f8:	adcl %ebx, %ebx
0x0041f0fa:	jae 0x0041f0e0
0x0041f121:	movl %ebx, (%esi)
0x0041f123:	subl %esi, $0xfffffffc<UINT8>
0x0041f126:	adcl %ebx, %ebx
0x0041f12c:	incl %ecx
0x0041f12d:	addl %ebx, %ebx
0x0041f12f:	jne 0x0041f138
0x0041f138:	adcl %ecx, %ecx
0x0041f13a:	addl %ebx, %ebx
0x0041f13c:	jae 0x0041f12d
0x0041f13e:	jne 0x0041f149
0x0041f149:	addl %ecx, $0x2<UINT8>
0x0041f131:	movl %ebx, (%esi)
0x0041f133:	subl %esi, $0xfffffffc<UINT8>
0x0041f136:	adcl %ebx, %ebx
0x0041f114:	movl %ebx, (%esi)
0x0041f116:	subl %esi, $0xfffffffc<UINT8>
0x0041f119:	adcl %ebx, %ebx
0x0041f140:	movl %ebx, (%esi)
0x0041f142:	subl %esi, $0xfffffffc<UINT8>
0x0041f145:	adcl %ebx, %ebx
0x0041f147:	jae 0x0041f12d
0x0041f182:	popl %esi
0x0041f183:	movl %edi, %esi
0x0041f185:	movl %ecx, $0x749<UINT32>
0x0041f18a:	movb %al, (%edi)
0x0041f18c:	incl %edi
0x0041f18d:	subb %al, $0xffffffe8<UINT8>
0x0041f18f:	cmpb %al, $0x1<UINT8>
0x0041f191:	ja 0x0041f18a
0x0041f193:	cmpb (%edi), $0x7<UINT8>
0x0041f196:	jne 0x0041f18a
0x0041f198:	movl %eax, (%edi)
0x0041f19a:	movb %bl, 0x4(%edi)
0x0041f19d:	shrw %ax, $0x8<UINT8>
0x0041f1a1:	roll %eax, $0x10<UINT8>
0x0041f1a4:	xchgb %ah, %al
0x0041f1a6:	subl %eax, %edi
0x0041f1a8:	subb %bl, $0xffffffe8<UINT8>
0x0041f1ab:	addl %eax, %esi
0x0041f1ad:	movl (%edi), %eax
0x0041f1af:	addl %edi, $0x5<UINT8>
0x0041f1b2:	movb %al, %bl
0x0041f1b4:	loop 0x0041f18f
0x0041f1b6:	leal %edi, 0x1d000(%esi)
0x0041f1bc:	movl %eax, (%edi)
0x0041f1be:	orl %eax, %eax
0x0041f1c0:	je 0x0041f207
0x0041f1c2:	movl %ebx, 0x4(%edi)
0x0041f1c5:	leal %eax, 0x20fdc(%eax,%esi)
0x0041f1cc:	addl %ebx, %esi
0x0041f1ce:	pushl %eax
0x0041f1cf:	addl %edi, $0x8<UINT8>
0x0041f1d2:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0041f1d8:	xchgl %ebp, %eax
0x0041f1d9:	movb %al, (%edi)
0x0041f1db:	incl %edi
0x0041f1dc:	orb %al, %al
0x0041f1de:	je 0x0041f1bc
0x0041f1e0:	movl %ecx, %edi
0x0041f1e2:	jns 0x0041f1eb
0x0041f1eb:	pushl %edi
0x0041f1ec:	decl %eax
0x0041f1ed:	repn scasb %al, %es:(%edi)
0x0041f1ef:	pushl %ebp
0x0041f1f0:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0041f1f6:	orl %eax, %eax
0x0041f1f8:	je 7
0x0041f1fa:	movl (%ebx), %eax
0x0041f1fc:	addl %ebx, $0x4<UINT8>
0x0041f1ff:	jmp 0x0041f1d9
GetProcAddress@KERNEL32.DLL: API Node	
0x0041f1e4:	movzwl %eax, (%edi)
0x0041f1e7:	incl %edi
0x0041f1e8:	pushl %eax
0x0041f1e9:	incl %edi
0x0041f1ea:	movl %ecx, $0xaef24857<UINT32>
0x0041f207:	movl %ebp, 0x210e4(%esi)
0x0041f20d:	leal %edi, -4096(%esi)
0x0041f213:	movl %ebx, $0x1000<UINT32>
0x0041f218:	pushl %eax
0x0041f219:	pushl %esp
0x0041f21a:	pushl $0x4<UINT8>
0x0041f21c:	pushl %ebx
0x0041f21d:	pushl %edi
0x0041f21e:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0041f220:	leal %eax, 0x20f(%edi)
0x0041f226:	andb (%eax), $0x7f<UINT8>
0x0041f229:	andb 0x28(%eax), $0x7f<UINT8>
0x0041f22d:	popl %eax
0x0041f22e:	pushl %eax
0x0041f22f:	pushl %esp
0x0041f230:	pushl %eax
0x0041f231:	pushl %ebx
0x0041f232:	pushl %edi
0x0041f233:	call VirtualProtect@kernel32.dll
0x0041f235:	popl %eax
0x0041f236:	popa
0x0041f237:	leal %eax, -128(%esp)
0x0041f23b:	pushl $0x0<UINT8>
0x0041f23d:	cmpl %esp, %eax
0x0041f23f:	jne 0x0041f23b
0x0041f241:	subl %esp, $0xffffff80<UINT8>
0x0041f244:	jmp 0x004109f0
0x004109f0:	pushl $0x70<UINT8>
0x004109f2:	pushl $0x411450<UINT32>
0x004109f7:	call 0x00410c04
0x00410c04:	pushl $0x410c54<UINT32>
0x00410c09:	movl %eax, %fs:0
0x00410c0f:	pushl %eax
0x00410c10:	movl %fs:0, %esp
0x00410c17:	movl %eax, 0x10(%esp)
0x00410c1b:	movl 0x10(%esp), %ebp
0x00410c1f:	leal %ebp, 0x10(%esp)
0x00410c23:	subl %esp, %eax
0x00410c25:	pushl %ebx
0x00410c26:	pushl %esi
0x00410c27:	pushl %edi
0x00410c28:	movl %eax, -8(%ebp)
0x00410c2b:	movl -24(%ebp), %esp
0x00410c2e:	pushl %eax
0x00410c2f:	movl %eax, -4(%ebp)
0x00410c32:	movl -4(%ebp), $0xffffffff<UINT32>
0x00410c39:	movl -8(%ebp), %eax
0x00410c3c:	ret

0x004109fc:	xorl %edi, %edi
0x004109fe:	pushl %edi
0x004109ff:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x00410a05:	cmpw (%eax), $0x5a4d<UINT16>
0x00410a0a:	jne 31
0x00410a0c:	movl %ecx, 0x3c(%eax)
0x00410a0f:	addl %ecx, %eax
0x00410a11:	cmpl (%ecx), $0x4550<UINT32>
0x00410a17:	jne 18
0x00410a19:	movzwl %eax, 0x18(%ecx)
0x00410a1d:	cmpl %eax, $0x10b<UINT32>
0x00410a22:	je 0x00410a43
0x00410a43:	cmpl 0x74(%ecx), $0xe<UINT8>
0x00410a47:	jbe -30
0x00410a49:	xorl %eax, %eax
0x00410a4b:	cmpl 0xe8(%ecx), %edi
0x00410a51:	setne %al
0x00410a54:	movl -28(%ebp), %eax
0x00410a57:	movl -4(%ebp), %edi
0x00410a5a:	pushl $0x2<UINT8>
0x00410a5c:	popl %ebx
0x00410a5d:	pushl %ebx
0x00410a5e:	call __set_app_type@msvcrt.dll
__set_app_type@msvcrt.dll: API Node	
0x00410a64:	popl %ecx
0x00410a65:	orl 0x416e48, $0xffffffff<UINT8>
0x00410a6c:	orl 0x416e4c, $0xffffffff<UINT8>
0x00410a73:	call __p__fmode@msvcrt.dll
__p__fmode@msvcrt.dll: API Node	
0x00410a79:	movl %ecx, 0x4158cc
0x00410a7f:	movl (%eax), %ecx
0x00410a81:	call __p__commode@msvcrt.dll
__p__commode@msvcrt.dll: API Node	
0x00410a87:	movl %ecx, 0x4158c8
0x00410a8d:	movl (%eax), %ecx
0x00410a8f:	movl %eax, 0x411384
0x00410a94:	movl %eax, (%eax)
0x00410a96:	movl 0x416e44, %eax
0x00410a9b:	call 0x00410bfe
0x00410bfe:	xorl %eax, %eax
0x00410c00:	ret

0x00410aa0:	cmpl 0x415000, %edi
0x00410aa6:	jne 0x00410ab4
0x00410ab4:	call 0x00410bec
0x00410bec:	pushl $0x30000<UINT32>
0x00410bf1:	pushl $0x10000<UINT32>
0x00410bf6:	call 0x00410c4e
0x00410c4e:	jmp _controlfp@msvcrt.dll
_controlfp@msvcrt.dll: API Node	
0x00410bfb:	popl %ecx
0x00410bfc:	popl %ecx
0x00410bfd:	ret

0x00410ab9:	pushl $0x411420<UINT32>
0x00410abe:	pushl $0x41141c<UINT32>
0x00410ac3:	call 0x00410be6
0x00410be6:	jmp _initterm@msvcrt.dll
_initterm@msvcrt.dll: API Node	
0x00410ac8:	movl %eax, 0x4158c4
0x00410acd:	movl -32(%ebp), %eax
0x00410ad0:	leal %eax, -32(%ebp)
0x00410ad3:	pushl %eax
0x00410ad4:	pushl 0x4158c0
0x00410ada:	leal %eax, -36(%ebp)
0x00410add:	pushl %eax
0x00410ade:	leal %eax, -40(%ebp)
0x00410ae1:	pushl %eax
0x00410ae2:	leal %eax, -44(%ebp)
0x00410ae5:	pushl %eax
0x00410ae6:	call __wgetmainargs@msvcrt.dll
__wgetmainargs@msvcrt.dll: API Node	
0x00410aec:	movl -48(%ebp), %eax
0x00410aef:	pushl $0x411418<UINT32>
0x00410af4:	pushl $0x4113e8<UINT32>
0x00410af9:	call 0x00410be6
0x00410afe:	addl %esp, $0x24<UINT8>
0x00410b01:	movl %eax, 0x411344
0x00410b06:	movl %esi, (%eax)
0x00410b08:	cmpl %esi, %edi
0x00410b0a:	jne 0x00410b1a
0x00410b1a:	movl -52(%ebp), %esi
0x00410b1d:	cmpw (%esi), $0x22<UINT8>
0x00410b21:	jne 69
0x00410b23:	addl %esi, %ebx
0x00410b25:	movl -52(%ebp), %esi
0x00410b28:	movw %ax, (%esi)
0x00410b2b:	cmpw %ax, %di
0x00410b2e:	je 6
0x00410b30:	cmpw %ax, $0x22<UINT16>
0x00410b34:	jne 0x00410b23
0x00410b36:	cmpw (%esi), $0x22<UINT8>
0x00410b3a:	jne 5
0x00410b3c:	addl %esi, %ebx
0x00410b3e:	movl -52(%ebp), %esi
0x00410b41:	movw %ax, (%esi)
0x00410b44:	cmpw %ax, %di
0x00410b47:	je 6
0x00410b49:	cmpw %ax, $0x20<UINT16>
0x00410b4d:	jbe 0x00410b3c
0x00410b4f:	movl -76(%ebp), %edi
0x00410b52:	leal %eax, -120(%ebp)
0x00410b55:	pushl %eax
0x00410b56:	call GetStartupInfoW@KERNEL32.DLL
GetStartupInfoW@KERNEL32.DLL: API Node	
0x00410b5c:	testb -76(%ebp), $0x1<UINT8>
0x00410b60:	je 0x00410b75
0x00410b75:	pushl $0xa<UINT8>
0x00410b77:	popl %eax
0x00410b78:	pushl %eax
0x00410b79:	pushl %esi
0x00410b7a:	pushl %edi
0x00410b7b:	pushl %edi
0x00410b7c:	call GetModuleHandleA@KERNEL32.DLL
0x00410b82:	pushl %eax
0x00410b83:	call 0x0040ddb6
0x0040ddb6:	pushl %ebp
0x0040ddb7:	movl %ebp, %esp
0x0040ddb9:	movl %eax, $0x12ac<UINT32>
0x0040ddbe:	call 0x00410cc0
0x00410cc0:	cmpl %eax, $0x1000<UINT32>
0x00410cc5:	jae 0x00410cd5
0x00410cd5:	pushl %ecx
0x00410cd6:	leal %ecx, 0x8(%esp)
0x00410cda:	subl %ecx, $0x1000<UINT32>
0x00410ce0:	subl %eax, $0x1000<UINT32>
0x00410ce5:	testl (%ecx), %eax
0x00410ce7:	cmpl %eax, $0x1000<UINT32>
0x00410cec:	jae -20
0x00410cee:	subl %ecx, %eax
0x00410cf0:	movl %eax, %esp
0x00410cf2:	testl (%ecx), %eax
0x00410cf4:	movl %esp, %ecx
0x00410cf6:	movl %ecx, (%eax)
0x00410cf8:	movl %eax, 0x4(%eax)
0x00410cfb:	pushl %eax
0x00410cfc:	ret

0x0040ddc3:	call 0x00402b36
0x00402b36:	pushl %ebp
0x00402b37:	movl %ebp, %esp
0x00402b39:	pushl %ecx
0x00402b3a:	pushl %ecx
0x00402b3b:	pushl %ebx
0x00402b3c:	pushl %esi
0x00402b3d:	pushl %edi
0x00402b3e:	pushl $0x4119b8<UINT32>
0x00402b43:	movl -8(%ebp), $0x8<UINT32>
0x00402b4a:	movl -4(%ebp), $0xff<UINT32>
0x00402b51:	xorl %ebx, %ebx
0x00402b53:	xorl %edi, %edi
0x00402b55:	call LoadLibraryW@KERNEL32.DLL
LoadLibraryW@KERNEL32.DLL: API Node	
0x00402b5b:	movl %esi, %eax
0x00402b5d:	testl %esi, %esi
0x00402b5f:	je 40
0x00402b61:	pushl $0x4119d4<UINT32>
0x00402b66:	pushl %esi
0x00402b67:	call GetProcAddress@KERNEL32.DLL
0x00402b6d:	testl %eax, %eax
0x00402b6f:	je 9
0x00402b71:	leal %ecx, -8(%ebp)
0x00402b74:	pushl %ecx
0x00402b75:	incl %edi
0x00402b76:	call InitCommonControlsEx@comctl32.dll
InitCommonControlsEx@comctl32.dll: API Node	
0x00402b78:	movl %ebx, %eax
0x00402b7a:	pushl %esi
0x00402b7b:	call FreeLibrary@KERNEL32.DLL
FreeLibrary@KERNEL32.DLL: API Node	
0x00402b81:	testl %edi, %edi
0x00402b83:	je 4
0x00402b85:	movl %eax, %ebx
0x00402b87:	jmp 0x00402b92
0x00402b92:	testl %eax, %eax
0x00402b94:	popl %edi
0x00402b95:	popl %esi
0x00402b96:	popl %ebx
0x00402b97:	jne 0x00402bb0
0x00402b99:	pushl $0x30<UINT8>
0x00402bb0:	xorl %eax, %eax
0x00402bb2:	incl %eax
0x00402bb3:	leave
0x00402bb4:	ret

0x0040ddc8:	testl %eax, %eax
0x0040ddca:	jne 0x0040ddd2
0x0040ddd2:	pushl %ebx
0x0040ddd3:	pushl %esi
0x0040ddd4:	pushl %edi
0x0040ddd5:	call 0x0040ff4b
0x0040ff4b:	cmpl 0x4167bc, $0x0<UINT8>
0x0040ff52:	jne 37
0x0040ff54:	pushl $0x411aac<UINT32>
0x0040ff59:	call LoadLibraryW@KERNEL32.DLL
0x0040ff5f:	testl %eax, %eax
0x0040ff61:	movl 0x4167bc, %eax
0x0040ff66:	je 17
0x0040ff68:	pushl $0x4132e8<UINT32>
0x0040ff6d:	pushl %eax
0x0040ff6e:	call GetProcAddress@KERNEL32.DLL
0x0040ff74:	movl 0x4167b8, %eax
0x0040ff79:	ret

0x0040ddda:	pushl $0x8001<UINT32>
0x0040dddf:	call SetErrorMode@KERNEL32.DLL
SetErrorMode@KERNEL32.DLL: API Node	
0x0040dde5:	xorl %ebx, %ebx
0x0040dde7:	pushl %ebx
0x0040dde8:	pushl $0x40fc94<UINT32>
0x0040dded:	pushl %ebx
0x0040ddee:	movl 0x416050, $0x11223344<UINT32>
0x0040ddf8:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0040ddfe:	pushl %eax
0x0040ddff:	call EnumResourceTypesW@KERNEL32.DLL
EnumResourceTypesW@KERNEL32.DLL: API Node	
0x0040de05:	leal %eax, -52(%ebp)
0x0040de08:	call 0x00407547
0x00407547:	xorl %ecx, %ecx
0x00407549:	movl 0x14(%eax), $0x400<UINT32>
0x00407550:	movl 0x18(%eax), $0x100<UINT32>
0x00407557:	movl (%eax), %ecx
0x00407559:	movl 0x4(%eax), %ecx
0x0040755c:	movl 0xc(%eax), %ecx
0x0040755f:	movl 0x10(%eax), %ecx
0x00407562:	movl 0x1c(%eax), %ecx
0x00407565:	movl 0x8(%eax), %ecx
0x00407568:	ret

0x0040de0d:	leal %eax, -4780(%ebp)
0x0040de13:	pushl %eax
0x0040de14:	movl -12(%ebp), $0x20<UINT32>
0x0040de1b:	movl -20(%ebp), %ebx
0x0040de1e:	movl -8(%ebp), %ebx
0x0040de21:	movl -16(%ebp), %ebx
0x0040de24:	movl -4(%ebp), %ebx
0x0040de27:	call 0x0040da0c
0x0040da0c:	pushl %ebx
0x0040da0d:	pushl %ebp
0x0040da0e:	movl %ebp, 0xc(%esp)
0x0040da12:	pushl %esi
0x0040da13:	movl (%ebp), $0x412dec<UINT32>
0x0040da1a:	pushl %edi
0x0040da1b:	xorl %edi, %edi
0x0040da1d:	movl 0x240(%ebp), %edi
0x0040da23:	movl 0x690(%ebp), %edi
0x0040da29:	leal %eax, 0x6a8(%ebp)
0x0040da2f:	movl 0x698(%ebp), %edi
0x0040da35:	leal %esi, 0x6bc(%ebp)
0x0040da3b:	movl 0xc(%eax), %edi
0x0040da3e:	movl (%eax), %edi
0x0040da40:	movl 0x4(%eax), %edi
0x0040da43:	movl 0x10(%eax), $0x100<UINT32>
0x0040da4a:	movl 0x8(%eax), %edi
0x0040da4d:	call 0x0040499a
0x0040499a:	leal %eax, 0x190(%esi)
0x004049a0:	pushl %eax
0x004049a1:	call 0x00404984
0x00404984:	pushl 0x4(%esp)
0x00404988:	movl %eax, $0x7b4<UINT32>
0x0040498d:	call 0x004070c5
0x004070c5:	addl %eax, $0xfffffffc<UINT8>
0x004070c8:	pushl %eax
0x004070c9:	movl %eax, 0x8(%esp)
0x004070cd:	addl %eax, $0x4<UINT8>
0x004070d0:	pushl $0x0<UINT8>
0x004070d2:	pushl %eax
0x004070d3:	call 0x00410966
0x00410966:	jmp memset@msvcrt.dll
memset@msvcrt.dll: API Node	
0x004070d8:	addl %esp, $0xc<UINT8>
0x004070db:	ret

0x0018f478:	addb (%eax), %al
0x0018f47a:	addb (%eax), %al
0x0018f47c:	addb (%eax), %al
0x0018f47e:	addb (%eax), %al
0x0018f480:	addb (%eax), %al
0x0018f482:	addb (%eax), %al
0x0018f484:	addb (%eax), %al
0x0018f486:	addb (%eax), %al
0x0018f488:	addb (%eax), %al
0x0018f48a:	addb (%eax), %al
0x0018f48c:	addb (%eax), %al
0x0018f48e:	addb (%eax), %al
0x0018f490:	addb (%eax), %al
0x0018f492:	addb (%eax), %al
0x0018f494:	addb (%eax), %al
0x0018f496:	addb (%eax), %al
0x0018f498:	addb (%eax), %al
0x0018f49a:	addb (%eax), %al
0x0018f49c:	addb (%eax), %al
0x0018f49e:	addb (%eax), %al
0x0018f4a0:	addb (%eax), %al
0x0018f4a2:	addb (%eax), %al
0x0018f4a4:	addb (%eax), %al
0x0018f4a6:	addb (%eax), %al
0x0018f4a8:	addb (%eax), %al
0x0018f4aa:	addb (%eax), %al
0x0018f4ac:	addb (%eax), %al
0x0018f4ae:	addb (%eax), %al
0x0018f4b0:	addb (%eax), %al
0x0018f4b2:	addb (%eax), %al
0x0018f4b4:	addb (%eax), %al
0x0018f4b6:	addb (%eax), %al
0x0018f4b8:	addb (%eax), %al
0x0018f4ba:	addb (%eax), %al
0x0018f4bc:	addb (%eax), %al
0x0018f4be:	addb (%eax), %al
0x0018f4c0:	addb (%eax), %al
0x0018f4c2:	addb (%eax), %al
0x0018f4c4:	addb (%eax), %al
0x0018f4c6:	addb (%eax), %al
0x0018f4c8:	addb (%eax), %al
0x0018f4ca:	addb (%eax), %al
0x0018f4cc:	addb (%eax), %al
0x0018f4ce:	addb (%eax), %al
0x0018f4d0:	addb (%eax), %al
0x0018f4d2:	addb (%eax), %al
0x0018f4d4:	addb (%eax), %al
0x0018f4d6:	addb (%eax), %al
0x0018f4d8:	addb (%eax), %al
0x0018f4da:	addb (%eax), %al
0x0018f4dc:	addb (%eax), %al
0x0018f4de:	addb (%eax), %al
0x00402b9b:	pushl $0x4119ec<UINT32>
0x00402ba0:	pushl $0x4119f8<UINT32>
0x00402ba5:	pushl %eax
0x00402ba6:	call MessageBoxW@USER32.dll
MessageBoxW@USER32.dll: API Node	
0x00402bac:	xorl %eax, %eax
0x00402bae:	leave
0x00402baf:	ret

0x0040ddcc:	incl %eax
0x0040ddcd:	jmp 0x0040dfcf
0x0040dfcf:	leave
0x0040dfd0:	ret $0x10<UINT16>

0x00410b88:	movl %esi, %eax
0x00410b8a:	movl -124(%ebp), %esi
0x00410b8d:	cmpl -28(%ebp), %edi
0x00410b90:	jne 7
0x00410b92:	pushl %esi
0x00410b93:	call exit@msvcrt.dll
exit@msvcrt.dll: Exit Node	
