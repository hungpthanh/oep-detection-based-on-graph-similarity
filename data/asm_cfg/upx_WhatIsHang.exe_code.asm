0x00419fe0:	pusha
0x00419fe1:	movl %esi, $0x411000<UINT32>
0x00419fe6:	leal %edi, -65536(%esi)
0x00419fec:	pushl %edi
0x00419fed:	orl %ebp, $0xffffffff<UINT8>
0x00419ff0:	jmp 0x0041a002
0x0041a002:	movl %ebx, (%esi)
0x0041a004:	subl %esi, $0xfffffffc<UINT8>
0x0041a007:	adcl %ebx, %ebx
0x0041a009:	jb 0x00419ff8
0x00419ff8:	movb %al, (%esi)
0x00419ffa:	incl %esi
0x00419ffb:	movb (%edi), %al
0x00419ffd:	incl %edi
0x00419ffe:	addl %ebx, %ebx
0x0041a000:	jne 0x0041a009
0x0041a00b:	movl %eax, $0x1<UINT32>
0x0041a010:	addl %ebx, %ebx
0x0041a012:	jne 0x0041a01b
0x0041a01b:	adcl %eax, %eax
0x0041a01d:	addl %ebx, %ebx
0x0041a01f:	jae 0x0041a010
0x0041a021:	jne 0x0041a02c
0x0041a02c:	xorl %ecx, %ecx
0x0041a02e:	subl %eax, $0x3<UINT8>
0x0041a031:	jb 0x0041a040
0x0041a040:	addl %ebx, %ebx
0x0041a042:	jne 0x0041a04b
0x0041a04b:	adcl %ecx, %ecx
0x0041a04d:	addl %ebx, %ebx
0x0041a04f:	jne 0x0041a058
0x0041a058:	adcl %ecx, %ecx
0x0041a05a:	jne 0x0041a07c
0x0041a07c:	cmpl %ebp, $0xfffff300<UINT32>
0x0041a082:	adcl %ecx, $0x1<UINT8>
0x0041a085:	leal %edx, (%edi,%ebp)
0x0041a088:	cmpl %ebp, $0xfffffffc<UINT8>
0x0041a08b:	jbe 0x0041a09c
0x0041a08d:	movb %al, (%edx)
0x0041a08f:	incl %edx
0x0041a090:	movb (%edi), %al
0x0041a092:	incl %edi
0x0041a093:	decl %ecx
0x0041a094:	jne 0x0041a08d
0x0041a096:	jmp 0x00419ffe
0x0041a033:	shll %eax, $0x8<UINT8>
0x0041a036:	movb %al, (%esi)
0x0041a038:	incl %esi
0x0041a039:	xorl %eax, $0xffffffff<UINT8>
0x0041a03c:	je 0x0041a0b2
0x0041a03e:	movl %ebp, %eax
0x0041a09c:	movl %eax, (%edx)
0x0041a09e:	addl %edx, $0x4<UINT8>
0x0041a0a1:	movl (%edi), %eax
0x0041a0a3:	addl %edi, $0x4<UINT8>
0x0041a0a6:	subl %ecx, $0x4<UINT8>
0x0041a0a9:	ja 0x0041a09c
0x0041a0ab:	addl %edi, %ecx
0x0041a0ad:	jmp 0x00419ffe
0x0041a044:	movl %ebx, (%esi)
0x0041a046:	subl %esi, $0xfffffffc<UINT8>
0x0041a049:	adcl %ebx, %ebx
0x0041a051:	movl %ebx, (%esi)
0x0041a053:	subl %esi, $0xfffffffc<UINT8>
0x0041a056:	adcl %ebx, %ebx
0x0041a05c:	incl %ecx
0x0041a05d:	addl %ebx, %ebx
0x0041a05f:	jne 0x0041a068
0x0041a068:	adcl %ecx, %ecx
0x0041a06a:	addl %ebx, %ebx
0x0041a06c:	jae 0x0041a05d
0x0041a06e:	jne 0x0041a079
0x0041a079:	addl %ecx, $0x2<UINT8>
0x0041a023:	movl %ebx, (%esi)
0x0041a025:	subl %esi, $0xfffffffc<UINT8>
0x0041a028:	adcl %ebx, %ebx
0x0041a02a:	jae 0x0041a010
0x0041a014:	movl %ebx, (%esi)
0x0041a016:	subl %esi, $0xfffffffc<UINT8>
0x0041a019:	adcl %ebx, %ebx
0x0041a070:	movl %ebx, (%esi)
0x0041a072:	subl %esi, $0xfffffffc<UINT8>
0x0041a075:	adcl %ebx, %ebx
0x0041a077:	jae 0x0041a05d
0x0041a061:	movl %ebx, (%esi)
0x0041a063:	subl %esi, $0xfffffffc<UINT8>
0x0041a066:	adcl %ebx, %ebx
0x0041a0b2:	popl %esi
0x0041a0b3:	movl %edi, %esi
0x0041a0b5:	movl %ecx, $0x533<UINT32>
0x0041a0ba:	movb %al, (%edi)
0x0041a0bc:	incl %edi
0x0041a0bd:	subb %al, $0xffffffe8<UINT8>
0x0041a0bf:	cmpb %al, $0x1<UINT8>
0x0041a0c1:	ja 0x0041a0ba
0x0041a0c3:	cmpb (%edi), $0x1<UINT8>
0x0041a0c6:	jne 0x0041a0ba
0x0041a0c8:	movl %eax, (%edi)
0x0041a0ca:	movb %bl, 0x4(%edi)
0x0041a0cd:	shrw %ax, $0x8<UINT8>
0x0041a0d1:	roll %eax, $0x10<UINT8>
0x0041a0d4:	xchgb %ah, %al
0x0041a0d6:	subl %eax, %edi
0x0041a0d8:	subb %bl, $0xffffffe8<UINT8>
0x0041a0db:	addl %eax, %esi
0x0041a0dd:	movl (%edi), %eax
0x0041a0df:	addl %edi, $0x5<UINT8>
0x0041a0e2:	movb %al, %bl
0x0041a0e4:	loop 0x0041a0bf
0x0041a0e6:	leal %edi, 0x17000(%esi)
0x0041a0ec:	movl %eax, (%edi)
0x0041a0ee:	orl %eax, %eax
0x0041a0f0:	je 0x0041a137
0x0041a0f2:	movl %ebx, 0x4(%edi)
0x0041a0f5:	leal %eax, 0x1c034(%eax,%esi)
0x0041a0fc:	addl %ebx, %esi
0x0041a0fe:	pushl %eax
0x0041a0ff:	addl %edi, $0x8<UINT8>
0x0041a102:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0041a108:	xchgl %ebp, %eax
0x0041a109:	movb %al, (%edi)
0x0041a10b:	incl %edi
0x0041a10c:	orb %al, %al
0x0041a10e:	je 0x0041a0ec
0x0041a110:	movl %ecx, %edi
0x0041a112:	jns 0x0041a11b
0x0041a11b:	pushl %edi
0x0041a11c:	decl %eax
0x0041a11d:	repn scasb %al, %es:(%edi)
0x0041a11f:	pushl %ebp
0x0041a120:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0041a126:	orl %eax, %eax
0x0041a128:	je 7
0x0041a12a:	movl (%ebx), %eax
0x0041a12c:	addl %ebx, $0x4<UINT8>
0x0041a12f:	jmp 0x0041a109
GetProcAddress@KERNEL32.DLL: API Node	
0x0041a114:	movzwl %eax, (%edi)
0x0041a117:	incl %edi
0x0041a118:	pushl %eax
0x0041a119:	incl %edi
0x0041a11a:	movl %ecx, $0xaef24857<UINT32>
0x0041a137:	movl %ebp, 0x1c10c(%esi)
0x0041a13d:	leal %edi, -4096(%esi)
0x0041a143:	movl %ebx, $0x1000<UINT32>
0x0041a148:	pushl %eax
0x0041a149:	pushl %esp
0x0041a14a:	pushl $0x4<UINT8>
0x0041a14c:	pushl %ebx
0x0041a14d:	pushl %edi
0x0041a14e:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0041a150:	leal %eax, 0x207(%edi)
0x0041a156:	andb (%eax), $0x7f<UINT8>
0x0041a159:	andb 0x28(%eax), $0x7f<UINT8>
0x0041a15d:	popl %eax
0x0041a15e:	pushl %eax
0x0041a15f:	pushl %esp
0x0041a160:	pushl %eax
0x0041a161:	pushl %ebx
0x0041a162:	pushl %edi
0x0041a163:	call VirtualProtect@kernel32.dll
0x0041a165:	popl %eax
0x0041a166:	popa
0x0041a167:	leal %eax, -128(%esp)
0x0041a16b:	pushl $0x0<UINT8>
0x0041a16d:	cmpl %esp, %eax
0x0041a16f:	jne 0x0041a16b
0x0041a171:	subl %esp, $0xffffff80<UINT8>
0x0041a174:	jmp 0x0040d924
0x0040d924:	pushl $0x70<UINT8>
0x0040d926:	pushl $0x40e3e0<UINT32>
0x0040d92b:	call 0x0040db38
0x0040db38:	pushl $0x40db88<UINT32>
0x0040db3d:	movl %eax, %fs:0
0x0040db43:	pushl %eax
0x0040db44:	movl %fs:0, %esp
0x0040db4b:	movl %eax, 0x10(%esp)
0x0040db4f:	movl 0x10(%esp), %ebp
0x0040db53:	leal %ebp, 0x10(%esp)
0x0040db57:	subl %esp, %eax
0x0040db59:	pushl %ebx
0x0040db5a:	pushl %esi
0x0040db5b:	pushl %edi
0x0040db5c:	movl %eax, -8(%ebp)
0x0040db5f:	movl -24(%ebp), %esp
0x0040db62:	pushl %eax
0x0040db63:	movl %eax, -4(%ebp)
0x0040db66:	movl -4(%ebp), $0xffffffff<UINT32>
0x0040db6d:	movl -8(%ebp), %eax
0x0040db70:	ret

0x0040d930:	xorl %edi, %edi
0x0040d932:	pushl %edi
0x0040d933:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x0040d939:	cmpw (%eax), $0x5a4d<UINT16>
0x0040d93e:	jne 31
0x0040d940:	movl %ecx, 0x3c(%eax)
0x0040d943:	addl %ecx, %eax
0x0040d945:	cmpl (%ecx), $0x4550<UINT32>
0x0040d94b:	jne 18
0x0040d94d:	movzwl %eax, 0x18(%ecx)
0x0040d951:	cmpl %eax, $0x10b<UINT32>
0x0040d956:	je 0x0040d977
0x0040d977:	cmpl 0x74(%ecx), $0xe<UINT8>
0x0040d97b:	jbe -30
0x0040d97d:	xorl %eax, %eax
0x0040d97f:	cmpl 0xe8(%ecx), %edi
0x0040d985:	setne %al
0x0040d988:	movl -28(%ebp), %eax
0x0040d98b:	movl -4(%ebp), %edi
0x0040d98e:	pushl $0x2<UINT8>
0x0040d990:	popl %ebx
0x0040d991:	pushl %ebx
0x0040d992:	call __set_app_type@msvcrt.dll
__set_app_type@msvcrt.dll: API Node	
0x0040d998:	popl %ecx
0x0040d999:	orl 0x412594, $0xffffffff<UINT8>
0x0040d9a0:	orl 0x412598, $0xffffffff<UINT8>
0x0040d9a7:	call __p__fmode@msvcrt.dll
__p__fmode@msvcrt.dll: API Node	
0x0040d9ad:	movl %ecx, 0x41122c
0x0040d9b3:	movl (%eax), %ecx
0x0040d9b5:	call __p__commode@msvcrt.dll
__p__commode@msvcrt.dll: API Node	
0x0040d9bb:	movl %ecx, 0x411228
0x0040d9c1:	movl (%eax), %ecx
0x0040d9c3:	movl %eax, 0x40e2e8
0x0040d9c8:	movl %eax, (%eax)
0x0040d9ca:	movl 0x412590, %eax
0x0040d9cf:	call 0x0040db32
0x0040db32:	xorl %eax, %eax
0x0040db34:	ret

0x0040d9d4:	cmpl 0x411000, %edi
0x0040d9da:	jne 0x0040d9e8
0x0040d9e8:	call 0x0040db20
0x0040db20:	pushl $0x30000<UINT32>
0x0040db25:	pushl $0x10000<UINT32>
0x0040db2a:	call 0x0040db82
0x0040db82:	jmp _controlfp@msvcrt.dll
_controlfp@msvcrt.dll: API Node	
0x0040db2f:	popl %ecx
0x0040db30:	popl %ecx
0x0040db31:	ret

0x0040d9ed:	pushl $0x40e3b8<UINT32>
0x0040d9f2:	pushl $0x40e3b4<UINT32>
0x0040d9f7:	call 0x0040db1a
0x0040db1a:	jmp _initterm@msvcrt.dll
_initterm@msvcrt.dll: API Node	
0x0040d9fc:	movl %eax, 0x411224
0x0040da01:	movl -32(%ebp), %eax
0x0040da04:	leal %eax, -32(%ebp)
0x0040da07:	pushl %eax
0x0040da08:	pushl 0x411220
0x0040da0e:	leal %eax, -36(%ebp)
0x0040da11:	pushl %eax
0x0040da12:	leal %eax, -40(%ebp)
0x0040da15:	pushl %eax
0x0040da16:	leal %eax, -44(%ebp)
0x0040da19:	pushl %eax
0x0040da1a:	call __wgetmainargs@msvcrt.dll
__wgetmainargs@msvcrt.dll: API Node	
0x0040da20:	movl -48(%ebp), %eax
0x0040da23:	pushl $0x40e3b0<UINT32>
0x0040da28:	pushl $0x40e394<UINT32>
0x0040da2d:	call 0x0040db1a
0x0040da32:	addl %esp, $0x24<UINT8>
0x0040da35:	movl %eax, 0x40e2f8
0x0040da3a:	movl %esi, (%eax)
0x0040da3c:	cmpl %esi, %edi
0x0040da3e:	jne 0x0040da4e
0x0040da4e:	movl -52(%ebp), %esi
0x0040da51:	cmpw (%esi), $0x22<UINT8>
0x0040da55:	jne 69
0x0040da57:	addl %esi, %ebx
0x0040da59:	movl -52(%ebp), %esi
0x0040da5c:	movw %ax, (%esi)
0x0040da5f:	cmpw %ax, %di
0x0040da62:	je 6
0x0040da64:	cmpw %ax, $0x22<UINT16>
0x0040da68:	jne 0x0040da57
0x0040da6a:	cmpw (%esi), $0x22<UINT8>
0x0040da6e:	jne 5
0x0040da70:	addl %esi, %ebx
0x0040da72:	movl -52(%ebp), %esi
0x0040da75:	movw %ax, (%esi)
0x0040da78:	cmpw %ax, %di
0x0040da7b:	je 6
0x0040da7d:	cmpw %ax, $0x20<UINT16>
0x0040da81:	jbe 0x0040da70
0x0040da83:	movl -76(%ebp), %edi
0x0040da86:	leal %eax, -120(%ebp)
0x0040da89:	pushl %eax
0x0040da8a:	call GetStartupInfoW@KERNEL32.DLL
GetStartupInfoW@KERNEL32.DLL: API Node	
0x0040da90:	testb -76(%ebp), $0x1<UINT8>
0x0040da94:	je 0x0040daa9
0x0040daa9:	pushl $0xa<UINT8>
0x0040daab:	popl %eax
0x0040daac:	pushl %eax
0x0040daad:	pushl %esi
0x0040daae:	pushl %edi
0x0040daaf:	pushl %edi
0x0040dab0:	call GetModuleHandleA@KERNEL32.DLL
0x0040dab6:	pushl %eax
0x0040dab7:	call 0x0040a5f4
0x0040a5f4:	pushl %ebp
0x0040a5f5:	movl %ebp, %esp
0x0040a5f7:	andl %esp, $0xfffffff8<UINT8>
0x0040a5fa:	subl %esp, $0x72c<UINT32>
0x0040a600:	pushl %ebx
0x0040a601:	pushl %esi
0x0040a602:	pushl %edi
0x0040a603:	call 0x00401f1d
0x00401f1d:	pushl %ebp
0x00401f1e:	movl %ebp, %esp
0x00401f20:	pushl %ecx
0x00401f21:	pushl %ecx
0x00401f22:	pushl %ebx
0x00401f23:	pushl %esi
0x00401f24:	pushl %edi
0x00401f25:	pushl $0x40e768<UINT32>
0x00401f2a:	movl -8(%ebp), $0x8<UINT32>
0x00401f31:	movl -4(%ebp), $0xff<UINT32>
0x00401f38:	xorl %ebx, %ebx
0x00401f3a:	xorl %edi, %edi
0x00401f3c:	call LoadLibraryW@KERNEL32.DLL
LoadLibraryW@KERNEL32.DLL: API Node	
0x00401f42:	movl %esi, %eax
0x00401f44:	testl %esi, %esi
0x00401f46:	je 40
0x00401f48:	pushl $0x40e784<UINT32>
0x00401f4d:	pushl %esi
0x00401f4e:	call GetProcAddress@KERNEL32.DLL
0x00401f54:	testl %eax, %eax
0x00401f56:	je 9
0x00401f58:	leal %ecx, -8(%ebp)
0x00401f5b:	pushl %ecx
0x00401f5c:	incl %edi
0x00401f5d:	call InitCommonControlsEx@comctl32.dll
InitCommonControlsEx@comctl32.dll: API Node	
0x00401f5f:	movl %ebx, %eax
0x00401f61:	pushl %esi
0x00401f62:	call FreeLibrary@KERNEL32.DLL
FreeLibrary@KERNEL32.DLL: API Node	
0x00401f68:	testl %edi, %edi
0x00401f6a:	je 4
0x00401f6c:	movl %eax, %ebx
0x00401f6e:	jmp 0x00401f79
0x00401f79:	testl %eax, %eax
0x00401f7b:	popl %edi
0x00401f7c:	popl %esi
0x00401f7d:	popl %ebx
0x00401f7e:	jne 0x00401f97
0x00401f80:	pushl $0x30<UINT8>
0x00401f97:	xorl %eax, %eax
0x00401f99:	incl %eax
0x00401f9a:	leave
0x00401f9b:	ret

0x0040a608:	testl %eax, %eax
0x0040a60a:	jne 0x0040a612
0x0040a612:	call 0x0040b5e5
0x0040b5e5:	call 0x004031f6
0x004031f6:	call 0x004031d2
0x004031d2:	cmpl 0x4119bc, $0x0<UINT8>
0x004031d9:	pushl %esi
0x004031da:	movl %esi, $0x4119b8<UINT32>
0x004031df:	jne 17
0x004031e1:	pushl %esi
0x004031e2:	movl 0x4119b8, $0x114<UINT32>
0x004031ec:	call GetVersionExW@KERNEL32.DLL
GetVersionExW@KERNEL32.DLL: API Node	
0x004031f2:	movl %eax, %esi
0x004031f4:	popl %esi
0x004031f5:	ret

0x004031fb:	xorl %ecx, %ecx
0x004031fd:	cmpl 0x10(%eax), $0x2<UINT8>
0x00403201:	sete %cl
0x00403204:	movl %eax, %ecx
0x00403206:	ret

0x0040b5ea:	testl %eax, %eax
0x0040b5ec:	je 7
0x0040b5ee:	call 0x0040b54d
0x0040b54d:	cmpl 0x412100, $0x0<UINT8>
0x0040b554:	jne 138
0x0040b55a:	pushl %edi
0x0040b55b:	pushl $0x40f59c<UINT32>
0x0040b560:	call LoadLibraryW@KERNEL32.DLL
0x0040b566:	movl %edi, %eax
0x0040b568:	testl %edi, %edi
0x0040b56a:	je 119
0x0040b56c:	pushl %esi
0x0040b56d:	movl %esi, 0x40e094
0x0040b573:	pushl $0x40f5b0<UINT32>
0x0040b578:	pushl %edi
0x0040b579:	call GetProcAddress@KERNEL32.DLL
0x0040b57b:	testl %eax, %eax
0x0040b57d:	movl 0x411788, %eax
0x0040b582:	je 78
0x0040b584:	pushl $0x40f5c4<UINT32>
0x0040b589:	pushl %edi
0x0040b58a:	call GetProcAddress@KERNEL32.DLL
0x0040b58c:	testl %eax, %eax
0x0040b58e:	movl 0x411780, %eax
0x0040b593:	je 61
0x0040b595:	pushl $0x40f5d8<UINT32>
0x0040b59a:	pushl %edi
0x0040b59b:	call GetProcAddress@KERNEL32.DLL
0x0040b59d:	testl %eax, %eax
0x0040b59f:	movl 0x411778, %eax
0x0040b5a4:	je 44
0x0040b5a6:	pushl $0x40f5f0<UINT32>
0x0040b5ab:	pushl %edi
0x0040b5ac:	call GetProcAddress@KERNEL32.DLL
0x0040b5ae:	testl %eax, %eax
0x0040b5b0:	movl 0x4119ac, %eax
0x0040b5b5:	je 27
0x0040b5b7:	pushl $0x40f600<UINT32>
0x0040b5bc:	pushl %edi
0x0040b5bd:	call GetProcAddress@KERNEL32.DLL
0x0040b5bf:	testl %eax, %eax
0x0040b5c1:	movl 0x411784, %eax
0x0040b5c6:	je 10
0x0040b5c8:	movl 0x412100, $0x1<UINT32>
0x0040b5d2:	cmpl 0x412100, $0x0<UINT8>
0x0040b5d9:	popl %esi
0x0040b5da:	jne 0x0040b5e3
0x0040b5e3:	popl %edi
0x0040b5e4:	ret

0x0040b5f3:	jmp 0x0040b5fa
0x0040b5fa:	xorl %eax, %eax
0x0040b5fc:	cmpl 0x4120fc, %eax
0x0040b602:	jne 8
0x0040b604:	cmpl 0x412100, %eax
0x0040b60a:	je 3
0x0040b60c:	xorl %eax, %eax
0x0040b60e:	incl %eax
0x0040b60f:	ret

0x0040a617:	call 0x0040c8c8
0x0040c8c8:	cmpl 0x412108, $0x0<UINT8>
0x0040c8cf:	jne 37
0x0040c8d1:	pushl $0x40f690<UINT32>
0x0040c8d6:	call LoadLibraryW@KERNEL32.DLL
0x0040c8dc:	testl %eax, %eax
0x0040c8de:	movl 0x412108, %eax
0x0040c8e3:	je 17
0x0040c8e5:	pushl $0x40f6a8<UINT32>
0x0040c8ea:	pushl %eax
0x0040c8eb:	call GetProcAddress@KERNEL32.DLL
0x0040c8f1:	movl 0x412104, %eax
0x0040c8f6:	ret

0x0040a61c:	pushl $0x8001<UINT32>
0x0040a621:	call SetErrorMode@KERNEL32.DLL
SetErrorMode@KERNEL32.DLL: API Node	
0x0040a627:	movl %ebx, 0x40e09c
0x0040a62d:	xorl %esi, %esi
0x0040a62f:	pushl %esi
0x0040a630:	pushl $0x40c8ad<UINT32>
0x0040a635:	pushl %esi
0x0040a636:	movl 0x4119b0, $0x11223344<UINT32>
0x0040a640:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0040a642:	pushl %eax
0x0040a643:	call EnumResourceTypesW@KERNEL32.DLL
EnumResourceTypesW@KERNEL32.DLL: API Node	
0x0040a649:	leal %eax, 0x10(%esp)
0x0040a64d:	call 0x004038e9
0x004038e9:	xorl %ecx, %ecx
0x004038eb:	movl 0x14(%eax), $0x400<UINT32>
0x004038f2:	movl 0x18(%eax), $0x100<UINT32>
0x004038f9:	movl (%eax), %ecx
0x004038fb:	movl 0x4(%eax), %ecx
0x004038fe:	movl 0xc(%eax), %ecx
0x00403901:	movl 0x10(%eax), %ecx
0x00403904:	movl 0x1c(%eax), %ecx
0x00403907:	movl 0x8(%eax), %ecx
0x0040390a:	ret

0x0040a652:	leal %eax, 0x60(%esp)
0x0040a656:	pushl %eax
0x0040a657:	movl 0x3c(%esp), $0x20<UINT32>
0x0040a65f:	movl 0x34(%esp), %esi
0x0040a663:	movl 0x40(%esp), %esi
0x0040a667:	movl 0x38(%esp), %esi
0x0040a66b:	movl 0x44(%esp), %esi
0x0040a66f:	call 0x0040a347
0x0040a347:	pushl %ebx
0x0040a348:	pushl %ebp
0x0040a349:	movl %ebp, 0xc(%esp)
0x0040a34d:	pushl %esi
0x0040a34e:	movl (%ebp), $0x40f2b0<UINT32>
0x0040a355:	pushl %edi
0x0040a356:	xorl %edi, %edi
0x0040a358:	movl 0x240(%ebp), %edi
0x0040a35e:	movl 0x270(%ebp), %edi
0x0040a364:	leal %eax, 0x6b8(%ebp)
0x0040a36a:	leal %esi, 0x690(%ebp)
0x0040a370:	movl (%esi), %edi
0x0040a372:	movl 0x6b4(%ebp), %edi
0x0040a378:	pushl $0x2c<UINT8>
0x0040a37a:	movl (%eax), $0x40f990<UINT32>
0x0040a380:	movl 0x4(%eax), %edi
0x0040a383:	movl 0x8(%eax), %edi
0x0040a386:	movl 0x10(%eax), %edi
0x0040a389:	call 0x0040d8b8
0x0040d8b8:	jmp ??2@YAPAXI@Z@msvcrt.dll
??2@YAPAXI@Z@msvcrt.dll: API Node	
0x0040a38e:	cmpl %eax, %edi
0x0040a390:	popl %ecx
0x0040a391:	je 17
0x0040a393:	movl 0x4119b4, %eax
0x0040a398:	movl 0x14(%eax), $0x2aaa<UINT32>
0x0040a39f:	movl 0x24(%eax), %edi
0x0040a3a2:	jmp 0x0040a3a6
0x0040a3a6:	pushl $0x308<UINT32>
0x0040a3ab:	movl 0x694(%ebp), %eax
0x0040a3b1:	call 0x0040d8b8
0x0040a3b6:	cmpl %eax, %edi
0x0040a3b8:	popl %ecx
0x0040a3b9:	je 7
0x0040a3bb:	call 0x00401e6b
0x00401e6b:	pushl %esi
0x00401e6c:	movl %esi, %eax
0x00401e6e:	call 0x00406727
0x00406727:	pushl %ebx
0x00406728:	pushl %edi
0x00406729:	pushl %esi
0x0040672a:	movl %eax, $0x2dc<UINT32>
0x0040672f:	movl (%esi), $0x40eff8<UINT32>
0x00406735:	call 0x00403565
0x00403565:	addl %eax, $0xfffffffc<UINT8>
0x00403568:	pushl %eax
0x00403569:	movl %eax, 0x8(%esp)
0x0040356d:	addl %eax, $0x4<UINT8>
0x00403570:	pushl $0x0<UINT8>
0x00403572:	pushl %eax
0x00403573:	call 0x0040d89a
0x0040d89a:	jmp memset@msvcrt.dll
memset@msvcrt.dll: API Node	
0x00403578:	addl %esp, $0xc<UINT8>
0x0040357b:	ret GetModuleHandleW@KERNEL32.DLL

0x00401e73:	movl (%esi), $0x40e6e0<UINT32>
0x00401e79:	xorl %ecx, %ecx
0x00401e7b:	leal %eax, 0x2f0(%esi)
0x00401e81:	pushl $0x20<UINT8>
0x00401e83:	popl %edx
0x00401e84:	movl 0x2e4(%esi), %edx
0x00401e8a:	movl 0x2dc(%esi), %ecx
0x00401e90:	movl 0x2e8(%esi), %ecx
0x00401e96:	movl 0x2e0(%esi), %ecx
0x00401e9c:	movl 0x8(%eax), %edx
0x00401e9f:	movl (%eax), %ecx
0x00401ea1:	movl 0xc(%eax), %ecx
0x00401ea4:	movl 0x4(%eax), %ecx
0x00401ea7:	movl 0x300(%esi), %ecx
0x00401ead:	movl 0x304(%esi), %ecx
0x00401eb3:	movl %eax, %esi
0x00401eb5:	popl %esi
0x00401eb6:	ret

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
0x00401f82:	pushl $0x40e79c<UINT32>
0x00401f87:	pushl $0x40e7a8<UINT32>
0x00401f8c:	pushl %eax
0x00401f8d:	call MessageBoxW@USER32.dll
MessageBoxW@USER32.dll: API Node	
0x00401f93:	xorl %eax, %eax
0x00401f95:	leave
0x00401f96:	ret

0x0040a60c:	incl %eax
0x0040a60d:	jmp 0x0040a7ba
0x0040a7ba:	popl %edi
0x0040a7bb:	popl %esi
0x0040a7bc:	popl %ebx
0x0040a7bd:	movl %esp, %ebp
0x0040a7bf:	popl %ebp
0x0040a7c0:	ret $0x10<UINT16>

0x0040dabc:	movl %esi, %eax
0x0040dabe:	movl -124(%ebp), %esi
0x0040dac1:	cmpl -28(%ebp), %edi
0x0040dac4:	jne 7
0x0040dac6:	pushl %esi
0x0040dac7:	call exit@msvcrt.dll
exit@msvcrt.dll: Exit Node	
