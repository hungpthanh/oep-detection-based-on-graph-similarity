0x00417ac0:	pusha
0x00417ac1:	movl %esi, $0x40f000<UINT32>
0x00417ac6:	leal %edi, -57344(%esi)
0x00417acc:	pushl %edi
0x00417acd:	jmp 0x00417ada
0x00417ada:	movl %ebx, (%esi)
0x00417adc:	subl %esi, $0xfffffffc<UINT8>
0x00417adf:	adcl %ebx, %ebx
0x00417ae1:	jb 0x00417ad0
0x00417ad0:	movb %al, (%esi)
0x00417ad2:	incl %esi
0x00417ad3:	movb (%edi), %al
0x00417ad5:	incl %edi
0x00417ad6:	addl %ebx, %ebx
0x00417ad8:	jne 0x00417ae1
0x00417ae3:	movl %eax, $0x1<UINT32>
0x00417ae8:	addl %ebx, %ebx
0x00417aea:	jne 0x00417af3
0x00417af3:	adcl %eax, %eax
0x00417af5:	addl %ebx, %ebx
0x00417af7:	jae 0x00417ae8
0x00417af9:	jne 0x00417b04
0x00417b04:	xorl %ecx, %ecx
0x00417b06:	subl %eax, $0x3<UINT8>
0x00417b09:	jb 0x00417b18
0x00417b0b:	shll %eax, $0x8<UINT8>
0x00417b0e:	movb %al, (%esi)
0x00417b10:	incl %esi
0x00417b11:	xorl %eax, $0xffffffff<UINT8>
0x00417b14:	je 0x00417b8a
0x00417b16:	movl %ebp, %eax
0x00417b18:	addl %ebx, %ebx
0x00417b1a:	jne 0x00417b23
0x00417b23:	adcl %ecx, %ecx
0x00417b25:	addl %ebx, %ebx
0x00417b27:	jne 0x00417b30
0x00417b30:	adcl %ecx, %ecx
0x00417b32:	jne 0x00417b54
0x00417b54:	cmpl %ebp, $0xfffff300<UINT32>
0x00417b5a:	adcl %ecx, $0x1<UINT8>
0x00417b5d:	leal %edx, (%edi,%ebp)
0x00417b60:	cmpl %ebp, $0xfffffffc<UINT8>
0x00417b63:	jbe 0x00417b74
0x00417b74:	movl %eax, (%edx)
0x00417b76:	addl %edx, $0x4<UINT8>
0x00417b79:	movl (%edi), %eax
0x00417b7b:	addl %edi, $0x4<UINT8>
0x00417b7e:	subl %ecx, $0x4<UINT8>
0x00417b81:	ja 0x00417b74
0x00417b83:	addl %edi, %ecx
0x00417b85:	jmp 0x00417ad6
0x00417b1c:	movl %ebx, (%esi)
0x00417b1e:	subl %esi, $0xfffffffc<UINT8>
0x00417b21:	adcl %ebx, %ebx
0x00417b29:	movl %ebx, (%esi)
0x00417b2b:	subl %esi, $0xfffffffc<UINT8>
0x00417b2e:	adcl %ebx, %ebx
0x00417afb:	movl %ebx, (%esi)
0x00417afd:	subl %esi, $0xfffffffc<UINT8>
0x00417b00:	adcl %ebx, %ebx
0x00417b02:	jae 0x00417ae8
0x00417b34:	incl %ecx
0x00417b35:	addl %ebx, %ebx
0x00417b37:	jne 0x00417b40
0x00417b40:	adcl %ecx, %ecx
0x00417b42:	addl %ebx, %ebx
0x00417b44:	jae 0x00417b35
0x00417b46:	jne 0x00417b51
0x00417b51:	addl %ecx, $0x2<UINT8>
0x00417aec:	movl %ebx, (%esi)
0x00417aee:	subl %esi, $0xfffffffc<UINT8>
0x00417af1:	adcl %ebx, %ebx
0x00417b39:	movl %ebx, (%esi)
0x00417b3b:	subl %esi, $0xfffffffc<UINT8>
0x00417b3e:	adcl %ebx, %ebx
0x00417b48:	movl %ebx, (%esi)
0x00417b4a:	subl %esi, $0xfffffffc<UINT8>
0x00417b4d:	adcl %ebx, %ebx
0x00417b4f:	jae 0x00417b35
0x00417b65:	movb %al, (%edx)
0x00417b67:	incl %edx
0x00417b68:	movb (%edi), %al
0x00417b6a:	incl %edi
0x00417b6b:	decl %ecx
0x00417b6c:	jne 0x00417b65
0x00417b6e:	jmp 0x00417ad6
0x00417b8a:	popl %esi
0x00417b8b:	movl %edi, %esi
0x00417b8d:	movl %ecx, $0x550<UINT32>
0x00417b92:	movb %al, (%edi)
0x00417b94:	incl %edi
0x00417b95:	subb %al, $0xffffffe8<UINT8>
0x00417b97:	cmpb %al, $0x1<UINT8>
0x00417b99:	ja 0x00417b92
0x00417b9b:	cmpb (%edi), $0x2<UINT8>
0x00417b9e:	jne 0x00417b92
0x00417ba0:	movl %eax, (%edi)
0x00417ba2:	movb %bl, 0x4(%edi)
0x00417ba5:	shrw %ax, $0x8<UINT8>
0x00417ba9:	roll %eax, $0x10<UINT8>
0x00417bac:	xchgb %ah, %al
0x00417bae:	subl %eax, %edi
0x00417bb0:	subb %bl, $0xffffffe8<UINT8>
0x00417bb3:	addl %eax, %esi
0x00417bb5:	movl (%edi), %eax
0x00417bb7:	addl %edi, $0x5<UINT8>
0x00417bba:	movb %al, %bl
0x00417bbc:	loop 0x00417b97
0x00417bbe:	leal %edi, 0x15000(%esi)
0x00417bc4:	movl %eax, (%edi)
0x00417bc6:	orl %eax, %eax
0x00417bc8:	je 0x00417c0f
0x00417bca:	movl %ebx, 0x4(%edi)
0x00417bcd:	leal %eax, 0x18184(%eax,%esi)
0x00417bd4:	addl %ebx, %esi
0x00417bd6:	pushl %eax
0x00417bd7:	addl %edi, $0x8<UINT8>
0x00417bda:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00417be0:	xchgl %ebp, %eax
0x00417be1:	movb %al, (%edi)
0x00417be3:	incl %edi
0x00417be4:	orb %al, %al
0x00417be6:	je 0x00417bc4
0x00417be8:	movl %ecx, %edi
0x00417bea:	jns 0x00417bf3
0x00417bf3:	pushl %edi
0x00417bf4:	decl %eax
0x00417bf5:	repn scasb %al, %es:(%edi)
0x00417bf7:	pushl %ebp
0x00417bf8:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00417bfe:	orl %eax, %eax
0x00417c00:	je 7
0x00417c02:	movl (%ebx), %eax
0x00417c04:	addl %ebx, $0x4<UINT8>
0x00417c07:	jmp 0x00417be1
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x00417bec:	movzwl %eax, (%edi)
0x00417bef:	incl %edi
0x00417bf0:	pushl %eax
0x00417bf1:	incl %edi
0x00417bf2:	movl %ecx, $0xaef24857<UINT32>
0x00417c0f:	movl %ebp, 0x182a0(%esi)
0x00417c15:	leal %edi, -4096(%esi)
0x00417c1b:	movl %ebx, $0x1000<UINT32>
0x00417c20:	pushl %eax
0x00417c21:	pushl %esp
0x00417c22:	pushl $0x4<UINT8>
0x00417c24:	pushl %ebx
0x00417c25:	pushl %edi
0x00417c26:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00417c28:	leal %eax, 0x207(%edi)
0x00417c2e:	andb (%eax), $0x7f<UINT8>
0x00417c31:	andb 0x28(%eax), $0x7f<UINT8>
0x00417c35:	popl %eax
0x00417c36:	pushl %eax
0x00417c37:	pushl %esp
0x00417c38:	pushl %eax
0x00417c39:	pushl %ebx
0x00417c3a:	pushl %edi
0x00417c3b:	call VirtualProtect@kernel32.dll
0x00417c3d:	popl %eax
0x00417c3e:	popa
0x00417c3f:	leal %eax, -128(%esp)
0x00417c43:	pushl $0x0<UINT8>
0x00417c45:	cmpl %esp, %eax
0x00417c47:	jne 0x00417c43
0x00417c49:	subl %esp, $0xffffff80<UINT8>
0x00417c4c:	jmp 0x0040d10a
0x0040d10a:	pushl $0x70<UINT8>
0x0040d10c:	pushl $0x40e400<UINT32>
0x0040d111:	call 0x0040d2f8
0x0040d2f8:	pushl $0x40d348<UINT32>
0x0040d2fd:	movl %eax, %fs:0
0x0040d303:	pushl %eax
0x0040d304:	movl %fs:0, %esp
0x0040d30b:	movl %eax, 0x10(%esp)
0x0040d30f:	movl 0x10(%esp), %ebp
0x0040d313:	leal %ebp, 0x10(%esp)
0x0040d317:	subl %esp, %eax
0x0040d319:	pushl %ebx
0x0040d31a:	pushl %esi
0x0040d31b:	pushl %edi
0x0040d31c:	movl %eax, -8(%ebp)
0x0040d31f:	movl -24(%ebp), %esp
0x0040d322:	pushl %eax
0x0040d323:	movl %eax, -4(%ebp)
0x0040d326:	movl -4(%ebp), $0xffffffff<UINT32>
0x0040d32d:	movl -8(%ebp), %eax
0x0040d330:	ret

0x0040d116:	xorl %ebx, %ebx
0x0040d118:	pushl %ebx
0x0040d119:	movl %edi, 0x40e110
0x0040d11f:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x0040d121:	cmpw (%eax), $0x5a4d<UINT16>
0x0040d126:	jne 31
0x0040d128:	movl %ecx, 0x3c(%eax)
0x0040d12b:	addl %ecx, %eax
0x0040d12d:	cmpl (%ecx), $0x4550<UINT32>
0x0040d133:	jne 18
0x0040d135:	movzwl %eax, 0x18(%ecx)
0x0040d139:	cmpl %eax, $0x10b<UINT32>
0x0040d13e:	je 0x0040d15f
0x0040d15f:	cmpl 0x74(%ecx), $0xe<UINT8>
0x0040d163:	jbe -30
0x0040d165:	xorl %eax, %eax
0x0040d167:	cmpl 0xe8(%ecx), %ebx
0x0040d16d:	setne %al
0x0040d170:	movl -28(%ebp), %eax
0x0040d173:	movl -4(%ebp), %ebx
0x0040d176:	pushl $0x2<UINT8>
0x0040d178:	call __set_app_type@msvcrt.dll
__set_app_type@msvcrt.dll: API Node	
0x0040d17e:	popl %ecx
0x0040d17f:	orl 0x411ee4, $0xffffffff<UINT8>
0x0040d186:	orl 0x411ee8, $0xffffffff<UINT8>
0x0040d18d:	call __p__fmode@msvcrt.dll
__p__fmode@msvcrt.dll: API Node	
0x0040d193:	movl %ecx, 0x4111ac
0x0040d199:	movl (%eax), %ecx
0x0040d19b:	call __p__commode@msvcrt.dll
__p__commode@msvcrt.dll: API Node	
0x0040d1a1:	movl %ecx, 0x4111a8
0x0040d1a7:	movl (%eax), %ecx
0x0040d1a9:	movl %eax, 0x40e37c
0x0040d1ae:	movl %eax, (%eax)
0x0040d1b0:	movl 0x411ee0, %eax
0x0040d1b5:	call 0x0040d2f4
0x0040d2f4:	xorl %eax, %eax
0x0040d2f6:	ret

0x0040d1ba:	cmpl 0x411000, %ebx
0x0040d1c0:	jne 0x0040d1ce
0x0040d1ce:	call 0x0040d2e2
0x0040d2e2:	pushl $0x30000<UINT32>
0x0040d2e7:	pushl $0x10000<UINT32>
0x0040d2ec:	call 0x0040d342
0x0040d342:	jmp _controlfp@msvcrt.dll
_controlfp@msvcrt.dll: API Node	
0x0040d2f1:	popl %ecx
0x0040d2f2:	popl %ecx
0x0040d2f3:	ret

0x0040d1d3:	pushl $0x40e3d8<UINT32>
0x0040d1d8:	pushl $0x40e3d4<UINT32>
0x0040d1dd:	call 0x0040d2dc
0x0040d2dc:	jmp _initterm@msvcrt.dll
_initterm@msvcrt.dll: API Node	
0x0040d1e2:	movl %eax, 0x4111a4
0x0040d1e7:	movl -32(%ebp), %eax
0x0040d1ea:	leal %eax, -32(%ebp)
0x0040d1ed:	pushl %eax
0x0040d1ee:	pushl 0x4111a0
0x0040d1f4:	leal %eax, -36(%ebp)
0x0040d1f7:	pushl %eax
0x0040d1f8:	leal %eax, -40(%ebp)
0x0040d1fb:	pushl %eax
0x0040d1fc:	leal %eax, -44(%ebp)
0x0040d1ff:	pushl %eax
0x0040d200:	call __getmainargs@msvcrt.dll
__getmainargs@msvcrt.dll: API Node	
0x0040d206:	movl -48(%ebp), %eax
0x0040d209:	pushl $0x40e3d0<UINT32>
0x0040d20e:	pushl $0x40e3a4<UINT32>
0x0040d213:	call 0x0040d2dc
0x0040d218:	addl %esp, $0x24<UINT8>
0x0040d21b:	movl %eax, 0x40e2ec
0x0040d220:	movl %esi, (%eax)
0x0040d222:	movl -52(%ebp), %esi
0x0040d225:	cmpb (%esi), $0x22<UINT8>
0x0040d228:	jne 58
0x0040d22a:	incl %esi
0x0040d22b:	movl -52(%ebp), %esi
0x0040d22e:	movb %al, (%esi)
0x0040d230:	cmpb %al, %bl
0x0040d232:	je 4
0x0040d234:	cmpb %al, $0x22<UINT8>
0x0040d236:	jne 0x0040d22a
0x0040d238:	cmpb (%esi), $0x22<UINT8>
0x0040d23b:	jne 4
0x0040d23d:	incl %esi
0x0040d23e:	movl -52(%ebp), %esi
0x0040d241:	movb %al, (%esi)
0x0040d243:	cmpb %al, %bl
0x0040d245:	je 4
0x0040d247:	cmpb %al, $0x20<UINT8>
0x0040d249:	jbe 0x0040d23d
0x0040d24b:	movl -76(%ebp), %ebx
0x0040d24e:	leal %eax, -120(%ebp)
0x0040d251:	pushl %eax
0x0040d252:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x0040d258:	testb -76(%ebp), $0x1<UINT8>
0x0040d25c:	je 0x0040d26f
0x0040d26f:	pushl $0xa<UINT8>
0x0040d271:	popl %eax
0x0040d272:	pushl %eax
0x0040d273:	pushl %esi
0x0040d274:	pushl %ebx
0x0040d275:	pushl %ebx
0x0040d276:	call GetModuleHandleA@KERNEL32.DLL
0x0040d278:	pushl %eax
0x0040d279:	call 0x0040b199
0x0040b199:	pushl %ebp
0x0040b19a:	movl %ebp, %esp
0x0040b19c:	andl %esp, $0xfffffff8<UINT8>
0x0040b19f:	subl %esp, $0x484<UINT32>
0x0040b1a5:	pushl %ebx
0x0040b1a6:	pushl %esi
0x0040b1a7:	pushl %edi
0x0040b1a8:	call 0x0040496b
0x0040496b:	pushl %ebp
0x0040496c:	movl %ebp, %esp
0x0040496e:	pushl %ecx
0x0040496f:	pushl %ecx
0x00404970:	pushl %ebx
0x00404971:	pushl %esi
0x00404972:	pushl %edi
0x00404973:	pushl $0x40ebec<UINT32>
0x00404978:	movl -8(%ebp), $0x8<UINT32>
0x0040497f:	movl -4(%ebp), $0xff<UINT32>
0x00404986:	xorl %ebx, %ebx
0x00404988:	xorl %edi, %edi
0x0040498a:	call LoadLibraryA@KERNEL32.DLL
0x00404990:	movl %esi, %eax
0x00404992:	testl %esi, %esi
0x00404994:	je 40
0x00404996:	pushl $0x40ebfc<UINT32>
0x0040499b:	pushl %esi
0x0040499c:	call GetProcAddress@KERNEL32.DLL
0x004049a2:	testl %eax, %eax
0x004049a4:	je 9
0x004049a6:	leal %ecx, -8(%ebp)
0x004049a9:	pushl %ecx
0x004049aa:	incl %edi
0x004049ab:	call InitCommonControlsEx@comctl32.dll
InitCommonControlsEx@comctl32.dll: API Node	
0x004049ad:	movl %ebx, %eax
0x004049af:	pushl %esi
0x004049b0:	call FreeLibrary@KERNEL32.DLL
FreeLibrary@KERNEL32.DLL: API Node	
0x004049b6:	testl %edi, %edi
0x004049b8:	je 4
0x004049ba:	movl %eax, %ebx
0x004049bc:	jmp 0x004049c7
0x004049c7:	testl %eax, %eax
0x004049c9:	popl %edi
0x004049ca:	popl %esi
0x004049cb:	popl %ebx
0x004049cc:	jne 0x004049e5
0x004049ce:	pushl $0x30<UINT8>
0x004049e5:	xorl %eax, %eax
0x004049e7:	incl %eax
0x004049e8:	leave
0x004049e9:	ret

0x0040b1ad:	testl %eax, %eax
0x0040b1af:	jne 0x0040b1bb
0x0040b1bb:	xorl %edi, %edi
0x0040b1bd:	pushl %edi
0x0040b1be:	call CoInitialize@ole32.dll
CoInitialize@ole32.dll: API Node	
0x0040b1c4:	call 0x0040ca2f
0x0040ca2f:	cmpl 0x411b4c, $0x0<UINT8>
0x0040ca36:	jne 37
0x0040ca38:	pushl $0x40f608<UINT32>
0x0040ca3d:	call LoadLibraryA@KERNEL32.DLL
0x0040ca43:	testl %eax, %eax
0x0040ca45:	movl 0x411b4c, %eax
0x0040ca4a:	je 17
0x0040ca4c:	pushl $0x40f614<UINT32>
0x0040ca51:	pushl %eax
0x0040ca52:	call GetProcAddress@KERNEL32.DLL
0x0040ca58:	movl 0x411b48, %eax
0x0040ca5d:	ret

0x0040b1c9:	pushl $0x8001<UINT32>
0x0040b1ce:	call SetErrorMode@KERNEL32.DLL
SetErrorMode@KERNEL32.DLL: API Node	
0x0040b1d4:	leal %eax, 0x300(%esp)
0x0040b1db:	pushl %eax
0x0040b1dc:	pushl $0x101<UINT32>
0x0040b1e1:	call 0x0040d354
0x0040d354:	jmp WSAStartup@WS2_32.dll
WSAStartup@WS2_32.dll: API Node	
0x0040b1e6:	leal %eax, 0x60(%esp)
0x0040b1ea:	movl 0x24(%esp), $0x400<UINT32>
0x0040b1f2:	movl 0x28(%esp), $0x100<UINT32>
0x0040b1fa:	movl 0x10(%esp), %edi
0x0040b1fe:	movl 0x14(%esp), %edi
0x0040b202:	movl 0x1c(%esp), %edi
0x0040b206:	movl 0x20(%esp), %edi
0x0040b20a:	movl 0x2c(%esp), %edi
0x0040b20e:	movl 0x18(%esp), %edi
0x0040b212:	movl 0x38(%esp), $0x20<UINT32>
0x0040b21a:	movl 0x30(%esp), %edi
0x0040b21e:	movl 0x3c(%esp), %edi
0x0040b222:	movl 0x34(%esp), %edi
0x0040b226:	movl 0x40(%esp), %edi
0x0040b22a:	call 0x0040ab73
0x0040ab73:	pushl %esi
0x0040ab74:	movl %esi, %eax
0x0040ab76:	pushl %edi
0x0040ab77:	xorl %edi, %edi
0x0040ab79:	pushl $0x5a0<UINT32>
0x0040ab7e:	movl 0x140(%esi), %edi
0x0040ab84:	movl (%esi), $0x40f27c<UINT32>
0x0040ab8a:	movl 0x298(%esi), %edi
0x0040ab90:	call 0x0040d0c2
0x0040d0c2:	jmp ??2@YAPAXI@Z@msvcrt.dll
??2@YAPAXI@Z@msvcrt.dll: API Node	
0x0040ab95:	movl %edx, %eax
0x0040ab97:	cmpl %edx, %edi
0x0040ab99:	popl %ecx
0x0040ab9a:	je 22
0x0040ab9c:	leal %eax, 0xc(%edx)
0x0040ab9f:	call 0x00401dca
0x00401dca:	xorb %cl, %cl
0x00401dcc:	movl 0x56c(%eax), $0x1<UINT32>
0x00401dd6:	movb (%eax), %cl
0x00401dd8:	movb 0x105(%eax), %cl
0x00401dde:	movb 0x20a(%eax), %cl
0x00401de4:	movb 0x30f(%eax), %cl
0x00401dea:	movb 0x414(%eax), %cl
0x00401df0:	ret

0x0040aba4:	movl 0x598(%edx), %edi
0x0040abaa:	movl 0x411728, %edx
0x0040abb0:	jmp 0x0040abb4
0x0040abb4:	pushl $0x880<UINT32>
0x0040abb9:	movl 0x28c(%esi), %edx
0x0040abbf:	call 0x0040d0c2
0x0040abc4:	cmpl %eax, %edi
0x0040abc6:	popl %ecx
0x0040abc7:	je 7
0x0040abc9:	call 0x0040489a
0x0040489a:	pushl %esi
0x0040489b:	pushl %edi
0x0040489c:	movl %esi, %eax
0x0040489e:	call 0x004072ad
0x004072ad:	pushl %ebx
0x004072ae:	pushl %edi
0x004072af:	pushl %esi
0x004072b0:	movl %eax, $0x1d4<UINT32>
0x004072b5:	movl (%esi), $0x40ef88<UINT32>
0x004072bb:	call 0x00405b72
0x00405b72:	addl %eax, $0xfffffffc<UINT8>
0x00405b75:	pushl %eax
0x00405b76:	movl %eax, 0x8(%esp)
0x00405b7a:	addl %eax, $0x4<UINT8>
0x00405b7d:	pushl $0x0<UINT8>
0x00405b7f:	pushl %eax
0x00405b80:	call 0x0040d080
0x0040d080:	jmp memset@msvcrt.dll
memset@msvcrt.dll: API Node	
0x00405b85:	addl %esp, $0xc<UINT8>
0x00405b88:	ret

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
0x004049d0:	pushl $0x40ec14<UINT32>
0x004049d5:	pushl $0x40ec1c<UINT32>
0x004049da:	pushl %eax
0x004049db:	call MessageBoxA@USER32.dll
MessageBoxA@USER32.dll: API Node	
0x004049e1:	xorl %eax, %eax
0x004049e3:	leave
0x004049e4:	ret

0x0040b1b1:	incl %eax
0x0040b1b2:	popl %edi
0x0040b1b3:	popl %esi
0x0040b1b4:	popl %ebx
0x0040b1b5:	movl %esp, %ebp
0x0040b1b7:	popl %ebp
0x0040b1b8:	ret $0x10<UINT16>

0x0040d27e:	movl %esi, %eax
0x0040d280:	movl -124(%ebp), %esi
0x0040d283:	cmpl -28(%ebp), %ebx
0x0040d286:	jne 7
0x0040d288:	pushl %esi
0x0040d289:	call exit@msvcrt.dll
exit@msvcrt.dll: Exit Node	
