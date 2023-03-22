0x004e5ce0:	pusha
0x004e5ce1:	movl %esi, $0x48b000<UINT32>
0x004e5ce6:	leal %edi, -565248(%esi)
0x004e5cec:	movl 0x9e0a8(%edi), $0xdc75f2f<UINT32>
0x004e5cf6:	pushl %edi
0x004e5cf7:	orl %ebp, $0xffffffff<UINT8>
0x004e5cfa:	jmp 0x004e5d0a
0x004e5d0a:	movl %ebx, (%esi)
0x004e5d0c:	subl %esi, $0xfffffffc<UINT8>
0x004e5d0f:	adcl %ebx, %ebx
0x004e5d11:	jb 0x004e5d00
0x004e5d00:	movb %al, (%esi)
0x004e5d02:	incl %esi
0x004e5d03:	movb (%edi), %al
0x004e5d05:	incl %edi
0x004e5d06:	addl %ebx, %ebx
0x004e5d08:	jne 0x004e5d11
0x004e5d13:	movl %eax, $0x1<UINT32>
0x004e5d18:	addl %ebx, %ebx
0x004e5d1a:	jne 0x004e5d23
0x004e5d23:	adcl %eax, %eax
0x004e5d25:	addl %ebx, %ebx
0x004e5d27:	jae 0x004e5d34
0x004e5d29:	jne 0x004e5d53
0x004e5d53:	xorl %ecx, %ecx
0x004e5d55:	subl %eax, $0x3<UINT8>
0x004e5d58:	jb 0x004e5d6b
0x004e5d6b:	addl %ebx, %ebx
0x004e5d6d:	jne 0x004e5d76
0x004e5d76:	jb 0x004e5d44
0x004e5d44:	addl %ebx, %ebx
0x004e5d46:	jne 0x004e5d4f
0x004e5d4f:	adcl %ecx, %ecx
0x004e5d51:	jmp 0x004e5da5
0x004e5da5:	cmpl %ebp, $0xfffffb00<UINT32>
0x004e5dab:	adcl %ecx, $0x2<UINT8>
0x004e5dae:	leal %edx, (%edi,%ebp)
0x004e5db1:	cmpl %ebp, $0xfffffffc<UINT8>
0x004e5db4:	jbe 0x004e5dc4
0x004e5db6:	movb %al, (%edx)
0x004e5db8:	incl %edx
0x004e5db9:	movb (%edi), %al
0x004e5dbb:	incl %edi
0x004e5dbc:	decl %ecx
0x004e5dbd:	jne 0x004e5db6
0x004e5dbf:	jmp 0x004e5d06
0x004e5d5a:	shll %eax, $0x8<UINT8>
0x004e5d5d:	movb %al, (%esi)
0x004e5d5f:	incl %esi
0x004e5d60:	xorl %eax, $0xffffffff<UINT8>
0x004e5d63:	je 0x004e5dda
0x004e5d65:	sarl %eax
0x004e5d67:	movl %ebp, %eax
0x004e5d69:	jmp 0x004e5d76
0x004e5d78:	incl %ecx
0x004e5d79:	addl %ebx, %ebx
0x004e5d7b:	jne 0x004e5d84
0x004e5d84:	jb 0x004e5d44
0x004e5dc4:	movl %eax, (%edx)
0x004e5dc6:	addl %edx, $0x4<UINT8>
0x004e5dc9:	movl (%edi), %eax
0x004e5dcb:	addl %edi, $0x4<UINT8>
0x004e5dce:	subl %ecx, $0x4<UINT8>
0x004e5dd1:	ja 0x004e5dc4
0x004e5dd3:	addl %edi, %ecx
0x004e5dd5:	jmp 0x004e5d06
0x004e5d2b:	movl %ebx, (%esi)
0x004e5d2d:	subl %esi, $0xfffffffc<UINT8>
0x004e5d30:	adcl %ebx, %ebx
0x004e5d32:	jb 0x004e5d53
0x004e5d48:	movl %ebx, (%esi)
0x004e5d4a:	subl %esi, $0xfffffffc<UINT8>
0x004e5d4d:	adcl %ebx, %ebx
0x004e5d1c:	movl %ebx, (%esi)
0x004e5d1e:	subl %esi, $0xfffffffc<UINT8>
0x004e5d21:	adcl %ebx, %ebx
0x004e5d86:	addl %ebx, %ebx
0x004e5d88:	jne 0x004e5d91
0x004e5d91:	adcl %ecx, %ecx
0x004e5d93:	addl %ebx, %ebx
0x004e5d95:	jae 0x004e5d86
0x004e5d97:	jne 0x004e5da2
0x004e5da2:	addl %ecx, $0x2<UINT8>
0x004e5d34:	decl %eax
0x004e5d35:	addl %ebx, %ebx
0x004e5d37:	jne 0x004e5d40
0x004e5d39:	movl %ebx, (%esi)
0x004e5d3b:	subl %esi, $0xfffffffc<UINT8>
0x004e5d3e:	adcl %ebx, %ebx
0x004e5d40:	adcl %eax, %eax
0x004e5d42:	jmp 0x004e5d18
0x004e5d7d:	movl %ebx, (%esi)
0x004e5d7f:	subl %esi, $0xfffffffc<UINT8>
0x004e5d82:	adcl %ebx, %ebx
0x004e5d8a:	movl %ebx, (%esi)
0x004e5d8c:	subl %esi, $0xfffffffc<UINT8>
0x004e5d8f:	adcl %ebx, %ebx
0x004e5d6f:	movl %ebx, (%esi)
0x004e5d71:	subl %esi, $0xfffffffc<UINT8>
0x004e5d74:	adcl %ebx, %ebx
0x004e5d99:	movl %ebx, (%esi)
0x004e5d9b:	subl %esi, $0xfffffffc<UINT8>
0x004e5d9e:	adcl %ebx, %ebx
0x004e5da0:	jae 0x004e5d86
0x004e5dda:	popl %esi
0x004e5ddb:	movl %edi, %esi
0x004e5ddd:	movl %ecx, $0x51c5<UINT32>
0x004e5de2:	movb %al, (%edi)
0x004e5de4:	incl %edi
0x004e5de5:	subb %al, $0xffffffe8<UINT8>
0x004e5de7:	cmpb %al, $0x1<UINT8>
0x004e5de9:	ja 0x004e5de2
0x004e5deb:	cmpb (%edi), $0x16<UINT8>
0x004e5dee:	jne 0x004e5de2
0x004e5df0:	movl %eax, (%edi)
0x004e5df2:	movb %bl, 0x4(%edi)
0x004e5df5:	shrw %ax, $0x8<UINT8>
0x004e5df9:	roll %eax, $0x10<UINT8>
0x004e5dfc:	xchgb %ah, %al
0x004e5dfe:	subl %eax, %edi
0x004e5e00:	subb %bl, $0xffffffe8<UINT8>
0x004e5e03:	addl %eax, %esi
0x004e5e05:	movl (%edi), %eax
0x004e5e07:	addl %edi, $0x5<UINT8>
0x004e5e0a:	movb %al, %bl
0x004e5e0c:	loop 0x004e5de7
0x004e5e0e:	leal %edi, 0xe2000(%esi)
0x004e5e14:	movl %eax, (%edi)
0x004e5e16:	orl %eax, %eax
0x004e5e18:	je 0x004e5e56
0x004e5e1a:	movl %ebx, 0x4(%edi)
0x004e5e1d:	leal %eax, 0xeca80(%eax,%esi)
0x004e5e24:	addl %ebx, %esi
0x004e5e26:	pushl %eax
0x004e5e27:	addl %edi, $0x8<UINT8>
0x004e5e2a:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x004e5e30:	xchgl %ebp, %eax
0x004e5e31:	movb %al, (%edi)
0x004e5e33:	incl %edi
0x004e5e34:	orb %al, %al
0x004e5e36:	je 0x004e5e14
0x004e5e38:	movl %ecx, %edi
0x004e5e3a:	pushl %edi
0x004e5e3b:	decl %eax
0x004e5e3c:	repn scasb %al, %es:(%edi)
0x004e5e3e:	pushl %ebp
0x004e5e3f:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x004e5e45:	orl %eax, %eax
0x004e5e47:	je 7
0x004e5e49:	movl (%ebx), %eax
0x004e5e4b:	addl %ebx, $0x4<UINT8>
0x004e5e4e:	jmp 0x004e5e31
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x004e5e56:	movl %ebp, 0xecb88(%esi)
0x004e5e5c:	leal %edi, -4096(%esi)
0x004e5e62:	movl %ebx, $0x1000<UINT32>
0x004e5e67:	pushl %eax
0x004e5e68:	pushl %esp
0x004e5e69:	pushl $0x4<UINT8>
0x004e5e6b:	pushl %ebx
0x004e5e6c:	pushl %edi
0x004e5e6d:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x004e5e6f:	leal %eax, 0x21f(%edi)
0x004e5e75:	andb (%eax), $0x7f<UINT8>
0x004e5e78:	andb 0x28(%eax), $0x7f<UINT8>
0x004e5e7c:	popl %eax
0x004e5e7d:	pushl %eax
0x004e5e7e:	pushl %esp
0x004e5e7f:	pushl %eax
0x004e5e80:	pushl %ebx
0x004e5e81:	pushl %edi
0x004e5e82:	call VirtualProtect@kernel32.dll
0x004e5e84:	popl %eax
0x004e5e85:	popa
0x004e5e86:	leal %eax, -128(%esp)
0x004e5e8a:	pushl $0x0<UINT8>
0x004e5e8c:	cmpl %esp, %eax
0x004e5e8e:	jne 0x004e5e8a
0x004e5e90:	subl %esp, $0xffffff80<UINT8>
0x004e5e93:	jmp 0x0049ec68
0x0049ec68:	pushl %ebp
0x0049ec69:	movl %ebp, %esp
0x0049ec6b:	addl %esp, $0xfffffff0<UINT8>
0x0049ec6e:	movl %eax, $0x49e9d0<UINT32>
0x0049ec73:	call 0x00406378
0x00406378:	pushl %ebx
0x00406379:	movl %ebx, %eax
0x0040637b:	xorl %eax, %eax
0x0040637d:	movl 0x49f0a8, %eax
0x00406382:	pushl $0x0<UINT8>
0x00406384:	call 0x004062b4
0x004062b4:	jmp GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x00406389:	movl 0x4a1668, %eax
0x0040638e:	movl %eax, 0x4a1668
0x00406393:	movl 0x49f0b4, %eax
0x00406398:	xorl %eax, %eax
0x0040639a:	movl 0x49f0b8, %eax
0x0040639f:	xorl %eax, %eax
0x004063a1:	movl 0x49f0bc, %eax
0x004063a6:	call 0x0040636c
0x0040636c:	movl %eax, $0x49f0b0<UINT32>
0x00406371:	call 0x00405b7c
0x00405b7c:	movl %edx, 0x49f038
0x00405b82:	movl (%eax), %edx
0x00405b84:	movl 0x49f038, %eax
0x00405b89:	ret

0x00406376:	ret

0x004063ab:	movl %edx, $0x49f0b0<UINT32>
0x004063b0:	movl %eax, %ebx
0x004063b2:	call 0x00403f6c
0x00403f6c:	movl 0x4a1014, $0x401234<UINT32>
0x00403f76:	movl 0x4a1018, $0x40123c<UINT32>
0x00403f80:	movl 0x4a1640, %eax
0x00403f85:	xorl %eax, %eax
0x00403f87:	movl 0x4a1644, %eax
0x00403f8c:	movl 0x4a1648, %edx
0x00403f92:	movl %eax, 0x4(%edx)
0x00403f95:	movl 0x4a1030, %eax
0x00403f9a:	call 0x00403e64
0x00403e64:	xorl %edx, %edx
0x00403e66:	leal %eax, -12(%ebp)
0x00403e69:	movl %ecx, %fs:(%edx)
0x00403e6c:	movl %fs:(%edx), %eax
0x00403e6f:	movl (%eax), %ecx
0x00403e71:	movl 0x4(%eax), $0x403dc4<UINT32>
0x00403e78:	movl 0x8(%eax), %ebp
0x00403e7b:	movl 0x4a163c, %eax
0x00403e80:	ret

0x00403f9f:	movb 0x4a1038, $0x0<UINT8>
0x00403fa6:	call 0x00403f0c
0x00403f0c:	pushl %ebp
0x00403f0d:	movl %ebp, %esp
0x00403f0f:	pushl %ebx
0x00403f10:	pushl %esi
0x00403f11:	pushl %edi
0x00403f12:	movl %eax, 0x4a1640
0x00403f17:	testl %eax, %eax
0x00403f19:	je 75
0x00403f1b:	movl %esi, (%eax)
0x00403f1d:	xorl %ebx, %ebx
0x00403f1f:	movl %edi, 0x4(%eax)
0x00403f22:	xorl %edx, %edx
0x00403f24:	pushl %ebp
0x00403f25:	pushl $0x403f52<UINT32>
0x00403f2a:	pushl %fs:(%edx)
0x00403f2d:	movl %fs:(%edx), %esp
0x00403f30:	cmpl %esi, %ebx
0x00403f32:	jle 20
0x00403f34:	movl %eax, (%edi,%ebx,8)
0x00403f37:	incl %ebx
0x00403f38:	movl 0x4a1644, %ebx
0x00403f3e:	testl %eax, %eax
0x00403f40:	je 2
0x00403f42:	call 0x0042c0f8
0x004063ec:	subl 0x4a166c, $0x1<UINT8>
0x004063f3:	ret

0x00403f44:	cmpl %esi, %ebx
0x00403f46:	jg 0x00403f34
0x004061e0:	subl 0x4a15bc, $0x1<UINT8>
0x004061e7:	jae 197
0x004061ed:	movb 0x49f00c, $0x2<UINT8>
0x004061f4:	movl 0x4a1014, $0x401234<UINT32>
0x004061fe:	movl 0x4a1018, $0x40123c<UINT32>
0x00406208:	movb 0x4a104e, $0x2<UINT8>
0x0040620f:	movl 0x4a1000, $0x4050b0<UINT32>
0x00406219:	call 0x004032d4
0x004032d4:	pushl %ebx
0x004032d5:	xorl %ebx, %ebx
0x004032d7:	pushl $0x0<UINT8>
0x004032d9:	call 0x004032cc
0x004032cc:	jmp GetKeyboardType@user32.dll
GetKeyboardType@user32.dll: API Node	
0x004032de:	cmpl %eax, $0x7<UINT8>
0x004032e1:	jne 28
0x004032e3:	pushl $0x1<UINT8>
0x004032e5:	call 0x004032cc
0x004032ea:	andl %eax, $0xff00<UINT32>
0x004032ef:	cmpl %eax, $0xd00<UINT32>
0x004032f4:	je 7
0x004032f6:	cmpl %eax, $0x400<UINT32>
0x004032fb:	jne 0x004032ff
0x004032ff:	movl %eax, %ebx
0x00403301:	popl %ebx
0x00403302:	ret

0x0040621e:	testb %al, %al
0x00406220:	je 0x00406227
0x00406227:	call 0x004033c8
0x004033c8:	fninit
0x004033ca:	fwait
0x004033cb:	fldcw 0x49f024
0x004033d1:	ret

0x0040622c:	movw 0x4a1054, $0xffffd7b0<UINT16>
0x00406235:	movw 0x4a1220, $0xffffd7b0<UINT16>
0x0040623e:	movw 0x4a13ec, $0xffffd7b0<UINT16>
0x00406247:	call 0x00401284
0x00401284:	jmp GetCommandLineA@KERNEL32.DLL
GetCommandLineA@KERNEL32.DLL: API Node	
0x0040624c:	movl 0x4a1040, %eax
0x00406251:	call 0x00401354
0x00401354:	pushl %ebx
0x00401355:	addl %esp, $0xffffffbc<UINT8>
0x00401358:	movl %ebx, $0xa<UINT32>
0x0040135d:	pushl %esp
0x0040135e:	call 0x004012ac
0x004012ac:	jmp GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x00401363:	testb 0x2c(%esp), $0x1<UINT8>
0x00401368:	je 0x0040136f
0x0040136f:	movl %eax, %ebx
0x00401371:	addl %esp, $0x44<UINT8>
0x00401374:	popl %ebx
0x00401375:	ret

0x00406256:	movl 0x4a103c, %eax
0x0040625b:	call 0x0040133c
0x0040133c:	jmp GetVersion@KERNEL32.DLL
GetVersion@KERNEL32.DLL: API Node	
0x00406260:	andl %eax, $0x80000000<UINT32>
0x00406265:	cmpl %eax, $0x80000000<UINT32>
0x0040626a:	je 45
0x0040626c:	call 0x0040133c
0x00406271:	andl %eax, $0xff<UINT32>
0x00406276:	cmpw %ax, $0x4<UINT8>
0x0040627a:	jbe 12
0x0040627c:	movl 0x4a15c0, $0x3<UINT32>
0x00406286:	jmp 0x004062a8
0x004062a8:	call 0x00401334
0x00401334:	jmp GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x004062ad:	movl 0x4a1034, %eax
0x004062b2:	ret

0x004064a8:	subl 0x4a1674, $0x1<UINT8>
0x004064af:	ret

0x004072a8:	subl 0x4a1678, $0x1<UINT8>
0x004072af:	ret

0x004072e0:	subl 0x4a167c, $0x1<UINT8>
0x004072e7:	ret

0x00416058:	subl 0x4a1848, $0x1<UINT8>
0x0041605f:	ret

0x00407610:	subl 0x4a1680, $0x1<UINT8>
0x00407617:	ret

0x0040e104:	pushl %ebp
0x0040e105:	movl %ebp, %esp
0x0040e107:	xorl %eax, %eax
0x0040e109:	pushl %ebp
0x0040e10a:	pushl $0x40e16c<UINT32>
0x0040e10f:	pushl %fs:(%eax)
0x0040e112:	movl %fs:(%eax), %esp
0x0040e115:	subl 0x4a1794, $0x1<UINT8>
0x0040e11c:	jae 64
0x0040e11e:	movl %eax, $0x40dcb4<UINT32>
0x0040e123:	call 0x00403fd0
0x00403fd0:	pushl %ebx
0x00403fd1:	xorl %ebx, %ebx
0x00403fd3:	pushl %edi
0x00403fd4:	pushl %esi
0x00403fd5:	movl %edi, (%eax,%ebx)
0x00403fd8:	leal %esi, 0x4(%eax,%ebx)
0x00403fdc:	movl %eax, 0x4(%esi)
0x00403fdf:	movl %edx, (%esi)
0x00403fe1:	movl %eax, (%eax,%ebx)
0x00403fe4:	addl %edx, %ebx
0x00403fe6:	call 0x004060c0
0x004060c0:	pushl %ebx
0x004060c1:	pushl %esi
0x004060c2:	addl %esp, $0xfffffc00<UINT32>
0x004060c8:	movl %esi, %edx
0x004060ca:	movl %ebx, %eax
0x004060cc:	testl %ebx, %ebx
0x004060ce:	je 61
0x004060d0:	cmpl 0x4(%ebx), $0x10000<UINT32>
0x004060d7:	jnl 42
0x004060d9:	pushl $0x400<UINT32>
0x004060de:	leal %eax, 0x4(%esp)
0x004060e2:	pushl %eax
0x004060e3:	movl %eax, 0x4(%ebx)
0x004060e6:	pushl %eax
0x004060e7:	movl %eax, (%ebx)
0x004060e9:	movl %eax, (%eax)
0x004060eb:	call 0x0040562c
0x0040562c:	movl %edx, 0x49f038
0x00405632:	testl %edx, %edx
0x00405634:	je 29
0x00405636:	cmpl %eax, 0x4(%edx)
0x00405639:	je 0x00405645
0x00405645:	movl %eax, %edx
0x00405647:	call 0x004055e4
0x004055e4:	pushl %ebx
0x004055e5:	pushl %esi
0x004055e6:	addl %esp, $0xfffffef8<UINT32>
0x004055ec:	movl %ebx, %eax
0x004055ee:	cmpl 0x10(%ebx), $0x0<UINT8>
0x004055f2:	jne 0x0040561f
0x004055f4:	pushl $0x105<UINT32>
0x004055f9:	leal %eax, 0x4(%esp)
0x004055fd:	pushl %eax
0x004055fe:	movl %eax, 0x4(%ebx)
0x00405601:	pushl %eax
0x00405602:	call 0x00401294
0x00401294:	jmp GetModuleFileNameA@KERNEL32.DLL
GetModuleFileNameA@KERNEL32.DLL: API Node	
0x00405607:	movl %eax, %esp
0x00405609:	movb %dl, $0x1<UINT8>
0x0040560b:	call 0x00405820
0x00405820:	pushl %ebp
0x00405821:	movl %ebp, %esp
0x00405823:	addl %esp, $0xfffffee0<UINT32>
0x00405829:	pushl %ebx
0x0040582a:	pushl %esi
0x0040582b:	movl -4(%ebp), %eax
0x0040582e:	pushl $0x105<UINT32>
0x00405833:	leal %eax, -285(%ebp)
0x00405839:	pushl %eax
0x0040583a:	pushl $0x0<UINT8>
0x0040583c:	call 0x00401294
0x00405841:	movb -18(%ebp), $0x0<UINT8>
0x00405845:	leal %eax, -8(%ebp)
0x00405848:	pushl %eax
0x00405849:	pushl $0xf0019<UINT32>
0x0040584e:	pushl $0x0<UINT8>
0x00405850:	pushl $0x405a50<UINT32>
0x00405855:	pushl $0x80000001<UINT32>
0x0040585a:	call 0x004012ec
0x004012ec:	jmp RegOpenKeyExA@advapi32.dll
RegOpenKeyExA@advapi32.dll: API Node	
0x0040585f:	testl %eax, %eax
0x00405861:	je 64
0x00405863:	leal %eax, -8(%ebp)
0x00405866:	pushl %eax
0x00405867:	pushl $0xf0019<UINT32>
0x0040586c:	pushl $0x0<UINT8>
0x0040586e:	pushl $0x405a50<UINT32>
0x00405873:	pushl $0x80000002<UINT32>
0x00405878:	call 0x004012ec
0x0040587d:	testl %eax, %eax
0x0040587f:	je 34
0x00405881:	leal %eax, -8(%ebp)
0x00405884:	pushl %eax
0x00405885:	pushl $0xf0019<UINT32>
0x0040588a:	pushl $0x0<UINT8>
0x0040588c:	pushl $0x405a6c<UINT32>
0x00405891:	pushl $0x80000001<UINT32>
0x00405896:	call 0x004012ec
0x0040589b:	testl %eax, %eax
0x0040589d:	jne 0x0040592c
0x0040592c:	pushl $0x105<UINT32>
0x00405931:	movl %eax, -4(%ebp)
0x00405934:	pushl %eax
0x00405935:	leal %eax, -285(%ebp)
0x0040593b:	pushl %eax
0x0040593c:	call 0x004012cc
0x004012cc:	jmp lstrcpynA@KERNEL32.DLL
lstrcpynA@KERNEL32.DLL: API Node	
0x00405941:	pushl $0x5<UINT8>
0x00405943:	leal %eax, -13(%ebp)
0x00405946:	pushl %eax
0x00405947:	pushl $0x3<UINT8>
0x00405949:	call 0x004012b4
0x004012b4:	jmp GetThreadLocale@KERNEL32.DLL
GetThreadLocale@KERNEL32.DLL: API Node	
0x0040594e:	pushl %eax
0x0040594f:	call 0x0040128c
0x0040128c:	jmp GetLocaleInfoA@KERNEL32.DLL
GetLocaleInfoA@KERNEL32.DLL: API Node	
0x00405954:	xorl %esi, %esi
0x00405956:	cmpb -285(%ebp), $0x0<UINT8>
0x0040595d:	je 227
0x00405963:	cmpb -13(%ebp), $0x0<UINT8>
0x00405967:	jne 0x00405973
0x00405973:	leal %eax, -285(%ebp)
0x00405979:	pushl %eax
0x0040597a:	call 0x004012d4
0x004012d4:	jmp lstrlenA@KERNEL32.DLL
lstrlenA@KERNEL32.DLL: API Node	
0x0040597f:	movl %ebx, %eax
0x00405981:	leal %eax, -285(%ebp)
0x00405987:	addl %ebx, %eax
0x00405989:	jmp 0x0040598c
0x0040598c:	cmpb (%ebx), $0x2e<UINT8>
0x0040598f:	je 0x0040599b
0x00405991:	leal %eax, -285(%ebp)
0x00405997:	cmpl %ebx, %eax
0x00405999:	jne 0x0040598b
0x0040598b:	decl %ebx
0x0040599b:	leal %eax, -285(%ebp)
0x004059a1:	cmpl %ebx, %eax
0x004059a3:	je 157
0x004059a9:	incl %ebx
0x004059aa:	cmpb -18(%ebp), $0x0<UINT8>
0x004059ae:	je 0x004059d8
0x004059d8:	testl %esi, %esi
0x004059da:	jne 106
0x004059dc:	cmpb -13(%ebp), $0x0<UINT8>
0x004059e0:	je 100
0x004059e2:	leal %eax, -285(%ebp)
0x004059e8:	movl %edx, %ebx
0x004059ea:	subl %edx, %eax
0x004059ec:	movl %eax, $0x105<UINT32>
0x004059f1:	subl %eax, %edx
0x004059f3:	pushl %eax
0x004059f4:	leal %eax, -13(%ebp)
0x004059f7:	pushl %eax
0x004059f8:	pushl %ebx
0x004059f9:	call 0x004012cc
0x004059fe:	pushl $0x2<UINT8>
0x00405a00:	pushl $0x0<UINT8>
0x00405a02:	leal %eax, -285(%ebp)
0x00405a08:	pushl %eax
0x00405a09:	call 0x004012bc
0x004012bc:	jmp LoadLibraryExA@KERNEL32.DLL
LoadLibraryExA@KERNEL32.DLL: API Node	
0x00405a0e:	movl %esi, %eax
0x00405a10:	testl %esi, %esi
0x00405a12:	jne 50
0x00405a14:	movb -11(%ebp), $0x0<UINT8>
0x00405a18:	leal %eax, -285(%ebp)
0x00405a1e:	movl %edx, %ebx
0x00405a20:	subl %edx, %eax
0x00405a22:	movl %eax, $0x105<UINT32>
0x00405a27:	subl %eax, %edx
0x00405a29:	pushl %eax
0x00405a2a:	leal %eax, -13(%ebp)
0x00405a2d:	pushl %eax
0x00405a2e:	pushl %ebx
0x00405a2f:	call 0x004012cc
0x00405a34:	pushl $0x2<UINT8>
0x00405a36:	pushl $0x0<UINT8>
0x00405a38:	leal %eax, -285(%ebp)
0x00405a3e:	pushl %eax
0x00405a3f:	call 0x004012bc
0x00405a44:	movl %esi, %eax
0x00405a46:	movl %eax, %esi
0x00405a48:	popl %esi
0x00405a49:	popl %ebx
0x00405a4a:	movl %esp, %ebp
0x00405a4c:	popl %ebp
0x00405a4d:	ret

0x00405610:	movl %esi, %eax
0x00405612:	movl 0x10(%ebx), %esi
0x00405615:	testl %esi, %esi
0x00405617:	jne 6
0x00405619:	movl %eax, 0x4(%ebx)
0x0040561c:	movl 0x10(%ebx), %eax
0x0040561f:	movl %eax, 0x10(%ebx)
0x00405622:	addl %esp, $0x108<UINT32>
0x00405628:	popl %esi
0x00405629:	popl %ebx
0x0040562a:	ret

0x0040564c:	ret

0x004060f0:	pushl %eax
0x004060f1:	call 0x004012c4
0x004012c4:	jmp LoadStringA@user32.dll
LoadStringA@user32.dll: API Node	
0x004060f6:	movl %ecx, %eax
0x004060f8:	movl %edx, %esp
0x004060fa:	movl %eax, %esi
0x004060fc:	call 0x00404314
0x00404314:	pushl %ebx
0x00404315:	pushl %esi
0x00404316:	pushl %edi
0x00404317:	movl %ebx, %eax
0x00404319:	movl %esi, %edx
0x0040431b:	movl %edi, %ecx
0x0040431d:	movl %eax, %edi
0x0040431f:	call 0x004042e8
0x004042e8:	testl %eax, %eax
0x004042ea:	jle 0x00404310
0x00404310:	xorl %eax, %eax
0x00404312:	ret

0x00404324:	movl %ecx, %edi
0x00404326:	movl %edi, %eax
0x00404328:	testl %esi, %esi
0x0040432a:	je 9
0x0040432c:	movl %edx, %eax
0x0040432e:	movl %eax, %esi
0x00404330:	call 0x00402900
0x00402900:	pushl %esi
0x00402901:	pushl %edi
0x00402902:	movl %esi, %eax
0x00402904:	movl %edi, %edx
0x00402906:	movl %eax, %ecx
0x00402908:	cmpl %edi, %esi
0x0040290a:	ja 0x0040291f
0x0040290c:	je 47
0x0040290e:	sarl %ecx, $0x2<UINT8>
0x00402911:	js 42
0x00402913:	rep movsl %es:(%edi), %ds:(%esi)
0x00402915:	movl %ecx, %eax
0x00402917:	andl %ecx, $0x3<UINT8>
0x0040291a:	rep movsb %es:(%edi), %ds:(%esi)
0x0040291c:	popl %edi
0x0040291d:	popl %esi
0x0040291e:	ret

0x00404335:	movl %eax, %ebx
0x00404337:	call 0x00404224
0x00404224:	movl %edx, (%eax)
0x00404226:	testl %edx, %edx
0x00404228:	je 0x00404246
0x00404246:	ret

0x0040433c:	movl (%ebx), %edi
0x0040433e:	popl %edi
0x0040433f:	popl %esi
0x00404340:	popl %ebx
0x00404341:	ret

0x00406101:	jmp 0x0040610d
0x0040610d:	addl %esp, $0x400<UINT32>
0x00406113:	popl %esi
0x00406114:	popl %ebx
0x00406115:	ret

0x00403feb:	addl %esi, $0x8<UINT8>
0x00403fee:	decl %edi
0x00403fef:	jne 0x00403fdc
0x00403ff1:	popl %esi
0x00403ff2:	popl %edi
0x00403ff3:	popl %ebx
0x00403ff4:	ret

0x0040e128:	movl %eax, $0x40dda0<UINT32>
0x0040e12d:	call 0x00403ff8
0x00403ff8:	pushl %ebx
0x00403ff9:	xorl %ebx, %ebx
0x00403ffb:	pushl %edi
0x00403ffc:	pushl %esi
0x00403ffd:	movl %edi, (%eax,%ebx)
0x00404000:	leal %esi, 0x4(%eax,%ebx)
0x00404004:	movl %eax, 0x4(%esi)
0x00404007:	movl %edx, (%esi)
0x00404009:	movl %eax, (%eax,%ebx)
0x0040400c:	addl %eax, 0x8(%esi)
0x0040400f:	movl (%edx,%ebx), %eax
0x00404012:	addl %esi, $0xc<UINT8>
0x00404015:	decl %edi
0x00404016:	jne 0x00404004
0x00404018:	popl %esi
0x00404019:	popl %edi
0x0040401a:	popl %ebx
0x0040401b:	ret

0x0040e132:	cmpb 0x4a1665, $0x0<UINT8>
0x0040e139:	je 0x0040e14a
0x0040e14a:	call 0x0040c700
0x0040c700:	movl %ecx, 0x4a0628
0x0040c706:	movb %dl, $0x1<UINT8>
0x0040c708:	movl %eax, 0x40770c
0x0040c70d:	call 0x0040c0b8
0x0040c0b8:	pushl %ebx
0x0040c0b9:	pushl %esi
0x0040c0ba:	pushl %edi
0x0040c0bb:	testb %dl, %dl
0x0040c0bd:	je 8
0x0040c0bf:	addl %esp, $0xfffffff0<UINT8>
0x0040c0c2:	call 0x004037f8
0x004037f8:	pushl %edx
0x004037f9:	pushl %ecx
0x004037fa:	pushl %ebx
0x004037fb:	testb %dl, %dl
0x004037fd:	jl 3
0x004037ff:	call 0x0040342c
0x0040342c:	pushl %ebx
0x0040342d:	movl %ebx, %eax
0x0040342f:	movl %eax, %ebx
0x00403431:	call 0x0040345c
0x0040345c:	addl %eax, $0xffffffd8<UINT8>
0x0040345f:	movl %eax, (%eax)
0x00403461:	ret

0x00403436:	call 0x00402704
0x00402704:	pushl %ebx
0x00402705:	testl %eax, %eax
0x00402707:	jle 21
0x00402709:	call 0x00402130
0x00402130:	pushl %ebp
0x00402131:	movl %ebp, %esp
0x00402133:	addl %esp, $0xfffffff8<UINT8>
0x00402136:	pushl %ebx
0x00402137:	pushl %esi
0x00402138:	pushl %edi
0x00402139:	movl %ebx, %eax
0x0040213b:	cmpb 0x4a15c4, $0x0<UINT8>
0x00402142:	jne 0x0040214d
0x00402144:	call 0x00401a44
0x00401a44:	pushl %ebp
0x00401a45:	movl %ebp, %esp
0x00401a47:	xorl %edx, %edx
0x00401a49:	pushl %ebp
0x00401a4a:	pushl $0x401afa<UINT32>
0x00401a4f:	pushl %fs:(%edx)
0x00401a52:	movl %fs:(%edx), %esp
0x00401a55:	pushl $0x4a15cc<UINT32>
0x00401a5a:	call 0x00401398
0x00401398:	jmp InitializeCriticalSection@KERNEL32.DLL
InitializeCriticalSection@KERNEL32.DLL: API Node	
0x00401a5f:	cmpb 0x4a104d, $0x0<UINT8>
0x00401a66:	je 0x00401a72
0x00401a72:	movl %eax, $0x4a15ec<UINT32>
0x00401a77:	call 0x00401408
0x00401408:	movl (%eax), %eax
0x0040140a:	movl 0x4(%eax), %eax
0x0040140d:	ret

0x00401a7c:	movl %eax, $0x4a15fc<UINT32>
0x00401a81:	call 0x00401408
0x00401a86:	movl %eax, $0x4a1628<UINT32>
0x00401a8b:	call 0x00401408
0x00401a90:	pushl $0xff8<UINT32>
0x00401a95:	pushl $0x0<UINT8>
0x00401a97:	call 0x00401378
0x00401378:	jmp LocalAlloc@KERNEL32.DLL
LocalAlloc@KERNEL32.DLL: API Node	
0x00401a9c:	movl 0x4a1624, %eax
0x00401aa1:	cmpl 0x4a1624, $0x0<UINT8>
0x00401aa8:	je 47
0x00401aaa:	movl %eax, $0x3<UINT32>
0x00401aaf:	movl %edx, 0x4a1624
0x00401ab5:	xorl %ecx, %ecx
0x00401ab7:	movl -12(%edx,%eax,4), %ecx
0x00401afa:	jmp 0x00403c28
0x00403c28:	movl %eax, 0x4(%esp)
0x00403c2c:	movl %edx, 0x8(%esp)
0x00403c30:	testl 0x4(%eax), $0x6<UINT32>
0x00403c37:	je 0x00403c58
0x00403c58:	movl %eax, $0x1<UINT32>
0x00403c5d:	ret

0x00401abb:	incl %eax
0x00401abc:	cmpl %eax, $0x401<UINT32>
0x00401ac1:	jne 0x00401aaf
0x00401ac3:	movl %eax, $0x4a160c<UINT32>
0x00401ac8:	movl 0x4(%eax), %eax
0x00401acb:	movl (%eax), %eax
0x00401acd:	movl 0x4a1618, %eax
0x00401ad2:	movb 0x4a15c4, $0x1<UINT8>
0x00401ad9:	xorl %eax, %eax
0x00401adb:	popl %edx
0x00401adc:	popl %ecx
0x00401add:	popl %ecx
0x00401ade:	movl %fs:(%eax), %edx
0x00401ae1:	pushl $0x401b01<UINT32>
0x00401ae6:	cmpb 0x4a104d, $0x0<UINT8>
0x00401aed:	je 0x00401af9
0x00401af9:	ret

0x00401b01:	movb %al, 0x4a15c4
0x00401b06:	popl %ebp
0x00401b07:	ret

0x00402149:	testb %al, %al
0x0040214b:	je 8
0x0040214d:	cmpl %ebx, $0x7ffffff8<UINT32>
0x00402153:	jle 0x0040215f
0x0040215f:	xorl %ecx, %ecx
0x00402161:	pushl %ebp
0x00402162:	pushl $0x4022ac<UINT32>
0x00402167:	pushl %fs:(%ecx)
0x0040216a:	movl %fs:(%ecx), %esp
0x0040216d:	cmpb 0x4a104d, $0x0<UINT8>
0x00402174:	je 0x00402180
0x00402180:	addl %ebx, $0x7<UINT8>
0x00402183:	andl %ebx, $0xfffffffc<UINT8>
0x00402186:	cmpl %ebx, $0xc<UINT8>
0x00402189:	jnl 0x00402190
0x00402190:	cmpl %ebx, $0x1000<UINT32>
0x00402196:	jg 147
0x0040219c:	movl %eax, %ebx
0x0040219e:	testl %eax, %eax
0x004021a0:	jns 0x004021a5
0x004021a5:	sarl %eax, $0x2<UINT8>
0x004021a8:	movl %edx, 0x4a1624
0x004021ae:	movl %edx, -12(%edx,%eax,4)
0x004021b2:	testl %edx, %edx
0x004021b4:	je 0x0040222f
0x0040222f:	cmpl %ebx, 0x4a161c
0x00402235:	jg 0x00402281
0x00402281:	movl %eax, %ebx
0x00402283:	call 0x0040203c
0x0040203c:	pushl %ebx
0x0040203d:	pushl %esi
0x0040203e:	pushl %edi
0x0040203f:	pushl %ebp
0x00402040:	movl %esi, %eax
0x00402042:	movl %edi, $0x4a1618<UINT32>
0x00402047:	movl %ebp, $0x4a161c<UINT32>
0x0040204c:	movl %ebx, 0x4a1610
0x00402052:	cmpl %esi, 0x8(%ebx)
0x00402055:	jle 0x004020df
0x0040205b:	movl %ebx, (%edi)
0x0040205d:	movl %eax, 0x8(%ebx)
0x00402060:	cmpl %esi, %eax
0x00402062:	jle 123
0x00402064:	movl 0x8(%ebx), %esi
0x00402067:	movl %ebx, 0x4(%ebx)
0x0040206a:	cmpl %esi, 0x8(%ebx)
0x0040206d:	jg -8
0x0040206f:	movl %edx, (%edi)
0x00402071:	movl 0x8(%edx), %eax
0x00402074:	cmpl %ebx, (%edi)
0x00402076:	je 0x0040207c
0x0040207c:	cmpl %esi, $0x1000<UINT32>
0x00402082:	jg 13
0x00402084:	movl %eax, %esi
0x00402086:	call 0x00402010
0x00402010:	xorl %edx, %edx
0x00402012:	testl %eax, %eax
0x00402014:	jns 0x00402019
0x00402019:	sarl %eax, $0x2<UINT8>
0x0040201c:	cmpl %eax, $0x400<UINT32>
0x00402021:	jg 22
0x00402023:	movl %edx, 0x4a1624
0x00402029:	movl %edx, -12(%edx,%eax,4)
0x0040202d:	testl %edx, %edx
0x0040202f:	jne 8
0x00402031:	incl %eax
0x00402032:	cmpl %eax, $0x401<UINT32>
0x00402037:	jne 0x00402023
0x00402039:	movl %eax, %edx
0x0040203b:	ret

0x0040208b:	movl %ebx, %eax
0x0040208d:	testl %ebx, %ebx
0x0040208f:	jne 78
0x00402091:	movl %eax, %esi
0x00402093:	call 0x00401fb0
0x00401fb0:	pushl %ebx
0x00401fb1:	addl %esp, $0xfffffff8<UINT8>
0x00401fb4:	movl %ebx, %eax
0x00401fb6:	movl %edx, %esp
0x00401fb8:	leal %eax, 0x4(%ebx)
0x00401fbb:	call 0x00401804
0x00401804:	pushl %ebx
0x00401805:	pushl %esi
0x00401806:	pushl %edi
0x00401807:	pushl %ebp
0x00401808:	addl %esp, $0xfffffff8<UINT8>
0x0040180b:	movl %esi, %edx
0x0040180d:	movl %edi, %eax
0x0040180f:	movl %ebp, $0x4a15fc<UINT32>
0x00401814:	addl %edi, $0x3fff<UINT32>
0x0040181a:	andl %edi, $0xffffc000<UINT32>
0x00401820:	movl %ebx, (%ebp)
0x00401823:	jmp 0x00401858
0x00401858:	cmpl %ebx, %ebp
0x0040185a:	jne 0x00401825
0x0040185c:	movl %edx, %esi
0x0040185e:	movl %eax, %edi
0x00401860:	call 0x0040155c
0x0040155c:	pushl %ebx
0x0040155d:	pushl %esi
0x0040155e:	pushl %edi
0x0040155f:	movl %ebx, %edx
0x00401561:	movl %esi, %eax
0x00401563:	cmpl %esi, $0x100000<UINT32>
0x00401569:	jnl 7
0x0040156b:	movl %esi, $0x100000<UINT32>
0x00401570:	jmp 0x0040157e
0x0040157e:	movl 0x4(%ebx), %esi
0x00401581:	pushl $0x1<UINT8>
0x00401583:	pushl $0x2000<UINT32>
0x00401588:	pushl %esi
0x00401589:	pushl $0x0<UINT8>
0x0040158b:	call 0x00401388
0x00401388:	jmp VirtualAlloc@KERNEL32.DLL
VirtualAlloc@KERNEL32.DLL: API Node	
0x00401590:	movl %edi, %eax
0x00401592:	movl (%ebx), %edi
0x00401594:	testl %edi, %edi
0x00401596:	je 35
0x00401598:	movl %edx, %ebx
0x0040159a:	movl %eax, $0x4a15ec<UINT32>
0x0040159f:	call 0x00401410
0x00401410:	pushl %ebx
0x00401411:	pushl %esi
0x00401412:	movl %esi, %edx
0x00401414:	movl %ebx, %eax
0x00401416:	call 0x004013b8
0x004013b8:	pushl %ebx
0x004013b9:	pushl %esi
0x004013ba:	movl %esi, $0x4a15e8<UINT32>
0x004013bf:	cmpl (%esi), $0x0<UINT8>
0x004013c2:	jne 0x004013fe
0x004013c4:	pushl $0x644<UINT32>
0x004013c9:	pushl $0x0<UINT8>
0x004013cb:	call 0x00401378
0x004013d0:	movl %ecx, %eax
0x004013d2:	testl %ecx, %ecx
0x004013d4:	jne 0x004013db
0x004013db:	movl %eax, 0x4a15e4
0x004013e0:	movl (%ecx), %eax
0x004022ac:	jmp 0x00403c28
0x004013e2:	movl 0x4a15e4, %ecx
0x004013e8:	xorl %edx, %edx
0x004013ea:	movl %eax, %edx
0x004013ec:	addl %eax, %eax
0x004013ee:	leal %eax, 0x4(%ecx,%eax,8)
0x004013f2:	movl %ebx, (%esi)
0x004013f4:	movl (%eax), %ebx
0x004013f6:	movl (%esi), %eax
0x004013f8:	incl %edx
0x004013f9:	cmpl %edx, $0x64<UINT8>
0x004013fc:	jne 0x004013ea
0x004013fe:	movl %eax, (%esi)
0x00401400:	movl %edx, (%eax)
0x00401402:	movl (%esi), %edx
0x00401404:	popl %esi
0x00401405:	popl %ebx
0x00401406:	ret

0x0040141b:	testl %eax, %eax
0x0040141d:	jne 0x00401424
0x00401424:	movl %edx, (%esi)
0x00401426:	movl 0x8(%eax), %edx
0x00401429:	movl %edx, 0x4(%esi)
0x0040142c:	movl 0xc(%eax), %edx
0x0040142f:	movl %edx, (%ebx)
0x00401431:	movl (%eax), %edx
0x00401433:	movl 0x4(%eax), %ebx
0x00401436:	movl 0x4(%edx), %eax
0x00401439:	movl (%ebx), %eax
0x0040143b:	movb %al, $0x1<UINT8>
0x0040143d:	popl %esi
0x0040143e:	popl %ebx
0x0040143f:	ret

0x004015a4:	testb %al, %al
0x004015a6:	jne 0x004015bb
0x004015bb:	popl %edi
0x004015bc:	popl %esi
0x004015bd:	popl %ebx
0x004015be:	ret

0x00401865:	cmpl (%esi), $0x0<UINT8>
0x00401868:	je 33
0x0040186a:	movl %ecx, %esp
0x0040186c:	movl %edx, %esi
0x0040186e:	movl %eax, %ebp
0x00401870:	call 0x00401458
0x00401458:	pushl %ebx
0x00401459:	pushl %esi
0x0040145a:	pushl %edi
0x0040145b:	pushl %ebp
0x0040145c:	pushl %ecx
0x0040145d:	movl %esi, %ecx
0x0040145f:	movl (%esp), %edx
0x00401462:	movl %ebp, %eax
0x00401464:	movl %ebx, (%ebp)
0x00401467:	movl %eax, (%esp)
0x0040146a:	movl %edx, (%eax)
0x0040146c:	movl (%esi), %edx
0x0040146e:	movl %edx, 0x4(%eax)
0x00401471:	movl 0x4(%esi), %edx
0x00401474:	movl %edi, (%ebx)
0x00401476:	movl %eax, (%esi)
0x00401478:	movl %edx, 0x8(%ebx)
0x0040147b:	addl %edx, 0xc(%ebx)
0x0040147e:	cmpl %eax, %edx
0x00401480:	jne 0x00401496
0x00401496:	addl %eax, 0x4(%esi)
0x00401499:	cmpl %eax, 0x8(%ebx)
0x0040149c:	jne 0x004014ab
0x004014ab:	movl %ebx, %edi
0x004014ad:	cmpl %ebp, %ebx
0x004014af:	jne -61
0x004014b1:	movl %edx, %esi
0x004014b3:	movl %eax, %ebp
0x004014b5:	call 0x00401410
0x004014ba:	testb %al, %al
0x004014bc:	jne 0x004014c2
0x004014c2:	popl %edx
0x004014c3:	popl %ebp
0x004014c4:	popl %edi
0x004014c5:	popl %esi
0x004014c6:	popl %ebx
0x004014c7:	ret

0x00401875:	cmpl (%esp), $0x0<UINT8>
0x00401879:	jne 0x00401820
0x00401825:	cmpl %edi, 0xc(%ebx)
0x00401828:	jg 44
0x0040182a:	movl %ecx, %esi
0x0040182c:	movl %edx, %edi
0x0040182e:	movl %eax, 0x8(%ebx)
0x00401831:	call 0x004016f0
0x004016f0:	pushl %ebx
0x004016f1:	pushl %esi
0x004016f2:	pushl %edi
0x004016f3:	pushl %ebp
0x004016f4:	addl %esp, $0xfffffff4<UINT8>
0x004016f7:	movl 0x4(%esp), %ecx
0x004016fb:	movl (%esp), %edx
0x004016fe:	movl %edx, %eax
0x00401700:	movl %ebp, %edx
0x00401702:	andl %ebp, $0xfffff000<UINT32>
0x00401708:	addl %edx, (%esp)
0x0040170b:	addl %edx, $0xfff<UINT32>
0x00401711:	andl %edx, $0xfffff000<UINT32>
0x00401717:	movl 0x8(%esp), %edx
0x0040171b:	movl %eax, 0x4(%esp)
0x0040171f:	movl (%eax), %ebp
0x00401721:	movl %eax, 0x8(%esp)
0x00401725:	subl %eax, %ebp
0x00401727:	movl %edx, 0x4(%esp)
0x0040172b:	movl 0x4(%edx), %eax
0x0040172e:	movl %esi, 0x4a15ec
0x00401734:	jmp 0x00401772
0x00401772:	cmpl %esi, $0x4a15ec<UINT32>
0x00401778:	jne 0x00401736
0x00401736:	movl %ebx, 0x8(%esi)
0x00401739:	movl %edi, 0xc(%esi)
0x0040173c:	addl %edi, %ebx
0x0040173e:	cmpl %ebp, %ebx
0x00401740:	jbe 0x00401744
0x00401744:	cmpl %edi, 0x8(%esp)
0x00401748:	jbe 4
0x0040174a:	movl %edi, 0x8(%esp)
0x0040174e:	cmpl %edi, %ebx
0x00401750:	jbe 30
0x00401752:	pushl $0x4<UINT8>
0x00401754:	pushl $0x1000<UINT32>
0x00401759:	subl %edi, %ebx
0x0040175b:	pushl %edi
0x0040175c:	pushl %ebx
0x0040175d:	call 0x00401388
0x00401762:	testl %eax, %eax
0x00401764:	jne 0x00401770
0x00401770:	movl %esi, (%esi)
0x0040177a:	addl %esp, $0xc<UINT8>
0x0040177d:	popl %ebp
0x0040177e:	popl %edi
0x0040177f:	popl %esi
0x00401780:	popl %ebx
0x00401781:	ret

0x00401836:	cmpl (%esi), $0x0<UINT8>
0x00401839:	je 80
0x0040183b:	movl %eax, 0x4(%esi)
0x0040183e:	addl 0x8(%ebx), %eax
0x00401841:	movl %eax, 0x4(%esi)
0x00401844:	subl 0xc(%ebx), %eax
0x00401847:	cmpl 0xc(%ebx), $0x0<UINT8>
0x0040184b:	jne 0x0040188b
0x0040188b:	popl %ecx
0x0040188c:	popl %edx
0x0040188d:	popl %ebp
0x0040188e:	popl %edi
0x0040188f:	popl %esi
0x00401890:	popl %ebx
0x00401891:	ret

0x00401fc0:	cmpl (%esp), $0x0<UINT8>
0x00401fc4:	je 11
0x00401fc6:	movl %eax, %esp
0x00401fc8:	call 0x00401f24
0x00401f24:	pushl %ebx
0x00401f25:	pushl %esi
0x00401f26:	pushl %edi
0x00401f27:	addl %esp, $0xfffffff0<UINT8>
0x00401f2a:	movl %esi, %eax
0x00401f2c:	leal %edi, (%esp)
0x00401f2f:	movsl %es:(%edi), %ds:(%esi)
0x00401f30:	movsl %es:(%edi), %ds:(%esi)
0x00401f31:	movl %edi, %esp
0x00401f33:	call 0x00401ed8
0x00401ed8:	cmpl 0x4a161c, $0x0<UINT8>
0x00401edf:	jle 0x00401f21
0x00401f21:	ret

0x00401f38:	leal %ecx, 0x8(%esp)
0x00401f3c:	movl %edx, %edi
0x00401f3e:	movl %eax, $0x4a1628<UINT32>
0x00401f43:	call 0x00401458
0x00401f48:	movl %ebx, 0x8(%esp)
0x00401f4c:	testl %ebx, %ebx
0x00401f4e:	jne 0x00401f54
0x00401f54:	movl %eax, (%edi)
0x00401f56:	cmpl %ebx, %eax
0x00401f58:	jae 0x00401f64
0x00401f64:	movl %eax, (%edi)
0x00401f66:	addl %eax, 0x4(%edi)
0x00401f69:	movl %esi, %ebx
0x00401f6b:	addl %esi, 0xc(%esp)
0x00401f6f:	cmpl %eax, %esi
0x00401f71:	jae 0x00401f7b
0x00401f7b:	movl %eax, (%edi)
0x00401f7d:	addl %eax, 0x4(%edi)
0x00401f80:	cmpl %esi, %eax
0x00401f82:	jne 17
0x00401f84:	subl %eax, $0x4<UINT8>
0x00401f87:	movl %edx, $0x4<UINT32>
0x00401f8c:	call 0x00401c7c
0x00401c7c:	pushl %ebx
0x00401c7d:	movl %ecx, %edx
0x00401c7f:	subl %ecx, $0x4<UINT8>
0x00401c82:	leal %ebx, (%ecx,%eax)
0x00401c85:	cmpl %edx, $0x10<UINT8>
0x00401c88:	jl 0x00401c99
0x00401c99:	cmpl %edx, $0x4<UINT8>
0x00401c9c:	jl 12
0x00401c9e:	movl %ecx, %edx
0x00401ca0:	orl %ecx, $0x80000002<UINT32>
0x00401ca6:	movl (%eax), %ecx
0x00401ca8:	movl (%ebx), %ecx
0x00401caa:	popl %ebx
0x00401cab:	ret

0x00401f91:	subl 0x4(%edi), $0x4<UINT8>
0x00401f95:	movl %eax, (%edi)
0x00401f97:	movl 0x4a1620, %eax
0x00401f9c:	movl %eax, 0x4(%edi)
0x00401f9f:	movl 0x4a161c, %eax
0x00401fa4:	movb %al, $0x1<UINT8>
0x00401fa6:	addl %esp, $0x10<UINT8>
0x00401fa9:	popl %edi
0x00401faa:	popl %esi
0x00401fab:	popl %ebx
0x00401fac:	ret

0x00401fcd:	testb %al, %al
0x00401fcf:	jne 0x00401fd5
0x00401fd5:	movb %al, $0x1<UINT8>
0x00401fd7:	popl %ecx
0x00401fd8:	popl %edx
0x00401fd9:	popl %ebx
0x00401fda:	ret

0x00402098:	testb %al, %al
0x0040209a:	jne 0x004020a3
0x004020a3:	cmpl %esi, (%ebp)
0x004020a6:	jg -92
0x004020a8:	subl (%ebp), %esi
0x004020ab:	cmpl (%ebp), $0xc<UINT8>
0x004020af:	jnl 0x004020b9
0x004020b9:	movl %eax, 0x4a1620
0x004020be:	addl 0x4a1620, %esi
0x004020c4:	movl %edx, %esi
0x004020c6:	orl %edx, $0x2<UINT8>
0x004020c9:	movl (%eax), %edx
0x004020cb:	addl %eax, $0x4<UINT8>
0x004020ce:	incl 0x4a15b4
0x004020d4:	subl %esi, $0x4<UINT8>
0x004020d7:	addl 0x4a15b8, %esi
0x004020dd:	jmp 0x0040212b
0x0040212b:	popl %ebp
0x0040212c:	popl %edi
0x0040212d:	popl %esi
0x0040212e:	popl %ebx
0x0040212f:	ret

0x00402288:	movl -4(%ebp), %eax
0x0040228b:	xorl %eax, %eax
0x0040228d:	popl %edx
0x0040228e:	popl %ecx
0x0040228f:	popl %ecx
0x00402290:	movl %fs:(%eax), %edx
0x00402293:	pushl $0x4022b3<UINT32>
0x00402298:	cmpb 0x4a104d, $0x0<UINT8>
0x0040229f:	je 0x004022ab
0x004022ab:	ret

0x004022b3:	movl %eax, -4(%ebp)
0x004022b6:	popl %edi
0x004022b7:	popl %esi
0x004022b8:	popl %ebx
0x004022b9:	popl %ecx
0x004022ba:	popl %ecx
0x004022bb:	popl %ebp
0x004022bc:	ret

0x0040270f:	movl %ebx, %eax
0x00402711:	testl %ebx, %ebx
0x00402713:	jne 0x00402720
0x00402720:	movl %eax, %ebx
0x00402722:	popl %ebx
0x00402723:	ret

0x0040343b:	movl %edx, %eax
0x0040343d:	movl %eax, %ebx
0x0040343f:	call 0x004034a0
0x004034a0:	pushl %ebx
0x004034a1:	pushl %esi
0x004034a2:	pushl %edi
0x004034a3:	movl %ebx, %eax
0x004034a5:	movl %edi, %edx
0x004034a7:	stosl %es:(%edi), %eax
0x004034a8:	movl %ecx, -40(%ebx)
0x004034ab:	xorl %eax, %eax
0x004034ad:	pushl %ecx
0x004034ae:	shrl %ecx, $0x2<UINT8>
0x004034b1:	decl %ecx
0x004034b2:	rep stosl %es:(%edi), %eax
0x004034b4:	popl %ecx
0x004034b5:	andl %ecx, $0x3<UINT8>
0x004034b8:	rep stosb %es:(%edi), %al
0x004034ba:	movl %eax, %edx
0x004034bc:	movl %edx, %esp
0x004034be:	movl %ecx, -72(%ebx)
0x004034c1:	testl %ecx, %ecx
0x004034c3:	je 0x004034c6
0x004034c6:	movl %ebx, -36(%ebx)
0x004034c9:	testl %ebx, %ebx
0x004034cb:	je 0x004034d1
0x004034cd:	movl %ebx, (%ebx)
0x004034cf:	jmp 0x004034be
0x004034d1:	cmpl %esp, %edx
0x004034d3:	je 0x004034f2
0x004034f2:	popl %edi
0x004034f3:	popl %esi
0x004034f4:	popl %ebx
0x004034f5:	ret

0x00403444:	popl %ebx
0x00403445:	ret

0x00403802:	xorl %edx, %edx
0x00403804:	leal %ecx, 0x10(%esp)
0x00403808:	movl %ebx, %fs:(%edx)
0x0040380b:	movl (%ecx), %ebx
0x0040380d:	movl 0x8(%ecx), %ebp
0x00403810:	movl 0x4(%ecx), $0x403821<UINT32>
0x00403817:	movl 0xc(%ecx), %eax
0x0040381a:	movl %fs:(%edx), %ecx
0x0040381d:	popl %ebx
0x0040381e:	popl %ecx
0x0040381f:	popl %edx
0x00403820:	ret

0x0040c0c7:	movl %esi, %ecx
0x0040c0c9:	movl %ebx, %edx
0x0040c0cb:	movl %edi, %eax
0x0040c0cd:	leal %edx, 0x4(%edi)
0x0040c0d0:	movl %eax, %esi
0x0040c0d2:	call 0x004060c0
0x0040c0d7:	movl %eax, %edi
0x0040c0d9:	testb %bl, %bl
0x0040c0db:	je 15
0x0040c0dd:	call 0x00403850
0x00403850:	pushl %ebx
0x00403851:	movl %ebx, %eax
0x00403853:	movl %eax, %ebx
0x00403855:	movl %edx, (%eax)
0x00403857:	call 0x004036e8
0x004036e8:	ret

0x0040385a:	movl %eax, %ebx
0x0040385c:	popl %ebx
0x0040385d:	ret

0x0040c0e2:	popl %fs:0
0x0040c0e9:	addl %esp, $0xc<UINT8>
0x0040c0ec:	movl %eax, %edi
0x0040c0ee:	popl %edi
0x0040c0ef:	popl %esi
0x0040c0f0:	popl %ebx
0x0040c0f1:	ret

0x0040c712:	movl 0x4a1798, %eax
0x0040c717:	movl %ecx, 0x4a081c
0x0040c71d:	movb %dl, $0x1<UINT8>
0x0040c71f:	movl %eax, 0x407b94
0x0040c724:	call 0x0040c0b8
0x00402237:	subl 0x4a161c, %ebx
0x0040223d:	cmpl 0x4a161c, $0xc<UINT8>
0x00402244:	jnl 0x00402253
0x00402253:	movl %eax, 0x4a1620
0x00402258:	addl 0x4a1620, %ebx
0x0040225e:	movl %edx, %ebx
0x00402260:	orl %edx, $0x2<UINT8>
0x00402263:	movl (%eax), %edx
0x00402265:	addl %eax, $0x4<UINT8>
0x00402268:	movl -4(%ebp), %eax
0x0040226b:	incl 0x4a15b4
0x00402271:	subl %ebx, $0x4<UINT8>
0x00402274:	addl 0x4a15b8, %ebx
0x0040227a:	call 0x00403d0c
0x00403d0c:	xorl %edx, %edx
0x00403d0e:	movl %ecx, 0x8(%esp)
0x00403d12:	movl %eax, 0x4(%esp)
0x00403d16:	addl %ecx, $0x5<UINT8>
0x00403d19:	movl %fs:(%edx), %eax
0x00403d1c:	call 0x00402457
0x004022b1:	jmp 0x00402298
0x00403d1e:	ret $0xc<UINT16>

0x0040227f:	jmp 0x004022b3
0x0040c729:	movl 0x4a179c, %eax
0x0040c72e:	movl %eax, 0x4a056c
0x0040c733:	movl (%eax), $0x40c27c<UINT32>
0x0040c739:	movl %eax, 0x4a06b8
0x0040c73e:	movl (%eax), $0x40c6f0<UINT32>
0x0040c744:	movl %eax, 0x4a060c
0x0040c749:	movl %edx, 0x407648
0x0040c74f:	movl (%eax), %edx
0x0040c751:	movl %eax, 0x4a069c
0x0040c756:	movl (%eax), $0x40c440<UINT32>
0x0040c75c:	movl %eax, 0x4a06c0
0x0040c761:	movl (%eax), $0x40c624<UINT32>
0x0040c767:	movl %eax, $0x40c38c<UINT32>
0x0040c76c:	movl %edx, 0x4a0848
0x0040c772:	movl (%edx), %eax
0x0040c774:	movl %eax, $0x40c3a8<UINT32>
0x0040c779:	movl %edx, 0x4a0554
0x0040c77f:	movl (%edx), %eax
0x0040c781:	ret

0x0040e14f:	call 0x0040c804
0x0040c804:	addl %esp, $0xffffff6c<UINT32>
0x0040c80a:	movl (%esp), $0x94<UINT32>
0x0040c811:	pushl %esp
0x0040c812:	call 0x00406714
0x00406714:	jmp GetVersionExA@KERNEL32.DLL
GetVersionExA@KERNEL32.DLL: API Node	
0x0040c817:	testl %eax, %eax
0x0040c819:	je 80
0x0040c81b:	movl %eax, 0x10(%esp)
0x0040c81f:	movl 0x49f0d0, %eax
0x0040c824:	movl %eax, 0x4(%esp)
0x0040c828:	movl 0x49f0d4, %eax
0x0040c82d:	movl %eax, 0x8(%esp)
0x0040c831:	movl 0x49f0d8, %eax
0x0040c836:	cmpl 0x49f0d0, $0x1<UINT8>
0x0040c83d:	jne 0x0040c84f
0x0040c84f:	movl %eax, 0xc(%esp)
0x0040c853:	movl 0x49f0dc, %eax
0x0040c858:	movl %eax, $0x49f0e0<UINT32>
0x0040c85d:	leal %edx, 0x14(%esp)
0x0040c861:	movl %ecx, $0x80<UINT32>
0x0040c866:	call 0x00404494
0x00404494:	pushl %edi
0x00404495:	pushl %eax
0x00404496:	pushl %ecx
0x00404497:	movl %edi, %edx
0x00404499:	xorl %eax, %eax
0x0040449b:	repn scasb %al, %es:(%edi)
0x0040449d:	jne 2
0x0040449f:	notl %ecx
0x004044a1:	popl %eax
0x004044a2:	addl %ecx, %eax
0x004044a4:	popl %eax
0x004044a5:	popl %edi
0x004044a6:	jmp 0x00404314
0x004042ec:	pushl %eax
0x004042ed:	addl %eax, $0xa<UINT8>
0x004042f0:	andl %eax, $0xfffffffe<UINT8>
0x004042f3:	pushl %eax
0x004042f4:	call 0x00402704
0x004042f9:	popl %edx
0x004042fa:	movw -2(%edx,%eax), $0x0<UINT16>
0x00404301:	addl %eax, $0x8<UINT8>
0x00404304:	popl %edx
0x00404305:	movl -4(%eax), %edx
0x00404308:	movl -8(%eax), $0x1<UINT32>
0x0040430f:	ret

0x0040291f:	leal %esi, -4(%ecx,%esi)
0x00402923:	leal %edi, -4(%ecx,%edi)
0x00402927:	sarl %ecx, $0x2<UINT8>
0x0040292a:	js 17
0x0040292c:	std
0x0040292d:	rep movsl %es:(%edi), %ds:(%esi)
0x0040292f:	movl %ecx, %eax
0x00402931:	andl %ecx, $0x3<UINT8>
0x00402934:	addl %esi, $0x3<UINT8>
0x00402937:	addl %edi, $0x3<UINT8>
0x0040293a:	rep movsb %es:(%edi), %ds:(%esi)
0x0040293c:	cld
0x0040293d:	popl %edi
0x0040293e:	popl %esi
0x0040293f:	ret

0x0040c86b:	addl %esp, $0x94<UINT32>
0x0040c871:	ret

0x0040e154:	call 0x0040d6f0
0x0040d6f0:	pushl %ebx
0x0040d6f1:	pushl $0x40d728<UINT32>
0x0040d6f6:	call 0x004066c4
0x004066c4:	jmp GetModuleHandleA@KERNEL32.DLL
0x0040d6fb:	movl %ebx, %eax
0x0040d6fd:	testl %ebx, %ebx
0x0040d6ff:	je 0x0040d711
0x0040d711:	cmpl 0x49f13c, $0x0<UINT8>
0x0040d718:	jne 10
0x0040d71a:	movl %eax, $0x408e74<UINT32>
0x0040d71f:	movl 0x49f13c, %eax
0x0040d724:	popl %ebx
0x0040d725:	ret

0x0040e159:	call 0x0040d154
0x0040d154:	pushl %ebp
0x0040d155:	movl %ebp, %esp
0x0040d157:	movl %ecx, $0x8<UINT32>
0x0040d15c:	pushl $0x0<UINT8>
0x0040d15e:	pushl $0x0<UINT8>
0x0040d160:	decl %ecx
0x0040d161:	jne 0x0040d15c
0x0040d163:	pushl %ebx
0x0040d164:	xorl %eax, %eax
0x0040d166:	pushl %ebp
0x0040d167:	pushl $0x40d41f<UINT32>
0x0040d16c:	pushl %fs:(%eax)
0x0040d16f:	movl %fs:(%eax), %esp
0x0040d172:	call 0x0040cfe0
0x0040cfe0:	pushl %ebp
0x0040cfe1:	movl %ebp, %esp
0x0040cfe3:	addl %esp, $0xfffffe68<UINT32>
0x0040cfe9:	pushl %ebx
0x0040cfea:	pushl %esi
0x0040cfeb:	pushl %edi
0x0040cfec:	movl 0x4a1744, $0x409<UINT32>
0x0040cff6:	movl 0x4a1748, $0x9<UINT32>
0x0040d000:	movl 0x4a174c, $0x1<UINT32>
0x0040d00a:	call 0x004066fc
0x004066fc:	jmp GetThreadLocale@KERNEL32.DLL
0x0040d00f:	testl %eax, %eax
0x0040d011:	je 5
0x0040d013:	movl 0x4a1744, %eax
0x0040d018:	testw %ax, %ax
0x0040d01b:	je 27
0x0040d01d:	movl %edx, %eax
0x0040d01f:	andw %dx, $0x3ff<UINT16>
0x0040d024:	movzwl %edx, %dx
0x0040d027:	movl 0x4a1748, %edx
0x0040d02d:	movzwl %eax, %ax
0x0040d030:	shrl %eax, $0xa<UINT8>
0x0040d033:	movl 0x4a174c, %eax
0x0040d038:	movl %esi, $0x40d134<UINT32>
0x0040d03d:	movl %edi, $0x49f118<UINT32>
0x0040d042:	movl %ecx, $0x8<UINT32>
0x0040d047:	rep movsl %es:(%edi), %ds:(%esi)
0x0040d049:	cmpl 0x49f0d0, $0x2<UINT8>
0x0040d050:	jne 167
0x0040d056:	call 0x0040cfc8
0x0040cfc8:	movl %eax, 0x4a1748
0x0040cfcd:	cmpl %eax, $0x1f<UINT8>
0x0040cfd0:	ja 7
0x0040cfd2:	btl 0x49f314, %eax
0x0040cfd9:	setb %al
0x0040cfdc:	ret

0x0040d05b:	testb %al, %al
0x0040d05d:	je 19
0x0040d05f:	movb 0x4a1751, $0x0<UINT8>
0x0040d066:	movb 0x4a1750, $0x0<UINT8>
0x0040d06d:	jmp 0x0040d12b
0x0040d12b:	popl %edi
0x0040d12c:	popl %esi
0x0040d12d:	popl %ebx
0x0040d12e:	movl %esp, %ebp
0x0040d130:	popl %ebp
0x0040d131:	ret

0x0040d177:	call 0x0040b8f0
0x0040b8f0:	pushl %ebp
0x0040b8f1:	movl %ebp, %esp
0x0040b8f3:	xorl %ecx, %ecx
0x0040b8f5:	pushl %ecx
0x0040b8f6:	pushl %ecx
0x0040b8f7:	pushl %ecx
0x0040b8f8:	pushl %ecx
0x0040b8f9:	pushl %ecx
0x0040b8fa:	pushl %ecx
0x0040b8fb:	pushl %ebx
0x0040b8fc:	pushl %esi
0x0040b8fd:	pushl %edi
0x0040b8fe:	xorl %eax, %eax
0x0040b900:	pushl %ebp
0x0040b901:	pushl $0x40ba03<UINT32>
0x0040b906:	pushl %fs:(%eax)
0x0040b909:	movl %fs:(%eax), %esp
0x0040b90c:	call 0x004066fc
0x0040b911:	movl -4(%ebp), %eax
0x0040b914:	movl %ebx, $0x1<UINT32>
0x0040b919:	movl %esi, $0x4a16ac<UINT32>
0x0040b91e:	movl %edi, $0x4a16dc<UINT32>
0x0040b923:	pushl %ebp
0x0040b924:	pushl $0xb<UINT8>
0x0040b926:	leal %eax, -12(%ebp)
0x0040b929:	pushl %eax
0x0040b92a:	movl %ecx, $0x49f194<UINT32>
0x0040b92f:	movl %edx, %ebx
0x0040b931:	decl %edx
0x0040b932:	leal %eax, 0x44(%ebx)
0x0040b935:	decl %eax
0x0040b936:	call 0x0040b8b4
0x0040b8b4:	pushl %ebp
0x0040b8b5:	movl %ebp, %esp
0x0040b8b7:	pushl %ecx
0x0040b8b8:	pushl %ebx
0x0040b8b9:	pushl %esi
0x0040b8ba:	pushl %edi
0x0040b8bb:	movl -4(%ebp), %ecx
0x0040b8be:	movl %edi, %edx
0x0040b8c0:	movl %esi, %eax
0x0040b8c2:	movl %ebx, 0x8(%ebp)
0x0040b8c5:	pushl %ebx
0x0040b8c6:	movl %eax, 0x10(%ebp)
0x0040b8c9:	movl %eax, -4(%eax)
0x0040b8cc:	xorl %ecx, %ecx
0x0040b8ce:	movl %edx, %esi
0x0040b8d0:	call 0x0040b840
0x0040b840:	pushl %ebp
0x0040b841:	movl %ebp, %esp
0x0040b843:	addl %esp, $0xffffff00<UINT32>
0x0040b849:	pushl %ebx
0x0040b84a:	pushl %esi
0x0040b84b:	movl %esi, %ecx
0x0040b84d:	movl %ebx, 0x8(%ebp)
0x0040b850:	pushl $0x100<UINT32>
0x0040b855:	leal %ecx, -256(%ebp)
0x0040b85b:	pushl %ecx
0x0040b85c:	pushl %edx
0x0040b85d:	pushl %eax
0x0040b85e:	call 0x004066b4
0x004066b4:	jmp GetLocaleInfoA@KERNEL32.DLL
0x0040b863:	testl %eax, %eax
0x0040b865:	jle 18
0x0040b867:	movl %ecx, %eax
0x0040b869:	decl %ecx
0x0040b86a:	leal %edx, -256(%ebp)
0x0040b870:	movl %eax, %ebx
0x0040b872:	call 0x00404314
0x0040b877:	jmp 0x0040b882
0x0040b882:	popl %esi
0x0040b883:	popl %ebx
0x0040b884:	movl %esp, %ebp
0x0040b886:	popl %ebp
0x0040b887:	ret $0x4<UINT16>

0x0040b8d5:	cmpl (%ebx), $0x0<UINT8>
0x0040b8d8:	jne 0x0040b8e7
0x0040b8e7:	popl %edi
0x0040b8e8:	popl %esi
0x0040b8e9:	popl %ebx
0x0040b8ea:	popl %ecx
0x0040b8eb:	popl %ebp
0x0040b8ec:	ret $0x8<UINT16>

0x0040b93b:	popl %ecx
0x0040b93c:	movl %edx, -12(%ebp)
0x0040b93f:	movl %eax, %esi
0x0040b941:	call 0x00404278
0x00404278:	testl %edx, %edx
0x0040427a:	je 36
0x0040427c:	movl %ecx, -8(%edx)
0x0040427f:	incl %ecx
0x00404280:	jg 0x0040429c
0x0040429c:	incl -8(%edx)
0x004042a0:	xchgl (%eax), %edx
0x004042a2:	testl %edx, %edx
0x004042a4:	je 0x004042ba
0x004042ba:	ret

0x0040b946:	pushl %ebp
0x0040b947:	pushl $0xb<UINT8>
0x0040b949:	leal %eax, -16(%ebp)
0x0040b94c:	pushl %eax
0x0040b94d:	movl %ecx, $0x49f1c4<UINT32>
0x0040b952:	movl %edx, %ebx
0x0040b954:	decl %edx
0x0040b955:	leal %eax, 0x38(%ebx)
0x0040b958:	decl %eax
0x0040b959:	call 0x0040b8b4
0x0040b95e:	popl %ecx
0x0040b95f:	movl %edx, -16(%ebp)
0x0040b962:	movl %eax, %edi
0x0040b964:	call 0x00404278
0x0040b969:	incl %ebx
0x0040b96a:	addl %edi, $0x4<UINT8>
0x0040b96d:	addl %esi, $0x4<UINT8>
0x0040b970:	cmpl %ebx, $0xd<UINT8>
0x0040b973:	jne 0x0040b923
0x0040422a:	movl (%eax), $0x0<UINT32>
0x00404230:	movl %ecx, -8(%edx)
0x00404233:	decl %ecx
0x00404234:	jl 16
0x00404236:	decl -8(%edx)
0x0040423a:	jne 0x00404246
0x0040b975:	movl %ebx, $0x1<UINT32>
0x0040b97a:	movl %esi, $0x4a170c<UINT32>
0x0040b97f:	movl %edi, $0x4a1728<UINT32>
0x0040b984:	leal %eax, 0x5(%ebx)
0x0040b987:	movl %ecx, $0x7<UINT32>
0x0040b98c:	cltd
0x0040b98d:	idivl %eax, %ecx
0x0040b98f:	movl -8(%ebp), %edx
0x0040b992:	pushl %ebp
0x0040b993:	pushl $0x6<UINT8>
0x0040b995:	leal %eax, -20(%ebp)
0x0040b998:	pushl %eax
0x0040b999:	movl %ecx, $0x49f1f4<UINT32>
0x0040b99e:	movl %edx, %ebx
0x0040b9a0:	decl %edx
0x0040b9a1:	movl %eax, -8(%ebp)
0x0040b9a4:	addl %eax, $0x31<UINT8>
0x0040b9a7:	call 0x0040b8b4
0x0040b9ac:	popl %ecx
0x0040b9ad:	movl %edx, -20(%ebp)
0x0040b9b0:	movl %eax, %esi
0x0040b9b2:	call 0x00404278
0x0040b9b7:	pushl %ebp
0x0040b9b8:	pushl $0x6<UINT8>
0x0040b9ba:	leal %eax, -24(%ebp)
0x0040b9bd:	pushl %eax
0x0040b9be:	movl %ecx, $0x49f210<UINT32>
0x0040b9c3:	movl %edx, %ebx
0x0040b9c5:	decl %edx
0x0040b9c6:	movl %eax, -8(%ebp)
0x0040b9c9:	addl %eax, $0x2a<UINT8>
0x0040b9cc:	call 0x0040b8b4
0x0040b9d1:	popl %ecx
0x0040b9d2:	movl %edx, -24(%ebp)
0x0040b9d5:	movl %eax, %edi
0x0040b9d7:	call 0x00404278
0x0040b9dc:	incl %ebx
0x0040b9dd:	addl %edi, $0x4<UINT8>
0x0040b9e0:	addl %esi, $0x4<UINT8>
0x0040b9e3:	cmpl %ebx, $0x8<UINT8>
0x0040b9e6:	jne 0x0040b984
0x0040b9e8:	xorl %eax, %eax
0x0040b9ea:	popl %edx
0x0040b9eb:	popl %ecx
0x0040b9ec:	popl %ecx
0x0040b9ed:	movl %fs:(%eax), %edx
0x0040b9f0:	pushl $0x40ba0a<UINT32>
0x0040b9f5:	leal %eax, -24(%ebp)
0x0040b9f8:	movl %edx, $0x4<UINT32>
0x0040b9fd:	call 0x00404248
0x00404248:	pushl %ebx
0x00404249:	pushl %esi
0x0040424a:	movl %ebx, %eax
0x0040424c:	movl %esi, %edx
0x0040424e:	movl %edx, (%ebx)
0x00404250:	testl %edx, %edx
0x00404252:	je 0x0040426e
0x00404254:	movl (%ebx), $0x0<UINT32>
0x0040425a:	movl %ecx, -8(%edx)
0x0040425d:	decl %ecx
0x0040425e:	jl 0x0040426e
0x00404260:	decl -8(%edx)
0x00404264:	jne 0x0040426e
0x0040426e:	addl %ebx, $0x4<UINT8>
0x00404271:	decl %esi
0x00404272:	jne 0x0040424e
0x00404274:	popl %esi
0x00404275:	popl %ebx
0x00404276:	ret

0x0040ba02:	ret

0x0040ba0a:	popl %edi
0x0040ba0b:	popl %esi
0x0040ba0c:	popl %ebx
0x0040ba0d:	movl %esp, %ebp
0x0040ba0f:	popl %ebp
0x0040ba10:	ret

0x0040d17c:	cmpb 0x4a1750, $0x0<UINT8>
0x0040d183:	je 0x0040d18a
0x0040d18a:	call 0x004066fc
0x0040d18f:	movl %ebx, %eax
0x0040d191:	leal %eax, -16(%ebp)
0x0040d194:	pushl %eax
0x0040d195:	xorl %ecx, %ecx
0x0040d197:	movl %edx, $0x14<UINT32>
0x0040d19c:	movl %eax, %ebx
0x0040d19e:	call 0x0040b840
0x0040d1a3:	movl %edx, -16(%ebp)
0x0040d1a6:	movl %eax, $0x4a1684<UINT32>
0x0040d1ab:	call 0x00404278
0x0040d1b0:	leal %eax, -20(%ebp)
0x0040d1b3:	pushl %eax
0x0040d1b4:	movl %ecx, $0x40d434<UINT32>
0x0040d1b9:	movl %edx, $0x1b<UINT32>
0x0040d1be:	movl %eax, %ebx
0x0040d1c0:	call 0x0040b840
0x0040d1c5:	movl %eax, -20(%ebp)
0x0040d1c8:	xorl %edx, %edx
0x0040d1ca:	call 0x004087b8
0x004087b8:	pushl %ebx
0x004087b9:	pushl %ecx
0x004087ba:	movl %ebx, %edx
0x004087bc:	movl %edx, %esp
0x004087be:	call 0x00402dc4
0x00402dc4:	pushl %ebx
0x00402dc5:	pushl %esi
0x00402dc6:	pushl %edi
0x00402dc7:	movl %esi, %eax
0x00402dc9:	pushl %eax
0x00402dca:	testl %eax, %eax
0x00402dcc:	je 108
0x00402dce:	xorl %eax, %eax
0x00402dd0:	xorl %ebx, %ebx
0x00402dd2:	movl %edi, $0xccccccc<UINT32>
0x00402dd7:	movb %bl, (%esi)
0x00402dd9:	incl %esi
0x00402dda:	cmpb %bl, $0x20<UINT8>
0x00402ddd:	je -8
0x00402ddf:	movb %ch, $0x0<UINT8>
0x00402de1:	cmpb %bl, $0x2d<UINT8>
0x00402de4:	je 98
0x00402de6:	cmpb %bl, $0x2b<UINT8>
0x00402de9:	je 95
0x00402deb:	cmpb %bl, $0x24<UINT8>
0x00402dee:	je 95
0x00402df0:	cmpb %bl, $0x78<UINT8>
0x00402df3:	je 90
0x00402df5:	cmpb %bl, $0x58<UINT8>
0x00402df8:	je 85
0x00402dfa:	cmpb %bl, $0x30<UINT8>
0x00402dfd:	jne 0x00402e12
0x00402dff:	movb %bl, (%esi)
0x00402e01:	incl %esi
0x00402e02:	cmpb %bl, $0x78<UINT8>
0x00402e05:	je 72
0x00402e07:	cmpb %bl, $0x58<UINT8>
0x00402e0a:	je 67
0x00402e0c:	testb %bl, %bl
0x00402e0e:	je 0x00402e30
0x00402e30:	decb %ch
0x00402e32:	je 9
0x00402e34:	testl %eax, %eax
0x00402e36:	jnl 0x00402e8c
0x00402e8c:	popl %ecx
0x00402e8d:	xorl %esi, %esi
0x00402e8f:	movl (%edx), %esi
0x00402e91:	popl %edi
0x00402e92:	popl %esi
0x00402e93:	popl %ebx
0x00402e94:	ret

0x004087c3:	cmpl (%esp), $0x0<UINT8>
0x004087c7:	je 0x004087cb
0x004087cb:	popl %edx
0x004087cc:	popl %ebx
0x004087cd:	ret

0x0040d1cf:	movb 0x4a1688, %al
0x0040d1d4:	leal %eax, -24(%ebp)
0x0040d1d7:	pushl %eax
0x0040d1d8:	movl %ecx, $0x40d434<UINT32>
0x0040d1dd:	movl %edx, $0x1c<UINT32>
0x0040d1e2:	movl %eax, %ebx
0x0040d1e4:	call 0x0040b840
0x0040d1e9:	movl %eax, -24(%ebp)
0x0040d1ec:	xorl %edx, %edx
0x0040d1ee:	call 0x004087b8
0x0040d1f3:	movb 0x4a1689, %al
0x0040d1f8:	movb %cl, $0x2c<UINT8>
0x0040d1fa:	movl %edx, $0xf<UINT32>
0x0040d1ff:	movl %eax, %ebx
0x0040d201:	call 0x0040b88c
0x0040b88c:	pushl %ebx
0x0040b88d:	pushl %esi
0x0040b88e:	pushl %edi
0x0040b88f:	pushl %ecx
0x0040b890:	movl %ebx, %ecx
0x0040b892:	movl %esi, %edx
0x0040b894:	movl %edi, %eax
0x0040b896:	pushl $0x2<UINT8>
0x0040b898:	leal %eax, 0x4(%esp)
0x0040b89c:	pushl %eax
0x0040b89d:	pushl %esi
0x0040b89e:	pushl %edi
0x0040b89f:	call 0x004066b4
0x0040b8a4:	testl %eax, %eax
0x0040b8a6:	jle 5
0x0040b8a8:	movb %al, (%esp)
0x0040b8ab:	jmp 0x0040b8af
0x0040b8af:	popl %edx
0x0040b8b0:	popl %edi
0x0040b8b1:	popl %esi
0x0040b8b2:	popl %ebx
0x0040b8b3:	ret

0x0040d206:	movb 0x4a168a, %al
0x0040d20b:	movb %cl, $0x2e<UINT8>
0x0040d20d:	movl %edx, $0xe<UINT32>
0x0040d212:	movl %eax, %ebx
0x0040d214:	call 0x0040b88c
0x0040d219:	movb 0x4a168b, %al
0x0040d21e:	leal %eax, -28(%ebp)
0x0040d221:	pushl %eax
0x0040d222:	movl %ecx, $0x40d434<UINT32>
0x0040d227:	movl %edx, $0x19<UINT32>
0x0040d22c:	movl %eax, %ebx
0x0040d22e:	call 0x0040b840
0x0040d233:	movl %eax, -28(%ebp)
0x0040d236:	xorl %edx, %edx
0x0040d238:	call 0x004087b8
0x00402e12:	testb %bl, %bl
0x00402e14:	je 45
0x00402e16:	subb %bl, $0x30<UINT8>
0x00402e19:	cmpb %bl, $0x9<UINT8>
0x00402e1c:	ja 37
0x00402e1e:	cmpl %eax, %edi
0x00402e20:	ja 33
0x00402e22:	leal %eax, (%eax,%eax,4)
0x00402e25:	addl %eax, %eax
0x00402e27:	addl %eax, %ebx
0x00402e29:	movb %bl, (%esi)
0x00402e2b:	incl %esi
0x00402e2c:	testb %bl, %bl
0x00402e2e:	jne -26
0x0040d23d:	movb 0x4a168c, %al
0x0040d242:	movb %cl, $0x2f<UINT8>
0x0040d244:	movl %edx, $0x1d<UINT32>
0x0040d249:	movl %eax, %ebx
0x0040d24b:	call 0x0040b88c
0x0040d250:	movb 0x4a168d, %al
0x0040d255:	leal %eax, -36(%ebp)
0x0040d258:	pushl %eax
0x0040d259:	movl %ecx, $0x40d440<UINT32>
0x0040d25e:	movl %edx, $0x1f<UINT32>
0x0040d263:	movl %eax, %ebx
0x0040d265:	call 0x0040b840
0x0040d26a:	movl %eax, -36(%ebp)
0x0040d26d:	leal %edx, -32(%ebp)
0x0040d270:	call 0x0040bb78
0x0040bb78:	pushl %ebp
0x0040bb79:	movl %ebp, %esp
0x0040bb7b:	xorl %ecx, %ecx
0x0040bb7d:	pushl %ecx
0x0040bb7e:	pushl %ecx
0x0040bb7f:	pushl %ecx
0x0040bb80:	pushl %ecx
0x0040bb81:	pushl %ecx
0x0040bb82:	pushl %ebx
0x0040bb83:	pushl %esi
0x0040bb84:	pushl %edi
0x0040bb85:	movl %edi, %edx
0x0040bb87:	movl %esi, %eax
0x0040bb89:	xorl %eax, %eax
0x0040bb8b:	pushl %ebp
0x0040bb8c:	pushl $0x40bd42<UINT32>
0x0040bb91:	pushl %fs:(%eax)
0x0040bb94:	movl %fs:(%eax), %esp
0x0040bb97:	movl %ebx, $0x1<UINT32>
0x0040bb9c:	movl %eax, %edi
0x0040bb9e:	call 0x00404224
0x0040bba3:	leal %eax, -8(%ebp)
0x0040bba6:	pushl %eax
0x0040bba7:	call 0x004066fc
0x0040bbac:	movl %ecx, $0x40bd58<UINT32>
0x0040bbb1:	movl %edx, $0x1009<UINT32>
0x0040bbb6:	call 0x0040b840
0x0040bbbb:	movl %eax, -8(%ebp)
0x0040bbbe:	movl %edx, $0x1<UINT32>
0x0040bbc3:	call 0x004087b8
0x0040bbc8:	addl %eax, $0xfffffffd<UINT8>
0x0040bbcb:	subl %eax, $0x3<UINT8>
0x0040bbce:	jb 324
0x0040bbd4:	movl %eax, 0x4a1748
0x0040bbd9:	subl %eax, $0x4<UINT8>
0x0040bbdc:	je 12
0x0040bbde:	addl %eax, $0xfffffff3<UINT8>
0x0040bbe1:	subl %eax, $0x2<UINT8>
0x0040bbe4:	jb 4
0x0040bbe6:	xorl %eax, %eax
0x0040bbe8:	jmp 0x0040bbec
0x0040bbec:	testb %al, %al
0x0040bbee:	je 0x0040bc25
0x0040bc25:	movl %eax, %edi
0x0040bc27:	movl %edx, %esi
0x0040bc29:	call 0x00404278
0x0040bc2e:	jmp 0x0040bd27
0x0040bd27:	xorl %eax, %eax
0x0040bd29:	popl %edx
0x0040bd2a:	popl %ecx
0x0040bd2b:	popl %ecx
0x0040bd2c:	movl %fs:(%eax), %edx
0x0040bd2f:	pushl $0x40bd49<UINT32>
0x0040bd34:	leal %eax, -20(%ebp)
0x0040bd37:	movl %edx, $0x4<UINT32>
0x0040bd3c:	call 0x00404248
0x00404266:	leal %eax, -8(%edx)
0x00404269:	call 0x00402724
0x00402724:	pushl %ebx
0x00402725:	testl %eax, %eax
0x00402727:	je 21
0x00402729:	call 0x004022c0
0x004022c0:	pushl %ebp
0x004022c1:	movl %ebp, %esp
0x004022c3:	pushl %ecx
0x004022c4:	pushl %ebx
0x004022c5:	pushl %esi
0x004022c6:	pushl %edi
0x004022c7:	movl %ebx, %eax
0x004022c9:	xorl %eax, %eax
0x004022cb:	movl 0x4a15c8, %eax
0x004022d0:	cmpb 0x4a15c4, $0x0<UINT8>
0x004022d7:	jne 0x004022f8
0x004022f8:	xorl %ecx, %ecx
0x004022fa:	pushl %ebp
0x004022fb:	pushl $0x402452<UINT32>
0x00402300:	pushl %fs:(%ecx)
0x00402303:	movl %fs:(%ecx), %esp
0x00402306:	cmpb 0x4a104d, $0x0<UINT8>
0x0040230d:	je 0x00402319
0x00402319:	movl %esi, %ebx
0x0040231b:	subl %esi, $0x4<UINT8>
0x0040231e:	movl %ebx, (%esi)
0x00402320:	testb %bl, $0x2<UINT8>
0x00402323:	jne 0x00402334
0x00402334:	decl 0x4a15b4
0x0040233a:	movl %eax, %ebx
0x0040233c:	andl %eax, $0x7ffffffc<UINT32>
0x00402341:	subl %eax, $0x4<UINT8>
0x00402344:	subl 0x4a15b8, %eax
0x0040234a:	testb %bl, $0x1<UINT8>
0x0040234d:	je 0x00402394
0x00402394:	andl %ebx, $0x7ffffffc<UINT32>
0x0040239a:	movl %eax, %esi
0x0040239c:	addl %eax, %ebx
0x0040239e:	movl %edi, %eax
0x004023a0:	cmpl %edi, 0x4a1620
0x004023a6:	jne 0x004023d4
0x004023a8:	subl 0x4a1620, %ebx
0x004023ae:	addl 0x4a161c, %ebx
0x004023b4:	cmpl 0x4a161c, $0x3c00<UINT32>
0x004023be:	jle 5
0x004023c0:	call 0x00401ed8
0x00401ee1:	cmpl 0x4a161c, $0xc<UINT8>
0x00401ee8:	jnl 0x00401ef6
0x00401ef6:	movl %eax, 0x4a161c
0x00401efb:	orl %eax, $0x2<UINT8>
0x00401efe:	movl %edx, 0x4a1620
0x00401f04:	movl (%edx), %eax
0x00401f06:	movl %eax, 0x4a1620
0x00401f0b:	addl %eax, $0x4<UINT8>
0x00401f0e:	call 0x00401cac
0x00401cac:	incl 0x4a15b4
0x00401cb2:	movl %edx, %eax
0x00401cb4:	subl %edx, $0x4<UINT8>
0x00401cb7:	movl %edx, (%edx)
0x00401cb9:	andl %edx, $0x7ffffffc<UINT32>
0x00401cbf:	subl %edx, $0x4<UINT8>
0x00401cc2:	addl 0x4a15b8, %edx
0x00401cc8:	call 0x004022c0
0x004023d4:	movl %edx, (%eax)
0x004023d6:	testb %dl, $0x2<UINT8>
0x004023d9:	je 0x004023f7
0x004023db:	andl %edx, $0x7ffffffc<UINT32>
0x004023e1:	cmpl %edx, $0x4<UINT8>
0x004023e4:	jnl 0x004023f2
0x004023f2:	orl (%eax), $0x1<UINT8>
0x004023f5:	jmp 0x00402420
0x00402420:	movl %edx, %ebx
0x00402422:	movl %eax, %esi
0x00402424:	call 0x00401e50
0x00401e50:	pushl %ebx
0x00401e51:	pushl %esi
0x00401e52:	pushl %edi
0x00401e53:	movl %esi, %edx
0x00401e55:	movl %edi, %eax
0x00401e57:	movl %ebx, %edi
0x00401e59:	movl 0x8(%ebx), %esi
0x00401e5c:	movl %eax, %ebx
0x00401e5e:	addl %eax, %esi
0x00401e60:	subl %eax, $0xc<UINT8>
0x00401e63:	movl 0x8(%eax), %esi
0x00401e66:	cmpl %esi, $0x1000<UINT32>
0x00401e6c:	jg 0x00401ea5
0x00401ea5:	cmpl %esi, $0x3c00<UINT32>
0x00401eab:	jl 0x00401eba
0x00401ead:	movl %edx, %esi
0x00401eaf:	movl %eax, %edi
0x00401eb1:	call 0x00401da0
0x00401da0:	pushl %ebx
0x00401da1:	pushl %esi
0x00401da2:	pushl %edi
0x00401da3:	pushl %ebp
0x00401da4:	addl %esp, $0xfffffff4<UINT8>
0x00401da7:	movl %edi, %edx
0x00401da9:	movl %esi, %eax
0x00401dab:	movb (%esp), $0x0<UINT8>
0x00401daf:	movl %eax, %esi
0x00401db1:	call 0x00401c4c
0x00401c4c:	movl %edx, 0x4a1628
0x00401c52:	jmp 0x00401c64
0x00401c64:	cmpl %edx, $0x4a1628<UINT32>
0x00401c6a:	jne 0x00401c54
0x00401c54:	movl %ecx, 0x8(%edx)
0x00401c57:	cmpl %eax, %ecx
0x00401c59:	jb 7
0x00401c5b:	addl %ecx, 0xc(%edx)
0x00401c5e:	cmpl %eax, %ecx
0x00401c60:	jb 0x00401c78
0x00401c78:	movl %eax, %edx
0x00401c7a:	ret

0x00401db6:	movl %ebx, %eax
0x00401db8:	testl %ebx, %ebx
0x00401dba:	je 130
0x00401dc0:	movl %ebp, 0x8(%ebx)
0x00401dc3:	movl %eax, %ebp
0x00401dc5:	addl %eax, 0xc(%ebx)
0x00401dc8:	movl %edx, %eax
0x00401dca:	leal %ecx, (%edi,%esi)
0x00401dcd:	subl %edx, %ecx
0x00401dcf:	cmpl %edx, $0xc<UINT8>
0x00401dd2:	jg 4
0x00401dd4:	movl %edi, %eax
0x00401dd6:	subl %edi, %esi
0x00401dd8:	movl %eax, %esi
0x00401dda:	subl %eax, %ebp
0x00401ddc:	cmpl %eax, $0xc<UINT8>
0x00401ddf:	jnl 0x00401df5
0x00401df5:	leal %ecx, 0x1(%esp)
0x00401df9:	movl %edx, %edi
0x00401dfb:	subl %edx, $0x4<UINT8>
0x00401dfe:	leal %eax, 0x4(%esi)
0x00401e01:	call 0x004019b8
0x004019b8:	pushl %ebx
0x004019b9:	pushl %esi
0x004019ba:	pushl %edi
0x004019bb:	addl %esp, $0xffffffec<UINT8>
0x004019be:	movl %edi, %ecx
0x004019c0:	movl (%esp), %edx
0x004019c3:	leal %ebx, 0x3fff(%eax)
0x004019c9:	andl %ebx, $0xffffc000<UINT32>
0x004019cf:	movl %esi, (%esp)
0x004019d2:	addl %esi, %eax
0x004019d4:	andl %esi, $0xffffc000<UINT32>
0x004019da:	cmpl %ebx, %esi
0x004019dc:	jae 0x00401a39
0x00401a39:	xorl %eax, %eax
0x00401a3b:	movl (%edi), %eax
0x00401a3d:	addl %esp, $0x14<UINT8>
0x00401a40:	popl %edi
0x00401a41:	popl %esi
0x00401a42:	popl %ebx
0x00401a43:	ret

0x00401e06:	movl %ebp, 0x1(%esp)
0x00401e0a:	testl %ebp, %ebp
0x00401e0c:	je 0x00401e42
0x00401e42:	movb %al, (%esp)
0x00401e45:	addl %esp, $0xc<UINT8>
0x00401e48:	popl %ebp
0x00401e49:	popl %edi
0x00401e4a:	popl %esi
0x00401e4b:	popl %ebx
0x00401e4c:	ret

0x00401eb6:	testb %al, %al
0x00401eb8:	jne 23
0x00401eba:	movl %eax, 0x4a1618
0x00401ebf:	movl 0x4a1618, %ebx
0x00401ec5:	movl %edx, (%eax)
0x00401ec7:	movl 0x4(%ebx), %eax
0x00401eca:	movl (%ebx), %edx
0x00401ecc:	movl (%eax), %ebx
0x00401ece:	movl 0x4(%edx), %ebx
0x00401ed1:	popl %edi
0x00401ed2:	popl %esi
0x00401ed3:	popl %ebx
0x00401ed4:	ret

0x00402429:	movl %eax, 0x4a15c8
0x0040242e:	movl -4(%ebp), %eax
0x00402431:	xorl %eax, %eax
0x00402433:	popl %edx
0x00402434:	popl %ecx
0x00402435:	popl %ecx
0x00402436:	movl %fs:(%eax), %edx
0x00402439:	pushl $0x402459<UINT32>
0x0040243e:	cmpb 0x4a104d, $0x0<UINT8>
0x00402445:	je 0x00402451
0x00402451:	ret

0x00402459:	movl %eax, -4(%ebp)
0x0040245c:	popl %edi
0x0040245d:	popl %esi
0x0040245e:	popl %ebx
0x0040245f:	popl %ecx
0x00402460:	popl %ebp
0x00402461:	ret

0x00401ccd:	ret

0x00401f13:	xorl %eax, %eax
0x00401f15:	movl 0x4a1620, %eax
0x00401f1a:	xorl %eax, %eax
0x00401f1c:	movl 0x4a161c, %eax
0x004023c5:	xorl %eax, %eax
0x004023c7:	movl -4(%ebp), %eax
0x004023ca:	call 0x00403d0c
0x00402457:	jmp 0x0040243e
0x004023cf:	jmp 0x00402459
0x0040272f:	movl %ebx, %eax
0x00402731:	testl %ebx, %ebx
0x00402733:	je 0x00402740
0x00402740:	movl %eax, %ebx
0x00402742:	popl %ebx
0x00402743:	ret

0x0040bd41:	ret

0x0040bd49:	popl %edi
0x0040bd4a:	popl %esi
0x0040bd4b:	popl %ebx
0x0040bd4c:	movl %esp, %ebp
0x0040bd4e:	popl %ebp
0x0040bd4f:	ret

0x0040d275:	movl %edx, -32(%ebp)
0x0040d278:	movl %eax, $0x4a1690<UINT32>
0x0040d27d:	call 0x00404278
0x0040d282:	leal %eax, -44(%ebp)
0x0040d285:	pushl %eax
0x0040d286:	movl %ecx, $0x40d450<UINT32>
0x0040d28b:	movl %edx, $0x20<UINT32>
0x0040d290:	movl %eax, %ebx
0x0040d292:	call 0x0040b840
0x004020df:	movl %eax, %ebx
0x004020e1:	call 0x00401be8
0x00401be8:	pushl %ebx
0x00401be9:	cmpl %eax, 0x4a1618
0x00401bef:	jne 0x00401bfa
0x00401bf1:	movl %edx, 0x4(%eax)
0x00401bf4:	movl 0x4a1618, %edx
0x00401bfa:	movl %edx, 0x4(%eax)
0x00401bfd:	movl %ecx, 0x8(%eax)
0x00401c00:	cmpl %ecx, $0x1000<UINT32>
0x00401c06:	jg 0x00401c40
0x00401c40:	movl %eax, (%eax)
0x00401c42:	movl (%edx), %eax
0x00401c44:	movl 0x4(%eax), %edx
0x00401c47:	popl %ebx
0x00401c48:	ret

0x004020e6:	movl %edx, 0x8(%ebx)
0x004020e9:	movl %eax, %edx
0x004020eb:	subl %eax, %esi
0x004020ed:	cmpl %eax, $0xc<UINT8>
0x004020f0:	jl 12
0x004020f2:	movl %edx, %ebx
0x004020f4:	addl %edx, %esi
0x004020f6:	xchgl %edx, %eax
0x004020f7:	call 0x00401e50
0x004020fc:	jmp 0x00402110
0x00402110:	movl %eax, %ebx
0x00402112:	movl %edx, %esi
0x00402114:	orl %edx, $0x2<UINT8>
0x00402117:	movl (%eax), %edx
0x00402119:	addl %eax, $0x4<UINT8>
0x0040211c:	incl 0x4a15b4
0x00402122:	subl %esi, $0x4<UINT8>
0x00402125:	addl 0x4a15b8, %esi
0x0040d297:	movl %eax, -44(%ebp)
0x0040d29a:	leal %edx, -40(%ebp)
0x0040d29d:	call 0x0040bb78
0x004023f7:	movl %eax, %edi
0x004023f9:	cmpl 0x4(%eax), $0x0<UINT8>
0x004023fd:	je 11
0x004023ff:	cmpl (%eax), $0x0<UINT8>
0x00402402:	je 6
0x00402404:	cmpl 0x8(%eax), $0xc<UINT8>
0x00402408:	jnl 0x00402416
0x00402416:	movl %edx, 0x8(%eax)
0x00402419:	addl %ebx, %edx
0x0040241b:	call 0x00401be8
0x0040d2a2:	movl %edx, -40(%ebp)
0x0040d2a5:	movl %eax, $0x4a1694<UINT32>
0x0040d2aa:	call 0x00404278
0x0040d2af:	movb %cl, $0x3a<UINT8>
0x0040d2b1:	movl %edx, $0x1e<UINT32>
0x0040d2b6:	movl %eax, %ebx
0x0040d2b8:	call 0x0040b88c
0x0040d2bd:	movb 0x4a1698, %al
0x0040d2c2:	leal %eax, -48(%ebp)
0x0040d2c5:	pushl %eax
0x0040d2c6:	movl %ecx, $0x40d468<UINT32>
0x0040d2cb:	movl %edx, $0x28<UINT32>
0x0040d2d0:	movl %eax, %ebx
0x0040d2d2:	call 0x0040b840
0x0040d2d7:	movl %edx, -48(%ebp)
0x0040d2da:	movl %eax, $0x4a169c<UINT32>
0x0040d2df:	call 0x00404278
0x0040d2e4:	leal %eax, -52(%ebp)
0x0040d2e7:	pushl %eax
0x0040d2e8:	movl %ecx, $0x40d474<UINT32>
0x0040d2ed:	movl %edx, $0x29<UINT32>
0x0040d2f2:	movl %eax, %ebx
0x0040d2f4:	call 0x0040b840
0x0040d2f9:	movl %edx, -52(%ebp)
0x0040d2fc:	movl %eax, $0x4a16a0<UINT32>
0x0040d301:	call 0x00404278
0x0040d306:	leal %eax, -8(%ebp)
0x0040d309:	call 0x00404224
0x0040d30e:	leal %eax, -12(%ebp)
0x0040d311:	call 0x00404224
0x0040d316:	leal %eax, -56(%ebp)
0x0040d319:	pushl %eax
0x0040d31a:	movl %ecx, $0x40d434<UINT32>
0x0040d31f:	movl %edx, $0x25<UINT32>
0x0040d324:	movl %eax, %ebx
0x0040d326:	call 0x0040b840
0x0040d32b:	movl %eax, -56(%ebp)
0x0040d32e:	xorl %edx, %edx
0x0040d330:	call 0x004087b8
0x0040d335:	testl %eax, %eax
0x0040d337:	jne 15
0x0040d339:	leal %eax, -4(%ebp)
0x0040d33c:	movl %edx, $0x40d480<UINT32>
0x0040d341:	call 0x004042bc
0x004042bc:	testl %edx, %edx
0x004042be:	je 10
0x004042c0:	movl %ecx, -8(%edx)
0x004042c3:	incl %ecx
0x004042c4:	jle 0x004042ca
0x004042ca:	xchgl (%eax), %edx
0x004042cc:	testl %edx, %edx
0x004042ce:	je 0x004042e4
0x004042e4:	ret

0x0040d346:	jmp 0x0040d355
0x0040d355:	leal %eax, -60(%ebp)
0x0040d358:	pushl %eax
0x0040d359:	movl %ecx, $0x40d434<UINT32>
0x0040d35e:	movl %edx, $0x23<UINT32>
0x0040d363:	movl %eax, %ebx
0x0040d365:	call 0x0040b840
0x0040d36a:	movl %eax, -60(%ebp)
0x0040d36d:	xorl %edx, %edx
0x0040d36f:	call 0x004087b8
0x0040d374:	testl %eax, %eax
0x0040d376:	jne 63
0x0040d378:	leal %eax, -64(%ebp)
0x0040d37b:	pushl %eax
0x0040d37c:	movl %ecx, $0x40d434<UINT32>
0x0040d381:	movl %edx, $0x1005<UINT32>
0x0040d386:	movl %eax, %ebx
0x0040d388:	call 0x0040b840
0x0040d38d:	movl %eax, -64(%ebp)
0x0040d390:	xorl %edx, %edx
0x0040d392:	call 0x004087b8
0x0040d397:	testl %eax, %eax
0x0040d399:	jne 15
0x0040d39b:	leal %eax, -12(%ebp)
0x0040d39e:	movl %edx, $0x40d498<UINT32>
0x0040d3a3:	call 0x004042bc
0x0040d3a8:	jmp 0x0040d3b7
0x0040d3b7:	pushl -8(%ebp)
0x0040d3ba:	pushl -4(%ebp)
0x0040d3bd:	pushl $0x40d4b8<UINT32>
0x0040d3c2:	pushl -12(%ebp)
0x0040d3c5:	movl %eax, $0x4a16a4<UINT32>
0x0040d3ca:	movl %edx, $0x4<UINT32>
0x0040d3cf:	call 0x004045a4
0x004045a4:	pushl %ebx
0x004045a5:	pushl %esi
0x004045a6:	pushl %edi
0x004045a7:	pushl %edx
0x004045a8:	pushl %eax
0x004045a9:	movl %ebx, %edx
0x004045ab:	xorl %edi, %edi
0x004045ad:	movl %ecx, 0x14(%esp,%edx,4)
0x004045b1:	testl %ecx, %ecx
0x004045b3:	je 0x004045c1
0x004045c1:	xorl %eax, %eax
0x004045c3:	movl %ecx, 0x14(%esp,%edx,4)
0x004045c7:	testl %ecx, %ecx
0x004045c9:	je 0x004045d4
0x004045d4:	decl %edx
0x004045d5:	jne 0x004045c3
0x004045cb:	addl %eax, -4(%ecx)
0x004045ce:	cmpl %edi, %ecx
0x004045d0:	jne 0x004045d4
0x004045d7:	testl %edi, %edi
0x004045d9:	je 0x004045f2
0x004045f2:	call 0x004042e8
0x004045f7:	pushl %eax
0x004045f8:	movl %esi, %eax
0x004045fa:	movl %eax, 0x18(%esp,%ebx,4)
0x004045fe:	movl %edx, %esi
0x00404600:	testl %eax, %eax
0x00404602:	je 0x0040460e
0x0040460e:	decl %ebx
0x0040460f:	jne 0x004045fa
0x00404604:	movl %ecx, -4(%eax)
0x00404607:	addl %esi, %ecx
0x00404609:	call 0x00402900
0x00404611:	popl %edx
0x00404612:	popl %eax
0x00404613:	testl %edi, %edi
0x00404615:	jne 12
0x00404617:	testl %edx, %edx
0x00404619:	je 3
0x0040461b:	decl -8(%edx)
0x0040461e:	call 0x00404278
0x00404623:	popl %edx
0x00404624:	popl %edi
0x00404625:	popl %esi
0x00404626:	popl %ebx
0x00404627:	popl %eax
0x00404628:	leal %esp, (%esp,%edx,4)
0x0040462b:	jmp 0x0040d3f1
0x0040d3d4:	pushl -8(%ebp)
0x0040d3d7:	pushl -4(%ebp)
0x0040d3da:	pushl $0x40d4c4<UINT32>
0x0040d3df:	pushl -12(%ebp)
0x0040d3e2:	movl %eax, $0x4a16a8<UINT32>
0x0040d3e7:	movl %edx, $0x4<UINT32>
0x0040d3ec:	call 0x004045a4
0x0040d3f1:	movb %cl, $0x2c<UINT8>
0x0040d3f3:	movl %edx, $0xc<UINT32>
0x0040d3f8:	movl %eax, %ebx
0x0040d3fa:	call 0x0040b88c
0x0040d3ff:	movb 0x4a1752, %al
0x0040d404:	xorl %eax, %eax
0x0040d406:	popl %edx
0x0040d407:	popl %ecx
0x0040d408:	popl %ecx
0x0040d409:	movl %fs:(%eax), %edx
0x0040d40c:	pushl $0x40d426<UINT32>
0x0040d411:	leal %eax, -64(%ebp)
0x0040d414:	movl %edx, $0x10<UINT32>
0x0040d419:	call 0x00404248
0x00401e6e:	movl %edx, %esi
0x00401e70:	testl %edx, %edx
0x00401e72:	jns 0x00401e77
0x00401e77:	sarl %edx, $0x2<UINT8>
0x00401e7a:	movl %eax, 0x4a1624
0x00401e7f:	movl %eax, -12(%eax,%edx,4)
0x00401e83:	testl %eax, %eax
0x00401e85:	jne 0x00401e97
0x00401e87:	movl %eax, 0x4a1624
0x00401e8c:	movl -12(%eax,%edx,4), %ebx
0x00401e90:	movl 0x4(%ebx), %ebx
0x00401e93:	movl (%ebx), %ebx
0x00401e95:	jmp 0x00401ed1
0x00401c08:	cmpl %eax, %edx
0x00401c0a:	jne 23
0x00401c0c:	testl %ecx, %ecx
0x00401c0e:	jns 0x00401c13
0x00401c13:	sarl %ecx, $0x2<UINT8>
0x00401c16:	movl %eax, 0x4a1624
0x00401c1b:	xorl %edx, %edx
0x00401c1d:	movl -12(%eax,%ecx,4), %edx
0x00401c21:	jmp 0x00401c47
0x00401e97:	movl %edx, (%eax)
0x00401e99:	movl 0x4(%ebx), %eax
0x00401e9c:	movl (%ebx), %edx
0x00401e9e:	movl (%eax), %ebx
0x00401ea0:	movl 0x4(%edx), %ebx
0x00401ea3:	jmp 0x00401ed1
0x0040d41e:	ret

0x0040d426:	popl %ebx
0x0040d427:	movl %esp, %ebp
0x0040d429:	popl %ebp
0x0040d42a:	ret

0x0040e15e:	xorl %eax, %eax
0x0040e160:	popl %edx
0x0040e161:	popl %ecx
0x0040e162:	popl %ecx
0x0040e163:	movl %fs:(%eax), %edx
0x0040e166:	pushl $0x40e173<UINT32>
0x0040e16b:	ret

0x0040e173:	popl %ebp
0x0040e174:	ret

0x0040e970:	subl 0x4a17fc, $0x1<UINT8>
0x0040e977:	jae 5
0x0040e979:	call 0x0040e634
0x0040e634:	pushl %ebp
0x0040e635:	movl %ebp, %esp
0x0040e637:	pushl %ecx
0x0040e638:	pushl $0x40e82c<UINT32>
0x0040e63d:	call 0x004066c4
0x0040e642:	movl -4(%ebp), %eax
0x0040e645:	pushl %ebp
0x0040e646:	movl %edx, $0x40e1a4<UINT32>
0x0040e64b:	movl %eax, $0x40e83c<UINT32>
0x0040e650:	call 0x0040e608
0x0040e608:	pushl %ebp
0x0040e609:	movl %ebp, %esp
0x0040e60b:	pushl %ebx
0x0040e60c:	movl %ebx, %edx
0x0040e60e:	movl %edx, %ebx
0x0040e610:	movl %ecx, 0x8(%ebp)
0x0040e613:	cmpl -4(%ecx), $0x0<UINT8>
0x0040e617:	je 21
0x0040e619:	pushl %eax
0x0040e61a:	movl %eax, 0x8(%ebp)
0x0040e61d:	movl %eax, -4(%eax)
0x0040e620:	pushl %eax
0x0040e621:	call 0x004066cc
0x004066cc:	jmp GetProcAddress@KERNEL32.DLL
0x0040e626:	movl %edx, %eax
0x0040e628:	testl %edx, %edx
0x0040e62a:	jne 0x0040e62e
0x0040e62e:	movl %eax, %edx
0x0040e630:	popl %ebx
0x0040e631:	popl %ebp
0x0040e632:	ret

0x0040e655:	popl %ecx
0x0040e656:	movl 0x4a17a4, %eax
0x0040e65b:	pushl %ebp
0x0040e65c:	movl %edx, $0x40e1d4<UINT32>
0x0040e661:	movl %eax, $0x40e850<UINT32>
0x0040e666:	call 0x0040e608
0x0040e66b:	popl %ecx
0x0040e66c:	movl 0x4a17a8, %eax
0x0040e671:	pushl %ebp
0x0040e672:	movl %edx, $0x40e1d4<UINT32>
0x0040e677:	movl %eax, $0x40e858<UINT32>
0x0040e67c:	call 0x0040e608
0x0040e681:	popl %ecx
0x0040e682:	movl 0x4a17ac, %eax
0x0040e687:	pushl %ebp
0x0040e688:	movl %edx, $0x40e1e0<UINT32>
0x0040e68d:	movl %eax, $0x40e860<UINT32>
0x0040e692:	call 0x0040e608
0x0040e697:	popl %ecx
0x0040e698:	movl 0x4a17b0, %eax
0x0040e69d:	pushl %ebp
0x0040e69e:	movl %edx, $0x40e1e0<UINT32>
0x0040e6a3:	movl %eax, $0x40e868<UINT32>
0x0040e6a8:	call 0x0040e608
0x0040e6ad:	popl %ecx
0x0040e6ae:	movl 0x4a17b4, %eax
0x0040e6b3:	pushl %ebp
0x0040e6b4:	movl %edx, $0x40e1e0<UINT32>
0x0040e6b9:	movl %eax, $0x40e870<UINT32>
0x0040e6be:	call 0x0040e608
0x0040e6c3:	popl %ecx
0x0040e6c4:	movl 0x4a17b8, %eax
0x0040e6c9:	pushl %ebp
0x0040e6ca:	movl %edx, $0x40e1e0<UINT32>
0x0040e6cf:	movl %eax, $0x40e878<UINT32>
0x0040e6d4:	call 0x0040e608
0x0040e6d9:	popl %ecx
0x0040e6da:	movl 0x4a17bc, %eax
0x0040e6df:	pushl %ebp
0x0040e6e0:	movl %edx, $0x40e1e0<UINT32>
0x0040e6e5:	movl %eax, $0x40e880<UINT32>
0x0040e6ea:	call 0x0040e608
0x0040e6ef:	popl %ecx
0x0040e6f0:	movl 0x4a17c0, %eax
0x0040e6f5:	pushl %ebp
0x0040e6f6:	movl %edx, $0x40e1e0<UINT32>
0x0040e6fb:	movl %eax, $0x40e888<UINT32>
0x0040e700:	call 0x0040e608
0x0040e705:	popl %ecx
0x0040e706:	movl 0x4a17c4, %eax
0x0040e70b:	pushl %ebp
0x0040e70c:	movl %edx, $0x40e1e0<UINT32>
0x0040e711:	movl %eax, $0x40e890<UINT32>
0x0040e716:	call 0x0040e608
0x0040e71b:	popl %ecx
0x0040e71c:	movl 0x4a17c8, %eax
0x0040e721:	pushl %ebp
0x0040e722:	movl %edx, $0x40e1e0<UINT32>
0x0040e727:	movl %eax, $0x40e898<UINT32>
0x0040e72c:	call 0x0040e608
0x0040e731:	popl %ecx
0x0040e732:	movl 0x4a17cc, %eax
0x0040e737:	pushl %ebp
0x0040e738:	movl %edx, $0x40e1e0<UINT32>
0x0040e73d:	movl %eax, $0x40e8a0<UINT32>
0x0040e742:	call 0x0040e608
0x0040e747:	popl %ecx
0x0040e748:	movl 0x4a17d0, %eax
0x0040e74d:	pushl %ebp
0x0040e74e:	movl %edx, $0x40e1ec<UINT32>
0x0040e753:	movl %eax, $0x40e8a8<UINT32>
0x0040e758:	call 0x0040e608
0x0040e75d:	popl %ecx
0x0040e75e:	movl 0x4a17d4, %eax
0x0040e763:	pushl %ebp
0x0040e764:	movl %edx, $0x40e1f8<UINT32>
0x0040e769:	movl %eax, $0x40e8b0<UINT32>
0x0040e76e:	call 0x0040e608
0x0040e773:	popl %ecx
0x0040e774:	movl 0x4a17d8, %eax
0x0040e779:	pushl %ebp
0x0040e77a:	movl %edx, $0x40e264<UINT32>
0x0040e77f:	movl %eax, $0x40e8c0<UINT32>
0x0040e784:	call 0x0040e608
0x0040e789:	popl %ecx
0x0040e78a:	movl 0x4a17dc, %eax
0x0040e78f:	pushl %ebp
0x0040e790:	movl %edx, $0x40e2d0<UINT32>
0x0040e795:	movl %eax, $0x40e8d0<UINT32>
0x0040e79a:	call 0x0040e608
0x0040e79f:	popl %ecx
0x0040e7a0:	movl 0x4a17e0, %eax
0x0040e7a5:	pushl %ebp
0x0040e7a6:	movl %edx, $0x40e33c<UINT32>
0x0040e7ab:	movl %eax, $0x40e8e0<UINT32>
0x0040e7b0:	call 0x0040e608
0x0040e7b5:	popl %ecx
0x0040e7b6:	movl 0x4a17e4, %eax
0x0040e7bb:	pushl %ebp
0x0040e7bc:	movl %edx, $0x40e3a8<UINT32>
0x0040e7c1:	movl %eax, $0x40e8f0<UINT32>
0x0040e7c6:	call 0x0040e608
0x0040e7cb:	popl %ecx
0x0040e7cc:	movl 0x4a17e8, %eax
0x0040e7d1:	pushl %ebp
0x0040e7d2:	movl %edx, $0x40e414<UINT32>
0x0040e7d7:	movl %eax, $0x40e900<UINT32>
0x0040e7dc:	call 0x0040e608
0x0040e7e1:	popl %ecx
0x0040e7e2:	movl 0x4a17ec, %eax
0x0040e7e7:	pushl %ebp
0x0040e7e8:	movl %edx, $0x40e494<UINT32>
0x0040e7ed:	movl %eax, $0x40e910<UINT32>
0x0040e7f2:	call 0x0040e608
0x0040e7f7:	popl %ecx
0x0040e7f8:	movl 0x4a17f0, %eax
0x0040e7fd:	pushl %ebp
0x0040e7fe:	movl %edx, $0x40e504<UINT32>
0x0040e803:	movl %eax, $0x40e920<UINT32>
0x0040e808:	call 0x0040e608
0x0040e80d:	popl %ecx
0x0040e80e:	movl 0x4a17f4, %eax
0x0040e813:	pushl %ebp
0x0040e814:	movl %edx, $0x40e574<UINT32>
0x0040e819:	movl %eax, $0x40e930<UINT32>
0x0040e81e:	call 0x0040e608
0x0040e823:	popl %ecx
0x0040e824:	movl 0x4a17f8, %eax
0x0040e829:	popl %ecx
0x0040e82a:	popl %ebp
0x0040e82b:	ret

0x0040e97e:	ret

0x00414f90:	pushl %ebp
0x00414f91:	movl %ebp, %esp
0x00414f93:	xorl %eax, %eax
0x00414f95:	pushl %ebp
0x00414f96:	pushl $0x415031<UINT32>
0x00414f9b:	pushl %fs:(%eax)
0x00414f9e:	movl %fs:(%eax), %esp
0x00414fa1:	subl 0x4a1820, $0x1<UINT8>
0x00414fa8:	jae 121
0x00414faa:	movl %eax, $0x4a1800<UINT32>
0x00414faf:	call 0x00414a18
0x00414a18:	movl %edx, $0x80020004<UINT32>
0x00414a1d:	call 0x00414a00
0x00414a00:	pushl %ebx
0x00414a01:	pushl %esi
0x00414a02:	movl %esi, %edx
0x00414a04:	movl %ebx, %eax
0x00414a06:	movl %eax, %ebx
0x00414a08:	call 0x0040f84c
0x0040f84c:	testw (%eax), $0xffffbfe8<UINT16>
0x0040f851:	jne 6
0x0040f853:	movw (%eax), $0x0<UINT16>
0x0040f858:	ret

0x00414a0d:	movw (%ebx), $0xa<UINT16>
0x00414a12:	movl 0x8(%ebx), %esi
0x00414a15:	popl %esi
0x00414a16:	popl %ebx
0x00414a17:	ret

0x00414a22:	ret

0x00414fb4:	movl %eax, $0x40f560<UINT32>
0x00414fb9:	movl 0x4a1810, %eax
0x00414fbe:	movl %eax, $0x40f0b0<UINT32>
0x00414fc3:	movl 0x4a1814, %eax
0x00414fc8:	movl %edx, $0x40efc0<UINT32>
0x00414fcd:	movl 0x4a1818, %edx
0x00414fd3:	movl 0x4a181c, %eax
0x00414fd8:	movl %eax, $0x40f860<UINT32>
0x00414fdd:	movl %edx, 0x4a07d4
0x00414fe3:	movl (%edx), %eax
0x00414fe5:	movl %eax, $0x41460c<UINT32>
0x00414fea:	movl %edx, 0x4a0560
0x00414ff0:	movl (%edx), %eax
0x00414ff2:	movl %eax, $0x40fb74<UINT32>
0x00414ff7:	movl %edx, 0x4a085c
0x00414ffd:	movl (%edx), %eax
0x00414fff:	movl %eax, $0x412b64<UINT32>
0x00415004:	movl %edx, 0x4a09d0
0x0041500a:	movl (%edx), %eax
0x0041500c:	movl %eax, $0x41328c<UINT32>
0x00415011:	movl %edx, 0x4a0880
0x00415017:	movl (%edx), %eax
0x00415019:	pushl $0x4a1828<UINT32>
0x0041501e:	call 0x00406764
0x00406764:	jmp InitializeCriticalSection@KERNEL32.DLL
0x00415023:	xorl %eax, %eax
0x00415025:	popl %edx
0x00415026:	popl %ecx
0x00415027:	popl %ecx
0x00415028:	movl %fs:(%eax), %edx
0x0041502b:	pushl $0x415038<UINT32>
0x00415030:	ret

0x00415038:	popl %ebp
0x00415039:	ret

0x004151a4:	subl 0x4a1840, $0x1<UINT8>
0x004151ab:	ret

0x00415f54:	subl 0x4a1844, $0x1<UINT8>
0x00415f5b:	ret

0x00422a38:	pushl %ebp
0x00422a39:	movl %ebp, %esp
0x00422a3b:	xorl %eax, %eax
0x00422a3d:	pushl %ebp
0x00422a3e:	pushl $0x422ac1<UINT32>
0x00422a43:	pushl %fs:(%eax)
0x00422a46:	movl %fs:(%eax), %esp
0x00422a49:	subl 0x4a1858, $0x1<UINT8>
0x00422a50:	jae 97
0x00422a52:	call 0x0042154c
0x0042154c:	pushl $0x4a186c<UINT32>
0x00421551:	call 0x00406764
0x00421556:	pushl $0x42157c<UINT32>
0x0042155b:	pushl $0x0<UINT8>
0x0042155d:	pushl $0xffffffff<UINT8>
0x0042155f:	pushl $0x0<UINT8>
0x00421561:	call 0x004065cc
0x004065cc:	jmp CreateEventA@KERNEL32.DLL
CreateEventA@KERNEL32.DLL: API Node	
0x00421566:	movl 0x4a1854, %eax
0x0042156b:	cmpl 0x4a1854, $0x0<UINT8>
0x00421572:	jne 0x00421579
0x00421579:	ret

0x00422a57:	movl %eax, $0x4227c0<UINT32>
0x00422a5c:	call 0x00405a90
0x00405a90:	call 0x00405aa0
0x00405aa0:	pushl %ebx
0x00405aa1:	movl %ebx, %eax
0x00405aa3:	movl %eax, $0x8<UINT32>
0x00405aa8:	call 0x00402704
0x00405aad:	movl %edx, 0x49f03c
0x00405ab3:	movl (%eax), %edx
0x00405ab5:	movl 0x4(%eax), %ebx
0x00405ab8:	movl 0x49f03c, %eax
0x00405abd:	popl %ebx
0x00405abe:	ret

0x00405a95:	ret

0x00422a61:	movb %dl, $0x1<UINT8>
0x00422a63:	movl %eax, 0x408170
0x00422a68:	call 0x0040d8a4
0x0040d8a4:	pushl %ebx
0x0040d8a5:	pushl %esi
0x0040d8a6:	testb %dl, %dl
0x0040d8a8:	je 8
0x0040d8aa:	addl %esp, $0xfffffff0<UINT8>
0x0040d8ad:	call 0x004037f8
0x00405c98:	call 0x0040342c
0x004034c5:	pushl %ecx
0x004034d5:	popl %ebx
0x004034d6:	movl %ecx, (%ebx)
0x004034d8:	addl %ebx, $0x4<UINT8>
0x004034db:	movl %esi, 0x10(%ebx)
0x004034de:	testl %esi, %esi
0x004034e0:	je 6
0x004034e2:	movl %edi, 0x14(%ebx)
0x004034e5:	movl (%edi,%eax), %esi
0x004034e8:	addl %ebx, $0x1c<UINT8>
0x004034eb:	decl %ecx
0x004034ec:	jne -19
0x004034ee:	cmpl %esp, %edx
0x004034f0:	jne 0x004034d5
0x00405c9d:	movl 0x4(%eax), $0x1<UINT32>
0x00405ca4:	ret

0x0040d8b2:	movl %ebx, %edx
0x0040d8b4:	movl %esi, %eax
0x0040d8b6:	xorl %edx, %edx
0x0040d8b8:	movl %eax, %esi
0x0040d8ba:	call 0x00403464
0x00403464:	testb %dl, %dl
0x00403466:	je 0x00403470
0x00403470:	testb %dl, %dl
0x00403472:	je 0x00403483
0x00403483:	ret

0x0040d8bf:	movl 0xc(%esi), $0xffff<UINT32>
0x0040d8c6:	pushl $0x0<UINT8>
0x0040d8c8:	pushl $0xffffffff<UINT8>
0x0040d8ca:	pushl $0xffffffff<UINT8>
0x0040d8cc:	pushl $0x0<UINT8>
0x0040d8ce:	call 0x004065cc
0x0040d8d3:	movl 0x10(%esi), %eax
0x0040d8d6:	pushl $0x0<UINT8>
0x0040d8d8:	pushl $0x0<UINT8>
0x0040d8da:	pushl $0x0<UINT8>
0x0040d8dc:	pushl $0x0<UINT8>
0x0040d8de:	call 0x004065cc
0x0040d8e3:	movl 0x14(%esi), %eax
0x0040d8e6:	movl 0x18(%esi), $0xffffffff<UINT32>
0x0040d8ed:	movb %dl, $0x1<UINT8>
0x0040d8ef:	movl %eax, 0x408094
0x0040d8f4:	call 0x00403464
0x00403468:	addl %esp, $0xfffffff0<UINT8>
0x0040346b:	call 0x004037f8
0x00403474:	call 0x00403850
0x00403479:	popl %fs:0
0x00403480:	addl %esp, $0xc<UINT8>
0x0040d8f9:	movl 0x20(%esi), %eax
0x0040d8fc:	movl %eax, %esi
0x0040d8fe:	testb %bl, %bl
0x0040d900:	je 15
0x0040d902:	call 0x00403850
0x00405c7c:	addl %eax, $0x4<UINT8>
0x00405c7f:	pushl %eax
0x00405c80:	call 0x0040132c
0x0040132c:	jmp InterlockedDecrement@KERNEL32.DLL
InterlockedDecrement@KERNEL32.DLL: API Node	
0x00405c85:	ret

0x0040d907:	popl %fs:0
0x0040d90e:	addl %esp, $0xc<UINT8>
0x0040d911:	movl %eax, %esi
0x0040d913:	popl %esi
0x0040d914:	popl %ebx
0x0040d915:	ret

0x00422a6d:	movl %edx, %eax
0x00422a6f:	testl %edx, %edx
0x00422a71:	je 3
0x00422a73:	subl %edx, $0xffffffd4<UINT8>
0x00422a76:	movl %eax, $0x4a184c<UINT32>
0x00422a7b:	call 0x00405c14
0x00405c14:	testl %edx, %edx
0x00405c16:	je 25
0x00405c18:	pushl %edx
0x00405c19:	pushl %eax
0x00405c1a:	movl %eax, (%edx)
0x00405c1c:	pushl %edx
0x00405c1d:	call 0x0040811f
0x0040811f:	addl 0x4(%esp), $0xffffffd4<UINT8>
0x00408124:	jmp 0x00405cd0
0x00405cd0:	pushl %ebp
0x00405cd1:	movl %ebp, %esp
0x00405cd3:	movl %eax, 0x8(%ebp)
0x00405cd6:	addl %eax, $0x4<UINT8>
0x00405cd9:	pushl %eax
0x00405cda:	call 0x00401324
0x00401324:	jmp InterlockedIncrement@KERNEL32.DLL
InterlockedIncrement@KERNEL32.DLL: API Node	
0x00405cdf:	popl %ebp
0x00405ce0:	ret $0x4<UINT16>

0x00405c20:	popl %eax
0x00405c21:	movl %ecx, (%eax)
0x00405c23:	popl (%eax)
0x00405c25:	testl %ecx, %ecx
0x00405c27:	jne 1
0x00405c29:	ret

0x00422a80:	movb %dl, $0x1<UINT8>
0x00422a82:	movl %eax, 0x417a48
0x00422a87:	call 0x00417eac
0x00417eac:	pushl %ebx
0x00417ead:	pushl %esi
0x00417eae:	pushl %edi
0x00417eaf:	testb %dl, %dl
0x00417eb1:	je 8
0x00417eb3:	addl %esp, $0xfffffff0<UINT8>
0x00417eb6:	call 0x004037f8
0x00417ebb:	movl %ebx, %edx
0x00417ebd:	movl %edi, %eax
0x00417ebf:	xorl %edx, %edx
0x00417ec1:	movl %eax, %edi
0x00417ec3:	call 0x00403464
0x00417ec8:	movb %dl, $0x1<UINT8>
0x00417eca:	movl %eax, 0x416778
0x00417ecf:	call 0x00403464
0x00417ed4:	movl 0x4(%edi), %eax
0x00417ed7:	leal %eax, 0x8(%edi)
0x00417eda:	pushl %eax
0x00417edb:	call 0x00406764
0x00417ee0:	movl %ecx, 0x416888
0x00417ee6:	movb %dl, $0x1<UINT8>
0x00417ee8:	movl %eax, 0x4179f0
0x00417eed:	call 0x00417b7c
0x00417b7c:	pushl %ebp
0x00417b7d:	movl %ebp, %esp
0x00417b7f:	pushl %ecx
0x00417b80:	pushl %ebx
0x00417b81:	pushl %esi
0x00417b82:	pushl %edi
0x00417b83:	testb %dl, %dl
0x00417b85:	je 8
0x00417b87:	addl %esp, $0xfffffff0<UINT8>
0x00417b8a:	call 0x004037f8
0x00417b8f:	movl %edi, %ecx
0x00417b91:	movb -1(%ebp), %dl
0x00417b94:	movl %ebx, %eax
0x00417b96:	xorl %edx, %edx
0x00417b98:	movl %eax, %ebx
0x00417b9a:	call 0x00403464
0x00417b9f:	movb %dl, $0x1<UINT8>
0x00417ba1:	movl %eax, 0x416778
0x00417ba6:	call 0x00403464
0x00417bab:	movl 0x4(%ebx), %eax
0x00417bae:	movb %dl, $0x1<UINT8>
0x00417bb0:	movl %eax, 0x416ddc
0x00417bb5:	call 0x00403464
0x00417bba:	movl 0x8(%ebx), %eax
0x00417bbd:	movb %dl, $0x1<UINT8>
0x00417bbf:	movl %eax, 0x416778
0x00417bc4:	call 0x00403464
0x00417bc9:	movl %esi, %eax
0x00417bcb:	movl 0xc(%ebx), %esi
0x00417bce:	movl %eax, %esi
0x00417bd0:	movl %edx, %edi
0x00417bd2:	call 0x00418e6c
0x00418e6c:	pushl %ebx
0x00418e6d:	pushl %esi
0x00418e6e:	pushl %edi
0x00418e6f:	movl %edi, %edx
0x00418e71:	movl %ebx, %eax
0x00418e73:	movl %esi, 0x8(%ebx)
0x00418e76:	cmpl %esi, 0xc(%ebx)
0x00418e79:	jne 0x00418e81
0x00418e7b:	movl %eax, %ebx
0x00418e7d:	movl %edx, (%eax)
0x00418e7f:	call 0x00418ff0
0x00418ff0:	movl %edx, 0xc(%eax)
0x00418ff3:	cmpl %edx, $0x40<UINT8>
0x00418ff6:	jle 0x00419006
0x00419006:	cmpl %edx, $0x8<UINT8>
0x00419009:	jle 0x00419012
0x00419012:	movl %ecx, $0x4<UINT32>
0x00419017:	addl %ecx, %edx
0x00419019:	movl %edx, %ecx
0x0041901b:	call 0x00419184
0x00419184:	pushl %ebx
0x00419185:	pushl %esi
0x00419186:	movl %esi, %edx
0x00419188:	movl %ebx, %eax
0x0041918a:	cmpl %esi, 0x8(%ebx)
0x0041918d:	jl 8
0x0041918f:	cmpl %esi, $0x7ffffff<UINT32>
0x00419195:	jle 0x004191a6
0x004191a6:	cmpl %esi, 0xc(%ebx)
0x004191a9:	je 16
0x004191ab:	movl %edx, %esi
0x004191ad:	shll %edx, $0x2<UINT8>
0x004191b0:	leal %eax, 0x4(%ebx)
0x004191b3:	call 0x00402744
0x00402744:	movl %ecx, (%eax)
0x00402746:	testl %ecx, %ecx
0x00402748:	je 0x0040277c
0x0040277c:	testl %edx, %edx
0x0040277e:	je 16
0x00402780:	pushl %eax
0x00402781:	movl %eax, %edx
0x00402783:	call 0x00402130
0x00402789:	popl %ecx
0x0040278a:	orl %eax, %eax
0x0040278c:	je -25
0x0040278e:	movl (%ecx), %eax
0x00402790:	ret

0x004191b8:	movl 0xc(%ebx), %esi
0x004191bb:	popl %esi
0x004191bc:	popl %ebx
0x004191bd:	ret

0x00419020:	ret

0x00418e81:	movl %eax, 0x4(%ebx)
0x00418e84:	movl (%eax,%esi,4), %edi
0x00418e87:	incl 0x8(%ebx)
0x00418e8a:	testl %edi, %edi
0x00418e8c:	je 11
0x00418e8e:	xorl %ecx, %ecx
0x00418e90:	movl %edx, %edi
0x00418e92:	movl %eax, %ebx
0x00418e94:	movl %ebx, (%eax)
0x00418e96:	call 0x00000000
0x004192d4:	ret

0x00418e99:	movl %eax, %esi
0x00418e9b:	popl %edi
0x00418e9c:	popl %esi
0x00418e9d:	popl %ebx
0x00418e9e:	ret

0x00417bd7:	movl %eax, %ebx
0x00417bd9:	cmpb -1(%ebp), $0x0<UINT8>
0x00417bdd:	je 15
0x00417bdf:	call 0x00403850
0x00417be4:	popl %fs:0
0x00417beb:	addl %esp, $0xc<UINT8>
0x00417bee:	movl %eax, %ebx
0x00417bf0:	popl %edi
0x00417bf1:	popl %esi
0x00417bf2:	popl %ebx
0x00417bf3:	popl %ecx
0x00417bf4:	popl %ebp
0x00417bf5:	ret

0x00417ef2:	movl %esi, %eax
0x00417ef4:	movl %eax, 0x4(%edi)
0x00417ef7:	movl %edx, %esi
0x00417ef9:	call 0x00418e6c
0x00417efe:	movb 0x10(%esi), $0x1<UINT8>
0x00417f02:	movl %eax, %edi
0x00417f04:	testb %bl, %bl
0x00417f06:	je 15
0x00417f08:	call 0x00403850
0x00417f0d:	popl %fs:0
0x00417f14:	addl %esp, $0xc<UINT8>
0x00417f17:	movl %eax, %edi
0x00417f19:	popl %edi
0x00417f1a:	popl %esi
0x00417f1b:	popl %ebx
0x00417f1c:	ret

0x00422a8c:	movl 0x4a1860, %eax
0x00422a91:	movb %dl, $0x1<UINT8>
0x00422a93:	movl %eax, 0x4167dc
0x00422a98:	call 0x004195a4
0x004195a4:	pushl %ebx
0x004195a5:	pushl %esi
0x004195a6:	testb %dl, %dl
0x004195a8:	je 8
0x004195aa:	addl %esp, $0xfffffff0<UINT8>
0x004195ad:	call 0x004037f8
0x004195b2:	movl %ebx, %edx
0x004195b4:	movl %esi, %eax
0x004195b6:	xorl %edx, %edx
0x004195b8:	movl %eax, %esi
0x004195ba:	call 0x00403464
0x004195bf:	leal %eax, 0x8(%esi)
0x004195c2:	pushl %eax
0x004195c3:	call 0x00406764
0x004195c8:	movb %dl, $0x1<UINT8>
0x004195ca:	movl %eax, 0x416778
0x004195cf:	call 0x00403464
0x004195d4:	movl 0x4(%esi), %eax
0x004195d7:	movb 0x20(%esi), $0x0<UINT8>
0x004195db:	movl %eax, %esi
0x004195dd:	testb %bl, %bl
0x004195df:	je 15
0x004195e1:	call 0x00403850
0x004195e6:	popl %fs:0
0x004195ed:	addl %esp, $0xc<UINT8>
0x004195f0:	movl %eax, %esi
0x004195f2:	popl %esi
0x004195f3:	popl %ebx
0x004195f4:	ret

0x00422a9d:	movl 0x4a185c, %eax
0x00422aa2:	movb %dl, $0x1<UINT8>
0x00422aa4:	movl %eax, 0x4167dc
0x00422aa9:	call 0x004195a4
0x00422aae:	movl 0x4a1868, %eax
0x00422ab3:	xorl %eax, %eax
0x00422ab5:	popl %edx
0x00422ab6:	popl %ecx
0x00422ab7:	popl %ecx
0x00422ab8:	movl %fs:(%eax), %edx
0x00422abb:	pushl $0x422ac8<UINT32>
0x00422ac0:	ret

0x00422ac8:	popl %ebp
0x00422ac9:	ret

0x0042c274:	subl 0x4a18f0, $0x1<UINT8>
0x0042c27b:	ret

0x0042c534:	subl 0x4a18f4, $0x1<UINT8>
0x0042c53b:	ret

0x0042e584:	subl 0x4a193c, $0x1<UINT8>
0x0042e58b:	ret

0x0042d54c:	subl 0x4a1924, $0x1<UINT8>
0x0042d553:	jae 5
0x0042d555:	call 0x0042d4b0
0x0042d4b0:	pushl $0x42d510<UINT32>
0x0042d4b5:	call 0x004066c4
0x0042d4ba:	movl 0x4a1928, %eax
0x0042d4bf:	movl 0x4a1904, $0x42cebc<UINT32>
0x0042d4c9:	movl 0x4a1908, $0x42cfd4<UINT32>
0x0042d4d3:	movl 0x4a190c, $0x42cf44<UINT32>
0x0042d4dd:	movl 0x4a1910, $0x42d06c<UINT32>
0x0042d4e7:	movl 0x4a1914, $0x42d104<UINT32>
0x0042d4f1:	movl 0x4a1918, $0x42d1d8<UINT32>
0x0042d4fb:	movl 0x4a191c, $0x42d2ac<UINT32>
0x0042d505:	movl 0x4a1920, $0x42d380<UINT32>
0x0042d50f:	ret

0x0042d55a:	ret

0x0042cdcc:	subl 0x4a18f8, $0x1<UINT8>
0x0042cdd3:	ret

0x00422dcc:	subl 0x4a188c, $0x1<UINT8>
0x00422dd3:	ret

0x0042c0f8:	subl 0x4a1894, $0x1<UINT8>
0x0042c0ff:	jae 237
0x0042c105:	call 0x0042bbfc
0x0042bbfc:	pushl %ebx
0x0042bbfd:	pushl $0x0<UINT8>
0x0042bbff:	call 0x00406c2c
0x00406c2c:	jmp GetDC@user32.dll
GetDC@user32.dll: API Node	
0x0042bc04:	movl %ebx, %eax
0x0042bc06:	pushl $0x5a<UINT8>
0x0042bc08:	pushl %ebx
0x0042bc09:	call 0x00406904
0x00406904:	jmp GetDeviceCaps@gdi32.dll
GetDeviceCaps@gdi32.dll: API Node	
0x0042bc0e:	movl 0x4a1898, %eax
0x0042bc13:	pushl %ebx
0x0042bc14:	pushl $0x0<UINT8>
0x0042bc16:	call 0x00406eac
0x00406eac:	jmp ReleaseDC@user32.dll
ReleaseDC@user32.dll: API Node	
0x0042bc1b:	movl %eax, $0x49f7a0<UINT32>
0x0042bc20:	movl %edx, $0xf<UINT32>
0x0042bc25:	call 0x00426834
0x00426834:	pushl %ebp
0x00426835:	movl %ebp, %esp
0x00426837:	addl %esp, $0xfffffbf8<UINT32>
0x0042683d:	pushl %ebx
0x0042683e:	movw -1032(%ebp), $0x300<UINT16>
0x00426847:	movw -1030(%ebp), $0x10<UINT16>
0x00426850:	leal %edx, -1028(%ebp)
0x00426856:	movl %ecx, $0x40<UINT32>
0x0042685b:	call 0x00402900
0x00426860:	pushl $0x0<UINT8>
0x00426862:	call 0x00406c2c
0x00426867:	movl -4(%ebp), %eax
0x0042686a:	xorl %eax, %eax
0x0042686c:	pushl %ebp
0x0042686d:	pushl $0x426931<UINT32>
0x00426872:	pushl %fs:(%eax)
0x00426875:	movl %fs:(%eax), %esp
0x00426878:	pushl $0x68<UINT8>
0x0042687a:	movl %eax, -4(%ebp)
0x0042687d:	pushl %eax
0x0042687e:	call 0x00406904
0x00426883:	movl %ebx, %eax
0x00426885:	cmpl %ebx, $0x10<UINT8>
0x00426888:	jl 0x00426918
0x00426918:	xorl %eax, %eax
0x0042691a:	popl %edx
0x0042691b:	popl %ecx
0x0042691c:	popl %ecx
0x0042691d:	movl %fs:(%eax), %edx
0x00426920:	pushl $0x426938<UINT32>
0x00426925:	movl %eax, -4(%ebp)
0x00426928:	pushl %eax
0x00426929:	pushl $0x0<UINT8>
0x0042692b:	call 0x00406eac
0x00426930:	ret

0x00426938:	leal %eax, -1032(%ebp)
0x0042693e:	pushl %eax
0x0042693f:	call 0x0040687c
0x0040687c:	jmp CreatePalette@gdi32.dll
CreatePalette@gdi32.dll: API Node	
0x00426944:	popl %ebx
0x00426945:	movl %esp, %ebp
0x00426947:	popl %ebp
0x00426948:	ret

0x0042bc2a:	movl 0x4a1890, %eax
0x0042bc2f:	popl %ebx
0x0042bc30:	ret

0x0042c10a:	pushl $0x4a18ac<UINT32>
0x0042c10f:	call 0x00406764
0x0042c114:	pushl $0x4a18c4<UINT32>
0x0042c119:	call 0x00406764
0x0042c11e:	pushl $0x7<UINT8>
0x0042c120:	call 0x0040693c
0x0040693c:	jmp GetStockObject@gdi32.dll
GetStockObject@gdi32.dll: API Node	
0x0042c125:	movl 0x4a189c, %eax
0x0042c12a:	pushl $0x5<UINT8>
0x0042c12c:	call 0x0040693c
0x0042c131:	movl 0x4a18a0, %eax
0x0042c136:	pushl $0xd<UINT8>
0x0042c138:	call 0x0040693c
0x0042c13d:	movl 0x4a18a4, %eax
0x0042c142:	pushl $0x7f00<UINT32>
0x0042c147:	pushl $0x0<UINT8>
0x0042c149:	call 0x00406e0c
0x00406e0c:	jmp LoadIconA@user32.dll
LoadIconA@user32.dll: API Node	
0x0042c14e:	movl 0x4a18a8, %eax
0x0042c153:	call 0x0042bc78
0x0042bc78:	pushl %ebx
0x0042bc79:	pushl %esi
0x0042bc7a:	pushl %edi
0x0042bc7b:	pushl $0x48<UINT8>
0x0042bc7d:	movl %eax, 0x4a1898
0x0042bc82:	pushl %eax
0x0042bc83:	pushl $0x8<UINT8>
0x0042bc85:	call 0x0040678c
0x0040678c:	jmp MulDiv@KERNEL32.DLL
MulDiv@KERNEL32.DLL: API Node	
0x0042bc8a:	negl %eax
0x0042bc8c:	movl 0x49f4e0, %eax
0x0042bc91:	movl %eax, 0x4a0a30
0x0042bc96:	cmpb 0xc(%eax), $0x0<UINT8>
0x0042bc9a:	je 0x0042bcd3
0x0042bcd3:	popl %edi
0x0042bcd4:	popl %esi
0x0042bcd5:	popl %ebx
0x0042bcd6:	ret

0x0042c158:	movw %cx, $0x2c<UINT16>
0x0042c15c:	movb %dl, $0x1<UINT8>
0x0042c15e:	movl %eax, 0x423dc8
0x0042c163:	call 0x00423e3c
0x00423e3c:	pushl %ebx
0x00423e3d:	pushl %esi
0x00423e3e:	testb %dl, %dl
0x00423e40:	je 8
0x00423e42:	addl %esp, $0xfffffff0<UINT8>
0x00423e45:	call 0x004037f8
0x00423e4a:	movl %ebx, %edx
0x00423e4c:	movl %esi, %eax
0x00423e4e:	movw 0x20(%esi), %cx
0x00423e52:	leal %eax, 0x8(%esi)
0x00423e55:	pushl %eax
0x00423e56:	call 0x00406764
0x00423e5b:	movl %eax, %esi
0x00423e5d:	testb %bl, %bl
0x00423e5f:	je 15
0x00423e61:	call 0x00403850
0x00423e66:	popl %fs:0
0x00423e6d:	addl %esp, $0xc<UINT8>
0x00423e70:	movl %eax, %esi
0x00423e72:	popl %esi
0x00423e73:	popl %ebx
0x00423e74:	ret

0x0042c168:	movl 0x4a18dc, %eax
0x0042c16d:	movw %cx, $0x10<UINT16>
0x0042c171:	movb %dl, $0x1<UINT8>
0x0042c173:	movl %eax, 0x423dc8
0x0042c178:	call 0x00423e3c
0x0042c17d:	movl 0x4a18e0, %eax
0x0042c182:	movw %cx, $0x10<UINT16>
0x0042c186:	movb %dl, $0x1<UINT8>
0x0042c188:	movl %eax, 0x423dc8
0x0042c18d:	call 0x00423e3c
0x0042c192:	movl 0x4a18e4, %eax
0x0042c197:	movb %dl, $0x1<UINT8>
0x0042c199:	movl %eax, 0x42bce8
0x0042c19e:	call 0x0042bd44
0x0042bd44:	pushl %ebx
0x0042bd45:	pushl %esi
0x0042bd46:	testb %dl, %dl
0x0042bd48:	je 8
0x0042bd4a:	addl %esp, $0xfffffff0<UINT8>
0x0042bd4d:	call 0x004037f8
0x0042bd52:	movl %ebx, %edx
0x0042bd54:	movl %esi, %eax
0x0042bd56:	leal %eax, 0x8(%esi)
0x0042bd59:	pushl %eax
0x0042bd5a:	call 0x00406764
0x0042bd5f:	movl %eax, %esi
0x0042bd61:	testb %bl, %bl
0x0042bd63:	je 15
0x0042bd65:	call 0x00403850
0x0042bd6a:	popl %fs:0
0x0042bd71:	addl %esp, $0xc<UINT8>
0x0042bd74:	movl %eax, %esi
0x0042bd76:	popl %esi
0x0042bd77:	popl %ebx
0x0042bd78:	ret

0x0042c1a3:	movl 0x4a18ec, %eax
0x0042c1a8:	movb %dl, $0x1<UINT8>
0x0042c1aa:	movl %eax, 0x4167dc
0x0042c1af:	call 0x004195a4
0x0042c1b4:	movl 0x49f794, %eax
0x0042c1b9:	movb %dl, $0x1<UINT8>
0x0042c1bb:	movl %eax, 0x4167dc
0x0042c1c0:	call 0x004195a4
0x0042c1c5:	movl 0x4a18e8, %eax
0x0042c1ca:	movl %ecx, $0x424694<UINT32>
0x0042c1cf:	movl %edx, $0x4246a4<UINT32>
0x0042c1d4:	movl %eax, 0x422dd4
0x0042c1d9:	call 0x00418788
0x00418788:	pushl %ebx
0x00418789:	pushl %esi
0x0041878a:	pushl %edi
0x0041878b:	movl %edi, %ecx
0x0041878d:	movl %esi, %edx
0x0041878f:	movl %ebx, %eax
0x00418791:	pushl %esi
0x00418792:	pushl %edi
0x00418793:	movl %ecx, %ebx
0x00418795:	movb %dl, $0x1<UINT8>
0x00418797:	movl %eax, 0x4186f8
0x0041879c:	call 0x00418750
0x00418750:	pushl %ebp
0x00418751:	movl %ebp, %esp
0x00418753:	testb %dl, %dl
0x00418755:	je 8
0x00418757:	addl %esp, $0xfffffff0<UINT8>
0x0041875a:	call 0x004037f8
0x0041875f:	movl 0x4(%eax), %ecx
0x00418762:	movl %ecx, 0xc(%ebp)
0x00418765:	movl 0x8(%eax), %ecx
0x00418768:	movl %ecx, 0x8(%ebp)
0x0041876b:	movl 0xc(%eax), %ecx
0x0041876e:	testb %dl, %dl
0x00418770:	je 15
0x00418772:	call 0x00403850
0x00418777:	popl %fs:0
0x0041877e:	addl %esp, $0xc<UINT8>
0x00418781:	popl %ebp
0x00418782:	ret $0x8<UINT16>

0x004187a1:	movl %edx, %eax
0x004187a3:	movl %eax, 0x4a185c
0x004187a8:	call 0x00419674
0x00419674:	pushl %ebp
0x00419675:	movl %ebp, %esp
0x00419677:	pushl %ecx
0x00419678:	pushl %ebx
0x00419679:	movl %ebx, %edx
0x0041967b:	movl -4(%ebp), %eax
0x0041967e:	movl %eax, -4(%ebp)
0x00419681:	call 0x004196fc
0x004196fc:	pushl %ebx
0x004196fd:	movl %ebx, %eax
0x004196ff:	leal %eax, 0x8(%ebx)
0x00419702:	pushl %eax
0x00419703:	call 0x004065f4
0x004065f4:	jmp EnterCriticalSection@KERNEL32.DLL
EnterCriticalSection@KERNEL32.DLL: API Node	
0x00419708:	movl %eax, 0x4(%ebx)
0x0041970b:	popl %ebx
0x0041970c:	ret

0x00419686:	xorl %eax, %eax
0x00419688:	pushl %ebp
0x00419689:	pushl $0x4196f0<UINT32>
0x0041968e:	pushl %fs:(%eax)
0x00419691:	movl %fs:(%eax), %esp
0x00419694:	movl %eax, -4(%ebp)
0x00419697:	cmpb 0x20(%eax), $0x1<UINT8>
0x0041969b:	je 16
0x0041969d:	movl %eax, -4(%ebp)
0x004196a0:	movl %eax, 0x4(%eax)
0x004196a3:	movl %edx, %ebx
0x004196a5:	call 0x00419024
0x00419024:	pushl %ebx
0x00419025:	xorl %ecx, %ecx
0x00419027:	jmp 0x0041902a
0x0041902a:	cmpl %ecx, 0x8(%eax)
0x0041902d:	jnl 0x00419037
0x00419037:	cmpl %ecx, 0x8(%eax)
0x0041903a:	jne 3
0x0041903c:	orl %ecx, $0xffffffff<UINT8>
0x0041903f:	movl %eax, %ecx
0x00419041:	popl %ebx
0x00419042:	ret

0x004196aa:	incl %eax
0x004196ab:	jne 15
0x004196ad:	movl %eax, -4(%ebp)
0x004196b0:	movl %eax, 0x4(%eax)
0x004196b3:	movl %edx, %ebx
0x004196b5:	call 0x00418e6c
0x004196ba:	jmp 0x004196da
0x004196da:	xorl %eax, %eax
0x004196dc:	popl %edx
0x004196dd:	popl %ecx
0x004196de:	popl %ecx
0x004196df:	movl %fs:(%eax), %edx
0x004196e2:	pushl $0x4196f7<UINT32>
0x004196e7:	movl %eax, -4(%ebp)
0x004196ea:	call 0x00419760
0x00419760:	addl %eax, $0x8<UINT8>
0x00419763:	pushl %eax
0x00419764:	call 0x0040676c
0x0040676c:	jmp LeaveCriticalSection@KERNEL32.DLL
LeaveCriticalSection@KERNEL32.DLL: API Node	
0x00419769:	ret

0x004196ef:	ret

0x004196f7:	popl %ebx
0x004196f8:	popl %ecx
0x004196f9:	popl %ebp
0x004196fa:	ret

0x004187ad:	popl %edi
0x004187ae:	popl %esi
0x004187af:	popl %ebx
0x004187b0:	ret

0x0042c1de:	movl %ecx, $0x42489c<UINT32>
0x0042c1e3:	movl %edx, $0x4248ac<UINT32>
0x0042c1e8:	movl %eax, 0x422f04
0x0042c1ed:	call 0x00418788
0x004196f0:	jmp 0x00403c28
Unknown Node: Unknown Node	
