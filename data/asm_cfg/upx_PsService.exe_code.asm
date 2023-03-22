0x00431cc0:	pusha
0x00431cc1:	movl %esi, $0x421000<UINT32>
0x00431cc6:	leal %edi, -131072(%esi)
0x00431ccc:	pushl %edi
0x00431ccd:	jmp 0x00431cda
0x00431cda:	movl %ebx, (%esi)
0x00431cdc:	subl %esi, $0xfffffffc<UINT8>
0x00431cdf:	adcl %ebx, %ebx
0x00431ce1:	jb 0x00431cd0
0x00431cd0:	movb %al, (%esi)
0x00431cd2:	incl %esi
0x00431cd3:	movb (%edi), %al
0x00431cd5:	incl %edi
0x00431cd6:	addl %ebx, %ebx
0x00431cd8:	jne 0x00431ce1
0x00431ce3:	movl %eax, $0x1<UINT32>
0x00431ce8:	addl %ebx, %ebx
0x00431cea:	jne 0x00431cf3
0x00431cf3:	adcl %eax, %eax
0x00431cf5:	addl %ebx, %ebx
0x00431cf7:	jae 0x00431ce8
0x00431cf9:	jne 0x00431d04
0x00431d04:	xorl %ecx, %ecx
0x00431d06:	subl %eax, $0x3<UINT8>
0x00431d09:	jb 0x00431d18
0x00431d0b:	shll %eax, $0x8<UINT8>
0x00431d0e:	movb %al, (%esi)
0x00431d10:	incl %esi
0x00431d11:	xorl %eax, $0xffffffff<UINT8>
0x00431d14:	je 0x00431d8a
0x00431d16:	movl %ebp, %eax
0x00431d18:	addl %ebx, %ebx
0x00431d1a:	jne 0x00431d23
0x00431d23:	adcl %ecx, %ecx
0x00431d25:	addl %ebx, %ebx
0x00431d27:	jne 0x00431d30
0x00431d30:	adcl %ecx, %ecx
0x00431d32:	jne 0x00431d54
0x00431d54:	cmpl %ebp, $0xfffff300<UINT32>
0x00431d5a:	adcl %ecx, $0x1<UINT8>
0x00431d5d:	leal %edx, (%edi,%ebp)
0x00431d60:	cmpl %ebp, $0xfffffffc<UINT8>
0x00431d63:	jbe 0x00431d74
0x00431d74:	movl %eax, (%edx)
0x00431d76:	addl %edx, $0x4<UINT8>
0x00431d79:	movl (%edi), %eax
0x00431d7b:	addl %edi, $0x4<UINT8>
0x00431d7e:	subl %ecx, $0x4<UINT8>
0x00431d81:	ja 0x00431d74
0x00431d83:	addl %edi, %ecx
0x00431d85:	jmp 0x00431cd6
0x00431d65:	movb %al, (%edx)
0x00431d67:	incl %edx
0x00431d68:	movb (%edi), %al
0x00431d6a:	incl %edi
0x00431d6b:	decl %ecx
0x00431d6c:	jne 0x00431d65
0x00431d6e:	jmp 0x00431cd6
0x00431d34:	incl %ecx
0x00431d35:	addl %ebx, %ebx
0x00431d37:	jne 0x00431d40
0x00431d40:	adcl %ecx, %ecx
0x00431d42:	addl %ebx, %ebx
0x00431d44:	jae 0x00431d35
0x00431d46:	jne 0x00431d51
0x00431d51:	addl %ecx, $0x2<UINT8>
0x00431cfb:	movl %ebx, (%esi)
0x00431cfd:	subl %esi, $0xfffffffc<UINT8>
0x00431d00:	adcl %ebx, %ebx
0x00431d02:	jae 0x00431ce8
0x00431cec:	movl %ebx, (%esi)
0x00431cee:	subl %esi, $0xfffffffc<UINT8>
0x00431cf1:	adcl %ebx, %ebx
0x00431d39:	movl %ebx, (%esi)
0x00431d3b:	subl %esi, $0xfffffffc<UINT8>
0x00431d3e:	adcl %ebx, %ebx
0x00431d29:	movl %ebx, (%esi)
0x00431d2b:	subl %esi, $0xfffffffc<UINT8>
0x00431d2e:	adcl %ebx, %ebx
0x00431d1c:	movl %ebx, (%esi)
0x00431d1e:	subl %esi, $0xfffffffc<UINT8>
0x00431d21:	adcl %ebx, %ebx
0x00431d48:	movl %ebx, (%esi)
0x00431d4a:	subl %esi, $0xfffffffc<UINT8>
0x00431d4d:	adcl %ebx, %ebx
0x00431d4f:	jae 0x00431d35
0x00431d8a:	popl %esi
0x00431d8b:	movl %edi, %esi
0x00431d8d:	movl %ecx, $0x941<UINT32>
0x00431d92:	movb %al, (%edi)
0x00431d94:	incl %edi
0x00431d95:	subb %al, $0xffffffe8<UINT8>
0x00431d97:	cmpb %al, $0x1<UINT8>
0x00431d99:	ja 0x00431d92
0x00431d9b:	cmpb (%edi), $0xc<UINT8>
0x00431d9e:	jne 0x00431d92
0x00431da0:	movl %eax, (%edi)
0x00431da2:	movb %bl, 0x4(%edi)
0x00431da5:	shrw %ax, $0x8<UINT8>
0x00431da9:	roll %eax, $0x10<UINT8>
0x00431dac:	xchgb %ah, %al
0x00431dae:	subl %eax, %edi
0x00431db0:	subb %bl, $0xffffffe8<UINT8>
0x00431db3:	addl %eax, %esi
0x00431db5:	movl (%edi), %eax
0x00431db7:	addl %edi, $0x5<UINT8>
0x00431dba:	movb %al, %bl
0x00431dbc:	loop 0x00431d97
0x00431dbe:	leal %edi, 0x2f000(%esi)
0x00431dc4:	movl %eax, (%edi)
0x00431dc6:	orl %eax, %eax
0x00431dc8:	je 0x00431e06
0x00431dca:	movl %ebx, 0x4(%edi)
0x00431dcd:	leal %eax, 0x3158c(%eax,%esi)
0x00431dd4:	addl %ebx, %esi
0x00431dd6:	pushl %eax
0x00431dd7:	addl %edi, $0x8<UINT8>
0x00431dda:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x00431de0:	xchgl %ebp, %eax
0x00431de1:	movb %al, (%edi)
0x00431de3:	incl %edi
0x00431de4:	orb %al, %al
0x00431de6:	je 0x00431dc4
0x00431de8:	movl %ecx, %edi
0x00431dea:	pushl %edi
0x00431deb:	decl %eax
0x00431dec:	repn scasb %al, %es:(%edi)
0x00431dee:	pushl %ebp
0x00431def:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00431df5:	orl %eax, %eax
0x00431df7:	je 7
0x00431df9:	movl (%ebx), %eax
0x00431dfb:	addl %ebx, $0x4<UINT8>
0x00431dfe:	jmp 0x00431de1
GetProcAddress@KERNEL32.DLL: API Node	
0x00431e06:	movl %ebp, 0x31634(%esi)
0x00431e0c:	leal %edi, -4096(%esi)
0x00431e12:	movl %ebx, $0x1000<UINT32>
0x00431e17:	pushl %eax
0x00431e18:	pushl %esp
0x00431e19:	pushl $0x4<UINT8>
0x00431e1b:	pushl %ebx
0x00431e1c:	pushl %edi
0x00431e1d:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00431e1f:	leal %eax, 0x20f(%edi)
0x00431e25:	andb (%eax), $0x7f<UINT8>
0x00431e28:	andb 0x28(%eax), $0x7f<UINT8>
0x00431e2c:	popl %eax
0x00431e2d:	pushl %eax
0x00431e2e:	pushl %esp
0x00431e2f:	pushl %eax
0x00431e30:	pushl %ebx
0x00431e31:	pushl %edi
0x00431e32:	call VirtualProtect@kernel32.dll
0x00431e34:	popl %eax
0x00431e35:	popa
0x00431e36:	leal %eax, -128(%esp)
0x00431e3a:	pushl $0x0<UINT8>
0x00431e3c:	cmpl %esp, %eax
0x00431e3e:	jne 0x00431e3a
0x00431e40:	subl %esp, $0xffffff80<UINT8>
0x00431e43:	jmp 0x00407f52
0x00407f52:	call 0x0040ee6d
0x0040ee6d:	pushl %ebp
0x0040ee6e:	movl %ebp, %esp
0x0040ee70:	subl %esp, $0x14<UINT8>
0x0040ee73:	andl -12(%ebp), $0x0<UINT8>
0x0040ee77:	andl -8(%ebp), $0x0<UINT8>
0x0040ee7b:	movl %eax, 0x42a8e0
0x0040ee80:	pushl %esi
0x0040ee81:	pushl %edi
0x0040ee82:	movl %edi, $0xbb40e64e<UINT32>
0x0040ee87:	movl %esi, $0xffff0000<UINT32>
0x0040ee8c:	cmpl %eax, %edi
0x0040ee8e:	je 0x0040ee9d
0x0040ee9d:	leal %eax, -12(%ebp)
0x0040eea0:	pushl %eax
0x0040eea1:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040eea7:	movl %eax, -8(%ebp)
0x0040eeaa:	xorl %eax, -12(%ebp)
0x0040eead:	movl -4(%ebp), %eax
0x0040eeb0:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040eeb6:	xorl -4(%ebp), %eax
0x0040eeb9:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040eebf:	xorl -4(%ebp), %eax
0x0040eec2:	leal %eax, -20(%ebp)
0x0040eec5:	pushl %eax
0x0040eec6:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040eecc:	movl %ecx, -16(%ebp)
0x0040eecf:	leal %eax, -4(%ebp)
0x0040eed2:	xorl %ecx, -20(%ebp)
0x0040eed5:	xorl %ecx, -4(%ebp)
0x0040eed8:	xorl %ecx, %eax
0x0040eeda:	cmpl %ecx, %edi
0x0040eedc:	jne 0x0040eee5
0x0040eee5:	testl %esi, %ecx
0x0040eee7:	jne 0x0040eef5
0x0040eef5:	movl 0x42a8e0, %ecx
0x0040eefb:	notl %ecx
0x0040eefd:	movl 0x42a8e4, %ecx
0x0040ef03:	popl %edi
0x0040ef04:	popl %esi
0x0040ef05:	movl %esp, %ebp
0x0040ef07:	popl %ebp
0x0040ef08:	ret

0x00407f57:	jmp 0x00407dd7
0x00407dd7:	pushl $0x14<UINT8>
0x00407dd9:	pushl $0x4285b8<UINT32>
0x00407dde:	call 0x0040adf0
0x0040adf0:	pushl $0x407640<UINT32>
0x0040adf5:	pushl %fs:0
0x0040adfc:	movl %eax, 0x10(%esp)
0x0040ae00:	movl 0x10(%esp), %ebp
0x0040ae04:	leal %ebp, 0x10(%esp)
0x0040ae08:	subl %esp, %eax
0x0040ae0a:	pushl %ebx
0x0040ae0b:	pushl %esi
0x0040ae0c:	pushl %edi
0x0040ae0d:	movl %eax, 0x42a8e0
0x0040ae12:	xorl -4(%ebp), %eax
0x0040ae15:	xorl %eax, %ebp
0x0040ae17:	pushl %eax
0x0040ae18:	movl -24(%ebp), %esp
0x0040ae1b:	pushl -8(%ebp)
0x0040ae1e:	movl %eax, -4(%ebp)
0x0040ae21:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040ae28:	movl -8(%ebp), %eax
0x0040ae2b:	leal %eax, -16(%ebp)
0x0040ae2e:	movl %fs:0, %eax
0x0040ae34:	ret

0x00407de3:	pushl $0x1<UINT8>
0x00407de5:	call 0x0040ee20
0x0040ee20:	pushl %ebp
0x0040ee21:	movl %ebp, %esp
0x0040ee23:	movl %eax, 0x8(%ebp)
0x0040ee26:	movl 0x42c230, %eax
0x0040ee2b:	popl %ebp
0x0040ee2c:	ret

0x00407dea:	popl %ecx
0x00407deb:	movl %eax, $0x5a4d<UINT32>
0x00407df0:	cmpw 0x400000, %ax
0x00407df7:	je 0x00407dfd
0x00407dfd:	movl %eax, 0x40003c
0x00407e02:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00407e0c:	jne -21
0x00407e0e:	movl %ecx, $0x10b<UINT32>
0x00407e13:	cmpw 0x400018(%eax), %cx
0x00407e1a:	jne -35
0x00407e1c:	xorl %ebx, %ebx
0x00407e1e:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00407e25:	jbe 9
0x00407e27:	cmpl 0x4000e8(%eax), %ebx
0x00407e2d:	setne %bl
0x00407e30:	movl -28(%ebp), %ebx
0x00407e33:	call 0x0040af20
0x0040af20:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x0040af26:	xorl %ecx, %ecx
0x0040af28:	movl 0x42c890, %eax
0x0040af2d:	testl %eax, %eax
0x0040af2f:	setne %cl
0x0040af32:	movl %eax, %ecx
0x0040af34:	ret

0x00407e38:	testl %eax, %eax
0x00407e3a:	jne 0x00407e44
0x00407e44:	call 0x00408e5e
0x00408e5e:	call 0x00405cee
0x00405cee:	pushl %esi
0x00405cef:	pushl $0x0<UINT8>
0x00405cf1:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00405cf7:	movl %esi, %eax
0x00405cf9:	pushl %esi
0x00405cfa:	call 0x0040a9c4
0x0040a9c4:	pushl %ebp
0x0040a9c5:	movl %ebp, %esp
0x0040a9c7:	movl %eax, 0x8(%ebp)
0x0040a9ca:	movl 0x42c868, %eax
0x0040a9cf:	popl %ebp
0x0040a9d0:	ret

0x00405cff:	pushl %esi
0x00405d00:	call 0x00408081
0x00408081:	pushl %ebp
0x00408082:	movl %ebp, %esp
0x00408084:	movl %eax, 0x8(%ebp)
0x00408087:	movl 0x42c0b8, %eax
0x0040808c:	popl %ebp
0x0040808d:	ret

0x00405d05:	pushl %esi
0x00405d06:	call 0x0040abaa
0x0040abaa:	pushl %ebp
0x0040abab:	movl %ebp, %esp
0x0040abad:	movl %eax, 0x8(%ebp)
0x0040abb0:	movl 0x42c86c, %eax
0x0040abb5:	popl %ebp
0x0040abb6:	ret

0x00405d0b:	pushl %esi
0x00405d0c:	call 0x0040abc4
0x0040abc4:	pushl %ebp
0x0040abc5:	movl %ebp, %esp
0x0040abc7:	movl %eax, 0x8(%ebp)
0x0040abca:	movl 0x42c870, %eax
0x0040abcf:	movl 0x42c874, %eax
0x0040abd4:	movl 0x42c878, %eax
0x0040abd9:	movl 0x42c87c, %eax
0x0040abde:	popl %ebp
0x0040abdf:	ret

0x00405d11:	pushl %esi
0x00405d12:	call 0x0040a98d
0x0040a98d:	pushl $0x40a959<UINT32>
0x0040a992:	call EncodePointer@KERNEL32.DLL
0x0040a998:	movl 0x42c864, %eax
0x0040a99d:	ret

0x00405d17:	pushl %esi
0x00405d18:	call 0x0040add5
0x0040add5:	pushl %ebp
0x0040add6:	movl %ebp, %esp
0x0040add8:	movl %eax, 0x8(%ebp)
0x0040addb:	movl 0x42c884, %eax
0x0040ade0:	popl %ebp
0x0040ade1:	ret

0x00405d1d:	addl %esp, $0x18<UINT8>
0x00405d20:	popl %esi
0x00405d21:	jmp 0x0040a0f3
0x0040a0f3:	pushl %esi
0x0040a0f4:	pushl %edi
0x0040a0f5:	pushl $0x423db8<UINT32>
0x0040a0fa:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0040a100:	movl %esi, 0x41a0cc
0x0040a106:	movl %edi, %eax
0x0040a108:	pushl $0x423dd4<UINT32>
0x0040a10d:	pushl %edi
0x0040a10e:	call GetProcAddress@KERNEL32.DLL
0x0040a110:	xorl %eax, 0x42a8e0
0x0040a116:	pushl $0x423de0<UINT32>
0x0040a11b:	pushl %edi
0x0040a11c:	movl 0x42d260, %eax
0x0040a121:	call GetProcAddress@KERNEL32.DLL
0x0040a123:	xorl %eax, 0x42a8e0
0x0040a129:	pushl $0x423de8<UINT32>
0x0040a12e:	pushl %edi
0x0040a12f:	movl 0x42d264, %eax
0x0040a134:	call GetProcAddress@KERNEL32.DLL
0x0040a136:	xorl %eax, 0x42a8e0
0x0040a13c:	pushl $0x423df4<UINT32>
0x0040a141:	pushl %edi
0x0040a142:	movl 0x42d268, %eax
0x0040a147:	call GetProcAddress@KERNEL32.DLL
0x0040a149:	xorl %eax, 0x42a8e0
0x0040a14f:	pushl $0x423e00<UINT32>
0x0040a154:	pushl %edi
0x0040a155:	movl 0x42d26c, %eax
0x0040a15a:	call GetProcAddress@KERNEL32.DLL
0x0040a15c:	xorl %eax, 0x42a8e0
0x0040a162:	pushl $0x423e1c<UINT32>
0x0040a167:	pushl %edi
0x0040a168:	movl 0x42d270, %eax
0x0040a16d:	call GetProcAddress@KERNEL32.DLL
0x0040a16f:	xorl %eax, 0x42a8e0
0x0040a175:	pushl $0x423e2c<UINT32>
0x0040a17a:	pushl %edi
0x0040a17b:	movl 0x42d274, %eax
0x0040a180:	call GetProcAddress@KERNEL32.DLL
0x0040a182:	xorl %eax, 0x42a8e0
0x0040a188:	pushl $0x423e40<UINT32>
0x0040a18d:	pushl %edi
0x0040a18e:	movl 0x42d278, %eax
0x0040a193:	call GetProcAddress@KERNEL32.DLL
0x0040a195:	xorl %eax, 0x42a8e0
0x0040a19b:	pushl $0x423e58<UINT32>
0x0040a1a0:	pushl %edi
0x0040a1a1:	movl 0x42d27c, %eax
0x0040a1a6:	call GetProcAddress@KERNEL32.DLL
0x0040a1a8:	xorl %eax, 0x42a8e0
0x0040a1ae:	pushl $0x423e70<UINT32>
0x0040a1b3:	pushl %edi
0x0040a1b4:	movl 0x42d280, %eax
0x0040a1b9:	call GetProcAddress@KERNEL32.DLL
0x0040a1bb:	xorl %eax, 0x42a8e0
0x0040a1c1:	pushl $0x423e84<UINT32>
0x0040a1c6:	pushl %edi
0x0040a1c7:	movl 0x42d284, %eax
0x0040a1cc:	call GetProcAddress@KERNEL32.DLL
0x0040a1ce:	xorl %eax, 0x42a8e0
0x0040a1d4:	pushl $0x423ea4<UINT32>
0x0040a1d9:	pushl %edi
0x0040a1da:	movl 0x42d288, %eax
0x0040a1df:	call GetProcAddress@KERNEL32.DLL
0x0040a1e1:	xorl %eax, 0x42a8e0
0x0040a1e7:	pushl $0x423ebc<UINT32>
0x0040a1ec:	pushl %edi
0x0040a1ed:	movl 0x42d28c, %eax
0x0040a1f2:	call GetProcAddress@KERNEL32.DLL
0x0040a1f4:	xorl %eax, 0x42a8e0
0x0040a1fa:	pushl $0x423ed4<UINT32>
0x0040a1ff:	pushl %edi
0x0040a200:	movl 0x42d290, %eax
0x0040a205:	call GetProcAddress@KERNEL32.DLL
0x0040a207:	xorl %eax, 0x42a8e0
0x0040a20d:	pushl $0x423ee8<UINT32>
0x0040a212:	pushl %edi
0x0040a213:	movl 0x42d294, %eax
0x0040a218:	call GetProcAddress@KERNEL32.DLL
0x0040a21a:	xorl %eax, 0x42a8e0
0x0040a220:	movl 0x42d298, %eax
0x0040a225:	pushl $0x423efc<UINT32>
0x0040a22a:	pushl %edi
0x0040a22b:	call GetProcAddress@KERNEL32.DLL
0x0040a22d:	xorl %eax, 0x42a8e0
0x0040a233:	pushl $0x423f18<UINT32>
0x0040a238:	pushl %edi
0x0040a239:	movl 0x42d29c, %eax
0x0040a23e:	call GetProcAddress@KERNEL32.DLL
0x0040a240:	xorl %eax, 0x42a8e0
0x0040a246:	pushl $0x423f38<UINT32>
0x0040a24b:	pushl %edi
0x0040a24c:	movl 0x42d2a0, %eax
0x0040a251:	call GetProcAddress@KERNEL32.DLL
0x0040a253:	xorl %eax, 0x42a8e0
0x0040a259:	pushl $0x423f54<UINT32>
0x0040a25e:	pushl %edi
0x0040a25f:	movl 0x42d2a4, %eax
0x0040a264:	call GetProcAddress@KERNEL32.DLL
0x0040a266:	xorl %eax, 0x42a8e0
0x0040a26c:	pushl $0x423f74<UINT32>
0x0040a271:	pushl %edi
0x0040a272:	movl 0x42d2a8, %eax
0x0040a277:	call GetProcAddress@KERNEL32.DLL
0x0040a279:	xorl %eax, 0x42a8e0
0x0040a27f:	pushl $0x423f88<UINT32>
0x0040a284:	pushl %edi
0x0040a285:	movl 0x42d2ac, %eax
0x0040a28a:	call GetProcAddress@KERNEL32.DLL
0x0040a28c:	xorl %eax, 0x42a8e0
0x0040a292:	pushl $0x423fa4<UINT32>
0x0040a297:	pushl %edi
0x0040a298:	movl 0x42d2b0, %eax
0x0040a29d:	call GetProcAddress@KERNEL32.DLL
0x0040a29f:	xorl %eax, 0x42a8e0
0x0040a2a5:	pushl $0x423fb8<UINT32>
0x0040a2aa:	pushl %edi
0x0040a2ab:	movl 0x42d2b8, %eax
0x0040a2b0:	call GetProcAddress@KERNEL32.DLL
0x0040a2b2:	xorl %eax, 0x42a8e0
0x0040a2b8:	pushl $0x423fc8<UINT32>
0x0040a2bd:	pushl %edi
0x0040a2be:	movl 0x42d2b4, %eax
0x0040a2c3:	call GetProcAddress@KERNEL32.DLL
0x0040a2c5:	xorl %eax, 0x42a8e0
0x0040a2cb:	pushl $0x423fd8<UINT32>
0x0040a2d0:	pushl %edi
0x0040a2d1:	movl 0x42d2bc, %eax
0x0040a2d6:	call GetProcAddress@KERNEL32.DLL
0x0040a2d8:	xorl %eax, 0x42a8e0
0x0040a2de:	pushl $0x423fe8<UINT32>
0x0040a2e3:	pushl %edi
0x0040a2e4:	movl 0x42d2c0, %eax
0x0040a2e9:	call GetProcAddress@KERNEL32.DLL
0x0040a2eb:	xorl %eax, 0x42a8e0
0x0040a2f1:	pushl $0x423ff8<UINT32>
0x0040a2f6:	pushl %edi
0x0040a2f7:	movl 0x42d2c4, %eax
0x0040a2fc:	call GetProcAddress@KERNEL32.DLL
0x0040a2fe:	xorl %eax, 0x42a8e0
0x0040a304:	pushl $0x424014<UINT32>
0x0040a309:	pushl %edi
0x0040a30a:	movl 0x42d2c8, %eax
0x0040a30f:	call GetProcAddress@KERNEL32.DLL
0x0040a311:	xorl %eax, 0x42a8e0
0x0040a317:	pushl $0x424028<UINT32>
0x0040a31c:	pushl %edi
0x0040a31d:	movl 0x42d2cc, %eax
0x0040a322:	call GetProcAddress@KERNEL32.DLL
0x0040a324:	xorl %eax, 0x42a8e0
0x0040a32a:	pushl $0x424038<UINT32>
0x0040a32f:	pushl %edi
0x0040a330:	movl 0x42d2d0, %eax
0x0040a335:	call GetProcAddress@KERNEL32.DLL
0x0040a337:	xorl %eax, 0x42a8e0
0x0040a33d:	pushl $0x42404c<UINT32>
0x0040a342:	pushl %edi
0x0040a343:	movl 0x42d2d4, %eax
0x0040a348:	call GetProcAddress@KERNEL32.DLL
0x0040a34a:	xorl %eax, 0x42a8e0
0x0040a350:	movl 0x42d2d8, %eax
0x0040a355:	pushl $0x42405c<UINT32>
0x0040a35a:	pushl %edi
0x0040a35b:	call GetProcAddress@KERNEL32.DLL
0x0040a35d:	xorl %eax, 0x42a8e0
0x0040a363:	pushl $0x42407c<UINT32>
0x0040a368:	pushl %edi
0x0040a369:	movl 0x42d2dc, %eax
0x0040a36e:	call GetProcAddress@KERNEL32.DLL
0x0040a370:	xorl %eax, 0x42a8e0
0x0040a376:	popl %edi
0x0040a377:	movl 0x42d2e0, %eax
0x0040a37c:	popl %esi
0x0040a37d:	ret

0x00408e63:	call 0x00409fb9
0x00409fb9:	pushl %esi
0x00409fba:	pushl %edi
0x00409fbb:	movl %esi, $0x42b438<UINT32>
0x00409fc0:	movl %edi, $0x42c0e0<UINT32>
0x00409fc5:	cmpl 0x4(%esi), $0x1<UINT8>
0x00409fc9:	jne 22
0x00409fcb:	pushl $0x0<UINT8>
0x00409fcd:	movl (%esi), %edi
0x00409fcf:	addl %edi, $0x18<UINT8>
0x00409fd2:	pushl $0xfa0<UINT32>
0x00409fd7:	pushl (%esi)
0x00409fd9:	call 0x0040a085
0x0040a085:	pushl %ebp
0x0040a086:	movl %ebp, %esp
0x0040a088:	movl %eax, 0x42d270
0x0040a08d:	xorl %eax, 0x42a8e0
0x0040a093:	je 13
0x0040a095:	pushl 0x10(%ebp)
0x0040a098:	pushl 0xc(%ebp)
0x0040a09b:	pushl 0x8(%ebp)
0x0040a09e:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x0040a0a0:	popl %ebp
0x0040a0a1:	ret

0x00000fa0:	addb (%eax), %al
0x00000fa2:	addb (%eax), %al
0x00000fa4:	addb (%eax), %al
0x00000fa6:	addb (%eax), %al
0x00000fa8:	addb (%eax), %al
0x00000faa:	addb (%eax), %al
0x00000fac:	addb (%eax), %al
0x00000fae:	addb (%eax), %al
0x00000fb0:	addb (%eax), %al
0x00000fb2:	addb (%eax), %al
0x00000fb4:	addb (%eax), %al
0x00000fb6:	addb (%eax), %al
0x00000fb8:	addb (%eax), %al
0x00000fba:	addb (%eax), %al
0x00000fbc:	addb (%eax), %al
0x00000fbe:	addb (%eax), %al
0x00000fc0:	addb (%eax), %al
0x00000fc2:	addb (%eax), %al
0x00000fc4:	addb (%eax), %al
0x00000fc6:	addb (%eax), %al
0x00000fc8:	addb (%eax), %al
0x00000fca:	addb (%eax), %al
0x00000fcc:	addb (%eax), %al
0x00000fce:	addb (%eax), %al
0x00000fd0:	addb (%eax), %al
0x00000fd2:	addb (%eax), %al
0x00000fd4:	addb (%eax), %al
0x00000fd6:	addb (%eax), %al
0x00000fd8:	addb (%eax), %al
0x00000fda:	addb (%eax), %al
0x00000fdc:	addb (%eax), %al
0x00000fde:	addb (%eax), %al
0x00000fe0:	addb (%eax), %al
0x00000fe2:	addb (%eax), %al
0x00000fe4:	addb (%eax), %al
0x00000fe6:	addb (%eax), %al
0x00000fe8:	addb (%eax), %al
0x00000fea:	addb (%eax), %al
0x00000fec:	addb (%eax), %al
0x00000fee:	addb (%eax), %al
0x00000ff0:	addb (%eax), %al
0x00000ff2:	addb (%eax), %al
0x00000ff4:	addb (%eax), %al
0x00000ff6:	addb (%eax), %al
0x00000ff8:	addb (%eax), %al
0x00000ffa:	addb (%eax), %al
0x00000ffc:	addb (%eax), %al
0x00000ffe:	addb (%eax), %al
0x00001000:	addb (%eax), %al
0x00001002:	addb (%eax), %al
0x00001004:	addb (%eax), %al
0x00001006:	addb (%eax), %al
