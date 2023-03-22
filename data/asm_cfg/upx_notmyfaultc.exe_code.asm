0x00441f20:	pusha
0x00441f21:	movl %esi, $0x430000<UINT32>
0x00441f26:	leal %edi, -192512(%esi)
0x00441f2c:	pushl %edi
0x00441f2d:	jmp 0x00441f3a
0x00441f3a:	movl %ebx, (%esi)
0x00441f3c:	subl %esi, $0xfffffffc<UINT8>
0x00441f3f:	adcl %ebx, %ebx
0x00441f41:	jb 0x00441f30
0x00441f30:	movb %al, (%esi)
0x00441f32:	incl %esi
0x00441f33:	movb (%edi), %al
0x00441f35:	incl %edi
0x00441f36:	addl %ebx, %ebx
0x00441f38:	jne 0x00441f41
0x00441f43:	movl %eax, $0x1<UINT32>
0x00441f48:	addl %ebx, %ebx
0x00441f4a:	jne 0x00441f53
0x00441f53:	adcl %eax, %eax
0x00441f55:	addl %ebx, %ebx
0x00441f57:	jae 0x00441f48
0x00441f59:	jne 0x00441f64
0x00441f64:	xorl %ecx, %ecx
0x00441f66:	subl %eax, $0x3<UINT8>
0x00441f69:	jb 0x00441f78
0x00441f6b:	shll %eax, $0x8<UINT8>
0x00441f6e:	movb %al, (%esi)
0x00441f70:	incl %esi
0x00441f71:	xorl %eax, $0xffffffff<UINT8>
0x00441f74:	je 0x00441fea
0x00441f76:	movl %ebp, %eax
0x00441f78:	addl %ebx, %ebx
0x00441f7a:	jne 0x00441f83
0x00441f83:	adcl %ecx, %ecx
0x00441f85:	addl %ebx, %ebx
0x00441f87:	jne 0x00441f90
0x00441f89:	movl %ebx, (%esi)
0x00441f8b:	subl %esi, $0xfffffffc<UINT8>
0x00441f8e:	adcl %ebx, %ebx
0x00441f90:	adcl %ecx, %ecx
0x00441f92:	jne 0x00441fb4
0x00441fb4:	cmpl %ebp, $0xfffff300<UINT32>
0x00441fba:	adcl %ecx, $0x1<UINT8>
0x00441fbd:	leal %edx, (%edi,%ebp)
0x00441fc0:	cmpl %ebp, $0xfffffffc<UINT8>
0x00441fc3:	jbe 0x00441fd4
0x00441fd4:	movl %eax, (%edx)
0x00441fd6:	addl %edx, $0x4<UINT8>
0x00441fd9:	movl (%edi), %eax
0x00441fdb:	addl %edi, $0x4<UINT8>
0x00441fde:	subl %ecx, $0x4<UINT8>
0x00441fe1:	ja 0x00441fd4
0x00441fe3:	addl %edi, %ecx
0x00441fe5:	jmp 0x00441f36
0x00441f94:	incl %ecx
0x00441f95:	addl %ebx, %ebx
0x00441f97:	jne 0x00441fa0
0x00441f99:	movl %ebx, (%esi)
0x00441f9b:	subl %esi, $0xfffffffc<UINT8>
0x00441f9e:	adcl %ebx, %ebx
0x00441fa0:	adcl %ecx, %ecx
0x00441fa2:	addl %ebx, %ebx
0x00441fa4:	jae 0x00441f95
0x00441fa6:	jne 0x00441fb1
0x00441fb1:	addl %ecx, $0x2<UINT8>
0x00441fc5:	movb %al, (%edx)
0x00441fc7:	incl %edx
0x00441fc8:	movb (%edi), %al
0x00441fca:	incl %edi
0x00441fcb:	decl %ecx
0x00441fcc:	jne 0x00441fc5
0x00441fce:	jmp 0x00441f36
0x00441f4c:	movl %ebx, (%esi)
0x00441f4e:	subl %esi, $0xfffffffc<UINT8>
0x00441f51:	adcl %ebx, %ebx
0x00441fa8:	movl %ebx, (%esi)
0x00441faa:	subl %esi, $0xfffffffc<UINT8>
0x00441fad:	adcl %ebx, %ebx
0x00441faf:	jae 0x00441f95
0x00441f7c:	movl %ebx, (%esi)
0x00441f7e:	subl %esi, $0xfffffffc<UINT8>
0x00441f81:	adcl %ebx, %ebx
0x00441f5b:	movl %ebx, (%esi)
0x00441f5d:	subl %esi, $0xfffffffc<UINT8>
0x00441f60:	adcl %ebx, %ebx
0x00441f62:	jae 0x00441f48
0x00441fea:	popl %esi
0x00441feb:	movl %edi, %esi
0x00441fed:	movl %ecx, $0x71e<UINT32>
0x00441ff2:	movb %al, (%edi)
0x00441ff4:	incl %edi
0x00441ff5:	subb %al, $0xffffffe8<UINT8>
0x00441ff7:	cmpb %al, $0x1<UINT8>
0x00441ff9:	ja 0x00441ff2
0x00441ffb:	cmpb (%edi), $0x5<UINT8>
0x00441ffe:	jne 0x00441ff2
0x00442000:	movl %eax, (%edi)
0x00442002:	movb %bl, 0x4(%edi)
0x00442005:	shrw %ax, $0x8<UINT8>
0x00442009:	roll %eax, $0x10<UINT8>
0x0044200c:	xchgb %ah, %al
0x0044200e:	subl %eax, %edi
0x00442010:	subb %bl, $0xffffffe8<UINT8>
0x00442013:	addl %eax, %esi
0x00442015:	movl (%edi), %eax
0x00442017:	addl %edi, $0x5<UINT8>
0x0044201a:	movb %al, %bl
0x0044201c:	loop 0x00441ff7
0x0044201e:	leal %edi, 0x3e000(%esi)
0x00442024:	movl %eax, (%edi)
0x00442026:	orl %eax, %eax
0x00442028:	je 0x00442066
0x0044202a:	movl %ebx, 0x4(%edi)
0x0044202d:	leal %eax, 0x523e8(%eax,%esi)
0x00442034:	addl %ebx, %esi
0x00442036:	pushl %eax
0x00442037:	addl %edi, $0x8<UINT8>
0x0044203a:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00442040:	xchgl %ebp, %eax
0x00442041:	movb %al, (%edi)
0x00442043:	incl %edi
0x00442044:	orb %al, %al
0x00442046:	je 0x00442024
0x00442048:	movl %ecx, %edi
0x0044204a:	pushl %edi
0x0044204b:	decl %eax
0x0044204c:	repn scasb %al, %es:(%edi)
0x0044204e:	pushl %ebp
0x0044204f:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00442055:	orl %eax, %eax
0x00442057:	je 7
0x00442059:	movl (%ebx), %eax
0x0044205b:	addl %ebx, $0x4<UINT8>
0x0044205e:	jmp 0x00442041
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x00442066:	addl %edi, $0x4<UINT8>
0x00442069:	leal %ebx, -4(%esi)
0x0044206c:	xorl %eax, %eax
0x0044206e:	movb %al, (%edi)
0x00442070:	incl %edi
0x00442071:	orl %eax, %eax
0x00442073:	je 0x00442097
0x00442075:	cmpb %al, $0xffffffef<UINT8>
0x00442077:	ja 0x0044208a
0x00442079:	addl %ebx, %eax
0x0044207b:	movl %eax, (%ebx)
0x0044207d:	xchgb %ah, %al
0x0044207f:	roll %eax, $0x10<UINT8>
0x00442082:	xchgb %ah, %al
0x00442084:	addl %eax, %esi
0x00442086:	movl (%ebx), %eax
0x00442088:	jmp 0x0044206c
0x0044208a:	andb %al, $0xf<UINT8>
0x0044208c:	shll %eax, $0x10<UINT8>
0x0044208f:	movw %ax, (%edi)
0x00442092:	addl %edi, $0x2<UINT8>
0x00442095:	jmp 0x00442079
0x00442097:	movl %ebp, 0x52498(%esi)
0x0044209d:	leal %edi, -4096(%esi)
0x004420a3:	movl %ebx, $0x1000<UINT32>
0x004420a8:	pushl %eax
0x004420a9:	pushl %esp
0x004420aa:	pushl $0x4<UINT8>
0x004420ac:	pushl %ebx
0x004420ad:	pushl %edi
0x004420ae:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x004420b0:	leal %eax, 0x21f(%edi)
0x004420b6:	andb (%eax), $0x7f<UINT8>
0x004420b9:	andb 0x28(%eax), $0x7f<UINT8>
0x004420bd:	popl %eax
0x004420be:	pushl %eax
0x004420bf:	pushl %esp
0x004420c0:	pushl %eax
0x004420c1:	pushl %ebx
0x004420c2:	pushl %edi
0x004420c3:	call VirtualProtect@kernel32.dll
0x004420c5:	popl %eax
0x004420c6:	popa
0x004420c7:	leal %eax, -128(%esp)
0x004420cb:	pushl $0x0<UINT8>
0x004420cd:	cmpl %esp, %eax
0x004420cf:	jne 0x004420cb
0x004420d1:	subl %esp, $0xffffff80<UINT8>
0x004420d4:	jmp 0x00405810
0x00405810:	call 0x0040be0e
0x0040be0e:	pushl %ebp
0x0040be0f:	movl %ebp, %esp
0x0040be11:	subl %esp, $0x14<UINT8>
0x0040be14:	andl -12(%ebp), $0x0<UINT8>
0x0040be18:	andl -8(%ebp), $0x0<UINT8>
0x0040be1c:	movl %eax, 0x421430
0x0040be21:	pushl %esi
0x0040be22:	pushl %edi
0x0040be23:	movl %edi, $0xbb40e64e<UINT32>
0x0040be28:	movl %esi, $0xffff0000<UINT32>
0x0040be2d:	cmpl %eax, %edi
0x0040be2f:	je 0x0040be3e
0x0040be3e:	leal %eax, -12(%ebp)
0x0040be41:	pushl %eax
0x0040be42:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040be48:	movl %eax, -8(%ebp)
0x0040be4b:	xorl %eax, -12(%ebp)
0x0040be4e:	movl -4(%ebp), %eax
0x0040be51:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040be57:	xorl -4(%ebp), %eax
0x0040be5a:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040be60:	xorl -4(%ebp), %eax
0x0040be63:	leal %eax, -20(%ebp)
0x0040be66:	pushl %eax
0x0040be67:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040be6d:	movl %ecx, -16(%ebp)
0x0040be70:	leal %eax, -4(%ebp)
0x0040be73:	xorl %ecx, -20(%ebp)
0x0040be76:	xorl %ecx, -4(%ebp)
0x0040be79:	xorl %ecx, %eax
0x0040be7b:	cmpl %ecx, %edi
0x0040be7d:	jne 0x0040be86
0x0040be86:	testl %esi, %ecx
0x0040be88:	jne 0x0040be96
0x0040be96:	movl 0x421430, %ecx
0x0040be9c:	notl %ecx
0x0040be9e:	movl 0x421434, %ecx
0x0040bea4:	popl %edi
0x0040bea5:	popl %esi
0x0040bea6:	movl %esp, %ebp
0x0040bea8:	popl %ebp
0x0040bea9:	ret

0x00405815:	jmp 0x00405695
0x00405695:	pushl $0x14<UINT8>
0x00405697:	pushl $0x41ff50<UINT32>
0x0040569c:	call 0x00406550
0x00406550:	pushl $0x4065b0<UINT32>
0x00406555:	pushl %fs:0
0x0040655c:	movl %eax, 0x10(%esp)
0x00406560:	movl 0x10(%esp), %ebp
0x00406564:	leal %ebp, 0x10(%esp)
0x00406568:	subl %esp, %eax
0x0040656a:	pushl %ebx
0x0040656b:	pushl %esi
0x0040656c:	pushl %edi
0x0040656d:	movl %eax, 0x421430
0x00406572:	xorl -4(%ebp), %eax
0x00406575:	xorl %eax, %ebp
0x00406577:	pushl %eax
0x00406578:	movl -24(%ebp), %esp
0x0040657b:	pushl -8(%ebp)
0x0040657e:	movl %eax, -4(%ebp)
0x00406581:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00406588:	movl -8(%ebp), %eax
0x0040658b:	leal %eax, -16(%ebp)
0x0040658e:	movl %fs:0, %eax
0x00406594:	ret

0x004056a1:	pushl $0x1<UINT8>
0x004056a3:	call 0x0040bdc1
0x0040bdc1:	pushl %ebp
0x0040bdc2:	movl %ebp, %esp
0x0040bdc4:	movl %eax, 0x8(%ebp)
0x0040bdc7:	movl 0x422630, %eax
0x0040bdcc:	popl %ebp
0x0040bdcd:	ret

0x004056a8:	popl %ecx
0x004056a9:	movl %eax, $0x5a4d<UINT32>
0x004056ae:	cmpw 0x400000, %ax
0x004056b5:	je 0x004056bb
0x004056bb:	movl %eax, 0x40003c
0x004056c0:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x004056ca:	jne -21
0x004056cc:	movl %ecx, $0x10b<UINT32>
0x004056d1:	cmpw 0x400018(%eax), %cx
0x004056d8:	jne -35
0x004056da:	xorl %ebx, %ebx
0x004056dc:	cmpl 0x400074(%eax), $0xe<UINT8>
0x004056e3:	jbe 9
0x004056e5:	cmpl 0x4000e8(%eax), %ebx
0x004056eb:	setne %bl
0x004056ee:	movl -28(%ebp), %ebx
0x004056f1:	call 0x004091fd
0x004091fd:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x00409203:	xorl %ecx, %ecx
0x00409205:	movl 0x422c68, %eax
0x0040920a:	testl %eax, %eax
0x0040920c:	setne %cl
0x0040920f:	movl %eax, %ecx
0x00409211:	ret

0x004056f6:	testl %eax, %eax
0x004056f8:	jne 0x00405702
0x00405702:	call 0x0040a222
0x0040a222:	call 0x004041fa
0x004041fa:	pushl %esi
0x004041fb:	pushl $0x0<UINT8>
0x004041fd:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00404203:	movl %esi, %eax
0x00404205:	pushl %esi
0x00404206:	call 0x004091f0
0x004091f0:	pushl %ebp
0x004091f1:	movl %ebp, %esp
0x004091f3:	movl %eax, 0x8(%ebp)
0x004091f6:	movl 0x422c60, %eax
0x004091fb:	popl %ebp
0x004091fc:	ret

0x0040420b:	pushl %esi
0x0040420c:	call 0x00406869
0x00406869:	pushl %ebp
0x0040686a:	movl %ebp, %esp
0x0040686c:	movl %eax, 0x8(%ebp)
0x0040686f:	movl 0x42251c, %eax
0x00406874:	popl %ebp
0x00406875:	ret

0x00404211:	pushl %esi
0x00404212:	call 0x0040a815
0x0040a815:	pushl %ebp
0x0040a816:	movl %ebp, %esp
0x0040a818:	movl %eax, 0x8(%ebp)
0x0040a81b:	movl 0x422fb0, %eax
0x0040a820:	popl %ebp
0x0040a821:	ret

0x00404217:	pushl %esi
0x00404218:	call 0x0040a82f
0x0040a82f:	pushl %ebp
0x0040a830:	movl %ebp, %esp
0x0040a832:	movl %eax, 0x8(%ebp)
0x0040a835:	movl 0x422fb4, %eax
0x0040a83a:	movl 0x422fb8, %eax
0x0040a83f:	movl 0x422fbc, %eax
0x0040a844:	movl 0x422fc0, %eax
0x0040a849:	popl %ebp
0x0040a84a:	ret

0x0040421d:	pushl %esi
0x0040421e:	call 0x0040a804
0x0040a804:	pushl $0x40a7d0<UINT32>
0x0040a809:	call EncodePointer@KERNEL32.DLL
0x0040a80f:	movl 0x422fac, %eax
0x0040a814:	ret

0x00404223:	pushl %esi
0x00404224:	call 0x0040aa40
0x0040aa40:	pushl %ebp
0x0040aa41:	movl %ebp, %esp
0x0040aa43:	movl %eax, 0x8(%ebp)
0x0040aa46:	movl 0x422fc8, %eax
0x0040aa4b:	popl %ebp
0x0040aa4c:	ret

0x00404229:	addl %esp, $0x18<UINT8>
0x0040422c:	popl %esi
0x0040422d:	jmp 0x00408cde
0x00408cde:	pushl %esi
0x00408cdf:	pushl %edi
0x00408ce0:	pushl $0x41c114<UINT32>
0x00408ce5:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00408ceb:	movl %esi, 0x4150d8
0x00408cf1:	movl %edi, %eax
0x00408cf3:	pushl $0x41c130<UINT32>
0x00408cf8:	pushl %edi
0x00408cf9:	call GetProcAddress@KERNEL32.DLL
0x00408cfb:	xorl %eax, 0x421430
0x00408d01:	pushl $0x41c13c<UINT32>
0x00408d06:	pushl %edi
0x00408d07:	movl 0x423120, %eax
0x00408d0c:	call GetProcAddress@KERNEL32.DLL
0x00408d0e:	xorl %eax, 0x421430
0x00408d14:	pushl $0x41c144<UINT32>
0x00408d19:	pushl %edi
0x00408d1a:	movl 0x423124, %eax
0x00408d1f:	call GetProcAddress@KERNEL32.DLL
0x00408d21:	xorl %eax, 0x421430
0x00408d27:	pushl $0x41c150<UINT32>
0x00408d2c:	pushl %edi
0x00408d2d:	movl 0x423128, %eax
0x00408d32:	call GetProcAddress@KERNEL32.DLL
0x00408d34:	xorl %eax, 0x421430
0x00408d3a:	pushl $0x41c15c<UINT32>
0x00408d3f:	pushl %edi
0x00408d40:	movl 0x42312c, %eax
0x00408d45:	call GetProcAddress@KERNEL32.DLL
0x00408d47:	xorl %eax, 0x421430
0x00408d4d:	pushl $0x41c178<UINT32>
0x00408d52:	pushl %edi
0x00408d53:	movl 0x423130, %eax
0x00408d58:	call GetProcAddress@KERNEL32.DLL
0x00408d5a:	xorl %eax, 0x421430
0x00408d60:	pushl $0x41c188<UINT32>
0x00408d65:	pushl %edi
0x00408d66:	movl 0x423134, %eax
0x00408d6b:	call GetProcAddress@KERNEL32.DLL
0x00408d6d:	xorl %eax, 0x421430
0x00408d73:	pushl $0x41c19c<UINT32>
0x00408d78:	pushl %edi
0x00408d79:	movl 0x423138, %eax
0x00408d7e:	call GetProcAddress@KERNEL32.DLL
0x00408d80:	xorl %eax, 0x421430
0x00408d86:	pushl $0x41c1b4<UINT32>
0x00408d8b:	pushl %edi
0x00408d8c:	movl 0x42313c, %eax
0x00408d91:	call GetProcAddress@KERNEL32.DLL
0x00408d93:	xorl %eax, 0x421430
0x00408d99:	pushl $0x41c1cc<UINT32>
0x00408d9e:	pushl %edi
0x00408d9f:	movl 0x423140, %eax
0x00408da4:	call GetProcAddress@KERNEL32.DLL
0x00408da6:	xorl %eax, 0x421430
0x00408dac:	pushl $0x41c1e0<UINT32>
0x00408db1:	pushl %edi
0x00408db2:	movl 0x423144, %eax
0x00408db7:	call GetProcAddress@KERNEL32.DLL
0x00408db9:	xorl %eax, 0x421430
0x00408dbf:	pushl $0x41c200<UINT32>
0x00408dc4:	pushl %edi
0x00408dc5:	movl 0x423148, %eax
0x00408dca:	call GetProcAddress@KERNEL32.DLL
0x00408dcc:	xorl %eax, 0x421430
0x00408dd2:	pushl $0x41c218<UINT32>
0x00408dd7:	pushl %edi
0x00408dd8:	movl 0x42314c, %eax
0x00408ddd:	call GetProcAddress@KERNEL32.DLL
0x00408ddf:	xorl %eax, 0x421430
0x00408de5:	pushl $0x41c230<UINT32>
0x00408dea:	pushl %edi
0x00408deb:	movl 0x423150, %eax
0x00408df0:	call GetProcAddress@KERNEL32.DLL
0x00408df2:	xorl %eax, 0x421430
0x00408df8:	pushl $0x41c244<UINT32>
0x00408dfd:	pushl %edi
0x00408dfe:	movl 0x423154, %eax
0x00408e03:	call GetProcAddress@KERNEL32.DLL
0x00408e05:	xorl %eax, 0x421430
0x00408e0b:	movl 0x423158, %eax
0x00408e10:	pushl $0x41c258<UINT32>
0x00408e15:	pushl %edi
0x00408e16:	call GetProcAddress@KERNEL32.DLL
0x00408e18:	xorl %eax, 0x421430
0x00408e1e:	pushl $0x41c274<UINT32>
0x00408e23:	pushl %edi
0x00408e24:	movl 0x42315c, %eax
0x00408e29:	call GetProcAddress@KERNEL32.DLL
0x00408e2b:	xorl %eax, 0x421430
0x00408e31:	pushl $0x41c294<UINT32>
0x00408e36:	pushl %edi
0x00408e37:	movl 0x423160, %eax
0x00408e3c:	call GetProcAddress@KERNEL32.DLL
0x00408e3e:	xorl %eax, 0x421430
0x00408e44:	pushl $0x41c2b0<UINT32>
0x00408e49:	pushl %edi
0x00408e4a:	movl 0x423164, %eax
0x00408e4f:	call GetProcAddress@KERNEL32.DLL
0x00408e51:	xorl %eax, 0x421430
0x00408e57:	pushl $0x41c2d0<UINT32>
0x00408e5c:	pushl %edi
0x00408e5d:	movl 0x423168, %eax
0x00408e62:	call GetProcAddress@KERNEL32.DLL
0x00408e64:	xorl %eax, 0x421430
0x00408e6a:	pushl $0x41c2e4<UINT32>
0x00408e6f:	pushl %edi
0x00408e70:	movl 0x42316c, %eax
0x00408e75:	call GetProcAddress@KERNEL32.DLL
0x00408e77:	xorl %eax, 0x421430
0x00408e7d:	pushl $0x41c300<UINT32>
0x00408e82:	pushl %edi
0x00408e83:	movl 0x423170, %eax
0x00408e88:	call GetProcAddress@KERNEL32.DLL
0x00408e8a:	xorl %eax, 0x421430
0x00408e90:	pushl $0x41c314<UINT32>
0x00408e95:	pushl %edi
0x00408e96:	movl 0x423178, %eax
0x00408e9b:	call GetProcAddress@KERNEL32.DLL
0x00408e9d:	xorl %eax, 0x421430
0x00408ea3:	pushl $0x41c324<UINT32>
0x00408ea8:	pushl %edi
0x00408ea9:	movl 0x423174, %eax
0x00408eae:	call GetProcAddress@KERNEL32.DLL
0x00408eb0:	xorl %eax, 0x421430
0x00408eb6:	pushl $0x41c334<UINT32>
0x00408ebb:	pushl %edi
0x00408ebc:	movl 0x42317c, %eax
0x00408ec1:	call GetProcAddress@KERNEL32.DLL
0x00408ec3:	xorl %eax, 0x421430
0x00408ec9:	pushl $0x41c344<UINT32>
0x00408ece:	pushl %edi
0x00408ecf:	movl 0x423180, %eax
0x00408ed4:	call GetProcAddress@KERNEL32.DLL
0x00408ed6:	xorl %eax, 0x421430
0x00408edc:	pushl $0x41c354<UINT32>
0x00408ee1:	pushl %edi
0x00408ee2:	movl 0x423184, %eax
0x00408ee7:	call GetProcAddress@KERNEL32.DLL
0x00408ee9:	xorl %eax, 0x421430
0x00408eef:	pushl $0x41c370<UINT32>
0x00408ef4:	pushl %edi
0x00408ef5:	movl 0x423188, %eax
0x00408efa:	call GetProcAddress@KERNEL32.DLL
0x00408efc:	xorl %eax, 0x421430
0x00408f02:	pushl $0x41c384<UINT32>
0x00408f07:	pushl %edi
0x00408f08:	movl 0x42318c, %eax
0x00408f0d:	call GetProcAddress@KERNEL32.DLL
0x00408f0f:	xorl %eax, 0x421430
0x00408f15:	pushl $0x41c394<UINT32>
0x00408f1a:	pushl %edi
0x00408f1b:	movl 0x423190, %eax
0x00408f20:	call GetProcAddress@KERNEL32.DLL
0x00408f22:	xorl %eax, 0x421430
0x00408f28:	pushl $0x41c3a8<UINT32>
0x00408f2d:	pushl %edi
0x00408f2e:	movl 0x423194, %eax
0x00408f33:	call GetProcAddress@KERNEL32.DLL
0x00408f35:	xorl %eax, 0x421430
0x00408f3b:	movl 0x423198, %eax
0x00408f40:	pushl $0x41c3b8<UINT32>
0x00408f45:	pushl %edi
0x00408f46:	call GetProcAddress@KERNEL32.DLL
0x00408f48:	xorl %eax, 0x421430
0x00408f4e:	pushl $0x41c3d8<UINT32>
0x00408f53:	pushl %edi
0x00408f54:	movl 0x42319c, %eax
0x00408f59:	call GetProcAddress@KERNEL32.DLL
0x00408f5b:	xorl %eax, 0x421430
0x00408f61:	popl %edi
0x00408f62:	movl 0x4231a0, %eax
0x00408f67:	popl %esi
0x00408f68:	ret

0x0040a227:	call 0x004059e8
0x004059e8:	pushl %esi
0x004059e9:	pushl %edi
0x004059ea:	movl %esi, $0x421440<UINT32>
0x004059ef:	movl %edi, $0x4223c8<UINT32>
0x004059f4:	cmpl 0x4(%esi), $0x1<UINT8>
0x004059f8:	jne 22
0x004059fa:	pushl $0x0<UINT8>
0x004059fc:	movl (%esi), %edi
0x004059fe:	addl %edi, $0x18<UINT8>
0x00405a01:	pushl $0xfa0<UINT32>
0x00405a06:	pushl (%esi)
0x00405a08:	call 0x00408c70
0x00408c70:	pushl %ebp
0x00408c71:	movl %ebp, %esp
0x00408c73:	movl %eax, 0x423130
0x00408c78:	xorl %eax, 0x421430
0x00408c7e:	je 13
0x00408c80:	pushl 0x10(%ebp)
0x00408c83:	pushl 0xc(%ebp)
0x00408c86:	pushl 0x8(%ebp)
0x00408c89:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x00408c8b:	popl %ebp
0x00408c8c:	ret

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
