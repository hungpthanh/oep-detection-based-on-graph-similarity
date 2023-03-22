0x00416be0:	pusha
0x00416be1:	movl %esi, $0x410000<UINT32>
0x00416be6:	leal %edi, -61440(%esi)
0x00416bec:	pushl %edi
0x00416bed:	jmp 0x00416bfa
0x00416bfa:	movl %ebx, (%esi)
0x00416bfc:	subl %esi, $0xfffffffc<UINT8>
0x00416bff:	adcl %ebx, %ebx
0x00416c01:	jb 0x00416bf0
0x00416bf0:	movb %al, (%esi)
0x00416bf2:	incl %esi
0x00416bf3:	movb (%edi), %al
0x00416bf5:	incl %edi
0x00416bf6:	addl %ebx, %ebx
0x00416bf8:	jne 0x00416c01
0x00416c03:	movl %eax, $0x1<UINT32>
0x00416c08:	addl %ebx, %ebx
0x00416c0a:	jne 0x00416c13
0x00416c13:	adcl %eax, %eax
0x00416c15:	addl %ebx, %ebx
0x00416c17:	jae 0x00416c08
0x00416c19:	jne 0x00416c24
0x00416c24:	xorl %ecx, %ecx
0x00416c26:	subl %eax, $0x3<UINT8>
0x00416c29:	jb 0x00416c38
0x00416c2b:	shll %eax, $0x8<UINT8>
0x00416c2e:	movb %al, (%esi)
0x00416c30:	incl %esi
0x00416c31:	xorl %eax, $0xffffffff<UINT8>
0x00416c34:	je 0x00416caa
0x00416c36:	movl %ebp, %eax
0x00416c38:	addl %ebx, %ebx
0x00416c3a:	jne 0x00416c43
0x00416c43:	adcl %ecx, %ecx
0x00416c45:	addl %ebx, %ebx
0x00416c47:	jne 0x00416c50
0x00416c50:	adcl %ecx, %ecx
0x00416c52:	jne 0x00416c74
0x00416c74:	cmpl %ebp, $0xfffff300<UINT32>
0x00416c7a:	adcl %ecx, $0x1<UINT8>
0x00416c7d:	leal %edx, (%edi,%ebp)
0x00416c80:	cmpl %ebp, $0xfffffffc<UINT8>
0x00416c83:	jbe 0x00416c94
0x00416c94:	movl %eax, (%edx)
0x00416c96:	addl %edx, $0x4<UINT8>
0x00416c99:	movl (%edi), %eax
0x00416c9b:	addl %edi, $0x4<UINT8>
0x00416c9e:	subl %ecx, $0x4<UINT8>
0x00416ca1:	ja 0x00416c94
0x00416ca3:	addl %edi, %ecx
0x00416ca5:	jmp 0x00416bf6
0x00416c49:	movl %ebx, (%esi)
0x00416c4b:	subl %esi, $0xfffffffc<UINT8>
0x00416c4e:	adcl %ebx, %ebx
0x00416c0c:	movl %ebx, (%esi)
0x00416c0e:	subl %esi, $0xfffffffc<UINT8>
0x00416c11:	adcl %ebx, %ebx
0x00416c85:	movb %al, (%edx)
0x00416c87:	incl %edx
0x00416c88:	movb (%edi), %al
0x00416c8a:	incl %edi
0x00416c8b:	decl %ecx
0x00416c8c:	jne 0x00416c85
0x00416c8e:	jmp 0x00416bf6
0x00416c3c:	movl %ebx, (%esi)
0x00416c3e:	subl %esi, $0xfffffffc<UINT8>
0x00416c41:	adcl %ebx, %ebx
0x00416c54:	incl %ecx
0x00416c55:	addl %ebx, %ebx
0x00416c57:	jne 0x00416c60
0x00416c60:	adcl %ecx, %ecx
0x00416c62:	addl %ebx, %ebx
0x00416c64:	jae 0x00416c55
0x00416c66:	jne 0x00416c71
0x00416c71:	addl %ecx, $0x2<UINT8>
0x00416c68:	movl %ebx, (%esi)
0x00416c6a:	subl %esi, $0xfffffffc<UINT8>
0x00416c6d:	adcl %ebx, %ebx
0x00416c6f:	jae 0x00416c55
0x00416c59:	movl %ebx, (%esi)
0x00416c5b:	subl %esi, $0xfffffffc<UINT8>
0x00416c5e:	adcl %ebx, %ebx
0x00416c1b:	movl %ebx, (%esi)
0x00416c1d:	subl %esi, $0xfffffffc<UINT8>
0x00416c20:	adcl %ebx, %ebx
0x00416c22:	jae 0x00416c08
0x00416caa:	popl %esi
0x00416cab:	movl %edi, %esi
0x00416cad:	movl %ecx, $0x1f8<UINT32>
0x00416cb2:	movb %al, (%edi)
0x00416cb4:	incl %edi
0x00416cb5:	subb %al, $0xffffffe8<UINT8>
0x00416cb7:	cmpb %al, $0x1<UINT8>
0x00416cb9:	ja 0x00416cb2
0x00416cbb:	cmpb (%edi), $0x7<UINT8>
0x00416cbe:	jne 0x00416cb2
0x00416cc0:	movl %eax, (%edi)
0x00416cc2:	movb %bl, 0x4(%edi)
0x00416cc5:	shrw %ax, $0x8<UINT8>
0x00416cc9:	roll %eax, $0x10<UINT8>
0x00416ccc:	xchgb %ah, %al
0x00416cce:	subl %eax, %edi
0x00416cd0:	subb %bl, $0xffffffe8<UINT8>
0x00416cd3:	addl %eax, %esi
0x00416cd5:	movl (%edi), %eax
0x00416cd7:	addl %edi, $0x5<UINT8>
0x00416cda:	movb %al, %bl
0x00416cdc:	loop 0x00416cb7
0x00416cde:	leal %edi, 0x14000(%esi)
0x00416ce4:	movl %eax, (%edi)
0x00416ce6:	orl %eax, %eax
0x00416ce8:	je 0x00416d26
0x00416cea:	movl %ebx, 0x4(%edi)
0x00416ced:	leal %eax, 0x173d8(%eax,%esi)
0x00416cf4:	addl %ebx, %esi
0x00416cf6:	pushl %eax
0x00416cf7:	addl %edi, $0x8<UINT8>
0x00416cfa:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x00416d00:	xchgl %ebp, %eax
0x00416d01:	movb %al, (%edi)
0x00416d03:	incl %edi
0x00416d04:	orb %al, %al
0x00416d06:	je 0x00416ce4
0x00416d08:	movl %ecx, %edi
0x00416d0a:	pushl %edi
0x00416d0b:	decl %eax
0x00416d0c:	repn scasb %al, %es:(%edi)
0x00416d0e:	pushl %ebp
0x00416d0f:	call GetProcAddress@kernel32.dll
GetProcAddress@kernel32.dll: API Node	
0x00416d15:	orl %eax, %eax
0x00416d17:	je 7
0x00416d19:	movl (%ebx), %eax
0x00416d1b:	addl %ebx, $0x4<UINT8>
0x00416d1e:	jmp 0x00416d01
0x00416d26:	movl %ebp, 0x174a4(%esi)
0x00416d2c:	leal %edi, -4096(%esi)
0x00416d32:	movl %ebx, $0x1000<UINT32>
0x00416d37:	pushl %eax
0x00416d38:	pushl %esp
0x00416d39:	pushl $0x4<UINT8>
0x00416d3b:	pushl %ebx
0x00416d3c:	pushl %edi
0x00416d3d:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00416d3f:	leal %eax, 0x17f(%edi)
0x00416d45:	andb (%eax), $0x7f<UINT8>
0x00416d48:	andb 0x28(%eax), $0x7f<UINT8>
0x00416d4c:	popl %eax
0x00416d4d:	pushl %eax
0x00416d4e:	pushl %esp
0x00416d4f:	pushl %eax
0x00416d50:	pushl %ebx
0x00416d51:	pushl %edi
0x00416d52:	call VirtualProtect@kernel32.dll
0x00416d54:	popl %eax
0x00416d55:	popa
0x00416d56:	leal %eax, -128(%esp)
0x00416d5a:	pushl $0x0<UINT8>
0x00416d5c:	cmpl %esp, %eax
0x00416d5e:	jne 0x00416d5a
0x00416d60:	subl %esp, $0xffffff80<UINT8>
0x00416d63:	jmp 0x00401000
0x00401000:	call 0x004010dc
0x004010dc:	pushl %ebp
0x004010dd:	movl %ebp, %esp
0x004010df:	subl %esp, $0x38<UINT8>
0x004010e2:	call 0x00401490
0x00401490:	pushl $0x2<UINT8>
0x00401492:	call GetSystemMetrics@USER32.dll
GetSystemMetrics@USER32.dll: API Node	
0x00401498:	movl 0x40a310, %eax
0x0040149d:	pushl $0x0<UINT8>
0x0040149f:	pushl $0x40a314<UINT32>
0x004014a4:	pushl $0x0<UINT8>
0x004014a6:	pushl $0x26<UINT8>
0x004014a8:	call SystemParametersInfoA@USER32.dll
SystemParametersInfoA@USER32.dll: API Node	
0x004014ae:	pushl $0x0<UINT8>
0x004014b0:	pushl $0x40a300<UINT32>
0x004014b5:	pushl $0x0<UINT8>
0x004014b7:	pushl $0x68<UINT8>
0x004014b9:	call SystemParametersInfoA@USER32.dll
0x004014bf:	ret

0x004010e7:	call 0x004014c0
0x004014c0:	pushl $0x5<UINT8>
0x004014c2:	call GetSysColor@USER32.dll
GetSysColor@USER32.dll: API Node	
0x004014c8:	movl 0x40a968, %eax
0x004014cd:	pushl $0x8<UINT8>
0x004014cf:	call GetSysColor@USER32.dll
0x004014d5:	movl 0x40a96c, %eax
0x004014da:	pushl $0xd<UINT8>
0x004014dc:	call GetSysColor@USER32.dll
0x004014e2:	movl 0x40a970, %eax
0x004014e7:	pushl $0xe<UINT8>
0x004014e9:	call GetSysColor@USER32.dll
0x004014ef:	movl 0x40a974, %eax
0x004014f4:	pushl $0x11<UINT8>
0x004014f6:	call GetSysColor@USER32.dll
0x004014fc:	movl 0x40a978, %eax
0x00401501:	movl %eax, 0x40a2f8
0x00401506:	testl %eax, %eax
0x00401508:	je 0x00401517
0x00401517:	xorl %eax, %eax
0x00401519:	ret

0x004010ec:	pushl $0x0<UINT8>
0x004010ee:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x004010f4:	testl %eax, %eax
0x004010f6:	je 334
0x004010fc:	movl 0x40a2e0, %eax
0x00401101:	movl %ebx, %eax
0x00401103:	movl -8(%ebp), $0x8<UINT32>
0x0040110a:	movl -4(%ebp), $0x6<UINT32>
0x00401111:	pushl %ebp
0x00401112:	addl (%esp), $0xfffffff8<UINT8>
0x00401116:	call InitCommonControlsEx@COMCTL32.dll
InitCommonControlsEx@COMCTL32.dll: API Node	
0x0040111c:	xorl %eax, %eax
0x0040111e:	movl -56(%ebp), $0x30<UINT32>
0x00401125:	movl -52(%ebp), %eax
0x00401128:	movl -48(%ebp), $0x401068<UINT32>
0x0040112f:	movl -44(%ebp), %eax
0x00401132:	movl -40(%ebp), %eax
0x00401135:	movl -36(%ebp), %ebx
0x00401138:	pushl $0x0<UINT8>
0x0040113a:	pushl $0x20<UINT8>
0x0040113c:	pushl $0x20<UINT8>
0x0040113e:	pushl $0x1<UINT8>
0x00401140:	pushl $0x1<UINT8>
0x00401142:	pushl %ebx
0x00401143:	call LoadImageA@USER32.dll
LoadImageA@USER32.dll: API Node	
0x00401149:	movl -32(%ebp), %eax
0x0040114c:	pushl $0x8040<UINT32>
0x00401151:	pushl $0x0<UINT8>
0x00401153:	pushl $0x0<UINT8>
0x00401155:	pushl $0x2<UINT8>
0x00401157:	pushl $0x7f84<UINT32>
0x0040115c:	pushl $0x0<UINT8>
0x0040115e:	call LoadImageA@USER32.dll
0x00401164:	movl -28(%ebp), %eax
0x00401167:	movl 0x40a2fc, %eax
0x0040116c:	movl -24(%ebp), $0x0<UINT32>
0x00401173:	movl -20(%ebp), $0x1<UINT32>
0x0040117a:	movl -16(%ebp), $0x40c188<UINT32>
0x00401181:	pushl $0x0<UINT8>
0x00401183:	pushl $0x10<UINT8>
0x00401185:	pushl $0x10<UINT8>
0x00401187:	pushl $0x1<UINT8>
0x00401189:	pushl $0x1<UINT8>
0x0040118b:	pushl %ebx
0x0040118c:	call LoadImageA@USER32.dll
0x00401192:	movl -12(%ebp), %eax
0x00401195:	pushl %ebp
0x00401196:	addl (%esp), $0xffffffc8<UINT8>
0x0040119a:	call RegisterClassExA@USER32.dll
RegisterClassExA@USER32.dll: API Node	
0x004011a0:	testl %eax, %eax
0x004011a2:	je 162
0x004011a8:	movl %eax, $0x6578652e<UINT32>
0x004011ad:	movl %ecx, $0x4<UINT32>
0x004011b2:	movl 0x40a7f4, %eax
0x004011b7:	movl 0x40a3d4, %ecx
0x004011bd:	call 0x0040159c
0x0040159c:	xorl %ebx, %ebx
0x0040159e:	movl %esi, $0x40a304<UINT32>
0x004015a3:	pushl %esi
0x004015a4:	pushl $0x20019<UINT32>
0x004015a9:	pushl %ebx
0x004015aa:	pushl $0x40c300<UINT32>
0x004015af:	pushl $0x80000001<UINT32>
0x004015b4:	call RegOpenKeyExA@ADVAPI32.dll
RegOpenKeyExA@ADVAPI32.dll: API Node	
0x004015ba:	testl %eax, %eax
0x004015bc:	jne 0x00401666
0x00401666:	ret

0x004011c2:	pushl %eax
0x004011c3:	xorl %eax, %eax
0x004011c5:	pushl %eax
0x004011c6:	pushl %ebx
0x004011c7:	pushl %eax
0x004011c8:	pushl %eax
0x004011c9:	pushl %eax
0x004011ca:	pushl %eax
0x004011cb:	pushl %eax
0x004011cc:	pushl %eax
0x004011cd:	pushl $0xcf0000<UINT32>
0x004011d2:	pushl %eax
0x004011d3:	pushl $0x40c188<UINT32>
0x004011d8:	pushl $0x10<UINT8>
0x004011da:	call CreateWindowExA@USER32.dll
CreateWindowExA@USER32.dll: API Node	
0x004011e0:	popl %edx
0x004011e1:	testl %eax, %eax
0x004011e3:	je 0x0040124a
0x0040124a:	incl %eax
0x0040124b:	jmp 0x00401246
0x00401246:	movl %esp, %ebp
0x00401248:	popl %ebp
0x00401249:	ret

0x00401005:	testl %eax, %eax
0x00401007:	jne 0x0040100e
0x0040100e:	pushl %eax
0x0040100f:	call ExitProcess@KERNEL32.DLL
ExitProcess@KERNEL32.DLL: Exit Node	
