0x005e0cc0:	pusha
0x005e0cc1:	movl %esi, $0x4cc000<UINT32>
0x005e0cc6:	leal %edi, -831488(%esi)
0x005e0ccc:	pushl %edi
0x005e0ccd:	jmp 0x005e0cda
0x005e0cda:	movl %ebx, (%esi)
0x005e0cdc:	subl %esi, $0xfffffffc<UINT8>
0x005e0cdf:	adcl %ebx, %ebx
0x005e0ce1:	jb 0x005e0cd0
0x005e0cd0:	movb %al, (%esi)
0x005e0cd2:	incl %esi
0x005e0cd3:	movb (%edi), %al
0x005e0cd5:	incl %edi
0x005e0cd6:	addl %ebx, %ebx
0x005e0cd8:	jne 0x005e0ce1
0x005e0ce3:	movl %eax, $0x1<UINT32>
0x005e0ce8:	addl %ebx, %ebx
0x005e0cea:	jne 0x005e0cf3
0x005e0cf3:	adcl %eax, %eax
0x005e0cf5:	addl %ebx, %ebx
0x005e0cf7:	jae 0x005e0d04
0x005e0cf9:	jne 0x005e0d23
0x005e0d23:	xorl %ecx, %ecx
0x005e0d25:	subl %eax, $0x3<UINT8>
0x005e0d28:	jb 0x005e0d3b
0x005e0d2a:	shll %eax, $0x8<UINT8>
0x005e0d2d:	movb %al, (%esi)
0x005e0d2f:	incl %esi
0x005e0d30:	xorl %eax, $0xffffffff<UINT8>
0x005e0d33:	je 0x005e0daa
0x005e0d35:	sarl %eax
0x005e0d37:	movl %ebp, %eax
0x005e0d39:	jmp 0x005e0d46
0x005e0d46:	jb 0x005e0d14
0x005e0d14:	addl %ebx, %ebx
0x005e0d16:	jne 0x005e0d1f
0x005e0d1f:	adcl %ecx, %ecx
0x005e0d21:	jmp 0x005e0d75
0x005e0d75:	cmpl %ebp, $0xfffffb00<UINT32>
0x005e0d7b:	adcl %ecx, $0x2<UINT8>
0x005e0d7e:	leal %edx, (%edi,%ebp)
0x005e0d81:	cmpl %ebp, $0xfffffffc<UINT8>
0x005e0d84:	jbe 0x005e0d94
0x005e0d86:	movb %al, (%edx)
0x005e0d88:	incl %edx
0x005e0d89:	movb (%edi), %al
0x005e0d8b:	incl %edi
0x005e0d8c:	decl %ecx
0x005e0d8d:	jne 0x005e0d86
0x005e0d8f:	jmp 0x005e0cd6
0x005e0d3b:	addl %ebx, %ebx
0x005e0d3d:	jne 0x005e0d46
0x005e0cec:	movl %ebx, (%esi)
0x005e0cee:	subl %esi, $0xfffffffc<UINT8>
0x005e0cf1:	adcl %ebx, %ebx
0x005e0d48:	incl %ecx
0x005e0d49:	addl %ebx, %ebx
0x005e0d4b:	jne 0x005e0d54
0x005e0d54:	jb 0x005e0d14
0x005e0d94:	movl %eax, (%edx)
0x005e0d96:	addl %edx, $0x4<UINT8>
0x005e0d99:	movl (%edi), %eax
0x005e0d9b:	addl %edi, $0x4<UINT8>
0x005e0d9e:	subl %ecx, $0x4<UINT8>
0x005e0da1:	ja 0x005e0d94
0x005e0da3:	addl %edi, %ecx
0x005e0da5:	jmp 0x005e0cd6
0x005e0d18:	movl %ebx, (%esi)
0x005e0d1a:	subl %esi, $0xfffffffc<UINT8>
0x005e0d1d:	adcl %ebx, %ebx
0x005e0d56:	addl %ebx, %ebx
0x005e0d58:	jne 0x005e0d61
0x005e0d5a:	movl %ebx, (%esi)
0x005e0d5c:	subl %esi, $0xfffffffc<UINT8>
0x005e0d5f:	adcl %ebx, %ebx
0x005e0d61:	adcl %ecx, %ecx
0x005e0d63:	addl %ebx, %ebx
0x005e0d65:	jae 0x005e0d56
0x005e0d67:	jne 0x005e0d72
0x005e0d72:	addl %ecx, $0x2<UINT8>
0x005e0cfb:	movl %ebx, (%esi)
0x005e0cfd:	subl %esi, $0xfffffffc<UINT8>
0x005e0d00:	adcl %ebx, %ebx
0x005e0d02:	jb 0x005e0d23
0x005e0d04:	decl %eax
0x005e0d05:	addl %ebx, %ebx
0x005e0d07:	jne 0x005e0d10
0x005e0d10:	adcl %eax, %eax
0x005e0d12:	jmp 0x005e0ce8
0x005e0d4d:	movl %ebx, (%esi)
0x005e0d4f:	subl %esi, $0xfffffffc<UINT8>
0x005e0d52:	adcl %ebx, %ebx
0x005e0d69:	movl %ebx, (%esi)
0x005e0d6b:	subl %esi, $0xfffffffc<UINT8>
0x005e0d6e:	adcl %ebx, %ebx
0x005e0d70:	jae 0x005e0d56
0x005e0d3f:	movl %ebx, (%esi)
0x005e0d41:	subl %esi, $0xfffffffc<UINT8>
0x005e0d44:	adcl %ebx, %ebx
0x005e0d09:	movl %ebx, (%esi)
0x005e0d0b:	subl %esi, $0xfffffffc<UINT8>
0x005e0d0e:	adcl %ebx, %ebx
0x005e0daa:	popl %esi
0x005e0dab:	movl %edi, %esi
0x005e0dad:	movl %ecx, $0x87f8<UINT32>
0x005e0db2:	movb %al, (%edi)
0x005e0db4:	incl %edi
0x005e0db5:	subb %al, $0xffffffe8<UINT8>
0x005e0db7:	cmpb %al, $0x1<UINT8>
0x005e0db9:	ja 0x005e0db2
0x005e0dbb:	cmpb (%edi), $0x22<UINT8>
0x005e0dbe:	jne 0x005e0db2
0x005e0dc0:	movl %eax, (%edi)
0x005e0dc2:	movb %bl, 0x4(%edi)
0x005e0dc5:	shrw %ax, $0x8<UINT8>
0x005e0dc9:	roll %eax, $0x10<UINT8>
0x005e0dcc:	xchgb %ah, %al
0x005e0dce:	subl %eax, %edi
0x005e0dd0:	subb %bl, $0xffffffe8<UINT8>
0x005e0dd3:	addl %eax, %esi
0x005e0dd5:	movl (%edi), %eax
0x005e0dd7:	addl %edi, $0x5<UINT8>
0x005e0dda:	movb %al, %bl
0x005e0ddc:	loop 0x005e0db7
0x005e0dde:	leal %edi, 0x1dd000(%esi)
0x005e0de4:	movl %eax, (%edi)
0x005e0de6:	orl %eax, %eax
0x005e0de8:	je 0x005e0e2f
0x005e0dea:	movl %ebx, 0x4(%edi)
0x005e0ded:	leal %eax, 0x203050(%eax,%esi)
0x005e0df4:	addl %ebx, %esi
0x005e0df6:	pushl %eax
0x005e0df7:	addl %edi, $0x8<UINT8>
0x005e0dfa:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x005e0e00:	xchgl %ebp, %eax
0x005e0e01:	movb %al, (%edi)
0x005e0e03:	incl %edi
0x005e0e04:	orb %al, %al
0x005e0e06:	je 0x005e0de4
0x005e0e08:	movl %ecx, %edi
0x005e0e0a:	jns 0x005e0e13
0x005e0e13:	pushl %edi
0x005e0e14:	decl %eax
0x005e0e15:	repn scasb %al, %es:(%edi)
0x005e0e17:	pushl %ebp
0x005e0e18:	call GetProcAddress@kernel32.dll
GetProcAddress@kernel32.dll: API Node	
0x005e0e1e:	orl %eax, %eax
0x005e0e20:	je 7
0x005e0e22:	movl (%ebx), %eax
0x005e0e24:	addl %ebx, $0x4<UINT8>
0x005e0e27:	jmp 0x005e0e01
LoadLibraryA@KERNEL32.DLL: API Node	
0x005e0e0c:	movzwl %eax, (%edi)
0x005e0e0f:	incl %edi
0x005e0e10:	pushl %eax
0x005e0e11:	incl %edi
0x005e0e12:	movl %ecx, $0xaef24857<UINT32>
0x005e0e2f:	movl %ebp, 0x20318c(%esi)
0x005e0e35:	leal %edi, -4096(%esi)
0x005e0e3b:	movl %ebx, $0x1000<UINT32>
0x005e0e40:	pushl %eax
0x005e0e41:	pushl %esp
0x005e0e42:	pushl $0x4<UINT8>
0x005e0e44:	pushl %ebx
0x005e0e45:	pushl %edi
0x005e0e46:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x005e0e48:	leal %eax, 0x227(%edi)
0x005e0e4e:	andb (%eax), $0x7f<UINT8>
0x005e0e51:	andb 0x28(%eax), $0x7f<UINT8>
0x005e0e55:	popl %eax
0x005e0e56:	pushl %eax
0x005e0e57:	pushl %esp
0x005e0e58:	pushl %eax
0x005e0e59:	pushl %ebx
0x005e0e5a:	pushl %edi
0x005e0e5b:	call VirtualProtect@kernel32.dll
0x005e0e5d:	popl %eax
0x005e0e5e:	popa
0x005e0e5f:	leal %eax, -128(%esp)
0x005e0e63:	pushl $0x0<UINT8>
0x005e0e65:	cmpl %esp, %eax
0x005e0e67:	jne 0x005e0e63
0x005e0e69:	subl %esp, $0xffffff80<UINT8>
0x005e0e6c:	jmp 0x0048f113
0x0048f113:	call 0x0049be27
0x0049be27:	pushl %ebp
0x0049be28:	movl %ebp, %esp
0x0049be2a:	subl %esp, $0x10<UINT8>
0x0049be2d:	movl %eax, 0x50a590
0x0049be32:	andl -8(%ebp), $0x0<UINT8>
0x0049be36:	andl -4(%ebp), $0x0<UINT8>
0x0049be3a:	pushl %ebx
0x0049be3b:	pushl %edi
0x0049be3c:	movl %edi, $0xbb40e64e<UINT32>
0x0049be41:	cmpl %eax, %edi
0x0049be43:	movl %ebx, $0xffff0000<UINT32>
0x0049be48:	je 0x0049be57
0x0049be57:	pushl %esi
0x0049be58:	leal %eax, -8(%ebp)
0x0049be5b:	pushl %eax
0x0049be5c:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0049be62:	movl %esi, -4(%ebp)
0x0049be65:	xorl %esi, -8(%ebp)
0x0049be68:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0049be6e:	xorl %esi, %eax
0x0049be70:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0049be76:	xorl %esi, %eax
0x0049be78:	call GetTickCount@KERNEL32.DLL
GetTickCount@KERNEL32.DLL: API Node	
0x0049be7e:	xorl %esi, %eax
0x0049be80:	leal %eax, -16(%ebp)
0x0049be83:	pushl %eax
0x0049be84:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0049be8a:	movl %eax, -12(%ebp)
0x0049be8d:	xorl %eax, -16(%ebp)
0x0049be90:	xorl %esi, %eax
0x0049be92:	cmpl %esi, %edi
0x0049be94:	jne 0x0049be9d
0x0049be9d:	testl %ebx, %esi
0x0049be9f:	jne 0x0049bea8
0x0049bea8:	movl 0x50a590, %esi
0x0049beae:	notl %esi
0x0049beb0:	movl 0x50a594, %esi
0x0049beb6:	popl %esi
0x0049beb7:	popl %edi
0x0049beb8:	popl %ebx
0x0049beb9:	leave
0x0049beba:	ret

0x0048f118:	jmp 0x0048ef34
0x0048ef34:	pushl $0x60<UINT8>
0x0048ef36:	pushl $0x4f7b30<UINT32>
0x0048ef3b:	call 0x0049961c
0x0049961c:	pushl $0x4996b0<UINT32>
0x00499621:	pushl %fs:0
0x00499628:	movl %eax, 0x10(%esp)
0x0049962c:	movl 0x10(%esp), %ebp
0x00499630:	leal %ebp, 0x10(%esp)
0x00499634:	subl %esp, %eax
0x00499636:	pushl %ebx
0x00499637:	pushl %esi
0x00499638:	pushl %edi
0x00499639:	movl %eax, 0x50a590
0x0049963e:	xorl -4(%ebp), %eax
0x00499641:	xorl %eax, %ebp
0x00499643:	pushl %eax
0x00499644:	movl -24(%ebp), %esp
0x00499647:	pushl -8(%ebp)
0x0049964a:	movl %eax, -4(%ebp)
0x0049964d:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00499654:	movl -8(%ebp), %eax
0x00499657:	leal %eax, -16(%ebp)
0x0049965a:	movl %fs:0, %eax
0x00499660:	ret

0x0048ef40:	andl -4(%ebp), $0x0<UINT8>
0x0048ef44:	leal %eax, -112(%ebp)
0x0048ef47:	pushl %eax
0x0048ef48:	call 0x004c0e3d
0x004c0e3d:	pushl $0x457069<UINT32>
0x004c0e42:	pushl 0x510d00
0x004c0e48:	pushl $0x50dae4<UINT32>
0x004c0e4d:	pushl $0x4dff98<UINT32>
0x004c0e52:	pushl $0x4d3870<UINT32>
0x004c0e57:	call 0x00456a61
0x00456a61:	movl %edi, %edi
0x00456a63:	pushl %ebp
0x00456a64:	movl %ebp, %esp
0x00456a66:	cmpl 0x50dc60, $0x0<UINT8>
0x00456a6d:	pushl %ebx
0x00456a6e:	pushl %esi
0x00456a6f:	pushl %edi
0x00456a70:	pushl $0x2<UINT8>
0x00456a72:	popl %ebx
0x00456a73:	jne 43
0x00456a75:	pushl $0x4d39d0<UINT32>
0x00456a7a:	pushl $0x4d39c4<UINT32>
0x00456a7f:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x00456a85:	pushl %eax
0x00456a86:	call 0x00456791
0x00456791:	movl %edi, %edi
0x00456793:	pushl %ebp
0x00456794:	movl %ebp, %esp
0x00456796:	pushl %esi
0x00456797:	pushl %edi
0x00456798:	movl %edi, 0x8(%ebp)
0x0045679b:	testl %edi, %edi
0x0045679d:	je 80
0x0045679f:	cmpl 0xc(%ebp), $0x0<UINT8>
0x004567a3:	je 74
0x004567a5:	leal %eax, 0x8(%ebp)
0x004567a8:	pushl %eax
0x004567a9:	pushl $0x0<UINT8>
0x004567ab:	pushl %edi
0x004567ac:	call 0x004566ec
0x004566ec:	movl %edi, %edi
0x004566ee:	pushl %ebp
0x004566ef:	movl %ebp, %esp
0x004566f1:	pushl %esi
0x004566f2:	movl %esi, 0x8(%ebp)
0x004566f5:	movl %eax, 0x3c(%esi)
0x004566f8:	addl %eax, %esi
0x004566fa:	je 31
0x004566fc:	movzwl %ecx, 0xc(%ebp)
0x00456700:	cmpl %ecx, 0x74(%eax)
0x00456703:	jae 22
0x00456705:	movl %edx, 0x78(%eax,%ecx,8)
0x00456709:	testl %edx, %edx
0x0045670b:	je 14
0x0045670d:	movl %eax, 0x7c(%eax,%ecx,8)
0x00456711:	movl %ecx, 0x10(%ebp)
0x00456714:	movl (%ecx), %eax
0x00456716:	leal %eax, (%edx,%esi)
0x00456719:	jmp 0x00456723
0x00456723:	popl %esi
0x00456724:	popl %ebp
0x00456725:	ret $0xc<UINT16>

0x004567b1:	movl %esi, %eax
0x004567b3:	testl %esi, %esi
0x004567b5:	je 56
0x004567b7:	movl %eax, 0x24(%esi)
0x004567ba:	addl %eax, %edi
0x004567bc:	pushl %eax
0x004567bd:	movl %eax, 0x20(%esi)
0x004567c0:	addl %eax, %edi
0x004567c2:	pushl %eax
0x004567c3:	pushl %edi
0x004567c4:	pushl 0x18(%esi)
0x004567c7:	pushl 0xc(%ebp)
0x004567ca:	call 0x0045666f
0x0045666f:	movl %edi, %edi
0x00456671:	pushl %ebp
0x00456672:	movl %ebp, %esp
0x00456674:	pushl %ecx
0x00456675:	movl %ecx, 0xc(%ebp)
0x00456678:	andl -4(%ebp), $0x0<UINT8>
0x0045667c:	decl %ecx
0x0045667d:	pushl %esi
0x0045667e:	js 90
0x00456680:	pushl %ebx
0x00456681:	pushl %edi
0x00456682:	movl %eax, -4(%ebp)
0x00456685:	movl %edi, 0x8(%ebp)
0x00456688:	leal %esi, (%ecx,%eax)
0x0045668b:	movl %eax, 0x14(%ebp)
0x0045668e:	sarl %esi
0x00456690:	movl %eax, (%eax,%esi,4)
0x00456693:	addl %eax, 0x10(%ebp)
0x00456696:	movb %bl, (%edi)
0x00456698:	movb %dl, %bl
0x0045669a:	cmpb %bl, (%eax)
0x0045669c:	jne 0x004566b8
0x004566b8:	sbbl %eax, %eax
0x004566ba:	sbbl %eax, $0xffffffff<UINT8>
0x004566bd:	testl %eax, %eax
0x004566bf:	jnl 0x004566c6
0x004566c1:	leal %ecx, -1(%esi)
0x004566c4:	jmp 0x004566ce
0x004566ce:	cmpl %ecx, -4(%ebp)
0x004566d1:	jnl 0x00456682
0x0045669e:	testb %dl, %dl
0x004566a0:	je 0x004566b4
0x004566a2:	movb %bl, 0x1(%edi)
0x004566a5:	movb %dl, %bl
0x004566a7:	cmpb %bl, 0x1(%eax)
0x004566aa:	jne 0x004566b8
0x004566ac:	incl %edi
0x004566ad:	incl %edi
0x004566ae:	incl %eax
0x004566af:	incl %eax
0x004566b0:	testb %dl, %dl
0x004566b2:	jne 0x00456696
0x004566c6:	jle 0x004566d3
0x004566c8:	leal %eax, 0x1(%esi)
0x004566cb:	movl -4(%ebp), %eax
0x004566b4:	xorl %eax, %eax
0x004566b6:	jmp 0x004566bd
0x004566d3:	cmpl %ecx, -4(%ebp)
0x004566d6:	popl %edi
0x004566d7:	popl %ebx
0x004566d8:	jnl 0x004566e0
0x004566e0:	movl %eax, 0x18(%ebp)
0x004566e3:	movw %ax, (%eax,%esi,2)
0x004566e7:	popl %esi
0x004566e8:	leave
0x004566e9:	ret $0x14<UINT16>

0x004567cf:	movzwl %eax, %ax
0x004567d2:	cmpl %eax, 0x14(%esi)
0x004567d5:	jae 24
0x004567d7:	movl %ecx, 0x1c(%esi)
0x004567da:	leal %eax, (%ecx,%eax,4)
0x004567dd:	movl %eax, (%eax,%edi)
0x004567e0:	addl %eax, %edi
0x004567e2:	cmpl %eax, %esi
0x004567e4:	jbe 0x004567f1
0x004567e6:	movl %ecx, 0x8(%ebp)
0x004567e9:	addl %ecx, %esi
0x004567eb:	cmpl %eax, %ecx
0x004567ed:	jae 0x004567f1
0x004567f1:	popl %edi
0x004567f2:	popl %esi
0x004567f3:	popl %ebp
0x004567f4:	ret $0x8<UINT16>

0x00456a8b:	testl %eax, %eax
0x00456a8d:	je 11
0x00456a8f:	xorl %edi, %edi
0x00456a91:	incl %edi
0x00456a92:	movl 0x50dc60, %edi
0x00456a98:	jmp 0x00456aaf
0x00456aaf:	movl %eax, 0x509008
0x00456ab4:	jmp 0x00456aee
0x00456aee:	testl %eax, %eax
0x00456af0:	movl 0x14(%ebp), %edi
0x00456af3:	jne 0x00456ab6
0x00456ab6:	movl %esi, %eax
0x00456ab8:	movl %eax, 0x8(%ebp)
0x00456abb:	movb %dl, (%eax)
0x00456abd:	movb %cl, %dl
0x00456abf:	cmpb %dl, (%esi)
0x00456ac1:	jne 26
0x00456ac3:	testb %cl, %cl
0x00456ac5:	je 0x00456ad9
0x00456ac7:	movb %dl, 0x1(%eax)
0x00456aca:	movb %cl, %dl
0x00456acc:	cmpb %dl, 0x1(%esi)
0x00456acf:	jne 12
0x00456ad1:	addl %eax, %ebx
0x00456ad3:	addl %esi, %ebx
0x00456ad5:	testb %cl, %cl
0x00456ad7:	jne 0x00456abb
0x00456ad9:	xorl %eax, %eax
0x00456adb:	jmp 0x00456ae2
0x00456ae2:	testl %eax, %eax
0x00456ae4:	je 0x00456b08
0x00456b08:	leal %edi, 0x509004(,%edi,8)
0x00456b0f:	cmpl (%edi), $0x0<UINT8>
0x00456b12:	jne 51
0x00456b14:	pushl 0x8(%ebp)
0x00456b17:	movl %esi, 0x4d317c
0x00456b1d:	call LoadLibraryA@KERNEL32.DLL
0x00456b1f:	movl %ebx, %eax
0x00456b21:	testl %ebx, %ebx
0x00456b23:	jne 0x00456b34
0x00456b34:	pushl %ebx
0x00456b35:	pushl %edi
0x00456b36:	call InterlockedExchange@KERNEL32.DLL
InterlockedExchange@KERNEL32.DLL: API Node	
0x00456b3c:	testl %eax, %eax
0x00456b3e:	je 7
0x00456b40:	pushl %ebx
0x00456b41:	call FreeLibrary@KERNEL32.DLL
FreeLibrary@KERNEL32.DLL: API Node	
0x00456b47:	pushl 0xc(%ebp)
0x00456b4a:	pushl (%edi)
0x00456b4c:	jmp 0x00456b95
0x00456b95:	call 0x00456791
0x00456b9a:	testl %eax, %eax
0x00456b9c:	je -173
0x00456ba2:	pushl %eax
0x00456ba3:	jmp 0x00456af8
0x00456af8:	pushl 0x10(%ebp)
0x00456afb:	call InterlockedExchange@KERNEL32.DLL
0x00456b01:	popl %edi
0x00456b02:	popl %esi
0x00456b03:	popl %ebx
0x00456b04:	popl %ebp
0x00456b05:	ret $0x14<UINT16>

0x004c0e5c:	jmp 0x50dae4
0x004996b0:	subl %esp, $0x14<UINT8>
0x004996b3:	pushl %ebx
0x004996b4:	movl %ebx, 0x20(%esp)
0x004996b8:	pushl %ebp
0x004996b9:	pushl %esi
0x004996ba:	movl %esi, 0x8(%ebx)
0x004996bd:	xorl %esi, 0x50a590
0x004996c3:	pushl %edi
0x004996c4:	movl %eax, (%esi)
0x004996c6:	cmpl %eax, $0xfffffffe<UINT8>
0x004996c9:	movb 0x13(%esp), $0x0<UINT8>
0x004996ce:	movl 0x18(%esp), $0x1<UINT32>
0x004996d6:	leal %edi, 0x10(%ebx)
0x004996d9:	je 0x004996e8
0x004996e8:	movl %ecx, 0xc(%esi)
0x004996eb:	movl %eax, 0x8(%esi)
0x004996ee:	addl %ecx, %edi
0x004996f0:	xorl %ecx, (%eax,%edi)
0x004996f3:	call 0x0048f5da
0x0048f5da:	cmpl %ecx, 0x50a590
0x0048f5e0:	jne 2
0x0048f5e2:	rep ret

0x004996f8:	movl %eax, 0x28(%esp)
0x004996fc:	testb 0x4(%eax), $0x66<UINT8>
0x00499700:	jne 287
0x00499706:	movl %ebp, 0xc(%ebx)
0x00499709:	cmpl %ebp, $0xfffffffe<UINT8>
0x0049970c:	movl %ecx, 0x30(%esp)
0x00499710:	leal %edx, 0x1c(%esp)
0x00499714:	movl 0x1c(%esp), %eax
0x00499718:	movl 0x20(%esp), %ecx
0x0049971c:	movl -4(%ebx), %edx
0x0049971f:	je 94
0x00499721:	leal %eax, (%ebp,%ebp,2)
0x00499725:	movl %ecx, 0x14(%esi,%eax,4)
0x00499729:	testl %ecx, %ecx
0x0049972b:	leal %ebx, 0x10(%esi,%eax,4)
0x0049972f:	movl %eax, (%ebx)
0x00499731:	movl 0x14(%esp), %eax
0x00499735:	je 22
0x00499737:	movl %edx, %edi
0x00499739:	call 0x004a3092
0x004a3092:	pushl %ebp
0x004a3093:	pushl %esi
0x004a3094:	pushl %edi
0x004a3095:	pushl %ebx
0x004a3096:	movl %ebp, %edx
0x004a3098:	xorl %eax, %eax
0x004a309a:	xorl %ebx, %ebx
0x004a309c:	xorl %edx, %edx
0x004a309e:	xorl %esi, %esi
0x004a30a0:	xorl %edi, %edi
0x004a30a2:	call 0x0048f0fa
0x0048f0fa:	xorl %eax, %eax
0x0048f0fc:	incl %eax
0x0048f0fd:	ret

0x004a30a4:	popl %ebx
0x004a30a5:	popl %edi
0x004a30a6:	popl %esi
0x004a30a7:	popl %ebp
0x004a30a8:	ret

0x0049973e:	testl %eax, %eax
0x00499740:	movb 0x13(%esp), $0x1<UINT8>
0x00499745:	jl 68
0x00499747:	jg 0x00499795
0x00499795:	movl %ecx, 0x28(%esp)
0x00499799:	cmpl (%ecx), $0xe06d7363<UINT32>
0x0049979f:	jne 0x004997cb
0x004997cb:	movl %ecx, 0x2c(%esp)
0x004997cf:	call 0x004a30c2
0x004a30c2:	pushl %ebp
0x004a30c3:	movl %ebp, %esp
0x004a30c5:	pushl %ebx
0x004a30c6:	pushl %esi
0x004a30c7:	pushl %edi
0x004a30c8:	pushl $0x0<UINT8>
0x004a30ca:	pushl $0x0<UINT8>
0x004a30cc:	pushl $0x4a30d7<UINT32>
0x004a30d1:	pushl %ecx
0x004a30d2:	call 0x004c1176
0x004c1176:	jmp RtlUnwind@KERNEL32.DLL
RtlUnwind@KERNEL32.DLL: API Node	
0x004a30d7:	popl %edi
0x004a30d8:	popl %esi
0x004a30d9:	popl %ebx
0x004a30da:	popl %ebp
0x004a30db:	ret

0x004997d4:	movl %eax, 0x2c(%esp)
0x004997d8:	cmpl 0xc(%eax), %ebp
0x004997db:	je 0x004997f0
0x004997f0:	movl %ecx, 0x14(%esp)
0x004997f4:	movl 0xc(%eax), %ecx
0x004997f7:	movl %eax, (%esi)
0x004997f9:	cmpl %eax, $0xfffffffe<UINT8>
0x004997fc:	je 0x0049980b
0x0049980b:	movl %ecx, 0xc(%esi)
0x0049980e:	movl %edx, 0x8(%esi)
0x00499811:	addl %ecx, %edi
0x00499813:	xorl %ecx, (%edx,%edi)
0x00499816:	call 0x0048f5da
0x0049981b:	movl %ecx, 0x8(%ebx)
0x0049981e:	movl %edx, %edi
0x00499820:	jmp 0x004a30a9
0x004a30a9:	movl %ebp, %edx
0x004a30ab:	movl %esi, %ecx
0x004a30ad:	movl %eax, %ecx
0x004a30af:	pushl $0x1<UINT8>
0x004a30b1:	call 0x004b8435
0x004b8435:	pushl %ebx
0x004b8436:	pushl %ecx
0x004b8437:	movl %ebx, $0x50b670<UINT32>
0x004b843c:	movl %ecx, 0xc(%esp)
0x004b8440:	movl 0x8(%ebx), %ecx
0x004b8443:	movl 0x4(%ebx), %eax
0x004b8446:	movl 0xc(%ebx), %ebp
0x004b8449:	pushl %ebp
0x004b844a:	pushl %ecx
0x004b844b:	pushl %eax
0x004b844c:	popl %eax
0x004b844d:	popl %ecx
0x004b844e:	popl %ebp
0x004b844f:	popl %ecx
0x004b8450:	popl %ebx
0x004b8451:	ret $0x4<UINT16>

0x004a30b6:	xorl %eax, %eax
0x004a30b8:	xorl %ebx, %ebx
0x004a30ba:	xorl %ecx, %ecx
0x004a30bc:	xorl %edx, %edx
0x004a30be:	xorl %edi, %edi
0x004a30c0:	jmp 0x0048f0fe
0x0048f0fe:	movl %esp, -24(%ebp)
0x0048f101:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0048f108:	movl %eax, $0xff<UINT32>
0x0048f10d:	call 0x00499661
0x00499661:	movl %ecx, -16(%ebp)
0x00499664:	movl %fs:0, %ecx
0x0049966b:	popl %ecx
0x0049966c:	popl %edi
0x0049966d:	popl %edi
0x0049966e:	popl %esi
0x0049966f:	popl %ebx
0x00499670:	movl %esp, %ebp
0x00499672:	popl %ebp
0x00499673:	pushl %ecx
0x00499674:	ret

0x0048f112:	ret

0x7c8000c0:	addb (%eax), %al
0x7c839aa8:	int3
0x7c839aa9:	int3
0x7c839aaa:	int3
0x7c839aab:	int3
0x7c839aac:	int3
0x7c839aad:	int3
0x7c839aae:	int3
0x7c839aaf:	int3
0x7c839ab0:	int3
0x7c839ab1:	int3
0x7c839ab2:	jmp TerminateProcess@kernel32.dll
TerminateProcess@kernel32.dll: API Node	
0x7c9032a8:	addb (%eax), %al
0x7c9032aa:	addb (%eax), %al
0x7c9032ac:	addb (%eax), %al
0x7c9032ae:	addb (%eax), %al
0x7c9032b0:	addb (%eax), %al
0x7c9032b2:	addb (%eax), %al
0x7c9032b4:	addb (%eax), %al
0x7c9032b6:	addb (%eax), %al
0x7c9032b8:	addb (%eax), %al
0x7c9032ba:	addb (%eax), %al
0x7c9032bc:	addb (%eax), %al
0x7c9032be:	addb (%eax), %al
0x7c9032c0:	addb (%eax), %al
0x7c9032c2:	addb (%eax), %al
0x7c9032c4:	addb (%eax), %al
0x7c9032c6:	addb (%eax), %al
0x7c9032c8:	addb (%eax), %al
0x7c9032ca:	addb (%eax), %al
0x7c9032cc:	addb (%eax), %al
0x7c9032ce:	addb (%eax), %al
0x7c9032d0:	addb (%eax), %al
0x7c9032d2:	addb (%eax), %al
0x7c9032d4:	addb (%eax), %al
0x7c9032d6:	addb (%eax), %al
0x7c9032d8:	addb (%eax), %al
0x7c9032da:	addb (%eax), %al
0x7c9032dc:	addb (%eax), %al
0x7c9032de:	addb (%eax), %al
0x7c9032e0:	addb (%eax), %al
0x7c9032e2:	addb (%eax), %al
0x7c9032e4:	addb (%eax), %al
0x7c9032e6:	addb (%eax), %al
0x7c9032e8:	addb (%eax), %al
0x7c9032ea:	addb (%eax), %al
0x7c9032ec:	addb (%eax), %al
0x7c9032ee:	addb (%eax), %al
0x7c9032f0:	addb (%eax), %al
0x7c9032f2:	addb (%eax), %al
0x7c9032f4:	addb (%eax), %al
0x7c9032f6:	addb (%eax), %al
0x7c9032f8:	addb (%eax), %al
0x7c9032fa:	addb (%eax), %al
0x7c9032fc:	addb (%eax), %al
0x7c9032fe:	addb (%eax), %al
0x7c903300:	addb (%eax), %al
0x7c903302:	addb (%eax), %al
0x7c903304:	addb (%eax), %al
0x7c903306:	addb (%eax), %al
0x7c903308:	addb (%eax), %al
0x7c90330a:	addb (%eax), %al
0x7c90330c:	addb (%eax), %al
