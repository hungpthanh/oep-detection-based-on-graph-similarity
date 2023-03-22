0x00426c70:	pusha
0x00426c71:	movl %esi, $0x419000<UINT32>
0x00426c76:	leal %edi, -98304(%esi)
0x00426c7c:	pushl %edi
0x00426c7d:	orl %ebp, $0xffffffff<UINT8>
0x00426c80:	jmp 0x00426c92
0x00426c92:	movl %ebx, (%esi)
0x00426c94:	subl %esi, $0xfffffffc<UINT8>
0x00426c97:	adcl %ebx, %ebx
0x00426c99:	jb 0x00426c88
0x00426c88:	movb %al, (%esi)
0x00426c8a:	incl %esi
0x00426c8b:	movb (%edi), %al
0x00426c8d:	incl %edi
0x00426c8e:	addl %ebx, %ebx
0x00426c90:	jne 0x00426c99
0x00426c9b:	movl %eax, $0x1<UINT32>
0x00426ca0:	addl %ebx, %ebx
0x00426ca2:	jne 0x00426cab
0x00426cab:	adcl %eax, %eax
0x00426cad:	addl %ebx, %ebx
0x00426caf:	jae 0x00426ca0
0x00426cb1:	jne 0x00426cbc
0x00426cbc:	xorl %ecx, %ecx
0x00426cbe:	subl %eax, $0x3<UINT8>
0x00426cc1:	jb 0x00426cd0
0x00426cd0:	addl %ebx, %ebx
0x00426cd2:	jne 0x00426cdb
0x00426cdb:	adcl %ecx, %ecx
0x00426cdd:	addl %ebx, %ebx
0x00426cdf:	jne 0x00426ce8
0x00426ce8:	adcl %ecx, %ecx
0x00426cea:	jne 0x00426d0c
0x00426d0c:	cmpl %ebp, $0xfffff300<UINT32>
0x00426d12:	adcl %ecx, $0x1<UINT8>
0x00426d15:	leal %edx, (%edi,%ebp)
0x00426d18:	cmpl %ebp, $0xfffffffc<UINT8>
0x00426d1b:	jbe 0x00426d2c
0x00426d1d:	movb %al, (%edx)
0x00426d1f:	incl %edx
0x00426d20:	movb (%edi), %al
0x00426d22:	incl %edi
0x00426d23:	decl %ecx
0x00426d24:	jne 0x00426d1d
0x00426d26:	jmp 0x00426c8e
0x00426cc3:	shll %eax, $0x8<UINT8>
0x00426cc6:	movb %al, (%esi)
0x00426cc8:	incl %esi
0x00426cc9:	xorl %eax, $0xffffffff<UINT8>
0x00426ccc:	je 0x00426d42
0x00426cce:	movl %ebp, %eax
0x00426d2c:	movl %eax, (%edx)
0x00426d2e:	addl %edx, $0x4<UINT8>
0x00426d31:	movl (%edi), %eax
0x00426d33:	addl %edi, $0x4<UINT8>
0x00426d36:	subl %ecx, $0x4<UINT8>
0x00426d39:	ja 0x00426d2c
0x00426d3b:	addl %edi, %ecx
0x00426d3d:	jmp 0x00426c8e
0x00426cec:	incl %ecx
0x00426ced:	addl %ebx, %ebx
0x00426cef:	jne 0x00426cf8
0x00426cf8:	adcl %ecx, %ecx
0x00426cfa:	addl %ebx, %ebx
0x00426cfc:	jae 0x00426ced
0x00426cfe:	jne 0x00426d09
0x00426d09:	addl %ecx, $0x2<UINT8>
0x00426cf1:	movl %ebx, (%esi)
0x00426cf3:	subl %esi, $0xfffffffc<UINT8>
0x00426cf6:	adcl %ebx, %ebx
0x00426ce1:	movl %ebx, (%esi)
0x00426ce3:	subl %esi, $0xfffffffc<UINT8>
0x00426ce6:	adcl %ebx, %ebx
0x00426ca4:	movl %ebx, (%esi)
0x00426ca6:	subl %esi, $0xfffffffc<UINT8>
0x00426ca9:	adcl %ebx, %ebx
0x00426cb3:	movl %ebx, (%esi)
0x00426cb5:	subl %esi, $0xfffffffc<UINT8>
0x00426cb8:	adcl %ebx, %ebx
0x00426cba:	jae 0x00426ca0
0x00426cd4:	movl %ebx, (%esi)
0x00426cd6:	subl %esi, $0xfffffffc<UINT8>
0x00426cd9:	adcl %ebx, %ebx
0x00426d00:	movl %ebx, (%esi)
0x00426d02:	subl %esi, $0xfffffffc<UINT8>
0x00426d05:	adcl %ebx, %ebx
0x00426d07:	jae 0x00426ced
0x00426d42:	popl %esi
0x00426d43:	movl %edi, %esi
0x00426d45:	movl %ecx, $0x670<UINT32>
0x00426d4a:	movb %al, (%edi)
0x00426d4c:	incl %edi
0x00426d4d:	subb %al, $0xffffffe8<UINT8>
0x00426d4f:	cmpb %al, $0x1<UINT8>
0x00426d51:	ja 0x00426d4a
0x00426d53:	cmpb (%edi), $0x5<UINT8>
0x00426d56:	jne 0x00426d4a
0x00426d58:	movl %eax, (%edi)
0x00426d5a:	movb %bl, 0x4(%edi)
0x00426d5d:	shrw %ax, $0x8<UINT8>
0x00426d61:	roll %eax, $0x10<UINT8>
0x00426d64:	xchgb %ah, %al
0x00426d66:	subl %eax, %edi
0x00426d68:	subb %bl, $0xffffffe8<UINT8>
0x00426d6b:	addl %eax, %esi
0x00426d6d:	movl (%edi), %eax
0x00426d6f:	addl %edi, $0x5<UINT8>
0x00426d72:	movb %al, %bl
0x00426d74:	loop 0x00426d4f
0x00426d76:	leal %edi, 0x24000(%esi)
0x00426d7c:	movl %eax, (%edi)
0x00426d7e:	orl %eax, %eax
0x00426d80:	je 0x00426dc7
0x00426d82:	movl %ebx, 0x4(%edi)
0x00426d85:	leal %eax, 0x26558(%eax,%esi)
0x00426d8c:	addl %ebx, %esi
0x00426d8e:	pushl %eax
0x00426d8f:	addl %edi, $0x8<UINT8>
0x00426d92:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x00426d98:	xchgl %ebp, %eax
0x00426d99:	movb %al, (%edi)
0x00426d9b:	incl %edi
0x00426d9c:	orb %al, %al
0x00426d9e:	je 0x00426d7c
0x00426da0:	movl %ecx, %edi
0x00426da2:	jns 0x00426dab
0x00426dab:	pushl %edi
0x00426dac:	decl %eax
0x00426dad:	repn scasb %al, %es:(%edi)
0x00426daf:	pushl %ebp
0x00426db0:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00426db6:	orl %eax, %eax
0x00426db8:	je 7
0x00426dba:	movl (%ebx), %eax
0x00426dbc:	addl %ebx, $0x4<UINT8>
0x00426dbf:	jmp 0x00426d99
GetProcAddress@KERNEL32.DLL: API Node	
0x00426da4:	movzwl %eax, (%edi)
0x00426da7:	incl %edi
0x00426da8:	pushl %eax
0x00426da9:	incl %edi
0x00426daa:	movl %ecx, $0xaef24857<UINT32>
0x00426dc7:	movl %ebp, 0x2661c(%esi)
0x00426dcd:	leal %edi, -4096(%esi)
0x00426dd3:	movl %ebx, $0x1000<UINT32>
0x00426dd8:	pushl %eax
0x00426dd9:	pushl %esp
0x00426dda:	pushl $0x4<UINT8>
0x00426ddc:	pushl %ebx
0x00426ddd:	pushl %edi
0x00426dde:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00426de0:	leal %eax, 0x217(%edi)
0x00426de6:	andb (%eax), $0x7f<UINT8>
0x00426de9:	andb 0x28(%eax), $0x7f<UINT8>
0x00426ded:	popl %eax
0x00426dee:	pushl %eax
0x00426def:	pushl %esp
0x00426df0:	pushl %eax
0x00426df1:	pushl %ebx
0x00426df2:	pushl %edi
0x00426df3:	call VirtualProtect@kernel32.dll
0x00426df5:	popl %eax
0x00426df6:	popa
0x00426df7:	leal %eax, -128(%esp)
0x00426dfb:	pushl $0x0<UINT8>
0x00426dfd:	cmpl %esp, %eax
0x00426dff:	jne 0x00426dfb
0x00426e01:	subl %esp, $0xffffff80<UINT8>
0x00426e04:	jmp 0x00404c99
0x00404c99:	call 0x0040a714
0x0040a714:	pushl %ebp
0x0040a715:	movl %ebp, %esp
0x0040a717:	subl %esp, $0x14<UINT8>
0x0040a71a:	andl -12(%ebp), $0x0<UINT8>
0x0040a71e:	andl -8(%ebp), $0x0<UINT8>
0x0040a722:	movl %eax, 0x420284
0x0040a727:	pushl %esi
0x0040a728:	pushl %edi
0x0040a729:	movl %edi, $0xbb40e64e<UINT32>
0x0040a72e:	movl %esi, $0xffff0000<UINT32>
0x0040a733:	cmpl %eax, %edi
0x0040a735:	je 0x0040a744
0x0040a744:	leal %eax, -12(%ebp)
0x0040a747:	pushl %eax
0x0040a748:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040a74e:	movl %eax, -8(%ebp)
0x0040a751:	xorl %eax, -12(%ebp)
0x0040a754:	movl -4(%ebp), %eax
0x0040a757:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040a75d:	xorl -4(%ebp), %eax
0x0040a760:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040a766:	xorl -4(%ebp), %eax
0x0040a769:	leal %eax, -20(%ebp)
0x0040a76c:	pushl %eax
0x0040a76d:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040a773:	movl %ecx, -16(%ebp)
0x0040a776:	leal %eax, -4(%ebp)
0x0040a779:	xorl %ecx, -20(%ebp)
0x0040a77c:	xorl %ecx, -4(%ebp)
0x0040a77f:	xorl %ecx, %eax
0x0040a781:	cmpl %ecx, %edi
0x0040a783:	jne 0x0040a78c
0x0040a78c:	testl %esi, %ecx
0x0040a78e:	jne 0x0040a79c
0x0040a79c:	movl 0x420284, %ecx
0x0040a7a2:	notl %ecx
0x0040a7a4:	movl 0x420288, %ecx
0x0040a7aa:	popl %edi
0x0040a7ab:	popl %esi
0x0040a7ac:	movl %esp, %ebp
0x0040a7ae:	popl %ebp
0x0040a7af:	ret

0x00404c9e:	jmp 0x00404b1e
0x00404b1e:	pushl $0x14<UINT8>
0x00404b20:	pushl $0x41e938<UINT32>
0x00404b25:	call 0x00406aa0
0x00406aa0:	pushl $0x406b00<UINT32>
0x00406aa5:	pushl %fs:0
0x00406aac:	movl %eax, 0x10(%esp)
0x00406ab0:	movl 0x10(%esp), %ebp
0x00406ab4:	leal %ebp, 0x10(%esp)
0x00406ab8:	subl %esp, %eax
0x00406aba:	pushl %ebx
0x00406abb:	pushl %esi
0x00406abc:	pushl %edi
0x00406abd:	movl %eax, 0x420284
0x00406ac2:	xorl -4(%ebp), %eax
0x00406ac5:	xorl %eax, %ebp
0x00406ac7:	pushl %eax
0x00406ac8:	movl -24(%ebp), %esp
0x00406acb:	pushl -8(%ebp)
0x00406ace:	movl %eax, -4(%ebp)
0x00406ad1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00406ad8:	movl -8(%ebp), %eax
0x00406adb:	leal %eax, -16(%ebp)
0x00406ade:	movl %fs:0, %eax
0x00406ae4:	ret

0x00404b2a:	pushl $0x1<UINT8>
0x00404b2c:	call 0x0040a6c7
0x0040a6c7:	pushl %ebp
0x0040a6c8:	movl %ebp, %esp
0x0040a6ca:	movl %eax, 0x8(%ebp)
0x0040a6cd:	movl 0x421618, %eax
0x0040a6d2:	popl %ebp
0x0040a6d3:	ret

0x00404b31:	popl %ecx
0x00404b32:	movl %eax, $0x5a4d<UINT32>
0x00404b37:	cmpw 0x400000, %ax
0x00404b3e:	je 0x00404b44
0x00404b44:	movl %eax, 0x40003c
0x00404b49:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00404b53:	jne -21
0x00404b55:	movl %ecx, $0x10b<UINT32>
0x00404b5a:	cmpw 0x400018(%eax), %cx
0x00404b61:	jne -35
0x00404b63:	xorl %ebx, %ebx
0x00404b65:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00404b6c:	jbe 9
0x00404b6e:	cmpl 0x4000e8(%eax), %ebx
0x00404b74:	setne %bl
0x00404b77:	movl -28(%ebp), %ebx
0x00404b7a:	call 0x00406ee1
0x00406ee1:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x00406ee7:	xorl %ecx, %ecx
0x00406ee9:	movl 0x421c4c, %eax
0x00406eee:	testl %eax, %eax
0x00406ef0:	setne %cl
0x00406ef3:	movl %eax, %ecx
0x00406ef5:	ret

0x00404b7f:	testl %eax, %eax
0x00404b81:	jne 0x00404b8b
0x00404b8b:	call 0x00405ba5
0x00405ba5:	call 0x004041c0
0x004041c0:	pushl %esi
0x004041c1:	pushl $0x0<UINT8>
0x004041c3:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x004041c9:	movl %esi, %eax
0x004041cb:	pushl %esi
0x004041cc:	call 0x00406cba
0x00406cba:	pushl %ebp
0x00406cbb:	movl %ebp, %esp
0x00406cbd:	movl %eax, 0x8(%ebp)
0x00406cc0:	movl 0x421614, %eax
0x00406cc5:	popl %ebp
0x00406cc6:	ret

0x004041d1:	pushl %esi
0x004041d2:	call 0x00404dc8
0x00404dc8:	pushl %ebp
0x00404dc9:	movl %ebp, %esp
0x00404dcb:	movl %eax, 0x8(%ebp)
0x00404dce:	movl 0x4215e8, %eax
0x00404dd3:	popl %ebp
0x00404dd4:	ret

0x004041d7:	pushl %esi
0x004041d8:	call 0x00409930
0x00409930:	pushl %ebp
0x00409931:	movl %ebp, %esp
0x00409933:	movl %eax, 0x8(%ebp)
0x00409936:	movl 0x421eb0, %eax
0x0040993b:	popl %ebp
0x0040993c:	ret

0x004041dd:	pushl %esi
0x004041de:	call 0x0040994a
0x0040994a:	pushl %ebp
0x0040994b:	movl %ebp, %esp
0x0040994d:	movl %eax, 0x8(%ebp)
0x00409950:	movl 0x421eb4, %eax
0x00409955:	movl 0x421eb8, %eax
0x0040995a:	movl 0x421ebc, %eax
0x0040995f:	movl 0x421ec0, %eax
0x00409964:	popl %ebp
0x00409965:	ret

0x004041e3:	pushl %esi
0x004041e4:	call 0x0040991f
0x0040991f:	pushl $0x4098d8<UINT32>
0x00409924:	call EncodePointer@KERNEL32.DLL
0x0040992a:	movl 0x421eac, %eax
0x0040992f:	ret

0x004041e9:	pushl %esi
0x004041ea:	call 0x00409b5b
0x00409b5b:	pushl %ebp
0x00409b5c:	movl %ebp, %esp
0x00409b5e:	movl %eax, 0x8(%ebp)
0x00409b61:	movl 0x421ec8, %eax
0x00409b66:	popl %ebp
0x00409b67:	ret

0x004041ef:	addl %esp, $0x18<UINT8>
0x004041f2:	popl %esi
0x004041f3:	jmp 0x00408418
0x00408418:	pushl %esi
0x00408419:	pushl %edi
0x0040841a:	pushl $0x41e3e4<UINT32>
0x0040841f:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00408425:	movl %esi, 0x41308c
0x0040842b:	movl %edi, %eax
0x0040842d:	pushl $0x414444<UINT32>
0x00408432:	pushl %edi
0x00408433:	call GetProcAddress@KERNEL32.DLL
0x00408435:	xorl %eax, 0x420284
0x0040843b:	pushl $0x414450<UINT32>
0x00408440:	pushl %edi
0x00408441:	movl 0x422180, %eax
0x00408446:	call GetProcAddress@KERNEL32.DLL
0x00408448:	xorl %eax, 0x420284
0x0040844e:	pushl $0x414458<UINT32>
0x00408453:	pushl %edi
0x00408454:	movl 0x422184, %eax
0x00408459:	call GetProcAddress@KERNEL32.DLL
0x0040845b:	xorl %eax, 0x420284
0x00408461:	pushl $0x414464<UINT32>
0x00408466:	pushl %edi
0x00408467:	movl 0x422188, %eax
0x0040846c:	call GetProcAddress@KERNEL32.DLL
0x0040846e:	xorl %eax, 0x420284
0x00408474:	pushl $0x414470<UINT32>
0x00408479:	pushl %edi
0x0040847a:	movl 0x42218c, %eax
0x0040847f:	call GetProcAddress@KERNEL32.DLL
0x00408481:	xorl %eax, 0x420284
0x00408487:	pushl $0x41448c<UINT32>
0x0040848c:	pushl %edi
0x0040848d:	movl 0x422190, %eax
0x00408492:	call GetProcAddress@KERNEL32.DLL
0x00408494:	xorl %eax, 0x420284
0x0040849a:	pushl $0x41449c<UINT32>
0x0040849f:	pushl %edi
0x004084a0:	movl 0x422194, %eax
0x004084a5:	call GetProcAddress@KERNEL32.DLL
0x004084a7:	xorl %eax, 0x420284
0x004084ad:	pushl $0x4144b0<UINT32>
0x004084b2:	pushl %edi
0x004084b3:	movl 0x422198, %eax
0x004084b8:	call GetProcAddress@KERNEL32.DLL
0x004084ba:	xorl %eax, 0x420284
0x004084c0:	pushl $0x4144c8<UINT32>
0x004084c5:	pushl %edi
0x004084c6:	movl 0x42219c, %eax
0x004084cb:	call GetProcAddress@KERNEL32.DLL
0x004084cd:	xorl %eax, 0x420284
0x004084d3:	pushl $0x4144e0<UINT32>
0x004084d8:	pushl %edi
0x004084d9:	movl 0x4221a0, %eax
0x004084de:	call GetProcAddress@KERNEL32.DLL
0x004084e0:	xorl %eax, 0x420284
0x004084e6:	pushl $0x4144f4<UINT32>
0x004084eb:	pushl %edi
0x004084ec:	movl 0x4221a4, %eax
0x004084f1:	call GetProcAddress@KERNEL32.DLL
0x004084f3:	xorl %eax, 0x420284
0x004084f9:	pushl $0x414514<UINT32>
0x004084fe:	pushl %edi
0x004084ff:	movl 0x4221a8, %eax
0x00408504:	call GetProcAddress@KERNEL32.DLL
0x00408506:	xorl %eax, 0x420284
0x0040850c:	pushl $0x41452c<UINT32>
0x00408511:	pushl %edi
0x00408512:	movl 0x4221ac, %eax
0x00408517:	call GetProcAddress@KERNEL32.DLL
0x00408519:	xorl %eax, 0x420284
0x0040851f:	pushl $0x414544<UINT32>
0x00408524:	pushl %edi
0x00408525:	movl 0x4221b0, %eax
0x0040852a:	call GetProcAddress@KERNEL32.DLL
0x0040852c:	xorl %eax, 0x420284
0x00408532:	pushl $0x414558<UINT32>
0x00408537:	pushl %edi
0x00408538:	movl 0x4221b4, %eax
0x0040853d:	call GetProcAddress@KERNEL32.DLL
0x0040853f:	xorl %eax, 0x420284
0x00408545:	movl 0x4221b8, %eax
0x0040854a:	pushl $0x41456c<UINT32>
0x0040854f:	pushl %edi
0x00408550:	call GetProcAddress@KERNEL32.DLL
0x00408552:	xorl %eax, 0x420284
0x00408558:	pushl $0x414588<UINT32>
0x0040855d:	pushl %edi
0x0040855e:	movl 0x4221bc, %eax
0x00408563:	call GetProcAddress@KERNEL32.DLL
0x00408565:	xorl %eax, 0x420284
0x0040856b:	pushl $0x4145a8<UINT32>
0x00408570:	pushl %edi
0x00408571:	movl 0x4221c0, %eax
0x00408576:	call GetProcAddress@KERNEL32.DLL
0x00408578:	xorl %eax, 0x420284
0x0040857e:	pushl $0x4145c4<UINT32>
0x00408583:	pushl %edi
0x00408584:	movl 0x4221c4, %eax
0x00408589:	call GetProcAddress@KERNEL32.DLL
0x0040858b:	xorl %eax, 0x420284
0x00408591:	pushl $0x4145e4<UINT32>
0x00408596:	pushl %edi
0x00408597:	movl 0x4221c8, %eax
0x0040859c:	call GetProcAddress@KERNEL32.DLL
0x0040859e:	xorl %eax, 0x420284
0x004085a4:	pushl $0x4145f8<UINT32>
0x004085a9:	pushl %edi
0x004085aa:	movl 0x4221cc, %eax
0x004085af:	call GetProcAddress@KERNEL32.DLL
0x004085b1:	xorl %eax, 0x420284
0x004085b7:	pushl $0x414614<UINT32>
0x004085bc:	pushl %edi
0x004085bd:	movl 0x4221d0, %eax
0x004085c2:	call GetProcAddress@KERNEL32.DLL
0x004085c4:	xorl %eax, 0x420284
0x004085ca:	pushl $0x414628<UINT32>
0x004085cf:	pushl %edi
0x004085d0:	movl 0x4221d8, %eax
0x004085d5:	call GetProcAddress@KERNEL32.DLL
0x004085d7:	xorl %eax, 0x420284
0x004085dd:	pushl $0x414638<UINT32>
0x004085e2:	pushl %edi
0x004085e3:	movl 0x4221d4, %eax
0x004085e8:	call GetProcAddress@KERNEL32.DLL
0x004085ea:	xorl %eax, 0x420284
0x004085f0:	pushl $0x414648<UINT32>
0x004085f5:	pushl %edi
0x004085f6:	movl 0x4221dc, %eax
0x004085fb:	call GetProcAddress@KERNEL32.DLL
0x004085fd:	xorl %eax, 0x420284
0x00408603:	pushl $0x414658<UINT32>
0x00408608:	pushl %edi
0x00408609:	movl 0x4221e0, %eax
0x0040860e:	call GetProcAddress@KERNEL32.DLL
0x00408610:	xorl %eax, 0x420284
0x00408616:	pushl $0x414668<UINT32>
0x0040861b:	pushl %edi
0x0040861c:	movl 0x4221e4, %eax
0x00408621:	call GetProcAddress@KERNEL32.DLL
0x00408623:	xorl %eax, 0x420284
0x00408629:	pushl $0x414684<UINT32>
0x0040862e:	pushl %edi
0x0040862f:	movl 0x4221e8, %eax
0x00408634:	call GetProcAddress@KERNEL32.DLL
0x00408636:	xorl %eax, 0x420284
0x0040863c:	pushl $0x414698<UINT32>
0x00408641:	pushl %edi
0x00408642:	movl 0x4221ec, %eax
0x00408647:	call GetProcAddress@KERNEL32.DLL
0x00408649:	xorl %eax, 0x420284
0x0040864f:	pushl $0x4146a8<UINT32>
0x00408654:	pushl %edi
0x00408655:	movl 0x4221f0, %eax
0x0040865a:	call GetProcAddress@KERNEL32.DLL
0x0040865c:	xorl %eax, 0x420284
0x00408662:	pushl $0x4146bc<UINT32>
0x00408667:	pushl %edi
0x00408668:	movl 0x4221f4, %eax
0x0040866d:	call GetProcAddress@KERNEL32.DLL
0x0040866f:	xorl %eax, 0x420284
0x00408675:	movl 0x4221f8, %eax
0x0040867a:	pushl $0x4146cc<UINT32>
0x0040867f:	pushl %edi
0x00408680:	call GetProcAddress@KERNEL32.DLL
0x00408682:	xorl %eax, 0x420284
0x00408688:	pushl $0x4146ec<UINT32>
0x0040868d:	pushl %edi
0x0040868e:	movl 0x4221fc, %eax
0x00408693:	call GetProcAddress@KERNEL32.DLL
0x00408695:	xorl %eax, 0x420284
0x0040869b:	popl %edi
0x0040869c:	movl 0x422200, %eax
0x004086a1:	popl %esi
0x004086a2:	ret

0x00405baa:	call 0x004070c4
0x004070c4:	pushl %esi
0x004070c5:	pushl %edi
0x004070c6:	movl %esi, $0x420b60<UINT32>
0x004070cb:	movl %edi, $0x421c50<UINT32>
0x004070d0:	cmpl 0x4(%esi), $0x1<UINT8>
0x004070d4:	jne 22
0x004070d6:	pushl $0x0<UINT8>
0x004070d8:	movl (%esi), %edi
0x004070da:	addl %edi, $0x18<UINT8>
0x004070dd:	pushl $0xfa0<UINT32>
0x004070e2:	pushl (%esi)
0x004070e4:	call 0x004083aa
0x004083aa:	pushl %ebp
0x004083ab:	movl %ebp, %esp
0x004083ad:	movl %eax, 0x422190
0x004083b2:	xorl %eax, 0x420284
0x004083b8:	je 13
0x004083ba:	pushl 0x10(%ebp)
0x004083bd:	pushl 0xc(%ebp)
0x004083c0:	pushl 0x8(%ebp)
0x004083c3:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x004083c5:	popl %ebp
0x004083c6:	ret

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
