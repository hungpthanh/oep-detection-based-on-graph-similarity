0x00484c90:	pusha
0x00484c91:	movl %esi, $0x460000<UINT32>
0x00484c96:	leal %edi, -389120(%esi)
0x00484c9c:	pushl %edi
0x00484c9d:	jmp 0x00484caa
0x00484caa:	movl %ebx, (%esi)
0x00484cac:	subl %esi, $0xfffffffc<UINT8>
0x00484caf:	adcl %ebx, %ebx
0x00484cb1:	jb 0x00484ca0
0x00484ca0:	movb %al, (%esi)
0x00484ca2:	incl %esi
0x00484ca3:	movb (%edi), %al
0x00484ca5:	incl %edi
0x00484ca6:	addl %ebx, %ebx
0x00484ca8:	jne 0x00484cb1
0x00484cb3:	movl %eax, $0x1<UINT32>
0x00484cb8:	addl %ebx, %ebx
0x00484cba:	jne 0x00484cc3
0x00484cc3:	adcl %eax, %eax
0x00484cc5:	addl %ebx, %ebx
0x00484cc7:	jae 0x00484cd4
0x00484cc9:	jne 0x00484cf3
0x00484cf3:	xorl %ecx, %ecx
0x00484cf5:	subl %eax, $0x3<UINT8>
0x00484cf8:	jb 0x00484d0b
0x00484cfa:	shll %eax, $0x8<UINT8>
0x00484cfd:	movb %al, (%esi)
0x00484cff:	incl %esi
0x00484d00:	xorl %eax, $0xffffffff<UINT8>
0x00484d03:	je 0x00484d7a
0x00484d05:	sarl %eax
0x00484d07:	movl %ebp, %eax
0x00484d09:	jmp 0x00484d16
0x00484d16:	jb 0x00484ce4
0x00484d18:	incl %ecx
0x00484d19:	addl %ebx, %ebx
0x00484d1b:	jne 0x00484d24
0x00484d24:	jb 0x00484ce4
0x00484d26:	addl %ebx, %ebx
0x00484d28:	jne 0x00484d31
0x00484d31:	adcl %ecx, %ecx
0x00484d33:	addl %ebx, %ebx
0x00484d35:	jae 0x00484d26
0x00484d37:	jne 0x00484d42
0x00484d42:	addl %ecx, $0x2<UINT8>
0x00484d45:	cmpl %ebp, $0xfffffb00<UINT32>
0x00484d4b:	adcl %ecx, $0x2<UINT8>
0x00484d4e:	leal %edx, (%edi,%ebp)
0x00484d51:	cmpl %ebp, $0xfffffffc<UINT8>
0x00484d54:	jbe 0x00484d64
0x00484d64:	movl %eax, (%edx)
0x00484d66:	addl %edx, $0x4<UINT8>
0x00484d69:	movl (%edi), %eax
0x00484d6b:	addl %edi, $0x4<UINT8>
0x00484d6e:	subl %ecx, $0x4<UINT8>
0x00484d71:	ja 0x00484d64
0x00484d73:	addl %edi, %ecx
0x00484d75:	jmp 0x00484ca6
0x00484ce4:	addl %ebx, %ebx
0x00484ce6:	jne 0x00484cef
0x00484cef:	adcl %ecx, %ecx
0x00484cf1:	jmp 0x00484d45
0x00484d56:	movb %al, (%edx)
0x00484d58:	incl %edx
0x00484d59:	movb (%edi), %al
0x00484d5b:	incl %edi
0x00484d5c:	decl %ecx
0x00484d5d:	jne 0x00484d56
0x00484d5f:	jmp 0x00484ca6
0x00484ccb:	movl %ebx, (%esi)
0x00484ccd:	subl %esi, $0xfffffffc<UINT8>
0x00484cd0:	adcl %ebx, %ebx
0x00484cd2:	jb 0x00484cf3
0x00484d0b:	addl %ebx, %ebx
0x00484d0d:	jne 0x00484d16
0x00484d0f:	movl %ebx, (%esi)
0x00484d11:	subl %esi, $0xfffffffc<UINT8>
0x00484d14:	adcl %ebx, %ebx
0x00484d39:	movl %ebx, (%esi)
0x00484d3b:	subl %esi, $0xfffffffc<UINT8>
0x00484d3e:	adcl %ebx, %ebx
0x00484d40:	jae 0x00484d26
0x00484cbc:	movl %ebx, (%esi)
0x00484cbe:	subl %esi, $0xfffffffc<UINT8>
0x00484cc1:	adcl %ebx, %ebx
0x00484cd4:	decl %eax
0x00484cd5:	addl %ebx, %ebx
0x00484cd7:	jne 0x00484ce0
0x00484ce0:	adcl %eax, %eax
0x00484ce2:	jmp 0x00484cb8
0x00484cd9:	movl %ebx, (%esi)
0x00484cdb:	subl %esi, $0xfffffffc<UINT8>
0x00484cde:	adcl %ebx, %ebx
0x00484d1d:	movl %ebx, (%esi)
0x00484d1f:	subl %esi, $0xfffffffc<UINT8>
0x00484d22:	adcl %ebx, %ebx
0x00484d2a:	movl %ebx, (%esi)
0x00484d2c:	subl %esi, $0xfffffffc<UINT8>
0x00484d2f:	adcl %ebx, %ebx
0x00484ce8:	movl %ebx, (%esi)
0x00484cea:	subl %esi, $0xfffffffc<UINT8>
0x00484ced:	adcl %ebx, %ebx
0x00484d7a:	popl %esi
0x00484d7b:	movl %edi, %esi
0x00484d7d:	movl %ecx, $0x144b<UINT32>
0x00484d82:	movb %al, (%edi)
0x00484d84:	incl %edi
0x00484d85:	subb %al, $0xffffffe8<UINT8>
0x00484d87:	cmpb %al, $0x1<UINT8>
0x00484d89:	ja 0x00484d82
0x00484d8b:	cmpb (%edi), $0x13<UINT8>
0x00484d8e:	jne 0x00484d82
0x00484d90:	movl %eax, (%edi)
0x00484d92:	movb %bl, 0x4(%edi)
0x00484d95:	shrw %ax, $0x8<UINT8>
0x00484d99:	roll %eax, $0x10<UINT8>
0x00484d9c:	xchgb %ah, %al
0x00484d9e:	subl %eax, %edi
0x00484da0:	subb %bl, $0xffffffe8<UINT8>
0x00484da3:	addl %eax, %esi
0x00484da5:	movl (%edi), %eax
0x00484da7:	addl %edi, $0x5<UINT8>
0x00484daa:	movb %al, %bl
0x00484dac:	loop 0x00484d87
0x00484dae:	leal %edi, 0x81000(%esi)
0x00484db4:	movl %eax, (%edi)
0x00484db6:	orl %eax, %eax
0x00484db8:	je 0x00484dff
0x00484dba:	movl %ebx, 0x4(%edi)
0x00484dbd:	leal %eax, 0x84ed4(%eax,%esi)
0x00484dc4:	addl %ebx, %esi
0x00484dc6:	pushl %eax
0x00484dc7:	addl %edi, $0x8<UINT8>
0x00484dca:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00484dd0:	xchgl %ebp, %eax
0x00484dd1:	movb %al, (%edi)
0x00484dd3:	incl %edi
0x00484dd4:	orb %al, %al
0x00484dd6:	je 0x00484db4
0x00484dd8:	movl %ecx, %edi
0x00484dda:	jns 0x00484de3
0x00484de3:	pushl %edi
0x00484de4:	decl %eax
0x00484de5:	repn scasb %al, %es:(%edi)
0x00484de7:	pushl %ebp
0x00484de8:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00484dee:	orl %eax, %eax
0x00484df0:	je 7
0x00484df2:	movl (%ebx), %eax
0x00484df4:	addl %ebx, $0x4<UINT8>
0x00484df7:	jmp 0x00484dd1
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x00484ddc:	movzwl %eax, (%edi)
0x00484ddf:	incl %edi
0x00484de0:	pushl %eax
0x00484de1:	incl %edi
0x00484de2:	movl %ecx, $0xaef24857<UINT32>
0x00484dff:	movl %ebp, 0x85018(%esi)
0x00484e05:	leal %edi, -4096(%esi)
0x00484e0b:	movl %ebx, $0x1000<UINT32>
0x00484e10:	pushl %eax
0x00484e11:	pushl %esp
0x00484e12:	pushl $0x4<UINT8>
0x00484e14:	pushl %ebx
0x00484e15:	pushl %edi
0x00484e16:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00484e18:	leal %eax, 0x21f(%edi)
0x00484e1e:	andb (%eax), $0x7f<UINT8>
0x00484e21:	andb 0x28(%eax), $0x7f<UINT8>
0x00484e25:	popl %eax
0x00484e26:	pushl %eax
0x00484e27:	pushl %esp
0x00484e28:	pushl %eax
0x00484e29:	pushl %ebx
0x00484e2a:	pushl %edi
0x00484e2b:	call VirtualProtect@kernel32.dll
0x00484e2d:	popl %eax
0x00484e2e:	popa
0x00484e2f:	leal %eax, -128(%esp)
0x00484e33:	pushl $0x0<UINT8>
0x00484e35:	cmpl %esp, %eax
0x00484e37:	jne 0x00484e33
0x00484e39:	subl %esp, $0xffffff80<UINT8>
0x00484e3c:	jmp 0x00411e58
0x00411e58:	pushl %ebp
0x00411e59:	movl %ebp, %esp
0x00411e5b:	pushl $0xffffffff<UINT8>
0x00411e5d:	pushl $0x46a240<UINT32>
0x00411e62:	pushl $0x4159d0<UINT32>
0x00411e67:	movl %eax, %fs:0
0x00411e6d:	pushl %eax
0x00411e6e:	movl %fs:0, %esp
0x00411e75:	subl %esp, $0x58<UINT8>
0x00411e78:	pushl %ebx
0x00411e79:	pushl %esi
0x00411e7a:	pushl %edi
0x00411e7b:	movl -24(%ebp), %esp
0x00411e7e:	call GetVersion@KERNEL32.DLL
GetVersion@KERNEL32.DLL: API Node	
0x00411e84:	xorl %edx, %edx
0x00411e86:	movb %dl, %ah
0x00411e88:	movl 0x479564, %edx
0x00411e8e:	movl %ecx, %eax
0x00411e90:	andl %ecx, $0xff<UINT32>
0x00411e96:	movl 0x479560, %ecx
0x00411e9c:	shll %ecx, $0x8<UINT8>
0x00411e9f:	addl %ecx, %edx
0x00411ea1:	movl 0x47955c, %ecx
0x00411ea7:	shrl %eax, $0x10<UINT8>
0x00411eaa:	movl 0x479558, %eax
0x00411eaf:	pushl $0x1<UINT8>
0x00411eb1:	call 0x00414755
0x00414755:	xorl %eax, %eax
0x00414757:	pushl $0x0<UINT8>
0x00414759:	cmpl 0x8(%esp), %eax
0x0041475d:	pushl $0x1000<UINT32>
0x00414762:	sete %al
0x00414765:	pushl %eax
0x00414766:	call HeapCreate@KERNEL32.DLL
HeapCreate@KERNEL32.DLL: API Node	
0x0041476c:	testl %eax, %eax
0x0041476e:	movl 0x47aa60, %eax
0x00414773:	je 54
0x00414775:	call 0x0041460d
0x0041460d:	pushl %ebp
0x0041460e:	movl %ebp, %esp
0x00414610:	movl %eax, $0x122c<UINT32>
0x00414615:	call 0x00411e20
0x00411e20:	pushl %ecx
0x00411e21:	cmpl %eax, $0x1000<UINT32>
0x00411e26:	leal %ecx, 0x8(%esp)
0x00411e2a:	jb 0x00411e40
0x00411e2c:	subl %ecx, $0x1000<UINT32>
0x00411e32:	subl %eax, $0x1000<UINT32>
0x00411e37:	testl (%ecx), %eax
0x00411e39:	cmpl %eax, $0x1000<UINT32>
0x00411e3e:	jae -20
0x00411e40:	subl %ecx, %eax
0x00411e42:	movl %eax, %esp
0x00411e44:	testl (%ecx), %eax
0x00411e46:	movl %esp, %ecx
0x00411e48:	movl %ecx, (%eax)
0x00411e4a:	movl %eax, 0x4(%eax)
0x00411e4d:	pushl %eax
0x00411e4e:	ret

0x0041461a:	leal %eax, -152(%ebp)
0x00414620:	pushl %ebx
0x00414621:	pushl %eax
0x00414622:	movl -152(%ebp), $0x94<UINT32>
0x0041462c:	call GetVersionExA@KERNEL32.DLL
GetVersionExA@KERNEL32.DLL: API Node	
0x00414632:	testl %eax, %eax
0x00414634:	je 26
0x00414636:	cmpl -136(%ebp), $0x2<UINT8>
0x0041463d:	jne 17
0x0041463f:	cmpl -148(%ebp), $0x5<UINT8>
0x00414646:	jb 8
0x00414648:	pushl $0x1<UINT8>
0x0041464a:	popl %eax
0x0041464b:	jmp 0x00414752
0x00414752:	popl %ebx
0x00414753:	leave
0x00414754:	ret

0x0041477a:	cmpl %eax, $0x3<UINT8>
0x0041477d:	movl 0x47aa64, %eax
0x00414782:	jne 0x00414791
0x00414791:	cmpl %eax, $0x2<UINT8>
0x00414794:	jne 0x004147ae
0x004147ae:	pushl $0x1<UINT8>
0x004147b0:	popl %eax
0x004147b1:	ret

0x00411eb6:	popl %ecx
0x00411eb7:	testl %eax, %eax
0x00411eb9:	jne 0x00411ec3
0x00411ec3:	call 0x004142cc
0x004142cc:	pushl %esi
0x004142cd:	call 0x004139bc
0x004139bc:	pushl %esi
0x004139bd:	movl %esi, 0x46728c
0x004139c3:	pushl 0x4734ac
0x004139c9:	call InitializeCriticalSection@KERNEL32.DLL
InitializeCriticalSection@KERNEL32.DLL: API Node	
0x004139cb:	pushl 0x47349c
0x004139d1:	call InitializeCriticalSection@KERNEL32.DLL
0x004139d3:	pushl 0x47348c
0x004139d9:	call InitializeCriticalSection@KERNEL32.DLL
0x004139db:	pushl 0x47346c
0x004139e1:	call InitializeCriticalSection@KERNEL32.DLL
0x004139e3:	popl %esi
0x004139e4:	ret

0x004142d2:	call TlsAlloc@KERNEL32.DLL
TlsAlloc@KERNEL32.DLL: API Node	
0x004142d8:	cmpl %eax, $0xffffffff<UINT8>
0x004142db:	movl 0x473530, %eax
0x004142e0:	je 58
0x004142e2:	pushl $0x74<UINT8>
0x004142e4:	pushl $0x1<UINT8>
0x004142e6:	call 0x0041698f
0x0041698f:	pushl %ebp
0x00416990:	movl %ebp, %esp
0x00416992:	pushl $0xffffffff<UINT8>
0x00416994:	pushl $0x46a7c8<UINT32>
0x00416999:	pushl $0x4159d0<UINT32>
0x0041699e:	movl %eax, %fs:0
0x004169a4:	pushl %eax
0x004169a5:	movl %fs:0, %esp
0x004169ac:	subl %esp, $0x18<UINT8>
0x004169af:	pushl %ebx
0x004169b0:	pushl %esi
0x004169b1:	pushl %edi
0x004169b2:	movl %esi, 0x8(%ebp)
0x004169b5:	imull %esi, 0xc(%ebp)
0x004169b9:	movl 0xc(%ebp), %esi
0x004169bc:	movl -28(%ebp), %esi
0x004169bf:	cmpl %esi, $0xffffffe0<UINT8>
0x004169c2:	ja 20
0x004169c4:	xorl %ebx, %ebx
0x004169c6:	cmpl %esi, %ebx
0x004169c8:	jne 0x004169cd
0x004169cd:	addl %esi, $0xf<UINT8>
0x004169d0:	andl %esi, $0xfffffff0<UINT8>
0x004169d3:	movl 0xc(%ebp), %esi
0x004169d6:	jmp 0x004169da
0x004169da:	movl -32(%ebp), %ebx
0x004169dd:	cmpl %esi, $0xffffffe0<UINT8>
0x004169e0:	ja 168
0x004169e6:	movl %eax, 0x47aa64
0x004169eb:	cmpl %eax, $0x3<UINT8>
0x004169ee:	jne 0x00416a31
0x00416a31:	cmpl %eax, $0x2<UINT8>
0x00416a34:	jne 0x00416a77
0x00416a77:	cmpl -32(%ebp), %ebx
0x00416a7a:	jne 62
0x00416a7c:	pushl %esi
0x00416a7d:	pushl $0x8<UINT8>
0x00416a7f:	pushl 0x47aa60
0x00416a85:	call HeapAlloc@KERNEL32.DLL
HeapAlloc@KERNEL32.DLL: API Node	
0x00416a8b:	movl -32(%ebp), %eax
0x00416a8e:	cmpl -32(%ebp), %ebx
0x00416a91:	jne 0x00416aba
0x00416aba:	movl %eax, -32(%ebp)
0x00416abd:	movl %ecx, -16(%ebp)
0x00416ac0:	movl %fs:0, %ecx
0x00416ac7:	popl %edi
0x00416ac8:	popl %esi
0x00416ac9:	popl %ebx
0x00416aca:	leave
0x00416acb:	ret

0x004142eb:	movl %esi, %eax
0x004142ed:	popl %ecx
0x004142ee:	testl %esi, %esi
0x004142f0:	popl %ecx
0x004142f1:	je 41
0x004142f3:	pushl %esi
0x004142f4:	pushl 0x473530
0x004142fa:	call TlsSetValue@KERNEL32.DLL
TlsSetValue@KERNEL32.DLL: API Node	
0x00414300:	testl %eax, %eax
0x00414302:	je 24
0x00414304:	pushl %esi
0x00414305:	call 0x00414320
0x00414320:	movl %eax, 0x4(%esp)
0x00414324:	movl 0x50(%eax), $0x4757b0<UINT32>
0x0041432b:	movl 0x14(%eax), $0x1<UINT32>
0x00414332:	ret

0x0041430a:	popl %ecx
0x0041430b:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x00414311:	orl 0x4(%esi), $0xffffffff<UINT8>
0x00414315:	pushl $0x1<UINT8>
0x00414317:	movl (%esi), %eax
0x00414319:	popl %eax
0x0041431a:	popl %esi
0x0041431b:	ret

0x00411ec8:	testl %eax, %eax
0x00411eca:	jne 0x00411ed4
0x00411ed4:	xorl %esi, %esi
0x00411ed6:	movl -4(%ebp), %esi
0x00411ed9:	call 0x00416647
0x00416647:	pushl %ebp
0x00416648:	movl %ebp, %esp
0x0041664a:	subl %esp, $0x48<UINT8>
0x0041664d:	pushl %ebx
0x0041664e:	pushl %esi
0x0041664f:	pushl %edi
0x00416650:	pushl $0x480<UINT32>
0x00416655:	call 0x004119a1
0x004119a1:	pushl 0x479654
0x004119a7:	pushl 0x8(%esp)
0x004119ab:	call 0x004119b3
0x004119b3:	cmpl 0x4(%esp), $0xffffffe0<UINT8>
0x004119b8:	ja 34
0x004119ba:	pushl 0x4(%esp)
0x004119be:	call 0x004119df
0x004119df:	pushl %ebp
0x004119e0:	movl %ebp, %esp
0x004119e2:	pushl $0xffffffff<UINT8>
0x004119e4:	pushl $0x46a228<UINT32>
0x004119e9:	pushl $0x4159d0<UINT32>
0x004119ee:	movl %eax, %fs:0
0x004119f4:	pushl %eax
0x004119f5:	movl %fs:0, %esp
0x004119fc:	subl %esp, $0xc<UINT8>
0x004119ff:	pushl %ebx
0x00411a00:	pushl %esi
0x00411a01:	pushl %edi
0x00411a02:	movl %eax, 0x47aa64
0x00411a07:	cmpl %eax, $0x3<UINT8>
0x00411a0a:	jne 0x00411a4f
0x00411a4f:	cmpl %eax, $0x2<UINT8>
0x00411a52:	jne 0x00411aae
0x00411aae:	movl %eax, 0x8(%ebp)
0x00411ab1:	testl %eax, %eax
0x00411ab3:	jne 0x00411ab8
0x00411ab8:	addl %eax, $0xf<UINT8>
0x00411abb:	andb %al, $0xfffffff0<UINT8>
0x00411abd:	pushl %eax
0x00411abe:	pushl $0x0<UINT8>
0x00411ac0:	pushl 0x47aa60
0x00411ac6:	call HeapAlloc@KERNEL32.DLL
0x00411acc:	movl %ecx, -16(%ebp)
0x00411acf:	movl %fs:0, %ecx
0x00411ad6:	popl %edi
0x00411ad7:	popl %esi
0x00411ad8:	popl %ebx
0x00411ad9:	leave
0x00411ada:	ret

0x004119c3:	testl %eax, %eax
0x004119c5:	popl %ecx
0x004119c6:	jne 0x004119de
0x004119de:	ret

0x004119b0:	popl %ecx
0x004119b1:	popl %ecx
0x004119b2:	ret

0x0041665a:	movl %esi, %eax
0x0041665c:	popl %ecx
0x0041665d:	testl %esi, %esi
0x0041665f:	jne 0x00416669
0x00416669:	movl 0x47a940, %esi
0x0041666f:	movl 0x47aa40, $0x20<UINT32>
0x00416679:	leal %eax, 0x480(%esi)
0x0041667f:	cmpl %esi, %eax
0x00416681:	jae 0x004166a1
0x00416683:	andb 0x4(%esi), $0x0<UINT8>
0x00416687:	orl (%esi), $0xffffffff<UINT8>
0x0041668a:	andl 0x8(%esi), $0x0<UINT8>
0x0041668e:	movb 0x5(%esi), $0xa<UINT8>
0x00416692:	movl %eax, 0x47a940
0x00416697:	addl %esi, $0x24<UINT8>
0x0041669a:	addl %eax, $0x480<UINT32>
0x0041669f:	jmp 0x0041667f
0x004166a1:	leal %eax, -72(%ebp)
0x004166a4:	pushl %eax
0x004166a5:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x004166ab:	cmpw -22(%ebp), $0x0<UINT8>
0x004166b0:	je 209
0x004166b6:	movl %eax, -20(%ebp)
0x004166b9:	testl %eax, %eax
0x004166bb:	je 198
0x004166c1:	movl %edi, (%eax)
0x004166c3:	leal %ebx, 0x4(%eax)
0x004166c6:	leal %eax, (%ebx,%edi)
0x004166c9:	movl -4(%ebp), %eax
0x004166cc:	movl %eax, $0x800<UINT32>
0x004166d1:	cmpl %edi, %eax
0x004166d3:	jl 0x004166d7
0x004166d7:	cmpl 0x47aa40, %edi
0x004166dd:	jnl 0x00416735
0x00416735:	xorl %esi, %esi
0x00416737:	testl %edi, %edi
0x00416739:	jle 0x00416787
0x00416787:	xorl %ebx, %ebx
0x00416789:	movl %ecx, 0x47a940
0x0041678f:	leal %eax, (%ebx,%ebx,8)
0x00416792:	cmpl (%ecx,%eax,4), $0xffffffff<UINT8>
0x00416796:	leal %esi, (%ecx,%eax,4)
0x00416799:	jne 77
0x0041679b:	testl %ebx, %ebx
0x0041679d:	movb 0x4(%esi), $0xffffff81<UINT8>
0x004167a1:	jne 0x004167a8
0x004167a3:	pushl $0xfffffff6<UINT8>
0x004167a5:	popl %eax
0x004167a6:	jmp 0x004167b2
0x004167b2:	pushl %eax
0x004167b3:	call GetStdHandle@KERNEL32.DLL
GetStdHandle@KERNEL32.DLL: API Node	
0x004167b9:	movl %edi, %eax
0x004167bb:	cmpl %edi, $0xffffffff<UINT8>
0x004167be:	je 23
0x004167c0:	pushl %edi
0x004167c1:	call GetFileType@KERNEL32.DLL
GetFileType@KERNEL32.DLL: API Node	
0x004167c7:	testl %eax, %eax
0x004167c9:	je 12
0x004167cb:	andl %eax, $0xff<UINT32>
0x004167d0:	movl (%esi), %edi
0x004167d2:	cmpl %eax, $0x2<UINT8>
0x004167d5:	jne 6
0x004167d7:	orb 0x4(%esi), $0x40<UINT8>
0x004167db:	jmp 0x004167ec
0x004167ec:	incl %ebx
0x004167ed:	cmpl %ebx, $0x3<UINT8>
0x004167f0:	jl 0x00416789
0x004167a8:	movl %eax, %ebx
0x004167aa:	decl %eax
0x004167ab:	negl %eax
0x004167ad:	sbbl %eax, %eax
0x004167af:	addl %eax, $0xfffffff5<UINT8>
0x004167f2:	pushl 0x47aa40
0x004167f8:	call SetHandleCount@KERNEL32.DLL
SetHandleCount@KERNEL32.DLL: API Node	
0x004167fe:	popl %edi
0x004167ff:	popl %esi
0x00416800:	popl %ebx
0x00416801:	leave
0x00416802:	ret

0x00411ede:	call GetCommandLineA@KERNEL32.DLL
GetCommandLineA@KERNEL32.DLL: API Node	
0x00411ee4:	movl 0x47ac88, %eax
0x00411ee9:	call 0x00416515
0x00416515:	pushl %ecx
0x00416516:	pushl %ecx
0x00416517:	movl %eax, 0x479760
0x0041651c:	pushl %ebx
0x0041651d:	pushl %ebp
0x0041651e:	movl %ebp, 0x467120
0x00416524:	pushl %esi
0x00416525:	pushl %edi
0x00416526:	xorl %ebx, %ebx
0x00416528:	xorl %esi, %esi
0x0041652a:	xorl %edi, %edi
0x0041652c:	cmpl %eax, %ebx
0x0041652e:	jne 51
0x00416530:	call GetEnvironmentStringsW@KERNEL32.DLL
GetEnvironmentStringsW@KERNEL32.DLL: API Node	
0x00416532:	movl %esi, %eax
0x00416534:	cmpl %esi, %ebx
0x00416536:	je 12
0x00416538:	movl 0x479760, $0x1<UINT32>
0x00416542:	jmp 0x0041656c
0x0041656c:	cmpl %esi, %ebx
0x0041656e:	jne 0x0041657c
0x0041657c:	cmpw (%esi), %bx
0x0041657f:	movl %eax, %esi
0x00416581:	je 14
0x00416583:	incl %eax
0x00416584:	incl %eax
0x00416585:	cmpw (%eax), %bx
0x00416588:	jne 0x00416583
0x0041658a:	incl %eax
0x0041658b:	incl %eax
0x0041658c:	cmpw (%eax), %bx
0x0041658f:	jne 0x00416583
0x00416591:	subl %eax, %esi
0x00416593:	movl %edi, 0x4671c4
0x00416599:	sarl %eax
0x0041659b:	pushl %ebx
0x0041659c:	pushl %ebx
0x0041659d:	incl %eax
0x0041659e:	pushl %ebx
0x0041659f:	pushl %ebx
0x004165a0:	pushl %eax
0x004165a1:	pushl %esi
0x004165a2:	pushl %ebx
0x004165a3:	pushl %ebx
0x004165a4:	movl 0x34(%esp), %eax
0x004165a8:	call WideCharToMultiByte@KERNEL32.DLL
WideCharToMultiByte@KERNEL32.DLL: API Node	
0x004165aa:	movl %ebp, %eax
0x004165ac:	cmpl %ebp, %ebx
0x004165ae:	je 50
0x004165b0:	pushl %ebp
0x004165b1:	call 0x004119a1
0x004165b6:	cmpl %eax, %ebx
0x004165b8:	popl %ecx
0x004165b9:	movl 0x10(%esp), %eax
0x004165bd:	je 35
0x004165bf:	pushl %ebx
0x004165c0:	pushl %ebx
0x004165c1:	pushl %ebp
0x004165c2:	pushl %eax
0x004165c3:	pushl 0x24(%esp)
0x004165c7:	pushl %esi
0x004165c8:	pushl %ebx
0x004165c9:	pushl %ebx
0x004165ca:	call WideCharToMultiByte@KERNEL32.DLL
0x004165cc:	testl %eax, %eax
0x004165ce:	jne 0x004165de
0x004165de:	movl %ebx, 0x10(%esp)
0x004165e2:	pushl %esi
0x004165e3:	call FreeEnvironmentStringsW@KERNEL32.DLL
FreeEnvironmentStringsW@KERNEL32.DLL: API Node	
0x004165e9:	movl %eax, %ebx
0x004165eb:	jmp 0x00416640
0x00416640:	popl %edi
0x00416641:	popl %esi
0x00416642:	popl %ebp
0x00416643:	popl %ebx
0x00416644:	popl %ecx
0x00416645:	popl %ecx
0x00416646:	ret

0x00411eee:	movl 0x4795a0, %eax
0x00411ef3:	call 0x004162c8
0x004162c8:	pushl %ebp
0x004162c9:	movl %ebp, %esp
0x004162cb:	pushl %ecx
0x004162cc:	pushl %ecx
0x004162cd:	pushl %ebx
0x004162ce:	xorl %ebx, %ebx
0x004162d0:	cmpl 0x47ac90, %ebx
0x004162d6:	pushl %esi
0x004162d7:	pushl %edi
0x004162d8:	jne 5
0x004162da:	call 0x0041308d
0x0041308d:	cmpl 0x47ac90, $0x0<UINT8>
0x00413094:	jne 0x004130a8
0x00413096:	pushl $0xfffffffd<UINT8>
0x00413098:	call 0x00412cb5
0x00412cb5:	pushl %ebp
0x00412cb6:	movl %ebp, %esp
0x00412cb8:	subl %esp, $0x18<UINT8>
0x00412cbb:	pushl %ebx
0x00412cbc:	pushl %esi
0x00412cbd:	pushl %edi
0x00412cbe:	pushl $0x19<UINT8>
0x00412cc0:	call 0x004139e5
0x004139e5:	pushl %ebp
0x004139e6:	movl %ebp, %esp
0x004139e8:	movl %eax, 0x8(%ebp)
0x004139eb:	pushl %esi
0x004139ec:	cmpl 0x473468(,%eax,4), $0x0<UINT8>
0x004139f4:	leal %esi, 0x473468(,%eax,4)
0x004139fb:	jne 0x00413a3b
0x004139fd:	pushl %edi
0x004139fe:	pushl $0x18<UINT8>
0x00413a00:	call 0x004119a1
0x00413a05:	movl %edi, %eax
0x00413a07:	popl %ecx
0x00413a08:	testl %edi, %edi
0x00413a0a:	jne 0x00413a14
0x00413a14:	pushl $0x11<UINT8>
0x00413a16:	call 0x004139e5
0x00413a3b:	pushl (%esi)
0x00413a3d:	call EnterCriticalSection@KERNEL32.DLL
EnterCriticalSection@KERNEL32.DLL: API Node	
0x00413a43:	popl %esi
0x00413a44:	popl %ebp
0x00413a45:	ret

0x00413a1b:	cmpl (%esi), $0x0<UINT8>
0x00413a1e:	popl %ecx
0x00413a1f:	pushl %edi
0x00413a20:	jne 10
0x00413a22:	call InitializeCriticalSection@KERNEL32.DLL
0x00413a28:	movl (%esi), %edi
0x00413a2a:	jmp 0x00413a32
0x00413a32:	pushl $0x11<UINT8>
0x00413a34:	call 0x00413a46
0x00413a46:	pushl %ebp
0x00413a47:	movl %ebp, %esp
0x00413a49:	movl %eax, 0x8(%ebp)
0x00413a4c:	pushl 0x473468(,%eax,4)
0x00413a53:	call LeaveCriticalSection@KERNEL32.DLL
LeaveCriticalSection@KERNEL32.DLL: API Node	
0x00413a59:	popl %ebp
0x00413a5a:	ret

0x00413a39:	popl %ecx
0x00413a3a:	popl %edi
0x00412cc5:	pushl 0x8(%ebp)
0x00412cc8:	call 0x00412e62
0x00412e62:	movl %eax, 0x4(%esp)
0x00412e66:	andl 0x4795ac, $0x0<UINT8>
0x00412e6d:	cmpl %eax, $0xfffffffe<UINT8>
0x00412e70:	jne 0x00412e82
0x00412e82:	cmpl %eax, $0xfffffffd<UINT8>
0x00412e85:	jne 16
0x00412e87:	movl 0x4795ac, $0x1<UINT32>
0x00412e91:	jmp GetACP@KERNEL32.DLL
GetACP@KERNEL32.DLL: API Node	
0x00412ccd:	movl %ebx, %eax
0x00412ccf:	popl %ecx
0x00412cd0:	cmpl %ebx, 0x47aa68
0x00412cd6:	popl %ecx
0x00412cd7:	movl 0x8(%ebp), %ebx
0x00412cda:	jne 0x00412ce3
0x00412ce3:	testl %ebx, %ebx
0x00412ce5:	je 342
0x00412ceb:	xorl %edx, %edx
0x00412ced:	movl %eax, $0x473150<UINT32>
0x00412cf2:	cmpl (%eax), %ebx
0x00412cf4:	je 116
0x00412cf6:	addl %eax, $0x30<UINT8>
0x00412cf9:	incl %edx
0x00412cfa:	cmpl %eax, $0x473240<UINT32>
0x00412cff:	jl 0x00412cf2
0x00412d01:	leal %eax, -24(%ebp)
0x00412d04:	pushl %eax
0x00412d05:	pushl %ebx
0x00412d06:	call GetCPInfo@KERNEL32.DLL
GetCPInfo@KERNEL32.DLL: API Node	
0x00412d0c:	pushl $0x1<UINT8>
0x00412d0e:	popl %esi
0x00412d0f:	cmpl %eax, %esi
0x00412d11:	jne 289
0x00412d17:	pushl $0x40<UINT8>
0x00412d19:	andl 0x47ac84, $0x0<UINT8>
0x00412d20:	popl %ecx
0x00412d21:	xorl %eax, %eax
0x00412d23:	movl %edi, $0x47ab80<UINT32>
0x00412d28:	cmpl -24(%ebp), %esi
0x00412d2b:	rep stosl %es:(%edi), %eax
0x00412d2d:	stosb %es:(%edi), %al
0x00412d2e:	movl 0x47aa68, %ebx
0x00412d34:	jbe 235
0x00412d3a:	cmpb -18(%ebp), $0x0<UINT8>
0x00412d3e:	je 0x00412e00
0x00412e00:	movl %eax, %esi
0x00412e02:	orb 0x47ab81(%eax), $0x8<UINT8>
0x00412e09:	incl %eax
0x00412e0a:	cmpl %eax, $0xff<UINT32>
0x00412e0f:	jb 0x00412e02
0x00412e11:	pushl %ebx
0x00412e12:	call 0x00412eac
0x00412eac:	movl %eax, 0x4(%esp)
0x00412eb0:	subl %eax, $0x3a4<UINT32>
0x00412eb5:	je 34
0x00412eb7:	subl %eax, $0x4<UINT8>
0x00412eba:	je 23
0x00412ebc:	subl %eax, $0xd<UINT8>
0x00412ebf:	je 12
0x00412ec1:	decl %eax
0x00412ec2:	je 3
0x00412ec4:	xorl %eax, %eax
0x00412ec6:	ret

0x00412e17:	popl %ecx
0x00412e18:	movl 0x47ac84, %eax
0x00412e1d:	movl 0x47aa7c, %esi
0x00412e23:	jmp 0x00412e2c
0x00412e2c:	xorl %eax, %eax
0x00412e2e:	movl %edi, $0x47aa70<UINT32>
0x00412e33:	stosl %es:(%edi), %eax
0x00412e34:	stosl %es:(%edi), %eax
0x00412e35:	stosl %es:(%edi), %eax
0x00412e36:	jmp 0x00412e46
0x00412e46:	call 0x00412f08
0x00412f08:	pushl %ebp
0x00412f09:	movl %ebp, %esp
0x00412f0b:	subl %esp, $0x514<UINT32>
0x00412f11:	leal %eax, -20(%ebp)
0x00412f14:	pushl %esi
0x00412f15:	pushl %eax
0x00412f16:	pushl 0x47aa68
0x00412f1c:	call GetCPInfo@KERNEL32.DLL
0x00412f22:	cmpl %eax, $0x1<UINT8>
0x00412f25:	jne 278
0x00412f2b:	xorl %eax, %eax
0x00412f2d:	movl %esi, $0x100<UINT32>
0x00412f32:	movb -276(%ebp,%eax), %al
0x00412f39:	incl %eax
0x00412f3a:	cmpl %eax, %esi
0x00412f3c:	jb 0x00412f32
0x00412f3e:	movb %al, -14(%ebp)
0x00412f41:	movb -276(%ebp), $0x20<UINT8>
0x00412f48:	testb %al, %al
0x00412f4a:	je 0x00412f83
0x00412f83:	pushl $0x0<UINT8>
0x00412f85:	leal %eax, -1300(%ebp)
0x00412f8b:	pushl 0x47ac84
0x00412f91:	pushl 0x47aa68
0x00412f97:	pushl %eax
0x00412f98:	leal %eax, -276(%ebp)
0x00412f9e:	pushl %esi
0x00412f9f:	pushl %eax
0x00412fa0:	pushl $0x1<UINT8>
0x00412fa2:	call 0x00417888
0x00417888:	pushl %ebp
0x00417889:	movl %ebp, %esp
0x0041788b:	pushl $0xffffffff<UINT8>
0x0041788d:	pushl $0x46a878<UINT32>
0x00417892:	pushl $0x4159d0<UINT32>
0x00417897:	movl %eax, %fs:0
0x0041789d:	pushl %eax
0x0041789e:	movl %fs:0, %esp
0x004178a5:	subl %esp, $0x18<UINT8>
0x004178a8:	pushl %ebx
0x004178a9:	pushl %esi
0x004178aa:	pushl %edi
0x004178ab:	movl -24(%ebp), %esp
0x004178ae:	movl %eax, 0x47976c
0x004178b3:	xorl %ebx, %ebx
0x004178b5:	cmpl %eax, %ebx
0x004178b7:	jne 62
0x004178b9:	leal %eax, -28(%ebp)
0x004178bc:	pushl %eax
0x004178bd:	pushl $0x1<UINT8>
0x004178bf:	popl %esi
0x004178c0:	pushl %esi
0x004178c1:	pushl $0x46a7e4<UINT32>
0x004178c6:	pushl %esi
0x004178c7:	call GetStringTypeW@KERNEL32.DLL
GetStringTypeW@KERNEL32.DLL: API Node	
0x004178cd:	testl %eax, %eax
0x004178cf:	je 4
0x004178d1:	movl %eax, %esi
0x004178d3:	jmp 0x004178f2
0x004178f2:	movl 0x47976c, %eax
0x004178f7:	cmpl %eax, $0x2<UINT8>
0x004178fa:	jne 0x00417920
0x00417920:	cmpl %eax, $0x1<UINT8>
0x00417923:	jne 148
0x00417929:	cmpl 0x18(%ebp), %ebx
0x0041792c:	jne 0x00417936
0x00417936:	pushl %ebx
0x00417937:	pushl %ebx
0x00417938:	pushl 0x10(%ebp)
0x0041793b:	pushl 0xc(%ebp)
0x0041793e:	movl %eax, 0x20(%ebp)
0x00417941:	negl %eax
0x00417943:	sbbl %eax, %eax
0x00417945:	andl %eax, $0x8<UINT8>
0x00417948:	incl %eax
0x00417949:	pushl %eax
0x0041794a:	pushl 0x18(%ebp)
0x0041794d:	call MultiByteToWideChar@KERNEL32.DLL
MultiByteToWideChar@KERNEL32.DLL: API Node	
0x00417953:	movl -32(%ebp), %eax
0x00417956:	cmpl %eax, %ebx
0x00417958:	je 99
0x0041795a:	movl -4(%ebp), %ebx
0x0041795d:	leal %edi, (%eax,%eax)
0x00417960:	movl %eax, %edi
0x00417962:	addl %eax, $0x3<UINT8>
0x00417965:	andb %al, $0xfffffffc<UINT8>
0x00417967:	call 0x00411e20
0x0041796c:	movl -24(%ebp), %esp
0x0041796f:	movl %esi, %esp
0x00417971:	movl -36(%ebp), %esi
0x00417974:	pushl %edi
0x00417975:	pushl %ebx
0x00417976:	pushl %esi
0x00417977:	call 0x00412010
0x00412010:	movl %edx, 0xc(%esp)
0x00412014:	movl %ecx, 0x4(%esp)
0x00412018:	testl %edx, %edx
0x0041201a:	je 71
0x0041201c:	xorl %eax, %eax
0x0041201e:	movb %al, 0x8(%esp)
0x00412022:	pushl %edi
0x00412023:	movl %edi, %ecx
0x00412025:	cmpl %edx, $0x4<UINT8>
0x00412028:	jb 45
0x0041202a:	negl %ecx
0x0041202c:	andl %ecx, $0x3<UINT8>
0x0041202f:	je 0x00412039
0x00412039:	movl %ecx, %eax
0x0041203b:	shll %eax, $0x8<UINT8>
0x0041203e:	addl %eax, %ecx
0x00412040:	movl %ecx, %eax
0x00412042:	shll %eax, $0x10<UINT8>
0x00412045:	addl %eax, %ecx
0x00412047:	movl %ecx, %edx
0x00412049:	andl %edx, $0x3<UINT8>
0x0041204c:	shrl %ecx, $0x2<UINT8>
0x0041204f:	je 6
0x00412051:	rep stosl %es:(%edi), %eax
0x00412053:	testl %edx, %edx
0x00412055:	je 0x0041205d
0x0041205d:	movl %eax, 0x8(%esp)
0x00412061:	popl %edi
0x00412062:	ret

0x0041797c:	addl %esp, $0xc<UINT8>
0x0041797f:	jmp 0x0041798c
0x0041798c:	orl -4(%ebp), $0xffffffff<UINT8>
0x00417990:	cmpl %esi, %ebx
0x00417992:	je 41
0x00417994:	pushl -32(%ebp)
0x00417997:	pushl %esi
0x00417998:	pushl 0x10(%ebp)
0x0041799b:	pushl 0xc(%ebp)
0x0041799e:	pushl $0x1<UINT8>
0x004179a0:	pushl 0x18(%ebp)
0x004179a3:	call MultiByteToWideChar@KERNEL32.DLL
0x004179a9:	cmpl %eax, %ebx
0x004179ab:	je 16
0x004179ad:	pushl 0x14(%ebp)
0x004179b0:	pushl %eax
0x004179b1:	pushl %esi
0x004179b2:	pushl 0x8(%ebp)
0x004179b5:	call GetStringTypeW@KERNEL32.DLL
0x004179bb:	jmp 0x004179bf
0x004179bf:	leal %esp, -52(%ebp)
0x004179c2:	movl %ecx, -16(%ebp)
0x004179c5:	movl %fs:0, %ecx
0x004179cc:	popl %edi
0x004179cd:	popl %esi
0x004179ce:	popl %ebx
0x004179cf:	leave
0x004179d0:	ret

0x00412fa7:	pushl $0x0<UINT8>
0x00412fa9:	leal %eax, -532(%ebp)
0x00412faf:	pushl 0x47aa68
0x00412fb5:	pushl %esi
0x00412fb6:	pushl %eax
0x00412fb7:	leal %eax, -276(%ebp)
0x00412fbd:	pushl %esi
0x00412fbe:	pushl %eax
0x00412fbf:	pushl %esi
0x00412fc0:	pushl 0x47ac84
0x00412fc6:	call 0x00416bda
0x00416bda:	pushl %ebp
0x00416bdb:	movl %ebp, %esp
0x00416bdd:	pushl $0xffffffff<UINT8>
0x00416bdf:	pushl $0x46a7e8<UINT32>
0x00416be4:	pushl $0x4159d0<UINT32>
0x00416be9:	movl %eax, %fs:0
0x00416bef:	pushl %eax
0x00416bf0:	movl %fs:0, %esp
0x00416bf7:	subl %esp, $0x1c<UINT8>
0x00416bfa:	pushl %ebx
0x00416bfb:	pushl %esi
0x00416bfc:	pushl %edi
0x00416bfd:	movl -24(%ebp), %esp
0x00416c00:	xorl %edi, %edi
0x00416c02:	cmpl 0x479768, %edi
0x00416c08:	jne 0x00416c50
0x00416c0a:	pushl %edi
0x00416c0b:	pushl %edi
0x00416c0c:	pushl $0x1<UINT8>
0x00416c0e:	popl %ebx
0x00416c0f:	pushl %ebx
0x00416c10:	pushl $0x46a7e4<UINT32>
0x00416c15:	movl %esi, $0x100<UINT32>
0x00416c1a:	pushl %esi
0x00416c1b:	pushl %edi
0x00416c1c:	call LCMapStringW@KERNEL32.DLL
LCMapStringW@KERNEL32.DLL: API Node	
0x00416c22:	testl %eax, %eax
0x00416c24:	je 8
0x00416c26:	movl 0x479768, %ebx
0x00416c2c:	jmp 0x00416c50
0x00416c50:	cmpl 0x14(%ebp), %edi
0x00416c53:	jle 16
0x00416c55:	pushl 0x14(%ebp)
0x00416c58:	pushl 0x10(%ebp)
0x00416c5b:	call 0x0041a8aa
0x0041a8aa:	movl %edx, 0x8(%esp)
0x0041a8ae:	movl %eax, 0x4(%esp)
0x0041a8b2:	testl %edx, %edx
0x0041a8b4:	pushl %esi
0x0041a8b5:	leal %ecx, -1(%edx)
0x0041a8b8:	je 13
0x0041a8ba:	cmpb (%eax), $0x0<UINT8>
0x0041a8bd:	je 8
0x0041a8bf:	incl %eax
0x0041a8c0:	movl %esi, %ecx
0x0041a8c2:	decl %ecx
0x0041a8c3:	testl %esi, %esi
0x0041a8c5:	jne 0x0041a8ba
0x0041a8c7:	cmpb (%eax), $0x0<UINT8>
0x0041a8ca:	popl %esi
0x0041a8cb:	jne 0x0041a8d2
0x0041a8d2:	movl %eax, %edx
0x0041a8d4:	ret

0x00416c60:	popl %ecx
0x00416c61:	popl %ecx
0x00416c62:	movl 0x14(%ebp), %eax
0x00416c65:	movl %eax, 0x479768
0x00416c6a:	cmpl %eax, $0x2<UINT8>
0x00416c6d:	jne 0x00416c8c
0x00416c8c:	cmpl %eax, $0x1<UINT8>
0x00416c8f:	jne 211
0x00416c95:	cmpl 0x20(%ebp), %edi
0x00416c98:	jne 0x00416ca2
0x00416ca2:	pushl %edi
0x00416ca3:	pushl %edi
0x00416ca4:	pushl 0x14(%ebp)
0x00416ca7:	pushl 0x10(%ebp)
0x00416caa:	movl %eax, 0x24(%ebp)
0x00416cad:	negl %eax
0x00416caf:	sbbl %eax, %eax
0x00416cb1:	andl %eax, $0x8<UINT8>
0x00416cb4:	incl %eax
0x00416cb5:	pushl %eax
0x00416cb6:	pushl 0x20(%ebp)
0x00416cb9:	call MultiByteToWideChar@KERNEL32.DLL
0x00416cbf:	movl %ebx, %eax
0x00416cc1:	movl -28(%ebp), %ebx
0x00416cc4:	cmpl %ebx, %edi
0x00416cc6:	je 156
0x00416ccc:	movl -4(%ebp), %edi
0x00416ccf:	leal %eax, (%ebx,%ebx)
0x00416cd2:	addl %eax, $0x3<UINT8>
0x00416cd5:	andb %al, $0xfffffffc<UINT8>
0x00416cd7:	call 0x00411e20
0x00416cdc:	movl -24(%ebp), %esp
0x00416cdf:	movl %eax, %esp
0x00416ce1:	movl -36(%ebp), %eax
0x00416ce4:	orl -4(%ebp), $0xffffffff<UINT8>
0x00416ce8:	jmp 0x00416cfd
0x00416cfd:	cmpl -36(%ebp), %edi
0x00416d00:	je 102
0x00416d02:	pushl %ebx
0x00416d03:	pushl -36(%ebp)
0x00416d06:	pushl 0x14(%ebp)
0x00416d09:	pushl 0x10(%ebp)
0x00416d0c:	pushl $0x1<UINT8>
0x00416d0e:	pushl 0x20(%ebp)
0x00416d11:	call MultiByteToWideChar@KERNEL32.DLL
0x00416d17:	testl %eax, %eax
0x00416d19:	je 77
0x00416d1b:	pushl %edi
0x00416d1c:	pushl %edi
0x00416d1d:	pushl %ebx
0x00416d1e:	pushl -36(%ebp)
0x00416d21:	pushl 0xc(%ebp)
0x00416d24:	pushl 0x8(%ebp)
0x00416d27:	call LCMapStringW@KERNEL32.DLL
0x00416d2d:	movl %esi, %eax
0x00416d2f:	movl -40(%ebp), %esi
0x00416d32:	cmpl %esi, %edi
0x00416d34:	je 50
0x00416d36:	testb 0xd(%ebp), $0x4<UINT8>
0x00416d3a:	je 0x00416d7c
0x00416d7c:	movl -4(%ebp), $0x1<UINT32>
0x00416d83:	leal %eax, (%esi,%esi)
0x00416d86:	addl %eax, $0x3<UINT8>
0x00416d89:	andb %al, $0xfffffffc<UINT8>
0x00416d8b:	call 0x00411e20
0x00416d90:	movl -24(%ebp), %esp
0x00416d93:	movl %ebx, %esp
0x00416d95:	movl -32(%ebp), %ebx
0x00416d98:	orl -4(%ebp), $0xffffffff<UINT8>
0x00416d9c:	jmp 0x00416db0
0x00416db0:	cmpl %ebx, %edi
0x00416db2:	je -76
0x00416db4:	pushl %esi
0x00416db5:	pushl %ebx
0x00416db6:	pushl -28(%ebp)
0x00416db9:	pushl -36(%ebp)
0x00416dbc:	pushl 0xc(%ebp)
0x00416dbf:	pushl 0x8(%ebp)
0x00416dc2:	call LCMapStringW@KERNEL32.DLL
0x00416dc8:	testl %eax, %eax
0x00416dca:	je -100
0x00416dcc:	cmpl 0x1c(%ebp), %edi
0x00416dcf:	pushl %edi
0x00416dd0:	pushl %edi
0x00416dd1:	jne 0x00416dd7
0x00416dd7:	pushl 0x1c(%ebp)
0x00416dda:	pushl 0x18(%ebp)
0x00416ddd:	pushl %esi
0x00416dde:	pushl %ebx
0x00416ddf:	pushl $0x220<UINT32>
0x00416de4:	pushl 0x20(%ebp)
0x00416de7:	call WideCharToMultiByte@KERNEL32.DLL
0x00416ded:	movl %esi, %eax
0x00416def:	cmpl %esi, %edi
0x00416df1:	je -143
0x00416df7:	movl %eax, %esi
0x00416df9:	jmp 0x00416d6a
0x00416d6a:	leal %esp, -56(%ebp)
0x00416d6d:	movl %ecx, -16(%ebp)
0x00416d70:	movl %fs:0, %ecx
0x00416d77:	popl %edi
0x00416d78:	popl %esi
0x00416d79:	popl %ebx
0x00416d7a:	leave
0x00416d7b:	ret

0x00412fcb:	pushl $0x0<UINT8>
0x00412fcd:	leal %eax, -788(%ebp)
0x00412fd3:	pushl 0x47aa68
0x00412fd9:	pushl %esi
0x00412fda:	pushl %eax
0x00412fdb:	leal %eax, -276(%ebp)
0x00412fe1:	pushl %esi
0x00412fe2:	pushl %eax
0x00412fe3:	pushl $0x200<UINT32>
0x00412fe8:	pushl 0x47ac84
0x00412fee:	call 0x00416bda
0x00412ff3:	addl %esp, $0x5c<UINT8>
0x00412ff6:	xorl %eax, %eax
0x00412ff8:	leal %ecx, -1300(%ebp)
0x00412ffe:	movw %dx, (%ecx)
0x00413001:	testb %dl, $0x1<UINT8>
0x00413004:	je 0x0041301c
0x0041301c:	testb %dl, $0x2<UINT8>
0x0041301f:	je 0x00413031
0x00413031:	andb 0x47aa80(%eax), $0x0<UINT8>
0x00413038:	incl %eax
0x00413039:	incl %ecx
0x0041303a:	incl %ecx
0x0041303b:	cmpl %eax, %esi
0x0041303d:	jb 0x00412ffe
0x00413006:	orb 0x47ab81(%eax), $0x10<UINT8>
0x0041300d:	movb %dl, -532(%ebp,%eax)
0x00413014:	movb 0x47aa80(%eax), %dl
0x0041301a:	jmp 0x00413038
0x00413021:	orb 0x47ab81(%eax), $0x20<UINT8>
0x00413028:	movb %dl, -788(%ebp,%eax)
0x0041302f:	jmp 0x00413014
0x0041303f:	jmp 0x0041308a
0x0041308a:	popl %esi
0x0041308b:	leave
0x0041308c:	ret

0x00412e4b:	jmp 0x00412cdc
0x00412cdc:	xorl %esi, %esi
0x00412cde:	jmp 0x00412e53
0x00412e53:	pushl $0x19<UINT8>
0x00412e55:	call 0x00413a46
0x00412e5a:	popl %ecx
0x00412e5b:	movl %eax, %esi
0x00412e5d:	popl %edi
0x00412e5e:	popl %esi
0x00412e5f:	popl %ebx
0x00412e60:	leave
0x00412e61:	ret

0x0041309d:	popl %ecx
0x0041309e:	movl 0x47ac90, $0x1<UINT32>
0x004130a8:	ret

0x004162df:	movl %esi, $0x47965c<UINT32>
0x004162e4:	pushl $0x104<UINT32>
0x004162e9:	pushl %esi
0x004162ea:	pushl %ebx
0x004162eb:	call GetModuleFileNameA@KERNEL32.DLL
GetModuleFileNameA@KERNEL32.DLL: API Node	
0x004162f1:	movl %eax, 0x47ac88
0x004162f6:	movl 0x479584, %esi
0x004162fc:	movl %edi, %esi
0x004162fe:	cmpb (%eax), %bl
0x00416300:	je 2
0x00416302:	movl %edi, %eax
0x00416304:	leal %eax, -8(%ebp)
0x00416307:	pushl %eax
0x00416308:	leal %eax, -4(%ebp)
0x0041630b:	pushl %eax
0x0041630c:	pushl %ebx
0x0041630d:	pushl %ebx
0x0041630e:	pushl %edi
0x0041630f:	call 0x00416361
0x00416361:	pushl %ebp
0x00416362:	movl %ebp, %esp
0x00416364:	movl %ecx, 0x18(%ebp)
0x00416367:	movl %eax, 0x14(%ebp)
0x0041636a:	pushl %ebx
0x0041636b:	pushl %esi
0x0041636c:	andl (%ecx), $0x0<UINT8>
0x0041636f:	movl %esi, 0x10(%ebp)
0x00416372:	pushl %edi
0x00416373:	movl %edi, 0xc(%ebp)
0x00416376:	movl (%eax), $0x1<UINT32>
0x0041637c:	movl %eax, 0x8(%ebp)
0x0041637f:	testl %edi, %edi
0x00416381:	je 0x0041638b
0x0041638b:	cmpb (%eax), $0x22<UINT8>
0x0041638e:	jne 68
0x00416390:	movb %dl, 0x1(%eax)
0x00416393:	incl %eax
0x00416394:	cmpb %dl, $0x22<UINT8>
0x00416397:	je 0x004163c2
0x00416399:	testb %dl, %dl
0x0041639b:	je 37
0x0041639d:	movzbl %edx, %dl
0x004163a0:	testb 0x47ab81(%edx), $0x4<UINT8>
0x004163a7:	je 0x004163b5
0x004163b5:	incl (%ecx)
0x004163b7:	testl %esi, %esi
0x004163b9:	je 0x00416390
0x004163c2:	incl (%ecx)
0x004163c4:	testl %esi, %esi
0x004163c6:	je 0x004163cc
0x004163cc:	cmpb (%eax), $0x22<UINT8>
0x004163cf:	jne 70
0x004163d1:	incl %eax
0x004163d2:	jmp 0x00416417
0x00416417:	andl 0x18(%ebp), $0x0<UINT8>
0x0041641b:	cmpb (%eax), $0x0<UINT8>
0x0041641e:	je 0x00416504
0x00416504:	testl %edi, %edi
0x00416506:	je 0x0041650b
0x0041650b:	movl %eax, 0x14(%ebp)
0x0041650e:	popl %edi
0x0041650f:	popl %esi
0x00416510:	popl %ebx
0x00416511:	incl (%eax)
0x00416513:	popl %ebp
0x00416514:	ret

0x00416314:	movl %eax, -8(%ebp)
0x00416317:	movl %ecx, -4(%ebp)
0x0041631a:	leal %eax, (%eax,%ecx,4)
0x0041631d:	pushl %eax
0x0041631e:	call 0x004119a1
0x00416323:	movl %esi, %eax
0x00416325:	addl %esp, $0x18<UINT8>
0x00416328:	cmpl %esi, %ebx
0x0041632a:	jne 0x00416334
0x00416334:	leal %eax, -8(%ebp)
0x00416337:	pushl %eax
0x00416338:	leal %eax, -4(%ebp)
0x0041633b:	pushl %eax
0x0041633c:	movl %eax, -4(%ebp)
0x0041633f:	leal %eax, (%esi,%eax,4)
0x00416342:	pushl %eax
0x00416343:	pushl %esi
0x00416344:	pushl %edi
0x00416345:	call 0x00416361
0x00416383:	movl (%edi), %esi
0x00416385:	addl %edi, $0x4<UINT8>
0x00416388:	movl 0xc(%ebp), %edi
0x004163bb:	movb %dl, (%eax)
0x004163bd:	movb (%esi), %dl
0x004163bf:	incl %esi
0x004163c0:	jmp 0x00416390
0x004163c8:	andb (%esi), $0x0<UINT8>
0x004163cb:	incl %esi
0x00416508:	andl (%edi), $0x0<UINT8>
0x0041634a:	movl %eax, -4(%ebp)
0x0041634d:	addl %esp, $0x14<UINT8>
0x00416350:	decl %eax
0x00416351:	movl 0x47956c, %esi
0x00416357:	popl %edi
0x00416358:	popl %esi
0x00416359:	movl 0x479568, %eax
0x0041635e:	popl %ebx
0x0041635f:	leave
0x00416360:	ret

0x00411ef8:	call 0x0041620f
0x0041620f:	pushl %ebx
0x00416210:	xorl %ebx, %ebx
0x00416212:	cmpl 0x47ac90, %ebx
0x00416218:	pushl %esi
0x00416219:	pushl %edi
0x0041621a:	jne 0x00416221
0x00416221:	movl %esi, 0x4795a0
0x00416227:	xorl %edi, %edi
0x00416229:	movb %al, (%esi)
0x0041622b:	cmpb %al, %bl
0x0041622d:	je 0x00416241
0x0041622f:	cmpb %al, $0x3d<UINT8>
0x00416231:	je 0x00416234
0x00416234:	pushl %esi
0x00416235:	call 0x00411890
0x00411890:	movl %ecx, 0x4(%esp)
0x00411894:	testl %ecx, $0x3<UINT32>
0x0041189a:	je 0x004118b0
0x004118b0:	movl %eax, (%ecx)
0x004118b2:	movl %edx, $0x7efefeff<UINT32>
0x004118b7:	addl %edx, %eax
0x004118b9:	xorl %eax, $0xffffffff<UINT8>
0x004118bc:	xorl %eax, %edx
0x004118be:	addl %ecx, $0x4<UINT8>
0x004118c1:	testl %eax, $0x81010100<UINT32>
0x004118c6:	je 0x004118b0
0x004118c8:	movl %eax, -4(%ecx)
0x004118cb:	testb %al, %al
0x004118cd:	je 50
0x004118cf:	testb %ah, %ah
0x004118d1:	je 36
0x004118d3:	testl %eax, $0xff0000<UINT32>
0x004118d8:	je 19
0x004118da:	testl %eax, $0xff000000<UINT32>
0x004118df:	je 0x004118e3
0x004118e3:	leal %eax, -1(%ecx)
0x004118e6:	movl %ecx, 0x4(%esp)
0x004118ea:	subl %eax, %ecx
0x004118ec:	ret

0x0041623a:	popl %ecx
0x0041623b:	leal %esi, 0x1(%esi,%eax)
0x0041623f:	jmp 0x00416229
0x00416241:	leal %eax, 0x4(,%edi,4)
0x00416248:	pushl %eax
0x00416249:	call 0x004119a1
0x0041624e:	movl %esi, %eax
0x00416250:	popl %ecx
0x00416251:	cmpl %esi, %ebx
0x00416253:	movl 0x479574, %esi
0x00416259:	jne 0x00416263
0x00416263:	movl %edi, 0x4795a0
0x00416269:	cmpb (%edi), %bl
0x0041626b:	je 57
0x0041626d:	pushl %ebp
0x0041626e:	pushl %edi
0x0041626f:	call 0x00411890
0x00416274:	movl %ebp, %eax
0x00416276:	popl %ecx
0x00416277:	incl %ebp
0x00416278:	cmpb (%edi), $0x3d<UINT8>
0x0041627b:	je 0x0041629f
0x0041629f:	addl %edi, %ebp
0x004162a1:	cmpb (%edi), %bl
0x004162a3:	jne -55
0x004162a5:	popl %ebp
0x004162a6:	pushl 0x4795a0
0x004162ac:	call 0x004116b4
0x004116b4:	pushl %ebp
0x004116b5:	movl %ebp, %esp
0x004116b7:	pushl $0xffffffff<UINT8>
0x004116b9:	pushl $0x46a210<UINT32>
0x004116be:	pushl $0x4159d0<UINT32>
0x004116c3:	movl %eax, %fs:0
0x004116c9:	pushl %eax
0x004116ca:	movl %fs:0, %esp
0x004116d1:	subl %esp, $0x18<UINT8>
0x004116d4:	pushl %ebx
0x004116d5:	pushl %esi
0x004116d6:	pushl %edi
0x004116d7:	movl %esi, 0x8(%ebp)
0x004116da:	testl %esi, %esi
0x004116dc:	je 172
0x004116e2:	movl %eax, 0x47aa64
0x004116e7:	cmpl %eax, $0x3<UINT8>
0x004116ea:	jne 0x00411727
0x00411727:	cmpl %eax, $0x2<UINT8>
0x0041172a:	jne 0x0041177f
0x0041177f:	pushl %esi
0x00411780:	pushl $0x0<UINT8>
0x00411782:	pushl 0x47aa60
0x00411788:	call HeapFree@KERNEL32.DLL
HeapFree@KERNEL32.DLL: API Node	
0x0041178e:	movl %ecx, -16(%ebp)
0x00411791:	movl %fs:0, %ecx
0x00411798:	popl %edi
0x00411799:	popl %esi
0x0041179a:	popl %ebx
0x0041179b:	leave
0x0041179c:	ret

0x004162b1:	popl %ecx
0x004162b2:	movl 0x4795a0, %ebx
0x004162b8:	movl (%esi), %ebx
0x004162ba:	popl %edi
0x004162bb:	popl %esi
0x004162bc:	movl 0x47ac8c, $0x1<UINT32>
0x004162c6:	popl %ebx
0x004162c7:	ret

0x00411efd:	call 0x004110e6
0x004110e6:	movl %eax, 0x473108
0x004110eb:	testl %eax, %eax
0x004110ed:	je 2
0x004110ef:	call 0x0041179d
0x0041179d:	call 0x004117b5
0x004117b5:	movl %eax, $0x415ed1<UINT32>
0x004117ba:	movl 0x475574, $0x415b7b<UINT32>
0x004117c4:	movl 0x475570, %eax
0x004117c9:	movl 0x475578, $0x415be1<UINT32>
0x004117d3:	movl 0x47557c, $0x415b21<UINT32>
0x004117dd:	movl 0x475580, $0x415bc9<UINT32>
0x004117e7:	movl 0x475584, %eax
0x004117ec:	ret

0x004117a2:	call 0x00415af8
0x00415af8:	pushl $0x46a4c4<UINT32>
0x00415afd:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x00415b03:	testl %eax, %eax
0x00415b05:	je 21
0x00415b07:	pushl $0x46a4a8<UINT32>
0x00415b0c:	pushl %eax
0x00415b0d:	call GetProcAddress@KERNEL32.DLL
0x00415b13:	testl %eax, %eax
0x00415b15:	je 5
0x00415b17:	pushl $0x0<UINT8>
0x00415b19:	call IsProcessorFeaturePresent@KERNEL32
IsProcessorFeaturePresent@KERNEL32: API Node	
0x00415b1b:	ret

0x004117a7:	movl 0x47959c, %eax
0x004117ac:	call 0x00415aa8
0x00415aa8:	pushl $0x30000<UINT32>
0x00415aad:	pushl $0x10000<UINT32>
0x00415ab2:	call 0x0041838c
0x0041838c:	movl %eax, 0x8(%esp)
0x00418390:	andl %eax, $0xfff7ffff<UINT32>
0x00418395:	pushl %eax
0x00418396:	pushl 0x8(%esp)
0x0041839a:	call 0x00418357
0x00418357:	pushl %ebp
0x00418358:	movl %ebp, %esp
0x0041835a:	pushl %ecx
0x0041835b:	pushl %esi
0x0041835c:	fwait
0x0041835d:	fnstcw -4(%ebp)
0x00418360:	pushl -4(%ebp)
0x00418363:	call 0x004183a2
0x004183a2:	pushl %ebx
0x004183a3:	movl %ebx, 0x8(%esp)
0x004183a7:	xorl %eax, %eax
0x004183a9:	pushl %ebp
0x004183aa:	testb %bl, $0x1<UINT8>
0x004183ad:	pushl %edi
0x004183ae:	je 0x004183b3
0x004183b3:	testb %bl, $0x4<UINT8>
0x004183b6:	je 0x004183ba
0x004183ba:	testb %bl, $0x8<UINT8>
0x004183bd:	je 0x004183c1
0x004183c1:	testb %bl, $0x10<UINT8>
0x004183c4:	je 0x004183c8
0x004183c8:	testb %bl, $0x20<UINT8>
0x004183cb:	je 2
0x004183cd:	orb %al, $0x1<UINT8>
0x004183cf:	testb %bl, $0x2<UINT8>
0x004183d2:	je 0x004183d9
0x004183d9:	movzwl %ecx, %bx
0x004183dc:	pushl %esi
0x004183dd:	movl %edx, %ecx
0x004183df:	movl %esi, $0xc00<UINT32>
0x004183e4:	movl %edi, $0x300<UINT32>
0x004183e9:	andl %edx, %esi
0x004183eb:	movl %ebp, $0x200<UINT32>
0x004183f0:	je 31
0x004183f2:	cmpl %edx, $0x400<UINT32>
0x004183f8:	je 20
0x004183fa:	cmpl %edx, $0x800<UINT32>
0x00418400:	je 8
0x00418402:	cmpl %edx, %esi
0x00418404:	jne 11
0x00418406:	orl %eax, %edi
0x00418408:	jmp 0x00418411
0x00418411:	andl %ecx, %edi
0x00418413:	popl %esi
0x00418414:	je 0x00418421
0x00418421:	orl %eax, $0x20000<UINT32>
0x00418426:	popl %edi
0x00418427:	popl %ebp
0x00418428:	testb %bh, $0x10<UINT8>
0x0041842b:	popl %ebx
0x0041842c:	je 0x00418433
0x00418433:	ret

0x00418368:	movl %esi, %eax
0x0041836a:	movl %eax, 0xc(%ebp)
0x0041836d:	notl %eax
0x0041836f:	andl %esi, %eax
0x00418371:	movl %eax, 0x8(%ebp)
0x00418374:	andl %eax, 0xc(%ebp)
0x00418377:	orl %esi, %eax
0x00418379:	pushl %esi
0x0041837a:	call 0x00418434
0x00418434:	pushl %ebx
0x00418435:	movl %ebx, 0x8(%esp)
0x00418439:	xorl %eax, %eax
0x0041843b:	pushl %esi
0x0041843c:	testb %bl, $0x10<UINT8>
0x0041843f:	je 0x00418444
0x00418444:	testb %bl, $0x8<UINT8>
0x00418447:	je 0x0041844b
0x0041844b:	testb %bl, $0x4<UINT8>
0x0041844e:	je 0x00418452
0x00418452:	testb %bl, $0x2<UINT8>
0x00418455:	je 0x00418459
0x00418459:	testb %bl, $0x1<UINT8>
0x0041845c:	je 2
0x0041845e:	orb %al, $0x20<UINT8>
0x00418460:	testl %ebx, $0x80000<UINT32>
0x00418466:	je 0x0041846a
0x0041846a:	movl %ecx, %ebx
0x0041846c:	movl %edx, $0x300<UINT32>
0x00418471:	andl %ecx, %edx
0x00418473:	movl %esi, $0x200<UINT32>
0x00418478:	je 29
0x0041847a:	cmpl %ecx, $0x100<UINT32>
0x00418480:	je 18
0x00418482:	cmpl %ecx, %esi
0x00418484:	je 9
0x00418486:	cmpl %ecx, %edx
0x00418488:	jne 13
0x0041848a:	orb %ah, $0xc<UINT8>
0x0041848d:	jmp 0x00418497
0x00418497:	movl %ecx, %ebx
0x00418499:	andl %ecx, $0x30000<UINT32>
0x0041849f:	je 12
0x004184a1:	cmpl %ecx, $0x10000<UINT32>
0x004184a7:	jne 6
0x004184a9:	orl %eax, %esi
0x004184ab:	jmp 0x004184af
0x004184af:	popl %esi
0x004184b0:	testl %ebx, $0x40000<UINT32>
0x004184b6:	popl %ebx
0x004184b7:	je 0x004184bc
0x004184bc:	ret

0x0041837f:	popl %ecx
0x00418380:	movl 0xc(%ebp), %eax
0x00418383:	popl %ecx
0x00418384:	fldcw 0xc(%ebp)
0x00418387:	movl %eax, %esi
0x00418389:	popl %esi
0x0041838a:	leave
0x0041838b:	ret

0x0041839f:	popl %ecx
0x004183a0:	popl %ecx
0x004183a1:	ret

0x00415ab7:	popl %ecx
0x00415ab8:	popl %ecx
0x00415ab9:	ret

0x004117b1:	fnclex
0x004117b3:	ret

0x004110f1:	pushl $0x4720a0<UINT32>
0x004110f6:	pushl $0x47208c<UINT32>
0x004110fb:	call 0x004111ec
0x004111ec:	pushl %esi
0x004111ed:	movl %esi, 0x8(%esp)
0x004111f1:	cmpl %esi, 0xc(%esp)
0x004111f5:	jae 0x00411204
0x004111f7:	movl %eax, (%esi)
0x004111f9:	testl %eax, %eax
0x004111fb:	je 0x004111ff
0x004111ff:	addl %esi, $0x4<UINT8>
0x00411202:	jmp 0x004111f1
0x004111fd:	call 0x00417a28
0x004110b7:	pushl $0x80<UINT32>
0x004110bc:	call 0x004119a1
0x004110c1:	testl %eax, %eax
0x004110c3:	popl %ecx
0x004110c4:	movl 0x47ac98, %eax
0x004110c9:	jne 0x004110d8
0x004110d8:	andl (%eax), $0x0<UINT8>
0x004110db:	movl %eax, 0x47ac98
0x004110e0:	movl 0x47ac94, %eax
0x004110e5:	ret

0x00419073:	movl %eax, 0x47a920
0x00419078:	pushl %esi
0x00419079:	pushl $0x14<UINT8>
0x0041907b:	testl %eax, %eax
0x0041907d:	popl %esi
0x0041907e:	jne 7
0x00419080:	movl %eax, $0x200<UINT32>
0x00419085:	jmp 0x0041908d
0x0041908d:	movl 0x47a920, %eax
0x00419092:	pushl $0x4<UINT8>
0x00419094:	pushl %eax
0x00419095:	call 0x0041698f
0x0041909a:	popl %ecx
0x0041909b:	movl 0x47991c, %eax
0x004190a0:	testl %eax, %eax
0x004190a2:	popl %ecx
0x004190a3:	jne 0x004190c6
0x004190c6:	xorl %ecx, %ecx
0x004190c8:	movl %eax, $0x475c80<UINT32>
0x004190cd:	movl %edx, 0x47991c
0x004190d3:	movl (%ecx,%edx), %eax
0x004190d6:	addl %eax, $0x20<UINT8>
0x004190d9:	addl %ecx, $0x4<UINT8>
0x004190dc:	cmpl %eax, $0x475f00<UINT32>
0x004190e1:	jl 0x004190cd
0x004190e3:	xorl %ecx, %ecx
0x004190e5:	movl %edx, $0x475c90<UINT32>
0x004190ea:	movl %esi, %ecx
0x004190ec:	movl %eax, %ecx
0x004190ee:	sarl %esi, $0x5<UINT8>
0x004190f1:	andl %eax, $0x1f<UINT8>
0x004190f4:	movl %esi, 0x47a940(,%esi,4)
0x004190fb:	leal %eax, (%eax,%eax,8)
0x004190fe:	movl %eax, (%esi,%eax,4)
0x00419101:	cmpl %eax, $0xffffffff<UINT8>
0x00419104:	je 4
0x00419106:	testl %eax, %eax
0x00419108:	jne 0x0041910d
0x0041910d:	addl %edx, $0x20<UINT8>
0x00419110:	incl %ecx
0x00419111:	cmpl %edx, $0x475cf0<UINT32>
0x00419117:	jl 0x004190ea
0x00419119:	popl %esi
0x0041911a:	ret

0x00417a17:	pushl $0x4179d1<UINT32>
0x00417a1c:	call SetUnhandledExceptionFilter@KERNEL32.DLL
SetUnhandledExceptionFilter@KERNEL32.DLL: API Node	
0x00417a22:	movl 0x479770, %eax
0x00417a27:	ret

0x00411204:	popl %esi
0x00411205:	ret

0x00411100:	pushl $0x472088<UINT32>
0x00411105:	pushl $0x472000<UINT32>
0x0041110a:	call 0x004111ec
0x0045a21e:	call 0x0045a228
0x0045a228:	pushl $0x40<UINT8>
0x0045a22a:	pushl $0x50<UINT8>
0x0045a22c:	movl %ecx, $0x4775b8<UINT32>
0x0045a231:	call 0x0040a3c9
0x0040a3c9:	movl %eax, 0x4(%esp)
0x0040a3cd:	pushl %esi
0x0040a3ce:	movl %esi, %ecx
0x0040a3d0:	andl 0xc(%esi), $0x0<UINT8>
0x0040a3d4:	andl 0x8(%esi), $0x0<UINT8>
0x0040a3d8:	movl (%esi), %eax
0x0040a3da:	movl %eax, 0xc(%esp)
0x0040a3de:	movl 0x4(%esi), %eax
0x0040a3e1:	leal %eax, 0x10(%esi)
0x0040a3e4:	pushl %eax
0x0040a3e5:	call InitializeCriticalSection@KERNEL32.DLL
0x0040a3eb:	movl %eax, %esi
0x0040a3ed:	popl %esi
0x0040a3ee:	ret $0x8<UINT16>

0x0045a236:	ret

0x0045a223:	jmp 0x0045a237
0x0045a237:	pushl $0x45a243<UINT32>
0x0045a23c:	call 0x004110a5
0x004110a5:	pushl 0x4(%esp)
0x004110a9:	call 0x00411027
0x00411027:	pushl %esi
0x00411028:	call 0x004111da
0x004111da:	pushl $0xd<UINT8>
0x004111dc:	call 0x004139e5
0x004111e1:	popl %ecx
0x004111e2:	ret

0x0041102d:	pushl 0x47ac98
0x00411033:	call 0x00412bc7
0x00412bc7:	pushl %ebp
0x00412bc8:	movl %ebp, %esp
0x00412bca:	pushl $0xffffffff<UINT8>
0x00412bcc:	pushl $0x46a290<UINT32>
0x00412bd1:	pushl $0x4159d0<UINT32>
0x00412bd6:	movl %eax, %fs:0
0x00412bdc:	pushl %eax
0x00412bdd:	movl %fs:0, %esp
0x00412be4:	subl %esp, $0x1c<UINT8>
0x00412be7:	pushl %ebx
0x00412be8:	pushl %esi
0x00412be9:	pushl %edi
0x00412bea:	movl %eax, 0x47aa64
0x00412bef:	cmpl %eax, $0x3<UINT8>
0x00412bf2:	jne 0x00412c3a
0x00412c3a:	cmpl %eax, $0x2<UINT8>
0x00412c3d:	jne 0x00412c85
0x00412c85:	pushl 0x8(%ebp)
0x00412c88:	pushl $0x0<UINT8>
0x00412c8a:	pushl 0x47aa60
0x00412c90:	call HeapSize@KERNEL32.DLL
HeapSize@KERNEL32.DLL: API Node	
0x00412c96:	movl %esi, %eax
0x00412c98:	movl %eax, %esi
0x00412c9a:	movl %ecx, -16(%ebp)
0x00412c9d:	movl %fs:0, %ecx
0x00412ca4:	popl %edi
0x00412ca5:	popl %esi
0x00412ca6:	popl %ebx
0x00412ca7:	leave
0x00412ca8:	ret

0x00411038:	movl %edx, 0x47ac98
0x0041103e:	popl %ecx
0x0041103f:	movl %ecx, 0x47ac94
0x00411045:	movl %esi, %ecx
0x00411047:	subl %esi, %edx
0x00411049:	addl %esi, $0x4<UINT8>
0x0041104c:	cmpl %eax, %esi
0x0041104e:	jae 0x0041108d
0x0041108d:	movl %eax, 0x8(%esp)
0x00411091:	movl (%ecx), %eax
0x00411093:	addl 0x47ac94, $0x4<UINT8>
0x0041109a:	movl %esi, %eax
0x0041109c:	call 0x004111e3
0x004111e3:	pushl $0xd<UINT8>
0x004111e5:	call 0x00413a46
0x004111ea:	popl %ecx
0x004111eb:	ret

0x004110a1:	movl %eax, %esi
0x004110a3:	popl %esi
0x004110a4:	ret

0x004110ae:	negl %eax
0x004110b0:	sbbl %eax, %eax
0x004110b2:	popl %ecx
0x004110b3:	negl %eax
0x004110b5:	decl %eax
0x004110b6:	ret

0x0045a241:	popl %ecx
0x0045a242:	ret

0x0045a24d:	call 0x0045a257
0x0045a257:	pushl $0x40<UINT8>
0x0045a259:	pushl $0x90<UINT32>
0x0045a25e:	movl %ecx, $0x477590<UINT32>
0x0045a263:	call 0x0040a3c9
0x0045a268:	ret

0x0045a252:	jmp 0x0045a269
0x0045a269:	pushl $0x45a275<UINT32>
0x0045a26e:	call 0x004110a5
0x0045a273:	popl %ecx
0x0045a274:	ret

0x0045a27f:	call 0x0045a289
0x0045a289:	pushl $0x40<UINT8>
0x0045a28b:	pushl $0x110<UINT32>
0x0045a290:	movl %ecx, $0x477568<UINT32>
0x0045a295:	call 0x0040a3c9
0x0045a29a:	ret

0x0045a284:	jmp 0x0045a29b
0x0045a29b:	pushl $0x45a2a7<UINT32>
0x0045a2a0:	call 0x004110a5
0x0045a2a5:	popl %ecx
0x0045a2a6:	ret

0x0045a2b1:	call 0x0045a2bb
0x0045a2bb:	pushl $0x40<UINT8>
0x0045a2bd:	pushl $0x210<UINT32>
0x0045a2c2:	movl %ecx, $0x477540<UINT32>
0x0045a2c7:	call 0x0040a3c9
0x0045a2cc:	ret

0x0045a2b6:	jmp 0x0045a2cd
0x0045a2cd:	pushl $0x45a2d9<UINT32>
0x0045a2d2:	call 0x004110a5
0x0045a2d7:	popl %ecx
0x0045a2d8:	ret

0x00461448:	call 0x00461452
0x00461452:	pushl $0x40<UINT8>
0x00461454:	pushl $0x3c<UINT8>
0x00461456:	movl %ecx, $0x478df0<UINT32>
0x0046145b:	call 0x0040a3c9
0x00461460:	ret

0x0046144d:	jmp 0x00461461
0x00461461:	pushl $0x46146d<UINT32>
0x00461466:	call 0x004110a5
0x0046146b:	popl %ecx
0x0046146c:	ret

0x00461640:	call 0x0046164a
0x0046164a:	pushl $0x40<UINT8>
0x0046164c:	pushl $0x10<UINT8>
0x0046164e:	movl %ecx, $0x479098<UINT32>
0x00461653:	call 0x0040a3c9
0x00461658:	ret

0x00461645:	jmp 0x00461659
0x00461659:	pushl $0x461665<UINT32>
0x0046165e:	call 0x004110a5
0x00461663:	popl %ecx
0x00461664:	ret

0x00461680:	call 0x0046168a
0x0046168a:	pushl $0x40<UINT8>
0x0046168c:	pushl $0x8<UINT8>
0x0046168e:	movl %ecx, $0x479070<UINT32>
0x00461693:	call 0x0040a3c9
0x00461698:	ret

0x00461685:	jmp 0x00461699
0x00461699:	pushl $0x4616a5<UINT32>
0x0046169e:	call 0x004110a5
0x004616a3:	popl %ecx
0x004616a4:	ret

0x004619a0:	call 0x004619aa
0x004619aa:	ret

0x004619a5:	jmp 0x004619ab
0x004619ab:	pushl $0x4619b7<UINT32>
0x004619b0:	call 0x004110a5
0x004619b5:	popl %ecx
0x004619b6:	ret

0x00461b9c:	call 0x00461ba6
0x00461ba6:	ret

0x00461ba1:	jmp 0x00461ba7
0x00461ba7:	pushl $0x461bb3<UINT32>
0x00461bac:	call 0x004110a5
0x00461bb1:	popl %ecx
0x00461bb2:	ret

0x00461d02:	call 0x00461d0c
0x00461d0c:	pushl $0x40<UINT8>
0x00461d0e:	pushl $0x8<UINT8>
0x00461d10:	movl %ecx, $0x4790d8<UINT32>
0x00461d15:	call 0x0040a3c9
0x00461d1a:	ret

0x00461d07:	jmp 0x00461d1b
0x00461d1b:	pushl $0x461d27<UINT32>
0x00461d20:	call 0x004110a5
0x00461d25:	popl %ecx
0x00461d26:	ret

0x0046108c:	call 0x00461096
0x00461096:	ret

0x00461091:	jmp 0x00461097
0x00461097:	pushl $0x4610a3<UINT32>
0x0046109c:	call 0x004110a5
0x004610a1:	popl %ecx
0x004610a2:	ret

0x00462656:	call 0x00462660
0x00462660:	ret

0x0046265b:	jmp 0x00462661
0x00462661:	pushl $0x46266d<UINT32>
0x00462666:	call 0x004110a5
0x0046266b:	popl %ecx
0x0046266c:	ret

0x0046267c:	call 0x00462686
0x00462686:	ret

0x00462681:	jmp 0x00462687
0x00462687:	pushl $0x462693<UINT32>
0x0046268c:	call 0x004110a5
0x00462691:	popl %ecx
0x00462692:	ret

0x00462bf8:	call 0x00462c02
0x00462c02:	ret

0x00462bfd:	jmp 0x00462c03
0x00462c03:	pushl $0x462c0f<UINT32>
0x00462c08:	call 0x004110a5
0x00462c0d:	popl %ecx
0x00462c0e:	ret

0x00456d20:	jmp 0x00456d25
0x00456d25:	pushl $0x600<UINT32>
0x00456d2a:	pushl $0x0<UINT8>
0x00456d2c:	call 0x00456cef
0x00456cef:	call 0x00461bbd
0x00461bbd:	pushl $0x461174<UINT32>
0x00461bc2:	movl %ecx, $0x4790c8<UINT32>
0x00461bc7:	call 0x004621cd
0x004621cd:	pushl %esi
0x004621ce:	pushl %edi
0x004621cf:	movl %edi, %ecx
0x004621d1:	cmpl (%edi), $0x0<UINT8>
0x004621d4:	jne 45
0x004621d6:	movl %ecx, 0x479104
0x004621dc:	testl %ecx, %ecx
0x004621de:	jne 28
0x004621e0:	movl %ecx, $0x479108<UINT32>
0x004621e5:	movl %eax, %ecx
0x004621e7:	testl %eax, %eax
0x004621e9:	je 9
0x004621eb:	call 0x00461dcd
0x00461dcd:	pushl %esi
0x00461dce:	movl %esi, %ecx
0x00461dd0:	xorl %eax, %eax
0x00461dd2:	movl 0x14(%esi), %eax
0x00461dd5:	movl 0x18(%esi), %eax
0x00461dd8:	movl 0x18(%esi), $0x4<UINT32>
0x00461ddf:	movl 0x4(%esi), %eax
0x00461de2:	movl 0x8(%esi), $0x1<UINT32>
0x00461de9:	movl 0xc(%esi), %eax
0x00461dec:	movl 0x10(%esi), %eax
0x00461def:	call TlsAlloc@KERNEL32.DLL
0x00461df5:	cmpl %eax, $0xffffffff<UINT8>
0x00461df8:	movl (%esi), %eax
0x00461dfa:	jne 0x00461e01
0x00461e01:	leal %eax, 0x1c(%esi)
0x00461e04:	pushl %eax
0x00461e05:	call InitializeCriticalSection@KERNEL32.DLL
0x00461e0b:	movl %eax, %esi
0x00461e0d:	popl %esi
0x00461e0e:	ret

0x004621f0:	movl %ecx, %eax
0x004621f2:	jmp 0x004621f6
0x004621f6:	movl 0x479104, %ecx
0x004621fc:	call 0x00461e66
0x00461e66:	pushl %ecx
0x00461e67:	pushl %ecx
0x00461e68:	pushl %ebp
0x00461e69:	pushl %esi
0x00461e6a:	movl %esi, %ecx
0x00461e6c:	pushl %edi
0x00461e6d:	leal %eax, 0x1c(%esi)
0x00461e70:	pushl %eax
0x00461e71:	movl 0x14(%esp), %eax
0x00461e75:	call EnterCriticalSection@KERNEL32.DLL
0x00461e7b:	movl %ebp, 0x4(%esi)
0x00461e7e:	movl %edi, 0x8(%esi)
0x00461e81:	cmpl %edi, %ebp
0x00461e83:	jnl 0x00461e92
0x00461e92:	pushl $0x1<UINT8>
0x00461e94:	popl %edi
0x00461e95:	cmpl %ebp, %edi
0x00461e97:	jle 0x00461eb4
0x00461eb4:	movl %eax, 0x10(%esi)
0x00461eb7:	addl %ebp, $0x20<UINT8>
0x00461eba:	testl %eax, %eax
0x00461ebc:	pushl %ebx
0x00461ebd:	jne 19
0x00461ebf:	movl %eax, %ebp
0x00461ec1:	shll %eax, $0x3<UINT8>
0x00461ec4:	pushl %eax
0x00461ec5:	pushl $0x2002<UINT32>
0x00461eca:	call GlobalAlloc@KERNEL32.DLL
GlobalAlloc@KERNEL32.DLL: API Node	
0x00461ed0:	jmp 0x00461ef4
0x00461ef4:	movl %ebx, 0x4671a0
0x00461efa:	movl 0x10(%esp), %eax
0x00461efe:	testl %eax, %eax
0x00461f00:	jne 0x00461f1d
0x00461f1d:	pushl 0x10(%esp)
0x00461f21:	call GlobalLock@KERNEL32.DLL
GlobalLock@KERNEL32.DLL: API Node	
0x00461f23:	movl %ebx, %eax
0x00461f25:	movl %eax, 0x4(%esi)
0x00461f28:	movl %ecx, %eax
0x00461f2a:	imull %ecx, %ecx, $0x1fffffff<UINT32>
0x00461f30:	addl %ecx, %ebp
0x00461f32:	leal %eax, (%ebx,%eax,8)
0x00461f35:	shll %ecx, $0x3<UINT8>
0x00461f38:	pushl %ecx
0x00461f39:	pushl $0x0<UINT8>
0x00461f3b:	pushl %eax
0x00461f3c:	call 0x00412010
0x00461f41:	addl %esp, $0xc<UINT8>
0x00461f44:	movl 0x10(%esi), %ebx
0x00461f47:	movl 0x4(%esi), %ebp
0x00461f4a:	popl %ebx
0x00461f4b:	cmpl %edi, 0xc(%esi)
0x00461f4e:	jl 6
0x00461f50:	leal %eax, 0x1(%edi)
0x00461f53:	movl 0xc(%esi), %eax
0x00461f56:	movl %eax, 0x10(%esi)
0x00461f59:	orl (%eax,%edi,8), $0x1<UINT8>
0x00461f5d:	pushl 0x10(%esp)
0x00461f61:	leal %eax, (%eax,%edi,8)
0x00461f64:	leal %eax, 0x1(%edi)
0x00461f67:	movl 0x8(%esi), %eax
0x00461f6a:	call LeaveCriticalSection@KERNEL32.DLL
0x00461f70:	movl %eax, %edi
0x00461f72:	popl %edi
0x00461f73:	popl %esi
0x00461f74:	popl %ebp
0x00461f75:	popl %ecx
0x00461f76:	popl %ecx
0x00461f77:	ret

0x00462201:	movl (%edi), %eax
0x00462203:	movl %eax, 0x479104
0x00462208:	movl %esi, (%edi)
0x0046220a:	pushl (%eax)
0x0046220c:	call TlsGetValue@KERNEL32.DLL
TlsGetValue@KERNEL32.DLL: API Node	
0x00462212:	testl %eax, %eax
0x00462214:	je 0x00462223
0x00462223:	xorl %esi, %esi
0x00462225:	testl %esi, %esi
0x00462227:	jne 20
0x00462229:	call 0x00461174
0x00461174:	movl %eax, $0x465419<UINT32>
0x00461179:	call 0x00411ff0
0x00411ff0:	pushl $0xffffffff<UINT8>
0x00411ff2:	pushl %eax
0x00411ff3:	movl %eax, %fs:0
0x00411ff9:	pushl %eax
0x00411ffa:	movl %eax, 0xc(%esp)
0x00411ffe:	movl %fs:0, %esp
0x00412005:	movl 0xc(%esp), %ebp
0x00412009:	leal %ebp, 0xc(%esp)
0x0041200d:	pushl %eax
0x0041200e:	ret

0x0046117e:	pushl %ecx
0x0046117f:	pushl $0x118<UINT32>
0x00461184:	call 0x00461d9b
0x00461d9b:	pushl %esi
0x00461d9c:	pushl 0x8(%esp)
0x00461da0:	pushl $0x40<UINT8>
0x00461da2:	call LocalAlloc@KERNEL32.DLL
LocalAlloc@KERNEL32.DLL: API Node	
0x00461da8:	movl %esi, %eax
0x00461daa:	testl %esi, %esi
0x00461dac:	jne 0x00461db3
0x00461db3:	movl %eax, %esi
0x00461db5:	popl %esi
0x00461db6:	ret $0x4<UINT16>

0x00461189:	movl %ecx, %eax
0x0046118b:	movl -16(%ebp), %ecx
0x0046118e:	xorl %eax, %eax
0x00461190:	cmpl %ecx, %eax
0x00461192:	movl -4(%ebp), %eax
0x00461195:	je 5
0x00461197:	call 0x004618ea
0x004618ea:	movl %eax, %ecx
0x004618ec:	orl 0xd4(%eax), $0xffffffff<UINT8>
0x00465419:	movl %eax, $0x46d8a8<UINT32>
0x0046541e:	jmp 0x00411297
0x00411297:	pushl %ebp
0x00411298:	movl %ebp, %esp
0x0041129a:	subl %esp, $0x4<UINT8>
0x0041129d:	pushl %ebx
0x0041129e:	pushl %esi
0x0041129f:	pushl %edi
0x004112a0:	cld
0x004112a1:	movl -4(%ebp), %eax
0x004112a4:	xorl %eax, %eax
0x004112a6:	pushl %eax
0x004112a7:	pushl %eax
0x004112a8:	pushl %eax
0x004112a9:	pushl -4(%ebp)
0x004112ac:	pushl 0x14(%ebp)
0x004112af:	pushl 0x10(%ebp)
0x004112b2:	pushl 0xc(%ebp)
0x004112b5:	pushl 0x8(%ebp)
0x004112b8:	call 0x00413a5b
0x00413a5b:	pushl %ebp
0x00413a5c:	movl %ebp, %esp
0x00413a5e:	pushl %esi
0x00413a5f:	movl %esi, 0x18(%ebp)
0x00413a62:	pushl %edi
0x00413a63:	movl %edi, $0x19930520<UINT32>
0x00413a68:	cmpl (%esi), %edi
0x00413a6a:	je 0x00413a71
0x00413a71:	movl %eax, 0x8(%ebp)
0x00413a74:	testb 0x4(%eax), $0x66<UINT8>
0x00413a78:	je 0x00413a99
0x00413a99:	cmpl 0xc(%esi), $0x0<UINT8>
0x00413a9d:	je 0x00413aef
0x00413aef:	pushl $0x1<UINT8>
0x00413af1:	popl %eax
0x00413af2:	popl %edi
0x00413af3:	popl %esi
0x00413af4:	popl %ebp
0x00413af5:	ret

0x004112bd:	addl %esp, $0x20<UINT8>
0x004112c0:	movl 0x14(%ebp), %eax
0x004112c3:	popl %edi
0x004112c4:	popl %esi
0x004112c5:	popl %ebx
0x004112c6:	movl %eax, 0x14(%ebp)
0x004112c9:	movl %esp, %ebp
0x004112cb:	popl %ebp
0x004112cc:	ret

0x004618f3:	orl 0x104(%eax), $0xffffffff<UINT8>
0x004618fa:	movl (%eax), $0x469064<UINT32>
0x00461900:	ret

0x0046119c:	movl %ecx, -12(%ebp)
0x0046119f:	movl %fs:0, %ecx
0x004611a6:	leave
0x004611a7:	ret

0x0046222d:	movl %ecx, 0x479104
0x00462233:	movl %esi, %eax
0x00462235:	pushl %esi
0x00462236:	pushl (%edi)
0x00462238:	call 0x00461fd5
0x00461fd5:	pushl %ebp
0x00461fd6:	movl %ebp, %esp
0x00461fd8:	pushl %ecx
0x00461fd9:	pushl %ebx
0x00461fda:	pushl %esi
0x00461fdb:	movl %esi, %ecx
0x00461fdd:	pushl %edi
0x00461fde:	pushl (%esi)
0x00461fe0:	call TlsGetValue@KERNEL32.DLL
0x00461fe6:	movl %edi, %eax
0x00461fe8:	testl %edi, %edi
0x00461fea:	je 0x00462006
0x00462006:	pushl $0x10<UINT8>
0x00462008:	call 0x00461d9b
0x0046200d:	testl %eax, %eax
0x0046200f:	je 10
0x00462011:	movl (%eax), $0x4690fc<UINT32>
0x004159d0:	pushl %ebp
0x004159d1:	movl %ebp, %esp
0x004159d3:	subl %esp, $0x8<UINT8>
0x004159d6:	pushl %ebx
0x004159d7:	pushl %esi
0x004159d8:	pushl %edi
0x004159d9:	pushl %ebp
0x004159da:	cld
0x004159db:	movl %ebx, 0xc(%ebp)
0x004159de:	movl %eax, 0x8(%ebp)
0x004159e1:	testl 0x4(%eax), $0x6<UINT32>
0x004159e8:	jne 130
0x004159ee:	movl -8(%ebp), %eax
0x004159f1:	movl %eax, 0x10(%ebp)
0x004159f4:	movl -4(%ebp), %eax
0x004159f7:	leal %eax, -8(%ebp)
0x004159fa:	movl -4(%ebx), %eax
0x004159fd:	movl %esi, 0xc(%ebx)
0x00415a00:	movl %edi, 0x8(%ebx)
0x00415a03:	cmpl %esi, $0xffffffff<UINT8>
0x00415a06:	je 97
0x00415a08:	leal %ecx, (%esi,%esi,2)
0x00415a0b:	cmpl 0x4(%edi,%ecx,4), $0x0<UINT8>
0x00415a10:	je 69
0x00415a12:	pushl %esi
0x00415a13:	pushl %ebp
0x00415a14:	leal %ebp, 0x10(%ebx)
0x00415a17:	call 0x00411f41
0x00411f41:	movl %eax, -20(%ebp)
0x00411f44:	movl %ecx, (%eax)
0x00411f46:	movl %ecx, (%ecx)
0x00411f48:	movl -104(%ebp), %ecx
0x00411f4b:	pushl %eax
0x00411f4c:	pushl %ecx
0x00411f4d:	call 0x0041603f
0x0041603f:	pushl %ebp
0x00416040:	movl %ebp, %esp
0x00416042:	pushl %ecx
0x00416043:	pushl %ebx
0x00416044:	pushl %esi
0x00416045:	call 0x00414333
0x00414333:	pushl %esi
0x00414334:	pushl %edi
0x00414335:	call GetLastError@KERNEL32.DLL
GetLastError@KERNEL32.DLL: API Node	
0x0041433b:	pushl 0x473530
0x00414341:	movl %edi, %eax
0x00414343:	call TlsGetValue@KERNEL32.DLL
0x00414349:	movl %esi, %eax
0x0041434b:	testl %esi, %esi
0x0041434d:	jne 0x0041438e
0x0041438e:	pushl %edi
0x0041438f:	call SetLastError@KERNEL32.DLL
SetLastError@KERNEL32.DLL: API Node	
0x00414395:	movl %eax, %esi
0x00414397:	popl %edi
0x00414398:	popl %esi
0x00414399:	ret

0x0041604a:	movl %esi, %eax
0x0041604c:	pushl 0x50(%esi)
0x0041604f:	pushl 0x8(%ebp)
0x00416052:	call 0x0041617d
0x0041617d:	movl %edx, 0x8(%esp)
0x00416181:	movl %ecx, 0x475834
0x00416187:	pushl %esi
0x00416188:	movl %esi, 0x8(%esp)
0x0041618c:	cmpl (%edx), %esi
0x0041618e:	pushl %edi
0x0041618f:	movl %eax, %edx
0x00416191:	je 0x004161a4
0x004161a4:	leal %ecx, (%ecx,%ecx,2)
0x004161a7:	leal %ecx, (%edx,%ecx,4)
0x004161aa:	cmpl %eax, %ecx
0x004161ac:	jae 4
0x004161ae:	cmpl (%eax), %esi
0x004161b0:	je 0x004161b4
0x004161b4:	popl %edi
0x004161b5:	popl %esi
0x004161b6:	ret

0x00416057:	popl %ecx
0x00416058:	testl %eax, %eax
0x0041605a:	popl %ecx
0x0041605b:	je 271
0x00416061:	movl %ebx, 0x8(%eax)
0x00416064:	testl %ebx, %ebx
0x00416066:	movl 0x8(%ebp), %ebx
0x00416069:	je 0x00416170
0x00416170:	pushl 0xc(%ebp)
0x00416173:	call UnhandledExceptionFilter@KERNEL32.DLL
UnhandledExceptionFilter@KERNEL32.DLL: API Node	
0x00416179:	popl %esi
0x0041617a:	popl %ebx
0x0041617b:	leave
0x0041617c:	ret

0x00411f52:	popl %ecx
0x00411f53:	popl %ecx
0x00411f54:	ret

0x00415a1b:	popl %ebp
0x00415a1c:	popl %esi
0x00415a1d:	movl %ebx, 0xc(%ebp)
0x00415a20:	orl %eax, %eax
0x00415a22:	je 51
0x00415a24:	js 60
0x00415a26:	movl %edi, 0x8(%ebx)
0x00415a29:	pushl %ebx
0x00415a2a:	call 0x004114ec
0x004114ec:	pushl %ebp
0x004114ed:	movl %ebp, %esp
0x004114ef:	pushl %ebx
0x004114f0:	pushl %esi
0x004114f1:	pushl %edi
0x004114f2:	pushl %ebp
0x004114f3:	pushl $0x0<UINT8>
0x004114f5:	pushl $0x0<UINT8>
0x004114f7:	pushl $0x411504<UINT32>
0x004114fc:	pushl 0x8(%ebp)
0x004114ff:	call 0x0041ac26
0x0041ac26:	jmp RtlUnwind@KERNEL32.DLL
RtlUnwind@KERNEL32.DLL: API Node	
0x00411504:	popl %ebp
0x00411505:	popl %edi
0x00411506:	popl %esi
0x00411507:	popl %ebx
0x00411508:	movl %esp, %ebp
0x0041150a:	popl %ebp
0x0041150b:	ret

0x00415a2f:	addl %esp, $0x4<UINT8>
0x00415a32:	leal %ebp, 0x10(%ebx)
0x00415a35:	pushl %esi
0x00415a36:	pushl %ebx
0x00415a37:	call 0x0041152e
0x0041152e:	pushl %ebx
0x0041152f:	pushl %esi
0x00411530:	pushl %edi
0x00411531:	movl %eax, 0x10(%esp)
0x00411535:	pushl %eax
0x00411536:	pushl $0xfffffffe<UINT8>
0x00411538:	pushl $0x41150c<UINT32>
0x0041153d:	pushl %fs:0
0x00411544:	movl %fs:0, %esp
0x0041154b:	movl %eax, 0x20(%esp)
0x0041154f:	movl %ebx, 0x8(%eax)
0x00411552:	movl %esi, 0xc(%eax)
0x00411555:	cmpl %esi, $0xffffffff<UINT8>
0x00411558:	je 46
0x0041155a:	cmpl %esi, 0x24(%esp)
0x0041155e:	je 0x00411588
0x00411588:	popl %fs:0
0x0041158f:	addl %esp, $0xc<UINT8>
0x00411592:	popl %edi
0x00411593:	popl %esi
0x00411594:	popl %ebx
0x00411595:	ret

0x00415a3c:	addl %esp, $0x8<UINT8>
0x00415a3f:	leal %ecx, (%esi,%esi,2)
0x00415a42:	pushl $0x1<UINT8>
0x00415a44:	movl %eax, 0x8(%edi,%ecx,4)
0x00415a48:	call 0x004115c2
0x004115c2:	pushl %ebx
0x004115c3:	pushl %ecx
0x004115c4:	movl %ebx, $0x4730f0<UINT32>
0x004115c9:	movl %ecx, 0x8(%ebp)
0x004115cc:	movl 0x8(%ebx), %ecx
0x004115cf:	movl 0x4(%ebx), %eax
0x004115d2:	movl 0xc(%ebx), %ebp
0x004115d5:	popl %ecx
0x004115d6:	popl %ebx
0x004115d7:	ret $0x4<UINT16>

0x00415a4d:	movl %eax, (%edi,%ecx,4)
0x00415a50:	movl 0xc(%ebx), %eax
0x00415a53:	call 0x00411f55
0x00411f55:	movl %esp, -24(%ebp)
0x00411f58:	pushl -104(%ebp)
0x00411f5b:	call 0x00411124
0x00411124:	pushl $0x0<UINT8>
0x00411126:	pushl $0x1<UINT8>
0x00411128:	pushl 0xc(%esp)
0x0041112c:	call 0x00411135
0x00411135:	pushl %edi
0x00411136:	call 0x004111da
0x0041113b:	pushl $0x1<UINT8>
0x0041113d:	popl %edi
0x0041113e:	cmpl 0x479594, %edi
0x00411144:	jne 0x00411157
0x00411157:	cmpl 0xc(%esp), $0x0<UINT8>
0x0041115c:	pushl %ebx
0x0041115d:	movl %ebx, 0x14(%esp)
0x00411161:	movl 0x479590, %edi
0x00411167:	movb 0x47958c, %bl
0x0041116d:	jne 0x004111ab
0x004111ab:	pushl $0x4720b8<UINT32>
0x004111b0:	pushl $0x4720b0<UINT32>
0x004111b5:	call 0x004111ec
0x00417a28:	pushl 0x479770
0x00417a2e:	call SetUnhandledExceptionFilter@KERNEL32.DLL
0x00417a34:	ret

0x004111ba:	popl %ecx
0x004111bb:	popl %ecx
0x004111bc:	testl %ebx, %ebx
0x004111be:	popl %ebx
0x004111bf:	je 0x004111c8
0x004111c8:	pushl 0x8(%esp)
0x004111cc:	movl 0x479594, %edi
0x004111d2:	call ExitProcess@KERNEL32.DLL
ExitProcess@KERNEL32.DLL: Exit Node	
