0x004c4980:	pusha
0x004c4981:	movl %esi, $0x495000<UINT32>
0x004c4986:	leal %edi, -606208(%esi)
0x004c498c:	pushl %edi
0x004c498d:	jmp 0x004c499a
0x004c499a:	movl %ebx, (%esi)
0x004c499c:	subl %esi, $0xfffffffc<UINT8>
0x004c499f:	adcl %ebx, %ebx
0x004c49a1:	jb 0x004c4990
0x004c4990:	movb %al, (%esi)
0x004c4992:	incl %esi
0x004c4993:	movb (%edi), %al
0x004c4995:	incl %edi
0x004c4996:	addl %ebx, %ebx
0x004c4998:	jne 0x004c49a1
0x004c49a3:	movl %eax, $0x1<UINT32>
0x004c49a8:	addl %ebx, %ebx
0x004c49aa:	jne 0x004c49b3
0x004c49b3:	adcl %eax, %eax
0x004c49b5:	addl %ebx, %ebx
0x004c49b7:	jae 0x004c49c4
0x004c49b9:	jne 0x004c49e3
0x004c49e3:	xorl %ecx, %ecx
0x004c49e5:	subl %eax, $0x3<UINT8>
0x004c49e8:	jb 0x004c49fb
0x004c49ea:	shll %eax, $0x8<UINT8>
0x004c49ed:	movb %al, (%esi)
0x004c49ef:	incl %esi
0x004c49f0:	xorl %eax, $0xffffffff<UINT8>
0x004c49f3:	je 0x004c4a6a
0x004c49f5:	sarl %eax
0x004c49f7:	movl %ebp, %eax
0x004c49f9:	jmp 0x004c4a06
0x004c4a06:	jb 0x004c49d4
0x004c49d4:	addl %ebx, %ebx
0x004c49d6:	jne 0x004c49df
0x004c49df:	adcl %ecx, %ecx
0x004c49e1:	jmp 0x004c4a35
0x004c4a35:	cmpl %ebp, $0xfffffb00<UINT32>
0x004c4a3b:	adcl %ecx, $0x2<UINT8>
0x004c4a3e:	leal %edx, (%edi,%ebp)
0x004c4a41:	cmpl %ebp, $0xfffffffc<UINT8>
0x004c4a44:	jbe 0x004c4a54
0x004c4a46:	movb %al, (%edx)
0x004c4a48:	incl %edx
0x004c4a49:	movb (%edi), %al
0x004c4a4b:	incl %edi
0x004c4a4c:	decl %ecx
0x004c4a4d:	jne 0x004c4a46
0x004c4a4f:	jmp 0x004c4996
0x004c4a08:	incl %ecx
0x004c4a09:	addl %ebx, %ebx
0x004c4a0b:	jne 0x004c4a14
0x004c4a14:	jb 0x004c49d4
0x004c4a16:	addl %ebx, %ebx
0x004c4a18:	jne 0x004c4a21
0x004c4a21:	adcl %ecx, %ecx
0x004c4a23:	addl %ebx, %ebx
0x004c4a25:	jae 0x004c4a16
0x004c4a27:	jne 0x004c4a32
0x004c4a32:	addl %ecx, $0x2<UINT8>
0x004c4a54:	movl %eax, (%edx)
0x004c4a56:	addl %edx, $0x4<UINT8>
0x004c4a59:	movl (%edi), %eax
0x004c4a5b:	addl %edi, $0x4<UINT8>
0x004c4a5e:	subl %ecx, $0x4<UINT8>
0x004c4a61:	ja 0x004c4a54
0x004c4a63:	addl %edi, %ecx
0x004c4a65:	jmp 0x004c4996
0x004c49fb:	addl %ebx, %ebx
0x004c49fd:	jne 0x004c4a06
0x004c49c4:	decl %eax
0x004c49c5:	addl %ebx, %ebx
0x004c49c7:	jne 0x004c49d0
0x004c49d0:	adcl %eax, %eax
0x004c49d2:	jmp 0x004c49a8
0x004c49bb:	movl %ebx, (%esi)
0x004c49bd:	subl %esi, $0xfffffffc<UINT8>
0x004c49c0:	adcl %ebx, %ebx
0x004c49c2:	jb 0x004c49e3
0x004c49ac:	movl %ebx, (%esi)
0x004c49ae:	subl %esi, $0xfffffffc<UINT8>
0x004c49b1:	adcl %ebx, %ebx
0x004c49d8:	movl %ebx, (%esi)
0x004c49da:	subl %esi, $0xfffffffc<UINT8>
0x004c49dd:	adcl %ebx, %ebx
0x004c4a29:	movl %ebx, (%esi)
0x004c4a2b:	subl %esi, $0xfffffffc<UINT8>
0x004c4a2e:	adcl %ebx, %ebx
0x004c4a30:	jae 0x004c4a16
0x004c4a0d:	movl %ebx, (%esi)
0x004c4a0f:	subl %esi, $0xfffffffc<UINT8>
0x004c4a12:	adcl %ebx, %ebx
0x004c4a1a:	movl %ebx, (%esi)
0x004c4a1c:	subl %esi, $0xfffffffc<UINT8>
0x004c4a1f:	adcl %ebx, %ebx
0x004c49c9:	movl %ebx, (%esi)
0x004c49cb:	subl %esi, $0xfffffffc<UINT8>
0x004c49ce:	adcl %ebx, %ebx
0x004c49ff:	movl %ebx, (%esi)
0x004c4a01:	subl %esi, $0xfffffffc<UINT8>
0x004c4a04:	adcl %ebx, %ebx
0x004c4a6a:	popl %esi
0x004c4a6b:	movl %edi, %esi
0x004c4a6d:	movl %ecx, $0xa9f<UINT32>
0x004c4a72:	movb %al, (%edi)
0x004c4a74:	incl %edi
0x004c4a75:	subb %al, $0xffffffe8<UINT8>
0x004c4a77:	cmpb %al, $0x1<UINT8>
0x004c4a79:	ja 0x004c4a72
0x004c4a7b:	cmpb (%edi), $0x9<UINT8>
0x004c4a7e:	jne 0x004c4a72
0x004c4a80:	movl %eax, (%edi)
0x004c4a82:	movb %bl, 0x4(%edi)
0x004c4a85:	shrw %ax, $0x8<UINT8>
0x004c4a89:	roll %eax, $0x10<UINT8>
0x004c4a8c:	xchgb %ah, %al
0x004c4a8e:	subl %eax, %edi
0x004c4a90:	subb %bl, $0xffffffe8<UINT8>
0x004c4a93:	addl %eax, %esi
0x004c4a95:	movl (%edi), %eax
0x004c4a97:	addl %edi, $0x5<UINT8>
0x004c4a9a:	movb %al, %bl
0x004c4a9c:	loop 0x004c4a77
0x004c4a9e:	leal %edi, 0xc1000(%esi)
0x004c4aa4:	movl %eax, (%edi)
0x004c4aa6:	orl %eax, %eax
0x004c4aa8:	je 0x004c4ae6
0x004c4aaa:	movl %ebx, 0x4(%edi)
0x004c4aad:	leal %eax, 0xc485c(%eax,%esi)
0x004c4ab4:	addl %ebx, %esi
0x004c4ab6:	pushl %eax
0x004c4ab7:	addl %edi, $0x8<UINT8>
0x004c4aba:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004c4ac0:	xchgl %ebp, %eax
0x004c4ac1:	movb %al, (%edi)
0x004c4ac3:	incl %edi
0x004c4ac4:	orb %al, %al
0x004c4ac6:	je 0x004c4aa4
0x004c4ac8:	movl %ecx, %edi
0x004c4aca:	pushl %edi
0x004c4acb:	decl %eax
0x004c4acc:	repn scasb %al, %es:(%edi)
0x004c4ace:	pushl %ebp
0x004c4acf:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x004c4ad5:	orl %eax, %eax
0x004c4ad7:	je 7
0x004c4ad9:	movl (%ebx), %eax
0x004c4adb:	addl %ebx, $0x4<UINT8>
0x004c4ade:	jmp 0x004c4ac1
GetProcAddress@KERNEL32.DLL: API Node	
0x004c4ae6:	addl %edi, $0x4<UINT8>
0x004c4ae9:	leal %ebx, -4(%esi)
0x004c4aec:	xorl %eax, %eax
0x004c4aee:	movb %al, (%edi)
0x004c4af0:	incl %edi
0x004c4af1:	orl %eax, %eax
0x004c4af3:	je 0x004c4b17
0x004c4af5:	cmpb %al, $0xffffffef<UINT8>
0x004c4af7:	ja 0x004c4b0a
0x004c4af9:	addl %ebx, %eax
0x004c4afb:	movl %eax, (%ebx)
0x004c4afd:	xchgb %ah, %al
0x004c4aff:	roll %eax, $0x10<UINT8>
0x004c4b02:	xchgb %ah, %al
0x004c4b04:	addl %eax, %esi
0x004c4b06:	movl (%ebx), %eax
0x004c4b08:	jmp 0x004c4aec
0x004c4b0a:	andb %al, $0xf<UINT8>
0x004c4b0c:	shll %eax, $0x10<UINT8>
0x004c4b0f:	movw %ax, (%edi)
0x004c4b12:	addl %edi, $0x2<UINT8>
0x004c4b15:	jmp 0x004c4af9
0x004c4b17:	movl %ebp, 0xc4934(%esi)
0x004c4b1d:	leal %edi, -4096(%esi)
0x004c4b23:	movl %ebx, $0x1000<UINT32>
0x004c4b28:	pushl %eax
0x004c4b29:	pushl %esp
0x004c4b2a:	pushl $0x4<UINT8>
0x004c4b2c:	pushl %ebx
0x004c4b2d:	pushl %edi
0x004c4b2e:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x004c4b30:	leal %eax, 0x20f(%edi)
0x004c4b36:	andb (%eax), $0x7f<UINT8>
0x004c4b39:	andb 0x28(%eax), $0x7f<UINT8>
0x004c4b3d:	popl %eax
0x004c4b3e:	pushl %eax
0x004c4b3f:	pushl %esp
0x004c4b40:	pushl %eax
0x004c4b41:	pushl %ebx
0x004c4b42:	pushl %edi
0x004c4b43:	call VirtualProtect@kernel32.dll
0x004c4b45:	popl %eax
0x004c4b46:	popa
0x004c4b47:	leal %eax, -128(%esp)
0x004c4b4b:	pushl $0x0<UINT8>
0x004c4b4d:	cmpl %esp, %eax
0x004c4b4f:	jne 0x004c4b4b
0x004c4b51:	subl %esp, $0xffffff80<UINT8>
0x004c4b54:	jmp 0x0040c429
0x0040c429:	call 0x00414ad4
0x00414ad4:	pushl %ebp
0x00414ad5:	movl %ebp, %esp
0x00414ad7:	subl %esp, $0x14<UINT8>
0x00414ada:	andl -12(%ebp), $0x0<UINT8>
0x00414ade:	andl -8(%ebp), $0x0<UINT8>
0x00414ae2:	movl %eax, 0x451d80
0x00414ae7:	pushl %esi
0x00414ae8:	pushl %edi
0x00414ae9:	movl %edi, $0xbb40e64e<UINT32>
0x00414aee:	movl %esi, $0xffff0000<UINT32>
0x00414af3:	cmpl %eax, %edi
0x00414af5:	je 0x00414b04
0x00414b04:	leal %eax, -12(%ebp)
0x00414b07:	pushl %eax
0x00414b08:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x00414b0e:	movl %eax, -8(%ebp)
0x00414b11:	xorl %eax, -12(%ebp)
0x00414b14:	movl -4(%ebp), %eax
0x00414b17:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x00414b1d:	xorl -4(%ebp), %eax
0x00414b20:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x00414b26:	xorl -4(%ebp), %eax
0x00414b29:	leal %eax, -20(%ebp)
0x00414b2c:	pushl %eax
0x00414b2d:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x00414b33:	movl %ecx, -16(%ebp)
0x00414b36:	leal %eax, -4(%ebp)
0x00414b39:	xorl %ecx, -20(%ebp)
0x00414b3c:	xorl %ecx, -4(%ebp)
0x00414b3f:	xorl %ecx, %eax
0x00414b41:	cmpl %ecx, %edi
0x00414b43:	jne 0x00414b4c
0x00414b4c:	testl %esi, %ecx
0x00414b4e:	jne 0x00414b5c
0x00414b5c:	movl 0x451d80, %ecx
0x00414b62:	notl %ecx
0x00414b64:	movl 0x451d84, %ecx
0x00414b6a:	popl %edi
0x00414b6b:	popl %esi
0x00414b6c:	movl %esp, %ebp
0x00414b6e:	popl %ebp
0x00414b6f:	ret

0x0040c42e:	jmp 0x0040c2ae
0x0040c2ae:	pushl $0x14<UINT8>
0x0040c2b0:	pushl $0x42e458<UINT32>
0x0040c2b5:	call 0x0040e1d0
0x0040e1d0:	pushl $0x40e230<UINT32>
0x0040e1d5:	pushl %fs:0
0x0040e1dc:	movl %eax, 0x10(%esp)
0x0040e1e0:	movl 0x10(%esp), %ebp
0x0040e1e4:	leal %ebp, 0x10(%esp)
0x0040e1e8:	subl %esp, %eax
0x0040e1ea:	pushl %ebx
0x0040e1eb:	pushl %esi
0x0040e1ec:	pushl %edi
0x0040e1ed:	movl %eax, 0x451d80
0x0040e1f2:	xorl -4(%ebp), %eax
0x0040e1f5:	xorl %eax, %ebp
0x0040e1f7:	pushl %eax
0x0040e1f8:	movl -24(%ebp), %esp
0x0040e1fb:	pushl -8(%ebp)
0x0040e1fe:	movl %eax, -4(%ebp)
0x0040e201:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040e208:	movl -8(%ebp), %eax
0x0040e20b:	leal %eax, -16(%ebp)
0x0040e20e:	movl %fs:0, %eax
0x0040e214:	ret

0x0040c2ba:	pushl $0x1<UINT8>
0x0040c2bc:	call 0x00414a87
0x00414a87:	pushl %ebp
0x00414a88:	movl %ebp, %esp
0x00414a8a:	movl %eax, 0x8(%ebp)
0x00414a8d:	movl 0x4537a8, %eax
0x00414a92:	popl %ebp
0x00414a93:	ret

0x0040c2c1:	popl %ecx
0x0040c2c2:	movl %eax, $0x5a4d<UINT32>
0x0040c2c7:	cmpw 0x400000, %ax
0x0040c2ce:	je 0x0040c2d4
0x0040c2d4:	movl %eax, 0x40003c
0x0040c2d9:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x0040c2e3:	jne -21
0x0040c2e5:	movl %ecx, $0x10b<UINT32>
0x0040c2ea:	cmpw 0x400018(%eax), %cx
0x0040c2f1:	jne -35
0x0040c2f3:	xorl %ebx, %ebx
0x0040c2f5:	cmpl 0x400074(%eax), $0xe<UINT8>
0x0040c2fc:	jbe 9
0x0040c2fe:	cmpl 0x4000e8(%eax), %ebx
0x0040c304:	setne %bl
0x0040c307:	movl -28(%ebp), %ebx
0x0040c30a:	call 0x0040e49b
0x0040e49b:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x0040e4a1:	xorl %ecx, %ecx
0x0040e4a3:	movl 0x453e08, %eax
0x0040e4a8:	testl %eax, %eax
0x0040e4aa:	setne %cl
0x0040e4ad:	movl %eax, %ecx
0x0040e4af:	ret

0x0040c30f:	testl %eax, %eax
0x0040c311:	jne 0x0040c31b
0x0040c31b:	call 0x0040d335
0x0040d335:	call 0x00409e0c
0x00409e0c:	pushl %esi
0x00409e0d:	pushl $0x0<UINT8>
0x00409e0f:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00409e15:	movl %esi, %eax
0x00409e17:	pushl %esi
0x00409e18:	call 0x0040df7d
0x0040df7d:	pushl %ebp
0x0040df7e:	movl %ebp, %esp
0x0040df80:	movl %eax, 0x8(%ebp)
0x0040df83:	movl 0x453de0, %eax
0x0040df88:	popl %ebp
0x0040df89:	ret

0x00409e1d:	pushl %esi
0x00409e1e:	call 0x0040c558
0x0040c558:	pushl %ebp
0x0040c559:	movl %ebp, %esp
0x0040c55b:	movl %eax, 0x8(%ebp)
0x0040c55e:	movl 0x453634, %eax
0x0040c563:	popl %ebp
0x0040c564:	ret

0x00409e23:	pushl %esi
0x00409e24:	call 0x0040df8a
0x0040df8a:	pushl %ebp
0x0040df8b:	movl %ebp, %esp
0x0040df8d:	movl %eax, 0x8(%ebp)
0x0040df90:	movl 0x453de4, %eax
0x0040df95:	popl %ebp
0x0040df96:	ret

0x00409e29:	pushl %esi
0x00409e2a:	call 0x0040dfa4
0x0040dfa4:	pushl %ebp
0x0040dfa5:	movl %ebp, %esp
0x0040dfa7:	movl %eax, 0x8(%ebp)
0x0040dfaa:	movl 0x453de8, %eax
0x0040dfaf:	movl 0x453dec, %eax
0x0040dfb4:	movl 0x453df0, %eax
0x0040dfb9:	movl 0x453df4, %eax
0x0040dfbe:	popl %ebp
0x0040dfbf:	ret

0x00409e2f:	pushl %esi
0x00409e30:	call 0x0040df46
0x0040df46:	pushl $0x40deff<UINT32>
0x0040df4b:	call EncodePointer@KERNEL32.DLL
0x0040df51:	movl 0x453ddc, %eax
0x0040df56:	ret

0x00409e35:	pushl %esi
0x00409e36:	call 0x0040e1b5
0x0040e1b5:	pushl %ebp
0x0040e1b6:	movl %ebp, %esp
0x0040e1b8:	movl %eax, 0x8(%ebp)
0x0040e1bb:	movl 0x453dfc, %eax
0x0040e1c0:	popl %ebp
0x0040e1c1:	ret

0x00409e3b:	addl %esp, $0x18<UINT8>
0x00409e3e:	popl %esi
0x00409e3f:	jmp 0x0040d74d
0x0040d74d:	pushl %esi
0x0040d74e:	pushl %edi
0x0040d74f:	pushl $0x428f70<UINT32>
0x0040d754:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0040d75a:	movl %esi, 0x41e19c
0x0040d760:	movl %edi, %eax
0x0040d762:	pushl $0x428f8c<UINT32>
0x0040d767:	pushl %edi
0x0040d768:	call GetProcAddress@KERNEL32.DLL
0x0040d76a:	xorl %eax, 0x451d80
0x0040d770:	pushl $0x428f98<UINT32>
0x0040d775:	pushl %edi
0x0040d776:	movl 0x4541c0, %eax
0x0040d77b:	call GetProcAddress@KERNEL32.DLL
0x0040d77d:	xorl %eax, 0x451d80
0x0040d783:	pushl $0x428fa0<UINT32>
0x0040d788:	pushl %edi
0x0040d789:	movl 0x4541c4, %eax
0x0040d78e:	call GetProcAddress@KERNEL32.DLL
0x0040d790:	xorl %eax, 0x451d80
0x0040d796:	pushl $0x428fac<UINT32>
0x0040d79b:	pushl %edi
0x0040d79c:	movl 0x4541c8, %eax
0x0040d7a1:	call GetProcAddress@KERNEL32.DLL
0x0040d7a3:	xorl %eax, 0x451d80
0x0040d7a9:	pushl $0x428fb8<UINT32>
0x0040d7ae:	pushl %edi
0x0040d7af:	movl 0x4541cc, %eax
0x0040d7b4:	call GetProcAddress@KERNEL32.DLL
0x0040d7b6:	xorl %eax, 0x451d80
0x0040d7bc:	pushl $0x428fd4<UINT32>
0x0040d7c1:	pushl %edi
0x0040d7c2:	movl 0x4541d0, %eax
0x0040d7c7:	call GetProcAddress@KERNEL32.DLL
0x0040d7c9:	xorl %eax, 0x451d80
0x0040d7cf:	pushl $0x428fe4<UINT32>
0x0040d7d4:	pushl %edi
0x0040d7d5:	movl 0x4541d4, %eax
0x0040d7da:	call GetProcAddress@KERNEL32.DLL
0x0040d7dc:	xorl %eax, 0x451d80
0x0040d7e2:	pushl $0x428ff8<UINT32>
0x0040d7e7:	pushl %edi
0x0040d7e8:	movl 0x4541d8, %eax
0x0040d7ed:	call GetProcAddress@KERNEL32.DLL
0x0040d7ef:	xorl %eax, 0x451d80
0x0040d7f5:	pushl $0x429010<UINT32>
0x0040d7fa:	pushl %edi
0x0040d7fb:	movl 0x4541dc, %eax
0x0040d800:	call GetProcAddress@KERNEL32.DLL
0x0040d802:	xorl %eax, 0x451d80
0x0040d808:	pushl $0x429028<UINT32>
0x0040d80d:	pushl %edi
0x0040d80e:	movl 0x4541e0, %eax
0x0040d813:	call GetProcAddress@KERNEL32.DLL
0x0040d815:	xorl %eax, 0x451d80
0x0040d81b:	pushl $0x42903c<UINT32>
0x0040d820:	pushl %edi
0x0040d821:	movl 0x4541e4, %eax
0x0040d826:	call GetProcAddress@KERNEL32.DLL
0x0040d828:	xorl %eax, 0x451d80
0x0040d82e:	pushl $0x42905c<UINT32>
0x0040d833:	pushl %edi
0x0040d834:	movl 0x4541e8, %eax
0x0040d839:	call GetProcAddress@KERNEL32.DLL
0x0040d83b:	xorl %eax, 0x451d80
0x0040d841:	pushl $0x429074<UINT32>
0x0040d846:	pushl %edi
0x0040d847:	movl 0x4541ec, %eax
0x0040d84c:	call GetProcAddress@KERNEL32.DLL
0x0040d84e:	xorl %eax, 0x451d80
0x0040d854:	pushl $0x42908c<UINT32>
0x0040d859:	pushl %edi
0x0040d85a:	movl 0x4541f0, %eax
0x0040d85f:	call GetProcAddress@KERNEL32.DLL
0x0040d861:	xorl %eax, 0x451d80
0x0040d867:	pushl $0x4290a0<UINT32>
0x0040d86c:	pushl %edi
0x0040d86d:	movl 0x4541f4, %eax
0x0040d872:	call GetProcAddress@KERNEL32.DLL
0x0040d874:	xorl %eax, 0x451d80
0x0040d87a:	movl 0x4541f8, %eax
0x0040d87f:	pushl $0x4290b4<UINT32>
0x0040d884:	pushl %edi
0x0040d885:	call GetProcAddress@KERNEL32.DLL
0x0040d887:	xorl %eax, 0x451d80
0x0040d88d:	pushl $0x4290d0<UINT32>
0x0040d892:	pushl %edi
0x0040d893:	movl 0x4541fc, %eax
0x0040d898:	call GetProcAddress@KERNEL32.DLL
0x0040d89a:	xorl %eax, 0x451d80
0x0040d8a0:	pushl $0x4290f0<UINT32>
0x0040d8a5:	pushl %edi
0x0040d8a6:	movl 0x454200, %eax
0x0040d8ab:	call GetProcAddress@KERNEL32.DLL
0x0040d8ad:	xorl %eax, 0x451d80
0x0040d8b3:	pushl $0x42910c<UINT32>
0x0040d8b8:	pushl %edi
0x0040d8b9:	movl 0x454204, %eax
0x0040d8be:	call GetProcAddress@KERNEL32.DLL
0x0040d8c0:	xorl %eax, 0x451d80
0x0040d8c6:	pushl $0x42912c<UINT32>
0x0040d8cb:	pushl %edi
0x0040d8cc:	movl 0x454208, %eax
0x0040d8d1:	call GetProcAddress@KERNEL32.DLL
0x0040d8d3:	xorl %eax, 0x451d80
0x0040d8d9:	pushl $0x429140<UINT32>
0x0040d8de:	pushl %edi
0x0040d8df:	movl 0x45420c, %eax
0x0040d8e4:	call GetProcAddress@KERNEL32.DLL
0x0040d8e6:	xorl %eax, 0x451d80
0x0040d8ec:	pushl $0x42915c<UINT32>
0x0040d8f1:	pushl %edi
0x0040d8f2:	movl 0x454210, %eax
0x0040d8f7:	call GetProcAddress@KERNEL32.DLL
0x0040d8f9:	xorl %eax, 0x451d80
0x0040d8ff:	pushl $0x429170<UINT32>
0x0040d904:	pushl %edi
0x0040d905:	movl 0x454218, %eax
0x0040d90a:	call GetProcAddress@KERNEL32.DLL
0x0040d90c:	xorl %eax, 0x451d80
0x0040d912:	pushl $0x429180<UINT32>
0x0040d917:	pushl %edi
0x0040d918:	movl 0x454214, %eax
0x0040d91d:	call GetProcAddress@KERNEL32.DLL
0x0040d91f:	xorl %eax, 0x451d80
0x0040d925:	pushl $0x429190<UINT32>
0x0040d92a:	pushl %edi
0x0040d92b:	movl 0x45421c, %eax
0x0040d930:	call GetProcAddress@KERNEL32.DLL
0x0040d932:	xorl %eax, 0x451d80
0x0040d938:	pushl $0x4291a0<UINT32>
0x0040d93d:	pushl %edi
0x0040d93e:	movl 0x454220, %eax
0x0040d943:	call GetProcAddress@KERNEL32.DLL
0x0040d945:	xorl %eax, 0x451d80
0x0040d94b:	pushl $0x4291b0<UINT32>
0x0040d950:	pushl %edi
0x0040d951:	movl 0x454224, %eax
0x0040d956:	call GetProcAddress@KERNEL32.DLL
0x0040d958:	xorl %eax, 0x451d80
0x0040d95e:	pushl $0x4291cc<UINT32>
0x0040d963:	pushl %edi
0x0040d964:	movl 0x454228, %eax
0x0040d969:	call GetProcAddress@KERNEL32.DLL
0x0040d96b:	xorl %eax, 0x451d80
0x0040d971:	pushl $0x4291e0<UINT32>
0x0040d976:	pushl %edi
0x0040d977:	movl 0x45422c, %eax
0x0040d97c:	call GetProcAddress@KERNEL32.DLL
0x0040d97e:	xorl %eax, 0x451d80
0x0040d984:	pushl $0x4291f0<UINT32>
0x0040d989:	pushl %edi
0x0040d98a:	movl 0x454230, %eax
0x0040d98f:	call GetProcAddress@KERNEL32.DLL
0x0040d991:	xorl %eax, 0x451d80
0x0040d997:	pushl $0x429204<UINT32>
0x0040d99c:	pushl %edi
0x0040d99d:	movl 0x454234, %eax
0x0040d9a2:	call GetProcAddress@KERNEL32.DLL
0x0040d9a4:	xorl %eax, 0x451d80
0x0040d9aa:	movl 0x454238, %eax
0x0040d9af:	pushl $0x429214<UINT32>
0x0040d9b4:	pushl %edi
0x0040d9b5:	call GetProcAddress@KERNEL32.DLL
0x0040d9b7:	xorl %eax, 0x451d80
0x0040d9bd:	pushl $0x429234<UINT32>
0x0040d9c2:	pushl %edi
0x0040d9c3:	movl 0x45423c, %eax
0x0040d9c8:	call GetProcAddress@KERNEL32.DLL
0x0040d9ca:	xorl %eax, 0x451d80
0x0040d9d0:	popl %edi
0x0040d9d1:	movl 0x454240, %eax
0x0040d9d6:	popl %esi
0x0040d9d7:	ret

0x0040d33a:	call 0x0040d613
0x0040d613:	pushl %esi
0x0040d614:	pushl %edi
0x0040d615:	movl %esi, $0x4528d8<UINT32>
0x0040d61a:	movl %edi, $0x453658<UINT32>
0x0040d61f:	cmpl 0x4(%esi), $0x1<UINT8>
0x0040d623:	jne 22
0x0040d625:	pushl $0x0<UINT8>
0x0040d627:	movl (%esi), %edi
0x0040d629:	addl %edi, $0x18<UINT8>
0x0040d62c:	pushl $0xfa0<UINT32>
0x0040d631:	pushl (%esi)
0x0040d633:	call 0x0040d6df
0x0040d6df:	pushl %ebp
0x0040d6e0:	movl %ebp, %esp
0x0040d6e2:	movl %eax, 0x4541d0
0x0040d6e7:	xorl %eax, 0x451d80
0x0040d6ed:	je 13
0x0040d6ef:	pushl 0x10(%ebp)
0x0040d6f2:	pushl 0xc(%ebp)
0x0040d6f5:	pushl 0x8(%ebp)
0x0040d6f8:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x0040d6fa:	popl %ebp
0x0040d6fb:	ret

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
