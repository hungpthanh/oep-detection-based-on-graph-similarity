0x00434910:	pusha
0x00434911:	movl %esi, $0x425000<UINT32>
0x00434916:	leal %edi, -147456(%esi)
0x0043491c:	pushl %edi
0x0043491d:	jmp 0x0043492a
0x0043492a:	movl %ebx, (%esi)
0x0043492c:	subl %esi, $0xfffffffc<UINT8>
0x0043492f:	adcl %ebx, %ebx
0x00434931:	jb 0x00434920
0x00434920:	movb %al, (%esi)
0x00434922:	incl %esi
0x00434923:	movb (%edi), %al
0x00434925:	incl %edi
0x00434926:	addl %ebx, %ebx
0x00434928:	jne 0x00434931
0x00434933:	movl %eax, $0x1<UINT32>
0x00434938:	addl %ebx, %ebx
0x0043493a:	jne 0x00434943
0x00434943:	adcl %eax, %eax
0x00434945:	addl %ebx, %ebx
0x00434947:	jae 0x00434938
0x00434949:	jne 0x00434954
0x00434954:	xorl %ecx, %ecx
0x00434956:	subl %eax, $0x3<UINT8>
0x00434959:	jb 0x00434968
0x0043495b:	shll %eax, $0x8<UINT8>
0x0043495e:	movb %al, (%esi)
0x00434960:	incl %esi
0x00434961:	xorl %eax, $0xffffffff<UINT8>
0x00434964:	je 0x004349da
0x00434966:	movl %ebp, %eax
0x00434968:	addl %ebx, %ebx
0x0043496a:	jne 0x00434973
0x00434973:	adcl %ecx, %ecx
0x00434975:	addl %ebx, %ebx
0x00434977:	jne 0x00434980
0x00434980:	adcl %ecx, %ecx
0x00434982:	jne 0x004349a4
0x004349a4:	cmpl %ebp, $0xfffff300<UINT32>
0x004349aa:	adcl %ecx, $0x1<UINT8>
0x004349ad:	leal %edx, (%edi,%ebp)
0x004349b0:	cmpl %ebp, $0xfffffffc<UINT8>
0x004349b3:	jbe 0x004349c4
0x004349c4:	movl %eax, (%edx)
0x004349c6:	addl %edx, $0x4<UINT8>
0x004349c9:	movl (%edi), %eax
0x004349cb:	addl %edi, $0x4<UINT8>
0x004349ce:	subl %ecx, $0x4<UINT8>
0x004349d1:	ja 0x004349c4
0x004349d3:	addl %edi, %ecx
0x004349d5:	jmp 0x00434926
0x0043496c:	movl %ebx, (%esi)
0x0043496e:	subl %esi, $0xfffffffc<UINT8>
0x00434971:	adcl %ebx, %ebx
0x00434979:	movl %ebx, (%esi)
0x0043497b:	subl %esi, $0xfffffffc<UINT8>
0x0043497e:	adcl %ebx, %ebx
0x00434984:	incl %ecx
0x00434985:	addl %ebx, %ebx
0x00434987:	jne 0x00434990
0x00434990:	adcl %ecx, %ecx
0x00434992:	addl %ebx, %ebx
0x00434994:	jae 0x00434985
0x00434996:	jne 0x004349a1
0x004349a1:	addl %ecx, $0x2<UINT8>
0x0043493c:	movl %ebx, (%esi)
0x0043493e:	subl %esi, $0xfffffffc<UINT8>
0x00434941:	adcl %ebx, %ebx
0x0043494b:	movl %ebx, (%esi)
0x0043494d:	subl %esi, $0xfffffffc<UINT8>
0x00434950:	adcl %ebx, %ebx
0x00434952:	jae 0x00434938
0x004349b5:	movb %al, (%edx)
0x004349b7:	incl %edx
0x004349b8:	movb (%edi), %al
0x004349ba:	incl %edi
0x004349bb:	decl %ecx
0x004349bc:	jne 0x004349b5
0x004349be:	jmp 0x00434926
0x00434998:	movl %ebx, (%esi)
0x0043499a:	subl %esi, $0xfffffffc<UINT8>
0x0043499d:	adcl %ebx, %ebx
0x0043499f:	jae 0x00434985
0x00434989:	movl %ebx, (%esi)
0x0043498b:	subl %esi, $0xfffffffc<UINT8>
0x0043498e:	adcl %ebx, %ebx
0x004349da:	popl %esi
0x004349db:	movl %edi, %esi
0x004349dd:	movl %ecx, $0x7ec<UINT32>
0x004349e2:	movb %al, (%edi)
0x004349e4:	incl %edi
0x004349e5:	subb %al, $0xffffffe8<UINT8>
0x004349e7:	cmpb %al, $0x1<UINT8>
0x004349e9:	ja 0x004349e2
0x004349eb:	cmpb (%edi), $0x9<UINT8>
0x004349ee:	jne 0x004349e2
0x004349f0:	movl %eax, (%edi)
0x004349f2:	movb %bl, 0x4(%edi)
0x004349f5:	shrw %ax, $0x8<UINT8>
0x004349f9:	roll %eax, $0x10<UINT8>
0x004349fc:	xchgb %ah, %al
0x004349fe:	subl %eax, %edi
0x00434a00:	subb %bl, $0xffffffe8<UINT8>
0x00434a03:	addl %eax, %esi
0x00434a05:	movl (%edi), %eax
0x00434a07:	addl %edi, $0x5<UINT8>
0x00434a0a:	movb %al, %bl
0x00434a0c:	loop 0x004349e7
0x00434a0e:	leal %edi, 0x31000(%esi)
0x00434a14:	movl %eax, (%edi)
0x00434a16:	orl %eax, %eax
0x00434a18:	je 0x00434a56
0x00434a1a:	movl %ebx, 0x4(%edi)
0x00434a1d:	leal %eax, 0x34a58(%eax,%esi)
0x00434a24:	addl %ebx, %esi
0x00434a26:	pushl %eax
0x00434a27:	addl %edi, $0x8<UINT8>
0x00434a2a:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00434a30:	xchgl %ebp, %eax
0x00434a31:	movb %al, (%edi)
0x00434a33:	incl %edi
0x00434a34:	orb %al, %al
0x00434a36:	je 0x00434a14
0x00434a38:	movl %ecx, %edi
0x00434a3a:	pushl %edi
0x00434a3b:	decl %eax
0x00434a3c:	repn scasb %al, %es:(%edi)
0x00434a3e:	pushl %ebp
0x00434a3f:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00434a45:	orl %eax, %eax
0x00434a47:	je 7
0x00434a49:	movl (%ebx), %eax
0x00434a4b:	addl %ebx, $0x4<UINT8>
0x00434a4e:	jmp 0x00434a31
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x00434a56:	addl %edi, $0x4<UINT8>
0x00434a59:	leal %ebx, -4(%esi)
0x00434a5c:	xorl %eax, %eax
0x00434a5e:	movb %al, (%edi)
0x00434a60:	incl %edi
0x00434a61:	orl %eax, %eax
0x00434a63:	je 0x00434a87
0x00434a65:	cmpb %al, $0xffffffef<UINT8>
0x00434a67:	ja 0x00434a7a
0x00434a69:	addl %ebx, %eax
0x00434a6b:	movl %eax, (%ebx)
0x00434a6d:	xchgb %ah, %al
0x00434a6f:	roll %eax, $0x10<UINT8>
0x00434a72:	xchgb %ah, %al
0x00434a74:	addl %eax, %esi
0x00434a76:	movl (%ebx), %eax
0x00434a78:	jmp 0x00434a5c
0x00434a7a:	andb %al, $0xf<UINT8>
0x00434a7c:	shll %eax, $0x10<UINT8>
0x00434a7f:	movw %ax, (%edi)
0x00434a82:	addl %edi, $0x2<UINT8>
0x00434a85:	jmp 0x00434a69
0x00434a87:	movl %ebp, 0x34b08(%esi)
0x00434a8d:	leal %edi, -4096(%esi)
0x00434a93:	movl %ebx, $0x1000<UINT32>
0x00434a98:	pushl %eax
0x00434a99:	pushl %esp
0x00434a9a:	pushl $0x4<UINT8>
0x00434a9c:	pushl %ebx
0x00434a9d:	pushl %edi
0x00434a9e:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00434aa0:	leal %eax, 0x21f(%edi)
0x00434aa6:	andb (%eax), $0x7f<UINT8>
0x00434aa9:	andb 0x28(%eax), $0x7f<UINT8>
0x00434aad:	popl %eax
0x00434aae:	pushl %eax
0x00434aaf:	pushl %esp
0x00434ab0:	pushl %eax
0x00434ab1:	pushl %ebx
0x00434ab2:	pushl %edi
0x00434ab3:	call VirtualProtect@kernel32.dll
0x00434ab5:	popl %eax
0x00434ab6:	popa
0x00434ab7:	leal %eax, -128(%esp)
0x00434abb:	pushl $0x0<UINT8>
0x00434abd:	cmpl %esp, %eax
0x00434abf:	jne 0x00434abb
0x00434ac1:	subl %esp, $0xffffff80<UINT8>
0x00434ac4:	jmp 0x00404de2
0x00404de2:	call 0x0040c0a3
0x0040c0a3:	pushl %ebp
0x0040c0a4:	movl %ebp, %esp
0x0040c0a6:	subl %esp, $0x14<UINT8>
0x0040c0a9:	andl -12(%ebp), $0x0<UINT8>
0x0040c0ad:	andl -8(%ebp), $0x0<UINT8>
0x0040c0b1:	movl %eax, 0x4250d0
0x0040c0b6:	pushl %esi
0x0040c0b7:	pushl %edi
0x0040c0b8:	movl %edi, $0xbb40e64e<UINT32>
0x0040c0bd:	movl %esi, $0xffff0000<UINT32>
0x0040c0c2:	cmpl %eax, %edi
0x0040c0c4:	je 0x0040c0d3
0x0040c0d3:	leal %eax, -12(%ebp)
0x0040c0d6:	pushl %eax
0x0040c0d7:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040c0dd:	movl %eax, -8(%ebp)
0x0040c0e0:	xorl %eax, -12(%ebp)
0x0040c0e3:	movl -4(%ebp), %eax
0x0040c0e6:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040c0ec:	xorl -4(%ebp), %eax
0x0040c0ef:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040c0f5:	xorl -4(%ebp), %eax
0x0040c0f8:	leal %eax, -20(%ebp)
0x0040c0fb:	pushl %eax
0x0040c0fc:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040c102:	movl %ecx, -16(%ebp)
0x0040c105:	leal %eax, -4(%ebp)
0x0040c108:	xorl %ecx, -20(%ebp)
0x0040c10b:	xorl %ecx, -4(%ebp)
0x0040c10e:	xorl %ecx, %eax
0x0040c110:	cmpl %ecx, %edi
0x0040c112:	jne 0x0040c11b
0x0040c11b:	testl %esi, %ecx
0x0040c11d:	jne 0x0040c12b
0x0040c12b:	movl 0x4250d0, %ecx
0x0040c131:	notl %ecx
0x0040c133:	movl 0x4250d4, %ecx
0x0040c139:	popl %edi
0x0040c13a:	popl %esi
0x0040c13b:	movl %esp, %ebp
0x0040c13d:	popl %ebp
0x0040c13e:	ret

0x00404de7:	jmp 0x00404c67
0x00404c67:	pushl $0x14<UINT8>
0x00404c69:	pushl $0x423868<UINT32>
0x00404c6e:	call 0x00407d20
0x00407d20:	pushl $0x407d80<UINT32>
0x00407d25:	pushl %fs:0
0x00407d2c:	movl %eax, 0x10(%esp)
0x00407d30:	movl 0x10(%esp), %ebp
0x00407d34:	leal %ebp, 0x10(%esp)
0x00407d38:	subl %esp, %eax
0x00407d3a:	pushl %ebx
0x00407d3b:	pushl %esi
0x00407d3c:	pushl %edi
0x00407d3d:	movl %eax, 0x4250d0
0x00407d42:	xorl -4(%ebp), %eax
0x00407d45:	xorl %eax, %ebp
0x00407d47:	pushl %eax
0x00407d48:	movl -24(%ebp), %esp
0x00407d4b:	pushl -8(%ebp)
0x00407d4e:	movl %eax, -4(%ebp)
0x00407d51:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00407d58:	movl -8(%ebp), %eax
0x00407d5b:	leal %eax, -16(%ebp)
0x00407d5e:	movl %fs:0, %eax
0x00407d64:	ret

0x00404c73:	pushl $0x1<UINT8>
0x00404c75:	call 0x0040c056
0x0040c056:	pushl %ebp
0x0040c057:	movl %ebp, %esp
0x0040c059:	movl %eax, 0x8(%ebp)
0x0040c05c:	movl 0x426898, %eax
0x0040c061:	popl %ebp
0x0040c062:	ret

0x00404c7a:	popl %ecx
0x00404c7b:	movl %eax, $0x5a4d<UINT32>
0x00404c80:	cmpw 0x400000, %ax
0x00404c87:	je 0x00404c8d
0x00404c8d:	movl %eax, 0x40003c
0x00404c92:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00404c9c:	jne -21
0x00404c9e:	movl %ecx, $0x10b<UINT32>
0x00404ca3:	cmpw 0x400018(%eax), %cx
0x00404caa:	jne -35
0x00404cac:	xorl %ebx, %ebx
0x00404cae:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00404cb5:	jbe 9
0x00404cb7:	cmpl 0x4000e8(%eax), %ebx
0x00404cbd:	setne %bl
0x00404cc0:	movl -28(%ebp), %ebx
0x00404cc3:	call 0x0040b30d
0x0040b30d:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x0040b313:	xorl %ecx, %ecx
0x0040b315:	movl 0x426ed0, %eax
0x0040b31a:	testl %eax, %eax
0x0040b31c:	setne %cl
0x0040b31f:	movl %eax, %ecx
0x0040b321:	ret

0x00404cc8:	testl %eax, %eax
0x00404cca:	jne 0x00404cd4
0x00404cd4:	call 0x0040603c
0x0040603c:	call 0x004040a4
0x004040a4:	pushl %esi
0x004040a5:	pushl $0x0<UINT8>
0x004040a7:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x004040ad:	movl %esi, %eax
0x004040af:	pushl %esi
0x004040b0:	call 0x0040b300
0x0040b300:	pushl %ebp
0x0040b301:	movl %ebp, %esp
0x0040b303:	movl %eax, 0x8(%ebp)
0x0040b306:	movl 0x426ec8, %eax
0x0040b30b:	popl %ebp
0x0040b30c:	ret

0x004040b5:	pushl %esi
0x004040b6:	call 0x00404f11
0x00404f11:	pushl %ebp
0x00404f12:	movl %ebp, %esp
0x00404f14:	movl %eax, 0x8(%ebp)
0x00404f17:	movl 0x4262e8, %eax
0x00404f1c:	popl %ebp
0x00404f1d:	ret

0x004040bb:	pushl %esi
0x004040bc:	call 0x0040b8de
0x0040b8de:	pushl %ebp
0x0040b8df:	movl %ebp, %esp
0x0040b8e1:	movl %eax, 0x8(%ebp)
0x0040b8e4:	movl 0x426ed8, %eax
0x0040b8e9:	popl %ebp
0x0040b8ea:	ret

0x004040c1:	pushl %esi
0x004040c2:	call 0x0040b8f8
0x0040b8f8:	pushl %ebp
0x0040b8f9:	movl %ebp, %esp
0x0040b8fb:	movl %eax, 0x8(%ebp)
0x0040b8fe:	movl 0x426edc, %eax
0x0040b903:	movl 0x426ee0, %eax
0x0040b908:	movl 0x426ee4, %eax
0x0040b90d:	movl 0x426ee8, %eax
0x0040b912:	popl %ebp
0x0040b913:	ret

0x004040c7:	pushl %esi
0x004040c8:	call 0x0040b6f4
0x0040b6f4:	pushl $0x40b6c0<UINT32>
0x0040b6f9:	call EncodePointer@KERNEL32.DLL
0x0040b6ff:	movl 0x426ed4, %eax
0x0040b704:	ret

0x004040cd:	pushl %esi
0x004040ce:	call 0x0040bb09
0x0040bb09:	pushl %ebp
0x0040bb0a:	movl %ebp, %esp
0x0040bb0c:	movl %eax, 0x8(%ebp)
0x0040bb0f:	movl 0x426ef0, %eax
0x0040bb14:	popl %ebp
0x0040bb15:	ret

0x004040d3:	addl %esp, $0x18<UINT8>
0x004040d6:	popl %esi
0x004040d7:	jmp 0x0040adee
0x0040adee:	pushl %esi
0x0040adef:	pushl %edi
0x0040adf0:	pushl $0x41f16c<UINT32>
0x0040adf5:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0040adfb:	movl %esi, 0x418074
0x0040ae01:	movl %edi, %eax
0x0040ae03:	pushl $0x41f188<UINT32>
0x0040ae08:	pushl %edi
0x0040ae09:	call GetProcAddress@KERNEL32.DLL
0x0040ae0b:	xorl %eax, 0x4250d0
0x0040ae11:	pushl $0x41f194<UINT32>
0x0040ae16:	pushl %edi
0x0040ae17:	movl 0x42ddc0, %eax
0x0040ae1c:	call GetProcAddress@KERNEL32.DLL
0x0040ae1e:	xorl %eax, 0x4250d0
0x0040ae24:	pushl $0x41f19c<UINT32>
0x0040ae29:	pushl %edi
0x0040ae2a:	movl 0x42ddc4, %eax
0x0040ae2f:	call GetProcAddress@KERNEL32.DLL
0x0040ae31:	xorl %eax, 0x4250d0
0x0040ae37:	pushl $0x41f1a8<UINT32>
0x0040ae3c:	pushl %edi
0x0040ae3d:	movl 0x42ddc8, %eax
0x0040ae42:	call GetProcAddress@KERNEL32.DLL
0x0040ae44:	xorl %eax, 0x4250d0
0x0040ae4a:	pushl $0x41f1b4<UINT32>
0x0040ae4f:	pushl %edi
0x0040ae50:	movl 0x42ddcc, %eax
0x0040ae55:	call GetProcAddress@KERNEL32.DLL
0x0040ae57:	xorl %eax, 0x4250d0
0x0040ae5d:	pushl $0x41f1d0<UINT32>
0x0040ae62:	pushl %edi
0x0040ae63:	movl 0x42ddd0, %eax
0x0040ae68:	call GetProcAddress@KERNEL32.DLL
0x0040ae6a:	xorl %eax, 0x4250d0
0x0040ae70:	pushl $0x41f1e0<UINT32>
0x0040ae75:	pushl %edi
0x0040ae76:	movl 0x42ddd4, %eax
0x0040ae7b:	call GetProcAddress@KERNEL32.DLL
0x0040ae7d:	xorl %eax, 0x4250d0
0x0040ae83:	pushl $0x41f1f4<UINT32>
0x0040ae88:	pushl %edi
0x0040ae89:	movl 0x42ddd8, %eax
0x0040ae8e:	call GetProcAddress@KERNEL32.DLL
0x0040ae90:	xorl %eax, 0x4250d0
0x0040ae96:	pushl $0x41f20c<UINT32>
0x0040ae9b:	pushl %edi
0x0040ae9c:	movl 0x42dddc, %eax
0x0040aea1:	call GetProcAddress@KERNEL32.DLL
0x0040aea3:	xorl %eax, 0x4250d0
0x0040aea9:	pushl $0x41f224<UINT32>
0x0040aeae:	pushl %edi
0x0040aeaf:	movl 0x42dde0, %eax
0x0040aeb4:	call GetProcAddress@KERNEL32.DLL
0x0040aeb6:	xorl %eax, 0x4250d0
0x0040aebc:	pushl $0x41f238<UINT32>
0x0040aec1:	pushl %edi
0x0040aec2:	movl 0x42dde4, %eax
0x0040aec7:	call GetProcAddress@KERNEL32.DLL
0x0040aec9:	xorl %eax, 0x4250d0
0x0040aecf:	pushl $0x41f258<UINT32>
0x0040aed4:	pushl %edi
0x0040aed5:	movl 0x42dde8, %eax
0x0040aeda:	call GetProcAddress@KERNEL32.DLL
0x0040aedc:	xorl %eax, 0x4250d0
0x0040aee2:	pushl $0x41f270<UINT32>
0x0040aee7:	pushl %edi
0x0040aee8:	movl 0x42ddec, %eax
0x0040aeed:	call GetProcAddress@KERNEL32.DLL
0x0040aeef:	xorl %eax, 0x4250d0
0x0040aef5:	pushl $0x41f288<UINT32>
0x0040aefa:	pushl %edi
0x0040aefb:	movl 0x42ddf0, %eax
0x0040af00:	call GetProcAddress@KERNEL32.DLL
0x0040af02:	xorl %eax, 0x4250d0
0x0040af08:	pushl $0x41f29c<UINT32>
0x0040af0d:	pushl %edi
0x0040af0e:	movl 0x42ddf4, %eax
0x0040af13:	call GetProcAddress@KERNEL32.DLL
0x0040af15:	xorl %eax, 0x4250d0
0x0040af1b:	movl 0x42ddf8, %eax
0x0040af20:	pushl $0x41f2b0<UINT32>
0x0040af25:	pushl %edi
0x0040af26:	call GetProcAddress@KERNEL32.DLL
0x0040af28:	xorl %eax, 0x4250d0
0x0040af2e:	pushl $0x41f2cc<UINT32>
0x0040af33:	pushl %edi
0x0040af34:	movl 0x42ddfc, %eax
0x0040af39:	call GetProcAddress@KERNEL32.DLL
0x0040af3b:	xorl %eax, 0x4250d0
0x0040af41:	pushl $0x41f2ec<UINT32>
0x0040af46:	pushl %edi
0x0040af47:	movl 0x42de00, %eax
0x0040af4c:	call GetProcAddress@KERNEL32.DLL
0x0040af4e:	xorl %eax, 0x4250d0
0x0040af54:	pushl $0x41f308<UINT32>
0x0040af59:	pushl %edi
0x0040af5a:	movl 0x42de04, %eax
0x0040af5f:	call GetProcAddress@KERNEL32.DLL
0x0040af61:	xorl %eax, 0x4250d0
0x0040af67:	pushl $0x41f328<UINT32>
0x0040af6c:	pushl %edi
0x0040af6d:	movl 0x42de08, %eax
0x0040af72:	call GetProcAddress@KERNEL32.DLL
0x0040af74:	xorl %eax, 0x4250d0
0x0040af7a:	pushl $0x41f33c<UINT32>
0x0040af7f:	pushl %edi
0x0040af80:	movl 0x42de0c, %eax
0x0040af85:	call GetProcAddress@KERNEL32.DLL
0x0040af87:	xorl %eax, 0x4250d0
0x0040af8d:	pushl $0x41f358<UINT32>
0x0040af92:	pushl %edi
0x0040af93:	movl 0x42de10, %eax
0x0040af98:	call GetProcAddress@KERNEL32.DLL
0x0040af9a:	xorl %eax, 0x4250d0
0x0040afa0:	pushl $0x41f36c<UINT32>
0x0040afa5:	pushl %edi
0x0040afa6:	movl 0x42de18, %eax
0x0040afab:	call GetProcAddress@KERNEL32.DLL
0x0040afad:	xorl %eax, 0x4250d0
0x0040afb3:	pushl $0x41f37c<UINT32>
0x0040afb8:	pushl %edi
0x0040afb9:	movl 0x42de14, %eax
0x0040afbe:	call GetProcAddress@KERNEL32.DLL
0x0040afc0:	xorl %eax, 0x4250d0
0x0040afc6:	pushl $0x41f38c<UINT32>
0x0040afcb:	pushl %edi
0x0040afcc:	movl 0x42de1c, %eax
0x0040afd1:	call GetProcAddress@KERNEL32.DLL
0x0040afd3:	xorl %eax, 0x4250d0
0x0040afd9:	pushl $0x41f39c<UINT32>
0x0040afde:	pushl %edi
0x0040afdf:	movl 0x42de20, %eax
0x0040afe4:	call GetProcAddress@KERNEL32.DLL
0x0040afe6:	xorl %eax, 0x4250d0
0x0040afec:	pushl $0x41f3ac<UINT32>
0x0040aff1:	pushl %edi
0x0040aff2:	movl 0x42de24, %eax
0x0040aff7:	call GetProcAddress@KERNEL32.DLL
0x0040aff9:	xorl %eax, 0x4250d0
0x0040afff:	pushl $0x41f3c8<UINT32>
0x0040b004:	pushl %edi
0x0040b005:	movl 0x42de28, %eax
0x0040b00a:	call GetProcAddress@KERNEL32.DLL
0x0040b00c:	xorl %eax, 0x4250d0
0x0040b012:	pushl $0x41f3dc<UINT32>
0x0040b017:	pushl %edi
0x0040b018:	movl 0x42de2c, %eax
0x0040b01d:	call GetProcAddress@KERNEL32.DLL
0x0040b01f:	xorl %eax, 0x4250d0
0x0040b025:	pushl $0x41f3ec<UINT32>
0x0040b02a:	pushl %edi
0x0040b02b:	movl 0x42de30, %eax
0x0040b030:	call GetProcAddress@KERNEL32.DLL
0x0040b032:	xorl %eax, 0x4250d0
0x0040b038:	pushl $0x41f400<UINT32>
0x0040b03d:	pushl %edi
0x0040b03e:	movl 0x42de34, %eax
0x0040b043:	call GetProcAddress@KERNEL32.DLL
0x0040b045:	xorl %eax, 0x4250d0
0x0040b04b:	movl 0x42de38, %eax
0x0040b050:	pushl $0x41f410<UINT32>
0x0040b055:	pushl %edi
0x0040b056:	call GetProcAddress@KERNEL32.DLL
0x0040b058:	xorl %eax, 0x4250d0
0x0040b05e:	pushl $0x41f430<UINT32>
0x0040b063:	pushl %edi
0x0040b064:	movl 0x42de3c, %eax
0x0040b069:	call GetProcAddress@KERNEL32.DLL
0x0040b06b:	xorl %eax, 0x4250d0
0x0040b071:	popl %edi
0x0040b072:	movl 0x42de40, %eax
0x0040b077:	popl %esi
0x0040b078:	ret

0x00406041:	call 0x0040893b
0x0040893b:	pushl %esi
0x0040893c:	pushl %edi
0x0040893d:	movl %esi, $0x425c40<UINT32>
0x00408942:	movl %edi, $0x426320<UINT32>
0x00408947:	cmpl 0x4(%esi), $0x1<UINT8>
0x0040894b:	jne 22
0x0040894d:	pushl $0x0<UINT8>
0x0040894f:	movl (%esi), %edi
0x00408951:	addl %edi, $0x18<UINT8>
0x00408954:	pushl $0xfa0<UINT32>
0x00408959:	pushl (%esi)
0x0040895b:	call 0x0040ad80
0x0040ad80:	pushl %ebp
0x0040ad81:	movl %ebp, %esp
0x0040ad83:	movl %eax, 0x42ddd0
0x0040ad88:	xorl %eax, 0x4250d0
0x0040ad8e:	je 13
0x0040ad90:	pushl 0x10(%ebp)
0x0040ad93:	pushl 0xc(%ebp)
0x0040ad96:	pushl 0x8(%ebp)
0x0040ad99:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x0040ad9b:	popl %ebp
0x0040ad9c:	ret

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
