0x0044c7f0:	pusha
0x0044c7f1:	movl %esi, $0x435000<UINT32>
0x0044c7f6:	leal %edi, -212992(%esi)
0x0044c7fc:	pushl %edi
0x0044c7fd:	jmp 0x0044c80a
0x0044c80a:	movl %ebx, (%esi)
0x0044c80c:	subl %esi, $0xfffffffc<UINT8>
0x0044c80f:	adcl %ebx, %ebx
0x0044c811:	jb 0x0044c800
0x0044c800:	movb %al, (%esi)
0x0044c802:	incl %esi
0x0044c803:	movb (%edi), %al
0x0044c805:	incl %edi
0x0044c806:	addl %ebx, %ebx
0x0044c808:	jne 0x0044c811
0x0044c813:	movl %eax, $0x1<UINT32>
0x0044c818:	addl %ebx, %ebx
0x0044c81a:	jne 0x0044c823
0x0044c823:	adcl %eax, %eax
0x0044c825:	addl %ebx, %ebx
0x0044c827:	jae 0x0044c834
0x0044c829:	jne 0x0044c853
0x0044c853:	xorl %ecx, %ecx
0x0044c855:	subl %eax, $0x3<UINT8>
0x0044c858:	jb 0x0044c86b
0x0044c85a:	shll %eax, $0x8<UINT8>
0x0044c85d:	movb %al, (%esi)
0x0044c85f:	incl %esi
0x0044c860:	xorl %eax, $0xffffffff<UINT8>
0x0044c863:	je 0x0044c8da
0x0044c865:	sarl %eax
0x0044c867:	movl %ebp, %eax
0x0044c869:	jmp 0x0044c876
0x0044c876:	jb 0x0044c844
0x0044c844:	addl %ebx, %ebx
0x0044c846:	jne 0x0044c84f
0x0044c84f:	adcl %ecx, %ecx
0x0044c851:	jmp 0x0044c8a5
0x0044c8a5:	cmpl %ebp, $0xfffffb00<UINT32>
0x0044c8ab:	adcl %ecx, $0x2<UINT8>
0x0044c8ae:	leal %edx, (%edi,%ebp)
0x0044c8b1:	cmpl %ebp, $0xfffffffc<UINT8>
0x0044c8b4:	jbe 0x0044c8c4
0x0044c8c4:	movl %eax, (%edx)
0x0044c8c6:	addl %edx, $0x4<UINT8>
0x0044c8c9:	movl (%edi), %eax
0x0044c8cb:	addl %edi, $0x4<UINT8>
0x0044c8ce:	subl %ecx, $0x4<UINT8>
0x0044c8d1:	ja 0x0044c8c4
0x0044c8d3:	addl %edi, %ecx
0x0044c8d5:	jmp 0x0044c806
0x0044c8b6:	movb %al, (%edx)
0x0044c8b8:	incl %edx
0x0044c8b9:	movb (%edi), %al
0x0044c8bb:	incl %edi
0x0044c8bc:	decl %ecx
0x0044c8bd:	jne 0x0044c8b6
0x0044c8bf:	jmp 0x0044c806
0x0044c878:	incl %ecx
0x0044c879:	addl %ebx, %ebx
0x0044c87b:	jne 0x0044c884
0x0044c884:	jb 0x0044c844
0x0044c886:	addl %ebx, %ebx
0x0044c888:	jne 0x0044c891
0x0044c891:	adcl %ecx, %ecx
0x0044c893:	addl %ebx, %ebx
0x0044c895:	jae 0x0044c886
0x0044c897:	jne 0x0044c8a2
0x0044c8a2:	addl %ecx, $0x2<UINT8>
0x0044c848:	movl %ebx, (%esi)
0x0044c84a:	subl %esi, $0xfffffffc<UINT8>
0x0044c84d:	adcl %ebx, %ebx
0x0044c81c:	movl %ebx, (%esi)
0x0044c81e:	subl %esi, $0xfffffffc<UINT8>
0x0044c821:	adcl %ebx, %ebx
0x0044c834:	decl %eax
0x0044c835:	addl %ebx, %ebx
0x0044c837:	jne 0x0044c840
0x0044c840:	adcl %eax, %eax
0x0044c842:	jmp 0x0044c818
0x0044c86b:	addl %ebx, %ebx
0x0044c86d:	jne 0x0044c876
0x0044c899:	movl %ebx, (%esi)
0x0044c89b:	subl %esi, $0xfffffffc<UINT8>
0x0044c89e:	adcl %ebx, %ebx
0x0044c8a0:	jae 0x0044c886
0x0044c839:	movl %ebx, (%esi)
0x0044c83b:	subl %esi, $0xfffffffc<UINT8>
0x0044c83e:	adcl %ebx, %ebx
0x0044c86f:	movl %ebx, (%esi)
0x0044c871:	subl %esi, $0xfffffffc<UINT8>
0x0044c874:	adcl %ebx, %ebx
0x0044c82b:	movl %ebx, (%esi)
0x0044c82d:	subl %esi, $0xfffffffc<UINT8>
0x0044c830:	adcl %ebx, %ebx
0x0044c832:	jb 0x0044c853
0x0044c88a:	movl %ebx, (%esi)
0x0044c88c:	subl %esi, $0xfffffffc<UINT8>
0x0044c88f:	adcl %ebx, %ebx
0x0044c87d:	movl %ebx, (%esi)
0x0044c87f:	subl %esi, $0xfffffffc<UINT8>
0x0044c882:	adcl %ebx, %ebx
0x0044c8da:	popl %esi
0x0044c8db:	movl %edi, %esi
0x0044c8dd:	movl %ecx, $0x888<UINT32>
0x0044c8e2:	movb %al, (%edi)
0x0044c8e4:	incl %edi
0x0044c8e5:	subb %al, $0xffffffe8<UINT8>
0x0044c8e7:	cmpb %al, $0x1<UINT8>
0x0044c8e9:	ja 0x0044c8e2
0x0044c8eb:	cmpb (%edi), $0x5<UINT8>
0x0044c8ee:	jne 0x0044c8e2
0x0044c8f0:	movl %eax, (%edi)
0x0044c8f2:	movb %bl, 0x4(%edi)
0x0044c8f5:	shrw %ax, $0x8<UINT8>
0x0044c8f9:	roll %eax, $0x10<UINT8>
0x0044c8fc:	xchgb %ah, %al
0x0044c8fe:	subl %eax, %edi
0x0044c900:	subb %bl, $0xffffffe8<UINT8>
0x0044c903:	addl %eax, %esi
0x0044c905:	movl (%edi), %eax
0x0044c907:	addl %edi, $0x5<UINT8>
0x0044c90a:	movb %al, %bl
0x0044c90c:	loop 0x0044c8e7
0x0044c90e:	leal %edi, 0x49000(%esi)
0x0044c914:	movl %eax, (%edi)
0x0044c916:	orl %eax, %eax
0x0044c918:	je 0x0044c95f
0x0044c91a:	movl %ebx, 0x4(%edi)
0x0044c91d:	leal %eax, 0x4c5e8(%eax,%esi)
0x0044c924:	addl %ebx, %esi
0x0044c926:	pushl %eax
0x0044c927:	addl %edi, $0x8<UINT8>
0x0044c92a:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x0044c930:	xchgl %ebp, %eax
0x0044c931:	movb %al, (%edi)
0x0044c933:	incl %edi
0x0044c934:	orb %al, %al
0x0044c936:	je 0x0044c914
0x0044c938:	movl %ecx, %edi
0x0044c93a:	jns 0x0044c943
0x0044c943:	pushl %edi
0x0044c944:	decl %eax
0x0044c945:	repn scasb %al, %es:(%edi)
0x0044c947:	pushl %ebp
0x0044c948:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0044c94e:	orl %eax, %eax
0x0044c950:	je 7
0x0044c952:	movl (%ebx), %eax
0x0044c954:	addl %ebx, $0x4<UINT8>
0x0044c957:	jmp 0x0044c931
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x0044c93c:	movzwl %eax, (%edi)
0x0044c93f:	incl %edi
0x0044c940:	pushl %eax
0x0044c941:	incl %edi
0x0044c942:	movl %ecx, $0xaef24857<UINT32>
0x0044c95f:	addl %edi, $0x4<UINT8>
0x0044c962:	leal %ebx, -4(%esi)
0x0044c965:	xorl %eax, %eax
0x0044c967:	movb %al, (%edi)
0x0044c969:	incl %edi
0x0044c96a:	orl %eax, %eax
0x0044c96c:	je 0x0044c990
0x0044c96e:	cmpb %al, $0xffffffef<UINT8>
0x0044c970:	ja 0x0044c983
0x0044c972:	addl %ebx, %eax
0x0044c974:	movl %eax, (%ebx)
0x0044c976:	xchgb %ah, %al
0x0044c978:	roll %eax, $0x10<UINT8>
0x0044c97b:	xchgb %ah, %al
0x0044c97d:	addl %eax, %esi
0x0044c97f:	movl (%ebx), %eax
0x0044c981:	jmp 0x0044c965
0x0044c983:	andb %al, $0xf<UINT8>
0x0044c985:	shll %eax, $0x10<UINT8>
0x0044c988:	movw %ax, (%edi)
0x0044c98b:	addl %edi, $0x2<UINT8>
0x0044c98e:	jmp 0x0044c972
0x0044c990:	movl %ebp, 0x4c6a4(%esi)
0x0044c996:	leal %edi, -4096(%esi)
0x0044c99c:	movl %ebx, $0x1000<UINT32>
0x0044c9a1:	pushl %eax
0x0044c9a2:	pushl %esp
0x0044c9a3:	pushl $0x4<UINT8>
0x0044c9a5:	pushl %ebx
0x0044c9a6:	pushl %edi
0x0044c9a7:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0044c9a9:	leal %eax, 0x217(%edi)
0x0044c9af:	andb (%eax), $0x7f<UINT8>
0x0044c9b2:	andb 0x28(%eax), $0x7f<UINT8>
0x0044c9b6:	popl %eax
0x0044c9b7:	pushl %eax
0x0044c9b8:	pushl %esp
0x0044c9b9:	pushl %eax
0x0044c9ba:	pushl %ebx
0x0044c9bb:	pushl %edi
0x0044c9bc:	call VirtualProtect@kernel32.dll
0x0044c9be:	popl %eax
0x0044c9bf:	popa
0x0044c9c0:	leal %eax, -128(%esp)
0x0044c9c4:	pushl $0x0<UINT8>
0x0044c9c6:	cmpl %esp, %eax
0x0044c9c8:	jne 0x0044c9c4
0x0044c9ca:	subl %esp, $0xffffff80<UINT8>
0x0044c9cd:	jmp 0x00407ecb
0x00407ecb:	call 0x00410f29
0x00410f29:	pushl %ebp
0x00410f2a:	movl %ebp, %esp
0x00410f2c:	subl %esp, $0x14<UINT8>
0x00410f2f:	andl -12(%ebp), $0x0<UINT8>
0x00410f33:	andl -8(%ebp), $0x0<UINT8>
0x00410f37:	movl %eax, 0x4250d0
0x00410f3c:	pushl %esi
0x00410f3d:	pushl %edi
0x00410f3e:	movl %edi, $0xbb40e64e<UINT32>
0x00410f43:	movl %esi, $0xffff0000<UINT32>
0x00410f48:	cmpl %eax, %edi
0x00410f4a:	je 0x00410f59
0x00410f59:	leal %eax, -12(%ebp)
0x00410f5c:	pushl %eax
0x00410f5d:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x00410f63:	movl %eax, -8(%ebp)
0x00410f66:	xorl %eax, -12(%ebp)
0x00410f69:	movl -4(%ebp), %eax
0x00410f6c:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x00410f72:	xorl -4(%ebp), %eax
0x00410f75:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x00410f7b:	xorl -4(%ebp), %eax
0x00410f7e:	leal %eax, -20(%ebp)
0x00410f81:	pushl %eax
0x00410f82:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x00410f88:	movl %ecx, -16(%ebp)
0x00410f8b:	leal %eax, -4(%ebp)
0x00410f8e:	xorl %ecx, -20(%ebp)
0x00410f91:	xorl %ecx, -4(%ebp)
0x00410f94:	xorl %ecx, %eax
0x00410f96:	cmpl %ecx, %edi
0x00410f98:	jne 0x00410fa1
0x00410fa1:	testl %esi, %ecx
0x00410fa3:	jne 0x00410fb1
0x00410fb1:	movl 0x4250d0, %ecx
0x00410fb7:	notl %ecx
0x00410fb9:	movl 0x4250d4, %ecx
0x00410fbf:	popl %edi
0x00410fc0:	popl %esi
0x00410fc1:	movl %esp, %ebp
0x00410fc3:	popl %ebp
0x00410fc4:	ret

0x00407ed0:	jmp 0x00407d50
0x00407d50:	pushl $0x14<UINT8>
0x00407d52:	pushl $0x423460<UINT32>
0x00407d57:	call 0x00409da0
0x00409da0:	pushl $0x407560<UINT32>
0x00409da5:	pushl %fs:0
0x00409dac:	movl %eax, 0x10(%esp)
0x00409db0:	movl 0x10(%esp), %ebp
0x00409db4:	leal %ebp, 0x10(%esp)
0x00409db8:	subl %esp, %eax
0x00409dba:	pushl %ebx
0x00409dbb:	pushl %esi
0x00409dbc:	pushl %edi
0x00409dbd:	movl %eax, 0x4250d0
0x00409dc2:	xorl -4(%ebp), %eax
0x00409dc5:	xorl %eax, %ebp
0x00409dc7:	pushl %eax
0x00409dc8:	movl -24(%ebp), %esp
0x00409dcb:	pushl -8(%ebp)
0x00409dce:	movl %eax, -4(%ebp)
0x00409dd1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00409dd8:	movl -8(%ebp), %eax
0x00409ddb:	leal %eax, -16(%ebp)
0x00409dde:	movl %fs:0, %eax
0x00409de4:	ret

0x00407d5c:	pushl $0x1<UINT8>
0x00407d5e:	call 0x00410edc
0x00410edc:	pushl %ebp
0x00410edd:	movl %ebp, %esp
0x00410edf:	movl %eax, 0x8(%ebp)
0x00410ee2:	movl 0x426b18, %eax
0x00410ee7:	popl %ebp
0x00410ee8:	ret

0x00407d63:	popl %ecx
0x00407d64:	movl %eax, $0x5a4d<UINT32>
0x00407d69:	cmpw 0x400000, %ax
0x00407d70:	je 0x00407d76
0x00407d76:	movl %eax, 0x40003c
0x00407d7b:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00407d85:	jne -21
0x00407d87:	movl %ecx, $0x10b<UINT32>
0x00407d8c:	cmpw 0x400018(%eax), %cx
0x00407d93:	jne -35
0x00407d95:	xorl %ebx, %ebx
0x00407d97:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00407d9e:	jbe 9
0x00407da0:	cmpl 0x4000e8(%eax), %ebx
0x00407da6:	setne %bl
0x00407da9:	movl -28(%ebp), %ebx
0x00407dac:	call 0x00409ed0
0x00409ed0:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x00409ed6:	xorl %ecx, %ecx
0x00409ed8:	movl 0x427178, %eax
0x00409edd:	testl %eax, %eax
0x00409edf:	setne %cl
0x00409ee2:	movl %eax, %ecx
0x00409ee4:	ret

0x00407db1:	testl %eax, %eax
0x00407db3:	jne 0x00407dbd
0x00407dbd:	call 0x00408e13
0x00408e13:	call 0x00404ece
0x00404ece:	pushl %esi
0x00404ecf:	pushl $0x0<UINT8>
0x00404ed1:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00404ed7:	movl %esi, %eax
0x00404ed9:	pushl %esi
0x00404eda:	call 0x00409b52
0x00409b52:	pushl %ebp
0x00409b53:	movl %ebp, %esp
0x00409b55:	movl %eax, 0x8(%ebp)
0x00409b58:	movl 0x427150, %eax
0x00409b5d:	popl %ebp
0x00409b5e:	ret

0x00404edf:	pushl %esi
0x00404ee0:	call 0x00407ffa
0x00407ffa:	pushl %ebp
0x00407ffb:	movl %ebp, %esp
0x00407ffd:	movl %eax, 0x8(%ebp)
0x00408000:	movl 0x4269a0, %eax
0x00408005:	popl %ebp
0x00408006:	ret

0x00404ee5:	pushl %esi
0x00404ee6:	call 0x00409b5f
0x00409b5f:	pushl %ebp
0x00409b60:	movl %ebp, %esp
0x00409b62:	movl %eax, 0x8(%ebp)
0x00409b65:	movl 0x427154, %eax
0x00409b6a:	popl %ebp
0x00409b6b:	ret

0x00404eeb:	pushl %esi
0x00404eec:	call 0x00409b79
0x00409b79:	pushl %ebp
0x00409b7a:	movl %ebp, %esp
0x00409b7c:	movl %eax, 0x8(%ebp)
0x00409b7f:	movl 0x427158, %eax
0x00409b84:	movl 0x42715c, %eax
0x00409b89:	movl 0x427160, %eax
0x00409b8e:	movl 0x427164, %eax
0x00409b93:	popl %ebp
0x00409b94:	ret

0x00404ef1:	pushl %esi
0x00404ef2:	call 0x00409b1b
0x00409b1b:	pushl $0x409ae7<UINT32>
0x00409b20:	call EncodePointer@KERNEL32.DLL
0x00409b26:	movl 0x42714c, %eax
0x00409b2b:	ret

0x00404ef7:	pushl %esi
0x00404ef8:	call 0x00409d8a
0x00409d8a:	pushl %ebp
0x00409d8b:	movl %ebp, %esp
0x00409d8d:	movl %eax, 0x8(%ebp)
0x00409d90:	movl 0x42716c, %eax
0x00409d95:	popl %ebp
0x00409d96:	ret

0x00404efd:	addl %esp, $0x18<UINT8>
0x00404f00:	popl %esi
0x00404f01:	jmp 0x0040922b
0x0040922b:	pushl %esi
0x0040922c:	pushl %edi
0x0040922d:	pushl $0x41f948<UINT32>
0x00409232:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00409238:	movl %esi, 0x418104
0x0040923e:	movl %edi, %eax
0x00409240:	pushl $0x41f964<UINT32>
0x00409245:	pushl %edi
0x00409246:	call GetProcAddress@KERNEL32.DLL
0x00409248:	xorl %eax, 0x4250d0
0x0040924e:	pushl $0x41f970<UINT32>
0x00409253:	pushl %edi
0x00409254:	movl 0x427740, %eax
0x00409259:	call GetProcAddress@KERNEL32.DLL
0x0040925b:	xorl %eax, 0x4250d0
0x00409261:	pushl $0x41f978<UINT32>
0x00409266:	pushl %edi
0x00409267:	movl 0x427744, %eax
0x0040926c:	call GetProcAddress@KERNEL32.DLL
0x0040926e:	xorl %eax, 0x4250d0
0x00409274:	pushl $0x41f984<UINT32>
0x00409279:	pushl %edi
0x0040927a:	movl 0x427748, %eax
0x0040927f:	call GetProcAddress@KERNEL32.DLL
0x00409281:	xorl %eax, 0x4250d0
0x00409287:	pushl $0x41f990<UINT32>
0x0040928c:	pushl %edi
0x0040928d:	movl 0x42774c, %eax
0x00409292:	call GetProcAddress@KERNEL32.DLL
0x00409294:	xorl %eax, 0x4250d0
0x0040929a:	pushl $0x41f9ac<UINT32>
0x0040929f:	pushl %edi
0x004092a0:	movl 0x427750, %eax
0x004092a5:	call GetProcAddress@KERNEL32.DLL
0x004092a7:	xorl %eax, 0x4250d0
0x004092ad:	pushl $0x41f9bc<UINT32>
0x004092b2:	pushl %edi
0x004092b3:	movl 0x427754, %eax
0x004092b8:	call GetProcAddress@KERNEL32.DLL
0x004092ba:	xorl %eax, 0x4250d0
0x004092c0:	pushl $0x41f9d0<UINT32>
0x004092c5:	pushl %edi
0x004092c6:	movl 0x427758, %eax
0x004092cb:	call GetProcAddress@KERNEL32.DLL
0x004092cd:	xorl %eax, 0x4250d0
0x004092d3:	pushl $0x41f9e8<UINT32>
0x004092d8:	pushl %edi
0x004092d9:	movl 0x42775c, %eax
0x004092de:	call GetProcAddress@KERNEL32.DLL
0x004092e0:	xorl %eax, 0x4250d0
0x004092e6:	pushl $0x41fa00<UINT32>
0x004092eb:	pushl %edi
0x004092ec:	movl 0x427760, %eax
0x004092f1:	call GetProcAddress@KERNEL32.DLL
0x004092f3:	xorl %eax, 0x4250d0
0x004092f9:	pushl $0x41fa14<UINT32>
0x004092fe:	pushl %edi
0x004092ff:	movl 0x427764, %eax
0x00409304:	call GetProcAddress@KERNEL32.DLL
0x00409306:	xorl %eax, 0x4250d0
0x0040930c:	pushl $0x41fa34<UINT32>
0x00409311:	pushl %edi
0x00409312:	movl 0x427768, %eax
0x00409317:	call GetProcAddress@KERNEL32.DLL
0x00409319:	xorl %eax, 0x4250d0
0x0040931f:	pushl $0x41fa4c<UINT32>
0x00409324:	pushl %edi
0x00409325:	movl 0x42776c, %eax
0x0040932a:	call GetProcAddress@KERNEL32.DLL
0x0040932c:	xorl %eax, 0x4250d0
0x00409332:	pushl $0x41fa64<UINT32>
0x00409337:	pushl %edi
0x00409338:	movl 0x427770, %eax
0x0040933d:	call GetProcAddress@KERNEL32.DLL
0x0040933f:	xorl %eax, 0x4250d0
0x00409345:	pushl $0x41fa78<UINT32>
0x0040934a:	pushl %edi
0x0040934b:	movl 0x427774, %eax
0x00409350:	call GetProcAddress@KERNEL32.DLL
0x00409352:	xorl %eax, 0x4250d0
0x00409358:	movl 0x427778, %eax
0x0040935d:	pushl $0x41fa8c<UINT32>
0x00409362:	pushl %edi
0x00409363:	call GetProcAddress@KERNEL32.DLL
0x00409365:	xorl %eax, 0x4250d0
0x0040936b:	pushl $0x41faa8<UINT32>
0x00409370:	pushl %edi
0x00409371:	movl 0x42777c, %eax
0x00409376:	call GetProcAddress@KERNEL32.DLL
0x00409378:	xorl %eax, 0x4250d0
0x0040937e:	pushl $0x41fac8<UINT32>
0x00409383:	pushl %edi
0x00409384:	movl 0x427780, %eax
0x00409389:	call GetProcAddress@KERNEL32.DLL
0x0040938b:	xorl %eax, 0x4250d0
0x00409391:	pushl $0x41fae4<UINT32>
0x00409396:	pushl %edi
0x00409397:	movl 0x427784, %eax
0x0040939c:	call GetProcAddress@KERNEL32.DLL
0x0040939e:	xorl %eax, 0x4250d0
0x004093a4:	pushl $0x41fb04<UINT32>
0x004093a9:	pushl %edi
0x004093aa:	movl 0x427788, %eax
0x004093af:	call GetProcAddress@KERNEL32.DLL
0x004093b1:	xorl %eax, 0x4250d0
0x004093b7:	pushl $0x41fb18<UINT32>
0x004093bc:	pushl %edi
0x004093bd:	movl 0x42778c, %eax
0x004093c2:	call GetProcAddress@KERNEL32.DLL
0x004093c4:	xorl %eax, 0x4250d0
0x004093ca:	pushl $0x41fb34<UINT32>
0x004093cf:	pushl %edi
0x004093d0:	movl 0x427790, %eax
0x004093d5:	call GetProcAddress@KERNEL32.DLL
0x004093d7:	xorl %eax, 0x4250d0
0x004093dd:	pushl $0x41fb48<UINT32>
0x004093e2:	pushl %edi
0x004093e3:	movl 0x427798, %eax
0x004093e8:	call GetProcAddress@KERNEL32.DLL
0x004093ea:	xorl %eax, 0x4250d0
0x004093f0:	pushl $0x41fb58<UINT32>
0x004093f5:	pushl %edi
0x004093f6:	movl 0x427794, %eax
0x004093fb:	call GetProcAddress@KERNEL32.DLL
0x004093fd:	xorl %eax, 0x4250d0
0x00409403:	pushl $0x41fb68<UINT32>
0x00409408:	pushl %edi
0x00409409:	movl 0x42779c, %eax
0x0040940e:	call GetProcAddress@KERNEL32.DLL
0x00409410:	xorl %eax, 0x4250d0
0x00409416:	pushl $0x41fb78<UINT32>
0x0040941b:	pushl %edi
0x0040941c:	movl 0x4277a0, %eax
0x00409421:	call GetProcAddress@KERNEL32.DLL
0x00409423:	xorl %eax, 0x4250d0
0x00409429:	pushl $0x41fb88<UINT32>
0x0040942e:	pushl %edi
0x0040942f:	movl 0x4277a4, %eax
0x00409434:	call GetProcAddress@KERNEL32.DLL
0x00409436:	xorl %eax, 0x4250d0
0x0040943c:	pushl $0x41fba4<UINT32>
0x00409441:	pushl %edi
0x00409442:	movl 0x4277a8, %eax
0x00409447:	call GetProcAddress@KERNEL32.DLL
0x00409449:	xorl %eax, 0x4250d0
0x0040944f:	pushl $0x41fbb8<UINT32>
0x00409454:	pushl %edi
0x00409455:	movl 0x4277ac, %eax
0x0040945a:	call GetProcAddress@KERNEL32.DLL
0x0040945c:	xorl %eax, 0x4250d0
0x00409462:	pushl $0x41fbc8<UINT32>
0x00409467:	pushl %edi
0x00409468:	movl 0x4277b0, %eax
0x0040946d:	call GetProcAddress@KERNEL32.DLL
0x0040946f:	xorl %eax, 0x4250d0
0x00409475:	pushl $0x41fbdc<UINT32>
0x0040947a:	pushl %edi
0x0040947b:	movl 0x4277b4, %eax
0x00409480:	call GetProcAddress@KERNEL32.DLL
0x00409482:	xorl %eax, 0x4250d0
0x00409488:	movl 0x4277b8, %eax
0x0040948d:	pushl $0x41fbec<UINT32>
0x00409492:	pushl %edi
0x00409493:	call GetProcAddress@KERNEL32.DLL
0x00409495:	xorl %eax, 0x4250d0
0x0040949b:	pushl $0x41fc0c<UINT32>
0x004094a0:	pushl %edi
0x004094a1:	movl 0x4277bc, %eax
0x004094a6:	call GetProcAddress@KERNEL32.DLL
0x004094a8:	xorl %eax, 0x4250d0
0x004094ae:	popl %edi
0x004094af:	movl 0x4277c0, %eax
0x004094b4:	popl %esi
0x004094b5:	ret

0x00408e18:	call 0x004090f1
0x004090f1:	pushl %esi
0x004090f2:	pushl %edi
0x004090f3:	movl %esi, $0x425c28<UINT32>
0x004090f8:	movl %edi, $0x4269c8<UINT32>
0x004090fd:	cmpl 0x4(%esi), $0x1<UINT8>
0x00409101:	jne 22
0x00409103:	pushl $0x0<UINT8>
0x00409105:	movl (%esi), %edi
0x00409107:	addl %edi, $0x18<UINT8>
0x0040910a:	pushl $0xfa0<UINT32>
0x0040910f:	pushl (%esi)
0x00409111:	call 0x004091bd
0x004091bd:	pushl %ebp
0x004091be:	movl %ebp, %esp
0x004091c0:	movl %eax, 0x427750
0x004091c5:	xorl %eax, 0x4250d0
0x004091cb:	je 13
0x004091cd:	pushl 0x10(%ebp)
0x004091d0:	pushl 0xc(%ebp)
0x004091d3:	pushl 0x8(%ebp)
0x004091d6:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x004091d8:	popl %ebp
0x004091d9:	ret

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
