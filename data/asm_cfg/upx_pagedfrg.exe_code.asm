0x00458910:	pusha
0x00458911:	movl %esi, $0x44b000<UINT32>
0x00458916:	leal %edi, -303104(%esi)
0x0045891c:	pushl %edi
0x0045891d:	jmp 0x0045892a
0x0045892a:	movl %ebx, (%esi)
0x0045892c:	subl %esi, $0xfffffffc<UINT8>
0x0045892f:	adcl %ebx, %ebx
0x00458931:	jb 0x00458920
0x00458920:	movb %al, (%esi)
0x00458922:	incl %esi
0x00458923:	movb (%edi), %al
0x00458925:	incl %edi
0x00458926:	addl %ebx, %ebx
0x00458928:	jne 0x00458931
0x00458933:	movl %eax, $0x1<UINT32>
0x00458938:	addl %ebx, %ebx
0x0045893a:	jne 0x00458943
0x00458943:	adcl %eax, %eax
0x00458945:	addl %ebx, %ebx
0x00458947:	jae 0x00458954
0x00458949:	jne 0x00458973
0x00458973:	xorl %ecx, %ecx
0x00458975:	subl %eax, $0x3<UINT8>
0x00458978:	jb 0x0045898b
0x0045897a:	shll %eax, $0x8<UINT8>
0x0045897d:	movb %al, (%esi)
0x0045897f:	incl %esi
0x00458980:	xorl %eax, $0xffffffff<UINT8>
0x00458983:	je 0x004589fa
0x00458985:	sarl %eax
0x00458987:	movl %ebp, %eax
0x00458989:	jmp 0x00458996
0x00458996:	jb 0x00458964
0x00458964:	addl %ebx, %ebx
0x00458966:	jne 0x0045896f
0x0045896f:	adcl %ecx, %ecx
0x00458971:	jmp 0x004589c5
0x004589c5:	cmpl %ebp, $0xfffffb00<UINT32>
0x004589cb:	adcl %ecx, $0x2<UINT8>
0x004589ce:	leal %edx, (%edi,%ebp)
0x004589d1:	cmpl %ebp, $0xfffffffc<UINT8>
0x004589d4:	jbe 0x004589e4
0x004589e4:	movl %eax, (%edx)
0x004589e6:	addl %edx, $0x4<UINT8>
0x004589e9:	movl (%edi), %eax
0x004589eb:	addl %edi, $0x4<UINT8>
0x004589ee:	subl %ecx, $0x4<UINT8>
0x004589f1:	ja 0x004589e4
0x004589f3:	addl %edi, %ecx
0x004589f5:	jmp 0x00458926
0x0045898b:	addl %ebx, %ebx
0x0045898d:	jne 0x00458996
0x00458998:	incl %ecx
0x00458999:	addl %ebx, %ebx
0x0045899b:	jne 0x004589a4
0x004589a4:	jb 0x00458964
0x004589a6:	addl %ebx, %ebx
0x004589a8:	jne 0x004589b1
0x004589b1:	adcl %ecx, %ecx
0x004589b3:	addl %ebx, %ebx
0x004589b5:	jae 0x004589a6
0x004589aa:	movl %ebx, (%esi)
0x004589ac:	subl %esi, $0xfffffffc<UINT8>
0x004589af:	adcl %ebx, %ebx
0x004589b7:	jne 0x004589c2
0x004589c2:	addl %ecx, $0x2<UINT8>
0x004589d6:	movb %al, (%edx)
0x004589d8:	incl %edx
0x004589d9:	movb (%edi), %al
0x004589db:	incl %edi
0x004589dc:	decl %ecx
0x004589dd:	jne 0x004589d6
0x004589df:	jmp 0x00458926
0x00458968:	movl %ebx, (%esi)
0x0045896a:	subl %esi, $0xfffffffc<UINT8>
0x0045896d:	adcl %ebx, %ebx
0x0045894b:	movl %ebx, (%esi)
0x0045894d:	subl %esi, $0xfffffffc<UINT8>
0x00458950:	adcl %ebx, %ebx
0x00458952:	jb 0x00458973
0x00458954:	decl %eax
0x00458955:	addl %ebx, %ebx
0x00458957:	jne 0x00458960
0x00458960:	adcl %eax, %eax
0x00458962:	jmp 0x00458938
0x0045893c:	movl %ebx, (%esi)
0x0045893e:	subl %esi, $0xfffffffc<UINT8>
0x00458941:	adcl %ebx, %ebx
0x004589b9:	movl %ebx, (%esi)
0x004589bb:	subl %esi, $0xfffffffc<UINT8>
0x004589be:	adcl %ebx, %ebx
0x004589c0:	jae 0x004589a6
0x00458959:	movl %ebx, (%esi)
0x0045895b:	subl %esi, $0xfffffffc<UINT8>
0x0045895e:	adcl %ebx, %ebx
0x0045899d:	movl %ebx, (%esi)
0x0045899f:	subl %esi, $0xfffffffc<UINT8>
0x004589a2:	adcl %ebx, %ebx
0x0045898f:	movl %ebx, (%esi)
0x00458991:	subl %esi, $0xfffffffc<UINT8>
0x00458994:	adcl %ebx, %ebx
0x004589fa:	popl %esi
0x004589fb:	movl %edi, %esi
0x004589fd:	movl %ecx, $0x1e2<UINT32>
0x00458a02:	movb %al, (%edi)
0x00458a04:	incl %edi
0x00458a05:	subb %al, $0xffffffe8<UINT8>
0x00458a07:	cmpb %al, $0x1<UINT8>
0x00458a09:	ja 0x00458a02
0x00458a0b:	cmpb (%edi), $0x7<UINT8>
0x00458a0e:	jne 0x00458a02
0x00458a10:	movl %eax, (%edi)
0x00458a12:	movb %bl, 0x4(%edi)
0x00458a15:	shrw %ax, $0x8<UINT8>
0x00458a19:	roll %eax, $0x10<UINT8>
0x00458a1c:	xchgb %ah, %al
0x00458a1e:	subl %eax, %edi
0x00458a20:	subb %bl, $0xffffffe8<UINT8>
0x00458a23:	addl %eax, %esi
0x00458a25:	movl (%edi), %eax
0x00458a27:	addl %edi, $0x5<UINT8>
0x00458a2a:	movb %al, %bl
0x00458a2c:	loop 0x00458a07
0x00458a2e:	leal %edi, 0x56000(%esi)
0x00458a34:	movl %eax, (%edi)
0x00458a36:	orl %eax, %eax
0x00458a38:	je 0x00458a7f
0x00458a3a:	movl %ebx, 0x4(%edi)
0x00458a3d:	leal %eax, 0x58c4c(%eax,%esi)
0x00458a44:	addl %ebx, %esi
0x00458a46:	pushl %eax
0x00458a47:	addl %edi, $0x8<UINT8>
0x00458a4a:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00458a50:	xchgl %ebp, %eax
0x00458a51:	movb %al, (%edi)
0x00458a53:	incl %edi
0x00458a54:	orb %al, %al
0x00458a56:	je 0x00458a34
0x00458a58:	movl %ecx, %edi
0x00458a5a:	jns 0x00458a63
0x00458a63:	pushl %edi
0x00458a64:	decl %eax
0x00458a65:	repn scasb %al, %es:(%edi)
0x00458a67:	pushl %ebp
0x00458a68:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00458a6e:	orl %eax, %eax
0x00458a70:	je 7
0x00458a72:	movl (%ebx), %eax
0x00458a74:	addl %ebx, $0x4<UINT8>
0x00458a77:	jmp 0x00458a51
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x00458a5c:	movzwl %eax, (%edi)
0x00458a5f:	incl %edi
0x00458a60:	pushl %eax
0x00458a61:	incl %edi
0x00458a62:	movl %ecx, $0xaef24857<UINT32>
0x00458a7f:	movl %ebp, 0x58d18(%esi)
0x00458a85:	leal %edi, -4096(%esi)
0x00458a8b:	movl %ebx, $0x1000<UINT32>
0x00458a90:	pushl %eax
0x00458a91:	pushl %esp
0x00458a92:	pushl $0x4<UINT8>
0x00458a94:	pushl %ebx
0x00458a95:	pushl %edi
0x00458a96:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00458a98:	leal %eax, 0x217(%edi)
0x00458a9e:	andb (%eax), $0x7f<UINT8>
0x00458aa1:	andb 0x28(%eax), $0x7f<UINT8>
0x00458aa5:	popl %eax
0x00458aa6:	pushl %eax
0x00458aa7:	pushl %esp
0x00458aa8:	pushl %eax
0x00458aa9:	pushl %ebx
0x00458aaa:	pushl %edi
0x00458aab:	call VirtualProtect@kernel32.dll
0x00458aad:	popl %eax
0x00458aae:	popa
0x00458aaf:	leal %eax, -128(%esp)
0x00458ab3:	pushl $0x0<UINT8>
0x00458ab5:	cmpl %esp, %eax
0x00458ab7:	jne 0x00458ab3
0x00458ab9:	subl %esp, $0xffffff80<UINT8>
0x00458abc:	jmp 0x00403d50
0x00403d50:	pushl %ebp
0x00403d51:	movl %ebp, %esp
0x00403d53:	pushl $0xffffffff<UINT8>
0x00403d55:	pushl $0x40a240<UINT32>
0x00403d5a:	pushl $0x407828<UINT32>
0x00403d5f:	movl %eax, %fs:0
0x00403d65:	pushl %eax
0x00403d66:	movl %fs:0, %esp
0x00403d6d:	subl %esp, $0x58<UINT8>
0x00403d70:	pushl %ebx
0x00403d71:	pushl %esi
0x00403d72:	pushl %edi
0x00403d73:	movl -24(%ebp), %esp
0x00403d76:	call GetVersion@KERNEL32.DLL
GetVersion@KERNEL32.DLL: API Node	
0x00403d7c:	xorl %edx, %edx
0x00403d7e:	movb %dl, %ah
0x00403d80:	movl 0x427538, %edx
0x00403d86:	movl %ecx, %eax
0x00403d88:	andl %ecx, $0xff<UINT32>
0x00403d8e:	movl 0x427534, %ecx
0x00403d94:	shll %ecx, $0x8<UINT8>
0x00403d97:	addl %ecx, %edx
0x00403d99:	movl 0x427530, %ecx
0x00403d9f:	shrl %eax, $0x10<UINT8>
0x00403da2:	movl 0x42752c, %eax
0x00403da7:	xorl %esi, %esi
0x00403da9:	pushl %esi
0x00403daa:	call 0x004051ea
0x004051ea:	xorl %eax, %eax
0x004051ec:	pushl $0x0<UINT8>
0x004051ee:	cmpl 0x8(%esp), %eax
0x004051f2:	pushl $0x1000<UINT32>
0x004051f7:	sete %al
0x004051fa:	pushl %eax
0x004051fb:	call HeapCreate@KERNEL32.DLL
HeapCreate@KERNEL32.DLL: API Node	
0x00405201:	testl %eax, %eax
0x00405203:	movl 0x44a4d0, %eax
0x00405208:	je 21
0x0040520a:	call 0x004052b8
0x004052b8:	pushl $0x140<UINT32>
0x004052bd:	pushl $0x0<UINT8>
0x004052bf:	pushl 0x44a4d0
0x004052c5:	call HeapAlloc@KERNEL32.DLL
HeapAlloc@KERNEL32.DLL: API Node	
0x004052cb:	testl %eax, %eax
0x004052cd:	movl 0x44a4cc, %eax
0x004052d2:	jne 0x004052d5
0x004052d5:	andl 0x44a4c4, $0x0<UINT8>
0x004052dc:	andl 0x44a4c8, $0x0<UINT8>
0x004052e3:	pushl $0x1<UINT8>
0x004052e5:	movl 0x44a4c0, %eax
0x004052ea:	movl 0x44a4b8, $0x10<UINT32>
0x004052f4:	popl %eax
0x004052f5:	ret

0x0040520f:	testl %eax, %eax
0x00405211:	jne 0x00405222
0x00405222:	pushl $0x1<UINT8>
0x00405224:	popl %eax
0x00405225:	ret

0x00403daf:	popl %ecx
0x00403db0:	testl %eax, %eax
0x00403db2:	jne 0x00403dbc
0x00403dbc:	movl -4(%ebp), %esi
0x00403dbf:	call 0x0040755f
0x0040755f:	subl %esp, $0x44<UINT8>
0x00407562:	pushl %ebx
0x00407563:	pushl %ebp
0x00407564:	pushl %esi
0x00407565:	pushl %edi
0x00407566:	pushl $0x100<UINT32>
0x0040756b:	call 0x00403bae
0x00403bae:	pushl 0x427518
0x00403bb4:	pushl 0x8(%esp)
0x00403bb8:	call 0x00403bc0
0x00403bc0:	cmpl 0x4(%esp), $0xffffffe0<UINT8>
0x00403bc5:	ja 34
0x00403bc7:	pushl 0x4(%esp)
0x00403bcb:	call 0x00403bec
0x00403bec:	pushl %esi
0x00403bed:	movl %esi, 0x8(%esp)
0x00403bf1:	cmpl %esi, 0x426cdc
0x00403bf7:	ja 0x00403c04
0x00403bf9:	pushl %esi
0x00403bfa:	call 0x0040564c
0x0040564c:	pushl %ebp
0x0040564d:	movl %ebp, %esp
0x0040564f:	subl %esp, $0x14<UINT8>
0x00405652:	movl %eax, 0x44a4c8
0x00405657:	movl %edx, 0x44a4cc
0x0040565d:	pushl %ebx
0x0040565e:	pushl %esi
0x0040565f:	leal %eax, (%eax,%eax,4)
0x00405662:	pushl %edi
0x00405663:	leal %edi, (%edx,%eax,4)
0x00405666:	movl %eax, 0x8(%ebp)
0x00405669:	movl -4(%ebp), %edi
0x0040566c:	leal %ecx, 0x17(%eax)
0x0040566f:	andl %ecx, $0xfffffff0<UINT8>
0x00405672:	movl -16(%ebp), %ecx
0x00405675:	sarl %ecx, $0x4<UINT8>
0x00405678:	decl %ecx
0x00405679:	cmpl %ecx, $0x20<UINT8>
0x0040567c:	jnl 14
0x0040567e:	orl %esi, $0xffffffff<UINT8>
0x00405681:	shrl %esi, %cl
0x00405683:	orl -8(%ebp), $0xffffffff<UINT8>
0x00405687:	movl -12(%ebp), %esi
0x0040568a:	jmp 0x0040569c
0x0040569c:	movl %eax, 0x44a4c0
0x004056a1:	movl %ebx, %eax
0x004056a3:	cmpl %ebx, %edi
0x004056a5:	movl 0x8(%ebp), %ebx
0x004056a8:	jae 0x004056c3
0x004056c3:	cmpl %ebx, -4(%ebp)
0x004056c6:	jne 0x00405741
0x004056c8:	movl %ebx, %edx
0x004056ca:	cmpl %ebx, %eax
0x004056cc:	movl 0x8(%ebp), %ebx
0x004056cf:	jae 0x004056e6
0x004056e6:	jne 89
0x004056e8:	cmpl %ebx, -4(%ebp)
0x004056eb:	jae 0x004056fe
0x004056fe:	jne 38
0x00405700:	movl %ebx, %edx
0x00405702:	cmpl %ebx, %eax
0x00405704:	movl 0x8(%ebp), %ebx
0x00405707:	jae 0x00405716
0x00405716:	jne 14
0x00405718:	call 0x00405955
0x00405955:	movl %eax, 0x44a4c8
0x0040595a:	movl %ecx, 0x44a4b8
0x00405960:	pushl %esi
0x00405961:	pushl %edi
0x00405962:	xorl %edi, %edi
0x00405964:	cmpl %eax, %ecx
0x00405966:	jne 0x00405998
0x00405998:	movl %ecx, 0x44a4cc
0x0040599e:	pushl $0x41c4<UINT32>
0x004059a3:	pushl $0x8<UINT8>
0x004059a5:	leal %eax, (%eax,%eax,4)
0x004059a8:	pushl 0x44a4d0
0x004059ae:	leal %esi, (%ecx,%eax,4)
0x004059b1:	call HeapAlloc@KERNEL32.DLL
0x004059b7:	cmpl %eax, %edi
0x004059b9:	movl 0x10(%esi), %eax
0x004059bc:	je 42
0x004059be:	pushl $0x4<UINT8>
0x004059c0:	pushl $0x2000<UINT32>
0x004059c5:	pushl $0x100000<UINT32>
0x004059ca:	pushl %edi
0x004059cb:	call VirtualAlloc@KERNEL32.DLL
VirtualAlloc@KERNEL32.DLL: API Node	
0x004059d1:	cmpl %eax, %edi
0x004059d3:	movl 0xc(%esi), %eax
0x004059d6:	jne 0x004059ec
0x004059ec:	orl 0x8(%esi), $0xffffffff<UINT8>
0x004059f0:	movl (%esi), %edi
0x004059f2:	movl 0x4(%esi), %edi
0x004059f5:	incl 0x44a4c8
0x004059fb:	movl %eax, 0x10(%esi)
0x004059fe:	orl (%eax), $0xffffffff<UINT8>
0x00405a01:	movl %eax, %esi
0x00405a03:	popl %edi
0x00405a04:	popl %esi
0x00405a05:	ret

0x0040571d:	movl %ebx, %eax
0x0040571f:	testl %ebx, %ebx
0x00405721:	movl 0x8(%ebp), %ebx
0x00405724:	je 20
0x00405726:	pushl %ebx
0x00405727:	call 0x00405a06
0x00405a06:	pushl %ebp
0x00405a07:	movl %ebp, %esp
0x00405a09:	pushl %ecx
0x00405a0a:	movl %ecx, 0x8(%ebp)
0x00405a0d:	pushl %ebx
0x00405a0e:	pushl %esi
0x00405a0f:	pushl %edi
0x00405a10:	movl %esi, 0x10(%ecx)
0x00405a13:	movl %eax, 0x8(%ecx)
0x00405a16:	xorl %ebx, %ebx
0x00405a18:	testl %eax, %eax
0x00405a1a:	jl 0x00405a21
0x00405a21:	movl %eax, %ebx
0x00405a23:	pushl $0x3f<UINT8>
0x00405a25:	imull %eax, %eax, $0x204<UINT32>
0x00405a2b:	popl %edx
0x00405a2c:	leal %eax, 0x144(%eax,%esi)
0x00405a33:	movl -4(%ebp), %eax
0x00405a36:	movl 0x8(%eax), %eax
0x00405a39:	movl 0x4(%eax), %eax
0x00405a3c:	addl %eax, $0x8<UINT8>
0x00405a3f:	decl %edx
0x00405a40:	jne 0x00405a36
0x00405a42:	movl %edi, %ebx
0x00405a44:	pushl $0x4<UINT8>
0x00405a46:	shll %edi, $0xf<UINT8>
0x00405a49:	addl %edi, 0xc(%ecx)
0x00405a4c:	pushl $0x1000<UINT32>
0x00405a51:	pushl $0x8000<UINT32>
0x00405a56:	pushl %edi
0x00405a57:	call VirtualAlloc@KERNEL32.DLL
0x00405a5d:	testl %eax, %eax
0x00405a5f:	jne 0x00405a69
0x00405a69:	leal %edx, 0x7000(%edi)
0x00405a6f:	cmpl %edi, %edx
0x00405a71:	ja 60
0x00405a73:	leal %eax, 0x10(%edi)
0x00405a76:	orl -8(%eax), $0xffffffff<UINT8>
0x00405a7a:	orl 0xfec(%eax), $0xffffffff<UINT8>
0x00405a81:	leal %ecx, 0xffc(%eax)
0x00405a87:	movl -4(%eax), $0xff0<UINT32>
0x00405a8e:	movl (%eax), %ecx
0x00405a90:	leal %ecx, -4100(%eax)
0x00405a96:	movl 0x4(%eax), %ecx
0x00405a99:	movl 0xfe8(%eax), $0xff0<UINT32>
0x00405aa3:	addl %eax, $0x1000<UINT32>
0x00405aa8:	leal %ecx, -16(%eax)
0x00405aab:	cmpl %ecx, %edx
0x00405aad:	jbe 0x00405a76
0x00405aaf:	movl %eax, -4(%ebp)
0x00405ab2:	leal %ecx, 0xc(%edi)
0x00405ab5:	addl %eax, $0x1f8<UINT32>
0x00405aba:	pushl $0x1<UINT8>
0x00405abc:	popl %edi
0x00405abd:	movl 0x4(%eax), %ecx
0x00405ac0:	movl 0x8(%ecx), %eax
0x00405ac3:	leal %ecx, 0xc(%edx)
0x00405ac6:	movl 0x8(%eax), %ecx
0x00405ac9:	movl 0x4(%ecx), %eax
0x00405acc:	andl 0x44(%esi,%ebx,4), $0x0<UINT8>
0x00405ad1:	movl 0xc4(%esi,%ebx,4), %edi
0x00405ad8:	movb %al, 0x43(%esi)
0x00405adb:	movb %cl, %al
0x00405add:	incb %cl
0x00405adf:	testb %al, %al
0x00405ae1:	movl %eax, 0x8(%ebp)
0x00405ae4:	movb 0x43(%esi), %cl
0x00405ae7:	jne 3
0x00405ae9:	orl 0x4(%eax), %edi
0x00405aec:	movl %edx, $0x80000000<UINT32>
0x00405af1:	movl %ecx, %ebx
0x00405af3:	shrl %edx, %cl
0x00405af5:	notl %edx
0x00405af7:	andl 0x8(%eax), %edx
0x00405afa:	movl %eax, %ebx
0x00405afc:	popl %edi
0x00405afd:	popl %esi
0x00405afe:	popl %ebx
0x00405aff:	leave
0x00405b00:	ret

0x0040572c:	popl %ecx
0x0040572d:	movl %ecx, 0x10(%ebx)
0x00405730:	movl (%ecx), %eax
0x00405732:	movl %eax, 0x10(%ebx)
0x00405735:	cmpl (%eax), $0xffffffff<UINT8>
0x00405738:	jne 0x00405741
0x00405741:	movl 0x44a4c0, %ebx
0x00405747:	movl %eax, 0x10(%ebx)
0x0040574a:	movl %edx, (%eax)
0x0040574c:	cmpl %edx, $0xffffffff<UINT8>
0x0040574f:	movl -4(%ebp), %edx
0x00405752:	je 20
0x00405754:	movl %ecx, 0xc4(%eax,%edx,4)
0x0040575b:	movl %edi, 0x44(%eax,%edx,4)
0x0040575f:	andl %ecx, -8(%ebp)
0x00405762:	andl %edi, %esi
0x00405764:	orl %ecx, %edi
0x00405766:	jne 0x0040579f
0x0040579f:	movl %ecx, %edx
0x004057a1:	xorl %edi, %edi
0x004057a3:	imull %ecx, %ecx, $0x204<UINT32>
0x004057a9:	leal %ecx, 0x144(%ecx,%eax)
0x004057b0:	movl -12(%ebp), %ecx
0x004057b3:	movl %ecx, 0x44(%eax,%edx,4)
0x004057b7:	andl %ecx, %esi
0x004057b9:	jne 13
0x004057bb:	movl %ecx, 0xc4(%eax,%edx,4)
0x004057c2:	pushl $0x20<UINT8>
0x004057c4:	andl %ecx, -8(%ebp)
0x004057c7:	popl %edi
0x004057c8:	testl %ecx, %ecx
0x004057ca:	jl 0x004057d1
0x004057cc:	shll %ecx
0x004057ce:	incl %edi
0x004057cf:	jmp 0x004057c8
0x004057d1:	movl %ecx, -12(%ebp)
0x004057d4:	movl %edx, 0x4(%ecx,%edi,8)
0x004057d8:	movl %ecx, (%edx)
0x004057da:	subl %ecx, -16(%ebp)
0x004057dd:	movl %esi, %ecx
0x004057df:	movl -8(%ebp), %ecx
0x004057e2:	sarl %esi, $0x4<UINT8>
0x004057e5:	decl %esi
0x004057e6:	cmpl %esi, $0x3f<UINT8>
0x004057e9:	jle 3
0x004057eb:	pushl $0x3f<UINT8>
0x004057ed:	popl %esi
0x004057ee:	cmpl %esi, %edi
0x004057f0:	je 0x00405903
0x00405903:	testl %ecx, %ecx
0x00405905:	je 11
0x00405907:	movl (%edx), %ecx
0x00405909:	movl -4(%ecx,%edx), %ecx
0x0040590d:	jmp 0x00405912
0x00405912:	movl %esi, -16(%ebp)
0x00405915:	addl %edx, %ecx
0x00405917:	leal %ecx, 0x1(%esi)
0x0040591a:	movl (%edx), %ecx
0x0040591c:	movl -4(%edx,%esi), %ecx
0x00405920:	movl %esi, -12(%ebp)
0x00405923:	movl %ecx, (%esi)
0x00405925:	testl %ecx, %ecx
0x00405927:	leal %edi, 0x1(%ecx)
0x0040592a:	movl (%esi), %edi
0x0040592c:	jne 0x00405948
0x0040592e:	cmpl %ebx, 0x44a4c4
0x00405934:	jne 0x00405948
0x00405948:	movl %ecx, -4(%ebp)
0x0040594b:	movl (%eax), %ecx
0x0040594d:	leal %eax, 0x4(%edx)
0x00405950:	popl %edi
0x00405951:	popl %esi
0x00405952:	popl %ebx
0x00405953:	leave
0x00405954:	ret

0x00403bff:	testl %eax, %eax
0x00403c01:	popl %ecx
0x00403c02:	jne 0x00403c20
0x00403c20:	popl %esi
0x00403c21:	ret

0x00403bd0:	testl %eax, %eax
0x00403bd2:	popl %ecx
0x00403bd3:	jne 0x00403beb
0x00403beb:	ret

0x00403bbd:	popl %ecx
0x00403bbe:	popl %ecx
0x00403bbf:	ret

0x00407570:	movl %esi, %eax
0x00407572:	popl %ecx
0x00407573:	testl %esi, %esi
0x00407575:	jne 0x0040757f
0x0040757f:	movl 0x44a3a0, %esi
0x00407585:	movl 0x44a4a0, $0x20<UINT32>
0x0040758f:	leal %eax, 0x100(%esi)
0x00407595:	cmpl %esi, %eax
0x00407597:	jae 0x004075b3
0x00407599:	andb 0x4(%esi), $0x0<UINT8>
0x0040759d:	orl (%esi), $0xffffffff<UINT8>
0x004075a0:	movb 0x5(%esi), $0xa<UINT8>
0x004075a4:	movl %eax, 0x44a3a0
0x004075a9:	addl %esi, $0x8<UINT8>
0x004075ac:	addl %eax, $0x100<UINT32>
0x004075b1:	jmp 0x00407595
0x004075b3:	leal %eax, 0x10(%esp)
0x004075b7:	pushl %eax
0x004075b8:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x004075be:	cmpw 0x42(%esp), $0x0<UINT8>
0x004075c4:	je 197
0x004075ca:	movl %eax, 0x44(%esp)
0x004075ce:	testl %eax, %eax
0x004075d0:	je 185
0x004075d6:	movl %esi, (%eax)
0x004075d8:	leal %ebp, 0x4(%eax)
0x004075db:	movl %eax, $0x800<UINT32>
0x004075e0:	cmpl %esi, %eax
0x004075e2:	leal %ebx, (%esi,%ebp)
0x004075e5:	jl 0x004075e9
0x004075e9:	cmpl 0x44a4a0, %esi
0x004075ef:	jnl 0x00407643
0x00407643:	xorl %edi, %edi
0x00407645:	testl %esi, %esi
0x00407647:	jle 0x0040768f
0x0040768f:	xorl %ebx, %ebx
0x00407691:	movl %eax, 0x44a3a0
0x00407696:	cmpl (%eax,%ebx,8), $0xffffffff<UINT8>
0x0040769a:	leal %esi, (%eax,%ebx,8)
0x0040769d:	jne 77
0x0040769f:	testl %ebx, %ebx
0x004076a1:	movb 0x4(%esi), $0xffffff81<UINT8>
0x004076a5:	jne 0x004076ac
0x004076a7:	pushl $0xfffffff6<UINT8>
0x004076a9:	popl %eax
0x004076aa:	jmp 0x004076b6
0x004076b6:	pushl %eax
0x004076b7:	call GetStdHandle@KERNEL32.DLL
GetStdHandle@KERNEL32.DLL: API Node	
0x004076bd:	movl %edi, %eax
0x004076bf:	cmpl %edi, $0xffffffff<UINT8>
0x004076c2:	je 23
0x004076c4:	pushl %edi
0x004076c5:	call GetFileType@KERNEL32.DLL
GetFileType@KERNEL32.DLL: API Node	
0x004076cb:	testl %eax, %eax
0x004076cd:	je 12
0x004076cf:	andl %eax, $0xff<UINT32>
0x004076d4:	movl (%esi), %edi
0x004076d6:	cmpl %eax, $0x2<UINT8>
0x004076d9:	jne 6
0x004076db:	orb 0x4(%esi), $0x40<UINT8>
0x004076df:	jmp 0x004076f0
0x004076f0:	incl %ebx
0x004076f1:	cmpl %ebx, $0x3<UINT8>
0x004076f4:	jl 0x00407691
0x004076ac:	movl %eax, %ebx
0x004076ae:	decl %eax
0x004076af:	negl %eax
0x004076b1:	sbbl %eax, %eax
0x004076b3:	addl %eax, $0xfffffff5<UINT8>
0x004076f6:	pushl 0x44a4a0
0x004076fc:	call SetHandleCount@KERNEL32.DLL
SetHandleCount@KERNEL32.DLL: API Node	
0x00407702:	popl %edi
0x00407703:	popl %esi
0x00407704:	popl %ebp
0x00407705:	popl %ebx
0x00407706:	addl %esp, $0x44<UINT8>
0x00407709:	ret

0x00403dc4:	call GetCommandLineA@KERNEL32.DLL
GetCommandLineA@KERNEL32.DLL: API Node	
0x00403dca:	movl 0x44b4e4, %eax
0x00403dcf:	call 0x0040742d
0x0040742d:	pushl %ecx
0x0040742e:	pushl %ecx
0x0040742f:	movl %eax, 0x427674
0x00407434:	pushl %ebx
0x00407435:	pushl %ebp
0x00407436:	movl %ebp, 0x40a0bc
0x0040743c:	pushl %esi
0x0040743d:	pushl %edi
0x0040743e:	xorl %ebx, %ebx
0x00407440:	xorl %esi, %esi
0x00407442:	xorl %edi, %edi
0x00407444:	cmpl %eax, %ebx
0x00407446:	jne 51
0x00407448:	call GetEnvironmentStringsW@KERNEL32.DLL
GetEnvironmentStringsW@KERNEL32.DLL: API Node	
0x0040744a:	movl %esi, %eax
0x0040744c:	cmpl %esi, %ebx
0x0040744e:	je 12
0x00407450:	movl 0x427674, $0x1<UINT32>
0x0040745a:	jmp 0x00407484
0x00407484:	cmpl %esi, %ebx
0x00407486:	jne 0x00407494
0x00407494:	cmpw (%esi), %bx
0x00407497:	movl %eax, %esi
0x00407499:	je 14
0x0040749b:	incl %eax
0x0040749c:	incl %eax
0x0040749d:	cmpw (%eax), %bx
0x004074a0:	jne 0x0040749b
0x004074a2:	incl %eax
0x004074a3:	incl %eax
0x004074a4:	cmpw (%eax), %bx
0x004074a7:	jne 0x0040749b
0x004074a9:	subl %eax, %esi
0x004074ab:	movl %edi, 0x40a0c4
0x004074b1:	sarl %eax
0x004074b3:	pushl %ebx
0x004074b4:	pushl %ebx
0x004074b5:	incl %eax
0x004074b6:	pushl %ebx
0x004074b7:	pushl %ebx
0x004074b8:	pushl %eax
0x004074b9:	pushl %esi
0x004074ba:	pushl %ebx
0x004074bb:	pushl %ebx
0x004074bc:	movl 0x34(%esp), %eax
0x004074c0:	call WideCharToMultiByte@KERNEL32.DLL
WideCharToMultiByte@KERNEL32.DLL: API Node	
0x004074c2:	movl %ebp, %eax
0x004074c4:	cmpl %ebp, %ebx
0x004074c6:	je 50
0x004074c8:	pushl %ebp
0x004074c9:	call 0x00403bae
0x00403c04:	testl %esi, %esi
0x00403c06:	jne 0x00403c0b
0x00403c0b:	addl %esi, $0xf<UINT8>
0x00403c0e:	andl %esi, $0xfffffff0<UINT8>
0x00403c11:	pushl %esi
0x00403c12:	pushl $0x0<UINT8>
0x00403c14:	pushl 0x44a4d0
0x00403c1a:	call HeapAlloc@KERNEL32.DLL
0x004074ce:	cmpl %eax, %ebx
0x004074d0:	popl %ecx
0x004074d1:	movl 0x10(%esp), %eax
0x004074d5:	je 35
0x004074d7:	pushl %ebx
0x004074d8:	pushl %ebx
0x004074d9:	pushl %ebp
0x004074da:	pushl %eax
0x004074db:	pushl 0x24(%esp)
0x004074df:	pushl %esi
0x004074e0:	pushl %ebx
0x004074e1:	pushl %ebx
0x004074e2:	call WideCharToMultiByte@KERNEL32.DLL
0x004074e4:	testl %eax, %eax
0x004074e6:	jne 0x004074f6
0x004074f6:	movl %ebx, 0x10(%esp)
0x004074fa:	pushl %esi
0x004074fb:	call FreeEnvironmentStringsW@KERNEL32.DLL
FreeEnvironmentStringsW@KERNEL32.DLL: API Node	
0x00407501:	movl %eax, %ebx
0x00407503:	jmp 0x00407558
0x00407558:	popl %edi
0x00407559:	popl %esi
0x0040755a:	popl %ebp
0x0040755b:	popl %ebx
0x0040755c:	popl %ecx
0x0040755d:	popl %ecx
0x0040755e:	ret

0x00403dd4:	movl 0x427500, %eax
0x00403dd9:	call 0x004071e0
0x004071e0:	pushl %ebp
0x004071e1:	movl %ebp, %esp
0x004071e3:	pushl %ecx
0x004071e4:	pushl %ecx
0x004071e5:	pushl %ebx
0x004071e6:	xorl %ebx, %ebx
0x004071e8:	cmpl 0x44a4a8, %ebx
0x004071ee:	pushl %esi
0x004071ef:	pushl %edi
0x004071f0:	jne 5
0x004071f2:	call 0x004091a8
0x004091a8:	cmpl 0x44a4a8, $0x0<UINT8>
0x004091af:	jne 0x004091c3
0x004091b1:	pushl $0xfffffffd<UINT8>
0x004091b3:	call 0x00408dd4
0x00408dd4:	pushl %ebp
0x00408dd5:	movl %ebp, %esp
0x00408dd7:	subl %esp, $0x18<UINT8>
0x00408dda:	pushl %ebx
0x00408ddb:	pushl %esi
0x00408ddc:	pushl %edi
0x00408ddd:	pushl 0x8(%ebp)
0x00408de0:	call 0x00408f6d
0x00408f6d:	movl %eax, 0x4(%esp)
0x00408f71:	andl 0x427680, $0x0<UINT8>
0x00408f78:	cmpl %eax, $0xfffffffe<UINT8>
0x00408f7b:	jne 0x00408f8d
0x00408f8d:	cmpl %eax, $0xfffffffd<UINT8>
0x00408f90:	jne 16
0x00408f92:	movl 0x427680, $0x1<UINT32>
0x00408f9c:	jmp GetACP@KERNEL32.DLL
GetACP@KERNEL32.DLL: API Node	
0x00408de5:	movl %esi, %eax
0x00408de7:	popl %ecx
0x00408de8:	cmpl %esi, 0x44a168
0x00408dee:	movl 0x8(%ebp), %esi
0x00408df1:	je 362
0x00408df7:	xorl %ebx, %ebx
0x00408df9:	cmpl %esi, %ebx
0x00408dfb:	je 342
0x00408e01:	xorl %edx, %edx
0x00408e03:	movl %eax, $0x4271c8<UINT32>
0x00408e08:	cmpl (%eax), %esi
0x00408e0a:	je 114
0x00408e0c:	addl %eax, $0x30<UINT8>
0x00408e0f:	incl %edx
0x00408e10:	cmpl %eax, $0x4272b8<UINT32>
0x00408e15:	jl 0x00408e08
0x00408e17:	leal %eax, -24(%ebp)
0x00408e1a:	pushl %eax
0x00408e1b:	pushl %esi
0x00408e1c:	call GetCPInfo@KERNEL32.DLL
GetCPInfo@KERNEL32.DLL: API Node	
0x00408e22:	cmpl %eax, $0x1<UINT8>
0x00408e25:	jne 292
0x00408e2b:	pushl $0x40<UINT8>
0x00408e2d:	xorl %eax, %eax
0x00408e2f:	popl %ecx
0x00408e30:	movl %edi, $0x44a280<UINT32>
0x00408e35:	cmpl -24(%ebp), $0x1<UINT8>
0x00408e39:	movl 0x44a168, %esi
0x00408e3f:	rep stosl %es:(%edi), %eax
0x00408e41:	stosb %es:(%edi), %al
0x00408e42:	movl 0x44a384, %ebx
0x00408e48:	jbe 239
0x00408e4e:	cmpb -18(%ebp), $0x0<UINT8>
0x00408e52:	je 0x00408f13
0x00408f13:	pushl $0x1<UINT8>
0x00408f15:	popl %eax
0x00408f16:	orb 0x44a281(%eax), $0x8<UINT8>
0x00408f1d:	incl %eax
0x00408f1e:	cmpl %eax, $0xff<UINT32>
0x00408f23:	jb 0x00408f16
0x00408f25:	pushl %esi
0x00408f26:	call 0x00408fb7
0x00408fb7:	movl %eax, 0x4(%esp)
0x00408fbb:	subl %eax, $0x3a4<UINT32>
0x00408fc0:	je 34
0x00408fc2:	subl %eax, $0x4<UINT8>
0x00408fc5:	je 23
0x00408fc7:	subl %eax, $0xd<UINT8>
0x00408fca:	je 12
0x00408fcc:	decl %eax
0x00408fcd:	je 3
0x00408fcf:	xorl %eax, %eax
0x00408fd1:	ret

0x00408f2b:	popl %ecx
0x00408f2c:	movl 0x44a384, %eax
0x00408f31:	movl 0x44a17c, $0x1<UINT32>
0x00408f3b:	jmp 0x00408f43
0x00408f43:	xorl %eax, %eax
0x00408f45:	movl %edi, $0x44a170<UINT32>
0x00408f4a:	stosl %es:(%edi), %eax
0x00408f4b:	stosl %es:(%edi), %eax
0x00408f4c:	stosl %es:(%edi), %eax
0x00408f4d:	jmp 0x00408f5c
0x00408f5c:	call 0x00409013
0x00409013:	pushl %ebp
0x00409014:	movl %ebp, %esp
0x00409016:	subl %esp, $0x514<UINT32>
0x0040901c:	leal %eax, -20(%ebp)
0x0040901f:	pushl %esi
0x00409020:	pushl %eax
0x00409021:	pushl 0x44a168
0x00409027:	call GetCPInfo@KERNEL32.DLL
0x0040902d:	cmpl %eax, $0x1<UINT8>
0x00409030:	jne 278
0x00409036:	xorl %eax, %eax
0x00409038:	movl %esi, $0x100<UINT32>
0x0040903d:	movb -276(%ebp,%eax), %al
0x00409044:	incl %eax
0x00409045:	cmpl %eax, %esi
0x00409047:	jb 0x0040903d
0x00409049:	movb %al, -14(%ebp)
0x0040904c:	movb -276(%ebp), $0x20<UINT8>
0x00409053:	testb %al, %al
0x00409055:	je 0x0040908e
0x0040908e:	pushl $0x0<UINT8>
0x00409090:	leal %eax, -1300(%ebp)
0x00409096:	pushl 0x44a384
0x0040909c:	pushl 0x44a168
0x004090a2:	pushl %eax
0x004090a3:	leal %eax, -276(%ebp)
0x004090a9:	pushl %esi
0x004090aa:	pushl %eax
0x004090ab:	pushl $0x1<UINT8>
0x004090ad:	call 0x00409793
0x00409793:	pushl %ebp
0x00409794:	movl %ebp, %esp
0x00409796:	pushl $0xffffffff<UINT8>
0x00409798:	pushl $0x40a5f8<UINT32>
0x0040979d:	pushl $0x407828<UINT32>
0x004097a2:	movl %eax, %fs:0
0x004097a8:	pushl %eax
0x004097a9:	movl %fs:0, %esp
0x004097b0:	subl %esp, $0x18<UINT8>
0x004097b3:	pushl %ebx
0x004097b4:	pushl %esi
0x004097b5:	pushl %edi
0x004097b6:	movl -24(%ebp), %esp
0x004097b9:	movl %eax, 0x4276b4
0x004097be:	xorl %ebx, %ebx
0x004097c0:	cmpl %eax, %ebx
0x004097c2:	jne 62
0x004097c4:	leal %eax, -28(%ebp)
0x004097c7:	pushl %eax
0x004097c8:	pushl $0x1<UINT8>
0x004097ca:	popl %esi
0x004097cb:	pushl %esi
0x004097cc:	pushl $0x40a5f0<UINT32>
0x004097d1:	pushl %esi
0x004097d2:	call GetStringTypeW@KERNEL32.DLL
GetStringTypeW@KERNEL32.DLL: API Node	
0x004097d8:	testl %eax, %eax
0x004097da:	je 4
0x004097dc:	movl %eax, %esi
0x004097de:	jmp 0x004097fd
0x004097fd:	movl 0x4276b4, %eax
0x00409802:	cmpl %eax, $0x2<UINT8>
0x00409805:	jne 0x0040982b
0x0040982b:	cmpl %eax, $0x1<UINT8>
0x0040982e:	jne 148
0x00409834:	cmpl 0x18(%ebp), %ebx
0x00409837:	jne 0x00409841
0x00409841:	pushl %ebx
0x00409842:	pushl %ebx
0x00409843:	pushl 0x10(%ebp)
0x00409846:	pushl 0xc(%ebp)
0x00409849:	movl %eax, 0x20(%ebp)
0x0040984c:	negl %eax
0x0040984e:	sbbl %eax, %eax
0x00409850:	andl %eax, $0x8<UINT8>
0x00409853:	incl %eax
0x00409854:	pushl %eax
0x00409855:	pushl 0x18(%ebp)
0x00409858:	call MultiByteToWideChar@KERNEL32.DLL
MultiByteToWideChar@KERNEL32.DLL: API Node	
0x0040985e:	movl -32(%ebp), %eax
0x00409861:	cmpl %eax, %ebx
0x00409863:	je 99
0x00409865:	movl -4(%ebp), %ebx
0x00409868:	leal %edi, (%eax,%eax)
0x0040986b:	movl %eax, %edi
0x0040986d:	addl %eax, $0x3<UINT8>
0x00409870:	andb %al, $0xfffffffc<UINT8>
0x00409872:	call 0x00403b50
0x00403b50:	pushl %ecx
0x00403b51:	cmpl %eax, $0x1000<UINT32>
0x00403b56:	leal %ecx, 0x8(%esp)
0x00403b5a:	jb 0x00403b70
0x00403b70:	subl %ecx, %eax
0x00403b72:	movl %eax, %esp
0x00403b74:	testl (%ecx), %eax
0x00403b76:	movl %esp, %ecx
0x00403b78:	movl %ecx, (%eax)
0x00403b7a:	movl %eax, 0x4(%eax)
0x00403b7d:	pushl %eax
0x00403b7e:	ret

0x00409877:	movl -24(%ebp), %esp
0x0040987a:	movl %esi, %esp
0x0040987c:	movl -36(%ebp), %esi
0x0040987f:	pushl %edi
0x00409880:	pushl %ebx
0x00409881:	pushl %esi
0x00409882:	call 0x004087e0
0x004087e0:	movl %edx, 0xc(%esp)
0x004087e4:	movl %ecx, 0x4(%esp)
0x004087e8:	testl %edx, %edx
0x004087ea:	je 71
0x004087ec:	xorl %eax, %eax
0x004087ee:	movb %al, 0x8(%esp)
0x004087f2:	pushl %edi
0x004087f3:	movl %edi, %ecx
0x004087f5:	cmpl %edx, $0x4<UINT8>
0x004087f8:	jb 45
0x004087fa:	negl %ecx
0x004087fc:	andl %ecx, $0x3<UINT8>
0x004087ff:	je 0x00408809
0x00408809:	movl %ecx, %eax
0x0040880b:	shll %eax, $0x8<UINT8>
0x0040880e:	addl %eax, %ecx
0x00408810:	movl %ecx, %eax
0x00408812:	shll %eax, $0x10<UINT8>
0x00408815:	addl %eax, %ecx
0x00408817:	movl %ecx, %edx
0x00408819:	andl %edx, $0x3<UINT8>
0x0040881c:	shrl %ecx, $0x2<UINT8>
0x0040881f:	je 6
0x00408821:	rep stosl %es:(%edi), %eax
0x00408823:	testl %edx, %edx
0x00408825:	je 0x0040882d
0x0040882d:	movl %eax, 0x8(%esp)
0x00408831:	popl %edi
0x00408832:	ret

0x00409887:	addl %esp, $0xc<UINT8>
0x0040988a:	jmp 0x00409897
0x00409897:	orl -4(%ebp), $0xffffffff<UINT8>
0x0040989b:	cmpl %esi, %ebx
0x0040989d:	je 41
0x0040989f:	pushl -32(%ebp)
0x004098a2:	pushl %esi
0x004098a3:	pushl 0x10(%ebp)
0x004098a6:	pushl 0xc(%ebp)
0x004098a9:	pushl $0x1<UINT8>
0x004098ab:	pushl 0x18(%ebp)
0x004098ae:	call MultiByteToWideChar@KERNEL32.DLL
0x004098b4:	cmpl %eax, %ebx
0x004098b6:	je 16
0x004098b8:	pushl 0x14(%ebp)
0x004098bb:	pushl %eax
0x004098bc:	pushl %esi
0x004098bd:	pushl 0x8(%ebp)
0x004098c0:	call GetStringTypeW@KERNEL32.DLL
0x004098c6:	jmp 0x004098ca
0x004098ca:	leal %esp, -52(%ebp)
0x004098cd:	movl %ecx, -16(%ebp)
0x004098d0:	movl %fs:0, %ecx
0x004098d7:	popl %edi
0x004098d8:	popl %esi
0x004098d9:	popl %ebx
0x004098da:	leave
0x004098db:	ret

0x004090b2:	pushl $0x0<UINT8>
0x004090b4:	leal %eax, -532(%ebp)
0x004090ba:	pushl 0x44a168
0x004090c0:	pushl %esi
0x004090c1:	pushl %eax
0x004090c2:	leal %eax, -276(%ebp)
0x004090c8:	pushl %esi
0x004090c9:	pushl %eax
0x004090ca:	pushl %esi
0x004090cb:	pushl 0x44a384
0x004090d1:	call 0x004098dc
0x004098dc:	pushl %ebp
0x004098dd:	movl %ebp, %esp
0x004098df:	pushl $0xffffffff<UINT8>
0x004098e1:	pushl $0x40a608<UINT32>
0x004098e6:	pushl $0x407828<UINT32>
0x004098eb:	movl %eax, %fs:0
0x004098f1:	pushl %eax
0x004098f2:	movl %fs:0, %esp
0x004098f9:	subl %esp, $0x1c<UINT8>
0x004098fc:	pushl %ebx
0x004098fd:	pushl %esi
0x004098fe:	pushl %edi
0x004098ff:	movl -24(%ebp), %esp
0x00409902:	xorl %edi, %edi
0x00409904:	cmpl 0x4276b8, %edi
0x0040990a:	jne 0x00409952
0x0040990c:	pushl %edi
0x0040990d:	pushl %edi
0x0040990e:	pushl $0x1<UINT8>
0x00409910:	popl %ebx
0x00409911:	pushl %ebx
0x00409912:	pushl $0x40a5f0<UINT32>
0x00409917:	movl %esi, $0x100<UINT32>
0x0040991c:	pushl %esi
0x0040991d:	pushl %edi
0x0040991e:	call LCMapStringW@KERNEL32.DLL
LCMapStringW@KERNEL32.DLL: API Node	
0x00409924:	testl %eax, %eax
0x00409926:	je 8
0x00409928:	movl 0x4276b8, %ebx
0x0040992e:	jmp 0x00409952
0x00409952:	cmpl 0x14(%ebp), %edi
0x00409955:	jle 16
0x00409957:	pushl 0x14(%ebp)
0x0040995a:	pushl 0x10(%ebp)
0x0040995d:	call 0x00409b00
0x00409b00:	movl %edx, 0x8(%esp)
0x00409b04:	movl %eax, 0x4(%esp)
0x00409b08:	testl %edx, %edx
0x00409b0a:	pushl %esi
0x00409b0b:	leal %ecx, -1(%edx)
0x00409b0e:	je 13
0x00409b10:	cmpb (%eax), $0x0<UINT8>
0x00409b13:	je 8
0x00409b15:	incl %eax
0x00409b16:	movl %esi, %ecx
0x00409b18:	decl %ecx
0x00409b19:	testl %esi, %esi
0x00409b1b:	jne 0x00409b10
0x00409b1d:	cmpb (%eax), $0x0<UINT8>
0x00409b20:	popl %esi
0x00409b21:	jne 0x00409b28
0x00409b28:	movl %eax, %edx
0x00409b2a:	ret

0x00409962:	popl %ecx
0x00409963:	popl %ecx
0x00409964:	movl 0x14(%ebp), %eax
0x00409967:	movl %eax, 0x4276b8
0x0040996c:	cmpl %eax, $0x2<UINT8>
0x0040996f:	jne 0x0040998e
0x0040998e:	cmpl %eax, $0x1<UINT8>
0x00409991:	jne 211
0x00409997:	cmpl 0x20(%ebp), %edi
0x0040999a:	jne 0x004099a4
0x004099a4:	pushl %edi
0x004099a5:	pushl %edi
0x004099a6:	pushl 0x14(%ebp)
0x004099a9:	pushl 0x10(%ebp)
0x004099ac:	movl %eax, 0x24(%ebp)
0x004099af:	negl %eax
0x004099b1:	sbbl %eax, %eax
0x004099b3:	andl %eax, $0x8<UINT8>
0x004099b6:	incl %eax
0x004099b7:	pushl %eax
0x004099b8:	pushl 0x20(%ebp)
0x004099bb:	call MultiByteToWideChar@KERNEL32.DLL
0x004099c1:	movl %ebx, %eax
0x004099c3:	movl -28(%ebp), %ebx
0x004099c6:	cmpl %ebx, %edi
0x004099c8:	je 156
0x004099ce:	movl -4(%ebp), %edi
0x004099d1:	leal %eax, (%ebx,%ebx)
0x004099d4:	addl %eax, $0x3<UINT8>
0x004099d7:	andb %al, $0xfffffffc<UINT8>
0x004099d9:	call 0x00403b50
0x004099de:	movl -24(%ebp), %esp
0x004099e1:	movl %eax, %esp
0x004099e3:	movl -36(%ebp), %eax
0x004099e6:	orl -4(%ebp), $0xffffffff<UINT8>
0x004099ea:	jmp 0x004099ff
0x004099ff:	cmpl -36(%ebp), %edi
0x00409a02:	je 102
0x00409a04:	pushl %ebx
0x00409a05:	pushl -36(%ebp)
0x00409a08:	pushl 0x14(%ebp)
0x00409a0b:	pushl 0x10(%ebp)
0x00409a0e:	pushl $0x1<UINT8>
0x00409a10:	pushl 0x20(%ebp)
0x00409a13:	call MultiByteToWideChar@KERNEL32.DLL
0x00409a19:	testl %eax, %eax
0x00409a1b:	je 77
0x00409a1d:	pushl %edi
0x00409a1e:	pushl %edi
0x00409a1f:	pushl %ebx
0x00409a20:	pushl -36(%ebp)
0x00409a23:	pushl 0xc(%ebp)
0x00409a26:	pushl 0x8(%ebp)
0x00409a29:	call LCMapStringW@KERNEL32.DLL
0x00409a2f:	movl %esi, %eax
0x00409a31:	movl -40(%ebp), %esi
0x00409a34:	cmpl %esi, %edi
0x00409a36:	je 50
0x00409a38:	testb 0xd(%ebp), $0x4<UINT8>
0x00409a3c:	je 0x00409a7e
0x00409a7e:	movl -4(%ebp), $0x1<UINT32>
0x00409a85:	leal %eax, (%esi,%esi)
0x00409a88:	addl %eax, $0x3<UINT8>
0x00409a8b:	andb %al, $0xfffffffc<UINT8>
0x00409a8d:	call 0x00403b50
0x00409a92:	movl -24(%ebp), %esp
0x00409a95:	movl %ebx, %esp
0x00409a97:	movl -32(%ebp), %ebx
0x00409a9a:	orl -4(%ebp), $0xffffffff<UINT8>
0x00409a9e:	jmp 0x00409ab2
0x00409ab2:	cmpl %ebx, %edi
0x00409ab4:	je -76
0x00409ab6:	pushl %esi
0x00409ab7:	pushl %ebx
0x00409ab8:	pushl -28(%ebp)
0x00409abb:	pushl -36(%ebp)
0x00409abe:	pushl 0xc(%ebp)
0x00409ac1:	pushl 0x8(%ebp)
0x00409ac4:	call LCMapStringW@KERNEL32.DLL
0x00409aca:	testl %eax, %eax
0x00409acc:	je -100
0x00409ace:	cmpl 0x1c(%ebp), %edi
0x00409ad1:	pushl %edi
0x00409ad2:	pushl %edi
0x00409ad3:	jne 0x00409ad9
0x00409ad9:	pushl 0x1c(%ebp)
0x00409adc:	pushl 0x18(%ebp)
0x00409adf:	pushl %esi
0x00409ae0:	pushl %ebx
0x00409ae1:	pushl $0x220<UINT32>
0x00409ae6:	pushl 0x20(%ebp)
0x00409ae9:	call WideCharToMultiByte@KERNEL32.DLL
0x00409aef:	movl %esi, %eax
0x00409af1:	cmpl %esi, %edi
0x00409af3:	je -143
0x00409af9:	movl %eax, %esi
0x00409afb:	jmp 0x00409a6c
0x00409a6c:	leal %esp, -56(%ebp)
0x00409a6f:	movl %ecx, -16(%ebp)
0x00409a72:	movl %fs:0, %ecx
0x00409a79:	popl %edi
0x00409a7a:	popl %esi
0x00409a7b:	popl %ebx
0x00409a7c:	leave
0x00409a7d:	ret

0x004090d6:	pushl $0x0<UINT8>
0x004090d8:	leal %eax, -788(%ebp)
0x004090de:	pushl 0x44a168
0x004090e4:	pushl %esi
0x004090e5:	pushl %eax
0x004090e6:	leal %eax, -276(%ebp)
0x004090ec:	pushl %esi
0x004090ed:	pushl %eax
0x004090ee:	pushl $0x200<UINT32>
0x004090f3:	pushl 0x44a384
0x004090f9:	call 0x004098dc
0x004090fe:	addl %esp, $0x5c<UINT8>
0x00409101:	xorl %eax, %eax
0x00409103:	leal %ecx, -1300(%ebp)
0x00409109:	movw %dx, (%ecx)
0x0040910c:	testb %dl, $0x1<UINT8>
0x0040910f:	je 0x00409127
0x00409127:	testb %dl, $0x2<UINT8>
0x0040912a:	je 0x0040913c
0x0040913c:	andb 0x44a180(%eax), $0x0<UINT8>
0x00409143:	incl %eax
0x00409144:	incl %ecx
0x00409145:	incl %ecx
0x00409146:	cmpl %eax, %esi
0x00409148:	jb 0x00409109
0x00409111:	orb 0x44a281(%eax), $0x10<UINT8>
0x00409118:	movb %dl, -532(%ebp,%eax)
0x0040911f:	movb 0x44a180(%eax), %dl
0x00409125:	jmp 0x00409143
0x0040912c:	orb 0x44a281(%eax), $0x20<UINT8>
0x00409133:	movb %dl, -788(%ebp,%eax)
0x0040913a:	jmp 0x0040911f
0x0040914a:	jmp 0x00409195
0x00409195:	popl %esi
0x00409196:	leave
0x00409197:	ret

0x00408f61:	xorl %eax, %eax
0x00408f63:	jmp 0x00408f68
0x00408f68:	popl %edi
0x00408f69:	popl %esi
0x00408f6a:	popl %ebx
0x00408f6b:	leave
0x00408f6c:	ret

0x004091b8:	popl %ecx
0x004091b9:	movl 0x44a4a8, $0x1<UINT32>
0x004091c3:	ret

0x004071f7:	movl %esi, $0x427570<UINT32>
0x004071fc:	pushl $0x104<UINT32>
0x00407201:	pushl %esi
0x00407202:	pushl %ebx
0x00407203:	call GetModuleFileNameA@KERNEL32.DLL
GetModuleFileNameA@KERNEL32.DLL: API Node	
0x00407209:	movl %eax, 0x44b4e4
0x0040720e:	movl 0x427558, %esi
0x00407214:	movl %edi, %esi
0x00407216:	cmpb (%eax), %bl
0x00407218:	je 2
0x0040721a:	movl %edi, %eax
0x0040721c:	leal %eax, -8(%ebp)
0x0040721f:	pushl %eax
0x00407220:	leal %eax, -4(%ebp)
0x00407223:	pushl %eax
0x00407224:	pushl %ebx
0x00407225:	pushl %ebx
0x00407226:	pushl %edi
0x00407227:	call 0x00407279
0x00407279:	pushl %ebp
0x0040727a:	movl %ebp, %esp
0x0040727c:	movl %ecx, 0x18(%ebp)
0x0040727f:	movl %eax, 0x14(%ebp)
0x00407282:	pushl %ebx
0x00407283:	pushl %esi
0x00407284:	andl (%ecx), $0x0<UINT8>
0x00407287:	movl %esi, 0x10(%ebp)
0x0040728a:	pushl %edi
0x0040728b:	movl %edi, 0xc(%ebp)
0x0040728e:	movl (%eax), $0x1<UINT32>
0x00407294:	movl %eax, 0x8(%ebp)
0x00407297:	testl %edi, %edi
0x00407299:	je 0x004072a3
0x004072a3:	cmpb (%eax), $0x22<UINT8>
0x004072a6:	jne 68
0x004072a8:	movb %dl, 0x1(%eax)
0x004072ab:	incl %eax
0x004072ac:	cmpb %dl, $0x22<UINT8>
0x004072af:	je 0x004072da
0x004072b1:	testb %dl, %dl
0x004072b3:	je 37
0x004072b5:	movzbl %edx, %dl
0x004072b8:	testb 0x44a281(%edx), $0x4<UINT8>
0x004072bf:	je 0x004072cd
0x004072cd:	incl (%ecx)
0x004072cf:	testl %esi, %esi
0x004072d1:	je 0x004072a8
0x004072da:	incl (%ecx)
0x004072dc:	testl %esi, %esi
0x004072de:	je 0x004072e4
0x004072e4:	cmpb (%eax), $0x22<UINT8>
0x004072e7:	jne 70
0x004072e9:	incl %eax
0x004072ea:	jmp 0x0040732f
0x0040732f:	andl 0x18(%ebp), $0x0<UINT8>
0x00407333:	cmpb (%eax), $0x0<UINT8>
0x00407336:	je 0x0040741c
0x0040741c:	testl %edi, %edi
0x0040741e:	je 0x00407423
0x00407423:	movl %eax, 0x14(%ebp)
0x00407426:	popl %edi
0x00407427:	popl %esi
0x00407428:	popl %ebx
0x00407429:	incl (%eax)
0x0040742b:	popl %ebp
0x0040742c:	ret

0x0040722c:	movl %eax, -8(%ebp)
0x0040722f:	movl %ecx, -4(%ebp)
0x00407232:	leal %eax, (%eax,%ecx,4)
0x00407235:	pushl %eax
0x00407236:	call 0x00403bae
0x004056aa:	movl %ecx, 0x4(%ebx)
0x004056ad:	movl %edi, (%ebx)
0x004056af:	andl %ecx, -8(%ebp)
0x004056b2:	andl %edi, %esi
0x004056b4:	orl %ecx, %edi
0x004056b6:	jne 0x004056c3
0x0040723b:	movl %esi, %eax
0x0040723d:	addl %esp, $0x18<UINT8>
0x00407240:	cmpl %esi, %ebx
0x00407242:	jne 0x0040724c
0x0040724c:	leal %eax, -8(%ebp)
0x0040724f:	pushl %eax
0x00407250:	leal %eax, -4(%ebp)
0x00407253:	pushl %eax
0x00407254:	movl %eax, -4(%ebp)
0x00407257:	leal %eax, (%esi,%eax,4)
0x0040725a:	pushl %eax
0x0040725b:	pushl %esi
0x0040725c:	pushl %edi
0x0040725d:	call 0x00407279
0x0040729b:	movl (%edi), %esi
0x0040729d:	addl %edi, $0x4<UINT8>
0x004072a0:	movl 0xc(%ebp), %edi
0x004072d3:	movb %dl, (%eax)
0x004072d5:	movb (%esi), %dl
0x004072d7:	incl %esi
0x004072d8:	jmp 0x004072a8
0x004072e0:	andb (%esi), $0x0<UINT8>
0x004072e3:	incl %esi
0x00407420:	andl (%edi), $0x0<UINT8>
0x00407262:	movl %eax, -4(%ebp)
0x00407265:	addl %esp, $0x14<UINT8>
0x00407268:	decl %eax
0x00407269:	movl 0x427540, %esi
0x0040726f:	popl %edi
0x00407270:	popl %esi
0x00407271:	movl 0x42753c, %eax
0x00407276:	popl %ebx
0x00407277:	leave
0x00407278:	ret

0x00403dde:	call 0x00407127
0x00407127:	pushl %ebx
0x00407128:	xorl %ebx, %ebx
0x0040712a:	cmpl 0x44a4a8, %ebx
0x00407130:	pushl %esi
0x00407131:	pushl %edi
0x00407132:	jne 0x00407139
0x00407139:	movl %esi, 0x427500
0x0040713f:	xorl %edi, %edi
0x00407141:	movb %al, (%esi)
0x00407143:	cmpb %al, %bl
0x00407145:	je 0x00407159
0x00407147:	cmpb %al, $0x3d<UINT8>
0x00407149:	je 0x0040714c
0x0040714c:	pushl %esi
0x0040714d:	call 0x00406db0
0x00406db0:	movl %ecx, 0x4(%esp)
0x00406db4:	testl %ecx, $0x3<UINT32>
0x00406dba:	je 0x00406dd0
0x00406dd0:	movl %eax, (%ecx)
0x00406dd2:	movl %edx, $0x7efefeff<UINT32>
0x00406dd7:	addl %edx, %eax
0x00406dd9:	xorl %eax, $0xffffffff<UINT8>
0x00406ddc:	xorl %eax, %edx
0x00406dde:	addl %ecx, $0x4<UINT8>
0x00406de1:	testl %eax, $0x81010100<UINT32>
0x00406de6:	je 0x00406dd0
0x00406de8:	movl %eax, -4(%ecx)
0x00406deb:	testb %al, %al
0x00406ded:	je 50
0x00406def:	testb %ah, %ah
0x00406df1:	je 36
0x00406df3:	testl %eax, $0xff0000<UINT32>
0x00406df8:	je 19
0x00406dfa:	testl %eax, $0xff000000<UINT32>
0x00406dff:	je 0x00406e03
0x00406e03:	leal %eax, -1(%ecx)
0x00406e06:	movl %ecx, 0x4(%esp)
0x00406e0a:	subl %eax, %ecx
0x00406e0c:	ret

0x00407152:	popl %ecx
0x00407153:	leal %esi, 0x1(%esi,%eax)
0x00407157:	jmp 0x00407141
0x00407159:	leal %eax, 0x4(,%edi,4)
0x00407160:	pushl %eax
0x00407161:	call 0x00403bae
0x00407166:	movl %esi, %eax
0x00407168:	popl %ecx
0x00407169:	cmpl %esi, %ebx
0x0040716b:	movl 0x427548, %esi
0x00407171:	jne 0x0040717b
0x0040717b:	movl %edi, 0x427500
0x00407181:	cmpb (%edi), %bl
0x00407183:	je 57
0x00407185:	pushl %ebp
0x00407186:	pushl %edi
0x00407187:	call 0x00406db0
0x0040718c:	movl %ebp, %eax
0x0040718e:	popl %ecx
0x0040718f:	incl %ebp
0x00407190:	cmpb (%edi), $0x3d<UINT8>
0x00407193:	je 0x004071b7
0x004071b7:	addl %edi, %ebp
0x004071b9:	cmpb (%edi), %bl
0x004071bb:	jne -55
0x004071bd:	popl %ebp
0x004071be:	pushl 0x427500
0x004071c4:	call 0x00403b7f
0x00403b7f:	pushl %esi
0x00403b80:	movl %esi, 0x8(%esp)
0x00403b84:	testl %esi, %esi
0x00403b86:	je 36
0x00403b88:	pushl %esi
0x00403b89:	call 0x004052f6
0x004052f6:	movl %eax, 0x44a4c8
0x004052fb:	leal %ecx, (%eax,%eax,4)
0x004052fe:	movl %eax, 0x44a4cc
0x00405303:	leal %ecx, (%eax,%ecx,4)
0x00405306:	cmpl %eax, %ecx
0x00405308:	jae 0x0040531e
0x0040530a:	movl %edx, 0x4(%esp)
0x0040530e:	subl %edx, 0xc(%eax)
0x00405311:	cmpl %edx, $0x100000<UINT32>
0x00405317:	jb 7
0x00405319:	addl %eax, $0x14<UINT8>
0x0040531c:	jmp 0x00405306
0x0040531e:	xorl %eax, %eax
0x00405320:	ret

0x00403b8e:	popl %ecx
0x00403b8f:	testl %eax, %eax
0x00403b91:	pushl %esi
0x00403b92:	je 0x00403b9e
0x00403b9e:	pushl $0x0<UINT8>
0x00403ba0:	pushl 0x44a4d0
0x00403ba6:	call HeapFree@KERNEL32.DLL
HeapFree@KERNEL32.DLL: API Node	
0x00403bac:	popl %esi
0x00403bad:	ret

0x004071c9:	popl %ecx
0x004071ca:	movl 0x427500, %ebx
0x004071d0:	movl (%esi), %ebx
0x004071d2:	popl %edi
0x004071d3:	popl %esi
0x004071d4:	movl 0x44a4a4, $0x1<UINT32>
0x004071de:	popl %ebx
0x004071df:	ret

0x00403de3:	call 0x00406e2b
0x00406e2b:	movl %eax, 0x44a4b4
0x00406e30:	testl %eax, %eax
0x00406e32:	je 0x00406e36
0x00406e36:	pushl $0x40c014<UINT32>
0x00406e3b:	pushl $0x40c008<UINT32>
0x00406e40:	call 0x00406f31
0x00406f31:	pushl %esi
0x00406f32:	movl %esi, 0x8(%esp)
0x00406f36:	cmpl %esi, 0xc(%esp)
0x00406f3a:	jae 0x00406f49
0x00406f3c:	movl %eax, (%esi)
0x00406f3e:	testl %eax, %eax
0x00406f40:	je 0x00406f44
0x00406f44:	addl %esi, $0x4<UINT8>
0x00406f47:	jmp 0x00406f36
0x00406f42:	call 0x004091a8
0x00405131:	movl %eax, 0x44b4e0
0x00405136:	pushl %esi
0x00405137:	pushl $0x14<UINT8>
0x00405139:	testl %eax, %eax
0x0040513b:	popl %esi
0x0040513c:	jne 7
0x0040513e:	movl %eax, $0x200<UINT32>
0x00405143:	jmp 0x0040514b
0x0040514b:	movl 0x44b4e0, %eax
0x00405150:	pushl $0x4<UINT8>
0x00405152:	pushl %eax
0x00405153:	call 0x00408305
0x00408305:	pushl %ebx
0x00408306:	pushl %esi
0x00408307:	movl %esi, 0xc(%esp)
0x0040830b:	pushl %edi
0x0040830c:	imull %esi, 0x14(%esp)
0x00408311:	cmpl %esi, $0xffffffe0<UINT8>
0x00408314:	movl %ebx, %esi
0x00408316:	ja 13
0x00408318:	testl %esi, %esi
0x0040831a:	jne 0x0040831f
0x0040831f:	addl %esi, $0xf<UINT8>
0x00408322:	andl %esi, $0xfffffff0<UINT8>
0x00408325:	xorl %edi, %edi
0x00408327:	cmpl %esi, $0xffffffe0<UINT8>
0x0040832a:	ja 42
0x0040832c:	cmpl %ebx, 0x426cdc
0x00408332:	ja 0x00408341
0x00408341:	pushl %esi
0x00408342:	pushl $0x8<UINT8>
0x00408344:	pushl 0x44a4d0
0x0040834a:	call HeapAlloc@KERNEL32.DLL
0x00408350:	movl %edi, %eax
0x00408352:	testl %edi, %edi
0x00408354:	jne 0x00408378
0x00408378:	movl %eax, %edi
0x0040837a:	popl %edi
0x0040837b:	popl %esi
0x0040837c:	popl %ebx
0x0040837d:	ret

0x00405158:	popl %ecx
0x00405159:	movl 0x44a4d4, %eax
0x0040515e:	testl %eax, %eax
0x00405160:	popl %ecx
0x00405161:	jne 0x00405184
0x00405184:	xorl %ecx, %ecx
0x00405186:	movl %eax, $0x426a58<UINT32>
0x0040518b:	movl %edx, 0x44a4d4
0x00405191:	movl (%ecx,%edx), %eax
0x00405194:	addl %eax, $0x20<UINT8>
0x00405197:	addl %ecx, $0x4<UINT8>
0x0040519a:	cmpl %eax, $0x426cd8<UINT32>
0x0040519f:	jl 0x0040518b
0x004051a1:	xorl %edx, %edx
0x004051a3:	movl %ecx, $0x426a68<UINT32>
0x004051a8:	movl %eax, %edx
0x004051aa:	movl %esi, %edx
0x004051ac:	sarl %eax, $0x5<UINT8>
0x004051af:	andl %esi, $0x1f<UINT8>
0x004051b2:	movl %eax, 0x44a3a0(,%eax,4)
0x004051b9:	movl %eax, (%eax,%esi,8)
0x004051bc:	cmpl %eax, $0xffffffff<UINT8>
0x004051bf:	je 4
0x004051c1:	testl %eax, %eax
0x004051c3:	jne 0x004051c8
0x004051c8:	addl %ecx, $0x20<UINT8>
0x004051cb:	incl %edx
0x004051cc:	cmpl %ecx, $0x426ac8<UINT32>
0x004051d2:	jl 0x004051a8
0x004051d4:	popl %esi
0x004051d5:	ret

0x00406f49:	popl %esi
0x00406f4a:	ret

0x00406e45:	pushl $0x40c004<UINT32>
0x00406e4a:	pushl $0x40c000<UINT32>
0x00406e4f:	call 0x00406f31
0x00406e54:	addl %esp, $0x10<UINT8>
0x00406e57:	ret

0x00403de8:	movl -48(%ebp), %esi
0x00403deb:	leal %eax, -92(%ebp)
0x00403dee:	pushl %eax
0x00403def:	call GetStartupInfoA@KERNEL32.DLL
0x00403df5:	call 0x004070cf
0x004070cf:	cmpl 0x44a4a8, $0x0<UINT8>
0x004070d6:	jne 0x004070dd
0x004070dd:	pushl %esi
0x004070de:	movl %esi, 0x44b4e4
0x004070e4:	movb %al, (%esi)
0x004070e6:	cmpb %al, $0x22<UINT8>
0x004070e8:	jne 37
0x004070ea:	movb %al, 0x1(%esi)
0x004070ed:	incl %esi
0x004070ee:	cmpb %al, $0x22<UINT8>
0x004070f0:	je 0x00407107
0x004070f2:	testb %al, %al
0x004070f4:	je 17
0x004070f6:	movzbl %eax, %al
0x004070f9:	pushl %eax
0x004070fa:	call 0x00408d5a
0x00408d5a:	pushl $0x4<UINT8>
0x00408d5c:	pushl $0x0<UINT8>
0x00408d5e:	pushl 0xc(%esp)
0x00408d62:	call 0x00408da3
0x00408da3:	movzbl %eax, 0x4(%esp)
0x00408da8:	movb %cl, 0xc(%esp)
0x00408dac:	testb 0x44a281(%eax), %cl
0x00408db2:	jne 28
0x00408db4:	cmpl 0x8(%esp), $0x0<UINT8>
0x00408db9:	je 0x00408dc9
0x00408dc9:	xorl %eax, %eax
0x00408dcb:	testl %eax, %eax
0x00408dcd:	jne 1
0x00408dcf:	ret

0x00408d67:	addl %esp, $0xc<UINT8>
0x00408d6a:	ret

0x004070ff:	testl %eax, %eax
0x00407101:	popl %ecx
0x00407102:	je 0x004070ea
0x00407107:	cmpb (%esi), $0x22<UINT8>
0x0040710a:	jne 13
0x0040710c:	incl %esi
0x0040710d:	jmp 0x00407119
0x00407119:	movb %al, (%esi)
0x0040711b:	testb %al, %al
0x0040711d:	je 0x00407123
0x00407123:	movl %eax, %esi
0x00407125:	popl %esi
0x00407126:	ret

0x00403dfa:	movl -100(%ebp), %eax
0x00403dfd:	testb -48(%ebp), $0x1<UINT8>
0x00403e01:	je 0x00403e09
0x00403e09:	pushl $0xa<UINT8>
0x00403e0b:	popl %eax
0x00403e0c:	pushl %eax
0x00403e0d:	pushl -100(%ebp)
0x00403e10:	pushl %esi
0x00403e11:	pushl %esi
0x00403e12:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x00403e18:	pushl %eax
0x00403e19:	call 0x00402d30
0x00402d30:	subl %esp, $0x254<UINT32>
0x00402d36:	pushl %esi
0x00402d37:	pushl $0x40c764<UINT32>
0x00402d3c:	call 0x004030a0
0x004030a0:	subl %esp, $0x110<UINT32>
0x004030a6:	movl %eax, 0x114(%esp)
0x004030ad:	pushl %ebx
0x004030ae:	pushl %eax
0x004030af:	leal %ecx, 0x14(%esp)
0x004030b3:	xorl %ebx, %ebx
0x004030b5:	pushl $0x4269f0<UINT32>
0x004030ba:	pushl %ecx
0x004030bb:	movl 0x14(%esp), %ebx
0x004030bf:	movl 0x10(%esp), %ebx
0x004030c3:	call 0x00403abf
0x00403abf:	pushl %ebp
0x00403ac0:	movl %ebp, %esp
0x00403ac2:	subl %esp, $0x20<UINT8>
0x00403ac5:	movl %eax, 0x8(%ebp)
0x00403ac8:	pushl %esi
0x00403ac9:	movl -24(%ebp), %eax
0x00403acc:	movl -32(%ebp), %eax
0x00403acf:	leal %eax, 0x10(%ebp)
0x00403ad2:	movl -20(%ebp), $0x42<UINT32>
0x00403ad9:	pushl %eax
0x00403ada:	leal %eax, -32(%ebp)
0x00403add:	pushl 0xc(%ebp)
0x00403ae0:	movl -28(%ebp), $0x7fffffff<UINT32>
0x00403ae7:	pushl %eax
0x00403ae8:	call 0x0040485d
0x0040485d:	pushl %ebp
0x0040485e:	movl %ebp, %esp
0x00404860:	subl %esp, $0x248<UINT32>
0x00404866:	pushl %ebx
0x00404867:	pushl %esi
0x00404868:	pushl %edi
0x00404869:	movl %edi, 0xc(%ebp)
0x0040486c:	xorl %esi, %esi
0x0040486e:	movb %bl, (%edi)
0x00404870:	incl %edi
0x00404871:	testb %bl, %bl
0x00404873:	movl -12(%ebp), %esi
0x00404876:	movl -20(%ebp), %esi
0x00404879:	movl 0xc(%ebp), %edi
0x0040487c:	je 1780
0x00404882:	movl %ecx, -16(%ebp)
0x00404885:	xorl %edx, %edx
0x00404887:	jmp 0x00404891
0x00404891:	cmpl -20(%ebp), %edx
0x00404894:	jl 1756
0x0040489a:	cmpb %bl, $0x20<UINT8>
0x0040489d:	jl 19
0x0040489f:	cmpb %bl, $0x78<UINT8>
0x004048a2:	jg 0x004048b2
0x004048a4:	movsbl %eax, %bl
0x004048a7:	movb %al, 0x40a22c(%eax)
0x004048ad:	andl %eax, $0xf<UINT8>
0x004048b0:	jmp 0x004048b4
0x004048b4:	movsbl %eax, 0x40a24c(%esi,%eax,8)
0x004048bc:	sarl %eax, $0x4<UINT8>
0x004048bf:	cmpl %eax, $0x7<UINT8>
0x004048c2:	movl -48(%ebp), %eax
0x004048c5:	ja 1690
0x004048cb:	jmp 0x00404a40
0x004049fc:	movl %ecx, 0x426fa0
0x00404a02:	movl -36(%ebp), %edx
0x00404a05:	movzbl %eax, %bl
0x00404a08:	testb 0x1(%ecx,%eax,2), $0xffffff80<UINT8>
0x00404a0d:	je 0x00404a28
0x00404a28:	leal %eax, -20(%ebp)
0x00404a2b:	pushl %eax
0x00404a2c:	pushl 0x8(%ebp)
0x00404a2f:	movsbl %eax, %bl
0x00404a32:	pushl %eax
0x00404a33:	call 0x00404f9e
0x00404f9e:	pushl %ebp
0x00404f9f:	movl %ebp, %esp
0x00404fa1:	movl %ecx, 0xc(%ebp)
0x00404fa4:	decl 0x4(%ecx)
0x00404fa7:	js 14
0x00404fa9:	movl %edx, (%ecx)
0x00404fab:	movb %al, 0x8(%ebp)
0x00404fae:	movb (%edx), %al
0x00404fb0:	incl (%ecx)
0x00404fb2:	movzbl %eax, %al
0x00404fb5:	jmp 0x00404fc2
0x00404fc2:	cmpl %eax, $0xffffffff<UINT8>
0x00404fc5:	movl %eax, 0x10(%ebp)
0x00404fc8:	jne 0x00404fcf
0x00404fcf:	incl (%eax)
0x00404fd1:	popl %ebp
0x00404fd2:	ret

0x00404a38:	addl %esp, $0xc<UINT8>
0x00404a3b:	jmp 0x00404f65
0x00404f65:	movl %edi, 0xc(%ebp)
0x00404f68:	movb %bl, (%edi)
0x00404f6a:	incl %edi
0x00404f6b:	testb %bl, %bl
0x00404f6d:	movl 0xc(%ebp), %edi
0x00404f70:	jne 0x00404889
0x00404889:	movl %ecx, -16(%ebp)
0x0040488c:	movl %esi, -48(%ebp)
0x0040488f:	xorl %edx, %edx
0x004048b2:	xorl %eax, %eax
0x004048d2:	orl -16(%ebp), $0xffffffff<UINT8>
0x004048d6:	movl -52(%ebp), %edx
0x004048d9:	movl -40(%ebp), %edx
0x004048dc:	movl -32(%ebp), %edx
0x004048df:	movl -28(%ebp), %edx
0x004048e2:	movl -4(%ebp), %edx
0x004048e5:	movl -36(%ebp), %edx
0x004048e8:	jmp 0x00404f65
0x00404a40:	movsbl %eax, %bl
0x00404a43:	cmpl %eax, $0x67<UINT8>
0x00404a46:	jg 0x00404c68
0x00404c68:	subl %eax, $0x69<UINT8>
0x00404c6b:	je 209
0x00404c71:	subl %eax, $0x5<UINT8>
0x00404c74:	je 158
0x00404c7a:	decl %eax
0x00404c7b:	je 132
0x00404c81:	decl %eax
0x00404c82:	je 81
0x00404c84:	subl %eax, $0x3<UINT8>
0x00404c87:	je 0x00404a8a
0x00404a8a:	movl %esi, -16(%ebp)
0x00404a8d:	cmpl %esi, $0xffffffff<UINT8>
0x00404a90:	jne 5
0x00404a92:	movl %esi, $0x7fffffff<UINT32>
0x00404a97:	leal %eax, 0x10(%ebp)
0x00404a9a:	pushl %eax
0x00404a9b:	call 0x0040503c
0x0040503c:	movl %eax, 0x4(%esp)
0x00405040:	addl (%eax), $0x4<UINT8>
0x00405043:	movl %eax, (%eax)
0x00405045:	movl %eax, -4(%eax)
0x00405048:	ret

0x00404aa0:	testw -4(%ebp), $0x810<UINT16>
0x00404aa6:	popl %ecx
0x00404aa7:	movl %ecx, %eax
0x00404aa9:	movl -8(%ebp), %ecx
0x00404aac:	je 0x00404cb0
0x00404cb0:	testl %ecx, %ecx
0x00404cb2:	jne 0x00404cbd
0x00404cbd:	movl %eax, %ecx
0x00404cbf:	movl %edx, %esi
0x00404cc1:	decl %esi
0x00404cc2:	testl %edx, %edx
0x00404cc4:	je 8
0x00404cc6:	cmpb (%eax), $0x0<UINT8>
0x00404cc9:	je 0x00404cce
0x00404ccb:	incl %eax
0x00404ccc:	jmp 0x00404cbf
0x00404cce:	subl %eax, %ecx
0x00404cd0:	jmp 0x00404e64
0x00404e64:	movl -12(%ebp), %eax
0x00404e67:	cmpl -40(%ebp), $0x0<UINT8>
0x00404e6b:	jne 244
0x00404e71:	movl %ebx, -4(%ebp)
0x00404e74:	testb %bl, $0x40<UINT8>
0x00404e77:	je 0x00404e9f
0x00404e9f:	movl %esi, -32(%ebp)
0x00404ea2:	subl %esi, -28(%ebp)
0x00404ea5:	subl %esi, -12(%ebp)
0x00404ea8:	testb %bl, $0xc<UINT8>
0x00404eab:	jne 18
0x00404ead:	leal %eax, -20(%ebp)
0x00404eb0:	pushl %eax
0x00404eb1:	pushl 0x8(%ebp)
0x00404eb4:	pushl %esi
0x00404eb5:	pushl $0x20<UINT8>
0x00404eb7:	call 0x00404fd3
0x00404fd3:	pushl %esi
0x00404fd4:	pushl %edi
0x00404fd5:	movl %edi, 0x10(%esp)
0x00404fd9:	movl %eax, %edi
0x00404fdb:	decl %edi
0x00404fdc:	testl %eax, %eax
0x00404fde:	jle 0x00405001
0x00405001:	popl %edi
0x00405002:	popl %esi
0x00405003:	ret

0x00404ebc:	addl %esp, $0x10<UINT8>
0x00404ebf:	leal %eax, -20(%ebp)
0x00404ec2:	pushl %eax
0x00404ec3:	leal %eax, -22(%ebp)
0x00404ec6:	pushl 0x8(%ebp)
0x00404ec9:	pushl -28(%ebp)
0x00404ecc:	pushl %eax
0x00404ecd:	call 0x00405004
0x00405004:	pushl %ebx
0x00405005:	movl %ebx, 0xc(%esp)
0x00405009:	movl %eax, %ebx
0x0040500b:	decl %ebx
0x0040500c:	pushl %esi
0x0040500d:	pushl %edi
0x0040500e:	testl %eax, %eax
0x00405010:	jle 0x00405038
0x00405038:	popl %edi
0x00405039:	popl %esi
0x0040503a:	popl %ebx
0x0040503b:	ret

0x00404ed2:	addl %esp, $0x10<UINT8>
0x00404ed5:	testb %bl, $0x8<UINT8>
0x00404ed8:	je 0x00404ef1
0x00404ef1:	cmpl -36(%ebp), $0x0<UINT8>
0x00404ef5:	je 0x00404f38
0x00404f38:	leal %eax, -20(%ebp)
0x00404f3b:	pushl %eax
0x00404f3c:	pushl 0x8(%ebp)
0x00404f3f:	pushl -12(%ebp)
0x00404f42:	pushl -8(%ebp)
0x00404f45:	call 0x00405004
0x00405012:	movl %edi, 0x1c(%esp)
0x00405016:	movl %esi, 0x10(%esp)
0x0040501a:	movsbl %eax, (%esi)
0x0040501d:	pushl %edi
0x0040501e:	incl %esi
0x0040501f:	pushl 0x1c(%esp)
0x00405023:	pushl %eax
0x00405024:	call 0x00404f9e
0x00405029:	addl %esp, $0xc<UINT8>
0x0040502c:	cmpl (%edi), $0xffffffff<UINT8>
0x0040502f:	je 7
0x00405031:	movl %eax, %ebx
0x00405033:	decl %ebx
0x00405034:	testl %eax, %eax
0x00405036:	jg 0x0040501a
0x00404f4a:	addl %esp, $0x10<UINT8>
0x00404f4d:	testb -4(%ebp), $0x4<UINT8>
0x00404f51:	je 0x00404f65
0x00404f76:	movl %eax, -20(%ebp)
0x00404f79:	popl %edi
0x00404f7a:	popl %esi
0x00404f7b:	popl %ebx
0x00404f7c:	leave
0x00404f7d:	ret

0x00403aed:	addl %esp, $0xc<UINT8>
0x00403af0:	decl -28(%ebp)
0x00403af3:	movl %esi, %eax
0x00403af5:	js 8
0x00403af7:	movl %eax, -32(%ebp)
0x00403afa:	andb (%eax), $0x0<UINT8>
0x00403afd:	jmp 0x00403b0c
0x00403b0c:	movl %eax, %esi
0x00403b0e:	popl %esi
0x00403b0f:	leave
0x00403b10:	ret

0x004030c8:	addl %esp, $0xc<UINT8>
0x004030cb:	leal %edx, 0x8(%esp)
0x004030cf:	leal %eax, 0x10(%esp)
0x004030d3:	pushl %edx
0x004030d4:	pushl %eax
0x004030d5:	pushl $0x80000001<UINT32>
0x004030da:	call RegCreateKeyA@ADVAPI32.dll
RegCreateKeyA@ADVAPI32.dll: API Node	
0x004030e0:	testl %eax, %eax
0x004030e2:	jne 36
0x004030e4:	movl %eax, 0x8(%esp)
0x004030e8:	leal %ecx, 0xc(%esp)
0x004030ec:	leal %edx, 0x4(%esp)
0x004030f0:	pushl %ecx
0x004030f1:	pushl %edx
0x004030f2:	pushl %ebx
0x004030f3:	pushl %ebx
0x004030f4:	pushl $0x4269e0<UINT32>
0x004030f9:	pushl %eax
0x004030fa:	movl 0x24(%esp), $0x4<UINT32>
0x00403102:	call RegQueryValueExA@ADVAPI32.dll
RegQueryValueExA@ADVAPI32.dll: API Node	
0x00403108:	cmpl 0x4(%esp), %ebx
0x0040310c:	jne 511
0x00403112:	pushl %esi
0x00403113:	pushl %edi
0x00403114:	pushl $0x3e8<UINT32>
0x00403119:	pushl $0x40<UINT8>
0x0040311b:	call LocalAlloc@KERNEL32.DLL
LocalAlloc@KERNEL32.DLL: API Node	
0x00403121:	movl %esi, %eax
0x00403123:	pushl $0x4269d0<UINT32>
0x00403128:	leal %edi, 0x12(%esi)
0x0040312b:	call LoadLibraryA@KERNEL32.DLL
0x00403131:	movl (%esi), $0x80c808d0<UINT32>
0x00407828:	pushl %ebp
0x00407829:	movl %ebp, %esp
0x0040782b:	subl %esp, $0x8<UINT8>
0x0040782e:	pushl %ebx
0x0040782f:	pushl %esi
0x00407830:	pushl %edi
0x00407831:	pushl %ebp
0x00407832:	cld
0x00407833:	movl %ebx, 0xc(%ebp)
0x00407836:	movl %eax, 0x8(%ebp)
0x00407839:	testl 0x4(%eax), $0x6<UINT32>
0x00407840:	jne 130
0x00407846:	movl -8(%ebp), %eax
0x00407849:	movl %eax, 0x10(%ebp)
0x0040784c:	movl -4(%ebp), %eax
0x0040784f:	leal %eax, -8(%ebp)
0x00407852:	movl -4(%ebx), %eax
0x00407855:	movl %esi, 0xc(%ebx)
0x00407858:	movl %edi, 0x8(%ebx)
0x0040785b:	cmpl %esi, $0xffffffff<UINT8>
0x0040785e:	je 97
0x00407860:	leal %ecx, (%esi,%esi,2)
0x00407863:	cmpl 0x4(%edi,%ecx,4), $0x0<UINT8>
0x00407868:	je 69
0x0040786a:	pushl %esi
0x0040786b:	pushl %ebp
0x0040786c:	leal %ebp, 0x10(%ebx)
0x0040786f:	call 0x00403e27
0x00403e27:	movl %eax, -20(%ebp)
0x00403e2a:	movl %ecx, (%eax)
0x00403e2c:	movl %ecx, (%ecx)
0x00403e2e:	movl -104(%ebp), %ecx
0x00403e31:	pushl %eax
0x00403e32:	pushl %ecx
0x00403e33:	call 0x00406f4b
0x00406f4b:	pushl %ebp
0x00406f4c:	movl %ebp, %esp
0x00406f4e:	pushl %ebx
0x00406f4f:	pushl 0x8(%ebp)
0x00406f52:	call 0x0040708c
0x0040708c:	movl %edx, 0x4(%esp)
0x00407090:	movl %ecx, 0x426d70
0x00407096:	cmpl 0x426cf0, %edx
0x0040709c:	pushl %esi
0x0040709d:	movl %eax, $0x426cf0<UINT32>
0x004070a2:	je 0x004070b9
0x004070b9:	leal %ecx, (%ecx,%ecx,2)
0x004070bc:	popl %esi
0x004070bd:	leal %ecx, 0x426cf0(,%ecx,4)
0x004070c4:	cmpl %eax, %ecx
0x004070c6:	jae 4
0x004070c8:	cmpl (%eax), %edx
0x004070ca:	je 0x004070ce
0x004070ce:	ret

0x00406f57:	testl %eax, %eax
0x00406f59:	popl %ecx
0x00406f5a:	je 288
0x00406f60:	movl %ebx, 0x8(%eax)
0x00406f63:	testl %ebx, %ebx
0x00406f65:	je 0x00407080
0x00407080:	pushl 0xc(%ebp)
0x00407083:	call UnhandledExceptionFilter@KERNEL32.DLL
UnhandledExceptionFilter@KERNEL32.DLL: API Node	
0x00407089:	popl %ebx
0x0040708a:	popl %ebp
0x0040708b:	ret

0x00403e38:	popl %ecx
0x00403e39:	popl %ecx
0x00403e3a:	ret

0x00407873:	popl %ebp
0x00407874:	popl %esi
0x00407875:	movl %ebx, 0xc(%ebp)
0x00407878:	orl %eax, %eax
0x0040787a:	je 51
0x0040787c:	js 60
0x0040787e:	movl %edi, 0x8(%ebx)
0x00407881:	pushl %ebx
0x00407882:	call 0x00407730
0x00407730:	pushl %ebp
0x00407731:	movl %ebp, %esp
0x00407733:	pushl %ebx
0x00407734:	pushl %esi
0x00407735:	pushl %edi
0x00407736:	pushl %ebp
0x00407737:	pushl $0x0<UINT8>
0x00407739:	pushl $0x0<UINT8>
0x0040773b:	pushl $0x407748<UINT32>
0x00407740:	pushl 0x8(%ebp)
0x00407743:	call 0x00409c34
0x00409c34:	jmp RtlUnwind@KERNEL32.DLL
RtlUnwind@KERNEL32.DLL: API Node	
0x00407748:	popl %ebp
0x00407749:	popl %edi
0x0040774a:	popl %esi
0x0040774b:	popl %ebx
0x0040774c:	movl %esp, %ebp
0x0040774e:	popl %ebp
0x0040774f:	ret

0x00407887:	addl %esp, $0x4<UINT8>
0x0040788a:	leal %ebp, 0x10(%ebx)
0x0040788d:	pushl %esi
0x0040788e:	pushl %ebx
0x0040788f:	call 0x00407772
0x00407772:	pushl %ebx
0x00407773:	pushl %esi
0x00407774:	pushl %edi
0x00407775:	movl %eax, 0x10(%esp)
0x00407779:	pushl %eax
0x0040777a:	pushl $0xfffffffe<UINT8>
0x0040777c:	pushl $0x407750<UINT32>
0x00407781:	pushl %fs:0
0x00407788:	movl %fs:0, %esp
0x0040778f:	movl %eax, 0x20(%esp)
0x00407793:	movl %ebx, 0x8(%eax)
0x00407796:	movl %esi, 0xc(%eax)
0x00407799:	cmpl %esi, $0xffffffff<UINT8>
0x0040779c:	je 46
0x0040779e:	cmpl %esi, 0x24(%esp)
0x004077a2:	je 0x004077cc
0x004077cc:	popl %fs:0
0x004077d3:	addl %esp, $0xc<UINT8>
0x004077d6:	popl %edi
0x004077d7:	popl %esi
0x004077d8:	popl %ebx
0x004077d9:	ret

0x00407894:	addl %esp, $0x8<UINT8>
0x00407897:	leal %ecx, (%esi,%esi,2)
0x0040789a:	pushl $0x1<UINT8>
0x0040789c:	movl %eax, 0x8(%edi,%ecx,4)
0x004078a0:	call 0x00407806
0x00407806:	pushl %ebx
0x00407807:	pushl %ecx
0x00407808:	movl %ebx, $0x426d80<UINT32>
0x0040780d:	movl %ecx, 0x8(%ebp)
0x00407810:	movl 0x8(%ebx), %ecx
0x00407813:	movl 0x4(%ebx), %eax
0x00407816:	movl 0xc(%ebx), %ebp
0x00407819:	popl %ecx
0x0040781a:	popl %ebx
0x0040781b:	ret $0x4<UINT16>

0x004078a5:	movl %eax, (%edi,%ecx,4)
0x004078a8:	movl 0xc(%ebx), %eax
0x004078ab:	call 0x00403e3b
0x00403e3b:	movl %esp, -24(%ebp)
0x00403e3e:	pushl -104(%ebp)
0x00403e41:	call 0x00406e69
0x00406e69:	pushl $0x0<UINT8>
0x00406e6b:	pushl $0x1<UINT8>
0x00406e6d:	pushl 0xc(%esp)
0x00406e71:	call 0x00406e98
0x00406e98:	pushl %edi
0x00406e99:	pushl $0x1<UINT8>
0x00406e9b:	popl %edi
0x00406e9c:	cmpl 0x427568, %edi
0x00406ea2:	jne 0x00406eb5
0x00406eb5:	cmpl 0xc(%esp), $0x0<UINT8>
0x00406eba:	pushl %ebx
0x00406ebb:	movl %ebx, 0x14(%esp)
0x00406ebf:	movl 0x427564, %edi
0x00406ec5:	movb 0x427560, %bl
0x00406ecb:	jne 0x00406f09
0x00406f09:	pushl $0x40c028<UINT32>
0x00406f0e:	pushl $0x40c024<UINT32>
0x00406f13:	call 0x00406f31
0x00406f18:	popl %ecx
0x00406f19:	popl %ecx
0x00406f1a:	testl %ebx, %ebx
0x00406f1c:	popl %ebx
0x00406f1d:	jne 16
0x00406f1f:	pushl 0x8(%esp)
0x00406f23:	movl 0x427568, %edi
0x00406f29:	call ExitProcess@KERNEL32.DLL
ExitProcess@KERNEL32.DLL: Exit Node	
