0x0046a000:	movl %ebx, $0x4001d0<UINT32>
0x0046a005:	movl %edi, $0x401000<UINT32>
0x0046a00a:	movl %esi, $0x45e6f8<UINT32>
0x0046a00f:	pushl %ebx
0x0046a010:	call 0x0046a01f
0x0046a01f:	cld
0x0046a020:	movb %dl, $0xffffff80<UINT8>
0x0046a022:	movsb %es:(%edi), %ds:(%esi)
0x0046a023:	pushl $0x2<UINT8>
0x0046a025:	popl %ebx
0x0046a026:	call 0x0046a015
0x0046a015:	addb %dl, %dl
0x0046a017:	jne 0x0046a01e
0x0046a019:	movb %dl, (%esi)
0x0046a01b:	incl %esi
0x0046a01c:	adcb %dl, %dl
0x0046a01e:	ret

0x0046a029:	jae 0x0046a022
0x0046a02b:	xorl %ecx, %ecx
0x0046a02d:	call 0x0046a015
0x0046a030:	jae 0x0046a04a
0x0046a032:	xorl %eax, %eax
0x0046a034:	call 0x0046a015
0x0046a037:	jae 0x0046a05a
0x0046a039:	movb %bl, $0x2<UINT8>
0x0046a03b:	incl %ecx
0x0046a03c:	movb %al, $0x10<UINT8>
0x0046a03e:	call 0x0046a015
0x0046a041:	adcb %al, %al
0x0046a043:	jae 0x0046a03e
0x0046a045:	jne 0x0046a086
0x0046a047:	stosb %es:(%edi), %al
0x0046a048:	jmp 0x0046a026
0x0046a05a:	lodsb %al, %ds:(%esi)
0x0046a05b:	shrl %eax
0x0046a05d:	je 0x0046a0a0
0x0046a05f:	adcl %ecx, %ecx
0x0046a061:	jmp 0x0046a07f
0x0046a07f:	incl %ecx
0x0046a080:	incl %ecx
0x0046a081:	xchgl %ebp, %eax
0x0046a082:	movl %eax, %ebp
0x0046a084:	movb %bl, $0x1<UINT8>
0x0046a086:	pushl %esi
0x0046a087:	movl %esi, %edi
0x0046a089:	subl %esi, %eax
0x0046a08b:	rep movsb %es:(%edi), %ds:(%esi)
0x0046a08d:	popl %esi
0x0046a08e:	jmp 0x0046a026
0x0046a04a:	call 0x0046a092
0x0046a092:	incl %ecx
0x0046a093:	call 0x0046a015
0x0046a097:	adcl %ecx, %ecx
0x0046a099:	call 0x0046a015
0x0046a09d:	jb 0x0046a093
0x0046a09f:	ret

0x0046a04f:	subl %ecx, %ebx
0x0046a051:	jne 0x0046a063
0x0046a053:	call 0x0046a090
0x0046a090:	xorl %ecx, %ecx
0x0046a058:	jmp 0x0046a082
0x0046a063:	xchgl %ecx, %eax
0x0046a064:	decl %eax
0x0046a065:	shll %eax, $0x8<UINT8>
0x0046a068:	lodsb %al, %ds:(%esi)
0x0046a069:	call 0x0046a090
0x0046a06e:	cmpl %eax, $0x7d00<UINT32>
0x0046a073:	jae 0x0046a07f
0x0046a075:	cmpb %ah, $0x5<UINT8>
0x0046a078:	jae 0x0046a080
0x0046a07a:	cmpl %eax, $0x7f<UINT8>
0x0046a07d:	ja 0x0046a081
0x0046a0a0:	popl %edi
0x0046a0a1:	popl %ebx
0x0046a0a2:	movzwl %edi, (%ebx)
0x0046a0a5:	decl %edi
0x0046a0a6:	je 0x0046a0b0
0x0046a0a8:	decl %edi
0x0046a0a9:	je 0x0046a0be
0x0046a0ab:	shll %edi, $0xc<UINT8>
0x0046a0ae:	jmp 0x0046a0b7
0x0046a0b7:	incl %ebx
0x0046a0b8:	incl %ebx
0x0046a0b9:	jmp 0x0046a00f
0x0046a0b0:	movl %edi, 0x2(%ebx)
0x0046a0b3:	pushl %edi
0x0046a0b4:	addl %ebx, $0x4<UINT8>
0x0046a0be:	popl %edi
0x0046a0bf:	movl %ebx, $0x46a128<UINT32>
0x0046a0c4:	incl %edi
0x0046a0c5:	movl %esi, (%edi)
0x0046a0c7:	scasl %eax, %es:(%edi)
0x0046a0c8:	pushl %edi
0x0046a0c9:	call LoadLibraryA@KERNEL32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0046a0cb:	xchgl %ebp, %eax
0x0046a0cc:	xorl %eax, %eax
0x0046a0ce:	scasb %al, %es:(%edi)
0x0046a0cf:	jne 0x0046a0ce
0x0046a0d1:	decb (%edi)
0x0046a0d3:	je 0x0046a0c4
0x0046a0d5:	decb (%edi)
0x0046a0d7:	jne 0x0046a0df
0x0046a0df:	decb (%edi)
0x0046a0e1:	je 0x00403d50
0x0046a0e7:	pushl %edi
0x0046a0e8:	pushl %ebp
0x0046a0e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x0046a0ec:	orl (%esi), %eax
0x0046a0ee:	lodsl %eax, %ds:(%esi)
0x0046a0ef:	jne 0x0046a0cc
GetProcAddress@KERNEL32.dll: API Node	
LoadLibraryA@KERNEL32.dll: API Node	
0x0046a0d9:	incl %edi
0x0046a0da:	pushl (%edi)
0x0046a0dc:	scasl %eax, %es:(%edi)
0x0046a0dd:	jmp 0x0046a0e8
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
0x00403d76:	call GetVersion@KERNEL32.dll
GetVersion@KERNEL32.dll: API Node	
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
0x004051fb:	call HeapCreate@KERNEL32.dll
HeapCreate@KERNEL32.dll: API Node	
0x00405201:	testl %eax, %eax
0x00405203:	movl 0x44a4d0, %eax
0x00405208:	je 21
0x0040520a:	call 0x004052b8
0x004052b8:	pushl $0x140<UINT32>
0x004052bd:	pushl $0x0<UINT8>
0x004052bf:	pushl 0x44a4d0
0x004052c5:	call HeapAlloc@KERNEL32.dll
HeapAlloc@KERNEL32.dll: API Node	
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
0x004056c6:	jne 121
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
0x004059b1:	call HeapAlloc@KERNEL32.dll
0x004059b7:	cmpl %eax, %edi
0x004059b9:	movl 0x10(%esi), %eax
0x004059bc:	je 42
0x004059be:	pushl $0x4<UINT8>
0x004059c0:	pushl $0x2000<UINT32>
0x004059c5:	pushl $0x100000<UINT32>
0x004059ca:	pushl %edi
0x004059cb:	call VirtualAlloc@KERNEL32.dll
VirtualAlloc@KERNEL32.dll: API Node	
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
0x00405a57:	call VirtualAlloc@KERNEL32.dll
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
0x0040592c:	jne 26
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
0x004075b8:	call GetStartupInfoA@KERNEL32.dll
GetStartupInfoA@KERNEL32.dll: API Node	
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
0x004076b7:	call GetStdHandle@KERNEL32.dll
GetStdHandle@KERNEL32.dll: API Node	
0x004076bd:	movl %edi, %eax
0x004076bf:	cmpl %edi, $0xffffffff<UINT8>
0x004076c2:	je 23
0x004076c4:	pushl %edi
0x004076c5:	call GetFileType@KERNEL32.dll
GetFileType@KERNEL32.dll: API Node	
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
0x004076fc:	call SetHandleCount@KERNEL32.dll
SetHandleCount@KERNEL32.dll: API Node	
0x00407702:	popl %edi
0x00407703:	popl %esi
0x00407704:	popl %ebp
0x00407705:	popl %ebx
0x00407706:	addl %esp, $0x44<UINT8>
0x00407709:	ret

0x00403dc4:	call GetCommandLineA@KERNEL32.dll
GetCommandLineA@KERNEL32.dll: API Node	
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
0x00407448:	call GetEnvironmentStringsW@KERNEL32.dll
GetEnvironmentStringsW@KERNEL32.dll: API Node	
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
0x004074c0:	call WideCharToMultiByte@KERNEL32.dll
WideCharToMultiByte@KERNEL32.dll: API Node	
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
0x00403c1a:	call HeapAlloc@KERNEL32.dll
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
0x004074e2:	call WideCharToMultiByte@KERNEL32.dll
0x004074e4:	testl %eax, %eax
0x004074e6:	jne 0x004074f6
0x004074f6:	movl %ebx, 0x10(%esp)
0x004074fa:	pushl %esi
0x004074fb:	call FreeEnvironmentStringsW@KERNEL32.dll
FreeEnvironmentStringsW@KERNEL32.dll: API Node	
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
0x004091af:	jne 18
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
0x00408f9c:	jmp GetACP@KERNEL32.dll
GetACP@KERNEL32.dll: API Node	
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
0x00408e1c:	call GetCPInfo@KERNEL32.dll
GetCPInfo@KERNEL32.dll: API Node	
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
0x00409027:	call GetCPInfo@KERNEL32.dll
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
0x004097d2:	call GetStringTypeW@KERNEL32.dll
GetStringTypeW@KERNEL32.dll: API Node	
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
0x00409858:	call MultiByteToWideChar@KERNEL32.dll
MultiByteToWideChar@KERNEL32.dll: API Node	
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
