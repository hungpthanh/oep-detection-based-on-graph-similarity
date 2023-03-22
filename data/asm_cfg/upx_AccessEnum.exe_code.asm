0x0042b6e0:	pusha
0x0042b6e1:	movl %esi, $0x422000<UINT32>
0x0042b6e6:	leal %edi, -135168(%esi)
0x0042b6ec:	pushl %edi
0x0042b6ed:	jmp 0x0042b6fa
0x0042b6fa:	movl %ebx, (%esi)
0x0042b6fc:	subl %esi, $0xfffffffc<UINT8>
0x0042b6ff:	adcl %ebx, %ebx
0x0042b701:	jb 0x0042b6f0
0x0042b6f0:	movb %al, (%esi)
0x0042b6f2:	incl %esi
0x0042b6f3:	movb (%edi), %al
0x0042b6f5:	incl %edi
0x0042b6f6:	addl %ebx, %ebx
0x0042b6f8:	jne 0x0042b701
0x0042b703:	movl %eax, $0x1<UINT32>
0x0042b708:	addl %ebx, %ebx
0x0042b70a:	jne 0x0042b713
0x0042b713:	adcl %eax, %eax
0x0042b715:	addl %ebx, %ebx
0x0042b717:	jae 0x0042b708
0x0042b719:	jne 0x0042b724
0x0042b724:	xorl %ecx, %ecx
0x0042b726:	subl %eax, $0x3<UINT8>
0x0042b729:	jb 0x0042b738
0x0042b72b:	shll %eax, $0x8<UINT8>
0x0042b72e:	movb %al, (%esi)
0x0042b730:	incl %esi
0x0042b731:	xorl %eax, $0xffffffff<UINT8>
0x0042b734:	je 0x0042b7aa
0x0042b736:	movl %ebp, %eax
0x0042b738:	addl %ebx, %ebx
0x0042b73a:	jne 0x0042b743
0x0042b743:	adcl %ecx, %ecx
0x0042b745:	addl %ebx, %ebx
0x0042b747:	jne 0x0042b750
0x0042b750:	adcl %ecx, %ecx
0x0042b752:	jne 0x0042b774
0x0042b774:	cmpl %ebp, $0xfffff300<UINT32>
0x0042b77a:	adcl %ecx, $0x1<UINT8>
0x0042b77d:	leal %edx, (%edi,%ebp)
0x0042b780:	cmpl %ebp, $0xfffffffc<UINT8>
0x0042b783:	jbe 0x0042b794
0x0042b794:	movl %eax, (%edx)
0x0042b796:	addl %edx, $0x4<UINT8>
0x0042b799:	movl (%edi), %eax
0x0042b79b:	addl %edi, $0x4<UINT8>
0x0042b79e:	subl %ecx, $0x4<UINT8>
0x0042b7a1:	ja 0x0042b794
0x0042b7a3:	addl %edi, %ecx
0x0042b7a5:	jmp 0x0042b6f6
0x0042b749:	movl %ebx, (%esi)
0x0042b74b:	subl %esi, $0xfffffffc<UINT8>
0x0042b74e:	adcl %ebx, %ebx
0x0042b754:	incl %ecx
0x0042b755:	addl %ebx, %ebx
0x0042b757:	jne 0x0042b760
0x0042b760:	adcl %ecx, %ecx
0x0042b762:	addl %ebx, %ebx
0x0042b764:	jae 0x0042b755
0x0042b766:	jne 0x0042b771
0x0042b771:	addl %ecx, $0x2<UINT8>
0x0042b785:	movb %al, (%edx)
0x0042b787:	incl %edx
0x0042b788:	movb (%edi), %al
0x0042b78a:	incl %edi
0x0042b78b:	decl %ecx
0x0042b78c:	jne 0x0042b785
0x0042b78e:	jmp 0x0042b6f6
0x0042b70c:	movl %ebx, (%esi)
0x0042b70e:	subl %esi, $0xfffffffc<UINT8>
0x0042b711:	adcl %ebx, %ebx
0x0042b73c:	movl %ebx, (%esi)
0x0042b73e:	subl %esi, $0xfffffffc<UINT8>
0x0042b741:	adcl %ebx, %ebx
0x0042b759:	movl %ebx, (%esi)
0x0042b75b:	subl %esi, $0xfffffffc<UINT8>
0x0042b75e:	adcl %ebx, %ebx
0x0042b71b:	movl %ebx, (%esi)
0x0042b71d:	subl %esi, $0xfffffffc<UINT8>
0x0042b720:	adcl %ebx, %ebx
0x0042b722:	jae 0x0042b708
0x0042b768:	movl %ebx, (%esi)
0x0042b76a:	subl %esi, $0xfffffffc<UINT8>
0x0042b76d:	adcl %ebx, %ebx
0x0042b76f:	jae 0x0042b755
0x0042b7aa:	popl %esi
0x0042b7ab:	movl %edi, %esi
0x0042b7ad:	movl %ecx, $0x1bf<UINT32>
0x0042b7b2:	movb %al, (%edi)
0x0042b7b4:	incl %edi
0x0042b7b5:	subb %al, $0xffffffe8<UINT8>
0x0042b7b7:	cmpb %al, $0x1<UINT8>
0x0042b7b9:	ja 0x0042b7b2
0x0042b7bb:	cmpb (%edi), $0x1<UINT8>
0x0042b7be:	jne 0x0042b7b2
0x0042b7c0:	movl %eax, (%edi)
0x0042b7c2:	movb %bl, 0x4(%edi)
0x0042b7c5:	shrw %ax, $0x8<UINT8>
0x0042b7c9:	roll %eax, $0x10<UINT8>
0x0042b7cc:	xchgb %ah, %al
0x0042b7ce:	subl %eax, %edi
0x0042b7d0:	subb %bl, $0xffffffe8<UINT8>
0x0042b7d3:	addl %eax, %esi
0x0042b7d5:	movl (%edi), %eax
0x0042b7d7:	addl %edi, $0x5<UINT8>
0x0042b7da:	movb %al, %bl
0x0042b7dc:	loop 0x0042b7b7
0x0042b7de:	leal %edi, 0x29000(%esi)
0x0042b7e4:	movl %eax, (%edi)
0x0042b7e6:	orl %eax, %eax
0x0042b7e8:	je 0x0042b82f
0x0042b7ea:	movl %ebx, 0x4(%edi)
0x0042b7ed:	leal %eax, 0x2c63c(%eax,%esi)
0x0042b7f4:	addl %ebx, %esi
0x0042b7f6:	pushl %eax
0x0042b7f7:	addl %edi, $0x8<UINT8>
0x0042b7fa:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0042b800:	xchgl %ebp, %eax
0x0042b801:	movb %al, (%edi)
0x0042b803:	incl %edi
0x0042b804:	orb %al, %al
0x0042b806:	je 0x0042b7e4
0x0042b808:	movl %ecx, %edi
0x0042b80a:	jns 0x0042b813
0x0042b813:	pushl %edi
0x0042b814:	decl %eax
0x0042b815:	repn scasb %al, %es:(%edi)
0x0042b817:	pushl %ebp
0x0042b818:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0042b81e:	orl %eax, %eax
0x0042b820:	je 7
0x0042b822:	movl (%ebx), %eax
0x0042b824:	addl %ebx, $0x4<UINT8>
0x0042b827:	jmp 0x0042b801
GetProcAddress@KERNEL32.DLL: API Node	
0x0042b80c:	movzwl %eax, (%edi)
0x0042b80f:	incl %edi
0x0042b810:	pushl %eax
0x0042b811:	incl %edi
0x0042b812:	movl %ecx, $0xaef24857<UINT32>
0x0042b82f:	movl %ebp, 0x2c76c(%esi)
0x0042b835:	leal %edi, -4096(%esi)
0x0042b83b:	movl %ebx, $0x1000<UINT32>
0x0042b840:	pushl %eax
0x0042b841:	pushl %esp
0x0042b842:	pushl $0x4<UINT8>
0x0042b844:	pushl %ebx
0x0042b845:	pushl %edi
0x0042b846:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0042b848:	leal %eax, 0x217(%edi)
0x0042b84e:	andb (%eax), $0x7f<UINT8>
0x0042b851:	andb 0x28(%eax), $0x7f<UINT8>
0x0042b855:	popl %eax
0x0042b856:	pushl %eax
0x0042b857:	pushl %esp
0x0042b858:	pushl %eax
0x0042b859:	pushl %ebx
0x0042b85a:	pushl %edi
0x0042b85b:	call VirtualProtect@kernel32.dll
0x0042b85d:	popl %eax
0x0042b85e:	popa
0x0042b85f:	leal %eax, -128(%esp)
0x0042b863:	pushl $0x0<UINT8>
0x0042b865:	cmpl %esp, %eax
0x0042b867:	jne 0x0042b863
0x0042b869:	subl %esp, $0xffffff80<UINT8>
0x0042b86c:	jmp 0x00407a98
0x00407a98:	pushl %ebp
0x00407a99:	movl %ebp, %esp
0x00407a9b:	pushl $0xffffffff<UINT8>
0x00407a9d:	pushl $0x409190<UINT32>
0x00407aa2:	pushl $0x407a3e<UINT32>
0x00407aa7:	movl %eax, %fs:0
0x00407aad:	pushl %eax
0x00407aae:	movl %fs:0, %esp
0x00407ab5:	subl %esp, $0x68<UINT8>
0x00407ab8:	pushl %ebx
0x00407ab9:	pushl %esi
0x00407aba:	pushl %edi
0x00407abb:	movl -24(%ebp), %esp
0x00407abe:	xorl %ebx, %ebx
0x00407ac0:	movl -4(%ebp), %ebx
0x00407ac3:	pushl $0x2<UINT8>
0x00407ac5:	call __set_app_type@MSVCRT.dll
__set_app_type@MSVCRT.dll: API Node	
0x00407acb:	popl %ecx
0x00407acc:	orl 0x426a2c, $0xffffffff<UINT8>
0x00407ad3:	orl 0x426a30, $0xffffffff<UINT8>
0x00407ada:	call __p__fmode@MSVCRT.dll
__p__fmode@MSVCRT.dll: API Node	
0x00407ae0:	movl %ecx, 0x426a24
0x00407ae6:	movl (%eax), %ecx
0x00407ae8:	call __p__commode@MSVCRT.dll
__p__commode@MSVCRT.dll: API Node	
0x00407aee:	movl %ecx, 0x426a20
0x00407af4:	movl (%eax), %ecx
0x00407af6:	movl %eax, 0x408164
0x00407afb:	movl %eax, (%eax)
0x00407afd:	movl 0x426a28, %eax
0x00407b02:	call 0x00407c67
0x00407c67:	ret

0x00407b07:	cmpl 0x425d88, %ebx
0x00407b0d:	jne 0x00407b1b
0x00407b1b:	call 0x00407c4c
0x00407c4c:	pushl $0x30000<UINT32>
0x00407c51:	pushl $0x10000<UINT32>
0x00407c56:	call 0x00407c80
0x00407c80:	jmp _controlfp@MSVCRT.dll
_controlfp@MSVCRT.dll: API Node	
0x00407c5b:	popl %ecx
0x00407c5c:	popl %ecx
0x00407c5d:	ret

0x00407b20:	pushl $0x40b010<UINT32>
0x00407b25:	pushl $0x40b00c<UINT32>
0x00407b2a:	call 0x00407c46
0x00407c46:	jmp _initterm@MSVCRT.dll
_initterm@MSVCRT.dll: API Node	
0x00407b2f:	movl %eax, 0x426a1c
0x00407b34:	movl -108(%ebp), %eax
0x00407b37:	leal %eax, -108(%ebp)
0x00407b3a:	pushl %eax
0x00407b3b:	pushl 0x426a18
0x00407b41:	leal %eax, -100(%ebp)
0x00407b44:	pushl %eax
0x00407b45:	leal %eax, -112(%ebp)
0x00407b48:	pushl %eax
0x00407b49:	leal %eax, -96(%ebp)
0x00407b4c:	pushl %eax
0x00407b4d:	call __getmainargs@MSVCRT.dll
__getmainargs@MSVCRT.dll: API Node	
0x00407b53:	pushl $0x40b008<UINT32>
0x00407b58:	pushl $0x40b000<UINT32>
0x00407b5d:	call 0x00407c46
0x00407b62:	addl %esp, $0x24<UINT8>
0x00407b65:	movl %eax, 0x408174
0x00407b6a:	movl %esi, (%eax)
0x00407b6c:	movl -116(%ebp), %esi
0x00407b6f:	cmpb (%esi), $0x22<UINT8>
0x00407b72:	jne 58
0x00407b74:	incl %esi
0x00407b75:	movl -116(%ebp), %esi
0x00407b78:	movb %al, (%esi)
0x00407b7a:	cmpb %al, %bl
0x00407b7c:	je 4
0x00407b7e:	cmpb %al, $0x22<UINT8>
0x00407b80:	jne 0x00407b74
0x00407b82:	cmpb (%esi), $0x22<UINT8>
0x00407b85:	jne 4
0x00407b87:	incl %esi
0x00407b88:	movl -116(%ebp), %esi
0x00407b8b:	movb %al, (%esi)
0x00407b8d:	cmpb %al, %bl
0x00407b8f:	je 4
0x00407b91:	cmpb %al, $0x20<UINT8>
0x00407b93:	jbe 0x00407b87
0x00407b95:	movl -48(%ebp), %ebx
0x00407b98:	leal %eax, -92(%ebp)
0x00407b9b:	pushl %eax
0x00407b9c:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x00407ba2:	testb -48(%ebp), $0x1<UINT8>
0x00407ba6:	je 0x00407bb9
0x00407bb9:	pushl $0xa<UINT8>
0x00407bbb:	popl %eax
0x00407bbc:	pushl %eax
0x00407bbd:	pushl %esi
0x00407bbe:	pushl %ebx
0x00407bbf:	pushl %ebx
0x00407bc0:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x00407bc6:	pushl %eax
0x00407bc7:	call 0x00403f99
0x00403f99:	pushl %ebp
0x00403f9a:	movl %ebp, %esp
0x00403f9c:	subl %esp, $0x4c<UINT8>
0x00403f9f:	pushl %ebx
0x00403fa0:	pushl %esi
0x00403fa1:	pushl %edi
0x00403fa2:	pushl $0x40b34c<UINT32>
0x00403fa7:	call 0x00406899
0x00406899:	pushl %ebp
0x0040689a:	movl %ebp, %esp
0x0040689c:	subl %esp, $0x214<UINT32>
0x004068a2:	pushl %ebx
0x004068a3:	leal %eax, -532(%ebp)
0x004068a9:	pushl 0x8(%ebp)
0x004068ac:	xorl %ebx, %ebx
0x004068ae:	movl -8(%ebp), %ebx
0x004068b1:	movl -4(%ebp), %ebx
0x004068b4:	pushl $0x425c94<UINT32>
0x004068b9:	pushl %eax
0x004068ba:	call swprintf@MSVCRT.dll
swprintf@MSVCRT.dll: API Node	
0x004068c0:	addl %esp, $0xc<UINT8>
0x004068c3:	leal %eax, -8(%ebp)
0x004068c6:	pushl %eax
0x004068c7:	leal %eax, -532(%ebp)
0x004068cd:	pushl %eax
0x004068ce:	pushl $0x80000001<UINT32>
0x004068d3:	call RegCreateKeyW@ADVAPI32.dll
RegCreateKeyW@ADVAPI32.dll: API Node	
0x004068d9:	testl %eax, %eax
0x004068db:	jne 31
0x004068dd:	leal %eax, -12(%ebp)
0x004068e0:	movl -12(%ebp), $0x4<UINT32>
0x004068e7:	pushl %eax
0x004068e8:	leal %eax, -4(%ebp)
0x004068eb:	pushl %eax
0x004068ec:	pushl %ebx
0x004068ed:	pushl %ebx
0x004068ee:	pushl $0x425c78<UINT32>
0x004068f3:	pushl -8(%ebp)
0x004068f6:	call RegQueryValueExW@ADVAPI32.dll
RegQueryValueExW@ADVAPI32.dll: API Node	
0x004068fc:	cmpl -4(%ebp), %ebx
0x004068ff:	jne 481
0x00406905:	pushl %esi
0x00406906:	pushl %edi
0x00406907:	pushl $0x3e8<UINT32>
0x0040690c:	pushl $0x40<UINT8>
0x0040690e:	call LocalAlloc@KERNEL32.DLL
LocalAlloc@KERNEL32.DLL: API Node	
0x00406914:	movl %esi, %eax
0x00406916:	pushl $0x425c5c<UINT32>
0x0040691b:	leal %edi, 0x12(%esi)
0x0040691e:	call LoadLibraryW@KERNEL32.DLL
LoadLibraryW@KERNEL32.DLL: API Node	
0x00406924:	movl (%esi), $0x80c808d0<UINT32>
0x00407a3e:	jmp _except_handler3@MSVCRT.dll
_except_handler3@MSVCRT.dll: API Node	
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
0x7c90330e:	addb (%eax), %al
