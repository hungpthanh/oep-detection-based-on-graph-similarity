0x0042e000:	movl %ebx, $0x4001d0<UINT32>
0x0042e005:	movl %edi, $0x401000<UINT32>
0x0042e00a:	movl %esi, $0x421443<UINT32>
0x0042e00f:	pushl %ebx
0x0042e010:	call 0x0042e01f
0x0042e01f:	cld
0x0042e020:	movb %dl, $0xffffff80<UINT8>
0x0042e022:	movsb %es:(%edi), %ds:(%esi)
0x0042e023:	pushl $0x2<UINT8>
0x0042e025:	popl %ebx
0x0042e026:	call 0x0042e015
0x0042e015:	addb %dl, %dl
0x0042e017:	jne 0x0042e01e
0x0042e019:	movb %dl, (%esi)
0x0042e01b:	incl %esi
0x0042e01c:	adcb %dl, %dl
0x0042e01e:	ret

0x0042e029:	jae 0x0042e022
0x0042e02b:	xorl %ecx, %ecx
0x0042e02d:	call 0x0042e015
0x0042e030:	jae 0x0042e04a
0x0042e032:	xorl %eax, %eax
0x0042e034:	call 0x0042e015
0x0042e037:	jae 0x0042e05a
0x0042e039:	movb %bl, $0x2<UINT8>
0x0042e03b:	incl %ecx
0x0042e03c:	movb %al, $0x10<UINT8>
0x0042e03e:	call 0x0042e015
0x0042e041:	adcb %al, %al
0x0042e043:	jae 0x0042e03e
0x0042e045:	jne 0x0042e086
0x0042e086:	pushl %esi
0x0042e087:	movl %esi, %edi
0x0042e089:	subl %esi, %eax
0x0042e08b:	rep movsb %es:(%edi), %ds:(%esi)
0x0042e08d:	popl %esi
0x0042e08e:	jmp 0x0042e026
0x0042e047:	stosb %es:(%edi), %al
0x0042e048:	jmp 0x0042e026
0x0042e05a:	lodsb %al, %ds:(%esi)
0x0042e05b:	shrl %eax
0x0042e05d:	je 0x0042e0a0
0x0042e05f:	adcl %ecx, %ecx
0x0042e061:	jmp 0x0042e07f
0x0042e07f:	incl %ecx
0x0042e080:	incl %ecx
0x0042e081:	xchgl %ebp, %eax
0x0042e082:	movl %eax, %ebp
0x0042e084:	movb %bl, $0x1<UINT8>
0x0042e04a:	call 0x0042e092
0x0042e092:	incl %ecx
0x0042e093:	call 0x0042e015
0x0042e097:	adcl %ecx, %ecx
0x0042e099:	call 0x0042e015
0x0042e09d:	jb 0x0042e093
0x0042e09f:	ret

0x0042e04f:	subl %ecx, %ebx
0x0042e051:	jne 0x0042e063
0x0042e053:	call 0x0042e090
0x0042e090:	xorl %ecx, %ecx
0x0042e058:	jmp 0x0042e082
0x0042e063:	xchgl %ecx, %eax
0x0042e064:	decl %eax
0x0042e065:	shll %eax, $0x8<UINT8>
0x0042e068:	lodsb %al, %ds:(%esi)
0x0042e069:	call 0x0042e090
0x0042e06e:	cmpl %eax, $0x7d00<UINT32>
0x0042e073:	jae 0x0042e07f
0x0042e075:	cmpb %ah, $0x5<UINT8>
0x0042e078:	jae 0x0042e080
0x0042e07a:	cmpl %eax, $0x7f<UINT8>
0x0042e07d:	ja 0x0042e081
0x0042e0a0:	popl %edi
0x0042e0a1:	popl %ebx
0x0042e0a2:	movzwl %edi, (%ebx)
0x0042e0a5:	decl %edi
0x0042e0a6:	je 0x0042e0b0
0x0042e0a8:	decl %edi
0x0042e0a9:	je 0x0042e0be
0x0042e0ab:	shll %edi, $0xc<UINT8>
0x0042e0ae:	jmp 0x0042e0b7
0x0042e0b7:	incl %ebx
0x0042e0b8:	incl %ebx
0x0042e0b9:	jmp 0x0042e00f
0x0042e0b0:	movl %edi, 0x2(%ebx)
0x0042e0b3:	pushl %edi
0x0042e0b4:	addl %ebx, $0x4<UINT8>
0x0042e0be:	popl %edi
0x0042e0bf:	movl %ebx, $0x42e128<UINT32>
0x0042e0c4:	incl %edi
0x0042e0c5:	movl %esi, (%edi)
0x0042e0c7:	scasl %eax, %es:(%edi)
0x0042e0c8:	pushl %edi
0x0042e0c9:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0042e0cb:	xchgl %ebp, %eax
0x0042e0cc:	xorl %eax, %eax
0x0042e0ce:	scasb %al, %es:(%edi)
0x0042e0cf:	jne 0x0042e0ce
0x0042e0d1:	decb (%edi)
0x0042e0d3:	je 0x0042e0c4
0x0042e0d5:	decb (%edi)
0x0042e0d7:	jne 0x0042e0df
0x0042e0df:	decb (%edi)
0x0042e0e1:	je 0x00403980
0x0042e0e7:	pushl %edi
0x0042e0e8:	pushl %ebp
0x0042e0e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x0042e0ec:	orl (%esi), %eax
0x0042e0ee:	lodsl %eax, %ds:(%esi)
0x0042e0ef:	jne 0x0042e0cc
GetProcAddress@KERNEL32.dll: API Node	
0x00403980:	call 0x00408490
0x00408490:	pushl %ebp
0x00408491:	movl %ebp, %esp
0x00408493:	subl %esp, $0x14<UINT8>
0x00408496:	andl -12(%ebp), $0x0<UINT8>
0x0040849a:	andl -8(%ebp), $0x0<UINT8>
0x0040849e:	movl %eax, 0x41c200
0x004084a3:	pushl %esi
0x004084a4:	pushl %edi
0x004084a5:	movl %edi, $0xbb40e64e<UINT32>
0x004084aa:	movl %esi, $0xffff0000<UINT32>
0x004084af:	cmpl %eax, %edi
0x004084b1:	je 0x004084c0
0x004084c0:	leal %eax, -12(%ebp)
0x004084c3:	pushl %eax
0x004084c4:	call GetSystemTimeAsFileTime@KERNEL32.dll
GetSystemTimeAsFileTime@KERNEL32.dll: API Node	
0x004084ca:	movl %eax, -8(%ebp)
0x004084cd:	xorl %eax, -12(%ebp)
0x004084d0:	movl -4(%ebp), %eax
0x004084d3:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x004084d9:	xorl -4(%ebp), %eax
0x004084dc:	call GetCurrentProcessId@KERNEL32.dll
GetCurrentProcessId@KERNEL32.dll: API Node	
0x004084e2:	xorl -4(%ebp), %eax
0x004084e5:	leal %eax, -20(%ebp)
0x004084e8:	pushl %eax
0x004084e9:	call QueryPerformanceCounter@KERNEL32.dll
QueryPerformanceCounter@KERNEL32.dll: API Node	
0x004084ef:	movl %ecx, -16(%ebp)
0x004084f2:	leal %eax, -4(%ebp)
0x004084f5:	xorl %ecx, -20(%ebp)
0x004084f8:	xorl %ecx, -4(%ebp)
0x004084fb:	xorl %ecx, %eax
0x004084fd:	cmpl %ecx, %edi
0x004084ff:	jne 0x00408508
0x00408508:	testl %esi, %ecx
0x0040850a:	jne 0x00408518
0x00408518:	movl 0x41c200, %ecx
0x0040851e:	notl %ecx
0x00408520:	movl 0x41c204, %ecx
0x00408526:	popl %edi
0x00408527:	popl %esi
0x00408528:	movl %esp, %ebp
0x0040852a:	popl %ebp
0x0040852b:	ret

0x00403985:	jmp 0x0040398a
0x0040398a:	pushl $0x14<UINT8>
0x0040398c:	pushl $0x41ac00<UINT32>
0x00403991:	call 0x00405960
0x00405960:	pushl $0x4059c0<UINT32>
0x00405965:	pushl %fs:0
0x0040596c:	movl %eax, 0x10(%esp)
0x00405970:	movl 0x10(%esp), %ebp
0x00405974:	leal %ebp, 0x10(%esp)
0x00405978:	subl %esp, %eax
0x0040597a:	pushl %ebx
0x0040597b:	pushl %esi
0x0040597c:	pushl %edi
0x0040597d:	movl %eax, 0x41c200
0x00405982:	xorl -4(%ebp), %eax
0x00405985:	xorl %eax, %ebp
0x00405987:	pushl %eax
0x00405988:	movl -24(%ebp), %esp
0x0040598b:	pushl -8(%ebp)
0x0040598e:	movl %eax, -4(%ebp)
0x00405991:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00405998:	movl -8(%ebp), %eax
0x0040599b:	leal %eax, -16(%ebp)
0x0040599e:	movl %fs:0, %eax
0x004059a4:	ret

0x00403996:	call 0x00404dad
0x00404dad:	pushl %ebp
0x00404dae:	movl %ebp, %esp
0x00404db0:	subl %esp, $0x44<UINT8>
0x00404db3:	leal %eax, -68(%ebp)
0x00404db6:	pushl %eax
0x00404db7:	call GetStartupInfoW@KERNEL32.dll
GetStartupInfoW@KERNEL32.dll: API Node	
0x00404dbd:	testb -24(%ebp), $0x1<UINT8>
0x00404dc1:	je 0x00404dc9
0x00404dc9:	pushl $0xa<UINT8>
0x00404dcb:	popl %eax
0x00404dcc:	movl %esp, %ebp
0x00404dce:	popl %ebp
0x00404dcf:	ret

0x0040399b:	movzwl %esi, %ax
0x0040399e:	pushl $0x2<UINT8>
0x004039a0:	call 0x00408443
0x00408443:	pushl %ebp
0x00408444:	movl %ebp, %esp
0x00408446:	movl %eax, 0x8(%ebp)
0x00408449:	movl 0x41d498, %eax
0x0040844e:	popl %ebp
0x0040844f:	ret

0x004039a5:	popl %ecx
0x004039a6:	movl %eax, $0x5a4d<UINT32>
0x004039ab:	cmpw 0x400000, %ax
0x004039b2:	je 0x004039b8
0x004039b8:	movl %eax, 0x40003c
0x004039bd:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x004039c7:	jne -21
0x004039c9:	movl %ecx, $0x10b<UINT32>
0x004039ce:	cmpw 0x400018(%eax), %cx
0x004039d5:	jne -35
0x004039d7:	xorl %ebx, %ebx
0x004039d9:	cmpl 0x400074(%eax), $0xe<UINT8>
0x004039e0:	jbe 9
0x004039e2:	cmpl 0x4000e8(%eax), %ebx
0x004039e8:	setne %bl
0x004039eb:	movl -28(%ebp), %ebx
0x004039ee:	call 0x00405c2b
0x00405c2b:	call GetProcessHeap@KERNEL32.dll
GetProcessHeap@KERNEL32.dll: API Node	
0x00405c31:	xorl %ecx, %ecx
0x00405c33:	movl 0x41daf8, %eax
0x00405c38:	testl %eax, %eax
0x00405c3a:	setne %cl
0x00405c3d:	movl %eax, %ecx
0x00405c3f:	ret

0x004039f3:	testl %eax, %eax
0x004039f5:	jne 0x004039ff
0x004039ff:	call 0x00404a03
0x00404a03:	call 0x00402bbe
0x00402bbe:	pushl %esi
0x00402bbf:	pushl $0x0<UINT8>
0x00402bc1:	call EncodePointer@KERNEL32.dll
EncodePointer@KERNEL32.dll: API Node	
0x00402bc7:	movl %esi, %eax
0x00402bc9:	pushl %esi
0x00402bca:	call 0x00405714
0x00405714:	pushl %ebp
0x00405715:	movl %ebp, %esp
0x00405717:	movl %eax, 0x8(%ebp)
0x0040571a:	movl 0x41dad0, %eax
0x0040571f:	popl %ebp
0x00405720:	ret

0x00402bcf:	pushl %esi
0x00402bd0:	call 0x00403c26
0x00403c26:	pushl %ebp
0x00403c27:	movl %ebp, %esp
0x00403c29:	movl %eax, 0x8(%ebp)
0x00403c2c:	movl 0x41d320, %eax
0x00403c31:	popl %ebp
0x00403c32:	ret

0x00402bd5:	pushl %esi
0x00402bd6:	call 0x00405721
0x00405721:	pushl %ebp
0x00405722:	movl %ebp, %esp
0x00405724:	movl %eax, 0x8(%ebp)
0x00405727:	movl 0x41dad4, %eax
0x0040572c:	popl %ebp
0x0040572d:	ret

0x00402bdb:	pushl %esi
0x00402bdc:	call 0x0040573b
0x0040573b:	pushl %ebp
0x0040573c:	movl %ebp, %esp
0x0040573e:	movl %eax, 0x8(%ebp)
0x00405741:	movl 0x41dad8, %eax
0x00405746:	movl 0x41dadc, %eax
0x0040574b:	movl 0x41dae0, %eax
0x00405750:	movl 0x41dae4, %eax
0x00405755:	popl %ebp
0x00405756:	ret

0x00402be1:	pushl %esi
0x00402be2:	call 0x004056dd
0x004056dd:	pushl $0x4056a9<UINT32>
0x004056e2:	call EncodePointer@KERNEL32.dll
0x004056e8:	movl 0x41dacc, %eax
0x004056ed:	ret

0x00402be7:	pushl %esi
0x00402be8:	call 0x0040594c
0x0040594c:	pushl %ebp
0x0040594d:	movl %ebp, %esp
0x0040594f:	movl %eax, 0x8(%ebp)
0x00405952:	movl 0x41daec, %eax
0x00405957:	popl %ebp
0x00405958:	ret

0x00402bed:	addl %esp, $0x18<UINT8>
0x00402bf0:	popl %esi
0x00402bf1:	jmp 0x00404e3f
0x00404e3f:	pushl %esi
0x00404e40:	pushl %edi
0x00404e41:	pushl $0x4172f0<UINT32>
0x00404e46:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x00404e4c:	movl %esi, 0x4100f4
0x00404e52:	movl %edi, %eax
0x00404e54:	pushl $0x41730c<UINT32>
0x00404e59:	pushl %edi
0x00404e5a:	call GetProcAddress@KERNEL32.dll
0x00404e5c:	xorl %eax, 0x41c200
0x00404e62:	pushl $0x417318<UINT32>
0x00404e67:	pushl %edi
0x00404e68:	movl 0x41f0a0, %eax
0x00404e6d:	call GetProcAddress@KERNEL32.dll
0x00404e6f:	xorl %eax, 0x41c200
0x00404e75:	pushl $0x417320<UINT32>
0x00404e7a:	pushl %edi
0x00404e7b:	movl 0x41f0a4, %eax
0x00404e80:	call GetProcAddress@KERNEL32.dll
0x00404e82:	xorl %eax, 0x41c200
0x00404e88:	pushl $0x41732c<UINT32>
0x00404e8d:	pushl %edi
0x00404e8e:	movl 0x41f0a8, %eax
0x00404e93:	call GetProcAddress@KERNEL32.dll
0x00404e95:	xorl %eax, 0x41c200
0x00404e9b:	pushl $0x417338<UINT32>
0x00404ea0:	pushl %edi
0x00404ea1:	movl 0x41f0ac, %eax
0x00404ea6:	call GetProcAddress@KERNEL32.dll
0x00404ea8:	xorl %eax, 0x41c200
0x00404eae:	pushl $0x417354<UINT32>
0x00404eb3:	pushl %edi
0x00404eb4:	movl 0x41f0b0, %eax
0x00404eb9:	call GetProcAddress@KERNEL32.dll
0x00404ebb:	xorl %eax, 0x41c200
0x00404ec1:	pushl $0x417364<UINT32>
0x00404ec6:	pushl %edi
0x00404ec7:	movl 0x41f0b4, %eax
0x00404ecc:	call GetProcAddress@KERNEL32.dll
0x00404ece:	xorl %eax, 0x41c200
0x00404ed4:	pushl $0x417378<UINT32>
0x00404ed9:	pushl %edi
0x00404eda:	movl 0x41f0b8, %eax
0x00404edf:	call GetProcAddress@KERNEL32.dll
0x00404ee1:	xorl %eax, 0x41c200
0x00404ee7:	pushl $0x417390<UINT32>
0x00404eec:	pushl %edi
0x00404eed:	movl 0x41f0bc, %eax
0x00404ef2:	call GetProcAddress@KERNEL32.dll
0x00404ef4:	xorl %eax, 0x41c200
0x00404efa:	pushl $0x4173a8<UINT32>
0x00404eff:	pushl %edi
0x00404f00:	movl 0x41f0c0, %eax
0x00404f05:	call GetProcAddress@KERNEL32.dll
0x00404f07:	xorl %eax, 0x41c200
0x00404f0d:	pushl $0x4173bc<UINT32>
0x00404f12:	pushl %edi
0x00404f13:	movl 0x41f0c4, %eax
0x00404f18:	call GetProcAddress@KERNEL32.dll
0x00404f1a:	xorl %eax, 0x41c200
0x00404f20:	pushl $0x4173dc<UINT32>
0x00404f25:	pushl %edi
0x00404f26:	movl 0x41f0c8, %eax
0x00404f2b:	call GetProcAddress@KERNEL32.dll
0x00404f2d:	xorl %eax, 0x41c200
0x00404f33:	pushl $0x4173f4<UINT32>
0x00404f38:	pushl %edi
0x00404f39:	movl 0x41f0cc, %eax
0x00404f3e:	call GetProcAddress@KERNEL32.dll
0x00404f40:	xorl %eax, 0x41c200
0x00404f46:	pushl $0x41740c<UINT32>
0x00404f4b:	pushl %edi
0x00404f4c:	movl 0x41f0d0, %eax
0x00404f51:	call GetProcAddress@KERNEL32.dll
0x00404f53:	xorl %eax, 0x41c200
0x00404f59:	pushl $0x417420<UINT32>
0x00404f5e:	pushl %edi
0x00404f5f:	movl 0x41f0d4, %eax
0x00404f64:	call GetProcAddress@KERNEL32.dll
0x00404f66:	xorl %eax, 0x41c200
0x00404f6c:	movl 0x41f0d8, %eax
0x00404f71:	pushl $0x417434<UINT32>
0x00404f76:	pushl %edi
0x00404f77:	call GetProcAddress@KERNEL32.dll
0x00404f79:	xorl %eax, 0x41c200
0x00404f7f:	pushl $0x417450<UINT32>
0x00404f84:	pushl %edi
0x00404f85:	movl 0x41f0dc, %eax
0x00404f8a:	call GetProcAddress@KERNEL32.dll
0x00404f8c:	xorl %eax, 0x41c200
0x00404f92:	pushl $0x417470<UINT32>
0x00404f97:	pushl %edi
0x00404f98:	movl 0x41f0e0, %eax
0x00404f9d:	call GetProcAddress@KERNEL32.dll
0x00404f9f:	xorl %eax, 0x41c200
0x00404fa5:	pushl $0x41748c<UINT32>
0x00404faa:	pushl %edi
0x00404fab:	movl 0x41f0e4, %eax
0x00404fb0:	call GetProcAddress@KERNEL32.dll
0x00404fb2:	xorl %eax, 0x41c200
0x00404fb8:	pushl $0x4174ac<UINT32>
0x00404fbd:	pushl %edi
0x00404fbe:	movl 0x41f0e8, %eax
0x00404fc3:	call GetProcAddress@KERNEL32.dll
0x00404fc5:	xorl %eax, 0x41c200
0x00404fcb:	pushl $0x4174c0<UINT32>
0x00404fd0:	pushl %edi
0x00404fd1:	movl 0x41f0ec, %eax
0x00404fd6:	call GetProcAddress@KERNEL32.dll
0x00404fd8:	xorl %eax, 0x41c200
0x00404fde:	pushl $0x4174dc<UINT32>
0x00404fe3:	pushl %edi
0x00404fe4:	movl 0x41f0f0, %eax
0x00404fe9:	call GetProcAddress@KERNEL32.dll
0x00404feb:	xorl %eax, 0x41c200
0x00404ff1:	pushl $0x4174f0<UINT32>
0x00404ff6:	pushl %edi
0x00404ff7:	movl 0x41f0f8, %eax
0x00404ffc:	call GetProcAddress@KERNEL32.dll
0x00404ffe:	xorl %eax, 0x41c200
0x00405004:	pushl $0x417500<UINT32>
0x00405009:	pushl %edi
0x0040500a:	movl 0x41f0f4, %eax
0x0040500f:	call GetProcAddress@KERNEL32.dll
0x00405011:	xorl %eax, 0x41c200
0x00405017:	pushl $0x417510<UINT32>
0x0040501c:	pushl %edi
0x0040501d:	movl 0x41f0fc, %eax
0x00405022:	call GetProcAddress@KERNEL32.dll
0x00405024:	xorl %eax, 0x41c200
0x0040502a:	pushl $0x417520<UINT32>
0x0040502f:	pushl %edi
0x00405030:	movl 0x41f100, %eax
0x00405035:	call GetProcAddress@KERNEL32.dll
0x00405037:	xorl %eax, 0x41c200
0x0040503d:	pushl $0x417530<UINT32>
0x00405042:	pushl %edi
0x00405043:	movl 0x41f104, %eax
0x00405048:	call GetProcAddress@KERNEL32.dll
0x0040504a:	xorl %eax, 0x41c200
0x00405050:	pushl $0x41754c<UINT32>
0x00405055:	pushl %edi
0x00405056:	movl 0x41f108, %eax
0x0040505b:	call GetProcAddress@KERNEL32.dll
0x0040505d:	xorl %eax, 0x41c200
0x00405063:	pushl $0x417560<UINT32>
0x00405068:	pushl %edi
0x00405069:	movl 0x41f10c, %eax
0x0040506e:	call GetProcAddress@KERNEL32.dll
0x00405070:	xorl %eax, 0x41c200
0x00405076:	pushl $0x417570<UINT32>
0x0040507b:	pushl %edi
0x0040507c:	movl 0x41f110, %eax
0x00405081:	call GetProcAddress@KERNEL32.dll
0x00405083:	xorl %eax, 0x41c200
0x00405089:	pushl $0x417584<UINT32>
0x0040508e:	pushl %edi
0x0040508f:	movl 0x41f114, %eax
0x00405094:	call GetProcAddress@KERNEL32.dll
0x00405096:	xorl %eax, 0x41c200
0x0040509c:	movl 0x41f118, %eax
0x004050a1:	pushl $0x417594<UINT32>
0x004050a6:	pushl %edi
0x004050a7:	call GetProcAddress@KERNEL32.dll
0x004050a9:	xorl %eax, 0x41c200
0x004050af:	pushl $0x4175b4<UINT32>
0x004050b4:	pushl %edi
0x004050b5:	movl 0x41f11c, %eax
0x004050ba:	call GetProcAddress@KERNEL32.dll
0x004050bc:	xorl %eax, 0x41c200
0x004050c2:	popl %edi
0x004050c3:	movl 0x41f120, %eax
0x004050c8:	popl %esi
0x004050c9:	ret

0x00404a08:	call 0x00404ce1
0x00404ce1:	pushl %esi
0x00404ce2:	pushl %edi
0x00404ce3:	movl %esi, $0x41cad0<UINT32>
0x00404ce8:	movl %edi, $0x41d348<UINT32>
0x00404ced:	cmpl 0x4(%esi), $0x1<UINT8>
0x00404cf1:	jne 22
0x00404cf3:	pushl $0x0<UINT8>
0x00404cf5:	movl (%esi), %edi
0x00404cf7:	addl %edi, $0x18<UINT8>
0x00404cfa:	pushl $0xfa0<UINT32>
0x00404cff:	pushl (%esi)
0x00404d01:	call 0x00404dd0
0x00404dd0:	pushl %ebp
0x00404dd1:	movl %ebp, %esp
0x00404dd3:	movl %eax, 0x41f0b0
0x00404dd8:	xorl %eax, 0x41c200
0x00404dde:	je 13
0x00404de0:	pushl 0x10(%ebp)
0x00404de3:	pushl 0xc(%ebp)
0x00404de6:	pushl 0x8(%ebp)
0x00404de9:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x00404deb:	popl %ebp
0x00404dec:	ret

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
