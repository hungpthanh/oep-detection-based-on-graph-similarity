0x00428770:	pusha
0x00428771:	movl %esi, $0x41b000<UINT32>
0x00428776:	leal %edi, -106496(%esi)
0x0042877c:	pushl %edi
0x0042877d:	orl %ebp, $0xffffffff<UINT8>
0x00428780:	jmp 0x00428792
0x00428792:	movl %ebx, (%esi)
0x00428794:	subl %esi, $0xfffffffc<UINT8>
0x00428797:	adcl %ebx, %ebx
0x00428799:	jb 0x00428788
0x00428788:	movb %al, (%esi)
0x0042878a:	incl %esi
0x0042878b:	movb (%edi), %al
0x0042878d:	incl %edi
0x0042878e:	addl %ebx, %ebx
0x00428790:	jne 0x00428799
0x0042879b:	movl %eax, $0x1<UINT32>
0x004287a0:	addl %ebx, %ebx
0x004287a2:	jne 0x004287ab
0x004287ab:	adcl %eax, %eax
0x004287ad:	addl %ebx, %ebx
0x004287af:	jae 0x004287a0
0x004287b1:	jne 0x004287bc
0x004287bc:	xorl %ecx, %ecx
0x004287be:	subl %eax, $0x3<UINT8>
0x004287c1:	jb 0x004287d0
0x004287d0:	addl %ebx, %ebx
0x004287d2:	jne 0x004287db
0x004287db:	adcl %ecx, %ecx
0x004287dd:	addl %ebx, %ebx
0x004287df:	jne 0x004287e8
0x004287e8:	adcl %ecx, %ecx
0x004287ea:	jne 0x0042880c
0x0042880c:	cmpl %ebp, $0xfffff300<UINT32>
0x00428812:	adcl %ecx, $0x1<UINT8>
0x00428815:	leal %edx, (%edi,%ebp)
0x00428818:	cmpl %ebp, $0xfffffffc<UINT8>
0x0042881b:	jbe 0x0042882c
0x0042881d:	movb %al, (%edx)
0x0042881f:	incl %edx
0x00428820:	movb (%edi), %al
0x00428822:	incl %edi
0x00428823:	decl %ecx
0x00428824:	jne 0x0042881d
0x00428826:	jmp 0x0042878e
0x004287c3:	shll %eax, $0x8<UINT8>
0x004287c6:	movb %al, (%esi)
0x004287c8:	incl %esi
0x004287c9:	xorl %eax, $0xffffffff<UINT8>
0x004287cc:	je 0x00428842
0x004287ce:	movl %ebp, %eax
0x0042882c:	movl %eax, (%edx)
0x0042882e:	addl %edx, $0x4<UINT8>
0x00428831:	movl (%edi), %eax
0x00428833:	addl %edi, $0x4<UINT8>
0x00428836:	subl %ecx, $0x4<UINT8>
0x00428839:	ja 0x0042882c
0x0042883b:	addl %edi, %ecx
0x0042883d:	jmp 0x0042878e
0x004287d4:	movl %ebx, (%esi)
0x004287d6:	subl %esi, $0xfffffffc<UINT8>
0x004287d9:	adcl %ebx, %ebx
0x004287ec:	incl %ecx
0x004287ed:	addl %ebx, %ebx
0x004287ef:	jne 0x004287f8
0x004287f8:	adcl %ecx, %ecx
0x004287fa:	addl %ebx, %ebx
0x004287fc:	jae 0x004287ed
0x004287fe:	jne 0x00428809
0x00428809:	addl %ecx, $0x2<UINT8>
0x004287e1:	movl %ebx, (%esi)
0x004287e3:	subl %esi, $0xfffffffc<UINT8>
0x004287e6:	adcl %ebx, %ebx
0x004287b3:	movl %ebx, (%esi)
0x004287b5:	subl %esi, $0xfffffffc<UINT8>
0x004287b8:	adcl %ebx, %ebx
0x004287ba:	jae 0x004287a0
0x004287a4:	movl %ebx, (%esi)
0x004287a6:	subl %esi, $0xfffffffc<UINT8>
0x004287a9:	adcl %ebx, %ebx
0x00428800:	movl %ebx, (%esi)
0x00428802:	subl %esi, $0xfffffffc<UINT8>
0x00428805:	adcl %ebx, %ebx
0x00428807:	jae 0x004287ed
0x004287f1:	movl %ebx, (%esi)
0x004287f3:	subl %esi, $0xfffffffc<UINT8>
0x004287f6:	adcl %ebx, %ebx
0x00428842:	popl %esi
0x00428843:	movl %edi, %esi
0x00428845:	movl %ecx, $0x647<UINT32>
0x0042884a:	movb %al, (%edi)
0x0042884c:	incl %edi
0x0042884d:	subb %al, $0xffffffe8<UINT8>
0x0042884f:	cmpb %al, $0x1<UINT8>
0x00428851:	ja 0x0042884a
0x00428853:	cmpb (%edi), $0x5<UINT8>
0x00428856:	jne 0x0042884a
0x00428858:	movl %eax, (%edi)
0x0042885a:	movb %bl, 0x4(%edi)
0x0042885d:	shrw %ax, $0x8<UINT8>
0x00428861:	roll %eax, $0x10<UINT8>
0x00428864:	xchgb %ah, %al
0x00428866:	subl %eax, %edi
0x00428868:	subb %bl, $0xffffffe8<UINT8>
0x0042886b:	addl %eax, %esi
0x0042886d:	movl (%edi), %eax
0x0042886f:	addl %edi, $0x5<UINT8>
0x00428872:	movb %al, %bl
0x00428874:	loop 0x0042884f
0x00428876:	leal %edi, 0x25000(%esi)
0x0042887c:	movl %eax, (%edi)
0x0042887e:	orl %eax, %eax
0x00428880:	je 0x004288be
0x00428882:	movl %ebx, 0x4(%edi)
0x00428885:	leal %eax, 0x2860c(%eax,%esi)
0x0042888c:	addl %ebx, %esi
0x0042888e:	pushl %eax
0x0042888f:	addl %edi, $0x8<UINT8>
0x00428892:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x00428898:	xchgl %ebp, %eax
0x00428899:	movb %al, (%edi)
0x0042889b:	incl %edi
0x0042889c:	orb %al, %al
0x0042889e:	je 0x0042887c
0x004288a0:	movl %ecx, %edi
0x004288a2:	pushl %edi
0x004288a3:	decl %eax
0x004288a4:	repn scasb %al, %es:(%edi)
0x004288a6:	pushl %ebp
0x004288a7:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x004288ad:	orl %eax, %eax
0x004288af:	je 7
0x004288b1:	movl (%ebx), %eax
0x004288b3:	addl %ebx, $0x4<UINT8>
0x004288b6:	jmp 0x00428899
GetProcAddress@KERNEL32.DLL: API Node	
0x004288be:	addl %edi, $0x4<UINT8>
0x004288c1:	leal %ebx, -4(%esi)
0x004288c4:	xorl %eax, %eax
0x004288c6:	movb %al, (%edi)
0x004288c8:	incl %edi
0x004288c9:	orl %eax, %eax
0x004288cb:	je 0x004288ef
0x004288cd:	cmpb %al, $0xffffffef<UINT8>
0x004288cf:	ja 0x004288e2
0x004288d1:	addl %ebx, %eax
0x004288d3:	movl %eax, (%ebx)
0x004288d5:	xchgb %ah, %al
0x004288d7:	roll %eax, $0x10<UINT8>
0x004288da:	xchgb %ah, %al
0x004288dc:	addl %eax, %esi
0x004288de:	movl (%ebx), %eax
0x004288e0:	jmp 0x004288c4
0x004288e2:	andb %al, $0xf<UINT8>
0x004288e4:	shll %eax, $0x10<UINT8>
0x004288e7:	movw %ax, (%edi)
0x004288ea:	addl %edi, $0x2<UINT8>
0x004288ed:	jmp 0x004288d1
0x004288ef:	movl %ebp, 0x286bc(%esi)
0x004288f5:	leal %edi, -4096(%esi)
0x004288fb:	movl %ebx, $0x1000<UINT32>
0x00428900:	pushl %eax
0x00428901:	pushl %esp
0x00428902:	pushl $0x4<UINT8>
0x00428904:	pushl %ebx
0x00428905:	pushl %edi
0x00428906:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00428908:	leal %eax, 0x20f(%edi)
0x0042890e:	andb (%eax), $0x7f<UINT8>
0x00428911:	andb 0x28(%eax), $0x7f<UINT8>
0x00428915:	popl %eax
0x00428916:	pushl %eax
0x00428917:	pushl %esp
0x00428918:	pushl %eax
0x00428919:	pushl %ebx
0x0042891a:	pushl %edi
0x0042891b:	call VirtualProtect@kernel32.dll
0x0042891d:	popl %eax
0x0042891e:	popa
0x0042891f:	leal %eax, -128(%esp)
0x00428923:	pushl $0x0<UINT8>
0x00428925:	cmpl %esp, %eax
0x00428927:	jne 0x00428923
0x00428929:	subl %esp, $0xffffff80<UINT8>
0x0042892c:	jmp 0x00405426
0x00405426:	call 0x0040b428
0x0040b428:	pushl %ebp
0x0040b429:	movl %ebp, %esp
0x0040b42b:	subl %esp, $0x14<UINT8>
0x0040b42e:	andl -12(%ebp), $0x0<UINT8>
0x0040b432:	andl -8(%ebp), $0x0<UINT8>
0x0040b436:	movl %eax, 0x41f358
0x0040b43b:	pushl %esi
0x0040b43c:	pushl %edi
0x0040b43d:	movl %edi, $0xbb40e64e<UINT32>
0x0040b442:	movl %esi, $0xffff0000<UINT32>
0x0040b447:	cmpl %eax, %edi
0x0040b449:	je 0x0040b458
0x0040b458:	leal %eax, -12(%ebp)
0x0040b45b:	pushl %eax
0x0040b45c:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040b462:	movl %eax, -8(%ebp)
0x0040b465:	xorl %eax, -12(%ebp)
0x0040b468:	movl -4(%ebp), %eax
0x0040b46b:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040b471:	xorl -4(%ebp), %eax
0x0040b474:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040b47a:	xorl -4(%ebp), %eax
0x0040b47d:	leal %eax, -20(%ebp)
0x0040b480:	pushl %eax
0x0040b481:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040b487:	movl %ecx, -16(%ebp)
0x0040b48a:	leal %eax, -4(%ebp)
0x0040b48d:	xorl %ecx, -20(%ebp)
0x0040b490:	xorl %ecx, -4(%ebp)
0x0040b493:	xorl %ecx, %eax
0x0040b495:	cmpl %ecx, %edi
0x0040b497:	jne 0x0040b4a0
0x0040b4a0:	testl %esi, %ecx
0x0040b4a2:	jne 0x0040b4b0
0x0040b4b0:	movl 0x41f358, %ecx
0x0040b4b6:	notl %ecx
0x0040b4b8:	movl 0x41f35c, %ecx
0x0040b4be:	popl %edi
0x0040b4bf:	popl %esi
0x0040b4c0:	movl %esp, %ebp
0x0040b4c2:	popl %ebp
0x0040b4c3:	ret

0x0040542b:	jmp 0x004052ab
0x004052ab:	pushl $0x14<UINT8>
0x004052ad:	pushl $0x41e178<UINT32>
0x004052b2:	call 0x00406170
0x00406170:	pushl $0x4061d0<UINT32>
0x00406175:	pushl %fs:0
0x0040617c:	movl %eax, 0x10(%esp)
0x00406180:	movl 0x10(%esp), %ebp
0x00406184:	leal %ebp, 0x10(%esp)
0x00406188:	subl %esp, %eax
0x0040618a:	pushl %ebx
0x0040618b:	pushl %esi
0x0040618c:	pushl %edi
0x0040618d:	movl %eax, 0x41f358
0x00406192:	xorl -4(%ebp), %eax
0x00406195:	xorl %eax, %ebp
0x00406197:	pushl %eax
0x00406198:	movl -24(%ebp), %esp
0x0040619b:	pushl -8(%ebp)
0x0040619e:	movl %eax, -4(%ebp)
0x004061a1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004061a8:	movl -8(%ebp), %eax
0x004061ab:	leal %eax, -16(%ebp)
0x004061ae:	movl %fs:0, %eax
0x004061b4:	ret

0x004052b7:	pushl $0x1<UINT8>
0x004052b9:	call 0x0040b3db
0x0040b3db:	pushl %ebp
0x0040b3dc:	movl %ebp, %esp
0x0040b3de:	movl %eax, 0x8(%ebp)
0x0040b3e1:	movl 0x420588, %eax
0x0040b3e6:	popl %ebp
0x0040b3e7:	ret

0x004052be:	popl %ecx
0x004052bf:	movl %eax, $0x5a4d<UINT32>
0x004052c4:	cmpw 0x400000, %ax
0x004052cb:	je 0x004052d1
0x004052d1:	movl %eax, 0x40003c
0x004052d6:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x004052e0:	jne -21
0x004052e2:	movl %ecx, $0x10b<UINT32>
0x004052e7:	cmpw 0x400018(%eax), %cx
0x004052ee:	jne -35
0x004052f0:	xorl %ebx, %ebx
0x004052f2:	cmpl 0x400074(%eax), $0xe<UINT8>
0x004052f9:	jbe 9
0x004052fb:	cmpl 0x4000e8(%eax), %ebx
0x00405301:	setne %bl
0x00405304:	movl -28(%ebp), %ebx
0x00405307:	call 0x00408ed0
0x00408ed0:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x00408ed6:	xorl %ecx, %ecx
0x00408ed8:	movl 0x420be0, %eax
0x00408edd:	testl %eax, %eax
0x00408edf:	setne %cl
0x00408ee2:	movl %eax, %ecx
0x00408ee4:	ret

0x0040530c:	testl %eax, %eax
0x0040530e:	jne 0x00405318
0x00405318:	call 0x00408db8
0x00408db8:	call 0x00403e5a
0x00403e5a:	pushl %esi
0x00403e5b:	pushl $0x0<UINT8>
0x00403e5d:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00403e63:	movl %esi, %eax
0x00403e65:	pushl %esi
0x00403e66:	call 0x00408ec3
0x00408ec3:	pushl %ebp
0x00408ec4:	movl %ebp, %esp
0x00408ec6:	movl %eax, 0x8(%ebp)
0x00408ec9:	movl 0x420bd8, %eax
0x00408ece:	popl %ebp
0x00408ecf:	ret

0x00403e6b:	pushl %esi
0x00403e6c:	call 0x00406489
0x00406489:	pushl %ebp
0x0040648a:	movl %ebp, %esp
0x0040648c:	movl %eax, 0x8(%ebp)
0x0040648f:	movl 0x420474, %eax
0x00406494:	popl %ebp
0x00406495:	ret

0x00403e71:	pushl %esi
0x00403e72:	call 0x00409345
0x00409345:	pushl %ebp
0x00409346:	movl %ebp, %esp
0x00409348:	movl %eax, 0x8(%ebp)
0x0040934b:	movl 0x420f0c, %eax
0x00409350:	popl %ebp
0x00409351:	ret

0x00403e77:	pushl %esi
0x00403e78:	call 0x0040935f
0x0040935f:	pushl %ebp
0x00409360:	movl %ebp, %esp
0x00409362:	movl %eax, 0x8(%ebp)
0x00409365:	movl 0x420f10, %eax
0x0040936a:	movl 0x420f14, %eax
0x0040936f:	movl 0x420f18, %eax
0x00409374:	movl 0x420f1c, %eax
0x00409379:	popl %ebp
0x0040937a:	ret

0x00403e7d:	pushl %esi
0x00403e7e:	call 0x00409334
0x00409334:	pushl $0x409300<UINT32>
0x00409339:	call EncodePointer@KERNEL32.DLL
0x0040933f:	movl 0x420f08, %eax
0x00409344:	ret

0x00403e83:	pushl %esi
0x00403e84:	call 0x00409570
0x00409570:	pushl %ebp
0x00409571:	movl %ebp, %esp
0x00409573:	movl %eax, 0x8(%ebp)
0x00409576:	movl 0x420f24, %eax
0x0040957b:	popl %ebp
0x0040957c:	ret

0x00403e89:	addl %esp, $0x18<UINT8>
0x00403e8c:	popl %esi
0x00403e8d:	jmp 0x00407b62
0x00407b62:	pushl %esi
0x00407b63:	pushl %edi
0x00407b64:	pushl $0x41a398<UINT32>
0x00407b69:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00407b6f:	movl %esi, 0x4130b4
0x00407b75:	movl %edi, %eax
0x00407b77:	pushl $0x41a3b4<UINT32>
0x00407b7c:	pushl %edi
0x00407b7d:	call GetProcAddress@KERNEL32.DLL
0x00407b7f:	xorl %eax, 0x41f358
0x00407b85:	pushl $0x41a3c0<UINT32>
0x00407b8a:	pushl %edi
0x00407b8b:	movl 0x421180, %eax
0x00407b90:	call GetProcAddress@KERNEL32.DLL
0x00407b92:	xorl %eax, 0x41f358
0x00407b98:	pushl $0x41a3c8<UINT32>
0x00407b9d:	pushl %edi
0x00407b9e:	movl 0x421184, %eax
0x00407ba3:	call GetProcAddress@KERNEL32.DLL
0x00407ba5:	xorl %eax, 0x41f358
0x00407bab:	pushl $0x41a3d4<UINT32>
0x00407bb0:	pushl %edi
0x00407bb1:	movl 0x421188, %eax
0x00407bb6:	call GetProcAddress@KERNEL32.DLL
0x00407bb8:	xorl %eax, 0x41f358
0x00407bbe:	pushl $0x41a3e0<UINT32>
0x00407bc3:	pushl %edi
0x00407bc4:	movl 0x42118c, %eax
0x00407bc9:	call GetProcAddress@KERNEL32.DLL
0x00407bcb:	xorl %eax, 0x41f358
0x00407bd1:	pushl $0x41a3fc<UINT32>
0x00407bd6:	pushl %edi
0x00407bd7:	movl 0x421190, %eax
0x00407bdc:	call GetProcAddress@KERNEL32.DLL
0x00407bde:	xorl %eax, 0x41f358
0x00407be4:	pushl $0x41a40c<UINT32>
0x00407be9:	pushl %edi
0x00407bea:	movl 0x421194, %eax
0x00407bef:	call GetProcAddress@KERNEL32.DLL
0x00407bf1:	xorl %eax, 0x41f358
0x00407bf7:	pushl $0x41a420<UINT32>
0x00407bfc:	pushl %edi
0x00407bfd:	movl 0x421198, %eax
0x00407c02:	call GetProcAddress@KERNEL32.DLL
0x00407c04:	xorl %eax, 0x41f358
0x00407c0a:	pushl $0x41a438<UINT32>
0x00407c0f:	pushl %edi
0x00407c10:	movl 0x42119c, %eax
0x00407c15:	call GetProcAddress@KERNEL32.DLL
0x00407c17:	xorl %eax, 0x41f358
0x00407c1d:	pushl $0x41a450<UINT32>
0x00407c22:	pushl %edi
0x00407c23:	movl 0x4211a0, %eax
0x00407c28:	call GetProcAddress@KERNEL32.DLL
0x00407c2a:	xorl %eax, 0x41f358
0x00407c30:	pushl $0x41a464<UINT32>
0x00407c35:	pushl %edi
0x00407c36:	movl 0x4211a4, %eax
0x00407c3b:	call GetProcAddress@KERNEL32.DLL
0x00407c3d:	xorl %eax, 0x41f358
0x00407c43:	pushl $0x41a484<UINT32>
0x00407c48:	pushl %edi
0x00407c49:	movl 0x4211a8, %eax
0x00407c4e:	call GetProcAddress@KERNEL32.DLL
0x00407c50:	xorl %eax, 0x41f358
0x00407c56:	pushl $0x41a49c<UINT32>
0x00407c5b:	pushl %edi
0x00407c5c:	movl 0x4211ac, %eax
0x00407c61:	call GetProcAddress@KERNEL32.DLL
0x00407c63:	xorl %eax, 0x41f358
0x00407c69:	pushl $0x41a4b4<UINT32>
0x00407c6e:	pushl %edi
0x00407c6f:	movl 0x4211b0, %eax
0x00407c74:	call GetProcAddress@KERNEL32.DLL
0x00407c76:	xorl %eax, 0x41f358
0x00407c7c:	pushl $0x41a4c8<UINT32>
0x00407c81:	pushl %edi
0x00407c82:	movl 0x4211b4, %eax
0x00407c87:	call GetProcAddress@KERNEL32.DLL
0x00407c89:	xorl %eax, 0x41f358
0x00407c8f:	movl 0x4211b8, %eax
0x00407c94:	pushl $0x41a4dc<UINT32>
0x00407c99:	pushl %edi
0x00407c9a:	call GetProcAddress@KERNEL32.DLL
0x00407c9c:	xorl %eax, 0x41f358
0x00407ca2:	pushl $0x41a4f8<UINT32>
0x00407ca7:	pushl %edi
0x00407ca8:	movl 0x4211bc, %eax
0x00407cad:	call GetProcAddress@KERNEL32.DLL
0x00407caf:	xorl %eax, 0x41f358
0x00407cb5:	pushl $0x41a518<UINT32>
0x00407cba:	pushl %edi
0x00407cbb:	movl 0x4211c0, %eax
0x00407cc0:	call GetProcAddress@KERNEL32.DLL
0x00407cc2:	xorl %eax, 0x41f358
0x00407cc8:	pushl $0x41a534<UINT32>
0x00407ccd:	pushl %edi
0x00407cce:	movl 0x4211c4, %eax
0x00407cd3:	call GetProcAddress@KERNEL32.DLL
0x00407cd5:	xorl %eax, 0x41f358
0x00407cdb:	pushl $0x41a554<UINT32>
0x00407ce0:	pushl %edi
0x00407ce1:	movl 0x4211c8, %eax
0x00407ce6:	call GetProcAddress@KERNEL32.DLL
0x00407ce8:	xorl %eax, 0x41f358
0x00407cee:	pushl $0x41a568<UINT32>
0x00407cf3:	pushl %edi
0x00407cf4:	movl 0x4211cc, %eax
0x00407cf9:	call GetProcAddress@KERNEL32.DLL
0x00407cfb:	xorl %eax, 0x41f358
0x00407d01:	pushl $0x41a584<UINT32>
0x00407d06:	pushl %edi
0x00407d07:	movl 0x4211d0, %eax
0x00407d0c:	call GetProcAddress@KERNEL32.DLL
0x00407d0e:	xorl %eax, 0x41f358
0x00407d14:	pushl $0x41a598<UINT32>
0x00407d19:	pushl %edi
0x00407d1a:	movl 0x4211d8, %eax
0x00407d1f:	call GetProcAddress@KERNEL32.DLL
0x00407d21:	xorl %eax, 0x41f358
0x00407d27:	pushl $0x41a5a8<UINT32>
0x00407d2c:	pushl %edi
0x00407d2d:	movl 0x4211d4, %eax
0x00407d32:	call GetProcAddress@KERNEL32.DLL
0x00407d34:	xorl %eax, 0x41f358
0x00407d3a:	pushl $0x41a5b8<UINT32>
0x00407d3f:	pushl %edi
0x00407d40:	movl 0x4211dc, %eax
0x00407d45:	call GetProcAddress@KERNEL32.DLL
0x00407d47:	xorl %eax, 0x41f358
0x00407d4d:	pushl $0x41a5c8<UINT32>
0x00407d52:	pushl %edi
0x00407d53:	movl 0x4211e0, %eax
0x00407d58:	call GetProcAddress@KERNEL32.DLL
0x00407d5a:	xorl %eax, 0x41f358
0x00407d60:	pushl $0x41a5d8<UINT32>
0x00407d65:	pushl %edi
0x00407d66:	movl 0x4211e4, %eax
0x00407d6b:	call GetProcAddress@KERNEL32.DLL
0x00407d6d:	xorl %eax, 0x41f358
0x00407d73:	pushl $0x41a5f4<UINT32>
0x00407d78:	pushl %edi
0x00407d79:	movl 0x4211e8, %eax
0x00407d7e:	call GetProcAddress@KERNEL32.DLL
0x00407d80:	xorl %eax, 0x41f358
0x00407d86:	pushl $0x41a608<UINT32>
0x00407d8b:	pushl %edi
0x00407d8c:	movl 0x4211ec, %eax
0x00407d91:	call GetProcAddress@KERNEL32.DLL
0x00407d93:	xorl %eax, 0x41f358
0x00407d99:	pushl $0x41a618<UINT32>
0x00407d9e:	pushl %edi
0x00407d9f:	movl 0x4211f0, %eax
0x00407da4:	call GetProcAddress@KERNEL32.DLL
0x00407da6:	xorl %eax, 0x41f358
0x00407dac:	pushl $0x41a62c<UINT32>
0x00407db1:	pushl %edi
0x00407db2:	movl 0x4211f4, %eax
0x00407db7:	call GetProcAddress@KERNEL32.DLL
0x00407db9:	xorl %eax, 0x41f358
0x00407dbf:	movl 0x4211f8, %eax
0x00407dc4:	pushl $0x41a63c<UINT32>
0x00407dc9:	pushl %edi
0x00407dca:	call GetProcAddress@KERNEL32.DLL
0x00407dcc:	xorl %eax, 0x41f358
0x00407dd2:	pushl $0x41a65c<UINT32>
0x00407dd7:	pushl %edi
0x00407dd8:	movl 0x4211fc, %eax
0x00407ddd:	call GetProcAddress@KERNEL32.DLL
0x00407ddf:	xorl %eax, 0x41f358
0x00407de5:	popl %edi
0x00407de6:	movl 0x421200, %eax
0x00407deb:	popl %esi
0x00407dec:	ret

0x00408dbd:	call 0x004055fe
0x004055fe:	pushl %esi
0x004055ff:	pushl %edi
0x00405600:	movl %esi, $0x41f370<UINT32>
0x00405605:	movl %edi, $0x420320<UINT32>
0x0040560a:	cmpl 0x4(%esi), $0x1<UINT8>
0x0040560e:	jne 22
0x00405610:	pushl $0x0<UINT8>
0x00405612:	movl (%esi), %edi
0x00405614:	addl %edi, $0x18<UINT8>
0x00405617:	pushl $0xfa0<UINT32>
0x0040561c:	pushl (%esi)
0x0040561e:	call 0x00407af4
0x00407af4:	pushl %ebp
0x00407af5:	movl %ebp, %esp
0x00407af7:	movl %eax, 0x421190
0x00407afc:	xorl %eax, 0x41f358
0x00407b02:	je 13
0x00407b04:	pushl 0x10(%ebp)
0x00407b07:	pushl 0xc(%ebp)
0x00407b0a:	pushl 0x8(%ebp)
0x00407b0d:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x00407b0f:	popl %ebp
0x00407b10:	ret

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
