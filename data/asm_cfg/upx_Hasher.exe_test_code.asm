0x004a9690:	pusha
0x004a9691:	movl %esi, $0x470000<UINT32>
0x004a9696:	leal %edi, -454656(%esi)
0x004a969c:	movl 0x820a0(%edi), $0x45b8e031<UINT32>
0x004a96a6:	pushl %edi
0x004a96a7:	orl %ebp, $0xffffffff<UINT8>
0x004a96aa:	jmp 0x004a96ba
0x004a96ba:	movl %ebx, (%esi)
0x004a96bc:	subl %esi, $0xfffffffc<UINT8>
0x004a96bf:	adcl %ebx, %ebx
0x004a96c1:	jb 0x004a96b0
0x004a96b0:	movb %al, (%esi)
0x004a96b2:	incl %esi
0x004a96b3:	movb (%edi), %al
0x004a96b5:	incl %edi
0x004a96b6:	addl %ebx, %ebx
0x004a96b8:	jne 0x004a96c1
0x004a96c3:	movl %eax, $0x1<UINT32>
0x004a96c8:	addl %ebx, %ebx
0x004a96ca:	jne 0x004a96d3
0x004a96d3:	adcl %eax, %eax
0x004a96d5:	addl %ebx, %ebx
0x004a96d7:	jae 0x004a96e4
0x004a96d9:	jne 0x004a9703
0x004a9703:	xorl %ecx, %ecx
0x004a9705:	subl %eax, $0x3<UINT8>
0x004a9708:	jb 0x004a971b
0x004a971b:	addl %ebx, %ebx
0x004a971d:	jne 0x004a9726
0x004a9726:	jb 0x004a96f4
0x004a96f4:	addl %ebx, %ebx
0x004a96f6:	jne 0x004a96ff
0x004a96ff:	adcl %ecx, %ecx
0x004a9701:	jmp 0x004a9755
0x004a9755:	cmpl %ebp, $0xfffffb00<UINT32>
0x004a975b:	adcl %ecx, $0x2<UINT8>
0x004a975e:	leal %edx, (%edi,%ebp)
0x004a9761:	cmpl %ebp, $0xfffffffc<UINT8>
0x004a9764:	jbe 0x004a9774
0x004a9766:	movb %al, (%edx)
0x004a9768:	incl %edx
0x004a9769:	movb (%edi), %al
0x004a976b:	incl %edi
0x004a976c:	decl %ecx
0x004a976d:	jne 0x004a9766
0x004a976f:	jmp 0x004a96b6
0x004a970a:	shll %eax, $0x8<UINT8>
0x004a970d:	movb %al, (%esi)
0x004a970f:	incl %esi
0x004a9710:	xorl %eax, $0xffffffff<UINT8>
0x004a9713:	je 0x004a978a
0x004a9715:	sarl %eax
0x004a9717:	movl %ebp, %eax
0x004a9719:	jmp 0x004a9726
0x004a9728:	incl %ecx
0x004a9729:	addl %ebx, %ebx
0x004a972b:	jne 0x004a9734
0x004a9734:	jb 0x004a96f4
0x004a9774:	movl %eax, (%edx)
0x004a9776:	addl %edx, $0x4<UINT8>
0x004a9779:	movl (%edi), %eax
0x004a977b:	addl %edi, $0x4<UINT8>
0x004a977e:	subl %ecx, $0x4<UINT8>
0x004a9781:	ja 0x004a9774
0x004a9783:	addl %edi, %ecx
0x004a9785:	jmp 0x004a96b6
0x004a96db:	movl %ebx, (%esi)
0x004a96dd:	subl %esi, $0xfffffffc<UINT8>
0x004a96e0:	adcl %ebx, %ebx
0x004a96e2:	jb 0x004a9703
0x004a96f8:	movl %ebx, (%esi)
0x004a96fa:	subl %esi, $0xfffffffc<UINT8>
0x004a96fd:	adcl %ebx, %ebx
0x004a96cc:	movl %ebx, (%esi)
0x004a96ce:	subl %esi, $0xfffffffc<UINT8>
0x004a96d1:	adcl %ebx, %ebx
0x004a9736:	addl %ebx, %ebx
0x004a9738:	jne 0x004a9741
0x004a9741:	adcl %ecx, %ecx
0x004a9743:	addl %ebx, %ebx
0x004a9745:	jae 0x004a9736
0x004a9747:	jne 0x004a9752
0x004a9752:	addl %ecx, $0x2<UINT8>
0x004a972d:	movl %ebx, (%esi)
0x004a972f:	subl %esi, $0xfffffffc<UINT8>
0x004a9732:	adcl %ebx, %ebx
0x004a96e4:	decl %eax
0x004a96e5:	addl %ebx, %ebx
0x004a96e7:	jne 0x004a96f0
0x004a96f0:	adcl %eax, %eax
0x004a96f2:	jmp 0x004a96c8
0x004a973a:	movl %ebx, (%esi)
0x004a973c:	subl %esi, $0xfffffffc<UINT8>
0x004a973f:	adcl %ebx, %ebx
0x004a9749:	movl %ebx, (%esi)
0x004a974b:	subl %esi, $0xfffffffc<UINT8>
0x004a974e:	adcl %ebx, %ebx
0x004a9750:	jae 0x004a9736
0x004a971f:	movl %ebx, (%esi)
0x004a9721:	subl %esi, $0xfffffffc<UINT8>
0x004a9724:	adcl %ebx, %ebx
0x004a96e9:	movl %ebx, (%esi)
0x004a96eb:	subl %esi, $0xfffffffc<UINT8>
0x004a96ee:	adcl %ebx, %ebx
0x004a978a:	popl %esi
0x004a978b:	movl %edi, %esi
0x004a978d:	movl %ecx, $0x3e4c<UINT32>
0x004a9792:	movb %al, (%edi)
0x004a9794:	incl %edi
0x004a9795:	subb %al, $0xffffffe8<UINT8>
0x004a9797:	cmpb %al, $0x1<UINT8>
0x004a9799:	ja 0x004a9792
0x004a979b:	cmpb (%edi), $0x1c<UINT8>
0x004a979e:	jne 0x004a9792
0x004a97a0:	movl %eax, (%edi)
0x004a97a2:	movb %bl, 0x4(%edi)
0x004a97a5:	shrw %ax, $0x8<UINT8>
0x004a97a9:	roll %eax, $0x10<UINT8>
0x004a97ac:	xchgb %ah, %al
0x004a97ae:	subl %eax, %edi
0x004a97b0:	subb %bl, $0xffffffe8<UINT8>
0x004a97b3:	addl %eax, %esi
0x004a97b5:	movl (%edi), %eax
0x004a97b7:	addl %edi, $0x5<UINT8>
0x004a97ba:	movb %al, %bl
0x004a97bc:	loop 0x004a9797
0x004a97be:	leal %edi, 0xa6000(%esi)
0x004a97c4:	movl %eax, (%edi)
0x004a97c6:	orl %eax, %eax
0x004a97c8:	je 0x004a9806
0x004a97ca:	movl %ebx, 0x4(%edi)
0x004a97cd:	leal %eax, 0xabcac(%eax,%esi)
0x004a97d4:	addl %ebx, %esi
0x004a97d6:	pushl %eax
0x004a97d7:	addl %edi, $0x8<UINT8>
0x004a97da:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x004a97e0:	xchgl %ebp, %eax
0x004a97e1:	movb %al, (%edi)
0x004a97e3:	incl %edi
0x004a97e4:	orb %al, %al
0x004a97e6:	je 0x004a97c4
0x004a97e8:	movl %ecx, %edi
0x004a97ea:	pushl %edi
0x004a97eb:	decl %eax
0x004a97ec:	repn scasb %al, %es:(%edi)
0x004a97ee:	pushl %ebp
0x004a97ef:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x004a97f5:	orl %eax, %eax
0x004a97f7:	je 7
0x004a97f9:	movl (%ebx), %eax
0x004a97fb:	addl %ebx, $0x4<UINT8>
0x004a97fe:	jmp 0x004a97e1
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x004a9806:	movl %ebp, 0xabdb4(%esi)
0x004a980c:	leal %edi, -4096(%esi)
0x004a9812:	movl %ebx, $0x1000<UINT32>
0x004a9817:	pushl %eax
0x004a9818:	pushl %esp
0x004a9819:	pushl $0x4<UINT8>
0x004a981b:	pushl %ebx
0x004a981c:	pushl %edi
0x004a981d:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x004a981f:	leal %eax, 0x21f(%edi)
0x004a9825:	andb (%eax), $0x7f<UINT8>
0x004a9828:	andb 0x28(%eax), $0x7f<UINT8>
0x004a982c:	popl %eax
0x004a982d:	pushl %eax
0x004a982e:	pushl %esp
0x004a982f:	pushl %eax
0x004a9830:	pushl %ebx
0x004a9831:	pushl %edi
0x004a9832:	call VirtualProtect@kernel32.dll
0x004a9834:	popl %eax
0x004a9835:	popa
0x004a9836:	leal %eax, -128(%esp)
0x004a983a:	pushl $0x0<UINT8>
0x004a983c:	cmpl %esp, %eax
0x004a983e:	jne 0x004a983a
0x004a9840:	subl %esp, $0xffffff80<UINT8>
0x004a9843:	jmp 0x00482628
0x00482628:	pushl %ebp
0x00482629:	movl %ebp, %esp
0x0048262b:	addl %esp, $0xfffffff0<UINT8>
0x0048262e:	pushl %ebx
0x0048262f:	movl %eax, $0x4823e0<UINT32>
0x00482634:	call 0x00406d20
0x00406d20:	pushl %ebx
0x00406d21:	movl %ebx, %eax
0x00406d23:	xorl %eax, %eax
0x00406d25:	movl 0x4830a0, %eax
0x00406d2a:	pushl $0x0<UINT8>
0x00406d2c:	call 0x00406c5c
0x00406c5c:	jmp GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x00406d31:	movl 0x485668, %eax
0x00406d36:	movl %eax, 0x485668
0x00406d3b:	movl 0x4830ac, %eax
0x00406d40:	xorl %eax, %eax
0x00406d42:	movl 0x4830b0, %eax
0x00406d47:	xorl %eax, %eax
0x00406d49:	movl 0x4830b4, %eax
0x00406d4e:	call 0x00406d14
0x00406d14:	movl %eax, $0x4830a8<UINT32>
0x00406d19:	call 0x00406510
0x00406510:	movl %edx, 0x483038
0x00406516:	movl (%eax), %edx
0x00406518:	movl 0x483038, %eax
0x0040651d:	ret

0x00406d1e:	ret

0x00406d53:	movl %edx, $0x4830a8<UINT32>
0x00406d58:	movl %eax, %ebx
0x00406d5a:	call 0x00404714
0x00404714:	movl 0x485014, $0x401244<UINT32>
0x0040471e:	movl 0x485018, $0x401254<UINT32>
0x00404728:	movl 0x485640, %eax
0x0040472d:	xorl %eax, %eax
0x0040472f:	movl 0x485644, %eax
0x00404734:	movl 0x485648, %edx
0x0040473a:	movl %eax, 0x4(%edx)
0x0040473d:	movl 0x485030, %eax
0x00404742:	call 0x004045ec
0x004045ec:	xorl %edx, %edx
0x004045ee:	leal %eax, -12(%ebp)
0x004045f1:	movl %ecx, %fs:(%edx)
0x004045f4:	movl %fs:(%edx), %eax
0x004045f7:	movl (%eax), %ecx
0x004045f9:	movl 0x4(%eax), $0x40454c<UINT32>
0x00404600:	movl 0x8(%eax), %ebp
0x00404603:	movl 0x48563c, %eax
0x00404608:	ret

0x00404747:	movb 0x485038, $0x0<UINT8>
0x0040474e:	call 0x004046a4
0x004046a4:	pushl %ebp
0x004046a5:	movl %ebp, %esp
0x004046a7:	addl %esp, $0xfffffff8<UINT8>
0x004046aa:	pushl %ebx
0x004046ab:	pushl %esi
0x004046ac:	pushl %edi
0x004046ad:	movl %edi, $0x485638<UINT32>
0x004046b2:	movl %eax, 0x8(%edi)
0x004046b5:	testl %eax, %eax
0x004046b7:	je 84
0x004046b9:	movl %esi, (%eax)
0x004046bb:	xorl %ebx, %ebx
0x004046bd:	movl %eax, 0x4(%eax)
0x004046c0:	movl -4(%ebp), %eax
0x004046c3:	xorl %eax, %eax
0x004046c5:	pushl %ebp
0x004046c6:	pushl $0x4046f9<UINT32>
0x004046cb:	pushl %fs:(%eax)
0x004046ce:	movl %fs:(%eax), %esp
0x004046d1:	cmpl %esi, %ebx
0x004046d3:	jle 26
0x004046d5:	movl %eax, -4(%ebp)
0x004046d8:	movl %eax, (%eax,%ebx,8)
0x004046db:	movl -8(%ebp), %eax
0x004046de:	incl %ebx
0x004046df:	movl 0xc(%edi), %ebx
0x004046e2:	cmpl -8(%ebp), $0x0<UINT8>
0x004046e6:	je 3
0x004046e8:	call 0x00429b34
0x00406d94:	subl 0x48566c, $0x1<UINT8>
0x00406d9b:	ret

0x004046eb:	cmpl %esi, %ebx
0x004046ed:	jg 0x004046d5
0x00406b88:	subl 0x4855bc, $0x1<UINT8>
0x00406b8f:	jae 197
0x00406b95:	movb 0x483008, $0x2<UINT8>
0x00406b9c:	movl 0x485014, $0x401244<UINT32>
0x00406ba6:	movl 0x485018, $0x401254<UINT32>
0x00406bb0:	movb 0x48504e, $0x2<UINT8>
0x00406bb7:	movl 0x485000, $0x405a0c<UINT32>
0x00406bc1:	call 0x00403a84
0x00403a84:	pushl %ebx
0x00403a85:	xorl %ebx, %ebx
0x00403a87:	pushl $0x0<UINT8>
0x00403a89:	call 0x00403a7c
0x00403a7c:	jmp GetKeyboardType@user32.dll
GetKeyboardType@user32.dll: API Node	
0x00403a8e:	cmpl %eax, $0x7<UINT8>
0x00403a91:	jne 28
0x00403a93:	pushl $0x1<UINT8>
0x00403a95:	call 0x00403a7c
0x00403a9a:	andl %eax, $0xff00<UINT32>
0x00403a9f:	cmpl %eax, $0xd00<UINT32>
0x00403aa4:	je 7
0x00403aa6:	cmpl %eax, $0x400<UINT32>
0x00403aab:	jne 0x00403aaf
0x00403aaf:	movl %eax, %ebx
0x00403ab1:	popl %ebx
0x00403ab2:	ret

0x00406bc6:	testb %al, %al
0x00406bc8:	je 0x00406bcf
0x00406bcf:	call 0x00403b78
0x00403b78:	fninit
0x00403b7a:	fwait
0x00403b7b:	fldcw 0x483020
0x00403b81:	ret

0x00406bd4:	movw 0x485054, $0xffffd7b0<UINT16>
0x00406bdd:	movw 0x485220, $0xffffd7b0<UINT16>
0x00406be6:	movw 0x4853ec, $0xffffd7b0<UINT16>
0x00406bef:	call 0x004012bc
0x004012bc:	jmp GetCommandLineA@KERNEL32.DLL
GetCommandLineA@KERNEL32.DLL: API Node	
0x00406bf4:	movl 0x485040, %eax
0x00406bf9:	call 0x00401384
0x00401384:	pushl %ebx
0x00401385:	addl %esp, $0xffffffbc<UINT8>
0x00401388:	movl %ebx, $0xa<UINT32>
0x0040138d:	pushl %esp
0x0040138e:	call 0x004012ec
0x004012ec:	jmp GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x00401393:	testb 0x2c(%esp), $0x1<UINT8>
0x00401398:	je 0x0040139f
0x0040139f:	movl %eax, %ebx
0x004013a1:	addl %esp, $0x44<UINT8>
0x004013a4:	popl %ebx
0x004013a5:	ret

0x00406bfe:	movl 0x48503c, %eax
0x00406c03:	call 0x0040137c
0x0040137c:	jmp GetVersion@KERNEL32.DLL
GetVersion@KERNEL32.DLL: API Node	
0x00406c08:	andl %eax, $0x80000000<UINT32>
0x00406c0d:	cmpl %eax, $0x80000000<UINT32>
0x00406c12:	je 45
0x00406c14:	call 0x0040137c
0x00406c19:	andl %eax, $0xff<UINT32>
0x00406c1e:	cmpw %ax, $0x4<UINT8>
0x00406c22:	jbe 12
0x00406c24:	movl 0x4855c0, $0x3<UINT32>
0x00406c2e:	jmp 0x00406c50
0x00406c50:	call 0x00401374
0x00401374:	jmp GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x00406c55:	movl 0x485034, %eax
0x00406c5a:	ret

0x00406e24:	subl 0x485674, $0x1<UINT8>
0x00406e2b:	ret

0x00407ba4:	subl 0x485678, $0x1<UINT8>
0x00407bab:	ret

0x00407bdc:	subl 0x48567c, $0x1<UINT8>
0x00407be3:	ret

0x00415fc4:	subl 0x485848, $0x1<UINT8>
0x00415fcb:	ret

0x00407f24:	subl 0x485680, $0x1<UINT8>
0x00407f2b:	ret

0x0040f218:	pushl %ebp
0x0040f219:	movl %ebp, %esp
0x0040f21b:	xorl %eax, %eax
0x0040f21d:	pushl %ebp
0x0040f21e:	pushl $0x40f280<UINT32>
0x0040f223:	pushl %fs:(%eax)
0x0040f226:	movl %fs:(%eax), %esp
0x0040f229:	subl 0x485794, $0x1<UINT8>
0x0040f230:	jae 64
0x0040f232:	movl %eax, $0x40edc8<UINT32>
0x0040f237:	call 0x00404778
0x00404778:	pushl %ebx
0x00404779:	xorl %ebx, %ebx
0x0040477b:	pushl %edi
0x0040477c:	pushl %esi
0x0040477d:	movl %edi, (%eax,%ebx)
0x00404780:	leal %esi, 0x4(%eax,%ebx)
0x00404784:	movl %eax, 0x4(%esi)
0x00404787:	movl %edx, (%esi)
0x00404789:	movl %eax, (%eax,%ebx)
0x0040478c:	addl %edx, %ebx
0x0040478e:	call 0x00406a68
0x00406a68:	pushl %ebx
0x00406a69:	pushl %esi
0x00406a6a:	addl %esp, $0xfffff004<UINT32>
0x00406a70:	pushl %eax
0x00406a71:	movl %esi, %edx
0x00406a73:	movl %ebx, %eax
0x00406a75:	testl %ebx, %ebx
0x00406a77:	je 61
0x00406a79:	cmpl 0x4(%ebx), $0x10000<UINT32>
0x00406a80:	jnl 42
0x00406a82:	pushl $0x1000<UINT32>
0x00406a87:	leal %eax, 0x4(%esp)
0x00406a8b:	pushl %eax
0x00406a8c:	movl %eax, 0x4(%ebx)
0x00406a8f:	pushl %eax
0x00406a90:	movl %eax, (%ebx)
0x00406a92:	movl %eax, (%eax)
0x00406a94:	call 0x00405f2c
0x00405f2c:	pushl %ebx
0x00405f2d:	pushl %esi
0x00405f2e:	pushl %edi
0x00405f2f:	pushl %ecx
0x00405f30:	movl %ebx, %eax
0x00405f32:	movl %esi, %esp
0x00405f34:	movl %eax, 0x483038
0x00405f39:	movl (%esi), %eax
0x00405f3b:	cmpl (%esi), $0x0<UINT8>
0x00405f3e:	je 43
0x00405f40:	movl %eax, (%esi)
0x00405f42:	cmpl %ebx, 0x4(%eax)
0x00405f45:	je 0x00405f55
0x00405f55:	movl %eax, (%esi)
0x00405f57:	call 0x00405ee4
0x00405ee4:	pushl %ebx
0x00405ee5:	pushl %esi
0x00405ee6:	addl %esp, $0xfffffef8<UINT32>
0x00405eec:	movl %ebx, %eax
0x00405eee:	cmpl 0x10(%ebx), $0x0<UINT8>
0x00405ef2:	jne 0x00405f1f
0x00405ef4:	pushl $0x105<UINT32>
0x00405ef9:	leal %eax, 0x4(%esp)
0x00405efd:	pushl %eax
0x00405efe:	movl %eax, 0x4(%ebx)
0x00405f01:	pushl %eax
0x00405f02:	call 0x004012d4
0x004012d4:	jmp GetModuleFileNameA@KERNEL32.DLL
GetModuleFileNameA@KERNEL32.DLL: API Node	
0x00405f07:	movl %eax, %esp
0x00405f09:	movb %dl, $0x1<UINT8>
0x00405f0b:	call 0x00406178
0x00406178:	pushl %ebp
0x00406179:	movl %ebp, %esp
0x0040617b:	addl %esp, $0xfffffedc<UINT32>
0x00406181:	pushl %ebx
0x00406182:	movl -4(%ebp), %eax
0x00406185:	pushl $0x105<UINT32>
0x0040618a:	leal %eax, -289(%ebp)
0x00406190:	pushl %eax
0x00406191:	pushl $0x0<UINT8>
0x00406193:	call 0x004012d4
0x00406198:	movb -18(%ebp), $0x0<UINT8>
0x0040619c:	leal %eax, -8(%ebp)
0x0040619f:	pushl %eax
0x004061a0:	pushl $0xf0019<UINT32>
0x004061a5:	pushl $0x0<UINT8>
0x004061a7:	pushl $0x4063bc<UINT32>
0x004061ac:	pushl $0x80000001<UINT32>
0x004061b1:	call 0x0040132c
0x0040132c:	jmp RegOpenKeyExA@advapi32.dll
RegOpenKeyExA@advapi32.dll: API Node	
0x004061b6:	testl %eax, %eax
0x004061b8:	je 64
0x004061ba:	leal %eax, -8(%ebp)
0x004061bd:	pushl %eax
0x004061be:	pushl $0xf0019<UINT32>
0x004061c3:	pushl $0x0<UINT8>
0x004061c5:	pushl $0x4063bc<UINT32>
0x004061ca:	pushl $0x80000002<UINT32>
0x004061cf:	call 0x0040132c
0x004061d4:	testl %eax, %eax
0x004061d6:	je 34
0x004061d8:	leal %eax, -8(%ebp)
0x004061db:	pushl %eax
0x004061dc:	pushl $0xf0019<UINT32>
0x004061e1:	pushl $0x0<UINT8>
0x004061e3:	pushl $0x4063d8<UINT32>
0x004061e8:	pushl $0x80000001<UINT32>
0x004061ed:	call 0x0040132c
0x004061f2:	testl %eax, %eax
0x004061f4:	jne 0x00406283
0x00406283:	pushl $0x105<UINT32>
0x00406288:	movl %eax, -4(%ebp)
0x0040628b:	pushl %eax
0x0040628c:	leal %eax, -289(%ebp)
0x00406292:	pushl %eax
0x00406293:	call 0x0040130c
0x0040130c:	jmp lstrcpynA@KERNEL32.DLL
lstrcpynA@KERNEL32.DLL: API Node	
0x00406298:	pushl $0x5<UINT8>
0x0040629a:	leal %eax, -13(%ebp)
0x0040629d:	pushl %eax
0x0040629e:	pushl $0x3<UINT8>
0x004062a0:	call 0x004012f4
0x004012f4:	jmp GetThreadLocale@KERNEL32.DLL
GetThreadLocale@KERNEL32.DLL: API Node	
0x004062a5:	pushl %eax
0x004062a6:	call 0x004012cc
0x004012cc:	jmp GetLocaleInfoA@KERNEL32.DLL
GetLocaleInfoA@KERNEL32.DLL: API Node	
0x004062ab:	xorl %ebx, %ebx
0x004062ad:	cmpb -289(%ebp), $0x0<UINT8>
0x004062b4:	je 249
0x004062ba:	cmpb -13(%ebp), $0x0<UINT8>
0x004062be:	jne 0x004062ca
0x004062ca:	leal %eax, -289(%ebp)
0x004062d0:	pushl %eax
0x004062d1:	call 0x00401314
0x00401314:	jmp lstrlenA@KERNEL32.DLL
lstrlenA@KERNEL32.DLL: API Node	
0x004062d6:	leal %edx, -289(%ebp)
0x004062dc:	addl %eax, %edx
0x004062de:	movl -28(%ebp), %eax
0x004062e1:	jmp 0x004062e6
0x004062e6:	movl %eax, -28(%ebp)
0x004062e9:	cmpb (%eax), $0x2e<UINT8>
0x004062ec:	je 0x004062f9
0x004062ee:	leal %eax, -289(%ebp)
0x004062f4:	cmpl %eax, -28(%ebp)
0x004062f7:	jne 0x004062e3
0x004062e3:	decl -28(%ebp)
0x004062f9:	leal %eax, -289(%ebp)
0x004062ff:	cmpl %eax, -28(%ebp)
0x00406302:	je 171
0x00406308:	incl -28(%ebp)
0x0040630b:	cmpb -18(%ebp), $0x0<UINT8>
0x0040630f:	je 0x0040633d
0x0040633d:	testl %ebx, %ebx
0x0040633f:	jne 114
0x00406341:	cmpb -13(%ebp), $0x0<UINT8>
0x00406345:	je 108
0x00406347:	leal %eax, -289(%ebp)
0x0040634d:	movl %edx, -28(%ebp)
0x00406350:	subl %edx, %eax
0x00406352:	movl %eax, $0x105<UINT32>
0x00406357:	subl %eax, %edx
0x00406359:	pushl %eax
0x0040635a:	leal %eax, -13(%ebp)
0x0040635d:	pushl %eax
0x0040635e:	movl %eax, -28(%ebp)
0x00406361:	pushl %eax
0x00406362:	call 0x0040130c
0x00406367:	pushl $0x2<UINT8>
0x00406369:	pushl $0x0<UINT8>
0x0040636b:	leal %eax, -289(%ebp)
0x00406371:	pushl %eax
0x00406372:	call 0x004012fc
0x004012fc:	jmp LoadLibraryExA@KERNEL32.DLL
LoadLibraryExA@KERNEL32.DLL: API Node	
0x00406377:	movl %ebx, %eax
0x00406379:	testl %ebx, %ebx
0x0040637b:	jne 54
0x0040637d:	movb -11(%ebp), $0x0<UINT8>
0x00406381:	leal %eax, -289(%ebp)
0x00406387:	movl %edx, -28(%ebp)
0x0040638a:	subl %edx, %eax
0x0040638c:	movl %eax, $0x105<UINT32>
0x00406391:	subl %eax, %edx
0x00406393:	pushl %eax
0x00406394:	leal %eax, -13(%ebp)
0x00406397:	pushl %eax
0x00406398:	movl %eax, -28(%ebp)
0x0040639b:	pushl %eax
0x0040639c:	call 0x0040130c
0x004063a1:	pushl $0x2<UINT8>
0x004063a3:	pushl $0x0<UINT8>
0x004063a5:	leal %eax, -289(%ebp)
0x004063ab:	pushl %eax
0x004063ac:	call 0x004012fc
0x004063b1:	movl %ebx, %eax
0x004063b3:	movl %eax, %ebx
0x004063b5:	popl %ebx
0x004063b6:	movl %esp, %ebp
0x004063b8:	popl %ebp
0x004063b9:	ret

0x00405f10:	movl %esi, %eax
0x00405f12:	movl 0x10(%ebx), %esi
0x00405f15:	testl %esi, %esi
0x00405f17:	jne 6
0x00405f19:	movl %eax, 0x4(%ebx)
0x00405f1c:	movl 0x10(%ebx), %eax
0x00405f1f:	movl %eax, 0x10(%ebx)
0x00405f22:	addl %esp, $0x108<UINT32>
0x00405f28:	popl %esi
0x00405f29:	popl %ebx
0x00405f2a:	ret

0x00405f5c:	movl %edi, %eax
0x00405f5e:	jmp 0x00405f6d
0x00405f6d:	movl %eax, %edi
0x00405f6f:	popl %edx
0x00405f70:	popl %edi
0x00405f71:	popl %esi
0x00405f72:	popl %ebx
0x00405f73:	ret

0x00406a99:	pushl %eax
0x00406a9a:	call 0x00401304
0x00401304:	jmp LoadStringA@user32.dll
LoadStringA@user32.dll: API Node	
0x00406a9f:	movl %ecx, %eax
0x00406aa1:	movl %edx, %esp
0x00406aa3:	movl %eax, %esi
0x00406aa5:	call 0x00404b48
0x00404b48:	pushl %ebx
0x00404b49:	pushl %esi
0x00404b4a:	pushl %edi
0x00404b4b:	movl %ebx, %eax
0x00404b4d:	movl %esi, %edx
0x00404b4f:	movl %edi, %ecx
0x00404b51:	movl %eax, %edi
0x00404b53:	call 0x00404b1c
0x00404b1c:	testl %eax, %eax
0x00404b1e:	jle 0x00404b44
0x00404b44:	xorl %eax, %eax
0x00404b46:	ret

0x00404b58:	movl %ecx, %edi
0x00404b5a:	movl %edi, %eax
0x00404b5c:	testl %esi, %esi
0x00404b5e:	je 9
0x00404b60:	movl %edx, %eax
0x00404b62:	movl %eax, %esi
0x00404b64:	call 0x00402cc0
0x00402cc0:	pushl %esi
0x00402cc1:	pushl %edi
0x00402cc2:	movl %esi, %eax
0x00402cc4:	movl %edi, %edx
0x00402cc6:	movl %eax, %ecx
0x00402cc8:	cmpl %edi, %esi
0x00402cca:	ja 0x00402cdf
0x00402ccc:	je 47
0x00402cce:	sarl %ecx, $0x2<UINT8>
0x00402cd1:	js 42
0x00402cd3:	rep movsl %es:(%edi), %ds:(%esi)
0x00402cd5:	movl %ecx, %eax
0x00402cd7:	andl %ecx, $0x3<UINT8>
0x00402cda:	rep movsb %es:(%edi), %ds:(%esi)
0x00402cdc:	popl %edi
0x00402cdd:	popl %esi
0x00402cde:	ret

0x00404b69:	movl %eax, %ebx
0x00404b6b:	call 0x00404a58
0x00404a58:	movl %edx, (%eax)
0x00404a5a:	testl %edx, %edx
0x00404a5c:	je 0x00404a7a
0x00404a7a:	ret

0x00404b70:	movl (%ebx), %edi
0x00404b72:	popl %edi
0x00404b73:	popl %esi
0x00404b74:	popl %ebx
0x00404b75:	ret

0x00406aaa:	jmp 0x00406ab6
0x00406ab6:	addl %esp, $0x1000<UINT32>
0x00406abc:	popl %esi
0x00406abd:	popl %ebx
0x00406abe:	ret

0x00404793:	addl %esi, $0x8<UINT8>
0x00404796:	decl %edi
0x00404797:	jne 0x00404784
0x00404799:	popl %esi
0x0040479a:	popl %edi
0x0040479b:	popl %ebx
0x0040479c:	ret

0x0040f23c:	movl %eax, $0x40eeb4<UINT32>
0x0040f241:	call 0x004047a0
0x004047a0:	pushl %ebx
0x004047a1:	xorl %ebx, %ebx
0x004047a3:	pushl %edi
0x004047a4:	pushl %esi
0x004047a5:	movl %edi, (%eax,%ebx)
0x004047a8:	leal %esi, 0x4(%eax,%ebx)
0x004047ac:	movl %eax, 0x4(%esi)
0x004047af:	movl %edx, (%esi)
0x004047b1:	movl %eax, (%eax,%ebx)
0x004047b4:	addl %eax, 0x8(%esi)
0x004047b7:	movl (%edx,%ebx), %eax
0x004047ba:	addl %esi, $0xc<UINT8>
0x004047bd:	decl %edi
0x004047be:	jne 0x004047ac
0x004047c0:	popl %esi
0x004047c1:	popl %edi
0x004047c2:	popl %ebx
0x004047c3:	ret

0x0040f246:	cmpb 0x485665, $0x0<UINT8>
0x0040f24d:	je 0x0040f25e
0x0040f25e:	call 0x0040d6f8
0x0040d6f8:	movl %ecx, 0x48447c
0x0040d6fe:	movb %dl, $0x1<UINT8>
0x0040d700:	movl %eax, 0x408020
0x0040d705:	call 0x0040d0a8
0x0040d0a8:	pushl %ebx
0x0040d0a9:	pushl %esi
0x0040d0aa:	pushl %edi
0x0040d0ab:	testb %dl, %dl
0x0040d0ad:	je 8
0x0040d0af:	addl %esp, $0xfffffff0<UINT8>
0x0040d0b2:	call 0x00403f80
0x00403f80:	pushl %edx
0x00403f81:	pushl %ecx
0x00403f82:	pushl %ebx
0x00403f83:	testb %dl, %dl
0x00403f85:	jl 3
0x00403f87:	call 0x00403be0
0x00403be0:	pushl %ebx
0x00403be1:	movl %ebx, %eax
0x00403be3:	movl %eax, %ebx
0x00403be5:	call 0x00403c10
0x00403c10:	addl %eax, $0xffffffd8<UINT8>
0x00403c13:	movl %eax, (%eax)
0x00403c15:	ret

0x00403bea:	call 0x00402aa0
0x00402aa0:	pushl %ebx
0x00402aa1:	pushl %ecx
0x00402aa2:	movl %ebx, %eax
0x00402aa4:	testl %ebx, %ebx
0x00402aa6:	jle 26
0x00402aa8:	movl %eax, %ebx
0x00402aaa:	call 0x0040244c
0x0040244c:	pushl %ebp
0x0040244d:	movl %ebp, %esp
0x0040244f:	addl %esp, $0xffffffec<UINT8>
0x00402452:	pushl %ebx
0x00402453:	movl %ebx, %eax
0x00402455:	cmpb 0x4855c4, $0x0<UINT8>
0x0040245c:	jne 0x00402467
0x0040245e:	call 0x00401bf0
0x00401bf0:	pushl %ebp
0x00401bf1:	movl %ebp, %esp
0x00401bf3:	pushl %ecx
0x00401bf4:	xorl %edx, %edx
0x00401bf6:	pushl %ebp
0x00401bf7:	pushl $0x401cb8<UINT32>
0x00401bfc:	pushl %fs:(%edx)
0x00401bff:	movl %fs:(%edx), %esp
0x00401c02:	pushl $0x4855cc<UINT32>
0x00401c07:	call 0x004013c8
0x004013c8:	jmp InitializeCriticalSection@KERNEL32.DLL
InitializeCriticalSection@KERNEL32.DLL: API Node	
0x00401c0c:	cmpb 0x48504d, $0x0<UINT8>
0x00401c13:	je 0x00401c1f
0x00401c1f:	movl %eax, $0x4855ec<UINT32>
0x00401c24:	call 0x0040146c
0x0040146c:	movl (%eax), %eax
0x0040146e:	movl 0x4(%eax), %eax
0x00401471:	ret

0x00401c29:	movl %eax, $0x4855fc<UINT32>
0x00401c2e:	call 0x0040146c
0x00401c33:	movl %eax, $0x485628<UINT32>
0x00401c38:	call 0x0040146c
0x00401c3d:	pushl $0xff8<UINT32>
0x00401c42:	pushl $0x0<UINT8>
0x00401c44:	call 0x004013a8
0x004013a8:	jmp LocalAlloc@KERNEL32.DLL
LocalAlloc@KERNEL32.DLL: API Node	
0x00401c49:	movl 0x485624, %eax
0x00401c4e:	cmpl 0x485624, $0x0<UINT8>
0x00401c55:	je 64
0x00401c57:	movl %eax, $0x3<UINT32>
0x00401c5c:	movl %edx, 0x485624
0x00401c62:	xorl %ecx, %ecx
0x00401c64:	movl -12(%edx,%eax,4), %ecx
0x00401cb8:	jmp 0x004043b0
0x004043b0:	movl %eax, 0x4(%esp)
0x004043b4:	movl %edx, 0x8(%esp)
0x004043b8:	testl 0x4(%eax), $0x6<UINT32>
0x004043bf:	je 0x004043e0
0x004043e0:	movl %eax, $0x1<UINT32>
0x004043e5:	ret

0x00401c68:	incl %eax
0x00401c69:	cmpl %eax, $0x401<UINT32>
0x00401c6e:	jne 0x00401c5c
0x00401c70:	movl -4(%ebp), $0x48560c<UINT32>
0x00401c77:	movl %eax, -4(%ebp)
0x00401c7a:	movl %edx, -4(%ebp)
0x00401c7d:	movl 0x4(%eax), %edx
0x00401c80:	movl %eax, -4(%ebp)
0x00401c83:	movl %edx, -4(%ebp)
0x00401c86:	movl (%eax), %edx
0x00401c88:	movl %eax, -4(%ebp)
0x00401c8b:	movl 0x485618, %eax
0x00401c90:	movb 0x4855c4, $0x1<UINT8>
0x00401c97:	xorl %eax, %eax
0x00401c99:	popl %edx
0x00401c9a:	popl %ecx
0x00401c9b:	popl %ecx
0x00401c9c:	movl %fs:(%eax), %edx
0x00401c9f:	pushl $0x401cbf<UINT32>
0x00401ca4:	cmpb 0x48504d, $0x0<UINT8>
0x00401cab:	je 0x00401cb7
0x00401cb7:	ret

0x00401cbf:	movb %al, 0x4855c4
0x00401cc4:	popl %ecx
0x00401cc5:	popl %ebp
0x00401cc6:	ret

0x00402463:	testb %al, %al
0x00402465:	je 8
0x00402467:	cmpl %ebx, $0x7ffffff8<UINT32>
0x0040246d:	jle 0x00402479
0x00402479:	xorl %edx, %edx
0x0040247b:	pushl %ebp
0x0040247c:	pushl $0x4025e8<UINT32>
0x00402481:	pushl %fs:(%edx)
0x00402484:	movl %fs:(%edx), %esp
0x00402487:	cmpb 0x48504d, $0x0<UINT8>
0x0040248e:	je 0x0040249a
0x0040249a:	addl %ebx, $0x7<UINT8>
0x0040249d:	andl %ebx, $0xfffffffc<UINT8>
0x004024a0:	cmpl %ebx, $0xc<UINT8>
0x004024a3:	jnl 0x004024aa
0x004024aa:	cmpl %ebx, $0x1000<UINT32>
0x004024b0:	jg 172
0x004024b6:	movl %eax, %ebx
0x004024b8:	testl %eax, %eax
0x004024ba:	jns 0x004024bf
0x004024bf:	sarl %eax, $0x2<UINT8>
0x004024c2:	movl %edx, 0x485624
0x004024c8:	movl %edx, -12(%edx,%eax,4)
0x004024cc:	movl -8(%ebp), %edx
0x004024cf:	cmpl -8(%ebp), $0x0<UINT8>
0x004024d3:	je 0x00402562
0x00402562:	cmpl %ebx, 0x48561c
0x00402568:	jg 0x004025bd
0x004025bd:	movl %eax, %ebx
0x004025bf:	call 0x00402304
0x00402304:	pushl %ebx
0x00402305:	pushl %esi
0x00402306:	pushl %edi
0x00402307:	pushl %ebp
0x00402308:	addl %esp, $0xfffffff4<UINT8>
0x0040230b:	movl %ebx, %eax
0x0040230d:	leal %esi, 0x8(%esp)
0x00402311:	movl %edi, $0x485618<UINT32>
0x00402316:	movl %ebp, $0x48561c<UINT32>
0x0040231b:	movl %eax, 0x485610
0x00402320:	movl (%esi), %eax
0x00402322:	movl %eax, (%esi)
0x00402324:	cmpl %ebx, 0x8(%eax)
0x00402327:	jle 0x004023d8
0x0040232d:	movl %eax, (%edi)
0x0040232f:	movl (%esi), %eax
0x00402331:	movl %eax, (%esi)
0x00402333:	movl %eax, 0x8(%eax)
0x00402336:	cmpl %ebx, %eax
0x00402338:	jle 154
0x0040233e:	movl %edx, (%esi)
0x00402340:	movl 0x8(%edx), %ebx
0x00402343:	movl %edx, (%esi)
0x00402345:	movl %edx, 0x4(%edx)
0x00402348:	movl (%esi), %edx
0x0040234a:	movl %edx, (%esi)
0x0040234c:	cmpl %ebx, 0x8(%edx)
0x0040234f:	jg -14
0x00402351:	movl %edx, (%edi)
0x00402353:	movl 0x8(%edx), %eax
0x00402356:	movl %eax, (%esi)
0x00402358:	cmpl %eax, (%edi)
0x0040235a:	je 0x00402362
0x00402362:	cmpl %ebx, $0x1000<UINT32>
0x00402368:	jg 14
0x0040236a:	movl %eax, %ebx
0x0040236c:	call 0x004022cc
0x004022cc:	pushl %ecx
0x004022cd:	movl %edx, %esp
0x004022cf:	xorl %ecx, %ecx
0x004022d1:	movl (%edx), %ecx
0x004022d3:	testl %eax, %eax
0x004022d5:	jns 0x004022da
0x004022da:	sarl %eax, $0x2<UINT8>
0x004022dd:	cmpl %eax, $0x400<UINT32>
0x004022e2:	jg 25
0x004022e4:	movl %ecx, 0x485624
0x004022ea:	movl %ecx, -12(%ecx,%eax,4)
0x004022ee:	movl (%edx), %ecx
0x004022f0:	cmpl (%edx), $0x0<UINT8>
0x004022f3:	jne 8
0x004022f5:	incl %eax
0x004022f6:	cmpl %eax, $0x401<UINT32>
0x004022fb:	jne 0x004022e4
0x004022fd:	movl %eax, (%edx)
0x004022ff:	popl %edx
0x00402300:	ret

0x00402371:	movl (%esi), %eax
0x00402373:	cmpl (%esi), $0x0<UINT8>
0x00402376:	jne 96
0x00402378:	movl %eax, %ebx
0x0040237a:	call 0x0040226c
0x0040226c:	pushl %ebx
0x0040226d:	addl %esp, $0xfffffff8<UINT8>
0x00402270:	movl %ebx, %eax
0x00402272:	movl %edx, %esp
0x00402274:	leal %eax, 0x4(%ebx)
0x00402277:	call 0x00401970
0x00401970:	pushl %ebx
0x00401971:	pushl %esi
0x00401972:	pushl %edi
0x00401973:	pushl %ebp
0x00401974:	addl %esp, $0xfffffff4<UINT8>
0x00401977:	movl %ebx, %edx
0x00401979:	movl %esi, %eax
0x0040197b:	movl %edi, %esp
0x0040197d:	movl %ebp, $0x4855fc<UINT32>
0x00401982:	addl %esi, $0x3fff<UINT32>
0x00401988:	andl %esi, $0xffffc000<UINT32>
0x0040198e:	movl %eax, (%ebp)
0x00401991:	movl (%edi), %eax
0x00401993:	jmp 0x004019d6
0x004019d6:	cmpl %ebp, (%edi)
0x004019d8:	jne 0x00401995
0x004019da:	movl %edx, %ebx
0x004019dc:	movl %eax, %esi
0x004019de:	call 0x00401650
0x00401650:	pushl %ebx
0x00401651:	pushl %esi
0x00401652:	pushl %edi
0x00401653:	movl %ebx, %edx
0x00401655:	movl %esi, %eax
0x00401657:	cmpl %esi, $0x100000<UINT32>
0x0040165d:	jnl 7
0x0040165f:	movl %esi, $0x100000<UINT32>
0x00401664:	jmp 0x00401672
0x00401672:	movl 0x4(%ebx), %esi
0x00401675:	pushl $0x1<UINT8>
0x00401677:	pushl $0x2000<UINT32>
0x0040167c:	pushl %esi
0x0040167d:	pushl $0x0<UINT8>
0x0040167f:	call 0x004013b8
0x004013b8:	jmp VirtualAlloc@KERNEL32.DLL
VirtualAlloc@KERNEL32.DLL: API Node	
0x00401684:	movl %edi, %eax
0x00401686:	movl (%ebx), %edi
0x00401688:	testl %edi, %edi
0x0040168a:	je 35
0x0040168c:	movl %edx, %ebx
0x0040168e:	movl %eax, $0x4855ec<UINT32>
0x00401693:	call 0x00401474
0x00401474:	pushl %ebx
0x00401475:	pushl %esi
0x00401476:	addl %esp, $0xfffffff8<UINT8>
0x00401479:	movl %esi, %edx
0x0040147b:	movl %ebx, %eax
0x0040147d:	call 0x004013e8
0x004013e8:	pushl %ebx
0x004013e9:	addl %esp, $0xfffffff4<UINT8>
0x004013ec:	movl %ebx, $0x4855e8<UINT32>
0x004013f1:	cmpl (%ebx), $0x0<UINT8>
0x004013f4:	jne 0x0040144f
0x004013f6:	pushl $0x644<UINT32>
0x004013fb:	pushl $0x0<UINT8>
0x004013fd:	call 0x004013a8
0x00401402:	movl 0x8(%esp), %eax
0x00401406:	cmpl 0x8(%esp), $0x0<UINT8>
0x0040140b:	jne 0x00401414
0x00401414:	movl %eax, 0x8(%esp)
0x00401418:	movl %edx, 0x4855e4
0x0040141e:	movl (%eax), %edx
0x004025e8:	jmp 0x004043b0
0x00401420:	movl %eax, 0x8(%esp)
0x00401424:	movl 0x4855e4, %eax
0x00401429:	xorl %eax, %eax
0x0040142b:	movl %edx, %eax
0x0040142d:	addl %edx, %edx
0x0040142f:	movl %ecx, 0x8(%esp)
0x00401433:	leal %edx, 0x4(%ecx,%edx,8)
0x00401437:	movl 0x4(%esp), %edx
0x0040143b:	movl %edx, 0x4(%esp)
0x0040143f:	movl %ecx, (%ebx)
0x00401441:	movl (%edx), %ecx
0x00401443:	movl %edx, 0x4(%esp)
0x00401447:	movl (%ebx), %edx
0x00401449:	incl %eax
0x0040144a:	cmpl %eax, $0x64<UINT8>
0x0040144d:	jne 0x0040142b
0x0040144f:	movl %eax, (%ebx)
0x00401451:	movl 0x4(%esp), %eax
0x00401455:	movl %eax, 0x4(%esp)
0x00401459:	movl %eax, (%eax)
0x0040145b:	movl (%ebx), %eax
0x0040145d:	movl %eax, 0x4(%esp)
0x00401461:	movl (%esp), %eax
0x00401464:	movl %eax, (%esp)
0x00401467:	addl %esp, $0xc<UINT8>
0x0040146a:	popl %ebx
0x0040146b:	ret

0x00401482:	movl 0x4(%esp), %eax
0x00401486:	cmpl 0x4(%esp), $0x0<UINT8>
0x0040148b:	jne 0x00401491
0x00401491:	movl %eax, (%esi)
0x00401493:	movl %edx, 0x4(%esp)
0x00401497:	movl 0x8(%edx), %eax
0x0040149a:	movl %eax, 0x4(%esi)
0x0040149d:	movl %edx, 0x4(%esp)
0x004014a1:	movl 0xc(%edx), %eax
0x004014a4:	movl %eax, (%ebx)
0x004014a6:	movl (%esp), %eax
0x004014a9:	movl %eax, 0x4(%esp)
0x004014ad:	movl %edx, (%esp)
0x004014b0:	movl (%eax), %edx
0x004014b2:	movl %eax, 0x4(%esp)
0x004014b6:	movl 0x4(%eax), %ebx
0x004014b9:	movl %eax, (%esp)
0x004014bc:	movl %edx, 0x4(%esp)
0x004014c0:	movl 0x4(%eax), %edx
0x004014c3:	movl %eax, 0x4(%esp)
0x004014c7:	movl (%ebx), %eax
0x004014c9:	movb %al, $0x1<UINT8>
0x004014cb:	popl %ecx
0x004014cc:	popl %edx
0x004014cd:	popl %esi
0x004014ce:	popl %ebx
0x004014cf:	ret

0x00401698:	testb %al, %al
0x0040169a:	jne 0x004016af
0x004016af:	popl %edi
0x004016b0:	popl %esi
0x004016b1:	popl %ebx
0x004016b2:	ret

0x004019e3:	cmpl (%ebx), $0x0<UINT8>
0x004019e6:	je 38
0x004019e8:	leal %ecx, 0x4(%esp)
0x004019ec:	movl %edx, %ebx
0x004019ee:	movl %eax, %ebp
0x004019f0:	call 0x00401504
0x00401504:	pushl %ebx
0x00401505:	pushl %esi
0x00401506:	pushl %edi
0x00401507:	pushl %ebp
0x00401508:	addl %esp, $0xfffffff8<UINT8>
0x0040150b:	movl %ebx, %ecx
0x0040150d:	movl %esi, %eax
0x0040150f:	movl %edi, %esp
0x00401511:	movl %eax, (%esi)
0x00401513:	movl (%edi), %eax
0x00401515:	movl %eax, (%edx)
0x00401517:	movl (%ebx), %eax
0x00401519:	movl %eax, 0x4(%edx)
0x0040151c:	movl 0x4(%ebx), %eax
0x0040151f:	movl %eax, (%edi)
0x00401521:	movl %eax, (%eax)
0x00401523:	movl 0x4(%esp), %eax
0x00401527:	movl %edx, (%edi)
0x00401529:	movl %edx, 0x8(%edx)
0x0040152c:	movl %ecx, %edx
0x0040152e:	movl %ebp, (%edi)
0x00401530:	addl %ecx, 0xc(%ebp)
0x00401533:	movl %eax, (%ebx)
0x00401535:	cmpl %ecx, %eax
0x00401537:	jne 0x00401551
0x00401551:	addl %eax, 0x4(%ebx)
0x00401554:	cmpl %edx, %eax
0x00401556:	jne 0x00401567
0x00401567:	movl %eax, 0x4(%esp)
0x0040156b:	movl (%edi), %eax
0x0040156d:	cmpl %esi, (%edi)
0x0040156f:	jne -82
0x00401571:	movl %edx, %ebx
0x00401573:	movl %eax, %esi
0x00401575:	call 0x00401474
0x0040157a:	testb %al, %al
0x0040157c:	jne 0x00401582
0x00401582:	popl %ecx
0x00401583:	popl %edx
0x00401584:	popl %ebp
0x00401585:	popl %edi
0x00401586:	popl %esi
0x00401587:	popl %ebx
0x00401588:	ret

0x004019f5:	cmpl 0x4(%esp), $0x0<UINT8>
0x004019fa:	jne 0x0040198e
0x00401995:	movl %eax, (%edi)
0x00401997:	cmpl %esi, 0xc(%eax)
0x0040199a:	jg 52
0x0040199c:	movl %ecx, %ebx
0x0040199e:	movl %eax, (%edi)
0x004019a0:	movl %eax, 0x8(%eax)
0x004019a3:	movl %edx, %esi
0x004019a5:	call 0x004017f4
0x004017f4:	pushl %ebx
0x004017f5:	pushl %esi
0x004017f6:	pushl %edi
0x004017f7:	pushl %ebp
0x004017f8:	addl %esp, $0xffffffe8<UINT8>
0x004017fb:	movl %ebx, %ecx
0x004017fd:	movl (%esp), %edx
0x00401800:	leal %esi, 0x8(%esp)
0x00401804:	leal %edi, 0x4(%esp)
0x00401808:	leal %ebp, 0xc(%esp)
0x0040180c:	movl %edx, %eax
0x0040180e:	movl %ecx, %edx
0x00401810:	andl %ecx, $0xfffff000<UINT32>
0x00401816:	movl 0x10(%esp), %ecx
0x0040181a:	addl %edx, (%esp)
0x0040181d:	addl %edx, $0xfff<UINT32>
0x00401823:	andl %edx, $0xfffff000<UINT32>
0x00401829:	movl 0x14(%esp), %edx
0x0040182d:	movl %eax, 0x10(%esp)
0x00401831:	movl (%ebx), %eax
0x00401833:	movl %eax, 0x14(%esp)
0x00401837:	subl %eax, 0x10(%esp)
0x0040183b:	movl 0x4(%ebx), %eax
0x0040183e:	movl %eax, 0x4855ec
0x00401843:	movl (%edi), %eax
0x00401845:	jmp 0x004018a2
0x004018a2:	movl %eax, $0x4855ec<UINT32>
0x004018a7:	cmpl %eax, (%edi)
0x004018a9:	jne 0x00401847
0x00401847:	movl %eax, (%edi)
0x00401849:	movl %eax, 0x8(%eax)
0x0040184c:	movl (%esi), %eax
0x0040184e:	movl %eax, (%edi)
0x00401850:	movl %eax, 0xc(%eax)
0x00401853:	addl %eax, (%esi)
0x00401855:	movl (%ebp), %eax
0x00401858:	movl %eax, (%esi)
0x0040185a:	cmpl %eax, 0x10(%esp)
0x0040185e:	jae 0x00401866
0x00401866:	movl %eax, (%ebp)
0x00401869:	cmpl %eax, 0x14(%esp)
0x0040186d:	jbe 7
0x0040186f:	movl %eax, 0x14(%esp)
0x00401873:	movl (%ebp), %eax
0x00401876:	movl %eax, (%esi)
0x00401878:	cmpl %eax, (%ebp)
0x0040187b:	jae 31
0x0040187d:	pushl $0x4<UINT8>
0x0040187f:	pushl $0x1000<UINT32>
0x00401884:	movl %eax, (%ebp)
0x00401887:	subl %eax, (%esi)
0x00401889:	pushl %eax
0x0040188a:	movl %eax, (%esi)
0x0040188c:	pushl %eax
0x0040188d:	call 0x004013b8
0x00401892:	testl %eax, %eax
0x00401894:	jne 0x0040189c
0x0040189c:	movl %eax, (%edi)
0x0040189e:	movl %eax, (%eax)
0x004018a0:	movl (%edi), %eax
0x004018ab:	addl %esp, $0x18<UINT8>
0x004018ae:	popl %ebp
0x004018af:	popl %edi
0x004018b0:	popl %esi
0x004018b1:	popl %ebx
0x004018b2:	ret

0x004019aa:	cmpl (%ebx), $0x0<UINT8>
0x004019ad:	je 95
0x004019af:	movl %eax, 0x4(%ebx)
0x004019b2:	movl %edx, (%edi)
0x004019b4:	addl 0x8(%edx), %eax
0x004019b7:	movl %eax, 0x4(%ebx)
0x004019ba:	movl %edx, (%edi)
0x004019bc:	subl 0xc(%edx), %eax
0x004019bf:	movl %eax, (%edi)
0x004019c1:	cmpl 0xc(%eax), $0x0<UINT8>
0x004019c5:	jne 0x00401a0e
0x00401a0e:	addl %esp, $0xc<UINT8>
0x00401a11:	popl %ebp
0x00401a12:	popl %edi
0x00401a13:	popl %esi
0x00401a14:	popl %ebx
0x00401a15:	ret

0x0040227c:	cmpl (%esp), $0x0<UINT8>
0x00402280:	je 11
0x00402282:	movl %eax, %esp
0x00402284:	call 0x004021e0
0x004021e0:	pushl %ebx
0x004021e1:	pushl %esi
0x004021e2:	pushl %edi
0x004021e3:	addl %esp, $0xfffffff0<UINT8>
0x004021e6:	movl %esi, %eax
0x004021e8:	leal %edi, (%esp)
0x004021eb:	movsl %es:(%edi), %ds:(%esi)
0x004021ec:	movsl %es:(%edi), %ds:(%esi)
0x004021ed:	movl %edi, %esp
0x004021ef:	call 0x00402194
0x00402194:	cmpl 0x48561c, $0x0<UINT8>
0x0040219b:	jle 0x004021dd
0x004021dd:	ret

0x004021f4:	leal %ecx, 0x8(%esp)
0x004021f8:	movl %edx, %edi
0x004021fa:	movl %eax, $0x485628<UINT32>
0x004021ff:	call 0x00401504
0x00402204:	movl %ebx, 0x8(%esp)
0x00402208:	testl %ebx, %ebx
0x0040220a:	jne 0x00402210
0x00402210:	movl %eax, (%edi)
0x00402212:	cmpl %ebx, %eax
0x00402214:	jae 0x00402220
0x00402220:	movl %eax, (%edi)
0x00402222:	addl %eax, 0x4(%edi)
0x00402225:	movl %esi, %ebx
0x00402227:	addl %esi, 0xc(%esp)
0x0040222b:	cmpl %eax, %esi
0x0040222d:	jae 0x00402237
0x00402237:	movl %eax, (%edi)
0x00402239:	addl %eax, 0x4(%edi)
0x0040223c:	cmpl %esi, %eax
0x0040223e:	jne 17
0x00402240:	subl %eax, $0x4<UINT8>
0x00402243:	movl %edx, $0x4<UINT32>
0x00402248:	call 0x00401ea0
0x00401ea0:	pushl %ebx
0x00401ea1:	pushl %ecx
0x00401ea2:	movl %ecx, %edx
0x00401ea4:	subl %ecx, $0x4<UINT8>
0x00401ea7:	leal %ebx, (%ecx,%eax)
0x00401eaa:	movl (%esp), %ebx
0x00401ead:	cmpl %edx, $0x10<UINT8>
0x00401eb0:	jl 0x00401ec5
0x00401ec5:	cmpl %edx, $0x4<UINT8>
0x00401ec8:	jl 15
0x00401eca:	movl %ecx, %edx
0x00401ecc:	orl %ecx, $0x80000002<UINT32>
0x00401ed2:	movl (%eax), %ecx
0x00401ed4:	movl %eax, (%esp)
0x00401ed7:	movl (%eax), %ecx
0x00401ed9:	popl %edx
0x00401eda:	popl %ebx
0x00401edb:	ret

0x0040224d:	subl 0x4(%edi), $0x4<UINT8>
0x00402251:	movl %eax, (%edi)
0x00402253:	movl 0x485620, %eax
0x00402258:	movl %eax, 0x4(%edi)
0x0040225b:	movl 0x48561c, %eax
0x00402260:	movb %al, $0x1<UINT8>
0x00402262:	addl %esp, $0x10<UINT8>
0x00402265:	popl %edi
0x00402266:	popl %esi
0x00402267:	popl %ebx
0x00402268:	ret

0x00402289:	testb %al, %al
0x0040228b:	jne 0x00402291
0x00402291:	movb %al, $0x1<UINT8>
0x00402293:	popl %ecx
0x00402294:	popl %edx
0x00402295:	popl %ebx
0x00402296:	ret

0x0040237f:	testb %al, %al
0x00402381:	jne 0x0040238d
0x0040238d:	cmpl %ebx, (%ebp)
0x00402390:	jg -119
0x00402392:	subl (%ebp), %ebx
0x00402395:	cmpl (%ebp), $0xc<UINT8>
0x00402399:	jnl 0x004023a3
0x004023a3:	movl %eax, 0x485620
0x004023a8:	movl 0x4(%esp), %eax
0x004023ac:	addl 0x485620, %ebx
0x004023b2:	movl %eax, %ebx
0x004023b4:	orl %eax, $0x2<UINT8>
0x004023b7:	movl %edx, 0x4(%esp)
0x004023bb:	movl (%edx), %eax
0x004023bd:	movl %eax, 0x4(%esp)
0x004023c1:	addl %eax, $0x4<UINT8>
0x004023c4:	movl (%esp), %eax
0x004023c7:	incl 0x4855b4
0x004023cd:	subl %ebx, $0x4<UINT8>
0x004023d0:	addl 0x4855b8, %ebx
0x004023d6:	jmp 0x00402441
0x00402441:	movl %eax, (%esp)
0x00402444:	addl %esp, $0xc<UINT8>
0x00402447:	popl %ebp
0x00402448:	popl %edi
0x00402449:	popl %esi
0x0040244a:	popl %ebx
0x0040244b:	ret

0x004025c4:	movl -4(%ebp), %eax
0x004025c7:	xorl %eax, %eax
0x004025c9:	popl %edx
0x004025ca:	popl %ecx
0x004025cb:	popl %ecx
0x004025cc:	movl %fs:(%eax), %edx
0x004025cf:	pushl $0x4025ef<UINT32>
0x004025d4:	cmpb 0x48504d, $0x0<UINT8>
0x004025db:	je 0x004025e7
0x004025e7:	ret

0x004025ef:	movl %eax, -4(%ebp)
0x004025f2:	popl %ebx
0x004025f3:	movl %esp, %ebp
0x004025f5:	popl %ebp
0x004025f6:	ret

0x00402ab0:	movl (%esp), %eax
0x00402ab3:	cmpl (%esp), $0x0<UINT8>
0x00402ab7:	jne 0x00402ac7
0x00402ac7:	movl %eax, (%esp)
0x00402aca:	popl %edx
0x00402acb:	popl %ebx
0x00402acc:	ret

0x00403bef:	movl %edx, %eax
0x00403bf1:	movl %eax, %ebx
0x00403bf3:	call 0x00403c54
0x00403c54:	pushl %ebx
0x00403c55:	pushl %esi
0x00403c56:	pushl %edi
0x00403c57:	movl %ebx, %eax
0x00403c59:	movl %edi, %edx
0x00403c5b:	stosl %es:(%edi), %eax
0x00403c5c:	movl %ecx, -40(%ebx)
0x00403c5f:	xorl %eax, %eax
0x00403c61:	pushl %ecx
0x00403c62:	shrl %ecx, $0x2<UINT8>
0x00403c65:	decl %ecx
0x00403c66:	rep stosl %es:(%edi), %eax
0x00403c68:	popl %ecx
0x00403c69:	andl %ecx, $0x3<UINT8>
0x00403c6c:	rep stosb %es:(%edi), %al
0x00403c6e:	movl %eax, %edx
0x00403c70:	movl %edx, %esp
0x00403c72:	movl %ecx, -72(%ebx)
0x00403c75:	testl %ecx, %ecx
0x00403c77:	je 0x00403c7a
0x00403c7a:	movl %ebx, -36(%ebx)
0x00403c7d:	testl %ebx, %ebx
0x00403c7f:	je 0x00403c85
0x00403c81:	movl %ebx, (%ebx)
0x00403c83:	jmp 0x00403c72
0x00403c85:	cmpl %esp, %edx
0x00403c87:	je 0x00403ca6
0x00403ca6:	popl %edi
0x00403ca7:	popl %esi
0x00403ca8:	popl %ebx
0x00403ca9:	ret

0x00403bf8:	popl %ebx
0x00403bf9:	ret

0x00403f8a:	xorl %edx, %edx
0x00403f8c:	leal %ecx, 0x10(%esp)
0x00403f90:	movl %ebx, %fs:(%edx)
0x00403f93:	movl (%ecx), %ebx
0x00403f95:	movl 0x8(%ecx), %ebp
0x00403f98:	movl 0x4(%ecx), $0x403fa9<UINT32>
0x00403f9f:	movl 0xc(%ecx), %eax
0x00403fa2:	movl %fs:(%edx), %ecx
0x00403fa5:	popl %ebx
0x00403fa6:	popl %ecx
0x00403fa7:	popl %edx
0x00403fa8:	ret

0x0040d0b7:	movl %esi, %ecx
0x0040d0b9:	movl %ebx, %edx
0x0040d0bb:	movl %edi, %eax
0x0040d0bd:	leal %edx, 0x4(%edi)
0x0040d0c0:	movl %eax, %esi
0x0040d0c2:	call 0x00406a68
0x0040d0c7:	movl %eax, %edi
0x0040d0c9:	testb %bl, %bl
0x0040d0cb:	je 15
0x0040d0cd:	call 0x00403fd8
0x00403fd8:	pushl %ebx
0x00403fd9:	movl %ebx, %eax
0x00403fdb:	movl %eax, %ebx
0x00403fdd:	movl %edx, (%eax)
0x00403fdf:	call 0x00403eb0
0x00403eb0:	ret

0x00403fe2:	movl %eax, %ebx
0x00403fe4:	popl %ebx
0x00403fe5:	ret

0x0040d0d2:	popl %fs:0
0x0040d0d9:	addl %esp, $0xc<UINT8>
0x0040d0dc:	movl %eax, %edi
0x0040d0de:	popl %edi
0x0040d0df:	popl %esi
0x0040d0e0:	popl %ebx
0x0040d0e1:	ret

0x0040d70a:	movl 0x485798, %eax
0x0040d70f:	movl %ecx, 0x484678
0x0040d715:	movb %dl, $0x1<UINT8>
0x0040d717:	movl %eax, 0x4084a8
0x0040d71c:	call 0x0040d0a8
0x0040256a:	subl 0x48561c, %ebx
0x00402570:	cmpl 0x48561c, $0xc<UINT8>
0x00402577:	jnl 0x00402586
0x00402586:	movl %eax, 0x485620
0x0040258b:	movl -20(%ebp), %eax
0x0040258e:	addl 0x485620, %ebx
0x00402594:	movl %eax, %ebx
0x00402596:	orl %eax, $0x2<UINT8>
0x00402599:	movl %edx, -20(%ebp)
0x0040259c:	movl (%edx), %eax
0x0040259e:	movl %eax, -20(%ebp)
0x004025a1:	addl %eax, $0x4<UINT8>
0x004025a4:	movl -4(%ebp), %eax
0x004025a7:	incl 0x4855b4
0x004025ad:	subl %ebx, $0x4<UINT8>
0x004025b0:	addl 0x4855b8, %ebx
0x004025b6:	call 0x00404494
0x00404494:	xorl %edx, %edx
0x00404496:	movl %ecx, 0x8(%esp)
0x0040449a:	movl %eax, 0x4(%esp)
0x0040449e:	addl %ecx, $0x5<UINT8>
0x004044a1:	movl %fs:(%edx), %eax
0x004044a4:	call 0x004027c4
0x004025ed:	jmp 0x004025d4
0x004044a6:	ret $0xc<UINT16>

0x004025bb:	jmp 0x004025ef
0x0040d721:	movl 0x48579c, %eax
0x0040d726:	movl %eax, 0x4843bc
0x0040d72b:	movl (%eax), $0x40d26c<UINT32>
0x0040d731:	movl %eax, 0x484510
0x0040d736:	movl (%eax), $0x40d6e8<UINT32>
0x0040d73c:	movl %eax, 0x484464
0x0040d741:	movl %edx, 0x407f5c
0x0040d747:	movl (%eax), %edx
0x0040d749:	movl %eax, 0x4844f0
0x0040d74e:	movl (%eax), $0x40d430<UINT32>
0x0040d754:	movl %eax, 0x484518
0x0040d759:	movl (%eax), $0x40d61c<UINT32>
0x0040d75f:	movl %eax, $0x40d37c<UINT32>
0x0040d764:	movl %edx, 0x4846a8
0x0040d76a:	movl (%edx), %eax
0x0040d76c:	movl %eax, $0x40d398<UINT32>
0x0040d771:	movl %edx, 0x4843a4
0x0040d777:	movl (%edx), %eax
0x0040d779:	ret

0x0040f263:	call 0x0040d7fc
0x0040d7fc:	addl %esp, $0xffffff6c<UINT32>
0x0040d802:	movl (%esp), $0x94<UINT32>
0x0040d809:	pushl %esp
0x0040d80a:	call 0x00407068
0x00407068:	jmp GetVersionExA@KERNEL32.DLL
GetVersionExA@KERNEL32.DLL: API Node	
0x0040d80f:	testl %eax, %eax
0x0040d811:	je 80
0x0040d813:	movl %eax, 0x10(%esp)
0x0040d817:	movl 0x4830c8, %eax
0x0040d81c:	movl %eax, 0x4(%esp)
0x0040d820:	movl 0x4830cc, %eax
0x0040d825:	movl %eax, 0x8(%esp)
0x0040d829:	movl 0x4830d0, %eax
0x0040d82e:	cmpl 0x4830c8, $0x1<UINT8>
0x0040d835:	jne 0x0040d847
0x0040d847:	movl %eax, 0xc(%esp)
0x0040d84b:	movl 0x4830d4, %eax
0x0040d850:	movl %eax, $0x4830d8<UINT32>
0x0040d855:	leal %edx, 0x14(%esp)
0x0040d859:	movl %ecx, $0x80<UINT32>
0x0040d85e:	call 0x00404cc8
0x00404cc8:	pushl %edi
0x00404cc9:	pushl %eax
0x00404cca:	pushl %ecx
0x00404ccb:	movl %edi, %edx
0x00404ccd:	xorl %eax, %eax
0x00404ccf:	repn scasb %al, %es:(%edi)
0x00404cd1:	jne 2
0x00404cd3:	notl %ecx
0x00404cd5:	popl %eax
0x00404cd6:	addl %ecx, %eax
0x00404cd8:	popl %eax
0x00404cd9:	popl %edi
0x00404cda:	jmp 0x00404b48
0x00404b20:	pushl %eax
0x00404b21:	addl %eax, $0xa<UINT8>
0x00404b24:	andl %eax, $0xfffffffe<UINT8>
0x00404b27:	pushl %eax
0x00404b28:	call 0x00402aa0
0x00404b2d:	popl %edx
0x00404b2e:	movw -2(%edx,%eax), $0x0<UINT16>
0x00404b35:	addl %eax, $0x8<UINT8>
0x00404b38:	popl %edx
0x00404b39:	movl -4(%eax), %edx
0x00404b3c:	movl -8(%eax), $0x1<UINT32>
0x00404b43:	ret

0x00402cdf:	leal %esi, -4(%ecx,%esi)
0x00402ce3:	leal %edi, -4(%ecx,%edi)
0x00402ce7:	sarl %ecx, $0x2<UINT8>
0x00402cea:	js 17
0x00402cec:	std
0x00402ced:	rep movsl %es:(%edi), %ds:(%esi)
0x00402cef:	movl %ecx, %eax
0x00402cf1:	andl %ecx, $0x3<UINT8>
0x00402cf4:	addl %esi, $0x3<UINT8>
0x00402cf7:	addl %edi, $0x3<UINT8>
0x00402cfa:	rep movsb %es:(%edi), %ds:(%esi)
0x00402cfc:	cld
0x00402cfd:	popl %edi
0x00402cfe:	popl %esi
0x00402cff:	ret

0x0040d863:	addl %esp, $0x94<UINT32>
0x0040d869:	ret

0x0040f268:	call 0x0040e7a4
0x0040e7a4:	pushl %ebx
0x0040e7a5:	pushl $0x40e7dc<UINT32>
0x0040e7aa:	call 0x00407028
0x00407028:	jmp GetModuleHandleA@KERNEL32.DLL
0x0040e7af:	movl %ebx, %eax
0x0040e7b1:	testl %ebx, %ebx
0x0040e7b3:	je 0x0040e7c5
0x0040e7c5:	cmpl 0x483134, $0x0<UINT8>
0x0040e7cc:	jne 10
0x0040e7ce:	movl %eax, $0x409a14<UINT32>
0x0040e7d3:	movl 0x483134, %eax
0x0040e7d8:	popl %ebx
0x0040e7d9:	ret

0x0040f26d:	call 0x0040e1ec
0x0040e1ec:	pushl %ebp
0x0040e1ed:	movl %ebp, %esp
0x0040e1ef:	movl %ecx, $0x8<UINT32>
0x0040e1f4:	pushl $0x0<UINT8>
0x0040e1f6:	pushl $0x0<UINT8>
0x0040e1f8:	decl %ecx
0x0040e1f9:	jne 0x0040e1f4
0x0040e1fb:	pushl %ebx
0x0040e1fc:	xorl %eax, %eax
0x0040e1fe:	pushl %ebp
0x0040e1ff:	pushl $0x40e4b7<UINT32>
0x0040e204:	pushl %fs:(%eax)
0x0040e207:	movl %fs:(%eax), %esp
0x0040e20a:	call 0x0040e074
0x0040e074:	pushl %ebp
0x0040e075:	movl %ebp, %esp
0x0040e077:	addl %esp, $0xfffffe64<UINT32>
0x0040e07d:	pushl %ebx
0x0040e07e:	pushl %esi
0x0040e07f:	pushl %edi
0x0040e080:	movl 0x485744, $0x409<UINT32>
0x0040e08a:	movl 0x485748, $0x9<UINT32>
0x0040e094:	movl 0x48574c, $0x1<UINT32>
0x0040e09e:	call 0x00407050
0x00407050:	jmp GetThreadLocale@KERNEL32.DLL
0x0040e0a3:	testl %eax, %eax
0x0040e0a5:	je 5
0x0040e0a7:	movl 0x485744, %eax
0x0040e0ac:	testw %ax, %ax
0x0040e0af:	je 27
0x0040e0b1:	movl %edx, %eax
0x0040e0b3:	andw %dx, $0x3ff<UINT16>
0x0040e0b8:	movzwl %edx, %dx
0x0040e0bb:	movl 0x485748, %edx
0x0040e0c1:	movzwl %eax, %ax
0x0040e0c4:	shrl %eax, $0xa<UINT8>
0x0040e0c7:	movl 0x48574c, %eax
0x0040e0cc:	movl %esi, $0x40e1cc<UINT32>
0x0040e0d1:	movl %edi, $0x483110<UINT32>
0x0040e0d6:	movl %ecx, $0x8<UINT32>
0x0040e0db:	rep movsl %es:(%edi), %ds:(%esi)
0x0040e0dd:	cmpl 0x4830c8, $0x2<UINT8>
0x0040e0e4:	jne 173
0x0040e0ea:	call 0x0040e05c
0x0040e05c:	movl %eax, 0x485748
0x0040e061:	cmpl %eax, $0x1f<UINT8>
0x0040e064:	ja 7
0x0040e066:	btl 0x48330c, %eax
0x0040e06d:	setb %al
0x0040e070:	ret

0x0040e0ef:	testb %al, %al
0x0040e0f1:	je 19
0x0040e0f3:	movb 0x485751, $0x0<UINT8>
0x0040e0fa:	movb 0x485750, $0x0<UINT8>
0x0040e101:	jmp 0x0040e1c5
0x0040e1c5:	popl %edi
0x0040e1c6:	popl %esi
0x0040e1c7:	popl %ebx
0x0040e1c8:	movl %esp, %ebp
0x0040e1ca:	popl %ebp
0x0040e1cb:	ret

0x0040e20f:	call 0x0040c8d0
0x0040c8d0:	pushl %ebp
0x0040c8d1:	movl %ebp, %esp
0x0040c8d3:	xorl %ecx, %ecx
0x0040c8d5:	pushl %ecx
0x0040c8d6:	pushl %ecx
0x0040c8d7:	pushl %ecx
0x0040c8d8:	pushl %ecx
0x0040c8d9:	pushl %ecx
0x0040c8da:	pushl %ecx
0x0040c8db:	pushl %ebx
0x0040c8dc:	pushl %esi
0x0040c8dd:	pushl %edi
0x0040c8de:	xorl %eax, %eax
0x0040c8e0:	pushl %ebp
0x0040c8e1:	pushl $0x40c9e3<UINT32>
0x0040c8e6:	pushl %fs:(%eax)
0x0040c8e9:	movl %fs:(%eax), %esp
0x0040c8ec:	call 0x00407050
0x0040c8f1:	movl -4(%ebp), %eax
0x0040c8f4:	movl %ebx, $0x1<UINT32>
0x0040c8f9:	movl %esi, $0x4856ac<UINT32>
0x0040c8fe:	movl %edi, $0x4856dc<UINT32>
0x0040c903:	pushl %ebp
0x0040c904:	pushl $0xb<UINT8>
0x0040c906:	leal %eax, -12(%ebp)
0x0040c909:	pushl %eax
0x0040c90a:	movl %ecx, $0x48318c<UINT32>
0x0040c90f:	movl %edx, %ebx
0x0040c911:	decl %edx
0x0040c912:	leal %eax, 0x44(%ebx)
0x0040c915:	decl %eax
0x0040c916:	call 0x0040c894
0x0040c894:	pushl %ebp
0x0040c895:	movl %ebp, %esp
0x0040c897:	pushl %ecx
0x0040c898:	pushl %ebx
0x0040c899:	pushl %esi
0x0040c89a:	pushl %edi
0x0040c89b:	movl -4(%ebp), %ecx
0x0040c89e:	movl %edi, %edx
0x0040c8a0:	movl %esi, %eax
0x0040c8a2:	movl %ebx, 0x8(%ebp)
0x0040c8a5:	pushl %ebx
0x0040c8a6:	movl %eax, 0x10(%ebp)
0x0040c8a9:	movl %eax, -4(%eax)
0x0040c8ac:	xorl %ecx, %ecx
0x0040c8ae:	movl %edx, %esi
0x0040c8b0:	call 0x0040c820
0x0040c820:	pushl %ebp
0x0040c821:	movl %ebp, %esp
0x0040c823:	addl %esp, $0xffffff00<UINT32>
0x0040c829:	pushl %ebx
0x0040c82a:	pushl %esi
0x0040c82b:	movl %esi, %ecx
0x0040c82d:	movl %ebx, 0x8(%ebp)
0x0040c830:	pushl $0x100<UINT32>
0x0040c835:	leal %ecx, -256(%ebp)
0x0040c83b:	pushl %ecx
0x0040c83c:	pushl %edx
0x0040c83d:	pushl %eax
0x0040c83e:	call 0x00407018
0x00407018:	jmp GetLocaleInfoA@KERNEL32.DLL
0x0040c843:	testl %eax, %eax
0x0040c845:	jle 18
0x0040c847:	movl %ecx, %eax
0x0040c849:	decl %ecx
0x0040c84a:	leal %edx, -256(%ebp)
0x0040c850:	movl %eax, %ebx
0x0040c852:	call 0x00404b48
0x0040c857:	jmp 0x0040c862
0x0040c862:	popl %esi
0x0040c863:	popl %ebx
0x0040c864:	movl %esp, %ebp
0x0040c866:	popl %ebp
0x0040c867:	ret $0x4<UINT16>

0x0040c8b5:	cmpl (%ebx), $0x0<UINT8>
0x0040c8b8:	jne 0x0040c8c7
0x0040c8c7:	popl %edi
0x0040c8c8:	popl %esi
0x0040c8c9:	popl %ebx
0x0040c8ca:	popl %ecx
0x0040c8cb:	popl %ebp
0x0040c8cc:	ret $0x8<UINT16>

0x0040c91b:	popl %ecx
0x0040c91c:	movl %edx, -12(%ebp)
0x0040c91f:	movl %eax, %esi
0x0040c921:	call 0x00404aac
0x00404aac:	testl %edx, %edx
0x00404aae:	je 36
0x00404ab0:	movl %ecx, -8(%edx)
0x00404ab3:	incl %ecx
0x00404ab4:	jg 0x00404ad0
0x00404ad0:	incl -8(%edx)
0x00404ad4:	xchgl (%eax), %edx
0x00404ad6:	testl %edx, %edx
0x00404ad8:	je 0x00404aee
0x00404aee:	ret

0x0040c926:	pushl %ebp
0x0040c927:	pushl $0xb<UINT8>
0x0040c929:	leal %eax, -16(%ebp)
0x0040c92c:	pushl %eax
0x0040c92d:	movl %ecx, $0x4831bc<UINT32>
0x0040c932:	movl %edx, %ebx
0x0040c934:	decl %edx
0x0040c935:	leal %eax, 0x38(%ebx)
0x0040c938:	decl %eax
0x0040c939:	call 0x0040c894
0x0040c93e:	popl %ecx
0x0040c93f:	movl %edx, -16(%ebp)
0x0040c942:	movl %eax, %edi
0x0040c944:	call 0x00404aac
0x0040c949:	incl %ebx
0x0040c94a:	addl %edi, $0x4<UINT8>
0x0040c94d:	addl %esi, $0x4<UINT8>
0x0040c950:	cmpl %ebx, $0xd<UINT8>
0x0040c953:	jne 0x0040c903
0x00404a5e:	movl (%eax), $0x0<UINT32>
0x00404a64:	movl %ecx, -8(%edx)
0x00404a67:	decl %ecx
0x00404a68:	jl 16
0x00404a6a:	decl -8(%edx)
0x00404a6e:	jne 0x00404a7a
0x0040c955:	movl %ebx, $0x1<UINT32>
0x0040c95a:	movl %esi, $0x48570c<UINT32>
0x0040c95f:	movl %edi, $0x485728<UINT32>
0x0040c964:	leal %eax, 0x5(%ebx)
0x0040c967:	movl %ecx, $0x7<UINT32>
0x0040c96c:	cltd
0x0040c96d:	idivl %eax, %ecx
0x0040c96f:	movl -8(%ebp), %edx
0x0040c972:	pushl %ebp
0x0040c973:	pushl $0x6<UINT8>
0x0040c975:	leal %eax, -20(%ebp)
0x0040c978:	pushl %eax
0x0040c979:	movl %ecx, $0x4831ec<UINT32>
0x0040c97e:	movl %edx, %ebx
0x0040c980:	decl %edx
0x0040c981:	movl %eax, -8(%ebp)
0x0040c984:	addl %eax, $0x31<UINT8>
0x0040c987:	call 0x0040c894
0x0040c98c:	popl %ecx
0x0040c98d:	movl %edx, -20(%ebp)
0x0040c990:	movl %eax, %esi
0x0040c992:	call 0x00404aac
0x0040c997:	pushl %ebp
0x0040c998:	pushl $0x6<UINT8>
0x0040c99a:	leal %eax, -24(%ebp)
0x0040c99d:	pushl %eax
0x0040c99e:	movl %ecx, $0x483208<UINT32>
0x0040c9a3:	movl %edx, %ebx
0x0040c9a5:	decl %edx
0x0040c9a6:	movl %eax, -8(%ebp)
0x0040c9a9:	addl %eax, $0x2a<UINT8>
0x0040c9ac:	call 0x0040c894
0x0040c9b1:	popl %ecx
0x0040c9b2:	movl %edx, -24(%ebp)
0x0040c9b5:	movl %eax, %edi
0x0040c9b7:	call 0x00404aac
0x0040c9bc:	incl %ebx
0x0040c9bd:	addl %edi, $0x4<UINT8>
0x0040c9c0:	addl %esi, $0x4<UINT8>
0x0040c9c3:	cmpl %ebx, $0x8<UINT8>
0x0040c9c6:	jne 0x0040c964
0x0040c9c8:	xorl %eax, %eax
0x0040c9ca:	popl %edx
0x0040c9cb:	popl %ecx
0x0040c9cc:	popl %ecx
0x0040c9cd:	movl %fs:(%eax), %edx
0x0040c9d0:	pushl $0x40c9ea<UINT32>
0x0040c9d5:	leal %eax, -24(%ebp)
0x0040c9d8:	movl %edx, $0x4<UINT32>
0x0040c9dd:	call 0x00404a7c
0x00404a7c:	pushl %ebx
0x00404a7d:	pushl %esi
0x00404a7e:	movl %ebx, %eax
0x00404a80:	movl %esi, %edx
0x00404a82:	movl %edx, (%ebx)
0x00404a84:	testl %edx, %edx
0x00404a86:	je 0x00404aa2
0x00404a88:	movl (%ebx), $0x0<UINT32>
0x00404a8e:	movl %ecx, -8(%edx)
0x00404a91:	decl %ecx
0x00404a92:	jl 0x00404aa2
0x00404a94:	decl -8(%edx)
0x00404a98:	jne 0x00404aa2
0x00404aa2:	addl %ebx, $0x4<UINT8>
0x00404aa5:	decl %esi
0x00404aa6:	jne 0x00404a82
0x00404aa8:	popl %esi
0x00404aa9:	popl %ebx
0x00404aaa:	ret

0x0040c9e2:	ret

0x0040c9ea:	popl %edi
0x0040c9eb:	popl %esi
0x0040c9ec:	popl %ebx
0x0040c9ed:	movl %esp, %ebp
0x0040c9ef:	popl %ebp
0x0040c9f0:	ret

0x0040e214:	cmpb 0x485750, $0x0<UINT8>
0x0040e21b:	je 0x0040e222
0x0040e222:	call 0x00407050
0x0040e227:	movl %ebx, %eax
0x0040e229:	leal %eax, -16(%ebp)
0x0040e22c:	pushl %eax
0x0040e22d:	xorl %ecx, %ecx
0x0040e22f:	movl %edx, $0x14<UINT32>
0x0040e234:	movl %eax, %ebx
0x0040e236:	call 0x0040c820
0x0040e23b:	movl %edx, -16(%ebp)
0x0040e23e:	movl %eax, $0x485684<UINT32>
0x0040e243:	call 0x00404aac
0x0040e248:	leal %eax, -20(%ebp)
0x0040e24b:	pushl %eax
0x0040e24c:	movl %ecx, $0x40e4cc<UINT32>
0x0040e251:	movl %edx, $0x1b<UINT32>
0x0040e256:	movl %eax, %ebx
0x0040e258:	call 0x0040c820
0x0040e25d:	movl %eax, -20(%ebp)
0x0040e260:	xorl %edx, %edx
0x0040e262:	call 0x0040927c
0x0040927c:	pushl %ebx
0x0040927d:	pushl %ecx
0x0040927e:	movl %ebx, %edx
0x00409280:	movl %edx, %esp
0x00409282:	call 0x004034b8
0x004034b8:	pushl %ebx
0x004034b9:	pushl %esi
0x004034ba:	pushl %edi
0x004034bb:	movl %esi, %eax
0x004034bd:	pushl %eax
0x004034be:	testl %eax, %eax
0x004034c0:	je 108
0x004034c2:	xorl %eax, %eax
0x004034c4:	xorl %ebx, %ebx
0x004034c6:	movl %edi, $0xccccccc<UINT32>
0x004034cb:	movb %bl, (%esi)
0x004034cd:	incl %esi
0x004034ce:	cmpb %bl, $0x20<UINT8>
0x004034d1:	je -8
0x004034d3:	movb %ch, $0x0<UINT8>
0x004034d5:	cmpb %bl, $0x2d<UINT8>
0x004034d8:	je 98
0x004034da:	cmpb %bl, $0x2b<UINT8>
0x004034dd:	je 95
0x004034df:	cmpb %bl, $0x24<UINT8>
0x004034e2:	je 95
0x004034e4:	cmpb %bl, $0x78<UINT8>
0x004034e7:	je 90
0x004034e9:	cmpb %bl, $0x58<UINT8>
0x004034ec:	je 85
0x004034ee:	cmpb %bl, $0x30<UINT8>
0x004034f1:	jne 0x00403506
0x004034f3:	movb %bl, (%esi)
0x004034f5:	incl %esi
0x004034f6:	cmpb %bl, $0x78<UINT8>
0x004034f9:	je 72
0x004034fb:	cmpb %bl, $0x58<UINT8>
0x004034fe:	je 67
0x00403500:	testb %bl, %bl
0x00403502:	je 0x00403524
0x00403524:	decb %ch
0x00403526:	je 9
0x00403528:	testl %eax, %eax
0x0040352a:	jnl 0x00403580
0x00403580:	popl %ecx
0x00403581:	xorl %esi, %esi
0x00403583:	movl (%edx), %esi
0x00403585:	popl %edi
0x00403586:	popl %esi
0x00403587:	popl %ebx
0x00403588:	ret

0x00409287:	cmpl (%esp), $0x0<UINT8>
0x0040928b:	je 0x0040928f
0x0040928f:	popl %edx
0x00409290:	popl %ebx
0x00409291:	ret

0x0040e267:	movb 0x485688, %al
0x0040e26c:	leal %eax, -24(%ebp)
0x0040e26f:	pushl %eax
0x0040e270:	movl %ecx, $0x40e4cc<UINT32>
0x0040e275:	movl %edx, $0x1c<UINT32>
0x0040e27a:	movl %eax, %ebx
0x0040e27c:	call 0x0040c820
0x0040e281:	movl %eax, -24(%ebp)
0x0040e284:	xorl %edx, %edx
0x0040e286:	call 0x0040927c
0x0040e28b:	movb 0x485689, %al
0x0040e290:	movb %cl, $0x2c<UINT8>
0x0040e292:	movl %edx, $0xf<UINT32>
0x0040e297:	movl %eax, %ebx
0x0040e299:	call 0x0040c86c
0x0040c86c:	pushl %ebx
0x0040c86d:	pushl %esi
0x0040c86e:	pushl %edi
0x0040c86f:	pushl %ecx
0x0040c870:	movl %ebx, %ecx
0x0040c872:	movl %esi, %edx
0x0040c874:	movl %edi, %eax
0x0040c876:	pushl $0x2<UINT8>
0x0040c878:	leal %eax, 0x4(%esp)
0x0040c87c:	pushl %eax
0x0040c87d:	pushl %esi
0x0040c87e:	pushl %edi
0x0040c87f:	call 0x00407018
0x0040c884:	testl %eax, %eax
0x0040c886:	jle 5
0x0040c888:	movb %al, (%esp)
0x0040c88b:	jmp 0x0040c88f
0x0040c88f:	popl %edx
0x0040c890:	popl %edi
0x0040c891:	popl %esi
0x0040c892:	popl %ebx
0x0040c893:	ret

0x0040e29e:	movb 0x48568a, %al
0x0040e2a3:	movb %cl, $0x2e<UINT8>
0x0040e2a5:	movl %edx, $0xe<UINT32>
0x0040e2aa:	movl %eax, %ebx
0x0040e2ac:	call 0x0040c86c
0x0040e2b1:	movb 0x48568b, %al
0x0040e2b6:	leal %eax, -28(%ebp)
0x0040e2b9:	pushl %eax
0x0040e2ba:	movl %ecx, $0x40e4cc<UINT32>
0x0040e2bf:	movl %edx, $0x19<UINT32>
0x0040e2c4:	movl %eax, %ebx
0x0040e2c6:	call 0x0040c820
0x0040e2cb:	movl %eax, -28(%ebp)
0x0040e2ce:	xorl %edx, %edx
0x0040e2d0:	call 0x0040927c
0x00403506:	testb %bl, %bl
0x00403508:	je 45
0x0040350a:	subb %bl, $0x30<UINT8>
0x0040350d:	cmpb %bl, $0x9<UINT8>
0x00403510:	ja 37
0x00403512:	cmpl %eax, %edi
0x00403514:	ja 33
0x00403516:	leal %eax, (%eax,%eax,4)
0x00403519:	addl %eax, %eax
0x0040351b:	addl %eax, %ebx
0x0040351d:	movb %bl, (%esi)
0x0040351f:	incl %esi
0x00403520:	testb %bl, %bl
0x00403522:	jne -26
0x0040e2d5:	movb 0x48568c, %al
0x0040e2da:	movb %cl, $0x2f<UINT8>
0x0040e2dc:	movl %edx, $0x1d<UINT32>
0x0040e2e1:	movl %eax, %ebx
0x0040e2e3:	call 0x0040c86c
0x0040e2e8:	movb 0x48568d, %al
0x0040e2ed:	leal %eax, -36(%ebp)
0x0040e2f0:	pushl %eax
0x0040e2f1:	movl %ecx, $0x40e4d8<UINT32>
0x0040e2f6:	movl %edx, $0x1f<UINT32>
0x0040e2fb:	movl %eax, %ebx
0x0040e2fd:	call 0x0040c820
0x0040e302:	movl %eax, -36(%ebp)
0x0040e305:	leal %edx, -32(%ebp)
0x0040e308:	call 0x0040cb58
0x0040cb58:	pushl %ebp
0x0040cb59:	movl %ebp, %esp
0x0040cb5b:	xorl %ecx, %ecx
0x0040cb5d:	pushl %ecx
0x0040cb5e:	pushl %ecx
0x0040cb5f:	pushl %ecx
0x0040cb60:	pushl %ecx
0x0040cb61:	pushl %ecx
0x0040cb62:	pushl %ebx
0x0040cb63:	pushl %esi
0x0040cb64:	pushl %edi
0x0040cb65:	movl %edi, %edx
0x0040cb67:	movl %esi, %eax
0x0040cb69:	xorl %eax, %eax
0x0040cb6b:	pushl %ebp
0x0040cb6c:	pushl $0x40cd22<UINT32>
0x0040cb71:	pushl %fs:(%eax)
0x0040cb74:	movl %fs:(%eax), %esp
0x0040cb77:	movl %ebx, $0x1<UINT32>
0x0040cb7c:	movl %eax, %edi
0x0040cb7e:	call 0x00404a58
0x0040cb83:	leal %eax, -8(%ebp)
0x0040cb86:	pushl %eax
0x0040cb87:	call 0x00407050
0x0040cb8c:	movl %ecx, $0x40cd38<UINT32>
0x0040cb91:	movl %edx, $0x1009<UINT32>
0x0040cb96:	call 0x0040c820
0x0040cb9b:	movl %eax, -8(%ebp)
0x0040cb9e:	movl %edx, $0x1<UINT32>
0x0040cba3:	call 0x0040927c
0x0040cba8:	addl %eax, $0xfffffffd<UINT8>
0x0040cbab:	subl %eax, $0x3<UINT8>
0x0040cbae:	jb 324
0x0040cbb4:	movl %eax, 0x485748
0x0040cbb9:	subl %eax, $0x4<UINT8>
0x0040cbbc:	je 12
0x0040cbbe:	addl %eax, $0xfffffff3<UINT8>
0x0040cbc1:	subl %eax, $0x2<UINT8>
0x0040cbc4:	jb 4
0x0040cbc6:	xorl %eax, %eax
0x0040cbc8:	jmp 0x0040cbcc
0x0040cbcc:	testb %al, %al
0x0040cbce:	je 0x0040cc05
0x0040cc05:	movl %eax, %edi
0x0040cc07:	movl %edx, %esi
0x0040cc09:	call 0x00404aac
0x0040cc0e:	jmp 0x0040cd07
0x0040cd07:	xorl %eax, %eax
0x0040cd09:	popl %edx
0x0040cd0a:	popl %ecx
0x0040cd0b:	popl %ecx
0x0040cd0c:	movl %fs:(%eax), %edx
0x0040cd0f:	pushl $0x40cd29<UINT32>
0x0040cd14:	leal %eax, -20(%ebp)
0x0040cd17:	movl %edx, $0x4<UINT32>
0x0040cd1c:	call 0x00404a7c
0x00404a9a:	leal %eax, -8(%edx)
0x00404a9d:	call 0x00402ad0
0x00402ad0:	pushl %ebx
0x00402ad1:	testl %eax, %eax
0x00402ad3:	je 21
0x00402ad5:	call 0x004025f8
0x004025f8:	pushl %ebp
0x004025f9:	movl %ebp, %esp
0x004025fb:	addl %esp, $0xfffffff0<UINT8>
0x004025fe:	pushl %ebx
0x004025ff:	movl %ebx, %eax
0x00402601:	xorl %eax, %eax
0x00402603:	movl 0x4855c8, %eax
0x00402608:	cmpb 0x4855c4, $0x0<UINT8>
0x0040260f:	jne 0x00402630
0x00402630:	xorl %edx, %edx
0x00402632:	pushl %ebp
0x00402633:	pushl $0x4027bf<UINT32>
0x00402638:	pushl %fs:(%edx)
0x0040263b:	movl %fs:(%edx), %esp
0x0040263e:	cmpb 0x48504d, $0x0<UINT8>
0x00402645:	je 0x00402651
0x00402651:	movl -8(%ebp), %ebx
0x00402654:	movl %eax, -8(%ebp)
0x00402657:	subl %eax, $0x4<UINT8>
0x0040265a:	movl -8(%ebp), %eax
0x0040265d:	movl %eax, -8(%ebp)
0x00402660:	movl %ebx, (%eax)
0x00402662:	testb %bl, $0x2<UINT8>
0x00402665:	jne 0x00402676
0x00402676:	decl 0x4855b4
0x0040267c:	movl %eax, %ebx
0x0040267e:	andl %eax, $0x7ffffffc<UINT32>
0x00402683:	subl %eax, $0x4<UINT8>
0x00402686:	subl 0x4855b8, %eax
0x0040268c:	testb %bl, $0x1<UINT8>
0x0040268f:	je 0x004026e4
0x004026e4:	andl %ebx, $0x7ffffffc<UINT32>
0x004026ea:	movl %eax, -8(%ebp)
0x004026ed:	addl %eax, %ebx
0x004026ef:	movl -12(%ebp), %eax
0x004026f2:	movl %eax, -12(%ebp)
0x004026f5:	cmpl %eax, 0x485620
0x004026fb:	jne 0x00402729
0x004026fd:	subl 0x485620, %ebx
0x00402703:	addl 0x48561c, %ebx
0x00402709:	cmpl 0x48561c, $0x3c00<UINT32>
0x00402713:	jle 5
0x00402715:	call 0x00402194
0x0040219d:	cmpl 0x48561c, $0xc<UINT8>
0x004021a4:	jnl 0x004021b2
0x004021b2:	movl %eax, 0x48561c
0x004021b7:	orl %eax, $0x2<UINT8>
0x004021ba:	movl %edx, 0x485620
0x004021c0:	movl (%edx), %eax
0x004021c2:	movl %eax, 0x485620
0x004021c7:	addl %eax, $0x4<UINT8>
0x004021ca:	call 0x00401edc
0x00401edc:	incl 0x4855b4
0x00401ee2:	movl %edx, %eax
0x00401ee4:	subl %edx, $0x4<UINT8>
0x00401ee7:	movl %edx, (%edx)
0x00401ee9:	andl %edx, $0x7ffffffc<UINT32>
0x00401eef:	subl %edx, $0x4<UINT8>
0x00401ef2:	addl 0x4855b8, %edx
0x00401ef8:	call 0x004025f8
0x00402729:	movl %eax, -12(%ebp)
0x0040272c:	movl %eax, (%eax)
0x0040272e:	testb %al, $0x2<UINT8>
0x00402730:	je 0x00402750
0x00402732:	andl %eax, $0x7ffffffc<UINT32>
0x00402737:	cmpl %eax, $0x4<UINT8>
0x0040273a:	jnl 0x00402748
0x00402748:	movl %eax, -12(%ebp)
0x0040274b:	orl (%eax), $0x1<UINT8>
0x0040274e:	jmp 0x0040278c
0x0040278c:	movl %edx, %ebx
0x0040278e:	movl %eax, -8(%ebp)
0x00402791:	call 0x0040209c
0x0040209c:	pushl %ebx
0x0040209d:	pushl %esi
0x0040209e:	addl %esp, $0xfffffff4<UINT8>
0x004020a1:	movl %ebx, %edx
0x004020a3:	movl %esi, %eax
0x004020a5:	movl (%esp), %esi
0x004020a8:	movl %eax, (%esp)
0x004020ab:	movl 0x8(%eax), %ebx
0x004020ae:	movl %eax, (%esp)
0x004020b1:	addl %eax, %ebx
0x004020b3:	subl %eax, $0xc<UINT8>
0x004020b6:	movl 0x8(%eax), %ebx
0x004020b9:	cmpl %ebx, $0x1000<UINT32>
0x004020bf:	jg 0x00402137
0x00402137:	cmpl %ebx, $0x3c00<UINT32>
0x0040213d:	jl 0x0040214c
0x0040213f:	movl %edx, %ebx
0x00402141:	movl %eax, %esi
0x00402143:	call 0x00401fe0
0x00401fe0:	pushl %ebx
0x00401fe1:	pushl %esi
0x00401fe2:	pushl %edi
0x00401fe3:	pushl %ebp
0x00401fe4:	addl %esp, $0xfffffff4<UINT8>
0x00401fe7:	movl %esi, %edx
0x00401fe9:	movl %ebp, %eax
0x00401feb:	xorl %ebx, %ebx
0x00401fed:	movl %eax, %ebp
0x00401fef:	call 0x00401e5c
0x00401e5c:	pushl %ebx
0x00401e5d:	pushl %ecx
0x00401e5e:	movl %ecx, %esp
0x00401e60:	movl %edx, 0x485628
0x00401e66:	movl (%ecx), %edx
0x00401e68:	jmp 0x00401e82
0x00401e82:	movl %edx, $0x485628<UINT32>
0x00401e87:	cmpl %edx, (%ecx)
0x00401e89:	jne 0x00401e6a
0x00401e6a:	movl %edx, (%ecx)
0x00401e6c:	movl %edx, 0x8(%edx)
0x00401e6f:	cmpl %eax, %edx
0x00401e71:	jb 9
0x00401e73:	movl %ebx, (%ecx)
0x00401e75:	addl %edx, 0xc(%ebx)
0x00401e78:	cmpl %eax, %edx
0x00401e7a:	jb 0x00401e99
0x00401e99:	movl %eax, (%ecx)
0x00401e9b:	popl %edx
0x00401e9c:	popl %ebx
0x00401e9d:	ret

0x00401ff4:	movl 0x8(%esp), %eax
0x00401ff8:	cmpl 0x8(%esp), $0x0<UINT8>
0x00401ffd:	je 143
0x00402003:	movl %eax, 0x8(%esp)
0x00402007:	movl %edi, 0x8(%eax)
0x0040200a:	movl %eax, %edi
0x0040200c:	movl %edx, 0x8(%esp)
0x00402010:	addl %eax, 0xc(%edx)
0x00402013:	movl %edx, %eax
0x00402015:	leal %ecx, (%esi,%ebp)
0x00402018:	subl %edx, %ecx
0x0040201a:	cmpl %edx, $0xc<UINT8>
0x0040201d:	jg 4
0x0040201f:	movl %esi, %eax
0x00402021:	subl %esi, %ebp
0x00402023:	movl %eax, %ebp
0x00402025:	subl %eax, %edi
0x00402027:	cmpl %eax, $0xc<UINT8>
0x0040202a:	jnl 0x00402042
0x00402042:	movl %ecx, %esp
0x00402044:	movl %edx, %esi
0x00402046:	subl %edx, $0x4<UINT8>
0x00402049:	leal %eax, 0x4(%ebp)
0x0040204c:	call 0x00401b5c
0x00401b5c:	pushl %ebx
0x00401b5d:	addl %esp, $0xffffffe8<UINT8>
0x00401b60:	movl %ebx, %ecx
0x00401b62:	leal %ecx, 0x3fff(%eax)
0x00401b68:	andl %ecx, $0xffffc000<UINT32>
0x00401b6e:	movl (%esp), %ecx
0x00401b71:	addl %edx, %eax
0x00401b73:	andl %edx, $0xffffc000<UINT32>
0x00401b79:	movl 0x4(%esp), %edx
0x00401b7d:	movl %eax, 0x4(%esp)
0x00401b81:	cmpl %eax, (%esp)
0x00401b84:	jbe 0x00401be5
0x00401be5:	xorl %eax, %eax
0x00401be7:	movl (%ebx), %eax
0x00401be9:	addl %esp, $0x18<UINT8>
0x00401bec:	popl %ebx
0x00401bed:	ret

0x00402051:	movl %edi, (%esp)
0x00402054:	testl %edi, %edi
0x00402056:	je 0x00402092
0x00402092:	movl %eax, %ebx
0x00402094:	addl %esp, $0xc<UINT8>
0x00402097:	popl %ebp
0x00402098:	popl %edi
0x00402099:	popl %esi
0x0040209a:	popl %ebx
0x0040209b:	ret

0x00402148:	testb %al, %al
0x0040214a:	jne 65
0x0040214c:	movl %eax, 0x485618
0x00402151:	movl 0x4(%esp), %eax
0x00402155:	movl %eax, (%esp)
0x00402158:	movl 0x485618, %eax
0x0040215d:	movl %eax, 0x4(%esp)
0x00402161:	movl %eax, (%eax)
0x00402163:	movl 0x8(%esp), %eax
0x00402167:	movl %eax, (%esp)
0x0040216a:	movl %edx, 0x4(%esp)
0x0040216e:	movl 0x4(%eax), %edx
0x00402171:	movl %eax, (%esp)
0x00402174:	movl %edx, 0x8(%esp)
0x00402178:	movl (%eax), %edx
0x0040217a:	movl %eax, 0x4(%esp)
0x0040217e:	movl %edx, (%esp)
0x00402181:	movl (%eax), %edx
0x00402183:	movl %eax, 0x8(%esp)
0x00402187:	movl %edx, (%esp)
0x0040218a:	movl 0x4(%eax), %edx
0x0040218d:	addl %esp, $0xc<UINT8>
0x00402190:	popl %esi
0x00402191:	popl %ebx
0x00402192:	ret

0x00402796:	movl %eax, 0x4855c8
0x0040279b:	movl -4(%ebp), %eax
0x0040279e:	xorl %eax, %eax
0x004027a0:	popl %edx
0x004027a1:	popl %ecx
0x004027a2:	popl %ecx
0x004027a3:	movl %fs:(%eax), %edx
0x004027a6:	pushl $0x4027c6<UINT32>
0x004027ab:	cmpb 0x48504d, $0x0<UINT8>
0x004027b2:	je 0x004027be
0x004027be:	ret

0x004027c6:	movl %eax, -4(%ebp)
0x004027c9:	popl %ebx
0x004027ca:	movl %esp, %ebp
0x004027cc:	popl %ebp
0x004027cd:	ret

0x00401efd:	ret

0x004021cf:	xorl %eax, %eax
0x004021d1:	movl 0x485620, %eax
0x004021d6:	xorl %eax, %eax
0x004021d8:	movl 0x48561c, %eax
0x0040271a:	xorl %eax, %eax
0x0040271c:	movl -4(%ebp), %eax
0x0040271f:	call 0x00404494
0x004027c4:	jmp 0x004027ab
0x00402724:	jmp 0x004027c6
0x00402adb:	movl %ebx, %eax
0x00402add:	testl %ebx, %ebx
0x00402adf:	je 0x00402aec
0x00402aec:	movl %eax, %ebx
0x00402aee:	popl %ebx
0x00402aef:	ret

0x0040cd21:	ret

0x0040cd29:	popl %edi
0x0040cd2a:	popl %esi
0x0040cd2b:	popl %ebx
0x0040cd2c:	movl %esp, %ebp
0x0040cd2e:	popl %ebp
0x0040cd2f:	ret

0x0040e30d:	movl %edx, -32(%ebp)
0x0040e310:	movl %eax, $0x485690<UINT32>
0x0040e315:	call 0x00404aac
0x0040e31a:	leal %eax, -44(%ebp)
0x0040e31d:	pushl %eax
0x0040e31e:	movl %ecx, $0x40e4e8<UINT32>
0x0040e323:	movl %edx, $0x20<UINT32>
0x0040e328:	movl %eax, %ebx
0x0040e32a:	call 0x0040c820
0x004023d8:	movl %eax, (%esi)
0x004023da:	call 0x00401dc8
0x00401dc8:	pushl %ebx
0x00401dc9:	addl %esp, $0xfffffff8<UINT8>
0x00401dcc:	cmpl %eax, 0x485618
0x00401dd2:	jne 0x00401ddd
0x00401dd4:	movl %edx, 0x4(%eax)
0x00401dd7:	movl 0x485618, %edx
0x00401ddd:	movl %edx, 0x4(%eax)
0x00401de0:	movl (%esp), %edx
0x00401de3:	movl %edx, 0x8(%eax)
0x00401de6:	cmpl %edx, $0x1000<UINT32>
0x00401dec:	jg 0x00401e3c
0x00401e3c:	movl %eax, (%eax)
0x00401e3e:	movl 0x4(%esp), %eax
0x00401e42:	movl %eax, (%esp)
0x00401e45:	movl %edx, 0x4(%esp)
0x00401e49:	movl (%eax), %edx
0x00401e4b:	movl %eax, 0x4(%esp)
0x00401e4f:	movl %edx, (%esp)
0x00401e52:	movl 0x4(%eax), %edx
0x00401e55:	popl %ecx
0x00401e56:	popl %edx
0x00401e57:	popl %ebx
0x00401e58:	ret

0x004023df:	movl %eax, (%esi)
0x004023e1:	movl %edx, 0x8(%eax)
0x004023e4:	movl %eax, %edx
0x004023e6:	subl %eax, %ebx
0x004023e8:	cmpl %eax, $0xc<UINT8>
0x004023eb:	jl 12
0x004023ed:	movl %edx, (%esi)
0x004023ef:	addl %edx, %ebx
0x004023f1:	xchgl %edx, %eax
0x004023f2:	call 0x0040209c
0x004023f7:	jmp 0x00402417
0x00402417:	movl %eax, (%esi)
0x00402419:	movl 0x4(%esp), %eax
0x0040241d:	movl %eax, %ebx
0x0040241f:	orl %eax, $0x2<UINT8>
0x00402422:	movl %edx, 0x4(%esp)
0x00402426:	movl (%edx), %eax
0x00402428:	movl %eax, 0x4(%esp)
0x0040242c:	addl %eax, $0x4<UINT8>
0x0040242f:	movl (%esp), %eax
0x00402432:	incl 0x4855b4
0x00402438:	subl %ebx, $0x4<UINT8>
0x0040243b:	addl 0x4855b8, %ebx
0x0040e32f:	movl %eax, -44(%ebp)
0x0040e332:	leal %edx, -40(%ebp)
0x0040e335:	call 0x0040cb58
0x00402750:	movl %eax, -12(%ebp)
0x00402753:	movl -16(%ebp), %eax
0x00402756:	movl %eax, -16(%ebp)
0x00402759:	cmpl 0x4(%eax), $0x0<UINT8>
0x0040275d:	je 17
0x0040275f:	movl %eax, -16(%ebp)
0x00402762:	cmpl (%eax), $0x0<UINT8>
0x00402765:	je 9
0x00402767:	movl %eax, -16(%ebp)
0x0040276a:	cmpl 0x8(%eax), $0xc<UINT8>
0x0040276e:	jnl 0x0040277c
0x0040277c:	movl %eax, -16(%ebp)
0x0040277f:	movl %eax, 0x8(%eax)
0x00402782:	addl %ebx, %eax
0x00402784:	movl %eax, -16(%ebp)
0x00402787:	call 0x00401dc8
0x0040e33a:	movl %edx, -40(%ebp)
0x0040e33d:	movl %eax, $0x485694<UINT32>
0x0040e342:	call 0x00404aac
0x0040e347:	movb %cl, $0x3a<UINT8>
0x0040e349:	movl %edx, $0x1e<UINT32>
0x0040e34e:	movl %eax, %ebx
0x0040e350:	call 0x0040c86c
0x0040e355:	movb 0x485698, %al
0x0040e35a:	leal %eax, -48(%ebp)
0x0040e35d:	pushl %eax
0x0040e35e:	movl %ecx, $0x40e500<UINT32>
0x0040e363:	movl %edx, $0x28<UINT32>
0x0040e368:	movl %eax, %ebx
0x0040e36a:	call 0x0040c820
0x0040e36f:	movl %edx, -48(%ebp)
0x0040e372:	movl %eax, $0x48569c<UINT32>
0x0040e377:	call 0x00404aac
0x0040e37c:	leal %eax, -52(%ebp)
0x0040e37f:	pushl %eax
0x0040e380:	movl %ecx, $0x40e50c<UINT32>
0x0040e385:	movl %edx, $0x29<UINT32>
0x0040e38a:	movl %eax, %ebx
0x0040e38c:	call 0x0040c820
0x0040e391:	movl %edx, -52(%ebp)
0x0040e394:	movl %eax, $0x4856a0<UINT32>
0x0040e399:	call 0x00404aac
0x0040e39e:	leal %eax, -8(%ebp)
0x0040e3a1:	call 0x00404a58
0x0040e3a6:	leal %eax, -12(%ebp)
0x0040e3a9:	call 0x00404a58
0x0040e3ae:	leal %eax, -56(%ebp)
0x0040e3b1:	pushl %eax
0x0040e3b2:	movl %ecx, $0x40e4cc<UINT32>
0x0040e3b7:	movl %edx, $0x25<UINT32>
0x0040e3bc:	movl %eax, %ebx
0x0040e3be:	call 0x0040c820
0x0040e3c3:	movl %eax, -56(%ebp)
0x0040e3c6:	xorl %edx, %edx
0x0040e3c8:	call 0x0040927c
0x0040e3cd:	testl %eax, %eax
0x0040e3cf:	jne 15
0x0040e3d1:	leal %eax, -4(%ebp)
0x0040e3d4:	movl %edx, $0x40e518<UINT32>
0x0040e3d9:	call 0x00404af0
0x00404af0:	testl %edx, %edx
0x00404af2:	je 10
0x00404af4:	movl %ecx, -8(%edx)
0x00404af7:	incl %ecx
0x00404af8:	jle 0x00404afe
0x00404afe:	xchgl (%eax), %edx
0x00404b00:	testl %edx, %edx
0x00404b02:	je 0x00404b18
0x00404b18:	ret

0x0040e3de:	jmp 0x0040e3ed
0x0040e3ed:	leal %eax, -60(%ebp)
0x0040e3f0:	pushl %eax
0x0040e3f1:	movl %ecx, $0x40e4cc<UINT32>
0x0040e3f6:	movl %edx, $0x23<UINT32>
0x0040e3fb:	movl %eax, %ebx
0x0040e3fd:	call 0x0040c820
0x0040e402:	movl %eax, -60(%ebp)
0x0040e405:	xorl %edx, %edx
0x0040e407:	call 0x0040927c
0x0040e40c:	testl %eax, %eax
0x0040e40e:	jne 63
0x0040e410:	leal %eax, -64(%ebp)
0x0040e413:	pushl %eax
0x0040e414:	movl %ecx, $0x40e4cc<UINT32>
0x0040e419:	movl %edx, $0x1005<UINT32>
0x0040e41e:	movl %eax, %ebx
0x0040e420:	call 0x0040c820
0x0040e425:	movl %eax, -64(%ebp)
0x0040e428:	xorl %edx, %edx
0x0040e42a:	call 0x0040927c
0x0040e42f:	testl %eax, %eax
0x0040e431:	jne 15
0x0040e433:	leal %eax, -12(%ebp)
0x0040e436:	movl %edx, $0x40e530<UINT32>
0x0040e43b:	call 0x00404af0
0x0040e440:	jmp 0x0040e44f
0x0040e44f:	pushl -8(%ebp)
0x0040e452:	pushl -4(%ebp)
0x0040e455:	pushl $0x40e550<UINT32>
0x0040e45a:	pushl -12(%ebp)
0x0040e45d:	movl %eax, $0x4856a4<UINT32>
0x0040e462:	movl %edx, $0x4<UINT32>
0x0040e467:	call 0x00404dd8
0x00404dd8:	pushl %ebx
0x00404dd9:	pushl %esi
0x00404dda:	pushl %edi
0x00404ddb:	pushl %edx
0x00404ddc:	pushl %eax
0x00404ddd:	movl %ebx, %edx
0x00404ddf:	xorl %edi, %edi
0x00404de1:	movl %ecx, 0x14(%esp,%edx,4)
0x00404de5:	testl %ecx, %ecx
0x00404de7:	je 0x00404df5
0x00404df5:	xorl %eax, %eax
0x00404df7:	movl %ecx, 0x14(%esp,%edx,4)
0x00404dfb:	testl %ecx, %ecx
0x00404dfd:	je 0x00404e08
0x00404e08:	decl %edx
0x00404e09:	jne 0x00404df7
0x00404dff:	addl %eax, -4(%ecx)
0x00404e02:	cmpl %edi, %ecx
0x00404e04:	jne 0x00404e08
0x00404e0b:	testl %edi, %edi
0x00404e0d:	je 0x00404e26
0x00404e26:	call 0x00404b1c
0x00404e2b:	pushl %eax
0x00404e2c:	movl %esi, %eax
0x00404e2e:	movl %eax, 0x18(%esp,%ebx,4)
0x00404e32:	movl %edx, %esi
0x00404e34:	testl %eax, %eax
0x00404e36:	je 0x00404e42
0x00404e42:	decl %ebx
0x00404e43:	jne 0x00404e2e
0x00404e38:	movl %ecx, -4(%eax)
0x00404e3b:	addl %esi, %ecx
0x00404e3d:	call 0x00402cc0
0x00404e45:	popl %edx
0x00404e46:	popl %eax
0x00404e47:	testl %edi, %edi
0x00404e49:	jne 12
0x00404e4b:	testl %edx, %edx
0x00404e4d:	je 3
0x00404e4f:	decl -8(%edx)
0x00404e52:	call 0x00404aac
0x00404e57:	popl %edx
0x00404e58:	popl %edi
0x00404e59:	popl %esi
0x00404e5a:	popl %ebx
0x00404e5b:	popl %eax
0x00404e5c:	leal %esp, (%esp,%edx,4)
0x00404e5f:	jmp 0x0040e489
0x0040e46c:	pushl -8(%ebp)
0x0040e46f:	pushl -4(%ebp)
0x0040e472:	pushl $0x40e55c<UINT32>
0x0040e477:	pushl -12(%ebp)
0x0040e47a:	movl %eax, $0x4856a8<UINT32>
0x0040e47f:	movl %edx, $0x4<UINT32>
0x0040e484:	call 0x00404dd8
0x0040e489:	movb %cl, $0x2c<UINT8>
0x0040e48b:	movl %edx, $0xc<UINT32>
0x0040e490:	movl %eax, %ebx
0x0040e492:	call 0x0040c86c
0x0040e497:	movb 0x485752, %al
0x0040e49c:	xorl %eax, %eax
0x0040e49e:	popl %edx
0x0040e49f:	popl %ecx
0x0040e4a0:	popl %ecx
0x0040e4a1:	movl %fs:(%eax), %edx
0x0040e4a4:	pushl $0x40e4be<UINT32>
0x0040e4a9:	leal %eax, -64(%ebp)
0x0040e4ac:	movl %edx, $0x10<UINT32>
0x0040e4b1:	call 0x00404a7c
0x004020c1:	movl %eax, %ebx
0x004020c3:	testl %eax, %eax
0x004020c5:	jns 0x004020ca
0x004020ca:	sarl %eax, $0x2<UINT8>
0x004020cd:	movl %edx, 0x485624
0x004020d3:	movl %edx, -12(%edx,%eax,4)
0x004020d7:	movl 0x4(%esp), %edx
0x004020db:	cmpl 0x4(%esp), $0x0<UINT8>
0x004020e0:	jne 0x00402105
0x004020e2:	movl %edx, 0x485624
0x004020e8:	movl %ecx, (%esp)
0x004020eb:	movl -12(%edx,%eax,4), %ecx
0x004020ef:	movl %eax, (%esp)
0x004020f2:	movl %edx, (%esp)
0x004020f5:	movl 0x4(%eax), %edx
0x004020f8:	movl %eax, (%esp)
0x004020fb:	movl %edx, (%esp)
0x004020fe:	movl (%eax), %edx
0x00402100:	jmp 0x0040218d
0x00401dee:	cmpl %eax, (%esp)
0x00401df1:	jne 23
0x00401df3:	testl %edx, %edx
0x00401df5:	jns 0x00401dfa
0x00401dfa:	sarl %edx, $0x2<UINT8>
0x00401dfd:	movl %eax, 0x485624
0x00401e02:	xorl %ecx, %ecx
0x00401e04:	movl -12(%eax,%edx,4), %ecx
0x00401e08:	jmp 0x00401e55
0x00402105:	movl %eax, 0x4(%esp)
0x00402109:	movl %eax, (%eax)
0x0040210b:	movl 0x8(%esp), %eax
0x0040210f:	movl %eax, (%esp)
0x00402112:	movl %edx, 0x4(%esp)
0x00402116:	movl 0x4(%eax), %edx
0x00402119:	movl %eax, (%esp)
0x0040211c:	movl %edx, 0x8(%esp)
0x00402120:	movl (%eax), %edx
0x00402122:	movl %eax, 0x4(%esp)
0x00402126:	movl %edx, (%esp)
0x00402129:	movl (%eax), %edx
0x0040212b:	movl %eax, 0x8(%esp)
0x0040212f:	movl %edx, (%esp)
0x00402132:	movl 0x4(%eax), %edx
0x00402135:	jmp 0x0040218d
0x0040e4b6:	ret

0x0040e4be:	popl %ebx
0x0040e4bf:	movl %esp, %ebp
0x0040e4c1:	popl %ebp
0x0040e4c2:	ret

0x0040f272:	xorl %eax, %eax
0x0040f274:	popl %edx
0x0040f275:	popl %ecx
0x0040f276:	popl %ecx
0x0040f277:	movl %fs:(%eax), %edx
0x0040f27a:	pushl $0x40f287<UINT32>
0x0040f27f:	ret

0x0040f287:	popl %ebp
0x0040f288:	ret

0x0040fa84:	subl 0x4857fc, $0x1<UINT8>
0x0040fa8b:	jae 5
0x0040fa8d:	call 0x0040f748
0x0040f748:	pushl %ebp
0x0040f749:	movl %ebp, %esp
0x0040f74b:	pushl %ecx
0x0040f74c:	pushl $0x40f940<UINT32>
0x0040f751:	call 0x00407028
0x0040f756:	movl -4(%ebp), %eax
0x0040f759:	pushl %ebp
0x0040f75a:	movl %edx, $0x40f2b8<UINT32>
0x0040f75f:	movl %eax, $0x40f950<UINT32>
0x0040f764:	call 0x0040f71c
0x0040f71c:	pushl %ebp
0x0040f71d:	movl %ebp, %esp
0x0040f71f:	pushl %ebx
0x0040f720:	movl %ebx, %edx
0x0040f722:	movl %edx, %ebx
0x0040f724:	movl %ecx, 0x8(%ebp)
0x0040f727:	cmpl -4(%ecx), $0x0<UINT8>
0x0040f72b:	je 21
0x0040f72d:	pushl %eax
0x0040f72e:	movl %eax, 0x8(%ebp)
0x0040f731:	movl %eax, -4(%eax)
0x0040f734:	pushl %eax
0x0040f735:	call 0x00407030
0x00407030:	jmp GetProcAddress@KERNEL32.DLL
0x0040f73a:	movl %edx, %eax
0x0040f73c:	testl %edx, %edx
0x0040f73e:	jne 0x0040f742
0x0040f742:	movl %eax, %edx
0x0040f744:	popl %ebx
0x0040f745:	popl %ebp
0x0040f746:	ret

0x0040f769:	popl %ecx
0x0040f76a:	movl 0x4857a4, %eax
0x0040f76f:	pushl %ebp
0x0040f770:	movl %edx, $0x40f2e8<UINT32>
0x0040f775:	movl %eax, $0x40f964<UINT32>
0x0040f77a:	call 0x0040f71c
0x0040f77f:	popl %ecx
0x0040f780:	movl 0x4857a8, %eax
0x0040f785:	pushl %ebp
0x0040f786:	movl %edx, $0x40f2e8<UINT32>
0x0040f78b:	movl %eax, $0x40f96c<UINT32>
0x0040f790:	call 0x0040f71c
0x0040f795:	popl %ecx
0x0040f796:	movl 0x4857ac, %eax
0x0040f79b:	pushl %ebp
0x0040f79c:	movl %edx, $0x40f2f4<UINT32>
0x0040f7a1:	movl %eax, $0x40f974<UINT32>
0x0040f7a6:	call 0x0040f71c
0x0040f7ab:	popl %ecx
0x0040f7ac:	movl 0x4857b0, %eax
0x0040f7b1:	pushl %ebp
0x0040f7b2:	movl %edx, $0x40f2f4<UINT32>
0x0040f7b7:	movl %eax, $0x40f97c<UINT32>
0x0040f7bc:	call 0x0040f71c
0x0040f7c1:	popl %ecx
0x0040f7c2:	movl 0x4857b4, %eax
0x0040f7c7:	pushl %ebp
0x0040f7c8:	movl %edx, $0x40f2f4<UINT32>
0x0040f7cd:	movl %eax, $0x40f984<UINT32>
0x0040f7d2:	call 0x0040f71c
0x0040f7d7:	popl %ecx
0x0040f7d8:	movl 0x4857b8, %eax
0x0040f7dd:	pushl %ebp
0x0040f7de:	movl %edx, $0x40f2f4<UINT32>
0x0040f7e3:	movl %eax, $0x40f98c<UINT32>
0x0040f7e8:	call 0x0040f71c
0x0040f7ed:	popl %ecx
0x0040f7ee:	movl 0x4857bc, %eax
0x0040f7f3:	pushl %ebp
0x0040f7f4:	movl %edx, $0x40f2f4<UINT32>
0x0040f7f9:	movl %eax, $0x40f994<UINT32>
0x0040f7fe:	call 0x0040f71c
0x0040f803:	popl %ecx
0x0040f804:	movl 0x4857c0, %eax
0x0040f809:	pushl %ebp
0x0040f80a:	movl %edx, $0x40f2f4<UINT32>
0x0040f80f:	movl %eax, $0x40f99c<UINT32>
0x0040f814:	call 0x0040f71c
0x0040f819:	popl %ecx
0x0040f81a:	movl 0x4857c4, %eax
0x0040f81f:	pushl %ebp
0x0040f820:	movl %edx, $0x40f2f4<UINT32>
0x0040f825:	movl %eax, $0x40f9a4<UINT32>
0x0040f82a:	call 0x0040f71c
0x0040f82f:	popl %ecx
0x0040f830:	movl 0x4857c8, %eax
0x0040f835:	pushl %ebp
0x0040f836:	movl %edx, $0x40f2f4<UINT32>
0x0040f83b:	movl %eax, $0x40f9ac<UINT32>
0x0040f840:	call 0x0040f71c
0x0040f845:	popl %ecx
0x0040f846:	movl 0x4857cc, %eax
0x0040f84b:	pushl %ebp
0x0040f84c:	movl %edx, $0x40f2f4<UINT32>
0x0040f851:	movl %eax, $0x40f9b4<UINT32>
0x0040f856:	call 0x0040f71c
0x0040f85b:	popl %ecx
0x0040f85c:	movl 0x4857d0, %eax
0x0040f861:	pushl %ebp
0x0040f862:	movl %edx, $0x40f300<UINT32>
0x0040f867:	movl %eax, $0x40f9bc<UINT32>
0x0040f86c:	call 0x0040f71c
0x0040f871:	popl %ecx
0x0040f872:	movl 0x4857d4, %eax
0x0040f877:	pushl %ebp
0x0040f878:	movl %edx, $0x40f30c<UINT32>
0x0040f87d:	movl %eax, $0x40f9c4<UINT32>
0x0040f882:	call 0x0040f71c
0x0040f887:	popl %ecx
0x0040f888:	movl 0x4857d8, %eax
0x0040f88d:	pushl %ebp
0x0040f88e:	movl %edx, $0x40f378<UINT32>
0x0040f893:	movl %eax, $0x40f9d4<UINT32>
0x0040f898:	call 0x0040f71c
0x0040f89d:	popl %ecx
0x0040f89e:	movl 0x4857dc, %eax
0x0040f8a3:	pushl %ebp
0x0040f8a4:	movl %edx, $0x40f3e4<UINT32>
0x0040f8a9:	movl %eax, $0x40f9e4<UINT32>
0x0040f8ae:	call 0x0040f71c
0x0040f8b3:	popl %ecx
0x0040f8b4:	movl 0x4857e0, %eax
0x0040f8b9:	pushl %ebp
0x0040f8ba:	movl %edx, $0x40f450<UINT32>
0x0040f8bf:	movl %eax, $0x40f9f4<UINT32>
0x0040f8c4:	call 0x0040f71c
0x0040f8c9:	popl %ecx
0x0040f8ca:	movl 0x4857e4, %eax
0x0040f8cf:	pushl %ebp
0x0040f8d0:	movl %edx, $0x40f4bc<UINT32>
0x0040f8d5:	movl %eax, $0x40fa04<UINT32>
0x0040f8da:	call 0x0040f71c
0x0040f8df:	popl %ecx
0x0040f8e0:	movl 0x4857e8, %eax
0x0040f8e5:	pushl %ebp
0x0040f8e6:	movl %edx, $0x40f528<UINT32>
0x0040f8eb:	movl %eax, $0x40fa14<UINT32>
0x0040f8f0:	call 0x0040f71c
0x0040f8f5:	popl %ecx
0x0040f8f6:	movl 0x4857ec, %eax
0x0040f8fb:	pushl %ebp
0x0040f8fc:	movl %edx, $0x40f5a8<UINT32>
0x0040f901:	movl %eax, $0x40fa24<UINT32>
0x0040f906:	call 0x0040f71c
0x0040f90b:	popl %ecx
0x0040f90c:	movl 0x4857f0, %eax
0x0040f911:	pushl %ebp
0x0040f912:	movl %edx, $0x40f618<UINT32>
0x0040f917:	movl %eax, $0x40fa34<UINT32>
0x0040f91c:	call 0x0040f71c
0x0040f921:	popl %ecx
0x0040f922:	movl 0x4857f4, %eax
0x0040f927:	pushl %ebp
0x0040f928:	movl %edx, $0x40f688<UINT32>
0x0040f92d:	movl %eax, $0x40fa44<UINT32>
0x0040f932:	call 0x0040f71c
0x0040f937:	popl %ecx
0x0040f938:	movl 0x4857f8, %eax
0x0040f93d:	popl %ecx
0x0040f93e:	popl %ebp
0x0040f93f:	ret

0x0040fa92:	ret

0x004154fc:	pushl %ebp
0x004154fd:	movl %ebp, %esp
0x004154ff:	xorl %eax, %eax
0x00415501:	pushl %ebp
0x00415502:	pushl $0x41559d<UINT32>
0x00415507:	pushl %fs:(%eax)
0x0041550a:	movl %fs:(%eax), %esp
0x0041550d:	subl 0x485820, $0x1<UINT8>
0x00415514:	jae 121
0x00415516:	movl %eax, $0x485800<UINT32>
0x0041551b:	call 0x00415008
0x00415008:	movl %edx, $0x80020004<UINT32>
0x0041500d:	call 0x00414ff0
0x00414ff0:	pushl %ebx
0x00414ff1:	pushl %esi
0x00414ff2:	movl %esi, %edx
0x00414ff4:	movl %ebx, %eax
0x00414ff6:	movl %eax, %ebx
0x00414ff8:	call 0x004108a4
0x004108a4:	testw (%eax), $0xffffbfe8<UINT16>
0x004108a9:	jne 6
0x004108ab:	movw (%eax), $0x0<UINT16>
0x004108b0:	ret

0x00414ffd:	movw (%ebx), $0xa<UINT16>
0x00415002:	movl 0x8(%ebx), %esi
0x00415005:	popl %esi
0x00415006:	popl %ebx
0x00415007:	ret

0x00415012:	ret

0x00415520:	movl %eax, $0x4105b8<UINT32>
0x00415525:	movl 0x485810, %eax
0x0041552a:	movl %eax, $0x41015c<UINT32>
0x0041552f:	movl 0x485814, %eax
0x00415534:	movl %edx, $0x41006c<UINT32>
0x00415539:	movl 0x485818, %edx
0x0041553f:	movl 0x48581c, %eax
0x00415544:	movl %eax, $0x4108b8<UINT32>
0x00415549:	movl %edx, 0x484630
0x0041554f:	movl (%edx), %eax
0x00415551:	movl %eax, $0x414cfc<UINT32>
0x00415556:	movl %edx, 0x4843b0
0x0041555c:	movl (%edx), %eax
0x0041555e:	movl %eax, $0x410be0<UINT32>
0x00415563:	movl %edx, 0x4846c0
0x00415569:	movl (%edx), %eax
0x0041556b:	movl %eax, $0x413ba8<UINT32>
0x00415570:	movl %edx, 0x484830
0x00415576:	movl (%edx), %eax
0x00415578:	movl %eax, $0x4142c8<UINT32>
0x0041557d:	movl %edx, 0x4846e8
0x00415583:	movl (%edx), %eax
0x00415585:	pushl $0x485828<UINT32>
0x0041558a:	call 0x004070b8
0x004070b8:	jmp InitializeCriticalSection@KERNEL32.DLL
0x0041558f:	xorl %eax, %eax
0x00415591:	popl %edx
0x00415592:	popl %ecx
0x00415593:	popl %ecx
0x00415594:	movl %fs:(%eax), %edx
0x00415597:	pushl $0x4155a4<UINT32>
0x0041559c:	ret

0x004155a4:	popl %ebp
0x004155a5:	ret

0x004156d8:	subl 0x485840, $0x1<UINT8>
0x004156df:	ret

0x00415f14:	subl 0x485844, $0x1<UINT8>
0x00415f1b:	ret

0x004207d0:	pushl %ebp
0x004207d1:	movl %ebp, %esp
0x004207d3:	xorl %eax, %eax
0x004207d5:	pushl %ebp
0x004207d6:	pushl $0x420859<UINT32>
0x004207db:	pushl %fs:(%eax)
0x004207de:	movl %fs:(%eax), %esp
0x004207e1:	subl 0x485858, $0x1<UINT8>
0x004207e8:	jae 97
0x004207ea:	call 0x0041ed30
0x0041ed30:	pushl $0x48586c<UINT32>
0x0041ed35:	call 0x004070b8
0x0041ed3a:	pushl $0x41ed60<UINT32>
0x0041ed3f:	pushl $0x0<UINT8>
0x0041ed41:	pushl $0xffffffff<UINT8>
0x0041ed43:	pushl $0x0<UINT8>
0x0041ed45:	call 0x00406f20
0x00406f20:	jmp CreateEventA@KERNEL32.DLL
CreateEventA@KERNEL32.DLL: API Node	
0x0041ed4a:	movl 0x485854, %eax
0x0041ed4f:	cmpl 0x485854, $0x0<UINT8>
0x0041ed56:	jne 0x0041ed5d
0x0041ed5d:	ret

0x004207ef:	movl %eax, $0x420558<UINT32>
0x004207f4:	call 0x004063fc
0x004063fc:	call 0x0040640c
0x0040640c:	pushl %ebx
0x0040640d:	movl %ebx, %eax
0x0040640f:	movl %eax, $0x8<UINT32>
0x00406414:	call 0x00402aa0
0x00406419:	movl %edx, 0x48303c
0x0040641f:	movl (%eax), %edx
0x00406421:	movl 0x4(%eax), %ebx
0x00406424:	movl 0x48303c, %eax
0x00406429:	popl %ebx
0x0040642a:	ret

0x00406401:	ret

0x004207f9:	movb %dl, $0x1<UINT8>
0x004207fb:	movl %eax, 0x408a84
0x00420800:	call 0x0040e9a4
0x0040e9a4:	pushl %ebx
0x0040e9a5:	pushl %esi
0x0040e9a6:	testb %dl, %dl
0x0040e9a8:	je 8
0x0040e9aa:	addl %esp, $0xfffffff0<UINT8>
0x0040e9ad:	call 0x00403f80
0x00406640:	call 0x00403be0
0x00403c79:	pushl %ecx
0x00403c89:	popl %ebx
0x00403c8a:	movl %ecx, (%ebx)
0x00403c8c:	addl %ebx, $0x4<UINT8>
0x00403c8f:	movl %esi, 0x10(%ebx)
0x00403c92:	testl %esi, %esi
0x00403c94:	je 6
0x00403c96:	movl %edi, 0x14(%ebx)
0x00403c99:	movl (%edi,%eax), %esi
0x00403c9c:	addl %ebx, $0x1c<UINT8>
0x00403c9f:	decl %ecx
0x00403ca0:	jne -19
0x00403ca2:	cmpl %esp, %edx
0x00403ca4:	jne 0x00403c89
0x00406645:	movl 0x4(%eax), $0x1<UINT32>
0x0040664c:	ret

0x0040e9b2:	movl %ebx, %edx
0x0040e9b4:	movl %esi, %eax
0x0040e9b6:	xorl %edx, %edx
0x0040e9b8:	movl %eax, %esi
0x0040e9ba:	call 0x00403c18
0x00403c18:	testb %dl, %dl
0x00403c1a:	je 0x00403c24
0x00403c24:	testb %dl, %dl
0x00403c26:	je 0x00403c37
0x00403c37:	ret

0x0040e9bf:	movl 0xc(%esi), $0xffff<UINT32>
0x0040e9c6:	pushl $0x0<UINT8>
0x0040e9c8:	pushl $0xffffffff<UINT8>
0x0040e9ca:	pushl $0xffffffff<UINT8>
0x0040e9cc:	pushl $0x0<UINT8>
0x0040e9ce:	call 0x00406f20
0x0040e9d3:	movl 0x10(%esi), %eax
0x0040e9d6:	pushl $0x0<UINT8>
0x0040e9d8:	pushl $0x0<UINT8>
0x0040e9da:	pushl $0x0<UINT8>
0x0040e9dc:	pushl $0x0<UINT8>
0x0040e9de:	call 0x00406f20
0x0040e9e3:	movl 0x14(%esi), %eax
0x0040e9e6:	movl 0x18(%esi), $0xffffffff<UINT32>
0x0040e9ed:	movb %dl, $0x1<UINT8>
0x0040e9ef:	movl %eax, 0x4089a8
0x0040e9f4:	call 0x00403c18
0x00403c1c:	addl %esp, $0xfffffff0<UINT8>
0x00403c1f:	call 0x00403f80
0x00403c28:	call 0x00403fd8
0x00403c2d:	popl %fs:0
0x00403c34:	addl %esp, $0xc<UINT8>
0x0040e9f9:	movl 0x20(%esi), %eax
0x0040e9fc:	movl %eax, %esi
0x0040e9fe:	testb %bl, %bl
0x0040ea00:	je 15
0x0040ea02:	call 0x00403fd8
0x00406624:	addl %eax, $0x4<UINT8>
0x00406627:	pushl %eax
0x00406628:	call 0x0040136c
0x0040136c:	jmp InterlockedDecrement@KERNEL32.DLL
InterlockedDecrement@KERNEL32.DLL: API Node	
0x0040662d:	ret

0x0040ea07:	popl %fs:0
0x0040ea0e:	addl %esp, $0xc<UINT8>
0x0040ea11:	movl %eax, %esi
0x0040ea13:	popl %esi
0x0040ea14:	popl %ebx
0x0040ea15:	ret

0x00420805:	movl %edx, %eax
0x00420807:	testl %edx, %edx
0x00420809:	je 3
0x0042080b:	subl %edx, $0xffffffd4<UINT8>
0x0042080e:	movl %eax, $0x48584c<UINT32>
0x00420813:	call 0x004065bc
0x004065bc:	testl %edx, %edx
0x004065be:	je 25
0x004065c0:	pushl %edx
0x004065c1:	pushl %eax
0x004065c2:	movl %eax, (%edx)
0x004065c4:	pushl %edx
0x004065c5:	call 0x00408a33
0x00408a33:	addl 0x4(%esp), $0xffffffd4<UINT8>
0x00408a38:	jmp 0x00406678
0x00406678:	pushl %ebp
0x00406679:	movl %ebp, %esp
0x0040667b:	movl %eax, 0x8(%ebp)
0x0040667e:	addl %eax, $0x4<UINT8>
0x00406681:	pushl %eax
0x00406682:	call 0x00401364
0x00401364:	jmp InterlockedIncrement@KERNEL32.DLL
InterlockedIncrement@KERNEL32.DLL: API Node	
0x00406687:	popl %ebp
0x00406688:	ret $0x4<UINT16>

0x004065c8:	popl %eax
0x004065c9:	movl %ecx, (%eax)
0x004065cb:	popl (%eax)
0x004065cd:	testl %ecx, %ecx
0x004065cf:	jne 1
0x004065d1:	ret

0x00420818:	movb %dl, $0x1<UINT8>
0x0042081a:	movl %eax, 0x4178e4
0x0042081f:	call 0x00417d48
0x00417d48:	pushl %ebx
0x00417d49:	pushl %esi
0x00417d4a:	pushl %edi
0x00417d4b:	testb %dl, %dl
0x00417d4d:	je 8
0x00417d4f:	addl %esp, $0xfffffff0<UINT8>
0x00417d52:	call 0x00403f80
0x00417d57:	movl %ebx, %edx
0x00417d59:	movl %edi, %eax
0x00417d5b:	xorl %edx, %edx
0x00417d5d:	movl %eax, %edi
0x00417d5f:	call 0x00403c18
0x00417d64:	movb %dl, $0x1<UINT8>
0x00417d66:	movl %eax, 0x41670c
0x00417d6b:	call 0x00403c18
0x00417d70:	movl 0x4(%edi), %eax
0x00417d73:	leal %eax, 0x8(%edi)
0x00417d76:	pushl %eax
0x00417d77:	call 0x004070b8
0x00417d7c:	movl %ecx, 0x41681c
0x00417d82:	movb %dl, $0x1<UINT8>
0x00417d84:	movl %eax, 0x41788c
0x00417d89:	call 0x00417a18
0x00417a18:	pushl %ebp
0x00417a19:	movl %ebp, %esp
0x00417a1b:	pushl %ecx
0x00417a1c:	pushl %ebx
0x00417a1d:	pushl %esi
0x00417a1e:	pushl %edi
0x00417a1f:	testb %dl, %dl
0x00417a21:	je 8
0x00417a23:	addl %esp, $0xfffffff0<UINT8>
0x00417a26:	call 0x00403f80
0x00417a2b:	movl %edi, %ecx
0x00417a2d:	movb -1(%ebp), %dl
0x00417a30:	movl %ebx, %eax
0x00417a32:	xorl %edx, %edx
0x00417a34:	movl %eax, %ebx
0x00417a36:	call 0x00403c18
0x00417a3b:	movb %dl, $0x1<UINT8>
0x00417a3d:	movl %eax, 0x41670c
0x00417a42:	call 0x00403c18
0x00417a47:	movl 0x4(%ebx), %eax
0x00417a4a:	movb %dl, $0x1<UINT8>
0x00417a4c:	movl %eax, 0x416cb4
0x00417a51:	call 0x00403c18
0x00417a56:	movl 0x8(%ebx), %eax
0x00417a59:	movb %dl, $0x1<UINT8>
0x00417a5b:	movl %eax, 0x41670c
0x00417a60:	call 0x00403c18
0x00417a65:	movl %esi, %eax
0x00417a67:	movl 0xc(%ebx), %esi
0x00417a6a:	movl %eax, %esi
0x00417a6c:	movl %edx, %edi
0x00417a6e:	call 0x00418b00
0x00418b00:	pushl %ebx
0x00418b01:	pushl %esi
0x00418b02:	pushl %edi
0x00418b03:	movl %edi, %edx
0x00418b05:	movl %ebx, %eax
0x00418b07:	movl %esi, 0x8(%ebx)
0x00418b0a:	cmpl %esi, 0xc(%ebx)
0x00418b0d:	jne 6
0x00418b0f:	movl %eax, %ebx
0x00418b11:	movl %edx, (%eax)
0x00418b13:	call 0x00418c84
0x00418c84:	movl %edx, 0xc(%eax)
0x00418c87:	cmpl %edx, $0x40<UINT8>
0x00418c8a:	jle 0x00418c9a
0x00418c9a:	cmpl %edx, $0x8<UINT8>
0x00418c9d:	jle 0x00418ca6
0x00418ca6:	movl %ecx, $0x4<UINT32>
0x00418cab:	addl %ecx, %edx
0x00418cad:	movl %edx, %ecx
0x00418caf:	call 0x00418e18
0x00418e18:	pushl %ebx
0x00418e19:	pushl %esi
0x00418e1a:	movl %esi, %edx
0x00418e1c:	movl %ebx, %eax
0x00418e1e:	cmpl %esi, 0x8(%ebx)
0x00418e21:	jl 8
0x00418e23:	cmpl %esi, $0x7ffffff<UINT32>
0x00418e29:	jle 0x00418e3a
0x00418e3a:	cmpl %esi, 0xc(%ebx)
0x00418e3d:	je 16
0x00418e3f:	movl %edx, %esi
0x00418e41:	shll %edx, $0x2<UINT8>
0x00418e44:	leal %eax, 0x4(%ebx)
0x00418e47:	call 0x00402af0
0x00402af0:	movl %ecx, (%eax)
0x00402af2:	testl %ecx, %ecx
0x00402af4:	je 0x00402b28
0x00402b28:	testl %edx, %edx
0x00402b2a:	je 16
0x00402b2c:	pushl %eax
0x00402b2d:	movl %eax, %edx
0x00402b2f:	call 0x0040244c
0x00402b35:	popl %ecx
0x00402b36:	orl %eax, %eax
0x00402b38:	je -25
0x00402b3a:	movl (%ecx), %eax
0x00402b3c:	ret

0x00418e4c:	movl 0xc(%ebx), %esi
0x00418e4f:	popl %esi
0x00418e50:	popl %ebx
0x00418e51:	ret

0x00418cb4:	ret

0x00418b15:	movl %eax, 0x4(%ebx)
0x00418b18:	movl (%eax,%esi,4), %edi
0x00418b1b:	incl 0x8(%ebx)
0x00418b1e:	testl %edi, %edi
0x00418b20:	je 11
0x00418b22:	xorl %ecx, %ecx
0x00418b24:	movl %edx, %edi
0x00418b26:	movl %eax, %ebx
0x00418b28:	movl %ebx, (%eax)
0x00418b2a:	call 0x00418ec4
0x00418ec4:	ret

0x00418b2d:	movl %eax, %esi
0x00418b2f:	popl %edi
0x00418b30:	popl %esi
0x00418b31:	popl %ebx
0x00418b32:	ret

0x00417a73:	movl %eax, %ebx
0x00417a75:	cmpb -1(%ebp), $0x0<UINT8>
0x00417a79:	je 15
0x00417a7b:	call 0x00403fd8
0x00417a80:	popl %fs:0
0x00417a87:	addl %esp, $0xc<UINT8>
0x00417a8a:	movl %eax, %ebx
0x00417a8c:	popl %edi
0x00417a8d:	popl %esi
0x00417a8e:	popl %ebx
0x00417a8f:	popl %ecx
0x00417a90:	popl %ebp
0x00417a91:	ret

0x00417d8e:	movl %esi, %eax
0x00417d90:	movl %eax, 0x4(%edi)
0x00417d93:	movl %edx, %esi
0x00417d95:	call 0x00418b00
0x00417d9a:	movb 0x10(%esi), $0x1<UINT8>
0x00417d9e:	movl %eax, %edi
0x00417da0:	testb %bl, %bl
0x00417da2:	je 15
0x00417da4:	call 0x00403fd8
0x00417da9:	popl %fs:0
0x00417db0:	addl %esp, $0xc<UINT8>
0x00417db3:	movl %eax, %edi
0x00417db5:	popl %edi
0x00417db6:	popl %esi
0x00417db7:	popl %ebx
0x00417db8:	ret

0x00420824:	movl 0x485860, %eax
0x00420829:	movb %dl, $0x1<UINT8>
0x0042082b:	movl %eax, 0x416770
0x00420830:	call 0x00418ec8
0x00418ec8:	pushl %ebx
0x00418ec9:	pushl %esi
0x00418eca:	testb %dl, %dl
0x00418ecc:	je 8
0x00418ece:	addl %esp, $0xfffffff0<UINT8>
0x00418ed1:	call 0x00403f80
0x00418ed6:	movl %ebx, %edx
0x00418ed8:	movl %esi, %eax
0x00418eda:	xorl %edx, %edx
0x00418edc:	movl %eax, %esi
0x00418ede:	call 0x00403c18
0x00418ee3:	leal %eax, 0x8(%esi)
0x00418ee6:	pushl %eax
0x00418ee7:	call 0x004070b8
0x00418eec:	movb %dl, $0x1<UINT8>
0x00418eee:	movl %eax, 0x41670c
0x00418ef3:	call 0x00403c18
0x00418ef8:	movl 0x4(%esi), %eax
0x00418efb:	movb 0x20(%esi), $0x0<UINT8>
0x00418eff:	movl %eax, %esi
0x00418f01:	testb %bl, %bl
0x00418f03:	je 15
0x00418f05:	call 0x00403fd8
0x00418f0a:	popl %fs:0
0x00418f11:	addl %esp, $0xc<UINT8>
0x00418f14:	movl %eax, %esi
0x00418f16:	popl %esi
0x00418f17:	popl %ebx
0x00418f18:	ret

0x00420835:	movl 0x48585c, %eax
0x0042083a:	movb %dl, $0x1<UINT8>
0x0042083c:	movl %eax, 0x416770
0x00420841:	call 0x00418ec8
0x00420846:	movl 0x485868, %eax
0x0042084b:	xorl %eax, %eax
0x0042084d:	popl %edx
0x0042084e:	popl %ecx
0x0042084f:	popl %ecx
0x00420850:	movl %fs:(%eax), %edx
0x00420853:	pushl $0x420860<UINT32>
0x00420858:	ret

0x00420860:	popl %ebp
0x00420861:	ret

0x00429c70:	subl 0x4858f4, $0x1<UINT8>
0x00429c77:	ret

0x00429f28:	subl 0x4858f8, $0x1<UINT8>
0x00429f2f:	ret

0x0042b878:	subl 0x485940, $0x1<UINT8>
0x0042b87f:	ret

0x0042a840:	subl 0x485928, $0x1<UINT8>
0x0042a847:	jae 5
0x0042a849:	call 0x0042a7a4
0x0042a7a4:	pushl $0x42a804<UINT32>
0x0042a7a9:	call 0x00407028
0x0042a7ae:	movl 0x48592c, %eax
0x0042a7b3:	movl 0x485908, $0x42a1b0<UINT32>
0x0042a7bd:	movl 0x48590c, $0x42a2c8<UINT32>
0x0042a7c7:	movl 0x485910, $0x42a238<UINT32>
0x0042a7d1:	movl 0x485914, $0x42a360<UINT32>
0x0042a7db:	movl 0x485918, $0x42a3f8<UINT32>
0x0042a7e5:	movl 0x48591c, $0x42a4cc<UINT32>
0x0042a7ef:	movl 0x485920, $0x42a5a0<UINT32>
0x0042a7f9:	movl 0x485924, $0x42a674<UINT32>
0x0042a803:	ret

0x0042a84e:	ret

0x0042a0c0:	subl 0x4858fc, $0x1<UINT8>
0x0042a0c7:	ret

0x00420b6c:	subl 0x485890, $0x1<UINT8>
0x00420b73:	ret

0x00429b34:	subl 0x485898, $0x1<UINT8>
0x00429b3b:	jae 237
0x00429b41:	call 0x00429630
0x00429630:	pushl %ebx
0x00429631:	pushl $0x0<UINT8>
0x00429633:	call 0x00407570
0x00407570:	jmp GetDC@user32.dll
GetDC@user32.dll: API Node	
0x00429638:	movl %ebx, %eax
0x0042963a:	pushl $0x5a<UINT8>
0x0042963c:	pushl %ebx
0x0042963d:	call 0x00407270
0x00407270:	jmp GetDeviceCaps@gdi32.dll
GetDeviceCaps@gdi32.dll: API Node	
0x00429642:	movl 0x48589c, %eax
0x00429647:	pushl %ebx
0x00429648:	pushl $0x0<UINT8>
0x0042964a:	call 0x004077d0
0x004077d0:	jmp ReleaseDC@user32.dll
ReleaseDC@user32.dll: API Node	
0x0042964f:	movl %eax, $0x48378c<UINT32>
0x00429654:	movl %edx, $0xf<UINT32>
0x00429659:	call 0x00424218
0x00424218:	pushl %ebp
0x00424219:	movl %ebp, %esp
0x0042421b:	addl %esp, $0xfffffbf8<UINT32>
0x00424221:	pushl %ebx
0x00424222:	movw -1032(%ebp), $0x300<UINT16>
0x0042422b:	movw -1030(%ebp), $0x10<UINT16>
0x00424234:	leal %edx, -1028(%ebp)
0x0042423a:	movl %ecx, $0x40<UINT32>
0x0042423f:	call 0x00402cc0
0x00424244:	pushl $0x0<UINT8>
0x00424246:	call 0x00407570
0x0042424b:	movl -4(%ebp), %eax
0x0042424e:	xorl %eax, %eax
0x00424250:	pushl %ebp
0x00424251:	pushl $0x424315<UINT32>
0x00424256:	pushl %fs:(%eax)
0x00424259:	movl %fs:(%eax), %esp
0x0042425c:	pushl $0x68<UINT8>
0x0042425e:	movl %eax, -4(%ebp)
0x00424261:	pushl %eax
0x00424262:	call 0x00407270
0x00424267:	movl %ebx, %eax
0x00424269:	cmpl %ebx, $0x10<UINT8>
0x0042426c:	jl 0x004242fc
0x004242fc:	xorl %eax, %eax
0x004242fe:	popl %edx
0x004242ff:	popl %ecx
0x00424300:	popl %ecx
0x00424301:	movl %fs:(%eax), %edx
0x00424304:	pushl $0x42431c<UINT32>
0x00424309:	movl %eax, -4(%ebp)
0x0042430c:	pushl %eax
0x0042430d:	pushl $0x0<UINT8>
0x0042430f:	call 0x004077d0
0x00424314:	ret

0x0042431c:	leal %eax, -1032(%ebp)
0x00424322:	pushl %eax
0x00424323:	call 0x004071f0
0x004071f0:	jmp CreatePalette@gdi32.dll
CreatePalette@gdi32.dll: API Node	
0x00424328:	popl %ebx
0x00424329:	movl %esp, %ebp
0x0042432b:	popl %ebp
0x0042432c:	ret

0x0042965e:	movl 0x485894, %eax
0x00429663:	popl %ebx
0x00429664:	ret

0x00429b46:	pushl $0x4858b0<UINT32>
0x00429b4b:	call 0x004070b8
0x00429b50:	pushl $0x4858c8<UINT32>
0x00429b55:	call 0x004070b8
0x00429b5a:	pushl $0x7<UINT8>
0x00429b5c:	call 0x004072b0
0x004072b0:	jmp GetStockObject@gdi32.dll
GetStockObject@gdi32.dll: API Node	
0x00429b61:	movl 0x4858a0, %eax
0x00429b66:	pushl $0x5<UINT8>
0x00429b68:	call 0x004072b0
0x00429b6d:	movl 0x4858a4, %eax
0x00429b72:	pushl $0xd<UINT8>
0x00429b74:	call 0x004072b0
0x00429b79:	movl 0x4858a8, %eax
0x00429b7e:	pushl $0x7f00<UINT32>
0x00429b83:	pushl $0x0<UINT8>
0x00429b85:	call 0x00407730
0x00407730:	jmp LoadIconA@user32.dll
LoadIconA@user32.dll: API Node	
0x00429b8a:	movl 0x4858ac, %eax
0x00429b8f:	call 0x004296ac
0x004296ac:	pushl %ebx
0x004296ad:	pushl %esi
0x004296ae:	pushl %edi
0x004296af:	pushl $0x48<UINT8>
0x004296b1:	movl %eax, 0x48589c
0x004296b6:	pushl %eax
0x004296b7:	pushl $0x8<UINT8>
0x004296b9:	call 0x004070e0
0x004070e0:	jmp MulDiv@KERNEL32.DLL
MulDiv@KERNEL32.DLL: API Node	
0x004296be:	negl %eax
0x004296c0:	movl 0x4834cc, %eax
0x004296c5:	movl %eax, 0x484878
0x004296ca:	cmpb 0xc(%eax), $0x0<UINT8>
0x004296ce:	je 0x00429707
0x00429707:	popl %edi
0x00429708:	popl %esi
0x00429709:	popl %ebx
0x0042970a:	ret

0x00429b94:	movw %cx, $0x2c<UINT16>
0x00429b98:	movb %dl, $0x1<UINT8>
0x00429b9a:	movl %eax, 0x421b68
0x00429b9f:	call 0x00421bdc
0x00421bdc:	pushl %ebx
0x00421bdd:	pushl %esi
0x00421bde:	testb %dl, %dl
0x00421be0:	je 8
0x00421be2:	addl %esp, $0xfffffff0<UINT8>
0x00421be5:	call 0x00403f80
0x00421bea:	movl %ebx, %edx
0x00421bec:	movl %esi, %eax
0x00421bee:	movw 0x20(%esi), %cx
0x00421bf2:	leal %eax, 0x8(%esi)
0x00421bf5:	pushl %eax
0x00421bf6:	call 0x004070b8
0x00421bfb:	movl %eax, %esi
0x00421bfd:	testb %bl, %bl
0x00421bff:	je 15
0x00421c01:	call 0x00403fd8
0x00421c06:	popl %fs:0
0x00421c0d:	addl %esp, $0xc<UINT8>
0x00421c10:	movl %eax, %esi
0x00421c12:	popl %esi
0x00421c13:	popl %ebx
0x00421c14:	ret

0x00429ba4:	movl 0x4858e0, %eax
0x00429ba9:	movw %cx, $0x10<UINT16>
0x00429bad:	movb %dl, $0x1<UINT8>
0x00429baf:	movl %eax, 0x421b68
0x00429bb4:	call 0x00421bdc
0x00429bb9:	movl 0x4858e4, %eax
0x00429bbe:	movw %cx, $0x10<UINT16>
0x00429bc2:	movb %dl, $0x1<UINT8>
0x00429bc4:	movl %eax, 0x421b68
0x00429bc9:	call 0x00421bdc
0x00429bce:	movl 0x4858e8, %eax
0x00429bd3:	movb %dl, $0x1<UINT8>
0x00429bd5:	movl %eax, 0x42971c
0x00429bda:	call 0x00429778
0x00429778:	pushl %ebx
0x00429779:	pushl %esi
0x0042977a:	testb %dl, %dl
0x0042977c:	je 8
0x0042977e:	addl %esp, $0xfffffff0<UINT8>
0x00429781:	call 0x00403f80
0x00429786:	movl %ebx, %edx
0x00429788:	movl %esi, %eax
0x0042978a:	leal %eax, 0x8(%esi)
0x0042978d:	pushl %eax
0x0042978e:	call 0x004070b8
0x00429793:	movl %eax, %esi
0x00429795:	testb %bl, %bl
0x00429797:	je 15
0x00429799:	call 0x00403fd8
0x0042979e:	popl %fs:0
0x004297a5:	addl %esp, $0xc<UINT8>
0x004297a8:	movl %eax, %esi
0x004297aa:	popl %esi
0x004297ab:	popl %ebx
0x004297ac:	ret

0x00429bdf:	movl 0x4858f0, %eax
0x00429be4:	movb %dl, $0x1<UINT8>
0x00429be6:	movl %eax, 0x416770
0x00429beb:	call 0x00418ec8
0x00429bf0:	movl 0x483780, %eax
0x00429bf5:	movb %dl, $0x1<UINT8>
0x00429bf7:	movl %eax, 0x416770
0x00429bfc:	call 0x00418ec8
0x00429c01:	movl 0x4858ec, %eax
0x00429c06:	movl %ecx, $0x422458<UINT32>
0x00429c0b:	movl %edx, $0x422468<UINT32>
0x00429c10:	movl %eax, 0x420b74
0x00429c15:	call 0x00418624
0x00418624:	pushl %ebx
0x00418625:	pushl %esi
0x00418626:	pushl %edi
0x00418627:	movl %edi, %ecx
0x00418629:	movl %esi, %edx
0x0041862b:	movl %ebx, %eax
0x0041862d:	pushl %esi
0x0041862e:	pushl %edi
0x0041862f:	movl %ecx, %ebx
0x00418631:	movb %dl, $0x1<UINT8>
0x00418633:	movl %eax, 0x418594
0x00418638:	call 0x004185ec
0x004185ec:	pushl %ebp
0x004185ed:	movl %ebp, %esp
0x004185ef:	testb %dl, %dl
0x004185f1:	je 8
0x004185f3:	addl %esp, $0xfffffff0<UINT8>
0x004185f6:	call 0x00403f80
0x004185fb:	movl 0x4(%eax), %ecx
0x004185fe:	movl %ecx, 0xc(%ebp)
0x00418601:	movl 0x8(%eax), %ecx
0x00418604:	movl %ecx, 0x8(%ebp)
0x00418607:	movl 0xc(%eax), %ecx
0x0041860a:	testb %dl, %dl
0x0041860c:	je 15
0x0041860e:	call 0x00403fd8
0x00418613:	popl %fs:0
0x0041861a:	addl %esp, $0xc<UINT8>
0x0041861d:	popl %ebp
0x0041861e:	ret $0x8<UINT16>

0x0041863d:	movl %edx, %eax
0x0041863f:	movl %eax, 0x48585c
0x00418644:	call 0x00418f98
0x00418f98:	pushl %ebp
0x00418f99:	movl %ebp, %esp
0x00418f9b:	pushl %ecx
0x00418f9c:	pushl %ebx
0x00418f9d:	movl %ebx, %edx
0x00418f9f:	movl -4(%ebp), %eax
0x00418fa2:	movl %eax, -4(%ebp)
0x00418fa5:	call 0x00419020
0x00419020:	pushl %ebx
0x00419021:	movl %ebx, %eax
0x00419023:	leal %eax, 0x8(%ebx)
0x00419026:	pushl %eax
0x00419027:	call 0x00406f48
0x00406f48:	jmp EnterCriticalSection@KERNEL32.DLL
EnterCriticalSection@KERNEL32.DLL: API Node	
0x0041902c:	movl %eax, 0x4(%ebx)
0x0041902f:	popl %ebx
0x00419030:	ret

0x00418faa:	xorl %eax, %eax
0x00418fac:	pushl %ebp
0x00418fad:	pushl $0x419014<UINT32>
0x00418fb2:	pushl %fs:(%eax)
0x00418fb5:	movl %fs:(%eax), %esp
0x00418fb8:	movl %eax, -4(%ebp)
0x00418fbb:	cmpb 0x20(%eax), $0x1<UINT8>
0x00418fbf:	je 16
0x00418fc1:	movl %eax, -4(%ebp)
0x00418fc4:	movl %eax, 0x4(%eax)
0x00418fc7:	movl %edx, %ebx
0x00418fc9:	call 0x00418cb8
0x00418cb8:	pushl %ebx
0x00418cb9:	xorl %ecx, %ecx
0x00418cbb:	jmp 0x00418cbe
0x00418cbe:	cmpl %ecx, 0x8(%eax)
0x00418cc1:	jnl 0x00418ccb
0x00418ccb:	cmpl %ecx, 0x8(%eax)
0x00418cce:	jne 3
0x00418cd0:	orl %ecx, $0xffffffff<UINT8>
0x00418cd3:	movl %eax, %ecx
0x00418cd5:	popl %ebx
0x00418cd6:	ret

0x00418fce:	incl %eax
0x00418fcf:	jne 15
0x00418fd1:	movl %eax, -4(%ebp)
0x00418fd4:	movl %eax, 0x4(%eax)
0x00418fd7:	movl %edx, %ebx
0x00418fd9:	call 0x00418b00
0x00418fde:	jmp 0x00418ffe
0x00418ffe:	xorl %eax, %eax
0x00419000:	popl %edx
0x00419001:	popl %ecx
0x00419002:	popl %ecx
0x00419003:	movl %fs:(%eax), %edx
0x00419006:	pushl $0x41901b<UINT32>
0x0041900b:	movl %eax, -4(%ebp)
0x0041900e:	call 0x00419084
0x00419084:	addl %eax, $0x8<UINT8>
0x00419087:	pushl %eax
0x00419088:	call 0x004070c0
0x004070c0:	jmp LeaveCriticalSection@KERNEL32.DLL
LeaveCriticalSection@KERNEL32.DLL: API Node	
0x0041908d:	ret

0x00419013:	ret

0x0041901b:	popl %ebx
0x0041901c:	popl %ecx
0x0041901d:	popl %ebp
0x0041901e:	ret

0x00418649:	popl %edi
0x0041864a:	popl %esi
0x0041864b:	popl %ebx
0x0041864c:	ret

0x00429c1a:	movl %ecx, $0x422660<UINT32>
0x00429c1f:	movl %edx, $0x422670<UINT32>
0x00429c24:	movl %eax, 0x420ca4
0x00429c29:	call 0x00418624
