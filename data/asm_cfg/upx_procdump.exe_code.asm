0x004a46f0:	pusha
0x004a46f1:	movl %esi, $0x46a000<UINT32>
0x004a46f6:	leal %edi, -430080(%esi)
0x004a46fc:	pushl %edi
0x004a46fd:	orl %ebp, $0xffffffff<UINT8>
0x004a4700:	jmp 0x004a4712
0x004a4712:	movl %ebx, (%esi)
0x004a4714:	subl %esi, $0xfffffffc<UINT8>
0x004a4717:	adcl %ebx, %ebx
0x004a4719:	jb 0x004a4708
0x004a4708:	movb %al, (%esi)
0x004a470a:	incl %esi
0x004a470b:	movb (%edi), %al
0x004a470d:	incl %edi
0x004a470e:	addl %ebx, %ebx
0x004a4710:	jne 0x004a4719
0x004a471b:	movl %eax, $0x1<UINT32>
0x004a4720:	addl %ebx, %ebx
0x004a4722:	jne 0x004a472b
0x004a472b:	adcl %eax, %eax
0x004a472d:	addl %ebx, %ebx
0x004a472f:	jae 0x004a473c
0x004a4731:	jne 0x004a475b
0x004a475b:	xorl %ecx, %ecx
0x004a475d:	subl %eax, $0x3<UINT8>
0x004a4760:	jb 0x004a4773
0x004a4773:	addl %ebx, %ebx
0x004a4775:	jne 0x004a477e
0x004a477e:	jb 0x004a474c
0x004a474c:	addl %ebx, %ebx
0x004a474e:	jne 0x004a4757
0x004a4757:	adcl %ecx, %ecx
0x004a4759:	jmp 0x004a47ad
0x004a47ad:	cmpl %ebp, $0xfffffb00<UINT32>
0x004a47b3:	adcl %ecx, $0x2<UINT8>
0x004a47b6:	leal %edx, (%edi,%ebp)
0x004a47b9:	cmpl %ebp, $0xfffffffc<UINT8>
0x004a47bc:	jbe 0x004a47cc
0x004a47be:	movb %al, (%edx)
0x004a47c0:	incl %edx
0x004a47c1:	movb (%edi), %al
0x004a47c3:	incl %edi
0x004a47c4:	decl %ecx
0x004a47c5:	jne 0x004a47be
0x004a47c7:	jmp 0x004a470e
0x004a4762:	shll %eax, $0x8<UINT8>
0x004a4765:	movb %al, (%esi)
0x004a4767:	incl %esi
0x004a4768:	xorl %eax, $0xffffffff<UINT8>
0x004a476b:	je 0x004a47e2
0x004a476d:	sarl %eax
0x004a476f:	movl %ebp, %eax
0x004a4771:	jmp 0x004a477e
0x004a4780:	incl %ecx
0x004a4781:	addl %ebx, %ebx
0x004a4783:	jne 0x004a478c
0x004a478c:	jb 0x004a474c
0x004a47cc:	movl %eax, (%edx)
0x004a47ce:	addl %edx, $0x4<UINT8>
0x004a47d1:	movl (%edi), %eax
0x004a47d3:	addl %edi, $0x4<UINT8>
0x004a47d6:	subl %ecx, $0x4<UINT8>
0x004a47d9:	ja 0x004a47cc
0x004a47db:	addl %edi, %ecx
0x004a47dd:	jmp 0x004a470e
0x004a478e:	addl %ebx, %ebx
0x004a4790:	jne 0x004a4799
0x004a4799:	adcl %ecx, %ecx
0x004a479b:	addl %ebx, %ebx
0x004a479d:	jae 0x004a478e
0x004a479f:	jne 0x004a47aa
0x004a47a1:	movl %ebx, (%esi)
0x004a47a3:	subl %esi, $0xfffffffc<UINT8>
0x004a47a6:	adcl %ebx, %ebx
0x004a47a8:	jae 0x004a478e
0x004a47aa:	addl %ecx, $0x2<UINT8>
0x004a4724:	movl %ebx, (%esi)
0x004a4726:	subl %esi, $0xfffffffc<UINT8>
0x004a4729:	adcl %ebx, %ebx
0x004a4750:	movl %ebx, (%esi)
0x004a4752:	subl %esi, $0xfffffffc<UINT8>
0x004a4755:	adcl %ebx, %ebx
0x004a4733:	movl %ebx, (%esi)
0x004a4735:	subl %esi, $0xfffffffc<UINT8>
0x004a4738:	adcl %ebx, %ebx
0x004a473a:	jb 0x004a475b
0x004a473c:	decl %eax
0x004a473d:	addl %ebx, %ebx
0x004a473f:	jne 0x004a4748
0x004a4748:	adcl %eax, %eax
0x004a474a:	jmp 0x004a4720
0x004a4785:	movl %ebx, (%esi)
0x004a4787:	subl %esi, $0xfffffffc<UINT8>
0x004a478a:	adcl %ebx, %ebx
0x004a4741:	movl %ebx, (%esi)
0x004a4743:	subl %esi, $0xfffffffc<UINT8>
0x004a4746:	adcl %ebx, %ebx
0x004a4792:	movl %ebx, (%esi)
0x004a4794:	subl %esi, $0xfffffffc<UINT8>
0x004a4797:	adcl %ebx, %ebx
0x004a4777:	movl %ebx, (%esi)
0x004a4779:	subl %esi, $0xfffffffc<UINT8>
0x004a477c:	adcl %ebx, %ebx
0x004a47e2:	popl %esi
0x004a47e3:	movl %edi, %esi
0x004a47e5:	movl %ecx, $0xf59<UINT32>
0x004a47ea:	movb %al, (%edi)
0x004a47ec:	incl %edi
0x004a47ed:	subb %al, $0xffffffe8<UINT8>
0x004a47ef:	cmpb %al, $0x1<UINT8>
0x004a47f1:	ja 0x004a47ea
0x004a47f3:	cmpb (%edi), $0xc<UINT8>
0x004a47f6:	jne 0x004a47ea
0x004a47f8:	movl %eax, (%edi)
0x004a47fa:	movb %bl, 0x4(%edi)
0x004a47fd:	shrw %ax, $0x8<UINT8>
0x004a4801:	roll %eax, $0x10<UINT8>
0x004a4804:	xchgb %ah, %al
0x004a4806:	subl %eax, %edi
0x004a4808:	subb %bl, $0xffffffe8<UINT8>
0x004a480b:	addl %eax, %esi
0x004a480d:	movl (%edi), %eax
0x004a480f:	addl %edi, $0x5<UINT8>
0x004a4812:	movb %al, %bl
0x004a4814:	loop 0x004a47ef
0x004a4816:	leal %edi, 0xa0000(%esi)
0x004a481c:	movl %eax, (%edi)
0x004a481e:	orl %eax, %eax
0x004a4820:	je 0x004a485e
0x004a4822:	movl %ebx, 0x4(%edi)
0x004a4825:	leal %eax, 0xa45e0(%eax,%esi)
0x004a482c:	addl %ebx, %esi
0x004a482e:	pushl %eax
0x004a482f:	addl %edi, $0x8<UINT8>
0x004a4832:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004a4838:	xchgl %ebp, %eax
0x004a4839:	movb %al, (%edi)
0x004a483b:	incl %edi
0x004a483c:	orb %al, %al
0x004a483e:	je 0x004a481c
0x004a4840:	movl %ecx, %edi
0x004a4842:	pushl %edi
0x004a4843:	decl %eax
0x004a4844:	repn scasb %al, %es:(%edi)
0x004a4846:	pushl %ebp
0x004a4847:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x004a484d:	orl %eax, %eax
0x004a484f:	je 7
0x004a4851:	movl (%ebx), %eax
0x004a4853:	addl %ebx, $0x4<UINT8>
0x004a4856:	jmp 0x004a4839
GetProcAddress@KERNEL32.DLL: API Node	
0x004a485e:	addl %edi, $0x4<UINT8>
0x004a4861:	leal %ebx, -4(%esi)
0x004a4864:	xorl %eax, %eax
0x004a4866:	movb %al, (%edi)
0x004a4868:	incl %edi
0x004a4869:	orl %eax, %eax
0x004a486b:	je 0x004a488f
0x004a486d:	cmpb %al, $0xffffffef<UINT8>
0x004a486f:	ja 0x004a4882
0x004a4871:	addl %ebx, %eax
0x004a4873:	movl %eax, (%ebx)
0x004a4875:	xchgb %ah, %al
0x004a4877:	roll %eax, $0x10<UINT8>
0x004a487a:	xchgb %ah, %al
0x004a487c:	addl %eax, %esi
0x004a487e:	movl (%ebx), %eax
0x004a4880:	jmp 0x004a4864
0x004a4882:	andb %al, $0xf<UINT8>
0x004a4884:	shll %eax, $0x10<UINT8>
0x004a4887:	movw %ax, (%edi)
0x004a488a:	addl %edi, $0x2<UINT8>
0x004a488d:	jmp 0x004a4871
0x004a488f:	movl %ebp, 0xa46f4(%esi)
0x004a4895:	leal %edi, -4096(%esi)
0x004a489b:	movl %ebx, $0x1000<UINT32>
0x004a48a0:	pushl %eax
0x004a48a1:	pushl %esp
0x004a48a2:	pushl $0x4<UINT8>
0x004a48a4:	pushl %ebx
0x004a48a5:	pushl %edi
0x004a48a6:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x004a48a8:	leal %eax, 0x217(%edi)
0x004a48ae:	andb (%eax), $0x7f<UINT8>
0x004a48b1:	andb 0x28(%eax), $0x7f<UINT8>
0x004a48b5:	popl %eax
0x004a48b6:	pushl %eax
0x004a48b7:	pushl %esp
0x004a48b8:	pushl %eax
0x004a48b9:	pushl %ebx
0x004a48ba:	pushl %edi
0x004a48bb:	call VirtualProtect@kernel32.dll
0x004a48bd:	popl %eax
0x004a48be:	popa
0x004a48bf:	leal %eax, -128(%esp)
0x004a48c3:	pushl $0x0<UINT8>
0x004a48c5:	cmpl %esp, %eax
0x004a48c7:	jne 0x004a48c3
0x004a48c9:	subl %esp, $0xffffff80<UINT8>
0x004a48cc:	jmp 0x004171e7
0x004171e7:	call 0x00421d99
0x00421d99:	pushl %ebp
0x00421d9a:	movl %ebp, %esp
0x00421d9c:	subl %esp, $0x14<UINT8>
0x00421d9f:	andl -12(%ebp), $0x0<UINT8>
0x00421da3:	andl -8(%ebp), $0x0<UINT8>
0x00421da7:	movl %eax, 0x445408
0x00421dac:	pushl %esi
0x00421dad:	pushl %edi
0x00421dae:	movl %edi, $0xbb40e64e<UINT32>
0x00421db3:	movl %esi, $0xffff0000<UINT32>
0x00421db8:	cmpl %eax, %edi
0x00421dba:	je 0x00421dc9
0x00421dc9:	leal %eax, -12(%ebp)
0x00421dcc:	pushl %eax
0x00421dcd:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x00421dd3:	movl %eax, -8(%ebp)
0x00421dd6:	xorl %eax, -12(%ebp)
0x00421dd9:	movl -4(%ebp), %eax
0x00421ddc:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x00421de2:	xorl -4(%ebp), %eax
0x00421de5:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x00421deb:	xorl -4(%ebp), %eax
0x00421dee:	leal %eax, -20(%ebp)
0x00421df1:	pushl %eax
0x00421df2:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x00421df8:	movl %ecx, -16(%ebp)
0x00421dfb:	leal %eax, -4(%ebp)
0x00421dfe:	xorl %ecx, -20(%ebp)
0x00421e01:	xorl %ecx, -4(%ebp)
0x00421e04:	xorl %ecx, %eax
0x00421e06:	cmpl %ecx, %edi
0x00421e08:	jne 0x00421e11
0x00421e11:	testl %esi, %ecx
0x00421e13:	jne 0x00421e21
0x00421e21:	movl 0x445408, %ecx
0x00421e27:	notl %ecx
0x00421e29:	movl 0x44540c, %ecx
0x00421e2f:	popl %edi
0x00421e30:	popl %esi
0x00421e31:	movl %esp, %ebp
0x00421e33:	popl %ebp
0x00421e34:	ret

0x004171ec:	jmp 0x0041706c
0x0041706c:	pushl $0x14<UINT8>
0x0041706e:	pushl $0x442c18<UINT32>
0x00417073:	call 0x00419de0
0x00419de0:	pushl $0x419e40<UINT32>
0x00419de5:	pushl %fs:0
0x00419dec:	movl %eax, 0x10(%esp)
0x00419df0:	movl 0x10(%esp), %ebp
0x00419df4:	leal %ebp, 0x10(%esp)
0x00419df8:	subl %esp, %eax
0x00419dfa:	pushl %ebx
0x00419dfb:	pushl %esi
0x00419dfc:	pushl %edi
0x00419dfd:	movl %eax, 0x445408
0x00419e02:	xorl -4(%ebp), %eax
0x00419e05:	xorl %eax, %ebp
0x00419e07:	pushl %eax
0x00419e08:	movl -24(%ebp), %esp
0x00419e0b:	pushl -8(%ebp)
0x00419e0e:	movl %eax, -4(%ebp)
0x00419e11:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00419e18:	movl -8(%ebp), %eax
0x00419e1b:	leal %eax, -16(%ebp)
0x00419e1e:	movl %fs:0, %eax
0x00419e24:	ret

0x00417078:	pushl $0x1<UINT8>
0x0041707a:	call 0x00421d4c
0x00421d4c:	pushl %ebp
0x00421d4d:	movl %ebp, %esp
0x00421d4f:	movl %eax, 0x8(%ebp)
0x00421d52:	movl 0x446960, %eax
0x00421d57:	popl %ebp
0x00421d58:	ret

0x0041707f:	popl %ecx
0x00417080:	movl %eax, $0x5a4d<UINT32>
0x00417085:	cmpw 0x400000, %ax
0x0041708c:	je 0x00417092
0x00417092:	movl %eax, 0x40003c
0x00417097:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x004170a1:	jne -21
0x004170a3:	movl %ecx, $0x10b<UINT32>
0x004170a8:	cmpw 0x400018(%eax), %cx
0x004170af:	jne -35
0x004170b1:	xorl %ebx, %ebx
0x004170b3:	cmpl 0x400074(%eax), $0xe<UINT8>
0x004170ba:	jbe 9
0x004170bc:	cmpl 0x4000e8(%eax), %ebx
0x004170c2:	setne %bl
0x004170c5:	movl -28(%ebp), %ebx
0x004170c8:	call 0x0041b7c0
0x0041b7c0:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x0041b7c6:	xorl %ecx, %ecx
0x0041b7c8:	movl 0x446954, %eax
0x0041b7cd:	testl %eax, %eax
0x0041b7cf:	setne %cl
0x0041b7d2:	movl %eax, %ecx
0x0041b7d4:	ret

0x004170cd:	testl %eax, %eax
0x004170cf:	jne 0x004170d9
0x004170d9:	call 0x0041b6db
0x0041b6db:	call 0x0041490e
0x0041490e:	pushl %esi
0x0041490f:	pushl $0x0<UINT8>
0x00414911:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00414917:	movl %esi, %eax
0x00414919:	pushl %esi
0x0041491a:	call 0x0041a963
0x0041a963:	pushl %ebp
0x0041a964:	movl %ebp, %esp
0x0041a966:	movl %eax, 0x8(%ebp)
0x0041a969:	movl 0x446930, %eax
0x0041a96e:	popl %ebp
0x0041a96f:	ret

0x0041491f:	pushl %esi
0x00414920:	call 0x004181a2
0x004181a2:	pushl %ebp
0x004181a3:	movl %ebp, %esp
0x004181a5:	movl %eax, 0x8(%ebp)
0x004181a8:	movl 0x44691c, %eax
0x004181ad:	popl %ebp
0x004181ae:	ret

0x00414925:	pushl %esi
0x00414926:	call 0x0041a036
0x0041a036:	pushl %ebp
0x0041a037:	movl %ebp, %esp
0x0041a039:	movl %eax, 0x8(%ebp)
0x0041a03c:	movl 0x446924, %eax
0x0041a041:	popl %ebp
0x0041a042:	ret

0x0041492b:	pushl %esi
0x0041492c:	call 0x0041cf1d
0x0041cf1d:	pushl %ebp
0x0041cf1e:	movl %ebp, %esp
0x0041cf20:	movl %eax, 0x8(%ebp)
0x0041cf23:	movl 0x4470ec, %eax
0x0041cf28:	movl 0x4470f0, %eax
0x0041cf2d:	movl 0x4470f4, %eax
0x0041cf32:	movl 0x4470f8, %eax
0x0041cf37:	popl %ebp
0x0041cf38:	ret

0x00414931:	pushl %esi
0x00414932:	call 0x0041ceff
0x0041ceff:	pushl $0x41ceb8<UINT32>
0x0041cf04:	call EncodePointer@KERNEL32.DLL
0x0041cf0a:	movl 0x4470e8, %eax
0x0041cf0f:	ret

0x00414937:	pushl %esi
0x00414938:	call 0x0041d12e
0x0041d12e:	pushl %ebp
0x0041d12f:	movl %ebp, %esp
0x0041d131:	movl %eax, 0x8(%ebp)
0x0041d134:	movl 0x447100, %eax
0x0041d139:	popl %ebp
0x0041d13a:	ret

0x0041493d:	addl %esp, $0x18<UINT8>
0x00414940:	popl %esi
0x00414941:	jmp 0x0041ca48
0x0041ca48:	pushl %esi
0x0041ca49:	pushl %edi
0x0041ca4a:	pushl $0x4386fc<UINT32>
0x0041ca4f:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0041ca55:	movl %esi, 0x42a1a0
0x0041ca5b:	movl %edi, %eax
0x0041ca5d:	pushl $0x42c50c<UINT32>
0x0041ca62:	pushl %edi
0x0041ca63:	call GetProcAddress@KERNEL32.DLL
0x0041ca65:	xorl %eax, 0x445408
0x0041ca6b:	pushl $0x42c518<UINT32>
0x0041ca70:	pushl %edi
0x0041ca71:	movl 0x448d00, %eax
0x0041ca76:	call GetProcAddress@KERNEL32.DLL
0x0041ca78:	xorl %eax, 0x445408
0x0041ca7e:	pushl $0x42c520<UINT32>
0x0041ca83:	pushl %edi
0x0041ca84:	movl 0x448d04, %eax
0x0041ca89:	call GetProcAddress@KERNEL32.DLL
0x0041ca8b:	xorl %eax, 0x445408
0x0041ca91:	pushl $0x42c52c<UINT32>
0x0041ca96:	pushl %edi
0x0041ca97:	movl 0x448d08, %eax
0x0041ca9c:	call GetProcAddress@KERNEL32.DLL
0x0041ca9e:	xorl %eax, 0x445408
0x0041caa4:	pushl $0x42c538<UINT32>
0x0041caa9:	pushl %edi
0x0041caaa:	movl 0x448d0c, %eax
0x0041caaf:	call GetProcAddress@KERNEL32.DLL
0x0041cab1:	xorl %eax, 0x445408
0x0041cab7:	pushl $0x42c554<UINT32>
0x0041cabc:	pushl %edi
0x0041cabd:	movl 0x448d10, %eax
0x0041cac2:	call GetProcAddress@KERNEL32.DLL
0x0041cac4:	xorl %eax, 0x445408
0x0041caca:	pushl $0x42c564<UINT32>
0x0041cacf:	pushl %edi
0x0041cad0:	movl 0x448d14, %eax
0x0041cad5:	call GetProcAddress@KERNEL32.DLL
0x0041cad7:	xorl %eax, 0x445408
0x0041cadd:	pushl $0x42c578<UINT32>
0x0041cae2:	pushl %edi
0x0041cae3:	movl 0x448d18, %eax
0x0041cae8:	call GetProcAddress@KERNEL32.DLL
0x0041caea:	xorl %eax, 0x445408
0x0041caf0:	pushl $0x42c590<UINT32>
0x0041caf5:	pushl %edi
0x0041caf6:	movl 0x448d1c, %eax
0x0041cafb:	call GetProcAddress@KERNEL32.DLL
0x0041cafd:	xorl %eax, 0x445408
0x0041cb03:	pushl $0x42c5a8<UINT32>
0x0041cb08:	pushl %edi
0x0041cb09:	movl 0x448d20, %eax
0x0041cb0e:	call GetProcAddress@KERNEL32.DLL
0x0041cb10:	xorl %eax, 0x445408
0x0041cb16:	pushl $0x42c5bc<UINT32>
0x0041cb1b:	pushl %edi
0x0041cb1c:	movl 0x448d24, %eax
0x0041cb21:	call GetProcAddress@KERNEL32.DLL
0x0041cb23:	xorl %eax, 0x445408
0x0041cb29:	pushl $0x42c5dc<UINT32>
0x0041cb2e:	pushl %edi
0x0041cb2f:	movl 0x448d28, %eax
0x0041cb34:	call GetProcAddress@KERNEL32.DLL
0x0041cb36:	xorl %eax, 0x445408
0x0041cb3c:	pushl $0x42c5f4<UINT32>
0x0041cb41:	pushl %edi
0x0041cb42:	movl 0x448d2c, %eax
0x0041cb47:	call GetProcAddress@KERNEL32.DLL
0x0041cb49:	xorl %eax, 0x445408
0x0041cb4f:	pushl $0x42c60c<UINT32>
0x0041cb54:	pushl %edi
0x0041cb55:	movl 0x448d30, %eax
0x0041cb5a:	call GetProcAddress@KERNEL32.DLL
0x0041cb5c:	xorl %eax, 0x445408
0x0041cb62:	pushl $0x42c620<UINT32>
0x0041cb67:	pushl %edi
0x0041cb68:	movl 0x448d34, %eax
0x0041cb6d:	call GetProcAddress@KERNEL32.DLL
0x0041cb6f:	xorl %eax, 0x445408
0x0041cb75:	movl 0x448d38, %eax
0x0041cb7a:	pushl $0x42c634<UINT32>
0x0041cb7f:	pushl %edi
0x0041cb80:	call GetProcAddress@KERNEL32.DLL
0x0041cb82:	xorl %eax, 0x445408
0x0041cb88:	pushl $0x42c650<UINT32>
0x0041cb8d:	pushl %edi
0x0041cb8e:	movl 0x448d3c, %eax
0x0041cb93:	call GetProcAddress@KERNEL32.DLL
0x0041cb95:	xorl %eax, 0x445408
0x0041cb9b:	pushl $0x42c670<UINT32>
0x0041cba0:	pushl %edi
0x0041cba1:	movl 0x448d40, %eax
0x0041cba6:	call GetProcAddress@KERNEL32.DLL
0x0041cba8:	xorl %eax, 0x445408
0x0041cbae:	pushl $0x42c68c<UINT32>
0x0041cbb3:	pushl %edi
0x0041cbb4:	movl 0x448d44, %eax
0x0041cbb9:	call GetProcAddress@KERNEL32.DLL
0x0041cbbb:	xorl %eax, 0x445408
0x0041cbc1:	pushl $0x42c6ac<UINT32>
0x0041cbc6:	pushl %edi
0x0041cbc7:	movl 0x448d48, %eax
0x0041cbcc:	call GetProcAddress@KERNEL32.DLL
0x0041cbce:	xorl %eax, 0x445408
0x0041cbd4:	pushl $0x42c6c0<UINT32>
0x0041cbd9:	pushl %edi
0x0041cbda:	movl 0x448d4c, %eax
0x0041cbdf:	call GetProcAddress@KERNEL32.DLL
0x0041cbe1:	xorl %eax, 0x445408
0x0041cbe7:	pushl $0x42c6dc<UINT32>
0x0041cbec:	pushl %edi
0x0041cbed:	movl 0x448d50, %eax
0x0041cbf2:	call GetProcAddress@KERNEL32.DLL
0x0041cbf4:	xorl %eax, 0x445408
0x0041cbfa:	pushl $0x42c6f0<UINT32>
0x0041cbff:	pushl %edi
0x0041cc00:	movl 0x448d58, %eax
0x0041cc05:	call GetProcAddress@KERNEL32.DLL
0x0041cc07:	xorl %eax, 0x445408
0x0041cc0d:	pushl $0x42c700<UINT32>
0x0041cc12:	pushl %edi
0x0041cc13:	movl 0x448d54, %eax
0x0041cc18:	call GetProcAddress@KERNEL32.DLL
0x0041cc1a:	xorl %eax, 0x445408
0x0041cc20:	pushl $0x42c710<UINT32>
0x0041cc25:	pushl %edi
0x0041cc26:	movl 0x448d5c, %eax
0x0041cc2b:	call GetProcAddress@KERNEL32.DLL
0x0041cc2d:	xorl %eax, 0x445408
0x0041cc33:	pushl $0x42c720<UINT32>
0x0041cc38:	pushl %edi
0x0041cc39:	movl 0x448d60, %eax
0x0041cc3e:	call GetProcAddress@KERNEL32.DLL
0x0041cc40:	xorl %eax, 0x445408
0x0041cc46:	pushl $0x42c730<UINT32>
0x0041cc4b:	pushl %edi
0x0041cc4c:	movl 0x448d64, %eax
0x0041cc51:	call GetProcAddress@KERNEL32.DLL
0x0041cc53:	xorl %eax, 0x445408
0x0041cc59:	pushl $0x42c74c<UINT32>
0x0041cc5e:	pushl %edi
0x0041cc5f:	movl 0x448d68, %eax
0x0041cc64:	call GetProcAddress@KERNEL32.DLL
0x0041cc66:	xorl %eax, 0x445408
0x0041cc6c:	pushl $0x42c760<UINT32>
0x0041cc71:	pushl %edi
0x0041cc72:	movl 0x448d6c, %eax
0x0041cc77:	call GetProcAddress@KERNEL32.DLL
0x0041cc79:	xorl %eax, 0x445408
0x0041cc7f:	pushl $0x42c770<UINT32>
0x0041cc84:	pushl %edi
0x0041cc85:	movl 0x448d70, %eax
0x0041cc8a:	call GetProcAddress@KERNEL32.DLL
0x0041cc8c:	xorl %eax, 0x445408
0x0041cc92:	pushl $0x42c784<UINT32>
0x0041cc97:	pushl %edi
0x0041cc98:	movl 0x448d74, %eax
0x0041cc9d:	call GetProcAddress@KERNEL32.DLL
0x0041cc9f:	xorl %eax, 0x445408
0x0041cca5:	movl 0x448d78, %eax
0x0041ccaa:	pushl $0x42c794<UINT32>
0x0041ccaf:	pushl %edi
0x0041ccb0:	call GetProcAddress@KERNEL32.DLL
0x0041ccb2:	xorl %eax, 0x445408
0x0041ccb8:	pushl $0x42c7b4<UINT32>
0x0041ccbd:	pushl %edi
0x0041ccbe:	movl 0x448d7c, %eax
0x0041ccc3:	call GetProcAddress@KERNEL32.DLL
0x0041ccc5:	xorl %eax, 0x445408
0x0041cccb:	popl %edi
0x0041cccc:	movl 0x448d80, %eax
0x0041ccd1:	popl %esi
0x0041ccd2:	ret

0x0041b6e0:	call 0x0041c863
0x0041c863:	pushl %esi
0x0041c864:	pushl %edi
0x0041c865:	movl %esi, $0x445cd0<UINT32>
0x0041c86a:	movl %edi, $0x446f98<UINT32>
0x0041c86f:	cmpl 0x4(%esi), $0x1<UINT8>
0x0041c873:	jne 22
0x0041c875:	pushl $0x0<UINT8>
0x0041c877:	movl (%esi), %edi
0x0041c879:	addl %edi, $0x18<UINT8>
0x0041c87c:	pushl $0xfa0<UINT32>
0x0041c881:	pushl (%esi)
0x0041c883:	call 0x0041c9da
0x0041c9da:	pushl %ebp
0x0041c9db:	movl %ebp, %esp
0x0041c9dd:	movl %eax, 0x448d10
0x0041c9e2:	xorl %eax, 0x445408
0x0041c9e8:	je 13
0x0041c9ea:	pushl 0x10(%ebp)
0x0041c9ed:	pushl 0xc(%ebp)
0x0041c9f0:	pushl 0x8(%ebp)
0x0041c9f3:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x0041c9f5:	popl %ebp
0x0041c9f6:	ret

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
