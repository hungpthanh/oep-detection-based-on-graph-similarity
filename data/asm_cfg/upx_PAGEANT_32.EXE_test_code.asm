0x0044ab90:	pusha
0x0044ab91:	movl %esi, $0x42d000<UINT32>
0x0044ab96:	leal %edi, -180224(%esi)
0x0044ab9c:	pushl %edi
0x0044ab9d:	orl %ebp, $0xffffffff<UINT8>
0x0044aba0:	jmp 0x0044abb2
0x0044abb2:	movl %ebx, (%esi)
0x0044abb4:	subl %esi, $0xfffffffc<UINT8>
0x0044abb7:	adcl %ebx, %ebx
0x0044abb9:	jb 0x0044aba8
0x0044aba8:	movb %al, (%esi)
0x0044abaa:	incl %esi
0x0044abab:	movb (%edi), %al
0x0044abad:	incl %edi
0x0044abae:	addl %ebx, %ebx
0x0044abb0:	jne 0x0044abb9
0x0044abbb:	movl %eax, $0x1<UINT32>
0x0044abc0:	addl %ebx, %ebx
0x0044abc2:	jne 0x0044abcb
0x0044abcb:	adcl %eax, %eax
0x0044abcd:	addl %ebx, %ebx
0x0044abcf:	jae 0x0044abdc
0x0044abd1:	jne 0x0044abfb
0x0044abfb:	xorl %ecx, %ecx
0x0044abfd:	subl %eax, $0x3<UINT8>
0x0044ac00:	jb 0x0044ac13
0x0044ac13:	addl %ebx, %ebx
0x0044ac15:	jne 0x0044ac1e
0x0044ac1e:	jb 0x0044abec
0x0044ac20:	incl %ecx
0x0044ac21:	addl %ebx, %ebx
0x0044ac23:	jne 0x0044ac2c
0x0044ac2c:	jb 0x0044abec
0x0044ac2e:	addl %ebx, %ebx
0x0044ac30:	jne 0x0044ac39
0x0044ac39:	adcl %ecx, %ecx
0x0044ac3b:	addl %ebx, %ebx
0x0044ac3d:	jae 0x0044ac2e
0x0044ac3f:	jne 0x0044ac4a
0x0044ac4a:	addl %ecx, $0x2<UINT8>
0x0044ac4d:	cmpl %ebp, $0xfffffb00<UINT32>
0x0044ac53:	adcl %ecx, $0x2<UINT8>
0x0044ac56:	leal %edx, (%edi,%ebp)
0x0044ac59:	cmpl %ebp, $0xfffffffc<UINT8>
0x0044ac5c:	jbe 0x0044ac6c
0x0044ac5e:	movb %al, (%edx)
0x0044ac60:	incl %edx
0x0044ac61:	movb (%edi), %al
0x0044ac63:	incl %edi
0x0044ac64:	decl %ecx
0x0044ac65:	jne 0x0044ac5e
0x0044ac67:	jmp 0x0044abae
0x0044ac02:	shll %eax, $0x8<UINT8>
0x0044ac05:	movb %al, (%esi)
0x0044ac07:	incl %esi
0x0044ac08:	xorl %eax, $0xffffffff<UINT8>
0x0044ac0b:	je 0x0044ac82
0x0044ac0d:	sarl %eax
0x0044ac0f:	movl %ebp, %eax
0x0044ac11:	jmp 0x0044ac1e
0x0044ac6c:	movl %eax, (%edx)
0x0044ac6e:	addl %edx, $0x4<UINT8>
0x0044ac71:	movl (%edi), %eax
0x0044ac73:	addl %edi, $0x4<UINT8>
0x0044ac76:	subl %ecx, $0x4<UINT8>
0x0044ac79:	ja 0x0044ac6c
0x0044ac7b:	addl %edi, %ecx
0x0044ac7d:	jmp 0x0044abae
0x0044abec:	addl %ebx, %ebx
0x0044abee:	jne 0x0044abf7
0x0044abf7:	adcl %ecx, %ecx
0x0044abf9:	jmp 0x0044ac4d
0x0044ac41:	movl %ebx, (%esi)
0x0044ac43:	subl %esi, $0xfffffffc<UINT8>
0x0044ac46:	adcl %ebx, %ebx
0x0044ac48:	jae 0x0044ac2e
0x0044abd3:	movl %ebx, (%esi)
0x0044abd5:	subl %esi, $0xfffffffc<UINT8>
0x0044abd8:	adcl %ebx, %ebx
0x0044abda:	jb 0x0044abfb
0x0044abc4:	movl %ebx, (%esi)
0x0044abc6:	subl %esi, $0xfffffffc<UINT8>
0x0044abc9:	adcl %ebx, %ebx
0x0044abdc:	decl %eax
0x0044abdd:	addl %ebx, %ebx
0x0044abdf:	jne 0x0044abe8
0x0044abe8:	adcl %eax, %eax
0x0044abea:	jmp 0x0044abc0
0x0044ac25:	movl %ebx, (%esi)
0x0044ac27:	subl %esi, $0xfffffffc<UINT8>
0x0044ac2a:	adcl %ebx, %ebx
0x0044ac32:	movl %ebx, (%esi)
0x0044ac34:	subl %esi, $0xfffffffc<UINT8>
0x0044ac37:	adcl %ebx, %ebx
0x0044abe1:	movl %ebx, (%esi)
0x0044abe3:	subl %esi, $0xfffffffc<UINT8>
0x0044abe6:	adcl %ebx, %ebx
0x0044abf0:	movl %ebx, (%esi)
0x0044abf2:	subl %esi, $0xfffffffc<UINT8>
0x0044abf5:	adcl %ebx, %ebx
0x0044ac17:	movl %ebx, (%esi)
0x0044ac19:	subl %esi, $0xfffffffc<UINT8>
0x0044ac1c:	adcl %ebx, %ebx
0x0044ac82:	popl %esi
0x0044ac83:	leal %edi, 0x14000(%esi)
0x0044ac89:	movl %ecx, $0x1265<UINT32>
0x0044ac8e:	movb %al, (%edi)
0x0044ac90:	incl %edi
0x0044ac91:	subb %al, $0xffffffe8<UINT8>
0x0044ac93:	cmpb %al, $0x1<UINT8>
0x0044ac95:	ja 0x0044ac8e
0x0044ac97:	cmpb (%edi), $0x19<UINT8>
0x0044ac9a:	jne 0x0044ac8e
0x0044ac9c:	movl %eax, (%edi)
0x0044ac9e:	movb %bl, 0x4(%edi)
0x0044aca1:	shrw %ax, $0x8<UINT8>
0x0044aca5:	roll %eax, $0x10<UINT8>
0x0044aca8:	xchgb %ah, %al
0x0044acaa:	subl %eax, %edi
0x0044acac:	subb %bl, $0xffffffe8<UINT8>
0x0044acaf:	addl %eax, %esi
0x0044acb1:	movl (%edi), %eax
0x0044acb3:	addl %edi, $0x5<UINT8>
0x0044acb6:	movb %al, %bl
0x0044acb8:	loop 0x0044ac93
0x0044acba:	leal %edi, 0x47000(%esi)
0x0044acc0:	movl %eax, (%edi)
0x0044acc2:	orl %eax, %eax
0x0044acc4:	je 0x0044ad02
0x0044acc6:	movl %ebx, 0x4(%edi)
0x0044acc9:	leal %eax, 0x4bb64(%eax,%esi)
0x0044acd0:	addl %ebx, %esi
0x0044acd2:	pushl %eax
0x0044acd3:	addl %edi, $0x8<UINT8>
0x0044acd6:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x0044acdc:	xchgl %ebp, %eax
0x0044acdd:	movb %al, (%edi)
0x0044acdf:	incl %edi
0x0044ace0:	orb %al, %al
0x0044ace2:	je 0x0044acc0
0x0044ace4:	movl %ecx, %edi
0x0044ace6:	pushl %edi
0x0044ace7:	decl %eax
0x0044ace8:	repn scasb %al, %es:(%edi)
0x0044acea:	pushl %ebp
0x0044aceb:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0044acf1:	orl %eax, %eax
0x0044acf3:	je 7
0x0044acf5:	movl (%ebx), %eax
0x0044acf7:	addl %ebx, $0x4<UINT8>
0x0044acfa:	jmp 0x0044acdd
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x0044ad02:	addl %edi, $0x4<UINT8>
0x0044ad05:	leal %ebx, -4(%esi)
0x0044ad08:	xorl %eax, %eax
0x0044ad0a:	movb %al, (%edi)
0x0044ad0c:	incl %edi
0x0044ad0d:	orl %eax, %eax
0x0044ad0f:	je 0x0044ad33
0x0044ad11:	cmpb %al, $0xffffffef<UINT8>
0x0044ad13:	ja 0x0044ad26
0x0044ad15:	addl %ebx, %eax
0x0044ad17:	movl %eax, (%ebx)
0x0044ad19:	xchgb %ah, %al
0x0044ad1b:	roll %eax, $0x10<UINT8>
0x0044ad1e:	xchgb %ah, %al
0x0044ad20:	addl %eax, %esi
0x0044ad22:	movl (%ebx), %eax
0x0044ad24:	jmp 0x0044ad08
0x0044ad26:	andb %al, $0xf<UINT8>
0x0044ad28:	shll %eax, $0x10<UINT8>
0x0044ad2b:	movw %ax, (%edi)
0x0044ad2e:	addl %edi, $0x2<UINT8>
0x0044ad31:	jmp 0x0044ad15
0x0044ad33:	movl %ebp, 0x4bc14(%esi)
0x0044ad39:	leal %edi, -4096(%esi)
0x0044ad3f:	movl %ebx, $0x1000<UINT32>
0x0044ad44:	pushl %eax
0x0044ad45:	pushl %esp
0x0044ad46:	pushl $0x4<UINT8>
0x0044ad48:	pushl %ebx
0x0044ad49:	pushl %edi
0x0044ad4a:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0044ad4c:	leal %eax, 0x15f(%edi)
0x0044ad52:	andb (%eax), $0x7f<UINT8>
0x0044ad55:	andb 0x28(%eax), $0x7f<UINT8>
0x0044ad59:	popl %eax
0x0044ad5a:	pushl %eax
0x0044ad5b:	pushl %esp
0x0044ad5c:	pushl %eax
0x0044ad5d:	pushl %ebx
0x0044ad5e:	pushl %edi
0x0044ad5f:	call VirtualProtect@kernel32.dll
0x0044ad61:	popl %eax
0x0044ad62:	popa
0x0044ad63:	leal %eax, -128(%esp)
0x0044ad67:	pushl $0x0<UINT8>
0x0044ad69:	cmpl %esp, %eax
0x0044ad6b:	jne 0x0044ad67
0x0044ad6d:	subl %esp, $0xffffff80<UINT8>
0x0044ad70:	jmp 0x0042c3a6
0x0042c3a6:	call 0x0042c635
0x0042c635:	pushl %ebp
0x0042c636:	movl %ebp, %esp
0x0042c638:	subl %esp, $0x14<UINT8>
0x0042c63b:	andl -12(%ebp), $0x0<UINT8>
0x0042c63f:	andl -8(%ebp), $0x0<UINT8>
0x0042c643:	movl %eax, 0x410030
0x0042c648:	pushl %esi
0x0042c649:	pushl %edi
0x0042c64a:	movl %edi, $0xbb40e64e<UINT32>
0x0042c64f:	movl %esi, $0xffff0000<UINT32>
0x0042c654:	cmpl %eax, %edi
0x0042c656:	je 0x0042c665
0x0042c665:	leal %eax, -12(%ebp)
0x0042c668:	pushl %eax
0x0042c669:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0042c66f:	movl %eax, -8(%ebp)
0x0042c672:	xorl %eax, -12(%ebp)
0x0042c675:	movl -4(%ebp), %eax
0x0042c678:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0042c67e:	xorl -4(%ebp), %eax
0x0042c681:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0042c687:	xorl -4(%ebp), %eax
0x0042c68a:	leal %eax, -20(%ebp)
0x0042c68d:	pushl %eax
0x0042c68e:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0042c694:	movl %ecx, -16(%ebp)
0x0042c697:	leal %eax, -4(%ebp)
0x0042c69a:	xorl %ecx, -20(%ebp)
0x0042c69d:	xorl %ecx, -4(%ebp)
0x0042c6a0:	xorl %ecx, %eax
0x0042c6a2:	cmpl %ecx, %edi
0x0042c6a4:	jne 0x0042c6ad
0x0042c6ad:	testl %esi, %ecx
0x0042c6af:	jne 0x0042c6bd
0x0042c6bd:	movl 0x410030, %ecx
0x0042c6c3:	notl %ecx
0x0042c6c5:	movl 0x41002c, %ecx
0x0042c6cb:	popl %edi
0x0042c6cc:	popl %esi
0x0042c6cd:	movl %esp, %ebp
0x0042c6cf:	popl %ebp
0x0042c6d0:	ret

0x0042c3ab:	jmp 0x0042c23e
0x0042c23e:	pushl $0x14<UINT8>
0x0042c240:	pushl $0x443000<UINT32>
0x0042c245:	call 0x0042c990
0x0042c990:	pushl $0x42cc20<UINT32>
0x0042c995:	pushl %fs:0
0x0042c99c:	movl %eax, 0x10(%esp)
0x0042c9a0:	movl 0x10(%esp), %ebp
0x0042c9a4:	leal %ebp, 0x10(%esp)
0x0042c9a8:	subl %esp, %eax
0x0042c9aa:	pushl %ebx
0x0042c9ab:	pushl %esi
0x0042c9ac:	pushl %edi
0x0042c9ad:	movl %eax, 0x410030
0x0042c9b2:	xorl -4(%ebp), %eax
0x0042c9b5:	xorl %eax, %ebp
0x0042c9b7:	pushl %eax
0x0042c9b8:	movl -24(%ebp), %esp
0x0042c9bb:	pushl -8(%ebp)
0x0042c9be:	movl %eax, -4(%ebp)
0x0042c9c1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0042c9c8:	movl -8(%ebp), %eax
0x0042c9cb:	leal %eax, -16(%ebp)
0x0042c9ce:	movl %fs:0, %eax
0x0042c9d4:	repn ret

0x0042c24a:	pushl $0x1<UINT8>
0x0042c24c:	call 0x0042c446
0x0042c446:	pushl %ebp
0x0042c447:	movl %ebp, %esp
0x0042c449:	cmpl 0x8(%ebp), $0x0<UINT8>
0x0042c44d:	jne 0x0042c456
0x0042c456:	call 0x0042c9eb
0x0042c9eb:	pushl %ebp
0x0042c9ec:	movl %ebp, %esp
0x0042c9ee:	andl 0x40f638, $0x0<UINT8>
0x0042c9f5:	subl %esp, $0x28<UINT8>
0x0042c9f8:	pushl %ebx
0x0042c9f9:	xorl %ebx, %ebx
0x0042c9fb:	incl %ebx
0x0042c9fc:	orl 0x410050, %ebx
0x0042ca02:	pushl $0xa<UINT8>
0x0042ca04:	call 0x00442c7a
0x00442c7a:	jmp IsProcessorFeaturePresent@KERNEL32.DLL
IsProcessorFeaturePresent@KERNEL32.DLL: API Node	
0x0042ca09:	testl %eax, %eax
0x0042ca0b:	je 365
0x0042ca11:	andl -16(%ebp), $0x0<UINT8>
0x0042ca15:	xorl %eax, %eax
0x0042ca17:	orl 0x410050, $0x2<UINT8>
0x0042ca1e:	xorl %ecx, %ecx
0x0042ca20:	pushl %esi
0x0042ca21:	pushl %edi
0x0042ca22:	movl 0x40f638, %ebx
0x0042ca28:	leal %edi, -40(%ebp)
0x0042ca2b:	pushl %ebx
0x0042ca2c:	cpuid
0x0042ca2e:	movl %esi, %ebx
0x0042ca30:	popl %ebx
0x0042ca31:	movl (%edi), %eax
0x0042ca33:	movl 0x4(%edi), %esi
0x0042ca36:	movl 0x8(%edi), %ecx
0x0042ca39:	movl 0xc(%edi), %edx
0x0042ca3c:	movl %eax, -40(%ebp)
0x0042ca3f:	movl %ecx, -28(%ebp)
0x0042ca42:	movl -8(%ebp), %eax
0x0042ca45:	xorl %ecx, $0x49656e69<UINT32>
0x0042ca4b:	movl %eax, -32(%ebp)
0x0042ca4e:	xorl %eax, $0x6c65746e<UINT32>
0x0042ca53:	orl %ecx, %eax
0x0042ca55:	movl %eax, -36(%ebp)
0x0042ca58:	pushl $0x1<UINT8>
0x0042ca5a:	xorl %eax, $0x756e6547<UINT32>
0x0042ca5f:	orl %ecx, %eax
0x0042ca61:	popl %eax
0x0042ca62:	pushl $0x0<UINT8>
0x0042ca64:	popl %ecx
0x0042ca65:	pushl %ebx
0x0042ca66:	cpuid
0x0042ca68:	movl %esi, %ebx
0x0042ca6a:	popl %ebx
0x0042ca6b:	movl (%edi), %eax
0x0042ca6d:	movl 0x4(%edi), %esi
0x0042ca70:	movl 0x8(%edi), %ecx
0x0042ca73:	movl 0xc(%edi), %edx
0x0042ca76:	jne 67
0x0042ca78:	movl %eax, -40(%ebp)
0x0042ca7b:	andl %eax, $0xfff3ff0<UINT32>
0x0042ca80:	cmpl %eax, $0x106c0<UINT32>
0x0042ca85:	je 35
0x0042ca87:	cmpl %eax, $0x20660<UINT32>
0x0042ca8c:	je 28
0x0042ca8e:	cmpl %eax, $0x20670<UINT32>
0x0042ca93:	je 21
0x0042ca95:	cmpl %eax, $0x30650<UINT32>
0x0042ca9a:	je 14
0x0042ca9c:	cmpl %eax, $0x30660<UINT32>
0x0042caa1:	je 7
0x0042caa3:	cmpl %eax, $0x30670<UINT32>
0x0042caa8:	jne 0x0042cabb
0x0042cabb:	movl %edi, 0x40f63c
0x0042cac1:	cmpl -8(%ebp), $0x7<UINT8>
0x0042cac5:	movl %eax, -28(%ebp)
0x0042cac8:	movl -24(%ebp), %eax
0x0042cacb:	movl %eax, -32(%ebp)
0x0042cace:	movl -4(%ebp), %eax
0x0042cad1:	movl -20(%ebp), %eax
0x0042cad4:	jl 0x0042cb08
0x0042cb08:	popl %edi
0x0042cb09:	popl %esi
0x0042cb0a:	testl %eax, $0x100000<UINT32>
0x0042cb0f:	je 0x0042cb7e
0x0042cb7e:	xorl %eax, %eax
0x0042cb80:	popl %ebx
0x0042cb81:	movl %esp, %ebp
0x0042cb83:	popl %ebp
0x0042cb84:	ret

0x0042c45b:	call 0x0042cb91
0x0042cb91:	call 0x00435bb5
0x00435bb5:	movl %eax, 0x410030
0x00435bba:	andl %eax, $0x1f<UINT8>
0x00435bbd:	pushl $0x20<UINT8>
0x00435bbf:	popl %ecx
0x00435bc0:	subl %ecx, %eax
0x00435bc2:	xorl %eax, %eax
0x00435bc4:	rorl %eax, %cl
0x00435bc6:	xorl %eax, 0x410030
0x00435bcc:	movl 0x40f850, %eax
0x00435bd1:	ret

0x0042cb96:	call 0x00435b49
0x00435b49:	movl %eax, 0x410030
0x00435b4e:	movl %edx, $0x40f850<UINT32>
0x00435b53:	pushl %esi
0x00435b54:	andl %eax, $0x1f<UINT8>
0x00435b57:	xorl %esi, %esi
0x00435b59:	pushl $0x20<UINT8>
0x00435b5b:	popl %ecx
0x00435b5c:	subl %ecx, %eax
0x00435b5e:	movl %eax, $0x40f82c<UINT32>
0x00435b63:	rorl %esi, %cl
0x00435b65:	xorl %ecx, %ecx
0x00435b67:	xorl %esi, 0x410030
0x00435b6d:	cmpl %edx, %eax
0x00435b6f:	sbbl %edx, %edx
0x00435b71:	andl %edx, $0xfffffff7<UINT8>
0x00435b74:	addl %edx, $0x9<UINT8>
0x00435b77:	incl %ecx
0x00435b78:	movl (%eax), %esi
0x00435b7a:	leal %eax, 0x4(%eax)
0x00435b7d:	cmpl %ecx, %edx
0x00435b7f:	jne 0x00435b77
0x00435b81:	popl %esi
0x00435b82:	ret

0x0042cb9b:	call 0x004358c6
0x004358c6:	pushl %esi
0x004358c7:	pushl %edi
0x004358c8:	movl %edi, $0x40f800<UINT32>
0x004358cd:	xorl %esi, %esi
0x004358cf:	pushl $0x0<UINT8>
0x004358d1:	pushl $0xfa0<UINT32>
0x004358d6:	pushl %edi
0x004358d7:	call 0x00435b03
0x00435b03:	pushl %ebp
0x00435b04:	movl %ebp, %esp
0x00435b06:	pushl %esi
0x00435b07:	pushl $0x409a34<UINT32>
0x00435b0c:	pushl $0x409a2c<UINT32>
0x00435b11:	pushl $0x409a34<UINT32>
0x00435b16:	pushl $0x8<UINT8>
0x00435b18:	call 0x00435931
0x00435931:	pushl %ebp
0x00435932:	movl %ebp, %esp
0x00435934:	movl %eax, 0x8(%ebp)
0x00435937:	xorl %ecx, %ecx
0x00435939:	pushl %ebx
0x0043593a:	pushl %esi
0x0043593b:	pushl %edi
0x0043593c:	leal %ebx, 0x40f82c(,%eax,4)
0x00435943:	xorl %eax, %eax
0x00435945:	cmpxchgl (%ebx), %ecx
0x00435949:	movl %edx, 0x410030
0x0043594f:	orl %edi, $0xffffffff<UINT8>
0x00435952:	movl %ecx, %edx
0x00435954:	movl %esi, %edx
0x00435956:	andl %ecx, $0x1f<UINT8>
0x00435959:	xorl %esi, %eax
0x0043595b:	rorl %esi, %cl
0x0043595d:	cmpl %esi, %edi
0x0043595f:	je 105
0x00435961:	testl %esi, %esi
0x00435963:	je 0x00435969
0x00435969:	movl %esi, 0x10(%ebp)
0x0043596c:	cmpl %esi, 0x14(%ebp)
0x0043596f:	je 26
0x00435971:	pushl (%esi)
0x00435973:	call 0x004359d1
0x004359d1:	pushl %ebp
0x004359d2:	movl %ebp, %esp
0x004359d4:	pushl %ebx
0x004359d5:	movl %ebx, 0x8(%ebp)
0x004359d8:	xorl %ecx, %ecx
0x004359da:	pushl %edi
0x004359db:	xorl %eax, %eax
0x004359dd:	leal %edi, 0x40f81c(,%ebx,4)
0x004359e4:	cmpxchgl (%edi), %ecx
0x004359e8:	movl %ecx, %eax
0x004359ea:	testl %ecx, %ecx
0x004359ec:	je 0x004359f9
0x004359f9:	movl %ebx, 0x409938(,%ebx,4)
0x00435a00:	pushl %esi
0x00435a01:	pushl $0x800<UINT32>
0x00435a06:	pushl $0x0<UINT8>
0x00435a08:	pushl %ebx
0x00435a09:	call LoadLibraryExW@KERNEL32.DLL
LoadLibraryExW@KERNEL32.DLL: API Node	
0x00435a0f:	movl %esi, %eax
0x00435a11:	testl %esi, %esi
0x00435a13:	jne 0x00435a3c
0x00435a3c:	movl %eax, %esi
0x00435a3e:	xchgl (%edi), %eax
0x00435a40:	testl %eax, %eax
0x00435a42:	je 0x00435a4b
0x00435a4b:	movl %eax, %esi
0x00435a4d:	popl %esi
0x00435a4e:	popl %edi
0x00435a4f:	popl %ebx
0x00435a50:	popl %ebp
0x00435a51:	ret

0x00435978:	popl %ecx
0x00435979:	testl %eax, %eax
0x0043597b:	jne 0x004359ac
0x004359ac:	movl %edx, 0x410030
0x004359b2:	jmp 0x0043598d
0x0043598d:	testl %eax, %eax
0x0043598f:	je 41
0x00435991:	pushl 0xc(%ebp)
0x00435994:	pushl %eax
0x00435995:	call GetProcAddress@KERNEL32.DLL
0x0043599b:	movl %esi, %eax
0x0043599d:	testl %esi, %esi
0x0043599f:	je 0x004359b4
0x004359b4:	movl %edx, 0x410030
0x004359ba:	movl %eax, %edx
0x004359bc:	pushl $0x20<UINT8>
0x004359be:	andl %eax, $0x1f<UINT8>
0x004359c1:	popl %ecx
0x004359c2:	subl %ecx, %eax
0x004359c4:	rorl %edi, %cl
0x004359c6:	xorl %edi, %edx
0x004359c8:	xchgl (%ebx), %edi
0x004359ca:	xorl %eax, %eax
0x004359cc:	popl %edi
0x004359cd:	popl %esi
0x004359ce:	popl %ebx
0x004359cf:	popl %ebp
0x004359d0:	ret

0x00435b1d:	movl %esi, %eax
0x00435b1f:	addl %esp, $0x10<UINT8>
0x00435b22:	testl %esi, %esi
0x00435b24:	je 0x00435b3a
0x00435b3a:	pushl 0xc(%ebp)
0x00435b3d:	pushl 0x8(%ebp)
0x00435b40:	call InitializeCriticalSectionAndSpinCount@KERNEL32.DLL
InitializeCriticalSectionAndSpinCount@KERNEL32.DLL: API Node	
0x00435b46:	popl %esi
0x00435b47:	popl %ebp
0x00435b48:	ret

0x004358dc:	addl %esp, $0xc<UINT8>
0x004358df:	testl %eax, %eax
0x004358e1:	je 21
0x004358e3:	incl 0x40f818
0x004358e9:	addl %esi, $0x18<UINT8>
0x004358ec:	addl %edi, $0x18<UINT8>
0x004358ef:	cmpl %esi, $0x18<UINT8>
0x004358f2:	jb -37
0x004358f4:	movb %al, $0x1<UINT8>
0x004358f6:	jmp 0x004358ff
0x004358ff:	popl %edi
0x00435900:	popl %esi
0x00435901:	ret

0x0042cba0:	testb %al, %al
0x0042cba2:	jne 0x0042cba7
0x0042cba7:	call 0x00435878
0x00435878:	pushl $0x43585c<UINT32>
0x0043587d:	call 0x00435a52
0x00435a52:	pushl %ebp
0x00435a53:	movl %ebp, %esp
0x00435a55:	pushl %esi
0x00435a56:	pushl $0x4099f0<UINT32>
0x00435a5b:	pushl $0x4099e8<UINT32>
0x00435a60:	pushl $0x4099f0<UINT32>
0x00435a65:	pushl $0x4<UINT8>
0x00435a67:	call 0x00435931
0x00435a15:	call GetLastError@KERNEL32.DLL
GetLastError@KERNEL32.DLL: API Node	
0x00435a1b:	cmpl %eax, $0x57<UINT8>
0x00435a1e:	jne 0x00435a2d
0x00435a2d:	xorl %esi, %esi
0x00435a2f:	testl %esi, %esi
0x00435a31:	jne 9
0x00435a33:	orl %eax, $0xffffffff<UINT8>
0x00435a36:	xchgl (%edi), %eax
0x00435a38:	xorl %eax, %eax
0x00435a3a:	jmp 0x00435a4d
0x0043597d:	addl %esi, $0x4<UINT8>
0x00435980:	cmpl %esi, 0x14(%ebp)
0x00435983:	jne 0x00435971
0x004359a1:	pushl %esi
0x004359a2:	call 0x0042f7f3
0x0042f7f3:	movl %edi, %edi
0x0042f7f5:	pushl %ebp
0x0042f7f6:	movl %ebp, %esp
0x0042f7f8:	movl %eax, 0x410030
0x0042f7fd:	andl %eax, $0x1f<UINT8>
0x0042f800:	pushl $0x20<UINT8>
0x0042f802:	popl %ecx
0x0042f803:	subl %ecx, %eax
0x0042f805:	movl %eax, 0x8(%ebp)
0x0042f808:	rorl %eax, %cl
0x0042f80a:	xorl %eax, 0x410030
0x0042f810:	popl %ebp
0x0042f811:	ret

0x004359a7:	popl %ecx
0x004359a8:	xchgl (%ebx), %eax
0x004359aa:	jmp 0x00435965
0x00435965:	movl %eax, %esi
0x00435967:	jmp 0x004359cc
0x00435a6c:	movl %esi, %eax
0x00435a6e:	addl %esp, $0x10<UINT8>
0x00435a71:	testl %esi, %esi
0x00435a73:	je 15
0x00435a75:	pushl 0x8(%ebp)
0x00435a78:	movl %ecx, %esi
0x00435a7a:	call 0x0042c987
0x0042c987:	jmp 0x0042c70e
0x0042c70e:	ret

0x00435a7f:	call FlsAlloc@kernel32.dll
FlsAlloc@kernel32.dll: API Node	
0x00435a81:	popl %esi
0x00435a82:	popl %ebp
0x00435a83:	ret

0x00435882:	movl 0x410070, %eax
0x00435887:	popl %ecx
0x00435888:	cmpl %eax, $0xffffffff<UINT8>
0x0043588b:	jne 0x00435890
0x00435890:	pushl $0x40f7d8<UINT32>
0x00435895:	pushl %eax
0x00435896:	call 0x00435ac6
0x00435ac6:	pushl %ebp
0x00435ac7:	movl %ebp, %esp
0x00435ac9:	pushl %esi
0x00435aca:	pushl $0x409a20<UINT32>
0x00435acf:	pushl $0x409a18<UINT32>
0x00435ad4:	pushl $0x409a20<UINT32>
0x00435ad9:	pushl $0x7<UINT8>
0x00435adb:	call 0x00435931
0x004359ee:	leal %eax, 0x1(%ecx)
0x004359f1:	negl %eax
0x004359f3:	sbbl %eax, %eax
0x004359f5:	andl %eax, %ecx
0x004359f7:	jmp 0x00435a4e
0x00435ae0:	addl %esp, $0x10<UINT8>
0x00435ae3:	movl %esi, %eax
0x00435ae5:	pushl 0xc(%ebp)
0x00435ae8:	pushl 0x8(%ebp)
0x00435aeb:	testl %esi, %esi
0x00435aed:	je 11
0x00435aef:	movl %ecx, %esi
0x00435af1:	call 0x0042c987
0x00435af6:	call FlsSetValue@kernel32.dll
FlsSetValue@kernel32.dll: API Node	
0x00435af8:	jmp 0x00435b00
0x00435b00:	popl %esi
0x00435b01:	popl %ebp
0x00435b02:	ret

0x0043589b:	popl %ecx
0x0043589c:	popl %ecx
0x0043589d:	testl %eax, %eax
0x0043589f:	jne 0x004358a8
0x004358a8:	movb %al, $0x1<UINT8>
0x004358aa:	ret

0x0042cbac:	testb %al, %al
0x0042cbae:	jne 0x0042cbb7
0x0042cbb7:	movb %al, $0x1<UINT8>
0x0042cbb9:	ret

0x0042c460:	testb %al, %al
0x0042c462:	jne 0x0042c468
0x0042c468:	call 0x0042f843
0x0042f843:	pushl $0x408de0<UINT32>
0x0042f848:	pushl $0x408d68<UINT32>
0x0042f84d:	call 0x004374c1
0x004374c1:	movl %edi, %edi
0x004374c3:	pushl %ebp
0x004374c4:	movl %ebp, %esp
0x004374c6:	pushl %ecx
0x004374c7:	movl %eax, 0x410030
0x004374cc:	xorl %eax, %ebp
0x004374ce:	movl -4(%ebp), %eax
0x004374d1:	pushl %edi
0x004374d2:	movl %edi, 0x8(%ebp)
0x004374d5:	cmpl %edi, 0xc(%ebp)
0x004374d8:	jne 0x004374de
0x004374de:	pushl %esi
0x004374df:	movl %esi, %edi
0x004374e1:	pushl %ebx
0x004374e2:	movl %ebx, (%esi)
0x004374e4:	testl %ebx, %ebx
0x004374e6:	je 0x004374f6
0x004374e8:	movl %ecx, %ebx
0x004374ea:	call 0x0042c70e
0x004374f0:	call 0x0042f705
0x0042f6f3:	pushl $0x4105e0<UINT32>
0x0042f6f8:	movl %ecx, $0x40fcc4<UINT32>
0x0042f6fd:	call 0x0042f812
0x0042f812:	movl %edi, %edi
0x0042f814:	pushl %ebp
0x0042f815:	movl %ebp, %esp
0x0042f817:	leal %eax, 0x4(%ecx)
0x0042f81a:	movl %edx, %eax
0x0042f81c:	subl %edx, %ecx
0x0042f81e:	addl %edx, $0x3<UINT8>
0x0042f821:	pushl %esi
0x0042f822:	xorl %esi, %esi
0x0042f824:	shrl %edx, $0x2<UINT8>
0x0042f827:	cmpl %eax, %ecx
0x0042f829:	sbbl %eax, %eax
0x0042f82b:	notl %eax
0x0042f82d:	andl %eax, %edx
0x0042f82f:	je 13
0x0042f831:	movl %edx, 0x8(%ebp)
0x0042f834:	incl %esi
0x0042f835:	movl (%ecx), %edx
0x0042f837:	leal %ecx, 0x4(%ecx)
0x0042f83a:	cmpl %esi, %eax
0x0042f83c:	jne -10
0x0042f83e:	popl %esi
0x0042f83f:	popl %ebp
0x0042f840:	ret $0x4<UINT16>

0x0042f702:	movb %al, $0x1<UINT8>
0x0042f704:	ret

0x004374f2:	testb %al, %al
0x004374f4:	je 8
0x004374f6:	addl %esi, $0x8<UINT8>
0x004374f9:	cmpl %esi, 0xc(%ebp)
0x004374fc:	jne 0x004374e2
0x0042f733:	movl %eax, 0x410030
0x0042f738:	pushl %esi
0x0042f739:	pushl $0x20<UINT8>
0x0042f73b:	andl %eax, $0x1f<UINT8>
0x0042f73e:	xorl %esi, %esi
0x0042f740:	popl %ecx
0x0042f741:	subl %ecx, %eax
0x0042f743:	rorl %esi, %cl
0x0042f745:	xorl %esi, 0x410030
0x0042f74b:	pushl %esi
0x0042f74c:	call 0x004376cc
0x004376cc:	movl %edi, %edi
0x004376ce:	pushl %ebp
0x004376cf:	movl %ebp, %esp
0x004376d1:	pushl 0x8(%ebp)
0x004376d4:	movl %ecx, $0x40fcac<UINT32>
0x004376d9:	call 0x0042f812
0x004376de:	popl %ebp
0x004376df:	ret

0x0042f751:	pushl %esi
0x0042f752:	call 0x0043779e
0x0043779e:	movl %edi, %edi
0x004377a0:	pushl %ebp
0x004377a1:	movl %ebp, %esp
0x004377a3:	pushl 0x8(%ebp)
0x004377a6:	movl %ecx, $0x40fcb0<UINT32>
0x004377ab:	call 0x0042f812
0x004377b0:	popl %ebp
0x004377b1:	ret

0x0042f757:	pushl %esi
0x0042f758:	call 0x0043794b
0x0043794b:	movl %edi, %edi
0x0043794d:	pushl %ebp
0x0043794e:	movl %ebp, %esp
0x00437950:	pushl 0x8(%ebp)
0x00437953:	movl %ecx, $0x40fcb4<UINT32>
0x00437958:	call 0x0042f812
0x0043795d:	pushl 0x8(%ebp)
0x00437960:	movl %ecx, $0x40fcb8<UINT32>
0x00437965:	call 0x0042f812
0x0043796a:	pushl 0x8(%ebp)
0x0043796d:	movl %ecx, $0x40fcbc<UINT32>
0x00437972:	call 0x0042f812
0x00437977:	pushl 0x8(%ebp)
0x0043797a:	movl %ecx, $0x40fcc0<UINT32>
0x0043797f:	call 0x0042f812
0x00437984:	popl %ebp
0x00437985:	ret

0x0042f75d:	pushl %esi
0x0042f75e:	call 0x0042f886
0x0042f886:	movl %edi, %edi
0x0042f888:	pushl %ebp
0x0042f889:	movl %ebp, %esp
0x0042f88b:	pushl 0x8(%ebp)
0x0042f88e:	movl %ecx, $0x40f64c<UINT32>
0x0042f893:	call 0x0042f812
0x0042f898:	popl %ebp
0x0042f899:	ret

0x0042f763:	pushl %esi
0x0042f764:	call 0x004324db
0x004324db:	movl %edi, %edi
0x004324dd:	pushl %ebp
0x004324de:	movl %ebp, %esp
0x004324e0:	movl %eax, 0x8(%ebp)
0x004324e3:	movl 0x40f654, %eax
0x004324e8:	popl %ebp
0x004324e9:	ret

0x0042f769:	addl %esp, $0x14<UINT8>
0x0042f76c:	movb %al, $0x1<UINT8>
0x0042f76e:	popl %esi
0x0042f76f:	ret

0x004363a9:	movl %eax, 0x410030
0x004363ae:	pushl %edi
0x004363af:	pushl $0x20<UINT8>
0x004363b1:	andl %eax, $0x1f<UINT8>
0x004363b4:	movl %edi, $0x40f8a8<UINT32>
0x004363b9:	popl %ecx
0x004363ba:	subl %ecx, %eax
0x004363bc:	xorl %eax, %eax
0x004363be:	rorl %eax, %cl
0x004363c0:	xorl %eax, 0x410030
0x004363c6:	pushl $0x20<UINT8>
0x004363c8:	popl %ecx
0x004363c9:	rep stosl %es:(%edi), %eax
0x004363cb:	movb %al, $0x1<UINT8>
0x004363cd:	popl %edi
0x004363ce:	ret

0x0042f72d:	movb %al, $0x1<UINT8>
0x0042f72f:	ret

0x00436532:	movl %edi, %edi
0x00436534:	pushl %esi
0x00436535:	pushl %edi
0x00436536:	movl %edi, $0x40f930<UINT32>
0x0043653b:	xorl %esi, %esi
0x0043653d:	pushl $0x0<UINT8>
0x0043653f:	pushl $0xfa0<UINT32>
0x00436544:	pushl %edi
0x00436545:	call 0x00436182
0x00436182:	movl %edi, %edi
0x00436184:	pushl %ebp
0x00436185:	movl %ebp, %esp
0x00436187:	pushl %ecx
0x00436188:	movl %eax, 0x410030
0x0043618d:	xorl %eax, %ebp
0x0043618f:	movl -4(%ebp), %eax
0x00436192:	pushl %esi
0x00436193:	pushl $0x409fc0<UINT32>
0x00436198:	pushl $0x409fb8<UINT32>
0x0043619d:	pushl $0x409a34<UINT32>
0x004361a2:	pushl $0x14<UINT8>
0x004361a4:	call 0x00435ec2
0x00435ec2:	movl %edi, %edi
0x00435ec4:	pushl %ebp
0x00435ec5:	movl %ebp, %esp
0x00435ec7:	movl %eax, 0x8(%ebp)
0x00435eca:	pushl %ebx
0x00435ecb:	pushl %esi
0x00435ecc:	pushl %edi
0x00435ecd:	leal %ebx, 0x40f8a8(,%eax,4)
0x00435ed4:	movl %eax, (%ebx)
0x00435ed6:	movl %edx, 0x410030
0x00435edc:	orl %edi, $0xffffffff<UINT8>
0x00435edf:	movl %ecx, %edx
0x00435ee1:	movl %esi, %edx
0x00435ee3:	andl %ecx, $0x1f<UINT8>
0x00435ee6:	xorl %esi, %eax
0x00435ee8:	rorl %esi, %cl
0x00435eea:	cmpl %esi, %edi
0x00435eec:	je 0x00435f57
0x00435eee:	testl %esi, %esi
0x00435ef0:	je 0x00435ef6
0x00435ef6:	movl %esi, 0x10(%ebp)
0x00435ef9:	cmpl %esi, 0x14(%ebp)
0x00435efc:	je 26
0x00435efe:	pushl (%esi)
0x00435f00:	call 0x00435f5e
0x00435f5e:	movl %edi, %edi
0x00435f60:	pushl %ebp
0x00435f61:	movl %ebp, %esp
0x00435f63:	movl %eax, 0x8(%ebp)
0x00435f66:	pushl %edi
0x00435f67:	leal %edi, 0x40f858(,%eax,4)
0x00435f6e:	movl %ecx, (%edi)
0x00435f70:	testl %ecx, %ecx
0x00435f72:	je 0x00435f7f
0x00435f7f:	pushl %ebx
0x00435f80:	movl %ebx, 0x409a50(,%eax,4)
0x00435f87:	pushl %esi
0x00435f88:	pushl $0x800<UINT32>
0x00435f8d:	pushl $0x0<UINT8>
0x00435f8f:	pushl %ebx
0x00435f90:	call LoadLibraryExW@KERNEL32.DLL
0x00435f96:	movl %esi, %eax
0x00435f98:	testl %esi, %esi
0x00435f9a:	jne 0x00435fc3
0x00435fc3:	movl %eax, %esi
0x00435fc5:	xchgl (%edi), %eax
0x00435fc7:	testl %eax, %eax
0x00435fc9:	je 0x00435fd2
0x00435fd2:	movl %eax, %esi
0x00435fd4:	popl %esi
0x00435fd5:	popl %ebx
0x00435fd6:	popl %edi
0x00435fd7:	popl %ebp
0x00435fd8:	ret

0x00435f05:	popl %ecx
0x00435f06:	testl %eax, %eax
0x00435f08:	jne 0x00435f39
0x00435f39:	movl %edx, 0x410030
0x00435f3f:	jmp 0x00435f1a
0x00435f1a:	testl %eax, %eax
0x00435f1c:	je 41
0x00435f1e:	pushl 0xc(%ebp)
0x00435f21:	pushl %eax
0x00435f22:	call GetProcAddress@KERNEL32.DLL
0x00435f28:	movl %esi, %eax
0x00435f2a:	testl %esi, %esi
0x00435f2c:	je 0x00435f41
0x00435f41:	movl %edx, 0x410030
0x00435f47:	movl %eax, %edx
0x00435f49:	pushl $0x20<UINT8>
0x00435f4b:	andl %eax, $0x1f<UINT8>
0x00435f4e:	popl %ecx
0x00435f4f:	subl %ecx, %eax
0x00435f51:	rorl %edi, %cl
0x00435f53:	xorl %edi, %edx
0x00435f55:	xchgl (%ebx), %edi
0x00435f57:	xorl %eax, %eax
0x00435f59:	popl %edi
0x00435f5a:	popl %esi
0x00435f5b:	popl %ebx
0x00435f5c:	popl %ebp
0x00435f5d:	ret

0x004361a9:	movl %esi, %eax
0x004361ab:	addl %esp, $0x10<UINT8>
0x004361ae:	testl %esi, %esi
0x004361b0:	je 0x004361c7
0x004361c7:	pushl 0xc(%ebp)
0x004361ca:	pushl 0x8(%ebp)
0x004361cd:	call InitializeCriticalSectionAndSpinCount@KERNEL32.DLL
0x004361d3:	movl %ecx, -4(%ebp)
0x004361d6:	xorl %ecx, %ebp
0x004361d8:	popl %esi
0x004361d9:	call 0x0042c018
0x0042c018:	cmpl %ecx, 0x410030
0x0042c01e:	repn jne 2
0x0042c021:	repn ret

0x004361de:	movl %esp, %ebp
0x004361e0:	popl %ebp
0x004361e1:	ret $0xc<UINT16>

0x0043654a:	testl %eax, %eax
0x0043654c:	je 24
0x0043654e:	incl 0x40fa68
0x00436554:	addl %esi, $0x18<UINT8>
0x00436557:	addl %edi, $0x18<UINT8>
0x0043655a:	cmpl %esi, $0x138<UINT32>
0x00436560:	jb 0x0043653d
0x00436562:	movb %al, $0x1<UINT8>
0x00436564:	jmp 0x00436570
0x00436570:	popl %edi
0x00436571:	popl %esi
0x00436572:	ret

0x004365d2:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x004365d8:	testl %eax, %eax
0x004365da:	movl 0x40fa6c, %eax
0x004365df:	setne %al
0x004365e2:	ret

0x00436a68:	pushl $0x43684a<UINT32>
0x00436a6d:	call 0x00436027
0x00436027:	movl %edi, %edi
0x00436029:	pushl %ebp
0x0043602a:	movl %ebp, %esp
0x0043602c:	pushl %ecx
0x0043602d:	movl %eax, 0x410030
0x00436032:	xorl %eax, %ebp
0x00436034:	movl -4(%ebp), %eax
0x00436037:	pushl %esi
0x00436038:	pushl $0x409f0c<UINT32>
0x0043603d:	pushl $0x409f04<UINT32>
0x00436042:	pushl $0x4099f0<UINT32>
0x00436047:	pushl $0x3<UINT8>
0x00436049:	call 0x00435ec2
0x00435f9c:	call GetLastError@KERNEL32.DLL
0x00435fa2:	cmpl %eax, $0x57<UINT8>
0x00435fa5:	jne 0x00435fb4
0x00435fb4:	xorl %esi, %esi
0x00435fb6:	testl %esi, %esi
0x00435fb8:	jne 9
0x00435fba:	orl %eax, $0xffffffff<UINT8>
0x00435fbd:	xchgl (%edi), %eax
0x00435fbf:	xorl %eax, %eax
0x00435fc1:	jmp 0x00435fd4
0x00435f0a:	addl %esi, $0x4<UINT8>
0x00435f0d:	cmpl %esi, 0x14(%ebp)
0x00435f10:	jne 0x00435efe
0x00435f2e:	pushl %esi
0x00435f2f:	call 0x0042f7f3
0x00435f34:	popl %ecx
0x00435f35:	xchgl (%ebx), %eax
0x00435f37:	jmp 0x00435ef2
0x00435ef2:	movl %eax, %esi
0x00435ef4:	jmp 0x00435f59
0x0043604e:	movl %esi, %eax
0x00436050:	addl %esp, $0x10<UINT8>
0x00436053:	testl %esi, %esi
0x00436055:	je 15
0x00436057:	pushl 0x8(%ebp)
0x0043605a:	movl %ecx, %esi
0x0043605c:	call 0x0042c70e
0x00436062:	call FlsAlloc@kernel32.dll
0x00436064:	jmp 0x0043606c
0x0043606c:	movl %ecx, -4(%ebp)
0x0043606f:	xorl %ecx, %ebp
0x00436071:	popl %esi
0x00436072:	call 0x0042c018
0x00436077:	movl %esp, %ebp
0x00436079:	popl %ebp
0x0043607a:	ret $0x4<UINT16>

0x00436a72:	movl 0x410080, %eax
0x00436a77:	cmpl %eax, $0xffffffff<UINT8>
0x00436a7a:	jne 0x00436a7f
0x00436a7f:	call 0x004369e3
0x004369e3:	movl %edi, %edi
0x004369e5:	pushl %ebx
0x004369e6:	pushl %esi
0x004369e7:	pushl %edi
0x004369e8:	call GetLastError@KERNEL32.DLL
0x004369ee:	movl %esi, %eax
0x004369f0:	xorl %ebx, %ebx
0x004369f2:	movl %eax, 0x410080
0x004369f7:	cmpl %eax, $0xffffffff<UINT8>
0x004369fa:	je 12
0x004369fc:	pushl %eax
0x004369fd:	call 0x004360d3
0x004360d3:	movl %edi, %edi
0x004360d5:	pushl %ebp
0x004360d6:	movl %ebp, %esp
0x004360d8:	pushl %ecx
0x004360d9:	movl %eax, 0x410030
0x004360de:	xorl %eax, %ebp
0x004360e0:	movl -4(%ebp), %eax
0x004360e3:	pushl %esi
0x004360e4:	pushl $0x409f1c<UINT32>
0x004360e9:	pushl $0x409f14<UINT32>
0x004360ee:	pushl $0x409a0c<UINT32>
0x004360f3:	pushl $0x5<UINT8>
0x004360f5:	call 0x00435ec2
0x00435f74:	leal %eax, 0x1(%ecx)
0x00435f77:	negl %eax
0x00435f79:	sbbl %eax, %eax
0x00435f7b:	andl %eax, %ecx
0x00435f7d:	jmp 0x00435fd6
0x004360fa:	addl %esp, $0x10<UINT8>
0x004360fd:	movl %esi, %eax
0x004360ff:	pushl 0x8(%ebp)
0x00436102:	testl %esi, %esi
0x00436104:	je 12
0x00436106:	movl %ecx, %esi
0x00436108:	call 0x0042c70e
0x0043610e:	call FlsGetValue@kernel32.dll
FlsGetValue@kernel32.dll: API Node	
0x00436110:	jmp 0x00436118
0x00436118:	movl %ecx, -4(%ebp)
0x0043611b:	xorl %ecx, %ebp
0x0043611d:	popl %esi
0x0043611e:	call 0x0042c018
0x00436123:	movl %esp, %ebp
0x00436125:	popl %ebp
0x00436126:	ret $0x4<UINT16>

0x00436a02:	movl %edi, %eax
0x00436a04:	testl %edi, %edi
0x00436a06:	jne 81
0x00436a08:	pushl $0x364<UINT32>
0x00436a0d:	pushl $0x1<UINT8>
0x00436a0f:	call 0x00439337
0x00439337:	movl %edi, %edi
0x00439339:	pushl %ebp
0x0043933a:	movl %ebp, %esp
0x0043933c:	pushl %esi
0x0043933d:	movl %esi, 0x8(%ebp)
0x00439340:	testl %esi, %esi
0x00439342:	je 12
0x00439344:	pushl $0xffffffe0<UINT8>
0x00439346:	xorl %edx, %edx
0x00439348:	popl %eax
0x00439349:	divl %eax, %esi
0x0043934b:	cmpl %eax, 0xc(%ebp)
0x0043934e:	jb 52
0x00439350:	imull %esi, 0xc(%ebp)
0x00439354:	testl %esi, %esi
0x00439356:	jne 0x0043936f
0x0043936f:	pushl %esi
0x00439370:	pushl $0x8<UINT8>
0x00439372:	pushl 0x40fa6c
0x00439378:	call HeapAlloc@KERNEL32.DLL
HeapAlloc@KERNEL32.DLL: API Node	
0x0043937e:	testl %eax, %eax
0x00439380:	je -39
0x00439382:	jmp 0x00439391
0x00439391:	popl %esi
0x00439392:	popl %ebp
0x00439393:	ret

0x00436a14:	movl %edi, %eax
0x00436a16:	popl %ecx
0x00436a17:	popl %ecx
0x00436a18:	testl %edi, %edi
0x00436a1a:	jne 0x00436a25
0x00436a25:	pushl %edi
0x00436a26:	pushl 0x410080
0x00436a2c:	call 0x00436129
0x00436129:	movl %edi, %edi
0x0043612b:	pushl %ebp
0x0043612c:	movl %ebp, %esp
0x0043612e:	pushl %ecx
0x0043612f:	movl %eax, 0x410030
0x00436134:	xorl %eax, %ebp
0x00436136:	movl -4(%ebp), %eax
0x00436139:	pushl %esi
0x0043613a:	pushl $0x409f24<UINT32>
0x0043613f:	pushl $0x409f1c<UINT32>
0x00436144:	pushl $0x409a20<UINT32>
0x00436149:	pushl $0x6<UINT8>
0x0043614b:	call 0x00435ec2
0x00436150:	addl %esp, $0x10<UINT8>
0x00436153:	movl %esi, %eax
0x00436155:	pushl 0xc(%ebp)
0x00436158:	pushl 0x8(%ebp)
0x0043615b:	testl %esi, %esi
0x0043615d:	je 12
0x0043615f:	movl %ecx, %esi
0x00436161:	call 0x0042c70e
0x00436167:	call FlsSetValue@kernel32.dll
0x00436169:	jmp 0x00436171
0x00436171:	movl %ecx, -4(%ebp)
0x00436174:	xorl %ecx, %ebp
0x00436176:	popl %esi
0x00436177:	call 0x0042c018
0x0043617c:	movl %esp, %ebp
0x0043617e:	popl %ebp
0x0043617f:	ret $0x8<UINT16>

0x00436a31:	testl %eax, %eax
0x00436a33:	jne 0x00436a38
0x00436a38:	pushl $0x40fcc4<UINT32>
0x00436a3d:	pushl %edi
0x00436a3e:	call 0x004367d1
0x004367d1:	movl %edi, %edi
0x004367d3:	pushl %ebp
0x004367d4:	movl %ebp, %esp
0x004367d6:	pushl %ecx
0x004367d7:	pushl %ecx
0x004367d8:	movl %eax, 0x8(%ebp)
0x004367db:	xorl %ecx, %ecx
0x004367dd:	incl %ecx
0x004367de:	pushl $0x43<UINT8>
0x004367e0:	movl 0x18(%eax), %ecx
0x004367e3:	movl %eax, 0x8(%ebp)
0x004367e6:	movl (%eax), $0x408e80<UINT32>
0x004367ec:	movl %eax, 0x8(%ebp)
0x004367ef:	movl 0x350(%eax), %ecx
0x004367f5:	movl %eax, 0x8(%ebp)
0x004367f8:	popl %ecx
0x004367f9:	movl 0x48(%eax), $0x4103b8<UINT32>
0x00436800:	movl %eax, 0x8(%ebp)
0x00436803:	movw 0x6c(%eax), %cx
0x00436807:	movl %eax, 0x8(%ebp)
0x0043680a:	movw 0x172(%eax), %cx
0x00436811:	movl %eax, 0x8(%ebp)
0x00436814:	andl 0x34c(%eax), $0x0<UINT8>
0x0043681b:	leal %eax, 0x8(%ebp)
0x0043681e:	movl -4(%ebp), %eax
0x00436821:	leal %eax, -4(%ebp)
0x00436824:	pushl %eax
0x00436825:	pushl $0x5<UINT8>
0x00436827:	call 0x004367a9
0x004367a9:	movl %edi, %edi
0x004367ab:	pushl %ebp
0x004367ac:	movl %ebp, %esp
0x004367ae:	subl %esp, $0xc<UINT8>
0x004367b1:	movl %eax, 0x8(%ebp)
0x004367b4:	leal %ecx, -1(%ebp)
0x004367b7:	movl -8(%ebp), %eax
0x004367ba:	movl -12(%ebp), %eax
0x004367bd:	leal %eax, -8(%ebp)
0x004367c0:	pushl %eax
0x004367c1:	pushl 0xc(%ebp)
0x004367c4:	leal %eax, -12(%ebp)
0x004367c7:	pushl %eax
0x004367c8:	call 0x004366e9
0x004366e9:	pushl $0x8<UINT8>
0x004366eb:	pushl $0x443208<UINT32>
0x004366f0:	call 0x0042c990
0x004366f5:	movl %eax, 0x8(%ebp)
0x004366f8:	pushl (%eax)
0x004366fa:	call 0x00436573
0x00436573:	movl %edi, %edi
0x00436575:	pushl %ebp
0x00436576:	movl %ebp, %esp
0x00436578:	imull %eax, 0x8(%ebp), $0x18<UINT8>
0x0043657c:	addl %eax, $0x40f930<UINT32>
0x00436581:	pushl %eax
0x00436582:	call EnterCriticalSection@KERNEL32.DLL
EnterCriticalSection@KERNEL32.DLL: API Node	
0x00436588:	popl %ebp
0x00436589:	ret

0x004366ff:	popl %ecx
0x00436700:	andl -4(%ebp), $0x0<UINT8>
0x00436704:	movl %eax, 0xc(%ebp)
0x00436707:	movl %eax, (%eax)
0x00436709:	movl %eax, (%eax)
0x0043670b:	movl %eax, 0x48(%eax)
0x0043670e:	incl (%eax)
0x00436711:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00436718:	call 0x00436725
0x00436725:	movl %eax, 0x10(%ebp)
0x00436728:	pushl (%eax)
0x0043672a:	call 0x004365bb
0x004365bb:	movl %edi, %edi
0x004365bd:	pushl %ebp
0x004365be:	movl %ebp, %esp
0x004365c0:	imull %eax, 0x8(%ebp), $0x18<UINT8>
0x004365c4:	addl %eax, $0x40f930<UINT32>
0x004365c9:	pushl %eax
0x004365ca:	call LeaveCriticalSection@KERNEL32.DLL
LeaveCriticalSection@KERNEL32.DLL: API Node	
0x004365d0:	popl %ebp
0x004365d1:	ret

0x0043672f:	popl %ecx
0x00436730:	ret

0x0043671d:	call 0x0042c9d6
0x0042c9d6:	movl %ecx, -16(%ebp)
0x0042c9d9:	movl %fs:0, %ecx
0x0042c9e0:	popl %ecx
0x0042c9e1:	popl %edi
0x0042c9e2:	popl %edi
0x0042c9e3:	popl %esi
0x0042c9e4:	popl %ebx
0x0042c9e5:	movl %esp, %ebp
0x0042c9e7:	popl %ebp
0x0042c9e8:	pushl %ecx
0x0042c9e9:	repn ret

0x00436722:	ret $0xc<UINT16>

0x004367cd:	movl %esp, %ebp
0x004367cf:	popl %ebp
0x004367d0:	ret

0x0043682c:	leal %eax, 0x8(%ebp)
0x0043682f:	movl -8(%ebp), %eax
0x00436832:	leal %eax, 0xc(%ebp)
0x00436835:	movl -4(%ebp), %eax
0x00436838:	leal %eax, -8(%ebp)
0x0043683b:	pushl %eax
0x0043683c:	pushl $0x4<UINT8>
0x0043683e:	call 0x00436759
0x00436759:	movl %edi, %edi
0x0043675b:	pushl %ebp
0x0043675c:	movl %ebp, %esp
0x0043675e:	subl %esp, $0xc<UINT8>
0x00436761:	movl %eax, 0x8(%ebp)
0x00436764:	leal %ecx, -1(%ebp)
0x00436767:	movl -8(%ebp), %eax
0x0043676a:	movl -12(%ebp), %eax
0x0043676d:	leal %eax, -8(%ebp)
0x00436770:	pushl %eax
0x00436771:	pushl 0xc(%ebp)
0x00436774:	leal %eax, -12(%ebp)
0x00436777:	pushl %eax
0x00436778:	call 0x004365ed
0x004365ed:	pushl $0x8<UINT8>
0x004365ef:	pushl $0x443228<UINT32>
0x004365f4:	call 0x0042c990
0x004365f9:	movl %eax, 0x8(%ebp)
0x004365fc:	pushl (%eax)
0x004365fe:	call 0x00436573
0x00436603:	popl %ecx
0x00436604:	andl -4(%ebp), $0x0<UINT8>
0x00436608:	movl %ecx, 0xc(%ebp)
0x0043660b:	movl %eax, 0x4(%ecx)
0x0043660e:	movl %eax, (%eax)
0x00436610:	pushl (%eax)
0x00436612:	movl %eax, (%ecx)
0x00436614:	pushl (%eax)
0x00436616:	call 0x00436914
0x00436914:	movl %edi, %edi
0x00436916:	pushl %ebp
0x00436917:	movl %ebp, %esp
0x00436919:	pushl %esi
0x0043691a:	movl %esi, 0x8(%ebp)
0x0043691d:	cmpl 0x4c(%esi), $0x0<UINT8>
0x00436921:	je 0x0043694b
0x0043694b:	movl %eax, 0xc(%ebp)
0x0043694e:	movl 0x4c(%esi), %eax
0x00436951:	popl %esi
0x00436952:	testl %eax, %eax
0x00436954:	je 7
0x00436956:	pushl %eax
0x00436957:	call 0x004395aa
0x004395aa:	movl %edi, %edi
0x004395ac:	pushl %ebp
0x004395ad:	movl %ebp, %esp
0x004395af:	movl %eax, 0x8(%ebp)
0x004395b2:	incl 0xc(%eax)
0x004395b6:	movl %ecx, 0x7c(%eax)
0x004395b9:	testl %ecx, %ecx
0x004395bb:	je 0x004395c0
0x004395c0:	movl %ecx, 0x84(%eax)
0x004395c6:	testl %ecx, %ecx
0x004395c8:	je 0x004395cd
0x004395cd:	movl %ecx, 0x80(%eax)
0x004395d3:	testl %ecx, %ecx
0x004395d5:	je 0x004395da
0x004395da:	movl %ecx, 0x8c(%eax)
0x004395e0:	testl %ecx, %ecx
0x004395e2:	je 0x004395e7
0x004395e7:	pushl %esi
0x004395e8:	pushl $0x6<UINT8>
0x004395ea:	leal %ecx, 0x28(%eax)
0x004395ed:	popl %esi
0x004395ee:	cmpl -8(%ecx), $0x4106a0<UINT32>
0x004395f5:	je 0x00439600
0x004395f7:	movl %edx, (%ecx)
0x004395f9:	testl %edx, %edx
0x004395fb:	je 0x00439600
0x00439600:	cmpl -12(%ecx), $0x0<UINT8>
0x00439604:	je 0x00439610
0x00439610:	addl %ecx, $0x10<UINT8>
0x00439613:	subl %esi, $0x1<UINT8>
0x00439616:	jne 0x004395ee
0x00439618:	pushl 0x9c(%eax)
0x0043961e:	call 0x00439771
0x00439771:	movl %edi, %edi
0x00439773:	pushl %ebp
0x00439774:	movl %ebp, %esp
0x00439776:	movl %ecx, 0x8(%ebp)
0x00439779:	testl %ecx, %ecx
0x0043977b:	je 22
0x0043977d:	cmpl %ecx, $0x40a3b8<UINT32>
0x00439783:	je 0x00439793
0x00439793:	movl %eax, $0x7fffffff<UINT32>
0x00439798:	popl %ebp
0x00439799:	ret

0x00439623:	popl %ecx
0x00439624:	popl %esi
0x00439625:	popl %ebp
0x00439626:	ret

0x0043695c:	popl %ecx
0x0043695d:	popl %ebp
0x0043695e:	ret

0x0043661b:	popl %ecx
0x0043661c:	popl %ecx
0x0043661d:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00436624:	call 0x00436631
0x00436631:	movl %eax, 0x10(%ebp)
0x00436634:	pushl (%eax)
0x00436636:	call 0x004365bb
0x0043663b:	popl %ecx
0x0043663c:	ret

0x00436629:	call 0x0042c9d6
0x0043662e:	ret $0xc<UINT16>

0x0043677d:	movl %esp, %ebp
0x0043677f:	popl %ebp
0x00436780:	ret

0x00436843:	addl %esp, $0x10<UINT8>
0x00436846:	movl %esp, %ebp
0x00436848:	popl %ebp
0x00436849:	ret

0x00436a43:	pushl %ebx
0x00436a44:	call 0x0043577a
0x0043577a:	movl %edi, %edi
0x0043577c:	pushl %ebp
0x0043577d:	movl %ebp, %esp
0x0043577f:	cmpl 0x8(%ebp), $0x0<UINT8>
0x00435783:	je 0x004357b2
0x004357b2:	popl %ebp
0x004357b3:	ret

0x00436a49:	addl %esp, $0xc<UINT8>
0x00436a4c:	testl %edi, %edi
0x00436a4e:	jne 0x00436a59
0x00436a59:	pushl %esi
0x00436a5a:	call SetLastError@KERNEL32.DLL
SetLastError@KERNEL32.DLL: API Node	
0x00436a60:	movl %ebx, %edi
0x00436a62:	popl %edi
0x00436a63:	popl %esi
0x00436a64:	movl %eax, %ebx
0x00436a66:	popl %ebx
0x00436a67:	ret

0x00436a84:	testl %eax, %eax
0x00436a86:	jne 0x00436a91
0x00436a91:	movb %al, $0x1<UINT8>
0x00436a93:	ret

0x00436c1a:	pushl $0xc<UINT8>
0x00436c1c:	pushl $0x443288<UINT32>
0x00436c21:	call 0x0042c990
0x00436c26:	pushl $0x7<UINT8>
0x00436c28:	call 0x00436573
0x00436c2d:	popl %ecx
0x00436c2e:	xorl %ebx, %ebx
0x00436c30:	movb -25(%ebp), %bl
0x00436c33:	movl -4(%ebp), %ebx
0x00436c36:	pushl %ebx
0x00436c37:	call 0x0043a6a4
0x0043a6a4:	pushl $0x14<UINT8>
0x0043a6a6:	pushl $0x443388<UINT32>
0x0043a6ab:	call 0x0042c990
0x0043a6b0:	cmpl 0x8(%ebp), $0x2000<UINT32>
0x0043a6b7:	sbbl %eax, %eax
0x0043a6b9:	negl %eax
0x0043a6bb:	jne 0x0043a6d4
0x0043a6d4:	xorl %esi, %esi
0x0043a6d6:	movl -28(%ebp), %esi
0x0043a6d9:	pushl $0x7<UINT8>
0x0043a6db:	call 0x00436573
0x0043a6e0:	popl %ecx
0x0043a6e1:	movl -4(%ebp), %esi
0x0043a6e4:	movl %edi, %esi
0x0043a6e6:	movl %eax, 0x40fc70
0x0043a6eb:	movl -32(%ebp), %edi
0x0043a6ee:	cmpl 0x8(%ebp), %eax
0x0043a6f1:	jl 0x0043a712
0x0043a6f3:	cmpl 0x40fa70(,%edi,4), %esi
0x0043a6fa:	jne 49
0x0043a6fc:	call 0x0043a5f5
0x0043a5f5:	movl %edi, %edi
0x0043a5f7:	pushl %ebp
0x0043a5f8:	movl %ebp, %esp
0x0043a5fa:	pushl %ecx
0x0043a5fb:	pushl %ecx
0x0043a5fc:	pushl %ebx
0x0043a5fd:	pushl %edi
0x0043a5fe:	pushl $0x30<UINT8>
0x0043a600:	pushl $0x40<UINT8>
0x0043a602:	call 0x00439337
0x0043a607:	movl %edi, %eax
0x0043a609:	xorl %ebx, %ebx
0x0043a60b:	movl -8(%ebp), %edi
0x0043a60e:	popl %ecx
0x0043a60f:	popl %ecx
0x0043a610:	testl %edi, %edi
0x0043a612:	jne 0x0043a618
0x0043a618:	leal %eax, 0xc00(%edi)
0x0043a61e:	cmpl %edi, %eax
0x0043a620:	je 62
0x0043a622:	pushl %esi
0x0043a623:	leal %esi, 0x20(%edi)
0x0043a626:	movl %edi, %eax
0x0043a628:	pushl %ebx
0x0043a629:	pushl $0xfa0<UINT32>
0x0043a62e:	leal %eax, -32(%esi)
0x0043a631:	pushl %eax
0x0043a632:	call 0x00436182
0x0043a637:	orl -8(%esi), $0xffffffff<UINT8>
0x0043a63b:	movl (%esi), %ebx
0x0043a63d:	leal %esi, 0x30(%esi)
0x0043a640:	movl -44(%esi), %ebx
0x0043a643:	leal %eax, -32(%esi)
0x0043a646:	movl -40(%esi), $0xa0a0000<UINT32>
0x0043a64d:	movb -36(%esi), $0xa<UINT8>
0x0043a651:	andb -35(%esi), $0xfffffff8<UINT8>
0x0043a655:	movb -34(%esi), %bl
0x0043a658:	cmpl %eax, %edi
0x0043a65a:	jne 0x0043a628
0x0043a65c:	movl %edi, -8(%ebp)
0x0043a65f:	popl %esi
0x0043a660:	pushl %ebx
0x0043a661:	call 0x0043577a
0x0043a666:	popl %ecx
0x0043a667:	movl %eax, %edi
0x0043a669:	popl %edi
0x0043a66a:	popl %ebx
0x0043a66b:	movl %esp, %ebp
0x0043a66d:	popl %ebp
0x0043a66e:	ret

0x0043a701:	movl 0x40fa70(,%edi,4), %eax
0x0043a708:	testl %eax, %eax
0x0043a70a:	jne 0x0043a720
0x0043a720:	movl %eax, 0x40fc70
0x0043a725:	addl %eax, $0x40<UINT8>
0x0043a728:	movl 0x40fc70, %eax
0x0043a72d:	incl %edi
0x0043a72e:	jmp 0x0043a6eb
0x0043a712:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0043a719:	call 0x0043a733
0x0043a733:	pushl $0x7<UINT8>
0x0043a735:	call 0x004365bb
0x0043a73a:	popl %ecx
0x0043a73b:	ret

0x0043a71e:	jmp 0x0043a6cc
0x0043a6cc:	movl %eax, %esi
0x0043a6ce:	call 0x0042c9d6
0x0043a6d3:	ret

0x00436c3c:	popl %ecx
0x00436c3d:	testl %eax, %eax
0x00436c3f:	jne 15
0x00436c41:	call 0x00436aae
0x00436aae:	movl %edi, %edi
0x00436ab0:	pushl %ebp
0x00436ab1:	movl %ebp, %esp
0x00436ab3:	subl %esp, $0x48<UINT8>
0x00436ab6:	leal %eax, -72(%ebp)
0x00436ab9:	pushl %eax
0x00436aba:	call GetStartupInfoW@KERNEL32.DLL
GetStartupInfoW@KERNEL32.DLL: API Node	
0x00436ac0:	cmpw -22(%ebp), $0x0<UINT8>
0x00436ac5:	je 149
0x00436acb:	movl %eax, -20(%ebp)
0x00436ace:	testl %eax, %eax
0x00436ad0:	je 138
0x00436ad6:	pushl %ebx
0x00436ad7:	pushl %esi
0x00436ad8:	movl %esi, (%eax)
0x00436ada:	leal %ebx, 0x4(%eax)
0x00436add:	leal %eax, (%ebx,%esi)
0x00436ae0:	movl -4(%ebp), %eax
0x00436ae3:	movl %eax, $0x2000<UINT32>
0x00436ae8:	cmpl %esi, %eax
0x00436aea:	jl 0x00436aee
0x00436aee:	pushl %esi
0x00436aef:	call 0x0043a6a4
0x00436af4:	movl %eax, 0x40fc70
0x00436af9:	popl %ecx
0x00436afa:	cmpl %esi, %eax
0x00436afc:	jle 0x00436b00
0x00436b00:	pushl %edi
0x00436b01:	xorl %edi, %edi
0x00436b03:	testl %esi, %esi
0x00436b05:	je 0x00436b5d
0x00436b5d:	popl %edi
0x00436b5e:	popl %esi
0x00436b5f:	popl %ebx
0x00436b60:	movl %esp, %ebp
0x00436b62:	popl %ebp
0x00436b63:	ret

0x00436c46:	call 0x00436b64
0x00436b64:	movl %edi, %edi
0x00436b66:	pushl %ebx
0x00436b67:	pushl %esi
0x00436b68:	pushl %edi
0x00436b69:	xorl %edi, %edi
0x00436b6b:	movl %eax, %edi
0x00436b6d:	movl %ecx, %edi
0x00436b6f:	andl %eax, $0x3f<UINT8>
0x00436b72:	sarl %ecx, $0x6<UINT8>
0x00436b75:	imull %esi, %eax, $0x30<UINT8>
0x00436b78:	addl %esi, 0x40fa70(,%ecx,4)
0x00436b7f:	cmpl 0x18(%esi), $0xffffffff<UINT8>
0x00436b83:	je 0x00436b91
0x00436b91:	movl %eax, %edi
0x00436b93:	movb 0x28(%esi), $0xffffff81<UINT8>
0x00436b97:	subl %eax, $0x0<UINT8>
0x00436b9a:	je 0x00436bac
0x00436bac:	pushl $0xfffffff6<UINT8>
0x00436bae:	popl %eax
0x00436baf:	pushl %eax
0x00436bb0:	call GetStdHandle@KERNEL32.DLL
GetStdHandle@KERNEL32.DLL: API Node	
0x00436bb6:	movl %ebx, %eax
0x00436bb8:	cmpl %ebx, $0xffffffff<UINT8>
0x00436bbb:	je 13
0x00436bbd:	testl %ebx, %ebx
0x00436bbf:	je 9
0x00436bc1:	pushl %ebx
0x00436bc2:	call GetFileType@KERNEL32.DLL
GetFileType@KERNEL32.DLL: API Node	
0x00436bc8:	jmp 0x00436bcc
0x00436bcc:	testl %eax, %eax
0x00436bce:	je 30
0x00436bd0:	andl %eax, $0xff<UINT32>
0x00436bd5:	movl 0x18(%esi), %ebx
0x00436bd8:	cmpl %eax, $0x2<UINT8>
0x00436bdb:	jne 6
0x00436bdd:	orb 0x28(%esi), $0x40<UINT8>
0x00436be1:	jmp 0x00436c0c
0x00436c0c:	incl %edi
0x00436c0d:	cmpl %edi, $0x3<UINT8>
0x00436c10:	jne 0x00436b6b
0x00436b9c:	subl %eax, $0x1<UINT8>
0x00436b9f:	je 0x00436ba8
0x00436ba8:	pushl $0xfffffff5<UINT8>
0x00436baa:	jmp 0x00436bae
0x00436ba1:	pushl $0xfffffff4<UINT8>
0x00436ba3:	subl %eax, $0x1<UINT8>
0x00436ba6:	jmp 0x00436bae
0x00436c16:	popl %edi
0x00436c17:	popl %esi
0x00436c18:	popl %ebx
0x00436c19:	ret

0x00436c4b:	movb %bl, $0x1<UINT8>
0x00436c4d:	movb -25(%ebp), %bl
0x00436c50:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00436c57:	call 0x00436c67
0x00436c67:	pushl $0x7<UINT8>
0x00436c69:	call 0x004365bb
0x00436c6e:	popl %ecx
0x00436c6f:	ret

0x00436c5c:	movb %al, %bl
0x00436c5e:	call 0x0042c9d6
0x00436c63:	ret

0x00436c9c:	call GetCommandLineA@KERNEL32.DLL
GetCommandLineA@KERNEL32.DLL: API Node	
0x00436ca2:	movl 0x40fc80, %eax
0x00436ca7:	call GetCommandLineW@KERNEL32.DLL
GetCommandLineW@KERNEL32.DLL: API Node	
0x00436cad:	movl 0x40fc84, %eax
0x00436cb2:	movb %al, $0x1<UINT8>
0x00436cb4:	ret

0x0043718f:	cmpb 0x40fca8, $0x0<UINT8>
0x00437196:	jne 0x004371aa
0x00437198:	pushl $0x1<UINT8>
0x0043719a:	pushl $0xfffffffd<UINT8>
0x0043719c:	call 0x0043708e
0x0043708e:	movl %edi, %edi
0x00437090:	pushl %ebp
0x00437091:	movl %ebp, %esp
0x00437093:	subl %esp, $0xc<UINT8>
0x00437096:	call 0x0043695f
0x0043695f:	movl %edi, %edi
0x00436961:	pushl %esi
0x00436962:	pushl %edi
0x00436963:	call GetLastError@KERNEL32.DLL
0x00436969:	movl %esi, %eax
0x0043696b:	movl %eax, 0x410080
0x00436970:	cmpl %eax, $0xffffffff<UINT8>
0x00436973:	je 12
0x00436975:	pushl %eax
0x00436976:	call 0x004360d3
0x0043697b:	movl %edi, %eax
0x0043697d:	testl %edi, %edi
0x0043697f:	jne 0x004369ca
0x004369ca:	pushl %esi
0x004369cb:	call SetLastError@KERNEL32.DLL
0x004369d1:	movl %eax, %edi
0x004369d3:	popl %edi
0x004369d4:	popl %esi
0x004369d5:	ret

0x0043709b:	movl -4(%ebp), %eax
0x0043709e:	call 0x004371ad
0x004371ad:	pushl $0xc<UINT8>
0x004371af:	pushl $0x4432a8<UINT32>
0x004371b4:	call 0x0042c990
0x004371b9:	xorl %esi, %esi
0x004371bb:	movl -28(%ebp), %esi
0x004371be:	call 0x0043695f
0x004371c3:	movl %edi, %eax
0x004371c5:	movl %ecx, 0x4107c0
0x004371cb:	testl 0x350(%edi), %ecx
0x004371d1:	je 0x004371e4
0x004371e4:	pushl $0x5<UINT8>
0x004371e6:	call 0x00436573
0x004371eb:	popl %ecx
0x004371ec:	movl -4(%ebp), %esi
0x004371ef:	movl %esi, 0x48(%edi)
0x004371f2:	movl -28(%ebp), %esi
0x004371f5:	cmpl %esi, 0x4105d8
0x004371fb:	je 0x0043722d
0x0043722d:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00437234:	call 0x0043723e
0x0043723e:	pushl $0x5<UINT8>
0x00437240:	call 0x004365bb
0x00437245:	popl %ecx
0x00437246:	ret

0x00437239:	jmp 0x004371db
0x004371db:	testl %esi, %esi
0x004371dd:	jne 0x00437247
0x00437247:	movl %eax, %esi
0x00437249:	call 0x0042c9d6
0x0043724e:	ret

0x004370a3:	pushl 0x8(%ebp)
0x004370a6:	call 0x00436e22
0x00436e22:	movl %edi, %edi
0x00436e24:	pushl %ebp
0x00436e25:	movl %ebp, %esp
0x00436e27:	subl %esp, $0x10<UINT8>
0x00436e2a:	leal %ecx, -16(%ebp)
0x00436e2d:	pushl $0x0<UINT8>
0x00436e2f:	call 0x004300bd
0x004300bd:	movl %edi, %edi
0x004300bf:	pushl %ebp
0x004300c0:	movl %ebp, %esp
0x004300c2:	pushl %edi
0x004300c3:	movl %edi, %ecx
0x004300c5:	movl %ecx, 0x8(%ebp)
0x004300c8:	movb 0xc(%edi), $0x0<UINT8>
0x004300cc:	testl %ecx, %ecx
0x004300ce:	je 0x004300da
0x004300da:	movl %eax, 0x40f65c
0x004300df:	testl %eax, %eax
0x004300e1:	jne 18
0x004300e3:	movl %eax, 0x410698
0x004300e8:	movl 0x4(%edi), %eax
0x004300eb:	movl %eax, 0x41069c
0x004300f0:	movl 0x8(%edi), %eax
0x004300f3:	jmp 0x00430139
0x00430139:	movl %eax, %edi
0x0043013b:	popl %edi
0x0043013c:	popl %ebp
0x0043013d:	ret $0x4<UINT16>

0x00436e34:	andl 0x40fca4, $0x0<UINT8>
0x00436e3b:	movl %eax, 0x8(%ebp)
0x00436e3e:	cmpl %eax, $0xfffffffe<UINT8>
0x00436e41:	jne 0x00436e55
0x00436e55:	cmpl %eax, $0xfffffffd<UINT8>
0x00436e58:	jne 0x00436e6c
0x00436e5a:	movl 0x40fca4, $0x1<UINT32>
0x00436e64:	call GetACP@KERNEL32.DLL
GetACP@KERNEL32.DLL: API Node	
0x00436e6a:	jmp 0x00436e81
0x00436e81:	cmpb -4(%ebp), $0x0<UINT8>
0x00436e85:	je 0x00436e91
0x00436e91:	movl %esp, %ebp
0x00436e93:	popl %ebp
0x00436e94:	ret

0x004370ab:	popl %ecx
0x004370ac:	movl %ecx, -4(%ebp)
0x004370af:	movl -12(%ebp), %eax
0x004370b2:	movl %ecx, 0x48(%ecx)
0x004370b5:	cmpl %eax, 0x4(%ecx)
0x004370b8:	jne 0x004370be
0x004370be:	pushl %ebx
0x004370bf:	pushl %esi
0x004370c0:	pushl %edi
0x004370c1:	pushl $0x220<UINT32>
0x004370c6:	call 0x004357b4
0x004357b4:	movl %edi, %edi
0x004357b6:	pushl %ebp
0x004357b7:	movl %ebp, %esp
0x004357b9:	pushl %esi
0x004357ba:	movl %esi, 0x8(%ebp)
0x004357bd:	cmpl %esi, $0xffffffe0<UINT8>
0x004357c0:	ja 48
0x004357c2:	testl %esi, %esi
0x004357c4:	jne 0x004357dd
0x004357dd:	pushl %esi
0x004357de:	pushl $0x0<UINT8>
0x004357e0:	pushl 0x40fa6c
0x004357e6:	call HeapAlloc@KERNEL32.DLL
0x004357ec:	testl %eax, %eax
0x004357ee:	je -39
0x004357f0:	jmp 0x004357ff
0x004357ff:	popl %esi
0x00435800:	popl %ebp
0x00435801:	ret

0x004370cb:	movl %edi, %eax
0x004370cd:	orl %ebx, $0xffffffff<UINT8>
0x004370d0:	popl %ecx
0x004370d1:	testl %edi, %edi
0x004370d3:	je 46
0x004370d5:	movl %esi, -4(%ebp)
0x004370d8:	movl %ecx, $0x88<UINT32>
0x004370dd:	movl %esi, 0x48(%esi)
0x004370e0:	rep movsl %es:(%edi), %ds:(%esi)
0x004370e2:	movl %edi, %eax
0x004370e4:	pushl %edi
0x004370e5:	pushl -12(%ebp)
0x004370e8:	andl (%edi), $0x0<UINT8>
0x004370eb:	call 0x0043724f
0x0043724f:	movl %edi, %edi
0x00437251:	pushl %ebp
0x00437252:	movl %ebp, %esp
0x00437254:	subl %esp, $0x20<UINT8>
0x00437257:	movl %eax, 0x410030
0x0043725c:	xorl %eax, %ebp
0x0043725e:	movl -4(%ebp), %eax
0x00437261:	pushl %ebx
0x00437262:	pushl %esi
0x00437263:	pushl 0x8(%ebp)
0x00437266:	movl %esi, 0xc(%ebp)
0x00437269:	call 0x00436e22
0x00436e6c:	cmpl %eax, $0xfffffffc<UINT8>
0x00436e6f:	jne 0x00436e81
0x0043726e:	movl %ebx, %eax
0x00437270:	popl %ecx
0x00437271:	testl %ebx, %ebx
0x00437273:	jne 0x00437283
0x00437283:	pushl %edi
0x00437284:	xorl %edi, %edi
0x00437286:	movl %ecx, %edi
0x00437288:	movl %eax, %edi
0x0043728a:	movl -28(%ebp), %ecx
0x0043728d:	cmpl 0x4100c0(%eax), %ebx
0x00437293:	je 234
0x00437299:	incl %ecx
0x0043729a:	addl %eax, $0x30<UINT8>
0x0043729d:	movl -28(%ebp), %ecx
0x004372a0:	cmpl %eax, $0xf0<UINT32>
0x004372a5:	jb 0x0043728d
0x004372a7:	cmpl %ebx, $0xfde8<UINT32>
0x004372ad:	je 200
0x004372b3:	cmpl %ebx, $0xfde9<UINT32>
0x004372b9:	je 188
0x004372bf:	movzwl %eax, %bx
0x004372c2:	pushl %eax
0x004372c3:	call IsValidCodePage@KERNEL32.DLL
IsValidCodePage@KERNEL32.DLL: API Node	
0x004372c9:	testl %eax, %eax
0x004372cb:	je 170
0x004372d1:	leal %eax, -24(%ebp)
0x004372d4:	pushl %eax
0x004372d5:	pushl %ebx
0x004372d6:	call GetCPInfo@KERNEL32.DLL
GetCPInfo@KERNEL32.DLL: API Node	
0x004372dc:	testl %eax, %eax
0x004372de:	je 132
0x004372e4:	pushl $0x101<UINT32>
0x004372e9:	leal %eax, 0x18(%esi)
0x004372ec:	pushl %edi
0x004372ed:	pushl %eax
0x004372ee:	call 0x0042f0c0
0x0042f0c0:	movl %ecx, 0xc(%esp)
0x0042f0c4:	movzbl %eax, 0x8(%esp)
0x0042f0c9:	movl %edx, %edi
0x0042f0cb:	movl %edi, 0x4(%esp)
0x0042f0cf:	testl %ecx, %ecx
0x0042f0d1:	je 316
0x0042f0d7:	imull %eax, %eax, $0x1010101<UINT32>
0x0042f0dd:	cmpl %ecx, $0x20<UINT8>
0x0042f0e0:	jle 223
0x0042f0e6:	cmpl %ecx, $0x80<UINT32>
0x0042f0ec:	jl 0x0042f17d
0x0042f0f2:	btl 0x40f63c, $0x1<UINT8>
0x0042f0fa:	jae 0x0042f105
0x0042f105:	btl 0x410050, $0x1<UINT8>
0x0042f10d:	jae 178
0x0042f113:	movd %xmm0, %eax
0x0042f117:	pshufd %xmm0, %xmm0, $0x0<UINT8>
0x0042f11c:	addl %ecx, %edi
0x0042f11e:	movups (%edi), %xmm0
0x0042f121:	addl %edi, $0x10<UINT8>
0x0042f124:	andl %edi, $0xfffffff0<UINT8>
0x0042f127:	subl %ecx, %edi
0x0042f129:	cmpl %ecx, $0x80<UINT32>
0x0042f12f:	jle 0x0042f17d
0x0042f131:	leal %esp, (%esp)
0x0042f138:	leal %esp, (%esp)
0x0042f13f:	nop
0x0042f140:	movdqa (%edi), %xmm0
0x0042f144:	movdqa 0x10(%edi), %xmm0
0x0042f149:	movdqa 0x20(%edi), %xmm0
0x0042f14e:	movdqa 0x30(%edi), %xmm0
0x0042f153:	movdqa 0x40(%edi), %xmm0
0x0042f158:	movdqa 0x50(%edi), %xmm0
0x0042f15d:	movdqa 0x60(%edi), %xmm0
0x0042f162:	movdqa 0x70(%edi), %xmm0
0x0042f167:	leal %edi, 0x80(%edi)
0x0042f16d:	subl %ecx, $0x80<UINT32>
0x0042f173:	testl %ecx, $0xffffff00<UINT32>
0x0042f179:	jne 0x0042f140
0x0042f17b:	jmp 0x0042f190
0x0042f190:	cmpl %ecx, $0x20<UINT8>
0x0042f193:	jb 28
0x0042f195:	movdqu (%edi), %xmm0
0x0042f199:	movdqu 0x10(%edi), %xmm0
0x0042f19e:	addl %edi, $0x20<UINT8>
0x0042f1a1:	subl %ecx, $0x20<UINT8>
0x0042f1a4:	cmpl %ecx, $0x20<UINT8>
0x0042f1a7:	jae 0x0042f195
0x0042f1a9:	testl %ecx, $0x1f<UINT32>
0x0042f1af:	je 98
0x0042f1b1:	leal %edi, -32(%ecx,%edi)
0x0042f1b5:	movdqu (%edi), %xmm0
0x0042f1b9:	movdqu 0x10(%edi), %xmm0
0x0042f1be:	movl %eax, 0x4(%esp)
0x0042f1c2:	movl %edi, %edx
0x0042f1c4:	ret

0x004372f3:	movl 0x4(%esi), %ebx
0x004372f6:	addl %esp, $0xc<UINT8>
0x004372f9:	xorl %ebx, %ebx
0x004372fb:	movl 0x21c(%esi), %edi
0x00437301:	incl %ebx
0x00437302:	cmpl -24(%ebp), %ebx
0x00437305:	jbe 81
0x00437307:	cmpb -18(%ebp), $0x0<UINT8>
0x0043730b:	leal %eax, -18(%ebp)
0x0043730e:	je 0x00437331
0x00437331:	leal %eax, 0x1a(%esi)
0x00437334:	movl %ecx, $0xfe<UINT32>
0x00437339:	orb (%eax), $0x8<UINT8>
0x0043733c:	incl %eax
0x0043733d:	subl %ecx, $0x1<UINT8>
0x00437340:	jne 0x00437339
0x00437342:	pushl 0x4(%esi)
0x00437345:	call 0x00436de4
0x00436de4:	movl %edi, %edi
0x00436de6:	pushl %ebp
0x00436de7:	movl %ebp, %esp
0x00436de9:	movl %eax, 0x8(%ebp)
0x00436dec:	subl %eax, $0x3a4<UINT32>
0x00436df1:	je 40
0x00436df3:	subl %eax, $0x4<UINT8>
0x00436df6:	je 28
0x00436df8:	subl %eax, $0xd<UINT8>
0x00436dfb:	je 16
0x00436dfd:	subl %eax, $0x1<UINT8>
0x00436e00:	je 4
0x00436e02:	xorl %eax, %eax
0x00436e04:	popl %ebp
0x00436e05:	ret

0x0043734a:	addl %esp, $0x4<UINT8>
0x0043734d:	movl 0x21c(%esi), %eax
0x00437353:	movl 0x8(%esi), %ebx
0x00437356:	jmp 0x0043735b
0x0043735b:	xorl %eax, %eax
0x0043735d:	leal %edi, 0xc(%esi)
0x00437360:	stosl %es:(%edi), %eax
0x00437361:	stosl %es:(%edi), %eax
0x00437362:	stosl %es:(%edi), %eax
0x00437363:	jmp 0x00437426
0x00437426:	pushl %esi
0x00437427:	call 0x00436efa
0x00436efa:	movl %edi, %edi
0x00436efc:	pushl %ebp
0x00436efd:	movl %ebp, %esp
0x00436eff:	subl %esp, $0x720<UINT32>
0x00436f05:	movl %eax, 0x410030
0x00436f0a:	xorl %eax, %ebp
0x00436f0c:	movl -4(%ebp), %eax
0x00436f0f:	pushl %ebx
0x00436f10:	pushl %esi
0x00436f11:	movl %esi, 0x8(%ebp)
0x00436f14:	leal %eax, -1816(%ebp)
0x00436f1a:	pushl %edi
0x00436f1b:	pushl %eax
0x00436f1c:	pushl 0x4(%esi)
0x00436f1f:	call GetCPInfo@KERNEL32.DLL
0x00436f25:	xorl %ebx, %ebx
0x00436f27:	movl %edi, $0x100<UINT32>
0x00436f2c:	testl %eax, %eax
0x00436f2e:	je 240
0x00436f34:	movl %eax, %ebx
0x00436f36:	movb -260(%ebp,%eax), %al
0x00436f3d:	incl %eax
0x00436f3e:	cmpl %eax, %edi
0x00436f40:	jb 0x00436f36
0x00436f42:	movb %al, -1810(%ebp)
0x00436f48:	leal %ecx, -1810(%ebp)
0x00436f4e:	movb -260(%ebp), $0x20<UINT8>
0x00436f55:	jmp 0x00436f76
0x00436f76:	testb %al, %al
0x00436f78:	jne -35
0x00436f7a:	pushl %ebx
0x00436f7b:	pushl 0x4(%esi)
0x00436f7e:	leal %eax, -1796(%ebp)
0x00436f84:	pushl %eax
0x00436f85:	pushl %edi
0x00436f86:	leal %eax, -260(%ebp)
0x00436f8c:	pushl %eax
0x00436f8d:	pushl $0x1<UINT8>
0x00436f8f:	pushl %ebx
0x00436f90:	call 0x0043946d
0x0043946d:	movl %edi, %edi
0x0043946f:	pushl %ebp
0x00439470:	movl %ebp, %esp
0x00439472:	subl %esp, $0x18<UINT8>
0x00439475:	movl %eax, 0x410030
0x0043947a:	xorl %eax, %ebp
0x0043947c:	movl -4(%ebp), %eax
0x0043947f:	pushl %ebx
0x00439480:	pushl %esi
0x00439481:	pushl %edi
0x00439482:	pushl 0x8(%ebp)
0x00439485:	leal %ecx, -24(%ebp)
0x00439488:	call 0x004300bd
0x0043948d:	movl %ecx, 0x1c(%ebp)
0x00439490:	testl %ecx, %ecx
0x00439492:	jne 0x0043949f
0x0043949f:	xorl %eax, %eax
0x004394a1:	xorl %edi, %edi
0x004394a3:	cmpl 0x20(%ebp), %eax
0x004394a6:	pushl %edi
0x004394a7:	pushl %edi
0x004394a8:	pushl 0x14(%ebp)
0x004394ab:	setne %al
0x004394ae:	pushl 0x10(%ebp)
0x004394b1:	leal %eax, 0x1(,%eax,8)
0x004394b8:	pushl %eax
0x004394b9:	pushl %ecx
0x004394ba:	call MultiByteToWideChar@KERNEL32.DLL
MultiByteToWideChar@KERNEL32.DLL: API Node	
0x004394c0:	movl -8(%ebp), %eax
0x004394c3:	testl %eax, %eax
0x004394c5:	je 153
0x004394cb:	leal %ebx, (%eax,%eax)
0x004394ce:	leal %ecx, 0x8(%ebx)
0x004394d1:	cmpl %ebx, %ecx
0x004394d3:	sbbl %eax, %eax
0x004394d5:	testl %ecx, %eax
0x004394d7:	je 74
0x004394d9:	leal %ecx, 0x8(%ebx)
0x004394dc:	cmpl %ebx, %ecx
0x004394de:	sbbl %eax, %eax
0x004394e0:	andl %eax, %ecx
0x004394e2:	leal %ecx, 0x8(%ebx)
0x004394e5:	cmpl %eax, $0x400<UINT32>
0x004394ea:	ja 25
0x004394ec:	cmpl %ebx, %ecx
0x004394ee:	sbbl %eax, %eax
0x004394f0:	andl %eax, %ecx
0x004394f2:	call 0x0043f4d0
0x0043f4d0:	pushl %ecx
0x0043f4d1:	leal %ecx, 0x8(%esp)
0x0043f4d5:	subl %ecx, %eax
0x0043f4d7:	andl %ecx, $0xf<UINT8>
0x0043f4da:	addl %eax, %ecx
0x0043f4dc:	sbbl %ecx, %ecx
0x0043f4de:	orl %eax, %ecx
0x0043f4e0:	popl %ecx
0x0043f4e1:	jmp 0x0042c030
0x0042c030:	pushl %ecx
0x0042c031:	leal %ecx, 0x4(%esp)
0x0042c035:	subl %ecx, %eax
0x0042c037:	sbbl %eax, %eax
0x0042c039:	notl %eax
0x0042c03b:	andl %ecx, %eax
0x0042c03d:	movl %eax, %esp
0x0042c03f:	andl %eax, $0xfffff000<UINT32>
0x0042c044:	cmpl %ecx, %eax
0x0042c046:	repn jb 11
0x0042c049:	movl %eax, %ecx
0x0042c04b:	popl %ecx
0x0042c04c:	xchgl %esp, %eax
0x0042c04d:	movl %eax, (%eax)
0x0042c04f:	movl (%esp), %eax
0x0042c052:	repn ret

0x004394f7:	movl %esi, %esp
0x004394f9:	testl %esi, %esi
0x004394fb:	je 96
0x004394fd:	movl (%esi), $0xcccc<UINT32>
0x00439503:	jmp 0x0043951e
0x0043951e:	addl %esi, $0x8<UINT8>
0x00439521:	jmp 0x00439525
0x00439525:	testl %esi, %esi
0x00439527:	je 52
0x00439529:	pushl %ebx
0x0043952a:	pushl %edi
0x0043952b:	pushl %esi
0x0043952c:	call 0x0042f0c0
0x00439531:	addl %esp, $0xc<UINT8>
0x00439534:	pushl -8(%ebp)
0x00439537:	pushl %esi
0x00439538:	pushl 0x14(%ebp)
0x0043953b:	pushl 0x10(%ebp)
0x0043953e:	pushl $0x1<UINT8>
0x00439540:	pushl 0x1c(%ebp)
0x00439543:	call MultiByteToWideChar@KERNEL32.DLL
0x00439549:	testl %eax, %eax
0x0043954b:	je 16
0x0043954d:	pushl 0x18(%ebp)
0x00439550:	pushl %eax
0x00439551:	pushl %esi
0x00439552:	pushl 0xc(%ebp)
0x00439555:	call GetStringTypeW@KERNEL32.DLL
GetStringTypeW@KERNEL32.DLL: API Node	
0x0043955b:	movl %edi, %eax
0x0043955d:	pushl %esi
0x0043955e:	call 0x0043958a
0x0043958a:	movl %edi, %edi
0x0043958c:	pushl %ebp
0x0043958d:	movl %ebp, %esp
0x0043958f:	movl %eax, 0x8(%ebp)
0x00439592:	testl %eax, %eax
0x00439594:	je 0x004395a8
0x00439596:	subl %eax, $0x8<UINT8>
0x00439599:	cmpl (%eax), $0xdddd<UINT32>
0x0043959f:	jne 0x004395a8
0x004395a8:	popl %ebp
0x004395a9:	ret

0x00439563:	popl %ecx
0x00439564:	cmpb -12(%ebp), $0x0<UINT8>
0x00439568:	je 0x00439574
0x00439574:	movl %eax, %edi
0x00439576:	leal %esp, -36(%ebp)
0x00439579:	popl %edi
0x0043957a:	popl %esi
0x0043957b:	popl %ebx
0x0043957c:	movl %ecx, -4(%ebp)
0x0043957f:	xorl %ecx, %ebp
0x00439581:	call 0x0042c018
0x00439586:	movl %esp, %ebp
0x00439588:	popl %ebp
0x00439589:	ret

0x00436f95:	pushl %ebx
0x00436f96:	pushl 0x4(%esi)
0x00436f99:	leal %eax, -516(%ebp)
0x00436f9f:	pushl %edi
0x00436fa0:	pushl %eax
0x00436fa1:	pushl %edi
0x00436fa2:	leal %eax, -260(%ebp)
0x00436fa8:	pushl %eax
0x00436fa9:	pushl %edi
0x00436faa:	pushl 0x21c(%esi)
0x00436fb0:	pushl %ebx
0x00436fb1:	call 0x0043d641
0x0043d641:	movl %edi, %edi
0x0043d643:	pushl %ebp
0x0043d644:	movl %ebp, %esp
0x0043d646:	subl %esp, $0x10<UINT8>
0x0043d649:	pushl 0x8(%ebp)
0x0043d64c:	leal %ecx, -16(%ebp)
0x0043d64f:	call 0x004300bd
0x0043d654:	pushl 0x28(%ebp)
0x0043d657:	leal %eax, -12(%ebp)
0x0043d65a:	pushl 0x24(%ebp)
0x0043d65d:	pushl 0x20(%ebp)
0x0043d660:	pushl 0x1c(%ebp)
0x0043d663:	pushl 0x18(%ebp)
0x0043d666:	pushl 0x14(%ebp)
0x0043d669:	pushl 0x10(%ebp)
0x0043d66c:	pushl 0xc(%ebp)
0x0043d66f:	pushl %eax
0x0043d670:	call 0x0043d424
0x0043d424:	movl %edi, %edi
0x0043d426:	pushl %ebp
0x0043d427:	movl %ebp, %esp
0x0043d429:	pushl %ecx
0x0043d42a:	pushl %ecx
0x0043d42b:	movl %eax, 0x410030
0x0043d430:	xorl %eax, %ebp
0x0043d432:	movl -4(%ebp), %eax
0x0043d435:	pushl %ebx
0x0043d436:	pushl %esi
0x0043d437:	movl %esi, 0x18(%ebp)
0x0043d43a:	pushl %edi
0x0043d43b:	testl %esi, %esi
0x0043d43d:	jle 20
0x0043d43f:	pushl %esi
0x0043d440:	pushl 0x14(%ebp)
0x0043d443:	call 0x00440884
0x00440884:	movl %edi, %edi
0x00440886:	pushl %ebp
0x00440887:	movl %ebp, %esp
0x00440889:	movl %ecx, 0x8(%ebp)
0x0044088c:	xorl %eax, %eax
0x0044088e:	cmpb (%ecx), %al
0x00440890:	je 12
0x00440892:	cmpl %eax, 0xc(%ebp)
0x00440895:	je 0x0044089e
0x00440897:	incl %eax
0x00440898:	cmpb (%eax,%ecx), $0x0<UINT8>
0x0044089c:	jne 0x00440892
0x0044089e:	popl %ebp
0x0044089f:	ret

0x0043d448:	popl %ecx
0x0043d449:	cmpl %eax, %esi
0x0043d44b:	popl %ecx
0x0043d44c:	leal %esi, 0x1(%eax)
0x0043d44f:	jl 2
0x0043d451:	movl %esi, %eax
0x0043d453:	movl %edi, 0x24(%ebp)
0x0043d456:	testl %edi, %edi
0x0043d458:	jne 0x0043d465
0x0043d465:	xorl %eax, %eax
0x0043d467:	cmpl 0x28(%ebp), %eax
0x0043d46a:	pushl $0x0<UINT8>
0x0043d46c:	pushl $0x0<UINT8>
0x0043d46e:	pushl %esi
0x0043d46f:	pushl 0x14(%ebp)
0x0043d472:	setne %al
0x0043d475:	leal %eax, 0x1(,%eax,8)
0x0043d47c:	pushl %eax
0x0043d47d:	pushl %edi
0x0043d47e:	call MultiByteToWideChar@KERNEL32.DLL
0x0043d484:	movl -8(%ebp), %eax
0x0043d487:	testl %eax, %eax
0x0043d489:	je 397
0x0043d48f:	leal %edx, (%eax,%eax)
0x0043d492:	leal %ecx, 0x8(%edx)
0x0043d495:	cmpl %edx, %ecx
0x0043d497:	sbbl %eax, %eax
0x0043d499:	testl %ecx, %eax
0x0043d49b:	je 82
0x0043d49d:	leal %ecx, 0x8(%edx)
0x0043d4a0:	cmpl %edx, %ecx
0x0043d4a2:	sbbl %eax, %eax
0x0043d4a4:	andl %eax, %ecx
0x0043d4a6:	leal %ecx, 0x8(%edx)
0x0043d4a9:	cmpl %eax, $0x400<UINT32>
0x0043d4ae:	ja 29
0x0043d4b0:	cmpl %edx, %ecx
0x0043d4b2:	sbbl %eax, %eax
0x0043d4b4:	andl %eax, %ecx
0x0043d4b6:	call 0x0043f4d0
0x0043d4bb:	movl %ebx, %esp
0x0043d4bd:	testl %ebx, %ebx
0x0043d4bf:	je 332
0x0043d4c5:	movl (%ebx), $0xcccc<UINT32>
0x0043d4cb:	jmp 0x0043d4ea
0x0043d4ea:	addl %ebx, $0x8<UINT8>
0x0043d4ed:	jmp 0x0043d4f1
0x0043d4f1:	testl %ebx, %ebx
0x0043d4f3:	je 280
0x0043d4f9:	pushl -8(%ebp)
0x0043d4fc:	pushl %ebx
0x0043d4fd:	pushl %esi
0x0043d4fe:	pushl 0x14(%ebp)
0x0043d501:	pushl $0x1<UINT8>
0x0043d503:	pushl %edi
0x0043d504:	call MultiByteToWideChar@KERNEL32.DLL
0x0043d50a:	testl %eax, %eax
0x0043d50c:	je 255
0x0043d512:	movl %edi, -8(%ebp)
0x0043d515:	xorl %eax, %eax
0x0043d517:	pushl %eax
0x0043d518:	pushl %eax
0x0043d519:	pushl %eax
0x0043d51a:	pushl %eax
0x0043d51b:	pushl %eax
0x0043d51c:	pushl %edi
0x0043d51d:	pushl %ebx
0x0043d51e:	pushl 0x10(%ebp)
0x0043d521:	pushl 0xc(%ebp)
0x0043d524:	call 0x004361e4
0x004361e4:	movl %edi, %edi
0x004361e6:	pushl %ebp
0x004361e7:	movl %ebp, %esp
0x004361e9:	pushl %ecx
0x004361ea:	movl %eax, 0x410030
0x004361ef:	xorl %eax, %ebp
0x004361f1:	movl -4(%ebp), %eax
0x004361f4:	pushl %esi
0x004361f5:	pushl $0x409fc8<UINT32>
0x004361fa:	pushl $0x409fc0<UINT32>
0x004361ff:	pushl $0x409fc8<UINT32>
0x00436204:	pushl $0x16<UINT8>
0x00436206:	call 0x00435ec2
0x0043620b:	movl %esi, %eax
0x0043620d:	addl %esp, $0x10<UINT8>
0x00436210:	testl %esi, %esi
0x00436212:	je 39
0x00436214:	pushl 0x28(%ebp)
0x00436217:	movl %ecx, %esi
0x00436219:	pushl 0x24(%ebp)
0x0043621c:	pushl 0x20(%ebp)
0x0043621f:	pushl 0x1c(%ebp)
0x00436222:	pushl 0x18(%ebp)
0x00436225:	pushl 0x14(%ebp)
0x00436228:	pushl 0x10(%ebp)
0x0043622b:	pushl 0xc(%ebp)
0x0043622e:	pushl 0x8(%ebp)
0x00436231:	call 0x0042c70e
0x00436237:	call LCMapStringEx@kernel32.dll
LCMapStringEx@kernel32.dll: API Node	
0x00436239:	jmp 0x0043625b
0x0043625b:	movl %ecx, -4(%ebp)
0x0043625e:	xorl %ecx, %ebp
0x00436260:	popl %esi
0x00436261:	call 0x0042c018
0x00436266:	movl %esp, %ebp
0x00436268:	popl %ebp
0x00436269:	ret $0x24<UINT16>

0x0043d529:	movl %esi, %eax
0x0043d52b:	testl %esi, %esi
0x0043d52d:	je 0x0043d611
0x0043d533:	testl 0x10(%ebp), $0x400<UINT32>
0x0043d611:	xorl %esi, %esi
0x0043d613:	pushl %ebx
0x0043d614:	call 0x0043958a
0x0043d619:	popl %ecx
0x0043d61a:	movl %eax, %esi
0x0043d61c:	leal %esp, -20(%ebp)
0x0043d61f:	popl %edi
0x0043d620:	popl %esi
0x0043d621:	popl %ebx
0x0043d622:	movl %ecx, -4(%ebp)
0x0043d625:	xorl %ecx, %ebp
0x0043d627:	call 0x0042c018
0x0043d62c:	movl %esp, %ebp
0x0043d62e:	popl %ebp
0x0043d62f:	ret

0x0043d675:	addl %esp, $0x24<UINT8>
0x0043d678:	cmpb -4(%ebp), $0x0<UINT8>
0x0043d67c:	je 0x0043d688
0x0043d688:	movl %esp, %ebp
0x0043d68a:	popl %ebp
0x0043d68b:	ret

0x00436fb6:	addl %esp, $0x40<UINT8>
0x00436fb9:	leal %eax, -772(%ebp)
0x00436fbf:	pushl %ebx
0x00436fc0:	pushl 0x4(%esi)
0x00436fc3:	pushl %edi
0x00436fc4:	pushl %eax
0x00436fc5:	pushl %edi
0x00436fc6:	leal %eax, -260(%ebp)
0x00436fcc:	pushl %eax
0x00436fcd:	pushl $0x200<UINT32>
0x00436fd2:	pushl 0x21c(%esi)
0x00436fd8:	pushl %ebx
0x00436fd9:	call 0x0043d641
0x00436fde:	addl %esp, $0x24<UINT8>
0x00436fe1:	movl %ecx, %ebx
0x00436fe3:	movzwl %eax, -1796(%ebp,%ecx,2)
0x00436feb:	testb %al, $0x1<UINT8>
0x00436fed:	je 0x00436ffd
0x00436ffd:	testb %al, $0x2<UINT8>
0x00436fff:	je 0x00437016
0x00437016:	movb 0x119(%esi,%ecx), %bl
0x0043701d:	incl %ecx
0x0043701e:	cmpl %ecx, %edi
0x00437020:	jb 0x00436fe3
0x00436fef:	orb 0x19(%esi,%ecx), $0x10<UINT8>
0x00436ff4:	movb %al, -516(%ebp,%ecx)
0x00436ffb:	jmp 0x0043700d
0x0043700d:	movb 0x119(%esi,%ecx), %al
0x00437014:	jmp 0x0043701d
0x00437001:	orb 0x19(%esi,%ecx), $0x20<UINT8>
0x00437006:	movb %al, -772(%ebp,%ecx)
0x00437022:	jmp 0x0043707d
0x0043707d:	movl %ecx, -4(%ebp)
0x00437080:	popl %edi
0x00437081:	popl %esi
0x00437082:	xorl %ecx, %ebp
0x00437084:	popl %ebx
0x00437085:	call 0x0042c018
0x0043708a:	movl %esp, %ebp
0x0043708c:	popl %ebp
0x0043708d:	ret

0x0043742c:	popl %ecx
0x0043742d:	xorl %eax, %eax
0x0043742f:	popl %edi
0x00437430:	movl %ecx, -4(%ebp)
0x00437433:	popl %esi
0x00437434:	xorl %ecx, %ebp
0x00437436:	popl %ebx
0x00437437:	call 0x0042c018
0x0043743c:	movl %esp, %ebp
0x0043743e:	popl %ebp
0x0043743f:	ret

0x004370f0:	movl %esi, %eax
0x004370f2:	popl %ecx
0x004370f3:	popl %ecx
0x004370f4:	cmpl %esi, %ebx
0x004370f6:	jne 0x00437115
0x00437115:	cmpb 0xc(%ebp), $0x0<UINT8>
0x00437119:	jne 0x00437120
0x00437120:	movl %eax, -4(%ebp)
0x00437123:	movl %eax, 0x48(%eax)
0x00437126:	xaddl (%eax), %ebx
0x0043712a:	decl %ebx
0x0043712b:	jne 21
0x0043712d:	movl %eax, -4(%ebp)
0x00437130:	cmpl 0x48(%eax), $0x4103b8<UINT32>
0x00437137:	je 0x00437142
0x00437142:	movl (%edi), $0x1<UINT32>
0x00437148:	movl %ecx, %edi
0x0043714a:	movl %eax, -4(%ebp)
0x0043714d:	xorl %edi, %edi
0x0043714f:	movl 0x48(%eax), %ecx
0x00437152:	movl %eax, -4(%ebp)
0x00437155:	testb 0x350(%eax), $0x2<UINT8>
0x0043715c:	jne -89
0x0043715e:	testb 0x4107c0, $0x1<UINT8>
0x00437165:	jne -98
0x00437167:	leal %eax, -4(%ebp)
0x0043716a:	movl -12(%ebp), %eax
0x0043716d:	leal %eax, -12(%ebp)
0x00437170:	pushl %eax
0x00437171:	pushl $0x5<UINT8>
0x00437173:	call 0x00436cf8
0x00436cf8:	movl %edi, %edi
0x00436cfa:	pushl %ebp
0x00436cfb:	movl %ebp, %esp
0x00436cfd:	subl %esp, $0xc<UINT8>
0x00436d00:	movl %eax, 0x8(%ebp)
0x00436d03:	leal %ecx, -1(%ebp)
0x00436d06:	movl -8(%ebp), %eax
0x00436d09:	movl -12(%ebp), %eax
0x00436d0c:	leal %eax, -8(%ebp)
0x00436d0f:	pushl %eax
0x00436d10:	pushl 0xc(%ebp)
0x00436d13:	leal %eax, -12(%ebp)
0x00436d16:	pushl %eax
0x00436d17:	call 0x00436cb5
0x00436cb5:	pushl $0x8<UINT8>
0x00436cb7:	pushl $0x4432c8<UINT32>
0x00436cbc:	call 0x0042c990
0x00436cc1:	movl %eax, 0x8(%ebp)
0x00436cc4:	pushl (%eax)
0x00436cc6:	call 0x00436573
0x00436ccb:	popl %ecx
0x00436ccc:	andl -4(%ebp), $0x0<UINT8>
0x00436cd0:	movl %ecx, 0xc(%ebp)
0x00436cd3:	call 0x00436d20
0x00436d20:	movl %edi, %edi
0x00436d22:	pushl %esi
0x00436d23:	movl %esi, %ecx
0x00436d25:	pushl $0xc<UINT8>
0x00436d27:	movl %eax, (%esi)
0x00436d29:	movl %eax, (%eax)
0x00436d2b:	movl %eax, 0x48(%eax)
0x00436d2e:	movl %eax, 0x4(%eax)
0x00436d31:	movl 0x40fc90, %eax
0x00436d36:	movl %eax, (%esi)
0x00436d38:	movl %eax, (%eax)
0x00436d3a:	movl %eax, 0x48(%eax)
0x00436d3d:	movl %eax, 0x8(%eax)
0x00436d40:	movl 0x40fc94, %eax
0x00436d45:	movl %eax, (%esi)
0x00436d47:	movl %eax, (%eax)
0x00436d49:	movl %eax, 0x48(%eax)
0x00436d4c:	movl %eax, 0x21c(%eax)
0x00436d52:	movl 0x40fc8c, %eax
0x00436d57:	movl %eax, (%esi)
0x00436d59:	movl %eax, (%eax)
0x00436d5b:	movl %eax, 0x48(%eax)
0x00436d5e:	addl %eax, $0xc<UINT8>
0x00436d61:	pushl %eax
0x00436d62:	pushl $0xc<UINT8>
0x00436d64:	pushl $0x40fc98<UINT32>
0x00436d69:	call 0x00437440
0x00437440:	movl %edi, %edi
0x00437442:	pushl %ebp
0x00437443:	movl %ebp, %esp
0x00437445:	pushl %esi
0x00437446:	movl %esi, 0x14(%ebp)
0x00437449:	testl %esi, %esi
0x0043744b:	jne 0x00437451
0x00437451:	movl %eax, 0x8(%ebp)
0x00437454:	testl %eax, %eax
0x00437456:	jne 0x0043746b
0x0043746b:	pushl %edi
0x0043746c:	movl %edi, 0x10(%ebp)
0x0043746f:	testl %edi, %edi
0x00437471:	je 20
0x00437473:	cmpl 0xc(%ebp), %esi
0x00437476:	jb 15
0x00437478:	pushl %esi
0x00437479:	pushl %edi
0x0043747a:	pushl %eax
0x0043747b:	call 0x0042e5c0
0x0042e5c0:	pushl %edi
0x0042e5c1:	pushl %esi
0x0042e5c2:	movl %esi, 0x10(%esp)
0x0042e5c6:	movl %ecx, 0x14(%esp)
0x0042e5ca:	movl %edi, 0xc(%esp)
0x0042e5ce:	movl %eax, %ecx
0x0042e5d0:	movl %edx, %ecx
0x0042e5d2:	addl %eax, %esi
0x0042e5d4:	cmpl %edi, %esi
0x0042e5d6:	jbe 0x0042e5e0
0x0042e5e0:	cmpl %ecx, $0x20<UINT8>
0x0042e5e3:	jb 0x0042eabb
0x0042eabb:	andl %ecx, $0x1f<UINT8>
0x0042eabe:	je 48
0x0042eac0:	movl %eax, %ecx
0x0042eac2:	shrl %ecx, $0x2<UINT8>
0x0042eac5:	je 0x0042ead6
0x0042eac7:	movl %edx, (%esi)
0x0042eac9:	movl (%edi), %edx
0x0042eacb:	addl %edi, $0x4<UINT8>
0x0042eace:	addl %esi, $0x4<UINT8>
0x0042ead1:	subl %ecx, $0x1<UINT8>
0x0042ead4:	jne 0x0042eac7
0x0042ead6:	movl %ecx, %eax
0x0042ead8:	andl %ecx, $0x3<UINT8>
0x0042eadb:	je 0x0042eaf0
0x0042eaf0:	movl %eax, 0xc(%esp)
0x0042eaf4:	popl %esi
0x0042eaf5:	popl %edi
0x0042eaf6:	ret

0x00437480:	addl %esp, $0xc<UINT8>
0x00437483:	xorl %eax, %eax
0x00437485:	jmp 0x004374bd
0x004374bd:	popl %edi
0x004374be:	popl %esi
0x004374bf:	popl %ebp
0x004374c0:	ret

0x00436d6e:	movl %eax, (%esi)
0x00436d70:	movl %ecx, $0x101<UINT32>
0x00436d75:	pushl %ecx
0x00436d76:	movl %eax, (%eax)
0x00436d78:	movl %eax, 0x48(%eax)
0x00436d7b:	addl %eax, $0x18<UINT8>
0x00436d7e:	pushl %eax
0x00436d7f:	pushl %ecx
0x00436d80:	pushl $0x4101b0<UINT32>
0x00436d85:	call 0x00437440
0x0042e5e9:	cmpl %ecx, $0x80<UINT32>
0x0042e5ef:	jae 0x0042e604
0x0042e604:	btl 0x40f63c, $0x1<UINT8>
0x0042e60c:	jae 0x0042e617
0x0042e617:	movl %eax, %edi
0x0042e619:	xorl %eax, %esi
0x0042e61b:	testl %eax, $0xf<UINT32>
0x0042e620:	jne 0x0042e630
0x0042e622:	btl 0x410050, $0x1<UINT8>
0x0042e62a:	jb 0x0042ea10
0x0042ea10:	movl %eax, %esi
0x0042ea12:	andl %eax, $0xf<UINT8>
0x0042ea15:	testl %eax, %eax
0x0042ea17:	jne 227
0x0042ea1d:	movl %edx, %ecx
0x0042ea1f:	andl %ecx, $0x7f<UINT8>
0x0042ea22:	shrl %edx, $0x7<UINT8>
0x0042ea25:	je 102
0x0042ea27:	leal %esp, (%esp)
0x0042ea2e:	movl %edi, %edi
0x0042ea30:	movdqa %xmm0, (%esi)
0x0042ea34:	movdqa %xmm1, 0x10(%esi)
0x0042ea39:	movdqa %xmm2, 0x20(%esi)
0x0042ea3e:	movdqa %xmm3, 0x30(%esi)
0x0042ea43:	movdqa (%edi), %xmm0
0x0042ea47:	movdqa 0x10(%edi), %xmm1
0x0042ea4c:	movdqa 0x20(%edi), %xmm2
0x0042ea51:	movdqa 0x30(%edi), %xmm3
0x0042ea56:	movdqa %xmm4, 0x40(%esi)
0x0042ea5b:	movdqa %xmm5, 0x50(%esi)
0x0042ea60:	movdqa %xmm6, 0x60(%esi)
0x0042ea65:	movdqa %xmm7, 0x70(%esi)
0x0042ea6a:	movdqa 0x40(%edi), %xmm4
0x0042ea6f:	movdqa 0x50(%edi), %xmm5
0x0042ea74:	movdqa 0x60(%edi), %xmm6
0x0042ea79:	movdqa 0x70(%edi), %xmm7
0x0042ea7e:	leal %esi, 0x80(%esi)
0x0042ea84:	leal %edi, 0x80(%edi)
0x0042ea8a:	decl %edx
0x0042ea8b:	jne 0x0042ea30
0x0042ea8d:	testl %ecx, %ecx
0x0042ea8f:	je 95
0x0042ea91:	movl %edx, %ecx
0x0042ea93:	shrl %edx, $0x5<UINT8>
0x0042ea96:	testl %edx, %edx
0x0042ea98:	je 0x0042eabb
0x0042eadd:	movb %al, (%esi)
0x0042eadf:	movb (%edi), %al
0x0042eae1:	incl %esi
0x0042eae2:	incl %edi
0x0042eae3:	decl %ecx
0x0042eae4:	jne -9
0x0042eae6:	leal %esp, (%esp)
0x0042eaed:	leal %ecx, (%ecx)
0x00436d8a:	movl %eax, (%esi)
0x00436d8c:	movl %ecx, $0x100<UINT32>
0x00436d91:	pushl %ecx
0x00436d92:	movl %eax, (%eax)
0x00436d94:	movl %eax, 0x48(%eax)
0x00436d97:	addl %eax, $0x119<UINT32>
0x00436d9c:	pushl %eax
0x00436d9d:	pushl %ecx
0x00436d9e:	pushl $0x4102b8<UINT32>
0x00436da3:	call 0x00437440
0x0042e630:	btl 0x40f63c, $0x0<UINT8>
0x0042e638:	jae 0x0042e7e7
0x0042e7e7:	testl %edi, $0x3<UINT32>
0x0042e7ed:	je 0x0042e802
0x0042e802:	movl %edx, %ecx
0x0042e804:	cmpl %ecx, $0x20<UINT8>
0x0042e807:	jb 686
0x0042e80d:	shrl %ecx, $0x2<UINT8>
0x0042e810:	rep movsl %es:(%edi), %ds:(%esi)
0x0042e812:	andl %edx, $0x3<UINT8>
0x0042e815:	jmp 0x0042e834
0x0042e834:	movl %eax, 0xc(%esp)
0x0042e838:	popl %esi
0x0042e839:	popl %edi
0x0042e83a:	ret

0x00436da8:	movl %eax, 0x4105d8
0x00436dad:	addl %esp, $0x30<UINT8>
0x00436db0:	orl %ecx, $0xffffffff<UINT8>
0x00436db3:	xaddl (%eax), %ecx
0x00436db7:	jne 0x00436dcc
0x00436dcc:	movl %eax, (%esi)
0x00436dce:	movl %eax, (%eax)
0x00436dd0:	movl %eax, 0x48(%eax)
0x00436dd3:	movl 0x4105d8, %eax
0x00436dd8:	movl %eax, (%esi)
0x00436dda:	movl %eax, (%eax)
0x00436ddc:	movl %eax, 0x48(%eax)
0x00436ddf:	incl (%eax)
0x00436de2:	popl %esi
0x00436de3:	ret

0x00436cd8:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00436cdf:	call 0x00436cec
0x00436cec:	movl %eax, 0x10(%ebp)
0x00436cef:	pushl (%eax)
0x00436cf1:	call 0x004365bb
0x00436cf6:	popl %ecx
0x00436cf7:	ret

0x00436ce4:	call 0x0042c9d6
0x00436ce9:	ret $0xc<UINT16>

0x00436d1c:	movl %esp, %ebp
0x00436d1e:	popl %ebp
0x00436d1f:	ret

0x00437178:	cmpb 0xc(%ebp), $0x0<UINT8>
0x0043717c:	popl %ecx
0x0043717d:	popl %ecx
0x0043717e:	je -123
0x00437180:	movl %eax, 0x4105d8
0x00437185:	movl 0x41069c, %eax
0x0043718a:	jmp 0x00437105
0x00437105:	pushl %edi
0x00437106:	call 0x0043577a
0x0043710b:	popl %ecx
0x0043710c:	popl %edi
0x0043710d:	movl %eax, %esi
0x0043710f:	popl %esi
0x00437110:	popl %ebx
0x00437111:	movl %esp, %ebp
0x00437113:	popl %ebp
0x00437114:	ret

0x004371a1:	popl %ecx
0x004371a2:	popl %ecx
0x004371a3:	movb 0x40fca8, $0x1<UINT8>
0x004371aa:	movb %al, $0x1<UINT8>
0x004371ac:	ret

0x0042f722:	movb %al, $0x1<UINT8>
0x0042f724:	ret

0x0042f705:	pushl $0x40f768<UINT32>
0x0042f70a:	call 0x00432d09
0x00432d09:	movl %edi, %edi
0x00432d0b:	pushl %ebp
0x00432d0c:	movl %ebp, %esp
0x00432d0e:	pushl %esi
0x00432d0f:	movl %esi, 0x8(%ebp)
0x00432d12:	testl %esi, %esi
0x00432d14:	jne 0x00432d1b
0x00432d1b:	movl %eax, (%esi)
0x00432d1d:	cmpl %eax, 0x8(%esi)
0x00432d20:	jne 31
0x00432d22:	movl %eax, 0x410030
0x00432d27:	andl %eax, $0x1f<UINT8>
0x00432d2a:	pushl $0x20<UINT8>
0x00432d2c:	popl %ecx
0x00432d2d:	subl %ecx, %eax
0x00432d2f:	xorl %eax, %eax
0x00432d31:	rorl %eax, %cl
0x00432d33:	xorl %eax, 0x410030
0x00432d39:	movl (%esi), %eax
0x00432d3b:	movl 0x4(%esi), %eax
0x00432d3e:	movl 0x8(%esi), %eax
0x00432d41:	xorl %eax, %eax
0x00432d43:	popl %esi
0x00432d44:	popl %ebp
0x00432d45:	ret

0x0042f70f:	movl (%esp), $0x40f774<UINT32>
0x0042f716:	call 0x00432d09
0x0042f71b:	popl %ecx
0x0042f71c:	movb %al, $0x1<UINT8>
0x0042f71e:	ret

0x004374fe:	cmpl %esi, 0xc(%ebp)
0x00437501:	jne 4
0x00437503:	movb %al, $0x1<UINT8>
0x00437505:	jmp 0x00437533
0x00437533:	popl %ebx
0x00437534:	popl %esi
0x00437535:	movl %ecx, -4(%ebp)
0x00437538:	xorl %ecx, %ebp
0x0043753a:	popl %edi
0x0043753b:	call 0x0042c018
0x00437540:	movl %esp, %ebp
0x00437542:	popl %ebp
0x00437543:	ret

0x0042f852:	popl %ecx
0x0042f853:	popl %ecx
0x0042f854:	ret

0x0042c46d:	testb %al, %al
0x0042c46f:	jne 0x0042c47b
0x0042c47b:	movb %al, $0x1<UINT8>
0x0042c47d:	popl %ebp
0x0042c47e:	ret

0x0042c251:	popl %ecx
0x0042c252:	testb %al, %al
0x0042c254:	jne 0x0042c25d
0x0042c25d:	xorb %bl, %bl
0x0042c25f:	movb -25(%ebp), %bl
0x0042c262:	andl -4(%ebp), $0x0<UINT8>
0x0042c266:	call 0x0042c411
0x0042c411:	call 0x0042cb85
0x0042cb85:	xorl %eax, %eax
0x0042cb87:	cmpl 0x40f640, %eax
0x0042cb8d:	setne %al
0x0042cb90:	ret

0x0042c416:	testl %eax, %eax
0x0042c418:	jne 3
0x0042c41a:	xorb %al, %al
0x0042c41c:	ret

0x0042c26b:	movb -36(%ebp), %al
0x0042c26e:	movl %eax, 0x40f5f4
0x0042c273:	xorl %ecx, %ecx
0x0042c275:	incl %ecx
0x0042c276:	cmpl %eax, %ecx
0x0042c278:	je -36
0x0042c27a:	testl %eax, %eax
0x0042c27c:	jne 73
0x0042c27e:	movl 0x40f5f4, %ecx
0x0042c284:	pushl $0x402024<UINT32>
0x0042c289:	pushl $0x40200c<UINT32>
0x0042c28e:	call 0x00433053
0x00433053:	movl %edi, %edi
0x00433055:	pushl %ebp
0x00433056:	movl %ebp, %esp
0x00433058:	pushl %ecx
0x00433059:	movl %eax, 0x410030
0x0043305e:	xorl %eax, %ebp
0x00433060:	movl -4(%ebp), %eax
0x00433063:	pushl %esi
0x00433064:	movl %esi, 0x8(%ebp)
0x00433067:	pushl %edi
0x00433068:	jmp 0x00433081
0x00433081:	cmpl %esi, 0xc(%ebp)
0x00433084:	jne 0x0043306a
0x0043306a:	movl %edi, (%esi)
0x0043306c:	testl %edi, %edi
0x0043306e:	je 0x0043307e
0x0043307e:	addl %esi, $0x4<UINT8>
0x00433070:	movl %ecx, %edi
0x00433072:	call 0x0042c70e
0x00433078:	call 0x0044142d
0x0042c180:	pushl %esi
0x0042c181:	pushl $0x2<UINT8>
0x0042c183:	call 0x00433211
0x00433211:	movl %edi, %edi
0x00433213:	pushl %ebp
0x00433214:	movl %ebp, %esp
0x00433216:	movl %eax, 0x8(%ebp)
0x00433219:	movl 0x40f794, %eax
0x0043321e:	popl %ebp
0x0043321f:	ret

0x0042c188:	call 0x0042c6d8
0x0042c6d8:	movl %eax, $0x4000<UINT32>
0x0042c6dd:	ret

0x0042c18d:	pushl %eax
0x0042c18e:	call 0x0043324c
0x0043324c:	movl %edi, %edi
0x0043324e:	pushl %ebp
0x0043324f:	movl %ebp, %esp
0x00433251:	movl %eax, 0x8(%ebp)
0x00433254:	cmpl %eax, $0x4000<UINT32>
0x00433259:	je 0x0043327e
0x0043327e:	movl %ecx, $0x40fcec<UINT32>
0x00433283:	xchgl (%ecx), %eax
0x00433285:	xorl %eax, %eax
0x00433287:	popl %ebp
0x00433288:	ret

0x0042c193:	call 0x0042f867
0x0042f867:	movl %eax, $0x40f648<UINT32>
0x0042f86c:	ret

0x0042c198:	movl %esi, %eax
0x0042c19a:	call 0x0042c6d1
0x0042c6d1:	xorl %eax, %eax
0x0042c6d3:	ret

0x0042c19f:	pushl $0x1<UINT8>
0x0042c1a1:	movl (%esi), %eax
0x0042c1a3:	call 0x0042c47f
0x0042c47f:	pushl %ebp
0x0042c480:	movl %ebp, %esp
0x0042c482:	subl %esp, $0xc<UINT8>
0x0042c485:	pushl %esi
0x0042c486:	movl %esi, 0x8(%ebp)
0x0042c489:	testl %esi, %esi
0x0042c48b:	je 5
0x0042c48d:	cmpl %esi, $0x1<UINT8>
0x0042c490:	jne 124
0x0042c492:	call 0x0042cb85
0x0042c497:	testl %eax, %eax
0x0042c499:	je 0x0042c4c5
0x0042c4c5:	movl %eax, 0x410030
0x0042c4ca:	leal %esi, -12(%ebp)
0x0042c4cd:	pushl %edi
0x0042c4ce:	andl %eax, $0x1f<UINT8>
0x0042c4d1:	movl %edi, $0x40f5fc<UINT32>
0x0042c4d6:	pushl $0x20<UINT8>
0x0042c4d8:	popl %ecx
0x0042c4d9:	subl %ecx, %eax
0x0042c4db:	orl %eax, $0xffffffff<UINT8>
0x0042c4de:	rorl %eax, %cl
0x0042c4e0:	xorl %eax, 0x410030
0x0042c4e6:	movl -12(%ebp), %eax
0x0042c4e9:	movl -8(%ebp), %eax
0x0042c4ec:	movl -4(%ebp), %eax
0x0042c4ef:	movsl %es:(%edi), %ds:(%esi)
0x0042c4f0:	movsl %es:(%edi), %ds:(%esi)
0x0042c4f1:	movsl %es:(%edi), %ds:(%esi)
0x0042c4f2:	movl %edi, $0x40f608<UINT32>
0x0042c4f7:	movl -12(%ebp), %eax
0x0042c4fa:	movl -8(%ebp), %eax
0x0042c4fd:	leal %esi, -12(%ebp)
0x0042c500:	movl -4(%ebp), %eax
0x0042c503:	movb %al, $0x1<UINT8>
0x0042c505:	movsl %es:(%edi), %ds:(%esi)
0x0042c506:	movsl %es:(%edi), %ds:(%esi)
0x0042c507:	movsl %es:(%edi), %ds:(%esi)
0x0042c508:	popl %edi
0x0042c509:	popl %esi
0x0042c50a:	movl %esp, %ebp
0x0042c50c:	popl %ebp
0x0042c50d:	ret

0x0042c1a8:	addl %esp, $0xc<UINT8>
0x0042c1ab:	popl %esi
0x0042c1ac:	testb %al, %al
0x0042c1ae:	je 108
0x0042c1b0:	fnclex
0x0042c1b2:	call 0x0042c931
0x0042c931:	pushl %ebx
0x0042c932:	pushl %esi
0x0042c933:	movl %esi, $0x40e5cc<UINT32>
0x0042c938:	movl %ebx, $0x40e5cc<UINT32>
0x0042c93d:	cmpl %esi, %ebx
0x0042c93f:	jae 0x0042c959
0x0042c959:	popl %esi
0x0042c95a:	popl %ebx
0x0042c95b:	ret

0x0042c1b7:	pushl $0x42c95c<UINT32>
0x0042c1bc:	call 0x0042c620
0x0042c620:	pushl %ebp
0x0042c621:	movl %ebp, %esp
0x0042c623:	pushl 0x8(%ebp)
0x0042c626:	call 0x0042c5e5
0x0042c5e5:	pushl %ebp
0x0042c5e6:	movl %ebp, %esp
0x0042c5e8:	movl %eax, 0x410030
0x0042c5ed:	movl %ecx, %eax
0x0042c5ef:	xorl %eax, 0x40f5fc
0x0042c5f5:	andl %ecx, $0x1f<UINT8>
0x0042c5f8:	pushl 0x8(%ebp)
0x0042c5fb:	rorl %eax, %cl
0x0042c5fd:	cmpl %eax, $0xffffffff<UINT8>
0x0042c600:	jne 7
0x0042c602:	call 0x00432cd6
0x00432cd6:	movl %edi, %edi
0x00432cd8:	pushl %ebp
0x00432cd9:	movl %ebp, %esp
0x00432cdb:	pushl 0x8(%ebp)
0x00432cde:	pushl $0x40f768<UINT32>
0x00432ce3:	call 0x00432d46
0x00432d46:	movl %edi, %edi
0x00432d48:	pushl %ebp
0x00432d49:	movl %ebp, %esp
0x00432d4b:	pushl %ecx
0x00432d4c:	pushl %ecx
0x00432d4d:	leal %eax, 0x8(%ebp)
0x00432d50:	movl -8(%ebp), %eax
0x00432d53:	leal %eax, 0xc(%ebp)
0x00432d56:	movl -4(%ebp), %eax
0x00432d59:	leal %eax, -8(%ebp)
0x00432d5c:	pushl %eax
0x00432d5d:	pushl $0x2<UINT8>
0x00432d5f:	call 0x00432a4d
0x00432a4d:	movl %edi, %edi
0x00432a4f:	pushl %ebp
0x00432a50:	movl %ebp, %esp
0x00432a52:	subl %esp, $0xc<UINT8>
0x00432a55:	movl %eax, 0x8(%ebp)
0x00432a58:	leal %ecx, -1(%ebp)
0x00432a5b:	movl -8(%ebp), %eax
0x00432a5e:	movl -12(%ebp), %eax
0x00432a61:	leal %eax, -8(%ebp)
0x00432a64:	pushl %eax
0x00432a65:	pushl 0xc(%ebp)
0x00432a68:	leal %eax, -12(%ebp)
0x00432a6b:	pushl %eax
0x00432a6c:	call 0x00432983
0x00432983:	pushl $0xc<UINT8>
0x00432985:	pushl $0x4430a8<UINT32>
0x0043298a:	call 0x0042c990
0x0043298f:	andl -28(%ebp), $0x0<UINT8>
0x00432993:	movl %eax, 0x8(%ebp)
0x00432996:	pushl (%eax)
0x00432998:	call 0x00436573
0x0043299d:	popl %ecx
0x0043299e:	andl -4(%ebp), $0x0<UINT8>
0x004329a2:	movl %ecx, 0xc(%ebp)
0x004329a5:	call 0x00432b95
0x00432b95:	movl %edi, %edi
0x00432b97:	pushl %ebp
0x00432b98:	movl %ebp, %esp
0x00432b9a:	subl %esp, $0xc<UINT8>
0x00432b9d:	movl %eax, %ecx
0x00432b9f:	movl -8(%ebp), %eax
0x00432ba2:	pushl %esi
0x00432ba3:	movl %eax, (%eax)
0x00432ba5:	movl %esi, (%eax)
0x00432ba7:	testl %esi, %esi
0x00432ba9:	jne 0x00432bb3
0x00432bb3:	movl %eax, 0x410030
0x00432bb8:	movl %ecx, %eax
0x00432bba:	pushl %ebx
0x00432bbb:	movl %ebx, (%esi)
0x00432bbd:	andl %ecx, $0x1f<UINT8>
0x00432bc0:	pushl %edi
0x00432bc1:	movl %edi, 0x4(%esi)
0x00432bc4:	xorl %ebx, %eax
0x00432bc6:	movl %esi, 0x8(%esi)
0x00432bc9:	xorl %edi, %eax
0x00432bcb:	xorl %esi, %eax
0x00432bcd:	rorl %edi, %cl
0x00432bcf:	rorl %esi, %cl
0x00432bd1:	rorl %ebx, %cl
0x00432bd3:	cmpl %edi, %esi
0x00432bd5:	jne 180
0x00432bdb:	subl %esi, %ebx
0x00432bdd:	movl %eax, $0x200<UINT32>
0x00432be2:	sarl %esi, $0x2<UINT8>
0x00432be5:	cmpl %esi, %eax
0x00432be7:	ja 2
0x00432be9:	movl %eax, %esi
0x00432beb:	leal %edi, (%eax,%esi)
0x00432bee:	testl %edi, %edi
0x00432bf0:	jne 3
0x00432bf2:	pushl $0x20<UINT8>
0x00432bf4:	popl %edi
0x00432bf5:	cmpl %edi, %esi
0x00432bf7:	jb 29
0x00432bf9:	pushl $0x4<UINT8>
0x00432bfb:	pushl %edi
0x00432bfc:	pushl %ebx
0x00432bfd:	call 0x0043a37e
0x0043a37e:	movl %edi, %edi
0x0043a380:	pushl %ebp
0x0043a381:	movl %ebp, %esp
0x0043a383:	popl %ebp
0x0043a384:	jmp 0x0043a389
0x0043a389:	movl %edi, %edi
0x0043a38b:	pushl %ebp
0x0043a38c:	movl %ebp, %esp
0x0043a38e:	pushl %esi
0x0043a38f:	movl %esi, 0xc(%ebp)
0x0043a392:	testl %esi, %esi
0x0043a394:	je 27
0x0043a396:	pushl $0xffffffe0<UINT8>
0x0043a398:	xorl %edx, %edx
0x0043a39a:	popl %eax
0x0043a39b:	divl %eax, %esi
0x0043a39d:	cmpl %eax, 0x10(%ebp)
0x0043a3a0:	jae 0x0043a3b1
0x0043a3b1:	pushl %ebx
0x0043a3b2:	movl %ebx, 0x8(%ebp)
0x0043a3b5:	pushl %edi
0x0043a3b6:	testl %ebx, %ebx
0x0043a3b8:	je 0x0043a3c5
0x0043a3c5:	xorl %edi, %edi
0x0043a3c7:	imull %esi, 0x10(%ebp)
0x0043a3cb:	pushl %esi
0x0043a3cc:	pushl %ebx
0x0043a3cd:	call 0x0043cff8
0x0043cff8:	movl %edi, %edi
0x0043cffa:	pushl %ebp
0x0043cffb:	movl %ebp, %esp
0x0043cffd:	pushl %edi
0x0043cffe:	movl %edi, 0x8(%ebp)
0x0043d001:	testl %edi, %edi
0x0043d003:	jne 11
0x0043d005:	pushl 0xc(%ebp)
0x0043d008:	call 0x004357b4
0x0043d00d:	popl %ecx
0x0043d00e:	jmp 0x0043d034
0x0043d034:	popl %edi
0x0043d035:	popl %ebp
0x0043d036:	ret

0x0043a3d2:	movl %ebx, %eax
0x0043a3d4:	popl %ecx
0x0043a3d5:	popl %ecx
0x0043a3d6:	testl %ebx, %ebx
0x0043a3d8:	je 21
0x0043a3da:	cmpl %edi, %esi
0x0043a3dc:	jae 17
0x0043a3de:	subl %esi, %edi
0x0043a3e0:	leal %eax, (%ebx,%edi)
0x0043a3e3:	pushl %esi
0x0043a3e4:	pushl $0x0<UINT8>
0x0043a3e6:	pushl %eax
0x0043a3e7:	call 0x0042f0c0
0x0042f17d:	btl 0x410050, $0x1<UINT8>
0x0042f185:	jae 62
0x0042f187:	movd %xmm0, %eax
0x0042f18b:	pshufd %xmm0, %xmm0, $0x0<UINT8>
0x0043a3ec:	addl %esp, $0xc<UINT8>
0x0043a3ef:	popl %edi
0x0043a3f0:	movl %eax, %ebx
0x0043a3f2:	popl %ebx
0x0043a3f3:	popl %esi
0x0043a3f4:	popl %ebp
0x0043a3f5:	ret

0x00432c02:	pushl $0x0<UINT8>
0x00432c04:	movl -4(%ebp), %eax
0x00432c07:	call 0x0043577a
0x00432c0c:	movl %ecx, -4(%ebp)
0x00432c0f:	addl %esp, $0x10<UINT8>
0x00432c12:	testl %ecx, %ecx
0x00432c14:	jne 0x00432c3e
0x00432c3e:	leal %eax, (%ecx,%esi,4)
0x00432c41:	movl %ebx, %ecx
0x00432c43:	movl -4(%ebp), %eax
0x00432c46:	leal %esi, (%ecx,%edi,4)
0x00432c49:	movl %eax, 0x410030
0x00432c4e:	movl %edi, -4(%ebp)
0x00432c51:	andl %eax, $0x1f<UINT8>
0x00432c54:	pushl $0x20<UINT8>
0x00432c56:	popl %ecx
0x00432c57:	subl %ecx, %eax
0x00432c59:	xorl %eax, %eax
0x00432c5b:	rorl %eax, %cl
0x00432c5d:	movl %ecx, %edi
0x00432c5f:	xorl %eax, 0x410030
0x00432c65:	movl -12(%ebp), %eax
0x00432c68:	movl %eax, %esi
0x00432c6a:	subl %eax, %edi
0x00432c6c:	addl %eax, $0x3<UINT8>
0x00432c6f:	shrl %eax, $0x2<UINT8>
0x00432c72:	cmpl %esi, %edi
0x00432c74:	sbbl %edx, %edx
0x00432c76:	notl %edx
0x00432c78:	andl %edx, %eax
0x00432c7a:	movl -4(%ebp), %edx
0x00432c7d:	je 16
0x00432c7f:	movl %edx, -12(%ebp)
0x00432c82:	xorl %eax, %eax
0x00432c84:	incl %eax
0x00432c85:	movl (%ecx), %edx
0x00432c87:	leal %ecx, 0x4(%ecx)
0x00432c8a:	cmpl %eax, -4(%ebp)
0x00432c8d:	jne 0x00432c84
0x00432c8f:	movl %eax, -8(%ebp)
0x00432c92:	movl %eax, 0x4(%eax)
0x00432c95:	pushl (%eax)
0x00432c97:	call 0x0042f7f3
0x00432c9c:	pushl %ebx
0x00432c9d:	movl (%edi), %eax
0x00432c9f:	call 0x0042c3b0
0x0042c3b0:	pushl %ebp
0x0042c3b1:	movl %ebp, %esp
0x0042c3b3:	movl %eax, 0x410030
0x0042c3b8:	andl %eax, $0x1f<UINT8>
0x0042c3bb:	pushl $0x20<UINT8>
0x0042c3bd:	popl %ecx
0x0042c3be:	subl %ecx, %eax
0x0042c3c0:	movl %eax, 0x8(%ebp)
0x0042c3c3:	rorl %eax, %cl
0x0042c3c5:	xorl %eax, 0x410030
0x0042c3cb:	popl %ebp
0x0042c3cc:	ret

0x00432ca4:	movl %ebx, -8(%ebp)
0x00432ca7:	movl %ecx, (%ebx)
0x00432ca9:	movl %ecx, (%ecx)
0x00432cab:	movl (%ecx), %eax
0x00432cad:	leal %eax, 0x4(%edi)
0x00432cb0:	pushl %eax
0x00432cb1:	call 0x0042c3b0
0x00432cb6:	movl %ecx, (%ebx)
0x00432cb8:	pushl %esi
0x00432cb9:	movl %ecx, (%ecx)
0x00432cbb:	movl 0x4(%ecx), %eax
0x00432cbe:	call 0x0042c3b0
0x00432cc3:	movl %ecx, (%ebx)
0x00432cc5:	addl %esp, $0x10<UINT8>
0x00432cc8:	movl %ecx, (%ecx)
0x00432cca:	movl 0x8(%ecx), %eax
0x00432ccd:	xorl %eax, %eax
0x00432ccf:	popl %edi
0x00432cd0:	popl %ebx
0x00432cd1:	popl %esi
0x00432cd2:	movl %esp, %ebp
0x00432cd4:	popl %ebp
0x00432cd5:	ret

0x004329aa:	movl %esi, %eax
0x004329ac:	movl -28(%ebp), %esi
0x004329af:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004329b6:	call 0x004329c8
0x004329c8:	movl %eax, 0x10(%ebp)
0x004329cb:	pushl (%eax)
0x004329cd:	call 0x004365bb
0x004329d2:	popl %ecx
0x004329d3:	ret

0x004329bb:	movl %eax, %esi
0x004329bd:	call 0x0042c9d6
0x004329c2:	ret $0xc<UINT16>

0x00432a71:	movl %esp, %ebp
0x00432a73:	popl %ebp
0x00432a74:	ret

0x00432d64:	popl %ecx
0x00432d65:	popl %ecx
0x00432d66:	movl %esp, %ebp
0x00432d68:	popl %ebp
0x00432d69:	ret

0x00432ce8:	popl %ecx
0x00432ce9:	popl %ecx
0x00432cea:	popl %ebp
0x00432ceb:	ret

0x0042c607:	jmp 0x0042c614
0x0042c614:	negl %eax
0x0042c616:	popl %ecx
0x0042c617:	sbbl %eax, %eax
0x0042c619:	notl %eax
0x0042c61b:	andl %eax, 0x8(%ebp)
0x0042c61e:	popl %ebp
0x0042c61f:	ret

0x0042c62b:	negl %eax
0x0042c62d:	popl %ecx
0x0042c62e:	sbbl %eax, %eax
0x0042c630:	negl %eax
0x0042c632:	decl %eax
0x0042c633:	popl %ebp
0x0042c634:	ret

0x0042c1c1:	call 0x0042c6d4
0x0042c6d4:	xorl %eax, %eax
0x0042c6d6:	incl %eax
0x0042c6d7:	ret

0x0042c1c6:	pushl %eax
0x0042c1c7:	call 0x00432919
0x00432919:	movl %edi, %edi
0x0043291b:	pushl %ebp
0x0043291c:	movl %ebp, %esp
0x0043291e:	popl %ebp
0x0043291f:	jmp 0x0043262b
0x0043262b:	movl %edi, %edi
0x0043262d:	pushl %ebp
0x0043262e:	movl %ebp, %esp
0x00432630:	subl %esp, $0xc<UINT8>
0x00432633:	cmpl 0x8(%ebp), $0x2<UINT8>
0x00432637:	pushl %esi
0x00432638:	je 28
0x0043263a:	cmpl 0x8(%ebp), $0x1<UINT8>
0x0043263e:	je 0x00432656
0x00432656:	pushl %ebx
0x00432657:	pushl %edi
0x00432658:	call 0x0043718f
0x0043265d:	pushl $0x104<UINT32>
0x00432662:	movl %esi, $0x40f660<UINT32>
0x00432667:	xorl %edi, %edi
0x00432669:	pushl %esi
0x0043266a:	pushl %edi
0x0043266b:	call GetModuleFileNameA@KERNEL32.DLL
GetModuleFileNameA@KERNEL32.DLL: API Node	
0x00432671:	movl %ebx, 0x40fc80
0x00432677:	movl 0x40fc88, %esi
0x0043267d:	testl %ebx, %ebx
0x0043267f:	je 5
0x00432681:	cmpb (%ebx), $0x0<UINT8>
0x00432684:	jne 0x00432688
0x00432688:	leal %eax, -12(%ebp)
0x0043268b:	movl -4(%ebp), %edi
0x0043268e:	pushl %eax
0x0043268f:	leal %eax, -4(%ebp)
0x00432692:	movl -12(%ebp), %edi
0x00432695:	pushl %eax
0x00432696:	pushl %edi
0x00432697:	pushl %edi
0x00432698:	pushl %ebx
0x00432699:	call 0x0043274f
0x0043274f:	movl %edi, %edi
0x00432751:	pushl %ebp
0x00432752:	movl %ebp, %esp
0x00432754:	pushl %ecx
0x00432755:	movl %eax, 0x14(%ebp)
0x00432758:	pushl %ebx
0x00432759:	movl %ebx, 0x18(%ebp)
0x0043275c:	pushl %esi
0x0043275d:	movl %esi, 0x8(%ebp)
0x00432760:	pushl %edi
0x00432761:	andl (%ebx), $0x0<UINT8>
0x00432764:	movl %edi, 0x10(%ebp)
0x00432767:	movl (%eax), $0x1<UINT32>
0x0043276d:	movl %eax, 0xc(%ebp)
0x00432770:	testl %eax, %eax
0x00432772:	je 0x0043277c
0x0043277c:	xorb %cl, %cl
0x0043277e:	movb -1(%ebp), %cl
0x00432781:	cmpb (%esi), $0x22<UINT8>
0x00432784:	jne 0x00432793
0x00432786:	testb %cl, %cl
0x00432788:	movb %al, $0x22<UINT8>
0x0043278a:	sete %cl
0x0043278d:	incl %esi
0x0043278e:	movb -1(%ebp), %cl
0x00432791:	jmp 0x004327c8
0x004327c8:	testb %cl, %cl
0x004327ca:	jne 0x00432781
0x00432793:	incl (%ebx)
0x00432795:	testl %edi, %edi
0x00432797:	je 0x0043279e
0x0043279e:	movb %al, (%esi)
0x004327a0:	incl %esi
0x004327a1:	movb -2(%ebp), %al
0x004327a4:	movsbl %eax, %al
0x004327a7:	pushl %eax
0x004327a8:	call 0x00439e42
0x00439e42:	movl %edi, %edi
0x00439e44:	pushl %ebp
0x00439e45:	movl %ebp, %esp
0x00439e47:	pushl $0x4<UINT8>
0x00439e49:	pushl $0x0<UINT8>
0x00439e4b:	pushl 0x8(%ebp)
0x00439e4e:	pushl $0x0<UINT8>
0x00439e50:	call 0x00439de9
0x00439de9:	movl %edi, %edi
0x00439deb:	pushl %ebp
0x00439dec:	movl %ebp, %esp
0x00439dee:	subl %esp, $0x10<UINT8>
0x00439df1:	pushl %esi
0x00439df2:	pushl 0x8(%ebp)
0x00439df5:	leal %ecx, -16(%ebp)
0x00439df8:	call 0x004300bd
0x00439dfd:	movzbl %esi, 0xc(%ebp)
0x00439e01:	movl %eax, -8(%ebp)
0x00439e04:	movb %cl, 0x14(%ebp)
0x00439e07:	testb 0x19(%eax,%esi), %cl
0x00439e0b:	jne 27
0x00439e0d:	xorl %edx, %edx
0x00439e0f:	cmpl 0x10(%ebp), %edx
0x00439e12:	je 0x00439e22
0x00439e22:	movl %eax, %edx
0x00439e24:	testl %eax, %eax
0x00439e26:	je 0x00439e2b
0x00439e2b:	cmpb -4(%ebp), $0x0<UINT8>
0x00439e2f:	popl %esi
0x00439e30:	je 0x00439e3c
0x00439e3c:	movl %eax, %edx
0x00439e3e:	movl %esp, %ebp
0x00439e40:	popl %ebp
0x00439e41:	ret

0x00439e55:	addl %esp, $0x10<UINT8>
0x00439e58:	popl %ebp
0x00439e59:	ret

0x004327ad:	popl %ecx
0x004327ae:	testl %eax, %eax
0x004327b0:	je 0x004327be
0x004327be:	movb %al, -2(%ebp)
0x004327c1:	testb %al, %al
0x004327c3:	je 0x004327de
0x004327de:	decl %esi
0x004327df:	movb -1(%ebp), $0x0<UINT8>
0x004327e3:	cmpb (%esi), $0x0<UINT8>
0x004327e6:	je 0x004328ae
0x004328ae:	movl %ecx, 0xc(%ebp)
0x004328b1:	popl %edi
0x004328b2:	popl %esi
0x004328b3:	popl %ebx
0x004328b4:	testl %ecx, %ecx
0x004328b6:	je 0x004328bb
0x004328bb:	movl %eax, 0x14(%ebp)
0x004328be:	incl (%eax)
0x004328c0:	movl %esp, %ebp
0x004328c2:	popl %ebp
0x004328c3:	ret

0x0043269e:	pushl $0x1<UINT8>
0x004326a0:	pushl -12(%ebp)
0x004326a3:	pushl -4(%ebp)
0x004326a6:	call 0x004328c4
0x004328c4:	movl %edi, %edi
0x004328c6:	pushl %ebp
0x004328c7:	movl %ebp, %esp
0x004328c9:	pushl %esi
0x004328ca:	movl %esi, 0x8(%ebp)
0x004328cd:	cmpl %esi, $0x3fffffff<UINT32>
0x004328d3:	jb 0x004328d9
0x004328d9:	pushl %edi
0x004328da:	orl %edi, $0xffffffff<UINT8>
0x004328dd:	movl %ecx, 0xc(%ebp)
0x004328e0:	xorl %edx, %edx
0x004328e2:	movl %eax, %edi
0x004328e4:	divl %eax, 0x10(%ebp)
0x004328e7:	cmpl %ecx, %eax
0x004328e9:	jae 13
0x004328eb:	imull %ecx, 0x10(%ebp)
0x004328ef:	shll %esi, $0x2<UINT8>
0x004328f2:	subl %edi, %esi
0x004328f4:	cmpl %edi, %ecx
0x004328f6:	ja 0x004328fc
0x004328fc:	leal %eax, (%ecx,%esi)
0x004328ff:	pushl $0x1<UINT8>
0x00432901:	pushl %eax
0x00432902:	call 0x00439337
0x00432907:	pushl $0x0<UINT8>
0x00432909:	movl %esi, %eax
0x0043290b:	call 0x0043577a
0x00432910:	addl %esp, $0xc<UINT8>
0x00432913:	movl %eax, %esi
0x00432915:	popl %edi
0x00432916:	popl %esi
0x00432917:	popl %ebp
0x00432918:	ret

0x004326ab:	movl %esi, %eax
0x004326ad:	addl %esp, $0x20<UINT8>
0x004326b0:	testl %esi, %esi
0x004326b2:	jne 0x004326c0
0x004326c0:	leal %eax, -12(%ebp)
0x004326c3:	pushl %eax
0x004326c4:	leal %eax, -4(%ebp)
0x004326c7:	pushl %eax
0x004326c8:	movl %eax, -4(%ebp)
0x004326cb:	leal %eax, (%esi,%eax,4)
0x004326ce:	pushl %eax
0x004326cf:	pushl %esi
0x004326d0:	pushl %ebx
0x004326d1:	call 0x0043274f
0x00432774:	movl (%eax), %edi
0x00432776:	addl %eax, $0x4<UINT8>
0x00432779:	movl 0xc(%ebp), %eax
0x00432799:	movb %al, (%esi)
0x0043279b:	movb (%edi), %al
0x0043279d:	incl %edi
0x004328b8:	andl (%ecx), $0x0<UINT8>
0x004326d6:	addl %esp, $0x14<UINT8>
0x004326d9:	cmpl 0x8(%ebp), $0x1<UINT8>
0x004326dd:	jne 22
0x004326df:	movl %eax, -4(%ebp)
0x004326e2:	decl %eax
0x004326e3:	movl 0x40fc74, %eax
0x004326e8:	movl %eax, %esi
0x004326ea:	movl %esi, %edi
0x004326ec:	movl 0x40fc78, %eax
0x004326f1:	movl %ebx, %edi
0x004326f3:	jmp 0x0043273f
0x0043273f:	pushl %esi
0x00432740:	call 0x0043577a
0x00432745:	popl %ecx
0x00432746:	popl %edi
0x00432747:	movl %eax, %ebx
0x00432749:	popl %ebx
0x0043274a:	popl %esi
0x0043274b:	movl %esp, %ebp
0x0043274d:	popl %ebp
0x0043274e:	ret

0x0042c1cc:	popl %ecx
0x0042c1cd:	popl %ecx
0x0042c1ce:	testl %eax, %eax
0x0042c1d0:	jne 74
0x0042c1d2:	call 0x0042c6de
0x0042c6de:	pushl $0x40f618<UINT32>
0x0042c6e3:	call InitializeSListHead@KERNEL32.DLL
InitializeSListHead@KERNEL32.DLL: API Node	
0x0042c6e9:	ret

0x0042c1d7:	call 0x0042c732
0x0042c732:	xorl %eax, %eax
0x0042c734:	cmpl 0x410044, %eax
0x0042c73a:	sete %al
0x0042c73d:	ret

0x0042c1dc:	testl %eax, %eax
0x0042c1de:	je 0x0042c1eb
0x0042c1eb:	call 0x0042c70e
0x0042c1f0:	call 0x0042c70e
0x0042c1f5:	call 0x0042c6ed
0x0042c6ed:	pushl $0x30000<UINT32>
0x0042c6f2:	pushl $0x10000<UINT32>
0x0042c6f7:	pushl $0x0<UINT8>
0x0042c6f9:	call 0x00432924
0x00432924:	movl %edi, %edi
0x00432926:	pushl %ebp
0x00432927:	movl %ebp, %esp
0x00432929:	movl %ecx, 0x10(%ebp)
0x0043292c:	movl %eax, 0xc(%ebp)
0x0043292f:	andl %ecx, $0xfff7ffff<UINT32>
0x00432935:	andl %eax, %ecx
0x00432937:	pushl %esi
0x00432938:	movl %esi, 0x8(%ebp)
0x0043293b:	testl %eax, $0xfcf0fce0<UINT32>
0x00432940:	je 0x00432966
0x00432966:	pushl %ecx
0x00432967:	pushl 0xc(%ebp)
0x0043296a:	testl %esi, %esi
0x0043296c:	je 0x00432977
0x00432977:	call 0x00439fe3
0x00439fe3:	movl %edi, %edi
0x00439fe5:	pushl %ebp
0x00439fe6:	movl %ebp, %esp
0x00439fe8:	subl %esp, $0x10<UINT8>
0x00439feb:	fwait
0x00439fec:	fnstcw -8(%ebp)
0x00439fef:	movw %ax, -8(%ebp)
0x00439ff3:	xorl %ecx, %ecx
0x00439ff5:	testb %al, $0x1<UINT8>
0x00439ff7:	je 0x00439ffc
0x00439ffc:	testb %al, $0x4<UINT8>
0x00439ffe:	je 0x0043a003
0x0043a003:	testb %al, $0x8<UINT8>
0x0043a005:	je 3
0x0043a007:	orl %ecx, $0x4<UINT8>
0x0043a00a:	testb %al, $0x10<UINT8>
0x0043a00c:	je 3
0x0043a00e:	orl %ecx, $0x2<UINT8>
0x0043a011:	testb %al, $0x20<UINT8>
0x0043a013:	je 0x0043a018
0x0043a018:	testb %al, $0x2<UINT8>
0x0043a01a:	je 0x0043a022
0x0043a022:	pushl %ebx
0x0043a023:	pushl %esi
0x0043a024:	movzwl %esi, %ax
0x0043a027:	movl %ebx, $0xc00<UINT32>
0x0043a02c:	movl %edx, %esi
0x0043a02e:	pushl %edi
0x0043a02f:	movl %edi, $0x200<UINT32>
0x0043a034:	andl %edx, %ebx
0x0043a036:	je 38
0x0043a038:	cmpl %edx, $0x400<UINT32>
0x0043a03e:	je 24
0x0043a040:	cmpl %edx, $0x800<UINT32>
0x0043a046:	je 12
0x0043a048:	cmpl %edx, %ebx
0x0043a04a:	jne 18
0x0043a04c:	orl %ecx, $0x300<UINT32>
0x0043a052:	jmp 0x0043a05e
0x0043a05e:	andl %esi, $0x300<UINT32>
0x0043a064:	je 12
0x0043a066:	cmpl %esi, %edi
0x0043a068:	jne 0x0043a078
0x0043a078:	movl %edx, $0x1000<UINT32>
0x0043a07d:	testw %dx, %ax
0x0043a080:	je 6
0x0043a082:	orl %ecx, $0x40000<UINT32>
0x0043a088:	movl %edi, 0xc(%ebp)
0x0043a08b:	movl %esi, %edi
0x0043a08d:	movl %eax, 0x8(%ebp)
0x0043a090:	notl %esi
0x0043a092:	andl %esi, %ecx
0x0043a094:	andl %eax, %edi
0x0043a096:	orl %esi, %eax
0x0043a098:	cmpl %esi, %ecx
0x0043a09a:	je 166
0x0043a0a0:	pushl %esi
0x0043a0a1:	call 0x0043a2e5
0x0043a2e5:	movl %edi, %edi
0x0043a2e7:	pushl %ebp
0x0043a2e8:	movl %ebp, %esp
0x0043a2ea:	movl %ecx, 0x8(%ebp)
0x0043a2ed:	xorl %eax, %eax
0x0043a2ef:	testb %cl, $0x10<UINT8>
0x0043a2f2:	je 0x0043a2f5
0x0043a2f5:	testb %cl, $0x8<UINT8>
0x0043a2f8:	je 0x0043a2fd
0x0043a2fd:	testb %cl, $0x4<UINT8>
0x0043a300:	je 3
0x0043a302:	orl %eax, $0x8<UINT8>
0x0043a305:	testb %cl, $0x2<UINT8>
0x0043a308:	je 3
0x0043a30a:	orl %eax, $0x10<UINT8>
0x0043a30d:	testb %cl, $0x1<UINT8>
0x0043a310:	je 0x0043a315
0x0043a315:	testl %ecx, $0x80000<UINT32>
0x0043a31b:	je 0x0043a320
0x0043a320:	pushl %esi
0x0043a321:	movl %edx, %ecx
0x0043a323:	movl %esi, $0x300<UINT32>
0x0043a328:	pushl %edi
0x0043a329:	movl %edi, $0x200<UINT32>
0x0043a32e:	andl %edx, %esi
0x0043a330:	je 35
0x0043a332:	cmpl %edx, $0x100<UINT32>
0x0043a338:	je 22
0x0043a33a:	cmpl %edx, %edi
0x0043a33c:	je 11
0x0043a33e:	cmpl %edx, %esi
0x0043a340:	jne 19
0x0043a342:	orl %eax, $0xc00<UINT32>
0x0043a347:	jmp 0x0043a355
0x0043a355:	movl %edx, %ecx
0x0043a357:	andl %edx, $0x30000<UINT32>
0x0043a35d:	je 12
0x0043a35f:	cmpl %edx, $0x10000<UINT32>
0x0043a365:	jne 6
0x0043a367:	orl %eax, %edi
0x0043a369:	jmp 0x0043a36d
0x0043a36d:	popl %edi
0x0043a36e:	popl %esi
0x0043a36f:	testl %ecx, $0x40000<UINT32>
0x0043a375:	je 5
0x0043a377:	orl %eax, $0x1000<UINT32>
0x0043a37c:	popl %ebp
0x0043a37d:	ret

0x0043a0a6:	popl %ecx
0x0043a0a7:	movw -4(%ebp), %ax
0x0043a0ab:	fldcw -4(%ebp)
0x0043a0ae:	fwait
0x0043a0af:	fnstcw -4(%ebp)
0x0043a0b2:	movw %ax, -4(%ebp)
0x0043a0b6:	xorl %esi, %esi
0x0043a0b8:	testb %al, $0x1<UINT8>
0x0043a0ba:	je 0x0043a0bf
0x0043a0bf:	testb %al, $0x4<UINT8>
0x0043a0c1:	je 0x0043a0c6
0x0043a0c6:	testb %al, $0x8<UINT8>
0x0043a0c8:	je 3
0x0043a0ca:	orl %esi, $0x4<UINT8>
0x0043a0cd:	testb %al, $0x10<UINT8>
0x0043a0cf:	je 3
0x0043a0d1:	orl %esi, $0x2<UINT8>
0x0043a0d4:	testb %al, $0x20<UINT8>
0x0043a0d6:	je 0x0043a0db
0x0043a0db:	testb %al, $0x2<UINT8>
0x0043a0dd:	je 0x0043a0e5
0x0043a0e5:	movzwl %edx, %ax
0x0043a0e8:	movl %ecx, %edx
0x0043a0ea:	andl %ecx, %ebx
0x0043a0ec:	je 42
0x0043a0ee:	cmpl %ecx, $0x400<UINT32>
0x0043a0f4:	je 28
0x0043a0f6:	cmpl %ecx, $0x800<UINT32>
0x0043a0fc:	je 12
0x0043a0fe:	cmpl %ecx, %ebx
0x0043a100:	jne 22
0x0043a102:	orl %esi, $0x300<UINT32>
0x0043a108:	jmp 0x0043a118
0x0043a118:	andl %edx, $0x300<UINT32>
0x0043a11e:	je 16
0x0043a120:	cmpl %edx, $0x200<UINT32>
0x0043a126:	jne 14
0x0043a128:	orl %esi, $0x10000<UINT32>
0x0043a12e:	jmp 0x0043a136
0x0043a136:	movl %edx, $0x1000<UINT32>
0x0043a13b:	testw %dx, %ax
0x0043a13e:	je 6
0x0043a140:	orl %esi, $0x40000<UINT32>
0x0043a146:	cmpl 0x40f638, $0x1<UINT8>
0x0043a14d:	jl 393
0x0043a153:	andl %edi, $0x308031f<UINT32>
0x0043a159:	stmxcsr -16(%ebp)
0x0043a15d:	movl %eax, -16(%ebp)
0x0043a160:	xorl %ecx, %ecx
0x0043a162:	testb %al, %al
0x0043a164:	jns 0x0043a169
0x0043a169:	testl %eax, $0x200<UINT32>
0x0043a16e:	je 3
0x0043a170:	orl %ecx, $0x8<UINT8>
0x0043a173:	testl %eax, $0x400<UINT32>
0x0043a178:	je 0x0043a17d
0x0043a17d:	testl %eax, $0x800<UINT32>
0x0043a182:	je 3
0x0043a184:	orl %ecx, $0x2<UINT8>
0x0043a187:	testl %edx, %eax
0x0043a189:	je 0x0043a18e
0x0043a18e:	testl %eax, $0x100<UINT32>
0x0043a193:	je 6
0x0043a195:	orl %ecx, $0x80000<UINT32>
0x0043a19b:	movl %edx, %eax
0x0043a19d:	movl %ebx, $0x6000<UINT32>
0x0043a1a2:	andl %edx, %ebx
0x0043a1a4:	je 42
0x0043a1a6:	cmpl %edx, $0x2000<UINT32>
0x0043a1ac:	je 0x0043a1ca
0x0043a1ca:	orl %ecx, $0x100<UINT32>
0x0043a1d0:	pushl $0x40<UINT8>
0x0043a1d2:	andl %eax, $0x8040<UINT32>
0x0043a1d7:	popl %ebx
0x0043a1d8:	subl %eax, %ebx
0x0043a1da:	je 0x0043a1f7
0x0043a1f7:	orl %ecx, $0x2000000<UINT32>
0x0043a1fd:	movl %eax, %edi
0x0043a1ff:	andl %edi, 0x8(%ebp)
0x0043a202:	notl %eax
0x0043a204:	andl %eax, %ecx
0x0043a206:	orl %eax, %edi
0x0043a208:	cmpl %eax, %ecx
0x0043a20a:	je 0x0043a2c5
0x0043a2c5:	movl %eax, %ecx
0x0043a2c7:	orl %ecx, %esi
0x0043a2c9:	xorl %eax, %esi
0x0043a2cb:	testl %eax, $0x8031f<UINT32>
0x0043a2d0:	je 6
0x0043a2d2:	orl %ecx, $0x80000000<UINT32>
0x0043a2d8:	movl %eax, %ecx
0x0043a2da:	jmp 0x0043a2de
0x0043a2de:	popl %edi
0x0043a2df:	popl %esi
0x0043a2e0:	popl %ebx
0x0043a2e1:	movl %esp, %ebp
0x0043a2e3:	popl %ebp
0x0043a2e4:	ret

0x0043297c:	popl %ecx
0x0043297d:	popl %ecx
0x0043297e:	xorl %eax, %eax
0x00432980:	popl %esi
0x00432981:	popl %ebp
0x00432982:	ret

0x0042c6fe:	addl %esp, $0xc<UINT8>
0x0042c701:	testl %eax, %eax
0x0042c703:	jne 1
0x0042c705:	ret

0x0042c1fa:	call 0x0042c6d1
0x0042c1ff:	pushl %eax
0x0042c200:	call 0x004325c9
0x004325c9:	movl %edi, %edi
0x004325cb:	pushl %ebp
0x004325cc:	movl %ebp, %esp
0x004325ce:	pushl %esi
0x004325cf:	call 0x0043695f
0x004325d4:	movl %edx, 0x8(%ebp)
0x004325d7:	movl %esi, %eax
0x004325d9:	pushl $0x0<UINT8>
0x004325db:	popl %eax
0x004325dc:	movl %ecx, 0x350(%esi)
0x004325e2:	testb %cl, $0x2<UINT8>
0x004325e5:	sete %al
0x004325e8:	incl %eax
0x004325e9:	cmpl %edx, $0xffffffff<UINT8>
0x004325ec:	je 51
0x004325ee:	testl %edx, %edx
0x004325f0:	je 0x00432628
0x00432628:	popl %esi
0x00432629:	popl %ebp
0x0043262a:	ret

0x0042c205:	popl %ecx
0x0042c206:	call 0x0042c6ea
0x0042c6ea:	movb %al, $0x1<UINT8>
0x0042c6ec:	ret

0x0042c20b:	testb %al, %al
0x0042c20d:	je 5
0x0042c20f:	call 0x00432ff2
0x00432ff2:	jmp 0x00432dbd
0x00432dbd:	cmpl 0x40f784, $0x0<UINT8>
0x00432dc4:	je 0x00432dc9
0x00432dc9:	pushl %esi
0x00432dca:	pushl %edi
0x00432dcb:	call 0x0043718f
0x00432dd0:	call 0x0043a42d
0x0043a42d:	movl %edi, %edi
0x0043a42f:	pushl %ebp
0x0043a430:	movl %ebp, %esp
0x0043a432:	pushl %ecx
0x0043a433:	pushl %ebx
0x0043a434:	pushl %esi
0x0043a435:	pushl %edi
0x0043a436:	call GetEnvironmentStringsW@KERNEL32.DLL
GetEnvironmentStringsW@KERNEL32.DLL: API Node	
0x0043a43c:	movl %esi, %eax
0x0043a43e:	xorl %edi, %edi
0x0043a440:	testl %esi, %esi
0x0043a442:	je 86
0x0043a444:	pushl %esi
0x0043a445:	call 0x0043a3f6
0x0043a3f6:	movl %edi, %edi
0x0043a3f8:	pushl %ebp
0x0043a3f9:	movl %ebp, %esp
0x0043a3fb:	movl %edx, 0x8(%ebp)
0x0043a3fe:	pushl %edi
0x0043a3ff:	xorl %edi, %edi
0x0043a401:	cmpw (%edx), %di
0x0043a404:	je 33
0x0043a406:	pushl %esi
0x0043a407:	movl %ecx, %edx
0x0043a409:	leal %esi, 0x2(%ecx)
0x0043a40c:	movw %ax, (%ecx)
0x0043a40f:	addl %ecx, $0x2<UINT8>
0x0043a412:	cmpw %ax, %di
0x0043a415:	jne 0x0043a40c
0x0043a417:	subl %ecx, %esi
0x0043a419:	sarl %ecx
0x0043a41b:	leal %edx, (%edx,%ecx,2)
0x0043a41e:	addl %edx, $0x2<UINT8>
0x0043a421:	cmpw (%edx), %di
0x0043a424:	jne 0x0043a407
0x0043a426:	popl %esi
0x0043a427:	leal %eax, 0x2(%edx)
0x0043a42a:	popl %edi
0x0043a42b:	popl %ebp
0x0043a42c:	ret

0x0043a44a:	popl %ecx
0x0043a44b:	pushl %edi
0x0043a44c:	pushl %edi
0x0043a44d:	pushl %edi
0x0043a44e:	movl %ebx, %eax
0x0043a450:	pushl %edi
0x0043a451:	subl %ebx, %esi
0x0043a453:	sarl %ebx
0x0043a455:	pushl %ebx
0x0043a456:	pushl %esi
0x0043a457:	pushl %edi
0x0043a458:	pushl %edi
0x0043a459:	call WideCharToMultiByte@KERNEL32.DLL
WideCharToMultiByte@KERNEL32.DLL: API Node	
0x0043a45f:	movl -4(%ebp), %eax
0x0043a462:	testl %eax, %eax
0x0043a464:	je 52
0x0043a466:	pushl %eax
0x0043a467:	call 0x004357b4
0x0043a46c:	movl %edi, %eax
0x0043a46e:	popl %ecx
0x0043a46f:	testl %edi, %edi
0x0043a471:	je 28
0x0043a473:	xorl %eax, %eax
0x0043a475:	pushl %eax
0x0043a476:	pushl %eax
0x0043a477:	pushl -4(%ebp)
0x0043a47a:	pushl %edi
0x0043a47b:	pushl %ebx
0x0043a47c:	pushl %esi
0x0043a47d:	pushl %eax
0x0043a47e:	pushl %eax
0x0043a47f:	call WideCharToMultiByte@KERNEL32.DLL
0x0043a485:	testl %eax, %eax
0x0043a487:	je 6
0x0043a489:	movl %ebx, %edi
0x0043a48b:	xorl %edi, %edi
0x0043a48d:	jmp 0x0043a491
0x0043a491:	pushl %edi
0x0043a492:	call 0x0043577a
0x0043a497:	popl %ecx
0x0043a498:	jmp 0x0043a49c
0x0043a49c:	testl %esi, %esi
0x0043a49e:	je 7
0x0043a4a0:	pushl %esi
0x0043a4a1:	call FreeEnvironmentStringsW@KERNEL32.DLL
FreeEnvironmentStringsW@KERNEL32.DLL: API Node	
0x0043a4a7:	popl %edi
0x0043a4a8:	popl %esi
0x0043a4a9:	movl %eax, %ebx
0x0043a4ab:	popl %ebx
0x0043a4ac:	movl %esp, %ebp
0x0043a4ae:	popl %ebp
0x0043a4af:	ret

0x00432dd5:	movl %esi, %eax
0x00432dd7:	testl %esi, %esi
0x00432dd9:	jne 0x00432de0
0x00432de0:	pushl %esi
0x00432de1:	call 0x00432e16
0x00432e16:	movl %edi, %edi
0x00432e18:	pushl %ebp
0x00432e19:	movl %ebp, %esp
0x00432e1b:	pushl %ecx
0x00432e1c:	pushl %ecx
0x00432e1d:	pushl %ebx
0x00432e1e:	pushl %esi
0x00432e1f:	pushl %edi
0x00432e20:	movl %edi, 0x8(%ebp)
0x00432e23:	xorl %edx, %edx
0x00432e25:	movl %esi, %edi
0x00432e27:	movb %al, (%edi)
0x00432e29:	jmp 0x00432e43
0x00432e43:	testb %al, %al
0x00432e45:	jne 0x00432e2b
0x00432e2b:	cmpb %al, $0x3d<UINT8>
0x00432e2d:	je 0x00432e30
0x00432e30:	movl %ecx, %esi
0x00432e32:	leal %ebx, 0x1(%ecx)
0x00432e35:	movb %al, (%ecx)
0x00432e37:	incl %ecx
0x00432e38:	testb %al, %al
0x00432e3a:	jne 0x00432e35
0x00432e3c:	subl %ecx, %ebx
0x00432e3e:	incl %esi
0x00432e3f:	addl %esi, %ecx
0x00432e41:	movb %al, (%esi)
0x00432e47:	leal %eax, 0x1(%edx)
0x00432e4a:	pushl $0x4<UINT8>
0x00432e4c:	pushl %eax
0x00432e4d:	call 0x00439337
0x00432e52:	movl %ebx, %eax
0x00432e54:	popl %ecx
0x00432e55:	popl %ecx
0x00432e56:	testl %ebx, %ebx
0x00432e58:	je 109
0x00432e5a:	movl -4(%ebp), %ebx
0x00432e5d:	jmp 0x00432eb1
0x00432eb1:	cmpb (%edi), $0x0<UINT8>
0x00432eb4:	jne 0x00432e5f
0x00432e5f:	movl %ecx, %edi
0x00432e61:	leal %edx, 0x1(%ecx)
0x00432e64:	movb %al, (%ecx)
0x00432e66:	incl %ecx
0x00432e67:	testb %al, %al
0x00432e69:	jne 0x00432e64
0x00432e6b:	subl %ecx, %edx
0x00432e6d:	cmpb (%edi), $0x3d<UINT8>
0x00432e70:	leal %eax, 0x1(%ecx)
0x00432e73:	movl -8(%ebp), %eax
0x00432e76:	je 0x00432eaf
0x00432eaf:	addl %edi, %eax
0x00432eb6:	jmp 0x00432ec9
0x00432ec9:	pushl $0x0<UINT8>
0x00432ecb:	call 0x0043577a
0x00432ed0:	popl %ecx
0x00432ed1:	popl %edi
0x00432ed2:	popl %esi
0x00432ed3:	movl %eax, %ebx
0x00432ed5:	popl %ebx
0x00432ed6:	movl %esp, %ebp
0x00432ed8:	popl %ebp
0x00432ed9:	ret

0x00432de6:	popl %ecx
0x00432de7:	testl %eax, %eax
0x00432de9:	jne 0x00432df0
0x00432df0:	pushl %eax
0x00432df1:	movl %ecx, $0x40f784<UINT32>
0x00432df6:	movl 0x40f790, %eax
0x00432dfb:	call 0x0042f812
0x00432e00:	xorl %edi, %edi
0x00432e02:	pushl $0x0<UINT8>
0x00432e04:	call 0x0043577a
0x00432e09:	popl %ecx
0x00432e0a:	pushl %esi
0x00432e0b:	call 0x0043577a
0x00435785:	pushl 0x8(%ebp)
0x00435788:	pushl $0x0<UINT8>
0x0043578a:	pushl 0x40fa6c
0x00435790:	call HeapFree@KERNEL32.DLL
HeapFree@KERNEL32.DLL: API Node	
0x00435796:	testl %eax, %eax
0x00435798:	jne 0x004357b2
0x00432e10:	popl %ecx
0x00432e11:	movl %eax, %edi
0x00432e13:	popl %edi
0x00432e14:	popl %esi
0x00432e15:	ret

0x0042c214:	call 0x0042c6d1
0x0042c219:	xorl %eax, %eax
0x0042c21b:	ret

0x0043307a:	testl %eax, %eax
0x0043307c:	jne 10
0x0042c224:	call 0x0042c715
0x0042c715:	call 0x00415752
0x00415752:	movl %eax, $0x40f000<UINT32>
0x00415757:	ret

0x0042c71a:	movl %ecx, 0x4(%eax)
0x0042c71d:	orl (%eax), $0x4<UINT8>
0x0042c720:	movl 0x4(%eax), %ecx
0x0042c723:	call 0x0042c70f
0x0042c70f:	movl %eax, $0x40f620<UINT32>
0x0042c714:	ret

0x0042c728:	movl %ecx, 0x4(%eax)
0x0042c72b:	orl (%eax), $0x2<UINT8>
0x0042c72e:	movl 0x4(%eax), %ecx
0x0042c731:	ret

0x0042c229:	xorl %eax, %eax
0x0042c22b:	ret

0x0043d90f:	call 0x0043718f
0x0043d914:	xorl %ecx, %ecx
0x0043d916:	testb %al, %al
0x0043d918:	sete %cl
0x0043d91b:	movl %eax, %ecx
0x0043d91d:	ret

0x00438e2e:	movl %eax, 0x40fcd0
0x00438e33:	pushl %esi
0x00438e34:	pushl $0x3<UINT8>
0x00438e36:	popl %esi
0x00438e37:	testl %eax, %eax
0x00438e39:	jne 7
0x00438e3b:	movl %eax, $0x200<UINT32>
0x00438e40:	jmp 0x00438e48
0x00438e48:	movl 0x40fcd0, %eax
0x00438e4d:	pushl $0x4<UINT8>
0x00438e4f:	pushl %eax
0x00438e50:	call 0x00439337
0x00438e55:	pushl $0x0<UINT8>
0x00438e57:	movl 0x40fcd4, %eax
0x00438e5c:	call 0x0043577a
0x00438e61:	addl %esp, $0xc<UINT8>
0x00438e64:	cmpl 0x40fcd4, $0x0<UINT8>
0x00438e6b:	jne 0x00438e98
0x00438e98:	pushl %edi
0x00438e99:	xorl %edi, %edi
0x00438e9b:	movl %esi, $0x4106b0<UINT32>
0x00438ea0:	pushl $0x0<UINT8>
0x00438ea2:	pushl $0xfa0<UINT32>
0x00438ea7:	leal %eax, 0x20(%esi)
0x00438eaa:	pushl %eax
0x00438eab:	call 0x00436182
0x00438eb0:	movl %eax, 0x40fcd4
0x00438eb5:	movl %edx, %edi
0x00438eb7:	sarl %edx, $0x6<UINT8>
0x00438eba:	movl (%eax,%edi,4), %esi
0x00438ebd:	movl %eax, %edi
0x00438ebf:	andl %eax, $0x3f<UINT8>
0x00438ec2:	imull %ecx, %eax, $0x30<UINT8>
0x00438ec5:	movl %eax, 0x40fa70(,%edx,4)
0x00438ecc:	movl %eax, 0x18(%eax,%ecx)
0x00438ed0:	cmpl %eax, $0xffffffff<UINT8>
0x00438ed3:	je 9
0x00438ed5:	cmpl %eax, $0xfffffffe<UINT8>
0x00438ed8:	je 4
0x00438eda:	testl %eax, %eax
0x00438edc:	jne 0x00438ee5
0x00438ee5:	addl %esi, $0x38<UINT8>
0x00438ee8:	incl %edi
0x00438ee9:	cmpl %esi, $0x410758<UINT32>
0x00438eef:	jne 0x00438ea0
0x00438ef1:	popl %edi
0x00438ef2:	xorl %eax, %eax
0x00438ef4:	popl %esi
0x00438ef5:	ret

0x0044142d:	pushl $0xa<UINT8>
0x0044142f:	call 0x00442c7a
0x00441434:	movl 0x40fcf4, %eax
0x00441439:	xorl %eax, %eax
0x0044143b:	ret

0x00433086:	xorl %eax, %eax
0x00433088:	movl %ecx, -4(%ebp)
0x0043308b:	popl %edi
0x0043308c:	xorl %ecx, %ebp
0x0043308e:	popl %esi
0x0043308f:	call 0x0042c018
0x00433094:	movl %esp, %ebp
0x00433096:	popl %ebp
0x00433097:	ret

0x0042c293:	popl %ecx
0x0042c294:	popl %ecx
0x0042c295:	testl %eax, %eax
0x0042c297:	je 0x0042c2aa
0x0042c2aa:	pushl $0x402008<UINT32>
0x0042c2af:	pushl $0x402000<UINT32>
0x0042c2b4:	call 0x00432ff7
0x00432ff7:	movl %edi, %edi
0x00432ff9:	pushl %ebp
0x00432ffa:	movl %ebp, %esp
0x00432ffc:	pushl %ecx
0x00432ffd:	pushl %ecx
0x00432ffe:	movl %eax, 0x410030
0x00433003:	xorl %eax, %ebp
0x00433005:	movl -4(%ebp), %eax
0x00433008:	movl %eax, 0xc(%ebp)
0x0043300b:	pushl %ebx
0x0043300c:	pushl %esi
0x0043300d:	movl %esi, 0x8(%ebp)
0x00433010:	subl %eax, %esi
0x00433012:	addl %eax, $0x3<UINT8>
0x00433015:	pushl %edi
0x00433016:	xorl %edi, %edi
0x00433018:	shrl %eax, $0x2<UINT8>
0x0043301b:	cmpl 0xc(%ebp), %esi
0x0043301e:	sbbl %ebx, %ebx
0x00433020:	notl %ebx
0x00433022:	andl %ebx, %eax
0x00433024:	je 28
0x00433026:	movl %eax, (%esi)
0x00433028:	movl -8(%ebp), %eax
0x0043302b:	testl %eax, %eax
0x0043302d:	je 0x0043303a
0x0043303a:	addl %esi, $0x4<UINT8>
0x0043303d:	incl %edi
0x0043303e:	cmpl %edi, %ebx
0x00433040:	jne 0x00433026
0x0043302f:	movl %ecx, %eax
0x00433031:	call 0x0042c70e
0x00433037:	call 0x0042c22c
0x0042c22c:	call 0x0042c8dc
0x0042c8dc:	pushl $0x42c8e8<UINT32>
0x0042c8e1:	call SetUnhandledExceptionFilter@KERNEL32.DLL
SetUnhandledExceptionFilter@KERNEL32.DLL: API Node	
0x0042c8e7:	ret

0x0042c231:	call 0x0042c6d1
0x0042c236:	pushl %eax
0x0042c237:	call 0x00433360
0x00433360:	movl %edi, %edi
0x00433362:	pushl %ebp
0x00433363:	movl %ebp, %esp
0x00433365:	movl %eax, 0x8(%ebp)
0x00433368:	testl %eax, %eax
0x0043336a:	je 0x00433386
0x00433386:	movl %ecx, $0x40f798<UINT32>
0x0043338b:	xchgl (%ecx), %eax
0x0043338d:	popl %ebp
0x0043338e:	ret

0x0042c23c:	popl %ecx
0x0042c23d:	ret

0x00433042:	movl %ecx, -4(%ebp)
0x00433045:	popl %edi
0x00433046:	popl %esi
0x00433047:	xorl %ecx, %ebp
0x00433049:	popl %ebx
0x0043304a:	call 0x0042c018
0x0043304f:	movl %esp, %ebp
0x00433051:	popl %ebp
0x00433052:	ret

0x0042c2b9:	popl %ecx
0x0042c2ba:	popl %ecx
0x0042c2bb:	movl 0x40f5f4, $0x2<UINT32>
0x0042c2c5:	jmp 0x0042c2cc
0x0042c2cc:	pushl -36(%ebp)
0x0042c2cf:	call 0x0042c5a0
0x0042c5a0:	pushl %ebp
0x0042c5a1:	movl %ebp, %esp
0x0042c5a3:	call 0x0042cb85
0x0042c5a8:	testl %eax, %eax
0x0042c5aa:	je 0x0042c5bb
0x0042c5bb:	popl %ebp
0x0042c5bc:	ret

0x0042c2d4:	popl %ecx
0x0042c2d5:	call 0x0042c73e
0x0042c73e:	movl %eax, $0x40f62c<UINT32>
0x0042c743:	ret

0x0042c2da:	movl %esi, %eax
0x0042c2dc:	xorl %edi, %edi
0x0042c2de:	cmpl (%esi), %edi
0x0042c2e0:	je 0x0042c2fc
0x0042c2fc:	call 0x0042c744
0x0042c744:	movl %eax, $0x40f630<UINT32>
0x0042c749:	ret

0x0042c301:	movl %esi, %eax
0x0042c303:	cmpl (%esi), %edi
0x0042c305:	je 0x0042c31a
0x0042c31a:	call 0x0042c865
0x0042c865:	pushl %ebp
0x0042c866:	movl %ebp, %esp
0x0042c868:	subl %esp, $0x44<UINT8>
0x0042c86b:	pushl $0x44<UINT8>
0x0042c86d:	leal %eax, -68(%ebp)
0x0042c870:	pushl $0x0<UINT8>
0x0042c872:	pushl %eax
0x0042c873:	call 0x0042f0c0
0x0042c878:	addl %esp, $0xc<UINT8>
0x0042c87b:	leal %eax, -68(%ebp)
0x0042c87e:	pushl %eax
0x0042c87f:	call GetStartupInfoW@KERNEL32.DLL
0x0042c885:	testb -24(%ebp), $0x1<UINT8>
0x0042c889:	je 0x0042c891
0x0042c891:	pushl $0xa<UINT8>
0x0042c893:	popl %eax
0x0042c894:	movl %esp, %ebp
0x0042c896:	popl %ebp
0x0042c897:	ret

0x0042c31f:	movzwl %eax, %ax
0x0042c322:	pushl %eax
0x0042c323:	call 0x00432d6a
0x00432d6a:	movl %edi, %edi
0x00432d6c:	pushl %ebx
0x00432d6d:	pushl %esi
0x00432d6e:	call 0x0043718f
0x00432d73:	movl %esi, 0x40fc80
0x00432d79:	testl %esi, %esi
0x00432d7b:	jne 0x00432d82
0x00432d82:	xorb %bl, %bl
0x00432d84:	movb %al, (%esi)
0x00432d86:	cmpb %al, $0x20<UINT8>
0x00432d88:	jg 0x00432d92
0x00432d92:	cmpb %al, $0x22<UINT8>
0x00432d94:	jne 5
0x00432d96:	testb %bl, %bl
0x00432d98:	sete %bl
0x00432d9b:	movsbl %eax, %al
0x00432d9e:	pushl %eax
0x00432d9f:	call 0x00439e42
0x00432da4:	popl %ecx
0x00432da5:	testl %eax, %eax
0x00432da7:	je 0x00432daa
0x00432daa:	incl %esi
0x00432dab:	jmp 0x00432d84
0x00432d8a:	testb %al, %al
0x00432d8c:	je 0x00432db8
0x00432db8:	movl %eax, %esi
0x00432dba:	popl %esi
0x00432dbb:	popl %ebx
0x00432dbc:	ret

0x0042c328:	pushl %eax
0x0042c329:	pushl %edi
0x0042c32a:	pushl $0x400000<UINT32>
0x0042c32f:	call 0x00429e78
0x00429e78:	pushl %ebp
0x00429e79:	pushl %ebx
0x00429e7a:	pushl %edi
0x00429e7b:	pushl %esi
0x00429e7c:	subl %esp, $0x858<UINT32>
0x00429e82:	movl %eax, 0x410030
0x00429e87:	movl %esi, 0x86c(%esp)
0x00429e8e:	movl 0x854(%esp), %eax
0x00429e95:	call 0x0042998c
0x0042998c:	cmpl 0x40f180, $0x0<UINT8>
0x00429993:	je 0x0042999d
0x0042999d:	pushl $0x407d96<UINT32>
0x004299a2:	call 0x00429917
0x00429917:	pushl %ebx
0x00429918:	pushl %edi
0x00429919:	pushl %esi
0x0042991a:	movl %eax, 0x40f188
0x0042991f:	movl %esi, 0x10(%esp)
0x00429923:	testl %eax, %eax
0x00429925:	jne 58
0x00429927:	movl %edi, 0x44448c
0x0042992d:	xorl %eax, %eax
0x0042992f:	xorl %ebx, %ebx
0x00429931:	leal %ecx, (%ebx,%ebx,2)
0x00429934:	movl %ebx, %ecx
0x00429936:	shrl %ebx, $0x1f<UINT8>
0x00429939:	addl %ebx, %ecx
0x0042993b:	sarl %ebx
0x0042993d:	addl %ebx, $0x200<UINT32>
0x00429943:	pushl $0x1<UINT8>
0x00429945:	pushl %ebx
0x00429946:	pushl %eax
0x00429947:	call 0x00415134
0x00415134:	pushl %esi
0x00415135:	subl %esp, $0xcc<UINT32>
0x0041513b:	movl %eax, 0x410030
0x00415140:	movl %ecx, 0xdc(%esp)
0x00415147:	movl %esi, 0xd8(%esp)
0x0041514e:	xorl %edx, %edx
0x00415150:	movl 0xc8(%esp), %eax
0x00415157:	movl %eax, $0x7fffffff<UINT32>
0x0041515c:	divl %eax, %ecx
0x0041515e:	cmpl %eax, %esi
0x00415160:	jb 41
0x00415162:	movl %eax, 0xd4(%esp)
0x00415169:	imull %ecx, %esi
0x0041516c:	testl %eax, %eax
0x0041516e:	je 0x0041517c
0x0041517c:	pushl %ecx
0x0041517d:	call 0x00434e7d
0x00434e7d:	movl %edi, %edi
0x00434e7f:	pushl %ebp
0x00434e80:	movl %ebp, %esp
0x00434e82:	popl %ebp
0x00434e83:	jmp 0x004357b4
0x00415182:	addl %esp, $0x4<UINT8>
0x00415185:	movl %esi, %eax
0x00415187:	testl %esi, %esi
0x00415189:	jne 0x004151ad
0x004151ad:	movl %ecx, 0xc8(%esp)
0x004151b4:	call 0x0042c018
0x004151b9:	movl %eax, %esi
0x004151bb:	addl %esp, $0xcc<UINT32>
0x004151c1:	popl %esi
0x004151c2:	ret

0x0042994c:	addl %esp, $0xc<UINT8>
0x0042994f:	movl 0x40f188, %eax
0x00429954:	pushl %ebx
0x00429955:	pushl %eax
0x00429956:	call GetSystemDirectoryA@KERNEL32.DLL
GetSystemDirectoryA@KERNEL32.DLL: API Node	
0x00429958:	cmpl %eax, %ebx
0x0042995a:	movl %eax, 0x40f188
0x0042995f:	jnl -48
0x00429961:	pushl $0x0<UINT8>
0x00429963:	pushl %esi
0x00429964:	pushl $0x407dbc<UINT32>
0x00429969:	pushl %eax
0x0042996a:	call 0x004151d0
0x004151d0:	pushl %ebp
0x004151d1:	pushl %ebx
0x004151d2:	pushl %edi
0x004151d3:	pushl %esi
0x004151d4:	subl %esp, $0x8<UINT8>
0x004151d7:	movl %eax, 0x410030
0x004151dc:	movl %ebx, 0x1c(%esp)
0x004151e0:	movl 0x4(%esp), %eax
0x004151e4:	pushl %ebx
0x004151e5:	call 0x00435150
0x00435150:	movl %ecx, 0x4(%esp)
0x00435154:	testl %ecx, $0x3<UINT32>
0x0043515a:	je 0x00435180
0x00435180:	movl %eax, (%ecx)
0x00435182:	movl %edx, $0x7efefeff<UINT32>
0x00435187:	addl %edx, %eax
0x00435189:	xorl %eax, $0xffffffff<UINT8>
0x0043518c:	xorl %eax, %edx
0x0043518e:	addl %ecx, $0x4<UINT8>
0x00435191:	testl %eax, $0x81010100<UINT32>
0x00435196:	je 0x00435180
0x00435198:	movl %eax, -4(%ecx)
0x0043519b:	testb %al, %al
0x0043519d:	je 0x004351d1
0x0043519f:	testb %ah, %ah
0x004351a1:	je 0x004351c7
0x004351a3:	testl %eax, $0xff0000<UINT32>
0x004351a8:	je 0x004351bd
0x004351aa:	testl %eax, $0xff000000<UINT32>
0x004351af:	je 0x004351b3
0x004351b3:	leal %eax, -1(%ecx)
0x004351b6:	movl %ecx, 0x4(%esp)
0x004351ba:	subl %eax, %ecx
0x004351bc:	ret

0x004151ea:	addl %esp, $0x4<UINT8>
0x004151ed:	leal %edi, 0x24(%esp)
0x004151f1:	movl %esi, %eax
0x004151f3:	movl (%esp), %edi
0x004151f6:	movl %eax, -4(%edi)
0x004151f9:	testl %eax, %eax
0x004151fb:	je 31
0x004151fd:	leal %ebp, 0x20(%esp)
0x00415201:	addl %ebp, $0x8<UINT8>
0x00415204:	pushl %eax
0x00415205:	call 0x00435150
0x004351c7:	leal %eax, -3(%ecx)
0x004351ca:	movl %ecx, 0x4(%esp)
0x004351ce:	subl %eax, %ecx
0x004351d0:	ret

0x0041520a:	addl %esp, $0x4<UINT8>
0x0041520d:	movl (%esp), %ebp
0x00415210:	addl %esi, %eax
0x00415212:	movl %eax, -4(%ebp)
0x00415215:	addl %ebp, $0x4<UINT8>
0x00415218:	testl %eax, %eax
0x0041521a:	jne 0x00415204
0x0043515c:	movb %al, (%ecx)
0x0043515e:	addl %ecx, $0x1<UINT8>
0x00435161:	testb %al, %al
0x00435163:	je 78
0x00435165:	testl %ecx, $0x3<UINT32>
0x0043516b:	jne 0x0043515c
0x0043516d:	addl %eax, $0x0<UINT32>
0x00435172:	leal %esp, (%esp)
0x00435179:	leal %esp, (%esp)
0x004351bd:	leal %eax, -2(%ecx)
0x004351c0:	movl %ecx, 0x4(%esp)
0x004351c4:	subl %eax, %ecx
0x004351c6:	ret

0x0041521c:	incl %esi
0x0041521d:	xorl %eax, %eax
0x0041521f:	incl %eax
0x00415220:	pushl %eax
0x00415221:	pushl %esi
0x00415222:	call 0x004150b4
0x004150b4:	pushl %esi
0x004150b5:	subl %esp, $0xcc<UINT32>
0x004150bb:	movl %eax, 0x410030
0x004150c0:	movl %ecx, 0xd8(%esp)
0x004150c7:	movl %esi, 0xd4(%esp)
0x004150ce:	xorl %edx, %edx
0x004150d0:	movl 0xc8(%esp), %eax
0x004150d7:	movl %eax, $0x7fffffff<UINT32>
0x004150dc:	divl %eax, %ecx
0x004150de:	cmpl %eax, %esi
0x004150e0:	jb 26
0x004150e2:	imull %ecx, %esi
0x004150e5:	xorl %eax, %eax
0x004150e7:	incl %eax
0x004150e8:	testl %ecx, %ecx
0x004150ea:	cmovnel %eax, %ecx
0x004150ed:	pushl %eax
0x004150ee:	call 0x00434e7d
0x004150f3:	addl %esp, $0x4<UINT8>
0x004150f6:	movl %esi, %eax
0x004150f8:	testl %esi, %esi
0x004150fa:	jne 0x0041511e
0x0041511e:	movl %ecx, 0xc8(%esp)
0x00415125:	call 0x0042c018
0x0041512a:	movl %eax, %esi
0x0041512c:	addl %esp, $0xcc<UINT32>
0x00415132:	popl %esi
0x00415133:	ret

0x00415227:	addl %esp, $0x8<UINT8>
0x0041522a:	movl %esi, %eax
0x0041522c:	pushl %ebx
0x0041522d:	pushl %esi
0x0041522e:	call 0x00434f70
0x00434f70:	pushl %edi
0x00434f71:	movl %edi, 0x8(%esp)
0x00434f75:	jmp 0x00434fe5
0x00434fe5:	movl %ecx, 0xc(%esp)
0x00434fe9:	testl %ecx, $0x3<UINT32>
0x00434fef:	je 0x0043500e
0x0043500e:	movl %edx, $0x7efefeff<UINT32>
0x00435013:	movl %eax, (%ecx)
0x00435015:	addl %edx, %eax
0x00435017:	xorl %eax, $0xffffffff<UINT8>
0x0043501a:	xorl %eax, %edx
0x0043501c:	movl %edx, (%ecx)
0x0043501e:	addl %ecx, $0x4<UINT8>
0x00435021:	testl %eax, $0x81010100<UINT32>
0x00435026:	je 0x00435009
0x00435009:	movl (%edi), %edx
0x0043500b:	addl %edi, $0x4<UINT8>
0x00435028:	testb %dl, %dl
0x0043502a:	je 52
0x0043502c:	testb %dh, %dh
0x0043502e:	je 0x00435057
0x00435030:	testl %edx, $0xff0000<UINT32>
0x00435036:	je 0x0043504a
0x00435038:	testl %edx, $0xff000000<UINT32>
0x0043503e:	je 0x00435042
0x00435042:	movl (%edi), %edx
0x00435044:	movl %eax, 0x8(%esp)
0x00435048:	popl %edi
0x00435049:	ret

0x00415233:	addl %esp, $0x8<UINT8>
0x00415236:	pushl %esi
0x00415237:	call 0x00435150
0x0041523c:	addl %esp, $0x4<UINT8>
0x0041523f:	movl (%esp), %edi
0x00415242:	movl %ecx, 0x20(%esp)
0x00415246:	testl %ecx, %ecx
0x00415248:	je 40
0x0041524a:	movl %edi, %esi
0x0041524c:	addl %edi, %eax
0x0041524e:	pushl %ecx
0x0041524f:	pushl %edi
0x00415250:	call 0x00434f70
0x00435057:	movw (%edi), %dx
0x0043505a:	movl %eax, 0x8(%esp)
0x0043505e:	popl %edi
0x0043505f:	ret

0x00415255:	addl %esp, $0x8<UINT8>
0x00415258:	pushl %edi
0x00415259:	call 0x00435150
0x004351d1:	leal %eax, -4(%ecx)
0x004351d4:	movl %ecx, 0x4(%esp)
0x004351d8:	subl %eax, %ecx
0x004351da:	ret

0x0041525e:	addl %esp, $0x4<UINT8>
0x00415261:	movl %edx, (%esp)
0x00415264:	addl %edi, %eax
0x00415266:	leal %ecx, 0x4(%edx)
0x00415269:	movl (%esp), %ecx
0x0041526c:	movl %ecx, (%edx)
0x0041526e:	testl %ecx, %ecx
0x00415270:	jne 0x0041524e
0x00434ff1:	movb %dl, (%ecx)
0x00434ff3:	addl %ecx, $0x1<UINT8>
0x00434ff6:	testb %dl, %dl
0x00434ff8:	je 102
0x00434ffa:	movb (%edi), %dl
0x00434ffc:	addl %edi, $0x1<UINT8>
0x00434fff:	testl %ecx, $0x3<UINT32>
0x00435005:	jne 0x00434ff1
0x00435007:	jmp 0x0043500e
0x0043504a:	movw (%edi), %dx
0x0043504d:	movl %eax, 0x8(%esp)
0x00435051:	movb 0x2(%edi), $0x0<UINT8>
0x00435055:	popl %edi
0x00435056:	ret

0x00415272:	movl %ecx, 0x4(%esp)
0x00415276:	call 0x0042c018
0x0041527b:	movl %eax, %esi
0x0041527d:	addl %esp, $0x8<UINT8>
0x00415280:	popl %esi
0x00415281:	popl %edi
0x00415282:	popl %ebx
0x00415283:	popl %ebp
0x00415284:	ret

0x0042996f:	addl %esp, $0x10<UINT8>
0x00429972:	movl %esi, %eax
0x00429974:	pushl %esi
0x00429975:	call LoadLibraryA@KERNEL32.DLL
0x0042997b:	movl %edi, %eax
0x0042997d:	pushl %esi
0x0042997e:	call 0x004151c3
0x004151c3:	movl %eax, 0x4(%esp)
0x004151c7:	testl %eax, %eax
0x004151c9:	jne 0x00434dae
0x00434dae:	jmp 0x0043577a
0x00429983:	addl %esp, $0x4<UINT8>
0x00429986:	movl %eax, %edi
0x00429988:	popl %esi
0x00429989:	popl %edi
0x0042998a:	popl %ebx
0x0042998b:	ret

0x004299a7:	addl %esp, $0x4<UINT8>
0x004299aa:	testl %eax, %eax
0x004299ac:	movl 0x40f180, %eax
0x004299b1:	je 16
0x004299b3:	pushl $0x407da3<UINT32>
0x004299b8:	pushl %eax
0x004299b9:	call GetProcAddress@KERNEL32.DLL
0x004299bf:	movl %ecx, %eax
0x004299c1:	jmp 0x004299c5
0x004299c5:	movl 0x40f184, %ecx
0x004299cb:	testl %ecx, %ecx
0x004299cd:	je 7
0x004299cf:	pushl $0xc00<UINT32>
0x004299d4:	call SetDefaultDllDirectories@C:\Windows\system32\kernel32.dll
SetDefaultDllDirectories@C:\Windows\system32\kernel32.dll: API Node	
0x004299d6:	ret

0x00000c00:	addb (%eax), %al
0x00000c02:	addb (%eax), %al
0x00000c04:	addb (%eax), %al
0x00000c06:	addb (%eax), %al
0x00000c08:	addb (%eax), %al
0x00000c0a:	addb (%eax), %al
0x00000c0c:	addb (%eax), %al
0x00000c0e:	addb (%eax), %al
0x00000c10:	addb (%eax), %al
0x00000c12:	addb (%eax), %al
0x00000c14:	addb (%eax), %al
0x00000c16:	addb (%eax), %al
0x00000c18:	addb (%eax), %al
0x00000c1a:	addb (%eax), %al
0x00000c1c:	addb (%eax), %al
0x00000c1e:	addb (%eax), %al
0x00000c20:	addb (%eax), %al
0x00000c22:	addb (%eax), %al
0x00000c24:	addb (%eax), %al
0x00000c26:	addb (%eax), %al
0x00000c28:	addb (%eax), %al
0x00000c2a:	addb (%eax), %al
0x00000c2c:	addb (%eax), %al
0x00000c2e:	addb (%eax), %al
0x00000c30:	addb (%eax), %al
0x00000c32:	addb (%eax), %al
0x00000c34:	addb (%eax), %al
0x00000c36:	addb (%eax), %al
0x00000c38:	addb (%eax), %al
0x00000c3a:	addb (%eax), %al
0x00000c3c:	addb (%eax), %al
0x00000c3e:	addb (%eax), %al
0x00000c40:	addb (%eax), %al
0x00000c42:	addb (%eax), %al
0x00000c44:	addb (%eax), %al
0x00000c46:	addb (%eax), %al
0x00000c48:	addb (%eax), %al
0x00000c4a:	addb (%eax), %al
0x00000c4c:	addb (%eax), %al
0x00000c4e:	addb (%eax), %al
0x00000c50:	addb (%eax), %al
0x00000c52:	addb (%eax), %al
0x00000c54:	addb (%eax), %al
0x00000c56:	addb (%eax), %al
0x00000c58:	addb (%eax), %al
0x00000c5a:	addb (%eax), %al
0x00000c5c:	addb (%eax), %al
0x00000c5e:	addb (%eax), %al
0x00000c60:	addb (%eax), %al
0x00000c62:	addb (%eax), %al
0x00000c64:	addb (%eax), %al
0x00000c66:	addb (%eax), %al
0x0043d53a:	je 0x0043d574
0x0043d574:	leal %edx, (%esi,%esi)
0x0043d577:	leal %ecx, 0x8(%edx)
0x0043d57a:	cmpl %edx, %ecx
0x0043d57c:	sbbl %eax, %eax
0x0043d57e:	testl %ecx, %eax
0x0043d580:	je 0x0043d5cc
0x0043d5cc:	xorl %edi, %edi
0x0043d5ce:	testl %edi, %edi
0x0043d5d0:	je 0x0043d60a
0x0043d60a:	pushl %edi
0x0043d60b:	call 0x0043958a
0x0043d610:	popl %ecx
