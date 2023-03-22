0x0082abc0:	pusha
0x0082abc1:	movl %esi, $0x795000<UINT32>
0x0082abc6:	leal %edi, -3751936(%esi)
0x0082abcc:	pushl %edi
0x0082abcd:	orl %ebp, $0xffffffff<UINT8>
0x0082abd0:	jmp 0x0082abe2
0x0082abe2:	movl %ebx, (%esi)
0x0082abe4:	subl %esi, $0xfffffffc<UINT8>
0x0082abe7:	adcl %ebx, %ebx
0x0082abe9:	jb 0x0082abd8
0x0082abd8:	movb %al, (%esi)
0x0082abda:	incl %esi
0x0082abdb:	movb (%edi), %al
0x0082abdd:	incl %edi
0x0082abde:	addl %ebx, %ebx
0x0082abe0:	jne 0x0082abe9
0x0082abeb:	movl %eax, $0x1<UINT32>
0x0082abf0:	addl %ebx, %ebx
0x0082abf2:	jne 0x0082abfb
0x0082abfb:	adcl %eax, %eax
0x0082abfd:	addl %ebx, %ebx
0x0082abff:	jae 0x0082ac0c
0x0082ac01:	jne 0x0082ac2b
0x0082ac2b:	xorl %ecx, %ecx
0x0082ac2d:	subl %eax, $0x3<UINT8>
0x0082ac30:	jb 0x0082ac43
0x0082ac43:	addl %ebx, %ebx
0x0082ac45:	jne 0x0082ac4e
0x0082ac4e:	jb 0x0082ac1c
0x0082ac1c:	addl %ebx, %ebx
0x0082ac1e:	jne 0x0082ac27
0x0082ac27:	adcl %ecx, %ecx
0x0082ac29:	jmp 0x0082ac7d
0x0082ac7d:	cmpl %ebp, $0xfffffb00<UINT32>
0x0082ac83:	adcl %ecx, $0x2<UINT8>
0x0082ac86:	leal %edx, (%edi,%ebp)
0x0082ac89:	cmpl %ebp, $0xfffffffc<UINT8>
0x0082ac8c:	jbe 0x0082ac9c
0x0082ac8e:	movb %al, (%edx)
0x0082ac90:	incl %edx
0x0082ac91:	movb (%edi), %al
0x0082ac93:	incl %edi
0x0082ac94:	decl %ecx
0x0082ac95:	jne 0x0082ac8e
0x0082ac97:	jmp 0x0082abde
0x0082ac32:	shll %eax, $0x8<UINT8>
0x0082ac35:	movb %al, (%esi)
0x0082ac37:	incl %esi
0x0082ac38:	xorl %eax, $0xffffffff<UINT8>
0x0082ac3b:	je 0x0082acb2
0x0082ac3d:	sarl %eax
0x0082ac3f:	movl %ebp, %eax
0x0082ac41:	jmp 0x0082ac4e
0x0082ac9c:	movl %eax, (%edx)
0x0082ac9e:	addl %edx, $0x4<UINT8>
0x0082aca1:	movl (%edi), %eax
0x0082aca3:	addl %edi, $0x4<UINT8>
0x0082aca6:	subl %ecx, $0x4<UINT8>
0x0082aca9:	ja 0x0082ac9c
0x0082acab:	addl %edi, %ecx
0x0082acad:	jmp 0x0082abde
0x0082ac20:	movl %ebx, (%esi)
0x0082ac22:	subl %esi, $0xfffffffc<UINT8>
0x0082ac25:	adcl %ebx, %ebx
0x0082ac50:	incl %ecx
0x0082ac51:	addl %ebx, %ebx
0x0082ac53:	jne 0x0082ac5c
0x0082ac5c:	jb 0x0082ac1c
0x0082ac0c:	decl %eax
0x0082ac0d:	addl %ebx, %ebx
0x0082ac0f:	jne 0x0082ac18
0x0082ac18:	adcl %eax, %eax
0x0082ac1a:	jmp 0x0082abf0
0x0082abf4:	movl %ebx, (%esi)
0x0082abf6:	subl %esi, $0xfffffffc<UINT8>
0x0082abf9:	adcl %ebx, %ebx
0x0082ac5e:	addl %ebx, %ebx
0x0082ac60:	jne 0x0082ac69
0x0082ac69:	adcl %ecx, %ecx
0x0082ac6b:	addl %ebx, %ebx
0x0082ac6d:	jae 0x0082ac5e
0x0082ac6f:	jne 0x0082ac7a
0x0082ac7a:	addl %ecx, $0x2<UINT8>
0x0082ac55:	movl %ebx, (%esi)
0x0082ac57:	subl %esi, $0xfffffffc<UINT8>
0x0082ac5a:	adcl %ebx, %ebx
0x0082ac03:	movl %ebx, (%esi)
0x0082ac05:	subl %esi, $0xfffffffc<UINT8>
0x0082ac08:	adcl %ebx, %ebx
0x0082ac0a:	jb 0x0082ac2b
0x0082ac71:	movl %ebx, (%esi)
0x0082ac73:	subl %esi, $0xfffffffc<UINT8>
0x0082ac76:	adcl %ebx, %ebx
0x0082ac78:	jae 0x0082ac5e
0x0082ac62:	movl %ebx, (%esi)
0x0082ac64:	subl %esi, $0xfffffffc<UINT8>
0x0082ac67:	adcl %ebx, %ebx
0x0082ac11:	movl %ebx, (%esi)
0x0082ac13:	subl %esi, $0xfffffffc<UINT8>
0x0082ac16:	adcl %ebx, %ebx
0x0082ac47:	movl %ebx, (%esi)
0x0082ac49:	subl %esi, $0xfffffffc<UINT8>
0x0082ac4c:	adcl %ebx, %ebx
0x0082acb2:	popl %esi
0x0082acb3:	movl %edi, %esi
0x0082acb5:	movl %ecx, $0x195d<UINT32>
0x0082acba:	movb %al, (%edi)
0x0082acbc:	incl %edi
0x0082acbd:	subb %al, $0xffffffe8<UINT8>
0x0082acbf:	cmpb %al, $0x1<UINT8>
0x0082acc1:	ja 0x0082acba
0x0082acc3:	cmpb (%edi), $0x9<UINT8>
0x0082acc6:	jne 0x0082acba
0x0082acc8:	movl %eax, (%edi)
0x0082acca:	movb %bl, 0x4(%edi)
0x0082accd:	shrw %ax, $0x8<UINT8>
0x0082acd1:	roll %eax, $0x10<UINT8>
0x0082acd4:	xchgb %ah, %al
0x0082acd6:	subl %eax, %edi
0x0082acd8:	subb %bl, $0xffffffe8<UINT8>
0x0082acdb:	addl %eax, %esi
0x0082acdd:	movl (%edi), %eax
0x0082acdf:	addl %edi, $0x5<UINT8>
0x0082ace2:	movb %al, %bl
0x0082ace4:	loop 0x0082acbf
0x0082ace6:	leal %edi, 0x425000(%esi)
0x0082acec:	movl %eax, (%edi)
0x0082acee:	orl %eax, %eax
0x0082acf0:	je 0x0082ad37
0x0082acf2:	movl %ebx, 0x4(%edi)
0x0082acf5:	leal %eax, 0x42e0c8(%eax,%esi)
0x0082acfc:	addl %ebx, %esi
0x0082acfe:	pushl %eax
0x0082acff:	addl %edi, $0x8<UINT8>
0x0082ad02:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x0082ad08:	xchgl %ebp, %eax
0x0082ad09:	movb %al, (%edi)
0x0082ad0b:	incl %edi
0x0082ad0c:	orb %al, %al
0x0082ad0e:	je 0x0082acec
0x0082ad10:	movl %ecx, %edi
0x0082ad12:	jns 0x0082ad1b
0x0082ad1b:	pushl %edi
0x0082ad1c:	decl %eax
0x0082ad1d:	repn scasb %al, %es:(%edi)
0x0082ad1f:	pushl %ebp
0x0082ad20:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0082ad26:	orl %eax, %eax
0x0082ad28:	je 7
0x0082ad2a:	movl (%ebx), %eax
0x0082ad2c:	addl %ebx, $0x4<UINT8>
0x0082ad2f:	jmp 0x0082ad09
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x0082ad14:	movzwl %eax, (%edi)
0x0082ad17:	incl %edi
0x0082ad18:	pushl %eax
0x0082ad19:	incl %edi
0x0082ad1a:	movl %ecx, $0xaef24857<UINT32>
0x0082ad37:	addl %edi, $0x4<UINT8>
0x0082ad3a:	leal %ebx, -4(%esi)
0x0082ad3d:	xorl %eax, %eax
0x0082ad3f:	movb %al, (%edi)
0x0082ad41:	incl %edi
0x0082ad42:	orl %eax, %eax
0x0082ad44:	je 0x0082ad68
0x0082ad46:	cmpb %al, $0xffffffef<UINT8>
0x0082ad48:	ja 0x0082ad5b
0x0082ad4a:	addl %ebx, %eax
0x0082ad4c:	movl %eax, (%ebx)
0x0082ad4e:	xchgb %ah, %al
0x0082ad50:	roll %eax, $0x10<UINT8>
0x0082ad53:	xchgb %ah, %al
0x0082ad55:	addl %eax, %esi
0x0082ad57:	movl (%ebx), %eax
0x0082ad59:	jmp 0x0082ad3d
0x0082ad5b:	andb %al, $0xf<UINT8>
0x0082ad5d:	shll %eax, $0x10<UINT8>
0x0082ad60:	movw %ax, (%edi)
0x0082ad63:	addl %edi, $0x2<UINT8>
0x0082ad66:	jmp 0x0082ad4a
0x0082ad68:	movl %ebp, 0x42e20c(%esi)
0x0082ad6e:	leal %edi, -4096(%esi)
0x0082ad74:	movl %ebx, $0x1000<UINT32>
0x0082ad79:	pushl %eax
0x0082ad7a:	pushl %esp
0x0082ad7b:	pushl $0x4<UINT8>
0x0082ad7d:	pushl %ebx
0x0082ad7e:	pushl %edi
0x0082ad7f:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0082ad81:	leal %eax, 0x21f(%edi)
0x0082ad87:	andb (%eax), $0x7f<UINT8>
0x0082ad8a:	andb 0x28(%eax), $0x7f<UINT8>
0x0082ad8e:	popl %eax
0x0082ad8f:	pushl %eax
0x0082ad90:	pushl %esp
0x0082ad91:	pushl %eax
0x0082ad92:	pushl %ebx
0x0082ad93:	pushl %edi
0x0082ad94:	call VirtualProtect@kernel32.dll
0x0082ad96:	popl %eax
0x0082ad97:	popa
0x0082ad98:	leal %eax, -128(%esp)
0x0082ad9c:	pushl $0x0<UINT8>
0x0082ad9e:	cmpl %esp, %eax
0x0082ada0:	jne 0x0082ad9c
0x0082ada2:	subl %esp, $0xffffff80<UINT8>
0x0082ada5:	jmp 0x00434dac
0x00434dac:	call 0x0043fcd8
0x0043fcd8:	pushl %ebp
0x0043fcd9:	movl %ebp, %esp
0x0043fcdb:	subl %esp, $0x14<UINT8>
0x0043fcde:	andl -12(%ebp), $0x0<UINT8>
0x0043fce2:	andl -8(%ebp), $0x0<UINT8>
0x0043fce6:	movl %eax, 0x464180
0x0043fceb:	pushl %esi
0x0043fcec:	pushl %edi
0x0043fced:	movl %edi, $0xbb40e64e<UINT32>
0x0043fcf2:	movl %esi, $0xffff0000<UINT32>
0x0043fcf7:	cmpl %eax, %edi
0x0043fcf9:	je 0x0043fd08
0x0043fd08:	leal %eax, -12(%ebp)
0x0043fd0b:	pushl %eax
0x0043fd0c:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0043fd12:	movl %eax, -8(%ebp)
0x0043fd15:	xorl %eax, -12(%ebp)
0x0043fd18:	movl -4(%ebp), %eax
0x0043fd1b:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0043fd21:	xorl -4(%ebp), %eax
0x0043fd24:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0043fd2a:	xorl -4(%ebp), %eax
0x0043fd2d:	leal %eax, -20(%ebp)
0x0043fd30:	pushl %eax
0x0043fd31:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0043fd37:	movl %ecx, -16(%ebp)
0x0043fd3a:	leal %eax, -4(%ebp)
0x0043fd3d:	xorl %ecx, -20(%ebp)
0x0043fd40:	xorl %ecx, -4(%ebp)
0x0043fd43:	xorl %ecx, %eax
0x0043fd45:	cmpl %ecx, %edi
0x0043fd47:	jne 0x0043fd50
0x0043fd50:	testl %esi, %ecx
0x0043fd52:	jne 0x0043fd60
0x0043fd60:	movl 0x464180, %ecx
0x0043fd66:	notl %ecx
0x0043fd68:	movl 0x464184, %ecx
0x0043fd6e:	popl %edi
0x0043fd6f:	popl %esi
0x0043fd70:	movl %esp, %ebp
0x0043fd72:	popl %ebp
0x0043fd73:	ret

0x00434db1:	jmp 0x00434db6
0x00434db6:	pushl $0x14<UINT8>
0x00434db8:	pushl $0x461158<UINT32>
0x00434dbd:	call 0x004387b0
0x004387b0:	pushl $0x438810<UINT32>
0x004387b5:	pushl %fs:0
0x004387bc:	movl %eax, 0x10(%esp)
0x004387c0:	movl 0x10(%esp), %ebp
0x004387c4:	leal %ebp, 0x10(%esp)
0x004387c8:	subl %esp, %eax
0x004387ca:	pushl %ebx
0x004387cb:	pushl %esi
0x004387cc:	pushl %edi
0x004387cd:	movl %eax, 0x464180
0x004387d2:	xorl -4(%ebp), %eax
0x004387d5:	xorl %eax, %ebp
0x004387d7:	pushl %eax
0x004387d8:	movl -24(%ebp), %esp
0x004387db:	pushl -8(%ebp)
0x004387de:	movl %eax, -4(%ebp)
0x004387e1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004387e8:	movl -8(%ebp), %eax
0x004387eb:	leal %eax, -16(%ebp)
0x004387ee:	movl %fs:0, %eax
0x004387f4:	ret

0x00434dc2:	call 0x0043b79b
0x0043b79b:	pushl %ebp
0x0043b79c:	movl %ebp, %esp
0x0043b79e:	subl %esp, $0x44<UINT8>
0x0043b7a1:	leal %eax, -68(%ebp)
0x0043b7a4:	pushl %eax
0x0043b7a5:	call GetStartupInfoW@KERNEL32.DLL
GetStartupInfoW@KERNEL32.DLL: API Node	
0x0043b7ab:	testb -24(%ebp), $0x1<UINT8>
0x0043b7af:	je 0x0043b7b7
0x0043b7b7:	pushl $0xa<UINT8>
0x0043b7b9:	popl %eax
0x0043b7ba:	movl %esp, %ebp
0x0043b7bc:	popl %ebp
0x0043b7bd:	ret

0x00434dc7:	movzwl %esi, %ax
0x00434dca:	pushl $0x2<UINT8>
0x00434dcc:	call 0x0043fc8b
0x0043fc8b:	pushl %ebp
0x0043fc8c:	movl %ebp, %esp
0x0043fc8e:	movl %eax, 0x8(%ebp)
0x0043fc91:	movl 0x479048, %eax
0x0043fc96:	popl %ebp
0x0043fc97:	ret

0x00434dd1:	popl %ecx
0x00434dd2:	movl %eax, $0x5a4d<UINT32>
0x00434dd7:	cmpw 0x400000, %ax
0x00434dde:	je 0x00434de4
0x00434de4:	movl %eax, 0x40003c
0x00434de9:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00434df3:	jne -21
0x00434df5:	movl %ecx, $0x10b<UINT32>
0x00434dfa:	cmpw 0x400018(%eax), %cx
0x00434e01:	jne -35
0x00434e03:	xorl %ebx, %ebx
0x00434e05:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00434e0c:	jbe 9
0x00434e0e:	cmpl 0x4000e8(%eax), %ebx
0x00434e14:	setne %bl
0x00434e17:	movl -28(%ebp), %ebx
0x00434e1a:	call 0x004350c5
0x004350c5:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x004350cb:	xorl %ecx, %ecx
0x004350cd:	movl 0x479008, %eax
0x004350d2:	testl %eax, %eax
0x004350d4:	setne %cl
0x004350d7:	movl %eax, %ecx
0x004350d9:	ret

0x00434e1f:	testl %eax, %eax
0x00434e21:	jne 0x00434e2b
0x00434e2b:	call 0x00436ab6
0x00436ab6:	call 0x00435229
0x00435229:	pushl %esi
0x0043522a:	pushl $0x0<UINT8>
0x0043522c:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00435232:	movl %esi, %eax
0x00435234:	pushl %esi
0x00435235:	call 0x00435100
0x00435100:	pushl %ebp
0x00435101:	movl %ebp, %esp
0x00435103:	movl %eax, 0x8(%ebp)
0x00435106:	movl 0x47900c, %eax
0x0043510b:	popl %ebp
0x0043510c:	ret

0x0043523a:	pushl %esi
0x0043523b:	call 0x00435052
0x00435052:	pushl %ebp
0x00435053:	movl %ebp, %esp
0x00435055:	movl %eax, 0x8(%ebp)
0x00435058:	movl 0x479004, %eax
0x0043505d:	popl %ebp
0x0043505e:	ret

0x00435240:	pushl %esi
0x00435241:	call 0x0043dd65
0x0043dd65:	pushl %ebp
0x0043dd66:	movl %ebp, %esp
0x0043dd68:	movl %eax, 0x8(%ebp)
0x0043dd6b:	movl 0x479814, %eax
0x0043dd70:	popl %ebp
0x0043dd71:	ret

0x00435246:	pushl %esi
0x00435247:	call 0x0044000d
0x0044000d:	pushl %ebp
0x0044000e:	movl %ebp, %esp
0x00440010:	movl %eax, 0x8(%ebp)
0x00440013:	movl 0x479ae4, %eax
0x00440018:	movl 0x479ae8, %eax
0x0044001d:	movl 0x479aec, %eax
0x00440022:	movl 0x479af0, %eax
0x00440027:	popl %ebp
0x00440028:	ret

0x0043524c:	pushl %esi
0x0043524d:	call 0x0043b5b1
0x0043b5b1:	pushl $0x43b56a<UINT32>
0x0043b5b6:	call EncodePointer@KERNEL32.DLL
0x0043b5bc:	movl 0x479808, %eax
0x0043b5c1:	ret

0x00435252:	pushl %esi
0x00435253:	call 0x0044021e
0x0044021e:	pushl %ebp
0x0044021f:	movl %ebp, %esp
0x00440221:	movl %eax, 0x8(%ebp)
0x00440224:	movl 0x479af8, %eax
0x00440229:	popl %ebp
0x0044022a:	ret

0x00435258:	addl %esp, $0x18<UINT8>
0x0043525b:	popl %esi
0x0043525c:	jmp 0x0043b82c
0x0043b82c:	pushl %esi
0x0043b82d:	pushl %edi
0x0043b82e:	pushl $0x459c70<UINT32>
0x0043b833:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0043b839:	movl %esi, 0x44b290
0x0043b83f:	movl %edi, %eax
0x0043b841:	pushl $0x44cb08<UINT32>
0x0043b846:	pushl %edi
0x0043b847:	call GetProcAddress@KERNEL32.DLL
0x0043b849:	xorl %eax, 0x464180
0x0043b84f:	pushl $0x44cb14<UINT32>
0x0043b854:	pushl %edi
0x0043b855:	movl 0x64b540, %eax
0x0043b85a:	call GetProcAddress@KERNEL32.DLL
0x0043b85c:	xorl %eax, 0x464180
0x0043b862:	pushl $0x44cb1c<UINT32>
0x0043b867:	pushl %edi
0x0043b868:	movl 0x64b544, %eax
0x0043b86d:	call GetProcAddress@KERNEL32.DLL
0x0043b86f:	xorl %eax, 0x464180
0x0043b875:	pushl $0x44cb28<UINT32>
0x0043b87a:	pushl %edi
0x0043b87b:	movl 0x64b548, %eax
0x0043b880:	call GetProcAddress@KERNEL32.DLL
0x0043b882:	xorl %eax, 0x464180
0x0043b888:	pushl $0x44cb34<UINT32>
0x0043b88d:	pushl %edi
0x0043b88e:	movl 0x64b54c, %eax
0x0043b893:	call GetProcAddress@KERNEL32.DLL
0x0043b895:	xorl %eax, 0x464180
0x0043b89b:	pushl $0x44cb50<UINT32>
0x0043b8a0:	pushl %edi
0x0043b8a1:	movl 0x64b550, %eax
0x0043b8a6:	call GetProcAddress@KERNEL32.DLL
0x0043b8a8:	xorl %eax, 0x464180
0x0043b8ae:	pushl $0x44cb60<UINT32>
0x0043b8b3:	pushl %edi
0x0043b8b4:	movl 0x64b554, %eax
0x0043b8b9:	call GetProcAddress@KERNEL32.DLL
0x0043b8bb:	xorl %eax, 0x464180
0x0043b8c1:	pushl $0x44cb74<UINT32>
0x0043b8c6:	pushl %edi
0x0043b8c7:	movl 0x64b558, %eax
0x0043b8cc:	call GetProcAddress@KERNEL32.DLL
0x0043b8ce:	xorl %eax, 0x464180
0x0043b8d4:	pushl $0x44cb8c<UINT32>
0x0043b8d9:	pushl %edi
0x0043b8da:	movl 0x64b55c, %eax
0x0043b8df:	call GetProcAddress@KERNEL32.DLL
0x0043b8e1:	xorl %eax, 0x464180
0x0043b8e7:	pushl $0x44cba4<UINT32>
0x0043b8ec:	pushl %edi
0x0043b8ed:	movl 0x64b560, %eax
0x0043b8f2:	call GetProcAddress@KERNEL32.DLL
0x0043b8f4:	xorl %eax, 0x464180
0x0043b8fa:	pushl $0x44cbb8<UINT32>
0x0043b8ff:	pushl %edi
0x0043b900:	movl 0x64b564, %eax
0x0043b905:	call GetProcAddress@KERNEL32.DLL
0x0043b907:	xorl %eax, 0x464180
0x0043b90d:	pushl $0x44cbd8<UINT32>
0x0043b912:	pushl %edi
0x0043b913:	movl 0x64b568, %eax
0x0043b918:	call GetProcAddress@KERNEL32.DLL
0x0043b91a:	xorl %eax, 0x464180
0x0043b920:	pushl $0x44cbf0<UINT32>
0x0043b925:	pushl %edi
0x0043b926:	movl 0x64b56c, %eax
0x0043b92b:	call GetProcAddress@KERNEL32.DLL
0x0043b92d:	xorl %eax, 0x464180
0x0043b933:	pushl $0x44cc08<UINT32>
0x0043b938:	pushl %edi
0x0043b939:	movl 0x64b570, %eax
0x0043b93e:	call GetProcAddress@KERNEL32.DLL
0x0043b940:	xorl %eax, 0x464180
0x0043b946:	pushl $0x44cc1c<UINT32>
0x0043b94b:	pushl %edi
0x0043b94c:	movl 0x64b574, %eax
0x0043b951:	call GetProcAddress@KERNEL32.DLL
0x0043b953:	xorl %eax, 0x464180
0x0043b959:	movl 0x64b578, %eax
0x0043b95e:	pushl $0x44cc30<UINT32>
0x0043b963:	pushl %edi
0x0043b964:	call GetProcAddress@KERNEL32.DLL
0x0043b966:	xorl %eax, 0x464180
0x0043b96c:	pushl $0x44cc4c<UINT32>
0x0043b971:	pushl %edi
0x0043b972:	movl 0x64b57c, %eax
0x0043b977:	call GetProcAddress@KERNEL32.DLL
0x0043b979:	xorl %eax, 0x464180
0x0043b97f:	pushl $0x44cc6c<UINT32>
0x0043b984:	pushl %edi
0x0043b985:	movl 0x64b580, %eax
0x0043b98a:	call GetProcAddress@KERNEL32.DLL
0x0043b98c:	xorl %eax, 0x464180
0x0043b992:	pushl $0x44cc88<UINT32>
0x0043b997:	pushl %edi
0x0043b998:	movl 0x64b584, %eax
0x0043b99d:	call GetProcAddress@KERNEL32.DLL
0x0043b99f:	xorl %eax, 0x464180
0x0043b9a5:	pushl $0x44cca8<UINT32>
0x0043b9aa:	pushl %edi
0x0043b9ab:	movl 0x64b588, %eax
0x0043b9b0:	call GetProcAddress@KERNEL32.DLL
0x0043b9b2:	xorl %eax, 0x464180
0x0043b9b8:	pushl $0x44ccbc<UINT32>
0x0043b9bd:	pushl %edi
0x0043b9be:	movl 0x64b58c, %eax
0x0043b9c3:	call GetProcAddress@KERNEL32.DLL
0x0043b9c5:	xorl %eax, 0x464180
0x0043b9cb:	pushl $0x44ccd8<UINT32>
0x0043b9d0:	pushl %edi
0x0043b9d1:	movl 0x64b590, %eax
0x0043b9d6:	call GetProcAddress@KERNEL32.DLL
0x0043b9d8:	xorl %eax, 0x464180
0x0043b9de:	pushl $0x44ccec<UINT32>
0x0043b9e3:	pushl %edi
0x0043b9e4:	movl 0x64b598, %eax
0x0043b9e9:	call GetProcAddress@KERNEL32.DLL
0x0043b9eb:	xorl %eax, 0x464180
0x0043b9f1:	pushl $0x44ccfc<UINT32>
0x0043b9f6:	pushl %edi
0x0043b9f7:	movl 0x64b594, %eax
0x0043b9fc:	call GetProcAddress@KERNEL32.DLL
0x0043b9fe:	xorl %eax, 0x464180
0x0043ba04:	pushl $0x44cd0c<UINT32>
0x0043ba09:	pushl %edi
0x0043ba0a:	movl 0x64b59c, %eax
0x0043ba0f:	call GetProcAddress@KERNEL32.DLL
0x0043ba11:	xorl %eax, 0x464180
0x0043ba17:	pushl $0x44cd1c<UINT32>
0x0043ba1c:	pushl %edi
0x0043ba1d:	movl 0x64b5a0, %eax
0x0043ba22:	call GetProcAddress@KERNEL32.DLL
0x0043ba24:	xorl %eax, 0x464180
0x0043ba2a:	pushl $0x44cd2c<UINT32>
0x0043ba2f:	pushl %edi
0x0043ba30:	movl 0x64b5a4, %eax
0x0043ba35:	call GetProcAddress@KERNEL32.DLL
0x0043ba37:	xorl %eax, 0x464180
0x0043ba3d:	pushl $0x44cd48<UINT32>
0x0043ba42:	pushl %edi
0x0043ba43:	movl 0x64b5a8, %eax
0x0043ba48:	call GetProcAddress@KERNEL32.DLL
0x0043ba4a:	xorl %eax, 0x464180
0x0043ba50:	pushl $0x44cd5c<UINT32>
0x0043ba55:	pushl %edi
0x0043ba56:	movl 0x64b5ac, %eax
0x0043ba5b:	call GetProcAddress@KERNEL32.DLL
0x0043ba5d:	xorl %eax, 0x464180
0x0043ba63:	pushl $0x44cd6c<UINT32>
0x0043ba68:	pushl %edi
0x0043ba69:	movl 0x64b5b0, %eax
0x0043ba6e:	call GetProcAddress@KERNEL32.DLL
0x0043ba70:	xorl %eax, 0x464180
0x0043ba76:	pushl $0x44cd80<UINT32>
0x0043ba7b:	pushl %edi
0x0043ba7c:	movl 0x64b5b4, %eax
0x0043ba81:	call GetProcAddress@KERNEL32.DLL
0x0043ba83:	xorl %eax, 0x464180
0x0043ba89:	movl 0x64b5b8, %eax
0x0043ba8e:	pushl $0x44cd90<UINT32>
0x0043ba93:	pushl %edi
0x0043ba94:	call GetProcAddress@KERNEL32.DLL
0x0043ba96:	xorl %eax, 0x464180
0x0043ba9c:	pushl $0x44cdb0<UINT32>
0x0043baa1:	pushl %edi
0x0043baa2:	movl 0x64b5bc, %eax
0x0043baa7:	call GetProcAddress@KERNEL32.DLL
0x0043baa9:	xorl %eax, 0x464180
0x0043baaf:	popl %edi
0x0043bab0:	movl 0x64b5c0, %eax
0x0043bab5:	popl %esi
0x0043bab6:	ret

0x00436abb:	call 0x00438ad5
0x00438ad5:	pushl %esi
0x00438ad6:	pushl %edi
0x00438ad7:	movl %esi, $0x464b80<UINT32>
0x00438adc:	movl %edi, $0x4796a8<UINT32>
0x00438ae1:	cmpl 0x4(%esi), $0x1<UINT8>
0x00438ae5:	jne 22
0x00438ae7:	pushl $0x0<UINT8>
0x00438ae9:	movl (%esi), %edi
0x00438aeb:	addl %edi, $0x18<UINT8>
0x00438aee:	pushl $0xfa0<UINT32>
0x00438af3:	pushl (%esi)
0x00438af5:	call 0x0043b7be
0x0043b7be:	pushl %ebp
0x0043b7bf:	movl %ebp, %esp
0x0043b7c1:	movl %eax, 0x64b550
0x0043b7c6:	xorl %eax, 0x464180
0x0043b7cc:	je 13
0x0043b7ce:	pushl 0x10(%ebp)
0x0043b7d1:	pushl 0xc(%ebp)
0x0043b7d4:	pushl 0x8(%ebp)
0x0043b7d7:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x0043b7d9:	popl %ebp
0x0043b7da:	ret

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
