0x0043ccb0:	pusha
0x0043ccb1:	movl %esi, $0x428000<UINT32>
0x0043ccb6:	leal %edi, -159744(%esi)
0x0043ccbc:	pushl %edi
0x0043ccbd:	jmp 0x0043ccca
0x0043ccca:	movl %ebx, (%esi)
0x0043cccc:	subl %esi, $0xfffffffc<UINT8>
0x0043cccf:	adcl %ebx, %ebx
0x0043ccd1:	jb 0x0043ccc0
0x0043ccc0:	movb %al, (%esi)
0x0043ccc2:	incl %esi
0x0043ccc3:	movb (%edi), %al
0x0043ccc5:	incl %edi
0x0043ccc6:	addl %ebx, %ebx
0x0043ccc8:	jne 0x0043ccd1
0x0043ccd3:	movl %eax, $0x1<UINT32>
0x0043ccd8:	addl %ebx, %ebx
0x0043ccda:	jne 0x0043cce3
0x0043cce3:	adcl %eax, %eax
0x0043cce5:	addl %ebx, %ebx
0x0043cce7:	jae 0x0043ccd8
0x0043cce9:	jne 0x0043ccf4
0x0043ccf4:	xorl %ecx, %ecx
0x0043ccf6:	subl %eax, $0x3<UINT8>
0x0043ccf9:	jb 0x0043cd08
0x0043ccfb:	shll %eax, $0x8<UINT8>
0x0043ccfe:	movb %al, (%esi)
0x0043cd00:	incl %esi
0x0043cd01:	xorl %eax, $0xffffffff<UINT8>
0x0043cd04:	je 0x0043cd7a
0x0043cd06:	movl %ebp, %eax
0x0043cd08:	addl %ebx, %ebx
0x0043cd0a:	jne 0x0043cd13
0x0043cd13:	adcl %ecx, %ecx
0x0043cd15:	addl %ebx, %ebx
0x0043cd17:	jne 0x0043cd20
0x0043cd19:	movl %ebx, (%esi)
0x0043cd1b:	subl %esi, $0xfffffffc<UINT8>
0x0043cd1e:	adcl %ebx, %ebx
0x0043cd20:	adcl %ecx, %ecx
0x0043cd22:	jne 0x0043cd44
0x0043cd44:	cmpl %ebp, $0xfffff300<UINT32>
0x0043cd4a:	adcl %ecx, $0x1<UINT8>
0x0043cd4d:	leal %edx, (%edi,%ebp)
0x0043cd50:	cmpl %ebp, $0xfffffffc<UINT8>
0x0043cd53:	jbe 0x0043cd64
0x0043cd64:	movl %eax, (%edx)
0x0043cd66:	addl %edx, $0x4<UINT8>
0x0043cd69:	movl (%edi), %eax
0x0043cd6b:	addl %edi, $0x4<UINT8>
0x0043cd6e:	subl %ecx, $0x4<UINT8>
0x0043cd71:	ja 0x0043cd64
0x0043cd73:	addl %edi, %ecx
0x0043cd75:	jmp 0x0043ccc6
0x0043cd24:	incl %ecx
0x0043cd25:	addl %ebx, %ebx
0x0043cd27:	jne 0x0043cd30
0x0043cd29:	movl %ebx, (%esi)
0x0043cd2b:	subl %esi, $0xfffffffc<UINT8>
0x0043cd2e:	adcl %ebx, %ebx
0x0043cd30:	adcl %ecx, %ecx
0x0043cd32:	addl %ebx, %ebx
0x0043cd34:	jae 0x0043cd25
0x0043cd36:	jne 0x0043cd41
0x0043cd41:	addl %ecx, $0x2<UINT8>
0x0043cd55:	movb %al, (%edx)
0x0043cd57:	incl %edx
0x0043cd58:	movb (%edi), %al
0x0043cd5a:	incl %edi
0x0043cd5b:	decl %ecx
0x0043cd5c:	jne 0x0043cd55
0x0043cd5e:	jmp 0x0043ccc6
0x0043ccdc:	movl %ebx, (%esi)
0x0043ccde:	subl %esi, $0xfffffffc<UINT8>
0x0043cce1:	adcl %ebx, %ebx
0x0043cd0c:	movl %ebx, (%esi)
0x0043cd0e:	subl %esi, $0xfffffffc<UINT8>
0x0043cd11:	adcl %ebx, %ebx
0x0043cceb:	movl %ebx, (%esi)
0x0043cced:	subl %esi, $0xfffffffc<UINT8>
0x0043ccf0:	adcl %ebx, %ebx
0x0043ccf2:	jae 0x0043ccd8
0x0043cd38:	movl %ebx, (%esi)
0x0043cd3a:	subl %esi, $0xfffffffc<UINT8>
0x0043cd3d:	adcl %ebx, %ebx
0x0043cd3f:	jae 0x0043cd25
0x0043cd7a:	popl %esi
0x0043cd7b:	movl %edi, %esi
0x0043cd7d:	movl %ecx, $0xc7b<UINT32>
0x0043cd82:	movb %al, (%edi)
0x0043cd84:	incl %edi
0x0043cd85:	subb %al, $0xffffffe8<UINT8>
0x0043cd87:	cmpb %al, $0x1<UINT8>
0x0043cd89:	ja 0x0043cd82
0x0043cd8b:	cmpb (%edi), $0xa<UINT8>
0x0043cd8e:	jne 0x0043cd82
0x0043cd90:	movl %eax, (%edi)
0x0043cd92:	movb %bl, 0x4(%edi)
0x0043cd95:	shrw %ax, $0x8<UINT8>
0x0043cd99:	roll %eax, $0x10<UINT8>
0x0043cd9c:	xchgb %ah, %al
0x0043cd9e:	subl %eax, %edi
0x0043cda0:	subb %bl, $0xffffffe8<UINT8>
0x0043cda3:	addl %eax, %esi
0x0043cda5:	movl (%edi), %eax
0x0043cda7:	addl %edi, $0x5<UINT8>
0x0043cdaa:	movb %al, %bl
0x0043cdac:	loop 0x0043cd87
0x0043cdae:	leal %edi, 0x39000(%esi)
0x0043cdb4:	movl %eax, (%edi)
0x0043cdb6:	orl %eax, %eax
0x0043cdb8:	je 0x0043cdf6
0x0043cdba:	movl %ebx, 0x4(%edi)
0x0043cdbd:	leal %eax, 0x3c54c(%eax,%esi)
0x0043cdc4:	addl %ebx, %esi
0x0043cdc6:	pushl %eax
0x0043cdc7:	addl %edi, $0x8<UINT8>
0x0043cdca:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x0043cdd0:	xchgl %ebp, %eax
0x0043cdd1:	movb %al, (%edi)
0x0043cdd3:	incl %edi
0x0043cdd4:	orb %al, %al
0x0043cdd6:	je 0x0043cdb4
0x0043cdd8:	movl %ecx, %edi
0x0043cdda:	pushl %edi
0x0043cddb:	decl %eax
0x0043cddc:	repn scasb %al, %es:(%edi)
0x0043cdde:	pushl %ebp
0x0043cddf:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0043cde5:	orl %eax, %eax
0x0043cde7:	je 7
0x0043cde9:	movl (%ebx), %eax
0x0043cdeb:	addl %ebx, $0x4<UINT8>
0x0043cdee:	jmp 0x0043cdd1
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x0043cdf6:	addl %edi, $0x4<UINT8>
0x0043cdf9:	leal %ebx, -4(%esi)
0x0043cdfc:	xorl %eax, %eax
0x0043cdfe:	movb %al, (%edi)
0x0043ce00:	incl %edi
0x0043ce01:	orl %eax, %eax
0x0043ce03:	je 0x0043ce27
0x0043ce05:	cmpb %al, $0xffffffef<UINT8>
0x0043ce07:	ja 0x0043ce1a
0x0043ce09:	addl %ebx, %eax
0x0043ce0b:	movl %eax, (%ebx)
0x0043ce0d:	xchgb %ah, %al
0x0043ce0f:	roll %eax, $0x10<UINT8>
0x0043ce12:	xchgb %ah, %al
0x0043ce14:	addl %eax, %esi
0x0043ce16:	movl (%ebx), %eax
0x0043ce18:	jmp 0x0043cdfc
0x0043ce1a:	andb %al, $0xf<UINT8>
0x0043ce1c:	shll %eax, $0x10<UINT8>
0x0043ce1f:	movw %ax, (%edi)
0x0043ce22:	addl %edi, $0x2<UINT8>
0x0043ce25:	jmp 0x0043ce09
0x0043ce27:	movl %ebp, 0x3c5fc(%esi)
0x0043ce2d:	leal %edi, -4096(%esi)
0x0043ce33:	movl %ebx, $0x1000<UINT32>
0x0043ce38:	pushl %eax
0x0043ce39:	pushl %esp
0x0043ce3a:	pushl $0x4<UINT8>
0x0043ce3c:	pushl %ebx
0x0043ce3d:	pushl %edi
0x0043ce3e:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0043ce40:	leal %eax, 0x20f(%edi)
0x0043ce46:	andb (%eax), $0x7f<UINT8>
0x0043ce49:	andb 0x28(%eax), $0x7f<UINT8>
0x0043ce4d:	popl %eax
0x0043ce4e:	pushl %eax
0x0043ce4f:	pushl %esp
0x0043ce50:	pushl %eax
0x0043ce51:	pushl %ebx
0x0043ce52:	pushl %edi
0x0043ce53:	call VirtualProtect@kernel32.dll
0x0043ce55:	popl %eax
0x0043ce56:	popa
0x0043ce57:	leal %eax, -128(%esp)
0x0043ce5b:	pushl $0x0<UINT8>
0x0043ce5d:	cmpl %esp, %eax
0x0043ce5f:	jne 0x0043ce5b
0x0043ce61:	subl %esp, $0xffffff80<UINT8>
0x0043ce64:	jmp 0x00405f50
0x00405f50:	call 0x00411371
0x00411371:	pushl %ebp
0x00411372:	movl %ebp, %esp
0x00411374:	subl %esp, $0x14<UINT8>
0x00411377:	andl -12(%ebp), $0x0<UINT8>
0x0041137b:	andl -8(%ebp), $0x0<UINT8>
0x0041137f:	movl %eax, 0x433350
0x00411384:	pushl %esi
0x00411385:	pushl %edi
0x00411386:	movl %edi, $0xbb40e64e<UINT32>
0x0041138b:	movl %esi, $0xffff0000<UINT32>
0x00411390:	cmpl %eax, %edi
0x00411392:	je 0x004113a1
0x004113a1:	leal %eax, -12(%ebp)
0x004113a4:	pushl %eax
0x004113a5:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x004113ab:	movl %eax, -8(%ebp)
0x004113ae:	xorl %eax, -12(%ebp)
0x004113b1:	movl -4(%ebp), %eax
0x004113b4:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x004113ba:	xorl -4(%ebp), %eax
0x004113bd:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x004113c3:	xorl -4(%ebp), %eax
0x004113c6:	leal %eax, -20(%ebp)
0x004113c9:	pushl %eax
0x004113ca:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x004113d0:	movl %ecx, -16(%ebp)
0x004113d3:	leal %eax, -4(%ebp)
0x004113d6:	xorl %ecx, -20(%ebp)
0x004113d9:	xorl %ecx, -4(%ebp)
0x004113dc:	xorl %ecx, %eax
0x004113de:	cmpl %ecx, %edi
0x004113e0:	jne 0x004113e9
0x004113e9:	testl %esi, %ecx
0x004113eb:	jne 0x004113f9
0x004113f9:	movl 0x433350, %ecx
0x004113ff:	notl %ecx
0x00411401:	movl 0x433354, %ecx
0x00411407:	popl %edi
0x00411408:	popl %esi
0x00411409:	movl %esp, %ebp
0x0041140b:	popl %ebp
0x0041140c:	ret

0x00405f55:	jmp 0x00405d8f
0x00405d8f:	pushl $0x14<UINT8>
0x00405d91:	pushl $0x431cb0<UINT32>
0x00405d96:	call 0x00406d40
0x00406d40:	pushl $0x406de0<UINT32>
0x00406d45:	pushl %fs:0
0x00406d4c:	movl %eax, 0x10(%esp)
0x00406d50:	movl 0x10(%esp), %ebp
0x00406d54:	leal %ebp, 0x10(%esp)
0x00406d58:	subl %esp, %eax
0x00406d5a:	pushl %ebx
0x00406d5b:	pushl %esi
0x00406d5c:	pushl %edi
0x00406d5d:	movl %eax, 0x433350
0x00406d62:	xorl -4(%ebp), %eax
0x00406d65:	xorl %eax, %ebp
0x00406d67:	pushl %eax
0x00406d68:	movl -24(%ebp), %esp
0x00406d6b:	pushl -8(%ebp)
0x00406d6e:	movl %eax, -4(%ebp)
0x00406d71:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00406d78:	movl -8(%ebp), %eax
0x00406d7b:	leal %eax, -16(%ebp)
0x00406d7e:	movl %fs:0, %eax
0x00406d84:	ret

0x00405d9b:	pushl $0x1<UINT8>
0x00405d9d:	call 0x00411324
0x00411324:	pushl %ebp
0x00411325:	movl %ebp, %esp
0x00411327:	movl %eax, 0x8(%ebp)
0x0041132a:	movl 0x434558, %eax
0x0041132f:	popl %ebp
0x00411330:	ret

0x00405da2:	popl %ecx
0x00405da3:	movl %eax, $0x5a4d<UINT32>
0x00405da8:	cmpw 0x400000, %ax
0x00405daf:	je 0x00405db5
0x00405db5:	movl %eax, 0x40003c
0x00405dba:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00405dc4:	jne -21
0x00405dc6:	movl %ecx, $0x10b<UINT32>
0x00405dcb:	cmpw 0x400018(%eax), %cx
0x00405dd2:	jne -35
0x00405dd4:	xorl %ebx, %ebx
0x00405dd6:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00405ddd:	jbe 9
0x00405ddf:	cmpl 0x4000e8(%eax), %ebx
0x00405de5:	setne %bl
0x00405de8:	movl -28(%ebp), %ebx
0x00405deb:	call 0x0040c1a0
0x0040c1a0:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x0040c1a6:	xorl %ecx, %ecx
0x0040c1a8:	movl 0x434bb0, %eax
0x0040c1ad:	testl %eax, %eax
0x0040c1af:	setne %cl
0x0040c1b2:	movl %eax, %ecx
0x0040c1b4:	ret

0x00405df0:	testl %eax, %eax
0x00405df2:	jne 0x00405dfc
0x00405dfc:	call 0x0040ae7a
0x0040ae7a:	call 0x00404708
0x00404708:	pushl %esi
0x00404709:	pushl $0x0<UINT8>
0x0040470b:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00404711:	movl %esi, %eax
0x00404713:	pushl %esi
0x00404714:	call 0x0040c18d
0x0040c18d:	pushl %ebp
0x0040c18e:	movl %ebp, %esp
0x0040c190:	movl %eax, 0x8(%ebp)
0x0040c193:	movl 0x434ba8, %eax
0x0040c198:	popl %ebp
0x0040c199:	ret

0x00404719:	pushl %esi
0x0040471a:	call 0x004070c3
0x004070c3:	pushl %ebp
0x004070c4:	movl %ebp, %esp
0x004070c6:	movl %eax, 0x8(%ebp)
0x004070c9:	movl 0x434444, %eax
0x004070ce:	popl %ebp
0x004070cf:	ret

0x0040471f:	pushl %esi
0x00404720:	call 0x0040caf9
0x0040caf9:	pushl %ebp
0x0040cafa:	movl %ebp, %esp
0x0040cafc:	movl %eax, 0x8(%ebp)
0x0040caff:	movl 0x434edc, %eax
0x0040cb04:	popl %ebp
0x0040cb05:	ret

0x00404725:	pushl %esi
0x00404726:	call 0x0040cb25
0x0040cb25:	pushl %ebp
0x0040cb26:	movl %ebp, %esp
0x0040cb28:	movl %eax, 0x8(%ebp)
0x0040cb2b:	movl 0x434ee0, %eax
0x0040cb30:	movl 0x434ee4, %eax
0x0040cb35:	movl 0x434ee8, %eax
0x0040cb3a:	movl 0x434eec, %eax
0x0040cb3f:	popl %ebp
0x0040cb40:	ret

0x0040472b:	pushl %esi
0x0040472c:	call 0x0040c90f
0x0040c90f:	pushl $0x40c8c8<UINT32>
0x0040c914:	call EncodePointer@KERNEL32.DLL
0x0040c91a:	movl 0x434ed8, %eax
0x0040c91f:	ret

0x00404731:	pushl %esi
0x00404732:	call 0x0040d032
0x0040d032:	pushl %ebp
0x0040d033:	movl %ebp, %esp
0x0040d035:	movl %eax, 0x8(%ebp)
0x0040d038:	movl 0x434ef4, %eax
0x0040d03d:	popl %ebp
0x0040d03e:	ret

0x00404737:	addl %esp, $0x18<UINT8>
0x0040473a:	popl %esi
0x0040473b:	jmp 0x00409a24
0x00409a24:	pushl %esi
0x00409a25:	pushl %edi
0x00409a26:	pushl $0x42cf4c<UINT32>
0x00409a2b:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00409a31:	movl %esi, 0x4260b0
0x00409a37:	movl %edi, %eax
0x00409a39:	pushl $0x42cf68<UINT32>
0x00409a3e:	pushl %edi
0x00409a3f:	call GetProcAddress@KERNEL32.DLL
0x00409a41:	xorl %eax, 0x433350
0x00409a47:	pushl $0x42cf74<UINT32>
0x00409a4c:	pushl %edi
0x00409a4d:	movl 0x435160, %eax
0x00409a52:	call GetProcAddress@KERNEL32.DLL
0x00409a54:	xorl %eax, 0x433350
0x00409a5a:	pushl $0x42cf7c<UINT32>
0x00409a5f:	pushl %edi
0x00409a60:	movl 0x435164, %eax
0x00409a65:	call GetProcAddress@KERNEL32.DLL
0x00409a67:	xorl %eax, 0x433350
0x00409a6d:	pushl $0x42cf88<UINT32>
0x00409a72:	pushl %edi
0x00409a73:	movl 0x435168, %eax
0x00409a78:	call GetProcAddress@KERNEL32.DLL
0x00409a7a:	xorl %eax, 0x433350
0x00409a80:	pushl $0x42cf94<UINT32>
0x00409a85:	pushl %edi
0x00409a86:	movl 0x43516c, %eax
0x00409a8b:	call GetProcAddress@KERNEL32.DLL
0x00409a8d:	xorl %eax, 0x433350
0x00409a93:	pushl $0x42cfb0<UINT32>
0x00409a98:	pushl %edi
0x00409a99:	movl 0x435170, %eax
0x00409a9e:	call GetProcAddress@KERNEL32.DLL
0x00409aa0:	xorl %eax, 0x433350
0x00409aa6:	pushl $0x42cfc0<UINT32>
0x00409aab:	pushl %edi
0x00409aac:	movl 0x435174, %eax
0x00409ab1:	call GetProcAddress@KERNEL32.DLL
0x00409ab3:	xorl %eax, 0x433350
0x00409ab9:	pushl $0x42cfd4<UINT32>
0x00409abe:	pushl %edi
0x00409abf:	movl 0x435178, %eax
0x00409ac4:	call GetProcAddress@KERNEL32.DLL
0x00409ac6:	xorl %eax, 0x433350
0x00409acc:	pushl $0x42cfec<UINT32>
0x00409ad1:	pushl %edi
0x00409ad2:	movl 0x43517c, %eax
0x00409ad7:	call GetProcAddress@KERNEL32.DLL
0x00409ad9:	xorl %eax, 0x433350
0x00409adf:	pushl $0x42d004<UINT32>
0x00409ae4:	pushl %edi
0x00409ae5:	movl 0x435180, %eax
0x00409aea:	call GetProcAddress@KERNEL32.DLL
0x00409aec:	xorl %eax, 0x433350
0x00409af2:	pushl $0x42d018<UINT32>
0x00409af7:	pushl %edi
0x00409af8:	movl 0x435184, %eax
0x00409afd:	call GetProcAddress@KERNEL32.DLL
0x00409aff:	xorl %eax, 0x433350
0x00409b05:	pushl $0x42d038<UINT32>
0x00409b0a:	pushl %edi
0x00409b0b:	movl 0x435188, %eax
0x00409b10:	call GetProcAddress@KERNEL32.DLL
0x00409b12:	xorl %eax, 0x433350
0x00409b18:	pushl $0x42d050<UINT32>
0x00409b1d:	pushl %edi
0x00409b1e:	movl 0x43518c, %eax
0x00409b23:	call GetProcAddress@KERNEL32.DLL
0x00409b25:	xorl %eax, 0x433350
0x00409b2b:	pushl $0x42d068<UINT32>
0x00409b30:	pushl %edi
0x00409b31:	movl 0x435190, %eax
0x00409b36:	call GetProcAddress@KERNEL32.DLL
0x00409b38:	xorl %eax, 0x433350
0x00409b3e:	pushl $0x42d07c<UINT32>
0x00409b43:	pushl %edi
0x00409b44:	movl 0x435194, %eax
0x00409b49:	call GetProcAddress@KERNEL32.DLL
0x00409b4b:	xorl %eax, 0x433350
0x00409b51:	movl 0x435198, %eax
0x00409b56:	pushl $0x42d090<UINT32>
0x00409b5b:	pushl %edi
0x00409b5c:	call GetProcAddress@KERNEL32.DLL
0x00409b5e:	xorl %eax, 0x433350
0x00409b64:	pushl $0x42d0ac<UINT32>
0x00409b69:	pushl %edi
0x00409b6a:	movl 0x43519c, %eax
0x00409b6f:	call GetProcAddress@KERNEL32.DLL
0x00409b71:	xorl %eax, 0x433350
0x00409b77:	pushl $0x42d0cc<UINT32>
0x00409b7c:	pushl %edi
0x00409b7d:	movl 0x4351a0, %eax
0x00409b82:	call GetProcAddress@KERNEL32.DLL
0x00409b84:	xorl %eax, 0x433350
0x00409b8a:	pushl $0x42d0e8<UINT32>
0x00409b8f:	pushl %edi
0x00409b90:	movl 0x4351a4, %eax
0x00409b95:	call GetProcAddress@KERNEL32.DLL
0x00409b97:	xorl %eax, 0x433350
0x00409b9d:	pushl $0x42d108<UINT32>
0x00409ba2:	pushl %edi
0x00409ba3:	movl 0x4351a8, %eax
0x00409ba8:	call GetProcAddress@KERNEL32.DLL
0x00409baa:	xorl %eax, 0x433350
0x00409bb0:	pushl $0x42d11c<UINT32>
0x00409bb5:	pushl %edi
0x00409bb6:	movl 0x4351ac, %eax
0x00409bbb:	call GetProcAddress@KERNEL32.DLL
0x00409bbd:	xorl %eax, 0x433350
0x00409bc3:	pushl $0x42d138<UINT32>
0x00409bc8:	pushl %edi
0x00409bc9:	movl 0x4351b0, %eax
0x00409bce:	call GetProcAddress@KERNEL32.DLL
0x00409bd0:	xorl %eax, 0x433350
0x00409bd6:	pushl $0x42d14c<UINT32>
0x00409bdb:	pushl %edi
0x00409bdc:	movl 0x4351b8, %eax
0x00409be1:	call GetProcAddress@KERNEL32.DLL
0x00409be3:	xorl %eax, 0x433350
0x00409be9:	pushl $0x42d15c<UINT32>
0x00409bee:	pushl %edi
0x00409bef:	movl 0x4351b4, %eax
0x00409bf4:	call GetProcAddress@KERNEL32.DLL
0x00409bf6:	xorl %eax, 0x433350
0x00409bfc:	pushl $0x42d16c<UINT32>
0x00409c01:	pushl %edi
0x00409c02:	movl 0x4351bc, %eax
0x00409c07:	call GetProcAddress@KERNEL32.DLL
0x00409c09:	xorl %eax, 0x433350
0x00409c0f:	pushl $0x42d17c<UINT32>
0x00409c14:	pushl %edi
0x00409c15:	movl 0x4351c0, %eax
0x00409c1a:	call GetProcAddress@KERNEL32.DLL
0x00409c1c:	xorl %eax, 0x433350
0x00409c22:	pushl $0x42d18c<UINT32>
0x00409c27:	pushl %edi
0x00409c28:	movl 0x4351c4, %eax
0x00409c2d:	call GetProcAddress@KERNEL32.DLL
0x00409c2f:	xorl %eax, 0x433350
0x00409c35:	pushl $0x42d1a8<UINT32>
0x00409c3a:	pushl %edi
0x00409c3b:	movl 0x4351c8, %eax
0x00409c40:	call GetProcAddress@KERNEL32.DLL
0x00409c42:	xorl %eax, 0x433350
0x00409c48:	pushl $0x42d1bc<UINT32>
0x00409c4d:	pushl %edi
0x00409c4e:	movl 0x4351cc, %eax
0x00409c53:	call GetProcAddress@KERNEL32.DLL
0x00409c55:	xorl %eax, 0x433350
0x00409c5b:	pushl $0x42d1cc<UINT32>
0x00409c60:	pushl %edi
0x00409c61:	movl 0x4351d0, %eax
0x00409c66:	call GetProcAddress@KERNEL32.DLL
0x00409c68:	xorl %eax, 0x433350
0x00409c6e:	pushl $0x42d1e0<UINT32>
0x00409c73:	pushl %edi
0x00409c74:	movl 0x4351d4, %eax
0x00409c79:	call GetProcAddress@KERNEL32.DLL
0x00409c7b:	xorl %eax, 0x433350
0x00409c81:	movl 0x4351d8, %eax
0x00409c86:	pushl $0x42d1f0<UINT32>
0x00409c8b:	pushl %edi
0x00409c8c:	call GetProcAddress@KERNEL32.DLL
0x00409c8e:	xorl %eax, 0x433350
0x00409c94:	pushl $0x42d210<UINT32>
0x00409c99:	pushl %edi
0x00409c9a:	movl 0x4351dc, %eax
0x00409c9f:	call GetProcAddress@KERNEL32.DLL
0x00409ca1:	xorl %eax, 0x433350
0x00409ca7:	popl %edi
0x00409ca8:	movl 0x4351e0, %eax
0x00409cad:	popl %esi
0x00409cae:	ret

0x0040ae7f:	call 0x00406148
0x00406148:	pushl %esi
0x00406149:	pushl %edi
0x0040614a:	movl %esi, $0x433360<UINT32>
0x0040614f:	movl %edi, $0x4342f0<UINT32>
0x00406154:	cmpl 0x4(%esi), $0x1<UINT8>
0x00406158:	jne 22
0x0040615a:	pushl $0x0<UINT8>
0x0040615c:	movl (%esi), %edi
0x0040615e:	addl %edi, $0x18<UINT8>
0x00406161:	pushl $0xfa0<UINT32>
0x00406166:	pushl (%esi)
0x00406168:	call 0x004099b6
0x004099b6:	pushl %ebp
0x004099b7:	movl %ebp, %esp
0x004099b9:	movl %eax, 0x435170
0x004099be:	xorl %eax, 0x433350
0x004099c4:	je 13
0x004099c6:	pushl 0x10(%ebp)
0x004099c9:	pushl 0xc(%ebp)
0x004099cc:	pushl 0x8(%ebp)
0x004099cf:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x004099d1:	popl %ebp
0x004099d2:	ret

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
