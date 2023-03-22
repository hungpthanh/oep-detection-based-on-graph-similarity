0x0042cab0:	pusha
0x0042cab1:	movl %esi, $0x420000<UINT32>
0x0042cab6:	leal %edi, -126976(%esi)
0x0042cabc:	pushl %edi
0x0042cabd:	jmp 0x0042caca
0x0042caca:	movl %ebx, (%esi)
0x0042cacc:	subl %esi, $0xfffffffc<UINT8>
0x0042cacf:	adcl %ebx, %ebx
0x0042cad1:	jb 0x0042cac0
0x0042cac0:	movb %al, (%esi)
0x0042cac2:	incl %esi
0x0042cac3:	movb (%edi), %al
0x0042cac5:	incl %edi
0x0042cac6:	addl %ebx, %ebx
0x0042cac8:	jne 0x0042cad1
0x0042cad3:	movl %eax, $0x1<UINT32>
0x0042cad8:	addl %ebx, %ebx
0x0042cada:	jne 0x0042cae3
0x0042cae3:	adcl %eax, %eax
0x0042cae5:	addl %ebx, %ebx
0x0042cae7:	jae 0x0042cad8
0x0042cae9:	jne 0x0042caf4
0x0042caf4:	xorl %ecx, %ecx
0x0042caf6:	subl %eax, $0x3<UINT8>
0x0042caf9:	jb 0x0042cb08
0x0042cafb:	shll %eax, $0x8<UINT8>
0x0042cafe:	movb %al, (%esi)
0x0042cb00:	incl %esi
0x0042cb01:	xorl %eax, $0xffffffff<UINT8>
0x0042cb04:	je 0x0042cb7a
0x0042cb06:	movl %ebp, %eax
0x0042cb08:	addl %ebx, %ebx
0x0042cb0a:	jne 0x0042cb13
0x0042cb13:	adcl %ecx, %ecx
0x0042cb15:	addl %ebx, %ebx
0x0042cb17:	jne 0x0042cb20
0x0042cb20:	adcl %ecx, %ecx
0x0042cb22:	jne 0x0042cb44
0x0042cb44:	cmpl %ebp, $0xfffff300<UINT32>
0x0042cb4a:	adcl %ecx, $0x1<UINT8>
0x0042cb4d:	leal %edx, (%edi,%ebp)
0x0042cb50:	cmpl %ebp, $0xfffffffc<UINT8>
0x0042cb53:	jbe 0x0042cb64
0x0042cb55:	movb %al, (%edx)
0x0042cb57:	incl %edx
0x0042cb58:	movb (%edi), %al
0x0042cb5a:	incl %edi
0x0042cb5b:	decl %ecx
0x0042cb5c:	jne 0x0042cb55
0x0042cb5e:	jmp 0x0042cac6
0x0042cb64:	movl %eax, (%edx)
0x0042cb66:	addl %edx, $0x4<UINT8>
0x0042cb69:	movl (%edi), %eax
0x0042cb6b:	addl %edi, $0x4<UINT8>
0x0042cb6e:	subl %ecx, $0x4<UINT8>
0x0042cb71:	ja 0x0042cb64
0x0042cb73:	addl %edi, %ecx
0x0042cb75:	jmp 0x0042cac6
0x0042cb19:	movl %ebx, (%esi)
0x0042cb1b:	subl %esi, $0xfffffffc<UINT8>
0x0042cb1e:	adcl %ebx, %ebx
0x0042caeb:	movl %ebx, (%esi)
0x0042caed:	subl %esi, $0xfffffffc<UINT8>
0x0042caf0:	adcl %ebx, %ebx
0x0042caf2:	jae 0x0042cad8
0x0042cb24:	incl %ecx
0x0042cb25:	addl %ebx, %ebx
0x0042cb27:	jne 0x0042cb30
0x0042cb30:	adcl %ecx, %ecx
0x0042cb32:	addl %ebx, %ebx
0x0042cb34:	jae 0x0042cb25
0x0042cb36:	jne 0x0042cb41
0x0042cb41:	addl %ecx, $0x2<UINT8>
0x0042cadc:	movl %ebx, (%esi)
0x0042cade:	subl %esi, $0xfffffffc<UINT8>
0x0042cae1:	adcl %ebx, %ebx
0x0042cb0c:	movl %ebx, (%esi)
0x0042cb0e:	subl %esi, $0xfffffffc<UINT8>
0x0042cb11:	adcl %ebx, %ebx
0x0042cb38:	movl %ebx, (%esi)
0x0042cb3a:	subl %esi, $0xfffffffc<UINT8>
0x0042cb3d:	adcl %ebx, %ebx
0x0042cb3f:	jae 0x0042cb25
0x0042cb29:	movl %ebx, (%esi)
0x0042cb2b:	subl %esi, $0xfffffffc<UINT8>
0x0042cb2e:	adcl %ebx, %ebx
0x0042cb7a:	popl %esi
0x0042cb7b:	movl %edi, %esi
0x0042cb7d:	movl %ecx, $0x517<UINT32>
0x0042cb82:	movb %al, (%edi)
0x0042cb84:	incl %edi
0x0042cb85:	subb %al, $0xffffffe8<UINT8>
0x0042cb87:	cmpb %al, $0x1<UINT8>
0x0042cb89:	ja 0x0042cb82
0x0042cb8b:	cmpb (%edi), $0x5<UINT8>
0x0042cb8e:	jne 0x0042cb82
0x0042cb90:	movl %eax, (%edi)
0x0042cb92:	movb %bl, 0x4(%edi)
0x0042cb95:	shrw %ax, $0x8<UINT8>
0x0042cb99:	roll %eax, $0x10<UINT8>
0x0042cb9c:	xchgb %ah, %al
0x0042cb9e:	subl %eax, %edi
0x0042cba0:	subb %bl, $0xffffffe8<UINT8>
0x0042cba3:	addl %eax, %esi
0x0042cba5:	movl (%edi), %eax
0x0042cba7:	addl %edi, $0x5<UINT8>
0x0042cbaa:	movb %al, %bl
0x0042cbac:	loop 0x0042cb87
0x0042cbae:	leal %edi, 0x29000(%esi)
0x0042cbb4:	movl %eax, (%edi)
0x0042cbb6:	orl %eax, %eax
0x0042cbb8:	je 0x0042cbff
0x0042cbba:	movl %ebx, 0x4(%edi)
0x0042cbbd:	leal %eax, 0x2ca58(%eax,%esi)
0x0042cbc4:	addl %ebx, %esi
0x0042cbc6:	pushl %eax
0x0042cbc7:	addl %edi, $0x8<UINT8>
0x0042cbca:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x0042cbd0:	xchgl %ebp, %eax
0x0042cbd1:	movb %al, (%edi)
0x0042cbd3:	incl %edi
0x0042cbd4:	orb %al, %al
0x0042cbd6:	je 0x0042cbb4
0x0042cbd8:	movl %ecx, %edi
0x0042cbda:	jns 0x0042cbe3
0x0042cbe3:	pushl %edi
0x0042cbe4:	decl %eax
0x0042cbe5:	repn scasb %al, %es:(%edi)
0x0042cbe7:	pushl %ebp
0x0042cbe8:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0042cbee:	orl %eax, %eax
0x0042cbf0:	je 7
0x0042cbf2:	movl (%ebx), %eax
0x0042cbf4:	addl %ebx, $0x4<UINT8>
0x0042cbf7:	jmp 0x0042cbd1
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x0042cbdc:	movzwl %eax, (%edi)
0x0042cbdf:	incl %edi
0x0042cbe0:	pushl %eax
0x0042cbe1:	incl %edi
0x0042cbe2:	movl %ecx, $0xaef24857<UINT32>
0x0042cbff:	addl %edi, $0x4<UINT8>
0x0042cc02:	leal %ebx, -4(%esi)
0x0042cc05:	xorl %eax, %eax
0x0042cc07:	movb %al, (%edi)
0x0042cc09:	incl %edi
0x0042cc0a:	orl %eax, %eax
0x0042cc0c:	je 0x0042cc30
0x0042cc0e:	cmpb %al, $0xffffffef<UINT8>
0x0042cc10:	ja 0x0042cc23
0x0042cc12:	addl %ebx, %eax
0x0042cc14:	movl %eax, (%ebx)
0x0042cc16:	xchgb %ah, %al
0x0042cc18:	roll %eax, $0x10<UINT8>
0x0042cc1b:	xchgb %ah, %al
0x0042cc1d:	addl %eax, %esi
0x0042cc1f:	movl (%ebx), %eax
0x0042cc21:	jmp 0x0042cc05
0x0042cc23:	andb %al, $0xf<UINT8>
0x0042cc25:	shll %eax, $0x10<UINT8>
0x0042cc28:	movw %ax, (%edi)
0x0042cc2b:	addl %edi, $0x2<UINT8>
0x0042cc2e:	jmp 0x0042cc12
0x0042cc30:	movl %ebp, 0x2cb24(%esi)
0x0042cc36:	leal %edi, -4096(%esi)
0x0042cc3c:	movl %ebx, $0x1000<UINT32>
0x0042cc41:	pushl %eax
0x0042cc42:	pushl %esp
0x0042cc43:	pushl $0x4<UINT8>
0x0042cc45:	pushl %ebx
0x0042cc46:	pushl %edi
0x0042cc47:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0042cc49:	leal %eax, 0x217(%edi)
0x0042cc4f:	andb (%eax), $0x7f<UINT8>
0x0042cc52:	andb 0x28(%eax), $0x7f<UINT8>
0x0042cc56:	popl %eax
0x0042cc57:	pushl %eax
0x0042cc58:	pushl %esp
0x0042cc59:	pushl %eax
0x0042cc5a:	pushl %ebx
0x0042cc5b:	pushl %edi
0x0042cc5c:	call VirtualProtect@kernel32.dll
0x0042cc5e:	popl %eax
0x0042cc5f:	popa
0x0042cc60:	leal %eax, -128(%esp)
0x0042cc64:	pushl $0x0<UINT8>
0x0042cc66:	cmpl %esp, %eax
0x0042cc68:	jne 0x0042cc64
0x0042cc6a:	subl %esp, $0xffffff80<UINT8>
0x0042cc6d:	jmp 0x00404e14
0x00404e14:	call 0x0040a823
0x0040a823:	pushl %ebp
0x0040a824:	movl %ebp, %esp
0x0040a826:	subl %esp, $0x14<UINT8>
0x0040a829:	andl -12(%ebp), $0x0<UINT8>
0x0040a82d:	andl -8(%ebp), $0x0<UINT8>
0x0040a831:	movl %eax, 0x41d0d0
0x0040a836:	pushl %esi
0x0040a837:	pushl %edi
0x0040a838:	movl %edi, $0xbb40e64e<UINT32>
0x0040a83d:	movl %esi, $0xffff0000<UINT32>
0x0040a842:	cmpl %eax, %edi
0x0040a844:	je 0x0040a853
0x0040a853:	leal %eax, -12(%ebp)
0x0040a856:	pushl %eax
0x0040a857:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040a85d:	movl %eax, -8(%ebp)
0x0040a860:	xorl %eax, -12(%ebp)
0x0040a863:	movl -4(%ebp), %eax
0x0040a866:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040a86c:	xorl -4(%ebp), %eax
0x0040a86f:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040a875:	xorl -4(%ebp), %eax
0x0040a878:	leal %eax, -20(%ebp)
0x0040a87b:	pushl %eax
0x0040a87c:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040a882:	movl %ecx, -16(%ebp)
0x0040a885:	leal %eax, -4(%ebp)
0x0040a888:	xorl %ecx, -20(%ebp)
0x0040a88b:	xorl %ecx, -4(%ebp)
0x0040a88e:	xorl %ecx, %eax
0x0040a890:	cmpl %ecx, %edi
0x0040a892:	jne 0x0040a89b
0x0040a89b:	testl %esi, %ecx
0x0040a89d:	jne 0x0040a8ab
0x0040a8ab:	movl 0x41d0d0, %ecx
0x0040a8b1:	notl %ecx
0x0040a8b3:	movl 0x41d0d4, %ecx
0x0040a8b9:	popl %edi
0x0040a8ba:	popl %esi
0x0040a8bb:	movl %esp, %ebp
0x0040a8bd:	popl %ebp
0x0040a8be:	ret

0x00404e19:	jmp 0x00404e1e
0x00404e1e:	pushl $0x14<UINT8>
0x00404e20:	pushl $0x41b918<UINT32>
0x00404e25:	call 0x00408350
0x00408350:	pushl $0x4083b0<UINT32>
0x00408355:	pushl %fs:0
0x0040835c:	movl %eax, 0x10(%esp)
0x00408360:	movl 0x10(%esp), %ebp
0x00408364:	leal %ebp, 0x10(%esp)
0x00408368:	subl %esp, %eax
0x0040836a:	pushl %ebx
0x0040836b:	pushl %esi
0x0040836c:	pushl %edi
0x0040836d:	movl %eax, 0x41d0d0
0x00408372:	xorl -4(%ebp), %eax
0x00408375:	xorl %eax, %ebp
0x00408377:	pushl %eax
0x00408378:	movl -24(%ebp), %esp
0x0040837b:	pushl -8(%ebp)
0x0040837e:	movl %eax, -4(%ebp)
0x00408381:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00408388:	movl -8(%ebp), %eax
0x0040838b:	leal %eax, -16(%ebp)
0x0040838e:	movl %fs:0, %eax
0x00408394:	ret

0x00404e2a:	call 0x0040962c
0x0040962c:	pushl %ebp
0x0040962d:	movl %ebp, %esp
0x0040962f:	subl %esp, $0x44<UINT8>
0x00409632:	leal %eax, -68(%ebp)
0x00409635:	pushl %eax
0x00409636:	call GetStartupInfoW@KERNEL32.DLL
GetStartupInfoW@KERNEL32.DLL: API Node	
0x0040963c:	testb -24(%ebp), $0x1<UINT8>
0x00409640:	je 0x00409648
0x00409648:	pushl $0xa<UINT8>
0x0040964a:	popl %eax
0x0040964b:	movl %esp, %ebp
0x0040964d:	popl %ebp
0x0040964e:	ret

0x00404e2f:	movzwl %esi, %ax
0x00404e32:	pushl $0x2<UINT8>
0x00404e34:	call 0x0040a7d6
0x0040a7d6:	pushl %ebp
0x0040a7d7:	movl %ebp, %esp
0x0040a7d9:	movl %eax, 0x8(%ebp)
0x0040a7dc:	movl 0x41e8a0, %eax
0x0040a7e1:	popl %ebp
0x0040a7e2:	ret

0x00404e39:	popl %ecx
0x00404e3a:	movl %eax, $0x5a4d<UINT32>
0x00404e3f:	cmpw 0x400000, %ax
0x00404e46:	je 0x00404e4c
0x00404e4c:	movl %eax, 0x40003c
0x00404e51:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00404e5b:	jne -21
0x00404e5d:	movl %ecx, $0x10b<UINT32>
0x00404e62:	cmpw 0x400018(%eax), %cx
0x00404e69:	jne -35
0x00404e6b:	xorl %ebx, %ebx
0x00404e6d:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00404e74:	jbe 9
0x00404e76:	cmpl 0x4000e8(%eax), %ebx
0x00404e7c:	setne %bl
0x00404e7f:	movl -28(%ebp), %ebx
0x00404e82:	call 0x00409bdc
0x00409bdc:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x00409be2:	xorl %ecx, %ecx
0x00409be4:	movl 0x41eed8, %eax
0x00409be9:	testl %eax, %eax
0x00409beb:	setne %cl
0x00409bee:	movl %eax, %ecx
0x00409bf0:	ret

0x00404e87:	testl %eax, %eax
0x00404e89:	jne 0x00404e93
0x00404e93:	call 0x0040601c
0x0040601c:	call 0x0040423e
0x0040423e:	pushl %esi
0x0040423f:	pushl $0x0<UINT8>
0x00404241:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00404247:	movl %esi, %eax
0x00404249:	pushl %esi
0x0040424a:	call 0x00409bcf
0x00409bcf:	pushl %ebp
0x00409bd0:	movl %ebp, %esp
0x00409bd2:	movl %eax, 0x8(%ebp)
0x00409bd5:	movl 0x41eed0, %eax
0x00409bda:	popl %ebp
0x00409bdb:	ret

0x0040424f:	pushl %esi
0x00404250:	call 0x00406226
0x00406226:	pushl %ebp
0x00406227:	movl %ebp, %esp
0x00406229:	movl %eax, 0x8(%ebp)
0x0040622c:	movl 0x41e308, %eax
0x00406231:	popl %ebp
0x00406232:	ret

0x00404255:	pushl %esi
0x00404256:	call 0x00409fd5
0x00409fd5:	pushl %ebp
0x00409fd6:	movl %ebp, %esp
0x00409fd8:	movl %eax, 0x8(%ebp)
0x00409fdb:	movl 0x41eee0, %eax
0x00409fe0:	popl %ebp
0x00409fe1:	ret

0x0040425b:	pushl %esi
0x0040425c:	call 0x00409fef
0x00409fef:	pushl %ebp
0x00409ff0:	movl %ebp, %esp
0x00409ff2:	movl %eax, 0x8(%ebp)
0x00409ff5:	movl 0x41eee4, %eax
0x00409ffa:	movl 0x41eee8, %eax
0x00409fff:	movl 0x41eeec, %eax
0x0040a004:	movl 0x41eef0, %eax
0x0040a009:	popl %ebp
0x0040a00a:	ret

0x00404261:	pushl %esi
0x00404262:	call 0x00409fc4
0x00409fc4:	pushl $0x409f90<UINT32>
0x00409fc9:	call EncodePointer@KERNEL32.DLL
0x00409fcf:	movl 0x41eedc, %eax
0x00409fd4:	ret

0x00404267:	pushl %esi
0x00404268:	call 0x0040a200
0x0040a200:	pushl %ebp
0x0040a201:	movl %ebp, %esp
0x0040a203:	movl %eax, 0x8(%ebp)
0x0040a206:	movl 0x41eef8, %eax
0x0040a20b:	popl %ebp
0x0040a20c:	ret

0x0040426d:	addl %esp, $0x18<UINT8>
0x00404270:	popl %esi
0x00404271:	jmp 0x004096bd
0x004096bd:	pushl %esi
0x004096be:	pushl %edi
0x004096bf:	pushl $0x418044<UINT32>
0x004096c4:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x004096ca:	movl %esi, 0x4110e0
0x004096d0:	movl %edi, %eax
0x004096d2:	pushl $0x418060<UINT32>
0x004096d7:	pushl %edi
0x004096d8:	call GetProcAddress@KERNEL32.DLL
0x004096da:	xorl %eax, 0x41d0d0
0x004096e0:	pushl $0x41806c<UINT32>
0x004096e5:	pushl %edi
0x004096e6:	movl 0x425dc0, %eax
0x004096eb:	call GetProcAddress@KERNEL32.DLL
0x004096ed:	xorl %eax, 0x41d0d0
0x004096f3:	pushl $0x418074<UINT32>
0x004096f8:	pushl %edi
0x004096f9:	movl 0x425dc4, %eax
0x004096fe:	call GetProcAddress@KERNEL32.DLL
0x00409700:	xorl %eax, 0x41d0d0
0x00409706:	pushl $0x418080<UINT32>
0x0040970b:	pushl %edi
0x0040970c:	movl 0x425dc8, %eax
0x00409711:	call GetProcAddress@KERNEL32.DLL
0x00409713:	xorl %eax, 0x41d0d0
0x00409719:	pushl $0x41808c<UINT32>
0x0040971e:	pushl %edi
0x0040971f:	movl 0x425dcc, %eax
0x00409724:	call GetProcAddress@KERNEL32.DLL
0x00409726:	xorl %eax, 0x41d0d0
0x0040972c:	pushl $0x4180a8<UINT32>
0x00409731:	pushl %edi
0x00409732:	movl 0x425dd0, %eax
0x00409737:	call GetProcAddress@KERNEL32.DLL
0x00409739:	xorl %eax, 0x41d0d0
0x0040973f:	pushl $0x4180b8<UINT32>
0x00409744:	pushl %edi
0x00409745:	movl 0x425dd4, %eax
0x0040974a:	call GetProcAddress@KERNEL32.DLL
0x0040974c:	xorl %eax, 0x41d0d0
0x00409752:	pushl $0x4180cc<UINT32>
0x00409757:	pushl %edi
0x00409758:	movl 0x425dd8, %eax
0x0040975d:	call GetProcAddress@KERNEL32.DLL
0x0040975f:	xorl %eax, 0x41d0d0
0x00409765:	pushl $0x4180e4<UINT32>
0x0040976a:	pushl %edi
0x0040976b:	movl 0x425ddc, %eax
0x00409770:	call GetProcAddress@KERNEL32.DLL
0x00409772:	xorl %eax, 0x41d0d0
0x00409778:	pushl $0x4180fc<UINT32>
0x0040977d:	pushl %edi
0x0040977e:	movl 0x425de0, %eax
0x00409783:	call GetProcAddress@KERNEL32.DLL
0x00409785:	xorl %eax, 0x41d0d0
0x0040978b:	pushl $0x418110<UINT32>
0x00409790:	pushl %edi
0x00409791:	movl 0x425de4, %eax
0x00409796:	call GetProcAddress@KERNEL32.DLL
0x00409798:	xorl %eax, 0x41d0d0
0x0040979e:	pushl $0x418130<UINT32>
0x004097a3:	pushl %edi
0x004097a4:	movl 0x425de8, %eax
0x004097a9:	call GetProcAddress@KERNEL32.DLL
0x004097ab:	xorl %eax, 0x41d0d0
0x004097b1:	pushl $0x418148<UINT32>
0x004097b6:	pushl %edi
0x004097b7:	movl 0x425dec, %eax
0x004097bc:	call GetProcAddress@KERNEL32.DLL
0x004097be:	xorl %eax, 0x41d0d0
0x004097c4:	pushl $0x418160<UINT32>
0x004097c9:	pushl %edi
0x004097ca:	movl 0x425df0, %eax
0x004097cf:	call GetProcAddress@KERNEL32.DLL
0x004097d1:	xorl %eax, 0x41d0d0
0x004097d7:	pushl $0x418174<UINT32>
0x004097dc:	pushl %edi
0x004097dd:	movl 0x425df4, %eax
0x004097e2:	call GetProcAddress@KERNEL32.DLL
0x004097e4:	xorl %eax, 0x41d0d0
0x004097ea:	movl 0x425df8, %eax
0x004097ef:	pushl $0x418188<UINT32>
0x004097f4:	pushl %edi
0x004097f5:	call GetProcAddress@KERNEL32.DLL
0x004097f7:	xorl %eax, 0x41d0d0
0x004097fd:	pushl $0x4181a4<UINT32>
0x00409802:	pushl %edi
0x00409803:	movl 0x425dfc, %eax
0x00409808:	call GetProcAddress@KERNEL32.DLL
0x0040980a:	xorl %eax, 0x41d0d0
0x00409810:	pushl $0x4181c4<UINT32>
0x00409815:	pushl %edi
0x00409816:	movl 0x425e00, %eax
0x0040981b:	call GetProcAddress@KERNEL32.DLL
0x0040981d:	xorl %eax, 0x41d0d0
0x00409823:	pushl $0x4181e0<UINT32>
0x00409828:	pushl %edi
0x00409829:	movl 0x425e04, %eax
0x0040982e:	call GetProcAddress@KERNEL32.DLL
0x00409830:	xorl %eax, 0x41d0d0
0x00409836:	pushl $0x418200<UINT32>
0x0040983b:	pushl %edi
0x0040983c:	movl 0x425e08, %eax
0x00409841:	call GetProcAddress@KERNEL32.DLL
0x00409843:	xorl %eax, 0x41d0d0
0x00409849:	pushl $0x418214<UINT32>
0x0040984e:	pushl %edi
0x0040984f:	movl 0x425e0c, %eax
0x00409854:	call GetProcAddress@KERNEL32.DLL
0x00409856:	xorl %eax, 0x41d0d0
0x0040985c:	pushl $0x418230<UINT32>
0x00409861:	pushl %edi
0x00409862:	movl 0x425e10, %eax
0x00409867:	call GetProcAddress@KERNEL32.DLL
0x00409869:	xorl %eax, 0x41d0d0
0x0040986f:	pushl $0x418244<UINT32>
0x00409874:	pushl %edi
0x00409875:	movl 0x425e18, %eax
0x0040987a:	call GetProcAddress@KERNEL32.DLL
0x0040987c:	xorl %eax, 0x41d0d0
0x00409882:	pushl $0x418254<UINT32>
0x00409887:	pushl %edi
0x00409888:	movl 0x425e14, %eax
0x0040988d:	call GetProcAddress@KERNEL32.DLL
0x0040988f:	xorl %eax, 0x41d0d0
0x00409895:	pushl $0x418264<UINT32>
0x0040989a:	pushl %edi
0x0040989b:	movl 0x425e1c, %eax
0x004098a0:	call GetProcAddress@KERNEL32.DLL
0x004098a2:	xorl %eax, 0x41d0d0
0x004098a8:	pushl $0x418274<UINT32>
0x004098ad:	pushl %edi
0x004098ae:	movl 0x425e20, %eax
0x004098b3:	call GetProcAddress@KERNEL32.DLL
0x004098b5:	xorl %eax, 0x41d0d0
0x004098bb:	pushl $0x418284<UINT32>
0x004098c0:	pushl %edi
0x004098c1:	movl 0x425e24, %eax
0x004098c6:	call GetProcAddress@KERNEL32.DLL
0x004098c8:	xorl %eax, 0x41d0d0
0x004098ce:	pushl $0x4182a0<UINT32>
0x004098d3:	pushl %edi
0x004098d4:	movl 0x425e28, %eax
0x004098d9:	call GetProcAddress@KERNEL32.DLL
0x004098db:	xorl %eax, 0x41d0d0
0x004098e1:	pushl $0x4182b4<UINT32>
0x004098e6:	pushl %edi
0x004098e7:	movl 0x425e2c, %eax
0x004098ec:	call GetProcAddress@KERNEL32.DLL
0x004098ee:	xorl %eax, 0x41d0d0
0x004098f4:	pushl $0x4182c4<UINT32>
0x004098f9:	pushl %edi
0x004098fa:	movl 0x425e30, %eax
0x004098ff:	call GetProcAddress@KERNEL32.DLL
0x00409901:	xorl %eax, 0x41d0d0
0x00409907:	pushl $0x4182d8<UINT32>
0x0040990c:	pushl %edi
0x0040990d:	movl 0x425e34, %eax
0x00409912:	call GetProcAddress@KERNEL32.DLL
0x00409914:	xorl %eax, 0x41d0d0
0x0040991a:	movl 0x425e38, %eax
0x0040991f:	pushl $0x4182e8<UINT32>
0x00409924:	pushl %edi
0x00409925:	call GetProcAddress@KERNEL32.DLL
0x00409927:	xorl %eax, 0x41d0d0
0x0040992d:	pushl $0x418308<UINT32>
0x00409932:	pushl %edi
0x00409933:	movl 0x425e3c, %eax
0x00409938:	call GetProcAddress@KERNEL32.DLL
0x0040993a:	xorl %eax, 0x41d0d0
0x00409940:	popl %edi
0x00409941:	movl 0x425e40, %eax
0x00409946:	popl %esi
0x00409947:	ret

0x00406021:	call 0x004077ec
0x004077ec:	pushl %esi
0x004077ed:	pushl %edi
0x004077ee:	movl %esi, $0x41dc40<UINT32>
0x004077f3:	movl %edi, $0x41e638<UINT32>
0x004077f8:	cmpl 0x4(%esi), $0x1<UINT8>
0x004077fc:	jne 22
0x004077fe:	pushl $0x0<UINT8>
0x00407800:	movl (%esi), %edi
0x00407802:	addl %edi, $0x18<UINT8>
0x00407805:	pushl $0xfa0<UINT32>
0x0040780a:	pushl (%esi)
0x0040780c:	call 0x0040964f
0x0040964f:	pushl %ebp
0x00409650:	movl %ebp, %esp
0x00409652:	movl %eax, 0x425dd0
0x00409657:	xorl %eax, 0x41d0d0
0x0040965d:	je 13
0x0040965f:	pushl 0x10(%ebp)
0x00409662:	pushl 0xc(%ebp)
0x00409665:	pushl 0x8(%ebp)
0x00409668:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x0040966a:	popl %ebp
0x0040966b:	ret

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
