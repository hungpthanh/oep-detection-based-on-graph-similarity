0x00428f10:	pusha
0x00428f11:	movl %esi, $0x41b000<UINT32>
0x00428f16:	leal %edi, -106496(%esi)
0x00428f1c:	pushl %edi
0x00428f1d:	jmp 0x00428f2a
0x00428f2a:	movl %ebx, (%esi)
0x00428f2c:	subl %esi, $0xfffffffc<UINT8>
0x00428f2f:	adcl %ebx, %ebx
0x00428f31:	jb 0x00428f20
0x00428f20:	movb %al, (%esi)
0x00428f22:	incl %esi
0x00428f23:	movb (%edi), %al
0x00428f25:	incl %edi
0x00428f26:	addl %ebx, %ebx
0x00428f28:	jne 0x00428f31
0x00428f33:	movl %eax, $0x1<UINT32>
0x00428f38:	addl %ebx, %ebx
0x00428f3a:	jne 0x00428f43
0x00428f43:	adcl %eax, %eax
0x00428f45:	addl %ebx, %ebx
0x00428f47:	jae 0x00428f38
0x00428f49:	jne 0x00428f54
0x00428f54:	xorl %ecx, %ecx
0x00428f56:	subl %eax, $0x3<UINT8>
0x00428f59:	jb 0x00428f68
0x00428f5b:	shll %eax, $0x8<UINT8>
0x00428f5e:	movb %al, (%esi)
0x00428f60:	incl %esi
0x00428f61:	xorl %eax, $0xffffffff<UINT8>
0x00428f64:	je 0x00428fda
0x00428f66:	movl %ebp, %eax
0x00428f68:	addl %ebx, %ebx
0x00428f6a:	jne 0x00428f73
0x00428f73:	adcl %ecx, %ecx
0x00428f75:	addl %ebx, %ebx
0x00428f77:	jne 0x00428f80
0x00428f80:	adcl %ecx, %ecx
0x00428f82:	jne 0x00428fa4
0x00428fa4:	cmpl %ebp, $0xfffff300<UINT32>
0x00428faa:	adcl %ecx, $0x1<UINT8>
0x00428fad:	leal %edx, (%edi,%ebp)
0x00428fb0:	cmpl %ebp, $0xfffffffc<UINT8>
0x00428fb3:	jbe 0x00428fc4
0x00428fc4:	movl %eax, (%edx)
0x00428fc6:	addl %edx, $0x4<UINT8>
0x00428fc9:	movl (%edi), %eax
0x00428fcb:	addl %edi, $0x4<UINT8>
0x00428fce:	subl %ecx, $0x4<UINT8>
0x00428fd1:	ja 0x00428fc4
0x00428fd3:	addl %edi, %ecx
0x00428fd5:	jmp 0x00428f26
0x00428fb5:	movb %al, (%edx)
0x00428fb7:	incl %edx
0x00428fb8:	movb (%edi), %al
0x00428fba:	incl %edi
0x00428fbb:	decl %ecx
0x00428fbc:	jne 0x00428fb5
0x00428fbe:	jmp 0x00428f26
0x00428f84:	incl %ecx
0x00428f85:	addl %ebx, %ebx
0x00428f87:	jne 0x00428f90
0x00428f90:	adcl %ecx, %ecx
0x00428f92:	addl %ebx, %ebx
0x00428f94:	jae 0x00428f85
0x00428f96:	jne 0x00428fa1
0x00428fa1:	addl %ecx, $0x2<UINT8>
0x00428f4b:	movl %ebx, (%esi)
0x00428f4d:	subl %esi, $0xfffffffc<UINT8>
0x00428f50:	adcl %ebx, %ebx
0x00428f52:	jae 0x00428f38
0x00428f3c:	movl %ebx, (%esi)
0x00428f3e:	subl %esi, $0xfffffffc<UINT8>
0x00428f41:	adcl %ebx, %ebx
0x00428f89:	movl %ebx, (%esi)
0x00428f8b:	subl %esi, $0xfffffffc<UINT8>
0x00428f8e:	adcl %ebx, %ebx
0x00428f6c:	movl %ebx, (%esi)
0x00428f6e:	subl %esi, $0xfffffffc<UINT8>
0x00428f71:	adcl %ebx, %ebx
0x00428f79:	movl %ebx, (%esi)
0x00428f7b:	subl %esi, $0xfffffffc<UINT8>
0x00428f7e:	adcl %ebx, %ebx
0x00428f98:	movl %ebx, (%esi)
0x00428f9a:	subl %esi, $0xfffffffc<UINT8>
0x00428f9d:	adcl %ebx, %ebx
0x00428f9f:	jae 0x00428f85
0x00428fda:	popl %esi
0x00428fdb:	movl %edi, %esi
0x00428fdd:	movl %ecx, $0x6d4<UINT32>
0x00428fe2:	movb %al, (%edi)
0x00428fe4:	incl %edi
0x00428fe5:	subb %al, $0xffffffe8<UINT8>
0x00428fe7:	cmpb %al, $0x1<UINT8>
0x00428fe9:	ja 0x00428fe2
0x00428feb:	cmpb (%edi), $0x5<UINT8>
0x00428fee:	jne 0x00428fe2
0x00428ff0:	movl %eax, (%edi)
0x00428ff2:	movb %bl, 0x4(%edi)
0x00428ff5:	shrw %ax, $0x8<UINT8>
0x00428ff9:	roll %eax, $0x10<UINT8>
0x00428ffc:	xchgb %ah, %al
0x00428ffe:	subl %eax, %edi
0x00429000:	subb %bl, $0xffffffe8<UINT8>
0x00429003:	addl %eax, %esi
0x00429005:	movl (%edi), %eax
0x00429007:	addl %edi, $0x5<UINT8>
0x0042900a:	movb %al, %bl
0x0042900c:	loop 0x00428fe7
0x0042900e:	leal %edi, 0x26000(%esi)
0x00429014:	movl %eax, (%edi)
0x00429016:	orl %eax, %eax
0x00429018:	je 0x00429056
0x0042901a:	movl %ebx, 0x4(%edi)
0x0042901d:	leal %eax, 0x29570(%eax,%esi)
0x00429024:	addl %ebx, %esi
0x00429026:	pushl %eax
0x00429027:	addl %edi, $0x8<UINT8>
0x0042902a:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x00429030:	xchgl %ebp, %eax
0x00429031:	movb %al, (%edi)
0x00429033:	incl %edi
0x00429034:	orb %al, %al
0x00429036:	je 0x00429014
0x00429038:	movl %ecx, %edi
0x0042903a:	pushl %edi
0x0042903b:	decl %eax
0x0042903c:	repn scasb %al, %es:(%edi)
0x0042903e:	pushl %ebp
0x0042903f:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00429045:	orl %eax, %eax
0x00429047:	je 7
0x00429049:	movl (%ebx), %eax
0x0042904b:	addl %ebx, $0x4<UINT8>
0x0042904e:	jmp 0x00429031
GetProcAddress@KERNEL32.DLL: API Node	
0x00429056:	movl %ebp, 0x29618(%esi)
0x0042905c:	leal %edi, -4096(%esi)
0x00429062:	movl %ebx, $0x1000<UINT32>
0x00429067:	pushl %eax
0x00429068:	pushl %esp
0x00429069:	pushl $0x4<UINT8>
0x0042906b:	pushl %ebx
0x0042906c:	pushl %edi
0x0042906d:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0042906f:	leal %eax, 0x21f(%edi)
0x00429075:	andb (%eax), $0x7f<UINT8>
0x00429078:	andb 0x28(%eax), $0x7f<UINT8>
0x0042907c:	popl %eax
0x0042907d:	pushl %eax
0x0042907e:	pushl %esp
0x0042907f:	pushl %eax
0x00429080:	pushl %ebx
0x00429081:	pushl %edi
0x00429082:	call VirtualProtect@kernel32.dll
0x00429084:	popl %eax
0x00429085:	popa
0x00429086:	leal %eax, -128(%esp)
0x0042908a:	pushl $0x0<UINT8>
0x0042908c:	cmpl %esp, %eax
0x0042908e:	jne 0x0042908a
0x00429090:	subl %esp, $0xffffff80<UINT8>
0x00429093:	jmp 0x00405be3
0x00405be3:	call 0x0040c67e
0x0040c67e:	pushl %ebp
0x0040c67f:	movl %ebp, %esp
0x0040c681:	subl %esp, $0x14<UINT8>
0x0040c684:	andl -12(%ebp), $0x0<UINT8>
0x0040c688:	andl -8(%ebp), $0x0<UINT8>
0x0040c68c:	movl %eax, 0x4210d0
0x0040c691:	pushl %esi
0x0040c692:	pushl %edi
0x0040c693:	movl %edi, $0xbb40e64e<UINT32>
0x0040c698:	movl %esi, $0xffff0000<UINT32>
0x0040c69d:	cmpl %eax, %edi
0x0040c69f:	je 0x0040c6ae
0x0040c6ae:	leal %eax, -12(%ebp)
0x0040c6b1:	pushl %eax
0x0040c6b2:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040c6b8:	movl %eax, -8(%ebp)
0x0040c6bb:	xorl %eax, -12(%ebp)
0x0040c6be:	movl -4(%ebp), %eax
0x0040c6c1:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040c6c7:	xorl -4(%ebp), %eax
0x0040c6ca:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040c6d0:	xorl -4(%ebp), %eax
0x0040c6d3:	leal %eax, -20(%ebp)
0x0040c6d6:	pushl %eax
0x0040c6d7:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040c6dd:	movl %ecx, -16(%ebp)
0x0040c6e0:	leal %eax, -4(%ebp)
0x0040c6e3:	xorl %ecx, -20(%ebp)
0x0040c6e6:	xorl %ecx, -4(%ebp)
0x0040c6e9:	xorl %ecx, %eax
0x0040c6eb:	cmpl %ecx, %edi
0x0040c6ed:	jne 0x0040c6f6
0x0040c6f6:	testl %esi, %ecx
0x0040c6f8:	jne 0x0040c706
0x0040c706:	movl 0x4210d0, %ecx
0x0040c70c:	notl %ecx
0x0040c70e:	movl 0x4210d4, %ecx
0x0040c714:	popl %edi
0x0040c715:	popl %esi
0x0040c716:	movl %esp, %ebp
0x0040c718:	popl %ebp
0x0040c719:	ret

0x00405be8:	jmp 0x00405a68
0x00405a68:	pushl $0x14<UINT8>
0x00405a6a:	pushl $0x41f590<UINT32>
0x00405a6f:	call 0x00407a30
0x00407a30:	pushl $0x4056c0<UINT32>
0x00407a35:	pushl %fs:0
0x00407a3c:	movl %eax, 0x10(%esp)
0x00407a40:	movl 0x10(%esp), %ebp
0x00407a44:	leal %ebp, 0x10(%esp)
0x00407a48:	subl %esp, %eax
0x00407a4a:	pushl %ebx
0x00407a4b:	pushl %esi
0x00407a4c:	pushl %edi
0x00407a4d:	movl %eax, 0x4210d0
0x00407a52:	xorl -4(%ebp), %eax
0x00407a55:	xorl %eax, %ebp
0x00407a57:	pushl %eax
0x00407a58:	movl -24(%ebp), %esp
0x00407a5b:	pushl -8(%ebp)
0x00407a5e:	movl %eax, -4(%ebp)
0x00407a61:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00407a68:	movl -8(%ebp), %eax
0x00407a6b:	leal %eax, -16(%ebp)
0x00407a6e:	movl %fs:0, %eax
0x00407a74:	ret

0x00405a74:	pushl $0x1<UINT8>
0x00405a76:	call 0x0040c631
0x0040c631:	pushl %ebp
0x0040c632:	movl %ebp, %esp
0x0040c634:	movl %eax, 0x8(%ebp)
0x0040c637:	movl 0x423a18, %eax
0x0040c63c:	popl %ebp
0x0040c63d:	ret

0x00405a7b:	popl %ecx
0x00405a7c:	movl %eax, $0x5a4d<UINT32>
0x00405a81:	cmpw 0x400000, %ax
0x00405a88:	je 0x00405a8e
0x00405a8e:	movl %eax, 0x40003c
0x00405a93:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00405a9d:	jne -21
0x00405a9f:	movl %ecx, $0x10b<UINT32>
0x00405aa4:	cmpw 0x400018(%eax), %cx
0x00405aab:	jne -35
0x00405aad:	xorl %ebx, %ebx
0x00405aaf:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00405ab6:	jbe 9
0x00405ab8:	cmpl 0x4000e8(%eax), %ebx
0x00405abe:	setne %bl
0x00405ac1:	movl -28(%ebp), %ebx
0x00405ac4:	call 0x00407b60
0x00407b60:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x00407b66:	xorl %ecx, %ecx
0x00407b68:	movl 0x424078, %eax
0x00407b6d:	testl %eax, %eax
0x00407b6f:	setne %cl
0x00407b72:	movl %eax, %ecx
0x00407b74:	ret

0x00405ac9:	testl %eax, %eax
0x00405acb:	jne 0x00405ad5
0x00405ad5:	call 0x00406aef
0x00406aef:	call 0x0040395a
0x0040395a:	pushl %esi
0x0040395b:	pushl $0x0<UINT8>
0x0040395d:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00403963:	movl %esi, %eax
0x00403965:	pushl %esi
0x00403966:	call 0x004077e4
0x004077e4:	pushl %ebp
0x004077e5:	movl %ebp, %esp
0x004077e7:	movl %eax, 0x8(%ebp)
0x004077ea:	movl 0x424050, %eax
0x004077ef:	popl %ebp
0x004077f0:	ret

0x0040396b:	pushl %esi
0x0040396c:	call 0x00405d12
0x00405d12:	pushl %ebp
0x00405d13:	movl %ebp, %esp
0x00405d15:	movl %eax, 0x8(%ebp)
0x00405d18:	movl 0x4238a0, %eax
0x00405d1d:	popl %ebp
0x00405d1e:	ret

0x00403971:	pushl %esi
0x00403972:	call 0x004077f1
0x004077f1:	pushl %ebp
0x004077f2:	movl %ebp, %esp
0x004077f4:	movl %eax, 0x8(%ebp)
0x004077f7:	movl 0x424054, %eax
0x004077fc:	popl %ebp
0x004077fd:	ret

0x00403977:	pushl %esi
0x00403978:	call 0x0040780b
0x0040780b:	pushl %ebp
0x0040780c:	movl %ebp, %esp
0x0040780e:	movl %eax, 0x8(%ebp)
0x00407811:	movl 0x424058, %eax
0x00407816:	movl 0x42405c, %eax
0x0040781b:	movl 0x424060, %eax
0x00407820:	movl 0x424064, %eax
0x00407825:	popl %ebp
0x00407826:	ret

0x0040397d:	pushl %esi
0x0040397e:	call 0x004077ad
0x004077ad:	pushl $0x407779<UINT32>
0x004077b2:	call EncodePointer@KERNEL32.DLL
0x004077b8:	movl 0x42404c, %eax
0x004077bd:	ret

0x00403983:	pushl %esi
0x00403984:	call 0x00407a1c
0x00407a1c:	pushl %ebp
0x00407a1d:	movl %ebp, %esp
0x00407a1f:	movl %eax, 0x8(%ebp)
0x00407a22:	movl 0x42406c, %eax
0x00407a27:	popl %ebp
0x00407a28:	ret

0x00403989:	addl %esp, $0x18<UINT8>
0x0040398c:	popl %esi
0x0040398d:	jmp 0x00406f07
0x00406f07:	pushl %esi
0x00406f08:	pushl %edi
0x00406f09:	pushl $0x41bac0<UINT32>
0x00406f0e:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00406f14:	movl %esi, 0x41407c
0x00406f1a:	movl %edi, %eax
0x00406f1c:	pushl $0x41badc<UINT32>
0x00406f21:	pushl %edi
0x00406f22:	call GetProcAddress@KERNEL32.DLL
0x00406f24:	xorl %eax, 0x4210d0
0x00406f2a:	pushl $0x41bae8<UINT32>
0x00406f2f:	pushl %edi
0x00406f30:	movl 0x424a40, %eax
0x00406f35:	call GetProcAddress@KERNEL32.DLL
0x00406f37:	xorl %eax, 0x4210d0
0x00406f3d:	pushl $0x41baf0<UINT32>
0x00406f42:	pushl %edi
0x00406f43:	movl 0x424a44, %eax
0x00406f48:	call GetProcAddress@KERNEL32.DLL
0x00406f4a:	xorl %eax, 0x4210d0
0x00406f50:	pushl $0x41bafc<UINT32>
0x00406f55:	pushl %edi
0x00406f56:	movl 0x424a48, %eax
0x00406f5b:	call GetProcAddress@KERNEL32.DLL
0x00406f5d:	xorl %eax, 0x4210d0
0x00406f63:	pushl $0x41bb08<UINT32>
0x00406f68:	pushl %edi
0x00406f69:	movl 0x424a4c, %eax
0x00406f6e:	call GetProcAddress@KERNEL32.DLL
0x00406f70:	xorl %eax, 0x4210d0
0x00406f76:	pushl $0x41bb24<UINT32>
0x00406f7b:	pushl %edi
0x00406f7c:	movl 0x424a50, %eax
0x00406f81:	call GetProcAddress@KERNEL32.DLL
0x00406f83:	xorl %eax, 0x4210d0
0x00406f89:	pushl $0x41bb34<UINT32>
0x00406f8e:	pushl %edi
0x00406f8f:	movl 0x424a54, %eax
0x00406f94:	call GetProcAddress@KERNEL32.DLL
0x00406f96:	xorl %eax, 0x4210d0
0x00406f9c:	pushl $0x41bb48<UINT32>
0x00406fa1:	pushl %edi
0x00406fa2:	movl 0x424a58, %eax
0x00406fa7:	call GetProcAddress@KERNEL32.DLL
0x00406fa9:	xorl %eax, 0x4210d0
0x00406faf:	pushl $0x41bb60<UINT32>
0x00406fb4:	pushl %edi
0x00406fb5:	movl 0x424a5c, %eax
0x00406fba:	call GetProcAddress@KERNEL32.DLL
0x00406fbc:	xorl %eax, 0x4210d0
0x00406fc2:	pushl $0x41bb78<UINT32>
0x00406fc7:	pushl %edi
0x00406fc8:	movl 0x424a60, %eax
0x00406fcd:	call GetProcAddress@KERNEL32.DLL
0x00406fcf:	xorl %eax, 0x4210d0
0x00406fd5:	pushl $0x41bb8c<UINT32>
0x00406fda:	pushl %edi
0x00406fdb:	movl 0x424a64, %eax
0x00406fe0:	call GetProcAddress@KERNEL32.DLL
0x00406fe2:	xorl %eax, 0x4210d0
0x00406fe8:	pushl $0x41bbac<UINT32>
0x00406fed:	pushl %edi
0x00406fee:	movl 0x424a68, %eax
0x00406ff3:	call GetProcAddress@KERNEL32.DLL
0x00406ff5:	xorl %eax, 0x4210d0
0x00406ffb:	pushl $0x41bbc4<UINT32>
0x00407000:	pushl %edi
0x00407001:	movl 0x424a6c, %eax
0x00407006:	call GetProcAddress@KERNEL32.DLL
0x00407008:	xorl %eax, 0x4210d0
0x0040700e:	pushl $0x41bbdc<UINT32>
0x00407013:	pushl %edi
0x00407014:	movl 0x424a70, %eax
0x00407019:	call GetProcAddress@KERNEL32.DLL
0x0040701b:	xorl %eax, 0x4210d0
0x00407021:	pushl $0x41bbf0<UINT32>
0x00407026:	pushl %edi
0x00407027:	movl 0x424a74, %eax
0x0040702c:	call GetProcAddress@KERNEL32.DLL
0x0040702e:	xorl %eax, 0x4210d0
0x00407034:	movl 0x424a78, %eax
0x00407039:	pushl $0x41bc04<UINT32>
0x0040703e:	pushl %edi
0x0040703f:	call GetProcAddress@KERNEL32.DLL
0x00407041:	xorl %eax, 0x4210d0
0x00407047:	pushl $0x41bc20<UINT32>
0x0040704c:	pushl %edi
0x0040704d:	movl 0x424a7c, %eax
0x00407052:	call GetProcAddress@KERNEL32.DLL
0x00407054:	xorl %eax, 0x4210d0
0x0040705a:	pushl $0x41bc40<UINT32>
0x0040705f:	pushl %edi
0x00407060:	movl 0x424a80, %eax
0x00407065:	call GetProcAddress@KERNEL32.DLL
0x00407067:	xorl %eax, 0x4210d0
0x0040706d:	pushl $0x41bc5c<UINT32>
0x00407072:	pushl %edi
0x00407073:	movl 0x424a84, %eax
0x00407078:	call GetProcAddress@KERNEL32.DLL
0x0040707a:	xorl %eax, 0x4210d0
0x00407080:	pushl $0x41bc7c<UINT32>
0x00407085:	pushl %edi
0x00407086:	movl 0x424a88, %eax
0x0040708b:	call GetProcAddress@KERNEL32.DLL
0x0040708d:	xorl %eax, 0x4210d0
0x00407093:	pushl $0x41bc90<UINT32>
0x00407098:	pushl %edi
0x00407099:	movl 0x424a8c, %eax
0x0040709e:	call GetProcAddress@KERNEL32.DLL
0x004070a0:	xorl %eax, 0x4210d0
0x004070a6:	pushl $0x41bcac<UINT32>
0x004070ab:	pushl %edi
0x004070ac:	movl 0x424a90, %eax
0x004070b1:	call GetProcAddress@KERNEL32.DLL
0x004070b3:	xorl %eax, 0x4210d0
0x004070b9:	pushl $0x41bcc0<UINT32>
0x004070be:	pushl %edi
0x004070bf:	movl 0x424a98, %eax
0x004070c4:	call GetProcAddress@KERNEL32.DLL
0x004070c6:	xorl %eax, 0x4210d0
0x004070cc:	pushl $0x41bcd0<UINT32>
0x004070d1:	pushl %edi
0x004070d2:	movl 0x424a94, %eax
0x004070d7:	call GetProcAddress@KERNEL32.DLL
0x004070d9:	xorl %eax, 0x4210d0
0x004070df:	pushl $0x41bce0<UINT32>
0x004070e4:	pushl %edi
0x004070e5:	movl 0x424a9c, %eax
0x004070ea:	call GetProcAddress@KERNEL32.DLL
0x004070ec:	xorl %eax, 0x4210d0
0x004070f2:	pushl $0x41bcf0<UINT32>
0x004070f7:	pushl %edi
0x004070f8:	movl 0x424aa0, %eax
0x004070fd:	call GetProcAddress@KERNEL32.DLL
0x004070ff:	xorl %eax, 0x4210d0
0x00407105:	pushl $0x41bd00<UINT32>
0x0040710a:	pushl %edi
0x0040710b:	movl 0x424aa4, %eax
0x00407110:	call GetProcAddress@KERNEL32.DLL
0x00407112:	xorl %eax, 0x4210d0
0x00407118:	pushl $0x41bd1c<UINT32>
0x0040711d:	pushl %edi
0x0040711e:	movl 0x424aa8, %eax
0x00407123:	call GetProcAddress@KERNEL32.DLL
0x00407125:	xorl %eax, 0x4210d0
0x0040712b:	pushl $0x41bd30<UINT32>
0x00407130:	pushl %edi
0x00407131:	movl 0x424aac, %eax
0x00407136:	call GetProcAddress@KERNEL32.DLL
0x00407138:	xorl %eax, 0x4210d0
0x0040713e:	pushl $0x41bd40<UINT32>
0x00407143:	pushl %edi
0x00407144:	movl 0x424ab0, %eax
0x00407149:	call GetProcAddress@KERNEL32.DLL
0x0040714b:	xorl %eax, 0x4210d0
0x00407151:	pushl $0x41bd54<UINT32>
0x00407156:	pushl %edi
0x00407157:	movl 0x424ab4, %eax
0x0040715c:	call GetProcAddress@KERNEL32.DLL
0x0040715e:	xorl %eax, 0x4210d0
0x00407164:	movl 0x424ab8, %eax
0x00407169:	pushl $0x41bd64<UINT32>
0x0040716e:	pushl %edi
0x0040716f:	call GetProcAddress@KERNEL32.DLL
0x00407171:	xorl %eax, 0x4210d0
0x00407177:	pushl $0x41bd84<UINT32>
0x0040717c:	pushl %edi
0x0040717d:	movl 0x424abc, %eax
0x00407182:	call GetProcAddress@KERNEL32.DLL
0x00407184:	xorl %eax, 0x4210d0
0x0040718a:	popl %edi
0x0040718b:	movl 0x424ac0, %eax
0x00407190:	popl %esi
0x00407191:	ret

0x00406af4:	call 0x00406dcd
0x00406dcd:	pushl %esi
0x00406dce:	pushl %edi
0x00406dcf:	movl %esi, $0x421c28<UINT32>
0x00406dd4:	movl %edi, $0x4238c8<UINT32>
0x00406dd9:	cmpl 0x4(%esi), $0x1<UINT8>
0x00406ddd:	jne 22
0x00406ddf:	pushl $0x0<UINT8>
0x00406de1:	movl (%esi), %edi
0x00406de3:	addl %edi, $0x18<UINT8>
0x00406de6:	pushl $0xfa0<UINT32>
0x00406deb:	pushl (%esi)
0x00406ded:	call 0x00406e99
0x00406e99:	pushl %ebp
0x00406e9a:	movl %ebp, %esp
0x00406e9c:	movl %eax, 0x424a50
0x00406ea1:	xorl %eax, 0x4210d0
0x00406ea7:	je 13
0x00406ea9:	pushl 0x10(%ebp)
0x00406eac:	pushl 0xc(%ebp)
0x00406eaf:	pushl 0x8(%ebp)
0x00406eb2:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x00406eb4:	popl %ebp
0x00406eb5:	ret

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
