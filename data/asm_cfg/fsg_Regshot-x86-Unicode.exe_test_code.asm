0x00430000:	movl %ebx, $0x4001d0<UINT32>
0x00430005:	movl %edi, $0x401000<UINT32>
0x0043000a:	movl %esi, $0x422689<UINT32>
0x0043000f:	pushl %ebx
0x00430010:	call 0x0043001f
0x0043001f:	cld
0x00430020:	movb %dl, $0xffffff80<UINT8>
0x00430022:	movsb %es:(%edi), %ds:(%esi)
0x00430023:	pushl $0x2<UINT8>
0x00430025:	popl %ebx
0x00430026:	call 0x00430015
0x00430015:	addb %dl, %dl
0x00430017:	jne 0x0043001e
0x00430019:	movb %dl, (%esi)
0x0043001b:	incl %esi
0x0043001c:	adcb %dl, %dl
0x0043001e:	ret

0x00430029:	jae 0x00430022
0x0043002b:	xorl %ecx, %ecx
0x0043002d:	call 0x00430015
0x00430030:	jae 0x0043004a
0x00430032:	xorl %eax, %eax
0x00430034:	call 0x00430015
0x00430037:	jae 0x0043005a
0x00430039:	movb %bl, $0x2<UINT8>
0x0043003b:	incl %ecx
0x0043003c:	movb %al, $0x10<UINT8>
0x0043003e:	call 0x00430015
0x00430041:	adcb %al, %al
0x00430043:	jae 0x0043003e
0x00430045:	jne 0x00430086
0x00430047:	stosb %es:(%edi), %al
0x00430048:	jmp 0x00430026
0x00430086:	pushl %esi
0x00430087:	movl %esi, %edi
0x00430089:	subl %esi, %eax
0x0043008b:	rep movsb %es:(%edi), %ds:(%esi)
0x0043008d:	popl %esi
0x0043008e:	jmp 0x00430026
0x0043005a:	lodsb %al, %ds:(%esi)
0x0043005b:	shrl %eax
0x0043005d:	je 0x004300a0
0x0043005f:	adcl %ecx, %ecx
0x00430061:	jmp 0x0043007f
0x0043007f:	incl %ecx
0x00430080:	incl %ecx
0x00430081:	xchgl %ebp, %eax
0x00430082:	movl %eax, %ebp
0x00430084:	movb %bl, $0x1<UINT8>
0x0043004a:	call 0x00430092
0x00430092:	incl %ecx
0x00430093:	call 0x00430015
0x00430097:	adcl %ecx, %ecx
0x00430099:	call 0x00430015
0x0043009d:	jb 0x00430093
0x0043009f:	ret

0x0043004f:	subl %ecx, %ebx
0x00430051:	jne 0x00430063
0x00430063:	xchgl %ecx, %eax
0x00430064:	decl %eax
0x00430065:	shll %eax, $0x8<UINT8>
0x00430068:	lodsb %al, %ds:(%esi)
0x00430069:	call 0x00430090
0x00430090:	xorl %ecx, %ecx
0x0043006e:	cmpl %eax, $0x7d00<UINT32>
0x00430073:	jae 0x0043007f
0x00430075:	cmpb %ah, $0x5<UINT8>
0x00430078:	jae 0x00430080
0x0043007a:	cmpl %eax, $0x7f<UINT8>
0x0043007d:	ja 0x00430081
0x00430053:	call 0x00430090
0x00430058:	jmp 0x00430082
0x004300a0:	popl %edi
0x004300a1:	popl %ebx
0x004300a2:	movzwl %edi, (%ebx)
0x004300a5:	decl %edi
0x004300a6:	je 0x004300b0
0x004300a8:	decl %edi
0x004300a9:	je 0x004300be
0x004300ab:	shll %edi, $0xc<UINT8>
0x004300ae:	jmp 0x004300b7
0x004300b7:	incl %ebx
0x004300b8:	incl %ebx
0x004300b9:	jmp 0x0043000f
0x004300b0:	movl %edi, 0x2(%ebx)
0x004300b3:	pushl %edi
0x004300b4:	addl %ebx, $0x4<UINT8>
0x004300be:	popl %edi
0x004300bf:	movl %ebx, $0x430128<UINT32>
0x004300c4:	incl %edi
0x004300c5:	movl %esi, (%edi)
0x004300c7:	scasl %eax, %es:(%edi)
0x004300c8:	pushl %edi
0x004300c9:	call LoadLibraryA@KERNEL32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004300cb:	xchgl %ebp, %eax
0x004300cc:	xorl %eax, %eax
0x004300ce:	scasb %al, %es:(%edi)
0x004300cf:	jne 0x004300ce
0x004300d1:	decb (%edi)
0x004300d3:	je 0x004300c4
0x004300d5:	decb (%edi)
0x004300d7:	jne 0x004300df
0x004300df:	decb (%edi)
0x004300e1:	je 0x00408e6a
0x004300e7:	pushl %edi
0x004300e8:	pushl %ebp
0x004300e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x004300ec:	orl (%esi), %eax
0x004300ee:	lodsl %eax, %ds:(%esi)
0x004300ef:	jne 0x004300cc
GetProcAddress@KERNEL32.dll: API Node	
LoadLibraryA@KERNEL32.dll: API Node	
0x00408e6a:	call 0x0040be6c
0x0040be6c:	movl %edi, %edi
0x0040be6e:	pushl %ebp
0x0040be6f:	movl %ebp, %esp
0x0040be71:	subl %esp, $0x10<UINT8>
0x0040be74:	movl %eax, 0x416004
0x0040be79:	andl -8(%ebp), $0x0<UINT8>
0x0040be7d:	andl -4(%ebp), $0x0<UINT8>
0x0040be81:	pushl %ebx
0x0040be82:	pushl %edi
0x0040be83:	movl %edi, $0xbb40e64e<UINT32>
0x0040be88:	movl %ebx, $0xffff0000<UINT32>
0x0040be8d:	cmpl %eax, %edi
0x0040be8f:	je 0x0040be9e
0x0040be9e:	pushl %esi
0x0040be9f:	leal %eax, -8(%ebp)
0x0040bea2:	pushl %eax
0x0040bea3:	call GetSystemTimeAsFileTime@KERNEL32.dll
GetSystemTimeAsFileTime@KERNEL32.dll: API Node	
0x0040bea9:	movl %esi, -4(%ebp)
0x0040beac:	xorl %esi, -8(%ebp)
0x0040beaf:	call GetCurrentProcessId@KERNEL32.dll
GetCurrentProcessId@KERNEL32.dll: API Node	
0x0040beb5:	xorl %esi, %eax
0x0040beb7:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x0040bebd:	xorl %esi, %eax
0x0040bebf:	call GetTickCount@KERNEL32.dll
GetTickCount@KERNEL32.dll: API Node	
0x0040bec5:	xorl %esi, %eax
0x0040bec7:	leal %eax, -16(%ebp)
0x0040beca:	pushl %eax
0x0040becb:	call QueryPerformanceCounter@KERNEL32.dll
QueryPerformanceCounter@KERNEL32.dll: API Node	
0x0040bed1:	movl %eax, -12(%ebp)
0x0040bed4:	xorl %eax, -16(%ebp)
0x0040bed7:	xorl %esi, %eax
0x0040bed9:	cmpl %esi, %edi
0x0040bedb:	jne 0x0040bee4
0x0040bee4:	testl %ebx, %esi
0x0040bee6:	jne 0x0040beef
0x0040beef:	movl 0x416004, %esi
0x0040bef5:	notl %esi
0x0040bef7:	movl 0x416008, %esi
0x0040befd:	popl %esi
0x0040befe:	popl %edi
0x0040beff:	popl %ebx
0x0040bf00:	leave
0x0040bf01:	ret

0x00408e6f:	jmp 0x00408ced
0x00408ced:	pushl $0x58<UINT8>
0x00408cef:	pushl $0x4149b0<UINT32>
0x00408cf4:	call 0x0040bc80
0x0040bc80:	pushl $0x40bce0<UINT32>
0x0040bc85:	pushl %fs:0
0x0040bc8c:	movl %eax, 0x10(%esp)
0x0040bc90:	movl 0x10(%esp), %ebp
0x0040bc94:	leal %ebp, 0x10(%esp)
0x0040bc98:	subl %esp, %eax
0x0040bc9a:	pushl %ebx
0x0040bc9b:	pushl %esi
0x0040bc9c:	pushl %edi
0x0040bc9d:	movl %eax, 0x416004
0x0040bca2:	xorl -4(%ebp), %eax
0x0040bca5:	xorl %eax, %ebp
0x0040bca7:	pushl %eax
0x0040bca8:	movl -24(%ebp), %esp
0x0040bcab:	pushl -8(%ebp)
0x0040bcae:	movl %eax, -4(%ebp)
0x0040bcb1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040bcb8:	movl -8(%ebp), %eax
0x0040bcbb:	leal %eax, -16(%ebp)
0x0040bcbe:	movl %fs:0, %eax
0x0040bcc4:	ret

0x00408cf9:	xorl %esi, %esi
0x00408cfb:	movl -4(%ebp), %esi
0x00408cfe:	leal %eax, -104(%ebp)
0x00408d01:	pushl %eax
0x00408d02:	call GetStartupInfoW@KERNEL32.dll
GetStartupInfoW@KERNEL32.dll: API Node	
0x00408d08:	pushl $0xfffffffe<UINT8>
0x00408d0a:	popl %edi
0x00408d0b:	movl -4(%ebp), %edi
0x00408d0e:	movl %eax, $0x5a4d<UINT32>
0x00408d13:	cmpw 0x400000, %ax
0x00408d1a:	jne 56
0x00408d1c:	movl %eax, 0x40003c
0x00408d21:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00408d2b:	jne 39
0x00408d2d:	movl %ecx, $0x10b<UINT32>
0x00408d32:	cmpw 0x400018(%eax), %cx
0x00408d39:	jne 25
0x00408d3b:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00408d42:	jbe 16
0x00408d44:	xorl %ecx, %ecx
0x00408d46:	cmpl 0x4000e8(%eax), %esi
0x00408d4c:	setne %cl
0x00408d4f:	movl -28(%ebp), %ecx
0x00408d52:	jmp 0x00408d57
0x00408d57:	xorl %ebx, %ebx
0x00408d59:	incl %ebx
0x00408d5a:	pushl %ebx
0x00408d5b:	call 0x0040bc4d
0x0040bc4d:	movl %edi, %edi
0x0040bc4f:	pushl %ebp
0x0040bc50:	movl %ebp, %esp
0x0040bc52:	xorl %eax, %eax
0x0040bc54:	cmpl 0x8(%ebp), %eax
0x0040bc57:	pushl $0x0<UINT8>
0x0040bc59:	sete %al
0x0040bc5c:	pushl $0x1000<UINT32>
0x0040bc61:	pushl %eax
0x0040bc62:	call HeapCreate@KERNEL32.dll
HeapCreate@KERNEL32.dll: API Node	
0x0040bc68:	movl 0x4178c4, %eax
0x0040bc6d:	testl %eax, %eax
0x0040bc6f:	jne 0x0040bc73
0x0040bc73:	xorl %eax, %eax
0x0040bc75:	incl %eax
0x0040bc76:	movl 0x418b6c, %eax
0x0040bc7b:	popl %ebp
0x0040bc7c:	ret

0x00408d60:	popl %ecx
0x00408d61:	testl %eax, %eax
0x00408d63:	jne 0x00408d6d
0x00408d6d:	call 0x00409d92
0x00409d92:	movl %edi, %edi
0x00409d94:	pushl %esi
0x00409d95:	pushl %edi
0x00409d96:	movl %esi, $0x412318<UINT32>
0x00409d9b:	pushl %esi
0x00409d9c:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x00409da2:	testl %eax, %eax
0x00409da4:	jne 0x00409dad
0x00409dad:	movl %edi, %eax
0x00409daf:	testl %edi, %edi
0x00409db1:	je 350
0x00409db7:	movl %esi, 0x41212c
0x00409dbd:	pushl $0x412364<UINT32>
0x00409dc2:	pushl %edi
0x00409dc3:	call GetProcAddress@KERNEL32.dll
0x00409dc5:	pushl $0x412358<UINT32>
0x00409dca:	pushl %edi
0x00409dcb:	movl 0x417354, %eax
0x00409dd0:	call GetProcAddress@KERNEL32.dll
0x00409dd2:	pushl $0x41234c<UINT32>
0x00409dd7:	pushl %edi
0x00409dd8:	movl 0x417358, %eax
0x00409ddd:	call GetProcAddress@KERNEL32.dll
0x00409ddf:	pushl $0x412344<UINT32>
0x00409de4:	pushl %edi
0x00409de5:	movl 0x41735c, %eax
0x00409dea:	call GetProcAddress@KERNEL32.dll
0x00409dec:	cmpl 0x417354, $0x0<UINT8>
0x00409df3:	movl %esi, 0x412138
0x00409df9:	movl 0x417360, %eax
0x00409dfe:	je 22
0x00409e00:	cmpl 0x417358, $0x0<UINT8>
0x00409e07:	je 13
0x00409e09:	cmpl 0x41735c, $0x0<UINT8>
0x00409e10:	je 4
0x00409e12:	testl %eax, %eax
0x00409e14:	jne 0x00409e3a
0x00409e3a:	call TlsAlloc@KERNEL32.dll
TlsAlloc@KERNEL32.dll: API Node	
0x00409e40:	movl 0x41662c, %eax
0x00409e45:	cmpl %eax, $0xffffffff<UINT8>
0x00409e48:	je 204
0x00409e4e:	pushl 0x417358
0x00409e54:	pushl %eax
0x00409e55:	call TlsSetValue@KERNEL32.dll
TlsSetValue@KERNEL32.dll: API Node	
0x00409e57:	testl %eax, %eax
0x00409e59:	je 187
0x00409e5f:	call 0x0040b29a
0x0040b29a:	movl %edi, %edi
0x0040b29c:	pushl %esi
0x0040b29d:	call 0x004099f4
0x004099f4:	pushl $0x0<UINT8>
0x004099f6:	call 0x00409982
0x00409982:	movl %edi, %edi
0x00409984:	pushl %ebp
0x00409985:	movl %ebp, %esp
0x00409987:	pushl %esi
0x00409988:	pushl 0x41662c
0x0040998e:	movl %esi, 0x412130
0x00409994:	call TlsGetValue@KERNEL32.dll
TlsGetValue@KERNEL32.dll: API Node	
0x00409996:	testl %eax, %eax
0x00409998:	je 33
0x0040999a:	movl %eax, 0x416628
0x0040999f:	cmpl %eax, $0xffffffff<UINT8>
0x004099a2:	je 0x004099bb
0x004099bb:	movl %esi, $0x412318<UINT32>
0x004099c0:	pushl %esi
0x004099c1:	call GetModuleHandleW@KERNEL32.dll
0x004099c7:	testl %eax, %eax
0x004099c9:	jne 0x004099d6
0x004099d6:	pushl $0x412308<UINT32>
0x004099db:	pushl %eax
0x004099dc:	call GetProcAddress@KERNEL32.dll
0x004099e2:	testl %eax, %eax
0x004099e4:	je 8
0x004099e6:	pushl 0x8(%ebp)
0x004099e9:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x004099eb:	movl 0x8(%ebp), %eax
0x004099ee:	movl %eax, 0x8(%ebp)
0x004099f1:	popl %esi
0x004099f2:	popl %ebp
0x004099f3:	ret

0x004099fb:	popl %ecx
0x004099fc:	ret

0x0040b2a2:	movl %esi, %eax
0x0040b2a4:	pushl %esi
0x0040b2a5:	call 0x0040e83c
0x0040e83c:	movl %edi, %edi
0x0040e83e:	pushl %ebp
0x0040e83f:	movl %ebp, %esp
0x0040e841:	movl %eax, 0x8(%ebp)
0x0040e844:	movl 0x417a5c, %eax
0x0040e849:	popl %ebp
0x0040e84a:	ret

0x0040b2aa:	pushl %esi
0x0040b2ab:	call 0x0040e7cd
0x0040e7cd:	movl %edi, %edi
0x0040e7cf:	pushl %ebp
0x0040e7d0:	movl %ebp, %esp
0x0040e7d2:	movl %eax, 0x8(%ebp)
0x0040e7d5:	movl 0x417a58, %eax
0x0040e7da:	popl %ebp
0x0040e7db:	ret

0x0040b2b0:	pushl %esi
0x0040b2b1:	call 0x00409fd4
0x00409fd4:	movl %edi, %edi
0x00409fd6:	pushl %ebp
0x00409fd7:	movl %ebp, %esp
0x00409fd9:	movl %eax, 0x8(%ebp)
0x00409fdc:	movl 0x417364, %eax
0x00409fe1:	popl %ebp
0x00409fe2:	ret

0x0040b2b6:	pushl %esi
0x0040b2b7:	call 0x0040e7be
0x0040e7be:	movl %edi, %edi
0x0040e7c0:	pushl %ebp
0x0040e7c1:	movl %ebp, %esp
0x0040e7c3:	movl %eax, 0x8(%ebp)
0x0040e7c6:	movl 0x417a54, %eax
0x0040e7cb:	popl %ebp
0x0040e7cc:	ret

0x0040b2bc:	pushl %esi
0x0040b2bd:	call 0x0040e7af
0x0040e7af:	movl %edi, %edi
0x0040e7b1:	pushl %ebp
0x0040e7b2:	movl %ebp, %esp
0x0040e7b4:	movl %eax, 0x8(%ebp)
0x0040e7b7:	movl 0x417a48, %eax
0x0040e7bc:	popl %ebp
0x0040e7bd:	ret

0x0040b2c2:	pushl %esi
0x0040b2c3:	call 0x0040e59d
0x0040e59d:	movl %edi, %edi
0x0040e59f:	pushl %ebp
0x0040e5a0:	movl %ebp, %esp
0x0040e5a2:	movl %eax, 0x8(%ebp)
0x0040e5a5:	movl 0x417a34, %eax
0x0040e5aa:	movl 0x417a38, %eax
0x0040e5af:	movl 0x417a3c, %eax
0x0040e5b4:	movl 0x417a40, %eax
0x0040e5b9:	popl %ebp
0x0040e5ba:	ret

0x0040b2c8:	pushl %esi
0x0040b2c9:	call 0x0040b4cc
0x0040b4cc:	ret

0x0040b2ce:	pushl %esi
0x0040b2cf:	call 0x0040e2fe
0x0040e2fe:	pushl $0x40e2c5<UINT32>
0x0040e303:	call 0x00409982
0x0040e308:	popl %ecx
0x0040e309:	movl 0x417a30, %eax
0x0040e30e:	ret

0x0040b2d4:	pushl $0x40b266<UINT32>
0x0040b2d9:	call 0x00409982
0x0040b2de:	addl %esp, $0x24<UINT8>
0x0040b2e1:	movl 0x4167a0, %eax
0x0040b2e6:	popl %esi
0x0040b2e7:	ret

0x00409e64:	pushl 0x417354
0x00409e6a:	call 0x00409982
0x00409e6f:	pushl 0x417358
0x00409e75:	movl 0x417354, %eax
0x00409e7a:	call 0x00409982
0x00409e7f:	pushl 0x41735c
0x00409e85:	movl 0x417358, %eax
0x00409e8a:	call 0x00409982
0x00409e8f:	pushl 0x417360
0x00409e95:	movl 0x41735c, %eax
0x00409e9a:	call 0x00409982
0x00409e9f:	addl %esp, $0x10<UINT8>
0x00409ea2:	movl 0x417360, %eax
0x00409ea7:	call 0x0040c590
0x0040c590:	movl %edi, %edi
0x0040c592:	pushl %esi
0x0040c593:	pushl %edi
0x0040c594:	xorl %esi, %esi
0x0040c596:	movl %edi, $0x4178d0<UINT32>
0x0040c59b:	cmpl 0x4168c4(,%esi,8), $0x1<UINT8>
0x0040c5a3:	jne 0x0040c5c3
0x0040c5a5:	leal %eax, 0x4168c0(,%esi,8)
0x0040c5ac:	movl (%eax), %edi
0x0040c5ae:	pushl $0xfa0<UINT32>
0x0040c5b3:	pushl (%eax)
0x0040c5b5:	addl %edi, $0x18<UINT8>
0x0040c5b8:	call 0x0040e7dc
0x0040e7dc:	pushl $0x10<UINT8>
0x0040e7de:	pushl $0x414bc8<UINT32>
0x0040e7e3:	call 0x0040bc80
0x0040e7e8:	andl -4(%ebp), $0x0<UINT8>
0x0040e7ec:	pushl 0xc(%ebp)
0x0040e7ef:	pushl 0x8(%ebp)
0x0040e7f2:	call InitializeCriticalSectionAndSpinCount@KERNEL32.dll
InitializeCriticalSectionAndSpinCount@KERNEL32.dll: API Node	
0x0040e7f8:	movl -28(%ebp), %eax
0x0040e7fb:	jmp 0x0040e82c
0x0040e82c:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040e833:	movl %eax, -28(%ebp)
0x0040e836:	call 0x0040bcc5
0x0040bcc5:	movl %ecx, -16(%ebp)
0x0040bcc8:	movl %fs:0, %ecx
0x0040bccf:	popl %ecx
0x0040bcd0:	popl %edi
0x0040bcd1:	popl %edi
0x0040bcd2:	popl %esi
0x0040bcd3:	popl %ebx
0x0040bcd4:	movl %esp, %ebp
0x0040bcd6:	popl %ebp
0x0040bcd7:	pushl %ecx
0x0040bcd8:	ret

0x0040e83b:	ret

0x0040c5bd:	popl %ecx
0x0040c5be:	popl %ecx
0x0040c5bf:	testl %eax, %eax
0x0040c5c1:	je 12
0x0040c5c3:	incl %esi
0x0040c5c4:	cmpl %esi, $0x24<UINT8>
0x0040c5c7:	jl 0x0040c59b
0x0040c5c9:	xorl %eax, %eax
0x0040c5cb:	incl %eax
0x0040c5cc:	popl %edi
0x0040c5cd:	popl %esi
0x0040c5ce:	ret

0x00409eac:	testl %eax, %eax
0x00409eae:	je 101
0x00409eb0:	pushl $0x409c63<UINT32>
0x00409eb5:	pushl 0x417354
0x00409ebb:	call 0x004099fd
0x004099fd:	movl %edi, %edi
0x004099ff:	pushl %ebp
0x00409a00:	movl %ebp, %esp
0x00409a02:	pushl %esi
0x00409a03:	pushl 0x41662c
0x00409a09:	movl %esi, 0x412130
0x00409a0f:	call TlsGetValue@KERNEL32.dll
0x00409a11:	testl %eax, %eax
0x00409a13:	je 33
0x00409a15:	movl %eax, 0x416628
0x00409a1a:	cmpl %eax, $0xffffffff<UINT8>
0x00409a1d:	je 0x00409a36
0x00409a36:	movl %esi, $0x412318<UINT32>
0x00409a3b:	pushl %esi
0x00409a3c:	call GetModuleHandleW@KERNEL32.dll
0x00409a42:	testl %eax, %eax
0x00409a44:	jne 0x00409a51
0x00409a51:	pushl $0x412334<UINT32>
0x00409a56:	pushl %eax
0x00409a57:	call GetProcAddress@KERNEL32.dll
0x00409a5d:	testl %eax, %eax
0x00409a5f:	je 8
0x00409a61:	pushl 0x8(%ebp)
0x00409a64:	call DecodePointer@KERNEL32.DLL
DecodePointer@KERNEL32.DLL: API Node	
0x00409a66:	movl 0x8(%ebp), %eax
0x00409a69:	movl %eax, 0x8(%ebp)
0x00409a6c:	popl %esi
0x00409a6d:	popl %ebp
0x00409a6e:	ret

0x00409ec0:	popl %ecx
0x00409ec1:	call FlsAlloc@KERNEL32.DLL
FlsAlloc@KERNEL32.DLL: API Node	
0x00409ec3:	movl 0x416628, %eax
0x00409ec8:	cmpl %eax, $0xffffffff<UINT8>
0x00409ecb:	je 72
0x00409ecd:	pushl $0x214<UINT32>
0x00409ed2:	pushl $0x1<UINT8>
0x00409ed4:	call 0x0040c812
0x0040c812:	movl %edi, %edi
0x0040c814:	pushl %ebp
0x0040c815:	movl %ebp, %esp
0x0040c817:	pushl %esi
0x0040c818:	pushl %edi
0x0040c819:	xorl %esi, %esi
0x0040c81b:	pushl $0x0<UINT8>
0x0040c81d:	pushl 0xc(%ebp)
0x0040c820:	pushl 0x8(%ebp)
0x0040c823:	call 0x0040fbbc
0x0040fbbc:	pushl $0xc<UINT8>
0x0040fbbe:	pushl $0x414c28<UINT32>
0x0040fbc3:	call 0x0040bc80
0x0040fbc8:	movl %ecx, 0x8(%ebp)
0x0040fbcb:	xorl %edi, %edi
0x0040fbcd:	cmpl %ecx, %edi
0x0040fbcf:	jbe 46
0x0040fbd1:	pushl $0xffffffe0<UINT8>
0x0040fbd3:	popl %eax
0x0040fbd4:	xorl %edx, %edx
0x0040fbd6:	divl %eax, %ecx
0x0040fbd8:	cmpl %eax, 0xc(%ebp)
0x0040fbdb:	sbbl %eax, %eax
0x0040fbdd:	incl %eax
0x0040fbde:	jne 0x0040fbff
0x0040fbff:	imull %ecx, 0xc(%ebp)
0x0040fc03:	movl %esi, %ecx
0x0040fc05:	movl 0x8(%ebp), %esi
0x0040fc08:	cmpl %esi, %edi
0x0040fc0a:	jne 0x0040fc0f
0x0040fc0f:	xorl %ebx, %ebx
0x0040fc11:	movl -28(%ebp), %ebx
0x0040fc14:	cmpl %esi, $0xffffffe0<UINT8>
0x0040fc17:	ja 105
0x0040fc19:	cmpl 0x418b6c, $0x3<UINT8>
0x0040fc20:	jne 0x0040fc6d
0x0040fc6d:	cmpl %ebx, %edi
0x0040fc6f:	jne 97
0x0040fc71:	pushl %esi
0x0040fc72:	pushl $0x8<UINT8>
0x0040fc74:	pushl 0x4178c4
0x0040fc7a:	call HeapAlloc@KERNEL32.dll
HeapAlloc@KERNEL32.dll: API Node	
0x0040fc80:	movl %ebx, %eax
0x0040fc82:	cmpl %ebx, %edi
0x0040fc84:	jne 0x0040fcd2
0x0040fcd2:	movl %eax, %ebx
0x0040fcd4:	call 0x0040bcc5
0x0040fcd9:	ret

0x0040c828:	movl %edi, %eax
0x0040c82a:	addl %esp, $0xc<UINT8>
0x0040c82d:	testl %edi, %edi
0x0040c82f:	jne 0x0040c858
0x0040c858:	movl %eax, %edi
0x0040c85a:	popl %edi
0x0040c85b:	popl %esi
0x0040c85c:	popl %ebp
0x0040c85d:	ret

0x00409ed9:	movl %esi, %eax
0x00409edb:	popl %ecx
0x00409edc:	popl %ecx
0x00409edd:	testl %esi, %esi
0x00409edf:	je 52
0x00409ee1:	pushl %esi
0x00409ee2:	pushl 0x416628
0x00409ee8:	pushl 0x41735c
0x00409eee:	call 0x004099fd
0x00409a1f:	pushl %eax
0x00409a20:	pushl 0x41662c
0x00409a26:	call TlsGetValue@KERNEL32.dll
0x00409a28:	call FlsGetValue@KERNEL32.DLL
FlsGetValue@KERNEL32.DLL: API Node	
0x00409a2a:	testl %eax, %eax
0x00409a2c:	je 0x00409a36
0x00409ef3:	popl %ecx
0x00409ef4:	call FlsSetValue@KERNEL32.DLL
FlsSetValue@KERNEL32.DLL: API Node	
0x00409ef6:	testl %eax, %eax
0x00409ef8:	je 27
0x00409efa:	pushl $0x0<UINT8>
0x00409efc:	pushl %esi
0x00409efd:	call 0x00409ae9
0x00409ae9:	pushl $0xc<UINT8>
0x00409aeb:	pushl $0x414a38<UINT32>
0x00409af0:	call 0x0040bc80
0x00409af5:	movl %esi, $0x412318<UINT32>
0x00409afa:	pushl %esi
0x00409afb:	call GetModuleHandleW@KERNEL32.dll
0x00409b01:	testl %eax, %eax
0x00409b03:	jne 0x00409b0c
0x00409b0c:	movl -28(%ebp), %eax
0x00409b0f:	movl %esi, 0x8(%ebp)
0x00409b12:	movl 0x5c(%esi), $0x412960<UINT32>
0x00409b19:	xorl %edi, %edi
0x00409b1b:	incl %edi
0x00409b1c:	movl 0x14(%esi), %edi
0x00409b1f:	testl %eax, %eax
0x00409b21:	je 36
0x00409b23:	pushl $0x412308<UINT32>
0x00409b28:	pushl %eax
0x00409b29:	movl %ebx, 0x41212c
0x00409b2f:	call GetProcAddress@KERNEL32.dll
0x00409b31:	movl 0x1f8(%esi), %eax
0x00409b37:	pushl $0x412334<UINT32>
0x00409b3c:	pushl -28(%ebp)
0x00409b3f:	call GetProcAddress@KERNEL32.dll
0x00409b41:	movl 0x1fc(%esi), %eax
0x00409b47:	movl 0x70(%esi), %edi
0x00409b4a:	movb 0xc8(%esi), $0x43<UINT8>
0x00409b51:	movb 0x14b(%esi), $0x43<UINT8>
0x00409b58:	movl 0x68(%esi), $0x416010<UINT32>
0x00409b5f:	pushl $0xd<UINT8>
0x00409b61:	call 0x0040c70c
0x0040c70c:	movl %edi, %edi
0x0040c70e:	pushl %ebp
0x0040c70f:	movl %ebp, %esp
0x0040c711:	movl %eax, 0x8(%ebp)
0x0040c714:	pushl %esi
0x0040c715:	leal %esi, 0x4168c0(,%eax,8)
0x0040c71c:	cmpl (%esi), $0x0<UINT8>
0x0040c71f:	jne 0x0040c734
0x0040c734:	pushl (%esi)
0x0040c736:	call EnterCriticalSection@KERNEL32.dll
EnterCriticalSection@KERNEL32.dll: API Node	
0x0040c73c:	popl %esi
0x0040c73d:	popl %ebp
0x0040c73e:	ret

0x00409b66:	popl %ecx
0x00409b67:	andl -4(%ebp), $0x0<UINT8>
0x00409b6b:	pushl 0x68(%esi)
0x00409b6e:	call InterlockedIncrement@KERNEL32.dll
InterlockedIncrement@KERNEL32.dll: API Node	
0x00409b74:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00409b7b:	call 0x00409bbe
0x00409bbe:	pushl $0xd<UINT8>
0x00409bc0:	call 0x0040c632
0x0040c632:	movl %edi, %edi
0x0040c634:	pushl %ebp
0x0040c635:	movl %ebp, %esp
0x0040c637:	movl %eax, 0x8(%ebp)
0x0040c63a:	pushl 0x4168c0(,%eax,8)
0x0040c641:	call LeaveCriticalSection@KERNEL32.dll
LeaveCriticalSection@KERNEL32.dll: API Node	
0x0040c647:	popl %ebp
0x0040c648:	ret

0x00409bc5:	popl %ecx
0x00409bc6:	ret

0x00409b80:	pushl $0xc<UINT8>
0x00409b82:	call 0x0040c70c
0x00409b87:	popl %ecx
0x00409b88:	movl -4(%ebp), %edi
0x00409b8b:	movl %eax, 0xc(%ebp)
0x00409b8e:	movl 0x6c(%esi), %eax
0x00409b91:	testl %eax, %eax
0x00409b93:	jne 8
0x00409b95:	movl %eax, 0x416618
0x00409b9a:	movl 0x6c(%esi), %eax
0x00409b9d:	pushl 0x6c(%esi)
0x00409ba0:	call 0x004097a6
0x004097a6:	movl %edi, %edi
0x004097a8:	pushl %ebp
0x004097a9:	movl %ebp, %esp
0x004097ab:	pushl %ebx
0x004097ac:	pushl %esi
0x004097ad:	movl %esi, 0x412114
0x004097b3:	pushl %edi
0x004097b4:	movl %edi, 0x8(%ebp)
0x004097b7:	pushl %edi
0x004097b8:	call InterlockedIncrement@KERNEL32.dll
0x004097ba:	movl %eax, 0xb0(%edi)
0x004097c0:	testl %eax, %eax
0x004097c2:	je 0x004097c7
0x004097c7:	movl %eax, 0xb8(%edi)
0x004097cd:	testl %eax, %eax
0x004097cf:	je 0x004097d4
0x004097d4:	movl %eax, 0xb4(%edi)
0x004097da:	testl %eax, %eax
0x004097dc:	je 0x004097e1
0x004097e1:	movl %eax, 0xc0(%edi)
0x004097e7:	testl %eax, %eax
0x004097e9:	je 0x004097ee
0x004097ee:	leal %ebx, 0x50(%edi)
0x004097f1:	movl 0x8(%ebp), $0x6<UINT32>
0x004097f8:	cmpl -8(%ebx), $0x416538<UINT32>
0x004097ff:	je 0x0040980a
0x00409801:	movl %eax, (%ebx)
0x00409803:	testl %eax, %eax
0x00409805:	je 0x0040980a
0x0040980a:	cmpl -4(%ebx), $0x0<UINT8>
0x0040980e:	je 0x0040981a
0x0040981a:	addl %ebx, $0x10<UINT8>
0x0040981d:	decl 0x8(%ebp)
0x00409820:	jne 0x004097f8
0x00409822:	movl %eax, 0xd4(%edi)
0x00409828:	addl %eax, $0xb4<UINT32>
0x0040982d:	pushl %eax
0x0040982e:	call InterlockedIncrement@KERNEL32.dll
0x00409830:	popl %edi
0x00409831:	popl %esi
0x00409832:	popl %ebx
0x00409833:	popl %ebp
0x00409834:	ret

0x00409ba5:	popl %ecx
0x00409ba6:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00409bad:	call 0x00409bc7
0x00409bc7:	pushl $0xc<UINT8>
0x00409bc9:	call 0x0040c632
0x00409bce:	popl %ecx
0x00409bcf:	ret

0x00409bb2:	call 0x0040bcc5
0x00409bb7:	ret

0x00409f02:	popl %ecx
0x00409f03:	popl %ecx
0x00409f04:	call GetCurrentThreadId@KERNEL32.dll
0x00409f0a:	orl 0x4(%esi), $0xffffffff<UINT8>
0x00409f0e:	movl (%esi), %eax
0x00409f10:	xorl %eax, %eax
0x00409f12:	incl %eax
0x00409f13:	jmp 0x00409f1c
0x00409f1c:	popl %edi
0x00409f1d:	popl %esi
0x00409f1e:	ret

0x00408d72:	testl %eax, %eax
0x00408d74:	jne 0x00408d7e
0x00408d7e:	call 0x0040bc01
0x0040bc01:	movl %edi, %edi
0x0040bc03:	pushl %esi
0x0040bc04:	movl %eax, $0x4149a0<UINT32>
0x0040bc09:	movl %esi, $0x4149a0<UINT32>
0x0040bc0e:	pushl %edi
0x0040bc0f:	movl %edi, %eax
0x0040bc11:	cmpl %eax, %esi
0x0040bc13:	jae 0x0040bc24
0x0040bc24:	popl %edi
0x0040bc25:	popl %esi
0x0040bc26:	ret

0x00408d83:	movl -4(%ebp), %ebx
0x00408d86:	call 0x0040b9ad
0x0040b9ad:	pushl $0x54<UINT8>
0x0040b9af:	pushl $0x414aa8<UINT32>
0x0040b9b4:	call 0x0040bc80
0x0040b9b9:	xorl %edi, %edi
0x0040b9bb:	movl -4(%ebp), %edi
0x0040b9be:	leal %eax, -100(%ebp)
0x0040b9c1:	pushl %eax
0x0040b9c2:	call GetStartupInfoA@KERNEL32.dll
GetStartupInfoA@KERNEL32.dll: API Node	
0x0040b9c8:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040b9cf:	pushl $0x40<UINT8>
0x0040b9d1:	pushl $0x20<UINT8>
0x0040b9d3:	popl %esi
0x0040b9d4:	pushl %esi
0x0040b9d5:	call 0x0040c812
0x0040b9da:	popl %ecx
0x0040b9db:	popl %ecx
0x0040b9dc:	cmpl %eax, %edi
0x0040b9de:	je 532
0x0040b9e4:	movl 0x418b80, %eax
0x0040b9e9:	movl 0x418b70, %esi
0x0040b9ef:	leal %ecx, 0x800(%eax)
0x0040b9f5:	jmp 0x0040ba27
0x0040ba27:	cmpl %eax, %ecx
0x0040ba29:	jb 0x0040b9f7
0x0040b9f7:	movb 0x4(%eax), $0x0<UINT8>
0x0040b9fb:	orl (%eax), $0xffffffff<UINT8>
0x0040b9fe:	movb 0x5(%eax), $0xa<UINT8>
0x0040ba02:	movl 0x8(%eax), %edi
0x0040ba05:	movb 0x24(%eax), $0x0<UINT8>
0x0040ba09:	movb 0x25(%eax), $0xa<UINT8>
0x0040ba0d:	movb 0x26(%eax), $0xa<UINT8>
0x0040ba11:	movl 0x38(%eax), %edi
0x0040ba14:	movb 0x34(%eax), $0x0<UINT8>
0x0040ba18:	addl %eax, $0x40<UINT8>
0x0040ba1b:	movl %ecx, 0x418b80
0x0040ba21:	addl %ecx, $0x800<UINT32>
0x0040ba2b:	cmpw -50(%ebp), %di
0x0040ba2f:	je 266
0x0040ba35:	movl %eax, -48(%ebp)
0x0040ba38:	cmpl %eax, %edi
0x0040ba3a:	je 255
0x0040ba40:	movl %edi, (%eax)
0x0040ba42:	leal %ebx, 0x4(%eax)
0x0040ba45:	leal %eax, (%ebx,%edi)
0x0040ba48:	movl -28(%ebp), %eax
0x0040ba4b:	movl %esi, $0x800<UINT32>
0x0040ba50:	cmpl %edi, %esi
0x0040ba52:	jl 0x0040ba56
0x0040ba56:	movl -32(%ebp), $0x1<UINT32>
0x0040ba5d:	jmp 0x0040baba
0x0040baba:	cmpl 0x418b70, %edi
0x0040bac0:	jl -99
0x0040bac2:	jmp 0x0040baca
0x0040baca:	andl -32(%ebp), $0x0<UINT8>
0x0040bace:	testl %edi, %edi
0x0040bad0:	jle 0x0040bb3f
0x0040bb3f:	xorl %ebx, %ebx
0x0040bb41:	movl %esi, %ebx
0x0040bb43:	shll %esi, $0x6<UINT8>
0x0040bb46:	addl %esi, 0x418b80
0x0040bb4c:	movl %eax, (%esi)
0x0040bb4e:	cmpl %eax, $0xffffffff<UINT8>
0x0040bb51:	je 0x0040bb5e
0x0040bb5e:	movb 0x4(%esi), $0xffffff81<UINT8>
0x0040bb62:	testl %ebx, %ebx
0x0040bb64:	jne 0x0040bb6b
0x0040bb66:	pushl $0xfffffff6<UINT8>
0x0040bb68:	popl %eax
0x0040bb69:	jmp 0x0040bb75
0x0040bb75:	pushl %eax
0x0040bb76:	call GetStdHandle@KERNEL32.dll
GetStdHandle@KERNEL32.dll: API Node	
0x0040bb7c:	movl %edi, %eax
0x0040bb7e:	cmpl %edi, $0xffffffff<UINT8>
0x0040bb81:	je 67
0x0040bb83:	testl %edi, %edi
0x0040bb85:	je 63
0x0040bb87:	pushl %edi
0x0040bb88:	call GetFileType@KERNEL32.dll
GetFileType@KERNEL32.dll: API Node	
0x0040bb8e:	testl %eax, %eax
0x0040bb90:	je 52
0x0040bb92:	movl (%esi), %edi
0x0040bb94:	andl %eax, $0xff<UINT32>
0x0040bb99:	cmpl %eax, $0x2<UINT8>
0x0040bb9c:	jne 6
0x0040bb9e:	orb 0x4(%esi), $0x40<UINT8>
0x0040bba2:	jmp 0x0040bbad
0x0040bbad:	pushl $0xfa0<UINT32>
0x0040bbb2:	leal %eax, 0xc(%esi)
0x0040bbb5:	pushl %eax
0x0040bbb6:	call 0x0040e7dc
0x0040bbbb:	popl %ecx
0x0040bbbc:	popl %ecx
0x0040bbbd:	testl %eax, %eax
0x0040bbbf:	je 55
0x0040bbc1:	incl 0x8(%esi)
0x0040bbc4:	jmp 0x0040bbd0
0x0040bbd0:	incl %ebx
0x0040bbd1:	cmpl %ebx, $0x3<UINT8>
0x0040bbd4:	jl 0x0040bb41
0x0040bb6b:	movl %eax, %ebx
0x0040bb6d:	decl %eax
0x0040bb6e:	negl %eax
0x0040bb70:	sbbl %eax, %eax
0x0040bb72:	addl %eax, $0xfffffff5<UINT8>
0x0040bbda:	pushl 0x418b70
0x0040bbe0:	call SetHandleCount@KERNEL32.dll
SetHandleCount@KERNEL32.dll: API Node	
0x0040bbe6:	xorl %eax, %eax
0x0040bbe8:	jmp 0x0040bbfb
0x0040bbfb:	call 0x0040bcc5
0x0040bc00:	ret

0x00408d8b:	testl %eax, %eax
0x00408d8d:	jnl 0x00408d97
0x00408d97:	call 0x0040b9a7
0x0040b9a7:	jmp GetCommandLineW@KERNEL32.dll
GetCommandLineW@KERNEL32.dll: API Node	
0x00408d9c:	movl 0x418c98, %eax
0x00408da1:	call 0x0040b950
0x0040b950:	movl %edi, %edi
0x0040b952:	pushl %esi
0x0040b953:	call GetEnvironmentStringsW@KERNEL32.dll
GetEnvironmentStringsW@KERNEL32.dll: API Node	
0x0040b959:	movl %esi, %eax
0x0040b95b:	xorl %ecx, %ecx
0x0040b95d:	cmpl %esi, %ecx
0x0040b95f:	jne 0x0040b965
0x0040b965:	cmpw (%esi), %cx
0x0040b968:	je 14
0x0040b96a:	incl %eax
0x0040b96b:	incl %eax
0x0040b96c:	cmpw (%eax), %cx
0x0040b96f:	jne 0x0040b96a
0x0040b971:	incl %eax
0x0040b972:	incl %eax
0x0040b973:	cmpw (%eax), %cx
0x0040b976:	jne 0x0040b96a
0x0040b978:	subl %eax, %esi
0x0040b97a:	incl %eax
0x0040b97b:	pushl %ebx
0x0040b97c:	incl %eax
0x0040b97d:	movl %ebx, %eax
0x0040b97f:	pushl %edi
0x0040b980:	pushl %ebx
0x0040b981:	call 0x0040c7cd
0x0040c7cd:	movl %edi, %edi
0x0040c7cf:	pushl %ebp
0x0040c7d0:	movl %ebp, %esp
0x0040c7d2:	pushl %esi
0x0040c7d3:	pushl %edi
0x0040c7d4:	xorl %esi, %esi
0x0040c7d6:	pushl 0x8(%ebp)
0x0040c7d9:	call 0x0040fab8
0x0040fab8:	movl %edi, %edi
0x0040faba:	pushl %ebp
0x0040fabb:	movl %ebp, %esp
0x0040fabd:	pushl %esi
0x0040fabe:	movl %esi, 0x8(%ebp)
0x0040fac1:	cmpl %esi, $0xffffffe0<UINT8>
0x0040fac4:	ja 161
0x0040faca:	pushl %ebx
0x0040facb:	pushl %edi
0x0040facc:	movl %edi, 0x4120dc
0x0040fad2:	cmpl 0x4178c4, $0x0<UINT8>
0x0040fad9:	jne 0x0040faf3
0x0040faf3:	movl %eax, 0x418b6c
0x0040faf8:	cmpl %eax, $0x1<UINT8>
0x0040fafb:	jne 14
0x0040fafd:	testl %esi, %esi
0x0040faff:	je 4
0x0040fb01:	movl %eax, %esi
0x0040fb03:	jmp 0x0040fb08
0x0040fb08:	pushl %eax
0x0040fb09:	jmp 0x0040fb27
0x0040fb27:	pushl $0x0<UINT8>
0x0040fb29:	pushl 0x4178c4
0x0040fb2f:	call HeapAlloc@KERNEL32.dll
0x0040fb31:	movl %ebx, %eax
0x0040fb33:	testl %ebx, %ebx
0x0040fb35:	jne 0x0040fb65
0x0040fb65:	popl %edi
0x0040fb66:	movl %eax, %ebx
0x0040fb68:	popl %ebx
0x0040fb69:	jmp 0x0040fb7f
0x0040fb7f:	popl %esi
0x0040fb80:	popl %ebp
0x0040fb81:	ret

0x0040c7de:	movl %edi, %eax
0x0040c7e0:	popl %ecx
0x0040c7e1:	testl %edi, %edi
0x0040c7e3:	jne 0x0040c80c
0x0040c80c:	movl %eax, %edi
0x0040c80e:	popl %edi
0x0040c80f:	popl %esi
0x0040c810:	popl %ebp
0x0040c811:	ret

0x0040b986:	movl %edi, %eax
0x0040b988:	popl %ecx
0x0040b989:	testl %edi, %edi
0x0040b98b:	jne 0x0040b99a
0x0040b99a:	pushl %ebx
0x0040b99b:	pushl %esi
0x0040b99c:	pushl %edi
0x0040b99d:	call 0x0040cd90
0x0040cd90:	pushl %ebp
0x0040cd91:	movl %ebp, %esp
0x0040cd93:	pushl %edi
0x0040cd94:	pushl %esi
0x0040cd95:	movl %esi, 0xc(%ebp)
0x0040cd98:	movl %ecx, 0x10(%ebp)
0x0040cd9b:	movl %edi, 0x8(%ebp)
0x0040cd9e:	movl %eax, %ecx
0x0040cda0:	movl %edx, %ecx
0x0040cda2:	addl %eax, %esi
0x0040cda4:	cmpl %edi, %esi
0x0040cda6:	jbe 8
0x0040cda8:	cmpl %edi, %eax
0x0040cdaa:	jb 420
0x0040cdb0:	cmpl %ecx, $0x100<UINT32>
0x0040cdb6:	jb 31
0x0040cdb8:	cmpl 0x417b3c, $0x0<UINT8>
0x0040cdbf:	je 0x0040cdd7
0x0040cdd7:	testl %edi, $0x3<UINT32>
0x0040cddd:	jne 21
0x0040cddf:	shrl %ecx, $0x2<UINT8>
0x0040cde2:	andl %edx, $0x3<UINT8>
0x0040cde5:	cmpl %ecx, $0x8<UINT8>
0x0040cde8:	jb 42
0x0040cdea:	rep movsl %es:(%edi), %ds:(%esi)
0x0040cdec:	jmp 0x0040cf14
0x0040cf14:	movl %eax, 0x8(%ebp)
0x0040cf17:	popl %esi
0x0040cf18:	popl %edi
0x0040cf19:	leave
0x0040cf1a:	ret

0x0040b9a2:	addl %esp, $0xc<UINT8>
0x0040b9a5:	jmp 0x0040b98d
0x0040b98d:	pushl %esi
0x0040b98e:	call FreeEnvironmentStringsW@KERNEL32.dll
FreeEnvironmentStringsW@KERNEL32.dll: API Node	
0x0040b994:	movl %eax, %edi
0x0040b996:	popl %edi
0x0040b997:	popl %ebx
0x0040b998:	popl %esi
0x0040b999:	ret

0x00408da6:	movl 0x416fe4, %eax
0x00408dab:	call 0x0040b8a2
0x0040b8a2:	movl %edi, %edi
0x0040b8a4:	pushl %ebp
0x0040b8a5:	movl %ebp, %esp
0x0040b8a7:	pushl %ecx
0x0040b8a8:	pushl %ecx
0x0040b8a9:	pushl %ebx
0x0040b8aa:	pushl %esi
0x0040b8ab:	pushl %edi
0x0040b8ac:	pushl $0x104<UINT32>
0x0040b8b1:	movl %esi, $0x4176b8<UINT32>
0x0040b8b6:	pushl %esi
0x0040b8b7:	xorl %eax, %eax
0x0040b8b9:	xorl %ebx, %ebx
0x0040b8bb:	pushl %ebx
0x0040b8bc:	movw 0x4178c0, %ax
0x0040b8c2:	call GetModuleFileNameW@KERNEL32.dll
GetModuleFileNameW@KERNEL32.dll: API Node	
0x0040b8c8:	movl %eax, 0x418c98
0x0040b8cd:	movl 0x41738c, %esi
0x0040b8d3:	cmpl %eax, %ebx
0x0040b8d5:	je 7
0x0040b8d7:	movl %edi, %eax
0x0040b8d9:	cmpw (%eax), %bx
0x0040b8dc:	jne 0x0040b8e0
0x0040b8e0:	leal %eax, -4(%ebp)
0x0040b8e3:	pushl %eax
0x0040b8e4:	pushl %ebx
0x0040b8e5:	leal %ebx, -8(%ebp)
0x0040b8e8:	xorl %ecx, %ecx
0x0040b8ea:	movl %eax, %edi
0x0040b8ec:	call 0x0040b751
0x0040b751:	movl %edi, %edi
0x0040b753:	pushl %ebp
0x0040b754:	movl %ebp, %esp
0x0040b756:	pushl %ecx
0x0040b757:	pushl %esi
0x0040b758:	xorl %edx, %edx
0x0040b75a:	pushl %edi
0x0040b75b:	movl %edi, 0xc(%ebp)
0x0040b75e:	movl (%ebx), %edx
0x0040b760:	movl %esi, %ecx
0x0040b762:	movl (%edi), $0x1<UINT32>
0x0040b768:	cmpl 0x8(%ebp), %edx
0x0040b76b:	je 0x0040b776
0x0040b776:	cmpw (%eax), $0x22<UINT8>
0x0040b77a:	jne 0x0040b78f
0x0040b77c:	movl %edi, 0xc(%ebp)
0x0040b77f:	xorl %ecx, %ecx
0x0040b781:	testl %edx, %edx
0x0040b783:	sete %cl
0x0040b786:	pushl $0x22<UINT8>
0x0040b788:	incl %eax
0x0040b789:	incl %eax
0x0040b78a:	movl %edx, %ecx
0x0040b78c:	popl %ecx
0x0040b78d:	jmp 0x0040b7a7
0x0040b7a7:	testl %edx, %edx
0x0040b7a9:	jne 0x0040b776
0x0040b78f:	incl (%ebx)
0x0040b791:	testl %esi, %esi
0x0040b793:	je 0x0040b79d
0x0040b79d:	movzwl %ecx, (%eax)
0x0040b7a0:	incl %eax
0x0040b7a1:	incl %eax
0x0040b7a2:	testw %cx, %cx
0x0040b7a5:	je 0x0040b7e3
0x0040b7ab:	cmpw %cx, $0x20<UINT8>
0x0040b7af:	je 6
0x0040b7b1:	cmpw %cx, $0x9<UINT8>
0x0040b7b5:	jne 0x0040b776
0x0040b7e3:	decl %eax
0x0040b7e4:	decl %eax
0x0040b7e5:	jmp 0x0040b7c1
0x0040b7c1:	andl -4(%ebp), $0x0<UINT8>
0x0040b7c5:	xorl %edx, %edx
0x0040b7c7:	cmpw (%eax), %dx
0x0040b7ca:	je 0x0040b893
0x0040b893:	movl %eax, 0x8(%ebp)
0x0040b896:	cmpl %eax, %edx
0x0040b898:	je 0x0040b89c
0x0040b89c:	incl (%edi)
0x0040b89e:	popl %edi
0x0040b89f:	popl %esi
0x0040b8a0:	leave
0x0040b8a1:	ret

0x0040b8f1:	movl %ebx, -4(%ebp)
0x0040b8f4:	popl %ecx
0x0040b8f5:	popl %ecx
0x0040b8f6:	cmpl %ebx, $0x3fffffff<UINT32>
0x0040b8fc:	jae 74
0x0040b8fe:	movl %ecx, -8(%ebp)
0x0040b901:	cmpl %ecx, $0x7fffffff<UINT32>
0x0040b907:	jae 63
0x0040b909:	leal %eax, (%ecx,%ebx,2)
0x0040b90c:	addl %eax, %eax
0x0040b90e:	addl %ecx, %ecx
0x0040b910:	cmpl %eax, %ecx
0x0040b912:	jb 52
0x0040b914:	pushl %eax
0x0040b915:	call 0x0040c7cd
0x0040b91a:	movl %esi, %eax
0x0040b91c:	popl %ecx
0x0040b91d:	testl %esi, %esi
0x0040b91f:	je 39
0x0040b921:	leal %eax, -4(%ebp)
0x0040b924:	pushl %eax
0x0040b925:	leal %ecx, (%esi,%ebx,4)
0x0040b928:	pushl %esi
0x0040b929:	leal %ebx, -8(%ebp)
0x0040b92c:	movl %eax, %edi
0x0040b92e:	call 0x0040b751
0x0040b76d:	movl %ecx, 0x8(%ebp)
0x0040b770:	addl 0x8(%ebp), $0x4<UINT8>
0x0040b774:	movl (%ecx), %esi
0x0040b795:	movw %cx, (%eax)
0x0040b798:	movw (%esi), %cx
0x0040b79b:	incl %esi
0x0040b79c:	incl %esi
0x0040b89a:	movl (%eax), %edx
0x0040b933:	movl %eax, -4(%ebp)
0x0040b936:	decl %eax
0x0040b937:	popl %ecx
0x0040b938:	movl 0x41736c, %eax
0x0040b93d:	popl %ecx
0x0040b93e:	movl 0x417374, %esi
0x0040b944:	xorl %eax, %eax
0x0040b946:	jmp 0x0040b94b
0x0040b94b:	popl %edi
0x0040b94c:	popl %esi
0x0040b94d:	popl %ebx
0x0040b94e:	leave
0x0040b94f:	ret

0x00408db0:	testl %eax, %eax
0x00408db2:	jnl 0x00408dbc
0x00408dbc:	call 0x0040b673
0x0040b673:	movl %edi, %edi
0x0040b675:	pushl %esi
0x0040b676:	movl %esi, 0x416fe4
0x0040b67c:	pushl %edi
0x0040b67d:	xorl %edi, %edi
0x0040b67f:	testl %esi, %esi
0x0040b681:	jne 0x0040b69d
0x0040b69d:	movzwl %eax, (%esi)
0x0040b6a0:	testw %ax, %ax
0x0040b6a3:	jne 0x0040b68b
0x0040b68b:	cmpw %ax, $0x3d<UINT8>
0x0040b68f:	je 0x0040b692
0x0040b692:	pushl %esi
0x0040b693:	call 0x0040ea96
0x0040ea96:	movl %edi, %edi
0x0040ea98:	pushl %ebp
0x0040ea99:	movl %ebp, %esp
0x0040ea9b:	movl %eax, 0x8(%ebp)
0x0040ea9e:	movw %cx, (%eax)
0x0040eaa1:	incl %eax
0x0040eaa2:	incl %eax
0x0040eaa3:	testw %cx, %cx
0x0040eaa6:	jne 0x0040ea9e
0x0040eaa8:	subl %eax, 0x8(%ebp)
0x0040eaab:	sarl %eax
0x0040eaad:	decl %eax
0x0040eaae:	popl %ebp
0x0040eaaf:	ret

0x0040b698:	popl %ecx
0x0040b699:	leal %esi, 0x2(%esi,%eax,2)
0x0040b691:	incl %edi
0x0040b6a5:	pushl %ebx
0x0040b6a6:	pushl $0x4<UINT8>
0x0040b6a8:	incl %edi
0x0040b6a9:	pushl %edi
0x0040b6aa:	call 0x0040c812
0x0040b6af:	movl %ebx, %eax
0x0040b6b1:	popl %ecx
0x0040b6b2:	popl %ecx
0x0040b6b3:	movl 0x417380, %ebx
0x0040b6b9:	testl %ebx, %ebx
0x0040b6bb:	jne 0x0040b6c2
0x0040b6c2:	movl %esi, 0x416fe4
0x0040b6c8:	jmp 0x0040b70e
0x0040b70e:	cmpw (%esi), $0x0<UINT8>
0x0040b712:	jne 0x0040b6ca
0x0040b6ca:	pushl %esi
0x0040b6cb:	call 0x0040ea96
0x0040b6d0:	movl %edi, %eax
0x0040b6d2:	incl %edi
0x0040b6d3:	cmpw (%esi), $0x3d<UINT8>
0x0040b6d7:	popl %ecx
0x0040b6d8:	je 0x0040b70b
0x0040b70b:	leal %esi, (%esi,%edi,2)
0x0040b6da:	pushl $0x2<UINT8>
0x0040b6dc:	pushl %edi
0x0040b6dd:	call 0x0040c812
0x0040b6e2:	popl %ecx
0x0040b6e3:	popl %ecx
0x0040b6e4:	movl (%ebx), %eax
0x0040b6e6:	testl %eax, %eax
0x0040b6e8:	je 80
0x0040b6ea:	pushl %esi
0x0040b6eb:	pushl %edi
0x0040b6ec:	pushl %eax
0x0040b6ed:	call 0x0040ea27
0x0040ea27:	movl %edi, %edi
0x0040ea29:	pushl %ebp
0x0040ea2a:	movl %ebp, %esp
0x0040ea2c:	movl %edx, 0x8(%ebp)
0x0040ea2f:	pushl %ebx
0x0040ea30:	pushl %esi
0x0040ea31:	pushl %edi
0x0040ea32:	xorl %edi, %edi
0x0040ea34:	cmpl %edx, %edi
0x0040ea36:	je 7
0x0040ea38:	movl %ebx, 0xc(%ebp)
0x0040ea3b:	cmpl %ebx, %edi
0x0040ea3d:	ja 0x0040ea5d
0x0040ea5d:	movl %esi, 0x10(%ebp)
0x0040ea60:	cmpl %esi, %edi
0x0040ea62:	jne 0x0040ea6b
0x0040ea6b:	movl %ecx, %edx
0x0040ea6d:	movzwl %eax, (%esi)
0x0040ea70:	movw (%ecx), %ax
0x0040ea73:	incl %ecx
0x0040ea74:	incl %ecx
0x0040ea75:	incl %esi
0x0040ea76:	incl %esi
0x0040ea77:	cmpw %ax, %di
0x0040ea7a:	je 0x0040ea7f
0x0040ea7c:	decl %ebx
0x0040ea7d:	jne 0x0040ea6d
0x0040ea7f:	xorl %eax, %eax
0x0040ea81:	cmpl %ebx, %edi
0x0040ea83:	jne 0x0040ea58
0x0040ea58:	popl %edi
0x0040ea59:	popl %esi
0x0040ea5a:	popl %ebx
0x0040ea5b:	popl %ebp
0x0040ea5c:	ret

0x0040b6f2:	addl %esp, $0xc<UINT8>
0x0040b6f5:	testl %eax, %eax
0x0040b6f7:	je 0x0040b708
0x0040b708:	addl %ebx, $0x4<UINT8>
0x0040b714:	pushl 0x416fe4
0x0040b71a:	call 0x0040c73f
0x0040c73f:	pushl $0xc<UINT8>
0x0040c741:	pushl $0x414ae8<UINT32>
0x0040c746:	call 0x0040bc80
0x0040c74b:	movl %esi, 0x8(%ebp)
0x0040c74e:	testl %esi, %esi
0x0040c750:	je 117
0x0040c752:	cmpl 0x418b6c, $0x3<UINT8>
0x0040c759:	jne 0x0040c79e
0x0040c79e:	pushl %esi
0x0040c79f:	pushl $0x0<UINT8>
0x0040c7a1:	pushl 0x4178c4
0x0040c7a7:	call HeapFree@KERNEL32.dll
HeapFree@KERNEL32.dll: API Node	
0x0040c7ad:	testl %eax, %eax
0x0040c7af:	jne 0x0040c7c7
0x0040c7c7:	call 0x0040bcc5
0x0040c7cc:	ret

0x0040b71f:	andl 0x416fe4, $0x0<UINT8>
0x0040b726:	andl (%ebx), $0x0<UINT8>
0x0040b729:	movl 0x418c80, $0x1<UINT32>
0x0040b733:	xorl %eax, %eax
0x0040b735:	popl %ecx
0x0040b736:	popl %ebx
0x0040b737:	popl %edi
0x0040b738:	popl %esi
0x0040b739:	ret

0x00408dc1:	testl %eax, %eax
0x00408dc3:	jnl 0x00408dcd
0x00408dcd:	pushl %ebx
0x00408dce:	call 0x0040b09f
0x0040b09f:	movl %edi, %edi
0x0040b0a1:	pushl %ebp
0x0040b0a2:	movl %ebp, %esp
0x0040b0a4:	cmpl 0x418c90, $0x0<UINT8>
0x0040b0ab:	je 0x0040b0c6
0x0040b0c6:	call 0x0040e079
0x0040e079:	movl %edi, %edi
0x0040e07b:	pushl %esi
0x0040e07c:	pushl %edi
0x0040e07d:	xorl %edi, %edi
0x0040e07f:	leal %esi, 0x416d78(%edi)
0x0040e085:	pushl (%esi)
0x0040e087:	call 0x00409982
0x004099a4:	pushl %eax
0x004099a5:	pushl 0x41662c
0x004099ab:	call TlsGetValue@KERNEL32.dll
0x004099ad:	call FlsGetValue@KERNEL32.DLL
0x004099af:	testl %eax, %eax
0x004099b1:	je 8
0x004099b3:	movl %eax, 0x1f8(%eax)
0x004099b9:	jmp 0x004099e2
0x0040e08c:	addl %edi, $0x4<UINT8>
0x0040e08f:	popl %ecx
0x0040e090:	movl (%esi), %eax
0x0040e092:	cmpl %edi, $0x28<UINT8>
0x0040e095:	jb 0x0040e07f
0x0040e097:	popl %edi
0x0040e098:	popl %esi
0x0040e099:	ret

0x0040b0cb:	pushl $0x41223c<UINT32>
0x0040b0d0:	pushl $0x412224<UINT32>
0x0040b0d5:	call 0x0040b07b
0x0040b07b:	movl %edi, %edi
0x0040b07d:	pushl %ebp
0x0040b07e:	movl %ebp, %esp
0x0040b080:	pushl %esi
0x0040b081:	movl %esi, 0x8(%ebp)
0x0040b084:	xorl %eax, %eax
0x0040b086:	jmp 0x0040b097
0x0040b097:	cmpl %esi, 0xc(%ebp)
0x0040b09a:	jb 0x0040b088
0x0040b088:	testl %eax, %eax
0x0040b08a:	jne 16
0x0040b08c:	movl %ecx, (%esi)
0x0040b08e:	testl %ecx, %ecx
0x0040b090:	je 0x0040b094
0x0040b094:	addl %esi, $0x4<UINT8>
0x0040b092:	call 0x0040963f
0x0040963f:	cmpl 0x418c8c, $0x0<UINT8>
0x00409646:	jne 18
0x00409648:	pushl $0xfffffffd<UINT8>
0x0040964a:	call 0x004094a5
0x004094a5:	pushl $0x14<UINT8>
0x004094a7:	pushl $0x4149f8<UINT32>
0x004094ac:	call 0x0040bc80
0x004094b1:	orl -32(%ebp), $0xffffffff<UINT8>
0x004094b5:	call 0x00409c49
0x00409c49:	movl %edi, %edi
0x00409c4b:	pushl %esi
0x00409c4c:	call 0x00409bd0
0x00409bd0:	movl %edi, %edi
0x00409bd2:	pushl %esi
0x00409bd3:	pushl %edi
0x00409bd4:	call GetLastError@KERNEL32.dll
GetLastError@KERNEL32.dll: API Node	
0x00409bda:	pushl 0x416628
0x00409be0:	movl %edi, %eax
0x00409be2:	call 0x00409a78
0x00409a78:	movl %edi, %edi
0x00409a7a:	pushl %esi
0x00409a7b:	pushl 0x41662c
0x00409a81:	call TlsGetValue@KERNEL32.dll
0x00409a87:	movl %esi, %eax
0x00409a89:	testl %esi, %esi
0x00409a8b:	jne 0x00409aa8
0x00409aa8:	movl %eax, %esi
0x00409aaa:	popl %esi
0x00409aab:	ret

0x00409be7:	call FlsGetValue@KERNEL32.DLL
0x00409be9:	movl %esi, %eax
0x00409beb:	testl %esi, %esi
0x00409bed:	jne 0x00409c3d
0x00409c3d:	pushl %edi
0x00409c3e:	call SetLastError@KERNEL32.dll
SetLastError@KERNEL32.dll: API Node	
0x00409c44:	popl %edi
0x00409c45:	movl %eax, %esi
0x00409c47:	popl %esi
0x00409c48:	ret

0x00409c51:	movl %esi, %eax
0x00409c53:	testl %esi, %esi
0x00409c55:	jne 0x00409c5f
0x00409c5f:	movl %eax, %esi
0x00409c61:	popl %esi
0x00409c62:	ret

0x004094ba:	movl %edi, %eax
0x004094bc:	movl -36(%ebp), %edi
0x004094bf:	call 0x004091a0
0x004091a0:	pushl $0xc<UINT8>
0x004091a2:	pushl $0x4149d8<UINT32>
0x004091a7:	call 0x0040bc80
0x004091ac:	call 0x00409c49
0x004091b1:	movl %edi, %eax
0x004091b3:	movl %eax, 0x416534
0x004091b8:	testl 0x70(%edi), %eax
0x004091bb:	je 0x004091da
0x004091da:	pushl $0xd<UINT8>
0x004091dc:	call 0x0040c70c
0x004091e1:	popl %ecx
0x004091e2:	andl -4(%ebp), $0x0<UINT8>
0x004091e6:	movl %esi, 0x68(%edi)
0x004091e9:	movl -28(%ebp), %esi
0x004091ec:	cmpl %esi, 0x416438
0x004091f2:	je 0x0040922a
0x0040922a:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00409231:	call 0x0040923b
0x0040923b:	pushl $0xd<UINT8>
0x0040923d:	call 0x0040c632
0x00409242:	popl %ecx
0x00409243:	ret

0x00409236:	jmp 0x004091c6
0x004091c6:	testl %esi, %esi
0x004091c8:	jne 0x004091d2
0x004091d2:	movl %eax, %esi
0x004091d4:	call 0x0040bcc5
0x004091d9:	ret

0x004094c4:	movl %ebx, 0x68(%edi)
0x004094c7:	movl %esi, 0x8(%ebp)
0x004094ca:	call 0x00409244
0x00409244:	movl %edi, %edi
0x00409246:	pushl %ebp
0x00409247:	movl %ebp, %esp
0x00409249:	subl %esp, $0x10<UINT8>
0x0040924c:	pushl %ebx
0x0040924d:	xorl %ebx, %ebx
0x0040924f:	pushl %ebx
0x00409250:	leal %ecx, -16(%ebp)
0x00409253:	call 0x0040873c
0x0040873c:	movl %edi, %edi
0x0040873e:	pushl %ebp
0x0040873f:	movl %ebp, %esp
0x00408741:	movl %eax, 0x8(%ebp)
0x00408744:	pushl %esi
0x00408745:	movl %esi, %ecx
0x00408747:	movb 0xc(%esi), $0x0<UINT8>
0x0040874b:	testl %eax, %eax
0x0040874d:	jne 99
0x0040874f:	call 0x00409c49
0x00408754:	movl 0x8(%esi), %eax
0x00408757:	movl %ecx, 0x6c(%eax)
0x0040875a:	movl (%esi), %ecx
0x0040875c:	movl %ecx, 0x68(%eax)
0x0040875f:	movl 0x4(%esi), %ecx
0x00408762:	movl %ecx, (%esi)
0x00408764:	cmpl %ecx, 0x416618
0x0040876a:	je 0x0040877e
0x0040877e:	movl %eax, 0x4(%esi)
0x00408781:	cmpl %eax, 0x416438
0x00408787:	je 0x0040879f
0x0040879f:	movl %eax, 0x8(%esi)
0x004087a2:	testb 0x70(%eax), $0x2<UINT8>
0x004087a6:	jne 20
0x004087a8:	orl 0x70(%eax), $0x2<UINT8>
0x004087ac:	movb 0xc(%esi), $0x1<UINT8>
0x004087b0:	jmp 0x004087bc
0x004087bc:	movl %eax, %esi
0x004087be:	popl %esi
0x004087bf:	popl %ebp
0x004087c0:	ret $0x4<UINT16>

0x00409258:	movl 0x417314, %ebx
0x0040925e:	cmpl %esi, $0xfffffffe<UINT8>
0x00409261:	jne 0x00409281
0x00409281:	cmpl %esi, $0xfffffffd<UINT8>
0x00409284:	jne 0x00409298
0x00409286:	movl 0x417314, $0x1<UINT32>
0x00409290:	call GetACP@KERNEL32.dll
GetACP@KERNEL32.dll: API Node	
0x00409296:	jmp 0x00409273
0x00409273:	cmpb -4(%ebp), %bl
0x00409276:	je 69
0x00409278:	movl %ecx, -8(%ebp)
0x0040927b:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0040927f:	jmp 0x004092bd
0x004092bd:	popl %ebx
0x004092be:	leave
0x004092bf:	ret

0x004094cf:	movl 0x8(%ebp), %eax
0x004094d2:	cmpl %eax, 0x4(%ebx)
0x004094d5:	je 343
0x004094db:	pushl $0x220<UINT32>
0x004094e0:	call 0x0040c7cd
0x004094e5:	popl %ecx
0x004094e6:	movl %ebx, %eax
0x004094e8:	testl %ebx, %ebx
0x004094ea:	je 326
0x004094f0:	movl %ecx, $0x88<UINT32>
0x004094f5:	movl %esi, 0x68(%edi)
0x004094f8:	movl %edi, %ebx
0x004094fa:	rep movsl %es:(%edi), %ds:(%esi)
0x004094fc:	andl (%ebx), $0x0<UINT8>
0x004094ff:	pushl %ebx
0x00409500:	pushl 0x8(%ebp)
0x00409503:	call 0x004092c0
0x004092c0:	movl %edi, %edi
0x004092c2:	pushl %ebp
0x004092c3:	movl %ebp, %esp
0x004092c5:	subl %esp, $0x20<UINT8>
0x004092c8:	movl %eax, 0x416004
0x004092cd:	xorl %eax, %ebp
0x004092cf:	movl -4(%ebp), %eax
0x004092d2:	pushl %ebx
0x004092d3:	movl %ebx, 0xc(%ebp)
0x004092d6:	pushl %esi
0x004092d7:	movl %esi, 0x8(%ebp)
0x004092da:	pushl %edi
0x004092db:	call 0x00409244
0x00409298:	cmpl %esi, $0xfffffffc<UINT8>
0x0040929b:	jne 0x004092af
0x004092af:	cmpb -4(%ebp), %bl
0x004092b2:	je 7
0x004092b4:	movl %eax, -8(%ebp)
0x004092b7:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x004092bb:	movl %eax, %esi
0x004092e0:	movl %edi, %eax
0x004092e2:	xorl %esi, %esi
0x004092e4:	movl 0x8(%ebp), %edi
0x004092e7:	cmpl %edi, %esi
0x004092e9:	jne 0x004092f9
0x004092f9:	movl -28(%ebp), %esi
0x004092fc:	xorl %eax, %eax
0x004092fe:	cmpl 0x416440(%eax), %edi
0x00409304:	je 145
0x0040930a:	incl -28(%ebp)
0x0040930d:	addl %eax, $0x30<UINT8>
0x00409310:	cmpl %eax, $0xf0<UINT32>
0x00409315:	jb 0x004092fe
0x00409317:	cmpl %edi, $0xfde8<UINT32>
0x0040931d:	je 368
0x00409323:	cmpl %edi, $0xfde9<UINT32>
0x00409329:	je 356
0x0040932f:	movzwl %eax, %di
0x00409332:	pushl %eax
0x00409333:	call IsValidCodePage@KERNEL32.dll
IsValidCodePage@KERNEL32.dll: API Node	
0x00409339:	testl %eax, %eax
0x0040933b:	je 338
0x00409341:	leal %eax, -24(%ebp)
0x00409344:	pushl %eax
0x00409345:	pushl %edi
0x00409346:	call GetCPInfo@KERNEL32.dll
GetCPInfo@KERNEL32.dll: API Node	
0x0040934c:	testl %eax, %eax
0x0040934e:	je 307
0x00409354:	pushl $0x101<UINT32>
0x00409359:	leal %eax, 0x1c(%ebx)
0x0040935c:	pushl %esi
0x0040935d:	pushl %eax
0x0040935e:	call 0x0040bf10
0x0040bf10:	movl %edx, 0xc(%esp)
0x0040bf14:	movl %ecx, 0x4(%esp)
0x0040bf18:	testl %edx, %edx
0x0040bf1a:	je 105
0x0040bf1c:	xorl %eax, %eax
0x0040bf1e:	movb %al, 0x8(%esp)
0x0040bf22:	testb %al, %al
0x0040bf24:	jne 22
0x0040bf26:	cmpl %edx, $0x100<UINT32>
0x0040bf2c:	jb 14
0x0040bf2e:	cmpl 0x417b3c, $0x0<UINT8>
0x0040bf35:	je 0x0040bf3c
0x0040bf3c:	pushl %edi
0x0040bf3d:	movl %edi, %ecx
0x0040bf3f:	cmpl %edx, $0x4<UINT8>
0x0040bf42:	jb 49
0x0040bf44:	negl %ecx
0x0040bf46:	andl %ecx, $0x3<UINT8>
0x0040bf49:	je 0x0040bf57
0x0040bf57:	movl %ecx, %eax
0x0040bf59:	shll %eax, $0x8<UINT8>
0x0040bf5c:	addl %eax, %ecx
0x0040bf5e:	movl %ecx, %eax
0x0040bf60:	shll %eax, $0x10<UINT8>
0x0040bf63:	addl %eax, %ecx
0x0040bf65:	movl %ecx, %edx
0x0040bf67:	andl %edx, $0x3<UINT8>
0x0040bf6a:	shrl %ecx, $0x2<UINT8>
0x0040bf6d:	je 6
0x0040bf6f:	rep stosl %es:(%edi), %eax
0x0040bf71:	testl %edx, %edx
0x0040bf73:	je 10
0x0040bf75:	movb (%edi), %al
0x0040bf77:	addl %edi, $0x1<UINT8>
0x0040bf7a:	subl %edx, $0x1<UINT8>
0x0040bf7d:	jne -10
0x0040bf7f:	movl %eax, 0x8(%esp)
0x0040bf83:	popl %edi
0x0040bf84:	ret

0x00409363:	xorl %edx, %edx
0x00409365:	incl %edx
0x00409366:	addl %esp, $0xc<UINT8>
0x00409369:	movl 0x4(%ebx), %edi
0x0040936c:	movl 0xc(%ebx), %esi
0x0040936f:	cmpl -24(%ebp), %edx
0x00409372:	jbe 248
0x00409378:	cmpb -18(%ebp), $0x0<UINT8>
0x0040937c:	je 0x00409451
0x00409451:	leal %eax, 0x1e(%ebx)
0x00409454:	movl %ecx, $0xfe<UINT32>
0x00409459:	orb (%eax), $0x8<UINT8>
0x0040945c:	incl %eax
0x0040945d:	decl %ecx
0x0040945e:	jne 0x00409459
0x00409460:	movl %eax, 0x4(%ebx)
0x00409463:	call 0x00408f7a
0x00408f7a:	subl %eax, $0x3a4<UINT32>
0x00408f7f:	je 34
0x00408f81:	subl %eax, $0x4<UINT8>
0x00408f84:	je 23
0x00408f86:	subl %eax, $0xd<UINT8>
0x00408f89:	je 12
0x00408f8b:	decl %eax
0x00408f8c:	je 3
0x00408f8e:	xorl %eax, %eax
0x00408f90:	ret

0x00409468:	movl 0xc(%ebx), %eax
0x0040946b:	movl 0x8(%ebx), %edx
0x0040946e:	jmp 0x00409473
0x00409473:	xorl %eax, %eax
0x00409475:	movzwl %ecx, %ax
0x00409478:	movl %eax, %ecx
0x0040947a:	shll %ecx, $0x10<UINT8>
0x0040947d:	orl %eax, %ecx
0x0040947f:	leal %edi, 0x10(%ebx)
0x00409482:	stosl %es:(%edi), %eax
0x00409483:	stosl %es:(%edi), %eax
0x00409484:	stosl %es:(%edi), %eax
0x00409485:	jmp 0x0040942f
0x0040942f:	movl %esi, %ebx
0x00409431:	call 0x0040900d
0x0040900d:	movl %edi, %edi
0x0040900f:	pushl %ebp
0x00409010:	movl %ebp, %esp
0x00409012:	subl %esp, $0x51c<UINT32>
0x00409018:	movl %eax, 0x416004
0x0040901d:	xorl %eax, %ebp
0x0040901f:	movl -4(%ebp), %eax
0x00409022:	pushl %ebx
0x00409023:	pushl %edi
0x00409024:	leal %eax, -1304(%ebp)
0x0040902a:	pushl %eax
0x0040902b:	pushl 0x4(%esi)
0x0040902e:	call GetCPInfo@KERNEL32.dll
0x00409034:	movl %edi, $0x100<UINT32>
0x00409039:	testl %eax, %eax
0x0040903b:	je 251
0x00409041:	xorl %eax, %eax
0x00409043:	movb -260(%ebp,%eax), %al
0x0040904a:	incl %eax
0x0040904b:	cmpl %eax, %edi
0x0040904d:	jb 0x00409043
0x0040904f:	movb %al, -1298(%ebp)
0x00409055:	movb -260(%ebp), $0x20<UINT8>
0x0040905c:	testb %al, %al
0x0040905e:	je 0x0040908e
0x0040908e:	pushl $0x0<UINT8>
0x00409090:	pushl 0xc(%esi)
0x00409093:	leal %eax, -1284(%ebp)
0x00409099:	pushl 0x4(%esi)
0x0040909c:	pushl %eax
0x0040909d:	pushl %edi
0x0040909e:	leal %eax, -260(%ebp)
0x004090a4:	pushl %eax
0x004090a5:	pushl $0x1<UINT8>
0x004090a7:	pushl $0x0<UINT8>
0x004090a9:	call 0x0040c54e
0x0040c54e:	movl %edi, %edi
0x0040c550:	pushl %ebp
0x0040c551:	movl %ebp, %esp
0x0040c553:	subl %esp, $0x10<UINT8>
0x0040c556:	pushl 0x8(%ebp)
0x0040c559:	leal %ecx, -16(%ebp)
0x0040c55c:	call 0x0040873c
0x0040c561:	pushl 0x24(%ebp)
0x0040c564:	leal %ecx, -16(%ebp)
0x0040c567:	pushl 0x20(%ebp)
0x0040c56a:	pushl 0x1c(%ebp)
0x0040c56d:	pushl 0x18(%ebp)
0x0040c570:	pushl 0x14(%ebp)
0x0040c573:	pushl 0x10(%ebp)
0x0040c576:	pushl 0xc(%ebp)
0x0040c579:	call 0x0040c394
0x0040c394:	movl %edi, %edi
0x0040c396:	pushl %ebp
0x0040c397:	movl %ebp, %esp
0x0040c399:	pushl %ecx
0x0040c39a:	pushl %ecx
0x0040c39b:	movl %eax, 0x416004
0x0040c3a0:	xorl %eax, %ebp
0x0040c3a2:	movl -4(%ebp), %eax
0x0040c3a5:	movl %eax, 0x4178cc
0x0040c3aa:	pushl %ebx
0x0040c3ab:	pushl %esi
0x0040c3ac:	xorl %ebx, %ebx
0x0040c3ae:	pushl %edi
0x0040c3af:	movl %edi, %ecx
0x0040c3b1:	cmpl %eax, %ebx
0x0040c3b3:	jne 58
0x0040c3b5:	leal %eax, -8(%ebp)
0x0040c3b8:	pushl %eax
0x0040c3b9:	xorl %esi, %esi
0x0040c3bb:	incl %esi
0x0040c3bc:	pushl %esi
0x0040c3bd:	pushl $0x4129d8<UINT32>
0x0040c3c2:	pushl %esi
0x0040c3c3:	call GetStringTypeW@KERNEL32.dll
GetStringTypeW@KERNEL32.dll: API Node	
0x0040c3c9:	testl %eax, %eax
0x0040c3cb:	je 8
0x0040c3cd:	movl 0x4178cc, %esi
0x0040c3d3:	jmp 0x0040c409
0x0040c409:	movl -8(%ebp), %ebx
0x0040c40c:	cmpl 0x18(%ebp), %ebx
0x0040c40f:	jne 0x0040c419
0x0040c419:	movl %esi, 0x412084
0x0040c41f:	xorl %eax, %eax
0x0040c421:	cmpl 0x20(%ebp), %ebx
0x0040c424:	pushl %ebx
0x0040c425:	pushl %ebx
0x0040c426:	pushl 0x10(%ebp)
0x0040c429:	setne %al
0x0040c42c:	pushl 0xc(%ebp)
0x0040c42f:	leal %eax, 0x1(,%eax,8)
0x0040c436:	pushl %eax
0x0040c437:	pushl 0x18(%ebp)
0x0040c43a:	call MultiByteToWideChar@KERNEL32.dll
MultiByteToWideChar@KERNEL32.dll: API Node	
0x0040c43c:	movl %edi, %eax
0x0040c43e:	cmpl %edi, %ebx
0x0040c440:	je 171
0x0040c446:	jle 60
0x0040c448:	cmpl %edi, $0x7ffffff0<UINT32>
0x0040c44e:	ja 52
0x0040c450:	leal %eax, 0x8(%edi,%edi)
0x0040c454:	cmpl %eax, $0x400<UINT32>
0x0040c459:	ja 19
0x0040c45b:	call 0x0040fb90
0x0040fb90:	pushl %ecx
0x0040fb91:	leal %ecx, 0x8(%esp)
0x0040fb95:	subl %ecx, %eax
0x0040fb97:	andl %ecx, $0xf<UINT8>
0x0040fb9a:	addl %eax, %ecx
0x0040fb9c:	sbbl %ecx, %ecx
0x0040fb9e:	orl %eax, %ecx
0x0040fba0:	popl %ecx
0x0040fba1:	jmp 0x00410340
0x00410340:	pushl %ecx
0x00410341:	leal %ecx, 0x4(%esp)
0x00410345:	subl %ecx, %eax
0x00410347:	sbbl %eax, %eax
0x00410349:	notl %eax
0x0041034b:	andl %ecx, %eax
0x0041034d:	movl %eax, %esp
0x0041034f:	andl %eax, $0xfffff000<UINT32>
0x00410354:	cmpl %ecx, %eax
0x00410356:	jb 10
0x00410358:	movl %eax, %ecx
0x0041035a:	popl %ecx
0x0041035b:	xchgl %esp, %eax
0x0041035c:	movl %eax, (%eax)
0x0041035e:	movl (%esp), %eax
0x00410361:	ret

0x0040c460:	movl %eax, %esp
0x0040c462:	cmpl %eax, %ebx
0x0040c464:	je 28
0x0040c466:	movl (%eax), $0xcccc<UINT32>
0x0040c46c:	jmp 0x0040c47f
0x0040c47f:	addl %eax, $0x8<UINT8>
0x0040c482:	movl %ebx, %eax
0x0040c484:	testl %ebx, %ebx
0x0040c486:	je 105
0x0040c488:	leal %eax, (%edi,%edi)
0x0040c48b:	pushl %eax
0x0040c48c:	pushl $0x0<UINT8>
0x0040c48e:	pushl %ebx
0x0040c48f:	call 0x0040bf10
