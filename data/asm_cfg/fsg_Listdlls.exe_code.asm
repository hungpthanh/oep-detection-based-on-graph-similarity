0x004b2000:	movl %ebx, $0x4001d0<UINT32>
0x004b2005:	movl %edi, $0x401000<UINT32>
0x004b200a:	movl %esi, $0x49d033<UINT32>
0x004b200f:	pushl %ebx
0x004b2010:	call 0x004b201f
0x004b201f:	cld
0x004b2020:	movb %dl, $0xffffff80<UINT8>
0x004b2022:	movsb %es:(%edi), %ds:(%esi)
0x004b2023:	pushl $0x2<UINT8>
0x004b2025:	popl %ebx
0x004b2026:	call 0x004b2015
0x004b2015:	addb %dl, %dl
0x004b2017:	jne 0x004b201e
0x004b2019:	movb %dl, (%esi)
0x004b201b:	incl %esi
0x004b201c:	adcb %dl, %dl
0x004b201e:	ret

0x004b2029:	jae 0x004b2022
0x004b202b:	xorl %ecx, %ecx
0x004b202d:	call 0x004b2015
0x004b2030:	jae 0x004b204a
0x004b2032:	xorl %eax, %eax
0x004b2034:	call 0x004b2015
0x004b2037:	jae 0x004b205a
0x004b2039:	movb %bl, $0x2<UINT8>
0x004b203b:	incl %ecx
0x004b203c:	movb %al, $0x10<UINT8>
0x004b203e:	call 0x004b2015
0x004b2041:	adcb %al, %al
0x004b2043:	jae 0x004b203e
0x004b2045:	jne 0x004b2086
0x004b2047:	stosb %es:(%edi), %al
0x004b2048:	jmp 0x004b2026
0x004b205a:	lodsb %al, %ds:(%esi)
0x004b205b:	shrl %eax
0x004b205d:	je 0x004b20a0
0x004b205f:	adcl %ecx, %ecx
0x004b2061:	jmp 0x004b207f
0x004b207f:	incl %ecx
0x004b2080:	incl %ecx
0x004b2081:	xchgl %ebp, %eax
0x004b2082:	movl %eax, %ebp
0x004b2084:	movb %bl, $0x1<UINT8>
0x004b2086:	pushl %esi
0x004b2087:	movl %esi, %edi
0x004b2089:	subl %esi, %eax
0x004b208b:	rep movsb %es:(%edi), %ds:(%esi)
0x004b208d:	popl %esi
0x004b208e:	jmp 0x004b2026
0x004b204a:	call 0x004b2092
0x004b2092:	incl %ecx
0x004b2093:	call 0x004b2015
0x004b2097:	adcl %ecx, %ecx
0x004b2099:	call 0x004b2015
0x004b209d:	jb 0x004b2093
0x004b209f:	ret

0x004b204f:	subl %ecx, %ebx
0x004b2051:	jne 0x004b2063
0x004b2063:	xchgl %ecx, %eax
0x004b2064:	decl %eax
0x004b2065:	shll %eax, $0x8<UINT8>
0x004b2068:	lodsb %al, %ds:(%esi)
0x004b2069:	call 0x004b2090
0x004b2090:	xorl %ecx, %ecx
0x004b206e:	cmpl %eax, $0x7d00<UINT32>
0x004b2073:	jae 0x004b207f
0x004b2075:	cmpb %ah, $0x5<UINT8>
0x004b2078:	jae 0x004b2080
0x004b207a:	cmpl %eax, $0x7f<UINT8>
0x004b207d:	ja 0x004b2081
0x004b2053:	call 0x004b2090
0x004b2058:	jmp 0x004b2082
0x004b20a0:	popl %edi
0x004b20a1:	popl %ebx
0x004b20a2:	movzwl %edi, (%ebx)
0x004b20a5:	decl %edi
0x004b20a6:	je 0x004b20b0
0x004b20a8:	decl %edi
0x004b20a9:	je 0x004b20be
0x004b20ab:	shll %edi, $0xc<UINT8>
0x004b20ae:	jmp 0x004b20b7
0x004b20b7:	incl %ebx
0x004b20b8:	incl %ebx
0x004b20b9:	jmp 0x004b200f
0x004b20b0:	movl %edi, 0x2(%ebx)
0x004b20b3:	pushl %edi
0x004b20b4:	addl %ebx, $0x4<UINT8>
0x004b20be:	popl %edi
0x004b20bf:	movl %ebx, $0x4b2128<UINT32>
0x004b20c4:	incl %edi
0x004b20c5:	movl %esi, (%edi)
0x004b20c7:	scasl %eax, %es:(%edi)
0x004b20c8:	pushl %edi
0x004b20c9:	call LoadLibraryA@KERNEL32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004b20cb:	xchgl %ebp, %eax
0x004b20cc:	xorl %eax, %eax
0x004b20ce:	scasb %al, %es:(%edi)
0x004b20cf:	jne 0x004b20ce
0x004b20d1:	decb (%edi)
0x004b20d3:	je 0x004b20c4
0x004b20d5:	decb (%edi)
0x004b20d7:	jne 0x004b20df
0x004b20df:	decb (%edi)
0x004b20e1:	je 0x00409666
0x004b20e7:	pushl %edi
0x004b20e8:	pushl %ebp
0x004b20e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x004b20ec:	orl (%esi), %eax
0x004b20ee:	lodsl %eax, %ds:(%esi)
0x004b20ef:	jne 0x004b20cc
GetProcAddress@KERNEL32.dll: API Node	
LoadLibraryA@KERNEL32.dll: API Node	
0x004b20d9:	incl %edi
0x004b20da:	pushl (%edi)
0x004b20dc:	scasl %eax, %es:(%edi)
0x004b20dd:	jmp 0x004b20e8
0x00409666:	call 0x00414903
0x00414903:	pushl %ebp
0x00414904:	movl %ebp, %esp
0x00414906:	subl %esp, $0x14<UINT8>
0x00414909:	andl -12(%ebp), $0x0<UINT8>
0x0041490d:	andl -8(%ebp), $0x0<UINT8>
0x00414911:	movl %eax, 0x42bdc0
0x00414916:	pushl %esi
0x00414917:	pushl %edi
0x00414918:	movl %edi, $0xbb40e64e<UINT32>
0x0041491d:	movl %esi, $0xffff0000<UINT32>
0x00414922:	cmpl %eax, %edi
0x00414924:	je 0x00414933
0x00414933:	leal %eax, -12(%ebp)
0x00414936:	pushl %eax
0x00414937:	call GetSystemTimeAsFileTime@KERNEL32.dll
GetSystemTimeAsFileTime@KERNEL32.dll: API Node	
0x0041493d:	movl %eax, -8(%ebp)
0x00414940:	xorl %eax, -12(%ebp)
0x00414943:	movl -4(%ebp), %eax
0x00414946:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x0041494c:	xorl -4(%ebp), %eax
0x0041494f:	call GetCurrentProcessId@KERNEL32.dll
GetCurrentProcessId@KERNEL32.dll: API Node	
0x00414955:	xorl -4(%ebp), %eax
0x00414958:	leal %eax, -20(%ebp)
0x0041495b:	pushl %eax
0x0041495c:	call QueryPerformanceCounter@KERNEL32.dll
QueryPerformanceCounter@KERNEL32.dll: API Node	
0x00414962:	movl %ecx, -16(%ebp)
0x00414965:	leal %eax, -4(%ebp)
0x00414968:	xorl %ecx, -20(%ebp)
0x0041496b:	xorl %ecx, -4(%ebp)
0x0041496e:	xorl %ecx, %eax
0x00414970:	cmpl %ecx, %edi
0x00414972:	jne 0x0041497b
0x0041497b:	testl %esi, %ecx
0x0041497d:	jne 0x0041498b
0x0041498b:	movl 0x42bdc0, %ecx
0x00414991:	notl %ecx
0x00414993:	movl 0x42bdc4, %ecx
0x00414999:	popl %edi
0x0041499a:	popl %esi
0x0041499b:	movl %esp, %ebp
0x0041499d:	popl %ebp
0x0041499e:	ret

0x0040966b:	jmp 0x004094eb
0x004094eb:	pushl $0x14<UINT8>
0x004094ed:	pushl $0x429528<UINT32>
0x004094f2:	call 0x00409b40
0x00409b40:	pushl $0x4096a0<UINT32>
0x00409b45:	pushl %fs:0
0x00409b4c:	movl %eax, 0x10(%esp)
0x00409b50:	movl 0x10(%esp), %ebp
0x00409b54:	leal %ebp, 0x10(%esp)
0x00409b58:	subl %esp, %eax
0x00409b5a:	pushl %ebx
0x00409b5b:	pushl %esi
0x00409b5c:	pushl %edi
0x00409b5d:	movl %eax, 0x42bdc0
0x00409b62:	xorl -4(%ebp), %eax
0x00409b65:	xorl %eax, %ebp
0x00409b67:	pushl %eax
0x00409b68:	movl -24(%ebp), %esp
0x00409b6b:	pushl -8(%ebp)
0x00409b6e:	movl %eax, -4(%ebp)
0x00409b71:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00409b78:	movl -8(%ebp), %eax
0x00409b7b:	leal %eax, -16(%ebp)
0x00409b7e:	movl %fs:0, %eax
0x00409b84:	ret

0x004094f7:	pushl $0x1<UINT8>
0x004094f9:	call 0x004148b6
0x004148b6:	pushl %ebp
0x004148b7:	movl %ebp, %esp
0x004148b9:	movl %eax, 0x8(%ebp)
0x004148bc:	movl 0x42da80, %eax
0x004148c1:	popl %ebp
0x004148c2:	ret

0x004094fe:	popl %ecx
0x004094ff:	movl %eax, $0x5a4d<UINT32>
0x00409504:	cmpw 0x400000, %ax
0x0040950b:	je 0x00409511
0x00409511:	movl %eax, 0x40003c
0x00409516:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00409520:	jne -21
0x00409522:	movl %ecx, $0x10b<UINT32>
0x00409527:	cmpw 0x400018(%eax), %cx
0x0040952e:	jne -35
0x00409530:	xorl %ebx, %ebx
0x00409532:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00409539:	jbe 9
0x0040953b:	cmpl 0x4000e8(%eax), %ebx
0x00409541:	setne %bl
0x00409544:	movl -28(%ebp), %ebx
0x00409547:	call 0x0040a9d4
0x0040a9d4:	call GetProcessHeap@KERNEL32.dll
GetProcessHeap@KERNEL32.dll: API Node	
0x0040a9da:	xorl %ecx, %ecx
0x0040a9dc:	movl 0x42da7c, %eax
0x0040a9e1:	testl %eax, %eax
0x0040a9e3:	setne %cl
0x0040a9e6:	movl %eax, %ecx
0x0040a9e8:	ret

0x0040954c:	testl %eax, %eax
0x0040954e:	jne 0x00409558
0x00409558:	call 0x0040dd95
0x0040dd95:	call 0x0040835f
0x0040835f:	pushl %esi
0x00408360:	pushl $0x0<UINT8>
0x00408362:	call EncodePointer@KERNEL32.dll
EncodePointer@KERNEL32.dll: API Node	
0x00408368:	movl %esi, %eax
0x0040836a:	pushl %esi
0x0040836b:	call 0x004099d5
0x004099d5:	pushl %ebp
0x004099d6:	movl %ebp, %esp
0x004099d8:	movl %eax, 0x8(%ebp)
0x004099db:	movl 0x42da68, %eax
0x004099e0:	popl %ebp
0x004099e1:	ret

0x00408370:	pushl %esi
0x00408371:	call 0x0040a084
0x0040a084:	pushl %ebp
0x0040a085:	movl %ebp, %esp
0x0040a087:	movl %eax, 0x8(%ebp)
0x0040a08a:	movl 0x42da70, %eax
0x0040a08f:	popl %ebp
0x0040a090:	ret

0x00408376:	pushl %esi
0x00408377:	call 0x00412471
0x00412471:	pushl %ebp
0x00412472:	movl %ebp, %esp
0x00412474:	movl %eax, 0x8(%ebp)
0x00412477:	movl 0x42e344, %eax
0x0041247c:	popl %ebp
0x0041247d:	ret

0x0040837c:	pushl %esi
0x0040837d:	call 0x0041248b
0x0041248b:	pushl %ebp
0x0041248c:	movl %ebp, %esp
0x0041248e:	movl %eax, 0x8(%ebp)
0x00412491:	movl 0x42e348, %eax
0x00412496:	movl 0x42e34c, %eax
0x0041249b:	movl 0x42e350, %eax
0x004124a0:	movl 0x42e354, %eax
0x004124a5:	popl %ebp
0x004124a6:	ret

0x00408382:	pushl %esi
0x00408383:	call 0x0040defb
0x0040defb:	pushl $0x40deb4<UINT32>
0x0040df00:	call EncodePointer@KERNEL32.dll
0x0040df06:	movl 0x42e0b4, %eax
0x0040df0b:	ret

0x00408388:	pushl %esi
0x00408389:	call 0x0041269c
0x0041269c:	pushl %ebp
0x0041269d:	movl %ebp, %esp
0x0041269f:	movl %eax, 0x8(%ebp)
0x004126a2:	movl 0x42e35c, %eax
0x004126a7:	popl %ebp
0x004126a8:	ret

0x0040838e:	addl %esp, $0x18<UINT8>
0x00408391:	popl %esi
0x00408392:	jmp 0x00409c8d
0x00409c8d:	pushl %esi
0x00409c8e:	pushl %edi
0x00409c8f:	pushl $0x424a88<UINT32>
0x00409c94:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x00409c9a:	movl %esi, 0x41d124
0x00409ca0:	movl %edi, %eax
0x00409ca2:	pushl $0x424aa4<UINT32>
0x00409ca7:	pushl %edi
0x00409ca8:	call GetProcAddress@KERNEL32.dll
0x00409caa:	xorl %eax, 0x42bdc0
0x00409cb0:	pushl $0x424ab0<UINT32>
0x00409cb5:	pushl %edi
0x00409cb6:	movl 0x42e5c0, %eax
0x00409cbb:	call GetProcAddress@KERNEL32.dll
0x00409cbd:	xorl %eax, 0x42bdc0
0x00409cc3:	pushl $0x424ab8<UINT32>
0x00409cc8:	pushl %edi
0x00409cc9:	movl 0x42e5c4, %eax
0x00409cce:	call GetProcAddress@KERNEL32.dll
0x00409cd0:	xorl %eax, 0x42bdc0
0x00409cd6:	pushl $0x424ac4<UINT32>
0x00409cdb:	pushl %edi
0x00409cdc:	movl 0x42e5c8, %eax
0x00409ce1:	call GetProcAddress@KERNEL32.dll
0x00409ce3:	xorl %eax, 0x42bdc0
0x00409ce9:	pushl $0x424ad0<UINT32>
0x00409cee:	pushl %edi
0x00409cef:	movl 0x42e5cc, %eax
0x00409cf4:	call GetProcAddress@KERNEL32.dll
0x00409cf6:	xorl %eax, 0x42bdc0
0x00409cfc:	pushl $0x424aec<UINT32>
0x00409d01:	pushl %edi
0x00409d02:	movl 0x42e5d0, %eax
0x00409d07:	call GetProcAddress@KERNEL32.dll
0x00409d09:	xorl %eax, 0x42bdc0
0x00409d0f:	pushl $0x424afc<UINT32>
0x00409d14:	pushl %edi
0x00409d15:	movl 0x42e5d4, %eax
0x00409d1a:	call GetProcAddress@KERNEL32.dll
0x00409d1c:	xorl %eax, 0x42bdc0
0x00409d22:	pushl $0x424b10<UINT32>
0x00409d27:	pushl %edi
0x00409d28:	movl 0x42e5d8, %eax
0x00409d2d:	call GetProcAddress@KERNEL32.dll
0x00409d2f:	xorl %eax, 0x42bdc0
0x00409d35:	pushl $0x424b28<UINT32>
0x00409d3a:	pushl %edi
0x00409d3b:	movl 0x42e5dc, %eax
0x00409d40:	call GetProcAddress@KERNEL32.dll
0x00409d42:	xorl %eax, 0x42bdc0
0x00409d48:	pushl $0x424b40<UINT32>
0x00409d4d:	pushl %edi
0x00409d4e:	movl 0x42e5e0, %eax
0x00409d53:	call GetProcAddress@KERNEL32.dll
0x00409d55:	xorl %eax, 0x42bdc0
0x00409d5b:	pushl $0x424b54<UINT32>
0x00409d60:	pushl %edi
0x00409d61:	movl 0x42e5e4, %eax
0x00409d66:	call GetProcAddress@KERNEL32.dll
0x00409d68:	xorl %eax, 0x42bdc0
0x00409d6e:	pushl $0x424b74<UINT32>
0x00409d73:	pushl %edi
0x00409d74:	movl 0x42e5e8, %eax
0x00409d79:	call GetProcAddress@KERNEL32.dll
0x00409d7b:	xorl %eax, 0x42bdc0
0x00409d81:	pushl $0x424b8c<UINT32>
0x00409d86:	pushl %edi
0x00409d87:	movl 0x42e5ec, %eax
0x00409d8c:	call GetProcAddress@KERNEL32.dll
0x00409d8e:	xorl %eax, 0x42bdc0
0x00409d94:	pushl $0x424ba4<UINT32>
0x00409d99:	pushl %edi
0x00409d9a:	movl 0x42e5f0, %eax
0x00409d9f:	call GetProcAddress@KERNEL32.dll
0x00409da1:	xorl %eax, 0x42bdc0
0x00409da7:	pushl $0x424bb8<UINT32>
0x00409dac:	pushl %edi
0x00409dad:	movl 0x42e5f4, %eax
0x00409db2:	call GetProcAddress@KERNEL32.dll
0x00409db4:	xorl %eax, 0x42bdc0
0x00409dba:	movl 0x42e5f8, %eax
0x00409dbf:	pushl $0x424bcc<UINT32>
0x00409dc4:	pushl %edi
0x00409dc5:	call GetProcAddress@KERNEL32.dll
0x00409dc7:	xorl %eax, 0x42bdc0
0x00409dcd:	pushl $0x424be8<UINT32>
0x00409dd2:	pushl %edi
0x00409dd3:	movl 0x42e5fc, %eax
0x00409dd8:	call GetProcAddress@KERNEL32.dll
0x00409dda:	xorl %eax, 0x42bdc0
0x00409de0:	pushl $0x424c08<UINT32>
0x00409de5:	pushl %edi
0x00409de6:	movl 0x42e600, %eax
0x00409deb:	call GetProcAddress@KERNEL32.dll
0x00409ded:	xorl %eax, 0x42bdc0
0x00409df3:	pushl $0x424c24<UINT32>
0x00409df8:	pushl %edi
0x00409df9:	movl 0x42e604, %eax
0x00409dfe:	call GetProcAddress@KERNEL32.dll
0x00409e00:	xorl %eax, 0x42bdc0
0x00409e06:	pushl $0x424c44<UINT32>
0x00409e0b:	pushl %edi
0x00409e0c:	movl 0x42e608, %eax
0x00409e11:	call GetProcAddress@KERNEL32.dll
0x00409e13:	xorl %eax, 0x42bdc0
0x00409e19:	pushl $0x424c58<UINT32>
0x00409e1e:	pushl %edi
0x00409e1f:	movl 0x42e60c, %eax
0x00409e24:	call GetProcAddress@KERNEL32.dll
0x00409e26:	xorl %eax, 0x42bdc0
0x00409e2c:	pushl $0x424c74<UINT32>
0x00409e31:	pushl %edi
0x00409e32:	movl 0x42e610, %eax
0x00409e37:	call GetProcAddress@KERNEL32.dll
0x00409e39:	xorl %eax, 0x42bdc0
0x00409e3f:	pushl $0x424c88<UINT32>
0x00409e44:	pushl %edi
0x00409e45:	movl 0x42e618, %eax
0x00409e4a:	call GetProcAddress@KERNEL32.dll
0x00409e4c:	xorl %eax, 0x42bdc0
0x00409e52:	pushl $0x424c98<UINT32>
0x00409e57:	pushl %edi
0x00409e58:	movl 0x42e614, %eax
0x00409e5d:	call GetProcAddress@KERNEL32.dll
0x00409e5f:	xorl %eax, 0x42bdc0
0x00409e65:	pushl $0x424ca8<UINT32>
0x00409e6a:	pushl %edi
0x00409e6b:	movl 0x42e61c, %eax
0x00409e70:	call GetProcAddress@KERNEL32.dll
0x00409e72:	xorl %eax, 0x42bdc0
0x00409e78:	pushl $0x424cb8<UINT32>
0x00409e7d:	pushl %edi
0x00409e7e:	movl 0x42e620, %eax
0x00409e83:	call GetProcAddress@KERNEL32.dll
0x00409e85:	xorl %eax, 0x42bdc0
0x00409e8b:	pushl $0x424cc8<UINT32>
0x00409e90:	pushl %edi
0x00409e91:	movl 0x42e624, %eax
0x00409e96:	call GetProcAddress@KERNEL32.dll
0x00409e98:	xorl %eax, 0x42bdc0
0x00409e9e:	pushl $0x424ce4<UINT32>
0x00409ea3:	pushl %edi
0x00409ea4:	movl 0x42e628, %eax
0x00409ea9:	call GetProcAddress@KERNEL32.dll
0x00409eab:	xorl %eax, 0x42bdc0
0x00409eb1:	pushl $0x424cf8<UINT32>
0x00409eb6:	pushl %edi
0x00409eb7:	movl 0x42e62c, %eax
0x00409ebc:	call GetProcAddress@KERNEL32.dll
0x00409ebe:	xorl %eax, 0x42bdc0
0x00409ec4:	pushl $0x424d08<UINT32>
0x00409ec9:	pushl %edi
0x00409eca:	movl 0x42e630, %eax
0x00409ecf:	call GetProcAddress@KERNEL32.dll
0x00409ed1:	xorl %eax, 0x42bdc0
0x00409ed7:	pushl $0x424d1c<UINT32>
0x00409edc:	pushl %edi
0x00409edd:	movl 0x42e634, %eax
0x00409ee2:	call GetProcAddress@KERNEL32.dll
0x00409ee4:	xorl %eax, 0x42bdc0
0x00409eea:	movl 0x42e638, %eax
0x00409eef:	pushl $0x424d2c<UINT32>
0x00409ef4:	pushl %edi
0x00409ef5:	call GetProcAddress@KERNEL32.dll
0x00409ef7:	xorl %eax, 0x42bdc0
0x00409efd:	pushl $0x424d4c<UINT32>
0x00409f02:	pushl %edi
0x00409f03:	movl 0x42e63c, %eax
0x00409f08:	call GetProcAddress@KERNEL32.dll
0x00409f0a:	xorl %eax, 0x42bdc0
0x00409f10:	popl %edi
0x00409f11:	movl 0x42e640, %eax
0x00409f16:	popl %esi
0x00409f17:	ret

0x0040dd9a:	call 0x00410b34
0x00410b34:	pushl %esi
0x00410b35:	pushl %edi
0x00410b36:	movl %esi, $0x42c360<UINT32>
0x00410b3b:	movl %edi, $0x42e0c8<UINT32>
0x00410b40:	cmpl 0x4(%esi), $0x1<UINT8>
0x00410b44:	jne 22
0x00410b46:	pushl $0x0<UINT8>
0x00410b48:	movl (%esi), %edi
0x00410b4a:	addl %edi, $0x18<UINT8>
0x00410b4d:	pushl $0xfa0<UINT32>
0x00410b52:	pushl (%esi)
0x00410b54:	call 0x00409c1f
0x00409c1f:	pushl %ebp
0x00409c20:	movl %ebp, %esp
0x00409c22:	movl %eax, 0x42e5d0
0x00409c27:	xorl %eax, 0x42bdc0
0x00409c2d:	je 13
0x00409c2f:	pushl 0x10(%ebp)
0x00409c32:	pushl 0xc(%ebp)
0x00409c35:	pushl 0x8(%ebp)
0x00409c38:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x00409c3a:	popl %ebp
0x00409c3b:	ret

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
