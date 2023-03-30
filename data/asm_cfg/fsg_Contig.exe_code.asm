0x00489000:	movl %ebx, $0x4001d0<UINT32>
0x00489005:	movl %edi, $0x401000<UINT32>
0x0048900a:	movl %esi, $0x47021d<UINT32>
0x0048900f:	pushl %ebx
0x00489010:	call 0x0048901f
0x0048901f:	cld
0x00489020:	movb %dl, $0xffffff80<UINT8>
0x00489022:	movsb %es:(%edi), %ds:(%esi)
0x00489023:	pushl $0x2<UINT8>
0x00489025:	popl %ebx
0x00489026:	call 0x00489015
0x00489015:	addb %dl, %dl
0x00489017:	jne 0x0048901e
0x00489019:	movb %dl, (%esi)
0x0048901b:	incl %esi
0x0048901c:	adcb %dl, %dl
0x0048901e:	ret

0x00489029:	jae 0x00489022
0x0048902b:	xorl %ecx, %ecx
0x0048902d:	call 0x00489015
0x00489030:	jae 0x0048904a
0x00489032:	xorl %eax, %eax
0x00489034:	call 0x00489015
0x00489037:	jae 0x0048905a
0x00489039:	movb %bl, $0x2<UINT8>
0x0048903b:	incl %ecx
0x0048903c:	movb %al, $0x10<UINT8>
0x0048903e:	call 0x00489015
0x00489041:	adcb %al, %al
0x00489043:	jae 0x0048903e
0x00489045:	jne 0x00489086
0x00489086:	pushl %esi
0x00489087:	movl %esi, %edi
0x00489089:	subl %esi, %eax
0x0048908b:	rep movsb %es:(%edi), %ds:(%esi)
0x0048908d:	popl %esi
0x0048908e:	jmp 0x00489026
0x00489047:	stosb %es:(%edi), %al
0x00489048:	jmp 0x00489026
0x0048905a:	lodsb %al, %ds:(%esi)
0x0048905b:	shrl %eax
0x0048905d:	je 0x004890a0
0x0048905f:	adcl %ecx, %ecx
0x00489061:	jmp 0x0048907f
0x0048907f:	incl %ecx
0x00489080:	incl %ecx
0x00489081:	xchgl %ebp, %eax
0x00489082:	movl %eax, %ebp
0x00489084:	movb %bl, $0x1<UINT8>
0x0048904a:	call 0x00489092
0x00489092:	incl %ecx
0x00489093:	call 0x00489015
0x00489097:	adcl %ecx, %ecx
0x00489099:	call 0x00489015
0x0048909d:	jb 0x00489093
0x0048909f:	ret

0x0048904f:	subl %ecx, %ebx
0x00489051:	jne 0x00489063
0x00489053:	call 0x00489090
0x00489090:	xorl %ecx, %ecx
0x00489058:	jmp 0x00489082
0x00489063:	xchgl %ecx, %eax
0x00489064:	decl %eax
0x00489065:	shll %eax, $0x8<UINT8>
0x00489068:	lodsb %al, %ds:(%esi)
0x00489069:	call 0x00489090
0x0048906e:	cmpl %eax, $0x7d00<UINT32>
0x00489073:	jae 0x0048907f
0x00489075:	cmpb %ah, $0x5<UINT8>
0x00489078:	jae 0x00489080
0x0048907a:	cmpl %eax, $0x7f<UINT8>
0x0048907d:	ja 0x00489081
0x004890a0:	popl %edi
0x004890a1:	popl %ebx
0x004890a2:	movzwl %edi, (%ebx)
0x004890a5:	decl %edi
0x004890a6:	je 0x004890b0
0x004890a8:	decl %edi
0x004890a9:	je 0x004890be
0x004890ab:	shll %edi, $0xc<UINT8>
0x004890ae:	jmp 0x004890b7
0x004890b7:	incl %ebx
0x004890b8:	incl %ebx
0x004890b9:	jmp 0x0048900f
0x004890b0:	movl %edi, 0x2(%ebx)
0x004890b3:	pushl %edi
0x004890b4:	addl %ebx, $0x4<UINT8>
0x004890be:	popl %edi
0x004890bf:	movl %ebx, $0x489128<UINT32>
0x004890c4:	incl %edi
0x004890c5:	movl %esi, (%edi)
0x004890c7:	scasl %eax, %es:(%edi)
0x004890c8:	pushl %edi
0x004890c9:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004890cb:	xchgl %ebp, %eax
0x004890cc:	xorl %eax, %eax
0x004890ce:	scasb %al, %es:(%edi)
0x004890cf:	jne 0x004890ce
0x004890d1:	decb (%edi)
0x004890d3:	je 0x004890c4
0x004890d5:	decb (%edi)
0x004890d7:	jne 0x004890df
0x004890df:	decb (%edi)
0x004890e1:	je 0x00407f58
0x004890e7:	pushl %edi
0x004890e8:	pushl %ebp
0x004890e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x004890ec:	orl (%esi), %eax
0x004890ee:	lodsl %eax, %ds:(%esi)
0x004890ef:	jne 0x004890cc
GetProcAddress@KERNEL32.dll: API Node	
0x00407f58:	call 0x00413cd6
0x00413cd6:	pushl %ebp
0x00413cd7:	movl %ebp, %esp
0x00413cd9:	subl %esp, $0x14<UINT8>
0x00413cdc:	andl -12(%ebp), $0x0<UINT8>
0x00413ce0:	andl -8(%ebp), $0x0<UINT8>
0x00413ce4:	movl %eax, 0x43a618
0x00413ce9:	pushl %esi
0x00413cea:	pushl %edi
0x00413ceb:	movl %edi, $0xbb40e64e<UINT32>
0x00413cf0:	movl %esi, $0xffff0000<UINT32>
0x00413cf5:	cmpl %eax, %edi
0x00413cf7:	je 0x00413d06
0x00413d06:	leal %eax, -12(%ebp)
0x00413d09:	pushl %eax
0x00413d0a:	call GetSystemTimeAsFileTime@KERNEL32.dll
GetSystemTimeAsFileTime@KERNEL32.dll: API Node	
0x00413d10:	movl %eax, -8(%ebp)
0x00413d13:	xorl %eax, -12(%ebp)
0x00413d16:	movl -4(%ebp), %eax
0x00413d19:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x00413d1f:	xorl -4(%ebp), %eax
0x00413d22:	call GetCurrentProcessId@KERNEL32.dll
GetCurrentProcessId@KERNEL32.dll: API Node	
0x00413d28:	xorl -4(%ebp), %eax
0x00413d2b:	leal %eax, -20(%ebp)
0x00413d2e:	pushl %eax
0x00413d2f:	call QueryPerformanceCounter@KERNEL32.dll
QueryPerformanceCounter@KERNEL32.dll: API Node	
0x00413d35:	movl %ecx, -16(%ebp)
0x00413d38:	leal %eax, -4(%ebp)
0x00413d3b:	xorl %ecx, -20(%ebp)
0x00413d3e:	xorl %ecx, -4(%ebp)
0x00413d41:	xorl %ecx, %eax
0x00413d43:	cmpl %ecx, %edi
0x00413d45:	jne 0x00413d4e
0x00413d4e:	testl %esi, %ecx
0x00413d50:	jne 0x00413d5e
0x00413d5e:	movl 0x43a618, %ecx
0x00413d64:	notl %ecx
0x00413d66:	movl 0x43a61c, %ecx
0x00413d6c:	popl %edi
0x00413d6d:	popl %esi
0x00413d6e:	movl %esp, %ebp
0x00413d70:	popl %ebp
0x00413d71:	ret

0x00407f5d:	jmp 0x00407d97
0x00407d97:	pushl $0x14<UINT8>
0x00407d99:	pushl $0x4361f0<UINT32>
0x00407d9e:	call 0x00408d40
0x00408d40:	pushl $0x408de0<UINT32>
0x00408d45:	pushl %fs:0
0x00408d4c:	movl %eax, 0x10(%esp)
0x00408d50:	movl 0x10(%esp), %ebp
0x00408d54:	leal %ebp, 0x10(%esp)
0x00408d58:	subl %esp, %eax
0x00408d5a:	pushl %ebx
0x00408d5b:	pushl %esi
0x00408d5c:	pushl %edi
0x00408d5d:	movl %eax, 0x43a618
0x00408d62:	xorl -4(%ebp), %eax
0x00408d65:	xorl %eax, %ebp
0x00408d67:	pushl %eax
0x00408d68:	movl -24(%ebp), %esp
0x00408d6b:	pushl -8(%ebp)
0x00408d6e:	movl %eax, -4(%ebp)
0x00408d71:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00408d78:	movl -8(%ebp), %eax
0x00408d7b:	leal %eax, -16(%ebp)
0x00408d7e:	movl %fs:0, %eax
0x00408d84:	ret

0x00407da3:	pushl $0x1<UINT8>
0x00407da5:	call 0x00413c89
0x00413c89:	pushl %ebp
0x00413c8a:	movl %ebp, %esp
0x00413c8c:	movl %eax, 0x8(%ebp)
0x00413c8f:	movl 0x43c178, %eax
0x00413c94:	popl %ebp
0x00413c95:	ret

0x00407daa:	popl %ecx
0x00407dab:	movl %eax, $0x5a4d<UINT32>
0x00407db0:	cmpw 0x400000, %ax
0x00407db7:	je 0x00407dbd
0x00407dbd:	movl %eax, 0x40003c
0x00407dc2:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00407dcc:	jne -21
0x00407dce:	movl %ecx, $0x10b<UINT32>
0x00407dd3:	cmpw 0x400018(%eax), %cx
0x00407dda:	jne -35
0x00407ddc:	xorl %ebx, %ebx
0x00407dde:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00407de5:	jbe 9
0x00407de7:	cmpl 0x4000e8(%eax), %ebx
0x00407ded:	setne %bl
0x00407df0:	movl -28(%ebp), %ebx
0x00407df3:	call 0x0040d2a9
0x0040d2a9:	call GetProcessHeap@KERNEL32.dll
GetProcessHeap@KERNEL32.dll: API Node	
0x0040d2af:	xorl %ecx, %ecx
0x0040d2b1:	movl 0x43c7d0, %eax
0x0040d2b6:	testl %eax, %eax
0x0040d2b8:	setne %cl
0x0040d2bb:	movl %eax, %ecx
0x0040d2bd:	ret

0x00407df8:	testl %eax, %eax
0x00407dfa:	jne 0x00407e04
0x00407e04:	call 0x0040bf83
0x0040bf83:	call 0x004065a7
0x004065a7:	pushl %esi
0x004065a8:	pushl $0x0<UINT8>
0x004065aa:	call EncodePointer@KERNEL32.dll
EncodePointer@KERNEL32.dll: API Node	
0x004065b0:	movl %esi, %eax
0x004065b2:	pushl %esi
0x004065b3:	call 0x0040d296
0x0040d296:	pushl %ebp
0x0040d297:	movl %ebp, %esp
0x0040d299:	movl %eax, 0x8(%ebp)
0x0040d29c:	movl 0x43c7c8, %eax
0x0040d2a1:	popl %ebp
0x0040d2a2:	ret

0x004065b8:	pushl %esi
0x004065b9:	call 0x004090c3
0x004090c3:	pushl %ebp
0x004090c4:	movl %ebp, %esp
0x004090c6:	movl %eax, 0x8(%ebp)
0x004090c9:	movl 0x43c064, %eax
0x004090ce:	popl %ebp
0x004090cf:	ret

0x004065be:	pushl %esi
0x004065bf:	call 0x0040e169
0x0040e169:	pushl %ebp
0x0040e16a:	movl %ebp, %esp
0x0040e16c:	movl %eax, 0x8(%ebp)
0x0040e16f:	movl 0x43cafc, %eax
0x0040e174:	popl %ebp
0x0040e175:	ret

0x004065c4:	pushl %esi
0x004065c5:	call 0x0040e195
0x0040e195:	pushl %ebp
0x0040e196:	movl %ebp, %esp
0x0040e198:	movl %eax, 0x8(%ebp)
0x0040e19b:	movl 0x43cb00, %eax
0x0040e1a0:	movl 0x43cb04, %eax
0x0040e1a5:	movl 0x43cb08, %eax
0x0040e1aa:	movl 0x43cb0c, %eax
0x0040e1af:	popl %ebp
0x0040e1b0:	ret

0x004065ca:	pushl %esi
0x004065cb:	call 0x0040df7f
0x0040df7f:	pushl $0x40df38<UINT32>
0x0040df84:	call EncodePointer@KERNEL32.dll
0x0040df8a:	movl 0x43caf8, %eax
0x0040df8f:	ret

0x004065d0:	pushl %esi
0x004065d1:	call 0x0040e6a2
0x0040e6a2:	pushl %ebp
0x0040e6a3:	movl %ebp, %esp
0x0040e6a5:	movl %eax, 0x8(%ebp)
0x0040e6a8:	movl 0x43cb14, %eax
0x0040e6ad:	popl %ebp
0x0040e6ae:	ret

0x004065d6:	addl %esp, $0x18<UINT8>
0x004065d9:	popl %esi
0x004065da:	jmp 0x0040abe5
0x0040abe5:	pushl %esi
0x0040abe6:	pushl %edi
0x0040abe7:	pushl $0x430738<UINT32>
0x0040abec:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x0040abf2:	movl %esi, 0x4290d4
0x0040abf8:	movl %edi, %eax
0x0040abfa:	pushl $0x431398<UINT32>
0x0040abff:	pushl %edi
0x0040ac00:	call GetProcAddress@KERNEL32.dll
0x0040ac02:	xorl %eax, 0x43a618
0x0040ac08:	pushl $0x4313a4<UINT32>
0x0040ac0d:	pushl %edi
0x0040ac0e:	movl 0x46d780, %eax
0x0040ac13:	call GetProcAddress@KERNEL32.dll
0x0040ac15:	xorl %eax, 0x43a618
0x0040ac1b:	pushl $0x4313ac<UINT32>
0x0040ac20:	pushl %edi
0x0040ac21:	movl 0x46d784, %eax
0x0040ac26:	call GetProcAddress@KERNEL32.dll
0x0040ac28:	xorl %eax, 0x43a618
0x0040ac2e:	pushl $0x4313b8<UINT32>
0x0040ac33:	pushl %edi
0x0040ac34:	movl 0x46d788, %eax
0x0040ac39:	call GetProcAddress@KERNEL32.dll
0x0040ac3b:	xorl %eax, 0x43a618
0x0040ac41:	pushl $0x4313c4<UINT32>
0x0040ac46:	pushl %edi
0x0040ac47:	movl 0x46d78c, %eax
0x0040ac4c:	call GetProcAddress@KERNEL32.dll
0x0040ac4e:	xorl %eax, 0x43a618
0x0040ac54:	pushl $0x4313e0<UINT32>
0x0040ac59:	pushl %edi
0x0040ac5a:	movl 0x46d790, %eax
0x0040ac5f:	call GetProcAddress@KERNEL32.dll
0x0040ac61:	xorl %eax, 0x43a618
0x0040ac67:	pushl $0x4313f0<UINT32>
0x0040ac6c:	pushl %edi
0x0040ac6d:	movl 0x46d794, %eax
0x0040ac72:	call GetProcAddress@KERNEL32.dll
0x0040ac74:	xorl %eax, 0x43a618
0x0040ac7a:	pushl $0x431404<UINT32>
0x0040ac7f:	pushl %edi
0x0040ac80:	movl 0x46d798, %eax
0x0040ac85:	call GetProcAddress@KERNEL32.dll
0x0040ac87:	xorl %eax, 0x43a618
0x0040ac8d:	pushl $0x43141c<UINT32>
0x0040ac92:	pushl %edi
0x0040ac93:	movl 0x46d79c, %eax
0x0040ac98:	call GetProcAddress@KERNEL32.dll
0x0040ac9a:	xorl %eax, 0x43a618
0x0040aca0:	pushl $0x431434<UINT32>
0x0040aca5:	pushl %edi
0x0040aca6:	movl 0x46d7a0, %eax
0x0040acab:	call GetProcAddress@KERNEL32.dll
0x0040acad:	xorl %eax, 0x43a618
0x0040acb3:	pushl $0x431448<UINT32>
0x0040acb8:	pushl %edi
0x0040acb9:	movl 0x46d7a4, %eax
0x0040acbe:	call GetProcAddress@KERNEL32.dll
0x0040acc0:	xorl %eax, 0x43a618
0x0040acc6:	pushl $0x431468<UINT32>
0x0040accb:	pushl %edi
0x0040accc:	movl 0x46d7a8, %eax
0x0040acd1:	call GetProcAddress@KERNEL32.dll
0x0040acd3:	xorl %eax, 0x43a618
0x0040acd9:	pushl $0x431480<UINT32>
0x0040acde:	pushl %edi
0x0040acdf:	movl 0x46d7ac, %eax
0x0040ace4:	call GetProcAddress@KERNEL32.dll
0x0040ace6:	xorl %eax, 0x43a618
0x0040acec:	pushl $0x431498<UINT32>
0x0040acf1:	pushl %edi
0x0040acf2:	movl 0x46d7b0, %eax
0x0040acf7:	call GetProcAddress@KERNEL32.dll
0x0040acf9:	xorl %eax, 0x43a618
0x0040acff:	pushl $0x4314ac<UINT32>
0x0040ad04:	pushl %edi
0x0040ad05:	movl 0x46d7b4, %eax
0x0040ad0a:	call GetProcAddress@KERNEL32.dll
0x0040ad0c:	xorl %eax, 0x43a618
0x0040ad12:	movl 0x46d7b8, %eax
0x0040ad17:	pushl $0x4314c0<UINT32>
0x0040ad1c:	pushl %edi
0x0040ad1d:	call GetProcAddress@KERNEL32.dll
0x0040ad1f:	xorl %eax, 0x43a618
0x0040ad25:	pushl $0x4314dc<UINT32>
0x0040ad2a:	pushl %edi
0x0040ad2b:	movl 0x46d7bc, %eax
0x0040ad30:	call GetProcAddress@KERNEL32.dll
0x0040ad32:	xorl %eax, 0x43a618
0x0040ad38:	pushl $0x4314fc<UINT32>
0x0040ad3d:	pushl %edi
0x0040ad3e:	movl 0x46d7c0, %eax
0x0040ad43:	call GetProcAddress@KERNEL32.dll
0x0040ad45:	xorl %eax, 0x43a618
0x0040ad4b:	pushl $0x431518<UINT32>
0x0040ad50:	pushl %edi
0x0040ad51:	movl 0x46d7c4, %eax
0x0040ad56:	call GetProcAddress@KERNEL32.dll
0x0040ad58:	xorl %eax, 0x43a618
0x0040ad5e:	pushl $0x431538<UINT32>
0x0040ad63:	pushl %edi
0x0040ad64:	movl 0x46d7c8, %eax
0x0040ad69:	call GetProcAddress@KERNEL32.dll
0x0040ad6b:	xorl %eax, 0x43a618
0x0040ad71:	pushl $0x43154c<UINT32>
0x0040ad76:	pushl %edi
0x0040ad77:	movl 0x46d7cc, %eax
0x0040ad7c:	call GetProcAddress@KERNEL32.dll
0x0040ad7e:	xorl %eax, 0x43a618
0x0040ad84:	pushl $0x431568<UINT32>
0x0040ad89:	pushl %edi
0x0040ad8a:	movl 0x46d7d0, %eax
0x0040ad8f:	call GetProcAddress@KERNEL32.dll
0x0040ad91:	xorl %eax, 0x43a618
0x0040ad97:	pushl $0x43157c<UINT32>
0x0040ad9c:	pushl %edi
0x0040ad9d:	movl 0x46d7d8, %eax
0x0040ada2:	call GetProcAddress@KERNEL32.dll
0x0040ada4:	xorl %eax, 0x43a618
0x0040adaa:	pushl $0x43158c<UINT32>
0x0040adaf:	pushl %edi
0x0040adb0:	movl 0x46d7d4, %eax
0x0040adb5:	call GetProcAddress@KERNEL32.dll
0x0040adb7:	xorl %eax, 0x43a618
0x0040adbd:	pushl $0x43159c<UINT32>
0x0040adc2:	pushl %edi
0x0040adc3:	movl 0x46d7dc, %eax
0x0040adc8:	call GetProcAddress@KERNEL32.dll
0x0040adca:	xorl %eax, 0x43a618
0x0040add0:	pushl $0x4315ac<UINT32>
0x0040add5:	pushl %edi
0x0040add6:	movl 0x46d7e0, %eax
0x0040addb:	call GetProcAddress@KERNEL32.dll
0x0040addd:	xorl %eax, 0x43a618
0x0040ade3:	pushl $0x4315bc<UINT32>
0x0040ade8:	pushl %edi
0x0040ade9:	movl 0x46d7e4, %eax
0x0040adee:	call GetProcAddress@KERNEL32.dll
0x0040adf0:	xorl %eax, 0x43a618
0x0040adf6:	pushl $0x4315d8<UINT32>
0x0040adfb:	pushl %edi
0x0040adfc:	movl 0x46d7e8, %eax
0x0040ae01:	call GetProcAddress@KERNEL32.dll
0x0040ae03:	xorl %eax, 0x43a618
0x0040ae09:	pushl $0x4315ec<UINT32>
0x0040ae0e:	pushl %edi
0x0040ae0f:	movl 0x46d7ec, %eax
0x0040ae14:	call GetProcAddress@KERNEL32.dll
0x0040ae16:	xorl %eax, 0x43a618
0x0040ae1c:	pushl $0x4315fc<UINT32>
0x0040ae21:	pushl %edi
0x0040ae22:	movl 0x46d7f0, %eax
0x0040ae27:	call GetProcAddress@KERNEL32.dll
0x0040ae29:	xorl %eax, 0x43a618
0x0040ae2f:	pushl $0x431610<UINT32>
0x0040ae34:	pushl %edi
0x0040ae35:	movl 0x46d7f4, %eax
0x0040ae3a:	call GetProcAddress@KERNEL32.dll
0x0040ae3c:	xorl %eax, 0x43a618
0x0040ae42:	movl 0x46d7f8, %eax
0x0040ae47:	pushl $0x431620<UINT32>
0x0040ae4c:	pushl %edi
0x0040ae4d:	call GetProcAddress@KERNEL32.dll
0x0040ae4f:	xorl %eax, 0x43a618
0x0040ae55:	pushl $0x431640<UINT32>
0x0040ae5a:	pushl %edi
0x0040ae5b:	movl 0x46d7fc, %eax
0x0040ae60:	call GetProcAddress@KERNEL32.dll
0x0040ae62:	xorl %eax, 0x43a618
0x0040ae68:	popl %edi
0x0040ae69:	movl 0x46d800, %eax
0x0040ae6e:	popl %esi
0x0040ae6f:	ret

0x0040bf88:	call 0x00408150
0x00408150:	pushl %esi
0x00408151:	pushl %edi
0x00408152:	movl %esi, $0x43a638<UINT32>
0x00408157:	movl %edi, $0x43bf10<UINT32>
0x0040815c:	cmpl 0x4(%esi), $0x1<UINT8>
0x00408160:	jne 22
0x00408162:	pushl $0x0<UINT8>
0x00408164:	movl (%esi), %edi
0x00408166:	addl %edi, $0x18<UINT8>
0x00408169:	pushl $0xfa0<UINT32>
0x0040816e:	pushl (%esi)
0x00408170:	call 0x0040ab77
0x0040ab77:	pushl %ebp
0x0040ab78:	movl %ebp, %esp
0x0040ab7a:	movl %eax, 0x46d790
0x0040ab7f:	xorl %eax, 0x43a618
0x0040ab85:	je 13
0x0040ab87:	pushl 0x10(%ebp)
0x0040ab8a:	pushl 0xc(%ebp)
0x0040ab8d:	pushl 0x8(%ebp)
0x0040ab90:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x0040ab92:	popl %ebp
0x0040ab93:	ret

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
