0x00450000:	movl %ebx, $0x4001d0<UINT32>
0x00450005:	movl %edi, $0x401000<UINT32>
0x0045000a:	movl %esi, $0x4362d2<UINT32>
0x0045000f:	pushl %ebx
0x00450010:	call 0x0045001f
0x0045001f:	cld
0x00450020:	movb %dl, $0xffffff80<UINT8>
0x00450022:	movsb %es:(%edi), %ds:(%esi)
0x00450023:	pushl $0x2<UINT8>
0x00450025:	popl %ebx
0x00450026:	call 0x00450015
0x00450015:	addb %dl, %dl
0x00450017:	jne 0x0045001e
0x00450019:	movb %dl, (%esi)
0x0045001b:	incl %esi
0x0045001c:	adcb %dl, %dl
0x0045001e:	ret

0x00450029:	jae 0x00450022
0x0045002b:	xorl %ecx, %ecx
0x0045002d:	call 0x00450015
0x00450030:	jae 0x0045004a
0x00450032:	xorl %eax, %eax
0x00450034:	call 0x00450015
0x00450037:	jae 0x0045005a
0x00450039:	movb %bl, $0x2<UINT8>
0x0045003b:	incl %ecx
0x0045003c:	movb %al, $0x10<UINT8>
0x0045003e:	call 0x00450015
0x00450041:	adcb %al, %al
0x00450043:	jae 0x0045003e
0x00450045:	jne 0x00450086
0x00450086:	pushl %esi
0x00450087:	movl %esi, %edi
0x00450089:	subl %esi, %eax
0x0045008b:	rep movsb %es:(%edi), %ds:(%esi)
0x0045008d:	popl %esi
0x0045008e:	jmp 0x00450026
0x00450047:	stosb %es:(%edi), %al
0x00450048:	jmp 0x00450026
0x0045005a:	lodsb %al, %ds:(%esi)
0x0045005b:	shrl %eax
0x0045005d:	je 0x004500a0
0x0045005f:	adcl %ecx, %ecx
0x00450061:	jmp 0x0045007f
0x0045007f:	incl %ecx
0x00450080:	incl %ecx
0x00450081:	xchgl %ebp, %eax
0x00450082:	movl %eax, %ebp
0x00450084:	movb %bl, $0x1<UINT8>
0x0045004a:	call 0x00450092
0x00450092:	incl %ecx
0x00450093:	call 0x00450015
0x00450097:	adcl %ecx, %ecx
0x00450099:	call 0x00450015
0x0045009d:	jb 0x00450093
0x0045009f:	ret

0x0045004f:	subl %ecx, %ebx
0x00450051:	jne 0x00450063
0x00450053:	call 0x00450090
0x00450090:	xorl %ecx, %ecx
0x00450058:	jmp 0x00450082
0x00450063:	xchgl %ecx, %eax
0x00450064:	decl %eax
0x00450065:	shll %eax, $0x8<UINT8>
0x00450068:	lodsb %al, %ds:(%esi)
0x00450069:	call 0x00450090
0x0045006e:	cmpl %eax, $0x7d00<UINT32>
0x00450073:	jae 0x0045007f
0x00450075:	cmpb %ah, $0x5<UINT8>
0x00450078:	jae 0x00450080
0x0045007a:	cmpl %eax, $0x7f<UINT8>
0x0045007d:	ja 0x00450081
0x004500a0:	popl %edi
0x004500a1:	popl %ebx
0x004500a2:	movzwl %edi, (%ebx)
0x004500a5:	decl %edi
0x004500a6:	je 0x004500b0
0x004500a8:	decl %edi
0x004500a9:	je 0x004500be
0x004500ab:	shll %edi, $0xc<UINT8>
0x004500ae:	jmp 0x004500b7
0x004500b7:	incl %ebx
0x004500b8:	incl %ebx
0x004500b9:	jmp 0x0045000f
0x004500b0:	movl %edi, 0x2(%ebx)
0x004500b3:	pushl %edi
0x004500b4:	addl %ebx, $0x4<UINT8>
0x004500be:	popl %edi
0x004500bf:	movl %ebx, $0x450128<UINT32>
0x004500c4:	incl %edi
0x004500c5:	movl %esi, (%edi)
0x004500c7:	scasl %eax, %es:(%edi)
0x004500c8:	pushl %edi
0x004500c9:	call LoadLibraryA@KERNEL32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004500cb:	xchgl %ebp, %eax
0x004500cc:	xorl %eax, %eax
0x004500ce:	scasb %al, %es:(%edi)
0x004500cf:	jne 0x004500ce
0x004500d1:	decb (%edi)
0x004500d3:	je 0x004500c4
0x004500d5:	decb (%edi)
0x004500d7:	jne 0x004500df
0x004500df:	decb (%edi)
0x004500e1:	je 0x0040b7ee
0x004500e7:	pushl %edi
0x004500e8:	pushl %ebp
0x004500e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x004500ec:	orl (%esi), %eax
0x004500ee:	lodsl %eax, %ds:(%esi)
0x004500ef:	jne 0x004500cc
GetProcAddress@KERNEL32.dll: API Node	
LoadLibraryA@KERNEL32.dll: API Node	
0x0040b7ee:	call 0x00417c70
0x00417c70:	movl %edi, %edi
0x00417c72:	pushl %ebp
0x00417c73:	movl %ebp, %esp
0x00417c75:	subl %esp, $0x10<UINT8>
0x00417c78:	movl %eax, 0x42f180
0x00417c7d:	andl -8(%ebp), $0x0<UINT8>
0x00417c81:	andl -4(%ebp), $0x0<UINT8>
0x00417c85:	pushl %ebx
0x00417c86:	pushl %edi
0x00417c87:	movl %edi, $0xbb40e64e<UINT32>
0x00417c8c:	movl %ebx, $0xffff0000<UINT32>
0x00417c91:	cmpl %eax, %edi
0x00417c93:	je 0x00417ca2
0x00417ca2:	pushl %esi
0x00417ca3:	leal %eax, -8(%ebp)
0x00417ca6:	pushl %eax
0x00417ca7:	call GetSystemTimeAsFileTime@KERNEL32.dll
GetSystemTimeAsFileTime@KERNEL32.dll: API Node	
0x00417cad:	movl %esi, -4(%ebp)
0x00417cb0:	xorl %esi, -8(%ebp)
0x00417cb3:	call GetCurrentProcessId@KERNEL32.dll
GetCurrentProcessId@KERNEL32.dll: API Node	
0x00417cb9:	xorl %esi, %eax
0x00417cbb:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x00417cc1:	xorl %esi, %eax
0x00417cc3:	call GetTickCount@KERNEL32.dll
GetTickCount@KERNEL32.dll: API Node	
0x00417cc9:	xorl %esi, %eax
0x00417ccb:	leal %eax, -16(%ebp)
0x00417cce:	pushl %eax
0x00417ccf:	call QueryPerformanceCounter@KERNEL32.dll
QueryPerformanceCounter@KERNEL32.dll: API Node	
0x00417cd5:	movl %eax, -12(%ebp)
0x00417cd8:	xorl %eax, -16(%ebp)
0x00417cdb:	xorl %esi, %eax
0x00417cdd:	cmpl %esi, %edi
0x00417cdf:	jne 0x00417ce8
0x00417ce8:	testl %ebx, %esi
0x00417cea:	jne 0x00417cf3
0x00417cf3:	movl 0x42f180, %esi
0x00417cf9:	notl %esi
0x00417cfb:	movl 0x42f184, %esi
0x00417d01:	popl %esi
0x00417d02:	popl %edi
0x00417d03:	popl %ebx
0x00417d04:	leave
0x00417d05:	ret

0x0040b7f3:	jmp 0x0040b670
0x0040b670:	pushl $0x58<UINT8>
0x0040b672:	pushl $0x42d5f0<UINT32>
0x0040b677:	call 0x004101f0
0x004101f0:	pushl $0x410280<UINT32>
0x004101f5:	pushl %fs:0
0x004101fc:	movl %eax, 0x10(%esp)
0x00410200:	movl 0x10(%esp), %ebp
0x00410204:	leal %ebp, 0x10(%esp)
0x00410208:	subl %esp, %eax
0x0041020a:	pushl %ebx
0x0041020b:	pushl %esi
0x0041020c:	pushl %edi
0x0041020d:	movl %eax, 0x42f180
0x00410212:	xorl -4(%ebp), %eax
0x00410215:	xorl %eax, %ebp
0x00410217:	pushl %eax
0x00410218:	movl -24(%ebp), %esp
0x0041021b:	pushl -8(%ebp)
0x0041021e:	movl %eax, -4(%ebp)
0x00410221:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00410228:	movl -8(%ebp), %eax
0x0041022b:	leal %eax, -16(%ebp)
0x0041022e:	movl %fs:0, %eax
0x00410234:	ret

0x0040b67c:	xorl %esi, %esi
0x0040b67e:	movl -4(%ebp), %esi
0x0040b681:	leal %eax, -104(%ebp)
0x0040b684:	pushl %eax
0x0040b685:	call GetStartupInfoA@KERNEL32.dll
GetStartupInfoA@KERNEL32.dll: API Node	
0x0040b68b:	pushl $0xfffffffe<UINT8>
0x0040b68d:	popl %edi
0x0040b68e:	movl -4(%ebp), %edi
0x0040b691:	movl %eax, $0x5a4d<UINT32>
0x0040b696:	cmpw 0x400000, %ax
0x0040b69d:	jne 56
0x0040b69f:	movl %eax, 0x40003c
0x0040b6a4:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x0040b6ae:	jne 39
0x0040b6b0:	movl %ecx, $0x10b<UINT32>
0x0040b6b5:	cmpw 0x400018(%eax), %cx
0x0040b6bc:	jne 25
0x0040b6be:	cmpl 0x400074(%eax), $0xe<UINT8>
0x0040b6c5:	jbe 16
0x0040b6c7:	xorl %ecx, %ecx
0x0040b6c9:	cmpl 0x4000e8(%eax), %esi
0x0040b6cf:	setne %cl
0x0040b6d2:	movl -28(%ebp), %ecx
0x0040b6d5:	jmp 0x0040b6da
0x0040b6da:	xorl %ebx, %ebx
0x0040b6dc:	incl %ebx
0x0040b6dd:	pushl %ebx
0x0040b6de:	call 0x0040ef5e
0x0040ef5e:	movl %edi, %edi
0x0040ef60:	pushl %ebp
0x0040ef61:	movl %ebp, %esp
0x0040ef63:	xorl %eax, %eax
0x0040ef65:	cmpl 0x8(%ebp), %eax
0x0040ef68:	pushl $0x0<UINT8>
0x0040ef6a:	sete %al
0x0040ef6d:	pushl $0x1000<UINT32>
0x0040ef72:	pushl %eax
0x0040ef73:	call HeapCreate@KERNEL32.dll
HeapCreate@KERNEL32.dll: API Node	
0x0040ef79:	movl 0x430728, %eax
0x0040ef7e:	testl %eax, %eax
0x0040ef80:	jne 0x0040ef84
0x0040ef84:	xorl %eax, %eax
0x0040ef86:	incl %eax
0x0040ef87:	movl 0x432460, %eax
0x0040ef8c:	popl %ebp
0x0040ef8d:	ret

0x0040b6e3:	popl %ecx
0x0040b6e4:	testl %eax, %eax
0x0040b6e6:	jne 0x0040b6f0
0x0040b6f0:	call 0x0040ece3
0x0040ece3:	movl %edi, %edi
0x0040ece5:	pushl %esi
0x0040ece6:	pushl %edi
0x0040ece7:	movl %esi, $0x42bb74<UINT32>
0x0040ecec:	pushl %esi
0x0040eced:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x0040ecf3:	testl %eax, %eax
0x0040ecf5:	jne 0x0040ecfe
0x0040ecfe:	movl %edi, %eax
0x0040ed00:	testl %edi, %edi
0x0040ed02:	je 350
0x0040ed08:	movl %esi, 0x425124
0x0040ed0e:	pushl $0x42bbc0<UINT32>
0x0040ed13:	pushl %edi
0x0040ed14:	call GetProcAddress@KERNEL32.dll
0x0040ed16:	pushl $0x42bbb4<UINT32>
0x0040ed1b:	pushl %edi
0x0040ed1c:	movl 0x430718, %eax
0x0040ed21:	call GetProcAddress@KERNEL32.dll
0x0040ed23:	pushl $0x42bba8<UINT32>
0x0040ed28:	pushl %edi
0x0040ed29:	movl 0x43071c, %eax
0x0040ed2e:	call GetProcAddress@KERNEL32.dll
0x0040ed30:	pushl $0x42bba0<UINT32>
0x0040ed35:	pushl %edi
0x0040ed36:	movl 0x430720, %eax
0x0040ed3b:	call GetProcAddress@KERNEL32.dll
0x0040ed3d:	cmpl 0x430718, $0x0<UINT8>
0x0040ed44:	movl %esi, 0x4251f4
0x0040ed4a:	movl 0x430724, %eax
0x0040ed4f:	je 22
0x0040ed51:	cmpl 0x43071c, $0x0<UINT8>
0x0040ed58:	je 13
0x0040ed5a:	cmpl 0x430720, $0x0<UINT8>
0x0040ed61:	je 4
0x0040ed63:	testl %eax, %eax
0x0040ed65:	jne 0x0040ed8b
0x0040ed8b:	call TlsAlloc@KERNEL32.dll
TlsAlloc@KERNEL32.dll: API Node	
0x0040ed91:	movl 0x42fd1c, %eax
0x0040ed96:	cmpl %eax, $0xffffffff<UINT8>
0x0040ed99:	je 204
0x0040ed9f:	pushl 0x43071c
0x0040eda5:	pushl %eax
0x0040eda6:	call TlsSetValue@KERNEL32.dll
TlsSetValue@KERNEL32.dll: API Node	
0x0040eda8:	testl %eax, %eax
0x0040edaa:	je 187
0x0040edb0:	call 0x0040b5b2
0x0040b5b2:	movl %edi, %edi
0x0040b5b4:	pushl %esi
0x0040b5b5:	call 0x0040e88e
0x0040e88e:	pushl $0x0<UINT8>
0x0040e890:	call 0x0040e81c
0x0040e81c:	movl %edi, %edi
0x0040e81e:	pushl %ebp
0x0040e81f:	movl %ebp, %esp
0x0040e821:	pushl %esi
0x0040e822:	pushl 0x42fd1c
0x0040e828:	movl %esi, 0x4251ec
0x0040e82e:	call TlsGetValue@KERNEL32.dll
TlsGetValue@KERNEL32.dll: API Node	
0x0040e830:	testl %eax, %eax
0x0040e832:	je 33
0x0040e834:	movl %eax, 0x42fd18
0x0040e839:	cmpl %eax, $0xffffffff<UINT8>
0x0040e83c:	je 0x0040e855
0x0040e855:	movl %esi, $0x42bb74<UINT32>
0x0040e85a:	pushl %esi
0x0040e85b:	call GetModuleHandleW@KERNEL32.dll
0x0040e861:	testl %eax, %eax
0x0040e863:	jne 0x0040e870
0x0040e870:	pushl $0x42bb64<UINT32>
0x0040e875:	pushl %eax
0x0040e876:	call GetProcAddress@KERNEL32.dll
0x0040e87c:	testl %eax, %eax
0x0040e87e:	je 8
0x0040e880:	pushl 0x8(%ebp)
0x0040e883:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x0040e885:	movl 0x8(%ebp), %eax
0x0040e888:	movl %eax, 0x8(%ebp)
0x0040e88b:	popl %esi
0x0040e88c:	popl %ebp
0x0040e88d:	ret

0x0040e895:	popl %ecx
0x0040e896:	ret

0x0040b5ba:	movl %esi, %eax
0x0040b5bc:	pushl %esi
0x0040b5bd:	call 0x00410616
0x00410616:	movl %edi, %edi
0x00410618:	pushl %ebp
0x00410619:	movl %ebp, %esp
0x0041061b:	movl %eax, 0x8(%ebp)
0x0041061e:	movl 0x430b9c, %eax
0x00410623:	popl %ebp
0x00410624:	ret

0x0040b5c2:	pushl %esi
0x0040b5c3:	call 0x004176d9
0x004176d9:	movl %edi, %edi
0x004176db:	pushl %ebp
0x004176dc:	movl %ebp, %esp
0x004176de:	movl %eax, 0x8(%ebp)
0x004176e1:	movl 0x430bd8, %eax
0x004176e6:	popl %ebp
0x004176e7:	ret

0x0040b5c8:	pushl %esi
0x0040b5c9:	call 0x0040bc0d
0x0040bc0d:	movl %edi, %edi
0x0040bc0f:	pushl %ebp
0x0040bc10:	movl %ebp, %esp
0x0040bc12:	movl %eax, 0x8(%ebp)
0x0040bc15:	movl 0x43061c, %eax
0x0040bc1a:	popl %ebp
0x0040bc1b:	ret

0x0040b5ce:	pushl %esi
0x0040b5cf:	call 0x004176ca
0x004176ca:	movl %edi, %edi
0x004176cc:	pushl %ebp
0x004176cd:	movl %ebp, %esp
0x004176cf:	movl %eax, 0x8(%ebp)
0x004176d2:	movl 0x430bd4, %eax
0x004176d7:	popl %ebp
0x004176d8:	ret

0x0040b5d4:	pushl %esi
0x0040b5d5:	call 0x00417434
0x00417434:	movl %edi, %edi
0x00417436:	pushl %ebp
0x00417437:	movl %ebp, %esp
0x00417439:	movl %eax, 0x8(%ebp)
0x0041743c:	movl 0x430bc8, %eax
0x00417441:	popl %ebp
0x00417442:	ret

0x0040b5da:	pushl %esi
0x0040b5db:	call 0x00416f38
0x00416f38:	movl %edi, %edi
0x00416f3a:	pushl %ebp
0x00416f3b:	movl %ebp, %esp
0x00416f3d:	movl %eax, 0x8(%ebp)
0x00416f40:	movl 0x430bb4, %eax
0x00416f45:	movl 0x430bb8, %eax
0x00416f4a:	movl 0x430bbc, %eax
0x00416f4f:	movl 0x430bc0, %eax
0x00416f54:	popl %ebp
0x00416f55:	ret

0x0040b5e0:	pushl %esi
0x0040b5e1:	call 0x00416d82
0x00416d82:	ret

0x0040b5e6:	pushl %esi
0x0040b5e7:	call 0x00416d71
0x00416d71:	pushl $0x416ced<UINT32>
0x00416d76:	call 0x0040e81c
0x00416d7b:	popl %ecx
0x00416d7c:	movl 0x430bb0, %eax
0x00416d81:	ret

0x0040b5ec:	pushl $0x40b57e<UINT32>
0x0040b5f1:	call 0x0040e81c
0x0040b5f6:	addl %esp, $0x24<UINT8>
0x0040b5f9:	movl 0x42f4cc, %eax
0x0040b5fe:	popl %esi
0x0040b5ff:	ret

0x0040edb5:	pushl 0x430718
0x0040edbb:	call 0x0040e81c
0x0040edc0:	pushl 0x43071c
0x0040edc6:	movl 0x430718, %eax
0x0040edcb:	call 0x0040e81c
0x0040edd0:	pushl 0x430720
0x0040edd6:	movl 0x43071c, %eax
0x0040eddb:	call 0x0040e81c
0x0040ede0:	pushl 0x430724
0x0040ede6:	movl 0x430720, %eax
0x0040edeb:	call 0x0040e81c
0x0040edf0:	addl %esp, $0x10<UINT8>
0x0040edf3:	movl 0x430724, %eax
0x0040edf8:	call 0x0040f008
0x0040f008:	movl %edi, %edi
0x0040f00a:	pushl %esi
0x0040f00b:	pushl %edi
0x0040f00c:	xorl %esi, %esi
0x0040f00e:	movl %edi, $0x430730<UINT32>
0x0040f013:	cmpl 0x42fd2c(,%esi,8), $0x1<UINT8>
0x0040f01b:	jne 0x0040f03b
0x0040f01d:	leal %eax, 0x42fd28(,%esi,8)
0x0040f024:	movl (%eax), %edi
0x0040f026:	pushl $0xfa0<UINT32>
0x0040f02b:	pushl (%eax)
0x0040f02d:	addl %edi, $0x18<UINT8>
0x0040f030:	call 0x004176e8
0x004176e8:	pushl $0x10<UINT8>
0x004176ea:	pushl $0x42da60<UINT32>
0x004176ef:	call 0x004101f0
0x004176f4:	andl -4(%ebp), $0x0<UINT8>
0x004176f8:	pushl 0xc(%ebp)
0x004176fb:	pushl 0x8(%ebp)
0x004176fe:	call InitializeCriticalSectionAndSpinCount@KERNEL32.dll
InitializeCriticalSectionAndSpinCount@KERNEL32.dll: API Node	
0x00417704:	movl -28(%ebp), %eax
0x00417707:	jmp 0x00417738
0x00417738:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0041773f:	movl %eax, -28(%ebp)
0x00417742:	call 0x00410235
0x00410235:	movl %ecx, -16(%ebp)
0x00410238:	movl %fs:0, %ecx
0x0041023f:	popl %ecx
0x00410240:	popl %edi
0x00410241:	popl %edi
0x00410242:	popl %esi
0x00410243:	popl %ebx
0x00410244:	movl %esp, %ebp
0x00410246:	popl %ebp
0x00410247:	pushl %ecx
0x00410248:	ret

0x00417747:	ret

0x0040f035:	popl %ecx
0x0040f036:	popl %ecx
0x0040f037:	testl %eax, %eax
0x0040f039:	je 12
0x0040f03b:	incl %esi
0x0040f03c:	cmpl %esi, $0x24<UINT8>
0x0040f03f:	jl 0x0040f013
0x0040f041:	xorl %eax, %eax
0x0040f043:	incl %eax
0x0040f044:	popl %edi
0x0040f045:	popl %esi
0x0040f046:	ret

0x0040edfd:	testl %eax, %eax
0x0040edff:	je 101
0x0040ee01:	pushl $0x40eb3a<UINT32>
0x0040ee06:	pushl 0x430718
0x0040ee0c:	call 0x0040e897
0x0040e897:	movl %edi, %edi
0x0040e899:	pushl %ebp
0x0040e89a:	movl %ebp, %esp
0x0040e89c:	pushl %esi
0x0040e89d:	pushl 0x42fd1c
0x0040e8a3:	movl %esi, 0x4251ec
0x0040e8a9:	call TlsGetValue@KERNEL32.dll
0x0040e8ab:	testl %eax, %eax
0x0040e8ad:	je 33
0x0040e8af:	movl %eax, 0x42fd18
0x0040e8b4:	cmpl %eax, $0xffffffff<UINT8>
0x0040e8b7:	je 0x0040e8d0
0x0040e8d0:	movl %esi, $0x42bb74<UINT32>
0x0040e8d5:	pushl %esi
0x0040e8d6:	call GetModuleHandleW@KERNEL32.dll
0x0040e8dc:	testl %eax, %eax
0x0040e8de:	jne 0x0040e8eb
0x0040e8eb:	pushl $0x42bb90<UINT32>
0x0040e8f0:	pushl %eax
0x0040e8f1:	call GetProcAddress@KERNEL32.dll
0x0040e8f7:	testl %eax, %eax
0x0040e8f9:	je 8
0x0040e8fb:	pushl 0x8(%ebp)
0x0040e8fe:	call DecodePointer@KERNEL32.DLL
DecodePointer@KERNEL32.DLL: API Node	
0x0040e900:	movl 0x8(%ebp), %eax
0x0040e903:	movl %eax, 0x8(%ebp)
0x0040e906:	popl %esi
0x0040e907:	popl %ebp
0x0040e908:	ret

0x0040ee11:	popl %ecx
0x0040ee12:	call FlsAlloc@KERNEL32.DLL
FlsAlloc@KERNEL32.DLL: API Node	
0x0040ee14:	movl 0x42fd18, %eax
0x0040ee19:	cmpl %eax, $0xffffffff<UINT8>
0x0040ee1c:	je 72
0x0040ee1e:	pushl $0x214<UINT32>
0x0040ee23:	pushl $0x1<UINT8>
0x0040ee25:	call 0x00410ea5
0x00410ea5:	movl %edi, %edi
0x00410ea7:	pushl %ebp
0x00410ea8:	movl %ebp, %esp
0x00410eaa:	pushl %esi
0x00410eab:	pushl %edi
0x00410eac:	xorl %esi, %esi
0x00410eae:	pushl $0x0<UINT8>
0x00410eb0:	pushl 0xc(%ebp)
0x00410eb3:	pushl 0x8(%ebp)
0x00410eb6:	call 0x0041da52
0x0041da52:	pushl $0xc<UINT8>
0x0041da54:	pushl $0x42dae0<UINT32>
0x0041da59:	call 0x004101f0
0x0041da5e:	movl %ecx, 0x8(%ebp)
0x0041da61:	xorl %edi, %edi
0x0041da63:	cmpl %ecx, %edi
0x0041da65:	jbe 46
0x0041da67:	pushl $0xffffffe0<UINT8>
0x0041da69:	popl %eax
0x0041da6a:	xorl %edx, %edx
0x0041da6c:	divl %eax, %ecx
0x0041da6e:	cmpl %eax, 0xc(%ebp)
0x0041da71:	sbbl %eax, %eax
0x0041da73:	incl %eax
0x0041da74:	jne 0x0041da95
0x0041da95:	imull %ecx, 0xc(%ebp)
0x0041da99:	movl %esi, %ecx
0x0041da9b:	movl 0x8(%ebp), %esi
0x0041da9e:	cmpl %esi, %edi
0x0041daa0:	jne 0x0041daa5
0x0041daa5:	xorl %ebx, %ebx
0x0041daa7:	movl -28(%ebp), %ebx
0x0041daaa:	cmpl %esi, $0xffffffe0<UINT8>
0x0041daad:	ja 105
0x0041daaf:	cmpl 0x432460, $0x3<UINT8>
0x0041dab6:	jne 0x0041db03
0x0041db03:	cmpl %ebx, %edi
0x0041db05:	jne 97
0x0041db07:	pushl %esi
0x0041db08:	pushl $0x8<UINT8>
0x0041db0a:	pushl 0x430728
0x0041db10:	call HeapAlloc@KERNEL32.dll
HeapAlloc@KERNEL32.dll: API Node	
0x0041db16:	movl %ebx, %eax
0x0041db18:	cmpl %ebx, %edi
0x0041db1a:	jne 0x0041db68
0x0041db68:	movl %eax, %ebx
0x0041db6a:	call 0x00410235
0x0041db6f:	ret

0x00410ebb:	movl %edi, %eax
0x00410ebd:	addl %esp, $0xc<UINT8>
0x00410ec0:	testl %edi, %edi
0x00410ec2:	jne 0x00410eeb
0x00410eeb:	movl %eax, %edi
0x00410eed:	popl %edi
0x00410eee:	popl %esi
0x00410eef:	popl %ebp
0x00410ef0:	ret

0x0040ee2a:	movl %esi, %eax
0x0040ee2c:	popl %ecx
0x0040ee2d:	popl %ecx
0x0040ee2e:	testl %esi, %esi
0x0040ee30:	je 52
0x0040ee32:	pushl %esi
0x0040ee33:	pushl 0x42fd18
0x0040ee39:	pushl 0x430720
0x0040ee3f:	call 0x0040e897
0x0040e8b9:	pushl %eax
0x0040e8ba:	pushl 0x42fd1c
0x0040e8c0:	call TlsGetValue@KERNEL32.dll
0x0040e8c2:	call FlsGetValue@KERNEL32.DLL
FlsGetValue@KERNEL32.DLL: API Node	
0x0040e8c4:	testl %eax, %eax
0x0040e8c6:	je 0x0040e8d0
0x0040ee44:	popl %ecx
0x0040ee45:	call FlsSetValue@KERNEL32.DLL
FlsSetValue@KERNEL32.DLL: API Node	
0x0040ee47:	testl %eax, %eax
0x0040ee49:	je 27
0x0040ee4b:	pushl $0x0<UINT8>
0x0040ee4d:	pushl %esi
0x0040ee4e:	call 0x0040e9c0
0x0040e9c0:	pushl $0xc<UINT8>
0x0040e9c2:	pushl $0x42d7a0<UINT32>
0x0040e9c7:	call 0x004101f0
0x0040e9cc:	movl %esi, $0x42bb74<UINT32>
0x0040e9d1:	pushl %esi
0x0040e9d2:	call GetModuleHandleW@KERNEL32.dll
0x0040e9d8:	testl %eax, %eax
0x0040e9da:	jne 0x0040e9e3
0x0040e9e3:	movl -28(%ebp), %eax
0x0040e9e6:	movl %esi, 0x8(%ebp)
0x0040e9e9:	movl 0x5c(%esi), $0x42c228<UINT32>
0x0040e9f0:	xorl %edi, %edi
0x0040e9f2:	incl %edi
0x0040e9f3:	movl 0x14(%esi), %edi
0x0040e9f6:	testl %eax, %eax
0x0040e9f8:	je 36
0x0040e9fa:	pushl $0x42bb64<UINT32>
0x0040e9ff:	pushl %eax
0x0040ea00:	movl %ebx, 0x425124
0x0040ea06:	call GetProcAddress@KERNEL32.dll
0x0040ea08:	movl 0x1f8(%esi), %eax
0x0040ea0e:	pushl $0x42bb90<UINT32>
0x0040ea13:	pushl -28(%ebp)
0x0040ea16:	call GetProcAddress@KERNEL32.dll
0x0040ea18:	movl 0x1fc(%esi), %eax
0x0040ea1e:	movl 0x70(%esi), %edi
0x0040ea21:	movb 0xc8(%esi), $0x43<UINT8>
0x0040ea28:	movb 0x14b(%esi), $0x43<UINT8>
0x0040ea2f:	movl 0x68(%esi), $0x42f700<UINT32>
0x0040ea36:	pushl $0xd<UINT8>
0x0040ea38:	call 0x0040f19c
0x0040f19c:	movl %edi, %edi
0x0040f19e:	pushl %ebp
0x0040f19f:	movl %ebp, %esp
0x0040f1a1:	movl %eax, 0x8(%ebp)
0x0040f1a4:	pushl %esi
0x0040f1a5:	leal %esi, 0x42fd28(,%eax,8)
0x0040f1ac:	cmpl (%esi), $0x0<UINT8>
0x0040f1af:	jne 0x0040f1c4
0x0040f1c4:	pushl (%esi)
0x0040f1c6:	call EnterCriticalSection@KERNEL32.dll
EnterCriticalSection@KERNEL32.dll: API Node	
0x0040f1cc:	popl %esi
0x0040f1cd:	popl %ebp
0x0040f1ce:	ret

0x0040ea3d:	popl %ecx
0x0040ea3e:	andl -4(%ebp), $0x0<UINT8>
0x0040ea42:	pushl 0x68(%esi)
0x0040ea45:	call InterlockedIncrement@KERNEL32.dll
InterlockedIncrement@KERNEL32.dll: API Node	
0x0040ea4b:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040ea52:	call 0x0040ea95
0x0040ea95:	pushl $0xd<UINT8>
0x0040ea97:	call 0x0040f0aa
0x0040f0aa:	movl %edi, %edi
0x0040f0ac:	pushl %ebp
0x0040f0ad:	movl %ebp, %esp
0x0040f0af:	movl %eax, 0x8(%ebp)
0x0040f0b2:	pushl 0x42fd28(,%eax,8)
0x0040f0b9:	call LeaveCriticalSection@KERNEL32.dll
LeaveCriticalSection@KERNEL32.dll: API Node	
0x0040f0bf:	popl %ebp
0x0040f0c0:	ret

0x0040ea9c:	popl %ecx
0x0040ea9d:	ret

0x0040ea57:	pushl $0xc<UINT8>
0x0040ea59:	call 0x0040f19c
0x0040ea5e:	popl %ecx
0x0040ea5f:	movl -4(%ebp), %edi
0x0040ea62:	movl %eax, 0xc(%ebp)
0x0040ea65:	movl 0x6c(%esi), %eax
0x0040ea68:	testl %eax, %eax
0x0040ea6a:	jne 8
0x0040ea6c:	movl %eax, 0x42fd08
0x0040ea71:	movl 0x6c(%esi), %eax
0x0040ea74:	pushl 0x6c(%esi)
0x0040ea77:	call 0x0040d6ae
0x0040d6ae:	movl %edi, %edi
0x0040d6b0:	pushl %ebp
0x0040d6b1:	movl %ebp, %esp
0x0040d6b3:	pushl %ebx
0x0040d6b4:	pushl %esi
0x0040d6b5:	movl %esi, 0x4251d8
0x0040d6bb:	pushl %edi
0x0040d6bc:	movl %edi, 0x8(%ebp)
0x0040d6bf:	pushl %edi
0x0040d6c0:	call InterlockedIncrement@KERNEL32.dll
0x0040d6c2:	movl %eax, 0xb0(%edi)
0x0040d6c8:	testl %eax, %eax
0x0040d6ca:	je 0x0040d6cf
0x0040d6cf:	movl %eax, 0xb8(%edi)
0x0040d6d5:	testl %eax, %eax
0x0040d6d7:	je 0x0040d6dc
0x0040d6dc:	movl %eax, 0xb4(%edi)
0x0040d6e2:	testl %eax, %eax
0x0040d6e4:	je 0x0040d6e9
0x0040d6e9:	movl %eax, 0xc0(%edi)
0x0040d6ef:	testl %eax, %eax
0x0040d6f1:	je 0x0040d6f6
0x0040d6f6:	leal %ebx, 0x50(%edi)
0x0040d6f9:	movl 0x8(%ebp), $0x6<UINT32>
0x0040d700:	cmpl -8(%ebx), $0x42fc28<UINT32>
0x0040d707:	je 0x0040d712
0x0040d709:	movl %eax, (%ebx)
0x0040d70b:	testl %eax, %eax
0x0040d70d:	je 0x0040d712
0x0040d712:	cmpl -4(%ebx), $0x0<UINT8>
0x0040d716:	je 0x0040d722
0x0040d722:	addl %ebx, $0x10<UINT8>
0x0040d725:	decl 0x8(%ebp)
0x0040d728:	jne 0x0040d700
0x0040d72a:	movl %eax, 0xd4(%edi)
0x0040d730:	addl %eax, $0xb4<UINT32>
0x0040d735:	pushl %eax
0x0040d736:	call InterlockedIncrement@KERNEL32.dll
0x0040d738:	popl %edi
0x0040d739:	popl %esi
0x0040d73a:	popl %ebx
0x0040d73b:	popl %ebp
0x0040d73c:	ret

0x0040ea7c:	popl %ecx
0x0040ea7d:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040ea84:	call 0x0040ea9e
0x0040ea9e:	pushl $0xc<UINT8>
0x0040eaa0:	call 0x0040f0aa
0x0040eaa5:	popl %ecx
0x0040eaa6:	ret

0x0040ea89:	call 0x00410235
0x0040ea8e:	ret

0x0040ee53:	popl %ecx
0x0040ee54:	popl %ecx
0x0040ee55:	call GetCurrentThreadId@KERNEL32.dll
0x0040ee5b:	orl 0x4(%esi), $0xffffffff<UINT8>
0x0040ee5f:	movl (%esi), %eax
0x0040ee61:	xorl %eax, %eax
0x0040ee63:	incl %eax
0x0040ee64:	jmp 0x0040ee6d
0x0040ee6d:	popl %edi
0x0040ee6e:	popl %esi
0x0040ee6f:	ret

0x0040b6f5:	testl %eax, %eax
0x0040b6f7:	jne 0x0040b701
0x0040b701:	call 0x00416b2f
0x00416b2f:	movl %edi, %edi
0x00416b31:	pushl %esi
0x00416b32:	movl %eax, $0x42d460<UINT32>
0x00416b37:	movl %esi, $0x42d460<UINT32>
0x00416b3c:	pushl %edi
0x00416b3d:	movl %edi, %eax
0x00416b3f:	cmpl %eax, %esi
0x00416b41:	jae 0x00416b52
0x00416b52:	popl %edi
0x00416b53:	popl %esi
0x00416b54:	ret

0x0040b706:	movl -4(%ebp), %ebx
0x0040b709:	call 0x0041187b
0x0041187b:	pushl $0x54<UINT8>
0x0041187d:	pushl $0x42d878<UINT32>
0x00411882:	call 0x004101f0
0x00411887:	xorl %edi, %edi
0x00411889:	movl -4(%ebp), %edi
0x0041188c:	leal %eax, -100(%ebp)
0x0041188f:	pushl %eax
0x00411890:	call GetStartupInfoA@KERNEL32.dll
0x00411896:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0041189d:	pushl $0x40<UINT8>
0x0041189f:	pushl $0x20<UINT8>
0x004118a1:	popl %esi
0x004118a2:	pushl %esi
0x004118a3:	call 0x00410ea5
0x004118a8:	popl %ecx
0x004118a9:	popl %ecx
0x004118aa:	cmpl %eax, %edi
0x004118ac:	je 532
0x004118b2:	movl 0x432340, %eax
0x004118b7:	movl 0x432338, %esi
0x004118bd:	leal %ecx, 0x800(%eax)
0x004118c3:	jmp 0x004118f5
0x004118f5:	cmpl %eax, %ecx
0x004118f7:	jb 0x004118c5
0x004118c5:	movb 0x4(%eax), $0x0<UINT8>
0x004118c9:	orl (%eax), $0xffffffff<UINT8>
0x004118cc:	movb 0x5(%eax), $0xa<UINT8>
0x004118d0:	movl 0x8(%eax), %edi
0x004118d3:	movb 0x24(%eax), $0x0<UINT8>
0x004118d7:	movb 0x25(%eax), $0xa<UINT8>
0x004118db:	movb 0x26(%eax), $0xa<UINT8>
0x004118df:	movl 0x38(%eax), %edi
0x004118e2:	movb 0x34(%eax), $0x0<UINT8>
0x004118e6:	addl %eax, $0x40<UINT8>
0x004118e9:	movl %ecx, 0x432340
0x004118ef:	addl %ecx, $0x800<UINT32>
0x004118f9:	cmpw -50(%ebp), %di
0x004118fd:	je 266
0x00411903:	movl %eax, -48(%ebp)
0x00411906:	cmpl %eax, %edi
0x00411908:	je 255
0x0041190e:	movl %edi, (%eax)
0x00411910:	leal %ebx, 0x4(%eax)
0x00411913:	leal %eax, (%ebx,%edi)
0x00411916:	movl -28(%ebp), %eax
0x00411919:	movl %esi, $0x800<UINT32>
0x0041191e:	cmpl %edi, %esi
0x00411920:	jl 0x00411924
0x00411924:	movl -32(%ebp), $0x1<UINT32>
0x0041192b:	jmp 0x00411988
0x00411988:	cmpl 0x432338, %edi
0x0041198e:	jl -99
0x00411990:	jmp 0x00411998
0x00411998:	andl -32(%ebp), $0x0<UINT8>
0x0041199c:	testl %edi, %edi
0x0041199e:	jle 0x00411a0d
0x00411a0d:	xorl %ebx, %ebx
0x00411a0f:	movl %esi, %ebx
0x00411a11:	shll %esi, $0x6<UINT8>
0x00411a14:	addl %esi, 0x432340
0x00411a1a:	movl %eax, (%esi)
0x00411a1c:	cmpl %eax, $0xffffffff<UINT8>
0x00411a1f:	je 0x00411a2c
0x00411a2c:	movb 0x4(%esi), $0xffffff81<UINT8>
0x00411a30:	testl %ebx, %ebx
0x00411a32:	jne 0x00411a39
0x00411a34:	pushl $0xfffffff6<UINT8>
0x00411a36:	popl %eax
0x00411a37:	jmp 0x00411a43
0x00411a43:	pushl %eax
0x00411a44:	call GetStdHandle@KERNEL32.dll
GetStdHandle@KERNEL32.dll: API Node	
0x00411a4a:	movl %edi, %eax
0x00411a4c:	cmpl %edi, $0xffffffff<UINT8>
0x00411a4f:	je 67
0x00411a51:	testl %edi, %edi
0x00411a53:	je 63
0x00411a55:	pushl %edi
0x00411a56:	call GetFileType@KERNEL32.dll
GetFileType@KERNEL32.dll: API Node	
0x00411a5c:	testl %eax, %eax
0x00411a5e:	je 52
0x00411a60:	movl (%esi), %edi
0x00411a62:	andl %eax, $0xff<UINT32>
0x00411a67:	cmpl %eax, $0x2<UINT8>
0x00411a6a:	jne 6
0x00411a6c:	orb 0x4(%esi), $0x40<UINT8>
0x00411a70:	jmp 0x00411a7b
0x00411a7b:	pushl $0xfa0<UINT32>
0x00411a80:	leal %eax, 0xc(%esi)
0x00411a83:	pushl %eax
0x00411a84:	call 0x004176e8
0x00411a89:	popl %ecx
0x00411a8a:	popl %ecx
0x00411a8b:	testl %eax, %eax
0x00411a8d:	je 55
0x00411a8f:	incl 0x8(%esi)
0x00411a92:	jmp 0x00411a9e
0x00411a9e:	incl %ebx
0x00411a9f:	cmpl %ebx, $0x3<UINT8>
0x00411aa2:	jl 0x00411a0f
0x00411a39:	movl %eax, %ebx
0x00411a3b:	decl %eax
0x00411a3c:	negl %eax
0x00411a3e:	sbbl %eax, %eax
0x00411a40:	addl %eax, $0xfffffff5<UINT8>
0x00411aa8:	pushl 0x432338
0x00411aae:	call SetHandleCount@KERNEL32.dll
SetHandleCount@KERNEL32.dll: API Node	
0x00411ab4:	xorl %eax, %eax
0x00411ab6:	jmp 0x00411ac9
0x00411ac9:	call 0x00410235
0x00411ace:	ret

0x0040b70e:	testl %eax, %eax
0x0040b710:	jnl 0x0040b71a
0x0040b71a:	call GetCommandLineA@KERNEL32.dll
GetCommandLineA@KERNEL32.dll: API Node	
0x0040b720:	movl 0x432470, %eax
0x0040b725:	call 0x00417b39
0x00417b39:	movl %edi, %edi
0x00417b3b:	pushl %ebp
0x00417b3c:	movl %ebp, %esp
0x00417b3e:	movl %eax, 0x430ce8
0x00417b43:	subl %esp, $0xc<UINT8>
0x00417b46:	pushl %ebx
0x00417b47:	pushl %esi
0x00417b48:	movl %esi, 0x4250f4
0x00417b4e:	pushl %edi
0x00417b4f:	xorl %ebx, %ebx
0x00417b51:	xorl %edi, %edi
0x00417b53:	cmpl %eax, %ebx
0x00417b55:	jne 46
0x00417b57:	call GetEnvironmentStringsW@KERNEL32.dll
GetEnvironmentStringsW@KERNEL32.dll: API Node	
0x00417b59:	movl %edi, %eax
0x00417b5b:	cmpl %edi, %ebx
0x00417b5d:	je 12
0x00417b5f:	movl 0x430ce8, $0x1<UINT32>
0x00417b69:	jmp 0x00417b8e
0x00417b8e:	cmpl %edi, %ebx
0x00417b90:	jne 0x00417ba1
0x00417ba1:	movl %eax, %edi
0x00417ba3:	cmpw (%edi), %bx
0x00417ba6:	je 14
0x00417ba8:	incl %eax
0x00417ba9:	incl %eax
0x00417baa:	cmpw (%eax), %bx
0x00417bad:	jne 0x00417ba8
0x00417baf:	incl %eax
0x00417bb0:	incl %eax
0x00417bb1:	cmpw (%eax), %bx
0x00417bb4:	jne 0x00417ba8
0x00417bb6:	movl %esi, 0x4251cc
0x00417bbc:	pushl %ebx
0x00417bbd:	pushl %ebx
0x00417bbe:	pushl %ebx
0x00417bbf:	subl %eax, %edi
0x00417bc1:	pushl %ebx
0x00417bc2:	sarl %eax
0x00417bc4:	incl %eax
0x00417bc5:	pushl %eax
0x00417bc6:	pushl %edi
0x00417bc7:	pushl %ebx
0x00417bc8:	pushl %ebx
0x00417bc9:	movl -12(%ebp), %eax
0x00417bcc:	call WideCharToMultiByte@KERNEL32.dll
WideCharToMultiByte@KERNEL32.dll: API Node	
0x00417bce:	movl -8(%ebp), %eax
0x00417bd1:	cmpl %eax, %ebx
0x00417bd3:	je 47
0x00417bd5:	pushl %eax
0x00417bd6:	call 0x00410e60
0x00410e60:	movl %edi, %edi
0x00410e62:	pushl %ebp
0x00410e63:	movl %ebp, %esp
0x00410e65:	pushl %esi
0x00410e66:	pushl %edi
0x00410e67:	xorl %esi, %esi
0x00410e69:	pushl 0x8(%ebp)
0x00410e6c:	call 0x00407fb7
0x00407fb7:	movl %edi, %edi
0x00407fb9:	pushl %ebp
0x00407fba:	movl %ebp, %esp
0x00407fbc:	pushl %esi
0x00407fbd:	movl %esi, 0x8(%ebp)
0x00407fc0:	cmpl %esi, $0xffffffe0<UINT8>
0x00407fc3:	ja 161
0x00407fc9:	pushl %ebx
0x00407fca:	pushl %edi
0x00407fcb:	movl %edi, 0x42517c
0x00407fd1:	cmpl 0x430728, $0x0<UINT8>
0x00407fd8:	jne 0x00407ff2
0x00407ff2:	movl %eax, 0x432460
0x00407ff7:	cmpl %eax, $0x1<UINT8>
0x00407ffa:	jne 14
0x00407ffc:	testl %esi, %esi
0x00407ffe:	je 4
0x00408000:	movl %eax, %esi
0x00408002:	jmp 0x00408007
0x00408007:	pushl %eax
0x00408008:	jmp 0x00408026
0x00408026:	pushl $0x0<UINT8>
0x00408028:	pushl 0x430728
0x0040802e:	call HeapAlloc@KERNEL32.dll
0x00408030:	movl %ebx, %eax
0x00408032:	testl %ebx, %ebx
0x00408034:	jne 0x00408064
0x00408064:	popl %edi
0x00408065:	movl %eax, %ebx
0x00408067:	popl %ebx
0x00408068:	jmp 0x0040807e
0x0040807e:	popl %esi
0x0040807f:	popl %ebp
0x00408080:	ret

0x00410e71:	movl %edi, %eax
0x00410e73:	popl %ecx
0x00410e74:	testl %edi, %edi
0x00410e76:	jne 0x00410e9f
0x00410e9f:	movl %eax, %edi
0x00410ea1:	popl %edi
0x00410ea2:	popl %esi
0x00410ea3:	popl %ebp
0x00410ea4:	ret

0x00417bdb:	popl %ecx
0x00417bdc:	movl -4(%ebp), %eax
0x00417bdf:	cmpl %eax, %ebx
0x00417be1:	je 33
0x00417be3:	pushl %ebx
0x00417be4:	pushl %ebx
0x00417be5:	pushl -8(%ebp)
0x00417be8:	pushl %eax
0x00417be9:	pushl -12(%ebp)
0x00417bec:	pushl %edi
0x00417bed:	pushl %ebx
0x00417bee:	pushl %ebx
0x00417bef:	call WideCharToMultiByte@KERNEL32.dll
0x00417bf1:	testl %eax, %eax
0x00417bf3:	jne 0x00417c01
0x00417c01:	movl %ebx, -4(%ebp)
0x00417c04:	pushl %edi
0x00417c05:	call FreeEnvironmentStringsW@KERNEL32.dll
FreeEnvironmentStringsW@KERNEL32.dll: API Node	
0x00417c0b:	movl %eax, %ebx
0x00417c0d:	jmp 0x00417c6b
0x00417c6b:	popl %edi
0x00417c6c:	popl %esi
0x00417c6d:	popl %ebx
0x00417c6e:	leave
0x00417c6f:	ret

0x0040b72a:	movl 0x4302ec, %eax
0x0040b72f:	call 0x00417a7e
0x00417a7e:	movl %edi, %edi
0x00417a80:	pushl %ebp
0x00417a81:	movl %ebp, %esp
0x00417a83:	subl %esp, $0xc<UINT8>
0x00417a86:	pushl %ebx
0x00417a87:	xorl %ebx, %ebx
0x00417a89:	pushl %esi
0x00417a8a:	pushl %edi
0x00417a8b:	cmpl 0x432480, %ebx
0x00417a91:	jne 5
0x00417a93:	call 0x0040d53b
0x0040d53b:	cmpl 0x432480, $0x0<UINT8>
0x0040d542:	jne 18
0x0040d544:	pushl $0xfffffffd<UINT8>
0x0040d546:	call 0x0040d3a1
0x0040d3a1:	pushl $0x14<UINT8>
0x0040d3a3:	pushl $0x42d6d8<UINT32>
0x0040d3a8:	call 0x004101f0
0x0040d3ad:	orl -32(%ebp), $0xffffffff<UINT8>
0x0040d3b1:	call 0x0040eb20
0x0040eb20:	movl %edi, %edi
0x0040eb22:	pushl %esi
0x0040eb23:	call 0x0040eaa7
0x0040eaa7:	movl %edi, %edi
0x0040eaa9:	pushl %esi
0x0040eaaa:	pushl %edi
0x0040eaab:	call GetLastError@KERNEL32.dll
GetLastError@KERNEL32.dll: API Node	
0x0040eab1:	pushl 0x42fd18
0x0040eab7:	movl %edi, %eax
0x0040eab9:	call 0x0040e932
0x0040e932:	movl %edi, %edi
0x0040e934:	pushl %esi
0x0040e935:	pushl 0x42fd1c
0x0040e93b:	call TlsGetValue@KERNEL32.dll
0x0040e941:	movl %esi, %eax
0x0040e943:	testl %esi, %esi
0x0040e945:	jne 0x0040e962
0x0040e962:	movl %eax, %esi
0x0040e964:	popl %esi
0x0040e965:	ret

0x0040eabe:	call FlsGetValue@KERNEL32.DLL
0x0040eac0:	movl %esi, %eax
0x0040eac2:	testl %esi, %esi
0x0040eac4:	jne 0x0040eb14
0x0040eb14:	pushl %edi
0x0040eb15:	call SetLastError@KERNEL32.dll
SetLastError@KERNEL32.dll: API Node	
0x0040eb1b:	popl %edi
0x0040eb1c:	movl %eax, %esi
0x0040eb1e:	popl %esi
0x0040eb1f:	ret

0x0040eb28:	movl %esi, %eax
0x0040eb2a:	testl %esi, %esi
0x0040eb2c:	jne 0x0040eb36
0x0040eb36:	movl %eax, %esi
0x0040eb38:	popl %esi
0x0040eb39:	ret

0x0040d3b6:	movl %edi, %eax
0x0040d3b8:	movl -36(%ebp), %edi
0x0040d3bb:	call 0x0040d05e
0x0040d05e:	pushl $0xc<UINT8>
0x0040d060:	pushl $0x42d6b8<UINT32>
0x0040d065:	call 0x004101f0
0x0040d06a:	call 0x0040eb20
0x0040d06f:	movl %edi, %eax
0x0040d071:	movl %eax, 0x42fc24
0x0040d076:	testl 0x70(%edi), %eax
0x0040d079:	je 0x0040d098
0x0040d098:	pushl $0xd<UINT8>
0x0040d09a:	call 0x0040f19c
0x0040d09f:	popl %ecx
0x0040d0a0:	andl -4(%ebp), $0x0<UINT8>
0x0040d0a4:	movl %esi, 0x68(%edi)
0x0040d0a7:	movl -28(%ebp), %esi
0x0040d0aa:	cmpl %esi, 0x42fb28
0x0040d0b0:	je 0x0040d0e8
0x0040d0e8:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040d0ef:	call 0x0040d0f9
0x0040d0f9:	pushl $0xd<UINT8>
0x0040d0fb:	call 0x0040f0aa
0x0040d100:	popl %ecx
0x0040d101:	ret

0x0040d0f4:	jmp 0x0040d084
0x0040d084:	testl %esi, %esi
0x0040d086:	jne 0x0040d090
0x0040d090:	movl %eax, %esi
0x0040d092:	call 0x00410235
0x0040d097:	ret

0x0040d3c0:	movl %ebx, 0x68(%edi)
0x0040d3c3:	movl %esi, 0x8(%ebp)
0x0040d3c6:	call 0x0040d102
0x0040d102:	movl %edi, %edi
0x0040d104:	pushl %ebp
0x0040d105:	movl %ebp, %esp
0x0040d107:	subl %esp, $0x10<UINT8>
0x0040d10a:	pushl %ebx
0x0040d10b:	xorl %ebx, %ebx
0x0040d10d:	pushl %ebx
0x0040d10e:	leal %ecx, -16(%ebp)
0x0040d111:	call 0x00407b08
0x00407b08:	movl %edi, %edi
0x00407b0a:	pushl %ebp
0x00407b0b:	movl %ebp, %esp
0x00407b0d:	movl %eax, 0x8(%ebp)
0x00407b10:	pushl %esi
0x00407b11:	movl %esi, %ecx
0x00407b13:	movb 0xc(%esi), $0x0<UINT8>
0x00407b17:	testl %eax, %eax
0x00407b19:	jne 99
0x00407b1b:	call 0x0040eb20
0x00407b20:	movl 0x8(%esi), %eax
0x00407b23:	movl %ecx, 0x6c(%eax)
0x00407b26:	movl (%esi), %ecx
0x00407b28:	movl %ecx, 0x68(%eax)
0x00407b2b:	movl 0x4(%esi), %ecx
0x00407b2e:	movl %ecx, (%esi)
0x00407b30:	cmpl %ecx, 0x42fd08
0x00407b36:	je 0x00407b4a
0x00407b4a:	movl %eax, 0x4(%esi)
0x00407b4d:	cmpl %eax, 0x42fb28
0x00407b53:	je 0x00407b6b
0x00407b6b:	movl %eax, 0x8(%esi)
0x00407b6e:	testb 0x70(%eax), $0x2<UINT8>
0x00407b72:	jne 20
0x00407b74:	orl 0x70(%eax), $0x2<UINT8>
0x00407b78:	movb 0xc(%esi), $0x1<UINT8>
0x00407b7c:	jmp 0x00407b88
0x00407b88:	movl %eax, %esi
0x00407b8a:	popl %esi
0x00407b8b:	popl %ebp
0x00407b8c:	ret $0x4<UINT16>

0x0040d116:	movl 0x4306d8, %ebx
0x0040d11c:	cmpl %esi, $0xfffffffe<UINT8>
0x0040d11f:	jne 0x0040d13f
0x0040d13f:	cmpl %esi, $0xfffffffd<UINT8>
0x0040d142:	jne 0x0040d156
0x0040d144:	movl 0x4306d8, $0x1<UINT32>
0x0040d14e:	call GetACP@KERNEL32.dll
GetACP@KERNEL32.dll: API Node	
0x0040d154:	jmp 0x0040d131
0x0040d131:	cmpb -4(%ebp), %bl
0x0040d134:	je 69
0x0040d136:	movl %ecx, -8(%ebp)
0x0040d139:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0040d13d:	jmp 0x0040d17b
0x0040d17b:	popl %ebx
0x0040d17c:	leave
0x0040d17d:	ret

0x0040d3cb:	movl 0x8(%ebp), %eax
0x0040d3ce:	cmpl %eax, 0x4(%ebx)
0x0040d3d1:	je 343
0x0040d3d7:	pushl $0x220<UINT32>
0x0040d3dc:	call 0x00410e60
0x0040d3e1:	popl %ecx
0x0040d3e2:	movl %ebx, %eax
0x0040d3e4:	testl %ebx, %ebx
0x0040d3e6:	je 326
0x0040d3ec:	movl %ecx, $0x88<UINT32>
0x0040d3f1:	movl %esi, 0x68(%edi)
0x0040d3f4:	movl %edi, %ebx
0x0040d3f6:	rep movsl %es:(%edi), %ds:(%esi)
0x0040d3f8:	andl (%ebx), $0x0<UINT8>
0x0040d3fb:	pushl %ebx
0x0040d3fc:	pushl 0x8(%ebp)
0x0040d3ff:	call 0x0040d17e
0x0040d17e:	movl %edi, %edi
0x0040d180:	pushl %ebp
0x0040d181:	movl %ebp, %esp
0x0040d183:	subl %esp, $0x20<UINT8>
0x0040d186:	movl %eax, 0x42f180
0x0040d18b:	xorl %eax, %ebp
0x0040d18d:	movl -4(%ebp), %eax
0x0040d190:	pushl %ebx
0x0040d191:	movl %ebx, 0xc(%ebp)
0x0040d194:	pushl %esi
0x0040d195:	movl %esi, 0x8(%ebp)
0x0040d198:	pushl %edi
0x0040d199:	call 0x0040d102
0x0040d156:	cmpl %esi, $0xfffffffc<UINT8>
0x0040d159:	jne 0x0040d16d
0x0040d16d:	cmpb -4(%ebp), %bl
0x0040d170:	je 7
0x0040d172:	movl %eax, -8(%ebp)
0x0040d175:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x0040d179:	movl %eax, %esi
0x0040d19e:	movl %edi, %eax
0x0040d1a0:	xorl %esi, %esi
0x0040d1a2:	movl 0x8(%ebp), %edi
0x0040d1a5:	cmpl %edi, %esi
0x0040d1a7:	jne 0x0040d1b7
0x0040d1b7:	movl -28(%ebp), %esi
0x0040d1ba:	xorl %eax, %eax
0x0040d1bc:	cmpl 0x42fb30(%eax), %edi
0x0040d1c2:	je 145
0x0040d1c8:	incl -28(%ebp)
0x0040d1cb:	addl %eax, $0x30<UINT8>
0x0040d1ce:	cmpl %eax, $0xf0<UINT32>
0x0040d1d3:	jb 0x0040d1bc
0x0040d1d5:	cmpl %edi, $0xfde8<UINT32>
0x0040d1db:	je 368
0x0040d1e1:	cmpl %edi, $0xfde9<UINT32>
0x0040d1e7:	je 356
0x0040d1ed:	movzwl %eax, %di
0x0040d1f0:	pushl %eax
0x0040d1f1:	call IsValidCodePage@KERNEL32.dll
IsValidCodePage@KERNEL32.dll: API Node	
0x0040d1f7:	testl %eax, %eax
0x0040d1f9:	je 338
0x0040d1ff:	leal %eax, -24(%ebp)
0x0040d202:	pushl %eax
0x0040d203:	pushl %edi
0x0040d204:	call GetCPInfo@KERNEL32.dll
GetCPInfo@KERNEL32.dll: API Node	
0x0040d20a:	testl %eax, %eax
0x0040d20c:	je 307
0x0040d212:	pushl $0x101<UINT32>
0x0040d217:	leal %eax, 0x1c(%ebx)
0x0040d21a:	pushl %esi
0x0040d21b:	pushl %eax
0x0040d21c:	call 0x004075f0
0x004075f0:	movl %edx, 0xc(%esp)
0x004075f4:	movl %ecx, 0x4(%esp)
0x004075f8:	testl %edx, %edx
0x004075fa:	je 105
0x004075fc:	xorl %eax, %eax
0x004075fe:	movb %al, 0x8(%esp)
0x00407602:	testb %al, %al
0x00407604:	jne 22
0x00407606:	cmpl %edx, $0x100<UINT32>
0x0040760c:	jb 14
0x0040760e:	cmpl 0x43246c, $0x0<UINT8>
0x00407615:	je 0x0040761c
0x0040761c:	pushl %edi
0x0040761d:	movl %edi, %ecx
0x0040761f:	cmpl %edx, $0x4<UINT8>
0x00407622:	jb 49
0x00407624:	negl %ecx
0x00407626:	andl %ecx, $0x3<UINT8>
0x00407629:	je 0x00407637
0x00407637:	movl %ecx, %eax
0x00407639:	shll %eax, $0x8<UINT8>
0x0040763c:	addl %eax, %ecx
0x0040763e:	movl %ecx, %eax
0x00407640:	shll %eax, $0x10<UINT8>
0x00407643:	addl %eax, %ecx
0x00407645:	movl %ecx, %edx
0x00407647:	andl %edx, $0x3<UINT8>
0x0040764a:	shrl %ecx, $0x2<UINT8>
0x0040764d:	je 6
0x0040764f:	rep stosl %es:(%edi), %eax
0x00407651:	testl %edx, %edx
0x00407653:	je 10
0x00407655:	movb (%edi), %al
0x00407657:	addl %edi, $0x1<UINT8>
0x0040765a:	subl %edx, $0x1<UINT8>
0x0040765d:	jne -10
0x0040765f:	movl %eax, 0x8(%esp)
0x00407663:	popl %edi
0x00407664:	ret

0x0040d221:	xorl %edx, %edx
0x0040d223:	incl %edx
0x0040d224:	addl %esp, $0xc<UINT8>
0x0040d227:	movl 0x4(%ebx), %edi
0x0040d22a:	movl 0xc(%ebx), %esi
0x0040d22d:	cmpl -24(%ebp), %edx
0x0040d230:	jbe 248
0x0040d236:	cmpb -18(%ebp), $0x0<UINT8>
0x0040d23a:	je 0x0040d30f
0x0040d30f:	leal %eax, 0x1e(%ebx)
0x0040d312:	movl %ecx, $0xfe<UINT32>
0x0040d317:	orb (%eax), $0x8<UINT8>
0x0040d31a:	incl %eax
0x0040d31b:	decl %ecx
0x0040d31c:	jne 0x0040d317
0x0040d31e:	movl %eax, 0x4(%ebx)
0x0040d321:	call 0x0040ce38
0x0040ce38:	subl %eax, $0x3a4<UINT32>
0x0040ce3d:	je 34
0x0040ce3f:	subl %eax, $0x4<UINT8>
0x0040ce42:	je 23
0x0040ce44:	subl %eax, $0xd<UINT8>
0x0040ce47:	je 12
0x0040ce49:	decl %eax
0x0040ce4a:	je 3
0x0040ce4c:	xorl %eax, %eax
0x0040ce4e:	ret

0x0040d326:	movl 0xc(%ebx), %eax
0x0040d329:	movl 0x8(%ebx), %edx
0x0040d32c:	jmp 0x0040d331
0x0040d331:	xorl %eax, %eax
0x0040d333:	movzwl %ecx, %ax
0x0040d336:	movl %eax, %ecx
0x0040d338:	shll %ecx, $0x10<UINT8>
0x0040d33b:	orl %eax, %ecx
0x0040d33d:	leal %edi, 0x10(%ebx)
0x0040d340:	stosl %es:(%edi), %eax
0x0040d341:	stosl %es:(%edi), %eax
0x0040d342:	stosl %es:(%edi), %eax
0x0040d343:	jmp 0x0040d2ed
0x0040d2ed:	movl %esi, %ebx
0x0040d2ef:	call 0x0040cecb
0x0040cecb:	movl %edi, %edi
0x0040cecd:	pushl %ebp
0x0040cece:	movl %ebp, %esp
0x0040ced0:	subl %esp, $0x51c<UINT32>
0x0040ced6:	movl %eax, 0x42f180
0x0040cedb:	xorl %eax, %ebp
0x0040cedd:	movl -4(%ebp), %eax
0x0040cee0:	pushl %ebx
0x0040cee1:	pushl %edi
0x0040cee2:	leal %eax, -1304(%ebp)
0x0040cee8:	pushl %eax
0x0040cee9:	pushl 0x4(%esi)
0x0040ceec:	call GetCPInfo@KERNEL32.dll
0x0040cef2:	movl %edi, $0x100<UINT32>
0x0040cef7:	testl %eax, %eax
0x0040cef9:	je 251
0x0040ceff:	xorl %eax, %eax
0x0040cf01:	movb -260(%ebp,%eax), %al
0x0040cf08:	incl %eax
0x0040cf09:	cmpl %eax, %edi
0x0040cf0b:	jb 0x0040cf01
0x0040cf0d:	movb %al, -1298(%ebp)
0x0040cf13:	movb -260(%ebp), $0x20<UINT8>
0x0040cf1a:	testb %al, %al
0x0040cf1c:	je 0x0040cf4c
0x0040cf4c:	pushl $0x0<UINT8>
0x0040cf4e:	pushl 0xc(%esi)
0x0040cf51:	leal %eax, -1284(%ebp)
0x0040cf57:	pushl 0x4(%esi)
0x0040cf5a:	pushl %eax
0x0040cf5b:	pushl %edi
0x0040cf5c:	leal %eax, -260(%ebp)
0x0040cf62:	pushl %eax
0x0040cf63:	pushl $0x1<UINT8>
0x0040cf65:	pushl $0x0<UINT8>
0x0040cf67:	call 0x00418d26
0x00418d26:	movl %edi, %edi
0x00418d28:	pushl %ebp
0x00418d29:	movl %ebp, %esp
0x00418d2b:	subl %esp, $0x10<UINT8>
0x00418d2e:	pushl 0x8(%ebp)
0x00418d31:	leal %ecx, -16(%ebp)
0x00418d34:	call 0x00407b08
0x00418d39:	pushl 0x24(%ebp)
0x00418d3c:	leal %ecx, -16(%ebp)
0x00418d3f:	pushl 0x20(%ebp)
0x00418d42:	pushl 0x1c(%ebp)
0x00418d45:	pushl 0x18(%ebp)
0x00418d48:	pushl 0x14(%ebp)
0x00418d4b:	pushl 0x10(%ebp)
0x00418d4e:	pushl 0xc(%ebp)
0x00418d51:	call 0x00418b6c
0x00418b6c:	movl %edi, %edi
0x00418b6e:	pushl %ebp
0x00418b6f:	movl %ebp, %esp
0x00418b71:	pushl %ecx
0x00418b72:	pushl %ecx
0x00418b73:	movl %eax, 0x42f180
0x00418b78:	xorl %eax, %ebp
0x00418b7a:	movl -4(%ebp), %eax
0x00418b7d:	movl %eax, 0x430cf0
0x00418b82:	pushl %ebx
0x00418b83:	pushl %esi
0x00418b84:	xorl %ebx, %ebx
0x00418b86:	pushl %edi
0x00418b87:	movl %edi, %ecx
0x00418b89:	cmpl %eax, %ebx
0x00418b8b:	jne 58
0x00418b8d:	leal %eax, -8(%ebp)
0x00418b90:	pushl %eax
0x00418b91:	xorl %esi, %esi
0x00418b93:	incl %esi
0x00418b94:	pushl %esi
0x00418b95:	pushl $0x42c2c4<UINT32>
0x00418b9a:	pushl %esi
0x00418b9b:	call GetStringTypeW@KERNEL32.dll
GetStringTypeW@KERNEL32.dll: API Node	
0x00418ba1:	testl %eax, %eax
0x00418ba3:	je 8
0x00418ba5:	movl 0x430cf0, %esi
0x00418bab:	jmp 0x00418be1
0x00418be1:	movl -8(%ebp), %ebx
0x00418be4:	cmpl 0x18(%ebp), %ebx
0x00418be7:	jne 0x00418bf1
0x00418bf1:	movl %esi, 0x42511c
0x00418bf7:	xorl %eax, %eax
0x00418bf9:	cmpl 0x20(%ebp), %ebx
0x00418bfc:	pushl %ebx
0x00418bfd:	pushl %ebx
0x00418bfe:	pushl 0x10(%ebp)
0x00418c01:	setne %al
0x00418c04:	pushl 0xc(%ebp)
0x00418c07:	leal %eax, 0x1(,%eax,8)
0x00418c0e:	pushl %eax
0x00418c0f:	pushl 0x18(%ebp)
0x00418c12:	call MultiByteToWideChar@KERNEL32.dll
MultiByteToWideChar@KERNEL32.dll: API Node	
0x00418c14:	movl %edi, %eax
0x00418c16:	cmpl %edi, %ebx
0x00418c18:	je 171
0x00418c1e:	jle 60
0x00418c20:	cmpl %edi, $0x7ffffff0<UINT32>
0x00418c26:	ja 52
0x00418c28:	leal %eax, 0x8(%edi,%edi)
0x00418c2c:	cmpl %eax, $0x400<UINT32>
0x00418c31:	ja 19
0x00418c33:	call 0x00408a10
0x00408a10:	pushl %ecx
0x00408a11:	leal %ecx, 0x8(%esp)
0x00408a15:	subl %ecx, %eax
0x00408a17:	andl %ecx, $0xf<UINT8>
0x00408a1a:	addl %eax, %ecx
0x00408a1c:	sbbl %ecx, %ecx
0x00408a1e:	orl %eax, %ecx
0x00408a20:	popl %ecx
0x00408a21:	jmp 0x00408d40
0x00408d40:	pushl %ecx
0x00408d41:	leal %ecx, 0x4(%esp)
0x00408d45:	subl %ecx, %eax
0x00408d47:	sbbl %eax, %eax
0x00408d49:	notl %eax
0x00408d4b:	andl %ecx, %eax
0x00408d4d:	movl %eax, %esp
0x00408d4f:	andl %eax, $0xfffff000<UINT32>
0x00408d54:	cmpl %ecx, %eax
0x00408d56:	jb 10
0x00408d58:	movl %eax, %ecx
0x00408d5a:	popl %ecx
0x00408d5b:	xchgl %esp, %eax
0x00408d5c:	movl %eax, (%eax)
0x00408d5e:	movl (%esp), %eax
0x00408d61:	ret

0x00418c38:	movl %eax, %esp
0x00418c3a:	cmpl %eax, %ebx
0x00418c3c:	je 28
0x00418c3e:	movl (%eax), $0xcccc<UINT32>
0x00418c44:	jmp 0x00418c57
0x00418c57:	addl %eax, $0x8<UINT8>
0x00418c5a:	movl %ebx, %eax
0x00418c5c:	testl %ebx, %ebx
0x00418c5e:	je 105
0x00418c60:	leal %eax, (%edi,%edi)
0x00418c63:	pushl %eax
0x00418c64:	pushl $0x0<UINT8>
0x00418c66:	pushl %ebx
0x00418c67:	call 0x004075f0