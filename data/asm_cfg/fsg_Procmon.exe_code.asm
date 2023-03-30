0x00798000:	movl %ebx, $0x4001d0<UINT32>
0x00798005:	movl %edi, $0x401000<UINT32>
0x0079800a:	movl %esi, $0x743ad8<UINT32>
0x0079800f:	pushl %ebx
0x00798010:	call 0x0079801f
0x0079801f:	cld
0x00798020:	movb %dl, $0xffffff80<UINT8>
0x00798022:	movsb %es:(%edi), %ds:(%esi)
0x00798023:	pushl $0x2<UINT8>
0x00798025:	popl %ebx
0x00798026:	call 0x00798015
0x00798015:	addb %dl, %dl
0x00798017:	jne 0x0079801e
0x00798019:	movb %dl, (%esi)
0x0079801b:	incl %esi
0x0079801c:	adcb %dl, %dl
0x0079801e:	ret

0x00798029:	jae 0x00798022
0x0079802b:	xorl %ecx, %ecx
0x0079802d:	call 0x00798015
0x00798030:	jae 0x0079804a
0x00798032:	xorl %eax, %eax
0x00798034:	call 0x00798015
0x00798037:	jae 0x0079805a
0x00798039:	movb %bl, $0x2<UINT8>
0x0079803b:	incl %ecx
0x0079803c:	movb %al, $0x10<UINT8>
0x0079803e:	call 0x00798015
0x00798041:	adcb %al, %al
0x00798043:	jae 0x0079803e
0x00798045:	jne 0x00798086
0x00798086:	pushl %esi
0x00798087:	movl %esi, %edi
0x00798089:	subl %esi, %eax
0x0079808b:	rep movsb %es:(%edi), %ds:(%esi)
0x0079808d:	popl %esi
0x0079808e:	jmp 0x00798026
0x0079805a:	lodsb %al, %ds:(%esi)
0x0079805b:	shrl %eax
0x0079805d:	je 0x007980a0
0x0079805f:	adcl %ecx, %ecx
0x00798061:	jmp 0x0079807f
0x0079807f:	incl %ecx
0x00798080:	incl %ecx
0x00798081:	xchgl %ebp, %eax
0x00798082:	movl %eax, %ebp
0x00798084:	movb %bl, $0x1<UINT8>
0x00798047:	stosb %es:(%edi), %al
0x00798048:	jmp 0x00798026
0x0079804a:	call 0x00798092
0x00798092:	incl %ecx
0x00798093:	call 0x00798015
0x00798097:	adcl %ecx, %ecx
0x00798099:	call 0x00798015
0x0079809d:	jb 0x00798093
0x0079809f:	ret

0x0079804f:	subl %ecx, %ebx
0x00798051:	jne 0x00798063
0x00798063:	xchgl %ecx, %eax
0x00798064:	decl %eax
0x00798065:	shll %eax, $0x8<UINT8>
0x00798068:	lodsb %al, %ds:(%esi)
0x00798069:	call 0x00798090
0x00798090:	xorl %ecx, %ecx
0x0079806e:	cmpl %eax, $0x7d00<UINT32>
0x00798073:	jae 0x0079807f
0x00798075:	cmpb %ah, $0x5<UINT8>
0x00798078:	jae 0x00798080
0x0079807a:	cmpl %eax, $0x7f<UINT8>
0x0079807d:	ja 0x00798081
0x00798053:	call 0x00798090
0x00798058:	jmp 0x00798082
0x007980a0:	popl %edi
0x007980a1:	popl %ebx
0x007980a2:	movzwl %edi, (%ebx)
0x007980a5:	decl %edi
0x007980a6:	je 0x007980b0
0x007980a8:	decl %edi
0x007980a9:	je 0x007980be
0x007980ab:	shll %edi, $0xc<UINT8>
0x007980ae:	jmp 0x007980b7
0x007980b7:	incl %ebx
0x007980b8:	incl %ebx
0x007980b9:	jmp 0x0079800f
0x007980b0:	movl %edi, 0x2(%ebx)
0x007980b3:	pushl %edi
0x007980b4:	addl %ebx, $0x4<UINT8>
0x007980be:	popl %edi
0x007980bf:	movl %ebx, $0x798128<UINT32>
0x007980c4:	incl %edi
0x007980c5:	movl %esi, (%edi)
0x007980c7:	scasl %eax, %es:(%edi)
0x007980c8:	pushl %edi
0x007980c9:	call LoadLibraryA@KERNEL32.dll
LoadLibraryA@kernel32.dll: API Node	
0x007980cb:	xchgl %ebp, %eax
0x007980cc:	xorl %eax, %eax
0x007980ce:	scasb %al, %es:(%edi)
0x007980cf:	jne 0x007980ce
0x007980d1:	decb (%edi)
0x007980d3:	je 0x007980c4
0x007980d5:	decb (%edi)
0x007980d7:	jne 0x007980df
0x007980d9:	incl %edi
0x007980da:	pushl (%edi)
0x007980dc:	scasl %eax, %es:(%edi)
0x007980dd:	jmp 0x007980e8
0x007980e8:	pushl %ebp
0x007980e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x007980ec:	orl (%esi), %eax
0x007980ee:	lodsl %eax, %ds:(%esi)
0x007980ef:	jne 0x007980cc
0x007980df:	decb (%edi)
0x007980e1:	je 0x004755cb
0x007980e7:	pushl %edi
GetProcAddress@KERNEL32.dll: API Node	
LoadLibraryA@KERNEL32.dll: API Node	
0x004755cb:	call 0x00480584
0x00480584:	pushl %ebp
0x00480585:	movl %ebp, %esp
0x00480587:	subl %esp, $0x14<UINT8>
0x0048058a:	andl -12(%ebp), $0x0<UINT8>
0x0048058e:	andl -8(%ebp), $0x0<UINT8>
0x00480592:	movl %eax, 0x4bc1dc
0x00480597:	pushl %esi
0x00480598:	pushl %edi
0x00480599:	movl %edi, $0xbb40e64e<UINT32>
0x0048059e:	movl %esi, $0xffff0000<UINT32>
0x004805a3:	cmpl %eax, %edi
0x004805a5:	je 0x004805b4
0x004805b4:	leal %eax, -12(%ebp)
0x004805b7:	pushl %eax
0x004805b8:	call GetSystemTimeAsFileTime@KERNEL32.dll
GetSystemTimeAsFileTime@KERNEL32.dll: API Node	
0x004805be:	movl %eax, -8(%ebp)
0x004805c1:	xorl %eax, -12(%ebp)
0x004805c4:	movl -4(%ebp), %eax
0x004805c7:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x004805cd:	xorl -4(%ebp), %eax
0x004805d0:	call GetCurrentProcessId@KERNEL32.dll
GetCurrentProcessId@KERNEL32.dll: API Node	
0x004805d6:	xorl -4(%ebp), %eax
0x004805d9:	leal %eax, -20(%ebp)
0x004805dc:	pushl %eax
0x004805dd:	call QueryPerformanceCounter@KERNEL32.dll
QueryPerformanceCounter@KERNEL32.dll: API Node	
0x004805e3:	movl %ecx, -16(%ebp)
0x004805e6:	leal %eax, -4(%ebp)
0x004805e9:	xorl %ecx, -20(%ebp)
0x004805ec:	xorl %ecx, -4(%ebp)
0x004805ef:	xorl %ecx, %eax
0x004805f1:	cmpl %ecx, %edi
0x004805f3:	jne 0x004805fc
0x004805fc:	testl %esi, %ecx
0x004805fe:	jne 0x0048060c
0x0048060c:	movl 0x4bc1dc, %ecx
0x00480612:	notl %ecx
0x00480614:	movl 0x4bc1e0, %ecx
0x0048061a:	popl %edi
0x0048061b:	popl %esi
0x0048061c:	movl %esp, %ebp
0x0048061e:	popl %ebp
0x0048061f:	ret

0x004755d0:	jmp 0x00475454
0x00475454:	pushl $0x14<UINT8>
0x00475456:	pushl $0x4b9278<UINT32>
0x0047545b:	call 0x004795f0
0x004795f0:	pushl $0x4752c0<UINT32>
0x004795f5:	pushl %fs:0
0x004795fc:	movl %eax, 0x10(%esp)
0x00479600:	movl 0x10(%esp), %ebp
0x00479604:	leal %ebp, 0x10(%esp)
0x00479608:	subl %esp, %eax
0x0047960a:	pushl %ebx
0x0047960b:	pushl %esi
0x0047960c:	pushl %edi
0x0047960d:	movl %eax, 0x4bc1dc
0x00479612:	xorl -4(%ebp), %eax
0x00479615:	xorl %eax, %ebp
0x00479617:	pushl %eax
0x00479618:	movl -24(%ebp), %esp
0x0047961b:	pushl -8(%ebp)
0x0047961e:	movl %eax, -4(%ebp)
0x00479621:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00479628:	movl -8(%ebp), %eax
0x0047962b:	leal %eax, -16(%ebp)
0x0047962e:	movl %fs:0, %eax
0x00479634:	ret

0x00475460:	call 0x00479a5a
0x00479a5a:	pushl %ebp
0x00479a5b:	movl %ebp, %esp
0x00479a5d:	subl %esp, $0x44<UINT8>
0x00479a60:	leal %eax, -68(%ebp)
0x00479a63:	pushl %eax
0x00479a64:	call GetStartupInfoW@KERNEL32.dll
GetStartupInfoW@KERNEL32.dll: API Node	
0x00479a6a:	testb -24(%ebp), $0x1<UINT8>
0x00479a6e:	je 0x00479a76
0x00479a76:	pushl $0xa<UINT8>
0x00479a78:	popl %eax
0x00479a79:	movl %esp, %ebp
0x00479a7b:	popl %ebp
0x00479a7c:	ret

0x00475465:	movzwl %esi, %ax
0x00475468:	pushl $0x2<UINT8>
0x0047546a:	call 0x00480537
0x00480537:	pushl %ebp
0x00480538:	movl %ebp, %esp
0x0048053a:	movl %eax, 0x8(%ebp)
0x0048053d:	movl 0x4c3cd8, %eax
0x00480542:	popl %ebp
0x00480543:	ret

0x0047546f:	popl %ecx
0x00475470:	movl %eax, $0x5a4d<UINT32>
0x00475475:	cmpw 0x400000, %ax
0x0047547c:	je 0x00475482
0x00475482:	movl %eax, 0x40003c
0x00475487:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00475491:	jne -21
0x00475493:	movl %ecx, $0x10b<UINT32>
0x00475498:	cmpw 0x400018(%eax), %cx
0x0047549f:	jne -35
0x004754a1:	xorl %ebx, %ebx
0x004754a3:	cmpl 0x400074(%eax), $0xe<UINT8>
0x004754aa:	jbe 9
0x004754ac:	cmpl 0x4000e8(%eax), %ebx
0x004754b2:	setne %bl
0x004754b5:	movl -28(%ebp), %ebx
0x004754b8:	call 0x0047a442
0x0047a442:	call GetProcessHeap@KERNEL32.dll
GetProcessHeap@KERNEL32.dll: API Node	
0x0047a448:	xorl %ecx, %ecx
0x0047a44a:	movl 0x4c4328, %eax
0x0047a44f:	testl %eax, %eax
0x0047a451:	setne %cl
0x0047a454:	movl %eax, %ecx
0x0047a456:	ret

0x004754bd:	testl %eax, %eax
0x004754bf:	jne 0x004754c9
0x004754c9:	call 0x00476a2e
0x00476a2e:	call 0x00471927
0x00471927:	pushl %esi
0x00471928:	pushl $0x0<UINT8>
0x0047192a:	call EncodePointer@KERNEL32.dll
EncodePointer@KERNEL32.dll: API Node	
0x00471930:	movl %esi, %eax
0x00471932:	pushl %esi
0x00471933:	call 0x00473397
0x00473397:	pushl %ebp
0x00473398:	movl %ebp, %esp
0x0047339a:	movl %eax, 0x8(%ebp)
0x0047339d:	movl 0x4c3804, %eax
0x004733a2:	popl %ebp
0x004733a3:	ret

0x00471938:	pushl %esi
0x00471939:	call 0x00475a14
0x00475a14:	pushl %ebp
0x00475a15:	movl %ebp, %esp
0x00475a17:	movl %eax, 0x8(%ebp)
0x00475a1a:	movl 0x4c3b40, %eax
0x00475a1f:	popl %ebp
0x00475a20:	ret

0x0047193e:	pushl %esi
0x0047193f:	call 0x00479487
0x00479487:	pushl %ebp
0x00479488:	movl %ebp, %esp
0x0047948a:	movl %eax, 0x8(%ebp)
0x0047948d:	movl 0x4c3b74, %eax
0x00479492:	popl %ebp
0x00479493:	ret

0x00471944:	pushl %esi
0x00471945:	call 0x0047a14d
0x0047a14d:	pushl %ebp
0x0047a14e:	movl %ebp, %esp
0x0047a150:	movl %eax, 0x8(%ebp)
0x0047a153:	movl 0x4c4308, %eax
0x0047a158:	movl 0x4c430c, %eax
0x0047a15d:	movl 0x4c4310, %eax
0x0047a162:	movl 0x4c4314, %eax
0x0047a167:	popl %ebp
0x0047a168:	ret

0x0047194a:	pushl %esi
0x0047194b:	call 0x0047864b
0x0047864b:	pushl $0x478604<UINT32>
0x00478650:	call EncodePointer@KERNEL32.dll
0x00478656:	movl 0x4c3b6c, %eax
0x0047865b:	ret

0x00471950:	pushl %esi
0x00471951:	call 0x0047a35e
0x0047a35e:	pushl %ebp
0x0047a35f:	movl %ebp, %esp
0x0047a361:	movl %eax, 0x8(%ebp)
0x0047a364:	movl 0x4c431c, %eax
0x0047a369:	popl %ebp
0x0047a36a:	ret

0x00471956:	addl %esp, $0x18<UINT8>
0x00471959:	popl %esi
0x0047195a:	jmp 0x00479aeb
0x00479aeb:	pushl %esi
0x00479aec:	pushl %edi
0x00479aed:	pushl $0x49d59c<UINT32>
0x00479af2:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x00479af8:	movl %esi, 0x490358
0x00479afe:	movl %edi, %eax
0x00479b00:	pushl $0x4ac1f0<UINT32>
0x00479b05:	pushl %edi
0x00479b06:	call GetProcAddress@KERNEL32.dll
0x00479b08:	xorl %eax, 0x4bc1dc
0x00479b0e:	pushl $0x4ac1fc<UINT32>
0x00479b13:	pushl %edi
0x00479b14:	movl 0x4c56e0, %eax
0x00479b19:	call GetProcAddress@KERNEL32.dll
0x00479b1b:	xorl %eax, 0x4bc1dc
0x00479b21:	pushl $0x4ac204<UINT32>
0x00479b26:	pushl %edi
0x00479b27:	movl 0x4c56e4, %eax
0x00479b2c:	call GetProcAddress@KERNEL32.dll
0x00479b2e:	xorl %eax, 0x4bc1dc
0x00479b34:	pushl $0x4ac210<UINT32>
0x00479b39:	pushl %edi
0x00479b3a:	movl 0x4c56e8, %eax
0x00479b3f:	call GetProcAddress@KERNEL32.dll
0x00479b41:	xorl %eax, 0x4bc1dc
0x00479b47:	pushl $0x4ac21c<UINT32>
0x00479b4c:	pushl %edi
0x00479b4d:	movl 0x4c56ec, %eax
0x00479b52:	call GetProcAddress@KERNEL32.dll
0x00479b54:	xorl %eax, 0x4bc1dc
0x00479b5a:	pushl $0x4ac238<UINT32>
0x00479b5f:	pushl %edi
0x00479b60:	movl 0x4c56f0, %eax
0x00479b65:	call GetProcAddress@KERNEL32.dll
0x00479b67:	xorl %eax, 0x4bc1dc
0x00479b6d:	pushl $0x4ac248<UINT32>
0x00479b72:	pushl %edi
0x00479b73:	movl 0x4c56f4, %eax
0x00479b78:	call GetProcAddress@KERNEL32.dll
0x00479b7a:	xorl %eax, 0x4bc1dc
0x00479b80:	pushl $0x4ac25c<UINT32>
0x00479b85:	pushl %edi
0x00479b86:	movl 0x4c56f8, %eax
0x00479b8b:	call GetProcAddress@KERNEL32.dll
0x00479b8d:	xorl %eax, 0x4bc1dc
0x00479b93:	pushl $0x4ac274<UINT32>
0x00479b98:	pushl %edi
0x00479b99:	movl 0x4c56fc, %eax
0x00479b9e:	call GetProcAddress@KERNEL32.dll
0x00479ba0:	xorl %eax, 0x4bc1dc
0x00479ba6:	pushl $0x4ac28c<UINT32>
0x00479bab:	pushl %edi
0x00479bac:	movl 0x4c5700, %eax
0x00479bb1:	call GetProcAddress@KERNEL32.dll
0x00479bb3:	xorl %eax, 0x4bc1dc
0x00479bb9:	pushl $0x4ac2a0<UINT32>
0x00479bbe:	pushl %edi
0x00479bbf:	movl 0x4c5704, %eax
0x00479bc4:	call GetProcAddress@KERNEL32.dll
0x00479bc6:	xorl %eax, 0x4bc1dc
0x00479bcc:	pushl $0x4ac2c0<UINT32>
0x00479bd1:	pushl %edi
0x00479bd2:	movl 0x4c5708, %eax
0x00479bd7:	call GetProcAddress@KERNEL32.dll
0x00479bd9:	xorl %eax, 0x4bc1dc
0x00479bdf:	pushl $0x4ac2d8<UINT32>
0x00479be4:	pushl %edi
0x00479be5:	movl 0x4c570c, %eax
0x00479bea:	call GetProcAddress@KERNEL32.dll
0x00479bec:	xorl %eax, 0x4bc1dc
0x00479bf2:	pushl $0x4ac2f0<UINT32>
0x00479bf7:	pushl %edi
0x00479bf8:	movl 0x4c5710, %eax
0x00479bfd:	call GetProcAddress@KERNEL32.dll
0x00479bff:	xorl %eax, 0x4bc1dc
0x00479c05:	pushl $0x4ac304<UINT32>
0x00479c0a:	pushl %edi
0x00479c0b:	movl 0x4c5714, %eax
0x00479c10:	call GetProcAddress@KERNEL32.dll
0x00479c12:	xorl %eax, 0x4bc1dc
0x00479c18:	movl 0x4c5718, %eax
0x00479c1d:	pushl $0x4ac318<UINT32>
0x00479c22:	pushl %edi
0x00479c23:	call GetProcAddress@KERNEL32.dll
0x00479c25:	xorl %eax, 0x4bc1dc
0x00479c2b:	pushl $0x4ac334<UINT32>
0x00479c30:	pushl %edi
0x00479c31:	movl 0x4c571c, %eax
0x00479c36:	call GetProcAddress@KERNEL32.dll
0x00479c38:	xorl %eax, 0x4bc1dc
0x00479c3e:	pushl $0x4ac354<UINT32>
0x00479c43:	pushl %edi
0x00479c44:	movl 0x4c5720, %eax
0x00479c49:	call GetProcAddress@KERNEL32.dll
0x00479c4b:	xorl %eax, 0x4bc1dc
0x00479c51:	pushl $0x4ac370<UINT32>
0x00479c56:	pushl %edi
0x00479c57:	movl 0x4c5724, %eax
0x00479c5c:	call GetProcAddress@KERNEL32.dll
0x00479c5e:	xorl %eax, 0x4bc1dc
0x00479c64:	pushl $0x4ac390<UINT32>
0x00479c69:	pushl %edi
0x00479c6a:	movl 0x4c5728, %eax
0x00479c6f:	call GetProcAddress@KERNEL32.dll
0x00479c71:	xorl %eax, 0x4bc1dc
0x00479c77:	pushl $0x4ac3a4<UINT32>
0x00479c7c:	pushl %edi
0x00479c7d:	movl 0x4c572c, %eax
0x00479c82:	call GetProcAddress@KERNEL32.dll
0x00479c84:	xorl %eax, 0x4bc1dc
0x00479c8a:	pushl $0x4ac3c0<UINT32>
0x00479c8f:	pushl %edi
0x00479c90:	movl 0x4c5730, %eax
0x00479c95:	call GetProcAddress@KERNEL32.dll
0x00479c97:	xorl %eax, 0x4bc1dc
0x00479c9d:	pushl $0x4ac3d4<UINT32>
0x00479ca2:	pushl %edi
0x00479ca3:	movl 0x4c5738, %eax
0x00479ca8:	call GetProcAddress@KERNEL32.dll
0x00479caa:	xorl %eax, 0x4bc1dc
0x00479cb0:	pushl $0x4ac3e4<UINT32>
0x00479cb5:	pushl %edi
0x00479cb6:	movl 0x4c5734, %eax
0x00479cbb:	call GetProcAddress@KERNEL32.dll
0x00479cbd:	xorl %eax, 0x4bc1dc
0x00479cc3:	pushl $0x4ac3f4<UINT32>
0x00479cc8:	pushl %edi
0x00479cc9:	movl 0x4c573c, %eax
0x00479cce:	call GetProcAddress@KERNEL32.dll
0x00479cd0:	xorl %eax, 0x4bc1dc
0x00479cd6:	pushl $0x4ac404<UINT32>
0x00479cdb:	pushl %edi
0x00479cdc:	movl 0x4c5740, %eax
0x00479ce1:	call GetProcAddress@KERNEL32.dll
0x00479ce3:	xorl %eax, 0x4bc1dc
0x00479ce9:	pushl $0x4ac414<UINT32>
0x00479cee:	pushl %edi
0x00479cef:	movl 0x4c5744, %eax
0x00479cf4:	call GetProcAddress@KERNEL32.dll
0x00479cf6:	xorl %eax, 0x4bc1dc
0x00479cfc:	pushl $0x4ac430<UINT32>
0x00479d01:	pushl %edi
0x00479d02:	movl 0x4c5748, %eax
0x00479d07:	call GetProcAddress@KERNEL32.dll
0x00479d09:	xorl %eax, 0x4bc1dc
0x00479d0f:	pushl $0x4ac444<UINT32>
0x00479d14:	pushl %edi
0x00479d15:	movl 0x4c574c, %eax
0x00479d1a:	call GetProcAddress@KERNEL32.dll
0x00479d1c:	xorl %eax, 0x4bc1dc
0x00479d22:	pushl $0x4ac454<UINT32>
0x00479d27:	pushl %edi
0x00479d28:	movl 0x4c5750, %eax
0x00479d2d:	call GetProcAddress@KERNEL32.dll
0x00479d2f:	xorl %eax, 0x4bc1dc
0x00479d35:	pushl $0x4ac468<UINT32>
0x00479d3a:	pushl %edi
0x00479d3b:	movl 0x4c5754, %eax
0x00479d40:	call GetProcAddress@KERNEL32.dll
0x00479d42:	xorl %eax, 0x4bc1dc
0x00479d48:	movl 0x4c5758, %eax
0x00479d4d:	pushl $0x4ac478<UINT32>
0x00479d52:	pushl %edi
0x00479d53:	call GetProcAddress@KERNEL32.dll
0x00479d55:	xorl %eax, 0x4bc1dc
0x00479d5b:	pushl $0x4ac498<UINT32>
0x00479d60:	pushl %edi
0x00479d61:	movl 0x4c575c, %eax
0x00479d66:	call GetProcAddress@KERNEL32.dll
0x00479d68:	xorl %eax, 0x4bc1dc
0x00479d6e:	popl %edi
0x00479d6f:	movl 0x4c5760, %eax
0x00479d74:	popl %esi
0x00479d75:	ret

0x00476a33:	call 0x0047998e
0x0047998e:	pushl %esi
0x0047998f:	pushl %edi
0x00479990:	movl %esi, $0x4bcb00<UINT32>
0x00479995:	movl %edi, $0x4c3b88<UINT32>
0x0047999a:	cmpl 0x4(%esi), $0x1<UINT8>
0x0047999e:	jne 22
0x004799a0:	pushl $0x0<UINT8>
0x004799a2:	movl (%esi), %edi
0x004799a4:	addl %edi, $0x18<UINT8>
0x004799a7:	pushl $0xfa0<UINT32>
0x004799ac:	pushl (%esi)
0x004799ae:	call 0x00479a7d
0x00479a7d:	pushl %ebp
0x00479a7e:	movl %ebp, %esp
0x00479a80:	movl %eax, 0x4c56f0
0x00479a85:	xorl %eax, 0x4bc1dc
0x00479a8b:	je 13
0x00479a8d:	pushl 0x10(%ebp)
0x00479a90:	pushl 0xc(%ebp)
0x00479a93:	pushl 0x8(%ebp)
0x00479a96:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x00479a98:	popl %ebp
0x00479a99:	ret

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
