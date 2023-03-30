0x0073d000:	movl %ebx, $0x4001d0<UINT32>
0x0073d005:	movl %edi, $0x401000<UINT32>
0x0073d00a:	movl %esi, $0x60701d<UINT32>
0x0073d00f:	pushl %ebx
0x0073d010:	call 0x0073d01f
0x0073d01f:	cld
0x0073d020:	movb %dl, $0xffffff80<UINT8>
0x0073d022:	movsb %es:(%edi), %ds:(%esi)
0x0073d023:	pushl $0x2<UINT8>
0x0073d025:	popl %ebx
0x0073d026:	call 0x0073d015
0x0073d015:	addb %dl, %dl
0x0073d017:	jne 0x0073d01e
0x0073d019:	movb %dl, (%esi)
0x0073d01b:	incl %esi
0x0073d01c:	adcb %dl, %dl
0x0073d01e:	ret

0x0073d029:	jae 0x0073d022
0x0073d02b:	xorl %ecx, %ecx
0x0073d02d:	call 0x0073d015
0x0073d030:	jae 0x0073d04a
0x0073d032:	xorl %eax, %eax
0x0073d034:	call 0x0073d015
0x0073d037:	jae 0x0073d05a
0x0073d039:	movb %bl, $0x2<UINT8>
0x0073d03b:	incl %ecx
0x0073d03c:	movb %al, $0x10<UINT8>
0x0073d03e:	call 0x0073d015
0x0073d041:	adcb %al, %al
0x0073d043:	jae 0x0073d03e
0x0073d045:	jne 0x0073d086
0x0073d047:	stosb %es:(%edi), %al
0x0073d048:	jmp 0x0073d026
0x0073d05a:	lodsb %al, %ds:(%esi)
0x0073d05b:	shrl %eax
0x0073d05d:	je 0x0073d0a0
0x0073d05f:	adcl %ecx, %ecx
0x0073d061:	jmp 0x0073d07f
0x0073d07f:	incl %ecx
0x0073d080:	incl %ecx
0x0073d081:	xchgl %ebp, %eax
0x0073d082:	movl %eax, %ebp
0x0073d084:	movb %bl, $0x1<UINT8>
0x0073d086:	pushl %esi
0x0073d087:	movl %esi, %edi
0x0073d089:	subl %esi, %eax
0x0073d08b:	rep movsb %es:(%edi), %ds:(%esi)
0x0073d08d:	popl %esi
0x0073d08e:	jmp 0x0073d026
0x0073d04a:	call 0x0073d092
0x0073d092:	incl %ecx
0x0073d093:	call 0x0073d015
0x0073d097:	adcl %ecx, %ecx
0x0073d099:	call 0x0073d015
0x0073d09d:	jb 0x0073d093
0x0073d09f:	ret

0x0073d04f:	subl %ecx, %ebx
0x0073d051:	jne 0x0073d063
0x0073d053:	call 0x0073d090
0x0073d090:	xorl %ecx, %ecx
0x0073d058:	jmp 0x0073d082
0x0073d063:	xchgl %ecx, %eax
0x0073d064:	decl %eax
0x0073d065:	shll %eax, $0x8<UINT8>
0x0073d068:	lodsb %al, %ds:(%esi)
0x0073d069:	call 0x0073d090
0x0073d06e:	cmpl %eax, $0x7d00<UINT32>
0x0073d073:	jae 0x0073d07f
0x0073d075:	cmpb %ah, $0x5<UINT8>
0x0073d078:	jae 0x0073d080
0x0073d07a:	cmpl %eax, $0x7f<UINT8>
0x0073d07d:	ja 0x0073d081
0x0073d0a0:	popl %edi
0x0073d0a1:	popl %ebx
0x0073d0a2:	movzwl %edi, (%ebx)
0x0073d0a5:	decl %edi
0x0073d0a6:	je 0x0073d0b0
0x0073d0a8:	decl %edi
0x0073d0a9:	je 0x0073d0be
0x0073d0ab:	shll %edi, $0xc<UINT8>
0x0073d0ae:	jmp 0x0073d0b7
0x0073d0b7:	incl %ebx
0x0073d0b8:	incl %ebx
0x0073d0b9:	jmp 0x0073d00f
0x0073d0b0:	movl %edi, 0x2(%ebx)
0x0073d0b3:	pushl %edi
0x0073d0b4:	addl %ebx, $0x4<UINT8>
0x0073d0be:	popl %edi
0x0073d0bf:	movl %ebx, $0x73d128<UINT32>
0x0073d0c4:	incl %edi
0x0073d0c5:	movl %esi, (%edi)
0x0073d0c7:	scasl %eax, %es:(%edi)
0x0073d0c8:	pushl %edi
0x0073d0c9:	call LoadLibraryA@KERNEL32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0073d0cb:	xchgl %ebp, %eax
0x0073d0cc:	xorl %eax, %eax
0x0073d0ce:	scasb %al, %es:(%edi)
0x0073d0cf:	jne 0x0073d0ce
0x0073d0d1:	decb (%edi)
0x0073d0d3:	je 0x0073d0c4
0x0073d0d5:	decb (%edi)
0x0073d0d7:	jne 0x0073d0df
0x0073d0d9:	incl %edi
0x0073d0da:	pushl (%edi)
0x0073d0dc:	scasl %eax, %es:(%edi)
0x0073d0dd:	jmp 0x0073d0e8
0x0073d0e8:	pushl %ebp
0x0073d0e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x0073d0ec:	orl (%esi), %eax
0x0073d0ee:	lodsl %eax, %ds:(%esi)
0x0073d0ef:	jne 0x0073d0cc
0x0073d0df:	decb (%edi)
0x0073d0e1:	je 0x0042800a
0x0073d0e7:	pushl %edi
GetProcAddress@KERNEL32.dll: API Node	
LoadLibraryA@KERNEL32.dll: API Node	
0x0042800a:	call 0x004350d7
0x004350d7:	pushl %ebp
0x004350d8:	movl %ebp, %esp
0x004350da:	subl %esp, $0x14<UINT8>
0x004350dd:	andl -12(%ebp), $0x0<UINT8>
0x004350e1:	andl -8(%ebp), $0x0<UINT8>
0x004350e5:	movl %eax, 0x4bfd50
0x004350ea:	pushl %esi
0x004350eb:	pushl %edi
0x004350ec:	movl %edi, $0xbb40e64e<UINT32>
0x004350f1:	movl %esi, $0xffff0000<UINT32>
0x004350f6:	cmpl %eax, %edi
0x004350f8:	je 0x00435107
0x00435107:	leal %eax, -12(%ebp)
0x0043510a:	pushl %eax
0x0043510b:	call GetSystemTimeAsFileTime@KERNEL32.dll
GetSystemTimeAsFileTime@KERNEL32.dll: API Node	
0x00435111:	movl %eax, -8(%ebp)
0x00435114:	xorl %eax, -12(%ebp)
0x00435117:	movl -4(%ebp), %eax
0x0043511a:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x00435120:	xorl -4(%ebp), %eax
0x00435123:	call GetCurrentProcessId@KERNEL32.dll
GetCurrentProcessId@KERNEL32.dll: API Node	
0x00435129:	xorl -4(%ebp), %eax
0x0043512c:	leal %eax, -20(%ebp)
0x0043512f:	pushl %eax
0x00435130:	call QueryPerformanceCounter@KERNEL32.dll
QueryPerformanceCounter@KERNEL32.dll: API Node	
0x00435136:	movl %ecx, -16(%ebp)
0x00435139:	leal %eax, -4(%ebp)
0x0043513c:	xorl %ecx, -20(%ebp)
0x0043513f:	xorl %ecx, -4(%ebp)
0x00435142:	xorl %ecx, %eax
0x00435144:	cmpl %ecx, %edi
0x00435146:	jne 0x0043514f
0x0043514f:	testl %esi, %ecx
0x00435151:	jne 0x0043515f
0x0043515f:	movl 0x4bfd50, %ecx
0x00435165:	notl %ecx
0x00435167:	movl 0x4bfd54, %ecx
0x0043516d:	popl %edi
0x0043516e:	popl %esi
0x0043516f:	movl %esp, %ebp
0x00435171:	popl %ebp
0x00435172:	ret

0x0042800f:	jmp 0x00427e93
0x00427e93:	pushl $0x14<UINT8>
0x00427e95:	pushl $0x4bbd38<UINT32>
0x00427e9a:	call 0x00428b40
0x00428b40:	pushl $0x428ba0<UINT32>
0x00428b45:	pushl %fs:0
0x00428b4c:	movl %eax, 0x10(%esp)
0x00428b50:	movl 0x10(%esp), %ebp
0x00428b54:	leal %ebp, 0x10(%esp)
0x00428b58:	subl %esp, %eax
0x00428b5a:	pushl %ebx
0x00428b5b:	pushl %esi
0x00428b5c:	pushl %edi
0x00428b5d:	movl %eax, 0x4bfd50
0x00428b62:	xorl -4(%ebp), %eax
0x00428b65:	xorl %eax, %ebp
0x00428b67:	pushl %eax
0x00428b68:	movl -24(%ebp), %esp
0x00428b6b:	pushl -8(%ebp)
0x00428b6e:	movl %eax, -4(%ebp)
0x00428b71:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00428b78:	movl -8(%ebp), %eax
0x00428b7b:	leal %eax, -16(%ebp)
0x00428b7e:	movl %fs:0, %eax
0x00428b84:	ret

0x00427e9f:	call 0x0042a048
0x0042a048:	pushl %ebp
0x0042a049:	movl %ebp, %esp
0x0042a04b:	subl %esp, $0x44<UINT8>
0x0042a04e:	leal %eax, -68(%ebp)
0x0042a051:	pushl %eax
0x0042a052:	call GetStartupInfoW@KERNEL32.dll
GetStartupInfoW@KERNEL32.dll: API Node	
0x0042a058:	testb -24(%ebp), $0x1<UINT8>
0x0042a05c:	je 0x0042a064
0x0042a064:	pushl $0xa<UINT8>
0x0042a066:	popl %eax
0x0042a067:	movl %esp, %ebp
0x0042a069:	popl %ebp
0x0042a06a:	ret

0x00427ea4:	movzwl %esi, %ax
0x00427ea7:	pushl $0x2<UINT8>
0x00427ea9:	call 0x0043508a
0x0043508a:	pushl %ebp
0x0043508b:	movl %ebp, %esp
0x0043508d:	movl %eax, 0x8(%ebp)
0x00435090:	movl 0x4c4380, %eax
0x00435095:	popl %ebp
0x00435096:	ret

0x00427eae:	popl %ecx
0x00427eaf:	movl %eax, $0x5a4d<UINT32>
0x00427eb4:	cmpw 0x400000, %ax
0x00427ebb:	je 0x00427ec1
0x00427ec1:	movl %eax, 0x40003c
0x00427ec6:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00427ed0:	jne -21
0x00427ed2:	movl %ecx, $0x10b<UINT32>
0x00427ed7:	cmpw 0x400018(%eax), %cx
0x00427ede:	jne -35
0x00427ee0:	xorl %ebx, %ebx
0x00427ee2:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00427ee9:	jbe 9
0x00427eeb:	cmpl 0x4000e8(%eax), %ebx
0x00427ef1:	setne %bl
0x00427ef4:	movl -28(%ebp), %ebx
0x00427ef7:	call 0x00428dbc
0x00428dbc:	call GetProcessHeap@KERNEL32.dll
GetProcessHeap@KERNEL32.dll: API Node	
0x00428dc2:	xorl %ecx, %ecx
0x00428dc4:	movl 0x4c4204, %eax
0x00428dc9:	testl %eax, %eax
0x00428dcb:	setne %cl
0x00428dce:	movl %eax, %ecx
0x00428dd0:	ret

0x00427efc:	testl %eax, %eax
0x00427efe:	jne 0x00427f08
0x00427f08:	call 0x00429d26
0x00429d26:	call 0x004233c7
0x004233c7:	pushl %esi
0x004233c8:	pushl $0x0<UINT8>
0x004233ca:	call EncodePointer@KERNEL32.dll
EncodePointer@KERNEL32.dll: API Node	
0x004233d0:	movl %esi, %eax
0x004233d2:	pushl %esi
0x004233d3:	call 0x00423607
0x00423607:	pushl %ebp
0x00423608:	movl %ebp, %esp
0x0042360a:	movl %eax, 0x8(%ebp)
0x0042360d:	movl 0x4c41d4, %eax
0x00423612:	popl %ebp
0x00423613:	ret

0x004233d8:	pushl %esi
0x004233d9:	call 0x00428fbe
0x00428fbe:	pushl %ebp
0x00428fbf:	movl %ebp, %esp
0x00428fc1:	movl %eax, 0x8(%ebp)
0x00428fc4:	movl 0x4c4208, %eax
0x00428fc9:	popl %ebp
0x00428fca:	ret

0x004233de:	pushl %esi
0x004233df:	call 0x004286c6
0x004286c6:	pushl %ebp
0x004286c7:	movl %ebp, %esp
0x004286c9:	movl %eax, 0x8(%ebp)
0x004286cc:	movl 0x4c41f4, %eax
0x004286d1:	popl %ebp
0x004286d2:	ret

0x004233e4:	pushl %esi
0x004233e5:	call 0x0042a782
0x0042a782:	pushl %ebp
0x0042a783:	movl %ebp, %esp
0x0042a785:	movl %eax, 0x8(%ebp)
0x0042a788:	movl 0x4c49b4, %eax
0x0042a78d:	movl 0x4c49b8, %eax
0x0042a792:	movl 0x4c49bc, %eax
0x0042a797:	movl 0x4c49c0, %eax
0x0042a79c:	popl %ebp
0x0042a79d:	ret

0x004233ea:	pushl %esi
0x004233eb:	call 0x0042a764
0x0042a764:	pushl $0x42a730<UINT32>
0x0042a769:	call EncodePointer@KERNEL32.dll
0x0042a76f:	movl 0x4c49b0, %eax
0x0042a774:	ret

0x004233f0:	pushl %esi
0x004233f1:	call 0x0042a993
0x0042a993:	pushl %ebp
0x0042a994:	movl %ebp, %esp
0x0042a996:	movl %eax, 0x8(%ebp)
0x0042a999:	movl 0x4c49c8, %eax
0x0042a99e:	popl %ebp
0x0042a99f:	ret

0x004233f6:	addl %esp, $0x18<UINT8>
0x004233f9:	popl %esi
0x004233fa:	jmp 0x0042a0d9
0x0042a0d9:	pushl %esi
0x0042a0da:	pushl %edi
0x0042a0db:	pushl $0x493370<UINT32>
0x0042a0e0:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x0042a0e6:	movl %esi, 0x48f1a0
0x0042a0ec:	movl %edi, %eax
0x0042a0ee:	pushl $0x49338c<UINT32>
0x0042a0f3:	pushl %edi
0x0042a0f4:	call GetProcAddress@KERNEL32.dll
0x0042a0f6:	xorl %eax, 0x4bfd50
0x0042a0fc:	pushl $0x493398<UINT32>
0x0042a101:	pushl %edi
0x0042a102:	movl 0x4c51a0, %eax
0x0042a107:	call GetProcAddress@KERNEL32.dll
0x0042a109:	xorl %eax, 0x4bfd50
0x0042a10f:	pushl $0x4933a0<UINT32>
0x0042a114:	pushl %edi
0x0042a115:	movl 0x4c51a4, %eax
0x0042a11a:	call GetProcAddress@KERNEL32.dll
0x0042a11c:	xorl %eax, 0x4bfd50
0x0042a122:	pushl $0x4933ac<UINT32>
0x0042a127:	pushl %edi
0x0042a128:	movl 0x4c51a8, %eax
0x0042a12d:	call GetProcAddress@KERNEL32.dll
0x0042a12f:	xorl %eax, 0x4bfd50
0x0042a135:	pushl $0x4933b8<UINT32>
0x0042a13a:	pushl %edi
0x0042a13b:	movl 0x4c51ac, %eax
0x0042a140:	call GetProcAddress@KERNEL32.dll
0x0042a142:	xorl %eax, 0x4bfd50
0x0042a148:	pushl $0x4933d4<UINT32>
0x0042a14d:	pushl %edi
0x0042a14e:	movl 0x4c51b0, %eax
0x0042a153:	call GetProcAddress@KERNEL32.dll
0x0042a155:	xorl %eax, 0x4bfd50
0x0042a15b:	pushl $0x4933e4<UINT32>
0x0042a160:	pushl %edi
0x0042a161:	movl 0x4c51b4, %eax
0x0042a166:	call GetProcAddress@KERNEL32.dll
0x0042a168:	xorl %eax, 0x4bfd50
0x0042a16e:	pushl $0x4933f8<UINT32>
0x0042a173:	pushl %edi
0x0042a174:	movl 0x4c51b8, %eax
0x0042a179:	call GetProcAddress@KERNEL32.dll
0x0042a17b:	xorl %eax, 0x4bfd50
0x0042a181:	pushl $0x493410<UINT32>
0x0042a186:	pushl %edi
0x0042a187:	movl 0x4c51bc, %eax
0x0042a18c:	call GetProcAddress@KERNEL32.dll
0x0042a18e:	xorl %eax, 0x4bfd50
0x0042a194:	pushl $0x493428<UINT32>
0x0042a199:	pushl %edi
0x0042a19a:	movl 0x4c51c0, %eax
0x0042a19f:	call GetProcAddress@KERNEL32.dll
0x0042a1a1:	xorl %eax, 0x4bfd50
0x0042a1a7:	pushl $0x49343c<UINT32>
0x0042a1ac:	pushl %edi
0x0042a1ad:	movl 0x4c51c4, %eax
0x0042a1b2:	call GetProcAddress@KERNEL32.dll
0x0042a1b4:	xorl %eax, 0x4bfd50
0x0042a1ba:	pushl $0x49345c<UINT32>
0x0042a1bf:	pushl %edi
0x0042a1c0:	movl 0x4c51c8, %eax
0x0042a1c5:	call GetProcAddress@KERNEL32.dll
0x0042a1c7:	xorl %eax, 0x4bfd50
0x0042a1cd:	pushl $0x493474<UINT32>
0x0042a1d2:	pushl %edi
0x0042a1d3:	movl 0x4c51cc, %eax
0x0042a1d8:	call GetProcAddress@KERNEL32.dll
0x0042a1da:	xorl %eax, 0x4bfd50
0x0042a1e0:	pushl $0x49348c<UINT32>
0x0042a1e5:	pushl %edi
0x0042a1e6:	movl 0x4c51d0, %eax
0x0042a1eb:	call GetProcAddress@KERNEL32.dll
0x0042a1ed:	xorl %eax, 0x4bfd50
0x0042a1f3:	pushl $0x4934a0<UINT32>
0x0042a1f8:	pushl %edi
0x0042a1f9:	movl 0x4c51d4, %eax
0x0042a1fe:	call GetProcAddress@KERNEL32.dll
0x0042a200:	xorl %eax, 0x4bfd50
0x0042a206:	movl 0x4c51d8, %eax
0x0042a20b:	pushl $0x4934b4<UINT32>
0x0042a210:	pushl %edi
0x0042a211:	call GetProcAddress@KERNEL32.dll
0x0042a213:	xorl %eax, 0x4bfd50
0x0042a219:	pushl $0x4934d0<UINT32>
0x0042a21e:	pushl %edi
0x0042a21f:	movl 0x4c51dc, %eax
0x0042a224:	call GetProcAddress@KERNEL32.dll
0x0042a226:	xorl %eax, 0x4bfd50
0x0042a22c:	pushl $0x4934f0<UINT32>
0x0042a231:	pushl %edi
0x0042a232:	movl 0x4c51e0, %eax
0x0042a237:	call GetProcAddress@KERNEL32.dll
0x0042a239:	xorl %eax, 0x4bfd50
0x0042a23f:	pushl $0x49350c<UINT32>
0x0042a244:	pushl %edi
0x0042a245:	movl 0x4c51e4, %eax
0x0042a24a:	call GetProcAddress@KERNEL32.dll
0x0042a24c:	xorl %eax, 0x4bfd50
0x0042a252:	pushl $0x49352c<UINT32>
0x0042a257:	pushl %edi
0x0042a258:	movl 0x4c51e8, %eax
0x0042a25d:	call GetProcAddress@KERNEL32.dll
0x0042a25f:	xorl %eax, 0x4bfd50
0x0042a265:	pushl $0x493540<UINT32>
0x0042a26a:	pushl %edi
0x0042a26b:	movl 0x4c51ec, %eax
0x0042a270:	call GetProcAddress@KERNEL32.dll
0x0042a272:	xorl %eax, 0x4bfd50
0x0042a278:	pushl $0x49355c<UINT32>
0x0042a27d:	pushl %edi
0x0042a27e:	movl 0x4c51f0, %eax
0x0042a283:	call GetProcAddress@KERNEL32.dll
0x0042a285:	xorl %eax, 0x4bfd50
0x0042a28b:	pushl $0x493570<UINT32>
0x0042a290:	pushl %edi
0x0042a291:	movl 0x4c51f8, %eax
0x0042a296:	call GetProcAddress@KERNEL32.dll
0x0042a298:	xorl %eax, 0x4bfd50
0x0042a29e:	pushl $0x493580<UINT32>
0x0042a2a3:	pushl %edi
0x0042a2a4:	movl 0x4c51f4, %eax
0x0042a2a9:	call GetProcAddress@KERNEL32.dll
0x0042a2ab:	xorl %eax, 0x4bfd50
0x0042a2b1:	pushl $0x493590<UINT32>
0x0042a2b6:	pushl %edi
0x0042a2b7:	movl 0x4c51fc, %eax
0x0042a2bc:	call GetProcAddress@KERNEL32.dll
0x0042a2be:	xorl %eax, 0x4bfd50
0x0042a2c4:	pushl $0x4935a0<UINT32>
0x0042a2c9:	pushl %edi
0x0042a2ca:	movl 0x4c5200, %eax
0x0042a2cf:	call GetProcAddress@KERNEL32.dll
0x0042a2d1:	xorl %eax, 0x4bfd50
0x0042a2d7:	pushl $0x4935b0<UINT32>
0x0042a2dc:	pushl %edi
0x0042a2dd:	movl 0x4c5204, %eax
0x0042a2e2:	call GetProcAddress@KERNEL32.dll
0x0042a2e4:	xorl %eax, 0x4bfd50
0x0042a2ea:	pushl $0x4935cc<UINT32>
0x0042a2ef:	pushl %edi
0x0042a2f0:	movl 0x4c5208, %eax
0x0042a2f5:	call GetProcAddress@KERNEL32.dll
0x0042a2f7:	xorl %eax, 0x4bfd50
0x0042a2fd:	pushl $0x4935e0<UINT32>
0x0042a302:	pushl %edi
0x0042a303:	movl 0x4c520c, %eax
0x0042a308:	call GetProcAddress@KERNEL32.dll
0x0042a30a:	xorl %eax, 0x4bfd50
0x0042a310:	pushl $0x4935f0<UINT32>
0x0042a315:	pushl %edi
0x0042a316:	movl 0x4c5210, %eax
0x0042a31b:	call GetProcAddress@KERNEL32.dll
0x0042a31d:	xorl %eax, 0x4bfd50
0x0042a323:	pushl $0x493604<UINT32>
0x0042a328:	pushl %edi
0x0042a329:	movl 0x4c5214, %eax
0x0042a32e:	call GetProcAddress@KERNEL32.dll
0x0042a330:	xorl %eax, 0x4bfd50
0x0042a336:	movl 0x4c5218, %eax
0x0042a33b:	pushl $0x493614<UINT32>
0x0042a340:	pushl %edi
0x0042a341:	call GetProcAddress@KERNEL32.dll
0x0042a343:	xorl %eax, 0x4bfd50
0x0042a349:	pushl $0x493634<UINT32>
0x0042a34e:	pushl %edi
0x0042a34f:	movl 0x4c521c, %eax
0x0042a354:	call GetProcAddress@KERNEL32.dll
0x0042a356:	xorl %eax, 0x4bfd50
0x0042a35c:	popl %edi
0x0042a35d:	movl 0x4c5220, %eax
0x0042a362:	popl %esi
0x0042a363:	ret

0x00429d2b:	call 0x00429f7c
0x00429f7c:	pushl %esi
0x00429f7d:	pushl %edi
0x00429f7e:	movl %esi, $0x4bfc00<UINT32>
0x00429f83:	movl %edi, $0x4c4230<UINT32>
0x00429f88:	cmpl 0x4(%esi), $0x1<UINT8>
0x00429f8c:	jne 22
0x00429f8e:	pushl $0x0<UINT8>
0x00429f90:	movl (%esi), %edi
0x00429f92:	addl %edi, $0x18<UINT8>
0x00429f95:	pushl $0xfa0<UINT32>
0x00429f9a:	pushl (%esi)
0x00429f9c:	call 0x0042a06b
0x0042a06b:	pushl %ebp
0x0042a06c:	movl %ebp, %esp
0x0042a06e:	movl %eax, 0x4c51b0
0x0042a073:	xorl %eax, 0x4bfd50
0x0042a079:	je 13
0x0042a07b:	pushl 0x10(%ebp)
0x0042a07e:	pushl 0xc(%ebp)
0x0042a081:	pushl 0x8(%ebp)
0x0042a084:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x0042a086:	popl %ebp
0x0042a087:	ret

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
