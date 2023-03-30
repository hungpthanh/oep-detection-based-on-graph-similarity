0x0045d000:	movl %ebx, $0x4001d0<UINT32>
0x0045d005:	movl %edi, $0x401000<UINT32>
0x0045d00a:	movl %esi, $0x437060<UINT32>
0x0045d00f:	pushl %ebx
0x0045d010:	call 0x0045d01f
0x0045d01f:	cld
0x0045d020:	movb %dl, $0xffffff80<UINT8>
0x0045d022:	movsb %es:(%edi), %ds:(%esi)
0x0045d023:	pushl $0x2<UINT8>
0x0045d025:	popl %ebx
0x0045d026:	call 0x0045d015
0x0045d015:	addb %dl, %dl
0x0045d017:	jne 0x0045d01e
0x0045d019:	movb %dl, (%esi)
0x0045d01b:	incl %esi
0x0045d01c:	adcb %dl, %dl
0x0045d01e:	ret

0x0045d029:	jae 0x0045d022
0x0045d02b:	xorl %ecx, %ecx
0x0045d02d:	call 0x0045d015
0x0045d030:	jae 0x0045d04a
0x0045d032:	xorl %eax, %eax
0x0045d034:	call 0x0045d015
0x0045d037:	jae 0x0045d05a
0x0045d05a:	lodsb %al, %ds:(%esi)
0x0045d05b:	shrl %eax
0x0045d05d:	je 0x0045d0a0
0x0045d05f:	adcl %ecx, %ecx
0x0045d061:	jmp 0x0045d07f
0x0045d07f:	incl %ecx
0x0045d080:	incl %ecx
0x0045d081:	xchgl %ebp, %eax
0x0045d082:	movl %eax, %ebp
0x0045d084:	movb %bl, $0x1<UINT8>
0x0045d086:	pushl %esi
0x0045d087:	movl %esi, %edi
0x0045d089:	subl %esi, %eax
0x0045d08b:	rep movsb %es:(%edi), %ds:(%esi)
0x0045d08d:	popl %esi
0x0045d08e:	jmp 0x0045d026
0x0045d039:	movb %bl, $0x2<UINT8>
0x0045d03b:	incl %ecx
0x0045d03c:	movb %al, $0x10<UINT8>
0x0045d03e:	call 0x0045d015
0x0045d041:	adcb %al, %al
0x0045d043:	jae 0x0045d03e
0x0045d045:	jne 0x0045d086
0x0045d047:	stosb %es:(%edi), %al
0x0045d048:	jmp 0x0045d026
0x0045d04a:	call 0x0045d092
0x0045d092:	incl %ecx
0x0045d093:	call 0x0045d015
0x0045d097:	adcl %ecx, %ecx
0x0045d099:	call 0x0045d015
0x0045d09d:	jb 0x0045d093
0x0045d09f:	ret

0x0045d04f:	subl %ecx, %ebx
0x0045d051:	jne 0x0045d063
0x0045d053:	call 0x0045d090
0x0045d090:	xorl %ecx, %ecx
0x0045d058:	jmp 0x0045d082
0x0045d063:	xchgl %ecx, %eax
0x0045d064:	decl %eax
0x0045d065:	shll %eax, $0x8<UINT8>
0x0045d068:	lodsb %al, %ds:(%esi)
0x0045d069:	call 0x0045d090
0x0045d06e:	cmpl %eax, $0x7d00<UINT32>
0x0045d073:	jae 0x0045d07f
0x0045d075:	cmpb %ah, $0x5<UINT8>
0x0045d078:	jae 0x0045d080
0x0045d07a:	cmpl %eax, $0x7f<UINT8>
0x0045d07d:	ja 0x0045d081
0x0045d0a0:	popl %edi
0x0045d0a1:	popl %ebx
0x0045d0a2:	movzwl %edi, (%ebx)
0x0045d0a5:	decl %edi
0x0045d0a6:	je 0x0045d0b0
0x0045d0a8:	decl %edi
0x0045d0a9:	je 0x0045d0be
0x0045d0ab:	shll %edi, $0xc<UINT8>
0x0045d0ae:	jmp 0x0045d0b7
0x0045d0b7:	incl %ebx
0x0045d0b8:	incl %ebx
0x0045d0b9:	jmp 0x0045d00f
0x0045d0b0:	movl %edi, 0x2(%ebx)
0x0045d0b3:	pushl %edi
0x0045d0b4:	addl %ebx, $0x4<UINT8>
0x0045d0be:	popl %edi
0x0045d0bf:	movl %ebx, $0x45d128<UINT32>
0x0045d0c4:	incl %edi
0x0045d0c5:	movl %esi, (%edi)
0x0045d0c7:	scasl %eax, %es:(%edi)
0x0045d0c8:	pushl %edi
0x0045d0c9:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0045d0cb:	xchgl %ebp, %eax
0x0045d0cc:	xorl %eax, %eax
0x0045d0ce:	scasb %al, %es:(%edi)
0x0045d0cf:	jne 0x0045d0ce
0x0045d0d1:	decb (%edi)
0x0045d0d3:	je 0x0045d0c4
0x0045d0d5:	decb (%edi)
0x0045d0d7:	jne 0x0045d0df
0x0045d0df:	decb (%edi)
0x0045d0e1:	je 0x0041137f
0x0045d0e7:	pushl %edi
0x0045d0e8:	pushl %ebp
0x0045d0e9:	call GetProcAddress@kernel32.dll
GetProcAddress@kernel32.dll: API Node	
0x0045d0ec:	orl (%esi), %eax
0x0045d0ee:	lodsl %eax, %ds:(%esi)
0x0045d0ef:	jne 0x0045d0cc
0x0041137f:	call 0x00411771
0x00411771:	movl %edi, %edi
0x00411773:	pushl %ebp
0x00411774:	movl %ebp, %esp
0x00411776:	subl %esp, $0x14<UINT8>
0x00411779:	movl %eax, 0x412040
0x0041177e:	andl -12(%ebp), $0x0<UINT8>
0x00411782:	andl -8(%ebp), $0x0<UINT8>
0x00411786:	pushl %esi
0x00411787:	pushl %edi
0x00411788:	movl %edi, $0xbb40e64e<UINT32>
0x0041178d:	movl %esi, $0xffff0000<UINT32>
0x00411792:	cmpl %eax, %edi
0x00411794:	je 0x004117a3
0x004117a3:	leal %eax, -12(%ebp)
0x004117a6:	pushl %eax
0x004117a7:	call GetSystemTimeAsFileTime@KERNEL32.dll
GetSystemTimeAsFileTime@KERNEL32.dll: API Node	
0x004117ad:	movl %eax, -8(%ebp)
0x004117b0:	xorl %eax, -12(%ebp)
0x004117b3:	movl -4(%ebp), %eax
0x004117b6:	call GetCurrentProcessId@KERNEL32.dll
GetCurrentProcessId@KERNEL32.dll: API Node	
0x004117bc:	xorl -4(%ebp), %eax
0x004117bf:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x004117c5:	xorl -4(%ebp), %eax
0x004117c8:	call GetTickCount@KERNEL32.dll
GetTickCount@KERNEL32.dll: API Node	
0x004117ce:	xorl %eax, -4(%ebp)
0x004117d1:	leal %ecx, -4(%ebp)
0x004117d4:	xorl %eax, %ecx
0x004117d6:	movl -4(%ebp), %eax
0x004117d9:	leal %eax, -20(%ebp)
0x004117dc:	pushl %eax
0x004117dd:	call QueryPerformanceCounter@KERNEL32.dll
QueryPerformanceCounter@KERNEL32.dll: API Node	
0x004117e3:	movl %eax, -16(%ebp)
0x004117e6:	xorl %eax, -20(%ebp)
0x004117e9:	movl %ecx, -4(%ebp)
0x004117ec:	xorl %ecx, %eax
0x004117ee:	cmpl %ecx, %edi
0x004117f0:	je 8
0x004117f2:	testl 0x412040, %esi
0x004117f8:	jne 0x004117ff
0x004117ff:	movl 0x412040, %ecx
0x00411805:	notl %ecx
0x00411807:	movl 0x412044, %ecx
0x0041180d:	popl %edi
0x0041180e:	popl %esi
0x0041180f:	leave
0x00411810:	ret

0x00411384:	jmp 0x00411212
0x00411212:	pushl $0xc<UINT8>
0x00411214:	pushl $0x411be0<UINT32>
0x00411219:	call 0x00411844
0x00411844:	pushl $0x4118a2<UINT32>
0x00411849:	pushl %fs:0
0x00411850:	movl %eax, 0x10(%esp)
0x00411854:	movl 0x10(%esp), %ebp
0x00411858:	leal %ebp, 0x10(%esp)
0x0041185c:	subl %esp, %eax
0x0041185e:	pushl %ebx
0x0041185f:	pushl %esi
0x00411860:	pushl %edi
0x00411861:	movl %eax, 0x412040
0x00411866:	xorl -4(%ebp), %eax
0x00411869:	xorl %eax, %ebp
0x0041186b:	pushl %eax
0x0041186c:	movl -24(%ebp), %esp
0x0041186f:	pushl -8(%ebp)
0x00411872:	movl %eax, -4(%ebp)
0x00411875:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0041187c:	movl -8(%ebp), %eax
0x0041187f:	leal %eax, -16(%ebp)
0x00411882:	movl %fs:0, %eax
0x00411888:	ret

0x0041121e:	xorl %ebx, %ebx
0x00411220:	movl -4(%ebp), %ebx
0x00411223:	movl %eax, %fs:0x18
0x00411229:	movl %esi, 0x4(%eax)
0x0041122c:	movl %edi, %ebx
0x0041122e:	pushl %ebx
0x0041122f:	pushl %esi
0x00411230:	pushl $0x4348bc<UINT32>
0x00411235:	call InterlockedCompareExchange@KERNEL32.dll
InterlockedCompareExchange@KERNEL32.dll: API Node	
0x0041123b:	testl %eax, %eax
0x0041123d:	je 24
0x0041123f:	cmpl %eax, %esi
0x00411241:	jne 0x0041124a
0x0041124a:	pushl $0x3e8<UINT32>
0x0041124f:	call Sleep@KERNEL32.dll
Sleep@KERNEL32.dll: API Node	
0x00411255:	jmp 0x0041122e
