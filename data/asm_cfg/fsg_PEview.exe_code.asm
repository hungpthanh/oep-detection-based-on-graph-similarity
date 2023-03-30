0x0041d000:	movl %ebx, $0x4001d0<UINT32>
0x0041d005:	movl %edi, $0x401000<UINT32>
0x0041d00a:	movl %esi, $0x415cad<UINT32>
0x0041d00f:	pushl %ebx
0x0041d010:	call 0x0041d01f
0x0041d01f:	cld
0x0041d020:	movb %dl, $0xffffff80<UINT8>
0x0041d022:	movsb %es:(%edi), %ds:(%esi)
0x0041d023:	pushl $0x2<UINT8>
0x0041d025:	popl %ebx
0x0041d026:	call 0x0041d015
0x0041d015:	addb %dl, %dl
0x0041d017:	jne 0x0041d01e
0x0041d019:	movb %dl, (%esi)
0x0041d01b:	incl %esi
0x0041d01c:	adcb %dl, %dl
0x0041d01e:	ret

0x0041d029:	jae 0x0041d022
0x0041d02b:	xorl %ecx, %ecx
0x0041d02d:	call 0x0041d015
0x0041d030:	jae 0x0041d04a
0x0041d032:	xorl %eax, %eax
0x0041d034:	call 0x0041d015
0x0041d037:	jae 0x0041d05a
0x0041d039:	movb %bl, $0x2<UINT8>
0x0041d03b:	incl %ecx
0x0041d03c:	movb %al, $0x10<UINT8>
0x0041d03e:	call 0x0041d015
0x0041d041:	adcb %al, %al
0x0041d043:	jae 0x0041d03e
0x0041d045:	jne 0x0041d086
0x0041d047:	stosb %es:(%edi), %al
0x0041d048:	jmp 0x0041d026
0x0041d05a:	lodsb %al, %ds:(%esi)
0x0041d05b:	shrl %eax
0x0041d05d:	je 0x0041d0a0
0x0041d05f:	adcl %ecx, %ecx
0x0041d061:	jmp 0x0041d07f
0x0041d07f:	incl %ecx
0x0041d080:	incl %ecx
0x0041d081:	xchgl %ebp, %eax
0x0041d082:	movl %eax, %ebp
0x0041d084:	movb %bl, $0x1<UINT8>
0x0041d086:	pushl %esi
0x0041d087:	movl %esi, %edi
0x0041d089:	subl %esi, %eax
0x0041d08b:	rep movsb %es:(%edi), %ds:(%esi)
0x0041d08d:	popl %esi
0x0041d08e:	jmp 0x0041d026
0x0041d04a:	call 0x0041d092
0x0041d092:	incl %ecx
0x0041d093:	call 0x0041d015
0x0041d097:	adcl %ecx, %ecx
0x0041d099:	call 0x0041d015
0x0041d09d:	jb 0x0041d093
0x0041d09f:	ret

0x0041d04f:	subl %ecx, %ebx
0x0041d051:	jne 0x0041d063
0x0041d053:	call 0x0041d090
0x0041d090:	xorl %ecx, %ecx
0x0041d058:	jmp 0x0041d082
0x0041d063:	xchgl %ecx, %eax
0x0041d064:	decl %eax
0x0041d065:	shll %eax, $0x8<UINT8>
0x0041d068:	lodsb %al, %ds:(%esi)
0x0041d069:	call 0x0041d090
0x0041d06e:	cmpl %eax, $0x7d00<UINT32>
0x0041d073:	jae 10
0x0041d075:	cmpb %ah, $0x5<UINT8>
0x0041d078:	jae 0x0041d080
0x0041d07a:	cmpl %eax, $0x7f<UINT8>
0x0041d07d:	ja 0x0041d081
0x0041d0a0:	popl %edi
0x0041d0a1:	popl %ebx
0x0041d0a2:	movzwl %edi, (%ebx)
0x0041d0a5:	decl %edi
0x0041d0a6:	je 0x0041d0b0
0x0041d0a8:	decl %edi
0x0041d0a9:	je 0x0041d0be
0x0041d0ab:	shll %edi, $0xc<UINT8>
0x0041d0ae:	jmp 0x0041d0b7
0x0041d0b7:	incl %ebx
0x0041d0b8:	incl %ebx
0x0041d0b9:	jmp 0x0041d00f
0x0041d0b0:	movl %edi, 0x2(%ebx)
0x0041d0b3:	pushl %edi
0x0041d0b4:	addl %ebx, $0x4<UINT8>
0x0041d0be:	popl %edi
0x0041d0bf:	movl %ebx, $0x41d128<UINT32>
0x0041d0c4:	incl %edi
0x0041d0c5:	movl %esi, (%edi)
0x0041d0c7:	scasl %eax, %es:(%edi)
0x0041d0c8:	pushl %edi
0x0041d0c9:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0041d0cb:	xchgl %ebp, %eax
0x0041d0cc:	xorl %eax, %eax
0x0041d0ce:	scasb %al, %es:(%edi)
0x0041d0cf:	jne 0x0041d0ce
0x0041d0d1:	decb (%edi)
0x0041d0d3:	je 0x0041d0c4
0x0041d0d5:	decb (%edi)
0x0041d0d7:	jne 0x0041d0df
0x0041d0df:	decb (%edi)
0x0041d0e1:	je 0x00401000
0x0041d0e7:	pushl %edi
0x0041d0e8:	pushl %ebp
0x0041d0e9:	call GetProcAddress@kernel32.dll
GetProcAddress@kernel32.dll: API Node	
0x0041d0ec:	orl (%esi), %eax
0x0041d0ee:	lodsl %eax, %ds:(%esi)
0x0041d0ef:	jne 0x0041d0cc
0x00401000:	call 0x004010dc
0x004010dc:	pushl %ebp
0x004010dd:	movl %ebp, %esp
0x004010df:	subl %esp, $0x38<UINT8>
0x004010e2:	call 0x00401490
0x00401490:	pushl $0x2<UINT8>
0x00401492:	call GetSystemMetrics@USER32.dll
GetSystemMetrics@USER32.dll: API Node	
0x00401498:	movl 0x40a310, %eax
0x0040149d:	pushl $0x0<UINT8>
0x0040149f:	pushl $0x40a314<UINT32>
0x004014a4:	pushl $0x0<UINT8>
0x004014a6:	pushl $0x26<UINT8>
0x004014a8:	call SystemParametersInfoA@USER32.dll
SystemParametersInfoA@USER32.dll: API Node	
0x004014ae:	pushl $0x0<UINT8>
0x004014b0:	pushl $0x40a300<UINT32>
0x004014b5:	pushl $0x0<UINT8>
0x004014b7:	pushl $0x68<UINT8>
0x004014b9:	call SystemParametersInfoA@USER32.dll
0x004014bf:	ret

0x004010e7:	call 0x004014c0
0x004014c0:	pushl $0x5<UINT8>
0x004014c2:	call GetSysColor@USER32.dll
GetSysColor@USER32.dll: API Node	
0x004014c8:	movl 0x40a968, %eax
0x004014cd:	pushl $0x8<UINT8>
0x004014cf:	call GetSysColor@USER32.dll
0x004014d5:	movl 0x40a96c, %eax
0x004014da:	pushl $0xd<UINT8>
0x004014dc:	call GetSysColor@USER32.dll
0x004014e2:	movl 0x40a970, %eax
0x004014e7:	pushl $0xe<UINT8>
0x004014e9:	call GetSysColor@USER32.dll
0x004014ef:	movl 0x40a974, %eax
0x004014f4:	pushl $0x11<UINT8>
0x004014f6:	call GetSysColor@USER32.dll
0x004014fc:	movl 0x40a978, %eax
0x00401501:	movl %eax, 0x40a2f8
0x00401506:	testl %eax, %eax
0x00401508:	je 0x00401517
0x00401517:	xorl %eax, %eax
0x00401519:	ret

0x004010ec:	pushl $0x0<UINT8>
0x004010ee:	call GetModuleHandleA@KERNEL32.dll
GetModuleHandleA@KERNEL32.dll: API Node	
0x004010f4:	testl %eax, %eax
0x004010f6:	je 334
0x004010fc:	movl 0x40a2e0, %eax
0x00401101:	movl %ebx, %eax
0x00401103:	movl -8(%ebp), $0x8<UINT32>
0x0040110a:	movl -4(%ebp), $0x6<UINT32>
0x00401111:	pushl %ebp
0x00401112:	addl (%esp), $0xfffffff8<UINT8>
0x00401116:	call InitCommonControlsEx@COMCTL32.dll
InitCommonControlsEx@COMCTL32.dll: API Node	
0x0040111c:	xorl %eax, %eax
0x0040111e:	movl -56(%ebp), $0x30<UINT32>
0x00401125:	movl -52(%ebp), %eax
0x00401128:	movl -48(%ebp), $0x401068<UINT32>
0x0040112f:	movl -44(%ebp), %eax
0x00401132:	movl -40(%ebp), %eax
0x00401135:	movl -36(%ebp), %ebx
0x00401138:	pushl $0x0<UINT8>
0x0040113a:	pushl $0x20<UINT8>
0x0040113c:	pushl $0x20<UINT8>
0x0040113e:	pushl $0x1<UINT8>
0x00401140:	pushl $0x1<UINT8>
0x00401142:	pushl %ebx
0x00401143:	call LoadImageA@USER32.dll
LoadImageA@USER32.dll: API Node	
0x00401149:	movl -32(%ebp), %eax
0x0040114c:	pushl $0x8040<UINT32>
0x00401151:	pushl $0x0<UINT8>
0x00401153:	pushl $0x0<UINT8>
0x00401155:	pushl $0x2<UINT8>
0x00401157:	pushl $0x7f84<UINT32>
0x0040115c:	pushl $0x0<UINT8>
0x0040115e:	call LoadImageA@USER32.dll
0x00401164:	movl -28(%ebp), %eax
0x00401167:	movl 0x40a2fc, %eax
0x0040116c:	movl -24(%ebp), $0x0<UINT32>
0x00401173:	movl -20(%ebp), $0x1<UINT32>
0x0040117a:	movl -16(%ebp), $0x40c188<UINT32>
0x00401181:	pushl $0x0<UINT8>
0x00401183:	pushl $0x10<UINT8>
0x00401185:	pushl $0x10<UINT8>
0x00401187:	pushl $0x1<UINT8>
0x00401189:	pushl $0x1<UINT8>
0x0040118b:	pushl %ebx
0x0040118c:	call LoadImageA@USER32.dll
0x00401192:	movl -12(%ebp), %eax
0x00401195:	pushl %ebp
0x00401196:	addl (%esp), $0xffffffc8<UINT8>
0x0040119a:	call RegisterClassExA@USER32.dll
RegisterClassExA@USER32.dll: API Node	
0x004011a0:	testl %eax, %eax
0x004011a2:	je 162
0x004011a8:	movl %eax, $0x6578652e<UINT32>
0x004011ad:	movl %ecx, $0x4<UINT32>
0x004011b2:	movl 0x40a7f4, %eax
0x004011b7:	movl 0x40a3d4, %ecx
0x004011bd:	call 0x0040159c
0x0040159c:	xorl %ebx, %ebx
0x0040159e:	movl %esi, $0x40a304<UINT32>
0x004015a3:	pushl %esi
0x004015a4:	pushl $0x20019<UINT32>
0x004015a9:	pushl %ebx
0x004015aa:	pushl $0x40c300<UINT32>
0x004015af:	pushl $0x80000001<UINT32>
0x004015b4:	call RegOpenKeyExA@ADVAPI32.dll
RegOpenKeyExA@ADVAPI32.dll: API Node	
0x004015ba:	testl %eax, %eax
0x004015bc:	jne 0x00401666
0x00401666:	ret

0x004011c2:	pushl %eax
0x004011c3:	xorl %eax, %eax
0x004011c5:	pushl %eax
0x004011c6:	pushl %ebx
0x004011c7:	pushl %eax
0x004011c8:	pushl %eax
0x004011c9:	pushl %eax
0x004011ca:	pushl %eax
0x004011cb:	pushl %eax
0x004011cc:	pushl %eax
0x004011cd:	pushl $0xcf0000<UINT32>
0x004011d2:	pushl %eax
0x004011d3:	pushl $0x40c188<UINT32>
0x004011d8:	pushl $0x10<UINT8>
0x004011da:	call CreateWindowExA@USER32.dll
CreateWindowExA@USER32.dll: API Node	
0x004011e0:	popl %edx
0x004011e1:	testl %eax, %eax
0x004011e3:	je 0x0040124a
0x0040124a:	incl %eax
0x0040124b:	jmp 0x00401246
0x00401246:	movl %esp, %ebp
0x00401248:	popl %ebp
0x00401249:	ret

0x00401005:	testl %eax, %eax
0x00401007:	jne 0x0040100e
0x0040100e:	pushl %eax
0x0040100f:	call ExitProcess@KERNEL32.dll
ExitProcess@KERNEL32.dll: Exit Node	
