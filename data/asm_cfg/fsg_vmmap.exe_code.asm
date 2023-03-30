0x0063b000:	movl %ebx, $0x4001d0<UINT32>
0x0063b005:	movl %edi, $0x401000<UINT32>
0x0063b00a:	movl %esi, $0x60a48c<UINT32>
0x0063b00f:	pushl %ebx
0x0063b010:	call 0x0063b01f
0x0063b01f:	cld
0x0063b020:	movb %dl, $0xffffff80<UINT8>
0x0063b022:	movsb %es:(%edi), %ds:(%esi)
0x0063b023:	pushl $0x2<UINT8>
0x0063b025:	popl %ebx
0x0063b026:	call 0x0063b015
0x0063b015:	addb %dl, %dl
0x0063b017:	jne 0x0063b01e
0x0063b019:	movb %dl, (%esi)
0x0063b01b:	incl %esi
0x0063b01c:	adcb %dl, %dl
0x0063b01e:	ret

0x0063b029:	jae 0x0063b022
0x0063b02b:	xorl %ecx, %ecx
0x0063b02d:	call 0x0063b015
0x0063b030:	jae 0x0063b04a
0x0063b032:	xorl %eax, %eax
0x0063b034:	call 0x0063b015
0x0063b037:	jae 0x0063b05a
0x0063b039:	movb %bl, $0x2<UINT8>
0x0063b03b:	incl %ecx
0x0063b03c:	movb %al, $0x10<UINT8>
0x0063b03e:	call 0x0063b015
0x0063b041:	adcb %al, %al
0x0063b043:	jae 0x0063b03e
0x0063b045:	jne 0x0063b086
0x0063b047:	stosb %es:(%edi), %al
0x0063b048:	jmp 0x0063b026
0x0063b05a:	lodsb %al, %ds:(%esi)
0x0063b05b:	shrl %eax
0x0063b05d:	je 0x0063b0a0
0x0063b05f:	adcl %ecx, %ecx
0x0063b061:	jmp 0x0063b07f
0x0063b07f:	incl %ecx
0x0063b080:	incl %ecx
0x0063b081:	xchgl %ebp, %eax
0x0063b082:	movl %eax, %ebp
0x0063b084:	movb %bl, $0x1<UINT8>
0x0063b086:	pushl %esi
0x0063b087:	movl %esi, %edi
0x0063b089:	subl %esi, %eax
0x0063b08b:	rep movsb %es:(%edi), %ds:(%esi)
0x0063b08d:	popl %esi
0x0063b08e:	jmp 0x0063b026
0x0063b04a:	call 0x0063b092
0x0063b092:	incl %ecx
0x0063b093:	call 0x0063b015
0x0063b097:	adcl %ecx, %ecx
0x0063b099:	call 0x0063b015
0x0063b09d:	jb 0x0063b093
0x0063b09f:	ret

0x0063b04f:	subl %ecx, %ebx
0x0063b051:	jne 0x0063b063
0x0063b063:	xchgl %ecx, %eax
0x0063b064:	decl %eax
0x0063b065:	shll %eax, $0x8<UINT8>
0x0063b068:	lodsb %al, %ds:(%esi)
0x0063b069:	call 0x0063b090
0x0063b090:	xorl %ecx, %ecx
0x0063b06e:	cmpl %eax, $0x7d00<UINT32>
0x0063b073:	jae 0x0063b07f
0x0063b075:	cmpb %ah, $0x5<UINT8>
0x0063b078:	jae 0x0063b080
0x0063b07a:	cmpl %eax, $0x7f<UINT8>
0x0063b07d:	ja 0x0063b081
0x0063b053:	call 0x0063b090
0x0063b058:	jmp 0x0063b082
0x0063b0a0:	popl %edi
0x0063b0a1:	popl %ebx
0x0063b0a2:	movzwl %edi, (%ebx)
0x0063b0a5:	decl %edi
0x0063b0a6:	je 0x0063b0b0
0x0063b0a8:	decl %edi
0x0063b0a9:	je 0x0063b0be
0x0063b0ab:	shll %edi, $0xc<UINT8>
0x0063b0ae:	jmp 0x0063b0b7
0x0063b0b7:	incl %ebx
0x0063b0b8:	incl %ebx
0x0063b0b9:	jmp 0x0063b00f
0x0063b0b0:	movl %edi, 0x2(%ebx)
0x0063b0b3:	pushl %edi
0x0063b0b4:	addl %ebx, $0x4<UINT8>
0x0063b0be:	popl %edi
0x0063b0bf:	movl %ebx, $0x63b128<UINT32>
0x0063b0c4:	incl %edi
0x0063b0c5:	movl %esi, (%edi)
0x0063b0c7:	scasl %eax, %es:(%edi)
0x0063b0c8:	pushl %edi
0x0063b0c9:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0063b0cb:	xchgl %ebp, %eax
0x0063b0cc:	xorl %eax, %eax
0x0063b0ce:	scasb %al, %es:(%edi)
0x0063b0cf:	jne 0x0063b0ce
0x0063b0d1:	decb (%edi)
0x0063b0d3:	je 0x0063b0c4
0x0063b0d5:	decb (%edi)
0x0063b0d7:	jne 0x0063b0df
0x0063b0df:	decb (%edi)
0x0063b0e1:	je 0x004313a5
0x0063b0e7:	pushl %edi
0x0063b0e8:	pushl %ebp
0x0063b0e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x0063b0ec:	orl (%esi), %eax
0x0063b0ee:	lodsl %eax, %ds:(%esi)
0x0063b0ef:	jne 0x0063b0cc
0x0063b0d9:	incl %edi
0x0063b0da:	pushl (%edi)
0x0063b0dc:	scasl %eax, %es:(%edi)
0x0063b0dd:	jmp 0x0063b0e8
GetProcAddress@KERNEL32.dll: API Node	
0x004313a5:	call 0x0043ea88
0x0043ea88:	pushl %ebp
0x0043ea89:	movl %ebp, %esp
0x0043ea8b:	subl %esp, $0x14<UINT8>
0x0043ea8e:	andl -12(%ebp), $0x0<UINT8>
0x0043ea92:	andl -8(%ebp), $0x0<UINT8>
0x0043ea96:	movl %eax, 0x45f120
0x0043ea9b:	pushl %esi
0x0043ea9c:	pushl %edi
0x0043ea9d:	movl %edi, $0xbb40e64e<UINT32>
0x0043eaa2:	movl %esi, $0xffff0000<UINT32>
0x0043eaa7:	cmpl %eax, %edi
0x0043eaa9:	je 0x0043eab8
0x0043eab8:	leal %eax, -12(%ebp)
0x0043eabb:	pushl %eax
0x0043eabc:	call GetSystemTimeAsFileTime@KERNEL32.dll
GetSystemTimeAsFileTime@KERNEL32.dll: API Node	
0x0043eac2:	movl %eax, -8(%ebp)
0x0043eac5:	xorl %eax, -12(%ebp)
0x0043eac8:	movl -4(%ebp), %eax
0x0043eacb:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x0043ead1:	xorl -4(%ebp), %eax
0x0043ead4:	call GetCurrentProcessId@KERNEL32.dll
GetCurrentProcessId@KERNEL32.dll: API Node	
0x0043eada:	xorl -4(%ebp), %eax
0x0043eadd:	leal %eax, -20(%ebp)
0x0043eae0:	pushl %eax
0x0043eae1:	call QueryPerformanceCounter@KERNEL32.dll
QueryPerformanceCounter@KERNEL32.dll: API Node	
0x0043eae7:	movl %ecx, -16(%ebp)
0x0043eaea:	leal %eax, -4(%ebp)
0x0043eaed:	xorl %ecx, -20(%ebp)
0x0043eaf0:	xorl %ecx, -4(%ebp)
0x0043eaf3:	xorl %ecx, %eax
0x0043eaf5:	cmpl %ecx, %edi
0x0043eaf7:	jne 0x0043eb00
0x0043eb00:	testl %esi, %ecx
0x0043eb02:	jne 0x0043eb10
0x0043eb10:	movl 0x45f120, %ecx
0x0043eb16:	notl %ecx
0x0043eb18:	movl 0x45f124, %ecx
0x0043eb1e:	popl %edi
0x0043eb1f:	popl %esi
0x0043eb20:	movl %esp, %ebp
0x0043eb22:	popl %ebp
0x0043eb23:	ret

0x004313aa:	jmp 0x004313af
0x004313af:	pushl $0x14<UINT8>
0x004313b1:	pushl $0x45c7e0<UINT32>
0x004313b6:	call 0x00433460
0x00433460:	pushl $0x42fb80<UINT32>
0x00433465:	pushl %fs:0
0x0043346c:	movl %eax, 0x10(%esp)
0x00433470:	movl 0x10(%esp), %ebp
0x00433474:	leal %ebp, 0x10(%esp)
0x00433478:	subl %esp, %eax
0x0043347a:	pushl %ebx
0x0043347b:	pushl %esi
0x0043347c:	pushl %edi
0x0043347d:	movl %eax, 0x45f120
0x00433482:	xorl -4(%ebp), %eax
0x00433485:	xorl %eax, %ebp
0x00433487:	pushl %eax
0x00433488:	movl -24(%ebp), %esp
0x0043348b:	pushl -8(%ebp)
0x0043348e:	movl %eax, -4(%ebp)
0x00433491:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00433498:	movl -8(%ebp), %eax
0x0043349b:	leal %eax, -16(%ebp)
0x0043349e:	movl %fs:0, %eax
0x004334a4:	ret

0x004313bb:	call 0x00432988
0x00432988:	pushl %ebp
0x00432989:	movl %ebp, %esp
0x0043298b:	subl %esp, $0x44<UINT8>
0x0043298e:	leal %eax, -68(%ebp)
0x00432991:	pushl %eax
0x00432992:	call GetStartupInfoW@KERNEL32.dll
GetStartupInfoW@KERNEL32.dll: API Node	
0x00432998:	testb -24(%ebp), $0x1<UINT8>
0x0043299c:	je 0x004329a4
0x004329a4:	pushl $0xa<UINT8>
0x004329a6:	popl %eax
0x004329a7:	movl %esp, %ebp
0x004329a9:	popl %ebp
0x004329aa:	ret

0x004313c0:	movzwl %esi, %ax
0x004313c3:	pushl $0x2<UINT8>
0x004313c5:	call 0x0043ea3b
0x0043ea3b:	pushl %ebp
0x0043ea3c:	movl %ebp, %esp
0x0043ea3e:	movl %eax, 0x8(%ebp)
0x0043ea41:	movl 0x462a48, %eax
0x0043ea46:	popl %ebp
0x0043ea47:	ret

0x004313ca:	popl %ecx
0x004313cb:	movl %eax, $0x5a4d<UINT32>
0x004313d0:	cmpw 0x400000, %ax
0x004313d7:	je 0x004313dd
0x004313dd:	movl %eax, 0x40003c
0x004313e2:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x004313ec:	jne -21
0x004313ee:	movl %ecx, $0x10b<UINT32>
0x004313f3:	cmpw 0x400018(%eax), %cx
0x004313fa:	jne -35
0x004313fc:	xorl %ebx, %ebx
0x004313fe:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00431405:	jbe 9
0x00431407:	cmpl 0x4000e8(%eax), %ebx
0x0043140d:	setne %bl
0x00431410:	movl -28(%ebp), %ebx
0x00431413:	call 0x00433590
0x00433590:	call GetProcessHeap@KERNEL32.dll
GetProcessHeap@KERNEL32.dll: API Node	
0x00433596:	xorl %ecx, %ecx
0x00433598:	movl 0x4630a4, %eax
0x0043359d:	testl %eax, %eax
0x0043359f:	setne %cl
0x004335a2:	movl %eax, %ecx
0x004335a4:	ret

0x00431418:	testl %eax, %eax
0x0043141a:	jne 0x00431424
0x00431424:	call 0x004325de
0x004325de:	call 0x0042a768
0x0042a768:	pushl %esi
0x0042a769:	pushl $0x0<UINT8>
0x0042a76b:	call EncodePointer@KERNEL32.dll
EncodePointer@KERNEL32.dll: API Node	
0x0042a771:	movl %esi, %eax
0x0042a773:	pushl %esi
0x0042a774:	call 0x0042dc01
0x0042dc01:	pushl %ebp
0x0042dc02:	movl %ebp, %esp
0x0042dc04:	movl %eax, 0x8(%ebp)
0x0042dc07:	movl 0x462588, %eax
0x0042dc0c:	popl %ebp
0x0042dc0d:	ret

0x0042a779:	pushl %esi
0x0042a77a:	call 0x004317c4
0x004317c4:	pushl %ebp
0x004317c5:	movl %ebp, %esp
0x004317c7:	movl %eax, 0x8(%ebp)
0x004317ca:	movl 0x4628d0, %eax
0x004317cf:	popl %ebp
0x004317d0:	ret

0x0042a77f:	pushl %esi
0x0042a780:	call 0x00433227
0x00433227:	pushl %ebp
0x00433228:	movl %ebp, %esp
0x0043322a:	movl %eax, 0x8(%ebp)
0x0043322d:	movl 0x463080, %eax
0x00433232:	popl %ebp
0x00433233:	ret

0x0042a785:	pushl %esi
0x0042a786:	call 0x00433241
0x00433241:	pushl %ebp
0x00433242:	movl %ebp, %esp
0x00433244:	movl %eax, 0x8(%ebp)
0x00433247:	movl 0x463084, %eax
0x0043324c:	movl 0x463088, %eax
0x00433251:	movl 0x46308c, %eax
0x00433256:	movl 0x463090, %eax
0x0043325b:	popl %ebp
0x0043325c:	ret

0x0042a78b:	pushl %esi
0x0042a78c:	call 0x00433216
0x00433216:	pushl $0x4331cf<UINT32>
0x0043321b:	call EncodePointer@KERNEL32.dll
0x00433221:	movl 0x46307c, %eax
0x00433226:	ret

0x0042a791:	pushl %esi
0x0042a792:	call 0x00433452
0x00433452:	pushl %ebp
0x00433453:	movl %ebp, %esp
0x00433455:	movl %eax, 0x8(%ebp)
0x00433458:	movl 0x463098, %eax
0x0043345d:	popl %ebp
0x0043345e:	ret

0x0042a797:	addl %esp, $0x18<UINT8>
0x0042a79a:	popl %esi
0x0042a79b:	jmp 0x00432a19
0x00432a19:	pushl %esi
0x00432a1a:	pushl %edi
0x00432a1b:	pushl $0x44fb4c<UINT32>
0x00432a20:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x00432a26:	movl %esi, 0x449330
0x00432a2c:	movl %edi, %eax
0x00432a2e:	pushl $0x454658<UINT32>
0x00432a33:	pushl %edi
0x00432a34:	call GetProcAddress@KERNEL32.dll
0x00432a36:	xorl %eax, 0x45f120
0x00432a3c:	pushl $0x454664<UINT32>
0x00432a41:	pushl %edi
0x00432a42:	movl 0x464440, %eax
0x00432a47:	call GetProcAddress@KERNEL32.dll
0x00432a49:	xorl %eax, 0x45f120
0x00432a4f:	pushl $0x45466c<UINT32>
0x00432a54:	pushl %edi
0x00432a55:	movl 0x464444, %eax
0x00432a5a:	call GetProcAddress@KERNEL32.dll
0x00432a5c:	xorl %eax, 0x45f120
0x00432a62:	pushl $0x454678<UINT32>
0x00432a67:	pushl %edi
0x00432a68:	movl 0x464448, %eax
0x00432a6d:	call GetProcAddress@KERNEL32.dll
0x00432a6f:	xorl %eax, 0x45f120
0x00432a75:	pushl $0x454684<UINT32>
0x00432a7a:	pushl %edi
0x00432a7b:	movl 0x46444c, %eax
0x00432a80:	call GetProcAddress@KERNEL32.dll
0x00432a82:	xorl %eax, 0x45f120
0x00432a88:	pushl $0x4546a0<UINT32>
0x00432a8d:	pushl %edi
0x00432a8e:	movl 0x464450, %eax
0x00432a93:	call GetProcAddress@KERNEL32.dll
0x00432a95:	xorl %eax, 0x45f120
0x00432a9b:	pushl $0x4546b0<UINT32>
0x00432aa0:	pushl %edi
0x00432aa1:	movl 0x464454, %eax
0x00432aa6:	call GetProcAddress@KERNEL32.dll
0x00432aa8:	xorl %eax, 0x45f120
0x00432aae:	pushl $0x4546c4<UINT32>
0x00432ab3:	pushl %edi
0x00432ab4:	movl 0x464458, %eax
0x00432ab9:	call GetProcAddress@KERNEL32.dll
0x00432abb:	xorl %eax, 0x45f120
0x00432ac1:	pushl $0x4546dc<UINT32>
0x00432ac6:	pushl %edi
0x00432ac7:	movl 0x46445c, %eax
0x00432acc:	call GetProcAddress@KERNEL32.dll
0x00432ace:	xorl %eax, 0x45f120
0x00432ad4:	pushl $0x4546f4<UINT32>
0x00432ad9:	pushl %edi
0x00432ada:	movl 0x464460, %eax
0x00432adf:	call GetProcAddress@KERNEL32.dll
0x00432ae1:	xorl %eax, 0x45f120
0x00432ae7:	pushl $0x454708<UINT32>
0x00432aec:	pushl %edi
0x00432aed:	movl 0x464464, %eax
0x00432af2:	call GetProcAddress@KERNEL32.dll
0x00432af4:	xorl %eax, 0x45f120
0x00432afa:	pushl $0x454728<UINT32>
0x00432aff:	pushl %edi
0x00432b00:	movl 0x464468, %eax
0x00432b05:	call GetProcAddress@KERNEL32.dll
0x00432b07:	xorl %eax, 0x45f120
0x00432b0d:	pushl $0x454740<UINT32>
0x00432b12:	pushl %edi
0x00432b13:	movl 0x46446c, %eax
0x00432b18:	call GetProcAddress@KERNEL32.dll
0x00432b1a:	xorl %eax, 0x45f120
0x00432b20:	pushl $0x454758<UINT32>
0x00432b25:	pushl %edi
0x00432b26:	movl 0x464470, %eax
0x00432b2b:	call GetProcAddress@KERNEL32.dll
0x00432b2d:	xorl %eax, 0x45f120
0x00432b33:	pushl $0x45476c<UINT32>
0x00432b38:	pushl %edi
0x00432b39:	movl 0x464474, %eax
0x00432b3e:	call GetProcAddress@KERNEL32.dll
0x00432b40:	xorl %eax, 0x45f120
0x00432b46:	movl 0x464478, %eax
0x00432b4b:	pushl $0x454780<UINT32>
0x00432b50:	pushl %edi
0x00432b51:	call GetProcAddress@KERNEL32.dll
0x00432b53:	xorl %eax, 0x45f120
0x00432b59:	pushl $0x45479c<UINT32>
0x00432b5e:	pushl %edi
0x00432b5f:	movl 0x46447c, %eax
0x00432b64:	call GetProcAddress@KERNEL32.dll
0x00432b66:	xorl %eax, 0x45f120
0x00432b6c:	pushl $0x4547bc<UINT32>
0x00432b71:	pushl %edi
0x00432b72:	movl 0x464480, %eax
0x00432b77:	call GetProcAddress@KERNEL32.dll
0x00432b79:	xorl %eax, 0x45f120
0x00432b7f:	pushl $0x4547d8<UINT32>
0x00432b84:	pushl %edi
0x00432b85:	movl 0x464484, %eax
0x00432b8a:	call GetProcAddress@KERNEL32.dll
0x00432b8c:	xorl %eax, 0x45f120
0x00432b92:	pushl $0x4547f8<UINT32>
0x00432b97:	pushl %edi
0x00432b98:	movl 0x464488, %eax
0x00432b9d:	call GetProcAddress@KERNEL32.dll
0x00432b9f:	xorl %eax, 0x45f120
0x00432ba5:	pushl $0x4503d4<UINT32>
0x00432baa:	pushl %edi
0x00432bab:	movl 0x46448c, %eax
0x00432bb0:	call GetProcAddress@KERNEL32.dll
0x00432bb2:	xorl %eax, 0x45f120
0x00432bb8:	pushl $0x45480c<UINT32>
0x00432bbd:	pushl %edi
0x00432bbe:	movl 0x464490, %eax
0x00432bc3:	call GetProcAddress@KERNEL32.dll
0x00432bc5:	xorl %eax, 0x45f120
0x00432bcb:	pushl $0x454820<UINT32>
0x00432bd0:	pushl %edi
0x00432bd1:	movl 0x464498, %eax
0x00432bd6:	call GetProcAddress@KERNEL32.dll
0x00432bd8:	xorl %eax, 0x45f120
0x00432bde:	pushl $0x454830<UINT32>
0x00432be3:	pushl %edi
0x00432be4:	movl 0x464494, %eax
0x00432be9:	call GetProcAddress@KERNEL32.dll
0x00432beb:	xorl %eax, 0x45f120
0x00432bf1:	pushl $0x454840<UINT32>
0x00432bf6:	pushl %edi
0x00432bf7:	movl 0x46449c, %eax
0x00432bfc:	call GetProcAddress@KERNEL32.dll
0x00432bfe:	xorl %eax, 0x45f120
0x00432c04:	pushl $0x454850<UINT32>
0x00432c09:	pushl %edi
0x00432c0a:	movl 0x4644a0, %eax
0x00432c0f:	call GetProcAddress@KERNEL32.dll
0x00432c11:	xorl %eax, 0x45f120
0x00432c17:	pushl $0x454860<UINT32>
0x00432c1c:	pushl %edi
0x00432c1d:	movl 0x4644a4, %eax
0x00432c22:	call GetProcAddress@KERNEL32.dll
0x00432c24:	xorl %eax, 0x45f120
0x00432c2a:	pushl $0x45487c<UINT32>
0x00432c2f:	pushl %edi
0x00432c30:	movl 0x4644a8, %eax
0x00432c35:	call GetProcAddress@KERNEL32.dll
0x00432c37:	xorl %eax, 0x45f120
0x00432c3d:	pushl $0x454890<UINT32>
0x00432c42:	pushl %edi
0x00432c43:	movl 0x4644ac, %eax
0x00432c48:	call GetProcAddress@KERNEL32.dll
0x00432c4a:	xorl %eax, 0x45f120
0x00432c50:	pushl $0x4548a0<UINT32>
0x00432c55:	pushl %edi
0x00432c56:	movl 0x4644b0, %eax
0x00432c5b:	call GetProcAddress@KERNEL32.dll
0x00432c5d:	xorl %eax, 0x45f120
0x00432c63:	pushl $0x4548b4<UINT32>
0x00432c68:	pushl %edi
0x00432c69:	movl 0x4644b4, %eax
0x00432c6e:	call GetProcAddress@KERNEL32.dll
0x00432c70:	xorl %eax, 0x45f120
0x00432c76:	movl 0x4644b8, %eax
0x00432c7b:	pushl $0x4548c4<UINT32>
0x00432c80:	pushl %edi
0x00432c81:	call GetProcAddress@KERNEL32.dll
0x00432c83:	xorl %eax, 0x45f120
0x00432c89:	pushl $0x4548e4<UINT32>
0x00432c8e:	pushl %edi
0x00432c8f:	movl 0x4644bc, %eax
0x00432c94:	call GetProcAddress@KERNEL32.dll
0x00432c96:	xorl %eax, 0x45f120
0x00432c9c:	popl %edi
0x00432c9d:	movl 0x4644c0, %eax
0x00432ca2:	popl %esi
0x00432ca3:	ret

0x004325e3:	call 0x004328bc
0x004328bc:	pushl %esi
0x004328bd:	pushl %edi
0x004328be:	movl %esi, $0x45fa28<UINT32>
0x004328c3:	movl %edi, $0x4628f8<UINT32>
0x004328c8:	cmpl 0x4(%esi), $0x1<UINT8>
0x004328cc:	jne 22
0x004328ce:	pushl $0x0<UINT8>
0x004328d0:	movl (%esi), %edi
0x004328d2:	addl %edi, $0x18<UINT8>
0x004328d5:	pushl $0xfa0<UINT32>
0x004328da:	pushl (%esi)
0x004328dc:	call 0x004329ab
0x004329ab:	pushl %ebp
0x004329ac:	movl %ebp, %esp
0x004329ae:	movl %eax, 0x464450
0x004329b3:	xorl %eax, 0x45f120
0x004329b9:	je 13
0x004329bb:	pushl 0x10(%ebp)
0x004329be:	pushl 0xc(%ebp)
0x004329c1:	pushl 0x8(%ebp)
0x004329c4:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x004329c6:	popl %ebp
0x004329c7:	ret

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
