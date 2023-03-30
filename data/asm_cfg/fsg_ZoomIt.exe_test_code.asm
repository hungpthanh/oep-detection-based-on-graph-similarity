0x004fd000:	movl %ebx, $0x4001d0<UINT32>
0x004fd005:	movl %edi, $0x401000<UINT32>
0x004fd00a:	movl %esi, $0x4dded9<UINT32>
0x004fd00f:	pushl %ebx
0x004fd010:	call 0x004fd01f
0x004fd01f:	cld
0x004fd020:	movb %dl, $0xffffff80<UINT8>
0x004fd022:	movsb %es:(%edi), %ds:(%esi)
0x004fd023:	pushl $0x2<UINT8>
0x004fd025:	popl %ebx
0x004fd026:	call 0x004fd015
0x004fd015:	addb %dl, %dl
0x004fd017:	jne 0x004fd01e
0x004fd019:	movb %dl, (%esi)
0x004fd01b:	incl %esi
0x004fd01c:	adcb %dl, %dl
0x004fd01e:	ret

0x004fd029:	jae 0x004fd022
0x004fd02b:	xorl %ecx, %ecx
0x004fd02d:	call 0x004fd015
0x004fd030:	jae 0x004fd04a
0x004fd032:	xorl %eax, %eax
0x004fd034:	call 0x004fd015
0x004fd037:	jae 0x004fd05a
0x004fd039:	movb %bl, $0x2<UINT8>
0x004fd03b:	incl %ecx
0x004fd03c:	movb %al, $0x10<UINT8>
0x004fd03e:	call 0x004fd015
0x004fd041:	adcb %al, %al
0x004fd043:	jae 0x004fd03e
0x004fd045:	jne 0x004fd086
0x004fd086:	pushl %esi
0x004fd087:	movl %esi, %edi
0x004fd089:	subl %esi, %eax
0x004fd08b:	rep movsb %es:(%edi), %ds:(%esi)
0x004fd08d:	popl %esi
0x004fd08e:	jmp 0x004fd026
0x004fd04a:	call 0x004fd092
0x004fd092:	incl %ecx
0x004fd093:	call 0x004fd015
0x004fd097:	adcl %ecx, %ecx
0x004fd099:	call 0x004fd015
0x004fd09d:	jb 0x004fd093
0x004fd09f:	ret

0x004fd04f:	subl %ecx, %ebx
0x004fd051:	jne 0x004fd063
0x004fd063:	xchgl %ecx, %eax
0x004fd064:	decl %eax
0x004fd065:	shll %eax, $0x8<UINT8>
0x004fd068:	lodsb %al, %ds:(%esi)
0x004fd069:	call 0x004fd090
0x004fd090:	xorl %ecx, %ecx
0x004fd06e:	cmpl %eax, $0x7d00<UINT32>
0x004fd073:	jae 0x004fd07f
0x004fd075:	cmpb %ah, $0x5<UINT8>
0x004fd078:	jae 0x004fd080
0x004fd07a:	cmpl %eax, $0x7f<UINT8>
0x004fd07d:	ja 0x004fd081
0x004fd07f:	incl %ecx
0x004fd080:	incl %ecx
0x004fd081:	xchgl %ebp, %eax
0x004fd082:	movl %eax, %ebp
0x004fd084:	movb %bl, $0x1<UINT8>
0x004fd047:	stosb %es:(%edi), %al
0x004fd048:	jmp 0x004fd026
0x004fd05a:	lodsb %al, %ds:(%esi)
0x004fd05b:	shrl %eax
0x004fd05d:	je 0x004fd0a0
0x004fd05f:	adcl %ecx, %ecx
0x004fd061:	jmp 0x004fd07f
0x004fd053:	call 0x004fd090
0x004fd058:	jmp 0x004fd082
0x004fd0a0:	popl %edi
0x004fd0a1:	popl %ebx
0x004fd0a2:	movzwl %edi, (%ebx)
0x004fd0a5:	decl %edi
0x004fd0a6:	je 0x004fd0b0
0x004fd0a8:	decl %edi
0x004fd0a9:	je 0x004fd0be
0x004fd0ab:	shll %edi, $0xc<UINT8>
0x004fd0ae:	jmp 0x004fd0b7
0x004fd0b7:	incl %ebx
0x004fd0b8:	incl %ebx
0x004fd0b9:	jmp 0x004fd00f
0x004fd0b0:	movl %edi, 0x2(%ebx)
0x004fd0b3:	pushl %edi
0x004fd0b4:	addl %ebx, $0x4<UINT8>
0x004fd0be:	popl %edi
0x004fd0bf:	movl %ebx, $0x4fd128<UINT32>
0x004fd0c4:	incl %edi
0x004fd0c5:	movl %esi, (%edi)
0x004fd0c7:	scasl %eax, %es:(%edi)
0x004fd0c8:	pushl %edi
0x004fd0c9:	call LoadLibraryA@KERNEL32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004fd0cb:	xchgl %ebp, %eax
0x004fd0cc:	xorl %eax, %eax
0x004fd0ce:	scasb %al, %es:(%edi)
0x004fd0cf:	jne 0x004fd0ce
0x004fd0d1:	decb (%edi)
0x004fd0d3:	je 0x004fd0c4
0x004fd0d5:	decb (%edi)
0x004fd0d7:	jne 0x004fd0df
0x004fd0d9:	incl %edi
0x004fd0da:	pushl (%edi)
0x004fd0dc:	scasl %eax, %es:(%edi)
0x004fd0dd:	jmp 0x004fd0e8
0x004fd0e8:	pushl %ebp
0x004fd0e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x004fd0ec:	orl (%esi), %eax
0x004fd0ee:	lodsl %eax, %ds:(%esi)
0x004fd0ef:	jne 0x004fd0cc
0x004fd0df:	decb (%edi)
0x004fd0e1:	je 0x0040c424
0x004fd0e7:	pushl %edi
GetProcAddress@KERNEL32.dll: API Node	
LoadLibraryA@KERNEL32.dll: API Node	
0x0040c424:	call 0x00416897
0x00416897:	pushl %ebp
0x00416898:	movl %ebp, %esp
0x0041689a:	subl %esp, $0x14<UINT8>
0x0041689d:	movl %eax, 0x43c650
0x004168a2:	andl -12(%ebp), $0x0<UINT8>
0x004168a6:	andl -8(%ebp), $0x0<UINT8>
0x004168aa:	pushl %esi
0x004168ab:	pushl %edi
0x004168ac:	movl %edi, $0xbb40e64e<UINT32>
0x004168b1:	movl %esi, $0xffff0000<UINT32>
0x004168b6:	cmpl %eax, %edi
0x004168b8:	je 0x004168c7
0x004168c7:	leal %eax, -12(%ebp)
0x004168ca:	pushl %eax
0x004168cb:	call GetSystemTimeAsFileTime@KERNEL32.dll
GetSystemTimeAsFileTime@KERNEL32.dll: API Node	
0x004168d1:	movl %eax, -8(%ebp)
0x004168d4:	xorl %eax, -12(%ebp)
0x004168d7:	movl -4(%ebp), %eax
0x004168da:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x004168e0:	xorl -4(%ebp), %eax
0x004168e3:	call GetCurrentProcessId@KERNEL32.dll
GetCurrentProcessId@KERNEL32.dll: API Node	
0x004168e9:	xorl -4(%ebp), %eax
0x004168ec:	leal %eax, -20(%ebp)
0x004168ef:	pushl %eax
0x004168f0:	call QueryPerformanceCounter@KERNEL32.dll
QueryPerformanceCounter@KERNEL32.dll: API Node	
0x004168f6:	movl %ecx, -16(%ebp)
0x004168f9:	xorl %ecx, -20(%ebp)
0x004168fc:	leal %eax, -4(%ebp)
0x004168ff:	xorl %ecx, -4(%ebp)
0x00416902:	xorl %ecx, %eax
0x00416904:	cmpl %ecx, %edi
0x00416906:	jne 0x0041690f
0x0041690f:	testl %esi, %ecx
0x00416911:	jne 0x0041691f
0x0041691f:	movl 0x43c650, %ecx
0x00416925:	notl %ecx
0x00416927:	movl 0x43c654, %ecx
0x0041692d:	popl %edi
0x0041692e:	popl %esi
0x0041692f:	leave
0x00416930:	ret

0x0040c429:	jmp 0x0040c42e
0x0040c42e:	pushl $0x14<UINT8>
0x0040c430:	pushl $0x439fd0<UINT32>
0x0040c435:	call 0x00410c00
0x00410c00:	pushl $0x410ca0<UINT32>
0x00410c05:	pushl %fs:0
0x00410c0c:	movl %eax, 0x10(%esp)
0x00410c10:	movl 0x10(%esp), %ebp
0x00410c14:	leal %ebp, 0x10(%esp)
0x00410c18:	subl %esp, %eax
0x00410c1a:	pushl %ebx
0x00410c1b:	pushl %esi
0x00410c1c:	pushl %edi
0x00410c1d:	movl %eax, 0x43c650
0x00410c22:	xorl -4(%ebp), %eax
0x00410c25:	xorl %eax, %ebp
0x00410c27:	pushl %eax
0x00410c28:	movl -24(%ebp), %esp
0x00410c2b:	pushl -8(%ebp)
0x00410c2e:	movl %eax, -4(%ebp)
0x00410c31:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00410c38:	movl -8(%ebp), %eax
0x00410c3b:	leal %eax, -16(%ebp)
0x00410c3e:	movl %fs:0, %eax
0x00410c44:	ret

0x0040c43a:	call 0x00416bc9
0x00416bc9:	pushl %ebp
0x00416bca:	movl %ebp, %esp
0x00416bcc:	subl %esp, $0x44<UINT8>
0x00416bcf:	leal %eax, -68(%ebp)
0x00416bd2:	pushl %eax
0x00416bd3:	call GetStartupInfoW@KERNEL32.dll
GetStartupInfoW@KERNEL32.dll: API Node	
0x00416bd9:	testb -24(%ebp), $0x1<UINT8>
0x00416bdd:	je 0x00416be5
0x00416be5:	pushl $0xa<UINT8>
0x00416be7:	popl %eax
0x00416be8:	leave
0x00416be9:	ret

0x0040c43f:	movzwl %esi, %ax
0x0040c442:	pushl $0x2<UINT8>
0x0040c444:	call 0x0041684a
0x0041684a:	pushl %ebp
0x0041684b:	movl %ebp, %esp
0x0041684d:	movl %eax, 0x8(%ebp)
0x00416850:	movl 0x43e218, %eax
0x00416855:	popl %ebp
0x00416856:	ret

0x0040c449:	popl %ecx
0x0040c44a:	movl %eax, $0x5a4d<UINT32>
0x0040c44f:	cmpw 0x400000, %ax
0x0040c456:	je 0x0040c45c
0x0040c45c:	movl %eax, 0x40003c
0x0040c461:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x0040c46b:	jne -21
0x0040c46d:	movl %ecx, $0x10b<UINT32>
0x0040c472:	cmpw 0x400018(%eax), %cx
0x0040c479:	jne -35
0x0040c47b:	xorl %ebx, %ebx
0x0040c47d:	cmpl 0x400074(%eax), $0xe<UINT8>
0x0040c484:	jbe 9
0x0040c486:	cmpl 0x4000e8(%eax), %ebx
0x0040c48c:	setne %bl
0x0040c48f:	movl -28(%ebp), %ebx
0x0040c492:	call 0x0040eb1b
0x0040eb1b:	call GetProcessHeap@KERNEL32.dll
GetProcessHeap@KERNEL32.dll: API Node	
0x0040eb21:	xorl %ecx, %ecx
0x0040eb23:	testl %eax, %eax
0x0040eb25:	setne %cl
0x0040eb28:	movl 0x43e1d8, %eax
0x0040eb2d:	movl %eax, %ecx
0x0040eb2f:	ret

0x0040c497:	testl %eax, %eax
0x0040c499:	jne 0x0040c4a3
0x0040c4a3:	call 0x0040d69b
0x0040d69b:	call 0x0040eefb
0x0040eefb:	pushl %esi
0x0040eefc:	pushl $0x0<UINT8>
0x0040eefe:	call EncodePointer@KERNEL32.dll
EncodePointer@KERNEL32.dll: API Node	
0x0040ef04:	movl %esi, %eax
0x0040ef06:	pushl %esi
0x0040ef07:	call 0x0040eba9
0x0040eba9:	pushl %ebp
0x0040ebaa:	movl %ebp, %esp
0x0040ebac:	movl %eax, 0x8(%ebp)
0x0040ebaf:	movl 0x43e1dc, %eax
0x0040ebb4:	popl %ebp
0x0040ebb5:	ret

0x0040ef0c:	pushl %esi
0x0040ef0d:	call 0x0040c738
0x0040c738:	pushl %ebp
0x0040c739:	movl %ebp, %esp
0x0040c73b:	movl %eax, 0x8(%ebp)
0x0040c73e:	movl 0x43e1b4, %eax
0x0040c743:	popl %ebp
0x0040c744:	ret

0x0040ef12:	pushl %esi
0x0040ef13:	call 0x0041da78
0x0041da78:	pushl %ebp
0x0041da79:	movl %ebp, %esp
0x0041da7b:	movl %eax, 0x8(%ebp)
0x0041da7e:	movl 0x43ef00, %eax
0x0041da83:	popl %ebp
0x0041da84:	ret

0x0040ef18:	pushl %esi
0x0040ef19:	call 0x0041da85
0x0041da85:	pushl %ebp
0x0041da86:	movl %ebp, %esp
0x0041da88:	movl %eax, 0x8(%ebp)
0x0041da8b:	movl 0x43ef04, %eax
0x0041da90:	popl %ebp
0x0041da91:	ret

0x0040ef1e:	pushl %esi
0x0040ef1f:	call 0x0041dbbf
0x0041dbbf:	pushl %ebp
0x0041dbc0:	movl %ebp, %esp
0x0041dbc2:	movl %eax, 0x8(%ebp)
0x0041dbc5:	movl 0x43ef08, %eax
0x0041dbca:	movl 0x43ef0c, %eax
0x0041dbcf:	movl 0x43ef10, %eax
0x0041dbd4:	movl 0x43ef14, %eax
0x0041dbd9:	popl %ebp
0x0041dbda:	ret

0x0040ef24:	pushl %esi
0x0040ef25:	call 0x0041d890
0x0041d890:	pushl $0x41d849<UINT32>
0x0041d895:	call EncodePointer@KERNEL32.dll
0x0041d89b:	movl 0x43eefc, %eax
0x0041d8a0:	ret

0x0040ef2a:	addl %esp, $0x18<UINT8>
0x0040ef2d:	popl %esi
0x0040ef2e:	jmp 0x00416c56
0x00416c56:	pushl %esi
0x00416c57:	pushl %edi
0x00416c58:	pushl $0x4355a8<UINT32>
0x00416c5d:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x00416c63:	movl %esi, 0x4311ec
0x00416c69:	movl %edi, %eax
0x00416c6b:	pushl $0x4355c4<UINT32>
0x00416c70:	pushl %edi
0x00416c71:	call GetProcAddress@KERNEL32.dll
0x00416c73:	xorl %eax, 0x43c650
0x00416c79:	pushl $0x4355d0<UINT32>
0x00416c7e:	pushl %edi
0x00416c7f:	movl 0x43efc0, %eax
0x00416c84:	call GetProcAddress@KERNEL32.dll
0x00416c86:	xorl %eax, 0x43c650
0x00416c8c:	pushl $0x4355d8<UINT32>
0x00416c91:	pushl %edi
0x00416c92:	movl 0x43efc4, %eax
0x00416c97:	call GetProcAddress@KERNEL32.dll
0x00416c99:	xorl %eax, 0x43c650
0x00416c9f:	pushl $0x4355e4<UINT32>
0x00416ca4:	pushl %edi
0x00416ca5:	movl 0x43efc8, %eax
0x00416caa:	call GetProcAddress@KERNEL32.dll
0x00416cac:	xorl %eax, 0x43c650
0x00416cb2:	pushl $0x4355f0<UINT32>
0x00416cb7:	pushl %edi
0x00416cb8:	movl 0x43efcc, %eax
0x00416cbd:	call GetProcAddress@KERNEL32.dll
0x00416cbf:	xorl %eax, 0x43c650
0x00416cc5:	pushl $0x43560c<UINT32>
0x00416cca:	pushl %edi
0x00416ccb:	movl 0x43efd0, %eax
0x00416cd0:	call GetProcAddress@KERNEL32.dll
0x00416cd2:	xorl %eax, 0x43c650
0x00416cd8:	pushl $0x435620<UINT32>
0x00416cdd:	pushl %edi
0x00416cde:	movl 0x43efd4, %eax
0x00416ce3:	call GetProcAddress@KERNEL32.dll
0x00416ce5:	xorl %eax, 0x43c650
0x00416ceb:	pushl $0x435638<UINT32>
0x00416cf0:	pushl %edi
0x00416cf1:	movl 0x43efd8, %eax
0x00416cf6:	call GetProcAddress@KERNEL32.dll
0x00416cf8:	xorl %eax, 0x43c650
0x00416cfe:	pushl $0x435650<UINT32>
0x00416d03:	pushl %edi
0x00416d04:	movl 0x43efdc, %eax
0x00416d09:	call GetProcAddress@KERNEL32.dll
0x00416d0b:	xorl %eax, 0x43c650
0x00416d11:	pushl $0x435664<UINT32>
0x00416d16:	pushl %edi
0x00416d17:	movl 0x43efe0, %eax
0x00416d1c:	call GetProcAddress@KERNEL32.dll
0x00416d1e:	xorl %eax, 0x43c650
0x00416d24:	pushl $0x435684<UINT32>
0x00416d29:	pushl %edi
0x00416d2a:	movl 0x43efe4, %eax
0x00416d2f:	call GetProcAddress@KERNEL32.dll
0x00416d31:	xorl %eax, 0x43c650
0x00416d37:	pushl $0x43569c<UINT32>
0x00416d3c:	pushl %edi
0x00416d3d:	movl 0x43efe8, %eax
0x00416d42:	call GetProcAddress@KERNEL32.dll
0x00416d44:	xorl %eax, 0x43c650
0x00416d4a:	pushl $0x4356b4<UINT32>
0x00416d4f:	pushl %edi
0x00416d50:	movl 0x43efec, %eax
0x00416d55:	call GetProcAddress@KERNEL32.dll
0x00416d57:	xorl %eax, 0x43c650
0x00416d5d:	pushl $0x4356c8<UINT32>
0x00416d62:	pushl %edi
0x00416d63:	movl 0x43eff0, %eax
0x00416d68:	call GetProcAddress@KERNEL32.dll
0x00416d6a:	xorl %eax, 0x43c650
0x00416d70:	pushl $0x4356dc<UINT32>
0x00416d75:	pushl %edi
0x00416d76:	movl 0x43eff4, %eax
0x00416d7b:	call GetProcAddress@KERNEL32.dll
0x00416d7d:	xorl %eax, 0x43c650
0x00416d83:	movl 0x43eff8, %eax
0x00416d88:	pushl $0x4356f8<UINT32>
0x00416d8d:	pushl %edi
0x00416d8e:	call GetProcAddress@KERNEL32.dll
0x00416d90:	xorl %eax, 0x43c650
0x00416d96:	pushl $0x435718<UINT32>
0x00416d9b:	pushl %edi
0x00416d9c:	movl 0x43effc, %eax
0x00416da1:	call GetProcAddress@KERNEL32.dll
0x00416da3:	xorl %eax, 0x43c650
0x00416da9:	pushl $0x435734<UINT32>
0x00416dae:	pushl %edi
0x00416daf:	movl 0x43f000, %eax
0x00416db4:	call GetProcAddress@KERNEL32.dll
0x00416db6:	xorl %eax, 0x43c650
0x00416dbc:	pushl $0x435754<UINT32>
0x00416dc1:	pushl %edi
0x00416dc2:	movl 0x43f004, %eax
0x00416dc7:	call GetProcAddress@KERNEL32.dll
0x00416dc9:	xorl %eax, 0x43c650
0x00416dcf:	pushl $0x435768<UINT32>
0x00416dd4:	pushl %edi
0x00416dd5:	movl 0x43f008, %eax
0x00416dda:	call GetProcAddress@KERNEL32.dll
0x00416ddc:	xorl %eax, 0x43c650
0x00416de2:	pushl $0x435784<UINT32>
0x00416de7:	pushl %edi
0x00416de8:	movl 0x43f00c, %eax
0x00416ded:	call GetProcAddress@KERNEL32.dll
0x00416def:	xorl %eax, 0x43c650
0x00416df5:	pushl $0x435798<UINT32>
0x00416dfa:	pushl %edi
0x00416dfb:	movl 0x43f014, %eax
0x00416e00:	call GetProcAddress@KERNEL32.dll
0x00416e02:	xorl %eax, 0x43c650
0x00416e08:	pushl $0x4357a8<UINT32>
0x00416e0d:	pushl %edi
0x00416e0e:	movl 0x43f010, %eax
0x00416e13:	call GetProcAddress@KERNEL32.dll
0x00416e15:	xorl %eax, 0x43c650
0x00416e1b:	pushl $0x4357b8<UINT32>
0x00416e20:	pushl %edi
0x00416e21:	movl 0x43f018, %eax
0x00416e26:	call GetProcAddress@KERNEL32.dll
0x00416e28:	xorl %eax, 0x43c650
0x00416e2e:	pushl $0x4357c8<UINT32>
0x00416e33:	pushl %edi
0x00416e34:	movl 0x43f01c, %eax
0x00416e39:	call GetProcAddress@KERNEL32.dll
0x00416e3b:	xorl %eax, 0x43c650
0x00416e41:	pushl $0x4357d8<UINT32>
0x00416e46:	pushl %edi
0x00416e47:	movl 0x43f020, %eax
0x00416e4c:	call GetProcAddress@KERNEL32.dll
0x00416e4e:	xorl %eax, 0x43c650
0x00416e54:	pushl $0x4357f4<UINT32>
0x00416e59:	pushl %edi
0x00416e5a:	movl 0x43f024, %eax
0x00416e5f:	call GetProcAddress@KERNEL32.dll
0x00416e61:	xorl %eax, 0x43c650
0x00416e67:	pushl $0x435808<UINT32>
0x00416e6c:	pushl %edi
0x00416e6d:	movl 0x43f028, %eax
0x00416e72:	call GetProcAddress@KERNEL32.dll
0x00416e74:	xorl %eax, 0x43c650
0x00416e7a:	pushl $0x435818<UINT32>
0x00416e7f:	pushl %edi
0x00416e80:	movl 0x43f02c, %eax
0x00416e85:	call GetProcAddress@KERNEL32.dll
0x00416e87:	xorl %eax, 0x43c650
0x00416e8d:	popl %edi
0x00416e8e:	movl 0x43f030, %eax
0x00416e93:	popl %esi
0x00416e94:	ret

0x0040d6a0:	call 0x004170f8
0x004170f8:	pushl %esi
0x004170f9:	pushl %edi
0x004170fa:	movl %esi, $0x43d260<UINT32>
0x004170ff:	movl %edi, $0x43eda0<UINT32>
0x00417104:	cmpl 0x4(%esi), $0x1<UINT8>
0x00417108:	jne 0x0041711c
0x0041710a:	movl (%esi), %edi
0x0041710c:	pushl $0xfa0<UINT32>
0x00417111:	pushl (%esi)
0x00417113:	addl %edi, $0x18<UINT8>
0x00417116:	call InitializeCriticalSectionAndSpinCount@KERNEL32.dll
InitializeCriticalSectionAndSpinCount@KERNEL32.dll: API Node	
0x0041711c:	addl %esi, $0x8<UINT8>
0x0041711f:	cmpl %esi, $0x43d380<UINT32>
0x00417125:	jl 0x00417104
0x00417127:	xorl %eax, %eax
0x00417129:	popl %edi
0x0041712a:	incl %eax
0x0041712b:	popl %esi
0x0041712c:	ret

0x0040d6a5:	testl %eax, %eax
0x0040d6a7:	jne 0x0040d6b1
0x0040d6b1:	pushl $0x40d3f4<UINT32>
0x0040d6b6:	call 0x00416ae9
0x00416ae9:	pushl %ebp
0x00416aea:	movl %ebp, %esp
0x00416aec:	movl %eax, 0x43efc0
0x00416af1:	xorl %eax, 0x43c650
0x00416af7:	je 7
0x00416af9:	pushl 0x8(%ebp)
0x00416afc:	call FlsAlloc@kernel32.dll
FlsAlloc@kernel32.dll: API Node	
0x00416afe:	popl %ebp
0x00416aff:	ret

0x0040d6bb:	popl %ecx
0x0040d6bc:	movl 0x43cba0, %eax
0x0040d6c1:	cmpl %eax, $0xffffffff<UINT8>
0x0040d6c4:	je -29
0x0040d6c6:	pushl %esi
0x0040d6c7:	pushl $0x3bc<UINT32>
0x0040d6cc:	pushl $0x1<UINT8>
0x0040d6ce:	call 0x00410a94
0x00410a94:	pushl %ebp
0x00410a95:	movl %ebp, %esp
0x00410a97:	pushl %esi
0x00410a98:	pushl %edi
0x00410a99:	xorl %esi, %esi
0x00410a9b:	pushl $0x0<UINT8>
0x00410a9d:	pushl 0xc(%ebp)
0x00410aa0:	pushl 0x8(%ebp)
0x00410aa3:	call 0x00420c29
0x00420c29:	pushl %ebp
0x00420c2a:	movl %ebp, %esp
0x00420c2c:	pushl %esi
0x00420c2d:	movl %esi, 0x8(%ebp)
0x00420c30:	testl %esi, %esi
0x00420c32:	je 27
0x00420c34:	pushl $0xffffffe0<UINT8>
0x00420c36:	xorl %edx, %edx
0x00420c38:	popl %eax
0x00420c39:	divl %eax, %esi
0x00420c3b:	cmpl %eax, 0xc(%ebp)
0x00420c3e:	jae 0x00420c4f
0x00420c4f:	imull %esi, 0xc(%ebp)
0x00420c53:	testl %esi, %esi
0x00420c55:	jne 0x00420c58
0x00420c58:	xorl %ecx, %ecx
0x00420c5a:	cmpl %esi, $0xffffffe0<UINT8>
0x00420c5d:	ja 21
0x00420c5f:	pushl %esi
0x00420c60:	pushl $0x8<UINT8>
0x00420c62:	pushl 0x43e1d8
0x00420c68:	call HeapAlloc@KERNEL32.dll
HeapAlloc@KERNEL32.dll: API Node	
0x00420c6e:	movl %ecx, %eax
0x00420c70:	testl %ecx, %ecx
0x00420c72:	jne 0x00420c9e
0x00420c9e:	movl %eax, %ecx
0x00420ca0:	popl %esi
0x00420ca1:	popl %ebp
0x00420ca2:	ret

0x00410aa8:	movl %edi, %eax
0x00410aaa:	addl %esp, $0xc<UINT8>
0x00410aad:	testl %edi, %edi
0x00410aaf:	jne 0x00410ad8
0x00410ad8:	movl %eax, %edi
0x00410ada:	popl %edi
0x00410adb:	popl %esi
0x00410adc:	popl %ebp
0x00410add:	ret

0x0040d6d3:	movl %esi, %eax
0x0040d6d5:	popl %ecx
0x0040d6d6:	popl %ecx
0x0040d6d7:	testl %esi, %esi
0x0040d6d9:	je 45
0x0040d6db:	pushl %esi
0x0040d6dc:	pushl 0x43cba0
0x0040d6e2:	call 0x00416b45
0x00416b45:	pushl %ebp
0x00416b46:	movl %ebp, %esp
0x00416b48:	movl %eax, 0x43efcc
0x00416b4d:	xorl %eax, 0x43c650
0x00416b53:	pushl 0xc(%ebp)
0x00416b56:	pushl 0x8(%ebp)
0x00416b59:	je 4
0x00416b5b:	call FlsSetValue@kernel32.dll
FlsSetValue@kernel32.dll: API Node	
0x00416b5d:	popl %ebp
0x00416b5e:	ret

0x0040d6e7:	popl %ecx
0x0040d6e8:	popl %ecx
0x0040d6e9:	testl %eax, %eax
0x0040d6eb:	je 27
0x0040d6ed:	pushl $0x0<UINT8>
0x0040d6ef:	pushl %esi
0x0040d6f0:	call 0x0040d5e8
0x0040d5e8:	pushl $0x8<UINT8>
0x0040d5ea:	pushl $0x43a078<UINT32>
0x0040d5ef:	call 0x00410c00
0x0040d5f4:	movl %esi, 0x8(%ebp)
0x0040d5f7:	movl 0x5c(%esi), $0x435508<UINT32>
0x0040d5fe:	andl 0x8(%esi), $0x0<UINT8>
0x0040d602:	xorl %edi, %edi
0x0040d604:	incl %edi
0x0040d605:	movl 0x14(%esi), %edi
0x0040d608:	movl 0x70(%esi), %edi
0x0040d60b:	pushl $0x43<UINT8>
0x0040d60d:	popl %eax
0x0040d60e:	movw 0xb8(%esi), %ax
0x0040d615:	movw 0x1be(%esi), %ax
0x0040d61c:	movl 0x68(%esi), $0x43c980<UINT32>
0x0040d623:	andl 0x3b8(%esi), $0x0<UINT8>
0x0040d62a:	pushl $0xd<UINT8>
0x0040d62c:	call 0x00416fa7
0x00416fa7:	pushl %ebp
0x00416fa8:	movl %ebp, %esp
0x00416faa:	pushl %esi
0x00416fab:	movl %esi, 0x8(%ebp)
0x00416fae:	cmpl 0x43d260(,%esi,8), $0x0<UINT8>
0x00416fb6:	jne 0x00416fcb
0x00416fcb:	pushl 0x43d260(,%esi,8)
0x00416fd2:	call EnterCriticalSection@KERNEL32.dll
EnterCriticalSection@KERNEL32.dll: API Node	
0x00416fd8:	popl %esi
0x00416fd9:	popl %ebp
0x00416fda:	ret

0x0040d631:	popl %ecx
0x0040d632:	andl -4(%ebp), $0x0<UINT8>
0x0040d636:	pushl 0x68(%esi)
0x0040d639:	call InterlockedIncrement@KERNEL32.dll
InterlockedIncrement@KERNEL32.dll: API Node	
0x0040d63f:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040d646:	call 0x0040d689
0x0040d689:	pushl $0xd<UINT8>
0x0040d68b:	call 0x0041712d
0x0041712d:	pushl %ebp
0x0041712e:	movl %ebp, %esp
0x00417130:	movl %eax, 0x8(%ebp)
0x00417133:	pushl 0x43d260(,%eax,8)
0x0041713a:	call LeaveCriticalSection@KERNEL32.dll
LeaveCriticalSection@KERNEL32.dll: API Node	
0x00417140:	popl %ebp
0x00417141:	ret

0x0040d690:	popl %ecx
0x0040d691:	ret

0x0040d64b:	pushl $0xc<UINT8>
0x0040d64d:	call 0x00416fa7
0x0040d652:	popl %ecx
0x0040d653:	movl -4(%ebp), %edi
0x0040d656:	movl %eax, 0xc(%ebp)
0x0040d659:	movl 0x6c(%esi), %eax
0x0040d65c:	testl %eax, %eax
0x0040d65e:	jne 8
0x0040d660:	movl %eax, 0x43ce84
0x0040d665:	movl 0x6c(%esi), %eax
0x0040d668:	pushl 0x6c(%esi)
0x0040d66b:	call 0x0040c7eb
0x0040c7eb:	pushl %ebp
0x0040c7ec:	movl %ebp, %esp
0x0040c7ee:	pushl %ebx
0x0040c7ef:	pushl %esi
0x0040c7f0:	movl %esi, 0x431188
0x0040c7f6:	pushl %edi
0x0040c7f7:	movl %edi, 0x8(%ebp)
0x0040c7fa:	pushl %edi
0x0040c7fb:	call InterlockedIncrement@KERNEL32.dll
0x0040c7fd:	cmpl 0x78(%edi), $0x0<UINT8>
0x0040c801:	je 0x0040c808
0x0040c808:	movl %eax, 0x80(%edi)
0x0040c80e:	testl %eax, %eax
0x0040c810:	je 0x0040c815
0x0040c815:	cmpl 0x7c(%edi), $0x0<UINT8>
0x0040c819:	je 0x0040c820
0x0040c820:	movl %eax, 0x88(%edi)
0x0040c826:	testl %eax, %eax
0x0040c828:	je 0x0040c82d
0x0040c82d:	pushl $0x6<UINT8>
0x0040c82f:	popl %eax
0x0040c830:	leal %ebx, 0x1c(%edi)
0x0040c833:	movl 0x8(%ebp), %eax
0x0040c836:	cmpl -8(%ebx), $0x43cd18<UINT32>
0x0040c83d:	je 0x0040c84b
0x0040c83f:	cmpl (%ebx), $0x0<UINT8>
0x0040c842:	je 0x0040c84b
0x0040c84b:	cmpl -12(%ebx), $0x0<UINT8>
0x0040c84f:	je 0x0040c85f
0x0040c85f:	addl %ebx, $0x10<UINT8>
0x0040c862:	decl %eax
0x0040c863:	movl 0x8(%ebp), %eax
0x0040c866:	jne 0x0040c836
0x0040c868:	movl %eax, 0x9c(%edi)
0x0040c86e:	addl %eax, $0xb0<UINT32>
0x0040c873:	pushl %eax
0x0040c874:	call InterlockedIncrement@KERNEL32.dll
0x0040c876:	popl %edi
0x0040c877:	popl %esi
0x0040c878:	popl %ebx
0x0040c879:	popl %ebp
0x0040c87a:	ret

0x0040d670:	popl %ecx
0x0040d671:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040d678:	call 0x0040d692
0x0040d692:	pushl $0xc<UINT8>
0x0040d694:	call 0x0041712d
0x0040d699:	popl %ecx
0x0040d69a:	ret

0x0040d67d:	call 0x00410c45
0x00410c45:	movl %ecx, -16(%ebp)
0x00410c48:	movl %fs:0, %ecx
0x00410c4f:	popl %ecx
0x00410c50:	popl %edi
0x00410c51:	popl %edi
0x00410c52:	popl %esi
0x00410c53:	popl %ebx
0x00410c54:	movl %esp, %ebp
0x00410c56:	popl %ebp
0x00410c57:	pushl %ecx
0x00410c58:	ret

0x0040d682:	ret

0x0040d6f5:	popl %ecx
0x0040d6f6:	popl %ecx
0x0040d6f7:	call GetCurrentThreadId@KERNEL32.dll
0x0040d6fd:	orl 0x4(%esi), $0xffffffff<UINT8>
0x0040d701:	movl (%esi), %eax
0x0040d703:	xorl %eax, %eax
0x0040d705:	incl %eax
0x0040d706:	popl %esi
0x0040d707:	ret

0x0040c4a8:	testl %eax, %eax
0x0040c4aa:	jne 0x0040c4b4
0x0040c4b4:	call 0x00416931
0x00416931:	pushl %esi
0x00416932:	pushl %edi
0x00416933:	movl %esi, $0x439f40<UINT32>
0x00416938:	movl %edi, $0x439f40<UINT32>
0x0041693d:	jmp 0x0041694a
0x0041694a:	cmpl %esi, %edi
0x0041694c:	jb -15
0x0041694e:	popl %edi
0x0041694f:	popl %esi
0x00416950:	ret

0x0040c4b9:	andl -4(%ebp), $0x0<UINT8>
0x0040c4bd:	call 0x0041622f
0x0041622f:	pushl $0x64<UINT8>
0x00416231:	pushl $0x43a2b0<UINT32>
0x00416236:	call 0x00410c00
0x0041623b:	pushl $0xb<UINT8>
0x0041623d:	call 0x00416fa7
0x00416fb8:	pushl %esi
0x00416fb9:	call 0x00417051
0x00417051:	pushl $0x8<UINT8>
0x00417053:	pushl $0x43a2d0<UINT32>
0x00417058:	call 0x00410c00
0x0041705d:	cmpl 0x43e1d8, $0x0<UINT8>
0x00417064:	jne 0x0041707e
0x0041707e:	movl %edi, 0x8(%ebp)
0x00417081:	cmpl 0x43d260(,%edi,8), $0x0<UINT8>
0x00417089:	jne 91
0x0041708b:	pushl $0x18<UINT8>
0x0041708d:	call 0x00410ade
0x00410ade:	pushl %ebp
0x00410adf:	movl %ebp, %esp
0x00410ae1:	pushl %ebx
0x00410ae2:	pushl %esi
0x00410ae3:	pushl %edi
0x00410ae4:	movl %edi, 0x43eb78
0x00410aea:	xorl %esi, %esi
0x00410aec:	pushl 0x8(%ebp)
0x00410aef:	call 0x0040a8ad
0x0040a8ad:	pushl %ebp
0x0040a8ae:	movl %ebp, %esp
0x0040a8b0:	pushl %esi
0x0040a8b1:	movl %esi, 0x8(%ebp)
0x0040a8b4:	cmpl %esi, $0xffffffe0<UINT8>
0x0040a8b7:	ja 111
0x0040a8b9:	pushl %ebx
0x0040a8ba:	pushl %edi
0x0040a8bb:	movl %eax, 0x43e1d8
0x0040a8c0:	testl %eax, %eax
0x0040a8c2:	jne 0x0040a8e1
0x0040a8e1:	testl %esi, %esi
0x0040a8e3:	je 4
0x0040a8e5:	movl %ecx, %esi
0x0040a8e7:	jmp 0x0040a8ec
0x0040a8ec:	pushl %ecx
0x0040a8ed:	pushl $0x0<UINT8>
0x0040a8ef:	pushl %eax
0x0040a8f0:	call HeapAlloc@KERNEL32.dll
0x0040a8f6:	movl %edi, %eax
0x0040a8f8:	testl %edi, %edi
0x0040a8fa:	jne 0x0040a922
0x0040a922:	movl %eax, %edi
0x0040a924:	popl %edi
0x0040a925:	popl %ebx
0x0040a926:	jmp 0x0040a93c
0x0040a93c:	popl %esi
0x0040a93d:	popl %ebp
0x0040a93e:	ret

0x00410af4:	movl %ebx, %eax
0x00410af6:	popl %ecx
0x00410af7:	testl %ebx, %ebx
0x00410af9:	jne 0x00410b20
0x00410b20:	popl %edi
0x00410b21:	popl %esi
0x00410b22:	movl %eax, %ebx
0x00410b24:	popl %ebx
0x00410b25:	popl %ebp
0x00410b26:	ret

0x00417092:	popl %ecx
0x00417093:	movl %esi, %eax
0x00417095:	testl %esi, %esi
0x00417097:	jne 0x004170a8
0x004170a8:	pushl $0xa<UINT8>
0x004170aa:	call 0x00416fa7
0x004170af:	popl %ecx
0x004170b0:	andl -4(%ebp), $0x0<UINT8>
0x004170b4:	cmpl 0x43d260(,%edi,8), $0x0<UINT8>
0x004170bc:	jne 21
0x004170be:	pushl $0xfa0<UINT32>
0x004170c3:	pushl %esi
0x004170c4:	call InitializeCriticalSectionAndSpinCount@KERNEL32.dll
0x004170ca:	movl 0x43d260(,%edi,8), %esi
0x004170d1:	jmp 0x004170da
0x004170da:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004170e1:	call 0x004170ef
0x004170ef:	pushl $0xa<UINT8>
0x004170f1:	call 0x0041712d
0x004170f6:	popl %ecx
0x004170f7:	ret

0x004170e6:	xorl %eax, %eax
0x004170e8:	incl %eax
0x004170e9:	call 0x00410c45
0x004170ee:	ret

0x00416fbe:	popl %ecx
0x00416fbf:	testl %eax, %eax
0x00416fc1:	jne 0x00416fcb
0x00416242:	popl %ecx
0x00416243:	xorl %ebx, %ebx
0x00416245:	movl -4(%ebp), %ebx
0x00416248:	pushl $0x40<UINT8>
0x0041624a:	pushl $0x20<UINT8>
0x0041624c:	popl %edi
0x0041624d:	pushl %edi
0x0041624e:	call 0x00410a94
0x00416253:	popl %ecx
0x00416254:	popl %ecx
0x00416255:	movl %ecx, %eax
0x00416257:	movl -36(%ebp), %ecx
0x0041625a:	testl %ecx, %ecx
0x0041625c:	jne 0x00416279
0x00416279:	movl 0x43eb90, %eax
0x0041627e:	movl 0x43f034, %edi
0x00416284:	addl %eax, $0x800<UINT32>
0x00416289:	cmpl %ecx, %eax
0x0041628b:	jae 0x004162be
0x0041628d:	movw 0x4(%ecx), $0xa00<UINT16>
0x00416293:	orl (%ecx), $0xffffffff<UINT8>
0x00416296:	movl 0x8(%ecx), %ebx
0x00416299:	andb 0x24(%ecx), $0xffffff80<UINT8>
0x0041629d:	movb %al, 0x24(%ecx)
0x004162a0:	andb %al, $0x7f<UINT8>
0x004162a2:	movb 0x24(%ecx), %al
0x004162a5:	movw 0x25(%ecx), $0xa0a<UINT16>
0x004162ab:	movl 0x38(%ecx), %ebx
0x004162ae:	movb 0x34(%ecx), %bl
0x004162b1:	addl %ecx, $0x40<UINT8>
0x004162b4:	movl -36(%ebp), %ecx
0x004162b7:	movl %eax, 0x43eb90
0x004162bc:	jmp 0x00416284
0x004162be:	leal %eax, -116(%ebp)
0x004162c1:	pushl %eax
0x004162c2:	call GetStartupInfoW@KERNEL32.dll
0x004162c8:	cmpw -66(%ebp), $0x0<UINT8>
0x004162cd:	je 297
0x004162d3:	movl %eax, -64(%ebp)
0x004162d6:	testl %eax, %eax
0x004162d8:	je 286
0x004162de:	movl %ecx, (%eax)
0x004162e0:	movl -28(%ebp), %ecx
0x004162e3:	addl %eax, $0x4<UINT8>
0x004162e6:	movl -40(%ebp), %eax
0x004162e9:	addl %eax, %ecx
0x004162eb:	movl -32(%ebp), %eax
0x004162ee:	movl %eax, $0x800<UINT32>
0x004162f3:	cmpl %ecx, %eax
0x004162f5:	jl 0x004162fc
0x004162fc:	xorl %esi, %esi
0x004162fe:	incl %esi
0x004162ff:	movl -48(%ebp), %esi
0x00416302:	cmpl 0x43f034, %ecx
0x00416308:	jnl 0x0041632a
0x0041632a:	movl %edi, %ebx
0x0041632c:	movl -44(%ebp), %edi
0x0041632f:	movl %eax, -40(%ebp)
0x00416332:	movl %edx, -32(%ebp)
0x00416335:	cmpl %edi, %ecx
0x00416337:	jge 0x004163fc
0x004163fc:	movl -44(%ebp), %ebx
0x004163ff:	cmpl %ebx, $0x3<UINT8>
0x00416402:	jge 0x004164c0
0x00416408:	movl %esi, %ebx
0x0041640a:	shll %esi, $0x6<UINT8>
0x0041640d:	addl %esi, 0x43eb90
0x00416413:	movl -36(%ebp), %esi
0x00416416:	cmpl (%esi), $0xffffffff<UINT8>
0x00416419:	je 0x0041642e
0x0041642e:	movb 0x4(%esi), $0xffffff81<UINT8>
0x00416432:	testl %ebx, %ebx
0x00416434:	jne 0x0041643b
0x00416436:	pushl $0xfffffff6<UINT8>
0x00416438:	popl %eax
0x00416439:	jmp 0x00416445
0x00416445:	pushl %eax
0x00416446:	call GetStdHandle@KERNEL32.dll
GetStdHandle@KERNEL32.dll: API Node	
0x0041644c:	movl %edi, %eax
0x0041644e:	cmpl %edi, $0xffffffff<UINT8>
0x00416451:	je 69
0x00416453:	testl %edi, %edi
0x00416455:	je 65
0x00416457:	pushl %edi
0x00416458:	call GetFileType@KERNEL32.dll
GetFileType@KERNEL32.dll: API Node	
0x0041645e:	testl %eax, %eax
0x00416460:	je 54
0x00416462:	movl (%esi), %edi
0x00416464:	andl %eax, $0xff<UINT32>
0x00416469:	cmpl %eax, $0x2<UINT8>
0x0041646c:	jne 8
0x0041646e:	movsbl %eax, 0x4(%esi)
0x00416472:	orb %al, $0x40<UINT8>
0x00416474:	jmp 0x00416481
0x00416481:	movb 0x4(%esi), %al
0x00416484:	pushl $0xfa0<UINT32>
0x00416489:	leal %eax, 0xc(%esi)
0x0041648c:	pushl %eax
0x0041648d:	call InitializeCriticalSectionAndSpinCount@KERNEL32.dll
0x00416493:	incl 0x8(%esi)
0x00416496:	jmp 0x004164ba
0x004164ba:	incl %ebx
0x004164bb:	jmp 0x004163fc
0x0041643b:	leal %eax, -1(%ebx)
0x0041643e:	negl %eax
0x00416440:	sbbl %eax, %eax
0x00416442:	addl %eax, $0xfffffff5<UINT8>
0x004164c0:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004164c7:	call 0x004164d4
0x004164d4:	pushl $0xb<UINT8>
0x004164d6:	call 0x0041712d
0x004164db:	popl %ecx
0x004164dc:	ret

0x004164cc:	xorl %eax, %eax
0x004164ce:	call 0x00410c45
0x004164d3:	ret

0x0040c4c2:	testl %eax, %eax
0x0040c4c4:	jns 0x0040c4ce
0x0040c4ce:	call GetCommandLineA@KERNEL32.dll
GetCommandLineA@KERNEL32.dll: API Node	
0x0040c4d4:	movl 0x440080, %eax
0x0040c4d9:	call 0x00416971
0x00416971:	pushl %ebp
0x00416972:	movl %ebp, %esp
0x00416974:	pushl %ecx
0x00416975:	pushl %edi
0x00416976:	call GetEnvironmentStringsW@KERNEL32.dll
GetEnvironmentStringsW@KERNEL32.dll: API Node	
0x0041697c:	movl %edi, %eax
0x0041697e:	xorl %eax, %eax
0x00416980:	testl %edi, %edi
0x00416982:	je 117
0x00416984:	pushl %esi
0x00416985:	movl %esi, %edi
0x00416987:	cmpw (%edi), %ax
0x0041698a:	je 0x0041699c
0x0041699c:	pushl %ebx
0x0041699d:	pushl %eax
0x0041699e:	pushl %eax
0x0041699f:	pushl %eax
0x004169a0:	subl %esi, %edi
0x004169a2:	pushl %eax
0x004169a3:	sarl %esi
0x004169a5:	incl %esi
0x004169a6:	pushl %esi
0x004169a7:	pushl %edi
0x004169a8:	pushl %eax
0x004169a9:	pushl %eax
0x004169aa:	call WideCharToMultiByte@KERNEL32.dll
WideCharToMultiByte@KERNEL32.dll: API Node	
0x004169b0:	movl -4(%ebp), %eax
0x004169b3:	testl %eax, %eax
0x004169b5:	je 55
0x004169b7:	pushl %eax
0x004169b8:	call 0x00410ade
0x004169bd:	movl %ebx, %eax
0x004169bf:	popl %ecx
0x004169c0:	testl %ebx, %ebx
0x004169c2:	je 42
0x004169c4:	xorl %eax, %eax
0x004169c6:	pushl %eax
0x004169c7:	pushl %eax
0x004169c8:	pushl -4(%ebp)
0x004169cb:	pushl %ebx
0x004169cc:	pushl %esi
0x004169cd:	pushl %edi
0x004169ce:	pushl %eax
0x004169cf:	pushl %eax
0x004169d0:	call WideCharToMultiByte@KERNEL32.dll
0x004169d6:	testl %eax, %eax
0x004169d8:	jne 0x004169e3
0x004169e3:	pushl %edi
0x004169e4:	call FreeEnvironmentStringsW@KERNEL32.dll
FreeEnvironmentStringsW@KERNEL32.dll: API Node	
0x004169ea:	movl %eax, %ebx
0x004169ec:	jmp 0x004169f7
0x004169f7:	popl %ebx
0x004169f8:	popl %esi
0x004169f9:	popl %edi
0x004169fa:	leave
0x004169fb:	ret

0x0040c4de:	movl 0x43e1ac, %eax
0x0040c4e3:	call 0x0041653c
0x0041653c:	pushl %ebp
0x0041653d:	movl %ebp, %esp
0x0041653f:	pushl %ecx
0x00416540:	pushl %ecx
0x00416541:	cmpl 0x440070, $0x0<UINT8>
0x00416548:	jne 5
0x0041654a:	call 0x0040cb37
0x0040cb37:	cmpl 0x440070, $0x0<UINT8>
0x0040cb3e:	jne 18
0x0040cb40:	pushl $0xfffffffd<UINT8>
0x0040cb42:	call 0x0040cec7
0x0040cec7:	pushl $0x10<UINT8>
0x0040cec9:	pushl $0x43a030<UINT32>
0x0040cece:	call 0x00410c00
0x0040ced3:	orl %edi, $0xffffffff<UINT8>
0x0040ced6:	call 0x0040d561
0x0040d561:	pushl %esi
0x0040d562:	call 0x0040d579
0x0040d579:	pushl %esi
0x0040d57a:	pushl %edi
0x0040d57b:	call GetLastError@KERNEL32.dll
GetLastError@KERNEL32.dll: API Node	
0x0040d581:	pushl 0x43cba0
0x0040d587:	movl %edi, %eax
0x0040d589:	call 0x00416b26
0x00416b26:	pushl %ebp
0x00416b27:	movl %ebp, %esp
0x00416b29:	movl %eax, 0x43efc8
0x00416b2e:	xorl %eax, 0x43c650
0x00416b34:	pushl 0x8(%ebp)
0x00416b37:	je 4
0x00416b39:	call FlsGetValue@kernel32.dll
FlsGetValue@kernel32.dll: API Node	
0x00416b3b:	popl %ebp
0x00416b3c:	ret

0x0040d58e:	movl %esi, %eax
0x0040d590:	popl %ecx
0x0040d591:	testl %esi, %esi
0x0040d593:	jne 0x0040d5dc
0x0040d5dc:	pushl %edi
0x0040d5dd:	call SetLastError@KERNEL32.dll
SetLastError@KERNEL32.dll: API Node	
0x0040d5e3:	popl %edi
0x0040d5e4:	movl %eax, %esi
0x0040d5e6:	popl %esi
0x0040d5e7:	ret

0x0040d567:	movl %esi, %eax
0x0040d569:	testl %esi, %esi
0x0040d56b:	jne 0x0040d575
0x0040d575:	movl %eax, %esi
0x0040d577:	popl %esi
0x0040d578:	ret

0x0040cedb:	movl %ebx, %eax
0x0040cedd:	movl -28(%ebp), %ebx
0x0040cee0:	call 0x0040cdf2
0x0040cdf2:	pushl $0xc<UINT8>
0x0040cdf4:	pushl $0x43a010<UINT32>
0x0040cdf9:	call 0x00410c00
0x0040cdfe:	call 0x0040d561
0x0040ce03:	movl %edi, %eax
0x0040ce05:	movl %ecx, 0x43cf4c
0x0040ce0b:	testl 0x70(%edi), %ecx
0x0040ce0e:	je 0x0040ce2d
0x0040ce2d:	pushl $0xd<UINT8>
0x0040ce2f:	call 0x00416fa7
0x0040ce34:	popl %ecx
0x0040ce35:	andl -4(%ebp), $0x0<UINT8>
0x0040ce39:	movl %esi, 0x68(%edi)
0x0040ce3c:	movl -28(%ebp), %esi
0x0040ce3f:	cmpl %esi, 0x43c680
0x0040ce45:	je 0x0040ce7d
0x0040ce7d:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040ce84:	call 0x0040ce8e
0x0040ce8e:	pushl $0xd<UINT8>
0x0040ce90:	call 0x0041712d
0x0040ce95:	popl %ecx
0x0040ce96:	ret

0x0040ce89:	jmp 0x0040ce19
0x0040ce19:	testl %esi, %esi
0x0040ce1b:	jne 0x0040ce25
0x0040ce25:	movl %eax, %esi
0x0040ce27:	call 0x00410c45
0x0040ce2c:	ret

0x0040cee5:	movl %esi, 0x68(%ebx)
0x0040cee8:	pushl 0x8(%ebp)
0x0040ceeb:	call 0x0040cb8f
0x0040cb8f:	pushl %ebp
0x0040cb90:	movl %ebp, %esp
0x0040cb92:	subl %esp, $0x10<UINT8>
0x0040cb95:	leal %ecx, -16(%ebp)
0x0040cb98:	pushl $0x0<UINT8>
0x0040cb9a:	call 0x0040a520
0x0040a520:	pushl %ebp
0x0040a521:	movl %ebp, %esp
0x0040a523:	pushl %esi
0x0040a524:	movl %esi, %ecx
0x0040a526:	movl %ecx, 0x8(%ebp)
0x0040a529:	movb 0xc(%esi), $0x0<UINT8>
0x0040a52d:	testl %ecx, %ecx
0x0040a52f:	jne 102
0x0040a531:	call 0x0040d561
0x0040a536:	movl %edx, %eax
0x0040a538:	movl 0x8(%esi), %edx
0x0040a53b:	movl %ecx, 0x6c(%edx)
0x0040a53e:	movl (%esi), %ecx
0x0040a540:	movl %ecx, 0x68(%edx)
0x0040a543:	movl 0x4(%esi), %ecx
0x0040a546:	movl %ecx, (%esi)
0x0040a548:	cmpl %ecx, 0x43ce84
0x0040a54e:	je 0x0040a561
0x0040a561:	movl %eax, 0x4(%esi)
0x0040a564:	cmpl %eax, 0x43c680
0x0040a56a:	je 0x0040a581
0x0040a581:	movl %ecx, 0x8(%esi)
0x0040a584:	movl %eax, 0x70(%ecx)
0x0040a587:	testb %al, $0x2<UINT8>
0x0040a589:	jne 22
0x0040a58b:	orl %eax, $0x2<UINT8>
0x0040a58e:	movl 0x70(%ecx), %eax
0x0040a591:	movb 0xc(%esi), $0x1<UINT8>
0x0040a595:	jmp 0x0040a5a1
0x0040a5a1:	movl %eax, %esi
0x0040a5a3:	popl %esi
0x0040a5a4:	popl %ebp
0x0040a5a5:	ret $0x4<UINT16>

0x0040cb9f:	movl %eax, 0x8(%ebp)
0x0040cba2:	andl 0x43e1d0, $0x0<UINT8>
0x0040cba9:	cmpl %eax, $0xfffffffe<UINT8>
0x0040cbac:	jne 0x0040cbc0
0x0040cbc0:	cmpl %eax, $0xfffffffd<UINT8>
0x0040cbc3:	jne 0x0040cbd7
0x0040cbc5:	movl 0x43e1d0, $0x1<UINT32>
0x0040cbcf:	call GetACP@KERNEL32.dll
GetACP@KERNEL32.dll: API Node	
0x0040cbd5:	jmp 0x0040cbec
0x0040cbec:	cmpb -4(%ebp), $0x0<UINT8>
0x0040cbf0:	je 7
0x0040cbf2:	movl %ecx, -8(%ebp)
0x0040cbf5:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0040cbf9:	leave
0x0040cbfa:	ret

0x0040cef0:	popl %ecx
0x0040cef1:	movl 0x8(%ebp), %eax
0x0040cef4:	cmpl %eax, 0x4(%esi)
0x0040cef7:	je 366
0x0040cefd:	pushl $0x220<UINT32>
0x0040cf02:	call 0x00410ade
0x0040cf07:	popl %ecx
0x0040cf08:	movl %ebx, %eax
0x0040cf0a:	testl %ebx, %ebx
0x0040cf0c:	je 347
0x0040cf12:	movl %ecx, $0x88<UINT32>
0x0040cf17:	movl %eax, -28(%ebp)
0x0040cf1a:	movl %esi, 0x68(%eax)
0x0040cf1d:	movl %edi, %ebx
0x0040cf1f:	rep movsl %es:(%edi), %ds:(%esi)
0x0040cf21:	xorl %esi, %esi
0x0040cf23:	movl (%ebx), %esi
0x0040cf25:	pushl %ebx
0x0040cf26:	pushl 0x8(%ebp)
0x0040cf29:	call 0x0040d075
0x0040d075:	pushl %ebp
0x0040d076:	movl %ebp, %esp
0x0040d078:	subl %esp, $0x20<UINT8>
0x0040d07b:	movl %eax, 0x43c650
0x0040d080:	xorl %eax, %ebp
0x0040d082:	movl -4(%ebp), %eax
0x0040d085:	pushl %ebx
0x0040d086:	pushl %esi
0x0040d087:	pushl 0x8(%ebp)
0x0040d08a:	movl %esi, 0xc(%ebp)
0x0040d08d:	call 0x0040cb8f
0x0040cbd7:	cmpl %eax, $0xfffffffc<UINT8>
0x0040cbda:	jne 0x0040cbec
0x0040d092:	movl %ebx, %eax
0x0040d094:	popl %ecx
0x0040d095:	movl -32(%ebp), %ebx
0x0040d098:	testl %ebx, %ebx
0x0040d09a:	jne 0x0040d0aa
0x0040d0aa:	pushl %edi
0x0040d0ab:	xorl %edi, %edi
0x0040d0ad:	movl %ecx, %edi
0x0040d0af:	movl -28(%ebp), %ecx
0x0040d0b2:	movl %eax, %edi
0x0040d0b4:	cmpl 0x43c688(%eax), %ebx
0x0040d0ba:	je 242
0x0040d0c0:	incl %ecx
0x0040d0c1:	addl %eax, $0x30<UINT8>
0x0040d0c4:	movl -28(%ebp), %ecx
0x0040d0c7:	cmpl %eax, $0xf0<UINT32>
0x0040d0cc:	jb 0x0040d0b4
0x0040d0ce:	cmpl %ebx, $0xfde8<UINT32>
0x0040d0d4:	je 208
0x0040d0da:	cmpl %ebx, $0xfde9<UINT32>
0x0040d0e0:	je 196
0x0040d0e6:	movzwl %eax, %bx
0x0040d0e9:	pushl %eax
0x0040d0ea:	call IsValidCodePage@KERNEL32.dll
IsValidCodePage@KERNEL32.dll: API Node	
0x0040d0f0:	testl %eax, %eax
0x0040d0f2:	je 178
0x0040d0f8:	leal %eax, -24(%ebp)
0x0040d0fb:	pushl %eax
0x0040d0fc:	pushl %ebx
0x0040d0fd:	call GetCPInfo@KERNEL32.dll
GetCPInfo@KERNEL32.dll: API Node	
0x0040d103:	testl %eax, %eax
0x0040d105:	je 140
0x0040d10b:	pushl $0x101<UINT32>
0x0040d110:	leal %eax, 0x18(%esi)
0x0040d113:	pushl %edi
0x0040d114:	pushl %eax
0x0040d115:	call 0x0040b140
0x0040b140:	movl %edx, 0xc(%esp)
0x0040b144:	movl %ecx, 0x4(%esp)
0x0040b148:	testl %edx, %edx
0x0040b14a:	je 127
0x0040b14c:	movzbl %eax, 0x8(%esp)
0x0040b151:	btl 0x43eb74, $0x1<UINT8>
0x0040b159:	jae 0x0040b168
0x0040b168:	movl %edx, 0xc(%esp)
0x0040b16c:	cmpl %edx, $0x80<UINT32>
0x0040b172:	jl 14
0x0040b174:	btl 0x43cf5c, $0x1<UINT8>
0x0040b17c:	jb 22553
0x0040b182:	pushl %edi
0x0040b183:	movl %edi, %ecx
0x0040b185:	cmpl %edx, $0x4<UINT8>
0x0040b188:	jb 49
0x0040b18a:	negl %ecx
0x0040b18c:	andl %ecx, $0x3<UINT8>
0x0040b18f:	je 0x0040b19d
0x0040b19d:	movl %ecx, %eax
0x0040b19f:	shll %eax, $0x8<UINT8>
0x0040b1a2:	addl %eax, %ecx
0x0040b1a4:	movl %ecx, %eax
0x0040b1a6:	shll %eax, $0x10<UINT8>
0x0040b1a9:	addl %eax, %ecx
0x0040b1ab:	movl %ecx, %edx
0x0040b1ad:	andl %edx, $0x3<UINT8>
0x0040b1b0:	shrl %ecx, $0x2<UINT8>
0x0040b1b3:	je 6
0x0040b1b5:	rep stosl %es:(%edi), %eax
0x0040b1b7:	testl %edx, %edx
0x0040b1b9:	je 10
0x0040b1bb:	movb (%edi), %al
0x0040b1bd:	addl %edi, $0x1<UINT8>
0x0040b1c0:	subl %edx, $0x1<UINT8>
0x0040b1c3:	jne -10
0x0040b1c5:	movl %eax, 0x8(%esp)
0x0040b1c9:	popl %edi
0x0040b1ca:	ret

0x0040d11a:	movl 0x4(%esi), %ebx
0x0040d11d:	xorl %ebx, %ebx
0x0040d11f:	incl %ebx
0x0040d120:	addl %esp, $0xc<UINT8>
0x0040d123:	movl 0x21c(%esi), %edi
0x0040d129:	cmpl -24(%ebp), %ebx
0x0040d12c:	jbe 79
0x0040d12e:	cmpb -18(%ebp), $0x0<UINT8>
0x0040d132:	leal %eax, -18(%ebp)
0x0040d135:	je 0x0040d158
0x0040d158:	leal %eax, 0x1a(%esi)
0x0040d15b:	movl %ecx, $0xfe<UINT32>
0x0040d160:	orb (%eax), $0x8<UINT8>
0x0040d163:	incl %eax
0x0040d164:	decl %ecx
0x0040d165:	jne 0x0040d160
0x0040d167:	pushl 0x4(%esi)
0x0040d16a:	call 0x0040cb55
0x0040cb55:	pushl %ebp
0x0040cb56:	movl %ebp, %esp
0x0040cb58:	movl %eax, 0x8(%ebp)
0x0040cb5b:	subl %eax, $0x3a4<UINT32>
0x0040cb60:	je 38
0x0040cb62:	subl %eax, $0x4<UINT8>
0x0040cb65:	je 26
0x0040cb67:	subl %eax, $0xd<UINT8>
0x0040cb6a:	je 14
0x0040cb6c:	decl %eax
0x0040cb6d:	je 4
0x0040cb6f:	xorl %eax, %eax
0x0040cb71:	popl %ebp
0x0040cb72:	ret

0x0040d16f:	addl %esp, $0x4<UINT8>
0x0040d172:	movl 0x21c(%esi), %eax
0x0040d178:	movl 0x8(%esi), %ebx
0x0040d17b:	jmp 0x0040d180
0x0040d180:	xorl %eax, %eax
0x0040d182:	movzwl %ecx, %ax
0x0040d185:	movl %eax, %ecx
0x0040d187:	shll %ecx, $0x10<UINT8>
0x0040d18a:	orl %eax, %ecx
0x0040d18c:	leal %edi, 0xc(%esi)
0x0040d18f:	stosl %es:(%edi), %eax
0x0040d190:	stosl %es:(%edi), %eax
0x0040d191:	stosl %es:(%edi), %eax
0x0040d192:	jmp 0x0040d252
0x0040d252:	pushl %esi
0x0040d253:	call 0x0040cc64
0x0040cc64:	pushl %ebp
0x0040cc65:	movl %ebp, %esp
0x0040cc67:	subl %esp, $0x520<UINT32>
0x0040cc6d:	movl %eax, 0x43c650
0x0040cc72:	xorl %eax, %ebp
0x0040cc74:	movl -4(%ebp), %eax
0x0040cc77:	pushl %ebx
0x0040cc78:	pushl %esi
0x0040cc79:	movl %esi, 0x8(%ebp)
0x0040cc7c:	pushl %edi
0x0040cc7d:	leal %eax, -1304(%ebp)
0x0040cc83:	pushl %eax
0x0040cc84:	pushl 0x4(%esi)
0x0040cc87:	call GetCPInfo@KERNEL32.dll
0x0040cc8d:	xorl %ebx, %ebx
0x0040cc8f:	movl %edi, $0x100<UINT32>
0x0040cc94:	testl %eax, %eax
0x0040cc96:	je 240
0x0040cc9c:	movl %eax, %ebx
0x0040cc9e:	movb -260(%ebp,%eax), %al
0x0040cca5:	incl %eax
0x0040cca6:	cmpl %eax, %edi
0x0040cca8:	jb 0x0040cc9e
0x0040ccaa:	movb %al, -1298(%ebp)
0x0040ccb0:	movb -260(%ebp), $0x20<UINT8>
0x0040ccb7:	leal %ecx, -1298(%ebp)
0x0040ccbd:	jmp 0x0040ccde
0x0040ccde:	testb %al, %al
0x0040cce0:	jne -35
0x0040cce2:	pushl %ebx
0x0040cce3:	pushl 0x4(%esi)
0x0040cce6:	leal %eax, -1284(%ebp)
0x0040ccec:	pushl %eax
0x0040cced:	pushl %edi
0x0040ccee:	leal %eax, -260(%ebp)
0x0040ccf4:	pushl %eax
0x0040ccf5:	pushl $0x1<UINT8>
0x0040ccf7:	pushl %ebx
0x0040ccf8:	call 0x0041883d
0x0041883d:	pushl %ebp
0x0041883e:	movl %ebp, %esp
0x00418840:	subl %esp, $0x10<UINT8>
0x00418843:	pushl 0x8(%ebp)
0x00418846:	leal %ecx, -16(%ebp)
0x00418849:	call 0x0040a520
0x0041884e:	pushl 0x20(%ebp)
0x00418851:	leal %eax, -16(%ebp)
0x00418854:	pushl 0x1c(%ebp)
0x00418857:	pushl 0x18(%ebp)
0x0041885a:	pushl 0x14(%ebp)
0x0041885d:	pushl 0x10(%ebp)
0x00418860:	pushl 0xc(%ebp)
0x00418863:	pushl %eax
0x00418864:	call 0x00418751
0x00418751:	pushl %ebp
0x00418752:	movl %ebp, %esp
0x00418754:	pushl %ecx
0x00418755:	movl %eax, 0x43c650
0x0041875a:	xorl %eax, %ebp
0x0041875c:	movl -4(%ebp), %eax
0x0041875f:	movl %ecx, 0x1c(%ebp)
0x00418762:	pushl %ebx
0x00418763:	pushl %esi
0x00418764:	pushl %edi
0x00418765:	xorl %edi, %edi
0x00418767:	testl %ecx, %ecx
0x00418769:	jne 0x00418778
0x00418778:	xorl %eax, %eax
0x0041877a:	cmpl 0x20(%ebp), %eax
0x0041877d:	pushl %edi
0x0041877e:	pushl %edi
0x0041877f:	pushl 0x14(%ebp)
0x00418782:	setne %al
0x00418785:	pushl 0x10(%ebp)
0x00418788:	leal %eax, 0x1(,%eax,8)
0x0041878f:	pushl %eax
0x00418790:	pushl %ecx
0x00418791:	call MultiByteToWideChar@KERNEL32.dll
MultiByteToWideChar@KERNEL32.dll: API Node	
0x00418797:	movl %ebx, %eax
0x00418799:	testl %ebx, %ebx
0x0041879b:	jne 0x004187a4
0x004187a4:	jle 65
0x004187a6:	cmpl %ebx, $0x7ffffff0<UINT32>
0x004187ac:	ja 57
0x004187ae:	leal %eax, 0x8(,%ebx,2)
0x004187b5:	cmpl %eax, $0x400<UINT32>
0x004187ba:	ja 19
0x004187bc:	call 0x00428d20
0x00428d20:	pushl %ecx
0x00428d21:	leal %ecx, 0x8(%esp)
0x00428d25:	subl %ecx, %eax
0x00428d27:	andl %ecx, $0xf<UINT8>
0x00428d2a:	addl %eax, %ecx
0x00428d2c:	sbbl %ecx, %ecx
0x00428d2e:	orl %eax, %ecx
0x00428d30:	popl %ecx
0x00428d31:	jmp 0x00421b30
0x00421b30:	pushl %ecx
0x00421b31:	leal %ecx, 0x4(%esp)
0x00421b35:	subl %ecx, %eax
0x00421b37:	sbbl %eax, %eax
0x00421b39:	notl %eax
0x00421b3b:	andl %ecx, %eax
0x00421b3d:	movl %eax, %esp
0x00421b3f:	andl %eax, $0xfffff000<UINT32>
0x00421b44:	cmpl %ecx, %eax
0x00421b46:	jb 10
0x00421b48:	movl %eax, %ecx
0x00421b4a:	popl %ecx
0x00421b4b:	xchgl %esp, %eax
0x00421b4c:	movl %eax, (%eax)
0x00421b4e:	movl (%esp), %eax
0x00421b51:	ret

0x004187c1:	movl %esi, %esp
0x004187c3:	testl %esi, %esi
0x004187c5:	je -42
0x004187c7:	movl (%esi), $0xcccc<UINT32>
0x004187cd:	jmp 0x004187e2
0x004187e2:	addl %esi, $0x8<UINT8>
0x004187e5:	jmp 0x004187e9
0x004187e9:	testl %esi, %esi
0x004187eb:	je -80
0x004187ed:	leal %eax, (%ebx,%ebx)
0x004187f0:	pushl %eax
0x004187f1:	pushl %edi
0x004187f2:	pushl %esi
0x004187f3:	call 0x0040b140
