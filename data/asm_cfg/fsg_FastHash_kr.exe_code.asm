0x004af000:	movl %ebx, $0x4001d0<UINT32>
0x004af005:	movl %edi, $0x401000<UINT32>
0x004af00a:	movl %esi, $0x47bf04<UINT32>
0x004af00f:	pushl %ebx
0x004af010:	call 0x004af01f
0x004af01f:	cld
0x004af020:	movb %dl, $0xffffff80<UINT8>
0x004af022:	movsb %es:(%edi), %ds:(%esi)
0x004af023:	pushl $0x2<UINT8>
0x004af025:	popl %ebx
0x004af026:	call 0x004af015
0x004af015:	addb %dl, %dl
0x004af017:	jne 0x004af01e
0x004af019:	movb %dl, (%esi)
0x004af01b:	incl %esi
0x004af01c:	adcb %dl, %dl
0x004af01e:	ret

0x004af029:	jae 0x004af022
0x004af02b:	xorl %ecx, %ecx
0x004af02d:	call 0x004af015
0x004af030:	jae 0x004af04a
0x004af032:	xorl %eax, %eax
0x004af034:	call 0x004af015
0x004af037:	jae 0x004af05a
0x004af039:	movb %bl, $0x2<UINT8>
0x004af03b:	incl %ecx
0x004af03c:	movb %al, $0x10<UINT8>
0x004af03e:	call 0x004af015
0x004af041:	adcb %al, %al
0x004af043:	jae 0x004af03e
0x004af045:	jne 0x004af086
0x004af047:	stosb %es:(%edi), %al
0x004af048:	jmp 0x004af026
0x004af04a:	call 0x004af092
0x004af092:	incl %ecx
0x004af093:	call 0x004af015
0x004af097:	adcl %ecx, %ecx
0x004af099:	call 0x004af015
0x004af09d:	jb 0x004af093
0x004af09f:	ret

0x004af04f:	subl %ecx, %ebx
0x004af051:	jne 0x004af063
0x004af063:	xchgl %ecx, %eax
0x004af064:	decl %eax
0x004af065:	shll %eax, $0x8<UINT8>
0x004af068:	lodsb %al, %ds:(%esi)
0x004af069:	call 0x004af090
0x004af090:	xorl %ecx, %ecx
0x004af06e:	cmpl %eax, $0x7d00<UINT32>
0x004af073:	jae 0x004af07f
0x004af075:	cmpb %ah, $0x5<UINT8>
0x004af078:	jae 0x004af080
0x004af07a:	cmpl %eax, $0x7f<UINT8>
0x004af07d:	ja 0x004af081
0x004af07f:	incl %ecx
0x004af080:	incl %ecx
0x004af081:	xchgl %ebp, %eax
0x004af082:	movl %eax, %ebp
0x004af084:	movb %bl, $0x1<UINT8>
0x004af086:	pushl %esi
0x004af087:	movl %esi, %edi
0x004af089:	subl %esi, %eax
0x004af08b:	rep movsb %es:(%edi), %ds:(%esi)
0x004af08d:	popl %esi
0x004af08e:	jmp 0x004af026
0x004af053:	call 0x004af090
0x004af058:	jmp 0x004af082
0x004af05a:	lodsb %al, %ds:(%esi)
0x004af05b:	shrl %eax
0x004af05d:	je 0x004af0a0
0x004af05f:	adcl %ecx, %ecx
0x004af061:	jmp 0x004af07f
0x004af0a0:	popl %edi
0x004af0a1:	popl %ebx
0x004af0a2:	movzwl %edi, (%ebx)
0x004af0a5:	decl %edi
0x004af0a6:	je 0x004af0b0
0x004af0a8:	decl %edi
0x004af0a9:	je 0x004af0be
0x004af0ab:	shll %edi, $0xc<UINT8>
0x004af0ae:	jmp 0x004af0b7
0x004af0b7:	incl %ebx
0x004af0b8:	incl %ebx
0x004af0b9:	jmp 0x004af00f
0x004af0b0:	movl %edi, 0x2(%ebx)
0x004af0b3:	pushl %edi
0x004af0b4:	addl %ebx, $0x4<UINT8>
0x004af0be:	popl %edi
0x004af0bf:	movl %ebx, $0x4af128<UINT32>
0x004af0c4:	incl %edi
0x004af0c5:	movl %esi, (%edi)
0x004af0c7:	scasl %eax, %es:(%edi)
0x004af0c8:	pushl %edi
0x004af0c9:	call LoadLibraryA@KERNEL32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004af0cb:	xchgl %ebp, %eax
0x004af0cc:	xorl %eax, %eax
0x004af0ce:	scasb %al, %es:(%edi)
0x004af0cf:	jne 0x004af0ce
0x004af0d1:	decb (%edi)
0x004af0d3:	je 0x004af0c4
0x004af0d5:	decb (%edi)
0x004af0d7:	jne 0x004af0df
0x004af0df:	decb (%edi)
0x004af0e1:	je 0x0041dffa
0x004af0e7:	pushl %edi
0x004af0e8:	pushl %ebp
0x004af0e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x004af0ec:	orl (%esi), %eax
0x004af0ee:	lodsl %eax, %ds:(%esi)
0x004af0ef:	jne 0x004af0cc
GetProcAddress@KERNEL32.dll: API Node	
LoadLibraryA@KERNEL32.dll: API Node	
0x004af0d9:	incl %edi
0x004af0da:	pushl (%edi)
0x004af0dc:	scasl %eax, %es:(%edi)
0x004af0dd:	jmp 0x004af0e8
0x0041dffa:	pushl $0x60<UINT8>
0x0041dffc:	pushl $0x45b9b8<UINT32>
0x0041e001:	call 0x0041eed4
0x0041eed4:	pushl $0x41dc50<UINT32>
0x0041eed9:	movl %eax, %fs:0
0x0041eedf:	pushl %eax
0x0041eee0:	movl %eax, 0x10(%esp)
0x0041eee4:	movl 0x10(%esp), %ebp
0x0041eee8:	leal %ebp, 0x10(%esp)
0x0041eeec:	subl %esp, %eax
0x0041eeee:	pushl %ebx
0x0041eeef:	pushl %esi
0x0041eef0:	pushl %edi
0x0041eef1:	movl %eax, -8(%ebp)
0x0041eef4:	movl -24(%ebp), %esp
0x0041eef7:	pushl %eax
0x0041eef8:	movl %eax, -4(%ebp)
0x0041eefb:	movl -4(%ebp), $0xffffffff<UINT32>
0x0041ef02:	movl -8(%ebp), %eax
0x0041ef05:	leal %eax, -16(%ebp)
0x0041ef08:	movl %fs:0, %eax
0x0041ef0e:	ret

0x0041e006:	movl %edi, $0x94<UINT32>
0x0041e00b:	movl %eax, %edi
0x0041e00d:	call 0x0041be80
0x0041be80:	cmpl %eax, $0x1000<UINT32>
0x0041be85:	jae 14
0x0041be87:	negl %eax
0x0041be89:	addl %eax, %esp
0x0041be8b:	addl %eax, $0x4<UINT8>
0x0041be8e:	testl (%eax), %eax
0x0041be90:	xchgl %esp, %eax
0x0041be91:	movl %eax, (%eax)
0x0041be93:	pushl %eax
0x0041be94:	ret

0x0041e012:	movl -24(%ebp), %esp
0x0041e015:	movl %esi, %esp
0x0041e017:	movl (%esi), %edi
0x0041e019:	pushl %esi
0x0041e01a:	call GetVersionExA@KERNEL32.dll
GetVersionExA@KERNEL32.dll: API Node	
0x0041e020:	movl %ecx, 0x10(%esi)
0x0041e023:	movl 0x46a558, %ecx
0x0041e029:	movl %eax, 0x4(%esi)
0x0041e02c:	movl 0x46a564, %eax
0x0041e031:	movl %edx, 0x8(%esi)
0x0041e034:	movl 0x46a568, %edx
0x0041e03a:	movl %esi, 0xc(%esi)
0x0041e03d:	andl %esi, $0x7fff<UINT32>
0x0041e043:	movl 0x46a55c, %esi
0x0041e049:	cmpl %ecx, $0x2<UINT8>
0x0041e04c:	je 0x0041e05a
0x0041e05a:	shll %eax, $0x8<UINT8>
0x0041e05d:	addl %eax, %edx
0x0041e05f:	movl 0x46a560, %eax
0x0041e064:	xorl %esi, %esi
0x0041e066:	pushl %esi
0x0041e067:	movl %edi, 0x45425c
0x0041e06d:	call GetModuleHandleA@KERNEL32.dll
GetModuleHandleA@KERNEL32.dll: API Node	
0x0041e06f:	cmpw (%eax), $0x5a4d<UINT16>
0x0041e074:	jne 31
0x0041e076:	movl %ecx, 0x3c(%eax)
0x0041e079:	addl %ecx, %eax
0x0041e07b:	cmpl (%ecx), $0x4550<UINT32>
0x0041e081:	jne 18
0x0041e083:	movzwl %eax, 0x18(%ecx)
0x0041e087:	cmpl %eax, $0x10b<UINT32>
0x0041e08c:	je 0x0041e0ad
0x0041e0ad:	cmpl 0x74(%ecx), $0xe<UINT8>
0x0041e0b1:	jbe -30
0x0041e0b3:	xorl %eax, %eax
0x0041e0b5:	cmpl 0xe8(%ecx), %esi
0x0041e0bb:	setne %al
0x0041e0be:	movl -28(%ebp), %eax
0x0041e0c1:	pushl $0x1<UINT8>
0x0041e0c3:	call 0x004227bf
0x004227bf:	xorl %eax, %eax
0x004227c1:	cmpl 0x4(%esp), %eax
0x004227c5:	pushl $0x0<UINT8>
0x004227c7:	sete %al
0x004227ca:	pushl $0x1000<UINT32>
0x004227cf:	pushl %eax
0x004227d0:	call HeapCreate@KERNEL32.dll
HeapCreate@KERNEL32.dll: API Node	
0x004227d6:	testl %eax, %eax
0x004227d8:	movl 0x46bbdc, %eax
0x004227dd:	je 42
0x004227df:	call 0x004227a5
0x004227a5:	cmpl 0x46a558, $0x2<UINT8>
0x004227ac:	jne 13
0x004227ae:	cmpl 0x46a564, $0x5<UINT8>
0x004227b5:	jb 4
0x004227b7:	xorl %eax, %eax
0x004227b9:	incl %eax
0x004227ba:	ret

0x004227e4:	cmpl %eax, $0x3<UINT8>
0x004227e7:	movl 0x46bbe0, %eax
0x004227ec:	jne 0x0042280c
0x0042280c:	xorl %eax, %eax
0x0042280e:	incl %eax
0x0042280f:	ret

0x0041e0c8:	popl %ecx
0x0041e0c9:	testl %eax, %eax
0x0041e0cb:	jne 0x0041e0d5
0x0041e0d5:	call 0x00420084
0x00420084:	call 0x00422599
0x00422599:	pushl %esi
0x0042259a:	pushl %edi
0x0042259b:	xorl %esi, %esi
0x0042259d:	movl %edi, $0x46a6b0<UINT32>
0x004225a2:	cmpl 0x467624(,%esi,8), $0x1<UINT8>
0x004225aa:	jne 0x004225ca
0x004225ac:	leal %eax, 0x467620(,%esi,8)
0x004225b3:	movl (%eax), %edi
0x004225b5:	pushl $0xfa0<UINT32>
0x004225ba:	pushl (%eax)
0x004225bc:	addl %edi, $0x18<UINT8>
0x004225bf:	call 0x00426770
0x00426770:	pushl $0x10<UINT8>
0x00426772:	pushl $0x45cac8<UINT32>
0x00426777:	call 0x0041eed4
0x0042677c:	movl %eax, 0x46a9e8
0x00426781:	testl %eax, %eax
0x00426783:	jne 0x004267bc
0x00426785:	cmpl 0x46a558, $0x1<UINT8>
0x0042678c:	je 36
0x0042678e:	pushl $0x459cd0<UINT32>
0x00426793:	call GetModuleHandleA@KERNEL32.dll
0x00426799:	testl %eax, %eax
0x0042679b:	je 21
0x0042679d:	pushl $0x45caa0<UINT32>
0x004267a2:	pushl %eax
0x004267a3:	call GetProcAddress@KERNEL32.dll
0x004267a9:	movl 0x46a9e8, %eax
0x004267ae:	testl %eax, %eax
0x004267b0:	jne 0x004267bc
0x004267bc:	andl -4(%ebp), $0x0<UINT8>
0x004267c0:	pushl 0xc(%ebp)
0x004267c3:	pushl 0x8(%ebp)
0x004267c6:	call InitializeCriticalSectionAndSpinCount@kernel32.dll
InitializeCriticalSectionAndSpinCount@kernel32.dll: API Node	
0x004267c8:	movl -32(%ebp), %eax
0x004267cb:	jmp 0x004267f1
0x004267f1:	orl -4(%ebp), $0xffffffff<UINT8>
0x004267f5:	call 0x0041ef0f
0x0041ef0f:	movl %ecx, -16(%ebp)
0x0041ef12:	movl %fs:0, %ecx
0x0041ef19:	popl %ecx
0x0041ef1a:	popl %edi
0x0041ef1b:	popl %esi
0x0041ef1c:	popl %ebx
0x0041ef1d:	leave
0x0041ef1e:	pushl %ecx
0x0041ef1f:	ret

0x004267fa:	ret

0x004225c4:	testl %eax, %eax
0x004225c6:	popl %ecx
0x004225c7:	popl %ecx
0x004225c8:	je 12
0x004225ca:	incl %esi
0x004225cb:	cmpl %esi, $0x24<UINT8>
0x004225ce:	jl 0x004225a2
0x004225d0:	xorl %eax, %eax
0x004225d2:	incl %eax
0x004225d3:	popl %edi
0x004225d4:	popl %esi
0x004225d5:	ret

0x00420089:	testl %eax, %eax
0x0042008b:	jne 0x00420095
0x00420095:	pushl %esi
0x00420096:	pushl %edi
0x00420097:	pushl $0x459cd0<UINT32>
0x0042009c:	call GetModuleHandleA@KERNEL32.dll
0x004200a2:	movl %edi, %eax
0x004200a4:	testl %edi, %edi
0x004200a6:	je 107
0x004200a8:	movl %esi, 0x45422c
0x004200ae:	pushl $0x45bb08<UINT32>
0x004200b3:	pushl %edi
0x004200b4:	call GetProcAddress@KERNEL32.dll
0x004200b6:	pushl $0x45bafc<UINT32>
0x004200bb:	pushl %edi
0x004200bc:	movl 0x46a5ac, %eax
0x004200c1:	call GetProcAddress@KERNEL32.dll
0x004200c3:	pushl $0x45baf0<UINT32>
0x004200c8:	pushl %edi
0x004200c9:	movl 0x46a5b0, %eax
0x004200ce:	call GetProcAddress@KERNEL32.dll
0x004200d0:	pushl $0x45bae8<UINT32>
0x004200d5:	pushl %edi
0x004200d6:	movl 0x46a5b4, %eax
0x004200db:	call GetProcAddress@KERNEL32.dll
0x004200dd:	cmpl 0x46a5b0, $0x0<UINT8>
0x004200e4:	movl 0x46a5b8, %eax
0x004200e9:	jne 0x00420113
0x00420113:	pushl $0x41ff0e<UINT32>
0x00420118:	call FlsAlloc@kernel32.dll
FlsAlloc@kernel32.dll: API Node	
0x0042011e:	cmpl %eax, $0xffffffff<UINT8>
0x00420121:	movl 0x4673a4, %eax
0x00420126:	je 65
0x00420128:	xorl %edi, %edi
0x0042012a:	pushl $0x8c<UINT32>
0x0042012f:	incl %edi
0x00420130:	pushl %edi
0x00420131:	call 0x0041ea5e
0x0041ea5e:	pushl $0x10<UINT8>
0x0041ea60:	pushl $0x45ba20<UINT32>
0x0041ea65:	call 0x0041eed4
0x0041ea6a:	movl %esi, 0x8(%ebp)
0x0041ea6d:	imull %esi, 0xc(%ebp)
0x0041ea71:	movl -32(%ebp), %esi
0x0041ea74:	testl %esi, %esi
0x0041ea76:	jne 0x0041ea79
0x0041ea79:	xorl %edi, %edi
0x0041ea7b:	movl -28(%ebp), %edi
0x0041ea7e:	cmpl %esi, $0xffffffe0<UINT8>
0x0041ea81:	ja 101
0x0041ea83:	cmpl 0x46bbe0, $0x3<UINT8>
0x0041ea8a:	jne 0x0041ead3
0x0041ead3:	testl %edi, %edi
0x0041ead5:	jne 58
0x0041ead7:	pushl %esi
0x0041ead8:	pushl $0x8<UINT8>
0x0041eada:	pushl 0x46bbdc
0x0041eae0:	call HeapAlloc@KERNEL32.dll
HeapAlloc@KERNEL32.dll: API Node	
0x0041eae6:	movl %edi, %eax
0x0041eae8:	testl %edi, %edi
0x0041eaea:	jne 0x0041eb11
0x0041eb11:	movl %eax, %edi
0x0041eb13:	call 0x0041ef0f
0x0041eb18:	ret

0x00420136:	movl %esi, %eax
0x00420138:	testl %esi, %esi
0x0042013a:	popl %ecx
0x0042013b:	popl %ecx
0x0042013c:	je 43
0x0042013e:	pushl %esi
0x0042013f:	pushl 0x4673a4
0x00420145:	call FlsSetValue@kernel32.dll
FlsSetValue@kernel32.dll: API Node	
0x0042014b:	testl %eax, %eax
0x0042014d:	je 26
0x0042014f:	movl 0x54(%esi), $0x467848<UINT32>
0x00420156:	movl 0x14(%esi), %edi
0x00420159:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x0042015f:	orl 0x4(%esi), $0xffffffff<UINT8>
0x00420163:	movl (%esi), %eax
0x00420165:	movl %eax, %edi
0x00420167:	jmp 0x00420170
0x00420170:	popl %edi
0x00420171:	popl %esi
0x00420172:	ret

0x0041e0da:	testl %eax, %eax
0x0041e0dc:	jne 0x0041e0e6
0x0041e0e6:	call 0x0042271d
0x0042271d:	pushl $0xc<UINT8>
0x0042271f:	pushl $0x45be48<UINT32>
0x00422724:	call 0x0041eed4
0x00422729:	movl -28(%ebp), $0x461410<UINT32>
0x00422730:	cmpl -28(%ebp), $0x461410<UINT32>
0x00422737:	jae 0x0042275b
0x0042275b:	call 0x0041ef0f
0x00422760:	ret

0x0041e0eb:	movl -4(%ebp), %esi
0x0041e0ee:	call 0x00423f30
0x00423f30:	subl %esp, $0x48<UINT8>
0x00423f33:	pushl %ebx
0x00423f34:	movl %ebx, $0x480<UINT32>
0x00423f39:	pushl %ebx
0x00423f3a:	call 0x0041dae0
0x0041dae0:	pushl 0x46a804
0x0041dae6:	pushl 0x8(%esp)
0x0041daea:	call 0x0041dab4
0x0041dab4:	cmpl 0x4(%esp), $0xffffffe0<UINT8>
0x0041dab9:	ja 34
0x0041dabb:	pushl 0x4(%esp)
0x0041dabf:	call 0x0041da39
0x0041da39:	pushl $0xc<UINT8>
0x0041da3b:	pushl $0x45b998<UINT32>
0x0041da40:	call 0x0041eed4
0x0041da45:	movl %esi, 0x8(%ebp)
0x0041da48:	cmpl 0x46bbe0, $0x3<UINT8>
0x0041da4f:	jne 0x0041da7f
0x0041da7f:	testl %esi, %esi
0x0041da81:	jne 0x0041da84
0x0041da84:	cmpl 0x46bbe0, $0x1<UINT8>
0x0041da8b:	je 0x0041da93
0x0041da93:	pushl %esi
0x0041da94:	pushl $0x0<UINT8>
0x0041da96:	pushl 0x46bbdc
0x0041da9c:	call HeapAlloc@KERNEL32.dll
0x0041daa2:	call 0x0041ef0f
0x0041daa7:	ret

0x0041dac4:	testl %eax, %eax
0x0041dac6:	popl %ecx
0x0041dac7:	jne 0x0041dadf
0x0041dadf:	ret

0x0041daef:	popl %ecx
0x0041daf0:	popl %ecx
0x0041daf1:	ret

0x00423f3f:	testl %eax, %eax
0x00423f41:	popl %ecx
0x00423f42:	jne 0x00423f4c
0x00423f4c:	movl 0x46bac0, %eax
0x00423f51:	movl 0x46baa4, $0x20<UINT32>
0x00423f5b:	leal %ecx, 0x480(%eax)
0x00423f61:	jmp 0x00423f81
0x00423f81:	cmpl %eax, %ecx
0x00423f83:	jb 0x00423f63
0x00423f63:	orl (%eax), $0xffffffff<UINT8>
0x00423f66:	andl 0x8(%eax), $0x0<UINT8>
0x00423f6a:	movb 0x4(%eax), $0x0<UINT8>
0x00423f6e:	movb 0x5(%eax), $0xa<UINT8>
0x00423f72:	movl %ecx, 0x46bac0
0x00423f78:	addl %eax, $0x24<UINT8>
0x00423f7b:	addl %ecx, $0x480<UINT32>
0x00423f85:	pushl %ebp
0x00423f86:	pushl %esi
0x00423f87:	pushl %edi
0x00423f88:	leal %eax, 0x14(%esp)
0x00423f8c:	pushl %eax
0x00423f8d:	call GetStartupInfoA@KERNEL32.dll
GetStartupInfoA@KERNEL32.dll: API Node	
0x00423f93:	cmpw 0x46(%esp), $0x0<UINT8>
0x00423f99:	je 233
0x00423f9f:	movl %eax, 0x48(%esp)
0x00423fa3:	testl %eax, %eax
0x00423fa5:	je 221
0x00423fab:	movl %edi, (%eax)
0x00423fad:	leal %ebp, 0x4(%eax)
0x00423fb0:	leal %eax, (%edi,%ebp)
0x00423fb3:	movl 0x10(%esp), %eax
0x00423fb7:	movl %eax, $0x800<UINT32>
0x00423fbc:	cmpl %edi, %eax
0x00423fbe:	jl 0x00423fc2
0x00423fc2:	cmpl 0x46baa4, %edi
0x00423fc8:	jnl 0x00424018
0x00424018:	xorl %ebx, %ebx
0x0042401a:	testl %edi, %edi
0x0042401c:	jle 0x00424088
0x00424088:	xorl %ebx, %ebx
0x0042408a:	movl %ecx, 0x46bac0
0x00424090:	leal %eax, (%ebx,%ebx,8)
0x00424093:	leal %esi, (%ecx,%eax,4)
0x00424096:	cmpl (%esi), $0xffffffff<UINT8>
0x00424099:	jne 111
0x0042409b:	testl %ebx, %ebx
0x0042409d:	movb 0x4(%esi), $0xffffff81<UINT8>
0x004240a1:	jne 0x004240ad
0x004240a3:	pushl $0xfffffff6<UINT8>
0x004240a5:	popl %eax
0x004240a6:	jmp 0x004240b7
0x004240b7:	pushl %eax
0x004240b8:	call GetStdHandle@KERNEL32.dll
GetStdHandle@KERNEL32.dll: API Node	
0x004240be:	movl %edi, %eax
0x004240c0:	cmpl %edi, $0xffffffff<UINT8>
0x004240c3:	je 63
0x004240c5:	pushl %edi
0x004240c6:	call GetFileType@KERNEL32.dll
GetFileType@KERNEL32.dll: API Node	
0x004240cc:	testl %eax, %eax
0x004240ce:	je 52
0x004240d0:	andl %eax, $0xff<UINT32>
0x004240d5:	cmpl %eax, $0x2<UINT8>
0x004240d8:	movl (%esi), %edi
0x004240da:	jne 6
0x004240dc:	orb 0x4(%esi), $0x40<UINT8>
0x004240e0:	jmp 0x004240eb
0x004240eb:	leal %eax, 0xc(%esi)
0x004240ee:	pushl $0xfa0<UINT32>
0x004240f3:	pushl %eax
0x004240f4:	call 0x00426770
0x004240f9:	testl %eax, %eax
0x004240fb:	popl %ecx
0x004240fc:	popl %ecx
0x004240fd:	je -87
0x004240ff:	incl 0x8(%esi)
0x00424102:	jmp 0x0042410e
0x0042410e:	incl %ebx
0x0042410f:	cmpl %ebx, $0x3<UINT8>
0x00424112:	jl 0x0042408a
0x004240ad:	movl %eax, %ebx
0x004240af:	decl %eax
0x004240b0:	negl %eax
0x004240b2:	sbbl %eax, %eax
0x004240b4:	addl %eax, $0xfffffff5<UINT8>
0x00424118:	pushl 0x46baa4
0x0042411e:	call SetHandleCount@KERNEL32.dll
SetHandleCount@KERNEL32.dll: API Node	
0x00424124:	xorl %eax, %eax
0x00424126:	popl %edi
0x00424127:	popl %esi
0x00424128:	popl %ebp
0x00424129:	popl %ebx
0x0042412a:	addl %esp, $0x48<UINT8>
0x0042412d:	ret

0x0041e0f3:	testl %eax, %eax
0x0041e0f5:	jnl 0x0041e0ff
0x0041e0ff:	call GetCommandLineA@KERNEL32.dll
GetCommandLineA@KERNEL32.dll: API Node	
0x0041e105:	movl 0x46be20, %eax
0x0041e10a:	call 0x00423e0e
0x00423e0e:	pushl %ecx
0x00423e0f:	pushl %ecx
0x00423e10:	movl %eax, 0x46a960
0x00423e15:	pushl %ebx
0x00423e16:	pushl %ebp
0x00423e17:	pushl %esi
0x00423e18:	pushl %edi
0x00423e19:	movl %edi, 0x45415c
0x00423e1f:	xorl %ebx, %ebx
0x00423e21:	xorl %esi, %esi
0x00423e23:	cmpl %eax, %ebx
0x00423e25:	pushl $0x2<UINT8>
0x00423e27:	popl %ebp
0x00423e28:	jne 45
0x00423e2a:	call GetEnvironmentStringsW@KERNEL32.dll
GetEnvironmentStringsW@KERNEL32.dll: API Node	
0x00423e2c:	movl %esi, %eax
0x00423e2e:	cmpl %esi, %ebx
0x00423e30:	je 12
0x00423e32:	movl 0x46a960, $0x1<UINT32>
0x00423e3c:	jmp 0x00423e5c
0x00423e5c:	cmpl %esi, %ebx
0x00423e5e:	jne 0x00423e68
0x00423e68:	cmpw (%esi), %bx
0x00423e6b:	movl %eax, %esi
0x00423e6d:	je 14
0x00423e6f:	addl %eax, %ebp
0x00423e71:	cmpw (%eax), %bx
0x00423e74:	jne 0x00423e6f
0x00423e76:	addl %eax, %ebp
0x00423e78:	cmpw (%eax), %bx
0x00423e7b:	jne 0x00423e6f
0x00423e7d:	movl %edi, 0x4542f4
0x00423e83:	pushl %ebx
0x00423e84:	pushl %ebx
0x00423e85:	pushl %ebx
0x00423e86:	subl %eax, %esi
0x00423e88:	pushl %ebx
0x00423e89:	sarl %eax
0x00423e8b:	incl %eax
0x00423e8c:	pushl %eax
0x00423e8d:	pushl %esi
0x00423e8e:	pushl %ebx
0x00423e8f:	pushl %ebx
0x00423e90:	movl 0x34(%esp), %eax
0x00423e94:	call WideCharToMultiByte@KERNEL32.dll
WideCharToMultiByte@KERNEL32.dll: API Node	
0x00423e96:	movl %ebp, %eax
0x00423e98:	cmpl %ebp, %ebx
0x00423e9a:	je 50
0x00423e9c:	pushl %ebp
0x00423e9d:	call 0x0041dae0
0x00423ea2:	cmpl %eax, %ebx
0x00423ea4:	popl %ecx
0x00423ea5:	movl 0x10(%esp), %eax
0x00423ea9:	je 35
0x00423eab:	pushl %ebx
0x00423eac:	pushl %ebx
0x00423ead:	pushl %ebp
0x00423eae:	pushl %eax
0x00423eaf:	pushl 0x24(%esp)
0x00423eb3:	pushl %esi
0x00423eb4:	pushl %ebx
0x00423eb5:	pushl %ebx
0x00423eb6:	call WideCharToMultiByte@KERNEL32.dll
0x00423eb8:	testl %eax, %eax
0x00423eba:	jne 0x00423eca
0x00423eca:	movl %ebx, 0x10(%esp)
0x00423ece:	pushl %esi
0x00423ecf:	call FreeEnvironmentStringsW@KERNEL32.dll
FreeEnvironmentStringsW@KERNEL32.dll: API Node	
0x00423ed5:	movl %eax, %ebx
0x00423ed7:	jmp 0x00423f29
0x00423f29:	popl %edi
0x00423f2a:	popl %esi
0x00423f2b:	popl %ebp
0x00423f2c:	popl %ebx
0x00423f2d:	popl %ecx
0x00423f2e:	popl %ecx
0x00423f2f:	ret

0x0041e10f:	movl 0x46a59c, %eax
0x0041e114:	call 0x00423d6c
0x00423d6c:	pushl %ebp
0x00423d6d:	movl %ebp, %esp
0x00423d6f:	pushl %ecx
0x00423d70:	pushl %ecx
0x00423d71:	pushl %ebx
0x00423d72:	pushl %esi
0x00423d73:	pushl %edi
0x00423d74:	xorl %edi, %edi
0x00423d76:	cmpl 0x46be30, %edi
0x00423d7c:	jne 5
0x00423d7e:	call 0x0041f4c8
0x0041f4c8:	cmpl 0x46be30, $0x0<UINT8>
0x0041f4cf:	jne 18
0x0041f4d1:	pushl $0xfffffffd<UINT8>
0x0041f4d3:	call 0x0041f378
0x0041f378:	pushl $0x14<UINT8>
0x0041f37a:	pushl $0x45ba70<UINT32>
0x0041f37f:	call 0x0041eed4
0x0041f384:	orl -32(%ebp), $0xffffffff<UINT8>
0x0041f388:	pushl $0xd<UINT8>
0x0041f38a:	call 0x004226ec
0x004226ec:	pushl %ebp
0x004226ed:	movl %ebp, %esp
0x004226ef:	movl %eax, 0x8(%ebp)
0x004226f2:	pushl %esi
0x004226f3:	leal %esi, 0x467620(,%eax,8)
0x004226fa:	cmpl (%esi), $0x0<UINT8>
0x004226fd:	jne 0x00422712
0x00422712:	pushl (%esi)
0x00422714:	call EnterCriticalSection@KERNEL32.dll
EnterCriticalSection@KERNEL32.dll: API Node	
0x0042271a:	popl %esi
0x0042271b:	popl %ebp
0x0042271c:	ret

0x0041f38f:	popl %ecx
0x0041f390:	xorl %edi, %edi
0x0041f392:	movl -4(%ebp), %edi
0x0041f395:	movl 0x46a5a8, %edi
0x0041f39b:	movl %eax, 0x8(%ebp)
0x0041f39e:	cmpl %eax, $0xfffffffe<UINT8>
0x0041f3a1:	jne 0x0041f3b5
0x0041f3b5:	cmpl %eax, $0xfffffffd<UINT8>
0x0041f3b8:	jne 18
0x0041f3ba:	movl 0x46a5a8, $0x1<UINT32>
0x0041f3c4:	call GetACP@KERNEL32.dll
GetACP@KERNEL32.dll: API Node	
0x0041f3ca:	jmp 0x0041f3e0
0x0041f3e0:	movl 0x8(%ebp), %eax
0x0041f3e3:	cmpl %eax, 0x46bd04
0x0041f3e9:	je 187
0x0041f3ef:	movl %esi, 0x46bbe8
0x0041f3f5:	movl -36(%ebp), %esi
0x0041f3f8:	cmpl %esi, %edi
0x0041f3fa:	je 0x0041f400
0x0041f400:	pushl $0x220<UINT32>
0x0041f405:	call 0x0041dae0
0x0041f40a:	popl %ecx
0x0041f40b:	movl %esi, %eax
0x0041f40d:	movl -36(%ebp), %esi
0x0041f410:	cmpl %esi, %edi
0x0041f412:	je 127
0x0041f414:	pushl 0x8(%ebp)
0x0041f417:	call 0x0041f1e8
0x0041f1e8:	pushl %ebp
0x0041f1e9:	movl %ebp, %esp
0x0041f1eb:	subl %esp, $0x1c<UINT8>
0x0041f1ee:	movl %eax, 0x467108
0x0041f1f3:	pushl %ebx
0x0041f1f4:	pushl %esi
0x0041f1f5:	movl %esi, 0x8(%ebp)
0x0041f1f8:	xorl %ebx, %ebx
0x0041f1fa:	cmpl %esi, %ebx
0x0041f1fc:	movl -4(%ebp), %eax
0x0041f1ff:	pushl %edi
0x0041f200:	je 340
0x0041f206:	xorl %edx, %edx
0x0041f208:	xorl %eax, %eax
0x0041f20a:	cmpl 0x467148(%eax), %esi
0x0041f210:	je 101
0x0041f212:	addl %eax, $0x30<UINT8>
0x0041f215:	incl %edx
0x0041f216:	cmpl %eax, $0xf0<UINT32>
0x0041f21b:	jb 0x0041f20a
0x0041f21d:	leal %eax, -24(%ebp)
0x0041f220:	pushl %eax
0x0041f221:	pushl %esi
0x0041f222:	call GetCPInfo@KERNEL32.dll
GetCPInfo@KERNEL32.dll: API Node	
0x0041f228:	cmpl %eax, $0x1<UINT8>
0x0041f22b:	jne 289
0x0041f231:	pushl $0x40<UINT8>
0x0041f233:	xorl %eax, %eax
0x0041f235:	cmpl -24(%ebp), $0x1<UINT8>
0x0041f239:	popl %ecx
0x0041f23a:	movl %edi, $0x46bc00<UINT32>
0x0041f23f:	rep stosl %es:(%edi), %eax
0x0041f241:	stosb %es:(%edi), %al
0x0041f242:	movl 0x46bd04, %esi
0x0041f248:	movl 0x46bbe4, %ebx
0x0041f24e:	jbe 236
0x0041f254:	cmpb -18(%ebp), $0x0<UINT8>
0x0041f258:	je 0x0041f318
0x0041f318:	xorl %ecx, %ecx
0x0041f31a:	incl %ecx
0x0041f31b:	movl %eax, %ecx
0x0041f31d:	orb 0x46bc01(%eax), $0x8<UINT8>
0x0041f324:	incl %eax
0x0041f325:	cmpl %eax, $0xff<UINT32>
0x0041f32a:	jb 0x0041f31d
0x0041f32c:	movl %eax, %esi
0x0041f32e:	call 0x0041ef95
0x0041ef95:	subl %eax, $0x3a4<UINT32>
0x0041ef9a:	je 34
0x0041ef9c:	subl %eax, $0x4<UINT8>
0x0041ef9f:	je 23
0x0041efa1:	subl %eax, $0xd<UINT8>
0x0041efa4:	je 12
0x0041efa6:	decl %eax
0x0041efa7:	je 3
0x0041efa9:	xorl %eax, %eax
0x0041efab:	ret

0x0041f333:	movl 0x46bbe4, %eax
0x0041f338:	movl 0x46bbec, %ecx
0x0041f33e:	jmp 0x0041f346
0x0041f346:	xorl %eax, %eax
0x0041f348:	movl %edi, $0x46bd10<UINT32>
0x0041f34d:	stosl %es:(%edi), %eax
0x0041f34e:	stosl %es:(%edi), %eax
0x0041f34f:	stosl %es:(%edi), %eax
0x0041f350:	jmp 0x0041f35f
0x0041f35f:	call 0x0041efed
0x0041efed:	pushl %ebp
0x0041efee:	movl %ebp, %esp
0x0041eff0:	subl %esp, $0x518<UINT32>
0x0041eff6:	movl %eax, 0x467108
0x0041effb:	movl -4(%ebp), %eax
0x0041effe:	pushl %esi
0x0041efff:	leal %eax, -24(%ebp)
0x0041f002:	pushl %eax
0x0041f003:	pushl 0x46bd04
0x0041f009:	call GetCPInfo@KERNEL32.dll
0x0041f00f:	cmpl %eax, $0x1<UINT8>
0x0041f012:	movl %esi, $0x100<UINT32>
0x0041f017:	jne 269
0x0041f01d:	xorl %eax, %eax
0x0041f01f:	movb -280(%ebp,%eax), %al
0x0041f026:	incl %eax
0x0041f027:	cmpl %eax, %esi
0x0041f029:	jb 0x0041f01f
0x0041f02b:	movb %al, -18(%ebp)
0x0041f02e:	testb %al, %al
0x0041f030:	movb -280(%ebp), $0x20<UINT8>
0x0041f037:	je 0x0041f06f
0x0041f06f:	pushl $0x0<UINT8>
0x0041f071:	pushl 0x46bbe4
0x0041f077:	leal %eax, -1304(%ebp)
0x0041f07d:	pushl 0x46bd04
0x0041f083:	pushl %eax
0x0041f084:	pushl %esi
0x0041f085:	leal %eax, -280(%ebp)
0x0041f08b:	pushl %eax
0x0041f08c:	pushl $0x1<UINT8>
0x0041f08e:	call 0x004251df
0x004251df:	pushl $0x1c<UINT8>
0x004251e1:	pushl $0x45c430<UINT32>
0x004251e6:	call 0x0041eed4
0x004251eb:	xorl %esi, %esi
0x004251ed:	cmpl 0x46a98c, %esi
0x004251f3:	jne 53
0x004251f5:	leal %eax, -28(%ebp)
0x004251f8:	pushl %eax
0x004251f9:	xorl %edi, %edi
0x004251fb:	incl %edi
0x004251fc:	pushl %edi
0x004251fd:	pushl $0x45bbac<UINT32>
0x00425202:	pushl %edi
0x00425203:	call GetStringTypeW@KERNEL32.dll
GetStringTypeW@KERNEL32.dll: API Node	
0x00425209:	testl %eax, %eax
0x0042520b:	je 8
0x0042520d:	movl 0x46a98c, %edi
0x00425213:	jmp 0x0042522a
0x0042522a:	movl %eax, 0x46a98c
0x0042522f:	cmpl %eax, $0x2<UINT8>
0x00425232:	je 234
0x00425238:	cmpl %eax, %esi
0x0042523a:	je 226
0x00425240:	cmpl %eax, $0x1<UINT8>
0x00425243:	jne 255
0x00425249:	movl -36(%ebp), %esi
0x0042524c:	movl -32(%ebp), %esi
0x0042524f:	cmpl 0x18(%ebp), %esi
0x00425252:	jne 0x0042525c
0x0042525c:	pushl %esi
0x0042525d:	pushl %esi
0x0042525e:	pushl 0x10(%ebp)
0x00425261:	pushl 0xc(%ebp)
0x00425264:	xorl %eax, %eax
0x00425266:	cmpl 0x20(%ebp), %esi
0x00425269:	setne %al
0x0042526c:	leal %eax, 0x1(,%eax,8)
0x00425273:	pushl %eax
0x00425274:	pushl 0x18(%ebp)
0x00425277:	call MultiByteToWideChar@KERNEL32.dll
MultiByteToWideChar@KERNEL32.dll: API Node	
0x0042527d:	movl %edi, %eax
0x0042527f:	movl -40(%ebp), %edi
0x00425282:	testl %edi, %edi
0x00425284:	je 190
0x0042528a:	andl -4(%ebp), $0x0<UINT8>
0x0042528e:	leal %ebx, (%edi,%edi)
0x00425291:	movl %eax, %ebx
0x00425293:	addl %eax, $0x3<UINT8>
0x00425296:	andl %eax, $0xfffffffc<UINT8>
0x00425299:	call 0x0041be80
0x0042529e:	movl -24(%ebp), %esp
0x004252a1:	movl %esi, %esp
0x004252a3:	movl -44(%ebp), %esi
0x004252a6:	pushl %ebx
0x004252a7:	pushl $0x0<UINT8>
0x004252a9:	pushl %esi
0x004252aa:	call 0x0041e270
0x0041e270:	movl %edx, 0xc(%esp)
0x0041e274:	movl %ecx, 0x4(%esp)
0x0041e278:	testl %edx, %edx
0x0041e27a:	je 79
0x0041e27c:	xorl %eax, %eax
0x0041e27e:	movb %al, 0x8(%esp)
0x0041e282:	pushl %edi
0x0041e283:	movl %edi, %ecx
0x0041e285:	cmpl %edx, $0x4<UINT8>
0x0041e288:	jb 49
0x0041e28a:	negl %ecx
0x0041e28c:	andl %ecx, $0x3<UINT8>
0x0041e28f:	je 0x0041e29d
0x0041e29d:	movl %ecx, %eax
0x0041e29f:	shll %eax, $0x8<UINT8>
0x0041e2a2:	addl %eax, %ecx
0x0041e2a4:	movl %ecx, %eax
0x0041e2a6:	shll %eax, $0x10<UINT8>
0x0041e2a9:	addl %eax, %ecx
0x0041e2ab:	movl %ecx, %edx
0x0041e2ad:	andl %edx, $0x3<UINT8>
0x0041e2b0:	shrl %ecx, $0x2<UINT8>
0x0041e2b3:	je 6
0x0041e2b5:	rep stosl %es:(%edi), %eax
0x0041e2b7:	testl %edx, %edx
0x0041e2b9:	je 0x0041e2c5
0x0041e2c5:	movl %eax, 0x8(%esp)
0x0041e2c9:	popl %edi
0x0041e2ca:	ret

0x004252af:	addl %esp, $0xc<UINT8>
0x004252b2:	orl -4(%ebp), $0xffffffff<UINT8>
0x004252b6:	jmp 0x004252cd
0x004252cd:	testl %esi, %esi
0x004252cf:	jne 0x004252e8
0x004252e8:	pushl %edi
0x004252e9:	pushl %esi
0x004252ea:	pushl 0x10(%ebp)
0x004252ed:	pushl 0xc(%ebp)
0x004252f0:	pushl $0x1<UINT8>
0x004252f2:	pushl 0x18(%ebp)
0x004252f5:	call MultiByteToWideChar@KERNEL32.dll
0x004252fb:	testl %eax, %eax
0x004252fd:	je 17
0x004252ff:	pushl 0x14(%ebp)
0x00425302:	pushl %eax
0x00425303:	pushl %esi
0x00425304:	pushl 0x8(%ebp)
0x00425307:	call GetStringTypeW@KERNEL32.dll
0x0042530d:	movl -36(%ebp), %eax
0x00425310:	cmpl -32(%ebp), $0x0<UINT8>
0x00425314:	je 0x0042531d
0x0042531d:	movl %eax, -36(%ebp)
0x00425320:	jmp 0x00425390
0x00425390:	leal %esp, -56(%ebp)
0x00425393:	call 0x0041ef0f
0x00425398:	ret

0x0041f093:	pushl $0x0<UINT8>
0x0041f095:	pushl 0x46bd04
0x0041f09b:	leal %eax, -536(%ebp)
0x0041f0a1:	pushl %esi
0x0041f0a2:	pushl %eax
0x0041f0a3:	pushl %esi
0x0041f0a4:	leal %eax, -280(%ebp)
0x0041f0aa:	pushl %eax
0x0041f0ab:	pushl %esi
0x0041f0ac:	pushl 0x46bbe4
0x0041f0b2:	call 0x00421148
0x00421148:	pushl $0x38<UINT8>
0x0042114a:	pushl $0x45bbc8<UINT32>
0x0042114f:	call 0x0041eed4
0x00421154:	xorl %ebx, %ebx
0x00421156:	cmpl 0x46a5c0, %ebx
0x0042115c:	jne 0x00421196
0x0042115e:	pushl %ebx
0x0042115f:	pushl %ebx
0x00421160:	xorl %esi, %esi
0x00421162:	incl %esi
0x00421163:	pushl %esi
0x00421164:	pushl $0x45bbac<UINT32>
0x00421169:	pushl $0x100<UINT32>
0x0042116e:	pushl %ebx
0x0042116f:	call LCMapStringW@KERNEL32.dll
LCMapStringW@KERNEL32.dll: API Node	
0x00421175:	testl %eax, %eax
0x00421177:	je 8
0x00421179:	movl 0x46a5c0, %esi
0x0042117f:	jmp 0x00421196
0x00421196:	cmpl 0x14(%ebp), %ebx
0x00421199:	jle 27
0x0042119b:	movl %ecx, 0x14(%ebp)
0x0042119e:	movl %eax, 0x10(%ebp)
0x004211a1:	decl %ecx
0x004211a2:	cmpb (%eax), %bl
0x004211a4:	je 8
0x004211a6:	incl %eax
0x004211a7:	cmpl %ecx, %ebx
0x004211a9:	jne 0x004211a1
0x004211ab:	orl %ecx, $0xffffffff<UINT8>
0x004211ae:	orl %eax, $0xffffffff<UINT8>
0x004211b1:	subl %eax, %ecx
0x004211b3:	addl 0x14(%ebp), %eax
0x004211b6:	movl %eax, 0x46a5c0
0x004211bb:	cmpl %eax, $0x2<UINT8>
0x004211be:	je 476
0x004211c4:	cmpl %eax, %ebx
0x004211c6:	je 468
0x004211cc:	cmpl %eax, $0x1<UINT8>
0x004211cf:	jne 510
0x004211d5:	xorl %edi, %edi
0x004211d7:	movl -44(%ebp), %edi
0x004211da:	movl -56(%ebp), %ebx
0x004211dd:	movl -52(%ebp), %ebx
0x004211e0:	cmpl 0x20(%ebp), %ebx
0x004211e3:	jne 0x004211ed
0x004211ed:	pushl %ebx
0x004211ee:	pushl %ebx
0x004211ef:	pushl 0x14(%ebp)
0x004211f2:	pushl 0x10(%ebp)
0x004211f5:	xorl %eax, %eax
0x004211f7:	cmpl 0x24(%ebp), %ebx
0x004211fa:	setne %al
0x004211fd:	leal %eax, 0x1(,%eax,8)
0x00421204:	pushl %eax
0x00421205:	pushl 0x20(%ebp)
0x00421208:	call MultiByteToWideChar@KERNEL32.dll
0x0042120e:	movl %esi, %eax
0x00421210:	movl -48(%ebp), %esi
0x00421213:	cmpl %esi, %ebx
0x00421215:	je 440
0x0042121b:	movl -4(%ebp), $0x1<UINT32>
0x00421222:	leal %eax, (%esi,%esi)
0x00421225:	addl %eax, $0x3<UINT8>
0x00421228:	andl %eax, $0xfffffffc<UINT8>
0x0042122b:	call 0x0041be80
0x00421230:	movl -24(%ebp), %esp
0x00421233:	movl %eax, %esp
0x00421235:	movl -28(%ebp), %eax
0x00421238:	orl -4(%ebp), $0xffffffff<UINT8>
0x0042123c:	jmp 0x00421259
0x00421259:	cmpl -28(%ebp), %ebx
0x0042125c:	jne 0x0042127a
0x0042127a:	pushl %esi
0x0042127b:	pushl -28(%ebp)
0x0042127e:	pushl 0x14(%ebp)
0x00421281:	pushl 0x10(%ebp)
0x00421284:	pushl $0x1<UINT8>
0x00421286:	pushl 0x20(%ebp)
0x00421289:	call MultiByteToWideChar@KERNEL32.dll
0x0042128f:	testl %eax, %eax
0x00421291:	je 230
0x00421297:	pushl %ebx
0x00421298:	pushl %ebx
0x00421299:	pushl %esi
0x0042129a:	pushl -28(%ebp)
0x0042129d:	pushl 0xc(%ebp)
0x004212a0:	pushl 0x8(%ebp)
0x004212a3:	call LCMapStringW@KERNEL32.dll
0x004212a9:	movl %edi, %eax
0x004212ab:	movl -44(%ebp), %edi
0x004212ae:	cmpl %edi, %ebx
0x004212b0:	je 199
0x004212b6:	testb 0xd(%ebp), $0x4<UINT8>
0x004212ba:	je 0x004212e9
0x004212e9:	movl -4(%ebp), $0x2<UINT32>
0x004212f0:	leal %eax, (%edi,%edi)
0x004212f3:	addl %eax, $0x3<UINT8>
0x004212f6:	andl %eax, $0xfffffffc<UINT8>
0x004212f9:	call 0x0041be80
0x004212fe:	movl -24(%ebp), %esp
0x00421301:	movl %eax, %esp
0x00421303:	movl -32(%ebp), %eax
0x00421306:	orl -4(%ebp), $0xffffffff<UINT8>
0x0042130a:	jmp 0x00421327
0x00421327:	cmpl -32(%ebp), %ebx
0x0042132a:	jne 0x00421344
0x00421344:	pushl %edi
0x00421345:	pushl -32(%ebp)
0x00421348:	pushl %esi
0x00421349:	pushl -28(%ebp)
0x0042134c:	pushl 0xc(%ebp)
0x0042134f:	pushl 0x8(%ebp)
0x00421352:	call LCMapStringW@KERNEL32.dll
0x00421358:	testl %eax, %eax
0x0042135a:	je 33
0x0042135c:	pushl %ebx
0x0042135d:	pushl %ebx
0x0042135e:	cmpl 0x1c(%ebp), %ebx
0x00421361:	jne 0x00421367
0x00421367:	pushl 0x1c(%ebp)
0x0042136a:	pushl 0x18(%ebp)
0x0042136d:	pushl %edi
0x0042136e:	pushl -32(%ebp)
0x00421371:	pushl %ebx
0x00421372:	pushl 0x20(%ebp)
0x00421375:	call WideCharToMultiByte@KERNEL32.dll
0x0042137b:	movl %edi, %eax
0x0042137d:	cmpl -52(%ebp), %ebx
0x00421380:	je 0x0042138b
0x0042138b:	cmpl -56(%ebp), %ebx
0x0042138e:	je 0x00421399
0x00421399:	movl %eax, %edi
0x0042139b:	jmp 0x004214fb
0x004214fb:	leal %esp, -84(%ebp)
0x004214fe:	call 0x0041ef0f
0x00421503:	ret

0x0041f0b7:	pushl $0x0<UINT8>
0x0041f0b9:	pushl 0x46bd04
0x0041f0bf:	leal %eax, -792(%ebp)
0x0041f0c5:	pushl %esi
0x0041f0c6:	pushl %eax
0x0041f0c7:	pushl %esi
0x0041f0c8:	leal %eax, -280(%ebp)
0x0041f0ce:	pushl %eax
0x0041f0cf:	pushl $0x200<UINT32>
0x0041f0d4:	pushl 0x46bbe4
0x0041f0da:	call 0x00421148
0x0041f0df:	addl %esp, $0x5c<UINT8>
0x0041f0e2:	xorl %eax, %eax
0x0041f0e4:	movw %cx, -1304(%ebp,%eax,2)
0x0041f0ec:	testb %cl, $0x1<UINT8>
0x0041f0ef:	je 0x0041f107
0x0041f107:	testb %cl, $0x2<UINT8>
0x0041f10a:	je 0x0041f11c
0x0041f11c:	movb 0x46bd20(%eax), $0x0<UINT8>
0x0041f123:	incl %eax
0x0041f124:	cmpl %eax, %esi
0x0041f126:	jb 0x0041f0e4
0x0041f0f1:	orb 0x46bc01(%eax), $0x10<UINT8>
0x0041f0f8:	movb %cl, -536(%ebp,%eax)
0x0041f0ff:	movb 0x46bd20(%eax), %cl
0x0041f105:	jmp 0x0041f123
0x0041f10c:	orb 0x46bc01(%eax), $0x20<UINT8>
0x0041f113:	movb %cl, -792(%ebp,%eax)
0x0041f11a:	jmp 0x0041f0ff
0x0041f128:	jmp 0x0041f16e
0x0041f16e:	movl %ecx, -4(%ebp)
0x0041f171:	popl %esi
0x0041f172:	call 0x0041e200
0x0041e200:	cmpl %ecx, 0x467108
0x0041e206:	jne 1
0x0041e208:	ret

0x0041f177:	leave
0x0041f178:	ret

0x0041f364:	xorl %eax, %eax
0x0041f366:	jmp 0x0041f36b
0x0041f36b:	movl %ecx, -4(%ebp)
0x0041f36e:	popl %edi
0x0041f36f:	popl %esi
0x0041f370:	popl %ebx
0x0041f371:	call 0x0041e200
0x0041f376:	leave
0x0041f377:	ret

0x0041f41c:	popl %ecx
0x0041f41d:	movl -32(%ebp), %eax
0x0041f420:	cmpl %eax, %edi
0x0041f422:	jne 111
0x0041f424:	movl (%esi), %edi
0x0041f426:	movl %eax, 0x46bd04
0x0041f42b:	movl 0x4(%esi), %eax
0x0041f42e:	movl %eax, 0x46bbec
0x0041f433:	movl 0x8(%esi), %eax
0x0041f436:	movl %eax, 0x46bbe4
0x0041f43b:	movl 0xc(%esi), %eax
0x0041f43e:	xorl %eax, %eax
0x0041f440:	movl -28(%ebp), %eax
0x0041f443:	cmpl %eax, $0x5<UINT8>
0x0041f446:	jnl 0x0041f458
0x0041f448:	movw %cx, 0x46bd10(,%eax,2)
0x0041f450:	movw 0x10(%esi,%eax,2), %cx
0x0041f455:	incl %eax
0x0041f456:	jmp 0x0041f440
0x0041f458:	xorl %eax, %eax
0x0041f45a:	movl -28(%ebp), %eax
0x0041f45d:	cmpl %eax, $0x101<UINT32>
0x0041f462:	jnl 0x0041f471
0x0041f464:	movb %cl, 0x46bc00(%eax)
0x0041f46a:	movb 0x1c(%eax,%esi), %cl
0x0041f46e:	incl %eax
0x0041f46f:	jmp 0x0041f45a
0x0041f471:	xorl %eax, %eax
0x0041f473:	movl -28(%ebp), %eax
0x0041f476:	cmpl %eax, $0x100<UINT32>
0x0041f47b:	jnl 0x0041f48d
0x0041f47d:	movb %cl, 0x46bd20(%eax)
0x0041f483:	movb 0x11d(%eax,%esi), %cl
0x0041f48a:	incl %eax
0x0041f48b:	jmp 0x0041f473
0x0041f48d:	movl 0x46bbe8, %esi
0x0041f493:	cmpl -32(%ebp), $0xffffffff<UINT8>
0x0041f497:	jne 0x0041f4ad
0x0041f4ad:	orl -4(%ebp), $0xffffffff<UINT8>
0x0041f4b1:	call 0x0041f4bf
0x0041f4bf:	pushl $0xd<UINT8>
0x0041f4c1:	call 0x00422637
0x00422637:	pushl %ebp
0x00422638:	movl %ebp, %esp
0x0042263a:	movl %eax, 0x8(%ebp)
0x0042263d:	pushl 0x467620(,%eax,8)
0x00422644:	call LeaveCriticalSection@KERNEL32.dll
LeaveCriticalSection@KERNEL32.dll: API Node	
0x0042264a:	popl %ebp
0x0042264b:	ret

0x0041f4c6:	popl %ecx
0x0041f4c7:	ret

0x0041f4b6:	movl %eax, -32(%ebp)
0x0041f4b9:	call 0x0041ef0f
0x0041f4be:	ret

0x0041f4d8:	popl %ecx
0x0041f4d9:	movl 0x46be30, $0x1<UINT32>
0x0041f4e3:	xorl %eax, %eax
0x0041f4e5:	ret

0x00423d83:	pushl $0x104<UINT32>
0x00423d88:	movl %esi, $0x46a858<UINT32>
0x00423d8d:	pushl %esi
0x00423d8e:	pushl %edi
0x00423d8f:	movb 0x46a95c, $0x0<UINT8>
0x00423d96:	call GetModuleFileNameA@KERNEL32.dll
GetModuleFileNameA@KERNEL32.dll: API Node	
0x00423d9c:	movl %eax, 0x46be20
0x00423da1:	cmpl %eax, %edi
0x00423da3:	movl 0x46a588, %esi
0x00423da9:	je 7
0x00423dab:	cmpb (%eax), $0x0<UINT8>
0x00423dae:	movl %ebx, %eax
0x00423db0:	jne 0x00423db4
0x00423db4:	leal %eax, -4(%ebp)
0x00423db7:	pushl %eax
0x00423db8:	pushl %edi
0x00423db9:	leal %esi, -8(%ebp)
0x00423dbc:	xorl %ecx, %ecx
0x00423dbe:	movl %eax, %ebx
0x00423dc0:	call 0x00423c00
0x00423c00:	pushl %ebp
0x00423c01:	movl %ebp, %esp
0x00423c03:	pushl %ecx
0x00423c04:	pushl %ebx
0x00423c05:	movl %ebx, 0xc(%ebp)
0x00423c08:	xorl %edx, %edx
0x00423c0a:	cmpl 0x8(%ebp), %edx
0x00423c0d:	pushl %edi
0x00423c0e:	movl (%esi), %edx
0x00423c10:	movl %edi, %ecx
0x00423c12:	movl (%ebx), $0x1<UINT32>
0x00423c18:	je 0x00423c23
0x00423c23:	cmpb (%eax), $0x22<UINT8>
0x00423c26:	jne 0x00423c36
0x00423c28:	xorl %ecx, %ecx
0x00423c2a:	testl %edx, %edx
0x00423c2c:	sete %cl
0x00423c2f:	incl %eax
0x00423c30:	movl %edx, %ecx
0x00423c32:	movb %cl, $0x22<UINT8>
0x00423c34:	jmp 0x00423c63
0x00423c63:	testl %edx, %edx
0x00423c65:	jne 0x00423c23
0x00423c36:	incl (%esi)
0x00423c38:	testl %edi, %edi
0x00423c3a:	je 0x00423c41
0x00423c41:	movb %cl, (%eax)
0x00423c43:	movzbl %ebx, %cl
0x00423c46:	incl %eax
0x00423c47:	testb 0x46bc01(%ebx), $0x4<UINT8>
0x00423c4e:	je 0x00423c5c
0x00423c5c:	testb %cl, %cl
0x00423c5e:	movl %ebx, 0xc(%ebp)
0x00423c61:	je 0x00423c95
0x00423c67:	cmpb %cl, $0x20<UINT8>
0x00423c6a:	je 5
0x00423c6c:	cmpb %cl, $0x9<UINT8>
0x00423c6f:	jne 0x00423c23
0x00423c95:	decl %eax
0x00423c96:	jmp 0x00423c79
0x00423c79:	andl -4(%ebp), $0x0<UINT8>
0x00423c7d:	cmpb (%eax), $0x0<UINT8>
0x00423c80:	je 0x00423d5c
0x00423d5c:	movl %eax, 0x8(%ebp)
0x00423d5f:	testl %eax, %eax
0x00423d61:	je 0x00423d66
0x00423d66:	incl (%ebx)
0x00423d68:	popl %edi
0x00423d69:	popl %ebx
0x00423d6a:	leave
0x00423d6b:	ret

0x00423dc5:	movl %esi, -4(%ebp)
0x00423dc8:	movl %eax, -8(%ebp)
0x00423dcb:	shll %esi, $0x2<UINT8>
0x00423dce:	addl %eax, %esi
0x00423dd0:	pushl %eax
0x00423dd1:	call 0x0041dae0
0x00423dd6:	movl %edi, %eax
0x00423dd8:	addl %esp, $0xc<UINT8>
0x00423ddb:	testl %edi, %edi
0x00423ddd:	jne 0x00423de4
0x00423de4:	leal %eax, -4(%ebp)
0x00423de7:	pushl %eax
0x00423de8:	leal %ecx, (%esi,%edi)
0x00423deb:	pushl %edi
0x00423dec:	leal %esi, -8(%ebp)
0x00423def:	movl %eax, %ebx
0x00423df1:	call 0x00423c00
0x00423c1a:	movl %ecx, 0x8(%ebp)
0x00423c1d:	addl 0x8(%ebp), $0x4<UINT8>
0x00423c21:	movl (%ecx), %edi
0x00423c3c:	movb %cl, (%eax)
0x00423c3e:	movb (%edi), %cl
0x00423c40:	incl %edi
0x00423d63:	andl (%eax), $0x0<UINT8>
0x00423df6:	movl %eax, -4(%ebp)
0x00423df9:	decl %eax
0x00423dfa:	popl %ecx
0x00423dfb:	movl 0x46a56c, %eax
0x00423e00:	popl %ecx
0x00423e01:	movl 0x46a570, %edi
0x00423e07:	xorl %eax, %eax
0x00423e09:	popl %edi
0x00423e0a:	popl %esi
0x00423e0b:	popl %ebx
0x00423e0c:	leave
0x00423e0d:	ret

0x0041e119:	testl %eax, %eax
0x0041e11b:	jnl 0x0041e125
0x0041e125:	call 0x00423b39
0x00423b39:	pushl %ebx
0x00423b3a:	xorl %ebx, %ebx
0x00423b3c:	cmpl 0x46be30, %ebx
0x00423b42:	pushl %esi
0x00423b43:	pushl %edi
0x00423b44:	jne 0x00423b4b
0x00423b4b:	movl %esi, 0x46a59c
0x00423b51:	xorl %edi, %edi
0x00423b53:	cmpl %esi, %ebx
0x00423b55:	jne 0x00423b69
0x00423b69:	movb %al, (%esi)
0x00423b6b:	cmpb %al, %bl
0x00423b6d:	jne 0x00423b59
0x00423b59:	cmpb %al, $0x3d<UINT8>
0x00423b5b:	je 0x00423b5e
0x00423b5e:	pushl %esi
0x00423b5f:	call 0x0041e670
0x0041e670:	movl %ecx, 0x4(%esp)
0x0041e674:	testl %ecx, $0x3<UINT32>
0x0041e67a:	je 0x0041e6a0
0x0041e6a0:	movl %eax, (%ecx)
0x0041e6a2:	movl %edx, $0x7efefeff<UINT32>
0x0041e6a7:	addl %edx, %eax
0x0041e6a9:	xorl %eax, $0xffffffff<UINT8>
0x0041e6ac:	xorl %eax, %edx
0x0041e6ae:	addl %ecx, $0x4<UINT8>
0x0041e6b1:	testl %eax, $0x81010100<UINT32>
0x0041e6b6:	je 0x0041e6a0
0x0041e6b8:	movl %eax, -4(%ecx)
0x0041e6bb:	testb %al, %al
0x0041e6bd:	je 50
0x0041e6bf:	testb %ah, %ah
0x0041e6c1:	je 36
0x0041e6c3:	testl %eax, $0xff0000<UINT32>
0x0041e6c8:	je 19
0x0041e6ca:	testl %eax, $0xff000000<UINT32>
0x0041e6cf:	je 0x0041e6d3
0x0041e6d3:	leal %eax, -1(%ecx)
0x0041e6d6:	movl %ecx, 0x4(%esp)
0x0041e6da:	subl %eax, %ecx
0x0041e6dc:	ret

0x00423b64:	popl %ecx
0x00423b65:	leal %esi, 0x1(%esi,%eax)
0x00423b6f:	leal %eax, 0x4(,%edi,4)
0x00423b76:	pushl %eax
0x00423b77:	call 0x0041dae0
0x00423b7c:	movl %edi, %eax
0x00423b7e:	cmpl %edi, %ebx
0x00423b80:	popl %ecx
0x00423b81:	movl 0x46a578, %edi
0x00423b87:	jne 0x00423b8e
0x00423b8e:	movl %esi, 0x46a59c
0x00423b94:	pushl %ebp
0x00423b95:	jmp 0x00423bc1
0x00423bc1:	cmpb (%esi), %bl
0x00423bc3:	jne 0x00423b97
0x00423b97:	pushl %esi
0x00423b98:	call 0x0041e670
0x00423b9d:	movl %ebp, %eax
0x00423b9f:	incl %ebp
0x00423ba0:	cmpb (%esi), $0x3d<UINT8>
0x00423ba3:	popl %ecx
0x00423ba4:	je 0x00423bbf
0x00423bbf:	addl %esi, %ebp
0x00423bc5:	pushl 0x46a59c
0x00423bcb:	call 0x0041daf2
0x0041daf2:	pushl $0xc<UINT8>
0x0041daf4:	pushl $0x45b9a8<UINT32>
0x0041daf9:	call 0x0041eed4
0x0041dafe:	movl %esi, 0x8(%ebp)
0x0041db01:	testl %esi, %esi
0x0041db03:	je 88
0x0041db05:	cmpl 0x46bbe0, $0x3<UINT8>
0x0041db0c:	jne 0x0041db4e
0x0041db4e:	pushl %esi
0x0041db4f:	pushl $0x0<UINT8>
0x0041db51:	pushl 0x46bbdc
0x0041db57:	call HeapFree@KERNEL32.dll
HeapFree@KERNEL32.dll: API Node	
0x0041db5d:	call 0x0041ef0f
0x0041db62:	ret

0x00423bd0:	movl 0x46a59c, %ebx
0x00423bd6:	movl (%edi), %ebx
0x00423bd8:	movl 0x46be24, $0x1<UINT32>
0x00423be2:	xorl %eax, %eax
0x00423be4:	popl %ecx
0x00423be5:	popl %ebp
0x00423be6:	popl %edi
0x00423be7:	popl %esi
0x00423be8:	popl %ebx
0x00423be9:	ret

0x0041e12a:	testl %eax, %eax
0x0041e12c:	jnl 0x0041e136
0x0041e136:	pushl $0x1<UINT8>
0x0041e138:	call 0x0041d66f
0x0041d66f:	movl %eax, 0x4670e8
0x0041d674:	testl %eax, %eax
0x0041d676:	je 7
0x0041d678:	pushl 0x4(%esp)
0x0041d67c:	call 0x0041cdeb
0x0041cdeb:	call 0x0041cdb3
0x0041cdb3:	movl %eax, $0x421a7e<UINT32>
0x0041cdb8:	movl 0x467554, %eax
0x0041cdbd:	movl 0x467558, $0x42170c<UINT32>
0x0041cdc7:	movl 0x46755c, $0x421771<UINT32>
0x0041cdd1:	movl 0x467560, $0x4216d0<UINT32>
0x0041cddb:	movl 0x467564, $0x421757<UINT32>
0x0041cde5:	movl 0x467568, %eax
0x0041cdea:	ret

0x0041cdf0:	call 0x00421b21
0x00421b21:	pushl $0x45b89c<UINT32>
0x00421b26:	call GetModuleHandleA@KERNEL32.dll
0x00421b2c:	testl %eax, %eax
0x00421b2e:	je 21
0x00421b30:	pushl $0x45bda8<UINT32>
0x00421b35:	pushl %eax
0x00421b36:	call GetProcAddress@KERNEL32.dll
0x00421b3c:	testl %eax, %eax
0x00421b3e:	je 5
0x00421b40:	pushl $0x0<UINT8>
0x00421b42:	call IsProcessorFeaturePresent@KERNEL32
IsProcessorFeaturePresent@KERNEL32: API Node	
0x00421b44:	ret

0x0041cdf5:	cmpl 0x4(%esp), $0x0<UINT8>
0x0041cdfa:	movl 0x46a550, %eax
0x0041cdff:	je 5
0x0041ce01:	call 0x00421acf
0x00421acf:	pushl $0x30000<UINT32>
0x00421ad4:	pushl $0x10000<UINT32>
0x00421ad9:	call 0x004266c9
0x004266c9:	movl %eax, 0x8(%esp)
0x004266cd:	andl %eax, $0xfff7ffff<UINT32>
0x004266d2:	pushl %eax
0x004266d3:	pushl 0x8(%esp)
0x004266d7:	call 0x00426697
0x00426697:	pushl %ebp
0x00426698:	movl %ebp, %esp
0x0042669a:	pushl %ecx
0x0042669b:	pushl %ebx
0x0042669c:	fwait
0x0042669d:	fnstcw -4(%ebp)
0x004266a0:	movl %ebx, -4(%ebp)
0x004266a3:	call 0x00426577
0x00426577:	xorl %eax, %eax
0x00426579:	testb %bl, $0x1<UINT8>
0x0042657c:	je 0x00426581
0x00426581:	testb %bl, $0x4<UINT8>
0x00426584:	je 0x00426589
0x00426589:	testb %bl, $0x8<UINT8>
0x0042658c:	je 0x00426591
0x00426591:	testb %bl, $0x10<UINT8>
0x00426594:	je 3
0x00426596:	orl %eax, $0x2<UINT8>
0x00426599:	testb %bl, $0x20<UINT8>
0x0042659c:	je 3
0x0042659e:	orl %eax, $0x1<UINT8>
0x004265a1:	testb %bl, $0x2<UINT8>
0x004265a4:	je 0x004265ab
0x004265ab:	pushl %ebp
0x004265ac:	movzwl %edx, %bx
0x004265af:	pushl %esi
0x004265b0:	movl %ecx, %edx
0x004265b2:	movl %esi, $0xc00<UINT32>
0x004265b7:	andl %ecx, %esi
0x004265b9:	pushl %edi
0x004265ba:	movl %edi, $0x300<UINT32>
0x004265bf:	movl %ebp, $0x200<UINT32>
0x004265c4:	je 33
0x004265c6:	cmpl %ecx, $0x400<UINT32>
0x004265cc:	je 20
0x004265ce:	cmpl %ecx, $0x800<UINT32>
0x004265d4:	je 8
0x004265d6:	cmpl %ecx, %esi
0x004265d8:	jne 13
0x004265da:	orl %eax, %edi
0x004265dc:	jmp 0x004265e7
0x004265e7:	andl %edx, %edi
0x004265e9:	je 0x004265f6
0x004265f6:	orl %eax, $0x20000<UINT32>
0x004265fb:	testb %bh, $0x10<UINT8>
0x004265fe:	popl %edi
0x004265ff:	popl %esi
0x00426600:	popl %ebp
0x00426601:	je 0x00426608
0x00426608:	ret

0x004266a8:	movl %ebx, %eax
0x004266aa:	movl %eax, 0xc(%ebp)
0x004266ad:	notl %eax
0x004266af:	andl %ebx, %eax
0x004266b1:	movl %eax, 0x8(%ebp)
0x004266b4:	andl %eax, 0xc(%ebp)
0x004266b7:	orl %ebx, %eax
0x004266b9:	call 0x00426609
0x00426609:	xorl %eax, %eax
0x0042660b:	testb %bl, $0x10<UINT8>
0x0042660e:	je 0x00426611
0x00426611:	testb %bl, $0x8<UINT8>
0x00426614:	je 0x00426619
0x00426619:	testb %bl, $0x4<UINT8>
0x0042661c:	je 0x00426621
0x00426621:	testb %bl, $0x2<UINT8>
0x00426624:	je 3
0x00426626:	orl %eax, $0x10<UINT8>
0x00426629:	testb %bl, $0x1<UINT8>
0x0042662c:	je 3
0x0042662e:	orl %eax, $0x20<UINT8>
0x00426631:	testl %ebx, $0x80000<UINT32>
0x00426637:	je 0x0042663c
0x0042663c:	movl %ecx, %ebx
0x0042663e:	movl %edx, $0x300<UINT32>
0x00426643:	andl %ecx, %edx
0x00426645:	pushl %esi
0x00426646:	movl %esi, $0x200<UINT32>
0x0042664b:	je 35
0x0042664d:	cmpl %ecx, $0x100<UINT32>
0x00426653:	je 22
0x00426655:	cmpl %ecx, %esi
0x00426657:	je 11
0x00426659:	cmpl %ecx, %edx
0x0042665b:	jne 19
0x0042665d:	orl %eax, $0xc00<UINT32>
0x00426662:	jmp 0x00426670
0x00426670:	movl %ecx, %ebx
0x00426672:	andl %ecx, $0x30000<UINT32>
0x00426678:	je 12
0x0042667a:	cmpl %ecx, $0x10000<UINT32>
0x00426680:	jne 6
0x00426682:	orl %eax, %esi
0x00426684:	jmp 0x00426688
0x00426688:	testl %ebx, $0x40000<UINT32>
0x0042668e:	popl %esi
0x0042668f:	je 0x00426696
0x00426696:	ret

0x004266be:	movl 0xc(%ebp), %eax
0x004266c1:	fldcw 0xc(%ebp)
0x004266c4:	movl %eax, %ebx
0x004266c6:	popl %ebx
0x004266c7:	leave
0x004266c8:	ret

0x004266dc:	popl %ecx
0x004266dd:	popl %ecx
0x004266de:	ret

0x00421ade:	popl %ecx
0x00421adf:	popl %ecx
0x00421ae0:	ret

0x0041ce06:	fnclex
0x0041ce08:	ret

0x0041d67e:	popl %ecx
0x0041d67f:	pushl %esi
0x0041d680:	pushl %edi
0x0041d681:	movl %ecx, $0x466068<UINT32>
0x0041d686:	movl %edi, $0x46607c<UINT32>
0x0041d68b:	xorl %eax, %eax
0x0041d68d:	cmpl %ecx, %edi
0x0041d68f:	movl %esi, %ecx
0x0041d691:	jae 23
0x0041d693:	testl %eax, %eax
0x0041d695:	jne 63
0x0041d697:	movl %ecx, (%esi)
0x0041d699:	testl %ecx, %ecx
0x0041d69b:	je 2
0x0041d69d:	call 0x69466576
0x69466576:	addb (%eax), %al
0x0041dc50:	pushl %ebp
0x0041dc51:	movl %ebp, %esp
0x0041dc53:	subl %esp, $0x8<UINT8>
0x0041dc56:	pushl %ebx
0x0041dc57:	pushl %esi
0x0041dc58:	pushl %edi
0x0041dc59:	pushl %ebp
0x0041dc5a:	cld
0x0041dc5b:	movl %ebx, 0xc(%ebp)
0x0041dc5e:	movl %eax, 0x8(%ebp)
0x0041dc61:	testl 0x4(%eax), $0x6<UINT32>
0x0041dc68:	jne 171
0x0041dc6e:	movl -8(%ebp), %eax
0x0041dc71:	movl %eax, 0x10(%ebp)
0x0041dc74:	movl -4(%ebp), %eax
0x0041dc77:	leal %eax, -8(%ebp)
0x0041dc7a:	movl -4(%ebx), %eax
0x0041dc7d:	movl %esi, 0xc(%ebx)
0x0041dc80:	movl %edi, 0x8(%ebx)
0x0041dc83:	pushl %ebx
0x0041dc84:	call 0x0042334e
0x0042334e:	pushl %ebp
0x0042334f:	movl %ebp, %esp
0x00423351:	subl %esp, $0x20<UINT8>
0x00423354:	pushl %ebx
0x00423355:	pushl %esi
0x00423356:	movl %esi, 0x8(%ebp)
0x00423359:	movl %ebx, 0x8(%esi)
0x0042335c:	testb %bl, $0x3<UINT8>
0x0042335f:	jne 27
0x00423361:	movl %eax, %fs:0x18
0x00423367:	movl 0x8(%ebp), %eax
0x0042336a:	movl %eax, 0x8(%ebp)
0x0042336d:	movl %ecx, 0x8(%eax)
0x00423370:	cmpl %ebx, %ecx
0x00423372:	movl -4(%ebp), %ecx
0x00423375:	jb 12
0x00423377:	cmpl %ebx, 0x4(%eax)
0x0042337a:	jae 0x00423383
0x00423383:	pushl %edi
0x00423384:	movl %edi, 0xc(%esi)
0x00423387:	cmpl %edi, $0xffffffff<UINT8>
0x0042338a:	jne 0x00423394
0x00423394:	xorl %edx, %edx
0x00423396:	movl 0x8(%ebp), %edx
0x00423399:	movl %eax, %ebx
0x0042339b:	movl %ecx, (%eax)
0x0042339d:	cmpl %ecx, $0xffffffff<UINT8>
0x004233a0:	je 0x004233aa
0x004233aa:	cmpl 0x4(%eax), $0x0<UINT8>
0x004233ae:	je 0x004233b3
0x004233b0:	incl 0x8(%ebp)
0x004233b3:	incl %edx
0x004233b4:	addl %eax, $0xc<UINT8>
0x004233b7:	cmpl %edx, %edi
0x004233b9:	jbe -32
0x004233bb:	cmpl 0x8(%ebp), $0x0<UINT8>
0x004233bf:	je 0x004233d5
0x004233c1:	movl %eax, -8(%esi)
0x004233c4:	cmpl %eax, -4(%ebp)
0x004233c7:	jb 290
0x004233cd:	cmpl %eax, %esi
0x004233cf:	jae 282
0x004233d5:	movl %eax, 0x46a808
0x004233da:	movl %edi, %ebx
0x004233dc:	andl %edi, $0xfffff000<UINT32>
0x004233e2:	xorl %esi, %esi
0x004233e4:	testl %eax, %eax
0x004233e6:	jle 0x004233fa
0x004233fa:	pushl $0x1c<UINT8>
0x004233fc:	leal %eax, -32(%ebp)
0x004233ff:	pushl %eax
0x00423400:	pushl %ebx
0x00423401:	call VirtualQuery@KERNEL32.dll
VirtualQuery@KERNEL32.dll: API Node	
0x00423407:	testl %eax, %eax
0x00423409:	je 352
0x0042340f:	cmpl -8(%ebp), $0x1000000<UINT32>
0x00423416:	jne 0x0042356f
0x0042356f:	orl %eax, $0xffffffff<UINT8>
0x00423572:	popl %edi
0x00423573:	popl %esi
0x00423574:	popl %ebx
0x00423575:	leave
0x00423576:	ret

0x0041dc89:	addl %esp, $0x4<UINT8>
0x0041dc8c:	orl %eax, %eax
0x0041dc8e:	je 123
0x0041dc90:	cmpl %esi, $0xffffffff<UINT8>
0x0041dc93:	je 0x0041dd12
0x0041dc95:	leal %ecx, (%esi,%esi,2)
0x0041dc98:	movl %eax, 0x4(%edi,%ecx,4)
0x0041dc9c:	orl %eax, %eax
0x0041dc9e:	je 0x0041dcf9
0x0041dca0:	pushl %esi
0x0041dca1:	pushl %ebp
0x0041dca2:	leal %ebp, 0x10(%ebx)
0x0041dca5:	xorl %ebx, %ebx
0x0041dca7:	xorl %ecx, %ecx
0x0041dca9:	xorl %edx, %edx
0x0041dcab:	xorl %esi, %esi
0x0041dcad:	xorl %edi, %edi
0x0041dcaf:	call 0x0041e195
0x0041e195:	movl %eax, -20(%ebp)
0x0041e198:	movl %ecx, (%eax)
0x0041e19a:	movl %ecx, (%ecx)
0x0041e19c:	movl -36(%ebp), %ecx
0x0041e19f:	pushl %eax
0x0041e1a0:	pushl %ecx
0x0041e1a1:	call 0x00423978
0x00423978:	pushl %ebp
0x00423979:	movl %ebp, %esp
0x0042397b:	pushl %ecx
0x0042397c:	pushl %ebx
0x0042397d:	pushl %esi
0x0042397e:	pushl %edi
0x0042397f:	call 0x0041fe9d
0x0041fe9d:	pushl %ebx
0x0041fe9e:	pushl %esi
0x0041fe9f:	call GetLastError@KERNEL32.dll
GetLastError@KERNEL32.dll: API Node	
0x0041fea5:	pushl 0x4673a4
0x0041feab:	movl %ebx, %eax
0x0041fead:	call FlsGetValue@kernel32.dll
FlsGetValue@kernel32.dll: API Node	
0x0041feb3:	movl %esi, %eax
0x0041feb5:	testl %esi, %esi
0x0041feb7:	jne 0x0041ff02
0x0041ff02:	pushl %ebx
0x0041ff03:	call SetLastError@KERNEL32.dll
SetLastError@KERNEL32.dll: API Node	
0x0041ff09:	movl %eax, %esi
0x0041ff0b:	popl %esi
0x0041ff0c:	popl %ebx
0x0041ff0d:	ret

0x00423984:	movl %edi, 0x8(%ebp)
0x00423987:	movl %esi, %eax
0x00423989:	movl %edx, 0x54(%esi)
0x0042398c:	movl %eax, 0x4678cc
0x00423991:	movl %ecx, %edx
0x00423993:	cmpl (%ecx), %edi
0x00423995:	je 0x004239a4
0x004239a4:	leal %eax, (%eax,%eax,2)
0x004239a7:	leal %eax, (%edx,%eax,4)
0x004239aa:	cmpl %ecx, %eax
0x004239ac:	jae 4
0x004239ae:	cmpl (%ecx), %edi
0x004239b0:	je 0x004239b4
0x004239b4:	testl %ecx, %ecx
0x004239b6:	je 274
0x004239bc:	movl %ebx, 0x8(%ecx)
0x004239bf:	testl %ebx, %ebx
0x004239c1:	movl 0x8(%ebp), %ebx
0x004239c4:	je 0x00423ace
0x00423ace:	pushl 0xc(%ebp)
0x00423ad1:	call UnhandledExceptionFilter@KERNEL32.dll
UnhandledExceptionFilter@KERNEL32.dll: API Node	
0x00423ad7:	popl %edi
0x00423ad8:	popl %esi
0x00423ad9:	popl %ebx
0x00423ada:	leave
0x00423adb:	ret

0x0041e1a6:	popl %ecx
0x0041e1a7:	popl %ecx
0x0041e1a8:	ret

0x0041dcb1:	popl %ebp
0x0041dcb2:	popl %esi
0x0041dcb3:	movl %ebx, 0xc(%ebp)
0x0041dcb6:	orl %eax, %eax
0x0041dcb8:	je 63
0x0041dcba:	js 72
0x0041dcbc:	movl %edi, 0x8(%ebx)
0x0041dcbf:	pushl %ebx
0x0041dcc0:	call 0x0041c298
0x0041c298:	pushl %ebp
0x0041c299:	movl %ebp, %esp
0x0041c29b:	pushl %ebx
0x0041c29c:	pushl %esi
0x0041c29d:	pushl %edi
0x0041c29e:	pushl %ebp
0x0041c29f:	pushl $0x0<UINT8>
0x0041c2a1:	pushl $0x0<UINT8>
0x0041c2a3:	pushl $0x41c2b0<UINT32>
0x0041c2a8:	pushl 0x8(%ebp)
0x0041c2ab:	call 0x00428676
0x00428676:	jmp RtlUnwind@KERNEL32.dll
RtlUnwind@KERNEL32.dll: API Node	
0x0041c2b0:	popl %ebp
0x0041c2b1:	popl %edi
0x0041c2b2:	popl %esi
0x0041c2b3:	popl %ebx
0x0041c2b4:	movl %esp, %ebp
0x0041c2b6:	popl %ebp
0x0041c2b7:	ret

0x0041dcc5:	addl %esp, $0x4<UINT8>
0x0041dcc8:	leal %ebp, 0x10(%ebx)
0x0041dccb:	pushl %esi
0x0041dccc:	pushl %ebx
0x0041dccd:	call 0x0041c2da
0x0041c2da:	pushl %ebx
0x0041c2db:	pushl %esi
0x0041c2dc:	pushl %edi
0x0041c2dd:	movl %eax, 0x10(%esp)
0x0041c2e1:	pushl %eax
0x0041c2e2:	pushl $0xfffffffe<UINT8>
0x0041c2e4:	pushl $0x41c2b8<UINT32>
0x0041c2e9:	pushl %fs:0
0x0041c2f0:	movl %fs:0, %esp
0x0041c2f7:	movl %eax, 0x20(%esp)
0x0041c2fb:	movl %ebx, 0x8(%eax)
0x0041c2fe:	movl %esi, 0xc(%eax)
0x0041c301:	cmpl %esi, $0xffffffff<UINT8>
0x0041c304:	je 46
0x0041c306:	cmpl %esi, 0x24(%esp)
0x0041c30a:	je 0x0041c334
0x0041c334:	popl %fs:0
0x0041c33b:	addl %esp, $0xc<UINT8>
0x0041c33e:	popl %edi
0x0041c33f:	popl %esi
0x0041c340:	popl %ebx
0x0041c341:	ret

0x0041dcd2:	addl %esp, $0x8<UINT8>
0x0041dcd5:	leal %ecx, (%esi,%esi,2)
0x0041dcd8:	pushl $0x1<UINT8>
0x0041dcda:	movl %eax, 0x8(%edi,%ecx,4)
0x0041dcde:	call 0x0041c36e
0x0041c36e:	pushl %ebx
0x0041c36f:	pushl %ecx
0x0041c370:	movl %ebx, $0x4670d0<UINT32>
0x0041c375:	movl %ecx, 0x8(%ebp)
0x0041c378:	movl 0x8(%ebx), %ecx
0x0041c37b:	movl 0x4(%ebx), %eax
0x0041c37e:	movl 0xc(%ebx), %ebp
0x0041c381:	popl %ecx
0x0041c382:	popl %ebx
0x0041c383:	ret $0x4<UINT16>

0x0041dce3:	movl %eax, (%edi,%ecx,4)
0x0041dce6:	movl 0xc(%ebx), %eax
0x0041dce9:	movl %eax, 0x8(%edi,%ecx,4)
0x0041dced:	xorl %ebx, %ebx
0x0041dcef:	xorl %ecx, %ecx
0x0041dcf1:	xorl %edx, %edx
0x0041dcf3:	xorl %esi, %esi
0x0041dcf5:	xorl %edi, %edi
0x0041dcf7:	call 0x0041e1a9
0x0041e1a9:	movl %esp, -24(%ebp)
0x0041e1ac:	movl %edi, -36(%ebp)
0x0041e1af:	cmpl -28(%ebp), $0x0<UINT8>
0x0041e1b3:	jne 6
0x0041e1b5:	pushl %edi
0x0041e1b6:	call 0x0041d7ad
0x0041d7ad:	pushl $0x0<UINT8>
0x0041d7af:	pushl $0x1<UINT8>
0x0041d7b1:	pushl 0xc(%esp)
0x0041d7b5:	call 0x0041d6d9
0x0041d6d9:	pushl $0x8<UINT8>
0x0041d6db:	pushl $0x45b988<UINT32>
0x0041d6e0:	call 0x0041eed4
0x0041d6e5:	pushl $0x8<UINT8>
0x0041d6e7:	call 0x004226ec
0x0041d6ec:	popl %ecx
0x0041d6ed:	xorl %edi, %edi
0x0041d6ef:	movl -4(%ebp), %edi
0x0041d6f2:	xorl %esi, %esi
0x0041d6f4:	incl %esi
0x0041d6f5:	cmpl 0x46a598, %esi
0x0041d6fb:	jne 0x0041d70d
0x0041d70d:	movl 0x46a594, %esi
0x0041d713:	movb %al, 0x10(%ebp)
0x0041d716:	movb 0x46a590, %al
0x0041d71b:	cmpl 0xc(%ebp), %edi
0x0041d71e:	jne 0x0041d757
0x0041d757:	pushl $0x466094<UINT32>
0x0041d75c:	movl %eax, $0x46608c<UINT32>
0x0041d761:	call 0x0041d657
0x0041d657:	pushl %esi
0x0041d658:	movl %esi, %eax
0x0041d65a:	jmp 0x0041d667
0x0041d667:	cmpl %esi, 0x8(%esp)
0x0041d66b:	jb 0x0041d65c
0x0041d65c:	movl %eax, (%esi)
0x0041d65e:	testl %eax, %eax
0x0041d660:	je 2
0x0041d662:	call 0x65746e69
0x65746e69:	addb (%eax), %al
0x0041dcf9:	movl %edi, 0x8(%ebx)
0x0041dcfc:	leal %ecx, (%esi,%esi,2)
0x0041dcff:	movl %esi, (%edi,%ecx,4)
0x0041dd02:	jmp 0x0041dc90
0x0041dd12:	movl %eax, $0x1<UINT32>
0x0041dd17:	jmp 0x0041dd2e
0x0041dd2e:	popl %ebp
0x0041dd2f:	popl %edi
0x0041dd30:	popl %esi
0x0041dd31:	popl %ebx
0x0041dd32:	movl %esp, %ebp
0x0041dd34:	popl %ebp
0x0041dd35:	ret

0x65746e6b:	addb (%eax), %al
0x65746e6d:	addb (%eax), %al
0x65746e6f:	addb (%eax), %al
0x65746e71:	addb (%eax), %al
0x65746e73:	addb (%eax), %al
0x65746e75:	addb (%eax), %al
0x65746e77:	addb (%eax), %al
0x65746e79:	addb (%eax), %al
0x65746e7b:	addb (%eax), %al
0x65746e7d:	addb (%eax), %al
0x65746e7f:	addb (%eax), %al
0x65746e81:	addb (%eax), %al
0x65746e83:	addb (%eax), %al
0x65746e85:	addb (%eax), %al
0x65746e87:	addb (%eax), %al
0x65746e89:	addb (%eax), %al
0x65746e8b:	addb (%eax), %al
0x65746e8d:	addb (%eax), %al
0x65746e8f:	addb (%eax), %al
0x65746e91:	addb (%eax), %al
0x65746e93:	addb (%eax), %al
0x65746e95:	addb (%eax), %al
0x65746e97:	addb (%eax), %al
0x65746e99:	addb (%eax), %al
0x65746e9b:	addb (%eax), %al
0x65746e9d:	addb (%eax), %al
0x65746e9f:	addb (%eax), %al
0x65746ea1:	addb (%eax), %al
0x65746ea3:	addb (%eax), %al
0x65746ea5:	addb (%eax), %al
0x65746ea7:	addb (%eax), %al
0x65746ea9:	addb (%eax), %al
0x65746eab:	addb (%eax), %al
0x65746ead:	addb (%eax), %al
0x65746eaf:	addb (%eax), %al
0x65746eb1:	addb (%eax), %al
0x65746eb3:	addb (%eax), %al
0x65746eb5:	addb (%eax), %al
0x65746eb7:	addb (%eax), %al
0x65746eb9:	addb (%eax), %al
0x65746ebb:	addb (%eax), %al
0x65746ebd:	addb (%eax), %al
0x65746ebf:	addb (%eax), %al
0x65746ec1:	addb (%eax), %al
0x65746ec3:	addb (%eax), %al
0x65746ec5:	addb (%eax), %al
0x65746ec7:	addb (%eax), %al
0x65746ec9:	addb (%eax), %al
0x65746ecb:	addb (%eax), %al
