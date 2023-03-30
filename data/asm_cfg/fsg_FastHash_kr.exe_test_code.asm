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
