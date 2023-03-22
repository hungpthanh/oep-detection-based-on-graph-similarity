0x004880a0:	pusha
0x004880a1:	movl %esi, $0x452000<UINT32>
0x004880a6:	leal %edi, -331776(%esi)
0x004880ac:	pushl %edi
0x004880ad:	orl %ebp, $0xffffffff<UINT8>
0x004880b0:	jmp 0x004880c2
0x004880c2:	movl %ebx, (%esi)
0x004880c4:	subl %esi, $0xfffffffc<UINT8>
0x004880c7:	adcl %ebx, %ebx
0x004880c9:	jb 0x004880b8
0x004880b8:	movb %al, (%esi)
0x004880ba:	incl %esi
0x004880bb:	movb (%edi), %al
0x004880bd:	incl %edi
0x004880be:	addl %ebx, %ebx
0x004880c0:	jne 0x004880c9
0x004880cb:	movl %eax, $0x1<UINT32>
0x004880d0:	addl %ebx, %ebx
0x004880d2:	jne 0x004880db
0x004880db:	adcl %eax, %eax
0x004880dd:	addl %ebx, %ebx
0x004880df:	jae 0x004880ec
0x004880e1:	jne 0x0048810b
0x0048810b:	xorl %ecx, %ecx
0x0048810d:	subl %eax, $0x3<UINT8>
0x00488110:	jb 0x00488123
0x00488123:	addl %ebx, %ebx
0x00488125:	jne 0x0048812e
0x0048812e:	jb 0x004880fc
0x00488130:	incl %ecx
0x00488131:	addl %ebx, %ebx
0x00488133:	jne 0x0048813c
0x0048813c:	jb 0x004880fc
0x0048813e:	addl %ebx, %ebx
0x00488140:	jne 0x00488149
0x00488149:	adcl %ecx, %ecx
0x0048814b:	addl %ebx, %ebx
0x0048814d:	jae 0x0048813e
0x0048814f:	jne 0x0048815a
0x0048815a:	addl %ecx, $0x2<UINT8>
0x0048815d:	cmpl %ebp, $0xfffffb00<UINT32>
0x00488163:	adcl %ecx, $0x2<UINT8>
0x00488166:	leal %edx, (%edi,%ebp)
0x00488169:	cmpl %ebp, $0xfffffffc<UINT8>
0x0048816c:	jbe 0x0048817c
0x0048816e:	movb %al, (%edx)
0x00488170:	incl %edx
0x00488171:	movb (%edi), %al
0x00488173:	incl %edi
0x00488174:	decl %ecx
0x00488175:	jne 0x0048816e
0x00488177:	jmp 0x004880be
0x00488112:	shll %eax, $0x8<UINT8>
0x00488115:	movb %al, (%esi)
0x00488117:	incl %esi
0x00488118:	xorl %eax, $0xffffffff<UINT8>
0x0048811b:	je 0x00488192
0x0048811d:	sarl %eax
0x0048811f:	movl %ebp, %eax
0x00488121:	jmp 0x0048812e
0x0048817c:	movl %eax, (%edx)
0x0048817e:	addl %edx, $0x4<UINT8>
0x00488181:	movl (%edi), %eax
0x00488183:	addl %edi, $0x4<UINT8>
0x00488186:	subl %ecx, $0x4<UINT8>
0x00488189:	ja 0x0048817c
0x0048818b:	addl %edi, %ecx
0x0048818d:	jmp 0x004880be
0x004880fc:	addl %ebx, %ebx
0x004880fe:	jne 0x00488107
0x00488107:	adcl %ecx, %ecx
0x00488109:	jmp 0x0048815d
0x004880d4:	movl %ebx, (%esi)
0x004880d6:	subl %esi, $0xfffffffc<UINT8>
0x004880d9:	adcl %ebx, %ebx
0x004880e3:	movl %ebx, (%esi)
0x004880e5:	subl %esi, $0xfffffffc<UINT8>
0x004880e8:	adcl %ebx, %ebx
0x004880ea:	jb 0x0048810b
0x00488100:	movl %ebx, (%esi)
0x00488102:	subl %esi, $0xfffffffc<UINT8>
0x00488105:	adcl %ebx, %ebx
0x004880ec:	decl %eax
0x004880ed:	addl %ebx, %ebx
0x004880ef:	jne 0x004880f8
0x004880f8:	adcl %eax, %eax
0x004880fa:	jmp 0x004880d0
0x00488135:	movl %ebx, (%esi)
0x00488137:	subl %esi, $0xfffffffc<UINT8>
0x0048813a:	adcl %ebx, %ebx
0x00488142:	movl %ebx, (%esi)
0x00488144:	subl %esi, $0xfffffffc<UINT8>
0x00488147:	adcl %ebx, %ebx
0x00488151:	movl %ebx, (%esi)
0x00488153:	subl %esi, $0xfffffffc<UINT8>
0x00488156:	adcl %ebx, %ebx
0x00488158:	jae 0x0048813e
0x004880f1:	movl %ebx, (%esi)
0x004880f3:	subl %esi, $0xfffffffc<UINT8>
0x004880f6:	adcl %ebx, %ebx
0x00488127:	movl %ebx, (%esi)
0x00488129:	subl %esi, $0xfffffffc<UINT8>
0x0048812c:	adcl %ebx, %ebx
0x00488192:	popl %esi
0x00488193:	leal %edi, 0x22000(%esi)
0x00488199:	movl %ecx, $0x2446<UINT32>
0x0048819e:	movb %al, (%edi)
0x004881a0:	incl %edi
0x004881a1:	subb %al, $0xffffffe8<UINT8>
0x004881a3:	cmpb %al, $0x1<UINT8>
0x004881a5:	ja 0x0048819e
0x004881a7:	cmpb (%edi), $0x12<UINT8>
0x004881aa:	jne 0x0048819e
0x004881ac:	movl %eax, (%edi)
0x004881ae:	movb %bl, 0x4(%edi)
0x004881b1:	shrw %ax, $0x8<UINT8>
0x004881b5:	roll %eax, $0x10<UINT8>
0x004881b8:	xchgb %ah, %al
0x004881ba:	subl %eax, %edi
0x004881bc:	subb %bl, $0xffffffe8<UINT8>
0x004881bf:	addl %eax, %esi
0x004881c1:	movl (%edi), %eax
0x004881c3:	addl %edi, $0x5<UINT8>
0x004881c6:	movb %al, %bl
0x004881c8:	loop 0x004881a3
0x004881ca:	leal %edi, 0x83000(%esi)
0x004881d0:	movl %eax, (%edi)
0x004881d2:	orl %eax, %eax
0x004881d4:	je 0x00488212
0x004881d6:	movl %ebx, 0x4(%edi)
0x004881d9:	leal %eax, 0x89c24(%eax,%esi)
0x004881e0:	addl %ebx, %esi
0x004881e2:	pushl %eax
0x004881e3:	addl %edi, $0x8<UINT8>
0x004881e6:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x004881ec:	xchgl %ebp, %eax
0x004881ed:	movb %al, (%edi)
0x004881ef:	incl %edi
0x004881f0:	orb %al, %al
0x004881f2:	je 0x004881d0
0x004881f4:	movl %ecx, %edi
0x004881f6:	pushl %edi
0x004881f7:	decl %eax
0x004881f8:	repn scasb %al, %es:(%edi)
0x004881fa:	pushl %ebp
0x004881fb:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00488201:	orl %eax, %eax
0x00488203:	je 7
0x00488205:	movl (%ebx), %eax
0x00488207:	addl %ebx, $0x4<UINT8>
0x0048820a:	jmp 0x004881ed
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x00488212:	addl %edi, $0x4<UINT8>
0x00488215:	leal %ebx, -4(%esi)
0x00488218:	xorl %eax, %eax
0x0048821a:	movb %al, (%edi)
0x0048821c:	incl %edi
0x0048821d:	orl %eax, %eax
0x0048821f:	je 0x00488243
0x00488221:	cmpb %al, $0xffffffef<UINT8>
0x00488223:	ja 0x00488236
0x00488225:	addl %ebx, %eax
0x00488227:	movl %eax, (%ebx)
0x00488229:	xchgb %ah, %al
0x0048822b:	roll %eax, $0x10<UINT8>
0x0048822e:	xchgb %ah, %al
0x00488230:	addl %eax, %esi
0x00488232:	movl (%ebx), %eax
0x00488234:	jmp 0x00488218
0x00488236:	andb %al, $0xf<UINT8>
0x00488238:	shll %eax, $0x10<UINT8>
0x0048823b:	movw %ax, (%edi)
0x0048823e:	addl %edi, $0x2<UINT8>
0x00488241:	jmp 0x00488225
0x00488243:	movl %ebp, 0x89d04(%esi)
0x00488249:	leal %edi, -4096(%esi)
0x0048824f:	movl %ebx, $0x1000<UINT32>
0x00488254:	pushl %eax
0x00488255:	pushl %esp
0x00488256:	pushl $0x4<UINT8>
0x00488258:	pushl %ebx
0x00488259:	pushl %edi
0x0048825a:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0048825c:	leal %eax, 0x15f(%edi)
0x00488262:	andb (%eax), $0x7f<UINT8>
0x00488265:	andb 0x28(%eax), $0x7f<UINT8>
0x00488269:	popl %eax
0x0048826a:	pushl %eax
0x0048826b:	pushl %esp
0x0048826c:	pushl %eax
0x0048826d:	pushl %ebx
0x0048826e:	pushl %edi
0x0048826f:	call VirtualProtect@kernel32.dll
0x00488271:	popl %eax
0x00488272:	popa
0x00488273:	leal %eax, -128(%esp)
0x00488277:	pushl $0x0<UINT8>
0x00488279:	cmpl %esp, %eax
0x0048827b:	jne 0x00488277
0x0048827d:	subl %esp, $0xffffff80<UINT8>
0x00488280:	jmp 0x0045bfe6
0x0045bfe6:	call 0x0045c275
0x0045c275:	pushl %ebp
0x0045c276:	movl %ebp, %esp
0x0045c278:	subl %esp, $0x14<UINT8>
0x0045c27b:	andl -12(%ebp), $0x0<UINT8>
0x0045c27f:	andl -8(%ebp), $0x0<UINT8>
0x0045c283:	movl %eax, 0x41e17c
0x0045c288:	pushl %esi
0x0045c289:	pushl %edi
0x0045c28a:	movl %edi, $0xbb40e64e<UINT32>
0x0045c28f:	movl %esi, $0xffff0000<UINT32>
0x0045c294:	cmpl %eax, %edi
0x0045c296:	je 0x0045c2a5
0x0045c2a5:	leal %eax, -12(%ebp)
0x0045c2a8:	pushl %eax
0x0045c2a9:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0045c2af:	movl %eax, -8(%ebp)
0x0045c2b2:	xorl %eax, -12(%ebp)
0x0045c2b5:	movl -4(%ebp), %eax
0x0045c2b8:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0045c2be:	xorl -4(%ebp), %eax
0x0045c2c1:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0045c2c7:	xorl -4(%ebp), %eax
0x0045c2ca:	leal %eax, -20(%ebp)
0x0045c2cd:	pushl %eax
0x0045c2ce:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0045c2d4:	movl %ecx, -16(%ebp)
0x0045c2d7:	leal %eax, -4(%ebp)
0x0045c2da:	xorl %ecx, -20(%ebp)
0x0045c2dd:	xorl %ecx, -4(%ebp)
0x0045c2e0:	xorl %ecx, %eax
0x0045c2e2:	cmpl %ecx, %edi
0x0045c2e4:	jne 0x0045c2ed
0x0045c2ed:	testl %esi, %ecx
0x0045c2ef:	jne 0x0045c2fd
0x0045c2fd:	movl 0x41e17c, %ecx
0x0045c303:	notl %ecx
0x0045c305:	movl 0x41e178, %ecx
0x0045c30b:	popl %edi
0x0045c30c:	popl %esi
0x0045c30d:	movl %esp, %ebp
0x0045c30f:	popl %ebp
0x0045c310:	ret

0x0045bfeb:	jmp 0x0045be7e
0x0045be7e:	pushl $0x14<UINT8>
0x0045be80:	pushl $0x47b000<UINT32>
0x0045be85:	call 0x0045c5d0
0x0045c5d0:	pushl $0x45c860<UINT32>
0x0045c5d5:	pushl %fs:0
0x0045c5dc:	movl %eax, 0x10(%esp)
0x0045c5e0:	movl 0x10(%esp), %ebp
0x0045c5e4:	leal %ebp, 0x10(%esp)
0x0045c5e8:	subl %esp, %eax
0x0045c5ea:	pushl %ebx
0x0045c5eb:	pushl %esi
0x0045c5ec:	pushl %edi
0x0045c5ed:	movl %eax, 0x41e17c
0x0045c5f2:	xorl -4(%ebp), %eax
0x0045c5f5:	xorl %eax, %ebp
0x0045c5f7:	pushl %eax
0x0045c5f8:	movl -24(%ebp), %esp
0x0045c5fb:	pushl -8(%ebp)
0x0045c5fe:	movl %eax, -4(%ebp)
0x0045c601:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0045c608:	movl -8(%ebp), %eax
0x0045c60b:	leal %eax, -16(%ebp)
0x0045c60e:	movl %fs:0, %eax
0x0045c614:	repn ret

0x0045be8a:	pushl $0x1<UINT8>
0x0045be8c:	call 0x0045c086
0x0045c086:	pushl %ebp
0x0045c087:	movl %ebp, %esp
0x0045c089:	cmpl 0x8(%ebp), $0x0<UINT8>
0x0045c08d:	jne 0x0045c096
0x0045c096:	call 0x0045c62b
0x0045c62b:	pushl %ebp
0x0045c62c:	movl %ebp, %esp
0x0045c62e:	andl 0x41cc40, $0x0<UINT8>
0x0045c635:	subl %esp, $0x28<UINT8>
0x0045c638:	pushl %ebx
0x0045c639:	xorl %ebx, %ebx
0x0045c63b:	incl %ebx
0x0045c63c:	orl 0x41e190, %ebx
0x0045c642:	pushl $0xa<UINT8>
0x0045c644:	call 0x0047a9f2
0x0047a9f2:	jmp IsProcessorFeaturePresent@KERNEL32.DLL
IsProcessorFeaturePresent@KERNEL32.DLL: API Node	
0x0045c649:	testl %eax, %eax
0x0045c64b:	je 365
0x0045c651:	andl -16(%ebp), $0x0<UINT8>
0x0045c655:	xorl %eax, %eax
0x0045c657:	orl 0x41e190, $0x2<UINT8>
0x0045c65e:	xorl %ecx, %ecx
0x0045c660:	pushl %esi
0x0045c661:	pushl %edi
0x0045c662:	movl 0x41cc40, %ebx
0x0045c668:	leal %edi, -40(%ebp)
0x0045c66b:	pushl %ebx
0x0045c66c:	cpuid
0x0045c66e:	movl %esi, %ebx
0x0045c670:	popl %ebx
0x0045c671:	movl (%edi), %eax
0x0045c673:	movl 0x4(%edi), %esi
0x0045c676:	movl 0x8(%edi), %ecx
0x0045c679:	movl 0xc(%edi), %edx
0x0045c67c:	movl %eax, -40(%ebp)
0x0045c67f:	movl %ecx, -28(%ebp)
0x0045c682:	movl -8(%ebp), %eax
0x0045c685:	xorl %ecx, $0x49656e69<UINT32>
0x0045c68b:	movl %eax, -32(%ebp)
0x0045c68e:	xorl %eax, $0x6c65746e<UINT32>
0x0045c693:	orl %ecx, %eax
0x0045c695:	movl %eax, -36(%ebp)
0x0045c698:	pushl $0x1<UINT8>
0x0045c69a:	xorl %eax, $0x756e6547<UINT32>
0x0045c69f:	orl %ecx, %eax
0x0045c6a1:	popl %eax
0x0045c6a2:	pushl $0x0<UINT8>
0x0045c6a4:	popl %ecx
0x0045c6a5:	pushl %ebx
0x0045c6a6:	cpuid
0x0045c6a8:	movl %esi, %ebx
0x0045c6aa:	popl %ebx
0x0045c6ab:	movl (%edi), %eax
0x0045c6ad:	movl 0x4(%edi), %esi
0x0045c6b0:	movl 0x8(%edi), %ecx
0x0045c6b3:	movl 0xc(%edi), %edx
0x0045c6b6:	jne 67
0x0045c6b8:	movl %eax, -40(%ebp)
0x0045c6bb:	andl %eax, $0xfff3ff0<UINT32>
0x0045c6c0:	cmpl %eax, $0x106c0<UINT32>
0x0045c6c5:	je 35
0x0045c6c7:	cmpl %eax, $0x20660<UINT32>
0x0045c6cc:	je 28
0x0045c6ce:	cmpl %eax, $0x20670<UINT32>
0x0045c6d3:	je 21
0x0045c6d5:	cmpl %eax, $0x30650<UINT32>
0x0045c6da:	je 14
0x0045c6dc:	cmpl %eax, $0x30660<UINT32>
0x0045c6e1:	je 7
0x0045c6e3:	cmpl %eax, $0x30670<UINT32>
0x0045c6e8:	jne 0x0045c6fb
0x0045c6fb:	movl %edi, 0x41cc44
0x0045c701:	cmpl -8(%ebp), $0x7<UINT8>
0x0045c705:	movl %eax, -28(%ebp)
0x0045c708:	movl -24(%ebp), %eax
0x0045c70b:	movl %eax, -32(%ebp)
0x0045c70e:	movl -4(%ebp), %eax
0x0045c711:	movl -20(%ebp), %eax
0x0045c714:	jl 0x0045c748
0x0045c748:	popl %edi
0x0045c749:	popl %esi
0x0045c74a:	testl %eax, $0x100000<UINT32>
0x0045c74f:	je 0x0045c7be
0x0045c7be:	xorl %eax, %eax
0x0045c7c0:	popl %ebx
0x0045c7c1:	movl %esp, %ebp
0x0045c7c3:	popl %ebp
0x0045c7c4:	ret

0x0045c09b:	call 0x0045c7d1
0x0045c7d1:	call 0x0046bf93
0x0046bf93:	movl %eax, 0x41e17c
0x0046bf98:	andl %eax, $0x1f<UINT8>
0x0046bf9b:	pushl $0x20<UINT8>
0x0046bf9d:	popl %ecx
0x0046bf9e:	subl %ecx, %eax
0x0046bfa0:	xorl %eax, %eax
0x0046bfa2:	rorl %eax, %cl
0x0046bfa4:	xorl %eax, 0x41e17c
0x0046bfaa:	movl 0x41ce68, %eax
0x0046bfaf:	ret

0x0045c7d6:	call 0x0046bf27
0x0046bf27:	movl %eax, 0x41e17c
0x0046bf2c:	movl %edx, $0x41ce68<UINT32>
0x0046bf31:	pushl %esi
0x0046bf32:	andl %eax, $0x1f<UINT8>
0x0046bf35:	xorl %esi, %esi
0x0046bf37:	pushl $0x20<UINT8>
0x0046bf39:	popl %ecx
0x0046bf3a:	subl %ecx, %eax
0x0046bf3c:	movl %eax, $0x41ce44<UINT32>
0x0046bf41:	rorl %esi, %cl
0x0046bf43:	xorl %ecx, %ecx
0x0046bf45:	xorl %esi, 0x41e17c
0x0046bf4b:	cmpl %edx, %eax
0x0046bf4d:	sbbl %edx, %edx
0x0046bf4f:	andl %edx, $0xfffffff7<UINT8>
0x0046bf52:	addl %edx, $0x9<UINT8>
0x0046bf55:	incl %ecx
0x0046bf56:	movl (%eax), %esi
0x0046bf58:	leal %eax, 0x4(%eax)
0x0046bf5b:	cmpl %ecx, %edx
0x0046bf5d:	jne 0x0046bf55
0x0046bf5f:	popl %esi
0x0046bf60:	ret

0x0045c7db:	call 0x0046bca4
0x0046bca4:	pushl %esi
0x0046bca5:	pushl %edi
0x0046bca6:	movl %edi, $0x41ce18<UINT32>
0x0046bcab:	xorl %esi, %esi
0x0046bcad:	pushl $0x0<UINT8>
0x0046bcaf:	pushl $0xfa0<UINT32>
0x0046bcb4:	pushl %edi
0x0046bcb5:	call 0x0046bee1
0x0046bee1:	pushl %ebp
0x0046bee2:	movl %ebp, %esp
0x0046bee4:	pushl %esi
0x0046bee5:	pushl $0x415164<UINT32>
0x0046beea:	pushl $0x41515c<UINT32>
0x0046beef:	pushl $0x415164<UINT32>
0x0046bef4:	pushl $0x8<UINT8>
0x0046bef6:	call 0x0046bd0f
0x0046bd0f:	pushl %ebp
0x0046bd10:	movl %ebp, %esp
0x0046bd12:	movl %eax, 0x8(%ebp)
0x0046bd15:	xorl %ecx, %ecx
0x0046bd17:	pushl %ebx
0x0046bd18:	pushl %esi
0x0046bd19:	pushl %edi
0x0046bd1a:	leal %ebx, 0x41ce44(,%eax,4)
0x0046bd21:	xorl %eax, %eax
0x0046bd23:	cmpxchgl (%ebx), %ecx
0x0046bd27:	movl %edx, 0x41e17c
0x0046bd2d:	orl %edi, $0xffffffff<UINT8>
0x0046bd30:	movl %ecx, %edx
0x0046bd32:	movl %esi, %edx
0x0046bd34:	andl %ecx, $0x1f<UINT8>
0x0046bd37:	xorl %esi, %eax
0x0046bd39:	rorl %esi, %cl
0x0046bd3b:	cmpl %esi, %edi
0x0046bd3d:	je 105
0x0046bd3f:	testl %esi, %esi
0x0046bd41:	je 0x0046bd47
0x0046bd47:	movl %esi, 0x10(%ebp)
0x0046bd4a:	cmpl %esi, 0x14(%ebp)
0x0046bd4d:	je 26
0x0046bd4f:	pushl (%esi)
0x0046bd51:	call 0x0046bdaf
0x0046bdaf:	pushl %ebp
0x0046bdb0:	movl %ebp, %esp
0x0046bdb2:	pushl %ebx
0x0046bdb3:	movl %ebx, 0x8(%ebp)
0x0046bdb6:	xorl %ecx, %ecx
0x0046bdb8:	pushl %edi
0x0046bdb9:	xorl %eax, %eax
0x0046bdbb:	leal %edi, 0x41ce34(,%ebx,4)
0x0046bdc2:	cmpxchgl (%edi), %ecx
0x0046bdc6:	movl %ecx, %eax
0x0046bdc8:	testl %ecx, %ecx
0x0046bdca:	je 0x0046bdd7
0x0046bdd7:	movl %ebx, 0x415068(,%ebx,4)
0x0046bdde:	pushl %esi
0x0046bddf:	pushl $0x800<UINT32>
0x0046bde4:	pushl $0x0<UINT8>
0x0046bde6:	pushl %ebx
0x0046bde7:	call LoadLibraryExW@KERNEL32.DLL
LoadLibraryExW@KERNEL32.DLL: API Node	
0x0046bded:	movl %esi, %eax
0x0046bdef:	testl %esi, %esi
0x0046bdf1:	jne 0x0046be1a
0x0046be1a:	movl %eax, %esi
0x0046be1c:	xchgl (%edi), %eax
0x0046be1e:	testl %eax, %eax
0x0046be20:	je 0x0046be29
0x0046be29:	movl %eax, %esi
0x0046be2b:	popl %esi
0x0046be2c:	popl %edi
0x0046be2d:	popl %ebx
0x0046be2e:	popl %ebp
0x0046be2f:	ret

0x0046bd56:	popl %ecx
0x0046bd57:	testl %eax, %eax
0x0046bd59:	jne 0x0046bd8a
0x0046bd8a:	movl %edx, 0x41e17c
0x0046bd90:	jmp 0x0046bd6b
0x0046bd6b:	testl %eax, %eax
0x0046bd6d:	je 41
0x0046bd6f:	pushl 0xc(%ebp)
0x0046bd72:	pushl %eax
0x0046bd73:	call GetProcAddress@KERNEL32.DLL
0x0046bd79:	movl %esi, %eax
0x0046bd7b:	testl %esi, %esi
0x0046bd7d:	je 0x0046bd92
0x0046bd92:	movl %edx, 0x41e17c
0x0046bd98:	movl %eax, %edx
0x0046bd9a:	pushl $0x20<UINT8>
0x0046bd9c:	andl %eax, $0x1f<UINT8>
0x0046bd9f:	popl %ecx
0x0046bda0:	subl %ecx, %eax
0x0046bda2:	rorl %edi, %cl
0x0046bda4:	xorl %edi, %edx
0x0046bda6:	xchgl (%ebx), %edi
0x0046bda8:	xorl %eax, %eax
0x0046bdaa:	popl %edi
0x0046bdab:	popl %esi
0x0046bdac:	popl %ebx
0x0046bdad:	popl %ebp
0x0046bdae:	ret

0x0046befb:	movl %esi, %eax
0x0046befd:	addl %esp, $0x10<UINT8>
0x0046bf00:	testl %esi, %esi
0x0046bf02:	je 0x0046bf18
0x0046bf18:	pushl 0xc(%ebp)
0x0046bf1b:	pushl 0x8(%ebp)
0x0046bf1e:	call InitializeCriticalSectionAndSpinCount@KERNEL32.DLL
InitializeCriticalSectionAndSpinCount@KERNEL32.DLL: API Node	
0x0046bf24:	popl %esi
0x0046bf25:	popl %ebp
0x0046bf26:	ret

0x0046bcba:	addl %esp, $0xc<UINT8>
0x0046bcbd:	testl %eax, %eax
0x0046bcbf:	je 21
0x0046bcc1:	incl 0x41ce30
0x0046bcc7:	addl %esi, $0x18<UINT8>
0x0046bcca:	addl %edi, $0x18<UINT8>
0x0046bccd:	cmpl %esi, $0x18<UINT8>
0x0046bcd0:	jb -37
0x0046bcd2:	movb %al, $0x1<UINT8>
0x0046bcd4:	jmp 0x0046bcdd
0x0046bcdd:	popl %edi
0x0046bcde:	popl %esi
0x0046bcdf:	ret

0x0045c7e0:	testb %al, %al
0x0045c7e2:	jne 0x0045c7e7
0x0045c7e7:	call 0x0046bc56
0x0046bc56:	pushl $0x46bc3a<UINT32>
0x0046bc5b:	call 0x0046be30
0x0046be30:	pushl %ebp
0x0046be31:	movl %ebp, %esp
0x0046be33:	pushl %esi
0x0046be34:	pushl $0x415120<UINT32>
0x0046be39:	pushl $0x415118<UINT32>
0x0046be3e:	pushl $0x415120<UINT32>
0x0046be43:	pushl $0x4<UINT8>
0x0046be45:	call 0x0046bd0f
0x0046bdf3:	call GetLastError@KERNEL32.DLL
GetLastError@KERNEL32.DLL: API Node	
0x0046bdf9:	cmpl %eax, $0x57<UINT8>
0x0046bdfc:	jne 0x0046be0b
0x0046be0b:	xorl %esi, %esi
0x0046be0d:	testl %esi, %esi
0x0046be0f:	jne 9
0x0046be11:	orl %eax, $0xffffffff<UINT8>
0x0046be14:	xchgl (%edi), %eax
0x0046be16:	xorl %eax, %eax
0x0046be18:	jmp 0x0046be2b
0x0046bd5b:	addl %esi, $0x4<UINT8>
0x0046bd5e:	cmpl %esi, 0x14(%ebp)
0x0046bd61:	jne 0x0046bd4f
0x0046bd7f:	pushl %esi
0x0046bd80:	call 0x0045f1c7
0x0045f1c7:	movl %edi, %edi
0x0045f1c9:	pushl %ebp
0x0045f1ca:	movl %ebp, %esp
0x0045f1cc:	movl %eax, 0x41e17c
0x0045f1d1:	andl %eax, $0x1f<UINT8>
0x0045f1d4:	pushl $0x20<UINT8>
0x0045f1d6:	popl %ecx
0x0045f1d7:	subl %ecx, %eax
0x0045f1d9:	movl %eax, 0x8(%ebp)
0x0045f1dc:	rorl %eax, %cl
0x0045f1de:	xorl %eax, 0x41e17c
0x0045f1e4:	popl %ebp
0x0045f1e5:	ret

0x0046bd85:	popl %ecx
0x0046bd86:	xchgl (%ebx), %eax
0x0046bd88:	jmp 0x0046bd43
0x0046bd43:	movl %eax, %esi
0x0046bd45:	jmp 0x0046bdaa
0x0046be4a:	movl %esi, %eax
0x0046be4c:	addl %esp, $0x10<UINT8>
0x0046be4f:	testl %esi, %esi
0x0046be51:	je 15
0x0046be53:	pushl 0x8(%ebp)
0x0046be56:	movl %ecx, %esi
0x0046be58:	call 0x0045c5c1
0x0045c5c1:	jmp 0x0045c34e
0x0045c34e:	ret

0x0046be5d:	call FlsAlloc@kernel32.dll
FlsAlloc@kernel32.dll: API Node	
0x0046be5f:	popl %esi
0x0046be60:	popl %ebp
0x0046be61:	ret

0x0046bc60:	movl 0x41e250, %eax
0x0046bc65:	popl %ecx
0x0046bc66:	cmpl %eax, $0xffffffff<UINT8>
0x0046bc69:	jne 0x0046bc6e
0x0046bc6e:	pushl $0x41cdf0<UINT32>
0x0046bc73:	pushl %eax
0x0046bc74:	call 0x0046bea4
0x0046bea4:	pushl %ebp
0x0046bea5:	movl %ebp, %esp
0x0046bea7:	pushl %esi
0x0046bea8:	pushl $0x415150<UINT32>
0x0046bead:	pushl $0x415148<UINT32>
0x0046beb2:	pushl $0x415150<UINT32>
0x0046beb7:	pushl $0x7<UINT8>
0x0046beb9:	call 0x0046bd0f
0x0046bdcc:	leal %eax, 0x1(%ecx)
0x0046bdcf:	negl %eax
0x0046bdd1:	sbbl %eax, %eax
0x0046bdd3:	andl %eax, %ecx
0x0046bdd5:	jmp 0x0046be2c
0x0046bebe:	addl %esp, $0x10<UINT8>
0x0046bec1:	movl %esi, %eax
0x0046bec3:	pushl 0xc(%ebp)
0x0046bec6:	pushl 0x8(%ebp)
0x0046bec9:	testl %esi, %esi
0x0046becb:	je 11
0x0046becd:	movl %ecx, %esi
0x0046becf:	call 0x0045c5c1
0x0046bed4:	call FlsSetValue@kernel32.dll
FlsSetValue@kernel32.dll: API Node	
0x0046bed6:	jmp 0x0046bede
0x0046bede:	popl %esi
0x0046bedf:	popl %ebp
0x0046bee0:	ret

0x0046bc79:	popl %ecx
0x0046bc7a:	popl %ecx
0x0046bc7b:	testl %eax, %eax
0x0046bc7d:	jne 0x0046bc86
0x0046bc86:	movb %al, $0x1<UINT8>
0x0046bc88:	ret

0x0045c7ec:	testb %al, %al
0x0045c7ee:	jne 0x0045c7f7
0x0045c7f7:	movb %al, $0x1<UINT8>
0x0045c7f9:	ret

0x0045c0a0:	testb %al, %al
0x0045c0a2:	jne 0x0045c0a8
0x0045c0a8:	call 0x0045f217
0x0045f217:	pushl $0x413908<UINT32>
0x0045f21c:	pushl $0x413890<UINT32>
0x0045f221:	call 0x0046da11
0x0046da11:	movl %edi, %edi
0x0046da13:	pushl %ebp
0x0046da14:	movl %ebp, %esp
0x0046da16:	pushl %ecx
0x0046da17:	movl %eax, 0x41e17c
0x0046da1c:	xorl %eax, %ebp
0x0046da1e:	movl -4(%ebp), %eax
0x0046da21:	pushl %edi
0x0046da22:	movl %edi, 0x8(%ebp)
0x0046da25:	cmpl %edi, 0xc(%ebp)
0x0046da28:	jne 0x0046da2e
0x0046da2e:	pushl %esi
0x0046da2f:	movl %esi, %edi
0x0046da31:	pushl %ebx
0x0046da32:	movl %ebx, (%esi)
0x0046da34:	testl %ebx, %ebx
0x0046da36:	je 0x0046da46
0x0046da38:	movl %ecx, %ebx
0x0046da3a:	call 0x0045c34e
0x0046da40:	call 0x0045f0d9
0x0045f0c7:	pushl $0x41e7c0<UINT32>
0x0045f0cc:	movl %ecx, $0x41d2dc<UINT32>
0x0045f0d1:	call 0x0045f1e6
0x0045f1e6:	movl %edi, %edi
0x0045f1e8:	pushl %ebp
0x0045f1e9:	movl %ebp, %esp
0x0045f1eb:	leal %eax, 0x4(%ecx)
0x0045f1ee:	movl %edx, %eax
0x0045f1f0:	subl %edx, %ecx
0x0045f1f2:	addl %edx, $0x3<UINT8>
0x0045f1f5:	pushl %esi
0x0045f1f6:	xorl %esi, %esi
0x0045f1f8:	shrl %edx, $0x2<UINT8>
0x0045f1fb:	cmpl %eax, %ecx
0x0045f1fd:	sbbl %eax, %eax
0x0045f1ff:	notl %eax
0x0045f201:	andl %eax, %edx
0x0045f203:	je 13
0x0045f205:	movl %edx, 0x8(%ebp)
0x0045f208:	incl %esi
0x0045f209:	movl (%ecx), %edx
0x0045f20b:	leal %ecx, 0x4(%ecx)
0x0045f20e:	cmpl %esi, %eax
0x0045f210:	jne -10
0x0045f212:	popl %esi
0x0045f213:	popl %ebp
0x0045f214:	ret $0x4<UINT16>

0x0045f0d6:	movb %al, $0x1<UINT8>
0x0045f0d8:	ret

0x0046da42:	testb %al, %al
0x0046da44:	je 8
0x0046da46:	addl %esi, $0x8<UINT8>
0x0046da49:	cmpl %esi, 0xc(%ebp)
0x0046da4c:	jne 0x0046da32
0x0045f107:	movl %eax, 0x41e17c
0x0045f10c:	pushl %esi
0x0045f10d:	pushl $0x20<UINT8>
0x0045f10f:	andl %eax, $0x1f<UINT8>
0x0045f112:	xorl %esi, %esi
0x0045f114:	popl %ecx
0x0045f115:	subl %ecx, %eax
0x0045f117:	rorl %esi, %cl
0x0045f119:	xorl %esi, 0x41e17c
0x0045f11f:	pushl %esi
0x0045f120:	call 0x0046dc1c
0x0046dc1c:	movl %edi, %edi
0x0046dc1e:	pushl %ebp
0x0046dc1f:	movl %ebp, %esp
0x0046dc21:	pushl 0x8(%ebp)
0x0046dc24:	movl %ecx, $0x41d2c4<UINT32>
0x0046dc29:	call 0x0045f1e6
0x0046dc2e:	popl %ebp
0x0046dc2f:	ret

0x0045f125:	pushl %esi
0x0045f126:	call 0x0046dcee
0x0046dcee:	movl %edi, %edi
0x0046dcf0:	pushl %ebp
0x0046dcf1:	movl %ebp, %esp
0x0046dcf3:	pushl 0x8(%ebp)
0x0046dcf6:	movl %ecx, $0x41d2c8<UINT32>
0x0046dcfb:	call 0x0045f1e6
0x0046dd00:	popl %ebp
0x0046dd01:	ret

0x0045f12b:	pushl %esi
0x0045f12c:	call 0x0046de9b
0x0046de9b:	movl %edi, %edi
0x0046de9d:	pushl %ebp
0x0046de9e:	movl %ebp, %esp
0x0046dea0:	pushl 0x8(%ebp)
0x0046dea3:	movl %ecx, $0x41d2cc<UINT32>
0x0046dea8:	call 0x0045f1e6
0x0046dead:	pushl 0x8(%ebp)
0x0046deb0:	movl %ecx, $0x41d2d0<UINT32>
0x0046deb5:	call 0x0045f1e6
0x0046deba:	pushl 0x8(%ebp)
0x0046debd:	movl %ecx, $0x41d2d4<UINT32>
0x0046dec2:	call 0x0045f1e6
0x0046dec7:	pushl 0x8(%ebp)
0x0046deca:	movl %ecx, $0x41d2d8<UINT32>
0x0046decf:	call 0x0045f1e6
0x0046ded4:	popl %ebp
0x0046ded5:	ret

0x0045f131:	pushl %esi
0x0045f132:	call 0x0045f3a6
0x0045f3a6:	movl %edi, %edi
0x0045f3a8:	pushl %ebp
0x0045f3a9:	movl %ebp, %esp
0x0045f3ab:	pushl 0x8(%ebp)
0x0045f3ae:	movl %ecx, $0x41cc60<UINT32>
0x0045f3b3:	call 0x0045f1e6
0x0045f3b8:	popl %ebp
0x0045f3b9:	ret

0x0045f137:	pushl %esi
0x0045f138:	call 0x0046744e
0x0046744e:	movl %edi, %edi
0x00467450:	pushl %ebp
0x00467451:	movl %ebp, %esp
0x00467453:	movl %eax, 0x8(%ebp)
0x00467456:	movl 0x41cc68, %eax
0x0046745b:	popl %ebp
0x0046745c:	ret

0x0045f13d:	addl %esp, $0x14<UINT8>
0x0045f140:	movb %al, $0x1<UINT8>
0x0045f142:	popl %esi
0x0045f143:	ret

0x0046c8f9:	movl %eax, 0x41e17c
0x0046c8fe:	pushl %edi
0x0046c8ff:	pushl $0x20<UINT8>
0x0046c901:	andl %eax, $0x1f<UINT8>
0x0046c904:	movl %edi, $0x41cec0<UINT32>
0x0046c909:	popl %ecx
0x0046c90a:	subl %ecx, %eax
0x0046c90c:	xorl %eax, %eax
0x0046c90e:	rorl %eax, %cl
0x0046c910:	xorl %eax, 0x41e17c
0x0046c916:	pushl $0x20<UINT8>
0x0046c918:	popl %ecx
0x0046c919:	rep stosl %es:(%edi), %eax
0x0046c91b:	movb %al, $0x1<UINT8>
0x0046c91d:	popl %edi
0x0046c91e:	ret

0x0045f101:	movb %al, $0x1<UINT8>
0x0045f103:	ret

0x0046ca82:	movl %edi, %edi
0x0046ca84:	pushl %esi
0x0046ca85:	pushl %edi
0x0046ca86:	movl %edi, $0x41cf48<UINT32>
0x0046ca8b:	xorl %esi, %esi
0x0046ca8d:	pushl $0x0<UINT8>
0x0046ca8f:	pushl $0xfa0<UINT32>
0x0046ca94:	pushl %edi
0x0046ca95:	call 0x0046c6d2
0x0046c6d2:	movl %edi, %edi
0x0046c6d4:	pushl %ebp
0x0046c6d5:	movl %ebp, %esp
0x0046c6d7:	pushl %ecx
0x0046c6d8:	movl %eax, 0x41e17c
0x0046c6dd:	xorl %eax, %ebp
0x0046c6df:	movl -4(%ebp), %eax
0x0046c6e2:	pushl %esi
0x0046c6e3:	pushl $0x415738<UINT32>
0x0046c6e8:	pushl $0x415730<UINT32>
0x0046c6ed:	pushl $0x415164<UINT32>
0x0046c6f2:	pushl $0x14<UINT8>
0x0046c6f4:	call 0x0046c2ac
0x0046c2ac:	movl %edi, %edi
0x0046c2ae:	pushl %ebp
0x0046c2af:	movl %ebp, %esp
0x0046c2b1:	movl %eax, 0x8(%ebp)
0x0046c2b4:	pushl %ebx
0x0046c2b5:	pushl %esi
0x0046c2b6:	pushl %edi
0x0046c2b7:	leal %ebx, 0x41cec0(,%eax,4)
0x0046c2be:	movl %eax, (%ebx)
0x0046c2c0:	movl %edx, 0x41e17c
0x0046c2c6:	orl %edi, $0xffffffff<UINT8>
0x0046c2c9:	movl %ecx, %edx
0x0046c2cb:	movl %esi, %edx
0x0046c2cd:	andl %ecx, $0x1f<UINT8>
0x0046c2d0:	xorl %esi, %eax
0x0046c2d2:	rorl %esi, %cl
0x0046c2d4:	cmpl %esi, %edi
0x0046c2d6:	je 0x0046c341
0x0046c2d8:	testl %esi, %esi
0x0046c2da:	je 0x0046c2e0
0x0046c2e0:	movl %esi, 0x10(%ebp)
0x0046c2e3:	cmpl %esi, 0x14(%ebp)
0x0046c2e6:	je 26
0x0046c2e8:	pushl (%esi)
0x0046c2ea:	call 0x0046c348
0x0046c348:	movl %edi, %edi
0x0046c34a:	pushl %ebp
0x0046c34b:	movl %ebp, %esp
0x0046c34d:	movl %eax, 0x8(%ebp)
0x0046c350:	pushl %edi
0x0046c351:	leal %edi, 0x41ce70(,%eax,4)
0x0046c358:	movl %ecx, (%edi)
0x0046c35a:	testl %ecx, %ecx
0x0046c35c:	je 0x0046c369
0x0046c369:	pushl %ebx
0x0046c36a:	movl %ebx, 0x415180(,%eax,4)
0x0046c371:	pushl %esi
0x0046c372:	pushl $0x800<UINT32>
0x0046c377:	pushl $0x0<UINT8>
0x0046c379:	pushl %ebx
0x0046c37a:	call LoadLibraryExW@KERNEL32.DLL
0x0046c380:	movl %esi, %eax
0x0046c382:	testl %esi, %esi
0x0046c384:	jne 0x0046c3ad
0x0046c3ad:	movl %eax, %esi
0x0046c3af:	xchgl (%edi), %eax
0x0046c3b1:	testl %eax, %eax
0x0046c3b3:	je 0x0046c3bc
0x0046c3bc:	movl %eax, %esi
0x0046c3be:	popl %esi
0x0046c3bf:	popl %ebx
0x0046c3c0:	popl %edi
0x0046c3c1:	popl %ebp
0x0046c3c2:	ret

0x0046c2ef:	popl %ecx
0x0046c2f0:	testl %eax, %eax
0x0046c2f2:	jne 0x0046c323
0x0046c323:	movl %edx, 0x41e17c
0x0046c329:	jmp 0x0046c304
0x0046c304:	testl %eax, %eax
0x0046c306:	je 41
0x0046c308:	pushl 0xc(%ebp)
0x0046c30b:	pushl %eax
0x0046c30c:	call GetProcAddress@KERNEL32.DLL
0x0046c312:	movl %esi, %eax
0x0046c314:	testl %esi, %esi
0x0046c316:	je 0x0046c32b
0x0046c32b:	movl %edx, 0x41e17c
0x0046c331:	movl %eax, %edx
0x0046c333:	pushl $0x20<UINT8>
0x0046c335:	andl %eax, $0x1f<UINT8>
0x0046c338:	popl %ecx
0x0046c339:	subl %ecx, %eax
0x0046c33b:	rorl %edi, %cl
0x0046c33d:	xorl %edi, %edx
0x0046c33f:	xchgl (%ebx), %edi
0x0046c341:	xorl %eax, %eax
0x0046c343:	popl %edi
0x0046c344:	popl %esi
0x0046c345:	popl %ebx
0x0046c346:	popl %ebp
0x0046c347:	ret

0x0046c6f9:	movl %esi, %eax
0x0046c6fb:	addl %esp, $0x10<UINT8>
0x0046c6fe:	testl %esi, %esi
0x0046c700:	je 0x0046c717
0x0046c717:	pushl 0xc(%ebp)
0x0046c71a:	pushl 0x8(%ebp)
0x0046c71d:	call InitializeCriticalSectionAndSpinCount@KERNEL32.DLL
0x0046c723:	movl %ecx, -4(%ebp)
0x0046c726:	xorl %ecx, %ebp
0x0046c728:	popl %esi
0x0046c729:	call 0x0045bc59
0x0045bc59:	cmpl %ecx, 0x41e17c
0x0045bc5f:	repn jne 2
0x0045bc62:	repn ret

0x0046c72e:	movl %esp, %ebp
0x0046c730:	popl %ebp
0x0046c731:	ret $0xc<UINT16>

0x0046ca9a:	testl %eax, %eax
0x0046ca9c:	je 24
0x0046ca9e:	incl 0x41d080
0x0046caa4:	addl %esi, $0x18<UINT8>
0x0046caa7:	addl %edi, $0x18<UINT8>
0x0046caaa:	cmpl %esi, $0x138<UINT32>
0x0046cab0:	jb 0x0046ca8d
0x0046cab2:	movb %al, $0x1<UINT8>
0x0046cab4:	jmp 0x0046cac0
0x0046cac0:	popl %edi
0x0046cac1:	popl %esi
0x0046cac2:	ret

0x0046cb22:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x0046cb28:	testl %eax, %eax
0x0046cb2a:	movl 0x41d084, %eax
0x0046cb2f:	setne %al
0x0046cb32:	ret

0x0046cfb8:	pushl $0x46cd9a<UINT32>
0x0046cfbd:	call 0x0046c485
0x0046c485:	movl %edi, %edi
0x0046c487:	pushl %ebp
0x0046c488:	movl %ebp, %esp
0x0046c48a:	pushl %ecx
0x0046c48b:	movl %eax, 0x41e17c
0x0046c490:	xorl %eax, %ebp
0x0046c492:	movl -4(%ebp), %eax
0x0046c495:	pushl %esi
0x0046c496:	pushl $0x415654<UINT32>
0x0046c49b:	pushl $0x41564c<UINT32>
0x0046c4a0:	pushl $0x415120<UINT32>
0x0046c4a5:	pushl $0x3<UINT8>
0x0046c4a7:	call 0x0046c2ac
0x0046c386:	call GetLastError@KERNEL32.DLL
0x0046c38c:	cmpl %eax, $0x57<UINT8>
0x0046c38f:	jne 0x0046c39e
0x0046c39e:	xorl %esi, %esi
0x0046c3a0:	testl %esi, %esi
0x0046c3a2:	jne 9
0x0046c3a4:	orl %eax, $0xffffffff<UINT8>
0x0046c3a7:	xchgl (%edi), %eax
0x0046c3a9:	xorl %eax, %eax
0x0046c3ab:	jmp 0x0046c3be
0x0046c2f4:	addl %esi, $0x4<UINT8>
0x0046c2f7:	cmpl %esi, 0x14(%ebp)
0x0046c2fa:	jne 0x0046c2e8
0x0046c318:	pushl %esi
0x0046c319:	call 0x0045f1c7
0x0046c31e:	popl %ecx
0x0046c31f:	xchgl (%ebx), %eax
0x0046c321:	jmp 0x0046c2dc
0x0046c2dc:	movl %eax, %esi
0x0046c2de:	jmp 0x0046c343
0x0046c4ac:	movl %esi, %eax
0x0046c4ae:	addl %esp, $0x10<UINT8>
0x0046c4b1:	testl %esi, %esi
0x0046c4b3:	je 15
0x0046c4b5:	pushl 0x8(%ebp)
0x0046c4b8:	movl %ecx, %esi
0x0046c4ba:	call 0x0045c34e
0x0046c4c0:	call FlsAlloc@kernel32.dll
0x0046c4c2:	jmp 0x0046c4ca
0x0046c4ca:	movl %ecx, -4(%ebp)
0x0046c4cd:	xorl %ecx, %ebp
0x0046c4cf:	popl %esi
0x0046c4d0:	call 0x0045bc59
0x0046c4d5:	movl %esp, %ebp
0x0046c4d7:	popl %ebp
0x0046c4d8:	ret $0x4<UINT16>

0x0046cfc2:	movl 0x41e260, %eax
0x0046cfc7:	cmpl %eax, $0xffffffff<UINT8>
0x0046cfca:	jne 0x0046cfcf
0x0046cfcf:	call 0x0046cf33
0x0046cf33:	movl %edi, %edi
0x0046cf35:	pushl %ebx
0x0046cf36:	pushl %esi
0x0046cf37:	pushl %edi
0x0046cf38:	call GetLastError@KERNEL32.DLL
0x0046cf3e:	movl %esi, %eax
0x0046cf40:	xorl %ebx, %ebx
0x0046cf42:	movl %eax, 0x41e260
0x0046cf47:	cmpl %eax, $0xffffffff<UINT8>
0x0046cf4a:	je 12
0x0046cf4c:	pushl %eax
0x0046cf4d:	call 0x0046c531
0x0046c531:	movl %edi, %edi
0x0046c533:	pushl %ebp
0x0046c534:	movl %ebp, %esp
0x0046c536:	pushl %ecx
0x0046c537:	movl %eax, 0x41e17c
0x0046c53c:	xorl %eax, %ebp
0x0046c53e:	movl -4(%ebp), %eax
0x0046c541:	pushl %esi
0x0046c542:	pushl $0x415664<UINT32>
0x0046c547:	pushl $0x41565c<UINT32>
0x0046c54c:	pushl $0x41513c<UINT32>
0x0046c551:	pushl $0x5<UINT8>
0x0046c553:	call 0x0046c2ac
0x0046c35e:	leal %eax, 0x1(%ecx)
0x0046c361:	negl %eax
0x0046c363:	sbbl %eax, %eax
0x0046c365:	andl %eax, %ecx
0x0046c367:	jmp 0x0046c3c0
0x0046c558:	addl %esp, $0x10<UINT8>
0x0046c55b:	movl %esi, %eax
0x0046c55d:	pushl 0x8(%ebp)
0x0046c560:	testl %esi, %esi
0x0046c562:	je 12
0x0046c564:	movl %ecx, %esi
0x0046c566:	call 0x0045c34e
0x0046c56c:	call FlsGetValue@kernel32.dll
FlsGetValue@kernel32.dll: API Node	
0x0046c56e:	jmp 0x0046c576
0x0046c576:	movl %ecx, -4(%ebp)
0x0046c579:	xorl %ecx, %ebp
0x0046c57b:	popl %esi
0x0046c57c:	call 0x0045bc59
0x0046c581:	movl %esp, %ebp
0x0046c583:	popl %ebp
0x0046c584:	ret $0x4<UINT16>

0x0046cf52:	movl %edi, %eax
0x0046cf54:	testl %edi, %edi
0x0046cf56:	jne 81
0x0046cf58:	pushl $0x364<UINT32>
0x0046cf5d:	pushl $0x1<UINT8>
0x0046cf5f:	call 0x0046e261
0x0046e261:	movl %edi, %edi
0x0046e263:	pushl %ebp
0x0046e264:	movl %ebp, %esp
0x0046e266:	pushl %esi
0x0046e267:	movl %esi, 0x8(%ebp)
0x0046e26a:	testl %esi, %esi
0x0046e26c:	je 12
0x0046e26e:	pushl $0xffffffe0<UINT8>
0x0046e270:	xorl %edx, %edx
0x0046e272:	popl %eax
0x0046e273:	divl %eax, %esi
0x0046e275:	cmpl %eax, 0xc(%ebp)
0x0046e278:	jb 52
0x0046e27a:	imull %esi, 0xc(%ebp)
0x0046e27e:	testl %esi, %esi
0x0046e280:	jne 0x0046e299
0x0046e299:	pushl %esi
0x0046e29a:	pushl $0x8<UINT8>
0x0046e29c:	pushl 0x41d084
0x0046e2a2:	call HeapAlloc@KERNEL32.DLL
HeapAlloc@KERNEL32.DLL: API Node	
0x0046e2a8:	testl %eax, %eax
0x0046e2aa:	je -39
0x0046e2ac:	jmp 0x0046e2bb
0x0046e2bb:	popl %esi
0x0046e2bc:	popl %ebp
0x0046e2bd:	ret

0x0046cf64:	movl %edi, %eax
0x0046cf66:	popl %ecx
0x0046cf67:	popl %ecx
0x0046cf68:	testl %edi, %edi
0x0046cf6a:	jne 0x0046cf75
0x0046cf75:	pushl %edi
0x0046cf76:	pushl 0x41e260
0x0046cf7c:	call 0x0046c587
0x0046c587:	movl %edi, %edi
0x0046c589:	pushl %ebp
0x0046c58a:	movl %ebp, %esp
0x0046c58c:	pushl %ecx
0x0046c58d:	movl %eax, 0x41e17c
0x0046c592:	xorl %eax, %ebp
0x0046c594:	movl -4(%ebp), %eax
0x0046c597:	pushl %esi
0x0046c598:	pushl $0x41566c<UINT32>
0x0046c59d:	pushl $0x415664<UINT32>
0x0046c5a2:	pushl $0x415150<UINT32>
0x0046c5a7:	pushl $0x6<UINT8>
0x0046c5a9:	call 0x0046c2ac
0x0046c5ae:	addl %esp, $0x10<UINT8>
0x0046c5b1:	movl %esi, %eax
0x0046c5b3:	pushl 0xc(%ebp)
0x0046c5b6:	pushl 0x8(%ebp)
0x0046c5b9:	testl %esi, %esi
0x0046c5bb:	je 12
0x0046c5bd:	movl %ecx, %esi
0x0046c5bf:	call 0x0045c34e
0x0046c5c5:	call FlsSetValue@kernel32.dll
0x0046c5c7:	jmp 0x0046c5cf
0x0046c5cf:	movl %ecx, -4(%ebp)
0x0046c5d2:	xorl %ecx, %ebp
0x0046c5d4:	popl %esi
0x0046c5d5:	call 0x0045bc59
0x0046c5da:	movl %esp, %ebp
0x0046c5dc:	popl %ebp
0x0046c5dd:	ret $0x8<UINT16>

0x0046cf81:	testl %eax, %eax
0x0046cf83:	jne 0x0046cf88
0x0046cf88:	pushl $0x41d2dc<UINT32>
0x0046cf8d:	pushl %edi
0x0046cf8e:	call 0x0046cd21
0x0046cd21:	movl %edi, %edi
0x0046cd23:	pushl %ebp
0x0046cd24:	movl %ebp, %esp
0x0046cd26:	pushl %ecx
0x0046cd27:	pushl %ecx
0x0046cd28:	movl %eax, 0x8(%ebp)
0x0046cd2b:	xorl %ecx, %ecx
0x0046cd2d:	incl %ecx
0x0046cd2e:	pushl $0x43<UINT8>
0x0046cd30:	movl 0x18(%eax), %ecx
0x0046cd33:	movl %eax, 0x8(%ebp)
0x0046cd36:	movl (%eax), $0x414580<UINT32>
0x0046cd3c:	movl %eax, 0x8(%ebp)
0x0046cd3f:	movl 0x350(%eax), %ecx
0x0046cd45:	movl %eax, 0x8(%ebp)
0x0046cd48:	popl %ecx
0x0046cd49:	movl 0x48(%eax), $0x41e598<UINT32>
0x0046cd50:	movl %eax, 0x8(%ebp)
0x0046cd53:	movw 0x6c(%eax), %cx
0x0046cd57:	movl %eax, 0x8(%ebp)
0x0046cd5a:	movw 0x172(%eax), %cx
0x0046cd61:	movl %eax, 0x8(%ebp)
0x0046cd64:	andl 0x34c(%eax), $0x0<UINT8>
0x0046cd6b:	leal %eax, 0x8(%ebp)
0x0046cd6e:	movl -4(%ebp), %eax
0x0046cd71:	leal %eax, -4(%ebp)
0x0046cd74:	pushl %eax
0x0046cd75:	pushl $0x5<UINT8>
0x0046cd77:	call 0x0046ccf9
0x0046ccf9:	movl %edi, %edi
0x0046ccfb:	pushl %ebp
0x0046ccfc:	movl %ebp, %esp
0x0046ccfe:	subl %esp, $0xc<UINT8>
0x0046cd01:	movl %eax, 0x8(%ebp)
0x0046cd04:	leal %ecx, -1(%ebp)
0x0046cd07:	movl -8(%ebp), %eax
0x0046cd0a:	movl -12(%ebp), %eax
0x0046cd0d:	leal %eax, -8(%ebp)
0x0046cd10:	pushl %eax
0x0046cd11:	pushl 0xc(%ebp)
0x0046cd14:	leal %eax, -12(%ebp)
0x0046cd17:	pushl %eax
0x0046cd18:	call 0x0046cc39
0x0046cc39:	pushl $0x8<UINT8>
0x0046cc3b:	pushl $0x47b230<UINT32>
0x0046cc40:	call 0x0045c5d0
0x0046cc45:	movl %eax, 0x8(%ebp)
0x0046cc48:	pushl (%eax)
0x0046cc4a:	call 0x0046cac3
0x0046cac3:	movl %edi, %edi
0x0046cac5:	pushl %ebp
0x0046cac6:	movl %ebp, %esp
0x0046cac8:	imull %eax, 0x8(%ebp), $0x18<UINT8>
0x0046cacc:	addl %eax, $0x41cf48<UINT32>
0x0046cad1:	pushl %eax
0x0046cad2:	call EnterCriticalSection@KERNEL32.DLL
EnterCriticalSection@KERNEL32.DLL: API Node	
0x0046cad8:	popl %ebp
0x0046cad9:	ret

0x0046cc4f:	popl %ecx
0x0046cc50:	andl -4(%ebp), $0x0<UINT8>
0x0046cc54:	movl %eax, 0xc(%ebp)
0x0046cc57:	movl %eax, (%eax)
0x0046cc59:	movl %eax, (%eax)
0x0046cc5b:	movl %eax, 0x48(%eax)
0x0046cc5e:	incl (%eax)
0x0046cc61:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0046cc68:	call 0x0046cc75
0x0046cc75:	movl %eax, 0x10(%ebp)
0x0046cc78:	pushl (%eax)
0x0046cc7a:	call 0x0046cb0b
0x0046cb0b:	movl %edi, %edi
0x0046cb0d:	pushl %ebp
0x0046cb0e:	movl %ebp, %esp
0x0046cb10:	imull %eax, 0x8(%ebp), $0x18<UINT8>
0x0046cb14:	addl %eax, $0x41cf48<UINT32>
0x0046cb19:	pushl %eax
0x0046cb1a:	call LeaveCriticalSection@KERNEL32.DLL
LeaveCriticalSection@KERNEL32.DLL: API Node	
0x0046cb20:	popl %ebp
0x0046cb21:	ret

0x0046cc7f:	popl %ecx
0x0046cc80:	ret

0x0046cc6d:	call 0x0045c616
0x0045c616:	movl %ecx, -16(%ebp)
0x0045c619:	movl %fs:0, %ecx
0x0045c620:	popl %ecx
0x0045c621:	popl %edi
0x0045c622:	popl %edi
0x0045c623:	popl %esi
0x0045c624:	popl %ebx
0x0045c625:	movl %esp, %ebp
0x0045c627:	popl %ebp
0x0045c628:	pushl %ecx
0x0045c629:	repn ret

0x0046cc72:	ret $0xc<UINT16>

0x0046cd1d:	movl %esp, %ebp
0x0046cd1f:	popl %ebp
0x0046cd20:	ret

0x0046cd7c:	leal %eax, 0x8(%ebp)
0x0046cd7f:	movl -8(%ebp), %eax
0x0046cd82:	leal %eax, 0xc(%ebp)
0x0046cd85:	movl -4(%ebp), %eax
0x0046cd88:	leal %eax, -8(%ebp)
0x0046cd8b:	pushl %eax
0x0046cd8c:	pushl $0x4<UINT8>
0x0046cd8e:	call 0x0046cca9
0x0046cca9:	movl %edi, %edi
0x0046ccab:	pushl %ebp
0x0046ccac:	movl %ebp, %esp
0x0046ccae:	subl %esp, $0xc<UINT8>
0x0046ccb1:	movl %eax, 0x8(%ebp)
0x0046ccb4:	leal %ecx, -1(%ebp)
0x0046ccb7:	movl -8(%ebp), %eax
0x0046ccba:	movl -12(%ebp), %eax
0x0046ccbd:	leal %eax, -8(%ebp)
0x0046ccc0:	pushl %eax
0x0046ccc1:	pushl 0xc(%ebp)
0x0046ccc4:	leal %eax, -12(%ebp)
0x0046ccc7:	pushl %eax
0x0046ccc8:	call 0x0046cb3d
0x0046cb3d:	pushl $0x8<UINT8>
0x0046cb3f:	pushl $0x47b250<UINT32>
0x0046cb44:	call 0x0045c5d0
0x0046cb49:	movl %eax, 0x8(%ebp)
0x0046cb4c:	pushl (%eax)
0x0046cb4e:	call 0x0046cac3
0x0046cb53:	popl %ecx
0x0046cb54:	andl -4(%ebp), $0x0<UINT8>
0x0046cb58:	movl %ecx, 0xc(%ebp)
0x0046cb5b:	movl %eax, 0x4(%ecx)
0x0046cb5e:	movl %eax, (%eax)
0x0046cb60:	pushl (%eax)
0x0046cb62:	movl %eax, (%ecx)
0x0046cb64:	pushl (%eax)
0x0046cb66:	call 0x0046ce64
0x0046ce64:	movl %edi, %edi
0x0046ce66:	pushl %ebp
0x0046ce67:	movl %ebp, %esp
0x0046ce69:	pushl %esi
0x0046ce6a:	movl %esi, 0x8(%ebp)
0x0046ce6d:	cmpl 0x4c(%esi), $0x0<UINT8>
0x0046ce71:	je 0x0046ce9b
0x0046ce9b:	movl %eax, 0xc(%ebp)
0x0046ce9e:	movl 0x4c(%esi), %eax
0x0046cea1:	popl %esi
0x0046cea2:	testl %eax, %eax
0x0046cea4:	je 7
0x0046cea6:	pushl %eax
0x0046cea7:	call 0x0046fc9e
0x0046fc9e:	movl %edi, %edi
0x0046fca0:	pushl %ebp
0x0046fca1:	movl %ebp, %esp
0x0046fca3:	movl %eax, 0x8(%ebp)
0x0046fca6:	incl 0xc(%eax)
0x0046fcaa:	movl %ecx, 0x7c(%eax)
0x0046fcad:	testl %ecx, %ecx
0x0046fcaf:	je 0x0046fcb4
0x0046fcb4:	movl %ecx, 0x84(%eax)
0x0046fcba:	testl %ecx, %ecx
0x0046fcbc:	je 0x0046fcc1
0x0046fcc1:	movl %ecx, 0x80(%eax)
0x0046fcc7:	testl %ecx, %ecx
0x0046fcc9:	je 0x0046fcce
0x0046fcce:	movl %ecx, 0x8c(%eax)
0x0046fcd4:	testl %ecx, %ecx
0x0046fcd6:	je 0x0046fcdb
0x0046fcdb:	pushl %esi
0x0046fcdc:	pushl $0x6<UINT8>
0x0046fcde:	leal %ecx, 0x28(%eax)
0x0046fce1:	popl %esi
0x0046fce2:	cmpl -8(%ecx), $0x41e880<UINT32>
0x0046fce9:	je 0x0046fcf4
0x0046fceb:	movl %edx, (%ecx)
0x0046fced:	testl %edx, %edx
0x0046fcef:	je 0x0046fcf4
0x0046fcf4:	cmpl -12(%ecx), $0x0<UINT8>
0x0046fcf8:	je 0x0046fd04
0x0046fd04:	addl %ecx, $0x10<UINT8>
0x0046fd07:	subl %esi, $0x1<UINT8>
0x0046fd0a:	jne 0x0046fce2
0x0046fd0c:	pushl 0x9c(%eax)
0x0046fd12:	call 0x0046fe65
0x0046fe65:	movl %edi, %edi
0x0046fe67:	pushl %ebp
0x0046fe68:	movl %ebp, %esp
0x0046fe6a:	movl %ecx, 0x8(%ebp)
0x0046fe6d:	testl %ecx, %ecx
0x0046fe6f:	je 22
0x0046fe71:	cmpl %ecx, $0x415b30<UINT32>
0x0046fe77:	je 0x0046fe87
0x0046fe87:	movl %eax, $0x7fffffff<UINT32>
0x0046fe8c:	popl %ebp
0x0046fe8d:	ret

0x0046fd17:	popl %ecx
0x0046fd18:	popl %esi
0x0046fd19:	popl %ebp
0x0046fd1a:	ret

0x0046ceac:	popl %ecx
0x0046cead:	popl %ebp
0x0046ceae:	ret

0x0046cb6b:	popl %ecx
0x0046cb6c:	popl %ecx
0x0046cb6d:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0046cb74:	call 0x0046cb81
0x0046cb81:	movl %eax, 0x10(%ebp)
0x0046cb84:	pushl (%eax)
0x0046cb86:	call 0x0046cb0b
0x0046cb8b:	popl %ecx
0x0046cb8c:	ret

0x0046cb79:	call 0x0045c616
0x0046cb7e:	ret $0xc<UINT16>

0x0046cccd:	movl %esp, %ebp
0x0046cccf:	popl %ebp
0x0046ccd0:	ret

0x0046cd93:	addl %esp, $0x10<UINT8>
0x0046cd96:	movl %esp, %ebp
0x0046cd98:	popl %ebp
0x0046cd99:	ret

0x0046cf93:	pushl %ebx
0x0046cf94:	call 0x0046bb58
0x0046bb58:	movl %edi, %edi
0x0046bb5a:	pushl %ebp
0x0046bb5b:	movl %ebp, %esp
0x0046bb5d:	cmpl 0x8(%ebp), $0x0<UINT8>
0x0046bb61:	je 0x0046bb90
0x0046bb90:	popl %ebp
0x0046bb91:	ret

0x0046cf99:	addl %esp, $0xc<UINT8>
0x0046cf9c:	testl %edi, %edi
0x0046cf9e:	jne 0x0046cfa9
0x0046cfa9:	pushl %esi
0x0046cfaa:	call SetLastError@KERNEL32.DLL
SetLastError@KERNEL32.DLL: API Node	
0x0046cfb0:	movl %ebx, %edi
0x0046cfb2:	popl %edi
0x0046cfb3:	popl %esi
0x0046cfb4:	movl %eax, %ebx
0x0046cfb6:	popl %ebx
0x0046cfb7:	ret

0x0046cfd4:	testl %eax, %eax
0x0046cfd6:	jne 0x0046cfe1
0x0046cfe1:	movb %al, $0x1<UINT8>
0x0046cfe3:	ret

0x0046d16a:	pushl $0xc<UINT8>
0x0046d16c:	pushl $0x47b2b0<UINT32>
0x0046d171:	call 0x0045c5d0
0x0046d176:	pushl $0x7<UINT8>
0x0046d178:	call 0x0046cac3
0x0046d17d:	popl %ecx
0x0046d17e:	xorl %ebx, %ebx
0x0046d180:	movb -25(%ebp), %bl
0x0046d183:	movl -4(%ebp), %ebx
0x0046d186:	pushl %ebx
0x0046d187:	call 0x004710e3
0x004710e3:	pushl $0x14<UINT8>
0x004710e5:	pushl $0x47b3d0<UINT32>
0x004710ea:	call 0x0045c5d0
0x004710ef:	cmpl 0x8(%ebp), $0x2000<UINT32>
0x004710f6:	sbbl %eax, %eax
0x004710f8:	negl %eax
0x004710fa:	jne 0x00471113
0x00471113:	xorl %esi, %esi
0x00471115:	movl -28(%ebp), %esi
0x00471118:	pushl $0x7<UINT8>
0x0047111a:	call 0x0046cac3
0x0047111f:	popl %ecx
0x00471120:	movl -4(%ebp), %esi
0x00471123:	movl %edi, %esi
0x00471125:	movl %eax, 0x41d288
0x0047112a:	movl -32(%ebp), %edi
0x0047112d:	cmpl 0x8(%ebp), %eax
0x00471130:	jl 0x00471151
0x00471132:	cmpl 0x41d088(,%edi,4), %esi
0x00471139:	jne 49
0x0047113b:	call 0x00471034
0x00471034:	movl %edi, %edi
0x00471036:	pushl %ebp
0x00471037:	movl %ebp, %esp
0x00471039:	pushl %ecx
0x0047103a:	pushl %ecx
0x0047103b:	pushl %ebx
0x0047103c:	pushl %edi
0x0047103d:	pushl $0x30<UINT8>
0x0047103f:	pushl $0x40<UINT8>
0x00471041:	call 0x0046e261
0x00471046:	movl %edi, %eax
0x00471048:	xorl %ebx, %ebx
0x0047104a:	movl -8(%ebp), %edi
0x0047104d:	popl %ecx
0x0047104e:	popl %ecx
0x0047104f:	testl %edi, %edi
0x00471051:	jne 0x00471057
0x00471057:	leal %eax, 0xc00(%edi)
0x0047105d:	cmpl %edi, %eax
0x0047105f:	je 62
0x00471061:	pushl %esi
0x00471062:	leal %esi, 0x20(%edi)
0x00471065:	movl %edi, %eax
0x00471067:	pushl %ebx
0x00471068:	pushl $0xfa0<UINT32>
0x0047106d:	leal %eax, -32(%esi)
0x00471070:	pushl %eax
0x00471071:	call 0x0046c6d2
0x00471076:	orl -8(%esi), $0xffffffff<UINT8>
0x0047107a:	movl (%esi), %ebx
0x0047107c:	leal %esi, 0x30(%esi)
0x0047107f:	movl -44(%esi), %ebx
0x00471082:	leal %eax, -32(%esi)
0x00471085:	movl -40(%esi), $0xa0a0000<UINT32>
0x0047108c:	movb -36(%esi), $0xa<UINT8>
0x00471090:	andb -35(%esi), $0xfffffff8<UINT8>
0x00471094:	movb -34(%esi), %bl
0x00471097:	cmpl %eax, %edi
0x00471099:	jne 0x00471067
0x0047109b:	movl %edi, -8(%ebp)
0x0047109e:	popl %esi
0x0047109f:	pushl %ebx
0x004710a0:	call 0x0046bb58
0x004710a5:	popl %ecx
0x004710a6:	movl %eax, %edi
0x004710a8:	popl %edi
0x004710a9:	popl %ebx
0x004710aa:	movl %esp, %ebp
0x004710ac:	popl %ebp
0x004710ad:	ret

0x00471140:	movl 0x41d088(,%edi,4), %eax
0x00471147:	testl %eax, %eax
0x00471149:	jne 0x0047115f
0x0047115f:	movl %eax, 0x41d288
0x00471164:	addl %eax, $0x40<UINT8>
0x00471167:	movl 0x41d288, %eax
0x0047116c:	incl %edi
0x0047116d:	jmp 0x0047112a
0x00471151:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00471158:	call 0x00471172
0x00471172:	pushl $0x7<UINT8>
0x00471174:	call 0x0046cb0b
0x00471179:	popl %ecx
0x0047117a:	ret

0x0047115d:	jmp 0x0047110b
0x0047110b:	movl %eax, %esi
0x0047110d:	call 0x0045c616
0x00471112:	ret

0x0046d18c:	popl %ecx
0x0046d18d:	testl %eax, %eax
0x0046d18f:	jne 15
0x0046d191:	call 0x0046cffe
0x0046cffe:	movl %edi, %edi
0x0046d000:	pushl %ebp
0x0046d001:	movl %ebp, %esp
0x0046d003:	subl %esp, $0x48<UINT8>
0x0046d006:	leal %eax, -72(%ebp)
0x0046d009:	pushl %eax
0x0046d00a:	call GetStartupInfoW@KERNEL32.DLL
GetStartupInfoW@KERNEL32.DLL: API Node	
0x0046d010:	cmpw -22(%ebp), $0x0<UINT8>
0x0046d015:	je 149
0x0046d01b:	movl %eax, -20(%ebp)
0x0046d01e:	testl %eax, %eax
0x0046d020:	je 138
0x0046d026:	pushl %ebx
0x0046d027:	pushl %esi
0x0046d028:	movl %esi, (%eax)
0x0046d02a:	leal %ebx, 0x4(%eax)
0x0046d02d:	leal %eax, (%ebx,%esi)
0x0046d030:	movl -4(%ebp), %eax
0x0046d033:	movl %eax, $0x2000<UINT32>
0x0046d038:	cmpl %esi, %eax
0x0046d03a:	jl 0x0046d03e
0x0046d03e:	pushl %esi
0x0046d03f:	call 0x004710e3
0x0046d044:	movl %eax, 0x41d288
0x0046d049:	popl %ecx
0x0046d04a:	cmpl %esi, %eax
0x0046d04c:	jle 0x0046d050
0x0046d050:	pushl %edi
0x0046d051:	xorl %edi, %edi
0x0046d053:	testl %esi, %esi
0x0046d055:	je 0x0046d0ad
0x0046d0ad:	popl %edi
0x0046d0ae:	popl %esi
0x0046d0af:	popl %ebx
0x0046d0b0:	movl %esp, %ebp
0x0046d0b2:	popl %ebp
0x0046d0b3:	ret

0x0046d196:	call 0x0046d0b4
0x0046d0b4:	movl %edi, %edi
0x0046d0b6:	pushl %ebx
0x0046d0b7:	pushl %esi
0x0046d0b8:	pushl %edi
0x0046d0b9:	xorl %edi, %edi
0x0046d0bb:	movl %eax, %edi
0x0046d0bd:	movl %ecx, %edi
0x0046d0bf:	andl %eax, $0x3f<UINT8>
0x0046d0c2:	sarl %ecx, $0x6<UINT8>
0x0046d0c5:	imull %esi, %eax, $0x30<UINT8>
0x0046d0c8:	addl %esi, 0x41d088(,%ecx,4)
0x0046d0cf:	cmpl 0x18(%esi), $0xffffffff<UINT8>
0x0046d0d3:	je 0x0046d0e1
0x0046d0e1:	movl %eax, %edi
0x0046d0e3:	movb 0x28(%esi), $0xffffff81<UINT8>
0x0046d0e7:	subl %eax, $0x0<UINT8>
0x0046d0ea:	je 0x0046d0fc
0x0046d0fc:	pushl $0xfffffff6<UINT8>
0x0046d0fe:	popl %eax
0x0046d0ff:	pushl %eax
0x0046d100:	call GetStdHandle@KERNEL32.DLL
GetStdHandle@KERNEL32.DLL: API Node	
0x0046d106:	movl %ebx, %eax
0x0046d108:	cmpl %ebx, $0xffffffff<UINT8>
0x0046d10b:	je 13
0x0046d10d:	testl %ebx, %ebx
0x0046d10f:	je 9
0x0046d111:	pushl %ebx
0x0046d112:	call GetFileType@KERNEL32.DLL
GetFileType@KERNEL32.DLL: API Node	
0x0046d118:	jmp 0x0046d11c
0x0046d11c:	testl %eax, %eax
0x0046d11e:	je 30
0x0046d120:	andl %eax, $0xff<UINT32>
0x0046d125:	movl 0x18(%esi), %ebx
0x0046d128:	cmpl %eax, $0x2<UINT8>
0x0046d12b:	jne 6
0x0046d12d:	orb 0x28(%esi), $0x40<UINT8>
0x0046d131:	jmp 0x0046d15c
0x0046d15c:	incl %edi
0x0046d15d:	cmpl %edi, $0x3<UINT8>
0x0046d160:	jne 0x0046d0bb
0x0046d0ec:	subl %eax, $0x1<UINT8>
0x0046d0ef:	je 0x0046d0f8
0x0046d0f8:	pushl $0xfffffff5<UINT8>
0x0046d0fa:	jmp 0x0046d0fe
0x0046d0f1:	pushl $0xfffffff4<UINT8>
0x0046d0f3:	subl %eax, $0x1<UINT8>
0x0046d0f6:	jmp 0x0046d0fe
0x0046d166:	popl %edi
0x0046d167:	popl %esi
0x0046d168:	popl %ebx
0x0046d169:	ret

0x0046d19b:	movb %bl, $0x1<UINT8>
0x0046d19d:	movb -25(%ebp), %bl
0x0046d1a0:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0046d1a7:	call 0x0046d1b7
0x0046d1b7:	pushl $0x7<UINT8>
0x0046d1b9:	call 0x0046cb0b
0x0046d1be:	popl %ecx
0x0046d1bf:	ret

0x0046d1ac:	movb %al, %bl
0x0046d1ae:	call 0x0045c616
0x0046d1b3:	ret

0x0046d1ec:	call GetCommandLineA@KERNEL32.DLL
GetCommandLineA@KERNEL32.DLL: API Node	
0x0046d1f2:	movl 0x41d298, %eax
0x0046d1f7:	call GetCommandLineW@KERNEL32.DLL
GetCommandLineW@KERNEL32.DLL: API Node	
0x0046d1fd:	movl 0x41d29c, %eax
0x0046d202:	movb %al, $0x1<UINT8>
0x0046d204:	ret

0x0046d6df:	cmpb 0x41d2c0, $0x0<UINT8>
0x0046d6e6:	jne 0x0046d6fa
0x0046d6e8:	pushl $0x1<UINT8>
0x0046d6ea:	pushl $0xfffffffd<UINT8>
0x0046d6ec:	call 0x0046d5de
0x0046d5de:	movl %edi, %edi
0x0046d5e0:	pushl %ebp
0x0046d5e1:	movl %ebp, %esp
0x0046d5e3:	subl %esp, $0xc<UINT8>
0x0046d5e6:	call 0x0046ceaf
0x0046ceaf:	movl %edi, %edi
0x0046ceb1:	pushl %esi
0x0046ceb2:	pushl %edi
0x0046ceb3:	call GetLastError@KERNEL32.DLL
0x0046ceb9:	movl %esi, %eax
0x0046cebb:	movl %eax, 0x41e260
0x0046cec0:	cmpl %eax, $0xffffffff<UINT8>
0x0046cec3:	je 12
0x0046cec5:	pushl %eax
0x0046cec6:	call 0x0046c531
0x0046cecb:	movl %edi, %eax
0x0046cecd:	testl %edi, %edi
0x0046cecf:	jne 0x0046cf1a
0x0046cf1a:	pushl %esi
0x0046cf1b:	call SetLastError@KERNEL32.DLL
0x0046cf21:	movl %eax, %edi
0x0046cf23:	popl %edi
0x0046cf24:	popl %esi
0x0046cf25:	ret

0x0046d5eb:	movl -4(%ebp), %eax
0x0046d5ee:	call 0x0046d6fd
0x0046d6fd:	pushl $0xc<UINT8>
0x0046d6ff:	pushl $0x47b2d0<UINT32>
0x0046d704:	call 0x0045c5d0
0x0046d709:	xorl %esi, %esi
0x0046d70b:	movl -28(%ebp), %esi
0x0046d70e:	call 0x0046ceaf
0x0046d713:	movl %edi, %eax
0x0046d715:	movl %ecx, 0x41e8f8
0x0046d71b:	testl 0x350(%edi), %ecx
0x0046d721:	je 0x0046d734
0x0046d734:	pushl $0x5<UINT8>
0x0046d736:	call 0x0046cac3
0x0046d73b:	popl %ecx
0x0046d73c:	movl -4(%ebp), %esi
0x0046d73f:	movl %esi, 0x48(%edi)
0x0046d742:	movl -28(%ebp), %esi
0x0046d745:	cmpl %esi, 0x41e7b8
0x0046d74b:	je 0x0046d77d
0x0046d77d:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0046d784:	call 0x0046d78e
0x0046d78e:	pushl $0x5<UINT8>
0x0046d790:	call 0x0046cb0b
0x0046d795:	popl %ecx
0x0046d796:	ret

0x0046d789:	jmp 0x0046d72b
0x0046d72b:	testl %esi, %esi
0x0046d72d:	jne 0x0046d797
0x0046d797:	movl %eax, %esi
0x0046d799:	call 0x0045c616
0x0046d79e:	ret

0x0046d5f3:	pushl 0x8(%ebp)
0x0046d5f6:	call 0x0046d372
0x0046d372:	movl %edi, %edi
0x0046d374:	pushl %ebp
0x0046d375:	movl %ebp, %esp
0x0046d377:	subl %esp, $0x10<UINT8>
0x0046d37a:	leal %ecx, -16(%ebp)
0x0046d37d:	pushl $0x0<UINT8>
0x0046d37f:	call 0x0045fc82
0x0045fc82:	movl %edi, %edi
0x0045fc84:	pushl %ebp
0x0045fc85:	movl %ebp, %esp
0x0045fc87:	pushl %edi
0x0045fc88:	movl %edi, %ecx
0x0045fc8a:	movl %ecx, 0x8(%ebp)
0x0045fc8d:	movb 0xc(%edi), $0x0<UINT8>
0x0045fc91:	testl %ecx, %ecx
0x0045fc93:	je 0x0045fc9f
0x0045fc9f:	movl %eax, 0x41cc70
0x0045fca4:	testl %eax, %eax
0x0045fca6:	jne 18
0x0045fca8:	movl %eax, 0x41e878
0x0045fcad:	movl 0x4(%edi), %eax
0x0045fcb0:	movl %eax, 0x41e87c
0x0045fcb5:	movl 0x8(%edi), %eax
0x0045fcb8:	jmp 0x0045fcfe
0x0045fcfe:	movl %eax, %edi
0x0045fd00:	popl %edi
0x0045fd01:	popl %ebp
0x0045fd02:	ret $0x4<UINT16>

0x0046d384:	andl 0x41d2bc, $0x0<UINT8>
0x0046d38b:	movl %eax, 0x8(%ebp)
0x0046d38e:	cmpl %eax, $0xfffffffe<UINT8>
0x0046d391:	jne 0x0046d3a5
0x0046d3a5:	cmpl %eax, $0xfffffffd<UINT8>
0x0046d3a8:	jne 0x0046d3bc
0x0046d3aa:	movl 0x41d2bc, $0x1<UINT32>
0x0046d3b4:	call GetACP@KERNEL32.DLL
GetACP@KERNEL32.DLL: API Node	
0x0046d3ba:	jmp 0x0046d3d1
0x0046d3d1:	cmpb -4(%ebp), $0x0<UINT8>
0x0046d3d5:	je 0x0046d3e1
0x0046d3e1:	movl %esp, %ebp
0x0046d3e3:	popl %ebp
0x0046d3e4:	ret

0x0046d5fb:	popl %ecx
0x0046d5fc:	movl %ecx, -4(%ebp)
0x0046d5ff:	movl -12(%ebp), %eax
0x0046d602:	movl %ecx, 0x48(%ecx)
0x0046d605:	cmpl %eax, 0x4(%ecx)
0x0046d608:	jne 0x0046d60e
0x0046d60e:	pushl %ebx
0x0046d60f:	pushl %esi
0x0046d610:	pushl %edi
0x0046d611:	pushl $0x220<UINT32>
0x0046d616:	call 0x0046bb92
0x0046bb92:	movl %edi, %edi
0x0046bb94:	pushl %ebp
0x0046bb95:	movl %ebp, %esp
0x0046bb97:	pushl %esi
0x0046bb98:	movl %esi, 0x8(%ebp)
0x0046bb9b:	cmpl %esi, $0xffffffe0<UINT8>
0x0046bb9e:	ja 48
0x0046bba0:	testl %esi, %esi
0x0046bba2:	jne 0x0046bbbb
0x0046bbbb:	pushl %esi
0x0046bbbc:	pushl $0x0<UINT8>
0x0046bbbe:	pushl 0x41d084
0x0046bbc4:	call HeapAlloc@KERNEL32.DLL
0x0046bbca:	testl %eax, %eax
0x0046bbcc:	je -39
0x0046bbce:	jmp 0x0046bbdd
0x0046bbdd:	popl %esi
0x0046bbde:	popl %ebp
0x0046bbdf:	ret

0x0046d61b:	movl %edi, %eax
0x0046d61d:	orl %ebx, $0xffffffff<UINT8>
0x0046d620:	popl %ecx
0x0046d621:	testl %edi, %edi
0x0046d623:	je 46
0x0046d625:	movl %esi, -4(%ebp)
0x0046d628:	movl %ecx, $0x88<UINT32>
0x0046d62d:	movl %esi, 0x48(%esi)
0x0046d630:	rep movsl %es:(%edi), %ds:(%esi)
0x0046d632:	movl %edi, %eax
0x0046d634:	pushl %edi
0x0046d635:	pushl -12(%ebp)
0x0046d638:	andl (%edi), $0x0<UINT8>
0x0046d63b:	call 0x0046d79f
0x0046d79f:	movl %edi, %edi
0x0046d7a1:	pushl %ebp
0x0046d7a2:	movl %ebp, %esp
0x0046d7a4:	subl %esp, $0x20<UINT8>
0x0046d7a7:	movl %eax, 0x41e17c
0x0046d7ac:	xorl %eax, %ebp
0x0046d7ae:	movl -4(%ebp), %eax
0x0046d7b1:	pushl %ebx
0x0046d7b2:	pushl %esi
0x0046d7b3:	pushl 0x8(%ebp)
0x0046d7b6:	movl %esi, 0xc(%ebp)
0x0046d7b9:	call 0x0046d372
0x0046d3bc:	cmpl %eax, $0xfffffffc<UINT8>
0x0046d3bf:	jne 0x0046d3d1
0x0046d7be:	movl %ebx, %eax
0x0046d7c0:	popl %ecx
0x0046d7c1:	testl %ebx, %ebx
0x0046d7c3:	jne 0x0046d7d3
0x0046d7d3:	pushl %edi
0x0046d7d4:	xorl %edi, %edi
0x0046d7d6:	movl %ecx, %edi
0x0046d7d8:	movl %eax, %edi
0x0046d7da:	movl -28(%ebp), %ecx
0x0046d7dd:	cmpl 0x41e2a0(%eax), %ebx
0x0046d7e3:	je 234
0x0046d7e9:	incl %ecx
0x0046d7ea:	addl %eax, $0x30<UINT8>
0x0046d7ed:	movl -28(%ebp), %ecx
0x0046d7f0:	cmpl %eax, $0xf0<UINT32>
0x0046d7f5:	jb 0x0046d7dd
0x0046d7f7:	cmpl %ebx, $0xfde8<UINT32>
0x0046d7fd:	je 200
0x0046d803:	cmpl %ebx, $0xfde9<UINT32>
0x0046d809:	je 188
0x0046d80f:	movzwl %eax, %bx
0x0046d812:	pushl %eax
0x0046d813:	call IsValidCodePage@KERNEL32.DLL
IsValidCodePage@KERNEL32.DLL: API Node	
0x0046d819:	testl %eax, %eax
0x0046d81b:	je 170
0x0046d821:	leal %eax, -24(%ebp)
0x0046d824:	pushl %eax
0x0046d825:	pushl %ebx
0x0046d826:	call GetCPInfo@KERNEL32.DLL
GetCPInfo@KERNEL32.DLL: API Node	
0x0046d82c:	testl %eax, %eax
0x0046d82e:	je 132
0x0046d834:	pushl $0x101<UINT32>
0x0046d839:	leal %eax, 0x18(%esi)
0x0046d83c:	pushl %edi
0x0046d83d:	pushl %eax
0x0046d83e:	call 0x0045ed00
0x0045ed00:	movl %ecx, 0xc(%esp)
0x0045ed04:	movzbl %eax, 0x8(%esp)
0x0045ed09:	movl %edx, %edi
0x0045ed0b:	movl %edi, 0x4(%esp)
0x0045ed0f:	testl %ecx, %ecx
0x0045ed11:	je 316
0x0045ed17:	imull %eax, %eax, $0x1010101<UINT32>
0x0045ed1d:	cmpl %ecx, $0x20<UINT8>
0x0045ed20:	jle 223
0x0045ed26:	cmpl %ecx, $0x80<UINT32>
0x0045ed2c:	jl 0x0045edbd
0x0045ed32:	btl 0x41cc44, $0x1<UINT8>
0x0045ed3a:	jae 0x0045ed45
0x0045ed45:	btl 0x41e190, $0x1<UINT8>
0x0045ed4d:	jae 178
0x0045ed53:	movd %xmm0, %eax
0x0045ed57:	pshufd %xmm0, %xmm0, $0x0<UINT8>
0x0045ed5c:	addl %ecx, %edi
0x0045ed5e:	movups (%edi), %xmm0
0x0045ed61:	addl %edi, $0x10<UINT8>
0x0045ed64:	andl %edi, $0xfffffff0<UINT8>
0x0045ed67:	subl %ecx, %edi
0x0045ed69:	cmpl %ecx, $0x80<UINT32>
0x0045ed6f:	jle 0x0045edbd
0x0045ed71:	leal %esp, (%esp)
0x0045ed78:	leal %esp, (%esp)
0x0045ed7f:	nop
0x0045ed80:	movdqa (%edi), %xmm0
0x0045ed84:	movdqa 0x10(%edi), %xmm0
0x0045ed89:	movdqa 0x20(%edi), %xmm0
0x0045ed8e:	movdqa 0x30(%edi), %xmm0
0x0045ed93:	movdqa 0x40(%edi), %xmm0
0x0045ed98:	movdqa 0x50(%edi), %xmm0
0x0045ed9d:	movdqa 0x60(%edi), %xmm0
0x0045eda2:	movdqa 0x70(%edi), %xmm0
0x0045eda7:	leal %edi, 0x80(%edi)
0x0045edad:	subl %ecx, $0x80<UINT32>
0x0045edb3:	testl %ecx, $0xffffff00<UINT32>
0x0045edb9:	jne 0x0045ed80
0x0045edbb:	jmp 0x0045edd0
0x0045edd0:	cmpl %ecx, $0x20<UINT8>
0x0045edd3:	jb 28
0x0045edd5:	movdqu (%edi), %xmm0
0x0045edd9:	movdqu 0x10(%edi), %xmm0
0x0045edde:	addl %edi, $0x20<UINT8>
0x0045ede1:	subl %ecx, $0x20<UINT8>
0x0045ede4:	cmpl %ecx, $0x20<UINT8>
0x0045ede7:	jae 0x0045edd5
0x0045ede9:	testl %ecx, $0x1f<UINT32>
0x0045edef:	je 98
0x0045edf1:	leal %edi, -32(%ecx,%edi)
0x0045edf5:	movdqu (%edi), %xmm0
0x0045edf9:	movdqu 0x10(%edi), %xmm0
0x0045edfe:	movl %eax, 0x4(%esp)
0x0045ee02:	movl %edi, %edx
0x0045ee04:	ret

0x0046d843:	movl 0x4(%esi), %ebx
0x0046d846:	addl %esp, $0xc<UINT8>
0x0046d849:	xorl %ebx, %ebx
0x0046d84b:	movl 0x21c(%esi), %edi
0x0046d851:	incl %ebx
0x0046d852:	cmpl -24(%ebp), %ebx
0x0046d855:	jbe 81
0x0046d857:	cmpb -18(%ebp), $0x0<UINT8>
0x0046d85b:	leal %eax, -18(%ebp)
0x0046d85e:	je 0x0046d881
0x0046d881:	leal %eax, 0x1a(%esi)
0x0046d884:	movl %ecx, $0xfe<UINT32>
0x0046d889:	orb (%eax), $0x8<UINT8>
0x0046d88c:	incl %eax
0x0046d88d:	subl %ecx, $0x1<UINT8>
0x0046d890:	jne 0x0046d889
0x0046d892:	pushl 0x4(%esi)
0x0046d895:	call 0x0046d334
0x0046d334:	movl %edi, %edi
0x0046d336:	pushl %ebp
0x0046d337:	movl %ebp, %esp
0x0046d339:	movl %eax, 0x8(%ebp)
0x0046d33c:	subl %eax, $0x3a4<UINT32>
0x0046d341:	je 40
0x0046d343:	subl %eax, $0x4<UINT8>
0x0046d346:	je 28
0x0046d348:	subl %eax, $0xd<UINT8>
0x0046d34b:	je 16
0x0046d34d:	subl %eax, $0x1<UINT8>
0x0046d350:	je 4
0x0046d352:	xorl %eax, %eax
0x0046d354:	popl %ebp
0x0046d355:	ret

0x0046d89a:	addl %esp, $0x4<UINT8>
0x0046d89d:	movl 0x21c(%esi), %eax
0x0046d8a3:	movl 0x8(%esi), %ebx
0x0046d8a6:	jmp 0x0046d8ab
0x0046d8ab:	xorl %eax, %eax
0x0046d8ad:	leal %edi, 0xc(%esi)
0x0046d8b0:	stosl %es:(%edi), %eax
0x0046d8b1:	stosl %es:(%edi), %eax
0x0046d8b2:	stosl %es:(%edi), %eax
0x0046d8b3:	jmp 0x0046d976
0x0046d976:	pushl %esi
0x0046d977:	call 0x0046d44a
0x0046d44a:	movl %edi, %edi
0x0046d44c:	pushl %ebp
0x0046d44d:	movl %ebp, %esp
0x0046d44f:	subl %esp, $0x720<UINT32>
0x0046d455:	movl %eax, 0x41e17c
0x0046d45a:	xorl %eax, %ebp
0x0046d45c:	movl -4(%ebp), %eax
0x0046d45f:	pushl %ebx
0x0046d460:	pushl %esi
0x0046d461:	movl %esi, 0x8(%ebp)
0x0046d464:	leal %eax, -1816(%ebp)
0x0046d46a:	pushl %edi
0x0046d46b:	pushl %eax
0x0046d46c:	pushl 0x4(%esi)
0x0046d46f:	call GetCPInfo@KERNEL32.DLL
0x0046d475:	xorl %ebx, %ebx
0x0046d477:	movl %edi, $0x100<UINT32>
0x0046d47c:	testl %eax, %eax
0x0046d47e:	je 240
0x0046d484:	movl %eax, %ebx
0x0046d486:	movb -260(%ebp,%eax), %al
0x0046d48d:	incl %eax
0x0046d48e:	cmpl %eax, %edi
0x0046d490:	jb 0x0046d486
0x0046d492:	movb %al, -1810(%ebp)
0x0046d498:	leal %ecx, -1810(%ebp)
0x0046d49e:	movb -260(%ebp), $0x20<UINT8>
0x0046d4a5:	jmp 0x0046d4c6
0x0046d4c6:	testb %al, %al
0x0046d4c8:	jne -35
0x0046d4ca:	pushl %ebx
0x0046d4cb:	pushl 0x4(%esi)
0x0046d4ce:	leal %eax, -1796(%ebp)
0x0046d4d4:	pushl %eax
0x0046d4d5:	pushl %edi
0x0046d4d6:	leal %eax, -260(%ebp)
0x0046d4dc:	pushl %eax
0x0046d4dd:	pushl $0x1<UINT8>
0x0046d4df:	pushl %ebx
0x0046d4e0:	call 0x0046fb61
0x0046fb61:	movl %edi, %edi
0x0046fb63:	pushl %ebp
0x0046fb64:	movl %ebp, %esp
0x0046fb66:	subl %esp, $0x18<UINT8>
0x0046fb69:	movl %eax, 0x41e17c
0x0046fb6e:	xorl %eax, %ebp
0x0046fb70:	movl -4(%ebp), %eax
0x0046fb73:	pushl %ebx
0x0046fb74:	pushl %esi
0x0046fb75:	pushl %edi
0x0046fb76:	pushl 0x8(%ebp)
0x0046fb79:	leal %ecx, -24(%ebp)
0x0046fb7c:	call 0x0045fc82
0x0046fb81:	movl %ecx, 0x1c(%ebp)
0x0046fb84:	testl %ecx, %ecx
0x0046fb86:	jne 0x0046fb93
0x0046fb93:	xorl %eax, %eax
0x0046fb95:	xorl %edi, %edi
0x0046fb97:	cmpl 0x20(%ebp), %eax
0x0046fb9a:	pushl %edi
0x0046fb9b:	pushl %edi
0x0046fb9c:	pushl 0x14(%ebp)
0x0046fb9f:	setne %al
0x0046fba2:	pushl 0x10(%ebp)
0x0046fba5:	leal %eax, 0x1(,%eax,8)
0x0046fbac:	pushl %eax
0x0046fbad:	pushl %ecx
0x0046fbae:	call MultiByteToWideChar@KERNEL32.DLL
MultiByteToWideChar@KERNEL32.DLL: API Node	
0x0046fbb4:	movl -8(%ebp), %eax
0x0046fbb7:	testl %eax, %eax
0x0046fbb9:	je 153
0x0046fbbf:	leal %ebx, (%eax,%eax)
0x0046fbc2:	leal %ecx, 0x8(%ebx)
0x0046fbc5:	cmpl %ebx, %ecx
0x0046fbc7:	sbbl %eax, %eax
0x0046fbc9:	testl %ecx, %eax
0x0046fbcb:	je 74
0x0046fbcd:	leal %ecx, 0x8(%ebx)
0x0046fbd0:	cmpl %ebx, %ecx
0x0046fbd2:	sbbl %eax, %eax
0x0046fbd4:	andl %eax, %ecx
0x0046fbd6:	leal %ecx, 0x8(%ebx)
0x0046fbd9:	cmpl %eax, $0x400<UINT32>
0x0046fbde:	ja 25
0x0046fbe0:	cmpl %ebx, %ecx
0x0046fbe2:	sbbl %eax, %eax
0x0046fbe4:	andl %eax, %ecx
0x0046fbe6:	call 0x004763b0
0x004763b0:	pushl %ecx
0x004763b1:	leal %ecx, 0x8(%esp)
0x004763b5:	subl %ecx, %eax
0x004763b7:	andl %ecx, $0xf<UINT8>
0x004763ba:	addl %eax, %ecx
0x004763bc:	sbbl %ecx, %ecx
0x004763be:	orl %eax, %ecx
0x004763c0:	popl %ecx
0x004763c1:	jmp 0x0045bc70
0x0045bc70:	pushl %ecx
0x0045bc71:	leal %ecx, 0x4(%esp)
0x0045bc75:	subl %ecx, %eax
0x0045bc77:	sbbl %eax, %eax
0x0045bc79:	notl %eax
0x0045bc7b:	andl %ecx, %eax
0x0045bc7d:	movl %eax, %esp
0x0045bc7f:	andl %eax, $0xfffff000<UINT32>
0x0045bc84:	cmpl %ecx, %eax
0x0045bc86:	repn jb 11
0x0045bc89:	movl %eax, %ecx
0x0045bc8b:	popl %ecx
0x0045bc8c:	xchgl %esp, %eax
0x0045bc8d:	movl %eax, (%eax)
0x0045bc8f:	movl (%esp), %eax
0x0045bc92:	repn ret

0x0046fbeb:	movl %esi, %esp
0x0046fbed:	testl %esi, %esi
0x0046fbef:	je 96
0x0046fbf1:	movl (%esi), $0xcccc<UINT32>
0x0046fbf7:	jmp 0x0046fc12
0x0046fc12:	addl %esi, $0x8<UINT8>
0x0046fc15:	jmp 0x0046fc19
0x0046fc19:	testl %esi, %esi
0x0046fc1b:	je 52
0x0046fc1d:	pushl %ebx
0x0046fc1e:	pushl %edi
0x0046fc1f:	pushl %esi
0x0046fc20:	call 0x0045ed00
0x0046fc25:	addl %esp, $0xc<UINT8>
0x0046fc28:	pushl -8(%ebp)
0x0046fc2b:	pushl %esi
0x0046fc2c:	pushl 0x14(%ebp)
0x0046fc2f:	pushl 0x10(%ebp)
0x0046fc32:	pushl $0x1<UINT8>
0x0046fc34:	pushl 0x1c(%ebp)
0x0046fc37:	call MultiByteToWideChar@KERNEL32.DLL
0x0046fc3d:	testl %eax, %eax
0x0046fc3f:	je 16
0x0046fc41:	pushl 0x18(%ebp)
0x0046fc44:	pushl %eax
0x0046fc45:	pushl %esi
0x0046fc46:	pushl 0xc(%ebp)
0x0046fc49:	call GetStringTypeW@KERNEL32.DLL
GetStringTypeW@KERNEL32.DLL: API Node	
0x0046fc4f:	movl %edi, %eax
0x0046fc51:	pushl %esi
0x0046fc52:	call 0x0046fc7e
0x0046fc7e:	movl %edi, %edi
0x0046fc80:	pushl %ebp
0x0046fc81:	movl %ebp, %esp
0x0046fc83:	movl %eax, 0x8(%ebp)
0x0046fc86:	testl %eax, %eax
0x0046fc88:	je 0x0046fc9c
0x0046fc8a:	subl %eax, $0x8<UINT8>
0x0046fc8d:	cmpl (%eax), $0xdddd<UINT32>
0x0046fc93:	jne 0x0046fc9c
0x0046fc9c:	popl %ebp
0x0046fc9d:	ret

0x0046fc57:	popl %ecx
0x0046fc58:	cmpb -12(%ebp), $0x0<UINT8>
0x0046fc5c:	je 0x0046fc68
0x0046fc68:	movl %eax, %edi
0x0046fc6a:	leal %esp, -36(%ebp)
0x0046fc6d:	popl %edi
0x0046fc6e:	popl %esi
0x0046fc6f:	popl %ebx
0x0046fc70:	movl %ecx, -4(%ebp)
0x0046fc73:	xorl %ecx, %ebp
0x0046fc75:	call 0x0045bc59
0x0046fc7a:	movl %esp, %ebp
0x0046fc7c:	popl %ebp
0x0046fc7d:	ret

0x0046d4e5:	pushl %ebx
0x0046d4e6:	pushl 0x4(%esi)
0x0046d4e9:	leal %eax, -516(%ebp)
0x0046d4ef:	pushl %edi
0x0046d4f0:	pushl %eax
0x0046d4f1:	pushl %edi
0x0046d4f2:	leal %eax, -260(%ebp)
0x0046d4f8:	pushl %eax
0x0046d4f9:	pushl %edi
0x0046d4fa:	pushl 0x21c(%esi)
0x0046d500:	pushl %ebx
0x0046d501:	call 0x00474602
0x00474602:	movl %edi, %edi
0x00474604:	pushl %ebp
0x00474605:	movl %ebp, %esp
0x00474607:	subl %esp, $0x10<UINT8>
0x0047460a:	pushl 0x8(%ebp)
0x0047460d:	leal %ecx, -16(%ebp)
0x00474610:	call 0x0045fc82
0x00474615:	pushl 0x28(%ebp)
0x00474618:	leal %eax, -12(%ebp)
0x0047461b:	pushl 0x24(%ebp)
0x0047461e:	pushl 0x20(%ebp)
0x00474621:	pushl 0x1c(%ebp)
0x00474624:	pushl 0x18(%ebp)
0x00474627:	pushl 0x14(%ebp)
0x0047462a:	pushl 0x10(%ebp)
0x0047462d:	pushl 0xc(%ebp)
0x00474630:	pushl %eax
0x00474631:	call 0x004743e5
0x004743e5:	movl %edi, %edi
0x004743e7:	pushl %ebp
0x004743e8:	movl %ebp, %esp
0x004743ea:	pushl %ecx
0x004743eb:	pushl %ecx
0x004743ec:	movl %eax, 0x41e17c
0x004743f1:	xorl %eax, %ebp
0x004743f3:	movl -4(%ebp), %eax
0x004743f6:	pushl %ebx
0x004743f7:	pushl %esi
0x004743f8:	movl %esi, 0x18(%ebp)
0x004743fb:	pushl %edi
0x004743fc:	testl %esi, %esi
0x004743fe:	jle 20
0x00474400:	pushl %esi
0x00474401:	pushl 0x14(%ebp)
0x00474404:	call 0x0047873b
0x0047873b:	movl %edi, %edi
0x0047873d:	pushl %ebp
0x0047873e:	movl %ebp, %esp
0x00478740:	movl %ecx, 0x8(%ebp)
0x00478743:	xorl %eax, %eax
0x00478745:	cmpb (%ecx), %al
0x00478747:	je 12
0x00478749:	cmpl %eax, 0xc(%ebp)
0x0047874c:	je 0x00478755
0x0047874e:	incl %eax
0x0047874f:	cmpb (%eax,%ecx), $0x0<UINT8>
0x00478753:	jne 0x00478749
0x00478755:	popl %ebp
0x00478756:	ret

0x00474409:	popl %ecx
0x0047440a:	cmpl %eax, %esi
0x0047440c:	popl %ecx
0x0047440d:	leal %esi, 0x1(%eax)
0x00474410:	jl 2
0x00474412:	movl %esi, %eax
0x00474414:	movl %edi, 0x24(%ebp)
0x00474417:	testl %edi, %edi
0x00474419:	jne 0x00474426
0x00474426:	xorl %eax, %eax
0x00474428:	cmpl 0x28(%ebp), %eax
0x0047442b:	pushl $0x0<UINT8>
0x0047442d:	pushl $0x0<UINT8>
0x0047442f:	pushl %esi
0x00474430:	pushl 0x14(%ebp)
0x00474433:	setne %al
0x00474436:	leal %eax, 0x1(,%eax,8)
0x0047443d:	pushl %eax
0x0047443e:	pushl %edi
0x0047443f:	call MultiByteToWideChar@KERNEL32.DLL
0x00474445:	movl -8(%ebp), %eax
0x00474448:	testl %eax, %eax
0x0047444a:	je 397
0x00474450:	leal %edx, (%eax,%eax)
0x00474453:	leal %ecx, 0x8(%edx)
0x00474456:	cmpl %edx, %ecx
0x00474458:	sbbl %eax, %eax
0x0047445a:	testl %ecx, %eax
0x0047445c:	je 82
0x0047445e:	leal %ecx, 0x8(%edx)
0x00474461:	cmpl %edx, %ecx
0x00474463:	sbbl %eax, %eax
0x00474465:	andl %eax, %ecx
0x00474467:	leal %ecx, 0x8(%edx)
0x0047446a:	cmpl %eax, $0x400<UINT32>
0x0047446f:	ja 29
0x00474471:	cmpl %edx, %ecx
0x00474473:	sbbl %eax, %eax
0x00474475:	andl %eax, %ecx
0x00474477:	call 0x004763b0
0x0047447c:	movl %ebx, %esp
0x0047447e:	testl %ebx, %ebx
0x00474480:	je 332
0x00474486:	movl (%ebx), $0xcccc<UINT32>
0x0047448c:	jmp 0x004744ab
0x004744ab:	addl %ebx, $0x8<UINT8>
0x004744ae:	jmp 0x004744b2
0x004744b2:	testl %ebx, %ebx
0x004744b4:	je 280
0x004744ba:	pushl -8(%ebp)
0x004744bd:	pushl %ebx
0x004744be:	pushl %esi
0x004744bf:	pushl 0x14(%ebp)
0x004744c2:	pushl $0x1<UINT8>
0x004744c4:	pushl %edi
0x004744c5:	call MultiByteToWideChar@KERNEL32.DLL
0x004744cb:	testl %eax, %eax
0x004744cd:	je 255
0x004744d3:	movl %edi, -8(%ebp)
0x004744d6:	xorl %eax, %eax
0x004744d8:	pushl %eax
0x004744d9:	pushl %eax
0x004744da:	pushl %eax
0x004744db:	pushl %eax
0x004744dc:	pushl %eax
0x004744dd:	pushl %edi
0x004744de:	pushl %ebx
0x004744df:	pushl 0x10(%ebp)
0x004744e2:	pushl 0xc(%ebp)
0x004744e5:	call 0x0046c734
0x0046c734:	movl %edi, %edi
0x0046c736:	pushl %ebp
0x0046c737:	movl %ebp, %esp
0x0046c739:	pushl %ecx
0x0046c73a:	movl %eax, 0x41e17c
0x0046c73f:	xorl %eax, %ebp
0x0046c741:	movl -4(%ebp), %eax
0x0046c744:	pushl %esi
0x0046c745:	pushl $0x415740<UINT32>
0x0046c74a:	pushl $0x415738<UINT32>
0x0046c74f:	pushl $0x415740<UINT32>
0x0046c754:	pushl $0x16<UINT8>
0x0046c756:	call 0x0046c2ac
0x0046c75b:	movl %esi, %eax
0x0046c75d:	addl %esp, $0x10<UINT8>
0x0046c760:	testl %esi, %esi
0x0046c762:	je 39
0x0046c764:	pushl 0x28(%ebp)
0x0046c767:	movl %ecx, %esi
0x0046c769:	pushl 0x24(%ebp)
0x0046c76c:	pushl 0x20(%ebp)
0x0046c76f:	pushl 0x1c(%ebp)
0x0046c772:	pushl 0x18(%ebp)
0x0046c775:	pushl 0x14(%ebp)
0x0046c778:	pushl 0x10(%ebp)
0x0046c77b:	pushl 0xc(%ebp)
0x0046c77e:	pushl 0x8(%ebp)
0x0046c781:	call 0x0045c34e
0x0046c787:	call LCMapStringEx@kernel32.dll
LCMapStringEx@kernel32.dll: API Node	
0x0046c789:	jmp 0x0046c7ab
0x0046c7ab:	movl %ecx, -4(%ebp)
0x0046c7ae:	xorl %ecx, %ebp
0x0046c7b0:	popl %esi
0x0046c7b1:	call 0x0045bc59
0x0046c7b6:	movl %esp, %ebp
0x0046c7b8:	popl %ebp
0x0046c7b9:	ret $0x24<UINT16>

0x004744ea:	movl %esi, %eax
0x004744ec:	testl %esi, %esi
0x004744ee:	je 0x004745d2
0x004744f4:	testl 0x10(%ebp), $0x400<UINT32>
0x004745d2:	xorl %esi, %esi
0x004745d4:	pushl %ebx
0x004745d5:	call 0x0046fc7e
0x004745da:	popl %ecx
0x004745db:	movl %eax, %esi
0x004745dd:	leal %esp, -20(%ebp)
0x004745e0:	popl %edi
0x004745e1:	popl %esi
0x004745e2:	popl %ebx
0x004745e3:	movl %ecx, -4(%ebp)
0x004745e6:	xorl %ecx, %ebp
0x004745e8:	call 0x0045bc59
0x004745ed:	movl %esp, %ebp
0x004745ef:	popl %ebp
0x004745f0:	ret

0x00474636:	addl %esp, $0x24<UINT8>
0x00474639:	cmpb -4(%ebp), $0x0<UINT8>
0x0047463d:	je 0x00474649
0x00474649:	movl %esp, %ebp
0x0047464b:	popl %ebp
0x0047464c:	ret

0x0046d506:	addl %esp, $0x40<UINT8>
0x0046d509:	leal %eax, -772(%ebp)
0x0046d50f:	pushl %ebx
0x0046d510:	pushl 0x4(%esi)
0x0046d513:	pushl %edi
0x0046d514:	pushl %eax
0x0046d515:	pushl %edi
0x0046d516:	leal %eax, -260(%ebp)
0x0046d51c:	pushl %eax
0x0046d51d:	pushl $0x200<UINT32>
0x0046d522:	pushl 0x21c(%esi)
0x0046d528:	pushl %ebx
0x0046d529:	call 0x00474602
0x0046d52e:	addl %esp, $0x24<UINT8>
0x0046d531:	movl %ecx, %ebx
0x0046d533:	movzwl %eax, -1796(%ebp,%ecx,2)
0x0046d53b:	testb %al, $0x1<UINT8>
0x0046d53d:	je 0x0046d54d
0x0046d54d:	testb %al, $0x2<UINT8>
0x0046d54f:	je 0x0046d566
0x0046d566:	movb 0x119(%esi,%ecx), %bl
0x0046d56d:	incl %ecx
0x0046d56e:	cmpl %ecx, %edi
0x0046d570:	jb 0x0046d533
0x0046d53f:	orb 0x19(%esi,%ecx), $0x10<UINT8>
0x0046d544:	movb %al, -516(%ebp,%ecx)
0x0046d54b:	jmp 0x0046d55d
0x0046d55d:	movb 0x119(%esi,%ecx), %al
0x0046d564:	jmp 0x0046d56d
0x0046d551:	orb 0x19(%esi,%ecx), $0x20<UINT8>
0x0046d556:	movb %al, -772(%ebp,%ecx)
0x0046d572:	jmp 0x0046d5cd
0x0046d5cd:	movl %ecx, -4(%ebp)
0x0046d5d0:	popl %edi
0x0046d5d1:	popl %esi
0x0046d5d2:	xorl %ecx, %ebp
0x0046d5d4:	popl %ebx
0x0046d5d5:	call 0x0045bc59
0x0046d5da:	movl %esp, %ebp
0x0046d5dc:	popl %ebp
0x0046d5dd:	ret

0x0046d97c:	popl %ecx
0x0046d97d:	xorl %eax, %eax
0x0046d97f:	popl %edi
0x0046d980:	movl %ecx, -4(%ebp)
0x0046d983:	popl %esi
0x0046d984:	xorl %ecx, %ebp
0x0046d986:	popl %ebx
0x0046d987:	call 0x0045bc59
0x0046d98c:	movl %esp, %ebp
0x0046d98e:	popl %ebp
0x0046d98f:	ret

0x0046d640:	movl %esi, %eax
0x0046d642:	popl %ecx
0x0046d643:	popl %ecx
0x0046d644:	cmpl %esi, %ebx
0x0046d646:	jne 0x0046d665
0x0046d665:	cmpb 0xc(%ebp), $0x0<UINT8>
0x0046d669:	jne 0x0046d670
0x0046d670:	movl %eax, -4(%ebp)
0x0046d673:	movl %eax, 0x48(%eax)
0x0046d676:	xaddl (%eax), %ebx
0x0046d67a:	decl %ebx
0x0046d67b:	jne 21
0x0046d67d:	movl %eax, -4(%ebp)
0x0046d680:	cmpl 0x48(%eax), $0x41e598<UINT32>
0x0046d687:	je 0x0046d692
0x0046d692:	movl (%edi), $0x1<UINT32>
0x0046d698:	movl %ecx, %edi
0x0046d69a:	movl %eax, -4(%ebp)
0x0046d69d:	xorl %edi, %edi
0x0046d69f:	movl 0x48(%eax), %ecx
0x0046d6a2:	movl %eax, -4(%ebp)
0x0046d6a5:	testb 0x350(%eax), $0x2<UINT8>
0x0046d6ac:	jne -89
0x0046d6ae:	testb 0x41e8f8, $0x1<UINT8>
0x0046d6b5:	jne -98
0x0046d6b7:	leal %eax, -4(%ebp)
0x0046d6ba:	movl -12(%ebp), %eax
0x0046d6bd:	leal %eax, -12(%ebp)
0x0046d6c0:	pushl %eax
0x0046d6c1:	pushl $0x5<UINT8>
0x0046d6c3:	call 0x0046d248
0x0046d248:	movl %edi, %edi
0x0046d24a:	pushl %ebp
0x0046d24b:	movl %ebp, %esp
0x0046d24d:	subl %esp, $0xc<UINT8>
0x0046d250:	movl %eax, 0x8(%ebp)
0x0046d253:	leal %ecx, -1(%ebp)
0x0046d256:	movl -8(%ebp), %eax
0x0046d259:	movl -12(%ebp), %eax
0x0046d25c:	leal %eax, -8(%ebp)
0x0046d25f:	pushl %eax
0x0046d260:	pushl 0xc(%ebp)
0x0046d263:	leal %eax, -12(%ebp)
0x0046d266:	pushl %eax
0x0046d267:	call 0x0046d205
0x0046d205:	pushl $0x8<UINT8>
0x0046d207:	pushl $0x47b2f0<UINT32>
0x0046d20c:	call 0x0045c5d0
0x0046d211:	movl %eax, 0x8(%ebp)
0x0046d214:	pushl (%eax)
0x0046d216:	call 0x0046cac3
0x0046d21b:	popl %ecx
0x0046d21c:	andl -4(%ebp), $0x0<UINT8>
0x0046d220:	movl %ecx, 0xc(%ebp)
0x0046d223:	call 0x0046d270
0x0046d270:	movl %edi, %edi
0x0046d272:	pushl %esi
0x0046d273:	movl %esi, %ecx
0x0046d275:	pushl $0xc<UINT8>
0x0046d277:	movl %eax, (%esi)
0x0046d279:	movl %eax, (%eax)
0x0046d27b:	movl %eax, 0x48(%eax)
0x0046d27e:	movl %eax, 0x4(%eax)
0x0046d281:	movl 0x41d2a8, %eax
0x0046d286:	movl %eax, (%esi)
0x0046d288:	movl %eax, (%eax)
0x0046d28a:	movl %eax, 0x48(%eax)
0x0046d28d:	movl %eax, 0x8(%eax)
0x0046d290:	movl 0x41d2ac, %eax
0x0046d295:	movl %eax, (%esi)
0x0046d297:	movl %eax, (%eax)
0x0046d299:	movl %eax, 0x48(%eax)
0x0046d29c:	movl %eax, 0x21c(%eax)
0x0046d2a2:	movl 0x41d2a4, %eax
0x0046d2a7:	movl %eax, (%esi)
0x0046d2a9:	movl %eax, (%eax)
0x0046d2ab:	movl %eax, 0x48(%eax)
0x0046d2ae:	addl %eax, $0xc<UINT8>
0x0046d2b1:	pushl %eax
0x0046d2b2:	pushl $0xc<UINT8>
0x0046d2b4:	pushl $0x41d2b0<UINT32>
0x0046d2b9:	call 0x0046d990
0x0046d990:	movl %edi, %edi
0x0046d992:	pushl %ebp
0x0046d993:	movl %ebp, %esp
0x0046d995:	pushl %esi
0x0046d996:	movl %esi, 0x14(%ebp)
0x0046d999:	testl %esi, %esi
0x0046d99b:	jne 0x0046d9a1
0x0046d9a1:	movl %eax, 0x8(%ebp)
0x0046d9a4:	testl %eax, %eax
0x0046d9a6:	jne 0x0046d9bb
0x0046d9bb:	pushl %edi
0x0046d9bc:	movl %edi, 0x10(%ebp)
0x0046d9bf:	testl %edi, %edi
0x0046d9c1:	je 20
0x0046d9c3:	cmpl 0xc(%ebp), %esi
0x0046d9c6:	jb 15
0x0046d9c8:	pushl %esi
0x0046d9c9:	pushl %edi
0x0046d9ca:	pushl %eax
0x0046d9cb:	call 0x0045e200
0x0045e200:	pushl %edi
0x0045e201:	pushl %esi
0x0045e202:	movl %esi, 0x10(%esp)
0x0045e206:	movl %ecx, 0x14(%esp)
0x0045e20a:	movl %edi, 0xc(%esp)
0x0045e20e:	movl %eax, %ecx
0x0045e210:	movl %edx, %ecx
0x0045e212:	addl %eax, %esi
0x0045e214:	cmpl %edi, %esi
0x0045e216:	jbe 0x0045e220
0x0045e220:	cmpl %ecx, $0x20<UINT8>
0x0045e223:	jb 0x0045e6fb
0x0045e6fb:	andl %ecx, $0x1f<UINT8>
0x0045e6fe:	je 48
0x0045e700:	movl %eax, %ecx
0x0045e702:	shrl %ecx, $0x2<UINT8>
0x0045e705:	je 15
0x0045e707:	movl %edx, (%esi)
0x0045e709:	movl (%edi), %edx
0x0045e70b:	addl %edi, $0x4<UINT8>
0x0045e70e:	addl %esi, $0x4<UINT8>
0x0045e711:	subl %ecx, $0x1<UINT8>
0x0045e714:	jne 0x0045e707
0x0045e716:	movl %ecx, %eax
0x0045e718:	andl %ecx, $0x3<UINT8>
0x0045e71b:	je 0x0045e730
0x0045e730:	movl %eax, 0xc(%esp)
0x0045e734:	popl %esi
0x0045e735:	popl %edi
0x0045e736:	ret

0x0046d9d0:	addl %esp, $0xc<UINT8>
0x0046d9d3:	xorl %eax, %eax
0x0046d9d5:	jmp 0x0046da0d
0x0046da0d:	popl %edi
0x0046da0e:	popl %esi
0x0046da0f:	popl %ebp
0x0046da10:	ret

0x0046d2be:	movl %eax, (%esi)
0x0046d2c0:	movl %ecx, $0x101<UINT32>
0x0046d2c5:	pushl %ecx
0x0046d2c6:	movl %eax, (%eax)
0x0046d2c8:	movl %eax, 0x48(%eax)
0x0046d2cb:	addl %eax, $0x18<UINT8>
0x0046d2ce:	pushl %eax
0x0046d2cf:	pushl %ecx
0x0046d2d0:	pushl $0x41e390<UINT32>
0x0046d2d5:	call 0x0046d990
0x0045e229:	cmpl %ecx, $0x80<UINT32>
0x0045e22f:	jae 0x0045e244
0x0045e244:	btl 0x41cc44, $0x1<UINT8>
0x0045e24c:	jae 0x0045e257
0x0045e257:	movl %eax, %edi
0x0045e259:	xorl %eax, %esi
0x0045e25b:	testl %eax, $0xf<UINT32>
0x0045e260:	jne 0x0045e270
0x0045e270:	btl 0x41cc44, $0x0<UINT8>
0x0045e278:	jae 0x0045e427
0x0045e427:	testl %edi, $0x3<UINT32>
0x0045e42d:	je 0x0045e442
0x0045e442:	movl %edx, %ecx
0x0045e444:	cmpl %ecx, $0x20<UINT8>
0x0045e447:	jb 686
0x0045e44d:	shrl %ecx, $0x2<UINT8>
0x0045e450:	rep movsl %es:(%edi), %ds:(%esi)
0x0045e452:	andl %edx, $0x3<UINT8>
0x0045e455:	jmp 0x0045e47c
0x0045e47c:	movb %al, (%esi)
0x0045e47e:	movb (%edi), %al
0x0045e480:	movl %eax, 0xc(%esp)
0x0045e484:	popl %esi
0x0045e485:	popl %edi
0x0045e486:	ret

0x0046d2da:	movl %eax, (%esi)
0x0046d2dc:	movl %ecx, $0x100<UINT32>
0x0046d2e1:	pushl %ecx
0x0046d2e2:	movl %eax, (%eax)
0x0046d2e4:	movl %eax, 0x48(%eax)
0x0046d2e7:	addl %eax, $0x119<UINT32>
0x0046d2ec:	pushl %eax
0x0046d2ed:	pushl %ecx
0x0046d2ee:	pushl $0x41e498<UINT32>
0x0046d2f3:	call 0x0046d990
0x0045e474:	movl %eax, 0xc(%esp)
0x0045e478:	popl %esi
0x0045e479:	popl %edi
0x0045e47a:	ret

0x0046d2f8:	movl %eax, 0x41e7b8
0x0046d2fd:	addl %esp, $0x30<UINT8>
0x0046d300:	orl %ecx, $0xffffffff<UINT8>
0x0046d303:	xaddl (%eax), %ecx
0x0046d307:	jne 0x0046d31c
0x0046d31c:	movl %eax, (%esi)
0x0046d31e:	movl %eax, (%eax)
0x0046d320:	movl %eax, 0x48(%eax)
0x0046d323:	movl 0x41e7b8, %eax
0x0046d328:	movl %eax, (%esi)
0x0046d32a:	movl %eax, (%eax)
0x0046d32c:	movl %eax, 0x48(%eax)
0x0046d32f:	incl (%eax)
0x0046d332:	popl %esi
0x0046d333:	ret

0x0046d228:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0046d22f:	call 0x0046d23c
0x0046d23c:	movl %eax, 0x10(%ebp)
0x0046d23f:	pushl (%eax)
0x0046d241:	call 0x0046cb0b
0x0046d246:	popl %ecx
0x0046d247:	ret

0x0046d234:	call 0x0045c616
0x0046d239:	ret $0xc<UINT16>

0x0046d26c:	movl %esp, %ebp
0x0046d26e:	popl %ebp
0x0046d26f:	ret

0x0046d6c8:	cmpb 0xc(%ebp), $0x0<UINT8>
0x0046d6cc:	popl %ecx
0x0046d6cd:	popl %ecx
0x0046d6ce:	je -123
0x0046d6d0:	movl %eax, 0x41e7b8
0x0046d6d5:	movl 0x41e87c, %eax
0x0046d6da:	jmp 0x0046d655
0x0046d655:	pushl %edi
0x0046d656:	call 0x0046bb58
0x0046d65b:	popl %ecx
0x0046d65c:	popl %edi
0x0046d65d:	movl %eax, %esi
0x0046d65f:	popl %esi
0x0046d660:	popl %ebx
0x0046d661:	movl %esp, %ebp
0x0046d663:	popl %ebp
0x0046d664:	ret

0x0046d6f1:	popl %ecx
0x0046d6f2:	popl %ecx
0x0046d6f3:	movb 0x41d2c0, $0x1<UINT8>
0x0046d6fa:	movb %al, $0x1<UINT8>
0x0046d6fc:	ret

0x0045f0f6:	movb %al, $0x1<UINT8>
0x0045f0f8:	ret

0x0045f0d9:	pushl $0x41cd80<UINT32>
0x0045f0de:	call 0x00467c7c
0x00467c7c:	movl %edi, %edi
0x00467c7e:	pushl %ebp
0x00467c7f:	movl %ebp, %esp
0x00467c81:	pushl %esi
0x00467c82:	movl %esi, 0x8(%ebp)
0x00467c85:	testl %esi, %esi
0x00467c87:	jne 0x00467c8e
0x00467c8e:	movl %eax, (%esi)
0x00467c90:	cmpl %eax, 0x8(%esi)
0x00467c93:	jne 31
0x00467c95:	movl %eax, 0x41e17c
0x00467c9a:	andl %eax, $0x1f<UINT8>
0x00467c9d:	pushl $0x20<UINT8>
0x00467c9f:	popl %ecx
0x00467ca0:	subl %ecx, %eax
0x00467ca2:	xorl %eax, %eax
0x00467ca4:	rorl %eax, %cl
0x00467ca6:	xorl %eax, 0x41e17c
0x00467cac:	movl (%esi), %eax
0x00467cae:	movl 0x4(%esi), %eax
0x00467cb1:	movl 0x8(%esi), %eax
0x00467cb4:	xorl %eax, %eax
0x00467cb6:	popl %esi
0x00467cb7:	popl %ebp
0x00467cb8:	ret

0x0045f0e3:	movl (%esp), $0x41cd8c<UINT32>
0x0045f0ea:	call 0x00467c7c
0x0045f0ef:	popl %ecx
0x0045f0f0:	movb %al, $0x1<UINT8>
0x0045f0f2:	ret

0x0046da4e:	cmpl %esi, 0xc(%ebp)
0x0046da51:	jne 4
0x0046da53:	movb %al, $0x1<UINT8>
0x0046da55:	jmp 0x0046da83
0x0046da83:	popl %ebx
0x0046da84:	popl %esi
0x0046da85:	movl %ecx, -4(%ebp)
0x0046da88:	xorl %ecx, %ebp
0x0046da8a:	popl %edi
0x0046da8b:	call 0x0045bc59
0x0046da90:	movl %esp, %ebp
0x0046da92:	popl %ebp
0x0046da93:	ret

0x0045f226:	popl %ecx
0x0045f227:	popl %ecx
0x0045f228:	ret

0x0045c0ad:	testb %al, %al
0x0045c0af:	jne 0x0045c0bb
0x0045c0bb:	movb %al, $0x1<UINT8>
0x0045c0bd:	popl %ebp
0x0045c0be:	ret

0x0045be91:	popl %ecx
0x0045be92:	testb %al, %al
0x0045be94:	jne 0x0045be9d
0x0045be9d:	xorb %bl, %bl
0x0045be9f:	movb -25(%ebp), %bl
0x0045bea2:	andl -4(%ebp), $0x0<UINT8>
0x0045bea6:	call 0x0045c051
0x0045c051:	call 0x0045c7c5
0x0045c7c5:	xorl %eax, %eax
0x0045c7c7:	cmpl 0x41cc48, %eax
0x0045c7cd:	setne %al
0x0045c7d0:	ret

0x0045c056:	testl %eax, %eax
0x0045c058:	jne 3
0x0045c05a:	xorb %al, %al
0x0045c05c:	ret

0x0045beab:	movb -36(%ebp), %al
0x0045beae:	movl %eax, 0x41cc04
0x0045beb3:	xorl %ecx, %ecx
0x0045beb5:	incl %ecx
0x0045beb6:	cmpl %eax, %ecx
0x0045beb8:	je -36
0x0045beba:	testl %eax, %eax
0x0045bebc:	jne 73
0x0045bebe:	movl 0x41cc04, %ecx
0x0045bec4:	pushl $0x402028<UINT32>
0x0045bec9:	pushl $0x40200c<UINT32>
0x0045bece:	call 0x00468079
0x00468079:	movl %edi, %edi
0x0046807b:	pushl %ebp
0x0046807c:	movl %ebp, %esp
0x0046807e:	pushl %ecx
0x0046807f:	movl %eax, 0x41e17c
0x00468084:	xorl %eax, %ebp
0x00468086:	movl -4(%ebp), %eax
0x00468089:	pushl %esi
0x0046808a:	movl %esi, 0x8(%ebp)
0x0046808d:	pushl %edi
0x0046808e:	jmp 0x004680a7
0x004680a7:	cmpl %esi, 0xc(%ebp)
0x004680aa:	jne 0x00468090
0x00468090:	movl %edi, (%esi)
0x00468092:	testl %edi, %edi
0x00468094:	je 0x004680a4
0x004680a4:	addl %esi, $0x4<UINT8>
0x00468096:	movl %ecx, %edi
0x00468098:	call 0x0045c34e
0x0046809e:	call 0x00478e94
0x0045bdc0:	pushl %esi
0x0045bdc1:	pushl $0x2<UINT8>
0x0045bdc3:	call 0x00468237
0x00468237:	movl %edi, %edi
0x00468239:	pushl %ebp
0x0046823a:	movl %ebp, %esp
0x0046823c:	movl %eax, 0x8(%ebp)
0x0046823f:	movl 0x41cdac, %eax
0x00468244:	popl %ebp
0x00468245:	ret

0x0045bdc8:	call 0x0045c318
0x0045c318:	movl %eax, $0x4000<UINT32>
0x0045c31d:	ret

0x0045bdcd:	pushl %eax
0x0045bdce:	call 0x00468272
0x00468272:	movl %edi, %edi
0x00468274:	pushl %ebp
0x00468275:	movl %ebp, %esp
0x00468277:	movl %eax, 0x8(%ebp)
0x0046827a:	cmpl %eax, $0x4000<UINT32>
0x0046827f:	je 0x004682a4
0x004682a4:	movl %ecx, $0x41d2f8<UINT32>
0x004682a9:	xchgl (%ecx), %eax
0x004682ab:	xorl %eax, %eax
0x004682ad:	popl %ebp
0x004682ae:	ret

0x0045bdd3:	call 0x0045f387
0x0045f387:	movl %eax, $0x41cc5c<UINT32>
0x0045f38c:	ret

0x0045bdd8:	movl %esi, %eax
0x0045bdda:	call 0x0045c311
0x0045c311:	xorl %eax, %eax
0x0045c313:	ret

0x0045bddf:	pushl $0x1<UINT8>
0x0045bde1:	movl (%esi), %eax
0x0045bde3:	call 0x0045c0bf
0x0045c0bf:	pushl %ebp
0x0045c0c0:	movl %ebp, %esp
0x0045c0c2:	subl %esp, $0xc<UINT8>
0x0045c0c5:	pushl %esi
0x0045c0c6:	movl %esi, 0x8(%ebp)
0x0045c0c9:	testl %esi, %esi
0x0045c0cb:	je 5
0x0045c0cd:	cmpl %esi, $0x1<UINT8>
0x0045c0d0:	jne 124
0x0045c0d2:	call 0x0045c7c5
0x0045c0d7:	testl %eax, %eax
0x0045c0d9:	je 0x0045c105
0x0045c105:	movl %eax, 0x41e17c
0x0045c10a:	leal %esi, -12(%ebp)
0x0045c10d:	pushl %edi
0x0045c10e:	andl %eax, $0x1f<UINT8>
0x0045c111:	movl %edi, $0x41cc0c<UINT32>
0x0045c116:	pushl $0x20<UINT8>
0x0045c118:	popl %ecx
0x0045c119:	subl %ecx, %eax
0x0045c11b:	orl %eax, $0xffffffff<UINT8>
0x0045c11e:	rorl %eax, %cl
0x0045c120:	xorl %eax, 0x41e17c
0x0045c126:	movl -12(%ebp), %eax
0x0045c129:	movl -8(%ebp), %eax
0x0045c12c:	movl -4(%ebp), %eax
0x0045c12f:	movsl %es:(%edi), %ds:(%esi)
0x0045c130:	movsl %es:(%edi), %ds:(%esi)
0x0045c131:	movsl %es:(%edi), %ds:(%esi)
0x0045c132:	movl %edi, $0x41cc18<UINT32>
0x0045c137:	movl -12(%ebp), %eax
0x0045c13a:	movl -8(%ebp), %eax
0x0045c13d:	leal %esi, -12(%ebp)
0x0045c140:	movl -4(%ebp), %eax
0x0045c143:	movb %al, $0x1<UINT8>
0x0045c145:	movsl %es:(%edi), %ds:(%esi)
0x0045c146:	movsl %es:(%edi), %ds:(%esi)
0x0045c147:	movsl %es:(%edi), %ds:(%esi)
0x0045c148:	popl %edi
0x0045c149:	popl %esi
0x0045c14a:	movl %esp, %ebp
0x0045c14c:	popl %ebp
0x0045c14d:	ret

0x0045bde8:	addl %esp, $0xc<UINT8>
0x0045bdeb:	popl %esi
0x0045bdec:	testb %al, %al
0x0045bdee:	je 108
0x0045bdf0:	fnclex
0x0045bdf2:	call 0x0045c56b
0x0045c56b:	pushl %ebx
0x0045c56c:	pushl %esi
0x0045c56d:	movl %esi, $0x4193a4<UINT32>
0x0045c572:	movl %ebx, $0x4193a4<UINT32>
0x0045c577:	cmpl %esi, %ebx
0x0045c579:	jae 0x0045c593
0x0045c593:	popl %esi
0x0045c594:	popl %ebx
0x0045c595:	ret

0x0045bdf7:	pushl $0x45c596<UINT32>
0x0045bdfc:	call 0x0045c260
0x0045c260:	pushl %ebp
0x0045c261:	movl %ebp, %esp
0x0045c263:	pushl 0x8(%ebp)
0x0045c266:	call 0x0045c225
0x0045c225:	pushl %ebp
0x0045c226:	movl %ebp, %esp
0x0045c228:	movl %eax, 0x41e17c
0x0045c22d:	movl %ecx, %eax
0x0045c22f:	xorl %eax, 0x41cc0c
0x0045c235:	andl %ecx, $0x1f<UINT8>
0x0045c238:	pushl 0x8(%ebp)
0x0045c23b:	rorl %eax, %cl
0x0045c23d:	cmpl %eax, $0xffffffff<UINT8>
0x0045c240:	jne 7
0x0045c242:	call 0x00467c49
0x00467c49:	movl %edi, %edi
0x00467c4b:	pushl %ebp
0x00467c4c:	movl %ebp, %esp
0x00467c4e:	pushl 0x8(%ebp)
0x00467c51:	pushl $0x41cd80<UINT32>
0x00467c56:	call 0x00467cb9
0x00467cb9:	movl %edi, %edi
0x00467cbb:	pushl %ebp
0x00467cbc:	movl %ebp, %esp
0x00467cbe:	pushl %ecx
0x00467cbf:	pushl %ecx
0x00467cc0:	leal %eax, 0x8(%ebp)
0x00467cc3:	movl -8(%ebp), %eax
0x00467cc6:	leal %eax, 0xc(%ebp)
0x00467cc9:	movl -4(%ebp), %eax
0x00467ccc:	leal %eax, -8(%ebp)
0x00467ccf:	pushl %eax
0x00467cd0:	pushl $0x2<UINT8>
0x00467cd2:	call 0x004679c0
0x004679c0:	movl %edi, %edi
0x004679c2:	pushl %ebp
0x004679c3:	movl %ebp, %esp
0x004679c5:	subl %esp, $0xc<UINT8>
0x004679c8:	movl %eax, 0x8(%ebp)
0x004679cb:	leal %ecx, -1(%ebp)
0x004679ce:	movl -8(%ebp), %eax
0x004679d1:	movl -12(%ebp), %eax
0x004679d4:	leal %eax, -8(%ebp)
0x004679d7:	pushl %eax
0x004679d8:	pushl 0xc(%ebp)
0x004679db:	leal %eax, -12(%ebp)
0x004679de:	pushl %eax
0x004679df:	call 0x004678f6
0x004678f6:	pushl $0xc<UINT8>
0x004678f8:	pushl $0x47b0c8<UINT32>
0x004678fd:	call 0x0045c5d0
0x00467902:	andl -28(%ebp), $0x0<UINT8>
0x00467906:	movl %eax, 0x8(%ebp)
0x00467909:	pushl (%eax)
0x0046790b:	call 0x0046cac3
0x00467910:	popl %ecx
0x00467911:	andl -4(%ebp), $0x0<UINT8>
0x00467915:	movl %ecx, 0xc(%ebp)
0x00467918:	call 0x00467b08
0x00467b08:	movl %edi, %edi
0x00467b0a:	pushl %ebp
0x00467b0b:	movl %ebp, %esp
0x00467b0d:	subl %esp, $0xc<UINT8>
0x00467b10:	movl %eax, %ecx
0x00467b12:	movl -8(%ebp), %eax
0x00467b15:	pushl %esi
0x00467b16:	movl %eax, (%eax)
0x00467b18:	movl %esi, (%eax)
0x00467b1a:	testl %esi, %esi
0x00467b1c:	jne 0x00467b26
0x00467b26:	movl %eax, 0x41e17c
0x00467b2b:	movl %ecx, %eax
0x00467b2d:	pushl %ebx
0x00467b2e:	movl %ebx, (%esi)
0x00467b30:	andl %ecx, $0x1f<UINT8>
0x00467b33:	pushl %edi
0x00467b34:	movl %edi, 0x4(%esi)
0x00467b37:	xorl %ebx, %eax
0x00467b39:	movl %esi, 0x8(%esi)
0x00467b3c:	xorl %edi, %eax
0x00467b3e:	xorl %esi, %eax
0x00467b40:	rorl %edi, %cl
0x00467b42:	rorl %esi, %cl
0x00467b44:	rorl %ebx, %cl
0x00467b46:	cmpl %edi, %esi
0x00467b48:	jne 180
0x00467b4e:	subl %esi, %ebx
0x00467b50:	movl %eax, $0x200<UINT32>
0x00467b55:	sarl %esi, $0x2<UINT8>
0x00467b58:	cmpl %esi, %eax
0x00467b5a:	ja 2
0x00467b5c:	movl %eax, %esi
0x00467b5e:	leal %edi, (%eax,%esi)
0x00467b61:	testl %edi, %edi
0x00467b63:	jne 3
0x00467b65:	pushl $0x20<UINT8>
0x00467b67:	popl %edi
0x00467b68:	cmpl %edi, %esi
0x00467b6a:	jb 29
0x00467b6c:	pushl $0x4<UINT8>
0x00467b6e:	pushl %edi
0x00467b6f:	pushl %ebx
0x00467b70:	call 0x00470a72
0x00470a72:	movl %edi, %edi
0x00470a74:	pushl %ebp
0x00470a75:	movl %ebp, %esp
0x00470a77:	popl %ebp
0x00470a78:	jmp 0x00470a7d
0x00470a7d:	movl %edi, %edi
0x00470a7f:	pushl %ebp
0x00470a80:	movl %ebp, %esp
0x00470a82:	pushl %esi
0x00470a83:	movl %esi, 0xc(%ebp)
0x00470a86:	testl %esi, %esi
0x00470a88:	je 27
0x00470a8a:	pushl $0xffffffe0<UINT8>
0x00470a8c:	xorl %edx, %edx
0x00470a8e:	popl %eax
0x00470a8f:	divl %eax, %esi
0x00470a91:	cmpl %eax, 0x10(%ebp)
0x00470a94:	jae 0x00470aa5
0x00470aa5:	pushl %ebx
0x00470aa6:	movl %ebx, 0x8(%ebp)
0x00470aa9:	pushl %edi
0x00470aaa:	testl %ebx, %ebx
0x00470aac:	je 0x00470ab9
0x00470ab9:	xorl %edi, %edi
0x00470abb:	imull %esi, 0x10(%ebp)
0x00470abf:	pushl %esi
0x00470ac0:	pushl %ebx
0x00470ac1:	call 0x00472fce
0x00472fce:	movl %edi, %edi
0x00472fd0:	pushl %ebp
0x00472fd1:	movl %ebp, %esp
0x00472fd3:	pushl %edi
0x00472fd4:	movl %edi, 0x8(%ebp)
0x00472fd7:	testl %edi, %edi
0x00472fd9:	jne 11
0x00472fdb:	pushl 0xc(%ebp)
0x00472fde:	call 0x0046bb92
0x00472fe3:	popl %ecx
0x00472fe4:	jmp 0x0047300a
0x0047300a:	popl %edi
0x0047300b:	popl %ebp
0x0047300c:	ret

0x00470ac6:	movl %ebx, %eax
0x00470ac8:	popl %ecx
0x00470ac9:	popl %ecx
0x00470aca:	testl %ebx, %ebx
0x00470acc:	je 21
0x00470ace:	cmpl %edi, %esi
0x00470ad0:	jae 17
0x00470ad2:	subl %esi, %edi
0x00470ad4:	leal %eax, (%ebx,%edi)
0x00470ad7:	pushl %esi
0x00470ad8:	pushl $0x0<UINT8>
0x00470ada:	pushl %eax
0x00470adb:	call 0x0045ed00
0x0045edbd:	btl 0x41e190, $0x1<UINT8>
0x0045edc5:	jae 62
0x0045edc7:	movd %xmm0, %eax
0x0045edcb:	pshufd %xmm0, %xmm0, $0x0<UINT8>
0x00470ae0:	addl %esp, $0xc<UINT8>
0x00470ae3:	popl %edi
0x00470ae4:	movl %eax, %ebx
0x00470ae6:	popl %ebx
0x00470ae7:	popl %esi
0x00470ae8:	popl %ebp
0x00470ae9:	ret

0x00467b75:	pushl $0x0<UINT8>
0x00467b77:	movl -4(%ebp), %eax
0x00467b7a:	call 0x0046bb58
0x00467b7f:	movl %ecx, -4(%ebp)
0x00467b82:	addl %esp, $0x10<UINT8>
0x00467b85:	testl %ecx, %ecx
0x00467b87:	jne 0x00467bb1
0x00467bb1:	leal %eax, (%ecx,%esi,4)
0x00467bb4:	movl %ebx, %ecx
0x00467bb6:	movl -4(%ebp), %eax
0x00467bb9:	leal %esi, (%ecx,%edi,4)
0x00467bbc:	movl %eax, 0x41e17c
0x00467bc1:	movl %edi, -4(%ebp)
0x00467bc4:	andl %eax, $0x1f<UINT8>
0x00467bc7:	pushl $0x20<UINT8>
0x00467bc9:	popl %ecx
0x00467bca:	subl %ecx, %eax
0x00467bcc:	xorl %eax, %eax
0x00467bce:	rorl %eax, %cl
0x00467bd0:	movl %ecx, %edi
0x00467bd2:	xorl %eax, 0x41e17c
0x00467bd8:	movl -12(%ebp), %eax
0x00467bdb:	movl %eax, %esi
0x00467bdd:	subl %eax, %edi
0x00467bdf:	addl %eax, $0x3<UINT8>
0x00467be2:	shrl %eax, $0x2<UINT8>
0x00467be5:	cmpl %esi, %edi
0x00467be7:	sbbl %edx, %edx
0x00467be9:	notl %edx
0x00467beb:	andl %edx, %eax
0x00467bed:	movl -4(%ebp), %edx
0x00467bf0:	je 16
0x00467bf2:	movl %edx, -12(%ebp)
0x00467bf5:	xorl %eax, %eax
0x00467bf7:	incl %eax
0x00467bf8:	movl (%ecx), %edx
0x00467bfa:	leal %ecx, 0x4(%ecx)
0x00467bfd:	cmpl %eax, -4(%ebp)
0x00467c00:	jne 0x00467bf7
0x00467c02:	movl %eax, -8(%ebp)
0x00467c05:	movl %eax, 0x4(%eax)
0x00467c08:	pushl (%eax)
0x00467c0a:	call 0x0045f1c7
0x00467c0f:	pushl %ebx
0x00467c10:	movl (%edi), %eax
0x00467c12:	call 0x0045bff0
0x0045bff0:	pushl %ebp
0x0045bff1:	movl %ebp, %esp
0x0045bff3:	movl %eax, 0x41e17c
0x0045bff8:	andl %eax, $0x1f<UINT8>
0x0045bffb:	pushl $0x20<UINT8>
0x0045bffd:	popl %ecx
0x0045bffe:	subl %ecx, %eax
0x0045c000:	movl %eax, 0x8(%ebp)
0x0045c003:	rorl %eax, %cl
0x0045c005:	xorl %eax, 0x41e17c
0x0045c00b:	popl %ebp
0x0045c00c:	ret

0x00467c17:	movl %ebx, -8(%ebp)
0x00467c1a:	movl %ecx, (%ebx)
0x00467c1c:	movl %ecx, (%ecx)
0x00467c1e:	movl (%ecx), %eax
0x00467c20:	leal %eax, 0x4(%edi)
0x00467c23:	pushl %eax
0x00467c24:	call 0x0045bff0
0x00467c29:	movl %ecx, (%ebx)
0x00467c2b:	pushl %esi
0x00467c2c:	movl %ecx, (%ecx)
0x00467c2e:	movl 0x4(%ecx), %eax
0x00467c31:	call 0x0045bff0
0x00467c36:	movl %ecx, (%ebx)
0x00467c38:	addl %esp, $0x10<UINT8>
0x00467c3b:	movl %ecx, (%ecx)
0x00467c3d:	movl 0x8(%ecx), %eax
0x00467c40:	xorl %eax, %eax
0x00467c42:	popl %edi
0x00467c43:	popl %ebx
0x00467c44:	popl %esi
0x00467c45:	movl %esp, %ebp
0x00467c47:	popl %ebp
0x00467c48:	ret

0x0046791d:	movl %esi, %eax
0x0046791f:	movl -28(%ebp), %esi
0x00467922:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00467929:	call 0x0046793b
0x0046793b:	movl %eax, 0x10(%ebp)
0x0046793e:	pushl (%eax)
0x00467940:	call 0x0046cb0b
0x00467945:	popl %ecx
0x00467946:	ret

0x0046792e:	movl %eax, %esi
0x00467930:	call 0x0045c616
0x00467935:	ret $0xc<UINT16>

0x004679e4:	movl %esp, %ebp
0x004679e6:	popl %ebp
0x004679e7:	ret

0x00467cd7:	popl %ecx
0x00467cd8:	popl %ecx
0x00467cd9:	movl %esp, %ebp
0x00467cdb:	popl %ebp
0x00467cdc:	ret

0x00467c5b:	popl %ecx
0x00467c5c:	popl %ecx
0x00467c5d:	popl %ebp
0x00467c5e:	ret

0x0045c247:	jmp 0x0045c254
0x0045c254:	negl %eax
0x0045c256:	popl %ecx
0x0045c257:	sbbl %eax, %eax
0x0045c259:	notl %eax
0x0045c25b:	andl %eax, 0x8(%ebp)
0x0045c25e:	popl %ebp
0x0045c25f:	ret

0x0045c26b:	negl %eax
0x0045c26d:	popl %ecx
0x0045c26e:	sbbl %eax, %eax
0x0045c270:	negl %eax
0x0045c272:	decl %eax
0x0045c273:	popl %ebp
0x0045c274:	ret

0x0045be01:	call 0x0045c314
0x0045c314:	xorl %eax, %eax
0x0045c316:	incl %eax
0x0045c317:	ret

0x0045be06:	pushl %eax
0x0045be07:	call 0x0046788c
0x0046788c:	movl %edi, %edi
0x0046788e:	pushl %ebp
0x0046788f:	movl %ebp, %esp
0x00467891:	popl %ebp
0x00467892:	jmp 0x0046759e
0x0046759e:	movl %edi, %edi
0x004675a0:	pushl %ebp
0x004675a1:	movl %ebp, %esp
0x004675a3:	subl %esp, $0xc<UINT8>
0x004675a6:	cmpl 0x8(%ebp), $0x2<UINT8>
0x004675aa:	pushl %esi
0x004675ab:	je 28
0x004675ad:	cmpl 0x8(%ebp), $0x1<UINT8>
0x004675b1:	je 0x004675c9
0x004675c9:	pushl %ebx
0x004675ca:	pushl %edi
0x004675cb:	call 0x0046d6df
0x004675d0:	pushl $0x104<UINT32>
0x004675d5:	movl %esi, $0x41cc78<UINT32>
0x004675da:	xorl %edi, %edi
0x004675dc:	pushl %esi
0x004675dd:	pushl %edi
0x004675de:	call GetModuleFileNameA@KERNEL32.DLL
GetModuleFileNameA@KERNEL32.DLL: API Node	
0x004675e4:	movl %ebx, 0x41d298
0x004675ea:	movl 0x41d2a0, %esi
0x004675f0:	testl %ebx, %ebx
0x004675f2:	je 5
0x004675f4:	cmpb (%ebx), $0x0<UINT8>
0x004675f7:	jne 0x004675fb
0x004675fb:	leal %eax, -12(%ebp)
0x004675fe:	movl -4(%ebp), %edi
0x00467601:	pushl %eax
0x00467602:	leal %eax, -4(%ebp)
0x00467605:	movl -12(%ebp), %edi
0x00467608:	pushl %eax
0x00467609:	pushl %edi
0x0046760a:	pushl %edi
0x0046760b:	pushl %ebx
0x0046760c:	call 0x004676c2
0x004676c2:	movl %edi, %edi
0x004676c4:	pushl %ebp
0x004676c5:	movl %ebp, %esp
0x004676c7:	pushl %ecx
0x004676c8:	movl %eax, 0x14(%ebp)
0x004676cb:	pushl %ebx
0x004676cc:	movl %ebx, 0x18(%ebp)
0x004676cf:	pushl %esi
0x004676d0:	movl %esi, 0x8(%ebp)
0x004676d3:	pushl %edi
0x004676d4:	andl (%ebx), $0x0<UINT8>
0x004676d7:	movl %edi, 0x10(%ebp)
0x004676da:	movl (%eax), $0x1<UINT32>
0x004676e0:	movl %eax, 0xc(%ebp)
0x004676e3:	testl %eax, %eax
0x004676e5:	je 0x004676ef
0x004676ef:	xorb %cl, %cl
0x004676f1:	movb -1(%ebp), %cl
0x004676f4:	cmpb (%esi), $0x22<UINT8>
0x004676f7:	jne 0x00467706
0x004676f9:	testb %cl, %cl
0x004676fb:	movb %al, $0x22<UINT8>
0x004676fd:	sete %cl
0x00467700:	incl %esi
0x00467701:	movb -1(%ebp), %cl
0x00467704:	jmp 0x0046773b
0x0046773b:	testb %cl, %cl
0x0046773d:	jne 0x004676f4
0x00467706:	incl (%ebx)
0x00467708:	testl %edi, %edi
0x0046770a:	je 0x00467711
0x00467711:	movb %al, (%esi)
0x00467713:	incl %esi
0x00467714:	movb -2(%ebp), %al
0x00467717:	movsbl %eax, %al
0x0046771a:	pushl %eax
0x0046771b:	call 0x00470536
0x00470536:	movl %edi, %edi
0x00470538:	pushl %ebp
0x00470539:	movl %ebp, %esp
0x0047053b:	pushl $0x4<UINT8>
0x0047053d:	pushl $0x0<UINT8>
0x0047053f:	pushl 0x8(%ebp)
0x00470542:	pushl $0x0<UINT8>
0x00470544:	call 0x004704dd
0x004704dd:	movl %edi, %edi
0x004704df:	pushl %ebp
0x004704e0:	movl %ebp, %esp
0x004704e2:	subl %esp, $0x10<UINT8>
0x004704e5:	pushl %esi
0x004704e6:	pushl 0x8(%ebp)
0x004704e9:	leal %ecx, -16(%ebp)
0x004704ec:	call 0x0045fc82
0x004704f1:	movzbl %esi, 0xc(%ebp)
0x004704f5:	movl %eax, -8(%ebp)
0x004704f8:	movb %cl, 0x14(%ebp)
0x004704fb:	testb 0x19(%eax,%esi), %cl
0x004704ff:	jne 27
0x00470501:	xorl %edx, %edx
0x00470503:	cmpl 0x10(%ebp), %edx
0x00470506:	je 0x00470516
0x00470516:	movl %eax, %edx
0x00470518:	testl %eax, %eax
0x0047051a:	je 0x0047051f
0x0047051f:	cmpb -4(%ebp), $0x0<UINT8>
0x00470523:	popl %esi
0x00470524:	je 0x00470530
0x00470530:	movl %eax, %edx
0x00470532:	movl %esp, %ebp
0x00470534:	popl %ebp
0x00470535:	ret

0x00470549:	addl %esp, $0x10<UINT8>
0x0047054c:	popl %ebp
0x0047054d:	ret

0x00467720:	popl %ecx
0x00467721:	testl %eax, %eax
0x00467723:	je 0x00467731
0x00467731:	movb %al, -2(%ebp)
0x00467734:	testb %al, %al
0x00467736:	je 0x00467751
0x00467751:	decl %esi
0x00467752:	movb -1(%ebp), $0x0<UINT8>
0x00467756:	cmpb (%esi), $0x0<UINT8>
0x00467759:	je 0x00467821
0x00467821:	movl %ecx, 0xc(%ebp)
0x00467824:	popl %edi
0x00467825:	popl %esi
0x00467826:	popl %ebx
0x00467827:	testl %ecx, %ecx
0x00467829:	je 0x0046782e
0x0046782e:	movl %eax, 0x14(%ebp)
0x00467831:	incl (%eax)
0x00467833:	movl %esp, %ebp
0x00467835:	popl %ebp
0x00467836:	ret

0x00467611:	pushl $0x1<UINT8>
0x00467613:	pushl -12(%ebp)
0x00467616:	pushl -4(%ebp)
0x00467619:	call 0x00467837
0x00467837:	movl %edi, %edi
0x00467839:	pushl %ebp
0x0046783a:	movl %ebp, %esp
0x0046783c:	pushl %esi
0x0046783d:	movl %esi, 0x8(%ebp)
0x00467840:	cmpl %esi, $0x3fffffff<UINT32>
0x00467846:	jb 0x0046784c
0x0046784c:	pushl %edi
0x0046784d:	orl %edi, $0xffffffff<UINT8>
0x00467850:	movl %ecx, 0xc(%ebp)
0x00467853:	xorl %edx, %edx
0x00467855:	movl %eax, %edi
0x00467857:	divl %eax, 0x10(%ebp)
0x0046785a:	cmpl %ecx, %eax
0x0046785c:	jae 13
0x0046785e:	imull %ecx, 0x10(%ebp)
0x00467862:	shll %esi, $0x2<UINT8>
0x00467865:	subl %edi, %esi
0x00467867:	cmpl %edi, %ecx
0x00467869:	ja 0x0046786f
0x0046786f:	leal %eax, (%ecx,%esi)
0x00467872:	pushl $0x1<UINT8>
0x00467874:	pushl %eax
0x00467875:	call 0x0046e261
0x0046787a:	pushl $0x0<UINT8>
0x0046787c:	movl %esi, %eax
0x0046787e:	call 0x0046bb58
0x00467883:	addl %esp, $0xc<UINT8>
0x00467886:	movl %eax, %esi
0x00467888:	popl %edi
0x00467889:	popl %esi
0x0046788a:	popl %ebp
0x0046788b:	ret

0x0046761e:	movl %esi, %eax
0x00467620:	addl %esp, $0x20<UINT8>
0x00467623:	testl %esi, %esi
0x00467625:	jne 0x00467633
0x00467633:	leal %eax, -12(%ebp)
0x00467636:	pushl %eax
0x00467637:	leal %eax, -4(%ebp)
0x0046763a:	pushl %eax
0x0046763b:	movl %eax, -4(%ebp)
0x0046763e:	leal %eax, (%esi,%eax,4)
0x00467641:	pushl %eax
0x00467642:	pushl %esi
0x00467643:	pushl %ebx
0x00467644:	call 0x004676c2
0x004676e7:	movl (%eax), %edi
0x004676e9:	addl %eax, $0x4<UINT8>
0x004676ec:	movl 0xc(%ebp), %eax
0x0046770c:	movb %al, (%esi)
0x0046770e:	movb (%edi), %al
0x00467710:	incl %edi
0x0046782b:	andl (%ecx), $0x0<UINT8>
0x00467649:	addl %esp, $0x14<UINT8>
0x0046764c:	cmpl 0x8(%ebp), $0x1<UINT8>
0x00467650:	jne 22
0x00467652:	movl %eax, -4(%ebp)
0x00467655:	decl %eax
0x00467656:	movl 0x41d28c, %eax
0x0046765b:	movl %eax, %esi
0x0046765d:	movl %esi, %edi
0x0046765f:	movl 0x41d290, %eax
0x00467664:	movl %ebx, %edi
0x00467666:	jmp 0x004676b2
0x004676b2:	pushl %esi
0x004676b3:	call 0x0046bb58
0x004676b8:	popl %ecx
0x004676b9:	popl %edi
0x004676ba:	movl %eax, %ebx
0x004676bc:	popl %ebx
0x004676bd:	popl %esi
0x004676be:	movl %esp, %ebp
0x004676c0:	popl %ebp
0x004676c1:	ret

0x0045be0c:	popl %ecx
0x0045be0d:	popl %ecx
0x0045be0e:	testl %eax, %eax
0x0045be10:	jne 74
0x0045be12:	call 0x0045c31e
0x0045c31e:	pushl $0x41cc28<UINT32>
0x0045c323:	call InitializeSListHead@KERNEL32.DLL
InitializeSListHead@KERNEL32.DLL: API Node	
0x0045c329:	ret

0x0045be17:	call 0x0045c36c
0x0045c36c:	xorl %eax, %eax
0x0045c36e:	cmpl 0x41e188, %eax
0x0045c374:	sete %al
0x0045c377:	ret

0x0045be1c:	testl %eax, %eax
0x0045be1e:	je 0x0045be2b
0x0045be2b:	call 0x0045c34e
0x0045be30:	call 0x0045c34e
0x0045be35:	call 0x0045c32d
0x0045c32d:	pushl $0x30000<UINT32>
0x0045c332:	pushl $0x10000<UINT32>
0x0045c337:	pushl $0x0<UINT8>
0x0045c339:	call 0x00467897
0x00467897:	movl %edi, %edi
0x00467899:	pushl %ebp
0x0046789a:	movl %ebp, %esp
0x0046789c:	movl %ecx, 0x10(%ebp)
0x0046789f:	movl %eax, 0xc(%ebp)
0x004678a2:	andl %ecx, $0xfff7ffff<UINT32>
0x004678a8:	andl %eax, %ecx
0x004678aa:	pushl %esi
0x004678ab:	movl %esi, 0x8(%ebp)
0x004678ae:	testl %eax, $0xfcf0fce0<UINT32>
0x004678b3:	je 0x004678d9
0x004678d9:	pushl %ecx
0x004678da:	pushl 0xc(%ebp)
0x004678dd:	testl %esi, %esi
0x004678df:	je 0x004678ea
0x004678ea:	call 0x004706d7
0x004706d7:	movl %edi, %edi
0x004706d9:	pushl %ebp
0x004706da:	movl %ebp, %esp
0x004706dc:	subl %esp, $0x10<UINT8>
0x004706df:	fwait
0x004706e0:	fnstcw -8(%ebp)
0x004706e3:	movw %ax, -8(%ebp)
0x004706e7:	xorl %ecx, %ecx
0x004706e9:	testb %al, $0x1<UINT8>
0x004706eb:	je 0x004706f0
0x004706f0:	testb %al, $0x4<UINT8>
0x004706f2:	je 0x004706f7
0x004706f7:	testb %al, $0x8<UINT8>
0x004706f9:	je 3
0x004706fb:	orl %ecx, $0x4<UINT8>
0x004706fe:	testb %al, $0x10<UINT8>
0x00470700:	je 3
0x00470702:	orl %ecx, $0x2<UINT8>
0x00470705:	testb %al, $0x20<UINT8>
0x00470707:	je 0x0047070c
0x0047070c:	testb %al, $0x2<UINT8>
0x0047070e:	je 0x00470716
0x00470716:	pushl %ebx
0x00470717:	pushl %esi
0x00470718:	movzwl %esi, %ax
0x0047071b:	movl %ebx, $0xc00<UINT32>
0x00470720:	movl %edx, %esi
0x00470722:	pushl %edi
0x00470723:	movl %edi, $0x200<UINT32>
0x00470728:	andl %edx, %ebx
0x0047072a:	je 38
0x0047072c:	cmpl %edx, $0x400<UINT32>
0x00470732:	je 24
0x00470734:	cmpl %edx, $0x800<UINT32>
0x0047073a:	je 12
0x0047073c:	cmpl %edx, %ebx
0x0047073e:	jne 18
0x00470740:	orl %ecx, $0x300<UINT32>
0x00470746:	jmp 0x00470752
0x00470752:	andl %esi, $0x300<UINT32>
0x00470758:	je 12
0x0047075a:	cmpl %esi, %edi
0x0047075c:	jne 0x0047076c
0x0047076c:	movl %edx, $0x1000<UINT32>
0x00470771:	testw %dx, %ax
0x00470774:	je 6
0x00470776:	orl %ecx, $0x40000<UINT32>
0x0047077c:	movl %edi, 0xc(%ebp)
0x0047077f:	movl %esi, %edi
0x00470781:	movl %eax, 0x8(%ebp)
0x00470784:	notl %esi
0x00470786:	andl %esi, %ecx
0x00470788:	andl %eax, %edi
0x0047078a:	orl %esi, %eax
0x0047078c:	cmpl %esi, %ecx
0x0047078e:	je 166
0x00470794:	pushl %esi
0x00470795:	call 0x004709d9
0x004709d9:	movl %edi, %edi
0x004709db:	pushl %ebp
0x004709dc:	movl %ebp, %esp
0x004709de:	movl %ecx, 0x8(%ebp)
0x004709e1:	xorl %eax, %eax
0x004709e3:	testb %cl, $0x10<UINT8>
0x004709e6:	je 0x004709e9
0x004709e9:	testb %cl, $0x8<UINT8>
0x004709ec:	je 0x004709f1
0x004709f1:	testb %cl, $0x4<UINT8>
0x004709f4:	je 3
0x004709f6:	orl %eax, $0x8<UINT8>
0x004709f9:	testb %cl, $0x2<UINT8>
0x004709fc:	je 3
0x004709fe:	orl %eax, $0x10<UINT8>
0x00470a01:	testb %cl, $0x1<UINT8>
0x00470a04:	je 0x00470a09
0x00470a09:	testl %ecx, $0x80000<UINT32>
0x00470a0f:	je 0x00470a14
0x00470a14:	pushl %esi
0x00470a15:	movl %edx, %ecx
0x00470a17:	movl %esi, $0x300<UINT32>
0x00470a1c:	pushl %edi
0x00470a1d:	movl %edi, $0x200<UINT32>
0x00470a22:	andl %edx, %esi
0x00470a24:	je 35
0x00470a26:	cmpl %edx, $0x100<UINT32>
0x00470a2c:	je 22
0x00470a2e:	cmpl %edx, %edi
0x00470a30:	je 11
0x00470a32:	cmpl %edx, %esi
0x00470a34:	jne 19
0x00470a36:	orl %eax, $0xc00<UINT32>
0x00470a3b:	jmp 0x00470a49
0x00470a49:	movl %edx, %ecx
0x00470a4b:	andl %edx, $0x30000<UINT32>
0x00470a51:	je 12
0x00470a53:	cmpl %edx, $0x10000<UINT32>
0x00470a59:	jne 6
0x00470a5b:	orl %eax, %edi
0x00470a5d:	jmp 0x00470a61
0x00470a61:	popl %edi
0x00470a62:	popl %esi
0x00470a63:	testl %ecx, $0x40000<UINT32>
0x00470a69:	je 5
0x00470a6b:	orl %eax, $0x1000<UINT32>
0x00470a70:	popl %ebp
0x00470a71:	ret

0x0047079a:	popl %ecx
0x0047079b:	movw -4(%ebp), %ax
0x0047079f:	fldcw -4(%ebp)
0x004707a2:	fwait
0x004707a3:	fnstcw -4(%ebp)
0x004707a6:	movw %ax, -4(%ebp)
0x004707aa:	xorl %esi, %esi
0x004707ac:	testb %al, $0x1<UINT8>
0x004707ae:	je 0x004707b3
0x004707b3:	testb %al, $0x4<UINT8>
0x004707b5:	je 0x004707ba
0x004707ba:	testb %al, $0x8<UINT8>
0x004707bc:	je 3
0x004707be:	orl %esi, $0x4<UINT8>
0x004707c1:	testb %al, $0x10<UINT8>
0x004707c3:	je 3
0x004707c5:	orl %esi, $0x2<UINT8>
0x004707c8:	testb %al, $0x20<UINT8>
0x004707ca:	je 0x004707cf
0x004707cf:	testb %al, $0x2<UINT8>
0x004707d1:	je 0x004707d9
0x004707d9:	movzwl %edx, %ax
0x004707dc:	movl %ecx, %edx
0x004707de:	andl %ecx, %ebx
0x004707e0:	je 42
0x004707e2:	cmpl %ecx, $0x400<UINT32>
0x004707e8:	je 28
0x004707ea:	cmpl %ecx, $0x800<UINT32>
0x004707f0:	je 12
0x004707f2:	cmpl %ecx, %ebx
0x004707f4:	jne 22
0x004707f6:	orl %esi, $0x300<UINT32>
0x004707fc:	jmp 0x0047080c
0x0047080c:	andl %edx, $0x300<UINT32>
0x00470812:	je 16
0x00470814:	cmpl %edx, $0x200<UINT32>
0x0047081a:	jne 14
0x0047081c:	orl %esi, $0x10000<UINT32>
0x00470822:	jmp 0x0047082a
0x0047082a:	movl %edx, $0x1000<UINT32>
0x0047082f:	testw %dx, %ax
0x00470832:	je 6
0x00470834:	orl %esi, $0x40000<UINT32>
0x0047083a:	cmpl 0x41cc40, $0x1<UINT8>
0x00470841:	jl 393
0x00470847:	andl %edi, $0x308031f<UINT32>
0x0047084d:	stmxcsr -16(%ebp)
0x00470851:	movl %eax, -16(%ebp)
0x00470854:	xorl %ecx, %ecx
0x00470856:	testb %al, %al
0x00470858:	jns 0x0047085d
0x0047085d:	testl %eax, $0x200<UINT32>
0x00470862:	je 3
0x00470864:	orl %ecx, $0x8<UINT8>
0x00470867:	testl %eax, $0x400<UINT32>
0x0047086c:	je 0x00470871
0x00470871:	testl %eax, $0x800<UINT32>
0x00470876:	je 3
0x00470878:	orl %ecx, $0x2<UINT8>
0x0047087b:	testl %edx, %eax
0x0047087d:	je 0x00470882
0x00470882:	testl %eax, $0x100<UINT32>
0x00470887:	je 6
0x00470889:	orl %ecx, $0x80000<UINT32>
0x0047088f:	movl %edx, %eax
0x00470891:	movl %ebx, $0x6000<UINT32>
0x00470896:	andl %edx, %ebx
0x00470898:	je 42
0x0047089a:	cmpl %edx, $0x2000<UINT32>
0x004708a0:	je 0x004708be
0x004708be:	orl %ecx, $0x100<UINT32>
0x004708c4:	pushl $0x40<UINT8>
0x004708c6:	andl %eax, $0x8040<UINT32>
0x004708cb:	popl %ebx
0x004708cc:	subl %eax, %ebx
0x004708ce:	je 0x004708eb
0x004708eb:	orl %ecx, $0x2000000<UINT32>
0x004708f1:	movl %eax, %edi
0x004708f3:	andl %edi, 0x8(%ebp)
0x004708f6:	notl %eax
0x004708f8:	andl %eax, %ecx
0x004708fa:	orl %eax, %edi
0x004708fc:	cmpl %eax, %ecx
0x004708fe:	je 0x004709b9
0x004709b9:	movl %eax, %ecx
0x004709bb:	orl %ecx, %esi
0x004709bd:	xorl %eax, %esi
0x004709bf:	testl %eax, $0x8031f<UINT32>
0x004709c4:	je 6
0x004709c6:	orl %ecx, $0x80000000<UINT32>
0x004709cc:	movl %eax, %ecx
0x004709ce:	jmp 0x004709d2
0x004709d2:	popl %edi
0x004709d3:	popl %esi
0x004709d4:	popl %ebx
0x004709d5:	movl %esp, %ebp
0x004709d7:	popl %ebp
0x004709d8:	ret

0x004678ef:	popl %ecx
0x004678f0:	popl %ecx
0x004678f1:	xorl %eax, %eax
0x004678f3:	popl %esi
0x004678f4:	popl %ebp
0x004678f5:	ret

0x0045c33e:	addl %esp, $0xc<UINT8>
0x0045c341:	testl %eax, %eax
0x0045c343:	jne 1
0x0045c345:	ret

0x0045be3a:	call 0x0045c311
0x0045be3f:	pushl %eax
0x0045be40:	call 0x0046753c
0x0046753c:	movl %edi, %edi
0x0046753e:	pushl %ebp
0x0046753f:	movl %ebp, %esp
0x00467541:	pushl %esi
0x00467542:	call 0x0046ceaf
0x00467547:	movl %edx, 0x8(%ebp)
0x0046754a:	movl %esi, %eax
0x0046754c:	pushl $0x0<UINT8>
0x0046754e:	popl %eax
0x0046754f:	movl %ecx, 0x350(%esi)
0x00467555:	testb %cl, $0x2<UINT8>
0x00467558:	sete %al
0x0046755b:	incl %eax
0x0046755c:	cmpl %edx, $0xffffffff<UINT8>
0x0046755f:	je 51
0x00467561:	testl %edx, %edx
0x00467563:	je 0x0046759b
0x0046759b:	popl %esi
0x0046759c:	popl %ebp
0x0046759d:	ret

0x0045be45:	popl %ecx
0x0045be46:	call 0x0045c32a
0x0045c32a:	movb %al, $0x1<UINT8>
0x0045c32c:	ret

0x0045be4b:	testb %al, %al
0x0045be4d:	je 5
0x0045be4f:	call 0x00468018
0x00468018:	jmp 0x00467d5f
0x00467d5f:	cmpl 0x41cd9c, $0x0<UINT8>
0x00467d66:	je 0x00467d6b
0x00467d6b:	pushl %esi
0x00467d6c:	pushl %edi
0x00467d6d:	call 0x0046d6df
0x00467d72:	call 0x00470b21
0x00470b21:	movl %edi, %edi
0x00470b23:	pushl %ebp
0x00470b24:	movl %ebp, %esp
0x00470b26:	pushl %ecx
0x00470b27:	pushl %ebx
0x00470b28:	pushl %esi
0x00470b29:	pushl %edi
0x00470b2a:	call GetEnvironmentStringsW@KERNEL32.DLL
GetEnvironmentStringsW@KERNEL32.DLL: API Node	
0x00470b30:	movl %esi, %eax
0x00470b32:	xorl %edi, %edi
0x00470b34:	testl %esi, %esi
0x00470b36:	je 86
0x00470b38:	pushl %esi
0x00470b39:	call 0x00470aea
0x00470aea:	movl %edi, %edi
0x00470aec:	pushl %ebp
0x00470aed:	movl %ebp, %esp
0x00470aef:	movl %edx, 0x8(%ebp)
0x00470af2:	pushl %edi
0x00470af3:	xorl %edi, %edi
0x00470af5:	cmpw (%edx), %di
0x00470af8:	je 33
0x00470afa:	pushl %esi
0x00470afb:	movl %ecx, %edx
0x00470afd:	leal %esi, 0x2(%ecx)
0x00470b00:	movw %ax, (%ecx)
0x00470b03:	addl %ecx, $0x2<UINT8>
0x00470b06:	cmpw %ax, %di
0x00470b09:	jne 0x00470b00
0x00470b0b:	subl %ecx, %esi
0x00470b0d:	sarl %ecx
0x00470b0f:	leal %edx, (%edx,%ecx,2)
0x00470b12:	addl %edx, $0x2<UINT8>
0x00470b15:	cmpw (%edx), %di
0x00470b18:	jne 0x00470afb
0x00470b1a:	popl %esi
0x00470b1b:	leal %eax, 0x2(%edx)
0x00470b1e:	popl %edi
0x00470b1f:	popl %ebp
0x00470b20:	ret

0x00470b3e:	popl %ecx
0x00470b3f:	pushl %edi
0x00470b40:	pushl %edi
0x00470b41:	pushl %edi
0x00470b42:	movl %ebx, %eax
0x00470b44:	pushl %edi
0x00470b45:	subl %ebx, %esi
0x00470b47:	sarl %ebx
0x00470b49:	pushl %ebx
0x00470b4a:	pushl %esi
0x00470b4b:	pushl %edi
0x00470b4c:	pushl %edi
0x00470b4d:	call WideCharToMultiByte@KERNEL32.DLL
WideCharToMultiByte@KERNEL32.DLL: API Node	
0x00470b53:	movl -4(%ebp), %eax
0x00470b56:	testl %eax, %eax
0x00470b58:	je 52
0x00470b5a:	pushl %eax
0x00470b5b:	call 0x0046bb92
0x00470b60:	movl %edi, %eax
0x00470b62:	popl %ecx
0x00470b63:	testl %edi, %edi
0x00470b65:	je 28
0x00470b67:	xorl %eax, %eax
0x00470b69:	pushl %eax
0x00470b6a:	pushl %eax
0x00470b6b:	pushl -4(%ebp)
0x00470b6e:	pushl %edi
0x00470b6f:	pushl %ebx
0x00470b70:	pushl %esi
0x00470b71:	pushl %eax
0x00470b72:	pushl %eax
0x00470b73:	call WideCharToMultiByte@KERNEL32.DLL
0x00470b79:	testl %eax, %eax
0x00470b7b:	je 6
0x00470b7d:	movl %ebx, %edi
0x00470b7f:	xorl %edi, %edi
0x00470b81:	jmp 0x00470b85
0x00470b85:	pushl %edi
0x00470b86:	call 0x0046bb58
0x00470b8b:	popl %ecx
0x00470b8c:	jmp 0x00470b90
0x00470b90:	testl %esi, %esi
0x00470b92:	je 7
0x00470b94:	pushl %esi
0x00470b95:	call FreeEnvironmentStringsW@KERNEL32.DLL
FreeEnvironmentStringsW@KERNEL32.DLL: API Node	
0x00470b9b:	popl %edi
0x00470b9c:	popl %esi
0x00470b9d:	movl %eax, %ebx
0x00470b9f:	popl %ebx
0x00470ba0:	movl %esp, %ebp
0x00470ba2:	popl %ebp
0x00470ba3:	ret

0x00467d77:	movl %esi, %eax
0x00467d79:	testl %esi, %esi
0x00467d7b:	jne 0x00467d82
0x00467d82:	pushl %esi
0x00467d83:	call 0x00467db8
0x00467db8:	movl %edi, %edi
0x00467dba:	pushl %ebp
0x00467dbb:	movl %ebp, %esp
0x00467dbd:	pushl %ecx
0x00467dbe:	pushl %ecx
0x00467dbf:	pushl %ebx
0x00467dc0:	pushl %esi
0x00467dc1:	pushl %edi
0x00467dc2:	movl %edi, 0x8(%ebp)
0x00467dc5:	xorl %edx, %edx
0x00467dc7:	movl %esi, %edi
0x00467dc9:	movb %al, (%edi)
0x00467dcb:	jmp 0x00467de5
0x00467de5:	testb %al, %al
0x00467de7:	jne 0x00467dcd
0x00467dcd:	cmpb %al, $0x3d<UINT8>
0x00467dcf:	je 0x00467dd2
0x00467dd2:	movl %ecx, %esi
0x00467dd4:	leal %ebx, 0x1(%ecx)
0x00467dd7:	movb %al, (%ecx)
0x00467dd9:	incl %ecx
0x00467dda:	testb %al, %al
0x00467ddc:	jne 0x00467dd7
0x00467dde:	subl %ecx, %ebx
0x00467de0:	incl %esi
0x00467de1:	addl %esi, %ecx
0x00467de3:	movb %al, (%esi)
0x00467de9:	leal %eax, 0x1(%edx)
0x00467dec:	pushl $0x4<UINT8>
0x00467dee:	pushl %eax
0x00467def:	call 0x0046e261
0x00467df4:	movl %ebx, %eax
0x00467df6:	popl %ecx
0x00467df7:	popl %ecx
0x00467df8:	testl %ebx, %ebx
0x00467dfa:	je 109
0x00467dfc:	movl -4(%ebp), %ebx
0x00467dff:	jmp 0x00467e53
0x00467e53:	cmpb (%edi), $0x0<UINT8>
0x00467e56:	jne 0x00467e01
0x00467e01:	movl %ecx, %edi
0x00467e03:	leal %edx, 0x1(%ecx)
0x00467e06:	movb %al, (%ecx)
0x00467e08:	incl %ecx
0x00467e09:	testb %al, %al
0x00467e0b:	jne 0x00467e06
0x00467e0d:	subl %ecx, %edx
0x00467e0f:	cmpb (%edi), $0x3d<UINT8>
0x00467e12:	leal %eax, 0x1(%ecx)
0x00467e15:	movl -8(%ebp), %eax
0x00467e18:	je 0x00467e51
0x00467e51:	addl %edi, %eax
0x00467e58:	jmp 0x00467e6b
0x00467e6b:	pushl $0x0<UINT8>
0x00467e6d:	call 0x0046bb58
0x00467e72:	popl %ecx
0x00467e73:	popl %edi
0x00467e74:	popl %esi
0x00467e75:	movl %eax, %ebx
0x00467e77:	popl %ebx
0x00467e78:	movl %esp, %ebp
0x00467e7a:	popl %ebp
0x00467e7b:	ret

0x00467d88:	popl %ecx
0x00467d89:	testl %eax, %eax
0x00467d8b:	jne 0x00467d92
0x00467d92:	pushl %eax
0x00467d93:	movl %ecx, $0x41cd9c<UINT32>
0x00467d98:	movl 0x41cda8, %eax
0x00467d9d:	call 0x0045f1e6
0x00467da2:	xorl %edi, %edi
0x00467da4:	pushl $0x0<UINT8>
0x00467da6:	call 0x0046bb58
0x00467dab:	popl %ecx
0x00467dac:	pushl %esi
0x00467dad:	call 0x0046bb58
0x0046bb63:	pushl 0x8(%ebp)
0x0046bb66:	pushl $0x0<UINT8>
0x0046bb68:	pushl 0x41d084
0x0046bb6e:	call HeapFree@KERNEL32.DLL
HeapFree@KERNEL32.DLL: API Node	
0x0046bb74:	testl %eax, %eax
0x0046bb76:	jne 0x0046bb90
0x00467db2:	popl %ecx
0x00467db3:	movl %eax, %edi
0x00467db5:	popl %edi
0x00467db6:	popl %esi
0x00467db7:	ret

0x0045be54:	call 0x0045c311
0x0045be59:	xorl %eax, %eax
0x0045be5b:	ret

0x004680a0:	testl %eax, %eax
0x004680a2:	jne 10
0x0045be64:	call 0x0045c34f
0x0045c34f:	call 0x0042ded4
0x0042ded4:	movl %eax, $0x41a038<UINT32>
0x0042ded9:	ret

0x0045c354:	movl %ecx, 0x4(%eax)
0x0045c357:	orl (%eax), $0x4<UINT8>
0x0045c35a:	movl 0x4(%eax), %ecx
0x0045c35d:	call 0x00435100
0x00435100:	movl %eax, $0x41a060<UINT32>
0x00435105:	ret

0x0045c362:	movl %ecx, 0x4(%eax)
0x0045c365:	orl (%eax), $0x2<UINT8>
0x0045c368:	movl 0x4(%eax), %ecx
0x0045c36b:	ret

0x0045be69:	xorl %eax, %eax
0x0045be6b:	ret

0x0045f23b:	movl %eax, 0x41cc50
0x0045f240:	pushl %esi
0x0045f241:	pushl $0x3<UINT8>
0x0045f243:	popl %esi
0x0045f244:	testl %eax, %eax
0x0045f246:	jne 7
0x0045f248:	movl %eax, $0x200<UINT32>
0x0045f24d:	jmp 0x0045f255
0x0045f255:	movl 0x41cc50, %eax
0x0045f25a:	pushl $0x4<UINT8>
0x0045f25c:	pushl %eax
0x0045f25d:	call 0x0046e261
0x0045f262:	pushl $0x0<UINT8>
0x0045f264:	movl 0x41cc54, %eax
0x0045f269:	call 0x0046bb58
0x0045f26e:	addl %esp, $0xc<UINT8>
0x0045f271:	cmpl 0x41cc54, $0x0<UINT8>
0x0045f278:	jne 0x0045f2a5
0x0045f2a5:	pushl %edi
0x0045f2a6:	xorl %edi, %edi
0x0045f2a8:	movl %esi, $0x41e1a0<UINT32>
0x0045f2ad:	pushl $0x0<UINT8>
0x0045f2af:	pushl $0xfa0<UINT32>
0x0045f2b4:	leal %eax, 0x20(%esi)
0x0045f2b7:	pushl %eax
0x0045f2b8:	call 0x0046c6d2
0x0045f2bd:	movl %eax, 0x41cc54
0x0045f2c2:	movl %edx, %edi
0x0045f2c4:	sarl %edx, $0x6<UINT8>
0x0045f2c7:	movl (%eax,%edi,4), %esi
0x0045f2ca:	movl %eax, %edi
0x0045f2cc:	andl %eax, $0x3f<UINT8>
0x0045f2cf:	imull %ecx, %eax, $0x30<UINT8>
0x0045f2d2:	movl %eax, 0x41d088(,%edx,4)
0x0045f2d9:	movl %eax, 0x18(%eax,%ecx)
0x0045f2dd:	cmpl %eax, $0xffffffff<UINT8>
0x0045f2e0:	je 9
0x0045f2e2:	cmpl %eax, $0xfffffffe<UINT8>
0x0045f2e5:	je 4
0x0045f2e7:	testl %eax, %eax
0x0045f2e9:	jne 0x0045f2f2
0x0045f2f2:	addl %esi, $0x38<UINT8>
0x0045f2f5:	incl %edi
0x0045f2f6:	cmpl %esi, $0x41e248<UINT32>
0x0045f2fc:	jne 0x0045f2ad
0x0045f2fe:	popl %edi
0x0045f2ff:	xorl %eax, %eax
0x0045f301:	popl %esi
0x0045f302:	ret

0x0047486f:	call 0x0046d6df
0x00474874:	xorl %ecx, %ecx
0x00474876:	testb %al, %al
0x00474878:	sete %cl
0x0047487b:	movl %eax, %ecx
0x0047487d:	ret

0x00478207:	pushl $0x7080<UINT32>
0x0047820c:	movl %ecx, $0x41d2fc<UINT32>
0x00478211:	call 0x0045f1e6
0x00478216:	pushl $0x1<UINT8>
0x00478218:	movl %ecx, $0x41d300<UINT32>
0x0047821d:	call 0x0045f1e6
0x00478222:	pushl $0xfffff1f0<UINT32>
0x00478227:	movl %ecx, $0x41d304<UINT32>
0x0047822c:	call 0x0045f1e6
0x00478231:	movl 0x41d308, $0x41eaa8<UINT32>
0x0047823b:	xorl %eax, %eax
0x0047823d:	ret

0x00478e94:	pushl $0xa<UINT8>
0x00478e96:	call 0x0047a9f2
0x00478e9b:	movl 0x41d3cc, %eax
0x00478ea0:	xorl %eax, %eax
0x00478ea2:	ret

0x004680ac:	xorl %eax, %eax
0x004680ae:	movl %ecx, -4(%ebp)
0x004680b1:	popl %edi
0x004680b2:	xorl %ecx, %ebp
0x004680b4:	popl %esi
0x004680b5:	call 0x0045bc59
0x004680ba:	movl %esp, %ebp
0x004680bc:	popl %ebp
0x004680bd:	ret

0x0045bed3:	popl %ecx
0x0045bed4:	popl %ecx
0x0045bed5:	testl %eax, %eax
0x0045bed7:	je 0x0045beea
0x0045beea:	pushl $0x402008<UINT32>
0x0045beef:	pushl $0x402000<UINT32>
0x0045bef4:	call 0x0046801d
0x0046801d:	movl %edi, %edi
0x0046801f:	pushl %ebp
0x00468020:	movl %ebp, %esp
0x00468022:	pushl %ecx
0x00468023:	pushl %ecx
0x00468024:	movl %eax, 0x41e17c
0x00468029:	xorl %eax, %ebp
0x0046802b:	movl -4(%ebp), %eax
0x0046802e:	movl %eax, 0xc(%ebp)
0x00468031:	pushl %ebx
0x00468032:	pushl %esi
0x00468033:	movl %esi, 0x8(%ebp)
0x00468036:	subl %eax, %esi
0x00468038:	addl %eax, $0x3<UINT8>
0x0046803b:	pushl %edi
0x0046803c:	xorl %edi, %edi
0x0046803e:	shrl %eax, $0x2<UINT8>
0x00468041:	cmpl 0xc(%ebp), %esi
0x00468044:	sbbl %ebx, %ebx
0x00468046:	notl %ebx
0x00468048:	andl %ebx, %eax
0x0046804a:	je 28
0x0046804c:	movl %eax, (%esi)
0x0046804e:	movl -8(%ebp), %eax
0x00468051:	testl %eax, %eax
0x00468053:	je 0x00468060
0x00468060:	addl %esi, $0x4<UINT8>
0x00468063:	incl %edi
0x00468064:	cmpl %edi, %ebx
0x00468066:	jne 0x0046804c
0x00468055:	movl %ecx, %eax
0x00468057:	call 0x0045c34e
0x0046805d:	call 0x0045be6c
0x0045be6c:	call 0x0045c516
0x0045c516:	pushl $0x45c522<UINT32>
0x0045c51b:	call SetUnhandledExceptionFilter@KERNEL32.DLL
SetUnhandledExceptionFilter@KERNEL32.DLL: API Node	
0x0045c521:	ret

0x0045be71:	call 0x0045c311
0x0045be76:	pushl %eax
0x0045be77:	call 0x00468386
0x00468386:	movl %edi, %edi
0x00468388:	pushl %ebp
0x00468389:	movl %ebp, %esp
0x0046838b:	movl %eax, 0x8(%ebp)
0x0046838e:	testl %eax, %eax
0x00468390:	je 0x004683ac
0x004683ac:	movl %ecx, $0x41cdb0<UINT32>
0x004683b1:	xchgl (%ecx), %eax
0x004683b3:	popl %ebp
0x004683b4:	ret

0x0045be7c:	popl %ecx
0x0045be7d:	ret

0x00468068:	movl %ecx, -4(%ebp)
0x0046806b:	popl %edi
0x0046806c:	popl %esi
0x0046806d:	xorl %ecx, %ebp
0x0046806f:	popl %ebx
0x00468070:	call 0x0045bc59
0x00468075:	movl %esp, %ebp
0x00468077:	popl %ebp
0x00468078:	ret

0x0045bef9:	popl %ecx
0x0045befa:	popl %ecx
0x0045befb:	movl 0x41cc04, $0x2<UINT32>
0x0045bf05:	jmp 0x0045bf0c
0x0045bf0c:	pushl -36(%ebp)
0x0045bf0f:	call 0x0045c1e0
0x0045c1e0:	pushl %ebp
0x0045c1e1:	movl %ebp, %esp
0x0045c1e3:	call 0x0045c7c5
0x0045c1e8:	testl %eax, %eax
0x0045c1ea:	je 0x0045c1fb
0x0045c1fb:	popl %ebp
0x0045c1fc:	ret

0x0045bf14:	popl %ecx
0x0045bf15:	call 0x0045c378
0x0045c378:	movl %eax, $0x41cc34<UINT32>
0x0045c37d:	ret

0x0045bf1a:	movl %esi, %eax
0x0045bf1c:	xorl %edi, %edi
0x0045bf1e:	cmpl (%esi), %edi
0x0045bf20:	je 0x0045bf3c
0x0045bf3c:	call 0x0045c37e
0x0045c37e:	movl %eax, $0x41cc38<UINT32>
0x0045c383:	ret

0x0045bf41:	movl %esi, %eax
0x0045bf43:	cmpl (%esi), %edi
0x0045bf45:	je 0x0045bf5a
0x0045bf5a:	call 0x0045c49f
0x0045c49f:	pushl %ebp
0x0045c4a0:	movl %ebp, %esp
0x0045c4a2:	subl %esp, $0x44<UINT8>
0x0045c4a5:	pushl $0x44<UINT8>
0x0045c4a7:	leal %eax, -68(%ebp)
0x0045c4aa:	pushl $0x0<UINT8>
0x0045c4ac:	pushl %eax
0x0045c4ad:	call 0x0045ed00
0x0045c4b2:	addl %esp, $0xc<UINT8>
0x0045c4b5:	leal %eax, -68(%ebp)
0x0045c4b8:	pushl %eax
0x0045c4b9:	call GetStartupInfoW@KERNEL32.DLL
0x0045c4bf:	testb -24(%ebp), $0x1<UINT8>
0x0045c4c3:	je 0x0045c4cb
0x0045c4cb:	pushl $0xa<UINT8>
0x0045c4cd:	popl %eax
0x0045c4ce:	movl %esp, %ebp
0x0045c4d0:	popl %ebp
0x0045c4d1:	ret

0x0045bf5f:	movzwl %eax, %ax
0x0045bf62:	pushl %eax
0x0045bf63:	call 0x00467cdd
0x00467cdd:	movl %edi, %edi
0x00467cdf:	pushl %ebx
0x00467ce0:	pushl %esi
0x00467ce1:	call 0x0046d6df
0x00467ce6:	movl %esi, 0x41d298
0x00467cec:	testl %esi, %esi
0x00467cee:	jne 0x00467cf5
0x00467cf5:	xorb %bl, %bl
0x00467cf7:	movb %al, (%esi)
0x00467cf9:	cmpb %al, $0x20<UINT8>
0x00467cfb:	jg 0x00467d05
0x00467d05:	cmpb %al, $0x22<UINT8>
0x00467d07:	jne 5
0x00467d09:	testb %bl, %bl
0x00467d0b:	sete %bl
0x00467d0e:	movsbl %eax, %al
0x00467d11:	pushl %eax
0x00467d12:	call 0x00470536
0x00467d17:	popl %ecx
0x00467d18:	testl %eax, %eax
0x00467d1a:	je 0x00467d1d
0x00467d1d:	incl %esi
0x00467d1e:	jmp 0x00467cf7
0x00467cfd:	testb %al, %al
0x00467cff:	je 0x00467d2b
0x00467d2b:	movl %eax, %esi
0x00467d2d:	popl %esi
0x00467d2e:	popl %ebx
0x00467d2f:	ret

0x0045bf68:	pushl %eax
0x0045bf69:	pushl %edi
0x0045bf6a:	pushl $0x400000<UINT32>
0x0045bf6f:	call 0x0044c519
0x0044c519:	pushl %ebp
0x0044c51a:	pushl %ebx
0x0044c51b:	pushl %edi
0x0044c51c:	pushl %esi
0x0044c51d:	subl %esp, $0x44<UINT8>
0x0044c520:	movl %eax, 0x41e17c
0x0044c525:	movl %ebp, 0x58(%esp)
0x0044c529:	movl 0x40(%esp), %eax
0x0044c52d:	call 0x004565f4
0x004565f4:	cmpl 0x41c0a0, $0x0<UINT8>
0x004565fb:	je 0x00456605
0x00456605:	pushl $0x4101ce<UINT32>
0x0045660a:	call 0x0045657f
0x0045657f:	pushl %ebx
0x00456580:	pushl %edi
0x00456581:	pushl %esi
0x00456582:	movl %eax, 0x41c0a8
0x00456587:	movl %esi, 0x10(%esp)
0x0045658b:	testl %eax, %eax
0x0045658d:	jne 58
0x0045658f:	movl %edi, 0x47c934
0x00456595:	xorl %eax, %eax
0x00456597:	xorl %ebx, %ebx
0x00456599:	leal %ecx, (%ebx,%ebx,2)
0x0045659c:	movl %ebx, %ecx
0x0045659e:	shrl %ebx, $0x1f<UINT8>
0x004565a1:	addl %ebx, %ecx
0x004565a3:	sarl %ebx
0x004565a5:	addl %ebx, $0x200<UINT32>
0x004565ab:	pushl $0x1<UINT8>
0x004565ad:	pushl %ebx
0x004565ae:	pushl %eax
0x004565af:	call 0x0043218b
0x0043218b:	pushl %esi
0x0043218c:	subl %esp, $0xcc<UINT32>
0x00432192:	movl %eax, 0x41e17c
0x00432197:	movl %ecx, 0xdc(%esp)
0x0043219e:	movl %esi, 0xd8(%esp)
0x004321a5:	xorl %edx, %edx
0x004321a7:	movl 0xc8(%esp), %eax
0x004321ae:	movl %eax, $0x7fffffff<UINT32>
0x004321b3:	divl %eax, %ecx
0x004321b5:	cmpl %eax, %esi
0x004321b7:	jb 41
0x004321b9:	movl %eax, 0xd4(%esp)
0x004321c0:	imull %ecx, %esi
0x004321c3:	testl %eax, %eax
0x004321c5:	je 0x004321d3
0x004321d3:	pushl %ecx
0x004321d4:	call 0x0046ac26
0x0046ac26:	movl %edi, %edi
0x0046ac28:	pushl %ebp
0x0046ac29:	movl %ebp, %esp
0x0046ac2b:	popl %ebp
0x0046ac2c:	jmp 0x0046bb92
0x004321d9:	addl %esp, $0x4<UINT8>
0x004321dc:	movl %esi, %eax
0x004321de:	testl %esi, %esi
0x004321e0:	jne 0x00432204
0x00432204:	movl %ecx, 0xc8(%esp)
0x0043220b:	call 0x0045bc59
0x00432210:	movl %eax, %esi
0x00432212:	addl %esp, $0xcc<UINT32>
0x00432218:	popl %esi
0x00432219:	ret

0x004565b4:	addl %esp, $0xc<UINT8>
0x004565b7:	movl 0x41c0a8, %eax
0x004565bc:	pushl %ebx
0x004565bd:	pushl %eax
0x004565be:	call GetSystemDirectoryA@KERNEL32.DLL
GetSystemDirectoryA@KERNEL32.DLL: API Node	
0x004565c0:	cmpl %eax, %ebx
0x004565c2:	movl %eax, 0x41c0a8
0x004565c7:	jnl -48
0x004565c9:	pushl $0x0<UINT8>
0x004565cb:	pushl %esi
0x004565cc:	pushl $0x410459<UINT32>
0x004565d1:	pushl %eax
0x004565d2:	call 0x00432347
0x00432347:	pushl %ebp
0x00432348:	pushl %ebx
0x00432349:	pushl %edi
0x0043234a:	pushl %esi
0x0043234b:	subl %esp, $0x8<UINT8>
0x0043234e:	movl %eax, 0x41e17c
0x00432353:	movl %ebx, 0x1c(%esp)
0x00432357:	movl 0x4(%esp), %eax
0x0043235b:	pushl %ebx
0x0043235c:	call 0x0046b400
0x0046b400:	movl %ecx, 0x4(%esp)
0x0046b404:	testl %ecx, $0x3<UINT32>
0x0046b40a:	je 0x0046b430
0x0046b430:	movl %eax, (%ecx)
0x0046b432:	movl %edx, $0x7efefeff<UINT32>
0x0046b437:	addl %edx, %eax
0x0046b439:	xorl %eax, $0xffffffff<UINT8>
0x0046b43c:	xorl %eax, %edx
0x0046b43e:	addl %ecx, $0x4<UINT8>
0x0046b441:	testl %eax, $0x81010100<UINT32>
0x0046b446:	je 0x0046b430
0x0046b448:	movl %eax, -4(%ecx)
0x0046b44b:	testb %al, %al
0x0046b44d:	je 0x0046b481
0x0046b44f:	testb %ah, %ah
0x0046b451:	je 36
0x0046b453:	testl %eax, $0xff0000<UINT32>
0x0046b458:	je 0x0046b46d
0x0046b45a:	testl %eax, $0xff000000<UINT32>
0x0046b45f:	je 0x0046b463
0x0046b463:	leal %eax, -1(%ecx)
0x0046b466:	movl %ecx, 0x4(%esp)
0x0046b46a:	subl %eax, %ecx
0x0046b46c:	ret

0x00432361:	addl %esp, $0x4<UINT8>
0x00432364:	leal %edi, 0x24(%esp)
0x00432368:	movl %esi, %eax
0x0043236a:	movl (%esp), %edi
0x0043236d:	movl %eax, -4(%edi)
0x00432370:	testl %eax, %eax
0x00432372:	je 31
0x00432374:	leal %ebp, 0x20(%esp)
0x00432378:	addl %ebp, $0x8<UINT8>
0x0043237b:	pushl %eax
0x0043237c:	call 0x0046b400
0x0046b40c:	movb %al, (%ecx)
0x0046b40e:	addl %ecx, $0x1<UINT8>
0x0046b411:	testb %al, %al
0x0046b413:	je 0x0046b463
0x0046b415:	testl %ecx, $0x3<UINT32>
0x0046b41b:	jne 0x0046b40c
0x00432381:	addl %esp, $0x4<UINT8>
0x00432384:	movl (%esp), %ebp
0x00432387:	addl %esi, %eax
0x00432389:	movl %eax, -4(%ebp)
0x0043238c:	addl %ebp, $0x4<UINT8>
0x0043238f:	testl %eax, %eax
0x00432391:	jne 0x0043237b
0x0046b41d:	addl %eax, $0x0<UINT32>
0x0046b422:	leal %esp, (%esp)
0x0046b429:	leal %esp, (%esp)
0x0046b46d:	leal %eax, -2(%ecx)
0x0046b470:	movl %ecx, 0x4(%esp)
0x0046b474:	subl %eax, %ecx
0x0046b476:	ret

0x00432393:	incl %esi
0x00432394:	xorl %eax, %eax
0x00432396:	incl %eax
0x00432397:	pushl %eax
0x00432398:	pushl %esi
0x00432399:	call 0x004320b7
0x004320b7:	pushl %esi
0x004320b8:	subl %esp, $0xcc<UINT32>
0x004320be:	movl %eax, 0x41e17c
0x004320c3:	movl %ecx, 0xd8(%esp)
0x004320ca:	movl %esi, 0xd4(%esp)
0x004320d1:	xorl %edx, %edx
0x004320d3:	movl 0xc8(%esp), %eax
0x004320da:	movl %eax, $0x7fffffff<UINT32>
0x004320df:	divl %eax, %ecx
0x004320e1:	cmpl %eax, %esi
0x004320e3:	jb 26
0x004320e5:	imull %ecx, %esi
0x004320e8:	xorl %eax, %eax
0x004320ea:	incl %eax
0x004320eb:	testl %ecx, %ecx
0x004320ed:	cmovnel %eax, %ecx
0x004320f0:	pushl %eax
0x004320f1:	call 0x0046ac26
0x004320f6:	addl %esp, $0x4<UINT8>
0x004320f9:	movl %esi, %eax
0x004320fb:	testl %esi, %esi
0x004320fd:	jne 0x00432121
0x00432121:	movl %ecx, 0xc8(%esp)
0x00432128:	call 0x0045bc59
0x0043212d:	movl %eax, %esi
0x0043212f:	addl %esp, $0xcc<UINT32>
0x00432135:	popl %esi
0x00432136:	ret

0x0043239e:	addl %esp, $0x8<UINT8>
0x004323a1:	movl %esi, %eax
0x004323a3:	pushl %ebx
0x004323a4:	pushl %esi
0x004323a5:	call 0x0046b0d0
0x0046b0d0:	pushl %edi
0x0046b0d1:	movl %edi, 0x8(%esp)
0x0046b0d5:	jmp 0x0046b145
0x0046b145:	movl %ecx, 0xc(%esp)
0x0046b149:	testl %ecx, $0x3<UINT32>
0x0046b14f:	je 0x0046b16e
0x0046b16e:	movl %edx, $0x7efefeff<UINT32>
0x0046b173:	movl %eax, (%ecx)
0x0046b175:	addl %edx, %eax
0x0046b177:	xorl %eax, $0xffffffff<UINT8>
0x0046b17a:	xorl %eax, %edx
0x0046b17c:	movl %edx, (%ecx)
0x0046b17e:	addl %ecx, $0x4<UINT8>
0x0046b181:	testl %eax, $0x81010100<UINT32>
0x0046b186:	je 0x0046b169
0x0046b169:	movl (%edi), %edx
0x0046b16b:	addl %edi, $0x4<UINT8>
0x0046b188:	testb %dl, %dl
0x0046b18a:	je 52
0x0046b18c:	testb %dh, %dh
0x0046b18e:	je 39
0x0046b190:	testl %edx, $0xff0000<UINT32>
0x0046b196:	je 0x0046b1aa
0x0046b198:	testl %edx, $0xff000000<UINT32>
0x0046b19e:	je 0x0046b1a2
0x0046b1a2:	movl (%edi), %edx
0x0046b1a4:	movl %eax, 0x8(%esp)
0x0046b1a8:	popl %edi
0x0046b1a9:	ret

0x004323aa:	addl %esp, $0x8<UINT8>
0x004323ad:	pushl %esi
0x004323ae:	call 0x0046b400
0x004323b3:	addl %esp, $0x4<UINT8>
0x004323b6:	movl (%esp), %edi
0x004323b9:	movl %ecx, 0x20(%esp)
0x004323bd:	testl %ecx, %ecx
0x004323bf:	je 40
0x004323c1:	movl %edi, %esi
0x004323c3:	addl %edi, %eax
0x004323c5:	pushl %ecx
0x004323c6:	pushl %edi
0x004323c7:	call 0x0046b0d0
0x0046b151:	movb %dl, (%ecx)
0x0046b153:	addl %ecx, $0x1<UINT8>
0x0046b156:	testb %dl, %dl
0x0046b158:	je 0x0046b1c0
0x0046b15a:	movb (%edi), %dl
0x0046b15c:	addl %edi, $0x1<UINT8>
0x0046b15f:	testl %ecx, $0x3<UINT32>
0x0046b165:	jne 0x0046b151
0x0046b1c0:	movb (%edi), %dl
0x0046b1c2:	movl %eax, 0x8(%esp)
0x0046b1c6:	popl %edi
0x0046b1c7:	ret

0x004323cc:	addl %esp, $0x8<UINT8>
0x004323cf:	pushl %edi
0x004323d0:	call 0x0046b400
0x0046b481:	leal %eax, -4(%ecx)
0x0046b484:	movl %ecx, 0x4(%esp)
0x0046b488:	subl %eax, %ecx
0x0046b48a:	ret

0x004323d5:	addl %esp, $0x4<UINT8>
0x004323d8:	movl %edx, (%esp)
0x004323db:	addl %edi, %eax
0x004323dd:	leal %ecx, 0x4(%edx)
0x004323e0:	movl (%esp), %ecx
0x004323e3:	movl %ecx, (%edx)
0x004323e5:	testl %ecx, %ecx
0x004323e7:	jne 0x004323c5
0x0046b167:	jmp 0x0046b16e
0x0046b1aa:	movw (%edi), %dx
0x0046b1ad:	movl %eax, 0x8(%esp)
0x0046b1b1:	movb 0x2(%edi), $0x0<UINT8>
0x0046b1b5:	popl %edi
0x0046b1b6:	ret

0x004323e9:	movl %ecx, 0x4(%esp)
0x004323ed:	call 0x0045bc59
0x004323f2:	movl %eax, %esi
0x004323f4:	addl %esp, $0x8<UINT8>
0x004323f7:	popl %esi
0x004323f8:	popl %edi
0x004323f9:	popl %ebx
0x004323fa:	popl %ebp
0x004323fb:	ret

0x004565d7:	addl %esp, $0x10<UINT8>
0x004565da:	movl %esi, %eax
0x004565dc:	pushl %esi
0x004565dd:	call LoadLibraryA@KERNEL32.DLL
0x004565e3:	movl %edi, %eax
0x004565e5:	pushl %esi
0x004565e6:	call 0x00432284
0x00432284:	movl %eax, 0x4(%esp)
0x00432288:	testl %eax, %eax
0x0043228a:	jne 0x0046a67b
0x0046a67b:	jmp 0x0046bb58
0x004565eb:	addl %esp, $0x4<UINT8>
0x004565ee:	movl %eax, %edi
0x004565f0:	popl %esi
0x004565f1:	popl %edi
0x004565f2:	popl %ebx
0x004565f3:	ret

0x0045660f:	addl %esp, $0x4<UINT8>
0x00456612:	testl %eax, %eax
0x00456614:	movl 0x41c0a0, %eax
0x00456619:	je 16
0x0045661b:	pushl $0x410440<UINT32>
0x00456620:	pushl %eax
0x00456621:	call GetProcAddress@KERNEL32.DLL
0x00456627:	movl %ecx, %eax
0x00456629:	jmp 0x0045662d
0x0045662d:	movl 0x41c0a4, %ecx
0x00456633:	testl %ecx, %ecx
0x00456635:	je 7
0x00456637:	pushl $0xc00<UINT32>
0x0045663c:	call SetDefaultDllDirectories@C:\Windows\system32\kernel32.dll
SetDefaultDllDirectories@C:\Windows\system32\kernel32.dll: API Node	
0x0045663e:	ret

0x00000c00:	addb (%eax), %al
0x00000c02:	addb (%eax), %al
0x00000c04:	addb (%eax), %al
0x00000c06:	addb (%eax), %al
0x00000c08:	addb (%eax), %al
0x00000c0a:	addb (%eax), %al
0x00000c0c:	addb (%eax), %al
0x00000c0e:	addb (%eax), %al
0x00000c10:	addb (%eax), %al
0x00000c12:	addb (%eax), %al
0x00000c14:	addb (%eax), %al
0x00000c16:	addb (%eax), %al
0x00000c18:	addb (%eax), %al
0x00000c1a:	addb (%eax), %al
0x00000c1c:	addb (%eax), %al
0x00000c1e:	addb (%eax), %al
0x00000c20:	addb (%eax), %al
0x00000c22:	addb (%eax), %al
0x00000c24:	addb (%eax), %al
0x00000c26:	addb (%eax), %al
0x00000c28:	addb (%eax), %al
0x00000c2a:	addb (%eax), %al
0x00000c2c:	addb (%eax), %al
0x00000c2e:	addb (%eax), %al
0x00000c30:	addb (%eax), %al
0x00000c32:	addb (%eax), %al
0x00000c34:	addb (%eax), %al
0x00000c36:	addb (%eax), %al
0x00000c38:	addb (%eax), %al
0x00000c3a:	addb (%eax), %al
0x00000c3c:	addb (%eax), %al
0x00000c3e:	addb (%eax), %al
0x00000c40:	addb (%eax), %al
0x00000c42:	addb (%eax), %al
0x00000c44:	addb (%eax), %al
0x00000c46:	addb (%eax), %al
0x00000c48:	addb (%eax), %al
0x00000c4a:	addb (%eax), %al
0x00000c4c:	addb (%eax), %al
0x00000c4e:	addb (%eax), %al
0x00000c50:	addb (%eax), %al
0x00000c52:	addb (%eax), %al
0x00000c54:	addb (%eax), %al
0x00000c56:	addb (%eax), %al
0x00000c58:	addb (%eax), %al
0x00000c5a:	addb (%eax), %al
0x00000c5c:	addb (%eax), %al
0x00000c5e:	addb (%eax), %al
0x00000c60:	addb (%eax), %al
0x00000c62:	addb (%eax), %al
0x00000c64:	addb (%eax), %al
0x00000c66:	addb (%eax), %al
0x004744fb:	je 0x00474535
0x00474535:	leal %edx, (%esi,%esi)
0x00474538:	leal %ecx, 0x8(%edx)
0x0047453b:	cmpl %edx, %ecx
0x0047453d:	sbbl %eax, %eax
0x0047453f:	testl %ecx, %eax
0x00474541:	je 0x0047458d
0x0047458d:	xorl %edi, %edi
0x0047458f:	testl %edi, %edi
0x00474591:	je 0x004745cb
0x004745cb:	pushl %edi
0x004745cc:	call 0x0046fc7e
0x004745d1:	popl %ecx
