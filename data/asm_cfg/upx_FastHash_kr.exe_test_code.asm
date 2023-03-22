0x0047b180:	pusha
0x0047b181:	movl %esi, $0x44f000<UINT32>
0x0047b186:	leal %edi, -319488(%esi)
0x0047b18c:	pushl %edi
0x0047b18d:	orl %ebp, $0xffffffff<UINT8>
0x0047b190:	jmp 0x0047b1a2
0x0047b1a2:	movl %ebx, (%esi)
0x0047b1a4:	subl %esi, $0xfffffffc<UINT8>
0x0047b1a7:	adcl %ebx, %ebx
0x0047b1a9:	jb 0x0047b198
0x0047b198:	movb %al, (%esi)
0x0047b19a:	incl %esi
0x0047b19b:	movb (%edi), %al
0x0047b19d:	incl %edi
0x0047b19e:	addl %ebx, %ebx
0x0047b1a0:	jne 0x0047b1a9
0x0047b1ab:	movl %eax, $0x1<UINT32>
0x0047b1b0:	addl %ebx, %ebx
0x0047b1b2:	jne 0x0047b1bb
0x0047b1bb:	adcl %eax, %eax
0x0047b1bd:	addl %ebx, %ebx
0x0047b1bf:	jae 0x0047b1cc
0x0047b1c1:	jne 0x0047b1eb
0x0047b1eb:	xorl %ecx, %ecx
0x0047b1ed:	subl %eax, $0x3<UINT8>
0x0047b1f0:	jb 0x0047b203
0x0047b203:	addl %ebx, %ebx
0x0047b205:	jne 0x0047b20e
0x0047b20e:	jb 0x0047b1dc
0x0047b210:	incl %ecx
0x0047b211:	addl %ebx, %ebx
0x0047b213:	jne 0x0047b21c
0x0047b21c:	jb 0x0047b1dc
0x0047b21e:	addl %ebx, %ebx
0x0047b220:	jne 0x0047b229
0x0047b229:	adcl %ecx, %ecx
0x0047b22b:	addl %ebx, %ebx
0x0047b22d:	jae 0x0047b21e
0x0047b22f:	jne 0x0047b23a
0x0047b23a:	addl %ecx, $0x2<UINT8>
0x0047b23d:	cmpl %ebp, $0xfffffb00<UINT32>
0x0047b243:	adcl %ecx, $0x2<UINT8>
0x0047b246:	leal %edx, (%edi,%ebp)
0x0047b249:	cmpl %ebp, $0xfffffffc<UINT8>
0x0047b24c:	jbe 0x0047b25c
0x0047b24e:	movb %al, (%edx)
0x0047b250:	incl %edx
0x0047b251:	movb (%edi), %al
0x0047b253:	incl %edi
0x0047b254:	decl %ecx
0x0047b255:	jne 0x0047b24e
0x0047b257:	jmp 0x0047b19e
0x0047b1f2:	shll %eax, $0x8<UINT8>
0x0047b1f5:	movb %al, (%esi)
0x0047b1f7:	incl %esi
0x0047b1f8:	xorl %eax, $0xffffffff<UINT8>
0x0047b1fb:	je 0x0047b272
0x0047b1fd:	sarl %eax
0x0047b1ff:	movl %ebp, %eax
0x0047b201:	jmp 0x0047b20e
0x0047b1dc:	addl %ebx, %ebx
0x0047b1de:	jne 0x0047b1e7
0x0047b1e7:	adcl %ecx, %ecx
0x0047b1e9:	jmp 0x0047b23d
0x0047b25c:	movl %eax, (%edx)
0x0047b25e:	addl %edx, $0x4<UINT8>
0x0047b261:	movl (%edi), %eax
0x0047b263:	addl %edi, $0x4<UINT8>
0x0047b266:	subl %ecx, $0x4<UINT8>
0x0047b269:	ja 0x0047b25c
0x0047b26b:	addl %edi, %ecx
0x0047b26d:	jmp 0x0047b19e
0x0047b1c3:	movl %ebx, (%esi)
0x0047b1c5:	subl %esi, $0xfffffffc<UINT8>
0x0047b1c8:	adcl %ebx, %ebx
0x0047b1ca:	jb 0x0047b1eb
0x0047b1cc:	decl %eax
0x0047b1cd:	addl %ebx, %ebx
0x0047b1cf:	jne 0x0047b1d8
0x0047b1d8:	adcl %eax, %eax
0x0047b1da:	jmp 0x0047b1b0
0x0047b1b4:	movl %ebx, (%esi)
0x0047b1b6:	subl %esi, $0xfffffffc<UINT8>
0x0047b1b9:	adcl %ebx, %ebx
0x0047b1e0:	movl %ebx, (%esi)
0x0047b1e2:	subl %esi, $0xfffffffc<UINT8>
0x0047b1e5:	adcl %ebx, %ebx
0x0047b231:	movl %ebx, (%esi)
0x0047b233:	subl %esi, $0xfffffffc<UINT8>
0x0047b236:	adcl %ebx, %ebx
0x0047b238:	jae 0x0047b21e
0x0047b222:	movl %ebx, (%esi)
0x0047b224:	subl %esi, $0xfffffffc<UINT8>
0x0047b227:	adcl %ebx, %ebx
0x0047b1d1:	movl %ebx, (%esi)
0x0047b1d3:	subl %esi, $0xfffffffc<UINT8>
0x0047b1d6:	adcl %ebx, %ebx
0x0047b215:	movl %ebx, (%esi)
0x0047b217:	subl %esi, $0xfffffffc<UINT8>
0x0047b21a:	adcl %ebx, %ebx
0x0047b207:	movl %ebx, (%esi)
0x0047b209:	subl %esi, $0xfffffffc<UINT8>
0x0047b20c:	adcl %ebx, %ebx
0x0047b272:	popl %esi
0x0047b273:	movl %edi, %esi
0x0047b275:	movl %ecx, $0x1a1d<UINT32>
0x0047b27a:	movb %al, (%edi)
0x0047b27c:	incl %edi
0x0047b27d:	subb %al, $0xffffffe8<UINT8>
0x0047b27f:	cmpb %al, $0x1<UINT8>
0x0047b281:	ja 0x0047b27a
0x0047b283:	cmpb (%edi), $0x12<UINT8>
0x0047b286:	jne 0x0047b27a
0x0047b288:	movl %eax, (%edi)
0x0047b28a:	movb %bl, 0x4(%edi)
0x0047b28d:	shrw %ax, $0x8<UINT8>
0x0047b291:	roll %eax, $0x10<UINT8>
0x0047b294:	xchgb %ah, %al
0x0047b296:	subl %eax, %edi
0x0047b298:	subb %bl, $0xffffffe8<UINT8>
0x0047b29b:	addl %eax, %esi
0x0047b29d:	movl (%edi), %eax
0x0047b29f:	addl %edi, $0x5<UINT8>
0x0047b2a2:	movb %al, %bl
0x0047b2a4:	loop 0x0047b27f
0x0047b2a6:	leal %edi, 0x78000(%esi)
0x0047b2ac:	movl %eax, (%edi)
0x0047b2ae:	orl %eax, %eax
0x0047b2b0:	je 0x0047b2f7
0x0047b2b2:	movl %ebx, 0x4(%edi)
0x0047b2b5:	leal %eax, 0x81d24(%eax,%esi)
0x0047b2bc:	addl %ebx, %esi
0x0047b2be:	pushl %eax
0x0047b2bf:	addl %edi, $0x8<UINT8>
0x0047b2c2:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x0047b2c8:	xchgl %ebp, %eax
0x0047b2c9:	movb %al, (%edi)
0x0047b2cb:	incl %edi
0x0047b2cc:	orb %al, %al
0x0047b2ce:	je 0x0047b2ac
0x0047b2d0:	movl %ecx, %edi
0x0047b2d2:	jns 0x0047b2db
0x0047b2db:	pushl %edi
0x0047b2dc:	decl %eax
0x0047b2dd:	repn scasb %al, %es:(%edi)
0x0047b2df:	pushl %ebp
0x0047b2e0:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0047b2e6:	orl %eax, %eax
0x0047b2e8:	je 7
0x0047b2ea:	movl (%ebx), %eax
0x0047b2ec:	addl %ebx, $0x4<UINT8>
0x0047b2ef:	jmp 0x0047b2c9
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x0047b2d4:	movzwl %eax, (%edi)
0x0047b2d7:	incl %edi
0x0047b2d8:	pushl %eax
0x0047b2d9:	incl %edi
0x0047b2da:	movl %ecx, $0xaef24857<UINT32>
0x0047b2f7:	movl %ebp, 0x81e48(%esi)
0x0047b2fd:	leal %edi, -4096(%esi)
0x0047b303:	movl %ebx, $0x1000<UINT32>
0x0047b308:	pushl %eax
0x0047b309:	pushl %esp
0x0047b30a:	pushl $0x4<UINT8>
0x0047b30c:	pushl %ebx
0x0047b30d:	pushl %edi
0x0047b30e:	call VirtualProtect@KERNEL32.DLL
VirtualProtect@KERNEL32.DLL: API Node	
0x0047b310:	leal %eax, 0x21f(%edi)
0x0047b316:	andb (%eax), $0x7f<UINT8>
0x0047b319:	andb 0x28(%eax), $0x7f<UINT8>
0x0047b31d:	popl %eax
0x0047b31e:	pushl %eax
0x0047b31f:	pushl %esp
0x0047b320:	pushl %eax
0x0047b321:	pushl %ebx
0x0047b322:	pushl %edi
0x0047b323:	call VirtualProtect@KERNEL32.DLL
0x0047b325:	popl %eax
0x0047b326:	popa
0x0047b327:	leal %eax, -128(%esp)
0x0047b32b:	pushl $0x0<UINT8>
0x0047b32d:	cmpl %esp, %eax
0x0047b32f:	jne 0x0047b32b
0x0047b331:	subl %esp, $0xffffff80<UINT8>
0x0047b334:	jmp 0x0041dffa
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
0x0041e01a:	call GetVersionExA@KERNEL32.DLL
GetVersionExA@KERNEL32.DLL: API Node	
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
0x0041e06d:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
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
0x004227d0:	call HeapCreate@KERNEL32.DLL
HeapCreate@KERNEL32.DLL: API Node	
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
0x00426793:	call GetModuleHandleA@KERNEL32.DLL
0x00426799:	testl %eax, %eax
0x0042679b:	je 21
0x0042679d:	pushl $0x45caa0<UINT32>
0x004267a2:	pushl %eax
0x004267a3:	call GetProcAddress@KERNEL32.DLL
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
0x0042009c:	call GetModuleHandleA@KERNEL32.DLL
0x004200a2:	movl %edi, %eax
0x004200a4:	testl %edi, %edi
0x004200a6:	je 107
0x004200a8:	movl %esi, 0x45422c
0x004200ae:	pushl $0x45bb08<UINT32>
0x004200b3:	pushl %edi
0x004200b4:	call GetProcAddress@KERNEL32.DLL
0x004200b6:	pushl $0x45bafc<UINT32>
0x004200bb:	pushl %edi
0x004200bc:	movl 0x46a5ac, %eax
0x004200c1:	call GetProcAddress@KERNEL32.DLL
0x004200c3:	pushl $0x45baf0<UINT32>
0x004200c8:	pushl %edi
0x004200c9:	movl 0x46a5b0, %eax
0x004200ce:	call GetProcAddress@KERNEL32.DLL
0x004200d0:	pushl $0x45bae8<UINT32>
0x004200d5:	pushl %edi
0x004200d6:	movl 0x46a5b4, %eax
0x004200db:	call GetProcAddress@KERNEL32.DLL
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
0x0041eae0:	call HeapAlloc@KERNEL32.DLL
HeapAlloc@KERNEL32.DLL: API Node	
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
0x00420159:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
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
0x0041da9c:	call HeapAlloc@KERNEL32.DLL
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
0x00423f8d:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
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
0x004240b8:	call GetStdHandle@KERNEL32.DLL
GetStdHandle@KERNEL32.DLL: API Node	
0x004240be:	movl %edi, %eax
0x004240c0:	cmpl %edi, $0xffffffff<UINT8>
0x004240c3:	je 63
0x004240c5:	pushl %edi
0x004240c6:	call GetFileType@KERNEL32.DLL
GetFileType@KERNEL32.DLL: API Node	
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
0x0042411e:	call SetHandleCount@KERNEL32.DLL
SetHandleCount@KERNEL32.DLL: API Node	
0x00424124:	xorl %eax, %eax
0x00424126:	popl %edi
0x00424127:	popl %esi
0x00424128:	popl %ebp
0x00424129:	popl %ebx
0x0042412a:	addl %esp, $0x48<UINT8>
0x0042412d:	ret

0x0041e0f3:	testl %eax, %eax
0x0041e0f5:	jnl 0x0041e0ff
0x0041e0ff:	call GetCommandLineA@KERNEL32.DLL
GetCommandLineA@KERNEL32.DLL: API Node	
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
0x00423e2a:	call GetEnvironmentStringsW@KERNEL32.DLL
GetEnvironmentStringsW@KERNEL32.DLL: API Node	
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
0x00423e94:	call WideCharToMultiByte@KERNEL32.DLL
WideCharToMultiByte@KERNEL32.DLL: API Node	
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
0x00423eb6:	call WideCharToMultiByte@KERNEL32.DLL
0x00423eb8:	testl %eax, %eax
0x00423eba:	jne 0x00423eca
0x00423eca:	movl %ebx, 0x10(%esp)
0x00423ece:	pushl %esi
0x00423ecf:	call FreeEnvironmentStringsW@KERNEL32.DLL
FreeEnvironmentStringsW@KERNEL32.DLL: API Node	
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
0x0041f4cf:	jne 0x0041f4e3
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
0x00422714:	call EnterCriticalSection@KERNEL32.DLL
EnterCriticalSection@KERNEL32.DLL: API Node	
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
0x0041f3c4:	call GetACP@KERNEL32.DLL
GetACP@KERNEL32.DLL: API Node	
0x0041f3ca:	jmp 0x0041f3e0
0x0041f3e0:	movl 0x8(%ebp), %eax
0x0041f3e3:	cmpl %eax, 0x46bd04
0x0041f3e9:	je 0x0041f4aa
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
0x0041f222:	call GetCPInfo@KERNEL32.DLL
GetCPInfo@KERNEL32.DLL: API Node	
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
0x0041f009:	call GetCPInfo@KERNEL32.DLL
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
0x00425203:	call GetStringTypeW@KERNEL32.DLL
GetStringTypeW@KERNEL32.DLL: API Node	
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
0x00425277:	call MultiByteToWideChar@KERNEL32.DLL
MultiByteToWideChar@KERNEL32.DLL: API Node	
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
0x004252f5:	call MultiByteToWideChar@KERNEL32.DLL
0x004252fb:	testl %eax, %eax
0x004252fd:	je 17
0x004252ff:	pushl 0x14(%ebp)
0x00425302:	pushl %eax
0x00425303:	pushl %esi
0x00425304:	pushl 0x8(%ebp)
0x00425307:	call GetStringTypeW@KERNEL32.DLL
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
0x0042116f:	call LCMapStringW@KERNEL32.DLL
LCMapStringW@KERNEL32.DLL: API Node	
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
0x00421208:	call MultiByteToWideChar@KERNEL32.DLL
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
0x00421289:	call MultiByteToWideChar@KERNEL32.DLL
0x0042128f:	testl %eax, %eax
0x00421291:	je 230
0x00421297:	pushl %ebx
0x00421298:	pushl %ebx
0x00421299:	pushl %esi
0x0042129a:	pushl -28(%ebp)
0x0042129d:	pushl 0xc(%ebp)
0x004212a0:	pushl 0x8(%ebp)
0x004212a3:	call LCMapStringW@KERNEL32.DLL
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
0x00421352:	call LCMapStringW@KERNEL32.DLL
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
0x00421375:	call WideCharToMultiByte@KERNEL32.DLL
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
0x00422644:	call LeaveCriticalSection@KERNEL32.DLL
LeaveCriticalSection@KERNEL32.DLL: API Node	
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
0x00423d96:	call GetModuleFileNameA@KERNEL32.DLL
GetModuleFileNameA@KERNEL32.DLL: API Node	
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
0x0041db57:	call HeapFree@KERNEL32.DLL
HeapFree@KERNEL32.DLL: API Node	
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
0x00421b26:	call GetModuleHandleA@KERNEL32.DLL
0x00421b2c:	testl %eax, %eax
0x00421b2e:	je 21
0x00421b30:	pushl $0x45bda8<UINT32>
0x00421b35:	pushl %eax
0x00421b36:	call GetProcAddress@KERNEL32.DLL
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
0x0041d69b:	je 0x0041d69f
0x0041d69f:	addl %esi, $0x4<UINT8>
0x0041d6a2:	cmpl %esi, %edi
0x0041d6a4:	jb 0x0041d693
0x0041d69d:	call 0x0042432a
0x0041c74d:	pushl $0x80<UINT32>
0x0041c752:	call 0x0041dae0
0x0041c757:	testl %eax, %eax
0x0041c759:	popl %ecx
0x0041c75a:	movl 0x46be2c, %eax
0x0041c75f:	jne 0x0041c765
0x0041c765:	andl (%eax), $0x0<UINT8>
0x0041c768:	movl %eax, 0x46be2c
0x0041c76d:	movl 0x46be28, %eax
0x0041c772:	xorl %eax, %eax
0x0041c774:	ret

0x00425854:	movl %eax, 0x46baa0
0x00425859:	testl %eax, %eax
0x0042585b:	pushl %esi
0x0042585c:	pushl $0x14<UINT8>
0x0042585e:	popl %esi
0x0042585f:	jne 7
0x00425861:	movl %eax, $0x200<UINT32>
0x00425866:	jmp 0x0042586e
0x0042586e:	movl 0x46baa0, %eax
0x00425873:	pushl $0x4<UINT8>
0x00425875:	pushl %eax
0x00425876:	call 0x0041ea5e
0x0042587b:	testl %eax, %eax
0x0042587d:	popl %ecx
0x0042587e:	popl %ecx
0x0042587f:	movl 0x46aa80, %eax
0x00425884:	jne 0x004258a4
0x004258a4:	xorl %edx, %edx
0x004258a6:	movl %ecx, $0x467910<UINT32>
0x004258ab:	jmp 0x004258b2
0x004258b2:	movl (%edx,%eax), %ecx
0x004258b5:	addl %ecx, $0x20<UINT8>
0x004258b8:	addl %edx, $0x4<UINT8>
0x004258bb:	cmpl %ecx, $0x467b90<UINT32>
0x004258c1:	jl 0x004258ad
0x004258ad:	movl %eax, 0x46aa80
0x004258c3:	xorl %ecx, %ecx
0x004258c5:	movl %edx, $0x467920<UINT32>
0x004258ca:	movl %esi, %ecx
0x004258cc:	movl %eax, %ecx
0x004258ce:	andl %eax, $0x1f<UINT8>
0x004258d1:	sarl %esi, $0x5<UINT8>
0x004258d4:	movl %esi, 0x46bac0(,%esi,4)
0x004258db:	leal %eax, (%eax,%eax,8)
0x004258de:	movl %eax, (%esi,%eax,4)
0x004258e1:	cmpl %eax, $0xffffffff<UINT8>
0x004258e4:	je 4
0x004258e6:	testl %eax, %eax
0x004258e8:	jne 0x004258ed
0x004258ed:	addl %edx, $0x20<UINT8>
0x004258f0:	incl %ecx
0x004258f1:	cmpl %edx, $0x467980<UINT32>
0x004258f7:	jl 0x004258ca
0x004258f9:	xorl %eax, %eax
0x004258fb:	popl %esi
0x004258fc:	ret

0x0042432a:	pushl $0x4242dc<UINT32>
0x0042432f:	call SetUnhandledExceptionFilter@KERNEL32.DLL
SetUnhandledExceptionFilter@KERNEL32.DLL: API Node	
0x00424335:	movl 0x46a968, %eax
0x0042433a:	xorl %eax, %eax
0x0042433c:	ret

0x0041d6a6:	testl %eax, %eax
0x0041d6a8:	jne 44
0x0041d6aa:	pushl $0x422761<UINT32>
0x0041d6af:	call 0x0041c7ad
0x0041c7ad:	pushl 0x4(%esp)
0x0041c7b1:	call 0x0041c775
0x0041c775:	pushl $0xc<UINT8>
0x0041c777:	pushl $0x45b950<UINT32>
0x0041c77c:	call 0x0041eed4
0x0041c781:	call 0x0041d645
0x0041d645:	pushl $0x8<UINT8>
0x0041d647:	call 0x004226ec
0x0041d64c:	popl %ecx
0x0041d64d:	ret

0x0041c786:	andl -4(%ebp), $0x0<UINT8>
0x0041c78a:	movl %edi, 0x8(%ebp)
0x0041c78d:	call 0x0041c6cd
0x0041c6cd:	pushl %esi
0x0041c6ce:	pushl 0x46be2c
0x0041c6d4:	call 0x0041edd5
0x0041edd5:	pushl $0x10<UINT8>
0x0041edd7:	pushl $0x45ba50<UINT32>
0x0041eddc:	call 0x0041eed4
0x0041ede1:	cmpl 0x46bbe0, $0x3<UINT8>
0x0041ede8:	jne 0x0041ee24
0x0041ee24:	pushl 0x8(%ebp)
0x0041ee27:	pushl $0x0<UINT8>
0x0041ee29:	pushl 0x46bbdc
0x0041ee2f:	call HeapSize@KERNEL32.DLL
HeapSize@KERNEL32.DLL: API Node	
0x0041ee35:	movl %esi, %eax
0x0041ee37:	movl %eax, %esi
0x0041ee39:	call 0x0041ef0f
0x0041ee3e:	ret

0x0041c6d9:	popl %ecx
0x0041c6da:	movl %ecx, 0x46be28
0x0041c6e0:	movl %esi, %eax
0x0041c6e2:	movl %eax, 0x46be2c
0x0041c6e7:	movl %edx, %ecx
0x0041c6e9:	subl %edx, %eax
0x0041c6eb:	addl %edx, $0x4<UINT8>
0x0041c6ee:	cmpl %esi, %edx
0x0041c6f0:	jae 0x0041c740
0x0041c740:	movl (%ecx), %edi
0x0041c742:	addl 0x46be28, $0x4<UINT8>
0x0041c749:	movl %eax, %edi
0x0041c74b:	popl %esi
0x0041c74c:	ret

0x0041c792:	movl -28(%ebp), %eax
0x0041c795:	orl -4(%ebp), $0xffffffff<UINT8>
0x0041c799:	call 0x0041c7a7
0x0041c7a7:	call 0x0041d64e
0x0041d64e:	pushl $0x8<UINT8>
0x0041d650:	call 0x00422637
0x0041d655:	popl %ecx
0x0041d656:	ret

0x0041c7ac:	ret

0x0041c79e:	movl %eax, -28(%ebp)
0x0041c7a1:	call 0x0041ef0f
0x0041c7a6:	ret

0x0041c7b6:	negl %eax
0x0041c7b8:	sbbl %eax, %eax
0x0041c7ba:	negl %eax
0x0041c7bc:	popl %ecx
0x0041c7bd:	decl %eax
0x0041c7be:	ret

0x0041d6b4:	movl %esi, $0x466000<UINT32>
0x0041d6b9:	movl %eax, %esi
0x0041d6bb:	movl %edi, $0x466064<UINT32>
0x0041d6c0:	cmpl %eax, %edi
0x0041d6c2:	popl %ecx
0x0041d6c3:	jae 15
0x0041d6c5:	movl %eax, (%esi)
0x0041d6c7:	testl %eax, %eax
0x0041d6c9:	je 0x0041d6cd
0x0041d6cd:	addl %esi, $0x4<UINT8>
0x0041d6d0:	cmpl %esi, %edi
0x0041d6d2:	jb 0x0041d6c5
0x0041d6cb:	call 0x0044f560
0x0042412e:	pushl %ebp
0x0042412f:	movl %ebp, %esp
0x00424131:	subl %esp, $0x10<UINT8>
0x00424134:	movl %eax, 0x467108
0x00424139:	testl %eax, %eax
0x0042413b:	je 7
0x0042413d:	cmpl %eax, $0xbb40e64e<UINT32>
0x00424142:	jne 78
0x00424144:	pushl %esi
0x00424145:	leal %eax, -8(%ebp)
0x00424148:	pushl %eax
0x00424149:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0042414f:	movl %esi, -4(%ebp)
0x00424152:	xorl %esi, -8(%ebp)
0x00424155:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0042415b:	xorl %esi, %eax
0x0042415d:	call GetCurrentThreadId@KERNEL32.DLL
0x00424163:	xorl %esi, %eax
0x00424165:	call GetTickCount@KERNEL32.DLL
GetTickCount@KERNEL32.DLL: API Node	
0x0042416b:	xorl %esi, %eax
0x0042416d:	leal %eax, -16(%ebp)
0x00424170:	pushl %eax
0x00424171:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x00424177:	movl %eax, -12(%ebp)
0x0042417a:	xorl %eax, -16(%ebp)
0x0042417d:	xorl %esi, %eax
0x0042417f:	movl 0x467108, %esi
0x00424185:	jne 0x00424191
0x00424191:	popl %esi
0x00424192:	leave
0x00424193:	ret

0x00443a93:	movl %ecx, $0x469f58<UINT32>
0x00443a98:	jmp 0x0044390c
0x0044390c:	movl %eax, %ecx
0x0044390e:	movl (%eax), $0x458ae4<UINT32>
0x00443914:	xorl %ecx, %ecx
0x00443916:	movl 0x4(%eax), %ecx
0x00443919:	movl 0x10(%eax), $0x2<UINT32>
0x00443920:	movl 0x8(%eax), %ecx
0x00443923:	movl 0xc(%eax), %ecx
0x00443926:	movw 0x14(%eax), %cx
0x0044392a:	movw 0x16(%eax), %cx
0x0044392e:	movl 0x4(%eax), %eax
0x00443931:	ret

0x00450fec:	pushl $0x451004<UINT32>
0x00450ff1:	call 0x0041c7ad
0x00450ff6:	popl %ecx
0x00450ff7:	ret

0x00450ff8:	pushl $0x45100e<UINT32>
0x00450ffd:	call 0x0041c7ad
0x00451002:	popl %ecx
0x00451003:	ret

0x00453bd6:	movl %ecx, $0x46aa24<UINT32>
0x00453bdb:	call 0x0043cc15
0x0043cc15:	pushl %ebp
0x0043cc16:	leal %ebp, -120(%esp)
0x0043cc1a:	subl %esp, $0x98<UINT32>
0x0043cc20:	movl %eax, 0x467108
0x0043cc25:	pushl %esi
0x0043cc26:	movl 0x74(%ebp), %eax
0x0043cc29:	movl %esi, %ecx
0x0043cc2b:	call 0x0043cbe5
0x0043cbe5:	pushl %esi
0x0043cbe6:	movl %esi, %ecx
0x0043cbe8:	leal %ecx, 0x18(%esi)
0x0043cbeb:	call 0x0041ba8f
0x0041ba8f:	pushl %esi
0x0041ba90:	pushl $0x18<UINT8>
0x0041ba92:	movl %esi, %ecx
0x0041ba94:	pushl $0x0<UINT8>
0x0041ba96:	pushl %esi
0x0041ba97:	call 0x0041e270
0x0041ba9c:	addl %esp, $0xc<UINT8>
0x0041ba9f:	movl %eax, %esi
0x0041baa1:	popl %esi
0x0041baa2:	ret

0x0043cbf0:	xorl %eax, %eax
0x0043cbf2:	movl 0x30(%esi), %eax
0x0043cbf5:	movl 0x34(%esi), %eax
0x0043cbf8:	movl 0x38(%esi), %eax
0x0043cbfb:	movl %eax, %esi
0x0043cbfd:	popl %esi
0x0043cbfe:	ret

0x0043cc30:	movl %eax, $0x400000<UINT32>
0x0043cc35:	pushl $0x94<UINT32>
0x0043cc3a:	movl 0x8(%esi), %eax
0x0043cc3d:	movl 0x4(%esi), %eax
0x0043cc40:	leal %eax, -32(%ebp)
0x0043cc43:	pushl $0x0<UINT8>
0x0043cc45:	pushl %eax
0x0043cc46:	movl (%esi), $0x3c<UINT32>
0x0043cc4c:	movb 0xc(%esi), $0x0<UINT8>
0x0043cc50:	call 0x0041e270
0x0043cc55:	addl %esp, $0xc<UINT8>
0x0043cc58:	leal %eax, -32(%ebp)
0x0043cc5b:	pushl %eax
0x0043cc5c:	movl -32(%ebp), $0x94<UINT32>
0x0043cc63:	call GetVersionExA@KERNEL32.DLL
0x0043cc69:	cmpl -16(%ebp), $0x2<UINT8>
0x0043cc6d:	jne 8
0x0043cc6f:	cmpl -28(%ebp), $0x5<UINT8>
0x0043cc73:	jb 26
0x0043cc75:	jmp 0x0043cc8b
0x0043cc8b:	movb 0xc(%esi), $0x1<UINT8>
0x0043cc8f:	leal %ecx, 0x18(%esi)
0x0043cc92:	movl 0x10(%esi), $0x710<UINT32>
0x0043cc99:	movl 0x14(%esi), $0x4600b8<UINT32>
0x0043cca0:	call 0x0041baa3
0x0041baa3:	pushl $0xc<UINT8>
0x0041baa5:	pushl $0x45b210<UINT32>
0x0041baaa:	call 0x0041eed4
0x0041baaf:	xorl %esi, %esi
0x0041bab1:	movl -4(%ebp), %esi
0x0041bab4:	pushl %ecx
0x0041bab5:	call InitializeCriticalSection@KERNEL32.DLL
InitializeCriticalSection@KERNEL32.DLL: API Node	
0x0041babb:	jmp 0x0041bae7
0x0041bae7:	orl -4(%ebp), $0xffffffff<UINT8>
0x0041baeb:	movl %eax, %esi
0x0041baed:	call 0x0041ef0f
0x0041baf2:	ret

0x0043cca5:	testl %eax, %eax
0x0043cca7:	jnl 0x0043ccb0
0x0043ccb0:	movl %ecx, 0x74(%ebp)
0x0043ccb3:	movl %eax, %esi
0x0043ccb5:	popl %esi
0x0043ccb6:	call 0x0041e200
0x0043ccbb:	addl %ebp, $0x78<UINT8>
0x0043ccbe:	leave
0x0043ccbf:	ret

0x00453be0:	pushl $0x453c1a<UINT32>
0x00453be5:	call 0x0041c7ad
0x00453bea:	popl %ecx
0x00453beb:	ret

0x00453bec:	pushl $0x710<UINT32>
0x00453bf1:	pushl $0x0<UINT8>
0x00453bf3:	call 0x0043cf39
0x0043cf39:	call 0x00450faf
0x00450faf:	pushl $0x44f595<UINT32>
0x00450fb4:	movl %ecx, $0x46a284<UINT32>
0x00450fb9:	call 0x00451b26
0x00451b26:	movl %eax, $0x45395e<UINT32>
0x00451b2b:	call 0x0041e2d0
0x0041e2d0:	pushl $0xffffffff<UINT8>
0x0041e2d2:	pushl %eax
0x0041e2d3:	movl %eax, %fs:0
0x0041e2d9:	pushl %eax
0x0041e2da:	movl %eax, 0xc(%esp)
0x0041e2de:	movl %fs:0, %esp
0x0041e2e5:	movl 0xc(%esp), %ebp
0x0041e2e9:	leal %ebp, 0xc(%esp)
0x0041e2ed:	pushl %eax
0x0041e2ee:	ret

0x00451b30:	pushl %ecx
0x00451b31:	pushl %esi
0x00451b32:	movl %esi, %ecx
0x00451b34:	cmpl (%esi), $0x0<UINT8>
0x00451b37:	pushl %edi
0x00451b38:	jne 0x00451b68
0x00451b3a:	movl %ecx, 0x46a2ec
0x00451b40:	testl %ecx, %ecx
0x00451b42:	jne 0x00451b61
0x00451b44:	movl %ecx, $0x46a2f0<UINT32>
0x00451b49:	movl -16(%ebp), %ecx
0x00451b4c:	andl -4(%ebp), $0x0<UINT8>
0x00451b50:	call 0x00451870
0x00451870:	xorl %eax, %eax
0x00451872:	pushl %esi
0x00451873:	movl %esi, %ecx
0x00451875:	movl 0x14(%esi), %eax
0x00451878:	movl 0x18(%esi), %eax
0x0045187b:	movl 0x18(%esi), $0x4<UINT32>
0x00451882:	movl 0x4(%esi), %eax
0x00451885:	movl 0x8(%esi), $0x1<UINT32>
0x0045188c:	movl 0xc(%esi), %eax
0x0045188f:	movl 0x10(%esi), %eax
0x00451892:	call TlsAlloc@KERNEL32.DLL
TlsAlloc@KERNEL32.DLL: API Node	
0x00451898:	cmpl %eax, $0xffffffff<UINT8>
0x0045189b:	movl (%esi), %eax
0x0045189d:	jne 0x004518a4
0x004518a4:	leal %eax, 0x1c(%esi)
0x004518a7:	pushl %eax
0x004518a8:	call InitializeCriticalSection@KERNEL32.DLL
0x004518ae:	movl %eax, %esi
0x004518b0:	popl %esi
0x004518b1:	ret

0x00451b55:	orl -4(%ebp), $0xffffffff<UINT8>
0x00451b59:	movl %ecx, %eax
0x00451b5b:	movl 0x46a2ec, %ecx
0x00451b61:	call 0x00451629
0x00451629:	pushl %ebp
0x0045162a:	movl %ebp, %esp
0x0045162c:	pushl %ecx
0x0045162d:	pushl %ecx
0x0045162e:	pushl %ebx
0x0045162f:	pushl %esi
0x00451630:	movl %esi, %ecx
0x00451632:	leal %eax, 0x1c(%esi)
0x00451635:	pushl %edi
0x00451636:	pushl %eax
0x00451637:	movl -4(%ebp), %eax
0x0045163a:	call EnterCriticalSection@KERNEL32.DLL
0x00451640:	movl %eax, 0x4(%esi)
0x00451643:	movl %edi, 0x8(%esi)
0x00451646:	cmpl %edi, %eax
0x00451648:	jnl 0x00451657
0x00451657:	xorl %edi, %edi
0x00451659:	incl %edi
0x0045165a:	cmpl %eax, %edi
0x0045165c:	jle 0x00451679
0x00451679:	leal %ebx, 0x20(%eax)
0x0045167c:	movl %eax, 0x10(%esi)
0x0045167f:	testl %eax, %eax
0x00451681:	jne 16
0x00451683:	movl %eax, %ebx
0x00451685:	shll %eax, $0x3<UINT8>
0x00451688:	pushl %eax
0x00451689:	pushl $0x2<UINT8>
0x0045168b:	call GlobalAlloc@KERNEL32.DLL
GlobalAlloc@KERNEL32.DLL: API Node	
0x00451691:	jmp 0x004516b8
0x004516b8:	testl %eax, %eax
0x004516ba:	jne 0x004516df
0x004516df:	pushl %eax
0x004516e0:	call GlobalLock@KERNEL32.DLL
GlobalLock@KERNEL32.DLL: API Node	
0x004516e6:	movl %ecx, 0x4(%esi)
0x004516e9:	movl %edx, %ebx
0x004516eb:	subl %edx, %ecx
0x004516ed:	shll %edx, $0x3<UINT8>
0x004516f0:	pushl %edx
0x004516f1:	movl -8(%ebp), %eax
0x004516f4:	leal %eax, (%eax,%ecx,8)
0x004516f7:	pushl $0x0<UINT8>
0x004516f9:	pushl %eax
0x004516fa:	call 0x0041e270
0x004516ff:	movl %eax, -8(%ebp)
0x00451702:	addl %esp, $0xc<UINT8>
0x00451705:	movl 0x4(%esi), %ebx
0x00451708:	movl 0x10(%esi), %eax
0x0045170b:	cmpl %edi, 0xc(%esi)
0x0045170e:	jl 6
0x00451710:	leal %eax, 0x1(%edi)
0x00451713:	movl 0xc(%esi), %eax
0x00451716:	movl %eax, 0x10(%esi)
0x00451719:	pushl -4(%ebp)
0x0045171c:	leal %eax, (%eax,%edi,8)
0x0045171f:	orl (%eax), $0x1<UINT8>
0x00451722:	leal %eax, 0x1(%edi)
0x00451725:	movl 0x8(%esi), %eax
0x00451728:	call LeaveCriticalSection@KERNEL32.DLL
0x0045172e:	movl %eax, %edi
0x00451730:	popl %edi
0x00451731:	popl %esi
0x00451732:	popl %ebx
0x00451733:	leave
0x00451734:	ret

0x00451b66:	movl (%esi), %eax
0x00451b68:	pushl (%esi)
0x00451b6a:	movl %ecx, 0x46a2ec
0x00451b70:	call 0x00451735
0x00451735:	pushl %ebx
0x00451736:	pushl %esi
0x00451737:	movl %esi, %ecx
0x00451739:	pushl %edi
0x0045173a:	leal %ebx, 0x1c(%esi)
0x0045173d:	pushl %ebx
0x0045173e:	call EnterCriticalSection@KERNEL32.DLL
0x00451744:	movl %edi, 0x10(%esp)
0x00451748:	testl %edi, %edi
0x0045174a:	jle 30
0x0045174c:	cmpl %edi, 0xc(%esi)
0x0045174f:	jnl 25
0x00451751:	pushl (%esi)
0x00451753:	call TlsGetValue@KERNEL32.DLL
TlsGetValue@KERNEL32.DLL: API Node	
0x00451759:	testl %eax, %eax
0x0045175b:	je 0x0045176a
0x0045176a:	xorl %edi, %edi
0x0045176c:	pushl %ebx
0x0045176d:	call LeaveCriticalSection@KERNEL32.DLL
0x00451773:	movl %eax, %edi
0x00451775:	popl %edi
0x00451776:	popl %esi
0x00451777:	popl %ebx
0x00451778:	ret $0x4<UINT16>

0x00451b75:	movl %edi, %eax
0x00451b77:	testl %edi, %edi
0x00451b79:	jne 0x00451b8e
0x00451b7b:	call 0x0044f595
0x0044f595:	movl %eax, $0x4532c0<UINT32>
0x0044f59a:	call 0x0041e2d0
0x0044f59f:	pushl %ecx
0x0044f5a0:	pushl $0x104<UINT32>
0x0044f5a5:	call 0x00451601
0x00451601:	pushl 0x4(%esp)
0x00451605:	pushl $0x40<UINT8>
0x00451607:	call LocalAlloc@KERNEL32.DLL
LocalAlloc@KERNEL32.DLL: API Node	
0x0045160d:	testl %eax, %eax
0x0045160f:	jne 0x00451616
0x00451616:	ret $0x4<UINT16>

0x0044f5aa:	movl %ecx, %eax
0x0044f5ac:	movl -16(%ebp), %ecx
0x0044f5af:	xorl %eax, %eax
0x0044f5b1:	cmpl %ecx, %eax
0x0044f5b3:	movl -4(%ebp), %eax
0x0044f5b6:	je 5
0x0044f5b8:	call 0x00450d1c
0x00450d1c:	movl %eax, %ecx
0x00450d1e:	xorl %edx, %edx
0x00450d20:	xorl %ecx, %ecx
0x00450d22:	movl (%eax), $0x459f9c<UINT32>
0x004532c0:	movl %eax, $0x4627fc<UINT32>
0x004532c5:	jmp 0x0041bf46
0x0041bf46:	pushl %ebp
0x0041bf47:	movl %ebp, %esp
0x0041bf49:	subl %esp, $0x4<UINT8>
0x0041bf4c:	pushl %ebx
0x0041bf4d:	pushl %esi
0x0041bf4e:	pushl %edi
0x0041bf4f:	cld
0x0041bf50:	movl -4(%ebp), %eax
0x0041bf53:	xorl %eax, %eax
0x0041bf55:	pushl %eax
0x0041bf56:	pushl %eax
0x0041bf57:	pushl %eax
0x0041bf58:	pushl -4(%ebp)
0x0041bf5b:	pushl 0x14(%ebp)
0x0041bf5e:	pushl 0x10(%ebp)
0x0041bf61:	pushl 0xc(%ebp)
0x0041bf64:	pushl 0x8(%ebp)
0x0041bf67:	call 0x0041fdc2
0x0041fdc2:	pushl %ebp
0x0041fdc3:	movl %ebp, %esp
0x0041fdc5:	pushl %esi
0x0041fdc6:	movl %esi, 0x18(%ebp)
0x0041fdc9:	movl %eax, (%esi)
0x0041fdcb:	pushl %edi
0x0041fdcc:	andl %eax, $0x1fffffff<UINT32>
0x0041fdd1:	movl %edi, $0x19930520<UINT32>
0x0041fdd6:	cmpl %eax, %edi
0x0041fdd8:	je 0x0041fddf
0x0041fddf:	movl %eax, 0x8(%ebp)
0x0041fde2:	testb 0x4(%eax), $0x66<UINT8>
0x0041fde6:	je 0x0041fe07
0x0041fe07:	cmpl 0xc(%esi), $0x0<UINT8>
0x0041fe0b:	je 0x0041fe5d
0x0041fe5d:	xorl %eax, %eax
0x0041fe5f:	incl %eax
0x0041fe60:	popl %edi
0x0041fe61:	popl %esi
0x0041fe62:	popl %ebp
0x0041fe63:	ret

0x0041bf6c:	addl %esp, $0x20<UINT8>
0x0041bf6f:	movl -4(%ebp), %eax
0x0041bf72:	popl %edi
0x0041bf73:	popl %esi
0x0041bf74:	popl %ebx
0x0041bf75:	movl %eax, -4(%ebp)
0x0041bf78:	movl %esp, %ebp
0x0041bf7a:	popl %ebp
0x0041bf7b:	ret

0x00450d28:	movl 0x34(%eax), %edx
0x00450d2b:	movl 0x54(%eax), %edx
0x00450d2e:	movl 0x4c(%eax), %ecx
0x00450d31:	movl 0x50(%eax), %edx
0x00450d34:	ret

0x0044f5bd:	movl %ecx, -12(%ebp)
0x0044f5c0:	movl %fs:0, %ecx
0x0044f5c7:	leave
0x0044f5c8:	ret

0x00451b7e:	movl %ecx, 0x46a2ec
0x00451b84:	movl %edi, %eax
0x00451b86:	pushl %edi
0x00451b87:	pushl (%esi)
0x00451b89:	call 0x00451915
0x00451915:	pushl %ebp
0x00451916:	movl %ebp, %esp
0x00451918:	pushl %ecx
0x00451919:	pushl %ebx
0x0045191a:	pushl %esi
0x0045191b:	pushl %edi
0x0045191c:	movl %edi, %ecx
0x0045191e:	leal %esi, 0x1c(%edi)
0x00451921:	pushl %esi
0x00451922:	movl -4(%ebp), %esi
0x00451925:	call EnterCriticalSection@KERNEL32.DLL
0x0045192b:	movl %eax, 0x8(%ebp)
0x0045192e:	xorl %ebx, %ebx
0x00451930:	cmpl %eax, %ebx
0x00451932:	jle 214
0x00451938:	cmpl %eax, 0xc(%edi)
0x0045193b:	jge 205
0x00451941:	pushl (%edi)
0x00451943:	call TlsGetValue@KERNEL32.DLL
0x00451949:	movl %esi, %eax
0x0045194b:	cmpl %esi, %ebx
0x0045194d:	je 0x00451966
0x00451966:	pushl $0x10<UINT8>
0x00451968:	call 0x00451601
0x0045196d:	cmpl %eax, %ebx
0x0045196f:	je 11
0x00451971:	movl %ecx, %eax
0x00451973:	call 0x00451867
0x00451867:	movl %eax, %ecx
0x00451869:	movl (%eax), $0x45b228<UINT32>
0x0045395e:	movl %eax, $0x463804<UINT32>
0x00453963:	jmp 0x0041bf46
0x0045186f:	ret

0x00451978:	movl %esi, %eax
0x0045197a:	jmp 0x0045197e
0x0045197e:	movl 0x8(%esi), %ebx
0x00451981:	movl 0xc(%esi), %ebx
0x00451984:	movl %ecx, 0x14(%edi)
0x00451987:	movl %eax, 0x18(%edi)
0x0045198a:	movl (%esi,%eax), %ecx
0x0045198d:	movl 0x14(%edi), %esi
0x00451990:	movl %eax, 0xc(%esi)
0x00451993:	cmpl %eax, %ebx
0x00451995:	jne 0x004519a7
0x00451997:	movl %eax, 0xc(%edi)
0x0045199a:	shll %eax, $0x2<UINT8>
0x0045199d:	pushl %eax
0x0045199e:	pushl %ebx
0x0045199f:	call LocalAlloc@KERNEL32.DLL
0x004519a5:	jmp 0x004519b7
0x004519b7:	cmpl %eax, %ebx
0x004519b9:	jne 0x004519c9
0x004519c9:	movl %ecx, 0x8(%esi)
0x004519cc:	movl 0xc(%esi), %eax
0x004519cf:	movl %edx, 0xc(%edi)
0x004519d2:	subl %edx, %ecx
0x004519d4:	shll %edx, $0x2<UINT8>
0x004519d7:	pushl %edx
0x004519d8:	leal %eax, (%eax,%ecx,4)
0x004519db:	pushl %ebx
0x004519dc:	pushl %eax
0x004519dd:	call 0x0041e270
0x004519e2:	movl %eax, 0xc(%edi)
0x004519e5:	addl %esp, $0xc<UINT8>
0x004519e8:	pushl %esi
0x004519e9:	movl 0x8(%esi), %eax
0x004519ec:	pushl (%edi)
0x004519ee:	call TlsSetValue@KERNEL32.DLL
TlsSetValue@KERNEL32.DLL: API Node	
0x004519f4:	movl %ecx, 0x8(%ebp)
0x004519f7:	movl %eax, 0xc(%esi)
0x004519fa:	cmpl %eax, %ebx
0x004519fc:	je 11
0x004519fe:	cmpl %ecx, 0x8(%esi)
0x00451a01:	jnl 6
0x00451a03:	movl %edx, 0xc(%ebp)
0x00451a06:	movl (%eax,%ecx,4), %edx
0x00451a09:	pushl -4(%ebp)
0x00451a0c:	jmp 0x00451a0f
0x00451a0f:	call LeaveCriticalSection@KERNEL32.DLL
0x00451a15:	popl %edi
0x00451a16:	popl %esi
0x00451a17:	popl %ebx
0x00451a18:	leave
0x00451a19:	ret $0x8<UINT16>

0x00451b8e:	movl %ecx, -12(%ebp)
0x00451b91:	movl %eax, %edi
0x00451b93:	popl %edi
0x00451b94:	popl %esi
0x00451b95:	movl %fs:0, %ecx
0x00451b9c:	leave
0x00451b9d:	ret $0x4<UINT16>

0x00450fbe:	movl %eax, 0x4(%eax)
0x00450fc1:	testl %eax, %eax
0x00450fc3:	jne 15
0x00450fc5:	pushl $0x450f87<UINT32>
0x00450fca:	movl %ecx, $0x46a288<UINT32>
0x00450fcf:	call 0x00451795
0x00451795:	movl %eax, $0x453944<UINT32>
0x0045179a:	call 0x0041e2d0
0x0045179f:	pushl %ecx
0x004517a0:	pushl %ecx
0x004517a1:	pushl %ebx
0x004517a2:	pushl %esi
0x004517a3:	pushl %edi
0x004517a4:	movl %esi, %ecx
0x004517a6:	xorl %edi, %edi
0x004517a8:	cmpl (%esi), %edi
0x004517aa:	movl -16(%ebp), %esp
0x004517ad:	jne 0x004517cd
0x004517af:	pushl $0x10<UINT8>
0x004517b1:	call 0x00451cb8
0x00451cb8:	cmpl 0x46a520, $0x0<UINT8>
0x00451cbf:	jne 0x00451cc6
0x00451cc1:	call 0x00451c4f
0x00451c4f:	cmpl 0x46a520, $0x0<UINT8>
0x00451c56:	jne 21
0x00451c58:	pushl $0x46a36c<UINT32>
0x00451c5d:	movl 0x46a520, $0x1<UINT32>
0x00451c67:	call InitializeCriticalSection@KERNEL32.DLL
0x00451c6d:	movl %eax, 0x46a520
0x00451c72:	ret

0x00451cc6:	pushl %ebx
0x00451cc7:	movl %ebx, 0x4541b8
0x00451ccd:	pushl %esi
0x00451cce:	pushl %edi
0x00451ccf:	movl %edi, 0x10(%esp)
0x00451cd3:	leal %esi, 0x46a328(,%edi,4)
0x00451cda:	cmpl (%esi), $0x0<UINT8>
0x00451cdd:	jne 0x00451d08
0x00451cdf:	pushl %ebp
0x00451ce0:	movl %ebp, $0x46a36c<UINT32>
0x00451ce5:	pushl %ebp
0x00451ce6:	call EnterCriticalSection@KERNEL32.DLL
0x00451ce8:	cmpl (%esi), $0x0<UINT8>
0x00451ceb:	jne 19
0x00451ced:	leal %eax, (%edi,%edi,2)
0x00451cf0:	leal %eax, 0x46a388(,%eax,8)
0x00451cf7:	pushl %eax
0x00451cf8:	call InitializeCriticalSection@KERNEL32.DLL
0x00451cfe:	incl (%esi)
0x00451d00:	pushl %ebp
0x00451d01:	call LeaveCriticalSection@KERNEL32.DLL
0x00451d07:	popl %ebp
0x00451d08:	leal %eax, (%edi,%edi,2)
0x00451d0b:	leal %eax, 0x46a388(,%eax,8)
0x00451d12:	pushl %eax
0x00451d13:	call EnterCriticalSection@KERNEL32.DLL
0x00451d15:	popl %edi
0x00451d16:	popl %esi
0x00451d17:	popl %ebx
0x00451d18:	ret $0x4<UINT16>

0x004517b6:	cmpl (%esi), %edi
0x004517b8:	movl -4(%ebp), %edi
0x004517bb:	jne 5
0x004517bd:	call 0x00450f87
0x00450f87:	pushl $0x1074<UINT32>
0x00450f8c:	call 0x00451601
0x00450f91:	testl %eax, %eax
0x00450f93:	je 7
0x00450f95:	movl %ecx, %eax
0x00450f97:	jmp 0x00450f53
0x00450f53:	pushl %esi
0x00450f54:	pushl $0x1<UINT8>
0x00450f56:	movl %esi, %ecx
0x00450f58:	call 0x00450e96
0x00450e96:	movl %eax, %ecx
0x00450e98:	xorl %edx, %edx
0x00450e9a:	movl (%eax), $0x459fa4<UINT32>
0x00453944:	movl %eax, $0x4637e0<UINT32>
0x00453949:	jmp 0x0041bf46
0x0041fe0d:	cmpl (%eax), $0xe06d7363<UINT32>
0x0041fe13:	jne 0x0041fe41
0x0041fe41:	pushl 0x20(%ebp)
0x0041fe44:	pushl 0x1c(%ebp)
0x0041fe47:	pushl 0x24(%ebp)
0x0041fe4a:	pushl %esi
0x0041fe4b:	pushl 0x14(%ebp)
0x0041fe4e:	pushl 0x10(%ebp)
0x0041fe51:	pushl 0xc(%ebp)
0x0041fe54:	pushl %eax
0x0041fe55:	call 0x0041fbbe
0x0041fbbe:	pushl %ebp
0x0041fbbf:	movl %ebp, %esp
0x0041fbc1:	subl %esp, $0x24<UINT8>
0x0041fbc4:	movl %eax, 0xc(%ebp)
0x0041fbc7:	movl %eax, 0x8(%eax)
0x0041fbca:	cmpl %eax, $0xffffffff<UINT8>
0x0041fbcd:	movb -1(%ebp), $0x0<UINT8>
0x0041fbd1:	movl -28(%ebp), %eax
0x0041fbd4:	jl 8
0x0041fbd6:	movl %ecx, 0x18(%ebp)
0x0041fbd9:	cmpl %eax, 0x4(%ecx)
0x0041fbdc:	jl 0x0041fbe3
0x0041fbe3:	pushl %ebx
0x0041fbe4:	movl %ebx, 0x8(%ebp)
0x0041fbe7:	cmpl (%ebx), $0xe06d7363<UINT32>
0x0041fbed:	pushl %esi
0x0041fbee:	pushl %edi
0x0041fbef:	jne 0x0041fd97
0x0041fd97:	cmpb 0x1c(%ebp), $0x0<UINT8>
0x0041fd9b:	jne 32
0x0041fd9d:	pushl 0x24(%ebp)
0x0041fda0:	pushl 0x20(%ebp)
0x0041fda3:	pushl -28(%ebp)
0x0041fda6:	pushl 0x18(%ebp)
0x0041fda9:	pushl 0x14(%ebp)
0x0041fdac:	pushl 0x10(%ebp)
0x0041fdaf:	pushl 0xc(%ebp)
0x0041fdb2:	pushl %ebx
0x0041fdb3:	call 0x0041fb00
0x0041fb00:	pushl %ebp
0x0041fb01:	movl %ebp, %esp
0x0041fb03:	pushl %ecx
0x0041fb04:	pushl %ecx
0x0041fb05:	pushl %esi
0x0041fb06:	movl %esi, 0x8(%ebp)
0x0041fb09:	cmpl (%esi), $0x80000003<UINT32>
0x0041fb0f:	je 166
0x0041fb15:	call 0x0041fe9d
0x0041fe9d:	pushl %ebx
0x0041fe9e:	pushl %esi
0x0041fe9f:	call GetLastError@KERNEL32.DLL
GetLastError@KERNEL32.DLL: API Node	
0x0041fea5:	pushl 0x4673a4
0x0041feab:	movl %ebx, %eax
0x0041fead:	call FlsGetValue@kernel32.dll
FlsGetValue@kernel32.dll: API Node	
0x0041feb3:	movl %esi, %eax
0x0041feb5:	testl %esi, %esi
0x0041feb7:	jne 0x0041ff02
0x0041ff02:	pushl %ebx
0x0041ff03:	call SetLastError@KERNEL32.DLL
SetLastError@KERNEL32.DLL: API Node	
0x0041ff09:	movl %eax, %esi
0x0041ff0b:	popl %esi
0x0041ff0c:	popl %ebx
0x0041ff0d:	ret

0x0041fb1a:	cmpl 0x74(%eax), $0x0<UINT8>
0x0041fb1e:	je 0x0041fb3f
0x0041fb3f:	movl %esi, 0x1c(%ebp)
0x0041fb42:	pushl %edi
0x0041fb43:	leal %eax, -8(%ebp)
0x0041fb46:	pushl %eax
0x0041fb47:	leal %eax, -4(%ebp)
0x0041fb4a:	pushl %eax
0x0041fb4b:	pushl %esi
0x0041fb4c:	pushl 0x20(%ebp)
0x0041fb4f:	pushl 0x18(%ebp)
0x0041fb52:	call 0x0041c130
0x0041c130:	pushl %ebp
0x0041c131:	movl %ebp, %esp
0x0041c133:	pushl %ecx
0x0041c134:	cmpl 0xc(%ebp), $0x0<UINT8>
0x0041c138:	pushl %ebx
0x0041c139:	pushl %esi
0x0041c13a:	pushl %edi
0x0041c13b:	movl %edi, 0x8(%ebp)
0x0041c13e:	movl %esi, 0xc(%edi)
0x0041c141:	movl %ebx, 0x10(%edi)
0x0041c144:	movl %eax, %esi
0x0041c146:	movl -4(%ebp), %eax
0x0041c149:	movl 0x8(%ebp), %esi
0x0041c14c:	jl 56
0x0041c14e:	cmpl %esi, $0xffffffff<UINT8>
0x0041c151:	jne 0x0041c158
0x0041c158:	movl %ecx, 0x10(%ebp)
0x0041c15b:	decl %esi
0x0041c15c:	leal %eax, (%esi,%esi,4)
0x0041c15f:	leal %eax, (%ebx,%eax,4)
0x0041c162:	cmpl 0x4(%eax), %ecx
0x0041c165:	jnl 0x0041c16c
0x0041c16c:	cmpl %esi, $0xffffffff<UINT8>
0x0041c16f:	jne 0x0041c17d
0x0041c17d:	cmpl 0xc(%ebp), $0x0<UINT8>
0x0041c181:	jnl 0x0041c14e
0x0041c171:	movl %eax, 0x8(%ebp)
0x0041c174:	decl 0xc(%ebp)
0x0041c177:	movl -4(%ebp), %eax
0x0041c17a:	movl 0x8(%ebp), %esi
0x0041c183:	movl %eax, -4(%ebp)
0x0041c186:	movl %ecx, 0x14(%ebp)
0x0041c189:	incl %esi
0x0041c18a:	movl (%ecx), %esi
0x0041c18c:	movl %ecx, 0x18(%ebp)
0x0041c18f:	movl (%ecx), %eax
0x0041c191:	cmpl %eax, 0xc(%edi)
0x0041c194:	ja 4
0x0041c196:	cmpl %esi, %eax
0x0041c198:	jbe 0x0041c19f
0x0041c19f:	popl %edi
0x0041c1a0:	leal %eax, (%esi,%esi,4)
0x0041c1a3:	popl %esi
0x0041c1a4:	leal %eax, (%ebx,%eax,4)
0x0041c1a7:	popl %ebx
0x0041c1a8:	leave
0x0041c1a9:	ret

0x0041fb57:	movl %edi, %eax
0x0041fb59:	movl %eax, -4(%ebp)
0x0041fb5c:	addl %esp, $0x14<UINT8>
0x0041fb5f:	cmpl %eax, -8(%ebp)
0x0041fb62:	jae 86
0x0041fb64:	pushl %ebx
0x0041fb65:	cmpl %esi, (%edi)
0x0041fb67:	jl 66
0x0041fb69:	cmpl %esi, 0x4(%edi)
0x0041fb6c:	jg 61
0x0041fb6e:	movl %eax, 0xc(%edi)
0x0041fb71:	movl %ecx, 0x10(%edi)
0x0041fb74:	shll %eax, $0x4<UINT8>
0x0041fb77:	addl %eax, %ecx
0x0041fb79:	movl %ecx, -12(%eax)
0x0041fb7c:	testl %ecx, %ecx
0x0041fb7e:	je 6
0x0041fb80:	cmpb 0x8(%ecx), $0x0<UINT8>
0x0041fb84:	jne 0x0041fbab
0x0041fbab:	incl -4(%ebp)
0x0041fbae:	movl %eax, -4(%ebp)
0x0041fbb1:	addl %edi, $0x14<UINT8>
0x0041fbb4:	cmpl %eax, -8(%ebp)
0x0041fbb7:	jb -84
0x0041fbb9:	popl %ebx
0x0041fbba:	popl %edi
0x0041fbbb:	popl %esi
0x0041fbbc:	leave
0x0041fbbd:	ret

0x0041fdb8:	addl %esp, $0x20<UINT8>
0x0041fdbb:	jmp 0x0041fd8f
0x0041fd8f:	popl %edi
0x0041fd90:	popl %esi
0x0041fd91:	popl %ebx
0x0041fd92:	leave
0x0041fd93:	ret

0x0041fe5a:	addl %esp, $0x20<UINT8>
0x00450ea0:	movl 0x1c(%eax), %edx
0x00450ea3:	movl 0x20(%eax), %edx
0x00450ea6:	movl 0x24(%eax), %edx
0x00450ea9:	movl 0x28(%eax), %edx
0x00450eac:	leal %ecx, 0x103c(%eax)
0x00450eb2:	movl (%ecx), %edx
0x00450eb4:	movl 0x4(%ecx), %edx
0x00450eb7:	leal %ecx, 0x1048(%eax)
0x00450ebd:	orl 0x4(%ecx), $0xffffffff<UINT8>
0x00450ec1:	movl 0x8(%ecx), %edx
0x00450ec4:	movl 0x1c(%ecx), %edx
0x00450ec7:	movl 0x20(%ecx), %edx
0x00450eca:	movb %cl, 0x4(%esp)
0x00450ece:	movl 0x28(%eax), $0x1c<UINT32>
0x00450ed5:	movl 0x20(%eax), $0x14<UINT32>
0x00450edc:	movl 0x18(%eax), %edx
0x00450edf:	movb 0x14(%eax), %cl
0x00450ee2:	movl 0x30(%eax), $0x1<UINT32>
0x00450ee9:	movl 0x1040(%eax), $0x18<UINT32>
0x00450ef3:	ret $0x4<UINT16>

0x00450f5d:	movl (%esi), $0x459fb4<UINT32>
0x00450f63:	movl %eax, %esi
0x00450f65:	popl %esi
0x00450f66:	ret

0x004517c0:	movl (%esi), %eax
0x004517c2:	orl -4(%ebp), $0xffffffff<UINT8>
0x004517c6:	pushl $0x10<UINT8>
0x004517c8:	call 0x00451d1b
0x00451d1b:	movl %eax, 0x4(%esp)
0x00451d1f:	leal %eax, (%eax,%eax,2)
0x00451d22:	leal %eax, 0x46a388(,%eax,8)
0x00451d29:	pushl %eax
0x00451d2a:	call LeaveCriticalSection@KERNEL32.DLL
0x00451d30:	ret $0x4<UINT16>

0x004517cd:	movl %eax, (%esi)
0x004517cf:	movl %ecx, -12(%ebp)
0x004517d2:	popl %edi
0x004517d3:	popl %esi
0x004517d4:	movl %fs:0, %ecx
0x004517db:	popl %ebx
0x004517dc:	leave
0x004517dd:	ret $0x4<UINT16>

0x00450fd4:	ret

0x0043cf3e:	movl %ecx, 0x4(%esp)
0x0043cf42:	testl %ecx, %ecx
0x0043cf44:	movb 0x14(%eax), %cl
0x0043cf47:	jne 8
0x0043cf49:	pushl $0xfffffffd<UINT8>
0x0043cf4b:	call 0x0041f378
0x0041f4aa:	movl -32(%ebp), %edi
0x0043cf50:	popl %ecx
0x0043cf51:	xorl %eax, %eax
0x0043cf53:	incl %eax
0x0043cf54:	ret $0x8<UINT16>

0x00453bf8:	pushl $0x43cf57<UINT32>
0x00453bfd:	call 0x0041c7ad
0x00453c02:	popl %ecx
0x00453c03:	movb 0x46aa70, %al
0x00453c08:	ret

0x00453bc0:	movl %ecx, $0x468520<UINT32>
0x00453bc5:	call 0x004042b0
0x004042b0:	pushl %esi
0x004042b1:	pushl $0x0<UINT8>
0x004042b3:	movl %esi, %ecx
0x004042b5:	call 0x004508a0
0x004508a0:	movl %eax, $0x4536c8<UINT32>
0x004508a5:	call 0x0041e2d0
0x004508aa:	pushl %ecx
0x004508ab:	pushl %ebx
0x004508ac:	pushl %esi
0x004508ad:	movl %esi, %ecx
0x004508af:	pushl %edi
0x004508b0:	movl -16(%ebp), %esi
0x004508b3:	call 0x00450ca0
0x00450ca0:	movl %eax, $0x453736<UINT32>
0x00450ca5:	call 0x0041e2d0
0x00450caa:	pushl %ecx
0x00450cab:	pushl %esi
0x00450cac:	movl %esi, %ecx
0x00450cae:	movl -16(%ebp), %esi
0x00450cb1:	call 0x00443e87
0x00443e87:	movl %eax, %ecx
0x00443e89:	xorl %edx, %edx
0x00443e8b:	xorl %ecx, %ecx
0x00443e8d:	incl %ecx
0x00443e8e:	movl 0x4(%eax), %ecx
0x00443e91:	movl 0x8(%eax), %edx
0x00443e94:	movl 0xc(%eax), %edx
0x00443e97:	movl 0x10(%eax), %edx
0x00443e9a:	movl 0x14(%eax), %ecx
0x00443e9d:	movl 0x18(%eax), %edx
0x00443ea0:	ret

0x00450cb6:	xorl %eax, %eax
0x00450cb8:	movl %ecx, %esi
0x00450cba:	movl -4(%ebp), %eax
0x00450cbd:	movl (%esi), $0x459f1c<UINT32>
0x00450cc3:	movl 0x30(%esi), %eax
0x00450cc6:	movl 0x34(%esi), %eax
0x00450cc9:	call 0x00450c03
0x00450c03:	pushl %esi
0x00450c04:	movl %esi, %ecx
0x00450c06:	pushl %edi
0x00450c07:	xorl %edi, %edi
0x00450c09:	movl 0x1c(%esi), %edi
0x00450c0c:	movl 0x20(%esi), %edi
0x00450c0f:	movl 0x28(%esi), %edi
0x00450c12:	movl 0x2c(%esi), %edi
0x00450c15:	call 0x00450f9f
0x00450f9f:	pushl $0x44f595<UINT32>
0x00450fa4:	movl %ecx, $0x46a284<UINT32>
0x00450fa9:	call 0x00451b26
0x0045175d:	cmpl %edi, 0x8(%eax)
0x00451760:	jnl 0x0045176a
0x00451762:	movl %eax, 0xc(%eax)
0x00451765:	movl %edi, (%eax,%edi,4)
0x00451768:	jmp 0x0045176c
0x00450fae:	ret

0x00450c1a:	movl 0x34(%eax), %edi
0x00450c1d:	movl 0x54(%eax), %edi
0x00450c20:	addl %eax, $0x4c<UINT8>
0x00450c23:	pushl %eax
0x00450c24:	call GetCursorPos@USER32.dll
GetCursorPos@USER32.dll: API Node	
0x00450c2a:	movl 0x3c(%esi), %edi
0x00450c2d:	movl 0x38(%esi), %edi
0x00450c30:	popl %edi
0x00450c31:	movl 0x24(%esi), $0x1<UINT32>
0x00450c38:	popl %esi
0x00450c39:	ret

0x00450cce:	movl %ecx, -12(%ebp)
0x00450cd1:	movl %eax, %esi
0x00450cd3:	popl %esi
0x00450cd4:	movl %fs:0, %ecx
0x00450cdb:	leave
0x00450cdc:	ret

0x004508b8:	xorl %edi, %edi
0x004508ba:	cmpl 0x8(%ebp), %edi
0x004508bd:	movl -4(%ebp), %edi
0x004508c0:	movl (%esi), $0x459e2c<UINT32>
0x004508c6:	je 0x004508d6
0x004508d6:	movl 0x4c(%esi), %edi
0x004508d9:	call 0x00450faf
0x004508de:	movl %ebx, %eax
0x004508e0:	pushl $0x45022d<UINT32>
0x004508e5:	leal %ecx, 0x1070(%ebx)
0x004508eb:	call 0x00451b26
0x0045164a:	movl %ecx, 0x10(%esi)
0x0045164d:	testb (%ecx,%edi,8), $0x1<UINT8>
0x00451651:	je 0x0045170b
0x0045022d:	movl %eax, $0x453575<UINT32>
0x00450232:	call 0x0041e2d0
0x00450237:	pushl %ecx
0x00450238:	pushl $0x80<UINT32>
0x0045023d:	call 0x00451601
0x00450242:	movl %ecx, %eax
0x00450244:	movl -16(%ebp), %ecx
0x00450247:	xorl %eax, %eax
0x00450249:	cmpl %ecx, %eax
0x0045024b:	movl -4(%ebp), %eax
0x0045024e:	je 5
0x00450250:	call 0x00450f11
0x00450f11:	movl %eax, %ecx
0x00450f13:	movl (%eax), $0x459fac<UINT32>
0x00453575:	movl %eax, $0x462fa4<UINT32>
0x0045357a:	jmp 0x0041bf46
0x00450f19:	andl 0x8(%eax), $0x0<UINT8>
0x00450f1d:	andl 0xc(%eax), $0x0<UINT8>
0x00450f21:	orl 0x44(%eax), $0xffffffff<UINT8>
0x00450f25:	orl 0x78(%eax), $0xffffffff<UINT8>
0x00450f29:	movl 0xc(%eax), $0x68<UINT32>
0x00450f30:	movl 0x28(%eax), $0x444374<UINT32>
0x00450f37:	ret

0x00450255:	movl %ecx, -12(%ebp)
0x00450258:	movl %fs:0, %ecx
0x0045025f:	leave
0x00450260:	ret

0x0045194f:	movl %ecx, 0x8(%ebp)
0x00451952:	cmpl %ecx, 0x8(%esi)
0x00451955:	jl 0x004519f7
0x0045195b:	cmpl 0xc(%ebp), %ebx
0x0045195e:	je 147
0x00451964:	jmp 0x00451990
0x004519a7:	movl %ecx, 0xc(%edi)
0x004519aa:	pushl $0x2<UINT8>
0x004519ac:	shll %ecx, $0x2<UINT8>
0x004519af:	pushl %ecx
0x004519b0:	pushl %eax
0x004519b1:	call LocalReAlloc@KERNEL32.DLL
LocalReAlloc@KERNEL32.DLL: API Node	
0x004508f0:	movl 0x4(%eax), %esi
0x004508f3:	call GetCurrentThread@KERNEL32.DLL
GetCurrentThread@KERNEL32.DLL: API Node	
0x004508f9:	movl 0x28(%esi), %eax
0x004508fc:	call GetCurrentThreadId@KERNEL32.DLL
0x00450902:	movl %ecx, -12(%ebp)
0x00450905:	movl 0x2c(%esi), %eax
0x00450908:	movl 0x4(%ebx), %esi
0x0045090b:	movl 0x40(%esi), %edi
0x0045090e:	movl 0x78(%esi), %edi
0x00450911:	movl 0x60(%esi), %edi
0x00450914:	movl 0x64(%esi), %edi
0x00450917:	movl 0x50(%esi), %edi
0x0045091a:	movl 0x5c(%esi), %edi
0x0045091d:	movl 0x84(%esi), %edi
0x00450923:	movl 0x54(%esi), %edi
0x00450926:	movw 0x8e(%esi), %di
0x0045092d:	movw 0x8c(%esi), %di
0x00450934:	movl 0x44(%esi), %edi
0x00450937:	movl 0x88(%esi), %edi
0x0045093d:	movl 0x7c(%esi), %edi
0x00450940:	movl 0x80(%esi), %edi
0x00450946:	movl 0x6c(%esi), %edi
0x00450949:	movl 0x70(%esi), %edi
0x0045094c:	movl 0x90(%esi), %edi
0x00450952:	movl 0x98(%esi), %edi
0x00450958:	movl 0x58(%esi), %edi
0x0045095b:	movl 0x68(%esi), %edi
0x0045095e:	popl %edi
0x0045095f:	movl 0x94(%esi), $0x200<UINT32>
0x00450969:	movl %eax, %esi
0x0045096b:	popl %esi
0x0045096c:	popl %ebx
0x0045096d:	movl %fs:0, %ecx
0x00450974:	leave
0x00450975:	ret $0x4<UINT16>

0x004042ba:	movl (%esi), $0x454fa0<UINT32>
0x004042c0:	movl %eax, %esi
0x004042c2:	popl %esi
0x004042c3:	ret

0x00453bca:	pushl $0x453c10<UINT32>
0x00453bcf:	call 0x0041c7ad
0x00453bd4:	popl %ecx
0x00453bd5:	ret

0x004437dd:	pushl $0x44385a<UINT32>
0x004437e2:	call 0x0041c7ad
0x004437e7:	popl %ecx
0x004437e8:	ret

0x004437e9:	pushl $0x458ac8<UINT32>
0x004437ee:	call RegisterClipboardFormatA@USER32.dll
RegisterClipboardFormatA@USER32.dll: API Node	
0x004437f4:	movl 0x469e08, %eax
0x004437f9:	ret

0x004437fa:	pushl $0x0<UINT8>
0x004437fc:	movl %ecx, $0x469e10<UINT32>
0x00443801:	call 0x0043fe12
0x0043fe12:	pushl %esi
0x0043fe13:	movl %esi, %ecx
0x0043fe15:	call 0x00443e87
0x0043fe1a:	movl %eax, 0x8(%esp)
0x0043fe1e:	movl (%esi), $0x4587fc<UINT32>
0x0043fe24:	movl 0x2c(%esi), $0x45876c<UINT32>
0x0043fe2b:	movl 0x30(%esi), $0x4587e0<UINT32>
0x0043fe32:	movl 0x1c(%esi), %eax
0x0043fe35:	xorl %eax, %eax
0x0043fe37:	movb 0x20(%esi), %al
0x0043fe3a:	movl 0x28(%esi), %eax
0x0043fe3d:	movl 0x34(%esi), %eax
0x0043fe40:	movl 0x38(%esi), %eax
0x0043fe43:	movl 0x3c(%esi), %eax
0x0043fe46:	movl 0x40(%esi), %eax
0x0043fe49:	movl 0x44(%esi), %eax
0x0043fe4c:	movl 0x48(%esi), %eax
0x0043fe4f:	movl 0x4c(%esi), %eax
0x0043fe52:	movl %eax, %esi
0x0043fe54:	popl %esi
0x0043fe55:	ret $0x4<UINT16>

0x00443806:	pushl $0x443864<UINT32>
0x0044380b:	call 0x0041c7ad
0x00443810:	popl %ecx
0x00443811:	ret

0x00443812:	pushl $0x1<UINT8>
0x00443814:	movl %ecx, $0x469e60<UINT32>
0x00443819:	call 0x0043fe12
0x0044381e:	pushl $0x44386e<UINT32>
0x00443823:	call 0x0041c7ad
0x00443828:	popl %ecx
0x00443829:	ret

0x0044382a:	pushl $0xffffffff<UINT8>
0x0044382c:	movl %ecx, $0x469eb0<UINT32>
0x00443831:	call 0x0043fe12
0x00443836:	pushl $0x443878<UINT32>
0x0044383b:	call 0x0041c7ad
0x00443840:	popl %ecx
0x00443841:	ret

0x00443842:	pushl $0xfffffffe<UINT8>
0x00443844:	movl %ecx, $0x469f00<UINT32>
0x00443849:	call 0x0043fe12
0x0044384e:	pushl $0x443882<UINT32>
0x00443853:	call 0x0041c7ad
0x00443858:	popl %ecx
0x00443859:	ret

0x0044ff52:	pushl $0xf023<UINT32>
0x0044ff57:	pushl $0x0<UINT8>
0x0044ff59:	movl %ecx, $0x469f70<UINT32>
0x0044ff5e:	call 0x0041b67c
0x0041b67c:	pushl %esi
0x0041b67d:	pushl 0x8(%esp)
0x0041b681:	movl %esi, %ecx
0x0041b683:	call 0x0041b648
0x0041b648:	pushl 0x4(%esp)
0x0041b64c:	movl %edx, %ecx
0x0041b64e:	call 0x00444446
0x00444446:	movl %eax, %ecx
0x00444448:	movl %ecx, 0x4(%esp)
0x0044444c:	movl 0x4(%eax), %ecx
0x0044444f:	ret $0x4<UINT16>

0x0041b653:	andl 0xc(%edx), $0x0<UINT8>
0x0041b657:	andl 0x10(%edx), $0x0<UINT8>
0x0041b65b:	movl %eax, %edx
0x0041b65d:	ret $0x4<UINT16>

0x0041b688:	movl %eax, 0xc(%esp)
0x0041b68c:	movl 0x94(%esi), %eax
0x0041b692:	movl (%esi), $0x458ea8<UINT32>
0x0041b698:	movl %eax, %esi
0x0041b69a:	popl %esi
0x0041b69b:	ret $0x8<UINT16>

0x0044ff63:	pushl $0x44ffa9<UINT32>
0x0044ff68:	call 0x0041c7ad
0x0044ff6d:	popl %ecx
0x0044ff6e:	ret

0x0044ff6f:	pushl $0xf021<UINT32>
0x0044ff74:	pushl $0x0<UINT8>
0x0044ff76:	movl %ecx, $0x46a008<UINT32>
0x0044ff7b:	call 0x0041b6ba
0x0041b6ba:	pushl %esi
0x0041b6bb:	pushl 0x8(%esp)
0x0041b6bf:	movl %esi, %ecx
0x0041b6c1:	call 0x0041b648
0x0041b6c6:	movl %eax, 0xc(%esp)
0x0041b6ca:	movl 0x94(%esi), %eax
0x0041b6d0:	movl (%esi), $0x458ec0<UINT32>
0x0041b6d6:	movl %eax, %esi
0x0041b6d8:	popl %esi
0x0041b6d9:	ret $0x8<UINT16>

0x0044ff80:	pushl $0x44ffb3<UINT32>
0x0044ff85:	call 0x0041c7ad
0x0044ff8a:	popl %ecx
0x0044ff8b:	ret

0x0044ff8c:	pushl $0xf025<UINT32>
0x0044ff91:	pushl $0x0<UINT8>
0x0044ff93:	movl %ecx, $0x46a0a0<UINT32>
0x0044ff98:	call 0x0041b6f8
0x0041b6f8:	pushl %esi
0x0041b6f9:	pushl 0x8(%esp)
0x0041b6fd:	movl %esi, %ecx
0x0041b6ff:	call 0x0041b648
0x0041b704:	movl %eax, 0xc(%esp)
0x0041b708:	movl 0x94(%esi), %eax
0x0041b70e:	movl (%esi), $0x458ed8<UINT32>
0x0041b714:	movl %eax, %esi
0x0041b716:	popl %esi
0x0041b717:	ret $0x8<UINT16>

0x0044ff9d:	pushl $0x44ffbd<UINT32>
0x0044ffa2:	call 0x0041c7ad
0x0044ffa7:	popl %ecx
0x0044ffa8:	ret

0x0044ffe6:	pushl $0x466ad8<UINT32>
0x0044ffeb:	call 0x0044588d
0x0044588d:	pushl %esi
0x0044588e:	call 0x00450faf
0x00445893:	pushl $0x0<UINT8>
0x00445895:	movl %esi, %eax
0x00445897:	call 0x00451cb8
0x0044589c:	pushl 0x8(%esp)
0x004458a0:	leal %ecx, 0x1c(%esi)
0x004458a3:	call 0x00451816
0x00451816:	movl %eax, 0x4(%esp)
0x0045181a:	movl %edx, 0x4(%ecx)
0x0045181d:	pushl %esi
0x0045181e:	movl %esi, (%ecx)
0x00451820:	movl (%eax,%edx), %esi
0x00451823:	movl (%ecx), %eax
0x00451825:	popl %esi
0x00451826:	ret $0x4<UINT16>

0x004458a8:	pushl $0x0<UINT8>
0x004458aa:	call 0x00451d1b
0x004458af:	popl %esi
0x004458b0:	ret $0x4<UINT16>

0x0044fff0:	ret

0x004501d3:	pushl $0xf022<UINT32>
0x004501d8:	pushl $0x0<UINT8>
0x004501da:	movl %ecx, $0x46a140<UINT32>
0x004501df:	call 0x0041b727
0x0041b727:	pushl %esi
0x0041b728:	pushl 0x8(%esp)
0x0041b72c:	movl %esi, %ecx
0x0041b72e:	call 0x0041b648
0x0041b733:	movl %eax, 0xc(%esp)
0x0041b737:	movl 0x94(%esi), %eax
0x0041b73d:	movl (%esi), $0x45927c<UINT32>
0x0041b743:	movl %eax, %esi
0x0041b745:	popl %esi
0x0041b746:	ret $0x8<UINT16>

0x004501e4:	pushl $0x45020d<UINT32>
0x004501e9:	call 0x0041c7ad
0x004501ee:	popl %ecx
0x004501ef:	ret

0x004501f0:	pushl $0xf024<UINT32>
0x004501f5:	pushl $0x0<UINT8>
0x004501f7:	movl %ecx, $0x46a1d8<UINT32>
0x004501fc:	call 0x0041b750
0x0041b750:	pushl %esi
0x0041b751:	pushl 0x8(%esp)
0x0041b755:	movl %esi, %ecx
0x0041b757:	call 0x0041b648
0x0041b75c:	movl %eax, 0xc(%esp)
0x0041b760:	movl 0x94(%esi), %eax
0x0041b766:	movl (%esi), $0x459294<UINT32>
0x0041b76c:	movl %eax, %esi
0x0041b76e:	popl %esi
0x0041b76f:	ret $0x8<UINT16>

0x00450201:	pushl $0x450217<UINT32>
0x00450206:	call 0x0041c7ad
0x0045020b:	popl %ecx
0x0045020c:	ret

0x0044e644:	pushl %esi
0x0044e645:	movl %esi, 0x454248
0x0044e64b:	pushl %edi
0x0044e64c:	call GetVersion@KERNEL32.DLL
GetVersion@KERNEL32.DLL: API Node	
0x0044e64e:	movl %edi, $0x80000000<UINT32>
0x0044e653:	testl %edi, %eax
0x0044e655:	je 0x0044e65f
0x0044e65f:	call GetVersion@KERNEL32.DLL
0x0044e661:	testl %edi, %eax
0x0044e663:	jne 26
0x0044e665:	call GetVersion@KERNEL32.DLL
0x0044e667:	cmpw %ax, $0x3<UINT16>
0x0044e66b:	jne 0x0044e67f
0x0044e67f:	andl 0x46a270, $0x0<UINT8>
0x0044e686:	popl %edi
0x0044e687:	popl %esi
0x0044e688:	ret

0x004515e0:	movl %ecx, $0x46a290<UINT32>
0x004515e5:	call 0x0045158b
0x0045158b:	pushl %ebx
0x0045158c:	pushl %esi
0x0045158d:	pushl %edi
0x0045158e:	movl %esi, %ecx
0x00451590:	call GetVersion@KERNEL32.DLL
0x00451596:	shrl %eax, $0x1f<UINT8>
0x00451599:	movl %ecx, %esi
0x0045159b:	movl 0x54(%esi), %eax
0x0045159e:	call 0x00445ced
0x00445ced:	pushl %ebx
0x00445cee:	pushl %esi
0x00445cef:	pushl %edi
0x00445cf0:	movl %edi, 0x454588
0x00445cf6:	pushl $0xb<UINT8>
0x00445cf8:	movl %esi, %ecx
0x00445cfa:	call GetSystemMetrics@USER32.dll
GetSystemMetrics@USER32.dll: API Node	
0x00445cfc:	pushl $0xc<UINT8>
0x00445cfe:	movl 0x8(%esi), %eax
0x00445d01:	call GetSystemMetrics@USER32.dll
0x00445d03:	pushl $0x2<UINT8>
0x00445d05:	movl 0xc(%esi), %eax
0x00445d08:	call GetSystemMetrics@USER32.dll
0x00445d0a:	incl %eax
0x00445d0b:	pushl $0x3<UINT8>
0x00445d0d:	movl 0x46a290, %eax
0x00445d12:	call GetSystemMetrics@USER32.dll
0x00445d14:	incl %eax
0x00445d15:	pushl $0x0<UINT8>
0x00445d17:	movl 0x46a294, %eax
0x00445d1c:	call GetDC@USER32.dll
GetDC@USER32.dll: API Node	
0x00445d22:	movl %ebx, 0x4540b0
0x00445d28:	movl %edi, %eax
0x00445d2a:	pushl $0x58<UINT8>
0x00445d2c:	pushl %edi
0x00445d2d:	call GetDeviceCaps@GDI32.dll
GetDeviceCaps@GDI32.dll: API Node	
0x00445d2f:	pushl $0x5a<UINT8>
0x00445d31:	pushl %edi
0x00445d32:	movl 0x18(%esi), %eax
0x00445d35:	call GetDeviceCaps@GDI32.dll
0x00445d37:	pushl %edi
0x00445d38:	pushl $0x0<UINT8>
0x00445d3a:	movl 0x1c(%esi), %eax
0x00445d3d:	call ReleaseDC@USER32.dll
ReleaseDC@USER32.dll: API Node	
0x00445d43:	popl %edi
0x00445d44:	popl %esi
0x00445d45:	popl %ebx
0x00445d46:	ret

0x004515a3:	xorl %ebx, %ebx
0x004515a5:	movl %ecx, %esi
0x004515a7:	movl 0x24(%esi), %ebx
0x004515aa:	call 0x00445ca9
0x00445ca9:	pushl %esi
0x00445caa:	pushl %edi
0x00445cab:	movl %edi, 0x454584
0x00445cb1:	pushl $0xf<UINT8>
0x00445cb3:	movl %esi, %ecx
0x00445cb5:	call GetSysColor@USER32.dll
GetSysColor@USER32.dll: API Node	
0x00445cb7:	pushl $0x10<UINT8>
0x00445cb9:	movl 0x28(%esi), %eax
0x00445cbc:	call GetSysColor@USER32.dll
0x00445cbe:	pushl $0x14<UINT8>
0x00445cc0:	movl 0x2c(%esi), %eax
0x00445cc3:	call GetSysColor@USER32.dll
0x00445cc5:	pushl $0x12<UINT8>
0x00445cc7:	movl 0x30(%esi), %eax
0x00445cca:	call GetSysColor@USER32.dll
0x00445ccc:	pushl $0x6<UINT8>
0x00445cce:	movl 0x34(%esi), %eax
0x00445cd1:	call GetSysColor@USER32.dll
0x00445cd3:	movl %edi, 0x454370
0x00445cd9:	pushl $0xf<UINT8>
0x00445cdb:	movl 0x38(%esi), %eax
0x00445cde:	call GetSysColorBrush@USER32.dll
GetSysColorBrush@USER32.dll: API Node	
0x00445ce0:	pushl $0x6<UINT8>
0x00445ce2:	movl 0x24(%esi), %eax
0x00445ce5:	call GetSysColorBrush@USER32.dll
0x00445ce7:	popl %edi
0x00445ce8:	movl 0x20(%esi), %eax
0x00445ceb:	popl %esi
0x00445cec:	ret

0x004515af:	movl %edi, 0x454558
0x004515b5:	pushl $0x7f02<UINT32>
0x004515ba:	pushl %ebx
0x004515bb:	call LoadCursorA@USER32.dll
LoadCursorA@USER32.dll: API Node	
0x004515bd:	pushl $0x7f00<UINT32>
0x004515c2:	pushl %ebx
0x004515c3:	movl 0x3c(%esi), %eax
0x004515c6:	call LoadCursorA@USER32.dll
0x004515c8:	pushl $0x2<UINT8>
0x004515ca:	movl 0x40(%esi), %eax
0x004515cd:	popl %eax
0x004515ce:	movl 0x10(%esi), %eax
0x004515d1:	movl 0x14(%esi), %eax
0x004515d4:	popl %edi
0x004515d5:	movl 0x50(%esi), %ebx
0x004515d8:	movl 0x44(%esi), %ebx
0x004515db:	movl %eax, %esi
0x004515dd:	popl %esi
0x004515de:	popl %ebx
0x004515df:	ret

0x004515ea:	pushl $0x4515f6<UINT32>
0x004515ef:	call 0x0041c7ad
0x004515f4:	popl %ecx
0x004515f5:	ret

0x00451d6c:	call 0x00451d39
0x00451d39:	pushl %ebp
0x00451d3a:	movl %ebp, %esp
0x00451d3c:	subl %esp, $0x18<UINT8>
0x00451d3f:	movl %eax, 0x467108
0x00451d44:	movl -4(%ebp), %eax
0x00451d47:	leal %eax, -24(%ebp)
0x00451d4a:	pushl %eax
0x00451d4b:	call GetOEMCP@KERNEL32.DLL
GetOEMCP@KERNEL32.DLL: API Node	
0x00451d51:	pushl %eax
0x00451d52:	call GetCPInfo@KERNEL32.DLL
0x00451d58:	movl %ecx, -4(%ebp)
0x00451d5b:	xorl %eax, %eax
0x00451d5d:	incl %eax
0x00451d5e:	cmpl %eax, -24(%ebp)
0x00451d61:	sbbl %eax, %eax
0x00451d63:	negl %eax
0x00451d65:	call 0x0041e200
0x00451d6a:	leave
0x00451d6b:	ret

0x00451d71:	movl 0x46a524, %eax
0x00451d76:	ret

0x00451eb7:	pushl $0x467070<UINT32>
0x00451ebc:	call 0x0044588d
0x00451ec1:	ret

0x0044f560:	pushl $0x45b93c<UINT32>
0x0044f565:	call RegisterClipboardFormatA@USER32.dll
0x0044f56b:	movl 0x46a544, %eax
0x0044f570:	ret

0x0041d6d4:	xorl %eax, %eax
0x0041d6d6:	popl %edi
0x0041d6d7:	popl %esi
0x0041d6d8:	ret

0x0041e13d:	popl %ecx
0x0041e13e:	movl -40(%ebp), %eax
0x0041e141:	cmpl %eax, %esi
0x0041e143:	je 0x0041e14c
0x0041e14c:	movl -68(%ebp), %esi
0x0041e14f:	leal %eax, -112(%ebp)
0x0041e152:	pushl %eax
0x0041e153:	call GetStartupInfoA@KERNEL32.DLL
0x0041e159:	call 0x00423adc
0x00423adc:	pushl %esi
0x00423add:	pushl %edi
0x00423ade:	xorl %edi, %edi
0x00423ae0:	cmpl 0x46be30, %edi
0x00423ae6:	jne 0x00423aed
0x00423aed:	movl %esi, 0x46be20
0x00423af3:	testl %esi, %esi
0x00423af5:	jne 0x00423afc
0x00423afc:	movb %al, (%esi)
0x00423afe:	cmpb %al, $0x20<UINT8>
0x00423b00:	ja 0x00423b0a
0x00423b0a:	cmpb %al, $0x22<UINT8>
0x00423b0c:	jne 0x00423b17
0x00423b0e:	xorl %ecx, %ecx
0x00423b10:	testl %edi, %edi
0x00423b12:	sete %cl
0x00423b15:	movl %edi, %ecx
0x00423b17:	movzbl %eax, %al
0x00423b1a:	pushl %eax
0x00423b1b:	call 0x00426927
0x00426927:	pushl $0x4<UINT8>
0x00426929:	pushl $0x0<UINT8>
0x0042692b:	pushl 0xc(%esp)
0x0042692f:	call 0x004268f4
0x004268f4:	movzbl %eax, 0x4(%esp)
0x004268f9:	movb %cl, 0xc(%esp)
0x004268fd:	testb 0x46bc01(%eax), %cl
0x00426903:	jne 30
0x00426905:	cmpl 0x8(%esp), $0x0<UINT8>
0x0042690a:	je 0x0042691c
0x0042691c:	xorl %eax, %eax
0x0042691e:	testl %eax, %eax
0x00426920:	jne 1
0x00426922:	ret

0x00426934:	addl %esp, $0xc<UINT8>
0x00426937:	ret

0x00423b20:	testl %eax, %eax
0x00423b22:	popl %ecx
0x00423b23:	je 0x00423b26
0x00423b26:	incl %esi
0x00423b27:	jmp 0x00423afc
0x00423b02:	testb %al, %al
0x00423b04:	je 0x00423b34
0x00423b34:	popl %edi
0x00423b35:	movl %eax, %esi
0x00423b37:	popl %esi
0x00423b38:	ret

0x0041e15e:	movl -32(%ebp), %eax
0x0041e161:	testb -68(%ebp), $0x1<UINT8>
0x0041e165:	je 0x0041e16d
0x0041e16d:	pushl $0xa<UINT8>
0x0041e16f:	popl %eax
0x0041e170:	pushl %eax
0x0041e171:	pushl -32(%ebp)
0x0041e174:	pushl %esi
0x0041e175:	pushl %esi
0x0041e176:	call GetModuleHandleA@KERNEL32.DLL
0x0041e178:	pushl %eax
0x0041e179:	call 0x0043cf34
0x0043cf34:	jmp 0x00445ff2
0x00445ff2:	pushl %ebx
0x00445ff3:	pushl %esi
0x00445ff4:	pushl %edi
0x00445ff5:	orl %ebx, $0xffffffff<UINT8>
0x00445ff8:	call 0x00444766
0x00444766:	call 0x00450fd5
0x00450fd5:	call 0x00450faf
0x00450fda:	addl %eax, $0x1070<UINT32>
0x00450fdf:	pushl $0x45022d<UINT32>
0x00450fe4:	movl %ecx, %eax
0x00450fe6:	call 0x00451b26
0x00450feb:	ret

0x0044476b:	movl %eax, 0x4(%eax)
0x0044476e:	ret

0x00445ffd:	movl %esi, %eax
0x00445fff:	call 0x00450faf
0x00446004:	pushl 0x1c(%esp)
0x00446008:	movl %edi, 0x4(%eax)
0x0044600b:	pushl 0x1c(%esp)
0x0044600f:	pushl 0x1c(%esp)
0x00446013:	pushl 0x1c(%esp)
0x00446017:	call 0x00452045
0x00452045:	pushl %esi
0x00452046:	movl %esi, 0x4540fc
0x0045204c:	pushl $0x0<UINT8>
0x0045204e:	call SetErrorMode@KERNEL32.DLL
SetErrorMode@KERNEL32.DLL: API Node	
0x00452050:	orl %eax, $0x8001<UINT32>
0x00452055:	pushl %eax
0x00452056:	call SetErrorMode@KERNEL32.DLL
0x00452058:	call 0x00450faf
0x0045205d:	movl %esi, 0x8(%esp)
0x00452061:	movl 0x8(%eax), %esi
0x00452064:	movl 0xc(%eax), %esi
0x00452067:	call 0x00450faf
0x0045206c:	movl %eax, 0x4(%eax)
0x0045206f:	testl %eax, %eax
0x00452071:	je 24
0x00452073:	movl %ecx, 0x10(%esp)
0x00452077:	movl 0x44(%eax), %ecx
0x0045207a:	movl %ecx, 0x14(%esp)
0x0045207e:	movl 0x48(%eax), %ecx
0x00452081:	movl %ecx, %eax
0x00452083:	movl 0x40(%eax), %esi
0x00452086:	call 0x00451ef7
0x00451ef7:	pushl %ebp
0x00451ef8:	leal %ebp, -656(%esp)
0x00451eff:	subl %esp, $0x310<UINT32>
0x00451f05:	movl %eax, 0x467108
0x00451f0a:	pushl %ebx
0x00451f0b:	pushl %esi
0x00451f0c:	pushl %edi
0x00451f0d:	movl 0x28c(%ebp), %eax
0x00451f13:	movl %esi, %ecx
0x00451f15:	call 0x00450faf
0x00451f1a:	movl %ebx, %eax
0x00451f1c:	movl %eax, 0x40(%esi)
0x00451f1f:	movl 0x8(%ebx), %eax
0x00451f22:	movl %eax, 0x40(%esi)
0x00451f25:	movl 0xc(%ebx), %eax
0x00451f28:	movl %edi, $0x104<UINT32>
0x00451f2d:	pushl %edi
0x00451f2e:	leal %eax, 0x84(%ebp)
0x00451f34:	pushl %eax
0x00451f35:	pushl 0x40(%esi)
0x00451f38:	call GetModuleFileNameA@KERNEL32.DLL
0x00451f3e:	testl %eax, %eax
0x00451f40:	je 0x00451f46
0x00451f46:	call 0x004462da
0x004462da:	pushl %ebp
0x004462db:	movl %ebp, %esp
0x004462dd:	pushl %ecx
0x004462de:	pushl $0x462e98<UINT32>
0x004462e3:	leal %eax, -4(%ebp)
0x004462e6:	pushl %eax
0x004462e7:	movl -4(%ebp), $0x46a1d8<UINT32>
0x004462ee:	call 0x0041e2ef
0x0041e2ef:	pushl %ebp
0x0041e2f0:	movl %ebp, %esp
0x0041e2f2:	subl %esp, $0x20<UINT8>
0x0041e2f5:	movl %eax, 0x8(%ebp)
0x0041e2f8:	pushl %esi
0x0041e2f9:	pushl %edi
0x0041e2fa:	pushl $0x8<UINT8>
0x0041e2fc:	popl %ecx
0x0041e2fd:	movl %esi, $0x45b9ec<UINT32>
0x0041e302:	leal %edi, -32(%ebp)
0x0041e305:	rep movsl %es:(%edi), %ds:(%esi)
