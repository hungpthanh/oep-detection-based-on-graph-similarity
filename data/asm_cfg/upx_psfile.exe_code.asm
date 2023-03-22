0x00426eb0:	pusha
0x00426eb1:	movl %esi, $0x419000<UINT32>
0x00426eb6:	leal %edi, -98304(%esi)
0x00426ebc:	pushl %edi
0x00426ebd:	jmp 0x00426eca
0x00426eca:	movl %ebx, (%esi)
0x00426ecc:	subl %esi, $0xfffffffc<UINT8>
0x00426ecf:	adcl %ebx, %ebx
0x00426ed1:	jb 0x00426ec0
0x00426ec0:	movb %al, (%esi)
0x00426ec2:	incl %esi
0x00426ec3:	movb (%edi), %al
0x00426ec5:	incl %edi
0x00426ec6:	addl %ebx, %ebx
0x00426ec8:	jne 0x00426ed1
0x00426ed3:	movl %eax, $0x1<UINT32>
0x00426ed8:	addl %ebx, %ebx
0x00426eda:	jne 0x00426ee3
0x00426ee3:	adcl %eax, %eax
0x00426ee5:	addl %ebx, %ebx
0x00426ee7:	jae 0x00426ed8
0x00426ee9:	jne 0x00426ef4
0x00426ef4:	xorl %ecx, %ecx
0x00426ef6:	subl %eax, $0x3<UINT8>
0x00426ef9:	jb 0x00426f08
0x00426efb:	shll %eax, $0x8<UINT8>
0x00426efe:	movb %al, (%esi)
0x00426f00:	incl %esi
0x00426f01:	xorl %eax, $0xffffffff<UINT8>
0x00426f04:	je 0x00426f7a
0x00426f06:	movl %ebp, %eax
0x00426f08:	addl %ebx, %ebx
0x00426f0a:	jne 0x00426f13
0x00426f13:	adcl %ecx, %ecx
0x00426f15:	addl %ebx, %ebx
0x00426f17:	jne 0x00426f20
0x00426f20:	adcl %ecx, %ecx
0x00426f22:	jne 0x00426f44
0x00426f44:	cmpl %ebp, $0xfffff300<UINT32>
0x00426f4a:	adcl %ecx, $0x1<UINT8>
0x00426f4d:	leal %edx, (%edi,%ebp)
0x00426f50:	cmpl %ebp, $0xfffffffc<UINT8>
0x00426f53:	jbe 0x00426f64
0x00426f64:	movl %eax, (%edx)
0x00426f66:	addl %edx, $0x4<UINT8>
0x00426f69:	movl (%edi), %eax
0x00426f6b:	addl %edi, $0x4<UINT8>
0x00426f6e:	subl %ecx, $0x4<UINT8>
0x00426f71:	ja 0x00426f64
0x00426f73:	addl %edi, %ecx
0x00426f75:	jmp 0x00426ec6
0x00426f55:	movb %al, (%edx)
0x00426f57:	incl %edx
0x00426f58:	movb (%edi), %al
0x00426f5a:	incl %edi
0x00426f5b:	decl %ecx
0x00426f5c:	jne 0x00426f55
0x00426f5e:	jmp 0x00426ec6
0x00426f24:	incl %ecx
0x00426f25:	addl %ebx, %ebx
0x00426f27:	jne 0x00426f30
0x00426f30:	adcl %ecx, %ecx
0x00426f32:	addl %ebx, %ebx
0x00426f34:	jae 0x00426f25
0x00426f36:	jne 0x00426f41
0x00426f41:	addl %ecx, $0x2<UINT8>
0x00426eeb:	movl %ebx, (%esi)
0x00426eed:	subl %esi, $0xfffffffc<UINT8>
0x00426ef0:	adcl %ebx, %ebx
0x00426ef2:	jae 0x00426ed8
0x00426edc:	movl %ebx, (%esi)
0x00426ede:	subl %esi, $0xfffffffc<UINT8>
0x00426ee1:	adcl %ebx, %ebx
0x00426f29:	movl %ebx, (%esi)
0x00426f2b:	subl %esi, $0xfffffffc<UINT8>
0x00426f2e:	adcl %ebx, %ebx
0x00426f0c:	movl %ebx, (%esi)
0x00426f0e:	subl %esi, $0xfffffffc<UINT8>
0x00426f11:	adcl %ebx, %ebx
0x00426f19:	movl %ebx, (%esi)
0x00426f1b:	subl %esi, $0xfffffffc<UINT8>
0x00426f1e:	adcl %ebx, %ebx
0x00426f38:	movl %ebx, (%esi)
0x00426f3a:	subl %esi, $0xfffffffc<UINT8>
0x00426f3d:	adcl %ebx, %ebx
0x00426f3f:	jae 0x00426f25
0x00426f7a:	popl %esi
0x00426f7b:	movl %edi, %esi
0x00426f7d:	movl %ecx, $0x6b7<UINT32>
0x00426f82:	movb %al, (%edi)
0x00426f84:	incl %edi
0x00426f85:	subb %al, $0xffffffe8<UINT8>
0x00426f87:	cmpb %al, $0x1<UINT8>
0x00426f89:	ja 0x00426f82
0x00426f8b:	cmpb (%edi), $0x5<UINT8>
0x00426f8e:	jne 0x00426f82
0x00426f90:	movl %eax, (%edi)
0x00426f92:	movb %bl, 0x4(%edi)
0x00426f95:	shrw %ax, $0x8<UINT8>
0x00426f99:	roll %eax, $0x10<UINT8>
0x00426f9c:	xchgb %ah, %al
0x00426f9e:	subl %eax, %edi
0x00426fa0:	subb %bl, $0xffffffe8<UINT8>
0x00426fa3:	addl %eax, %esi
0x00426fa5:	movl (%edi), %eax
0x00426fa7:	addl %edi, $0x5<UINT8>
0x00426faa:	movb %al, %bl
0x00426fac:	loop 0x00426f87
0x00426fae:	leal %edi, 0x24000(%esi)
0x00426fb4:	movl %eax, (%edi)
0x00426fb6:	orl %eax, %eax
0x00426fb8:	je 0x00426ff6
0x00426fba:	movl %ebx, 0x4(%edi)
0x00426fbd:	leal %eax, 0x2754c(%eax,%esi)
0x00426fc4:	addl %ebx, %esi
0x00426fc6:	pushl %eax
0x00426fc7:	addl %edi, $0x8<UINT8>
0x00426fca:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x00426fd0:	xchgl %ebp, %eax
0x00426fd1:	movb %al, (%edi)
0x00426fd3:	incl %edi
0x00426fd4:	orb %al, %al
0x00426fd6:	je 0x00426fb4
0x00426fd8:	movl %ecx, %edi
0x00426fda:	pushl %edi
0x00426fdb:	decl %eax
0x00426fdc:	repn scasb %al, %es:(%edi)
0x00426fde:	pushl %ebp
0x00426fdf:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00426fe5:	orl %eax, %eax
0x00426fe7:	je 7
0x00426fe9:	movl (%ebx), %eax
0x00426feb:	addl %ebx, $0x4<UINT8>
0x00426fee:	jmp 0x00426fd1
GetProcAddress@KERNEL32.DLL: API Node	
0x00426ff6:	movl %ebp, 0x275f4(%esi)
0x00426ffc:	leal %edi, -4096(%esi)
0x00427002:	movl %ebx, $0x1000<UINT32>
0x00427007:	pushl %eax
0x00427008:	pushl %esp
0x00427009:	pushl $0x4<UINT8>
0x0042700b:	pushl %ebx
0x0042700c:	pushl %edi
0x0042700d:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0042700f:	leal %eax, 0x21f(%edi)
0x00427015:	andb (%eax), $0x7f<UINT8>
0x00427018:	andb 0x28(%eax), $0x7f<UINT8>
0x0042701c:	popl %eax
0x0042701d:	pushl %eax
0x0042701e:	pushl %esp
0x0042701f:	pushl %eax
0x00427020:	pushl %ebx
0x00427021:	pushl %edi
0x00427022:	call VirtualProtect@kernel32.dll
0x00427024:	popl %eax
0x00427025:	popa
0x00427026:	leal %eax, -128(%esp)
0x0042702a:	pushl $0x0<UINT8>
0x0042702c:	cmpl %esp, %eax
0x0042702e:	jne 0x0042702a
0x00427030:	subl %esp, $0xffffff80<UINT8>
0x00427033:	jmp 0x004054a0
0x004054a0:	call 0x0040c3c8
0x0040c3c8:	pushl %ebp
0x0040c3c9:	movl %ebp, %esp
0x0040c3cb:	subl %esp, $0x14<UINT8>
0x0040c3ce:	andl -12(%ebp), $0x0<UINT8>
0x0040c3d2:	andl -8(%ebp), $0x0<UINT8>
0x0040c3d6:	movl %eax, 0x4200d0
0x0040c3db:	pushl %esi
0x0040c3dc:	pushl %edi
0x0040c3dd:	movl %edi, $0xbb40e64e<UINT32>
0x0040c3e2:	movl %esi, $0xffff0000<UINT32>
0x0040c3e7:	cmpl %eax, %edi
0x0040c3e9:	je 0x0040c3f8
0x0040c3f8:	leal %eax, -12(%ebp)
0x0040c3fb:	pushl %eax
0x0040c3fc:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040c402:	movl %eax, -8(%ebp)
0x0040c405:	xorl %eax, -12(%ebp)
0x0040c408:	movl -4(%ebp), %eax
0x0040c40b:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040c411:	xorl -4(%ebp), %eax
0x0040c414:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040c41a:	xorl -4(%ebp), %eax
0x0040c41d:	leal %eax, -20(%ebp)
0x0040c420:	pushl %eax
0x0040c421:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040c427:	movl %ecx, -16(%ebp)
0x0040c42a:	leal %eax, -4(%ebp)
0x0040c42d:	xorl %ecx, -20(%ebp)
0x0040c430:	xorl %ecx, -4(%ebp)
0x0040c433:	xorl %ecx, %eax
0x0040c435:	cmpl %ecx, %edi
0x0040c437:	jne 0x0040c440
0x0040c440:	testl %esi, %ecx
0x0040c442:	jne 0x0040c450
0x0040c450:	movl 0x4200d0, %ecx
0x0040c456:	notl %ecx
0x0040c458:	movl 0x4200d4, %ecx
0x0040c45e:	popl %edi
0x0040c45f:	popl %esi
0x0040c460:	movl %esp, %ebp
0x0040c462:	popl %ebp
0x0040c463:	ret

0x004054a5:	jmp 0x00405325
0x00405325:	pushl $0x14<UINT8>
0x00405327:	pushl $0x41f188<UINT32>
0x0040532c:	call 0x00407330
0x00407330:	pushl $0x404e90<UINT32>
0x00407335:	pushl %fs:0
0x0040733c:	movl %eax, 0x10(%esp)
0x00407340:	movl 0x10(%esp), %ebp
0x00407344:	leal %ebp, 0x10(%esp)
0x00407348:	subl %esp, %eax
0x0040734a:	pushl %ebx
0x0040734b:	pushl %esi
0x0040734c:	pushl %edi
0x0040734d:	movl %eax, 0x4200d0
0x00407352:	xorl -4(%ebp), %eax
0x00407355:	xorl %eax, %ebp
0x00407357:	pushl %eax
0x00407358:	movl -24(%ebp), %esp
0x0040735b:	pushl -8(%ebp)
0x0040735e:	movl %eax, -4(%ebp)
0x00407361:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00407368:	movl -8(%ebp), %eax
0x0040736b:	leal %eax, -16(%ebp)
0x0040736e:	movl %fs:0, %eax
0x00407374:	ret

0x00405331:	pushl $0x1<UINT8>
0x00405333:	call 0x0040c37b
0x0040c37b:	pushl %ebp
0x0040c37c:	movl %ebp, %esp
0x0040c37e:	movl %eax, 0x8(%ebp)
0x0040c381:	movl 0x421a18, %eax
0x0040c386:	popl %ebp
0x0040c387:	ret

0x00405338:	popl %ecx
0x00405339:	movl %eax, $0x5a4d<UINT32>
0x0040533e:	cmpw 0x400000, %ax
0x00405345:	je 0x0040534b
0x0040534b:	movl %eax, 0x40003c
0x00405350:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x0040535a:	jne -21
0x0040535c:	movl %ecx, $0x10b<UINT32>
0x00405361:	cmpw 0x400018(%eax), %cx
0x00405368:	jne -35
0x0040536a:	xorl %ebx, %ebx
0x0040536c:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00405373:	jbe 9
0x00405375:	cmpl 0x4000e8(%eax), %ebx
0x0040537b:	setne %bl
0x0040537e:	movl -28(%ebp), %ebx
0x00405381:	call 0x00407460
0x00407460:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x00407466:	xorl %ecx, %ecx
0x00407468:	movl 0x422078, %eax
0x0040746d:	testl %eax, %eax
0x0040746f:	setne %cl
0x00407472:	movl %eax, %ecx
0x00407474:	ret

0x00405386:	testl %eax, %eax
0x00405388:	jne 0x00405392
0x00405392:	call 0x004063ac
0x004063ac:	call 0x00403684
0x00403684:	pushl %esi
0x00403685:	pushl $0x0<UINT8>
0x00403687:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x0040368d:	movl %esi, %eax
0x0040368f:	pushl %esi
0x00403690:	call 0x004070e2
0x004070e2:	pushl %ebp
0x004070e3:	movl %ebp, %esp
0x004070e5:	movl %eax, 0x8(%ebp)
0x004070e8:	movl 0x422050, %eax
0x004070ed:	popl %ebp
0x004070ee:	ret

0x00403695:	pushl %esi
0x00403696:	call 0x004055cf
0x004055cf:	pushl %ebp
0x004055d0:	movl %ebp, %esp
0x004055d2:	movl %eax, 0x8(%ebp)
0x004055d5:	movl 0x4218a0, %eax
0x004055da:	popl %ebp
0x004055db:	ret

0x0040369b:	pushl %esi
0x0040369c:	call 0x004070ef
0x004070ef:	pushl %ebp
0x004070f0:	movl %ebp, %esp
0x004070f2:	movl %eax, 0x8(%ebp)
0x004070f5:	movl 0x422054, %eax
0x004070fa:	popl %ebp
0x004070fb:	ret

0x004036a1:	pushl %esi
0x004036a2:	call 0x00407109
0x00407109:	pushl %ebp
0x0040710a:	movl %ebp, %esp
0x0040710c:	movl %eax, 0x8(%ebp)
0x0040710f:	movl 0x422058, %eax
0x00407114:	movl 0x42205c, %eax
0x00407119:	movl 0x422060, %eax
0x0040711e:	movl 0x422064, %eax
0x00407123:	popl %ebp
0x00407124:	ret

0x004036a7:	pushl %esi
0x004036a8:	call 0x004070ab
0x004070ab:	pushl $0x407077<UINT32>
0x004070b0:	call EncodePointer@KERNEL32.DLL
0x004070b6:	movl 0x42204c, %eax
0x004070bb:	ret

0x004036ad:	pushl %esi
0x004036ae:	call 0x0040731a
0x0040731a:	pushl %ebp
0x0040731b:	movl %ebp, %esp
0x0040731d:	movl %eax, 0x8(%ebp)
0x00407320:	movl 0x42206c, %eax
0x00407325:	popl %ebp
0x00407326:	ret

0x004036b3:	addl %esp, $0x18<UINT8>
0x004036b6:	popl %esi
0x004036b7:	jmp 0x004067c4
0x004067c4:	pushl %esi
0x004067c5:	pushl %edi
0x004067c6:	pushl $0x41b750<UINT32>
0x004067cb:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x004067d1:	movl %esi, 0x414074
0x004067d7:	movl %edi, %eax
0x004067d9:	pushl $0x41b76c<UINT32>
0x004067de:	pushl %edi
0x004067df:	call GetProcAddress@KERNEL32.DLL
0x004067e1:	xorl %eax, 0x4200d0
0x004067e7:	pushl $0x41b778<UINT32>
0x004067ec:	pushl %edi
0x004067ed:	movl 0x422a40, %eax
0x004067f2:	call GetProcAddress@KERNEL32.DLL
0x004067f4:	xorl %eax, 0x4200d0
0x004067fa:	pushl $0x41b780<UINT32>
0x004067ff:	pushl %edi
0x00406800:	movl 0x422a44, %eax
0x00406805:	call GetProcAddress@KERNEL32.DLL
0x00406807:	xorl %eax, 0x4200d0
0x0040680d:	pushl $0x41b78c<UINT32>
0x00406812:	pushl %edi
0x00406813:	movl 0x422a48, %eax
0x00406818:	call GetProcAddress@KERNEL32.DLL
0x0040681a:	xorl %eax, 0x4200d0
0x00406820:	pushl $0x41b798<UINT32>
0x00406825:	pushl %edi
0x00406826:	movl 0x422a4c, %eax
0x0040682b:	call GetProcAddress@KERNEL32.DLL
0x0040682d:	xorl %eax, 0x4200d0
0x00406833:	pushl $0x41b7b4<UINT32>
0x00406838:	pushl %edi
0x00406839:	movl 0x422a50, %eax
0x0040683e:	call GetProcAddress@KERNEL32.DLL
0x00406840:	xorl %eax, 0x4200d0
0x00406846:	pushl $0x41b7c4<UINT32>
0x0040684b:	pushl %edi
0x0040684c:	movl 0x422a54, %eax
0x00406851:	call GetProcAddress@KERNEL32.DLL
0x00406853:	xorl %eax, 0x4200d0
0x00406859:	pushl $0x41b7d8<UINT32>
0x0040685e:	pushl %edi
0x0040685f:	movl 0x422a58, %eax
0x00406864:	call GetProcAddress@KERNEL32.DLL
0x00406866:	xorl %eax, 0x4200d0
0x0040686c:	pushl $0x41b7f0<UINT32>
0x00406871:	pushl %edi
0x00406872:	movl 0x422a5c, %eax
0x00406877:	call GetProcAddress@KERNEL32.DLL
0x00406879:	xorl %eax, 0x4200d0
0x0040687f:	pushl $0x41b808<UINT32>
0x00406884:	pushl %edi
0x00406885:	movl 0x422a60, %eax
0x0040688a:	call GetProcAddress@KERNEL32.DLL
0x0040688c:	xorl %eax, 0x4200d0
0x00406892:	pushl $0x41b81c<UINT32>
0x00406897:	pushl %edi
0x00406898:	movl 0x422a64, %eax
0x0040689d:	call GetProcAddress@KERNEL32.DLL
0x0040689f:	xorl %eax, 0x4200d0
0x004068a5:	pushl $0x41b83c<UINT32>
0x004068aa:	pushl %edi
0x004068ab:	movl 0x422a68, %eax
0x004068b0:	call GetProcAddress@KERNEL32.DLL
0x004068b2:	xorl %eax, 0x4200d0
0x004068b8:	pushl $0x41b854<UINT32>
0x004068bd:	pushl %edi
0x004068be:	movl 0x422a6c, %eax
0x004068c3:	call GetProcAddress@KERNEL32.DLL
0x004068c5:	xorl %eax, 0x4200d0
0x004068cb:	pushl $0x41b86c<UINT32>
0x004068d0:	pushl %edi
0x004068d1:	movl 0x422a70, %eax
0x004068d6:	call GetProcAddress@KERNEL32.DLL
0x004068d8:	xorl %eax, 0x4200d0
0x004068de:	pushl $0x41b880<UINT32>
0x004068e3:	pushl %edi
0x004068e4:	movl 0x422a74, %eax
0x004068e9:	call GetProcAddress@KERNEL32.DLL
0x004068eb:	xorl %eax, 0x4200d0
0x004068f1:	movl 0x422a78, %eax
0x004068f6:	pushl $0x41b894<UINT32>
0x004068fb:	pushl %edi
0x004068fc:	call GetProcAddress@KERNEL32.DLL
0x004068fe:	xorl %eax, 0x4200d0
0x00406904:	pushl $0x41b8b0<UINT32>
0x00406909:	pushl %edi
0x0040690a:	movl 0x422a7c, %eax
0x0040690f:	call GetProcAddress@KERNEL32.DLL
0x00406911:	xorl %eax, 0x4200d0
0x00406917:	pushl $0x41b8d0<UINT32>
0x0040691c:	pushl %edi
0x0040691d:	movl 0x422a80, %eax
0x00406922:	call GetProcAddress@KERNEL32.DLL
0x00406924:	xorl %eax, 0x4200d0
0x0040692a:	pushl $0x41b8ec<UINT32>
0x0040692f:	pushl %edi
0x00406930:	movl 0x422a84, %eax
0x00406935:	call GetProcAddress@KERNEL32.DLL
0x00406937:	xorl %eax, 0x4200d0
0x0040693d:	pushl $0x41b90c<UINT32>
0x00406942:	pushl %edi
0x00406943:	movl 0x422a88, %eax
0x00406948:	call GetProcAddress@KERNEL32.DLL
0x0040694a:	xorl %eax, 0x4200d0
0x00406950:	pushl $0x41b920<UINT32>
0x00406955:	pushl %edi
0x00406956:	movl 0x422a8c, %eax
0x0040695b:	call GetProcAddress@KERNEL32.DLL
0x0040695d:	xorl %eax, 0x4200d0
0x00406963:	pushl $0x41b93c<UINT32>
0x00406968:	pushl %edi
0x00406969:	movl 0x422a90, %eax
0x0040696e:	call GetProcAddress@KERNEL32.DLL
0x00406970:	xorl %eax, 0x4200d0
0x00406976:	pushl $0x41b950<UINT32>
0x0040697b:	pushl %edi
0x0040697c:	movl 0x422a98, %eax
0x00406981:	call GetProcAddress@KERNEL32.DLL
0x00406983:	xorl %eax, 0x4200d0
0x00406989:	pushl $0x41b960<UINT32>
0x0040698e:	pushl %edi
0x0040698f:	movl 0x422a94, %eax
0x00406994:	call GetProcAddress@KERNEL32.DLL
0x00406996:	xorl %eax, 0x4200d0
0x0040699c:	pushl $0x41b970<UINT32>
0x004069a1:	pushl %edi
0x004069a2:	movl 0x422a9c, %eax
0x004069a7:	call GetProcAddress@KERNEL32.DLL
0x004069a9:	xorl %eax, 0x4200d0
0x004069af:	pushl $0x41b980<UINT32>
0x004069b4:	pushl %edi
0x004069b5:	movl 0x422aa0, %eax
0x004069ba:	call GetProcAddress@KERNEL32.DLL
0x004069bc:	xorl %eax, 0x4200d0
0x004069c2:	pushl $0x41b990<UINT32>
0x004069c7:	pushl %edi
0x004069c8:	movl 0x422aa4, %eax
0x004069cd:	call GetProcAddress@KERNEL32.DLL
0x004069cf:	xorl %eax, 0x4200d0
0x004069d5:	pushl $0x41b9ac<UINT32>
0x004069da:	pushl %edi
0x004069db:	movl 0x422aa8, %eax
0x004069e0:	call GetProcAddress@KERNEL32.DLL
0x004069e2:	xorl %eax, 0x4200d0
0x004069e8:	pushl $0x41b9c0<UINT32>
0x004069ed:	pushl %edi
0x004069ee:	movl 0x422aac, %eax
0x004069f3:	call GetProcAddress@KERNEL32.DLL
0x004069f5:	xorl %eax, 0x4200d0
0x004069fb:	pushl $0x41b9d0<UINT32>
0x00406a00:	pushl %edi
0x00406a01:	movl 0x422ab0, %eax
0x00406a06:	call GetProcAddress@KERNEL32.DLL
0x00406a08:	xorl %eax, 0x4200d0
0x00406a0e:	pushl $0x41b9e4<UINT32>
0x00406a13:	pushl %edi
0x00406a14:	movl 0x422ab4, %eax
0x00406a19:	call GetProcAddress@KERNEL32.DLL
0x00406a1b:	xorl %eax, 0x4200d0
0x00406a21:	movl 0x422ab8, %eax
0x00406a26:	pushl $0x41b9f4<UINT32>
0x00406a2b:	pushl %edi
0x00406a2c:	call GetProcAddress@KERNEL32.DLL
0x00406a2e:	xorl %eax, 0x4200d0
0x00406a34:	pushl $0x41ba14<UINT32>
0x00406a39:	pushl %edi
0x00406a3a:	movl 0x422abc, %eax
0x00406a3f:	call GetProcAddress@KERNEL32.DLL
0x00406a41:	xorl %eax, 0x4200d0
0x00406a47:	popl %edi
0x00406a48:	movl 0x422ac0, %eax
0x00406a4d:	popl %esi
0x00406a4e:	ret

0x004063b1:	call 0x0040668a
0x0040668a:	pushl %esi
0x0040668b:	pushl %edi
0x0040668c:	movl %esi, $0x420c28<UINT32>
0x00406691:	movl %edi, $0x4218c8<UINT32>
0x00406696:	cmpl 0x4(%esi), $0x1<UINT8>
0x0040669a:	jne 22
0x0040669c:	pushl $0x0<UINT8>
0x0040669e:	movl (%esi), %edi
0x004066a0:	addl %edi, $0x18<UINT8>
0x004066a3:	pushl $0xfa0<UINT32>
0x004066a8:	pushl (%esi)
0x004066aa:	call 0x00406756
0x00406756:	pushl %ebp
0x00406757:	movl %ebp, %esp
0x00406759:	movl %eax, 0x422a50
0x0040675e:	xorl %eax, 0x4200d0
0x00406764:	je 13
0x00406766:	pushl 0x10(%ebp)
0x00406769:	pushl 0xc(%ebp)
0x0040676c:	pushl 0x8(%ebp)
0x0040676f:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x00406771:	popl %ebp
0x00406772:	ret

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
