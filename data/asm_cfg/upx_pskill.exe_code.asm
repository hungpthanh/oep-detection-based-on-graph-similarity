0x00448400:	pusha
0x00448401:	movl %esi, $0x432000<UINT32>
0x00448406:	leal %edi, -200704(%esi)
0x0044840c:	pushl %edi
0x0044840d:	jmp 0x0044841a
0x0044841a:	movl %ebx, (%esi)
0x0044841c:	subl %esi, $0xfffffffc<UINT8>
0x0044841f:	adcl %ebx, %ebx
0x00448421:	jb 0x00448410
0x00448410:	movb %al, (%esi)
0x00448412:	incl %esi
0x00448413:	movb (%edi), %al
0x00448415:	incl %edi
0x00448416:	addl %ebx, %ebx
0x00448418:	jne 0x00448421
0x00448423:	movl %eax, $0x1<UINT32>
0x00448428:	addl %ebx, %ebx
0x0044842a:	jne 0x00448433
0x00448433:	adcl %eax, %eax
0x00448435:	addl %ebx, %ebx
0x00448437:	jae 0x00448444
0x00448439:	jne 0x00448463
0x00448463:	xorl %ecx, %ecx
0x00448465:	subl %eax, $0x3<UINT8>
0x00448468:	jb 0x0044847b
0x0044846a:	shll %eax, $0x8<UINT8>
0x0044846d:	movb %al, (%esi)
0x0044846f:	incl %esi
0x00448470:	xorl %eax, $0xffffffff<UINT8>
0x00448473:	je 0x004484ea
0x00448475:	sarl %eax
0x00448477:	movl %ebp, %eax
0x00448479:	jmp 0x00448486
0x00448486:	jb 0x00448454
0x00448454:	addl %ebx, %ebx
0x00448456:	jne 0x0044845f
0x0044845f:	adcl %ecx, %ecx
0x00448461:	jmp 0x004484b5
0x004484b5:	cmpl %ebp, $0xfffffb00<UINT32>
0x004484bb:	adcl %ecx, $0x2<UINT8>
0x004484be:	leal %edx, (%edi,%ebp)
0x004484c1:	cmpl %ebp, $0xfffffffc<UINT8>
0x004484c4:	jbe 0x004484d4
0x004484d4:	movl %eax, (%edx)
0x004484d6:	addl %edx, $0x4<UINT8>
0x004484d9:	movl (%edi), %eax
0x004484db:	addl %edi, $0x4<UINT8>
0x004484de:	subl %ecx, $0x4<UINT8>
0x004484e1:	ja 0x004484d4
0x004484e3:	addl %edi, %ecx
0x004484e5:	jmp 0x00448416
0x004484c6:	movb %al, (%edx)
0x004484c8:	incl %edx
0x004484c9:	movb (%edi), %al
0x004484cb:	incl %edi
0x004484cc:	decl %ecx
0x004484cd:	jne 0x004484c6
0x004484cf:	jmp 0x00448416
0x00448488:	incl %ecx
0x00448489:	addl %ebx, %ebx
0x0044848b:	jne 0x00448494
0x00448494:	jb 0x00448454
0x00448496:	addl %ebx, %ebx
0x00448498:	jne 0x004484a1
0x004484a1:	adcl %ecx, %ecx
0x004484a3:	addl %ebx, %ebx
0x004484a5:	jae 0x00448496
0x004484a7:	jne 0x004484b2
0x004484b2:	addl %ecx, $0x2<UINT8>
0x00448458:	movl %ebx, (%esi)
0x0044845a:	subl %esi, $0xfffffffc<UINT8>
0x0044845d:	adcl %ebx, %ebx
0x0044842c:	movl %ebx, (%esi)
0x0044842e:	subl %esi, $0xfffffffc<UINT8>
0x00448431:	adcl %ebx, %ebx
0x0044847b:	addl %ebx, %ebx
0x0044847d:	jne 0x00448486
0x00448444:	decl %eax
0x00448445:	addl %ebx, %ebx
0x00448447:	jne 0x00448450
0x00448450:	adcl %eax, %eax
0x00448452:	jmp 0x00448428
0x004484a9:	movl %ebx, (%esi)
0x004484ab:	subl %esi, $0xfffffffc<UINT8>
0x004484ae:	adcl %ebx, %ebx
0x004484b0:	jae 0x00448496
0x0044843b:	movl %ebx, (%esi)
0x0044843d:	subl %esi, $0xfffffffc<UINT8>
0x00448440:	adcl %ebx, %ebx
0x00448442:	jb 0x00448463
0x00448449:	movl %ebx, (%esi)
0x0044844b:	subl %esi, $0xfffffffc<UINT8>
0x0044844e:	adcl %ebx, %ebx
0x0044849a:	movl %ebx, (%esi)
0x0044849c:	subl %esi, $0xfffffffc<UINT8>
0x0044849f:	adcl %ebx, %ebx
0x0044848d:	movl %ebx, (%esi)
0x0044848f:	subl %esi, $0xfffffffc<UINT8>
0x00448492:	adcl %ebx, %ebx
0x0044847f:	movl %ebx, (%esi)
0x00448481:	subl %esi, $0xfffffffc<UINT8>
0x00448484:	adcl %ebx, %ebx
0x004484ea:	popl %esi
0x004484eb:	movl %edi, %esi
0x004484ed:	movl %ecx, $0x7ae<UINT32>
0x004484f2:	movb %al, (%edi)
0x004484f4:	incl %edi
0x004484f5:	subb %al, $0xffffffe8<UINT8>
0x004484f7:	cmpb %al, $0x1<UINT8>
0x004484f9:	ja 0x004484f2
0x004484fb:	cmpb (%edi), $0x5<UINT8>
0x004484fe:	jne 0x004484f2
0x00448500:	movl %eax, (%edi)
0x00448502:	movb %bl, 0x4(%edi)
0x00448505:	shrw %ax, $0x8<UINT8>
0x00448509:	roll %eax, $0x10<UINT8>
0x0044850c:	xchgb %ah, %al
0x0044850e:	subl %eax, %edi
0x00448510:	subb %bl, $0xffffffe8<UINT8>
0x00448513:	addl %eax, %esi
0x00448515:	movl (%edi), %eax
0x00448517:	addl %edi, $0x5<UINT8>
0x0044851a:	movb %al, %bl
0x0044851c:	loop 0x004484f7
0x0044851e:	leal %edi, 0x46000(%esi)
0x00448524:	movl %eax, (%edi)
0x00448526:	orl %eax, %eax
0x00448528:	je 0x0044856f
0x0044852a:	movl %ebx, 0x4(%edi)
0x0044852d:	leal %eax, 0x485e4(%eax,%esi)
0x00448534:	addl %ebx, %esi
0x00448536:	pushl %eax
0x00448537:	addl %edi, $0x8<UINT8>
0x0044853a:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00448540:	xchgl %ebp, %eax
0x00448541:	movb %al, (%edi)
0x00448543:	incl %edi
0x00448544:	orb %al, %al
0x00448546:	je 0x00448524
0x00448548:	movl %ecx, %edi
0x0044854a:	jns 0x00448553
0x00448553:	pushl %edi
0x00448554:	decl %eax
0x00448555:	repn scasb %al, %es:(%edi)
0x00448557:	pushl %ebp
0x00448558:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0044855e:	orl %eax, %eax
0x00448560:	je 7
0x00448562:	movl (%ebx), %eax
0x00448564:	addl %ebx, $0x4<UINT8>
0x00448567:	jmp 0x00448541
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x0044854c:	movzwl %eax, (%edi)
0x0044854f:	incl %edi
0x00448550:	pushl %eax
0x00448551:	incl %edi
0x00448552:	movl %ecx, $0xaef24857<UINT32>
0x0044856f:	movl %ebp, 0x4868c(%esi)
0x00448575:	leal %edi, -4096(%esi)
0x0044857b:	movl %ebx, $0x1000<UINT32>
0x00448580:	pushl %eax
0x00448581:	pushl %esp
0x00448582:	pushl $0x4<UINT8>
0x00448584:	pushl %ebx
0x00448585:	pushl %edi
0x00448586:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00448588:	leal %eax, 0x20f(%edi)
0x0044858e:	andb (%eax), $0x7f<UINT8>
0x00448591:	andb 0x28(%eax), $0x7f<UINT8>
0x00448595:	popl %eax
0x00448596:	pushl %eax
0x00448597:	pushl %esp
0x00448598:	pushl %eax
0x00448599:	pushl %ebx
0x0044859a:	pushl %edi
0x0044859b:	call VirtualProtect@kernel32.dll
0x0044859d:	popl %eax
0x0044859e:	popa
0x0044859f:	leal %eax, -128(%esp)
0x004485a3:	pushl $0x0<UINT8>
0x004485a5:	cmpl %esp, %eax
0x004485a7:	jne 0x004485a3
0x004485a9:	subl %esp, $0xffffff80<UINT8>
0x004485ac:	jmp 0x0040763e
0x0040763e:	call 0x0040e000
0x0040e000:	pushl %ebp
0x0040e001:	movl %ebp, %esp
0x0040e003:	subl %esp, $0x14<UINT8>
0x0040e006:	andl -12(%ebp), $0x0<UINT8>
0x0040e00a:	andl -8(%ebp), $0x0<UINT8>
0x0040e00e:	movl %eax, 0x4240d0
0x0040e013:	pushl %esi
0x0040e014:	pushl %edi
0x0040e015:	movl %edi, $0xbb40e64e<UINT32>
0x0040e01a:	movl %esi, $0xffff0000<UINT32>
0x0040e01f:	cmpl %eax, %edi
0x0040e021:	je 0x0040e030
0x0040e030:	leal %eax, -12(%ebp)
0x0040e033:	pushl %eax
0x0040e034:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040e03a:	movl %eax, -8(%ebp)
0x0040e03d:	xorl %eax, -12(%ebp)
0x0040e040:	movl -4(%ebp), %eax
0x0040e043:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040e049:	xorl -4(%ebp), %eax
0x0040e04c:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040e052:	xorl -4(%ebp), %eax
0x0040e055:	leal %eax, -20(%ebp)
0x0040e058:	pushl %eax
0x0040e059:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040e05f:	movl %ecx, -16(%ebp)
0x0040e062:	leal %eax, -4(%ebp)
0x0040e065:	xorl %ecx, -20(%ebp)
0x0040e068:	xorl %ecx, -4(%ebp)
0x0040e06b:	xorl %ecx, %eax
0x0040e06d:	cmpl %ecx, %edi
0x0040e06f:	jne 0x0040e078
0x0040e078:	testl %esi, %ecx
0x0040e07a:	jne 0x0040e088
0x0040e088:	movl 0x4240d0, %ecx
0x0040e08e:	notl %ecx
0x0040e090:	movl 0x4240d4, %ecx
0x0040e096:	popl %edi
0x0040e097:	popl %esi
0x0040e098:	movl %esp, %ebp
0x0040e09a:	popl %ebp
0x0040e09b:	ret

0x00407643:	jmp 0x004074c3
0x004074c3:	pushl $0x14<UINT8>
0x004074c5:	pushl $0x4221e0<UINT32>
0x004074ca:	call 0x004094c0
0x004094c0:	pushl $0x406c90<UINT32>
0x004094c5:	pushl %fs:0
0x004094cc:	movl %eax, 0x10(%esp)
0x004094d0:	movl 0x10(%esp), %ebp
0x004094d4:	leal %ebp, 0x10(%esp)
0x004094d8:	subl %esp, %eax
0x004094da:	pushl %ebx
0x004094db:	pushl %esi
0x004094dc:	pushl %edi
0x004094dd:	movl %eax, 0x4240d0
0x004094e2:	xorl -4(%ebp), %eax
0x004094e5:	xorl %eax, %ebp
0x004094e7:	pushl %eax
0x004094e8:	movl -24(%ebp), %esp
0x004094eb:	pushl -8(%ebp)
0x004094ee:	movl %eax, -4(%ebp)
0x004094f1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004094f8:	movl -8(%ebp), %eax
0x004094fb:	leal %eax, -16(%ebp)
0x004094fe:	movl %fs:0, %eax
0x00409504:	ret

0x004074cf:	pushl $0x1<UINT8>
0x004074d1:	call 0x0040dfb3
0x0040dfb3:	pushl %ebp
0x0040dfb4:	movl %ebp, %esp
0x0040dfb6:	movl %eax, 0x8(%ebp)
0x0040dfb9:	movl 0x4259f8, %eax
0x0040dfbe:	popl %ebp
0x0040dfbf:	ret

0x004074d6:	popl %ecx
0x004074d7:	movl %eax, $0x5a4d<UINT32>
0x004074dc:	cmpw 0x400000, %ax
0x004074e3:	je 0x004074e9
0x004074e9:	movl %eax, 0x40003c
0x004074ee:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x004074f8:	jne -21
0x004074fa:	movl %ecx, $0x10b<UINT32>
0x004074ff:	cmpw 0x400018(%eax), %cx
0x00407506:	jne -35
0x00407508:	xorl %ebx, %ebx
0x0040750a:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00407511:	jbe 9
0x00407513:	cmpl 0x4000e8(%eax), %ebx
0x00407519:	setne %bl
0x0040751c:	movl -28(%ebp), %ebx
0x0040751f:	call 0x004095f0
0x004095f0:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x004095f6:	xorl %ecx, %ecx
0x004095f8:	movl 0x426058, %eax
0x004095fd:	testl %eax, %eax
0x004095ff:	setne %cl
0x00409602:	movl %eax, %ecx
0x00409604:	ret

0x00407524:	testl %eax, %eax
0x00407526:	jne 0x00407530
0x00407530:	call 0x00408586
0x00408586:	call 0x00404ada
0x00404ada:	pushl %esi
0x00404adb:	pushl $0x0<UINT8>
0x00404add:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00404ae3:	movl %esi, %eax
0x00404ae5:	pushl %esi
0x00404ae6:	call 0x00409274
0x00409274:	pushl %ebp
0x00409275:	movl %ebp, %esp
0x00409277:	movl %eax, 0x8(%ebp)
0x0040927a:	movl 0x426030, %eax
0x0040927f:	popl %ebp
0x00409280:	ret

0x00404aeb:	pushl %esi
0x00404aec:	call 0x0040776d
0x0040776d:	pushl %ebp
0x0040776e:	movl %ebp, %esp
0x00407770:	movl %eax, 0x8(%ebp)
0x00407773:	movl 0x425880, %eax
0x00407778:	popl %ebp
0x00407779:	ret

0x00404af1:	pushl %esi
0x00404af2:	call 0x00409281
0x00409281:	pushl %ebp
0x00409282:	movl %ebp, %esp
0x00409284:	movl %eax, 0x8(%ebp)
0x00409287:	movl 0x426034, %eax
0x0040928c:	popl %ebp
0x0040928d:	ret

0x00404af7:	pushl %esi
0x00404af8:	call 0x0040929b
0x0040929b:	pushl %ebp
0x0040929c:	movl %ebp, %esp
0x0040929e:	movl %eax, 0x8(%ebp)
0x004092a1:	movl 0x426038, %eax
0x004092a6:	movl 0x42603c, %eax
0x004092ab:	movl 0x426040, %eax
0x004092b0:	movl 0x426044, %eax
0x004092b5:	popl %ebp
0x004092b6:	ret

0x00404afd:	pushl %esi
0x00404afe:	call 0x0040923d
0x0040923d:	pushl $0x409209<UINT32>
0x00409242:	call EncodePointer@KERNEL32.DLL
0x00409248:	movl 0x42602c, %eax
0x0040924d:	ret

0x00404b03:	pushl %esi
0x00404b04:	call 0x004094ac
0x004094ac:	pushl %ebp
0x004094ad:	movl %ebp, %esp
0x004094af:	movl %eax, 0x8(%ebp)
0x004094b2:	movl 0x42604c, %eax
0x004094b7:	popl %ebp
0x004094b8:	ret

0x00404b09:	addl %esp, $0x18<UINT8>
0x00404b0c:	popl %esi
0x00404b0d:	jmp 0x0040899e
0x0040899e:	pushl %esi
0x0040899f:	pushl %edi
0x004089a0:	pushl $0x41e728<UINT32>
0x004089a5:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x004089ab:	movl %esi, 0x4170e0
0x004089b1:	movl %edi, %eax
0x004089b3:	pushl $0x41e744<UINT32>
0x004089b8:	pushl %edi
0x004089b9:	call GetProcAddress@KERNEL32.DLL
0x004089bb:	xorl %eax, 0x4240d0
0x004089c1:	pushl $0x41e750<UINT32>
0x004089c6:	pushl %edi
0x004089c7:	movl 0x426620, %eax
0x004089cc:	call GetProcAddress@KERNEL32.DLL
0x004089ce:	xorl %eax, 0x4240d0
0x004089d4:	pushl $0x41e758<UINT32>
0x004089d9:	pushl %edi
0x004089da:	movl 0x426624, %eax
0x004089df:	call GetProcAddress@KERNEL32.DLL
0x004089e1:	xorl %eax, 0x4240d0
0x004089e7:	pushl $0x41e764<UINT32>
0x004089ec:	pushl %edi
0x004089ed:	movl 0x426628, %eax
0x004089f2:	call GetProcAddress@KERNEL32.DLL
0x004089f4:	xorl %eax, 0x4240d0
0x004089fa:	pushl $0x41e770<UINT32>
0x004089ff:	pushl %edi
0x00408a00:	movl 0x42662c, %eax
0x00408a05:	call GetProcAddress@KERNEL32.DLL
0x00408a07:	xorl %eax, 0x4240d0
0x00408a0d:	pushl $0x41e78c<UINT32>
0x00408a12:	pushl %edi
0x00408a13:	movl 0x426630, %eax
0x00408a18:	call GetProcAddress@KERNEL32.DLL
0x00408a1a:	xorl %eax, 0x4240d0
0x00408a20:	pushl $0x41e79c<UINT32>
0x00408a25:	pushl %edi
0x00408a26:	movl 0x426634, %eax
0x00408a2b:	call GetProcAddress@KERNEL32.DLL
0x00408a2d:	xorl %eax, 0x4240d0
0x00408a33:	pushl $0x41e7b0<UINT32>
0x00408a38:	pushl %edi
0x00408a39:	movl 0x426638, %eax
0x00408a3e:	call GetProcAddress@KERNEL32.DLL
0x00408a40:	xorl %eax, 0x4240d0
0x00408a46:	pushl $0x41e7c8<UINT32>
0x00408a4b:	pushl %edi
0x00408a4c:	movl 0x42663c, %eax
0x00408a51:	call GetProcAddress@KERNEL32.DLL
0x00408a53:	xorl %eax, 0x4240d0
0x00408a59:	pushl $0x41e7e0<UINT32>
0x00408a5e:	pushl %edi
0x00408a5f:	movl 0x426640, %eax
0x00408a64:	call GetProcAddress@KERNEL32.DLL
0x00408a66:	xorl %eax, 0x4240d0
0x00408a6c:	pushl $0x41e7f4<UINT32>
0x00408a71:	pushl %edi
0x00408a72:	movl 0x426644, %eax
0x00408a77:	call GetProcAddress@KERNEL32.DLL
0x00408a79:	xorl %eax, 0x4240d0
0x00408a7f:	pushl $0x41e814<UINT32>
0x00408a84:	pushl %edi
0x00408a85:	movl 0x426648, %eax
0x00408a8a:	call GetProcAddress@KERNEL32.DLL
0x00408a8c:	xorl %eax, 0x4240d0
0x00408a92:	pushl $0x41e82c<UINT32>
0x00408a97:	pushl %edi
0x00408a98:	movl 0x42664c, %eax
0x00408a9d:	call GetProcAddress@KERNEL32.DLL
0x00408a9f:	xorl %eax, 0x4240d0
0x00408aa5:	pushl $0x41e844<UINT32>
0x00408aaa:	pushl %edi
0x00408aab:	movl 0x426650, %eax
0x00408ab0:	call GetProcAddress@KERNEL32.DLL
0x00408ab2:	xorl %eax, 0x4240d0
0x00408ab8:	pushl $0x41e858<UINT32>
0x00408abd:	pushl %edi
0x00408abe:	movl 0x426654, %eax
0x00408ac3:	call GetProcAddress@KERNEL32.DLL
0x00408ac5:	xorl %eax, 0x4240d0
0x00408acb:	movl 0x426658, %eax
0x00408ad0:	pushl $0x41e86c<UINT32>
0x00408ad5:	pushl %edi
0x00408ad6:	call GetProcAddress@KERNEL32.DLL
0x00408ad8:	xorl %eax, 0x4240d0
0x00408ade:	pushl $0x41e888<UINT32>
0x00408ae3:	pushl %edi
0x00408ae4:	movl 0x42665c, %eax
0x00408ae9:	call GetProcAddress@KERNEL32.DLL
0x00408aeb:	xorl %eax, 0x4240d0
0x00408af1:	pushl $0x41e8a8<UINT32>
0x00408af6:	pushl %edi
0x00408af7:	movl 0x426660, %eax
0x00408afc:	call GetProcAddress@KERNEL32.DLL
0x00408afe:	xorl %eax, 0x4240d0
0x00408b04:	pushl $0x41e8c4<UINT32>
0x00408b09:	pushl %edi
0x00408b0a:	movl 0x426664, %eax
0x00408b0f:	call GetProcAddress@KERNEL32.DLL
0x00408b11:	xorl %eax, 0x4240d0
0x00408b17:	pushl $0x41e8e4<UINT32>
0x00408b1c:	pushl %edi
0x00408b1d:	movl 0x426668, %eax
0x00408b22:	call GetProcAddress@KERNEL32.DLL
0x00408b24:	xorl %eax, 0x4240d0
0x00408b2a:	pushl $0x41e8f8<UINT32>
0x00408b2f:	pushl %edi
0x00408b30:	movl 0x42666c, %eax
0x00408b35:	call GetProcAddress@KERNEL32.DLL
0x00408b37:	xorl %eax, 0x4240d0
0x00408b3d:	pushl $0x41e914<UINT32>
0x00408b42:	pushl %edi
0x00408b43:	movl 0x426670, %eax
0x00408b48:	call GetProcAddress@KERNEL32.DLL
0x00408b4a:	xorl %eax, 0x4240d0
0x00408b50:	pushl $0x41e928<UINT32>
0x00408b55:	pushl %edi
0x00408b56:	movl 0x426678, %eax
0x00408b5b:	call GetProcAddress@KERNEL32.DLL
0x00408b5d:	xorl %eax, 0x4240d0
0x00408b63:	pushl $0x41e938<UINT32>
0x00408b68:	pushl %edi
0x00408b69:	movl 0x426674, %eax
0x00408b6e:	call GetProcAddress@KERNEL32.DLL
0x00408b70:	xorl %eax, 0x4240d0
0x00408b76:	pushl $0x41e948<UINT32>
0x00408b7b:	pushl %edi
0x00408b7c:	movl 0x42667c, %eax
0x00408b81:	call GetProcAddress@KERNEL32.DLL
0x00408b83:	xorl %eax, 0x4240d0
0x00408b89:	pushl $0x41e958<UINT32>
0x00408b8e:	pushl %edi
0x00408b8f:	movl 0x426680, %eax
0x00408b94:	call GetProcAddress@KERNEL32.DLL
0x00408b96:	xorl %eax, 0x4240d0
0x00408b9c:	pushl $0x41e968<UINT32>
0x00408ba1:	pushl %edi
0x00408ba2:	movl 0x426684, %eax
0x00408ba7:	call GetProcAddress@KERNEL32.DLL
0x00408ba9:	xorl %eax, 0x4240d0
0x00408baf:	pushl $0x41e984<UINT32>
0x00408bb4:	pushl %edi
0x00408bb5:	movl 0x426688, %eax
0x00408bba:	call GetProcAddress@KERNEL32.DLL
0x00408bbc:	xorl %eax, 0x4240d0
0x00408bc2:	pushl $0x41e998<UINT32>
0x00408bc7:	pushl %edi
0x00408bc8:	movl 0x42668c, %eax
0x00408bcd:	call GetProcAddress@KERNEL32.DLL
0x00408bcf:	xorl %eax, 0x4240d0
0x00408bd5:	pushl $0x41e9a8<UINT32>
0x00408bda:	pushl %edi
0x00408bdb:	movl 0x426690, %eax
0x00408be0:	call GetProcAddress@KERNEL32.DLL
0x00408be2:	xorl %eax, 0x4240d0
0x00408be8:	pushl $0x41e9bc<UINT32>
0x00408bed:	pushl %edi
0x00408bee:	movl 0x426694, %eax
0x00408bf3:	call GetProcAddress@KERNEL32.DLL
0x00408bf5:	xorl %eax, 0x4240d0
0x00408bfb:	movl 0x426698, %eax
0x00408c00:	pushl $0x41e9cc<UINT32>
0x00408c05:	pushl %edi
0x00408c06:	call GetProcAddress@KERNEL32.DLL
0x00408c08:	xorl %eax, 0x4240d0
0x00408c0e:	pushl $0x41e9ec<UINT32>
0x00408c13:	pushl %edi
0x00408c14:	movl 0x42669c, %eax
0x00408c19:	call GetProcAddress@KERNEL32.DLL
0x00408c1b:	xorl %eax, 0x4240d0
0x00408c21:	popl %edi
0x00408c22:	movl 0x4266a0, %eax
0x00408c27:	popl %esi
0x00408c28:	ret

0x0040858b:	call 0x00408864
0x00408864:	pushl %esi
0x00408865:	pushl %edi
0x00408866:	movl %esi, $0x424c30<UINT32>
0x0040886b:	movl %edi, $0x4258a8<UINT32>
0x00408870:	cmpl 0x4(%esi), $0x1<UINT8>
0x00408874:	jne 22
0x00408876:	pushl $0x0<UINT8>
0x00408878:	movl (%esi), %edi
0x0040887a:	addl %edi, $0x18<UINT8>
0x0040887d:	pushl $0xfa0<UINT32>
0x00408882:	pushl (%esi)
0x00408884:	call 0x00408930
0x00408930:	pushl %ebp
0x00408931:	movl %ebp, %esp
0x00408933:	movl %eax, 0x426630
0x00408938:	xorl %eax, 0x4240d0
0x0040893e:	je 13
0x00408940:	pushl 0x10(%ebp)
0x00408943:	pushl 0xc(%ebp)
0x00408946:	pushl 0x8(%ebp)
0x00408949:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x0040894b:	popl %ebp
0x0040894c:	ret

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
