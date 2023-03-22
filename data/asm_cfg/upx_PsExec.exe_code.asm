0x0047f460:	pusha
0x0047f461:	movl %esi, $0x464000<UINT32>
0x0047f466:	leal %edi, -405504(%esi)
0x0047f46c:	pushl %edi
0x0047f46d:	jmp 0x0047f47a
0x0047f47a:	movl %ebx, (%esi)
0x0047f47c:	subl %esi, $0xfffffffc<UINT8>
0x0047f47f:	adcl %ebx, %ebx
0x0047f481:	jb 0x0047f470
0x0047f470:	movb %al, (%esi)
0x0047f472:	incl %esi
0x0047f473:	movb (%edi), %al
0x0047f475:	incl %edi
0x0047f476:	addl %ebx, %ebx
0x0047f478:	jne 0x0047f481
0x0047f483:	movl %eax, $0x1<UINT32>
0x0047f488:	addl %ebx, %ebx
0x0047f48a:	jne 0x0047f493
0x0047f493:	adcl %eax, %eax
0x0047f495:	addl %ebx, %ebx
0x0047f497:	jae 0x0047f4a4
0x0047f499:	jne 0x0047f4c3
0x0047f4c3:	xorl %ecx, %ecx
0x0047f4c5:	subl %eax, $0x3<UINT8>
0x0047f4c8:	jb 0x0047f4db
0x0047f4ca:	shll %eax, $0x8<UINT8>
0x0047f4cd:	movb %al, (%esi)
0x0047f4cf:	incl %esi
0x0047f4d0:	xorl %eax, $0xffffffff<UINT8>
0x0047f4d3:	je 0x0047f54a
0x0047f4d5:	sarl %eax
0x0047f4d7:	movl %ebp, %eax
0x0047f4d9:	jmp 0x0047f4e6
0x0047f4e6:	jb 0x0047f4b4
0x0047f4b4:	addl %ebx, %ebx
0x0047f4b6:	jne 0x0047f4bf
0x0047f4bf:	adcl %ecx, %ecx
0x0047f4c1:	jmp 0x0047f515
0x0047f515:	cmpl %ebp, $0xfffffb00<UINT32>
0x0047f51b:	adcl %ecx, $0x2<UINT8>
0x0047f51e:	leal %edx, (%edi,%ebp)
0x0047f521:	cmpl %ebp, $0xfffffffc<UINT8>
0x0047f524:	jbe 0x0047f534
0x0047f534:	movl %eax, (%edx)
0x0047f536:	addl %edx, $0x4<UINT8>
0x0047f539:	movl (%edi), %eax
0x0047f53b:	addl %edi, $0x4<UINT8>
0x0047f53e:	subl %ecx, $0x4<UINT8>
0x0047f541:	ja 0x0047f534
0x0047f543:	addl %edi, %ecx
0x0047f545:	jmp 0x0047f476
0x0047f526:	movb %al, (%edx)
0x0047f528:	incl %edx
0x0047f529:	movb (%edi), %al
0x0047f52b:	incl %edi
0x0047f52c:	decl %ecx
0x0047f52d:	jne 0x0047f526
0x0047f52f:	jmp 0x0047f476
0x0047f4e8:	incl %ecx
0x0047f4e9:	addl %ebx, %ebx
0x0047f4eb:	jne 0x0047f4f4
0x0047f4f4:	jb 0x0047f4b4
0x0047f4f6:	addl %ebx, %ebx
0x0047f4f8:	jne 0x0047f501
0x0047f501:	adcl %ecx, %ecx
0x0047f503:	addl %ebx, %ebx
0x0047f505:	jae 0x0047f4f6
0x0047f507:	jne 0x0047f512
0x0047f512:	addl %ecx, $0x2<UINT8>
0x0047f4b8:	movl %ebx, (%esi)
0x0047f4ba:	subl %esi, $0xfffffffc<UINT8>
0x0047f4bd:	adcl %ebx, %ebx
0x0047f4a4:	decl %eax
0x0047f4a5:	addl %ebx, %ebx
0x0047f4a7:	jne 0x0047f4b0
0x0047f4b0:	adcl %eax, %eax
0x0047f4b2:	jmp 0x0047f488
0x0047f4db:	addl %ebx, %ebx
0x0047f4dd:	jne 0x0047f4e6
0x0047f509:	movl %ebx, (%esi)
0x0047f50b:	subl %esi, $0xfffffffc<UINT8>
0x0047f50e:	adcl %ebx, %ebx
0x0047f510:	jae 0x0047f4f6
0x0047f48c:	movl %ebx, (%esi)
0x0047f48e:	subl %esi, $0xfffffffc<UINT8>
0x0047f491:	adcl %ebx, %ebx
0x0047f4a9:	movl %ebx, (%esi)
0x0047f4ab:	subl %esi, $0xfffffffc<UINT8>
0x0047f4ae:	adcl %ebx, %ebx
0x0047f4df:	movl %ebx, (%esi)
0x0047f4e1:	subl %esi, $0xfffffffc<UINT8>
0x0047f4e4:	adcl %ebx, %ebx
0x0047f49b:	movl %ebx, (%esi)
0x0047f49d:	subl %esi, $0xfffffffc<UINT8>
0x0047f4a0:	adcl %ebx, %ebx
0x0047f4a2:	jb 0x0047f4c3
0x0047f4ed:	movl %ebx, (%esi)
0x0047f4ef:	subl %esi, $0xfffffffc<UINT8>
0x0047f4f2:	adcl %ebx, %ebx
0x0047f4fa:	movl %ebx, (%esi)
0x0047f4fc:	subl %esi, $0xfffffffc<UINT8>
0x0047f4ff:	adcl %ebx, %ebx
0x0047f54a:	popl %esi
0x0047f54b:	movl %edi, %esi
0x0047f54d:	movl %ecx, $0x900<UINT32>
0x0047f552:	movb %al, (%edi)
0x0047f554:	incl %edi
0x0047f555:	subb %al, $0xffffffe8<UINT8>
0x0047f557:	cmpb %al, $0x1<UINT8>
0x0047f559:	ja 0x0047f552
0x0047f55b:	cmpb (%edi), $0x5<UINT8>
0x0047f55e:	jne 0x0047f552
0x0047f560:	movl %eax, (%edi)
0x0047f562:	movb %bl, 0x4(%edi)
0x0047f565:	shrw %ax, $0x8<UINT8>
0x0047f569:	roll %eax, $0x10<UINT8>
0x0047f56c:	xchgb %ah, %al
0x0047f56e:	subl %eax, %edi
0x0047f570:	subb %bl, $0xffffffe8<UINT8>
0x0047f573:	addl %eax, %esi
0x0047f575:	movl (%edi), %eax
0x0047f577:	addl %edi, $0x5<UINT8>
0x0047f57a:	movb %al, %bl
0x0047f57c:	loop 0x0047f557
0x0047f57e:	leal %edi, 0x7c000(%esi)
0x0047f584:	movl %eax, (%edi)
0x0047f586:	orl %eax, %eax
0x0047f588:	je 0x0047f5cf
0x0047f58a:	movl %ebx, 0x4(%edi)
0x0047f58d:	leal %eax, 0x7f5fc(%eax,%esi)
0x0047f594:	addl %ebx, %esi
0x0047f596:	pushl %eax
0x0047f597:	addl %edi, $0x8<UINT8>
0x0047f59a:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0047f5a0:	xchgl %ebp, %eax
0x0047f5a1:	movb %al, (%edi)
0x0047f5a3:	incl %edi
0x0047f5a4:	orb %al, %al
0x0047f5a6:	je 0x0047f584
0x0047f5a8:	movl %ecx, %edi
0x0047f5aa:	jns 0x0047f5b3
0x0047f5b3:	pushl %edi
0x0047f5b4:	decl %eax
0x0047f5b5:	repn scasb %al, %es:(%edi)
0x0047f5b7:	pushl %ebp
0x0047f5b8:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0047f5be:	orl %eax, %eax
0x0047f5c0:	je 7
0x0047f5c2:	movl (%ebx), %eax
0x0047f5c4:	addl %ebx, $0x4<UINT8>
0x0047f5c7:	jmp 0x0047f5a1
GetProcAddress@KERNEL32.DLL: API Node	
0x0047f5ac:	movzwl %eax, (%edi)
0x0047f5af:	incl %edi
0x0047f5b0:	pushl %eax
0x0047f5b1:	incl %edi
0x0047f5b2:	movl %ecx, $0xaef24857<UINT32>
0x0047f5cf:	addl %edi, $0x4<UINT8>
0x0047f5d2:	leal %ebx, -4(%esi)
0x0047f5d5:	xorl %eax, %eax
0x0047f5d7:	movb %al, (%edi)
0x0047f5d9:	incl %edi
0x0047f5da:	orl %eax, %eax
0x0047f5dc:	je 0x0047f600
0x0047f5de:	cmpb %al, $0xffffffef<UINT8>
0x0047f5e0:	ja 0x0047f5f3
0x0047f5e2:	addl %ebx, %eax
0x0047f5e4:	movl %eax, (%ebx)
0x0047f5e6:	xchgb %ah, %al
0x0047f5e8:	roll %eax, $0x10<UINT8>
0x0047f5eb:	xchgb %ah, %al
0x0047f5ed:	addl %eax, %esi
0x0047f5ef:	movl (%ebx), %eax
0x0047f5f1:	jmp 0x0047f5d5
0x0047f5f3:	andb %al, $0xf<UINT8>
0x0047f5f5:	shll %eax, $0x10<UINT8>
0x0047f5f8:	movw %ax, (%edi)
0x0047f5fb:	addl %edi, $0x2<UINT8>
0x0047f5fe:	jmp 0x0047f5e2
0x0047f600:	movl %ebp, 0x7f6b8(%esi)
0x0047f606:	leal %edi, -4096(%esi)
0x0047f60c:	movl %ebx, $0x1000<UINT32>
0x0047f611:	pushl %eax
0x0047f612:	pushl %esp
0x0047f613:	pushl $0x4<UINT8>
0x0047f615:	pushl %ebx
0x0047f616:	pushl %edi
0x0047f617:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0047f619:	leal %eax, 0x217(%edi)
0x0047f61f:	andb (%eax), $0x7f<UINT8>
0x0047f622:	andb 0x28(%eax), $0x7f<UINT8>
0x0047f626:	popl %eax
0x0047f627:	pushl %eax
0x0047f628:	pushl %esp
0x0047f629:	pushl %eax
0x0047f62a:	pushl %ebx
0x0047f62b:	pushl %edi
0x0047f62c:	call VirtualProtect@kernel32.dll
0x0047f62e:	popl %eax
0x0047f62f:	popa
0x0047f630:	leal %eax, -128(%esp)
0x0047f634:	pushl $0x0<UINT8>
0x0047f636:	cmpl %esp, %eax
0x0047f638:	jne 0x0047f634
0x0047f63a:	subl %esp, $0xffffff80<UINT8>
0x0047f63d:	jmp 0x00409de6
0x00409de6:	call 0x00411500
0x00411500:	pushl %ebp
0x00411501:	movl %ebp, %esp
0x00411503:	subl %esp, $0x14<UINT8>
0x00411506:	andl -12(%ebp), $0x0<UINT8>
0x0041150a:	andl -8(%ebp), $0x0<UINT8>
0x0041150e:	movl %eax, 0x42a130
0x00411513:	pushl %esi
0x00411514:	pushl %edi
0x00411515:	movl %edi, $0xbb40e64e<UINT32>
0x0041151a:	movl %esi, $0xffff0000<UINT32>
0x0041151f:	cmpl %eax, %edi
0x00411521:	je 0x00411530
0x00411530:	leal %eax, -12(%ebp)
0x00411533:	pushl %eax
0x00411534:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0041153a:	movl %eax, -8(%ebp)
0x0041153d:	xorl %eax, -12(%ebp)
0x00411540:	movl -4(%ebp), %eax
0x00411543:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x00411549:	xorl -4(%ebp), %eax
0x0041154c:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x00411552:	xorl -4(%ebp), %eax
0x00411555:	leal %eax, -20(%ebp)
0x00411558:	pushl %eax
0x00411559:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0041155f:	movl %ecx, -16(%ebp)
0x00411562:	leal %eax, -4(%ebp)
0x00411565:	xorl %ecx, -20(%ebp)
0x00411568:	xorl %ecx, -4(%ebp)
0x0041156b:	xorl %ecx, %eax
0x0041156d:	cmpl %ecx, %edi
0x0041156f:	jne 0x00411578
0x00411578:	testl %esi, %ecx
0x0041157a:	jne 0x00411588
0x00411588:	movl 0x42a130, %ecx
0x0041158e:	notl %ecx
0x00411590:	movl 0x42a134, %ecx
0x00411596:	popl %edi
0x00411597:	popl %esi
0x00411598:	movl %esp, %ebp
0x0041159a:	popl %ebp
0x0041159b:	ret

0x00409deb:	jmp 0x00409c6b
0x00409c6b:	pushl $0x14<UINT8>
0x00409c6d:	pushl $0x427250<UINT32>
0x00409c72:	call 0x0040bcc0
0x0040bcc0:	pushl $0x409240<UINT32>
0x0040bcc5:	pushl %fs:0
0x0040bccc:	movl %eax, 0x10(%esp)
0x0040bcd0:	movl 0x10(%esp), %ebp
0x0040bcd4:	leal %ebp, 0x10(%esp)
0x0040bcd8:	subl %esp, %eax
0x0040bcda:	pushl %ebx
0x0040bcdb:	pushl %esi
0x0040bcdc:	pushl %edi
0x0040bcdd:	movl %eax, 0x42a130
0x0040bce2:	xorl -4(%ebp), %eax
0x0040bce5:	xorl %eax, %ebp
0x0040bce7:	pushl %eax
0x0040bce8:	movl -24(%ebp), %esp
0x0040bceb:	pushl -8(%ebp)
0x0040bcee:	movl %eax, -4(%ebp)
0x0040bcf1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040bcf8:	movl -8(%ebp), %eax
0x0040bcfb:	leal %eax, -16(%ebp)
0x0040bcfe:	movl %fs:0, %eax
0x0040bd04:	ret

0x00409c77:	pushl $0x1<UINT8>
0x00409c79:	call 0x004114b3
0x004114b3:	pushl %ebp
0x004114b4:	movl %ebp, %esp
0x004114b6:	movl %eax, 0x8(%ebp)
0x004114b9:	movl 0x430ca8, %eax
0x004114be:	popl %ebp
0x004114bf:	ret

0x00409c7e:	popl %ecx
0x00409c7f:	movl %eax, $0x5a4d<UINT32>
0x00409c84:	cmpw 0x400000, %ax
0x00409c8b:	je 0x00409c91
0x00409c91:	movl %eax, 0x40003c
0x00409c96:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00409ca0:	jne -21
0x00409ca2:	movl %ecx, $0x10b<UINT32>
0x00409ca7:	cmpw 0x400018(%eax), %cx
0x00409cae:	jne -35
0x00409cb0:	xorl %ebx, %ebx
0x00409cb2:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00409cb9:	jbe 9
0x00409cbb:	cmpl 0x4000e8(%eax), %ebx
0x00409cc1:	setne %bl
0x00409cc4:	movl -28(%ebp), %ebx
0x00409cc7:	call 0x0040bdf0
0x0040bdf0:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x0040bdf6:	xorl %ecx, %ecx
0x0040bdf8:	movl 0x431308, %eax
0x0040bdfd:	testl %eax, %eax
0x0040bdff:	setne %cl
0x0040be02:	movl %eax, %ecx
0x0040be04:	ret

0x00409ccc:	testl %eax, %eax
0x00409cce:	jne 0x00409cd8
0x00409cd8:	call 0x0040ad2e
0x0040ad2e:	call 0x004070f9
0x004070f9:	pushl %esi
0x004070fa:	pushl $0x0<UINT8>
0x004070fc:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00407102:	movl %esi, %eax
0x00407104:	pushl %esi
0x00407105:	call 0x0040ba72
0x0040ba72:	pushl %ebp
0x0040ba73:	movl %ebp, %esp
0x0040ba75:	movl %eax, 0x8(%ebp)
0x0040ba78:	movl 0x4312e0, %eax
0x0040ba7d:	popl %ebp
0x0040ba7e:	ret

0x0040710a:	pushl %esi
0x0040710b:	call 0x00409f15
0x00409f15:	pushl %ebp
0x00409f16:	movl %ebp, %esp
0x00409f18:	movl %eax, 0x8(%ebp)
0x00409f1b:	movl 0x430b30, %eax
0x00409f20:	popl %ebp
0x00409f21:	ret

0x00407110:	pushl %esi
0x00407111:	call 0x0040ba7f
0x0040ba7f:	pushl %ebp
0x0040ba80:	movl %ebp, %esp
0x0040ba82:	movl %eax, 0x8(%ebp)
0x0040ba85:	movl 0x4312e4, %eax
0x0040ba8a:	popl %ebp
0x0040ba8b:	ret

0x00407116:	pushl %esi
0x00407117:	call 0x0040ba99
0x0040ba99:	pushl %ebp
0x0040ba9a:	movl %ebp, %esp
0x0040ba9c:	movl %eax, 0x8(%ebp)
0x0040ba9f:	movl 0x4312e8, %eax
0x0040baa4:	movl 0x4312ec, %eax
0x0040baa9:	movl 0x4312f0, %eax
0x0040baae:	movl 0x4312f4, %eax
0x0040bab3:	popl %ebp
0x0040bab4:	ret

0x0040711c:	pushl %esi
0x0040711d:	call 0x0040ba3b
0x0040ba3b:	pushl $0x40ba07<UINT32>
0x0040ba40:	call EncodePointer@KERNEL32.DLL
0x0040ba46:	movl 0x4312dc, %eax
0x0040ba4b:	ret

0x00407122:	pushl %esi
0x00407123:	call 0x0040bcaa
0x0040bcaa:	pushl %ebp
0x0040bcab:	movl %ebp, %esp
0x0040bcad:	movl %eax, 0x8(%ebp)
0x0040bcb0:	movl 0x4312fc, %eax
0x0040bcb5:	popl %ebp
0x0040bcb6:	ret

0x00407128:	addl %esp, $0x18<UINT8>
0x0040712b:	popl %esi
0x0040712c:	jmp 0x0040b146
0x0040b146:	pushl %esi
0x0040b147:	pushl %edi
0x0040b148:	pushl $0x423758<UINT32>
0x0040b14d:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0040b153:	movl %esi, 0x41a18c
0x0040b159:	movl %edi, %eax
0x0040b15b:	pushl $0x423774<UINT32>
0x0040b160:	pushl %edi
0x0040b161:	call GetProcAddress@KERNEL32.DLL
0x0040b163:	xorl %eax, 0x42a130
0x0040b169:	pushl $0x423780<UINT32>
0x0040b16e:	pushl %edi
0x0040b16f:	movl 0x455ce0, %eax
0x0040b174:	call GetProcAddress@KERNEL32.DLL
0x0040b176:	xorl %eax, 0x42a130
0x0040b17c:	pushl $0x423788<UINT32>
0x0040b181:	pushl %edi
0x0040b182:	movl 0x455ce4, %eax
0x0040b187:	call GetProcAddress@KERNEL32.DLL
0x0040b189:	xorl %eax, 0x42a130
0x0040b18f:	pushl $0x423794<UINT32>
0x0040b194:	pushl %edi
0x0040b195:	movl 0x455ce8, %eax
0x0040b19a:	call GetProcAddress@KERNEL32.DLL
0x0040b19c:	xorl %eax, 0x42a130
0x0040b1a2:	pushl $0x4237a0<UINT32>
0x0040b1a7:	pushl %edi
0x0040b1a8:	movl 0x455cec, %eax
0x0040b1ad:	call GetProcAddress@KERNEL32.DLL
0x0040b1af:	xorl %eax, 0x42a130
0x0040b1b5:	pushl $0x4237bc<UINT32>
0x0040b1ba:	pushl %edi
0x0040b1bb:	movl 0x455cf0, %eax
0x0040b1c0:	call GetProcAddress@KERNEL32.DLL
0x0040b1c2:	xorl %eax, 0x42a130
0x0040b1c8:	pushl $0x4237cc<UINT32>
0x0040b1cd:	pushl %edi
0x0040b1ce:	movl 0x455cf4, %eax
0x0040b1d3:	call GetProcAddress@KERNEL32.DLL
0x0040b1d5:	xorl %eax, 0x42a130
0x0040b1db:	pushl $0x4237e0<UINT32>
0x0040b1e0:	pushl %edi
0x0040b1e1:	movl 0x455cf8, %eax
0x0040b1e6:	call GetProcAddress@KERNEL32.DLL
0x0040b1e8:	xorl %eax, 0x42a130
0x0040b1ee:	pushl $0x4237f8<UINT32>
0x0040b1f3:	pushl %edi
0x0040b1f4:	movl 0x455cfc, %eax
0x0040b1f9:	call GetProcAddress@KERNEL32.DLL
0x0040b1fb:	xorl %eax, 0x42a130
0x0040b201:	pushl $0x423810<UINT32>
0x0040b206:	pushl %edi
0x0040b207:	movl 0x455d00, %eax
0x0040b20c:	call GetProcAddress@KERNEL32.DLL
0x0040b20e:	xorl %eax, 0x42a130
0x0040b214:	pushl $0x423824<UINT32>
0x0040b219:	pushl %edi
0x0040b21a:	movl 0x455d04, %eax
0x0040b21f:	call GetProcAddress@KERNEL32.DLL
0x0040b221:	xorl %eax, 0x42a130
0x0040b227:	pushl $0x423844<UINT32>
0x0040b22c:	pushl %edi
0x0040b22d:	movl 0x455d08, %eax
0x0040b232:	call GetProcAddress@KERNEL32.DLL
0x0040b234:	xorl %eax, 0x42a130
0x0040b23a:	pushl $0x42385c<UINT32>
0x0040b23f:	pushl %edi
0x0040b240:	movl 0x455d0c, %eax
0x0040b245:	call GetProcAddress@KERNEL32.DLL
0x0040b247:	xorl %eax, 0x42a130
0x0040b24d:	pushl $0x423874<UINT32>
0x0040b252:	pushl %edi
0x0040b253:	movl 0x455d10, %eax
0x0040b258:	call GetProcAddress@KERNEL32.DLL
0x0040b25a:	xorl %eax, 0x42a130
0x0040b260:	pushl $0x423888<UINT32>
0x0040b265:	pushl %edi
0x0040b266:	movl 0x455d14, %eax
0x0040b26b:	call GetProcAddress@KERNEL32.DLL
0x0040b26d:	xorl %eax, 0x42a130
0x0040b273:	movl 0x455d18, %eax
0x0040b278:	pushl $0x42389c<UINT32>
0x0040b27d:	pushl %edi
0x0040b27e:	call GetProcAddress@KERNEL32.DLL
0x0040b280:	xorl %eax, 0x42a130
0x0040b286:	pushl $0x4238b8<UINT32>
0x0040b28b:	pushl %edi
0x0040b28c:	movl 0x455d1c, %eax
0x0040b291:	call GetProcAddress@KERNEL32.DLL
0x0040b293:	xorl %eax, 0x42a130
0x0040b299:	pushl $0x4238d8<UINT32>
0x0040b29e:	pushl %edi
0x0040b29f:	movl 0x455d20, %eax
0x0040b2a4:	call GetProcAddress@KERNEL32.DLL
0x0040b2a6:	xorl %eax, 0x42a130
0x0040b2ac:	pushl $0x4238f4<UINT32>
0x0040b2b1:	pushl %edi
0x0040b2b2:	movl 0x455d24, %eax
0x0040b2b7:	call GetProcAddress@KERNEL32.DLL
0x0040b2b9:	xorl %eax, 0x42a130
0x0040b2bf:	pushl $0x423914<UINT32>
0x0040b2c4:	pushl %edi
0x0040b2c5:	movl 0x455d28, %eax
0x0040b2ca:	call GetProcAddress@KERNEL32.DLL
0x0040b2cc:	xorl %eax, 0x42a130
0x0040b2d2:	pushl $0x423928<UINT32>
0x0040b2d7:	pushl %edi
0x0040b2d8:	movl 0x455d2c, %eax
0x0040b2dd:	call GetProcAddress@KERNEL32.DLL
0x0040b2df:	xorl %eax, 0x42a130
0x0040b2e5:	pushl $0x423944<UINT32>
0x0040b2ea:	pushl %edi
0x0040b2eb:	movl 0x455d30, %eax
0x0040b2f0:	call GetProcAddress@KERNEL32.DLL
0x0040b2f2:	xorl %eax, 0x42a130
0x0040b2f8:	pushl $0x423958<UINT32>
0x0040b2fd:	pushl %edi
0x0040b2fe:	movl 0x455d38, %eax
0x0040b303:	call GetProcAddress@KERNEL32.DLL
0x0040b305:	xorl %eax, 0x42a130
0x0040b30b:	pushl $0x423968<UINT32>
0x0040b310:	pushl %edi
0x0040b311:	movl 0x455d34, %eax
0x0040b316:	call GetProcAddress@KERNEL32.DLL
0x0040b318:	xorl %eax, 0x42a130
0x0040b31e:	pushl $0x423978<UINT32>
0x0040b323:	pushl %edi
0x0040b324:	movl 0x455d3c, %eax
0x0040b329:	call GetProcAddress@KERNEL32.DLL
0x0040b32b:	xorl %eax, 0x42a130
0x0040b331:	pushl $0x423988<UINT32>
0x0040b336:	pushl %edi
0x0040b337:	movl 0x455d40, %eax
0x0040b33c:	call GetProcAddress@KERNEL32.DLL
0x0040b33e:	xorl %eax, 0x42a130
0x0040b344:	pushl $0x423998<UINT32>
0x0040b349:	pushl %edi
0x0040b34a:	movl 0x455d44, %eax
0x0040b34f:	call GetProcAddress@KERNEL32.DLL
0x0040b351:	xorl %eax, 0x42a130
0x0040b357:	pushl $0x4239b4<UINT32>
0x0040b35c:	pushl %edi
0x0040b35d:	movl 0x455d48, %eax
0x0040b362:	call GetProcAddress@KERNEL32.DLL
0x0040b364:	xorl %eax, 0x42a130
0x0040b36a:	pushl $0x4239c8<UINT32>
0x0040b36f:	pushl %edi
0x0040b370:	movl 0x455d4c, %eax
0x0040b375:	call GetProcAddress@KERNEL32.DLL
0x0040b377:	xorl %eax, 0x42a130
0x0040b37d:	pushl $0x4239d8<UINT32>
0x0040b382:	pushl %edi
0x0040b383:	movl 0x455d50, %eax
0x0040b388:	call GetProcAddress@KERNEL32.DLL
0x0040b38a:	xorl %eax, 0x42a130
0x0040b390:	pushl $0x4239ec<UINT32>
0x0040b395:	pushl %edi
0x0040b396:	movl 0x455d54, %eax
0x0040b39b:	call GetProcAddress@KERNEL32.DLL
0x0040b39d:	xorl %eax, 0x42a130
0x0040b3a3:	movl 0x455d58, %eax
0x0040b3a8:	pushl $0x4239fc<UINT32>
0x0040b3ad:	pushl %edi
0x0040b3ae:	call GetProcAddress@KERNEL32.DLL
0x0040b3b0:	xorl %eax, 0x42a130
0x0040b3b6:	pushl $0x423a1c<UINT32>
0x0040b3bb:	pushl %edi
0x0040b3bc:	movl 0x455d5c, %eax
0x0040b3c1:	call GetProcAddress@KERNEL32.DLL
0x0040b3c3:	xorl %eax, 0x42a130
0x0040b3c9:	popl %edi
0x0040b3ca:	movl 0x455d60, %eax
0x0040b3cf:	popl %esi
0x0040b3d0:	ret

0x0040ad33:	call 0x0040b00c
0x0040b00c:	pushl %esi
0x0040b00d:	pushl %edi
0x0040b00e:	movl %esi, $0x42ac88<UINT32>
0x0040b013:	movl %edi, $0x430b58<UINT32>
0x0040b018:	cmpl 0x4(%esi), $0x1<UINT8>
0x0040b01c:	jne 22
0x0040b01e:	pushl $0x0<UINT8>
0x0040b020:	movl (%esi), %edi
0x0040b022:	addl %edi, $0x18<UINT8>
0x0040b025:	pushl $0xfa0<UINT32>
0x0040b02a:	pushl (%esi)
0x0040b02c:	call 0x0040b0d8
0x0040b0d8:	pushl %ebp
0x0040b0d9:	movl %ebp, %esp
0x0040b0db:	movl %eax, 0x455cf0
0x0040b0e0:	xorl %eax, 0x42a130
0x0040b0e6:	je 13
0x0040b0e8:	pushl 0x10(%ebp)
0x0040b0eb:	pushl 0xc(%ebp)
0x0040b0ee:	pushl 0x8(%ebp)
0x0040b0f1:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x0040b0f3:	popl %ebp
0x0040b0f4:	ret

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
