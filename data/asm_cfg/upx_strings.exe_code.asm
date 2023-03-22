0x00428530:	pusha
0x00428531:	movl %esi, $0x41b000<UINT32>
0x00428536:	leal %edi, -106496(%esi)
0x0042853c:	pushl %edi
0x0042853d:	orl %ebp, $0xffffffff<UINT8>
0x00428540:	jmp 0x00428552
0x00428552:	movl %ebx, (%esi)
0x00428554:	subl %esi, $0xfffffffc<UINT8>
0x00428557:	adcl %ebx, %ebx
0x00428559:	jb 0x00428548
0x00428548:	movb %al, (%esi)
0x0042854a:	incl %esi
0x0042854b:	movb (%edi), %al
0x0042854d:	incl %edi
0x0042854e:	addl %ebx, %ebx
0x00428550:	jne 0x00428559
0x0042855b:	movl %eax, $0x1<UINT32>
0x00428560:	addl %ebx, %ebx
0x00428562:	jne 0x0042856b
0x0042856b:	adcl %eax, %eax
0x0042856d:	addl %ebx, %ebx
0x0042856f:	jae 0x00428560
0x00428571:	jne 0x0042857c
0x0042857c:	xorl %ecx, %ecx
0x0042857e:	subl %eax, $0x3<UINT8>
0x00428581:	jb 0x00428590
0x00428590:	addl %ebx, %ebx
0x00428592:	jne 0x0042859b
0x0042859b:	adcl %ecx, %ecx
0x0042859d:	addl %ebx, %ebx
0x0042859f:	jne 0x004285a8
0x004285a8:	adcl %ecx, %ecx
0x004285aa:	jne 0x004285cc
0x004285cc:	cmpl %ebp, $0xfffff300<UINT32>
0x004285d2:	adcl %ecx, $0x1<UINT8>
0x004285d5:	leal %edx, (%edi,%ebp)
0x004285d8:	cmpl %ebp, $0xfffffffc<UINT8>
0x004285db:	jbe 0x004285ec
0x004285dd:	movb %al, (%edx)
0x004285df:	incl %edx
0x004285e0:	movb (%edi), %al
0x004285e2:	incl %edi
0x004285e3:	decl %ecx
0x004285e4:	jne 0x004285dd
0x004285e6:	jmp 0x0042854e
0x00428583:	shll %eax, $0x8<UINT8>
0x00428586:	movb %al, (%esi)
0x00428588:	incl %esi
0x00428589:	xorl %eax, $0xffffffff<UINT8>
0x0042858c:	je 0x00428602
0x0042858e:	movl %ebp, %eax
0x004285ec:	movl %eax, (%edx)
0x004285ee:	addl %edx, $0x4<UINT8>
0x004285f1:	movl (%edi), %eax
0x004285f3:	addl %edi, $0x4<UINT8>
0x004285f6:	subl %ecx, $0x4<UINT8>
0x004285f9:	ja 0x004285ec
0x004285fb:	addl %edi, %ecx
0x004285fd:	jmp 0x0042854e
0x00428594:	movl %ebx, (%esi)
0x00428596:	subl %esi, $0xfffffffc<UINT8>
0x00428599:	adcl %ebx, %ebx
0x004285ac:	incl %ecx
0x004285ad:	addl %ebx, %ebx
0x004285af:	jne 0x004285b8
0x004285b8:	adcl %ecx, %ecx
0x004285ba:	addl %ebx, %ebx
0x004285bc:	jae 0x004285ad
0x004285be:	jne 0x004285c9
0x004285c9:	addl %ecx, $0x2<UINT8>
0x004285a1:	movl %ebx, (%esi)
0x004285a3:	subl %esi, $0xfffffffc<UINT8>
0x004285a6:	adcl %ebx, %ebx
0x00428564:	movl %ebx, (%esi)
0x00428566:	subl %esi, $0xfffffffc<UINT8>
0x00428569:	adcl %ebx, %ebx
0x00428573:	movl %ebx, (%esi)
0x00428575:	subl %esi, $0xfffffffc<UINT8>
0x00428578:	adcl %ebx, %ebx
0x0042857a:	jae 0x00428560
0x004285c0:	movl %ebx, (%esi)
0x004285c2:	subl %esi, $0xfffffffc<UINT8>
0x004285c5:	adcl %ebx, %ebx
0x004285c7:	jae 0x004285ad
0x004285b1:	movl %ebx, (%esi)
0x004285b3:	subl %esi, $0xfffffffc<UINT8>
0x004285b6:	adcl %ebx, %ebx
0x00428602:	popl %esi
0x00428603:	movl %edi, %esi
0x00428605:	movl %ecx, $0x66e<UINT32>
0x0042860a:	movb %al, (%edi)
0x0042860c:	incl %edi
0x0042860d:	subb %al, $0xffffffe8<UINT8>
0x0042860f:	cmpb %al, $0x1<UINT8>
0x00428611:	ja 0x0042860a
0x00428613:	cmpb (%edi), $0x5<UINT8>
0x00428616:	jne 0x0042860a
0x00428618:	movl %eax, (%edi)
0x0042861a:	movb %bl, 0x4(%edi)
0x0042861d:	shrw %ax, $0x8<UINT8>
0x00428621:	roll %eax, $0x10<UINT8>
0x00428624:	xchgb %ah, %al
0x00428626:	subl %eax, %edi
0x00428628:	subb %bl, $0xffffffe8<UINT8>
0x0042862b:	addl %eax, %esi
0x0042862d:	movl (%edi), %eax
0x0042862f:	addl %edi, $0x5<UINT8>
0x00428632:	movb %al, %bl
0x00428634:	loop 0x0042860f
0x00428636:	leal %edi, 0x25000(%esi)
0x0042863c:	movl %eax, (%edi)
0x0042863e:	orl %eax, %eax
0x00428640:	je 0x0042867e
0x00428642:	movl %ebx, 0x4(%edi)
0x00428645:	leal %eax, 0x28590(%eax,%esi)
0x0042864c:	addl %ebx, %esi
0x0042864e:	pushl %eax
0x0042864f:	addl %edi, $0x8<UINT8>
0x00428652:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00428658:	xchgl %ebp, %eax
0x00428659:	movb %al, (%edi)
0x0042865b:	incl %edi
0x0042865c:	orb %al, %al
0x0042865e:	je 0x0042863c
0x00428660:	movl %ecx, %edi
0x00428662:	pushl %edi
0x00428663:	decl %eax
0x00428664:	repn scasb %al, %es:(%edi)
0x00428666:	pushl %ebp
0x00428667:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0042866d:	orl %eax, %eax
0x0042866f:	je 7
0x00428671:	movl (%ebx), %eax
0x00428673:	addl %ebx, $0x4<UINT8>
0x00428676:	jmp 0x00428659
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x0042867e:	addl %edi, $0x4<UINT8>
0x00428681:	leal %ebx, -4(%esi)
0x00428684:	xorl %eax, %eax
0x00428686:	movb %al, (%edi)
0x00428688:	incl %edi
0x00428689:	orl %eax, %eax
0x0042868b:	je 0x004286af
0x0042868d:	cmpb %al, $0xffffffef<UINT8>
0x0042868f:	ja 0x004286a2
0x00428691:	addl %ebx, %eax
0x00428693:	movl %eax, (%ebx)
0x00428695:	xchgb %ah, %al
0x00428697:	roll %eax, $0x10<UINT8>
0x0042869a:	xchgb %ah, %al
0x0042869c:	addl %eax, %esi
0x0042869e:	movl (%ebx), %eax
0x004286a0:	jmp 0x00428684
0x004286a2:	andb %al, $0xf<UINT8>
0x004286a4:	shll %eax, $0x10<UINT8>
0x004286a7:	movw %ax, (%edi)
0x004286aa:	addl %edi, $0x2<UINT8>
0x004286ad:	jmp 0x00428691
0x004286af:	movl %ebp, 0x28640(%esi)
0x004286b5:	leal %edi, -4096(%esi)
0x004286bb:	movl %ebx, $0x1000<UINT32>
0x004286c0:	pushl %eax
0x004286c1:	pushl %esp
0x004286c2:	pushl $0x4<UINT8>
0x004286c4:	pushl %ebx
0x004286c5:	pushl %edi
0x004286c6:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x004286c8:	leal %eax, 0x217(%edi)
0x004286ce:	andb (%eax), $0x7f<UINT8>
0x004286d1:	andb 0x28(%eax), $0x7f<UINT8>
0x004286d5:	popl %eax
0x004286d6:	pushl %eax
0x004286d7:	pushl %esp
0x004286d8:	pushl %eax
0x004286d9:	pushl %ebx
0x004286da:	pushl %edi
0x004286db:	call VirtualProtect@kernel32.dll
0x004286dd:	popl %eax
0x004286de:	popa
0x004286df:	leal %eax, -128(%esp)
0x004286e3:	pushl $0x0<UINT8>
0x004286e5:	cmpl %esp, %eax
0x004286e7:	jne 0x004286e3
0x004286e9:	subl %esp, $0xffffff80<UINT8>
0x004286ec:	jmp 0x004058a6
0x004058a6:	call 0x0040bee8
0x0040bee8:	pushl %ebp
0x0040bee9:	movl %ebp, %esp
0x0040beeb:	subl %esp, $0x14<UINT8>
0x0040beee:	andl -12(%ebp), $0x0<UINT8>
0x0040bef2:	andl -8(%ebp), $0x0<UINT8>
0x0040bef6:	movl %eax, 0x41f358
0x0040befb:	pushl %esi
0x0040befc:	pushl %edi
0x0040befd:	movl %edi, $0xbb40e64e<UINT32>
0x0040bf02:	movl %esi, $0xffff0000<UINT32>
0x0040bf07:	cmpl %eax, %edi
0x0040bf09:	je 0x0040bf18
0x0040bf18:	leal %eax, -12(%ebp)
0x0040bf1b:	pushl %eax
0x0040bf1c:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040bf22:	movl %eax, -8(%ebp)
0x0040bf25:	xorl %eax, -12(%ebp)
0x0040bf28:	movl -4(%ebp), %eax
0x0040bf2b:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040bf31:	xorl -4(%ebp), %eax
0x0040bf34:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040bf3a:	xorl -4(%ebp), %eax
0x0040bf3d:	leal %eax, -20(%ebp)
0x0040bf40:	pushl %eax
0x0040bf41:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040bf47:	movl %ecx, -16(%ebp)
0x0040bf4a:	leal %eax, -4(%ebp)
0x0040bf4d:	xorl %ecx, -20(%ebp)
0x0040bf50:	xorl %ecx, -4(%ebp)
0x0040bf53:	xorl %ecx, %eax
0x0040bf55:	cmpl %ecx, %edi
0x0040bf57:	jne 0x0040bf60
0x0040bf60:	testl %esi, %ecx
0x0040bf62:	jne 0x0040bf70
0x0040bf70:	movl 0x41f358, %ecx
0x0040bf76:	notl %ecx
0x0040bf78:	movl 0x41f35c, %ecx
0x0040bf7e:	popl %edi
0x0040bf7f:	popl %esi
0x0040bf80:	movl %esp, %ebp
0x0040bf82:	popl %ebp
0x0040bf83:	ret

0x004058ab:	jmp 0x0040572b
0x0040572b:	pushl $0x14<UINT8>
0x0040572d:	pushl $0x41dbe8<UINT32>
0x00405732:	call 0x004065f0
0x004065f0:	pushl $0x406650<UINT32>
0x004065f5:	pushl %fs:0
0x004065fc:	movl %eax, 0x10(%esp)
0x00406600:	movl 0x10(%esp), %ebp
0x00406604:	leal %ebp, 0x10(%esp)
0x00406608:	subl %esp, %eax
0x0040660a:	pushl %ebx
0x0040660b:	pushl %esi
0x0040660c:	pushl %edi
0x0040660d:	movl %eax, 0x41f358
0x00406612:	xorl -4(%ebp), %eax
0x00406615:	xorl %eax, %ebp
0x00406617:	pushl %eax
0x00406618:	movl -24(%ebp), %esp
0x0040661b:	pushl -8(%ebp)
0x0040661e:	movl %eax, -4(%ebp)
0x00406621:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00406628:	movl -8(%ebp), %eax
0x0040662b:	leal %eax, -16(%ebp)
0x0040662e:	movl %fs:0, %eax
0x00406634:	ret

0x00405737:	pushl $0x1<UINT8>
0x00405739:	call 0x0040be9b
0x0040be9b:	pushl %ebp
0x0040be9c:	movl %ebp, %esp
0x0040be9e:	movl %eax, 0x8(%ebp)
0x0040bea1:	movl 0x420570, %eax
0x0040bea6:	popl %ebp
0x0040bea7:	ret

0x0040573e:	popl %ecx
0x0040573f:	movl %eax, $0x5a4d<UINT32>
0x00405744:	cmpw 0x400000, %ax
0x0040574b:	je 0x00405751
0x00405751:	movl %eax, 0x40003c
0x00405756:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00405760:	jne -21
0x00405762:	movl %ecx, $0x10b<UINT32>
0x00405767:	cmpw 0x400018(%eax), %cx
0x0040576e:	jne -35
0x00405770:	xorl %ebx, %ebx
0x00405772:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00405779:	jbe 9
0x0040577b:	cmpl 0x4000e8(%eax), %ebx
0x00405781:	setne %bl
0x00405784:	movl -28(%ebp), %ebx
0x00405787:	call 0x0040914e
0x0040914e:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x00409154:	xorl %ecx, %ecx
0x00409156:	movl 0x420ba8, %eax
0x0040915b:	testl %eax, %eax
0x0040915d:	setne %cl
0x00409160:	movl %eax, %ecx
0x00409162:	ret

0x0040578c:	testl %eax, %eax
0x0040578e:	jne 0x00405798
0x00405798:	call 0x0040a134
0x0040a134:	call 0x00404447
0x00404447:	pushl %esi
0x00404448:	pushl $0x0<UINT8>
0x0040444a:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00404450:	movl %esi, %eax
0x00404452:	pushl %esi
0x00404453:	call 0x00409141
0x00409141:	pushl %ebp
0x00409142:	movl %ebp, %esp
0x00409144:	movl %eax, 0x8(%ebp)
0x00409147:	movl 0x420ba0, %eax
0x0040914c:	popl %ebp
0x0040914d:	ret

0x00404458:	pushl %esi
0x00404459:	call 0x00406909
0x00406909:	pushl %ebp
0x0040690a:	movl %ebp, %esp
0x0040690c:	movl %eax, 0x8(%ebp)
0x0040690f:	movl 0x42045c, %eax
0x00406914:	popl %ebp
0x00406915:	ret

0x0040445e:	pushl %esi
0x0040445f:	call 0x0040a735
0x0040a735:	pushl %ebp
0x0040a736:	movl %ebp, %esp
0x0040a738:	movl %eax, 0x8(%ebp)
0x0040a73b:	movl 0x420ef0, %eax
0x0040a740:	popl %ebp
0x0040a741:	ret

0x00404464:	pushl %esi
0x00404465:	call 0x0040a74f
0x0040a74f:	pushl %ebp
0x0040a750:	movl %ebp, %esp
0x0040a752:	movl %eax, 0x8(%ebp)
0x0040a755:	movl 0x420ef4, %eax
0x0040a75a:	movl 0x420ef8, %eax
0x0040a75f:	movl 0x420efc, %eax
0x0040a764:	movl 0x420f00, %eax
0x0040a769:	popl %ebp
0x0040a76a:	ret

0x0040446a:	pushl %esi
0x0040446b:	call 0x0040a724
0x0040a724:	pushl $0x40a6f0<UINT32>
0x0040a729:	call EncodePointer@KERNEL32.DLL
0x0040a72f:	movl 0x420eec, %eax
0x0040a734:	ret

0x00404470:	pushl %esi
0x00404471:	call 0x0040a960
0x0040a960:	pushl %ebp
0x0040a961:	movl %ebp, %esp
0x0040a963:	movl %eax, 0x8(%ebp)
0x0040a966:	movl 0x420f08, %eax
0x0040a96b:	popl %ebp
0x0040a96c:	ret

0x00404476:	addl %esp, $0x18<UINT8>
0x00404479:	popl %esi
0x0040447a:	jmp 0x00408c2f
0x00408c2f:	pushl %esi
0x00408c30:	pushl %edi
0x00408c31:	pushl $0x419e34<UINT32>
0x00408c36:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00408c3c:	movl %esi, 0x4130a8
0x00408c42:	movl %edi, %eax
0x00408c44:	pushl $0x419e50<UINT32>
0x00408c49:	pushl %edi
0x00408c4a:	call GetProcAddress@KERNEL32.DLL
0x00408c4c:	xorl %eax, 0x41f358
0x00408c52:	pushl $0x419e5c<UINT32>
0x00408c57:	pushl %edi
0x00408c58:	movl 0x421060, %eax
0x00408c5d:	call GetProcAddress@KERNEL32.DLL
0x00408c5f:	xorl %eax, 0x41f358
0x00408c65:	pushl $0x419e64<UINT32>
0x00408c6a:	pushl %edi
0x00408c6b:	movl 0x421064, %eax
0x00408c70:	call GetProcAddress@KERNEL32.DLL
0x00408c72:	xorl %eax, 0x41f358
0x00408c78:	pushl $0x419e70<UINT32>
0x00408c7d:	pushl %edi
0x00408c7e:	movl 0x421068, %eax
0x00408c83:	call GetProcAddress@KERNEL32.DLL
0x00408c85:	xorl %eax, 0x41f358
0x00408c8b:	pushl $0x419e7c<UINT32>
0x00408c90:	pushl %edi
0x00408c91:	movl 0x42106c, %eax
0x00408c96:	call GetProcAddress@KERNEL32.DLL
0x00408c98:	xorl %eax, 0x41f358
0x00408c9e:	pushl $0x419e98<UINT32>
0x00408ca3:	pushl %edi
0x00408ca4:	movl 0x421070, %eax
0x00408ca9:	call GetProcAddress@KERNEL32.DLL
0x00408cab:	xorl %eax, 0x41f358
0x00408cb1:	pushl $0x419ea8<UINT32>
0x00408cb6:	pushl %edi
0x00408cb7:	movl 0x421074, %eax
0x00408cbc:	call GetProcAddress@KERNEL32.DLL
0x00408cbe:	xorl %eax, 0x41f358
0x00408cc4:	pushl $0x419ebc<UINT32>
0x00408cc9:	pushl %edi
0x00408cca:	movl 0x421078, %eax
0x00408ccf:	call GetProcAddress@KERNEL32.DLL
0x00408cd1:	xorl %eax, 0x41f358
0x00408cd7:	pushl $0x419ed4<UINT32>
0x00408cdc:	pushl %edi
0x00408cdd:	movl 0x42107c, %eax
0x00408ce2:	call GetProcAddress@KERNEL32.DLL
0x00408ce4:	xorl %eax, 0x41f358
0x00408cea:	pushl $0x419eec<UINT32>
0x00408cef:	pushl %edi
0x00408cf0:	movl 0x421080, %eax
0x00408cf5:	call GetProcAddress@KERNEL32.DLL
0x00408cf7:	xorl %eax, 0x41f358
0x00408cfd:	pushl $0x419f00<UINT32>
0x00408d02:	pushl %edi
0x00408d03:	movl 0x421084, %eax
0x00408d08:	call GetProcAddress@KERNEL32.DLL
0x00408d0a:	xorl %eax, 0x41f358
0x00408d10:	pushl $0x419f20<UINT32>
0x00408d15:	pushl %edi
0x00408d16:	movl 0x421088, %eax
0x00408d1b:	call GetProcAddress@KERNEL32.DLL
0x00408d1d:	xorl %eax, 0x41f358
0x00408d23:	pushl $0x419f38<UINT32>
0x00408d28:	pushl %edi
0x00408d29:	movl 0x42108c, %eax
0x00408d2e:	call GetProcAddress@KERNEL32.DLL
0x00408d30:	xorl %eax, 0x41f358
0x00408d36:	pushl $0x419f50<UINT32>
0x00408d3b:	pushl %edi
0x00408d3c:	movl 0x421090, %eax
0x00408d41:	call GetProcAddress@KERNEL32.DLL
0x00408d43:	xorl %eax, 0x41f358
0x00408d49:	pushl $0x419f64<UINT32>
0x00408d4e:	pushl %edi
0x00408d4f:	movl 0x421094, %eax
0x00408d54:	call GetProcAddress@KERNEL32.DLL
0x00408d56:	xorl %eax, 0x41f358
0x00408d5c:	movl 0x421098, %eax
0x00408d61:	pushl $0x419f78<UINT32>
0x00408d66:	pushl %edi
0x00408d67:	call GetProcAddress@KERNEL32.DLL
0x00408d69:	xorl %eax, 0x41f358
0x00408d6f:	pushl $0x419f94<UINT32>
0x00408d74:	pushl %edi
0x00408d75:	movl 0x42109c, %eax
0x00408d7a:	call GetProcAddress@KERNEL32.DLL
0x00408d7c:	xorl %eax, 0x41f358
0x00408d82:	pushl $0x419fb4<UINT32>
0x00408d87:	pushl %edi
0x00408d88:	movl 0x4210a0, %eax
0x00408d8d:	call GetProcAddress@KERNEL32.DLL
0x00408d8f:	xorl %eax, 0x41f358
0x00408d95:	pushl $0x419fd0<UINT32>
0x00408d9a:	pushl %edi
0x00408d9b:	movl 0x4210a4, %eax
0x00408da0:	call GetProcAddress@KERNEL32.DLL
0x00408da2:	xorl %eax, 0x41f358
0x00408da8:	pushl $0x419ff0<UINT32>
0x00408dad:	pushl %edi
0x00408dae:	movl 0x4210a8, %eax
0x00408db3:	call GetProcAddress@KERNEL32.DLL
0x00408db5:	xorl %eax, 0x41f358
0x00408dbb:	pushl $0x41a004<UINT32>
0x00408dc0:	pushl %edi
0x00408dc1:	movl 0x4210ac, %eax
0x00408dc6:	call GetProcAddress@KERNEL32.DLL
0x00408dc8:	xorl %eax, 0x41f358
0x00408dce:	pushl $0x41a020<UINT32>
0x00408dd3:	pushl %edi
0x00408dd4:	movl 0x4210b0, %eax
0x00408dd9:	call GetProcAddress@KERNEL32.DLL
0x00408ddb:	xorl %eax, 0x41f358
0x00408de1:	pushl $0x41a034<UINT32>
0x00408de6:	pushl %edi
0x00408de7:	movl 0x4210b8, %eax
0x00408dec:	call GetProcAddress@KERNEL32.DLL
0x00408dee:	xorl %eax, 0x41f358
0x00408df4:	pushl $0x41a044<UINT32>
0x00408df9:	pushl %edi
0x00408dfa:	movl 0x4210b4, %eax
0x00408dff:	call GetProcAddress@KERNEL32.DLL
0x00408e01:	xorl %eax, 0x41f358
0x00408e07:	pushl $0x41a054<UINT32>
0x00408e0c:	pushl %edi
0x00408e0d:	movl 0x4210bc, %eax
0x00408e12:	call GetProcAddress@KERNEL32.DLL
0x00408e14:	xorl %eax, 0x41f358
0x00408e1a:	pushl $0x41a064<UINT32>
0x00408e1f:	pushl %edi
0x00408e20:	movl 0x4210c0, %eax
0x00408e25:	call GetProcAddress@KERNEL32.DLL
0x00408e27:	xorl %eax, 0x41f358
0x00408e2d:	pushl $0x41a074<UINT32>
0x00408e32:	pushl %edi
0x00408e33:	movl 0x4210c4, %eax
0x00408e38:	call GetProcAddress@KERNEL32.DLL
0x00408e3a:	xorl %eax, 0x41f358
0x00408e40:	pushl $0x41a090<UINT32>
0x00408e45:	pushl %edi
0x00408e46:	movl 0x4210c8, %eax
0x00408e4b:	call GetProcAddress@KERNEL32.DLL
0x00408e4d:	xorl %eax, 0x41f358
0x00408e53:	pushl $0x41a0a4<UINT32>
0x00408e58:	pushl %edi
0x00408e59:	movl 0x4210cc, %eax
0x00408e5e:	call GetProcAddress@KERNEL32.DLL
0x00408e60:	xorl %eax, 0x41f358
0x00408e66:	pushl $0x41a0b4<UINT32>
0x00408e6b:	pushl %edi
0x00408e6c:	movl 0x4210d0, %eax
0x00408e71:	call GetProcAddress@KERNEL32.DLL
0x00408e73:	xorl %eax, 0x41f358
0x00408e79:	pushl $0x41a0c8<UINT32>
0x00408e7e:	pushl %edi
0x00408e7f:	movl 0x4210d4, %eax
0x00408e84:	call GetProcAddress@KERNEL32.DLL
0x00408e86:	xorl %eax, 0x41f358
0x00408e8c:	movl 0x4210d8, %eax
0x00408e91:	pushl $0x41a0d8<UINT32>
0x00408e96:	pushl %edi
0x00408e97:	call GetProcAddress@KERNEL32.DLL
0x00408e99:	xorl %eax, 0x41f358
0x00408e9f:	pushl $0x41a0f8<UINT32>
0x00408ea4:	pushl %edi
0x00408ea5:	movl 0x4210dc, %eax
0x00408eaa:	call GetProcAddress@KERNEL32.DLL
0x00408eac:	xorl %eax, 0x41f358
0x00408eb2:	popl %edi
0x00408eb3:	movl 0x4210e0, %eax
0x00408eb8:	popl %esi
0x00408eb9:	ret

0x0040a139:	call 0x00405a7e
0x00405a7e:	pushl %esi
0x00405a7f:	pushl %edi
0x00405a80:	movl %esi, $0x41f370<UINT32>
0x00405a85:	movl %edi, $0x420308<UINT32>
0x00405a8a:	cmpl 0x4(%esi), $0x1<UINT8>
0x00405a8e:	jne 22
0x00405a90:	pushl $0x0<UINT8>
0x00405a92:	movl (%esi), %edi
0x00405a94:	addl %edi, $0x18<UINT8>
0x00405a97:	pushl $0xfa0<UINT32>
0x00405a9c:	pushl (%esi)
0x00405a9e:	call 0x00408bc1
0x00408bc1:	pushl %ebp
0x00408bc2:	movl %ebp, %esp
0x00408bc4:	movl %eax, 0x421070
0x00408bc9:	xorl %eax, 0x41f358
0x00408bcf:	je 13
0x00408bd1:	pushl 0x10(%ebp)
0x00408bd4:	pushl 0xc(%ebp)
0x00408bd7:	pushl 0x8(%ebp)
0x00408bda:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x00408bdc:	popl %ebp
0x00408bdd:	ret

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
