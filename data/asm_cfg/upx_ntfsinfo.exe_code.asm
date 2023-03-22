0x00424890:	pusha
0x00424891:	movl %esi, $0x418000<UINT32>
0x00424896:	leal %edi, -94208(%esi)
0x0042489c:	pushl %edi
0x0042489d:	jmp 0x004248aa
0x004248aa:	movl %ebx, (%esi)
0x004248ac:	subl %esi, $0xfffffffc<UINT8>
0x004248af:	adcl %ebx, %ebx
0x004248b1:	jb 0x004248a0
0x004248a0:	movb %al, (%esi)
0x004248a2:	incl %esi
0x004248a3:	movb (%edi), %al
0x004248a5:	incl %edi
0x004248a6:	addl %ebx, %ebx
0x004248a8:	jne 0x004248b1
0x004248b3:	movl %eax, $0x1<UINT32>
0x004248b8:	addl %ebx, %ebx
0x004248ba:	jne 0x004248c3
0x004248c3:	adcl %eax, %eax
0x004248c5:	addl %ebx, %ebx
0x004248c7:	jae 0x004248b8
0x004248c9:	jne 0x004248d4
0x004248d4:	xorl %ecx, %ecx
0x004248d6:	subl %eax, $0x3<UINT8>
0x004248d9:	jb 0x004248e8
0x004248db:	shll %eax, $0x8<UINT8>
0x004248de:	movb %al, (%esi)
0x004248e0:	incl %esi
0x004248e1:	xorl %eax, $0xffffffff<UINT8>
0x004248e4:	je 0x0042495a
0x004248e6:	movl %ebp, %eax
0x004248e8:	addl %ebx, %ebx
0x004248ea:	jne 0x004248f3
0x004248f3:	adcl %ecx, %ecx
0x004248f5:	addl %ebx, %ebx
0x004248f7:	jne 0x00424900
0x004248f9:	movl %ebx, (%esi)
0x004248fb:	subl %esi, $0xfffffffc<UINT8>
0x004248fe:	adcl %ebx, %ebx
0x00424900:	adcl %ecx, %ecx
0x00424902:	jne 0x00424924
0x00424924:	cmpl %ebp, $0xfffff300<UINT32>
0x0042492a:	adcl %ecx, $0x1<UINT8>
0x0042492d:	leal %edx, (%edi,%ebp)
0x00424930:	cmpl %ebp, $0xfffffffc<UINT8>
0x00424933:	jbe 0x00424944
0x00424944:	movl %eax, (%edx)
0x00424946:	addl %edx, $0x4<UINT8>
0x00424949:	movl (%edi), %eax
0x0042494b:	addl %edi, $0x4<UINT8>
0x0042494e:	subl %ecx, $0x4<UINT8>
0x00424951:	ja 0x00424944
0x00424953:	addl %edi, %ecx
0x00424955:	jmp 0x004248a6
0x00424904:	incl %ecx
0x00424905:	addl %ebx, %ebx
0x00424907:	jne 0x00424910
0x00424910:	adcl %ecx, %ecx
0x00424912:	addl %ebx, %ebx
0x00424914:	jae 0x00424905
0x00424916:	jne 0x00424921
0x00424921:	addl %ecx, $0x2<UINT8>
0x00424935:	movb %al, (%edx)
0x00424937:	incl %edx
0x00424938:	movb (%edi), %al
0x0042493a:	incl %edi
0x0042493b:	decl %ecx
0x0042493c:	jne 0x00424935
0x0042493e:	jmp 0x004248a6
0x004248bc:	movl %ebx, (%esi)
0x004248be:	subl %esi, $0xfffffffc<UINT8>
0x004248c1:	adcl %ebx, %ebx
0x004248ec:	movl %ebx, (%esi)
0x004248ee:	subl %esi, $0xfffffffc<UINT8>
0x004248f1:	adcl %ebx, %ebx
0x004248cb:	movl %ebx, (%esi)
0x004248cd:	subl %esi, $0xfffffffc<UINT8>
0x004248d0:	adcl %ebx, %ebx
0x004248d2:	jae 0x004248b8
0x00424918:	movl %ebx, (%esi)
0x0042491a:	subl %esi, $0xfffffffc<UINT8>
0x0042491d:	adcl %ebx, %ebx
0x0042491f:	jae 0x00424905
0x00424909:	movl %ebx, (%esi)
0x0042490b:	subl %esi, $0xfffffffc<UINT8>
0x0042490e:	adcl %ebx, %ebx
0x0042495a:	popl %esi
0x0042495b:	movl %edi, %esi
0x0042495d:	movl %ecx, $0x607<UINT32>
0x00424962:	movb %al, (%edi)
0x00424964:	incl %edi
0x00424965:	subb %al, $0xffffffe8<UINT8>
0x00424967:	cmpb %al, $0x1<UINT8>
0x00424969:	ja 0x00424962
0x0042496b:	cmpb (%edi), $0x5<UINT8>
0x0042496e:	jne 0x00424962
0x00424970:	movl %eax, (%edi)
0x00424972:	movb %bl, 0x4(%edi)
0x00424975:	shrw %ax, $0x8<UINT8>
0x00424979:	roll %eax, $0x10<UINT8>
0x0042497c:	xchgb %ah, %al
0x0042497e:	subl %eax, %edi
0x00424980:	subb %bl, $0xffffffe8<UINT8>
0x00424983:	addl %eax, %esi
0x00424985:	movl (%edi), %eax
0x00424987:	addl %edi, $0x5<UINT8>
0x0042498a:	movb %al, %bl
0x0042498c:	loop 0x00424967
0x0042498e:	leal %edi, 0x22000(%esi)
0x00424994:	movl %eax, (%edi)
0x00424996:	orl %eax, %eax
0x00424998:	je 0x004249d6
0x0042499a:	movl %ebx, 0x4(%edi)
0x0042499d:	leal %eax, 0x24550(%eax,%esi)
0x004249a4:	addl %ebx, %esi
0x004249a6:	pushl %eax
0x004249a7:	addl %edi, $0x8<UINT8>
0x004249aa:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x004249b0:	xchgl %ebp, %eax
0x004249b1:	movb %al, (%edi)
0x004249b3:	incl %edi
0x004249b4:	orb %al, %al
0x004249b6:	je 0x00424994
0x004249b8:	movl %ecx, %edi
0x004249ba:	pushl %edi
0x004249bb:	decl %eax
0x004249bc:	repn scasb %al, %es:(%edi)
0x004249be:	pushl %ebp
0x004249bf:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x004249c5:	orl %eax, %eax
0x004249c7:	je 7
0x004249c9:	movl (%ebx), %eax
0x004249cb:	addl %ebx, $0x4<UINT8>
0x004249ce:	jmp 0x004249b1
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x004249d6:	movl %ebp, 0x24600(%esi)
0x004249dc:	leal %edi, -4096(%esi)
0x004249e2:	movl %ebx, $0x1000<UINT32>
0x004249e7:	pushl %eax
0x004249e8:	pushl %esp
0x004249e9:	pushl $0x4<UINT8>
0x004249eb:	pushl %ebx
0x004249ec:	pushl %edi
0x004249ed:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x004249ef:	leal %eax, 0x217(%edi)
0x004249f5:	andb (%eax), $0x7f<UINT8>
0x004249f8:	andb 0x28(%eax), $0x7f<UINT8>
0x004249fc:	popl %eax
0x004249fd:	pushl %eax
0x004249fe:	pushl %esp
0x004249ff:	pushl %eax
0x00424a00:	pushl %ebx
0x00424a01:	pushl %edi
0x00424a02:	call VirtualProtect@kernel32.dll
0x00424a04:	popl %eax
0x00424a05:	popa
0x00424a06:	leal %eax, -128(%esp)
0x00424a0a:	pushl $0x0<UINT8>
0x00424a0c:	cmpl %esp, %eax
0x00424a0e:	jne 0x00424a0a
0x00424a10:	subl %esp, $0xffffff80<UINT8>
0x00424a13:	jmp 0x004046af
0x004046af:	call 0x0040a533
0x0040a533:	pushl %ebp
0x0040a534:	movl %ebp, %esp
0x0040a536:	subl %esp, $0x14<UINT8>
0x0040a539:	andl -12(%ebp), $0x0<UINT8>
0x0040a53d:	andl -8(%ebp), $0x0<UINT8>
0x0040a541:	movl %eax, 0x41e4d0
0x0040a546:	pushl %esi
0x0040a547:	pushl %edi
0x0040a548:	movl %edi, $0xbb40e64e<UINT32>
0x0040a54d:	movl %esi, $0xffff0000<UINT32>
0x0040a552:	cmpl %eax, %edi
0x0040a554:	je 0x0040a563
0x0040a563:	leal %eax, -12(%ebp)
0x0040a566:	pushl %eax
0x0040a567:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040a56d:	movl %eax, -8(%ebp)
0x0040a570:	xorl %eax, -12(%ebp)
0x0040a573:	movl -4(%ebp), %eax
0x0040a576:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040a57c:	xorl -4(%ebp), %eax
0x0040a57f:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040a585:	xorl -4(%ebp), %eax
0x0040a588:	leal %eax, -20(%ebp)
0x0040a58b:	pushl %eax
0x0040a58c:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040a592:	movl %ecx, -16(%ebp)
0x0040a595:	leal %eax, -4(%ebp)
0x0040a598:	xorl %ecx, -20(%ebp)
0x0040a59b:	xorl %ecx, -4(%ebp)
0x0040a59e:	xorl %ecx, %eax
0x0040a5a0:	cmpl %ecx, %edi
0x0040a5a2:	jne 0x0040a5ab
0x0040a5ab:	testl %esi, %ecx
0x0040a5ad:	jne 0x0040a5bb
0x0040a5bb:	movl 0x41e4d0, %ecx
0x0040a5c1:	notl %ecx
0x0040a5c3:	movl 0x41e4d4, %ecx
0x0040a5c9:	popl %edi
0x0040a5ca:	popl %esi
0x0040a5cb:	movl %esp, %ebp
0x0040a5cd:	popl %ebp
0x0040a5ce:	ret

0x004046b4:	jmp 0x00404534
0x00404534:	pushl $0x14<UINT8>
0x00404536:	pushl $0x41ccc8<UINT32>
0x0040453b:	call 0x004053f0
0x004053f0:	pushl $0x405450<UINT32>
0x004053f5:	pushl %fs:0
0x004053fc:	movl %eax, 0x10(%esp)
0x00405400:	movl 0x10(%esp), %ebp
0x00405404:	leal %ebp, 0x10(%esp)
0x00405408:	subl %esp, %eax
0x0040540a:	pushl %ebx
0x0040540b:	pushl %esi
0x0040540c:	pushl %edi
0x0040540d:	movl %eax, 0x41e4d0
0x00405412:	xorl -4(%ebp), %eax
0x00405415:	xorl %eax, %ebp
0x00405417:	pushl %eax
0x00405418:	movl -24(%ebp), %esp
0x0040541b:	pushl -8(%ebp)
0x0040541e:	movl %eax, -4(%ebp)
0x00405421:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00405428:	movl -8(%ebp), %eax
0x0040542b:	leal %eax, -16(%ebp)
0x0040542e:	movl %fs:0, %eax
0x00405434:	ret

0x00404540:	pushl $0x1<UINT8>
0x00404542:	call 0x0040a4e6
0x0040a4e6:	pushl %ebp
0x0040a4e7:	movl %ebp, %esp
0x0040a4e9:	movl %eax, 0x8(%ebp)
0x0040a4ec:	movl 0x41f6d0, %eax
0x0040a4f1:	popl %ebp
0x0040a4f2:	ret

0x00404547:	popl %ecx
0x00404548:	movl %eax, $0x5a4d<UINT32>
0x0040454d:	cmpw 0x400000, %ax
0x00404554:	je 0x0040455a
0x0040455a:	movl %eax, 0x40003c
0x0040455f:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00404569:	jne -21
0x0040456b:	movl %ecx, $0x10b<UINT32>
0x00404570:	cmpw 0x400018(%eax), %cx
0x00404577:	jne -35
0x00404579:	xorl %ebx, %ebx
0x0040457b:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00404582:	jbe 9
0x00404584:	cmpl 0x4000e8(%eax), %ebx
0x0040458a:	setne %bl
0x0040458d:	movl -28(%ebp), %ebx
0x00404590:	call 0x00408028
0x00408028:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x0040802e:	xorl %ecx, %ecx
0x00408030:	movl 0x41fd08, %eax
0x00408035:	testl %eax, %eax
0x00408037:	setne %cl
0x0040803a:	movl %eax, %ecx
0x0040803c:	ret

0x00404595:	testl %eax, %eax
0x00404597:	jne 0x004045a1
0x004045a1:	call 0x00408f40
0x00408f40:	call 0x004036b5
0x004036b5:	pushl %esi
0x004036b6:	pushl $0x0<UINT8>
0x004036b8:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x004036be:	movl %esi, %eax
0x004036c0:	pushl %esi
0x004036c1:	call 0x0040801b
0x0040801b:	pushl %ebp
0x0040801c:	movl %ebp, %esp
0x0040801e:	movl %eax, 0x8(%ebp)
0x00408021:	movl 0x41fd00, %eax
0x00408026:	popl %ebp
0x00408027:	ret

0x004036c6:	pushl %esi
0x004036c7:	call 0x00405709
0x00405709:	pushl %ebp
0x0040570a:	movl %ebp, %esp
0x0040570c:	movl %eax, 0x8(%ebp)
0x0040570f:	movl 0x41f5bc, %eax
0x00405714:	popl %ebp
0x00405715:	ret

0x004036cc:	pushl %esi
0x004036cd:	call 0x00409935
0x00409935:	pushl %ebp
0x00409936:	movl %ebp, %esp
0x00409938:	movl %eax, 0x8(%ebp)
0x0040993b:	movl 0x420050, %eax
0x00409940:	popl %ebp
0x00409941:	ret

0x004036d2:	pushl %esi
0x004036d3:	call 0x0040994f
0x0040994f:	pushl %ebp
0x00409950:	movl %ebp, %esp
0x00409952:	movl %eax, 0x8(%ebp)
0x00409955:	movl 0x420054, %eax
0x0040995a:	movl 0x420058, %eax
0x0040995f:	movl 0x42005c, %eax
0x00409964:	movl 0x420060, %eax
0x00409969:	popl %ebp
0x0040996a:	ret

0x004036d8:	pushl %esi
0x004036d9:	call 0x00409924
0x00409924:	pushl $0x4098f0<UINT32>
0x00409929:	call EncodePointer@KERNEL32.DLL
0x0040992f:	movl 0x42004c, %eax
0x00409934:	ret

0x004036de:	pushl %esi
0x004036df:	call 0x00409b60
0x00409b60:	pushl %ebp
0x00409b61:	movl %ebp, %esp
0x00409b63:	movl %eax, 0x8(%ebp)
0x00409b66:	movl 0x420068, %eax
0x00409b6b:	popl %ebp
0x00409b6c:	ret

0x004036e4:	addl %esp, $0x18<UINT8>
0x004036e7:	popl %esi
0x004036e8:	jmp 0x00407b09
0x00407b09:	pushl %esi
0x00407b0a:	pushl %edi
0x00407b0b:	pushl $0x418f7c<UINT32>
0x00407b10:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00407b16:	movl %esi, 0x412094
0x00407b1c:	movl %edi, %eax
0x00407b1e:	pushl $0x418f98<UINT32>
0x00407b23:	pushl %edi
0x00407b24:	call GetProcAddress@KERNEL32.DLL
0x00407b26:	xorl %eax, 0x41e4d0
0x00407b2c:	pushl $0x418fa4<UINT32>
0x00407b31:	pushl %edi
0x00407b32:	movl 0x4201c0, %eax
0x00407b37:	call GetProcAddress@KERNEL32.DLL
0x00407b39:	xorl %eax, 0x41e4d0
0x00407b3f:	pushl $0x418fac<UINT32>
0x00407b44:	pushl %edi
0x00407b45:	movl 0x4201c4, %eax
0x00407b4a:	call GetProcAddress@KERNEL32.DLL
0x00407b4c:	xorl %eax, 0x41e4d0
0x00407b52:	pushl $0x418fb8<UINT32>
0x00407b57:	pushl %edi
0x00407b58:	movl 0x4201c8, %eax
0x00407b5d:	call GetProcAddress@KERNEL32.DLL
0x00407b5f:	xorl %eax, 0x41e4d0
0x00407b65:	pushl $0x418fc4<UINT32>
0x00407b6a:	pushl %edi
0x00407b6b:	movl 0x4201cc, %eax
0x00407b70:	call GetProcAddress@KERNEL32.DLL
0x00407b72:	xorl %eax, 0x41e4d0
0x00407b78:	pushl $0x418fe0<UINT32>
0x00407b7d:	pushl %edi
0x00407b7e:	movl 0x4201d0, %eax
0x00407b83:	call GetProcAddress@KERNEL32.DLL
0x00407b85:	xorl %eax, 0x41e4d0
0x00407b8b:	pushl $0x418ff0<UINT32>
0x00407b90:	pushl %edi
0x00407b91:	movl 0x4201d4, %eax
0x00407b96:	call GetProcAddress@KERNEL32.DLL
0x00407b98:	xorl %eax, 0x41e4d0
0x00407b9e:	pushl $0x419004<UINT32>
0x00407ba3:	pushl %edi
0x00407ba4:	movl 0x4201d8, %eax
0x00407ba9:	call GetProcAddress@KERNEL32.DLL
0x00407bab:	xorl %eax, 0x41e4d0
0x00407bb1:	pushl $0x41901c<UINT32>
0x00407bb6:	pushl %edi
0x00407bb7:	movl 0x4201dc, %eax
0x00407bbc:	call GetProcAddress@KERNEL32.DLL
0x00407bbe:	xorl %eax, 0x41e4d0
0x00407bc4:	pushl $0x419034<UINT32>
0x00407bc9:	pushl %edi
0x00407bca:	movl 0x4201e0, %eax
0x00407bcf:	call GetProcAddress@KERNEL32.DLL
0x00407bd1:	xorl %eax, 0x41e4d0
0x00407bd7:	pushl $0x419048<UINT32>
0x00407bdc:	pushl %edi
0x00407bdd:	movl 0x4201e4, %eax
0x00407be2:	call GetProcAddress@KERNEL32.DLL
0x00407be4:	xorl %eax, 0x41e4d0
0x00407bea:	pushl $0x419068<UINT32>
0x00407bef:	pushl %edi
0x00407bf0:	movl 0x4201e8, %eax
0x00407bf5:	call GetProcAddress@KERNEL32.DLL
0x00407bf7:	xorl %eax, 0x41e4d0
0x00407bfd:	pushl $0x419080<UINT32>
0x00407c02:	pushl %edi
0x00407c03:	movl 0x4201ec, %eax
0x00407c08:	call GetProcAddress@KERNEL32.DLL
0x00407c0a:	xorl %eax, 0x41e4d0
0x00407c10:	pushl $0x419098<UINT32>
0x00407c15:	pushl %edi
0x00407c16:	movl 0x4201f0, %eax
0x00407c1b:	call GetProcAddress@KERNEL32.DLL
0x00407c1d:	xorl %eax, 0x41e4d0
0x00407c23:	pushl $0x4190ac<UINT32>
0x00407c28:	pushl %edi
0x00407c29:	movl 0x4201f4, %eax
0x00407c2e:	call GetProcAddress@KERNEL32.DLL
0x00407c30:	xorl %eax, 0x41e4d0
0x00407c36:	movl 0x4201f8, %eax
0x00407c3b:	pushl $0x4190c0<UINT32>
0x00407c40:	pushl %edi
0x00407c41:	call GetProcAddress@KERNEL32.DLL
0x00407c43:	xorl %eax, 0x41e4d0
0x00407c49:	pushl $0x4190dc<UINT32>
0x00407c4e:	pushl %edi
0x00407c4f:	movl 0x4201fc, %eax
0x00407c54:	call GetProcAddress@KERNEL32.DLL
0x00407c56:	xorl %eax, 0x41e4d0
0x00407c5c:	pushl $0x4190fc<UINT32>
0x00407c61:	pushl %edi
0x00407c62:	movl 0x420200, %eax
0x00407c67:	call GetProcAddress@KERNEL32.DLL
0x00407c69:	xorl %eax, 0x41e4d0
0x00407c6f:	pushl $0x419118<UINT32>
0x00407c74:	pushl %edi
0x00407c75:	movl 0x420204, %eax
0x00407c7a:	call GetProcAddress@KERNEL32.DLL
0x00407c7c:	xorl %eax, 0x41e4d0
0x00407c82:	pushl $0x419138<UINT32>
0x00407c87:	pushl %edi
0x00407c88:	movl 0x420208, %eax
0x00407c8d:	call GetProcAddress@KERNEL32.DLL
0x00407c8f:	xorl %eax, 0x41e4d0
0x00407c95:	pushl $0x41914c<UINT32>
0x00407c9a:	pushl %edi
0x00407c9b:	movl 0x42020c, %eax
0x00407ca0:	call GetProcAddress@KERNEL32.DLL
0x00407ca2:	xorl %eax, 0x41e4d0
0x00407ca8:	pushl $0x419168<UINT32>
0x00407cad:	pushl %edi
0x00407cae:	movl 0x420210, %eax
0x00407cb3:	call GetProcAddress@KERNEL32.DLL
0x00407cb5:	xorl %eax, 0x41e4d0
0x00407cbb:	pushl $0x41917c<UINT32>
0x00407cc0:	pushl %edi
0x00407cc1:	movl 0x420218, %eax
0x00407cc6:	call GetProcAddress@KERNEL32.DLL
0x00407cc8:	xorl %eax, 0x41e4d0
0x00407cce:	pushl $0x41918c<UINT32>
0x00407cd3:	pushl %edi
0x00407cd4:	movl 0x420214, %eax
0x00407cd9:	call GetProcAddress@KERNEL32.DLL
0x00407cdb:	xorl %eax, 0x41e4d0
0x00407ce1:	pushl $0x41919c<UINT32>
0x00407ce6:	pushl %edi
0x00407ce7:	movl 0x42021c, %eax
0x00407cec:	call GetProcAddress@KERNEL32.DLL
0x00407cee:	xorl %eax, 0x41e4d0
0x00407cf4:	pushl $0x4191ac<UINT32>
0x00407cf9:	pushl %edi
0x00407cfa:	movl 0x420220, %eax
0x00407cff:	call GetProcAddress@KERNEL32.DLL
0x00407d01:	xorl %eax, 0x41e4d0
0x00407d07:	pushl $0x4191bc<UINT32>
0x00407d0c:	pushl %edi
0x00407d0d:	movl 0x420224, %eax
0x00407d12:	call GetProcAddress@KERNEL32.DLL
0x00407d14:	xorl %eax, 0x41e4d0
0x00407d1a:	pushl $0x4191d8<UINT32>
0x00407d1f:	pushl %edi
0x00407d20:	movl 0x420228, %eax
0x00407d25:	call GetProcAddress@KERNEL32.DLL
0x00407d27:	xorl %eax, 0x41e4d0
0x00407d2d:	pushl $0x4191ec<UINT32>
0x00407d32:	pushl %edi
0x00407d33:	movl 0x42022c, %eax
0x00407d38:	call GetProcAddress@KERNEL32.DLL
0x00407d3a:	xorl %eax, 0x41e4d0
0x00407d40:	pushl $0x4191fc<UINT32>
0x00407d45:	pushl %edi
0x00407d46:	movl 0x420230, %eax
0x00407d4b:	call GetProcAddress@KERNEL32.DLL
0x00407d4d:	xorl %eax, 0x41e4d0
0x00407d53:	pushl $0x419210<UINT32>
0x00407d58:	pushl %edi
0x00407d59:	movl 0x420234, %eax
0x00407d5e:	call GetProcAddress@KERNEL32.DLL
0x00407d60:	xorl %eax, 0x41e4d0
0x00407d66:	movl 0x420238, %eax
0x00407d6b:	pushl $0x419220<UINT32>
0x00407d70:	pushl %edi
0x00407d71:	call GetProcAddress@KERNEL32.DLL
0x00407d73:	xorl %eax, 0x41e4d0
0x00407d79:	pushl $0x419240<UINT32>
0x00407d7e:	pushl %edi
0x00407d7f:	movl 0x42023c, %eax
0x00407d84:	call GetProcAddress@KERNEL32.DLL
0x00407d86:	xorl %eax, 0x41e4d0
0x00407d8c:	popl %edi
0x00407d8d:	movl 0x420240, %eax
0x00407d92:	popl %esi
0x00407d93:	ret

0x00408f45:	call 0x00404887
0x00404887:	pushl %esi
0x00404888:	pushl %edi
0x00404889:	movl %esi, $0x41e4e0<UINT32>
0x0040488e:	movl %edi, $0x41f468<UINT32>
0x00404893:	cmpl 0x4(%esi), $0x1<UINT8>
0x00404897:	jne 22
0x00404899:	pushl $0x0<UINT8>
0x0040489b:	movl (%esi), %edi
0x0040489d:	addl %edi, $0x18<UINT8>
0x004048a0:	pushl $0xfa0<UINT32>
0x004048a5:	pushl (%esi)
0x004048a7:	call 0x00407a9b
0x00407a9b:	pushl %ebp
0x00407a9c:	movl %ebp, %esp
0x00407a9e:	movl %eax, 0x4201d0
0x00407aa3:	xorl %eax, 0x41e4d0
0x00407aa9:	je 13
0x00407aab:	pushl 0x10(%ebp)
0x00407aae:	pushl 0xc(%ebp)
0x00407ab1:	pushl 0x8(%ebp)
0x00407ab4:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x00407ab6:	popl %ebp
0x00407ab7:	ret

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
