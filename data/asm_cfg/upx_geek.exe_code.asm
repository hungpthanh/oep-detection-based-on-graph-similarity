0x009fcd20:	pusha
0x009fcd21:	movl %esi, $0x7c1000<UINT32>
0x009fcd26:	leal %edi, -3932160(%esi)
0x009fcd2c:	pushl %edi
0x009fcd2d:	jmp 0x009fcd3a
0x009fcd3a:	movl %ebx, (%esi)
0x009fcd3c:	subl %esi, $0xfffffffc<UINT8>
0x009fcd3f:	adcl %ebx, %ebx
0x009fcd41:	jb 0x009fcd30
0x009fcd30:	movb %al, (%esi)
0x009fcd32:	incl %esi
0x009fcd33:	movb (%edi), %al
0x009fcd35:	incl %edi
0x009fcd36:	addl %ebx, %ebx
0x009fcd38:	jne 0x009fcd41
0x009fcd43:	movl %eax, $0x1<UINT32>
0x009fcd48:	addl %ebx, %ebx
0x009fcd4a:	jne 0x009fcd53
0x009fcd53:	adcl %eax, %eax
0x009fcd55:	addl %ebx, %ebx
0x009fcd57:	jae 0x009fcd64
0x009fcd59:	jne 0x009fcd83
0x009fcd83:	xorl %ecx, %ecx
0x009fcd85:	subl %eax, $0x3<UINT8>
0x009fcd88:	jb 0x009fcd9b
0x009fcd8a:	shll %eax, $0x8<UINT8>
0x009fcd8d:	movb %al, (%esi)
0x009fcd8f:	incl %esi
0x009fcd90:	xorl %eax, $0xffffffff<UINT8>
0x009fcd93:	je 0x009fce0a
0x009fcd95:	sarl %eax
0x009fcd97:	movl %ebp, %eax
0x009fcd99:	jmp 0x009fcda6
0x009fcda6:	jb 0x009fcd74
0x009fcd74:	addl %ebx, %ebx
0x009fcd76:	jne 0x009fcd7f
0x009fcd7f:	adcl %ecx, %ecx
0x009fcd81:	jmp 0x009fcdd5
0x009fcdd5:	cmpl %ebp, $0xfffffb00<UINT32>
0x009fcddb:	adcl %ecx, $0x2<UINT8>
0x009fcdde:	leal %edx, (%edi,%ebp)
0x009fcde1:	cmpl %ebp, $0xfffffffc<UINT8>
0x009fcde4:	jbe 0x009fcdf4
0x009fcdf4:	movl %eax, (%edx)
0x009fcdf6:	addl %edx, $0x4<UINT8>
0x009fcdf9:	movl (%edi), %eax
0x009fcdfb:	addl %edi, $0x4<UINT8>
0x009fcdfe:	subl %ecx, $0x4<UINT8>
0x009fce01:	ja 0x009fcdf4
0x009fce03:	addl %edi, %ecx
0x009fce05:	jmp 0x009fcd36
0x009fcda8:	incl %ecx
0x009fcda9:	addl %ebx, %ebx
0x009fcdab:	jne 0x009fcdb4
0x009fcdb4:	jb 0x009fcd74
0x009fcd9b:	addl %ebx, %ebx
0x009fcd9d:	jne 0x009fcda6
0x009fcdb6:	addl %ebx, %ebx
0x009fcdb8:	jne 0x009fcdc1
0x009fcdc1:	adcl %ecx, %ecx
0x009fcdc3:	addl %ebx, %ebx
0x009fcdc5:	jae 0x009fcdb6
0x009fcdc7:	jne 0x009fcdd2
0x009fcdd2:	addl %ecx, $0x2<UINT8>
0x009fcd5b:	movl %ebx, (%esi)
0x009fcd5d:	subl %esi, $0xfffffffc<UINT8>
0x009fcd60:	adcl %ebx, %ebx
0x009fcd62:	jb 0x009fcd83
0x009fcd78:	movl %ebx, (%esi)
0x009fcd7a:	subl %esi, $0xfffffffc<UINT8>
0x009fcd7d:	adcl %ebx, %ebx
0x009fcdba:	movl %ebx, (%esi)
0x009fcdbc:	subl %esi, $0xfffffffc<UINT8>
0x009fcdbf:	adcl %ebx, %ebx
0x009fcd64:	decl %eax
0x009fcd65:	addl %ebx, %ebx
0x009fcd67:	jne 0x009fcd70
0x009fcd70:	adcl %eax, %eax
0x009fcd72:	jmp 0x009fcd48
0x009fcdad:	movl %ebx, (%esi)
0x009fcdaf:	subl %esi, $0xfffffffc<UINT8>
0x009fcdb2:	adcl %ebx, %ebx
0x009fcd4c:	movl %ebx, (%esi)
0x009fcd4e:	subl %esi, $0xfffffffc<UINT8>
0x009fcd51:	adcl %ebx, %ebx
0x009fcde6:	movb %al, (%edx)
0x009fcde8:	incl %edx
0x009fcde9:	movb (%edi), %al
0x009fcdeb:	incl %edi
0x009fcdec:	decl %ecx
0x009fcded:	jne 0x009fcde6
0x009fcdef:	jmp 0x009fcd36
0x009fcd9f:	movl %ebx, (%esi)
0x009fcda1:	subl %esi, $0xfffffffc<UINT8>
0x009fcda4:	adcl %ebx, %ebx
0x009fcdc9:	movl %ebx, (%esi)
0x009fcdcb:	subl %esi, $0xfffffffc<UINT8>
0x009fcdce:	adcl %ebx, %ebx
0x009fcdd0:	jae 0x009fcdb6
0x009fcd69:	movl %ebx, (%esi)
0x009fcd6b:	subl %esi, $0xfffffffc<UINT8>
0x009fcd6e:	adcl %ebx, %ebx
0x009fce0a:	popl %esi
0x009fce0b:	movl %edi, %esi
0x009fce0d:	movl %ecx, $0xb9e8<UINT32>
0x009fce12:	movb %al, (%edi)
0x009fce14:	incl %edi
0x009fce15:	subb %al, $0xffffffe8<UINT8>
0x009fce17:	cmpb %al, $0x1<UINT8>
0x009fce19:	ja 0x009fce12
0x009fce1b:	cmpb (%edi), $0x31<UINT8>
0x009fce1e:	jne 0x009fce12
0x009fce20:	movl %eax, (%edi)
0x009fce22:	movb %bl, 0x4(%edi)
0x009fce25:	shrw %ax, $0x8<UINT8>
0x009fce29:	roll %eax, $0x10<UINT8>
0x009fce2c:	xchgb %ah, %al
0x009fce2e:	subl %eax, %edi
0x009fce30:	subb %bl, $0xffffffe8<UINT8>
0x009fce33:	addl %eax, %esi
0x009fce35:	movl (%edi), %eax
0x009fce37:	addl %edi, $0x5<UINT8>
0x009fce3a:	movb %al, %bl
0x009fce3c:	loop 0x009fce17
0x009fce3e:	leal %edi, 0x5f8000(%esi)
0x009fce44:	movl %eax, (%edi)
0x009fce46:	orl %eax, %eax
0x009fce48:	je 0x009fce8f
0x009fce4a:	movl %ebx, 0x4(%edi)
0x009fce4d:	leal %eax, 0x624d58(%eax,%esi)
0x009fce54:	addl %ebx, %esi
0x009fce56:	pushl %eax
0x009fce57:	addl %edi, $0x8<UINT8>
0x009fce5a:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x009fce60:	xchgl %ebp, %eax
0x009fce61:	movb %al, (%edi)
0x009fce63:	incl %edi
0x009fce64:	orb %al, %al
0x009fce66:	je 0x009fce44
0x009fce68:	movl %ecx, %edi
0x009fce6a:	jns 0x009fce73
0x009fce73:	pushl %edi
0x009fce74:	decl %eax
0x009fce75:	repn scasb %al, %es:(%edi)
0x009fce77:	pushl %ebp
0x009fce78:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x009fce7e:	orl %eax, %eax
0x009fce80:	je 7
0x009fce82:	movl (%ebx), %eax
0x009fce84:	addl %ebx, $0x4<UINT8>
0x009fce87:	jmp 0x009fce61
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x009fce6c:	movzwl %eax, (%edi)
0x009fce6f:	incl %edi
0x009fce70:	pushl %eax
0x009fce71:	incl %edi
0x009fce72:	movl %ecx, $0xaef24857<UINT32>
0x009fce8f:	movl %ebp, 0x624ef8(%esi)
0x009fce95:	leal %edi, -4096(%esi)
0x009fce9b:	movl %ebx, $0x1000<UINT32>
0x009fcea0:	pushl %eax
0x009fcea1:	pushl %esp
0x009fcea2:	pushl $0x4<UINT8>
0x009fcea4:	pushl %ebx
0x009fcea5:	pushl %edi
0x009fcea6:	call VirtualProtect@KERNEL32.DLL
VirtualProtect@KERNEL32.DLL: API Node	
0x009fcea8:	leal %eax, 0x23f(%edi)
0x009fceae:	andb (%eax), $0x7f<UINT8>
0x009fceb1:	andb 0x28(%eax), $0x7f<UINT8>
0x009fceb5:	popl %eax
0x009fceb6:	pushl %eax
0x009fceb7:	pushl %esp
0x009fceb8:	pushl %eax
0x009fceb9:	pushl %ebx
0x009fceba:	pushl %edi
0x009fcebb:	call VirtualProtect@KERNEL32.DLL
0x009fcebd:	popl %eax
0x009fcebe:	popa
0x009fcebf:	leal %eax, -128(%esp)
0x009fcec3:	pushl $0x0<UINT8>
0x009fcec5:	cmpl %esp, %eax
0x009fcec7:	jne 0x009fcec3
0x009fcec9:	subl %esp, $0xffffff80<UINT8>
0x009fcecc:	jmp 0x00559760
0x00559760:	call 0x0055a94d
0x0055a94d:	movl %ecx, 0x60a440
0x0055a953:	pushl %esi
0x0055a954:	pushl %edi
0x0055a955:	movl %edi, $0xbb40e64e<UINT32>
0x0055a95a:	movl %esi, $0xffff0000<UINT32>
0x0055a95f:	cmpl %ecx, %edi
0x0055a961:	je 0x0055a967
0x0055a967:	call 0x0055a900
0x0055a900:	pushl %ebp
0x0055a901:	movl %ebp, %esp
0x0055a903:	subl %esp, $0x14<UINT8>
0x0055a906:	andl -12(%ebp), $0x0<UINT8>
0x0055a90a:	leal %eax, -12(%ebp)
0x0055a90d:	andl -8(%ebp), $0x0<UINT8>
0x0055a911:	pushl %eax
0x0055a912:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0055a918:	movl %eax, -8(%ebp)
0x0055a91b:	xorl %eax, -12(%ebp)
0x0055a91e:	movl -4(%ebp), %eax
0x0055a921:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0055a927:	xorl -4(%ebp), %eax
0x0055a92a:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0055a930:	xorl -4(%ebp), %eax
0x0055a933:	leal %eax, -20(%ebp)
0x0055a936:	pushl %eax
0x0055a937:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0055a93d:	movl %eax, -16(%ebp)
0x0055a940:	leal %ecx, -4(%ebp)
0x0055a943:	xorl %eax, -20(%ebp)
0x0055a946:	xorl %eax, -4(%ebp)
0x0055a949:	xorl %eax, %ecx
0x0055a94b:	leave
0x0055a94c:	ret

0x0055a96c:	movl %ecx, %eax
0x0055a96e:	cmpl %ecx, %edi
0x0055a970:	jne 0x0055a979
0x0055a979:	testl %esi, %ecx
0x0055a97b:	jne 0x0055a987
0x0055a987:	movl 0x60a440, %ecx
0x0055a98d:	notl %ecx
0x0055a98f:	popl %edi
0x0055a990:	movl 0x60a43c, %ecx
0x0055a996:	popl %esi
0x0055a997:	ret

0x00559765:	jmp 0x005595e4
0x005595e4:	pushl $0x14<UINT8>
0x005595e6:	pushl $0x603be8<UINT32>
0x005595eb:	call 0x0055a840
0x0055a840:	pushl $0x55eed0<UINT32>
0x0055a845:	pushl %fs:0
0x0055a84c:	movl %eax, 0x10(%esp)
0x0055a850:	movl 0x10(%esp), %ebp
0x0055a854:	leal %ebp, 0x10(%esp)
0x0055a858:	subl %esp, %eax
0x0055a85a:	pushl %ebx
0x0055a85b:	pushl %esi
0x0055a85c:	pushl %edi
0x0055a85d:	movl %eax, 0x60a440
0x0055a862:	xorl -4(%ebp), %eax
0x0055a865:	xorl %eax, %ebp
0x0055a867:	pushl %eax
0x0055a868:	movl -24(%ebp), %esp
0x0055a86b:	pushl -8(%ebp)
0x0055a86e:	movl %eax, -4(%ebp)
0x0055a871:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0055a878:	movl -8(%ebp), %eax
0x0055a87b:	leal %eax, -16(%ebp)
0x0055a87e:	movl %fs:0, %eax
0x0055a884:	repn ret

0x005595f0:	pushl $0x1<UINT8>
0x005595f2:	call 0x00559952
0x00559952:	pushl %ebp
0x00559953:	movl %ebp, %esp
0x00559955:	cmpl 0x8(%ebp), $0x0<UINT8>
0x00559959:	jne 0x00559962
0x00559962:	call 0x0055a2cb
0x0055a2cb:	pushl %ebp
0x0055a2cc:	movl %ebp, %esp
0x0055a2ce:	andl 0x615028, $0x0<UINT8>
0x0055a2d5:	subl %esp, $0x24<UINT8>
0x0055a2d8:	pushl %ebx
0x0055a2d9:	xorl %ebx, %ebx
0x0055a2db:	incl %ebx
0x0055a2dc:	orl 0x60a460, %ebx
0x0055a2e2:	pushl $0xa<UINT8>
0x0055a2e4:	call 0x0055ac5e
0x0055ac5e:	jmp IsProcessorFeaturePresent@KERNEL32.DLL
IsProcessorFeaturePresent@KERNEL32.DLL: API Node	
0x0055a2e9:	testl %eax, %eax
0x0055a2eb:	je 364
0x0055a2f1:	andl -16(%ebp), $0x0<UINT8>
0x0055a2f5:	xorl %eax, %eax
0x0055a2f7:	orl 0x60a460, $0x2<UINT8>
0x0055a2fe:	xorl %ecx, %ecx
0x0055a300:	pushl %esi
0x0055a301:	pushl %edi
0x0055a302:	movl 0x615028, %ebx
0x0055a308:	leal %edi, -36(%ebp)
0x0055a30b:	pushl %ebx
0x0055a30c:	cpuid
0x0055a30e:	movl %esi, %ebx
0x0055a310:	popl %ebx
0x0055a311:	movl (%edi), %eax
0x0055a313:	movl 0x4(%edi), %esi
0x0055a316:	movl 0x8(%edi), %ecx
0x0055a319:	xorl %ecx, %ecx
0x0055a31b:	movl 0xc(%edi), %edx
0x0055a31e:	movl %eax, -36(%ebp)
0x0055a321:	movl %edi, -32(%ebp)
0x0055a324:	movl -12(%ebp), %eax
0x0055a327:	xorl %edi, $0x756e6547<UINT32>
0x0055a32d:	movl %eax, -24(%ebp)
0x0055a330:	xorl %eax, $0x49656e69<UINT32>
0x0055a335:	movl -8(%ebp), %eax
0x0055a338:	movl %eax, -28(%ebp)
0x0055a33b:	xorl %eax, $0x6c65746e<UINT32>
0x0055a340:	movl -4(%ebp), %eax
0x0055a343:	xorl %eax, %eax
0x0055a345:	incl %eax
0x0055a346:	pushl %ebx
0x0055a347:	cpuid
0x0055a349:	movl %esi, %ebx
0x0055a34b:	popl %ebx
0x0055a34c:	leal %ebx, -36(%ebp)
0x0055a34f:	movl (%ebx), %eax
0x0055a351:	movl %eax, -4(%ebp)
0x0055a354:	orl %eax, -8(%ebp)
0x0055a357:	orl %eax, %edi
0x0055a359:	movl 0x4(%ebx), %esi
0x0055a35c:	movl 0x8(%ebx), %ecx
0x0055a35f:	movl 0xc(%ebx), %edx
0x0055a362:	jne 67
0x0055a364:	movl %eax, -36(%ebp)
0x0055a367:	andl %eax, $0xfff3ff0<UINT32>
0x0055a36c:	cmpl %eax, $0x106c0<UINT32>
0x0055a371:	je 35
0x0055a373:	cmpl %eax, $0x20660<UINT32>
0x0055a378:	je 28
0x0055a37a:	cmpl %eax, $0x20670<UINT32>
0x0055a37f:	je 21
0x0055a381:	cmpl %eax, $0x30650<UINT32>
0x0055a386:	je 14
0x0055a388:	cmpl %eax, $0x30660<UINT32>
0x0055a38d:	je 7
0x0055a38f:	cmpl %eax, $0x30670<UINT32>
0x0055a394:	jne 0x0055a3a7
0x0055a3a7:	movl %edi, 0x61502c
0x0055a3ad:	cmpl -12(%ebp), $0x7<UINT8>
0x0055a3b1:	movl %eax, -28(%ebp)
0x0055a3b4:	movl -4(%ebp), %eax
0x0055a3b7:	jl 0x0055a3eb
0x0055a3eb:	movl %ebx, -16(%ebp)
0x0055a3ee:	popl %edi
0x0055a3ef:	popl %esi
0x0055a3f0:	testl %eax, $0x100000<UINT32>
0x0055a3f5:	je 0x0055a45d
0x0055a45d:	xorl %eax, %eax
0x0055a45f:	popl %ebx
0x0055a460:	leave
0x0055a461:	ret

0x00559967:	call 0x0055f027
0x0055f027:	call 0x0055ff99
0x0055ff99:	movl %eax, 0x60a440
0x0055ff9e:	movl 0x615660, %eax
0x0055ffa3:	ret

0x0055f02c:	call 0x005605eb
0x005605eb:	movl %ecx, $0x6156a0<UINT32>
0x005605f0:	movl %eax, $0x61568c<UINT32>
0x005605f5:	xorl %edx, %edx
0x005605f7:	cmpl %ecx, %eax
0x005605f9:	pushl %esi
0x005605fa:	movl %esi, 0x60a440
0x00560600:	sbbl %ecx, %ecx
0x00560602:	andl %ecx, $0xfffffffb<UINT8>
0x00560605:	addl %ecx, $0x5<UINT8>
0x00560608:	incl %edx
0x00560609:	movl (%eax), %esi
0x0056060b:	leal %eax, 0x4(%eax)
0x0056060e:	cmpl %edx, %ecx
0x00560610:	jne 0x00560608
0x00560612:	popl %esi
0x00560613:	ret

0x0055f031:	call 0x00560317
0x00560317:	pushl %esi
0x00560318:	pushl %edi
0x00560319:	movl %edi, $0x615664<UINT32>
0x0056031e:	xorl %esi, %esi
0x00560320:	pushl $0x0<UINT8>
0x00560322:	pushl $0xfa0<UINT32>
0x00560327:	pushl %edi
0x00560328:	call 0x005605a4
0x005605a4:	pushl %ebp
0x005605a5:	movl %ebp, %esp
0x005605a7:	pushl %esi
0x005605a8:	pushl $0x5d394c<UINT32>
0x005605ad:	pushl $0x5d3944<UINT32>
0x005605b2:	pushl $0x5d234c<UINT32>
0x005605b7:	pushl $0x4<UINT8>
0x005605b9:	call 0x00560446
0x00560446:	pushl %ebp
0x00560447:	movl %ebp, %esp
0x00560449:	movl %eax, 0x8(%ebp)
0x0056044c:	pushl %edi
0x0056044d:	leal %edi, 0x61568c(,%eax,4)
0x00560454:	movl %eax, (%edi)
0x00560456:	movl %edx, 0x60a440
0x0056045c:	movl %ecx, %edx
0x0056045e:	andl %ecx, $0x1f<UINT8>
0x00560461:	xorl %edx, %eax
0x00560463:	rorl %edx, %cl
0x00560465:	cmpl %edx, $0xffffffff<UINT8>
0x00560468:	jne 0x0056046e
0x0056046e:	testl %edx, %edx
0x00560470:	je 0x00560476
0x00560476:	pushl %esi
0x00560477:	pushl 0x14(%ebp)
0x0056047a:	pushl 0x10(%ebp)
0x0056047d:	call 0x00560382
0x00560382:	pushl %ebp
0x00560383:	movl %ebp, %esp
0x00560385:	pushl %ecx
0x00560386:	pushl %ebx
0x00560387:	pushl %esi
0x00560388:	pushl %edi
0x00560389:	movl %edi, 0x8(%ebp)
0x0056038c:	jmp 0x00560432
0x00560432:	cmpl %edi, 0xc(%ebp)
0x00560435:	jne 0x00560391
0x00560391:	movl %ebx, (%edi)
0x00560393:	leal %eax, 0x615680(,%ebx,4)
0x0056039a:	movl %esi, (%eax)
0x0056039c:	movl -4(%ebp), %eax
0x0056039f:	testl %esi, %esi
0x005603a1:	je 0x005603ae
0x005603ae:	movl %ebx, 0x5d3880(,%ebx,4)
0x005603b5:	pushl $0x800<UINT32>
0x005603ba:	pushl $0x0<UINT8>
0x005603bc:	pushl %ebx
0x005603bd:	call LoadLibraryExW@KERNEL32.DLL
LoadLibraryExW@KERNEL32.DLL: API Node	
0x005603c3:	movl %esi, %eax
0x005603c5:	testl %esi, %esi
0x005603c7:	jne 0x00560419
0x00560419:	movl %ecx, -4(%ebp)
0x0056041c:	movl %eax, %esi
0x0056041e:	xchgl (%ecx), %eax
0x00560420:	testl %eax, %eax
0x00560422:	je 0x0056042b
0x0056042b:	testl %esi, %esi
0x0056042d:	jne 0x00560442
0x00560442:	movl %eax, %esi
0x00560444:	jmp 0x0056043d
0x0056043d:	popl %edi
0x0056043e:	popl %esi
0x0056043f:	popl %ebx
0x00560440:	leave
0x00560441:	ret

0x00560482:	popl %ecx
0x00560483:	popl %ecx
0x00560484:	testl %eax, %eax
0x00560486:	je 29
0x00560488:	pushl 0xc(%ebp)
0x0056048b:	pushl %eax
0x0056048c:	call GetProcAddress@KERNEL32.DLL
0x00560492:	movl %esi, %eax
0x00560494:	testl %esi, %esi
0x00560496:	je 0x005604a5
0x005604a5:	pushl $0xffffffff<UINT8>
0x005604a7:	call 0x005598bf
0x005598bf:	pushl %ebp
0x005598c0:	movl %ebp, %esp
0x005598c2:	movl %eax, 0x60a440
0x005598c7:	andl %eax, $0x1f<UINT8>
0x005598ca:	pushl $0x20<UINT8>
0x005598cc:	popl %ecx
0x005598cd:	subl %ecx, %eax
0x005598cf:	movl %eax, 0x8(%ebp)
0x005598d2:	rorl %eax, %cl
0x005598d4:	xorl %eax, 0x60a440
0x005598da:	popl %ebp
0x005598db:	ret

0x005604ac:	popl %ecx
0x005604ad:	xchgl (%edi), %eax
0x005604af:	xorl %eax, %eax
0x005604b1:	popl %esi
0x005604b2:	popl %edi
0x005604b3:	popl %ebp
0x005604b4:	ret

0x005605be:	movl %esi, %eax
0x005605c0:	addl %esp, $0x10<UINT8>
0x005605c3:	testl %esi, %esi
0x005605c5:	je 0x005605dc
0x005605dc:	pushl 0xc(%ebp)
0x005605df:	pushl 0x8(%ebp)
0x005605e2:	call InitializeCriticalSectionAndSpinCount@KERNEL32.DLL
InitializeCriticalSectionAndSpinCount@KERNEL32.DLL: API Node	
0x005605e8:	popl %esi
0x005605e9:	popl %ebp
0x005605ea:	ret

0x0056032d:	addl %esp, $0xc<UINT8>
0x00560330:	testl %eax, %eax
0x00560332:	je 21
0x00560334:	incl 0x61567c
0x0056033a:	addl %esi, $0x18<UINT8>
0x0056033d:	addl %edi, $0x18<UINT8>
0x00560340:	cmpl %esi, $0x18<UINT8>
0x00560343:	jb -37
0x00560345:	movb %al, $0x1<UINT8>
0x00560347:	jmp 0x00560350
0x00560350:	popl %edi
0x00560351:	popl %esi
0x00560352:	ret

0x0055f036:	testb %al, %al
0x0055f038:	jne 0x0055f03d
0x0055f03d:	call 0x0055f1b2
0x0055f1b2:	pushl $0x55f0bf<UINT32>
0x0055f1b7:	call 0x005604b5
0x005604b5:	pushl %ebp
0x005604b6:	movl %ebp, %esp
0x005604b8:	pushl %esi
0x005604b9:	pushl $0x5d392c<UINT32>
0x005604be:	pushl $0x5d3924<UINT32>
0x005604c3:	pushl $0x5d2320<UINT32>
0x005604c8:	pushl $0x0<UINT8>
0x005604ca:	call 0x00560446
0x005603c9:	call GetLastError@KERNEL32.DLL
GetLastError@KERNEL32.DLL: API Node	
0x005603cf:	cmpl %eax, $0x57<UINT8>
0x005603d2:	jne 0x00560409
0x00560409:	xorl %esi, %esi
0x0056040b:	testl %esi, %esi
0x0056040d:	jne 10
0x0056040f:	movl %ecx, -4(%ebp)
0x00560412:	orl %eax, $0xffffffff<UINT8>
0x00560415:	xchgl (%ecx), %eax
0x00560417:	jmp 0x0056042f
0x0056042f:	addl %edi, $0x4<UINT8>
0x00560498:	pushl %esi
0x00560499:	call 0x005598bf
0x0056049e:	popl %ecx
0x0056049f:	xchgl (%edi), %eax
0x005604a1:	movl %eax, %esi
0x005604a3:	jmp 0x005604b1
0x005604cf:	movl %esi, %eax
0x005604d1:	addl %esp, $0x10<UINT8>
0x005604d4:	testl %esi, %esi
0x005604d6:	je 16
0x005604d8:	pushl 0x8(%ebp)
0x005604db:	movl %ecx, %esi
0x005604dd:	call 0x004047c0
0x004047c0:	ret

0x005604e3:	call FlsAlloc@kernel32.dll
FlsAlloc@kernel32.dll: API Node	
0x005604e5:	popl %esi
0x005604e6:	popl %ebp
0x005604e7:	ret

0x0055f1bc:	movl 0x60a4f0, %eax
0x0055f1c1:	popl %ecx
0x0055f1c2:	cmpl %eax, $0xffffffff<UINT8>
0x0055f1c5:	jne 0x0055f1ca
0x0055f1ca:	pushl $0x615638<UINT32>
0x0055f1cf:	pushl %eax
0x0055f1d0:	call 0x00560566
0x00560566:	pushl %ebp
0x00560567:	movl %ebp, %esp
0x00560569:	pushl %esi
0x0056056a:	pushl $0x5d3944<UINT32>
0x0056056f:	pushl $0x5d393c<UINT32>
0x00560574:	pushl $0x5d2340<UINT32>
0x00560579:	pushl $0x3<UINT8>
0x0056057b:	call 0x00560446
0x005603a3:	cmpl %esi, $0xffffffff<UINT8>
0x005603a6:	je 0x0056042f
0x005603ac:	jmp 0x0056042b
0x00560580:	addl %esp, $0x10<UINT8>
0x00560583:	movl %esi, %eax
0x00560585:	pushl 0xc(%ebp)
0x00560588:	pushl 0x8(%ebp)
0x0056058b:	testl %esi, %esi
0x0056058d:	je 12
0x0056058f:	movl %ecx, %esi
0x00560591:	call 0x004047c0
0x00560597:	call FlsSetValue@kernel32.dll
FlsSetValue@kernel32.dll: API Node	
0x00560599:	jmp 0x005605a1
0x005605a1:	popl %esi
0x005605a2:	popl %ebp
0x005605a3:	ret

0x0055f1d5:	popl %ecx
0x0055f1d6:	popl %ecx
0x0055f1d7:	testl %eax, %eax
0x0055f1d9:	jne 0x0055f1e2
0x0055f1e2:	movb %al, $0x1<UINT8>
0x0055f1e4:	ret

0x0055f042:	testb %al, %al
0x0055f044:	jne 0x0055f04d
0x0055f04d:	movb %al, $0x1<UINT8>
0x0055f04f:	ret

0x0055996c:	testb %al, %al
0x0055996e:	jne 0x00559974
0x00559974:	call 0x005795ce
0x005795ce:	pushl $0x5d54b0<UINT32>
0x005795d3:	pushl $0x5d5438<UINT32>
0x005795d8:	call 0x005860b8
0x005860b8:	movl %edi, %edi
0x005860ba:	pushl %ebp
0x005860bb:	movl %ebp, %esp
0x005860bd:	pushl %ecx
0x005860be:	movl %eax, 0x60a440
0x005860c3:	xorl %eax, %ebp
0x005860c5:	movl -4(%ebp), %eax
0x005860c8:	pushl %edi
0x005860c9:	movl %edi, 0x8(%ebp)
0x005860cc:	cmpl %edi, 0xc(%ebp)
0x005860cf:	jne 0x005860d5
0x005860d5:	pushl %esi
0x005860d6:	movl %esi, %edi
0x005860d8:	pushl %ebx
0x005860d9:	movl %ebx, (%esi)
0x005860db:	testl %ebx, %ebx
0x005860dd:	je 0x005860ed
0x005860df:	movl %ecx, %ebx
0x005860e1:	call 0x004047c0
0x005860e7:	call 0x005794ef
0x005794dd:	pushl $0x60a648<UINT32>
0x005794e2:	movl %ecx, $0x615b9c<UINT32>
0x005794e7:	call 0x005606bf
0x005606bf:	movl %edi, %edi
0x005606c1:	pushl %ebp
0x005606c2:	movl %ebp, %esp
0x005606c4:	leal %eax, 0x4(%ecx)
0x005606c7:	movl %edx, %eax
0x005606c9:	subl %edx, %ecx
0x005606cb:	addl %edx, $0x3<UINT8>
0x005606ce:	pushl %esi
0x005606cf:	xorl %esi, %esi
0x005606d1:	shrl %edx, $0x2<UINT8>
0x005606d4:	cmpl %eax, %ecx
0x005606d6:	sbbl %eax, %eax
0x005606d8:	notl %eax
0x005606da:	andl %eax, %edx
0x005606dc:	je 13
0x005606de:	movl %edx, 0x8(%ebp)
0x005606e1:	incl %esi
0x005606e2:	movl (%ecx), %edx
0x005606e4:	leal %ecx, 0x4(%ecx)
0x005606e7:	cmpl %esi, %eax
0x005606e9:	jne -10
0x005606eb:	popl %esi
0x005606ec:	popl %ebp
0x005606ed:	ret $0x4<UINT16>

0x005794ec:	movb %al, $0x1<UINT8>
0x005794ee:	ret

0x005860e9:	testb %al, %al
0x005860eb:	je 8
0x005860ed:	addl %esi, $0x8<UINT8>
0x005860f0:	cmpl %esi, 0xc(%ebp)
0x005860f3:	jne 0x005860d9
0x00579511:	movl %eax, 0x60a440
0x00579516:	pushl %esi
0x00579517:	pushl $0x20<UINT8>
0x00579519:	andl %eax, $0x1f<UINT8>
0x0057951c:	xorl %esi, %esi
0x0057951e:	popl %ecx
0x0057951f:	subl %ecx, %eax
0x00579521:	rorl %esi, %cl
0x00579523:	xorl %esi, 0x60a440
0x00579529:	pushl %esi
0x0057952a:	call 0x0056082b
0x0056082b:	movl %edi, %edi
0x0056082d:	pushl %ebp
0x0056082e:	movl %ebp, %esp
0x00560830:	pushl 0x8(%ebp)
0x00560833:	movl %ecx, $0x6156dc<UINT32>
0x00560838:	call 0x005606bf
0x0056083d:	popl %ebp
0x0056083e:	ret

0x0057952f:	pushl %esi
0x00579530:	call 0x00586188
0x00586188:	movl %edi, %edi
0x0058618a:	pushl %ebp
0x0058618b:	movl %ebp, %esp
0x0058618d:	pushl 0x8(%ebp)
0x00586190:	movl %ecx, $0x615ea0<UINT32>
0x00586195:	call 0x005606bf
0x0058619a:	popl %ebp
0x0058619b:	ret

0x00579535:	pushl %esi
0x00579536:	call 0x00573716
0x00573716:	movl %edi, %edi
0x00573718:	pushl %ebp
0x00573719:	movl %ebp, %esp
0x0057371b:	pushl 0x8(%ebp)
0x0057371e:	movl %ecx, $0x6156f8<UINT32>
0x00573723:	call 0x005606bf
0x00573728:	pushl 0x8(%ebp)
0x0057372b:	movl %ecx, $0x6156fc<UINT32>
0x00573730:	call 0x005606bf
0x00573735:	pushl 0x8(%ebp)
0x00573738:	movl %ecx, $0x615700<UINT32>
0x0057373d:	call 0x005606bf
0x00573742:	pushl 0x8(%ebp)
0x00573745:	movl %ecx, $0x615704<UINT32>
0x0057374a:	call 0x005606bf
0x0057374f:	popl %ebp
0x00573750:	ret

0x0057953b:	pushl %esi
0x0057953c:	call 0x0057846b
0x0057846b:	movl %edi, %edi
0x0057846d:	pushl %ebp
0x0057846e:	movl %ebp, %esp
0x00578470:	pushl 0x8(%ebp)
0x00578473:	movl %ecx, $0x615724<UINT32>
0x00578478:	call 0x005606bf
0x0057847d:	popl %ebp
0x0057847e:	ret

0x00579541:	pushl %esi
0x00579542:	call 0x00578ef0
0x00578ef0:	movl %edi, %edi
0x00578ef2:	pushl %ebp
0x00578ef3:	movl %ebp, %esp
0x00578ef5:	movl %eax, 0x8(%ebp)
0x00578ef8:	movl 0x61594c, %eax
0x00578efd:	popl %ebp
0x00578efe:	ret

0x00579547:	addl %esp, $0x14<UINT8>
0x0057954a:	movb %al, $0x1<UINT8>
0x0057954c:	popl %esi
0x0057954d:	ret

0x0057b45a:	movl %eax, 0x60a440
0x0057b45f:	pushl %edi
0x0057b460:	pushl $0x20<UINT8>
0x0057b462:	andl %eax, $0x1f<UINT8>
0x0057b465:	movl %edi, $0x615b08<UINT32>
0x0057b46a:	popl %ecx
0x0057b46b:	subl %ecx, %eax
0x0057b46d:	xorl %eax, %eax
0x0057b46f:	rorl %eax, %cl
0x0057b471:	xorl %eax, 0x60a440
0x0057b477:	pushl $0x20<UINT8>
0x0057b479:	popl %ecx
0x0057b47a:	rep stosl %es:(%edi), %eax
0x0057b47c:	movb %al, $0x1<UINT8>
0x0057b47e:	popl %edi
0x0057b47f:	ret

0x00424630:	movb %al, $0x1<UINT8>
0x00424632:	ret

0x00579d90:	movl %edi, %edi
0x00579d92:	pushl %esi
0x00579d93:	pushl %edi
0x00579d94:	movl %edi, $0x615978<UINT32>
0x00579d99:	xorl %esi, %esi
0x00579d9b:	pushl $0x0<UINT8>
0x00579d9d:	pushl $0xfa0<UINT32>
0x00579da2:	pushl %edi
0x00579da3:	call 0x0057b14e
0x0057b14e:	movl %edi, %edi
0x0057b150:	pushl %ebp
0x0057b151:	movl %ebp, %esp
0x0057b153:	pushl %ecx
0x0057b154:	movl %eax, 0x60a440
0x0057b159:	xorl %eax, %ebp
0x0057b15b:	movl -4(%ebp), %eax
0x0057b15e:	pushl %esi
0x0057b15f:	pushl $0x5d64ec<UINT32>
0x0057b164:	pushl $0x5d64e4<UINT32>
0x0057b169:	pushl $0x5d64ec<UINT32>
0x0057b16e:	pushl $0x14<UINT8>
0x0057b170:	call 0x0057abe2
0x0057abe2:	movl %edi, %edi
0x0057abe4:	pushl %ebp
0x0057abe5:	movl %ebp, %esp
0x0057abe7:	movl %eax, 0x8(%ebp)
0x0057abea:	pushl %ebx
0x0057abeb:	pushl %esi
0x0057abec:	pushl %edi
0x0057abed:	leal %ebx, 0x615b08(,%eax,4)
0x0057abf4:	movl %eax, (%ebx)
0x0057abf6:	movl %edx, 0x60a440
0x0057abfc:	orl %edi, $0xffffffff<UINT8>
0x0057abff:	movl %ecx, %edx
0x0057ac01:	movl %esi, %edx
0x0057ac03:	andl %ecx, $0x1f<UINT8>
0x0057ac06:	xorl %esi, %eax
0x0057ac08:	rorl %esi, %cl
0x0057ac0a:	cmpl %esi, %edi
0x0057ac0c:	je 0x0057ac77
0x0057ac0e:	testl %esi, %esi
0x0057ac10:	je 0x0057ac16
0x0057ac16:	movl %esi, 0x10(%ebp)
0x0057ac19:	cmpl %esi, 0x14(%ebp)
0x0057ac1c:	je 26
0x0057ac1e:	pushl (%esi)
0x0057ac20:	call 0x0057ac7e
0x0057ac7e:	movl %edi, %edi
0x0057ac80:	pushl %ebp
0x0057ac81:	movl %ebp, %esp
0x0057ac83:	movl %eax, 0x8(%ebp)
0x0057ac86:	pushl %edi
0x0057ac87:	leal %edi, 0x615ab8(,%eax,4)
0x0057ac8e:	movl %ecx, (%edi)
0x0057ac90:	testl %ecx, %ecx
0x0057ac92:	je 0x0057ac9f
0x0057ac9f:	pushl %ebx
0x0057aca0:	movl %ebx, 0x5d5e70(,%eax,4)
0x0057aca7:	pushl %esi
0x0057aca8:	pushl $0x800<UINT32>
0x0057acad:	pushl $0x0<UINT8>
0x0057acaf:	pushl %ebx
0x0057acb0:	call LoadLibraryExW@KERNEL32.DLL
0x0057acb6:	movl %esi, %eax
0x0057acb8:	testl %esi, %esi
0x0057acba:	jne 0x0057ace3
0x0057ace3:	movl %eax, %esi
0x0057ace5:	xchgl (%edi), %eax
0x0057ace7:	testl %eax, %eax
0x0057ace9:	je 0x0057acf2
0x0057acf2:	movl %eax, %esi
0x0057acf4:	popl %esi
0x0057acf5:	popl %ebx
0x0057acf6:	popl %edi
0x0057acf7:	popl %ebp
0x0057acf8:	ret

0x0057ac25:	popl %ecx
0x0057ac26:	testl %eax, %eax
0x0057ac28:	jne 0x0057ac59
0x0057ac59:	movl %edx, 0x60a440
0x0057ac5f:	jmp 0x0057ac3a
0x0057ac3a:	testl %eax, %eax
0x0057ac3c:	je 41
0x0057ac3e:	pushl 0xc(%ebp)
0x0057ac41:	pushl %eax
0x0057ac42:	call GetProcAddress@KERNEL32.DLL
0x0057ac48:	movl %esi, %eax
0x0057ac4a:	testl %esi, %esi
0x0057ac4c:	je 0x0057ac61
0x0057ac61:	movl %edx, 0x60a440
0x0057ac67:	movl %eax, %edx
0x0057ac69:	pushl $0x20<UINT8>
0x0057ac6b:	andl %eax, $0x1f<UINT8>
0x0057ac6e:	popl %ecx
0x0057ac6f:	subl %ecx, %eax
0x0057ac71:	rorl %edi, %cl
0x0057ac73:	xorl %edi, %edx
0x0057ac75:	xchgl (%ebx), %edi
0x0057ac77:	xorl %eax, %eax
0x0057ac79:	popl %edi
0x0057ac7a:	popl %esi
0x0057ac7b:	popl %ebx
0x0057ac7c:	popl %ebp
0x0057ac7d:	ret

0x0057b175:	movl %esi, %eax
0x0057b177:	addl %esp, $0x10<UINT8>
0x0057b17a:	testl %esi, %esi
0x0057b17c:	je 0x0057b193
0x0057b193:	pushl 0xc(%ebp)
0x0057b196:	pushl 0x8(%ebp)
0x0057b199:	call InitializeCriticalSectionAndSpinCount@KERNEL32.DLL
0x0057b19f:	movl %ecx, -4(%ebp)
0x0057b1a2:	xorl %ecx, %ebp
0x0057b1a4:	popl %esi
0x0057b1a5:	call 0x00559778
0x00559778:	cmpl %ecx, 0x60a440
0x0055977e:	repn jne 2
0x00559781:	repn ret

0x0057b1aa:	movl %esp, %ebp
0x0057b1ac:	popl %ebp
0x0057b1ad:	ret $0xc<UINT16>

0x00579da8:	testl %eax, %eax
0x00579daa:	je 24
0x00579dac:	incl 0x615ab0
0x00579db2:	addl %esi, $0x18<UINT8>
0x00579db5:	addl %edi, $0x18<UINT8>
0x00579db8:	cmpl %esi, $0x138<UINT32>
0x00579dbe:	jb 0x00579d9b
0x00579dc0:	movb %al, $0x1<UINT8>
0x00579dc2:	jmp 0x00579dce
0x00579dce:	popl %edi
0x00579dcf:	popl %esi
0x00579dd0:	ret

0x00585723:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x00585729:	testl %eax, %eax
0x0058572b:	movl 0x615e98, %eax
0x00585730:	setne %al
0x00585733:	ret

0x0057a9ab:	pushl $0x57a78d<UINT32>
0x0057a9b0:	call 0x0057adda
0x0057adda:	movl %edi, %edi
0x0057addc:	pushl %ebp
0x0057addd:	movl %ebp, %esp
0x0057addf:	pushl %ecx
0x0057ade0:	movl %eax, 0x60a440
0x0057ade5:	xorl %eax, %ebp
0x0057ade7:	movl -4(%ebp), %eax
0x0057adea:	pushl %esi
0x0057adeb:	pushl $0x5d63f4<UINT32>
0x0057adf0:	pushl $0x5d63ec<UINT32>
0x0057adf5:	pushl $0x5d63f4<UINT32>
0x0057adfa:	pushl $0x3<UINT8>
0x0057adfc:	call 0x0057abe2
0x0057acbc:	call GetLastError@KERNEL32.DLL
0x0057acc2:	cmpl %eax, $0x57<UINT8>
0x0057acc5:	jne 0x0057acd4
0x0057acd4:	xorl %esi, %esi
0x0057acd6:	testl %esi, %esi
0x0057acd8:	jne 9
0x0057acda:	orl %eax, $0xffffffff<UINT8>
0x0057acdd:	xchgl (%edi), %eax
0x0057acdf:	xorl %eax, %eax
0x0057ace1:	jmp 0x0057acf4
0x0057ac2a:	addl %esi, $0x4<UINT8>
0x0057ac2d:	cmpl %esi, 0x14(%ebp)
0x0057ac30:	jne 0x0057ac1e
0x0057ac4e:	pushl %esi
0x0057ac4f:	call 0x005598bf
0x0057ac54:	popl %ecx
0x0057ac55:	xchgl (%ebx), %eax
0x0057ac57:	jmp 0x0057ac12
0x0057ac12:	movl %eax, %esi
0x0057ac14:	jmp 0x0057ac79
0x0057ae01:	movl %esi, %eax
0x0057ae03:	addl %esp, $0x10<UINT8>
0x0057ae06:	testl %esi, %esi
0x0057ae08:	je 15
0x0057ae0a:	pushl 0x8(%ebp)
0x0057ae0d:	movl %ecx, %esi
0x0057ae0f:	call 0x004047c0
0x0057ae15:	call FlsAlloc@kernel32.dll
0x0057ae17:	jmp 0x0057ae1f
0x0057ae1f:	movl %ecx, -4(%ebp)
0x0057ae22:	xorl %ecx, %ebp
0x0057ae24:	popl %esi
0x0057ae25:	call 0x00559778
0x0057ae2a:	movl %esp, %ebp
0x0057ae2c:	popl %ebp
0x0057ae2d:	ret $0x4<UINT16>

0x0057a9b5:	movl 0x60a63c, %eax
0x0057a9ba:	cmpl %eax, $0xffffffff<UINT8>
0x0057a9bd:	jne 0x0057a9c2
0x0057a9c2:	call 0x0057a926
0x0057a926:	movl %edi, %edi
0x0057a928:	pushl %ebx
0x0057a929:	pushl %esi
0x0057a92a:	pushl %edi
0x0057a92b:	call GetLastError@KERNEL32.DLL
0x0057a931:	movl %esi, %eax
0x0057a933:	xorl %ebx, %ebx
0x0057a935:	movl %eax, 0x60a63c
0x0057a93a:	cmpl %eax, $0xffffffff<UINT8>
0x0057a93d:	je 12
0x0057a93f:	pushl %eax
0x0057a940:	call 0x0057ae86
0x0057ae86:	movl %edi, %edi
0x0057ae88:	pushl %ebp
0x0057ae89:	movl %ebp, %esp
0x0057ae8b:	pushl %ecx
0x0057ae8c:	movl %eax, 0x60a440
0x0057ae91:	xorl %eax, %ebp
0x0057ae93:	movl -4(%ebp), %eax
0x0057ae96:	pushl %esi
0x0057ae97:	pushl $0x5d6418<UINT32>
0x0057ae9c:	pushl $0x5d6410<UINT32>
0x0057aea1:	pushl $0x5d6418<UINT32>
0x0057aea6:	pushl $0x5<UINT8>
0x0057aea8:	call 0x0057abe2
0x0057ac94:	leal %eax, 0x1(%ecx)
0x0057ac97:	negl %eax
0x0057ac99:	sbbl %eax, %eax
0x0057ac9b:	andl %eax, %ecx
0x0057ac9d:	jmp 0x0057acf6
0x0057aead:	addl %esp, $0x10<UINT8>
0x0057aeb0:	movl %esi, %eax
0x0057aeb2:	pushl 0x8(%ebp)
0x0057aeb5:	testl %esi, %esi
0x0057aeb7:	je 12
0x0057aeb9:	movl %ecx, %esi
0x0057aebb:	call 0x004047c0
0x0057aec1:	call FlsGetValue@kernel32.dll
FlsGetValue@kernel32.dll: API Node	
0x0057aec3:	jmp 0x0057aecb
0x0057aecb:	movl %ecx, -4(%ebp)
0x0057aece:	xorl %ecx, %ebp
0x0057aed0:	popl %esi
0x0057aed1:	call 0x00559778
0x0057aed6:	movl %esp, %ebp
0x0057aed8:	popl %ebp
0x0057aed9:	ret $0x4<UINT16>

0x0057a945:	movl %edi, %eax
0x0057a947:	testl %edi, %edi
0x0057a949:	jne 0x0057a99c
0x0057a94b:	pushl $0x364<UINT32>
0x0057a950:	pushl $0x1<UINT8>
0x0057a952:	call 0x0057aa79
0x0057aa79:	movl %edi, %edi
0x0057aa7b:	pushl %ebp
0x0057aa7c:	movl %ebp, %esp
0x0057aa7e:	pushl %esi
0x0057aa7f:	movl %esi, 0x8(%ebp)
0x0057aa82:	testl %esi, %esi
0x0057aa84:	je 12
0x0057aa86:	pushl $0xffffffe0<UINT8>
0x0057aa88:	xorl %edx, %edx
0x0057aa8a:	popl %eax
0x0057aa8b:	divl %eax, %esi
0x0057aa8d:	cmpl %eax, 0xc(%ebp)
0x0057aa90:	jb 52
0x0057aa92:	imull %esi, 0xc(%ebp)
0x0057aa96:	testl %esi, %esi
0x0057aa98:	jne 0x0057aab1
0x0057aab1:	pushl %esi
0x0057aab2:	pushl $0x8<UINT8>
0x0057aab4:	pushl 0x615e98
0x0057aaba:	call HeapAlloc@KERNEL32.DLL
HeapAlloc@KERNEL32.DLL: API Node	
0x0057aac0:	testl %eax, %eax
0x0057aac2:	je -39
0x0057aac4:	jmp 0x0057aad3
0x0057aad3:	popl %esi
0x0057aad4:	popl %ebp
0x0057aad5:	ret

0x0057a957:	movl %edi, %eax
0x0057a959:	popl %ecx
0x0057a95a:	popl %ecx
0x0057a95b:	testl %edi, %edi
0x0057a95d:	jne 0x0057a968
0x0057a968:	pushl %edi
0x0057a969:	pushl 0x60a63c
0x0057a96f:	call 0x0057aedc
0x0057aedc:	movl %edi, %edi
0x0057aede:	pushl %ebp
0x0057aedf:	movl %ebp, %esp
0x0057aee1:	pushl %ecx
0x0057aee2:	movl %eax, 0x60a440
0x0057aee7:	xorl %eax, %ebp
0x0057aee9:	movl -4(%ebp), %eax
0x0057aeec:	pushl %esi
0x0057aeed:	pushl $0x5d642c<UINT32>
0x0057aef2:	pushl $0x5d6424<UINT32>
0x0057aef7:	pushl $0x5d642c<UINT32>
0x0057aefc:	pushl $0x6<UINT8>
0x0057aefe:	call 0x0057abe2
0x0057af03:	addl %esp, $0x10<UINT8>
0x0057af06:	movl %esi, %eax
0x0057af08:	pushl 0xc(%ebp)
0x0057af0b:	pushl 0x8(%ebp)
0x0057af0e:	testl %esi, %esi
0x0057af10:	je 12
0x0057af12:	movl %ecx, %esi
0x0057af14:	call 0x004047c0
0x0057af1a:	call FlsSetValue@kernel32.dll
0x0057af1c:	jmp 0x0057af24
0x0057af24:	movl %ecx, -4(%ebp)
0x0057af27:	xorl %ecx, %ebp
0x0057af29:	popl %esi
0x0057af2a:	call 0x00559778
0x0057af2f:	movl %esp, %ebp
0x0057af31:	popl %ebp
0x0057af32:	ret $0x8<UINT16>

0x0057a974:	testl %eax, %eax
0x0057a976:	jne 0x0057a97b
0x0057a97b:	pushl $0x615b9c<UINT32>
0x0057a980:	pushl %edi
0x0057a981:	call 0x0057a714
0x0057a714:	movl %edi, %edi
0x0057a716:	pushl %ebp
0x0057a717:	movl %ebp, %esp
0x0057a719:	pushl %ecx
0x0057a71a:	pushl %ecx
0x0057a71b:	movl %eax, 0x8(%ebp)
0x0057a71e:	xorl %ecx, %ecx
0x0057a720:	incl %ecx
0x0057a721:	pushl $0x43<UINT8>
0x0057a723:	movl 0x18(%eax), %ecx
0x0057a726:	movl %eax, 0x8(%ebp)
0x0057a729:	movl (%eax), $0x5d5370<UINT32>
0x0057a72f:	movl %eax, 0x8(%ebp)
0x0057a732:	movl 0x350(%eax), %ecx
0x0057a738:	movl %eax, 0x8(%ebp)
0x0057a73b:	popl %ecx
0x0057a73c:	movl 0x48(%eax), $0x60aa40<UINT32>
0x0057a743:	movl %eax, 0x8(%ebp)
0x0057a746:	movw 0x6c(%eax), %cx
0x0057a74a:	movl %eax, 0x8(%ebp)
0x0057a74d:	movw 0x172(%eax), %cx
0x0057a754:	movl %eax, 0x8(%ebp)
0x0057a757:	andl 0x34c(%eax), $0x0<UINT8>
0x0057a75e:	leal %eax, 0x8(%ebp)
0x0057a761:	movl -4(%ebp), %eax
0x0057a764:	leal %eax, -4(%ebp)
0x0057a767:	pushl %eax
0x0057a768:	pushl $0x5<UINT8>
0x0057a76a:	call 0x0057a6ec
0x0057a6ec:	movl %edi, %edi
0x0057a6ee:	pushl %ebp
0x0057a6ef:	movl %ebp, %esp
0x0057a6f1:	subl %esp, $0xc<UINT8>
0x0057a6f4:	movl %eax, 0x8(%ebp)
0x0057a6f7:	leal %ecx, -1(%ebp)
0x0057a6fa:	movl -8(%ebp), %eax
0x0057a6fd:	movl -12(%ebp), %eax
0x0057a700:	leal %eax, -8(%ebp)
0x0057a703:	pushl %eax
0x0057a704:	pushl 0xc(%ebp)
0x0057a707:	leal %eax, -12(%ebp)
0x0057a70a:	pushl %eax
0x0057a70b:	call 0x0057a62c
0x0057a62c:	pushl $0x8<UINT8>
0x0057a62e:	pushl $0x6043c0<UINT32>
0x0057a633:	call 0x0055a840
0x0057a638:	movl %eax, 0x8(%ebp)
0x0057a63b:	pushl (%eax)
0x0057a63d:	call 0x00579dd1
0x00579dd1:	movl %edi, %edi
0x00579dd3:	pushl %ebp
0x00579dd4:	movl %ebp, %esp
0x00579dd6:	imull %eax, 0x8(%ebp), $0x18<UINT8>
0x00579dda:	addl %eax, $0x615978<UINT32>
0x00579ddf:	pushl %eax
0x00579de0:	call EnterCriticalSection@KERNEL32.DLL
EnterCriticalSection@KERNEL32.DLL: API Node	
0x00579de6:	popl %ebp
0x00579de7:	ret

0x0057a642:	popl %ecx
0x0057a643:	andl -4(%ebp), $0x0<UINT8>
0x0057a647:	movl %eax, 0xc(%ebp)
0x0057a64a:	movl %eax, (%eax)
0x0057a64c:	movl %eax, (%eax)
0x0057a64e:	movl %eax, 0x48(%eax)
0x0057a651:	incl (%eax)
0x0057a654:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0057a65b:	call 0x0057a668
0x0057a668:	movl %eax, 0x10(%ebp)
0x0057a66b:	pushl (%eax)
0x0057a66d:	call 0x00579e19
0x00579e19:	movl %edi, %edi
0x00579e1b:	pushl %ebp
0x00579e1c:	movl %ebp, %esp
0x00579e1e:	imull %eax, 0x8(%ebp), $0x18<UINT8>
0x00579e22:	addl %eax, $0x615978<UINT32>
0x00579e27:	pushl %eax
0x00579e28:	call LeaveCriticalSection@KERNEL32.DLL
LeaveCriticalSection@KERNEL32.DLL: API Node	
0x00579e2e:	popl %ebp
0x00579e2f:	ret

0x0057a672:	popl %ecx
0x0057a673:	ret

0x0057a660:	call 0x0055a886
0x0055a886:	movl %ecx, -16(%ebp)
0x0055a889:	movl %fs:0, %ecx
0x0055a890:	popl %ecx
0x0055a891:	popl %edi
0x0055a892:	popl %edi
0x0055a893:	popl %esi
0x0055a894:	popl %ebx
0x0055a895:	movl %esp, %ebp
0x0055a897:	popl %ebp
0x0055a898:	pushl %ecx
0x0055a899:	repn ret

0x0057a665:	ret $0xc<UINT16>

0x0057a710:	movl %esp, %ebp
0x0057a712:	popl %ebp
0x0057a713:	ret

0x0057a76f:	leal %eax, 0x8(%ebp)
0x0057a772:	movl -8(%ebp), %eax
0x0057a775:	leal %eax, 0xc(%ebp)
0x0057a778:	movl -4(%ebp), %eax
0x0057a77b:	leal %eax, -8(%ebp)
0x0057a77e:	pushl %eax
0x0057a77f:	pushl $0x4<UINT8>
0x0057a781:	call 0x0057a69c
0x0057a69c:	movl %edi, %edi
0x0057a69e:	pushl %ebp
0x0057a69f:	movl %ebp, %esp
0x0057a6a1:	subl %esp, $0xc<UINT8>
0x0057a6a4:	movl %eax, 0x8(%ebp)
0x0057a6a7:	leal %ecx, -1(%ebp)
0x0057a6aa:	movl -8(%ebp), %eax
0x0057a6ad:	movl -12(%ebp), %eax
0x0057a6b0:	leal %eax, -8(%ebp)
0x0057a6b3:	pushl %eax
0x0057a6b4:	pushl 0xc(%ebp)
0x0057a6b7:	leal %eax, -12(%ebp)
0x0057a6ba:	pushl %eax
0x0057a6bb:	call 0x0057a530
0x0057a530:	pushl $0x8<UINT8>
0x0057a532:	pushl $0x6043e0<UINT32>
0x0057a537:	call 0x0055a840
0x0057a53c:	movl %eax, 0x8(%ebp)
0x0057a53f:	pushl (%eax)
0x0057a541:	call 0x00579dd1
0x0057a546:	popl %ecx
0x0057a547:	andl -4(%ebp), $0x0<UINT8>
0x0057a54b:	movl %ecx, 0xc(%ebp)
0x0057a54e:	movl %eax, 0x4(%ecx)
0x0057a551:	movl %eax, (%eax)
0x0057a553:	pushl (%eax)
0x0057a555:	movl %eax, (%ecx)
0x0057a557:	pushl (%eax)
0x0057a559:	call 0x0057a857
0x0057a857:	movl %edi, %edi
0x0057a859:	pushl %ebp
0x0057a85a:	movl %ebp, %esp
0x0057a85c:	pushl %esi
0x0057a85d:	movl %esi, 0x8(%ebp)
0x0057a860:	cmpl 0x4c(%esi), $0x0<UINT8>
0x0057a864:	je 0x0057a88e
0x0057a88e:	movl %eax, 0xc(%ebp)
0x0057a891:	movl 0x4c(%esi), %eax
0x0057a894:	popl %esi
0x0057a895:	testl %eax, %eax
0x0057a897:	je 7
0x0057a899:	pushl %eax
0x0057a89a:	call 0x0057d2bf
0x0057d2bf:	movl %edi, %edi
0x0057d2c1:	pushl %ebp
0x0057d2c2:	movl %ebp, %esp
0x0057d2c4:	movl %eax, 0x8(%ebp)
0x0057d2c7:	incl 0xc(%eax)
0x0057d2cb:	movl %ecx, 0x7c(%eax)
0x0057d2ce:	testl %ecx, %ecx
0x0057d2d0:	je 0x0057d2d5
0x0057d2d5:	movl %ecx, 0x84(%eax)
0x0057d2db:	testl %ecx, %ecx
0x0057d2dd:	je 0x0057d2e2
0x0057d2e2:	movl %ecx, 0x80(%eax)
0x0057d2e8:	testl %ecx, %ecx
0x0057d2ea:	je 0x0057d2ef
0x0057d2ef:	movl %ecx, 0x8c(%eax)
0x0057d2f5:	testl %ecx, %ecx
0x0057d2f7:	je 0x0057d2fc
0x0057d2fc:	pushl %esi
0x0057d2fd:	pushl $0x6<UINT8>
0x0057d2ff:	leal %ecx, 0x28(%eax)
0x0057d302:	popl %esi
0x0057d303:	cmpl -8(%ecx), $0x60a708<UINT32>
0x0057d30a:	je 0x0057d315
0x0057d30c:	movl %edx, (%ecx)
0x0057d30e:	testl %edx, %edx
0x0057d310:	je 0x0057d315
0x0057d315:	cmpl -12(%ecx), $0x0<UINT8>
0x0057d319:	je 0x0057d325
0x0057d325:	addl %ecx, $0x10<UINT8>
0x0057d328:	subl %esi, $0x1<UINT8>
0x0057d32b:	jne 0x0057d303
0x0057d32d:	pushl 0x9c(%eax)
0x0057d333:	call 0x0057d486
0x0057d486:	movl %edi, %edi
0x0057d488:	pushl %ebp
0x0057d489:	movl %ebp, %esp
0x0057d48b:	movl %ecx, 0x8(%ebp)
0x0057d48e:	testl %ecx, %ecx
0x0057d490:	je 22
0x0057d492:	cmpl %ecx, $0x5d6960<UINT32>
0x0057d498:	je 0x0057d4a8
0x0057d4a8:	movl %eax, $0x7fffffff<UINT32>
0x0057d4ad:	popl %ebp
0x0057d4ae:	ret

0x0057d338:	popl %ecx
0x0057d339:	popl %esi
0x0057d33a:	popl %ebp
0x0057d33b:	ret

0x0057a89f:	popl %ecx
0x0057a8a0:	popl %ebp
0x0057a8a1:	ret

0x0057a55e:	popl %ecx
0x0057a55f:	popl %ecx
0x0057a560:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0057a567:	call 0x0057a574
0x0057a574:	movl %eax, 0x10(%ebp)
0x0057a577:	pushl (%eax)
0x0057a579:	call 0x00579e19
0x0057a57e:	popl %ecx
0x0057a57f:	ret

0x0057a56c:	call 0x0055a886
0x0057a571:	ret $0xc<UINT16>

0x0057a6c0:	movl %esp, %ebp
0x0057a6c2:	popl %ebp
0x0057a6c3:	ret

0x0057a786:	addl %esp, $0x10<UINT8>
0x0057a789:	movl %esp, %ebp
0x0057a78b:	popl %ebp
0x0057a78c:	ret

0x0057a986:	pushl %ebx
0x0057a987:	call 0x0057a9f1
0x0057a9f1:	movl %edi, %edi
0x0057a9f3:	pushl %ebp
0x0057a9f4:	movl %ebp, %esp
0x0057a9f6:	cmpl 0x8(%ebp), $0x0<UINT8>
0x0057a9fa:	je 0x0057aa29
0x0057aa29:	popl %ebp
0x0057aa2a:	ret

0x0057a98c:	addl %esp, $0xc<UINT8>
0x0057a98f:	testl %edi, %edi
0x0057a991:	jne 0x0057a99c
0x0057a99c:	pushl %esi
0x0057a99d:	call SetLastError@KERNEL32.DLL
SetLastError@KERNEL32.DLL: API Node	
0x0057a9a3:	movl %ebx, %edi
0x0057a9a5:	popl %edi
0x0057a9a6:	popl %esi
0x0057a9a7:	movl %eax, %ebx
0x0057a9a9:	popl %ebx
0x0057a9aa:	ret

0x0057a9c7:	testl %eax, %eax
0x0057a9c9:	jne 0x0057a9d4
0x0057a9d4:	movb %al, $0x1<UINT8>
0x0057a9d6:	ret

0x0057c5c5:	pushl $0xc<UINT8>
0x0057c5c7:	pushl $0x604460<UINT32>
0x0057c5cc:	call 0x0055a840
0x0057c5d1:	pushl $0x7<UINT8>
0x0057c5d3:	call 0x00579dd1
0x0057c5d8:	popl %ecx
0x0057c5d9:	xorl %ebx, %ebx
0x0057c5db:	movb -25(%ebp), %bl
0x0057c5de:	movl -4(%ebp), %ebx
0x0057c5e1:	pushl %ebx
0x0057c5e2:	call 0x00577e1e
0x00577e1e:	pushl $0x14<UINT8>
0x00577e20:	pushl $0x604318<UINT32>
0x00577e25:	call 0x0055a840
0x00577e2a:	cmpl 0x8(%ebp), $0x2000<UINT32>
0x00577e31:	sbbl %eax, %eax
0x00577e33:	negl %eax
0x00577e35:	jne 0x00577e4e
0x00577e4e:	xorl %esi, %esi
0x00577e50:	movl -28(%ebp), %esi
0x00577e53:	pushl $0x7<UINT8>
0x00577e55:	call 0x00579dd1
0x00577e5a:	popl %ecx
0x00577e5b:	movl -4(%ebp), %esi
0x00577e5e:	movl %edi, %esi
0x00577e60:	movl %eax, 0x615da0
0x00577e65:	movl -32(%ebp), %edi
0x00577e68:	cmpl 0x8(%ebp), %eax
0x00577e6b:	jl 0x00577e8c
0x00577e6d:	cmpl 0x615ba0(,%edi,4), %esi
0x00577e74:	jne 49
0x00577e76:	call 0x00577d6f
0x00577d6f:	movl %edi, %edi
0x00577d71:	pushl %ebp
0x00577d72:	movl %ebp, %esp
0x00577d74:	pushl %ecx
0x00577d75:	pushl %ecx
0x00577d76:	pushl %ebx
0x00577d77:	pushl %edi
0x00577d78:	pushl $0x30<UINT8>
0x00577d7a:	pushl $0x40<UINT8>
0x00577d7c:	call 0x0057aa79
0x00577d81:	movl %edi, %eax
0x00577d83:	xorl %ebx, %ebx
0x00577d85:	movl -8(%ebp), %edi
0x00577d88:	popl %ecx
0x00577d89:	popl %ecx
0x00577d8a:	testl %edi, %edi
0x00577d8c:	jne 0x00577d92
0x00577d92:	leal %eax, 0xc00(%edi)
0x00577d98:	cmpl %edi, %eax
0x00577d9a:	je 62
0x00577d9c:	pushl %esi
0x00577d9d:	leal %esi, 0x20(%edi)
0x00577da0:	movl %edi, %eax
0x00577da2:	pushl %ebx
0x00577da3:	pushl $0xfa0<UINT32>
0x00577da8:	leal %eax, -32(%esi)
0x00577dab:	pushl %eax
0x00577dac:	call 0x0057b14e
0x00577db1:	orl -8(%esi), $0xffffffff<UINT8>
0x00577db5:	movl (%esi), %ebx
0x00577db7:	leal %esi, 0x30(%esi)
0x00577dba:	movl -44(%esi), %ebx
0x00577dbd:	leal %eax, -32(%esi)
0x00577dc0:	movl -40(%esi), $0xa0a0000<UINT32>
0x00577dc7:	movb -36(%esi), $0xa<UINT8>
0x00577dcb:	andb -35(%esi), $0xfffffff8<UINT8>
0x00577dcf:	movb -34(%esi), %bl
0x00577dd2:	cmpl %eax, %edi
0x00577dd4:	jne 0x00577da2
0x00577dd6:	movl %edi, -8(%ebp)
0x00577dd9:	popl %esi
0x00577dda:	pushl %ebx
0x00577ddb:	call 0x0057a9f1
0x00577de0:	popl %ecx
0x00577de1:	movl %eax, %edi
0x00577de3:	popl %edi
0x00577de4:	popl %ebx
0x00577de5:	movl %esp, %ebp
0x00577de7:	popl %ebp
0x00577de8:	ret

0x00577e7b:	movl 0x615ba0(,%edi,4), %eax
0x00577e82:	testl %eax, %eax
0x00577e84:	jne 0x00577e9a
0x00577e9a:	movl %eax, 0x615da0
0x00577e9f:	addl %eax, $0x40<UINT8>
0x00577ea2:	movl 0x615da0, %eax
0x00577ea7:	incl %edi
0x00577ea8:	jmp 0x00577e65
0x00577e8c:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00577e93:	call 0x00577ead
0x00577ead:	pushl $0x7<UINT8>
0x00577eaf:	call 0x00579e19
0x00577eb4:	popl %ecx
0x00577eb5:	ret

0x00577e98:	jmp 0x00577e46
0x00577e46:	movl %eax, %esi
0x00577e48:	call 0x0055a886
0x00577e4d:	ret

0x0057c5e7:	popl %ecx
0x0057c5e8:	testl %eax, %eax
0x0057c5ea:	jne 15
0x0057c5ec:	call 0x0057c459
0x0057c459:	movl %edi, %edi
0x0057c45b:	pushl %ebp
0x0057c45c:	movl %ebp, %esp
0x0057c45e:	subl %esp, $0x48<UINT8>
0x0057c461:	leal %eax, -72(%ebp)
0x0057c464:	pushl %eax
0x0057c465:	call GetStartupInfoW@KERNEL32.DLL
GetStartupInfoW@KERNEL32.DLL: API Node	
0x0057c46b:	cmpw -22(%ebp), $0x0<UINT8>
0x0057c470:	je 149
0x0057c476:	movl %eax, -20(%ebp)
0x0057c479:	testl %eax, %eax
0x0057c47b:	je 138
0x0057c481:	pushl %ebx
0x0057c482:	pushl %esi
0x0057c483:	movl %esi, (%eax)
0x0057c485:	leal %ebx, 0x4(%eax)
0x0057c488:	leal %eax, (%ebx,%esi)
0x0057c48b:	movl -4(%ebp), %eax
0x0057c48e:	movl %eax, $0x2000<UINT32>
0x0057c493:	cmpl %esi, %eax
0x0057c495:	jl 0x0057c499
0x0057c499:	pushl %esi
0x0057c49a:	call 0x00577e1e
0x0057c49f:	movl %eax, 0x615da0
0x0057c4a4:	popl %ecx
0x0057c4a5:	cmpl %esi, %eax
0x0057c4a7:	jle 0x0057c4ab
0x0057c4ab:	pushl %edi
0x0057c4ac:	xorl %edi, %edi
0x0057c4ae:	testl %esi, %esi
0x0057c4b0:	je 0x0057c508
0x0057c508:	popl %edi
0x0057c509:	popl %esi
0x0057c50a:	popl %ebx
0x0057c50b:	movl %esp, %ebp
0x0057c50d:	popl %ebp
0x0057c50e:	ret

0x0057c5f1:	call 0x0057c50f
0x0057c50f:	movl %edi, %edi
0x0057c511:	pushl %ebx
0x0057c512:	pushl %esi
0x0057c513:	pushl %edi
0x0057c514:	xorl %edi, %edi
0x0057c516:	movl %eax, %edi
0x0057c518:	movl %ecx, %edi
0x0057c51a:	andl %eax, $0x3f<UINT8>
0x0057c51d:	sarl %ecx, $0x6<UINT8>
0x0057c520:	imull %esi, %eax, $0x30<UINT8>
0x0057c523:	addl %esi, 0x615ba0(,%ecx,4)
0x0057c52a:	cmpl 0x18(%esi), $0xffffffff<UINT8>
0x0057c52e:	je 0x0057c53c
0x0057c53c:	movl %eax, %edi
0x0057c53e:	movb 0x28(%esi), $0xffffff81<UINT8>
0x0057c542:	subl %eax, $0x0<UINT8>
0x0057c545:	je 0x0057c557
0x0057c557:	pushl $0xfffffff6<UINT8>
0x0057c559:	popl %eax
0x0057c55a:	pushl %eax
0x0057c55b:	call GetStdHandle@KERNEL32.DLL
GetStdHandle@KERNEL32.DLL: API Node	
0x0057c561:	movl %ebx, %eax
0x0057c563:	cmpl %ebx, $0xffffffff<UINT8>
0x0057c566:	je 13
0x0057c568:	testl %ebx, %ebx
0x0057c56a:	je 9
0x0057c56c:	pushl %ebx
0x0057c56d:	call GetFileType@KERNEL32.DLL
GetFileType@KERNEL32.DLL: API Node	
0x0057c573:	jmp 0x0057c577
0x0057c577:	testl %eax, %eax
0x0057c579:	je 30
0x0057c57b:	andl %eax, $0xff<UINT32>
0x0057c580:	movl 0x18(%esi), %ebx
0x0057c583:	cmpl %eax, $0x2<UINT8>
0x0057c586:	jne 6
0x0057c588:	orb 0x28(%esi), $0x40<UINT8>
0x0057c58c:	jmp 0x0057c5b7
0x0057c5b7:	incl %edi
0x0057c5b8:	cmpl %edi, $0x3<UINT8>
0x0057c5bb:	jne 0x0057c516
0x0057c547:	subl %eax, $0x1<UINT8>
0x0057c54a:	je 0x0057c553
0x0057c553:	pushl $0xfffffff5<UINT8>
0x0057c555:	jmp 0x0057c559
0x0057c54c:	pushl $0xfffffff4<UINT8>
0x0057c54e:	subl %eax, $0x1<UINT8>
0x0057c551:	jmp 0x0057c559
0x0057c5c1:	popl %edi
0x0057c5c2:	popl %esi
0x0057c5c3:	popl %ebx
0x0057c5c4:	ret

0x0057c5f6:	movb %bl, $0x1<UINT8>
0x0057c5f8:	movb -25(%ebp), %bl
0x0057c5fb:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0057c602:	call 0x0057c612
0x0057c612:	pushl $0x7<UINT8>
0x0057c614:	call 0x00579e19
0x0057c619:	popl %ecx
0x0057c61a:	ret

0x0057c607:	movb %al, %bl
0x0057c609:	call 0x0055a886
0x0057c60e:	ret

0x005770fd:	call GetCommandLineA@KERNEL32.DLL
GetCommandLineA@KERNEL32.DLL: API Node	
0x00577103:	movl 0x615714, %eax
0x00577108:	call GetCommandLineW@KERNEL32.DLL
GetCommandLineW@KERNEL32.DLL: API Node	
0x0057710e:	movl 0x615718, %eax
0x00577113:	movb %al, $0x1<UINT8>
0x00577115:	ret

0x0057db2a:	cmpb 0x615dc0, $0x0<UINT8>
0x0057db31:	jne 18
0x0057db33:	pushl $0x1<UINT8>
0x0057db35:	pushl $0xfffffffd<UINT8>
0x0057db37:	call 0x0057da29
0x0057da29:	movl %edi, %edi
0x0057da2b:	pushl %ebp
0x0057da2c:	movl %ebp, %esp
0x0057da2e:	subl %esp, $0xc<UINT8>
0x0057da31:	call 0x0057a8a2
0x0057a8a2:	movl %edi, %edi
0x0057a8a4:	pushl %esi
0x0057a8a5:	pushl %edi
0x0057a8a6:	call GetLastError@KERNEL32.DLL
0x0057a8ac:	movl %esi, %eax
0x0057a8ae:	movl %eax, 0x60a63c
0x0057a8b3:	cmpl %eax, $0xffffffff<UINT8>
0x0057a8b6:	je 12
0x0057a8b8:	pushl %eax
0x0057a8b9:	call 0x0057ae86
0x0057a8be:	movl %edi, %eax
0x0057a8c0:	testl %edi, %edi
0x0057a8c2:	jne 0x0057a90d
0x0057a90d:	pushl %esi
0x0057a90e:	call SetLastError@KERNEL32.DLL
0x0057a914:	movl %eax, %edi
0x0057a916:	popl %edi
0x0057a917:	popl %esi
0x0057a918:	ret

0x0057da36:	movl -4(%ebp), %eax
0x0057da39:	call 0x0057db48
0x0057db48:	pushl $0xc<UINT8>
0x0057db4a:	pushl $0x6044a0<UINT32>
0x0057db4f:	call 0x0055a840
0x0057db54:	xorl %esi, %esi
0x0057db56:	movl -28(%ebp), %esi
0x0057db59:	call 0x0057a8a2
0x0057db5e:	movl %edi, %eax
0x0057db60:	movl %ecx, 0x60ac64
0x0057db66:	testl 0x350(%edi), %ecx
0x0057db6c:	je 0x0057db7f
0x0057db7f:	pushl $0x5<UINT8>
0x0057db81:	call 0x00579dd1
0x0057db86:	popl %ecx
0x0057db87:	movl -4(%ebp), %esi
0x0057db8a:	movl %esi, 0x48(%edi)
0x0057db8d:	movl -28(%ebp), %esi
0x0057db90:	cmpl %esi, 0x60ac60
0x0057db96:	je 0x0057dbc8
0x0057dbc8:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0057dbcf:	call 0x0057dbd9
0x0057dbd9:	pushl $0x5<UINT8>
0x0057dbdb:	call 0x00579e19
0x0057dbe0:	popl %ecx
0x0057dbe1:	ret

0x0057dbd4:	jmp 0x0057db76
0x0057db76:	testl %esi, %esi
0x0057db78:	jne 0x0057dbe2
0x0057dbe2:	movl %eax, %esi
0x0057dbe4:	call 0x0055a886
0x0057dbe9:	ret

0x0057da3e:	pushl 0x8(%ebp)
0x0057da41:	call 0x0057d7bd
0x0057d7bd:	movl %edi, %edi
0x0057d7bf:	pushl %ebp
0x0057d7c0:	movl %ebp, %esp
0x0057d7c2:	subl %esp, $0x10<UINT8>
0x0057d7c5:	leal %ecx, -16(%ebp)
0x0057d7c8:	pushl $0x0<UINT8>
0x0057d7ca:	call 0x00561cea
0x00561cea:	movl %edi, %edi
0x00561cec:	pushl %ebp
0x00561ced:	movl %ebp, %esp
0x00561cef:	pushl %edi
0x00561cf0:	movl %edi, %ecx
0x00561cf2:	movl %ecx, 0x8(%ebp)
0x00561cf5:	movb 0xc(%edi), $0x0<UINT8>
0x00561cf9:	testl %ecx, %ecx
0x00561cfb:	je 0x00561d07
0x00561d07:	movl %eax, 0x6156e0
0x00561d0c:	testl %eax, %eax
0x00561d0e:	jne 18
0x00561d10:	movl %eax, 0x60a700
0x00561d15:	movl 0x4(%edi), %eax
0x00561d18:	movl %eax, 0x60a704
0x00561d1d:	movl 0x8(%edi), %eax
0x00561d20:	jmp 0x00561d66
0x00561d66:	movl %eax, %edi
0x00561d68:	popl %edi
0x00561d69:	popl %ebp
0x00561d6a:	ret $0x4<UINT16>

0x0057d7cf:	andl 0x615dbc, $0x0<UINT8>
0x0057d7d6:	movl %eax, 0x8(%ebp)
0x0057d7d9:	cmpl %eax, $0xfffffffe<UINT8>
0x0057d7dc:	jne 0x0057d7f0
0x0057d7f0:	cmpl %eax, $0xfffffffd<UINT8>
0x0057d7f3:	jne 0x0057d807
0x0057d7f5:	movl 0x615dbc, $0x1<UINT32>
0x0057d7ff:	call GetACP@KERNEL32.DLL
GetACP@KERNEL32.DLL: API Node	
0x0057d805:	jmp 0x0057d81c
0x0057d81c:	cmpb -4(%ebp), $0x0<UINT8>
0x0057d820:	je 0x0057d82c
0x0057d82c:	movl %esp, %ebp
0x0057d82e:	popl %ebp
0x0057d82f:	ret

0x0057da46:	popl %ecx
0x0057da47:	movl %ecx, -4(%ebp)
0x0057da4a:	movl -12(%ebp), %eax
0x0057da4d:	movl %ecx, 0x48(%ecx)
0x0057da50:	cmpl %eax, 0x4(%ecx)
0x0057da53:	jne 0x0057da59
0x0057da59:	pushl %ebx
0x0057da5a:	pushl %esi
0x0057da5b:	pushl %edi
0x0057da5c:	pushl $0x220<UINT32>
0x0057da61:	call 0x0057aa2b
0x0057aa2b:	movl %edi, %edi
0x0057aa2d:	pushl %ebp
0x0057aa2e:	movl %ebp, %esp
0x0057aa30:	pushl %esi
0x0057aa31:	movl %esi, 0x8(%ebp)
0x0057aa34:	cmpl %esi, $0xffffffe0<UINT8>
0x0057aa37:	ja 48
0x0057aa39:	testl %esi, %esi
0x0057aa3b:	jne 0x0057aa54
0x0057aa54:	pushl %esi
0x0057aa55:	pushl $0x0<UINT8>
0x0057aa57:	pushl 0x615e98
0x0057aa5d:	call HeapAlloc@KERNEL32.DLL
0x0057aa63:	testl %eax, %eax
0x0057aa65:	je -39
0x0057aa67:	jmp 0x0057aa76
0x0057aa76:	popl %esi
0x0057aa77:	popl %ebp
0x0057aa78:	ret

0x0057da66:	movl %edi, %eax
0x0057da68:	orl %ebx, $0xffffffff<UINT8>
0x0057da6b:	popl %ecx
0x0057da6c:	testl %edi, %edi
0x0057da6e:	je 46
0x0057da70:	movl %esi, -4(%ebp)
0x0057da73:	movl %ecx, $0x88<UINT32>
0x0057da78:	movl %esi, 0x48(%esi)
0x0057da7b:	rep movsl %es:(%edi), %ds:(%esi)
0x0057da7d:	movl %edi, %eax
0x0057da7f:	pushl %edi
0x0057da80:	pushl -12(%ebp)
0x0057da83:	andl (%edi), $0x0<UINT8>
0x0057da86:	call 0x0057dbea
0x0057dbea:	movl %edi, %edi
0x0057dbec:	pushl %ebp
0x0057dbed:	movl %ebp, %esp
0x0057dbef:	subl %esp, $0x20<UINT8>
0x0057dbf2:	movl %eax, 0x60a440
0x0057dbf7:	xorl %eax, %ebp
0x0057dbf9:	movl -4(%ebp), %eax
0x0057dbfc:	pushl %ebx
0x0057dbfd:	pushl %esi
0x0057dbfe:	pushl 0x8(%ebp)
0x0057dc01:	movl %esi, 0xc(%ebp)
0x0057dc04:	call 0x0057d7bd
0x0057d807:	cmpl %eax, $0xfffffffc<UINT8>
0x0057d80a:	jne 0x0057d81c
0x0057dc09:	movl %ebx, %eax
0x0057dc0b:	popl %ecx
0x0057dc0c:	testl %ebx, %ebx
0x0057dc0e:	jne 0x0057dc1e
0x0057dc1e:	pushl %edi
0x0057dc1f:	xorl %edi, %edi
0x0057dc21:	movl %ecx, %edi
0x0057dc23:	movl %eax, %edi
0x0057dc25:	movl -28(%ebp), %ecx
0x0057dc28:	cmpl 0x60a748(%eax), %ebx
0x0057dc2e:	je 234
0x0057dc34:	incl %ecx
0x0057dc35:	addl %eax, $0x30<UINT8>
0x0057dc38:	movl -28(%ebp), %ecx
0x0057dc3b:	cmpl %eax, $0xf0<UINT32>
0x0057dc40:	jb 0x0057dc28
0x0057dc42:	cmpl %ebx, $0xfde8<UINT32>
0x0057dc48:	je 200
0x0057dc4e:	cmpl %ebx, $0xfde9<UINT32>
0x0057dc54:	je 188
0x0057dc5a:	movzwl %eax, %bx
0x0057dc5d:	pushl %eax
0x0057dc5e:	call IsValidCodePage@KERNEL32.DLL
IsValidCodePage@KERNEL32.DLL: API Node	
0x0057dc64:	testl %eax, %eax
0x0057dc66:	je 170
0x0057dc6c:	leal %eax, -24(%ebp)
0x0057dc6f:	pushl %eax
0x0057dc70:	pushl %ebx
0x0057dc71:	call GetCPInfo@KERNEL32.DLL
GetCPInfo@KERNEL32.DLL: API Node	
0x0057dc77:	testl %eax, %eax
0x0057dc79:	je 132
0x0057dc7f:	pushl $0x101<UINT32>
0x0057dc84:	leal %eax, 0x18(%esi)
0x0057dc87:	pushl %edi
0x0057dc88:	pushl %eax
0x0057dc89:	call 0x0055cbe0
0x0055cbe0:	movl %ecx, 0xc(%esp)
0x0055cbe4:	movzbl %eax, 0x8(%esp)
0x0055cbe9:	movl %edx, %edi
0x0055cbeb:	movl %edi, 0x4(%esp)
0x0055cbef:	testl %ecx, %ecx
0x0055cbf1:	je 316
0x0055cbf7:	imull %eax, %eax, $0x1010101<UINT32>
0x0055cbfd:	cmpl %ecx, $0x20<UINT8>
0x0055cc00:	jbe 223
0x0055cc06:	cmpl %ecx, $0x80<UINT32>
0x0055cc0c:	jb 139
0x0055cc12:	btl 0x61502c, $0x1<UINT8>
0x0055cc1a:	jae 0x0055cc25
0x0055cc25:	btl 0x60a460, $0x1<UINT8>
0x0055cc2d:	jae 178
0x0055cc33:	movd %xmm0, %eax
0x0055cc37:	pshufd %xmm0, %xmm0, $0x0<UINT8>
0x0055cc3c:	addl %ecx, %edi
0x0055cc3e:	movups (%edi), %xmm0
0x0055cc41:	addl %edi, $0x10<UINT8>
0x0055cc44:	andl %edi, $0xfffffff0<UINT8>
0x0055cc47:	subl %ecx, %edi
0x0055cc49:	cmpl %ecx, $0x80<UINT32>
0x0055cc4f:	jbe 0x0055cc9d
0x0055cc51:	leal %esp, (%esp)
0x0055cc58:	leal %esp, (%esp)
0x0055cc5f:	nop
0x0055cc60:	movdqa (%edi), %xmm0
0x0055cc64:	movdqa 0x10(%edi), %xmm0
0x0055cc69:	movdqa 0x20(%edi), %xmm0
0x0055cc6e:	movdqa 0x30(%edi), %xmm0
0x0055cc73:	movdqa 0x40(%edi), %xmm0
0x0055cc78:	movdqa 0x50(%edi), %xmm0
0x0055cc7d:	movdqa 0x60(%edi), %xmm0
0x0055cc82:	movdqa 0x70(%edi), %xmm0
0x0055cc87:	leal %edi, 0x80(%edi)
0x0055cc8d:	subl %ecx, $0x80<UINT32>
0x0055cc93:	testl %ecx, $0xffffff00<UINT32>
0x0055cc99:	jne 0x0055cc60
0x0055cc9b:	jmp 0x0055ccb0
0x0055ccb0:	cmpl %ecx, $0x20<UINT8>
0x0055ccb3:	jb 28
0x0055ccb5:	movdqu (%edi), %xmm0
0x0055ccb9:	movdqu 0x10(%edi), %xmm0
0x0055ccbe:	addl %edi, $0x20<UINT8>
0x0055ccc1:	subl %ecx, $0x20<UINT8>
0x0055ccc4:	cmpl %ecx, $0x20<UINT8>
0x0055ccc7:	jae 0x0055ccb5
0x0055ccc9:	testl %ecx, $0x1f<UINT32>
0x0055cccf:	je 98
0x0055ccd1:	leal %edi, -32(%edi,%ecx)
0x0055ccd5:	movdqu (%edi), %xmm0
0x0055ccd9:	movdqu 0x10(%edi), %xmm0
0x0055ccde:	movl %eax, 0x4(%esp)
0x0055cce2:	movl %edi, %edx
0x0055cce4:	ret

0x0057dc8e:	movl 0x4(%esi), %ebx
0x0057dc91:	addl %esp, $0xc<UINT8>
0x0057dc94:	xorl %ebx, %ebx
0x0057dc96:	movl 0x21c(%esi), %edi
0x0057dc9c:	incl %ebx
0x0057dc9d:	cmpl -24(%ebp), %ebx
0x0057dca0:	jbe 81
0x0057dca2:	cmpb -18(%ebp), $0x0<UINT8>
0x0057dca6:	leal %eax, -18(%ebp)
0x0057dca9:	je 0x0057dccc
0x0057dccc:	leal %eax, 0x1a(%esi)
0x0057dccf:	movl %ecx, $0xfe<UINT32>
0x0057dcd4:	orb (%eax), $0x8<UINT8>
0x0057dcd7:	incl %eax
0x0057dcd8:	subl %ecx, $0x1<UINT8>
0x0057dcdb:	jne 0x0057dcd4
0x0057dcdd:	pushl 0x4(%esi)
0x0057dce0:	call 0x0057d77f
0x0057d77f:	movl %edi, %edi
0x0057d781:	pushl %ebp
0x0057d782:	movl %ebp, %esp
0x0057d784:	movl %eax, 0x8(%ebp)
0x0057d787:	subl %eax, $0x3a4<UINT32>
0x0057d78c:	je 40
0x0057d78e:	subl %eax, $0x4<UINT8>
0x0057d791:	je 28
0x0057d793:	subl %eax, $0xd<UINT8>
0x0057d796:	je 16
0x0057d798:	subl %eax, $0x1<UINT8>
0x0057d79b:	je 4
0x0057d79d:	xorl %eax, %eax
0x0057d79f:	popl %ebp
0x0057d7a0:	ret

0x0057dce5:	addl %esp, $0x4<UINT8>
0x0057dce8:	movl 0x21c(%esi), %eax
0x0057dcee:	movl 0x8(%esi), %ebx
0x0057dcf1:	jmp 0x0057dcf6
0x0057dcf6:	xorl %eax, %eax
0x0057dcf8:	leal %edi, 0xc(%esi)
0x0057dcfb:	stosl %es:(%edi), %eax
0x0057dcfc:	stosl %es:(%edi), %eax
0x0057dcfd:	stosl %es:(%edi), %eax
0x0057dcfe:	jmp 0x0057ddc1
0x0057ddc1:	pushl %esi
0x0057ddc2:	call 0x0057d895
0x0057d895:	movl %edi, %edi
0x0057d897:	pushl %ebp
0x0057d898:	movl %ebp, %esp
0x0057d89a:	subl %esp, $0x720<UINT32>
0x0057d8a0:	movl %eax, 0x60a440
0x0057d8a5:	xorl %eax, %ebp
0x0057d8a7:	movl -4(%ebp), %eax
0x0057d8aa:	pushl %ebx
0x0057d8ab:	pushl %esi
0x0057d8ac:	movl %esi, 0x8(%ebp)
0x0057d8af:	leal %eax, -1816(%ebp)
0x0057d8b5:	pushl %edi
0x0057d8b6:	pushl %eax
0x0057d8b7:	pushl 0x4(%esi)
0x0057d8ba:	call GetCPInfo@KERNEL32.DLL
0x0057d8c0:	xorl %ebx, %ebx
0x0057d8c2:	movl %edi, $0x100<UINT32>
0x0057d8c7:	testl %eax, %eax
0x0057d8c9:	je 240
0x0057d8cf:	movl %eax, %ebx
0x0057d8d1:	movb -260(%ebp,%eax), %al
0x0057d8d8:	incl %eax
0x0057d8d9:	cmpl %eax, %edi
0x0057d8db:	jb 0x0057d8d1
0x0057d8dd:	movb %al, -1810(%ebp)
0x0057d8e3:	leal %ecx, -1810(%ebp)
0x0057d8e9:	movb -260(%ebp), $0x20<UINT8>
0x0057d8f0:	jmp 0x0057d911
0x0057d911:	testb %al, %al
0x0057d913:	jne -35
0x0057d915:	pushl %ebx
0x0057d916:	pushl 0x4(%esi)
0x0057d919:	leal %eax, -1796(%ebp)
0x0057d91f:	pushl %eax
0x0057d920:	pushl %edi
0x0057d921:	leal %eax, -260(%ebp)
0x0057d927:	pushl %eax
0x0057d928:	pushl $0x1<UINT8>
0x0057d92a:	pushl %ebx
0x0057d92b:	call 0x0057d1a2
0x0057d1a2:	movl %edi, %edi
0x0057d1a4:	pushl %ebp
0x0057d1a5:	movl %ebp, %esp
0x0057d1a7:	subl %esp, $0x18<UINT8>
0x0057d1aa:	movl %eax, 0x60a440
0x0057d1af:	xorl %eax, %ebp
0x0057d1b1:	movl -4(%ebp), %eax
0x0057d1b4:	pushl %ebx
0x0057d1b5:	pushl %esi
0x0057d1b6:	pushl %edi
0x0057d1b7:	pushl 0x8(%ebp)
0x0057d1ba:	leal %ecx, -24(%ebp)
0x0057d1bd:	call 0x00561cea
0x0057d1c2:	movl %ecx, 0x1c(%ebp)
0x0057d1c5:	testl %ecx, %ecx
0x0057d1c7:	jne 0x0057d1d4
0x0057d1d4:	xorl %eax, %eax
0x0057d1d6:	xorl %edi, %edi
0x0057d1d8:	cmpl 0x20(%ebp), %eax
0x0057d1db:	pushl %edi
0x0057d1dc:	pushl %edi
0x0057d1dd:	pushl 0x14(%ebp)
0x0057d1e0:	setne %al
0x0057d1e3:	pushl 0x10(%ebp)
0x0057d1e6:	leal %eax, 0x1(,%eax,8)
0x0057d1ed:	pushl %eax
0x0057d1ee:	pushl %ecx
0x0057d1ef:	call MultiByteToWideChar@KERNEL32.DLL
MultiByteToWideChar@KERNEL32.DLL: API Node	
0x0057d1f5:	movl -8(%ebp), %eax
0x0057d1f8:	testl %eax, %eax
0x0057d1fa:	je 153
0x0057d200:	leal %ebx, (%eax,%eax)
0x0057d203:	leal %ecx, 0x8(%ebx)
0x0057d206:	cmpl %ebx, %ecx
0x0057d208:	sbbl %eax, %eax
0x0057d20a:	testl %ecx, %eax
0x0057d20c:	je 74
0x0057d20e:	leal %ecx, 0x8(%ebx)
0x0057d211:	cmpl %ebx, %ecx
0x0057d213:	sbbl %eax, %eax
0x0057d215:	andl %eax, %ecx
0x0057d217:	leal %ecx, 0x8(%ebx)
0x0057d21a:	cmpl %eax, $0x400<UINT32>
0x0057d21f:	ja 25
0x0057d221:	cmpl %ebx, %ecx
0x0057d223:	sbbl %eax, %eax
0x0057d225:	andl %eax, %ecx
0x0057d227:	call 0x0055a170
0x0055a170:	pushl %ecx
0x0055a171:	leal %ecx, 0x8(%esp)
0x0055a175:	subl %ecx, %eax
0x0055a177:	andl %ecx, $0xf<UINT8>
0x0055a17a:	addl %eax, %ecx
0x0055a17c:	sbbl %ecx, %ecx
0x0055a17e:	orl %eax, %ecx
0x0055a180:	popl %ecx
0x0055a181:	jmp 0x0055a1a0
0x0055a1a0:	pushl %ecx
0x0055a1a1:	leal %ecx, 0x4(%esp)
0x0055a1a5:	subl %ecx, %eax
0x0055a1a7:	sbbl %eax, %eax
0x0055a1a9:	notl %eax
0x0055a1ab:	andl %ecx, %eax
0x0055a1ad:	movl %eax, %esp
0x0055a1af:	andl %eax, $0xfffff000<UINT32>
0x0055a1b4:	cmpl %ecx, %eax
0x0055a1b6:	repn jb 11
0x0055a1b9:	movl %eax, %ecx
0x0055a1bb:	popl %ecx
0x0055a1bc:	xchgl %esp, %eax
0x0055a1bd:	movl %eax, (%eax)
0x0055a1bf:	movl (%esp), %eax
0x0055a1c2:	repn ret

0x0057d22c:	movl %esi, %esp
0x0057d22e:	testl %esi, %esi
0x0057d230:	je 96
0x0057d232:	movl (%esi), $0xcccc<UINT32>
0x0057d238:	jmp 0x0057d253
0x0057d253:	addl %esi, $0x8<UINT8>
0x0057d256:	jmp 0x0057d25a
0x0057d25a:	testl %esi, %esi
0x0057d25c:	je 52
0x0057d25e:	pushl %ebx
0x0057d25f:	pushl %edi
0x0057d260:	pushl %esi
0x0057d261:	call 0x0055cbe0
0x0057d266:	addl %esp, $0xc<UINT8>
0x0057d269:	pushl -8(%ebp)
0x0057d26c:	pushl %esi
0x0057d26d:	pushl 0x14(%ebp)
0x0057d270:	pushl 0x10(%ebp)
0x0057d273:	pushl $0x1<UINT8>
0x0057d275:	pushl 0x1c(%ebp)
0x0057d278:	call MultiByteToWideChar@KERNEL32.DLL
0x0057d27e:	testl %eax, %eax
0x0057d280:	je 16
0x0057d282:	pushl 0x18(%ebp)
0x0057d285:	pushl %eax
0x0057d286:	pushl %esi
0x0057d287:	pushl 0xc(%ebp)
0x0057d28a:	call GetStringTypeW@KERNEL32.DLL
GetStringTypeW@KERNEL32.DLL: API Node	
0x0057d290:	movl %edi, %eax
0x0057d292:	pushl %esi
0x0057d293:	call 0x0055b99a
0x0055b99a:	pushl %ebp
0x0055b99b:	movl %ebp, %esp
0x0055b99d:	movl %eax, 0x8(%ebp)
0x0055b9a0:	testl %eax, %eax
0x0055b9a2:	je 0x0055b9b6
0x0055b9a4:	subl %eax, $0x8<UINT8>
0x0055b9a7:	cmpl (%eax), $0xdddd<UINT32>
0x0055b9ad:	jne 0x0055b9b6
0x0055b9b6:	popl %ebp
0x0055b9b7:	ret

0x0057d298:	popl %ecx
0x0057d299:	cmpb -12(%ebp), $0x0<UINT8>
0x0057d29d:	je 0x0057d2a9
0x0057d2a9:	movl %eax, %edi
0x0057d2ab:	leal %esp, -36(%ebp)
0x0057d2ae:	popl %edi
0x0057d2af:	popl %esi
0x0057d2b0:	popl %ebx
0x0057d2b1:	movl %ecx, -4(%ebp)
0x0057d2b4:	xorl %ecx, %ebp
0x0057d2b6:	call 0x00559778
0x0057d2bb:	movl %esp, %ebp
0x0057d2bd:	popl %ebp
0x0057d2be:	ret

0x0057d930:	pushl %ebx
0x0057d931:	pushl 0x4(%esi)
0x0057d934:	leal %eax, -516(%ebp)
0x0057d93a:	pushl %edi
0x0057d93b:	pushl %eax
0x0057d93c:	pushl %edi
0x0057d93d:	leal %eax, -260(%ebp)
0x0057d943:	pushl %eax
0x0057d944:	pushl %edi
0x0057d945:	pushl 0x21c(%esi)
0x0057d94b:	pushl %ebx
0x0057d94c:	call 0x00584feb
0x00584feb:	movl %edi, %edi
0x00584fed:	pushl %ebp
0x00584fee:	movl %ebp, %esp
0x00584ff0:	subl %esp, $0x10<UINT8>
0x00584ff3:	pushl 0x8(%ebp)
0x00584ff6:	leal %ecx, -16(%ebp)
0x00584ff9:	call 0x00561cea
0x00584ffe:	pushl 0x28(%ebp)
0x00585001:	leal %eax, -12(%ebp)
0x00585004:	pushl 0x24(%ebp)
0x00585007:	pushl 0x20(%ebp)
0x0058500a:	pushl 0x1c(%ebp)
0x0058500d:	pushl 0x18(%ebp)
0x00585010:	pushl 0x14(%ebp)
0x00585013:	pushl 0x10(%ebp)
0x00585016:	pushl 0xc(%ebp)
0x00585019:	pushl %eax
0x0058501a:	call 0x00584dce
0x00584dce:	movl %edi, %edi
0x00584dd0:	pushl %ebp
0x00584dd1:	movl %ebp, %esp
0x00584dd3:	pushl %ecx
0x00584dd4:	pushl %ecx
0x00584dd5:	movl %eax, 0x60a440
0x00584dda:	xorl %eax, %ebp
0x00584ddc:	movl -4(%ebp), %eax
0x00584ddf:	pushl %ebx
0x00584de0:	pushl %esi
0x00584de1:	movl %esi, 0x18(%ebp)
0x00584de4:	pushl %edi
0x00584de5:	testl %esi, %esi
0x00584de7:	jle 20
0x00584de9:	pushl %esi
0x00584dea:	pushl 0x14(%ebp)
0x00584ded:	call 0x0057a477
0x0057a477:	movl %edi, %edi
0x0057a479:	pushl %ebp
0x0057a47a:	movl %ebp, %esp
0x0057a47c:	movl %ecx, 0x8(%ebp)
0x0057a47f:	xorl %eax, %eax
0x0057a481:	cmpb (%ecx), %al
0x0057a483:	je 12
0x0057a485:	cmpl %eax, 0xc(%ebp)
0x0057a488:	je 0x0057a491
0x0057a48a:	incl %eax
0x0057a48b:	cmpb (%eax,%ecx), $0x0<UINT8>
0x0057a48f:	jne 0x0057a485
0x0057a491:	popl %ebp
0x0057a492:	ret

0x00584df2:	popl %ecx
0x00584df3:	cmpl %eax, %esi
0x00584df5:	popl %ecx
0x00584df6:	leal %esi, 0x1(%eax)
0x00584df9:	jl 2
0x00584dfb:	movl %esi, %eax
0x00584dfd:	movl %edi, 0x24(%ebp)
0x00584e00:	testl %edi, %edi
0x00584e02:	jne 0x00584e0f
0x00584e0f:	xorl %eax, %eax
0x00584e11:	cmpl 0x28(%ebp), %eax
0x00584e14:	pushl $0x0<UINT8>
0x00584e16:	pushl $0x0<UINT8>
0x00584e18:	pushl %esi
0x00584e19:	pushl 0x14(%ebp)
0x00584e1c:	setne %al
0x00584e1f:	leal %eax, 0x1(,%eax,8)
0x00584e26:	pushl %eax
0x00584e27:	pushl %edi
0x00584e28:	call MultiByteToWideChar@KERNEL32.DLL
0x00584e2e:	movl -8(%ebp), %eax
0x00584e31:	testl %eax, %eax
0x00584e33:	je 397
0x00584e39:	leal %edx, (%eax,%eax)
0x00584e3c:	leal %ecx, 0x8(%edx)
0x00584e3f:	cmpl %edx, %ecx
0x00584e41:	sbbl %eax, %eax
0x00584e43:	testl %ecx, %eax
0x00584e45:	je 82
0x00584e47:	leal %ecx, 0x8(%edx)
0x00584e4a:	cmpl %edx, %ecx
0x00584e4c:	sbbl %eax, %eax
0x00584e4e:	andl %eax, %ecx
0x00584e50:	leal %ecx, 0x8(%edx)
0x00584e53:	cmpl %eax, $0x400<UINT32>
0x00584e58:	ja 29
0x00584e5a:	cmpl %edx, %ecx
0x00584e5c:	sbbl %eax, %eax
0x00584e5e:	andl %eax, %ecx
0x00584e60:	call 0x0055a170
0x00584e65:	movl %ebx, %esp
0x00584e67:	testl %ebx, %ebx
0x00584e69:	je 332
0x00584e6f:	movl (%ebx), $0xcccc<UINT32>
0x00584e75:	jmp 0x00584e94
0x00584e94:	addl %ebx, $0x8<UINT8>
0x00584e97:	jmp 0x00584e9b
0x00584e9b:	testl %ebx, %ebx
0x00584e9d:	je 280
0x00584ea3:	pushl -8(%ebp)
0x00584ea6:	pushl %ebx
0x00584ea7:	pushl %esi
0x00584ea8:	pushl 0x14(%ebp)
0x00584eab:	pushl $0x1<UINT8>
0x00584ead:	pushl %edi
0x00584eae:	call MultiByteToWideChar@KERNEL32.DLL
0x00584eb4:	testl %eax, %eax
0x00584eb6:	je 255
0x00584ebc:	movl %edi, -8(%ebp)
0x00584ebf:	xorl %eax, %eax
0x00584ec1:	pushl %eax
0x00584ec2:	pushl %eax
0x00584ec3:	pushl %eax
0x00584ec4:	pushl %eax
0x00584ec5:	pushl %eax
0x00584ec6:	pushl %edi
0x00584ec7:	pushl %ebx
0x00584ec8:	pushl 0x10(%ebp)
0x00584ecb:	pushl 0xc(%ebp)
0x00584ece:	call 0x0057b27d
0x0057b27d:	movl %edi, %edi
0x0057b27f:	pushl %ebp
0x0057b280:	movl %ebp, %esp
0x0057b282:	pushl %ecx
0x0057b283:	movl %eax, 0x60a440
0x0057b288:	xorl %eax, %ebp
0x0057b28a:	movl -4(%ebp), %eax
0x0057b28d:	pushl %esi
0x0057b28e:	pushl $0x5d652c<UINT32>
0x0057b293:	pushl $0x5d6524<UINT32>
0x0057b298:	pushl $0x5d652c<UINT32>
0x0057b29d:	pushl $0x16<UINT8>
0x0057b29f:	call 0x0057abe2
0x0057b2a4:	movl %esi, %eax
0x0057b2a6:	addl %esp, $0x10<UINT8>
0x0057b2a9:	testl %esi, %esi
0x0057b2ab:	je 39
0x0057b2ad:	pushl 0x28(%ebp)
0x0057b2b0:	movl %ecx, %esi
0x0057b2b2:	pushl 0x24(%ebp)
0x0057b2b5:	pushl 0x20(%ebp)
0x0057b2b8:	pushl 0x1c(%ebp)
0x0057b2bb:	pushl 0x18(%ebp)
0x0057b2be:	pushl 0x14(%ebp)
0x0057b2c1:	pushl 0x10(%ebp)
0x0057b2c4:	pushl 0xc(%ebp)
0x0057b2c7:	pushl 0x8(%ebp)
0x0057b2ca:	call 0x004047c0
0x0057b2d0:	call LCMapStringEx@kernel32.dll
LCMapStringEx@kernel32.dll: API Node	
0x0057b2d2:	jmp 0x0057b2f4
0x0057b2f4:	movl %ecx, -4(%ebp)
0x0057b2f7:	xorl %ecx, %ebp
0x0057b2f9:	popl %esi
0x0057b2fa:	call 0x00559778
0x0057b2ff:	movl %esp, %ebp
0x0057b301:	popl %ebp
0x0057b302:	ret $0x24<UINT16>

0x00584ed3:	movl %esi, %eax
0x00584ed5:	testl %esi, %esi
0x00584ed7:	je 0x00584fbb
0x00584edd:	testl 0x10(%ebp), $0x400<UINT32>
0x00584fbb:	xorl %esi, %esi
0x00584fbd:	pushl %ebx
0x00584fbe:	call 0x0055b99a
0x00584fc3:	popl %ecx
0x00584fc4:	movl %eax, %esi
0x00584fc6:	leal %esp, -20(%ebp)
0x00584fc9:	popl %edi
0x00584fca:	popl %esi
0x00584fcb:	popl %ebx
0x00584fcc:	movl %ecx, -4(%ebp)
0x00584fcf:	xorl %ecx, %ebp
0x00584fd1:	call 0x00559778
0x00584fd6:	movl %esp, %ebp
0x00584fd8:	popl %ebp
0x00584fd9:	ret

0x0058501f:	addl %esp, $0x24<UINT8>
0x00585022:	cmpb -4(%ebp), $0x0<UINT8>
0x00585026:	je 0x00585032
0x00585032:	movl %esp, %ebp
0x00585034:	popl %ebp
0x00585035:	ret

0x0057d951:	addl %esp, $0x40<UINT8>
0x0057d954:	leal %eax, -772(%ebp)
0x0057d95a:	pushl %ebx
0x0057d95b:	pushl 0x4(%esi)
0x0057d95e:	pushl %edi
0x0057d95f:	pushl %eax
0x0057d960:	pushl %edi
0x0057d961:	leal %eax, -260(%ebp)
0x0057d967:	pushl %eax
0x0057d968:	pushl $0x200<UINT32>
0x0057d96d:	pushl 0x21c(%esi)
0x0057d973:	pushl %ebx
0x0057d974:	call 0x00584feb
0x0057d979:	addl %esp, $0x24<UINT8>
0x0057d97c:	movl %ecx, %ebx
0x0057d97e:	movzwl %eax, -1796(%ebp,%ecx,2)
0x0057d986:	testb %al, $0x1<UINT8>
0x0057d988:	je 0x0057d998
0x0057d998:	testb %al, $0x2<UINT8>
0x0057d99a:	je 0x0057d9b1
0x0057d9b1:	movb 0x119(%esi,%ecx), %bl
0x0057d9b8:	incl %ecx
0x0057d9b9:	cmpl %ecx, %edi
0x0057d9bb:	jb 0x0057d97e
0x0057d98a:	orb 0x19(%esi,%ecx), $0x10<UINT8>
0x0057d98f:	movb %al, -516(%ebp,%ecx)
0x0057d996:	jmp 0x0057d9a8
0x0057d9a8:	movb 0x119(%esi,%ecx), %al
0x0057d9af:	jmp 0x0057d9b8
0x0057d99c:	orb 0x19(%esi,%ecx), $0x20<UINT8>
0x0057d9a1:	movb %al, -772(%ebp,%ecx)
0x0057d9bd:	jmp 0x0057da18
0x0057da18:	movl %ecx, -4(%ebp)
0x0057da1b:	popl %edi
0x0057da1c:	popl %esi
0x0057da1d:	xorl %ecx, %ebp
0x0057da1f:	popl %ebx
0x0057da20:	call 0x00559778
0x0057da25:	movl %esp, %ebp
0x0057da27:	popl %ebp
0x0057da28:	ret

0x0057ddc7:	popl %ecx
0x0057ddc8:	xorl %eax, %eax
0x0057ddca:	popl %edi
0x0057ddcb:	movl %ecx, -4(%ebp)
0x0057ddce:	popl %esi
0x0057ddcf:	xorl %ecx, %ebp
0x0057ddd1:	popl %ebx
0x0057ddd2:	call 0x00559778
0x0057ddd7:	movl %esp, %ebp
0x0057ddd9:	popl %ebp
0x0057ddda:	ret

0x0057da8b:	movl %esi, %eax
0x0057da8d:	popl %ecx
0x0057da8e:	popl %ecx
0x0057da8f:	cmpl %esi, %ebx
0x0057da91:	jne 0x0057dab0
0x0057dab0:	cmpb 0xc(%ebp), $0x0<UINT8>
0x0057dab4:	jne 0x0057dabb
0x0057dabb:	movl %eax, -4(%ebp)
0x0057dabe:	movl %eax, 0x48(%eax)
0x0057dac1:	xaddl (%eax), %ebx
0x0057dac5:	decl %ebx
0x0057dac6:	jne 21
0x0057dac8:	movl %eax, -4(%ebp)
0x0057dacb:	cmpl 0x48(%eax), $0x60aa40<UINT32>
0x0057dad2:	je 0x0057dadd
0x0057dadd:	movl (%edi), $0x1<UINT32>
0x0057dae3:	movl %ecx, %edi
0x0057dae5:	movl %eax, -4(%ebp)
0x0057dae8:	xorl %edi, %edi
0x0057daea:	movl 0x48(%eax), %ecx
0x0057daed:	movl %eax, -4(%ebp)
0x0057daf0:	testb 0x350(%eax), $0x2<UINT8>
0x0057daf7:	jne -89
0x0057daf9:	testb 0x60ac64, $0x1<UINT8>
0x0057db00:	jne -98
0x0057db02:	leal %eax, -4(%ebp)
0x0057db05:	movl -12(%ebp), %eax
0x0057db08:	leal %eax, -12(%ebp)
0x0057db0b:	pushl %eax
0x0057db0c:	pushl $0x5<UINT8>
0x0057db0e:	call 0x0057d693
0x0057d693:	movl %edi, %edi
0x0057d695:	pushl %ebp
0x0057d696:	movl %ebp, %esp
0x0057d698:	subl %esp, $0xc<UINT8>
0x0057d69b:	movl %eax, 0x8(%ebp)
0x0057d69e:	leal %ecx, -1(%ebp)
0x0057d6a1:	movl -8(%ebp), %eax
0x0057d6a4:	movl -12(%ebp), %eax
0x0057d6a7:	leal %eax, -8(%ebp)
0x0057d6aa:	pushl %eax
0x0057d6ab:	pushl 0xc(%ebp)
0x0057d6ae:	leal %eax, -12(%ebp)
0x0057d6b1:	pushl %eax
0x0057d6b2:	call 0x0057d650
0x0057d650:	pushl $0x8<UINT8>
0x0057d652:	pushl $0x6044c0<UINT32>
0x0057d657:	call 0x0055a840
0x0057d65c:	movl %eax, 0x8(%ebp)
0x0057d65f:	pushl (%eax)
0x0057d661:	call 0x00579dd1
0x0057d666:	popl %ecx
0x0057d667:	andl -4(%ebp), $0x0<UINT8>
0x0057d66b:	movl %ecx, 0xc(%ebp)
0x0057d66e:	call 0x0057d6bb
0x0057d6bb:	movl %edi, %edi
0x0057d6bd:	pushl %esi
0x0057d6be:	movl %esi, %ecx
0x0057d6c0:	pushl $0xc<UINT8>
0x0057d6c2:	movl %eax, (%esi)
0x0057d6c4:	movl %eax, (%eax)
0x0057d6c6:	movl %eax, 0x48(%eax)
0x0057d6c9:	movl %eax, 0x4(%eax)
0x0057d6cc:	movl 0x615da8, %eax
0x0057d6d1:	movl %eax, (%esi)
0x0057d6d3:	movl %eax, (%eax)
0x0057d6d5:	movl %eax, 0x48(%eax)
0x0057d6d8:	movl %eax, 0x8(%eax)
0x0057d6db:	movl 0x615dac, %eax
0x0057d6e0:	movl %eax, (%esi)
0x0057d6e2:	movl %eax, (%eax)
0x0057d6e4:	movl %eax, 0x48(%eax)
0x0057d6e7:	movl %eax, 0x21c(%eax)
0x0057d6ed:	movl 0x615da4, %eax
0x0057d6f2:	movl %eax, (%esi)
0x0057d6f4:	movl %eax, (%eax)
0x0057d6f6:	movl %eax, 0x48(%eax)
0x0057d6f9:	addl %eax, $0xc<UINT8>
0x0057d6fc:	pushl %eax
0x0057d6fd:	pushl $0xc<UINT8>
0x0057d6ff:	pushl $0x615db0<UINT32>
0x0057d704:	call 0x00569c20
0x00569c20:	movl %edi, %edi
0x00569c22:	pushl %ebp
0x00569c23:	movl %ebp, %esp
0x00569c25:	pushl %esi
0x00569c26:	movl %esi, 0x14(%ebp)
0x00569c29:	testl %esi, %esi
0x00569c2b:	jne 0x00569c31
0x00569c31:	movl %eax, 0x8(%ebp)
0x00569c34:	testl %eax, %eax
0x00569c36:	jne 0x00569c4b
0x00569c4b:	pushl %edi
0x00569c4c:	movl %edi, 0x10(%ebp)
0x00569c4f:	testl %edi, %edi
0x00569c51:	je 20
0x00569c53:	cmpl 0xc(%ebp), %esi
0x00569c56:	jb 15
0x00569c58:	pushl %esi
0x00569c59:	pushl %edi
0x00569c5a:	pushl %eax
0x00569c5b:	call 0x0055c0e0
0x0055c0e0:	pushl %edi
0x0055c0e1:	pushl %esi
0x0055c0e2:	movl %esi, 0x10(%esp)
0x0055c0e6:	movl %ecx, 0x14(%esp)
0x0055c0ea:	movl %edi, 0xc(%esp)
0x0055c0ee:	movl %eax, %ecx
0x0055c0f0:	movl %edx, %ecx
0x0055c0f2:	addl %eax, %esi
0x0055c0f4:	cmpl %edi, %esi
0x0055c0f6:	jbe 0x0055c100
0x0055c100:	cmpl %ecx, $0x20<UINT8>
0x0055c103:	jb 0x0055c5db
0x0055c5db:	andl %ecx, $0x1f<UINT8>
0x0055c5de:	je 48
0x0055c5e0:	movl %eax, %ecx
0x0055c5e2:	shrl %ecx, $0x2<UINT8>
0x0055c5e5:	je 15
0x0055c5e7:	movl %edx, (%esi)
0x0055c5e9:	movl (%edi), %edx
0x0055c5eb:	addl %edi, $0x4<UINT8>
0x0055c5ee:	addl %esi, $0x4<UINT8>
0x0055c5f1:	subl %ecx, $0x1<UINT8>
0x0055c5f4:	jne 0x0055c5e7
0x0055c5f6:	movl %ecx, %eax
0x0055c5f8:	andl %ecx, $0x3<UINT8>
0x0055c5fb:	je 0x0055c610
0x0055c610:	movl %eax, 0xc(%esp)
0x0055c614:	popl %esi
0x0055c615:	popl %edi
0x0055c616:	ret

0x00569c60:	addl %esp, $0xc<UINT8>
0x00569c63:	xorl %eax, %eax
0x00569c65:	jmp 0x00569c9d
0x00569c9d:	popl %edi
0x00569c9e:	popl %esi
0x00569c9f:	popl %ebp
0x00569ca0:	ret

0x0057d709:	movl %eax, (%esi)
0x0057d70b:	movl %ecx, $0x101<UINT32>
0x0057d710:	pushl %ecx
0x0057d711:	movl %eax, (%eax)
0x0057d713:	movl %eax, 0x48(%eax)
0x0057d716:	addl %eax, $0x18<UINT8>
0x0057d719:	pushl %eax
0x0057d71a:	pushl %ecx
0x0057d71b:	pushl $0x60a838<UINT32>
0x0057d720:	call 0x00569c20
0x0055c109:	cmpl %ecx, $0x80<UINT32>
0x0055c10f:	jae 0x0055c124
0x0055c124:	btl 0x61502c, $0x1<UINT8>
0x0055c12c:	jae 0x0055c137
0x0055c137:	movl %eax, %edi
0x0055c139:	xorl %eax, %esi
0x0055c13b:	testl %eax, $0xf<UINT32>
0x0055c140:	jne 0x0055c150
0x0055c142:	btl 0x60a460, $0x1<UINT8>
0x0055c14a:	jb 0x0055c530
0x0055c530:	movl %eax, %esi
0x0055c532:	andl %eax, $0xf<UINT8>
0x0055c535:	testl %eax, %eax
0x0055c537:	jne 0x0055c620
0x0055c620:	movl %edx, $0x10<UINT32>
0x0055c625:	subl %edx, %eax
0x0055c627:	subl %ecx, %edx
0x0055c629:	pushl %ecx
0x0055c62a:	movl %eax, %edx
0x0055c62c:	movl %ecx, %eax
0x0055c62e:	andl %ecx, $0x3<UINT8>
0x0055c631:	je 0x0055c63c
0x0055c63c:	shrl %eax, $0x2<UINT8>
0x0055c63f:	je 13
0x0055c641:	movl %edx, (%esi)
0x0055c643:	movl (%edi), %edx
0x0055c645:	leal %esi, 0x4(%esi)
0x0055c648:	leal %edi, 0x4(%edi)
0x0055c64b:	decl %eax
0x0055c64c:	jne 0x0055c641
0x0055c64e:	popl %ecx
0x0055c64f:	jmp 0x0055c53d
0x0055c53d:	movl %edx, %ecx
0x0055c53f:	andl %ecx, $0x7f<UINT8>
0x0055c542:	shrl %edx, $0x7<UINT8>
0x0055c545:	je 102
0x0055c547:	leal %esp, (%esp)
0x0055c54e:	movl %edi, %edi
0x0055c550:	movdqa %xmm0, (%esi)
0x0055c554:	movdqa %xmm1, 0x10(%esi)
0x0055c559:	movdqa %xmm2, 0x20(%esi)
0x0055c55e:	movdqa %xmm3, 0x30(%esi)
0x0055c563:	movdqa (%edi), %xmm0
0x0055c567:	movdqa 0x10(%edi), %xmm1
0x0055c56c:	movdqa 0x20(%edi), %xmm2
0x0055c571:	movdqa 0x30(%edi), %xmm3
0x0055c576:	movdqa %xmm4, 0x40(%esi)
0x0055c57b:	movdqa %xmm5, 0x50(%esi)
0x0055c580:	movdqa %xmm6, 0x60(%esi)
0x0055c585:	movdqa %xmm7, 0x70(%esi)
0x0055c58a:	movdqa 0x40(%edi), %xmm4
0x0055c58f:	movdqa 0x50(%edi), %xmm5
0x0055c594:	movdqa 0x60(%edi), %xmm6
0x0055c599:	movdqa 0x70(%edi), %xmm7
0x0055c59e:	leal %esi, 0x80(%esi)
0x0055c5a4:	leal %edi, 0x80(%edi)
0x0055c5aa:	decl %edx
0x0055c5ab:	jne 0x0055c550
0x0055c5ad:	testl %ecx, %ecx
0x0055c5af:	je 95
0x0055c5b1:	movl %edx, %ecx
0x0055c5b3:	shrl %edx, $0x5<UINT8>
0x0055c5b6:	testl %edx, %edx
0x0055c5b8:	je 0x0055c5db
0x0055c5ba:	leal %ebx, (%ebx)
0x0055c5c0:	movdqu %xmm0, (%esi)
0x0055c5c4:	movdqu %xmm1, 0x10(%esi)
0x0055c5c9:	movdqu (%edi), %xmm0
0x0055c5cd:	movdqu 0x10(%edi), %xmm1
0x0055c5d2:	leal %esi, 0x20(%esi)
0x0055c5d5:	leal %edi, 0x20(%edi)
0x0055c5d8:	decl %edx
0x0055c5d9:	jne 0x0055c5c0
0x0055c5fd:	movb %al, (%esi)
0x0055c5ff:	movb (%edi), %al
0x0055c601:	incl %esi
0x0055c602:	incl %edi
0x0055c603:	decl %ecx
0x0055c604:	jne 0x0055c5fd
0x0055c606:	leal %esp, (%esp)
0x0055c60d:	leal %ecx, (%ecx)
0x0057d725:	movl %eax, (%esi)
0x0057d727:	movl %ecx, $0x100<UINT32>
0x0057d72c:	pushl %ecx
0x0057d72d:	movl %eax, (%eax)
0x0057d72f:	movl %eax, 0x48(%eax)
0x0057d732:	addl %eax, $0x119<UINT32>
0x0057d737:	pushl %eax
0x0057d738:	pushl %ecx
0x0057d739:	pushl $0x60a940<UINT32>
0x0057d73e:	call 0x00569c20
0x0055c150:	btl 0x61502c, $0x0<UINT8>
0x0055c158:	jae 0x0055c307
0x0055c307:	testl %edi, $0x3<UINT32>
0x0055c30d:	je 0x0055c322
0x0055c322:	movl %edx, %ecx
0x0055c324:	cmpl %ecx, $0x20<UINT8>
0x0055c327:	jb 686
0x0055c32d:	shrl %ecx, $0x2<UINT8>
0x0055c330:	rep movsl %es:(%edi), %ds:(%esi)
0x0055c332:	andl %edx, $0x3<UINT8>
0x0055c335:	jmp 0x0055c354
0x0055c354:	movl %eax, 0xc(%esp)
0x0055c358:	popl %esi
0x0055c359:	popl %edi
0x0055c35a:	ret

0x0057d743:	movl %eax, 0x60ac60
0x0057d748:	addl %esp, $0x30<UINT8>
0x0057d74b:	orl %ecx, $0xffffffff<UINT8>
0x0057d74e:	xaddl (%eax), %ecx
0x0057d752:	jne 0x0057d767
0x0057d767:	movl %eax, (%esi)
0x0057d769:	movl %eax, (%eax)
0x0057d76b:	movl %eax, 0x48(%eax)
0x0057d76e:	movl 0x60ac60, %eax
0x0057d773:	movl %eax, (%esi)
0x0057d775:	movl %eax, (%eax)
0x0057d777:	movl %eax, 0x48(%eax)
0x0057d77a:	incl (%eax)
0x0057d77d:	popl %esi
0x0057d77e:	ret

0x0057d673:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0057d67a:	call 0x0057d687
0x0057d687:	movl %eax, 0x10(%ebp)
0x0057d68a:	pushl (%eax)
0x0057d68c:	call 0x00579e19
0x0057d691:	popl %ecx
0x0057d692:	ret

0x0057d67f:	call 0x0055a886
0x0057d684:	ret $0xc<UINT16>

0x0057d6b7:	movl %esp, %ebp
0x0057d6b9:	popl %ebp
0x0057d6ba:	ret

0x0057db13:	cmpb 0xc(%ebp), $0x0<UINT8>
0x0057db17:	popl %ecx
0x0057db18:	popl %ecx
0x0057db19:	je -123
0x0057db1b:	movl %eax, 0x60ac60
0x0057db20:	movl 0x60a704, %eax
0x0057db25:	jmp 0x0057daa0
0x0057daa0:	pushl %edi
0x0057daa1:	call 0x0057a9f1
0x0057daa6:	popl %ecx
0x0057daa7:	popl %edi
0x0057daa8:	movl %eax, %esi
0x0057daaa:	popl %esi
0x0057daab:	popl %ebx
0x0057daac:	movl %esp, %ebp
0x0057daae:	popl %ebp
0x0057daaf:	ret

0x0057db3c:	popl %ecx
0x0057db3d:	popl %ecx
0x0057db3e:	movb 0x615dc0, $0x1<UINT8>
0x0057db45:	movb %al, $0x1<UINT8>
0x0057db47:	ret

0x005794ef:	pushl $0x61595c<UINT32>
0x005794f4:	call 0x0057947c
0x0057947c:	movl %edi, %edi
0x0057947e:	pushl %ebp
0x0057947f:	movl %ebp, %esp
0x00579481:	pushl %esi
0x00579482:	movl %esi, 0x8(%ebp)
0x00579485:	testl %esi, %esi
0x00579487:	jne 0x0057948e
0x0057948e:	movl %eax, (%esi)
0x00579490:	cmpl %eax, 0x8(%esi)
0x00579493:	jne 31
0x00579495:	movl %eax, 0x60a440
0x0057949a:	andl %eax, $0x1f<UINT8>
0x0057949d:	pushl $0x20<UINT8>
0x0057949f:	popl %ecx
0x005794a0:	subl %ecx, %eax
0x005794a2:	xorl %eax, %eax
0x005794a4:	rorl %eax, %cl
0x005794a6:	xorl %eax, 0x60a440
0x005794ac:	movl (%esi), %eax
0x005794ae:	movl 0x4(%esi), %eax
0x005794b1:	movl 0x8(%esi), %eax
0x005794b4:	xorl %eax, %eax
0x005794b6:	popl %esi
0x005794b7:	popl %ebp
0x005794b8:	ret

0x005794f9:	movl (%esp), $0x615968<UINT32>
0x00579500:	call 0x0057947c
0x00579505:	popl %ecx
0x00579506:	movb %al, $0x1<UINT8>
0x00579508:	ret

0x005860f5:	cmpl %esi, 0xc(%ebp)
0x005860f8:	jne 4
0x005860fa:	movb %al, $0x1<UINT8>
0x005860fc:	jmp 0x0058612a
0x0058612a:	popl %ebx
0x0058612b:	popl %esi
0x0058612c:	movl %ecx, -4(%ebp)
0x0058612f:	xorl %ecx, %ebp
0x00586131:	popl %edi
0x00586132:	call 0x00559778
0x00586137:	movl %esp, %ebp
0x00586139:	popl %ebp
0x0058613a:	ret

0x005795dd:	popl %ecx
0x005795de:	popl %ecx
0x005795df:	ret

0x00559979:	testb %al, %al
0x0055997b:	jne 0x00559987
0x00559987:	movb %al, $0x1<UINT8>
0x00559989:	popl %ebp
0x0055998a:	ret

0x005595f7:	popl %ecx
0x005595f8:	testb %al, %al
0x005595fa:	je 330
0x00559600:	xorb %bl, %bl
0x00559602:	movb -25(%ebp), %bl
0x00559605:	andl -4(%ebp), $0x0<UINT8>
0x00559609:	call 0x00559920
0x00559920:	pushl %esi
0x00559921:	call 0x0055ac40
0x0055ac40:	xorl %eax, %eax
0x0055ac42:	cmpl 0x615ec4, %eax
0x0055ac48:	setne %al
0x0055ac4b:	ret

0x00559926:	testl %eax, %eax
0x00559928:	je 0x0055994a
0x0055994a:	xorb %al, %al
0x0055994c:	popl %esi
0x0055994d:	ret

0x0055960e:	movb -36(%ebp), %al
0x00559611:	movl %eax, 0x614fd8
0x00559616:	xorl %ecx, %ecx
0x00559618:	incl %ecx
0x00559619:	cmpl %eax, %ecx
0x0055961b:	je 297
0x00559621:	testl %eax, %eax
0x00559623:	jne 73
0x00559625:	movl 0x614fd8, %ecx
0x0055962b:	pushl $0x59fd9c<UINT32>
0x00559630:	pushl $0x59fd78<UINT32>
0x00559635:	call 0x00578c90
0x00578c90:	movl %edi, %edi
0x00578c92:	pushl %ebp
0x00578c93:	movl %ebp, %esp
0x00578c95:	pushl %ecx
0x00578c96:	movl %eax, 0x60a440
0x00578c9b:	xorl %eax, %ebp
0x00578c9d:	movl -4(%ebp), %eax
0x00578ca0:	pushl %esi
0x00578ca1:	movl %esi, 0x8(%ebp)
0x00578ca4:	pushl %edi
0x00578ca5:	jmp 0x00578cbe
0x00578cbe:	cmpl %esi, 0xc(%ebp)
0x00578cc1:	jne 0x00578ca7
0x00578ca7:	movl %edi, (%esi)
0x00578ca9:	testl %edi, %edi
0x00578cab:	je 0x00578cbb
0x00578cbb:	addl %esi, $0x4<UINT8>
0x00578cad:	movl %ecx, %edi
0x00578caf:	call 0x004047c0
0x00578cb5:	call 0xe8006a00
0x0055951f:	pushl %esi
0x00559520:	pushl $0x2<UINT8>
0x00559522:	call 0x00578424
0x00578424:	movl %edi, %edi
0x00578426:	pushl %ebp
0x00578427:	movl %ebp, %esp
0x00578429:	movl %eax, 0x8(%ebp)
0x0057842c:	movl 0x615720, %eax
0x00578431:	popl %ebp
0x00578432:	ret

0x00559527:	call 0x0055a998
0x0055a998:	movl %eax, $0x4000<UINT32>
0x0055a99d:	ret

0x0055952c:	pushl %eax
0x0055952d:	call 0x00578fad
0x00578fad:	movl %edi, %edi
0x00578faf:	pushl %ebp
0x00578fb0:	movl %ebp, %esp
0x00578fb2:	movl %eax, 0x8(%ebp)
0x00578fb5:	cmpl %eax, $0x4000<UINT32>
0x00578fba:	je 0x00578fdf
0x00578fdf:	movl %ecx, $0x615e9c<UINT32>
0x00578fe4:	xchgl (%ecx), %eax
0x00578fe6:	xorl %eax, %eax
0x00578fe8:	popl %ebp
0x00578fe9:	ret

0x00559532:	call 0x005790f0
0x005790f0:	movl %eax, $0x615958<UINT32>
0x005790f5:	ret

0x00559537:	movl %esi, %eax
0x00559539:	call 0x00405d20
0x00405d20:	xorl %eax, %eax
0x00405d22:	ret

0x0055953e:	pushl $0x1<UINT8>
0x00559540:	movl (%esi), %eax
0x00559542:	call 0x0055998b
0x0055998b:	pushl %ebp
0x0055998c:	movl %ebp, %esp
0x0055998e:	subl %esp, $0xc<UINT8>
0x00559991:	cmpb 0x614fe1, $0x0<UINT8>
0x00559998:	je 0x0055999e
0x0055999e:	pushl %esi
0x0055999f:	movl %esi, 0x8(%ebp)
0x005599a2:	testl %esi, %esi
0x005599a4:	je 5
0x005599a6:	cmpl %esi, $0x1<UINT8>
0x005599a9:	jne 125
0x005599ab:	call 0x0055ac40
0x005599b0:	testl %eax, %eax
0x005599b2:	je 0x005599da
0x005599da:	movl %eax, 0x60a440
0x005599df:	leal %esi, -12(%ebp)
0x005599e2:	pushl %edi
0x005599e3:	andl %eax, $0x1f<UINT8>
0x005599e6:	movl %edi, $0x614fe4<UINT32>
0x005599eb:	pushl $0x20<UINT8>
0x005599ed:	popl %ecx
0x005599ee:	subl %ecx, %eax
0x005599f0:	orl %eax, $0xffffffff<UINT8>
0x005599f3:	rorl %eax, %cl
0x005599f5:	xorl %eax, 0x60a440
0x005599fb:	movl -12(%ebp), %eax
0x005599fe:	movl -8(%ebp), %eax
0x00559a01:	movl -4(%ebp), %eax
0x00559a04:	movsl %es:(%edi), %ds:(%esi)
0x00559a05:	movsl %es:(%edi), %ds:(%esi)
0x00559a06:	movsl %es:(%edi), %ds:(%esi)
0x00559a07:	movl %edi, $0x614ff0<UINT32>
0x00559a0c:	movl -12(%ebp), %eax
0x00559a0f:	movl -8(%ebp), %eax
0x00559a12:	leal %esi, -12(%ebp)
0x00559a15:	movl -4(%ebp), %eax
0x00559a18:	movsl %es:(%edi), %ds:(%esi)
0x00559a19:	movsl %es:(%edi), %ds:(%esi)
0x00559a1a:	movsl %es:(%edi), %ds:(%esi)
0x00559a1b:	popl %edi
0x00559a1c:	movb 0x614fe1, $0x1<UINT8>
0x00559a23:	movb %al, $0x1<UINT8>
0x00559a25:	popl %esi
0x00559a26:	leave
0x00559a27:	ret

0x00559547:	addl %esp, $0xc<UINT8>
0x0055954a:	popl %esi
0x0055954b:	testb %al, %al
0x0055954d:	je 115
0x0055954f:	fnclex
0x00559551:	call 0x0055abe8
0x0055abe8:	pushl %ebx
0x0055abe9:	pushl %esi
0x0055abea:	movl %esi, $0x5f06ec<UINT32>
0x0055abef:	movl %ebx, $0x5f06ec<UINT32>
0x0055abf4:	cmpl %esi, %ebx
0x0055abf6:	jae 0x0055ac11
0x0055ac11:	popl %esi
0x0055ac12:	popl %ebx
0x0055ac13:	ret

0x00559556:	pushl $0x55ac14<UINT32>
0x0055955b:	call 0x00559b44
0x00559b44:	pushl %ebp
0x00559b45:	movl %ebp, %esp
0x00559b47:	pushl 0x8(%ebp)
0x00559b4a:	call 0x00559b09
0x00559b09:	pushl %ebp
0x00559b0a:	movl %ebp, %esp
0x00559b0c:	movl %eax, 0x60a440
0x00559b11:	movl %ecx, %eax
0x00559b13:	xorl %eax, 0x614fe4
0x00559b19:	andl %ecx, $0x1f<UINT8>
0x00559b1c:	pushl 0x8(%ebp)
0x00559b1f:	rorl %eax, %cl
0x00559b21:	cmpl %eax, $0xffffffff<UINT8>
0x00559b24:	jne 7
0x00559b26:	call 0x00579449
0x00579449:	movl %edi, %edi
0x0057944b:	pushl %ebp
0x0057944c:	movl %ebp, %esp
0x0057944e:	pushl 0x8(%ebp)
0x00579451:	pushl $0x61595c<UINT32>
0x00579456:	call 0x005794b9
0x005794b9:	movl %edi, %edi
0x005794bb:	pushl %ebp
0x005794bc:	movl %ebp, %esp
0x005794be:	pushl %ecx
0x005794bf:	pushl %ecx
0x005794c0:	leal %eax, 0x8(%ebp)
0x005794c3:	movl -8(%ebp), %eax
0x005794c6:	leal %eax, 0xc(%ebp)
0x005794c9:	movl -4(%ebp), %eax
0x005794cc:	leal %eax, -8(%ebp)
0x005794cf:	pushl %eax
0x005794d0:	pushl $0x2<UINT8>
0x005794d2:	call 0x005791c0
0x005791c0:	movl %edi, %edi
0x005791c2:	pushl %ebp
0x005791c3:	movl %ebp, %esp
0x005791c5:	subl %esp, $0xc<UINT8>
0x005791c8:	movl %eax, 0x8(%ebp)
0x005791cb:	leal %ecx, -1(%ebp)
0x005791ce:	movl -8(%ebp), %eax
0x005791d1:	movl -12(%ebp), %eax
0x005791d4:	leal %eax, -8(%ebp)
0x005791d7:	pushl %eax
0x005791d8:	pushl 0xc(%ebp)
0x005791db:	leal %eax, -12(%ebp)
0x005791de:	pushl %eax
0x005791df:	call 0x005790f6
0x005790f6:	pushl $0xc<UINT8>
0x005790f8:	pushl $0x604360<UINT32>
0x005790fd:	call 0x0055a840
0x00579102:	andl -28(%ebp), $0x0<UINT8>
0x00579106:	movl %eax, 0x8(%ebp)
0x00579109:	pushl (%eax)
0x0057910b:	call 0x00579dd1
0x00579110:	popl %ecx
0x00579111:	andl -4(%ebp), $0x0<UINT8>
0x00579115:	movl %ecx, 0xc(%ebp)
0x00579118:	call 0x00579308
0x00579308:	movl %edi, %edi
0x0057930a:	pushl %ebp
0x0057930b:	movl %ebp, %esp
0x0057930d:	subl %esp, $0xc<UINT8>
0x00579310:	movl %eax, %ecx
0x00579312:	movl -8(%ebp), %eax
0x00579315:	pushl %esi
0x00579316:	movl %eax, (%eax)
0x00579318:	movl %esi, (%eax)
0x0057931a:	testl %esi, %esi
0x0057931c:	jne 0x00579326
0x00579326:	movl %eax, 0x60a440
0x0057932b:	movl %ecx, %eax
0x0057932d:	pushl %ebx
0x0057932e:	movl %ebx, (%esi)
0x00579330:	andl %ecx, $0x1f<UINT8>
0x00579333:	pushl %edi
0x00579334:	movl %edi, 0x4(%esi)
0x00579337:	xorl %ebx, %eax
0x00579339:	movl %esi, 0x8(%esi)
0x0057933c:	xorl %edi, %eax
0x0057933e:	xorl %esi, %eax
0x00579340:	rorl %edi, %cl
0x00579342:	rorl %esi, %cl
0x00579344:	rorl %ebx, %cl
0x00579346:	cmpl %edi, %esi
0x00579348:	jne 0x00579402
0x0057934e:	subl %esi, %ebx
0x00579350:	movl %eax, $0x200<UINT32>
0x00579355:	sarl %esi, $0x2<UINT8>
0x00579358:	cmpl %esi, %eax
0x0057935a:	ja 2
0x0057935c:	movl %eax, %esi
0x0057935e:	leal %edi, (%eax,%esi)
0x00579361:	testl %edi, %edi
0x00579363:	jne 3
0x00579365:	pushl $0x20<UINT8>
0x00579367:	popl %edi
0x00579368:	cmpl %edi, %esi
0x0057936a:	jb 29
0x0057936c:	pushl $0x4<UINT8>
0x0057936e:	pushl %edi
0x0057936f:	pushl %ebx
0x00579370:	call 0x00579d18
0x00579d18:	movl %edi, %edi
0x00579d1a:	pushl %ebp
0x00579d1b:	movl %ebp, %esp
0x00579d1d:	popl %ebp
0x00579d1e:	jmp 0x00579d23
0x00579d23:	movl %edi, %edi
0x00579d25:	pushl %ebp
0x00579d26:	movl %ebp, %esp
0x00579d28:	pushl %esi
0x00579d29:	movl %esi, 0xc(%ebp)
0x00579d2c:	testl %esi, %esi
0x00579d2e:	je 27
0x00579d30:	pushl $0xffffffe0<UINT8>
0x00579d32:	xorl %edx, %edx
0x00579d34:	popl %eax
0x00579d35:	divl %eax, %esi
0x00579d37:	cmpl %eax, 0x10(%ebp)
0x00579d3a:	jae 0x00579d4b
0x00579d4b:	pushl %ebx
0x00579d4c:	movl %ebx, 0x8(%ebp)
0x00579d4f:	pushl %edi
0x00579d50:	testl %ebx, %ebx
0x00579d52:	je 0x00579d5f
0x00579d5f:	xorl %edi, %edi
0x00579d61:	imull %esi, 0x10(%ebp)
0x00579d65:	pushl %esi
0x00579d66:	pushl %ebx
0x00579d67:	call 0x00585036
0x00585036:	movl %edi, %edi
0x00585038:	pushl %ebp
0x00585039:	movl %ebp, %esp
0x0058503b:	pushl %edi
0x0058503c:	movl %edi, 0x8(%ebp)
0x0058503f:	testl %edi, %edi
0x00585041:	jne 11
0x00585043:	pushl 0xc(%ebp)
0x00585046:	call 0x0057aa2b
0x0058504b:	popl %ecx
0x0058504c:	jmp 0x00585072
0x00585072:	popl %edi
0x00585073:	popl %ebp
0x00585074:	ret

0x00579d6c:	movl %ebx, %eax
0x00579d6e:	popl %ecx
0x00579d6f:	popl %ecx
0x00579d70:	testl %ebx, %ebx
0x00579d72:	je 21
0x00579d74:	cmpl %edi, %esi
0x00579d76:	jae 17
0x00579d78:	subl %esi, %edi
0x00579d7a:	leal %eax, (%ebx,%edi)
0x00579d7d:	pushl %esi
0x00579d7e:	pushl $0x0<UINT8>
0x00579d80:	pushl %eax
0x00579d81:	call 0x0055cbe0
0x0055cc9d:	btl 0x60a460, $0x1<UINT8>
0x0055cca5:	jae 62
0x0055cca7:	movd %xmm0, %eax
0x0055ccab:	pshufd %xmm0, %xmm0, $0x0<UINT8>
0x00579d86:	addl %esp, $0xc<UINT8>
0x00579d89:	popl %edi
0x00579d8a:	movl %eax, %ebx
0x00579d8c:	popl %ebx
0x00579d8d:	popl %esi
0x00579d8e:	popl %ebp
0x00579d8f:	ret

0x00579375:	pushl $0x0<UINT8>
0x00579377:	movl -4(%ebp), %eax
0x0057937a:	call 0x0057a9f1
0x0057937f:	movl %ecx, -4(%ebp)
0x00579382:	addl %esp, $0x10<UINT8>
0x00579385:	testl %ecx, %ecx
0x00579387:	jne 0x005793b1
0x005793b1:	leal %eax, (%ecx,%esi,4)
0x005793b4:	movl %ebx, %ecx
0x005793b6:	movl -4(%ebp), %eax
0x005793b9:	leal %esi, (%ecx,%edi,4)
0x005793bc:	movl %eax, 0x60a440
0x005793c1:	movl %edi, -4(%ebp)
0x005793c4:	andl %eax, $0x1f<UINT8>
0x005793c7:	pushl $0x20<UINT8>
0x005793c9:	popl %ecx
0x005793ca:	subl %ecx, %eax
0x005793cc:	xorl %eax, %eax
0x005793ce:	rorl %eax, %cl
0x005793d0:	movl %ecx, %edi
0x005793d2:	xorl %eax, 0x60a440
0x005793d8:	movl -12(%ebp), %eax
0x005793db:	movl %eax, %esi
0x005793dd:	subl %eax, %edi
0x005793df:	addl %eax, $0x3<UINT8>
0x005793e2:	shrl %eax, $0x2<UINT8>
0x005793e5:	cmpl %esi, %edi
0x005793e7:	sbbl %edx, %edx
0x005793e9:	notl %edx
0x005793eb:	andl %edx, %eax
0x005793ed:	movl -4(%ebp), %edx
0x005793f0:	je 16
0x005793f2:	movl %edx, -12(%ebp)
0x005793f5:	xorl %eax, %eax
0x005793f7:	incl %eax
0x005793f8:	movl (%ecx), %edx
0x005793fa:	leal %ecx, 0x4(%ecx)
0x005793fd:	cmpl %eax, -4(%ebp)
0x00579400:	jne 0x005793f7
0x00579402:	movl %eax, -8(%ebp)
0x00579405:	movl %eax, 0x4(%eax)
0x00579408:	pushl (%eax)
0x0057940a:	call 0x00578433
0x00578433:	movl %edi, %edi
0x00578435:	pushl %ebp
0x00578436:	movl %ebp, %esp
0x00578438:	movl %eax, 0x60a440
0x0057843d:	andl %eax, $0x1f<UINT8>
0x00578440:	pushl $0x20<UINT8>
0x00578442:	popl %ecx
0x00578443:	subl %ecx, %eax
0x00578445:	movl %eax, 0x8(%ebp)
0x00578448:	rorl %eax, %cl
0x0057844a:	xorl %eax, 0x60a440
0x00578450:	popl %ebp
0x00578451:	ret

0x0057940f:	pushl %ebx
0x00579410:	movl (%edi), %eax
0x00579412:	call 0x005598bf
0x00579417:	movl %ebx, -8(%ebp)
0x0057941a:	movl %ecx, (%ebx)
0x0057941c:	movl %ecx, (%ecx)
0x0057941e:	movl (%ecx), %eax
0x00579420:	leal %eax, 0x4(%edi)
0x00579423:	pushl %eax
0x00579424:	call 0x005598bf
0x00579429:	movl %ecx, (%ebx)
0x0057942b:	pushl %esi
0x0057942c:	movl %ecx, (%ecx)
0x0057942e:	movl 0x4(%ecx), %eax
0x00579431:	call 0x005598bf
0x00579436:	movl %ecx, (%ebx)
0x00579438:	addl %esp, $0x10<UINT8>
0x0057943b:	movl %ecx, (%ecx)
0x0057943d:	movl 0x8(%ecx), %eax
0x00579440:	xorl %eax, %eax
0x00579442:	popl %edi
0x00579443:	popl %ebx
0x00579444:	popl %esi
0x00579445:	movl %esp, %ebp
0x00579447:	popl %ebp
0x00579448:	ret

0x0057911d:	movl %esi, %eax
0x0057911f:	movl -28(%ebp), %esi
0x00579122:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00579129:	call 0x0057913b
0x0057913b:	movl %eax, 0x10(%ebp)
0x0057913e:	pushl (%eax)
0x00579140:	call 0x00579e19
0x00579145:	popl %ecx
0x00579146:	ret

0x0057912e:	movl %eax, %esi
0x00579130:	call 0x0055a886
0x00579135:	ret $0xc<UINT16>

0x005791e4:	movl %esp, %ebp
0x005791e6:	popl %ebp
0x005791e7:	ret

0x005794d7:	popl %ecx
0x005794d8:	popl %ecx
0x005794d9:	movl %esp, %ebp
0x005794db:	popl %ebp
0x005794dc:	ret

0x0057945b:	popl %ecx
0x0057945c:	popl %ecx
0x0057945d:	popl %ebp
0x0057945e:	ret

0x00559b2b:	jmp 0x00559b38
0x00559b38:	negl %eax
0x00559b3a:	popl %ecx
0x00559b3b:	sbbl %eax, %eax
0x00559b3d:	notl %eax
0x00559b3f:	andl %eax, 0x8(%ebp)
0x00559b42:	popl %ebp
0x00559b43:	ret

0x00559b4f:	negl %eax
0x00559b51:	popl %ecx
0x00559b52:	sbbl %eax, %eax
0x00559b54:	negl %eax
0x00559b56:	decl %eax
0x00559b57:	popl %ebp
0x00559b58:	ret

0x00559560:	call 0x0042566c
0x0042566c:	xorl %eax, %eax
0x0042566e:	incl %eax
0x0042566f:	ret

0x00559565:	pushl %eax
0x00559566:	call 0x005787d7
0x005787d7:	movl %edi, %edi
0x005787d9:	pushl %ebp
0x005787da:	movl %ebp, %esp
0x005787dc:	popl %ebp
0x005787dd:	jmp 0x005784dd
0x005784dd:	movl %edi, %edi
0x005784df:	pushl %ebp
0x005784e0:	movl %ebp, %esp
0x005784e2:	subl %esp, $0xc<UINT8>
0x005784e5:	cmpl 0x8(%ebp), $0x2<UINT8>
0x005784e9:	pushl %esi
0x005784ea:	je 28
0x005784ec:	cmpl 0x8(%ebp), $0x1<UINT8>
0x005784f0:	je 0x00578508
0x00578508:	pushl %ebx
0x00578509:	pushl %edi
0x0057850a:	pushl $0x104<UINT32>
0x0057850f:	movl %esi, $0x615728<UINT32>
0x00578514:	xorl %edi, %edi
0x00578516:	pushl %esi
0x00578517:	pushl %edi
0x00578518:	call GetModuleFileNameW@KERNEL32.DLL
GetModuleFileNameW@KERNEL32.DLL: API Node	
0x0057851e:	movl %ebx, 0x615718
0x00578524:	movl 0x61571c, %esi
0x0057852a:	testl %ebx, %ebx
0x0057852c:	je 5
0x0057852e:	cmpw (%ebx), %di
0x00578531:	jne 0x00578535
0x00578535:	leal %eax, -12(%ebp)
0x00578538:	movl -4(%ebp), %edi
0x0057853b:	pushl %eax
0x0057853c:	leal %eax, -4(%ebp)
0x0057853f:	movl -12(%ebp), %edi
0x00578542:	pushl %eax
0x00578543:	pushl %edi
0x00578544:	pushl %edi
0x00578545:	pushl %ebx
0x00578546:	call 0x005785fc
0x005785fc:	movl %edi, %edi
0x005785fe:	pushl %ebp
0x005785ff:	movl %ebp, %esp
0x00578601:	movl %eax, 0x14(%ebp)
0x00578604:	subl %esp, $0x10<UINT8>
0x00578607:	movl %ecx, 0x8(%ebp)
0x0057860a:	movl %edx, 0x10(%ebp)
0x0057860d:	pushl %ebx
0x0057860e:	pushl %esi
0x0057860f:	movl %esi, 0xc(%ebp)
0x00578612:	xorl %ebx, %ebx
0x00578614:	pushl %edi
0x00578615:	movl %edi, 0x18(%ebp)
0x00578618:	movl (%edi), %ebx
0x0057861a:	movl (%eax), $0x1<UINT32>
0x00578620:	testl %esi, %esi
0x00578622:	je 0x0057862c
0x0057862c:	movl -8(%ebp), $0x20<UINT32>
0x00578633:	movl -12(%ebp), $0x9<UINT32>
0x0057863a:	pushl $0x22<UINT8>
0x0057863c:	popl %eax
0x0057863d:	cmpw (%ecx), %ax
0x00578640:	jne 0x0057864c
0x00578642:	testb %bl, %bl
0x00578644:	sete %bl
0x00578647:	addl %ecx, $0x2<UINT8>
0x0057864a:	jmp 0x00578666
0x00578666:	testb %bl, %bl
0x00578668:	jne 0x0057863a
0x0057864c:	incl (%edi)
0x0057864e:	testl %edx, %edx
0x00578650:	je 0x0057865b
0x0057865b:	movzwl %eax, (%ecx)
0x0057865e:	addl %ecx, $0x2<UINT8>
0x00578661:	testw %ax, %ax
0x00578664:	je 0x00578685
0x0057866a:	cmpw %ax, -8(%ebp)
0x0057866e:	je 9
0x00578670:	cmpw %ax, -12(%ebp)
0x00578674:	pushl $0x22<UINT8>
0x00578676:	popl %eax
0x00578677:	jne 0x0057863d
0x00578685:	subl %ecx, $0x2<UINT8>
0x00578688:	movl %ebx, 0x14(%ebp)
0x0057868b:	xorl %eax, %eax
0x0057868d:	movb -1(%ebp), %al
0x00578690:	cmpw (%ecx), %ax
0x00578693:	je 0x00578773
0x00578773:	testl %esi, %esi
0x00578775:	je 0x00578779
0x00578779:	incl (%ebx)
0x0057877b:	popl %edi
0x0057877c:	popl %esi
0x0057877d:	popl %ebx
0x0057877e:	movl %esp, %ebp
0x00578780:	popl %ebp
0x00578781:	ret

0x0057854b:	pushl $0x2<UINT8>
0x0057854d:	pushl -12(%ebp)
0x00578550:	pushl -4(%ebp)
0x00578553:	call 0x00578782
0x00578782:	movl %edi, %edi
0x00578784:	pushl %ebp
0x00578785:	movl %ebp, %esp
0x00578787:	pushl %esi
0x00578788:	movl %esi, 0x8(%ebp)
0x0057878b:	cmpl %esi, $0x3fffffff<UINT32>
0x00578791:	jb 0x00578797
0x00578797:	pushl %edi
0x00578798:	orl %edi, $0xffffffff<UINT8>
0x0057879b:	movl %ecx, 0xc(%ebp)
0x0057879e:	xorl %edx, %edx
0x005787a0:	movl %eax, %edi
0x005787a2:	divl %eax, 0x10(%ebp)
0x005787a5:	cmpl %ecx, %eax
0x005787a7:	jae 13
0x005787a9:	imull %ecx, 0x10(%ebp)
0x005787ad:	shll %esi, $0x2<UINT8>
0x005787b0:	subl %edi, %esi
0x005787b2:	cmpl %edi, %ecx
0x005787b4:	ja 0x005787ba
0x005787ba:	leal %eax, (%ecx,%esi)
0x005787bd:	pushl $0x1<UINT8>
0x005787bf:	pushl %eax
0x005787c0:	call 0x0057aa79
0x005787c5:	pushl $0x0<UINT8>
0x005787c7:	movl %esi, %eax
0x005787c9:	call 0x0057a9f1
0x005787ce:	addl %esp, $0xc<UINT8>
0x005787d1:	movl %eax, %esi
0x005787d3:	popl %edi
0x005787d4:	popl %esi
0x005787d5:	popl %ebp
0x005787d6:	ret

0x00578558:	movl %esi, %eax
0x0057855a:	addl %esp, $0x20<UINT8>
0x0057855d:	testl %esi, %esi
0x0057855f:	jne 0x0057856d
0x0057856d:	leal %eax, -12(%ebp)
0x00578570:	pushl %eax
0x00578571:	leal %eax, -4(%ebp)
0x00578574:	pushl %eax
0x00578575:	movl %eax, -4(%ebp)
0x00578578:	leal %eax, (%esi,%eax,4)
0x0057857b:	pushl %eax
0x0057857c:	pushl %esi
0x0057857d:	pushl %ebx
0x0057857e:	call 0x005785fc
0x00578624:	movl (%esi), %edx
0x00578626:	addl %esi, $0x4<UINT8>
0x00578629:	movl 0xc(%ebp), %esi
0x00578652:	movw %ax, (%ecx)
0x00578655:	movw (%edx), %ax
0x00578658:	addl %edx, $0x2<UINT8>
0x00578777:	movl (%esi), %eax
0x00578583:	addl %esp, $0x14<UINT8>
0x00578586:	cmpl 0x8(%ebp), $0x1<UINT8>
0x0057858a:	jne 22
0x0057858c:	movl %eax, -4(%ebp)
0x0057858f:	decl %eax
0x00578590:	movl 0x615708, %eax
0x00578595:	movl %eax, %esi
0x00578597:	movl %esi, %edi
0x00578599:	movl 0x615710, %eax
0x0057859e:	movl %ebx, %edi
0x005785a0:	jmp 0x005785ec
0x005785ec:	pushl %esi
0x005785ed:	call 0x0057a9f1
0x005785f2:	popl %ecx
0x005785f3:	popl %edi
0x005785f4:	movl %eax, %ebx
0x005785f6:	popl %ebx
0x005785f7:	popl %esi
0x005785f8:	movl %esp, %ebp
0x005785fa:	popl %ebp
0x005785fb:	ret

0x0055956b:	popl %ecx
0x0055956c:	popl %ecx
0x0055956d:	testl %eax, %eax
0x0055956f:	jne 81
0x00559571:	call 0x0055a99e
0x0055a99e:	pushl $0x615350<UINT32>
0x0055a9a3:	call InitializeSListHead@KERNEL32.DLL
InitializeSListHead@KERNEL32.DLL: API Node	
0x0055a9a9:	ret

0x00559576:	call 0x0055a9e8
0x0055a9e8:	xorl %eax, %eax
0x0055a9ea:	cmpl 0x60a470, %eax
0x0055a9f0:	sete %al
0x0055a9f3:	ret

0x0055957b:	testl %eax, %eax
0x0055957d:	je 0x0055958a
0x0055958a:	call 0x004047c0
0x0055958f:	call 0x004047c0
0x00559594:	call 0x0055a9aa
0x0055a9aa:	pushl $0x30000<UINT32>
0x0055a9af:	pushl $0x10000<UINT32>
0x0055a9b4:	pushl $0x0<UINT8>
0x0055a9b6:	call 0x00579cb9
0x00579cb9:	movl %edi, %edi
0x00579cbb:	pushl %ebp
0x00579cbc:	movl %ebp, %esp
0x00579cbe:	movl %ecx, 0x10(%ebp)
0x00579cc1:	movl %eax, 0xc(%ebp)
0x00579cc4:	andl %ecx, $0xfff7ffff<UINT32>
0x00579cca:	andl %eax, %ecx
0x00579ccc:	pushl %esi
0x00579ccd:	movl %esi, 0x8(%ebp)
0x00579cd0:	testl %eax, $0xfcf0fce0<UINT32>
0x00579cd5:	je 0x00579cfb
0x00579cfb:	pushl %ecx
0x00579cfc:	pushl 0xc(%ebp)
0x00579cff:	testl %esi, %esi
0x00579d01:	je 0x00579d0c
0x00579d0c:	call 0x005863bb
0x005863bb:	movl %edi, %edi
0x005863bd:	pushl %ebp
0x005863be:	movl %ebp, %esp
0x005863c0:	subl %esp, $0x10<UINT8>
0x005863c3:	fwait
0x005863c4:	fnstcw -8(%ebp)
0x005863c7:	movw %ax, -8(%ebp)
0x005863cb:	xorl %ecx, %ecx
0x005863cd:	testb %al, $0x1<UINT8>
0x005863cf:	je 0x005863d4
0x005863d4:	testb %al, $0x4<UINT8>
0x005863d6:	je 0x005863db
0x005863db:	testb %al, $0x8<UINT8>
0x005863dd:	je 3
0x005863df:	orl %ecx, $0x4<UINT8>
0x005863e2:	testb %al, $0x10<UINT8>
0x005863e4:	je 3
0x005863e6:	orl %ecx, $0x2<UINT8>
0x005863e9:	testb %al, $0x20<UINT8>
0x005863eb:	je 0x005863f0
0x005863f0:	testb %al, $0x2<UINT8>
0x005863f2:	je 0x005863fa
0x005863fa:	pushl %ebx
0x005863fb:	pushl %esi
0x005863fc:	movzwl %esi, %ax
0x005863ff:	movl %ebx, $0xc00<UINT32>
0x00586404:	movl %edx, %esi
0x00586406:	pushl %edi
0x00586407:	movl %edi, $0x200<UINT32>
0x0058640c:	andl %edx, %ebx
0x0058640e:	je 38
0x00586410:	cmpl %edx, $0x400<UINT32>
0x00586416:	je 24
0x00586418:	cmpl %edx, $0x800<UINT32>
0x0058641e:	je 12
0x00586420:	cmpl %edx, %ebx
0x00586422:	jne 18
0x00586424:	orl %ecx, $0x300<UINT32>
0x0058642a:	jmp 0x00586436
0x00586436:	andl %esi, $0x300<UINT32>
0x0058643c:	je 12
0x0058643e:	cmpl %esi, %edi
0x00586440:	jne 0x00586450
0x00586450:	movl %edx, $0x1000<UINT32>
0x00586455:	testw %dx, %ax
0x00586458:	je 6
0x0058645a:	orl %ecx, $0x40000<UINT32>
0x00586460:	movl %edi, 0xc(%ebp)
0x00586463:	movl %esi, %edi
0x00586465:	movl %eax, 0x8(%ebp)
0x00586468:	notl %esi
0x0058646a:	andl %esi, %ecx
0x0058646c:	andl %eax, %edi
0x0058646e:	orl %esi, %eax
0x00586470:	cmpl %esi, %ecx
0x00586472:	je 166
0x00586478:	pushl %esi
0x00586479:	call 0x005866bd
0x005866bd:	movl %edi, %edi
0x005866bf:	pushl %ebp
0x005866c0:	movl %ebp, %esp
0x005866c2:	movl %ecx, 0x8(%ebp)
0x005866c5:	xorl %eax, %eax
0x005866c7:	testb %cl, $0x10<UINT8>
0x005866ca:	je 0x005866cd
0x005866cd:	testb %cl, $0x8<UINT8>
0x005866d0:	je 0x005866d5
0x005866d5:	testb %cl, $0x4<UINT8>
0x005866d8:	je 3
0x005866da:	orl %eax, $0x8<UINT8>
0x005866dd:	testb %cl, $0x2<UINT8>
0x005866e0:	je 3
0x005866e2:	orl %eax, $0x10<UINT8>
0x005866e5:	testb %cl, $0x1<UINT8>
0x005866e8:	je 0x005866ed
0x005866ed:	testl %ecx, $0x80000<UINT32>
0x005866f3:	je 0x005866f8
0x005866f8:	pushl %esi
0x005866f9:	movl %edx, %ecx
0x005866fb:	movl %esi, $0x300<UINT32>
0x00586700:	pushl %edi
0x00586701:	movl %edi, $0x200<UINT32>
0x00586706:	andl %edx, %esi
0x00586708:	je 35
0x0058670a:	cmpl %edx, $0x100<UINT32>
0x00586710:	je 22
0x00586712:	cmpl %edx, %edi
0x00586714:	je 11
0x00586716:	cmpl %edx, %esi
0x00586718:	jne 19
0x0058671a:	orl %eax, $0xc00<UINT32>
0x0058671f:	jmp 0x0058672d
0x0058672d:	movl %edx, %ecx
0x0058672f:	andl %edx, $0x30000<UINT32>
0x00586735:	je 12
0x00586737:	cmpl %edx, $0x10000<UINT32>
0x0058673d:	jne 6
0x0058673f:	orl %eax, %edi
0x00586741:	jmp 0x00586745
0x00586745:	popl %edi
0x00586746:	popl %esi
0x00586747:	testl %ecx, $0x40000<UINT32>
0x0058674d:	je 5
0x0058674f:	orl %eax, $0x1000<UINT32>
0x00586754:	popl %ebp
0x00586755:	ret

0x0058647e:	popl %ecx
0x0058647f:	movw -4(%ebp), %ax
0x00586483:	fldcw -4(%ebp)
0x00586486:	fwait
0x00586487:	fnstcw -4(%ebp)
0x0058648a:	movw %ax, -4(%ebp)
0x0058648e:	xorl %esi, %esi
0x00586490:	testb %al, $0x1<UINT8>
0x00586492:	je 0x00586497
0x00586497:	testb %al, $0x4<UINT8>
0x00586499:	je 0x0058649e
0x0058649e:	testb %al, $0x8<UINT8>
0x005864a0:	je 3
0x005864a2:	orl %esi, $0x4<UINT8>
0x005864a5:	testb %al, $0x10<UINT8>
0x005864a7:	je 3
0x005864a9:	orl %esi, $0x2<UINT8>
0x005864ac:	testb %al, $0x20<UINT8>
0x005864ae:	je 0x005864b3
0x005864b3:	testb %al, $0x2<UINT8>
0x005864b5:	je 0x005864bd
0x005864bd:	movzwl %edx, %ax
0x005864c0:	movl %ecx, %edx
0x005864c2:	andl %ecx, %ebx
0x005864c4:	je 42
0x005864c6:	cmpl %ecx, $0x400<UINT32>
0x005864cc:	je 28
0x005864ce:	cmpl %ecx, $0x800<UINT32>
0x005864d4:	je 12
0x005864d6:	cmpl %ecx, %ebx
0x005864d8:	jne 22
0x005864da:	orl %esi, $0x300<UINT32>
0x005864e0:	jmp 0x005864f0
0x005864f0:	andl %edx, $0x300<UINT32>
0x005864f6:	je 16
0x005864f8:	cmpl %edx, $0x200<UINT32>
0x005864fe:	jne 14
0x00586500:	orl %esi, $0x10000<UINT32>
0x00586506:	jmp 0x0058650e
0x0058650e:	movl %edx, $0x1000<UINT32>
0x00586513:	testw %dx, %ax
0x00586516:	je 6
0x00586518:	orl %esi, $0x40000<UINT32>
0x0058651e:	cmpl 0x615028, $0x1<UINT8>
0x00586525:	jl 393
0x0058652b:	andl %edi, $0x308031f<UINT32>
0x00586531:	stmxcsr -16(%ebp)
0x00586535:	movl %eax, -16(%ebp)
0x00586538:	xorl %ecx, %ecx
0x0058653a:	testb %al, %al
0x0058653c:	jns 0x00586541
0x00586541:	testl %eax, $0x200<UINT32>
0x00586546:	je 3
0x00586548:	orl %ecx, $0x8<UINT8>
0x0058654b:	testl %eax, $0x400<UINT32>
0x00586550:	je 0x00586555
0x00586555:	testl %eax, $0x800<UINT32>
0x0058655a:	je 3
0x0058655c:	orl %ecx, $0x2<UINT8>
0x0058655f:	testl %edx, %eax
0x00586561:	je 0x00586566
0x00586566:	testl %eax, $0x100<UINT32>
0x0058656b:	je 6
0x0058656d:	orl %ecx, $0x80000<UINT32>
0x00586573:	movl %edx, %eax
0x00586575:	movl %ebx, $0x6000<UINT32>
0x0058657a:	andl %edx, %ebx
0x0058657c:	je 42
0x0058657e:	cmpl %edx, $0x2000<UINT32>
0x00586584:	je 0x005865a2
0x005865a2:	orl %ecx, $0x100<UINT32>
0x005865a8:	pushl $0x40<UINT8>
0x005865aa:	andl %eax, $0x8040<UINT32>
0x005865af:	popl %ebx
0x005865b0:	subl %eax, %ebx
0x005865b2:	je 0x005865cf
0x005865cf:	orl %ecx, $0x2000000<UINT32>
0x005865d5:	movl %eax, %edi
0x005865d7:	andl %edi, 0x8(%ebp)
0x005865da:	notl %eax
0x005865dc:	andl %eax, %ecx
0x005865de:	orl %eax, %edi
0x005865e0:	cmpl %eax, %ecx
0x005865e2:	je 0x0058669d
0x0058669d:	movl %eax, %ecx
0x0058669f:	orl %ecx, %esi
0x005866a1:	xorl %eax, %esi
0x005866a3:	testl %eax, $0x8031f<UINT32>
0x005866a8:	je 6
0x005866aa:	orl %ecx, $0x80000000<UINT32>
0x005866b0:	movl %eax, %ecx
0x005866b2:	jmp 0x005866b6
0x005866b6:	popl %edi
0x005866b7:	popl %esi
0x005866b8:	popl %ebx
0x005866b9:	movl %esp, %ebp
0x005866bb:	popl %ebp
0x005866bc:	ret

0x00579d11:	popl %ecx
0x00579d12:	popl %ecx
0x00579d13:	xorl %eax, %eax
0x00579d15:	popl %esi
0x00579d16:	popl %ebp
0x00579d17:	ret

0x0055a9bb:	addl %esp, $0xc<UINT8>
0x0055a9be:	testl %eax, %eax
0x0055a9c0:	jne 1
0x0055a9c2:	ret

0x00559599:	call 0x00405d20
0x0055959e:	pushl %eax
0x0055959f:	call 0x0056482b
0x0056482b:	movl %edi, %edi
0x0056482d:	pushl %ebp
0x0056482e:	movl %ebp, %esp
0x00564830:	pushl %esi
0x00564831:	call 0x0057a8a2
0x00564836:	movl %edx, 0x8(%ebp)
0x00564839:	movl %esi, %eax
0x0056483b:	pushl $0x0<UINT8>
0x0056483d:	popl %eax
0x0056483e:	movl %ecx, 0x350(%esi)
0x00564844:	testb %cl, $0x2<UINT8>
0x00564847:	sete %al
0x0056484a:	incl %eax
0x0056484b:	cmpl %edx, $0xffffffff<UINT8>
0x0056484e:	je 51
0x00564850:	testl %edx, %edx
0x00564852:	je 0x0056488a
0x0056488a:	popl %esi
0x0056488b:	popl %ebp
0x0056488c:	ret

0x005595a4:	popl %ecx
0x005595a5:	call 0x00424630
0x005595aa:	testb %al, %al
0x005595ac:	je 5
0x005595ae:	call 0x00578be9
0x00578be9:	jmp 0x0057886a
0x0057886a:	cmpl 0x615938, $0x0<UINT8>
0x00578871:	je 0x00578876
0x00578876:	pushl %esi
0x00578877:	pushl %edi
0x00578878:	call 0x00585d1d
0x00585d1d:	movl %edi, %edi
0x00585d1f:	pushl %esi
0x00585d20:	pushl %edi
0x00585d21:	call GetEnvironmentStringsW@KERNEL32.DLL
GetEnvironmentStringsW@KERNEL32.DLL: API Node	
0x00585d27:	movl %esi, %eax
0x00585d29:	testl %esi, %esi
0x00585d2b:	jne 0x00585d31
0x00585d31:	pushl %ebx
0x00585d32:	pushl %esi
0x00585d33:	call 0x00585c63
0x00585c63:	movl %edi, %edi
0x00585c65:	pushl %ebp
0x00585c66:	movl %ebp, %esp
0x00585c68:	movl %edx, 0x8(%ebp)
0x00585c6b:	pushl %edi
0x00585c6c:	xorl %edi, %edi
0x00585c6e:	cmpw (%edx), %di
0x00585c71:	je 33
0x00585c73:	pushl %esi
0x00585c74:	movl %ecx, %edx
0x00585c76:	leal %esi, 0x2(%ecx)
0x00585c79:	movw %ax, (%ecx)
0x00585c7c:	addl %ecx, $0x2<UINT8>
0x00585c7f:	cmpw %ax, %di
0x00585c82:	jne 0x00585c79
0x00585c84:	subl %ecx, %esi
0x00585c86:	sarl %ecx
0x00585c88:	leal %edx, (%edx,%ecx,2)
0x00585c8b:	addl %edx, $0x2<UINT8>
0x00585c8e:	cmpw (%edx), %di
0x00585c91:	jne 0x00585c74
0x00585c93:	popl %esi
0x00585c94:	leal %eax, 0x2(%edx)
0x00585c97:	popl %edi
0x00585c98:	popl %ebp
0x00585c99:	ret

0x00585d38:	subl %eax, %esi
0x00585d3a:	sarl %eax
0x00585d3c:	leal %ebx, (%eax,%eax)
0x00585d3f:	pushl %ebx
0x00585d40:	call 0x0057aa2b
0x00585d45:	movl %edi, %eax
0x00585d47:	popl %ecx
0x00585d48:	popl %ecx
0x00585d49:	testl %edi, %edi
0x00585d4b:	je 11
0x00585d4d:	pushl %ebx
0x00585d4e:	pushl %esi
0x00585d4f:	pushl %edi
0x00585d50:	call 0x0055c0e0
0x0055c0f8:	cmpl %edi, %eax
0x0055c0fa:	jb 660
0x0055c368:	movb %al, (%esi)
0x0055c36a:	movb (%edi), %al
0x0055c36c:	movb %al, 0x1(%esi)
0x0055c36f:	movb 0x1(%edi), %al
0x0055c372:	movl %eax, 0xc(%esp)
0x0055c376:	popl %esi
0x0055c377:	popl %edi
0x0055c378:	ret

0x00585d55:	addl %esp, $0xc<UINT8>
0x00585d58:	pushl $0x0<UINT8>
0x00585d5a:	call 0x0057a9f1
0x00585d5f:	popl %ecx
0x00585d60:	pushl %esi
0x00585d61:	call FreeEnvironmentStringsW@KERNEL32.DLL
FreeEnvironmentStringsW@KERNEL32.DLL: API Node	
0x00585d67:	popl %ebx
0x00585d68:	movl %eax, %edi
0x00585d6a:	popl %edi
0x00585d6b:	popl %esi
0x00585d6c:	ret

0x0057887d:	movl %esi, %eax
0x0057887f:	testl %esi, %esi
0x00578881:	jne 0x00578888
0x00578888:	pushl %esi
0x00578889:	call 0x0057898f
0x0057898f:	movl %edi, %edi
0x00578991:	pushl %ebp
0x00578992:	movl %ebp, %esp
0x00578994:	pushl %ecx
0x00578995:	pushl %ecx
0x00578996:	pushl %ebx
0x00578997:	movl %ebx, 0x8(%ebp)
0x0057899a:	xorl %eax, %eax
0x0057899c:	movl -8(%ebp), %eax
0x0057899f:	movl %edx, %eax
0x005789a1:	pushl %esi
0x005789a2:	pushl %edi
0x005789a3:	movzwl %eax, (%ebx)
0x005789a6:	movl %esi, %ebx
0x005789a8:	testw %ax, %ax
0x005789ab:	je 47
0x005789ad:	pushl $0x3d<UINT8>
0x005789af:	popl %ebx
0x005789b0:	cmpw %ax, %bx
0x005789b3:	je 0x005789b6
0x005789b6:	movl %ecx, %esi
0x005789b8:	leal %edi, 0x2(%ecx)
0x005789bb:	movw %ax, (%ecx)
0x005789be:	addl %ecx, $0x2<UINT8>
0x005789c1:	cmpw %ax, -8(%ebp)
0x005789c5:	jne 0x005789bb
0x005789c7:	subl %ecx, %edi
0x005789c9:	sarl %ecx
0x005789cb:	leal %esi, (%esi,%ecx,2)
0x005789ce:	addl %esi, $0x2<UINT8>
0x005789d1:	movzwl %eax, (%esi)
0x005789d4:	testw %ax, %ax
0x005789d7:	jne 0x005789b0
0x005789b5:	incl %edx
0x005789d9:	movl %ebx, 0x8(%ebp)
0x005789dc:	leal %eax, 0x1(%edx)
0x005789df:	pushl $0x4<UINT8>
0x005789e1:	pushl %eax
0x005789e2:	call 0x0057aa79
0x005789e7:	movl %edi, %eax
0x005789e9:	xorl %esi, %esi
0x005789eb:	popl %ecx
0x005789ec:	popl %ecx
0x005789ed:	testl %edi, %edi
0x005789ef:	je 121
0x005789f1:	movl -4(%ebp), %edi
0x005789f4:	jmp 0x00578a53
0x00578a53:	cmpw (%ebx), %si
0x00578a56:	jne 0x005789f6
0x005789f6:	movl %ecx, %ebx
0x005789f8:	leal %edx, 0x2(%ecx)
0x005789fb:	movw %ax, (%ecx)
0x005789fe:	addl %ecx, $0x2<UINT8>
0x00578a01:	cmpw %ax, %si
0x00578a04:	jne 0x005789fb
0x00578a06:	subl %ecx, %edx
0x00578a08:	sarl %ecx
0x00578a0a:	pushl $0x3d<UINT8>
0x00578a0c:	leal %eax, 0x1(%ecx)
0x00578a0f:	popl %ecx
0x00578a10:	movl -8(%ebp), %eax
0x00578a13:	cmpw (%ebx), %cx
0x00578a16:	je 0x00578a50
0x00578a50:	leal %ebx, (%ebx,%eax,2)
0x00578a18:	pushl $0x2<UINT8>
0x00578a1a:	pushl %eax
0x00578a1b:	call 0x0057aa79
0x00578a20:	movl %esi, %eax
0x00578a22:	popl %ecx
0x00578a23:	popl %ecx
0x00578a24:	testl %esi, %esi
0x00578a26:	je 50
0x00578a28:	pushl %ebx
0x00578a29:	pushl -8(%ebp)
0x00578a2c:	pushl %esi
0x00578a2d:	call 0x0056553e
0x0056553e:	movl %edi, %edi
0x00565540:	pushl %ebp
0x00565541:	movl %ebp, %esp
0x00565543:	movl %edx, 0x8(%ebp)
0x00565546:	pushl %esi
0x00565547:	testl %edx, %edx
0x00565549:	je 19
0x0056554b:	movl %ecx, 0xc(%ebp)
0x0056554e:	testl %ecx, %ecx
0x00565550:	je 12
0x00565552:	movl %esi, 0x10(%ebp)
0x00565555:	testl %esi, %esi
0x00565557:	jne 0x00565572
0x00565572:	pushl %edi
0x00565573:	movl %edi, %edx
0x00565575:	subl %esi, %edx
0x00565577:	movzwl %eax, (%esi,%edi)
0x0056557b:	movw (%edi), %ax
0x0056557e:	leal %edi, 0x2(%edi)
0x00565581:	testw %ax, %ax
0x00565584:	je 0x0056558b
0x00565586:	subl %ecx, $0x1<UINT8>
0x00565589:	jne 0x00565577
0x0056558b:	popl %edi
0x0056558c:	testl %ecx, %ecx
0x0056558e:	jne 0x0056559e
0x0056559e:	xorl %esi, %esi
0x005655a0:	jmp 0x0056556d
0x0056556d:	movl %eax, %esi
0x0056556f:	popl %esi
0x00565570:	popl %ebp
0x00565571:	ret

0x00578a32:	addl %esp, $0xc<UINT8>
0x00578a35:	testl %eax, %eax
0x00578a37:	jne 67
0x00578a39:	movl %eax, -4(%ebp)
0x00578a3c:	movl (%eax), %esi
0x00578a3e:	xorl %esi, %esi
0x00578a40:	addl %eax, $0x4<UINT8>
0x00578a43:	pushl %esi
0x00578a44:	movl -4(%ebp), %eax
0x00578a47:	call 0x0057a9f1
0x00578a4c:	movl %eax, -8(%ebp)
0x00578a4f:	popl %ecx
0x00578a58:	jmp 0x00578a6c
0x00578a6c:	pushl %esi
0x00578a6d:	call 0x0057a9f1
0x00578a72:	popl %ecx
0x00578a73:	movl %eax, %edi
0x00578a75:	popl %edi
0x00578a76:	popl %esi
0x00578a77:	popl %ebx
0x00578a78:	movl %esp, %ebp
0x00578a7a:	popl %ebp
0x00578a7b:	ret

0x0057888e:	popl %ecx
0x0057888f:	testl %eax, %eax
0x00578891:	jne 0x00578898
0x00578898:	pushl %eax
0x00578899:	movl %ecx, $0x615938<UINT32>
0x0057889e:	movl 0x61593c, %eax
0x005788a3:	call 0x005606bf
0x005788a8:	xorl %edi, %edi
0x005788aa:	pushl $0x0<UINT8>
0x005788ac:	call 0x0057a9f1
0x005788b1:	popl %ecx
0x005788b2:	pushl %esi
0x005788b3:	call 0x0057a9f1
0x0057a9fc:	pushl 0x8(%ebp)
0x0057a9ff:	pushl $0x0<UINT8>
0x0057aa01:	pushl 0x615e98
0x0057aa07:	call HeapFree@KERNEL32.DLL
HeapFree@KERNEL32.DLL: API Node	
0x0057aa0d:	testl %eax, %eax
0x0057aa0f:	jne 0x0057aa29
0x005788b8:	popl %ecx
0x005788b9:	movl %eax, %edi
0x005788bb:	popl %edi
0x005788bc:	popl %esi
0x005788bd:	ret

0x005595b3:	call 0x00405d20
0x005595b8:	call 0x0055ab4b
0x0055ab4b:	jmp 0x00405d20
0x005595bd:	testl %eax, %eax
0x005595bf:	jne 1
0x005595c1:	ret

0x00578cb7:	testl %eax, %eax
0x00578cb9:	jne 10
0x005595ca:	call 0x0055a9cb
0x0055a9cb:	call 0x004053db
0x004053db:	movl %eax, $0x611550<UINT32>
0x004053e0:	ret

0x0055a9d0:	movl %ecx, 0x4(%eax)
0x0055a9d3:	orl (%eax), $0x4<UINT8>
0x0055a9d6:	movl 0x4(%eax), %ecx
0x0055a9d9:	call 0x0043bf10
0x0043bf10:	movl %eax, $0x611a40<UINT32>
0x0043bf15:	ret

0x0055a9de:	movl %ecx, 0x4(%eax)
0x0055a9e1:	orl (%eax), $0x2<UINT8>
0x0055a9e4:	movl 0x4(%eax), %ecx
0x0055a9e7:	ret

0x005595cf:	xorl %eax, %eax
0x005595d1:	ret

0x00559b59:	call 0x00559b80
0x00559b80:	pushl %ebp
0x00559b81:	movl %ebp, %esp
0x00559b83:	pushl $0xffffffff<UINT8>
0x00559b85:	pushl $0x58cf50<UINT32>
0x00559b8a:	movl %eax, %fs:0
0x00559b90:	pushl %eax
0x00559b91:	pushl %ebx
0x00559b92:	pushl %esi
0x00559b93:	pushl %edi
0x00559b94:	movl %eax, 0x60a440
0x00559b99:	xorl %eax, %ebp
0x00559b9b:	pushl %eax
0x00559b9c:	leal %eax, -12(%ebp)
0x00559b9f:	movl %fs:0, %eax
0x00559ba5:	pushl $0xfa0<UINT32>
0x00559baa:	pushl $0x614ffc<UINT32>
0x00559baf:	call InitializeCriticalSectionAndSpinCount@KERNEL32.DLL
0x00559bb5:	pushl $0x5d0aa8<UINT32>
0x00559bba:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00559bc0:	movl %esi, %eax
0x00559bc2:	testl %esi, %esi
0x00559bc4:	jne 0x00559bdb
0x00559bdb:	pushl $0x5d0aec<UINT32>
0x00559be0:	pushl %esi
0x00559be1:	call GetProcAddress@KERNEL32.DLL
0x00559be7:	pushl $0x5d0b08<UINT32>
0x00559bec:	pushl %esi
0x00559bed:	movl %ebx, %eax
0x00559bef:	call GetProcAddress@KERNEL32.DLL
0x00559bf5:	pushl $0x5d0b24<UINT32>
0x00559bfa:	pushl %esi
0x00559bfb:	movl %edi, %eax
0x00559bfd:	call GetProcAddress@KERNEL32.DLL
0x00559c03:	movl %esi, %eax
0x00559c05:	testl %ebx, %ebx
0x00559c07:	je 56
0x00559c09:	testl %edi, %edi
0x00559c0b:	je 52
0x00559c0d:	testl %esi, %esi
0x00559c0f:	je 48
0x00559c11:	andl 0x615018, $0x0<UINT8>
0x00559c18:	movl %ecx, %ebx
0x00559c1a:	pushl $0x615014<UINT32>
0x00559c1f:	call 0x004047c0
0x00559c25:	call InitializeConditionVariable@api-ms-win-core-synch-l1-2-0.dll
InitializeConditionVariable@api-ms-win-core-synch-l1-2-0.dll: API Node	
0x00559c27:	pushl %edi
0x00559c28:	call 0x005598bf
0x00559c2d:	pushl %esi
0x00559c2e:	movl 0x61501c, %eax
0x00559c33:	call 0x005598bf
0x00559c38:	popl %ecx
0x00559c39:	popl %ecx
0x00559c3a:	movl 0x615020, %eax
0x00559c3f:	jmp 0x00559c57
0x00559c57:	movl %ecx, -12(%ebp)
0x00559c5a:	movl %fs:0, %ecx
0x00559c61:	popl %ecx
0x00559c62:	popl %edi
0x00559c63:	popl %esi
0x00559c64:	popl %ebx
0x00559c65:	leave
0x00559c66:	ret

0x00559b5e:	pushl $0x0<UINT8>
0x00559b60:	call 0x0055998b
0x0055999a:	movb %al, $0x1<UINT8>
0x0055999c:	leave
0x0055999d:	ret

0x00559b65:	popl %ecx
0x00559b66:	testb %al, %al
0x00559b68:	je 14
0x00559b6a:	pushl $0x559c6f<UINT32>
0x00559b6f:	call 0x00559b44
0x00559b74:	popl %ecx
0x00559b75:	xorl %eax, %eax
0x00559b77:	ret

0xe8006a00:	addb (%eax), %al
0x0055eed0:	pushl %ebp
0x0055eed1:	movl %ebp, %esp
0x0055eed3:	subl %esp, $0x1c<UINT8>
0x0055eed6:	pushl %ebx
0x0055eed7:	movl %ebx, 0xc(%ebp)
0x0055eeda:	pushl %esi
0x0055eedb:	pushl %edi
0x0055eedc:	movb -1(%ebp), $0x0<UINT8>
0x0055eee0:	movl %eax, 0x8(%ebx)
0x0055eee3:	leal %esi, 0x10(%ebx)
0x0055eee6:	xorl %eax, 0x60a440
0x0055eeec:	pushl %esi
0x0055eeed:	pushl %eax
0x0055eeee:	movl -12(%ebp), $0x1<UINT32>
0x0055eef5:	movl -16(%ebp), %esi
0x0055eef8:	movl -8(%ebp), %eax
0x0055eefb:	call 0x0055ee90
0x0055ee90:	pushl %ebp
0x0055ee91:	movl %ebp, %esp
0x0055ee93:	pushl %esi
0x0055ee94:	movl %esi, 0x8(%ebp)
0x0055ee97:	pushl %edi
0x0055ee98:	movl %edi, 0xc(%ebp)
0x0055ee9b:	movl %eax, (%esi)
0x0055ee9d:	cmpl %eax, $0xfffffffe<UINT8>
0x0055eea0:	je 0x0055eeaf
0x0055eeaf:	movl %eax, 0x8(%esi)
0x0055eeb2:	movl %ecx, 0xc(%esi)
0x0055eeb5:	addl %ecx, %edi
0x0055eeb7:	xorl %ecx, (%eax,%edi)
0x0055eeba:	popl %edi
0x0055eebb:	popl %esi
0x0055eebc:	popl %ebp
0x0055eebd:	jmp 0x00559778
0x0055ef00:	pushl 0x10(%ebp)
0x0055ef03:	call 0x0055ff3c
0x0055ff3c:	pushl %ebp
0x0055ff3d:	movl %ebp, %esp
0x0055ff3f:	movl %eax, 0x59fa78
0x0055ff44:	cmpl %eax, $0x4047c0<UINT32>
0x0055ff49:	je 0x0055ff6a
0x0055ff6a:	popl %ebp
0x0055ff6b:	ret

0x0055ef08:	movl %eax, 0x8(%ebp)
0x0055ef0b:	addl %esp, $0xc<UINT8>
0x0055ef0e:	movl %edi, 0xc(%ebx)
0x0055ef11:	testb 0x4(%eax), $0x66<UINT8>
0x0055ef15:	jne 95
0x0055ef17:	movl -28(%ebp), %eax
0x0055ef1a:	movl %eax, 0x10(%ebp)
0x0055ef1d:	movl -24(%ebp), %eax
0x0055ef20:	leal %eax, -28(%ebp)
0x0055ef23:	movl -4(%ebx), %eax
0x0055ef26:	cmpl %edi, $0xfffffffe<UINT8>
0x0055ef29:	je 110
0x0055ef2b:	jmp 0x0055ef30
0x0055ef30:	movl %ecx, -8(%ebp)
0x0055ef33:	leal %eax, 0x2(%edi)
0x0055ef36:	leal %eax, (%edi,%eax,2)
0x0055ef39:	movl %ebx, (%ecx,%eax,4)
0x0055ef3c:	leal %eax, (%ecx,%eax,4)
0x0055ef3f:	movl %ecx, 0x4(%eax)
0x0055ef42:	movl -20(%ebp), %eax
0x0055ef45:	testl %ecx, %ecx
0x0055ef47:	je 20
0x0055ef49:	movl %edx, %esi
0x0055ef4b:	call 0x005602b0
0x005602b0:	pushl %ebp
0x005602b1:	pushl %esi
0x005602b2:	pushl %edi
0x005602b3:	pushl %ebx
0x005602b4:	movl %ebp, %edx
0x005602b6:	xorl %eax, %eax
0x005602b8:	xorl %ebx, %ebx
0x005602ba:	xorl %edx, %edx
0x005602bc:	xorl %esi, %esi
0x005602be:	xorl %edi, %edi
0x005602c0:	call 0x00559705
0x00559705:	movl %ecx, -20(%ebp)
0x00559708:	movl %eax, (%ecx)
0x0055970a:	movl %eax, (%eax)
0x0055970c:	movl -32(%ebp), %eax
0x0055970f:	pushl %ecx
0x00559710:	pushl %eax
0x00559711:	call 0x005782ab
0x005782ab:	movl %edi, %edi
0x005782ad:	pushl %ebp
0x005782ae:	movl %ebp, %esp
0x005782b0:	pushl %ecx
0x005782b1:	pushl %ecx
0x005782b2:	movl %eax, 0x60a440
0x005782b7:	xorl %eax, %ebp
0x005782b9:	movl -4(%ebp), %eax
0x005782bc:	pushl %esi
0x005782bd:	call 0x0057a926
0x005782c2:	movl %esi, %eax
0x005782c4:	testl %esi, %esi
0x005782c6:	je 323
0x005782cc:	movl %edx, (%esi)
0x005782ce:	movl %ecx, %edx
0x005782d0:	pushl %ebx
0x005782d1:	xorl %ebx, %ebx
0x005782d3:	pushl %edi
0x005782d4:	leal %eax, 0x90(%edx)
0x005782da:	cmpl %edx, %eax
0x005782dc:	je 14
0x005782de:	movl %edi, 0x8(%ebp)
0x005782e1:	cmpl (%ecx), %edi
0x005782e3:	je 9
0x005782e5:	addl %ecx, $0xc<UINT8>
0x005782e8:	cmpl %ecx, %eax
0x005782ea:	jne 0x005782e1
0x005782ec:	movl %ecx, %ebx
0x005782ee:	testl %ecx, %ecx
0x005782f0:	je 0x005782f9
0x005782f9:	xorl %eax, %eax
0x005782fb:	jmp 0x0057840d
0x0057840d:	popl %edi
0x0057840e:	popl %ebx
0x0057840f:	movl %ecx, -4(%ebp)
0x00578412:	xorl %ecx, %ebp
0x00578414:	popl %esi
0x00578415:	call 0x00559778
0x0057841a:	movl %esp, %ebp
0x0057841c:	popl %ebp
0x0057841d:	ret

0x00559716:	popl %ecx
0x00559717:	popl %ecx
0x00559718:	ret

0x005602c2:	popl %ebx
0x005602c3:	popl %edi
0x005602c4:	popl %esi
0x005602c5:	popl %ebp
0x005602c6:	ret

0x0055ef50:	movb %cl, $0x1<UINT8>
0x0055ef52:	movb -1(%ebp), %cl
0x0055ef55:	testl %eax, %eax
0x0055ef57:	js 20
0x0055ef59:	jg 72
0x0055ef5b:	jmp 0x0055ef60
0x0055ef60:	movl %edi, %ebx
0x0055ef62:	cmpl %ebx, $0xfffffffe<UINT8>
0x0055ef65:	jne -55
0x0055ef67:	testb %cl, %cl
0x0055ef69:	je 46
0x0055ef6b:	jmp 0x0055ef8d
0x0055ef8d:	pushl %esi
0x0055ef8e:	pushl -8(%ebp)
0x0055ef91:	call 0x0055ee90
0x0055ef96:	addl %esp, $0x8<UINT8>
0x0055ef99:	movl %eax, -12(%ebp)
0x0055ef9c:	popl %edi
0x0055ef9d:	popl %esi
0x0055ef9e:	popl %ebx
0x0055ef9f:	movl %esp, %ebp
0x0055efa1:	popl %ebp
0x0055efa2:	ret

0xe8006a02:	addb (%eax), %al
0xe8006a04:	addb (%eax), %al
0xe8006a06:	addb (%eax), %al
0xe8006a08:	addb (%eax), %al
0xe8006a0a:	addb (%eax), %al
0xe8006a0c:	addb (%eax), %al
0xe8006a0e:	addb (%eax), %al
0xe8006a10:	addb (%eax), %al
0xe8006a12:	addb (%eax), %al
0xe8006a14:	addb (%eax), %al
0xe8006a16:	addb (%eax), %al
0xe8006a18:	addb (%eax), %al
0xe8006a1a:	addb (%eax), %al
0xe8006a1c:	addb (%eax), %al
0xe8006a1e:	addb (%eax), %al
0xe8006a20:	addb (%eax), %al
0xe8006a22:	addb (%eax), %al
0xe8006a24:	addb (%eax), %al
0xe8006a26:	addb (%eax), %al
0xe8006a28:	addb (%eax), %al
0xe8006a2a:	addb (%eax), %al
0xe8006a2c:	addb (%eax), %al
0xe8006a2e:	addb (%eax), %al
0xe8006a30:	addb (%eax), %al
0xe8006a32:	addb (%eax), %al
0xe8006a34:	addb (%eax), %al
0xe8006a36:	addb (%eax), %al
0xe8006a38:	addb (%eax), %al
0xe8006a3a:	addb (%eax), %al
0xe8006a3c:	addb (%eax), %al
0xe8006a3e:	addb (%eax), %al
0xe8006a40:	addb (%eax), %al
0xe8006a42:	addb (%eax), %al
0xe8006a44:	addb (%eax), %al
0xe8006a46:	addb (%eax), %al
0xe8006a48:	addb (%eax), %al
0xe8006a4a:	addb (%eax), %al
0xe8006a4c:	addb (%eax), %al
0xe8006a4e:	addb (%eax), %al
0xe8006a50:	addb (%eax), %al
0xe8006a52:	addb (%eax), %al
0xe8006a54:	addb (%eax), %al
0xe8006a56:	addb (%eax), %al
0xe8006a58:	addb (%eax), %al
0xe8006a5a:	addb (%eax), %al
0xe8006a5c:	addb (%eax), %al
0xe8006a5e:	addb (%eax), %al
0xe8006a60:	addb (%eax), %al
0xe8006a62:	addb (%eax), %al
0xe8006a64:	addb (%eax), %al
0x00584ee4:	je 0x00584f1e
0x00584f1e:	leal %edx, (%esi,%esi)
0x00584f21:	leal %ecx, 0x8(%edx)
0x00584f24:	cmpl %edx, %ecx
0x00584f26:	sbbl %eax, %eax
0x00584f28:	testl %ecx, %eax
0x00584f2a:	je 0x00584f76
0x00584f76:	xorl %edi, %edi
0x00584f78:	testl %edi, %edi
0x00584f7a:	je 0x00584fb4
0x00584fb4:	pushl %edi
0x00584fb5:	call 0x0055b99a
0x00584fba:	popl %ecx
0x00000000:	addb (%eax), %al
0x00000002:	addb (%eax), %al
0x00000004:	addb (%eax), %al
0x00000006:	addb (%eax), %al
0x00000008:	addb (%eax), %al
0x0000000a:	addb (%eax), %al
0x0000000c:	addb (%eax), %al
0x0000000e:	addb (%eax), %al
0x00000010:	addb (%eax), %al
0x00000012:	addb (%eax), %al
0x00000014:	addb (%eax), %al
0x00000016:	addb (%eax), %al
0x00000018:	addb (%eax), %al
0x0000001a:	addb (%eax), %al
0x0000001c:	addb (%eax), %al
0x0000001e:	addb (%eax), %al
0x00000020:	addb (%eax), %al
0x00000022:	addb (%eax), %al
0x00000024:	addb (%eax), %al
0x00000026:	addb (%eax), %al
0x00000028:	addb (%eax), %al
0x0000002a:	addb (%eax), %al
0x0000002c:	addb (%eax), %al
0x0000002e:	addb (%eax), %al
0x00000030:	addb (%eax), %al
0x00000032:	addb (%eax), %al
0x00000034:	addb (%eax), %al
0x00000036:	addb (%eax), %al
0x00000038:	addb (%eax), %al
0x0000003a:	addb (%eax), %al
0x0000003c:	addb (%eax), %al
0x0000003e:	addb (%eax), %al
0x00000040:	addb (%eax), %al
0x00000042:	addb (%eax), %al
0x00000044:	addb (%eax), %al
0x00000046:	addb (%eax), %al
0x00000048:	addb (%eax), %al
0x0000004a:	addb (%eax), %al
0x0000004c:	addb (%eax), %al
0x0000004e:	addb (%eax), %al
0x00000050:	addb (%eax), %al
0x00000052:	addb (%eax), %al
0x00000054:	addb (%eax), %al
0x00000056:	addb (%eax), %al
0x00000058:	addb (%eax), %al
0x0000005a:	addb (%eax), %al
0x0000005c:	addb (%eax), %al
0x0000005e:	addb (%eax), %al
0x00000060:	addb (%eax), %al
0x00000062:	addb (%eax), %al
0x00000064:	addb (%eax), %al
