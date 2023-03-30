0x004be000:	movl %ebx, $0x4001d0<UINT32>
0x004be005:	movl %edi, $0x401000<UINT32>
0x004be00a:	movl %esi, $0x48a0a6<UINT32>
0x004be00f:	pushl %ebx
0x004be010:	call 0x004be01f
0x004be01f:	cld
0x004be020:	movb %dl, $0xffffff80<UINT8>
0x004be022:	movsb %es:(%edi), %ds:(%esi)
0x004be023:	pushl $0x2<UINT8>
0x004be025:	popl %ebx
0x004be026:	call 0x004be015
0x004be015:	addb %dl, %dl
0x004be017:	jne 0x004be01e
0x004be019:	movb %dl, (%esi)
0x004be01b:	incl %esi
0x004be01c:	adcb %dl, %dl
0x004be01e:	ret

0x004be029:	jae 0x004be022
0x004be02b:	xorl %ecx, %ecx
0x004be02d:	call 0x004be015
0x004be030:	jae 0x004be04a
0x004be032:	xorl %eax, %eax
0x004be034:	call 0x004be015
0x004be037:	jae 0x004be05a
0x004be039:	movb %bl, $0x2<UINT8>
0x004be03b:	incl %ecx
0x004be03c:	movb %al, $0x10<UINT8>
0x004be03e:	call 0x004be015
0x004be041:	adcb %al, %al
0x004be043:	jae 0x004be03e
0x004be045:	jne 0x004be086
0x004be047:	stosb %es:(%edi), %al
0x004be048:	jmp 0x004be026
0x004be05a:	lodsb %al, %ds:(%esi)
0x004be05b:	shrl %eax
0x004be05d:	je 0x004be0a0
0x004be05f:	adcl %ecx, %ecx
0x004be061:	jmp 0x004be07f
0x004be07f:	incl %ecx
0x004be080:	incl %ecx
0x004be081:	xchgl %ebp, %eax
0x004be082:	movl %eax, %ebp
0x004be084:	movb %bl, $0x1<UINT8>
0x004be086:	pushl %esi
0x004be087:	movl %esi, %edi
0x004be089:	subl %esi, %eax
0x004be08b:	rep movsb %es:(%edi), %ds:(%esi)
0x004be08d:	popl %esi
0x004be08e:	jmp 0x004be026
0x004be04a:	call 0x004be092
0x004be092:	incl %ecx
0x004be093:	call 0x004be015
0x004be097:	adcl %ecx, %ecx
0x004be099:	call 0x004be015
0x004be09d:	jb 0x004be093
0x004be09f:	ret

0x004be04f:	subl %ecx, %ebx
0x004be051:	jne 0x004be063
0x004be053:	call 0x004be090
0x004be090:	xorl %ecx, %ecx
0x004be058:	jmp 0x004be082
0x004be063:	xchgl %ecx, %eax
0x004be064:	decl %eax
0x004be065:	shll %eax, $0x8<UINT8>
0x004be068:	lodsb %al, %ds:(%esi)
0x004be069:	call 0x004be090
0x004be06e:	cmpl %eax, $0x7d00<UINT32>
0x004be073:	jae 0x004be07f
0x004be075:	cmpb %ah, $0x5<UINT8>
0x004be078:	jae 0x004be080
0x004be07a:	cmpl %eax, $0x7f<UINT8>
0x004be07d:	ja 0x004be081
0x004be0a0:	popl %edi
0x004be0a1:	popl %ebx
0x004be0a2:	movzwl %edi, (%ebx)
0x004be0a5:	decl %edi
0x004be0a6:	je 0x004be0b0
0x004be0a8:	decl %edi
0x004be0a9:	je 0x004be0be
0x004be0ab:	shll %edi, $0xc<UINT8>
0x004be0ae:	jmp 0x004be0b7
0x004be0b7:	incl %ebx
0x004be0b8:	incl %ebx
0x004be0b9:	jmp 0x004be00f
0x004be0b0:	movl %edi, 0x2(%ebx)
0x004be0b3:	pushl %edi
0x004be0b4:	addl %ebx, $0x4<UINT8>
0x004be0be:	popl %edi
0x004be0bf:	movl %ebx, $0x4be128<UINT32>
0x004be0c4:	incl %edi
0x004be0c5:	movl %esi, (%edi)
0x004be0c7:	scasl %eax, %es:(%edi)
0x004be0c8:	pushl %edi
0x004be0c9:	call LoadLibraryA@KERNEL32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004be0cb:	xchgl %ebp, %eax
0x004be0cc:	xorl %eax, %eax
0x004be0ce:	scasb %al, %es:(%edi)
0x004be0cf:	jne 0x004be0ce
0x004be0d1:	decb (%edi)
0x004be0d3:	je 0x004be0c4
0x004be0d5:	decb (%edi)
0x004be0d7:	jne 0x004be0df
0x004be0d9:	incl %edi
0x004be0da:	pushl (%edi)
0x004be0dc:	scasl %eax, %es:(%edi)
0x004be0dd:	jmp 0x004be0e8
0x004be0e8:	pushl %ebp
0x004be0e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x004be0ec:	orl (%esi), %eax
0x004be0ee:	lodsl %eax, %ds:(%esi)
0x004be0ef:	jne 0x004be0cc
0x004be0df:	decb (%edi)
0x004be0e1:	je 0x00415757
0x004be0e7:	pushl %edi
GetProcAddress@KERNEL32.dll: API Node	
LoadLibraryA@KERNEL32.dll: API Node	
0x00415757:	call 0x00421820
0x00421820:	movl %edi, %edi
0x00421822:	pushl %ebp
0x00421823:	movl %ebp, %esp
0x00421825:	subl %esp, $0x10<UINT8>
0x00421828:	movl %eax, 0x43d68c
0x0042182d:	andl -8(%ebp), $0x0<UINT8>
0x00421831:	andl -4(%ebp), $0x0<UINT8>
0x00421835:	pushl %ebx
0x00421836:	pushl %edi
0x00421837:	movl %edi, $0xbb40e64e<UINT32>
0x0042183c:	movl %ebx, $0xffff0000<UINT32>
0x00421841:	cmpl %eax, %edi
0x00421843:	je 0x00421852
0x00421852:	pushl %esi
0x00421853:	leal %eax, -8(%ebp)
0x00421856:	pushl %eax
0x00421857:	call GetSystemTimeAsFileTime@KERNEL32.dll
GetSystemTimeAsFileTime@KERNEL32.dll: API Node	
0x0042185d:	movl %esi, -4(%ebp)
0x00421860:	xorl %esi, -8(%ebp)
0x00421863:	call GetCurrentProcessId@KERNEL32.dll
GetCurrentProcessId@KERNEL32.dll: API Node	
0x00421869:	xorl %esi, %eax
0x0042186b:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x00421871:	xorl %esi, %eax
0x00421873:	call GetTickCount@KERNEL32.dll
GetTickCount@KERNEL32.dll: API Node	
0x00421879:	xorl %esi, %eax
0x0042187b:	leal %eax, -16(%ebp)
0x0042187e:	pushl %eax
0x0042187f:	call QueryPerformanceCounter@KERNEL32.dll
QueryPerformanceCounter@KERNEL32.dll: API Node	
0x00421885:	movl %eax, -12(%ebp)
0x00421888:	xorl %eax, -16(%ebp)
0x0042188b:	xorl %esi, %eax
0x0042188d:	cmpl %esi, %edi
0x0042188f:	jne 0x00421898
0x00421898:	testl %ebx, %esi
0x0042189a:	jne 0x004218a3
0x004218a3:	movl 0x43d68c, %esi
0x004218a9:	notl %esi
0x004218ab:	movl 0x43d690, %esi
0x004218b1:	popl %esi
0x004218b2:	popl %edi
0x004218b3:	popl %ebx
0x004218b4:	leave
0x004218b5:	ret

0x0041575c:	jmp 0x004155d9
0x004155d9:	pushl $0x58<UINT8>
0x004155db:	pushl $0x43ac58<UINT32>
0x004155e0:	call 0x0041a9a0
0x0041a9a0:	pushl $0x412720<UINT32>
0x0041a9a5:	pushl %fs:0
0x0041a9ac:	movl %eax, 0x10(%esp)
0x0041a9b0:	movl 0x10(%esp), %ebp
0x0041a9b4:	leal %ebp, 0x10(%esp)
0x0041a9b8:	subl %esp, %eax
0x0041a9ba:	pushl %ebx
0x0041a9bb:	pushl %esi
0x0041a9bc:	pushl %edi
0x0041a9bd:	movl %eax, 0x43d68c
0x0041a9c2:	xorl -4(%ebp), %eax
0x0041a9c5:	xorl %eax, %ebp
0x0041a9c7:	pushl %eax
0x0041a9c8:	movl -24(%ebp), %esp
0x0041a9cb:	pushl -8(%ebp)
0x0041a9ce:	movl %eax, -4(%ebp)
0x0041a9d1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0041a9d8:	movl -8(%ebp), %eax
0x0041a9db:	leal %eax, -16(%ebp)
0x0041a9de:	movl %fs:0, %eax
0x0041a9e4:	ret

0x004155e5:	xorl %esi, %esi
0x004155e7:	movl -4(%ebp), %esi
0x004155ea:	leal %eax, -104(%ebp)
0x004155ed:	pushl %eax
0x004155ee:	call GetStartupInfoA@KERNEL32.dll
GetStartupInfoA@KERNEL32.dll: API Node	
0x004155f4:	pushl $0xfffffffe<UINT8>
0x004155f6:	popl %edi
0x004155f7:	movl -4(%ebp), %edi
0x004155fa:	movl %eax, $0x5a4d<UINT32>
0x004155ff:	cmpw 0x400000, %ax
0x00415606:	jne 56
0x00415608:	movl %eax, 0x40003c
0x0041560d:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00415617:	jne 39
0x00415619:	movl %ecx, $0x10b<UINT32>
0x0041561e:	cmpw 0x400018(%eax), %cx
0x00415625:	jne 25
0x00415627:	cmpl 0x400074(%eax), $0xe<UINT8>
0x0041562e:	jbe 16
0x00415630:	xorl %ecx, %ecx
0x00415632:	cmpl 0x4000e8(%eax), %esi
0x00415638:	setne %cl
0x0041563b:	movl -28(%ebp), %ecx
0x0041563e:	jmp 0x00415643
0x00415643:	xorl %ebx, %ebx
0x00415645:	incl %ebx
0x00415646:	pushl %ebx
0x00415647:	call 0x00419710
0x00419710:	movl %edi, %edi
0x00419712:	pushl %ebp
0x00419713:	movl %ebp, %esp
0x00419715:	xorl %eax, %eax
0x00419717:	cmpl 0x8(%ebp), %eax
0x0041971a:	pushl $0x0<UINT8>
0x0041971c:	sete %al
0x0041971f:	pushl $0x1000<UINT32>
0x00419724:	pushl %eax
0x00419725:	call HeapCreate@KERNEL32.dll
HeapCreate@KERNEL32.dll: API Node	
0x0041972b:	movl 0x447990, %eax
0x00419730:	testl %eax, %eax
0x00419732:	jne 0x00419736
0x00419736:	xorl %eax, %eax
0x00419738:	incl %eax
0x00419739:	movl 0x454894, %eax
0x0041973e:	popl %ebp
0x0041973f:	ret

0x0041564c:	popl %ecx
0x0041564d:	testl %eax, %eax
0x0041564f:	jne 0x00415659
0x00415659:	call 0x004190bd
0x004190bd:	movl %edi, %edi
0x004190bf:	pushl %esi
0x004190c0:	pushl %edi
0x004190c1:	movl %esi, $0x438fdc<UINT32>
0x004190c6:	pushl %esi
0x004190c7:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x004190cd:	testl %eax, %eax
0x004190cf:	jne 0x004190d8
0x004190d8:	movl %edi, %eax
0x004190da:	testl %edi, %edi
0x004190dc:	je 350
0x004190e2:	movl %esi, 0x4342d4
0x004190e8:	pushl $0x439028<UINT32>
0x004190ed:	pushl %edi
0x004190ee:	call GetProcAddress@KERNEL32.dll
0x004190f0:	pushl $0x43901c<UINT32>
0x004190f5:	pushl %edi
0x004190f6:	movl 0x44797c, %eax
0x004190fb:	call GetProcAddress@KERNEL32.dll
0x004190fd:	pushl $0x439010<UINT32>
0x00419102:	pushl %edi
0x00419103:	movl 0x447980, %eax
0x00419108:	call GetProcAddress@KERNEL32.dll
0x0041910a:	pushl $0x439008<UINT32>
0x0041910f:	pushl %edi
0x00419110:	movl 0x447984, %eax
0x00419115:	call GetProcAddress@KERNEL32.dll
0x00419117:	cmpl 0x44797c, $0x0<UINT8>
0x0041911e:	movl %esi, 0x434200
0x00419124:	movl 0x447988, %eax
0x00419129:	je 22
0x0041912b:	cmpl 0x447980, $0x0<UINT8>
0x00419132:	je 13
0x00419134:	cmpl 0x447984, $0x0<UINT8>
0x0041913b:	je 4
0x0041913d:	testl %eax, %eax
0x0041913f:	jne 0x00419165
0x00419165:	call TlsAlloc@KERNEL32.dll
TlsAlloc@KERNEL32.dll: API Node	
0x0041916b:	movl 0x43de4c, %eax
0x00419170:	cmpl %eax, $0xffffffff<UINT8>
0x00419173:	je 204
0x00419179:	pushl 0x447980
0x0041917f:	pushl %eax
0x00419180:	call TlsSetValue@KERNEL32.dll
TlsSetValue@KERNEL32.dll: API Node	
0x00419182:	testl %eax, %eax
0x00419184:	je 187
0x0041918a:	call 0x0041ad5b
0x0041ad5b:	movl %edi, %edi
0x0041ad5d:	pushl %esi
0x0041ad5e:	call 0x00418c68
0x00418c68:	pushl $0x0<UINT8>
0x00418c6a:	call 0x00418bf6
0x00418bf6:	movl %edi, %edi
0x00418bf8:	pushl %ebp
0x00418bf9:	movl %ebp, %esp
0x00418bfb:	pushl %esi
0x00418bfc:	pushl 0x43de4c
0x00418c02:	movl %esi, 0x434208
0x00418c08:	call TlsGetValue@KERNEL32.dll
TlsGetValue@KERNEL32.dll: API Node	
0x00418c0a:	testl %eax, %eax
0x00418c0c:	je 33
0x00418c0e:	movl %eax, 0x43de48
0x00418c13:	cmpl %eax, $0xffffffff<UINT8>
0x00418c16:	je 0x00418c2f
0x00418c2f:	movl %esi, $0x438fdc<UINT32>
0x00418c34:	pushl %esi
0x00418c35:	call GetModuleHandleW@KERNEL32.dll
0x00418c3b:	testl %eax, %eax
0x00418c3d:	jne 0x00418c4a
0x00418c4a:	pushl $0x438fcc<UINT32>
0x00418c4f:	pushl %eax
0x00418c50:	call GetProcAddress@KERNEL32.dll
0x00418c56:	testl %eax, %eax
0x00418c58:	je 8
0x00418c5a:	pushl 0x8(%ebp)
0x00418c5d:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00418c5f:	movl 0x8(%ebp), %eax
0x00418c62:	movl %eax, 0x8(%ebp)
0x00418c65:	popl %esi
0x00418c66:	popl %ebp
0x00418c67:	ret

0x00418c6f:	popl %ecx
0x00418c70:	ret

0x0041ad63:	movl %esi, %eax
0x0041ad65:	pushl %esi
0x0041ad66:	call 0x0041afb3
0x0041afb3:	movl %edi, %edi
0x0041afb5:	pushl %ebp
0x0041afb6:	movl %ebp, %esp
0x0041afb8:	movl %eax, 0x8(%ebp)
0x0041afbb:	movl 0x447e34, %eax
0x0041afc0:	popl %ebp
0x0041afc1:	ret

0x0041ad6b:	pushl %esi
0x0041ad6c:	call 0x00429ccd
0x00429ccd:	movl %edi, %edi
0x00429ccf:	pushl %ebp
0x00429cd0:	movl %ebp, %esp
0x00429cd2:	movl %eax, 0x8(%ebp)
0x00429cd5:	movl 0x447f68, %eax
0x00429cda:	popl %ebp
0x00429cdb:	ret

0x0041ad71:	pushl %esi
0x0041ad72:	call 0x0041653d
0x0041653d:	movl %edi, %edi
0x0041653f:	pushl %ebp
0x00416540:	movl %ebp, %esp
0x00416542:	movl %eax, 0x8(%ebp)
0x00416545:	movl 0x447614, %eax
0x0041654a:	popl %ebp
0x0041654b:	ret

0x0041ad77:	pushl %esi
0x0041ad78:	call 0x0042aa0a
0x0042aa0a:	movl %edi, %edi
0x0042aa0c:	pushl %ebp
0x0042aa0d:	movl %ebp, %esp
0x0042aa0f:	movl %eax, 0x8(%ebp)
0x0042aa12:	movl 0x447f90, %eax
0x0042aa17:	popl %ebp
0x0042aa18:	ret

0x0041ad7d:	pushl %esi
0x0041ad7e:	call 0x0042a774
0x0042a774:	movl %edi, %edi
0x0042a776:	pushl %ebp
0x0042a777:	movl %ebp, %esp
0x0042a779:	movl %eax, 0x8(%ebp)
0x0042a77c:	movl 0x447f84, %eax
0x0042a781:	popl %ebp
0x0042a782:	ret

0x0041ad83:	pushl %esi
0x0041ad84:	call 0x0042a278
0x0042a278:	movl %edi, %edi
0x0042a27a:	pushl %ebp
0x0042a27b:	movl %ebp, %esp
0x0042a27d:	movl %eax, 0x8(%ebp)
0x0042a280:	movl 0x447f70, %eax
0x0042a285:	movl 0x447f74, %eax
0x0042a28a:	movl 0x447f78, %eax
0x0042a28f:	movl 0x447f7c, %eax
0x0042a294:	popl %ebp
0x0042a295:	ret

0x0041ad89:	pushl %esi
0x0041ad8a:	call 0x0041c01f
0x0041c01f:	ret

0x0041ad8f:	pushl %esi
0x0041ad90:	call 0x0042a267
0x0042a267:	pushl $0x42a1e3<UINT32>
0x0042a26c:	call 0x00418bf6
0x0042a271:	popl %ecx
0x0042a272:	movl 0x447f6c, %eax
0x0042a277:	ret

0x0041ad95:	pushl $0x41ad27<UINT32>
0x0041ad9a:	call 0x00418bf6
0x0041ad9f:	addl %esp, $0x24<UINT8>
0x0041ada2:	movl 0x43df78, %eax
0x0041ada7:	popl %esi
0x0041ada8:	ret

0x0041918f:	pushl 0x44797c
0x00419195:	call 0x00418bf6
0x0041919a:	pushl 0x447980
0x004191a0:	movl 0x44797c, %eax
0x004191a5:	call 0x00418bf6
0x004191aa:	pushl 0x447984
0x004191b0:	movl 0x447980, %eax
0x004191b5:	call 0x00418bf6
0x004191ba:	pushl 0x447988
0x004191c0:	movl 0x447984, %eax
0x004191c5:	call 0x00418bf6
0x004191ca:	addl %esp, $0x10<UINT8>
0x004191cd:	movl 0x447988, %eax
0x004191d2:	call 0x004197ba
0x004197ba:	movl %edi, %edi
0x004197bc:	pushl %esi
0x004197bd:	pushl %edi
0x004197be:	xorl %esi, %esi
0x004197c0:	movl %edi, $0x447998<UINT32>
0x004197c5:	cmpl 0x43de5c(,%esi,8), $0x1<UINT8>
0x004197cd:	jne 0x004197ed
0x004197cf:	leal %eax, 0x43de58(,%esi,8)
0x004197d6:	movl (%eax), %edi
0x004197d8:	pushl $0xfa0<UINT32>
0x004197dd:	pushl (%eax)
0x004197df:	addl %edi, $0x18<UINT8>
0x004197e2:	call 0x00429cdc
0x00429cdc:	pushl $0x10<UINT8>
0x00429cde:	pushl $0x43af98<UINT32>
0x00429ce3:	call 0x0041a9a0
0x00429ce8:	andl -4(%ebp), $0x0<UINT8>
0x00429cec:	pushl 0xc(%ebp)
0x00429cef:	pushl 0x8(%ebp)
0x00429cf2:	call InitializeCriticalSectionAndSpinCount@KERNEL32.dll
InitializeCriticalSectionAndSpinCount@KERNEL32.dll: API Node	
0x00429cf8:	movl -28(%ebp), %eax
0x00429cfb:	jmp 0x00429d2c
0x00429d2c:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00429d33:	movl %eax, -28(%ebp)
0x00429d36:	call 0x0041a9e5
0x0041a9e5:	movl %ecx, -16(%ebp)
0x0041a9e8:	movl %fs:0, %ecx
0x0041a9ef:	popl %ecx
0x0041a9f0:	popl %edi
0x0041a9f1:	popl %edi
0x0041a9f2:	popl %esi
0x0041a9f3:	popl %ebx
0x0041a9f4:	movl %esp, %ebp
0x0041a9f6:	popl %ebp
0x0041a9f7:	pushl %ecx
0x0041a9f8:	ret

0x00429d3b:	ret

0x004197e7:	popl %ecx
0x004197e8:	popl %ecx
0x004197e9:	testl %eax, %eax
0x004197eb:	je 12
0x004197ed:	incl %esi
0x004197ee:	cmpl %esi, $0x24<UINT8>
0x004197f1:	jl 0x004197c5
0x004197f3:	xorl %eax, %eax
0x004197f5:	incl %eax
0x004197f6:	popl %edi
0x004197f7:	popl %esi
0x004197f8:	ret

0x004191d7:	testl %eax, %eax
0x004191d9:	je 101
0x004191db:	pushl $0x418f14<UINT32>
0x004191e0:	pushl 0x44797c
0x004191e6:	call 0x00418c71
0x00418c71:	movl %edi, %edi
0x00418c73:	pushl %ebp
0x00418c74:	movl %ebp, %esp
0x00418c76:	pushl %esi
0x00418c77:	pushl 0x43de4c
0x00418c7d:	movl %esi, 0x434208
0x00418c83:	call TlsGetValue@KERNEL32.dll
0x00418c85:	testl %eax, %eax
0x00418c87:	je 33
0x00418c89:	movl %eax, 0x43de48
0x00418c8e:	cmpl %eax, $0xffffffff<UINT8>
0x00418c91:	je 0x00418caa
0x00418caa:	movl %esi, $0x438fdc<UINT32>
0x00418caf:	pushl %esi
0x00418cb0:	call GetModuleHandleW@KERNEL32.dll
0x00418cb6:	testl %eax, %eax
0x00418cb8:	jne 0x00418cc5
0x00418cc5:	pushl $0x438ff8<UINT32>
0x00418cca:	pushl %eax
0x00418ccb:	call GetProcAddress@KERNEL32.dll
0x00418cd1:	testl %eax, %eax
0x00418cd3:	je 8
0x00418cd5:	pushl 0x8(%ebp)
0x00418cd8:	call DecodePointer@KERNEL32.DLL
DecodePointer@KERNEL32.DLL: API Node	
0x00418cda:	movl 0x8(%ebp), %eax
0x00418cdd:	movl %eax, 0x8(%ebp)
0x00418ce0:	popl %esi
0x00418ce1:	popl %ebp
0x00418ce2:	ret

0x004191eb:	popl %ecx
0x004191ec:	call FlsAlloc@KERNEL32.DLL
FlsAlloc@KERNEL32.DLL: API Node	
0x004191ee:	movl 0x43de48, %eax
0x004191f3:	cmpl %eax, $0xffffffff<UINT8>
0x004191f6:	je 72
0x004191f8:	pushl $0x214<UINT32>
0x004191fd:	pushl $0x1<UINT8>
0x004191ff:	call 0x0041c255
0x0041c255:	movl %edi, %edi
0x0041c257:	pushl %ebp
0x0041c258:	movl %ebp, %esp
0x0041c25a:	pushl %esi
0x0041c25b:	pushl %edi
0x0041c25c:	xorl %esi, %esi
0x0041c25e:	pushl $0x0<UINT8>
0x0041c260:	pushl 0xc(%ebp)
0x0041c263:	pushl 0x8(%ebp)
0x0041c266:	call 0x0042be32
0x0042be32:	pushl $0xc<UINT8>
0x0042be34:	pushl $0x43b140<UINT32>
0x0042be39:	call 0x0041a9a0
0x0042be3e:	movl %ecx, 0x8(%ebp)
0x0042be41:	xorl %edi, %edi
0x0042be43:	cmpl %ecx, %edi
0x0042be45:	jbe 46
0x0042be47:	pushl $0xffffffe0<UINT8>
0x0042be49:	popl %eax
0x0042be4a:	xorl %edx, %edx
0x0042be4c:	divl %eax, %ecx
0x0042be4e:	cmpl %eax, 0xc(%ebp)
0x0042be51:	sbbl %eax, %eax
0x0042be53:	incl %eax
0x0042be54:	jne 0x0042be75
0x0042be75:	imull %ecx, 0xc(%ebp)
0x0042be79:	movl %esi, %ecx
0x0042be7b:	movl 0x8(%ebp), %esi
0x0042be7e:	cmpl %esi, %edi
0x0042be80:	jne 0x0042be85
0x0042be85:	xorl %ebx, %ebx
0x0042be87:	movl -28(%ebp), %ebx
0x0042be8a:	cmpl %esi, $0xffffffe0<UINT8>
0x0042be8d:	ja 105
0x0042be8f:	cmpl 0x454894, $0x3<UINT8>
0x0042be96:	jne 0x0042bee3
0x0042bee3:	cmpl %ebx, %edi
0x0042bee5:	jne 97
0x0042bee7:	pushl %esi
0x0042bee8:	pushl $0x8<UINT8>
0x0042beea:	pushl 0x447990
0x0042bef0:	call HeapAlloc@KERNEL32.dll
HeapAlloc@KERNEL32.dll: API Node	
0x0042bef6:	movl %ebx, %eax
0x0042bef8:	cmpl %ebx, %edi
0x0042befa:	jne 0x0042bf48
0x0042bf48:	movl %eax, %ebx
0x0042bf4a:	call 0x0041a9e5
0x0042bf4f:	ret

0x0041c26b:	movl %edi, %eax
0x0041c26d:	addl %esp, $0xc<UINT8>
0x0041c270:	testl %edi, %edi
0x0041c272:	jne 0x0041c29b
0x0041c29b:	movl %eax, %edi
0x0041c29d:	popl %edi
0x0041c29e:	popl %esi
0x0041c29f:	popl %ebp
0x0041c2a0:	ret

0x00419204:	movl %esi, %eax
0x00419206:	popl %ecx
0x00419207:	popl %ecx
0x00419208:	testl %esi, %esi
0x0041920a:	je 52
0x0041920c:	pushl %esi
0x0041920d:	pushl 0x43de48
0x00419213:	pushl 0x447984
0x00419219:	call 0x00418c71
0x00418c93:	pushl %eax
0x00418c94:	pushl 0x43de4c
0x00418c9a:	call TlsGetValue@KERNEL32.dll
0x00418c9c:	call FlsGetValue@KERNEL32.DLL
FlsGetValue@KERNEL32.DLL: API Node	
0x00418c9e:	testl %eax, %eax
0x00418ca0:	je 0x00418caa
0x0041921e:	popl %ecx
0x0041921f:	call FlsSetValue@KERNEL32.DLL
FlsSetValue@KERNEL32.DLL: API Node	
0x00419221:	testl %eax, %eax
0x00419223:	je 27
0x00419225:	pushl $0x0<UINT8>
0x00419227:	pushl %esi
0x00419228:	call 0x00418d9a
0x00418d9a:	pushl $0xc<UINT8>
0x00418d9c:	pushl $0x43ada8<UINT32>
0x00418da1:	call 0x0041a9a0
0x00418da6:	movl %esi, $0x438fdc<UINT32>
0x00418dab:	pushl %esi
0x00418dac:	call GetModuleHandleW@KERNEL32.dll
0x00418db2:	testl %eax, %eax
0x00418db4:	jne 0x00418dbd
0x00418dbd:	movl -28(%ebp), %eax
0x00418dc0:	movl %esi, 0x8(%ebp)
0x00418dc3:	movl 0x5c(%esi), $0x439640<UINT32>
0x00418dca:	xorl %edi, %edi
0x00418dcc:	incl %edi
0x00418dcd:	movl 0x14(%esi), %edi
0x00418dd0:	testl %eax, %eax
0x00418dd2:	je 36
0x00418dd4:	pushl $0x438fcc<UINT32>
0x00418dd9:	pushl %eax
0x00418dda:	movl %ebx, 0x4342d4
0x00418de0:	call GetProcAddress@KERNEL32.dll
0x00418de2:	movl 0x1f8(%esi), %eax
0x00418de8:	pushl $0x438ff8<UINT32>
0x00418ded:	pushl -28(%ebp)
0x00418df0:	call GetProcAddress@KERNEL32.dll
0x00418df2:	movl 0x1fc(%esi), %eax
0x00418df8:	movl 0x70(%esi), %edi
0x00418dfb:	movb 0xc8(%esi), $0x43<UINT8>
0x00418e02:	movb 0x14b(%esi), $0x43<UINT8>
0x00418e09:	movl 0x68(%esi), $0x43d830<UINT32>
0x00418e10:	pushl $0xd<UINT8>
0x00418e12:	call 0x0041994e
0x0041994e:	movl %edi, %edi
0x00419950:	pushl %ebp
0x00419951:	movl %ebp, %esp
0x00419953:	movl %eax, 0x8(%ebp)
0x00419956:	pushl %esi
0x00419957:	leal %esi, 0x43de58(,%eax,8)
0x0041995e:	cmpl (%esi), $0x0<UINT8>
0x00419961:	jne 0x00419976
0x00419976:	pushl (%esi)
0x00419978:	call EnterCriticalSection@KERNEL32.dll
EnterCriticalSection@KERNEL32.dll: API Node	
0x0041997e:	popl %esi
0x0041997f:	popl %ebp
0x00419980:	ret

0x00418e17:	popl %ecx
0x00418e18:	andl -4(%ebp), $0x0<UINT8>
0x00418e1c:	pushl 0x68(%esi)
0x00418e1f:	call InterlockedIncrement@KERNEL32.dll
InterlockedIncrement@KERNEL32.dll: API Node	
0x00418e25:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00418e2c:	call 0x00418e6f
0x00418e6f:	pushl $0xd<UINT8>
0x00418e71:	call 0x0041985c
0x0041985c:	movl %edi, %edi
0x0041985e:	pushl %ebp
0x0041985f:	movl %ebp, %esp
0x00419861:	movl %eax, 0x8(%ebp)
0x00419864:	pushl 0x43de58(,%eax,8)
0x0041986b:	call LeaveCriticalSection@KERNEL32.dll
LeaveCriticalSection@KERNEL32.dll: API Node	
0x00419871:	popl %ebp
0x00419872:	ret

0x00418e76:	popl %ecx
0x00418e77:	ret

0x00418e31:	pushl $0xc<UINT8>
0x00418e33:	call 0x0041994e
0x00418e38:	popl %ecx
0x00418e39:	movl -4(%ebp), %edi
0x00418e3c:	movl %eax, 0xc(%ebp)
0x00418e3f:	movl 0x6c(%esi), %eax
0x00418e42:	testl %eax, %eax
0x00418e44:	jne 8
0x00418e46:	movl %eax, 0x43de38
0x00418e4b:	movl 0x6c(%esi), %eax
0x00418e4e:	pushl 0x6c(%esi)
0x00418e51:	call 0x00417a88
0x00417a88:	movl %edi, %edi
0x00417a8a:	pushl %ebp
0x00417a8b:	movl %ebp, %esp
0x00417a8d:	pushl %ebx
0x00417a8e:	pushl %esi
0x00417a8f:	movl %esi, 0x4342b4
0x00417a95:	pushl %edi
0x00417a96:	movl %edi, 0x8(%ebp)
0x00417a99:	pushl %edi
0x00417a9a:	call InterlockedIncrement@KERNEL32.dll
0x00417a9c:	movl %eax, 0xb0(%edi)
0x00417aa2:	testl %eax, %eax
0x00417aa4:	je 0x00417aa9
0x00417aa9:	movl %eax, 0xb8(%edi)
0x00417aaf:	testl %eax, %eax
0x00417ab1:	je 0x00417ab6
0x00417ab6:	movl %eax, 0xb4(%edi)
0x00417abc:	testl %eax, %eax
0x00417abe:	je 0x00417ac3
0x00417ac3:	movl %eax, 0xc0(%edi)
0x00417ac9:	testl %eax, %eax
0x00417acb:	je 0x00417ad0
0x00417ad0:	leal %ebx, 0x50(%edi)
0x00417ad3:	movl 0x8(%ebp), $0x6<UINT32>
0x00417ada:	cmpl -8(%ebx), $0x43dd58<UINT32>
0x00417ae1:	je 0x00417aec
0x00417ae3:	movl %eax, (%ebx)
0x00417ae5:	testl %eax, %eax
0x00417ae7:	je 0x00417aec
0x00417aec:	cmpl -4(%ebx), $0x0<UINT8>
0x00417af0:	je 0x00417afc
0x00417afc:	addl %ebx, $0x10<UINT8>
0x00417aff:	decl 0x8(%ebp)
0x00417b02:	jne 0x00417ada
0x00417b04:	movl %eax, 0xd4(%edi)
0x00417b0a:	addl %eax, $0xb4<UINT32>
0x00417b0f:	pushl %eax
0x00417b10:	call InterlockedIncrement@KERNEL32.dll
0x00417b12:	popl %edi
0x00417b13:	popl %esi
0x00417b14:	popl %ebx
0x00417b15:	popl %ebp
0x00417b16:	ret

0x00418e56:	popl %ecx
0x00418e57:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00418e5e:	call 0x00418e78
0x00418e78:	pushl $0xc<UINT8>
0x00418e7a:	call 0x0041985c
0x00418e7f:	popl %ecx
0x00418e80:	ret

0x00418e63:	call 0x0041a9e5
0x00418e68:	ret

0x0041922d:	popl %ecx
0x0041922e:	popl %ecx
0x0041922f:	call GetCurrentThreadId@KERNEL32.dll
0x00419235:	orl 0x4(%esi), $0xffffffff<UINT8>
0x00419239:	movl (%esi), %eax
0x0041923b:	xorl %eax, %eax
0x0041923d:	incl %eax
0x0041923e:	jmp 0x00419247
0x00419247:	popl %edi
0x00419248:	popl %esi
0x00419249:	ret

0x0041565e:	testl %eax, %eax
0x00415660:	jne 0x0041566a
0x0041566a:	call 0x004217d4
0x004217d4:	movl %edi, %edi
0x004217d6:	pushl %esi
0x004217d7:	movl %eax, $0x43aa40<UINT32>
0x004217dc:	movl %esi, $0x43aa40<UINT32>
0x004217e1:	pushl %edi
0x004217e2:	movl %edi, %eax
0x004217e4:	cmpl %eax, %esi
0x004217e6:	jae 0x004217f7
0x004217f7:	popl %edi
0x004217f8:	popl %esi
0x004217f9:	ret

0x0041566f:	movl -4(%ebp), %ebx
0x00415672:	call 0x0041e4ee
0x0041e4ee:	pushl $0x54<UINT8>
0x0041e4f0:	pushl $0x43aeb8<UINT32>
0x0041e4f5:	call 0x0041a9a0
0x0041e4fa:	xorl %edi, %edi
0x0041e4fc:	movl -4(%ebp), %edi
0x0041e4ff:	leal %eax, -100(%ebp)
0x0041e502:	pushl %eax
0x0041e503:	call GetStartupInfoA@KERNEL32.dll
0x0041e509:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0041e510:	pushl $0x40<UINT8>
0x0041e512:	pushl $0x20<UINT8>
0x0041e514:	popl %esi
0x0041e515:	pushl %esi
0x0041e516:	call 0x0041c255
0x0041e51b:	popl %ecx
0x0041e51c:	popl %ecx
0x0041e51d:	cmpl %eax, %edi
0x0041e51f:	je 532
0x0041e525:	movl 0x453740, %eax
0x0041e52a:	movl 0x45372c, %esi
0x0041e530:	leal %ecx, 0x800(%eax)
0x0041e536:	jmp 0x0041e568
0x0041e568:	cmpl %eax, %ecx
0x0041e56a:	jb 0x0041e538
0x0041e538:	movb 0x4(%eax), $0x0<UINT8>
0x0041e53c:	orl (%eax), $0xffffffff<UINT8>
0x0041e53f:	movb 0x5(%eax), $0xa<UINT8>
0x0041e543:	movl 0x8(%eax), %edi
0x0041e546:	movb 0x24(%eax), $0x0<UINT8>
0x0041e54a:	movb 0x25(%eax), $0xa<UINT8>
0x0041e54e:	movb 0x26(%eax), $0xa<UINT8>
0x0041e552:	movl 0x38(%eax), %edi
0x0041e555:	movb 0x34(%eax), $0x0<UINT8>
0x0041e559:	addl %eax, $0x40<UINT8>
0x0041e55c:	movl %ecx, 0x453740
0x0041e562:	addl %ecx, $0x800<UINT32>
0x0041e56c:	cmpw -50(%ebp), %di
0x0041e570:	je 266
0x0041e576:	movl %eax, -48(%ebp)
0x0041e579:	cmpl %eax, %edi
0x0041e57b:	je 255
0x0041e581:	movl %edi, (%eax)
0x0041e583:	leal %ebx, 0x4(%eax)
0x0041e586:	leal %eax, (%ebx,%edi)
0x0041e589:	movl -28(%ebp), %eax
0x0041e58c:	movl %esi, $0x800<UINT32>
0x0041e591:	cmpl %edi, %esi
0x0041e593:	jl 0x0041e597
0x0041e597:	movl -32(%ebp), $0x1<UINT32>
0x0041e59e:	jmp 0x0041e5fb
0x0041e5fb:	cmpl 0x45372c, %edi
0x0041e601:	jl -99
0x0041e603:	jmp 0x0041e60b
0x0041e60b:	andl -32(%ebp), $0x0<UINT8>
0x0041e60f:	testl %edi, %edi
0x0041e611:	jle 0x0041e680
0x0041e680:	xorl %ebx, %ebx
0x0041e682:	movl %esi, %ebx
0x0041e684:	shll %esi, $0x6<UINT8>
0x0041e687:	addl %esi, 0x453740
0x0041e68d:	movl %eax, (%esi)
0x0041e68f:	cmpl %eax, $0xffffffff<UINT8>
0x0041e692:	je 0x0041e69f
0x0041e69f:	movb 0x4(%esi), $0xffffff81<UINT8>
0x0041e6a3:	testl %ebx, %ebx
0x0041e6a5:	jne 0x0041e6ac
0x0041e6a7:	pushl $0xfffffff6<UINT8>
0x0041e6a9:	popl %eax
0x0041e6aa:	jmp 0x0041e6b6
0x0041e6b6:	pushl %eax
0x0041e6b7:	call GetStdHandle@KERNEL32.dll
GetStdHandle@KERNEL32.dll: API Node	
0x0041e6bd:	movl %edi, %eax
0x0041e6bf:	cmpl %edi, $0xffffffff<UINT8>
0x0041e6c2:	je 67
0x0041e6c4:	testl %edi, %edi
0x0041e6c6:	je 63
0x0041e6c8:	pushl %edi
0x0041e6c9:	call GetFileType@KERNEL32.dll
GetFileType@KERNEL32.dll: API Node	
0x0041e6cf:	testl %eax, %eax
0x0041e6d1:	je 52
0x0041e6d3:	movl (%esi), %edi
0x0041e6d5:	andl %eax, $0xff<UINT32>
0x0041e6da:	cmpl %eax, $0x2<UINT8>
0x0041e6dd:	jne 6
0x0041e6df:	orb 0x4(%esi), $0x40<UINT8>
0x0041e6e3:	jmp 0x0041e6ee
0x0041e6ee:	pushl $0xfa0<UINT32>
0x0041e6f3:	leal %eax, 0xc(%esi)
0x0041e6f6:	pushl %eax
0x0041e6f7:	call 0x00429cdc
0x0041e6fc:	popl %ecx
0x0041e6fd:	popl %ecx
0x0041e6fe:	testl %eax, %eax
0x0041e700:	je 55
0x0041e702:	incl 0x8(%esi)
0x0041e705:	jmp 0x0041e711
0x0041e711:	incl %ebx
0x0041e712:	cmpl %ebx, $0x3<UINT8>
0x0041e715:	jl 0x0041e682
0x0041e6ac:	movl %eax, %ebx
0x0041e6ae:	decl %eax
0x0041e6af:	negl %eax
0x0041e6b1:	sbbl %eax, %eax
0x0041e6b3:	addl %eax, $0xfffffff5<UINT8>
0x0041e71b:	pushl 0x45372c
0x0041e721:	call SetHandleCount@KERNEL32.dll
SetHandleCount@KERNEL32.dll: API Node	
0x0041e727:	xorl %eax, %eax
0x0041e729:	jmp 0x0041e73c
0x0041e73c:	call 0x0041a9e5
0x0041e741:	ret

0x00415677:	testl %eax, %eax
0x00415679:	jnl 0x00415683
0x00415683:	call GetCommandLineA@KERNEL32.dll
GetCommandLineA@KERNEL32.dll: API Node	
0x00415689:	movl 0x4548a4, %eax
0x0041568e:	call 0x0042169d
0x0042169d:	movl %edi, %edi
0x0042169f:	pushl %ebp
0x004216a0:	movl %ebp, %esp
0x004216a2:	movl %eax, 0x447f58
0x004216a7:	subl %esp, $0xc<UINT8>
0x004216aa:	pushl %ebx
0x004216ab:	pushl %esi
0x004216ac:	movl %esi, 0x43419c
0x004216b2:	pushl %edi
0x004216b3:	xorl %ebx, %ebx
0x004216b5:	xorl %edi, %edi
0x004216b7:	cmpl %eax, %ebx
0x004216b9:	jne 46
0x004216bb:	call GetEnvironmentStringsW@KERNEL32.dll
GetEnvironmentStringsW@KERNEL32.dll: API Node	
0x004216bd:	movl %edi, %eax
0x004216bf:	cmpl %edi, %ebx
0x004216c1:	je 12
0x004216c3:	movl 0x447f58, $0x1<UINT32>
0x004216cd:	jmp 0x004216f2
0x004216f2:	cmpl %edi, %ebx
0x004216f4:	jne 0x00421705
0x00421705:	movl %eax, %edi
0x00421707:	cmpw (%edi), %bx
0x0042170a:	je 14
0x0042170c:	incl %eax
0x0042170d:	incl %eax
0x0042170e:	cmpw (%eax), %bx
0x00421711:	jne 0x0042170c
0x00421713:	incl %eax
0x00421714:	incl %eax
0x00421715:	cmpw (%eax), %bx
0x00421718:	jne 0x0042170c
0x0042171a:	movl %esi, 0x4341f0
0x00421720:	pushl %ebx
0x00421721:	pushl %ebx
0x00421722:	pushl %ebx
0x00421723:	subl %eax, %edi
0x00421725:	pushl %ebx
0x00421726:	sarl %eax
0x00421728:	incl %eax
0x00421729:	pushl %eax
0x0042172a:	pushl %edi
0x0042172b:	pushl %ebx
0x0042172c:	pushl %ebx
0x0042172d:	movl -12(%ebp), %eax
0x00421730:	call WideCharToMultiByte@KERNEL32.dll
WideCharToMultiByte@KERNEL32.dll: API Node	
0x00421732:	movl -8(%ebp), %eax
0x00421735:	cmpl %eax, %ebx
0x00421737:	je 47
0x00421739:	pushl %eax
0x0042173a:	call 0x0041c210
0x0041c210:	movl %edi, %edi
0x0041c212:	pushl %ebp
0x0041c213:	movl %ebp, %esp
0x0041c215:	pushl %esi
0x0041c216:	pushl %edi
0x0041c217:	xorl %esi, %esi
0x0041c219:	pushl 0x8(%ebp)
0x0041c21c:	call 0x00412dc9
0x00412dc9:	movl %edi, %edi
0x00412dcb:	pushl %ebp
0x00412dcc:	movl %ebp, %esp
0x00412dce:	pushl %esi
0x00412dcf:	movl %esi, 0x8(%ebp)
0x00412dd2:	cmpl %esi, $0xffffffe0<UINT8>
0x00412dd5:	ja 161
0x00412ddb:	pushl %ebx
0x00412ddc:	pushl %edi
0x00412ddd:	movl %edi, 0x434164
0x00412de3:	cmpl 0x447990, $0x0<UINT8>
0x00412dea:	jne 0x00412e04
0x00412e04:	movl %eax, 0x454894
0x00412e09:	cmpl %eax, $0x1<UINT8>
0x00412e0c:	jne 14
0x00412e0e:	testl %esi, %esi
0x00412e10:	je 4
0x00412e12:	movl %eax, %esi
0x00412e14:	jmp 0x00412e19
0x00412e19:	pushl %eax
0x00412e1a:	jmp 0x00412e38
0x00412e38:	pushl $0x0<UINT8>
0x00412e3a:	pushl 0x447990
0x00412e40:	call HeapAlloc@KERNEL32.dll
0x00412e42:	movl %ebx, %eax
0x00412e44:	testl %ebx, %ebx
0x00412e46:	jne 0x00412e76
0x00412e76:	popl %edi
0x00412e77:	movl %eax, %ebx
0x00412e79:	popl %ebx
0x00412e7a:	jmp 0x00412e90
0x00412e90:	popl %esi
0x00412e91:	popl %ebp
0x00412e92:	ret

0x0041c221:	movl %edi, %eax
0x0041c223:	popl %ecx
0x0041c224:	testl %edi, %edi
0x0041c226:	jne 0x0041c24f
0x0041c24f:	movl %eax, %edi
0x0041c251:	popl %edi
0x0041c252:	popl %esi
0x0041c253:	popl %ebp
0x0041c254:	ret

0x0042173f:	popl %ecx
0x00421740:	movl -4(%ebp), %eax
0x00421743:	cmpl %eax, %ebx
0x00421745:	je 33
0x00421747:	pushl %ebx
0x00421748:	pushl %ebx
0x00421749:	pushl -8(%ebp)
0x0042174c:	pushl %eax
0x0042174d:	pushl -12(%ebp)
0x00421750:	pushl %edi
0x00421751:	pushl %ebx
0x00421752:	pushl %ebx
0x00421753:	call WideCharToMultiByte@KERNEL32.dll
0x00421755:	testl %eax, %eax
0x00421757:	jne 0x00421765
0x00421765:	movl %ebx, -4(%ebp)
0x00421768:	pushl %edi
0x00421769:	call FreeEnvironmentStringsW@KERNEL32.dll
FreeEnvironmentStringsW@KERNEL32.dll: API Node	
0x0042176f:	movl %eax, %ebx
0x00421771:	jmp 0x004217cf
0x004217cf:	popl %edi
0x004217d0:	popl %esi
0x004217d1:	popl %ebx
0x004217d2:	leave
0x004217d3:	ret

0x00415693:	movl 0x447608, %eax
0x00415698:	call 0x004215e2
0x004215e2:	movl %edi, %edi
0x004215e4:	pushl %ebp
0x004215e5:	movl %ebp, %esp
0x004215e7:	subl %esp, $0xc<UINT8>
0x004215ea:	pushl %ebx
0x004215eb:	xorl %ebx, %ebx
0x004215ed:	pushl %esi
0x004215ee:	pushl %edi
0x004215ef:	cmpl 0x454870, %ebx
0x004215f5:	jne 5
0x004215f7:	call 0x00417915
0x00417915:	cmpl 0x454870, $0x0<UINT8>
0x0041791c:	jne 0x00417930
0x0041791e:	pushl $0xfffffffd<UINT8>
0x00417920:	call 0x0041777b
0x0041777b:	pushl $0x14<UINT8>
0x0041777d:	pushl $0x43ace0<UINT32>
0x00417782:	call 0x0041a9a0
0x00417787:	orl -32(%ebp), $0xffffffff<UINT8>
0x0041778b:	call 0x00418efa
0x00418efa:	movl %edi, %edi
0x00418efc:	pushl %esi
0x00418efd:	call 0x00418e81
0x00418e81:	movl %edi, %edi
0x00418e83:	pushl %esi
0x00418e84:	pushl %edi
0x00418e85:	call GetLastError@KERNEL32.dll
GetLastError@KERNEL32.dll: API Node	
0x00418e8b:	pushl 0x43de48
0x00418e91:	movl %edi, %eax
0x00418e93:	call 0x00418d0c
0x00418d0c:	movl %edi, %edi
0x00418d0e:	pushl %esi
0x00418d0f:	pushl 0x43de4c
0x00418d15:	call TlsGetValue@KERNEL32.dll
0x00418d1b:	movl %esi, %eax
0x00418d1d:	testl %esi, %esi
0x00418d1f:	jne 0x00418d3c
0x00418d3c:	movl %eax, %esi
0x00418d3e:	popl %esi
0x00418d3f:	ret

0x00418e98:	call FlsGetValue@KERNEL32.DLL
0x00418e9a:	movl %esi, %eax
0x00418e9c:	testl %esi, %esi
0x00418e9e:	jne 0x00418eee
0x00418eee:	pushl %edi
0x00418eef:	call SetLastError@KERNEL32.dll
SetLastError@KERNEL32.dll: API Node	
0x00418ef5:	popl %edi
0x00418ef6:	movl %eax, %esi
0x00418ef8:	popl %esi
0x00418ef9:	ret

0x00418f02:	movl %esi, %eax
0x00418f04:	testl %esi, %esi
0x00418f06:	jne 0x00418f10
0x00418f10:	movl %eax, %esi
0x00418f12:	popl %esi
0x00418f13:	ret

0x00417790:	movl %edi, %eax
0x00417792:	movl -36(%ebp), %edi
0x00417795:	call 0x00417438
0x00417438:	pushl $0xc<UINT8>
0x0041743a:	pushl $0x43acc0<UINT32>
0x0041743f:	call 0x0041a9a0
0x00417444:	call 0x00418efa
0x00417449:	movl %edi, %eax
0x0041744b:	movl %eax, 0x43dd54
0x00417450:	testl 0x70(%edi), %eax
0x00417453:	je 0x00417472
0x00417472:	pushl $0xd<UINT8>
0x00417474:	call 0x0041994e
0x00417479:	popl %ecx
0x0041747a:	andl -4(%ebp), $0x0<UINT8>
0x0041747e:	movl %esi, 0x68(%edi)
0x00417481:	movl -28(%ebp), %esi
0x00417484:	cmpl %esi, 0x43dc58
0x0041748a:	je 0x004174c2
0x004174c2:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004174c9:	call 0x004174d3
0x004174d3:	pushl $0xd<UINT8>
0x004174d5:	call 0x0041985c
0x004174da:	popl %ecx
0x004174db:	ret

0x004174ce:	jmp 0x0041745e
0x0041745e:	testl %esi, %esi
0x00417460:	jne 0x0041746a
0x0041746a:	movl %eax, %esi
0x0041746c:	call 0x0041a9e5
0x00417471:	ret

0x0041779a:	movl %ebx, 0x68(%edi)
0x0041779d:	movl %esi, 0x8(%ebp)
0x004177a0:	call 0x004174dc
0x004174dc:	movl %edi, %edi
0x004174de:	pushl %ebp
0x004174df:	movl %ebp, %esp
0x004174e1:	subl %esp, $0x10<UINT8>
0x004174e4:	pushl %ebx
0x004174e5:	xorl %ebx, %ebx
0x004174e7:	pushl %ebx
0x004174e8:	leal %ecx, -16(%ebp)
0x004174eb:	call 0x00412991
0x00412991:	movl %edi, %edi
0x00412993:	pushl %ebp
0x00412994:	movl %ebp, %esp
0x00412996:	movl %eax, 0x8(%ebp)
0x00412999:	pushl %esi
0x0041299a:	movl %esi, %ecx
0x0041299c:	movb 0xc(%esi), $0x0<UINT8>
0x004129a0:	testl %eax, %eax
0x004129a2:	jne 0x00412a07
0x004129a4:	call 0x00418efa
0x004129a9:	movl 0x8(%esi), %eax
0x004129ac:	movl %ecx, 0x6c(%eax)
0x004129af:	movl (%esi), %ecx
0x004129b1:	movl %ecx, 0x68(%eax)
0x004129b4:	movl 0x4(%esi), %ecx
0x004129b7:	movl %ecx, (%esi)
0x004129b9:	cmpl %ecx, 0x43de38
0x004129bf:	je 0x004129d3
0x004129d3:	movl %eax, 0x4(%esi)
0x004129d6:	cmpl %eax, 0x43dc58
0x004129dc:	je 0x004129f4
0x004129f4:	movl %eax, 0x8(%esi)
0x004129f7:	testb 0x70(%eax), $0x2<UINT8>
0x004129fb:	jne 20
0x004129fd:	orl 0x70(%eax), $0x2<UINT8>
0x00412a01:	movb 0xc(%esi), $0x1<UINT8>
0x00412a05:	jmp 0x00412a11
0x00412a11:	movl %eax, %esi
0x00412a13:	popl %esi
0x00412a14:	popl %ebp
0x00412a15:	ret $0x4<UINT16>

0x004174f0:	movl 0x44793c, %ebx
0x004174f6:	cmpl %esi, $0xfffffffe<UINT8>
0x004174f9:	jne 0x00417519
0x00417519:	cmpl %esi, $0xfffffffd<UINT8>
0x0041751c:	jne 0x00417530
0x0041751e:	movl 0x44793c, $0x1<UINT32>
0x00417528:	call GetACP@KERNEL32.dll
GetACP@KERNEL32.dll: API Node	
0x0041752e:	jmp 0x0041750b
0x0041750b:	cmpb -4(%ebp), %bl
0x0041750e:	je 69
0x00417510:	movl %ecx, -8(%ebp)
0x00417513:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x00417517:	jmp 0x00417555
0x00417555:	popl %ebx
0x00417556:	leave
0x00417557:	ret

0x004177a5:	movl 0x8(%ebp), %eax
0x004177a8:	cmpl %eax, 0x4(%ebx)
0x004177ab:	je 343
0x004177b1:	pushl $0x220<UINT32>
0x004177b6:	call 0x0041c210
0x004177bb:	popl %ecx
0x004177bc:	movl %ebx, %eax
0x004177be:	testl %ebx, %ebx
0x004177c0:	je 326
0x004177c6:	movl %ecx, $0x88<UINT32>
0x004177cb:	movl %esi, 0x68(%edi)
0x004177ce:	movl %edi, %ebx
0x004177d0:	rep movsl %es:(%edi), %ds:(%esi)
0x004177d2:	andl (%ebx), $0x0<UINT8>
0x004177d5:	pushl %ebx
0x004177d6:	pushl 0x8(%ebp)
0x004177d9:	call 0x00417558
0x00417558:	movl %edi, %edi
0x0041755a:	pushl %ebp
0x0041755b:	movl %ebp, %esp
0x0041755d:	subl %esp, $0x20<UINT8>
0x00417560:	movl %eax, 0x43d68c
0x00417565:	xorl %eax, %ebp
0x00417567:	movl -4(%ebp), %eax
0x0041756a:	pushl %ebx
0x0041756b:	movl %ebx, 0xc(%ebp)
0x0041756e:	pushl %esi
0x0041756f:	movl %esi, 0x8(%ebp)
0x00417572:	pushl %edi
0x00417573:	call 0x004174dc
0x00417530:	cmpl %esi, $0xfffffffc<UINT8>
0x00417533:	jne 0x00417547
0x00417547:	cmpb -4(%ebp), %bl
0x0041754a:	je 7
0x0041754c:	movl %eax, -8(%ebp)
0x0041754f:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x00417553:	movl %eax, %esi
0x00417578:	movl %edi, %eax
0x0041757a:	xorl %esi, %esi
0x0041757c:	movl 0x8(%ebp), %edi
0x0041757f:	cmpl %edi, %esi
0x00417581:	jne 0x00417591
0x00417591:	movl -28(%ebp), %esi
0x00417594:	xorl %eax, %eax
0x00417596:	cmpl 0x43dc60(%eax), %edi
0x0041759c:	je 145
0x004175a2:	incl -28(%ebp)
0x004175a5:	addl %eax, $0x30<UINT8>
0x004175a8:	cmpl %eax, $0xf0<UINT32>
0x004175ad:	jb 0x00417596
0x004175af:	cmpl %edi, $0xfde8<UINT32>
0x004175b5:	je 368
0x004175bb:	cmpl %edi, $0xfde9<UINT32>
0x004175c1:	je 356
0x004175c7:	movzwl %eax, %di
0x004175ca:	pushl %eax
0x004175cb:	call IsValidCodePage@KERNEL32.dll
IsValidCodePage@KERNEL32.dll: API Node	
0x004175d1:	testl %eax, %eax
0x004175d3:	je 338
0x004175d9:	leal %eax, -24(%ebp)
0x004175dc:	pushl %eax
0x004175dd:	pushl %edi
0x004175de:	call GetCPInfo@KERNEL32.dll
GetCPInfo@KERNEL32.dll: API Node	
0x004175e4:	testl %eax, %eax
0x004175e6:	je 307
0x004175ec:	pushl $0x101<UINT32>
0x004175f1:	leal %eax, 0x1c(%ebx)
0x004175f4:	pushl %esi
0x004175f5:	pushl %eax
0x004175f6:	call 0x004128b0
0x004128b0:	movl %edx, 0xc(%esp)
0x004128b4:	movl %ecx, 0x4(%esp)
0x004128b8:	testl %edx, %edx
0x004128ba:	je 105
0x004128bc:	xorl %eax, %eax
0x004128be:	movb %al, 0x8(%esp)
0x004128c2:	testb %al, %al
0x004128c4:	jne 22
0x004128c6:	cmpl %edx, $0x100<UINT32>
0x004128cc:	jb 14
0x004128ce:	cmpl 0x4548a0, $0x0<UINT8>
0x004128d5:	je 0x004128dc
0x004128dc:	pushl %edi
0x004128dd:	movl %edi, %ecx
0x004128df:	cmpl %edx, $0x4<UINT8>
0x004128e2:	jb 49
0x004128e4:	negl %ecx
0x004128e6:	andl %ecx, $0x3<UINT8>
0x004128e9:	je 0x004128f7
0x004128f7:	movl %ecx, %eax
0x004128f9:	shll %eax, $0x8<UINT8>
0x004128fc:	addl %eax, %ecx
0x004128fe:	movl %ecx, %eax
0x00412900:	shll %eax, $0x10<UINT8>
0x00412903:	addl %eax, %ecx
0x00412905:	movl %ecx, %edx
0x00412907:	andl %edx, $0x3<UINT8>
0x0041290a:	shrl %ecx, $0x2<UINT8>
0x0041290d:	je 6
0x0041290f:	rep stosl %es:(%edi), %eax
0x00412911:	testl %edx, %edx
0x00412913:	je 0x0041291f
0x00412915:	movb (%edi), %al
0x00412917:	addl %edi, $0x1<UINT8>
0x0041291a:	subl %edx, $0x1<UINT8>
0x0041291d:	jne -10
0x0041291f:	movl %eax, 0x8(%esp)
0x00412923:	popl %edi
0x00412924:	ret

0x004175fb:	xorl %edx, %edx
0x004175fd:	incl %edx
0x004175fe:	addl %esp, $0xc<UINT8>
0x00417601:	movl 0x4(%ebx), %edi
0x00417604:	movl 0xc(%ebx), %esi
0x00417607:	cmpl -24(%ebp), %edx
0x0041760a:	jbe 248
0x00417610:	cmpb -18(%ebp), $0x0<UINT8>
0x00417614:	je 0x004176e9
0x004176e9:	leal %eax, 0x1e(%ebx)
0x004176ec:	movl %ecx, $0xfe<UINT32>
0x004176f1:	orb (%eax), $0x8<UINT8>
0x004176f4:	incl %eax
0x004176f5:	decl %ecx
0x004176f6:	jne 0x004176f1
0x004176f8:	movl %eax, 0x4(%ebx)
0x004176fb:	call 0x00417212
0x00417212:	subl %eax, $0x3a4<UINT32>
0x00417217:	je 34
0x00417219:	subl %eax, $0x4<UINT8>
0x0041721c:	je 23
0x0041721e:	subl %eax, $0xd<UINT8>
0x00417221:	je 12
0x00417223:	decl %eax
0x00417224:	je 3
0x00417226:	xorl %eax, %eax
0x00417228:	ret

0x00417700:	movl 0xc(%ebx), %eax
0x00417703:	movl 0x8(%ebx), %edx
0x00417706:	jmp 0x0041770b
0x0041770b:	xorl %eax, %eax
0x0041770d:	movzwl %ecx, %ax
0x00417710:	movl %eax, %ecx
0x00417712:	shll %ecx, $0x10<UINT8>
0x00417715:	orl %eax, %ecx
0x00417717:	leal %edi, 0x10(%ebx)
0x0041771a:	stosl %es:(%edi), %eax
0x0041771b:	stosl %es:(%edi), %eax
0x0041771c:	stosl %es:(%edi), %eax
0x0041771d:	jmp 0x004176c7
0x004176c7:	movl %esi, %ebx
0x004176c9:	call 0x004172a5
0x004172a5:	movl %edi, %edi
0x004172a7:	pushl %ebp
0x004172a8:	movl %ebp, %esp
0x004172aa:	subl %esp, $0x51c<UINT32>
0x004172b0:	movl %eax, 0x43d68c
0x004172b5:	xorl %eax, %ebp
0x004172b7:	movl -4(%ebp), %eax
0x004172ba:	pushl %ebx
0x004172bb:	pushl %edi
0x004172bc:	leal %eax, -1304(%ebp)
0x004172c2:	pushl %eax
0x004172c3:	pushl 0x4(%esi)
0x004172c6:	call GetCPInfo@KERNEL32.dll
0x004172cc:	movl %edi, $0x100<UINT32>
0x004172d1:	testl %eax, %eax
0x004172d3:	je 251
0x004172d9:	xorl %eax, %eax
0x004172db:	movb -260(%ebp,%eax), %al
0x004172e2:	incl %eax
0x004172e3:	cmpl %eax, %edi
0x004172e5:	jb 0x004172db
0x004172e7:	movb %al, -1298(%ebp)
0x004172ed:	movb -260(%ebp), $0x20<UINT8>
0x004172f4:	testb %al, %al
0x004172f6:	je 0x00417326
0x00417326:	pushl $0x0<UINT8>
0x00417328:	pushl 0xc(%esi)
0x0041732b:	leal %eax, -1284(%ebp)
0x00417331:	pushl 0x4(%esi)
0x00417334:	pushl %eax
0x00417335:	pushl %edi
0x00417336:	leal %eax, -260(%ebp)
0x0041733c:	pushl %eax
0x0041733d:	pushl $0x1<UINT8>
0x0041733f:	pushl $0x0<UINT8>
0x00417341:	call 0x0042432d
0x0042432d:	movl %edi, %edi
0x0042432f:	pushl %ebp
0x00424330:	movl %ebp, %esp
0x00424332:	subl %esp, $0x10<UINT8>
0x00424335:	pushl 0x8(%ebp)
0x00424338:	leal %ecx, -16(%ebp)
0x0042433b:	call 0x00412991
0x00424340:	pushl 0x24(%ebp)
0x00424343:	leal %ecx, -16(%ebp)
0x00424346:	pushl 0x20(%ebp)
0x00424349:	pushl 0x1c(%ebp)
0x0042434c:	pushl 0x18(%ebp)
0x0042434f:	pushl 0x14(%ebp)
0x00424352:	pushl 0x10(%ebp)
0x00424355:	pushl 0xc(%ebp)
0x00424358:	call 0x00424173
0x00424173:	movl %edi, %edi
0x00424175:	pushl %ebp
0x00424176:	movl %ebp, %esp
0x00424178:	pushl %ecx
0x00424179:	pushl %ecx
0x0042417a:	movl %eax, 0x43d68c
0x0042417f:	xorl %eax, %ebp
0x00424181:	movl -4(%ebp), %eax
0x00424184:	movl %eax, 0x447f60
0x00424189:	pushl %ebx
0x0042418a:	pushl %esi
0x0042418b:	xorl %ebx, %ebx
0x0042418d:	pushl %edi
0x0042418e:	movl %edi, %ecx
0x00424190:	cmpl %eax, %ebx
0x00424192:	jne 58
0x00424194:	leal %eax, -8(%ebp)
0x00424197:	pushl %eax
0x00424198:	xorl %esi, %esi
0x0042419a:	incl %esi
0x0042419b:	pushl %esi
0x0042419c:	pushl $0x439034<UINT32>
0x004241a1:	pushl %esi
0x004241a2:	call GetStringTypeW@KERNEL32.dll
GetStringTypeW@KERNEL32.dll: API Node	
0x004241a8:	testl %eax, %eax
0x004241aa:	je 8
0x004241ac:	movl 0x447f60, %esi
0x004241b2:	jmp 0x004241e8
0x004241e8:	movl -8(%ebp), %ebx
0x004241eb:	cmpl 0x18(%ebp), %ebx
0x004241ee:	jne 0x004241f8
0x004241f8:	movl %esi, 0x4341ec
0x004241fe:	xorl %eax, %eax
0x00424200:	cmpl 0x20(%ebp), %ebx
0x00424203:	pushl %ebx
0x00424204:	pushl %ebx
0x00424205:	pushl 0x10(%ebp)
0x00424208:	setne %al
0x0042420b:	pushl 0xc(%ebp)
0x0042420e:	leal %eax, 0x1(,%eax,8)
0x00424215:	pushl %eax
0x00424216:	pushl 0x18(%ebp)
0x00424219:	call MultiByteToWideChar@KERNEL32.dll
MultiByteToWideChar@KERNEL32.dll: API Node	
0x0042421b:	movl %edi, %eax
0x0042421d:	cmpl %edi, %ebx
0x0042421f:	je 171
0x00424225:	jle 60
0x00424227:	cmpl %edi, $0x7ffffff0<UINT32>
0x0042422d:	ja 52
0x0042422f:	leal %eax, 0x8(%edi,%edi)
0x00424233:	cmpl %eax, $0x400<UINT32>
0x00424238:	ja 19
0x0042423a:	call 0x004196e0
0x004196e0:	pushl %ecx
0x004196e1:	leal %ecx, 0x8(%esp)
0x004196e5:	subl %ecx, %eax
0x004196e7:	andl %ecx, $0xf<UINT8>
0x004196ea:	addl %eax, %ecx
0x004196ec:	sbbl %ecx, %ecx
0x004196ee:	orl %eax, %ecx
0x004196f0:	popl %ecx
0x004196f1:	jmp 0x00412930
0x00412930:	pushl %ecx
0x00412931:	leal %ecx, 0x4(%esp)
0x00412935:	subl %ecx, %eax
0x00412937:	sbbl %eax, %eax
0x00412939:	notl %eax
0x0041293b:	andl %ecx, %eax
0x0041293d:	movl %eax, %esp
0x0041293f:	andl %eax, $0xfffff000<UINT32>
0x00412944:	cmpl %ecx, %eax
0x00412946:	jb 10
0x00412948:	movl %eax, %ecx
0x0041294a:	popl %ecx
0x0041294b:	xchgl %esp, %eax
0x0041294c:	movl %eax, (%eax)
0x0041294e:	movl (%esp), %eax
0x00412951:	ret

0x0042423f:	movl %eax, %esp
0x00424241:	cmpl %eax, %ebx
0x00424243:	je 28
0x00424245:	movl (%eax), $0xcccc<UINT32>
0x0042424b:	jmp 0x0042425e
0x0042425e:	addl %eax, $0x8<UINT8>
0x00424261:	movl %ebx, %eax
0x00424263:	testl %ebx, %ebx
0x00424265:	je 105
0x00424267:	leal %eax, (%edi,%edi)
0x0042426a:	pushl %eax
0x0042426b:	pushl $0x0<UINT8>
0x0042426d:	pushl %ebx
0x0042426e:	call 0x004128b0
0x00424273:	addl %esp, $0xc<UINT8>
0x00424276:	pushl %edi
0x00424277:	pushl %ebx
0x00424278:	pushl 0x10(%ebp)
0x0042427b:	pushl 0xc(%ebp)
0x0042427e:	pushl $0x1<UINT8>
0x00424280:	pushl 0x18(%ebp)
0x00424283:	call MultiByteToWideChar@KERNEL32.dll
0x00424285:	testl %eax, %eax
0x00424287:	je 17
0x00424289:	pushl 0x14(%ebp)
0x0042428c:	pushl %eax
0x0042428d:	pushl %ebx
0x0042428e:	pushl 0x8(%ebp)
0x00424291:	call GetStringTypeW@KERNEL32.dll
0x00424297:	movl -8(%ebp), %eax
0x0042429a:	pushl %ebx
0x0042429b:	call 0x00412971
0x00412971:	movl %edi, %edi
0x00412973:	pushl %ebp
0x00412974:	movl %ebp, %esp
0x00412976:	movl %eax, 0x8(%ebp)
0x00412979:	testl %eax, %eax
0x0041297b:	je 18
0x0041297d:	subl %eax, $0x8<UINT8>
0x00412980:	cmpl (%eax), $0xdddd<UINT32>
0x00412986:	jne 0x0041298f
0x0041298f:	popl %ebp
0x00412990:	ret

0x004242a0:	movl %eax, -8(%ebp)
0x004242a3:	popl %ecx
0x004242a4:	jmp 0x0042431b
0x0042431b:	leal %esp, -20(%ebp)
0x0042431e:	popl %edi
0x0042431f:	popl %esi
0x00424320:	popl %ebx
0x00424321:	movl %ecx, -4(%ebp)
0x00424324:	xorl %ecx, %ebp
0x00424326:	call 0x004126d4
0x004126d4:	cmpl %ecx, 0x43d68c
0x004126da:	jne 2
0x004126dc:	rep ret

0x0042432b:	leave
0x0042432c:	ret

0x0042435d:	addl %esp, $0x1c<UINT8>
0x00424360:	cmpb -4(%ebp), $0x0<UINT8>
0x00424364:	je 7
0x00424366:	movl %ecx, -8(%ebp)
0x00424369:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0042436d:	leave
0x0042436e:	ret

0x00417346:	xorl %ebx, %ebx
0x00417348:	pushl %ebx
0x00417349:	pushl 0x4(%esi)
0x0041734c:	leal %eax, -516(%ebp)
0x00417352:	pushl %edi
0x00417353:	pushl %eax
0x00417354:	pushl %edi
0x00417355:	leal %eax, -260(%ebp)
0x0041735b:	pushl %eax
0x0041735c:	pushl %edi
0x0041735d:	pushl 0xc(%esi)
0x00417360:	pushl %ebx
0x00417361:	call 0x00419675
0x00419675:	movl %edi, %edi
0x00419677:	pushl %ebp
0x00419678:	movl %ebp, %esp
0x0041967a:	subl %esp, $0x10<UINT8>
0x0041967d:	pushl 0x8(%ebp)
0x00419680:	leal %ecx, -16(%ebp)
0x00419683:	call 0x00412991
0x00419688:	pushl 0x28(%ebp)
0x0041968b:	leal %ecx, -16(%ebp)
0x0041968e:	pushl 0x24(%ebp)
0x00419691:	pushl 0x20(%ebp)
0x00419694:	pushl 0x1c(%ebp)
0x00419697:	pushl 0x18(%ebp)
0x0041969a:	pushl 0x14(%ebp)
0x0041969d:	pushl 0x10(%ebp)
0x004196a0:	pushl 0xc(%ebp)
0x004196a3:	call 0x004192d0
0x004192d0:	movl %edi, %edi
0x004192d2:	pushl %ebp
0x004192d3:	movl %ebp, %esp
0x004192d5:	subl %esp, $0x14<UINT8>
0x004192d8:	movl %eax, 0x43d68c
0x004192dd:	xorl %eax, %ebp
0x004192df:	movl -4(%ebp), %eax
0x004192e2:	pushl %ebx
0x004192e3:	pushl %esi
0x004192e4:	xorl %ebx, %ebx
0x004192e6:	pushl %edi
0x004192e7:	movl %esi, %ecx
0x004192e9:	cmpl 0x44798c, %ebx
0x004192ef:	jne 0x00419329
0x004192f1:	pushl %ebx
0x004192f2:	pushl %ebx
0x004192f3:	xorl %edi, %edi
0x004192f5:	incl %edi
0x004192f6:	pushl %edi
0x004192f7:	pushl $0x439034<UINT32>
0x004192fc:	pushl $0x100<UINT32>
0x00419301:	pushl %ebx
0x00419302:	call LCMapStringW@KERNEL32.dll
LCMapStringW@KERNEL32.dll: API Node	
0x00419308:	testl %eax, %eax
0x0041930a:	je 8
0x0041930c:	movl 0x44798c, %edi
0x00419312:	jmp 0x00419329
0x00419329:	cmpl 0x14(%ebp), %ebx
0x0041932c:	jle 0x00419350
0x00419350:	movl %eax, 0x44798c
0x00419355:	cmpl %eax, $0x2<UINT8>
0x00419358:	je 428
0x0041935e:	cmpl %eax, %ebx
0x00419360:	je 420
0x00419366:	cmpl %eax, $0x1<UINT8>
0x00419369:	jne 460
0x0041936f:	movl -8(%ebp), %ebx
0x00419372:	cmpl 0x20(%ebp), %ebx
0x00419375:	jne 0x0041937f
0x0041937f:	movl %esi, 0x4341ec
0x00419385:	xorl %eax, %eax
0x00419387:	cmpl 0x24(%ebp), %ebx
0x0041938a:	pushl %ebx
0x0041938b:	pushl %ebx
0x0041938c:	pushl 0x14(%ebp)
0x0041938f:	setne %al
0x00419392:	pushl 0x10(%ebp)
0x00419395:	leal %eax, 0x1(,%eax,8)
0x0041939c:	pushl %eax
0x0041939d:	pushl 0x20(%ebp)
0x004193a0:	call MultiByteToWideChar@KERNEL32.dll
0x004193a2:	movl %edi, %eax
0x004193a4:	cmpl %edi, %ebx
0x004193a6:	je 0x0041953b
0x0041953b:	xorl %eax, %eax
0x0041953d:	jmp 0x00419663
0x00419663:	leal %esp, -32(%ebp)
0x00419666:	popl %edi
0x00419667:	popl %esi
0x00419668:	popl %ebx
0x00419669:	movl %ecx, -4(%ebp)
0x0041966c:	xorl %ecx, %ebp
0x0041966e:	call 0x004126d4
0x00419673:	leave
0x00419674:	ret

0x004196a8:	addl %esp, $0x20<UINT8>
0x004196ab:	cmpb -4(%ebp), $0x0<UINT8>
0x004196af:	je 7
0x004196b1:	movl %ecx, -8(%ebp)
0x004196b4:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x004196b8:	leave
0x004196b9:	ret

0x00417366:	addl %esp, $0x44<UINT8>
0x00417369:	pushl %ebx
0x0041736a:	pushl 0x4(%esi)
0x0041736d:	leal %eax, -772(%ebp)
0x00417373:	pushl %edi
0x00417374:	pushl %eax
0x00417375:	pushl %edi
0x00417376:	leal %eax, -260(%ebp)
0x0041737c:	pushl %eax
0x0041737d:	pushl $0x200<UINT32>
0x00417382:	pushl 0xc(%esi)
0x00417385:	pushl %ebx
0x00417386:	call 0x00419675
0x0041738b:	addl %esp, $0x24<UINT8>
0x0041738e:	xorl %eax, %eax
0x00417390:	movzwl %ecx, -1284(%ebp,%eax,2)
0x00417398:	testb %cl, $0x1<UINT8>
0x0041739b:	je 0x004173ab
0x004173ab:	testb %cl, $0x2<UINT8>
0x004173ae:	je 0x004173c5
0x004173c5:	movb 0x11d(%esi,%eax), $0x0<UINT8>
0x004173cd:	incl %eax
0x004173ce:	cmpl %eax, %edi
0x004173d0:	jb -66
0x004173d2:	jmp 0x0041742a
0x0041742a:	movl %ecx, -4(%ebp)
0x0041742d:	popl %edi
0x0041742e:	xorl %ecx, %ebp
0x00417430:	popl %ebx
0x00417431:	call 0x004126d4
0x00417436:	leave
0x00417437:	ret

0x004176ce:	jmp 0x0041758a
0x0041758a:	xorl %eax, %eax
0x0041758c:	jmp 0x0041772e
0x0041772e:	movl %ecx, -4(%ebp)
0x00417731:	popl %edi
0x00417732:	popl %esi
0x00417733:	xorl %ecx, %ebp
0x00417735:	popl %ebx
0x00417736:	call 0x004126d4
0x0041773b:	leave
0x0041773c:	ret

0x004177de:	popl %ecx
0x004177df:	popl %ecx
0x004177e0:	movl -32(%ebp), %eax
0x004177e3:	testl %eax, %eax
0x004177e5:	jne 252
0x004177eb:	movl %esi, -36(%ebp)
0x004177ee:	pushl 0x68(%esi)
0x004177f1:	call InterlockedDecrement@KERNEL32.dll
InterlockedDecrement@KERNEL32.dll: API Node	
0x004177f7:	testl %eax, %eax
0x004177f9:	jne 17
0x004177fb:	movl %eax, 0x68(%esi)
0x004177fe:	cmpl %eax, $0x43d830<UINT32>
0x00417803:	je 0x0041780c
0x0041780c:	movl 0x68(%esi), %ebx
0x0041780f:	pushl %ebx
0x00417810:	movl %edi, 0x4342b4
0x00417816:	call InterlockedIncrement@KERNEL32.dll
0x00417818:	testb 0x70(%esi), $0x2<UINT8>
0x0041781c:	jne 234
0x00417822:	testb 0x43dd54, $0x1<UINT8>
0x00417829:	jne 221
0x0041782f:	pushl $0xd<UINT8>
0x00417831:	call 0x0041994e
0x00417836:	popl %ecx
0x00417837:	andl -4(%ebp), $0x0<UINT8>
0x0041783b:	movl %eax, 0x4(%ebx)
0x0041783e:	movl 0x44794c, %eax
0x00417843:	movl %eax, 0x8(%ebx)
0x00417846:	movl 0x447950, %eax
0x0041784b:	movl %eax, 0xc(%ebx)
0x0041784e:	movl 0x447954, %eax
0x00417853:	xorl %eax, %eax
0x00417855:	movl -28(%ebp), %eax
0x00417858:	cmpl %eax, $0x5<UINT8>
0x0041785b:	jnl 0x0041786d
0x0041785d:	movw %cx, 0x10(%ebx,%eax,2)
0x00417862:	movw 0x447940(,%eax,2), %cx
0x0041786a:	incl %eax
0x0041786b:	jmp 0x00417855
0x0041786d:	xorl %eax, %eax
0x0041786f:	movl -28(%ebp), %eax
0x00417872:	cmpl %eax, $0x101<UINT32>
0x00417877:	jnl 0x00417886
0x00417879:	movb %cl, 0x1c(%eax,%ebx)
0x0041787d:	movb 0x43da50(%eax), %cl
0x00417883:	incl %eax
0x00417884:	jmp 0x0041786f
0x00417886:	xorl %eax, %eax
0x00417888:	movl -28(%ebp), %eax
0x0041788b:	cmpl %eax, $0x100<UINT32>
0x00417890:	jnl 0x004178a2
0x00417892:	movb %cl, 0x11d(%eax,%ebx)
0x00417899:	movb 0x43db58(%eax), %cl
0x0041789f:	incl %eax
0x004178a0:	jmp 0x00417888
0x004178a2:	pushl 0x43dc58
0x004178a8:	call InterlockedDecrement@KERNEL32.dll
0x004178ae:	testl %eax, %eax
0x004178b0:	jne 0x004178c5
0x004178c5:	movl 0x43dc58, %ebx
0x004178cb:	pushl %ebx
0x004178cc:	call InterlockedIncrement@KERNEL32.dll
0x004178ce:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004178d5:	call 0x004178dc
0x004178dc:	pushl $0xd<UINT8>
0x004178de:	call 0x0041985c
0x004178e3:	popl %ecx
0x004178e4:	ret

0x004178da:	jmp 0x0041790c
0x0041790c:	movl %eax, -32(%ebp)
0x0041790f:	call 0x0041a9e5
0x00417914:	ret

0x00417925:	popl %ecx
0x00417926:	movl 0x454870, $0x1<UINT32>
0x00417930:	xorl %eax, %eax
0x00417932:	ret

0x004215fc:	pushl $0x104<UINT32>
0x00421601:	movl %esi, $0x447e50<UINT32>
0x00421606:	pushl %esi
0x00421607:	pushl %ebx
0x00421608:	movb 0x447f54, %bl
0x0042160e:	call GetModuleFileNameA@KERNEL32.dll
GetModuleFileNameA@KERNEL32.dll: API Node	
0x00421614:	movl %eax, 0x4548a4
0x00421619:	movl 0x447b0c, %esi
0x0042161f:	cmpl %eax, %ebx
0x00421621:	je 7
0x00421623:	movl -4(%ebp), %eax
0x00421626:	cmpb (%eax), %bl
0x00421628:	jne 0x0042162d
0x0042162d:	movl %edx, -4(%ebp)
0x00421630:	leal %eax, -8(%ebp)
0x00421633:	pushl %eax
0x00421634:	pushl %ebx
0x00421635:	pushl %ebx
0x00421636:	leal %edi, -12(%ebp)
0x00421639:	call 0x00421448
0x00421448:	movl %edi, %edi
0x0042144a:	pushl %ebp
0x0042144b:	movl %ebp, %esp
0x0042144d:	pushl %ecx
0x0042144e:	movl %ecx, 0x10(%ebp)
0x00421451:	pushl %ebx
0x00421452:	xorl %eax, %eax
0x00421454:	pushl %esi
0x00421455:	movl (%edi), %eax
0x00421457:	movl %esi, %edx
0x00421459:	movl %edx, 0xc(%ebp)
0x0042145c:	movl (%ecx), $0x1<UINT32>
0x00421462:	cmpl 0x8(%ebp), %eax
0x00421465:	je 0x00421470
0x00421470:	movl -4(%ebp), %eax
0x00421473:	cmpb (%esi), $0x22<UINT8>
0x00421476:	jne 0x00421488
0x00421478:	xorl %eax, %eax
0x0042147a:	cmpl -4(%ebp), %eax
0x0042147d:	movb %bl, $0x22<UINT8>
0x0042147f:	sete %al
0x00421482:	incl %esi
0x00421483:	movl -4(%ebp), %eax
0x00421486:	jmp 0x004214c4
0x004214c4:	cmpl -4(%ebp), $0x0<UINT8>
0x004214c8:	jne 0x00421473
0x00421488:	incl (%edi)
0x0042148a:	testl %edx, %edx
0x0042148c:	je 0x00421496
0x00421496:	movb %bl, (%esi)
0x00421498:	movzbl %eax, %bl
0x0042149b:	pushl %eax
0x0042149c:	incl %esi
0x0042149d:	call 0x0042d032
0x0042d032:	movl %edi, %edi
0x0042d034:	pushl %ebp
0x0042d035:	movl %ebp, %esp
0x0042d037:	pushl $0x4<UINT8>
0x0042d039:	pushl $0x0<UINT8>
0x0042d03b:	pushl 0x8(%ebp)
0x0042d03e:	pushl $0x0<UINT8>
0x0042d040:	call 0x0042ce26
0x0042ce26:	movl %edi, %edi
0x0042ce28:	pushl %ebp
0x0042ce29:	movl %ebp, %esp
0x0042ce2b:	subl %esp, $0x10<UINT8>
0x0042ce2e:	pushl 0x8(%ebp)
0x0042ce31:	leal %ecx, -16(%ebp)
0x0042ce34:	call 0x00412991
0x0042ce39:	movzbl %eax, 0xc(%ebp)
0x0042ce3d:	movl %ecx, -12(%ebp)
0x0042ce40:	movb %dl, 0x14(%ebp)
0x0042ce43:	testb 0x1d(%ecx,%eax), %dl
0x0042ce47:	jne 30
0x0042ce49:	cmpl 0x10(%ebp), $0x0<UINT8>
0x0042ce4d:	je 0x0042ce61
0x0042ce61:	xorl %eax, %eax
0x0042ce63:	testl %eax, %eax
0x0042ce65:	je 0x0042ce6a
0x0042ce6a:	cmpb -4(%ebp), $0x0<UINT8>
0x0042ce6e:	je 7
0x0042ce70:	movl %ecx, -8(%ebp)
0x0042ce73:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0042ce77:	leave
0x0042ce78:	ret

0x0042d045:	addl %esp, $0x10<UINT8>
0x0042d048:	popl %ebp
0x0042d049:	ret

0x004214a2:	popl %ecx
0x004214a3:	testl %eax, %eax
0x004214a5:	je 0x004214ba
0x004214ba:	movl %edx, 0xc(%ebp)
0x004214bd:	movl %ecx, 0x10(%ebp)
0x004214c0:	testb %bl, %bl
0x004214c2:	je 0x004214f6
0x004214ca:	cmpb %bl, $0x20<UINT8>
0x004214cd:	je 5
0x004214cf:	cmpb %bl, $0x9<UINT8>
0x004214d2:	jne 0x00421473
0x004214f6:	decl %esi
0x004214f7:	jmp 0x004214dc
0x004214dc:	andl -4(%ebp), $0x0<UINT8>
0x004214e0:	cmpb (%esi), $0x0<UINT8>
0x004214e3:	je 0x004215d2
0x004215d2:	movl %eax, 0x8(%ebp)
0x004215d5:	popl %esi
0x004215d6:	popl %ebx
0x004215d7:	testl %eax, %eax
0x004215d9:	je 0x004215de
0x004215de:	incl (%ecx)
0x004215e0:	leave
0x004215e1:	ret

0x0042163e:	movl %eax, -8(%ebp)
0x00421641:	addl %esp, $0xc<UINT8>
0x00421644:	cmpl %eax, $0x3fffffff<UINT32>
0x00421649:	jae 74
0x0042164b:	movl %ecx, -12(%ebp)
0x0042164e:	cmpl %ecx, $0xffffffff<UINT8>
0x00421651:	jae 66
0x00421653:	movl %edi, %eax
0x00421655:	shll %edi, $0x2<UINT8>
0x00421658:	leal %eax, (%edi,%ecx)
0x0042165b:	cmpl %eax, %ecx
0x0042165d:	jb 54
0x0042165f:	pushl %eax
0x00421660:	call 0x0041c210
0x00421665:	movl %esi, %eax
0x00421667:	popl %ecx
0x00421668:	cmpl %esi, %ebx
0x0042166a:	je 41
0x0042166c:	movl %edx, -4(%ebp)
0x0042166f:	leal %eax, -8(%ebp)
0x00421672:	pushl %eax
0x00421673:	addl %edi, %esi
0x00421675:	pushl %edi
0x00421676:	pushl %esi
0x00421677:	leal %edi, -12(%ebp)
0x0042167a:	call 0x00421448
0x00421467:	movl %ebx, 0x8(%ebp)
0x0042146a:	addl 0x8(%ebp), $0x4<UINT8>
0x0042146e:	movl (%ebx), %edx
0x0042148e:	movb %al, (%esi)
0x00421490:	movb (%edx), %al
0x00421492:	incl %edx
0x00421493:	movl 0xc(%ebp), %edx
0x004215db:	andl (%eax), $0x0<UINT8>
0x0042167f:	movl %eax, -8(%ebp)
0x00421682:	addl %esp, $0xc<UINT8>
0x00421685:	decl %eax
0x00421686:	movl 0x447af0, %eax
0x0042168b:	movl 0x447af4, %esi
0x00421691:	xorl %eax, %eax
0x00421693:	jmp 0x00421698
0x00421698:	popl %edi
0x00421699:	popl %esi
0x0042169a:	popl %ebx
0x0042169b:	leave
0x0042169c:	ret

0x0041569d:	testl %eax, %eax
0x0041569f:	jnl 0x004156a9
0x004156a9:	call 0x0042135b
0x0042135b:	cmpl 0x454870, $0x0<UINT8>
0x00421362:	jne 0x00421369
0x00421369:	pushl %esi
0x0042136a:	movl %esi, 0x447608
0x00421370:	pushl %edi
0x00421371:	xorl %edi, %edi
0x00421373:	testl %esi, %esi
0x00421375:	jne 0x0042138f
0x0042138f:	movb %al, (%esi)
0x00421391:	testb %al, %al
0x00421393:	jne 0x0042137f
0x0042137f:	cmpb %al, $0x3d<UINT8>
0x00421381:	je 0x00421384
0x00421384:	pushl %esi
0x00421385:	call 0x0041e790
0x0041e790:	movl %ecx, 0x4(%esp)
0x0041e794:	testl %ecx, $0x3<UINT32>
0x0041e79a:	je 0x0041e7c0
0x0041e7c0:	movl %eax, (%ecx)
0x0041e7c2:	movl %edx, $0x7efefeff<UINT32>
0x0041e7c7:	addl %edx, %eax
0x0041e7c9:	xorl %eax, $0xffffffff<UINT8>
0x0041e7cc:	xorl %eax, %edx
0x0041e7ce:	addl %ecx, $0x4<UINT8>
0x0041e7d1:	testl %eax, $0x81010100<UINT32>
0x0041e7d6:	je 0x0041e7c0
0x0041e7d8:	movl %eax, -4(%ecx)
0x0041e7db:	testb %al, %al
0x0041e7dd:	je 50
0x0041e7df:	testb %ah, %ah
0x0041e7e1:	je 36
0x0041e7e3:	testl %eax, $0xff0000<UINT32>
0x0041e7e8:	je 19
0x0041e7ea:	testl %eax, $0xff000000<UINT32>
0x0041e7ef:	je 0x0041e7f3
0x0041e7f3:	leal %eax, -1(%ecx)
0x0041e7f6:	movl %ecx, 0x4(%esp)
0x0041e7fa:	subl %eax, %ecx
0x0041e7fc:	ret

0x0042138a:	popl %ecx
0x0042138b:	leal %esi, 0x1(%esi,%eax)
0x00421395:	pushl $0x4<UINT8>
0x00421397:	incl %edi
0x00421398:	pushl %edi
0x00421399:	call 0x0041c255
0x0042139e:	movl %edi, %eax
0x004213a0:	popl %ecx
0x004213a1:	popl %ecx
0x004213a2:	movl 0x447afc, %edi
0x004213a8:	testl %edi, %edi
0x004213aa:	je -53
0x004213ac:	movl %esi, 0x447608
0x004213b2:	pushl %ebx
0x004213b3:	jmp 0x004213f7
0x004213f7:	cmpb (%esi), $0x0<UINT8>
0x004213fa:	jne 0x004213b5
0x004213b5:	pushl %esi
0x004213b6:	call 0x0041e790
0x004213bb:	movl %ebx, %eax
0x004213bd:	incl %ebx
0x004213be:	cmpb (%esi), $0x3d<UINT8>
0x004213c1:	popl %ecx
0x004213c2:	je 0x004213f5
0x004213f5:	addl %esi, %ebx
0x004213fc:	pushl 0x447608
0x00421402:	call 0x00412c72
0x00412c72:	pushl $0xc<UINT8>
0x00412c74:	pushl $0x43aab0<UINT32>
0x00412c79:	call 0x0041a9a0
0x00412c7e:	movl %esi, 0x8(%ebp)
0x00412c81:	testl %esi, %esi
0x00412c83:	je 117
0x00412c85:	cmpl 0x454894, $0x3<UINT8>
0x00412c8c:	jne 0x00412cd1
0x00412cd1:	pushl %esi
0x00412cd2:	pushl $0x0<UINT8>
0x00412cd4:	pushl 0x447990
0x00412cda:	call HeapFree@KERNEL32.dll
HeapFree@KERNEL32.dll: API Node	
0x00412ce0:	testl %eax, %eax
0x00412ce2:	jne 0x00412cfa
0x00412cfa:	call 0x0041a9e5
0x00412cff:	ret

0x00421407:	andl 0x447608, $0x0<UINT8>
0x0042140e:	andl (%edi), $0x0<UINT8>
0x00421411:	movl 0x454864, $0x1<UINT32>
0x0042141b:	xorl %eax, %eax
0x0042141d:	popl %ecx
0x0042141e:	popl %ebx
0x0042141f:	popl %edi
0x00421420:	popl %esi
0x00421421:	ret

0x004156ae:	testl %eax, %eax
0x004156b0:	jnl 0x004156ba
0x004156ba:	pushl %ebx
0x004156bb:	call 0x0041ab60
0x0041ab60:	movl %edi, %edi
0x0041ab62:	pushl %ebp
0x0041ab63:	movl %ebp, %esp
0x0041ab65:	cmpl 0x438e1c, $0x0<UINT8>
0x0041ab6c:	je 25
0x0041ab6e:	pushl $0x438e1c<UINT32>
0x0041ab73:	call 0x00416fb0
0x00416fb0:	movl %edi, %edi
0x00416fb2:	pushl %ebp
0x00416fb3:	movl %ebp, %esp
0x00416fb5:	pushl $0xfffffffe<UINT8>
0x00416fb7:	pushl $0x43ac80<UINT32>
0x00416fbc:	pushl $0x412720<UINT32>
0x00416fc1:	movl %eax, %fs:0
0x00416fc7:	pushl %eax
0x00416fc8:	subl %esp, $0x8<UINT8>
0x00416fcb:	pushl %ebx
0x00416fcc:	pushl %esi
0x00416fcd:	pushl %edi
0x00416fce:	movl %eax, 0x43d68c
0x00416fd3:	xorl -8(%ebp), %eax
0x00416fd6:	xorl %eax, %ebp
0x00416fd8:	pushl %eax
0x00416fd9:	leal %eax, -16(%ebp)
0x00416fdc:	movl %fs:0, %eax
0x00416fe2:	movl -24(%ebp), %esp
0x00416fe5:	movl -4(%ebp), $0x0<UINT32>
0x00416fec:	pushl $0x400000<UINT32>
0x00416ff1:	call 0x00416f20
0x00416f20:	movl %edi, %edi
0x00416f22:	pushl %ebp
0x00416f23:	movl %ebp, %esp
0x00416f25:	movl %ecx, 0x8(%ebp)
0x00416f28:	movl %eax, $0x5a4d<UINT32>
0x00416f2d:	cmpw (%ecx), %ax
0x00416f30:	je 0x00416f36
0x00416f36:	movl %eax, 0x3c(%ecx)
0x00416f39:	addl %eax, %ecx
0x00416f3b:	cmpl (%eax), $0x4550<UINT32>
0x00416f41:	jne -17
0x00416f43:	xorl %edx, %edx
0x00416f45:	movl %ecx, $0x10b<UINT32>
0x00416f4a:	cmpw 0x18(%eax), %cx
0x00416f4e:	sete %dl
0x00416f51:	movl %eax, %edx
0x00416f53:	popl %ebp
0x00416f54:	ret

0x00416ff6:	addl %esp, $0x4<UINT8>
0x00416ff9:	testl %eax, %eax
0x00416ffb:	je 85
0x00416ffd:	movl %eax, 0x8(%ebp)
0x00417000:	subl %eax, $0x400000<UINT32>
0x00417005:	pushl %eax
0x00417006:	pushl $0x400000<UINT32>
0x0041700b:	call 0x00416f60
0x00416f60:	movl %edi, %edi
0x00416f62:	pushl %ebp
0x00416f63:	movl %ebp, %esp
0x00416f65:	movl %eax, 0x8(%ebp)
0x00416f68:	movl %ecx, 0x3c(%eax)
0x00416f6b:	addl %ecx, %eax
0x00416f6d:	movzwl %eax, 0x14(%ecx)
0x00416f71:	pushl %ebx
0x00416f72:	pushl %esi
0x00416f73:	movzwl %esi, 0x6(%ecx)
0x00416f77:	xorl %edx, %edx
0x00416f79:	pushl %edi
0x00416f7a:	leal %eax, 0x18(%eax,%ecx)
0x00416f7e:	testl %esi, %esi
0x00416f80:	jbe 27
0x00416f82:	movl %edi, 0xc(%ebp)
0x00416f85:	movl %ecx, 0xc(%eax)
0x00416f88:	cmpl %edi, %ecx
0x00416f8a:	jb 9
0x00416f8c:	movl %ebx, 0x8(%eax)
0x00416f8f:	addl %ebx, %ecx
0x00416f91:	cmpl %edi, %ebx
0x00416f93:	jb 0x00416f9f
0x00416f9f:	popl %edi
0x00416fa0:	popl %esi
0x00416fa1:	popl %ebx
0x00416fa2:	popl %ebp
0x00416fa3:	ret

0x00417010:	addl %esp, $0x8<UINT8>
0x00417013:	testl %eax, %eax
0x00417015:	je 59
0x00417017:	movl %eax, 0x24(%eax)
0x0041701a:	shrl %eax, $0x1f<UINT8>
0x0041701d:	notl %eax
0x0041701f:	andl %eax, $0x1<UINT8>
0x00417022:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00417029:	movl %ecx, -16(%ebp)
0x0041702c:	movl %fs:0, %ecx
0x00417033:	popl %ecx
0x00417034:	popl %edi
0x00417035:	popl %esi
0x00417036:	popl %ebx
0x00417037:	movl %esp, %ebp
0x00417039:	popl %ebp
0x0041703a:	ret

0x0041ab78:	popl %ecx
0x0041ab79:	testl %eax, %eax
0x0041ab7b:	je 0x0041ab87
0x0041ab87:	call 0x0041db64
0x0041db64:	movl %edi, %edi
0x0041db66:	pushl %esi
0x0041db67:	pushl %edi
0x0041db68:	xorl %edi, %edi
0x0041db6a:	leal %esi, 0x43e3d0(%edi)
0x0041db70:	pushl (%esi)
0x0041db72:	call 0x00418bf6
0x00418c18:	pushl %eax
0x00418c19:	pushl 0x43de4c
0x00418c1f:	call TlsGetValue@KERNEL32.dll
0x00418c21:	call FlsGetValue@KERNEL32.DLL
0x00418c23:	testl %eax, %eax
0x00418c25:	je 8
0x00418c27:	movl %eax, 0x1f8(%eax)
0x00418c2d:	jmp 0x00418c56
0x0041db77:	addl %edi, $0x4<UINT8>
0x0041db7a:	popl %ecx
0x0041db7b:	movl (%esi), %eax
0x0041db7d:	cmpl %edi, $0x28<UINT8>
0x0041db80:	jb 0x0041db6a
0x0041db82:	popl %edi
0x0041db83:	popl %esi
0x0041db84:	ret

0x0041ab8c:	pushl $0x434530<UINT32>
0x0041ab91:	pushl $0x434518<UINT32>
0x0041ab96:	call 0x0041aac4
0x0041aac4:	movl %edi, %edi
0x0041aac6:	pushl %ebp
0x0041aac7:	movl %ebp, %esp
0x0041aac9:	pushl %esi
0x0041aaca:	movl %esi, 0x8(%ebp)
0x0041aacd:	xorl %eax, %eax
0x0041aacf:	jmp 0x0041aae0
0x0041aae0:	cmpl %esi, 0xc(%ebp)
0x0041aae3:	jb 0x0041aad1
0x0041aad1:	testl %eax, %eax
0x0041aad3:	jne 16
0x0041aad5:	movl %ecx, (%esi)
0x0041aad7:	testl %ecx, %ecx
0x0041aad9:	je 0x0041aadd
0x0041aadd:	addl %esi, $0x4<UINT8>
0x0041aadb:	call 0x004212ee
0x00417205:	call 0x004171a3
0x004171a3:	movl %edi, %edi
0x004171a5:	pushl %ebp
0x004171a6:	movl %ebp, %esp
0x004171a8:	subl %esp, $0x18<UINT8>
0x004171ab:	xorl %eax, %eax
0x004171ad:	pushl %ebx
0x004171ae:	movl -4(%ebp), %eax
0x004171b1:	movl -12(%ebp), %eax
0x004171b4:	movl -8(%ebp), %eax
0x004171b7:	pushl %ebx
0x004171b8:	pushfl
0x004171b9:	popl %eax
0x004171ba:	movl %ecx, %eax
0x004171bc:	xorl %eax, $0x200000<UINT32>
0x004171c1:	pushl %eax
0x004171c2:	popfl
0x004171c3:	pushfl
0x004171c4:	popl %edx
0x004171c5:	subl %edx, %ecx
0x004171c7:	je 0x004171e8
0x004171e8:	popl %ebx
0x004171e9:	testl -4(%ebp), $0x4000000<UINT32>
0x004171f0:	je 0x00417200
0x00417200:	xorl %eax, %eax
0x00417202:	popl %ebx
0x00417203:	leave
0x00417204:	ret

0x0041720a:	movl 0x4548a0, %eax
0x0041720f:	xorl %eax, %eax
0x00417211:	ret

0x0041b208:	movl %eax, 0x454860
0x0041b20d:	pushl %esi
0x0041b20e:	pushl $0x14<UINT8>
0x0041b210:	popl %esi
0x0041b211:	testl %eax, %eax
0x0041b213:	jne 7
0x0041b215:	movl %eax, $0x200<UINT32>
0x0041b21a:	jmp 0x0041b222
0x0041b222:	movl 0x454860, %eax
0x0041b227:	pushl $0x4<UINT8>
0x0041b229:	pushl %eax
0x0041b22a:	call 0x0041c255
0x0041b22f:	popl %ecx
0x0041b230:	popl %ecx
0x0041b231:	movl 0x453840, %eax
0x0041b236:	testl %eax, %eax
0x0041b238:	jne 0x0041b258
0x0041b258:	xorl %edx, %edx
0x0041b25a:	movl %ecx, $0x43e038<UINT32>
0x0041b25f:	jmp 0x0041b266
0x0041b266:	movl (%edx,%eax), %ecx
0x0041b269:	addl %ecx, $0x20<UINT8>
0x0041b26c:	addl %edx, $0x4<UINT8>
0x0041b26f:	cmpl %ecx, $0x43e2b8<UINT32>
0x0041b275:	jl 0x0041b261
0x0041b261:	movl %eax, 0x453840
0x0041b277:	pushl $0xfffffffe<UINT8>
0x0041b279:	popl %esi
0x0041b27a:	xorl %edx, %edx
0x0041b27c:	movl %ecx, $0x43e048<UINT32>
0x0041b281:	pushl %edi
0x0041b282:	movl %eax, %edx
0x0041b284:	sarl %eax, $0x5<UINT8>
0x0041b287:	movl %eax, 0x453740(,%eax,4)
0x0041b28e:	movl %edi, %edx
0x0041b290:	andl %edi, $0x1f<UINT8>
0x0041b293:	shll %edi, $0x6<UINT8>
0x0041b296:	movl %eax, (%edi,%eax)
0x0041b299:	cmpl %eax, $0xffffffff<UINT8>
0x0041b29c:	je 8
0x0041b29e:	cmpl %eax, %esi
0x0041b2a0:	je 4
0x0041b2a2:	testl %eax, %eax
0x0041b2a4:	jne 0x0041b2a8
0x0041b2a8:	addl %ecx, $0x20<UINT8>
0x0041b2ab:	incl %edx
0x0041b2ac:	cmpl %ecx, $0x43e0a8<UINT32>
0x0041b2b2:	jl 0x0041b282
0x0041b2b4:	popl %edi
0x0041b2b5:	xorl %eax, %eax
0x0041b2b7:	popl %esi
0x0041b2b8:	ret

0x0042a15f:	movl %edi, %edi
0x0042a161:	pushl %esi
0x0042a162:	pushl $0x4<UINT8>
0x0042a164:	pushl $0x20<UINT8>
0x0042a166:	call 0x0041c255
0x0042a16b:	movl %esi, %eax
0x0042a16d:	pushl %esi
0x0042a16e:	call 0x00418bf6
0x0042a173:	addl %esp, $0xc<UINT8>
0x0042a176:	movl 0x45486c, %eax
0x0042a17b:	movl 0x454868, %eax
0x0042a180:	testl %esi, %esi
0x0042a182:	jne 0x0042a189
0x0042a189:	andl (%esi), $0x0<UINT8>
0x0042a18c:	xorl %eax, %eax
0x0042a18e:	popl %esi
0x0042a18f:	ret

0x004212ee:	pushl $0x4212ac<UINT32>
0x004212f3:	call SetUnhandledExceptionFilter@KERNEL32.dll
SetUnhandledExceptionFilter@KERNEL32.dll: API Node	
0x004212f9:	xorl %eax, %eax
0x004212fb:	ret

0x0041aae5:	popl %esi
0x0041aae6:	popl %ebp
0x0041aae7:	ret

0x0041ab9b:	popl %ecx
0x0041ab9c:	popl %ecx
0x0041ab9d:	testl %eax, %eax
0x0041ab9f:	jne 66
0x0041aba1:	pushl $0x4217fa<UINT32>
0x0041aba6:	call 0x0042a1cc
0x0042a1cc:	movl %edi, %edi
0x0042a1ce:	pushl %ebp
0x0042a1cf:	movl %ebp, %esp
0x0042a1d1:	pushl 0x8(%ebp)
0x0042a1d4:	call 0x0042a190
0x0042a190:	pushl $0xc<UINT8>
0x0042a192:	pushl $0x43afb8<UINT32>
0x0042a197:	call 0x0041a9a0
0x0042a19c:	call 0x0041aa95
0x0041aa95:	pushl $0x8<UINT8>
0x0041aa97:	call 0x0041994e
0x0041aa9c:	popl %ecx
0x0041aa9d:	ret

0x0042a1a1:	andl -4(%ebp), $0x0<UINT8>
0x0042a1a5:	pushl 0x8(%ebp)
0x0042a1a8:	call 0x0042a0a5
0x0042a0a5:	movl %edi, %edi
0x0042a0a7:	pushl %ebp
0x0042a0a8:	movl %ebp, %esp
0x0042a0aa:	pushl %ecx
0x0042a0ab:	pushl %ebx
0x0042a0ac:	pushl %esi
0x0042a0ad:	pushl %edi
0x0042a0ae:	pushl 0x45486c
0x0042a0b4:	call 0x00418c71
0x00418ca2:	movl %eax, 0x1fc(%eax)
0x00418ca8:	jmp 0x00418cd1
0x0042a0b9:	pushl 0x454868
0x0042a0bf:	movl %edi, %eax
0x0042a0c1:	movl -4(%ebp), %edi
0x0042a0c4:	call 0x00418c71
0x0042a0c9:	movl %esi, %eax
0x0042a0cb:	popl %ecx
0x0042a0cc:	popl %ecx
0x0042a0cd:	cmpl %esi, %edi
0x0042a0cf:	jb 131
0x0042a0d5:	movl %ebx, %esi
0x0042a0d7:	subl %ebx, %edi
0x0042a0d9:	leal %eax, 0x4(%ebx)
0x0042a0dc:	cmpl %eax, $0x4<UINT8>
0x0042a0df:	jb 119
0x0042a0e1:	pushl %edi
0x0042a0e2:	call 0x0042de29
0x0042de29:	pushl $0x10<UINT8>
0x0042de2b:	pushl $0x43b280<UINT32>
0x0042de30:	call 0x0041a9a0
0x0042de35:	xorl %eax, %eax
0x0042de37:	movl %ebx, 0x8(%ebp)
0x0042de3a:	xorl %edi, %edi
0x0042de3c:	cmpl %ebx, %edi
0x0042de3e:	setne %al
0x0042de41:	cmpl %eax, %edi
0x0042de43:	jne 0x0042de62
0x0042de62:	cmpl 0x454894, $0x3<UINT8>
0x0042de69:	jne 0x0042dea3
0x0042dea3:	pushl %ebx
0x0042dea4:	pushl %edi
0x0042dea5:	pushl 0x447990
0x0042deab:	call HeapSize@KERNEL32.dll
HeapSize@KERNEL32.dll: API Node	
0x0042deb1:	movl %esi, %eax
0x0042deb3:	movl %eax, %esi
0x0042deb5:	call 0x0041a9e5
0x0042deba:	ret

0x0042a0e7:	movl %edi, %eax
0x0042a0e9:	leal %eax, 0x4(%ebx)
0x0042a0ec:	popl %ecx
0x0042a0ed:	cmpl %edi, %eax
0x0042a0ef:	jae 0x0042a139
0x0042a139:	pushl 0x8(%ebp)
0x0042a13c:	call 0x00418bf6
0x0042a141:	movl (%esi), %eax
0x0042a143:	addl %esi, $0x4<UINT8>
0x0042a146:	pushl %esi
0x0042a147:	call 0x00418bf6
0x0042a14c:	popl %ecx
0x0042a14d:	movl 0x454868, %eax
0x0042a152:	movl %eax, 0x8(%ebp)
0x0042a155:	popl %ecx
0x0042a156:	jmp 0x0042a15a
0x0042a15a:	popl %edi
0x0042a15b:	popl %esi
0x0042a15c:	popl %ebx
0x0042a15d:	leave
0x0042a15e:	ret

0x0042a1ad:	popl %ecx
0x0042a1ae:	movl -28(%ebp), %eax
0x0042a1b1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0042a1b8:	call 0x0042a1c6
0x0042a1c6:	call 0x0041aa9e
0x0041aa9e:	pushl $0x8<UINT8>
0x0041aaa0:	call 0x0041985c
0x0041aaa5:	popl %ecx
0x0041aaa6:	ret

0x0042a1cb:	ret

0x0042a1bd:	movl %eax, -28(%ebp)
0x0042a1c0:	call 0x0041a9e5
0x0042a1c5:	ret

0x0042a1d9:	negl %eax
0x0042a1db:	sbbl %eax, %eax
0x0042a1dd:	negl %eax
0x0042a1df:	popl %ecx
0x0042a1e0:	decl %eax
0x0042a1e1:	popl %ebp
0x0042a1e2:	ret

0x0041abab:	movl %eax, $0x434510<UINT32>
0x0041abb0:	movl (%esp), $0x434514<UINT32>
0x0041abb7:	call 0x0041aaa7
0x0041aaa7:	movl %edi, %edi
0x0041aaa9:	pushl %ebp
0x0041aaaa:	movl %ebp, %esp
0x0041aaac:	pushl %esi
0x0041aaad:	movl %esi, %eax
0x0041aaaf:	jmp 0x0041aabc
0x0041aabc:	cmpl %esi, 0x8(%ebp)
0x0041aabf:	jb 0x0041aab1
0x0041aab1:	movl %eax, (%esi)
0x0041aab3:	testl %eax, %eax
0x0041aab5:	je 0x0041aab9
0x0041aab9:	addl %esi, $0x4<UINT8>
0x0041aac1:	popl %esi
0x0041aac2:	popl %ebp
0x0041aac3:	ret

0x0041abbc:	cmpl 0x454874, $0x0<UINT8>
0x0041abc3:	popl %ecx
0x0041abc4:	je 0x0041abe1
0x0041abe1:	xorl %eax, %eax
0x0041abe3:	popl %ebp
0x0041abe4:	ret

0x004156c0:	popl %ecx
0x004156c1:	cmpl %eax, %esi
0x004156c3:	je 0x004156cc
0x004156cc:	call 0x004212fc
0x004212fc:	movl %edi, %edi
0x004212fe:	pushl %esi
0x004212ff:	pushl %edi
0x00421300:	xorl %edi, %edi
0x00421302:	cmpl 0x454870, %edi
0x00421308:	jne 0x0042130f
0x0042130f:	movl %esi, 0x4548a4
0x00421315:	testl %esi, %esi
0x00421317:	jne 0x0042131e
0x0042131e:	movb %al, (%esi)
0x00421320:	cmpb %al, $0x20<UINT8>
0x00421322:	ja 0x0042132c
0x0042132c:	cmpb %al, $0x22<UINT8>
0x0042132e:	jne 0x00421339
0x00421330:	xorl %ecx, %ecx
0x00421332:	testl %edi, %edi
0x00421334:	sete %cl
0x00421337:	movl %edi, %ecx
0x00421339:	movzbl %eax, %al
0x0042133c:	pushl %eax
0x0042133d:	call 0x0042d032
0x00421342:	popl %ecx
0x00421343:	testl %eax, %eax
0x00421345:	je 0x00421348
0x00421348:	incl %esi
0x00421349:	jmp 0x0042131e
0x00421324:	testb %al, %al
0x00421326:	je 0x00421356
0x00421356:	popl %edi
0x00421357:	movl %eax, %esi
0x00421359:	popl %esi
0x0042135a:	ret

0x004156d1:	testb -60(%ebp), %bl
0x004156d4:	je 0x004156dc
0x004156dc:	pushl $0xa<UINT8>
0x004156de:	popl %ecx
0x004156df:	pushl %ecx
0x004156e0:	pushl %eax
0x004156e1:	pushl %esi
0x004156e2:	pushl $0x400000<UINT32>
0x004156e7:	call 0x00408770
0x00408770:	subl %esp, $0x248<UINT32>
0x00408776:	movl %eax, 0x43d68c
0x0040877b:	xorl %eax, %esp
0x0040877d:	movl 0x244(%esp), %eax
0x00408784:	movl %eax, 0x24c(%esp)
0x0040878b:	pushl %ebx
0x0040878c:	pushl %esi
0x0040878d:	movl %esi, 0x25c(%esp)
0x00408794:	leal %ecx, 0x1c(%esp)
0x00408798:	pushl %ecx
0x00408799:	movl 0xc(%esp), %eax
0x0040879d:	movl 0x10(%esp), %esi
0x004087a1:	xorb %bl, %bl
0x004087a3:	call GetCommandLineW@KERNEL32.dll
GetCommandLineW@KERNEL32.dll: API Node	
0x004087a9:	pushl %eax
0x004087aa:	call CommandLineToArgvW@SHELL32.dll
CommandLineToArgvW@SHELL32.dll: API Node	
0x004087b0:	pushl %eax
0x004087b1:	leal %edx, 0x20(%esp)
0x004087b5:	pushl %edx
0x004087b6:	pushl $0x435d84<UINT32>
0x004087bb:	call 0x0040b430
0x0040b430:	pushl %ebx
0x0040b431:	movl %ebx, 0xc(%esp)
0x0040b435:	pushl %ebp
0x0040b436:	pushl %esi
0x0040b437:	xorl %ebp, %ebp
0x0040b439:	pushl %edi
0x0040b43a:	testl %ebx, %ebx
0x0040b43c:	je 8
0x0040b43e:	movl %edi, 0x1c(%esp)
0x0040b442:	testl %edi, %edi
0x0040b444:	jne 0x0040b474
0x0040b474:	xorl %esi, %esi
0x0040b476:	cmpl (%ebx), %ebp
0x0040b478:	jle 0x0040b4d1
0x0040b4d1:	movl %edx, 0x14(%esp)
0x0040b4d5:	pushl %ebp
0x0040b4d6:	pushl %edx
0x0040b4d7:	call 0x0040b0a0
0x0040b0a0:	subl %esp, $0x110<UINT32>
0x0040b0a6:	movl %eax, 0x43d68c
0x0040b0ab:	xorl %eax, %esp
0x0040b0ad:	movl 0x10c(%esp), %eax
0x0040b0b4:	pushl %ebp
0x0040b0b5:	movl %ebp, 0x118(%esp)
0x0040b0bc:	pushl %ebp
0x0040b0bd:	leal %eax, 0x10(%esp)
0x0040b0c1:	pushl $0x4386a4<UINT32>
0x0040b0c6:	pushl %eax
0x0040b0c7:	movl 0x10(%esp), $0x0<UINT32>
0x0040b0cf:	call 0x00412522
0x00412522:	movl %edi, %edi
0x00412524:	pushl %ebp
0x00412525:	movl %ebp, %esp
0x00412527:	subl %esp, $0x20<UINT8>
0x0041252a:	pushl %ebx
0x0041252b:	xorl %ebx, %ebx
0x0041252d:	cmpl 0xc(%ebp), %ebx
0x00412530:	jne 0x0041254f
0x0041254f:	movl %eax, 0x8(%ebp)
0x00412552:	cmpl %eax, %ebx
0x00412554:	je -36
0x00412556:	pushl %esi
0x00412557:	movl -24(%ebp), %eax
0x0041255a:	movl -32(%ebp), %eax
0x0041255d:	leal %eax, 0x10(%ebp)
0x00412560:	pushl %eax
0x00412561:	pushl %ebx
0x00412562:	pushl 0xc(%ebp)
0x00412565:	leal %eax, -32(%ebp)
0x00412568:	pushl %eax
0x00412569:	movl -28(%ebp), $0x7fffffff<UINT32>
0x00412570:	movl -20(%ebp), $0x42<UINT32>
0x00412577:	call 0x004159a5
0x004159a5:	movl %edi, %edi
0x004159a7:	pushl %ebp
0x004159a8:	movl %ebp, %esp
0x004159aa:	subl %esp, $0x278<UINT32>
0x004159b0:	movl %eax, 0x43d68c
0x004159b5:	xorl %eax, %ebp
0x004159b7:	movl -4(%ebp), %eax
0x004159ba:	pushl %ebx
0x004159bb:	movl %ebx, 0xc(%ebp)
0x004159be:	pushl %esi
0x004159bf:	movl %esi, 0x8(%ebp)
0x004159c2:	xorl %eax, %eax
0x004159c4:	pushl %edi
0x004159c5:	movl %edi, 0x14(%ebp)
0x004159c8:	pushl 0x10(%ebp)
0x004159cb:	leal %ecx, -604(%ebp)
0x004159d1:	movl -588(%ebp), %esi
0x004159d7:	movl -548(%ebp), %edi
0x004159dd:	movl -584(%ebp), %eax
0x004159e3:	movl -528(%ebp), %eax
0x004159e9:	movl -564(%ebp), %eax
0x004159ef:	movl -536(%ebp), %eax
0x004159f5:	movl -560(%ebp), %eax
0x004159fb:	movl -576(%ebp), %eax
0x00415a01:	movl -568(%ebp), %eax
0x00415a07:	call 0x00412991
0x00415a0c:	testl %esi, %esi
0x00415a0e:	jne 0x00415a45
0x00415a45:	testb 0xc(%esi), $0x40<UINT8>
0x00415a49:	jne 0x00415aa9
0x00415aa9:	xorl %ecx, %ecx
0x00415aab:	cmpl %ebx, %ecx
0x00415aad:	je -163
0x00415ab3:	movb %dl, (%ebx)
0x00415ab5:	movl -552(%ebp), %ecx
0x00415abb:	movl -544(%ebp), %ecx
0x00415ac1:	movl -580(%ebp), %ecx
0x00415ac7:	movb -529(%ebp), %dl
0x00415acd:	testb %dl, %dl
0x00415acf:	je 2591
0x00415ad5:	incl %ebx
0x00415ad6:	cmpl -552(%ebp), $0x0<UINT8>
0x00415add:	movl -572(%ebp), %ebx
0x00415ae3:	jl 2571
0x00415ae9:	movb %al, %dl
0x00415aeb:	subb %al, $0x20<UINT8>
0x00415aed:	cmpb %al, $0x58<UINT8>
0x00415aef:	ja 0x00415b02
0x00415af1:	movsbl %eax, %dl
0x00415af4:	movsbl %eax, 0x438e20(%eax)
0x00415afb:	andl %eax, $0xf<UINT8>
0x00415afe:	xorl %esi, %esi
0x00415b00:	jmp 0x00415b06
0x00415b06:	movsbl %eax, 0x438e40(%ecx,%eax,8)
0x00415b0e:	pushl $0x7<UINT8>
0x00415b10:	sarl %eax, $0x4<UINT8>
0x00415b13:	popl %ecx
0x00415b14:	movl -620(%ebp), %eax
0x00415b1a:	cmpl %eax, %ecx
0x00415b1c:	ja 2477
0x00415b22:	jmp 0x00415d82
0x00415d28:	leal %eax, -604(%ebp)
0x00415d2e:	pushl %eax
0x00415d2f:	movzbl %eax, %dl
0x00415d32:	pushl %eax
0x00415d33:	movl -568(%ebp), %esi
0x00415d39:	call 0x0041cccb
0x0041cccb:	movl %edi, %edi
0x0041cccd:	pushl %ebp
0x0041ccce:	movl %ebp, %esp
0x0041ccd0:	subl %esp, $0x10<UINT8>
0x0041ccd3:	pushl 0xc(%ebp)
0x0041ccd6:	leal %ecx, -16(%ebp)
0x0041ccd9:	call 0x00412991
0x00412a07:	movl %ecx, (%eax)
0x00412a09:	movl (%esi), %ecx
0x00412a0b:	movl %eax, 0x4(%eax)
0x00412a0e:	movl 0x4(%esi), %eax
0x0041ccde:	movzbl %eax, 0x8(%ebp)
0x0041cce2:	movl %ecx, -16(%ebp)
0x0041cce5:	movl %ecx, 0xc8(%ecx)
0x0041cceb:	movzwl %eax, (%ecx,%eax,2)
0x0041ccef:	andl %eax, $0x8000<UINT32>
0x0041ccf4:	cmpb -4(%ebp), $0x0<UINT8>
0x0041ccf8:	je 0x0041cd01
0x0041cd01:	leave
0x0041cd02:	ret

0x00415d3e:	popl %ecx
0x00415d3f:	testl %eax, %eax
0x00415d41:	movb %al, -529(%ebp)
0x00415d47:	popl %ecx
0x00415d48:	je 0x00415d6c
0x00415d6c:	movl %ecx, -588(%ebp)
0x00415d72:	leal %esi, -552(%ebp)
0x00415d78:	call 0x004158c5
0x004158c5:	testb 0xc(%ecx), $0x40<UINT8>
0x004158c9:	je 6
0x004158cb:	cmpl 0x8(%ecx), $0x0<UINT8>
0x004158cf:	je 36
0x004158d1:	decl 0x4(%ecx)
0x004158d4:	js 11
0x004158d6:	movl %edx, (%ecx)
0x004158d8:	movb (%edx), %al
0x004158da:	incl (%ecx)
0x004158dc:	movzbl %eax, %al
0x004158df:	jmp 0x004158ed
0x004158ed:	cmpl %eax, $0xffffffff<UINT8>
0x004158f0:	jne 0x004158f5
0x004158f5:	incl (%esi)
0x004158f7:	ret

0x00415d7d:	jmp 0x004164cf
0x004164cf:	movl %ebx, -572(%ebp)
0x004164d5:	movb %al, (%ebx)
0x004164d7:	movb -529(%ebp), %al
0x004164dd:	testb %al, %al
0x004164df:	je 0x004164f4
0x004164e1:	movl %ecx, -620(%ebp)
0x004164e7:	movl %edi, -548(%ebp)
0x004164ed:	movb %dl, %al
0x004164ef:	jmp 0x00415ad5
0x00415b02:	xorl %esi, %esi
0x00415b04:	xorl %eax, %eax
0x00415b29:	orl -536(%ebp), $0xffffffff<UINT8>
0x00415b30:	movl -624(%ebp), %esi
0x00415b36:	movl -576(%ebp), %esi
0x00415b3c:	movl -564(%ebp), %esi
0x00415b42:	movl -560(%ebp), %esi
0x00415b48:	movl -528(%ebp), %esi
0x00415b4e:	movl -568(%ebp), %esi
0x00415b54:	jmp 0x004164cf
0x00415d82:	movsbl %eax, %dl
0x00415d85:	cmpl %eax, $0x64<UINT8>
0x00415d88:	jg 0x00415f76
0x00415f76:	cmpl %eax, $0x70<UINT8>
0x00415f79:	jg 0x0041617a
0x0041617a:	subl %eax, $0x73<UINT8>
0x0041617d:	je 0x00415e39
0x00415e39:	movl %ecx, -536(%ebp)
0x00415e3f:	cmpl %ecx, $0xffffffff<UINT8>
0x00415e42:	jne 5
0x00415e44:	movl %ecx, $0x7fffffff<UINT32>
0x00415e49:	addl %edi, $0x4<UINT8>
0x00415e4c:	testl -528(%ebp), $0x810<UINT32>
0x00415e56:	movl -548(%ebp), %edi
0x00415e5c:	movl %edi, -4(%edi)
0x00415e5f:	movl -540(%ebp), %edi
0x00415e65:	je 0x0041631c
0x0041631c:	cmpl %edi, %esi
0x0041631e:	jne 0x0041632b
0x0041632b:	movl %eax, -540(%ebp)
0x00416331:	jmp 0x0041633a
0x0041633a:	cmpl %ecx, %esi
0x0041633c:	jne 0x00416333
0x00416333:	decl %ecx
0x00416334:	cmpb (%eax), $0x0<UINT8>
0x00416337:	je 0x0041633e
0x00416339:	incl %eax
0x0041633e:	subl %eax, -540(%ebp)
0x00416344:	movl -544(%ebp), %eax
0x0041634a:	cmpl -576(%ebp), $0x0<UINT8>
0x00416351:	jne 348
0x00416357:	movl %eax, -528(%ebp)
0x0041635d:	testb %al, $0x40<UINT8>
0x0041635f:	je 0x00416393
0x00416393:	movl %ebx, -564(%ebp)
0x00416399:	subl %ebx, -544(%ebp)
0x0041639f:	subl %ebx, -560(%ebp)
0x004163a5:	testb -528(%ebp), $0xc<UINT8>
0x004163ac:	jne 23
0x004163ae:	pushl -588(%ebp)
0x004163b4:	leal %eax, -552(%ebp)
0x004163ba:	pushl %ebx
0x004163bb:	pushl $0x20<UINT8>
0x004163bd:	call 0x004158f8
0x004158f8:	movl %edi, %edi
0x004158fa:	pushl %ebp
0x004158fb:	movl %ebp, %esp
0x004158fd:	pushl %esi
0x004158fe:	movl %esi, %eax
0x00415900:	jmp 0x00415915
0x00415915:	cmpl 0xc(%ebp), $0x0<UINT8>
0x00415919:	jg -25
0x0041591b:	popl %esi
0x0041591c:	popl %ebp
0x0041591d:	ret

0x004163c2:	addl %esp, $0xc<UINT8>
0x004163c5:	pushl -560(%ebp)
0x004163cb:	movl %edi, -588(%ebp)
0x004163d1:	leal %eax, -552(%ebp)
0x004163d7:	leal %ecx, -556(%ebp)
0x004163dd:	call 0x0041591e
0x0041591e:	movl %edi, %edi
0x00415920:	pushl %ebp
0x00415921:	movl %ebp, %esp
0x00415923:	testb 0xc(%edi), $0x40<UINT8>
0x00415927:	pushl %ebx
0x00415928:	pushl %esi
0x00415929:	movl %esi, %eax
0x0041592b:	movl %ebx, %ecx
0x0041592d:	je 50
0x0041592f:	cmpl 0x8(%edi), $0x0<UINT8>
0x00415933:	jne 0x00415961
0x00415961:	cmpl 0x8(%ebp), $0x0<UINT8>
0x00415965:	jg 0x0041593c
0x00415967:	popl %esi
0x00415968:	popl %ebx
0x00415969:	popl %ebp
0x0041596a:	ret

0x004163e2:	testb -528(%ebp), $0x8<UINT8>
0x004163e9:	popl %ecx
0x004163ea:	je 0x00416407
0x00416407:	cmpl -568(%ebp), $0x0<UINT8>
0x0041640e:	movl %eax, -544(%ebp)
0x00416414:	je 0x0041647c
0x0041647c:	movl %ecx, -540(%ebp)
0x00416482:	pushl %eax
0x00416483:	leal %eax, -552(%ebp)
0x00416489:	call 0x0041591e
0x0041593c:	movb %al, (%ebx)
0x0041593e:	decl 0x8(%ebp)
0x00415941:	movl %ecx, %edi
0x00415943:	call 0x004158c5
0x00415948:	incl %ebx
0x00415949:	cmpl (%esi), $0xffffffff<UINT8>
0x0041594c:	jne 0x00415961
0x0041648e:	popl %ecx
0x0041648f:	cmpl -552(%ebp), $0x0<UINT8>
0x00416496:	jl 27
0x00416498:	testb -528(%ebp), $0x4<UINT8>
0x0041649f:	je 0x004164b3
0x004164b3:	cmpl -580(%ebp), $0x0<UINT8>
0x004164ba:	je 0x004164cf
0x004164f4:	cmpb -592(%ebp), $0x0<UINT8>
0x004164fb:	je 10
0x004164fd:	movl %eax, -596(%ebp)
0x00416503:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x00416507:	movl %eax, -552(%ebp)
0x0041650d:	movl %ecx, -4(%ebp)
0x00416510:	popl %edi
0x00416511:	popl %esi
0x00416512:	xorl %ecx, %ebp
0x00416514:	popl %ebx
0x00416515:	call 0x004126d4
0x0041651a:	leave
0x0041651b:	ret

0x0041257c:	addl %esp, $0x10<UINT8>
0x0041257f:	decl -28(%ebp)
0x00412582:	movl %esi, %eax
0x00412584:	js 7
0x00412586:	movl %eax, -32(%ebp)
0x00412589:	movb (%eax), %bl
0x0041258b:	jmp 0x00412599
0x00412599:	movl %eax, %esi
0x0041259b:	popl %esi
0x0041259c:	popl %ebx
0x0041259d:	leave
0x0041259e:	ret

0x0040b0d4:	addl %esp, $0xc<UINT8>
0x0040b0d7:	leal %ecx, 0x4(%esp)
0x0040b0db:	pushl %ecx
0x0040b0dc:	leal %edx, 0x10(%esp)
0x0040b0e0:	pushl %edx
0x0040b0e1:	pushl $0x80000001<UINT32>
0x0040b0e6:	call RegCreateKeyA@ADVAPI32.dll
RegCreateKeyA@ADVAPI32.dll: API Node	
0x0040b0ec:	testl %eax, %eax
0x0040b0ee:	jne 41
0x0040b0f0:	movl %edx, 0x4(%esp)
0x0040b0f4:	leal %eax, 0x8(%esp)
0x0040b0f8:	pushl %eax
0x0040b0f9:	leal %ecx, 0x120(%esp)
0x0040b100:	pushl %ecx
0x0040b101:	pushl $0x0<UINT8>
0x0040b103:	pushl $0x0<UINT8>
0x0040b105:	pushl $0x438694<UINT32>
0x0040b10a:	pushl %edx
0x0040b10b:	movl 0x20(%esp), $0x4<UINT32>
0x0040b113:	call RegQueryValueExA@ADVAPI32.dll
RegQueryValueExA@ADVAPI32.dll: API Node	
0x0040b119:	cmpl 0x11c(%esp), $0x0<UINT8>
0x0040b121:	jne 694
0x0040b127:	pushl %ebx
0x0040b128:	pushl %esi
0x0040b129:	pushl %edi
0x0040b12a:	pushl $0x3e8<UINT32>
0x0040b12f:	pushl $0x40<UINT8>
0x0040b131:	call LocalAlloc@KERNEL32.dll
LocalAlloc@KERNEL32.dll: API Node	
0x0040b137:	movl %esi, %eax
0x0040b139:	pushl $0x438684<UINT32>
0x0040b13e:	leal %edi, 0x12(%esi)
0x0040b141:	call LoadLibraryA@KERNEL32.dll
0x0040b147:	xorl %eax, %eax
0x0040b149:	movw 0xa(%esi), %ax
0x00412720:	movl %edi, %edi
0x00412722:	pushl %ebp
0x00412723:	movl %ebp, %esp
0x00412725:	subl %esp, $0x18<UINT8>
0x00412728:	pushl %ebx
0x00412729:	movl %ebx, 0xc(%ebp)
0x0041272c:	pushl %esi
0x0041272d:	movl %esi, 0x8(%ebx)
0x00412730:	xorl %esi, 0x43d68c
0x00412736:	pushl %edi
0x00412737:	movl %eax, (%esi)
0x00412739:	movb -1(%ebp), $0x0<UINT8>
0x0041273d:	movl -12(%ebp), $0x1<UINT32>
0x00412744:	leal %edi, 0x10(%ebx)
0x00412747:	cmpl %eax, $0xfffffffe<UINT8>
0x0041274a:	je 0x00412759
0x00412759:	movl %ecx, 0xc(%esi)
0x0041275c:	movl %eax, 0x8(%esi)
0x0041275f:	addl %ecx, %edi
0x00412761:	xorl %ecx, (%eax,%edi)
0x00412764:	call 0x004126d4
0x00412769:	movl %eax, 0x8(%ebp)
0x0041276c:	testb 0x4(%eax), $0x66<UINT8>
0x00412770:	jne 278
0x00412776:	movl %ecx, 0x10(%ebp)
0x00412779:	leal %edx, -24(%ebp)
0x0041277c:	movl -4(%ebx), %edx
0x0041277f:	movl %ebx, 0xc(%ebx)
0x00412782:	movl -24(%ebp), %eax
0x00412785:	movl -20(%ebp), %ecx
0x00412788:	cmpl %ebx, $0xfffffffe<UINT8>
0x0041278b:	je 95
0x0041278d:	leal %ecx, (%ecx)
0x00412790:	leal %eax, (%ebx,%ebx,2)
0x00412793:	movl %ecx, 0x14(%esi,%eax,4)
0x00412797:	leal %eax, 0x10(%esi,%eax,4)
0x0041279b:	movl -16(%ebp), %eax
0x0041279e:	movl %eax, (%eax)
0x004127a0:	movl -8(%ebp), %eax
0x004127a3:	testl %ecx, %ecx
0x004127a5:	je 20
0x004127a7:	movl %edx, %edi
0x004127a9:	call 0x00416eb6
0x00416eb6:	pushl %ebp
0x00416eb7:	pushl %esi
0x00416eb8:	pushl %edi
0x00416eb9:	pushl %ebx
0x00416eba:	movl %ebp, %edx
0x00416ebc:	xorl %eax, %eax
0x00416ebe:	xorl %ebx, %ebx
0x00416ec0:	xorl %edx, %edx
0x00416ec2:	xorl %esi, %esi
0x00416ec4:	xorl %edi, %edi
0x00416ec6:	call 0x00415704
0x00415704:	movl %eax, -20(%ebp)
0x00415707:	movl %ecx, (%eax)
0x00415709:	movl %ecx, (%ecx)
0x0041570b:	movl -36(%ebp), %ecx
0x0041570e:	pushl %eax
0x0041570f:	pushl %ecx
0x00415710:	call 0x0041c055
0x0041c055:	movl %edi, %edi
0x0041c057:	pushl %ebp
0x0041c058:	movl %ebp, %esp
0x0041c05a:	pushl %ecx
0x0041c05b:	pushl %ecx
0x0041c05c:	pushl %esi
0x0041c05d:	call 0x00418e81
0x0041c062:	movl %esi, %eax
0x0041c064:	testl %esi, %esi
0x0041c066:	je 326
0x0041c06c:	movl %edx, 0x5c(%esi)
0x0041c06f:	movl %eax, 0x43e3c4
0x0041c074:	pushl %edi
0x0041c075:	movl %edi, 0x8(%ebp)
0x0041c078:	movl %ecx, %edx
0x0041c07a:	pushl %ebx
0x0041c07b:	cmpl (%ecx), %edi
0x0041c07d:	je 0x0041c08d
0x0041c08d:	imull %eax, %eax, $0xc<UINT8>
0x0041c090:	addl %eax, %edx
0x0041c092:	cmpl %ecx, %eax
0x0041c094:	jae 8
0x0041c096:	cmpl (%ecx), %edi
0x0041c098:	jne 4
0x0041c09a:	movl %eax, %ecx
0x0041c09c:	jmp 0x0041c0a0
0x0041c0a0:	testl %eax, %eax
0x0041c0a2:	je 10
0x0041c0a4:	movl %ebx, 0x8(%eax)
0x0041c0a7:	movl -4(%ebp), %ebx
0x0041c0aa:	testl %ebx, %ebx
0x0041c0ac:	jne 7
0x0041c0ae:	xorl %eax, %eax
0x0041c0b0:	jmp 0x0041c1b0
0x0041c1b0:	popl %ebx
0x0041c1b1:	popl %edi
0x0041c1b2:	popl %esi
0x0041c1b3:	leave
0x0041c1b4:	ret

0x00415715:	popl %ecx
0x00415716:	popl %ecx
0x00415717:	ret

0x00416ec8:	popl %ebx
0x00416ec9:	popl %edi
0x00416eca:	popl %esi
0x00416ecb:	popl %ebp
0x00416ecc:	ret

0x004127ae:	movb -1(%ebp), $0x1<UINT8>
0x004127b2:	testl %eax, %eax
0x004127b4:	jl 64
0x004127b6:	jg 71
0x004127b8:	movl %eax, -8(%ebp)
0x004127bb:	movl %ebx, %eax
0x004127bd:	cmpl %eax, $0xfffffffe<UINT8>
0x004127c0:	jne -50
0x004127c2:	cmpb -1(%ebp), $0x0<UINT8>
0x004127c6:	je 36
0x004127c8:	movl %eax, (%esi)
0x004127ca:	cmpl %eax, $0xfffffffe<UINT8>
0x004127cd:	je 0x004127dc
0x004127dc:	movl %ecx, 0xc(%esi)
0x004127df:	movl %edx, 0x8(%esi)
0x004127e2:	addl %ecx, %edi
0x004127e4:	xorl %ecx, (%edx,%edi)
0x004127e7:	call 0x004126d4
0x004127ec:	movl %eax, -12(%ebp)
0x004127ef:	popl %edi
0x004127f0:	popl %esi
0x004127f1:	popl %ebx
0x004127f2:	movl %esp, %ebp
0x004127f4:	popl %ebp
0x004127f5:	ret

0x0040b14d:	xorl %ecx, %ecx
0x0040b14f:	movl %edx, $0x138<UINT32>
0x0040b154:	movw 0xe(%esi), %dx
0x0040b158:	movw 0xc(%esi), %cx
0x0040b15c:	movl %eax, $0xb4<UINT32>
0x0040b161:	movw 0x10(%esi), %ax
0x0040b165:	movw 0x8(%esi), %cx
0x0040b169:	movl (%esi), $0x80c808d0<UINT32>
0x0040b16f:	xorl %edx, %edx
0x0040b171:	movw (%edi), %dx
0x0040b174:	addl %edi, $0x2<UINT8>
0x0040b177:	xorl %eax, %eax
0x0040b179:	movw (%edi), %ax
0x0040b17c:	addl %edi, $0x2<UINT8>
0x0040b17f:	pushl %edi
0x0040b180:	movl %ecx, $0x438660<UINT32>
0x0040b185:	call 0x0040b060
0x0040b060:	movl %eax, %ecx
0x0040b062:	pushl %esi
0x0040b063:	leal %esi, 0x2(%eax)
0x0040b066:	movw %dx, (%eax)
0x0040b069:	addl %eax, $0x2<UINT8>
0x0040b06c:	testw %dx, %dx
0x0040b06f:	jne 0x0040b066
0x0040b071:	subl %eax, %esi
0x0040b073:	movl %esi, 0x8(%esp)
0x0040b077:	sarl %eax
0x0040b079:	incl %eax
0x0040b07a:	subl %esi, %ecx
0x0040b07c:	leal %esp, (%esp)
0x0040b080:	movzwl %edx, (%ecx)
0x0040b083:	movw (%esi,%ecx), %dx
0x0040b087:	addl %ecx, $0x2<UINT8>
0x0040b08a:	testw %dx, %dx
0x0040b08d:	jne 0x0040b080
0x0040b08f:	popl %esi
0x0040b090:	ret

0x0040b18a:	leal %edi, (%edi,%eax,2)
0x0040b18d:	movl %ecx, $0x8<UINT32>
0x0040b192:	movw (%edi), %cx
0x0040b195:	addl %edi, $0x2<UINT8>
0x0040b198:	pushl %edi
0x0040b199:	movl %ecx, $0x438644<UINT32>
0x0040b19e:	call 0x0040b060
0x0040b1a3:	leal %eax, (%edi,%eax,2)
0x0040b1a6:	call 0x0040b050
0x0040b050:	addl %eax, $0x3<UINT8>
0x0040b053:	andl %eax, $0xfffffffc<UINT8>
0x0040b056:	ret

0x0040b1ab:	movl %edx, $0x7<UINT32>
0x0040b1b0:	movw 0x8(%eax), %dx
0x0040b1b4:	movl %ecx, $0x3<UINT32>
0x0040b1b9:	movw 0xa(%eax), %cx
0x0040b1bd:	movl %edx, $0x12a<UINT32>
0x0040b1c2:	movw 0xc(%eax), %dx
0x0040b1c6:	movl %ecx, $0xe<UINT32>
0x0040b1cb:	movw 0xe(%eax), %cx
0x0040b1cf:	movl %edx, $0x1f6<UINT32>
0x0040b1d4:	movw 0x10(%eax), %dx
0x0040b1d8:	movl (%eax), $0x50000000<UINT32>
0x0040b1de:	leal %edi, 0x12(%eax)
0x0040b1e1:	movl %eax, $0xffff<UINT32>
0x0040b1e6:	movw (%edi), %ax
0x0040b1e9:	addl %edi, $0x2<UINT8>
0x0040b1ec:	movl %ecx, $0x82<UINT32>
0x0040b1f1:	movw (%edi), %cx
0x0040b1f4:	addl %edi, $0x2<UINT8>
0x0040b1f7:	pushl %edi
0x0040b1f8:	movl %ecx, $0x4385b0<UINT32>
0x0040b1fd:	call 0x0040b060
0x0040b202:	leal %eax, (%edi,%eax,2)
0x0040b205:	xorl %edx, %edx
0x0040b207:	movw (%eax), %dx
0x0040b20a:	movl %ebx, $0x1<UINT32>
0x0040b20f:	addw 0x8(%esi), %bx
0x0040b213:	addl %eax, $0x2<UINT8>
0x0040b216:	call 0x0040b050
0x0040b21b:	movl %ecx, $0xc9<UINT32>
0x0040b220:	movw 0x8(%eax), %cx
0x0040b224:	movl %edx, $0x9f<UINT32>
0x0040b229:	movw 0xa(%eax), %dx
0x0040b22d:	movl %ecx, $0x32<UINT32>
0x0040b232:	movl %edx, $0xe<UINT32>
0x0040b237:	movw 0xc(%eax), %cx
0x0040b23b:	movw 0xe(%eax), %dx
0x0040b23f:	movl %ecx, %ebx
0x0040b241:	leal %edi, 0x12(%eax)
0x0040b244:	movl %edx, $0xffff<UINT32>
0x0040b249:	movw 0x10(%eax), %cx
0x0040b24d:	movl (%eax), $0x50010000<UINT32>
0x0040b253:	movw (%edi), %dx
0x0040b256:	addl %edi, $0x2<UINT8>
0x0040b259:	movl %eax, $0x80<UINT32>
0x0040b25e:	movw (%edi), %ax
0x0040b261:	addl %edi, $0x2<UINT8>
0x0040b264:	pushl %edi
0x0040b265:	movl %ecx, $0x4385a0<UINT32>
0x0040b26a:	call 0x0040b060
0x0040b26f:	leal %eax, (%edi,%eax,2)
0x0040b272:	xorl %ecx, %ecx
0x0040b274:	movw (%eax), %cx
0x0040b277:	addw 0x8(%esi), %bx
0x0040b27b:	addl %eax, $0x2<UINT8>
0x0040b27e:	call 0x0040b050
0x0040b283:	movl %edx, $0xff<UINT32>
0x0040b288:	movw 0x8(%eax), %dx
0x0040b28c:	movl %ecx, $0x9f<UINT32>
0x0040b291:	movw 0xa(%eax), %cx
0x0040b295:	movl %edx, $0x32<UINT32>
0x0040b29a:	movw 0xc(%eax), %dx
0x0040b29e:	movl %edx, $0x2<UINT32>
0x0040b2a3:	movl %ecx, $0xe<UINT32>
0x0040b2a8:	movw 0xe(%eax), %cx
0x0040b2ac:	movw 0x10(%eax), %dx
0x0040b2b0:	movl (%eax), $0x50010000<UINT32>
0x0040b2b6:	leal %edi, 0x12(%eax)
0x0040b2b9:	movl %eax, $0xffff<UINT32>
0x0040b2be:	movw (%edi), %ax
0x0040b2c1:	addl %edi, %edx
0x0040b2c3:	movl %ecx, $0x80<UINT32>
0x0040b2c8:	movw (%edi), %cx
0x0040b2cb:	addl %edi, %edx
0x0040b2cd:	pushl %edi
0x0040b2ce:	movl %ecx, $0x43858c<UINT32>
0x0040b2d3:	call 0x0040b060
0x0040b2d8:	leal %eax, (%edi,%eax,2)
0x0040b2db:	xorl %edx, %edx
0x0040b2dd:	movw (%eax), %dx
0x0040b2e0:	addw 0x8(%esi), %bx
0x0040b2e4:	addl %eax, $0x2<UINT8>
0x0040b2e7:	call 0x0040b050
0x0040b2ec:	movl %ecx, $0x7<UINT32>
0x0040b2f1:	movw 0x8(%eax), %cx
0x0040b2f5:	movl %edx, $0x9f<UINT32>
0x0040b2fa:	movw 0xa(%eax), %dx
0x0040b2fe:	movl %ecx, $0x32<UINT32>
0x0040b303:	movw 0xc(%eax), %cx
0x0040b307:	movl %edx, $0xe<UINT32>
0x0040b30c:	movw 0xe(%eax), %dx
0x0040b310:	leal %edi, 0x12(%eax)
0x0040b313:	movl %ecx, $0x1f5<UINT32>
0x0040b318:	movw 0x10(%eax), %cx
0x0040b31c:	movl (%eax), $0x50010000<UINT32>
0x0040b322:	movl %edx, $0xffff<UINT32>
0x0040b327:	movw (%edi), %dx
0x0040b32a:	addl %edi, $0x2<UINT8>
0x0040b32d:	movl %eax, $0x80<UINT32>
0x0040b332:	movw (%edi), %ax
0x0040b335:	addl %edi, $0x2<UINT8>
0x0040b338:	pushl %edi
0x0040b339:	movl %ecx, $0x43857c<UINT32>
0x0040b33e:	call 0x0040b060
0x0040b343:	leal %eax, (%edi,%eax,2)
0x0040b346:	xorl %ecx, %ecx
0x0040b348:	movw (%eax), %cx
0x0040b34b:	addw 0x8(%esi), %bx
0x0040b34f:	addl %eax, $0x2<UINT8>
0x0040b352:	call 0x0040b050
0x0040b357:	movl %edx, $0x7<UINT32>
0x0040b35c:	movw 0x8(%eax), %dx
0x0040b360:	movl %ecx, $0xe<UINT32>
0x0040b365:	movw 0xa(%eax), %cx
0x0040b369:	movl %edx, $0x12a<UINT32>
0x0040b36e:	movl %ecx, $0x8c<UINT32>
0x0040b373:	movw 0xc(%eax), %dx
0x0040b377:	leal %edi, 0x12(%eax)
0x0040b37a:	movw 0xe(%eax), %cx
0x0040b37e:	movl %edx, $0x1f4<UINT32>
0x0040b383:	pushl %edi
0x0040b384:	movl %ecx, $0x438568<UINT32>
0x0040b389:	movw 0x10(%eax), %dx
0x0040b38d:	movl (%eax), $0x50a11844<UINT32>
0x0040b393:	call 0x0040b060
0x0040b398:	leal %edi, (%edi,%eax,2)
0x0040b39b:	pushl %edi
0x0040b39c:	movl %ecx, $0x43858c<UINT32>
0x0040b3a1:	call 0x0040b060
0x0040b3a6:	addl %esp, $0x20<UINT8>
0x0040b3a9:	pushl %ebp
0x0040b3aa:	xorl %ecx, %ecx
0x0040b3ac:	pushl $0x40aef0<UINT32>
0x0040b3b1:	pushl %ecx
0x0040b3b2:	pushl %esi
0x0040b3b3:	movw (%edi,%eax,2), %cx
0x0040b3b7:	addw 0x8(%esi), %bx
0x0040b3bb:	pushl %ecx
0x0040b3bc:	call DialogBoxIndirectParamA@USER32.dll
DialogBoxIndirectParamA@USER32.dll: API Node	
0x0040b3c2:	pushl %esi
0x0040b3c3:	movl 0x12c(%esp), %eax
0x0040b3ca:	call LocalFree@KERNEL32.dll
LocalFree@KERNEL32.dll: API Node	
0x0040b3d0:	cmpl 0x128(%esp), $0x0<UINT8>
0x0040b3d8:	popl %edi
0x0040b3d9:	popl %esi
0x0040b3da:	popl %ebx
0x0040b3db:	je 30
