0x00435800:	pusha
0x00435801:	movl %esi, $0x421000<UINT32>
0x00435806:	leal %edi, -131072(%esi)
0x0043580c:	pushl %edi
0x0043580d:	orl %ebp, $0xffffffff<UINT8>
0x00435810:	jmp 0x00435822
0x00435822:	movl %ebx, (%esi)
0x00435824:	subl %esi, $0xfffffffc<UINT8>
0x00435827:	adcl %ebx, %ebx
0x00435829:	jb 0x00435818
0x00435818:	movb %al, (%esi)
0x0043581a:	incl %esi
0x0043581b:	movb (%edi), %al
0x0043581d:	incl %edi
0x0043581e:	addl %ebx, %ebx
0x00435820:	jne 0x00435829
0x0043582b:	movl %eax, $0x1<UINT32>
0x00435830:	addl %ebx, %ebx
0x00435832:	jne 0x0043583b
0x0043583b:	adcl %eax, %eax
0x0043583d:	addl %ebx, %ebx
0x0043583f:	jae 0x00435830
0x00435841:	jne 0x0043584c
0x0043584c:	xorl %ecx, %ecx
0x0043584e:	subl %eax, $0x3<UINT8>
0x00435851:	jb 0x00435860
0x00435860:	addl %ebx, %ebx
0x00435862:	jne 0x0043586b
0x0043586b:	adcl %ecx, %ecx
0x0043586d:	addl %ebx, %ebx
0x0043586f:	jne 0x00435878
0x00435878:	adcl %ecx, %ecx
0x0043587a:	jne 0x0043589c
0x0043587c:	incl %ecx
0x0043587d:	addl %ebx, %ebx
0x0043587f:	jne 0x00435888
0x00435888:	adcl %ecx, %ecx
0x0043588a:	addl %ebx, %ebx
0x0043588c:	jae 0x0043587d
0x0043588e:	jne 0x00435899
0x00435899:	addl %ecx, $0x2<UINT8>
0x0043589c:	cmpl %ebp, $0xfffff300<UINT32>
0x004358a2:	adcl %ecx, $0x1<UINT8>
0x004358a5:	leal %edx, (%edi,%ebp)
0x004358a8:	cmpl %ebp, $0xfffffffc<UINT8>
0x004358ab:	jbe 0x004358bc
0x004358ad:	movb %al, (%edx)
0x004358af:	incl %edx
0x004358b0:	movb (%edi), %al
0x004358b2:	incl %edi
0x004358b3:	decl %ecx
0x004358b4:	jne 0x004358ad
0x004358b6:	jmp 0x0043581e
0x00435834:	movl %ebx, (%esi)
0x00435836:	subl %esi, $0xfffffffc<UINT8>
0x00435839:	adcl %ebx, %ebx
0x00435853:	shll %eax, $0x8<UINT8>
0x00435856:	movb %al, (%esi)
0x00435858:	incl %esi
0x00435859:	xorl %eax, $0xffffffff<UINT8>
0x0043585c:	je 0x004358d2
0x0043585e:	movl %ebp, %eax
0x004358bc:	movl %eax, (%edx)
0x004358be:	addl %edx, $0x4<UINT8>
0x004358c1:	movl (%edi), %eax
0x004358c3:	addl %edi, $0x4<UINT8>
0x004358c6:	subl %ecx, $0x4<UINT8>
0x004358c9:	ja 0x004358bc
0x004358cb:	addl %edi, %ecx
0x004358cd:	jmp 0x0043581e
0x00435881:	movl %ebx, (%esi)
0x00435883:	subl %esi, $0xfffffffc<UINT8>
0x00435886:	adcl %ebx, %ebx
0x00435890:	movl %ebx, (%esi)
0x00435892:	subl %esi, $0xfffffffc<UINT8>
0x00435895:	adcl %ebx, %ebx
0x00435897:	jae 0x0043587d
0x00435871:	movl %ebx, (%esi)
0x00435873:	subl %esi, $0xfffffffc<UINT8>
0x00435876:	adcl %ebx, %ebx
0x00435864:	movl %ebx, (%esi)
0x00435866:	subl %esi, $0xfffffffc<UINT8>
0x00435869:	adcl %ebx, %ebx
0x00435843:	movl %ebx, (%esi)
0x00435845:	subl %esi, $0xfffffffc<UINT8>
0x00435848:	adcl %ebx, %ebx
0x0043584a:	jae 0x00435830
0x004358d2:	popl %esi
0x004358d3:	movl %edi, %esi
0x004358d5:	movl %ecx, $0xbf6<UINT32>
0x004358da:	movb %al, (%edi)
0x004358dc:	incl %edi
0x004358dd:	subb %al, $0xffffffe8<UINT8>
0x004358df:	cmpb %al, $0x1<UINT8>
0x004358e1:	ja 0x004358da
0x004358e3:	cmpb (%edi), $0x5<UINT8>
0x004358e6:	jne 0x004358da
0x004358e8:	movl %eax, (%edi)
0x004358ea:	movb %bl, 0x4(%edi)
0x004358ed:	shrw %ax, $0x8<UINT8>
0x004358f1:	roll %eax, $0x10<UINT8>
0x004358f4:	xchgb %ah, %al
0x004358f6:	subl %eax, %edi
0x004358f8:	subb %bl, $0xffffffe8<UINT8>
0x004358fb:	addl %eax, %esi
0x004358fd:	movl (%edi), %eax
0x004358ff:	addl %edi, $0x5<UINT8>
0x00435902:	movb %al, %bl
0x00435904:	loop 0x004358df
0x00435906:	leal %edi, 0x33000(%esi)
0x0043590c:	movl %eax, (%edi)
0x0043590e:	orl %eax, %eax
0x00435910:	je 0x00435957
0x00435912:	movl %ebx, 0x4(%edi)
0x00435915:	leal %eax, 0x36018(%eax,%esi)
0x0043591c:	addl %ebx, %esi
0x0043591e:	pushl %eax
0x0043591f:	addl %edi, $0x8<UINT8>
0x00435922:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00435928:	xchgl %ebp, %eax
0x00435929:	movb %al, (%edi)
0x0043592b:	incl %edi
0x0043592c:	orb %al, %al
0x0043592e:	je 0x0043590c
0x00435930:	movl %ecx, %edi
0x00435932:	jns 0x0043593b
0x0043593b:	pushl %edi
0x0043593c:	decl %eax
0x0043593d:	repn scasb %al, %es:(%edi)
0x0043593f:	pushl %ebp
0x00435940:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00435946:	orl %eax, %eax
0x00435948:	je 7
0x0043594a:	movl (%ebx), %eax
0x0043594c:	addl %ebx, $0x4<UINT8>
0x0043594f:	jmp 0x00435929
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x00435934:	movzwl %eax, (%edi)
0x00435937:	incl %edi
0x00435938:	pushl %eax
0x00435939:	incl %edi
0x0043593a:	movl %ecx, $0xaef24857<UINT32>
0x00435957:	movl %ebp, 0x36150(%esi)
0x0043595d:	leal %edi, -4096(%esi)
0x00435963:	movl %ebx, $0x1000<UINT32>
0x00435968:	pushl %eax
0x00435969:	pushl %esp
0x0043596a:	pushl $0x4<UINT8>
0x0043596c:	pushl %ebx
0x0043596d:	pushl %edi
0x0043596e:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00435970:	leal %eax, 0x207(%edi)
0x00435976:	andb (%eax), $0x7f<UINT8>
0x00435979:	andb 0x28(%eax), $0x7f<UINT8>
0x0043597d:	popl %eax
0x0043597e:	pushl %eax
0x0043597f:	pushl %esp
0x00435980:	pushl %eax
0x00435981:	pushl %ebx
0x00435982:	pushl %edi
0x00435983:	call VirtualProtect@kernel32.dll
0x00435985:	popl %eax
0x00435986:	popa
0x00435987:	leal %eax, -128(%esp)
0x0043598b:	pushl $0x0<UINT8>
0x0043598d:	cmpl %esp, %eax
0x0043598f:	jne 0x0043598b
0x00435991:	subl %esp, $0xffffff80<UINT8>
0x00435994:	jmp 0x00408fd4
0x00408fd4:	call 0x0040f34e
0x0040f34e:	movl %edi, %edi
0x0040f350:	pushl %ebp
0x0040f351:	movl %ebp, %esp
0x0040f353:	subl %esp, $0x10<UINT8>
0x0040f356:	movl %eax, 0x4272b4
0x0040f35b:	andl -8(%ebp), $0x0<UINT8>
0x0040f35f:	andl -4(%ebp), $0x0<UINT8>
0x0040f363:	pushl %ebx
0x0040f364:	pushl %edi
0x0040f365:	movl %edi, $0xbb40e64e<UINT32>
0x0040f36a:	movl %ebx, $0xffff0000<UINT32>
0x0040f36f:	cmpl %eax, %edi
0x0040f371:	je 0x0040f380
0x0040f380:	pushl %esi
0x0040f381:	leal %eax, -8(%ebp)
0x0040f384:	pushl %eax
0x0040f385:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040f38b:	movl %esi, -4(%ebp)
0x0040f38e:	xorl %esi, -8(%ebp)
0x0040f391:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040f397:	xorl %esi, %eax
0x0040f399:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040f39f:	xorl %esi, %eax
0x0040f3a1:	call GetTickCount@KERNEL32.DLL
GetTickCount@KERNEL32.DLL: API Node	
0x0040f3a7:	xorl %esi, %eax
0x0040f3a9:	leal %eax, -16(%ebp)
0x0040f3ac:	pushl %eax
0x0040f3ad:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040f3b3:	movl %eax, -12(%ebp)
0x0040f3b6:	xorl %eax, -16(%ebp)
0x0040f3b9:	xorl %esi, %eax
0x0040f3bb:	cmpl %esi, %edi
0x0040f3bd:	jne 0x0040f3c6
0x0040f3c6:	testl %ebx, %esi
0x0040f3c8:	jne 0x0040f3d1
0x0040f3d1:	movl 0x4272b4, %esi
0x0040f3d7:	notl %esi
0x0040f3d9:	movl 0x4272b8, %esi
0x0040f3df:	popl %esi
0x0040f3e0:	popl %edi
0x0040f3e1:	popl %ebx
0x0040f3e2:	leave
0x0040f3e3:	ret

0x00408fd9:	jmp 0x00408e82
0x00408e82:	pushl $0x14<UINT8>
0x00408e84:	pushl $0x4252a8<UINT32>
0x00408e89:	call 0x0040a468
0x0040a468:	pushl $0x40a4d0<UINT32>
0x0040a46d:	pushl %fs:0
0x0040a474:	movl %eax, 0x10(%esp)
0x0040a478:	movl 0x10(%esp), %ebp
0x0040a47c:	leal %ebp, 0x10(%esp)
0x0040a480:	subl %esp, %eax
0x0040a482:	pushl %ebx
0x0040a483:	pushl %esi
0x0040a484:	pushl %edi
0x0040a485:	movl %eax, 0x4272b4
0x0040a48a:	xorl -4(%ebp), %eax
0x0040a48d:	xorl %eax, %ebp
0x0040a48f:	pushl %eax
0x0040a490:	movl -24(%ebp), %esp
0x0040a493:	pushl -8(%ebp)
0x0040a496:	movl %eax, -4(%ebp)
0x0040a499:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040a4a0:	movl -8(%ebp), %eax
0x0040a4a3:	leal %eax, -16(%ebp)
0x0040a4a6:	movl %fs:0, %eax
0x0040a4ac:	ret

0x00408e8e:	movl %eax, $0x5a4d<UINT32>
0x00408e93:	cmpw 0x400000, %ax
0x00408e9a:	jne 56
0x00408e9c:	movl %eax, 0x40003c
0x00408ea1:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00408eab:	jne 39
0x00408ead:	movl %ecx, $0x10b<UINT32>
0x00408eb2:	cmpw 0x400018(%eax), %cx
0x00408eb9:	jne 25
0x00408ebb:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00408ec2:	jbe 16
0x00408ec4:	xorl %ecx, %ecx
0x00408ec6:	cmpl 0x4000e8(%eax), %ecx
0x00408ecc:	setne %cl
0x00408ecf:	movl -28(%ebp), %ecx
0x00408ed2:	jmp 0x00408ed8
0x00408ed8:	pushl $0x1<UINT8>
0x00408eda:	call 0x0040c8a2
0x0040c8a2:	movl %edi, %edi
0x0040c8a4:	pushl %ebp
0x0040c8a5:	movl %ebp, %esp
0x0040c8a7:	xorl %eax, %eax
0x0040c8a9:	cmpl 0x8(%ebp), %eax
0x0040c8ac:	pushl $0x0<UINT8>
0x0040c8ae:	sete %al
0x0040c8b1:	pushl $0x1000<UINT32>
0x0040c8b6:	pushl %eax
0x0040c8b7:	call HeapCreate@KERNEL32.DLL
HeapCreate@KERNEL32.DLL: API Node	
0x0040c8bd:	movl 0x42b1b0, %eax
0x0040c8c2:	testl %eax, %eax
0x0040c8c4:	jne 0x0040c8c8
0x0040c8c8:	xorl %eax, %eax
0x0040c8ca:	incl %eax
0x0040c8cb:	movl 0x42c90c, %eax
0x0040c8d0:	popl %ebp
0x0040c8d1:	ret

0x00408edf:	popl %ecx
0x00408ee0:	testl %eax, %eax
0x00408ee2:	jne 0x00408eec
0x00408eec:	call 0x0040c276
0x0040c276:	movl %edi, %edi
0x0040c278:	pushl %esi
0x0040c279:	pushl %edi
0x0040c27a:	movl %esi, $0x4225fc<UINT32>
0x0040c27f:	pushl %esi
0x0040c280:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0040c286:	testl %eax, %eax
0x0040c288:	jne 0x0040c291
0x0040c291:	movl %edi, %eax
0x0040c293:	testl %edi, %edi
0x0040c295:	je 350
0x0040c29b:	movl %esi, 0x42222c
0x0040c2a1:	pushl $0x422648<UINT32>
0x0040c2a6:	pushl %edi
0x0040c2a7:	call GetProcAddress@KERNEL32.DLL
0x0040c2a9:	pushl $0x42263c<UINT32>
0x0040c2ae:	pushl %edi
0x0040c2af:	movl 0x42b19c, %eax
0x0040c2b4:	call GetProcAddress@KERNEL32.DLL
0x0040c2b6:	pushl $0x422630<UINT32>
0x0040c2bb:	pushl %edi
0x0040c2bc:	movl 0x42b1a0, %eax
0x0040c2c1:	call GetProcAddress@KERNEL32.DLL
0x0040c2c3:	pushl $0x422628<UINT32>
0x0040c2c8:	pushl %edi
0x0040c2c9:	movl 0x42b1a4, %eax
0x0040c2ce:	call GetProcAddress@KERNEL32.DLL
0x0040c2d0:	cmpl 0x42b19c, $0x0<UINT8>
0x0040c2d7:	movl %esi, 0x4221ac
0x0040c2dd:	movl 0x42b1a8, %eax
0x0040c2e2:	je 22
0x0040c2e4:	cmpl 0x42b1a0, $0x0<UINT8>
0x0040c2eb:	je 13
0x0040c2ed:	cmpl 0x42b1a4, $0x0<UINT8>
0x0040c2f4:	je 4
0x0040c2f6:	testl %eax, %eax
0x0040c2f8:	jne 0x0040c31e
0x0040c31e:	call TlsAlloc@KERNEL32.DLL
TlsAlloc@KERNEL32.DLL: API Node	
0x0040c324:	movl 0x427a54, %eax
0x0040c329:	cmpl %eax, $0xffffffff<UINT8>
0x0040c32c:	je 204
0x0040c332:	pushl 0x42b1a0
0x0040c338:	pushl %eax
0x0040c339:	call TlsSetValue@KERNEL32.DLL
TlsSetValue@KERNEL32.DLL: API Node	
0x0040c33b:	testl %eax, %eax
0x0040c33d:	je 187
0x0040c343:	call 0x0040d82f
0x0040d82f:	movl %edi, %edi
0x0040d831:	pushl %esi
0x0040d832:	call 0x0040be2d
0x0040be2d:	pushl $0x0<UINT8>
0x0040be2f:	call 0x0040bdbb
0x0040bdbb:	movl %edi, %edi
0x0040bdbd:	pushl %ebp
0x0040bdbe:	movl %ebp, %esp
0x0040bdc0:	pushl %esi
0x0040bdc1:	pushl 0x427a54
0x0040bdc7:	movl %esi, 0x4221b4
0x0040bdcd:	call TlsGetValue@KERNEL32.DLL
TlsGetValue@KERNEL32.DLL: API Node	
0x0040bdcf:	testl %eax, %eax
0x0040bdd1:	je 33
0x0040bdd3:	movl %eax, 0x427a50
0x0040bdd8:	cmpl %eax, $0xffffffff<UINT8>
0x0040bddb:	je 0x0040bdf4
0x0040bdf4:	movl %esi, $0x4225fc<UINT32>
0x0040bdf9:	pushl %esi
0x0040bdfa:	call GetModuleHandleW@KERNEL32.DLL
0x0040be00:	testl %eax, %eax
0x0040be02:	jne 0x0040be0f
0x0040be0f:	pushl $0x4225ec<UINT32>
0x0040be14:	pushl %eax
0x0040be15:	call GetProcAddress@KERNEL32.DLL
0x0040be1b:	testl %eax, %eax
0x0040be1d:	je 8
0x0040be1f:	pushl 0x8(%ebp)
0x0040be22:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x0040be24:	movl 0x8(%ebp), %eax
0x0040be27:	movl %eax, 0x8(%ebp)
0x0040be2a:	popl %esi
0x0040be2b:	popl %ebp
0x0040be2c:	ret

0x0040be34:	popl %ecx
0x0040be35:	ret

0x0040d837:	movl %esi, %eax
0x0040d839:	pushl %esi
0x0040d83a:	call 0x0040da61
0x0040da61:	movl %edi, %edi
0x0040da63:	pushl %ebp
0x0040da64:	movl %ebp, %esp
0x0040da66:	movl %eax, 0x8(%ebp)
0x0040da69:	movl 0x42b654, %eax
0x0040da6e:	popl %ebp
0x0040da6f:	ret

0x0040d83f:	pushl %esi
0x0040d840:	call 0x00411019
0x00411019:	movl %edi, %edi
0x0041101b:	pushl %ebp
0x0041101c:	movl %ebp, %esp
0x0041101e:	movl %eax, 0x8(%ebp)
0x00411021:	movl 0x42b780, %eax
0x00411026:	popl %ebp
0x00411027:	ret

0x0040d845:	pushl %esi
0x0040d846:	call 0x0040820d
0x0040820d:	movl %edi, %edi
0x0040820f:	pushl %ebp
0x00408210:	movl %ebp, %esp
0x00408212:	movl %eax, 0x8(%ebp)
0x00408215:	movl 0x42ae14, %eax
0x0040821a:	popl %ebp
0x0040821b:	ret

0x0040d84b:	pushl %esi
0x0040d84c:	call 0x00412444
0x00412444:	movl %edi, %edi
0x00412446:	pushl %ebp
0x00412447:	movl %ebp, %esp
0x00412449:	movl %eax, 0x8(%ebp)
0x0041244c:	movl 0x42b7b0, %eax
0x00412451:	popl %ebp
0x00412452:	ret

0x0040d851:	pushl %esi
0x0040d852:	call 0x00412435
0x00412435:	movl %edi, %edi
0x00412437:	pushl %ebp
0x00412438:	movl %ebp, %esp
0x0041243a:	movl %eax, 0x8(%ebp)
0x0041243d:	movl 0x42b7a4, %eax
0x00412442:	popl %ebp
0x00412443:	ret

0x0040d857:	pushl %esi
0x0040d858:	call 0x00412223
0x00412223:	movl %edi, %edi
0x00412225:	pushl %ebp
0x00412226:	movl %ebp, %esp
0x00412228:	movl %eax, 0x8(%ebp)
0x0041222b:	movl 0x42b790, %eax
0x00412230:	movl 0x42b794, %eax
0x00412235:	movl 0x42b798, %eax
0x0041223a:	movl 0x42b79c, %eax
0x0041223f:	popl %ebp
0x00412240:	ret

0x0040d85d:	pushl %esi
0x0040d85e:	call 0x0040ea7d
0x0040ea7d:	ret

0x0040d863:	pushl %esi
0x0040d864:	call 0x00412212
0x00412212:	pushl $0x41218e<UINT32>
0x00412217:	call 0x0040bdbb
0x0041221c:	popl %ecx
0x0041221d:	movl 0x42b78c, %eax
0x00412222:	ret

0x0040d869:	pushl $0x40d7fb<UINT32>
0x0040d86e:	call 0x0040bdbb
0x0040d873:	addl %esp, $0x24<UINT8>
0x0040d876:	movl 0x427b80, %eax
0x0040d87b:	popl %esi
0x0040d87c:	ret

0x0040c348:	pushl 0x42b19c
0x0040c34e:	call 0x0040bdbb
0x0040c353:	pushl 0x42b1a0
0x0040c359:	movl 0x42b19c, %eax
0x0040c35e:	call 0x0040bdbb
0x0040c363:	pushl 0x42b1a4
0x0040c369:	movl 0x42b1a0, %eax
0x0040c36e:	call 0x0040bdbb
0x0040c373:	pushl 0x42b1a8
0x0040c379:	movl 0x42b1a4, %eax
0x0040c37e:	call 0x0040bdbb
0x0040c383:	addl %esp, $0x10<UINT8>
0x0040c386:	movl 0x42b1a8, %eax
0x0040c38b:	call 0x0040c8d2
0x0040c8d2:	movl %edi, %edi
0x0040c8d4:	pushl %esi
0x0040c8d5:	pushl %edi
0x0040c8d6:	xorl %esi, %esi
0x0040c8d8:	movl %edi, $0x42b1b8<UINT32>
0x0040c8dd:	cmpl 0x427a64(,%esi,8), $0x1<UINT8>
0x0040c8e5:	jne 0x0040c905
0x0040c8e7:	leal %eax, 0x427a60(,%esi,8)
0x0040c8ee:	movl (%eax), %edi
0x0040c8f0:	pushl $0xfa0<UINT32>
0x0040c8f5:	pushl (%eax)
0x0040c8f7:	addl %edi, $0x18<UINT8>
0x0040c8fa:	call 0x00411028
0x00411028:	pushl $0x10<UINT8>
0x0041102a:	pushl $0x425538<UINT32>
0x0041102f:	call 0x0040a468
0x00411034:	andl -4(%ebp), $0x0<UINT8>
0x00411038:	pushl 0xc(%ebp)
0x0041103b:	pushl 0x8(%ebp)
0x0041103e:	call InitializeCriticalSectionAndSpinCount@KERNEL32.DLL
InitializeCriticalSectionAndSpinCount@KERNEL32.DLL: API Node	
0x00411044:	movl -28(%ebp), %eax
0x00411047:	jmp 0x00411078
0x00411078:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0041107f:	movl %eax, -28(%ebp)
0x00411082:	call 0x0040a4ad
0x0040a4ad:	movl %ecx, -16(%ebp)
0x0040a4b0:	movl %fs:0, %ecx
0x0040a4b7:	popl %ecx
0x0040a4b8:	popl %edi
0x0040a4b9:	popl %edi
0x0040a4ba:	popl %esi
0x0040a4bb:	popl %ebx
0x0040a4bc:	movl %esp, %ebp
0x0040a4be:	popl %ebp
0x0040a4bf:	pushl %ecx
0x0040a4c0:	ret

0x00411087:	ret

0x0040c8ff:	popl %ecx
0x0040c900:	popl %ecx
0x0040c901:	testl %eax, %eax
0x0040c903:	je 12
0x0040c905:	incl %esi
0x0040c906:	cmpl %esi, $0x24<UINT8>
0x0040c909:	jl 0x0040c8dd
0x0040c90b:	xorl %eax, %eax
0x0040c90d:	incl %eax
0x0040c90e:	popl %edi
0x0040c90f:	popl %esi
0x0040c910:	ret

0x0040c390:	testl %eax, %eax
0x0040c392:	je 101
0x0040c394:	pushl $0x40c0d9<UINT32>
0x0040c399:	pushl 0x42b19c
0x0040c39f:	call 0x0040be36
0x0040be36:	movl %edi, %edi
0x0040be38:	pushl %ebp
0x0040be39:	movl %ebp, %esp
0x0040be3b:	pushl %esi
0x0040be3c:	pushl 0x427a54
0x0040be42:	movl %esi, 0x4221b4
0x0040be48:	call TlsGetValue@KERNEL32.DLL
0x0040be4a:	testl %eax, %eax
0x0040be4c:	je 33
0x0040be4e:	movl %eax, 0x427a50
0x0040be53:	cmpl %eax, $0xffffffff<UINT8>
0x0040be56:	je 0x0040be6f
0x0040be6f:	movl %esi, $0x4225fc<UINT32>
0x0040be74:	pushl %esi
0x0040be75:	call GetModuleHandleW@KERNEL32.DLL
0x0040be7b:	testl %eax, %eax
0x0040be7d:	jne 0x0040be8a
0x0040be8a:	pushl $0x422618<UINT32>
0x0040be8f:	pushl %eax
0x0040be90:	call GetProcAddress@KERNEL32.DLL
0x0040be96:	testl %eax, %eax
0x0040be98:	je 8
0x0040be9a:	pushl 0x8(%ebp)
0x0040be9d:	call DecodePointer@KERNEL32.DLL
DecodePointer@KERNEL32.DLL: API Node	
0x0040be9f:	movl 0x8(%ebp), %eax
0x0040bea2:	movl %eax, 0x8(%ebp)
0x0040bea5:	popl %esi
0x0040bea6:	popl %ebp
0x0040bea7:	ret

0x0040c3a4:	popl %ecx
0x0040c3a5:	call FlsAlloc@KERNEL32.DLL
FlsAlloc@KERNEL32.DLL: API Node	
0x0040c3a7:	movl 0x427a50, %eax
0x0040c3ac:	cmpl %eax, $0xffffffff<UINT8>
0x0040c3af:	je 72
0x0040c3b1:	pushl $0x214<UINT32>
0x0040c3b6:	pushl $0x1<UINT8>
0x0040c3b8:	call 0x0040e4b5
0x0040e4b5:	movl %edi, %edi
0x0040e4b7:	pushl %ebp
0x0040e4b8:	movl %ebp, %esp
0x0040e4ba:	pushl %esi
0x0040e4bb:	pushl %edi
0x0040e4bc:	xorl %esi, %esi
0x0040e4be:	pushl $0x0<UINT8>
0x0040e4c0:	pushl 0xc(%ebp)
0x0040e4c3:	pushl 0x8(%ebp)
0x0040e4c6:	call 0x00412607
0x00412607:	pushl $0xc<UINT8>
0x00412609:	pushl $0x425600<UINT32>
0x0041260e:	call 0x0040a468
0x00412613:	movl %ecx, 0x8(%ebp)
0x00412616:	xorl %edi, %edi
0x00412618:	cmpl %ecx, %edi
0x0041261a:	jbe 46
0x0041261c:	pushl $0xffffffe0<UINT8>
0x0041261e:	popl %eax
0x0041261f:	xorl %edx, %edx
0x00412621:	divl %eax, %ecx
0x00412623:	cmpl %eax, 0xc(%ebp)
0x00412626:	sbbl %eax, %eax
0x00412628:	incl %eax
0x00412629:	jne 0x0041264a
0x0041264a:	imull %ecx, 0xc(%ebp)
0x0041264e:	movl %esi, %ecx
0x00412650:	movl 0x8(%ebp), %esi
0x00412653:	cmpl %esi, %edi
0x00412655:	jne 0x0041265a
0x0041265a:	xorl %ebx, %ebx
0x0041265c:	movl -28(%ebp), %ebx
0x0041265f:	cmpl %esi, $0xffffffe0<UINT8>
0x00412662:	ja 105
0x00412664:	cmpl 0x42c90c, $0x3<UINT8>
0x0041266b:	jne 0x004126b8
0x004126b8:	cmpl %ebx, %edi
0x004126ba:	jne 97
0x004126bc:	pushl %esi
0x004126bd:	pushl $0x8<UINT8>
0x004126bf:	pushl 0x42b1b0
0x004126c5:	call HeapAlloc@KERNEL32.DLL
HeapAlloc@KERNEL32.DLL: API Node	
0x004126cb:	movl %ebx, %eax
0x004126cd:	cmpl %ebx, %edi
0x004126cf:	jne 0x0041271d
0x0041271d:	movl %eax, %ebx
0x0041271f:	call 0x0040a4ad
0x00412724:	ret

0x0040e4cb:	movl %edi, %eax
0x0040e4cd:	addl %esp, $0xc<UINT8>
0x0040e4d0:	testl %edi, %edi
0x0040e4d2:	jne 0x0040e4fb
0x0040e4fb:	movl %eax, %edi
0x0040e4fd:	popl %edi
0x0040e4fe:	popl %esi
0x0040e4ff:	popl %ebp
0x0040e500:	ret

0x0040c3bd:	movl %esi, %eax
0x0040c3bf:	popl %ecx
0x0040c3c0:	popl %ecx
0x0040c3c1:	testl %esi, %esi
0x0040c3c3:	je 52
0x0040c3c5:	pushl %esi
0x0040c3c6:	pushl 0x427a50
0x0040c3cc:	pushl 0x42b1a4
0x0040c3d2:	call 0x0040be36
0x0040be58:	pushl %eax
0x0040be59:	pushl 0x427a54
0x0040be5f:	call TlsGetValue@KERNEL32.DLL
0x0040be61:	call FlsGetValue@KERNEL32.DLL
FlsGetValue@KERNEL32.DLL: API Node	
0x0040be63:	testl %eax, %eax
0x0040be65:	je 0x0040be6f
0x0040c3d7:	popl %ecx
0x0040c3d8:	call FlsSetValue@KERNEL32.DLL
FlsSetValue@KERNEL32.DLL: API Node	
0x0040c3da:	testl %eax, %eax
0x0040c3dc:	je 27
0x0040c3de:	pushl $0x0<UINT8>
0x0040c3e0:	pushl %esi
0x0040c3e1:	call 0x0040bf5f
0x0040bf5f:	pushl $0xc<UINT8>
0x0040bf61:	pushl $0x4253a8<UINT32>
0x0040bf66:	call 0x0040a468
0x0040bf6b:	movl %esi, $0x4225fc<UINT32>
0x0040bf70:	pushl %esi
0x0040bf71:	call GetModuleHandleW@KERNEL32.DLL
0x0040bf77:	testl %eax, %eax
0x0040bf79:	jne 0x0040bf82
0x0040bf82:	movl -28(%ebp), %eax
0x0040bf85:	movl %esi, 0x8(%ebp)
0x0040bf88:	movl 0x5c(%esi), $0x422c48<UINT32>
0x0040bf8f:	xorl %edi, %edi
0x0040bf91:	incl %edi
0x0040bf92:	movl 0x14(%esi), %edi
0x0040bf95:	testl %eax, %eax
0x0040bf97:	je 36
0x0040bf99:	pushl $0x4225ec<UINT32>
0x0040bf9e:	pushl %eax
0x0040bf9f:	movl %ebx, 0x42222c
0x0040bfa5:	call GetProcAddress@KERNEL32.DLL
0x0040bfa7:	movl 0x1f8(%esi), %eax
0x0040bfad:	pushl $0x422618<UINT32>
0x0040bfb2:	pushl -28(%ebp)
0x0040bfb5:	call GetProcAddress@KERNEL32.DLL
0x0040bfb7:	movl 0x1fc(%esi), %eax
0x0040bfbd:	movl 0x70(%esi), %edi
0x0040bfc0:	movb 0xc8(%esi), $0x43<UINT8>
0x0040bfc7:	movb 0x14b(%esi), $0x43<UINT8>
0x0040bfce:	movl 0x68(%esi), $0x427438<UINT32>
0x0040bfd5:	pushl $0xd<UINT8>
0x0040bfd7:	call 0x0040ca4e
0x0040ca4e:	movl %edi, %edi
0x0040ca50:	pushl %ebp
0x0040ca51:	movl %ebp, %esp
0x0040ca53:	movl %eax, 0x8(%ebp)
0x0040ca56:	pushl %esi
0x0040ca57:	leal %esi, 0x427a60(,%eax,8)
0x0040ca5e:	cmpl (%esi), $0x0<UINT8>
0x0040ca61:	jne 0x0040ca76
0x0040ca76:	pushl (%esi)
0x0040ca78:	call EnterCriticalSection@KERNEL32.DLL
EnterCriticalSection@KERNEL32.DLL: API Node	
0x0040ca7e:	popl %esi
0x0040ca7f:	popl %ebp
0x0040ca80:	ret

0x0040bfdc:	popl %ecx
0x0040bfdd:	andl -4(%ebp), $0x0<UINT8>
0x0040bfe1:	pushl 0x68(%esi)
0x0040bfe4:	call InterlockedIncrement@KERNEL32.DLL
InterlockedIncrement@KERNEL32.DLL: API Node	
0x0040bfea:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040bff1:	call 0x0040c034
0x0040c034:	pushl $0xd<UINT8>
0x0040c036:	call 0x0040c974
0x0040c974:	movl %edi, %edi
0x0040c976:	pushl %ebp
0x0040c977:	movl %ebp, %esp
0x0040c979:	movl %eax, 0x8(%ebp)
0x0040c97c:	pushl 0x427a60(,%eax,8)
0x0040c983:	call LeaveCriticalSection@KERNEL32.DLL
LeaveCriticalSection@KERNEL32.DLL: API Node	
0x0040c989:	popl %ebp
0x0040c98a:	ret

0x0040c03b:	popl %ecx
0x0040c03c:	ret

0x0040bff6:	pushl $0xc<UINT8>
0x0040bff8:	call 0x0040ca4e
0x0040bffd:	popl %ecx
0x0040bffe:	movl -4(%ebp), %edi
0x0040c001:	movl %eax, 0xc(%ebp)
0x0040c004:	movl 0x6c(%esi), %eax
0x0040c007:	testl %eax, %eax
0x0040c009:	jne 8
0x0040c00b:	movl %eax, 0x427a40
0x0040c010:	movl 0x6c(%esi), %eax
0x0040c013:	pushl 0x6c(%esi)
0x0040c016:	call 0x0040bbdf
0x0040bbdf:	movl %edi, %edi
0x0040bbe1:	pushl %ebp
0x0040bbe2:	movl %ebp, %esp
0x0040bbe4:	pushl %ebx
0x0040bbe5:	pushl %esi
0x0040bbe6:	movl %esi, 0x4220e4
0x0040bbec:	pushl %edi
0x0040bbed:	movl %edi, 0x8(%ebp)
0x0040bbf0:	pushl %edi
0x0040bbf1:	call InterlockedIncrement@KERNEL32.DLL
0x0040bbf3:	movl %eax, 0xb0(%edi)
0x0040bbf9:	testl %eax, %eax
0x0040bbfb:	je 0x0040bc00
0x0040bc00:	movl %eax, 0xb8(%edi)
0x0040bc06:	testl %eax, %eax
0x0040bc08:	je 0x0040bc0d
0x0040bc0d:	movl %eax, 0xb4(%edi)
0x0040bc13:	testl %eax, %eax
0x0040bc15:	je 0x0040bc1a
0x0040bc1a:	movl %eax, 0xc0(%edi)
0x0040bc20:	testl %eax, %eax
0x0040bc22:	je 0x0040bc27
0x0040bc27:	leal %ebx, 0x50(%edi)
0x0040bc2a:	movl 0x8(%ebp), $0x6<UINT32>
0x0040bc31:	cmpl -8(%ebx), $0x427960<UINT32>
0x0040bc38:	je 0x0040bc43
0x0040bc3a:	movl %eax, (%ebx)
0x0040bc3c:	testl %eax, %eax
0x0040bc3e:	je 0x0040bc43
0x0040bc43:	cmpl -4(%ebx), $0x0<UINT8>
0x0040bc47:	je 0x0040bc53
0x0040bc53:	addl %ebx, $0x10<UINT8>
0x0040bc56:	decl 0x8(%ebp)
0x0040bc59:	jne 0x0040bc31
0x0040bc5b:	movl %eax, 0xd4(%edi)
0x0040bc61:	addl %eax, $0xb4<UINT32>
0x0040bc66:	pushl %eax
0x0040bc67:	call InterlockedIncrement@KERNEL32.DLL
0x0040bc69:	popl %edi
0x0040bc6a:	popl %esi
0x0040bc6b:	popl %ebx
0x0040bc6c:	popl %ebp
0x0040bc6d:	ret

0x0040c01b:	popl %ecx
0x0040c01c:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040c023:	call 0x0040c03d
0x0040c03d:	pushl $0xc<UINT8>
0x0040c03f:	call 0x0040c974
0x0040c044:	popl %ecx
0x0040c045:	ret

0x0040c028:	call 0x0040a4ad
0x0040c02d:	ret

0x0040c3e6:	popl %ecx
0x0040c3e7:	popl %ecx
0x0040c3e8:	call GetCurrentThreadId@KERNEL32.DLL
0x0040c3ee:	orl 0x4(%esi), $0xffffffff<UINT8>
0x0040c3f2:	movl (%esi), %eax
0x0040c3f4:	xorl %eax, %eax
0x0040c3f6:	incl %eax
0x0040c3f7:	jmp 0x0040c400
0x0040c400:	popl %edi
0x0040c401:	popl %esi
0x0040c402:	ret

0x00408ef1:	testl %eax, %eax
0x00408ef3:	jne 0x00408efd
0x00408efd:	call 0x0040f302
0x0040f302:	movl %edi, %edi
0x0040f304:	pushl %esi
0x0040f305:	movl %eax, $0x4250f0<UINT32>
0x0040f30a:	movl %esi, $0x4250f0<UINT32>
0x0040f30f:	pushl %edi
0x0040f310:	movl %edi, %eax
0x0040f312:	cmpl %eax, %esi
0x0040f314:	jae 0x0040f325
0x0040f325:	popl %edi
0x0040f326:	popl %esi
0x0040f327:	ret

0x00408f02:	andl -4(%ebp), $0x0<UINT8>
0x00408f06:	call 0x0040e21c
0x0040e21c:	pushl $0x54<UINT8>
0x0040e21e:	pushl $0x425438<UINT32>
0x0040e223:	call 0x0040a468
0x0040e228:	xorl %edi, %edi
0x0040e22a:	movl -4(%ebp), %edi
0x0040e22d:	leal %eax, -100(%ebp)
0x0040e230:	pushl %eax
0x0040e231:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x0040e237:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040e23e:	pushl $0x40<UINT8>
0x0040e240:	pushl $0x20<UINT8>
0x0040e242:	popl %esi
0x0040e243:	pushl %esi
0x0040e244:	call 0x0040e4b5
0x0040e249:	popl %ecx
0x0040e24a:	popl %ecx
0x0040e24b:	cmpl %eax, %edi
0x0040e24d:	je 532
0x0040e253:	movl 0x42c7e0, %eax
0x0040e258:	movl 0x42c7d0, %esi
0x0040e25e:	leal %ecx, 0x800(%eax)
0x0040e264:	jmp 0x0040e296
0x0040e296:	cmpl %eax, %ecx
0x0040e298:	jb 0x0040e266
0x0040e266:	movb 0x4(%eax), $0x0<UINT8>
0x0040e26a:	orl (%eax), $0xffffffff<UINT8>
0x0040e26d:	movb 0x5(%eax), $0xa<UINT8>
0x0040e271:	movl 0x8(%eax), %edi
0x0040e274:	movb 0x24(%eax), $0x0<UINT8>
0x0040e278:	movb 0x25(%eax), $0xa<UINT8>
0x0040e27c:	movb 0x26(%eax), $0xa<UINT8>
0x0040e280:	movl 0x38(%eax), %edi
0x0040e283:	movb 0x34(%eax), $0x0<UINT8>
0x0040e287:	addl %eax, $0x40<UINT8>
0x0040e28a:	movl %ecx, 0x42c7e0
0x0040e290:	addl %ecx, $0x800<UINT32>
0x0040e29a:	cmpw -50(%ebp), %di
0x0040e29e:	je 266
0x0040e2a4:	movl %eax, -48(%ebp)
0x0040e2a7:	cmpl %eax, %edi
0x0040e2a9:	je 255
0x0040e2af:	movl %edi, (%eax)
0x0040e2b1:	leal %ebx, 0x4(%eax)
0x0040e2b4:	leal %eax, (%ebx,%edi)
0x0040e2b7:	movl -28(%ebp), %eax
0x0040e2ba:	movl %esi, $0x800<UINT32>
0x0040e2bf:	cmpl %edi, %esi
0x0040e2c1:	jl 0x0040e2c5
0x0040e2c5:	movl -32(%ebp), $0x1<UINT32>
0x0040e2cc:	jmp 0x0040e329
0x0040e329:	cmpl 0x42c7d0, %edi
0x0040e32f:	jl -99
0x0040e331:	jmp 0x0040e339
0x0040e339:	andl -32(%ebp), $0x0<UINT8>
0x0040e33d:	testl %edi, %edi
0x0040e33f:	jle 0x0040e3ae
0x0040e3ae:	xorl %ebx, %ebx
0x0040e3b0:	movl %esi, %ebx
0x0040e3b2:	shll %esi, $0x6<UINT8>
0x0040e3b5:	addl %esi, 0x42c7e0
0x0040e3bb:	movl %eax, (%esi)
0x0040e3bd:	cmpl %eax, $0xffffffff<UINT8>
0x0040e3c0:	je 0x0040e3cd
0x0040e3cd:	movb 0x4(%esi), $0xffffff81<UINT8>
0x0040e3d1:	testl %ebx, %ebx
0x0040e3d3:	jne 0x0040e3da
0x0040e3d5:	pushl $0xfffffff6<UINT8>
0x0040e3d7:	popl %eax
0x0040e3d8:	jmp 0x0040e3e4
0x0040e3e4:	pushl %eax
0x0040e3e5:	call GetStdHandle@KERNEL32.DLL
GetStdHandle@KERNEL32.DLL: API Node	
0x0040e3eb:	movl %edi, %eax
0x0040e3ed:	cmpl %edi, $0xffffffff<UINT8>
0x0040e3f0:	je 67
0x0040e3f2:	testl %edi, %edi
0x0040e3f4:	je 63
0x0040e3f6:	pushl %edi
0x0040e3f7:	call GetFileType@KERNEL32.DLL
GetFileType@KERNEL32.DLL: API Node	
0x0040e3fd:	testl %eax, %eax
0x0040e3ff:	je 52
0x0040e401:	movl (%esi), %edi
0x0040e403:	andl %eax, $0xff<UINT32>
0x0040e408:	cmpl %eax, $0x2<UINT8>
0x0040e40b:	jne 6
0x0040e40d:	orb 0x4(%esi), $0x40<UINT8>
0x0040e411:	jmp 0x0040e41c
0x0040e41c:	pushl $0xfa0<UINT32>
0x0040e421:	leal %eax, 0xc(%esi)
0x0040e424:	pushl %eax
0x0040e425:	call 0x00411028
0x0040e42a:	popl %ecx
0x0040e42b:	popl %ecx
0x0040e42c:	testl %eax, %eax
0x0040e42e:	je 55
0x0040e430:	incl 0x8(%esi)
0x0040e433:	jmp 0x0040e43f
0x0040e43f:	incl %ebx
0x0040e440:	cmpl %ebx, $0x3<UINT8>
0x0040e443:	jl 0x0040e3b0
0x0040e3da:	movl %eax, %ebx
0x0040e3dc:	decl %eax
0x0040e3dd:	negl %eax
0x0040e3df:	sbbl %eax, %eax
0x0040e3e1:	addl %eax, $0xfffffff5<UINT8>
0x0040e449:	pushl 0x42c7d0
0x0040e44f:	call SetHandleCount@KERNEL32.DLL
SetHandleCount@KERNEL32.DLL: API Node	
0x0040e455:	xorl %eax, %eax
0x0040e457:	jmp 0x0040e46a
0x0040e46a:	call 0x0040a4ad
0x0040e46f:	ret

0x00408f0b:	testl %eax, %eax
0x00408f0d:	jnl 0x00408f17
0x00408f17:	call GetCommandLineA@KERNEL32.DLL
GetCommandLineA@KERNEL32.DLL: API Node	
0x00408f1d:	movl 0x42c914, %eax
0x00408f22:	call 0x0040f1cb
0x0040f1cb:	movl %edi, %edi
0x0040f1cd:	pushl %ebp
0x0040f1ce:	movl %ebp, %esp
0x0040f1d0:	movl %eax, 0x42b778
0x0040f1d5:	subl %esp, $0xc<UINT8>
0x0040f1d8:	pushl %ebx
0x0040f1d9:	pushl %esi
0x0040f1da:	movl %esi, 0x422154
0x0040f1e0:	pushl %edi
0x0040f1e1:	xorl %ebx, %ebx
0x0040f1e3:	xorl %edi, %edi
0x0040f1e5:	cmpl %eax, %ebx
0x0040f1e7:	jne 46
0x0040f1e9:	call GetEnvironmentStringsW@KERNEL32.DLL
GetEnvironmentStringsW@KERNEL32.DLL: API Node	
0x0040f1eb:	movl %edi, %eax
0x0040f1ed:	cmpl %edi, %ebx
0x0040f1ef:	je 12
0x0040f1f1:	movl 0x42b778, $0x1<UINT32>
0x0040f1fb:	jmp 0x0040f220
0x0040f220:	cmpl %edi, %ebx
0x0040f222:	jne 0x0040f233
0x0040f233:	movl %eax, %edi
0x0040f235:	cmpw (%edi), %bx
0x0040f238:	je 14
0x0040f23a:	incl %eax
0x0040f23b:	incl %eax
0x0040f23c:	cmpw (%eax), %bx
0x0040f23f:	jne 0x0040f23a
0x0040f241:	incl %eax
0x0040f242:	incl %eax
0x0040f243:	cmpw (%eax), %bx
0x0040f246:	jne 0x0040f23a
0x0040f248:	movl %esi, 0x4221d4
0x0040f24e:	pushl %ebx
0x0040f24f:	pushl %ebx
0x0040f250:	pushl %ebx
0x0040f251:	subl %eax, %edi
0x0040f253:	pushl %ebx
0x0040f254:	sarl %eax
0x0040f256:	incl %eax
0x0040f257:	pushl %eax
0x0040f258:	pushl %edi
0x0040f259:	pushl %ebx
0x0040f25a:	pushl %ebx
0x0040f25b:	movl -12(%ebp), %eax
0x0040f25e:	call WideCharToMultiByte@KERNEL32.DLL
WideCharToMultiByte@KERNEL32.DLL: API Node	
0x0040f260:	movl -8(%ebp), %eax
0x0040f263:	cmpl %eax, %ebx
0x0040f265:	je 47
0x0040f267:	pushl %eax
0x0040f268:	call 0x0040e470
0x0040e470:	movl %edi, %edi
0x0040e472:	pushl %ebp
0x0040e473:	movl %ebp, %esp
0x0040e475:	pushl %esi
0x0040e476:	pushl %edi
0x0040e477:	xorl %esi, %esi
0x0040e479:	pushl 0x8(%ebp)
0x0040e47c:	call 0x0040576a
0x0040576a:	movl %edi, %edi
0x0040576c:	pushl %ebp
0x0040576d:	movl %ebp, %esp
0x0040576f:	pushl %esi
0x00405770:	movl %esi, 0x8(%ebp)
0x00405773:	cmpl %esi, $0xffffffe0<UINT8>
0x00405776:	ja 161
0x0040577c:	pushl %ebx
0x0040577d:	pushl %edi
0x0040577e:	movl %edi, 0x422200
0x00405784:	cmpl 0x42b1b0, $0x0<UINT8>
0x0040578b:	jne 0x004057a5
0x004057a5:	movl %eax, 0x42c90c
0x004057aa:	cmpl %eax, $0x1<UINT8>
0x004057ad:	jne 14
0x004057af:	testl %esi, %esi
0x004057b1:	je 4
0x004057b3:	movl %eax, %esi
0x004057b5:	jmp 0x004057ba
0x004057ba:	pushl %eax
0x004057bb:	jmp 0x004057d9
0x004057d9:	pushl $0x0<UINT8>
0x004057db:	pushl 0x42b1b0
0x004057e1:	call HeapAlloc@KERNEL32.DLL
0x004057e3:	movl %ebx, %eax
0x004057e5:	testl %ebx, %ebx
0x004057e7:	jne 0x00405817
0x00405817:	popl %edi
0x00405818:	movl %eax, %ebx
0x0040581a:	popl %ebx
0x0040581b:	jmp 0x00405831
0x00405831:	popl %esi
0x00405832:	popl %ebp
0x00405833:	ret

0x0040e481:	movl %edi, %eax
0x0040e483:	popl %ecx
0x0040e484:	testl %edi, %edi
0x0040e486:	jne 0x0040e4af
0x0040e4af:	movl %eax, %edi
0x0040e4b1:	popl %edi
0x0040e4b2:	popl %esi
0x0040e4b3:	popl %ebp
0x0040e4b4:	ret

0x0040f26d:	popl %ecx
0x0040f26e:	movl -4(%ebp), %eax
0x0040f271:	cmpl %eax, %ebx
0x0040f273:	je 33
0x0040f275:	pushl %ebx
0x0040f276:	pushl %ebx
0x0040f277:	pushl -8(%ebp)
0x0040f27a:	pushl %eax
0x0040f27b:	pushl -12(%ebp)
0x0040f27e:	pushl %edi
0x0040f27f:	pushl %ebx
0x0040f280:	pushl %ebx
0x0040f281:	call WideCharToMultiByte@KERNEL32.DLL
0x0040f283:	testl %eax, %eax
0x0040f285:	jne 0x0040f293
0x0040f293:	movl %ebx, -4(%ebp)
0x0040f296:	pushl %edi
0x0040f297:	call FreeEnvironmentStringsW@KERNEL32.DLL
FreeEnvironmentStringsW@KERNEL32.DLL: API Node	
0x0040f29d:	movl %eax, %ebx
0x0040f29f:	jmp 0x0040f2fd
0x0040f2fd:	popl %edi
0x0040f2fe:	popl %esi
0x0040f2ff:	popl %ebx
0x0040f300:	leave
0x0040f301:	ret

0x00408f27:	movl 0x42ae2c, %eax
0x00408f2c:	call 0x0040f110
0x0040f110:	movl %edi, %edi
0x0040f112:	pushl %ebp
0x0040f113:	movl %ebp, %esp
0x0040f115:	subl %esp, $0xc<UINT8>
0x0040f118:	pushl %ebx
0x0040f119:	xorl %ebx, %ebx
0x0040f11b:	pushl %esi
0x0040f11c:	pushl %edi
0x0040f11d:	cmpl 0x42c8ec, %ebx
0x0040f123:	jne 5
0x0040f125:	call 0x0040ba78
0x0040ba78:	cmpl 0x42c8ec, $0x0<UINT8>
0x0040ba7f:	jne 0x0040ba93
0x0040ba81:	pushl $0xfffffffd<UINT8>
0x0040ba83:	call 0x0040b8de
0x0040b8de:	pushl $0x14<UINT8>
0x0040b8e0:	pushl $0x425368<UINT32>
0x0040b8e5:	call 0x0040a468
0x0040b8ea:	orl -32(%ebp), $0xffffffff<UINT8>
0x0040b8ee:	call 0x0040c0bf
0x0040c0bf:	movl %edi, %edi
0x0040c0c1:	pushl %esi
0x0040c0c2:	call 0x0040c046
0x0040c046:	movl %edi, %edi
0x0040c048:	pushl %esi
0x0040c049:	pushl %edi
0x0040c04a:	call GetLastError@KERNEL32.DLL
GetLastError@KERNEL32.DLL: API Node	
0x0040c050:	pushl 0x427a50
0x0040c056:	movl %edi, %eax
0x0040c058:	call 0x0040bed1
0x0040bed1:	movl %edi, %edi
0x0040bed3:	pushl %esi
0x0040bed4:	pushl 0x427a54
0x0040beda:	call TlsGetValue@KERNEL32.DLL
0x0040bee0:	movl %esi, %eax
0x0040bee2:	testl %esi, %esi
0x0040bee4:	jne 0x0040bf01
0x0040bf01:	movl %eax, %esi
0x0040bf03:	popl %esi
0x0040bf04:	ret

0x0040c05d:	call FlsGetValue@KERNEL32.DLL
0x0040c05f:	movl %esi, %eax
0x0040c061:	testl %esi, %esi
0x0040c063:	jne 0x0040c0b3
0x0040c0b3:	pushl %edi
0x0040c0b4:	call SetLastError@KERNEL32.DLL
SetLastError@KERNEL32.DLL: API Node	
0x0040c0ba:	popl %edi
0x0040c0bb:	movl %eax, %esi
0x0040c0bd:	popl %esi
0x0040c0be:	ret

0x0040c0c7:	movl %esi, %eax
0x0040c0c9:	testl %esi, %esi
0x0040c0cb:	jne 0x0040c0d5
0x0040c0d5:	movl %eax, %esi
0x0040c0d7:	popl %esi
0x0040c0d8:	ret

0x0040b8f3:	movl %edi, %eax
0x0040b8f5:	movl -36(%ebp), %edi
0x0040b8f8:	call 0x0040b5d9
0x0040b5d9:	pushl $0xc<UINT8>
0x0040b5db:	pushl $0x425348<UINT32>
0x0040b5e0:	call 0x0040a468
0x0040b5e5:	call 0x0040c0bf
0x0040b5ea:	movl %edi, %eax
0x0040b5ec:	movl %eax, 0x42795c
0x0040b5f1:	testl 0x70(%edi), %eax
0x0040b5f4:	je 0x0040b613
0x0040b613:	pushl $0xd<UINT8>
0x0040b615:	call 0x0040ca4e
0x0040b61a:	popl %ecx
0x0040b61b:	andl -4(%ebp), $0x0<UINT8>
0x0040b61f:	movl %esi, 0x68(%edi)
0x0040b622:	movl -28(%ebp), %esi
0x0040b625:	cmpl %esi, 0x427860
0x0040b62b:	je 0x0040b663
0x0040b663:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040b66a:	call 0x0040b674
0x0040b674:	pushl $0xd<UINT8>
0x0040b676:	call 0x0040c974
0x0040b67b:	popl %ecx
0x0040b67c:	ret

0x0040b66f:	jmp 0x0040b5ff
0x0040b5ff:	testl %esi, %esi
0x0040b601:	jne 0x0040b60b
0x0040b60b:	movl %eax, %esi
0x0040b60d:	call 0x0040a4ad
0x0040b612:	ret

0x0040b8fd:	movl %ebx, 0x68(%edi)
0x0040b900:	movl %esi, 0x8(%ebp)
0x0040b903:	call 0x0040b67d
0x0040b67d:	movl %edi, %edi
0x0040b67f:	pushl %ebp
0x0040b680:	movl %ebp, %esp
0x0040b682:	subl %esp, $0x10<UINT8>
0x0040b685:	pushl %ebx
0x0040b686:	xorl %ebx, %ebx
0x0040b688:	pushl %ebx
0x0040b689:	leal %ecx, -16(%ebp)
0x0040b68c:	call 0x00405225
0x00405225:	movl %edi, %edi
0x00405227:	pushl %ebp
0x00405228:	movl %ebp, %esp
0x0040522a:	movl %eax, 0x8(%ebp)
0x0040522d:	pushl %esi
0x0040522e:	movl %esi, %ecx
0x00405230:	movb 0xc(%esi), $0x0<UINT8>
0x00405234:	testl %eax, %eax
0x00405236:	jne 99
0x00405238:	call 0x0040c0bf
0x0040523d:	movl 0x8(%esi), %eax
0x00405240:	movl %ecx, 0x6c(%eax)
0x00405243:	movl (%esi), %ecx
0x00405245:	movl %ecx, 0x68(%eax)
0x00405248:	movl 0x4(%esi), %ecx
0x0040524b:	movl %ecx, (%esi)
0x0040524d:	cmpl %ecx, 0x427a40
0x00405253:	je 0x00405267
0x00405267:	movl %eax, 0x4(%esi)
0x0040526a:	cmpl %eax, 0x427860
0x00405270:	je 0x00405288
0x00405288:	movl %eax, 0x8(%esi)
0x0040528b:	testb 0x70(%eax), $0x2<UINT8>
0x0040528f:	jne 20
0x00405291:	orl 0x70(%eax), $0x2<UINT8>
0x00405295:	movb 0xc(%esi), $0x1<UINT8>
0x00405299:	jmp 0x004052a5
0x004052a5:	movl %eax, %esi
0x004052a7:	popl %esi
0x004052a8:	popl %ebp
0x004052a9:	ret $0x4<UINT16>

0x0040b691:	movl 0x42b15c, %ebx
0x0040b697:	cmpl %esi, $0xfffffffe<UINT8>
0x0040b69a:	jne 0x0040b6ba
0x0040b6ba:	cmpl %esi, $0xfffffffd<UINT8>
0x0040b6bd:	jne 0x0040b6d1
0x0040b6bf:	movl 0x42b15c, $0x1<UINT32>
0x0040b6c9:	call GetACP@KERNEL32.DLL
GetACP@KERNEL32.DLL: API Node	
0x0040b6cf:	jmp 0x0040b6ac
0x0040b6ac:	cmpb -4(%ebp), %bl
0x0040b6af:	je 69
0x0040b6b1:	movl %ecx, -8(%ebp)
0x0040b6b4:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0040b6b8:	jmp 0x0040b6f6
0x0040b6f6:	popl %ebx
0x0040b6f7:	leave
0x0040b6f8:	ret

0x0040b908:	movl 0x8(%ebp), %eax
0x0040b90b:	cmpl %eax, 0x4(%ebx)
0x0040b90e:	je 343
0x0040b914:	pushl $0x220<UINT32>
0x0040b919:	call 0x0040e470
0x0040b91e:	popl %ecx
0x0040b91f:	movl %ebx, %eax
0x0040b921:	testl %ebx, %ebx
0x0040b923:	je 326
0x0040b929:	movl %ecx, $0x88<UINT32>
0x0040b92e:	movl %esi, 0x68(%edi)
0x0040b931:	movl %edi, %ebx
0x0040b933:	rep movsl %es:(%edi), %ds:(%esi)
0x0040b935:	andl (%ebx), $0x0<UINT8>
0x0040b938:	pushl %ebx
0x0040b939:	pushl 0x8(%ebp)
0x0040b93c:	call 0x0040b6f9
0x0040b6f9:	movl %edi, %edi
0x0040b6fb:	pushl %ebp
0x0040b6fc:	movl %ebp, %esp
0x0040b6fe:	subl %esp, $0x20<UINT8>
0x0040b701:	movl %eax, 0x4272b4
0x0040b706:	xorl %eax, %ebp
0x0040b708:	movl -4(%ebp), %eax
0x0040b70b:	pushl %ebx
0x0040b70c:	movl %ebx, 0xc(%ebp)
0x0040b70f:	pushl %esi
0x0040b710:	movl %esi, 0x8(%ebp)
0x0040b713:	pushl %edi
0x0040b714:	call 0x0040b67d
0x0040b6d1:	cmpl %esi, $0xfffffffc<UINT8>
0x0040b6d4:	jne 0x0040b6e8
0x0040b6e8:	cmpb -4(%ebp), %bl
0x0040b6eb:	je 7
0x0040b6ed:	movl %eax, -8(%ebp)
0x0040b6f0:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x0040b6f4:	movl %eax, %esi
0x0040b719:	movl %edi, %eax
0x0040b71b:	xorl %esi, %esi
0x0040b71d:	movl 0x8(%ebp), %edi
0x0040b720:	cmpl %edi, %esi
0x0040b722:	jne 0x0040b732
0x0040b732:	movl -28(%ebp), %esi
0x0040b735:	xorl %eax, %eax
0x0040b737:	cmpl 0x427868(%eax), %edi
0x0040b73d:	je 145
0x0040b743:	incl -28(%ebp)
0x0040b746:	addl %eax, $0x30<UINT8>
0x0040b749:	cmpl %eax, $0xf0<UINT32>
0x0040b74e:	jb 0x0040b737
0x0040b750:	cmpl %edi, $0xfde8<UINT32>
0x0040b756:	je 368
0x0040b75c:	cmpl %edi, $0xfde9<UINT32>
0x0040b762:	je 356
0x0040b768:	movzwl %eax, %di
0x0040b76b:	pushl %eax
0x0040b76c:	call IsValidCodePage@KERNEL32.DLL
IsValidCodePage@KERNEL32.DLL: API Node	
0x0040b772:	testl %eax, %eax
0x0040b774:	je 338
0x0040b77a:	leal %eax, -24(%ebp)
0x0040b77d:	pushl %eax
0x0040b77e:	pushl %edi
0x0040b77f:	call GetCPInfo@KERNEL32.DLL
GetCPInfo@KERNEL32.DLL: API Node	
0x0040b785:	testl %eax, %eax
0x0040b787:	je 307
0x0040b78d:	pushl $0x101<UINT32>
0x0040b792:	leal %eax, 0x1c(%ebx)
0x0040b795:	pushl %esi
0x0040b796:	pushl %eax
0x0040b797:	call 0x00405c10
0x00405c10:	movl %edx, 0xc(%esp)
0x00405c14:	movl %ecx, 0x4(%esp)
0x00405c18:	testl %edx, %edx
0x00405c1a:	je 105
0x00405c1c:	xorl %eax, %eax
0x00405c1e:	movb %al, 0x8(%esp)
0x00405c22:	testb %al, %al
0x00405c24:	jne 22
0x00405c26:	cmpl %edx, $0x100<UINT32>
0x00405c2c:	jb 14
0x00405c2e:	cmpl 0x42c910, $0x0<UINT8>
0x00405c35:	je 0x00405c3c
0x00405c3c:	pushl %edi
0x00405c3d:	movl %edi, %ecx
0x00405c3f:	cmpl %edx, $0x4<UINT8>
0x00405c42:	jb 49
0x00405c44:	negl %ecx
0x00405c46:	andl %ecx, $0x3<UINT8>
0x00405c49:	je 0x00405c57
0x00405c57:	movl %ecx, %eax
0x00405c59:	shll %eax, $0x8<UINT8>
0x00405c5c:	addl %eax, %ecx
0x00405c5e:	movl %ecx, %eax
0x00405c60:	shll %eax, $0x10<UINT8>
0x00405c63:	addl %eax, %ecx
0x00405c65:	movl %ecx, %edx
0x00405c67:	andl %edx, $0x3<UINT8>
0x00405c6a:	shrl %ecx, $0x2<UINT8>
0x00405c6d:	je 6
0x00405c6f:	rep stosl %es:(%edi), %eax
0x00405c71:	testl %edx, %edx
0x00405c73:	je 0x00405c7f
0x00405c75:	movb (%edi), %al
0x00405c77:	addl %edi, $0x1<UINT8>
0x00405c7a:	subl %edx, $0x1<UINT8>
0x00405c7d:	jne -10
0x00405c7f:	movl %eax, 0x8(%esp)
0x00405c83:	popl %edi
0x00405c84:	ret

0x0040b79c:	xorl %edx, %edx
0x0040b79e:	incl %edx
0x0040b79f:	addl %esp, $0xc<UINT8>
0x0040b7a2:	movl 0x4(%ebx), %edi
0x0040b7a5:	movl 0xc(%ebx), %esi
0x0040b7a8:	cmpl -24(%ebp), %edx
0x0040b7ab:	jbe 248
0x0040b7b1:	cmpb -18(%ebp), $0x0<UINT8>
0x0040b7b5:	je 0x0040b88a
0x0040b88a:	leal %eax, 0x1e(%ebx)
0x0040b88d:	movl %ecx, $0xfe<UINT32>
0x0040b892:	orb (%eax), $0x8<UINT8>
0x0040b895:	incl %eax
0x0040b896:	decl %ecx
0x0040b897:	jne 0x0040b892
0x0040b899:	movl %eax, 0x4(%ebx)
0x0040b89c:	call 0x0040b3b3
0x0040b3b3:	subl %eax, $0x3a4<UINT32>
0x0040b3b8:	je 34
0x0040b3ba:	subl %eax, $0x4<UINT8>
0x0040b3bd:	je 23
0x0040b3bf:	subl %eax, $0xd<UINT8>
0x0040b3c2:	je 12
0x0040b3c4:	decl %eax
0x0040b3c5:	je 3
0x0040b3c7:	xorl %eax, %eax
0x0040b3c9:	ret

0x0040b8a1:	movl 0xc(%ebx), %eax
0x0040b8a4:	movl 0x8(%ebx), %edx
0x0040b8a7:	jmp 0x0040b8ac
0x0040b8ac:	xorl %eax, %eax
0x0040b8ae:	movzwl %ecx, %ax
0x0040b8b1:	movl %eax, %ecx
0x0040b8b3:	shll %ecx, $0x10<UINT8>
0x0040b8b6:	orl %eax, %ecx
0x0040b8b8:	leal %edi, 0x10(%ebx)
0x0040b8bb:	stosl %es:(%edi), %eax
0x0040b8bc:	stosl %es:(%edi), %eax
0x0040b8bd:	stosl %es:(%edi), %eax
0x0040b8be:	jmp 0x0040b868
0x0040b868:	movl %esi, %ebx
0x0040b86a:	call 0x0040b446
0x0040b446:	movl %edi, %edi
0x0040b448:	pushl %ebp
0x0040b449:	movl %ebp, %esp
0x0040b44b:	subl %esp, $0x51c<UINT32>
0x0040b451:	movl %eax, 0x4272b4
0x0040b456:	xorl %eax, %ebp
0x0040b458:	movl -4(%ebp), %eax
0x0040b45b:	pushl %ebx
0x0040b45c:	pushl %edi
0x0040b45d:	leal %eax, -1304(%ebp)
0x0040b463:	pushl %eax
0x0040b464:	pushl 0x4(%esi)
0x0040b467:	call GetCPInfo@KERNEL32.DLL
0x0040b46d:	movl %edi, $0x100<UINT32>
0x0040b472:	testl %eax, %eax
0x0040b474:	je 251
0x0040b47a:	xorl %eax, %eax
0x0040b47c:	movb -260(%ebp,%eax), %al
0x0040b483:	incl %eax
0x0040b484:	cmpl %eax, %edi
0x0040b486:	jb 0x0040b47c
0x0040b488:	movb %al, -1298(%ebp)
0x0040b48e:	movb -260(%ebp), $0x20<UINT8>
0x0040b495:	testb %al, %al
0x0040b497:	je 0x0040b4c7
0x0040b4c7:	pushl $0x0<UINT8>
0x0040b4c9:	pushl 0xc(%esi)
0x0040b4cc:	leal %eax, -1284(%ebp)
0x0040b4d2:	pushl 0x4(%esi)
0x0040b4d5:	pushl %eax
0x0040b4d6:	pushl %edi
0x0040b4d7:	leal %eax, -260(%ebp)
0x0040b4dd:	pushl %eax
0x0040b4de:	pushl $0x1<UINT8>
0x0040b4e0:	pushl $0x0<UINT8>
0x0040b4e2:	call 0x00411984
0x00411984:	movl %edi, %edi
0x00411986:	pushl %ebp
0x00411987:	movl %ebp, %esp
0x00411989:	subl %esp, $0x10<UINT8>
0x0041198c:	pushl 0x8(%ebp)
0x0041198f:	leal %ecx, -16(%ebp)
0x00411992:	call 0x00405225
0x00411997:	pushl 0x24(%ebp)
0x0041199a:	leal %ecx, -16(%ebp)
0x0041199d:	pushl 0x20(%ebp)
0x004119a0:	pushl 0x1c(%ebp)
0x004119a3:	pushl 0x18(%ebp)
0x004119a6:	pushl 0x14(%ebp)
0x004119a9:	pushl 0x10(%ebp)
0x004119ac:	pushl 0xc(%ebp)
0x004119af:	call 0x004117ca
0x004117ca:	movl %edi, %edi
0x004117cc:	pushl %ebp
0x004117cd:	movl %ebp, %esp
0x004117cf:	pushl %ecx
0x004117d0:	pushl %ecx
0x004117d1:	movl %eax, 0x4272b4
0x004117d6:	xorl %eax, %ebp
0x004117d8:	movl -4(%ebp), %eax
0x004117db:	movl %eax, 0x42b784
0x004117e0:	pushl %ebx
0x004117e1:	pushl %esi
0x004117e2:	xorl %ebx, %ebx
0x004117e4:	pushl %edi
0x004117e5:	movl %edi, %ecx
0x004117e7:	cmpl %eax, %ebx
0x004117e9:	jne 58
0x004117eb:	leal %eax, -8(%ebp)
0x004117ee:	pushl %eax
0x004117ef:	xorl %esi, %esi
0x004117f1:	incl %esi
0x004117f2:	pushl %esi
0x004117f3:	pushl $0x422654<UINT32>
0x004117f8:	pushl %esi
0x004117f9:	call GetStringTypeW@KERNEL32.DLL
GetStringTypeW@KERNEL32.DLL: API Node	
0x004117ff:	testl %eax, %eax
0x00411801:	je 8
0x00411803:	movl 0x42b784, %esi
0x00411809:	jmp 0x0041183f
0x0041183f:	movl -8(%ebp), %ebx
0x00411842:	cmpl 0x18(%ebp), %ebx
0x00411845:	jne 0x0041184f
0x0041184f:	movl %esi, 0x42219c
0x00411855:	xorl %eax, %eax
0x00411857:	cmpl 0x20(%ebp), %ebx
0x0041185a:	pushl %ebx
0x0041185b:	pushl %ebx
0x0041185c:	pushl 0x10(%ebp)
0x0041185f:	setne %al
0x00411862:	pushl 0xc(%ebp)
0x00411865:	leal %eax, 0x1(,%eax,8)
0x0041186c:	pushl %eax
0x0041186d:	pushl 0x18(%ebp)
0x00411870:	call MultiByteToWideChar@KERNEL32.DLL
MultiByteToWideChar@KERNEL32.DLL: API Node	
0x00411872:	movl %edi, %eax
0x00411874:	cmpl %edi, %ebx
0x00411876:	je 171
0x0041187c:	jle 60
0x0041187e:	cmpl %edi, $0x7ffffff0<UINT32>
0x00411884:	ja 52
0x00411886:	leal %eax, 0x8(%edi,%edi)
0x0041188a:	cmpl %eax, $0x400<UINT32>
0x0041188f:	ja 19
0x00411891:	call 0x0040e120
0x0040e120:	pushl %ecx
0x0040e121:	leal %ecx, 0x8(%esp)
0x0040e125:	subl %ecx, %eax
0x0040e127:	andl %ecx, $0xf<UINT8>
0x0040e12a:	addl %eax, %ecx
0x0040e12c:	sbbl %ecx, %ecx
0x0040e12e:	orl %eax, %ecx
0x0040e130:	popl %ecx
0x0040e131:	jmp 0x004113c0
0x004113c0:	pushl %ecx
0x004113c1:	leal %ecx, 0x4(%esp)
0x004113c5:	subl %ecx, %eax
0x004113c7:	sbbl %eax, %eax
0x004113c9:	notl %eax
0x004113cb:	andl %ecx, %eax
0x004113cd:	movl %eax, %esp
0x004113cf:	andl %eax, $0xfffff000<UINT32>
0x004113d4:	cmpl %ecx, %eax
0x004113d6:	jb 10
0x004113d8:	movl %eax, %ecx
0x004113da:	popl %ecx
0x004113db:	xchgl %esp, %eax
0x004113dc:	movl %eax, (%eax)
0x004113de:	movl (%esp), %eax
0x004113e1:	ret

0x00411896:	movl %eax, %esp
0x00411898:	cmpl %eax, %ebx
0x0041189a:	je 28
0x0041189c:	movl (%eax), $0xcccc<UINT32>
0x004118a2:	jmp 0x004118b5
0x004118b5:	addl %eax, $0x8<UINT8>
0x004118b8:	movl %ebx, %eax
0x004118ba:	testl %ebx, %ebx
0x004118bc:	je 105
0x004118be:	leal %eax, (%edi,%edi)
0x004118c1:	pushl %eax
0x004118c2:	pushl $0x0<UINT8>
0x004118c4:	pushl %ebx
0x004118c5:	call 0x00405c10
0x004118ca:	addl %esp, $0xc<UINT8>
0x004118cd:	pushl %edi
0x004118ce:	pushl %ebx
0x004118cf:	pushl 0x10(%ebp)
0x004118d2:	pushl 0xc(%ebp)
0x004118d5:	pushl $0x1<UINT8>
0x004118d7:	pushl 0x18(%ebp)
0x004118da:	call MultiByteToWideChar@KERNEL32.DLL
0x004118dc:	testl %eax, %eax
0x004118de:	je 17
0x004118e0:	pushl 0x14(%ebp)
0x004118e3:	pushl %eax
0x004118e4:	pushl %ebx
0x004118e5:	pushl 0x8(%ebp)
0x004118e8:	call GetStringTypeW@KERNEL32.DLL
0x004118ee:	movl -8(%ebp), %eax
0x004118f1:	pushl %ebx
0x004118f2:	call 0x004075d9
0x004075d9:	movl %edi, %edi
0x004075db:	pushl %ebp
0x004075dc:	movl %ebp, %esp
0x004075de:	movl %eax, 0x8(%ebp)
0x004075e1:	testl %eax, %eax
0x004075e3:	je 18
0x004075e5:	subl %eax, $0x8<UINT8>
0x004075e8:	cmpl (%eax), $0xdddd<UINT32>
0x004075ee:	jne 0x004075f7
0x004075f7:	popl %ebp
0x004075f8:	ret

0x004118f7:	movl %eax, -8(%ebp)
0x004118fa:	popl %ecx
0x004118fb:	jmp 0x00411972
0x00411972:	leal %esp, -20(%ebp)
0x00411975:	popl %edi
0x00411976:	popl %esi
0x00411977:	popl %ebx
0x00411978:	movl %ecx, -4(%ebp)
0x0041197b:	xorl %ecx, %ebp
0x0041197d:	call 0x004049ce
0x004049ce:	cmpl %ecx, 0x4272b4
0x004049d4:	jne 2
0x004049d6:	rep ret

0x00411982:	leave
0x00411983:	ret

0x004119b4:	addl %esp, $0x1c<UINT8>
0x004119b7:	cmpb -4(%ebp), $0x0<UINT8>
0x004119bb:	je 7
0x004119bd:	movl %ecx, -8(%ebp)
0x004119c0:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x004119c4:	leave
0x004119c5:	ret

0x0040b4e7:	xorl %ebx, %ebx
0x0040b4e9:	pushl %ebx
0x0040b4ea:	pushl 0x4(%esi)
0x0040b4ed:	leal %eax, -516(%ebp)
0x0040b4f3:	pushl %edi
0x0040b4f4:	pushl %eax
0x0040b4f5:	pushl %edi
0x0040b4f6:	leal %eax, -260(%ebp)
0x0040b4fc:	pushl %eax
0x0040b4fd:	pushl %edi
0x0040b4fe:	pushl 0xc(%esi)
0x0040b501:	pushl %ebx
0x0040b502:	call 0x0040c85d
0x0040c85d:	movl %edi, %edi
0x0040c85f:	pushl %ebp
0x0040c860:	movl %ebp, %esp
0x0040c862:	subl %esp, $0x10<UINT8>
0x0040c865:	pushl 0x8(%ebp)
0x0040c868:	leal %ecx, -16(%ebp)
0x0040c86b:	call 0x00405225
0x0040c870:	pushl 0x28(%ebp)
0x0040c873:	leal %ecx, -16(%ebp)
0x0040c876:	pushl 0x24(%ebp)
0x0040c879:	pushl 0x20(%ebp)
0x0040c87c:	pushl 0x1c(%ebp)
0x0040c87f:	pushl 0x18(%ebp)
0x0040c882:	pushl 0x14(%ebp)
0x0040c885:	pushl 0x10(%ebp)
0x0040c888:	pushl 0xc(%ebp)
0x0040c88b:	call 0x0040c4b8
0x0040c4b8:	movl %edi, %edi
0x0040c4ba:	pushl %ebp
0x0040c4bb:	movl %ebp, %esp
0x0040c4bd:	subl %esp, $0x14<UINT8>
0x0040c4c0:	movl %eax, 0x4272b4
0x0040c4c5:	xorl %eax, %ebp
0x0040c4c7:	movl -4(%ebp), %eax
0x0040c4ca:	pushl %ebx
0x0040c4cb:	pushl %esi
0x0040c4cc:	xorl %ebx, %ebx
0x0040c4ce:	pushl %edi
0x0040c4cf:	movl %esi, %ecx
0x0040c4d1:	cmpl 0x42b1ac, %ebx
0x0040c4d7:	jne 0x0040c511
0x0040c4d9:	pushl %ebx
0x0040c4da:	pushl %ebx
0x0040c4db:	xorl %edi, %edi
0x0040c4dd:	incl %edi
0x0040c4de:	pushl %edi
0x0040c4df:	pushl $0x422654<UINT32>
0x0040c4e4:	pushl $0x100<UINT32>
0x0040c4e9:	pushl %ebx
0x0040c4ea:	call LCMapStringW@KERNEL32.DLL
LCMapStringW@KERNEL32.DLL: API Node	
0x0040c4f0:	testl %eax, %eax
0x0040c4f2:	je 8
0x0040c4f4:	movl 0x42b1ac, %edi
0x0040c4fa:	jmp 0x0040c511
0x0040c511:	cmpl 0x14(%ebp), %ebx
0x0040c514:	jle 0x0040c538
0x0040c516:	movl %ecx, 0x14(%ebp)
0x0040c519:	movl %eax, 0x10(%ebp)
0x0040c51c:	decl %ecx
0x0040c51d:	cmpb (%eax), %bl
0x0040c51f:	je 8
0x0040c521:	incl %eax
0x0040c522:	cmpl %ecx, %ebx
0x0040c524:	jne 0x0040c51c
0x0040c526:	orl %ecx, $0xffffffff<UINT8>
0x0040c529:	movl %eax, 0x14(%ebp)
0x0040c52c:	subl %eax, %ecx
0x0040c52e:	decl %eax
0x0040c52f:	cmpl %eax, 0x14(%ebp)
0x0040c532:	jnl 0x0040c535
0x0040c535:	movl 0x14(%ebp), %eax
0x0040c538:	movl %eax, 0x42b1ac
0x0040c53d:	cmpl %eax, $0x2<UINT8>
0x0040c540:	je 428
0x0040c546:	cmpl %eax, %ebx
0x0040c548:	je 420
0x0040c54e:	cmpl %eax, $0x1<UINT8>
0x0040c551:	jne 460
0x0040c557:	movl -8(%ebp), %ebx
0x0040c55a:	cmpl 0x20(%ebp), %ebx
0x0040c55d:	jne 0x0040c567
0x0040c567:	movl %esi, 0x42219c
0x0040c56d:	xorl %eax, %eax
0x0040c56f:	cmpl 0x24(%ebp), %ebx
0x0040c572:	pushl %ebx
0x0040c573:	pushl %ebx
0x0040c574:	pushl 0x14(%ebp)
0x0040c577:	setne %al
0x0040c57a:	pushl 0x10(%ebp)
0x0040c57d:	leal %eax, 0x1(,%eax,8)
0x0040c584:	pushl %eax
0x0040c585:	pushl 0x20(%ebp)
0x0040c588:	call MultiByteToWideChar@KERNEL32.DLL
0x0040c58a:	movl %edi, %eax
0x0040c58c:	cmpl %edi, %ebx
0x0040c58e:	je 0x0040c723
0x0040c594:	jle 67
0x0040c596:	pushl $0xffffffe0<UINT8>
0x0040c598:	xorl %edx, %edx
0x0040c59a:	popl %eax
0x0040c59b:	divl %eax, %edi
0x0040c59d:	cmpl %eax, $0x2<UINT8>
0x0040c5a0:	jb 55
0x0040c5a2:	leal %eax, 0x8(%edi,%edi)
0x0040c5a6:	cmpl %eax, $0x400<UINT32>
0x0040c5ab:	ja 19
0x0040c5ad:	call 0x0040e120
0x0040c5b2:	movl %eax, %esp
0x0040c5b4:	cmpl %eax, %ebx
0x0040c5b6:	je 28
0x0040c5b8:	movl (%eax), $0xcccc<UINT32>
0x0040c5be:	jmp 0x0040c5d1
0x0040c5d1:	addl %eax, $0x8<UINT8>
0x0040c5d4:	movl -12(%ebp), %eax
0x0040c5d7:	jmp 0x0040c5dc
0x0040c5dc:	cmpl -12(%ebp), %ebx
0x0040c5df:	je 318
0x0040c5e5:	pushl %edi
0x0040c5e6:	pushl -12(%ebp)
0x0040c5e9:	pushl 0x14(%ebp)
0x0040c5ec:	pushl 0x10(%ebp)
0x0040c5ef:	pushl $0x1<UINT8>
0x0040c5f1:	pushl 0x20(%ebp)
0x0040c5f4:	call MultiByteToWideChar@KERNEL32.DLL
0x0040c5f6:	testl %eax, %eax
0x0040c5f8:	je 227
0x0040c5fe:	movl %esi, 0x422198
0x0040c604:	pushl %ebx
0x0040c605:	pushl %ebx
0x0040c606:	pushl %edi
0x0040c607:	pushl -12(%ebp)
0x0040c60a:	pushl 0xc(%ebp)
0x0040c60d:	pushl 0x8(%ebp)
0x0040c610:	call LCMapStringW@KERNEL32.DLL
0x0040c612:	movl %ecx, %eax
0x0040c614:	movl -8(%ebp), %ecx
0x0040c617:	cmpl %ecx, %ebx
0x0040c619:	je 194
0x0040c61f:	testl 0xc(%ebp), $0x400<UINT32>
0x0040c626:	je 0x0040c651
0x0040c651:	cmpl %ecx, %ebx
0x0040c653:	jle 69
0x0040c655:	pushl $0xffffffe0<UINT8>
0x0040c657:	xorl %edx, %edx
0x0040c659:	popl %eax
0x0040c65a:	divl %eax, %ecx
0x0040c65c:	cmpl %eax, $0x2<UINT8>
0x0040c65f:	jb 57
0x0040c661:	leal %eax, 0x8(%ecx,%ecx)
0x0040c665:	cmpl %eax, $0x400<UINT32>
0x0040c66a:	ja 22
0x0040c66c:	call 0x0040e120
0x0040c671:	movl %esi, %esp
0x0040c673:	cmpl %esi, %ebx
0x0040c675:	je 106
0x0040c677:	movl (%esi), $0xcccc<UINT32>
0x0040c67d:	addl %esi, $0x8<UINT8>
0x0040c680:	jmp 0x0040c69c
0x0040c69c:	cmpl %esi, %ebx
0x0040c69e:	je 65
0x0040c6a0:	pushl -8(%ebp)
0x0040c6a3:	pushl %esi
0x0040c6a4:	pushl %edi
0x0040c6a5:	pushl -12(%ebp)
0x0040c6a8:	pushl 0xc(%ebp)
0x0040c6ab:	pushl 0x8(%ebp)
0x0040c6ae:	call LCMapStringW@KERNEL32.DLL
0x0040c6b4:	testl %eax, %eax
0x0040c6b6:	je 34
0x0040c6b8:	pushl %ebx
0x0040c6b9:	pushl %ebx
0x0040c6ba:	cmpl 0x1c(%ebp), %ebx
0x0040c6bd:	jne 0x0040c6c3
0x0040c6c3:	pushl 0x1c(%ebp)
0x0040c6c6:	pushl 0x18(%ebp)
0x0040c6c9:	pushl -8(%ebp)
0x0040c6cc:	pushl %esi
0x0040c6cd:	pushl %ebx
0x0040c6ce:	pushl 0x20(%ebp)
0x0040c6d1:	call WideCharToMultiByte@KERNEL32.DLL
0x0040c6d7:	movl -8(%ebp), %eax
0x0040c6da:	pushl %esi
0x0040c6db:	call 0x004075d9
0x0040c6e0:	popl %ecx
0x0040c6e1:	pushl -12(%ebp)
0x0040c6e4:	call 0x004075d9
0x0040c6e9:	movl %eax, -8(%ebp)
0x0040c6ec:	popl %ecx
0x0040c6ed:	jmp 0x0040c84b
0x0040c84b:	leal %esp, -32(%ebp)
0x0040c84e:	popl %edi
0x0040c84f:	popl %esi
0x0040c850:	popl %ebx
0x0040c851:	movl %ecx, -4(%ebp)
0x0040c854:	xorl %ecx, %ebp
0x0040c856:	call 0x004049ce
0x0040c85b:	leave
0x0040c85c:	ret

0x0040c890:	addl %esp, $0x20<UINT8>
0x0040c893:	cmpb -4(%ebp), $0x0<UINT8>
0x0040c897:	je 7
0x0040c899:	movl %ecx, -8(%ebp)
0x0040c89c:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x0040c8a0:	leave
0x0040c8a1:	ret

0x0040b507:	addl %esp, $0x44<UINT8>
0x0040b50a:	pushl %ebx
0x0040b50b:	pushl 0x4(%esi)
0x0040b50e:	leal %eax, -772(%ebp)
0x0040b514:	pushl %edi
0x0040b515:	pushl %eax
0x0040b516:	pushl %edi
0x0040b517:	leal %eax, -260(%ebp)
0x0040b51d:	pushl %eax
0x0040b51e:	pushl $0x200<UINT32>
0x0040b523:	pushl 0xc(%esi)
0x0040b526:	pushl %ebx
0x0040b527:	call 0x0040c85d
0x0040c723:	xorl %eax, %eax
0x0040c725:	jmp 0x0040c84b
0x0040b52c:	addl %esp, $0x24<UINT8>
0x0040b52f:	xorl %eax, %eax
0x0040b531:	movzwl %ecx, -1284(%ebp,%eax,2)
0x0040b539:	testb %cl, $0x1<UINT8>
0x0040b53c:	je 0x0040b54c
0x0040b54c:	testb %cl, $0x2<UINT8>
0x0040b54f:	je 0x0040b566
0x0040b566:	movb 0x11d(%esi,%eax), $0x0<UINT8>
0x0040b56e:	incl %eax
0x0040b56f:	cmpl %eax, %edi
0x0040b571:	jb -66
0x0040b573:	jmp 0x0040b5cb
0x0040b5cb:	movl %ecx, -4(%ebp)
0x0040b5ce:	popl %edi
0x0040b5cf:	xorl %ecx, %ebp
0x0040b5d1:	popl %ebx
0x0040b5d2:	call 0x004049ce
0x0040b5d7:	leave
0x0040b5d8:	ret

0x0040b86f:	jmp 0x0040b72b
0x0040b72b:	xorl %eax, %eax
0x0040b72d:	jmp 0x0040b8cf
0x0040b8cf:	movl %ecx, -4(%ebp)
0x0040b8d2:	popl %edi
0x0040b8d3:	popl %esi
0x0040b8d4:	xorl %ecx, %ebp
0x0040b8d6:	popl %ebx
0x0040b8d7:	call 0x004049ce
0x0040b8dc:	leave
0x0040b8dd:	ret

0x0040b941:	popl %ecx
0x0040b942:	popl %ecx
0x0040b943:	movl -32(%ebp), %eax
0x0040b946:	testl %eax, %eax
0x0040b948:	jne 252
0x0040b94e:	movl %esi, -36(%ebp)
0x0040b951:	pushl 0x68(%esi)
0x0040b954:	call InterlockedDecrement@KERNEL32.DLL
InterlockedDecrement@KERNEL32.DLL: API Node	
0x0040b95a:	testl %eax, %eax
0x0040b95c:	jne 17
0x0040b95e:	movl %eax, 0x68(%esi)
0x0040b961:	cmpl %eax, $0x427438<UINT32>
0x0040b966:	je 0x0040b96f
0x0040b96f:	movl 0x68(%esi), %ebx
0x0040b972:	pushl %ebx
0x0040b973:	movl %edi, 0x4220e4
0x0040b979:	call InterlockedIncrement@KERNEL32.DLL
0x0040b97b:	testb 0x70(%esi), $0x2<UINT8>
0x0040b97f:	jne 234
0x0040b985:	testb 0x42795c, $0x1<UINT8>
0x0040b98c:	jne 221
0x0040b992:	pushl $0xd<UINT8>
0x0040b994:	call 0x0040ca4e
0x0040b999:	popl %ecx
0x0040b99a:	andl -4(%ebp), $0x0<UINT8>
0x0040b99e:	movl %eax, 0x4(%ebx)
0x0040b9a1:	movl 0x42b16c, %eax
0x0040b9a6:	movl %eax, 0x8(%ebx)
0x0040b9a9:	movl 0x42b170, %eax
0x0040b9ae:	movl %eax, 0xc(%ebx)
0x0040b9b1:	movl 0x42b174, %eax
0x0040b9b6:	xorl %eax, %eax
0x0040b9b8:	movl -28(%ebp), %eax
0x0040b9bb:	cmpl %eax, $0x5<UINT8>
0x0040b9be:	jnl 0x0040b9d0
0x0040b9c0:	movw %cx, 0x10(%ebx,%eax,2)
0x0040b9c5:	movw 0x42b160(,%eax,2), %cx
0x0040b9cd:	incl %eax
0x0040b9ce:	jmp 0x0040b9b8
0x0040b9d0:	xorl %eax, %eax
0x0040b9d2:	movl -28(%ebp), %eax
0x0040b9d5:	cmpl %eax, $0x101<UINT32>
0x0040b9da:	jnl 0x0040b9e9
0x0040b9dc:	movb %cl, 0x1c(%eax,%ebx)
0x0040b9e0:	movb 0x427658(%eax), %cl
0x0040b9e6:	incl %eax
0x0040b9e7:	jmp 0x0040b9d2
0x0040b9e9:	xorl %eax, %eax
0x0040b9eb:	movl -28(%ebp), %eax
0x0040b9ee:	cmpl %eax, $0x100<UINT32>
0x0040b9f3:	jnl 0x0040ba05
0x0040b9f5:	movb %cl, 0x11d(%eax,%ebx)
0x0040b9fc:	movb 0x427760(%eax), %cl
0x0040ba02:	incl %eax
0x0040ba03:	jmp 0x0040b9eb
0x0040ba05:	pushl 0x427860
0x0040ba0b:	call InterlockedDecrement@KERNEL32.DLL
0x0040ba11:	testl %eax, %eax
0x0040ba13:	jne 0x0040ba28
0x0040ba28:	movl 0x427860, %ebx
0x0040ba2e:	pushl %ebx
0x0040ba2f:	call InterlockedIncrement@KERNEL32.DLL
0x0040ba31:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040ba38:	call 0x0040ba3f
0x0040ba3f:	pushl $0xd<UINT8>
0x0040ba41:	call 0x0040c974
0x0040ba46:	popl %ecx
0x0040ba47:	ret

0x0040ba3d:	jmp 0x0040ba6f
0x0040ba6f:	movl %eax, -32(%ebp)
0x0040ba72:	call 0x0040a4ad
0x0040ba77:	ret

0x0040ba88:	popl %ecx
0x0040ba89:	movl 0x42c8ec, $0x1<UINT32>
0x0040ba93:	xorl %eax, %eax
0x0040ba95:	ret

0x0040f12a:	pushl $0x104<UINT32>
0x0040f12f:	movl %esi, $0x42b670<UINT32>
0x0040f134:	pushl %esi
0x0040f135:	pushl %ebx
0x0040f136:	movb 0x42b774, %bl
0x0040f13c:	call GetModuleFileNameA@KERNEL32.DLL
GetModuleFileNameA@KERNEL32.DLL: API Node	
0x0040f142:	movl %eax, 0x42c914
0x0040f147:	movl 0x42b32c, %esi
0x0040f14d:	cmpl %eax, %ebx
0x0040f14f:	je 7
0x0040f151:	movl -4(%ebp), %eax
0x0040f154:	cmpb (%eax), %bl
0x0040f156:	jne 0x0040f15b
0x0040f15b:	movl %edx, -4(%ebp)
0x0040f15e:	leal %eax, -8(%ebp)
0x0040f161:	pushl %eax
0x0040f162:	pushl %ebx
0x0040f163:	pushl %ebx
0x0040f164:	leal %edi, -12(%ebp)
0x0040f167:	call 0x0040ef76
0x0040ef76:	movl %edi, %edi
0x0040ef78:	pushl %ebp
0x0040ef79:	movl %ebp, %esp
0x0040ef7b:	pushl %ecx
0x0040ef7c:	movl %ecx, 0x10(%ebp)
0x0040ef7f:	pushl %ebx
0x0040ef80:	xorl %eax, %eax
0x0040ef82:	pushl %esi
0x0040ef83:	movl (%edi), %eax
0x0040ef85:	movl %esi, %edx
0x0040ef87:	movl %edx, 0xc(%ebp)
0x0040ef8a:	movl (%ecx), $0x1<UINT32>
0x0040ef90:	cmpl 0x8(%ebp), %eax
0x0040ef93:	je 0x0040ef9e
0x0040ef9e:	movl -4(%ebp), %eax
0x0040efa1:	cmpb (%esi), $0x22<UINT8>
0x0040efa4:	jne 0x0040efb6
0x0040efa6:	xorl %eax, %eax
0x0040efa8:	cmpl -4(%ebp), %eax
0x0040efab:	movb %bl, $0x22<UINT8>
0x0040efad:	sete %al
0x0040efb0:	incl %esi
0x0040efb1:	movl -4(%ebp), %eax
0x0040efb4:	jmp 0x0040eff2
0x0040eff2:	cmpl -4(%ebp), $0x0<UINT8>
0x0040eff6:	jne 0x0040efa1
0x0040efb6:	incl (%edi)
0x0040efb8:	testl %edx, %edx
0x0040efba:	je 0x0040efc4
0x0040efc4:	movb %bl, (%esi)
0x0040efc6:	movzbl %eax, %bl
0x0040efc9:	pushl %eax
0x0040efca:	incl %esi
0x0040efcb:	call 0x004127b7
0x004127b7:	movl %edi, %edi
0x004127b9:	pushl %ebp
0x004127ba:	movl %ebp, %esp
0x004127bc:	pushl $0x4<UINT8>
0x004127be:	pushl $0x0<UINT8>
0x004127c0:	pushl 0x8(%ebp)
0x004127c3:	pushl $0x0<UINT8>
0x004127c5:	call 0x00412764
0x00412764:	movl %edi, %edi
0x00412766:	pushl %ebp
0x00412767:	movl %ebp, %esp
0x00412769:	subl %esp, $0x10<UINT8>
0x0041276c:	pushl 0x8(%ebp)
0x0041276f:	leal %ecx, -16(%ebp)
0x00412772:	call 0x00405225
0x00412777:	movzbl %eax, 0xc(%ebp)
0x0041277b:	movl %ecx, -12(%ebp)
0x0041277e:	movb %dl, 0x14(%ebp)
0x00412781:	testb 0x1d(%ecx,%eax), %dl
0x00412785:	jne 30
0x00412787:	cmpl 0x10(%ebp), $0x0<UINT8>
0x0041278b:	je 0x0041279f
0x0041279f:	xorl %eax, %eax
0x004127a1:	testl %eax, %eax
0x004127a3:	je 0x004127a8
0x004127a8:	cmpb -4(%ebp), $0x0<UINT8>
0x004127ac:	je 7
0x004127ae:	movl %ecx, -8(%ebp)
0x004127b1:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x004127b5:	leave
0x004127b6:	ret

0x004127ca:	addl %esp, $0x10<UINT8>
0x004127cd:	popl %ebp
0x004127ce:	ret

0x0040efd0:	popl %ecx
0x0040efd1:	testl %eax, %eax
0x0040efd3:	je 0x0040efe8
0x0040efe8:	movl %edx, 0xc(%ebp)
0x0040efeb:	movl %ecx, 0x10(%ebp)
0x0040efee:	testb %bl, %bl
0x0040eff0:	je 0x0040f024
0x0040eff8:	cmpb %bl, $0x20<UINT8>
0x0040effb:	je 5
0x0040effd:	cmpb %bl, $0x9<UINT8>
0x0040f000:	jne 0x0040efa1
0x0040f024:	decl %esi
0x0040f025:	jmp 0x0040f00a
0x0040f00a:	andl -4(%ebp), $0x0<UINT8>
0x0040f00e:	cmpb (%esi), $0x0<UINT8>
0x0040f011:	je 0x0040f100
0x0040f100:	movl %eax, 0x8(%ebp)
0x0040f103:	popl %esi
0x0040f104:	popl %ebx
0x0040f105:	testl %eax, %eax
0x0040f107:	je 0x0040f10c
0x0040f10c:	incl (%ecx)
0x0040f10e:	leave
0x0040f10f:	ret

0x0040f16c:	movl %eax, -8(%ebp)
0x0040f16f:	addl %esp, $0xc<UINT8>
0x0040f172:	cmpl %eax, $0x3fffffff<UINT32>
0x0040f177:	jae 74
0x0040f179:	movl %ecx, -12(%ebp)
0x0040f17c:	cmpl %ecx, $0xffffffff<UINT8>
0x0040f17f:	jae 66
0x0040f181:	movl %edi, %eax
0x0040f183:	shll %edi, $0x2<UINT8>
0x0040f186:	leal %eax, (%edi,%ecx)
0x0040f189:	cmpl %eax, %ecx
0x0040f18b:	jb 54
0x0040f18d:	pushl %eax
0x0040f18e:	call 0x0040e470
0x0040f193:	movl %esi, %eax
0x0040f195:	popl %ecx
0x0040f196:	cmpl %esi, %ebx
0x0040f198:	je 41
0x0040f19a:	movl %edx, -4(%ebp)
0x0040f19d:	leal %eax, -8(%ebp)
0x0040f1a0:	pushl %eax
0x0040f1a1:	addl %edi, %esi
0x0040f1a3:	pushl %edi
0x0040f1a4:	pushl %esi
0x0040f1a5:	leal %edi, -12(%ebp)
0x0040f1a8:	call 0x0040ef76
0x0040ef95:	movl %ebx, 0x8(%ebp)
0x0040ef98:	addl 0x8(%ebp), $0x4<UINT8>
0x0040ef9c:	movl (%ebx), %edx
0x0040efbc:	movb %al, (%esi)
0x0040efbe:	movb (%edx), %al
0x0040efc0:	incl %edx
0x0040efc1:	movl 0xc(%ebp), %edx
0x0040f109:	andl (%eax), $0x0<UINT8>
0x0040f1ad:	movl %eax, -8(%ebp)
0x0040f1b0:	addl %esp, $0xc<UINT8>
0x0040f1b3:	decl %eax
0x0040f1b4:	movl 0x42b310, %eax
0x0040f1b9:	movl 0x42b314, %esi
0x0040f1bf:	xorl %eax, %eax
0x0040f1c1:	jmp 0x0040f1c6
0x0040f1c6:	popl %edi
0x0040f1c7:	popl %esi
0x0040f1c8:	popl %ebx
0x0040f1c9:	leave
0x0040f1ca:	ret

0x00408f31:	testl %eax, %eax
0x00408f33:	jnl 0x00408f3d
0x00408f3d:	call 0x0040ee98
0x0040ee98:	cmpl 0x42c8ec, $0x0<UINT8>
0x0040ee9f:	jne 0x0040eea6
0x0040eea6:	pushl %esi
0x0040eea7:	movl %esi, 0x42ae2c
0x0040eead:	pushl %edi
0x0040eeae:	xorl %edi, %edi
0x0040eeb0:	testl %esi, %esi
0x0040eeb2:	jne 0x0040eecc
0x0040eecc:	movb %al, (%esi)
0x0040eece:	testb %al, %al
0x0040eed0:	jne 0x0040eebc
0x0040eebc:	cmpb %al, $0x3d<UINT8>
0x0040eebe:	je 0x0040eec1
0x0040eec1:	pushl %esi
0x0040eec2:	call 0x00404a80
0x00404a80:	movl %ecx, 0x4(%esp)
0x00404a84:	testl %ecx, $0x3<UINT32>
0x00404a8a:	je 0x00404ab0
0x00404ab0:	movl %eax, (%ecx)
0x00404ab2:	movl %edx, $0x7efefeff<UINT32>
0x00404ab7:	addl %edx, %eax
0x00404ab9:	xorl %eax, $0xffffffff<UINT8>
0x00404abc:	xorl %eax, %edx
0x00404abe:	addl %ecx, $0x4<UINT8>
0x00404ac1:	testl %eax, $0x81010100<UINT32>
0x00404ac6:	je 0x00404ab0
0x00404ac8:	movl %eax, -4(%ecx)
0x00404acb:	testb %al, %al
0x00404acd:	je 50
0x00404acf:	testb %ah, %ah
0x00404ad1:	je 36
0x00404ad3:	testl %eax, $0xff0000<UINT32>
0x00404ad8:	je 19
0x00404ada:	testl %eax, $0xff000000<UINT32>
0x00404adf:	je 0x00404ae3
0x00404ae3:	leal %eax, -1(%ecx)
0x00404ae6:	movl %ecx, 0x4(%esp)
0x00404aea:	subl %eax, %ecx
0x00404aec:	ret

0x0040eec7:	popl %ecx
0x0040eec8:	leal %esi, 0x1(%esi,%eax)
0x0040eed2:	pushl $0x4<UINT8>
0x0040eed4:	incl %edi
0x0040eed5:	pushl %edi
0x0040eed6:	call 0x0040e4b5
0x0040eedb:	movl %edi, %eax
0x0040eedd:	popl %ecx
0x0040eede:	popl %ecx
0x0040eedf:	movl 0x42b31c, %edi
0x0040eee5:	testl %edi, %edi
0x0040eee7:	je -53
0x0040eee9:	movl %esi, 0x42ae2c
0x0040eeef:	pushl %ebx
0x0040eef0:	jmp 0x0040ef34
0x0040ef34:	cmpb (%esi), $0x0<UINT8>
0x0040ef37:	jne 0x0040eef2
0x0040eef2:	pushl %esi
0x0040eef3:	call 0x00404a80
0x0040eef8:	movl %ebx, %eax
0x0040eefa:	incl %ebx
0x0040eefb:	cmpb (%esi), $0x3d<UINT8>
0x0040eefe:	popl %ecx
0x0040eeff:	je 0x0040ef32
0x0040ef32:	addl %esi, %ebx
0x0040ef39:	pushl 0x42ae2c
0x0040ef3f:	call 0x0040568d
0x0040568d:	pushl $0xc<UINT8>
0x0040568f:	pushl $0x425160<UINT32>
0x00405694:	call 0x0040a468
0x00405699:	movl %esi, 0x8(%ebp)
0x0040569c:	testl %esi, %esi
0x0040569e:	je 117
0x004056a0:	cmpl 0x42c90c, $0x3<UINT8>
0x004056a7:	jne 0x004056ec
0x004056ec:	pushl %esi
0x004056ed:	pushl $0x0<UINT8>
0x004056ef:	pushl 0x42b1b0
0x004056f5:	call HeapFree@KERNEL32.DLL
HeapFree@KERNEL32.DLL: API Node	
0x004056fb:	testl %eax, %eax
0x004056fd:	jne 0x00405715
0x00405715:	call 0x0040a4ad
0x0040571a:	ret

0x0040ef44:	andl 0x42ae2c, $0x0<UINT8>
0x0040ef4b:	andl (%edi), $0x0<UINT8>
0x0040ef4e:	movl 0x42c8e0, $0x1<UINT32>
0x0040ef58:	xorl %eax, %eax
0x0040ef5a:	popl %ecx
0x0040ef5b:	popl %ebx
0x0040ef5c:	popl %edi
0x0040ef5d:	popl %esi
0x0040ef5e:	ret

0x00408f42:	testl %eax, %eax
0x00408f44:	jnl 0x00408f4e
0x00408f4e:	pushl $0x1<UINT8>
0x00408f50:	call 0x0040d634
0x0040d634:	movl %edi, %edi
0x0040d636:	pushl %ebp
0x0040d637:	movl %ebp, %esp
0x0040d639:	cmpl 0x423e98, $0x0<UINT8>
0x0040d640:	je 25
0x0040d642:	pushl $0x423e98<UINT32>
0x0040d647:	call 0x0040e9c0
0x0040e9c0:	movl %edi, %edi
0x0040e9c2:	pushl %ebp
0x0040e9c3:	movl %ebp, %esp
0x0040e9c5:	pushl $0xfffffffe<UINT8>
0x0040e9c7:	pushl $0x425498<UINT32>
0x0040e9cc:	pushl $0x40a4d0<UINT32>
0x0040e9d1:	movl %eax, %fs:0
0x0040e9d7:	pushl %eax
0x0040e9d8:	subl %esp, $0x8<UINT8>
0x0040e9db:	pushl %ebx
0x0040e9dc:	pushl %esi
0x0040e9dd:	pushl %edi
0x0040e9de:	movl %eax, 0x4272b4
0x0040e9e3:	xorl -8(%ebp), %eax
0x0040e9e6:	xorl %eax, %ebp
0x0040e9e8:	pushl %eax
0x0040e9e9:	leal %eax, -16(%ebp)
0x0040e9ec:	movl %fs:0, %eax
0x0040e9f2:	movl -24(%ebp), %esp
0x0040e9f5:	movl -4(%ebp), $0x0<UINT32>
0x0040e9fc:	pushl $0x400000<UINT32>
0x0040ea01:	call 0x0040e930
0x0040e930:	movl %edi, %edi
0x0040e932:	pushl %ebp
0x0040e933:	movl %ebp, %esp
0x0040e935:	movl %ecx, 0x8(%ebp)
0x0040e938:	movl %eax, $0x5a4d<UINT32>
0x0040e93d:	cmpw (%ecx), %ax
0x0040e940:	je 0x0040e946
0x0040e946:	movl %eax, 0x3c(%ecx)
0x0040e949:	addl %eax, %ecx
0x0040e94b:	cmpl (%eax), $0x4550<UINT32>
0x0040e951:	jne -17
0x0040e953:	xorl %edx, %edx
0x0040e955:	movl %ecx, $0x10b<UINT32>
0x0040e95a:	cmpw 0x18(%eax), %cx
0x0040e95e:	sete %dl
0x0040e961:	movl %eax, %edx
0x0040e963:	popl %ebp
0x0040e964:	ret

0x0040ea06:	addl %esp, $0x4<UINT8>
0x0040ea09:	testl %eax, %eax
0x0040ea0b:	je 85
0x0040ea0d:	movl %eax, 0x8(%ebp)
0x0040ea10:	subl %eax, $0x400000<UINT32>
0x0040ea15:	pushl %eax
0x0040ea16:	pushl $0x400000<UINT32>
0x0040ea1b:	call 0x0040e970
0x0040e970:	movl %edi, %edi
0x0040e972:	pushl %ebp
0x0040e973:	movl %ebp, %esp
0x0040e975:	movl %eax, 0x8(%ebp)
0x0040e978:	movl %ecx, 0x3c(%eax)
0x0040e97b:	addl %ecx, %eax
0x0040e97d:	movzwl %eax, 0x14(%ecx)
0x0040e981:	pushl %ebx
0x0040e982:	pushl %esi
0x0040e983:	movzwl %esi, 0x6(%ecx)
0x0040e987:	xorl %edx, %edx
0x0040e989:	pushl %edi
0x0040e98a:	leal %eax, 0x18(%eax,%ecx)
0x0040e98e:	testl %esi, %esi
0x0040e990:	jbe 27
0x0040e992:	movl %edi, 0xc(%ebp)
0x0040e995:	movl %ecx, 0xc(%eax)
0x0040e998:	cmpl %edi, %ecx
0x0040e99a:	jb 9
0x0040e99c:	movl %ebx, 0x8(%eax)
0x0040e99f:	addl %ebx, %ecx
0x0040e9a1:	cmpl %edi, %ebx
0x0040e9a3:	jb 0x0040e9af
0x0040e9a5:	incl %edx
0x0040e9a6:	addl %eax, $0x28<UINT8>
0x0040e9a9:	cmpl %edx, %esi
0x0040e9ab:	jb 0x0040e995
0x0040e9af:	popl %edi
0x0040e9b0:	popl %esi
0x0040e9b1:	popl %ebx
0x0040e9b2:	popl %ebp
0x0040e9b3:	ret

0x0040ea20:	addl %esp, $0x8<UINT8>
0x0040ea23:	testl %eax, %eax
0x0040ea25:	je 59
0x0040ea27:	movl %eax, 0x24(%eax)
0x0040ea2a:	shrl %eax, $0x1f<UINT8>
0x0040ea2d:	notl %eax
0x0040ea2f:	andl %eax, $0x1<UINT8>
0x0040ea32:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040ea39:	movl %ecx, -16(%ebp)
0x0040ea3c:	movl %fs:0, %ecx
0x0040ea43:	popl %ecx
0x0040ea44:	popl %edi
0x0040ea45:	popl %esi
0x0040ea46:	popl %ebx
0x0040ea47:	movl %esp, %ebp
0x0040ea49:	popl %ebp
0x0040ea4a:	ret

0x0040d64c:	popl %ecx
0x0040d64d:	testl %eax, %eax
0x0040d64f:	je 10
0x0040d651:	pushl 0x8(%ebp)
0x0040d654:	call 0x00413b55
0x00413b55:	movl %edi, %edi
0x00413b57:	pushl %ebp
0x00413b58:	movl %ebp, %esp
0x00413b5a:	call 0x00413af5
0x00413af5:	movl %eax, $0x415344<UINT32>
0x00413afa:	movl 0x427c94, %eax
0x00413aff:	movl 0x427c98, $0x414a2b<UINT32>
0x00413b09:	movl 0x427c9c, $0x4149df<UINT32>
0x00413b13:	movl 0x427ca0, $0x414a18<UINT32>
0x00413b1d:	movl 0x427ca4, $0x414981<UINT32>
0x00413b27:	movl 0x427ca8, %eax
0x00413b2c:	movl 0x427cac, $0x4152bc<UINT32>
0x00413b36:	movl 0x427cb0, $0x41499d<UINT32>
0x00413b40:	movl 0x427cb4, $0x4148ff<UINT32>
0x00413b4a:	movl 0x427cb8, $0x41488c<UINT32>
0x00413b54:	ret

0x00413b5f:	call 0x004153d0
0x004153d0:	pushl $0x423efc<UINT32>
0x004153d5:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x004153db:	testl %eax, %eax
0x004153dd:	je 21
0x004153df:	pushl $0x423ee0<UINT32>
0x004153e4:	pushl %eax
0x004153e5:	call GetProcAddress@KERNEL32.DLL
0x004153eb:	testl %eax, %eax
0x004153ed:	je 5
0x004153ef:	pushl $0x0<UINT8>
0x004153f1:	call IsProcessorFeaturePresent@KERNEL32
IsProcessorFeaturePresent@KERNEL32: API Node	
0x004153f3:	ret

0x00413b64:	cmpl 0x8(%ebp), $0x0<UINT8>
0x00413b68:	movl 0x42b8c8, %eax
0x00413b6d:	je 5
0x00413b6f:	call 0x00415367
0x00415367:	movl %edi, %edi
0x00415369:	pushl %esi
0x0041536a:	pushl $0x30000<UINT32>
0x0041536f:	pushl $0x10000<UINT32>
0x00415374:	xorl %esi, %esi
0x00415376:	pushl %esi
0x00415377:	call 0x0041586f
0x0041586f:	movl %edi, %edi
0x00415871:	pushl %ebp
0x00415872:	movl %ebp, %esp
0x00415874:	movl %eax, 0x10(%ebp)
0x00415877:	movl %ecx, 0xc(%ebp)
0x0041587a:	andl %eax, $0xfff7ffff<UINT32>
0x0041587f:	andl %ecx, %eax
0x00415881:	pushl %esi
0x00415882:	testl %ecx, $0xfcf0fce0<UINT32>
0x00415888:	je 0x004158bb
0x004158bb:	movl %esi, 0x8(%ebp)
0x004158be:	pushl %eax
0x004158bf:	pushl 0xc(%ebp)
0x004158c2:	testl %esi, %esi
0x004158c4:	je 0x004158cf
0x004158cf:	call 0x004174ad
0x004174ad:	movl %edi, %edi
0x004174af:	pushl %ebp
0x004174b0:	movl %ebp, %esp
0x004174b2:	subl %esp, $0x14<UINT8>
0x004174b5:	pushl %ebx
0x004174b6:	pushl %esi
0x004174b7:	pushl %edi
0x004174b8:	fwait
0x004174b9:	fnstcw -8(%ebp)
0x004174bc:	movl %ebx, -8(%ebp)
0x004174bf:	xorl %edx, %edx
0x004174c1:	testb %bl, $0x1<UINT8>
0x004174c4:	je 0x004174c9
0x004174c9:	testb %bl, $0x4<UINT8>
0x004174cc:	je 0x004174d1
0x004174d1:	testb %bl, $0x8<UINT8>
0x004174d4:	je 0x004174d9
0x004174d9:	testb %bl, $0x10<UINT8>
0x004174dc:	je 3
0x004174de:	orl %edx, $0x2<UINT8>
0x004174e1:	testb %bl, $0x20<UINT8>
0x004174e4:	je 3
0x004174e6:	orl %edx, $0x1<UINT8>
0x004174e9:	testb %bl, $0x2<UINT8>
0x004174ec:	je 0x004174f4
0x004174f4:	movzwl %ecx, %bx
0x004174f7:	movl %eax, %ecx
0x004174f9:	movl %esi, $0xc00<UINT32>
0x004174fe:	andl %eax, %esi
0x00417500:	movl %edi, $0x300<UINT32>
0x00417505:	je 36
0x00417507:	cmpl %eax, $0x400<UINT32>
0x0041750c:	je 23
0x0041750e:	cmpl %eax, $0x800<UINT32>
0x00417513:	je 8
0x00417515:	cmpl %eax, %esi
0x00417517:	jne 18
0x00417519:	orl %edx, %edi
0x0041751b:	jmp 0x0041752b
0x0041752b:	andl %ecx, %edi
0x0041752d:	je 16
0x0041752f:	cmpl %ecx, $0x200<UINT32>
0x00417535:	jne 0x00417545
0x00417545:	testl %ebx, $0x1000<UINT32>
0x0041754b:	je 6
0x0041754d:	orl %edx, $0x40000<UINT32>
0x00417553:	movl %edi, 0xc(%ebp)
0x00417556:	movl %ecx, 0x8(%ebp)
0x00417559:	movl %eax, %edi
0x0041755b:	notl %eax
0x0041755d:	andl %eax, %edx
0x0041755f:	andl %ecx, %edi
0x00417561:	orl %eax, %ecx
0x00417563:	movl 0xc(%ebp), %eax
0x00417566:	cmpl %eax, %edx
0x00417568:	je 174
0x0041756e:	movl %ebx, %eax
0x00417570:	call 0x0041737f
0x0041737f:	xorl %eax, %eax
0x00417381:	testb %bl, $0x10<UINT8>
0x00417384:	je 0x00417387
0x00417387:	testb %bl, $0x8<UINT8>
0x0041738a:	je 0x0041738f
0x0041738f:	testb %bl, $0x4<UINT8>
0x00417392:	je 0x00417397
0x00417397:	testb %bl, $0x2<UINT8>
0x0041739a:	je 3
0x0041739c:	orl %eax, $0x10<UINT8>
0x0041739f:	testb %bl, $0x1<UINT8>
0x004173a2:	je 3
0x004173a4:	orl %eax, $0x20<UINT8>
0x004173a7:	testl %ebx, $0x80000<UINT32>
0x004173ad:	je 0x004173b2
0x004173b2:	movl %ecx, %ebx
0x004173b4:	movl %edx, $0x300<UINT32>
0x004173b9:	andl %ecx, %edx
0x004173bb:	pushl %esi
0x004173bc:	movl %esi, $0x200<UINT32>
0x004173c1:	je 35
0x004173c3:	cmpl %ecx, $0x100<UINT32>
0x004173c9:	je 22
0x004173cb:	cmpl %ecx, %esi
0x004173cd:	je 11
0x004173cf:	cmpl %ecx, %edx
0x004173d1:	jne 19
0x004173d3:	orl %eax, $0xc00<UINT32>
0x004173d8:	jmp 0x004173e6
0x004173e6:	movl %ecx, %ebx
0x004173e8:	andl %ecx, $0x30000<UINT32>
0x004173ee:	je 12
0x004173f0:	cmpl %ecx, $0x10000<UINT32>
0x004173f6:	jne 6
0x004173f8:	orl %eax, %esi
0x004173fa:	jmp 0x004173fe
0x004173fe:	popl %esi
0x004173ff:	testl %ebx, $0x40000<UINT32>
0x00417405:	je 5
0x00417407:	orl %eax, $0x1000<UINT32>
0x0041740c:	ret

0x00417575:	movzwl %eax, %ax
0x00417578:	movl -4(%ebp), %eax
0x0041757b:	fldcw -4(%ebp)
0x0041757e:	fwait
0x0041757f:	fnstcw -4(%ebp)
0x00417582:	movl %ebx, -4(%ebp)
0x00417585:	xorl %edx, %edx
0x00417587:	testb %bl, $0x1<UINT8>
0x0041758a:	je 0x0041758f
0x0041758f:	testb %bl, $0x4<UINT8>
0x00417592:	je 0x00417597
0x00417597:	testb %bl, $0x8<UINT8>
0x0041759a:	je 0x0041759f
0x0041759f:	testb %bl, $0x10<UINT8>
0x004175a2:	je 3
0x004175a4:	orl %edx, $0x2<UINT8>
0x004175a7:	testb %bl, $0x20<UINT8>
0x004175aa:	je 3
0x004175ac:	orl %edx, $0x1<UINT8>
0x004175af:	testb %bl, $0x2<UINT8>
0x004175b2:	je 0x004175ba
0x004175ba:	movzwl %ecx, %bx
0x004175bd:	movl %eax, %ecx
0x004175bf:	andl %eax, %esi
0x004175c1:	je 40
0x004175c3:	cmpl %eax, $0x400<UINT32>
0x004175c8:	je 27
0x004175ca:	cmpl %eax, $0x800<UINT32>
0x004175cf:	je 12
0x004175d1:	cmpl %eax, %esi
0x004175d3:	jne 22
0x004175d5:	orl %edx, $0x300<UINT32>
0x004175db:	jmp 0x004175eb
0x004175eb:	andl %ecx, $0x300<UINT32>
0x004175f1:	je 16
0x004175f3:	cmpl %ecx, $0x200<UINT32>
0x004175f9:	jne 14
0x004175fb:	orl %edx, $0x10000<UINT32>
0x00417601:	jmp 0x00417609
0x00417609:	testl %ebx, $0x1000<UINT32>
0x0041760f:	je 6
0x00417611:	orl %edx, $0x40000<UINT32>
0x00417617:	movl 0xc(%ebp), %edx
0x0041761a:	movl %eax, %edx
0x0041761c:	xorl %esi, %esi
0x0041761e:	cmpl 0x42c910, %esi
0x00417624:	je 0x004177b7
0x004177b7:	popl %edi
0x004177b8:	popl %esi
0x004177b9:	popl %ebx
0x004177ba:	leave
0x004177bb:	ret

0x004158d4:	popl %ecx
0x004158d5:	popl %ecx
0x004158d6:	xorl %eax, %eax
0x004158d8:	popl %esi
0x004158d9:	popl %ebp
0x004158da:	ret

0x0041537c:	addl %esp, $0xc<UINT8>
0x0041537f:	testl %eax, %eax
0x00415381:	je 0x00415390
0x00415390:	popl %esi
0x00415391:	ret

0x00413b74:	fnclex
0x00413b76:	popl %ebp
0x00413b77:	ret

0x0040d65a:	popl %ecx
0x0040d65b:	call 0x0040f62f
0x0040f62f:	movl %edi, %edi
0x0040f631:	pushl %esi
0x0040f632:	pushl %edi
0x0040f633:	xorl %edi, %edi
0x0040f635:	leal %esi, 0x427c94(%edi)
0x0040f63b:	pushl (%esi)
0x0040f63d:	call 0x0040bdbb
0x0040bddd:	pushl %eax
0x0040bdde:	pushl 0x427a54
0x0040bde4:	call TlsGetValue@KERNEL32.DLL
0x0040bde6:	call FlsGetValue@KERNEL32.DLL
0x0040bde8:	testl %eax, %eax
0x0040bdea:	je 8
0x0040bdec:	movl %eax, 0x1f8(%eax)
0x0040bdf2:	jmp 0x0040be1b
0x0040f642:	addl %edi, $0x4<UINT8>
0x0040f645:	popl %ecx
0x0040f646:	movl (%esi), %eax
0x0040f648:	cmpl %edi, $0x28<UINT8>
0x0040f64b:	jb 0x0040f635
0x0040f64d:	popl %edi
0x0040f64e:	popl %esi
0x0040f64f:	ret

0x0040d660:	pushl $0x422404<UINT32>
0x0040d665:	pushl $0x4223ec<UINT32>
0x0040d66a:	call 0x0040d610
0x0040d610:	movl %edi, %edi
0x0040d612:	pushl %ebp
0x0040d613:	movl %ebp, %esp
0x0040d615:	pushl %esi
0x0040d616:	movl %esi, 0x8(%ebp)
0x0040d619:	xorl %eax, %eax
0x0040d61b:	jmp 0x0040d62c
0x0040d62c:	cmpl %esi, 0xc(%ebp)
0x0040d62f:	jb 0x0040d61d
0x0040d61d:	testl %eax, %eax
0x0040d61f:	jne 16
0x0040d621:	movl %ecx, (%esi)
0x0040d623:	testl %ecx, %ecx
0x0040d625:	je 0x0040d629
0x0040d629:	addl %esi, $0x4<UINT8>
0x0040d627:	call 0x0040ee8a
0x0040792a:	movl %eax, 0x42d920
0x0040792f:	pushl %esi
0x00407930:	pushl $0x14<UINT8>
0x00407932:	popl %esi
0x00407933:	testl %eax, %eax
0x00407935:	jne 7
0x00407937:	movl %eax, $0x200<UINT32>
0x0040793c:	jmp 0x00407944
0x00407944:	movl 0x42d920, %eax
0x00407949:	pushl $0x4<UINT8>
0x0040794b:	pushl %eax
0x0040794c:	call 0x0040e4b5
0x00407951:	popl %ecx
0x00407952:	popl %ecx
0x00407953:	movl 0x42c918, %eax
0x00407958:	testl %eax, %eax
0x0040795a:	jne 0x0040797a
0x0040797a:	xorl %edx, %edx
0x0040797c:	movl %ecx, $0x427008<UINT32>
0x00407981:	jmp 0x00407988
0x00407988:	movl (%edx,%eax), %ecx
0x0040798b:	addl %ecx, $0x20<UINT8>
0x0040798e:	addl %edx, $0x4<UINT8>
0x00407991:	cmpl %ecx, $0x427288<UINT32>
0x00407997:	jl 0x00407983
0x00407983:	movl %eax, 0x42c918
0x00407999:	pushl $0xfffffffe<UINT8>
0x0040799b:	popl %esi
0x0040799c:	xorl %edx, %edx
0x0040799e:	movl %ecx, $0x427018<UINT32>
0x004079a3:	pushl %edi
0x004079a4:	movl %eax, %edx
0x004079a6:	sarl %eax, $0x5<UINT8>
0x004079a9:	movl %eax, 0x42c7e0(,%eax,4)
0x004079b0:	movl %edi, %edx
0x004079b2:	andl %edi, $0x1f<UINT8>
0x004079b5:	shll %edi, $0x6<UINT8>
0x004079b8:	movl %eax, (%edi,%eax)
0x004079bb:	cmpl %eax, $0xffffffff<UINT8>
0x004079be:	je 8
0x004079c0:	cmpl %eax, %esi
0x004079c2:	je 4
0x004079c4:	testl %eax, %eax
0x004079c6:	jne 0x004079ca
0x004079ca:	addl %ecx, $0x20<UINT8>
0x004079cd:	incl %edx
0x004079ce:	cmpl %ecx, $0x427078<UINT32>
0x004079d4:	jl 0x004079a4
0x004079d6:	popl %edi
0x004079d7:	xorl %eax, %eax
0x004079d9:	popl %esi
0x004079da:	ret

0x00408189:	movl %edi, %edi
0x0040818b:	pushl %esi
0x0040818c:	pushl $0x4<UINT8>
0x0040818e:	pushl $0x20<UINT8>
0x00408190:	call 0x0040e4b5
0x00408195:	movl %esi, %eax
0x00408197:	pushl %esi
0x00408198:	call 0x0040bdbb
0x0040819d:	addl %esp, $0xc<UINT8>
0x004081a0:	movl 0x42c8e8, %eax
0x004081a5:	movl 0x42c8e4, %eax
0x004081aa:	testl %esi, %esi
0x004081ac:	jne 0x004081b3
0x004081b3:	andl (%esi), $0x0<UINT8>
0x004081b6:	xorl %eax, %eax
0x004081b8:	popl %esi
0x004081b9:	ret

0x0040b3a6:	call 0x0040b344
0x0040b344:	movl %edi, %edi
0x0040b346:	pushl %ebp
0x0040b347:	movl %ebp, %esp
0x0040b349:	subl %esp, $0x18<UINT8>
0x0040b34c:	xorl %eax, %eax
0x0040b34e:	pushl %ebx
0x0040b34f:	movl -4(%ebp), %eax
0x0040b352:	movl -12(%ebp), %eax
0x0040b355:	movl -8(%ebp), %eax
0x0040b358:	pushl %ebx
0x0040b359:	pushfl
0x0040b35a:	popl %eax
0x0040b35b:	movl %ecx, %eax
0x0040b35d:	xorl %eax, $0x200000<UINT32>
0x0040b362:	pushl %eax
0x0040b363:	popfl
0x0040b364:	pushfl
0x0040b365:	popl %edx
0x0040b366:	subl %edx, %ecx
0x0040b368:	je 0x0040b389
0x0040b389:	popl %ebx
0x0040b38a:	testl -4(%ebp), $0x4000000<UINT32>
0x0040b391:	je 0x0040b3a1
0x0040b3a1:	xorl %eax, %eax
0x0040b3a3:	popl %ebx
0x0040b3a4:	leave
0x0040b3a5:	ret

0x0040b3ab:	movl 0x42c910, %eax
0x0040b3b0:	xorl %eax, %eax
0x0040b3b2:	ret

0x0040ee8a:	pushl $0x40ee48<UINT32>
0x0040ee8f:	call SetUnhandledExceptionFilter@KERNEL32.DLL
SetUnhandledExceptionFilter@KERNEL32.DLL: API Node	
0x0040ee95:	xorl %eax, %eax
0x0040ee97:	ret

0x0040d631:	popl %esi
0x0040d632:	popl %ebp
0x0040d633:	ret

0x0040d66f:	popl %ecx
0x0040d670:	popl %ecx
0x0040d671:	testl %eax, %eax
0x0040d673:	jne 66
0x0040d675:	pushl $0x40f328<UINT32>
0x0040d67a:	call 0x004081f6
0x004081f6:	movl %edi, %edi
0x004081f8:	pushl %ebp
0x004081f9:	movl %ebp, %esp
0x004081fb:	pushl 0x8(%ebp)
0x004081fe:	call 0x004081ba
0x004081ba:	pushl $0xc<UINT8>
0x004081bc:	pushl $0x425228<UINT32>
0x004081c1:	call 0x0040a468
0x004081c6:	call 0x0040d5e1
0x0040d5e1:	pushl $0x8<UINT8>
0x0040d5e3:	call 0x0040ca4e
0x0040d5e8:	popl %ecx
0x0040d5e9:	ret

0x004081cb:	andl -4(%ebp), $0x0<UINT8>
0x004081cf:	pushl 0x8(%ebp)
0x004081d2:	call 0x004080cf
0x004080cf:	movl %edi, %edi
0x004080d1:	pushl %ebp
0x004080d2:	movl %ebp, %esp
0x004080d4:	pushl %ecx
0x004080d5:	pushl %ebx
0x004080d6:	pushl %esi
0x004080d7:	pushl %edi
0x004080d8:	pushl 0x42c8e8
0x004080de:	call 0x0040be36
0x0040be67:	movl %eax, 0x1fc(%eax)
0x0040be6d:	jmp 0x0040be96
0x004080e3:	pushl 0x42c8e4
0x004080e9:	movl %edi, %eax
0x004080eb:	movl -4(%ebp), %edi
0x004080ee:	call 0x0040be36
0x004080f3:	movl %esi, %eax
0x004080f5:	popl %ecx
0x004080f6:	popl %ecx
0x004080f7:	cmpl %esi, %edi
0x004080f9:	jb 131
0x004080ff:	movl %ebx, %esi
0x00408101:	subl %ebx, %edi
0x00408103:	leal %eax, 0x4(%ebx)
0x00408106:	cmpl %eax, $0x4<UINT8>
0x00408109:	jb 119
0x0040810b:	pushl %edi
0x0040810c:	call 0x0040ebde
0x0040ebde:	pushl $0x10<UINT8>
0x0040ebe0:	pushl $0x4254b8<UINT32>
0x0040ebe5:	call 0x0040a468
0x0040ebea:	xorl %eax, %eax
0x0040ebec:	movl %ebx, 0x8(%ebp)
0x0040ebef:	xorl %edi, %edi
0x0040ebf1:	cmpl %ebx, %edi
0x0040ebf3:	setne %al
0x0040ebf6:	cmpl %eax, %edi
0x0040ebf8:	jne 0x0040ec17
0x0040ec17:	cmpl 0x42c90c, $0x3<UINT8>
0x0040ec1e:	jne 0x0040ec58
0x0040ec58:	pushl %ebx
0x0040ec59:	pushl %edi
0x0040ec5a:	pushl 0x42b1b0
0x0040ec60:	call HeapSize@KERNEL32.DLL
HeapSize@KERNEL32.DLL: API Node	
0x0040ec66:	movl %esi, %eax
0x0040ec68:	movl %eax, %esi
0x0040ec6a:	call 0x0040a4ad
0x0040ec6f:	ret

0x00408111:	movl %edi, %eax
0x00408113:	leal %eax, 0x4(%ebx)
0x00408116:	popl %ecx
0x00408117:	cmpl %edi, %eax
0x00408119:	jae 0x00408163
0x00408163:	pushl 0x8(%ebp)
0x00408166:	call 0x0040bdbb
0x0040816b:	movl (%esi), %eax
0x0040816d:	addl %esi, $0x4<UINT8>
0x00408170:	pushl %esi
0x00408171:	call 0x0040bdbb
0x00408176:	popl %ecx
0x00408177:	movl 0x42c8e4, %eax
0x0040817c:	movl %eax, 0x8(%ebp)
0x0040817f:	popl %ecx
0x00408180:	jmp 0x00408184
0x00408184:	popl %edi
0x00408185:	popl %esi
0x00408186:	popl %ebx
0x00408187:	leave
0x00408188:	ret

0x004081d7:	popl %ecx
0x004081d8:	movl -28(%ebp), %eax
0x004081db:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004081e2:	call 0x004081f0
0x004081f0:	call 0x0040d5ea
0x0040d5ea:	pushl $0x8<UINT8>
0x0040d5ec:	call 0x0040c974
0x0040d5f1:	popl %ecx
0x0040d5f2:	ret

0x004081f5:	ret

0x004081e7:	movl %eax, -28(%ebp)
0x004081ea:	call 0x0040a4ad
0x004081ef:	ret

0x00408203:	negl %eax
0x00408205:	sbbl %eax, %eax
0x00408207:	negl %eax
0x00408209:	popl %ecx
0x0040820a:	decl %eax
0x0040820b:	popl %ebp
0x0040820c:	ret

0x0040d67f:	movl %eax, $0x4223d8<UINT32>
0x0040d684:	movl (%esp), $0x4223e8<UINT32>
0x0040d68b:	call 0x0040d5f3
0x0040d5f3:	movl %edi, %edi
0x0040d5f5:	pushl %ebp
0x0040d5f6:	movl %ebp, %esp
0x0040d5f8:	pushl %esi
0x0040d5f9:	movl %esi, %eax
0x0040d5fb:	jmp 0x0040d608
0x0040d608:	cmpl %esi, 0x8(%ebp)
0x0040d60b:	jb 0x0040d5fd
0x0040d5fd:	movl %eax, (%esi)
0x0040d5ff:	testl %eax, %eax
0x0040d601:	je 0x0040d605
0x0040d605:	addl %esi, $0x4<UINT8>
0x0040d603:	call 0x004215b0
0x004215f0:	pushl $0x421640<UINT32>
0x004215f5:	call 0x004081f6
0x004215fa:	popl %ecx
0x004215fb:	ret

0x004215b0:	pushl %ebp
0x004215b1:	movl %ebp, %esp
0x004215b3:	movl %ecx, $0x42bd30<UINT32>
0x004215b8:	call 0x00401910
0x00401910:	pushl %ebp
0x00401911:	movl %ebp, %esp
0x00401913:	pushl %ecx
0x00401914:	movl -4(%ebp), %ecx
0x00401917:	movl %eax, -4(%ebp)
0x0040191a:	movl 0x4b0(%eax), $0x0<UINT32>
0x00401924:	movl 0x4b4(%eax), $0x0<UINT32>
0x0040192e:	movl %ecx, -4(%ebp)
0x00401931:	movb 0x4b8(%ecx), $0x0<UINT8>
0x00401938:	pushl $0x4b0<UINT32>
0x0040193d:	pushl $0x0<UINT8>
0x0040193f:	movl %edx, -4(%ebp)
0x00401942:	pushl %edx
0x00401943:	call 0x00405c10
