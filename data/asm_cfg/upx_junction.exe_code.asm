0x004377f0:	pusha
0x004377f1:	movl %esi, $0x424000<UINT32>
0x004377f6:	leal %edi, -143360(%esi)
0x004377fc:	pushl %edi
0x004377fd:	jmp 0x0043780a
0x0043780a:	movl %ebx, (%esi)
0x0043780c:	subl %esi, $0xfffffffc<UINT8>
0x0043780f:	adcl %ebx, %ebx
0x00437811:	jb 0x00437800
0x00437800:	movb %al, (%esi)
0x00437802:	incl %esi
0x00437803:	movb (%edi), %al
0x00437805:	incl %edi
0x00437806:	addl %ebx, %ebx
0x00437808:	jne 0x00437811
0x00437813:	movl %eax, $0x1<UINT32>
0x00437818:	addl %ebx, %ebx
0x0043781a:	jne 0x00437823
0x00437823:	adcl %eax, %eax
0x00437825:	addl %ebx, %ebx
0x00437827:	jae 0x00437818
0x00437829:	jne 0x00437834
0x00437834:	xorl %ecx, %ecx
0x00437836:	subl %eax, $0x3<UINT8>
0x00437839:	jb 0x00437848
0x0043783b:	shll %eax, $0x8<UINT8>
0x0043783e:	movb %al, (%esi)
0x00437840:	incl %esi
0x00437841:	xorl %eax, $0xffffffff<UINT8>
0x00437844:	je 0x004378ba
0x00437846:	movl %ebp, %eax
0x00437848:	addl %ebx, %ebx
0x0043784a:	jne 0x00437853
0x00437853:	adcl %ecx, %ecx
0x00437855:	addl %ebx, %ebx
0x00437857:	jne 0x00437860
0x00437859:	movl %ebx, (%esi)
0x0043785b:	subl %esi, $0xfffffffc<UINT8>
0x0043785e:	adcl %ebx, %ebx
0x00437860:	adcl %ecx, %ecx
0x00437862:	jne 0x00437884
0x00437884:	cmpl %ebp, $0xfffff300<UINT32>
0x0043788a:	adcl %ecx, $0x1<UINT8>
0x0043788d:	leal %edx, (%edi,%ebp)
0x00437890:	cmpl %ebp, $0xfffffffc<UINT8>
0x00437893:	jbe 0x004378a4
0x004378a4:	movl %eax, (%edx)
0x004378a6:	addl %edx, $0x4<UINT8>
0x004378a9:	movl (%edi), %eax
0x004378ab:	addl %edi, $0x4<UINT8>
0x004378ae:	subl %ecx, $0x4<UINT8>
0x004378b1:	ja 0x004378a4
0x004378b3:	addl %edi, %ecx
0x004378b5:	jmp 0x00437806
0x00437864:	incl %ecx
0x00437865:	addl %ebx, %ebx
0x00437867:	jne 0x00437870
0x00437870:	adcl %ecx, %ecx
0x00437872:	addl %ebx, %ebx
0x00437874:	jae 0x00437865
0x00437876:	jne 0x00437881
0x00437881:	addl %ecx, $0x2<UINT8>
0x00437895:	movb %al, (%edx)
0x00437897:	incl %edx
0x00437898:	movb (%edi), %al
0x0043789a:	incl %edi
0x0043789b:	decl %ecx
0x0043789c:	jne 0x00437895
0x0043789e:	jmp 0x00437806
0x0043781c:	movl %ebx, (%esi)
0x0043781e:	subl %esi, $0xfffffffc<UINT8>
0x00437821:	adcl %ebx, %ebx
0x0043784c:	movl %ebx, (%esi)
0x0043784e:	subl %esi, $0xfffffffc<UINT8>
0x00437851:	adcl %ebx, %ebx
0x0043782b:	movl %ebx, (%esi)
0x0043782d:	subl %esi, $0xfffffffc<UINT8>
0x00437830:	adcl %ebx, %ebx
0x00437832:	jae 0x00437818
0x00437878:	movl %ebx, (%esi)
0x0043787a:	subl %esi, $0xfffffffc<UINT8>
0x0043787d:	adcl %ebx, %ebx
0x0043787f:	jae 0x00437865
0x00437869:	movl %ebx, (%esi)
0x0043786b:	subl %esi, $0xfffffffc<UINT8>
0x0043786e:	adcl %ebx, %ebx
0x004378ba:	popl %esi
0x004378bb:	movl %edi, %esi
0x004378bd:	movl %ecx, $0xb40<UINT32>
0x004378c2:	movb %al, (%edi)
0x004378c4:	incl %edi
0x004378c5:	subb %al, $0xffffffe8<UINT8>
0x004378c7:	cmpb %al, $0x1<UINT8>
0x004378c9:	ja 0x004378c2
0x004378cb:	cmpb (%edi), $0xa<UINT8>
0x004378ce:	jne 0x004378c2
0x004378d0:	movl %eax, (%edi)
0x004378d2:	movb %bl, 0x4(%edi)
0x004378d5:	shrw %ax, $0x8<UINT8>
0x004378d9:	roll %eax, $0x10<UINT8>
0x004378dc:	xchgb %ah, %al
0x004378de:	subl %eax, %edi
0x004378e0:	subb %bl, $0xffffffe8<UINT8>
0x004378e3:	addl %eax, %esi
0x004378e5:	movl (%edi), %eax
0x004378e7:	addl %edi, $0x5<UINT8>
0x004378ea:	movb %al, %bl
0x004378ec:	loop 0x004378c7
0x004378ee:	leal %edi, 0x35000(%esi)
0x004378f4:	movl %eax, (%edi)
0x004378f6:	orl %eax, %eax
0x004378f8:	je 0x00437936
0x004378fa:	movl %ebx, 0x4(%edi)
0x004378fd:	leal %eax, 0x37570(%eax,%esi)
0x00437904:	addl %ebx, %esi
0x00437906:	pushl %eax
0x00437907:	addl %edi, $0x8<UINT8>
0x0043790a:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x00437910:	xchgl %ebp, %eax
0x00437911:	movb %al, (%edi)
0x00437913:	incl %edi
0x00437914:	orb %al, %al
0x00437916:	je 0x004378f4
0x00437918:	movl %ecx, %edi
0x0043791a:	pushl %edi
0x0043791b:	decl %eax
0x0043791c:	repn scasb %al, %es:(%edi)
0x0043791e:	pushl %ebp
0x0043791f:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00437925:	orl %eax, %eax
0x00437927:	je 7
0x00437929:	movl (%ebx), %eax
0x0043792b:	addl %ebx, $0x4<UINT8>
0x0043792e:	jmp 0x00437911
GetProcAddress@KERNEL32.DLL: API Node	
0x00437936:	movl %ebp, 0x37620(%esi)
0x0043793c:	leal %edi, -4096(%esi)
0x00437942:	movl %ebx, $0x1000<UINT32>
0x00437947:	pushl %eax
0x00437948:	pushl %esp
0x00437949:	pushl $0x4<UINT8>
0x0043794b:	pushl %ebx
0x0043794c:	pushl %edi
0x0043794d:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0043794f:	leal %eax, 0x217(%edi)
0x00437955:	andb (%eax), $0x7f<UINT8>
0x00437958:	andb 0x28(%eax), $0x7f<UINT8>
0x0043795c:	popl %eax
0x0043795d:	pushl %eax
0x0043795e:	pushl %esp
0x0043795f:	pushl %eax
0x00437960:	pushl %ebx
0x00437961:	pushl %edi
0x00437962:	call VirtualProtect@kernel32.dll
0x00437964:	popl %eax
0x00437965:	popa
0x00437966:	leal %eax, -128(%esp)
0x0043796a:	pushl $0x0<UINT8>
0x0043796c:	cmpl %esp, %eax
0x0043796e:	jne 0x0043796a
0x00437970:	subl %esp, $0xffffff80<UINT8>
0x00437973:	jmp 0x004064ac
0x004064ac:	call 0x0040e19a
0x0040e19a:	pushl %ebp
0x0040e19b:	movl %ebp, %esp
0x0040e19d:	subl %esp, $0x14<UINT8>
0x0040e1a0:	andl -12(%ebp), $0x0<UINT8>
0x0040e1a4:	andl -8(%ebp), $0x0<UINT8>
0x0040e1a8:	movl %eax, 0x431350
0x0040e1ad:	pushl %esi
0x0040e1ae:	pushl %edi
0x0040e1af:	movl %edi, $0xbb40e64e<UINT32>
0x0040e1b4:	movl %esi, $0xffff0000<UINT32>
0x0040e1b9:	cmpl %eax, %edi
0x0040e1bb:	je 0x0040e1ca
0x0040e1ca:	leal %eax, -12(%ebp)
0x0040e1cd:	pushl %eax
0x0040e1ce:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040e1d4:	movl %eax, -8(%ebp)
0x0040e1d7:	xorl %eax, -12(%ebp)
0x0040e1da:	movl -4(%ebp), %eax
0x0040e1dd:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040e1e3:	xorl -4(%ebp), %eax
0x0040e1e6:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040e1ec:	xorl -4(%ebp), %eax
0x0040e1ef:	leal %eax, -20(%ebp)
0x0040e1f2:	pushl %eax
0x0040e1f3:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040e1f9:	movl %ecx, -16(%ebp)
0x0040e1fc:	leal %eax, -4(%ebp)
0x0040e1ff:	xorl %ecx, -20(%ebp)
0x0040e202:	xorl %ecx, -4(%ebp)
0x0040e205:	xorl %ecx, %eax
0x0040e207:	cmpl %ecx, %edi
0x0040e209:	jne 0x0040e212
0x0040e212:	testl %esi, %ecx
0x0040e214:	jne 0x0040e222
0x0040e222:	movl 0x431350, %ecx
0x0040e228:	notl %ecx
0x0040e22a:	movl 0x431354, %ecx
0x0040e230:	popl %edi
0x0040e231:	popl %esi
0x0040e232:	movl %esp, %ebp
0x0040e234:	popl %ebp
0x0040e235:	ret

0x004064b1:	jmp 0x004062eb
0x004062eb:	pushl $0x14<UINT8>
0x004062ed:	pushl $0x42f540<UINT32>
0x004062f2:	call 0x00407290
0x00407290:	pushl $0x407330<UINT32>
0x00407295:	pushl %fs:0
0x0040729c:	movl %eax, 0x10(%esp)
0x004072a0:	movl 0x10(%esp), %ebp
0x004072a4:	leal %ebp, 0x10(%esp)
0x004072a8:	subl %esp, %eax
0x004072aa:	pushl %ebx
0x004072ab:	pushl %esi
0x004072ac:	pushl %edi
0x004072ad:	movl %eax, 0x431350
0x004072b2:	xorl -4(%ebp), %eax
0x004072b5:	xorl %eax, %ebp
0x004072b7:	pushl %eax
0x004072b8:	movl -24(%ebp), %esp
0x004072bb:	pushl -8(%ebp)
0x004072be:	movl %eax, -4(%ebp)
0x004072c1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004072c8:	movl -8(%ebp), %eax
0x004072cb:	leal %eax, -16(%ebp)
0x004072ce:	movl %fs:0, %eax
0x004072d4:	ret

0x004062f7:	pushl $0x1<UINT8>
0x004062f9:	call 0x0040e14d
0x0040e14d:	pushl %ebp
0x0040e14e:	movl %ebp, %esp
0x0040e150:	movl %eax, 0x8(%ebp)
0x0040e153:	movl 0x432880, %eax
0x0040e158:	popl %ebp
0x0040e159:	ret

0x004062fe:	popl %ecx
0x004062ff:	movl %eax, $0x5a4d<UINT32>
0x00406304:	cmpw 0x400000, %ax
0x0040630b:	je 0x00406311
0x00406311:	movl %eax, 0x40003c
0x00406316:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00406320:	jne -21
0x00406322:	movl %ecx, $0x10b<UINT32>
0x00406327:	cmpw 0x400018(%eax), %cx
0x0040632e:	jne -35
0x00406330:	xorl %ebx, %ebx
0x00406332:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00406339:	jbe 9
0x0040633b:	cmpl 0x4000e8(%eax), %ebx
0x00406341:	setne %bl
0x00406344:	movl -28(%ebp), %ebx
0x00406347:	call 0x0040b7f9
0x0040b7f9:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x0040b7ff:	xorl %ecx, %ecx
0x0040b801:	movl 0x432ed8, %eax
0x0040b806:	testl %eax, %eax
0x0040b808:	setne %cl
0x0040b80b:	movl %eax, %ecx
0x0040b80d:	ret

0x0040634c:	testl %eax, %eax
0x0040634e:	jne 0x00406358
0x00406358:	call 0x0040a4d3
0x0040a4d3:	call 0x00404b23
0x00404b23:	pushl %esi
0x00404b24:	pushl $0x0<UINT8>
0x00404b26:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00404b2c:	movl %esi, %eax
0x00404b2e:	pushl %esi
0x00404b2f:	call 0x0040b7e6
0x0040b7e6:	pushl %ebp
0x0040b7e7:	movl %ebp, %esp
0x0040b7e9:	movl %eax, 0x8(%ebp)
0x0040b7ec:	movl 0x432ed0, %eax
0x0040b7f1:	popl %ebp
0x0040b7f2:	ret

0x00404b34:	pushl %esi
0x00404b35:	call 0x00407613
0x00407613:	pushl %ebp
0x00407614:	movl %ebp, %esp
0x00407616:	movl %eax, 0x8(%ebp)
0x00407619:	movl 0x43276c, %eax
0x0040761e:	popl %ebp
0x0040761f:	ret

0x00404b3a:	pushl %esi
0x00404b3b:	call 0x0040c389
0x0040c389:	pushl %ebp
0x0040c38a:	movl %ebp, %esp
0x0040c38c:	movl %eax, 0x8(%ebp)
0x0040c38f:	movl 0x432ee0, %eax
0x0040c394:	popl %ebp
0x0040c395:	ret

0x00404b40:	pushl %esi
0x00404b41:	call 0x0040c3b5
0x0040c3b5:	pushl %ebp
0x0040c3b6:	movl %ebp, %esp
0x0040c3b8:	movl %eax, 0x8(%ebp)
0x0040c3bb:	movl 0x432ee4, %eax
0x0040c3c0:	movl 0x432ee8, %eax
0x0040c3c5:	movl 0x432eec, %eax
0x0040c3ca:	movl 0x432ef0, %eax
0x0040c3cf:	popl %ebp
0x0040c3d0:	ret

0x00404b46:	pushl %esi
0x00404b47:	call 0x0040c19f
0x0040c19f:	pushl $0x40c158<UINT32>
0x0040c1a4:	call EncodePointer@KERNEL32.DLL
0x0040c1aa:	movl 0x432edc, %eax
0x0040c1af:	ret

0x00404b4c:	pushl %esi
0x00404b4d:	call 0x0040c8c2
0x0040c8c2:	pushl %ebp
0x0040c8c3:	movl %ebp, %esp
0x0040c8c5:	movl %eax, 0x8(%ebp)
0x0040c8c8:	movl 0x432ef8, %eax
0x0040c8cd:	popl %ebp
0x0040c8ce:	ret

0x00404b52:	addl %esp, $0x18<UINT8>
0x00404b55:	popl %esi
0x00404b56:	jmp 0x00409135
0x00409135:	pushl %esi
0x00409136:	pushl %edi
0x00409137:	pushl $0x42a798<UINT32>
0x0040913c:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00409142:	movl %esi, 0x4230b4
0x00409148:	movl %edi, %eax
0x0040914a:	pushl $0x42a7b4<UINT32>
0x0040914f:	pushl %edi
0x00409150:	call GetProcAddress@KERNEL32.DLL
0x00409152:	xorl %eax, 0x431350
0x00409158:	pushl $0x42a7c0<UINT32>
0x0040915d:	pushl %edi
0x0040915e:	movl 0x433160, %eax
0x00409163:	call GetProcAddress@KERNEL32.DLL
0x00409165:	xorl %eax, 0x431350
0x0040916b:	pushl $0x42a7c8<UINT32>
0x00409170:	pushl %edi
0x00409171:	movl 0x433164, %eax
0x00409176:	call GetProcAddress@KERNEL32.DLL
0x00409178:	xorl %eax, 0x431350
0x0040917e:	pushl $0x42a7d4<UINT32>
0x00409183:	pushl %edi
0x00409184:	movl 0x433168, %eax
0x00409189:	call GetProcAddress@KERNEL32.DLL
0x0040918b:	xorl %eax, 0x431350
0x00409191:	pushl $0x42a7e0<UINT32>
0x00409196:	pushl %edi
0x00409197:	movl 0x43316c, %eax
0x0040919c:	call GetProcAddress@KERNEL32.DLL
0x0040919e:	xorl %eax, 0x431350
0x004091a4:	pushl $0x42a7fc<UINT32>
0x004091a9:	pushl %edi
0x004091aa:	movl 0x433170, %eax
0x004091af:	call GetProcAddress@KERNEL32.DLL
0x004091b1:	xorl %eax, 0x431350
0x004091b7:	pushl $0x42a80c<UINT32>
0x004091bc:	pushl %edi
0x004091bd:	movl 0x433174, %eax
0x004091c2:	call GetProcAddress@KERNEL32.DLL
0x004091c4:	xorl %eax, 0x431350
0x004091ca:	pushl $0x42a820<UINT32>
0x004091cf:	pushl %edi
0x004091d0:	movl 0x433178, %eax
0x004091d5:	call GetProcAddress@KERNEL32.DLL
0x004091d7:	xorl %eax, 0x431350
0x004091dd:	pushl $0x42a838<UINT32>
0x004091e2:	pushl %edi
0x004091e3:	movl 0x43317c, %eax
0x004091e8:	call GetProcAddress@KERNEL32.DLL
0x004091ea:	xorl %eax, 0x431350
0x004091f0:	pushl $0x42a850<UINT32>
0x004091f5:	pushl %edi
0x004091f6:	movl 0x433180, %eax
0x004091fb:	call GetProcAddress@KERNEL32.DLL
0x004091fd:	xorl %eax, 0x431350
0x00409203:	pushl $0x42a864<UINT32>
0x00409208:	pushl %edi
0x00409209:	movl 0x433184, %eax
0x0040920e:	call GetProcAddress@KERNEL32.DLL
0x00409210:	xorl %eax, 0x431350
0x00409216:	pushl $0x42a884<UINT32>
0x0040921b:	pushl %edi
0x0040921c:	movl 0x433188, %eax
0x00409221:	call GetProcAddress@KERNEL32.DLL
0x00409223:	xorl %eax, 0x431350
0x00409229:	pushl $0x42a89c<UINT32>
0x0040922e:	pushl %edi
0x0040922f:	movl 0x43318c, %eax
0x00409234:	call GetProcAddress@KERNEL32.DLL
0x00409236:	xorl %eax, 0x431350
0x0040923c:	pushl $0x42a8b4<UINT32>
0x00409241:	pushl %edi
0x00409242:	movl 0x433190, %eax
0x00409247:	call GetProcAddress@KERNEL32.DLL
0x00409249:	xorl %eax, 0x431350
0x0040924f:	pushl $0x42a8c8<UINT32>
0x00409254:	pushl %edi
0x00409255:	movl 0x433194, %eax
0x0040925a:	call GetProcAddress@KERNEL32.DLL
0x0040925c:	xorl %eax, 0x431350
0x00409262:	movl 0x433198, %eax
0x00409267:	pushl $0x42a8dc<UINT32>
0x0040926c:	pushl %edi
0x0040926d:	call GetProcAddress@KERNEL32.DLL
0x0040926f:	xorl %eax, 0x431350
0x00409275:	pushl $0x42a8f8<UINT32>
0x0040927a:	pushl %edi
0x0040927b:	movl 0x43319c, %eax
0x00409280:	call GetProcAddress@KERNEL32.DLL
0x00409282:	xorl %eax, 0x431350
0x00409288:	pushl $0x42a918<UINT32>
0x0040928d:	pushl %edi
0x0040928e:	movl 0x4331a0, %eax
0x00409293:	call GetProcAddress@KERNEL32.DLL
0x00409295:	xorl %eax, 0x431350
0x0040929b:	pushl $0x42a934<UINT32>
0x004092a0:	pushl %edi
0x004092a1:	movl 0x4331a4, %eax
0x004092a6:	call GetProcAddress@KERNEL32.DLL
0x004092a8:	xorl %eax, 0x431350
0x004092ae:	pushl $0x42a954<UINT32>
0x004092b3:	pushl %edi
0x004092b4:	movl 0x4331a8, %eax
0x004092b9:	call GetProcAddress@KERNEL32.DLL
0x004092bb:	xorl %eax, 0x431350
0x004092c1:	pushl $0x42a968<UINT32>
0x004092c6:	pushl %edi
0x004092c7:	movl 0x4331ac, %eax
0x004092cc:	call GetProcAddress@KERNEL32.DLL
0x004092ce:	xorl %eax, 0x431350
0x004092d4:	pushl $0x42a984<UINT32>
0x004092d9:	pushl %edi
0x004092da:	movl 0x4331b0, %eax
0x004092df:	call GetProcAddress@KERNEL32.DLL
0x004092e1:	xorl %eax, 0x431350
0x004092e7:	pushl $0x42a998<UINT32>
0x004092ec:	pushl %edi
0x004092ed:	movl 0x4331b8, %eax
0x004092f2:	call GetProcAddress@KERNEL32.DLL
0x004092f4:	xorl %eax, 0x431350
0x004092fa:	pushl $0x42a9a8<UINT32>
0x004092ff:	pushl %edi
0x00409300:	movl 0x4331b4, %eax
0x00409305:	call GetProcAddress@KERNEL32.DLL
0x00409307:	xorl %eax, 0x431350
0x0040930d:	pushl $0x42a9b8<UINT32>
0x00409312:	pushl %edi
0x00409313:	movl 0x4331bc, %eax
0x00409318:	call GetProcAddress@KERNEL32.DLL
0x0040931a:	xorl %eax, 0x431350
0x00409320:	pushl $0x42a9c8<UINT32>
0x00409325:	pushl %edi
0x00409326:	movl 0x4331c0, %eax
0x0040932b:	call GetProcAddress@KERNEL32.DLL
0x0040932d:	xorl %eax, 0x431350
0x00409333:	pushl $0x42a9d8<UINT32>
0x00409338:	pushl %edi
0x00409339:	movl 0x4331c4, %eax
0x0040933e:	call GetProcAddress@KERNEL32.DLL
0x00409340:	xorl %eax, 0x431350
0x00409346:	pushl $0x42a9f4<UINT32>
0x0040934b:	pushl %edi
0x0040934c:	movl 0x4331c8, %eax
0x00409351:	call GetProcAddress@KERNEL32.DLL
0x00409353:	xorl %eax, 0x431350
0x00409359:	pushl $0x42aa08<UINT32>
0x0040935e:	pushl %edi
0x0040935f:	movl 0x4331cc, %eax
0x00409364:	call GetProcAddress@KERNEL32.DLL
0x00409366:	xorl %eax, 0x431350
0x0040936c:	pushl $0x42aa18<UINT32>
0x00409371:	pushl %edi
0x00409372:	movl 0x4331d0, %eax
0x00409377:	call GetProcAddress@KERNEL32.DLL
0x00409379:	xorl %eax, 0x431350
0x0040937f:	pushl $0x42aa2c<UINT32>
0x00409384:	pushl %edi
0x00409385:	movl 0x4331d4, %eax
0x0040938a:	call GetProcAddress@KERNEL32.DLL
0x0040938c:	xorl %eax, 0x431350
0x00409392:	movl 0x4331d8, %eax
0x00409397:	pushl $0x42aa3c<UINT32>
0x0040939c:	pushl %edi
0x0040939d:	call GetProcAddress@KERNEL32.DLL
0x0040939f:	xorl %eax, 0x431350
0x004093a5:	pushl $0x42aa5c<UINT32>
0x004093aa:	pushl %edi
0x004093ab:	movl 0x4331dc, %eax
0x004093b0:	call GetProcAddress@KERNEL32.DLL
0x004093b2:	xorl %eax, 0x431350
0x004093b8:	popl %edi
0x004093b9:	movl 0x4331e0, %eax
0x004093be:	popl %esi
0x004093bf:	ret

0x0040a4d8:	call 0x004066a4
0x004066a4:	pushl %esi
0x004066a5:	pushl %edi
0x004066a6:	movl %esi, $0x431360<UINT32>
0x004066ab:	movl %edi, $0x432618<UINT32>
0x004066b0:	cmpl 0x4(%esi), $0x1<UINT8>
0x004066b4:	jne 22
0x004066b6:	pushl $0x0<UINT8>
0x004066b8:	movl (%esi), %edi
0x004066ba:	addl %edi, $0x18<UINT8>
0x004066bd:	pushl $0xfa0<UINT32>
0x004066c2:	pushl (%esi)
0x004066c4:	call 0x004090c7
0x004090c7:	pushl %ebp
0x004090c8:	movl %ebp, %esp
0x004090ca:	movl %eax, 0x433170
0x004090cf:	xorl %eax, 0x431350
0x004090d5:	je 13
0x004090d7:	pushl 0x10(%ebp)
0x004090da:	pushl 0xc(%ebp)
0x004090dd:	pushl 0x8(%ebp)
0x004090e0:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x004090e2:	popl %ebp
0x004090e3:	ret

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
