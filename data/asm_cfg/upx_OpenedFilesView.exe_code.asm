0x00420910:	pusha
0x00420911:	movl %esi, $0x414000<UINT32>
0x00420916:	leal %edi, -77824(%esi)
0x0042091c:	pushl %edi
0x0042091d:	jmp 0x0042092a
0x0042092a:	movl %ebx, (%esi)
0x0042092c:	subl %esi, $0xfffffffc<UINT8>
0x0042092f:	adcl %ebx, %ebx
0x00420931:	jb 0x00420920
0x00420920:	movb %al, (%esi)
0x00420922:	incl %esi
0x00420923:	movb (%edi), %al
0x00420925:	incl %edi
0x00420926:	addl %ebx, %ebx
0x00420928:	jne 0x00420931
0x00420933:	movl %eax, $0x1<UINT32>
0x00420938:	addl %ebx, %ebx
0x0042093a:	jne 0x00420943
0x00420943:	adcl %eax, %eax
0x00420945:	addl %ebx, %ebx
0x00420947:	jae 0x00420938
0x00420949:	jne 0x00420954
0x00420954:	xorl %ecx, %ecx
0x00420956:	subl %eax, $0x3<UINT8>
0x00420959:	jb 0x00420968
0x0042095b:	shll %eax, $0x8<UINT8>
0x0042095e:	movb %al, (%esi)
0x00420960:	incl %esi
0x00420961:	xorl %eax, $0xffffffff<UINT8>
0x00420964:	je 0x004209da
0x00420966:	movl %ebp, %eax
0x00420968:	addl %ebx, %ebx
0x0042096a:	jne 0x00420973
0x00420973:	adcl %ecx, %ecx
0x00420975:	addl %ebx, %ebx
0x00420977:	jne 0x00420980
0x00420980:	adcl %ecx, %ecx
0x00420982:	jne 0x004209a4
0x004209a4:	cmpl %ebp, $0xfffff300<UINT32>
0x004209aa:	adcl %ecx, $0x1<UINT8>
0x004209ad:	leal %edx, (%edi,%ebp)
0x004209b0:	cmpl %ebp, $0xfffffffc<UINT8>
0x004209b3:	jbe 0x004209c4
0x004209c4:	movl %eax, (%edx)
0x004209c6:	addl %edx, $0x4<UINT8>
0x004209c9:	movl (%edi), %eax
0x004209cb:	addl %edi, $0x4<UINT8>
0x004209ce:	subl %ecx, $0x4<UINT8>
0x004209d1:	ja 0x004209c4
0x004209d3:	addl %edi, %ecx
0x004209d5:	jmp 0x00420926
0x00420979:	movl %ebx, (%esi)
0x0042097b:	subl %esi, $0xfffffffc<UINT8>
0x0042097e:	adcl %ebx, %ebx
0x0042096c:	movl %ebx, (%esi)
0x0042096e:	subl %esi, $0xfffffffc<UINT8>
0x00420971:	adcl %ebx, %ebx
0x00420984:	incl %ecx
0x00420985:	addl %ebx, %ebx
0x00420987:	jne 0x00420990
0x00420990:	adcl %ecx, %ecx
0x00420992:	addl %ebx, %ebx
0x00420994:	jae 0x00420985
0x00420996:	jne 0x004209a1
0x004209a1:	addl %ecx, $0x2<UINT8>
0x0042093c:	movl %ebx, (%esi)
0x0042093e:	subl %esi, $0xfffffffc<UINT8>
0x00420941:	adcl %ebx, %ebx
0x0042094b:	movl %ebx, (%esi)
0x0042094d:	subl %esi, $0xfffffffc<UINT8>
0x00420950:	adcl %ebx, %ebx
0x00420952:	jae 0x00420938
0x00420989:	movl %ebx, (%esi)
0x0042098b:	subl %esi, $0xfffffffc<UINT8>
0x0042098e:	adcl %ebx, %ebx
0x004209b5:	movb %al, (%edx)
0x004209b7:	incl %edx
0x004209b8:	movb (%edi), %al
0x004209ba:	incl %edi
0x004209bb:	decl %ecx
0x004209bc:	jne 0x004209b5
0x004209be:	jmp 0x00420926
0x00420998:	movl %ebx, (%esi)
0x0042099a:	subl %esi, $0xfffffffc<UINT8>
0x0042099d:	adcl %ebx, %ebx
0x0042099f:	jae 0x00420985
0x004209da:	popl %esi
0x004209db:	movl %edi, %esi
0x004209dd:	movl %ecx, $0x62d<UINT32>
0x004209e2:	movb %al, (%edi)
0x004209e4:	incl %edi
0x004209e5:	subb %al, $0xffffffe8<UINT8>
0x004209e7:	cmpb %al, $0x1<UINT8>
0x004209e9:	ja 0x004209e2
0x004209eb:	cmpb (%edi), $0x5<UINT8>
0x004209ee:	jne 0x004209e2
0x004209f0:	movl %eax, (%edi)
0x004209f2:	movb %bl, 0x4(%edi)
0x004209f5:	shrw %ax, $0x8<UINT8>
0x004209f9:	roll %eax, $0x10<UINT8>
0x004209fc:	xchgb %ah, %al
0x004209fe:	subl %eax, %edi
0x00420a00:	subb %bl, $0xffffffe8<UINT8>
0x00420a03:	addl %eax, %esi
0x00420a05:	movl (%edi), %eax
0x00420a07:	addl %edi, $0x5<UINT8>
0x00420a0a:	movb %al, %bl
0x00420a0c:	loop 0x004209e7
0x00420a0e:	leal %edi, 0x1d000(%esi)
0x00420a14:	movl %eax, (%edi)
0x00420a16:	orl %eax, %eax
0x00420a18:	je 0x00420a5f
0x00420a1a:	movl %ebx, 0x4(%edi)
0x00420a1d:	leal %eax, 0x211a8(%eax,%esi)
0x00420a24:	addl %ebx, %esi
0x00420a26:	pushl %eax
0x00420a27:	addl %edi, $0x8<UINT8>
0x00420a2a:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00420a30:	xchgl %ebp, %eax
0x00420a31:	movb %al, (%edi)
0x00420a33:	incl %edi
0x00420a34:	orb %al, %al
0x00420a36:	je 0x00420a14
0x00420a38:	movl %ecx, %edi
0x00420a3a:	jns 0x00420a43
0x00420a43:	pushl %edi
0x00420a44:	decl %eax
0x00420a45:	repn scasb %al, %es:(%edi)
0x00420a47:	pushl %ebp
0x00420a48:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00420a4e:	orl %eax, %eax
0x00420a50:	je 7
0x00420a52:	movl (%ebx), %eax
0x00420a54:	addl %ebx, $0x4<UINT8>
0x00420a57:	jmp 0x00420a31
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x00420a3c:	movzwl %eax, (%edi)
0x00420a3f:	incl %edi
0x00420a40:	pushl %eax
0x00420a41:	incl %edi
0x00420a42:	movl %ecx, $0xaef24857<UINT32>
0x00420a5f:	movl %ebp, 0x2129c(%esi)
0x00420a65:	leal %edi, -4096(%esi)
0x00420a6b:	movl %ebx, $0x1000<UINT32>
0x00420a70:	pushl %eax
0x00420a71:	pushl %esp
0x00420a72:	pushl $0x4<UINT8>
0x00420a74:	pushl %ebx
0x00420a75:	pushl %edi
0x00420a76:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x00420a78:	leal %eax, 0x20f(%edi)
0x00420a7e:	andb (%eax), $0x7f<UINT8>
0x00420a81:	andb 0x28(%eax), $0x7f<UINT8>
0x00420a85:	popl %eax
0x00420a86:	pushl %eax
0x00420a87:	pushl %esp
0x00420a88:	pushl %eax
0x00420a89:	pushl %ebx
0x00420a8a:	pushl %edi
0x00420a8b:	call VirtualProtect@kernel32.dll
0x00420a8d:	popl %eax
0x00420a8e:	popa
0x00420a8f:	leal %eax, -128(%esp)
0x00420a93:	pushl $0x0<UINT8>
0x00420a95:	cmpl %esp, %eax
0x00420a97:	jne 0x00420a93
0x00420a99:	subl %esp, $0xffffff80<UINT8>
0x00420a9c:	jmp 0x0040fc10
0x0040fc10:	pushl $0x70<UINT8>
0x0040fc12:	pushl $0x410460<UINT32>
0x0040fc17:	call 0x0040fe00
0x0040fe00:	pushl $0x40fe50<UINT32>
0x0040fe05:	movl %eax, %fs:0
0x0040fe0b:	pushl %eax
0x0040fe0c:	movl %fs:0, %esp
0x0040fe13:	movl %eax, 0x10(%esp)
0x0040fe17:	movl 0x10(%esp), %ebp
0x0040fe1b:	leal %ebp, 0x10(%esp)
0x0040fe1f:	subl %esp, %eax
0x0040fe21:	pushl %ebx
0x0040fe22:	pushl %esi
0x0040fe23:	pushl %edi
0x0040fe24:	movl %eax, -8(%ebp)
0x0040fe27:	movl -24(%ebp), %esp
0x0040fe2a:	pushl %eax
0x0040fe2b:	movl %eax, -4(%ebp)
0x0040fe2e:	movl -4(%ebp), $0xffffffff<UINT32>
0x0040fe35:	movl -8(%ebp), %eax
0x0040fe38:	ret

0x0040fc1c:	xorl %ebx, %ebx
0x0040fc1e:	pushl %ebx
0x0040fc1f:	movl %edi, 0x4100e0
0x0040fc25:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x0040fc27:	cmpw (%eax), $0x5a4d<UINT16>
0x0040fc2c:	jne 31
0x0040fc2e:	movl %ecx, 0x3c(%eax)
0x0040fc31:	addl %ecx, %eax
0x0040fc33:	cmpl (%ecx), $0x4550<UINT32>
0x0040fc39:	jne 18
0x0040fc3b:	movzwl %eax, 0x18(%ecx)
0x0040fc3f:	cmpl %eax, $0x10b<UINT32>
0x0040fc44:	je 0x0040fc65
0x0040fc65:	cmpl 0x74(%ecx), $0xe<UINT8>
0x0040fc69:	jbe -30
0x0040fc6b:	xorl %eax, %eax
0x0040fc6d:	cmpl 0xe8(%ecx), %ebx
0x0040fc73:	setne %al
0x0040fc76:	movl -28(%ebp), %eax
0x0040fc79:	movl -4(%ebp), %ebx
0x0040fc7c:	pushl $0x2<UINT8>
0x0040fc7e:	call __set_app_type@msvcrt.dll
__set_app_type@msvcrt.dll: API Node	
0x0040fc84:	popl %ecx
0x0040fc85:	orl 0x41473c, $0xffffffff<UINT8>
0x0040fc8c:	orl 0x414740, $0xffffffff<UINT8>
0x0040fc93:	call __p__fmode@msvcrt.dll
__p__fmode@msvcrt.dll: API Node	
0x0040fc99:	movl %ecx, 0x41349c
0x0040fc9f:	movl (%eax), %ecx
0x0040fca1:	call __p__commode@msvcrt.dll
__p__commode@msvcrt.dll: API Node	
0x0040fca7:	movl %ecx, 0x413498
0x0040fcad:	movl (%eax), %ecx
0x0040fcaf:	movl %eax, 0x41033c
0x0040fcb4:	movl %eax, (%eax)
0x0040fcb6:	movl 0x414738, %eax
0x0040fcbb:	call 0x0040fdfa
0x0040fdfa:	xorl %eax, %eax
0x0040fdfc:	ret

0x0040fcc0:	cmpl 0x413000, %ebx
0x0040fcc6:	jne 0x0040fcd4
0x0040fcd4:	call 0x0040fde8
0x0040fde8:	pushl $0x30000<UINT32>
0x0040fded:	pushl $0x10000<UINT32>
0x0040fdf2:	call 0x0040fe4a
0x0040fe4a:	jmp _controlfp@msvcrt.dll
_controlfp@msvcrt.dll: API Node	
0x0040fdf7:	popl %ecx
0x0040fdf8:	popl %ecx
0x0040fdf9:	ret

0x0040fcd9:	pushl $0x41043c<UINT32>
0x0040fcde:	pushl $0x410438<UINT32>
0x0040fce3:	call 0x0040fde2
0x0040fde2:	jmp _initterm@msvcrt.dll
_initterm@msvcrt.dll: API Node	
0x0040fce8:	movl %eax, 0x413494
0x0040fced:	movl -32(%ebp), %eax
0x0040fcf0:	leal %eax, -32(%ebp)
0x0040fcf3:	pushl %eax
0x0040fcf4:	pushl 0x413490
0x0040fcfa:	leal %eax, -36(%ebp)
0x0040fcfd:	pushl %eax
0x0040fcfe:	leal %eax, -40(%ebp)
0x0040fd01:	pushl %eax
0x0040fd02:	leal %eax, -44(%ebp)
0x0040fd05:	pushl %eax
0x0040fd06:	call __getmainargs@msvcrt.dll
__getmainargs@msvcrt.dll: API Node	
0x0040fd0c:	movl -48(%ebp), %eax
0x0040fd0f:	pushl $0x410434<UINT32>
0x0040fd14:	pushl $0x41040c<UINT32>
0x0040fd19:	call 0x0040fde2
0x0040fd1e:	addl %esp, $0x24<UINT8>
0x0040fd21:	movl %eax, 0x41034c
0x0040fd26:	movl %esi, (%eax)
0x0040fd28:	movl -52(%ebp), %esi
0x0040fd2b:	cmpb (%esi), $0x22<UINT8>
0x0040fd2e:	jne 58
0x0040fd30:	incl %esi
0x0040fd31:	movl -52(%ebp), %esi
0x0040fd34:	movb %al, (%esi)
0x0040fd36:	cmpb %al, %bl
0x0040fd38:	je 4
0x0040fd3a:	cmpb %al, $0x22<UINT8>
0x0040fd3c:	jne 0x0040fd30
0x0040fd3e:	cmpb (%esi), $0x22<UINT8>
0x0040fd41:	jne 4
0x0040fd43:	incl %esi
0x0040fd44:	movl -52(%ebp), %esi
0x0040fd47:	movb %al, (%esi)
0x0040fd49:	cmpb %al, %bl
0x0040fd4b:	je 4
0x0040fd4d:	cmpb %al, $0x20<UINT8>
0x0040fd4f:	jbe 0x0040fd43
0x0040fd51:	movl -76(%ebp), %ebx
0x0040fd54:	leal %eax, -120(%ebp)
0x0040fd57:	pushl %eax
0x0040fd58:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x0040fd5e:	testb -76(%ebp), $0x1<UINT8>
0x0040fd62:	je 0x0040fd75
0x0040fd75:	pushl $0xa<UINT8>
0x0040fd77:	popl %eax
0x0040fd78:	pushl %eax
0x0040fd79:	pushl %esi
0x0040fd7a:	pushl %ebx
0x0040fd7b:	pushl %ebx
0x0040fd7c:	call GetModuleHandleA@KERNEL32.DLL
0x0040fd7e:	pushl %eax
0x0040fd7f:	call 0x0040d465
0x0040d465:	pushl %ebp
0x0040d466:	movl %ebp, %esp
0x0040d468:	andl %esp, $0xfffffff8<UINT8>
0x0040d46b:	movl %eax, $0x2304<UINT32>
0x0040d470:	call 0x0040fe70
0x0040fe70:	cmpl %eax, $0x1000<UINT32>
0x0040fe75:	jae 0x0040fe85
0x0040fe85:	pushl %ecx
0x0040fe86:	leal %ecx, 0x8(%esp)
0x0040fe8a:	subl %ecx, $0x1000<UINT32>
0x0040fe90:	subl %eax, $0x1000<UINT32>
0x0040fe95:	testl (%ecx), %eax
0x0040fe97:	cmpl %eax, $0x1000<UINT32>
0x0040fe9c:	jae 0x0040fe8a
0x0040fe9e:	subl %ecx, %eax
0x0040fea0:	movl %eax, %esp
0x0040fea2:	testl (%ecx), %eax
0x0040fea4:	movl %esp, %ecx
0x0040fea6:	movl %ecx, (%eax)
0x0040fea8:	movl %eax, 0x4(%eax)
0x0040feab:	pushl %eax
0x0040feac:	ret

0x0040d475:	pushl %ebx
0x0040d476:	pushl %esi
0x0040d477:	pushl %edi
0x0040d478:	call 0x00403229
0x00403229:	pushl %ebp
0x0040322a:	movl %ebp, %esp
0x0040322c:	pushl %ecx
0x0040322d:	pushl %ecx
0x0040322e:	pushl %ebx
0x0040322f:	pushl %esi
0x00403230:	pushl %edi
0x00403231:	pushl $0x41080c<UINT32>
0x00403236:	movl -8(%ebp), $0x8<UINT32>
0x0040323d:	movl -4(%ebp), $0xff<UINT32>
0x00403244:	xorl %ebx, %ebx
0x00403246:	xorl %edi, %edi
0x00403248:	call LoadLibraryA@KERNEL32.DLL
0x0040324e:	movl %esi, %eax
0x00403250:	testl %esi, %esi
0x00403252:	je 40
0x00403254:	pushl $0x41081c<UINT32>
0x00403259:	pushl %esi
0x0040325a:	call GetProcAddress@KERNEL32.DLL
0x00403260:	testl %eax, %eax
0x00403262:	je 9
0x00403264:	leal %ecx, -8(%ebp)
0x00403267:	pushl %ecx
0x00403268:	incl %edi
0x00403269:	call InitCommonControlsEx@comctl32.dll
InitCommonControlsEx@comctl32.dll: API Node	
0x0040326b:	movl %ebx, %eax
0x0040326d:	pushl %esi
0x0040326e:	call FreeLibrary@KERNEL32.DLL
FreeLibrary@KERNEL32.DLL: API Node	
0x00403274:	testl %edi, %edi
0x00403276:	je 4
0x00403278:	movl %eax, %ebx
0x0040327a:	jmp 0x00403285
0x00403285:	testl %eax, %eax
0x00403287:	popl %edi
0x00403288:	popl %esi
0x00403289:	popl %ebx
0x0040328a:	jne 0x004032a3
0x0040328c:	pushl $0x30<UINT8>
0x004032a3:	xorl %eax, %eax
0x004032a5:	incl %eax
0x004032a6:	leave
0x004032a7:	ret

0x0040d47d:	testl %eax, %eax
0x0040d47f:	jne 0x0040d487
0x0040d487:	call 0x0040f008
0x0040f008:	cmpl 0x413e28, $0x0<UINT8>
0x0040f00f:	jne 37
0x0040f011:	pushl $0x4114f0<UINT32>
0x0040f016:	call LoadLibraryA@KERNEL32.DLL
0x0040f01c:	testl %eax, %eax
0x0040f01e:	movl 0x413e28, %eax
0x0040f023:	je 17
0x0040f025:	pushl $0x4114fc<UINT32>
0x0040f02a:	pushl %eax
0x0040f02b:	call GetProcAddress@KERNEL32.DLL
0x0040f031:	movl 0x413e24, %eax
0x0040f036:	ret

0x0040d48c:	xorl %ebx, %ebx
0x0040d48e:	pushl $0x411128<UINT32>
0x0040d493:	leal %eax, 0x14(%esp)
0x0040d497:	movl 0x14(%esp), %ebx
0x0040d49b:	call 0x0040dc74
0x0040dc74:	pushl %ebp
0x0040dc75:	movl %ebp, %esp
0x0040dc77:	subl %esp, $0x18<UINT8>
0x0040dc7a:	pushl %ebx
0x0040dc7b:	pushl %esi
0x0040dc7c:	pushl %edi
0x0040dc7d:	movl %esi, %eax
0x0040dc7f:	leal %eax, -8(%ebp)
0x0040dc82:	pushl %eax
0x0040dc83:	pushl $0x28<UINT8>
0x0040dc85:	call GetCurrentProcess@KERNEL32.DLL
GetCurrentProcess@KERNEL32.DLL: API Node	
0x0040dc8b:	pushl %eax
0x0040dc8c:	movl %eax, %esi
0x0040dc8e:	call 0x0040dc3d
0x0040dc3d:	pushl %esi
0x0040dc3e:	pushl %edi
0x0040dc3f:	movl %esi, %eax
0x0040dc41:	xorl %edi, %edi
0x0040dc43:	call 0x0040dc1d
0x0040dc1d:	cmpl (%esi), $0x0<UINT8>
0x0040dc20:	jne 0x0040dc39
0x0040dc22:	pushl $0x411310<UINT32>
0x0040dc27:	call LoadLibraryA@KERNEL32.DLL
0x0040dc2d:	xorl %ecx, %ecx
0x0040dc2f:	testl %eax, %eax
0x0040dc31:	setne %cl
0x0040dc34:	movl (%esi), %eax
0x0040dc36:	movl %eax, %ecx
0x0040dc38:	ret

0x0040dc48:	testl %eax, %eax
0x0040dc4a:	je 33
0x0040dc4c:	pushl $0x411320<UINT32>
0x0040dc51:	pushl (%esi)
0x0040dc53:	call GetProcAddress@KERNEL32.DLL
0x0040dc59:	testl %eax, %eax
0x0040dc5b:	je 16
0x0040dc5d:	pushl 0x14(%esp)
0x0040dc61:	pushl 0x14(%esp)
0x0040dc65:	pushl 0x14(%esp)
0x0040dc69:	call OpenProcessToken@advapi32.dll
OpenProcessToken@advapi32.dll: API Node	
0x0040dc6b:	movl %edi, %eax
0x0040dc6d:	movl %eax, %edi
0x0040dc6f:	popl %edi
0x0040dc70:	popl %esi
0x0040dc71:	ret $0xc<UINT16>

0x0040dc93:	testl %eax, %eax
0x0040dc95:	jne 0x0040dc9f
0x0040dc9f:	call 0x0040dc1d
0x0040dc39:	xorl %eax, %eax
0x0040dc3b:	incl %eax
0x0040dc3c:	ret

0x0040dca4:	movl %edi, 0x4100d4
0x0040dcaa:	xorl %ebx, %ebx
0x0040dcac:	testl %eax, %eax
0x0040dcae:	je 23
0x0040dcb0:	pushl $0x411334<UINT32>
0x0040dcb5:	pushl (%esi)
0x0040dcb7:	call GetProcAddress@KERNEL32.DLL
0x0040dcb9:	cmpl %eax, %ebx
0x0040dcbb:	je 10
0x0040dcbd:	leal %ecx, -20(%ebp)
0x0040dcc0:	pushl %ecx
0x0040dcc1:	pushl 0x8(%ebp)
0x0040dcc4:	pushl %ebx
0x0040dcc5:	call LookupPrivilegeValueA@advapi32.dll
LookupPrivilegeValueA@advapi32.dll: API Node	
0x0040dcc7:	movl %eax, -8(%ebp)
0x0040dcca:	movl -24(%ebp), $0x1<UINT32>
0x0040dcd1:	movl -12(%ebp), $0x2<UINT32>
0x0040dcd8:	movl 0x8(%ebp), %eax
0x0040dcdb:	call 0x0040dc1d
0x0040dce0:	testl %eax, %eax
0x0040dce2:	je 26
0x0040dce4:	pushl $0x41134c<UINT32>
0x0040dce9:	pushl (%esi)
0x0040dceb:	call GetProcAddress@KERNEL32.DLL
0x0040dced:	cmpl %eax, %ebx
0x0040dcef:	je 13
0x0040dcf1:	pushl %ebx
0x0040dcf2:	pushl %ebx
0x0040dcf3:	pushl %ebx
0x0040dcf4:	leal %ecx, -24(%ebp)
0x0040dcf7:	pushl %ecx
0x0040dcf8:	pushl %ebx
0x0040dcf9:	pushl 0x8(%ebp)
0x0040dcfc:	call AdjustTokenPrivileges@advapi32.dll
AdjustTokenPrivileges@advapi32.dll: API Node	
0x0040dcfe:	call GetLastError@KERNEL32.DLL
GetLastError@KERNEL32.DLL: API Node	
0x0040dd04:	pushl -8(%ebp)
0x0040dd07:	movl %esi, %eax
0x0040dd09:	call CloseHandle@KERNEL32.DLL
CloseHandle@KERNEL32.DLL: API Node	
0x0040dd0f:	movl %eax, %esi
0x0040dd11:	popl %edi
0x0040dd12:	popl %esi
0x0040dd13:	popl %ebx
0x0040dd14:	leave
0x0040dd15:	ret $0x4<UINT16>

0x0040d4a0:	pushl $0x411140<UINT32>
0x0040d4a5:	leal %eax, 0x14(%esp)
0x0040d4a9:	call 0x0040dc74
0x0040d4ae:	pushl $0x8001<UINT32>
0x0040d4b3:	call SetErrorMode@KERNEL32.DLL
SetErrorMode@KERNEL32.DLL: API Node	
0x0040d4b9:	leal %eax, 0x374(%esp)
0x0040d4c0:	call 0x00405d22
0x00405d22:	xorl %ecx, %ecx
0x00405d24:	movl 0x14(%eax), $0x400<UINT32>
0x00405d2b:	movl 0x18(%eax), $0x100<UINT32>
0x00405d32:	movl (%eax), %ecx
0x00405d34:	movl 0x4(%eax), %ecx
0x00405d37:	movl 0xc(%eax), %ecx
0x00405d3a:	movl 0x10(%eax), %ecx
0x00405d3d:	movl 0x1c(%eax), %ecx
0x00405d40:	movl 0x8(%eax), %ecx
0x00405d43:	ret

0x0040d4c5:	leal %eax, 0x18(%esp)
0x0040d4c9:	call 0x00405d22
0x0040d4ce:	leal %edi, 0x398(%esp)
0x0040d4d5:	movl 0x40(%esp), $0x20<UINT32>
0x0040d4dd:	movl 0x38(%esp), %ebx
0x0040d4e1:	movl 0x44(%esp), %ebx
0x0040d4e5:	movl 0x3c(%esp), %ebx
0x0040d4e9:	movl 0x48(%esp), %ebx
0x0040d4ed:	call 0x0040ce08
0x0040ce08:	pushl %ebp
0x0040ce09:	movl %ebp, %esp
0x0040ce0b:	xorl %ecx, %ecx
0x0040ce0d:	subl %esp, $0x508<UINT32>
0x0040ce13:	pushl %ebx
0x0040ce14:	leal %eax, 0xec8(%edi)
0x0040ce1a:	movl 0x108(%edi), %ecx
0x0040ce20:	movl 0x144(%edi), %ecx
0x0040ce26:	movl 0x174(%edi), %ecx
0x0040ce2c:	movl 0x140(%edi), %ecx
0x0040ce32:	movl (%edi), $0x4111ac<UINT32>
0x0040ce38:	pushl %esi
0x0040ce39:	leal %ebx, 0xeec(%edi)
0x0040ce3f:	movl %esi, %ebx
0x0040ce41:	movl (%eax), $0x4115b4<UINT32>
0x0040ce47:	movl 0x4(%eax), %ecx
0x0040ce4a:	movl 0x8(%eax), %ecx
0x0040ce4d:	movl 0x10(%eax), %ecx
0x0040ce50:	call 0x004012f3
0x004012f3:	andl 0x10(%esi), $0x0<UINT8>
0x004012f7:	pushl $0x2c<UINT8>
0x004012f9:	leal %eax, 0x14(%esi)
0x004012fc:	pushl $0x0<UINT8>
0x004012fe:	pushl %eax
0x004012ff:	movl (%esi), $0x4104e0<UINT32>
0x00401305:	call 0x0040fb50
0x0040fb50:	jmp memset@msvcrt.dll
memset@msvcrt.dll: API Node	
0x0040130a:	addl %esp, $0xc<UINT8>
0x0040130d:	movl %eax, %esi
0x0040130f:	ret

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
0x00000066:	addb (%eax), %al
0x0040328e:	pushl $0x410834<UINT32>
0x00403293:	pushl $0x41083c<UINT32>
0x00403298:	pushl %eax
0x00403299:	call MessageBoxA@USER32.dll
MessageBoxA@USER32.dll: API Node	
0x0040329f:	xorl %eax, %eax
0x004032a1:	leave
0x004032a2:	ret

0x0040d481:	incl %eax
0x0040d482:	jmp 0x0040d71c
0x0040d71c:	popl %edi
0x0040d71d:	popl %esi
0x0040d71e:	popl %ebx
0x0040d71f:	movl %esp, %ebp
0x0040d721:	popl %ebp
0x0040d722:	ret $0x10<UINT16>

0x0040fd84:	movl %esi, %eax
0x0040fd86:	movl -124(%ebp), %esi
0x0040fd89:	cmpl -28(%ebp), %ebx
0x0040fd8c:	jne 7
0x0040fd8e:	pushl %esi
0x0040fd8f:	call exit@msvcrt.dll
exit@msvcrt.dll: Exit Node	
