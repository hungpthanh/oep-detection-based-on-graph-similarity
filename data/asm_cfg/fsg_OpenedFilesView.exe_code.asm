0x0042f000:	movl %ebx, $0x4001d0<UINT32>
0x0042f005:	movl %edi, $0x401000<UINT32>
0x0042f00a:	movl %esi, $0x4239fc<UINT32>
0x0042f00f:	pushl %ebx
0x0042f010:	call 0x0042f01f
0x0042f01f:	cld
0x0042f020:	movb %dl, $0xffffff80<UINT8>
0x0042f022:	movsb %es:(%edi), %ds:(%esi)
0x0042f023:	pushl $0x2<UINT8>
0x0042f025:	popl %ebx
0x0042f026:	call 0x0042f015
0x0042f015:	addb %dl, %dl
0x0042f017:	jne 0x0042f01e
0x0042f019:	movb %dl, (%esi)
0x0042f01b:	incl %esi
0x0042f01c:	adcb %dl, %dl
0x0042f01e:	ret

0x0042f029:	jae 0x0042f022
0x0042f02b:	xorl %ecx, %ecx
0x0042f02d:	call 0x0042f015
0x0042f030:	jae 0x0042f04a
0x0042f032:	xorl %eax, %eax
0x0042f034:	call 0x0042f015
0x0042f037:	jae 0x0042f05a
0x0042f039:	movb %bl, $0x2<UINT8>
0x0042f03b:	incl %ecx
0x0042f03c:	movb %al, $0x10<UINT8>
0x0042f03e:	call 0x0042f015
0x0042f041:	adcb %al, %al
0x0042f043:	jae 0x0042f03e
0x0042f045:	jne 0x0042f086
0x0042f086:	pushl %esi
0x0042f087:	movl %esi, %edi
0x0042f089:	subl %esi, %eax
0x0042f08b:	rep movsb %es:(%edi), %ds:(%esi)
0x0042f08d:	popl %esi
0x0042f08e:	jmp 0x0042f026
0x0042f047:	stosb %es:(%edi), %al
0x0042f048:	jmp 0x0042f026
0x0042f05a:	lodsb %al, %ds:(%esi)
0x0042f05b:	shrl %eax
0x0042f05d:	je 0x0042f0a0
0x0042f05f:	adcl %ecx, %ecx
0x0042f061:	jmp 0x0042f07f
0x0042f07f:	incl %ecx
0x0042f080:	incl %ecx
0x0042f081:	xchgl %ebp, %eax
0x0042f082:	movl %eax, %ebp
0x0042f084:	movb %bl, $0x1<UINT8>
0x0042f04a:	call 0x0042f092
0x0042f092:	incl %ecx
0x0042f093:	call 0x0042f015
0x0042f097:	adcl %ecx, %ecx
0x0042f099:	call 0x0042f015
0x0042f09d:	jb 0x0042f093
0x0042f09f:	ret

0x0042f04f:	subl %ecx, %ebx
0x0042f051:	jne 0x0042f063
0x0042f063:	xchgl %ecx, %eax
0x0042f064:	decl %eax
0x0042f065:	shll %eax, $0x8<UINT8>
0x0042f068:	lodsb %al, %ds:(%esi)
0x0042f069:	call 0x0042f090
0x0042f090:	xorl %ecx, %ecx
0x0042f06e:	cmpl %eax, $0x7d00<UINT32>
0x0042f073:	jae 0x0042f07f
0x0042f075:	cmpb %ah, $0x5<UINT8>
0x0042f078:	jae 0x0042f080
0x0042f07a:	cmpl %eax, $0x7f<UINT8>
0x0042f07d:	ja 0x0042f081
0x0042f053:	call 0x0042f090
0x0042f058:	jmp 0x0042f082
0x0042f0a0:	popl %edi
0x0042f0a1:	popl %ebx
0x0042f0a2:	movzwl %edi, (%ebx)
0x0042f0a5:	decl %edi
0x0042f0a6:	je 0x0042f0b0
0x0042f0a8:	decl %edi
0x0042f0a9:	je 0x0042f0be
0x0042f0ab:	shll %edi, $0xc<UINT8>
0x0042f0ae:	jmp 0x0042f0b7
0x0042f0b7:	incl %ebx
0x0042f0b8:	incl %ebx
0x0042f0b9:	jmp 0x0042f00f
0x0042f0b0:	movl %edi, 0x2(%ebx)
0x0042f0b3:	pushl %edi
0x0042f0b4:	addl %ebx, $0x4<UINT8>
0x0042f0be:	popl %edi
0x0042f0bf:	movl %ebx, $0x42f128<UINT32>
0x0042f0c4:	incl %edi
0x0042f0c5:	movl %esi, (%edi)
0x0042f0c7:	scasl %eax, %es:(%edi)
0x0042f0c8:	pushl %edi
0x0042f0c9:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x0042f0cb:	xchgl %ebp, %eax
0x0042f0cc:	xorl %eax, %eax
0x0042f0ce:	scasb %al, %es:(%edi)
0x0042f0cf:	jne 0x0042f0ce
0x0042f0d1:	decb (%edi)
0x0042f0d3:	je 0x0042f0c4
0x0042f0d5:	decb (%edi)
0x0042f0d7:	jne 0x0042f0df
0x0042f0df:	decb (%edi)
0x0042f0e1:	je 0x0040fc10
0x0042f0e7:	pushl %edi
0x0042f0e8:	pushl %ebp
0x0042f0e9:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0042f0ec:	orl (%esi), %eax
0x0042f0ee:	lodsl %eax, %ds:(%esi)
0x0042f0ef:	jne 0x0042f0cc
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x0042f0d9:	incl %edi
0x0042f0da:	pushl (%edi)
0x0042f0dc:	scasl %eax, %es:(%edi)
0x0042f0dd:	jmp 0x0042f0e8
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
