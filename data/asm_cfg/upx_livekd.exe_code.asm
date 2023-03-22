0x0049ffa0:	pusha
0x0049ffa1:	movl %esi, $0x464000<UINT32>
0x0049ffa6:	leal %edi, -405504(%esi)
0x0049ffac:	pushl %edi
0x0049ffad:	jmp 0x0049ffba
0x0049ffba:	movl %ebx, (%esi)
0x0049ffbc:	subl %esi, $0xfffffffc<UINT8>
0x0049ffbf:	adcl %ebx, %ebx
0x0049ffc1:	jb 0x0049ffb0
0x0049ffb0:	movb %al, (%esi)
0x0049ffb2:	incl %esi
0x0049ffb3:	movb (%edi), %al
0x0049ffb5:	incl %edi
0x0049ffb6:	addl %ebx, %ebx
0x0049ffb8:	jne 0x0049ffc1
0x0049ffc3:	movl %eax, $0x1<UINT32>
0x0049ffc8:	addl %ebx, %ebx
0x0049ffca:	jne 0x0049ffd3
0x0049ffd3:	adcl %eax, %eax
0x0049ffd5:	addl %ebx, %ebx
0x0049ffd7:	jae 0x0049ffe4
0x0049ffd9:	jne 0x004a0003
0x004a0003:	xorl %ecx, %ecx
0x004a0005:	subl %eax, $0x3<UINT8>
0x004a0008:	jb 0x004a001b
0x004a000a:	shll %eax, $0x8<UINT8>
0x004a000d:	movb %al, (%esi)
0x004a000f:	incl %esi
0x004a0010:	xorl %eax, $0xffffffff<UINT8>
0x004a0013:	je 0x004a008a
0x004a0015:	sarl %eax
0x004a0017:	movl %ebp, %eax
0x004a0019:	jmp 0x004a0026
0x004a0026:	jb 0x0049fff4
0x004a0028:	incl %ecx
0x004a0029:	addl %ebx, %ebx
0x004a002b:	jne 0x004a0034
0x004a0034:	jb 0x0049fff4
0x0049fff4:	addl %ebx, %ebx
0x0049fff6:	jne 0x0049ffff
0x0049ffff:	adcl %ecx, %ecx
0x004a0001:	jmp 0x004a0055
0x004a0055:	cmpl %ebp, $0xfffffb00<UINT32>
0x004a005b:	adcl %ecx, $0x2<UINT8>
0x004a005e:	leal %edx, (%edi,%ebp)
0x004a0061:	cmpl %ebp, $0xfffffffc<UINT8>
0x004a0064:	jbe 0x004a0074
0x004a0074:	movl %eax, (%edx)
0x004a0076:	addl %edx, $0x4<UINT8>
0x004a0079:	movl (%edi), %eax
0x004a007b:	addl %edi, $0x4<UINT8>
0x004a007e:	subl %ecx, $0x4<UINT8>
0x004a0081:	ja 0x004a0074
0x004a0083:	addl %edi, %ecx
0x004a0085:	jmp 0x0049ffb6
0x004a0066:	movb %al, (%edx)
0x004a0068:	incl %edx
0x004a0069:	movb (%edi), %al
0x004a006b:	incl %edi
0x004a006c:	decl %ecx
0x004a006d:	jne 0x004a0066
0x004a006f:	jmp 0x0049ffb6
0x0049ffdb:	movl %ebx, (%esi)
0x0049ffdd:	subl %esi, $0xfffffffc<UINT8>
0x0049ffe0:	adcl %ebx, %ebx
0x0049ffe2:	jb 0x004a0003
0x004a0036:	addl %ebx, %ebx
0x004a0038:	jne 0x004a0041
0x004a0041:	adcl %ecx, %ecx
0x004a0043:	addl %ebx, %ebx
0x004a0045:	jae 0x004a0036
0x004a0047:	jne 0x004a0052
0x004a0052:	addl %ecx, $0x2<UINT8>
0x0049ffe4:	decl %eax
0x0049ffe5:	addl %ebx, %ebx
0x0049ffe7:	jne 0x0049fff0
0x0049fff0:	adcl %eax, %eax
0x0049fff2:	jmp 0x0049ffc8
0x0049fff8:	movl %ebx, (%esi)
0x0049fffa:	subl %esi, $0xfffffffc<UINT8>
0x0049fffd:	adcl %ebx, %ebx
0x004a0049:	movl %ebx, (%esi)
0x004a004b:	subl %esi, $0xfffffffc<UINT8>
0x004a004e:	adcl %ebx, %ebx
0x004a0050:	jae 0x004a0036
0x004a002d:	movl %ebx, (%esi)
0x004a002f:	subl %esi, $0xfffffffc<UINT8>
0x004a0032:	adcl %ebx, %ebx
0x004a001b:	addl %ebx, %ebx
0x004a001d:	jne 0x004a0026
0x0049ffcc:	movl %ebx, (%esi)
0x0049ffce:	subl %esi, $0xfffffffc<UINT8>
0x0049ffd1:	adcl %ebx, %ebx
0x0049ffe9:	movl %ebx, (%esi)
0x0049ffeb:	subl %esi, $0xfffffffc<UINT8>
0x0049ffee:	adcl %ebx, %ebx
0x004a003a:	movl %ebx, (%esi)
0x004a003c:	subl %esi, $0xfffffffc<UINT8>
0x004a003f:	adcl %ebx, %ebx
0x004a001f:	movl %ebx, (%esi)
0x004a0021:	subl %esi, $0xfffffffc<UINT8>
0x004a0024:	adcl %ebx, %ebx
0x004a008a:	popl %esi
0x004a008b:	movl %edi, %esi
0x004a008d:	movl %ecx, $0x7fd<UINT32>
0x004a0092:	movb %al, (%edi)
0x004a0094:	incl %edi
0x004a0095:	subb %al, $0xffffffe8<UINT8>
0x004a0097:	cmpb %al, $0x1<UINT8>
0x004a0099:	ja 0x004a0092
0x004a009b:	cmpb (%edi), $0x5<UINT8>
0x004a009e:	jne 0x004a0092
0x004a00a0:	movl %eax, (%edi)
0x004a00a2:	movb %bl, 0x4(%edi)
0x004a00a5:	shrw %ax, $0x8<UINT8>
0x004a00a9:	roll %eax, $0x10<UINT8>
0x004a00ac:	xchgb %ah, %al
0x004a00ae:	subl %eax, %edi
0x004a00b0:	subb %bl, $0xffffffe8<UINT8>
0x004a00b3:	addl %eax, %esi
0x004a00b5:	movl (%edi), %eax
0x004a00b7:	addl %edi, $0x5<UINT8>
0x004a00ba:	movb %al, %bl
0x004a00bc:	loop 0x004a0097
0x004a00be:	leal %edi, 0x9c000(%esi)
0x004a00c4:	movl %eax, (%edi)
0x004a00c6:	orl %eax, %eax
0x004a00c8:	je 0x004a0106
0x004a00ca:	movl %ebx, 0x4(%edi)
0x004a00cd:	leal %eax, 0xa0658(%eax,%esi)
0x004a00d4:	addl %ebx, %esi
0x004a00d6:	pushl %eax
0x004a00d7:	addl %edi, $0x8<UINT8>
0x004a00da:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x004a00e0:	xchgl %ebp, %eax
0x004a00e1:	movb %al, (%edi)
0x004a00e3:	incl %edi
0x004a00e4:	orb %al, %al
0x004a00e6:	je 0x004a00c4
0x004a00e8:	movl %ecx, %edi
0x004a00ea:	pushl %edi
0x004a00eb:	decl %eax
0x004a00ec:	repn scasb %al, %es:(%edi)
0x004a00ee:	pushl %ebp
0x004a00ef:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x004a00f5:	orl %eax, %eax
0x004a00f7:	je 7
0x004a00f9:	movl (%ebx), %eax
0x004a00fb:	addl %ebx, $0x4<UINT8>
0x004a00fe:	jmp 0x004a00e1
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x004a0106:	addl %edi, $0x4<UINT8>
0x004a0109:	leal %ebx, -4(%esi)
0x004a010c:	xorl %eax, %eax
0x004a010e:	movb %al, (%edi)
0x004a0110:	incl %edi
0x004a0111:	orl %eax, %eax
0x004a0113:	je 0x004a0137
0x004a0115:	cmpb %al, $0xffffffef<UINT8>
0x004a0117:	ja 0x004a012a
0x004a0119:	addl %ebx, %eax
0x004a011b:	movl %eax, (%ebx)
0x004a011d:	xchgb %ah, %al
0x004a011f:	roll %eax, $0x10<UINT8>
0x004a0122:	xchgb %ah, %al
0x004a0124:	addl %eax, %esi
0x004a0126:	movl (%ebx), %eax
0x004a0128:	jmp 0x004a010c
0x004a012a:	andb %al, $0xf<UINT8>
0x004a012c:	shll %eax, $0x10<UINT8>
0x004a012f:	movw %ax, (%edi)
0x004a0132:	addl %edi, $0x2<UINT8>
0x004a0135:	jmp 0x004a0119
0x004a0137:	movl %ebp, 0xa0708(%esi)
0x004a013d:	leal %edi, -4096(%esi)
0x004a0143:	movl %ebx, $0x1000<UINT32>
0x004a0148:	pushl %eax
0x004a0149:	pushl %esp
0x004a014a:	pushl $0x4<UINT8>
0x004a014c:	pushl %ebx
0x004a014d:	pushl %edi
0x004a014e:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x004a0150:	leal %eax, 0x20f(%edi)
0x004a0156:	andb (%eax), $0x7f<UINT8>
0x004a0159:	andb 0x28(%eax), $0x7f<UINT8>
0x004a015d:	popl %eax
0x004a015e:	pushl %eax
0x004a015f:	pushl %esp
0x004a0160:	pushl %eax
0x004a0161:	pushl %ebx
0x004a0162:	pushl %edi
0x004a0163:	call VirtualProtect@kernel32.dll
0x004a0165:	popl %eax
0x004a0166:	popa
0x004a0167:	leal %eax, -128(%esp)
0x004a016b:	pushl $0x0<UINT8>
0x004a016d:	cmpl %esp, %eax
0x004a016f:	jne 0x004a016b
0x004a0171:	subl %esp, $0xffffff80<UINT8>
0x004a0174:	jmp 0x00409663
0x00409663:	call 0x0040fcae
0x0040fcae:	pushl %ebp
0x0040fcaf:	movl %ebp, %esp
0x0040fcb1:	subl %esp, $0x14<UINT8>
0x0040fcb4:	andl -12(%ebp), $0x0<UINT8>
0x0040fcb8:	andl -8(%ebp), $0x0<UINT8>
0x0040fcbc:	movl %eax, 0x4269f0
0x0040fcc1:	pushl %esi
0x0040fcc2:	pushl %edi
0x0040fcc3:	movl %edi, $0xbb40e64e<UINT32>
0x0040fcc8:	movl %esi, $0xffff0000<UINT32>
0x0040fccd:	cmpl %eax, %edi
0x0040fccf:	je 0x0040fcde
0x0040fcde:	leal %eax, -12(%ebp)
0x0040fce1:	pushl %eax
0x0040fce2:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040fce8:	movl %eax, -8(%ebp)
0x0040fceb:	xorl %eax, -12(%ebp)
0x0040fcee:	movl -4(%ebp), %eax
0x0040fcf1:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040fcf7:	xorl -4(%ebp), %eax
0x0040fcfa:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040fd00:	xorl -4(%ebp), %eax
0x0040fd03:	leal %eax, -20(%ebp)
0x0040fd06:	pushl %eax
0x0040fd07:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040fd0d:	movl %ecx, -16(%ebp)
0x0040fd10:	leal %eax, -4(%ebp)
0x0040fd13:	xorl %ecx, -20(%ebp)
0x0040fd16:	xorl %ecx, -4(%ebp)
0x0040fd19:	xorl %ecx, %eax
0x0040fd1b:	cmpl %ecx, %edi
0x0040fd1d:	jne 0x0040fd26
0x0040fd26:	testl %esi, %ecx
0x0040fd28:	jne 0x0040fd36
0x0040fd36:	movl 0x4269f0, %ecx
0x0040fd3c:	notl %ecx
0x0040fd3e:	movl 0x4269f4, %ecx
0x0040fd44:	popl %edi
0x0040fd45:	popl %esi
0x0040fd46:	movl %esp, %ebp
0x0040fd48:	popl %ebp
0x0040fd49:	ret

0x00409668:	jmp 0x004094e8
0x004094e8:	pushl $0x14<UINT8>
0x004094ea:	pushl $0x424288<UINT32>
0x004094ef:	call 0x0040b4b0
0x0040b4b0:	pushl $0x408140<UINT32>
0x0040b4b5:	pushl %fs:0
0x0040b4bc:	movl %eax, 0x10(%esp)
0x0040b4c0:	movl 0x10(%esp), %ebp
0x0040b4c4:	leal %ebp, 0x10(%esp)
0x0040b4c8:	subl %esp, %eax
0x0040b4ca:	pushl %ebx
0x0040b4cb:	pushl %esi
0x0040b4cc:	pushl %edi
0x0040b4cd:	movl %eax, 0x4269f0
0x0040b4d2:	xorl -4(%ebp), %eax
0x0040b4d5:	xorl %eax, %ebp
0x0040b4d7:	pushl %eax
0x0040b4d8:	movl -24(%ebp), %esp
0x0040b4db:	pushl -8(%ebp)
0x0040b4de:	movl %eax, -4(%ebp)
0x0040b4e1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040b4e8:	movl -8(%ebp), %eax
0x0040b4eb:	leal %eax, -16(%ebp)
0x0040b4ee:	movl %fs:0, %eax
0x0040b4f4:	ret

0x004094f4:	pushl $0x1<UINT8>
0x004094f6:	call 0x0040fc61
0x0040fc61:	pushl %ebp
0x0040fc62:	movl %ebp, %esp
0x0040fc64:	movl %eax, 0x8(%ebp)
0x0040fc67:	movl 0x427d88, %eax
0x0040fc6c:	popl %ebp
0x0040fc6d:	ret

0x004094fb:	popl %ecx
0x004094fc:	movl %eax, $0x5a4d<UINT32>
0x00409501:	cmpw 0x400000, %ax
0x00409508:	je 0x0040950e
0x0040950e:	movl %eax, 0x40003c
0x00409513:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x0040951d:	jne -21
0x0040951f:	movl %ecx, $0x10b<UINT32>
0x00409524:	cmpw 0x400018(%eax), %cx
0x0040952b:	jne -35
0x0040952d:	xorl %ebx, %ebx
0x0040952f:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00409536:	jbe 9
0x00409538:	cmpl 0x4000e8(%eax), %ebx
0x0040953e:	setne %bl
0x00409541:	movl -28(%ebp), %ebx
0x00409544:	call 0x0040b5e0
0x0040b5e0:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x0040b5e6:	xorl %ecx, %ecx
0x0040b5e8:	movl 0x4283e8, %eax
0x0040b5ed:	testl %eax, %eax
0x0040b5ef:	setne %cl
0x0040b5f2:	movl %eax, %ecx
0x0040b5f4:	ret

0x00409549:	testl %eax, %eax
0x0040954b:	jne 0x00409555
0x00409555:	call 0x0040a571
0x0040a571:	call 0x004066fa
0x004066fa:	pushl %esi
0x004066fb:	pushl $0x0<UINT8>
0x004066fd:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00406703:	movl %esi, %eax
0x00406705:	pushl %esi
0x00406706:	call 0x0040b264
0x0040b264:	pushl %ebp
0x0040b265:	movl %ebp, %esp
0x0040b267:	movl %eax, 0x8(%ebp)
0x0040b26a:	movl 0x4283c0, %eax
0x0040b26f:	popl %ebp
0x0040b270:	ret

0x0040670b:	pushl %esi
0x0040670c:	call 0x00409792
0x00409792:	pushl %ebp
0x00409793:	movl %ebp, %esp
0x00409795:	movl %eax, 0x8(%ebp)
0x00409798:	movl 0x427c10, %eax
0x0040979d:	popl %ebp
0x0040979e:	ret

0x00406711:	pushl %esi
0x00406712:	call 0x0040b271
0x0040b271:	pushl %ebp
0x0040b272:	movl %ebp, %esp
0x0040b274:	movl %eax, 0x8(%ebp)
0x0040b277:	movl 0x4283c4, %eax
0x0040b27c:	popl %ebp
0x0040b27d:	ret

0x00406717:	pushl %esi
0x00406718:	call 0x0040b28b
0x0040b28b:	pushl %ebp
0x0040b28c:	movl %ebp, %esp
0x0040b28e:	movl %eax, 0x8(%ebp)
0x0040b291:	movl 0x4283c8, %eax
0x0040b296:	movl 0x4283cc, %eax
0x0040b29b:	movl 0x4283d0, %eax
0x0040b2a0:	movl 0x4283d4, %eax
0x0040b2a5:	popl %ebp
0x0040b2a6:	ret

0x0040671d:	pushl %esi
0x0040671e:	call 0x0040b22d
0x0040b22d:	pushl $0x40b1f9<UINT32>
0x0040b232:	call EncodePointer@KERNEL32.DLL
0x0040b238:	movl 0x4283bc, %eax
0x0040b23d:	ret

0x00406723:	pushl %esi
0x00406724:	call 0x0040b49c
0x0040b49c:	pushl %ebp
0x0040b49d:	movl %ebp, %esp
0x0040b49f:	movl %eax, 0x8(%ebp)
0x0040b4a2:	movl 0x4283dc, %eax
0x0040b4a7:	popl %ebp
0x0040b4a8:	ret

0x00406729:	addl %esp, $0x18<UINT8>
0x0040672c:	popl %esi
0x0040672d:	jmp 0x0040a989
0x0040a989:	pushl %esi
0x0040a98a:	pushl %edi
0x0040a98b:	pushl $0x41d824<UINT32>
0x0040a990:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0040a996:	movl %esi, 0x417180
0x0040a99c:	movl %edi, %eax
0x0040a99e:	pushl $0x420890<UINT32>
0x0040a9a3:	pushl %edi
0x0040a9a4:	call GetProcAddress@KERNEL32.DLL
0x0040a9a6:	xorl %eax, 0x4269f0
0x0040a9ac:	pushl $0x42089c<UINT32>
0x0040a9b1:	pushl %edi
0x0040a9b2:	movl 0x428c00, %eax
0x0040a9b7:	call GetProcAddress@KERNEL32.DLL
0x0040a9b9:	xorl %eax, 0x4269f0
0x0040a9bf:	pushl $0x4208a4<UINT32>
0x0040a9c4:	pushl %edi
0x0040a9c5:	movl 0x428c04, %eax
0x0040a9ca:	call GetProcAddress@KERNEL32.DLL
0x0040a9cc:	xorl %eax, 0x4269f0
0x0040a9d2:	pushl $0x4208b0<UINT32>
0x0040a9d7:	pushl %edi
0x0040a9d8:	movl 0x428c08, %eax
0x0040a9dd:	call GetProcAddress@KERNEL32.DLL
0x0040a9df:	xorl %eax, 0x4269f0
0x0040a9e5:	pushl $0x4208bc<UINT32>
0x0040a9ea:	pushl %edi
0x0040a9eb:	movl 0x428c0c, %eax
0x0040a9f0:	call GetProcAddress@KERNEL32.DLL
0x0040a9f2:	xorl %eax, 0x4269f0
0x0040a9f8:	pushl $0x4208d8<UINT32>
0x0040a9fd:	pushl %edi
0x0040a9fe:	movl 0x428c10, %eax
0x0040aa03:	call GetProcAddress@KERNEL32.DLL
0x0040aa05:	xorl %eax, 0x4269f0
0x0040aa0b:	pushl $0x4208e8<UINT32>
0x0040aa10:	pushl %edi
0x0040aa11:	movl 0x428c14, %eax
0x0040aa16:	call GetProcAddress@KERNEL32.DLL
0x0040aa18:	xorl %eax, 0x4269f0
0x0040aa1e:	pushl $0x4208fc<UINT32>
0x0040aa23:	pushl %edi
0x0040aa24:	movl 0x428c18, %eax
0x0040aa29:	call GetProcAddress@KERNEL32.DLL
0x0040aa2b:	xorl %eax, 0x4269f0
0x0040aa31:	pushl $0x420914<UINT32>
0x0040aa36:	pushl %edi
0x0040aa37:	movl 0x428c1c, %eax
0x0040aa3c:	call GetProcAddress@KERNEL32.DLL
0x0040aa3e:	xorl %eax, 0x4269f0
0x0040aa44:	pushl $0x42092c<UINT32>
0x0040aa49:	pushl %edi
0x0040aa4a:	movl 0x428c20, %eax
0x0040aa4f:	call GetProcAddress@KERNEL32.DLL
0x0040aa51:	xorl %eax, 0x4269f0
0x0040aa57:	pushl $0x420940<UINT32>
0x0040aa5c:	pushl %edi
0x0040aa5d:	movl 0x428c24, %eax
0x0040aa62:	call GetProcAddress@KERNEL32.DLL
0x0040aa64:	xorl %eax, 0x4269f0
0x0040aa6a:	pushl $0x420960<UINT32>
0x0040aa6f:	pushl %edi
0x0040aa70:	movl 0x428c28, %eax
0x0040aa75:	call GetProcAddress@KERNEL32.DLL
0x0040aa77:	xorl %eax, 0x4269f0
0x0040aa7d:	pushl $0x420978<UINT32>
0x0040aa82:	pushl %edi
0x0040aa83:	movl 0x428c2c, %eax
0x0040aa88:	call GetProcAddress@KERNEL32.DLL
0x0040aa8a:	xorl %eax, 0x4269f0
0x0040aa90:	pushl $0x420990<UINT32>
0x0040aa95:	pushl %edi
0x0040aa96:	movl 0x428c30, %eax
0x0040aa9b:	call GetProcAddress@KERNEL32.DLL
0x0040aa9d:	xorl %eax, 0x4269f0
0x0040aaa3:	pushl $0x4209a4<UINT32>
0x0040aaa8:	pushl %edi
0x0040aaa9:	movl 0x428c34, %eax
0x0040aaae:	call GetProcAddress@KERNEL32.DLL
0x0040aab0:	xorl %eax, 0x4269f0
0x0040aab6:	movl 0x428c38, %eax
0x0040aabb:	pushl $0x4209b8<UINT32>
0x0040aac0:	pushl %edi
0x0040aac1:	call GetProcAddress@KERNEL32.DLL
0x0040aac3:	xorl %eax, 0x4269f0
0x0040aac9:	pushl $0x4209d4<UINT32>
0x0040aace:	pushl %edi
0x0040aacf:	movl 0x428c3c, %eax
0x0040aad4:	call GetProcAddress@KERNEL32.DLL
0x0040aad6:	xorl %eax, 0x4269f0
0x0040aadc:	pushl $0x4209f4<UINT32>
0x0040aae1:	pushl %edi
0x0040aae2:	movl 0x428c40, %eax
0x0040aae7:	call GetProcAddress@KERNEL32.DLL
0x0040aae9:	xorl %eax, 0x4269f0
0x0040aaef:	pushl $0x420a10<UINT32>
0x0040aaf4:	pushl %edi
0x0040aaf5:	movl 0x428c44, %eax
0x0040aafa:	call GetProcAddress@KERNEL32.DLL
0x0040aafc:	xorl %eax, 0x4269f0
0x0040ab02:	pushl $0x420a30<UINT32>
0x0040ab07:	pushl %edi
0x0040ab08:	movl 0x428c48, %eax
0x0040ab0d:	call GetProcAddress@KERNEL32.DLL
0x0040ab0f:	xorl %eax, 0x4269f0
0x0040ab15:	pushl $0x420a44<UINT32>
0x0040ab1a:	pushl %edi
0x0040ab1b:	movl 0x428c4c, %eax
0x0040ab20:	call GetProcAddress@KERNEL32.DLL
0x0040ab22:	xorl %eax, 0x4269f0
0x0040ab28:	pushl $0x420a60<UINT32>
0x0040ab2d:	pushl %edi
0x0040ab2e:	movl 0x428c50, %eax
0x0040ab33:	call GetProcAddress@KERNEL32.DLL
0x0040ab35:	xorl %eax, 0x4269f0
0x0040ab3b:	pushl $0x420a74<UINT32>
0x0040ab40:	pushl %edi
0x0040ab41:	movl 0x428c58, %eax
0x0040ab46:	call GetProcAddress@KERNEL32.DLL
0x0040ab48:	xorl %eax, 0x4269f0
0x0040ab4e:	pushl $0x420a84<UINT32>
0x0040ab53:	pushl %edi
0x0040ab54:	movl 0x428c54, %eax
0x0040ab59:	call GetProcAddress@KERNEL32.DLL
0x0040ab5b:	xorl %eax, 0x4269f0
0x0040ab61:	pushl $0x420a94<UINT32>
0x0040ab66:	pushl %edi
0x0040ab67:	movl 0x428c5c, %eax
0x0040ab6c:	call GetProcAddress@KERNEL32.DLL
0x0040ab6e:	xorl %eax, 0x4269f0
0x0040ab74:	pushl $0x420aa4<UINT32>
0x0040ab79:	pushl %edi
0x0040ab7a:	movl 0x428c60, %eax
0x0040ab7f:	call GetProcAddress@KERNEL32.DLL
0x0040ab81:	xorl %eax, 0x4269f0
0x0040ab87:	pushl $0x420ab4<UINT32>
0x0040ab8c:	pushl %edi
0x0040ab8d:	movl 0x428c64, %eax
0x0040ab92:	call GetProcAddress@KERNEL32.DLL
0x0040ab94:	xorl %eax, 0x4269f0
0x0040ab9a:	pushl $0x420ad0<UINT32>
0x0040ab9f:	pushl %edi
0x0040aba0:	movl 0x428c68, %eax
0x0040aba5:	call GetProcAddress@KERNEL32.DLL
0x0040aba7:	xorl %eax, 0x4269f0
0x0040abad:	pushl $0x420ae4<UINT32>
0x0040abb2:	pushl %edi
0x0040abb3:	movl 0x428c6c, %eax
0x0040abb8:	call GetProcAddress@KERNEL32.DLL
0x0040abba:	xorl %eax, 0x4269f0
0x0040abc0:	pushl $0x420af4<UINT32>
0x0040abc5:	pushl %edi
0x0040abc6:	movl 0x428c70, %eax
0x0040abcb:	call GetProcAddress@KERNEL32.DLL
0x0040abcd:	xorl %eax, 0x4269f0
0x0040abd3:	pushl $0x420b08<UINT32>
0x0040abd8:	pushl %edi
0x0040abd9:	movl 0x428c74, %eax
0x0040abde:	call GetProcAddress@KERNEL32.DLL
0x0040abe0:	xorl %eax, 0x4269f0
0x0040abe6:	movl 0x428c78, %eax
0x0040abeb:	pushl $0x420b18<UINT32>
0x0040abf0:	pushl %edi
0x0040abf1:	call GetProcAddress@KERNEL32.DLL
0x0040abf3:	xorl %eax, 0x4269f0
0x0040abf9:	pushl $0x420b38<UINT32>
0x0040abfe:	pushl %edi
0x0040abff:	movl 0x428c7c, %eax
0x0040ac04:	call GetProcAddress@KERNEL32.DLL
0x0040ac06:	xorl %eax, 0x4269f0
0x0040ac0c:	popl %edi
0x0040ac0d:	movl 0x428c80, %eax
0x0040ac12:	popl %esi
0x0040ac13:	ret

0x0040a576:	call 0x0040a84f
0x0040a84f:	pushl %esi
0x0040a850:	pushl %edi
0x0040a851:	movl %esi, $0x427550<UINT32>
0x0040a856:	movl %edi, $0x427c38<UINT32>
0x0040a85b:	cmpl 0x4(%esi), $0x1<UINT8>
0x0040a85f:	jne 22
0x0040a861:	pushl $0x0<UINT8>
0x0040a863:	movl (%esi), %edi
0x0040a865:	addl %edi, $0x18<UINT8>
0x0040a868:	pushl $0xfa0<UINT32>
0x0040a86d:	pushl (%esi)
0x0040a86f:	call 0x0040a91b
0x0040a91b:	pushl %ebp
0x0040a91c:	movl %ebp, %esp
0x0040a91e:	movl %eax, 0x428c10
0x0040a923:	xorl %eax, 0x4269f0
0x0040a929:	je 13
0x0040a92b:	pushl 0x10(%ebp)
0x0040a92e:	pushl 0xc(%ebp)
0x0040a931:	pushl 0x8(%ebp)
0x0040a934:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x0040a936:	popl %ebp
0x0040a937:	ret

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
