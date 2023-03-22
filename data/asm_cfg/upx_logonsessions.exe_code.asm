0x0043afd0:	pusha
0x0043afd1:	movl %esi, $0x425000<UINT32>
0x0043afd6:	leal %edi, -147456(%esi)
0x0043afdc:	pushl %edi
0x0043afdd:	jmp 0x0043afea
0x0043afea:	movl %ebx, (%esi)
0x0043afec:	subl %esi, $0xfffffffc<UINT8>
0x0043afef:	adcl %ebx, %ebx
0x0043aff1:	jb 0x0043afe0
0x0043afe0:	movb %al, (%esi)
0x0043afe2:	incl %esi
0x0043afe3:	movb (%edi), %al
0x0043afe5:	incl %edi
0x0043afe6:	addl %ebx, %ebx
0x0043afe8:	jne 0x0043aff1
0x0043aff3:	movl %eax, $0x1<UINT32>
0x0043aff8:	addl %ebx, %ebx
0x0043affa:	jne 0x0043b003
0x0043b003:	adcl %eax, %eax
0x0043b005:	addl %ebx, %ebx
0x0043b007:	jae 0x0043aff8
0x0043b009:	jne 0x0043b014
0x0043b014:	xorl %ecx, %ecx
0x0043b016:	subl %eax, $0x3<UINT8>
0x0043b019:	jb 0x0043b028
0x0043b01b:	shll %eax, $0x8<UINT8>
0x0043b01e:	movb %al, (%esi)
0x0043b020:	incl %esi
0x0043b021:	xorl %eax, $0xffffffff<UINT8>
0x0043b024:	je 0x0043b09a
0x0043b026:	movl %ebp, %eax
0x0043b028:	addl %ebx, %ebx
0x0043b02a:	jne 0x0043b033
0x0043b033:	adcl %ecx, %ecx
0x0043b035:	addl %ebx, %ebx
0x0043b037:	jne 0x0043b040
0x0043b040:	adcl %ecx, %ecx
0x0043b042:	jne 0x0043b064
0x0043b064:	cmpl %ebp, $0xfffff300<UINT32>
0x0043b06a:	adcl %ecx, $0x1<UINT8>
0x0043b06d:	leal %edx, (%edi,%ebp)
0x0043b070:	cmpl %ebp, $0xfffffffc<UINT8>
0x0043b073:	jbe 0x0043b084
0x0043b084:	movl %eax, (%edx)
0x0043b086:	addl %edx, $0x4<UINT8>
0x0043b089:	movl (%edi), %eax
0x0043b08b:	addl %edi, $0x4<UINT8>
0x0043b08e:	subl %ecx, $0x4<UINT8>
0x0043b091:	ja 0x0043b084
0x0043b093:	addl %edi, %ecx
0x0043b095:	jmp 0x0043afe6
0x0043b075:	movb %al, (%edx)
0x0043b077:	incl %edx
0x0043b078:	movb (%edi), %al
0x0043b07a:	incl %edi
0x0043b07b:	decl %ecx
0x0043b07c:	jne 0x0043b075
0x0043b07e:	jmp 0x0043afe6
0x0043b00b:	movl %ebx, (%esi)
0x0043b00d:	subl %esi, $0xfffffffc<UINT8>
0x0043b010:	adcl %ebx, %ebx
0x0043b012:	jae 0x0043aff8
0x0043b044:	incl %ecx
0x0043b045:	addl %ebx, %ebx
0x0043b047:	jne 0x0043b050
0x0043b050:	adcl %ecx, %ecx
0x0043b052:	addl %ebx, %ebx
0x0043b054:	jae 0x0043b045
0x0043b056:	jne 0x0043b061
0x0043b061:	addl %ecx, $0x2<UINT8>
0x0043b058:	movl %ebx, (%esi)
0x0043b05a:	subl %esi, $0xfffffffc<UINT8>
0x0043b05d:	adcl %ebx, %ebx
0x0043b05f:	jae 0x0043b045
0x0043b039:	movl %ebx, (%esi)
0x0043b03b:	subl %esi, $0xfffffffc<UINT8>
0x0043b03e:	adcl %ebx, %ebx
0x0043b049:	movl %ebx, (%esi)
0x0043b04b:	subl %esi, $0xfffffffc<UINT8>
0x0043b04e:	adcl %ebx, %ebx
0x0043b02c:	movl %ebx, (%esi)
0x0043b02e:	subl %esi, $0xfffffffc<UINT8>
0x0043b031:	adcl %ebx, %ebx
0x0043affc:	movl %ebx, (%esi)
0x0043affe:	subl %esi, $0xfffffffc<UINT8>
0x0043b001:	adcl %ebx, %ebx
0x0043b09a:	popl %esi
0x0043b09b:	movl %edi, %esi
0x0043b09d:	movl %ecx, $0x775<UINT32>
0x0043b0a2:	movb %al, (%edi)
0x0043b0a4:	incl %edi
0x0043b0a5:	subb %al, $0xffffffe8<UINT8>
0x0043b0a7:	cmpb %al, $0x1<UINT8>
0x0043b0a9:	ja 0x0043b0a2
0x0043b0ab:	cmpb (%edi), $0x5<UINT8>
0x0043b0ae:	jne 0x0043b0a2
0x0043b0b0:	movl %eax, (%edi)
0x0043b0b2:	movb %bl, 0x4(%edi)
0x0043b0b5:	shrw %ax, $0x8<UINT8>
0x0043b0b9:	roll %eax, $0x10<UINT8>
0x0043b0bc:	xchgb %ah, %al
0x0043b0be:	subl %eax, %edi
0x0043b0c0:	subb %bl, $0xffffffe8<UINT8>
0x0043b0c3:	addl %eax, %esi
0x0043b0c5:	movl (%edi), %eax
0x0043b0c7:	addl %edi, $0x5<UINT8>
0x0043b0ca:	movb %al, %bl
0x0043b0cc:	loop 0x0043b0a7
0x0043b0ce:	leal %edi, 0x37000(%esi)
0x0043b0d4:	movl %eax, (%edi)
0x0043b0d6:	orl %eax, %eax
0x0043b0d8:	je 0x0043b11f
0x0043b0da:	movl %ebx, 0x4(%edi)
0x0043b0dd:	leal %eax, 0x3b638(%eax,%esi)
0x0043b0e4:	addl %ebx, %esi
0x0043b0e6:	pushl %eax
0x0043b0e7:	addl %edi, $0x8<UINT8>
0x0043b0ea:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0043b0f0:	xchgl %ebp, %eax
0x0043b0f1:	movb %al, (%edi)
0x0043b0f3:	incl %edi
0x0043b0f4:	orb %al, %al
0x0043b0f6:	je 0x0043b0d4
0x0043b0f8:	movl %ecx, %edi
0x0043b0fa:	jns 0x0043b103
0x0043b103:	pushl %edi
0x0043b104:	decl %eax
0x0043b105:	repn scasb %al, %es:(%edi)
0x0043b107:	pushl %ebp
0x0043b108:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0043b10e:	orl %eax, %eax
0x0043b110:	je 7
0x0043b112:	movl (%ebx), %eax
0x0043b114:	addl %ebx, $0x4<UINT8>
0x0043b117:	jmp 0x0043b0f1
GetProcAddress@KERNEL32.DLL: API Node	
0x0043b0fc:	movzwl %eax, (%edi)
0x0043b0ff:	incl %edi
0x0043b100:	pushl %eax
0x0043b101:	incl %edi
0x0043b102:	movl %ecx, $0xaef24857<UINT32>
0x0043b11f:	addl %edi, $0x4<UINT8>
0x0043b122:	leal %ebx, -4(%esi)
0x0043b125:	xorl %eax, %eax
0x0043b127:	movb %al, (%edi)
0x0043b129:	incl %edi
0x0043b12a:	orl %eax, %eax
0x0043b12c:	je 0x0043b150
0x0043b12e:	cmpb %al, $0xffffffef<UINT8>
0x0043b130:	ja 0x0043b143
0x0043b132:	addl %ebx, %eax
0x0043b134:	movl %eax, (%ebx)
0x0043b136:	xchgb %ah, %al
0x0043b138:	roll %eax, $0x10<UINT8>
0x0043b13b:	xchgb %ah, %al
0x0043b13d:	addl %eax, %esi
0x0043b13f:	movl (%ebx), %eax
0x0043b141:	jmp 0x0043b125
0x0043b143:	andb %al, $0xf<UINT8>
0x0043b145:	shll %eax, $0x10<UINT8>
0x0043b148:	movw %ax, (%edi)
0x0043b14b:	addl %edi, $0x2<UINT8>
0x0043b14e:	jmp 0x0043b132
0x0043b150:	movl %ebp, 0x3b710(%esi)
0x0043b156:	leal %edi, -4096(%esi)
0x0043b15c:	movl %ebx, $0x1000<UINT32>
0x0043b161:	pushl %eax
0x0043b162:	pushl %esp
0x0043b163:	pushl $0x4<UINT8>
0x0043b165:	pushl %ebx
0x0043b166:	pushl %edi
0x0043b167:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0043b169:	leal %eax, 0x217(%edi)
0x0043b16f:	andb (%eax), $0x7f<UINT8>
0x0043b172:	andb 0x28(%eax), $0x7f<UINT8>
0x0043b176:	popl %eax
0x0043b177:	pushl %eax
0x0043b178:	pushl %esp
0x0043b179:	pushl %eax
0x0043b17a:	pushl %ebx
0x0043b17b:	pushl %edi
0x0043b17c:	call VirtualProtect@kernel32.dll
0x0043b17e:	popl %eax
0x0043b17f:	popa
0x0043b180:	leal %eax, -128(%esp)
0x0043b184:	pushl $0x0<UINT8>
0x0043b186:	cmpl %esp, %eax
0x0043b188:	jne 0x0043b184
0x0043b18a:	subl %esp, $0xffffff80<UINT8>
0x0043b18d:	jmp 0x00405f5b
0x00405f5b:	call 0x0040e5f5
0x0040e5f5:	pushl %ebp
0x0040e5f6:	movl %ebp, %esp
0x0040e5f8:	subl %esp, $0x14<UINT8>
0x0040e5fb:	andl -12(%ebp), $0x0<UINT8>
0x0040e5ff:	andl -8(%ebp), $0x0<UINT8>
0x0040e603:	movl %eax, 0x4220d0
0x0040e608:	pushl %esi
0x0040e609:	pushl %edi
0x0040e60a:	movl %edi, $0xbb40e64e<UINT32>
0x0040e60f:	movl %esi, $0xffff0000<UINT32>
0x0040e614:	cmpl %eax, %edi
0x0040e616:	je 0x0040e625
0x0040e625:	leal %eax, -12(%ebp)
0x0040e628:	pushl %eax
0x0040e629:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040e62f:	movl %eax, -8(%ebp)
0x0040e632:	xorl %eax, -12(%ebp)
0x0040e635:	movl -4(%ebp), %eax
0x0040e638:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040e63e:	xorl -4(%ebp), %eax
0x0040e641:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040e647:	xorl -4(%ebp), %eax
0x0040e64a:	leal %eax, -20(%ebp)
0x0040e64d:	pushl %eax
0x0040e64e:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040e654:	movl %ecx, -16(%ebp)
0x0040e657:	leal %eax, -4(%ebp)
0x0040e65a:	xorl %ecx, -20(%ebp)
0x0040e65d:	xorl %ecx, -4(%ebp)
0x0040e660:	xorl %ecx, %eax
0x0040e662:	cmpl %ecx, %edi
0x0040e664:	jne 0x0040e66d
0x0040e66d:	testl %esi, %ecx
0x0040e66f:	jne 0x0040e67d
0x0040e67d:	movl 0x4220d0, %ecx
0x0040e683:	notl %ecx
0x0040e685:	movl 0x4220d4, %ecx
0x0040e68b:	popl %edi
0x0040e68c:	popl %esi
0x0040e68d:	movl %esp, %ebp
0x0040e68f:	popl %ebp
0x0040e690:	ret

0x00405f60:	jmp 0x00405de0
0x00405de0:	pushl $0x14<UINT8>
0x00405de2:	pushl $0x420ef8<UINT32>
0x00405de7:	call 0x00407fb0
0x00407fb0:	pushl $0x408010<UINT32>
0x00407fb5:	pushl %fs:0
0x00407fbc:	movl %eax, 0x10(%esp)
0x00407fc0:	movl 0x10(%esp), %ebp
0x00407fc4:	leal %ebp, 0x10(%esp)
0x00407fc8:	subl %esp, %eax
0x00407fca:	pushl %ebx
0x00407fcb:	pushl %esi
0x00407fcc:	pushl %edi
0x00407fcd:	movl %eax, 0x4220d0
0x00407fd2:	xorl -4(%ebp), %eax
0x00407fd5:	xorl %eax, %ebp
0x00407fd7:	pushl %eax
0x00407fd8:	movl -24(%ebp), %esp
0x00407fdb:	pushl -8(%ebp)
0x00407fde:	movl %eax, -4(%ebp)
0x00407fe1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00407fe8:	movl -8(%ebp), %eax
0x00407feb:	leal %eax, -16(%ebp)
0x00407fee:	movl %fs:0, %eax
0x00407ff4:	ret

0x00405dec:	pushl $0x1<UINT8>
0x00405dee:	call 0x0040e5a8
0x0040e5a8:	pushl %ebp
0x0040e5a9:	movl %ebp, %esp
0x0040e5ab:	movl %eax, 0x8(%ebp)
0x0040e5ae:	movl 0x4236c8, %eax
0x0040e5b3:	popl %ebp
0x0040e5b4:	ret

0x00405df3:	popl %ecx
0x00405df4:	movl %eax, $0x5a4d<UINT32>
0x00405df9:	cmpw 0x400000, %ax
0x00405e00:	je 0x00405e06
0x00405e06:	movl %eax, 0x40003c
0x00405e0b:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00405e15:	jne -21
0x00405e17:	movl %ecx, $0x10b<UINT32>
0x00405e1c:	cmpw 0x400018(%eax), %cx
0x00405e23:	jne -35
0x00405e25:	xorl %ebx, %ebx
0x00405e27:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00405e2e:	jbe 9
0x00405e30:	cmpl 0x4000e8(%eax), %ebx
0x00405e36:	setne %bl
0x00405e39:	movl -28(%ebp), %ebx
0x00405e3c:	call 0x0040a045
0x0040a045:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x0040a04b:	xorl %ecx, %ecx
0x0040a04d:	movl 0x4236c4, %eax
0x0040a052:	testl %eax, %eax
0x0040a054:	setne %cl
0x0040a057:	movl %eax, %ecx
0x0040a059:	ret

0x00405e41:	testl %eax, %eax
0x00405e43:	jne 0x00405e4d
0x00405e4d:	call 0x00409f60
0x00409f60:	call 0x00405264
0x00405264:	pushl %esi
0x00405265:	pushl $0x0<UINT8>
0x00405267:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x0040526d:	movl %esi, %eax
0x0040526f:	pushl %esi
0x00405270:	call 0x00409086
0x00409086:	pushl %ebp
0x00409087:	movl %ebp, %esp
0x00409089:	movl %eax, 0x8(%ebp)
0x0040908c:	movl 0x4236a0, %eax
0x00409091:	popl %ebp
0x00409092:	ret

0x00405275:	pushl %esi
0x00405276:	call 0x0040608a
0x0040608a:	pushl %ebp
0x0040608b:	movl %ebp, %esp
0x0040608d:	movl %eax, 0x8(%ebp)
0x00406090:	movl 0x423378, %eax
0x00406095:	popl %ebp
0x00406096:	ret

0x0040527b:	pushl %esi
0x0040527c:	call 0x0040dc01
0x0040dc01:	pushl %ebp
0x0040dc02:	movl %ebp, %esp
0x0040dc04:	movl %eax, 0x8(%ebp)
0x0040dc07:	movl 0x423f6c, %eax
0x0040dc0c:	popl %ebp
0x0040dc0d:	ret

0x00405281:	pushl %esi
0x00405282:	call 0x0040dc1b
0x0040dc1b:	pushl %ebp
0x0040dc1c:	movl %ebp, %esp
0x0040dc1e:	movl %eax, 0x8(%ebp)
0x0040dc21:	movl 0x423f70, %eax
0x0040dc26:	movl 0x423f74, %eax
0x0040dc2b:	movl 0x423f78, %eax
0x0040dc30:	movl 0x423f7c, %eax
0x0040dc35:	popl %ebp
0x0040dc36:	ret

0x00405287:	pushl %esi
0x00405288:	call 0x0040b78b
0x0040b78b:	pushl $0x40b744<UINT32>
0x0040b790:	call EncodePointer@KERNEL32.DLL
0x0040b796:	movl 0x423f60, %eax
0x0040b79b:	ret

0x0040528d:	pushl %esi
0x0040528e:	call 0x0040de2c
0x0040de2c:	pushl %ebp
0x0040de2d:	movl %ebp, %esp
0x0040de2f:	movl %eax, 0x8(%ebp)
0x0040de32:	movl 0x423f84, %eax
0x0040de37:	popl %ebp
0x0040de38:	ret

0x00405293:	addl %esp, $0x18<UINT8>
0x00405296:	popl %esi
0x00405297:	jmp 0x0040d66e
0x0040d66e:	pushl %esi
0x0040d66f:	pushl %edi
0x0040d670:	pushl $0x41d59c<UINT32>
0x0040d675:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0040d67b:	movl %esi, 0x4150c8
0x0040d681:	movl %edi, %eax
0x0040d683:	pushl $0x41d5b8<UINT32>
0x0040d688:	pushl %edi
0x0040d689:	call GetProcAddress@KERNEL32.DLL
0x0040d68b:	xorl %eax, 0x4220d0
0x0040d691:	pushl $0x41d5c4<UINT32>
0x0040d696:	pushl %edi
0x0040d697:	movl 0x424220, %eax
0x0040d69c:	call GetProcAddress@KERNEL32.DLL
0x0040d69e:	xorl %eax, 0x4220d0
0x0040d6a4:	pushl $0x41d5cc<UINT32>
0x0040d6a9:	pushl %edi
0x0040d6aa:	movl 0x424224, %eax
0x0040d6af:	call GetProcAddress@KERNEL32.DLL
0x0040d6b1:	xorl %eax, 0x4220d0
0x0040d6b7:	pushl $0x41d5d8<UINT32>
0x0040d6bc:	pushl %edi
0x0040d6bd:	movl 0x424228, %eax
0x0040d6c2:	call GetProcAddress@KERNEL32.DLL
0x0040d6c4:	xorl %eax, 0x4220d0
0x0040d6ca:	pushl $0x41d5e4<UINT32>
0x0040d6cf:	pushl %edi
0x0040d6d0:	movl 0x42422c, %eax
0x0040d6d5:	call GetProcAddress@KERNEL32.DLL
0x0040d6d7:	xorl %eax, 0x4220d0
0x0040d6dd:	pushl $0x41d600<UINT32>
0x0040d6e2:	pushl %edi
0x0040d6e3:	movl 0x424230, %eax
0x0040d6e8:	call GetProcAddress@KERNEL32.DLL
0x0040d6ea:	xorl %eax, 0x4220d0
0x0040d6f0:	pushl $0x41d610<UINT32>
0x0040d6f5:	pushl %edi
0x0040d6f6:	movl 0x424234, %eax
0x0040d6fb:	call GetProcAddress@KERNEL32.DLL
0x0040d6fd:	xorl %eax, 0x4220d0
0x0040d703:	pushl $0x41d624<UINT32>
0x0040d708:	pushl %edi
0x0040d709:	movl 0x424238, %eax
0x0040d70e:	call GetProcAddress@KERNEL32.DLL
0x0040d710:	xorl %eax, 0x4220d0
0x0040d716:	pushl $0x41d63c<UINT32>
0x0040d71b:	pushl %edi
0x0040d71c:	movl 0x42423c, %eax
0x0040d721:	call GetProcAddress@KERNEL32.DLL
0x0040d723:	xorl %eax, 0x4220d0
0x0040d729:	pushl $0x41d654<UINT32>
0x0040d72e:	pushl %edi
0x0040d72f:	movl 0x424240, %eax
0x0040d734:	call GetProcAddress@KERNEL32.DLL
0x0040d736:	xorl %eax, 0x4220d0
0x0040d73c:	pushl $0x41d668<UINT32>
0x0040d741:	pushl %edi
0x0040d742:	movl 0x424244, %eax
0x0040d747:	call GetProcAddress@KERNEL32.DLL
0x0040d749:	xorl %eax, 0x4220d0
0x0040d74f:	pushl $0x41d688<UINT32>
0x0040d754:	pushl %edi
0x0040d755:	movl 0x424248, %eax
0x0040d75a:	call GetProcAddress@KERNEL32.DLL
0x0040d75c:	xorl %eax, 0x4220d0
0x0040d762:	pushl $0x41d6a0<UINT32>
0x0040d767:	pushl %edi
0x0040d768:	movl 0x42424c, %eax
0x0040d76d:	call GetProcAddress@KERNEL32.DLL
0x0040d76f:	xorl %eax, 0x4220d0
0x0040d775:	pushl $0x41d6b8<UINT32>
0x0040d77a:	pushl %edi
0x0040d77b:	movl 0x424250, %eax
0x0040d780:	call GetProcAddress@KERNEL32.DLL
0x0040d782:	xorl %eax, 0x4220d0
0x0040d788:	pushl $0x41d6cc<UINT32>
0x0040d78d:	pushl %edi
0x0040d78e:	movl 0x424254, %eax
0x0040d793:	call GetProcAddress@KERNEL32.DLL
0x0040d795:	xorl %eax, 0x4220d0
0x0040d79b:	movl 0x424258, %eax
0x0040d7a0:	pushl $0x41d6e0<UINT32>
0x0040d7a5:	pushl %edi
0x0040d7a6:	call GetProcAddress@KERNEL32.DLL
0x0040d7a8:	xorl %eax, 0x4220d0
0x0040d7ae:	pushl $0x41d6fc<UINT32>
0x0040d7b3:	pushl %edi
0x0040d7b4:	movl 0x42425c, %eax
0x0040d7b9:	call GetProcAddress@KERNEL32.DLL
0x0040d7bb:	xorl %eax, 0x4220d0
0x0040d7c1:	pushl $0x41d71c<UINT32>
0x0040d7c6:	pushl %edi
0x0040d7c7:	movl 0x424260, %eax
0x0040d7cc:	call GetProcAddress@KERNEL32.DLL
0x0040d7ce:	xorl %eax, 0x4220d0
0x0040d7d4:	pushl $0x41d738<UINT32>
0x0040d7d9:	pushl %edi
0x0040d7da:	movl 0x424264, %eax
0x0040d7df:	call GetProcAddress@KERNEL32.DLL
0x0040d7e1:	xorl %eax, 0x4220d0
0x0040d7e7:	pushl $0x41d758<UINT32>
0x0040d7ec:	pushl %edi
0x0040d7ed:	movl 0x424268, %eax
0x0040d7f2:	call GetProcAddress@KERNEL32.DLL
0x0040d7f4:	xorl %eax, 0x4220d0
0x0040d7fa:	pushl $0x41d76c<UINT32>
0x0040d7ff:	pushl %edi
0x0040d800:	movl 0x42426c, %eax
0x0040d805:	call GetProcAddress@KERNEL32.DLL
0x0040d807:	xorl %eax, 0x4220d0
0x0040d80d:	pushl $0x41d788<UINT32>
0x0040d812:	pushl %edi
0x0040d813:	movl 0x424270, %eax
0x0040d818:	call GetProcAddress@KERNEL32.DLL
0x0040d81a:	xorl %eax, 0x4220d0
0x0040d820:	pushl $0x41d79c<UINT32>
0x0040d825:	pushl %edi
0x0040d826:	movl 0x424278, %eax
0x0040d82b:	call GetProcAddress@KERNEL32.DLL
0x0040d82d:	xorl %eax, 0x4220d0
0x0040d833:	pushl $0x41d7ac<UINT32>
0x0040d838:	pushl %edi
0x0040d839:	movl 0x424274, %eax
0x0040d83e:	call GetProcAddress@KERNEL32.DLL
0x0040d840:	xorl %eax, 0x4220d0
0x0040d846:	pushl $0x41d7bc<UINT32>
0x0040d84b:	pushl %edi
0x0040d84c:	movl 0x42427c, %eax
0x0040d851:	call GetProcAddress@KERNEL32.DLL
0x0040d853:	xorl %eax, 0x4220d0
0x0040d859:	pushl $0x41d7cc<UINT32>
0x0040d85e:	pushl %edi
0x0040d85f:	movl 0x424280, %eax
0x0040d864:	call GetProcAddress@KERNEL32.DLL
0x0040d866:	xorl %eax, 0x4220d0
0x0040d86c:	pushl $0x41d7dc<UINT32>
0x0040d871:	pushl %edi
0x0040d872:	movl 0x424284, %eax
0x0040d877:	call GetProcAddress@KERNEL32.DLL
0x0040d879:	xorl %eax, 0x4220d0
0x0040d87f:	pushl $0x41d7f8<UINT32>
0x0040d884:	pushl %edi
0x0040d885:	movl 0x424288, %eax
0x0040d88a:	call GetProcAddress@KERNEL32.DLL
0x0040d88c:	xorl %eax, 0x4220d0
0x0040d892:	pushl $0x41d80c<UINT32>
0x0040d897:	pushl %edi
0x0040d898:	movl 0x42428c, %eax
0x0040d89d:	call GetProcAddress@KERNEL32.DLL
0x0040d89f:	xorl %eax, 0x4220d0
0x0040d8a5:	pushl $0x41d81c<UINT32>
0x0040d8aa:	pushl %edi
0x0040d8ab:	movl 0x424290, %eax
0x0040d8b0:	call GetProcAddress@KERNEL32.DLL
0x0040d8b2:	xorl %eax, 0x4220d0
0x0040d8b8:	pushl $0x41d830<UINT32>
0x0040d8bd:	pushl %edi
0x0040d8be:	movl 0x424294, %eax
0x0040d8c3:	call GetProcAddress@KERNEL32.DLL
0x0040d8c5:	xorl %eax, 0x4220d0
0x0040d8cb:	movl 0x424298, %eax
0x0040d8d0:	pushl $0x41d840<UINT32>
0x0040d8d5:	pushl %edi
0x0040d8d6:	call GetProcAddress@KERNEL32.DLL
0x0040d8d8:	xorl %eax, 0x4220d0
0x0040d8de:	pushl $0x41d860<UINT32>
0x0040d8e3:	pushl %edi
0x0040d8e4:	movl 0x42429c, %eax
0x0040d8e9:	call GetProcAddress@KERNEL32.DLL
0x0040d8eb:	xorl %eax, 0x4220d0
0x0040d8f1:	popl %edi
0x0040d8f2:	movl 0x4242a0, %eax
0x0040d8f7:	popl %esi
0x0040d8f8:	ret

0x00409f65:	call 0x0040a442
0x0040a442:	pushl %esi
0x0040a443:	pushl %edi
0x0040a444:	movl %esi, $0x422c38<UINT32>
0x0040a449:	movl %edi, $0x423d00<UINT32>
0x0040a44e:	cmpl 0x4(%esi), $0x1<UINT8>
0x0040a452:	jne 22
0x0040a454:	pushl $0x0<UINT8>
0x0040a456:	movl (%esi), %edi
0x0040a458:	addl %edi, $0x18<UINT8>
0x0040a45b:	pushl $0xfa0<UINT32>
0x0040a460:	pushl (%esi)
0x0040a462:	call 0x0040d600
0x0040d600:	pushl %ebp
0x0040d601:	movl %ebp, %esp
0x0040d603:	movl %eax, 0x424230
0x0040d608:	xorl %eax, 0x4220d0
0x0040d60e:	je 13
0x0040d610:	pushl 0x10(%ebp)
0x0040d613:	pushl 0xc(%ebp)
0x0040d616:	pushl 0x8(%ebp)
0x0040d619:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x0040d61b:	popl %ebp
0x0040d61c:	ret

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
