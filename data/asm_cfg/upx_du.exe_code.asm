0x0042d0a0:	pusha
0x0042d0a1:	movl %esi, $0x41d000<UINT32>
0x0042d0a6:	leal %edi, -114688(%esi)
0x0042d0ac:	pushl %edi
0x0042d0ad:	jmp 0x0042d0ba
0x0042d0ba:	movl %ebx, (%esi)
0x0042d0bc:	subl %esi, $0xfffffffc<UINT8>
0x0042d0bf:	adcl %ebx, %ebx
0x0042d0c1:	jb 0x0042d0b0
0x0042d0b0:	movb %al, (%esi)
0x0042d0b2:	incl %esi
0x0042d0b3:	movb (%edi), %al
0x0042d0b5:	incl %edi
0x0042d0b6:	addl %ebx, %ebx
0x0042d0b8:	jne 0x0042d0c1
0x0042d0c3:	movl %eax, $0x1<UINT32>
0x0042d0c8:	addl %ebx, %ebx
0x0042d0ca:	jne 0x0042d0d3
0x0042d0d3:	adcl %eax, %eax
0x0042d0d5:	addl %ebx, %ebx
0x0042d0d7:	jae 0x0042d0c8
0x0042d0d9:	jne 0x0042d0e4
0x0042d0e4:	xorl %ecx, %ecx
0x0042d0e6:	subl %eax, $0x3<UINT8>
0x0042d0e9:	jb 0x0042d0f8
0x0042d0eb:	shll %eax, $0x8<UINT8>
0x0042d0ee:	movb %al, (%esi)
0x0042d0f0:	incl %esi
0x0042d0f1:	xorl %eax, $0xffffffff<UINT8>
0x0042d0f4:	je 0x0042d16a
0x0042d0f6:	movl %ebp, %eax
0x0042d0f8:	addl %ebx, %ebx
0x0042d0fa:	jne 0x0042d103
0x0042d103:	adcl %ecx, %ecx
0x0042d105:	addl %ebx, %ebx
0x0042d107:	jne 0x0042d110
0x0042d110:	adcl %ecx, %ecx
0x0042d112:	jne 0x0042d134
0x0042d114:	incl %ecx
0x0042d115:	addl %ebx, %ebx
0x0042d117:	jne 0x0042d120
0x0042d120:	adcl %ecx, %ecx
0x0042d122:	addl %ebx, %ebx
0x0042d124:	jae 0x0042d115
0x0042d126:	jne 0x0042d131
0x0042d131:	addl %ecx, $0x2<UINT8>
0x0042d134:	cmpl %ebp, $0xfffff300<UINT32>
0x0042d13a:	adcl %ecx, $0x1<UINT8>
0x0042d13d:	leal %edx, (%edi,%ebp)
0x0042d140:	cmpl %ebp, $0xfffffffc<UINT8>
0x0042d143:	jbe 0x0042d154
0x0042d154:	movl %eax, (%edx)
0x0042d156:	addl %edx, $0x4<UINT8>
0x0042d159:	movl (%edi), %eax
0x0042d15b:	addl %edi, $0x4<UINT8>
0x0042d15e:	subl %ecx, $0x4<UINT8>
0x0042d161:	ja 0x0042d154
0x0042d163:	addl %edi, %ecx
0x0042d165:	jmp 0x0042d0b6
0x0042d0fc:	movl %ebx, (%esi)
0x0042d0fe:	subl %esi, $0xfffffffc<UINT8>
0x0042d101:	adcl %ebx, %ebx
0x0042d119:	movl %ebx, (%esi)
0x0042d11b:	subl %esi, $0xfffffffc<UINT8>
0x0042d11e:	adcl %ebx, %ebx
0x0042d145:	movb %al, (%edx)
0x0042d147:	incl %edx
0x0042d148:	movb (%edi), %al
0x0042d14a:	incl %edi
0x0042d14b:	decl %ecx
0x0042d14c:	jne 0x0042d145
0x0042d14e:	jmp 0x0042d0b6
0x0042d0db:	movl %ebx, (%esi)
0x0042d0dd:	subl %esi, $0xfffffffc<UINT8>
0x0042d0e0:	adcl %ebx, %ebx
0x0042d0e2:	jae 0x0042d0c8
0x0042d128:	movl %ebx, (%esi)
0x0042d12a:	subl %esi, $0xfffffffc<UINT8>
0x0042d12d:	adcl %ebx, %ebx
0x0042d12f:	jae 0x0042d115
0x0042d0cc:	movl %ebx, (%esi)
0x0042d0ce:	subl %esi, $0xfffffffc<UINT8>
0x0042d0d1:	adcl %ebx, %ebx
0x0042d109:	movl %ebx, (%esi)
0x0042d10b:	subl %esi, $0xfffffffc<UINT8>
0x0042d10e:	adcl %ebx, %ebx
0x0042d16a:	popl %esi
0x0042d16b:	movl %edi, %esi
0x0042d16d:	movl %ecx, $0x75f<UINT32>
0x0042d172:	movb %al, (%edi)
0x0042d174:	incl %edi
0x0042d175:	subb %al, $0xffffffe8<UINT8>
0x0042d177:	cmpb %al, $0x1<UINT8>
0x0042d179:	ja 0x0042d172
0x0042d17b:	cmpb (%edi), $0x9<UINT8>
0x0042d17e:	jne 0x0042d172
0x0042d180:	movl %eax, (%edi)
0x0042d182:	movb %bl, 0x4(%edi)
0x0042d185:	shrw %ax, $0x8<UINT8>
0x0042d189:	roll %eax, $0x10<UINT8>
0x0042d18c:	xchgb %ah, %al
0x0042d18e:	subl %eax, %edi
0x0042d190:	subb %bl, $0xffffffe8<UINT8>
0x0042d193:	addl %eax, %esi
0x0042d195:	movl (%edi), %eax
0x0042d197:	addl %edi, $0x5<UINT8>
0x0042d19a:	movb %al, %bl
0x0042d19c:	loop 0x0042d177
0x0042d19e:	leal %edi, 0x2a000(%esi)
0x0042d1a4:	movl %eax, (%edi)
0x0042d1a6:	orl %eax, %eax
0x0042d1a8:	je 0x0042d1e6
0x0042d1aa:	movl %ebx, 0x4(%edi)
0x0042d1ad:	leal %eax, 0x2d544(%eax,%esi)
0x0042d1b4:	addl %ebx, %esi
0x0042d1b6:	pushl %eax
0x0042d1b7:	addl %edi, $0x8<UINT8>
0x0042d1ba:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0042d1c0:	xchgl %ebp, %eax
0x0042d1c1:	movb %al, (%edi)
0x0042d1c3:	incl %edi
0x0042d1c4:	orb %al, %al
0x0042d1c6:	je 0x0042d1a4
0x0042d1c8:	movl %ecx, %edi
0x0042d1ca:	pushl %edi
0x0042d1cb:	decl %eax
0x0042d1cc:	repn scasb %al, %es:(%edi)
0x0042d1ce:	pushl %ebp
0x0042d1cf:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0042d1d5:	orl %eax, %eax
0x0042d1d7:	je 7
0x0042d1d9:	movl (%ebx), %eax
0x0042d1db:	addl %ebx, $0x4<UINT8>
0x0042d1de:	jmp 0x0042d1c1
GetProcAddress@KERNEL32.DLL: API Node	
0x0042d1e6:	addl %edi, $0x4<UINT8>
0x0042d1e9:	leal %ebx, -4(%esi)
0x0042d1ec:	xorl %eax, %eax
0x0042d1ee:	movb %al, (%edi)
0x0042d1f0:	incl %edi
0x0042d1f1:	orl %eax, %eax
0x0042d1f3:	je 0x0042d217
0x0042d1f5:	cmpb %al, $0xffffffef<UINT8>
0x0042d1f7:	ja 0x0042d20a
0x0042d1f9:	addl %ebx, %eax
0x0042d1fb:	movl %eax, (%ebx)
0x0042d1fd:	xchgb %ah, %al
0x0042d1ff:	roll %eax, $0x10<UINT8>
0x0042d202:	xchgb %ah, %al
0x0042d204:	addl %eax, %esi
0x0042d206:	movl (%ebx), %eax
0x0042d208:	jmp 0x0042d1ec
0x0042d20a:	andb %al, $0xf<UINT8>
0x0042d20c:	shll %eax, $0x10<UINT8>
0x0042d20f:	movw %ax, (%edi)
0x0042d212:	addl %edi, $0x2<UINT8>
0x0042d215:	jmp 0x0042d1f9
0x0042d217:	movl %ebp, 0x2d5f4(%esi)
0x0042d21d:	leal %edi, -4096(%esi)
0x0042d223:	movl %ebx, $0x1000<UINT32>
0x0042d228:	pushl %eax
0x0042d229:	pushl %esp
0x0042d22a:	pushl $0x4<UINT8>
0x0042d22c:	pushl %ebx
0x0042d22d:	pushl %edi
0x0042d22e:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0042d230:	leal %eax, 0x217(%edi)
0x0042d236:	andb (%eax), $0x7f<UINT8>
0x0042d239:	andb 0x28(%eax), $0x7f<UINT8>
0x0042d23d:	popl %eax
0x0042d23e:	pushl %eax
0x0042d23f:	pushl %esp
0x0042d240:	pushl %eax
0x0042d241:	pushl %ebx
0x0042d242:	pushl %edi
0x0042d243:	call VirtualProtect@kernel32.dll
0x0042d245:	popl %eax
0x0042d246:	popa
0x0042d247:	leal %eax, -128(%esp)
0x0042d24b:	pushl $0x0<UINT8>
0x0042d24d:	cmpl %esp, %eax
0x0042d24f:	jne 0x0042d24b
0x0042d251:	subl %esp, $0xffffff80<UINT8>
0x0042d254:	jmp 0x004068c9
0x004068c9:	call 0x0040e5f0
0x0040e5f0:	pushl %ebp
0x0040e5f1:	movl %ebp, %esp
0x0040e5f3:	subl %esp, $0x14<UINT8>
0x0040e5f6:	andl -12(%ebp), $0x0<UINT8>
0x0040e5fa:	andl -8(%ebp), $0x0<UINT8>
0x0040e5fe:	movl %eax, 0x424100
0x0040e603:	pushl %esi
0x0040e604:	pushl %edi
0x0040e605:	movl %edi, $0xbb40e64e<UINT32>
0x0040e60a:	movl %esi, $0xffff0000<UINT32>
0x0040e60f:	cmpl %eax, %edi
0x0040e611:	je 0x0040e620
0x0040e620:	leal %eax, -12(%ebp)
0x0040e623:	pushl %eax
0x0040e624:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040e62a:	movl %eax, -8(%ebp)
0x0040e62d:	xorl %eax, -12(%ebp)
0x0040e630:	movl -4(%ebp), %eax
0x0040e633:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040e639:	xorl -4(%ebp), %eax
0x0040e63c:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040e642:	xorl -4(%ebp), %eax
0x0040e645:	leal %eax, -20(%ebp)
0x0040e648:	pushl %eax
0x0040e649:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040e64f:	movl %ecx, -16(%ebp)
0x0040e652:	leal %eax, -4(%ebp)
0x0040e655:	xorl %ecx, -20(%ebp)
0x0040e658:	xorl %ecx, -4(%ebp)
0x0040e65b:	xorl %ecx, %eax
0x0040e65d:	cmpl %ecx, %edi
0x0040e65f:	jne 0x0040e668
0x0040e668:	testl %esi, %ecx
0x0040e66a:	jne 0x0040e678
0x0040e678:	movl 0x424100, %ecx
0x0040e67e:	notl %ecx
0x0040e680:	movl 0x424104, %ecx
0x0040e686:	popl %edi
0x0040e687:	popl %esi
0x0040e688:	movl %esp, %ebp
0x0040e68a:	popl %ebp
0x0040e68b:	ret

0x004068ce:	jmp 0x0040674e
0x0040674e:	pushl $0x14<UINT8>
0x00406750:	pushl $0x422e80<UINT32>
0x00406755:	call 0x00408620
0x00408620:	pushl $0x408680<UINT32>
0x00408625:	pushl %fs:0
0x0040862c:	movl %eax, 0x10(%esp)
0x00408630:	movl 0x10(%esp), %ebp
0x00408634:	leal %ebp, 0x10(%esp)
0x00408638:	subl %esp, %eax
0x0040863a:	pushl %ebx
0x0040863b:	pushl %esi
0x0040863c:	pushl %edi
0x0040863d:	movl %eax, 0x424100
0x00408642:	xorl -4(%ebp), %eax
0x00408645:	xorl %eax, %ebp
0x00408647:	pushl %eax
0x00408648:	movl -24(%ebp), %esp
0x0040864b:	pushl -8(%ebp)
0x0040864e:	movl %eax, -4(%ebp)
0x00408651:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00408658:	movl -8(%ebp), %eax
0x0040865b:	leal %eax, -16(%ebp)
0x0040865e:	movl %fs:0, %eax
0x00408664:	ret

0x0040675a:	pushl $0x1<UINT8>
0x0040675c:	call 0x0040e5a3
0x0040e5a3:	pushl %ebp
0x0040e5a4:	movl %ebp, %esp
0x0040e5a6:	movl %eax, 0x8(%ebp)
0x0040e5a9:	movl 0x425aa8, %eax
0x0040e5ae:	popl %ebp
0x0040e5af:	ret

0x00406761:	popl %ecx
0x00406762:	movl %eax, $0x5a4d<UINT32>
0x00406767:	cmpw 0x400000, %ax
0x0040676e:	je 0x00406774
0x00406774:	movl %eax, 0x40003c
0x00406779:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00406783:	jne -21
0x00406785:	movl %ecx, $0x10b<UINT32>
0x0040678a:	cmpw 0x400018(%eax), %cx
0x00406791:	jne -35
0x00406793:	xorl %ebx, %ebx
0x00406795:	cmpl 0x400074(%eax), $0xe<UINT8>
0x0040679c:	jbe 9
0x0040679e:	cmpl 0x4000e8(%eax), %ebx
0x004067a4:	setne %bl
0x004067a7:	movl -28(%ebp), %ebx
0x004067aa:	call 0x004088eb
0x004088eb:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x004088f1:	xorl %ecx, %ecx
0x004088f3:	movl 0x426108, %eax
0x004088f8:	testl %eax, %eax
0x004088fa:	setne %cl
0x004088fd:	movl %eax, %ecx
0x004088ff:	ret

0x004067af:	testl %eax, %eax
0x004067b1:	jne 0x004067bb
0x004067bb:	call 0x004077d5
0x004077d5:	call 0x0040417e
0x0040417e:	pushl %esi
0x0040417f:	pushl $0x0<UINT8>
0x00404181:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00404187:	movl %esi, %eax
0x00404189:	pushl %esi
0x0040418a:	call 0x004083cf
0x004083cf:	pushl %ebp
0x004083d0:	movl %ebp, %esp
0x004083d2:	movl %eax, 0x8(%ebp)
0x004083d5:	movl 0x4260e0, %eax
0x004083da:	popl %ebp
0x004083db:	ret

0x0040418f:	pushl %esi
0x00404190:	call 0x004069f8
0x004069f8:	pushl %ebp
0x004069f9:	movl %ebp, %esp
0x004069fb:	movl %eax, 0x8(%ebp)
0x004069fe:	movl 0x425934, %eax
0x00406a03:	popl %ebp
0x00406a04:	ret

0x00404195:	pushl %esi
0x00404196:	call 0x004083dc
0x004083dc:	pushl %ebp
0x004083dd:	movl %ebp, %esp
0x004083df:	movl %eax, 0x8(%ebp)
0x004083e2:	movl 0x4260e4, %eax
0x004083e7:	popl %ebp
0x004083e8:	ret

0x0040419b:	pushl %esi
0x0040419c:	call 0x004083f6
0x004083f6:	pushl %ebp
0x004083f7:	movl %ebp, %esp
0x004083f9:	movl %eax, 0x8(%ebp)
0x004083fc:	movl 0x4260e8, %eax
0x00408401:	movl 0x4260ec, %eax
0x00408406:	movl 0x4260f0, %eax
0x0040840b:	movl 0x4260f4, %eax
0x00408410:	popl %ebp
0x00408411:	ret

0x004041a1:	pushl %esi
0x004041a2:	call 0x00408398
0x00408398:	pushl $0x408351<UINT32>
0x0040839d:	call EncodePointer@KERNEL32.DLL
0x004083a3:	movl 0x4260dc, %eax
0x004083a8:	ret

0x004041a7:	pushl %esi
0x004041a8:	call 0x00408607
0x00408607:	pushl %ebp
0x00408608:	movl %ebp, %esp
0x0040860a:	movl %eax, 0x8(%ebp)
0x0040860d:	movl 0x4260fc, %eax
0x00408612:	popl %ebp
0x00408613:	ret

0x004041ad:	addl %esp, $0x18<UINT8>
0x004041b0:	popl %esi
0x004041b1:	jmp 0x00407bed
0x00407bed:	pushl %esi
0x00407bee:	pushl %edi
0x00407bef:	pushl $0x41d968<UINT32>
0x00407bf4:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00407bfa:	movl %esi, 0x4160ac
0x00407c00:	movl %edi, %eax
0x00407c02:	pushl $0x41d984<UINT32>
0x00407c07:	pushl %edi
0x00407c08:	call GetProcAddress@KERNEL32.DLL
0x00407c0a:	xorl %eax, 0x424100
0x00407c10:	pushl $0x41d990<UINT32>
0x00407c15:	pushl %edi
0x00407c16:	movl 0x4264c0, %eax
0x00407c1b:	call GetProcAddress@KERNEL32.DLL
0x00407c1d:	xorl %eax, 0x424100
0x00407c23:	pushl $0x41d998<UINT32>
0x00407c28:	pushl %edi
0x00407c29:	movl 0x4264c4, %eax
0x00407c2e:	call GetProcAddress@KERNEL32.DLL
0x00407c30:	xorl %eax, 0x424100
0x00407c36:	pushl $0x41d9a4<UINT32>
0x00407c3b:	pushl %edi
0x00407c3c:	movl 0x4264c8, %eax
0x00407c41:	call GetProcAddress@KERNEL32.DLL
0x00407c43:	xorl %eax, 0x424100
0x00407c49:	pushl $0x41d9b0<UINT32>
0x00407c4e:	pushl %edi
0x00407c4f:	movl 0x4264cc, %eax
0x00407c54:	call GetProcAddress@KERNEL32.DLL
0x00407c56:	xorl %eax, 0x424100
0x00407c5c:	pushl $0x41d9cc<UINT32>
0x00407c61:	pushl %edi
0x00407c62:	movl 0x4264d0, %eax
0x00407c67:	call GetProcAddress@KERNEL32.DLL
0x00407c69:	xorl %eax, 0x424100
0x00407c6f:	pushl $0x41d9dc<UINT32>
0x00407c74:	pushl %edi
0x00407c75:	movl 0x4264d4, %eax
0x00407c7a:	call GetProcAddress@KERNEL32.DLL
0x00407c7c:	xorl %eax, 0x424100
0x00407c82:	pushl $0x41d9f0<UINT32>
0x00407c87:	pushl %edi
0x00407c88:	movl 0x4264d8, %eax
0x00407c8d:	call GetProcAddress@KERNEL32.DLL
0x00407c8f:	xorl %eax, 0x424100
0x00407c95:	pushl $0x41da08<UINT32>
0x00407c9a:	pushl %edi
0x00407c9b:	movl 0x4264dc, %eax
0x00407ca0:	call GetProcAddress@KERNEL32.DLL
0x00407ca2:	xorl %eax, 0x424100
0x00407ca8:	pushl $0x41da20<UINT32>
0x00407cad:	pushl %edi
0x00407cae:	movl 0x4264e0, %eax
0x00407cb3:	call GetProcAddress@KERNEL32.DLL
0x00407cb5:	xorl %eax, 0x424100
0x00407cbb:	pushl $0x41da34<UINT32>
0x00407cc0:	pushl %edi
0x00407cc1:	movl 0x4264e4, %eax
0x00407cc6:	call GetProcAddress@KERNEL32.DLL
0x00407cc8:	xorl %eax, 0x424100
0x00407cce:	pushl $0x41da54<UINT32>
0x00407cd3:	pushl %edi
0x00407cd4:	movl 0x4264e8, %eax
0x00407cd9:	call GetProcAddress@KERNEL32.DLL
0x00407cdb:	xorl %eax, 0x424100
0x00407ce1:	pushl $0x41da6c<UINT32>
0x00407ce6:	pushl %edi
0x00407ce7:	movl 0x4264ec, %eax
0x00407cec:	call GetProcAddress@KERNEL32.DLL
0x00407cee:	xorl %eax, 0x424100
0x00407cf4:	pushl $0x41da84<UINT32>
0x00407cf9:	pushl %edi
0x00407cfa:	movl 0x4264f0, %eax
0x00407cff:	call GetProcAddress@KERNEL32.DLL
0x00407d01:	xorl %eax, 0x424100
0x00407d07:	pushl $0x41da98<UINT32>
0x00407d0c:	pushl %edi
0x00407d0d:	movl 0x4264f4, %eax
0x00407d12:	call GetProcAddress@KERNEL32.DLL
0x00407d14:	xorl %eax, 0x424100
0x00407d1a:	movl 0x4264f8, %eax
0x00407d1f:	pushl $0x41daac<UINT32>
0x00407d24:	pushl %edi
0x00407d25:	call GetProcAddress@KERNEL32.DLL
0x00407d27:	xorl %eax, 0x424100
0x00407d2d:	pushl $0x41dac8<UINT32>
0x00407d32:	pushl %edi
0x00407d33:	movl 0x4264fc, %eax
0x00407d38:	call GetProcAddress@KERNEL32.DLL
0x00407d3a:	xorl %eax, 0x424100
0x00407d40:	pushl $0x41dae8<UINT32>
0x00407d45:	pushl %edi
0x00407d46:	movl 0x426500, %eax
0x00407d4b:	call GetProcAddress@KERNEL32.DLL
0x00407d4d:	xorl %eax, 0x424100
0x00407d53:	pushl $0x41db04<UINT32>
0x00407d58:	pushl %edi
0x00407d59:	movl 0x426504, %eax
0x00407d5e:	call GetProcAddress@KERNEL32.DLL
0x00407d60:	xorl %eax, 0x424100
0x00407d66:	pushl $0x41db24<UINT32>
0x00407d6b:	pushl %edi
0x00407d6c:	movl 0x426508, %eax
0x00407d71:	call GetProcAddress@KERNEL32.DLL
0x00407d73:	xorl %eax, 0x424100
0x00407d79:	pushl $0x41db38<UINT32>
0x00407d7e:	pushl %edi
0x00407d7f:	movl 0x42650c, %eax
0x00407d84:	call GetProcAddress@KERNEL32.DLL
0x00407d86:	xorl %eax, 0x424100
0x00407d8c:	pushl $0x41db54<UINT32>
0x00407d91:	pushl %edi
0x00407d92:	movl 0x426510, %eax
0x00407d97:	call GetProcAddress@KERNEL32.DLL
0x00407d99:	xorl %eax, 0x424100
0x00407d9f:	pushl $0x41db68<UINT32>
0x00407da4:	pushl %edi
0x00407da5:	movl 0x426518, %eax
0x00407daa:	call GetProcAddress@KERNEL32.DLL
0x00407dac:	xorl %eax, 0x424100
0x00407db2:	pushl $0x41db78<UINT32>
0x00407db7:	pushl %edi
0x00407db8:	movl 0x426514, %eax
0x00407dbd:	call GetProcAddress@KERNEL32.DLL
0x00407dbf:	xorl %eax, 0x424100
0x00407dc5:	pushl $0x41db88<UINT32>
0x00407dca:	pushl %edi
0x00407dcb:	movl 0x42651c, %eax
0x00407dd0:	call GetProcAddress@KERNEL32.DLL
0x00407dd2:	xorl %eax, 0x424100
0x00407dd8:	pushl $0x41db98<UINT32>
0x00407ddd:	pushl %edi
0x00407dde:	movl 0x426520, %eax
0x00407de3:	call GetProcAddress@KERNEL32.DLL
0x00407de5:	xorl %eax, 0x424100
0x00407deb:	pushl $0x41dba8<UINT32>
0x00407df0:	pushl %edi
0x00407df1:	movl 0x426524, %eax
0x00407df6:	call GetProcAddress@KERNEL32.DLL
0x00407df8:	xorl %eax, 0x424100
0x00407dfe:	pushl $0x41dbc4<UINT32>
0x00407e03:	pushl %edi
0x00407e04:	movl 0x426528, %eax
0x00407e09:	call GetProcAddress@KERNEL32.DLL
0x00407e0b:	xorl %eax, 0x424100
0x00407e11:	pushl $0x41dbd8<UINT32>
0x00407e16:	pushl %edi
0x00407e17:	movl 0x42652c, %eax
0x00407e1c:	call GetProcAddress@KERNEL32.DLL
0x00407e1e:	xorl %eax, 0x424100
0x00407e24:	pushl $0x41dbe8<UINT32>
0x00407e29:	pushl %edi
0x00407e2a:	movl 0x426530, %eax
0x00407e2f:	call GetProcAddress@KERNEL32.DLL
0x00407e31:	xorl %eax, 0x424100
0x00407e37:	pushl $0x41dbfc<UINT32>
0x00407e3c:	pushl %edi
0x00407e3d:	movl 0x426534, %eax
0x00407e42:	call GetProcAddress@KERNEL32.DLL
0x00407e44:	xorl %eax, 0x424100
0x00407e4a:	movl 0x426538, %eax
0x00407e4f:	pushl $0x41dc0c<UINT32>
0x00407e54:	pushl %edi
0x00407e55:	call GetProcAddress@KERNEL32.DLL
0x00407e57:	xorl %eax, 0x424100
0x00407e5d:	pushl $0x41dc2c<UINT32>
0x00407e62:	pushl %edi
0x00407e63:	movl 0x42653c, %eax
0x00407e68:	call GetProcAddress@KERNEL32.DLL
0x00407e6a:	xorl %eax, 0x424100
0x00407e70:	popl %edi
0x00407e71:	movl 0x426540, %eax
0x00407e76:	popl %esi
0x00407e77:	ret

0x004077da:	call 0x00407ab3
0x00407ab3:	pushl %esi
0x00407ab4:	pushl %edi
0x00407ab5:	movl %esi, $0x424c58<UINT32>
0x00407aba:	movl %edi, $0x425958<UINT32>
0x00407abf:	cmpl 0x4(%esi), $0x1<UINT8>
0x00407ac3:	jne 22
0x00407ac5:	pushl $0x0<UINT8>
0x00407ac7:	movl (%esi), %edi
0x00407ac9:	addl %edi, $0x18<UINT8>
0x00407acc:	pushl $0xfa0<UINT32>
0x00407ad1:	pushl (%esi)
0x00407ad3:	call 0x00407b7f
0x00407b7f:	pushl %ebp
0x00407b80:	movl %ebp, %esp
0x00407b82:	movl %eax, 0x4264d0
0x00407b87:	xorl %eax, 0x424100
0x00407b8d:	je 13
0x00407b8f:	pushl 0x10(%ebp)
0x00407b92:	pushl 0xc(%ebp)
0x00407b95:	pushl 0x8(%ebp)
0x00407b98:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x00407b9a:	popl %ebp
0x00407b9b:	ret

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
