0x00706160:	pusha
0x00706161:	movl %esi, $0x5f6000<UINT32>
0x00706166:	leal %edi, -2052096(%esi)
0x0070616c:	pushl %edi
0x0070616d:	jmp 0x0070617a
0x0070617a:	movl %ebx, (%esi)
0x0070617c:	subl %esi, $0xfffffffc<UINT8>
0x0070617f:	adcl %ebx, %ebx
0x00706181:	jb 0x00706170
0x00706170:	movb %al, (%esi)
0x00706172:	incl %esi
0x00706173:	movb (%edi), %al
0x00706175:	incl %edi
0x00706176:	addl %ebx, %ebx
0x00706178:	jne 0x00706181
0x00706183:	movl %eax, $0x1<UINT32>
0x00706188:	addl %ebx, %ebx
0x0070618a:	jne 0x00706193
0x00706193:	adcl %eax, %eax
0x00706195:	addl %ebx, %ebx
0x00706197:	jae 0x007061a4
0x00706199:	jne 0x007061c3
0x007061c3:	xorl %ecx, %ecx
0x007061c5:	subl %eax, $0x3<UINT8>
0x007061c8:	jb 0x007061db
0x007061ca:	shll %eax, $0x8<UINT8>
0x007061cd:	movb %al, (%esi)
0x007061cf:	incl %esi
0x007061d0:	xorl %eax, $0xffffffff<UINT8>
0x007061d3:	je 0x0070624a
0x007061d5:	sarl %eax
0x007061d7:	movl %ebp, %eax
0x007061d9:	jmp 0x007061e6
0x007061e6:	jb 0x007061b4
0x007061b4:	addl %ebx, %ebx
0x007061b6:	jne 0x007061bf
0x007061bf:	adcl %ecx, %ecx
0x007061c1:	jmp 0x00706215
0x00706215:	cmpl %ebp, $0xfffffb00<UINT32>
0x0070621b:	adcl %ecx, $0x2<UINT8>
0x0070621e:	leal %edx, (%edi,%ebp)
0x00706221:	cmpl %ebp, $0xfffffffc<UINT8>
0x00706224:	jbe 0x00706234
0x00706234:	movl %eax, (%edx)
0x00706236:	addl %edx, $0x4<UINT8>
0x00706239:	movl (%edi), %eax
0x0070623b:	addl %edi, $0x4<UINT8>
0x0070623e:	subl %ecx, $0x4<UINT8>
0x00706241:	ja 0x00706234
0x00706243:	addl %edi, %ecx
0x00706245:	jmp 0x00706176
0x007061e8:	incl %ecx
0x007061e9:	addl %ebx, %ebx
0x007061eb:	jne 0x007061f4
0x007061ed:	movl %ebx, (%esi)
0x007061ef:	subl %esi, $0xfffffffc<UINT8>
0x007061f2:	adcl %ebx, %ebx
0x007061f4:	jb 0x007061b4
0x007061db:	addl %ebx, %ebx
0x007061dd:	jne 0x007061e6
0x007061f6:	addl %ebx, %ebx
0x007061f8:	jne 0x00706201
0x00706201:	adcl %ecx, %ecx
0x00706203:	addl %ebx, %ebx
0x00706205:	jae 0x007061f6
0x00706207:	jne 0x00706212
0x00706212:	addl %ecx, $0x2<UINT8>
0x0070618c:	movl %ebx, (%esi)
0x0070618e:	subl %esi, $0xfffffffc<UINT8>
0x00706191:	adcl %ebx, %ebx
0x007061df:	movl %ebx, (%esi)
0x007061e1:	subl %esi, $0xfffffffc<UINT8>
0x007061e4:	adcl %ebx, %ebx
0x007061b8:	movl %ebx, (%esi)
0x007061ba:	subl %esi, $0xfffffffc<UINT8>
0x007061bd:	adcl %ebx, %ebx
0x007061a4:	decl %eax
0x007061a5:	addl %ebx, %ebx
0x007061a7:	jne 0x007061b0
0x007061b0:	adcl %eax, %eax
0x007061b2:	jmp 0x00706188
0x007061fa:	movl %ebx, (%esi)
0x007061fc:	subl %esi, $0xfffffffc<UINT8>
0x007061ff:	adcl %ebx, %ebx
0x0070619b:	movl %ebx, (%esi)
0x0070619d:	subl %esi, $0xfffffffc<UINT8>
0x007061a0:	adcl %ebx, %ebx
0x007061a2:	jb 0x007061c3
0x00706209:	movl %ebx, (%esi)
0x0070620b:	subl %esi, $0xfffffffc<UINT8>
0x0070620e:	adcl %ebx, %ebx
0x00706210:	jae 0x007061f6
0x007061a9:	movl %ebx, (%esi)
0x007061ab:	subl %esi, $0xfffffffc<UINT8>
0x007061ae:	adcl %ebx, %ebx
0x00706226:	movb %al, (%edx)
0x00706228:	incl %edx
0x00706229:	movb (%edi), %al
0x0070622b:	incl %edi
0x0070622c:	decl %ecx
0x0070622d:	jne 0x00706226
0x0070622f:	jmp 0x00706176
0x0070624a:	popl %esi
0x0070624b:	movl %edi, %esi
0x0070624d:	movl %ecx, $0x1155d<UINT32>
0x00706252:	movb %al, (%edi)
0x00706254:	incl %edi
0x00706255:	subb %al, $0xffffffe8<UINT8>
0x00706257:	cmpb %al, $0x1<UINT8>
0x00706259:	ja 0x00706252
0x0070625b:	cmpb (%edi), $0x4b<UINT8>
0x0070625e:	jne 0x00706252
0x00706260:	movl %eax, (%edi)
0x00706262:	movb %bl, 0x4(%edi)
0x00706265:	shrw %ax, $0x8<UINT8>
0x00706269:	roll %eax, $0x10<UINT8>
0x0070626c:	xchgb %ah, %al
0x0070626e:	subl %eax, %edi
0x00706270:	subb %bl, $0xffffffe8<UINT8>
0x00706273:	addl %eax, %esi
0x00706275:	movl (%edi), %eax
0x00706277:	addl %edi, $0x5<UINT8>
0x0070627a:	movb %al, %bl
0x0070627c:	loop 0x00706257
0x0070627e:	leal %edi, 0x2eb000(%esi)
0x00706284:	movl %eax, (%edi)
0x00706286:	orl %eax, %eax
0x00706288:	je 0x007062cf
0x0070628a:	movl %ebx, 0x4(%edi)
0x0070628d:	leal %eax, 0x308118(%eax,%esi)
0x00706294:	addl %ebx, %esi
0x00706296:	pushl %eax
0x00706297:	addl %edi, $0x8<UINT8>
0x0070629a:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x007062a0:	xchgl %ebp, %eax
0x007062a1:	movb %al, (%edi)
0x007062a3:	incl %edi
0x007062a4:	orb %al, %al
0x007062a6:	je 0x00706284
0x007062a8:	movl %ecx, %edi
0x007062aa:	jns 0x007062b3
0x007062b3:	pushl %edi
0x007062b4:	decl %eax
0x007062b5:	repn scasb %al, %es:(%edi)
0x007062b7:	pushl %ebp
0x007062b8:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x007062be:	orl %eax, %eax
0x007062c0:	je 7
0x007062c2:	movl (%ebx), %eax
0x007062c4:	addl %ebx, $0x4<UINT8>
0x007062c7:	jmp 0x007062a1
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x007062ac:	movzwl %eax, (%edi)
0x007062af:	incl %edi
0x007062b0:	pushl %eax
0x007062b1:	incl %edi
0x007062b2:	movl %ecx, $0xaef24857<UINT32>
0x007062cf:	addl %edi, $0x4<UINT8>
0x007062d2:	leal %ebx, -4(%esi)
0x007062d5:	xorl %eax, %eax
0x007062d7:	movb %al, (%edi)
0x007062d9:	incl %edi
0x007062da:	orl %eax, %eax
0x007062dc:	je 0x00706300
0x007062de:	cmpb %al, $0xffffffef<UINT8>
0x007062e0:	ja 0x007062f3
0x007062e2:	addl %ebx, %eax
0x007062e4:	movl %eax, (%ebx)
0x007062e6:	xchgb %ah, %al
0x007062e8:	roll %eax, $0x10<UINT8>
0x007062eb:	xchgb %ah, %al
0x007062ed:	addl %eax, %esi
0x007062ef:	movl (%ebx), %eax
0x007062f1:	jmp 0x007062d5
0x007062f3:	andb %al, $0xf<UINT8>
0x007062f5:	shll %eax, $0x10<UINT8>
0x007062f8:	movw %ax, (%edi)
0x007062fb:	addl %edi, $0x2<UINT8>
0x007062fe:	jmp 0x007062e2
0x00706300:	movl %ebp, 0x308334(%esi)
0x00706306:	leal %edi, -4096(%esi)
0x0070630c:	movl %ebx, $0x1000<UINT32>
0x00706311:	pushl %eax
0x00706312:	pushl %esp
0x00706313:	pushl $0x4<UINT8>
0x00706315:	pushl %ebx
0x00706316:	pushl %edi
0x00706317:	call VirtualProtect@KERNEL32.DLL
VirtualProtect@KERNEL32.DLL: API Node	
0x00706319:	leal %eax, 0x22f(%edi)
0x0070631f:	andb (%eax), $0x7f<UINT8>
0x00706322:	andb 0x28(%eax), $0x7f<UINT8>
0x00706326:	popl %eax
0x00706327:	pushl %eax
0x00706328:	pushl %esp
0x00706329:	pushl %eax
0x0070632a:	pushl %ebx
0x0070632b:	pushl %edi
0x0070632c:	call VirtualProtect@KERNEL32.DLL
0x0070632e:	popl %eax
0x0070632f:	popa
0x00706330:	leal %eax, -128(%esp)
0x00706334:	pushl $0x0<UINT8>
0x00706336:	cmpl %esp, %eax
0x00706338:	jne 0x00706334
0x0070633a:	subl %esp, $0xffffff80<UINT8>
0x0070633d:	jmp 0x005b5d42
0x005b5d42:	call 0x005c4706
0x005c4706:	pushl %ebp
0x005c4707:	movl %ebp, %esp
0x005c4709:	subl %esp, $0x14<UINT8>
0x005c470c:	andl -12(%ebp), $0x0<UINT8>
0x005c4710:	andl -8(%ebp), $0x0<UINT8>
0x005c4714:	movl %eax, 0x69d710
0x005c4719:	pushl %esi
0x005c471a:	pushl %edi
0x005c471b:	movl %edi, $0xbb40e64e<UINT32>
0x005c4720:	movl %esi, $0xffff0000<UINT32>
0x005c4725:	cmpl %eax, %edi
0x005c4727:	je 0x005c4736
0x005c4736:	leal %eax, -12(%ebp)
0x005c4739:	pushl %eax
0x005c473a:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x005c4740:	movl %eax, -8(%ebp)
0x005c4743:	xorl %eax, -12(%ebp)
0x005c4746:	movl -4(%ebp), %eax
0x005c4749:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x005c474f:	xorl -4(%ebp), %eax
0x005c4752:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x005c4758:	xorl -4(%ebp), %eax
0x005c475b:	leal %eax, -20(%ebp)
0x005c475e:	pushl %eax
0x005c475f:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x005c4765:	movl %ecx, -16(%ebp)
0x005c4768:	leal %eax, -4(%ebp)
0x005c476b:	xorl %ecx, -20(%ebp)
0x005c476e:	xorl %ecx, -4(%ebp)
0x005c4771:	xorl %ecx, %eax
0x005c4773:	cmpl %ecx, %edi
0x005c4775:	jne 0x005c477e
0x005c477e:	testl %esi, %ecx
0x005c4780:	jne 0x005c478e
0x005c478e:	movl 0x69d710, %ecx
0x005c4794:	notl %ecx
0x005c4796:	movl 0x69d714, %ecx
0x005c479c:	popl %edi
0x005c479d:	popl %esi
0x005c479e:	movl %esp, %ebp
0x005c47a0:	popl %ebp
0x005c47a1:	ret

0x005b5d47:	jmp 0x005b5b85
0x005b5b85:	pushl $0x14<UINT8>
0x005b5b87:	pushl $0x696070<UINT32>
0x005b5b8c:	call 0x005bf900
0x005bf900:	pushl $0x5ba760<UINT32>
0x005bf905:	pushl %fs:0
0x005bf90c:	movl %eax, 0x10(%esp)
0x005bf910:	movl 0x10(%esp), %ebp
0x005bf914:	leal %ebp, 0x10(%esp)
0x005bf918:	subl %esp, %eax
0x005bf91a:	pushl %ebx
0x005bf91b:	pushl %esi
0x005bf91c:	pushl %edi
0x005bf91d:	movl %eax, 0x69d710
0x005bf922:	xorl -4(%ebp), %eax
0x005bf925:	xorl %eax, %ebp
0x005bf927:	pushl %eax
0x005bf928:	movl -24(%ebp), %esp
0x005bf92b:	pushl -8(%ebp)
0x005bf92e:	movl %eax, -4(%ebp)
0x005bf931:	movl -4(%ebp), $0xfffffffe<UINT32>
0x005bf938:	movl -8(%ebp), %eax
0x005bf93b:	leal %eax, -16(%ebp)
0x005bf93e:	movl %fs:0, %eax
0x005bf944:	ret

0x005b5b91:	call 0x005c4a86
0x005c4a86:	pushl %ebp
0x005c4a87:	movl %ebp, %esp
0x005c4a89:	subl %esp, $0x44<UINT8>
0x005c4a8c:	leal %eax, -68(%ebp)
0x005c4a8f:	pushl %eax
0x005c4a90:	call GetStartupInfoW@KERNEL32.DLL
GetStartupInfoW@KERNEL32.DLL: API Node	
0x005c4a96:	testb -24(%ebp), $0x1<UINT8>
0x005c4a9a:	je 0x005c4aa2
0x005c4aa2:	pushl $0xa<UINT8>
0x005c4aa4:	popl %eax
0x005c4aa5:	movl %esp, %ebp
0x005c4aa7:	popl %ebp
0x005c4aa8:	ret

0x005b5b96:	movzwl %esi, %ax
0x005b5b99:	pushl $0x2<UINT8>
0x005b5b9b:	call 0x005c46b9
0x005c46b9:	pushl %ebp
0x005c46ba:	movl %ebp, %esp
0x005c46bc:	movl %eax, 0x8(%ebp)
0x005c46bf:	movl 0x6aff80, %eax
0x005c46c4:	popl %ebp
0x005c46c5:	ret

0x005b5ba0:	popl %ecx
0x005b5ba1:	movl %eax, $0x5a4d<UINT32>
0x005b5ba6:	cmpw 0x400000, %ax
0x005b5bad:	je 0x005b5bb3
0x005b5bb3:	movl %eax, 0x40003c
0x005b5bb8:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x005b5bc2:	jne -21
0x005b5bc4:	movl %ecx, $0x10b<UINT32>
0x005b5bc9:	cmpw 0x400018(%eax), %cx
0x005b5bd0:	jne -35
0x005b5bd2:	xorl %ebx, %ebx
0x005b5bd4:	cmpl 0x400074(%eax), $0xe<UINT8>
0x005b5bdb:	jbe 9
0x005b5bdd:	cmpl 0x4000e8(%eax), %ebx
0x005b5be3:	setne %bl
0x005b5be6:	movl -28(%ebp), %ebx
0x005b5be9:	call 0x005c3e50
0x005c3e50:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x005c3e56:	xorl %ecx, %ecx
0x005c3e58:	movl 0x6afc68, %eax
0x005c3e5d:	testl %eax, %eax
0x005c3e5f:	setne %cl
0x005c3e62:	movl %eax, %ecx
0x005c3e64:	ret

0x005b5bee:	testl %eax, %eax
0x005b5bf0:	jne 0x005b5bfa
0x005b5bfa:	call 0x005c3db7
0x005c3db7:	call 0x005c0170
0x005c0170:	pushl %esi
0x005c0171:	pushl $0x0<UINT8>
0x005c0173:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x005c0179:	movl %esi, %eax
0x005c017b:	pushl %esi
0x005c017c:	call 0x005d1972
0x005d1972:	pushl %ebp
0x005d1973:	movl %ebp, %esp
0x005d1975:	movl %eax, 0x8(%ebp)
0x005d1978:	movl 0x6b05f4, %eax
0x005d197d:	popl %ebp
0x005d197e:	ret

0x005c0181:	pushl %esi
0x005c0182:	call 0x005c519a
0x005c519a:	pushl %ebp
0x005c519b:	movl %ebp, %esp
0x005c519d:	movl %eax, 0x8(%ebp)
0x005c51a0:	movl 0x6b05b8, %eax
0x005c51a5:	popl %ebp
0x005c51a6:	ret

0x005c0187:	pushl %esi
0x005c0188:	call 0x005da833
0x005da833:	pushl %ebp
0x005da834:	movl %ebp, %esp
0x005da836:	movl %eax, 0x8(%ebp)
0x005da839:	movl 0x6b0824, %eax
0x005da83e:	popl %ebp
0x005da83f:	ret

0x005c018d:	pushl %esi
0x005c018e:	call 0x005da85f
0x005da85f:	pushl %ebp
0x005da860:	movl %ebp, %esp
0x005da862:	movl %eax, 0x8(%ebp)
0x005da865:	movl 0x6b0828, %eax
0x005da86a:	movl 0x6b082c, %eax
0x005da86f:	movl 0x6b0830, %eax
0x005da874:	movl 0x6b0834, %eax
0x005da879:	popl %ebp
0x005da87a:	ret

0x005c0193:	pushl %esi
0x005c0194:	call 0x005ce7db
0x005ce7db:	pushl $0x5ce794<UINT32>
0x005ce7e0:	call EncodePointer@KERNEL32.DLL
0x005ce7e6:	movl 0x6b05e0, %eax
0x005ce7eb:	ret

0x005c0199:	pushl %esi
0x005c019a:	call 0x005dad6c
0x005dad6c:	pushl %ebp
0x005dad6d:	movl %ebp, %esp
0x005dad6f:	movl %eax, 0x8(%ebp)
0x005dad72:	movl 0x6b083c, %eax
0x005dad77:	popl %ebp
0x005dad78:	ret

0x005c019f:	addl %esp, $0x18<UINT8>
0x005c01a2:	popl %esi
0x005c01a3:	jmp 0x005c4b2f
0x005c4b2f:	pushl %esi
0x005c4b30:	pushl %edi
0x005c4b31:	pushl $0x61e784<UINT32>
0x005c4b36:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x005c4b3c:	movl %esi, 0x60e4e0
0x005c4b42:	movl %edi, %eax
0x005c4b44:	pushl $0x654a94<UINT32>
0x005c4b49:	pushl %edi
0x005c4b4a:	call GetProcAddress@KERNEL32.DLL
0x005c4b4c:	xorl %eax, 0x69d710
0x005c4b52:	pushl $0x654aa0<UINT32>
0x005c4b57:	pushl %edi
0x005c4b58:	movl 0x6b1940, %eax
0x005c4b5d:	call GetProcAddress@KERNEL32.DLL
0x005c4b5f:	xorl %eax, 0x69d710
0x005c4b65:	pushl $0x654aa8<UINT32>
0x005c4b6a:	pushl %edi
0x005c4b6b:	movl 0x6b1944, %eax
0x005c4b70:	call GetProcAddress@KERNEL32.DLL
0x005c4b72:	xorl %eax, 0x69d710
0x005c4b78:	pushl $0x654ab4<UINT32>
0x005c4b7d:	pushl %edi
0x005c4b7e:	movl 0x6b1948, %eax
0x005c4b83:	call GetProcAddress@KERNEL32.DLL
0x005c4b85:	xorl %eax, 0x69d710
0x005c4b8b:	pushl $0x654ac0<UINT32>
0x005c4b90:	pushl %edi
0x005c4b91:	movl 0x6b194c, %eax
0x005c4b96:	call GetProcAddress@KERNEL32.DLL
0x005c4b98:	xorl %eax, 0x69d710
0x005c4b9e:	pushl $0x654adc<UINT32>
0x005c4ba3:	pushl %edi
0x005c4ba4:	movl 0x6b1950, %eax
0x005c4ba9:	call GetProcAddress@KERNEL32.DLL
0x005c4bab:	xorl %eax, 0x69d710
0x005c4bb1:	pushl $0x654aec<UINT32>
0x005c4bb6:	pushl %edi
0x005c4bb7:	movl 0x6b1954, %eax
0x005c4bbc:	call GetProcAddress@KERNEL32.DLL
0x005c4bbe:	xorl %eax, 0x69d710
0x005c4bc4:	pushl $0x654b00<UINT32>
0x005c4bc9:	pushl %edi
0x005c4bca:	movl 0x6b1958, %eax
0x005c4bcf:	call GetProcAddress@KERNEL32.DLL
0x005c4bd1:	xorl %eax, 0x69d710
0x005c4bd7:	pushl $0x654b18<UINT32>
0x005c4bdc:	pushl %edi
0x005c4bdd:	movl 0x6b195c, %eax
0x005c4be2:	call GetProcAddress@KERNEL32.DLL
0x005c4be4:	xorl %eax, 0x69d710
0x005c4bea:	pushl $0x654b30<UINT32>
0x005c4bef:	pushl %edi
0x005c4bf0:	movl 0x6b1960, %eax
0x005c4bf5:	call GetProcAddress@KERNEL32.DLL
0x005c4bf7:	xorl %eax, 0x69d710
0x005c4bfd:	pushl $0x654b44<UINT32>
0x005c4c02:	pushl %edi
0x005c4c03:	movl 0x6b1964, %eax
0x005c4c08:	call GetProcAddress@KERNEL32.DLL
0x005c4c0a:	xorl %eax, 0x69d710
0x005c4c10:	pushl $0x654b64<UINT32>
0x005c4c15:	pushl %edi
0x005c4c16:	movl 0x6b1968, %eax
0x005c4c1b:	call GetProcAddress@KERNEL32.DLL
0x005c4c1d:	xorl %eax, 0x69d710
0x005c4c23:	pushl $0x654b7c<UINT32>
0x005c4c28:	pushl %edi
0x005c4c29:	movl 0x6b196c, %eax
0x005c4c2e:	call GetProcAddress@KERNEL32.DLL
0x005c4c30:	xorl %eax, 0x69d710
0x005c4c36:	pushl $0x654b94<UINT32>
0x005c4c3b:	pushl %edi
0x005c4c3c:	movl 0x6b1970, %eax
0x005c4c41:	call GetProcAddress@KERNEL32.DLL
0x005c4c43:	xorl %eax, 0x69d710
0x005c4c49:	pushl $0x654ba8<UINT32>
0x005c4c4e:	pushl %edi
0x005c4c4f:	movl 0x6b1974, %eax
0x005c4c54:	call GetProcAddress@KERNEL32.DLL
0x005c4c56:	xorl %eax, 0x69d710
0x005c4c5c:	movl 0x6b1978, %eax
0x005c4c61:	pushl $0x654bbc<UINT32>
0x005c4c66:	pushl %edi
0x005c4c67:	call GetProcAddress@KERNEL32.DLL
0x005c4c69:	xorl %eax, 0x69d710
0x005c4c6f:	pushl $0x654bd8<UINT32>
0x005c4c74:	pushl %edi
0x005c4c75:	movl 0x6b197c, %eax
0x005c4c7a:	call GetProcAddress@KERNEL32.DLL
0x005c4c7c:	xorl %eax, 0x69d710
0x005c4c82:	pushl $0x654bf8<UINT32>
0x005c4c87:	pushl %edi
0x005c4c88:	movl 0x6b1980, %eax
0x005c4c8d:	call GetProcAddress@KERNEL32.DLL
0x005c4c8f:	xorl %eax, 0x69d710
0x005c4c95:	pushl $0x654c14<UINT32>
0x005c4c9a:	pushl %edi
0x005c4c9b:	movl 0x6b1984, %eax
0x005c4ca0:	call GetProcAddress@KERNEL32.DLL
0x005c4ca2:	xorl %eax, 0x69d710
0x005c4ca8:	pushl $0x654c34<UINT32>
0x005c4cad:	pushl %edi
0x005c4cae:	movl 0x6b1988, %eax
0x005c4cb3:	call GetProcAddress@KERNEL32.DLL
0x005c4cb5:	xorl %eax, 0x69d710
0x005c4cbb:	pushl $0x61e7a0<UINT32>
0x005c4cc0:	pushl %edi
0x005c4cc1:	movl 0x6b198c, %eax
0x005c4cc6:	call GetProcAddress@KERNEL32.DLL
0x005c4cc8:	xorl %eax, 0x69d710
0x005c4cce:	pushl $0x654c48<UINT32>
0x005c4cd3:	pushl %edi
0x005c4cd4:	movl 0x6b1990, %eax
0x005c4cd9:	call GetProcAddress@KERNEL32.DLL
0x005c4cdb:	xorl %eax, 0x69d710
0x005c4ce1:	pushl $0x61f348<UINT32>
0x005c4ce6:	pushl %edi
0x005c4ce7:	movl 0x6b1998, %eax
0x005c4cec:	call GetProcAddress@KERNEL32.DLL
0x005c4cee:	xorl %eax, 0x69d710
0x005c4cf4:	pushl $0x654c5c<UINT32>
0x005c4cf9:	pushl %edi
0x005c4cfa:	movl 0x6b1994, %eax
0x005c4cff:	call GetProcAddress@KERNEL32.DLL
0x005c4d01:	xorl %eax, 0x69d710
0x005c4d07:	pushl $0x61f318<UINT32>
0x005c4d0c:	pushl %edi
0x005c4d0d:	movl 0x6b199c, %eax
0x005c4d12:	call GetProcAddress@KERNEL32.DLL
0x005c4d14:	xorl %eax, 0x69d710
0x005c4d1a:	pushl $0x654c6c<UINT32>
0x005c4d1f:	pushl %edi
0x005c4d20:	movl 0x6b19a0, %eax
0x005c4d25:	call GetProcAddress@KERNEL32.DLL
0x005c4d27:	xorl %eax, 0x69d710
0x005c4d2d:	pushl $0x654c7c<UINT32>
0x005c4d32:	pushl %edi
0x005c4d33:	movl 0x6b19a4, %eax
0x005c4d38:	call GetProcAddress@KERNEL32.DLL
0x005c4d3a:	xorl %eax, 0x69d710
0x005c4d40:	pushl $0x654c98<UINT32>
0x005c4d45:	pushl %edi
0x005c4d46:	movl 0x6b19a8, %eax
0x005c4d4b:	call GetProcAddress@KERNEL32.DLL
0x005c4d4d:	xorl %eax, 0x69d710
0x005c4d53:	pushl $0x654cac<UINT32>
0x005c4d58:	pushl %edi
0x005c4d59:	movl 0x6b19ac, %eax
0x005c4d5e:	call GetProcAddress@KERNEL32.DLL
0x005c4d60:	xorl %eax, 0x69d710
0x005c4d66:	pushl $0x654cbc<UINT32>
0x005c4d6b:	pushl %edi
0x005c4d6c:	movl 0x6b19b0, %eax
0x005c4d71:	call GetProcAddress@KERNEL32.DLL
0x005c4d73:	xorl %eax, 0x69d710
0x005c4d79:	pushl $0x654cd0<UINT32>
0x005c4d7e:	pushl %edi
0x005c4d7f:	movl 0x6b19b4, %eax
0x005c4d84:	call GetProcAddress@KERNEL32.DLL
0x005c4d86:	xorl %eax, 0x69d710
0x005c4d8c:	movl 0x6b19b8, %eax
0x005c4d91:	pushl $0x654ce0<UINT32>
0x005c4d96:	pushl %edi
0x005c4d97:	call GetProcAddress@KERNEL32.DLL
0x005c4d99:	xorl %eax, 0x69d710
0x005c4d9f:	pushl $0x654d00<UINT32>
0x005c4da4:	pushl %edi
0x005c4da5:	movl 0x6b19bc, %eax
0x005c4daa:	call GetProcAddress@KERNEL32.DLL
0x005c4dac:	xorl %eax, 0x69d710
0x005c4db2:	popl %edi
0x005c4db3:	movl 0x6b19c0, %eax
0x005c4db8:	popl %esi
0x005c4db9:	ret

0x005c3dbc:	call 0x005d5237
0x005d5237:	pushl %esi
0x005d5238:	pushl %edi
0x005d5239:	movl %esi, $0x69e470<UINT32>
0x005d523e:	movl %edi, $0x6b0600<UINT32>
0x005d5243:	cmpl 0x4(%esi), $0x1<UINT8>
0x005d5247:	jne 22
0x005d5249:	pushl $0x0<UINT8>
0x005d524b:	movl (%esi), %edi
0x005d524d:	addl %edi, $0x18<UINT8>
0x005d5250:	pushl $0xfa0<UINT32>
0x005d5255:	pushl (%esi)
0x005d5257:	call 0x005c4ac1
0x005c4ac1:	pushl %ebp
0x005c4ac2:	movl %ebp, %esp
0x005c4ac4:	movl %eax, 0x6b1950
0x005c4ac9:	xorl %eax, 0x69d710
0x005c4acf:	je 13
0x005c4ad1:	pushl 0x10(%ebp)
0x005c4ad4:	pushl 0xc(%ebp)
0x005c4ad7:	pushl 0x8(%ebp)
0x005c4ada:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x005c4adc:	popl %ebp
0x005c4add:	ret

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
