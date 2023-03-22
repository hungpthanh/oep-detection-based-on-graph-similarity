0x004281e0:	pusha
0x004281e1:	movl %esi, $0x41a000<UINT32>
0x004281e6:	leal %edi, -102400(%esi)
0x004281ec:	pushl %edi
0x004281ed:	jmp 0x004281fa
0x004281fa:	movl %ebx, (%esi)
0x004281fc:	subl %esi, $0xfffffffc<UINT8>
0x004281ff:	adcl %ebx, %ebx
0x00428201:	jb 0x004281f0
0x004281f0:	movb %al, (%esi)
0x004281f2:	incl %esi
0x004281f3:	movb (%edi), %al
0x004281f5:	incl %edi
0x004281f6:	addl %ebx, %ebx
0x004281f8:	jne 0x00428201
0x00428203:	movl %eax, $0x1<UINT32>
0x00428208:	addl %ebx, %ebx
0x0042820a:	jne 0x00428213
0x00428213:	adcl %eax, %eax
0x00428215:	addl %ebx, %ebx
0x00428217:	jae 0x00428208
0x00428219:	jne 0x00428224
0x00428224:	xorl %ecx, %ecx
0x00428226:	subl %eax, $0x3<UINT8>
0x00428229:	jb 0x00428238
0x0042822b:	shll %eax, $0x8<UINT8>
0x0042822e:	movb %al, (%esi)
0x00428230:	incl %esi
0x00428231:	xorl %eax, $0xffffffff<UINT8>
0x00428234:	je 0x004282aa
0x00428236:	movl %ebp, %eax
0x00428238:	addl %ebx, %ebx
0x0042823a:	jne 0x00428243
0x00428243:	adcl %ecx, %ecx
0x00428245:	addl %ebx, %ebx
0x00428247:	jne 0x00428250
0x00428250:	adcl %ecx, %ecx
0x00428252:	jne 0x00428274
0x00428274:	cmpl %ebp, $0xfffff300<UINT32>
0x0042827a:	adcl %ecx, $0x1<UINT8>
0x0042827d:	leal %edx, (%edi,%ebp)
0x00428280:	cmpl %ebp, $0xfffffffc<UINT8>
0x00428283:	jbe 0x00428294
0x00428294:	movl %eax, (%edx)
0x00428296:	addl %edx, $0x4<UINT8>
0x00428299:	movl (%edi), %eax
0x0042829b:	addl %edi, $0x4<UINT8>
0x0042829e:	subl %ecx, $0x4<UINT8>
0x004282a1:	ja 0x00428294
0x004282a3:	addl %edi, %ecx
0x004282a5:	jmp 0x004281f6
0x00428285:	movb %al, (%edx)
0x00428287:	incl %edx
0x00428288:	movb (%edi), %al
0x0042828a:	incl %edi
0x0042828b:	decl %ecx
0x0042828c:	jne 0x00428285
0x0042828e:	jmp 0x004281f6
0x00428254:	incl %ecx
0x00428255:	addl %ebx, %ebx
0x00428257:	jne 0x00428260
0x00428260:	adcl %ecx, %ecx
0x00428262:	addl %ebx, %ebx
0x00428264:	jae 0x00428255
0x00428266:	jne 0x00428271
0x00428271:	addl %ecx, $0x2<UINT8>
0x0042821b:	movl %ebx, (%esi)
0x0042821d:	subl %esi, $0xfffffffc<UINT8>
0x00428220:	adcl %ebx, %ebx
0x00428222:	jae 0x00428208
0x0042820c:	movl %ebx, (%esi)
0x0042820e:	subl %esi, $0xfffffffc<UINT8>
0x00428211:	adcl %ebx, %ebx
0x00428259:	movl %ebx, (%esi)
0x0042825b:	subl %esi, $0xfffffffc<UINT8>
0x0042825e:	adcl %ebx, %ebx
0x0042823c:	movl %ebx, (%esi)
0x0042823e:	subl %esi, $0xfffffffc<UINT8>
0x00428241:	adcl %ebx, %ebx
0x00428249:	movl %ebx, (%esi)
0x0042824b:	subl %esi, $0xfffffffc<UINT8>
0x0042824e:	adcl %ebx, %ebx
0x00428268:	movl %ebx, (%esi)
0x0042826a:	subl %esi, $0xfffffffc<UINT8>
0x0042826d:	adcl %ebx, %ebx
0x0042826f:	jae 0x00428255
0x004282aa:	popl %esi
0x004282ab:	movl %edi, %esi
0x004282ad:	movl %ecx, $0x6b7<UINT32>
0x004282b2:	movb %al, (%edi)
0x004282b4:	incl %edi
0x004282b5:	subb %al, $0xffffffe8<UINT8>
0x004282b7:	cmpb %al, $0x1<UINT8>
0x004282b9:	ja 0x004282b2
0x004282bb:	cmpb (%edi), $0x5<UINT8>
0x004282be:	jne 0x004282b2
0x004282c0:	movl %eax, (%edi)
0x004282c2:	movb %bl, 0x4(%edi)
0x004282c5:	shrw %ax, $0x8<UINT8>
0x004282c9:	roll %eax, $0x10<UINT8>
0x004282cc:	xchgb %ah, %al
0x004282ce:	subl %eax, %edi
0x004282d0:	subb %bl, $0xffffffe8<UINT8>
0x004282d3:	addl %eax, %esi
0x004282d5:	movl (%edi), %eax
0x004282d7:	addl %edi, $0x5<UINT8>
0x004282da:	movb %al, %bl
0x004282dc:	loop 0x004282b7
0x004282de:	leal %edi, 0x26000(%esi)
0x004282e4:	movl %eax, (%edi)
0x004282e6:	orl %eax, %eax
0x004282e8:	je 0x00428326
0x004282ea:	movl %ebx, 0x4(%edi)
0x004282ed:	leal %eax, 0x28560(%eax,%esi)
0x004282f4:	addl %ebx, %esi
0x004282f6:	pushl %eax
0x004282f7:	addl %edi, $0x8<UINT8>
0x004282fa:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x00428300:	xchgl %ebp, %eax
0x00428301:	movb %al, (%edi)
0x00428303:	incl %edi
0x00428304:	orb %al, %al
0x00428306:	je 0x004282e4
0x00428308:	movl %ecx, %edi
0x0042830a:	pushl %edi
0x0042830b:	decl %eax
0x0042830c:	repn scasb %al, %es:(%edi)
0x0042830e:	pushl %ebp
0x0042830f:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00428315:	orl %eax, %eax
0x00428317:	je 7
0x00428319:	movl (%ebx), %eax
0x0042831b:	addl %ebx, $0x4<UINT8>
0x0042831e:	jmp 0x00428301
GetProcAddress@KERNEL32.DLL: API Node	
0x00428326:	movl %ebp, 0x285f4(%esi)
0x0042832c:	leal %edi, -4096(%esi)
0x00428332:	movl %ebx, $0x1000<UINT32>
0x00428337:	pushl %eax
0x00428338:	pushl %esp
0x00428339:	pushl $0x4<UINT8>
0x0042833b:	pushl %ebx
0x0042833c:	pushl %edi
0x0042833d:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0042833f:	leal %eax, 0x217(%edi)
0x00428345:	andb (%eax), $0x7f<UINT8>
0x00428348:	andb 0x28(%eax), $0x7f<UINT8>
0x0042834c:	popl %eax
0x0042834d:	pushl %eax
0x0042834e:	pushl %esp
0x0042834f:	pushl %eax
0x00428350:	pushl %ebx
0x00428351:	pushl %edi
0x00428352:	call VirtualProtect@kernel32.dll
0x00428354:	popl %eax
0x00428355:	popa
0x00428356:	leal %eax, -128(%esp)
0x0042835a:	pushl $0x0<UINT8>
0x0042835c:	cmpl %esp, %eax
0x0042835e:	jne 0x0042835a
0x00428360:	subl %esp, $0xffffff80<UINT8>
0x00428363:	jmp 0x00405926
0x00405926:	call 0x0040ca32
0x0040ca32:	pushl %ebp
0x0040ca33:	movl %ebp, %esp
0x0040ca35:	subl %esp, $0x14<UINT8>
0x0040ca38:	andl -12(%ebp), $0x0<UINT8>
0x0040ca3c:	andl -8(%ebp), $0x0<UINT8>
0x0040ca40:	movl %eax, 0x4220d0
0x0040ca45:	pushl %esi
0x0040ca46:	pushl %edi
0x0040ca47:	movl %edi, $0xbb40e64e<UINT32>
0x0040ca4c:	movl %esi, $0xffff0000<UINT32>
0x0040ca51:	cmpl %eax, %edi
0x0040ca53:	je 0x0040ca62
0x0040ca62:	leal %eax, -12(%ebp)
0x0040ca65:	pushl %eax
0x0040ca66:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040ca6c:	movl %eax, -8(%ebp)
0x0040ca6f:	xorl %eax, -12(%ebp)
0x0040ca72:	movl -4(%ebp), %eax
0x0040ca75:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040ca7b:	xorl -4(%ebp), %eax
0x0040ca7e:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040ca84:	xorl -4(%ebp), %eax
0x0040ca87:	leal %eax, -20(%ebp)
0x0040ca8a:	pushl %eax
0x0040ca8b:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040ca91:	movl %ecx, -16(%ebp)
0x0040ca94:	leal %eax, -4(%ebp)
0x0040ca97:	xorl %ecx, -20(%ebp)
0x0040ca9a:	xorl %ecx, -4(%ebp)
0x0040ca9d:	xorl %ecx, %eax
0x0040ca9f:	cmpl %ecx, %edi
0x0040caa1:	jne 0x0040caaa
0x0040caaa:	testl %esi, %ecx
0x0040caac:	jne 0x0040caba
0x0040caba:	movl 0x4220d0, %ecx
0x0040cac0:	notl %ecx
0x0040cac2:	movl 0x4220d4, %ecx
0x0040cac8:	popl %edi
0x0040cac9:	popl %esi
0x0040caca:	movl %esp, %ebp
0x0040cacc:	popl %ebp
0x0040cacd:	ret

0x0040592b:	jmp 0x004057ab
0x004057ab:	pushl $0x14<UINT8>
0x004057ad:	pushl $0x420248<UINT32>
0x004057b2:	call 0x004077c0
0x004077c0:	pushl $0x4052c0<UINT32>
0x004077c5:	pushl %fs:0
0x004077cc:	movl %eax, 0x10(%esp)
0x004077d0:	movl 0x10(%esp), %ebp
0x004077d4:	leal %ebp, 0x10(%esp)
0x004077d8:	subl %esp, %eax
0x004077da:	pushl %ebx
0x004077db:	pushl %esi
0x004077dc:	pushl %edi
0x004077dd:	movl %eax, 0x4220d0
0x004077e2:	xorl -4(%ebp), %eax
0x004077e5:	xorl %eax, %ebp
0x004077e7:	pushl %eax
0x004077e8:	movl -24(%ebp), %esp
0x004077eb:	pushl -8(%ebp)
0x004077ee:	movl %eax, -4(%ebp)
0x004077f1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004077f8:	movl -8(%ebp), %eax
0x004077fb:	leal %eax, -16(%ebp)
0x004077fe:	movl %fs:0, %eax
0x00407804:	ret

0x004057b7:	pushl $0x1<UINT8>
0x004057b9:	call 0x0040c9e5
0x0040c9e5:	pushl %ebp
0x0040c9e6:	movl %ebp, %esp
0x0040c9e8:	movl %eax, 0x8(%ebp)
0x0040c9eb:	movl 0x4234e0, %eax
0x0040c9f0:	popl %ebp
0x0040c9f1:	ret

0x004057be:	popl %ecx
0x004057bf:	movl %eax, $0x5a4d<UINT32>
0x004057c4:	cmpw 0x400000, %ax
0x004057cb:	je 0x004057d1
0x004057d1:	movl %eax, 0x40003c
0x004057d6:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x004057e0:	jne -21
0x004057e2:	movl %ecx, $0x10b<UINT32>
0x004057e7:	cmpw 0x400018(%eax), %cx
0x004057ee:	jne -35
0x004057f0:	xorl %ebx, %ebx
0x004057f2:	cmpl 0x400074(%eax), $0xe<UINT8>
0x004057f9:	jbe 9
0x004057fb:	cmpl 0x4000e8(%eax), %ebx
0x00405801:	setne %bl
0x00405804:	movl -28(%ebp), %ebx
0x00405807:	call 0x004078f0
0x004078f0:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x004078f6:	xorl %ecx, %ecx
0x004078f8:	movl 0x423b40, %eax
0x004078fd:	testl %eax, %eax
0x004078ff:	setne %cl
0x00407902:	movl %eax, %ecx
0x00407904:	ret

0x0040580c:	testl %eax, %eax
0x0040580e:	jne 0x00405818
0x00405818:	call 0x00406832
0x00406832:	call 0x00403ab2
0x00403ab2:	pushl %esi
0x00403ab3:	pushl $0x0<UINT8>
0x00403ab5:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00403abb:	movl %esi, %eax
0x00403abd:	pushl %esi
0x00403abe:	call 0x00407572
0x00407572:	pushl %ebp
0x00407573:	movl %ebp, %esp
0x00407575:	movl %eax, 0x8(%ebp)
0x00407578:	movl 0x423b18, %eax
0x0040757d:	popl %ebp
0x0040757e:	ret

0x00403ac3:	pushl %esi
0x00403ac4:	call 0x00405a55
0x00405a55:	pushl %ebp
0x00405a56:	movl %ebp, %esp
0x00405a58:	movl %eax, 0x8(%ebp)
0x00405a5b:	movl 0x423368, %eax
0x00405a60:	popl %ebp
0x00405a61:	ret

0x00403ac9:	pushl %esi
0x00403aca:	call 0x0040757f
0x0040757f:	pushl %ebp
0x00407580:	movl %ebp, %esp
0x00407582:	movl %eax, 0x8(%ebp)
0x00407585:	movl 0x423b1c, %eax
0x0040758a:	popl %ebp
0x0040758b:	ret

0x00403acf:	pushl %esi
0x00403ad0:	call 0x00407599
0x00407599:	pushl %ebp
0x0040759a:	movl %ebp, %esp
0x0040759c:	movl %eax, 0x8(%ebp)
0x0040759f:	movl 0x423b20, %eax
0x004075a4:	movl 0x423b24, %eax
0x004075a9:	movl 0x423b28, %eax
0x004075ae:	movl 0x423b2c, %eax
0x004075b3:	popl %ebp
0x004075b4:	ret

0x00403ad5:	pushl %esi
0x00403ad6:	call 0x0040753b
0x0040753b:	pushl $0x407507<UINT32>
0x00407540:	call EncodePointer@KERNEL32.DLL
0x00407546:	movl 0x423b14, %eax
0x0040754b:	ret

0x00403adb:	pushl %esi
0x00403adc:	call 0x004077aa
0x004077aa:	pushl %ebp
0x004077ab:	movl %ebp, %esp
0x004077ad:	movl %eax, 0x8(%ebp)
0x004077b0:	movl 0x423b34, %eax
0x004077b5:	popl %ebp
0x004077b6:	ret

0x00403ae1:	addl %esp, $0x18<UINT8>
0x00403ae4:	popl %esi
0x00403ae5:	jmp 0x00406c4a
0x00406c4a:	pushl %esi
0x00406c4b:	pushl %edi
0x00406c4c:	pushl $0x41c808<UINT32>
0x00406c51:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00406c57:	movl %esi, 0x4150a0
0x00406c5d:	movl %edi, %eax
0x00406c5f:	pushl $0x41c824<UINT32>
0x00406c64:	pushl %edi
0x00406c65:	call GetProcAddress@KERNEL32.DLL
0x00406c67:	xorl %eax, 0x4220d0
0x00406c6d:	pushl $0x41c830<UINT32>
0x00406c72:	pushl %edi
0x00406c73:	movl 0x4241c0, %eax
0x00406c78:	call GetProcAddress@KERNEL32.DLL
0x00406c7a:	xorl %eax, 0x4220d0
0x00406c80:	pushl $0x41c838<UINT32>
0x00406c85:	pushl %edi
0x00406c86:	movl 0x4241c4, %eax
0x00406c8b:	call GetProcAddress@KERNEL32.DLL
0x00406c8d:	xorl %eax, 0x4220d0
0x00406c93:	pushl $0x41c844<UINT32>
0x00406c98:	pushl %edi
0x00406c99:	movl 0x4241c8, %eax
0x00406c9e:	call GetProcAddress@KERNEL32.DLL
0x00406ca0:	xorl %eax, 0x4220d0
0x00406ca6:	pushl $0x41c850<UINT32>
0x00406cab:	pushl %edi
0x00406cac:	movl 0x4241cc, %eax
0x00406cb1:	call GetProcAddress@KERNEL32.DLL
0x00406cb3:	xorl %eax, 0x4220d0
0x00406cb9:	pushl $0x41c86c<UINT32>
0x00406cbe:	pushl %edi
0x00406cbf:	movl 0x4241d0, %eax
0x00406cc4:	call GetProcAddress@KERNEL32.DLL
0x00406cc6:	xorl %eax, 0x4220d0
0x00406ccc:	pushl $0x41c87c<UINT32>
0x00406cd1:	pushl %edi
0x00406cd2:	movl 0x4241d4, %eax
0x00406cd7:	call GetProcAddress@KERNEL32.DLL
0x00406cd9:	xorl %eax, 0x4220d0
0x00406cdf:	pushl $0x41c890<UINT32>
0x00406ce4:	pushl %edi
0x00406ce5:	movl 0x4241d8, %eax
0x00406cea:	call GetProcAddress@KERNEL32.DLL
0x00406cec:	xorl %eax, 0x4220d0
0x00406cf2:	pushl $0x41c8a8<UINT32>
0x00406cf7:	pushl %edi
0x00406cf8:	movl 0x4241dc, %eax
0x00406cfd:	call GetProcAddress@KERNEL32.DLL
0x00406cff:	xorl %eax, 0x4220d0
0x00406d05:	pushl $0x41c8c0<UINT32>
0x00406d0a:	pushl %edi
0x00406d0b:	movl 0x4241e0, %eax
0x00406d10:	call GetProcAddress@KERNEL32.DLL
0x00406d12:	xorl %eax, 0x4220d0
0x00406d18:	pushl $0x41c8d4<UINT32>
0x00406d1d:	pushl %edi
0x00406d1e:	movl 0x4241e4, %eax
0x00406d23:	call GetProcAddress@KERNEL32.DLL
0x00406d25:	xorl %eax, 0x4220d0
0x00406d2b:	pushl $0x41c8f4<UINT32>
0x00406d30:	pushl %edi
0x00406d31:	movl 0x4241e8, %eax
0x00406d36:	call GetProcAddress@KERNEL32.DLL
0x00406d38:	xorl %eax, 0x4220d0
0x00406d3e:	pushl $0x41c90c<UINT32>
0x00406d43:	pushl %edi
0x00406d44:	movl 0x4241ec, %eax
0x00406d49:	call GetProcAddress@KERNEL32.DLL
0x00406d4b:	xorl %eax, 0x4220d0
0x00406d51:	pushl $0x41c924<UINT32>
0x00406d56:	pushl %edi
0x00406d57:	movl 0x4241f0, %eax
0x00406d5c:	call GetProcAddress@KERNEL32.DLL
0x00406d5e:	xorl %eax, 0x4220d0
0x00406d64:	pushl $0x41c938<UINT32>
0x00406d69:	pushl %edi
0x00406d6a:	movl 0x4241f4, %eax
0x00406d6f:	call GetProcAddress@KERNEL32.DLL
0x00406d71:	xorl %eax, 0x4220d0
0x00406d77:	movl 0x4241f8, %eax
0x00406d7c:	pushl $0x41c94c<UINT32>
0x00406d81:	pushl %edi
0x00406d82:	call GetProcAddress@KERNEL32.DLL
0x00406d84:	xorl %eax, 0x4220d0
0x00406d8a:	pushl $0x41c968<UINT32>
0x00406d8f:	pushl %edi
0x00406d90:	movl 0x4241fc, %eax
0x00406d95:	call GetProcAddress@KERNEL32.DLL
0x00406d97:	xorl %eax, 0x4220d0
0x00406d9d:	pushl $0x41c988<UINT32>
0x00406da2:	pushl %edi
0x00406da3:	movl 0x424200, %eax
0x00406da8:	call GetProcAddress@KERNEL32.DLL
0x00406daa:	xorl %eax, 0x4220d0
0x00406db0:	pushl $0x41c9a4<UINT32>
0x00406db5:	pushl %edi
0x00406db6:	movl 0x424204, %eax
0x00406dbb:	call GetProcAddress@KERNEL32.DLL
0x00406dbd:	xorl %eax, 0x4220d0
0x00406dc3:	pushl $0x41c9c4<UINT32>
0x00406dc8:	pushl %edi
0x00406dc9:	movl 0x424208, %eax
0x00406dce:	call GetProcAddress@KERNEL32.DLL
0x00406dd0:	xorl %eax, 0x4220d0
0x00406dd6:	pushl $0x41c9d8<UINT32>
0x00406ddb:	pushl %edi
0x00406ddc:	movl 0x42420c, %eax
0x00406de1:	call GetProcAddress@KERNEL32.DLL
0x00406de3:	xorl %eax, 0x4220d0
0x00406de9:	pushl $0x41c9f4<UINT32>
0x00406dee:	pushl %edi
0x00406def:	movl 0x424210, %eax
0x00406df4:	call GetProcAddress@KERNEL32.DLL
0x00406df6:	xorl %eax, 0x4220d0
0x00406dfc:	pushl $0x41ca08<UINT32>
0x00406e01:	pushl %edi
0x00406e02:	movl 0x424218, %eax
0x00406e07:	call GetProcAddress@KERNEL32.DLL
0x00406e09:	xorl %eax, 0x4220d0
0x00406e0f:	pushl $0x41ca18<UINT32>
0x00406e14:	pushl %edi
0x00406e15:	movl 0x424214, %eax
0x00406e1a:	call GetProcAddress@KERNEL32.DLL
0x00406e1c:	xorl %eax, 0x4220d0
0x00406e22:	pushl $0x41ca28<UINT32>
0x00406e27:	pushl %edi
0x00406e28:	movl 0x42421c, %eax
0x00406e2d:	call GetProcAddress@KERNEL32.DLL
0x00406e2f:	xorl %eax, 0x4220d0
0x00406e35:	pushl $0x41ca38<UINT32>
0x00406e3a:	pushl %edi
0x00406e3b:	movl 0x424220, %eax
0x00406e40:	call GetProcAddress@KERNEL32.DLL
0x00406e42:	xorl %eax, 0x4220d0
0x00406e48:	pushl $0x41ca48<UINT32>
0x00406e4d:	pushl %edi
0x00406e4e:	movl 0x424224, %eax
0x00406e53:	call GetProcAddress@KERNEL32.DLL
0x00406e55:	xorl %eax, 0x4220d0
0x00406e5b:	pushl $0x41ca64<UINT32>
0x00406e60:	pushl %edi
0x00406e61:	movl 0x424228, %eax
0x00406e66:	call GetProcAddress@KERNEL32.DLL
0x00406e68:	xorl %eax, 0x4220d0
0x00406e6e:	pushl $0x41ca78<UINT32>
0x00406e73:	pushl %edi
0x00406e74:	movl 0x42422c, %eax
0x00406e79:	call GetProcAddress@KERNEL32.DLL
0x00406e7b:	xorl %eax, 0x4220d0
0x00406e81:	pushl $0x41ca88<UINT32>
0x00406e86:	pushl %edi
0x00406e87:	movl 0x424230, %eax
0x00406e8c:	call GetProcAddress@KERNEL32.DLL
0x00406e8e:	xorl %eax, 0x4220d0
0x00406e94:	pushl $0x41ca9c<UINT32>
0x00406e99:	pushl %edi
0x00406e9a:	movl 0x424234, %eax
0x00406e9f:	call GetProcAddress@KERNEL32.DLL
0x00406ea1:	xorl %eax, 0x4220d0
0x00406ea7:	movl 0x424238, %eax
0x00406eac:	pushl $0x41caac<UINT32>
0x00406eb1:	pushl %edi
0x00406eb2:	call GetProcAddress@KERNEL32.DLL
0x00406eb4:	xorl %eax, 0x4220d0
0x00406eba:	pushl $0x41cacc<UINT32>
0x00406ebf:	pushl %edi
0x00406ec0:	movl 0x42423c, %eax
0x00406ec5:	call GetProcAddress@KERNEL32.DLL
0x00406ec7:	xorl %eax, 0x4220d0
0x00406ecd:	popl %edi
0x00406ece:	movl 0x424240, %eax
0x00406ed3:	popl %esi
0x00406ed4:	ret

0x00406837:	call 0x00406b10
0x00406b10:	pushl %esi
0x00406b11:	pushl %edi
0x00406b12:	movl %esi, $0x422c28<UINT32>
0x00406b17:	movl %edi, $0x423390<UINT32>
0x00406b1c:	cmpl 0x4(%esi), $0x1<UINT8>
0x00406b20:	jne 22
0x00406b22:	pushl $0x0<UINT8>
0x00406b24:	movl (%esi), %edi
0x00406b26:	addl %edi, $0x18<UINT8>
0x00406b29:	pushl $0xfa0<UINT32>
0x00406b2e:	pushl (%esi)
0x00406b30:	call 0x00406bdc
0x00406bdc:	pushl %ebp
0x00406bdd:	movl %ebp, %esp
0x00406bdf:	movl %eax, 0x4241d0
0x00406be4:	xorl %eax, 0x4220d0
0x00406bea:	je 13
0x00406bec:	pushl 0x10(%ebp)
0x00406bef:	pushl 0xc(%ebp)
0x00406bf2:	pushl 0x8(%ebp)
0x00406bf5:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x00406bf7:	popl %ebp
0x00406bf8:	ret

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
