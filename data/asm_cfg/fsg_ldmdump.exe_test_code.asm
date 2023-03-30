0x0042e000:	movl %ebx, $0x4001d0<UINT32>
0x0042e005:	movl %edi, $0x401000<UINT32>
0x0042e00a:	movl %esi, $0x425000<UINT32>
0x0042e00f:	pushl %ebx
0x0042e010:	call 0x0042e01f
0x0042e01f:	cld
0x0042e020:	movb %dl, $0xffffff80<UINT8>
0x0042e022:	movsb %es:(%edi), %ds:(%esi)
0x0042e023:	pushl $0x2<UINT8>
0x0042e025:	popl %ebx
0x0042e026:	call 0x0042e015
0x0042e015:	addb %dl, %dl
0x0042e017:	jne 0x0042e01e
0x0042e019:	movb %dl, (%esi)
0x0042e01b:	incl %esi
0x0042e01c:	adcb %dl, %dl
0x0042e01e:	ret

0x0042e029:	jae 0x0042e022
0x0042e02b:	xorl %ecx, %ecx
0x0042e02d:	call 0x0042e015
0x0042e030:	jae 0x0042e04a
0x0042e032:	xorl %eax, %eax
0x0042e034:	call 0x0042e015
0x0042e037:	jae 0x0042e05a
0x0042e039:	movb %bl, $0x2<UINT8>
0x0042e03b:	incl %ecx
0x0042e03c:	movb %al, $0x10<UINT8>
0x0042e03e:	call 0x0042e015
0x0042e041:	adcb %al, %al
0x0042e043:	jae 0x0042e03e
0x0042e045:	jne 0x0042e086
0x0042e047:	stosb %es:(%edi), %al
0x0042e048:	jmp 0x0042e026
0x0042e086:	pushl %esi
0x0042e087:	movl %esi, %edi
0x0042e089:	subl %esi, %eax
0x0042e08b:	rep movsb %es:(%edi), %ds:(%esi)
0x0042e08d:	popl %esi
0x0042e08e:	jmp 0x0042e026
0x0042e05a:	lodsb %al, %ds:(%esi)
0x0042e05b:	shrl %eax
0x0042e05d:	je 0x0042e0a0
0x0042e05f:	adcl %ecx, %ecx
0x0042e061:	jmp 0x0042e07f
0x0042e07f:	incl %ecx
0x0042e080:	incl %ecx
0x0042e081:	xchgl %ebp, %eax
0x0042e082:	movl %eax, %ebp
0x0042e084:	movb %bl, $0x1<UINT8>
0x0042e04a:	call 0x0042e092
0x0042e092:	incl %ecx
0x0042e093:	call 0x0042e015
0x0042e097:	adcl %ecx, %ecx
0x0042e099:	call 0x0042e015
0x0042e09d:	jb 0x0042e093
0x0042e09f:	ret

0x0042e04f:	subl %ecx, %ebx
0x0042e051:	jne 0x0042e063
0x0042e053:	call 0x0042e090
0x0042e090:	xorl %ecx, %ecx
0x0042e058:	jmp 0x0042e082
0x0042e063:	xchgl %ecx, %eax
0x0042e064:	decl %eax
0x0042e065:	shll %eax, $0x8<UINT8>
0x0042e068:	lodsb %al, %ds:(%esi)
0x0042e069:	call 0x0042e090
0x0042e06e:	cmpl %eax, $0x7d00<UINT32>
0x0042e073:	jae 0x0042e07f
0x0042e075:	cmpb %ah, $0x5<UINT8>
0x0042e078:	jae 0x0042e080
0x0042e07a:	cmpl %eax, $0x7f<UINT8>
0x0042e07d:	ja 0x0042e081
0x0042e0a0:	popl %edi
0x0042e0a1:	popl %ebx
0x0042e0a2:	movzwl %edi, (%ebx)
0x0042e0a5:	decl %edi
0x0042e0a6:	je 0x0042e0b0
0x0042e0a8:	decl %edi
0x0042e0a9:	je 0x0042e0be
0x0042e0ab:	shll %edi, $0xc<UINT8>
0x0042e0ae:	jmp 0x0042e0b7
0x0042e0b7:	incl %ebx
0x0042e0b8:	incl %ebx
0x0042e0b9:	jmp 0x0042e00f
0x0042e0b0:	movl %edi, 0x2(%ebx)
0x0042e0b3:	pushl %edi
0x0042e0b4:	addl %ebx, $0x4<UINT8>
0x0042e0be:	popl %edi
0x0042e0bf:	movl %ebx, $0x42e128<UINT32>
0x0042e0c4:	incl %edi
0x0042e0c5:	movl %esi, (%edi)
0x0042e0c7:	scasl %eax, %es:(%edi)
0x0042e0c8:	pushl %edi
0x0042e0c9:	call LoadLibraryA@KERNEL32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0042e0cb:	xchgl %ebp, %eax
0x0042e0cc:	xorl %eax, %eax
0x0042e0ce:	scasb %al, %es:(%edi)
0x0042e0cf:	jne 0x0042e0ce
0x0042e0d1:	decb (%edi)
0x0042e0d3:	je 0x0042e0c4
0x0042e0d5:	decb (%edi)
0x0042e0d7:	jne 0x0042e0df
0x0042e0df:	decb (%edi)
0x0042e0e1:	je 0x00403024
0x0042e0e7:	pushl %edi
0x0042e0e8:	pushl %ebp
0x0042e0e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x0042e0ec:	orl (%esi), %eax
0x0042e0ee:	lodsl %eax, %ds:(%esi)
0x0042e0ef:	jne 0x0042e0cc
GetProcAddress@KERNEL32.dll: API Node	
LoadLibraryA@KERNEL32.dll: API Node	
0x00403024:	pushl %ebp
0x00403025:	movl %ebp, %esp
0x00403027:	pushl $0xffffffff<UINT8>
0x00403029:	pushl $0x407130<UINT32>
0x0040302e:	pushl $0x404d64<UINT32>
0x00403033:	movl %eax, %fs:0
0x00403039:	pushl %eax
0x0040303a:	movl %fs:0, %esp
0x00403041:	subl %esp, $0x10<UINT8>
0x00403044:	pushl %ebx
0x00403045:	pushl %esi
0x00403046:	pushl %edi
0x00403047:	movl -24(%ebp), %esp
0x0040304a:	call GetVersion@KERNEL32.dll
GetVersion@KERNEL32.dll: API Node	
0x00403050:	xorl %edx, %edx
0x00403052:	movb %dl, %ah
0x00403054:	movl 0x423454, %edx
0x0040305a:	movl %ecx, %eax
0x0040305c:	andl %ecx, $0xff<UINT32>
0x00403062:	movl 0x423450, %ecx
0x00403068:	shll %ecx, $0x8<UINT8>
0x0040306b:	addl %ecx, %edx
0x0040306d:	movl 0x42344c, %ecx
0x00403073:	shrl %eax, $0x10<UINT8>
0x00403076:	movl 0x423448, %eax
0x0040307b:	pushl $0x0<UINT8>
0x0040307d:	call 0x00403af4
0x00403af4:	xorl %eax, %eax
0x00403af6:	pushl $0x0<UINT8>
0x00403af8:	cmpl 0x8(%esp), %eax
0x00403afc:	pushl $0x1000<UINT32>
0x00403b01:	sete %al
0x00403b04:	pushl %eax
0x00403b05:	call HeapCreate@KERNEL32.dll
HeapCreate@KERNEL32.dll: API Node	
0x00403b0b:	testl %eax, %eax
0x00403b0d:	movl 0x423d5c, %eax
0x00403b12:	je 21
0x00403b14:	call 0x00403b30
0x00403b30:	pushl $0x140<UINT32>
0x00403b35:	pushl $0x0<UINT8>
0x00403b37:	pushl 0x423d5c
0x00403b3d:	call HeapAlloc@KERNEL32.dll
HeapAlloc@KERNEL32.dll: API Node	
0x00403b43:	testl %eax, %eax
0x00403b45:	movl 0x423d58, %eax
0x00403b4a:	jne 0x00403b4d
0x00403b4d:	andl 0x423d50, $0x0<UINT8>
0x00403b54:	andl 0x423d54, $0x0<UINT8>
0x00403b5b:	pushl $0x1<UINT8>
0x00403b5d:	movl 0x423d4c, %eax
0x00403b62:	movl 0x423d44, $0x10<UINT32>
0x00403b6c:	popl %eax
0x00403b6d:	ret

0x00403b19:	testl %eax, %eax
0x00403b1b:	jne 0x00403b2c
0x00403b2c:	pushl $0x1<UINT8>
0x00403b2e:	popl %eax
0x00403b2f:	ret

0x00403082:	popl %ecx
0x00403083:	testl %eax, %eax
0x00403085:	jne 0x0040308f
0x0040308f:	andl -4(%ebp), $0x0<UINT8>
0x00403093:	call 0x00404abf
0x00404abf:	subl %esp, $0x44<UINT8>
0x00404ac2:	pushl %ebx
0x00404ac3:	pushl %ebp
0x00404ac4:	pushl %esi
0x00404ac5:	pushl %edi
0x00404ac6:	pushl $0x100<UINT32>
0x00404acb:	call 0x00402d84
0x00402d84:	pushl 0x4234a0
0x00402d8a:	pushl 0x8(%esp)
0x00402d8e:	call 0x00402d96
0x00402d96:	cmpl 0x4(%esp), $0xffffffe0<UINT8>
0x00402d9b:	ja 34
0x00402d9d:	pushl 0x4(%esp)
0x00402da1:	call 0x00402dc2
0x00402dc2:	pushl %esi
0x00402dc3:	movl %esi, 0x8(%esp)
0x00402dc7:	cmpl %esi, 0x422e54
0x00402dcd:	ja 0x00402dda
0x00402dcf:	pushl %esi
0x00402dd0:	call 0x00403ec4
0x00403ec4:	pushl %ebp
0x00403ec5:	movl %ebp, %esp
0x00403ec7:	subl %esp, $0x14<UINT8>
0x00403eca:	movl %eax, 0x423d54
0x00403ecf:	movl %edx, 0x423d58
0x00403ed5:	pushl %ebx
0x00403ed6:	pushl %esi
0x00403ed7:	leal %eax, (%eax,%eax,4)
0x00403eda:	pushl %edi
0x00403edb:	leal %edi, (%edx,%eax,4)
0x00403ede:	movl %eax, 0x8(%ebp)
0x00403ee1:	movl -4(%ebp), %edi
0x00403ee4:	leal %ecx, 0x17(%eax)
0x00403ee7:	andl %ecx, $0xfffffff0<UINT8>
0x00403eea:	movl -16(%ebp), %ecx
0x00403eed:	sarl %ecx, $0x4<UINT8>
0x00403ef0:	decl %ecx
0x00403ef1:	cmpl %ecx, $0x20<UINT8>
0x00403ef4:	jnl 14
0x00403ef6:	orl %esi, $0xffffffff<UINT8>
0x00403ef9:	shrl %esi, %cl
0x00403efb:	orl -8(%ebp), $0xffffffff<UINT8>
0x00403eff:	movl -12(%ebp), %esi
0x00403f02:	jmp 0x00403f14
0x00403f14:	movl %eax, 0x423d4c
0x00403f19:	movl %ebx, %eax
0x00403f1b:	cmpl %ebx, %edi
0x00403f1d:	movl 0x8(%ebp), %ebx
0x00403f20:	jae 0x00403f3b
0x00403f3b:	cmpl %ebx, -4(%ebp)
0x00403f3e:	jne 121
0x00403f40:	movl %ebx, %edx
0x00403f42:	cmpl %ebx, %eax
0x00403f44:	movl 0x8(%ebp), %ebx
0x00403f47:	jae 0x00403f5e
0x00403f5e:	jne 89
0x00403f60:	cmpl %ebx, -4(%ebp)
0x00403f63:	jae 0x00403f76
0x00403f76:	jne 38
0x00403f78:	movl %ebx, %edx
0x00403f7a:	cmpl %ebx, %eax
0x00403f7c:	movl 0x8(%ebp), %ebx
0x00403f7f:	jae 0x00403f8e
0x00403f8e:	jne 14
0x00403f90:	call 0x004041cd
0x004041cd:	movl %eax, 0x423d54
0x004041d2:	movl %ecx, 0x423d44
0x004041d8:	pushl %esi
0x004041d9:	pushl %edi
0x004041da:	xorl %edi, %edi
0x004041dc:	cmpl %eax, %ecx
0x004041de:	jne 0x00404210
0x00404210:	movl %ecx, 0x423d58
0x00404216:	pushl $0x41c4<UINT32>
0x0040421b:	pushl $0x8<UINT8>
0x0040421d:	leal %eax, (%eax,%eax,4)
0x00404220:	pushl 0x423d5c
0x00404226:	leal %esi, (%ecx,%eax,4)
0x00404229:	call HeapAlloc@KERNEL32.dll
0x0040422f:	cmpl %eax, %edi
0x00404231:	movl 0x10(%esi), %eax
0x00404234:	je 42
0x00404236:	pushl $0x4<UINT8>
0x00404238:	pushl $0x2000<UINT32>
0x0040423d:	pushl $0x100000<UINT32>
0x00404242:	pushl %edi
0x00404243:	call VirtualAlloc@KERNEL32.dll
VirtualAlloc@KERNEL32.dll: API Node	
0x00404249:	cmpl %eax, %edi
0x0040424b:	movl 0xc(%esi), %eax
0x0040424e:	jne 0x00404264
0x00404264:	orl 0x8(%esi), $0xffffffff<UINT8>
0x00404268:	movl (%esi), %edi
0x0040426a:	movl 0x4(%esi), %edi
0x0040426d:	incl 0x423d54
0x00404273:	movl %eax, 0x10(%esi)
0x00404276:	orl (%eax), $0xffffffff<UINT8>
0x00404279:	movl %eax, %esi
0x0040427b:	popl %edi
0x0040427c:	popl %esi
0x0040427d:	ret

0x00403f95:	movl %ebx, %eax
0x00403f97:	testl %ebx, %ebx
0x00403f99:	movl 0x8(%ebp), %ebx
0x00403f9c:	je 20
0x00403f9e:	pushl %ebx
0x00403f9f:	call 0x0040427e
0x0040427e:	pushl %ebp
0x0040427f:	movl %ebp, %esp
0x00404281:	pushl %ecx
0x00404282:	movl %ecx, 0x8(%ebp)
0x00404285:	pushl %ebx
0x00404286:	pushl %esi
0x00404287:	pushl %edi
0x00404288:	movl %esi, 0x10(%ecx)
0x0040428b:	movl %eax, 0x8(%ecx)
0x0040428e:	xorl %ebx, %ebx
0x00404290:	testl %eax, %eax
0x00404292:	jl 0x00404299
0x00404299:	movl %eax, %ebx
0x0040429b:	pushl $0x3f<UINT8>
0x0040429d:	imull %eax, %eax, $0x204<UINT32>
0x004042a3:	popl %edx
0x004042a4:	leal %eax, 0x144(%eax,%esi)
0x004042ab:	movl -4(%ebp), %eax
0x004042ae:	movl 0x8(%eax), %eax
0x004042b1:	movl 0x4(%eax), %eax
0x004042b4:	addl %eax, $0x8<UINT8>
0x004042b7:	decl %edx
0x004042b8:	jne 0x004042ae
0x004042ba:	movl %edi, %ebx
0x004042bc:	pushl $0x4<UINT8>
0x004042be:	shll %edi, $0xf<UINT8>
0x004042c1:	addl %edi, 0xc(%ecx)
0x004042c4:	pushl $0x1000<UINT32>
0x004042c9:	pushl $0x8000<UINT32>
0x004042ce:	pushl %edi
0x004042cf:	call VirtualAlloc@KERNEL32.dll
0x004042d5:	testl %eax, %eax
0x004042d7:	jne 0x004042e1
0x004042e1:	leal %edx, 0x7000(%edi)
0x004042e7:	cmpl %edi, %edx
0x004042e9:	ja 60
0x004042eb:	leal %eax, 0x10(%edi)
0x004042ee:	orl -8(%eax), $0xffffffff<UINT8>
0x004042f2:	orl 0xfec(%eax), $0xffffffff<UINT8>
0x004042f9:	leal %ecx, 0xffc(%eax)
0x004042ff:	movl -4(%eax), $0xff0<UINT32>
0x00404306:	movl (%eax), %ecx
0x00404308:	leal %ecx, -4100(%eax)
0x0040430e:	movl 0x4(%eax), %ecx
0x00404311:	movl 0xfe8(%eax), $0xff0<UINT32>
0x0040431b:	addl %eax, $0x1000<UINT32>
0x00404320:	leal %ecx, -16(%eax)
0x00404323:	cmpl %ecx, %edx
0x00404325:	jbe 0x004042ee
0x00404327:	movl %eax, -4(%ebp)
0x0040432a:	leal %ecx, 0xc(%edi)
0x0040432d:	addl %eax, $0x1f8<UINT32>
0x00404332:	pushl $0x1<UINT8>
0x00404334:	popl %edi
0x00404335:	movl 0x4(%eax), %ecx
0x00404338:	movl 0x8(%ecx), %eax
0x0040433b:	leal %ecx, 0xc(%edx)
0x0040433e:	movl 0x8(%eax), %ecx
0x00404341:	movl 0x4(%ecx), %eax
0x00404344:	andl 0x44(%esi,%ebx,4), $0x0<UINT8>
0x00404349:	movl 0xc4(%esi,%ebx,4), %edi
0x00404350:	movb %al, 0x43(%esi)
0x00404353:	movb %cl, %al
0x00404355:	incb %cl
0x00404357:	testb %al, %al
0x00404359:	movl %eax, 0x8(%ebp)
0x0040435c:	movb 0x43(%esi), %cl
0x0040435f:	jne 3
0x00404361:	orl 0x4(%eax), %edi
0x00404364:	movl %edx, $0x80000000<UINT32>
0x00404369:	movl %ecx, %ebx
0x0040436b:	shrl %edx, %cl
0x0040436d:	notl %edx
0x0040436f:	andl 0x8(%eax), %edx
0x00404372:	movl %eax, %ebx
0x00404374:	popl %edi
0x00404375:	popl %esi
0x00404376:	popl %ebx
0x00404377:	leave
0x00404378:	ret

0x00403fa4:	popl %ecx
0x00403fa5:	movl %ecx, 0x10(%ebx)
0x00403fa8:	movl (%ecx), %eax
0x00403faa:	movl %eax, 0x10(%ebx)
0x00403fad:	cmpl (%eax), $0xffffffff<UINT8>
0x00403fb0:	jne 0x00403fb9
0x00403fb9:	movl 0x423d4c, %ebx
0x00403fbf:	movl %eax, 0x10(%ebx)
0x00403fc2:	movl %edx, (%eax)
0x00403fc4:	cmpl %edx, $0xffffffff<UINT8>
0x00403fc7:	movl -4(%ebp), %edx
0x00403fca:	je 20
0x00403fcc:	movl %ecx, 0xc4(%eax,%edx,4)
0x00403fd3:	movl %edi, 0x44(%eax,%edx,4)
0x00403fd7:	andl %ecx, -8(%ebp)
0x00403fda:	andl %edi, %esi
0x00403fdc:	orl %ecx, %edi
0x00403fde:	jne 0x00404017
0x00404017:	movl %ecx, %edx
0x00404019:	xorl %edi, %edi
0x0040401b:	imull %ecx, %ecx, $0x204<UINT32>
0x00404021:	leal %ecx, 0x144(%ecx,%eax)
0x00404028:	movl -12(%ebp), %ecx
0x0040402b:	movl %ecx, 0x44(%eax,%edx,4)
0x0040402f:	andl %ecx, %esi
0x00404031:	jne 13
0x00404033:	movl %ecx, 0xc4(%eax,%edx,4)
0x0040403a:	pushl $0x20<UINT8>
0x0040403c:	andl %ecx, -8(%ebp)
0x0040403f:	popl %edi
0x00404040:	testl %ecx, %ecx
0x00404042:	jl 0x00404049
0x00404044:	shll %ecx
0x00404046:	incl %edi
0x00404047:	jmp 0x00404040
0x00404049:	movl %ecx, -12(%ebp)
0x0040404c:	movl %edx, 0x4(%ecx,%edi,8)
0x00404050:	movl %ecx, (%edx)
0x00404052:	subl %ecx, -16(%ebp)
0x00404055:	movl %esi, %ecx
0x00404057:	movl -8(%ebp), %ecx
0x0040405a:	sarl %esi, $0x4<UINT8>
0x0040405d:	decl %esi
0x0040405e:	cmpl %esi, $0x3f<UINT8>
0x00404061:	jle 3
0x00404063:	pushl $0x3f<UINT8>
0x00404065:	popl %esi
0x00404066:	cmpl %esi, %edi
0x00404068:	je 0x0040417b
0x0040417b:	testl %ecx, %ecx
0x0040417d:	je 11
0x0040417f:	movl (%edx), %ecx
0x00404181:	movl -4(%ecx,%edx), %ecx
0x00404185:	jmp 0x0040418a
0x0040418a:	movl %esi, -16(%ebp)
0x0040418d:	addl %edx, %ecx
0x0040418f:	leal %ecx, 0x1(%esi)
0x00404192:	movl (%edx), %ecx
0x00404194:	movl -4(%edx,%esi), %ecx
0x00404198:	movl %esi, -12(%ebp)
0x0040419b:	movl %ecx, (%esi)
0x0040419d:	testl %ecx, %ecx
0x0040419f:	leal %edi, 0x1(%ecx)
0x004041a2:	movl (%esi), %edi
0x004041a4:	jne 26
0x004041a6:	cmpl %ebx, 0x423d50
0x004041ac:	jne 0x004041c0
0x004041c0:	movl %ecx, -4(%ebp)
0x004041c3:	movl (%eax), %ecx
0x004041c5:	leal %eax, 0x4(%edx)
0x004041c8:	popl %edi
0x004041c9:	popl %esi
0x004041ca:	popl %ebx
0x004041cb:	leave
0x004041cc:	ret

0x00402dd5:	testl %eax, %eax
0x00402dd7:	popl %ecx
0x00402dd8:	jne 0x00402df6
0x00402df6:	popl %esi
0x00402df7:	ret

0x00402da6:	testl %eax, %eax
0x00402da8:	popl %ecx
0x00402da9:	jne 0x00402dc1
0x00402dc1:	ret

0x00402d93:	popl %ecx
0x00402d94:	popl %ecx
0x00402d95:	ret

0x00404ad0:	movl %esi, %eax
0x00404ad2:	popl %ecx
0x00404ad3:	testl %esi, %esi
0x00404ad5:	jne 0x00404adf
0x00404adf:	movl 0x423c40, %esi
0x00404ae5:	movl 0x423d40, $0x20<UINT32>
0x00404aef:	leal %eax, 0x100(%esi)
0x00404af5:	cmpl %esi, %eax
0x00404af7:	jae 0x00404b13
0x00404af9:	andb 0x4(%esi), $0x0<UINT8>
0x00404afd:	orl (%esi), $0xffffffff<UINT8>
0x00404b00:	movb 0x5(%esi), $0xa<UINT8>
0x00404b04:	movl %eax, 0x423c40
0x00404b09:	addl %esi, $0x8<UINT8>
0x00404b0c:	addl %eax, $0x100<UINT32>
0x00404b11:	jmp 0x00404af5
0x00404b13:	leal %eax, 0x10(%esp)
0x00404b17:	pushl %eax
0x00404b18:	call GetStartupInfoA@KERNEL32.dll
GetStartupInfoA@KERNEL32.dll: API Node	
0x00404b1e:	cmpw 0x42(%esp), $0x0<UINT8>
0x00404b24:	je 197
0x00404b2a:	movl %eax, 0x44(%esp)
0x00404b2e:	testl %eax, %eax
0x00404b30:	je 185
0x00404b36:	movl %esi, (%eax)
0x00404b38:	leal %ebp, 0x4(%eax)
0x00404b3b:	movl %eax, $0x800<UINT32>
0x00404b40:	cmpl %esi, %eax
0x00404b42:	leal %ebx, (%esi,%ebp)
0x00404b45:	jl 0x00404b49
0x00404b49:	cmpl 0x423d40, %esi
0x00404b4f:	jnl 0x00404ba3
0x00404ba3:	xorl %edi, %edi
0x00404ba5:	testl %esi, %esi
0x00404ba7:	jle 0x00404bef
0x00404bef:	xorl %ebx, %ebx
0x00404bf1:	movl %eax, 0x423c40
0x00404bf6:	cmpl (%eax,%ebx,8), $0xffffffff<UINT8>
0x00404bfa:	leal %esi, (%eax,%ebx,8)
0x00404bfd:	jne 77
0x00404bff:	testl %ebx, %ebx
0x00404c01:	movb 0x4(%esi), $0xffffff81<UINT8>
0x00404c05:	jne 0x00404c0c
0x00404c07:	pushl $0xfffffff6<UINT8>
0x00404c09:	popl %eax
0x00404c0a:	jmp 0x00404c16
0x00404c16:	pushl %eax
0x00404c17:	call GetStdHandle@KERNEL32.dll
GetStdHandle@KERNEL32.dll: API Node	
0x00404c1d:	movl %edi, %eax
0x00404c1f:	cmpl %edi, $0xffffffff<UINT8>
0x00404c22:	je 23
0x00404c24:	pushl %edi
0x00404c25:	call GetFileType@KERNEL32.dll
GetFileType@KERNEL32.dll: API Node	
0x00404c2b:	testl %eax, %eax
0x00404c2d:	je 12
0x00404c2f:	andl %eax, $0xff<UINT32>
0x00404c34:	movl (%esi), %edi
0x00404c36:	cmpl %eax, $0x2<UINT8>
0x00404c39:	jne 6
0x00404c3b:	orb 0x4(%esi), $0x40<UINT8>
0x00404c3f:	jmp 0x00404c50
0x00404c50:	incl %ebx
0x00404c51:	cmpl %ebx, $0x3<UINT8>
0x00404c54:	jl 0x00404bf1
0x00404c0c:	movl %eax, %ebx
0x00404c0e:	decl %eax
0x00404c0f:	negl %eax
0x00404c11:	sbbl %eax, %eax
0x00404c13:	addl %eax, $0xfffffff5<UINT8>
0x00404c56:	pushl 0x423d40
0x00404c5c:	call SetHandleCount@KERNEL32.dll
SetHandleCount@KERNEL32.dll: API Node	
0x00404c62:	popl %edi
0x00404c63:	popl %esi
0x00404c64:	popl %ebp
0x00404c65:	popl %ebx
0x00404c66:	addl %esp, $0x44<UINT8>
0x00404c69:	ret

0x00403098:	call GetCommandLineA@KERNEL32.dll
GetCommandLineA@KERNEL32.dll: API Node	
0x0040309e:	movl 0x424d84, %eax
0x004030a3:	call 0x0040498d
0x0040498d:	pushl %ecx
0x0040498e:	pushl %ecx
0x0040498f:	movl %eax, 0x4235b0
0x00404994:	pushl %ebx
0x00404995:	pushl %ebp
0x00404996:	movl %ebp, 0x4070e4
0x0040499c:	pushl %esi
0x0040499d:	pushl %edi
0x0040499e:	xorl %ebx, %ebx
0x004049a0:	xorl %esi, %esi
0x004049a2:	xorl %edi, %edi
0x004049a4:	cmpl %eax, %ebx
0x004049a6:	jne 51
0x004049a8:	call GetEnvironmentStringsW@KERNEL32.dll
GetEnvironmentStringsW@KERNEL32.dll: API Node	
0x004049aa:	movl %esi, %eax
0x004049ac:	cmpl %esi, %ebx
0x004049ae:	je 12
0x004049b0:	movl 0x4235b0, $0x1<UINT32>
0x004049ba:	jmp 0x004049e4
0x004049e4:	cmpl %esi, %ebx
0x004049e6:	jne 0x004049f4
0x004049f4:	cmpw (%esi), %bx
0x004049f7:	movl %eax, %esi
0x004049f9:	je 14
0x004049fb:	incl %eax
0x004049fc:	incl %eax
0x004049fd:	cmpw (%eax), %bx
0x00404a00:	jne 0x004049fb
0x00404a02:	incl %eax
0x00404a03:	incl %eax
0x00404a04:	cmpw (%eax), %bx
0x00404a07:	jne 0x004049fb
0x00404a09:	subl %eax, %esi
0x00404a0b:	movl %edi, 0x4070dc
0x00404a11:	sarl %eax
0x00404a13:	pushl %ebx
0x00404a14:	pushl %ebx
0x00404a15:	incl %eax
0x00404a16:	pushl %ebx
0x00404a17:	pushl %ebx
0x00404a18:	pushl %eax
0x00404a19:	pushl %esi
0x00404a1a:	pushl %ebx
0x00404a1b:	pushl %ebx
0x00404a1c:	movl 0x34(%esp), %eax
0x00404a20:	call WideCharToMultiByte@KERNEL32.dll
WideCharToMultiByte@KERNEL32.dll: API Node	
0x00404a22:	movl %ebp, %eax
0x00404a24:	cmpl %ebp, %ebx
0x00404a26:	je 50
0x00404a28:	pushl %ebp
0x00404a29:	call 0x00402d84
0x00402dda:	testl %esi, %esi
0x00402ddc:	jne 0x00402de1
0x00402de1:	addl %esi, $0xf<UINT8>
0x00402de4:	andl %esi, $0xfffffff0<UINT8>
0x00402de7:	pushl %esi
0x00402de8:	pushl $0x0<UINT8>
0x00402dea:	pushl 0x423d5c
0x00402df0:	call HeapAlloc@KERNEL32.dll
0x00404a2e:	cmpl %eax, %ebx
0x00404a30:	popl %ecx
0x00404a31:	movl 0x10(%esp), %eax
0x00404a35:	je 35
0x00404a37:	pushl %ebx
0x00404a38:	pushl %ebx
0x00404a39:	pushl %ebp
0x00404a3a:	pushl %eax
0x00404a3b:	pushl 0x24(%esp)
0x00404a3f:	pushl %esi
0x00404a40:	pushl %ebx
0x00404a41:	pushl %ebx
0x00404a42:	call WideCharToMultiByte@KERNEL32.dll
0x00404a44:	testl %eax, %eax
0x00404a46:	jne 0x00404a56
0x00404a56:	movl %ebx, 0x10(%esp)
0x00404a5a:	pushl %esi
0x00404a5b:	call FreeEnvironmentStringsW@KERNEL32.dll
FreeEnvironmentStringsW@KERNEL32.dll: API Node	
0x00404a61:	movl %eax, %ebx
0x00404a63:	jmp 0x00404ab8
0x00404ab8:	popl %edi
0x00404ab9:	popl %esi
0x00404aba:	popl %ebp
0x00404abb:	popl %ebx
0x00404abc:	popl %ecx
0x00404abd:	popl %ecx
0x00404abe:	ret

0x004030a8:	movl 0x423488, %eax
0x004030ad:	call 0x00404740
0x00404740:	pushl %ebp
0x00404741:	movl %ebp, %esp
0x00404743:	pushl %ecx
0x00404744:	pushl %ecx
0x00404745:	pushl %ebx
0x00404746:	xorl %ebx, %ebx
0x00404748:	cmpl 0x424d8c, %ebx
0x0040474e:	pushl %esi
0x0040474f:	pushl %edi
0x00404750:	jne 5
0x00404752:	call 0x00405f74
0x00405f74:	cmpl 0x424d8c, $0x0<UINT8>
0x00405f7b:	jne 18
0x00405f7d:	pushl $0xfffffffd<UINT8>
0x00405f7f:	call 0x00405bb0
0x00405bb0:	pushl %ebp
0x00405bb1:	movl %ebp, %esp
0x00405bb3:	subl %esp, $0x18<UINT8>
0x00405bb6:	pushl %ebx
0x00405bb7:	pushl %esi
0x00405bb8:	pushl %edi
0x00405bb9:	pushl 0x8(%ebp)
0x00405bbc:	call 0x00405d49
0x00405d49:	movl %eax, 0x4(%esp)
0x00405d4d:	andl 0x4235bc, $0x0<UINT8>
0x00405d54:	cmpl %eax, $0xfffffffe<UINT8>
0x00405d57:	jne 0x00405d69
0x00405d69:	cmpl %eax, $0xfffffffd<UINT8>
0x00405d6c:	jne 16
0x00405d6e:	movl 0x4235bc, $0x1<UINT32>
0x00405d78:	jmp GetACP@KERNEL32.dll
GetACP@KERNEL32.dll: API Node	
0x00405bc1:	movl %esi, %eax
0x00405bc3:	popl %ecx
0x00405bc4:	cmpl %esi, 0x423a00
0x00405bca:	movl 0x8(%ebp), %esi
0x00405bcd:	je 362
0x00405bd3:	xorl %ebx, %ebx
0x00405bd5:	cmpl %esi, %ebx
0x00405bd7:	je 342
0x00405bdd:	xorl %edx, %edx
0x00405bdf:	movl %eax, $0x4231c8<UINT32>
0x00405be4:	cmpl (%eax), %esi
0x00405be6:	je 114
0x00405be8:	addl %eax, $0x30<UINT8>
0x00405beb:	incl %edx
0x00405bec:	cmpl %eax, $0x4232b8<UINT32>
0x00405bf1:	jl 0x00405be4
0x00405bf3:	leal %eax, -24(%ebp)
0x00405bf6:	pushl %eax
0x00405bf7:	pushl %esi
0x00405bf8:	call GetCPInfo@KERNEL32.dll
GetCPInfo@KERNEL32.dll: API Node	
0x00405bfe:	cmpl %eax, $0x1<UINT8>
0x00405c01:	jne 292
0x00405c07:	pushl $0x40<UINT8>
0x00405c09:	xorl %eax, %eax
0x00405c0b:	popl %ecx
0x00405c0c:	movl %edi, $0x423b20<UINT32>
0x00405c11:	cmpl -24(%ebp), $0x1<UINT8>
0x00405c15:	movl 0x423a00, %esi
0x00405c1b:	rep stosl %es:(%edi), %eax
0x00405c1d:	stosb %es:(%edi), %al
0x00405c1e:	movl 0x423c24, %ebx
0x00405c24:	jbe 239
0x00405c2a:	cmpb -18(%ebp), $0x0<UINT8>
0x00405c2e:	je 0x00405cef
0x00405cef:	pushl $0x1<UINT8>
0x00405cf1:	popl %eax
0x00405cf2:	orb 0x423b21(%eax), $0x8<UINT8>
0x00405cf9:	incl %eax
0x00405cfa:	cmpl %eax, $0xff<UINT32>
0x00405cff:	jb 0x00405cf2
0x00405d01:	pushl %esi
0x00405d02:	call 0x00405d93
0x00405d93:	movl %eax, 0x4(%esp)
0x00405d97:	subl %eax, $0x3a4<UINT32>
0x00405d9c:	je 34
0x00405d9e:	subl %eax, $0x4<UINT8>
0x00405da1:	je 23
0x00405da3:	subl %eax, $0xd<UINT8>
0x00405da6:	je 12
0x00405da8:	decl %eax
0x00405da9:	je 3
0x00405dab:	xorl %eax, %eax
0x00405dad:	ret

0x00405d07:	popl %ecx
0x00405d08:	movl 0x423c24, %eax
0x00405d0d:	movl 0x423a1c, $0x1<UINT32>
0x00405d17:	jmp 0x00405d1f
0x00405d1f:	xorl %eax, %eax
0x00405d21:	movl %edi, $0x423a10<UINT32>
0x00405d26:	stosl %es:(%edi), %eax
0x00405d27:	stosl %es:(%edi), %eax
0x00405d28:	stosl %es:(%edi), %eax
0x00405d29:	jmp 0x00405d38
0x00405d38:	call 0x00405def
0x00405def:	pushl %ebp
0x00405df0:	movl %ebp, %esp
0x00405df2:	subl %esp, $0x514<UINT32>
0x00405df8:	leal %eax, -20(%ebp)
0x00405dfb:	pushl %esi
0x00405dfc:	pushl %eax
0x00405dfd:	pushl 0x423a00
0x00405e03:	call GetCPInfo@KERNEL32.dll
0x00405e09:	cmpl %eax, $0x1<UINT8>
0x00405e0c:	jne 278
0x00405e12:	xorl %eax, %eax
0x00405e14:	movl %esi, $0x100<UINT32>
0x00405e19:	movb -276(%ebp,%eax), %al
0x00405e20:	incl %eax
0x00405e21:	cmpl %eax, %esi
0x00405e23:	jb 0x00405e19
0x00405e25:	movb %al, -14(%ebp)
0x00405e28:	movb -276(%ebp), $0x20<UINT8>
0x00405e2f:	testb %al, %al
0x00405e31:	je 0x00405e6a
0x00405e6a:	pushl $0x0<UINT8>
0x00405e6c:	leal %eax, -1300(%ebp)
0x00405e72:	pushl 0x423c24
0x00405e78:	pushl 0x423a00
0x00405e7e:	pushl %eax
0x00405e7f:	leal %eax, -276(%ebp)
0x00405e85:	pushl %esi
0x00405e86:	pushl %eax
0x00405e87:	pushl $0x1<UINT8>
0x00405e89:	call 0x00405970
0x00405970:	pushl %ebp
0x00405971:	movl %ebp, %esp
0x00405973:	pushl $0xffffffff<UINT8>
0x00405975:	pushl $0x4074a8<UINT32>
0x0040597a:	pushl $0x404d64<UINT32>
0x0040597f:	movl %eax, %fs:0
0x00405985:	pushl %eax
0x00405986:	movl %fs:0, %esp
0x0040598d:	subl %esp, $0x18<UINT8>
0x00405990:	pushl %ebx
0x00405991:	pushl %esi
0x00405992:	pushl %edi
0x00405993:	movl -24(%ebp), %esp
0x00405996:	movl %eax, 0x4235b8
0x0040599b:	xorl %ebx, %ebx
0x0040599d:	cmpl %eax, %ebx
0x0040599f:	jne 62
0x004059a1:	leal %eax, -28(%ebp)
0x004059a4:	pushl %eax
0x004059a5:	pushl $0x1<UINT8>
0x004059a7:	popl %esi
0x004059a8:	pushl %esi
0x004059a9:	pushl $0x4074a4<UINT32>
0x004059ae:	pushl %esi
0x004059af:	call GetStringTypeW@KERNEL32.dll
GetStringTypeW@KERNEL32.dll: API Node	
0x004059b5:	testl %eax, %eax
0x004059b7:	je 4
0x004059b9:	movl %eax, %esi
0x004059bb:	jmp 0x004059da
0x004059da:	movl 0x4235b8, %eax
0x004059df:	cmpl %eax, $0x2<UINT8>
0x004059e2:	jne 0x00405a08
0x00405a08:	cmpl %eax, $0x1<UINT8>
0x00405a0b:	jne 148
0x00405a11:	cmpl 0x18(%ebp), %ebx
0x00405a14:	jne 0x00405a1e
0x00405a1e:	pushl %ebx
0x00405a1f:	pushl %ebx
0x00405a20:	pushl 0x10(%ebp)
0x00405a23:	pushl 0xc(%ebp)
0x00405a26:	movl %eax, 0x20(%ebp)
0x00405a29:	negl %eax
0x00405a2b:	sbbl %eax, %eax
0x00405a2d:	andl %eax, $0x8<UINT8>
0x00405a30:	incl %eax
0x00405a31:	pushl %eax
0x00405a32:	pushl 0x18(%ebp)
0x00405a35:	call MultiByteToWideChar@KERNEL32.dll
MultiByteToWideChar@KERNEL32.dll: API Node	
0x00405a3b:	movl -32(%ebp), %eax
0x00405a3e:	cmpl %eax, %ebx
0x00405a40:	je 99
0x00405a42:	movl -4(%ebp), %ebx
0x00405a45:	leal %edi, (%eax,%eax)
0x00405a48:	movl %eax, %edi
0x00405a4a:	addl %eax, $0x3<UINT8>
0x00405a4d:	andb %al, $0xfffffffc<UINT8>
0x00405a4f:	call 0x00406680
0x00406680:	pushl %ecx
0x00406681:	cmpl %eax, $0x1000<UINT32>
0x00406686:	leal %ecx, 0x8(%esp)
0x0040668a:	jb 0x004066a0
0x004066a0:	subl %ecx, %eax
0x004066a2:	movl %eax, %esp
0x004066a4:	testl (%ecx), %eax
0x004066a6:	movl %esp, %ecx
0x004066a8:	movl %ecx, (%eax)
0x004066aa:	movl %eax, 0x4(%eax)
0x004066ad:	pushl %eax
0x004066ae:	ret

0x00405a54:	movl -24(%ebp), %esp
0x00405a57:	movl %esi, %esp
0x00405a59:	movl -36(%ebp), %esi
0x00405a5c:	pushl %edi
0x00405a5d:	pushl %ebx
0x00405a5e:	pushl %esi
0x00405a5f:	call 0x004064b0
0x004064b0:	movl %edx, 0xc(%esp)
0x004064b4:	movl %ecx, 0x4(%esp)
0x004064b8:	testl %edx, %edx
0x004064ba:	je 71
0x004064bc:	xorl %eax, %eax
0x004064be:	movb %al, 0x8(%esp)
0x004064c2:	pushl %edi
0x004064c3:	movl %edi, %ecx
0x004064c5:	cmpl %edx, $0x4<UINT8>
0x004064c8:	jb 45
0x004064ca:	negl %ecx
0x004064cc:	andl %ecx, $0x3<UINT8>
0x004064cf:	je 0x004064d9
0x004064d9:	movl %ecx, %eax
0x004064db:	shll %eax, $0x8<UINT8>
0x004064de:	addl %eax, %ecx
0x004064e0:	movl %ecx, %eax
0x004064e2:	shll %eax, $0x10<UINT8>
0x004064e5:	addl %eax, %ecx
0x004064e7:	movl %ecx, %edx
0x004064e9:	andl %edx, $0x3<UINT8>
0x004064ec:	shrl %ecx, $0x2<UINT8>
0x004064ef:	je 6
0x004064f1:	rep stosl %es:(%edi), %eax
