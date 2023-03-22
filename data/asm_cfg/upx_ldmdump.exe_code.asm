0x00426150:	pusha
0x00426151:	movl %esi, $0x41e000<UINT32>
0x00426156:	leal %edi, -118784(%esi)
0x0042615c:	pushl %edi
0x0042615d:	jmp 0x0042616a
0x0042616a:	movl %ebx, (%esi)
0x0042616c:	subl %esi, $0xfffffffc<UINT8>
0x0042616f:	adcl %ebx, %ebx
0x00426171:	jb 0x00426160
0x00426160:	movb %al, (%esi)
0x00426162:	incl %esi
0x00426163:	movb (%edi), %al
0x00426165:	incl %edi
0x00426166:	addl %ebx, %ebx
0x00426168:	jne 0x00426171
0x00426173:	movl %eax, $0x1<UINT32>
0x00426178:	addl %ebx, %ebx
0x0042617a:	jne 0x00426183
0x00426183:	adcl %eax, %eax
0x00426185:	addl %ebx, %ebx
0x00426187:	jae 0x00426178
0x00426189:	jne 0x00426194
0x00426194:	xorl %ecx, %ecx
0x00426196:	subl %eax, $0x3<UINT8>
0x00426199:	jb 0x004261a8
0x0042619b:	shll %eax, $0x8<UINT8>
0x0042619e:	movb %al, (%esi)
0x004261a0:	incl %esi
0x004261a1:	xorl %eax, $0xffffffff<UINT8>
0x004261a4:	je 0x0042621a
0x004261a6:	movl %ebp, %eax
0x004261a8:	addl %ebx, %ebx
0x004261aa:	jne 0x004261b3
0x004261b3:	adcl %ecx, %ecx
0x004261b5:	addl %ebx, %ebx
0x004261b7:	jne 0x004261c0
0x004261c0:	adcl %ecx, %ecx
0x004261c2:	jne 0x004261e4
0x004261e4:	cmpl %ebp, $0xfffff300<UINT32>
0x004261ea:	adcl %ecx, $0x1<UINT8>
0x004261ed:	leal %edx, (%edi,%ebp)
0x004261f0:	cmpl %ebp, $0xfffffffc<UINT8>
0x004261f3:	jbe 0x00426204
0x00426204:	movl %eax, (%edx)
0x00426206:	addl %edx, $0x4<UINT8>
0x00426209:	movl (%edi), %eax
0x0042620b:	addl %edi, $0x4<UINT8>
0x0042620e:	subl %ecx, $0x4<UINT8>
0x00426211:	ja 0x00426204
0x00426213:	addl %edi, %ecx
0x00426215:	jmp 0x00426166
0x004261c4:	incl %ecx
0x004261c5:	addl %ebx, %ebx
0x004261c7:	jne 0x004261d0
0x004261d0:	adcl %ecx, %ecx
0x004261d2:	addl %ebx, %ebx
0x004261d4:	jae 0x004261c5
0x004261d6:	jne 0x004261e1
0x004261e1:	addl %ecx, $0x2<UINT8>
0x0042618b:	movl %ebx, (%esi)
0x0042618d:	subl %esi, $0xfffffffc<UINT8>
0x00426190:	adcl %ebx, %ebx
0x00426192:	jae 0x00426178
0x004261f5:	movb %al, (%edx)
0x004261f7:	incl %edx
0x004261f8:	movb (%edi), %al
0x004261fa:	incl %edi
0x004261fb:	decl %ecx
0x004261fc:	jne 0x004261f5
0x004261fe:	jmp 0x00426166
0x004261b9:	movl %ebx, (%esi)
0x004261bb:	subl %esi, $0xfffffffc<UINT8>
0x004261be:	adcl %ebx, %ebx
0x0042617c:	movl %ebx, (%esi)
0x0042617e:	subl %esi, $0xfffffffc<UINT8>
0x00426181:	adcl %ebx, %ebx
0x004261c9:	movl %ebx, (%esi)
0x004261cb:	subl %esi, $0xfffffffc<UINT8>
0x004261ce:	adcl %ebx, %ebx
0x004261ac:	movl %ebx, (%esi)
0x004261ae:	subl %esi, $0xfffffffc<UINT8>
0x004261b1:	adcl %ebx, %ebx
0x004261d8:	movl %ebx, (%esi)
0x004261da:	subl %esi, $0xfffffffc<UINT8>
0x004261dd:	adcl %ebx, %ebx
0x004261df:	jae 0x004261c5
0x0042621a:	popl %esi
0x0042621b:	movl %edi, %esi
0x0042621d:	movl %ecx, $0x1be<UINT32>
0x00426222:	movb %al, (%edi)
0x00426224:	incl %edi
0x00426225:	subb %al, $0xffffffe8<UINT8>
0x00426227:	cmpb %al, $0x1<UINT8>
0x00426229:	ja 0x00426222
0x0042622b:	cmpb (%edi), $0x6<UINT8>
0x0042622e:	jne 0x00426222
0x00426230:	movl %eax, (%edi)
0x00426232:	movb %bl, 0x4(%edi)
0x00426235:	shrw %ax, $0x8<UINT8>
0x00426239:	roll %eax, $0x10<UINT8>
0x0042623c:	xchgb %ah, %al
0x0042623e:	subl %eax, %edi
0x00426240:	subb %bl, $0xffffffe8<UINT8>
0x00426243:	addl %eax, %esi
0x00426245:	movl (%edi), %eax
0x00426247:	addl %edi, $0x5<UINT8>
0x0042624a:	movb %al, %bl
0x0042624c:	loop 0x00426227
0x0042624e:	leal %edi, 0x24000(%esi)
0x00426254:	movl %eax, (%edi)
0x00426256:	orl %eax, %eax
0x00426258:	je 0x00426296
0x0042625a:	movl %ebx, 0x4(%edi)
0x0042625d:	leal %eax, 0x26000(%eax,%esi)
0x00426264:	addl %ebx, %esi
0x00426266:	pushl %eax
0x00426267:	addl %edi, $0x8<UINT8>
0x0042626a:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00426270:	xchgl %ebp, %eax
0x00426271:	movb %al, (%edi)
0x00426273:	incl %edi
0x00426274:	orb %al, %al
0x00426276:	je 0x00426254
0x00426278:	movl %ecx, %edi
0x0042627a:	pushl %edi
0x0042627b:	decl %eax
0x0042627c:	repn scasb %al, %es:(%edi)
0x0042627e:	pushl %ebp
0x0042627f:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00426285:	orl %eax, %eax
0x00426287:	je 7
0x00426289:	movl (%ebx), %eax
0x0042628b:	addl %ebx, $0x4<UINT8>
0x0042628e:	jmp 0x00426271
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x00426296:	movl %ebp, 0x2609c(%esi)
0x0042629c:	leal %edi, -4096(%esi)
0x004262a2:	movl %ebx, $0x1000<UINT32>
0x004262a7:	pushl %eax
0x004262a8:	pushl %esp
0x004262a9:	pushl $0x4<UINT8>
0x004262ab:	pushl %ebx
0x004262ac:	pushl %edi
0x004262ad:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x004262af:	leal %eax, 0x1ff(%edi)
0x004262b5:	andb (%eax), $0x7f<UINT8>
0x004262b8:	andb 0x28(%eax), $0x7f<UINT8>
0x004262bc:	popl %eax
0x004262bd:	pushl %eax
0x004262be:	pushl %esp
0x004262bf:	pushl %eax
0x004262c0:	pushl %ebx
0x004262c1:	pushl %edi
0x004262c2:	call VirtualProtect@kernel32.dll
0x004262c4:	popl %eax
0x004262c5:	popa
0x004262c6:	leal %eax, -128(%esp)
0x004262ca:	pushl $0x0<UINT8>
0x004262cc:	cmpl %esp, %eax
0x004262ce:	jne 0x004262ca
0x004262d0:	subl %esp, $0xffffff80<UINT8>
0x004262d3:	jmp 0x00403024
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
0x0040304a:	call GetVersion@KERNEL32.DLL
GetVersion@KERNEL32.DLL: API Node	
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
0x00403b05:	call HeapCreate@KERNEL32.DLL
HeapCreate@KERNEL32.DLL: API Node	
0x00403b0b:	testl %eax, %eax
0x00403b0d:	movl 0x423d5c, %eax
0x00403b12:	je 21
0x00403b14:	call 0x00403b30
0x00403b30:	pushl $0x140<UINT32>
0x00403b35:	pushl $0x0<UINT8>
0x00403b37:	pushl 0x423d5c
0x00403b3d:	call HeapAlloc@KERNEL32.DLL
HeapAlloc@KERNEL32.DLL: API Node	
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
0x00403f3e:	jne 0x00403fb9
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
0x00404229:	call HeapAlloc@KERNEL32.DLL
0x0040422f:	cmpl %eax, %edi
0x00404231:	movl 0x10(%esi), %eax
0x00404234:	je 42
0x00404236:	pushl $0x4<UINT8>
0x00404238:	pushl $0x2000<UINT32>
0x0040423d:	pushl $0x100000<UINT32>
0x00404242:	pushl %edi
0x00404243:	call VirtualAlloc@KERNEL32.DLL
VirtualAlloc@KERNEL32.DLL: API Node	
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
0x004042cf:	call VirtualAlloc@KERNEL32.DLL
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
0x004041a4:	jne 0x004041c0
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
0x00404b18:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
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
0x00404c17:	call GetStdHandle@KERNEL32.DLL
GetStdHandle@KERNEL32.DLL: API Node	
0x00404c1d:	movl %edi, %eax
0x00404c1f:	cmpl %edi, $0xffffffff<UINT8>
0x00404c22:	je 23
0x00404c24:	pushl %edi
0x00404c25:	call GetFileType@KERNEL32.DLL
GetFileType@KERNEL32.DLL: API Node	
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
0x00404c5c:	call SetHandleCount@KERNEL32.DLL
SetHandleCount@KERNEL32.DLL: API Node	
0x00404c62:	popl %edi
0x00404c63:	popl %esi
0x00404c64:	popl %ebp
0x00404c65:	popl %ebx
0x00404c66:	addl %esp, $0x44<UINT8>
0x00404c69:	ret

0x00403098:	call GetCommandLineA@KERNEL32.DLL
GetCommandLineA@KERNEL32.DLL: API Node	
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
0x004049a8:	call GetEnvironmentStringsW@KERNEL32.DLL
GetEnvironmentStringsW@KERNEL32.DLL: API Node	
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
0x00404a20:	call WideCharToMultiByte@KERNEL32.DLL
WideCharToMultiByte@KERNEL32.DLL: API Node	
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
0x00402df0:	call HeapAlloc@KERNEL32.DLL
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
0x00404a42:	call WideCharToMultiByte@KERNEL32.DLL
0x00404a44:	testl %eax, %eax
0x00404a46:	jne 0x00404a56
0x00404a56:	movl %ebx, 0x10(%esp)
0x00404a5a:	pushl %esi
0x00404a5b:	call FreeEnvironmentStringsW@KERNEL32.DLL
FreeEnvironmentStringsW@KERNEL32.DLL: API Node	
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
0x00405f7b:	jne 0x00405f8f
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
0x00405d78:	jmp GetACP@KERNEL32.DLL
GetACP@KERNEL32.DLL: API Node	
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
0x00405bf8:	call GetCPInfo@KERNEL32.DLL
GetCPInfo@KERNEL32.DLL: API Node	
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
0x00405e03:	call GetCPInfo@KERNEL32.DLL
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
0x004059af:	call GetStringTypeW@KERNEL32.DLL
GetStringTypeW@KERNEL32.DLL: API Node	
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
0x00405a35:	call MultiByteToWideChar@KERNEL32.DLL
MultiByteToWideChar@KERNEL32.DLL: API Node	
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
0x004064f3:	testl %edx, %edx
0x004064f5:	je 0x004064fd
0x004064fd:	movl %eax, 0x8(%esp)
0x00406501:	popl %edi
0x00406502:	ret

0x00405a64:	addl %esp, $0xc<UINT8>
0x00405a67:	jmp 0x00405a74
0x00405a74:	orl -4(%ebp), $0xffffffff<UINT8>
0x00405a78:	cmpl %esi, %ebx
0x00405a7a:	je 41
0x00405a7c:	pushl -32(%ebp)
0x00405a7f:	pushl %esi
0x00405a80:	pushl 0x10(%ebp)
0x00405a83:	pushl 0xc(%ebp)
0x00405a86:	pushl $0x1<UINT8>
0x00405a88:	pushl 0x18(%ebp)
0x00405a8b:	call MultiByteToWideChar@KERNEL32.DLL
0x00405a91:	cmpl %eax, %ebx
0x00405a93:	je 16
0x00405a95:	pushl 0x14(%ebp)
0x00405a98:	pushl %eax
0x00405a99:	pushl %esi
0x00405a9a:	pushl 0x8(%ebp)
0x00405a9d:	call GetStringTypeW@KERNEL32.DLL
0x00405aa3:	jmp 0x00405aa7
0x00405aa7:	leal %esp, -52(%ebp)
0x00405aaa:	movl %ecx, -16(%ebp)
0x00405aad:	movl %fs:0, %ecx
0x00405ab4:	popl %edi
0x00405ab5:	popl %esi
0x00405ab6:	popl %ebx
0x00405ab7:	leave
0x00405ab8:	ret

0x00405e8e:	pushl $0x0<UINT8>
0x00405e90:	leal %eax, -532(%ebp)
0x00405e96:	pushl 0x423a00
0x00405e9c:	pushl %esi
0x00405e9d:	pushl %eax
0x00405e9e:	leal %eax, -276(%ebp)
0x00405ea4:	pushl %esi
0x00405ea5:	pushl %eax
0x00405ea6:	pushl %esi
0x00405ea7:	pushl 0x423c24
0x00405ead:	call 0x004066af
0x004066af:	pushl %ebp
0x004066b0:	movl %ebp, %esp
0x004066b2:	pushl $0xffffffff<UINT8>
0x004066b4:	pushl $0x4074f0<UINT32>
0x004066b9:	pushl $0x404d64<UINT32>
0x004066be:	movl %eax, %fs:0
0x004066c4:	pushl %eax
0x004066c5:	movl %fs:0, %esp
0x004066cc:	subl %esp, $0x1c<UINT8>
0x004066cf:	pushl %ebx
0x004066d0:	pushl %esi
0x004066d1:	pushl %edi
0x004066d2:	movl -24(%ebp), %esp
0x004066d5:	xorl %edi, %edi
0x004066d7:	cmpl 0x4235ec, %edi
0x004066dd:	jne 0x00406725
0x004066df:	pushl %edi
0x004066e0:	pushl %edi
0x004066e1:	pushl $0x1<UINT8>
0x004066e3:	popl %ebx
0x004066e4:	pushl %ebx
0x004066e5:	pushl $0x4074a4<UINT32>
0x004066ea:	movl %esi, $0x100<UINT32>
0x004066ef:	pushl %esi
0x004066f0:	pushl %edi
0x004066f1:	call LCMapStringW@KERNEL32.DLL
LCMapStringW@KERNEL32.DLL: API Node	
0x004066f7:	testl %eax, %eax
0x004066f9:	je 8
0x004066fb:	movl 0x4235ec, %ebx
0x00406701:	jmp 0x00406725
0x00406725:	cmpl 0x14(%ebp), %edi
0x00406728:	jle 16
0x0040672a:	pushl 0x14(%ebp)
0x0040672d:	pushl 0x10(%ebp)
0x00406730:	call 0x004068d3
0x004068d3:	movl %edx, 0x8(%esp)
0x004068d7:	movl %eax, 0x4(%esp)
0x004068db:	testl %edx, %edx
0x004068dd:	pushl %esi
0x004068de:	leal %ecx, -1(%edx)
0x004068e1:	je 13
0x004068e3:	cmpb (%eax), $0x0<UINT8>
0x004068e6:	je 8
0x004068e8:	incl %eax
0x004068e9:	movl %esi, %ecx
0x004068eb:	decl %ecx
0x004068ec:	testl %esi, %esi
0x004068ee:	jne 0x004068e3
0x004068f0:	cmpb (%eax), $0x0<UINT8>
0x004068f3:	popl %esi
0x004068f4:	jne 0x004068fb
0x004068fb:	movl %eax, %edx
0x004068fd:	ret

0x00406735:	popl %ecx
0x00406736:	popl %ecx
0x00406737:	movl 0x14(%ebp), %eax
0x0040673a:	movl %eax, 0x4235ec
0x0040673f:	cmpl %eax, $0x2<UINT8>
0x00406742:	jne 0x00406761
0x00406761:	cmpl %eax, $0x1<UINT8>
0x00406764:	jne 211
0x0040676a:	cmpl 0x20(%ebp), %edi
0x0040676d:	jne 0x00406777
0x00406777:	pushl %edi
0x00406778:	pushl %edi
0x00406779:	pushl 0x14(%ebp)
0x0040677c:	pushl 0x10(%ebp)
0x0040677f:	movl %eax, 0x24(%ebp)
0x00406782:	negl %eax
0x00406784:	sbbl %eax, %eax
0x00406786:	andl %eax, $0x8<UINT8>
0x00406789:	incl %eax
0x0040678a:	pushl %eax
0x0040678b:	pushl 0x20(%ebp)
0x0040678e:	call MultiByteToWideChar@KERNEL32.DLL
0x00406794:	movl %ebx, %eax
0x00406796:	movl -28(%ebp), %ebx
0x00406799:	cmpl %ebx, %edi
0x0040679b:	je 156
0x004067a1:	movl -4(%ebp), %edi
0x004067a4:	leal %eax, (%ebx,%ebx)
0x004067a7:	addl %eax, $0x3<UINT8>
0x004067aa:	andb %al, $0xfffffffc<UINT8>
0x004067ac:	call 0x00406680
0x004067b1:	movl -24(%ebp), %esp
0x004067b4:	movl %eax, %esp
0x004067b6:	movl -36(%ebp), %eax
0x004067b9:	orl -4(%ebp), $0xffffffff<UINT8>
0x004067bd:	jmp 0x004067d2
0x004067d2:	cmpl -36(%ebp), %edi
0x004067d5:	je 102
0x004067d7:	pushl %ebx
0x004067d8:	pushl -36(%ebp)
0x004067db:	pushl 0x14(%ebp)
0x004067de:	pushl 0x10(%ebp)
0x004067e1:	pushl $0x1<UINT8>
0x004067e3:	pushl 0x20(%ebp)
0x004067e6:	call MultiByteToWideChar@KERNEL32.DLL
0x004067ec:	testl %eax, %eax
0x004067ee:	je 77
0x004067f0:	pushl %edi
0x004067f1:	pushl %edi
0x004067f2:	pushl %ebx
0x004067f3:	pushl -36(%ebp)
0x004067f6:	pushl 0xc(%ebp)
0x004067f9:	pushl 0x8(%ebp)
0x004067fc:	call LCMapStringW@KERNEL32.DLL
0x00406802:	movl %esi, %eax
0x00406804:	movl -40(%ebp), %esi
0x00406807:	cmpl %esi, %edi
0x00406809:	je 50
0x0040680b:	testb 0xd(%ebp), $0x4<UINT8>
0x0040680f:	je 0x00406851
0x00406851:	movl -4(%ebp), $0x1<UINT32>
0x00406858:	leal %eax, (%esi,%esi)
0x0040685b:	addl %eax, $0x3<UINT8>
0x0040685e:	andb %al, $0xfffffffc<UINT8>
0x00406860:	call 0x00406680
0x00406865:	movl -24(%ebp), %esp
0x00406868:	movl %ebx, %esp
0x0040686a:	movl -32(%ebp), %ebx
0x0040686d:	orl -4(%ebp), $0xffffffff<UINT8>
0x00406871:	jmp 0x00406885
0x00406885:	cmpl %ebx, %edi
0x00406887:	je -76
0x00406889:	pushl %esi
0x0040688a:	pushl %ebx
0x0040688b:	pushl -28(%ebp)
0x0040688e:	pushl -36(%ebp)
0x00406891:	pushl 0xc(%ebp)
0x00406894:	pushl 0x8(%ebp)
0x00406897:	call LCMapStringW@KERNEL32.DLL
0x0040689d:	testl %eax, %eax
0x0040689f:	je -100
0x004068a1:	cmpl 0x1c(%ebp), %edi
0x004068a4:	pushl %edi
0x004068a5:	pushl %edi
0x004068a6:	jne 0x004068ac
0x004068ac:	pushl 0x1c(%ebp)
0x004068af:	pushl 0x18(%ebp)
0x004068b2:	pushl %esi
0x004068b3:	pushl %ebx
0x004068b4:	pushl $0x220<UINT32>
0x004068b9:	pushl 0x20(%ebp)
0x004068bc:	call WideCharToMultiByte@KERNEL32.DLL
0x004068c2:	movl %esi, %eax
0x004068c4:	cmpl %esi, %edi
0x004068c6:	je -143
0x004068cc:	movl %eax, %esi
0x004068ce:	jmp 0x0040683f
0x0040683f:	leal %esp, -56(%ebp)
0x00406842:	movl %ecx, -16(%ebp)
0x00406845:	movl %fs:0, %ecx
0x0040684c:	popl %edi
0x0040684d:	popl %esi
0x0040684e:	popl %ebx
0x0040684f:	leave
0x00406850:	ret

0x00405eb2:	pushl $0x0<UINT8>
0x00405eb4:	leal %eax, -788(%ebp)
0x00405eba:	pushl 0x423a00
0x00405ec0:	pushl %esi
0x00405ec1:	pushl %eax
0x00405ec2:	leal %eax, -276(%ebp)
0x00405ec8:	pushl %esi
0x00405ec9:	pushl %eax
0x00405eca:	pushl $0x200<UINT32>
0x00405ecf:	pushl 0x423c24
0x00405ed5:	call 0x004066af
0x00405eda:	addl %esp, $0x5c<UINT8>
0x00405edd:	xorl %eax, %eax
0x00405edf:	leal %ecx, -1300(%ebp)
0x00405ee5:	movw %dx, (%ecx)
0x00405ee8:	testb %dl, $0x1<UINT8>
0x00405eeb:	je 0x00405f03
0x00405f03:	testb %dl, $0x2<UINT8>
0x00405f06:	je 0x00405f18
0x00405f18:	andb 0x423a20(%eax), $0x0<UINT8>
0x00405f1f:	incl %eax
0x00405f20:	incl %ecx
0x00405f21:	incl %ecx
0x00405f22:	cmpl %eax, %esi
0x00405f24:	jb 0x00405ee5
0x00405eed:	orb 0x423b21(%eax), $0x10<UINT8>
0x00405ef4:	movb %dl, -532(%ebp,%eax)
0x00405efb:	movb 0x423a20(%eax), %dl
0x00405f01:	jmp 0x00405f1f
0x00405f08:	orb 0x423b21(%eax), $0x20<UINT8>
0x00405f0f:	movb %dl, -788(%ebp,%eax)
0x00405f16:	jmp 0x00405efb
0x00405f26:	jmp 0x00405f71
0x00405f71:	popl %esi
0x00405f72:	leave
0x00405f73:	ret

0x00405d3d:	xorl %eax, %eax
0x00405d3f:	jmp 0x00405d44
0x00405d44:	popl %edi
0x00405d45:	popl %esi
0x00405d46:	popl %ebx
0x00405d47:	leave
0x00405d48:	ret

0x00405f84:	popl %ecx
0x00405f85:	movl 0x424d8c, $0x1<UINT32>
0x00405f8f:	ret

0x00404757:	movl %esi, $0x4234ac<UINT32>
0x0040475c:	pushl $0x104<UINT32>
0x00404761:	pushl %esi
0x00404762:	pushl %ebx
0x00404763:	call GetModuleFileNameA@KERNEL32.DLL
GetModuleFileNameA@KERNEL32.DLL: API Node	
0x00404769:	movl %eax, 0x424d84
0x0040476e:	movl 0x423474, %esi
0x00404774:	movl %edi, %esi
0x00404776:	cmpb (%eax), %bl
0x00404778:	je 2
0x0040477a:	movl %edi, %eax
0x0040477c:	leal %eax, -8(%ebp)
0x0040477f:	pushl %eax
0x00404780:	leal %eax, -4(%ebp)
0x00404783:	pushl %eax
0x00404784:	pushl %ebx
0x00404785:	pushl %ebx
0x00404786:	pushl %edi
0x00404787:	call 0x004047d9
0x004047d9:	pushl %ebp
0x004047da:	movl %ebp, %esp
0x004047dc:	movl %ecx, 0x18(%ebp)
0x004047df:	movl %eax, 0x14(%ebp)
0x004047e2:	pushl %ebx
0x004047e3:	pushl %esi
0x004047e4:	andl (%ecx), $0x0<UINT8>
0x004047e7:	movl %esi, 0x10(%ebp)
0x004047ea:	pushl %edi
0x004047eb:	movl %edi, 0xc(%ebp)
0x004047ee:	movl (%eax), $0x1<UINT32>
0x004047f4:	movl %eax, 0x8(%ebp)
0x004047f7:	testl %edi, %edi
0x004047f9:	je 0x00404803
0x00404803:	cmpb (%eax), $0x22<UINT8>
0x00404806:	jne 68
0x00404808:	movb %dl, 0x1(%eax)
0x0040480b:	incl %eax
0x0040480c:	cmpb %dl, $0x22<UINT8>
0x0040480f:	je 0x0040483a
0x00404811:	testb %dl, %dl
0x00404813:	je 37
0x00404815:	movzbl %edx, %dl
0x00404818:	testb 0x423b21(%edx), $0x4<UINT8>
0x0040481f:	je 0x0040482d
0x0040482d:	incl (%ecx)
0x0040482f:	testl %esi, %esi
0x00404831:	je 0x00404808
0x0040483a:	incl (%ecx)
0x0040483c:	testl %esi, %esi
0x0040483e:	je 0x00404844
0x00404844:	cmpb (%eax), $0x22<UINT8>
0x00404847:	jne 70
0x00404849:	incl %eax
0x0040484a:	jmp 0x0040488f
0x0040488f:	andl 0x18(%ebp), $0x0<UINT8>
0x00404893:	cmpb (%eax), $0x0<UINT8>
0x00404896:	je 0x0040497c
0x0040497c:	testl %edi, %edi
0x0040497e:	je 0x00404983
0x00404983:	movl %eax, 0x14(%ebp)
0x00404986:	popl %edi
0x00404987:	popl %esi
0x00404988:	popl %ebx
0x00404989:	incl (%eax)
0x0040498b:	popl %ebp
0x0040498c:	ret

0x0040478c:	movl %eax, -8(%ebp)
0x0040478f:	movl %ecx, -4(%ebp)
0x00404792:	leal %eax, (%eax,%ecx,4)
0x00404795:	pushl %eax
0x00404796:	call 0x00402d84
0x00403f22:	movl %ecx, 0x4(%ebx)
0x00403f25:	movl %edi, (%ebx)
0x00403f27:	andl %ecx, -8(%ebp)
0x00403f2a:	andl %edi, %esi
0x00403f2c:	orl %ecx, %edi
0x00403f2e:	jne 0x00403f3b
0x0040479b:	movl %esi, %eax
0x0040479d:	addl %esp, $0x18<UINT8>
0x004047a0:	cmpl %esi, %ebx
0x004047a2:	jne 0x004047ac
0x004047ac:	leal %eax, -8(%ebp)
0x004047af:	pushl %eax
0x004047b0:	leal %eax, -4(%ebp)
0x004047b3:	pushl %eax
0x004047b4:	movl %eax, -4(%ebp)
0x004047b7:	leal %eax, (%esi,%eax,4)
0x004047ba:	pushl %eax
0x004047bb:	pushl %esi
0x004047bc:	pushl %edi
0x004047bd:	call 0x004047d9
0x004047fb:	movl (%edi), %esi
0x004047fd:	addl %edi, $0x4<UINT8>
0x00404800:	movl 0xc(%ebp), %edi
0x00404833:	movb %dl, (%eax)
0x00404835:	movb (%esi), %dl
0x00404837:	incl %esi
0x00404838:	jmp 0x00404808
0x00404840:	andb (%esi), $0x0<UINT8>
0x00404843:	incl %esi
0x00404980:	andl (%edi), $0x0<UINT8>
0x004047c2:	movl %eax, -4(%ebp)
0x004047c5:	addl %esp, $0x14<UINT8>
0x004047c8:	decl %eax
0x004047c9:	movl 0x42345c, %esi
0x004047cf:	popl %edi
0x004047d0:	popl %esi
0x004047d1:	movl 0x423458, %eax
0x004047d6:	popl %ebx
0x004047d7:	leave
0x004047d8:	ret

0x004030b2:	call 0x00404687
0x00404687:	pushl %ebx
0x00404688:	xorl %ebx, %ebx
0x0040468a:	cmpl 0x424d8c, %ebx
0x00404690:	pushl %esi
0x00404691:	pushl %edi
0x00404692:	jne 0x00404699
0x00404699:	movl %esi, 0x423488
0x0040469f:	xorl %edi, %edi
0x004046a1:	movb %al, (%esi)
0x004046a3:	cmpb %al, %bl
0x004046a5:	je 0x004046b9
0x004046a7:	cmpb %al, $0x3d<UINT8>
0x004046a9:	je 0x004046ac
0x004046ac:	pushl %esi
0x004046ad:	call 0x00405100
0x00405100:	movl %ecx, 0x4(%esp)
0x00405104:	testl %ecx, $0x3<UINT32>
0x0040510a:	je 0x00405120
0x00405120:	movl %eax, (%ecx)
0x00405122:	movl %edx, $0x7efefeff<UINT32>
0x00405127:	addl %edx, %eax
0x00405129:	xorl %eax, $0xffffffff<UINT8>
0x0040512c:	xorl %eax, %edx
0x0040512e:	addl %ecx, $0x4<UINT8>
0x00405131:	testl %eax, $0x81010100<UINT32>
0x00405136:	je 0x00405120
0x00405138:	movl %eax, -4(%ecx)
0x0040513b:	testb %al, %al
0x0040513d:	je 50
0x0040513f:	testb %ah, %ah
0x00405141:	je 36
0x00405143:	testl %eax, $0xff0000<UINT32>
0x00405148:	je 19
0x0040514a:	testl %eax, $0xff000000<UINT32>
0x0040514f:	je 0x00405153
0x00405153:	leal %eax, -1(%ecx)
0x00405156:	movl %ecx, 0x4(%esp)
0x0040515a:	subl %eax, %ecx
0x0040515c:	ret

0x004046b2:	popl %ecx
0x004046b3:	leal %esi, 0x1(%esi,%eax)
0x004046b7:	jmp 0x004046a1
0x004046b9:	leal %eax, 0x4(,%edi,4)
0x004046c0:	pushl %eax
0x004046c1:	call 0x00402d84
0x004046c6:	movl %esi, %eax
0x004046c8:	popl %ecx
0x004046c9:	cmpl %esi, %ebx
0x004046cb:	movl 0x423464, %esi
0x004046d1:	jne 0x004046db
0x004046db:	movl %edi, 0x423488
0x004046e1:	cmpb (%edi), %bl
0x004046e3:	je 57
0x004046e5:	pushl %ebp
0x004046e6:	pushl %edi
0x004046e7:	call 0x00405100
0x004046ec:	movl %ebp, %eax
0x004046ee:	popl %ecx
0x004046ef:	incl %ebp
0x004046f0:	cmpb (%edi), $0x3d<UINT8>
0x004046f3:	je 0x00404717
0x00404717:	addl %edi, %ebp
0x00404719:	cmpb (%edi), %bl
0x0040471b:	jne -55
0x0040471d:	popl %ebp
0x0040471e:	pushl 0x423488
0x00404724:	call 0x00402e1f
0x00402e1f:	pushl %esi
0x00402e20:	movl %esi, 0x8(%esp)
0x00402e24:	testl %esi, %esi
0x00402e26:	je 36
0x00402e28:	pushl %esi
0x00402e29:	call 0x00403b6e
0x00403b6e:	movl %eax, 0x423d54
0x00403b73:	leal %ecx, (%eax,%eax,4)
0x00403b76:	movl %eax, 0x423d58
0x00403b7b:	leal %ecx, (%eax,%ecx,4)
0x00403b7e:	cmpl %eax, %ecx
0x00403b80:	jae 0x00403b96
0x00403b82:	movl %edx, 0x4(%esp)
0x00403b86:	subl %edx, 0xc(%eax)
0x00403b89:	cmpl %edx, $0x100000<UINT32>
0x00403b8f:	jb 7
0x00403b91:	addl %eax, $0x14<UINT8>
0x00403b94:	jmp 0x00403b7e
0x00403b96:	xorl %eax, %eax
0x00403b98:	ret

0x00402e2e:	popl %ecx
0x00402e2f:	testl %eax, %eax
0x00402e31:	pushl %esi
0x00402e32:	je 0x00402e3e
0x00402e3e:	pushl $0x0<UINT8>
0x00402e40:	pushl 0x423d5c
0x00402e46:	call HeapFree@KERNEL32.DLL
HeapFree@KERNEL32.DLL: API Node	
0x00402e4c:	popl %esi
0x00402e4d:	ret

0x00404729:	popl %ecx
0x0040472a:	movl 0x423488, %ebx
0x00404730:	movl (%esi), %ebx
0x00404732:	popl %edi
0x00404733:	popl %esi
0x00404734:	movl 0x424d88, $0x1<UINT32>
0x0040473e:	popl %ebx
0x0040473f:	ret

0x004030b7:	call 0x00402c10
0x00402c10:	movl %eax, 0x424d98
0x00402c15:	testl %eax, %eax
0x00402c17:	je 0x00402c1b
0x00402c1b:	pushl $0x408014<UINT32>
0x00402c20:	pushl $0x408008<UINT32>
0x00402c25:	call 0x00402cf8
0x00402cf8:	pushl %esi
0x00402cf9:	movl %esi, 0x8(%esp)
0x00402cfd:	cmpl %esi, 0xc(%esp)
0x00402d01:	jae 0x00402d10
0x00402d03:	movl %eax, (%esi)
0x00402d05:	testl %eax, %eax
0x00402d07:	je 0x00402d0b
0x00402d0b:	addl %esi, $0x4<UINT8>
0x00402d0e:	jmp 0x00402cfd
0x00402d09:	call 0x00405f74
0x00403a20:	movl %eax, 0x424d80
0x00403a25:	pushl %esi
0x00403a26:	pushl $0x14<UINT8>
0x00403a28:	testl %eax, %eax
0x00403a2a:	popl %esi
0x00403a2b:	jne 7
0x00403a2d:	movl %eax, $0x200<UINT32>
0x00403a32:	jmp 0x00403a3a
0x00403a3a:	movl 0x424d80, %eax
0x00403a3f:	pushl $0x4<UINT8>
0x00403a41:	pushl %eax
0x00403a42:	call 0x004052d5
0x004052d5:	pushl %ebx
0x004052d6:	pushl %esi
0x004052d7:	movl %esi, 0xc(%esp)
0x004052db:	pushl %edi
0x004052dc:	imull %esi, 0x14(%esp)
0x004052e1:	cmpl %esi, $0xffffffe0<UINT8>
0x004052e4:	movl %ebx, %esi
0x004052e6:	ja 13
0x004052e8:	testl %esi, %esi
0x004052ea:	jne 0x004052ef
0x004052ef:	addl %esi, $0xf<UINT8>
0x004052f2:	andl %esi, $0xfffffff0<UINT8>
0x004052f5:	xorl %edi, %edi
0x004052f7:	cmpl %esi, $0xffffffe0<UINT8>
0x004052fa:	ja 42
0x004052fc:	cmpl %ebx, 0x422e54
0x00405302:	ja 0x00405311
0x00405311:	pushl %esi
0x00405312:	pushl $0x8<UINT8>
0x00405314:	pushl 0x423d5c
0x0040531a:	call HeapAlloc@KERNEL32.DLL
0x00405320:	movl %edi, %eax
0x00405322:	testl %edi, %edi
0x00405324:	jne 0x00405348
0x00405348:	movl %eax, %edi
0x0040534a:	popl %edi
0x0040534b:	popl %esi
0x0040534c:	popl %ebx
0x0040534d:	ret

0x00403a47:	popl %ecx
0x00403a48:	movl 0x423d60, %eax
0x00403a4d:	testl %eax, %eax
0x00403a4f:	popl %ecx
0x00403a50:	jne 0x00403a73
0x00403a73:	xorl %ecx, %ecx
0x00403a75:	movl %eax, $0x422bd0<UINT32>
0x00403a7a:	movl %edx, 0x423d60
0x00403a80:	movl (%ecx,%edx), %eax
0x00403a83:	addl %eax, $0x20<UINT8>
0x00403a86:	addl %ecx, $0x4<UINT8>
0x00403a89:	cmpl %eax, $0x422e50<UINT32>
0x00403a8e:	jl 0x00403a7a
0x00403a90:	xorl %edx, %edx
0x00403a92:	movl %ecx, $0x422be0<UINT32>
0x00403a97:	movl %eax, %edx
0x00403a99:	movl %esi, %edx
0x00403a9b:	sarl %eax, $0x5<UINT8>
0x00403a9e:	andl %esi, $0x1f<UINT8>
0x00403aa1:	movl %eax, 0x423c40(,%eax,4)
0x00403aa8:	movl %eax, (%eax,%esi,8)
0x00403aab:	cmpl %eax, $0xffffffff<UINT8>
0x00403aae:	je 4
0x00403ab0:	testl %eax, %eax
0x00403ab2:	jne 0x00403ab7
0x00403ab7:	addl %ecx, $0x20<UINT8>
0x00403aba:	incl %edx
0x00403abb:	cmpl %ecx, $0x422c40<UINT32>
0x00403ac1:	jl 0x00403a97
0x00403ac3:	popl %esi
0x00403ac4:	ret

0x00402d10:	popl %esi
0x00402d11:	ret

0x00402c2a:	pushl $0x408004<UINT32>
0x00402c2f:	pushl $0x408000<UINT32>
0x00402c34:	call 0x00402cf8
0x00402c39:	addl %esp, $0x10<UINT8>
0x00402c3c:	ret

0x004030bc:	movl %eax, 0x423464
0x004030c1:	movl 0x423468, %eax
0x004030c6:	pushl %eax
0x004030c7:	pushl 0x42345c
0x004030cd:	pushl 0x423458
0x004030d3:	call 0x00402340
0x00402340:	subl %esp, $0x304<UINT32>
0x00402346:	pushl %ebp
0x00402347:	pushl %esi
0x00402348:	pushl %edi
0x00402349:	pushl $0x4088b8<UINT32>
0x0040234e:	call 0x00402d12
0x00402d12:	pushl %ebx
0x00402d13:	pushl %esi
0x00402d14:	movl %esi, $0x422bf0<UINT32>
0x00402d19:	pushl %edi
0x00402d1a:	pushl %esi
0x00402d1b:	call 0x0040314c
0x0040314c:	pushl %esi
0x0040314d:	movl %esi, 0x8(%esp)
0x00403151:	pushl 0x10(%esi)
0x00403154:	call 0x00404fc8
0x00404fc8:	movl %eax, 0x4(%esp)
0x00404fcc:	cmpl %eax, 0x423d40
0x00404fd2:	jb 0x00404fd7
0x00404fd7:	movl %ecx, %eax
0x00404fd9:	andl %eax, $0x1f<UINT8>
0x00404fdc:	sarl %ecx, $0x5<UINT8>
0x00404fdf:	movl %ecx, 0x423c40(,%ecx,4)
0x00404fe6:	movb %al, 0x4(%ecx,%eax,8)
0x00404fea:	andl %eax, $0x40<UINT8>
0x00404fed:	ret

0x00403159:	testl %eax, %eax
0x0040315b:	popl %ecx
0x0040315c:	je 119
0x0040315e:	cmpl %esi, $0x422bf0<UINT32>
0x00403164:	jne 4
0x00403166:	xorl %eax, %eax
0x00403168:	jmp 0x00403175
0x00403175:	incl 0x42349c
0x0040317b:	testw 0xc(%esi), $0x10c<UINT16>
0x00403181:	jne 82
0x00403183:	cmpl 0x423494(,%eax,4), $0x0<UINT8>
0x0040318b:	pushl %ebx
0x0040318c:	pushl %edi
0x0040318d:	leal %edi, 0x423494(,%eax,4)
0x00403194:	movl %ebx, $0x1000<UINT32>
0x00403199:	jne 0x004031bb
0x0040319b:	pushl %ebx
0x0040319c:	call 0x00402d84
0x004031a1:	testl %eax, %eax
0x004031a3:	popl %ecx
0x004031a4:	movl (%edi), %eax
0x004031a6:	jne 0x004031bb
0x004031bb:	movl %edi, (%edi)
0x004031bd:	movl 0x18(%esi), %ebx
0x004031c0:	movl 0x8(%esi), %edi
0x004031c3:	movl (%esi), %edi
0x004031c5:	movl 0x4(%esi), %ebx
0x004031c8:	orw 0xc(%esi), $0x1102<UINT16>
0x004031ce:	pushl $0x1<UINT8>
0x004031d0:	popl %eax
0x004031d1:	popl %edi
0x004031d2:	popl %ebx
0x004031d3:	popl %esi
0x004031d4:	ret

0x00402d20:	movl %edi, %eax
0x00402d22:	leal %eax, 0x18(%esp)
0x00402d26:	pushl %eax
0x00402d27:	pushl 0x18(%esp)
0x00402d2b:	pushl %esi
0x00402d2c:	call 0x00403216
0x00403216:	pushl %ebp
0x00403217:	movl %ebp, %esp
0x00403219:	subl %esp, $0x248<UINT32>
0x0040321f:	pushl %ebx
0x00403220:	pushl %esi
0x00403221:	pushl %edi
0x00403222:	movl %edi, 0xc(%ebp)
0x00403225:	xorl %esi, %esi
0x00403227:	movb %bl, (%edi)
0x00403229:	incl %edi
0x0040322a:	testb %bl, %bl
0x0040322c:	movl -12(%ebp), %esi
0x0040322f:	movl -20(%ebp), %esi
0x00403232:	movl 0xc(%ebp), %edi
0x00403235:	je 1780
0x0040323b:	movl %ecx, -16(%ebp)
0x0040323e:	xorl %edx, %edx
0x00403240:	jmp 0x0040324a
0x0040324a:	cmpl -20(%ebp), %edx
0x0040324d:	jl 1756
0x00403253:	cmpb %bl, $0x20<UINT8>
0x00403256:	jl 0x0040326b
0x0040326b:	xorl %eax, %eax
0x0040326d:	movsbl %eax, 0x40713c(%esi,%eax,8)
0x00403275:	sarl %eax, $0x4<UINT8>
0x00403278:	cmpl %eax, $0x7<UINT8>
0x0040327b:	movl -48(%ebp), %eax
0x0040327e:	ja 1690
0x00403284:	jmp 0x004033f9
0x004033b5:	movl %ecx, 0x422e58
0x004033bb:	movl -36(%ebp), %edx
0x004033be:	movzbl %eax, %bl
0x004033c1:	testb 0x1(%ecx,%eax,2), $0xffffff80<UINT8>
0x004033c6:	je 0x004033e1
0x004033e1:	leal %eax, -20(%ebp)
0x004033e4:	pushl %eax
0x004033e5:	pushl 0x8(%ebp)
0x004033e8:	movsbl %eax, %bl
0x004033eb:	pushl %eax
0x004033ec:	call 0x00403957
0x00403957:	pushl %ebp
0x00403958:	movl %ebp, %esp
0x0040395a:	movl %ecx, 0xc(%ebp)
0x0040395d:	decl 0x4(%ecx)
0x00403960:	js 14
0x00403962:	movl %edx, (%ecx)
0x00403964:	movb %al, 0x8(%ebp)
0x00403967:	movb (%edx), %al
0x00403969:	incl (%ecx)
0x0040396b:	movzbl %eax, %al
0x0040396e:	jmp 0x0040397b
0x0040397b:	cmpl %eax, $0xffffffff<UINT8>
0x0040397e:	movl %eax, 0x10(%ebp)
0x00403981:	jne 0x00403988
0x00403988:	incl (%eax)
0x0040398a:	popl %ebp
0x0040398b:	ret

0x004033f1:	addl %esp, $0xc<UINT8>
0x004033f4:	jmp 0x0040391e
0x0040391e:	movl %edi, 0xc(%ebp)
0x00403921:	movb %bl, (%edi)
0x00403923:	incl %edi
0x00403924:	testb %bl, %bl
0x00403926:	movl 0xc(%ebp), %edi
0x00403929:	jne 0x00403242
0x00403242:	movl %ecx, -16(%ebp)
0x00403245:	movl %esi, -48(%ebp)
0x00403248:	xorl %edx, %edx
0x00403258:	cmpb %bl, $0x78<UINT8>
0x0040325b:	jg 0x0040326b
0x0040325d:	movsbl %eax, %bl
0x00403260:	movb %al, 0x40711c(%eax)
0x00403266:	andl %eax, $0xf<UINT8>
0x00403269:	jmp 0x0040326d
0x0040392f:	movl %eax, -20(%ebp)
0x00403932:	popl %edi
0x00403933:	popl %esi
0x00403934:	popl %ebx
0x00403935:	leave
0x00403936:	ret

0x00402d31:	pushl %esi
0x00402d32:	pushl %edi
0x00402d33:	movl %ebx, %eax
0x00402d35:	call 0x004031d9
0x004031d9:	cmpl 0x4(%esp), $0x0<UINT8>
0x004031de:	pushl %esi
0x004031df:	je 34
0x004031e1:	movl %esi, 0xc(%esp)
0x004031e5:	testb 0xd(%esi), $0x10<UINT8>
0x004031e9:	je 41
0x004031eb:	pushl %esi
0x004031ec:	call 0x00405029
0x00405029:	pushl %ebx
0x0040502a:	pushl %esi
0x0040502b:	movl %esi, 0xc(%esp)
0x0040502f:	xorl %ebx, %ebx
0x00405031:	pushl %edi
0x00405032:	movl %eax, 0xc(%esi)
0x00405035:	movl %ecx, %eax
0x00405037:	andl %ecx, $0x3<UINT8>
0x0040503a:	cmpb %cl, $0x2<UINT8>
0x0040503d:	jne 55
0x0040503f:	testw %ax, $0x108<UINT16>
0x00405043:	je 49
0x00405045:	movl %eax, 0x8(%esi)
0x00405048:	movl %edi, (%esi)
0x0040504a:	subl %edi, %eax
0x0040504c:	testl %edi, %edi
0x0040504e:	jle 38
0x00405050:	pushl %edi
0x00405051:	pushl %eax
0x00405052:	pushl 0x10(%esi)
0x00405055:	call 0x0040577f
0x0040577f:	pushl %ebp
0x00405780:	movl %ebp, %esp
0x00405782:	subl %esp, $0x414<UINT32>
0x00405788:	movl %ecx, 0x8(%ebp)
0x0040578b:	pushl %ebx
0x0040578c:	cmpl %ecx, 0x423d40
0x00405792:	pushl %esi
0x00405793:	pushl %edi
0x00405794:	jae 377
0x0040579a:	movl %eax, %ecx
0x0040579c:	movl %esi, %ecx
0x0040579e:	sarl %eax, $0x5<UINT8>
0x004057a1:	andl %esi, $0x1f<UINT8>
0x004057a4:	leal %ebx, 0x423c40(,%eax,4)
0x004057ab:	shll %esi, $0x3<UINT8>
0x004057ae:	movl %eax, (%ebx)
0x004057b0:	movb %al, 0x4(%eax,%esi)
0x004057b4:	testb %al, $0x1<UINT8>
0x004057b6:	je 343
0x004057bc:	xorl %edi, %edi
0x004057be:	cmpl 0x10(%ebp), %edi
0x004057c1:	movl -8(%ebp), %edi
0x004057c4:	movl -16(%ebp), %edi
0x004057c7:	jne 0x004057d0
0x004057d0:	testb %al, $0x20<UINT8>
0x004057d2:	je 0x004057e0
0x004057e0:	movl %eax, (%ebx)
0x004057e2:	addl %eax, %esi
0x004057e4:	testb 0x4(%eax), $0xffffff80<UINT8>
0x004057e8:	je 193
0x004057ee:	movl %eax, 0xc(%ebp)
0x004057f1:	cmpl 0x10(%ebp), %edi
0x004057f4:	movl -4(%ebp), %eax
0x004057f7:	movl 0x8(%ebp), %edi
0x004057fa:	jbe 231
0x00405800:	leal %eax, -1044(%ebp)
0x00405806:	movl %ecx, -4(%ebp)
0x00405809:	subl %ecx, 0xc(%ebp)
0x0040580c:	cmpl %ecx, 0x10(%ebp)
0x0040580f:	jae 0x0040583a
0x00405811:	movl %ecx, -4(%ebp)
0x00405814:	incl -4(%ebp)
0x00405817:	movb %cl, (%ecx)
0x00405819:	cmpb %cl, $0xa<UINT8>
0x0040581c:	jne 0x00405825
0x0040581e:	incl -16(%ebp)
0x00405821:	movb (%eax), $0xd<UINT8>
0x00405824:	incl %eax
0x00405825:	movb (%eax), %cl
0x00405827:	incl %eax
0x00405828:	movl %ecx, %eax
0x0040582a:	leal %edx, -1044(%ebp)
0x00405830:	subl %ecx, %edx
0x00405832:	cmpl %ecx, $0x400<UINT32>
0x00405838:	jl 0x00405806
0x0040583a:	movl %edi, %eax
0x0040583c:	leal %eax, -1044(%ebp)
0x00405842:	subl %edi, %eax
0x00405844:	leal %eax, -12(%ebp)
0x00405847:	pushl $0x0<UINT8>
0x00405849:	pushl %eax
0x0040584a:	leal %eax, -1044(%ebp)
0x00405850:	pushl %edi
0x00405851:	pushl %eax
0x00405852:	movl %eax, (%ebx)
0x00405854:	pushl (%eax,%esi)
0x00405857:	call WriteFile@KERNEL32.DLL
WriteFile@KERNEL32.DLL: API Node	
0x0040585d:	testl %eax, %eax
0x0040585f:	je 67
0x00405861:	movl %eax, -12(%ebp)
0x00405864:	addl -8(%ebp), %eax
0x00405867:	cmpl %eax, %edi
0x00405869:	jl 0x00405876
0x00405876:	xorl %edi, %edi
0x00405878:	movl %eax, -8(%ebp)
0x0040587b:	cmpl %eax, %edi
0x0040587d:	jne 0x0040590e
0x00405883:	cmpl 0x8(%ebp), %edi
0x00405886:	je 0x004058e7
0x004058e7:	movl %eax, (%ebx)
0x004058e9:	testb 0x4(%eax,%esi), $0x40<UINT8>
0x004058ee:	je 12
0x004058f0:	movl %eax, 0xc(%ebp)
0x004058f3:	cmpb (%eax), $0x1a<UINT8>
0x004058f6:	je -307
0x004058fc:	movl 0x42343c, $0x1c<UINT32>
0x00405906:	movl 0x423440, %edi
0x0040590c:	jmp 0x00405924
0x00405924:	orl %eax, $0xffffffff<UINT8>
0x00405927:	popl %edi
0x00405928:	popl %esi
0x00405929:	popl %ebx
0x0040592a:	leave
0x0040592b:	ret

0x0040505a:	addl %esp, $0xc<UINT8>
0x0040505d:	cmpl %eax, %edi
0x0040505f:	jne 0x0040506f
0x0040506f:	orl 0xc(%esi), $0x20<UINT8>
0x00405073:	orl %ebx, $0xffffffff<UINT8>
0x00405076:	movl %eax, 0x8(%esi)
0x00405079:	andl 0x4(%esi), $0x0<UINT8>
0x0040507d:	movl (%esi), %eax
0x0040507f:	popl %edi
0x00405080:	movl %eax, %ebx
0x00405082:	popl %esi
0x00405083:	popl %ebx
0x00405084:	ret

0x004031f1:	andb 0xd(%esi), $0xffffffee<UINT8>
0x004031f5:	andl 0x18(%esi), $0x0<UINT8>
0x004031f9:	andl (%esi), $0x0<UINT8>
0x004031fc:	andl 0x8(%esi), $0x0<UINT8>
0x00403200:	popl %ecx
0x00403201:	popl %esi
0x00403202:	ret

0x00402d3a:	addl %esp, $0x18<UINT8>
0x00402d3d:	movl %eax, %ebx
0x00402d3f:	popl %edi
0x00402d40:	popl %esi
0x00402d41:	popl %ebx
0x00402d42:	ret

0x00402353:	pushl $0x40888c<UINT32>
0x00402358:	call 0x00402d12
0x0040590e:	subl %eax, -16(%ebp)
0x00405911:	jmp 0x00405927
0x0040235d:	pushl $0x408884<UINT32>
0x00402362:	call 0x004025a0
0x004025a0:	subl %esp, $0x110<UINT32>
0x004025a6:	movl %eax, 0x114(%esp)
0x004025ad:	pushl %ebx
0x004025ae:	pushl %eax
0x004025af:	leal %ecx, 0x14(%esp)
0x004025b3:	xorl %ebx, %ebx
0x004025b5:	pushl $0x422b68<UINT32>
0x004025ba:	pushl %ecx
0x004025bb:	movl 0x14(%esp), %ebx
0x004025bf:	movl 0x10(%esp), %ebx
0x004025c3:	call 0x00402efa
0x00402efa:	pushl %ebp
0x00402efb:	movl %ebp, %esp
0x00402efd:	subl %esp, $0x20<UINT8>
0x00402f00:	movl %eax, 0x8(%ebp)
0x00402f03:	pushl %esi
0x00402f04:	movl -24(%ebp), %eax
0x00402f07:	movl -32(%ebp), %eax
0x00402f0a:	leal %eax, 0x10(%ebp)
0x00402f0d:	movl -20(%ebp), $0x42<UINT32>
0x00402f14:	pushl %eax
0x00402f15:	leal %eax, -32(%ebp)
0x00402f18:	pushl 0xc(%ebp)
0x00402f1b:	movl -28(%ebp), $0x7fffffff<UINT32>
0x00402f22:	pushl %eax
0x00402f23:	call 0x00403216
0x0040328b:	orl -16(%ebp), $0xffffffff<UINT8>
0x0040328f:	movl -52(%ebp), %edx
0x00403292:	movl -40(%ebp), %edx
0x00403295:	movl -32(%ebp), %edx
0x00403298:	movl -28(%ebp), %edx
0x0040329b:	movl -4(%ebp), %edx
0x0040329e:	movl -36(%ebp), %edx
0x004032a1:	jmp 0x0040391e
0x004033f9:	movsbl %eax, %bl
0x004033fc:	cmpl %eax, $0x67<UINT8>
0x004033ff:	jg 0x00403621
0x00403621:	subl %eax, $0x69<UINT8>
0x00403624:	je 209
0x0040362a:	subl %eax, $0x5<UINT8>
0x0040362d:	je 158
0x00403633:	decl %eax
0x00403634:	je 132
0x0040363a:	decl %eax
0x0040363b:	je 81
0x0040363d:	subl %eax, $0x3<UINT8>
0x00403640:	je 0x00403443
0x00403443:	movl %esi, -16(%ebp)
0x00403446:	cmpl %esi, $0xffffffff<UINT8>
0x00403449:	jne 5
0x0040344b:	movl %esi, $0x7fffffff<UINT32>
0x00403450:	leal %eax, 0x10(%ebp)
0x00403453:	pushl %eax
0x00403454:	call 0x004039f5
0x004039f5:	movl %eax, 0x4(%esp)
0x004039f9:	addl (%eax), $0x4<UINT8>
0x004039fc:	movl %eax, (%eax)
0x004039fe:	movl %eax, -4(%eax)
0x00403a01:	ret

0x00403459:	testw -4(%ebp), $0x810<UINT16>
0x0040345f:	popl %ecx
0x00403460:	movl %ecx, %eax
0x00403462:	movl -8(%ebp), %ecx
0x00403465:	je 0x00403669
0x00403669:	testl %ecx, %ecx
0x0040366b:	jne 0x00403676
0x00403676:	movl %eax, %ecx
0x00403678:	movl %edx, %esi
0x0040367a:	decl %esi
0x0040367b:	testl %edx, %edx
0x0040367d:	je 8
0x0040367f:	cmpb (%eax), $0x0<UINT8>
0x00403682:	je 0x00403687
0x00403684:	incl %eax
0x00403685:	jmp 0x00403678
0x00403687:	subl %eax, %ecx
0x00403689:	jmp 0x0040381d
0x0040381d:	movl -12(%ebp), %eax
0x00403820:	cmpl -40(%ebp), $0x0<UINT8>
0x00403824:	jne 244
0x0040382a:	movl %ebx, -4(%ebp)
0x0040382d:	testb %bl, $0x40<UINT8>
0x00403830:	je 0x00403858
0x00403858:	movl %esi, -32(%ebp)
0x0040385b:	subl %esi, -28(%ebp)
0x0040385e:	subl %esi, -12(%ebp)
0x00403861:	testb %bl, $0xc<UINT8>
0x00403864:	jne 18
0x00403866:	leal %eax, -20(%ebp)
0x00403869:	pushl %eax
0x0040386a:	pushl 0x8(%ebp)
0x0040386d:	pushl %esi
0x0040386e:	pushl $0x20<UINT8>
0x00403870:	call 0x0040398c
0x0040398c:	pushl %esi
0x0040398d:	pushl %edi
0x0040398e:	movl %edi, 0x10(%esp)
0x00403992:	movl %eax, %edi
0x00403994:	decl %edi
0x00403995:	testl %eax, %eax
0x00403997:	jle 0x004039ba
0x004039ba:	popl %edi
0x004039bb:	popl %esi
0x004039bc:	ret

0x00403875:	addl %esp, $0x10<UINT8>
0x00403878:	leal %eax, -20(%ebp)
0x0040387b:	pushl %eax
0x0040387c:	leal %eax, -22(%ebp)
0x0040387f:	pushl 0x8(%ebp)
0x00403882:	pushl -28(%ebp)
0x00403885:	pushl %eax
0x00403886:	call 0x004039bd
0x004039bd:	pushl %ebx
0x004039be:	movl %ebx, 0xc(%esp)
0x004039c2:	movl %eax, %ebx
0x004039c4:	decl %ebx
0x004039c5:	pushl %esi
0x004039c6:	pushl %edi
0x004039c7:	testl %eax, %eax
0x004039c9:	jle 0x004039f1
0x004039f1:	popl %edi
0x004039f2:	popl %esi
0x004039f3:	popl %ebx
0x004039f4:	ret

0x0040388b:	addl %esp, $0x10<UINT8>
0x0040388e:	testb %bl, $0x8<UINT8>
0x00403891:	je 0x004038aa
0x004038aa:	cmpl -36(%ebp), $0x0<UINT8>
0x004038ae:	je 0x004038f1
0x004038f1:	leal %eax, -20(%ebp)
0x004038f4:	pushl %eax
0x004038f5:	pushl 0x8(%ebp)
0x004038f8:	pushl -12(%ebp)
0x004038fb:	pushl -8(%ebp)
0x004038fe:	call 0x004039bd
0x004039cb:	movl %edi, 0x1c(%esp)
0x004039cf:	movl %esi, 0x10(%esp)
0x004039d3:	movsbl %eax, (%esi)
0x004039d6:	pushl %edi
0x004039d7:	incl %esi
0x004039d8:	pushl 0x1c(%esp)
0x004039dc:	pushl %eax
0x004039dd:	call 0x00403957
0x004039e2:	addl %esp, $0xc<UINT8>
0x004039e5:	cmpl (%edi), $0xffffffff<UINT8>
0x004039e8:	je 7
0x004039ea:	movl %eax, %ebx
0x004039ec:	decl %ebx
0x004039ed:	testl %eax, %eax
0x004039ef:	jg 0x004039d3
0x00403903:	addl %esp, $0x10<UINT8>
0x00403906:	testb -4(%ebp), $0x4<UINT8>
0x0040390a:	je 0x0040391e
0x00402f28:	addl %esp, $0xc<UINT8>
0x00402f2b:	decl -28(%ebp)
0x00402f2e:	movl %esi, %eax
0x00402f30:	js 8
0x00402f32:	movl %eax, -32(%ebp)
0x00402f35:	andb (%eax), $0x0<UINT8>
0x00402f38:	jmp 0x00402f47
0x00402f47:	movl %eax, %esi
0x00402f49:	popl %esi
0x00402f4a:	leave
0x00402f4b:	ret

0x004025c8:	addl %esp, $0xc<UINT8>
0x004025cb:	leal %edx, 0x8(%esp)
0x004025cf:	leal %eax, 0x10(%esp)
0x004025d3:	pushl %edx
0x004025d4:	pushl %eax
0x004025d5:	pushl $0x80000001<UINT32>
0x004025da:	call RegCreateKeyA@ADVAPI32.dll
RegCreateKeyA@ADVAPI32.dll: API Node	
0x004025e0:	testl %eax, %eax
0x004025e2:	jne 36
0x004025e4:	movl %eax, 0x8(%esp)
0x004025e8:	leal %ecx, 0xc(%esp)
0x004025ec:	leal %edx, 0x4(%esp)
0x004025f0:	pushl %ecx
0x004025f1:	pushl %edx
0x004025f2:	pushl %ebx
0x004025f3:	pushl %ebx
0x004025f4:	pushl $0x422b58<UINT32>
0x004025f9:	pushl %eax
0x004025fa:	movl 0x24(%esp), $0x4<UINT32>
0x00402602:	call RegQueryValueExA@ADVAPI32.dll
RegQueryValueExA@ADVAPI32.dll: API Node	
0x00402608:	cmpl 0x4(%esp), %ebx
0x0040260c:	jne 511
0x00402612:	pushl %esi
0x00402613:	pushl %edi
0x00402614:	pushl $0x3e8<UINT32>
0x00402619:	pushl $0x40<UINT8>
0x0040261b:	call LocalAlloc@KERNEL32.DLL
LocalAlloc@KERNEL32.DLL: API Node	
0x00402621:	movl %esi, %eax
0x00402623:	pushl $0x422b48<UINT32>
0x00402628:	leal %edi, 0x12(%esi)
0x0040262b:	call LoadLibraryA@KERNEL32.DLL
0x00402631:	movl (%esi), $0x80c808d0<UINT32>
0x00404d64:	pushl %ebp
0x00404d65:	movl %ebp, %esp
0x00404d67:	subl %esp, $0x8<UINT8>
0x00404d6a:	pushl %ebx
0x00404d6b:	pushl %esi
0x00404d6c:	pushl %edi
0x00404d6d:	pushl %ebp
0x00404d6e:	cld
0x00404d6f:	movl %ebx, 0xc(%ebp)
0x00404d72:	movl %eax, 0x8(%ebp)
0x00404d75:	testl 0x4(%eax), $0x6<UINT32>
0x00404d7c:	jne 130
0x00404d82:	movl -8(%ebp), %eax
0x00404d85:	movl %eax, 0x10(%ebp)
0x00404d88:	movl -4(%ebp), %eax
0x00404d8b:	leal %eax, -8(%ebp)
0x00404d8e:	movl -4(%ebx), %eax
0x00404d91:	movl %esi, 0xc(%ebx)
0x00404d94:	movl %edi, 0x8(%ebx)
0x00404d97:	cmpl %esi, $0xffffffff<UINT8>
0x00404d9a:	je 97
0x00404d9c:	leal %ecx, (%esi,%esi,2)
0x00404d9f:	cmpl 0x4(%edi,%ecx,4), $0x0<UINT8>
0x00404da4:	je 69
0x00404da6:	pushl %esi
0x00404da7:	pushl %ebp
0x00404da8:	leal %ebp, 0x10(%ebx)
0x00404dab:	call 0x004030e4
0x004030e4:	movl %eax, -20(%ebp)
0x004030e7:	movl %ecx, (%eax)
0x004030e9:	movl %ecx, (%ecx)
0x004030eb:	movl -32(%ebp), %ecx
0x004030ee:	pushl %eax
0x004030ef:	pushl %ecx
0x004030f0:	call 0x00404503
0x00404503:	pushl %ebp
0x00404504:	movl %ebp, %esp
0x00404506:	pushl %ebx
0x00404507:	pushl 0x8(%ebp)
0x0040450a:	call 0x00404644
0x00404644:	movl %edx, 0x4(%esp)
0x00404648:	movl %ecx, 0x4230f0
0x0040464e:	cmpl 0x423070, %edx
0x00404654:	pushl %esi
0x00404655:	movl %eax, $0x423070<UINT32>
0x0040465a:	je 0x00404671
0x00404671:	leal %ecx, (%ecx,%ecx,2)
0x00404674:	popl %esi
0x00404675:	leal %ecx, 0x423070(,%ecx,4)
0x0040467c:	cmpl %eax, %ecx
0x0040467e:	jae 4
0x00404680:	cmpl (%eax), %edx
0x00404682:	je 0x00404686
0x00404686:	ret

0x0040450f:	testl %eax, %eax
0x00404511:	popl %ecx
0x00404512:	je 288
0x00404518:	movl %ebx, 0x8(%eax)
0x0040451b:	testl %ebx, %ebx
0x0040451d:	je 0x00404638
0x00404638:	pushl 0xc(%ebp)
0x0040463b:	call UnhandledExceptionFilter@KERNEL32.DLL
UnhandledExceptionFilter@KERNEL32.DLL: API Node	
0x00404641:	popl %ebx
0x00404642:	popl %ebp
0x00404643:	ret

0x004030f5:	popl %ecx
0x004030f6:	popl %ecx
0x004030f7:	ret

0x00404daf:	popl %ebp
0x00404db0:	popl %esi
0x00404db1:	movl %ebx, 0xc(%ebp)
0x00404db4:	orl %eax, %eax
0x00404db6:	je 51
0x00404db8:	js 60
0x00404dba:	movl %edi, 0x8(%ebx)
0x00404dbd:	pushl %ebx
0x00404dbe:	call 0x00404c6c
0x00404c6c:	pushl %ebp
0x00404c6d:	movl %ebp, %esp
0x00404c6f:	pushl %ebx
0x00404c70:	pushl %esi
0x00404c71:	pushl %edi
0x00404c72:	pushl %ebp
0x00404c73:	pushl $0x0<UINT8>
0x00404c75:	pushl $0x0<UINT8>
0x00404c77:	pushl $0x404c84<UINT32>
0x00404c7c:	pushl 0x8(%ebp)
0x00404c7f:	call 0x004069e0
0x004069e0:	jmp RtlUnwind@KERNEL32.DLL
RtlUnwind@KERNEL32.DLL: API Node	
0x00404c84:	popl %ebp
0x00404c85:	popl %edi
0x00404c86:	popl %esi
0x00404c87:	popl %ebx
0x00404c88:	movl %esp, %ebp
0x00404c8a:	popl %ebp
0x00404c8b:	ret

0x00404dc3:	addl %esp, $0x4<UINT8>
0x00404dc6:	leal %ebp, 0x10(%ebx)
0x00404dc9:	pushl %esi
0x00404dca:	pushl %ebx
0x00404dcb:	call 0x00404cae
0x00404cae:	pushl %ebx
0x00404caf:	pushl %esi
0x00404cb0:	pushl %edi
0x00404cb1:	movl %eax, 0x10(%esp)
0x00404cb5:	pushl %eax
0x00404cb6:	pushl $0xfffffffe<UINT8>
0x00404cb8:	pushl $0x404c8c<UINT32>
0x00404cbd:	pushl %fs:0
0x00404cc4:	movl %fs:0, %esp
0x00404ccb:	movl %eax, 0x20(%esp)
0x00404ccf:	movl %ebx, 0x8(%eax)
0x00404cd2:	movl %esi, 0xc(%eax)
0x00404cd5:	cmpl %esi, $0xffffffff<UINT8>
0x00404cd8:	je 46
0x00404cda:	cmpl %esi, 0x24(%esp)
0x00404cde:	je 0x00404d08
0x00404d08:	popl %fs:0
0x00404d0f:	addl %esp, $0xc<UINT8>
0x00404d12:	popl %edi
0x00404d13:	popl %esi
0x00404d14:	popl %ebx
0x00404d15:	ret

0x00404dd0:	addl %esp, $0x8<UINT8>
0x00404dd3:	leal %ecx, (%esi,%esi,2)
0x00404dd6:	pushl $0x1<UINT8>
0x00404dd8:	movl %eax, 0x8(%edi,%ecx,4)
0x00404ddc:	call 0x00404d42
0x00404d42:	pushl %ebx
0x00404d43:	pushl %ecx
0x00404d44:	movl %ebx, $0x423100<UINT32>
0x00404d49:	movl %ecx, 0x8(%ebp)
0x00404d4c:	movl 0x8(%ebx), %ecx
0x00404d4f:	movl 0x4(%ebx), %eax
0x00404d52:	movl 0xc(%ebx), %ebp
0x00404d55:	popl %ecx
0x00404d56:	popl %ebx
0x00404d57:	ret $0x4<UINT16>

0x00404de1:	movl %eax, (%edi,%ecx,4)
0x00404de4:	movl 0xc(%ebx), %eax
0x00404de7:	call 0x004030f8
0x004030f8:	movl %esp, -24(%ebp)
0x004030fb:	pushl -32(%ebp)
0x004030fe:	call 0x00402c4e
0x00402c4e:	pushl $0x0<UINT8>
0x00402c50:	pushl $0x1<UINT8>
0x00402c52:	pushl 0xc(%esp)
0x00402c56:	call 0x00402c5f
0x00402c5f:	pushl %edi
0x00402c60:	pushl $0x1<UINT8>
0x00402c62:	popl %edi
0x00402c63:	cmpl 0x423484, %edi
0x00402c69:	jne 0x00402c7c
0x00402c7c:	cmpl 0xc(%esp), $0x0<UINT8>
0x00402c81:	pushl %ebx
0x00402c82:	movl %ebx, 0x14(%esp)
0x00402c86:	movl 0x423480, %edi
0x00402c8c:	movb 0x42347c, %bl
0x00402c92:	jne 0x00402cd0
0x00402cd0:	pushl $0x408028<UINT32>
0x00402cd5:	pushl $0x408024<UINT32>
0x00402cda:	call 0x00402cf8
0x00402cdf:	popl %ecx
0x00402ce0:	popl %ecx
0x00402ce1:	testl %ebx, %ebx
0x00402ce3:	popl %ebx
0x00402ce4:	jne 16
0x00402ce6:	pushl 0x8(%esp)
0x00402cea:	movl 0x423484, %edi
0x00402cf0:	call ExitProcess@KERNEL32.DLL
ExitProcess@KERNEL32.DLL: Exit Node	
