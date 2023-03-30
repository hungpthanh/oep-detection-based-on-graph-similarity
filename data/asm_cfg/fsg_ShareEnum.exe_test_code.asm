0x00455000:	movl %ebx, $0x4001d0<UINT32>
0x00455005:	movl %edi, $0x401000<UINT32>
0x0045500a:	movl %esi, $0x4408f8<UINT32>
0x0045500f:	pushl %ebx
0x00455010:	call 0x0045501f
0x0045501f:	cld
0x00455020:	movb %dl, $0xffffff80<UINT8>
0x00455022:	movsb %es:(%edi), %ds:(%esi)
0x00455023:	pushl $0x2<UINT8>
0x00455025:	popl %ebx
0x00455026:	call 0x00455015
0x00455015:	addb %dl, %dl
0x00455017:	jne 0x0045501e
0x00455019:	movb %dl, (%esi)
0x0045501b:	incl %esi
0x0045501c:	adcb %dl, %dl
0x0045501e:	ret

0x00455029:	jae 0x00455022
0x0045502b:	xorl %ecx, %ecx
0x0045502d:	call 0x00455015
0x00455030:	jae 0x0045504a
0x00455032:	xorl %eax, %eax
0x00455034:	call 0x00455015
0x00455037:	jae 0x0045505a
0x00455039:	movb %bl, $0x2<UINT8>
0x0045503b:	incl %ecx
0x0045503c:	movb %al, $0x10<UINT8>
0x0045503e:	call 0x00455015
0x00455041:	adcb %al, %al
0x00455043:	jae 0x0045503e
0x00455045:	jne 0x00455086
0x00455047:	stosb %es:(%edi), %al
0x00455048:	jmp 0x00455026
0x0045505a:	lodsb %al, %ds:(%esi)
0x0045505b:	shrl %eax
0x0045505d:	je 0x004550a0
0x0045505f:	adcl %ecx, %ecx
0x00455061:	jmp 0x0045507f
0x0045507f:	incl %ecx
0x00455080:	incl %ecx
0x00455081:	xchgl %ebp, %eax
0x00455082:	movl %eax, %ebp
0x00455084:	movb %bl, $0x1<UINT8>
0x00455086:	pushl %esi
0x00455087:	movl %esi, %edi
0x00455089:	subl %esi, %eax
0x0045508b:	rep movsb %es:(%edi), %ds:(%esi)
0x0045508d:	popl %esi
0x0045508e:	jmp 0x00455026
0x0045504a:	call 0x00455092
0x00455092:	incl %ecx
0x00455093:	call 0x00455015
0x00455097:	adcl %ecx, %ecx
0x00455099:	call 0x00455015
0x0045509d:	jb 0x00455093
0x0045509f:	ret

0x0045504f:	subl %ecx, %ebx
0x00455051:	jne 0x00455063
0x00455063:	xchgl %ecx, %eax
0x00455064:	decl %eax
0x00455065:	shll %eax, $0x8<UINT8>
0x00455068:	lodsb %al, %ds:(%esi)
0x00455069:	call 0x00455090
0x00455090:	xorl %ecx, %ecx
0x0045506e:	cmpl %eax, $0x7d00<UINT32>
0x00455073:	jae 0x0045507f
0x00455075:	cmpb %ah, $0x5<UINT8>
0x00455078:	jae 0x00455080
0x0045507a:	cmpl %eax, $0x7f<UINT8>
0x0045507d:	ja 0x00455081
0x00455053:	call 0x00455090
0x00455058:	jmp 0x00455082
0x004550a0:	popl %edi
0x004550a1:	popl %ebx
0x004550a2:	movzwl %edi, (%ebx)
0x004550a5:	decl %edi
0x004550a6:	je 0x004550b0
0x004550a8:	decl %edi
0x004550a9:	je 0x004550be
0x004550ab:	shll %edi, $0xc<UINT8>
0x004550ae:	jmp 0x004550b7
0x004550b7:	incl %ebx
0x004550b8:	incl %ebx
0x004550b9:	jmp 0x0045500f
0x004550b0:	movl %edi, 0x2(%ebx)
0x004550b3:	pushl %edi
0x004550b4:	addl %ebx, $0x4<UINT8>
0x004550be:	popl %edi
0x004550bf:	movl %ebx, $0x455128<UINT32>
0x004550c4:	incl %edi
0x004550c5:	movl %esi, (%edi)
0x004550c7:	scasl %eax, %es:(%edi)
0x004550c8:	pushl %edi
0x004550c9:	call LoadLibraryA@KERNEL32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004550cb:	xchgl %ebp, %eax
0x004550cc:	xorl %eax, %eax
0x004550ce:	scasb %al, %es:(%edi)
0x004550cf:	jne 0x004550ce
0x004550d1:	decb (%edi)
0x004550d3:	je 0x004550c4
0x004550d5:	decb (%edi)
0x004550d7:	jne 0x004550df
0x004550d9:	incl %edi
0x004550da:	pushl (%edi)
0x004550dc:	scasl %eax, %es:(%edi)
0x004550dd:	jmp 0x004550e8
0x004550e8:	pushl %ebp
0x004550e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x004550ec:	orl (%esi), %eax
0x004550ee:	lodsl %eax, %ds:(%esi)
0x004550ef:	jne 0x004550cc
0x004550df:	decb (%edi)
0x004550e1:	je 0x00409013
0x004550e7:	pushl %edi
GetProcAddress@KERNEL32.dll: API Node	
LoadLibraryA@KERNEL32.dll: API Node	
0x00409013:	pushl %ebp
0x00409014:	movl %ebp, %esp
0x00409016:	pushl $0xffffffff<UINT8>
0x00409018:	pushl $0x4190c0<UINT32>
0x0040901d:	pushl $0x40e74c<UINT32>
0x00409022:	movl %eax, %fs:0
0x00409028:	pushl %eax
0x00409029:	movl %fs:0, %esp
0x00409030:	subl %esp, $0x58<UINT8>
0x00409033:	pushl %ebx
0x00409034:	pushl %esi
0x00409035:	pushl %edi
0x00409036:	movl -24(%ebp), %esp
0x00409039:	call GetVersion@KERNEL32.dll
GetVersion@KERNEL32.dll: API Node	
0x0040903f:	xorl %edx, %edx
0x00409041:	movb %dl, %ah
0x00409043:	movl 0x438e70, %edx
0x00409049:	movl %ecx, %eax
0x0040904b:	andl %ecx, $0xff<UINT32>
0x00409051:	movl 0x438e6c, %ecx
0x00409057:	shll %ecx, $0x8<UINT8>
0x0040905a:	addl %ecx, %edx
0x0040905c:	movl 0x438e68, %ecx
0x00409062:	shrl %eax, $0x10<UINT8>
0x00409065:	movl 0x438e64, %eax
0x0040906a:	pushl $0x1<UINT8>
0x0040906c:	call 0x0040bbd2
0x0040bbd2:	xorl %eax, %eax
0x0040bbd4:	pushl $0x0<UINT8>
0x0040bbd6:	cmpl 0x8(%esp), %eax
0x0040bbda:	pushl $0x1000<UINT32>
0x0040bbdf:	sete %al
0x0040bbe2:	pushl %eax
0x0040bbe3:	call HeapCreate@KERNEL32.dll
HeapCreate@KERNEL32.dll: API Node	
0x0040bbe9:	testl %eax, %eax
0x0040bbeb:	movl 0x4393a0, %eax
0x0040bbf0:	je 21
0x0040bbf2:	call 0x0040bca0
0x0040bca0:	pushl $0x140<UINT32>
0x0040bca5:	pushl $0x0<UINT8>
0x0040bca7:	pushl 0x4393a0
0x0040bcad:	call HeapAlloc@KERNEL32.dll
HeapAlloc@KERNEL32.dll: API Node	
0x0040bcb3:	testl %eax, %eax
0x0040bcb5:	movl 0x43939c, %eax
0x0040bcba:	jne 0x0040bcbd
0x0040bcbd:	andl 0x439394, $0x0<UINT8>
0x0040bcc4:	andl 0x439398, $0x0<UINT8>
0x0040bccb:	pushl $0x1<UINT8>
0x0040bccd:	movl 0x439390, %eax
0x0040bcd2:	movl 0x439388, $0x10<UINT32>
0x0040bcdc:	popl %eax
0x0040bcdd:	ret

0x0040bbf7:	testl %eax, %eax
0x0040bbf9:	jne 0x0040bc0a
0x0040bc0a:	pushl $0x1<UINT8>
0x0040bc0c:	popl %eax
0x0040bc0d:	ret

0x00409071:	popl %ecx
0x00409072:	testl %eax, %eax
0x00409074:	jne 0x0040907e
0x0040907e:	call 0x0040aedc
0x0040aedc:	pushl %esi
0x0040aedd:	call 0x00409164
0x00409164:	pushl %esi
0x00409165:	movl %esi, 0x4181c8
0x0040916b:	pushl 0x436f5c
0x00409171:	call InitializeCriticalSection@KERNEL32.dll
InitializeCriticalSection@KERNEL32.dll: API Node	
0x00409173:	pushl 0x436f4c
0x00409179:	call InitializeCriticalSection@KERNEL32.dll
0x0040917b:	pushl 0x436f3c
0x00409181:	call InitializeCriticalSection@KERNEL32.dll
0x00409183:	pushl 0x436f1c
0x00409189:	call InitializeCriticalSection@KERNEL32.dll
0x0040918b:	popl %esi
0x0040918c:	ret

0x0040aee2:	call TlsAlloc@KERNEL32.dll
TlsAlloc@KERNEL32.dll: API Node	
0x0040aee8:	cmpl %eax, $0xffffffff<UINT8>
0x0040aeeb:	movl 0x437750, %eax
0x0040aef0:	je 58
0x0040aef2:	pushl $0x74<UINT8>
0x0040aef4:	pushl $0x1<UINT8>
0x0040aef6:	call 0x004106dd
0x004106dd:	pushl %ebx
0x004106de:	pushl %esi
0x004106df:	movl %esi, 0xc(%esp)
0x004106e3:	pushl %edi
0x004106e4:	imull %esi, 0x14(%esp)
0x004106e9:	cmpl %esi, $0xffffffe0<UINT8>
0x004106ec:	movl %ebx, %esi
0x004106ee:	ja 13
0x004106f0:	testl %esi, %esi
0x004106f2:	jne 0x004106f7
0x004106f7:	addl %esi, $0xf<UINT8>
0x004106fa:	andl %esi, $0xfffffff0<UINT8>
0x004106fd:	xorl %edi, %edi
0x004106ff:	cmpl %esi, $0xffffffe0<UINT8>
0x00410702:	ja 58
0x00410704:	cmpl %ebx, 0x43775c
0x0041070a:	ja 29
0x0041070c:	pushl $0x9<UINT8>
0x0041070e:	call 0x004091f9
0x004091f9:	pushl %ebp
0x004091fa:	movl %ebp, %esp
0x004091fc:	movl %eax, 0x8(%ebp)
0x004091ff:	pushl %esi
0x00409200:	cmpl 0x436f18(,%eax,4), $0x0<UINT8>
0x00409208:	leal %esi, 0x436f18(,%eax,4)
0x0040920f:	jne 0x0040924f
0x0040924f:	pushl (%esi)
0x00409251:	call EnterCriticalSection@KERNEL32.dll
EnterCriticalSection@KERNEL32.dll: API Node	
0x00409257:	popl %esi
0x00409258:	popl %ebp
0x00409259:	ret

0x00410713:	pushl %ebx
0x00410714:	call 0x0040c034
0x0040c034:	pushl %ebp
0x0040c035:	movl %ebp, %esp
0x0040c037:	subl %esp, $0x14<UINT8>
0x0040c03a:	movl %eax, 0x439398
0x0040c03f:	movl %edx, 0x43939c
0x0040c045:	pushl %ebx
0x0040c046:	pushl %esi
0x0040c047:	leal %eax, (%eax,%eax,4)
0x0040c04a:	pushl %edi
0x0040c04b:	leal %edi, (%edx,%eax,4)
0x0040c04e:	movl %eax, 0x8(%ebp)
0x0040c051:	movl -4(%ebp), %edi
0x0040c054:	leal %ecx, 0x17(%eax)
0x0040c057:	andl %ecx, $0xfffffff0<UINT8>
0x0040c05a:	movl -16(%ebp), %ecx
0x0040c05d:	sarl %ecx, $0x4<UINT8>
0x0040c060:	decl %ecx
0x0040c061:	cmpl %ecx, $0x20<UINT8>
0x0040c064:	jnl 14
0x0040c066:	orl %esi, $0xffffffff<UINT8>
0x0040c069:	shrl %esi, %cl
0x0040c06b:	orl -8(%ebp), $0xffffffff<UINT8>
0x0040c06f:	movl -12(%ebp), %esi
0x0040c072:	jmp 0x0040c084
0x0040c084:	movl %eax, 0x439390
0x0040c089:	movl %ebx, %eax
0x0040c08b:	cmpl %ebx, %edi
0x0040c08d:	movl 0x8(%ebp), %ebx
0x0040c090:	jae 0x0040c0ab
0x0040c0ab:	cmpl %ebx, -4(%ebp)
0x0040c0ae:	jne 0x0040c129
0x0040c0b0:	movl %ebx, %edx
0x0040c0b2:	cmpl %ebx, %eax
0x0040c0b4:	movl 0x8(%ebp), %ebx
0x0040c0b7:	jae 0x0040c0ce
0x0040c0ce:	jne 89
0x0040c0d0:	cmpl %ebx, -4(%ebp)
0x0040c0d3:	jae 0x0040c0e6
0x0040c0e6:	jne 38
0x0040c0e8:	movl %ebx, %edx
0x0040c0ea:	cmpl %ebx, %eax
0x0040c0ec:	movl 0x8(%ebp), %ebx
0x0040c0ef:	jae 0x0040c0fe
0x0040c0fe:	jne 14
0x0040c100:	call 0x0040c33d
0x0040c33d:	movl %eax, 0x439398
0x0040c342:	movl %ecx, 0x439388
0x0040c348:	pushl %esi
0x0040c349:	pushl %edi
0x0040c34a:	xorl %edi, %edi
0x0040c34c:	cmpl %eax, %ecx
0x0040c34e:	jne 0x0040c380
0x0040c380:	movl %ecx, 0x43939c
0x0040c386:	pushl $0x41c4<UINT32>
0x0040c38b:	pushl $0x8<UINT8>
0x0040c38d:	leal %eax, (%eax,%eax,4)
0x0040c390:	pushl 0x4393a0
0x0040c396:	leal %esi, (%ecx,%eax,4)
0x0040c399:	call HeapAlloc@KERNEL32.dll
0x0040c39f:	cmpl %eax, %edi
0x0040c3a1:	movl 0x10(%esi), %eax
0x0040c3a4:	je 42
0x0040c3a6:	pushl $0x4<UINT8>
0x0040c3a8:	pushl $0x2000<UINT32>
0x0040c3ad:	pushl $0x100000<UINT32>
0x0040c3b2:	pushl %edi
0x0040c3b3:	call VirtualAlloc@KERNEL32.dll
VirtualAlloc@KERNEL32.dll: API Node	
0x0040c3b9:	cmpl %eax, %edi
0x0040c3bb:	movl 0xc(%esi), %eax
0x0040c3be:	jne 0x0040c3d4
0x0040c3d4:	orl 0x8(%esi), $0xffffffff<UINT8>
0x0040c3d8:	movl (%esi), %edi
0x0040c3da:	movl 0x4(%esi), %edi
0x0040c3dd:	incl 0x439398
0x0040c3e3:	movl %eax, 0x10(%esi)
0x0040c3e6:	orl (%eax), $0xffffffff<UINT8>
0x0040c3e9:	movl %eax, %esi
0x0040c3eb:	popl %edi
0x0040c3ec:	popl %esi
0x0040c3ed:	ret

0x0040c105:	movl %ebx, %eax
0x0040c107:	testl %ebx, %ebx
0x0040c109:	movl 0x8(%ebp), %ebx
0x0040c10c:	je 20
0x0040c10e:	pushl %ebx
0x0040c10f:	call 0x0040c3ee
0x0040c3ee:	pushl %ebp
0x0040c3ef:	movl %ebp, %esp
0x0040c3f1:	pushl %ecx
0x0040c3f2:	movl %ecx, 0x8(%ebp)
0x0040c3f5:	pushl %ebx
0x0040c3f6:	pushl %esi
0x0040c3f7:	pushl %edi
0x0040c3f8:	movl %esi, 0x10(%ecx)
0x0040c3fb:	movl %eax, 0x8(%ecx)
0x0040c3fe:	xorl %ebx, %ebx
0x0040c400:	testl %eax, %eax
0x0040c402:	jl 0x0040c409
0x0040c409:	movl %eax, %ebx
0x0040c40b:	pushl $0x3f<UINT8>
0x0040c40d:	imull %eax, %eax, $0x204<UINT32>
0x0040c413:	popl %edx
0x0040c414:	leal %eax, 0x144(%eax,%esi)
0x0040c41b:	movl -4(%ebp), %eax
0x0040c41e:	movl 0x8(%eax), %eax
0x0040c421:	movl 0x4(%eax), %eax
0x0040c424:	addl %eax, $0x8<UINT8>
0x0040c427:	decl %edx
0x0040c428:	jne 0x0040c41e
0x0040c42a:	movl %edi, %ebx
0x0040c42c:	pushl $0x4<UINT8>
0x0040c42e:	shll %edi, $0xf<UINT8>
0x0040c431:	addl %edi, 0xc(%ecx)
0x0040c434:	pushl $0x1000<UINT32>
0x0040c439:	pushl $0x8000<UINT32>
0x0040c43e:	pushl %edi
0x0040c43f:	call VirtualAlloc@KERNEL32.dll
0x0040c445:	testl %eax, %eax
0x0040c447:	jne 0x0040c451
0x0040c451:	leal %edx, 0x7000(%edi)
0x0040c457:	cmpl %edi, %edx
0x0040c459:	ja 60
0x0040c45b:	leal %eax, 0x10(%edi)
0x0040c45e:	orl -8(%eax), $0xffffffff<UINT8>
0x0040c462:	orl 0xfec(%eax), $0xffffffff<UINT8>
0x0040c469:	leal %ecx, 0xffc(%eax)
0x0040c46f:	movl -4(%eax), $0xff0<UINT32>
0x0040c476:	movl (%eax), %ecx
0x0040c478:	leal %ecx, -4100(%eax)
0x0040c47e:	movl 0x4(%eax), %ecx
0x0040c481:	movl 0xfe8(%eax), $0xff0<UINT32>
0x0040c48b:	addl %eax, $0x1000<UINT32>
0x0040c490:	leal %ecx, -16(%eax)
0x0040c493:	cmpl %ecx, %edx
0x0040c495:	jbe 0x0040c45e
0x0040c497:	movl %eax, -4(%ebp)
0x0040c49a:	leal %ecx, 0xc(%edi)
0x0040c49d:	addl %eax, $0x1f8<UINT32>
0x0040c4a2:	pushl $0x1<UINT8>
0x0040c4a4:	popl %edi
0x0040c4a5:	movl 0x4(%eax), %ecx
0x0040c4a8:	movl 0x8(%ecx), %eax
0x0040c4ab:	leal %ecx, 0xc(%edx)
0x0040c4ae:	movl 0x8(%eax), %ecx
0x0040c4b1:	movl 0x4(%ecx), %eax
0x0040c4b4:	andl 0x44(%esi,%ebx,4), $0x0<UINT8>
0x0040c4b9:	movl 0xc4(%esi,%ebx,4), %edi
0x0040c4c0:	movb %al, 0x43(%esi)
0x0040c4c3:	movb %cl, %al
0x0040c4c5:	incb %cl
0x0040c4c7:	testb %al, %al
0x0040c4c9:	movl %eax, 0x8(%ebp)
0x0040c4cc:	movb 0x43(%esi), %cl
0x0040c4cf:	jne 3
0x0040c4d1:	orl 0x4(%eax), %edi
0x0040c4d4:	movl %edx, $0x80000000<UINT32>
0x0040c4d9:	movl %ecx, %ebx
0x0040c4db:	shrl %edx, %cl
0x0040c4dd:	notl %edx
0x0040c4df:	andl 0x8(%eax), %edx
0x0040c4e2:	movl %eax, %ebx
0x0040c4e4:	popl %edi
0x0040c4e5:	popl %esi
0x0040c4e6:	popl %ebx
0x0040c4e7:	leave
0x0040c4e8:	ret

0x0040c114:	popl %ecx
0x0040c115:	movl %ecx, 0x10(%ebx)
0x0040c118:	movl (%ecx), %eax
0x0040c11a:	movl %eax, 0x10(%ebx)
0x0040c11d:	cmpl (%eax), $0xffffffff<UINT8>
0x0040c120:	jne 0x0040c129
0x0040c129:	movl 0x439390, %ebx
0x0040c12f:	movl %eax, 0x10(%ebx)
0x0040c132:	movl %edx, (%eax)
0x0040c134:	cmpl %edx, $0xffffffff<UINT8>
0x0040c137:	movl -4(%ebp), %edx
0x0040c13a:	je 20
0x0040c13c:	movl %ecx, 0xc4(%eax,%edx,4)
0x0040c143:	movl %edi, 0x44(%eax,%edx,4)
0x0040c147:	andl %ecx, -8(%ebp)
0x0040c14a:	andl %edi, %esi
0x0040c14c:	orl %ecx, %edi
0x0040c14e:	jne 0x0040c187
0x0040c187:	movl %ecx, %edx
0x0040c189:	xorl %edi, %edi
0x0040c18b:	imull %ecx, %ecx, $0x204<UINT32>
0x0040c191:	leal %ecx, 0x144(%ecx,%eax)
0x0040c198:	movl -12(%ebp), %ecx
0x0040c19b:	movl %ecx, 0x44(%eax,%edx,4)
0x0040c19f:	andl %ecx, %esi
0x0040c1a1:	jne 13
0x0040c1a3:	movl %ecx, 0xc4(%eax,%edx,4)
0x0040c1aa:	pushl $0x20<UINT8>
0x0040c1ac:	andl %ecx, -8(%ebp)
0x0040c1af:	popl %edi
0x0040c1b0:	testl %ecx, %ecx
0x0040c1b2:	jl 0x0040c1b9
0x0040c1b4:	shll %ecx
0x0040c1b6:	incl %edi
0x0040c1b7:	jmp 0x0040c1b0
0x0040c1b9:	movl %ecx, -12(%ebp)
0x0040c1bc:	movl %edx, 0x4(%ecx,%edi,8)
0x0040c1c0:	movl %ecx, (%edx)
0x0040c1c2:	subl %ecx, -16(%ebp)
0x0040c1c5:	movl %esi, %ecx
0x0040c1c7:	movl -8(%ebp), %ecx
0x0040c1ca:	sarl %esi, $0x4<UINT8>
0x0040c1cd:	decl %esi
0x0040c1ce:	cmpl %esi, $0x3f<UINT8>
0x0040c1d1:	jle 3
0x0040c1d3:	pushl $0x3f<UINT8>
0x0040c1d5:	popl %esi
0x0040c1d6:	cmpl %esi, %edi
0x0040c1d8:	je 0x0040c2eb
0x0040c2eb:	testl %ecx, %ecx
0x0040c2ed:	je 11
0x0040c2ef:	movl (%edx), %ecx
0x0040c2f1:	movl -4(%ecx,%edx), %ecx
0x0040c2f5:	jmp 0x0040c2fa
0x0040c2fa:	movl %esi, -16(%ebp)
0x0040c2fd:	addl %edx, %ecx
0x0040c2ff:	leal %ecx, 0x1(%esi)
0x0040c302:	movl (%edx), %ecx
0x0040c304:	movl -4(%edx,%esi), %ecx
0x0040c308:	movl %esi, -12(%ebp)
0x0040c30b:	movl %ecx, (%esi)
0x0040c30d:	testl %ecx, %ecx
0x0040c30f:	leal %edi, 0x1(%ecx)
0x0040c312:	movl (%esi), %edi
0x0040c314:	jne 0x0040c330
0x0040c316:	cmpl %ebx, 0x439394
0x0040c31c:	jne 0x0040c330
0x0040c330:	movl %ecx, -4(%ebp)
0x0040c333:	movl (%eax), %ecx
0x0040c335:	leal %eax, 0x4(%edx)
0x0040c338:	popl %edi
0x0040c339:	popl %esi
0x0040c33a:	popl %ebx
0x0040c33b:	leave
0x0040c33c:	ret

0x00410719:	pushl $0x9<UINT8>
0x0041071b:	movl %edi, %eax
0x0041071d:	call 0x0040925a
0x0040925a:	pushl %ebp
0x0040925b:	movl %ebp, %esp
0x0040925d:	movl %eax, 0x8(%ebp)
0x00409260:	pushl 0x436f18(,%eax,4)
0x00409267:	call LeaveCriticalSection@KERNEL32.dll
LeaveCriticalSection@KERNEL32.dll: API Node	
0x0040926d:	popl %ebp
0x0040926e:	ret

0x00410722:	addl %esp, $0xc<UINT8>
0x00410725:	testl %edi, %edi
0x00410727:	jne 0x00410754
0x00410754:	pushl %ebx
0x00410755:	pushl $0x0<UINT8>
0x00410757:	pushl %edi
0x00410758:	call 0x004104c0
0x004104c0:	movl %edx, 0xc(%esp)
0x004104c4:	movl %ecx, 0x4(%esp)
0x004104c8:	testl %edx, %edx
0x004104ca:	je 71
0x004104cc:	xorl %eax, %eax
0x004104ce:	movb %al, 0x8(%esp)
0x004104d2:	pushl %edi
0x004104d3:	movl %edi, %ecx
0x004104d5:	cmpl %edx, $0x4<UINT8>
0x004104d8:	jb 45
0x004104da:	negl %ecx
0x004104dc:	andl %ecx, $0x3<UINT8>
0x004104df:	je 0x004104e9
0x004104e9:	movl %ecx, %eax
0x004104eb:	shll %eax, $0x8<UINT8>
0x004104ee:	addl %eax, %ecx
0x004104f0:	movl %ecx, %eax
0x004104f2:	shll %eax, $0x10<UINT8>
0x004104f5:	addl %eax, %ecx
0x004104f7:	movl %ecx, %edx
0x004104f9:	andl %edx, $0x3<UINT8>
0x004104fc:	shrl %ecx, $0x2<UINT8>
0x004104ff:	je 6
0x00410501:	rep stosl %es:(%edi), %eax
0x00410503:	testl %edx, %edx
0x00410505:	je 0x0041050d
0x0041050d:	movl %eax, 0x8(%esp)
0x00410511:	popl %edi
0x00410512:	ret

0x0041075d:	addl %esp, $0xc<UINT8>
0x00410760:	movl %eax, %edi
0x00410762:	popl %edi
0x00410763:	popl %esi
0x00410764:	popl %ebx
0x00410765:	ret

0x0040aefb:	movl %esi, %eax
0x0040aefd:	popl %ecx
0x0040aefe:	testl %esi, %esi
0x0040af00:	popl %ecx
0x0040af01:	je 41
0x0040af03:	pushl %esi
0x0040af04:	pushl 0x437750
0x0040af0a:	call TlsSetValue@KERNEL32.dll
TlsSetValue@KERNEL32.dll: API Node	
0x0040af10:	testl %eax, %eax
0x0040af12:	je 24
0x0040af14:	pushl %esi
0x0040af15:	call 0x0040af4e
0x0040af4e:	movl %eax, 0x4(%esp)
0x0040af52:	movl 0x50(%eax), $0x4377a0<UINT32>
0x0040af59:	movl 0x14(%eax), $0x1<UINT32>
0x0040af60:	ret

0x0040af1a:	popl %ecx
0x0040af1b:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x0040af21:	orl 0x4(%esi), $0xffffffff<UINT8>
0x0040af25:	pushl $0x1<UINT8>
0x0040af27:	movl (%esi), %eax
0x0040af29:	popl %eax
0x0040af2a:	popl %esi
0x0040af2b:	ret

0x00409083:	testl %eax, %eax
0x00409085:	jne 0x0040908f
0x0040908f:	xorl %esi, %esi
0x00409091:	movl -4(%ebp), %esi
0x00409094:	call 0x0040a227
0x0040a227:	pushl %ebp
0x0040a228:	movl %ebp, %esp
0x0040a22a:	subl %esp, $0x48<UINT8>
0x0040a22d:	pushl %ebx
0x0040a22e:	pushl %esi
0x0040a22f:	pushl %edi
0x0040a230:	pushl $0x480<UINT32>
0x0040a235:	call 0x00408f87
0x00408f87:	pushl 0x438ea8
0x00408f8d:	pushl 0x8(%esp)
0x00408f91:	call 0x00408f99
0x00408f99:	cmpl 0x4(%esp), $0xffffffe0<UINT8>
0x00408f9e:	ja 34
0x00408fa0:	pushl 0x4(%esp)
0x00408fa4:	call 0x00408fc5
0x00408fc5:	pushl %esi
0x00408fc6:	movl %esi, 0x8(%esp)
0x00408fca:	cmpl %esi, 0x43775c
0x00408fd0:	pushl %edi
0x00408fd1:	ja 0x00408ff4
0x00408ff4:	testl %esi, %esi
0x00408ff6:	jne 0x00408ffb
0x00408ffb:	addl %esi, $0xf<UINT8>
0x00408ffe:	andl %esi, $0xfffffff0<UINT8>
0x00409001:	pushl %esi
0x00409002:	pushl $0x0<UINT8>
0x00409004:	pushl 0x4393a0
0x0040900a:	call HeapAlloc@KERNEL32.dll
0x00409010:	popl %edi
0x00409011:	popl %esi
0x00409012:	ret

0x00408fa9:	testl %eax, %eax
0x00408fab:	popl %ecx
0x00408fac:	jne 0x00408fc4
0x00408fc4:	ret

0x00408f96:	popl %ecx
0x00408f97:	popl %ecx
0x00408f98:	ret

0x0040a23a:	movl %esi, %eax
0x0040a23c:	popl %ecx
0x0040a23d:	testl %esi, %esi
0x0040a23f:	jne 0x0040a249
0x0040a249:	movl 0x4393c0, %esi
0x0040a24f:	movl 0x4394c0, $0x20<UINT32>
0x0040a259:	leal %eax, 0x480(%esi)
0x0040a25f:	cmpl %esi, %eax
0x0040a261:	jae 0x0040a281
0x0040a263:	andb 0x4(%esi), $0x0<UINT8>
0x0040a267:	orl (%esi), $0xffffffff<UINT8>
0x0040a26a:	andl 0x8(%esi), $0x0<UINT8>
0x0040a26e:	movb 0x5(%esi), $0xa<UINT8>
0x0040a272:	movl %eax, 0x4393c0
0x0040a277:	addl %esi, $0x24<UINT8>
0x0040a27a:	addl %eax, $0x480<UINT32>
0x0040a27f:	jmp 0x0040a25f
0x0040a281:	leal %eax, -72(%ebp)
0x0040a284:	pushl %eax
0x0040a285:	call GetStartupInfoA@KERNEL32.dll
GetStartupInfoA@KERNEL32.dll: API Node	
0x0040a28b:	cmpw -22(%ebp), $0x0<UINT8>
0x0040a290:	je 209
0x0040a296:	movl %eax, -20(%ebp)
0x0040a299:	testl %eax, %eax
0x0040a29b:	je 198
0x0040a2a1:	movl %edi, (%eax)
0x0040a2a3:	leal %ebx, 0x4(%eax)
0x0040a2a6:	leal %eax, (%ebx,%edi)
0x0040a2a9:	movl -4(%ebp), %eax
0x0040a2ac:	movl %eax, $0x800<UINT32>
0x0040a2b1:	cmpl %edi, %eax
0x0040a2b3:	jl 0x0040a2b7
0x0040a2b7:	cmpl 0x4394c0, %edi
0x0040a2bd:	jnl 0x0040a315
0x0040a315:	xorl %esi, %esi
0x0040a317:	testl %edi, %edi
0x0040a319:	jle 0x0040a367
0x0040a367:	xorl %ebx, %ebx
0x0040a369:	movl %ecx, 0x4393c0
0x0040a36f:	leal %eax, (%ebx,%ebx,8)
0x0040a372:	cmpl (%ecx,%eax,4), $0xffffffff<UINT8>
0x0040a376:	leal %esi, (%ecx,%eax,4)
0x0040a379:	jne 77
0x0040a37b:	testl %ebx, %ebx
0x0040a37d:	movb 0x4(%esi), $0xffffff81<UINT8>
0x0040a381:	jne 0x0040a388
0x0040a383:	pushl $0xfffffff6<UINT8>
0x0040a385:	popl %eax
0x0040a386:	jmp 0x0040a392
0x0040a392:	pushl %eax
0x0040a393:	call GetStdHandle@KERNEL32.dll
GetStdHandle@KERNEL32.dll: API Node	
0x0040a399:	movl %edi, %eax
0x0040a39b:	cmpl %edi, $0xffffffff<UINT8>
0x0040a39e:	je 23
0x0040a3a0:	pushl %edi
0x0040a3a1:	call GetFileType@KERNEL32.dll
GetFileType@KERNEL32.dll: API Node	
0x0040a3a7:	testl %eax, %eax
0x0040a3a9:	je 12
0x0040a3ab:	andl %eax, $0xff<UINT32>
0x0040a3b0:	movl (%esi), %edi
0x0040a3b2:	cmpl %eax, $0x2<UINT8>
0x0040a3b5:	jne 6
0x0040a3b7:	orb 0x4(%esi), $0x40<UINT8>
0x0040a3bb:	jmp 0x0040a3cc
0x0040a3cc:	incl %ebx
0x0040a3cd:	cmpl %ebx, $0x3<UINT8>
0x0040a3d0:	jl 0x0040a369
0x0040a388:	movl %eax, %ebx
0x0040a38a:	decl %eax
0x0040a38b:	negl %eax
0x0040a38d:	sbbl %eax, %eax
0x0040a38f:	addl %eax, $0xfffffff5<UINT8>
0x0040a3d2:	pushl 0x4394c0
0x0040a3d8:	call SetHandleCount@KERNEL32.dll
SetHandleCount@KERNEL32.dll: API Node	
0x0040a3de:	popl %edi
0x0040a3df:	popl %esi
0x0040a3e0:	popl %ebx
0x0040a3e1:	leave
0x0040a3e2:	ret

0x00409099:	call GetCommandLineA@KERNEL32.dll
GetCommandLineA@KERNEL32.dll: API Node	
0x0040909f:	movl 0x43a4ec, %eax
0x004090a4:	call 0x0040e610
0x0040e610:	pushl %ecx
0x0040e611:	pushl %ecx
0x0040e612:	movl %eax, 0x438fb0
0x0040e617:	pushl %ebx
0x0040e618:	pushl %ebp
0x0040e619:	movl %ebp, 0x418124
0x0040e61f:	pushl %esi
0x0040e620:	pushl %edi
0x0040e621:	xorl %ebx, %ebx
0x0040e623:	xorl %esi, %esi
0x0040e625:	xorl %edi, %edi
0x0040e627:	cmpl %eax, %ebx
0x0040e629:	jne 51
0x0040e62b:	call GetEnvironmentStringsW@KERNEL32.dll
GetEnvironmentStringsW@KERNEL32.dll: API Node	
0x0040e62d:	movl %esi, %eax
0x0040e62f:	cmpl %esi, %ebx
0x0040e631:	je 12
0x0040e633:	movl 0x438fb0, $0x1<UINT32>
0x0040e63d:	jmp 0x0040e667
0x0040e667:	cmpl %esi, %ebx
0x0040e669:	jne 0x0040e677
0x0040e677:	cmpw (%esi), %bx
0x0040e67a:	movl %eax, %esi
0x0040e67c:	je 14
0x0040e67e:	incl %eax
0x0040e67f:	incl %eax
0x0040e680:	cmpw (%eax), %bx
0x0040e683:	jne 0x0040e67e
0x0040e685:	incl %eax
0x0040e686:	incl %eax
0x0040e687:	cmpw (%eax), %bx
0x0040e68a:	jne 0x0040e67e
0x0040e68c:	subl %eax, %esi
0x0040e68e:	movl %edi, 0x418194
0x0040e694:	sarl %eax
0x0040e696:	pushl %ebx
0x0040e697:	pushl %ebx
0x0040e698:	incl %eax
0x0040e699:	pushl %ebx
0x0040e69a:	pushl %ebx
0x0040e69b:	pushl %eax
0x0040e69c:	pushl %esi
0x0040e69d:	pushl %ebx
0x0040e69e:	pushl %ebx
0x0040e69f:	movl 0x34(%esp), %eax
0x0040e6a3:	call WideCharToMultiByte@KERNEL32.dll
WideCharToMultiByte@KERNEL32.dll: API Node	
0x0040e6a5:	movl %ebp, %eax
0x0040e6a7:	cmpl %ebp, %ebx
0x0040e6a9:	je 50
0x0040e6ab:	pushl %ebp
0x0040e6ac:	call 0x00408f87
0x0040e6b1:	cmpl %eax, %ebx
0x0040e6b3:	popl %ecx
0x0040e6b4:	movl 0x10(%esp), %eax
0x0040e6b8:	je 35
0x0040e6ba:	pushl %ebx
0x0040e6bb:	pushl %ebx
0x0040e6bc:	pushl %ebp
0x0040e6bd:	pushl %eax
0x0040e6be:	pushl 0x24(%esp)
0x0040e6c2:	pushl %esi
0x0040e6c3:	pushl %ebx
0x0040e6c4:	pushl %ebx
0x0040e6c5:	call WideCharToMultiByte@KERNEL32.dll
0x0040e6c7:	testl %eax, %eax
0x0040e6c9:	jne 0x0040e6d9
0x0040e6d9:	movl %ebx, 0x10(%esp)
0x0040e6dd:	pushl %esi
0x0040e6de:	call FreeEnvironmentStringsW@KERNEL32.dll
FreeEnvironmentStringsW@KERNEL32.dll: API Node	
0x0040e6e4:	movl %eax, %ebx
0x0040e6e6:	jmp 0x0040e73b
0x0040e73b:	popl %edi
0x0040e73c:	popl %esi
0x0040e73d:	popl %ebp
0x0040e73e:	popl %ebx
0x0040e73f:	popl %ecx
0x0040e740:	popl %ecx
0x0040e741:	ret

0x004090a9:	movl 0x438dc0, %eax
0x004090ae:	call 0x0040e3c3
0x0040e3c3:	pushl %ebp
0x0040e3c4:	movl %ebp, %esp
0x0040e3c6:	pushl %ecx
0x0040e3c7:	pushl %ecx
0x0040e3c8:	pushl %ebx
0x0040e3c9:	xorl %ebx, %ebx
0x0040e3cb:	cmpl 0x4393a8, %ebx
0x0040e3d1:	pushl %esi
0x0040e3d2:	pushl %edi
0x0040e3d3:	jne 5
0x0040e3d5:	call 0x004136aa
0x004136aa:	cmpl 0x4393a8, $0x0<UINT8>
0x004136b1:	jne 18
0x004136b3:	pushl $0xfffffffd<UINT8>
0x004136b5:	call 0x004132c2
0x004132c2:	pushl %ebp
0x004132c3:	movl %ebp, %esp
0x004132c5:	subl %esp, $0x18<UINT8>
0x004132c8:	pushl %ebx
0x004132c9:	pushl %esi
0x004132ca:	pushl %edi
0x004132cb:	pushl $0x19<UINT8>
0x004132cd:	call 0x004091f9
0x00409211:	pushl %edi
0x00409212:	pushl $0x18<UINT8>
0x00409214:	call 0x00408f87
0x00408fd3:	pushl $0x9<UINT8>
0x00408fd5:	call 0x004091f9
0x00408fda:	pushl %esi
0x00408fdb:	call 0x0040c034
0x0040c092:	movl %ecx, 0x4(%ebx)
0x0040c095:	movl %edi, (%ebx)
0x0040c097:	andl %ecx, -8(%ebp)
0x0040c09a:	andl %edi, %esi
0x0040c09c:	orl %ecx, %edi
0x0040c09e:	jne 0x0040c0ab
0x00408fe0:	pushl $0x9<UINT8>
0x00408fe2:	movl %edi, %eax
0x00408fe4:	call 0x0040925a
0x00408fe9:	addl %esp, $0xc<UINT8>
0x00408fec:	testl %edi, %edi
0x00408fee:	je 4
0x00408ff0:	movl %eax, %edi
0x00408ff2:	jmp 0x00409010
0x00409219:	movl %edi, %eax
0x0040921b:	popl %ecx
0x0040921c:	testl %edi, %edi
0x0040921e:	jne 0x00409228
0x00409228:	pushl $0x11<UINT8>
0x0040922a:	call 0x004091f9
0x0040922f:	cmpl (%esi), $0x0<UINT8>
0x00409232:	popl %ecx
0x00409233:	pushl %edi
0x00409234:	jne 10
0x00409236:	call InitializeCriticalSection@KERNEL32.dll
0x0040923c:	movl (%esi), %edi
0x0040923e:	jmp 0x00409246
0x00409246:	pushl $0x11<UINT8>
0x00409248:	call 0x0040925a
0x0040924d:	popl %ecx
0x0040924e:	popl %edi
0x004132d2:	pushl 0x8(%ebp)
0x004132d5:	call 0x0041346f
0x0041346f:	movl %eax, 0x4(%esp)
0x00413473:	andl 0x439030, $0x0<UINT8>
0x0041347a:	cmpl %eax, $0xfffffffe<UINT8>
0x0041347d:	jne 0x0041348f
0x0041348f:	cmpl %eax, $0xfffffffd<UINT8>
0x00413492:	jne 16
0x00413494:	movl 0x439030, $0x1<UINT32>
0x0041349e:	jmp GetACP@KERNEL32.dll
GetACP@KERNEL32.dll: API Node	
0x004132da:	movl %ebx, %eax
0x004132dc:	popl %ecx
0x004132dd:	cmpl %ebx, 0x439158
0x004132e3:	popl %ecx
0x004132e4:	movl 0x8(%ebp), %ebx
0x004132e7:	jne 0x004132f0
0x004132f0:	testl %ebx, %ebx
0x004132f2:	je 342
0x004132f8:	xorl %edx, %edx
0x004132fa:	movl %eax, $0x438088<UINT32>
0x004132ff:	cmpl (%eax), %ebx
0x00413301:	je 116
0x00413303:	addl %eax, $0x30<UINT8>
0x00413306:	incl %edx
0x00413307:	cmpl %eax, $0x438178<UINT32>
0x0041330c:	jl 0x004132ff
0x0041330e:	leal %eax, -24(%ebp)
0x00413311:	pushl %eax
0x00413312:	pushl %ebx
0x00413313:	call GetCPInfo@KERNEL32.dll
GetCPInfo@KERNEL32.dll: API Node	
0x00413319:	pushl $0x1<UINT8>
0x0041331b:	popl %esi
0x0041331c:	cmpl %eax, %esi
0x0041331e:	jne 289
0x00413324:	pushl $0x40<UINT8>
0x00413326:	andl 0x439384, $0x0<UINT8>
0x0041332d:	popl %ecx
0x0041332e:	xorl %eax, %eax
0x00413330:	movl %edi, $0x439280<UINT32>
0x00413335:	cmpl -24(%ebp), %esi
0x00413338:	rep stosl %es:(%edi), %eax
0x0041333a:	stosb %es:(%edi), %al
0x0041333b:	movl 0x439158, %ebx
0x00413341:	jbe 235
0x00413347:	cmpb -18(%ebp), $0x0<UINT8>
0x0041334b:	je 0x0041340d
0x0041340d:	movl %eax, %esi
0x0041340f:	orb 0x439281(%eax), $0x8<UINT8>
0x00413416:	incl %eax
0x00413417:	cmpl %eax, $0xff<UINT32>
0x0041341c:	jb 0x0041340f
0x0041341e:	pushl %ebx
0x0041341f:	call 0x004134b9
0x004134b9:	movl %eax, 0x4(%esp)
0x004134bd:	subl %eax, $0x3a4<UINT32>
0x004134c2:	je 34
0x004134c4:	subl %eax, $0x4<UINT8>
0x004134c7:	je 23
0x004134c9:	subl %eax, $0xd<UINT8>
0x004134cc:	je 12
0x004134ce:	decl %eax
0x004134cf:	je 3
0x004134d1:	xorl %eax, %eax
0x004134d3:	ret

0x00413424:	popl %ecx
0x00413425:	movl 0x439384, %eax
0x0041342a:	movl 0x43916c, %esi
0x00413430:	jmp 0x00413439
0x00413439:	xorl %eax, %eax
0x0041343b:	movl %edi, $0x439160<UINT32>
0x00413440:	stosl %es:(%edi), %eax
0x00413441:	stosl %es:(%edi), %eax
0x00413442:	stosl %es:(%edi), %eax
0x00413443:	jmp 0x00413453
0x00413453:	call 0x00413515
0x00413515:	pushl %ebp
0x00413516:	movl %ebp, %esp
0x00413518:	subl %esp, $0x514<UINT32>
0x0041351e:	leal %eax, -20(%ebp)
0x00413521:	pushl %esi
0x00413522:	pushl %eax
0x00413523:	pushl 0x439158
0x00413529:	call GetCPInfo@KERNEL32.dll
0x0041352f:	cmpl %eax, $0x1<UINT8>
0x00413532:	jne 278
0x00413538:	xorl %eax, %eax
0x0041353a:	movl %esi, $0x100<UINT32>
0x0041353f:	movb -276(%ebp,%eax), %al
0x00413546:	incl %eax
0x00413547:	cmpl %eax, %esi
0x00413549:	jb 0x0041353f
0x0041354b:	movb %al, -14(%ebp)
0x0041354e:	movb -276(%ebp), $0x20<UINT8>
0x00413555:	testb %al, %al
0x00413557:	je 0x00413590
0x00413590:	pushl $0x0<UINT8>
0x00413592:	leal %eax, -1300(%ebp)
0x00413598:	pushl 0x439384
0x0041359e:	pushl 0x439158
0x004135a4:	pushl %eax
0x004135a5:	leal %eax, -276(%ebp)
0x004135ab:	pushl %esi
0x004135ac:	pushl %eax
0x004135ad:	pushl $0x1<UINT8>
0x004135af:	call 0x0041306b
0x0041306b:	pushl %ebp
0x0041306c:	movl %ebp, %esp
0x0041306e:	pushl $0xffffffff<UINT8>
0x00413070:	pushl $0x419c18<UINT32>
0x00413075:	pushl $0x40e74c<UINT32>
0x0041307a:	movl %eax, %fs:0
0x00413080:	pushl %eax
0x00413081:	movl %fs:0, %esp
0x00413088:	subl %esp, $0x18<UINT8>
0x0041308b:	pushl %ebx
0x0041308c:	pushl %esi
0x0041308d:	pushl %edi
0x0041308e:	movl -24(%ebp), %esp
0x00413091:	movl %eax, 0x43902c
0x00413096:	xorl %ebx, %ebx
0x00413098:	cmpl %eax, %ebx
0x0041309a:	jne 62
0x0041309c:	leal %eax, -28(%ebp)
0x0041309f:	pushl %eax
0x004130a0:	pushl $0x1<UINT8>
0x004130a2:	popl %esi
0x004130a3:	pushl %esi
0x004130a4:	pushl $0x4194e4<UINT32>
0x004130a9:	pushl %esi
0x004130aa:	call GetStringTypeW@KERNEL32.dll
GetStringTypeW@KERNEL32.dll: API Node	
0x004130b0:	testl %eax, %eax
0x004130b2:	je 4
0x004130b4:	movl %eax, %esi
0x004130b6:	jmp 0x004130d5
0x004130d5:	movl 0x43902c, %eax
0x004130da:	cmpl %eax, $0x2<UINT8>
0x004130dd:	jne 0x00413103
0x00413103:	cmpl %eax, $0x1<UINT8>
0x00413106:	jne 148
0x0041310c:	cmpl 0x18(%ebp), %ebx
0x0041310f:	jne 0x00413119
0x00413119:	pushl %ebx
0x0041311a:	pushl %ebx
0x0041311b:	pushl 0x10(%ebp)
0x0041311e:	pushl 0xc(%ebp)
0x00413121:	movl %eax, 0x20(%ebp)
0x00413124:	negl %eax
0x00413126:	sbbl %eax, %eax
0x00413128:	andl %eax, $0x8<UINT8>
0x0041312b:	incl %eax
0x0041312c:	pushl %eax
0x0041312d:	pushl 0x18(%ebp)
0x00413130:	call MultiByteToWideChar@KERNEL32.dll
MultiByteToWideChar@KERNEL32.dll: API Node	
0x00413136:	movl -32(%ebp), %eax
0x00413139:	cmpl %eax, %ebx
0x0041313b:	je 99
0x0041313d:	movl -4(%ebp), %ebx
0x00413140:	leal %edi, (%eax,%eax)
0x00413143:	movl %eax, %edi
0x00413145:	addl %eax, $0x3<UINT8>
0x00413148:	andb %al, $0xfffffffc<UINT8>
0x0041314a:	call 0x00408670
0x00408670:	pushl %ecx
0x00408671:	cmpl %eax, $0x1000<UINT32>
0x00408676:	leal %ecx, 0x8(%esp)
0x0040867a:	jb 0x00408690
0x00408690:	subl %ecx, %eax
0x00408692:	movl %eax, %esp
0x00408694:	testl (%ecx), %eax
0x00408696:	movl %esp, %ecx
0x00408698:	movl %ecx, (%eax)
0x0040869a:	movl %eax, 0x4(%eax)
0x0040869d:	pushl %eax
0x0040869e:	ret

0x0041314f:	movl -24(%ebp), %esp
0x00413152:	movl %esi, %esp
0x00413154:	movl -36(%ebp), %esi
0x00413157:	pushl %edi
0x00413158:	pushl %ebx
0x00413159:	pushl %esi
0x0041315a:	call 0x004104c0
