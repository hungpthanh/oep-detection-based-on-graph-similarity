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
0x0041070a:	ja 0x00410729
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
0x004136b1:	jne 0x004136c5
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
0x0041315f:	addl %esp, $0xc<UINT8>
0x00413162:	jmp 0x0041316f
0x0041316f:	orl -4(%ebp), $0xffffffff<UINT8>
0x00413173:	cmpl %esi, %ebx
0x00413175:	je 41
0x00413177:	pushl -32(%ebp)
0x0041317a:	pushl %esi
0x0041317b:	pushl 0x10(%ebp)
0x0041317e:	pushl 0xc(%ebp)
0x00413181:	pushl $0x1<UINT8>
0x00413183:	pushl 0x18(%ebp)
0x00413186:	call MultiByteToWideChar@KERNEL32.dll
0x0041318c:	cmpl %eax, %ebx
0x0041318e:	je 16
0x00413190:	pushl 0x14(%ebp)
0x00413193:	pushl %eax
0x00413194:	pushl %esi
0x00413195:	pushl 0x8(%ebp)
0x00413198:	call GetStringTypeW@KERNEL32.dll
0x0041319e:	jmp 0x004131a2
0x004131a2:	leal %esp, -52(%ebp)
0x004131a5:	movl %ecx, -16(%ebp)
0x004131a8:	movl %fs:0, %ecx
0x004131af:	popl %edi
0x004131b0:	popl %esi
0x004131b1:	popl %ebx
0x004131b2:	leave
0x004131b3:	ret

0x004135b4:	pushl $0x0<UINT8>
0x004135b6:	leal %eax, -532(%ebp)
0x004135bc:	pushl 0x439158
0x004135c2:	pushl %esi
0x004135c3:	pushl %eax
0x004135c4:	leal %eax, -276(%ebp)
0x004135ca:	pushl %esi
0x004135cb:	pushl %eax
0x004135cc:	pushl %esi
0x004135cd:	pushl 0x439384
0x004135d3:	call 0x00414e6b
0x00414e6b:	pushl %ebp
0x00414e6c:	movl %ebp, %esp
0x00414e6e:	pushl $0xffffffff<UINT8>
0x00414e70:	pushl $0x419d90<UINT32>
0x00414e75:	pushl $0x40e74c<UINT32>
0x00414e7a:	movl %eax, %fs:0
0x00414e80:	pushl %eax
0x00414e81:	movl %fs:0, %esp
0x00414e88:	subl %esp, $0x1c<UINT8>
0x00414e8b:	pushl %ebx
0x00414e8c:	pushl %esi
0x00414e8d:	pushl %edi
0x00414e8e:	movl -24(%ebp), %esp
0x00414e91:	xorl %edi, %edi
0x00414e93:	cmpl 0x439064, %edi
0x00414e99:	jne 0x00414ee1
0x00414e9b:	pushl %edi
0x00414e9c:	pushl %edi
0x00414e9d:	pushl $0x1<UINT8>
0x00414e9f:	popl %ebx
0x00414ea0:	pushl %ebx
0x00414ea1:	pushl $0x4194e4<UINT32>
0x00414ea6:	movl %esi, $0x100<UINT32>
0x00414eab:	pushl %esi
0x00414eac:	pushl %edi
0x00414ead:	call LCMapStringW@KERNEL32.dll
LCMapStringW@KERNEL32.dll: API Node	
0x00414eb3:	testl %eax, %eax
0x00414eb5:	je 8
0x00414eb7:	movl 0x439064, %ebx
0x00414ebd:	jmp 0x00414ee1
0x00414ee1:	cmpl 0x14(%ebp), %edi
0x00414ee4:	jle 16
0x00414ee6:	pushl 0x14(%ebp)
0x00414ee9:	pushl 0x10(%ebp)
0x00414eec:	call 0x0041508f
0x0041508f:	movl %edx, 0x8(%esp)
0x00415093:	movl %eax, 0x4(%esp)
0x00415097:	testl %edx, %edx
0x00415099:	pushl %esi
0x0041509a:	leal %ecx, -1(%edx)
0x0041509d:	je 13
0x0041509f:	cmpb (%eax), $0x0<UINT8>
0x004150a2:	je 8
0x004150a4:	incl %eax
0x004150a5:	movl %esi, %ecx
0x004150a7:	decl %ecx
0x004150a8:	testl %esi, %esi
0x004150aa:	jne 0x0041509f
0x004150ac:	cmpb (%eax), $0x0<UINT8>
0x004150af:	popl %esi
0x004150b0:	jne 0x004150b7
0x004150b7:	movl %eax, %edx
0x004150b9:	ret

0x00414ef1:	popl %ecx
0x00414ef2:	popl %ecx
0x00414ef3:	movl 0x14(%ebp), %eax
0x00414ef6:	movl %eax, 0x439064
0x00414efb:	cmpl %eax, $0x2<UINT8>
0x00414efe:	jne 0x00414f1d
0x00414f1d:	cmpl %eax, $0x1<UINT8>
0x00414f20:	jne 211
0x00414f26:	cmpl 0x20(%ebp), %edi
0x00414f29:	jne 0x00414f33
0x00414f33:	pushl %edi
0x00414f34:	pushl %edi
0x00414f35:	pushl 0x14(%ebp)
0x00414f38:	pushl 0x10(%ebp)
0x00414f3b:	movl %eax, 0x24(%ebp)
0x00414f3e:	negl %eax
0x00414f40:	sbbl %eax, %eax
0x00414f42:	andl %eax, $0x8<UINT8>
0x00414f45:	incl %eax
0x00414f46:	pushl %eax
0x00414f47:	pushl 0x20(%ebp)
0x00414f4a:	call MultiByteToWideChar@KERNEL32.dll
0x00414f50:	movl %ebx, %eax
0x00414f52:	movl -28(%ebp), %ebx
0x00414f55:	cmpl %ebx, %edi
0x00414f57:	je 156
0x00414f5d:	movl -4(%ebp), %edi
0x00414f60:	leal %eax, (%ebx,%ebx)
0x00414f63:	addl %eax, $0x3<UINT8>
0x00414f66:	andb %al, $0xfffffffc<UINT8>
0x00414f68:	call 0x00408670
0x00414f6d:	movl -24(%ebp), %esp
0x00414f70:	movl %eax, %esp
0x00414f72:	movl -36(%ebp), %eax
0x00414f75:	orl -4(%ebp), $0xffffffff<UINT8>
0x00414f79:	jmp 0x00414f8e
0x00414f8e:	cmpl -36(%ebp), %edi
0x00414f91:	je 102
0x00414f93:	pushl %ebx
0x00414f94:	pushl -36(%ebp)
0x00414f97:	pushl 0x14(%ebp)
0x00414f9a:	pushl 0x10(%ebp)
0x00414f9d:	pushl $0x1<UINT8>
0x00414f9f:	pushl 0x20(%ebp)
0x00414fa2:	call MultiByteToWideChar@KERNEL32.dll
0x00414fa8:	testl %eax, %eax
0x00414faa:	je 77
0x00414fac:	pushl %edi
0x00414fad:	pushl %edi
0x00414fae:	pushl %ebx
0x00414faf:	pushl -36(%ebp)
0x00414fb2:	pushl 0xc(%ebp)
0x00414fb5:	pushl 0x8(%ebp)
0x00414fb8:	call LCMapStringW@KERNEL32.dll
0x00414fbe:	movl %esi, %eax
0x00414fc0:	movl -40(%ebp), %esi
0x00414fc3:	cmpl %esi, %edi
0x00414fc5:	je 50
0x00414fc7:	testb 0xd(%ebp), $0x4<UINT8>
0x00414fcb:	je 0x0041500d
0x0041500d:	movl -4(%ebp), $0x1<UINT32>
0x00415014:	leal %eax, (%esi,%esi)
0x00415017:	addl %eax, $0x3<UINT8>
0x0041501a:	andb %al, $0xfffffffc<UINT8>
0x0041501c:	call 0x00408670
0x00415021:	movl -24(%ebp), %esp
0x00415024:	movl %ebx, %esp
0x00415026:	movl -32(%ebp), %ebx
0x00415029:	orl -4(%ebp), $0xffffffff<UINT8>
0x0041502d:	jmp 0x00415041
0x00415041:	cmpl %ebx, %edi
0x00415043:	je -76
0x00415045:	pushl %esi
0x00415046:	pushl %ebx
0x00415047:	pushl -28(%ebp)
0x0041504a:	pushl -36(%ebp)
0x0041504d:	pushl 0xc(%ebp)
0x00415050:	pushl 0x8(%ebp)
0x00415053:	call LCMapStringW@KERNEL32.dll
0x00415059:	testl %eax, %eax
0x0041505b:	je -100
0x0041505d:	cmpl 0x1c(%ebp), %edi
0x00415060:	pushl %edi
0x00415061:	pushl %edi
0x00415062:	jne 0x00415068
0x00415068:	pushl 0x1c(%ebp)
0x0041506b:	pushl 0x18(%ebp)
0x0041506e:	pushl %esi
0x0041506f:	pushl %ebx
0x00415070:	pushl $0x220<UINT32>
0x00415075:	pushl 0x20(%ebp)
0x00415078:	call WideCharToMultiByte@KERNEL32.dll
0x0041507e:	movl %esi, %eax
0x00415080:	cmpl %esi, %edi
0x00415082:	je -143
0x00415088:	movl %eax, %esi
0x0041508a:	jmp 0x00414ffb
0x00414ffb:	leal %esp, -56(%ebp)
0x00414ffe:	movl %ecx, -16(%ebp)
0x00415001:	movl %fs:0, %ecx
0x00415008:	popl %edi
0x00415009:	popl %esi
0x0041500a:	popl %ebx
0x0041500b:	leave
0x0041500c:	ret

0x004135d8:	pushl $0x0<UINT8>
0x004135da:	leal %eax, -788(%ebp)
0x004135e0:	pushl 0x439158
0x004135e6:	pushl %esi
0x004135e7:	pushl %eax
0x004135e8:	leal %eax, -276(%ebp)
0x004135ee:	pushl %esi
0x004135ef:	pushl %eax
0x004135f0:	pushl $0x200<UINT32>
0x004135f5:	pushl 0x439384
0x004135fb:	call 0x00414e6b
0x00413600:	addl %esp, $0x5c<UINT8>
0x00413603:	xorl %eax, %eax
0x00413605:	leal %ecx, -1300(%ebp)
0x0041360b:	movw %dx, (%ecx)
0x0041360e:	testb %dl, $0x1<UINT8>
0x00413611:	je 0x00413629
0x00413629:	testb %dl, $0x2<UINT8>
0x0041362c:	je 0x0041363e
0x0041363e:	andb 0x439180(%eax), $0x0<UINT8>
0x00413645:	incl %eax
0x00413646:	incl %ecx
0x00413647:	incl %ecx
0x00413648:	cmpl %eax, %esi
0x0041364a:	jb 0x0041360b
0x00413613:	orb 0x439281(%eax), $0x10<UINT8>
0x0041361a:	movb %dl, -532(%ebp,%eax)
0x00413621:	movb 0x439180(%eax), %dl
0x00413627:	jmp 0x00413645
0x0041362e:	orb 0x439281(%eax), $0x20<UINT8>
0x00413635:	movb %dl, -788(%ebp,%eax)
0x0041363c:	jmp 0x00413621
0x0041364c:	jmp 0x00413697
0x00413697:	popl %esi
0x00413698:	leave
0x00413699:	ret

0x00413458:	jmp 0x004132e9
0x004132e9:	xorl %esi, %esi
0x004132eb:	jmp 0x00413460
0x00413460:	pushl $0x19<UINT8>
0x00413462:	call 0x0040925a
0x00413467:	popl %ecx
0x00413468:	movl %eax, %esi
0x0041346a:	popl %edi
0x0041346b:	popl %esi
0x0041346c:	popl %ebx
0x0041346d:	leave
0x0041346e:	ret

0x004136ba:	popl %ecx
0x004136bb:	movl 0x4393a8, $0x1<UINT32>
0x004136c5:	ret

0x0040e3da:	movl %esi, $0x438eac<UINT32>
0x0040e3df:	pushl $0x104<UINT32>
0x0040e3e4:	pushl %esi
0x0040e3e5:	pushl %ebx
0x0040e3e6:	call GetModuleFileNameA@KERNEL32.dll
GetModuleFileNameA@KERNEL32.dll: API Node	
0x0040e3ec:	movl %eax, 0x43a4ec
0x0040e3f1:	movl 0x438e90, %esi
0x0040e3f7:	movl %edi, %esi
0x0040e3f9:	cmpb (%eax), %bl
0x0040e3fb:	je 2
0x0040e3fd:	movl %edi, %eax
0x0040e3ff:	leal %eax, -8(%ebp)
0x0040e402:	pushl %eax
0x0040e403:	leal %eax, -4(%ebp)
0x0040e406:	pushl %eax
0x0040e407:	pushl %ebx
0x0040e408:	pushl %ebx
0x0040e409:	pushl %edi
0x0040e40a:	call 0x0040e45c
0x0040e45c:	pushl %ebp
0x0040e45d:	movl %ebp, %esp
0x0040e45f:	movl %ecx, 0x18(%ebp)
0x0040e462:	movl %eax, 0x14(%ebp)
0x0040e465:	pushl %ebx
0x0040e466:	pushl %esi
0x0040e467:	andl (%ecx), $0x0<UINT8>
0x0040e46a:	movl %esi, 0x10(%ebp)
0x0040e46d:	pushl %edi
0x0040e46e:	movl %edi, 0xc(%ebp)
0x0040e471:	movl (%eax), $0x1<UINT32>
0x0040e477:	movl %eax, 0x8(%ebp)
0x0040e47a:	testl %edi, %edi
0x0040e47c:	je 0x0040e486
0x0040e486:	cmpb (%eax), $0x22<UINT8>
0x0040e489:	jne 68
0x0040e48b:	movb %dl, 0x1(%eax)
0x0040e48e:	incl %eax
0x0040e48f:	cmpb %dl, $0x22<UINT8>
0x0040e492:	je 0x0040e4bd
0x0040e494:	testb %dl, %dl
0x0040e496:	je 37
0x0040e498:	movzbl %edx, %dl
0x0040e49b:	testb 0x439281(%edx), $0x4<UINT8>
0x0040e4a2:	je 0x0040e4b0
0x0040e4b0:	incl (%ecx)
0x0040e4b2:	testl %esi, %esi
0x0040e4b4:	je 0x0040e48b
0x0040e4bd:	incl (%ecx)
0x0040e4bf:	testl %esi, %esi
0x0040e4c1:	je 0x0040e4c7
0x0040e4c7:	cmpb (%eax), $0x22<UINT8>
0x0040e4ca:	jne 70
0x0040e4cc:	incl %eax
0x0040e4cd:	jmp 0x0040e512
0x0040e512:	andl 0x18(%ebp), $0x0<UINT8>
0x0040e516:	cmpb (%eax), $0x0<UINT8>
0x0040e519:	je 0x0040e5ff
0x0040e5ff:	testl %edi, %edi
0x0040e601:	je 0x0040e606
0x0040e606:	movl %eax, 0x14(%ebp)
0x0040e609:	popl %edi
0x0040e60a:	popl %esi
0x0040e60b:	popl %ebx
0x0040e60c:	incl (%eax)
0x0040e60e:	popl %ebp
0x0040e60f:	ret

0x0040e40f:	movl %eax, -8(%ebp)
0x0040e412:	movl %ecx, -4(%ebp)
0x0040e415:	leal %eax, (%eax,%ecx,4)
0x0040e418:	pushl %eax
0x0040e419:	call 0x00408f87
0x0040e41e:	movl %esi, %eax
0x0040e420:	addl %esp, $0x18<UINT8>
0x0040e423:	cmpl %esi, %ebx
0x0040e425:	jne 0x0040e42f
0x0040e42f:	leal %eax, -8(%ebp)
0x0040e432:	pushl %eax
0x0040e433:	leal %eax, -4(%ebp)
0x0040e436:	pushl %eax
0x0040e437:	movl %eax, -4(%ebp)
0x0040e43a:	leal %eax, (%esi,%eax,4)
0x0040e43d:	pushl %eax
0x0040e43e:	pushl %esi
0x0040e43f:	pushl %edi
0x0040e440:	call 0x0040e45c
0x0040e47e:	movl (%edi), %esi
0x0040e480:	addl %edi, $0x4<UINT8>
0x0040e483:	movl 0xc(%ebp), %edi
0x0040e4b6:	movb %dl, (%eax)
0x0040e4b8:	movb (%esi), %dl
0x0040e4ba:	incl %esi
0x0040e4bb:	jmp 0x0040e48b
0x0040e4c3:	andb (%esi), $0x0<UINT8>
0x0040e4c6:	incl %esi
0x0040e603:	andl (%edi), $0x0<UINT8>
0x0040e445:	movl %eax, -4(%ebp)
0x0040e448:	addl %esp, $0x14<UINT8>
0x0040e44b:	decl %eax
0x0040e44c:	movl 0x438e78, %esi
0x0040e452:	popl %edi
0x0040e453:	popl %esi
0x0040e454:	movl 0x438e74, %eax
0x0040e459:	popl %ebx
0x0040e45a:	leave
0x0040e45b:	ret

0x004090b3:	call 0x0040e30a
0x0040e30a:	pushl %ebx
0x0040e30b:	xorl %ebx, %ebx
0x0040e30d:	cmpl 0x4393a8, %ebx
0x0040e313:	pushl %esi
0x0040e314:	pushl %edi
0x0040e315:	jne 0x0040e31c
0x0040e31c:	movl %esi, 0x438dc0
0x0040e322:	xorl %edi, %edi
0x0040e324:	movb %al, (%esi)
0x0040e326:	cmpb %al, %bl
0x0040e328:	je 0x0040e33c
0x0040e32a:	cmpb %al, $0x3d<UINT8>
0x0040e32c:	je 0x0040e32f
0x0040e32f:	pushl %esi
0x0040e330:	call 0x0040fa20
0x0040fa20:	movl %ecx, 0x4(%esp)
0x0040fa24:	testl %ecx, $0x3<UINT32>
0x0040fa2a:	je 0x0040fa40
0x0040fa40:	movl %eax, (%ecx)
0x0040fa42:	movl %edx, $0x7efefeff<UINT32>
0x0040fa47:	addl %edx, %eax
0x0040fa49:	xorl %eax, $0xffffffff<UINT8>
0x0040fa4c:	xorl %eax, %edx
0x0040fa4e:	addl %ecx, $0x4<UINT8>
0x0040fa51:	testl %eax, $0x81010100<UINT32>
0x0040fa56:	je 0x0040fa40
0x0040fa58:	movl %eax, -4(%ecx)
0x0040fa5b:	testb %al, %al
0x0040fa5d:	je 50
0x0040fa5f:	testb %ah, %ah
0x0040fa61:	je 36
0x0040fa63:	testl %eax, $0xff0000<UINT32>
0x0040fa68:	je 19
0x0040fa6a:	testl %eax, $0xff000000<UINT32>
0x0040fa6f:	je 0x0040fa73
0x0040fa73:	leal %eax, -1(%ecx)
0x0040fa76:	movl %ecx, 0x4(%esp)
0x0040fa7a:	subl %eax, %ecx
0x0040fa7c:	ret

0x0040e335:	popl %ecx
0x0040e336:	leal %esi, 0x1(%esi,%eax)
0x0040e33a:	jmp 0x0040e324
0x0040e33c:	leal %eax, 0x4(,%edi,4)
0x0040e343:	pushl %eax
0x0040e344:	call 0x00408f87
0x0040e349:	movl %esi, %eax
0x0040e34b:	popl %ecx
0x0040e34c:	cmpl %esi, %ebx
0x0040e34e:	movl 0x438e80, %esi
0x0040e354:	jne 0x0040e35e
0x0040e35e:	movl %edi, 0x438dc0
0x0040e364:	cmpb (%edi), %bl
0x0040e366:	je 57
0x0040e368:	pushl %ebp
0x0040e369:	pushl %edi
0x0040e36a:	call 0x0040fa20
0x0040e36f:	movl %ebp, %eax
0x0040e371:	popl %ecx
0x0040e372:	incl %ebp
0x0040e373:	cmpb (%edi), $0x3d<UINT8>
0x0040e376:	je 0x0040e39a
0x0040e39a:	addl %edi, %ebp
0x0040e39c:	cmpb (%edi), %bl
0x0040e39e:	jne -55
0x0040e3a0:	popl %ebp
0x0040e3a1:	pushl 0x438dc0
0x0040e3a7:	call 0x004088f8
0x004088f8:	pushl %esi
0x004088f9:	movl %esi, 0x8(%esp)
0x004088fd:	testl %esi, %esi
0x004088ff:	je 61
0x00408901:	pushl $0x9<UINT8>
0x00408903:	call 0x004091f9
0x00408908:	pushl %esi
0x00408909:	call 0x0040bcde
0x0040bcde:	movl %eax, 0x439398
0x0040bce3:	leal %ecx, (%eax,%eax,4)
0x0040bce6:	movl %eax, 0x43939c
0x0040bceb:	leal %ecx, (%eax,%ecx,4)
0x0040bcee:	cmpl %eax, %ecx
0x0040bcf0:	jae 0x0040bd06
0x0040bcf2:	movl %edx, 0x4(%esp)
0x0040bcf6:	subl %edx, 0xc(%eax)
0x0040bcf9:	cmpl %edx, $0x100000<UINT32>
0x0040bcff:	jb 0x0040bd08
0x0040bd01:	addl %eax, $0x14<UINT8>
0x0040bd04:	jmp 0x0040bcee
0x0040bd06:	xorl %eax, %eax
0x0040bd08:	ret

0x0040890e:	popl %ecx
0x0040890f:	testl %eax, %eax
0x00408911:	popl %ecx
0x00408912:	je 0x00408927
0x00408927:	pushl $0x9<UINT8>
0x00408929:	call 0x0040925a
0x0040892e:	popl %ecx
0x0040892f:	pushl %esi
0x00408930:	pushl $0x0<UINT8>
0x00408932:	pushl 0x4393a0
0x00408938:	call HeapFree@KERNEL32.dll
HeapFree@KERNEL32.dll: API Node	
0x0040893e:	popl %esi
0x0040893f:	ret

0x0040e3ac:	popl %ecx
0x0040e3ad:	movl 0x438dc0, %ebx
0x0040e3b3:	movl (%esi), %ebx
0x0040e3b5:	popl %edi
0x0040e3b6:	popl %esi
0x0040e3b7:	movl 0x4393a4, $0x1<UINT32>
0x0040e3c1:	popl %ebx
0x0040e3c2:	ret

0x004090b8:	call 0x0040ba4f
0x0040ba4f:	movl %eax, 0x436ef8
0x0040ba54:	testl %eax, %eax
0x0040ba56:	je 2
0x0040ba58:	call 0x004089e5
0x004089e5:	call 0x004089fd
0x004089fd:	movl %eax, $0x40db7a<UINT32>
0x00408a02:	movl 0x437774, $0x40d824<UINT32>
0x00408a0c:	movl 0x437770, %eax
0x00408a11:	movl 0x437778, $0x40d88a<UINT32>
0x00408a1b:	movl 0x43777c, $0x40d7ca<UINT32>
0x00408a25:	movl 0x437780, $0x40d872<UINT32>
0x00408a2f:	movl 0x437784, %eax
0x00408a34:	ret

0x004089ea:	call 0x0040d7a1
0x0040d7a1:	pushl $0x4191d4<UINT32>
0x0040d7a6:	call GetModuleHandleA@KERNEL32.dll
GetModuleHandleA@KERNEL32.dll: API Node	
0x0040d7ac:	testl %eax, %eax
0x0040d7ae:	je 21
0x0040d7b0:	pushl $0x4191b8<UINT32>
0x0040d7b5:	pushl %eax
0x0040d7b6:	call GetProcAddress@KERNEL32.dll
0x0040d7bc:	testl %eax, %eax
0x0040d7be:	je 5
0x0040d7c0:	pushl $0x0<UINT8>
0x0040d7c2:	call IsProcessorFeaturePresent@KERNEL32
IsProcessorFeaturePresent@KERNEL32: API Node	
0x0040d7c4:	ret

0x004089ef:	movl 0x438dbc, %eax
0x004089f4:	call 0x0040d751
0x0040d751:	pushl $0x30000<UINT32>
0x0040d756:	pushl $0x10000<UINT32>
0x0040d75b:	call 0x00412772
0x00412772:	movl %eax, 0x8(%esp)
0x00412776:	andl %eax, $0xfff7ffff<UINT32>
0x0041277b:	pushl %eax
0x0041277c:	pushl 0x8(%esp)
0x00412780:	call 0x0041273d
0x0041273d:	pushl %ebp
0x0041273e:	movl %ebp, %esp
0x00412740:	pushl %ecx
0x00412741:	pushl %esi
0x00412742:	fwait
0x00412743:	fnstcw -4(%ebp)
0x00412746:	pushl -4(%ebp)
0x00412749:	call 0x004127b3
0x004127b3:	pushl %ebx
0x004127b4:	movl %ebx, 0x8(%esp)
0x004127b8:	xorl %eax, %eax
0x004127ba:	pushl %ebp
0x004127bb:	testb %bl, $0x1<UINT8>
0x004127be:	pushl %edi
0x004127bf:	je 0x004127c4
0x004127c4:	testb %bl, $0x4<UINT8>
0x004127c7:	je 0x004127cb
0x004127cb:	testb %bl, $0x8<UINT8>
0x004127ce:	je 0x004127d2
0x004127d2:	testb %bl, $0x10<UINT8>
0x004127d5:	je 2
0x004127d7:	orb %al, $0x2<UINT8>
0x004127d9:	testb %bl, $0x20<UINT8>
0x004127dc:	je 2
0x004127de:	orb %al, $0x1<UINT8>
0x004127e0:	testb %bl, $0x2<UINT8>
0x004127e3:	je 0x004127ea
0x004127ea:	movzwl %ecx, %bx
0x004127ed:	pushl %esi
0x004127ee:	movl %edx, %ecx
0x004127f0:	movl %esi, $0xc00<UINT32>
0x004127f5:	movl %edi, $0x300<UINT32>
0x004127fa:	andl %edx, %esi
0x004127fc:	movl %ebp, $0x200<UINT32>
0x00412801:	je 31
0x00412803:	cmpl %edx, $0x400<UINT32>
0x00412809:	je 20
0x0041280b:	cmpl %edx, $0x800<UINT32>
0x00412811:	je 8
0x00412813:	cmpl %edx, %esi
0x00412815:	jne 11
0x00412817:	orl %eax, %edi
0x00412819:	jmp 0x00412822
0x00412822:	andl %ecx, %edi
0x00412824:	popl %esi
0x00412825:	je 11
0x00412827:	cmpl %ecx, %ebp
0x00412829:	jne 0x00412837
0x00412837:	popl %edi
0x00412838:	popl %ebp
0x00412839:	testb %bh, $0x10<UINT8>
0x0041283c:	popl %ebx
0x0041283d:	je 0x00412844
0x00412844:	ret

0x0041274e:	movl %esi, %eax
0x00412750:	movl %eax, 0xc(%ebp)
0x00412753:	notl %eax
0x00412755:	andl %esi, %eax
0x00412757:	movl %eax, 0x8(%ebp)
0x0041275a:	andl %eax, 0xc(%ebp)
0x0041275d:	orl %esi, %eax
0x0041275f:	pushl %esi
0x00412760:	call 0x00412845
0x00412845:	pushl %ebx
0x00412846:	movl %ebx, 0x8(%esp)
0x0041284a:	xorl %eax, %eax
0x0041284c:	pushl %esi
0x0041284d:	testb %bl, $0x10<UINT8>
0x00412850:	je 0x00412855
0x00412855:	testb %bl, $0x8<UINT8>
0x00412858:	je 0x0041285c
0x0041285c:	testb %bl, $0x4<UINT8>
0x0041285f:	je 0x00412863
0x00412863:	testb %bl, $0x2<UINT8>
0x00412866:	je 2
0x00412868:	orb %al, $0x10<UINT8>
0x0041286a:	testb %bl, $0x1<UINT8>
0x0041286d:	je 2
0x0041286f:	orb %al, $0x20<UINT8>
0x00412871:	testl %ebx, $0x80000<UINT32>
0x00412877:	je 0x0041287b
0x0041287b:	movl %ecx, %ebx
0x0041287d:	movl %edx, $0x300<UINT32>
0x00412882:	andl %ecx, %edx
0x00412884:	movl %esi, $0x200<UINT32>
0x00412889:	je 29
0x0041288b:	cmpl %ecx, $0x100<UINT32>
0x00412891:	je 18
0x00412893:	cmpl %ecx, %esi
0x00412895:	je 9
0x00412897:	cmpl %ecx, %edx
0x00412899:	jne 13
0x0041289b:	orb %ah, $0xc<UINT8>
0x0041289e:	jmp 0x004128a8
0x004128a8:	movl %ecx, %ebx
0x004128aa:	andl %ecx, $0x30000<UINT32>
0x004128b0:	je 12
0x004128b2:	cmpl %ecx, $0x10000<UINT32>
0x004128b8:	jne 6
0x004128ba:	orl %eax, %esi
0x004128bc:	jmp 0x004128c0
0x004128c0:	popl %esi
0x004128c1:	testl %ebx, $0x40000<UINT32>
0x004128c7:	popl %ebx
0x004128c8:	je 0x004128cd
0x004128cd:	ret

0x00412765:	popl %ecx
0x00412766:	movl 0xc(%ebp), %eax
0x00412769:	popl %ecx
0x0041276a:	fldcw 0xc(%ebp)
0x0041276d:	movl %eax, %esi
0x0041276f:	popl %esi
0x00412770:	leave
0x00412771:	ret

0x00412785:	popl %ecx
0x00412786:	popl %ecx
0x00412787:	ret

0x0040d760:	popl %ecx
0x0040d761:	popl %ecx
0x0040d762:	ret

0x004089f9:	fnclex
0x004089fb:	ret

0x0040ba5a:	pushl $0x41c020<UINT32>
0x0040ba5f:	pushl $0x41c00c<UINT32>
0x0040ba64:	call 0x0040bb73
0x0040bb73:	pushl %esi
0x0040bb74:	movl %esi, 0x8(%esp)
0x0040bb78:	cmpl %esi, 0xc(%esp)
0x0040bb7c:	jae 0x0040bb8b
0x0040bb7e:	movl %eax, (%esi)
0x0040bb80:	testl %eax, %eax
0x0040bb82:	je 0x0040bb86
0x0040bb86:	addl %esi, $0x4<UINT8>
0x0040bb89:	jmp 0x0040bb78
0x0040bb84:	call 0x004113b6
0x004088c9:	pushl $0x80<UINT32>
0x004088ce:	call 0x00408f87
0x004088d3:	testl %eax, %eax
0x004088d5:	popl %ecx
0x004088d6:	movl 0x4393b0, %eax
0x004088db:	jne 0x004088ea
0x004088ea:	andl (%eax), $0x0<UINT8>
0x004088ed:	movl %eax, 0x4393b0
0x004088f2:	movl 0x4393ac, %eax
0x004088f7:	ret

0x00409a51:	movl %eax, 0x43a4e0
0x00409a56:	pushl %esi
0x00409a57:	pushl $0x14<UINT8>
0x00409a59:	testl %eax, %eax
0x00409a5b:	popl %esi
0x00409a5c:	jne 7
0x00409a5e:	movl %eax, $0x200<UINT32>
0x00409a63:	jmp 0x00409a6b
0x00409a6b:	movl 0x43a4e0, %eax
0x00409a70:	pushl $0x4<UINT8>
0x00409a72:	pushl %eax
0x00409a73:	call 0x004106dd
0x00410729:	pushl %esi
0x0041072a:	pushl $0x8<UINT8>
0x0041072c:	pushl 0x4393a0
0x00410732:	call HeapAlloc@KERNEL32.dll
0x00410738:	movl %edi, %eax
0x0041073a:	testl %edi, %edi
0x0041073c:	jne 0x00410760
0x00409a78:	popl %ecx
0x00409a79:	movl 0x4394c4, %eax
0x00409a7e:	testl %eax, %eax
0x00409a80:	popl %ecx
0x00409a81:	jne 0x00409aa4
0x00409aa4:	xorl %ecx, %ecx
0x00409aa6:	movl %eax, $0x437340<UINT32>
0x00409aab:	movl %edx, 0x4394c4
0x00409ab1:	movl (%ecx,%edx), %eax
0x00409ab4:	addl %eax, $0x20<UINT8>
0x00409ab7:	addl %ecx, $0x4<UINT8>
0x00409aba:	cmpl %eax, $0x4375c0<UINT32>
0x00409abf:	jl 0x00409aab
0x00409ac1:	xorl %ecx, %ecx
0x00409ac3:	movl %edx, $0x437350<UINT32>
0x00409ac8:	movl %esi, %ecx
0x00409aca:	movl %eax, %ecx
0x00409acc:	sarl %esi, $0x5<UINT8>
0x00409acf:	andl %eax, $0x1f<UINT8>
0x00409ad2:	movl %esi, 0x4393c0(,%esi,4)
0x00409ad9:	leal %eax, (%eax,%eax,8)
0x00409adc:	movl %eax, (%esi,%eax,4)
0x00409adf:	cmpl %eax, $0xffffffff<UINT8>
0x00409ae2:	je 4
0x00409ae4:	testl %eax, %eax
0x00409ae6:	jne 0x00409aeb
0x00409aeb:	addl %edx, $0x20<UINT8>
0x00409aee:	incl %ecx
0x00409aef:	cmpl %edx, $0x4373b0<UINT32>
0x00409af5:	jl 0x00409ac8
0x00409af7:	popl %esi
0x00409af8:	ret

0x004113a5:	pushl $0x41135f<UINT32>
0x004113aa:	call SetUnhandledExceptionFilter@KERNEL32.dll
SetUnhandledExceptionFilter@KERNEL32.dll: API Node	
0x004113b0:	movl 0x439028, %eax
0x004113b5:	ret

0x0040bb8b:	popl %esi
0x0040bb8c:	ret

0x0040ba69:	pushl $0x41c008<UINT32>
0x0040ba6e:	pushl $0x41c000<UINT32>
0x0040ba73:	call 0x0040bb73
0x004172dc:	call 0x004172e6
0x004172e6:	pushl $0xa<UINT8>
0x004172e8:	pushl $0x80020004<UINT32>
0x004172ed:	movl %ecx, $0x439140<UINT32>
0x004172f2:	call 0x00417403
0x00417403:	pushl %esi
0x00417404:	pushl %edi
0x00417405:	movw %di, 0x10(%esp)
0x0041740a:	movl %esi, %ecx
0x0041740c:	cmpw %di, $0x3<UINT8>
0x00417410:	je 22
0x00417412:	cmpw %di, $0xa<UINT8>
0x00417416:	je 0x0041742e
0x0041742e:	movw (%esi), $0xa<UINT16>
0x00417433:	jmp 0x00417451
0x00417451:	movl %eax, 0xc(%esp)
0x00417455:	movl 0x8(%esi), %eax
0x00417458:	movl %eax, %esi
0x0041745a:	popl %edi
0x0041745b:	popl %esi
0x0041745c:	ret $0x8<UINT16>

0x004172f7:	ret

0x004172e1:	jmp 0x004172f8
0x004172f8:	pushl $0x417304<UINT32>
0x004172fd:	call 0x004088b7
0x004088b7:	pushl 0x4(%esp)
0x004088bb:	call 0x00408839
0x00408839:	pushl %esi
0x0040883a:	call 0x0040bb61
0x0040bb61:	pushl $0xd<UINT8>
0x0040bb63:	call 0x004091f9
0x0040bb68:	popl %ecx
0x0040bb69:	ret

0x0040883f:	pushl 0x4393b0
0x00408845:	call 0x0040bb8d
0x0040bb8d:	pushl %esi
0x0040bb8e:	pushl $0x9<UINT8>
0x0040bb90:	call 0x004091f9
0x0040bb95:	movl %esi, 0xc(%esp)
0x0040bb99:	pushl %esi
0x0040bb9a:	call 0x0040bcde
0x0040bb9f:	popl %ecx
0x0040bba0:	testl %eax, %eax
0x0040bba2:	popl %ecx
0x0040bba3:	je 16
0x0040bba5:	movl %esi, -4(%esi)
0x0040bba8:	pushl $0x9<UINT8>
0x0040bbaa:	subl %esi, $0x9<UINT8>
0x0040bbad:	call 0x0040925a
0x0040bbb2:	popl %ecx
0x0040bbb3:	jmp 0x0040bbce
0x0040bbce:	movl %eax, %esi
0x0040bbd0:	popl %esi
0x0040bbd1:	ret

0x0040884a:	movl %edx, 0x4393b0
0x00408850:	popl %ecx
0x00408851:	movl %ecx, 0x4393ac
0x00408857:	movl %esi, %ecx
0x00408859:	subl %esi, %edx
0x0040885b:	addl %esi, $0x4<UINT8>
0x0040885e:	cmpl %eax, %esi
0x00408860:	jae 0x0040889f
0x0040889f:	movl %eax, 0x8(%esp)
0x004088a3:	movl (%ecx), %eax
0x004088a5:	addl 0x4393ac, $0x4<UINT8>
0x004088ac:	movl %esi, %eax
0x004088ae:	call 0x0040bb6a
0x0040bb6a:	pushl $0xd<UINT8>
0x0040bb6c:	call 0x0040925a
0x0040bb71:	popl %ecx
0x0040bb72:	ret

0x004088b3:	movl %eax, %esi
0x004088b5:	popl %esi
0x004088b6:	ret

0x004088c0:	negl %eax
0x004088c2:	sbbl %eax, %eax
0x004088c4:	popl %ecx
0x004088c5:	negl %eax
0x004088c7:	decl %eax
0x004088c8:	ret

0x00417302:	popl %ecx
0x00417303:	ret

0x0040ba78:	addl %esp, $0x10<UINT8>
0x0040ba7b:	ret

0x004090bd:	movl -48(%ebp), %esi
0x004090c0:	leal %eax, -92(%ebp)
0x004090c3:	pushl %eax
0x004090c4:	call GetStartupInfoA@KERNEL32.dll
0x004090ca:	call 0x0040e2b2
0x0040e2b2:	cmpl 0x4393a8, $0x0<UINT8>
0x0040e2b9:	jne 0x0040e2c0
0x0040e2c0:	pushl %esi
0x0040e2c1:	movl %esi, 0x43a4ec
0x0040e2c7:	movb %al, (%esi)
0x0040e2c9:	cmpb %al, $0x22<UINT8>
0x0040e2cb:	jne 37
0x0040e2cd:	movb %al, 0x1(%esi)
0x0040e2d0:	incl %esi
0x0040e2d1:	cmpb %al, $0x22<UINT8>
0x0040e2d3:	je 0x0040e2ea
0x0040e2d5:	testb %al, %al
0x0040e2d7:	je 17
0x0040e2d9:	movzbl %eax, %al
0x0040e2dc:	pushl %eax
0x0040e2dd:	call 0x00413248
0x00413248:	pushl $0x4<UINT8>
0x0041324a:	pushl $0x0<UINT8>
0x0041324c:	pushl 0xc(%esp)
0x00413250:	call 0x00413291
0x00413291:	movzbl %eax, 0x4(%esp)
0x00413296:	movb %cl, 0xc(%esp)
0x0041329a:	testb 0x439281(%eax), %cl
0x004132a0:	jne 28
0x004132a2:	cmpl 0x8(%esp), $0x0<UINT8>
0x004132a7:	je 0x004132b7
0x004132b7:	xorl %eax, %eax
0x004132b9:	testl %eax, %eax
0x004132bb:	jne 1
0x004132bd:	ret

0x00413255:	addl %esp, $0xc<UINT8>
0x00413258:	ret

0x0040e2e2:	testl %eax, %eax
0x0040e2e4:	popl %ecx
0x0040e2e5:	je 0x0040e2cd
0x0040e2ea:	cmpb (%esi), $0x22<UINT8>
0x0040e2ed:	jne 13
0x0040e2ef:	incl %esi
0x0040e2f0:	jmp 0x0040e2fc
0x0040e2fc:	movb %al, (%esi)
0x0040e2fe:	testb %al, %al
0x0040e300:	je 0x0040e306
0x0040e306:	movl %eax, %esi
0x0040e308:	popl %esi
0x0040e309:	ret

0x004090cf:	movl -100(%ebp), %eax
0x004090d2:	testb -48(%ebp), $0x1<UINT8>
0x004090d6:	je 0x004090de
0x004090de:	pushl $0xa<UINT8>
0x004090e0:	popl %eax
0x004090e1:	pushl %eax
0x004090e2:	pushl -100(%ebp)
0x004090e5:	pushl %esi
0x004090e6:	pushl %esi
0x004090e7:	call GetModuleHandleA@KERNEL32.dll
0x004090ed:	pushl %eax
0x004090ee:	call 0x004071d0
0x004071d0:	subl %esp, $0x1e4<UINT32>
0x004071d6:	leal %eax, 0x4(%esp)
0x004071da:	pushl %esi
0x004071db:	pushl %edi
0x004071dc:	pushl %eax
0x004071dd:	call GetCommandLineW@KERNEL32.dll
GetCommandLineW@KERNEL32.dll: API Node	
0x004071e3:	pushl %eax
0x004071e4:	call CommandLineToArgvW@SHELL32.dll
CommandLineToArgvW@SHELL32.dll: API Node	
0x004071ea:	leal %ecx, 0x5c(%esp)
0x004071ee:	movl %edi, %eax
0x004071f0:	pushl %ecx
0x004071f1:	pushl $0x102<UINT32>
0x004071f6:	call 0x00407f0c
0x00407f0c:	jmp WSAStartup@WS2_32.dll
WSAStartup@WS2_32.dll: API Node	
0x004071fb:	call InitCommonControls@COMCTL32.dll
InitCommonControls@COMCTL32.dll: API Node	
0x00407201:	pushl $0x41c120<UINT32>
0x00407206:	call 0x004074d0
0x004074d0:	subl %esp, $0x214<UINT32>
0x004074d6:	movl %eax, 0x218(%esp)
0x004074dd:	pushl %ebx
0x004074de:	pushl %eax
0x004074df:	leal %ecx, 0x14(%esp)
0x004074e3:	xorl %ebx, %ebx
0x004074e5:	pushl $0x436e50<UINT32>
0x004074ea:	pushl %ecx
0x004074eb:	movl 0x14(%esp), %ebx
0x004074ef:	movl 0x10(%esp), %ebx
0x004074f3:	call 0x00408940
0x00408940:	pushl %ebp
0x00408941:	movl %ebp, %esp
0x00408943:	subl %esp, $0x20<UINT8>
0x00408946:	movl %eax, 0x8(%ebp)
0x00408949:	pushl %esi
0x0040894a:	movl -24(%ebp), %eax
0x0040894d:	movl -32(%ebp), %eax
0x00408950:	leal %eax, 0x10(%ebp)
0x00408953:	movl -20(%ebp), $0x42<UINT32>
0x0040895a:	pushl %eax
0x0040895b:	leal %eax, -32(%ebp)
0x0040895e:	pushl 0xc(%ebp)
0x00408961:	movl -28(%ebp), $0x7fffffff<UINT32>
0x00408968:	pushl %eax
0x00408969:	call 0x0040b25b
0x0040b25b:	pushl %ebp
0x0040b25c:	movl %ebp, %esp
0x0040b25e:	subl %esp, $0x450<UINT32>
0x0040b264:	movl %eax, 0xc(%ebp)
0x0040b267:	addl 0xc(%ebp), $0x2<UINT8>
0x0040b26b:	pushl %ebx
0x0040b26c:	xorl %ecx, %ecx
0x0040b26e:	movw %bx, (%eax)
0x0040b271:	pushl %esi
0x0040b272:	cmpw %bx, %cx
0x0040b275:	pushl %edi
0x0040b276:	movl -8(%ebp), %ecx
0x0040b279:	movl -20(%ebp), %ecx
0x0040b27c:	je 1790
0x0040b282:	xorl %esi, %esi
0x0040b284:	jmp 0x0040b289
0x0040b289:	cmpl -20(%ebp), %esi
0x0040b28c:	jl 1774
0x0040b292:	pushl $0x20<UINT8>
0x0040b294:	popl %edi
0x0040b295:	cmpw %bx, %di
0x0040b298:	jb 20
0x0040b29a:	cmpw %bx, $0x78<UINT8>
0x0040b29e:	ja 0x0040b2ae
0x0040b2a0:	movzwl %eax, %bx
0x0040b2a3:	movb %al, 0x419b80(%eax)
0x0040b2a9:	andl %eax, $0xf<UINT8>
0x0040b2ac:	jmp 0x0040b2b0
0x0040b2b0:	movsbl %eax, 0x419ba0(%ecx,%eax,8)
0x0040b2b8:	pushl $0x7<UINT8>
0x0040b2ba:	sarl %eax, $0x4<UINT8>
0x0040b2bd:	popl %ecx
0x0040b2be:	movl -56(%ebp), %eax
0x0040b2c1:	cmpl %eax, %ecx
0x0040b2c3:	ja 1698
0x0040b2c9:	jmp 0x0040b412
0x0040b3f6:	leal %eax, -20(%ebp)
0x0040b3f9:	movl -28(%ebp), $0x1<UINT32>
0x0040b400:	pushl %eax
0x0040b401:	pushl 0x8(%ebp)
0x0040b404:	pushl %ebx
0x0040b405:	call 0x0040b9a8
0x0040b9a8:	pushl 0x8(%esp)
0x0040b9ac:	pushl 0x8(%esp)
0x0040b9b0:	call 0x0041218f
0x0041218f:	pushl %ebp
0x00412190:	movl %ebp, %esp
0x00412192:	pushl %esi
0x00412193:	movl %esi, 0xc(%ebp)
0x00412196:	testb 0xc(%esi), $0x40<UINT8>
0x0041219a:	jne 0x00412265
0x00412265:	addl 0x4(%esi), $0xfffffffe<UINT8>
0x00412269:	js 13
0x0041226b:	movl %ecx, (%esi)
0x0041226d:	movl %eax, 0x8(%ebp)
0x00412270:	movw (%ecx), %ax
0x00412273:	addl (%esi), $0x2<UINT8>
0x00412276:	jmp 0x00412285
0x00412285:	popl %esi
0x00412286:	popl %ebp
0x00412287:	ret

0x0040b9b5:	popl %ecx
0x0040b9b6:	cmpw %ax, $0xffffffff<UINT16>
0x0040b9ba:	movl %eax, 0x10(%esp)
0x0040b9be:	popl %ecx
0x0040b9bf:	jne 0x0040b9c5
0x0040b9c5:	incl (%eax)
0x0040b9c7:	ret

0x0040b40a:	addl %esp, $0xc<UINT8>
0x0040b40d:	jmp 0x0040b96b
0x0040b96b:	movl %eax, 0xc(%ebp)
0x0040b96e:	addl 0xc(%ebp), $0x2<UINT8>
0x0040b972:	xorl %esi, %esi
0x0040b974:	movw %bx, (%eax)
0x0040b977:	cmpw %bx, %si
0x0040b97a:	jne 0x0040b286
0x0040b286:	movl %ecx, -56(%ebp)
0x0040b2ae:	xorl %eax, %eax
0x0040b2d0:	orl -16(%ebp), $0xffffffff<UINT8>
0x0040b2d4:	movl -52(%ebp), %esi
0x0040b2d7:	movl -48(%ebp), %esi
0x0040b2da:	movl -40(%ebp), %esi
0x0040b2dd:	movl -24(%ebp), %esi
0x0040b2e0:	movl -4(%ebp), %esi
0x0040b2e3:	movl -28(%ebp), %esi
0x0040b2e6:	jmp 0x0040b96b
0x0040b412:	movzwl %eax, %bx
0x0040b415:	cmpl %eax, $0x67<UINT8>
0x0040b418:	jg 0x0040b657
0x0040b657:	subl %eax, $0x69<UINT8>
0x0040b65a:	je 213
0x0040b660:	subl %eax, $0x5<UINT8>
0x0040b663:	je 162
0x0040b669:	decl %eax
0x0040b66a:	je 136
0x0040b670:	decl %eax
0x0040b671:	je 85
0x0040b673:	subl %eax, $0x3<UINT8>
0x0040b676:	je 0x0040b460
0x0040b460:	movl %esi, -16(%ebp)
0x0040b463:	cmpl %esi, $0xffffffff<UINT8>
0x0040b466:	jne 5
0x0040b468:	movl %esi, $0x7fffffff<UINT32>
0x0040b46d:	leal %eax, 0x10(%ebp)
0x0040b470:	pushl %eax
0x0040b471:	call 0x0040ba32
0x0040ba32:	movl %eax, 0x4(%esp)
0x0040ba36:	addl (%eax), $0x4<UINT8>
0x0040ba39:	movl %eax, (%eax)
0x0040ba3b:	movl %eax, -4(%eax)
0x0040ba3e:	ret

0x0040b476:	testb -4(%ebp), $0x20<UINT8>
0x0040b47a:	popl %ecx
0x0040b47b:	movl %ecx, %eax
0x0040b47d:	movl -12(%ebp), %ecx
0x0040b480:	je 0x0040b698
0x0040b698:	testl %ecx, %ecx
0x0040b69a:	jne 0x0040b6a5
0x0040b6a5:	movl -28(%ebp), $0x1<UINT32>
0x0040b6ac:	movl %eax, %ecx
0x0040b6ae:	movl %edx, %esi
0x0040b6b0:	decl %esi
0x0040b6b1:	testl %edx, %edx
0x0040b6b3:	je 10
0x0040b6b5:	cmpw (%eax), $0x0<UINT8>
0x0040b6b9:	je 0x0040b6bf
0x0040b6bb:	incl %eax
0x0040b6bc:	incl %eax
0x0040b6bd:	jmp 0x0040b6ae
0x0040b6bf:	subl %eax, %ecx
0x0040b6c1:	sarl %eax
0x0040b6c3:	jmp 0x0040b5a9
0x0040b5a9:	movl -8(%ebp), %eax
0x0040b5ac:	jmp 0x0040b861
0x0040b861:	cmpl -48(%ebp), $0x0<UINT8>
0x0040b865:	jne 256
0x0040b86b:	movl %ebx, -4(%ebp)
0x0040b86e:	testb %bl, $0x40<UINT8>
0x0040b871:	je 0x0040b89f
0x0040b89f:	movl %esi, -40(%ebp)
0x0040b8a2:	subl %esi, -24(%ebp)
0x0040b8a5:	subl %esi, -8(%ebp)
0x0040b8a8:	testb %bl, $0xc<UINT8>
0x0040b8ab:	jne 18
0x0040b8ad:	leal %eax, -20(%ebp)
0x0040b8b0:	pushl %eax
0x0040b8b1:	pushl 0x8(%ebp)
0x0040b8b4:	pushl %esi
0x0040b8b5:	pushl $0x20<UINT8>
0x0040b8b7:	call 0x0040b9c8
0x0040b9c8:	pushl %esi
0x0040b9c9:	pushl %edi
0x0040b9ca:	movl %edi, 0x10(%esp)
0x0040b9ce:	movl %eax, %edi
0x0040b9d0:	decl %edi
0x0040b9d1:	testl %eax, %eax
0x0040b9d3:	jle 0x0040b9f6
0x0040b9f6:	popl %edi
0x0040b9f7:	popl %esi
0x0040b9f8:	ret

0x0040b8bc:	addl %esp, $0x10<UINT8>
0x0040b8bf:	leal %eax, -20(%ebp)
0x0040b8c2:	pushl %eax
0x0040b8c3:	leal %eax, -32(%ebp)
0x0040b8c6:	pushl 0x8(%ebp)
0x0040b8c9:	pushl -24(%ebp)
0x0040b8cc:	pushl %eax
0x0040b8cd:	call 0x0040b9f9
0x0040b9f9:	pushl %ebx
0x0040b9fa:	movl %ebx, 0xc(%esp)
0x0040b9fe:	movl %eax, %ebx
0x0040ba00:	decl %ebx
0x0040ba01:	pushl %esi
0x0040ba02:	pushl %edi
0x0040ba03:	testl %eax, %eax
0x0040ba05:	jle 0x0040ba2e
0x0040ba2e:	popl %edi
0x0040ba2f:	popl %esi
0x0040ba30:	popl %ebx
0x0040ba31:	ret

0x0040b8d2:	addl %esp, $0x10<UINT8>
0x0040b8d5:	testb %bl, $0x8<UINT8>
0x0040b8d8:	je 0x0040b8f1
0x0040b8f1:	cmpl -28(%ebp), $0x0<UINT8>
0x0040b8f5:	jne 0x0040b93e
0x0040b93e:	leal %eax, -20(%ebp)
0x0040b941:	pushl %eax
0x0040b942:	pushl 0x8(%ebp)
0x0040b945:	pushl -8(%ebp)
0x0040b948:	pushl -12(%ebp)
0x0040b94b:	call 0x0040b9f9
0x0040ba07:	movl %edi, 0x1c(%esp)
0x0040ba0b:	movl %esi, 0x10(%esp)
0x0040ba0f:	movw %ax, (%esi)
0x0040ba12:	pushl %edi
0x0040ba13:	pushl 0x1c(%esp)
0x0040ba17:	incl %esi
0x0040ba18:	incl %esi
0x0040ba19:	pushl %eax
0x0040ba1a:	call 0x0040b9a8
0x0040ba1f:	addl %esp, $0xc<UINT8>
0x0040ba22:	cmpl (%edi), $0xffffffff<UINT8>
0x0040ba25:	je 7
0x0040ba27:	movl %eax, %ebx
0x0040ba29:	decl %ebx
0x0040ba2a:	testl %eax, %eax
0x0040ba2c:	jg 0x0040ba0f
0x0040b950:	addl %esp, $0x10<UINT8>
0x0040b953:	testb -4(%ebp), $0x4<UINT8>
0x0040b957:	je 0x0040b96b
0x0040b980:	movl %eax, -20(%ebp)
0x0040b983:	popl %edi
0x0040b984:	popl %esi
0x0040b985:	popl %ebx
0x0040b986:	leave
0x0040b987:	ret

0x0040896e:	addl %esp, $0xc<UINT8>
0x00408971:	decl -28(%ebp)
0x00408974:	movl %esi, %eax
0x00408976:	js 11
0x00408978:	movl %eax, -32(%ebp)
0x0040897b:	andb (%eax), $0x0<UINT8>
0x0040897e:	incl -32(%ebp)
0x00408981:	jmp 0x00408990
0x00408990:	decl -28(%ebp)
0x00408993:	js 8
0x00408995:	movl %eax, -32(%ebp)
0x00408998:	andb (%eax), $0x0<UINT8>
0x0040899b:	jmp 0x004089aa
0x004089aa:	movl %eax, %esi
0x004089ac:	popl %esi
0x004089ad:	leave
0x004089ae:	ret

0x004074f8:	addl %esp, $0xc<UINT8>
0x004074fb:	leal %edx, 0x8(%esp)
0x004074ff:	leal %eax, 0x10(%esp)
0x00407503:	pushl %edx
0x00407504:	pushl %eax
0x00407505:	pushl $0x80000001<UINT32>
0x0040750a:	call RegCreateKeyW@ADVAPI32.dll
RegCreateKeyW@ADVAPI32.dll: API Node	
0x00407510:	testl %eax, %eax
0x00407512:	jne 36
0x00407514:	movl %eax, 0x8(%esp)
0x00407518:	leal %ecx, 0xc(%esp)
0x0040751c:	leal %edx, 0x4(%esp)
0x00407520:	pushl %ecx
0x00407521:	pushl %edx
0x00407522:	pushl %ebx
0x00407523:	pushl %ebx
0x00407524:	pushl $0x436e34<UINT32>
0x00407529:	pushl %eax
0x0040752a:	movl 0x24(%esp), $0x4<UINT32>
0x00407532:	call RegQueryValueExW@ADVAPI32.dll
RegQueryValueExW@ADVAPI32.dll: API Node	
0x00407538:	cmpl 0x4(%esp), %ebx
0x0040753c:	jne 511
0x00407542:	pushl %esi
0x00407543:	pushl %edi
0x00407544:	pushl $0x3e8<UINT32>
0x00407549:	pushl $0x40<UINT8>
0x0040754b:	call LocalAlloc@KERNEL32.dll
LocalAlloc@KERNEL32.dll: API Node	
0x00407551:	movl %esi, %eax
0x00407553:	pushl $0x436e18<UINT32>
0x00407558:	leal %edi, 0x12(%esi)
0x0040755b:	call LoadLibraryW@KERNEL32.dll
LoadLibraryW@KERNEL32.dll: API Node	
0x00407561:	movl (%esi), $0x80c808d0<UINT32>
0x0040e74c:	pushl %ebp
0x0040e74d:	movl %ebp, %esp
0x0040e74f:	subl %esp, $0x8<UINT8>
0x0040e752:	pushl %ebx
0x0040e753:	pushl %esi
0x0040e754:	pushl %edi
0x0040e755:	pushl %ebp
0x0040e756:	cld
0x0040e757:	movl %ebx, 0xc(%ebp)
0x0040e75a:	movl %eax, 0x8(%ebp)
0x0040e75d:	testl 0x4(%eax), $0x6<UINT32>
0x0040e764:	jne 130
0x0040e76a:	movl -8(%ebp), %eax
0x0040e76d:	movl %eax, 0x10(%ebp)
0x0040e770:	movl -4(%ebp), %eax
0x0040e773:	leal %eax, -8(%ebp)
0x0040e776:	movl -4(%ebx), %eax
0x0040e779:	movl %esi, 0xc(%ebx)
0x0040e77c:	movl %edi, 0x8(%ebx)
0x0040e77f:	cmpl %esi, $0xffffffff<UINT8>
0x0040e782:	je 97
0x0040e784:	leal %ecx, (%esi,%esi,2)
0x0040e787:	cmpl 0x4(%edi,%ecx,4), $0x0<UINT8>
0x0040e78c:	je 69
0x0040e78e:	pushl %esi
0x0040e78f:	pushl %ebp
0x0040e790:	leal %ebp, 0x10(%ebx)
0x0040e793:	call 0x004090fc
0x004090fc:	movl %eax, -20(%ebp)
0x004090ff:	movl %ecx, (%eax)
0x00409101:	movl %ecx, (%ecx)
0x00409103:	movl -104(%ebp), %ecx
0x00409106:	pushl %eax
0x00409107:	pushl %ecx
0x00409108:	call 0x0040e13a
0x0040e13a:	pushl %ebp
0x0040e13b:	movl %ebp, %esp
0x0040e13d:	pushl %ecx
0x0040e13e:	pushl %ebx
0x0040e13f:	pushl %esi
0x0040e140:	call 0x0040af61
0x0040af61:	pushl %esi
0x0040af62:	pushl %edi
0x0040af63:	call GetLastError@KERNEL32.dll
GetLastError@KERNEL32.dll: API Node	
0x0040af69:	pushl 0x437750
0x0040af6f:	movl %edi, %eax
0x0040af71:	call TlsGetValue@KERNEL32.dll
TlsGetValue@KERNEL32.dll: API Node	
0x0040af77:	movl %esi, %eax
0x0040af79:	testl %esi, %esi
0x0040af7b:	jne 0x0040afbc
0x0040afbc:	pushl %edi
0x0040afbd:	call SetLastError@KERNEL32.dll
SetLastError@KERNEL32.dll: API Node	
0x0040afc3:	movl %eax, %esi
0x0040afc5:	popl %edi
0x0040afc6:	popl %esi
0x0040afc7:	ret

0x0040e145:	movl %esi, %eax
0x0040e147:	pushl 0x50(%esi)
0x0040e14a:	pushl 0x8(%ebp)
0x0040e14d:	call 0x0040e278
0x0040e278:	movl %edx, 0x8(%esp)
0x0040e27c:	movl %ecx, 0x437824
0x0040e282:	pushl %esi
0x0040e283:	movl %esi, 0x8(%esp)
0x0040e287:	cmpl (%edx), %esi
0x0040e289:	pushl %edi
0x0040e28a:	movl %eax, %edx
0x0040e28c:	je 0x0040e29f
0x0040e29f:	leal %ecx, (%ecx,%ecx,2)
0x0040e2a2:	leal %ecx, (%edx,%ecx,4)
0x0040e2a5:	cmpl %eax, %ecx
0x0040e2a7:	jae 4
0x0040e2a9:	cmpl (%eax), %esi
0x0040e2ab:	je 0x0040e2af
0x0040e2af:	popl %edi
0x0040e2b0:	popl %esi
0x0040e2b1:	ret

0x0040e152:	popl %ecx
0x0040e153:	testl %eax, %eax
0x0040e155:	popl %ecx
0x0040e156:	je 271
0x0040e15c:	movl %ebx, 0x8(%eax)
0x0040e15f:	testl %ebx, %ebx
0x0040e161:	movl 0x8(%ebp), %ebx
0x0040e164:	je 0x0040e26b
0x0040e26b:	pushl 0xc(%ebp)
0x0040e26e:	call UnhandledExceptionFilter@KERNEL32.dll
UnhandledExceptionFilter@KERNEL32.dll: API Node	
0x0040e274:	popl %esi
0x0040e275:	popl %ebx
0x0040e276:	leave
0x0040e277:	ret

0x0040910d:	popl %ecx
0x0040910e:	popl %ecx
0x0040910f:	ret

0x0040e797:	popl %ebp
0x0040e798:	popl %esi
0x0040e799:	movl %ebx, 0xc(%ebp)
0x0040e79c:	orl %eax, %eax
0x0040e79e:	je 51
0x0040e7a0:	js 60
0x0040e7a2:	movl %edi, 0x8(%ebx)
0x0040e7a5:	pushl %ebx
0x0040e7a6:	call 0x004086a0
0x004086a0:	pushl %ebp
0x004086a1:	movl %ebp, %esp
0x004086a3:	pushl %ebx
0x004086a4:	pushl %esi
0x004086a5:	pushl %edi
0x004086a6:	pushl %ebp
0x004086a7:	pushl $0x0<UINT8>
0x004086a9:	pushl $0x0<UINT8>
0x004086ab:	pushl $0x4086b8<UINT32>
0x004086b0:	pushl 0x8(%ebp)
0x004086b3:	call 0x00417524
0x00417524:	jmp RtlUnwind@KERNEL32.dll
RtlUnwind@KERNEL32.dll: API Node	
0x004086b8:	popl %ebp
0x004086b9:	popl %edi
0x004086ba:	popl %esi
0x004086bb:	popl %ebx
0x004086bc:	movl %esp, %ebp
0x004086be:	popl %ebp
0x004086bf:	ret

0x0040e7ab:	addl %esp, $0x4<UINT8>
0x0040e7ae:	leal %ebp, 0x10(%ebx)
0x0040e7b1:	pushl %esi
0x0040e7b2:	pushl %ebx
0x0040e7b3:	call 0x004086e2
0x004086e2:	pushl %ebx
0x004086e3:	pushl %esi
0x004086e4:	pushl %edi
0x004086e5:	movl %eax, 0x10(%esp)
0x004086e9:	pushl %eax
0x004086ea:	pushl $0xfffffffe<UINT8>
0x004086ec:	pushl $0x4086c0<UINT32>
0x004086f1:	pushl %fs:0
0x004086f8:	movl %fs:0, %esp
0x004086ff:	movl %eax, 0x20(%esp)
0x00408703:	movl %ebx, 0x8(%eax)
0x00408706:	movl %esi, 0xc(%eax)
0x00408709:	cmpl %esi, $0xffffffff<UINT8>
0x0040870c:	je 46
0x0040870e:	cmpl %esi, 0x24(%esp)
0x00408712:	je 0x0040873c
0x0040873c:	popl %fs:0
0x00408743:	addl %esp, $0xc<UINT8>
0x00408746:	popl %edi
0x00408747:	popl %esi
0x00408748:	popl %ebx
0x00408749:	ret

0x0040e7b8:	addl %esp, $0x8<UINT8>
0x0040e7bb:	leal %ecx, (%esi,%esi,2)
0x0040e7be:	pushl $0x1<UINT8>
0x0040e7c0:	movl %eax, 0x8(%edi,%ecx,4)
0x0040e7c4:	call 0x00408776
0x00408776:	pushl %ebx
0x00408777:	pushl %ecx
0x00408778:	movl %ebx, $0x436ee0<UINT32>
0x0040877d:	movl %ecx, 0x8(%ebp)
0x00408780:	movl 0x8(%ebx), %ecx
0x00408783:	movl 0x4(%ebx), %eax
0x00408786:	movl 0xc(%ebx), %ebp
0x00408789:	popl %ecx
0x0040878a:	popl %ebx
0x0040878b:	ret $0x4<UINT16>

0x0040e7c9:	movl %eax, (%edi,%ecx,4)
0x0040e7cc:	movl 0xc(%ebx), %eax
0x0040e7cf:	call 0x00409110
0x00409110:	movl %esp, -24(%ebp)
0x00409113:	pushl -104(%ebp)
0x00409116:	call 0x0040ba8d
0x0040ba8d:	pushl $0x0<UINT8>
0x0040ba8f:	pushl $0x1<UINT8>
0x0040ba91:	pushl 0xc(%esp)
0x0040ba95:	call 0x0040babc
0x0040babc:	pushl %edi
0x0040babd:	call 0x0040bb61
0x0040bac2:	pushl $0x1<UINT8>
0x0040bac4:	popl %edi
0x0040bac5:	cmpl 0x438ea0, %edi
0x0040bacb:	jne 0x0040bade
0x0040bade:	cmpl 0xc(%esp), $0x0<UINT8>
0x0040bae3:	pushl %ebx
0x0040bae4:	movl %ebx, 0x14(%esp)
0x0040bae8:	movl 0x438e9c, %edi
0x0040baee:	movb 0x438e98, %bl
0x0040baf4:	jne 0x0040bb32
0x0040bb32:	pushl $0x41c038<UINT32>
0x0040bb37:	pushl $0x41c030<UINT32>
0x0040bb3c:	call 0x0040bb73
0x004113b6:	pushl 0x439028
0x004113bc:	call SetUnhandledExceptionFilter@KERNEL32.dll
0x004113c2:	ret

0x0040bb41:	popl %ecx
0x0040bb42:	popl %ecx
0x0040bb43:	testl %ebx, %ebx
0x0040bb45:	popl %ebx
0x0040bb46:	je 0x0040bb4f
0x0040bb4f:	pushl 0x8(%esp)
0x0040bb53:	movl 0x438ea0, %edi
0x0040bb59:	call ExitProcess@KERNEL32.dll
ExitProcess@KERNEL32.dll: Exit Node	
