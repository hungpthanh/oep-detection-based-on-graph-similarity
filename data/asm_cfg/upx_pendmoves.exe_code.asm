0x00426860:	pusha
0x00426861:	movl %esi, $0x41a000<UINT32>
0x00426866:	leal %edi, -102400(%esi)
0x0042686c:	pushl %edi
0x0042686d:	jmp 0x0042687a
0x0042687a:	movl %ebx, (%esi)
0x0042687c:	subl %esi, $0xfffffffc<UINT8>
0x0042687f:	adcl %ebx, %ebx
0x00426881:	jb 0x00426870
0x00426870:	movb %al, (%esi)
0x00426872:	incl %esi
0x00426873:	movb (%edi), %al
0x00426875:	incl %edi
0x00426876:	addl %ebx, %ebx
0x00426878:	jne 0x00426881
0x00426883:	movl %eax, $0x1<UINT32>
0x00426888:	addl %ebx, %ebx
0x0042688a:	jne 0x00426893
0x00426893:	adcl %eax, %eax
0x00426895:	addl %ebx, %ebx
0x00426897:	jae 0x00426888
0x00426899:	jne 0x004268a4
0x004268a4:	xorl %ecx, %ecx
0x004268a6:	subl %eax, $0x3<UINT8>
0x004268a9:	jb 0x004268b8
0x004268ab:	shll %eax, $0x8<UINT8>
0x004268ae:	movb %al, (%esi)
0x004268b0:	incl %esi
0x004268b1:	xorl %eax, $0xffffffff<UINT8>
0x004268b4:	je 0x0042692a
0x004268b6:	movl %ebp, %eax
0x004268b8:	addl %ebx, %ebx
0x004268ba:	jne 0x004268c3
0x004268c3:	adcl %ecx, %ecx
0x004268c5:	addl %ebx, %ebx
0x004268c7:	jne 0x004268d0
0x004268c9:	movl %ebx, (%esi)
0x004268cb:	subl %esi, $0xfffffffc<UINT8>
0x004268ce:	adcl %ebx, %ebx
0x004268d0:	adcl %ecx, %ecx
0x004268d2:	jne 0x004268f4
0x004268f4:	cmpl %ebp, $0xfffff300<UINT32>
0x004268fa:	adcl %ecx, $0x1<UINT8>
0x004268fd:	leal %edx, (%edi,%ebp)
0x00426900:	cmpl %ebp, $0xfffffffc<UINT8>
0x00426903:	jbe 0x00426914
0x00426914:	movl %eax, (%edx)
0x00426916:	addl %edx, $0x4<UINT8>
0x00426919:	movl (%edi), %eax
0x0042691b:	addl %edi, $0x4<UINT8>
0x0042691e:	subl %ecx, $0x4<UINT8>
0x00426921:	ja 0x00426914
0x00426923:	addl %edi, %ecx
0x00426925:	jmp 0x00426876
0x0042688c:	movl %ebx, (%esi)
0x0042688e:	subl %esi, $0xfffffffc<UINT8>
0x00426891:	adcl %ebx, %ebx
0x004268d4:	incl %ecx
0x004268d5:	addl %ebx, %ebx
0x004268d7:	jne 0x004268e0
0x004268e0:	adcl %ecx, %ecx
0x004268e2:	addl %ebx, %ebx
0x004268e4:	jae 0x004268d5
0x004268e6:	jne 0x004268f1
0x004268f1:	addl %ecx, $0x2<UINT8>
0x004268d9:	movl %ebx, (%esi)
0x004268db:	subl %esi, $0xfffffffc<UINT8>
0x004268de:	adcl %ebx, %ebx
0x00426905:	movb %al, (%edx)
0x00426907:	incl %edx
0x00426908:	movb (%edi), %al
0x0042690a:	incl %edi
0x0042690b:	decl %ecx
0x0042690c:	jne 0x00426905
0x0042690e:	jmp 0x00426876
0x0042689b:	movl %ebx, (%esi)
0x0042689d:	subl %esi, $0xfffffffc<UINT8>
0x004268a0:	adcl %ebx, %ebx
0x004268a2:	jae 0x00426888
0x004268bc:	movl %ebx, (%esi)
0x004268be:	subl %esi, $0xfffffffc<UINT8>
0x004268c1:	adcl %ebx, %ebx
0x004268e8:	movl %ebx, (%esi)
0x004268ea:	subl %esi, $0xfffffffc<UINT8>
0x004268ed:	adcl %ebx, %ebx
0x004268ef:	jae 0x004268d5
0x0042692a:	popl %esi
0x0042692b:	movl %edi, %esi
0x0042692d:	movl %ecx, $0x5c3<UINT32>
0x00426932:	movb %al, (%edi)
0x00426934:	incl %edi
0x00426935:	subb %al, $0xffffffe8<UINT8>
0x00426937:	cmpb %al, $0x1<UINT8>
0x00426939:	ja 0x00426932
0x0042693b:	cmpb (%edi), $0x5<UINT8>
0x0042693e:	jne 0x00426932
0x00426940:	movl %eax, (%edi)
0x00426942:	movb %bl, 0x4(%edi)
0x00426945:	shrw %ax, $0x8<UINT8>
0x00426949:	roll %eax, $0x10<UINT8>
0x0042694c:	xchgb %ah, %al
0x0042694e:	subl %eax, %edi
0x00426950:	subb %bl, $0xffffffe8<UINT8>
0x00426953:	addl %eax, %esi
0x00426955:	movl (%edi), %eax
0x00426957:	addl %edi, $0x5<UINT8>
0x0042695a:	movb %al, %bl
0x0042695c:	loop 0x00426937
0x0042695e:	leal %edi, 0x23000(%esi)
0x00426964:	movl %eax, (%edi)
0x00426966:	orl %eax, %eax
0x00426968:	je 0x004269a6
0x0042696a:	movl %ebx, 0x4(%edi)
0x0042696d:	leal %eax, 0x2657c(%eax,%esi)
0x00426974:	addl %ebx, %esi
0x00426976:	pushl %eax
0x00426977:	addl %edi, $0x8<UINT8>
0x0042697a:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00426980:	xchgl %ebp, %eax
0x00426981:	movb %al, (%edi)
0x00426983:	incl %edi
0x00426984:	orb %al, %al
0x00426986:	je 0x00426964
0x00426988:	movl %ecx, %edi
0x0042698a:	pushl %edi
0x0042698b:	decl %eax
0x0042698c:	repn scasb %al, %es:(%edi)
0x0042698e:	pushl %ebp
0x0042698f:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00426995:	orl %eax, %eax
0x00426997:	je 7
0x00426999:	movl (%ebx), %eax
0x0042699b:	addl %ebx, $0x4<UINT8>
0x0042699e:	jmp 0x00426981
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x004269a6:	addl %edi, $0x4<UINT8>
0x004269a9:	leal %ebx, -4(%esi)
0x004269ac:	xorl %eax, %eax
0x004269ae:	movb %al, (%edi)
0x004269b0:	incl %edi
0x004269b1:	orl %eax, %eax
0x004269b3:	je 0x004269d7
0x004269b5:	cmpb %al, $0xffffffef<UINT8>
0x004269b7:	ja 0x004269ca
0x004269b9:	addl %ebx, %eax
0x004269bb:	movl %eax, (%ebx)
0x004269bd:	xchgb %ah, %al
0x004269bf:	roll %eax, $0x10<UINT8>
0x004269c2:	xchgb %ah, %al
0x004269c4:	addl %eax, %esi
0x004269c6:	movl (%ebx), %eax
0x004269c8:	jmp 0x004269ac
0x004269ca:	andb %al, $0xf<UINT8>
0x004269cc:	shll %eax, $0x10<UINT8>
0x004269cf:	movw %ax, (%edi)
0x004269d2:	addl %edi, $0x2<UINT8>
0x004269d5:	jmp 0x004269b9
0x004269d7:	movl %ebp, 0x2662c(%esi)
0x004269dd:	leal %edi, -4096(%esi)
0x004269e3:	movl %ebx, $0x1000<UINT32>
0x004269e8:	pushl %eax
0x004269e9:	pushl %esp
0x004269ea:	pushl $0x4<UINT8>
0x004269ec:	pushl %ebx
0x004269ed:	pushl %edi
0x004269ee:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x004269f0:	leal %eax, 0x20f(%edi)
0x004269f6:	andb (%eax), $0x7f<UINT8>
0x004269f9:	andb 0x28(%eax), $0x7f<UINT8>
0x004269fd:	popl %eax
0x004269fe:	pushl %eax
0x004269ff:	pushl %esp
0x00426a00:	pushl %eax
0x00426a01:	pushl %ebx
0x00426a02:	pushl %edi
0x00426a03:	call VirtualProtect@kernel32.dll
0x00426a05:	popl %eax
0x00426a06:	popa
0x00426a07:	leal %eax, -128(%esp)
0x00426a0b:	pushl $0x0<UINT8>
0x00426a0d:	cmpl %esp, %eax
0x00426a0f:	jne 0x00426a0b
0x00426a11:	subl %esp, $0xffffff80<UINT8>
0x00426a14:	jmp 0x00404452
0x00404452:	call 0x0040a0f7
0x0040a0f7:	pushl %ebp
0x0040a0f8:	movl %ebp, %esp
0x0040a0fa:	subl %esp, $0x14<UINT8>
0x0040a0fd:	andl -12(%ebp), $0x0<UINT8>
0x0040a101:	andl -8(%ebp), $0x0<UINT8>
0x0040a105:	movl %eax, 0x41e348
0x0040a10a:	pushl %esi
0x0040a10b:	pushl %edi
0x0040a10c:	movl %edi, $0xbb40e64e<UINT32>
0x0040a111:	movl %esi, $0xffff0000<UINT32>
0x0040a116:	cmpl %eax, %edi
0x0040a118:	je 0x0040a127
0x0040a127:	leal %eax, -12(%ebp)
0x0040a12a:	pushl %eax
0x0040a12b:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040a131:	movl %eax, -8(%ebp)
0x0040a134:	xorl %eax, -12(%ebp)
0x0040a137:	movl -4(%ebp), %eax
0x0040a13a:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040a140:	xorl -4(%ebp), %eax
0x0040a143:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040a149:	xorl -4(%ebp), %eax
0x0040a14c:	leal %eax, -20(%ebp)
0x0040a14f:	pushl %eax
0x0040a150:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040a156:	movl %ecx, -16(%ebp)
0x0040a159:	leal %eax, -4(%ebp)
0x0040a15c:	xorl %ecx, -20(%ebp)
0x0040a15f:	xorl %ecx, -4(%ebp)
0x0040a162:	xorl %ecx, %eax
0x0040a164:	cmpl %ecx, %edi
0x0040a166:	jne 0x0040a16f
0x0040a16f:	testl %esi, %ecx
0x0040a171:	jne 0x0040a17f
0x0040a17f:	movl 0x41e348, %ecx
0x0040a185:	notl %ecx
0x0040a187:	movl 0x41e34c, %ecx
0x0040a18d:	popl %edi
0x0040a18e:	popl %esi
0x0040a18f:	movl %esp, %ebp
0x0040a191:	popl %ebp
0x0040a192:	ret

0x00404457:	jmp 0x004042d7
0x004042d7:	pushl $0x14<UINT8>
0x004042d9:	pushl $0x41c9e8<UINT32>
0x004042de:	call 0x00405190
0x00405190:	pushl $0x4051f0<UINT32>
0x00405195:	pushl %fs:0
0x0040519c:	movl %eax, 0x10(%esp)
0x004051a0:	movl 0x10(%esp), %ebp
0x004051a4:	leal %ebp, 0x10(%esp)
0x004051a8:	subl %esp, %eax
0x004051aa:	pushl %ebx
0x004051ab:	pushl %esi
0x004051ac:	pushl %edi
0x004051ad:	movl %eax, 0x41e348
0x004051b2:	xorl -4(%ebp), %eax
0x004051b5:	xorl %eax, %ebp
0x004051b7:	pushl %eax
0x004051b8:	movl -24(%ebp), %esp
0x004051bb:	pushl -8(%ebp)
0x004051be:	movl %eax, -4(%ebp)
0x004051c1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004051c8:	movl -8(%ebp), %eax
0x004051cb:	leal %eax, -16(%ebp)
0x004051ce:	movl %fs:0, %eax
0x004051d4:	ret

0x004042e3:	pushl $0x1<UINT8>
0x004042e5:	call 0x0040a0aa
0x0040a0aa:	pushl %ebp
0x0040a0ab:	movl %ebp, %esp
0x0040a0ad:	movl %eax, 0x8(%ebp)
0x0040a0b0:	movl 0x41f550, %eax
0x0040a0b5:	popl %ebp
0x0040a0b6:	ret

0x004042ea:	popl %ecx
0x004042eb:	movl %eax, $0x5a4d<UINT32>
0x004042f0:	cmpw 0x400000, %ax
0x004042f7:	je 0x004042fd
0x004042fd:	movl %eax, 0x40003c
0x00404302:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x0040430c:	jne -21
0x0040430e:	movl %ecx, $0x10b<UINT32>
0x00404313:	cmpw 0x400018(%eax), %cx
0x0040431a:	jne -35
0x0040431c:	xorl %ebx, %ebx
0x0040431e:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00404325:	jbe 9
0x00404327:	cmpl 0x4000e8(%eax), %ebx
0x0040432d:	setne %bl
0x00404330:	movl -28(%ebp), %ebx
0x00404333:	call 0x00407d67
0x00407d67:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x00407d6d:	xorl %ecx, %ecx
0x00407d6f:	movl 0x41fb88, %eax
0x00407d74:	testl %eax, %eax
0x00407d76:	setne %cl
0x00407d79:	movl %eax, %ecx
0x00407d7b:	ret

0x00404338:	testl %eax, %eax
0x0040433a:	jne 0x00404344
0x00404344:	call 0x00408d4d
0x00408d4d:	call 0x00403404
0x00403404:	pushl %esi
0x00403405:	pushl $0x0<UINT8>
0x00403407:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x0040340d:	movl %esi, %eax
0x0040340f:	pushl %esi
0x00403410:	call 0x00407d5a
0x00407d5a:	pushl %ebp
0x00407d5b:	movl %ebp, %esp
0x00407d5d:	movl %eax, 0x8(%ebp)
0x00407d60:	movl 0x41fb80, %eax
0x00407d65:	popl %ebp
0x00407d66:	ret

0x00403415:	pushl %esi
0x00403416:	call 0x004054a9
0x004054a9:	pushl %ebp
0x004054aa:	movl %ebp, %esp
0x004054ac:	movl %eax, 0x8(%ebp)
0x004054af:	movl 0x41f43c, %eax
0x004054b4:	popl %ebp
0x004054b5:	ret

0x0040341b:	pushl %esi
0x0040341c:	call 0x00409495
0x00409495:	pushl %ebp
0x00409496:	movl %ebp, %esp
0x00409498:	movl %eax, 0x8(%ebp)
0x0040949b:	movl 0x41fed0, %eax
0x004094a0:	popl %ebp
0x004094a1:	ret

0x00403421:	pushl %esi
0x00403422:	call 0x004094af
0x004094af:	pushl %ebp
0x004094b0:	movl %ebp, %esp
0x004094b2:	movl %eax, 0x8(%ebp)
0x004094b5:	movl 0x41fed4, %eax
0x004094ba:	movl 0x41fed8, %eax
0x004094bf:	movl 0x41fedc, %eax
0x004094c4:	movl 0x41fee0, %eax
0x004094c9:	popl %ebp
0x004094ca:	ret

0x00403427:	pushl %esi
0x00403428:	call 0x00409484
0x00409484:	pushl $0x409450<UINT32>
0x00409489:	call EncodePointer@KERNEL32.DLL
0x0040948f:	movl 0x41fecc, %eax
0x00409494:	ret

0x0040342d:	pushl %esi
0x0040342e:	call 0x004096c0
0x004096c0:	pushl %ebp
0x004096c1:	movl %ebp, %esp
0x004096c3:	movl %eax, 0x8(%ebp)
0x004096c6:	movl 0x41fee8, %eax
0x004096cb:	popl %ebp
0x004096cc:	ret

0x00403433:	addl %esp, $0x18<UINT8>
0x00403436:	popl %esi
0x00403437:	jmp 0x00407848
0x00407848:	pushl %esi
0x00407849:	pushl %edi
0x0040784a:	pushl $0x418c94<UINT32>
0x0040784f:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00407855:	movl %esi, 0x41209c
0x0040785b:	movl %edi, %eax
0x0040785d:	pushl $0x418cb0<UINT32>
0x00407862:	pushl %edi
0x00407863:	call GetProcAddress@KERNEL32.DLL
0x00407865:	xorl %eax, 0x41e348
0x0040786b:	pushl $0x418cbc<UINT32>
0x00407870:	pushl %edi
0x00407871:	movl 0x420040, %eax
0x00407876:	call GetProcAddress@KERNEL32.DLL
0x00407878:	xorl %eax, 0x41e348
0x0040787e:	pushl $0x418cc4<UINT32>
0x00407883:	pushl %edi
0x00407884:	movl 0x420044, %eax
0x00407889:	call GetProcAddress@KERNEL32.DLL
0x0040788b:	xorl %eax, 0x41e348
0x00407891:	pushl $0x418cd0<UINT32>
0x00407896:	pushl %edi
0x00407897:	movl 0x420048, %eax
0x0040789c:	call GetProcAddress@KERNEL32.DLL
0x0040789e:	xorl %eax, 0x41e348
0x004078a4:	pushl $0x418cdc<UINT32>
0x004078a9:	pushl %edi
0x004078aa:	movl 0x42004c, %eax
0x004078af:	call GetProcAddress@KERNEL32.DLL
0x004078b1:	xorl %eax, 0x41e348
0x004078b7:	pushl $0x418cf8<UINT32>
0x004078bc:	pushl %edi
0x004078bd:	movl 0x420050, %eax
0x004078c2:	call GetProcAddress@KERNEL32.DLL
0x004078c4:	xorl %eax, 0x41e348
0x004078ca:	pushl $0x418d08<UINT32>
0x004078cf:	pushl %edi
0x004078d0:	movl 0x420054, %eax
0x004078d5:	call GetProcAddress@KERNEL32.DLL
0x004078d7:	xorl %eax, 0x41e348
0x004078dd:	pushl $0x418d1c<UINT32>
0x004078e2:	pushl %edi
0x004078e3:	movl 0x420058, %eax
0x004078e8:	call GetProcAddress@KERNEL32.DLL
0x004078ea:	xorl %eax, 0x41e348
0x004078f0:	pushl $0x418d34<UINT32>
0x004078f5:	pushl %edi
0x004078f6:	movl 0x42005c, %eax
0x004078fb:	call GetProcAddress@KERNEL32.DLL
0x004078fd:	xorl %eax, 0x41e348
0x00407903:	pushl $0x418d4c<UINT32>
0x00407908:	pushl %edi
0x00407909:	movl 0x420060, %eax
0x0040790e:	call GetProcAddress@KERNEL32.DLL
0x00407910:	xorl %eax, 0x41e348
0x00407916:	pushl $0x418d60<UINT32>
0x0040791b:	pushl %edi
0x0040791c:	movl 0x420064, %eax
0x00407921:	call GetProcAddress@KERNEL32.DLL
0x00407923:	xorl %eax, 0x41e348
0x00407929:	pushl $0x418d80<UINT32>
0x0040792e:	pushl %edi
0x0040792f:	movl 0x420068, %eax
0x00407934:	call GetProcAddress@KERNEL32.DLL
0x00407936:	xorl %eax, 0x41e348
0x0040793c:	pushl $0x418d98<UINT32>
0x00407941:	pushl %edi
0x00407942:	movl 0x42006c, %eax
0x00407947:	call GetProcAddress@KERNEL32.DLL
0x00407949:	xorl %eax, 0x41e348
0x0040794f:	pushl $0x418db0<UINT32>
0x00407954:	pushl %edi
0x00407955:	movl 0x420070, %eax
0x0040795a:	call GetProcAddress@KERNEL32.DLL
0x0040795c:	xorl %eax, 0x41e348
0x00407962:	pushl $0x418dc4<UINT32>
0x00407967:	pushl %edi
0x00407968:	movl 0x420074, %eax
0x0040796d:	call GetProcAddress@KERNEL32.DLL
0x0040796f:	xorl %eax, 0x41e348
0x00407975:	movl 0x420078, %eax
0x0040797a:	pushl $0x418dd8<UINT32>
0x0040797f:	pushl %edi
0x00407980:	call GetProcAddress@KERNEL32.DLL
0x00407982:	xorl %eax, 0x41e348
0x00407988:	pushl $0x418df4<UINT32>
0x0040798d:	pushl %edi
0x0040798e:	movl 0x42007c, %eax
0x00407993:	call GetProcAddress@KERNEL32.DLL
0x00407995:	xorl %eax, 0x41e348
0x0040799b:	pushl $0x418e14<UINT32>
0x004079a0:	pushl %edi
0x004079a1:	movl 0x420080, %eax
0x004079a6:	call GetProcAddress@KERNEL32.DLL
0x004079a8:	xorl %eax, 0x41e348
0x004079ae:	pushl $0x418e30<UINT32>
0x004079b3:	pushl %edi
0x004079b4:	movl 0x420084, %eax
0x004079b9:	call GetProcAddress@KERNEL32.DLL
0x004079bb:	xorl %eax, 0x41e348
0x004079c1:	pushl $0x418e50<UINT32>
0x004079c6:	pushl %edi
0x004079c7:	movl 0x420088, %eax
0x004079cc:	call GetProcAddress@KERNEL32.DLL
0x004079ce:	xorl %eax, 0x41e348
0x004079d4:	pushl $0x418e64<UINT32>
0x004079d9:	pushl %edi
0x004079da:	movl 0x42008c, %eax
0x004079df:	call GetProcAddress@KERNEL32.DLL
0x004079e1:	xorl %eax, 0x41e348
0x004079e7:	pushl $0x418e80<UINT32>
0x004079ec:	pushl %edi
0x004079ed:	movl 0x420090, %eax
0x004079f2:	call GetProcAddress@KERNEL32.DLL
0x004079f4:	xorl %eax, 0x41e348
0x004079fa:	pushl $0x418e94<UINT32>
0x004079ff:	pushl %edi
0x00407a00:	movl 0x420098, %eax
0x00407a05:	call GetProcAddress@KERNEL32.DLL
0x00407a07:	xorl %eax, 0x41e348
0x00407a0d:	pushl $0x418ea4<UINT32>
0x00407a12:	pushl %edi
0x00407a13:	movl 0x420094, %eax
0x00407a18:	call GetProcAddress@KERNEL32.DLL
0x00407a1a:	xorl %eax, 0x41e348
0x00407a20:	pushl $0x418eb4<UINT32>
0x00407a25:	pushl %edi
0x00407a26:	movl 0x42009c, %eax
0x00407a2b:	call GetProcAddress@KERNEL32.DLL
0x00407a2d:	xorl %eax, 0x41e348
0x00407a33:	pushl $0x418ec4<UINT32>
0x00407a38:	pushl %edi
0x00407a39:	movl 0x4200a0, %eax
0x00407a3e:	call GetProcAddress@KERNEL32.DLL
0x00407a40:	xorl %eax, 0x41e348
0x00407a46:	pushl $0x418ed4<UINT32>
0x00407a4b:	pushl %edi
0x00407a4c:	movl 0x4200a4, %eax
0x00407a51:	call GetProcAddress@KERNEL32.DLL
0x00407a53:	xorl %eax, 0x41e348
0x00407a59:	pushl $0x418ef0<UINT32>
0x00407a5e:	pushl %edi
0x00407a5f:	movl 0x4200a8, %eax
0x00407a64:	call GetProcAddress@KERNEL32.DLL
0x00407a66:	xorl %eax, 0x41e348
0x00407a6c:	pushl $0x418f04<UINT32>
0x00407a71:	pushl %edi
0x00407a72:	movl 0x4200ac, %eax
0x00407a77:	call GetProcAddress@KERNEL32.DLL
0x00407a79:	xorl %eax, 0x41e348
0x00407a7f:	pushl $0x418f14<UINT32>
0x00407a84:	pushl %edi
0x00407a85:	movl 0x4200b0, %eax
0x00407a8a:	call GetProcAddress@KERNEL32.DLL
0x00407a8c:	xorl %eax, 0x41e348
0x00407a92:	pushl $0x418f28<UINT32>
0x00407a97:	pushl %edi
0x00407a98:	movl 0x4200b4, %eax
0x00407a9d:	call GetProcAddress@KERNEL32.DLL
0x00407a9f:	xorl %eax, 0x41e348
0x00407aa5:	movl 0x4200b8, %eax
0x00407aaa:	pushl $0x418f38<UINT32>
0x00407aaf:	pushl %edi
0x00407ab0:	call GetProcAddress@KERNEL32.DLL
0x00407ab2:	xorl %eax, 0x41e348
0x00407ab8:	pushl $0x418f58<UINT32>
0x00407abd:	pushl %edi
0x00407abe:	movl 0x4200bc, %eax
0x00407ac3:	call GetProcAddress@KERNEL32.DLL
0x00407ac5:	xorl %eax, 0x41e348
0x00407acb:	popl %edi
0x00407acc:	movl 0x4200c0, %eax
0x00407ad1:	popl %esi
0x00407ad2:	ret

0x00408d52:	call 0x0040462a
0x0040462a:	pushl %esi
0x0040462b:	pushl %edi
0x0040462c:	movl %esi, $0x41e360<UINT32>
0x00404631:	movl %edi, $0x41f2e8<UINT32>
0x00404636:	cmpl 0x4(%esi), $0x1<UINT8>
0x0040463a:	jne 22
0x0040463c:	pushl $0x0<UINT8>
0x0040463e:	movl (%esi), %edi
0x00404640:	addl %edi, $0x18<UINT8>
0x00404643:	pushl $0xfa0<UINT32>
0x00404648:	pushl (%esi)
0x0040464a:	call 0x004077da
0x004077da:	pushl %ebp
0x004077db:	movl %ebp, %esp
0x004077dd:	movl %eax, 0x420050
0x004077e2:	xorl %eax, 0x41e348
0x004077e8:	je 13
0x004077ea:	pushl 0x10(%ebp)
0x004077ed:	pushl 0xc(%ebp)
0x004077f0:	pushl 0x8(%ebp)
0x004077f3:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x004077f5:	popl %ebp
0x004077f6:	ret

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
