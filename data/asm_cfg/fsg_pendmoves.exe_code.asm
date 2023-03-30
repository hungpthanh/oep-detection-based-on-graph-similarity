0x00431000:	movl %ebx, $0x4001d0<UINT32>
0x00431005:	movl %edi, $0x401000<UINT32>
0x0043100a:	movl %esi, $0x42321d<UINT32>
0x0043100f:	pushl %ebx
0x00431010:	call 0x0043101f
0x0043101f:	cld
0x00431020:	movb %dl, $0xffffff80<UINT8>
0x00431022:	movsb %es:(%edi), %ds:(%esi)
0x00431023:	pushl $0x2<UINT8>
0x00431025:	popl %ebx
0x00431026:	call 0x00431015
0x00431015:	addb %dl, %dl
0x00431017:	jne 0x0043101e
0x00431019:	movb %dl, (%esi)
0x0043101b:	incl %esi
0x0043101c:	adcb %dl, %dl
0x0043101e:	ret

0x00431029:	jae 0x00431022
0x0043102b:	xorl %ecx, %ecx
0x0043102d:	call 0x00431015
0x00431030:	jae 0x0043104a
0x00431032:	xorl %eax, %eax
0x00431034:	call 0x00431015
0x00431037:	jae 0x0043105a
0x00431039:	movb %bl, $0x2<UINT8>
0x0043103b:	incl %ecx
0x0043103c:	movb %al, $0x10<UINT8>
0x0043103e:	call 0x00431015
0x00431041:	adcb %al, %al
0x00431043:	jae 0x0043103e
0x00431045:	jne 0x00431086
0x00431086:	pushl %esi
0x00431087:	movl %esi, %edi
0x00431089:	subl %esi, %eax
0x0043108b:	rep movsb %es:(%edi), %ds:(%esi)
0x0043108d:	popl %esi
0x0043108e:	jmp 0x00431026
0x00431047:	stosb %es:(%edi), %al
0x00431048:	jmp 0x00431026
0x0043105a:	lodsb %al, %ds:(%esi)
0x0043105b:	shrl %eax
0x0043105d:	je 0x004310a0
0x0043105f:	adcl %ecx, %ecx
0x00431061:	jmp 0x0043107f
0x0043107f:	incl %ecx
0x00431080:	incl %ecx
0x00431081:	xchgl %ebp, %eax
0x00431082:	movl %eax, %ebp
0x00431084:	movb %bl, $0x1<UINT8>
0x0043104a:	call 0x00431092
0x00431092:	incl %ecx
0x00431093:	call 0x00431015
0x00431097:	adcl %ecx, %ecx
0x00431099:	call 0x00431015
0x0043109d:	jb 0x00431093
0x0043109f:	ret

0x0043104f:	subl %ecx, %ebx
0x00431051:	jne 0x00431063
0x00431053:	call 0x00431090
0x00431090:	xorl %ecx, %ecx
0x00431058:	jmp 0x00431082
0x00431063:	xchgl %ecx, %eax
0x00431064:	decl %eax
0x00431065:	shll %eax, $0x8<UINT8>
0x00431068:	lodsb %al, %ds:(%esi)
0x00431069:	call 0x00431090
0x0043106e:	cmpl %eax, $0x7d00<UINT32>
0x00431073:	jae 0x0043107f
0x00431075:	cmpb %ah, $0x5<UINT8>
0x00431078:	jae 0x00431080
0x0043107a:	cmpl %eax, $0x7f<UINT8>
0x0043107d:	ja 0x00431081
0x004310a0:	popl %edi
0x004310a1:	popl %ebx
0x004310a2:	movzwl %edi, (%ebx)
0x004310a5:	decl %edi
0x004310a6:	je 0x004310b0
0x004310a8:	decl %edi
0x004310a9:	je 0x004310be
0x004310ab:	shll %edi, $0xc<UINT8>
0x004310ae:	jmp 0x004310b7
0x004310b7:	incl %ebx
0x004310b8:	incl %ebx
0x004310b9:	jmp 0x0043100f
0x004310b0:	movl %edi, 0x2(%ebx)
0x004310b3:	pushl %edi
0x004310b4:	addl %ebx, $0x4<UINT8>
0x004310be:	popl %edi
0x004310bf:	movl %ebx, $0x431128<UINT32>
0x004310c4:	incl %edi
0x004310c5:	movl %esi, (%edi)
0x004310c7:	scasl %eax, %es:(%edi)
0x004310c8:	pushl %edi
0x004310c9:	call LoadLibraryA@KERNEL32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004310cb:	xchgl %ebp, %eax
0x004310cc:	xorl %eax, %eax
0x004310ce:	scasb %al, %es:(%edi)
0x004310cf:	jne 0x004310ce
0x004310d1:	decb (%edi)
0x004310d3:	je 0x004310c4
0x004310d5:	decb (%edi)
0x004310d7:	jne 0x004310df
0x004310df:	decb (%edi)
0x004310e1:	je 0x00404452
0x004310e7:	pushl %edi
0x004310e8:	pushl %ebp
0x004310e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x004310ec:	orl (%esi), %eax
0x004310ee:	lodsl %eax, %ds:(%esi)
0x004310ef:	jne 0x004310cc
GetProcAddress@KERNEL32.dll: API Node	
LoadLibraryA@KERNEL32.dll: API Node	
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
0x0040a12b:	call GetSystemTimeAsFileTime@KERNEL32.dll
GetSystemTimeAsFileTime@KERNEL32.dll: API Node	
0x0040a131:	movl %eax, -8(%ebp)
0x0040a134:	xorl %eax, -12(%ebp)
0x0040a137:	movl -4(%ebp), %eax
0x0040a13a:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x0040a140:	xorl -4(%ebp), %eax
0x0040a143:	call GetCurrentProcessId@KERNEL32.dll
GetCurrentProcessId@KERNEL32.dll: API Node	
0x0040a149:	xorl -4(%ebp), %eax
0x0040a14c:	leal %eax, -20(%ebp)
0x0040a14f:	pushl %eax
0x0040a150:	call QueryPerformanceCounter@KERNEL32.dll
QueryPerformanceCounter@KERNEL32.dll: API Node	
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
0x00407d67:	call GetProcessHeap@KERNEL32.dll
GetProcessHeap@KERNEL32.dll: API Node	
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
0x00403407:	call EncodePointer@KERNEL32.dll
EncodePointer@KERNEL32.dll: API Node	
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
0x00409489:	call EncodePointer@KERNEL32.dll
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
0x0040784f:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x00407855:	movl %esi, 0x41209c
0x0040785b:	movl %edi, %eax
0x0040785d:	pushl $0x418cb0<UINT32>
0x00407862:	pushl %edi
0x00407863:	call GetProcAddress@KERNEL32.dll
0x00407865:	xorl %eax, 0x41e348
0x0040786b:	pushl $0x418cbc<UINT32>
0x00407870:	pushl %edi
0x00407871:	movl 0x420040, %eax
0x00407876:	call GetProcAddress@KERNEL32.dll
0x00407878:	xorl %eax, 0x41e348
0x0040787e:	pushl $0x418cc4<UINT32>
0x00407883:	pushl %edi
0x00407884:	movl 0x420044, %eax
0x00407889:	call GetProcAddress@KERNEL32.dll
0x0040788b:	xorl %eax, 0x41e348
0x00407891:	pushl $0x418cd0<UINT32>
0x00407896:	pushl %edi
0x00407897:	movl 0x420048, %eax
0x0040789c:	call GetProcAddress@KERNEL32.dll
0x0040789e:	xorl %eax, 0x41e348
0x004078a4:	pushl $0x418cdc<UINT32>
0x004078a9:	pushl %edi
0x004078aa:	movl 0x42004c, %eax
0x004078af:	call GetProcAddress@KERNEL32.dll
0x004078b1:	xorl %eax, 0x41e348
0x004078b7:	pushl $0x418cf8<UINT32>
0x004078bc:	pushl %edi
0x004078bd:	movl 0x420050, %eax
0x004078c2:	call GetProcAddress@KERNEL32.dll
0x004078c4:	xorl %eax, 0x41e348
0x004078ca:	pushl $0x418d08<UINT32>
0x004078cf:	pushl %edi
0x004078d0:	movl 0x420054, %eax
0x004078d5:	call GetProcAddress@KERNEL32.dll
0x004078d7:	xorl %eax, 0x41e348
0x004078dd:	pushl $0x418d1c<UINT32>
0x004078e2:	pushl %edi
0x004078e3:	movl 0x420058, %eax
0x004078e8:	call GetProcAddress@KERNEL32.dll
0x004078ea:	xorl %eax, 0x41e348
0x004078f0:	pushl $0x418d34<UINT32>
0x004078f5:	pushl %edi
0x004078f6:	movl 0x42005c, %eax
0x004078fb:	call GetProcAddress@KERNEL32.dll
0x004078fd:	xorl %eax, 0x41e348
0x00407903:	pushl $0x418d4c<UINT32>
0x00407908:	pushl %edi
0x00407909:	movl 0x420060, %eax
0x0040790e:	call GetProcAddress@KERNEL32.dll
0x00407910:	xorl %eax, 0x41e348
0x00407916:	pushl $0x418d60<UINT32>
0x0040791b:	pushl %edi
0x0040791c:	movl 0x420064, %eax
0x00407921:	call GetProcAddress@KERNEL32.dll
0x00407923:	xorl %eax, 0x41e348
0x00407929:	pushl $0x418d80<UINT32>
0x0040792e:	pushl %edi
0x0040792f:	movl 0x420068, %eax
0x00407934:	call GetProcAddress@KERNEL32.dll
0x00407936:	xorl %eax, 0x41e348
0x0040793c:	pushl $0x418d98<UINT32>
0x00407941:	pushl %edi
0x00407942:	movl 0x42006c, %eax
0x00407947:	call GetProcAddress@KERNEL32.dll
0x00407949:	xorl %eax, 0x41e348
0x0040794f:	pushl $0x418db0<UINT32>
0x00407954:	pushl %edi
0x00407955:	movl 0x420070, %eax
0x0040795a:	call GetProcAddress@KERNEL32.dll
0x0040795c:	xorl %eax, 0x41e348
0x00407962:	pushl $0x418dc4<UINT32>
0x00407967:	pushl %edi
0x00407968:	movl 0x420074, %eax
0x0040796d:	call GetProcAddress@KERNEL32.dll
0x0040796f:	xorl %eax, 0x41e348
0x00407975:	movl 0x420078, %eax
0x0040797a:	pushl $0x418dd8<UINT32>
0x0040797f:	pushl %edi
0x00407980:	call GetProcAddress@KERNEL32.dll
0x00407982:	xorl %eax, 0x41e348
0x00407988:	pushl $0x418df4<UINT32>
0x0040798d:	pushl %edi
0x0040798e:	movl 0x42007c, %eax
0x00407993:	call GetProcAddress@KERNEL32.dll
0x00407995:	xorl %eax, 0x41e348
0x0040799b:	pushl $0x418e14<UINT32>
0x004079a0:	pushl %edi
0x004079a1:	movl 0x420080, %eax
0x004079a6:	call GetProcAddress@KERNEL32.dll
0x004079a8:	xorl %eax, 0x41e348
0x004079ae:	pushl $0x418e30<UINT32>
0x004079b3:	pushl %edi
0x004079b4:	movl 0x420084, %eax
0x004079b9:	call GetProcAddress@KERNEL32.dll
0x004079bb:	xorl %eax, 0x41e348
0x004079c1:	pushl $0x418e50<UINT32>
0x004079c6:	pushl %edi
0x004079c7:	movl 0x420088, %eax
0x004079cc:	call GetProcAddress@KERNEL32.dll
0x004079ce:	xorl %eax, 0x41e348
0x004079d4:	pushl $0x418e64<UINT32>
0x004079d9:	pushl %edi
0x004079da:	movl 0x42008c, %eax
0x004079df:	call GetProcAddress@KERNEL32.dll
0x004079e1:	xorl %eax, 0x41e348
0x004079e7:	pushl $0x418e80<UINT32>
0x004079ec:	pushl %edi
0x004079ed:	movl 0x420090, %eax
0x004079f2:	call GetProcAddress@KERNEL32.dll
0x004079f4:	xorl %eax, 0x41e348
0x004079fa:	pushl $0x418e94<UINT32>
0x004079ff:	pushl %edi
0x00407a00:	movl 0x420098, %eax
0x00407a05:	call GetProcAddress@KERNEL32.dll
0x00407a07:	xorl %eax, 0x41e348
0x00407a0d:	pushl $0x418ea4<UINT32>
0x00407a12:	pushl %edi
0x00407a13:	movl 0x420094, %eax
0x00407a18:	call GetProcAddress@KERNEL32.dll
0x00407a1a:	xorl %eax, 0x41e348
0x00407a20:	pushl $0x418eb4<UINT32>
0x00407a25:	pushl %edi
0x00407a26:	movl 0x42009c, %eax
0x00407a2b:	call GetProcAddress@KERNEL32.dll
0x00407a2d:	xorl %eax, 0x41e348
0x00407a33:	pushl $0x418ec4<UINT32>
0x00407a38:	pushl %edi
0x00407a39:	movl 0x4200a0, %eax
0x00407a3e:	call GetProcAddress@KERNEL32.dll
0x00407a40:	xorl %eax, 0x41e348
0x00407a46:	pushl $0x418ed4<UINT32>
0x00407a4b:	pushl %edi
0x00407a4c:	movl 0x4200a4, %eax
0x00407a51:	call GetProcAddress@KERNEL32.dll
0x00407a53:	xorl %eax, 0x41e348
0x00407a59:	pushl $0x418ef0<UINT32>
0x00407a5e:	pushl %edi
0x00407a5f:	movl 0x4200a8, %eax
0x00407a64:	call GetProcAddress@KERNEL32.dll
0x00407a66:	xorl %eax, 0x41e348
0x00407a6c:	pushl $0x418f04<UINT32>
0x00407a71:	pushl %edi
0x00407a72:	movl 0x4200ac, %eax
0x00407a77:	call GetProcAddress@KERNEL32.dll
0x00407a79:	xorl %eax, 0x41e348
0x00407a7f:	pushl $0x418f14<UINT32>
0x00407a84:	pushl %edi
0x00407a85:	movl 0x4200b0, %eax
0x00407a8a:	call GetProcAddress@KERNEL32.dll
0x00407a8c:	xorl %eax, 0x41e348
0x00407a92:	pushl $0x418f28<UINT32>
0x00407a97:	pushl %edi
0x00407a98:	movl 0x4200b4, %eax
0x00407a9d:	call GetProcAddress@KERNEL32.dll
0x00407a9f:	xorl %eax, 0x41e348
0x00407aa5:	movl 0x4200b8, %eax
0x00407aaa:	pushl $0x418f38<UINT32>
0x00407aaf:	pushl %edi
0x00407ab0:	call GetProcAddress@KERNEL32.dll
0x00407ab2:	xorl %eax, 0x41e348
0x00407ab8:	pushl $0x418f58<UINT32>
0x00407abd:	pushl %edi
0x00407abe:	movl 0x4200bc, %eax
0x00407ac3:	call GetProcAddress@KERNEL32.dll
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
