0x004de980:	pusha
0x004de981:	movl %esi, $0x4b8000<UINT32>
0x004de986:	leal %edi, -749568(%esi)
0x004de98c:	pushl %edi
0x004de98d:	jmp 0x004de99a
0x004de99a:	movl %ebx, (%esi)
0x004de99c:	subl %esi, $0xfffffffc<UINT8>
0x004de99f:	adcl %ebx, %ebx
0x004de9a1:	jb 0x004de990
0x004de990:	movb %al, (%esi)
0x004de992:	incl %esi
0x004de993:	movb (%edi), %al
0x004de995:	incl %edi
0x004de996:	addl %ebx, %ebx
0x004de998:	jne 0x004de9a1
0x004de9a3:	movl %eax, $0x1<UINT32>
0x004de9a8:	addl %ebx, %ebx
0x004de9aa:	jne 0x004de9b3
0x004de9b3:	adcl %eax, %eax
0x004de9b5:	addl %ebx, %ebx
0x004de9b7:	jae 0x004de9c4
0x004de9b9:	jne 0x004de9e3
0x004de9e3:	xorl %ecx, %ecx
0x004de9e5:	subl %eax, $0x3<UINT8>
0x004de9e8:	jb 0x004de9fb
0x004de9ea:	shll %eax, $0x8<UINT8>
0x004de9ed:	movb %al, (%esi)
0x004de9ef:	incl %esi
0x004de9f0:	xorl %eax, $0xffffffff<UINT8>
0x004de9f3:	je 0x004dea6a
0x004de9f5:	sarl %eax
0x004de9f7:	movl %ebp, %eax
0x004de9f9:	jmp 0x004dea06
0x004dea06:	jb 0x004de9d4
0x004de9d4:	addl %ebx, %ebx
0x004de9d6:	jne 0x004de9df
0x004de9df:	adcl %ecx, %ecx
0x004de9e1:	jmp 0x004dea35
0x004dea35:	cmpl %ebp, $0xfffffb00<UINT32>
0x004dea3b:	adcl %ecx, $0x2<UINT8>
0x004dea3e:	leal %edx, (%edi,%ebp)
0x004dea41:	cmpl %ebp, $0xfffffffc<UINT8>
0x004dea44:	jbe 0x004dea54
0x004dea54:	movl %eax, (%edx)
0x004dea56:	addl %edx, $0x4<UINT8>
0x004dea59:	movl (%edi), %eax
0x004dea5b:	addl %edi, $0x4<UINT8>
0x004dea5e:	subl %ecx, $0x4<UINT8>
0x004dea61:	ja 0x004dea54
0x004dea63:	addl %edi, %ecx
0x004dea65:	jmp 0x004de996
0x004dea08:	incl %ecx
0x004dea09:	addl %ebx, %ebx
0x004dea0b:	jne 0x004dea14
0x004dea14:	jb 0x004de9d4
0x004de9bb:	movl %ebx, (%esi)
0x004de9bd:	subl %esi, $0xfffffffc<UINT8>
0x004de9c0:	adcl %ebx, %ebx
0x004de9c2:	jb 0x004de9e3
0x004de9fb:	addl %ebx, %ebx
0x004de9fd:	jne 0x004dea06
0x004dea16:	addl %ebx, %ebx
0x004dea18:	jne 0x004dea21
0x004dea21:	adcl %ecx, %ecx
0x004dea23:	addl %ebx, %ebx
0x004dea25:	jae 0x004dea16
0x004dea27:	jne 0x004dea32
0x004dea32:	addl %ecx, $0x2<UINT8>
0x004dea46:	movb %al, (%edx)
0x004dea48:	incl %edx
0x004dea49:	movb (%edi), %al
0x004dea4b:	incl %edi
0x004dea4c:	decl %ecx
0x004dea4d:	jne 0x004dea46
0x004dea4f:	jmp 0x004de996
0x004de9c4:	decl %eax
0x004de9c5:	addl %ebx, %ebx
0x004de9c7:	jne 0x004de9d0
0x004de9d0:	adcl %eax, %eax
0x004de9d2:	jmp 0x004de9a8
0x004de9ac:	movl %ebx, (%esi)
0x004de9ae:	subl %esi, $0xfffffffc<UINT8>
0x004de9b1:	adcl %ebx, %ebx
0x004dea0d:	movl %ebx, (%esi)
0x004dea0f:	subl %esi, $0xfffffffc<UINT8>
0x004dea12:	adcl %ebx, %ebx
0x004de9d8:	movl %ebx, (%esi)
0x004de9da:	subl %esi, $0xfffffffc<UINT8>
0x004de9dd:	adcl %ebx, %ebx
0x004dea1a:	movl %ebx, (%esi)
0x004dea1c:	subl %esi, $0xfffffffc<UINT8>
0x004dea1f:	adcl %ebx, %ebx
0x004dea29:	movl %ebx, (%esi)
0x004dea2b:	subl %esi, $0xfffffffc<UINT8>
0x004dea2e:	adcl %ebx, %ebx
0x004dea30:	jae 0x004dea16
0x004de9c9:	movl %ebx, (%esi)
0x004de9cb:	subl %esi, $0xfffffffc<UINT8>
0x004de9ce:	adcl %ebx, %ebx
0x004de9ff:	movl %ebx, (%esi)
0x004dea01:	subl %esi, $0xfffffffc<UINT8>
0x004dea04:	adcl %ebx, %ebx
0x004dea6a:	popl %esi
0x004dea6b:	movl %edi, %esi
0x004dea6d:	movl %ecx, $0x7fc<UINT32>
0x004dea72:	movb %al, (%edi)
0x004dea74:	incl %edi
0x004dea75:	subb %al, $0xffffffe8<UINT8>
0x004dea77:	cmpb %al, $0x1<UINT8>
0x004dea79:	ja 0x004dea72
0x004dea7b:	cmpb (%edi), $0x9<UINT8>
0x004dea7e:	jne 0x004dea72
0x004dea80:	movl %eax, (%edi)
0x004dea82:	movb %bl, 0x4(%edi)
0x004dea85:	shrw %ax, $0x8<UINT8>
0x004dea89:	roll %eax, $0x10<UINT8>
0x004dea8c:	xchgb %ah, %al
0x004dea8e:	subl %eax, %edi
0x004dea90:	subb %bl, $0xffffffe8<UINT8>
0x004dea93:	addl %eax, %esi
0x004dea95:	movl (%edi), %eax
0x004dea97:	addl %edi, $0x5<UINT8>
0x004dea9a:	movb %al, %bl
0x004dea9c:	loop 0x004dea77
0x004dea9e:	leal %edi, 0xdb000(%esi)
0x004deaa4:	movl %eax, (%edi)
0x004deaa6:	orl %eax, %eax
0x004deaa8:	je 0x004deae6
0x004deaaa:	movl %ebx, 0x4(%edi)
0x004deaad:	leal %eax, 0xde708(%eax,%esi)
0x004deab4:	addl %ebx, %esi
0x004deab6:	pushl %eax
0x004deab7:	addl %edi, $0x8<UINT8>
0x004deaba:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x004deac0:	xchgl %ebp, %eax
0x004deac1:	movb %al, (%edi)
0x004deac3:	incl %edi
0x004deac4:	orb %al, %al
0x004deac6:	je 0x004deaa4
0x004deac8:	movl %ecx, %edi
0x004deaca:	pushl %edi
0x004deacb:	decl %eax
0x004deacc:	repn scasb %al, %es:(%edi)
0x004deace:	pushl %ebp
0x004deacf:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x004dead5:	orl %eax, %eax
0x004dead7:	je 7
0x004dead9:	movl (%ebx), %eax
0x004deadb:	addl %ebx, $0x4<UINT8>
0x004deade:	jmp 0x004deac1
GetProcAddress@KERNEL32.DLL: API Node	
0x004deae6:	addl %edi, $0x4<UINT8>
0x004deae9:	leal %ebx, -4(%esi)
0x004deaec:	xorl %eax, %eax
0x004deaee:	movb %al, (%edi)
0x004deaf0:	incl %edi
0x004deaf1:	orl %eax, %eax
0x004deaf3:	je 0x004deb17
0x004deaf5:	cmpb %al, $0xffffffef<UINT8>
0x004deaf7:	ja 0x004deb0a
0x004deaf9:	addl %ebx, %eax
0x004deafb:	movl %eax, (%ebx)
0x004deafd:	xchgb %ah, %al
0x004deaff:	roll %eax, $0x10<UINT8>
0x004deb02:	xchgb %ah, %al
0x004deb04:	addl %eax, %esi
0x004deb06:	movl (%ebx), %eax
0x004deb08:	jmp 0x004deaec
0x004deb0a:	andb %al, $0xf<UINT8>
0x004deb0c:	shll %eax, $0x10<UINT8>
0x004deb0f:	movw %ax, (%edi)
0x004deb12:	addl %edi, $0x2<UINT8>
0x004deb15:	jmp 0x004deaf9
0x004deb17:	movl %ebp, 0xde7b8(%esi)
0x004deb1d:	leal %edi, -4096(%esi)
0x004deb23:	movl %ebx, $0x1000<UINT32>
0x004deb28:	pushl %eax
0x004deb29:	pushl %esp
0x004deb2a:	pushl $0x4<UINT8>
0x004deb2c:	pushl %ebx
0x004deb2d:	pushl %edi
0x004deb2e:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x004deb30:	leal %eax, 0x21f(%edi)
0x004deb36:	andb (%eax), $0x7f<UINT8>
0x004deb39:	andb 0x28(%eax), $0x7f<UINT8>
0x004deb3d:	popl %eax
0x004deb3e:	pushl %eax
0x004deb3f:	pushl %esp
0x004deb40:	pushl %eax
0x004deb41:	pushl %ebx
0x004deb42:	pushl %edi
0x004deb43:	call VirtualProtect@kernel32.dll
0x004deb45:	popl %eax
0x004deb46:	popa
0x004deb47:	leal %eax, -128(%esp)
0x004deb4b:	pushl $0x0<UINT8>
0x004deb4d:	cmpl %esp, %eax
0x004deb4f:	jne 0x004deb4b
0x004deb51:	subl %esp, $0xffffff80<UINT8>
0x004deb54:	jmp 0x00407474
0x00407474:	call 0x0040ef2e
0x0040ef2e:	pushl %ebp
0x0040ef2f:	movl %ebp, %esp
0x0040ef31:	subl %esp, $0x14<UINT8>
0x0040ef34:	andl -12(%ebp), $0x0<UINT8>
0x0040ef38:	andl -8(%ebp), $0x0<UINT8>
0x0040ef3c:	movl %eax, 0x423280
0x0040ef41:	pushl %esi
0x0040ef42:	pushl %edi
0x0040ef43:	movl %edi, $0xbb40e64e<UINT32>
0x0040ef48:	movl %esi, $0xffff0000<UINT32>
0x0040ef4d:	cmpl %eax, %edi
0x0040ef4f:	je 0x0040ef5e
0x0040ef5e:	leal %eax, -12(%ebp)
0x0040ef61:	pushl %eax
0x0040ef62:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040ef68:	movl %eax, -8(%ebp)
0x0040ef6b:	xorl %eax, -12(%ebp)
0x0040ef6e:	movl -4(%ebp), %eax
0x0040ef71:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040ef77:	xorl -4(%ebp), %eax
0x0040ef7a:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040ef80:	xorl -4(%ebp), %eax
0x0040ef83:	leal %eax, -20(%ebp)
0x0040ef86:	pushl %eax
0x0040ef87:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040ef8d:	movl %ecx, -16(%ebp)
0x0040ef90:	leal %eax, -4(%ebp)
0x0040ef93:	xorl %ecx, -20(%ebp)
0x0040ef96:	xorl %ecx, -4(%ebp)
0x0040ef99:	xorl %ecx, %eax
0x0040ef9b:	cmpl %ecx, %edi
0x0040ef9d:	jne 0x0040efa6
0x0040efa6:	testl %esi, %ecx
0x0040efa8:	jne 0x0040efb6
0x0040efb6:	movl 0x423280, %ecx
0x0040efbc:	notl %ecx
0x0040efbe:	movl 0x423284, %ecx
0x0040efc4:	popl %edi
0x0040efc5:	popl %esi
0x0040efc6:	movl %esp, %ebp
0x0040efc8:	popl %ebp
0x0040efc9:	ret

0x00407479:	jmp 0x004072f9
0x004072f9:	pushl $0x14<UINT8>
0x004072fb:	pushl $0x421dd0<UINT32>
0x00407300:	call 0x00409940
0x00409940:	pushl $0x4099a0<UINT32>
0x00409945:	pushl %fs:0
0x0040994c:	movl %eax, 0x10(%esp)
0x00409950:	movl 0x10(%esp), %ebp
0x00409954:	leal %ebp, 0x10(%esp)
0x00409958:	subl %esp, %eax
0x0040995a:	pushl %ebx
0x0040995b:	pushl %esi
0x0040995c:	pushl %edi
0x0040995d:	movl %eax, 0x423280
0x00409962:	xorl -4(%ebp), %eax
0x00409965:	xorl %eax, %ebp
0x00409967:	pushl %eax
0x00409968:	movl -24(%ebp), %esp
0x0040996b:	pushl -8(%ebp)
0x0040996e:	movl %eax, -4(%ebp)
0x00409971:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00409978:	movl -8(%ebp), %eax
0x0040997b:	leal %eax, -16(%ebp)
0x0040997e:	movl %fs:0, %eax
0x00409984:	ret

0x00407305:	pushl $0x1<UINT8>
0x00407307:	call 0x0040eee1
0x0040eee1:	pushl %ebp
0x0040eee2:	movl %ebp, %esp
0x0040eee4:	movl %eax, 0x8(%ebp)
0x0040eee7:	movl 0x462dd0, %eax
0x0040eeec:	popl %ebp
0x0040eeed:	ret

0x0040730c:	popl %ecx
0x0040730d:	movl %eax, $0x5a4d<UINT32>
0x00407312:	cmpw 0x400000, %ax
0x00407319:	je 0x0040731f
0x0040731f:	movl %eax, 0x40003c
0x00407324:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x0040732e:	jne -21
0x00407330:	movl %ecx, $0x10b<UINT32>
0x00407335:	cmpw 0x400018(%eax), %cx
0x0040733c:	jne -35
0x0040733e:	xorl %ebx, %ebx
0x00407340:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00407347:	jbe 9
0x00407349:	cmpl 0x4000e8(%eax), %ebx
0x0040734f:	setne %bl
0x00407352:	movl -28(%ebp), %ebx
0x00407355:	call 0x004084ed
0x004084ed:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x004084f3:	xorl %ecx, %ecx
0x004084f5:	movl 0x462dc8, %eax
0x004084fa:	testl %eax, %eax
0x004084fc:	setne %cl
0x004084ff:	movl %eax, %ecx
0x00408501:	ret

0x0040735a:	testl %eax, %eax
0x0040735c:	jne 0x00407366
0x00407366:	call 0x00408380
0x00408380:	call 0x00407078
0x00407078:	pushl %esi
0x00407079:	pushl $0x0<UINT8>
0x0040707b:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00407081:	movl %esi, %eax
0x00407083:	pushl %esi
0x00407084:	call 0x00409356
0x00409356:	pushl %ebp
0x00409357:	movl %ebp, %esp
0x00409359:	movl %eax, 0x8(%ebp)
0x0040935c:	movl 0x462dcc, %eax
0x00409361:	popl %ebp
0x00409362:	ret

0x00407089:	pushl %esi
0x0040708a:	call 0x004075a3
0x004075a3:	pushl %ebp
0x004075a4:	movl %ebp, %esp
0x004075a6:	movl %eax, 0x8(%ebp)
0x004075a9:	movl 0x462da4, %eax
0x004075ae:	popl %ebp
0x004075af:	ret

0x0040708f:	pushl %esi
0x00407090:	call 0x0040e650
0x0040e650:	pushl %ebp
0x0040e651:	movl %ebp, %esp
0x0040e653:	movl %eax, 0x8(%ebp)
0x0040e656:	movl 0x46367c, %eax
0x0040e65b:	popl %ebp
0x0040e65c:	ret

0x00407095:	pushl %esi
0x00407096:	call 0x0040e66a
0x0040e66a:	pushl %ebp
0x0040e66b:	movl %ebp, %esp
0x0040e66d:	movl %eax, 0x8(%ebp)
0x0040e670:	movl 0x463680, %eax
0x0040e675:	movl 0x463684, %eax
0x0040e67a:	movl 0x463688, %eax
0x0040e67f:	movl 0x46368c, %eax
0x0040e684:	popl %ebp
0x0040e685:	ret

0x0040709b:	pushl %esi
0x0040709c:	call 0x0040e63f
0x0040e63f:	pushl $0x40e5f8<UINT32>
0x0040e644:	call EncodePointer@KERNEL32.DLL
0x0040e64a:	movl 0x463678, %eax
0x0040e64f:	ret

0x004070a1:	pushl %esi
0x004070a2:	call 0x0040e87b
0x0040e87b:	pushl %ebp
0x0040e87c:	movl %ebp, %esp
0x0040e87e:	movl %eax, 0x8(%ebp)
0x0040e881:	movl 0x463694, %eax
0x0040e886:	popl %ebp
0x0040e887:	ret

0x004070a7:	addl %esp, $0x18<UINT8>
0x004070aa:	popl %esi
0x004070ab:	jmp 0x0040dddb
0x0040dddb:	pushl %esi
0x0040dddc:	pushl %edi
0x0040dddd:	pushl $0x4207f8<UINT32>
0x0040dde2:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0040dde8:	movl %esi, 0x418100
0x0040ddee:	movl %edi, %eax
0x0040ddf0:	pushl $0x4192bc<UINT32>
0x0040ddf5:	pushl %edi
0x0040ddf6:	call GetProcAddress@KERNEL32.DLL
0x0040ddf8:	xorl %eax, 0x423280
0x0040ddfe:	pushl $0x4192c8<UINT32>
0x0040de03:	pushl %edi
0x0040de04:	movl 0x463980, %eax
0x0040de09:	call GetProcAddress@KERNEL32.DLL
0x0040de0b:	xorl %eax, 0x423280
0x0040de11:	pushl $0x4192d0<UINT32>
0x0040de16:	pushl %edi
0x0040de17:	movl 0x463984, %eax
0x0040de1c:	call GetProcAddress@KERNEL32.DLL
0x0040de1e:	xorl %eax, 0x423280
0x0040de24:	pushl $0x4192dc<UINT32>
0x0040de29:	pushl %edi
0x0040de2a:	movl 0x463988, %eax
0x0040de2f:	call GetProcAddress@KERNEL32.DLL
0x0040de31:	xorl %eax, 0x423280
0x0040de37:	pushl $0x4192e8<UINT32>
0x0040de3c:	pushl %edi
0x0040de3d:	movl 0x46398c, %eax
0x0040de42:	call GetProcAddress@KERNEL32.DLL
0x0040de44:	xorl %eax, 0x423280
0x0040de4a:	pushl $0x419304<UINT32>
0x0040de4f:	pushl %edi
0x0040de50:	movl 0x463990, %eax
0x0040de55:	call GetProcAddress@KERNEL32.DLL
0x0040de57:	xorl %eax, 0x423280
0x0040de5d:	pushl $0x419314<UINT32>
0x0040de62:	pushl %edi
0x0040de63:	movl 0x463994, %eax
0x0040de68:	call GetProcAddress@KERNEL32.DLL
0x0040de6a:	xorl %eax, 0x423280
0x0040de70:	pushl $0x419328<UINT32>
0x0040de75:	pushl %edi
0x0040de76:	movl 0x463998, %eax
0x0040de7b:	call GetProcAddress@KERNEL32.DLL
0x0040de7d:	xorl %eax, 0x423280
0x0040de83:	pushl $0x419340<UINT32>
0x0040de88:	pushl %edi
0x0040de89:	movl 0x46399c, %eax
0x0040de8e:	call GetProcAddress@KERNEL32.DLL
0x0040de90:	xorl %eax, 0x423280
0x0040de96:	pushl $0x419358<UINT32>
0x0040de9b:	pushl %edi
0x0040de9c:	movl 0x4639a0, %eax
0x0040dea1:	call GetProcAddress@KERNEL32.DLL
0x0040dea3:	xorl %eax, 0x423280
0x0040dea9:	pushl $0x41936c<UINT32>
0x0040deae:	pushl %edi
0x0040deaf:	movl 0x4639a4, %eax
0x0040deb4:	call GetProcAddress@KERNEL32.DLL
0x0040deb6:	xorl %eax, 0x423280
0x0040debc:	pushl $0x41938c<UINT32>
0x0040dec1:	pushl %edi
0x0040dec2:	movl 0x4639a8, %eax
0x0040dec7:	call GetProcAddress@KERNEL32.DLL
0x0040dec9:	xorl %eax, 0x423280
0x0040decf:	pushl $0x4193a4<UINT32>
0x0040ded4:	pushl %edi
0x0040ded5:	movl 0x4639ac, %eax
0x0040deda:	call GetProcAddress@KERNEL32.DLL
0x0040dedc:	xorl %eax, 0x423280
0x0040dee2:	pushl $0x4193bc<UINT32>
0x0040dee7:	pushl %edi
0x0040dee8:	movl 0x4639b0, %eax
0x0040deed:	call GetProcAddress@KERNEL32.DLL
0x0040deef:	xorl %eax, 0x423280
0x0040def5:	pushl $0x4193d0<UINT32>
0x0040defa:	pushl %edi
0x0040defb:	movl 0x4639b4, %eax
0x0040df00:	call GetProcAddress@KERNEL32.DLL
0x0040df02:	xorl %eax, 0x423280
0x0040df08:	movl 0x4639b8, %eax
0x0040df0d:	pushl $0x4193e4<UINT32>
0x0040df12:	pushl %edi
0x0040df13:	call GetProcAddress@KERNEL32.DLL
0x0040df15:	xorl %eax, 0x423280
0x0040df1b:	pushl $0x419400<UINT32>
0x0040df20:	pushl %edi
0x0040df21:	movl 0x4639bc, %eax
0x0040df26:	call GetProcAddress@KERNEL32.DLL
0x0040df28:	xorl %eax, 0x423280
0x0040df2e:	pushl $0x419420<UINT32>
0x0040df33:	pushl %edi
0x0040df34:	movl 0x4639c0, %eax
0x0040df39:	call GetProcAddress@KERNEL32.DLL
0x0040df3b:	xorl %eax, 0x423280
0x0040df41:	pushl $0x421568<UINT32>
0x0040df46:	pushl %edi
0x0040df47:	movl 0x4639c4, %eax
0x0040df4c:	call GetProcAddress@KERNEL32.DLL
0x0040df4e:	xorl %eax, 0x423280
0x0040df54:	pushl $0x41943c<UINT32>
0x0040df59:	pushl %edi
0x0040df5a:	movl 0x4639c8, %eax
0x0040df5f:	call GetProcAddress@KERNEL32.DLL
0x0040df61:	xorl %eax, 0x423280
0x0040df67:	pushl $0x419450<UINT32>
0x0040df6c:	pushl %edi
0x0040df6d:	movl 0x4639cc, %eax
0x0040df72:	call GetProcAddress@KERNEL32.DLL
0x0040df74:	xorl %eax, 0x423280
0x0040df7a:	pushl $0x41946c<UINT32>
0x0040df7f:	pushl %edi
0x0040df80:	movl 0x4639d0, %eax
0x0040df85:	call GetProcAddress@KERNEL32.DLL
0x0040df87:	xorl %eax, 0x423280
0x0040df8d:	pushl $0x419480<UINT32>
0x0040df92:	pushl %edi
0x0040df93:	movl 0x4639d8, %eax
0x0040df98:	call GetProcAddress@KERNEL32.DLL
0x0040df9a:	xorl %eax, 0x423280
0x0040dfa0:	pushl $0x419490<UINT32>
0x0040dfa5:	pushl %edi
0x0040dfa6:	movl 0x4639d4, %eax
0x0040dfab:	call GetProcAddress@KERNEL32.DLL
0x0040dfad:	xorl %eax, 0x423280
0x0040dfb3:	pushl $0x4194a0<UINT32>
0x0040dfb8:	pushl %edi
0x0040dfb9:	movl 0x4639dc, %eax
0x0040dfbe:	call GetProcAddress@KERNEL32.DLL
0x0040dfc0:	xorl %eax, 0x423280
0x0040dfc6:	pushl $0x4194b0<UINT32>
0x0040dfcb:	pushl %edi
0x0040dfcc:	movl 0x4639e0, %eax
0x0040dfd1:	call GetProcAddress@KERNEL32.DLL
0x0040dfd3:	xorl %eax, 0x423280
0x0040dfd9:	pushl $0x4194c0<UINT32>
0x0040dfde:	pushl %edi
0x0040dfdf:	movl 0x4639e4, %eax
0x0040dfe4:	call GetProcAddress@KERNEL32.DLL
0x0040dfe6:	xorl %eax, 0x423280
0x0040dfec:	pushl $0x4194dc<UINT32>
0x0040dff1:	pushl %edi
0x0040dff2:	movl 0x4639e8, %eax
0x0040dff7:	call GetProcAddress@KERNEL32.DLL
0x0040dff9:	xorl %eax, 0x423280
0x0040dfff:	pushl $0x4194f0<UINT32>
0x0040e004:	pushl %edi
0x0040e005:	movl 0x4639ec, %eax
0x0040e00a:	call GetProcAddress@KERNEL32.DLL
0x0040e00c:	xorl %eax, 0x423280
0x0040e012:	pushl $0x419500<UINT32>
0x0040e017:	pushl %edi
0x0040e018:	movl 0x4639f0, %eax
0x0040e01d:	call GetProcAddress@KERNEL32.DLL
0x0040e01f:	xorl %eax, 0x423280
0x0040e025:	pushl $0x419514<UINT32>
0x0040e02a:	pushl %edi
0x0040e02b:	movl 0x4639f4, %eax
0x0040e030:	call GetProcAddress@KERNEL32.DLL
0x0040e032:	xorl %eax, 0x423280
0x0040e038:	movl 0x4639f8, %eax
0x0040e03d:	pushl $0x419524<UINT32>
0x0040e042:	pushl %edi
0x0040e043:	call GetProcAddress@KERNEL32.DLL
0x0040e045:	xorl %eax, 0x423280
0x0040e04b:	pushl $0x419544<UINT32>
0x0040e050:	pushl %edi
0x0040e051:	movl 0x4639fc, %eax
0x0040e056:	call GetProcAddress@KERNEL32.DLL
0x0040e058:	xorl %eax, 0x423280
0x0040e05e:	popl %edi
0x0040e05f:	movl 0x463a00, %eax
0x0040e064:	popl %esi
0x0040e065:	ret

0x00408385:	call 0x0040cda4
0x0040cda4:	pushl %esi
0x0040cda5:	pushl %edi
0x0040cda6:	movl %esi, $0x423ce0<UINT32>
0x0040cdab:	movl %edi, $0x463528<UINT32>
0x0040cdb0:	cmpl 0x4(%esi), $0x1<UINT8>
0x0040cdb4:	jne 22
0x0040cdb6:	pushl $0x0<UINT8>
0x0040cdb8:	movl (%esi), %edi
0x0040cdba:	addl %edi, $0x18<UINT8>
0x0040cdbd:	pushl $0xfa0<UINT32>
0x0040cdc2:	pushl (%esi)
0x0040cdc4:	call 0x0040dd6c
0x0040dd6c:	pushl %ebp
0x0040dd6d:	movl %ebp, %esp
0x0040dd6f:	movl %eax, 0x463990
0x0040dd74:	xorl %eax, 0x423280
0x0040dd7a:	je 13
0x0040dd7c:	pushl 0x10(%ebp)
0x0040dd7f:	pushl 0xc(%ebp)
0x0040dd82:	pushl 0x8(%ebp)
0x0040dd85:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x0040dd87:	popl %ebp
0x0040dd88:	ret

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
