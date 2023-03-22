0x0042edb0:	pusha
0x0042edb1:	movl %esi, $0x41e000<UINT32>
0x0042edb6:	leal %edi, -118784(%esi)
0x0042edbc:	pushl %edi
0x0042edbd:	jmp 0x0042edca
0x0042edca:	movl %ebx, (%esi)
0x0042edcc:	subl %esi, $0xfffffffc<UINT8>
0x0042edcf:	adcl %ebx, %ebx
0x0042edd1:	jb 0x0042edc0
0x0042edc0:	movb %al, (%esi)
0x0042edc2:	incl %esi
0x0042edc3:	movb (%edi), %al
0x0042edc5:	incl %edi
0x0042edc6:	addl %ebx, %ebx
0x0042edc8:	jne 0x0042edd1
0x0042edd3:	movl %eax, $0x1<UINT32>
0x0042edd8:	addl %ebx, %ebx
0x0042edda:	jne 0x0042ede3
0x0042ede3:	adcl %eax, %eax
0x0042ede5:	addl %ebx, %ebx
0x0042ede7:	jae 0x0042edd8
0x0042ede9:	jne 0x0042edf4
0x0042edf4:	xorl %ecx, %ecx
0x0042edf6:	subl %eax, $0x3<UINT8>
0x0042edf9:	jb 0x0042ee08
0x0042edfb:	shll %eax, $0x8<UINT8>
0x0042edfe:	movb %al, (%esi)
0x0042ee00:	incl %esi
0x0042ee01:	xorl %eax, $0xffffffff<UINT8>
0x0042ee04:	je 0x0042ee7a
0x0042ee06:	movl %ebp, %eax
0x0042ee08:	addl %ebx, %ebx
0x0042ee0a:	jne 0x0042ee13
0x0042ee13:	adcl %ecx, %ecx
0x0042ee15:	addl %ebx, %ebx
0x0042ee17:	jne 0x0042ee20
0x0042ee20:	adcl %ecx, %ecx
0x0042ee22:	jne 0x0042ee44
0x0042ee44:	cmpl %ebp, $0xfffff300<UINT32>
0x0042ee4a:	adcl %ecx, $0x1<UINT8>
0x0042ee4d:	leal %edx, (%edi,%ebp)
0x0042ee50:	cmpl %ebp, $0xfffffffc<UINT8>
0x0042ee53:	jbe 0x0042ee64
0x0042ee64:	movl %eax, (%edx)
0x0042ee66:	addl %edx, $0x4<UINT8>
0x0042ee69:	movl (%edi), %eax
0x0042ee6b:	addl %edi, $0x4<UINT8>
0x0042ee6e:	subl %ecx, $0x4<UINT8>
0x0042ee71:	ja 0x0042ee64
0x0042ee73:	addl %edi, %ecx
0x0042ee75:	jmp 0x0042edc6
0x0042ee55:	movb %al, (%edx)
0x0042ee57:	incl %edx
0x0042ee58:	movb (%edi), %al
0x0042ee5a:	incl %edi
0x0042ee5b:	decl %ecx
0x0042ee5c:	jne 0x0042ee55
0x0042ee5e:	jmp 0x0042edc6
0x0042ee24:	incl %ecx
0x0042ee25:	addl %ebx, %ebx
0x0042ee27:	jne 0x0042ee30
0x0042ee30:	adcl %ecx, %ecx
0x0042ee32:	addl %ebx, %ebx
0x0042ee34:	jae 0x0042ee25
0x0042ee36:	jne 0x0042ee41
0x0042ee41:	addl %ecx, $0x2<UINT8>
0x0042edeb:	movl %ebx, (%esi)
0x0042eded:	subl %esi, $0xfffffffc<UINT8>
0x0042edf0:	adcl %ebx, %ebx
0x0042edf2:	jae 0x0042edd8
0x0042eddc:	movl %ebx, (%esi)
0x0042edde:	subl %esi, $0xfffffffc<UINT8>
0x0042ede1:	adcl %ebx, %ebx
0x0042ee29:	movl %ebx, (%esi)
0x0042ee2b:	subl %esi, $0xfffffffc<UINT8>
0x0042ee2e:	adcl %ebx, %ebx
0x0042ee0c:	movl %ebx, (%esi)
0x0042ee0e:	subl %esi, $0xfffffffc<UINT8>
0x0042ee11:	adcl %ebx, %ebx
0x0042ee19:	movl %ebx, (%esi)
0x0042ee1b:	subl %esi, $0xfffffffc<UINT8>
0x0042ee1e:	adcl %ebx, %ebx
0x0042ee38:	movl %ebx, (%esi)
0x0042ee3a:	subl %esi, $0xfffffffc<UINT8>
0x0042ee3d:	adcl %ebx, %ebx
0x0042ee3f:	jae 0x0042ee25
0x0042ee7a:	popl %esi
0x0042ee7b:	movl %edi, %esi
0x0042ee7d:	movl %ecx, $0x8fe<UINT32>
0x0042ee82:	movb %al, (%edi)
0x0042ee84:	incl %edi
0x0042ee85:	subb %al, $0xffffffe8<UINT8>
0x0042ee87:	cmpb %al, $0x1<UINT8>
0x0042ee89:	ja 0x0042ee82
0x0042ee8b:	cmpb (%edi), $0xb<UINT8>
0x0042ee8e:	jne 0x0042ee82
0x0042ee90:	movl %eax, (%edi)
0x0042ee92:	movb %bl, 0x4(%edi)
0x0042ee95:	shrw %ax, $0x8<UINT8>
0x0042ee99:	roll %eax, $0x10<UINT8>
0x0042ee9c:	xchgb %ah, %al
0x0042ee9e:	subl %eax, %edi
0x0042eea0:	subb %bl, $0xffffffe8<UINT8>
0x0042eea3:	addl %eax, %esi
0x0042eea5:	movl (%edi), %eax
0x0042eea7:	addl %edi, $0x5<UINT8>
0x0042eeaa:	movb %al, %bl
0x0042eeac:	loop 0x0042ee87
0x0042eeae:	leal %edi, 0x2c000(%esi)
0x0042eeb4:	movl %eax, (%edi)
0x0042eeb6:	orl %eax, %eax
0x0042eeb8:	je 0x0042eef6
0x0042eeba:	movl %ebx, 0x4(%edi)
0x0042eebd:	leal %eax, 0x2e550(%eax,%esi)
0x0042eec4:	addl %ebx, %esi
0x0042eec6:	pushl %eax
0x0042eec7:	addl %edi, $0x8<UINT8>
0x0042eeca:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x0042eed0:	xchgl %ebp, %eax
0x0042eed1:	movb %al, (%edi)
0x0042eed3:	incl %edi
0x0042eed4:	orb %al, %al
0x0042eed6:	je 0x0042eeb4
0x0042eed8:	movl %ecx, %edi
0x0042eeda:	pushl %edi
0x0042eedb:	decl %eax
0x0042eedc:	repn scasb %al, %es:(%edi)
0x0042eede:	pushl %ebp
0x0042eedf:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0042eee5:	orl %eax, %eax
0x0042eee7:	je 7
0x0042eee9:	movl (%ebx), %eax
0x0042eeeb:	addl %ebx, $0x4<UINT8>
0x0042eeee:	jmp 0x0042eed1
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x0042eef6:	movl %ebp, 0x2e5e4(%esi)
0x0042eefc:	leal %edi, -4096(%esi)
0x0042ef02:	movl %ebx, $0x1000<UINT32>
0x0042ef07:	pushl %eax
0x0042ef08:	pushl %esp
0x0042ef09:	pushl $0x4<UINT8>
0x0042ef0b:	pushl %ebx
0x0042ef0c:	pushl %edi
0x0042ef0d:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0042ef0f:	leal %eax, 0x217(%edi)
0x0042ef15:	andb (%eax), $0x7f<UINT8>
0x0042ef18:	andb 0x28(%eax), $0x7f<UINT8>
0x0042ef1c:	popl %eax
0x0042ef1d:	pushl %eax
0x0042ef1e:	pushl %esp
0x0042ef1f:	pushl %eax
0x0042ef20:	pushl %ebx
0x0042ef21:	pushl %edi
0x0042ef22:	call VirtualProtect@kernel32.dll
0x0042ef24:	popl %eax
0x0042ef25:	popa
0x0042ef26:	leal %eax, -128(%esp)
0x0042ef2a:	pushl $0x0<UINT8>
0x0042ef2c:	cmpl %esp, %eax
0x0042ef2e:	jne 0x0042ef2a
0x0042ef30:	subl %esp, $0xffffff80<UINT8>
0x0042ef33:	jmp 0x00409bbe
0x00409bbe:	call 0x0041270c
0x0041270c:	pushl %ebp
0x0041270d:	movl %ebp, %esp
0x0041270f:	subl %esp, $0x14<UINT8>
0x00412712:	andl -12(%ebp), $0x0<UINT8>
0x00412716:	andl -8(%ebp), $0x0<UINT8>
0x0041271a:	movl %eax, 0x427be0
0x0041271f:	pushl %esi
0x00412720:	pushl %edi
0x00412721:	movl %edi, $0xbb40e64e<UINT32>
0x00412726:	movl %esi, $0xffff0000<UINT32>
0x0041272b:	cmpl %eax, %edi
0x0041272d:	je 0x0041273c
0x0041273c:	leal %eax, -12(%ebp)
0x0041273f:	pushl %eax
0x00412740:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x00412746:	movl %eax, -8(%ebp)
0x00412749:	xorl %eax, -12(%ebp)
0x0041274c:	movl -4(%ebp), %eax
0x0041274f:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x00412755:	xorl -4(%ebp), %eax
0x00412758:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0041275e:	xorl -4(%ebp), %eax
0x00412761:	leal %eax, -20(%ebp)
0x00412764:	pushl %eax
0x00412765:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0041276b:	movl %ecx, -16(%ebp)
0x0041276e:	leal %eax, -4(%ebp)
0x00412771:	xorl %ecx, -20(%ebp)
0x00412774:	xorl %ecx, -4(%ebp)
0x00412777:	xorl %ecx, %eax
0x00412779:	cmpl %ecx, %edi
0x0041277b:	jne 0x00412784
0x00412784:	testl %esi, %ecx
0x00412786:	jne 0x00412794
0x00412794:	movl 0x427be0, %ecx
0x0041279a:	notl %ecx
0x0041279c:	movl 0x427be4, %ecx
0x004127a2:	popl %edi
0x004127a3:	popl %esi
0x004127a4:	movl %esp, %ebp
0x004127a6:	popl %ebp
0x004127a7:	ret

0x00409bc3:	jmp 0x00409a43
0x00409a43:	pushl $0x14<UINT8>
0x00409a45:	pushl $0x425518<UINT32>
0x00409a4a:	call 0x0040ba90
0x0040ba90:	pushl $0x407ea0<UINT32>
0x0040ba95:	pushl %fs:0
0x0040ba9c:	movl %eax, 0x10(%esp)
0x0040baa0:	movl 0x10(%esp), %ebp
0x0040baa4:	leal %ebp, 0x10(%esp)
0x0040baa8:	subl %esp, %eax
0x0040baaa:	pushl %ebx
0x0040baab:	pushl %esi
0x0040baac:	pushl %edi
0x0040baad:	movl %eax, 0x427be0
0x0040bab2:	xorl -4(%ebp), %eax
0x0040bab5:	xorl %eax, %ebp
0x0040bab7:	pushl %eax
0x0040bab8:	movl -24(%ebp), %esp
0x0040babb:	pushl -8(%ebp)
0x0040babe:	movl %eax, -4(%ebp)
0x0040bac1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0040bac8:	movl -8(%ebp), %eax
0x0040bacb:	leal %eax, -16(%ebp)
0x0040bace:	movl %fs:0, %eax
0x0040bad4:	ret

0x00409a4f:	pushl $0x1<UINT8>
0x00409a51:	call 0x004126bf
0x004126bf:	pushl %ebp
0x004126c0:	movl %ebp, %esp
0x004126c2:	movl %eax, 0x8(%ebp)
0x004126c5:	movl 0x4298d0, %eax
0x004126ca:	popl %ebp
0x004126cb:	ret

0x00409a56:	popl %ecx
0x00409a57:	movl %eax, $0x5a4d<UINT32>
0x00409a5c:	cmpw 0x400000, %ax
0x00409a63:	je 0x00409a69
0x00409a69:	movl %eax, 0x40003c
0x00409a6e:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00409a78:	jne -21
0x00409a7a:	movl %ecx, $0x10b<UINT32>
0x00409a7f:	cmpw 0x400018(%eax), %cx
0x00409a86:	jne -35
0x00409a88:	xorl %ebx, %ebx
0x00409a8a:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00409a91:	jbe 9
0x00409a93:	cmpl 0x4000e8(%eax), %ebx
0x00409a99:	setne %bl
0x00409a9c:	movl -28(%ebp), %ebx
0x00409a9f:	call 0x0040bbc0
0x0040bbc0:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x0040bbc6:	xorl %ecx, %ecx
0x0040bbc8:	movl 0x429f30, %eax
0x0040bbcd:	testl %eax, %eax
0x0040bbcf:	setne %cl
0x0040bbd2:	movl %eax, %ecx
0x0040bbd4:	ret

0x00409aa4:	testl %eax, %eax
0x00409aa6:	jne 0x00409ab0
0x00409ab0:	call 0x0040ab06
0x0040ab06:	call 0x00406338
0x00406338:	pushl %esi
0x00406339:	pushl $0x0<UINT8>
0x0040633b:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00406341:	movl %esi, %eax
0x00406343:	pushl %esi
0x00406344:	call 0x0040b83f
0x0040b83f:	pushl %ebp
0x0040b840:	movl %ebp, %esp
0x0040b842:	movl %eax, 0x8(%ebp)
0x0040b845:	movl 0x429f08, %eax
0x0040b84a:	popl %ebp
0x0040b84b:	ret

0x00406349:	pushl %esi
0x0040634a:	call 0x00409ced
0x00409ced:	pushl %ebp
0x00409cee:	movl %ebp, %esp
0x00409cf0:	movl %eax, 0x8(%ebp)
0x00409cf3:	movl 0x42975c, %eax
0x00409cf8:	popl %ebp
0x00409cf9:	ret

0x0040634f:	pushl %esi
0x00406350:	call 0x0040b84c
0x0040b84c:	pushl %ebp
0x0040b84d:	movl %ebp, %esp
0x0040b84f:	movl %eax, 0x8(%ebp)
0x0040b852:	movl 0x429f0c, %eax
0x0040b857:	popl %ebp
0x0040b858:	ret

0x00406355:	pushl %esi
0x00406356:	call 0x0040b866
0x0040b866:	pushl %ebp
0x0040b867:	movl %ebp, %esp
0x0040b869:	movl %eax, 0x8(%ebp)
0x0040b86c:	movl 0x429f10, %eax
0x0040b871:	movl 0x429f14, %eax
0x0040b876:	movl 0x429f18, %eax
0x0040b87b:	movl 0x429f1c, %eax
0x0040b880:	popl %ebp
0x0040b881:	ret

0x0040635b:	pushl %esi
0x0040635c:	call 0x0040b808
0x0040b808:	pushl $0x40b7c1<UINT32>
0x0040b80d:	call EncodePointer@KERNEL32.DLL
0x0040b813:	movl 0x429f04, %eax
0x0040b818:	ret

0x00406361:	pushl %esi
0x00406362:	call 0x0040ba77
0x0040ba77:	pushl %ebp
0x0040ba78:	movl %ebp, %esp
0x0040ba7a:	movl %eax, 0x8(%ebp)
0x0040ba7d:	movl 0x429f24, %eax
0x0040ba82:	popl %ebp
0x0040ba83:	ret

0x00406367:	addl %esp, $0x18<UINT8>
0x0040636a:	popl %esi
0x0040636b:	jmp 0x0040af1e
0x0040af1e:	pushl %esi
0x0040af1f:	pushl %edi
0x0040af20:	pushl $0x420fb0<UINT32>
0x0040af25:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0040af2b:	movl %esi, 0x4190b8
0x0040af31:	movl %edi, %eax
0x0040af33:	pushl $0x420fcc<UINT32>
0x0040af38:	pushl %edi
0x0040af39:	call GetProcAddress@KERNEL32.DLL
0x0040af3b:	xorl %eax, 0x427be0
0x0040af41:	pushl $0x420fd8<UINT32>
0x0040af46:	pushl %edi
0x0040af47:	movl 0x42a1e0, %eax
0x0040af4c:	call GetProcAddress@KERNEL32.DLL
0x0040af4e:	xorl %eax, 0x427be0
0x0040af54:	pushl $0x420fe0<UINT32>
0x0040af59:	pushl %edi
0x0040af5a:	movl 0x42a1e4, %eax
0x0040af5f:	call GetProcAddress@KERNEL32.DLL
0x0040af61:	xorl %eax, 0x427be0
0x0040af67:	pushl $0x420fec<UINT32>
0x0040af6c:	pushl %edi
0x0040af6d:	movl 0x42a1e8, %eax
0x0040af72:	call GetProcAddress@KERNEL32.DLL
0x0040af74:	xorl %eax, 0x427be0
0x0040af7a:	pushl $0x420ff8<UINT32>
0x0040af7f:	pushl %edi
0x0040af80:	movl 0x42a1ec, %eax
0x0040af85:	call GetProcAddress@KERNEL32.DLL
0x0040af87:	xorl %eax, 0x427be0
0x0040af8d:	pushl $0x421014<UINT32>
0x0040af92:	pushl %edi
0x0040af93:	movl 0x42a1f0, %eax
0x0040af98:	call GetProcAddress@KERNEL32.DLL
0x0040af9a:	xorl %eax, 0x427be0
0x0040afa0:	pushl $0x421024<UINT32>
0x0040afa5:	pushl %edi
0x0040afa6:	movl 0x42a1f4, %eax
0x0040afab:	call GetProcAddress@KERNEL32.DLL
0x0040afad:	xorl %eax, 0x427be0
0x0040afb3:	pushl $0x421038<UINT32>
0x0040afb8:	pushl %edi
0x0040afb9:	movl 0x42a1f8, %eax
0x0040afbe:	call GetProcAddress@KERNEL32.DLL
0x0040afc0:	xorl %eax, 0x427be0
0x0040afc6:	pushl $0x421050<UINT32>
0x0040afcb:	pushl %edi
0x0040afcc:	movl 0x42a1fc, %eax
0x0040afd1:	call GetProcAddress@KERNEL32.DLL
0x0040afd3:	xorl %eax, 0x427be0
0x0040afd9:	pushl $0x421068<UINT32>
0x0040afde:	pushl %edi
0x0040afdf:	movl 0x42a200, %eax
0x0040afe4:	call GetProcAddress@KERNEL32.DLL
0x0040afe6:	xorl %eax, 0x427be0
0x0040afec:	pushl $0x42107c<UINT32>
0x0040aff1:	pushl %edi
0x0040aff2:	movl 0x42a204, %eax
0x0040aff7:	call GetProcAddress@KERNEL32.DLL
0x0040aff9:	xorl %eax, 0x427be0
0x0040afff:	pushl $0x42109c<UINT32>
0x0040b004:	pushl %edi
0x0040b005:	movl 0x42a208, %eax
0x0040b00a:	call GetProcAddress@KERNEL32.DLL
0x0040b00c:	xorl %eax, 0x427be0
0x0040b012:	pushl $0x4210b4<UINT32>
0x0040b017:	pushl %edi
0x0040b018:	movl 0x42a20c, %eax
0x0040b01d:	call GetProcAddress@KERNEL32.DLL
0x0040b01f:	xorl %eax, 0x427be0
0x0040b025:	pushl $0x4210cc<UINT32>
0x0040b02a:	pushl %edi
0x0040b02b:	movl 0x42a210, %eax
0x0040b030:	call GetProcAddress@KERNEL32.DLL
0x0040b032:	xorl %eax, 0x427be0
0x0040b038:	pushl $0x4210e0<UINT32>
0x0040b03d:	pushl %edi
0x0040b03e:	movl 0x42a214, %eax
0x0040b043:	call GetProcAddress@KERNEL32.DLL
0x0040b045:	xorl %eax, 0x427be0
0x0040b04b:	movl 0x42a218, %eax
0x0040b050:	pushl $0x4210f4<UINT32>
0x0040b055:	pushl %edi
0x0040b056:	call GetProcAddress@KERNEL32.DLL
0x0040b058:	xorl %eax, 0x427be0
0x0040b05e:	pushl $0x421110<UINT32>
0x0040b063:	pushl %edi
0x0040b064:	movl 0x42a21c, %eax
0x0040b069:	call GetProcAddress@KERNEL32.DLL
0x0040b06b:	xorl %eax, 0x427be0
0x0040b071:	pushl $0x421130<UINT32>
0x0040b076:	pushl %edi
0x0040b077:	movl 0x42a220, %eax
0x0040b07c:	call GetProcAddress@KERNEL32.DLL
0x0040b07e:	xorl %eax, 0x427be0
0x0040b084:	pushl $0x42114c<UINT32>
0x0040b089:	pushl %edi
0x0040b08a:	movl 0x42a224, %eax
0x0040b08f:	call GetProcAddress@KERNEL32.DLL
0x0040b091:	xorl %eax, 0x427be0
0x0040b097:	pushl $0x42116c<UINT32>
0x0040b09c:	pushl %edi
0x0040b09d:	movl 0x42a228, %eax
0x0040b0a2:	call GetProcAddress@KERNEL32.DLL
0x0040b0a4:	xorl %eax, 0x427be0
0x0040b0aa:	pushl $0x421180<UINT32>
0x0040b0af:	pushl %edi
0x0040b0b0:	movl 0x42a22c, %eax
0x0040b0b5:	call GetProcAddress@KERNEL32.DLL
0x0040b0b7:	xorl %eax, 0x427be0
0x0040b0bd:	pushl $0x42119c<UINT32>
0x0040b0c2:	pushl %edi
0x0040b0c3:	movl 0x42a230, %eax
0x0040b0c8:	call GetProcAddress@KERNEL32.DLL
0x0040b0ca:	xorl %eax, 0x427be0
0x0040b0d0:	pushl $0x4211b0<UINT32>
0x0040b0d5:	pushl %edi
0x0040b0d6:	movl 0x42a238, %eax
0x0040b0db:	call GetProcAddress@KERNEL32.DLL
0x0040b0dd:	xorl %eax, 0x427be0
0x0040b0e3:	pushl $0x4211c0<UINT32>
0x0040b0e8:	pushl %edi
0x0040b0e9:	movl 0x42a234, %eax
0x0040b0ee:	call GetProcAddress@KERNEL32.DLL
0x0040b0f0:	xorl %eax, 0x427be0
0x0040b0f6:	pushl $0x4211d0<UINT32>
0x0040b0fb:	pushl %edi
0x0040b0fc:	movl 0x42a23c, %eax
0x0040b101:	call GetProcAddress@KERNEL32.DLL
0x0040b103:	xorl %eax, 0x427be0
0x0040b109:	pushl $0x4211e0<UINT32>
0x0040b10e:	pushl %edi
0x0040b10f:	movl 0x42a240, %eax
0x0040b114:	call GetProcAddress@KERNEL32.DLL
0x0040b116:	xorl %eax, 0x427be0
0x0040b11c:	pushl $0x4211f0<UINT32>
0x0040b121:	pushl %edi
0x0040b122:	movl 0x42a244, %eax
0x0040b127:	call GetProcAddress@KERNEL32.DLL
0x0040b129:	xorl %eax, 0x427be0
0x0040b12f:	pushl $0x42120c<UINT32>
0x0040b134:	pushl %edi
0x0040b135:	movl 0x42a248, %eax
0x0040b13a:	call GetProcAddress@KERNEL32.DLL
0x0040b13c:	xorl %eax, 0x427be0
0x0040b142:	pushl $0x421220<UINT32>
0x0040b147:	pushl %edi
0x0040b148:	movl 0x42a24c, %eax
0x0040b14d:	call GetProcAddress@KERNEL32.DLL
0x0040b14f:	xorl %eax, 0x427be0
0x0040b155:	pushl $0x421230<UINT32>
0x0040b15a:	pushl %edi
0x0040b15b:	movl 0x42a250, %eax
0x0040b160:	call GetProcAddress@KERNEL32.DLL
0x0040b162:	xorl %eax, 0x427be0
0x0040b168:	pushl $0x421244<UINT32>
0x0040b16d:	pushl %edi
0x0040b16e:	movl 0x42a254, %eax
0x0040b173:	call GetProcAddress@KERNEL32.DLL
0x0040b175:	xorl %eax, 0x427be0
0x0040b17b:	movl 0x42a258, %eax
0x0040b180:	pushl $0x421254<UINT32>
0x0040b185:	pushl %edi
0x0040b186:	call GetProcAddress@KERNEL32.DLL
0x0040b188:	xorl %eax, 0x427be0
0x0040b18e:	pushl $0x421274<UINT32>
0x0040b193:	pushl %edi
0x0040b194:	movl 0x42a25c, %eax
0x0040b199:	call GetProcAddress@KERNEL32.DLL
0x0040b19b:	xorl %eax, 0x427be0
0x0040b1a1:	popl %edi
0x0040b1a2:	movl 0x42a260, %eax
0x0040b1a7:	popl %esi
0x0040b1a8:	ret

0x0040ab0b:	call 0x0040ade4
0x0040ade4:	pushl %esi
0x0040ade5:	pushl %edi
0x0040ade6:	movl %esi, $0x428748<UINT32>
0x0040adeb:	movl %edi, $0x429780<UINT32>
0x0040adf0:	cmpl 0x4(%esi), $0x1<UINT8>
0x0040adf4:	jne 22
0x0040adf6:	pushl $0x0<UINT8>
0x0040adf8:	movl (%esi), %edi
0x0040adfa:	addl %edi, $0x18<UINT8>
0x0040adfd:	pushl $0xfa0<UINT32>
0x0040ae02:	pushl (%esi)
0x0040ae04:	call 0x0040aeb0
0x0040aeb0:	pushl %ebp
0x0040aeb1:	movl %ebp, %esp
0x0040aeb3:	movl %eax, 0x42a1f0
0x0040aeb8:	xorl %eax, 0x427be0
0x0040aebe:	je 13
0x0040aec0:	pushl 0x10(%ebp)
0x0040aec3:	pushl 0xc(%ebp)
0x0040aec6:	pushl 0x8(%ebp)
0x0040aec9:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x0040aecb:	popl %ebp
0x0040aecc:	ret

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
