0x0041c000:	movl %ebx, $0x4001d0<UINT32>
0x0041c005:	movl %edi, $0x401000<UINT32>
0x0041c00a:	movl %esi, $0x414060<UINT32>
0x0041c00f:	pushl %ebx
0x0041c010:	call 0x0041c01f
0x0041c01f:	cld
0x0041c020:	movb %dl, $0xffffff80<UINT8>
0x0041c022:	movsb %es:(%edi), %ds:(%esi)
0x0041c023:	pushl $0x2<UINT8>
0x0041c025:	popl %ebx
0x0041c026:	call 0x0041c015
0x0041c015:	addb %dl, %dl
0x0041c017:	jne 0x0041c01e
0x0041c019:	movb %dl, (%esi)
0x0041c01b:	incl %esi
0x0041c01c:	adcb %dl, %dl
0x0041c01e:	ret

0x0041c029:	jae 0x0041c022
0x0041c02b:	xorl %ecx, %ecx
0x0041c02d:	call 0x0041c015
0x0041c030:	jae 0x0041c04a
0x0041c04a:	call 0x0041c092
0x0041c092:	incl %ecx
0x0041c093:	call 0x0041c015
0x0041c097:	adcl %ecx, %ecx
0x0041c099:	call 0x0041c015
0x0041c09d:	jb 0x0041c093
0x0041c09f:	ret

0x0041c04f:	subl %ecx, %ebx
0x0041c051:	jne 0x0041c063
0x0041c063:	xchgl %ecx, %eax
0x0041c064:	decl %eax
0x0041c065:	shll %eax, $0x8<UINT8>
0x0041c068:	lodsb %al, %ds:(%esi)
0x0041c069:	call 0x0041c090
0x0041c090:	xorl %ecx, %ecx
0x0041c06e:	cmpl %eax, $0x7d00<UINT32>
0x0041c073:	jae 0x0041c07f
0x0041c075:	cmpb %ah, $0x5<UINT8>
0x0041c078:	jae 0x0041c080
0x0041c07a:	cmpl %eax, $0x7f<UINT8>
0x0041c07d:	ja 0x0041c081
0x0041c07f:	incl %ecx
0x0041c080:	incl %ecx
0x0041c081:	xchgl %ebp, %eax
0x0041c082:	movl %eax, %ebp
0x0041c084:	movb %bl, $0x1<UINT8>
0x0041c086:	pushl %esi
0x0041c087:	movl %esi, %edi
0x0041c089:	subl %esi, %eax
0x0041c08b:	rep movsb %es:(%edi), %ds:(%esi)
0x0041c08d:	popl %esi
0x0041c08e:	jmp 0x0041c026
0x0041c032:	xorl %eax, %eax
0x0041c034:	call 0x0041c015
0x0041c037:	jae 0x0041c05a
0x0041c039:	movb %bl, $0x2<UINT8>
0x0041c03b:	incl %ecx
0x0041c03c:	movb %al, $0x10<UINT8>
0x0041c03e:	call 0x0041c015
0x0041c041:	adcb %al, %al
0x0041c043:	jae 0x0041c03e
0x0041c045:	jne 0x0041c086
0x0041c047:	stosb %es:(%edi), %al
0x0041c048:	jmp 0x0041c026
0x0041c05a:	lodsb %al, %ds:(%esi)
0x0041c05b:	shrl %eax
0x0041c05d:	je 0x0041c0a0
0x0041c05f:	adcl %ecx, %ecx
0x0041c061:	jmp 0x0041c07f
0x0041c053:	call 0x0041c090
0x0041c058:	jmp 0x0041c082
0x0041c0a0:	popl %edi
0x0041c0a1:	popl %ebx
0x0041c0a2:	movzwl %edi, (%ebx)
0x0041c0a5:	decl %edi
0x0041c0a6:	je 0x0041c0b0
0x0041c0a8:	decl %edi
0x0041c0a9:	je 0x0041c0be
0x0041c0ab:	shll %edi, $0xc<UINT8>
0x0041c0ae:	jmp 0x0041c0b7
0x0041c0b7:	incl %ebx
0x0041c0b8:	incl %ebx
0x0041c0b9:	jmp 0x0041c00f
0x0041c0b0:	movl %edi, 0x2(%ebx)
0x0041c0b3:	pushl %edi
0x0041c0b4:	addl %ebx, $0x4<UINT8>
0x0041c0be:	popl %edi
0x0041c0bf:	movl %ebx, $0x41c128<UINT32>
0x0041c0c4:	incl %edi
0x0041c0c5:	movl %esi, (%edi)
0x0041c0c7:	scasl %eax, %es:(%edi)
0x0041c0c8:	pushl %edi
0x0041c0c9:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x0041c0cb:	xchgl %ebp, %eax
0x0041c0cc:	xorl %eax, %eax
0x0041c0ce:	scasb %al, %es:(%edi)
0x0041c0cf:	jne 0x0041c0ce
0x0041c0d1:	decb (%edi)
0x0041c0d3:	je 0x0041c0c4
0x0041c0d5:	decb (%edi)
0x0041c0d7:	jne 0x0041c0df
0x0041c0df:	decb (%edi)
0x0041c0e1:	je 0x00404090
0x0041c0e7:	pushl %edi
0x0041c0e8:	pushl %ebp
0x0041c0e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x0041c0ec:	orl (%esi), %eax
0x0041c0ee:	lodsl %eax, %ds:(%esi)
0x0041c0ef:	jne 0x0041c0cc
GetProcAddress@KERNEL32.dll: API Node	
0x00404090:	call 0x004059e8
0x004059e8:	movl %edi, %edi
0x004059ea:	pushl %ebp
0x004059eb:	movl %ebp, %esp
0x004059ed:	subl %esp, $0x14<UINT8>
0x004059f0:	andl -12(%ebp), $0x0<UINT8>
0x004059f4:	andl -8(%ebp), $0x0<UINT8>
0x004059f8:	movl %eax, 0x40f048
0x004059fd:	pushl %esi
0x004059fe:	pushl %edi
0x004059ff:	movl %edi, $0xbb40e64e<UINT32>
0x00405a04:	movl %esi, $0xffff0000<UINT32>
0x00405a09:	cmpl %eax, %edi
0x00405a0b:	je 0x00405a1a
0x00405a1a:	leal %eax, -12(%ebp)
0x00405a1d:	pushl %eax
0x00405a1e:	call GetSystemTimeAsFileTime@KERNEL32.dll
GetSystemTimeAsFileTime@KERNEL32.dll: API Node	
0x00405a24:	movl %eax, -8(%ebp)
0x00405a27:	xorl %eax, -12(%ebp)
0x00405a2a:	movl -4(%ebp), %eax
0x00405a2d:	call GetCurrentProcessId@KERNEL32.dll
GetCurrentProcessId@KERNEL32.dll: API Node	
0x00405a33:	xorl -4(%ebp), %eax
0x00405a36:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x00405a3c:	xorl -4(%ebp), %eax
0x00405a3f:	call GetTickCount@KERNEL32.dll
GetTickCount@KERNEL32.dll: API Node	
0x00405a45:	xorl %eax, -4(%ebp)
0x00405a48:	leal %ecx, -4(%ebp)
0x00405a4b:	xorl %eax, %ecx
0x00405a4d:	movl -4(%ebp), %eax
0x00405a50:	leal %eax, -20(%ebp)
0x00405a53:	pushl %eax
0x00405a54:	call QueryPerformanceCounter@KERNEL32.dll
QueryPerformanceCounter@KERNEL32.dll: API Node	
0x00405a5a:	movl %eax, -16(%ebp)
0x00405a5d:	xorl %eax, -20(%ebp)
0x00405a60:	movl %ecx, -4(%ebp)
0x00405a63:	xorl %ecx, %eax
0x00405a65:	cmpl %ecx, %edi
0x00405a67:	je 8
0x00405a69:	testl 0x40f048, %esi
0x00405a6f:	jne 0x00405a76
0x00405a76:	movl 0x40f048, %ecx
0x00405a7c:	notl %ecx
0x00405a7e:	movl 0x40f04c, %ecx
0x00405a84:	popl %edi
0x00405a85:	popl %esi
0x00405a86:	movl %esp, %ebp
0x00405a88:	popl %ebp
0x00405a89:	ret

0x00404095:	jmp 0x00403e84
0x00403e84:	pushl $0xac<UINT32>
0x00403e89:	pushl $0x40dfd8<UINT32>
0x00403e8e:	call 0x00405bb4
0x00405bb4:	pushl $0x405c50<UINT32>
0x00405bb9:	pushl %fs:0
0x00405bc0:	movl %eax, 0x10(%esp)
0x00405bc4:	movl 0x10(%esp), %ebp
0x00405bc8:	leal %ebp, 0x10(%esp)
0x00405bcc:	subl %esp, %eax
0x00405bce:	pushl %ebx
0x00405bcf:	pushl %esi
0x00405bd0:	pushl %edi
0x00405bd1:	movl %eax, 0x40f048
0x00405bd6:	xorl -4(%ebp), %eax
0x00405bd9:	xorl %eax, %ebp
0x00405bdb:	movl -28(%ebp), %eax
0x00405bde:	pushl %eax
0x00405bdf:	movl -24(%ebp), %esp
0x00405be2:	pushl -8(%ebp)
0x00405be5:	movl %eax, -4(%ebp)
0x00405be8:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00405bef:	movl -8(%ebp), %eax
0x00405bf2:	leal %eax, -16(%ebp)
0x00405bf5:	movl %fs:0, %eax
0x00405bfb:	ret

0x00403e93:	movl -176(%ebp), $0x94<UINT32>
0x00403e9d:	leal %eax, -176(%ebp)
0x00403ea3:	pushl %eax
0x00403ea4:	call GetVersionExA@KERNEL32.dll
GetVersionExA@KERNEL32.dll: API Node	
0x00403eaa:	testl %eax, %eax
0x00403eac:	jne 0x00403eb8
0x00403eb8:	movl %esi, -164(%ebp)
0x00403ebe:	andl %esi, $0x7fff<UINT32>
0x00403ec4:	movl %edi, -160(%ebp)
0x00403eca:	cmpl %edi, $0x2<UINT8>
0x00403ecd:	je 0x00403ed5
0x00403ed5:	movl %edx, -172(%ebp)
0x00403edb:	movl %ecx, %edx
0x00403edd:	shll %ecx, $0x8<UINT8>
0x00403ee0:	movl %eax, -168(%ebp)
0x00403ee6:	addl %ecx, %eax
0x00403ee8:	movl 0x40fb70, %edi
0x00403eee:	movl 0x40fb78, %ecx
0x00403ef4:	movl 0x40fb7c, %edx
0x00403efa:	movl 0x40fb80, %eax
0x00403eff:	movl 0x40fb74, %esi
0x00403f05:	call 0x00404017
0x00404017:	movl %eax, $0x5a4d<UINT32>
0x0040401c:	cmpw 0x400000, %ax
0x00404023:	jne 53
0x00404025:	movl %ecx, 0x40003c
0x0040402b:	cmpl 0x400000(%ecx), $0x4550<UINT32>
0x00404035:	jne 35
0x00404037:	movl %eax, $0x10b<UINT32>
0x0040403c:	cmpw 0x400018(%ecx), %ax
0x00404043:	jne 21
0x00404045:	xorl %eax, %eax
0x00404047:	cmpl 0x400074(%ecx), $0xe<UINT8>
0x0040404e:	jbe 12
0x00404050:	cmpl 0x4000e8(%ecx), %eax
0x00404056:	setne %al
0x00404059:	ret

0x00403f0a:	movl %edi, %eax
0x00403f0c:	movl -188(%ebp), %edi
0x00403f12:	pushl $0x1<UINT8>
0x00403f14:	call 0x004052e4
0x004052e4:	movl %edi, %edi
0x004052e6:	pushl %ebp
0x004052e7:	movl %ebp, %esp
0x004052e9:	xorl %eax, %eax
0x004052eb:	cmpl 0x8(%ebp), %eax
0x004052ee:	pushl $0x0<UINT8>
0x004052f0:	pushl $0x1000<UINT32>
0x004052f5:	sete %al
0x004052f8:	pushl %eax
0x004052f9:	call HeapCreate@KERNEL32.dll
HeapCreate@KERNEL32.dll: API Node	
0x004052ff:	movl 0x40fea4, %eax
0x00405304:	testl %eax, %eax
0x00405306:	jne 0x0040530a
0x0040530a:	xorl %eax, %eax
0x0040530c:	incl %eax
0x0040530d:	movl 0x4116a0, %eax
0x00405312:	popl %ebp
0x00405313:	ret

0x00403f19:	popl %ecx
0x00403f1a:	testl %eax, %eax
0x00403f1c:	jne 0x00403f26
0x00403f26:	call 0x00404acb
0x00404acb:	movl %edi, %edi
0x00404acd:	pushl %ebp
0x00404ace:	movl %ebp, %esp
0x00404ad0:	pushl %ecx
0x00404ad1:	movl %eax, 0x40f048
0x00404ad6:	xorl %eax, %ebp
0x00404ad8:	movl -4(%ebp), %eax
0x00404adb:	pushl %esi
0x00404adc:	pushl %edi
0x00404add:	call 0x00404903
0x00404903:	movl %edi, %edi
0x00404905:	pushl %esi
0x00404906:	xorl %ecx, %ecx
0x00404908:	movl %esi, $0x40fb58<UINT32>
0x0040490d:	xorl %eax, %eax
0x0040490f:	cmpxchgl (%esi), %ecx
0x00404913:	testl %eax, %eax
0x00404915:	jne 0x0040493d
0x00404917:	pushl 0x40f01c
0x0040491d:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x00404923:	movl %ecx, %eax
0x00404925:	testl %ecx, %ecx
0x00404927:	jne 0x00404937
0x00404937:	movl %eax, %ecx
0x00404939:	xchgl (%esi), %eax
0x0040493b:	movl %eax, %ecx
0x0040493d:	popl %esi
0x0040493e:	ret

0x00404ae2:	movl %esi, %eax
0x00404ae4:	testl %esi, %esi
0x00404ae6:	jne 0x00404aff
0x00404aff:	pushl $0x4011d4<UINT32>
0x00404b04:	pushl %esi
0x00404b05:	call GetProcAddress@KERNEL32.dll
0x00404b0b:	pushl $0x4011e0<UINT32>
0x00404b10:	pushl %esi
0x00404b11:	movl 0x40fb48, %eax
0x00404b16:	call GetProcAddress@KERNEL32.dll
0x00404b1c:	pushl $0x4011ec<UINT32>
0x00404b21:	pushl %esi
0x00404b22:	movl 0x40fb4c, %eax
0x00404b27:	call GetProcAddress@KERNEL32.dll
0x00404b2d:	pushl $0x4011f8<UINT32>
0x00404b32:	pushl %esi
0x00404b33:	movl 0x40fb50, %eax
0x00404b38:	call GetProcAddress@KERNEL32.dll
0x00404b3e:	cmpl 0x40fb48, $0x0<UINT8>
0x00404b45:	movl 0x40fb54, %eax
0x00404b4a:	je 22
0x00404b4c:	cmpl 0x40fb4c, $0x0<UINT8>
0x00404b53:	je 13
0x00404b55:	cmpl 0x40fb50, $0x0<UINT8>
0x00404b5c:	je 4
0x00404b5e:	testl %eax, %eax
0x00404b60:	jne 0x00404b8a
0x00404b8a:	call TlsAlloc@KERNEL32.dll
TlsAlloc@KERNEL32.dll: API Node	
0x00404b90:	movl 0x40f014, %eax
0x00404b95:	cmpl %eax, $0xffffffff<UINT8>
0x00404b98:	je -177
0x00404b9e:	pushl 0x40fb4c
0x00404ba4:	pushl %eax
0x00404ba5:	call TlsSetValue@KERNEL32.dll
TlsSetValue@KERNEL32.dll: API Node	
0x00404bab:	testl %eax, %eax
0x00404bad:	je -198
0x00404bb3:	call 0x00404f07
0x00404f07:	movl %edi, %edi
0x00404f09:	pushl %esi
0x00404f0a:	call 0x004047a5
0x004047a5:	pushl $0x0<UINT8>
0x004047a7:	call 0x00404719
0x00404719:	movl %edi, %edi
0x0040471b:	pushl %ebp
0x0040471c:	movl %ebp, %esp
0x0040471e:	pushl %ecx
0x0040471f:	movl %eax, 0x40f048
0x00404724:	xorl %eax, %ebp
0x00404726:	movl -4(%ebp), %eax
0x00404729:	pushl %esi
0x0040472a:	pushl 0x40f014
0x00404730:	call TlsGetValue@KERNEL32.dll
TlsGetValue@KERNEL32.dll: API Node	
0x00404736:	testl %eax, %eax
0x00404738:	je 47
0x0040473a:	movl %eax, 0x40f010
0x0040473f:	cmpl %eax, $0xffffffff<UINT8>
0x00404742:	je 0x00404769
0x00404769:	call 0x00404903
0x0040476e:	testl %eax, %eax
0x00404770:	je 33
0x00404772:	pushl $0x4011b4<UINT32>
0x00404777:	pushl %eax
0x00404778:	call GetProcAddress@KERNEL32.dll
0x0040477e:	movl %esi, %eax
0x00404780:	testl %esi, %esi
0x00404782:	je 15
0x00404784:	pushl 0x8(%ebp)
0x00404787:	movl %ecx, %esi
0x00404789:	call 0x00404640
0x00404640:	ret

0x0040478f:	call EncodePointer@KERNELBASE.DLL
EncodePointer@KERNELBASE.DLL: API Node	
0x00404791:	jmp 0x00404796
0x00404796:	movl %ecx, -4(%ebp)
0x00404799:	xorl %ecx, %ebp
0x0040479b:	popl %esi
0x0040479c:	call 0x0040409f
0x0040409f:	cmpl %ecx, 0x40f048
0x004040a5:	jne 3
0x004040a7:	ret $0x0<UINT16>

0x004047a1:	movl %esp, %ebp
0x004047a3:	popl %ebp
0x004047a4:	ret

0x004047ac:	popl %ecx
0x004047ad:	ret

0x00404f0f:	movl %esi, %eax
0x00404f11:	pushl %esi
0x00404f12:	call 0x00407e82
0x00407e82:	movl %edi, %edi
0x00407e84:	pushl %ebp
0x00407e85:	movl %ebp, %esp
0x00407e87:	movl %eax, 0x8(%ebp)
0x00407e8a:	movl 0x410300, %eax
0x00407e8f:	popl %ebp
0x00407e90:	ret

0x00404f17:	pushl %esi
0x00404f18:	call 0x00408fd2
0x00408fd2:	movl %edi, %edi
0x00408fd4:	pushl %ebp
0x00408fd5:	movl %ebp, %esp
0x00408fd7:	movl %eax, 0x8(%ebp)
0x00408fda:	movl 0x41045c, %eax
0x00408fdf:	popl %ebp
0x00408fe0:	ret

0x00404f1d:	pushl %esi
0x00404f1e:	call 0x00408fe1
0x00408fe1:	movl %edi, %edi
0x00408fe3:	pushl %ebp
0x00408fe4:	movl %ebp, %esp
0x00408fe6:	movl %eax, 0x8(%ebp)
0x00408fe9:	movl 0x410460, %eax
0x00408fee:	popl %ebp
0x00408fef:	ret

0x00404f23:	pushl %esi
0x00404f24:	call 0x00408ffd
0x00408ffd:	movl %edi, %edi
0x00408fff:	pushl %ebp
0x00409000:	movl %ebp, %esp
0x00409002:	movl %eax, 0x8(%ebp)
0x00409005:	movl 0x410464, %eax
0x0040900a:	movl 0x410468, %eax
0x0040900f:	movl 0x41046c, %eax
0x00409014:	movl 0x410470, %eax
0x00409019:	popl %ebp
0x0040901a:	ret

0x00404f29:	pushl %esi
0x00404f2a:	call 0x00404640
0x00404f2f:	pushl %esi
0x00404f30:	call 0x00408bdc
0x00408bdc:	pushl $0x408ba0<UINT32>
0x00408be1:	call 0x00404719
0x00408be6:	popl %ecx
0x00408be7:	movl 0x410304, %eax
0x00408bec:	ret

0x00404f35:	pushl %esi
0x00404f36:	call 0x004092b8
0x004092b8:	movl %edi, %edi
0x004092ba:	pushl %ebp
0x004092bb:	movl %ebp, %esp
0x004092bd:	pushl %ecx
0x004092be:	movl %eax, 0x412150
0x004092c3:	cmpl %eax, $0x404640<UINT32>
0x004092c8:	je 0x0040931d
0x0040931d:	movl %esp, %ebp
0x0040931f:	popl %ebp
0x00409320:	ret

0x00404f3b:	pushl $0x404d00<UINT32>
0x00404f40:	call 0x00404719
0x00404f45:	addl %esp, $0x20<UINT8>
0x00404f48:	movl 0x40f020, %eax
0x00404f4d:	popl %esi
0x00404f4e:	ret

0x00404bb8:	pushl 0x40fb48
0x00404bbe:	call 0x00404719
0x00404bc3:	pushl 0x40fb4c
0x00404bc9:	movl 0x40fb48, %eax
0x00404bce:	call 0x00404719
0x00404bd3:	pushl 0x40fb50
0x00404bd9:	movl 0x40fb4c, %eax
0x00404bde:	call 0x00404719
0x00404be3:	pushl 0x40fb54
0x00404be9:	movl 0x40fb50, %eax
0x00404bee:	call 0x00404719
0x00404bf3:	addl %esp, $0x10<UINT8>
0x00404bf6:	movl 0x40fb54, %eax
0x00404bfb:	call 0x00408d46
0x00408d46:	movl %edi, %edi
0x00408d48:	pushl %esi
0x00408d49:	pushl %edi
0x00408d4a:	xorl %esi, %esi
0x00408d4c:	movl %edi, $0x410308<UINT32>
0x00408d51:	cmpl 0x40f7f4(,%esi,8), $0x1<UINT8>
0x00408d59:	jne 0x00408d82
0x00408d5b:	pushl $0x4000000<UINT32>
0x00408d60:	movl 0x40f7f0(,%esi,8), %edi
0x00408d67:	addl %edi, $0x18<UINT8>
0x00408d6a:	pushl $0xfa0<UINT32>
0x00408d6f:	pushl 0x40f7f0(,%esi,8)
0x00408d76:	call 0x00408fbe
0x00408fbe:	movl %edi, %edi
0x00408fc0:	pushl %ebp
0x00408fc1:	movl %ebp, %esp
0x00408fc3:	pushl 0xc(%ebp)
0x00408fc6:	pushl 0x8(%ebp)
0x00408fc9:	call 0x00408f64
0x00408f64:	pushl $0x10<UINT8>
0x00408f66:	pushl $0x40e1c8<UINT32>
0x00408f6b:	call 0x004070e8
0x004070e8:	pushl $0x405c50<UINT32>
0x004070ed:	pushl %fs:0
0x004070f4:	movl %eax, 0x10(%esp)
0x004070f8:	movl 0x10(%esp), %ebp
0x004070fc:	leal %ebp, 0x10(%esp)
0x00407100:	subl %esp, %eax
0x00407102:	pushl %ebx
0x00407103:	pushl %esi
0x00407104:	pushl %edi
0x00407105:	movl %eax, 0x40f048
0x0040710a:	xorl -4(%ebp), %eax
0x0040710d:	xorl %eax, %ebp
0x0040710f:	pushl %eax
0x00407110:	movl -24(%ebp), %esp
0x00407113:	pushl -8(%ebp)
0x00407116:	movl %eax, -4(%ebp)
0x00407119:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00407120:	movl -8(%ebp), %eax
0x00407123:	leal %eax, -16(%ebp)
0x00407126:	movl %fs:0, %eax
0x0040712c:	ret

0x00408f70:	andl -4(%ebp), $0x0<UINT8>
0x00408f74:	pushl 0xc(%ebp)
0x00408f77:	pushl 0x8(%ebp)
0x00408f7a:	call InitializeCriticalSectionAndSpinCount@KERNEL32.dll
InitializeCriticalSectionAndSpinCount@KERNEL32.dll: API Node	
0x00408f80:	jmp 0x00408fae
0x00408fae:	movl -32(%ebp), %eax
0x00408fb1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00408fb8:	call 0x0040712d
0x0040712d:	movl %ecx, -16(%ebp)
0x00407130:	movl %fs:0, %ecx
0x00407137:	popl %ecx
0x00407138:	popl %edi
0x00407139:	popl %edi
0x0040713a:	popl %esi
0x0040713b:	popl %ebx
0x0040713c:	movl %esp, %ebp
0x0040713e:	popl %ebp
0x0040713f:	pushl %ecx
0x00407140:	ret

0x00408fbd:	ret

0x00408fce:	popl %ecx
0x00408fcf:	popl %ecx
0x00408fd0:	popl %ebp
0x00408fd1:	ret

0x00408d7b:	addl %esp, $0xc<UINT8>
0x00408d7e:	testl %eax, %eax
0x00408d80:	je 12
0x00408d82:	incl %esi
0x00408d83:	cmpl %esi, $0x24<UINT8>
0x00408d86:	jl 0x00408d51
0x00408d88:	xorl %eax, %eax
0x00408d8a:	incl %eax
0x00408d8b:	popl %edi
0x00408d8c:	popl %esi
0x00408d8d:	ret

0x00404c00:	testl %eax, %eax
0x00404c02:	je -288
0x00404c08:	pushl $0x4047b0<UINT32>
0x00404c0d:	pushl 0x40fb48
0x00404c13:	call 0x0040468d
0x0040468d:	movl %edi, %edi
0x0040468f:	pushl %ebp
0x00404690:	movl %ebp, %esp
0x00404692:	pushl %ecx
0x00404693:	movl %eax, 0x40f048
0x00404698:	xorl %eax, %ebp
0x0040469a:	movl -4(%ebp), %eax
0x0040469d:	pushl %esi
0x0040469e:	pushl 0x40f014
0x004046a4:	call TlsGetValue@KERNEL32.dll
0x004046aa:	testl %eax, %eax
0x004046ac:	je 47
0x004046ae:	movl %eax, 0x40f010
0x004046b3:	cmpl %eax, $0xffffffff<UINT8>
0x004046b6:	je 0x004046dd
0x004046dd:	call 0x00404903
0x004046e2:	testl %eax, %eax
0x004046e4:	je 33
0x004046e6:	pushl $0x4011c4<UINT32>
0x004046eb:	pushl %eax
0x004046ec:	call GetProcAddress@KERNEL32.dll
0x004046f2:	movl %esi, %eax
0x004046f4:	testl %esi, %esi
0x004046f6:	je 15
0x004046f8:	pushl 0x8(%ebp)
0x004046fb:	movl %ecx, %esi
0x004046fd:	call 0x00404640
0x00404703:	call DecodePointer@KERNELBASE.DLL
DecodePointer@KERNELBASE.DLL: API Node	
0x00404705:	jmp 0x0040470a
0x0040470a:	movl %ecx, -4(%ebp)
0x0040470d:	xorl %ecx, %ebp
0x0040470f:	popl %esi
0x00404710:	call 0x0040409f
0x00404715:	movl %esp, %ebp
0x00404717:	popl %ebp
0x00404718:	ret

0x00404c18:	popl %ecx
0x00404c19:	movl %esi, %eax
0x00404c1b:	movl %ecx, %eax
0x00404c1d:	call 0x00404640
0x00404c23:	call %esi
Unknown Node: Unknown Node	
