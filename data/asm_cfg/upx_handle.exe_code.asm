0x00475810:	pusha
0x00475811:	movl %esi, $0x44d000<UINT32>
0x00475816:	leal %edi, -311296(%esi)
0x0047581c:	pushl %edi
0x0047581d:	jmp 0x0047582a
0x0047582a:	movl %ebx, (%esi)
0x0047582c:	subl %esi, $0xfffffffc<UINT8>
0x0047582f:	adcl %ebx, %ebx
0x00475831:	jb 0x00475820
0x00475820:	movb %al, (%esi)
0x00475822:	incl %esi
0x00475823:	movb (%edi), %al
0x00475825:	incl %edi
0x00475826:	addl %ebx, %ebx
0x00475828:	jne 0x00475831
0x00475833:	movl %eax, $0x1<UINT32>
0x00475838:	addl %ebx, %ebx
0x0047583a:	jne 0x00475843
0x00475843:	adcl %eax, %eax
0x00475845:	addl %ebx, %ebx
0x00475847:	jae 0x00475854
0x00475849:	jne 0x00475873
0x00475873:	xorl %ecx, %ecx
0x00475875:	subl %eax, $0x3<UINT8>
0x00475878:	jb 0x0047588b
0x0047587a:	shll %eax, $0x8<UINT8>
0x0047587d:	movb %al, (%esi)
0x0047587f:	incl %esi
0x00475880:	xorl %eax, $0xffffffff<UINT8>
0x00475883:	je 0x004758fa
0x00475885:	sarl %eax
0x00475887:	movl %ebp, %eax
0x00475889:	jmp 0x00475896
0x00475896:	jb 0x00475864
0x00475864:	addl %ebx, %ebx
0x00475866:	jne 0x0047586f
0x0047586f:	adcl %ecx, %ecx
0x00475871:	jmp 0x004758c5
0x004758c5:	cmpl %ebp, $0xfffffb00<UINT32>
0x004758cb:	adcl %ecx, $0x2<UINT8>
0x004758ce:	leal %edx, (%edi,%ebp)
0x004758d1:	cmpl %ebp, $0xfffffffc<UINT8>
0x004758d4:	jbe 0x004758e4
0x004758e4:	movl %eax, (%edx)
0x004758e6:	addl %edx, $0x4<UINT8>
0x004758e9:	movl (%edi), %eax
0x004758eb:	addl %edi, $0x4<UINT8>
0x004758ee:	subl %ecx, $0x4<UINT8>
0x004758f1:	ja 0x004758e4
0x004758f3:	addl %edi, %ecx
0x004758f5:	jmp 0x00475826
0x00475898:	incl %ecx
0x00475899:	addl %ebx, %ebx
0x0047589b:	jne 0x004758a4
0x004758a4:	jb 0x00475864
0x0047588b:	addl %ebx, %ebx
0x0047588d:	jne 0x00475896
0x004758a6:	addl %ebx, %ebx
0x004758a8:	jne 0x004758b1
0x004758b1:	adcl %ecx, %ecx
0x004758b3:	addl %ebx, %ebx
0x004758b5:	jae 0x004758a6
0x004758b7:	jne 0x004758c2
0x004758c2:	addl %ecx, $0x2<UINT8>
0x004758d6:	movb %al, (%edx)
0x004758d8:	incl %edx
0x004758d9:	movb (%edi), %al
0x004758db:	incl %edi
0x004758dc:	decl %ecx
0x004758dd:	jne 0x004758d6
0x004758df:	jmp 0x00475826
0x0047583c:	movl %ebx, (%esi)
0x0047583e:	subl %esi, $0xfffffffc<UINT8>
0x00475841:	adcl %ebx, %ebx
0x00475854:	decl %eax
0x00475855:	addl %ebx, %ebx
0x00475857:	jne 0x00475860
0x00475860:	adcl %eax, %eax
0x00475862:	jmp 0x00475838
0x0047588f:	movl %ebx, (%esi)
0x00475891:	subl %esi, $0xfffffffc<UINT8>
0x00475894:	adcl %ebx, %ebx
0x0047584b:	movl %ebx, (%esi)
0x0047584d:	subl %esi, $0xfffffffc<UINT8>
0x00475850:	adcl %ebx, %ebx
0x00475852:	jb 0x00475873
0x00475868:	movl %ebx, (%esi)
0x0047586a:	subl %esi, $0xfffffffc<UINT8>
0x0047586d:	adcl %ebx, %ebx
0x0047589d:	movl %ebx, (%esi)
0x0047589f:	subl %esi, $0xfffffffc<UINT8>
0x004758a2:	adcl %ebx, %ebx
0x00475859:	movl %ebx, (%esi)
0x0047585b:	subl %esi, $0xfffffffc<UINT8>
0x0047585e:	adcl %ebx, %ebx
0x004758aa:	movl %ebx, (%esi)
0x004758ac:	subl %esi, $0xfffffffc<UINT8>
0x004758af:	adcl %ebx, %ebx
0x004758b9:	movl %ebx, (%esi)
0x004758bb:	subl %esi, $0xfffffffc<UINT8>
0x004758be:	adcl %ebx, %ebx
0x004758c0:	jae 0x004758a6
0x004758fa:	popl %esi
0x004758fb:	movl %edi, %esi
0x004758fd:	movl %ecx, $0x7df<UINT32>
0x00475902:	movb %al, (%edi)
0x00475904:	incl %edi
0x00475905:	subb %al, $0xffffffe8<UINT8>
0x00475907:	cmpb %al, $0x1<UINT8>
0x00475909:	ja 0x00475902
0x0047590b:	cmpb (%edi), $0x5<UINT8>
0x0047590e:	jne 0x00475902
0x00475910:	movl %eax, (%edi)
0x00475912:	movb %bl, 0x4(%edi)
0x00475915:	shrw %ax, $0x8<UINT8>
0x00475919:	roll %eax, $0x10<UINT8>
0x0047591c:	xchgb %ah, %al
0x0047591e:	subl %eax, %edi
0x00475920:	subb %bl, $0xffffffe8<UINT8>
0x00475923:	addl %eax, %esi
0x00475925:	movl (%edi), %eax
0x00475927:	addl %edi, $0x5<UINT8>
0x0047592a:	movb %al, %bl
0x0047592c:	loop 0x00475907
0x0047592e:	leal %edi, 0x73000(%esi)
0x00475934:	movl %eax, (%edi)
0x00475936:	orl %eax, %eax
0x00475938:	je 0x00475976
0x0047593a:	movl %ebx, 0x4(%edi)
0x0047593d:	leal %eax, 0x755e0(%eax,%esi)
0x00475944:	addl %ebx, %esi
0x00475946:	pushl %eax
0x00475947:	addl %edi, $0x8<UINT8>
0x0047594a:	call LoadLibraryA@kernel32.dll
LoadLibraryA@kernel32.dll: API Node	
0x00475950:	xchgl %ebp, %eax
0x00475951:	movb %al, (%edi)
0x00475953:	incl %edi
0x00475954:	orb %al, %al
0x00475956:	je 0x00475934
0x00475958:	movl %ecx, %edi
0x0047595a:	pushl %edi
0x0047595b:	decl %eax
0x0047595c:	repn scasb %al, %es:(%edi)
0x0047595e:	pushl %ebp
0x0047595f:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00475965:	orl %eax, %eax
0x00475967:	je 7
0x00475969:	movl (%ebx), %eax
0x0047596b:	addl %ebx, $0x4<UINT8>
0x0047596e:	jmp 0x00475951
GetProcAddress@KERNEL32.DLL: API Node	
0x00475976:	movl %ebp, 0x75690(%esi)
0x0047597c:	leal %edi, -4096(%esi)
0x00475982:	movl %ebx, $0x1000<UINT32>
0x00475987:	pushl %eax
0x00475988:	pushl %esp
0x00475989:	pushl $0x4<UINT8>
0x0047598b:	pushl %ebx
0x0047598c:	pushl %edi
0x0047598d:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0047598f:	leal %eax, 0x20f(%edi)
0x00475995:	andb (%eax), $0x7f<UINT8>
0x00475998:	andb 0x28(%eax), $0x7f<UINT8>
0x0047599c:	popl %eax
0x0047599d:	pushl %eax
0x0047599e:	pushl %esp
0x0047599f:	pushl %eax
0x004759a0:	pushl %ebx
0x004759a1:	pushl %edi
0x004759a2:	call VirtualProtect@kernel32.dll
0x004759a4:	popl %eax
0x004759a5:	popa
0x004759a6:	leal %eax, -128(%esp)
0x004759aa:	pushl $0x0<UINT8>
0x004759ac:	cmpl %esp, %eax
0x004759ae:	jne 0x004759aa
0x004759b0:	subl %esp, $0xffffff80<UINT8>
0x004759b3:	jmp 0x00407336
0x00407336:	call 0x0040f93f
0x0040f93f:	pushl %ebp
0x0040f940:	movl %ebp, %esp
0x0040f942:	subl %esp, $0x14<UINT8>
0x0040f945:	andl -12(%ebp), $0x0<UINT8>
0x0040f949:	andl -8(%ebp), $0x0<UINT8>
0x0040f94d:	movl %eax, 0x425188
0x0040f952:	pushl %esi
0x0040f953:	pushl %edi
0x0040f954:	movl %edi, $0xbb40e64e<UINT32>
0x0040f959:	movl %esi, $0xffff0000<UINT32>
0x0040f95e:	cmpl %eax, %edi
0x0040f960:	je 0x0040f96f
0x0040f96f:	leal %eax, -12(%ebp)
0x0040f972:	pushl %eax
0x0040f973:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040f979:	movl %eax, -8(%ebp)
0x0040f97c:	xorl %eax, -12(%ebp)
0x0040f97f:	movl -4(%ebp), %eax
0x0040f982:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040f988:	xorl -4(%ebp), %eax
0x0040f98b:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040f991:	xorl -4(%ebp), %eax
0x0040f994:	leal %eax, -20(%ebp)
0x0040f997:	pushl %eax
0x0040f998:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040f99e:	movl %ecx, -16(%ebp)
0x0040f9a1:	leal %eax, -4(%ebp)
0x0040f9a4:	xorl %ecx, -20(%ebp)
0x0040f9a7:	xorl %ecx, -4(%ebp)
0x0040f9aa:	xorl %ecx, %eax
0x0040f9ac:	cmpl %ecx, %edi
0x0040f9ae:	jne 0x0040f9b7
0x0040f9b7:	testl %esi, %ecx
0x0040f9b9:	jne 0x0040f9c7
0x0040f9c7:	movl 0x425188, %ecx
0x0040f9cd:	notl %ecx
0x0040f9cf:	movl 0x42518c, %ecx
0x0040f9d5:	popl %edi
0x0040f9d6:	popl %esi
0x0040f9d7:	movl %esp, %ebp
0x0040f9d9:	popl %ebp
0x0040f9da:	ret

0x0040733b:	jmp 0x004071bb
0x004071bb:	pushl $0x14<UINT8>
0x004071bd:	pushl $0x422d50<UINT32>
0x004071c2:	call 0x004080c0
0x004080c0:	pushl $0x408120<UINT32>
0x004080c5:	pushl %fs:0
0x004080cc:	movl %eax, 0x10(%esp)
0x004080d0:	movl 0x10(%esp), %ebp
0x004080d4:	leal %ebp, 0x10(%esp)
0x004080d8:	subl %esp, %eax
0x004080da:	pushl %ebx
0x004080db:	pushl %esi
0x004080dc:	pushl %edi
0x004080dd:	movl %eax, 0x425188
0x004080e2:	xorl -4(%ebp), %eax
0x004080e5:	xorl %eax, %ebp
0x004080e7:	pushl %eax
0x004080e8:	movl -24(%ebp), %esp
0x004080eb:	pushl -8(%ebp)
0x004080ee:	movl %eax, -4(%ebp)
0x004080f1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004080f8:	movl -8(%ebp), %eax
0x004080fb:	leal %eax, -16(%ebp)
0x004080fe:	movl %fs:0, %eax
0x00408104:	ret

0x004071c7:	pushl $0x1<UINT8>
0x004071c9:	call 0x0040f8f2
0x0040f8f2:	pushl %ebp
0x0040f8f3:	movl %ebp, %esp
0x0040f8f5:	movl %eax, 0x8(%ebp)
0x0040f8f8:	movl 0x4264f8, %eax
0x0040f8fd:	popl %ebp
0x0040f8fe:	ret

0x004071ce:	popl %ecx
0x004071cf:	movl %eax, $0x5a4d<UINT32>
0x004071d4:	cmpw 0x400000, %ax
0x004071db:	je 0x004071e1
0x004071e1:	movl %eax, 0x40003c
0x004071e6:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x004071f0:	jne -21
0x004071f2:	movl %ecx, $0x10b<UINT32>
0x004071f7:	cmpw 0x400018(%eax), %cx
0x004071fe:	jne -35
0x00407200:	xorl %ebx, %ebx
0x00407202:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00407209:	jbe 9
0x0040720b:	cmpl 0x4000e8(%eax), %ebx
0x00407211:	setne %bl
0x00407214:	movl -28(%ebp), %ebx
0x00407217:	call 0x0040ae73
0x0040ae73:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x0040ae79:	xorl %ecx, %ecx
0x0040ae7b:	movl 0x426b50, %eax
0x0040ae80:	testl %eax, %eax
0x0040ae82:	setne %cl
0x0040ae85:	movl %eax, %ecx
0x0040ae87:	ret

0x0040721c:	testl %eax, %eax
0x0040721e:	jne 0x00407228
0x00407228:	call 0x0040ad5b
0x0040ad5b:	call 0x0040579a
0x0040579a:	pushl %esi
0x0040579b:	pushl $0x0<UINT8>
0x0040579d:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x004057a3:	movl %esi, %eax
0x004057a5:	pushl %esi
0x004057a6:	call 0x0040ae66
0x0040ae66:	pushl %ebp
0x0040ae67:	movl %ebp, %esp
0x0040ae69:	movl %eax, 0x8(%ebp)
0x0040ae6c:	movl 0x426b48, %eax
0x0040ae71:	popl %ebp
0x0040ae72:	ret

0x004057ab:	pushl %esi
0x004057ac:	call 0x004083d9
0x004083d9:	pushl %ebp
0x004083da:	movl %ebp, %esp
0x004083dc:	movl %eax, 0x8(%ebp)
0x004083df:	movl 0x4263e4, %eax
0x004083e4:	popl %ebp
0x004083e5:	ret

0x004057b1:	pushl %esi
0x004057b2:	call 0x0040b435
0x0040b435:	pushl %ebp
0x0040b436:	movl %ebp, %esp
0x0040b438:	movl %eax, 0x8(%ebp)
0x0040b43b:	movl 0x426e7c, %eax
0x0040b440:	popl %ebp
0x0040b441:	ret

0x004057b7:	pushl %esi
0x004057b8:	call 0x0040b44f
0x0040b44f:	pushl %ebp
0x0040b450:	movl %ebp, %esp
0x0040b452:	movl %eax, 0x8(%ebp)
0x0040b455:	movl 0x426e80, %eax
0x0040b45a:	movl 0x426e84, %eax
0x0040b45f:	movl 0x426e88, %eax
0x0040b464:	movl 0x426e8c, %eax
0x0040b469:	popl %ebp
0x0040b46a:	ret

0x004057bd:	pushl %esi
0x004057be:	call 0x0040b424
0x0040b424:	pushl $0x40b3f0<UINT32>
0x0040b429:	call EncodePointer@KERNEL32.DLL
0x0040b42f:	movl 0x426e78, %eax
0x0040b434:	ret

0x004057c3:	pushl %esi
0x004057c4:	call 0x0040b660
0x0040b660:	pushl %ebp
0x0040b661:	movl %ebp, %esp
0x0040b663:	movl %eax, 0x8(%ebp)
0x0040b666:	movl 0x426e94, %eax
0x0040b66b:	popl %ebp
0x0040b66c:	ret

0x004057c9:	addl %esp, $0x18<UINT8>
0x004057cc:	popl %esi
0x004057cd:	jmp 0x00409ac9
0x00409ac9:	pushl %esi
0x00409aca:	pushl %edi
0x00409acb:	pushl $0x41e394<UINT32>
0x00409ad0:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00409ad6:	movl %esi, 0x4170dc
0x00409adc:	movl %edi, %eax
0x00409ade:	pushl $0x41eeb0<UINT32>
0x00409ae3:	pushl %edi
0x00409ae4:	call GetProcAddress@KERNEL32.DLL
0x00409ae6:	xorl %eax, 0x425188
0x00409aec:	pushl $0x41eebc<UINT32>
0x00409af1:	pushl %edi
0x00409af2:	movl 0x4337c0, %eax
0x00409af7:	call GetProcAddress@KERNEL32.DLL
0x00409af9:	xorl %eax, 0x425188
0x00409aff:	pushl $0x41eec4<UINT32>
0x00409b04:	pushl %edi
0x00409b05:	movl 0x4337c4, %eax
0x00409b0a:	call GetProcAddress@KERNEL32.DLL
0x00409b0c:	xorl %eax, 0x425188
0x00409b12:	pushl $0x41eed0<UINT32>
0x00409b17:	pushl %edi
0x00409b18:	movl 0x4337c8, %eax
0x00409b1d:	call GetProcAddress@KERNEL32.DLL
0x00409b1f:	xorl %eax, 0x425188
0x00409b25:	pushl $0x41eedc<UINT32>
0x00409b2a:	pushl %edi
0x00409b2b:	movl 0x4337cc, %eax
0x00409b30:	call GetProcAddress@KERNEL32.DLL
0x00409b32:	xorl %eax, 0x425188
0x00409b38:	pushl $0x41eef8<UINT32>
0x00409b3d:	pushl %edi
0x00409b3e:	movl 0x4337d0, %eax
0x00409b43:	call GetProcAddress@KERNEL32.DLL
0x00409b45:	xorl %eax, 0x425188
0x00409b4b:	pushl $0x41ef08<UINT32>
0x00409b50:	pushl %edi
0x00409b51:	movl 0x4337d4, %eax
0x00409b56:	call GetProcAddress@KERNEL32.DLL
0x00409b58:	xorl %eax, 0x425188
0x00409b5e:	pushl $0x41ef1c<UINT32>
0x00409b63:	pushl %edi
0x00409b64:	movl 0x4337d8, %eax
0x00409b69:	call GetProcAddress@KERNEL32.DLL
0x00409b6b:	xorl %eax, 0x425188
0x00409b71:	pushl $0x41ef34<UINT32>
0x00409b76:	pushl %edi
0x00409b77:	movl 0x4337dc, %eax
0x00409b7c:	call GetProcAddress@KERNEL32.DLL
0x00409b7e:	xorl %eax, 0x425188
0x00409b84:	pushl $0x41ef4c<UINT32>
0x00409b89:	pushl %edi
0x00409b8a:	movl 0x4337e0, %eax
0x00409b8f:	call GetProcAddress@KERNEL32.DLL
0x00409b91:	xorl %eax, 0x425188
0x00409b97:	pushl $0x41ef60<UINT32>
0x00409b9c:	pushl %edi
0x00409b9d:	movl 0x4337e4, %eax
0x00409ba2:	call GetProcAddress@KERNEL32.DLL
0x00409ba4:	xorl %eax, 0x425188
0x00409baa:	pushl $0x41ef80<UINT32>
0x00409baf:	pushl %edi
0x00409bb0:	movl 0x4337e8, %eax
0x00409bb5:	call GetProcAddress@KERNEL32.DLL
0x00409bb7:	xorl %eax, 0x425188
0x00409bbd:	pushl $0x41ef98<UINT32>
0x00409bc2:	pushl %edi
0x00409bc3:	movl 0x4337ec, %eax
0x00409bc8:	call GetProcAddress@KERNEL32.DLL
0x00409bca:	xorl %eax, 0x425188
0x00409bd0:	pushl $0x41efb0<UINT32>
0x00409bd5:	pushl %edi
0x00409bd6:	movl 0x4337f0, %eax
0x00409bdb:	call GetProcAddress@KERNEL32.DLL
0x00409bdd:	xorl %eax, 0x425188
0x00409be3:	pushl $0x41efc4<UINT32>
0x00409be8:	pushl %edi
0x00409be9:	movl 0x4337f4, %eax
0x00409bee:	call GetProcAddress@KERNEL32.DLL
0x00409bf0:	xorl %eax, 0x425188
0x00409bf6:	movl 0x4337f8, %eax
0x00409bfb:	pushl $0x41efd8<UINT32>
0x00409c00:	pushl %edi
0x00409c01:	call GetProcAddress@KERNEL32.DLL
0x00409c03:	xorl %eax, 0x425188
0x00409c09:	pushl $0x41eff4<UINT32>
0x00409c0e:	pushl %edi
0x00409c0f:	movl 0x4337fc, %eax
0x00409c14:	call GetProcAddress@KERNEL32.DLL
0x00409c16:	xorl %eax, 0x425188
0x00409c1c:	pushl $0x41f014<UINT32>
0x00409c21:	pushl %edi
0x00409c22:	movl 0x433800, %eax
0x00409c27:	call GetProcAddress@KERNEL32.DLL
0x00409c29:	xorl %eax, 0x425188
0x00409c2f:	pushl $0x41f030<UINT32>
0x00409c34:	pushl %edi
0x00409c35:	movl 0x433804, %eax
0x00409c3a:	call GetProcAddress@KERNEL32.DLL
0x00409c3c:	xorl %eax, 0x425188
0x00409c42:	pushl $0x41f050<UINT32>
0x00409c47:	pushl %edi
0x00409c48:	movl 0x433808, %eax
0x00409c4d:	call GetProcAddress@KERNEL32.DLL
0x00409c4f:	xorl %eax, 0x425188
0x00409c55:	pushl $0x41f064<UINT32>
0x00409c5a:	pushl %edi
0x00409c5b:	movl 0x43380c, %eax
0x00409c60:	call GetProcAddress@KERNEL32.DLL
0x00409c62:	xorl %eax, 0x425188
0x00409c68:	pushl $0x41f080<UINT32>
0x00409c6d:	pushl %edi
0x00409c6e:	movl 0x433810, %eax
0x00409c73:	call GetProcAddress@KERNEL32.DLL
0x00409c75:	xorl %eax, 0x425188
0x00409c7b:	pushl $0x41f094<UINT32>
0x00409c80:	pushl %edi
0x00409c81:	movl 0x433818, %eax
0x00409c86:	call GetProcAddress@KERNEL32.DLL
0x00409c88:	xorl %eax, 0x425188
0x00409c8e:	pushl $0x41f0a4<UINT32>
0x00409c93:	pushl %edi
0x00409c94:	movl 0x433814, %eax
0x00409c99:	call GetProcAddress@KERNEL32.DLL
0x00409c9b:	xorl %eax, 0x425188
0x00409ca1:	pushl $0x41f0b4<UINT32>
0x00409ca6:	pushl %edi
0x00409ca7:	movl 0x43381c, %eax
0x00409cac:	call GetProcAddress@KERNEL32.DLL
0x00409cae:	xorl %eax, 0x425188
0x00409cb4:	pushl $0x41f0c4<UINT32>
0x00409cb9:	pushl %edi
0x00409cba:	movl 0x433820, %eax
0x00409cbf:	call GetProcAddress@KERNEL32.DLL
0x00409cc1:	xorl %eax, 0x425188
0x00409cc7:	pushl $0x41f0d4<UINT32>
0x00409ccc:	pushl %edi
0x00409ccd:	movl 0x433824, %eax
0x00409cd2:	call GetProcAddress@KERNEL32.DLL
0x00409cd4:	xorl %eax, 0x425188
0x00409cda:	pushl $0x41f0f0<UINT32>
0x00409cdf:	pushl %edi
0x00409ce0:	movl 0x433828, %eax
0x00409ce5:	call GetProcAddress@KERNEL32.DLL
0x00409ce7:	xorl %eax, 0x425188
0x00409ced:	pushl $0x41f104<UINT32>
0x00409cf2:	pushl %edi
0x00409cf3:	movl 0x43382c, %eax
0x00409cf8:	call GetProcAddress@KERNEL32.DLL
0x00409cfa:	xorl %eax, 0x425188
0x00409d00:	pushl $0x41f114<UINT32>
0x00409d05:	pushl %edi
0x00409d06:	movl 0x433830, %eax
0x00409d0b:	call GetProcAddress@KERNEL32.DLL
0x00409d0d:	xorl %eax, 0x425188
0x00409d13:	pushl $0x41f128<UINT32>
0x00409d18:	pushl %edi
0x00409d19:	movl 0x433834, %eax
0x00409d1e:	call GetProcAddress@KERNEL32.DLL
0x00409d20:	xorl %eax, 0x425188
0x00409d26:	movl 0x433838, %eax
0x00409d2b:	pushl $0x41f138<UINT32>
0x00409d30:	pushl %edi
0x00409d31:	call GetProcAddress@KERNEL32.DLL
0x00409d33:	xorl %eax, 0x425188
0x00409d39:	pushl $0x41f158<UINT32>
0x00409d3e:	pushl %edi
0x00409d3f:	movl 0x43383c, %eax
0x00409d44:	call GetProcAddress@KERNEL32.DLL
0x00409d46:	xorl %eax, 0x425188
0x00409d4c:	popl %edi
0x00409d4d:	movl 0x433840, %eax
0x00409d52:	popl %esi
0x00409d53:	ret

0x0040ad60:	call 0x0040750e
0x0040750e:	pushl %esi
0x0040750f:	pushl %edi
0x00407510:	movl %esi, $0x4251a0<UINT32>
0x00407515:	movl %edi, $0x426290<UINT32>
0x0040751a:	cmpl 0x4(%esi), $0x1<UINT8>
0x0040751e:	jne 22
0x00407520:	pushl $0x0<UINT8>
0x00407522:	movl (%esi), %edi
0x00407524:	addl %edi, $0x18<UINT8>
0x00407527:	pushl $0xfa0<UINT32>
0x0040752c:	pushl (%esi)
0x0040752e:	call 0x00409a5b
0x00409a5b:	pushl %ebp
0x00409a5c:	movl %ebp, %esp
0x00409a5e:	movl %eax, 0x4337d0
0x00409a63:	xorl %eax, 0x425188
0x00409a69:	je 13
0x00409a6b:	pushl 0x10(%ebp)
0x00409a6e:	pushl 0xc(%ebp)
0x00409a71:	pushl 0x8(%ebp)
0x00409a74:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x00409a76:	popl %ebp
0x00409a77:	ret

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
