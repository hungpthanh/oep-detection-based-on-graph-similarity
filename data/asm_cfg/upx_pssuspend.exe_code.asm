0x0044abc0:	pusha
0x0044abc1:	movl %esi, $0x434000<UINT32>
0x0044abc6:	leal %edi, -208896(%esi)
0x0044abcc:	pushl %edi
0x0044abcd:	jmp 0x0044abda
0x0044abda:	movl %ebx, (%esi)
0x0044abdc:	subl %esi, $0xfffffffc<UINT8>
0x0044abdf:	adcl %ebx, %ebx
0x0044abe1:	jb 0x0044abd0
0x0044abd0:	movb %al, (%esi)
0x0044abd2:	incl %esi
0x0044abd3:	movb (%edi), %al
0x0044abd5:	incl %edi
0x0044abd6:	addl %ebx, %ebx
0x0044abd8:	jne 0x0044abe1
0x0044abe3:	movl %eax, $0x1<UINT32>
0x0044abe8:	addl %ebx, %ebx
0x0044abea:	jne 0x0044abf3
0x0044abf3:	adcl %eax, %eax
0x0044abf5:	addl %ebx, %ebx
0x0044abf7:	jae 0x0044ac04
0x0044abf9:	jne 0x0044ac23
0x0044ac23:	xorl %ecx, %ecx
0x0044ac25:	subl %eax, $0x3<UINT8>
0x0044ac28:	jb 0x0044ac3b
0x0044ac2a:	shll %eax, $0x8<UINT8>
0x0044ac2d:	movb %al, (%esi)
0x0044ac2f:	incl %esi
0x0044ac30:	xorl %eax, $0xffffffff<UINT8>
0x0044ac33:	je 0x0044acaa
0x0044ac35:	sarl %eax
0x0044ac37:	movl %ebp, %eax
0x0044ac39:	jmp 0x0044ac46
0x0044ac46:	jb 0x0044ac14
0x0044ac14:	addl %ebx, %ebx
0x0044ac16:	jne 0x0044ac1f
0x0044ac1f:	adcl %ecx, %ecx
0x0044ac21:	jmp 0x0044ac75
0x0044ac75:	cmpl %ebp, $0xfffffb00<UINT32>
0x0044ac7b:	adcl %ecx, $0x2<UINT8>
0x0044ac7e:	leal %edx, (%edi,%ebp)
0x0044ac81:	cmpl %ebp, $0xfffffffc<UINT8>
0x0044ac84:	jbe 0x0044ac94
0x0044ac94:	movl %eax, (%edx)
0x0044ac96:	addl %edx, $0x4<UINT8>
0x0044ac99:	movl (%edi), %eax
0x0044ac9b:	addl %edi, $0x4<UINT8>
0x0044ac9e:	subl %ecx, $0x4<UINT8>
0x0044aca1:	ja 0x0044ac94
0x0044aca3:	addl %edi, %ecx
0x0044aca5:	jmp 0x0044abd6
0x0044ac86:	movb %al, (%edx)
0x0044ac88:	incl %edx
0x0044ac89:	movb (%edi), %al
0x0044ac8b:	incl %edi
0x0044ac8c:	decl %ecx
0x0044ac8d:	jne 0x0044ac86
0x0044ac8f:	jmp 0x0044abd6
0x0044ac48:	incl %ecx
0x0044ac49:	addl %ebx, %ebx
0x0044ac4b:	jne 0x0044ac54
0x0044ac54:	jb 0x0044ac14
0x0044ac56:	addl %ebx, %ebx
0x0044ac58:	jne 0x0044ac61
0x0044ac61:	adcl %ecx, %ecx
0x0044ac63:	addl %ebx, %ebx
0x0044ac65:	jae 0x0044ac56
0x0044ac67:	jne 0x0044ac72
0x0044ac72:	addl %ecx, $0x2<UINT8>
0x0044ac18:	movl %ebx, (%esi)
0x0044ac1a:	subl %esi, $0xfffffffc<UINT8>
0x0044ac1d:	adcl %ebx, %ebx
0x0044abec:	movl %ebx, (%esi)
0x0044abee:	subl %esi, $0xfffffffc<UINT8>
0x0044abf1:	adcl %ebx, %ebx
0x0044ac04:	decl %eax
0x0044ac05:	addl %ebx, %ebx
0x0044ac07:	jne 0x0044ac10
0x0044ac10:	adcl %eax, %eax
0x0044ac12:	jmp 0x0044abe8
0x0044ac09:	movl %ebx, (%esi)
0x0044ac0b:	subl %esi, $0xfffffffc<UINT8>
0x0044ac0e:	adcl %ebx, %ebx
0x0044ac3b:	addl %ebx, %ebx
0x0044ac3d:	jne 0x0044ac46
0x0044ac5a:	movl %ebx, (%esi)
0x0044ac5c:	subl %esi, $0xfffffffc<UINT8>
0x0044ac5f:	adcl %ebx, %ebx
0x0044ac4d:	movl %ebx, (%esi)
0x0044ac4f:	subl %esi, $0xfffffffc<UINT8>
0x0044ac52:	adcl %ebx, %ebx
0x0044ac3f:	movl %ebx, (%esi)
0x0044ac41:	subl %esi, $0xfffffffc<UINT8>
0x0044ac44:	adcl %ebx, %ebx
0x0044ac69:	movl %ebx, (%esi)
0x0044ac6b:	subl %esi, $0xfffffffc<UINT8>
0x0044ac6e:	adcl %ebx, %ebx
0x0044ac70:	jae 0x0044ac56
0x0044abfb:	movl %ebx, (%esi)
0x0044abfd:	subl %esi, $0xfffffffc<UINT8>
0x0044ac00:	adcl %ebx, %ebx
0x0044ac02:	jb 0x0044ac23
0x0044acaa:	popl %esi
0x0044acab:	movl %edi, %esi
0x0044acad:	movl %ecx, $0x795<UINT32>
0x0044acb2:	movb %al, (%edi)
0x0044acb4:	incl %edi
0x0044acb5:	subb %al, $0xffffffe8<UINT8>
0x0044acb7:	cmpb %al, $0x1<UINT8>
0x0044acb9:	ja 0x0044acb2
0x0044acbb:	cmpb (%edi), $0x5<UINT8>
0x0044acbe:	jne 0x0044acb2
0x0044acc0:	movl %eax, (%edi)
0x0044acc2:	movb %bl, 0x4(%edi)
0x0044acc5:	shrw %ax, $0x8<UINT8>
0x0044acc9:	roll %eax, $0x10<UINT8>
0x0044accc:	xchgb %ah, %al
0x0044acce:	subl %eax, %edi
0x0044acd0:	subb %bl, $0xffffffe8<UINT8>
0x0044acd3:	addl %eax, %esi
0x0044acd5:	movl (%edi), %eax
0x0044acd7:	addl %edi, $0x5<UINT8>
0x0044acda:	movb %al, %bl
0x0044acdc:	loop 0x0044acb7
0x0044acde:	leal %edi, 0x47000(%esi)
0x0044ace4:	movl %eax, (%edi)
0x0044ace6:	orl %eax, %eax
0x0044ace8:	je 0x0044ad2f
0x0044acea:	movl %ebx, 0x4(%edi)
0x0044aced:	leal %eax, 0x4a614(%eax,%esi)
0x0044acf4:	addl %ebx, %esi
0x0044acf6:	pushl %eax
0x0044acf7:	addl %edi, $0x8<UINT8>
0x0044acfa:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x0044ad00:	xchgl %ebp, %eax
0x0044ad01:	movb %al, (%edi)
0x0044ad03:	incl %edi
0x0044ad04:	orb %al, %al
0x0044ad06:	je 0x0044ace4
0x0044ad08:	movl %ecx, %edi
0x0044ad0a:	jns 0x0044ad13
0x0044ad13:	pushl %edi
0x0044ad14:	decl %eax
0x0044ad15:	repn scasb %al, %es:(%edi)
0x0044ad17:	pushl %ebp
0x0044ad18:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0044ad1e:	orl %eax, %eax
0x0044ad20:	je 7
0x0044ad22:	movl (%ebx), %eax
0x0044ad24:	addl %ebx, $0x4<UINT8>
0x0044ad27:	jmp 0x0044ad01
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x0044ad0c:	movzwl %eax, (%edi)
0x0044ad0f:	incl %edi
0x0044ad10:	pushl %eax
0x0044ad11:	incl %edi
0x0044ad12:	movl %ecx, $0xaef24857<UINT32>
0x0044ad2f:	addl %edi, $0x4<UINT8>
0x0044ad32:	leal %ebx, -4(%esi)
0x0044ad35:	xorl %eax, %eax
0x0044ad37:	movb %al, (%edi)
0x0044ad39:	incl %edi
0x0044ad3a:	orl %eax, %eax
0x0044ad3c:	je 0x0044ad60
0x0044ad3e:	cmpb %al, $0xffffffef<UINT8>
0x0044ad40:	ja 0x0044ad53
0x0044ad42:	addl %ebx, %eax
0x0044ad44:	movl %eax, (%ebx)
0x0044ad46:	xchgb %ah, %al
0x0044ad48:	roll %eax, $0x10<UINT8>
0x0044ad4b:	xchgb %ah, %al
0x0044ad4d:	addl %eax, %esi
0x0044ad4f:	movl (%ebx), %eax
0x0044ad51:	jmp 0x0044ad35
0x0044ad53:	andb %al, $0xf<UINT8>
0x0044ad55:	shll %eax, $0x10<UINT8>
0x0044ad58:	movw %ax, (%edi)
0x0044ad5b:	addl %edi, $0x2<UINT8>
0x0044ad5e:	jmp 0x0044ad42
0x0044ad60:	movl %ebp, 0x4a6bc(%esi)
0x0044ad66:	leal %edi, -4096(%esi)
0x0044ad6c:	movl %ebx, $0x1000<UINT32>
0x0044ad71:	pushl %eax
0x0044ad72:	pushl %esp
0x0044ad73:	pushl $0x4<UINT8>
0x0044ad75:	pushl %ebx
0x0044ad76:	pushl %edi
0x0044ad77:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0044ad79:	leal %eax, 0x20f(%edi)
0x0044ad7f:	andb (%eax), $0x7f<UINT8>
0x0044ad82:	andb 0x28(%eax), $0x7f<UINT8>
0x0044ad86:	popl %eax
0x0044ad87:	pushl %eax
0x0044ad88:	pushl %esp
0x0044ad89:	pushl %eax
0x0044ad8a:	pushl %ebx
0x0044ad8b:	pushl %edi
0x0044ad8c:	call VirtualProtect@kernel32.dll
0x0044ad8e:	popl %eax
0x0044ad8f:	popa
0x0044ad90:	leal %eax, -128(%esp)
0x0044ad94:	pushl $0x0<UINT8>
0x0044ad96:	cmpl %esp, %eax
0x0044ad98:	jne 0x0044ad94
0x0044ad9a:	subl %esp, $0xffffff80<UINT8>
0x0044ad9d:	jmp 0x004074fe
0x004074fe:	call 0x0040de85
0x0040de85:	pushl %ebp
0x0040de86:	movl %ebp, %esp
0x0040de88:	subl %esp, $0x14<UINT8>
0x0040de8b:	andl -12(%ebp), $0x0<UINT8>
0x0040de8f:	andl -8(%ebp), $0x0<UINT8>
0x0040de93:	movl %eax, 0x4230d0
0x0040de98:	pushl %esi
0x0040de99:	pushl %edi
0x0040de9a:	movl %edi, $0xbb40e64e<UINT32>
0x0040de9f:	movl %esi, $0xffff0000<UINT32>
0x0040dea4:	cmpl %eax, %edi
0x0040dea6:	je 0x0040deb5
0x0040deb5:	leal %eax, -12(%ebp)
0x0040deb8:	pushl %eax
0x0040deb9:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040debf:	movl %eax, -8(%ebp)
0x0040dec2:	xorl %eax, -12(%ebp)
0x0040dec5:	movl -4(%ebp), %eax
0x0040dec8:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040dece:	xorl -4(%ebp), %eax
0x0040ded1:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040ded7:	xorl -4(%ebp), %eax
0x0040deda:	leal %eax, -20(%ebp)
0x0040dedd:	pushl %eax
0x0040dede:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040dee4:	movl %ecx, -16(%ebp)
0x0040dee7:	leal %eax, -4(%ebp)
0x0040deea:	xorl %ecx, -20(%ebp)
0x0040deed:	xorl %ecx, -4(%ebp)
0x0040def0:	xorl %ecx, %eax
0x0040def2:	cmpl %ecx, %edi
0x0040def4:	jne 0x0040defd
0x0040defd:	testl %esi, %ecx
0x0040deff:	jne 0x0040df0d
0x0040df0d:	movl 0x4230d0, %ecx
0x0040df13:	notl %ecx
0x0040df15:	movl 0x4230d4, %ecx
0x0040df1b:	popl %edi
0x0040df1c:	popl %esi
0x0040df1d:	movl %esp, %ebp
0x0040df1f:	popl %ebp
0x0040df20:	ret

0x00407503:	jmp 0x00407383
0x00407383:	pushl $0x14<UINT8>
0x00407385:	pushl $0x421230<UINT32>
0x0040738a:	call 0x00409380
0x00409380:	pushl $0x406d10<UINT32>
0x00409385:	pushl %fs:0
0x0040938c:	movl %eax, 0x10(%esp)
0x00409390:	movl 0x10(%esp), %ebp
0x00409394:	leal %ebp, 0x10(%esp)
0x00409398:	subl %esp, %eax
0x0040939a:	pushl %ebx
0x0040939b:	pushl %esi
0x0040939c:	pushl %edi
0x0040939d:	movl %eax, 0x4230d0
0x004093a2:	xorl -4(%ebp), %eax
0x004093a5:	xorl %eax, %ebp
0x004093a7:	pushl %eax
0x004093a8:	movl -24(%ebp), %esp
0x004093ab:	pushl -8(%ebp)
0x004093ae:	movl %eax, -4(%ebp)
0x004093b1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004093b8:	movl -8(%ebp), %eax
0x004093bb:	leal %eax, -16(%ebp)
0x004093be:	movl %fs:0, %eax
0x004093c4:	ret

0x0040738f:	pushl $0x1<UINT8>
0x00407391:	call 0x0040de38
0x0040de38:	pushl %ebp
0x0040de39:	movl %ebp, %esp
0x0040de3b:	movl %eax, 0x8(%ebp)
0x0040de3e:	movl 0x424a18, %eax
0x0040de43:	popl %ebp
0x0040de44:	ret

0x00407396:	popl %ecx
0x00407397:	movl %eax, $0x5a4d<UINT32>
0x0040739c:	cmpw 0x400000, %ax
0x004073a3:	je 0x004073a9
0x004073a9:	movl %eax, 0x40003c
0x004073ae:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x004073b8:	jne -21
0x004073ba:	movl %ecx, $0x10b<UINT32>
0x004073bf:	cmpw 0x400018(%eax), %cx
0x004073c6:	jne -35
0x004073c8:	xorl %ebx, %ebx
0x004073ca:	cmpl 0x400074(%eax), $0xe<UINT8>
0x004073d1:	jbe 9
0x004073d3:	cmpl 0x4000e8(%eax), %ebx
0x004073d9:	setne %bl
0x004073dc:	movl -28(%ebp), %ebx
0x004073df:	call 0x004094b0
0x004094b0:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x004094b6:	xorl %ecx, %ecx
0x004094b8:	movl 0x425078, %eax
0x004094bd:	testl %eax, %eax
0x004094bf:	setne %cl
0x004094c2:	movl %eax, %ecx
0x004094c4:	ret

0x004073e4:	testl %eax, %eax
0x004073e6:	jne 0x004073f0
0x004073f0:	call 0x00408446
0x00408446:	call 0x00404b54
0x00404b54:	pushl %esi
0x00404b55:	pushl $0x0<UINT8>
0x00404b57:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00404b5d:	movl %esi, %eax
0x00404b5f:	pushl %esi
0x00404b60:	call 0x00409134
0x00409134:	pushl %ebp
0x00409135:	movl %ebp, %esp
0x00409137:	movl %eax, 0x8(%ebp)
0x0040913a:	movl 0x425050, %eax
0x0040913f:	popl %ebp
0x00409140:	ret

0x00404b65:	pushl %esi
0x00404b66:	call 0x0040762d
0x0040762d:	pushl %ebp
0x0040762e:	movl %ebp, %esp
0x00407630:	movl %eax, 0x8(%ebp)
0x00407633:	movl 0x4248a0, %eax
0x00407638:	popl %ebp
0x00407639:	ret

0x00404b6b:	pushl %esi
0x00404b6c:	call 0x00409141
0x00409141:	pushl %ebp
0x00409142:	movl %ebp, %esp
0x00409144:	movl %eax, 0x8(%ebp)
0x00409147:	movl 0x425054, %eax
0x0040914c:	popl %ebp
0x0040914d:	ret

0x00404b71:	pushl %esi
0x00404b72:	call 0x0040915b
0x0040915b:	pushl %ebp
0x0040915c:	movl %ebp, %esp
0x0040915e:	movl %eax, 0x8(%ebp)
0x00409161:	movl 0x425058, %eax
0x00409166:	movl 0x42505c, %eax
0x0040916b:	movl 0x425060, %eax
0x00409170:	movl 0x425064, %eax
0x00409175:	popl %ebp
0x00409176:	ret

0x00404b77:	pushl %esi
0x00404b78:	call 0x004090fd
0x004090fd:	pushl $0x4090c9<UINT32>
0x00409102:	call EncodePointer@KERNEL32.DLL
0x00409108:	movl 0x42504c, %eax
0x0040910d:	ret

0x00404b7d:	pushl %esi
0x00404b7e:	call 0x0040936c
0x0040936c:	pushl %ebp
0x0040936d:	movl %ebp, %esp
0x0040936f:	movl %eax, 0x8(%ebp)
0x00409372:	movl 0x42506c, %eax
0x00409377:	popl %ebp
0x00409378:	ret

0x00404b83:	addl %esp, $0x18<UINT8>
0x00404b86:	popl %esi
0x00404b87:	jmp 0x0040885e
0x0040885e:	pushl %esi
0x0040885f:	pushl %edi
0x00408860:	pushl $0x41d778<UINT32>
0x00408865:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0040886b:	movl %esi, 0x4160dc
0x00408871:	movl %edi, %eax
0x00408873:	pushl $0x41d794<UINT32>
0x00408878:	pushl %edi
0x00408879:	call GetProcAddress@KERNEL32.DLL
0x0040887b:	xorl %eax, 0x4230d0
0x00408881:	pushl $0x41d7a0<UINT32>
0x00408886:	pushl %edi
0x00408887:	movl 0x425660, %eax
0x0040888c:	call GetProcAddress@KERNEL32.DLL
0x0040888e:	xorl %eax, 0x4230d0
0x00408894:	pushl $0x41d7a8<UINT32>
0x00408899:	pushl %edi
0x0040889a:	movl 0x425664, %eax
0x0040889f:	call GetProcAddress@KERNEL32.DLL
0x004088a1:	xorl %eax, 0x4230d0
0x004088a7:	pushl $0x41d7b4<UINT32>
0x004088ac:	pushl %edi
0x004088ad:	movl 0x425668, %eax
0x004088b2:	call GetProcAddress@KERNEL32.DLL
0x004088b4:	xorl %eax, 0x4230d0
0x004088ba:	pushl $0x41d7c0<UINT32>
0x004088bf:	pushl %edi
0x004088c0:	movl 0x42566c, %eax
0x004088c5:	call GetProcAddress@KERNEL32.DLL
0x004088c7:	xorl %eax, 0x4230d0
0x004088cd:	pushl $0x41d7dc<UINT32>
0x004088d2:	pushl %edi
0x004088d3:	movl 0x425670, %eax
0x004088d8:	call GetProcAddress@KERNEL32.DLL
0x004088da:	xorl %eax, 0x4230d0
0x004088e0:	pushl $0x41d7ec<UINT32>
0x004088e5:	pushl %edi
0x004088e6:	movl 0x425674, %eax
0x004088eb:	call GetProcAddress@KERNEL32.DLL
0x004088ed:	xorl %eax, 0x4230d0
0x004088f3:	pushl $0x41d800<UINT32>
0x004088f8:	pushl %edi
0x004088f9:	movl 0x425678, %eax
0x004088fe:	call GetProcAddress@KERNEL32.DLL
0x00408900:	xorl %eax, 0x4230d0
0x00408906:	pushl $0x41d818<UINT32>
0x0040890b:	pushl %edi
0x0040890c:	movl 0x42567c, %eax
0x00408911:	call GetProcAddress@KERNEL32.DLL
0x00408913:	xorl %eax, 0x4230d0
0x00408919:	pushl $0x41d830<UINT32>
0x0040891e:	pushl %edi
0x0040891f:	movl 0x425680, %eax
0x00408924:	call GetProcAddress@KERNEL32.DLL
0x00408926:	xorl %eax, 0x4230d0
0x0040892c:	pushl $0x41d844<UINT32>
0x00408931:	pushl %edi
0x00408932:	movl 0x425684, %eax
0x00408937:	call GetProcAddress@KERNEL32.DLL
0x00408939:	xorl %eax, 0x4230d0
0x0040893f:	pushl $0x41d864<UINT32>
0x00408944:	pushl %edi
0x00408945:	movl 0x425688, %eax
0x0040894a:	call GetProcAddress@KERNEL32.DLL
0x0040894c:	xorl %eax, 0x4230d0
0x00408952:	pushl $0x41d87c<UINT32>
0x00408957:	pushl %edi
0x00408958:	movl 0x42568c, %eax
0x0040895d:	call GetProcAddress@KERNEL32.DLL
0x0040895f:	xorl %eax, 0x4230d0
0x00408965:	pushl $0x41d894<UINT32>
0x0040896a:	pushl %edi
0x0040896b:	movl 0x425690, %eax
0x00408970:	call GetProcAddress@KERNEL32.DLL
0x00408972:	xorl %eax, 0x4230d0
0x00408978:	pushl $0x41d8a8<UINT32>
0x0040897d:	pushl %edi
0x0040897e:	movl 0x425694, %eax
0x00408983:	call GetProcAddress@KERNEL32.DLL
0x00408985:	xorl %eax, 0x4230d0
0x0040898b:	movl 0x425698, %eax
0x00408990:	pushl $0x41d8bc<UINT32>
0x00408995:	pushl %edi
0x00408996:	call GetProcAddress@KERNEL32.DLL
0x00408998:	xorl %eax, 0x4230d0
0x0040899e:	pushl $0x41d8d8<UINT32>
0x004089a3:	pushl %edi
0x004089a4:	movl 0x42569c, %eax
0x004089a9:	call GetProcAddress@KERNEL32.DLL
0x004089ab:	xorl %eax, 0x4230d0
0x004089b1:	pushl $0x41d8f8<UINT32>
0x004089b6:	pushl %edi
0x004089b7:	movl 0x4256a0, %eax
0x004089bc:	call GetProcAddress@KERNEL32.DLL
0x004089be:	xorl %eax, 0x4230d0
0x004089c4:	pushl $0x41d914<UINT32>
0x004089c9:	pushl %edi
0x004089ca:	movl 0x4256a4, %eax
0x004089cf:	call GetProcAddress@KERNEL32.DLL
0x004089d1:	xorl %eax, 0x4230d0
0x004089d7:	pushl $0x41d934<UINT32>
0x004089dc:	pushl %edi
0x004089dd:	movl 0x4256a8, %eax
0x004089e2:	call GetProcAddress@KERNEL32.DLL
0x004089e4:	xorl %eax, 0x4230d0
0x004089ea:	pushl $0x41d948<UINT32>
0x004089ef:	pushl %edi
0x004089f0:	movl 0x4256ac, %eax
0x004089f5:	call GetProcAddress@KERNEL32.DLL
0x004089f7:	xorl %eax, 0x4230d0
0x004089fd:	pushl $0x41d964<UINT32>
0x00408a02:	pushl %edi
0x00408a03:	movl 0x4256b0, %eax
0x00408a08:	call GetProcAddress@KERNEL32.DLL
0x00408a0a:	xorl %eax, 0x4230d0
0x00408a10:	pushl $0x41d978<UINT32>
0x00408a15:	pushl %edi
0x00408a16:	movl 0x4256b8, %eax
0x00408a1b:	call GetProcAddress@KERNEL32.DLL
0x00408a1d:	xorl %eax, 0x4230d0
0x00408a23:	pushl $0x41d988<UINT32>
0x00408a28:	pushl %edi
0x00408a29:	movl 0x4256b4, %eax
0x00408a2e:	call GetProcAddress@KERNEL32.DLL
0x00408a30:	xorl %eax, 0x4230d0
0x00408a36:	pushl $0x41d998<UINT32>
0x00408a3b:	pushl %edi
0x00408a3c:	movl 0x4256bc, %eax
0x00408a41:	call GetProcAddress@KERNEL32.DLL
0x00408a43:	xorl %eax, 0x4230d0
0x00408a49:	pushl $0x41d9a8<UINT32>
0x00408a4e:	pushl %edi
0x00408a4f:	movl 0x4256c0, %eax
0x00408a54:	call GetProcAddress@KERNEL32.DLL
0x00408a56:	xorl %eax, 0x4230d0
0x00408a5c:	pushl $0x41d9b8<UINT32>
0x00408a61:	pushl %edi
0x00408a62:	movl 0x4256c4, %eax
0x00408a67:	call GetProcAddress@KERNEL32.DLL
0x00408a69:	xorl %eax, 0x4230d0
0x00408a6f:	pushl $0x41d9d4<UINT32>
0x00408a74:	pushl %edi
0x00408a75:	movl 0x4256c8, %eax
0x00408a7a:	call GetProcAddress@KERNEL32.DLL
0x00408a7c:	xorl %eax, 0x4230d0
0x00408a82:	pushl $0x41d9e8<UINT32>
0x00408a87:	pushl %edi
0x00408a88:	movl 0x4256cc, %eax
0x00408a8d:	call GetProcAddress@KERNEL32.DLL
0x00408a8f:	xorl %eax, 0x4230d0
0x00408a95:	pushl $0x41d9f8<UINT32>
0x00408a9a:	pushl %edi
0x00408a9b:	movl 0x4256d0, %eax
0x00408aa0:	call GetProcAddress@KERNEL32.DLL
0x00408aa2:	xorl %eax, 0x4230d0
0x00408aa8:	pushl $0x41da0c<UINT32>
0x00408aad:	pushl %edi
0x00408aae:	movl 0x4256d4, %eax
0x00408ab3:	call GetProcAddress@KERNEL32.DLL
0x00408ab5:	xorl %eax, 0x4230d0
0x00408abb:	movl 0x4256d8, %eax
0x00408ac0:	pushl $0x41da1c<UINT32>
0x00408ac5:	pushl %edi
0x00408ac6:	call GetProcAddress@KERNEL32.DLL
0x00408ac8:	xorl %eax, 0x4230d0
0x00408ace:	pushl $0x41da3c<UINT32>
0x00408ad3:	pushl %edi
0x00408ad4:	movl 0x4256dc, %eax
0x00408ad9:	call GetProcAddress@KERNEL32.DLL
0x00408adb:	xorl %eax, 0x4230d0
0x00408ae1:	popl %edi
0x00408ae2:	movl 0x4256e0, %eax
0x00408ae7:	popl %esi
0x00408ae8:	ret

0x0040844b:	call 0x00408724
0x00408724:	pushl %esi
0x00408725:	pushl %edi
0x00408726:	movl %esi, $0x423c30<UINT32>
0x0040872b:	movl %edi, $0x4248c8<UINT32>
0x00408730:	cmpl 0x4(%esi), $0x1<UINT8>
0x00408734:	jne 22
0x00408736:	pushl $0x0<UINT8>
0x00408738:	movl (%esi), %edi
0x0040873a:	addl %edi, $0x18<UINT8>
0x0040873d:	pushl $0xfa0<UINT32>
0x00408742:	pushl (%esi)
0x00408744:	call 0x004087f0
0x004087f0:	pushl %ebp
0x004087f1:	movl %ebp, %esp
0x004087f3:	movl %eax, 0x425670
0x004087f8:	xorl %eax, 0x4230d0
0x004087fe:	je 13
0x00408800:	pushl 0x10(%ebp)
0x00408803:	pushl 0xc(%ebp)
0x00408806:	pushl 0x8(%ebp)
0x00408809:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x0040880b:	popl %ebp
0x0040880c:	ret

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
