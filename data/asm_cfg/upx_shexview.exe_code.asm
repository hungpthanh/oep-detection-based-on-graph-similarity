0x0041c030:	pusha
0x0041c031:	movl %esi, $0x412000<UINT32>
0x0041c036:	leal %edi, -69632(%esi)
0x0041c03c:	pushl %edi
0x0041c03d:	jmp 0x0041c04a
0x0041c04a:	movl %ebx, (%esi)
0x0041c04c:	subl %esi, $0xfffffffc<UINT8>
0x0041c04f:	adcl %ebx, %ebx
0x0041c051:	jb 0x0041c040
0x0041c040:	movb %al, (%esi)
0x0041c042:	incl %esi
0x0041c043:	movb (%edi), %al
0x0041c045:	incl %edi
0x0041c046:	addl %ebx, %ebx
0x0041c048:	jne 0x0041c051
0x0041c053:	movl %eax, $0x1<UINT32>
0x0041c058:	addl %ebx, %ebx
0x0041c05a:	jne 0x0041c063
0x0041c063:	adcl %eax, %eax
0x0041c065:	addl %ebx, %ebx
0x0041c067:	jae 0x0041c058
0x0041c069:	jne 0x0041c074
0x0041c074:	xorl %ecx, %ecx
0x0041c076:	subl %eax, $0x3<UINT8>
0x0041c079:	jb 0x0041c088
0x0041c07b:	shll %eax, $0x8<UINT8>
0x0041c07e:	movb %al, (%esi)
0x0041c080:	incl %esi
0x0041c081:	xorl %eax, $0xffffffff<UINT8>
0x0041c084:	je 0x0041c0fa
0x0041c086:	movl %ebp, %eax
0x0041c088:	addl %ebx, %ebx
0x0041c08a:	jne 0x0041c093
0x0041c093:	adcl %ecx, %ecx
0x0041c095:	addl %ebx, %ebx
0x0041c097:	jne 0x0041c0a0
0x0041c0a0:	adcl %ecx, %ecx
0x0041c0a2:	jne 0x0041c0c4
0x0041c0c4:	cmpl %ebp, $0xfffff300<UINT32>
0x0041c0ca:	adcl %ecx, $0x1<UINT8>
0x0041c0cd:	leal %edx, (%edi,%ebp)
0x0041c0d0:	cmpl %ebp, $0xfffffffc<UINT8>
0x0041c0d3:	jbe 0x0041c0e4
0x0041c0e4:	movl %eax, (%edx)
0x0041c0e6:	addl %edx, $0x4<UINT8>
0x0041c0e9:	movl (%edi), %eax
0x0041c0eb:	addl %edi, $0x4<UINT8>
0x0041c0ee:	subl %ecx, $0x4<UINT8>
0x0041c0f1:	ja 0x0041c0e4
0x0041c0f3:	addl %edi, %ecx
0x0041c0f5:	jmp 0x0041c046
0x0041c099:	movl %ebx, (%esi)
0x0041c09b:	subl %esi, $0xfffffffc<UINT8>
0x0041c09e:	adcl %ebx, %ebx
0x0041c0a4:	incl %ecx
0x0041c0a5:	addl %ebx, %ebx
0x0041c0a7:	jne 0x0041c0b0
0x0041c0b0:	adcl %ecx, %ecx
0x0041c0b2:	addl %ebx, %ebx
0x0041c0b4:	jae 0x0041c0a5
0x0041c0b6:	jne 0x0041c0c1
0x0041c0c1:	addl %ecx, $0x2<UINT8>
0x0041c08c:	movl %ebx, (%esi)
0x0041c08e:	subl %esi, $0xfffffffc<UINT8>
0x0041c091:	adcl %ebx, %ebx
0x0041c0a9:	movl %ebx, (%esi)
0x0041c0ab:	subl %esi, $0xfffffffc<UINT8>
0x0041c0ae:	adcl %ebx, %ebx
0x0041c05c:	movl %ebx, (%esi)
0x0041c05e:	subl %esi, $0xfffffffc<UINT8>
0x0041c061:	adcl %ebx, %ebx
0x0041c0b8:	movl %ebx, (%esi)
0x0041c0ba:	subl %esi, $0xfffffffc<UINT8>
0x0041c0bd:	adcl %ebx, %ebx
0x0041c0bf:	jae 0x0041c0a5
0x0041c06b:	movl %ebx, (%esi)
0x0041c06d:	subl %esi, $0xfffffffc<UINT8>
0x0041c070:	adcl %ebx, %ebx
0x0041c072:	jae 0x0041c058
0x0041c0d5:	movb %al, (%edx)
0x0041c0d7:	incl %edx
0x0041c0d8:	movb (%edi), %al
0x0041c0da:	incl %edi
0x0041c0db:	decl %ecx
0x0041c0dc:	jne 0x0041c0d5
0x0041c0de:	jmp 0x0041c046
0x0041c0fa:	popl %esi
0x0041c0fb:	movl %edi, %esi
0x0041c0fd:	movl %ecx, $0x64d<UINT32>
0x0041c102:	movb %al, (%edi)
0x0041c104:	incl %edi
0x0041c105:	subb %al, $0xffffffe8<UINT8>
0x0041c107:	cmpb %al, $0x1<UINT8>
0x0041c109:	ja 0x0041c102
0x0041c10b:	cmpb (%edi), $0x7<UINT8>
0x0041c10e:	jne 0x0041c102
0x0041c110:	movl %eax, (%edi)
0x0041c112:	movb %bl, 0x4(%edi)
0x0041c115:	shrw %ax, $0x8<UINT8>
0x0041c119:	roll %eax, $0x10<UINT8>
0x0041c11c:	xchgb %ah, %al
0x0041c11e:	subl %eax, %edi
0x0041c120:	subb %bl, $0xffffffe8<UINT8>
0x0041c123:	addl %eax, %esi
0x0041c125:	movl (%edi), %eax
0x0041c127:	addl %edi, $0x5<UINT8>
0x0041c12a:	movb %al, %bl
0x0041c12c:	loop 0x0041c107
0x0041c12e:	leal %edi, 0x1a000(%esi)
0x0041c134:	movl %eax, (%edi)
0x0041c136:	orl %eax, %eax
0x0041c138:	je 0x0041c17f
0x0041c13a:	movl %ebx, 0x4(%edi)
0x0041c13d:	leal %eax, 0x1d298(%eax,%esi)
0x0041c144:	addl %ebx, %esi
0x0041c146:	pushl %eax
0x0041c147:	addl %edi, $0x8<UINT8>
0x0041c14a:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x0041c150:	xchgl %ebp, %eax
0x0041c151:	movb %al, (%edi)
0x0041c153:	incl %edi
0x0041c154:	orb %al, %al
0x0041c156:	je 0x0041c134
0x0041c158:	movl %ecx, %edi
0x0041c15a:	jns 0x0041c163
0x0041c163:	pushl %edi
0x0041c164:	decl %eax
0x0041c165:	repn scasb %al, %es:(%edi)
0x0041c167:	pushl %ebp
0x0041c168:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0041c16e:	orl %eax, %eax
0x0041c170:	je 7
0x0041c172:	movl (%ebx), %eax
0x0041c174:	addl %ebx, $0x4<UINT8>
0x0041c177:	jmp 0x0041c151
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x0041c15c:	movzwl %eax, (%edi)
0x0041c15f:	incl %edi
0x0041c160:	pushl %eax
0x0041c161:	incl %edi
0x0041c162:	movl %ecx, $0xaef24857<UINT32>
0x0041c17f:	movl %ebp, 0x1d3b4(%esi)
0x0041c185:	leal %edi, -4096(%esi)
0x0041c18b:	movl %ebx, $0x1000<UINT32>
0x0041c190:	pushl %eax
0x0041c191:	pushl %esp
0x0041c192:	pushl $0x4<UINT8>
0x0041c194:	pushl %ebx
0x0041c195:	pushl %edi
0x0041c196:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0041c198:	leal %eax, 0x207(%edi)
0x0041c19e:	andb (%eax), $0x7f<UINT8>
0x0041c1a1:	andb 0x28(%eax), $0x7f<UINT8>
0x0041c1a5:	popl %eax
0x0041c1a6:	pushl %eax
0x0041c1a7:	pushl %esp
0x0041c1a8:	pushl %eax
0x0041c1a9:	pushl %ebx
0x0041c1aa:	pushl %edi
0x0041c1ab:	call VirtualProtect@kernel32.dll
0x0041c1ad:	popl %eax
0x0041c1ae:	popa
0x0041c1af:	leal %eax, -128(%esp)
0x0041c1b3:	pushl $0x0<UINT8>
0x0041c1b5:	cmpl %esp, %eax
0x0041c1b7:	jne 0x0041c1b3
0x0041c1b9:	subl %esp, $0xffffff80<UINT8>
0x0041c1bc:	jmp 0x0040ef60
0x0040ef60:	pushl $0x70<UINT8>
0x0040ef62:	pushl $0x410450<UINT32>
0x0040ef67:	call 0x0040f14c
0x0040f14c:	pushl $0x40f19c<UINT32>
0x0040f151:	movl %eax, %fs:0
0x0040f157:	pushl %eax
0x0040f158:	movl %fs:0, %esp
0x0040f15f:	movl %eax, 0x10(%esp)
0x0040f163:	movl 0x10(%esp), %ebp
0x0040f167:	leal %ebp, 0x10(%esp)
0x0040f16b:	subl %esp, %eax
0x0040f16d:	pushl %ebx
0x0040f16e:	pushl %esi
0x0040f16f:	pushl %edi
0x0040f170:	movl %eax, -8(%ebp)
0x0040f173:	movl -24(%ebp), %esp
0x0040f176:	pushl %eax
0x0040f177:	movl %eax, -4(%ebp)
0x0040f17a:	movl -4(%ebp), $0xffffffff<UINT32>
0x0040f181:	movl -8(%ebp), %eax
0x0040f184:	ret

0x0040ef6c:	xorl %ebx, %ebx
0x0040ef6e:	pushl %ebx
0x0040ef6f:	movl %edi, 0x4100e4
0x0040ef75:	call GetModuleHandleA@KERNEL32.DLL
GetModuleHandleA@KERNEL32.DLL: API Node	
0x0040ef77:	cmpw (%eax), $0x5a4d<UINT16>
0x0040ef7c:	jne 31
0x0040ef7e:	movl %ecx, 0x3c(%eax)
0x0040ef81:	addl %ecx, %eax
0x0040ef83:	cmpl (%ecx), $0x4550<UINT32>
0x0040ef89:	jne 18
0x0040ef8b:	movzwl %eax, 0x18(%ecx)
0x0040ef8f:	cmpl %eax, $0x10b<UINT32>
0x0040ef94:	je 0x0040efb5
0x0040efb5:	cmpl 0x74(%ecx), $0xe<UINT8>
0x0040efb9:	jbe -30
0x0040efbb:	xorl %eax, %eax
0x0040efbd:	cmpl 0xe8(%ecx), %ebx
0x0040efc3:	setne %al
0x0040efc6:	movl -28(%ebp), %eax
0x0040efc9:	movl -4(%ebp), %ebx
0x0040efcc:	pushl $0x2<UINT8>
0x0040efce:	call __set_app_type@msvcrt.dll
__set_app_type@msvcrt.dll: API Node	
0x0040efd4:	popl %ecx
0x0040efd5:	orl 0x415114, $0xffffffff<UINT8>
0x0040efdc:	orl 0x415118, $0xffffffff<UINT8>
0x0040efe3:	call __p__fmode@msvcrt.dll
__p__fmode@msvcrt.dll: API Node	
0x0040efe9:	movl %ecx, 0x41441c
0x0040efef:	movl (%eax), %ecx
0x0040eff1:	call __p__commode@msvcrt.dll
__p__commode@msvcrt.dll: API Node	
0x0040eff7:	movl %ecx, 0x414418
0x0040effd:	movl (%eax), %ecx
0x0040efff:	movl %eax, 0x410330
0x0040f004:	movl %eax, (%eax)
0x0040f006:	movl 0x415110, %eax
0x0040f00b:	call 0x00401848
0x00401848:	xorl %eax, %eax
0x0040184a:	ret

0x0040f010:	cmpl 0x414000, %ebx
0x0040f016:	jne 0x0040f024
0x0040f024:	call 0x0040f138
0x0040f138:	pushl $0x30000<UINT32>
0x0040f13d:	pushl $0x10000<UINT32>
0x0040f142:	call 0x0040f196
0x0040f196:	jmp _controlfp@msvcrt.dll
_controlfp@msvcrt.dll: API Node	
0x0040f147:	popl %ecx
0x0040f148:	popl %ecx
0x0040f149:	ret

0x0040f029:	pushl $0x41042c<UINT32>
0x0040f02e:	pushl $0x410428<UINT32>
0x0040f033:	call 0x0040f132
0x0040f132:	jmp _initterm@msvcrt.dll
_initterm@msvcrt.dll: API Node	
0x0040f038:	movl %eax, 0x414414
0x0040f03d:	movl -32(%ebp), %eax
0x0040f040:	leal %eax, -32(%ebp)
0x0040f043:	pushl %eax
0x0040f044:	pushl 0x414410
0x0040f04a:	leal %eax, -36(%ebp)
0x0040f04d:	pushl %eax
0x0040f04e:	leal %eax, -40(%ebp)
0x0040f051:	pushl %eax
0x0040f052:	leal %eax, -44(%ebp)
0x0040f055:	pushl %eax
0x0040f056:	call __getmainargs@msvcrt.dll
__getmainargs@msvcrt.dll: API Node	
0x0040f05c:	movl -48(%ebp), %eax
0x0040f05f:	pushl $0x410424<UINT32>
0x0040f064:	pushl $0x4103f0<UINT32>
0x0040f069:	call 0x0040f132
0x0040f06e:	addl %esp, $0x24<UINT8>
0x0040f071:	movl %eax, 0x410364
0x0040f076:	movl %esi, (%eax)
0x0040f078:	movl -52(%ebp), %esi
0x0040f07b:	cmpb (%esi), $0x22<UINT8>
0x0040f07e:	jne 58
0x0040f080:	incl %esi
0x0040f081:	movl -52(%ebp), %esi
0x0040f084:	movb %al, (%esi)
0x0040f086:	cmpb %al, %bl
0x0040f088:	je 4
0x0040f08a:	cmpb %al, $0x22<UINT8>
0x0040f08c:	jne 0x0040f080
0x0040f08e:	cmpb (%esi), $0x22<UINT8>
0x0040f091:	jne 4
0x0040f093:	incl %esi
0x0040f094:	movl -52(%ebp), %esi
0x0040f097:	movb %al, (%esi)
0x0040f099:	cmpb %al, %bl
0x0040f09b:	je 4
0x0040f09d:	cmpb %al, $0x20<UINT8>
0x0040f09f:	jbe 0x0040f093
0x0040f0a1:	movl -76(%ebp), %ebx
0x0040f0a4:	leal %eax, -120(%ebp)
0x0040f0a7:	pushl %eax
0x0040f0a8:	call GetStartupInfoA@KERNEL32.DLL
GetStartupInfoA@KERNEL32.DLL: API Node	
0x0040f0ae:	testb -76(%ebp), $0x1<UINT8>
0x0040f0b2:	je 0x0040f0c5
0x0040f0c5:	pushl $0xa<UINT8>
0x0040f0c7:	popl %eax
0x0040f0c8:	pushl %eax
0x0040f0c9:	pushl %esi
0x0040f0ca:	pushl %ebx
0x0040f0cb:	pushl %ebx
0x0040f0cc:	call GetModuleHandleA@KERNEL32.DLL
0x0040f0ce:	pushl %eax
0x0040f0cf:	call 0x0040c991
0x0040c991:	pushl %ebp
0x0040c992:	movl %ebp, %esp
0x0040c994:	andl %esp, $0xfffffff8<UINT8>
0x0040c997:	movl %eax, 0x8(%ebp)
0x0040c99a:	subl %esp, $0x334<UINT32>
0x0040c9a0:	pushl %ebx
0x0040c9a1:	pushl %esi
0x0040c9a2:	pushl %edi
0x0040c9a3:	movl 0x414420, %eax
0x0040c9a8:	call 0x00404bb9
0x00404bb9:	pushl %ebp
0x00404bba:	movl %ebp, %esp
0x00404bbc:	pushl %ecx
0x00404bbd:	pushl %ecx
0x00404bbe:	pushl %ebx
0x00404bbf:	pushl %esi
0x00404bc0:	pushl %edi
0x00404bc1:	pushl $0x411314<UINT32>
0x00404bc6:	movl -8(%ebp), $0x8<UINT32>
0x00404bcd:	movl -4(%ebp), $0xff<UINT32>
0x00404bd4:	xorl %ebx, %ebx
0x00404bd6:	xorl %edi, %edi
0x00404bd8:	call LoadLibraryA@KERNEL32.DLL
0x00404bde:	movl %esi, %eax
0x00404be0:	testl %esi, %esi
0x00404be2:	je 40
0x00404be4:	pushl $0x411324<UINT32>
0x00404be9:	pushl %esi
0x00404bea:	call GetProcAddress@KERNEL32.DLL
0x00404bf0:	testl %eax, %eax
0x00404bf2:	je 9
0x00404bf4:	leal %ecx, -8(%ebp)
0x00404bf7:	pushl %ecx
0x00404bf8:	incl %edi
0x00404bf9:	call InitCommonControlsEx@comctl32.dll
InitCommonControlsEx@comctl32.dll: API Node	
0x00404bfb:	movl %ebx, %eax
0x00404bfd:	pushl %esi
0x00404bfe:	call FreeLibrary@KERNEL32.DLL
FreeLibrary@KERNEL32.DLL: API Node	
0x00404c04:	testl %edi, %edi
0x00404c06:	je 4
0x00404c08:	movl %eax, %ebx
0x00404c0a:	jmp 0x00404c15
0x00404c15:	testl %eax, %eax
0x00404c17:	popl %edi
0x00404c18:	popl %esi
0x00404c19:	popl %ebx
0x00404c1a:	jne 0x00404c33
0x00404c1c:	pushl $0x30<UINT8>
0x00404c33:	xorl %eax, %eax
0x00404c35:	incl %eax
0x00404c36:	leave
0x00404c37:	ret

0x0040c9ad:	testl %eax, %eax
0x0040c9af:	jne 0x0040c9b7
0x0040c9b7:	call 0x0040e727
0x0040e727:	cmpl 0x414d3c, $0x0<UINT8>
0x0040e72e:	jne 37
0x0040e730:	pushl $0x411bf4<UINT32>
0x0040e735:	call LoadLibraryA@KERNEL32.DLL
0x0040e73b:	testl %eax, %eax
0x0040e73d:	movl 0x414d3c, %eax
0x0040e742:	je 17
0x0040e744:	pushl $0x41201c<UINT32>
0x0040e749:	pushl %eax
0x0040e74a:	call GetProcAddress@KERNEL32.DLL
0x0040e750:	movl 0x414d38, %eax
0x0040e755:	ret

0x0040c9bc:	xorl %edi, %edi
0x0040c9be:	leal %eax, 0x60(%esp)
0x0040c9c2:	movl 0x24(%esp), $0x400<UINT32>
0x0040c9ca:	movl 0x28(%esp), $0x100<UINT32>
0x0040c9d2:	movl 0x10(%esp), %edi
0x0040c9d6:	movl 0x14(%esp), %edi
0x0040c9da:	movl 0x1c(%esp), %edi
0x0040c9de:	movl 0x20(%esp), %edi
0x0040c9e2:	movl 0x2c(%esp), %edi
0x0040c9e6:	movl 0x18(%esp), %edi
0x0040c9ea:	movl 0x38(%esp), $0x20<UINT32>
0x0040c9f2:	movl 0x30(%esp), %edi
0x0040c9f6:	movl 0x3c(%esp), %edi
0x0040c9fa:	movl 0x34(%esp), %edi
0x0040c9fe:	movl 0x40(%esp), %edi
0x0040ca02:	call 0x0040c665
0x0040c665:	pushl %esi
0x0040c666:	movl %esi, %eax
0x0040c668:	movl (%esi), $0x411d1c<UINT32>
0x0040c66e:	leal %eax, 0x290(%esi)
0x0040c674:	pushl %edi
0x0040c675:	xorl %edi, %edi
0x0040c677:	movl 0x140(%esi), %edi
0x0040c67d:	movl 0x28c(%esi), $0x411cec<UINT32>
0x0040c687:	movl 0x14(%eax), $0x400<UINT32>
0x0040c68e:	movl 0x18(%eax), $0x100<UINT32>
0x0040c695:	movl (%eax), %edi
0x0040c697:	movl 0x4(%eax), %edi
0x0040c69a:	movl 0xc(%eax), %edi
0x0040c69d:	movl 0x10(%eax), %edi
0x0040c6a0:	movl 0x1c(%eax), %edi
0x0040c6a3:	movl 0x8(%eax), %edi
0x0040c6a6:	movl 0x2b0(%esi), $0x411cd0<UINT32>
0x0040c6b0:	movl 0x2b8(%esi), $0x411cbc<UINT32>
0x0040c6ba:	leal %eax, 0x2bc(%esi)
0x0040c6c0:	movl (%eax), $0x4121bc<UINT32>
0x0040c6c6:	movl 0x4(%eax), %edi
0x0040c6c9:	movl 0x8(%eax), %edi
0x0040c6cc:	movl 0x10(%eax), %edi
0x0040c6cf:	pushl $0x134<UINT32>
0x0040c6d4:	movl 0x288(%esi), %edi
0x0040c6da:	call 0x0040ef0c
0x0040ef0c:	jmp ??2@YAPAXI@Z@msvcrt.dll
??2@YAPAXI@Z@msvcrt.dll: API Node	
0x0040c6df:	cmpl %eax, %edi
0x0040c6e1:	popl %ecx
0x0040c6e2:	je 7
0x0040c6e4:	movl 0x41499c, %eax
0x0040c6e9:	jmp 0x0040c6ed
0x0040c6ed:	pushl $0x708<UINT32>
0x0040c6f2:	movl 0x284(%esi), %eax
0x0040c6f8:	call 0x0040ef0c
0x0040c6fd:	cmpl %eax, %edi
0x0040c6ff:	popl %ecx
0x0040c700:	je 7
0x0040c702:	call 0x00404ab7
0x00404ab7:	pushl %esi
0x00404ab8:	movl %esi, %eax
0x00404aba:	call 0x00408824
0x00408824:	pushl %ebx
0x00408825:	pushl %edi
0x00408826:	pushl %esi
0x00408827:	movl %eax, $0x1d0<UINT32>
0x0040882c:	movl (%esi), $0x411aa0<UINT32>
0x00408832:	call 0x00407241
0x00407241:	addl %eax, $0xfffffffc<UINT8>
0x00407244:	pushl %eax
0x00407245:	movl %eax, 0x8(%esp)
0x00407249:	addl %eax, $0x4<UINT8>
0x0040724c:	pushl $0x0<UINT8>
0x0040724e:	pushl %eax
0x0040724f:	call 0x0040eefa
0x0040eefa:	jmp memset@msvcrt.dll
memset@msvcrt.dll: API Node	
0x00407254:	addl %esp, $0xc<UINT8>
0x00407257:	ret

0x00000000:	addb (%eax), %al
0x00000002:	addb (%eax), %al
0x00000004:	addb (%eax), %al
0x00000006:	addb (%eax), %al
0x00000008:	addb (%eax), %al
0x0000000a:	addb (%eax), %al
0x0000000c:	addb (%eax), %al
0x0000000e:	addb (%eax), %al
0x00000010:	addb (%eax), %al
0x00000012:	addb (%eax), %al
0x00000014:	addb (%eax), %al
0x00000016:	addb (%eax), %al
0x00000018:	addb (%eax), %al
0x0000001a:	addb (%eax), %al
0x0000001c:	addb (%eax), %al
0x0000001e:	addb (%eax), %al
0x00000020:	addb (%eax), %al
0x00000022:	addb (%eax), %al
0x00000024:	addb (%eax), %al
0x00000026:	addb (%eax), %al
0x00000028:	addb (%eax), %al
0x0000002a:	addb (%eax), %al
0x0000002c:	addb (%eax), %al
0x0000002e:	addb (%eax), %al
0x00000030:	addb (%eax), %al
0x00000032:	addb (%eax), %al
0x00000034:	addb (%eax), %al
0x00000036:	addb (%eax), %al
0x00000038:	addb (%eax), %al
0x0000003a:	addb (%eax), %al
0x0000003c:	addb (%eax), %al
0x0000003e:	addb (%eax), %al
0x00000040:	addb (%eax), %al
0x00000042:	addb (%eax), %al
0x00000044:	addb (%eax), %al
0x00000046:	addb (%eax), %al
0x00000048:	addb (%eax), %al
0x0000004a:	addb (%eax), %al
0x0000004c:	addb (%eax), %al
0x0000004e:	addb (%eax), %al
0x00000050:	addb (%eax), %al
0x00000052:	addb (%eax), %al
0x00000054:	addb (%eax), %al
0x00000056:	addb (%eax), %al
0x00000058:	addb (%eax), %al
0x0000005a:	addb (%eax), %al
0x0000005c:	addb (%eax), %al
0x0000005e:	addb (%eax), %al
0x00000060:	addb (%eax), %al
0x00000062:	addb (%eax), %al
0x00000064:	addb (%eax), %al
0x00000066:	addb (%eax), %al
0x00404c1e:	pushl $0x41133c<UINT32>
0x00404c23:	pushl $0x411344<UINT32>
0x00404c28:	pushl %eax
0x00404c29:	call MessageBoxA@USER32.dll
MessageBoxA@USER32.dll: API Node	
0x00404c2f:	xorl %eax, %eax
0x00404c31:	leave
0x00404c32:	ret

0x0040c9b1:	incl %eax
0x0040c9b2:	jmp 0x0040cc77
0x0040cc77:	popl %edi
0x0040cc78:	popl %esi
0x0040cc79:	popl %ebx
0x0040cc7a:	movl %esp, %ebp
0x0040cc7c:	popl %ebp
0x0040cc7d:	ret $0x10<UINT16>

0x0040f0d4:	movl %esi, %eax
0x0040f0d6:	movl -124(%ebp), %esi
0x0040f0d9:	cmpl -28(%ebp), %ebx
0x0040f0dc:	jne 7
0x0040f0de:	pushl %esi
0x0040f0df:	call exit@msvcrt.dll
exit@msvcrt.dll: Exit Node	
