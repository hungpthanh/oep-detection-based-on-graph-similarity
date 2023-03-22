0x0041ff80:	pusha
0x0041ff81:	movl %esi, $0x415000<UINT32>
0x0041ff86:	leal %edi, -81920(%esi)
0x0041ff8c:	pushl %edi
0x0041ff8d:	jmp 0x0041ff9a
0x0041ff9a:	movl %ebx, (%esi)
0x0041ff9c:	subl %esi, $0xfffffffc<UINT8>
0x0041ff9f:	adcl %ebx, %ebx
0x0041ffa1:	jb 0x0041ff90
0x0041ff90:	movb %al, (%esi)
0x0041ff92:	incl %esi
0x0041ff93:	movb (%edi), %al
0x0041ff95:	incl %edi
0x0041ff96:	addl %ebx, %ebx
0x0041ff98:	jne 0x0041ffa1
0x0041ffa3:	movl %eax, $0x1<UINT32>
0x0041ffa8:	addl %ebx, %ebx
0x0041ffaa:	jne 0x0041ffb3
0x0041ffb3:	adcl %eax, %eax
0x0041ffb5:	addl %ebx, %ebx
0x0041ffb7:	jae 0x0041ffa8
0x0041ffb9:	jne 0x0041ffc4
0x0041ffc4:	xorl %ecx, %ecx
0x0041ffc6:	subl %eax, $0x3<UINT8>
0x0041ffc9:	jb 0x0041ffd8
0x0041ffcb:	shll %eax, $0x8<UINT8>
0x0041ffce:	movb %al, (%esi)
0x0041ffd0:	incl %esi
0x0041ffd1:	xorl %eax, $0xffffffff<UINT8>
0x0041ffd4:	je 0x0042004a
0x0041ffd6:	movl %ebp, %eax
0x0041ffd8:	addl %ebx, %ebx
0x0041ffda:	jne 0x0041ffe3
0x0041ffe3:	adcl %ecx, %ecx
0x0041ffe5:	addl %ebx, %ebx
0x0041ffe7:	jne 0x0041fff0
0x0041fff0:	adcl %ecx, %ecx
0x0041fff2:	jne 0x00420014
0x00420014:	cmpl %ebp, $0xfffff300<UINT32>
0x0042001a:	adcl %ecx, $0x1<UINT8>
0x0042001d:	leal %edx, (%edi,%ebp)
0x00420020:	cmpl %ebp, $0xfffffffc<UINT8>
0x00420023:	jbe 0x00420034
0x00420034:	movl %eax, (%edx)
0x00420036:	addl %edx, $0x4<UINT8>
0x00420039:	movl (%edi), %eax
0x0042003b:	addl %edi, $0x4<UINT8>
0x0042003e:	subl %ecx, $0x4<UINT8>
0x00420041:	ja 0x00420034
0x00420043:	addl %edi, %ecx
0x00420045:	jmp 0x0041ff96
0x00420025:	movb %al, (%edx)
0x00420027:	incl %edx
0x00420028:	movb (%edi), %al
0x0042002a:	incl %edi
0x0042002b:	decl %ecx
0x0042002c:	jne 0x00420025
0x0042002e:	jmp 0x0041ff96
0x0041fff4:	incl %ecx
0x0041fff5:	addl %ebx, %ebx
0x0041fff7:	jne 0x00420000
0x00420000:	adcl %ecx, %ecx
0x00420002:	addl %ebx, %ebx
0x00420004:	jae 0x0041fff5
0x00420006:	jne 0x00420011
0x00420011:	addl %ecx, $0x2<UINT8>
0x0041ffbb:	movl %ebx, (%esi)
0x0041ffbd:	subl %esi, $0xfffffffc<UINT8>
0x0041ffc0:	adcl %ebx, %ebx
0x0041ffc2:	jae 0x0041ffa8
0x0041ffdc:	movl %ebx, (%esi)
0x0041ffde:	subl %esi, $0xfffffffc<UINT8>
0x0041ffe1:	adcl %ebx, %ebx
0x0041ffe9:	movl %ebx, (%esi)
0x0041ffeb:	subl %esi, $0xfffffffc<UINT8>
0x0041ffee:	adcl %ebx, %ebx
0x0041ffac:	movl %ebx, (%esi)
0x0041ffae:	subl %esi, $0xfffffffc<UINT8>
0x0041ffb1:	adcl %ebx, %ebx
0x0041fff9:	movl %ebx, (%esi)
0x0041fffb:	subl %esi, $0xfffffffc<UINT8>
0x0041fffe:	adcl %ebx, %ebx
0x00420008:	movl %ebx, (%esi)
0x0042000a:	subl %esi, $0xfffffffc<UINT8>
0x0042000d:	adcl %ebx, %ebx
0x0042000f:	jae 0x0041fff5
0x0042004a:	popl %esi
0x0042004b:	movl %edi, %esi
0x0042004d:	movl %ecx, $0x499<UINT32>
0x00420052:	movb %al, (%edi)
0x00420054:	incl %edi
0x00420055:	subb %al, $0xffffffe8<UINT8>
0x00420057:	cmpb %al, $0x1<UINT8>
0x00420059:	ja 0x00420052
0x0042005b:	cmpb (%edi), $0x5<UINT8>
0x0042005e:	jne 0x00420052
0x00420060:	movl %eax, (%edi)
0x00420062:	movb %bl, 0x4(%edi)
0x00420065:	shrw %ax, $0x8<UINT8>
0x00420069:	roll %eax, $0x10<UINT8>
0x0042006c:	xchgb %ah, %al
0x0042006e:	subl %eax, %edi
0x00420070:	subb %bl, $0xffffffe8<UINT8>
0x00420073:	addl %eax, %esi
0x00420075:	movl (%edi), %eax
0x00420077:	addl %edi, $0x5<UINT8>
0x0042007a:	movb %al, %bl
0x0042007c:	loop 0x00420057
0x0042007e:	leal %edi, 0x1d000(%esi)
0x00420084:	movl %eax, (%edi)
0x00420086:	orl %eax, %eax
0x00420088:	je 0x004200c6
0x0042008a:	movl %ebx, 0x4(%edi)
0x0042008d:	leal %eax, 0x2053c(%eax,%esi)
0x00420094:	addl %ebx, %esi
0x00420096:	pushl %eax
0x00420097:	addl %edi, $0x8<UINT8>
0x0042009a:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x004200a0:	xchgl %ebp, %eax
0x004200a1:	movb %al, (%edi)
0x004200a3:	incl %edi
0x004200a4:	orb %al, %al
0x004200a6:	je 0x00420084
0x004200a8:	movl %ecx, %edi
0x004200aa:	pushl %edi
0x004200ab:	decl %eax
0x004200ac:	repn scasb %al, %es:(%edi)
0x004200ae:	pushl %ebp
0x004200af:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x004200b5:	orl %eax, %eax
0x004200b7:	je 7
0x004200b9:	movl (%ebx), %eax
0x004200bb:	addl %ebx, $0x4<UINT8>
0x004200be:	jmp 0x004200a1
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x004200c6:	movl %ebp, 0x205d8(%esi)
0x004200cc:	leal %edi, -4096(%esi)
0x004200d2:	movl %ebx, $0x1000<UINT32>
0x004200d7:	pushl %eax
0x004200d8:	pushl %esp
0x004200d9:	pushl $0x4<UINT8>
0x004200db:	pushl %ebx
0x004200dc:	pushl %edi
0x004200dd:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x004200df:	leal %eax, 0x217(%edi)
0x004200e5:	andb (%eax), $0x7f<UINT8>
0x004200e8:	andb 0x28(%eax), $0x7f<UINT8>
0x004200ec:	popl %eax
0x004200ed:	pushl %eax
0x004200ee:	pushl %esp
0x004200ef:	pushl %eax
0x004200f0:	pushl %ebx
0x004200f1:	pushl %edi
0x004200f2:	call VirtualProtect@kernel32.dll
0x004200f4:	popl %eax
0x004200f5:	popa
0x004200f6:	leal %eax, -128(%esp)
0x004200fa:	pushl $0x0<UINT8>
0x004200fc:	cmpl %esp, %eax
0x004200fe:	jne 0x004200fa
0x00420100:	subl %esp, $0xffffff80<UINT8>
0x00420103:	jmp 0x00404256
0x00404256:	call 0x00407e3c
0x00407e3c:	pushl %ebp
0x00407e3d:	movl %ebp, %esp
0x00407e3f:	subl %esp, $0x14<UINT8>
0x00407e42:	andl -12(%ebp), $0x0<UINT8>
0x00407e46:	andl -8(%ebp), $0x0<UINT8>
0x00407e4a:	movl %eax, 0x4190d0
0x00407e4f:	pushl %esi
0x00407e50:	pushl %edi
0x00407e51:	movl %edi, $0xbb40e64e<UINT32>
0x00407e56:	movl %esi, $0xffff0000<UINT32>
0x00407e5b:	cmpl %eax, %edi
0x00407e5d:	je 0x00407e6c
0x00407e6c:	leal %eax, -12(%ebp)
0x00407e6f:	pushl %eax
0x00407e70:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x00407e76:	movl %eax, -8(%ebp)
0x00407e79:	xorl %eax, -12(%ebp)
0x00407e7c:	movl -4(%ebp), %eax
0x00407e7f:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x00407e85:	xorl -4(%ebp), %eax
0x00407e88:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x00407e8e:	xorl -4(%ebp), %eax
0x00407e91:	leal %eax, -20(%ebp)
0x00407e94:	pushl %eax
0x00407e95:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x00407e9b:	movl %ecx, -16(%ebp)
0x00407e9e:	leal %eax, -4(%ebp)
0x00407ea1:	xorl %ecx, -20(%ebp)
0x00407ea4:	xorl %ecx, -4(%ebp)
0x00407ea7:	xorl %ecx, %eax
0x00407ea9:	cmpl %ecx, %edi
0x00407eab:	jne 0x00407eb4
0x00407eb4:	testl %esi, %ecx
0x00407eb6:	jne 0x00407ec4
0x00407ec4:	movl 0x4190d0, %ecx
0x00407eca:	notl %ecx
0x00407ecc:	movl 0x4190d4, %ecx
0x00407ed2:	popl %edi
0x00407ed3:	popl %esi
0x00407ed4:	movl %esp, %ebp
0x00407ed6:	popl %ebp
0x00407ed7:	ret

0x0040425b:	jmp 0x004040db
0x004040db:	pushl $0x14<UINT8>
0x004040dd:	pushl $0x417c30<UINT32>
0x004040e2:	call 0x00406580
0x00406580:	pushl $0x4065e0<UINT32>
0x00406585:	pushl %fs:0
0x0040658c:	movl %eax, 0x10(%esp)
0x00406590:	movl 0x10(%esp), %ebp
0x00406594:	leal %ebp, 0x10(%esp)
0x00406598:	subl %esp, %eax
0x0040659a:	pushl %ebx
0x0040659b:	pushl %esi
0x0040659c:	pushl %edi
0x0040659d:	movl %eax, 0x4190d0
0x004065a2:	xorl -4(%ebp), %eax
0x004065a5:	xorl %eax, %ebp
0x004065a7:	pushl %eax
0x004065a8:	movl -24(%ebp), %esp
0x004065ab:	pushl -8(%ebp)
0x004065ae:	movl %eax, -4(%ebp)
0x004065b1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004065b8:	movl -8(%ebp), %eax
0x004065bb:	leal %eax, -16(%ebp)
0x004065be:	movl %fs:0, %eax
0x004065c4:	ret

0x004040e7:	pushl $0x1<UINT8>
0x004040e9:	call 0x00407def
0x00407def:	pushl %ebp
0x00407df0:	movl %ebp, %esp
0x00407df2:	movl %eax, 0x8(%ebp)
0x00407df5:	movl 0x41a218, %eax
0x00407dfa:	popl %ebp
0x00407dfb:	ret

0x004040ee:	popl %ecx
0x004040ef:	movl %eax, $0x5a4d<UINT32>
0x004040f4:	cmpw 0x400000, %ax
0x004040fb:	je 0x00404101
0x00404101:	movl %eax, 0x40003c
0x00404106:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x00404110:	jne -21
0x00404112:	movl %ecx, $0x10b<UINT32>
0x00404117:	cmpw 0x400018(%eax), %cx
0x0040411e:	jne -35
0x00404120:	xorl %ebx, %ebx
0x00404122:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00404129:	jbe 9
0x0040412b:	cmpl 0x4000e8(%eax), %ebx
0x00404131:	setne %bl
0x00404134:	movl -28(%ebp), %ebx
0x00404137:	call 0x004052cf
0x004052cf:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x004052d5:	xorl %ecx, %ecx
0x004052d7:	movl 0x41a1d8, %eax
0x004052dc:	testl %eax, %eax
0x004052de:	setne %cl
0x004052e1:	movl %eax, %ecx
0x004052e3:	ret

0x0040413c:	testl %eax, %eax
0x0040413e:	jne 0x00404148
0x00404148:	call 0x00405162
0x00405162:	call 0x00405433
0x00405433:	pushl %esi
0x00405434:	pushl $0x0<UINT8>
0x00405436:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x0040543c:	movl %esi, %eax
0x0040543e:	pushl %esi
0x0040543f:	call 0x0040530a
0x0040530a:	pushl %ebp
0x0040530b:	movl %ebp, %esp
0x0040530d:	movl %eax, 0x8(%ebp)
0x00405310:	movl 0x41a1dc, %eax
0x00405315:	popl %ebp
0x00405316:	ret

0x00405444:	pushl %esi
0x00405445:	call 0x00404385
0x00404385:	pushl %ebp
0x00404386:	movl %ebp, %esp
0x00404388:	movl %eax, 0x8(%ebp)
0x0040438b:	movl 0x41a1b4, %eax
0x00404390:	popl %ebp
0x00404391:	ret

0x0040544a:	pushl %esi
0x0040544b:	call 0x00408fe5
0x00408fe5:	pushl %ebp
0x00408fe6:	movl %ebp, %esp
0x00408fe8:	movl %eax, 0x8(%ebp)
0x00408feb:	movl 0x41aef4, %eax
0x00408ff0:	popl %ebp
0x00408ff1:	ret

0x00405450:	pushl %esi
0x00405451:	call 0x00408fff
0x00408fff:	pushl %ebp
0x00409000:	movl %ebp, %esp
0x00409002:	movl %eax, 0x8(%ebp)
0x00409005:	movl 0x41aef8, %eax
0x0040900a:	movl 0x41aefc, %eax
0x0040900f:	movl 0x41af00, %eax
0x00409014:	movl 0x41af04, %eax
0x00409019:	popl %ebp
0x0040901a:	ret

0x00405456:	pushl %esi
0x00405457:	call 0x00408fd4
0x00408fd4:	pushl $0x408fa0<UINT32>
0x00408fd9:	call EncodePointer@KERNEL32.DLL
0x00408fdf:	movl 0x41aef0, %eax
0x00408fe4:	ret

0x0040545c:	pushl %esi
0x0040545d:	call 0x00409210
0x00409210:	pushl %ebp
0x00409211:	movl %ebp, %esp
0x00409213:	movl %eax, 0x8(%ebp)
0x00409216:	movl 0x41af0c, %eax
0x0040921b:	popl %ebp
0x0040921c:	ret

0x00405462:	addl %esp, $0x18<UINT8>
0x00405465:	popl %esi
0x00405466:	jmp 0x00408091
0x00408091:	pushl %esi
0x00408092:	pushl %edi
0x00408093:	pushl $0x414ee8<UINT32>
0x00408098:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0040809e:	movl %esi, 0x40f0bc
0x004080a4:	movl %edi, %eax
0x004080a6:	pushl $0x414f04<UINT32>
0x004080ab:	pushl %edi
0x004080ac:	call GetProcAddress@KERNEL32.DLL
0x004080ae:	xorl %eax, 0x4190d0
0x004080b4:	pushl $0x414f10<UINT32>
0x004080b9:	pushl %edi
0x004080ba:	movl 0x41af40, %eax
0x004080bf:	call GetProcAddress@KERNEL32.DLL
0x004080c1:	xorl %eax, 0x4190d0
0x004080c7:	pushl $0x414f18<UINT32>
0x004080cc:	pushl %edi
0x004080cd:	movl 0x41af44, %eax
0x004080d2:	call GetProcAddress@KERNEL32.DLL
0x004080d4:	xorl %eax, 0x4190d0
0x004080da:	pushl $0x414f24<UINT32>
0x004080df:	pushl %edi
0x004080e0:	movl 0x41af48, %eax
0x004080e5:	call GetProcAddress@KERNEL32.DLL
0x004080e7:	xorl %eax, 0x4190d0
0x004080ed:	pushl $0x414f30<UINT32>
0x004080f2:	pushl %edi
0x004080f3:	movl 0x41af4c, %eax
0x004080f8:	call GetProcAddress@KERNEL32.DLL
0x004080fa:	xorl %eax, 0x4190d0
0x00408100:	pushl $0x414f4c<UINT32>
0x00408105:	pushl %edi
0x00408106:	movl 0x41af50, %eax
0x0040810b:	call GetProcAddress@KERNEL32.DLL
0x0040810d:	xorl %eax, 0x4190d0
0x00408113:	pushl $0x414f5c<UINT32>
0x00408118:	pushl %edi
0x00408119:	movl 0x41af54, %eax
0x0040811e:	call GetProcAddress@KERNEL32.DLL
0x00408120:	xorl %eax, 0x4190d0
0x00408126:	pushl $0x414f70<UINT32>
0x0040812b:	pushl %edi
0x0040812c:	movl 0x41af58, %eax
0x00408131:	call GetProcAddress@KERNEL32.DLL
0x00408133:	xorl %eax, 0x4190d0
0x00408139:	pushl $0x414f88<UINT32>
0x0040813e:	pushl %edi
0x0040813f:	movl 0x41af5c, %eax
0x00408144:	call GetProcAddress@KERNEL32.DLL
0x00408146:	xorl %eax, 0x4190d0
0x0040814c:	pushl $0x414fa0<UINT32>
0x00408151:	pushl %edi
0x00408152:	movl 0x41af60, %eax
0x00408157:	call GetProcAddress@KERNEL32.DLL
0x00408159:	xorl %eax, 0x4190d0
0x0040815f:	pushl $0x414fb4<UINT32>
0x00408164:	pushl %edi
0x00408165:	movl 0x41af64, %eax
0x0040816a:	call GetProcAddress@KERNEL32.DLL
0x0040816c:	xorl %eax, 0x4190d0
0x00408172:	pushl $0x414fd4<UINT32>
0x00408177:	pushl %edi
0x00408178:	movl 0x41af68, %eax
0x0040817d:	call GetProcAddress@KERNEL32.DLL
0x0040817f:	xorl %eax, 0x4190d0
0x00408185:	pushl $0x414fec<UINT32>
0x0040818a:	pushl %edi
0x0040818b:	movl 0x41af6c, %eax
0x00408190:	call GetProcAddress@KERNEL32.DLL
0x00408192:	xorl %eax, 0x4190d0
0x00408198:	pushl $0x415004<UINT32>
0x0040819d:	pushl %edi
0x0040819e:	movl 0x41af70, %eax
0x004081a3:	call GetProcAddress@KERNEL32.DLL
0x004081a5:	xorl %eax, 0x4190d0
0x004081ab:	pushl $0x415018<UINT32>
0x004081b0:	pushl %edi
0x004081b1:	movl 0x41af74, %eax
0x004081b6:	call GetProcAddress@KERNEL32.DLL
0x004081b8:	xorl %eax, 0x4190d0
0x004081be:	movl 0x41af78, %eax
0x004081c3:	pushl $0x41502c<UINT32>
0x004081c8:	pushl %edi
0x004081c9:	call GetProcAddress@KERNEL32.DLL
0x004081cb:	xorl %eax, 0x4190d0
0x004081d1:	pushl $0x415048<UINT32>
0x004081d6:	pushl %edi
0x004081d7:	movl 0x41af7c, %eax
0x004081dc:	call GetProcAddress@KERNEL32.DLL
0x004081de:	xorl %eax, 0x4190d0
0x004081e4:	pushl $0x415068<UINT32>
0x004081e9:	pushl %edi
0x004081ea:	movl 0x41af80, %eax
0x004081ef:	call GetProcAddress@KERNEL32.DLL
0x004081f1:	xorl %eax, 0x4190d0
0x004081f7:	pushl $0x415084<UINT32>
0x004081fc:	pushl %edi
0x004081fd:	movl 0x41af84, %eax
0x00408202:	call GetProcAddress@KERNEL32.DLL
0x00408204:	xorl %eax, 0x4190d0
0x0040820a:	pushl $0x4150a4<UINT32>
0x0040820f:	pushl %edi
0x00408210:	movl 0x41af88, %eax
0x00408215:	call GetProcAddress@KERNEL32.DLL
0x00408217:	xorl %eax, 0x4190d0
0x0040821d:	pushl $0x4150b8<UINT32>
0x00408222:	pushl %edi
0x00408223:	movl 0x41af8c, %eax
0x00408228:	call GetProcAddress@KERNEL32.DLL
0x0040822a:	xorl %eax, 0x4190d0
0x00408230:	pushl $0x4150d4<UINT32>
0x00408235:	pushl %edi
0x00408236:	movl 0x41af90, %eax
0x0040823b:	call GetProcAddress@KERNEL32.DLL
0x0040823d:	xorl %eax, 0x4190d0
0x00408243:	pushl $0x4150e8<UINT32>
0x00408248:	pushl %edi
0x00408249:	movl 0x41af98, %eax
0x0040824e:	call GetProcAddress@KERNEL32.DLL
0x00408250:	xorl %eax, 0x4190d0
0x00408256:	pushl $0x4150f8<UINT32>
0x0040825b:	pushl %edi
0x0040825c:	movl 0x41af94, %eax
0x00408261:	call GetProcAddress@KERNEL32.DLL
0x00408263:	xorl %eax, 0x4190d0
0x00408269:	pushl $0x415108<UINT32>
0x0040826e:	pushl %edi
0x0040826f:	movl 0x41af9c, %eax
0x00408274:	call GetProcAddress@KERNEL32.DLL
0x00408276:	xorl %eax, 0x4190d0
0x0040827c:	pushl $0x415118<UINT32>
0x00408281:	pushl %edi
0x00408282:	movl 0x41afa0, %eax
0x00408287:	call GetProcAddress@KERNEL32.DLL
0x00408289:	xorl %eax, 0x4190d0
0x0040828f:	pushl $0x415128<UINT32>
0x00408294:	pushl %edi
0x00408295:	movl 0x41afa4, %eax
0x0040829a:	call GetProcAddress@KERNEL32.DLL
0x0040829c:	xorl %eax, 0x4190d0
0x004082a2:	pushl $0x415144<UINT32>
0x004082a7:	pushl %edi
0x004082a8:	movl 0x41afa8, %eax
0x004082ad:	call GetProcAddress@KERNEL32.DLL
0x004082af:	xorl %eax, 0x4190d0
0x004082b5:	pushl $0x415158<UINT32>
0x004082ba:	pushl %edi
0x004082bb:	movl 0x41afac, %eax
0x004082c0:	call GetProcAddress@KERNEL32.DLL
0x004082c2:	xorl %eax, 0x4190d0
0x004082c8:	pushl $0x415168<UINT32>
0x004082cd:	pushl %edi
0x004082ce:	movl 0x41afb0, %eax
0x004082d3:	call GetProcAddress@KERNEL32.DLL
0x004082d5:	xorl %eax, 0x4190d0
0x004082db:	pushl $0x41517c<UINT32>
0x004082e0:	pushl %edi
0x004082e1:	movl 0x41afb4, %eax
0x004082e6:	call GetProcAddress@KERNEL32.DLL
0x004082e8:	xorl %eax, 0x4190d0
0x004082ee:	movl 0x41afb8, %eax
0x004082f3:	pushl $0x41518c<UINT32>
0x004082f8:	pushl %edi
0x004082f9:	call GetProcAddress@KERNEL32.DLL
0x004082fb:	xorl %eax, 0x4190d0
0x00408301:	pushl $0x4151ac<UINT32>
0x00408306:	pushl %edi
0x00408307:	movl 0x41afbc, %eax
0x0040830c:	call GetProcAddress@KERNEL32.DLL
0x0040830e:	xorl %eax, 0x4190d0
0x00408314:	popl %edi
0x00408315:	movl 0x41afc0, %eax
0x0040831a:	popl %esi
0x0040831b:	ret

0x00405167:	call 0x00406c3e
0x00406c3e:	pushl %esi
0x00406c3f:	pushl %edi
0x00406c40:	movl %esi, $0x419c30<UINT32>
0x00406c45:	movl %edi, $0x41a858<UINT32>
0x00406c4a:	cmpl 0x4(%esi), $0x1<UINT8>
0x00406c4e:	jne 22
0x00406c50:	pushl $0x0<UINT8>
0x00406c52:	movl (%esi), %edi
0x00406c54:	addl %edi, $0x18<UINT8>
0x00406c57:	pushl $0xfa0<UINT32>
0x00406c5c:	pushl (%esi)
0x00406c5e:	call 0x00408023
0x00408023:	pushl %ebp
0x00408024:	movl %ebp, %esp
0x00408026:	movl %eax, 0x41af50
0x0040802b:	xorl %eax, 0x4190d0
0x00408031:	je 13
0x00408033:	pushl 0x10(%ebp)
0x00408036:	pushl 0xc(%ebp)
0x00408039:	pushl 0x8(%ebp)
0x0040803c:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x0040803e:	popl %ebp
0x0040803f:	ret

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
