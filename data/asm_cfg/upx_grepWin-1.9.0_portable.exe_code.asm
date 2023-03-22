0x00520fe0:	pusha
0x00520fe1:	movl %esi, $0x4c7000<UINT32>
0x00520fe6:	leal %edi, -811008(%esi)
0x00520fec:	movl 0xef4c0(%edi), $0x20646461<UINT32>
0x00520ff6:	pushl %edi
0x00520ff7:	orl %ebp, $0xffffffff<UINT8>
0x00520ffa:	jmp 0x0052100a
0x0052100a:	movl %ebx, (%esi)
0x0052100c:	subl %esi, $0xfffffffc<UINT8>
0x0052100f:	adcl %ebx, %ebx
0x00521011:	jb 0x00521000
0x00521000:	movb %al, (%esi)
0x00521002:	incl %esi
0x00521003:	movb (%edi), %al
0x00521005:	incl %edi
0x00521006:	addl %ebx, %ebx
0x00521008:	jne 0x00521011
0x00521013:	movl %eax, $0x1<UINT32>
0x00521018:	addl %ebx, %ebx
0x0052101a:	jne 0x00521023
0x00521023:	adcl %eax, %eax
0x00521025:	addl %ebx, %ebx
0x00521027:	jae 0x00521034
0x00521029:	jne 0x00521053
0x00521053:	xorl %ecx, %ecx
0x00521055:	subl %eax, $0x3<UINT8>
0x00521058:	jb 0x0052106b
0x0052106b:	addl %ebx, %ebx
0x0052106d:	jne 0x00521076
0x00521076:	jb 0x00521044
0x00521044:	addl %ebx, %ebx
0x00521046:	jne 0x0052104f
0x0052104f:	adcl %ecx, %ecx
0x00521051:	jmp 0x005210a5
0x005210a5:	cmpl %ebp, $0xfffffb00<UINT32>
0x005210ab:	adcl %ecx, $0x2<UINT8>
0x005210ae:	leal %edx, (%edi,%ebp)
0x005210b1:	cmpl %ebp, $0xfffffffc<UINT8>
0x005210b4:	jbe 0x005210c4
0x005210b6:	movb %al, (%edx)
0x005210b8:	incl %edx
0x005210b9:	movb (%edi), %al
0x005210bb:	incl %edi
0x005210bc:	decl %ecx
0x005210bd:	jne 0x005210b6
0x005210bf:	jmp 0x00521006
0x0052105a:	shll %eax, $0x8<UINT8>
0x0052105d:	movb %al, (%esi)
0x0052105f:	incl %esi
0x00521060:	xorl %eax, $0xffffffff<UINT8>
0x00521063:	je 0x005210da
0x00521065:	sarl %eax
0x00521067:	movl %ebp, %eax
0x00521069:	jmp 0x00521076
0x005210c4:	movl %eax, (%edx)
0x005210c6:	addl %edx, $0x4<UINT8>
0x005210c9:	movl (%edi), %eax
0x005210cb:	addl %edi, $0x4<UINT8>
0x005210ce:	subl %ecx, $0x4<UINT8>
0x005210d1:	ja 0x005210c4
0x005210d3:	addl %edi, %ecx
0x005210d5:	jmp 0x00521006
0x00521078:	incl %ecx
0x00521079:	addl %ebx, %ebx
0x0052107b:	jne 0x00521084
0x00521084:	jb 0x00521044
0x00521086:	addl %ebx, %ebx
0x00521088:	jne 0x00521091
0x00521091:	adcl %ecx, %ecx
0x00521093:	addl %ebx, %ebx
0x00521095:	jae 0x00521086
0x00521097:	jne 0x005210a2
0x005210a2:	addl %ecx, $0x2<UINT8>
0x0052102b:	movl %ebx, (%esi)
0x0052102d:	subl %esi, $0xfffffffc<UINT8>
0x00521030:	adcl %ebx, %ebx
0x00521032:	jb 0x00521053
0x00521048:	movl %ebx, (%esi)
0x0052104a:	subl %esi, $0xfffffffc<UINT8>
0x0052104d:	adcl %ebx, %ebx
0x0052101c:	movl %ebx, (%esi)
0x0052101e:	subl %esi, $0xfffffffc<UINT8>
0x00521021:	adcl %ebx, %ebx
0x00521034:	decl %eax
0x00521035:	addl %ebx, %ebx
0x00521037:	jne 0x00521040
0x00521040:	adcl %eax, %eax
0x00521042:	jmp 0x00521018
0x00521039:	movl %ebx, (%esi)
0x0052103b:	subl %esi, $0xfffffffc<UINT8>
0x0052103e:	adcl %ebx, %ebx
0x00521099:	movl %ebx, (%esi)
0x0052109b:	subl %esi, $0xfffffffc<UINT8>
0x0052109e:	adcl %ebx, %ebx
0x005210a0:	jae 0x00521086
0x0052107d:	movl %ebx, (%esi)
0x0052107f:	subl %esi, $0xfffffffc<UINT8>
0x00521082:	adcl %ebx, %ebx
0x0052108a:	movl %ebx, (%esi)
0x0052108c:	subl %esi, $0xfffffffc<UINT8>
0x0052108f:	adcl %ebx, %ebx
0x0052106f:	movl %ebx, (%esi)
0x00521071:	subl %esi, $0xfffffffc<UINT8>
0x00521074:	adcl %ebx, %ebx
0x005210da:	popl %esi
0x005210db:	movl %edi, %esi
0x005210dd:	movl %ecx, $0x4eb5<UINT32>
0x005210e2:	movb %al, (%edi)
0x005210e4:	incl %edi
0x005210e5:	subb %al, $0xffffffe8<UINT8>
0x005210e7:	cmpb %al, $0x1<UINT8>
0x005210e9:	ja 0x005210e2
0x005210eb:	cmpb (%edi), $0x11<UINT8>
0x005210ee:	jne 0x005210e2
0x005210f0:	movl %eax, (%edi)
0x005210f2:	movb %bl, 0x4(%edi)
0x005210f5:	shrw %ax, $0x8<UINT8>
0x005210f9:	roll %eax, $0x10<UINT8>
0x005210fc:	xchgb %ah, %al
0x005210fe:	subl %eax, %edi
0x00521100:	subb %bl, $0xffffffe8<UINT8>
0x00521103:	addl %eax, %esi
0x00521105:	movl (%edi), %eax
0x00521107:	addl %edi, $0x5<UINT8>
0x0052110a:	movb %al, %bl
0x0052110c:	loop 0x005210e7
0x0052110e:	leal %edi, 0x119000(%esi)
0x00521114:	movl %eax, (%edi)
0x00521116:	orl %eax, %eax
0x00521118:	je 0x0052115f
0x0052111a:	movl %ebx, 0x4(%edi)
0x0052111d:	leal %eax, 0x13c1fc(%eax,%esi)
0x00521124:	addl %ebx, %esi
0x00521126:	pushl %eax
0x00521127:	addl %edi, $0x8<UINT8>
0x0052112a:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00521130:	xchgl %ebp, %eax
0x00521131:	movb %al, (%edi)
0x00521133:	incl %edi
0x00521134:	orb %al, %al
0x00521136:	je 0x00521114
0x00521138:	movl %ecx, %edi
0x0052113a:	jns 0x00521143
0x00521143:	pushl %edi
0x00521144:	decl %eax
0x00521145:	repn scasb %al, %es:(%edi)
0x00521147:	pushl %ebp
0x00521148:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x0052114e:	orl %eax, %eax
0x00521150:	je 7
0x00521152:	movl (%ebx), %eax
0x00521154:	addl %ebx, $0x4<UINT8>
0x00521157:	jmp 0x00521131
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x0052113c:	movzwl %eax, (%edi)
0x0052113f:	incl %edi
0x00521140:	pushl %eax
0x00521141:	incl %edi
0x00521142:	movl %ecx, $0xaef24857<UINT32>
0x0052115f:	addl %edi, $0x4<UINT8>
0x00521162:	leal %ebx, -4(%esi)
0x00521165:	xorl %eax, %eax
0x00521167:	movb %al, (%edi)
0x00521169:	incl %edi
0x0052116a:	orl %eax, %eax
0x0052116c:	je 0x00521190
0x0052116e:	cmpb %al, $0xffffffef<UINT8>
0x00521170:	ja 0x00521183
0x00521172:	addl %ebx, %eax
0x00521174:	movl %eax, (%ebx)
0x00521176:	xchgb %ah, %al
0x00521178:	roll %eax, $0x10<UINT8>
0x0052117b:	xchgb %ah, %al
0x0052117d:	addl %eax, %esi
0x0052117f:	movl (%ebx), %eax
0x00521181:	jmp 0x00521165
0x00521183:	andb %al, $0xf<UINT8>
0x00521185:	shll %eax, $0x10<UINT8>
0x00521188:	movw %ax, (%edi)
0x0052118b:	addl %edi, $0x2<UINT8>
0x0052118e:	jmp 0x00521172
0x00521190:	movl %ebp, 0x13c334(%esi)
0x00521196:	leal %edi, -4096(%esi)
0x0052119c:	movl %ebx, $0x1000<UINT32>
0x005211a1:	pushl %eax
0x005211a2:	pushl %esp
0x005211a3:	pushl $0x4<UINT8>
0x005211a5:	pushl %ebx
0x005211a6:	pushl %edi
0x005211a7:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x005211a9:	leal %eax, 0x23f(%edi)
0x005211af:	andb (%eax), $0x7f<UINT8>
0x005211b2:	andb 0x28(%eax), $0x7f<UINT8>
0x005211b6:	popl %eax
0x005211b7:	pushl %eax
0x005211b8:	pushl %esp
0x005211b9:	pushl %eax
0x005211ba:	pushl %ebx
0x005211bb:	pushl %edi
0x005211bc:	call VirtualProtect@kernel32.dll
0x005211be:	popl %eax
0x005211bf:	popa
0x005211c0:	leal %eax, -128(%esp)
0x005211c4:	pushl $0x0<UINT8>
0x005211c6:	cmpl %esp, %eax
0x005211c8:	jne 0x005211c4
0x005211ca:	subl %esp, $0xffffff80<UINT8>
0x005211cd:	jmp 0x0046db4b
0x0046db4b:	call 0x0046e1d8
0x0046e1d8:	movl %ecx, 0x4ed06c
0x0046e1de:	pushl %esi
0x0046e1df:	pushl %edi
0x0046e1e0:	movl %edi, $0xbb40e64e<UINT32>
0x0046e1e5:	movl %esi, $0xffff0000<UINT32>
0x0046e1ea:	cmpl %ecx, %edi
0x0046e1ec:	je 0x0046e1f2
0x0046e1f2:	call 0x0046e18b
0x0046e18b:	pushl %ebp
0x0046e18c:	movl %ebp, %esp
0x0046e18e:	subl %esp, $0x14<UINT8>
0x0046e191:	andl -12(%ebp), $0x0<UINT8>
0x0046e195:	leal %eax, -12(%ebp)
0x0046e198:	andl -8(%ebp), $0x0<UINT8>
0x0046e19c:	pushl %eax
0x0046e19d:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0046e1a3:	movl %eax, -8(%ebp)
0x0046e1a6:	xorl %eax, -12(%ebp)
0x0046e1a9:	movl -4(%ebp), %eax
0x0046e1ac:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0046e1b2:	xorl -4(%ebp), %eax
0x0046e1b5:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0046e1bb:	xorl -4(%ebp), %eax
0x0046e1be:	leal %eax, -20(%ebp)
0x0046e1c1:	pushl %eax
0x0046e1c2:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0046e1c8:	movl %eax, -16(%ebp)
0x0046e1cb:	leal %ecx, -4(%ebp)
0x0046e1ce:	xorl %eax, -20(%ebp)
0x0046e1d1:	xorl %eax, -4(%ebp)
0x0046e1d4:	xorl %eax, %ecx
0x0046e1d6:	leave
0x0046e1d7:	ret

0x0046e1f7:	movl %ecx, %eax
0x0046e1f9:	cmpl %ecx, %edi
0x0046e1fb:	jne 0x0046e204
0x0046e204:	testl %esi, %ecx
0x0046e206:	jne 0x0046e212
0x0046e212:	movl 0x4ed06c, %ecx
0x0046e218:	notl %ecx
0x0046e21a:	popl %edi
0x0046e21b:	movl 0x4ed068, %ecx
0x0046e221:	popl %esi
0x0046e222:	ret

0x0046db50:	jmp 0x0046d9cf
0x0046d9cf:	pushl $0x14<UINT8>
0x0046d9d1:	pushl $0x4e7900<UINT32>
0x0046d9d6:	call 0x0046e130
0x0046e130:	pushl $0x49ddc0<UINT32>
0x0046e135:	pushl %fs:0
0x0046e13c:	movl %eax, 0x10(%esp)
0x0046e140:	movl 0x10(%esp), %ebp
0x0046e144:	leal %ebp, 0x10(%esp)
0x0046e148:	subl %esp, %eax
0x0046e14a:	pushl %ebx
0x0046e14b:	pushl %esi
0x0046e14c:	pushl %edi
0x0046e14d:	movl %eax, 0x4ed06c
0x0046e152:	xorl -4(%ebp), %eax
0x0046e155:	xorl %eax, %ebp
0x0046e157:	pushl %eax
0x0046e158:	movl -24(%ebp), %esp
0x0046e15b:	pushl -8(%ebp)
0x0046e15e:	movl %eax, -4(%ebp)
0x0046e161:	movl -4(%ebp), $0xfffffffe<UINT32>
0x0046e168:	movl -8(%ebp), %eax
0x0046e16b:	leal %eax, -16(%ebp)
0x0046e16e:	movl %fs:0, %eax
0x0046e174:	repn ret

0x0046d9db:	pushl $0x1<UINT8>
0x0046d9dd:	call 0x0046d21b
0x0046d21b:	pushl %ebp
0x0046d21c:	movl %ebp, %esp
0x0046d21e:	cmpl 0x8(%ebp), $0x0<UINT8>
0x0046d222:	jne 0x0046d22b
0x0046d22b:	call 0x0046dda1
0x0046dda1:	pushl %ebp
0x0046dda2:	movl %ebp, %esp
0x0046dda4:	andl 0x4f04b4, $0x0<UINT8>
0x0046ddab:	subl %esp, $0x24<UINT8>
0x0046ddae:	pushl %ebx
0x0046ddaf:	xorl %ebx, %ebx
0x0046ddb1:	incl %ebx
0x0046ddb2:	orl 0x4ed080, %ebx
0x0046ddb8:	pushl $0xa<UINT8>
0x0046ddba:	call 0x004c10b9
0x004c10b9:	jmp IsProcessorFeaturePresent@KERNEL32.DLL
IsProcessorFeaturePresent@KERNEL32.DLL: API Node	
0x0046ddbf:	testl %eax, %eax
0x0046ddc1:	je 364
0x0046ddc7:	andl -16(%ebp), $0x0<UINT8>
0x0046ddcb:	xorl %eax, %eax
0x0046ddcd:	orl 0x4ed080, $0x2<UINT8>
0x0046ddd4:	xorl %ecx, %ecx
0x0046ddd6:	pushl %esi
0x0046ddd7:	pushl %edi
0x0046ddd8:	movl 0x4f04b4, %ebx
0x0046ddde:	leal %edi, -36(%ebp)
0x0046dde1:	pushl %ebx
0x0046dde2:	cpuid
0x0046dde4:	movl %esi, %ebx
0x0046dde6:	popl %ebx
0x0046dde7:	movl (%edi), %eax
0x0046dde9:	movl 0x4(%edi), %esi
0x0046ddec:	movl 0x8(%edi), %ecx
0x0046ddef:	xorl %ecx, %ecx
0x0046ddf1:	movl 0xc(%edi), %edx
0x0046ddf4:	movl %eax, -36(%ebp)
0x0046ddf7:	movl %edi, -32(%ebp)
0x0046ddfa:	movl -12(%ebp), %eax
0x0046ddfd:	xorl %edi, $0x756e6547<UINT32>
0x0046de03:	movl %eax, -24(%ebp)
0x0046de06:	xorl %eax, $0x49656e69<UINT32>
0x0046de0b:	movl -8(%ebp), %eax
0x0046de0e:	movl %eax, -28(%ebp)
0x0046de11:	xorl %eax, $0x6c65746e<UINT32>
0x0046de16:	movl -4(%ebp), %eax
0x0046de19:	xorl %eax, %eax
0x0046de1b:	incl %eax
0x0046de1c:	pushl %ebx
0x0046de1d:	cpuid
0x0046de1f:	movl %esi, %ebx
0x0046de21:	popl %ebx
0x0046de22:	leal %ebx, -36(%ebp)
0x0046de25:	movl (%ebx), %eax
0x0046de27:	movl %eax, -4(%ebp)
0x0046de2a:	orl %eax, -8(%ebp)
0x0046de2d:	orl %eax, %edi
0x0046de2f:	movl 0x4(%ebx), %esi
0x0046de32:	movl 0x8(%ebx), %ecx
0x0046de35:	movl 0xc(%ebx), %edx
0x0046de38:	jne 67
0x0046de3a:	movl %eax, -36(%ebp)
0x0046de3d:	andl %eax, $0xfff3ff0<UINT32>
0x0046de42:	cmpl %eax, $0x106c0<UINT32>
0x0046de47:	je 35
0x0046de49:	cmpl %eax, $0x20660<UINT32>
0x0046de4e:	je 28
0x0046de50:	cmpl %eax, $0x20670<UINT32>
0x0046de55:	je 21
0x0046de57:	cmpl %eax, $0x30650<UINT32>
0x0046de5c:	je 14
0x0046de5e:	cmpl %eax, $0x30660<UINT32>
0x0046de63:	je 7
0x0046de65:	cmpl %eax, $0x30670<UINT32>
0x0046de6a:	jne 0x0046de7d
0x0046de7d:	movl %edi, 0x4f04b8
0x0046de83:	cmpl -12(%ebp), $0x7<UINT8>
0x0046de87:	movl %eax, -28(%ebp)
0x0046de8a:	movl -4(%ebp), %eax
0x0046de8d:	jl 0x0046dec1
0x0046dec1:	movl %ebx, -16(%ebp)
0x0046dec4:	popl %edi
0x0046dec5:	popl %esi
0x0046dec6:	testl %eax, $0x100000<UINT32>
0x0046decb:	je 0x0046df33
0x0046df33:	xorl %eax, %eax
0x0046df35:	popl %ebx
0x0046df36:	leave
0x0046df37:	ret

0x0046d230:	call 0x0049dd31
0x0049dd31:	call 0x0049edd9
0x0049edd9:	movl %eax, 0x4ed06c
0x0049edde:	movl 0x4f05e4, %eax
0x0049ede3:	ret

0x0049dd36:	call 0x0049f0bb
0x0049f0bb:	movl %ecx, $0x4f0660<UINT32>
0x0049f0c0:	movl %eax, $0x4f064c<UINT32>
0x0049f0c5:	xorl %edx, %edx
0x0049f0c7:	cmpl %ecx, %eax
0x0049f0c9:	pushl %esi
0x0049f0ca:	movl %esi, 0x4ed06c
0x0049f0d0:	sbbl %ecx, %ecx
0x0049f0d2:	andl %ecx, $0xfffffffb<UINT8>
0x0049f0d5:	addl %ecx, $0x5<UINT8>
0x0049f0d8:	incl %edx
0x0049f0d9:	movl (%eax), %esi
0x0049f0db:	leal %eax, 0x4(%eax)
0x0049f0de:	cmpl %edx, %ecx
0x0049f0e0:	jne 0x0049f0d8
0x0049f0e2:	popl %esi
0x0049f0e3:	ret

0x0049dd3b:	call 0x0049ede4
0x0049ede4:	pushl %esi
0x0049ede5:	pushl %edi
0x0049ede6:	movl %edi, $0x4f0624<UINT32>
0x0049edeb:	xorl %esi, %esi
0x0049eded:	pushl $0x0<UINT8>
0x0049edef:	pushl $0xfa0<UINT32>
0x0049edf4:	pushl %edi
0x0049edf5:	call 0x0049f074
0x0049f074:	pushl %ebp
0x0049f075:	movl %ebp, %esp
0x0049f077:	pushl %esi
0x0049f078:	pushl $0x4d0e34<UINT32>
0x0049f07d:	pushl $0x4d0e2c<UINT32>
0x0049f082:	pushl $0x4cb558<UINT32>
0x0049f087:	pushl $0x4<UINT8>
0x0049f089:	call 0x0049ef13
0x0049ef13:	pushl %ebp
0x0049ef14:	movl %ebp, %esp
0x0049ef16:	movl %eax, 0x8(%ebp)
0x0049ef19:	pushl %edi
0x0049ef1a:	leal %edi, 0x4f064c(,%eax,4)
0x0049ef21:	movl %eax, (%edi)
0x0049ef23:	movl %edx, 0x4ed06c
0x0049ef29:	movl %ecx, %edx
0x0049ef2b:	andl %ecx, $0x1f<UINT8>
0x0049ef2e:	xorl %edx, %eax
0x0049ef30:	rorl %edx, %cl
0x0049ef32:	cmpl %edx, $0xffffffff<UINT8>
0x0049ef35:	jne 0x0049ef3b
0x0049ef3b:	testl %edx, %edx
0x0049ef3d:	je 0x0049ef43
0x0049ef43:	pushl %esi
0x0049ef44:	pushl 0x14(%ebp)
0x0049ef47:	pushl 0x10(%ebp)
0x0049ef4a:	call 0x0049ee4f
0x0049ee4f:	pushl %ebp
0x0049ee50:	movl %ebp, %esp
0x0049ee52:	pushl %ecx
0x0049ee53:	pushl %ebx
0x0049ee54:	pushl %esi
0x0049ee55:	pushl %edi
0x0049ee56:	movl %edi, 0x8(%ebp)
0x0049ee59:	jmp 0x0049eeff
0x0049eeff:	cmpl %edi, 0xc(%ebp)
0x0049ef02:	jne 0x0049ee5e
0x0049ee5e:	movl %ebx, (%edi)
0x0049ee60:	leal %eax, 0x4f0640(,%ebx,4)
0x0049ee67:	movl %esi, (%eax)
0x0049ee69:	movl -4(%ebp), %eax
0x0049ee6c:	testl %esi, %esi
0x0049ee6e:	je 0x0049ee7b
0x0049ee7b:	movl %ebx, 0x4d0d54(,%ebx,4)
0x0049ee82:	pushl $0x800<UINT32>
0x0049ee87:	pushl $0x0<UINT8>
0x0049ee89:	pushl %ebx
0x0049ee8a:	call LoadLibraryExW@KERNEL32.DLL
LoadLibraryExW@KERNEL32.DLL: API Node	
0x0049ee90:	movl %esi, %eax
0x0049ee92:	testl %esi, %esi
0x0049ee94:	jne 0x0049eee6
0x0049eee6:	movl %ecx, -4(%ebp)
0x0049eee9:	movl %eax, %esi
0x0049eeeb:	xchgl (%ecx), %eax
0x0049eeed:	testl %eax, %eax
0x0049eeef:	je 0x0049eef8
0x0049eef8:	testl %esi, %esi
0x0049eefa:	jne 0x0049ef0f
0x0049ef0f:	movl %eax, %esi
0x0049ef11:	jmp 0x0049ef0a
0x0049ef0a:	popl %edi
0x0049ef0b:	popl %esi
0x0049ef0c:	popl %ebx
0x0049ef0d:	leave
0x0049ef0e:	ret

0x0049ef4f:	popl %ecx
0x0049ef50:	popl %ecx
0x0049ef51:	testl %eax, %eax
0x0049ef53:	je 29
0x0049ef55:	pushl 0xc(%ebp)
0x0049ef58:	pushl %eax
0x0049ef59:	call GetProcAddress@KERNEL32.DLL
0x0049ef5f:	movl %esi, %eax
0x0049ef61:	testl %esi, %esi
0x0049ef63:	je 0x0049ef72
0x0049ef72:	pushl $0xffffffff<UINT8>
0x0049ef74:	call 0x0046d188
0x0046d188:	pushl %ebp
0x0046d189:	movl %ebp, %esp
0x0046d18b:	movl %eax, 0x4ed06c
0x0046d190:	andl %eax, $0x1f<UINT8>
0x0046d193:	pushl $0x20<UINT8>
0x0046d195:	popl %ecx
0x0046d196:	subl %ecx, %eax
0x0046d198:	movl %eax, 0x8(%ebp)
0x0046d19b:	rorl %eax, %cl
0x0046d19d:	xorl %eax, 0x4ed06c
0x0046d1a3:	popl %ebp
0x0046d1a4:	ret

0x0049ef79:	popl %ecx
0x0049ef7a:	xchgl (%edi), %eax
0x0049ef7c:	xorl %eax, %eax
0x0049ef7e:	popl %esi
0x0049ef7f:	popl %edi
0x0049ef80:	popl %ebp
0x0049ef81:	ret

0x0049f08e:	movl %esi, %eax
0x0049f090:	addl %esp, $0x10<UINT8>
0x0049f093:	testl %esi, %esi
0x0049f095:	je 0x0049f0ac
0x0049f0ac:	pushl 0xc(%ebp)
0x0049f0af:	pushl 0x8(%ebp)
0x0049f0b2:	call InitializeCriticalSectionAndSpinCount@KERNEL32.DLL
InitializeCriticalSectionAndSpinCount@KERNEL32.DLL: API Node	
0x0049f0b8:	popl %esi
0x0049f0b9:	popl %ebp
0x0049f0ba:	ret

0x0049edfa:	addl %esp, $0xc<UINT8>
0x0049edfd:	testl %eax, %eax
0x0049edff:	je 21
0x0049ee01:	incl 0x4f063c
0x0049ee07:	addl %esi, $0x18<UINT8>
0x0049ee0a:	addl %edi, $0x18<UINT8>
0x0049ee0d:	cmpl %esi, $0x18<UINT8>
0x0049ee10:	jb -37
0x0049ee12:	movb %al, $0x1<UINT8>
0x0049ee14:	jmp 0x0049ee1d
0x0049ee1d:	popl %edi
0x0049ee1e:	popl %esi
0x0049ee1f:	ret

0x0049dd40:	testb %al, %al
0x0049dd42:	jne 0x0049dd47
0x0049dd47:	call 0x0049e00a
0x0049e00a:	pushl $0x49df17<UINT32>
0x0049e00f:	call 0x0049ef82
0x0049ef82:	pushl %ebp
0x0049ef83:	movl %ebp, %esp
0x0049ef85:	pushl %esi
0x0049ef86:	pushl $0x4d0e14<UINT32>
0x0049ef8b:	pushl $0x4d0e0c<UINT32>
0x0049ef90:	pushl $0x4cb52c<UINT32>
0x0049ef95:	pushl $0x0<UINT8>
0x0049ef97:	call 0x0049ef13
0x0049ee96:	call GetLastError@KERNEL32.DLL
GetLastError@KERNEL32.DLL: API Node	
0x0049ee9c:	cmpl %eax, $0x57<UINT8>
0x0049ee9f:	jne 0x0049eed6
0x0049eed6:	xorl %esi, %esi
0x0049eed8:	testl %esi, %esi
0x0049eeda:	jne 10
0x0049eedc:	movl %ecx, -4(%ebp)
0x0049eedf:	orl %eax, $0xffffffff<UINT8>
0x0049eee2:	xchgl (%ecx), %eax
0x0049eee4:	jmp 0x0049eefc
0x0049eefc:	addl %edi, $0x4<UINT8>
0x0049ef65:	pushl %esi
0x0049ef66:	call 0x0046d188
0x0049ef6b:	popl %ecx
0x0049ef6c:	xchgl (%edi), %eax
0x0049ef6e:	movl %eax, %esi
0x0049ef70:	jmp 0x0049ef7e
0x0049ef9c:	movl %esi, %eax
0x0049ef9e:	addl %esp, $0x10<UINT8>
0x0049efa1:	testl %esi, %esi
0x0049efa3:	je 16
0x0049efa5:	pushl 0x8(%ebp)
0x0049efa8:	movl %ecx, %esi
0x0049efaa:	call 0x00403560
0x00403560:	ret

0x0049efb0:	call FlsAlloc@kernel32.dll
FlsAlloc@kernel32.dll: API Node	
0x0049efb2:	popl %esi
0x0049efb3:	popl %ebp
0x0049efb4:	ret

0x0049e014:	movl 0x4ed340, %eax
0x0049e019:	popl %ecx
0x0049e01a:	cmpl %eax, $0xffffffff<UINT8>
0x0049e01d:	jne 0x0049e022
0x0049e022:	pushl $0x4f05bc<UINT32>
0x0049e027:	pushl %eax
0x0049e028:	call 0x0049f036
0x0049f036:	pushl %ebp
0x0049f037:	movl %ebp, %esp
0x0049f039:	pushl %esi
0x0049f03a:	pushl $0x4d0e2c<UINT32>
0x0049f03f:	pushl $0x4d0e24<UINT32>
0x0049f044:	pushl $0x4cb54c<UINT32>
0x0049f049:	pushl $0x3<UINT8>
0x0049f04b:	call 0x0049ef13
0x0049ee70:	cmpl %esi, $0xffffffff<UINT8>
0x0049ee73:	je 0x0049eefc
0x0049ee79:	jmp 0x0049eef8
0x0049f050:	addl %esp, $0x10<UINT8>
0x0049f053:	movl %esi, %eax
0x0049f055:	pushl 0xc(%ebp)
0x0049f058:	pushl 0x8(%ebp)
0x0049f05b:	testl %esi, %esi
0x0049f05d:	je 12
0x0049f05f:	movl %ecx, %esi
0x0049f061:	call 0x00403560
0x0049f067:	call FlsSetValue@kernel32.dll
FlsSetValue@kernel32.dll: API Node	
0x0049f069:	jmp 0x0049f071
0x0049f071:	popl %esi
0x0049f072:	popl %ebp
0x0049f073:	ret

0x0049e02d:	popl %ecx
0x0049e02e:	popl %ecx
0x0049e02f:	testl %eax, %eax
0x0049e031:	jne 0x0049e03a
0x0049e03a:	movb %al, $0x1<UINT8>
0x0049e03c:	ret

0x0049dd4c:	testb %al, %al
0x0049dd4e:	jne 0x0049dd57
0x0049dd57:	movb %al, $0x1<UINT8>
0x0049dd59:	ret

0x0046d235:	testb %al, %al
0x0046d237:	jne 0x0046d23d
0x0046d23d:	call 0x004b0417
0x004b0417:	pushl $0x4d2640<UINT32>
0x004b041c:	pushl $0x4d25c8<UINT32>
0x004b0421:	call 0x004ba675
0x004ba675:	movl %edi, %edi
0x004ba677:	pushl %ebp
0x004ba678:	movl %ebp, %esp
0x004ba67a:	pushl %ecx
0x004ba67b:	movl %eax, 0x4ed06c
0x004ba680:	xorl %eax, %ebp
0x004ba682:	movl -4(%ebp), %eax
0x004ba685:	pushl %edi
0x004ba686:	movl %edi, 0x8(%ebp)
0x004ba689:	cmpl %edi, 0xc(%ebp)
0x004ba68c:	jne 0x004ba692
0x004ba692:	pushl %esi
0x004ba693:	movl %esi, %edi
0x004ba695:	pushl %ebx
0x004ba696:	movl %ebx, (%esi)
0x004ba698:	testl %ebx, %ebx
0x004ba69a:	je 0x004ba6aa
0x004ba69c:	movl %ecx, %ebx
0x004ba69e:	call 0x00403560
0x004ba6a4:	call 0x004b0338
0x004b0326:	pushl $0x4ed498<UINT32>
0x004b032b:	movl %ecx, $0x4f0a14<UINT32>
0x004b0330:	call 0x0049f40e
0x0049f40e:	movl %edi, %edi
0x0049f410:	pushl %ebp
0x0049f411:	movl %ebp, %esp
0x0049f413:	leal %eax, 0x4(%ecx)
0x0049f416:	movl %edx, %eax
0x0049f418:	subl %edx, %ecx
0x0049f41a:	addl %edx, $0x3<UINT8>
0x0049f41d:	pushl %esi
0x0049f41e:	xorl %esi, %esi
0x0049f420:	shrl %edx, $0x2<UINT8>
0x0049f423:	cmpl %eax, %ecx
0x0049f425:	sbbl %eax, %eax
0x0049f427:	notl %eax
0x0049f429:	andl %eax, %edx
0x0049f42b:	je 13
0x0049f42d:	movl %edx, 0x8(%ebp)
0x0049f430:	incl %esi
0x0049f431:	movl (%ecx), %edx
0x0049f433:	leal %ecx, 0x4(%ecx)
0x0049f436:	cmpl %esi, %eax
0x0049f438:	jne -10
0x0049f43a:	popl %esi
0x0049f43b:	popl %ebp
0x0049f43c:	ret $0x4<UINT16>

0x004b0335:	movb %al, $0x1<UINT8>
0x004b0337:	ret

0x004ba6a6:	testb %al, %al
0x004ba6a8:	je 8
0x004ba6aa:	addl %esi, $0x8<UINT8>
0x004ba6ad:	cmpl %esi, 0xc(%ebp)
0x004ba6b0:	jne 0x004ba696
0x004b035a:	movl %eax, 0x4ed06c
0x004b035f:	pushl %esi
0x004b0360:	pushl $0x20<UINT8>
0x004b0362:	andl %eax, $0x1f<UINT8>
0x004b0365:	xorl %esi, %esi
0x004b0367:	popl %ecx
0x004b0368:	subl %ecx, %eax
0x004b036a:	rorl %esi, %cl
0x004b036c:	xorl %esi, 0x4ed06c
0x004b0372:	pushl %esi
0x004b0373:	call 0x0049f57a
0x0049f57a:	movl %edi, %edi
0x0049f57c:	pushl %ebp
0x0049f57d:	movl %ebp, %esp
0x0049f57f:	pushl 0x8(%ebp)
0x0049f582:	movl %ecx, $0x4f0660<UINT32>
0x0049f587:	call 0x0049f40e
0x0049f58c:	popl %ebp
0x0049f58d:	ret

0x004b0378:	pushl %esi
0x004b0379:	call 0x004af346
0x004af346:	movl %edi, %edi
0x004af348:	pushl %ebp
0x004af349:	movl %ebp, %esp
0x004af34b:	pushl 0x8(%ebp)
0x004af34e:	movl %ecx, $0x4f07b4<UINT32>
0x004af353:	call 0x0049f40e
0x004af358:	popl %ebp
0x004af359:	ret

0x004b037e:	pushl %esi
0x004b037f:	call 0x004b8d44
0x004b8d44:	movl %edi, %edi
0x004b8d46:	pushl %ebp
0x004b8d47:	movl %ebp, %esp
0x004b8d49:	pushl 0x8(%ebp)
0x004b8d4c:	movl %ecx, $0x4f0d08<UINT32>
0x004b8d51:	call 0x0049f40e
0x004b8d56:	pushl 0x8(%ebp)
0x004b8d59:	movl %ecx, $0x4f0d0c<UINT32>
0x004b8d5e:	call 0x0049f40e
0x004b8d63:	pushl 0x8(%ebp)
0x004b8d66:	movl %ecx, $0x4f0d10<UINT32>
0x004b8d6b:	call 0x0049f40e
0x004b8d70:	pushl 0x8(%ebp)
0x004b8d73:	movl %ecx, $0x4f0d14<UINT32>
0x004b8d78:	call 0x0049f40e
0x004b8d7d:	popl %ebp
0x004b8d7e:	ret

0x004b0384:	pushl %esi
0x004b0385:	call 0x004b0469
0x004b0469:	movl %edi, %edi
0x004b046b:	pushl %ebp
0x004b046c:	movl %ebp, %esp
0x004b046e:	pushl 0x8(%ebp)
0x004b0471:	movl %ecx, $0x4f0a00<UINT32>
0x004b0476:	call 0x0049f40e
0x004b047b:	popl %ebp
0x004b047c:	ret

0x004b038a:	pushl %esi
0x004b038b:	call 0x004af79d
0x004af79d:	movl %edi, %edi
0x004af79f:	pushl %ebp
0x004af7a0:	movl %ebp, %esp
0x004af7a2:	movl %eax, 0x8(%ebp)
0x004af7a5:	movl 0x4f07bc, %eax
0x004af7aa:	popl %ebp
0x004af7ab:	ret

0x004b0390:	addl %esp, $0x14<UINT8>
0x004b0393:	movb %al, $0x1<UINT8>
0x004b0395:	popl %esi
0x004b0396:	ret

0x004b42f3:	movl %eax, 0x4ed06c
0x004b42f8:	pushl %edi
0x004b42f9:	pushl $0x20<UINT8>
0x004b42fb:	andl %eax, $0x1f<UINT8>
0x004b42fe:	movl %edi, $0x4f0c78<UINT32>
0x004b4303:	popl %ecx
0x004b4304:	subl %ecx, %eax
0x004b4306:	xorl %eax, %eax
0x004b4308:	rorl %eax, %cl
0x004b430a:	xorl %eax, 0x4ed06c
0x004b4310:	pushl $0x20<UINT8>
0x004b4312:	popl %ecx
0x004b4313:	rep stosl %es:(%edi), %eax
0x004b4315:	movb %al, $0x1<UINT8>
0x004b4317:	popl %edi
0x004b4318:	ret

0x0043e0a0:	movb %al, $0x1<UINT8>
0x0043e0a2:	ret

0x004aba94:	movl %edi, %edi
0x004aba96:	pushl %esi
0x004aba97:	pushl %edi
0x004aba98:	movl %edi, $0x4f0670<UINT32>
0x004aba9d:	xorl %esi, %esi
0x004aba9f:	pushl $0x0<UINT8>
0x004abaa1:	pushl $0xfa0<UINT32>
0x004abaa6:	pushl %edi
0x004abaa7:	call 0x004b40d4
0x004b40d4:	movl %edi, %edi
0x004b40d6:	pushl %ebp
0x004b40d7:	movl %ebp, %esp
0x004b40d9:	pushl %ecx
0x004b40da:	movl %eax, 0x4ed06c
0x004b40df:	xorl %eax, %ebp
0x004b40e1:	movl -4(%ebp), %eax
0x004b40e4:	pushl %esi
0x004b40e5:	pushl $0x4d32dc<UINT32>
0x004b40ea:	pushl $0x4d32d4<UINT32>
0x004b40ef:	pushl $0x4d32dc<UINT32>
0x004b40f4:	pushl $0x14<UINT8>
0x004b40f6:	call 0x004b3b70
0x004b3b70:	movl %edi, %edi
0x004b3b72:	pushl %ebp
0x004b3b73:	movl %ebp, %esp
0x004b3b75:	movl %eax, 0x8(%ebp)
0x004b3b78:	pushl %ebx
0x004b3b79:	pushl %esi
0x004b3b7a:	pushl %edi
0x004b3b7b:	leal %ebx, 0x4f0c78(,%eax,4)
0x004b3b82:	movl %eax, (%ebx)
0x004b3b84:	movl %edx, 0x4ed06c
0x004b3b8a:	orl %edi, $0xffffffff<UINT8>
0x004b3b8d:	movl %ecx, %edx
0x004b3b8f:	movl %esi, %edx
0x004b3b91:	andl %ecx, $0x1f<UINT8>
0x004b3b94:	xorl %esi, %eax
0x004b3b96:	rorl %esi, %cl
0x004b3b98:	cmpl %esi, %edi
0x004b3b9a:	je 0x004b3c05
0x004b3b9c:	testl %esi, %esi
0x004b3b9e:	je 0x004b3ba4
0x004b3ba4:	movl %esi, 0x10(%ebp)
0x004b3ba7:	cmpl %esi, 0x14(%ebp)
0x004b3baa:	je 26
0x004b3bac:	pushl (%esi)
0x004b3bae:	call 0x004b3c0c
0x004b3c0c:	movl %edi, %edi
0x004b3c0e:	pushl %ebp
0x004b3c0f:	movl %ebp, %esp
0x004b3c11:	movl %eax, 0x8(%ebp)
0x004b3c14:	pushl %edi
0x004b3c15:	leal %edi, 0x4f0c28(,%eax,4)
0x004b3c1c:	movl %ecx, (%edi)
0x004b3c1e:	testl %ecx, %ecx
0x004b3c20:	je 0x004b3c2d
0x004b3c2d:	pushl %ebx
0x004b3c2e:	movl %ebx, 0x4d2c70(,%eax,4)
0x004b3c35:	pushl %esi
0x004b3c36:	pushl $0x800<UINT32>
0x004b3c3b:	pushl $0x0<UINT8>
0x004b3c3d:	pushl %ebx
0x004b3c3e:	call LoadLibraryExW@KERNEL32.DLL
0x004b3c44:	movl %esi, %eax
0x004b3c46:	testl %esi, %esi
0x004b3c48:	jne 0x004b3c71
0x004b3c71:	movl %eax, %esi
0x004b3c73:	xchgl (%edi), %eax
0x004b3c75:	testl %eax, %eax
0x004b3c77:	je 0x004b3c80
0x004b3c80:	movl %eax, %esi
0x004b3c82:	popl %esi
0x004b3c83:	popl %ebx
0x004b3c84:	popl %edi
0x004b3c85:	popl %ebp
0x004b3c86:	ret

0x004b3bb3:	popl %ecx
0x004b3bb4:	testl %eax, %eax
0x004b3bb6:	jne 0x004b3be7
0x004b3be7:	movl %edx, 0x4ed06c
0x004b3bed:	jmp 0x004b3bc8
0x004b3bc8:	testl %eax, %eax
0x004b3bca:	je 41
0x004b3bcc:	pushl 0xc(%ebp)
0x004b3bcf:	pushl %eax
0x004b3bd0:	call GetProcAddress@KERNEL32.DLL
0x004b3bd6:	movl %esi, %eax
0x004b3bd8:	testl %esi, %esi
0x004b3bda:	je 0x004b3bef
0x004b3bef:	movl %edx, 0x4ed06c
0x004b3bf5:	movl %eax, %edx
0x004b3bf7:	pushl $0x20<UINT8>
0x004b3bf9:	andl %eax, $0x1f<UINT8>
0x004b3bfc:	popl %ecx
0x004b3bfd:	subl %ecx, %eax
0x004b3bff:	rorl %edi, %cl
0x004b3c01:	xorl %edi, %edx
0x004b3c03:	xchgl (%ebx), %edi
0x004b3c05:	xorl %eax, %eax
0x004b3c07:	popl %edi
0x004b3c08:	popl %esi
0x004b3c09:	popl %ebx
0x004b3c0a:	popl %ebp
0x004b3c0b:	ret

0x004b40fb:	movl %esi, %eax
0x004b40fd:	addl %esp, $0x10<UINT8>
0x004b4100:	testl %esi, %esi
0x004b4102:	je 0x004b4119
0x004b4119:	pushl 0xc(%ebp)
0x004b411c:	pushl 0x8(%ebp)
0x004b411f:	call InitializeCriticalSectionAndSpinCount@KERNEL32.DLL
0x004b4125:	movl %ecx, -4(%ebp)
0x004b4128:	xorl %ecx, %ebp
0x004b412a:	popl %esi
0x004b412b:	call 0x0046d108
0x0046d108:	cmpl %ecx, 0x4ed06c
0x0046d10e:	repn jne 2
0x0046d111:	repn ret

0x004b4130:	movl %esp, %ebp
0x004b4132:	popl %ebp
0x004b4133:	ret $0xc<UINT16>

0x004abaac:	testl %eax, %eax
0x004abaae:	je 24
0x004abab0:	incl 0x4f07a8
0x004abab6:	addl %esi, $0x18<UINT8>
0x004abab9:	addl %edi, $0x18<UINT8>
0x004ababc:	cmpl %esi, $0x138<UINT32>
0x004abac2:	jb 0x004aba9f
0x004abac4:	movb %al, $0x1<UINT8>
0x004abac6:	jmp 0x004abad2
0x004abad2:	popl %edi
0x004abad3:	popl %esi
0x004abad4:	ret

0x004ba65a:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x004ba660:	testl %eax, %eax
0x004ba662:	movl 0x4f0e20, %eax
0x004ba667:	setne %al
0x004ba66a:	ret

0x004b1ee3:	pushl $0x4b1cc5<UINT32>
0x004b1ee8:	call 0x004b3db6
0x004b3db6:	movl %edi, %edi
0x004b3db8:	pushl %ebp
0x004b3db9:	movl %ebp, %esp
0x004b3dbb:	pushl %ecx
0x004b3dbc:	movl %eax, 0x4ed06c
0x004b3dc1:	xorl %eax, %ebp
0x004b3dc3:	movl -4(%ebp), %eax
0x004b3dc6:	pushl %esi
0x004b3dc7:	pushl $0x4d3208<UINT32>
0x004b3dcc:	pushl $0x4d3200<UINT32>
0x004b3dd1:	pushl $0x4d3208<UINT32>
0x004b3dd6:	pushl $0x3<UINT8>
0x004b3dd8:	call 0x004b3b70
0x004b3c4a:	call GetLastError@KERNEL32.DLL
0x004b3c50:	cmpl %eax, $0x57<UINT8>
0x004b3c53:	jne 0x004b3c62
0x004b3c62:	xorl %esi, %esi
0x004b3c64:	testl %esi, %esi
0x004b3c66:	jne 9
0x004b3c68:	orl %eax, $0xffffffff<UINT8>
0x004b3c6b:	xchgl (%edi), %eax
0x004b3c6d:	xorl %eax, %eax
0x004b3c6f:	jmp 0x004b3c82
0x004b3bb8:	addl %esi, $0x4<UINT8>
0x004b3bbb:	cmpl %esi, 0x14(%ebp)
0x004b3bbe:	jne 0x004b3bac
0x004b3bdc:	pushl %esi
0x004b3bdd:	call 0x0046d188
0x004b3be2:	popl %ecx
0x004b3be3:	xchgl (%ebx), %eax
0x004b3be5:	jmp 0x004b3ba0
0x004b3ba0:	movl %eax, %esi
0x004b3ba2:	jmp 0x004b3c07
0x004b3ddd:	movl %esi, %eax
0x004b3ddf:	addl %esp, $0x10<UINT8>
0x004b3de2:	testl %esi, %esi
0x004b3de4:	je 15
0x004b3de6:	pushl 0x8(%ebp)
0x004b3de9:	movl %ecx, %esi
0x004b3deb:	call 0x00403560
0x004b3df1:	call FlsAlloc@kernel32.dll
0x004b3df3:	jmp 0x004b3dfb
0x004b3dfb:	movl %ecx, -4(%ebp)
0x004b3dfe:	xorl %ecx, %ebp
0x004b3e00:	popl %esi
0x004b3e01:	call 0x0046d108
0x004b3e06:	movl %esp, %ebp
0x004b3e08:	popl %ebp
0x004b3e09:	ret $0x4<UINT16>

0x004b1eed:	movl 0x4ed490, %eax
0x004b1ef2:	cmpl %eax, $0xffffffff<UINT8>
0x004b1ef5:	jne 0x004b1efa
0x004b1efa:	call 0x004b1e5e
0x004b1e5e:	movl %edi, %edi
0x004b1e60:	pushl %ebx
0x004b1e61:	pushl %esi
0x004b1e62:	pushl %edi
0x004b1e63:	call GetLastError@KERNEL32.DLL
0x004b1e69:	movl %esi, %eax
0x004b1e6b:	xorl %ebx, %ebx
0x004b1e6d:	movl %eax, 0x4ed490
0x004b1e72:	cmpl %eax, $0xffffffff<UINT8>
0x004b1e75:	je 12
0x004b1e77:	pushl %eax
0x004b1e78:	call 0x004b3e62
0x004b3e62:	movl %edi, %edi
0x004b3e64:	pushl %ebp
0x004b3e65:	movl %ebp, %esp
0x004b3e67:	pushl %ecx
0x004b3e68:	movl %eax, 0x4ed06c
0x004b3e6d:	xorl %eax, %ebp
0x004b3e6f:	movl -4(%ebp), %eax
0x004b3e72:	pushl %esi
0x004b3e73:	pushl $0x4d322c<UINT32>
0x004b3e78:	pushl $0x4d3224<UINT32>
0x004b3e7d:	pushl $0x4d322c<UINT32>
0x004b3e82:	pushl $0x5<UINT8>
0x004b3e84:	call 0x004b3b70
0x004b3c22:	leal %eax, 0x1(%ecx)
0x004b3c25:	negl %eax
0x004b3c27:	sbbl %eax, %eax
0x004b3c29:	andl %eax, %ecx
0x004b3c2b:	jmp 0x004b3c84
0x004b3e89:	addl %esp, $0x10<UINT8>
0x004b3e8c:	movl %esi, %eax
0x004b3e8e:	pushl 0x8(%ebp)
0x004b3e91:	testl %esi, %esi
0x004b3e93:	je 12
0x004b3e95:	movl %ecx, %esi
0x004b3e97:	call 0x00403560
0x004b3e9d:	call FlsGetValue@kernel32.dll
FlsGetValue@kernel32.dll: API Node	
0x004b3e9f:	jmp 0x004b3ea7
0x004b3ea7:	movl %ecx, -4(%ebp)
0x004b3eaa:	xorl %ecx, %ebp
0x004b3eac:	popl %esi
0x004b3ead:	call 0x0046d108
0x004b3eb2:	movl %esp, %ebp
0x004b3eb4:	popl %ebp
0x004b3eb5:	ret $0x4<UINT16>

0x004b1e7d:	movl %edi, %eax
0x004b1e7f:	testl %edi, %edi
0x004b1e81:	jne 0x004b1ed4
0x004b1e83:	pushl $0x364<UINT32>
0x004b1e88:	pushl $0x1<UINT8>
0x004b1e8a:	call 0x004b3a07
0x004b3a07:	movl %edi, %edi
0x004b3a09:	pushl %ebp
0x004b3a0a:	movl %ebp, %esp
0x004b3a0c:	pushl %esi
0x004b3a0d:	movl %esi, 0x8(%ebp)
0x004b3a10:	testl %esi, %esi
0x004b3a12:	je 12
0x004b3a14:	pushl $0xffffffe0<UINT8>
0x004b3a16:	xorl %edx, %edx
0x004b3a18:	popl %eax
0x004b3a19:	divl %eax, %esi
0x004b3a1b:	cmpl %eax, 0xc(%ebp)
0x004b3a1e:	jb 52
0x004b3a20:	imull %esi, 0xc(%ebp)
0x004b3a24:	testl %esi, %esi
0x004b3a26:	jne 0x004b3a3f
0x004b3a3f:	pushl %esi
0x004b3a40:	pushl $0x8<UINT8>
0x004b3a42:	pushl 0x4f0e20
0x004b3a48:	call HeapAlloc@KERNEL32.DLL
HeapAlloc@KERNEL32.DLL: API Node	
0x004b3a4e:	testl %eax, %eax
0x004b3a50:	je -39
0x004b3a52:	jmp 0x004b3a61
0x004b3a61:	popl %esi
0x004b3a62:	popl %ebp
0x004b3a63:	ret

0x004b1e8f:	movl %edi, %eax
0x004b1e91:	popl %ecx
0x004b1e92:	popl %ecx
0x004b1e93:	testl %edi, %edi
0x004b1e95:	jne 0x004b1ea0
0x004b1ea0:	pushl %edi
0x004b1ea1:	pushl 0x4ed490
0x004b1ea7:	call 0x004b3eb8
0x004b3eb8:	movl %edi, %edi
0x004b3eba:	pushl %ebp
0x004b3ebb:	movl %ebp, %esp
0x004b3ebd:	pushl %ecx
0x004b3ebe:	movl %eax, 0x4ed06c
0x004b3ec3:	xorl %eax, %ebp
0x004b3ec5:	movl -4(%ebp), %eax
0x004b3ec8:	pushl %esi
0x004b3ec9:	pushl $0x4d3240<UINT32>
0x004b3ece:	pushl $0x4d3238<UINT32>
0x004b3ed3:	pushl $0x4d3240<UINT32>
0x004b3ed8:	pushl $0x6<UINT8>
0x004b3eda:	call 0x004b3b70
0x004b3edf:	addl %esp, $0x10<UINT8>
0x004b3ee2:	movl %esi, %eax
0x004b3ee4:	pushl 0xc(%ebp)
0x004b3ee7:	pushl 0x8(%ebp)
0x004b3eea:	testl %esi, %esi
0x004b3eec:	je 12
0x004b3eee:	movl %ecx, %esi
0x004b3ef0:	call 0x00403560
0x004b3ef6:	call FlsSetValue@kernel32.dll
0x004b3ef8:	jmp 0x004b3f00
0x004b3f00:	movl %ecx, -4(%ebp)
0x004b3f03:	xorl %ecx, %ebp
0x004b3f05:	popl %esi
0x004b3f06:	call 0x0046d108
0x004b3f0b:	movl %esp, %ebp
0x004b3f0d:	popl %ebp
0x004b3f0e:	ret $0x8<UINT16>

0x004b1eac:	testl %eax, %eax
0x004b1eae:	jne 0x004b1eb3
0x004b1eb3:	pushl $0x4f0a14<UINT32>
0x004b1eb8:	pushl %edi
0x004b1eb9:	call 0x004b1c4c
0x004b1c4c:	movl %edi, %edi
0x004b1c4e:	pushl %ebp
0x004b1c4f:	movl %ebp, %esp
0x004b1c51:	pushl %ecx
0x004b1c52:	pushl %ecx
0x004b1c53:	movl %eax, 0x8(%ebp)
0x004b1c56:	xorl %ecx, %ecx
0x004b1c58:	incl %ecx
0x004b1c59:	pushl $0x43<UINT8>
0x004b1c5b:	movl 0x18(%eax), %ecx
0x004b1c5e:	movl %eax, 0x8(%ebp)
0x004b1c61:	movl (%eax), $0x4d2500<UINT32>
0x004b1c67:	movl %eax, 0x8(%ebp)
0x004b1c6a:	movl 0x350(%eax), %ecx
0x004b1c70:	movl %eax, 0x8(%ebp)
0x004b1c73:	popl %ecx
0x004b1c74:	movl 0x48(%eax), $0x4eda40<UINT32>
0x004b1c7b:	movl %eax, 0x8(%ebp)
0x004b1c7e:	movw 0x6c(%eax), %cx
0x004b1c82:	movl %eax, 0x8(%ebp)
0x004b1c85:	movw 0x172(%eax), %cx
0x004b1c8c:	movl %eax, 0x8(%ebp)
0x004b1c8f:	andl 0x34c(%eax), $0x0<UINT8>
0x004b1c96:	leal %eax, 0x8(%ebp)
0x004b1c99:	movl -4(%ebp), %eax
0x004b1c9c:	leal %eax, -4(%ebp)
0x004b1c9f:	pushl %eax
0x004b1ca0:	pushl $0x5<UINT8>
0x004b1ca2:	call 0x004b1c24
0x004b1c24:	movl %edi, %edi
0x004b1c26:	pushl %ebp
0x004b1c27:	movl %ebp, %esp
0x004b1c29:	subl %esp, $0xc<UINT8>
0x004b1c2c:	movl %eax, 0x8(%ebp)
0x004b1c2f:	leal %ecx, -1(%ebp)
0x004b1c32:	movl -8(%ebp), %eax
0x004b1c35:	movl -12(%ebp), %eax
0x004b1c38:	leal %eax, -8(%ebp)
0x004b1c3b:	pushl %eax
0x004b1c3c:	pushl 0xc(%ebp)
0x004b1c3f:	leal %eax, -12(%ebp)
0x004b1c42:	pushl %eax
0x004b1c43:	call 0x004b1b64
0x004b1b64:	pushl $0x8<UINT8>
0x004b1b66:	pushl $0x4eaa98<UINT32>
0x004b1b6b:	call 0x0046e130
0x004b1b70:	movl %eax, 0x8(%ebp)
0x004b1b73:	pushl (%eax)
0x004b1b75:	call 0x004abad5
0x004abad5:	movl %edi, %edi
0x004abad7:	pushl %ebp
0x004abad8:	movl %ebp, %esp
0x004abada:	imull %eax, 0x8(%ebp), $0x18<UINT8>
0x004abade:	addl %eax, $0x4f0670<UINT32>
0x004abae3:	pushl %eax
0x004abae4:	call EnterCriticalSection@KERNEL32.DLL
EnterCriticalSection@KERNEL32.DLL: API Node	
0x004abaea:	popl %ebp
0x004abaeb:	ret

0x004b1b7a:	popl %ecx
0x004b1b7b:	andl -4(%ebp), $0x0<UINT8>
0x004b1b7f:	movl %eax, 0xc(%ebp)
0x004b1b82:	movl %eax, (%eax)
0x004b1b84:	movl %eax, (%eax)
0x004b1b86:	movl %eax, 0x48(%eax)
0x004b1b89:	incl (%eax)
0x004b1b8c:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004b1b93:	call 0x004b1ba0
0x004b1ba0:	movl %eax, 0x10(%ebp)
0x004b1ba3:	pushl (%eax)
0x004b1ba5:	call 0x004abb1d
0x004abb1d:	movl %edi, %edi
0x004abb1f:	pushl %ebp
0x004abb20:	movl %ebp, %esp
0x004abb22:	imull %eax, 0x8(%ebp), $0x18<UINT8>
0x004abb26:	addl %eax, $0x4f0670<UINT32>
0x004abb2b:	pushl %eax
0x004abb2c:	call LeaveCriticalSection@KERNEL32.DLL
LeaveCriticalSection@KERNEL32.DLL: API Node	
0x004abb32:	popl %ebp
0x004abb33:	ret

0x004b1baa:	popl %ecx
0x004b1bab:	ret

0x004b1b98:	call 0x0046e176
0x0046e176:	movl %ecx, -16(%ebp)
0x0046e179:	movl %fs:0, %ecx
0x0046e180:	popl %ecx
0x0046e181:	popl %edi
0x0046e182:	popl %edi
0x0046e183:	popl %esi
0x0046e184:	popl %ebx
0x0046e185:	movl %esp, %ebp
0x0046e187:	popl %ebp
0x0046e188:	pushl %ecx
0x0046e189:	repn ret

0x004b1b9d:	ret $0xc<UINT16>

0x004b1c48:	movl %esp, %ebp
0x004b1c4a:	popl %ebp
0x004b1c4b:	ret

0x004b1ca7:	leal %eax, 0x8(%ebp)
0x004b1caa:	movl -8(%ebp), %eax
0x004b1cad:	leal %eax, 0xc(%ebp)
0x004b1cb0:	movl -4(%ebp), %eax
0x004b1cb3:	leal %eax, -8(%ebp)
0x004b1cb6:	pushl %eax
0x004b1cb7:	pushl $0x4<UINT8>
0x004b1cb9:	call 0x004b1bd4
0x004b1bd4:	movl %edi, %edi
0x004b1bd6:	pushl %ebp
0x004b1bd7:	movl %ebp, %esp
0x004b1bd9:	subl %esp, $0xc<UINT8>
0x004b1bdc:	movl %eax, 0x8(%ebp)
0x004b1bdf:	leal %ecx, -1(%ebp)
0x004b1be2:	movl -8(%ebp), %eax
0x004b1be5:	movl -12(%ebp), %eax
0x004b1be8:	leal %eax, -8(%ebp)
0x004b1beb:	pushl %eax
0x004b1bec:	pushl 0xc(%ebp)
0x004b1bef:	leal %eax, -12(%ebp)
0x004b1bf2:	pushl %eax
0x004b1bf3:	call 0x004b1a68
0x004b1a68:	pushl $0x8<UINT8>
0x004b1a6a:	pushl $0x4eaab8<UINT32>
0x004b1a6f:	call 0x0046e130
0x004b1a74:	movl %eax, 0x8(%ebp)
0x004b1a77:	pushl (%eax)
0x004b1a79:	call 0x004abad5
0x004b1a7e:	popl %ecx
0x004b1a7f:	andl -4(%ebp), $0x0<UINT8>
0x004b1a83:	movl %ecx, 0xc(%ebp)
0x004b1a86:	movl %eax, 0x4(%ecx)
0x004b1a89:	movl %eax, (%eax)
0x004b1a8b:	pushl (%eax)
0x004b1a8d:	movl %eax, (%ecx)
0x004b1a8f:	pushl (%eax)
0x004b1a91:	call 0x004b1d8f
0x004b1d8f:	movl %edi, %edi
0x004b1d91:	pushl %ebp
0x004b1d92:	movl %ebp, %esp
0x004b1d94:	pushl %esi
0x004b1d95:	movl %esi, 0x8(%ebp)
0x004b1d98:	cmpl 0x4c(%esi), $0x0<UINT8>
0x004b1d9c:	je 0x004b1dc6
0x004b1dc6:	movl %eax, 0xc(%ebp)
0x004b1dc9:	movl 0x4c(%esi), %eax
0x004b1dcc:	popl %esi
0x004b1dcd:	testl %eax, %eax
0x004b1dcf:	je 7
0x004b1dd1:	pushl %eax
0x004b1dd2:	call 0x004bb6ce
0x004bb6ce:	movl %edi, %edi
0x004bb6d0:	pushl %ebp
0x004bb6d1:	movl %ebp, %esp
0x004bb6d3:	movl %eax, 0x8(%ebp)
0x004bb6d6:	incl 0xc(%eax)
0x004bb6da:	movl %ecx, 0x7c(%eax)
0x004bb6dd:	testl %ecx, %ecx
0x004bb6df:	je 0x004bb6e4
0x004bb6e4:	movl %ecx, 0x84(%eax)
0x004bb6ea:	testl %ecx, %ecx
0x004bb6ec:	je 0x004bb6f1
0x004bb6f1:	movl %ecx, 0x80(%eax)
0x004bb6f7:	testl %ecx, %ecx
0x004bb6f9:	je 0x004bb6fe
0x004bb6fe:	movl %ecx, 0x8c(%eax)
0x004bb704:	testl %ecx, %ecx
0x004bb706:	je 0x004bb70b
0x004bb70b:	pushl %esi
0x004bb70c:	pushl $0x6<UINT8>
0x004bb70e:	leal %ecx, 0x28(%eax)
0x004bb711:	popl %esi
0x004bb712:	cmpl -8(%ecx), $0x4ed558<UINT32>
0x004bb719:	je 0x004bb724
0x004bb71b:	movl %edx, (%ecx)
0x004bb71d:	testl %edx, %edx
0x004bb71f:	je 0x004bb724
0x004bb724:	cmpl -12(%ecx), $0x0<UINT8>
0x004bb728:	je 0x004bb734
0x004bb734:	addl %ecx, $0x10<UINT8>
0x004bb737:	subl %esi, $0x1<UINT8>
0x004bb73a:	jne 0x004bb712
0x004bb73c:	pushl 0x9c(%eax)
0x004bb742:	call 0x004bb895
0x004bb895:	movl %edi, %edi
0x004bb897:	pushl %ebp
0x004bb898:	movl %ebp, %esp
0x004bb89a:	movl %ecx, 0x8(%ebp)
0x004bb89d:	testl %ecx, %ecx
0x004bb89f:	je 22
0x004bb8a1:	cmpl %ecx, $0x4d2b08<UINT32>
0x004bb8a7:	je 0x004bb8b7
0x004bb8b7:	movl %eax, $0x7fffffff<UINT32>
0x004bb8bc:	popl %ebp
0x004bb8bd:	ret

0x004bb747:	popl %ecx
0x004bb748:	popl %esi
0x004bb749:	popl %ebp
0x004bb74a:	ret

0x004b1dd7:	popl %ecx
0x004b1dd8:	popl %ebp
0x004b1dd9:	ret

0x004b1a96:	popl %ecx
0x004b1a97:	popl %ecx
0x004b1a98:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004b1a9f:	call 0x004b1aac
0x004b1aac:	movl %eax, 0x10(%ebp)
0x004b1aaf:	pushl (%eax)
0x004b1ab1:	call 0x004abb1d
0x004b1ab6:	popl %ecx
0x004b1ab7:	ret

0x004b1aa4:	call 0x0046e176
0x004b1aa9:	ret $0xc<UINT16>

0x004b1bf8:	movl %esp, %ebp
0x004b1bfa:	popl %ebp
0x004b1bfb:	ret

0x004b1cbe:	addl %esp, $0x10<UINT8>
0x004b1cc1:	movl %esp, %ebp
0x004b1cc3:	popl %ebp
0x004b1cc4:	ret

0x004b1ebe:	pushl %ebx
0x004b1ebf:	call 0x004b2ce4
0x004b2ce4:	movl %edi, %edi
0x004b2ce6:	pushl %ebp
0x004b2ce7:	movl %ebp, %esp
0x004b2ce9:	cmpl 0x8(%ebp), $0x0<UINT8>
0x004b2ced:	je 0x004b2d1c
0x004b2d1c:	popl %ebp
0x004b2d1d:	ret

0x004b1ec4:	addl %esp, $0xc<UINT8>
0x004b1ec7:	testl %edi, %edi
0x004b1ec9:	jne 0x004b1ed4
0x004b1ed4:	pushl %esi
0x004b1ed5:	call SetLastError@KERNEL32.DLL
SetLastError@KERNEL32.DLL: API Node	
0x004b1edb:	movl %ebx, %edi
0x004b1edd:	popl %edi
0x004b1ede:	popl %esi
0x004b1edf:	movl %eax, %ebx
0x004b1ee1:	popl %ebx
0x004b1ee2:	ret

0x004b1eff:	testl %eax, %eax
0x004b1f01:	jne 0x004b1f0c
0x004b1f0c:	movb %al, $0x1<UINT8>
0x004b1f0e:	ret

0x004b25d7:	pushl $0xc<UINT8>
0x004b25d9:	pushl $0x4eab18<UINT32>
0x004b25de:	call 0x0046e130
0x004b25e3:	pushl $0x7<UINT8>
0x004b25e5:	call 0x004abad5
0x004b25ea:	popl %ecx
0x004b25eb:	xorl %ebx, %ebx
0x004b25ed:	movb -25(%ebp), %bl
0x004b25f0:	movl -4(%ebp), %ebx
0x004b25f3:	pushl %ebx
0x004b25f4:	call 0x004ba7f4
0x004ba7f4:	pushl $0x14<UINT8>
0x004ba7f6:	pushl $0x4ead18<UINT32>
0x004ba7fb:	call 0x0046e130
0x004ba800:	cmpl 0x8(%ebp), $0x2000<UINT32>
0x004ba807:	sbbl %eax, %eax
0x004ba809:	negl %eax
0x004ba80b:	jne 0x004ba824
0x004ba824:	xorl %esi, %esi
0x004ba826:	movl -28(%ebp), %esi
0x004ba829:	pushl $0x7<UINT8>
0x004ba82b:	call 0x004abad5
0x004ba830:	popl %ecx
0x004ba831:	movl -4(%ebp), %esi
0x004ba834:	movl %edi, %esi
0x004ba836:	movl %eax, 0x4f0c18
0x004ba83b:	movl -32(%ebp), %edi
0x004ba83e:	cmpl 0x8(%ebp), %eax
0x004ba841:	jl 0x004ba862
0x004ba843:	cmpl 0x4f0a18(,%edi,4), %esi
0x004ba84a:	jne 49
0x004ba84c:	call 0x004ba745
0x004ba745:	movl %edi, %edi
0x004ba747:	pushl %ebp
0x004ba748:	movl %ebp, %esp
0x004ba74a:	pushl %ecx
0x004ba74b:	pushl %ecx
0x004ba74c:	pushl %ebx
0x004ba74d:	pushl %edi
0x004ba74e:	pushl $0x30<UINT8>
0x004ba750:	pushl $0x40<UINT8>
0x004ba752:	call 0x004b3a07
0x004ba757:	movl %edi, %eax
0x004ba759:	xorl %ebx, %ebx
0x004ba75b:	movl -8(%ebp), %edi
0x004ba75e:	popl %ecx
0x004ba75f:	popl %ecx
0x004ba760:	testl %edi, %edi
0x004ba762:	jne 0x004ba768
0x004ba768:	leal %eax, 0xc00(%edi)
0x004ba76e:	cmpl %edi, %eax
0x004ba770:	je 62
0x004ba772:	pushl %esi
0x004ba773:	leal %esi, 0x20(%edi)
0x004ba776:	movl %edi, %eax
0x004ba778:	pushl %ebx
0x004ba779:	pushl $0xfa0<UINT32>
0x004ba77e:	leal %eax, -32(%esi)
0x004ba781:	pushl %eax
0x004ba782:	call 0x004b40d4
0x004ba787:	orl -8(%esi), $0xffffffff<UINT8>
0x004ba78b:	movl (%esi), %ebx
0x004ba78d:	leal %esi, 0x30(%esi)
0x004ba790:	movl -44(%esi), %ebx
0x004ba793:	leal %eax, -32(%esi)
0x004ba796:	movl -40(%esi), $0xa0a0000<UINT32>
0x004ba79d:	movb -36(%esi), $0xa<UINT8>
0x004ba7a1:	andb -35(%esi), $0xfffffff8<UINT8>
0x004ba7a5:	movb -34(%esi), %bl
0x004ba7a8:	cmpl %eax, %edi
0x004ba7aa:	jne 0x004ba778
0x004ba7ac:	movl %edi, -8(%ebp)
0x004ba7af:	popl %esi
0x004ba7b0:	pushl %ebx
0x004ba7b1:	call 0x004b2ce4
0x004ba7b6:	popl %ecx
0x004ba7b7:	movl %eax, %edi
0x004ba7b9:	popl %edi
0x004ba7ba:	popl %ebx
0x004ba7bb:	movl %esp, %ebp
0x004ba7bd:	popl %ebp
0x004ba7be:	ret

0x004ba851:	movl 0x4f0a18(,%edi,4), %eax
0x004ba858:	testl %eax, %eax
0x004ba85a:	jne 0x004ba870
0x004ba870:	movl %eax, 0x4f0c18
0x004ba875:	addl %eax, $0x40<UINT8>
0x004ba878:	movl 0x4f0c18, %eax
0x004ba87d:	incl %edi
0x004ba87e:	jmp 0x004ba83b
0x004ba862:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004ba869:	call 0x004ba883
0x004ba883:	pushl $0x7<UINT8>
0x004ba885:	call 0x004abb1d
0x004ba88a:	popl %ecx
0x004ba88b:	ret

0x004ba86e:	jmp 0x004ba81c
0x004ba81c:	movl %eax, %esi
0x004ba81e:	call 0x0046e176
0x004ba823:	ret

0x004b25f9:	popl %ecx
0x004b25fa:	testl %eax, %eax
0x004b25fc:	jne 15
0x004b25fe:	call 0x004b246b
0x004b246b:	movl %edi, %edi
0x004b246d:	pushl %ebp
0x004b246e:	movl %ebp, %esp
0x004b2470:	subl %esp, $0x48<UINT8>
0x004b2473:	leal %eax, -72(%ebp)
0x004b2476:	pushl %eax
0x004b2477:	call GetStartupInfoW@KERNEL32.DLL
GetStartupInfoW@KERNEL32.DLL: API Node	
0x004b247d:	cmpw -22(%ebp), $0x0<UINT8>
0x004b2482:	je 149
0x004b2488:	movl %eax, -20(%ebp)
0x004b248b:	testl %eax, %eax
0x004b248d:	je 138
0x004b2493:	pushl %ebx
0x004b2494:	pushl %esi
0x004b2495:	movl %esi, (%eax)
0x004b2497:	leal %ebx, 0x4(%eax)
0x004b249a:	leal %eax, (%ebx,%esi)
0x004b249d:	movl -4(%ebp), %eax
0x004b24a0:	movl %eax, $0x2000<UINT32>
0x004b24a5:	cmpl %esi, %eax
0x004b24a7:	jl 0x004b24ab
0x004b24ab:	pushl %esi
0x004b24ac:	call 0x004ba7f4
0x004b24b1:	movl %eax, 0x4f0c18
0x004b24b6:	popl %ecx
0x004b24b7:	cmpl %esi, %eax
0x004b24b9:	jle 0x004b24bd
0x004b24bd:	pushl %edi
0x004b24be:	xorl %edi, %edi
0x004b24c0:	testl %esi, %esi
0x004b24c2:	je 0x004b251a
0x004b251a:	popl %edi
0x004b251b:	popl %esi
0x004b251c:	popl %ebx
0x004b251d:	movl %esp, %ebp
0x004b251f:	popl %ebp
0x004b2520:	ret

0x004b2603:	call 0x004b2521
0x004b2521:	movl %edi, %edi
0x004b2523:	pushl %ebx
0x004b2524:	pushl %esi
0x004b2525:	pushl %edi
0x004b2526:	xorl %edi, %edi
0x004b2528:	movl %eax, %edi
0x004b252a:	movl %ecx, %edi
0x004b252c:	andl %eax, $0x3f<UINT8>
0x004b252f:	sarl %ecx, $0x6<UINT8>
0x004b2532:	imull %esi, %eax, $0x30<UINT8>
0x004b2535:	addl %esi, 0x4f0a18(,%ecx,4)
0x004b253c:	cmpl 0x18(%esi), $0xffffffff<UINT8>
0x004b2540:	je 0x004b254e
0x004b254e:	movl %eax, %edi
0x004b2550:	movb 0x28(%esi), $0xffffff81<UINT8>
0x004b2554:	subl %eax, $0x0<UINT8>
0x004b2557:	je 0x004b2569
0x004b2569:	pushl $0xfffffff6<UINT8>
0x004b256b:	popl %eax
0x004b256c:	pushl %eax
0x004b256d:	call GetStdHandle@KERNEL32.DLL
GetStdHandle@KERNEL32.DLL: API Node	
0x004b2573:	movl %ebx, %eax
0x004b2575:	cmpl %ebx, $0xffffffff<UINT8>
0x004b2578:	je 13
0x004b257a:	testl %ebx, %ebx
0x004b257c:	je 9
0x004b257e:	pushl %ebx
0x004b257f:	call GetFileType@KERNEL32.DLL
GetFileType@KERNEL32.DLL: API Node	
0x004b2585:	jmp 0x004b2589
0x004b2589:	testl %eax, %eax
0x004b258b:	je 30
0x004b258d:	andl %eax, $0xff<UINT32>
0x004b2592:	movl 0x18(%esi), %ebx
0x004b2595:	cmpl %eax, $0x2<UINT8>
0x004b2598:	jne 6
0x004b259a:	orb 0x28(%esi), $0x40<UINT8>
0x004b259e:	jmp 0x004b25c9
0x004b25c9:	incl %edi
0x004b25ca:	cmpl %edi, $0x3<UINT8>
0x004b25cd:	jne 0x004b2528
0x004b2559:	subl %eax, $0x1<UINT8>
0x004b255c:	je 0x004b2565
0x004b2565:	pushl $0xfffffff5<UINT8>
0x004b2567:	jmp 0x004b256b
0x004b255e:	pushl $0xfffffff4<UINT8>
0x004b2560:	subl %eax, $0x1<UINT8>
0x004b2563:	jmp 0x004b256b
0x004b25d3:	popl %edi
0x004b25d4:	popl %esi
0x004b25d5:	popl %ebx
0x004b25d6:	ret

0x004b2608:	movb %bl, $0x1<UINT8>
0x004b260a:	movb -25(%ebp), %bl
0x004b260d:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004b2614:	call 0x004b2624
0x004b2624:	pushl $0x7<UINT8>
0x004b2626:	call 0x004abb1d
0x004b262b:	popl %ecx
0x004b262c:	ret

0x004b2619:	movb %al, %bl
0x004b261b:	call 0x0046e176
0x004b2620:	ret

0x004ba174:	call GetCommandLineA@KERNEL32.DLL
GetCommandLineA@KERNEL32.DLL: API Node	
0x004ba17a:	movl 0x4f0e14, %eax
0x004ba17f:	call GetCommandLineW@KERNEL32.DLL
GetCommandLineW@KERNEL32.DLL: API Node	
0x004ba185:	movl 0x4f0e18, %eax
0x004ba18a:	movb %al, $0x1<UINT8>
0x004ba18c:	ret

0x004b9ec3:	cmpb 0x4f0e04, $0x0<UINT8>
0x004b9eca:	jne 18
0x004b9ecc:	pushl $0x1<UINT8>
0x004b9ece:	pushl $0xfffffffd<UINT8>
0x004b9ed0:	call 0x004b9dc2
0x004b9dc2:	movl %edi, %edi
0x004b9dc4:	pushl %ebp
0x004b9dc5:	movl %ebp, %esp
0x004b9dc7:	subl %esp, $0xc<UINT8>
0x004b9dca:	call 0x004b1dda
0x004b1dda:	movl %edi, %edi
0x004b1ddc:	pushl %esi
0x004b1ddd:	pushl %edi
0x004b1dde:	call GetLastError@KERNEL32.DLL
0x004b1de4:	movl %esi, %eax
0x004b1de6:	movl %eax, 0x4ed490
0x004b1deb:	cmpl %eax, $0xffffffff<UINT8>
0x004b1dee:	je 12
0x004b1df0:	pushl %eax
0x004b1df1:	call 0x004b3e62
0x004b1df6:	movl %edi, %eax
0x004b1df8:	testl %edi, %edi
0x004b1dfa:	jne 0x004b1e45
0x004b1e45:	pushl %esi
0x004b1e46:	call SetLastError@KERNEL32.DLL
0x004b1e4c:	movl %eax, %edi
0x004b1e4e:	popl %edi
0x004b1e4f:	popl %esi
0x004b1e50:	ret

0x004b9dcf:	movl -4(%ebp), %eax
0x004b9dd2:	call 0x004b9ee1
0x004b9ee1:	pushl $0xc<UINT8>
0x004b9ee3:	pushl $0x4eacb8<UINT32>
0x004b9ee8:	call 0x0046e130
0x004b9eed:	xorl %esi, %esi
0x004b9eef:	movl -28(%ebp), %esi
0x004b9ef2:	call 0x004b1dda
0x004b9ef7:	movl %edi, %eax
0x004b9ef9:	movl %ecx, 0x4ed690
0x004b9eff:	testl 0x350(%edi), %ecx
0x004b9f05:	je 0x004b9f18
0x004b9f18:	pushl $0x5<UINT8>
0x004b9f1a:	call 0x004abad5
0x004b9f1f:	popl %ecx
0x004b9f20:	movl -4(%ebp), %esi
0x004b9f23:	movl %esi, 0x48(%edi)
0x004b9f26:	movl -28(%ebp), %esi
0x004b9f29:	cmpl %esi, 0x4edc60
0x004b9f2f:	je 0x004b9f61
0x004b9f61:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004b9f68:	call 0x004b9f72
0x004b9f72:	pushl $0x5<UINT8>
0x004b9f74:	call 0x004abb1d
0x004b9f79:	popl %ecx
0x004b9f7a:	ret

0x004b9f6d:	jmp 0x004b9f0f
0x004b9f0f:	testl %esi, %esi
0x004b9f11:	jne 0x004b9f7b
0x004b9f7b:	movl %eax, %esi
0x004b9f7d:	call 0x0046e176
0x004b9f82:	ret

0x004b9dd7:	pushl 0x8(%ebp)
0x004b9dda:	call 0x004b9b56
0x004b9b56:	movl %edi, %edi
0x004b9b58:	pushl %ebp
0x004b9b59:	movl %ebp, %esp
0x004b9b5b:	subl %esp, $0x10<UINT8>
0x004b9b5e:	leal %ecx, -16(%ebp)
0x004b9b61:	pushl $0x0<UINT8>
0x004b9b63:	call 0x0049f712
0x0049f712:	movl %edi, %edi
0x0049f714:	pushl %ebp
0x0049f715:	movl %ebp, %esp
0x0049f717:	pushl %edi
0x0049f718:	movl %edi, %ecx
0x0049f71a:	movl %ecx, 0x8(%ebp)
0x0049f71d:	movb 0xc(%edi), $0x0<UINT8>
0x0049f721:	testl %ecx, %ecx
0x0049f723:	je 0x0049f72f
0x0049f72f:	movl %eax, 0x4f0a08
0x0049f734:	testl %eax, %eax
0x0049f736:	jne 18
0x0049f738:	movl %eax, 0x4ed550
0x0049f73d:	movl 0x4(%edi), %eax
0x0049f740:	movl %eax, 0x4ed554
0x0049f745:	movl 0x8(%edi), %eax
0x0049f748:	jmp 0x0049f78e
0x0049f78e:	movl %eax, %edi
0x0049f790:	popl %edi
0x0049f791:	popl %ebp
0x0049f792:	ret $0x4<UINT16>

0x004b9b68:	andl 0x4f0e00, $0x0<UINT8>
0x004b9b6f:	movl %eax, 0x8(%ebp)
0x004b9b72:	cmpl %eax, $0xfffffffe<UINT8>
0x004b9b75:	jne 0x004b9b89
0x004b9b89:	cmpl %eax, $0xfffffffd<UINT8>
0x004b9b8c:	jne 0x004b9ba0
0x004b9b8e:	movl 0x4f0e00, $0x1<UINT32>
0x004b9b98:	call GetACP@KERNEL32.DLL
GetACP@KERNEL32.DLL: API Node	
0x004b9b9e:	jmp 0x004b9bb5
0x004b9bb5:	cmpb -4(%ebp), $0x0<UINT8>
0x004b9bb9:	je 0x004b9bc5
0x004b9bc5:	movl %esp, %ebp
0x004b9bc7:	popl %ebp
0x004b9bc8:	ret

0x004b9ddf:	popl %ecx
0x004b9de0:	movl %ecx, -4(%ebp)
0x004b9de3:	movl -12(%ebp), %eax
0x004b9de6:	movl %ecx, 0x48(%ecx)
0x004b9de9:	cmpl %eax, 0x4(%ecx)
0x004b9dec:	jne 0x004b9df2
0x004b9df2:	pushl %ebx
0x004b9df3:	pushl %esi
0x004b9df4:	pushl %edi
0x004b9df5:	pushl $0x220<UINT32>
0x004b9dfa:	call 0x004b36d4
0x004b36d4:	movl %edi, %edi
0x004b36d6:	pushl %ebp
0x004b36d7:	movl %ebp, %esp
0x004b36d9:	pushl %esi
0x004b36da:	movl %esi, 0x8(%ebp)
0x004b36dd:	cmpl %esi, $0xffffffe0<UINT8>
0x004b36e0:	ja 48
0x004b36e2:	testl %esi, %esi
0x004b36e4:	jne 0x004b36fd
0x004b36fd:	pushl %esi
0x004b36fe:	pushl $0x0<UINT8>
0x004b3700:	pushl 0x4f0e20
0x004b3706:	call HeapAlloc@KERNEL32.DLL
0x004b370c:	testl %eax, %eax
0x004b370e:	je -39
0x004b3710:	jmp 0x004b371f
0x004b371f:	popl %esi
0x004b3720:	popl %ebp
0x004b3721:	ret

0x004b9dff:	movl %edi, %eax
0x004b9e01:	orl %ebx, $0xffffffff<UINT8>
0x004b9e04:	popl %ecx
0x004b9e05:	testl %edi, %edi
0x004b9e07:	je 46
0x004b9e09:	movl %esi, -4(%ebp)
0x004b9e0c:	movl %ecx, $0x88<UINT32>
0x004b9e11:	movl %esi, 0x48(%esi)
0x004b9e14:	rep movsl %es:(%edi), %ds:(%esi)
0x004b9e16:	movl %edi, %eax
0x004b9e18:	pushl %edi
0x004b9e19:	pushl -12(%ebp)
0x004b9e1c:	andl (%edi), $0x0<UINT8>
0x004b9e1f:	call 0x004b9f83
0x004b9f83:	movl %edi, %edi
0x004b9f85:	pushl %ebp
0x004b9f86:	movl %ebp, %esp
0x004b9f88:	subl %esp, $0x20<UINT8>
0x004b9f8b:	movl %eax, 0x4ed06c
0x004b9f90:	xorl %eax, %ebp
0x004b9f92:	movl -4(%ebp), %eax
0x004b9f95:	pushl %ebx
0x004b9f96:	pushl %esi
0x004b9f97:	pushl 0x8(%ebp)
0x004b9f9a:	movl %esi, 0xc(%ebp)
0x004b9f9d:	call 0x004b9b56
0x004b9ba0:	cmpl %eax, $0xfffffffc<UINT8>
0x004b9ba3:	jne 0x004b9bb5
0x004b9fa2:	movl %ebx, %eax
0x004b9fa4:	popl %ecx
0x004b9fa5:	testl %ebx, %ebx
0x004b9fa7:	jne 0x004b9fb7
0x004b9fb7:	pushl %edi
0x004b9fb8:	xorl %edi, %edi
0x004b9fba:	movl %ecx, %edi
0x004b9fbc:	movl %eax, %edi
0x004b9fbe:	movl -28(%ebp), %ecx
0x004b9fc1:	cmpl 0x4ed748(%eax), %ebx
0x004b9fc7:	je 234
0x004b9fcd:	incl %ecx
0x004b9fce:	addl %eax, $0x30<UINT8>
0x004b9fd1:	movl -28(%ebp), %ecx
0x004b9fd4:	cmpl %eax, $0xf0<UINT32>
0x004b9fd9:	jb 0x004b9fc1
0x004b9fdb:	cmpl %ebx, $0xfde8<UINT32>
0x004b9fe1:	je 200
0x004b9fe7:	cmpl %ebx, $0xfde9<UINT32>
0x004b9fed:	je 188
0x004b9ff3:	movzwl %eax, %bx
0x004b9ff6:	pushl %eax
0x004b9ff7:	call IsValidCodePage@KERNEL32.DLL
IsValidCodePage@KERNEL32.DLL: API Node	
0x004b9ffd:	testl %eax, %eax
0x004b9fff:	je 170
0x004ba005:	leal %eax, -24(%ebp)
0x004ba008:	pushl %eax
0x004ba009:	pushl %ebx
0x004ba00a:	call GetCPInfo@KERNEL32.DLL
GetCPInfo@KERNEL32.DLL: API Node	
0x004ba010:	testl %eax, %eax
0x004ba012:	je 132
0x004ba018:	pushl $0x101<UINT32>
0x004ba01d:	leal %eax, 0x18(%esi)
0x004ba020:	pushl %edi
0x004ba021:	pushl %eax
0x004ba022:	call 0x0049c5f0
0x0049c5f0:	movl %ecx, 0xc(%esp)
0x0049c5f4:	movzbl %eax, 0x8(%esp)
0x0049c5f9:	movl %edx, %edi
0x0049c5fb:	movl %edi, 0x4(%esp)
0x0049c5ff:	testl %ecx, %ecx
0x0049c601:	je 316
0x0049c607:	imull %eax, %eax, $0x1010101<UINT32>
0x0049c60d:	cmpl %ecx, $0x20<UINT8>
0x0049c610:	jbe 223
0x0049c616:	cmpl %ecx, $0x80<UINT32>
0x0049c61c:	jb 139
0x0049c622:	btl 0x4f04b8, $0x1<UINT8>
0x0049c62a:	jae 0x0049c635
0x0049c635:	btl 0x4ed080, $0x1<UINT8>
0x0049c63d:	jae 178
0x0049c643:	movd %xmm0, %eax
0x0049c647:	pshufd %xmm0, %xmm0, $0x0<UINT8>
0x0049c64c:	addl %ecx, %edi
0x0049c64e:	movups (%edi), %xmm0
0x0049c651:	addl %edi, $0x10<UINT8>
0x0049c654:	andl %edi, $0xfffffff0<UINT8>
0x0049c657:	subl %ecx, %edi
0x0049c659:	cmpl %ecx, $0x80<UINT32>
0x0049c65f:	jbe 0x0049c6ad
0x0049c661:	leal %esp, (%esp)
0x0049c668:	leal %esp, (%esp)
0x0049c66f:	nop
0x0049c670:	movdqa (%edi), %xmm0
0x0049c674:	movdqa 0x10(%edi), %xmm0
0x0049c679:	movdqa 0x20(%edi), %xmm0
0x0049c67e:	movdqa 0x30(%edi), %xmm0
0x0049c683:	movdqa 0x40(%edi), %xmm0
0x0049c688:	movdqa 0x50(%edi), %xmm0
0x0049c68d:	movdqa 0x60(%edi), %xmm0
0x0049c692:	movdqa 0x70(%edi), %xmm0
0x0049c697:	leal %edi, 0x80(%edi)
0x0049c69d:	subl %ecx, $0x80<UINT32>
0x0049c6a3:	testl %ecx, $0xffffff00<UINT32>
0x0049c6a9:	jne 0x0049c670
0x0049c6ab:	jmp 0x0049c6c0
0x0049c6c0:	cmpl %ecx, $0x20<UINT8>
0x0049c6c3:	jb 28
0x0049c6c5:	movdqu (%edi), %xmm0
0x0049c6c9:	movdqu 0x10(%edi), %xmm0
0x0049c6ce:	addl %edi, $0x20<UINT8>
0x0049c6d1:	subl %ecx, $0x20<UINT8>
0x0049c6d4:	cmpl %ecx, $0x20<UINT8>
0x0049c6d7:	jae 0x0049c6c5
0x0049c6d9:	testl %ecx, $0x1f<UINT32>
0x0049c6df:	je 98
0x0049c6e1:	leal %edi, -32(%edi,%ecx)
0x0049c6e5:	movdqu (%edi), %xmm0
0x0049c6e9:	movdqu 0x10(%edi), %xmm0
0x0049c6ee:	movl %eax, 0x4(%esp)
0x0049c6f2:	movl %edi, %edx
0x0049c6f4:	ret

0x004ba027:	movl 0x4(%esi), %ebx
0x004ba02a:	addl %esp, $0xc<UINT8>
0x004ba02d:	xorl %ebx, %ebx
0x004ba02f:	movl 0x21c(%esi), %edi
0x004ba035:	incl %ebx
0x004ba036:	cmpl -24(%ebp), %ebx
0x004ba039:	jbe 81
0x004ba03b:	cmpb -18(%ebp), $0x0<UINT8>
0x004ba03f:	leal %eax, -18(%ebp)
0x004ba042:	je 0x004ba065
0x004ba065:	leal %eax, 0x1a(%esi)
0x004ba068:	movl %ecx, $0xfe<UINT32>
0x004ba06d:	orb (%eax), $0x8<UINT8>
0x004ba070:	incl %eax
0x004ba071:	subl %ecx, $0x1<UINT8>
0x004ba074:	jne 0x004ba06d
0x004ba076:	pushl 0x4(%esi)
0x004ba079:	call 0x004b9b18
0x004b9b18:	movl %edi, %edi
0x004b9b1a:	pushl %ebp
0x004b9b1b:	movl %ebp, %esp
0x004b9b1d:	movl %eax, 0x8(%ebp)
0x004b9b20:	subl %eax, $0x3a4<UINT32>
0x004b9b25:	je 40
0x004b9b27:	subl %eax, $0x4<UINT8>
0x004b9b2a:	je 28
0x004b9b2c:	subl %eax, $0xd<UINT8>
0x004b9b2f:	je 16
0x004b9b31:	subl %eax, $0x1<UINT8>
0x004b9b34:	je 4
0x004b9b36:	xorl %eax, %eax
0x004b9b38:	popl %ebp
0x004b9b39:	ret

0x004ba07e:	addl %esp, $0x4<UINT8>
0x004ba081:	movl 0x21c(%esi), %eax
0x004ba087:	movl 0x8(%esi), %ebx
0x004ba08a:	jmp 0x004ba08f
0x004ba08f:	xorl %eax, %eax
0x004ba091:	leal %edi, 0xc(%esi)
0x004ba094:	stosl %es:(%edi), %eax
0x004ba095:	stosl %es:(%edi), %eax
0x004ba096:	stosl %es:(%edi), %eax
0x004ba097:	jmp 0x004ba15a
0x004ba15a:	pushl %esi
0x004ba15b:	call 0x004b9c2e
0x004b9c2e:	movl %edi, %edi
0x004b9c30:	pushl %ebp
0x004b9c31:	movl %ebp, %esp
0x004b9c33:	subl %esp, $0x720<UINT32>
0x004b9c39:	movl %eax, 0x4ed06c
0x004b9c3e:	xorl %eax, %ebp
0x004b9c40:	movl -4(%ebp), %eax
0x004b9c43:	pushl %ebx
0x004b9c44:	pushl %esi
0x004b9c45:	movl %esi, 0x8(%ebp)
0x004b9c48:	leal %eax, -1816(%ebp)
0x004b9c4e:	pushl %edi
0x004b9c4f:	pushl %eax
0x004b9c50:	pushl 0x4(%esi)
0x004b9c53:	call GetCPInfo@KERNEL32.DLL
0x004b9c59:	xorl %ebx, %ebx
0x004b9c5b:	movl %edi, $0x100<UINT32>
0x004b9c60:	testl %eax, %eax
0x004b9c62:	je 240
0x004b9c68:	movl %eax, %ebx
0x004b9c6a:	movb -260(%ebp,%eax), %al
0x004b9c71:	incl %eax
0x004b9c72:	cmpl %eax, %edi
0x004b9c74:	jb 0x004b9c6a
0x004b9c76:	movb %al, -1810(%ebp)
0x004b9c7c:	leal %ecx, -1810(%ebp)
0x004b9c82:	movb -260(%ebp), $0x20<UINT8>
0x004b9c89:	jmp 0x004b9caa
0x004b9caa:	testb %al, %al
0x004b9cac:	jne -35
0x004b9cae:	pushl %ebx
0x004b9caf:	pushl 0x4(%esi)
0x004b9cb2:	leal %eax, -1796(%ebp)
0x004b9cb8:	pushl %eax
0x004b9cb9:	pushl %edi
0x004b9cba:	leal %eax, -260(%ebp)
0x004b9cc0:	pushl %eax
0x004b9cc1:	pushl $0x1<UINT8>
0x004b9cc3:	pushl %ebx
0x004b9cc4:	call 0x004b6ce5
0x004b6ce5:	movl %edi, %edi
0x004b6ce7:	pushl %ebp
0x004b6ce8:	movl %ebp, %esp
0x004b6cea:	subl %esp, $0x18<UINT8>
0x004b6ced:	movl %eax, 0x4ed06c
0x004b6cf2:	xorl %eax, %ebp
0x004b6cf4:	movl -4(%ebp), %eax
0x004b6cf7:	pushl %ebx
0x004b6cf8:	pushl %esi
0x004b6cf9:	pushl %edi
0x004b6cfa:	pushl 0x8(%ebp)
0x004b6cfd:	leal %ecx, -24(%ebp)
0x004b6d00:	call 0x0049f712
0x004b6d05:	movl %ecx, 0x1c(%ebp)
0x004b6d08:	testl %ecx, %ecx
0x004b6d0a:	jne 0x004b6d17
0x004b6d17:	xorl %eax, %eax
0x004b6d19:	xorl %edi, %edi
0x004b6d1b:	cmpl 0x20(%ebp), %eax
0x004b6d1e:	pushl %edi
0x004b6d1f:	pushl %edi
0x004b6d20:	pushl 0x14(%ebp)
0x004b6d23:	setne %al
0x004b6d26:	pushl 0x10(%ebp)
0x004b6d29:	leal %eax, 0x1(,%eax,8)
0x004b6d30:	pushl %eax
0x004b6d31:	pushl %ecx
0x004b6d32:	call MultiByteToWideChar@KERNEL32.DLL
MultiByteToWideChar@KERNEL32.DLL: API Node	
0x004b6d38:	movl -8(%ebp), %eax
0x004b6d3b:	testl %eax, %eax
0x004b6d3d:	je 153
0x004b6d43:	leal %ebx, (%eax,%eax)
0x004b6d46:	leal %ecx, 0x8(%ebx)
0x004b6d49:	cmpl %ebx, %ecx
0x004b6d4b:	sbbl %eax, %eax
0x004b6d4d:	testl %ecx, %eax
0x004b6d4f:	je 74
0x004b6d51:	leal %ecx, 0x8(%ebx)
0x004b6d54:	cmpl %ebx, %ecx
0x004b6d56:	sbbl %eax, %eax
0x004b6d58:	andl %eax, %ecx
0x004b6d5a:	leal %ecx, 0x8(%ebx)
0x004b6d5d:	cmpl %eax, $0x400<UINT32>
0x004b6d62:	ja 25
0x004b6d64:	cmpl %ebx, %ecx
0x004b6d66:	sbbl %eax, %eax
0x004b6d68:	andl %eax, %ecx
0x004b6d6a:	call 0x0046dd20
0x0046dd20:	pushl %ecx
0x0046dd21:	leal %ecx, 0x8(%esp)
0x0046dd25:	subl %ecx, %eax
0x0046dd27:	andl %ecx, $0xf<UINT8>
0x0046dd2a:	addl %eax, %ecx
0x0046dd2c:	sbbl %ecx, %ecx
0x0046dd2e:	orl %eax, %ecx
0x0046dd30:	popl %ecx
0x0046dd31:	jmp 0x0046e2f0
0x0046e2f0:	pushl %ecx
0x0046e2f1:	leal %ecx, 0x4(%esp)
0x0046e2f5:	subl %ecx, %eax
0x0046e2f7:	sbbl %eax, %eax
0x0046e2f9:	notl %eax
0x0046e2fb:	andl %ecx, %eax
0x0046e2fd:	movl %eax, %esp
0x0046e2ff:	andl %eax, $0xfffff000<UINT32>
0x0046e304:	cmpl %ecx, %eax
0x0046e306:	repn jb 11
0x0046e309:	movl %eax, %ecx
0x0046e30b:	popl %ecx
0x0046e30c:	xchgl %esp, %eax
0x0046e30d:	movl %eax, (%eax)
0x0046e30f:	movl (%esp), %eax
0x0046e312:	repn ret

0x004b6d6f:	movl %esi, %esp
0x004b6d71:	testl %esi, %esi
0x004b6d73:	je 96
0x004b6d75:	movl (%esi), $0xcccc<UINT32>
0x004b6d7b:	jmp 0x004b6d96
0x004b6d96:	addl %esi, $0x8<UINT8>
0x004b6d99:	jmp 0x004b6d9d
0x004b6d9d:	testl %esi, %esi
0x004b6d9f:	je 52
0x004b6da1:	pushl %ebx
0x004b6da2:	pushl %edi
0x004b6da3:	pushl %esi
0x004b6da4:	call 0x0049c5f0
0x004b6da9:	addl %esp, $0xc<UINT8>
0x004b6dac:	pushl -8(%ebp)
0x004b6daf:	pushl %esi
0x004b6db0:	pushl 0x14(%ebp)
0x004b6db3:	pushl 0x10(%ebp)
0x004b6db6:	pushl $0x1<UINT8>
0x004b6db8:	pushl 0x1c(%ebp)
0x004b6dbb:	call MultiByteToWideChar@KERNEL32.DLL
0x004b6dc1:	testl %eax, %eax
0x004b6dc3:	je 16
0x004b6dc5:	pushl 0x18(%ebp)
0x004b6dc8:	pushl %eax
0x004b6dc9:	pushl %esi
0x004b6dca:	pushl 0xc(%ebp)
0x004b6dcd:	call GetStringTypeW@KERNEL32.DLL
GetStringTypeW@KERNEL32.DLL: API Node	
0x004b6dd3:	movl %edi, %eax
0x004b6dd5:	pushl %esi
0x004b6dd6:	call 0x0046c8f3
0x0046c8f3:	pushl %ebp
0x0046c8f4:	movl %ebp, %esp
0x0046c8f6:	movl %eax, 0x8(%ebp)
0x0046c8f9:	testl %eax, %eax
0x0046c8fb:	je 0x0046c90f
0x0046c8fd:	subl %eax, $0x8<UINT8>
0x0046c900:	cmpl (%eax), $0xdddd<UINT32>
0x0046c906:	jne 0x0046c90f
0x0046c90f:	popl %ebp
0x0046c910:	ret

0x004b6ddb:	popl %ecx
0x004b6ddc:	cmpb -12(%ebp), $0x0<UINT8>
0x004b6de0:	je 0x004b6dec
0x004b6dec:	movl %eax, %edi
0x004b6dee:	leal %esp, -36(%ebp)
0x004b6df1:	popl %edi
0x004b6df2:	popl %esi
0x004b6df3:	popl %ebx
0x004b6df4:	movl %ecx, -4(%ebp)
0x004b6df7:	xorl %ecx, %ebp
0x004b6df9:	call 0x0046d108
0x004b6dfe:	movl %esp, %ebp
0x004b6e00:	popl %ebp
0x004b6e01:	ret

0x004b9cc9:	pushl %ebx
0x004b9cca:	pushl 0x4(%esi)
0x004b9ccd:	leal %eax, -516(%ebp)
0x004b9cd3:	pushl %edi
0x004b9cd4:	pushl %eax
0x004b9cd5:	pushl %edi
0x004b9cd6:	leal %eax, -260(%ebp)
0x004b9cdc:	pushl %eax
0x004b9cdd:	pushl %edi
0x004b9cde:	pushl 0x21c(%esi)
0x004b9ce4:	pushl %ebx
0x004b9ce5:	call 0x004b53df
0x004b53df:	movl %edi, %edi
0x004b53e1:	pushl %ebp
0x004b53e2:	movl %ebp, %esp
0x004b53e4:	subl %esp, $0x10<UINT8>
0x004b53e7:	pushl 0x8(%ebp)
0x004b53ea:	leal %ecx, -16(%ebp)
0x004b53ed:	call 0x0049f712
0x004b53f2:	pushl 0x28(%ebp)
0x004b53f5:	leal %eax, -12(%ebp)
0x004b53f8:	pushl 0x24(%ebp)
0x004b53fb:	pushl 0x20(%ebp)
0x004b53fe:	pushl 0x1c(%ebp)
0x004b5401:	pushl 0x18(%ebp)
0x004b5404:	pushl 0x14(%ebp)
0x004b5407:	pushl 0x10(%ebp)
0x004b540a:	pushl 0xc(%ebp)
0x004b540d:	pushl %eax
0x004b540e:	call 0x004b51c2
0x004b51c2:	movl %edi, %edi
0x004b51c4:	pushl %ebp
0x004b51c5:	movl %ebp, %esp
0x004b51c7:	pushl %ecx
0x004b51c8:	pushl %ecx
0x004b51c9:	movl %eax, 0x4ed06c
0x004b51ce:	xorl %eax, %ebp
0x004b51d0:	movl -4(%ebp), %eax
0x004b51d3:	pushl %ebx
0x004b51d4:	pushl %esi
0x004b51d5:	movl %esi, 0x18(%ebp)
0x004b51d8:	pushl %edi
0x004b51d9:	testl %esi, %esi
0x004b51db:	jle 20
0x004b51dd:	pushl %esi
0x004b51de:	pushl 0x14(%ebp)
0x004b51e1:	call 0x004af04c
0x004af04c:	movl %edi, %edi
0x004af04e:	pushl %ebp
0x004af04f:	movl %ebp, %esp
0x004af051:	movl %ecx, 0x8(%ebp)
0x004af054:	xorl %eax, %eax
0x004af056:	cmpb (%ecx), %al
0x004af058:	je 12
0x004af05a:	cmpl %eax, 0xc(%ebp)
0x004af05d:	je 0x004af066
0x004af05f:	incl %eax
0x004af060:	cmpb (%eax,%ecx), $0x0<UINT8>
0x004af064:	jne 0x004af05a
0x004af066:	popl %ebp
0x004af067:	ret

0x004b51e6:	popl %ecx
0x004b51e7:	cmpl %eax, %esi
0x004b51e9:	popl %ecx
0x004b51ea:	leal %esi, 0x1(%eax)
0x004b51ed:	jl 2
0x004b51ef:	movl %esi, %eax
0x004b51f1:	movl %edi, 0x24(%ebp)
0x004b51f4:	testl %edi, %edi
0x004b51f6:	jne 0x004b5203
0x004b5203:	xorl %eax, %eax
0x004b5205:	cmpl 0x28(%ebp), %eax
0x004b5208:	pushl $0x0<UINT8>
0x004b520a:	pushl $0x0<UINT8>
0x004b520c:	pushl %esi
0x004b520d:	pushl 0x14(%ebp)
0x004b5210:	setne %al
0x004b5213:	leal %eax, 0x1(,%eax,8)
0x004b521a:	pushl %eax
0x004b521b:	pushl %edi
0x004b521c:	call MultiByteToWideChar@KERNEL32.DLL
0x004b5222:	movl -8(%ebp), %eax
0x004b5225:	testl %eax, %eax
0x004b5227:	je 397
0x004b522d:	leal %edx, (%eax,%eax)
0x004b5230:	leal %ecx, 0x8(%edx)
0x004b5233:	cmpl %edx, %ecx
0x004b5235:	sbbl %eax, %eax
0x004b5237:	testl %ecx, %eax
0x004b5239:	je 82
0x004b523b:	leal %ecx, 0x8(%edx)
0x004b523e:	cmpl %edx, %ecx
0x004b5240:	sbbl %eax, %eax
0x004b5242:	andl %eax, %ecx
0x004b5244:	leal %ecx, 0x8(%edx)
0x004b5247:	cmpl %eax, $0x400<UINT32>
0x004b524c:	ja 29
0x004b524e:	cmpl %edx, %ecx
0x004b5250:	sbbl %eax, %eax
0x004b5252:	andl %eax, %ecx
0x004b5254:	call 0x0046dd20
0x004b5259:	movl %ebx, %esp
0x004b525b:	testl %ebx, %ebx
0x004b525d:	je 332
0x004b5263:	movl (%ebx), $0xcccc<UINT32>
0x004b5269:	jmp 0x004b5288
0x004b5288:	addl %ebx, $0x8<UINT8>
0x004b528b:	jmp 0x004b528f
0x004b528f:	testl %ebx, %ebx
0x004b5291:	je 280
0x004b5297:	pushl -8(%ebp)
0x004b529a:	pushl %ebx
0x004b529b:	pushl %esi
0x004b529c:	pushl 0x14(%ebp)
0x004b529f:	pushl $0x1<UINT8>
0x004b52a1:	pushl %edi
0x004b52a2:	call MultiByteToWideChar@KERNEL32.DLL
0x004b52a8:	testl %eax, %eax
0x004b52aa:	je 255
0x004b52b0:	movl %edi, -8(%ebp)
0x004b52b3:	xorl %eax, %eax
0x004b52b5:	pushl %eax
0x004b52b6:	pushl %eax
0x004b52b7:	pushl %eax
0x004b52b8:	pushl %eax
0x004b52b9:	pushl %eax
0x004b52ba:	pushl %edi
0x004b52bb:	pushl %ebx
0x004b52bc:	pushl 0x10(%ebp)
0x004b52bf:	pushl 0xc(%ebp)
0x004b52c2:	call 0x004b4203
0x004b4203:	movl %edi, %edi
0x004b4205:	pushl %ebp
0x004b4206:	movl %ebp, %esp
0x004b4208:	pushl %ecx
0x004b4209:	movl %eax, 0x4ed06c
0x004b420e:	xorl %eax, %ebp
0x004b4210:	movl -4(%ebp), %eax
0x004b4213:	pushl %esi
0x004b4214:	pushl $0x4d331c<UINT32>
0x004b4219:	pushl $0x4d3314<UINT32>
0x004b421e:	pushl $0x4d331c<UINT32>
0x004b4223:	pushl $0x16<UINT8>
0x004b4225:	call 0x004b3b70
0x004b422a:	movl %esi, %eax
0x004b422c:	addl %esp, $0x10<UINT8>
0x004b422f:	testl %esi, %esi
0x004b4231:	je 39
0x004b4233:	pushl 0x28(%ebp)
0x004b4236:	movl %ecx, %esi
0x004b4238:	pushl 0x24(%ebp)
0x004b423b:	pushl 0x20(%ebp)
0x004b423e:	pushl 0x1c(%ebp)
0x004b4241:	pushl 0x18(%ebp)
0x004b4244:	pushl 0x14(%ebp)
0x004b4247:	pushl 0x10(%ebp)
0x004b424a:	pushl 0xc(%ebp)
0x004b424d:	pushl 0x8(%ebp)
0x004b4250:	call 0x00403560
0x004b4256:	call LCMapStringEx@kernel32.dll
LCMapStringEx@kernel32.dll: API Node	
0x004b4258:	jmp 0x004b427a
0x004b427a:	movl %ecx, -4(%ebp)
0x004b427d:	xorl %ecx, %ebp
0x004b427f:	popl %esi
0x004b4280:	call 0x0046d108
0x004b4285:	movl %esp, %ebp
0x004b4287:	popl %ebp
0x004b4288:	ret $0x24<UINT16>

0x004b52c7:	movl %esi, %eax
0x004b52c9:	testl %esi, %esi
0x004b52cb:	je 0x004b53af
0x004b52d1:	testl 0x10(%ebp), $0x400<UINT32>
0x004b53af:	xorl %esi, %esi
0x004b53b1:	pushl %ebx
0x004b53b2:	call 0x0046c8f3
0x004b53b7:	popl %ecx
0x004b53b8:	movl %eax, %esi
0x004b53ba:	leal %esp, -20(%ebp)
0x004b53bd:	popl %edi
0x004b53be:	popl %esi
0x004b53bf:	popl %ebx
0x004b53c0:	movl %ecx, -4(%ebp)
0x004b53c3:	xorl %ecx, %ebp
0x004b53c5:	call 0x0046d108
0x004b53ca:	movl %esp, %ebp
0x004b53cc:	popl %ebp
0x004b53cd:	ret

0x004b5413:	addl %esp, $0x24<UINT8>
0x004b5416:	cmpb -4(%ebp), $0x0<UINT8>
0x004b541a:	je 0x004b5426
0x004b5426:	movl %esp, %ebp
0x004b5428:	popl %ebp
0x004b5429:	ret

0x004b9cea:	addl %esp, $0x40<UINT8>
0x004b9ced:	leal %eax, -772(%ebp)
0x004b9cf3:	pushl %ebx
0x004b9cf4:	pushl 0x4(%esi)
0x004b9cf7:	pushl %edi
0x004b9cf8:	pushl %eax
0x004b9cf9:	pushl %edi
0x004b9cfa:	leal %eax, -260(%ebp)
0x004b9d00:	pushl %eax
0x004b9d01:	pushl $0x200<UINT32>
0x004b9d06:	pushl 0x21c(%esi)
0x004b9d0c:	pushl %ebx
0x004b9d0d:	call 0x004b53df
0x004b9d12:	addl %esp, $0x24<UINT8>
0x004b9d15:	movl %ecx, %ebx
0x004b9d17:	movzwl %eax, -1796(%ebp,%ecx,2)
0x004b9d1f:	testb %al, $0x1<UINT8>
0x004b9d21:	je 0x004b9d31
0x004b9d31:	testb %al, $0x2<UINT8>
0x004b9d33:	je 0x004b9d4a
0x004b9d4a:	movb 0x119(%esi,%ecx), %bl
0x004b9d51:	incl %ecx
0x004b9d52:	cmpl %ecx, %edi
0x004b9d54:	jb 0x004b9d17
0x004b9d23:	orb 0x19(%esi,%ecx), $0x10<UINT8>
0x004b9d28:	movb %al, -516(%ebp,%ecx)
0x004b9d2f:	jmp 0x004b9d41
0x004b9d41:	movb 0x119(%esi,%ecx), %al
0x004b9d48:	jmp 0x004b9d51
0x004b9d35:	orb 0x19(%esi,%ecx), $0x20<UINT8>
0x004b9d3a:	movb %al, -772(%ebp,%ecx)
0x004b9d56:	jmp 0x004b9db1
0x004b9db1:	movl %ecx, -4(%ebp)
0x004b9db4:	popl %edi
0x004b9db5:	popl %esi
0x004b9db6:	xorl %ecx, %ebp
0x004b9db8:	popl %ebx
0x004b9db9:	call 0x0046d108
0x004b9dbe:	movl %esp, %ebp
0x004b9dc0:	popl %ebp
0x004b9dc1:	ret

0x004ba160:	popl %ecx
0x004ba161:	xorl %eax, %eax
0x004ba163:	popl %edi
0x004ba164:	movl %ecx, -4(%ebp)
0x004ba167:	popl %esi
0x004ba168:	xorl %ecx, %ebp
0x004ba16a:	popl %ebx
0x004ba16b:	call 0x0046d108
0x004ba170:	movl %esp, %ebp
0x004ba172:	popl %ebp
0x004ba173:	ret

0x004b9e24:	movl %esi, %eax
0x004b9e26:	popl %ecx
0x004b9e27:	popl %ecx
0x004b9e28:	cmpl %esi, %ebx
0x004b9e2a:	jne 0x004b9e49
0x004b9e49:	cmpb 0xc(%ebp), $0x0<UINT8>
0x004b9e4d:	jne 0x004b9e54
0x004b9e54:	movl %eax, -4(%ebp)
0x004b9e57:	movl %eax, 0x48(%eax)
0x004b9e5a:	xaddl (%eax), %ebx
0x004b9e5e:	decl %ebx
0x004b9e5f:	jne 21
0x004b9e61:	movl %eax, -4(%ebp)
0x004b9e64:	cmpl 0x48(%eax), $0x4eda40<UINT32>
0x004b9e6b:	je 0x004b9e76
0x004b9e76:	movl (%edi), $0x1<UINT32>
0x004b9e7c:	movl %ecx, %edi
0x004b9e7e:	movl %eax, -4(%ebp)
0x004b9e81:	xorl %edi, %edi
0x004b9e83:	movl 0x48(%eax), %ecx
0x004b9e86:	movl %eax, -4(%ebp)
0x004b9e89:	testb 0x350(%eax), $0x2<UINT8>
0x004b9e90:	jne -89
0x004b9e92:	testb 0x4ed690, $0x1<UINT8>
0x004b9e99:	jne -98
0x004b9e9b:	leal %eax, -4(%ebp)
0x004b9e9e:	movl -12(%ebp), %eax
0x004b9ea1:	leal %eax, -12(%ebp)
0x004b9ea4:	pushl %eax
0x004b9ea5:	pushl $0x5<UINT8>
0x004b9ea7:	call 0x004b9a2c
0x004b9a2c:	movl %edi, %edi
0x004b9a2e:	pushl %ebp
0x004b9a2f:	movl %ebp, %esp
0x004b9a31:	subl %esp, $0xc<UINT8>
0x004b9a34:	movl %eax, 0x8(%ebp)
0x004b9a37:	leal %ecx, -1(%ebp)
0x004b9a3a:	movl -8(%ebp), %eax
0x004b9a3d:	movl -12(%ebp), %eax
0x004b9a40:	leal %eax, -8(%ebp)
0x004b9a43:	pushl %eax
0x004b9a44:	pushl 0xc(%ebp)
0x004b9a47:	leal %eax, -12(%ebp)
0x004b9a4a:	pushl %eax
0x004b9a4b:	call 0x004b99e9
0x004b99e9:	pushl $0x8<UINT8>
0x004b99eb:	pushl $0x4eacd8<UINT32>
0x004b99f0:	call 0x0046e130
0x004b99f5:	movl %eax, 0x8(%ebp)
0x004b99f8:	pushl (%eax)
0x004b99fa:	call 0x004abad5
0x004b99ff:	popl %ecx
0x004b9a00:	andl -4(%ebp), $0x0<UINT8>
0x004b9a04:	movl %ecx, 0xc(%ebp)
0x004b9a07:	call 0x004b9a54
0x004b9a54:	movl %edi, %edi
0x004b9a56:	pushl %esi
0x004b9a57:	movl %esi, %ecx
0x004b9a59:	pushl $0xc<UINT8>
0x004b9a5b:	movl %eax, (%esi)
0x004b9a5d:	movl %eax, (%eax)
0x004b9a5f:	movl %eax, 0x48(%eax)
0x004b9a62:	movl %eax, 0x4(%eax)
0x004b9a65:	movl 0x4f0dec, %eax
0x004b9a6a:	movl %eax, (%esi)
0x004b9a6c:	movl %eax, (%eax)
0x004b9a6e:	movl %eax, 0x48(%eax)
0x004b9a71:	movl %eax, 0x8(%eax)
0x004b9a74:	movl 0x4f0df0, %eax
0x004b9a79:	movl %eax, (%esi)
0x004b9a7b:	movl %eax, (%eax)
0x004b9a7d:	movl %eax, 0x48(%eax)
0x004b9a80:	movl %eax, 0x21c(%eax)
0x004b9a86:	movl 0x4f0de8, %eax
0x004b9a8b:	movl %eax, (%esi)
0x004b9a8d:	movl %eax, (%eax)
0x004b9a8f:	movl %eax, 0x48(%eax)
0x004b9a92:	addl %eax, $0xc<UINT8>
0x004b9a95:	pushl %eax
0x004b9a96:	pushl $0xc<UINT8>
0x004b9a98:	pushl $0x4f0df4<UINT32>
0x004b9a9d:	call 0x004a55f3
0x004a55f3:	movl %edi, %edi
0x004a55f5:	pushl %ebp
0x004a55f6:	movl %ebp, %esp
0x004a55f8:	pushl %esi
0x004a55f9:	movl %esi, 0x14(%ebp)
0x004a55fc:	testl %esi, %esi
0x004a55fe:	jne 0x004a5604
0x004a5604:	movl %eax, 0x8(%ebp)
0x004a5607:	testl %eax, %eax
0x004a5609:	jne 0x004a561e
0x004a561e:	pushl %edi
0x004a561f:	movl %edi, 0x10(%ebp)
0x004a5622:	testl %edi, %edi
0x004a5624:	je 20
0x004a5626:	cmpl 0xc(%ebp), %esi
0x004a5629:	jb 15
0x004a562b:	pushl %esi
0x004a562c:	pushl %edi
0x004a562d:	pushl %eax
0x004a562e:	call 0x0049c070
0x0049c070:	pushl %edi
0x0049c071:	pushl %esi
0x0049c072:	movl %esi, 0x10(%esp)
0x0049c076:	movl %ecx, 0x14(%esp)
0x0049c07a:	movl %edi, 0xc(%esp)
0x0049c07e:	movl %eax, %ecx
0x0049c080:	movl %edx, %ecx
0x0049c082:	addl %eax, %esi
0x0049c084:	cmpl %edi, %esi
0x0049c086:	jbe 8
0x0049c088:	cmpl %edi, %eax
0x0049c08a:	jb 660
0x0049c090:	cmpl %ecx, $0x20<UINT8>
0x0049c093:	jb 0x0049c56b
0x0049c56b:	andl %ecx, $0x1f<UINT8>
0x0049c56e:	je 48
0x0049c570:	movl %eax, %ecx
0x0049c572:	shrl %ecx, $0x2<UINT8>
0x0049c575:	je 0x0049c586
0x0049c577:	movl %edx, (%esi)
0x0049c579:	movl (%edi), %edx
0x0049c57b:	addl %edi, $0x4<UINT8>
0x0049c57e:	addl %esi, $0x4<UINT8>
0x0049c581:	subl %ecx, $0x1<UINT8>
0x0049c584:	jne 0x0049c577
0x0049c586:	movl %ecx, %eax
0x0049c588:	andl %ecx, $0x3<UINT8>
0x0049c58b:	je 0x0049c5a0
0x0049c5a0:	movl %eax, 0xc(%esp)
0x0049c5a4:	popl %esi
0x0049c5a5:	popl %edi
0x0049c5a6:	ret

0x004a5633:	addl %esp, $0xc<UINT8>
0x004a5636:	xorl %eax, %eax
0x004a5638:	jmp 0x004a5670
0x004a5670:	popl %edi
0x004a5671:	popl %esi
0x004a5672:	popl %ebp
0x004a5673:	ret

0x004b9aa2:	movl %eax, (%esi)
0x004b9aa4:	movl %ecx, $0x101<UINT32>
0x004b9aa9:	pushl %ecx
0x004b9aaa:	movl %eax, (%eax)
0x004b9aac:	movl %eax, 0x48(%eax)
0x004b9aaf:	addl %eax, $0x18<UINT8>
0x004b9ab2:	pushl %eax
0x004b9ab3:	pushl %ecx
0x004b9ab4:	pushl $0x4ed838<UINT32>
0x004b9ab9:	call 0x004a55f3
0x0049c099:	cmpl %ecx, $0x80<UINT32>
0x0049c09f:	jae 0x0049c0b4
0x0049c0b4:	btl 0x4f04b8, $0x1<UINT8>
0x0049c0bc:	jae 0x0049c0c7
0x0049c0c7:	movl %eax, %edi
0x0049c0c9:	xorl %eax, %esi
0x0049c0cb:	testl %eax, $0xf<UINT32>
0x0049c0d0:	jne 0x0049c0e0
0x0049c0d2:	btl 0x4ed080, $0x1<UINT8>
0x0049c0da:	jb 0x0049c4c0
0x0049c4c0:	movl %eax, %esi
0x0049c4c2:	andl %eax, $0xf<UINT8>
0x0049c4c5:	testl %eax, %eax
0x0049c4c7:	jne 0x0049c5b0
0x0049c5b0:	movl %edx, $0x10<UINT32>
0x0049c5b5:	subl %edx, %eax
0x0049c5b7:	subl %ecx, %edx
0x0049c5b9:	pushl %ecx
0x0049c5ba:	movl %eax, %edx
0x0049c5bc:	movl %ecx, %eax
0x0049c5be:	andl %ecx, $0x3<UINT8>
0x0049c5c1:	je 0x0049c5cc
0x0049c5cc:	shrl %eax, $0x2<UINT8>
0x0049c5cf:	je 13
0x0049c5d1:	movl %edx, (%esi)
0x0049c5d3:	movl (%edi), %edx
0x0049c5d5:	leal %esi, 0x4(%esi)
0x0049c5d8:	leal %edi, 0x4(%edi)
0x0049c5db:	decl %eax
0x0049c5dc:	jne 0x0049c5d1
0x0049c5de:	popl %ecx
0x0049c5df:	jmp 0x0049c4cd
0x0049c4cd:	movl %edx, %ecx
0x0049c4cf:	andl %ecx, $0x7f<UINT8>
0x0049c4d2:	shrl %edx, $0x7<UINT8>
0x0049c4d5:	je 102
0x0049c4d7:	leal %esp, (%esp)
0x0049c4de:	movl %edi, %edi
0x0049c4e0:	movdqa %xmm0, (%esi)
0x0049c4e4:	movdqa %xmm1, 0x10(%esi)
0x0049c4e9:	movdqa %xmm2, 0x20(%esi)
0x0049c4ee:	movdqa %xmm3, 0x30(%esi)
0x0049c4f3:	movdqa (%edi), %xmm0
0x0049c4f7:	movdqa 0x10(%edi), %xmm1
0x0049c4fc:	movdqa 0x20(%edi), %xmm2
0x0049c501:	movdqa 0x30(%edi), %xmm3
0x0049c506:	movdqa %xmm4, 0x40(%esi)
0x0049c50b:	movdqa %xmm5, 0x50(%esi)
0x0049c510:	movdqa %xmm6, 0x60(%esi)
0x0049c515:	movdqa %xmm7, 0x70(%esi)
0x0049c51a:	movdqa 0x40(%edi), %xmm4
0x0049c51f:	movdqa 0x50(%edi), %xmm5
0x0049c524:	movdqa 0x60(%edi), %xmm6
0x0049c529:	movdqa 0x70(%edi), %xmm7
0x0049c52e:	leal %esi, 0x80(%esi)
0x0049c534:	leal %edi, 0x80(%edi)
0x0049c53a:	decl %edx
0x0049c53b:	jne 0x0049c4e0
0x0049c53d:	testl %ecx, %ecx
0x0049c53f:	je 95
0x0049c541:	movl %edx, %ecx
0x0049c543:	shrl %edx, $0x5<UINT8>
0x0049c546:	testl %edx, %edx
0x0049c548:	je 0x0049c56b
0x0049c54a:	leal %ebx, (%ebx)
0x0049c550:	movdqu %xmm0, (%esi)
0x0049c554:	movdqu %xmm1, 0x10(%esi)
0x0049c559:	movdqu (%edi), %xmm0
0x0049c55d:	movdqu 0x10(%edi), %xmm1
0x0049c562:	leal %esi, 0x20(%esi)
0x0049c565:	leal %edi, 0x20(%edi)
0x0049c568:	decl %edx
0x0049c569:	jne 0x0049c550
0x0049c58d:	movb %al, (%esi)
0x0049c58f:	movb (%edi), %al
0x0049c591:	incl %esi
0x0049c592:	incl %edi
0x0049c593:	decl %ecx
0x0049c594:	jne 0x0049c58d
0x0049c596:	leal %esp, (%esp)
0x0049c59d:	leal %ecx, (%ecx)
0x004b9abe:	movl %eax, (%esi)
0x004b9ac0:	movl %ecx, $0x100<UINT32>
0x004b9ac5:	pushl %ecx
0x004b9ac6:	movl %eax, (%eax)
0x004b9ac8:	movl %eax, 0x48(%eax)
0x004b9acb:	addl %eax, $0x119<UINT32>
0x004b9ad0:	pushl %eax
0x004b9ad1:	pushl %ecx
0x004b9ad2:	pushl $0x4ed940<UINT32>
0x004b9ad7:	call 0x004a55f3
0x0049c0e0:	btl 0x4f04b8, $0x0<UINT8>
0x0049c0e8:	jae 0x0049c297
0x0049c297:	testl %edi, $0x3<UINT32>
0x0049c29d:	je 0x0049c2b2
0x0049c2b2:	movl %edx, %ecx
0x0049c2b4:	cmpl %ecx, $0x20<UINT8>
0x0049c2b7:	jb 686
0x0049c2bd:	shrl %ecx, $0x2<UINT8>
0x0049c2c0:	rep movsl %es:(%edi), %ds:(%esi)
0x0049c2c2:	andl %edx, $0x3<UINT8>
0x0049c2c5:	jmp 0x0049c2e4
0x0049c2e4:	movl %eax, 0xc(%esp)
0x0049c2e8:	popl %esi
0x0049c2e9:	popl %edi
0x0049c2ea:	ret

0x004b9adc:	movl %eax, 0x4edc60
0x004b9ae1:	addl %esp, $0x30<UINT8>
0x004b9ae4:	orl %ecx, $0xffffffff<UINT8>
0x004b9ae7:	xaddl (%eax), %ecx
0x004b9aeb:	jne 0x004b9b00
0x004b9b00:	movl %eax, (%esi)
0x004b9b02:	movl %eax, (%eax)
0x004b9b04:	movl %eax, 0x48(%eax)
0x004b9b07:	movl 0x4edc60, %eax
0x004b9b0c:	movl %eax, (%esi)
0x004b9b0e:	movl %eax, (%eax)
0x004b9b10:	movl %eax, 0x48(%eax)
0x004b9b13:	incl (%eax)
0x004b9b16:	popl %esi
0x004b9b17:	ret

0x004b9a0c:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004b9a13:	call 0x004b9a20
0x004b9a20:	movl %eax, 0x10(%ebp)
0x004b9a23:	pushl (%eax)
0x004b9a25:	call 0x004abb1d
0x004b9a2a:	popl %ecx
0x004b9a2b:	ret

0x004b9a18:	call 0x0046e176
0x004b9a1d:	ret $0xc<UINT16>

0x004b9a50:	movl %esp, %ebp
0x004b9a52:	popl %ebp
0x004b9a53:	ret

0x004b9eac:	cmpb 0xc(%ebp), $0x0<UINT8>
0x004b9eb0:	popl %ecx
0x004b9eb1:	popl %ecx
0x004b9eb2:	je -123
0x004b9eb4:	movl %eax, 0x4edc60
0x004b9eb9:	movl 0x4ed554, %eax
0x004b9ebe:	jmp 0x004b9e39
0x004b9e39:	pushl %edi
0x004b9e3a:	call 0x004b2ce4
0x004b9e3f:	popl %ecx
0x004b9e40:	popl %edi
0x004b9e41:	movl %eax, %esi
0x004b9e43:	popl %esi
0x004b9e44:	popl %ebx
0x004b9e45:	movl %esp, %ebp
0x004b9e47:	popl %ebp
0x004b9e48:	ret

0x004b9ed5:	popl %ecx
0x004b9ed6:	popl %ecx
0x004b9ed7:	movb 0x4f0e04, $0x1<UINT8>
0x004b9ede:	movb %al, $0x1<UINT8>
0x004b9ee0:	ret

0x004b0338:	pushl $0x4f09e4<UINT32>
0x004b033d:	call 0x004b02c5
0x004b02c5:	movl %edi, %edi
0x004b02c7:	pushl %ebp
0x004b02c8:	movl %ebp, %esp
0x004b02ca:	pushl %esi
0x004b02cb:	movl %esi, 0x8(%ebp)
0x004b02ce:	testl %esi, %esi
0x004b02d0:	jne 0x004b02d7
0x004b02d7:	movl %eax, (%esi)
0x004b02d9:	cmpl %eax, 0x8(%esi)
0x004b02dc:	jne 31
0x004b02de:	movl %eax, 0x4ed06c
0x004b02e3:	andl %eax, $0x1f<UINT8>
0x004b02e6:	pushl $0x20<UINT8>
0x004b02e8:	popl %ecx
0x004b02e9:	subl %ecx, %eax
0x004b02eb:	xorl %eax, %eax
0x004b02ed:	rorl %eax, %cl
0x004b02ef:	xorl %eax, 0x4ed06c
0x004b02f5:	movl (%esi), %eax
0x004b02f7:	movl 0x4(%esi), %eax
0x004b02fa:	movl 0x8(%esi), %eax
0x004b02fd:	xorl %eax, %eax
0x004b02ff:	popl %esi
0x004b0300:	popl %ebp
0x004b0301:	ret

0x004b0342:	movl (%esp), $0x4f09f0<UINT32>
0x004b0349:	call 0x004b02c5
0x004b034e:	popl %ecx
0x004b034f:	movb %al, $0x1<UINT8>
0x004b0351:	ret

0x004ba6b2:	cmpl %esi, 0xc(%ebp)
0x004ba6b5:	jne 4
0x004ba6b7:	movb %al, $0x1<UINT8>
0x004ba6b9:	jmp 0x004ba6e7
0x004ba6e7:	popl %ebx
0x004ba6e8:	popl %esi
0x004ba6e9:	movl %ecx, -4(%ebp)
0x004ba6ec:	xorl %ecx, %ebp
0x004ba6ee:	popl %edi
0x004ba6ef:	call 0x0046d108
0x004ba6f4:	movl %esp, %ebp
0x004ba6f6:	popl %ebp
0x004ba6f7:	ret

0x004b0426:	popl %ecx
0x004b0427:	popl %ecx
0x004b0428:	ret

0x0046d242:	testb %al, %al
0x0046d244:	jne 0x0046d250
0x0046d250:	movb %al, $0x1<UINT8>
0x0046d252:	popl %ebp
0x0046d253:	ret

0x0046d9e2:	popl %ecx
0x0046d9e3:	testb %al, %al
0x0046d9e5:	je 330
0x0046d9eb:	xorb %bl, %bl
0x0046d9ed:	movb -25(%ebp), %bl
0x0046d9f0:	andl -4(%ebp), $0x0<UINT8>
0x0046d9f4:	call 0x0046d1e9
0x0046d1e9:	pushl %esi
0x0046d1ea:	call 0x0046df3c
0x0046df3c:	xorl %eax, %eax
0x0046df3e:	cmpl 0x4f12b0, %eax
0x0046df44:	setne %al
0x0046df47:	ret

0x0046d1ef:	testl %eax, %eax
0x0046d1f1:	je 0x0046d213
0x0046d213:	xorb %al, %al
0x0046d215:	popl %esi
0x0046d216:	ret

0x0046d9f9:	movb -36(%ebp), %al
0x0046d9fc:	movl %eax, 0x4f0148
0x0046da01:	xorl %ecx, %ecx
0x0046da03:	incl %ecx
0x0046da04:	cmpl %eax, %ecx
0x0046da06:	je 297
0x0046da0c:	testl %eax, %eax
0x0046da0e:	jne 73
0x0046da10:	movl 0x4f0148, %ecx
0x0046da16:	pushl $0x4ca5e8<UINT32>
0x0046da1b:	pushl $0x4ca5c4<UINT32>
0x0046da20:	call 0x004b057d
0x004b057d:	movl %edi, %edi
0x004b057f:	pushl %ebp
0x004b0580:	movl %ebp, %esp
0x004b0582:	pushl %ecx
0x004b0583:	movl %eax, 0x4ed06c
0x004b0588:	xorl %eax, %ebp
0x004b058a:	movl -4(%ebp), %eax
0x004b058d:	pushl %esi
0x004b058e:	movl %esi, 0x8(%ebp)
0x004b0591:	pushl %edi
0x004b0592:	jmp 0x004b05ab
0x004b05ab:	cmpl %esi, 0xc(%ebp)
0x004b05ae:	jne 0x004b0594
0x004b0594:	movl %edi, (%esi)
0x004b0596:	testl %edi, %edi
0x004b0598:	je 0x004b05a8
0x004b05a8:	addl %esi, $0x4<UINT8>
0x004b059a:	movl %ecx, %edi
0x004b059c:	call 0x00403560
0x004b05a2:	call 0xe8006a00
0x0046d90a:	pushl %esi
0x0046d90b:	pushl $0x2<UINT8>
0x0046d90d:	call 0x004b0441
0x004b0441:	movl %edi, %edi
0x004b0443:	pushl %ebp
0x004b0444:	movl %ebp, %esp
0x004b0446:	movl %eax, 0x8(%ebp)
0x004b0449:	movl 0x4f09fc, %eax
0x004b044e:	popl %ebp
0x004b044f:	ret

0x0046d912:	call 0x0046e223
0x0046e223:	movl %eax, $0x4000<UINT32>
0x0046e228:	ret

0x0046d917:	pushl %eax
0x0046d918:	call 0x004b05ee
0x004b05ee:	movl %edi, %edi
0x004b05f0:	pushl %ebp
0x004b05f1:	movl %ebp, %esp
0x004b05f3:	movl %eax, 0x8(%ebp)
0x004b05f6:	cmpl %eax, $0x4000<UINT32>
0x004b05fb:	je 0x004b0620
0x004b0620:	movl %ecx, $0x4f0e24<UINT32>
0x004b0625:	xchgl (%ecx), %eax
0x004b0627:	xorl %eax, %eax
0x004b0629:	popl %ebp
0x004b062a:	ret

0x0046d91d:	call 0x004b18a6
0x004b18a6:	movl %eax, $0x4f0a10<UINT32>
0x004b18ab:	ret

0x0046d922:	movl %esi, %eax
0x0046d924:	call 0x0040fe30
0x0040fe30:	xorl %eax, %eax
0x0040fe32:	ret

0x0046d929:	pushl $0x1<UINT8>
0x0046d92b:	movl (%esi), %eax
0x0046d92d:	call 0x0046d254
0x0046d254:	pushl %ebp
0x0046d255:	movl %ebp, %esp
0x0046d257:	subl %esp, $0xc<UINT8>
0x0046d25a:	cmpb 0x4f0151, $0x0<UINT8>
0x0046d261:	je 0x0046d267
0x0046d267:	pushl %esi
0x0046d268:	movl %esi, 0x8(%ebp)
0x0046d26b:	testl %esi, %esi
0x0046d26d:	je 5
0x0046d26f:	cmpl %esi, $0x1<UINT8>
0x0046d272:	jne 125
0x0046d274:	call 0x0046df3c
0x0046d279:	testl %eax, %eax
0x0046d27b:	je 0x0046d2a3
0x0046d2a3:	movl %eax, 0x4ed06c
0x0046d2a8:	leal %esi, -12(%ebp)
0x0046d2ab:	pushl %edi
0x0046d2ac:	andl %eax, $0x1f<UINT8>
0x0046d2af:	movl %edi, $0x4f0154<UINT32>
0x0046d2b4:	pushl $0x20<UINT8>
0x0046d2b6:	popl %ecx
0x0046d2b7:	subl %ecx, %eax
0x0046d2b9:	orl %eax, $0xffffffff<UINT8>
0x0046d2bc:	rorl %eax, %cl
0x0046d2be:	xorl %eax, 0x4ed06c
0x0046d2c4:	movl -12(%ebp), %eax
0x0046d2c7:	movl -8(%ebp), %eax
0x0046d2ca:	movl -4(%ebp), %eax
0x0046d2cd:	movsl %es:(%edi), %ds:(%esi)
0x0046d2ce:	movsl %es:(%edi), %ds:(%esi)
0x0046d2cf:	movsl %es:(%edi), %ds:(%esi)
0x0046d2d0:	movl %edi, $0x4f0160<UINT32>
0x0046d2d5:	movl -12(%ebp), %eax
0x0046d2d8:	movl -8(%ebp), %eax
0x0046d2db:	leal %esi, -12(%ebp)
0x0046d2de:	movl -4(%ebp), %eax
0x0046d2e1:	movsl %es:(%edi), %ds:(%esi)
0x0046d2e2:	movsl %es:(%edi), %ds:(%esi)
0x0046d2e3:	movsl %es:(%edi), %ds:(%esi)
0x0046d2e4:	popl %edi
0x0046d2e5:	movb 0x4f0151, $0x1<UINT8>
0x0046d2ec:	movb %al, $0x1<UINT8>
0x0046d2ee:	popl %esi
0x0046d2ef:	leave
0x0046d2f0:	ret

0x0046d932:	addl %esp, $0xc<UINT8>
0x0046d935:	popl %esi
0x0046d936:	testb %al, %al
0x0046d938:	je 115
0x0046d93a:	fnclex
0x0046d93c:	call 0x0046e28b
0x0046e28b:	pushl %ebx
0x0046e28c:	pushl %esi
0x0046e28d:	movl %esi, $0x4e1208<UINT32>
0x0046e292:	movl %ebx, $0x4e1208<UINT32>
0x0046e297:	cmpl %esi, %ebx
0x0046e299:	jae 0x0046e2b4
0x0046e2b4:	popl %esi
0x0046e2b5:	popl %ebx
0x0046e2b6:	ret

0x0046d941:	pushl $0x46e2b7<UINT32>
0x0046d946:	call 0x0046d40d
0x0046d40d:	pushl %ebp
0x0046d40e:	movl %ebp, %esp
0x0046d410:	pushl 0x8(%ebp)
0x0046d413:	call 0x0046d3d2
0x0046d3d2:	pushl %ebp
0x0046d3d3:	movl %ebp, %esp
0x0046d3d5:	movl %eax, 0x4ed06c
0x0046d3da:	movl %ecx, %eax
0x0046d3dc:	xorl %eax, 0x4f0154
0x0046d3e2:	andl %ecx, $0x1f<UINT8>
0x0046d3e5:	pushl 0x8(%ebp)
0x0046d3e8:	rorl %eax, %cl
0x0046d3ea:	cmpl %eax, $0xffffffff<UINT8>
0x0046d3ed:	jne 7
0x0046d3ef:	call 0x004b0292
0x004b0292:	movl %edi, %edi
0x004b0294:	pushl %ebp
0x004b0295:	movl %ebp, %esp
0x004b0297:	pushl 0x8(%ebp)
0x004b029a:	pushl $0x4f09e4<UINT32>
0x004b029f:	call 0x004b0302
0x004b0302:	movl %edi, %edi
0x004b0304:	pushl %ebp
0x004b0305:	movl %ebp, %esp
0x004b0307:	pushl %ecx
0x004b0308:	pushl %ecx
0x004b0309:	leal %eax, 0x8(%ebp)
0x004b030c:	movl -8(%ebp), %eax
0x004b030f:	leal %eax, 0xc(%ebp)
0x004b0312:	movl -4(%ebp), %eax
0x004b0315:	leal %eax, -8(%ebp)
0x004b0318:	pushl %eax
0x004b0319:	pushl $0x2<UINT8>
0x004b031b:	call 0x004b0009
0x004b0009:	movl %edi, %edi
0x004b000b:	pushl %ebp
0x004b000c:	movl %ebp, %esp
0x004b000e:	subl %esp, $0xc<UINT8>
0x004b0011:	movl %eax, 0x8(%ebp)
0x004b0014:	leal %ecx, -1(%ebp)
0x004b0017:	movl -8(%ebp), %eax
0x004b001a:	movl -12(%ebp), %eax
0x004b001d:	leal %eax, -8(%ebp)
0x004b0020:	pushl %eax
0x004b0021:	pushl 0xc(%ebp)
0x004b0024:	leal %eax, -12(%ebp)
0x004b0027:	pushl %eax
0x004b0028:	call 0x004aff3f
0x004aff3f:	pushl $0xc<UINT8>
0x004aff41:	pushl $0x4ea9f8<UINT32>
0x004aff46:	call 0x0046e130
0x004aff4b:	andl -28(%ebp), $0x0<UINT8>
0x004aff4f:	movl %eax, 0x8(%ebp)
0x004aff52:	pushl (%eax)
0x004aff54:	call 0x004abad5
0x004aff59:	popl %ecx
0x004aff5a:	andl -4(%ebp), $0x0<UINT8>
0x004aff5e:	movl %ecx, 0xc(%ebp)
0x004aff61:	call 0x004b0151
0x004b0151:	movl %edi, %edi
0x004b0153:	pushl %ebp
0x004b0154:	movl %ebp, %esp
0x004b0156:	subl %esp, $0xc<UINT8>
0x004b0159:	movl %eax, %ecx
0x004b015b:	movl -8(%ebp), %eax
0x004b015e:	pushl %esi
0x004b015f:	movl %eax, (%eax)
0x004b0161:	movl %esi, (%eax)
0x004b0163:	testl %esi, %esi
0x004b0165:	jne 0x004b016f
0x004b016f:	movl %eax, 0x4ed06c
0x004b0174:	movl %ecx, %eax
0x004b0176:	pushl %ebx
0x004b0177:	movl %ebx, (%esi)
0x004b0179:	andl %ecx, $0x1f<UINT8>
0x004b017c:	pushl %edi
0x004b017d:	movl %edi, 0x4(%esi)
0x004b0180:	xorl %ebx, %eax
0x004b0182:	movl %esi, 0x8(%esi)
0x004b0185:	xorl %edi, %eax
0x004b0187:	xorl %esi, %eax
0x004b0189:	rorl %edi, %cl
0x004b018b:	rorl %esi, %cl
0x004b018d:	rorl %ebx, %cl
0x004b018f:	cmpl %edi, %esi
0x004b0191:	jne 0x004b024b
0x004b0197:	subl %esi, %ebx
0x004b0199:	movl %eax, $0x200<UINT32>
0x004b019e:	sarl %esi, $0x2<UINT8>
0x004b01a1:	cmpl %esi, %eax
0x004b01a3:	ja 2
0x004b01a5:	movl %eax, %esi
0x004b01a7:	leal %edi, (%eax,%esi)
0x004b01aa:	testl %edi, %edi
0x004b01ac:	jne 3
0x004b01ae:	pushl $0x20<UINT8>
0x004b01b0:	popl %edi
0x004b01b1:	cmpl %edi, %esi
0x004b01b3:	jb 29
0x004b01b5:	pushl $0x4<UINT8>
0x004b01b7:	pushl %edi
0x004b01b8:	pushl %ebx
0x004b01b9:	call 0x004ba5e2
0x004ba5e2:	movl %edi, %edi
0x004ba5e4:	pushl %ebp
0x004ba5e5:	movl %ebp, %esp
0x004ba5e7:	popl %ebp
0x004ba5e8:	jmp 0x004ba5ed
0x004ba5ed:	movl %edi, %edi
0x004ba5ef:	pushl %ebp
0x004ba5f0:	movl %ebp, %esp
0x004ba5f2:	pushl %esi
0x004ba5f3:	movl %esi, 0xc(%ebp)
0x004ba5f6:	testl %esi, %esi
0x004ba5f8:	je 27
0x004ba5fa:	pushl $0xffffffe0<UINT8>
0x004ba5fc:	xorl %edx, %edx
0x004ba5fe:	popl %eax
0x004ba5ff:	divl %eax, %esi
0x004ba601:	cmpl %eax, 0x10(%ebp)
0x004ba604:	jae 0x004ba615
0x004ba615:	pushl %ebx
0x004ba616:	movl %ebx, 0x8(%ebp)
0x004ba619:	pushl %edi
0x004ba61a:	testl %ebx, %ebx
0x004ba61c:	je 0x004ba629
0x004ba629:	xorl %edi, %edi
0x004ba62b:	imull %esi, 0x10(%ebp)
0x004ba62f:	pushl %esi
0x004ba630:	pushl %ebx
0x004ba631:	call 0x004b6e02
0x004b6e02:	movl %edi, %edi
0x004b6e04:	pushl %ebp
0x004b6e05:	movl %ebp, %esp
0x004b6e07:	pushl %edi
0x004b6e08:	movl %edi, 0x8(%ebp)
0x004b6e0b:	testl %edi, %edi
0x004b6e0d:	jne 11
0x004b6e0f:	pushl 0xc(%ebp)
0x004b6e12:	call 0x004b36d4
0x004b6e17:	popl %ecx
0x004b6e18:	jmp 0x004b6e3e
0x004b6e3e:	popl %edi
0x004b6e3f:	popl %ebp
0x004b6e40:	ret

0x004ba636:	movl %ebx, %eax
0x004ba638:	popl %ecx
0x004ba639:	popl %ecx
0x004ba63a:	testl %ebx, %ebx
0x004ba63c:	je 21
0x004ba63e:	cmpl %edi, %esi
0x004ba640:	jae 17
0x004ba642:	subl %esi, %edi
0x004ba644:	leal %eax, (%ebx,%edi)
0x004ba647:	pushl %esi
0x004ba648:	pushl $0x0<UINT8>
0x004ba64a:	pushl %eax
0x004ba64b:	call 0x0049c5f0
0x0049c6ad:	btl 0x4ed080, $0x1<UINT8>
0x0049c6b5:	jae 62
0x0049c6b7:	movd %xmm0, %eax
0x0049c6bb:	pshufd %xmm0, %xmm0, $0x0<UINT8>
0x004ba650:	addl %esp, $0xc<UINT8>
0x004ba653:	popl %edi
0x004ba654:	movl %eax, %ebx
0x004ba656:	popl %ebx
0x004ba657:	popl %esi
0x004ba658:	popl %ebp
0x004ba659:	ret

0x004b01be:	pushl $0x0<UINT8>
0x004b01c0:	movl -4(%ebp), %eax
0x004b01c3:	call 0x004b2ce4
0x004b01c8:	movl %ecx, -4(%ebp)
0x004b01cb:	addl %esp, $0x10<UINT8>
0x004b01ce:	testl %ecx, %ecx
0x004b01d0:	jne 0x004b01fa
0x004b01fa:	leal %eax, (%ecx,%esi,4)
0x004b01fd:	movl %ebx, %ecx
0x004b01ff:	movl -4(%ebp), %eax
0x004b0202:	leal %esi, (%ecx,%edi,4)
0x004b0205:	movl %eax, 0x4ed06c
0x004b020a:	movl %edi, -4(%ebp)
0x004b020d:	andl %eax, $0x1f<UINT8>
0x004b0210:	pushl $0x20<UINT8>
0x004b0212:	popl %ecx
0x004b0213:	subl %ecx, %eax
0x004b0215:	xorl %eax, %eax
0x004b0217:	rorl %eax, %cl
0x004b0219:	movl %ecx, %edi
0x004b021b:	xorl %eax, 0x4ed06c
0x004b0221:	movl -12(%ebp), %eax
0x004b0224:	movl %eax, %esi
0x004b0226:	subl %eax, %edi
0x004b0228:	addl %eax, $0x3<UINT8>
0x004b022b:	shrl %eax, $0x2<UINT8>
0x004b022e:	cmpl %esi, %edi
0x004b0230:	sbbl %edx, %edx
0x004b0232:	notl %edx
0x004b0234:	andl %edx, %eax
0x004b0236:	movl -4(%ebp), %edx
0x004b0239:	je 16
0x004b023b:	movl %edx, -12(%ebp)
0x004b023e:	xorl %eax, %eax
0x004b0240:	incl %eax
0x004b0241:	movl (%ecx), %edx
0x004b0243:	leal %ecx, 0x4(%ecx)
0x004b0246:	cmpl %eax, -4(%ebp)
0x004b0249:	jne 0x004b0240
0x004b024b:	movl %eax, -8(%ebp)
0x004b024e:	movl %eax, 0x4(%eax)
0x004b0251:	pushl (%eax)
0x004b0253:	call 0x004af563
0x004af563:	movl %edi, %edi
0x004af565:	pushl %ebp
0x004af566:	movl %ebp, %esp
0x004af568:	movl %eax, 0x4ed06c
0x004af56d:	andl %eax, $0x1f<UINT8>
0x004af570:	pushl $0x20<UINT8>
0x004af572:	popl %ecx
0x004af573:	subl %ecx, %eax
0x004af575:	movl %eax, 0x8(%ebp)
0x004af578:	rorl %eax, %cl
0x004af57a:	xorl %eax, 0x4ed06c
0x004af580:	popl %ebp
0x004af581:	ret

0x004b0258:	pushl %ebx
0x004b0259:	movl (%edi), %eax
0x004b025b:	call 0x0046d188
0x004b0260:	movl %ebx, -8(%ebp)
0x004b0263:	movl %ecx, (%ebx)
0x004b0265:	movl %ecx, (%ecx)
0x004b0267:	movl (%ecx), %eax
0x004b0269:	leal %eax, 0x4(%edi)
0x004b026c:	pushl %eax
0x004b026d:	call 0x0046d188
0x004b0272:	movl %ecx, (%ebx)
0x004b0274:	pushl %esi
0x004b0275:	movl %ecx, (%ecx)
0x004b0277:	movl 0x4(%ecx), %eax
0x004b027a:	call 0x0046d188
0x004b027f:	movl %ecx, (%ebx)
0x004b0281:	addl %esp, $0x10<UINT8>
0x004b0284:	movl %ecx, (%ecx)
0x004b0286:	movl 0x8(%ecx), %eax
0x004b0289:	xorl %eax, %eax
0x004b028b:	popl %edi
0x004b028c:	popl %ebx
0x004b028d:	popl %esi
0x004b028e:	movl %esp, %ebp
0x004b0290:	popl %ebp
0x004b0291:	ret

0x004aff66:	movl %esi, %eax
0x004aff68:	movl -28(%ebp), %esi
0x004aff6b:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004aff72:	call 0x004aff84
0x004aff84:	movl %eax, 0x10(%ebp)
0x004aff87:	pushl (%eax)
0x004aff89:	call 0x004abb1d
0x004aff8e:	popl %ecx
0x004aff8f:	ret

0x004aff77:	movl %eax, %esi
0x004aff79:	call 0x0046e176
0x004aff7e:	ret $0xc<UINT16>

0x004b002d:	movl %esp, %ebp
0x004b002f:	popl %ebp
0x004b0030:	ret

0x004b0320:	popl %ecx
0x004b0321:	popl %ecx
0x004b0322:	movl %esp, %ebp
0x004b0324:	popl %ebp
0x004b0325:	ret

0x004b02a4:	popl %ecx
0x004b02a5:	popl %ecx
0x004b02a6:	popl %ebp
0x004b02a7:	ret

0x0046d3f4:	jmp 0x0046d401
0x0046d401:	negl %eax
0x0046d403:	popl %ecx
0x0046d404:	sbbl %eax, %eax
0x0046d406:	notl %eax
0x0046d408:	andl %eax, 0x8(%ebp)
0x0046d40b:	popl %ebp
0x0046d40c:	ret

0x0046d418:	negl %eax
0x0046d41a:	popl %ecx
0x0046d41b:	sbbl %eax, %eax
0x0046d41d:	negl %eax
0x0046d41f:	decl %eax
0x0046d420:	popl %ebp
0x0046d421:	ret

0x0046d94b:	call 0x0046df38
0x0046df38:	xorl %eax, %eax
0x0046df3a:	incl %eax
0x0046df3b:	ret

0x0046d950:	pushl %eax
0x0046d951:	call 0x004afb28
0x004afb28:	movl %edi, %edi
0x004afb2a:	pushl %ebp
0x004afb2b:	movl %ebp, %esp
0x004afb2d:	popl %ebp
0x004afb2e:	jmp 0x004af82e
0x004af82e:	movl %edi, %edi
0x004af830:	pushl %ebp
0x004af831:	movl %ebp, %esp
0x004af833:	subl %esp, $0xc<UINT8>
0x004af836:	cmpl 0x8(%ebp), $0x2<UINT8>
0x004af83a:	pushl %esi
0x004af83b:	je 28
0x004af83d:	cmpl 0x8(%ebp), $0x1<UINT8>
0x004af841:	je 0x004af859
0x004af859:	pushl %ebx
0x004af85a:	pushl %edi
0x004af85b:	pushl $0x104<UINT32>
0x004af860:	movl %esi, $0x4f07c8<UINT32>
0x004af865:	xorl %edi, %edi
0x004af867:	pushl %esi
0x004af868:	pushl %edi
0x004af869:	call GetModuleFileNameW@KERNEL32.DLL
GetModuleFileNameW@KERNEL32.DLL: API Node	
0x004af86f:	movl %ebx, 0x4f0e18
0x004af875:	movl 0x4f0e1c, %esi
0x004af87b:	testl %ebx, %ebx
0x004af87d:	je 5
0x004af87f:	cmpw (%ebx), %di
0x004af882:	jne 0x004af886
0x004af886:	leal %eax, -12(%ebp)
0x004af889:	movl -4(%ebp), %edi
0x004af88c:	pushl %eax
0x004af88d:	leal %eax, -4(%ebp)
0x004af890:	movl -12(%ebp), %edi
0x004af893:	pushl %eax
0x004af894:	pushl %edi
0x004af895:	pushl %edi
0x004af896:	pushl %ebx
0x004af897:	call 0x004af94d
0x004af94d:	movl %edi, %edi
0x004af94f:	pushl %ebp
0x004af950:	movl %ebp, %esp
0x004af952:	movl %eax, 0x14(%ebp)
0x004af955:	subl %esp, $0x10<UINT8>
0x004af958:	movl %ecx, 0x8(%ebp)
0x004af95b:	movl %edx, 0x10(%ebp)
0x004af95e:	pushl %ebx
0x004af95f:	pushl %esi
0x004af960:	movl %esi, 0xc(%ebp)
0x004af963:	xorl %ebx, %ebx
0x004af965:	pushl %edi
0x004af966:	movl %edi, 0x18(%ebp)
0x004af969:	movl (%edi), %ebx
0x004af96b:	movl (%eax), $0x1<UINT32>
0x004af971:	testl %esi, %esi
0x004af973:	je 0x004af97d
0x004af97d:	movl -8(%ebp), $0x20<UINT32>
0x004af984:	movl -12(%ebp), $0x9<UINT32>
0x004af98b:	pushl $0x22<UINT8>
0x004af98d:	popl %eax
0x004af98e:	cmpw (%ecx), %ax
0x004af991:	jne 0x004af99d
0x004af993:	testb %bl, %bl
0x004af995:	sete %bl
0x004af998:	addl %ecx, $0x2<UINT8>
0x004af99b:	jmp 0x004af9b7
0x004af9b7:	testb %bl, %bl
0x004af9b9:	jne 0x004af98b
0x004af99d:	incl (%edi)
0x004af99f:	testl %edx, %edx
0x004af9a1:	je 0x004af9ac
0x004af9ac:	movzwl %eax, (%ecx)
0x004af9af:	addl %ecx, $0x2<UINT8>
0x004af9b2:	testw %ax, %ax
0x004af9b5:	je 0x004af9d6
0x004af9bb:	cmpw %ax, -8(%ebp)
0x004af9bf:	je 9
0x004af9c1:	cmpw %ax, -12(%ebp)
0x004af9c5:	pushl $0x22<UINT8>
0x004af9c7:	popl %eax
0x004af9c8:	jne 0x004af98e
0x004af9d6:	subl %ecx, $0x2<UINT8>
0x004af9d9:	movl %ebx, 0x14(%ebp)
0x004af9dc:	xorl %eax, %eax
0x004af9de:	movb -1(%ebp), %al
0x004af9e1:	cmpw (%ecx), %ax
0x004af9e4:	je 0x004afac4
0x004afac4:	testl %esi, %esi
0x004afac6:	je 0x004afaca
0x004afaca:	incl (%ebx)
0x004afacc:	popl %edi
0x004afacd:	popl %esi
0x004aface:	popl %ebx
0x004afacf:	movl %esp, %ebp
0x004afad1:	popl %ebp
0x004afad2:	ret

0x004af89c:	pushl $0x2<UINT8>
0x004af89e:	pushl -12(%ebp)
0x004af8a1:	pushl -4(%ebp)
0x004af8a4:	call 0x004afad3
0x004afad3:	movl %edi, %edi
0x004afad5:	pushl %ebp
0x004afad6:	movl %ebp, %esp
0x004afad8:	pushl %esi
0x004afad9:	movl %esi, 0x8(%ebp)
0x004afadc:	cmpl %esi, $0x3fffffff<UINT32>
0x004afae2:	jb 0x004afae8
0x004afae8:	pushl %edi
0x004afae9:	orl %edi, $0xffffffff<UINT8>
0x004afaec:	movl %ecx, 0xc(%ebp)
0x004afaef:	xorl %edx, %edx
0x004afaf1:	movl %eax, %edi
0x004afaf3:	divl %eax, 0x10(%ebp)
0x004afaf6:	cmpl %ecx, %eax
0x004afaf8:	jae 13
0x004afafa:	imull %ecx, 0x10(%ebp)
0x004afafe:	shll %esi, $0x2<UINT8>
0x004afb01:	subl %edi, %esi
0x004afb03:	cmpl %edi, %ecx
0x004afb05:	ja 0x004afb0b
0x004afb0b:	leal %eax, (%ecx,%esi)
0x004afb0e:	pushl $0x1<UINT8>
0x004afb10:	pushl %eax
0x004afb11:	call 0x004b3a07
0x004afb16:	pushl $0x0<UINT8>
0x004afb18:	movl %esi, %eax
0x004afb1a:	call 0x004b2ce4
0x004afb1f:	addl %esp, $0xc<UINT8>
0x004afb22:	movl %eax, %esi
0x004afb24:	popl %edi
0x004afb25:	popl %esi
0x004afb26:	popl %ebp
0x004afb27:	ret

0x004af8a9:	movl %esi, %eax
0x004af8ab:	addl %esp, $0x20<UINT8>
0x004af8ae:	testl %esi, %esi
0x004af8b0:	jne 0x004af8be
0x004af8be:	leal %eax, -12(%ebp)
0x004af8c1:	pushl %eax
0x004af8c2:	leal %eax, -4(%ebp)
0x004af8c5:	pushl %eax
0x004af8c6:	movl %eax, -4(%ebp)
0x004af8c9:	leal %eax, (%esi,%eax,4)
0x004af8cc:	pushl %eax
0x004af8cd:	pushl %esi
0x004af8ce:	pushl %ebx
0x004af8cf:	call 0x004af94d
0x004af975:	movl (%esi), %edx
0x004af977:	addl %esi, $0x4<UINT8>
0x004af97a:	movl 0xc(%ebp), %esi
0x004af9a3:	movw %ax, (%ecx)
0x004af9a6:	movw (%edx), %ax
0x004af9a9:	addl %edx, $0x2<UINT8>
0x004afac8:	movl (%esi), %eax
0x004af8d4:	addl %esp, $0x14<UINT8>
0x004af8d7:	cmpl 0x8(%ebp), $0x1<UINT8>
0x004af8db:	jne 22
0x004af8dd:	movl %eax, -4(%ebp)
0x004af8e0:	decl %eax
0x004af8e1:	movl 0x4f0e08, %eax
0x004af8e6:	movl %eax, %esi
0x004af8e8:	movl %esi, %edi
0x004af8ea:	movl 0x4f0e10, %eax
0x004af8ef:	movl %ebx, %edi
0x004af8f1:	jmp 0x004af93d
0x004af93d:	pushl %esi
0x004af93e:	call 0x004b2ce4
0x004af943:	popl %ecx
0x004af944:	popl %edi
0x004af945:	movl %eax, %ebx
0x004af947:	popl %ebx
0x004af948:	popl %esi
0x004af949:	movl %esp, %ebp
0x004af94b:	popl %ebp
0x004af94c:	ret

0x0046d956:	popl %ecx
0x0046d957:	popl %ecx
0x0046d958:	testl %eax, %eax
0x0046d95a:	jne 81
0x0046d95c:	call 0x0046e229
0x0046e229:	pushl $0x4f04c8<UINT32>
0x0046e22e:	call InitializeSListHead@KERNEL32.DLL
InitializeSListHead@KERNEL32.DLL: API Node	
0x0046e234:	ret

0x0046d961:	call 0x0046e273
0x0046e273:	xorl %eax, %eax
0x0046e275:	cmpl 0x4ed090, %eax
0x0046e27b:	sete %al
0x0046e27e:	ret

0x0046d966:	testl %eax, %eax
0x0046d968:	je 0x0046d975
0x0046d975:	call 0x00403560
0x0046d97a:	call 0x00403560
0x0046d97f:	call 0x0046e235
0x0046e235:	pushl $0x30000<UINT32>
0x0046e23a:	pushl $0x10000<UINT32>
0x0046e23f:	pushl $0x0<UINT8>
0x0046e241:	call 0x004b18ac
0x004b18ac:	movl %edi, %edi
0x004b18ae:	pushl %ebp
0x004b18af:	movl %ebp, %esp
0x004b18b1:	movl %ecx, 0x10(%ebp)
0x004b18b4:	movl %eax, 0xc(%ebp)
0x004b18b7:	andl %ecx, $0xfff7ffff<UINT32>
0x004b18bd:	andl %eax, %ecx
0x004b18bf:	pushl %esi
0x004b18c0:	movl %esi, 0x8(%ebp)
0x004b18c3:	testl %eax, $0xfcf0fce0<UINT32>
0x004b18c8:	je 0x004b18ee
0x004b18ee:	pushl %ecx
0x004b18ef:	pushl 0xc(%ebp)
0x004b18f2:	testl %esi, %esi
0x004b18f4:	je 0x004b18ff
0x004b18ff:	call 0x004bce25
0x004bce25:	movl %edi, %edi
0x004bce27:	pushl %ebp
0x004bce28:	movl %ebp, %esp
0x004bce2a:	subl %esp, $0x10<UINT8>
0x004bce2d:	fwait
0x004bce2e:	fnstcw -8(%ebp)
0x004bce31:	movw %ax, -8(%ebp)
0x004bce35:	xorl %ecx, %ecx
0x004bce37:	testb %al, $0x1<UINT8>
0x004bce39:	je 0x004bce3e
0x004bce3e:	testb %al, $0x4<UINT8>
0x004bce40:	je 0x004bce45
0x004bce45:	testb %al, $0x8<UINT8>
0x004bce47:	je 3
0x004bce49:	orl %ecx, $0x4<UINT8>
0x004bce4c:	testb %al, $0x10<UINT8>
0x004bce4e:	je 3
0x004bce50:	orl %ecx, $0x2<UINT8>
0x004bce53:	testb %al, $0x20<UINT8>
0x004bce55:	je 0x004bce5a
0x004bce5a:	testb %al, $0x2<UINT8>
0x004bce5c:	je 0x004bce64
0x004bce64:	pushl %ebx
0x004bce65:	pushl %esi
0x004bce66:	movzwl %esi, %ax
0x004bce69:	movl %ebx, $0xc00<UINT32>
0x004bce6e:	movl %edx, %esi
0x004bce70:	pushl %edi
0x004bce71:	movl %edi, $0x200<UINT32>
0x004bce76:	andl %edx, %ebx
0x004bce78:	je 38
0x004bce7a:	cmpl %edx, $0x400<UINT32>
0x004bce80:	je 24
0x004bce82:	cmpl %edx, $0x800<UINT32>
0x004bce88:	je 12
0x004bce8a:	cmpl %edx, %ebx
0x004bce8c:	jne 18
0x004bce8e:	orl %ecx, $0x300<UINT32>
0x004bce94:	jmp 0x004bcea0
0x004bcea0:	andl %esi, $0x300<UINT32>
0x004bcea6:	je 12
0x004bcea8:	cmpl %esi, %edi
0x004bceaa:	jne 0x004bceba
0x004bceba:	movl %edx, $0x1000<UINT32>
0x004bcebf:	testw %dx, %ax
0x004bcec2:	je 6
0x004bcec4:	orl %ecx, $0x40000<UINT32>
0x004bceca:	movl %edi, 0xc(%ebp)
0x004bcecd:	movl %esi, %edi
0x004bcecf:	movl %eax, 0x8(%ebp)
0x004bced2:	notl %esi
0x004bced4:	andl %esi, %ecx
0x004bced6:	andl %eax, %edi
0x004bced8:	orl %esi, %eax
0x004bceda:	cmpl %esi, %ecx
0x004bcedc:	je 166
0x004bcee2:	pushl %esi
0x004bcee3:	call 0x004bd127
0x004bd127:	movl %edi, %edi
0x004bd129:	pushl %ebp
0x004bd12a:	movl %ebp, %esp
0x004bd12c:	movl %ecx, 0x8(%ebp)
0x004bd12f:	xorl %eax, %eax
0x004bd131:	testb %cl, $0x10<UINT8>
0x004bd134:	je 0x004bd137
0x004bd137:	testb %cl, $0x8<UINT8>
0x004bd13a:	je 0x004bd13f
0x004bd13f:	testb %cl, $0x4<UINT8>
0x004bd142:	je 3
0x004bd144:	orl %eax, $0x8<UINT8>
0x004bd147:	testb %cl, $0x2<UINT8>
0x004bd14a:	je 3
0x004bd14c:	orl %eax, $0x10<UINT8>
0x004bd14f:	testb %cl, $0x1<UINT8>
0x004bd152:	je 0x004bd157
0x004bd157:	testl %ecx, $0x80000<UINT32>
0x004bd15d:	je 0x004bd162
0x004bd162:	pushl %esi
0x004bd163:	movl %edx, %ecx
0x004bd165:	movl %esi, $0x300<UINT32>
0x004bd16a:	pushl %edi
0x004bd16b:	movl %edi, $0x200<UINT32>
0x004bd170:	andl %edx, %esi
0x004bd172:	je 35
0x004bd174:	cmpl %edx, $0x100<UINT32>
0x004bd17a:	je 22
0x004bd17c:	cmpl %edx, %edi
0x004bd17e:	je 11
0x004bd180:	cmpl %edx, %esi
0x004bd182:	jne 19
0x004bd184:	orl %eax, $0xc00<UINT32>
0x004bd189:	jmp 0x004bd197
0x004bd197:	movl %edx, %ecx
0x004bd199:	andl %edx, $0x30000<UINT32>
0x004bd19f:	je 12
0x004bd1a1:	cmpl %edx, $0x10000<UINT32>
0x004bd1a7:	jne 6
0x004bd1a9:	orl %eax, %edi
0x004bd1ab:	jmp 0x004bd1af
0x004bd1af:	popl %edi
0x004bd1b0:	popl %esi
0x004bd1b1:	testl %ecx, $0x40000<UINT32>
0x004bd1b7:	je 5
0x004bd1b9:	orl %eax, $0x1000<UINT32>
0x004bd1be:	popl %ebp
0x004bd1bf:	ret

0x004bcee8:	popl %ecx
0x004bcee9:	movw -4(%ebp), %ax
0x004bceed:	fldcw -4(%ebp)
0x004bcef0:	fwait
0x004bcef1:	fnstcw -4(%ebp)
0x004bcef4:	movw %ax, -4(%ebp)
0x004bcef8:	xorl %esi, %esi
0x004bcefa:	testb %al, $0x1<UINT8>
0x004bcefc:	je 0x004bcf01
0x004bcf01:	testb %al, $0x4<UINT8>
0x004bcf03:	je 0x004bcf08
0x004bcf08:	testb %al, $0x8<UINT8>
0x004bcf0a:	je 3
0x004bcf0c:	orl %esi, $0x4<UINT8>
0x004bcf0f:	testb %al, $0x10<UINT8>
0x004bcf11:	je 3
0x004bcf13:	orl %esi, $0x2<UINT8>
0x004bcf16:	testb %al, $0x20<UINT8>
0x004bcf18:	je 0x004bcf1d
0x004bcf1d:	testb %al, $0x2<UINT8>
0x004bcf1f:	je 0x004bcf27
0x004bcf27:	movzwl %edx, %ax
0x004bcf2a:	movl %ecx, %edx
0x004bcf2c:	andl %ecx, %ebx
0x004bcf2e:	je 42
0x004bcf30:	cmpl %ecx, $0x400<UINT32>
0x004bcf36:	je 28
0x004bcf38:	cmpl %ecx, $0x800<UINT32>
0x004bcf3e:	je 12
0x004bcf40:	cmpl %ecx, %ebx
0x004bcf42:	jne 22
0x004bcf44:	orl %esi, $0x300<UINT32>
0x004bcf4a:	jmp 0x004bcf5a
0x004bcf5a:	andl %edx, $0x300<UINT32>
0x004bcf60:	je 16
0x004bcf62:	cmpl %edx, $0x200<UINT32>
0x004bcf68:	jne 14
0x004bcf6a:	orl %esi, $0x10000<UINT32>
0x004bcf70:	jmp 0x004bcf78
0x004bcf78:	movl %edx, $0x1000<UINT32>
0x004bcf7d:	testw %dx, %ax
0x004bcf80:	je 6
0x004bcf82:	orl %esi, $0x40000<UINT32>
0x004bcf88:	cmpl 0x4f04b4, $0x1<UINT8>
0x004bcf8f:	jl 393
0x004bcf95:	andl %edi, $0x308031f<UINT32>
0x004bcf9b:	stmxcsr -16(%ebp)
0x004bcf9f:	movl %eax, -16(%ebp)
0x004bcfa2:	xorl %ecx, %ecx
0x004bcfa4:	testb %al, %al
0x004bcfa6:	jns 0x004bcfab
0x004bcfab:	testl %eax, $0x200<UINT32>
0x004bcfb0:	je 3
0x004bcfb2:	orl %ecx, $0x8<UINT8>
0x004bcfb5:	testl %eax, $0x400<UINT32>
0x004bcfba:	je 0x004bcfbf
0x004bcfbf:	testl %eax, $0x800<UINT32>
0x004bcfc4:	je 3
0x004bcfc6:	orl %ecx, $0x2<UINT8>
0x004bcfc9:	testl %edx, %eax
0x004bcfcb:	je 0x004bcfd0
0x004bcfd0:	testl %eax, $0x100<UINT32>
0x004bcfd5:	je 6
0x004bcfd7:	orl %ecx, $0x80000<UINT32>
0x004bcfdd:	movl %edx, %eax
0x004bcfdf:	movl %ebx, $0x6000<UINT32>
0x004bcfe4:	andl %edx, %ebx
0x004bcfe6:	je 42
0x004bcfe8:	cmpl %edx, $0x2000<UINT32>
0x004bcfee:	je 0x004bd00c
0x004bd00c:	orl %ecx, $0x100<UINT32>
0x004bd012:	pushl $0x40<UINT8>
0x004bd014:	andl %eax, $0x8040<UINT32>
0x004bd019:	popl %ebx
0x004bd01a:	subl %eax, %ebx
0x004bd01c:	je 0x004bd039
0x004bd039:	orl %ecx, $0x2000000<UINT32>
0x004bd03f:	movl %eax, %edi
0x004bd041:	andl %edi, 0x8(%ebp)
0x004bd044:	notl %eax
0x004bd046:	andl %eax, %ecx
0x004bd048:	orl %eax, %edi
0x004bd04a:	cmpl %eax, %ecx
0x004bd04c:	je 0x004bd107
0x004bd107:	movl %eax, %ecx
0x004bd109:	orl %ecx, %esi
0x004bd10b:	xorl %eax, %esi
0x004bd10d:	testl %eax, $0x8031f<UINT32>
0x004bd112:	je 6
0x004bd114:	orl %ecx, $0x80000000<UINT32>
0x004bd11a:	movl %eax, %ecx
0x004bd11c:	jmp 0x004bd120
0x004bd120:	popl %edi
0x004bd121:	popl %esi
0x004bd122:	popl %ebx
0x004bd123:	movl %esp, %ebp
0x004bd125:	popl %ebp
0x004bd126:	ret

0x004b1904:	popl %ecx
0x004b1905:	popl %ecx
0x004b1906:	xorl %eax, %eax
0x004b1908:	popl %esi
0x004b1909:	popl %ebp
0x004b190a:	ret

0x0046e246:	addl %esp, $0xc<UINT8>
0x0046e249:	testl %eax, %eax
0x0046e24b:	jne 1
0x0046e24d:	ret

0x0046d984:	call 0x0040fe30
0x0046d989:	pushl %eax
0x0046d98a:	call 0x004b0b5e
0x004b0b5e:	movl %edi, %edi
0x004b0b60:	pushl %ebp
0x004b0b61:	movl %ebp, %esp
0x004b0b63:	pushl %esi
0x004b0b64:	call 0x004b1dda
0x004b0b69:	movl %edx, 0x8(%ebp)
0x004b0b6c:	movl %esi, %eax
0x004b0b6e:	pushl $0x0<UINT8>
0x004b0b70:	popl %eax
0x004b0b71:	movl %ecx, 0x350(%esi)
0x004b0b77:	testb %cl, $0x2<UINT8>
0x004b0b7a:	sete %al
0x004b0b7d:	incl %eax
0x004b0b7e:	cmpl %edx, $0xffffffff<UINT8>
0x004b0b81:	je 51
0x004b0b83:	testl %edx, %edx
0x004b0b85:	je 0x004b0bbd
0x004b0bbd:	popl %esi
0x004b0bbe:	popl %ebp
0x004b0bbf:	ret

0x0046d98f:	popl %ecx
0x0046d990:	call 0x0043e0a0
0x0046d995:	testb %al, %al
0x0046d997:	je 5
0x0046d999:	call 0x004aff3a
0x004aff3a:	jmp 0x004afbbb
0x004afbbb:	cmpl 0x4f09d8, $0x0<UINT8>
0x004afbc2:	je 0x004afbc7
0x004afbc7:	pushl %esi
0x004afbc8:	pushl %edi
0x004afbc9:	call 0x004ba247
0x004ba247:	movl %edi, %edi
0x004ba249:	pushl %esi
0x004ba24a:	pushl %edi
0x004ba24b:	call GetEnvironmentStringsW@KERNEL32.DLL
GetEnvironmentStringsW@KERNEL32.DLL: API Node	
0x004ba251:	movl %esi, %eax
0x004ba253:	testl %esi, %esi
0x004ba255:	jne 0x004ba25b
0x004ba25b:	pushl %ebx
0x004ba25c:	pushl %esi
0x004ba25d:	call 0x004ba18d
0x004ba18d:	movl %edi, %edi
0x004ba18f:	pushl %ebp
0x004ba190:	movl %ebp, %esp
0x004ba192:	movl %edx, 0x8(%ebp)
0x004ba195:	pushl %edi
0x004ba196:	xorl %edi, %edi
0x004ba198:	cmpw (%edx), %di
0x004ba19b:	je 33
0x004ba19d:	pushl %esi
0x004ba19e:	movl %ecx, %edx
0x004ba1a0:	leal %esi, 0x2(%ecx)
0x004ba1a3:	movw %ax, (%ecx)
0x004ba1a6:	addl %ecx, $0x2<UINT8>
0x004ba1a9:	cmpw %ax, %di
0x004ba1ac:	jne 0x004ba1a3
0x004ba1ae:	subl %ecx, %esi
0x004ba1b0:	sarl %ecx
0x004ba1b2:	leal %edx, (%edx,%ecx,2)
0x004ba1b5:	addl %edx, $0x2<UINT8>
0x004ba1b8:	cmpw (%edx), %di
0x004ba1bb:	jne 0x004ba19e
0x004ba1bd:	popl %esi
0x004ba1be:	leal %eax, 0x2(%edx)
0x004ba1c1:	popl %edi
0x004ba1c2:	popl %ebp
0x004ba1c3:	ret

0x004ba262:	subl %eax, %esi
0x004ba264:	sarl %eax
0x004ba266:	leal %ebx, (%eax,%eax)
0x004ba269:	pushl %ebx
0x004ba26a:	call 0x004b36d4
0x004ba26f:	movl %edi, %eax
0x004ba271:	popl %ecx
0x004ba272:	popl %ecx
0x004ba273:	testl %edi, %edi
0x004ba275:	je 11
0x004ba277:	pushl %ebx
0x004ba278:	pushl %esi
0x004ba279:	pushl %edi
0x004ba27a:	call 0x0049c070
0x004ba27f:	addl %esp, $0xc<UINT8>
0x004ba282:	pushl $0x0<UINT8>
0x004ba284:	call 0x004b2ce4
0x004ba289:	popl %ecx
0x004ba28a:	pushl %esi
0x004ba28b:	call FreeEnvironmentStringsW@KERNEL32.DLL
FreeEnvironmentStringsW@KERNEL32.DLL: API Node	
0x004ba291:	popl %ebx
0x004ba292:	movl %eax, %edi
0x004ba294:	popl %edi
0x004ba295:	popl %esi
0x004ba296:	ret

0x004afbce:	movl %esi, %eax
0x004afbd0:	testl %esi, %esi
0x004afbd2:	jne 0x004afbd9
0x004afbd9:	pushl %esi
0x004afbda:	call 0x004afce0
0x004afce0:	movl %edi, %edi
0x004afce2:	pushl %ebp
0x004afce3:	movl %ebp, %esp
0x004afce5:	pushl %ecx
0x004afce6:	pushl %ecx
0x004afce7:	pushl %ebx
0x004afce8:	movl %ebx, 0x8(%ebp)
0x004afceb:	xorl %eax, %eax
0x004afced:	movl -8(%ebp), %eax
0x004afcf0:	movl %edx, %eax
0x004afcf2:	pushl %esi
0x004afcf3:	pushl %edi
0x004afcf4:	movzwl %eax, (%ebx)
0x004afcf7:	movl %esi, %ebx
0x004afcf9:	testw %ax, %ax
0x004afcfc:	je 0x004afd2d
0x004afcfe:	pushl $0x3d<UINT8>
0x004afd00:	popl %ebx
0x004afd01:	cmpw %ax, %bx
0x004afd04:	je 0x004afd07
0x004afd07:	movl %ecx, %esi
0x004afd09:	leal %edi, 0x2(%ecx)
0x004afd0c:	movw %ax, (%ecx)
0x004afd0f:	addl %ecx, $0x2<UINT8>
0x004afd12:	cmpw %ax, -8(%ebp)
0x004afd16:	jne 0x004afd0c
0x004afd18:	subl %ecx, %edi
0x004afd1a:	sarl %ecx
0x004afd1c:	leal %esi, (%esi,%ecx,2)
0x004afd1f:	addl %esi, $0x2<UINT8>
0x004afd22:	movzwl %eax, (%esi)
0x004afd25:	testw %ax, %ax
0x004afd28:	jne -41
0x004afd2a:	movl %ebx, 0x8(%ebp)
0x004afd2d:	leal %eax, 0x1(%edx)
0x004afd30:	pushl $0x4<UINT8>
0x004afd32:	pushl %eax
0x004afd33:	call 0x004b3a07
0x004afd38:	movl %edi, %eax
0x004afd3a:	xorl %esi, %esi
0x004afd3c:	popl %ecx
0x004afd3d:	popl %ecx
0x004afd3e:	testl %edi, %edi
0x004afd40:	je 121
0x004afd42:	movl -4(%ebp), %edi
0x004afd45:	jmp 0x004afda4
0x004afda4:	cmpw (%ebx), %si
0x004afda7:	jne 0x004afd47
0x004afd47:	movl %ecx, %ebx
0x004afd49:	leal %edx, 0x2(%ecx)
0x004afd4c:	movw %ax, (%ecx)
0x004afd4f:	addl %ecx, $0x2<UINT8>
0x004afd52:	cmpw %ax, %si
0x004afd55:	jne 0x004afd4c
0x004afd57:	subl %ecx, %edx
0x004afd59:	sarl %ecx
0x004afd5b:	pushl $0x3d<UINT8>
0x004afd5d:	leal %eax, 0x1(%ecx)
0x004afd60:	popl %ecx
0x004afd61:	movl -8(%ebp), %eax
0x004afd64:	cmpw (%ebx), %cx
0x004afd67:	je 0x004afda1
0x004afda1:	leal %ebx, (%ebx,%eax,2)
0x004afda9:	jmp 0x004afdbd
0x004afdbd:	pushl %esi
0x004afdbe:	call 0x004b2ce4
0x004afdc3:	popl %ecx
0x004afdc4:	movl %eax, %edi
0x004afdc6:	popl %edi
0x004afdc7:	popl %esi
0x004afdc8:	popl %ebx
0x004afdc9:	movl %esp, %ebp
0x004afdcb:	popl %ebp
0x004afdcc:	ret

0x004afbdf:	popl %ecx
0x004afbe0:	testl %eax, %eax
0x004afbe2:	jne 0x004afbe9
0x004afbe9:	pushl %eax
0x004afbea:	movl %ecx, $0x4f09d8<UINT32>
0x004afbef:	movl 0x4f09dc, %eax
0x004afbf4:	call 0x0049f40e
0x004afbf9:	xorl %edi, %edi
0x004afbfb:	pushl $0x0<UINT8>
0x004afbfd:	call 0x004b2ce4
0x004afc02:	popl %ecx
0x004afc03:	pushl %esi
0x004afc04:	call 0x004b2ce4
0x004b2cef:	pushl 0x8(%ebp)
0x004b2cf2:	pushl $0x0<UINT8>
0x004b2cf4:	pushl 0x4f0e20
0x004b2cfa:	call HeapFree@KERNEL32.DLL
HeapFree@KERNEL32.DLL: API Node	
0x004b2d00:	testl %eax, %eax
0x004b2d02:	jne 0x004b2d1c
0x004afc09:	popl %ecx
0x004afc0a:	movl %eax, %edi
0x004afc0c:	popl %edi
0x004afc0d:	popl %esi
0x004afc0e:	ret

0x0046d99e:	call 0x0040fe30
0x0046d9a3:	call 0x0046e093
0x0046e093:	jmp 0x0040fe30
0x0046d9a8:	testl %eax, %eax
0x0046d9aa:	jne 1
0x0046d9ac:	ret

0x004b05a4:	testl %eax, %eax
0x004b05a6:	jne 10
0x0046d9b5:	call 0x0046e256
0x0046e256:	call 0x004175e0
0x004175e0:	movl %eax, $0x4f1210<UINT32>
0x004175e5:	ret

0x0046e25b:	movl %ecx, 0x4(%eax)
0x0046e25e:	orl (%eax), $0x4<UINT8>
0x0046e261:	movl 0x4(%eax), %ecx
0x0046e264:	call 0x00420f90
0x00420f90:	movl %eax, $0x4f1218<UINT32>
0x00420f95:	ret

0x0046e269:	movl %ecx, 0x4(%eax)
0x0046e26c:	orl (%eax), $0x2<UINT8>
0x0046e26f:	movl 0x4(%eax), %ecx
0x0046e272:	ret

0x0046d9ba:	xorl %eax, %eax
0x0046d9bc:	ret

0x0045abf0:	pushl %esi
0x0045abf1:	pushl $0x4cb510<UINT32>
0x0045abf6:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x0045abfc:	movl %esi, %eax
0x0045abfe:	pushl $0x4cb52c<UINT32>
0x0045ac03:	pushl %esi
0x0045ac04:	call GetProcAddress@KERNEL32.DLL
0x0045ac0a:	xorl %eax, 0x4ed06c
0x0045ac10:	pushl $0x4cb538<UINT32>
0x0045ac15:	pushl %esi
0x0045ac16:	movl 0x4effb8, %eax
0x0045ac1b:	call GetProcAddress@KERNEL32.DLL
0x0045ac21:	xorl %eax, 0x4ed06c
0x0045ac27:	pushl $0x4cb540<UINT32>
0x0045ac2c:	pushl %esi
0x0045ac2d:	movl 0x4effbc, %eax
0x0045ac32:	call GetProcAddress@KERNEL32.DLL
0x0045ac38:	xorl %eax, 0x4ed06c
0x0045ac3e:	pushl $0x4cb54c<UINT32>
0x0045ac43:	pushl %esi
0x0045ac44:	movl 0x4effc0, %eax
0x0045ac49:	call GetProcAddress@KERNEL32.DLL
0x0045ac4f:	xorl %eax, 0x4ed06c
0x0045ac55:	pushl $0x4cb558<UINT32>
0x0045ac5a:	pushl %esi
0x0045ac5b:	movl 0x4effc4, %eax
0x0045ac60:	call GetProcAddress@KERNEL32.DLL
0x0045ac66:	xorl %eax, 0x4ed06c
0x0045ac6c:	pushl $0x4cb574<UINT32>
0x0045ac71:	pushl %esi
0x0045ac72:	movl 0x4effc8, %eax
0x0045ac77:	call GetProcAddress@KERNEL32.DLL
0x0045ac7d:	xorl %eax, 0x4ed06c
0x0045ac83:	pushl $0x4cb588<UINT32>
0x0045ac88:	pushl %esi
0x0045ac89:	movl 0x4effcc, %eax
0x0045ac8e:	call GetProcAddress@KERNEL32.DLL
0x0045ac94:	xorl %eax, 0x4ed06c
0x0045ac9a:	pushl $0x4cb598<UINT32>
0x0045ac9f:	pushl %esi
0x0045aca0:	movl 0x4effd0, %eax
0x0045aca5:	call GetProcAddress@KERNEL32.DLL
0x0045acab:	xorl %eax, 0x4ed06c
0x0045acb1:	pushl $0x4cb5ac<UINT32>
0x0045acb6:	pushl %esi
0x0045acb7:	movl 0x4effd4, %eax
0x0045acbc:	call GetProcAddress@KERNEL32.DLL
0x0045acc2:	xorl %eax, 0x4ed06c
0x0045acc8:	pushl $0x4cb5c0<UINT32>
0x0045accd:	pushl %esi
0x0045acce:	movl 0x4effd8, %eax
0x0045acd3:	call GetProcAddress@KERNEL32.DLL
0x0045acd9:	xorl %eax, 0x4ed06c
0x0045acdf:	pushl $0x4cb5d8<UINT32>
0x0045ace4:	pushl %esi
0x0045ace5:	movl 0x4effdc, %eax
0x0045acea:	call GetProcAddress@KERNEL32.DLL
0x0045acf0:	xorl %eax, 0x4ed06c
0x0045acf6:	pushl $0x4cb5ec<UINT32>
0x0045acfb:	pushl %esi
0x0045acfc:	movl 0x4effe0, %eax
0x0045ad01:	call GetProcAddress@KERNEL32.DLL
0x0045ad07:	xorl %eax, 0x4ed06c
0x0045ad0d:	pushl $0x4cb60c<UINT32>
0x0045ad12:	pushl %esi
0x0045ad13:	movl 0x4effe4, %eax
0x0045ad18:	call GetProcAddress@KERNEL32.DLL
0x0045ad1e:	xorl %eax, 0x4ed06c
0x0045ad24:	pushl $0x4cb624<UINT32>
0x0045ad29:	pushl %esi
0x0045ad2a:	movl 0x4effe8, %eax
0x0045ad2f:	call GetProcAddress@KERNEL32.DLL
0x0045ad35:	xorl %eax, 0x4ed06c
0x0045ad3b:	pushl $0x4cb63c<UINT32>
0x0045ad40:	pushl %esi
0x0045ad41:	movl 0x4effec, %eax
0x0045ad46:	call GetProcAddress@KERNEL32.DLL
0x0045ad4c:	xorl %eax, 0x4ed06c
0x0045ad52:	pushl $0x4cb650<UINT32>
0x0045ad57:	movl 0x4efff0, %eax
0x0045ad5c:	pushl %esi
0x0045ad5d:	call GetProcAddress@KERNEL32.DLL
0x0045ad63:	xorl %eax, 0x4ed06c
0x0045ad69:	pushl $0x4cb664<UINT32>
0x0045ad6e:	pushl %esi
0x0045ad6f:	movl 0x4efff4, %eax
0x0045ad74:	call GetProcAddress@KERNEL32.DLL
0x0045ad7a:	xorl %eax, 0x4ed06c
0x0045ad80:	pushl $0x4cb680<UINT32>
0x0045ad85:	pushl %esi
0x0045ad86:	movl 0x4efff8, %eax
0x0045ad8b:	call GetProcAddress@KERNEL32.DLL
0x0045ad91:	xorl %eax, 0x4ed06c
0x0045ad97:	pushl $0x4cb6a0<UINT32>
0x0045ad9c:	pushl %esi
0x0045ad9d:	movl 0x4efffc, %eax
0x0045ada2:	call GetProcAddress@KERNEL32.DLL
0x0045ada8:	xorl %eax, 0x4ed06c
0x0045adae:	pushl $0x4cb6bc<UINT32>
0x0045adb3:	pushl %esi
0x0045adb4:	movl 0x4f0000, %eax
0x0045adb9:	call GetProcAddress@KERNEL32.DLL
0x0045adbf:	xorl %eax, 0x4ed06c
0x0045adc5:	pushl $0x4cb6d0<UINT32>
0x0045adca:	pushl %esi
0x0045adcb:	movl 0x4f0004, %eax
0x0045add0:	call GetProcAddress@KERNEL32.DLL
0x0045add6:	xorl %eax, 0x4ed06c
0x0045addc:	pushl $0x4cb6e4<UINT32>
0x0045ade1:	pushl %esi
0x0045ade2:	movl 0x4f0008, %eax
0x0045ade7:	call GetProcAddress@KERNEL32.DLL
0x0045aded:	xorl %eax, 0x4ed06c
0x0045adf3:	pushl $0x4cb6f4<UINT32>
0x0045adf8:	pushl %esi
0x0045adf9:	movl 0x4f000c, %eax
0x0045adfe:	call GetProcAddress@KERNEL32.DLL
0x0045ae04:	xorl %eax, 0x4ed06c
0x0045ae0a:	pushl $0x4cb714<UINT32>
0x0045ae0f:	pushl %esi
0x0045ae10:	movl 0x4f0010, %eax
0x0045ae15:	call GetProcAddress@KERNEL32.DLL
0x0045ae1b:	xorl %eax, 0x4ed06c
0x0045ae21:	pushl $0x4cb730<UINT32>
0x0045ae26:	pushl %esi
0x0045ae27:	movl 0x4f0014, %eax
0x0045ae2c:	call GetProcAddress@KERNEL32.DLL
0x0045ae32:	xorl %eax, 0x4ed06c
0x0045ae38:	pushl $0x4cb750<UINT32>
0x0045ae3d:	pushl %esi
0x0045ae3e:	movl 0x4f0018, %eax
0x0045ae43:	call GetProcAddress@KERNEL32.DLL
0x0045ae49:	xorl %eax, 0x4ed06c
0x0045ae4f:	pushl $0x4cb76c<UINT32>
0x0045ae54:	pushl %esi
0x0045ae55:	movl 0x4f001c, %eax
0x0045ae5a:	call GetProcAddress@KERNEL32.DLL
0x0045ae60:	xorl %eax, 0x4ed06c
0x0045ae66:	pushl $0x4cb784<UINT32>
0x0045ae6b:	pushl %esi
0x0045ae6c:	movl 0x4f0020, %eax
0x0045ae71:	call GetProcAddress@KERNEL32.DLL
0x0045ae77:	xorl %eax, 0x4ed06c
0x0045ae7d:	pushl $0x4cb7a0<UINT32>
0x0045ae82:	pushl %esi
0x0045ae83:	movl 0x4f0024, %eax
0x0045ae88:	call GetProcAddress@KERNEL32.DLL
0x0045ae8e:	xorl %eax, 0x4ed06c
0x0045ae94:	pushl $0x4cb7bc<UINT32>
0x0045ae99:	pushl %esi
0x0045ae9a:	movl 0x4f0028, %eax
0x0045ae9f:	call GetProcAddress@KERNEL32.DLL
0x0045aea5:	xorl %eax, 0x4ed06c
0x0045aeab:	pushl $0x4cb7d0<UINT32>
0x0045aeb0:	pushl %esi
0x0045aeb1:	movl 0x4f002c, %eax
0x0045aeb6:	call GetProcAddress@KERNEL32.DLL
0x0045aebc:	xorl %eax, 0x4ed06c
0x0045aec2:	pushl $0x4cb7e8<UINT32>
0x0045aec7:	pushl %esi
0x0045aec8:	movl 0x4f0030, %eax
0x0045aecd:	call GetProcAddress@KERNEL32.DLL
0x0045aed3:	xorl %eax, 0x4ed06c
0x0045aed9:	pushl $0x4cb804<UINT32>
0x0045aede:	pushl %esi
0x0045aedf:	movl 0x4f0034, %eax
0x0045aee4:	call GetProcAddress@KERNEL32.DLL
0x0045aeea:	xorl %eax, 0x4ed06c
0x0045aef0:	pushl $0x4cb81c<UINT32>
0x0045aef5:	pushl %esi
0x0045aef6:	movl 0x4f0038, %eax
0x0045aefb:	call GetProcAddress@KERNEL32.DLL
0x0045af01:	xorl %eax, 0x4ed06c
0x0045af07:	pushl $0x4cb838<UINT32>
0x0045af0c:	pushl %esi
0x0045af0d:	movl 0x4f003c, %eax
0x0045af12:	call GetProcAddress@KERNEL32.DLL
0x0045af18:	xorl %eax, 0x4ed06c
0x0045af1e:	pushl $0x4cb850<UINT32>
0x0045af23:	pushl %esi
0x0045af24:	movl 0x4f0040, %eax
0x0045af29:	call GetProcAddress@KERNEL32.DLL
0x0045af2f:	xorl %eax, 0x4ed06c
0x0045af35:	pushl $0x4cb868<UINT32>
0x0045af3a:	pushl %esi
0x0045af3b:	movl 0x4f0044, %eax
0x0045af40:	call GetProcAddress@KERNEL32.DLL
0x0045af46:	xorl %eax, 0x4ed06c
0x0045af4c:	pushl $0x4cb87c<UINT32>
0x0045af51:	pushl %esi
0x0045af52:	movl 0x4f0048, %eax
0x0045af57:	call GetProcAddress@KERNEL32.DLL
0x0045af5d:	xorl %eax, 0x4ed06c
0x0045af63:	pushl $0x4cb88c<UINT32>
0x0045af68:	pushl %esi
0x0045af69:	movl 0x4f004c, %eax
0x0045af6e:	call GetProcAddress@KERNEL32.DLL
0x0045af74:	xorl %eax, 0x4ed06c
0x0045af7a:	pushl $0x4cb89c<UINT32>
0x0045af7f:	pushl %esi
0x0045af80:	movl 0x4f0050, %eax
0x0045af85:	call GetProcAddress@KERNEL32.DLL
0x0045af8b:	xorl %eax, 0x4ed06c
0x0045af91:	movl 0x4f0054, %eax
0x0045af96:	xorl %eax, %eax
0x0045af98:	popl %esi
0x0045af99:	ret

0x0046d472:	call 0x0046d499
0x0046d499:	pushl %ebp
0x0046d49a:	movl %ebp, %esp
0x0046d49c:	pushl $0xffffffff<UINT8>
0x0046d49e:	pushl $0x4c4cf0<UINT32>
0x0046d4a3:	movl %eax, %fs:0
0x0046d4a9:	pushl %eax
0x0046d4aa:	pushl %ebx
0x0046d4ab:	pushl %esi
0x0046d4ac:	pushl %edi
0x0046d4ad:	movl %eax, 0x4ed06c
0x0046d4b2:	xorl %eax, %ebp
0x0046d4b4:	pushl %eax
0x0046d4b5:	leal %eax, -12(%ebp)
0x0046d4b8:	movl %fs:0, %eax
0x0046d4be:	pushl $0xfa0<UINT32>
0x0046d4c3:	pushl $0x4f016c<UINT32>
0x0046d4c8:	call InitializeCriticalSectionAndSpinCount@KERNEL32.DLL
0x0046d4ce:	pushl $0x4ce490<UINT32>
0x0046d4d3:	call GetModuleHandleW@KERNEL32.DLL
0x0046d4d9:	movl %esi, %eax
0x0046d4db:	testl %esi, %esi
0x0046d4dd:	jne 0x0046d4f4
0x0046d4f4:	pushl $0x4cb750<UINT32>
0x0046d4f9:	pushl %esi
0x0046d4fa:	call GetProcAddress@KERNEL32.DLL
0x0046d500:	pushl $0x4cb7a0<UINT32>
0x0046d505:	pushl %esi
0x0046d506:	movl %ebx, %eax
0x0046d508:	call GetProcAddress@KERNEL32.DLL
0x0046d50e:	pushl $0x4cb784<UINT32>
0x0046d513:	pushl %esi
0x0046d514:	movl %edi, %eax
0x0046d516:	call GetProcAddress@KERNEL32.DLL
0x0046d51c:	movl %esi, %eax
0x0046d51e:	testl %ebx, %ebx
0x0046d520:	je 56
0x0046d522:	testl %edi, %edi
0x0046d524:	je 52
0x0046d526:	testl %esi, %esi
0x0046d528:	je 48
0x0046d52a:	andl 0x4f0188, $0x0<UINT8>
0x0046d531:	movl %ecx, %ebx
0x0046d533:	pushl $0x4f0184<UINT32>
0x0046d538:	call 0x00403560
0x0046d53e:	call InitializeConditionVariable@api-ms-win-core-synch-l1-2-0.dll
InitializeConditionVariable@api-ms-win-core-synch-l1-2-0.dll: API Node	
0x0046d540:	pushl %edi
0x0046d541:	call 0x0046d188
0x0046d546:	pushl %esi
0x0046d547:	movl 0x4f018c, %eax
0x0046d54c:	call 0x0046d188
0x0046d551:	popl %ecx
0x0046d552:	popl %ecx
0x0046d553:	movl 0x4f0190, %eax
0x0046d558:	jmp 0x0046d570
0x0046d570:	movl %ecx, -12(%ebp)
0x0046d573:	movl %fs:0, %ecx
0x0046d57a:	popl %ecx
0x0046d57b:	popl %edi
0x0046d57c:	popl %esi
0x0046d57d:	popl %ebx
0x0046d57e:	leave
0x0046d57f:	ret

0x0046d477:	pushl $0x0<UINT8>
0x0046d479:	call 0x0046d254
0x0046d263:	movb %al, $0x1<UINT8>
0x0046d265:	leave
0x0046d266:	ret

0x0046d47e:	popl %ecx
0x0046d47f:	testb %al, %al
0x0046d481:	je 14
0x0046d483:	pushl $0x46d588<UINT32>
0x0046d488:	call 0x0046d40d
0x0046d48d:	popl %ecx
0x0046d48e:	xorl %eax, %eax
0x0046d490:	ret

0xe8006a00:	addb (%eax), %al
0x0049ddc0:	pushl %ebp
0x0049ddc1:	movl %ebp, %esp
0x0049ddc3:	subl %esp, $0x1c<UINT8>
0x0049ddc6:	pushl %ebx
0x0049ddc7:	movl %ebx, 0xc(%ebp)
0x0049ddca:	pushl %esi
0x0049ddcb:	pushl %edi
0x0049ddcc:	movb -1(%ebp), $0x0<UINT8>
0x0049ddd0:	movl %eax, 0x8(%ebx)
0x0049ddd3:	leal %esi, 0x10(%ebx)
0x0049ddd6:	xorl %eax, 0x4ed06c
0x0049dddc:	pushl %esi
0x0049dddd:	pushl %eax
0x0049ddde:	movl -12(%ebp), $0x1<UINT32>
0x0049dde5:	movl -16(%ebp), %esi
0x0049dde8:	movl -8(%ebp), %eax
0x0049ddeb:	call 0x0049dd80
0x0049dd80:	pushl %ebp
0x0049dd81:	movl %ebp, %esp
0x0049dd83:	pushl %esi
0x0049dd84:	movl %esi, 0x8(%ebp)
0x0049dd87:	pushl %edi
0x0049dd88:	movl %edi, 0xc(%ebp)
0x0049dd8b:	movl %eax, (%esi)
0x0049dd8d:	cmpl %eax, $0xfffffffe<UINT8>
0x0049dd90:	je 0x0049dd9f
0x0049dd9f:	movl %eax, 0x8(%esi)
0x0049dda2:	movl %ecx, 0xc(%esi)
0x0049dda5:	addl %ecx, %edi
0x0049dda7:	xorl %ecx, (%eax,%edi)
0x0049ddaa:	popl %edi
0x0049ddab:	popl %esi
0x0049ddac:	popl %ebp
0x0049ddad:	jmp 0x0046d108
0x0049ddf0:	pushl 0x10(%ebp)
0x0049ddf3:	call 0x0049ed7c
0x0049ed7c:	pushl %ebp
0x0049ed7d:	movl %ebp, %esp
0x0049ed7f:	movl %eax, 0x4ca56c
0x0049ed84:	cmpl %eax, $0x403560<UINT32>
0x0049ed89:	je 0x0049edaa
0x0049edaa:	popl %ebp
0x0049edab:	ret

0x0049ddf8:	movl %eax, 0x8(%ebp)
0x0049ddfb:	addl %esp, $0xc<UINT8>
0x0049ddfe:	movl %edi, 0xc(%ebx)
0x0049de01:	testb 0x4(%eax), $0x66<UINT8>
0x0049de05:	jne 95
0x0049de07:	movl -28(%ebp), %eax
0x0049de0a:	movl %eax, 0x10(%ebp)
0x0049de0d:	movl -24(%ebp), %eax
0x0049de10:	leal %eax, -28(%ebp)
0x0049de13:	movl -4(%ebx), %eax
0x0049de16:	cmpl %edi, $0xfffffffe<UINT8>
0x0049de19:	je 110
0x0049de1b:	jmp 0x0049de20
0x0049de20:	movl %ecx, -8(%ebp)
0x0049de23:	leal %eax, 0x2(%edi)
0x0049de26:	leal %eax, (%edi,%eax,2)
0x0049de29:	movl %ebx, (%ecx,%eax,4)
0x0049de2c:	leal %eax, (%ecx,%eax,4)
0x0049de2f:	movl %ecx, 0x4(%eax)
0x0049de32:	movl -20(%ebp), %eax
0x0049de35:	testl %ecx, %ecx
0x0049de37:	je 20
0x0049de39:	movl %edx, %esi
0x0049de3b:	call 0x0049f220
0x0049f220:	pushl %ebp
0x0049f221:	pushl %esi
0x0049f222:	pushl %edi
0x0049f223:	pushl %ebx
0x0049f224:	movl %ebp, %edx
0x0049f226:	xorl %eax, %eax
0x0049f228:	xorl %ebx, %ebx
0x0049f22a:	xorl %edx, %edx
0x0049f22c:	xorl %esi, %esi
0x0049f22e:	xorl %edi, %edi
0x0049f230:	call 0x0046daf0
0x0046daf0:	movl %ecx, -20(%ebp)
0x0046daf3:	movl %eax, (%ecx)
0x0046daf5:	movl %eax, (%eax)
0x0046daf7:	movl -32(%ebp), %eax
0x0046dafa:	pushl %ecx
0x0046dafb:	pushl %eax
0x0046dafc:	call 0x004af3f0
0x004af3f0:	movl %edi, %edi
0x004af3f2:	pushl %ebp
0x004af3f3:	movl %ebp, %esp
0x004af3f5:	pushl %ecx
0x004af3f6:	pushl %ecx
0x004af3f7:	movl %eax, 0x4ed06c
0x004af3fc:	xorl %eax, %ebp
0x004af3fe:	movl -4(%ebp), %eax
0x004af401:	pushl %esi
0x004af402:	call 0x004b1e5e
0x004af407:	movl %esi, %eax
0x004af409:	testl %esi, %esi
0x004af40b:	je 323
0x004af411:	movl %edx, (%esi)
0x004af413:	movl %ecx, %edx
0x004af415:	pushl %ebx
0x004af416:	xorl %ebx, %ebx
0x004af418:	pushl %edi
0x004af419:	leal %eax, 0x90(%edx)
0x004af41f:	cmpl %edx, %eax
0x004af421:	je 14
0x004af423:	movl %edi, 0x8(%ebp)
0x004af426:	cmpl (%ecx), %edi
0x004af428:	je 9
0x004af42a:	addl %ecx, $0xc<UINT8>
0x004af42d:	cmpl %ecx, %eax
0x004af42f:	jne 0x004af426
0x004af431:	movl %ecx, %ebx
0x004af433:	testl %ecx, %ecx
0x004af435:	je 0x004af43e
0x004af43e:	xorl %eax, %eax
0x004af440:	jmp 0x004af552
0x004af552:	popl %edi
0x004af553:	popl %ebx
0x004af554:	movl %ecx, -4(%ebp)
0x004af557:	xorl %ecx, %ebp
0x004af559:	popl %esi
0x004af55a:	call 0x0046d108
0x004af55f:	movl %esp, %ebp
0x004af561:	popl %ebp
0x004af562:	ret

0x0046db01:	popl %ecx
0x0046db02:	popl %ecx
0x0046db03:	ret

0x0049f232:	popl %ebx
0x0049f233:	popl %edi
0x0049f234:	popl %esi
0x0049f235:	popl %ebp
0x0049f236:	ret

0x0049de40:	movb %cl, $0x1<UINT8>
0x0049de42:	movb -1(%ebp), %cl
0x0049de45:	testl %eax, %eax
0x0049de47:	js 20
0x0049de49:	jg 72
0x0049de4b:	jmp 0x0049de50
0x0049de50:	movl %edi, %ebx
0x0049de52:	cmpl %ebx, $0xfffffffe<UINT8>
0x0049de55:	jne -55
0x0049de57:	testb %cl, %cl
0x0049de59:	je 46
0x0049de5b:	jmp 0x0049de7d
0x0049de7d:	pushl %esi
0x0049de7e:	pushl -8(%ebp)
0x0049de81:	call 0x0049dd80
0x0049de86:	addl %esp, $0x8<UINT8>
0x0049de89:	movl %eax, -12(%ebp)
0x0049de8c:	popl %edi
0x0049de8d:	popl %esi
0x0049de8e:	popl %ebx
0x0049de8f:	movl %esp, %ebp
0x0049de91:	popl %ebp
0x0049de92:	ret

0xe8006a02:	addb (%eax), %al
0xe8006a04:	addb (%eax), %al
0xe8006a06:	addb (%eax), %al
0xe8006a08:	addb (%eax), %al
0xe8006a0a:	addb (%eax), %al
0xe8006a0c:	addb (%eax), %al
0xe8006a0e:	addb (%eax), %al
0xe8006a10:	addb (%eax), %al
0xe8006a12:	addb (%eax), %al
0xe8006a14:	addb (%eax), %al
0xe8006a16:	addb (%eax), %al
0xe8006a18:	addb (%eax), %al
0xe8006a1a:	addb (%eax), %al
0xe8006a1c:	addb (%eax), %al
0xe8006a1e:	addb (%eax), %al
0xe8006a20:	addb (%eax), %al
0xe8006a22:	addb (%eax), %al
0xe8006a24:	addb (%eax), %al
0xe8006a26:	addb (%eax), %al
0xe8006a28:	addb (%eax), %al
0xe8006a2a:	addb (%eax), %al
0xe8006a2c:	addb (%eax), %al
0xe8006a2e:	addb (%eax), %al
0xe8006a30:	addb (%eax), %al
0xe8006a32:	addb (%eax), %al
0xe8006a34:	addb (%eax), %al
0xe8006a36:	addb (%eax), %al
0xe8006a38:	addb (%eax), %al
0xe8006a3a:	addb (%eax), %al
0xe8006a3c:	addb (%eax), %al
0xe8006a3e:	addb (%eax), %al
0xe8006a40:	addb (%eax), %al
0xe8006a42:	addb (%eax), %al
0xe8006a44:	addb (%eax), %al
0xe8006a46:	addb (%eax), %al
0xe8006a48:	addb (%eax), %al
0xe8006a4a:	addb (%eax), %al
0xe8006a4c:	addb (%eax), %al
0xe8006a4e:	addb (%eax), %al
0xe8006a50:	addb (%eax), %al
0xe8006a52:	addb (%eax), %al
0xe8006a54:	addb (%eax), %al
0xe8006a56:	addb (%eax), %al
0xe8006a58:	addb (%eax), %al
0xe8006a5a:	addb (%eax), %al
0xe8006a5c:	addb (%eax), %al
0xe8006a5e:	addb (%eax), %al
0xe8006a60:	addb (%eax), %al
0xe8006a62:	addb (%eax), %al
0xe8006a64:	addb (%eax), %al
0x004b52d8:	je 0x004b5312
0x004b5312:	leal %edx, (%esi,%esi)
0x004b5315:	leal %ecx, 0x8(%edx)
0x004b5318:	cmpl %edx, %ecx
0x004b531a:	sbbl %eax, %eax
0x004b531c:	testl %ecx, %eax
0x004b531e:	je 0x004b536a
0x004b536a:	xorl %edi, %edi
0x004b536c:	testl %edi, %edi
0x004b536e:	je 0x004b53a8
0x004b53a8:	pushl %edi
0x004b53a9:	call 0x0046c8f3
0x004b53ae:	popl %ecx
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
