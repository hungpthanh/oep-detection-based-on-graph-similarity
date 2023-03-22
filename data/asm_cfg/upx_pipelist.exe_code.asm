0x00436200:	pusha
0x00436201:	movl %esi, $0x423000<UINT32>
0x00436206:	leal %edi, -139264(%esi)
0x0043620c:	pushl %edi
0x0043620d:	jmp 0x0043621a
0x0043621a:	movl %ebx, (%esi)
0x0043621c:	subl %esi, $0xfffffffc<UINT8>
0x0043621f:	adcl %ebx, %ebx
0x00436221:	jb 0x00436210
0x00436210:	movb %al, (%esi)
0x00436212:	incl %esi
0x00436213:	movb (%edi), %al
0x00436215:	incl %edi
0x00436216:	addl %ebx, %ebx
0x00436218:	jne 0x00436221
0x00436223:	movl %eax, $0x1<UINT32>
0x00436228:	addl %ebx, %ebx
0x0043622a:	jne 0x00436233
0x00436233:	adcl %eax, %eax
0x00436235:	addl %ebx, %ebx
0x00436237:	jae 0x00436228
0x00436239:	jne 0x00436244
0x00436244:	xorl %ecx, %ecx
0x00436246:	subl %eax, $0x3<UINT8>
0x00436249:	jb 0x00436258
0x0043624b:	shll %eax, $0x8<UINT8>
0x0043624e:	movb %al, (%esi)
0x00436250:	incl %esi
0x00436251:	xorl %eax, $0xffffffff<UINT8>
0x00436254:	je 0x004362ca
0x00436256:	movl %ebp, %eax
0x00436258:	addl %ebx, %ebx
0x0043625a:	jne 0x00436263
0x00436263:	adcl %ecx, %ecx
0x00436265:	addl %ebx, %ebx
0x00436267:	jne 0x00436270
0x00436269:	movl %ebx, (%esi)
0x0043626b:	subl %esi, $0xfffffffc<UINT8>
0x0043626e:	adcl %ebx, %ebx
0x00436270:	adcl %ecx, %ecx
0x00436272:	jne 0x00436294
0x00436294:	cmpl %ebp, $0xfffff300<UINT32>
0x0043629a:	adcl %ecx, $0x1<UINT8>
0x0043629d:	leal %edx, (%edi,%ebp)
0x004362a0:	cmpl %ebp, $0xfffffffc<UINT8>
0x004362a3:	jbe 0x004362b4
0x004362b4:	movl %eax, (%edx)
0x004362b6:	addl %edx, $0x4<UINT8>
0x004362b9:	movl (%edi), %eax
0x004362bb:	addl %edi, $0x4<UINT8>
0x004362be:	subl %ecx, $0x4<UINT8>
0x004362c1:	ja 0x004362b4
0x004362c3:	addl %edi, %ecx
0x004362c5:	jmp 0x00436216
0x00436274:	incl %ecx
0x00436275:	addl %ebx, %ebx
0x00436277:	jne 0x00436280
0x00436280:	adcl %ecx, %ecx
0x00436282:	addl %ebx, %ebx
0x00436284:	jae 0x00436275
0x00436286:	jne 0x00436291
0x00436291:	addl %ecx, $0x2<UINT8>
0x00436288:	movl %ebx, (%esi)
0x0043628a:	subl %esi, $0xfffffffc<UINT8>
0x0043628d:	adcl %ebx, %ebx
0x0043628f:	jae 0x00436275
0x004362a5:	movb %al, (%edx)
0x004362a7:	incl %edx
0x004362a8:	movb (%edi), %al
0x004362aa:	incl %edi
0x004362ab:	decl %ecx
0x004362ac:	jne 0x004362a5
0x004362ae:	jmp 0x00436216
0x0043622c:	movl %ebx, (%esi)
0x0043622e:	subl %esi, $0xfffffffc<UINT8>
0x00436231:	adcl %ebx, %ebx
0x0043625c:	movl %ebx, (%esi)
0x0043625e:	subl %esi, $0xfffffffc<UINT8>
0x00436261:	adcl %ebx, %ebx
0x0043623b:	movl %ebx, (%esi)
0x0043623d:	subl %esi, $0xfffffffc<UINT8>
0x00436240:	adcl %ebx, %ebx
0x00436242:	jae 0x00436228
0x00436279:	movl %ebx, (%esi)
0x0043627b:	subl %esi, $0xfffffffc<UINT8>
0x0043627e:	adcl %ebx, %ebx
0x004362ca:	popl %esi
0x004362cb:	movl %edi, %esi
0x004362cd:	movl %ecx, $0xb48<UINT32>
0x004362d2:	movb %al, (%edi)
0x004362d4:	incl %edi
0x004362d5:	subb %al, $0xffffffe8<UINT8>
0x004362d7:	cmpb %al, $0x1<UINT8>
0x004362d9:	ja 0x004362d2
0x004362db:	cmpb (%edi), $0xa<UINT8>
0x004362de:	jne 0x004362d2
0x004362e0:	movl %eax, (%edi)
0x004362e2:	movb %bl, 0x4(%edi)
0x004362e5:	shrw %ax, $0x8<UINT8>
0x004362e9:	roll %eax, $0x10<UINT8>
0x004362ec:	xchgb %ah, %al
0x004362ee:	subl %eax, %edi
0x004362f0:	subb %bl, $0xffffffe8<UINT8>
0x004362f3:	addl %eax, %esi
0x004362f5:	movl (%edi), %eax
0x004362f7:	addl %edi, $0x5<UINT8>
0x004362fa:	movb %al, %bl
0x004362fc:	loop 0x004362d7
0x004362fe:	leal %edi, 0x34000(%esi)
0x00436304:	movl %eax, (%edi)
0x00436306:	orl %eax, %eax
0x00436308:	je 0x00436346
0x0043630a:	movl %ebx, 0x4(%edi)
0x0043630d:	leal %eax, 0x3655c(%eax,%esi)
0x00436314:	addl %ebx, %esi
0x00436316:	pushl %eax
0x00436317:	addl %edi, $0x8<UINT8>
0x0043631a:	call LoadLibraryA@KERNEL32.DLL
LoadLibraryA@kernel32.dll: API Node	
0x00436320:	xchgl %ebp, %eax
0x00436321:	movb %al, (%edi)
0x00436323:	incl %edi
0x00436324:	orb %al, %al
0x00436326:	je 0x00436304
0x00436328:	movl %ecx, %edi
0x0043632a:	pushl %edi
0x0043632b:	decl %eax
0x0043632c:	repn scasb %al, %es:(%edi)
0x0043632e:	pushl %ebp
0x0043632f:	call GetProcAddress@KERNEL32.DLL
GetProcAddress@kernel32.dll: API Node	
0x00436335:	orl %eax, %eax
0x00436337:	je 7
0x00436339:	movl (%ebx), %eax
0x0043633b:	addl %ebx, $0x4<UINT8>
0x0043633e:	jmp 0x00436321
GetProcAddress@KERNEL32.DLL: API Node	
LoadLibraryA@KERNEL32.DLL: API Node	
0x00436346:	movl %ebp, 0x3660c(%esi)
0x0043634c:	leal %edi, -4096(%esi)
0x00436352:	movl %ebx, $0x1000<UINT32>
0x00436357:	pushl %eax
0x00436358:	pushl %esp
0x00436359:	pushl $0x4<UINT8>
0x0043635b:	pushl %ebx
0x0043635c:	pushl %edi
0x0043635d:	call VirtualProtect@kernel32.dll
VirtualProtect@kernel32.dll: API Node	
0x0043635f:	leal %eax, 0x21f(%edi)
0x00436365:	andb (%eax), $0x7f<UINT8>
0x00436368:	andb 0x28(%eax), $0x7f<UINT8>
0x0043636c:	popl %eax
0x0043636d:	pushl %eax
0x0043636e:	pushl %esp
0x0043636f:	pushl %eax
0x00436370:	pushl %ebx
0x00436371:	pushl %edi
0x00436372:	call VirtualProtect@kernel32.dll
0x00436374:	popl %eax
0x00436375:	popa
0x00436376:	leal %eax, -128(%esp)
0x0043637a:	pushl $0x0<UINT8>
0x0043637c:	cmpl %esp, %eax
0x0043637e:	jne 0x0043637a
0x00436380:	subl %esp, $0xffffff80<UINT8>
0x00436383:	jmp 0x0040550b
0x0040550b:	call 0x0040dbab
0x0040dbab:	pushl %ebp
0x0040dbac:	movl %ebp, %esp
0x0040dbae:	subl %esp, $0x14<UINT8>
0x0040dbb1:	andl -12(%ebp), $0x0<UINT8>
0x0040dbb5:	andl -8(%ebp), $0x0<UINT8>
0x0040dbb9:	movl %eax, 0x430348
0x0040dbbe:	pushl %esi
0x0040dbbf:	pushl %edi
0x0040dbc0:	movl %edi, $0xbb40e64e<UINT32>
0x0040dbc5:	movl %esi, $0xffff0000<UINT32>
0x0040dbca:	cmpl %eax, %edi
0x0040dbcc:	je 0x0040dbdb
0x0040dbdb:	leal %eax, -12(%ebp)
0x0040dbde:	pushl %eax
0x0040dbdf:	call GetSystemTimeAsFileTime@KERNEL32.DLL
GetSystemTimeAsFileTime@KERNEL32.DLL: API Node	
0x0040dbe5:	movl %eax, -8(%ebp)
0x0040dbe8:	xorl %eax, -12(%ebp)
0x0040dbeb:	movl -4(%ebp), %eax
0x0040dbee:	call GetCurrentThreadId@KERNEL32.DLL
GetCurrentThreadId@KERNEL32.DLL: API Node	
0x0040dbf4:	xorl -4(%ebp), %eax
0x0040dbf7:	call GetCurrentProcessId@KERNEL32.DLL
GetCurrentProcessId@KERNEL32.DLL: API Node	
0x0040dbfd:	xorl -4(%ebp), %eax
0x0040dc00:	leal %eax, -20(%ebp)
0x0040dc03:	pushl %eax
0x0040dc04:	call QueryPerformanceCounter@KERNEL32.DLL
QueryPerformanceCounter@KERNEL32.DLL: API Node	
0x0040dc0a:	movl %ecx, -16(%ebp)
0x0040dc0d:	leal %eax, -4(%ebp)
0x0040dc10:	xorl %ecx, -20(%ebp)
0x0040dc13:	xorl %ecx, -4(%ebp)
0x0040dc16:	xorl %ecx, %eax
0x0040dc18:	cmpl %ecx, %edi
0x0040dc1a:	jne 0x0040dc23
0x0040dc23:	testl %esi, %ecx
0x0040dc25:	jne 0x0040dc33
0x0040dc33:	movl 0x430348, %ecx
0x0040dc39:	notl %ecx
0x0040dc3b:	movl 0x43034c, %ecx
0x0040dc41:	popl %edi
0x0040dc42:	popl %esi
0x0040dc43:	movl %esp, %ebp
0x0040dc45:	popl %ebp
0x0040dc46:	ret

0x00405510:	jmp 0x0040534a
0x0040534a:	pushl $0x14<UINT8>
0x0040534c:	pushl $0x42ea80<UINT32>
0x00405351:	call 0x004062f0
0x004062f0:	pushl $0x406390<UINT32>
0x004062f5:	pushl %fs:0
0x004062fc:	movl %eax, 0x10(%esp)
0x00406300:	movl 0x10(%esp), %ebp
0x00406304:	leal %ebp, 0x10(%esp)
0x00406308:	subl %esp, %eax
0x0040630a:	pushl %ebx
0x0040630b:	pushl %esi
0x0040630c:	pushl %edi
0x0040630d:	movl %eax, 0x430348
0x00406312:	xorl -4(%ebp), %eax
0x00406315:	xorl %eax, %ebp
0x00406317:	pushl %eax
0x00406318:	movl -24(%ebp), %esp
0x0040631b:	pushl -8(%ebp)
0x0040631e:	movl %eax, -4(%ebp)
0x00406321:	movl -4(%ebp), $0xfffffffe<UINT32>
0x00406328:	movl -8(%ebp), %eax
0x0040632b:	leal %eax, -16(%ebp)
0x0040632e:	movl %fs:0, %eax
0x00406334:	ret

0x00405356:	pushl $0x1<UINT8>
0x00405358:	call 0x0040db5e
0x0040db5e:	pushl %ebp
0x0040db5f:	movl %ebp, %esp
0x0040db61:	movl %eax, 0x8(%ebp)
0x0040db64:	movl 0x431870, %eax
0x0040db69:	popl %ebp
0x0040db6a:	ret

0x0040535d:	popl %ecx
0x0040535e:	movl %eax, $0x5a4d<UINT32>
0x00405363:	cmpw 0x400000, %ax
0x0040536a:	je 0x00405370
0x00405370:	movl %eax, 0x40003c
0x00405375:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x0040537f:	jne -21
0x00405381:	movl %ecx, $0x10b<UINT32>
0x00405386:	cmpw 0x400018(%eax), %cx
0x0040538d:	jne -35
0x0040538f:	xorl %ebx, %ebx
0x00405391:	cmpl 0x400074(%eax), $0xe<UINT8>
0x00405398:	jbe 9
0x0040539a:	cmpl 0x4000e8(%eax), %ebx
0x004053a0:	setne %bl
0x004053a3:	movl -28(%ebp), %ebx
0x004053a6:	call 0x00409602
0x00409602:	call GetProcessHeap@KERNEL32.DLL
GetProcessHeap@KERNEL32.DLL: API Node	
0x00409608:	xorl %ecx, %ecx
0x0040960a:	movl 0x431ea8, %eax
0x0040960f:	testl %eax, %eax
0x00409611:	setne %cl
0x00409614:	movl %eax, %ecx
0x00409616:	ret

0x004053ab:	testl %eax, %eax
0x004053ad:	jne 0x004053b7
0x004053b7:	call 0x0040a6d0
0x0040a6d0:	call 0x00403fd6
0x00403fd6:	pushl %esi
0x00403fd7:	pushl $0x0<UINT8>
0x00403fd9:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x00403fdf:	movl %esi, %eax
0x00403fe1:	pushl %esi
0x00403fe2:	call 0x004095ef
0x004095ef:	pushl %ebp
0x004095f0:	movl %ebp, %esp
0x004095f2:	movl %eax, 0x8(%ebp)
0x004095f5:	movl 0x431ea0, %eax
0x004095fa:	popl %ebp
0x004095fb:	ret

0x00403fe7:	pushl %esi
0x00403fe8:	call 0x00406673
0x00406673:	pushl %ebp
0x00406674:	movl %ebp, %esp
0x00406676:	movl %eax, 0x8(%ebp)
0x00406679:	movl 0x43175c, %eax
0x0040667e:	popl %ebp
0x0040667f:	ret

0x00403fed:	pushl %esi
0x00403fee:	call 0x0040ca29
0x0040ca29:	pushl %ebp
0x0040ca2a:	movl %ebp, %esp
0x0040ca2c:	movl %eax, 0x8(%ebp)
0x0040ca2f:	movl 0x431ed0, %eax
0x0040ca34:	popl %ebp
0x0040ca35:	ret

0x00403ff3:	pushl %esi
0x00403ff4:	call 0x0040ca55
0x0040ca55:	pushl %ebp
0x0040ca56:	movl %ebp, %esp
0x0040ca58:	movl %eax, 0x8(%ebp)
0x0040ca5b:	movl 0x431ed4, %eax
0x0040ca60:	movl 0x431ed8, %eax
0x0040ca65:	movl 0x431edc, %eax
0x0040ca6a:	movl 0x431ee0, %eax
0x0040ca6f:	popl %ebp
0x0040ca70:	ret

0x00403ff9:	pushl %esi
0x00403ffa:	call 0x0040c83f
0x0040c83f:	pushl $0x40c7f8<UINT32>
0x0040c844:	call EncodePointer@KERNEL32.DLL
0x0040c84a:	movl 0x431ecc, %eax
0x0040c84f:	ret

0x00403fff:	pushl %esi
0x00404000:	call 0x0040cf62
0x0040cf62:	pushl %ebp
0x0040cf63:	movl %ebp, %esp
0x0040cf65:	movl %eax, 0x8(%ebp)
0x0040cf68:	movl 0x431ee8, %eax
0x0040cf6d:	popl %ebp
0x0040cf6e:	ret

0x00404005:	addl %esp, $0x18<UINT8>
0x00404008:	popl %esi
0x00404009:	jmp 0x00408fd4
0x00408fd4:	pushl %esi
0x00408fd5:	pushl %edi
0x00408fd6:	pushl $0x429d24<UINT32>
0x00408fdb:	call GetModuleHandleW@KERNEL32.DLL
GetModuleHandleW@KERNEL32.DLL: API Node	
0x00408fe1:	movl %esi, 0x423094
0x00408fe7:	movl %edi, %eax
0x00408fe9:	pushl $0x429d40<UINT32>
0x00408fee:	pushl %edi
0x00408fef:	call GetProcAddress@KERNEL32.DLL
0x00408ff1:	xorl %eax, 0x430348
0x00408ff7:	pushl $0x429d4c<UINT32>
0x00408ffc:	pushl %edi
0x00408ffd:	movl 0x432040, %eax
0x00409002:	call GetProcAddress@KERNEL32.DLL
0x00409004:	xorl %eax, 0x430348
0x0040900a:	pushl $0x429d54<UINT32>
0x0040900f:	pushl %edi
0x00409010:	movl 0x432044, %eax
0x00409015:	call GetProcAddress@KERNEL32.DLL
0x00409017:	xorl %eax, 0x430348
0x0040901d:	pushl $0x429d60<UINT32>
0x00409022:	pushl %edi
0x00409023:	movl 0x432048, %eax
0x00409028:	call GetProcAddress@KERNEL32.DLL
0x0040902a:	xorl %eax, 0x430348
0x00409030:	pushl $0x429d6c<UINT32>
0x00409035:	pushl %edi
0x00409036:	movl 0x43204c, %eax
0x0040903b:	call GetProcAddress@KERNEL32.DLL
0x0040903d:	xorl %eax, 0x430348
0x00409043:	pushl $0x429d88<UINT32>
0x00409048:	pushl %edi
0x00409049:	movl 0x432050, %eax
0x0040904e:	call GetProcAddress@KERNEL32.DLL
0x00409050:	xorl %eax, 0x430348
0x00409056:	pushl $0x429d98<UINT32>
0x0040905b:	pushl %edi
0x0040905c:	movl 0x432054, %eax
0x00409061:	call GetProcAddress@KERNEL32.DLL
0x00409063:	xorl %eax, 0x430348
0x00409069:	pushl $0x429dac<UINT32>
0x0040906e:	pushl %edi
0x0040906f:	movl 0x432058, %eax
0x00409074:	call GetProcAddress@KERNEL32.DLL
0x00409076:	xorl %eax, 0x430348
0x0040907c:	pushl $0x429dc4<UINT32>
0x00409081:	pushl %edi
0x00409082:	movl 0x43205c, %eax
0x00409087:	call GetProcAddress@KERNEL32.DLL
0x00409089:	xorl %eax, 0x430348
0x0040908f:	pushl $0x429ddc<UINT32>
0x00409094:	pushl %edi
0x00409095:	movl 0x432060, %eax
0x0040909a:	call GetProcAddress@KERNEL32.DLL
0x0040909c:	xorl %eax, 0x430348
0x004090a2:	pushl $0x429df0<UINT32>
0x004090a7:	pushl %edi
0x004090a8:	movl 0x432064, %eax
0x004090ad:	call GetProcAddress@KERNEL32.DLL
0x004090af:	xorl %eax, 0x430348
0x004090b5:	pushl $0x429e10<UINT32>
0x004090ba:	pushl %edi
0x004090bb:	movl 0x432068, %eax
0x004090c0:	call GetProcAddress@KERNEL32.DLL
0x004090c2:	xorl %eax, 0x430348
0x004090c8:	pushl $0x429e28<UINT32>
0x004090cd:	pushl %edi
0x004090ce:	movl 0x43206c, %eax
0x004090d3:	call GetProcAddress@KERNEL32.DLL
0x004090d5:	xorl %eax, 0x430348
0x004090db:	pushl $0x429e40<UINT32>
0x004090e0:	pushl %edi
0x004090e1:	movl 0x432070, %eax
0x004090e6:	call GetProcAddress@KERNEL32.DLL
0x004090e8:	xorl %eax, 0x430348
0x004090ee:	pushl $0x429e54<UINT32>
0x004090f3:	pushl %edi
0x004090f4:	movl 0x432074, %eax
0x004090f9:	call GetProcAddress@KERNEL32.DLL
0x004090fb:	xorl %eax, 0x430348
0x00409101:	movl 0x432078, %eax
0x00409106:	pushl $0x429e68<UINT32>
0x0040910b:	pushl %edi
0x0040910c:	call GetProcAddress@KERNEL32.DLL
0x0040910e:	xorl %eax, 0x430348
0x00409114:	pushl $0x429e84<UINT32>
0x00409119:	pushl %edi
0x0040911a:	movl 0x43207c, %eax
0x0040911f:	call GetProcAddress@KERNEL32.DLL
0x00409121:	xorl %eax, 0x430348
0x00409127:	pushl $0x429ea4<UINT32>
0x0040912c:	pushl %edi
0x0040912d:	movl 0x432080, %eax
0x00409132:	call GetProcAddress@KERNEL32.DLL
0x00409134:	xorl %eax, 0x430348
0x0040913a:	pushl $0x429ec0<UINT32>
0x0040913f:	pushl %edi
0x00409140:	movl 0x432084, %eax
0x00409145:	call GetProcAddress@KERNEL32.DLL
0x00409147:	xorl %eax, 0x430348
0x0040914d:	pushl $0x429ee0<UINT32>
0x00409152:	pushl %edi
0x00409153:	movl 0x432088, %eax
0x00409158:	call GetProcAddress@KERNEL32.DLL
0x0040915a:	xorl %eax, 0x430348
0x00409160:	pushl $0x429ef4<UINT32>
0x00409165:	pushl %edi
0x00409166:	movl 0x43208c, %eax
0x0040916b:	call GetProcAddress@KERNEL32.DLL
0x0040916d:	xorl %eax, 0x430348
0x00409173:	pushl $0x429f10<UINT32>
0x00409178:	pushl %edi
0x00409179:	movl 0x432090, %eax
0x0040917e:	call GetProcAddress@KERNEL32.DLL
0x00409180:	xorl %eax, 0x430348
0x00409186:	pushl $0x429f24<UINT32>
0x0040918b:	pushl %edi
0x0040918c:	movl 0x432098, %eax
0x00409191:	call GetProcAddress@KERNEL32.DLL
0x00409193:	xorl %eax, 0x430348
0x00409199:	pushl $0x429f34<UINT32>
0x0040919e:	pushl %edi
0x0040919f:	movl 0x432094, %eax
0x004091a4:	call GetProcAddress@KERNEL32.DLL
0x004091a6:	xorl %eax, 0x430348
0x004091ac:	pushl $0x429f44<UINT32>
0x004091b1:	pushl %edi
0x004091b2:	movl 0x43209c, %eax
0x004091b7:	call GetProcAddress@KERNEL32.DLL
0x004091b9:	xorl %eax, 0x430348
0x004091bf:	pushl $0x429f54<UINT32>
0x004091c4:	pushl %edi
0x004091c5:	movl 0x4320a0, %eax
0x004091ca:	call GetProcAddress@KERNEL32.DLL
0x004091cc:	xorl %eax, 0x430348
0x004091d2:	pushl $0x429f64<UINT32>
0x004091d7:	pushl %edi
0x004091d8:	movl 0x4320a4, %eax
0x004091dd:	call GetProcAddress@KERNEL32.DLL
0x004091df:	xorl %eax, 0x430348
0x004091e5:	pushl $0x429f80<UINT32>
0x004091ea:	pushl %edi
0x004091eb:	movl 0x4320a8, %eax
0x004091f0:	call GetProcAddress@KERNEL32.DLL
0x004091f2:	xorl %eax, 0x430348
0x004091f8:	pushl $0x429f94<UINT32>
0x004091fd:	pushl %edi
0x004091fe:	movl 0x4320ac, %eax
0x00409203:	call GetProcAddress@KERNEL32.DLL
0x00409205:	xorl %eax, 0x430348
0x0040920b:	pushl $0x429fa4<UINT32>
0x00409210:	pushl %edi
0x00409211:	movl 0x4320b0, %eax
0x00409216:	call GetProcAddress@KERNEL32.DLL
0x00409218:	xorl %eax, 0x430348
0x0040921e:	pushl $0x429fb8<UINT32>
0x00409223:	pushl %edi
0x00409224:	movl 0x4320b4, %eax
0x00409229:	call GetProcAddress@KERNEL32.DLL
0x0040922b:	xorl %eax, 0x430348
0x00409231:	movl 0x4320b8, %eax
0x00409236:	pushl $0x429fc8<UINT32>
0x0040923b:	pushl %edi
0x0040923c:	call GetProcAddress@KERNEL32.DLL
0x0040923e:	xorl %eax, 0x430348
0x00409244:	pushl $0x429fe8<UINT32>
0x00409249:	pushl %edi
0x0040924a:	movl 0x4320bc, %eax
0x0040924f:	call GetProcAddress@KERNEL32.DLL
0x00409251:	xorl %eax, 0x430348
0x00409257:	popl %edi
0x00409258:	movl 0x4320c0, %eax
0x0040925d:	popl %esi
0x0040925e:	ret

0x0040a6d5:	call 0x00405703
0x00405703:	pushl %esi
0x00405704:	pushl %edi
0x00405705:	movl %esi, $0x430360<UINT32>
0x0040570a:	movl %edi, $0x431608<UINT32>
0x0040570f:	cmpl 0x4(%esi), $0x1<UINT8>
0x00405713:	jne 22
0x00405715:	pushl $0x0<UINT8>
0x00405717:	movl (%esi), %edi
0x00405719:	addl %edi, $0x18<UINT8>
0x0040571c:	pushl $0xfa0<UINT32>
0x00405721:	pushl (%esi)
0x00405723:	call 0x00408f66
0x00408f66:	pushl %ebp
0x00408f67:	movl %ebp, %esp
0x00408f69:	movl %eax, 0x432050
0x00408f6e:	xorl %eax, 0x430348
0x00408f74:	je 13
0x00408f76:	pushl 0x10(%ebp)
0x00408f79:	pushl 0xc(%ebp)
0x00408f7c:	pushl 0x8(%ebp)
0x00408f7f:	call InitializeCriticalSectionEx@kernel32.dll
InitializeCriticalSectionEx@kernel32.dll: API Node	
0x00408f81:	popl %ebp
0x00408f82:	ret

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
