0x004141d0:	pusha
0x004141d1:	movl %esi, $0x40e000<UINT32>
0x004141d6:	leal %edi, -53248(%esi)
0x004141dc:	pushl %edi
0x004141dd:	orl %ebp, $0xffffffff<UINT8>
0x004141e0:	jmp 0x004141f2
0x004141f2:	movl %ebx, (%esi)
0x004141f4:	subl %esi, $0xfffffffc<UINT8>
0x004141f7:	adcl %ebx, %ebx
0x004141f9:	jb 0x004141e8
0x004141e8:	movb %al, (%esi)
0x004141ea:	incl %esi
0x004141eb:	movb (%edi), %al
0x004141ed:	incl %edi
0x004141ee:	addl %ebx, %ebx
0x004141f0:	jne 0x004141f9
0x004141fb:	movl %eax, $0x1<UINT32>
0x00414200:	addl %ebx, %ebx
0x00414202:	jne 0x0041420b
0x0041420b:	adcl %eax, %eax
0x0041420d:	addl %ebx, %ebx
0x0041420f:	jae 0x00414200
0x00414211:	jne 0x0041421c
0x0041421c:	xorl %ecx, %ecx
0x0041421e:	subl %eax, $0x3<UINT8>
0x00414221:	jb 0x00414230
0x00414230:	addl %ebx, %ebx
0x00414232:	jne 0x0041423b
0x0041423b:	adcl %ecx, %ecx
0x0041423d:	addl %ebx, %ebx
0x0041423f:	jne 0x00414248
0x00414248:	adcl %ecx, %ecx
0x0041424a:	jne 0x0041426c
0x0041424c:	incl %ecx
0x0041424d:	addl %ebx, %ebx
0x0041424f:	jne 0x00414258
0x00414258:	adcl %ecx, %ecx
0x0041425a:	addl %ebx, %ebx
0x0041425c:	jae 0x0041424d
0x0041425e:	jne 0x00414269
0x00414269:	addl %ecx, $0x2<UINT8>
0x0041426c:	cmpl %ebp, $0xfffff300<UINT32>
0x00414272:	adcl %ecx, $0x1<UINT8>
0x00414275:	leal %edx, (%edi,%ebp)
0x00414278:	cmpl %ebp, $0xfffffffc<UINT8>
0x0041427b:	jbe 0x0041428c
0x0041427d:	movb %al, (%edx)
0x0041427f:	incl %edx
0x00414280:	movb (%edi), %al
0x00414282:	incl %edi
0x00414283:	decl %ecx
0x00414284:	jne 0x0041427d
0x00414286:	jmp 0x004141ee
0x00414223:	shll %eax, $0x8<UINT8>
0x00414226:	movb %al, (%esi)
0x00414228:	incl %esi
0x00414229:	xorl %eax, $0xffffffff<UINT8>
0x0041422c:	je 0x004142a2
0x0041422e:	movl %ebp, %eax
0x0041428c:	movl %eax, (%edx)
0x0041428e:	addl %edx, $0x4<UINT8>
0x00414291:	movl (%edi), %eax
0x00414293:	addl %edi, $0x4<UINT8>
0x00414296:	subl %ecx, $0x4<UINT8>
0x00414299:	ja 0x0041428c
0x0041429b:	addl %edi, %ecx
0x0041429d:	jmp 0x004141ee
0x00414213:	movl %ebx, (%esi)
0x00414215:	subl %esi, $0xfffffffc<UINT8>
0x00414218:	adcl %ebx, %ebx
0x0041421a:	jae 0x00414200
0x00414204:	movl %ebx, (%esi)
0x00414206:	subl %esi, $0xfffffffc<UINT8>
0x00414209:	adcl %ebx, %ebx
0x00414260:	movl %ebx, (%esi)
0x00414262:	subl %esi, $0xfffffffc<UINT8>
0x00414265:	adcl %ebx, %ebx
0x00414267:	jae 0x0041424d
0x00414234:	movl %ebx, (%esi)
0x00414236:	subl %esi, $0xfffffffc<UINT8>
0x00414239:	adcl %ebx, %ebx
0x00414241:	movl %ebx, (%esi)
0x00414243:	subl %esi, $0xfffffffc<UINT8>
0x00414246:	adcl %ebx, %ebx
0x00414251:	movl %ebx, (%esi)
0x00414253:	subl %esi, $0xfffffffc<UINT8>
0x00414256:	adcl %ebx, %ebx
0x004142a2:	popl %esi
0x004142a3:	movl %edi, %esi
0x004142a5:	movl %ecx, $0x461<UINT32>
0x004142aa:	movb %al, (%edi)
0x004142ac:	incl %edi
0x004142ad:	subb %al, $0xffffffe8<UINT8>
0x004142af:	cmpb %al, $0x1<UINT8>
0x004142b1:	ja 0x004142aa
0x004142b3:	cmpb (%edi), $0x0<UINT8>
0x004142b6:	jne 0x004142aa
0x004142b8:	movl %eax, (%edi)
0x004142ba:	movb %bl, 0x4(%edi)
0x004142bd:	shrw %ax, $0x8<UINT8>
0x004142c1:	roll %eax, $0x10<UINT8>
0x004142c4:	xchgb %ah, %al
0x004142c6:	subl %eax, %edi
0x004142c8:	subb %bl, $0xffffffe8<UINT8>
0x004142cb:	addl %eax, %esi
0x004142cd:	movl (%edi), %eax
0x004142cf:	addl %edi, $0x5<UINT8>
0x004142d2:	movb %al, %bl
0x004142d4:	loop 0x004142af
0x004142d6:	leal %edi, 0x12000(%esi)
0x004142dc:	movl %eax, (%edi)
0x004142de:	orl %eax, %eax
0x004142e0:	je 60
0x004142e2:	movl %ebx, 0x4(%edi)
0x004142e5:	leal %eax, 0x151d4(%eax,%esi)
0x004142ec:	addl %ebx, %esi
0x004142ee:	pushl %eax
0x004142ef:	addl %edi, $0x8<UINT8>
0x004142f2:	call 0x00000000
Unknown Node: Unknown Node	
