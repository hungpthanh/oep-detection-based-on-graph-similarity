0x00436000:	movl %ebx, $0x4001d0<UINT32>
0x00436005:	movl %edi, $0x401000<UINT32>
0x0043600a:	movl %esi, $0x42721d<UINT32>
0x0043600f:	pushl %ebx
0x00436010:	call 0x0043601f
0x0043601f:	cld
0x00436020:	movb %dl, $0xffffff80<UINT8>
0x00436022:	movsb %es:(%edi), %ds:(%esi)
0x00436023:	pushl $0x2<UINT8>
0x00436025:	popl %ebx
0x00436026:	call 0x00436015
0x00436015:	addb %dl, %dl
0x00436017:	jne 0x0043601e
0x00436019:	movb %dl, (%esi)
0x0043601b:	incl %esi
0x0043601c:	adcb %dl, %dl
0x0043601e:	ret

0x00436029:	jae 0x00436022
0x0043602b:	xorl %ecx, %ecx
0x0043602d:	call 0x00436015
0x00436030:	jae 0x0043604a
0x00436032:	xorl %eax, %eax
0x00436034:	call 0x00436015
0x00436037:	jae 0x0043605a
0x00436039:	movb %bl, $0x2<UINT8>
0x0043603b:	incl %ecx
0x0043603c:	movb %al, $0x10<UINT8>
0x0043603e:	call 0x00436015
0x00436041:	adcb %al, %al
0x00436043:	jae 0x0043603e
0x00436045:	jne 0x00436086
0x00436086:	pushl %esi
0x00436087:	movl %esi, %edi
0x00436089:	subl %esi, %eax
0x0043608b:	rep movsb %es:(%edi), %ds:(%esi)
0x0043608d:	popl %esi
0x0043608e:	jmp 0x00436026
0x00436047:	stosb %es:(%edi), %al
0x00436048:	jmp 0x00436026
0x0043605a:	lodsb %al, %ds:(%esi)
0x0043605b:	shrl %eax
0x0043605d:	je 0x004360a0
0x0043605f:	adcl %ecx, %ecx
0x00436061:	jmp 0x0043607f
0x0043607f:	incl %ecx
0x00436080:	incl %ecx
0x00436081:	xchgl %ebp, %eax
0x00436082:	movl %eax, %ebp
0x00436084:	movb %bl, $0x1<UINT8>
0x0043604a:	call 0x00436092
0x00436092:	incl %ecx
0x00436093:	call 0x00436015
0x00436097:	adcl %ecx, %ecx
0x00436099:	call 0x00436015
0x0043609d:	jb 0x00436093
0x0043609f:	ret

0x0043604f:	subl %ecx, %ebx
0x00436051:	jne 0x00436063
0x00436063:	xchgl %ecx, %eax
0x00436064:	decl %eax
0x00436065:	shll %eax, $0x8<UINT8>
0x00436068:	lodsb %al, %ds:(%esi)
0x00436069:	call 0x00436090
0x00436090:	xorl %ecx, %ecx
0x0043606e:	cmpl %eax, $0x7d00<UINT32>
0x00436073:	jae 0x0043607f
0x00436075:	cmpb %ah, $0x5<UINT8>
0x00436078:	jae 0x00436080
0x0043607a:	cmpl %eax, $0x7f<UINT8>
0x0043607d:	ja 0x00436081
0x00436053:	call 0x00436090
0x00436058:	jmp 0x00436082
0x004360a0:	popl %edi
0x004360a1:	popl %ebx
0x004360a2:	movzwl %edi, (%ebx)
0x004360a5:	decl %edi
0x004360a6:	je 0x004360b0
0x004360a8:	decl %edi
0x004360a9:	je 19
0x004360ab:	shll %edi, $0xc<UINT8>
0x004360ae:	jmp 0x004360b7
0x004360b7:	incl %ebx
0x004360b8:	incl %ebx
0x004360b9:	jmp 0x0043600f
0x004360b0:	movl %edi, 0x2(%ebx)
0x004360b3:	pushl %edi
0x004360b4:	addl %ebx, $0x4<UINT8>