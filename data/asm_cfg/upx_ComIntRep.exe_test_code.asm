0x00614800:	pusha
0x00614801:	movl %esi, $0x506000<UINT32>
0x00614806:	leal %edi, -1069056(%esi)
0x0061480c:	pushl %edi
0x0061480d:	jmp 0x0061481a
0x0061481a:	movl %ebx, (%esi)
0x0061481c:	subl %esi, $0xfffffffc<UINT8>
0x0061481f:	adcl %ebx, %ebx
0x00614821:	jb 0x00614810
0x00614810:	movb %al, (%esi)
0x00614812:	incl %esi
0x00614813:	movb (%edi), %al
0x00614815:	incl %edi
0x00614816:	addl %ebx, %ebx
0x00614818:	jne 0x00614821
0x00614823:	movl %eax, $0x1<UINT32>
0x00614828:	addl %ebx, %ebx
0x0061482a:	jne 0x00614833
0x00614833:	adcl %eax, %eax
0x00614835:	addl %ebx, %ebx
0x00614837:	jae 0x00614844
0x00614839:	jne 0x00614863
0x00614863:	xorl %ecx, %ecx
0x00614865:	subl %eax, $0x3<UINT8>
0x00614868:	jb 0x0061487b
0x0061486a:	shll %eax, $0x8<UINT8>
0x0061486d:	movb %al, (%esi)
0x0061486f:	incl %esi
0x00614870:	xorl %eax, $0xffffffff<UINT8>
0x00614873:	je 0x006148ea
0x00614875:	sarl %eax
0x00614877:	movl %ebp, %eax
0x00614879:	jmp 0x00614886
0x00614886:	jb 0x00614854
0x00614854:	addl %ebx, %ebx
0x00614856:	jne 0x0061485f
0x0061485f:	adcl %ecx, %ecx
0x00614861:	jmp 0x006148b5
0x006148b5:	cmpl %ebp, $0xfffffb00<UINT32>
0x006148bb:	adcl %ecx, $0x2<UINT8>
0x006148be:	leal %edx, (%edi,%ebp)
0x006148c1:	cmpl %ebp, $0xfffffffc<UINT8>
0x006148c4:	jbe 0x006148d4
0x006148d4:	movl %eax, (%edx)
0x006148d6:	addl %edx, $0x4<UINT8>
0x006148d9:	movl (%edi), %eax
0x006148db:	addl %edi, $0x4<UINT8>
0x006148de:	subl %ecx, $0x4<UINT8>
0x006148e1:	ja 0x006148d4
0x006148e3:	addl %edi, %ecx
0x006148e5:	jmp 0x00614816
0x0061482c:	movl %ebx, (%esi)
0x0061482e:	subl %esi, $0xfffffffc<UINT8>
0x00614831:	adcl %ebx, %ebx
0x0061487b:	addl %ebx, %ebx
0x0061487d:	jne 0x00614886
0x00614888:	incl %ecx
0x00614889:	addl %ebx, %ebx
0x0061488b:	jne 0x00614894
0x00614894:	jb 0x00614854
0x00614896:	addl %ebx, %ebx
0x00614898:	jne 0x006148a1
0x006148a1:	adcl %ecx, %ecx
0x006148a3:	addl %ebx, %ebx
0x006148a5:	jae 0x00614896
0x006148a7:	jne 0x006148b2
0x006148b2:	addl %ecx, $0x2<UINT8>
0x0061483b:	movl %ebx, (%esi)
0x0061483d:	subl %esi, $0xfffffffc<UINT8>
0x00614840:	adcl %ebx, %ebx
0x00614842:	jb 0x00614863
0x0061488d:	movl %ebx, (%esi)
0x0061488f:	subl %esi, $0xfffffffc<UINT8>
0x00614892:	adcl %ebx, %ebx
0x00614858:	movl %ebx, (%esi)
0x0061485a:	subl %esi, $0xfffffffc<UINT8>
0x0061485d:	adcl %ebx, %ebx
0x00614844:	decl %eax
0x00614845:	addl %ebx, %ebx
0x00614847:	jne 0x00614850
0x00614850:	adcl %eax, %eax
0x00614852:	jmp 0x00614828
0x006148c6:	movb %al, (%edx)
0x006148c8:	incl %edx
0x006148c9:	movb (%edi), %al
0x006148cb:	incl %edi
0x006148cc:	decl %ecx
0x006148cd:	jne 0x006148c6
0x006148cf:	jmp 0x00614816
0x0061489a:	movl %ebx, (%esi)
0x0061489c:	subl %esi, $0xfffffffc<UINT8>
0x0061489f:	adcl %ebx, %ebx
0x00614849:	movl %ebx, (%esi)
0x0061484b:	subl %esi, $0xfffffffc<UINT8>
0x0061484e:	adcl %ebx, %ebx
0x006148a9:	movl %ebx, (%esi)
0x006148ab:	subl %esi, $0xfffffffc<UINT8>
0x006148ae:	adcl %ebx, %ebx
0x006148b0:	jae 0x00614896
0x0061487f:	movl %ebx, (%esi)
0x00614881:	subl %esi, $0xfffffffc<UINT8>
0x00614884:	adcl %ebx, %ebx
0x006148ea:	popl %esi
0x006148eb:	movl %edi, %esi
0x006148ed:	movl %ecx, $0x3ea9<UINT32>
0x006148f2:	movb %al, (%edi)
0x006148f4:	incl %edi
0x006148f5:	subb %al, $0xffffffe8<UINT8>
0x006148f7:	cmpb %al, $0x1<UINT8>
0x006148f9:	ja 0x006148f2
0x006148fb:	cmpb (%edi), $0x11<UINT8>
0x006148fe:	jne 0x006148f2
0x00614900:	movl %eax, (%edi)
0x00614902:	movb %bl, 0x4(%edi)
0x00614905:	shrw %ax, $0x8<UINT8>
0x00614909:	roll %eax, $0x10<UINT8>
0x0061490c:	xchgb %ah, %al
0x0061490e:	subl %eax, %edi
0x00614910:	subb %bl, $0xffffffe8<UINT8>
0x00614913:	addl %eax, %esi
0x00614915:	movl (%edi), %eax
0x00614917:	addl %edi, $0x5<UINT8>
0x0061491a:	movb %al, %bl
0x0061491c:	loop 0x006148f7
