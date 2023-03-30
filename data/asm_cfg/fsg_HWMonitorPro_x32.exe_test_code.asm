0x006b6000:	movl %ebx, $0x4001d0<UINT32>
0x006b6005:	movl %edi, $0x401000<UINT32>
0x006b600a:	movl %esi, $0x60153a<UINT32>
0x006b600f:	pushl %ebx
0x006b6010:	call 0x006b601f
0x006b601f:	cld
0x006b6020:	movb %dl, $0xffffff80<UINT8>
0x006b6022:	movsb %es:(%edi), %ds:(%esi)
0x006b6023:	pushl $0x2<UINT8>
0x006b6025:	popl %ebx
0x006b6026:	call 0x006b6015
0x006b6015:	addb %dl, %dl
0x006b6017:	jne 0x006b601e
0x006b6019:	movb %dl, (%esi)
0x006b601b:	incl %esi
0x006b601c:	adcb %dl, %dl
0x006b601e:	ret

0x006b6029:	jae 0x006b6022
0x006b602b:	xorl %ecx, %ecx
0x006b602d:	call 0x006b6015
0x006b6030:	jae 0x006b604a
0x006b6032:	xorl %eax, %eax
0x006b6034:	call 0x006b6015
0x006b6037:	jae 0x006b605a
0x006b6039:	movb %bl, $0x2<UINT8>
0x006b603b:	incl %ecx
0x006b603c:	movb %al, $0x10<UINT8>
0x006b603e:	call 0x006b6015
0x006b6041:	adcb %al, %al
0x006b6043:	jae 0x006b603e
0x006b6045:	jne 0x006b6086
0x006b6086:	pushl %esi
0x006b6087:	movl %esi, %edi
0x006b6089:	subl %esi, %eax
0x006b608b:	rep movsb %es:(%edi), %ds:(%esi)
0x006b608d:	popl %esi
0x006b608e:	jmp 0x006b6026
0x006b6047:	stosb %es:(%edi), %al
0x006b6048:	jmp 0x006b6026
0x006b604a:	call 0x006b6092
0x006b6092:	incl %ecx
0x006b6093:	call 0x006b6015
0x006b6097:	adcl %ecx, %ecx
0x006b6099:	call 0x006b6015
0x006b609d:	jb 0x006b6093
0x006b609f:	ret

0x006b604f:	subl %ecx, %ebx
0x006b6051:	jne 0x006b6063
0x006b6063:	xchgl %ecx, %eax
0x006b6064:	decl %eax
0x006b6065:	shll %eax, $0x8<UINT8>
0x006b6068:	lodsb %al, %ds:(%esi)
0x006b6069:	call 0x006b6090
0x006b6090:	xorl %ecx, %ecx
0x006b606e:	cmpl %eax, $0x7d00<UINT32>
0x006b6073:	jae 0x006b607f
0x006b6075:	cmpb %ah, $0x5<UINT8>
0x006b6078:	jae 0x006b6080
0x006b607a:	cmpl %eax, $0x7f<UINT8>
0x006b607d:	ja 0x006b6081
0x006b607f:	incl %ecx
0x006b6080:	incl %ecx
0x006b6081:	xchgl %ebp, %eax
0x006b6082:	movl %eax, %ebp
0x006b6084:	movb %bl, $0x1<UINT8>
0x006b6053:	call 0x006b6090
0x006b6058:	jmp 0x006b6082
0x006b605a:	lodsb %al, %ds:(%esi)
0x006b605b:	shrl %eax
0x006b605d:	je 0x006b60a0
0x006b605f:	adcl %ecx, %ecx
0x006b6061:	jmp 0x006b607f
0x006b60a0:	popl %edi
0x006b60a1:	popl %ebx
0x006b60a2:	movzwl %edi, (%ebx)
0x006b60a5:	decl %edi
0x006b60a6:	je 0x006b60b0
0x006b60a8:	decl %edi
0x006b60a9:	je 0x006b60be
0x006b60ab:	shll %edi, $0xc<UINT8>
0x006b60ae:	jmp 0x006b60b7
0x006b60b7:	incl %ebx
0x006b60b8:	incl %ebx
0x006b60b9:	jmp 0x006b600f
0x006b60b0:	movl %edi, 0x2(%ebx)
0x006b60b3:	pushl %edi
0x006b60b4:	addl %ebx, $0x4<UINT8>
0x006b60be:	popl %edi
0x006b60bf:	movl %ebx, $0x6b6128<UINT32>
0x006b60c4:	incl %edi
0x006b60c5:	movl %esi, (%edi)
0x006b60c7:	scasl %eax, %es:(%edi)
0x006b60c8:	pushl %edi
0x006b60c9:	call LoadLibraryA@KERNEL32.dll
LoadLibraryA@kernel32.dll: API Node	
0x006b60cb:	xchgl %ebp, %eax
0x006b60cc:	xorl %eax, %eax
0x006b60ce:	scasb %al, %es:(%edi)
0x006b60cf:	jne 0x006b60ce
0x006b60d1:	decb (%edi)
0x006b60d3:	je 0x006b60c4
0x006b60d5:	decb (%edi)
0x006b60d7:	jne 0x006b60df
0x006b60df:	decb (%edi)
0x006b60e1:	je 0x004cb60b
0x006b60e7:	pushl %edi
0x006b60e8:	pushl %ebp
0x006b60e9:	call GetProcAddress@KERNEL32.dll
GetProcAddress@kernel32.dll: API Node	
0x006b60ec:	orl (%esi), %eax
0x006b60ee:	lodsl %eax, %ds:(%esi)
0x006b60ef:	jne 0x006b60cc
GetProcAddress@KERNEL32.dll: API Node	
LoadLibraryA@KERNEL32.dll: API Node	
0x006b60d9:	incl %edi
0x006b60da:	pushl (%edi)
0x006b60dc:	scasl %eax, %es:(%edi)
0x006b60dd:	jmp 0x006b60e8
0x004cb60b:	call 0x004d2230
0x004d2230:	movl %edi, %edi
0x004d2232:	pushl %ebp
0x004d2233:	movl %ebp, %esp
0x004d2235:	subl %esp, $0x10<UINT8>
0x004d2238:	movl %eax, 0x594ea0
0x004d223d:	andl -8(%ebp), $0x0<UINT8>
0x004d2241:	andl -4(%ebp), $0x0<UINT8>
0x004d2245:	pushl %ebx
0x004d2246:	pushl %edi
0x004d2247:	movl %edi, $0xbb40e64e<UINT32>
0x004d224c:	movl %ebx, $0xffff0000<UINT32>
0x004d2251:	cmpl %eax, %edi
0x004d2253:	je 0x004d2262
0x004d2262:	pushl %esi
0x004d2263:	leal %eax, -8(%ebp)
0x004d2266:	pushl %eax
0x004d2267:	call GetSystemTimeAsFileTime@KERNEL32.dll
GetSystemTimeAsFileTime@KERNEL32.dll: API Node	
0x004d226d:	movl %esi, -4(%ebp)
0x004d2270:	xorl %esi, -8(%ebp)
0x004d2273:	call GetCurrentProcessId@KERNEL32.dll
GetCurrentProcessId@KERNEL32.dll: API Node	
0x004d2279:	xorl %esi, %eax
0x004d227b:	call GetCurrentThreadId@KERNEL32.dll
GetCurrentThreadId@KERNEL32.dll: API Node	
0x004d2281:	xorl %esi, %eax
0x004d2283:	call GetTickCount@KERNEL32.dll
GetTickCount@KERNEL32.dll: API Node	
0x004d2289:	xorl %esi, %eax
0x004d228b:	leal %eax, -16(%ebp)
0x004d228e:	pushl %eax
0x004d228f:	call QueryPerformanceCounter@KERNEL32.dll
QueryPerformanceCounter@KERNEL32.dll: API Node	
0x004d2295:	movl %eax, -12(%ebp)
0x004d2298:	xorl %eax, -16(%ebp)
0x004d229b:	xorl %esi, %eax
0x004d229d:	cmpl %esi, %edi
0x004d229f:	jne 0x004d22a8
0x004d22a8:	testl %ebx, %esi
0x004d22aa:	jne 0x004d22b3
0x004d22b3:	movl 0x594ea0, %esi
0x004d22b9:	notl %esi
0x004d22bb:	movl 0x594ea4, %esi
0x004d22c1:	popl %esi
0x004d22c2:	popl %edi
0x004d22c3:	popl %ebx
0x004d22c4:	leave
0x004d22c5:	ret

0x004cb610:	jmp 0x004cb48e
0x004cb48e:	pushl $0x58<UINT8>
0x004cb490:	pushl $0x575d28<UINT32>
0x004cb495:	call 0x004ceaa0
0x004ceaa0:	pushl $0x4cdb30<UINT32>
0x004ceaa5:	pushl %fs:0
0x004ceaac:	movl %eax, 0x10(%esp)
0x004ceab0:	movl 0x10(%esp), %ebp
0x004ceab4:	leal %ebp, 0x10(%esp)
0x004ceab8:	subl %esp, %eax
0x004ceaba:	pushl %ebx
0x004ceabb:	pushl %esi
0x004ceabc:	pushl %edi
0x004ceabd:	movl %eax, 0x594ea0
0x004ceac2:	xorl -4(%ebp), %eax
0x004ceac5:	xorl %eax, %ebp
0x004ceac7:	pushl %eax
0x004ceac8:	movl -24(%ebp), %esp
0x004ceacb:	pushl -8(%ebp)
0x004ceace:	movl %eax, -4(%ebp)
0x004cead1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004cead8:	movl -8(%ebp), %eax
0x004ceadb:	leal %eax, -16(%ebp)
0x004ceade:	movl %fs:0, %eax
0x004ceae4:	ret

0x004cb49a:	xorl %esi, %esi
0x004cb49c:	movl -4(%ebp), %esi
0x004cb49f:	leal %eax, -104(%ebp)
0x004cb4a2:	pushl %eax
0x004cb4a3:	call GetStartupInfoW@KERNEL32.dll
GetStartupInfoW@KERNEL32.dll: API Node	
0x004cb4a9:	pushl $0xfffffffe<UINT8>
0x004cb4ab:	popl %edi
0x004cb4ac:	movl -4(%ebp), %edi
0x004cb4af:	movl %eax, $0x5a4d<UINT32>
0x004cb4b4:	cmpw 0x400000, %ax
0x004cb4bb:	jne 56
0x004cb4bd:	movl %eax, 0x40003c
0x004cb4c2:	cmpl 0x400000(%eax), $0x4550<UINT32>
0x004cb4cc:	jne 39
0x004cb4ce:	movl %ecx, $0x10b<UINT32>
0x004cb4d3:	cmpw 0x400018(%eax), %cx
0x004cb4da:	jne 25
0x004cb4dc:	cmpl 0x400074(%eax), $0xe<UINT8>
0x004cb4e3:	jbe 16
0x004cb4e5:	xorl %ecx, %ecx
0x004cb4e7:	cmpl 0x4000e8(%eax), %esi
0x004cb4ed:	setne %cl
0x004cb4f0:	movl -28(%ebp), %ecx
0x004cb4f3:	jmp 0x004cb4f8
0x004cb4f8:	xorl %ebx, %ebx
0x004cb4fa:	incl %ebx
0x004cb4fb:	pushl %ebx
0x004cb4fc:	call 0x004d2200
0x004d2200:	movl %edi, %edi
0x004d2202:	pushl %ebp
0x004d2203:	movl %ebp, %esp
0x004d2205:	xorl %eax, %eax
0x004d2207:	cmpl 0x8(%ebp), %eax
0x004d220a:	pushl $0x0<UINT8>
0x004d220c:	sete %al
0x004d220f:	pushl $0x1000<UINT32>
0x004d2214:	pushl %eax
0x004d2215:	call HeapCreate@KERNEL32.dll
HeapCreate@KERNEL32.dll: API Node	
0x004d221b:	movl 0x59b494, %eax
0x004d2220:	testl %eax, %eax
0x004d2222:	jne 0x004d2226
0x004d2226:	xorl %eax, %eax
0x004d2228:	incl %eax
0x004d2229:	movl 0x59e6e8, %eax
0x004d222e:	popl %ebp
0x004d222f:	ret

0x004cb501:	popl %ecx
0x004cb502:	testl %eax, %eax
0x004cb504:	jne 0x004cb50e
0x004cb50e:	call 0x004d2073
0x004d2073:	movl %edi, %edi
0x004d2075:	pushl %esi
0x004d2076:	pushl %edi
0x004d2077:	movl %esi, $0x547698<UINT32>
0x004d207c:	pushl %esi
0x004d207d:	call GetModuleHandleW@KERNEL32.dll
GetModuleHandleW@KERNEL32.dll: API Node	
0x004d2083:	testl %eax, %eax
0x004d2085:	jne 0x004d208e
0x004d208e:	movl %edi, %eax
0x004d2090:	testl %edi, %edi
0x004d2092:	je 350
0x004d2098:	movl %esi, 0x52a3f4
0x004d209e:	pushl $0x5476e4<UINT32>
0x004d20a3:	pushl %edi
0x004d20a4:	call GetProcAddress@KERNEL32.dll
0x004d20a6:	pushl $0x5476d8<UINT32>
0x004d20ab:	pushl %edi
0x004d20ac:	movl 0x59b484, %eax
0x004d20b1:	call GetProcAddress@KERNEL32.dll
0x004d20b3:	pushl $0x5476cc<UINT32>
0x004d20b8:	pushl %edi
0x004d20b9:	movl 0x59b488, %eax
0x004d20be:	call GetProcAddress@KERNEL32.dll
0x004d20c0:	pushl $0x5476c4<UINT32>
0x004d20c5:	pushl %edi
0x004d20c6:	movl 0x59b48c, %eax
0x004d20cb:	call GetProcAddress@KERNEL32.dll
0x004d20cd:	cmpl 0x59b484, $0x0<UINT8>
0x004d20d4:	movl %esi, 0x52a15c
0x004d20da:	movl 0x59b490, %eax
0x004d20df:	je 22
0x004d20e1:	cmpl 0x59b488, $0x0<UINT8>
0x004d20e8:	je 13
0x004d20ea:	cmpl 0x59b48c, $0x0<UINT8>
0x004d20f1:	je 4
0x004d20f3:	testl %eax, %eax
0x004d20f5:	jne 0x004d211b
0x004d211b:	call TlsAlloc@KERNEL32.dll
TlsAlloc@KERNEL32.dll: API Node	
0x004d2121:	movl 0x59514c, %eax
0x004d2126:	cmpl %eax, $0xffffffff<UINT8>
0x004d2129:	je 204
0x004d212f:	pushl 0x59b488
0x004d2135:	pushl %eax
0x004d2136:	call TlsSetValue@KERNEL32.dll
TlsSetValue@KERNEL32.dll: API Node	
0x004d2138:	testl %eax, %eax
0x004d213a:	je 187
0x004d2140:	call 0x004d0b78
0x004d0b78:	movl %edi, %edi
0x004d0b7a:	pushl %esi
0x004d0b7b:	call 0x004d1cd5
0x004d1cd5:	pushl $0x0<UINT8>
0x004d1cd7:	call 0x004d1c63
0x004d1c63:	movl %edi, %edi
0x004d1c65:	pushl %ebp
0x004d1c66:	movl %ebp, %esp
0x004d1c68:	pushl %esi
0x004d1c69:	pushl 0x59514c
0x004d1c6f:	movl %esi, 0x52a294
0x004d1c75:	call TlsGetValue@KERNEL32.dll
TlsGetValue@KERNEL32.dll: API Node	
0x004d1c77:	testl %eax, %eax
0x004d1c79:	je 33
0x004d1c7b:	movl %eax, 0x595148
0x004d1c80:	cmpl %eax, $0xffffffff<UINT8>
0x004d1c83:	je 0x004d1c9c
0x004d1c9c:	movl %esi, $0x547698<UINT32>
0x004d1ca1:	pushl %esi
0x004d1ca2:	call GetModuleHandleW@KERNEL32.dll
0x004d1ca8:	testl %eax, %eax
0x004d1caa:	jne 0x004d1cb7
0x004d1cb7:	pushl $0x547688<UINT32>
0x004d1cbc:	pushl %eax
0x004d1cbd:	call GetProcAddress@KERNEL32.dll
0x004d1cc3:	testl %eax, %eax
0x004d1cc5:	je 8
0x004d1cc7:	pushl 0x8(%ebp)
0x004d1cca:	call EncodePointer@KERNEL32.DLL
EncodePointer@KERNEL32.DLL: API Node	
0x004d1ccc:	movl 0x8(%ebp), %eax
0x004d1ccf:	movl %eax, 0x8(%ebp)
0x004d1cd2:	popl %esi
0x004d1cd3:	popl %ebp
0x004d1cd4:	ret

0x004d1cdc:	popl %ecx
0x004d1cdd:	ret

0x004d0b80:	movl %esi, %eax
0x004d0b82:	pushl %esi
0x004d0b83:	call 0x004e063a
0x004e063a:	movl %edi, %edi
0x004e063c:	pushl %ebp
0x004e063d:	movl %ebp, %esp
0x004e063f:	movl %eax, 0x8(%ebp)
0x004e0642:	movl 0x59ba3c, %eax
0x004e0647:	popl %ebp
0x004e0648:	ret

0x004d0b88:	pushl %esi
0x004d0b89:	call 0x004e0892
0x004e0892:	movl %edi, %edi
0x004e0894:	pushl %ebp
0x004e0895:	movl %ebp, %esp
0x004e0897:	movl %eax, 0x8(%ebp)
0x004e089a:	movl 0x59ba5c, %eax
0x004e089f:	popl %ebp
0x004e08a0:	ret

0x004d0b8e:	pushl %esi
0x004d0b8f:	call 0x004d32dd
0x004d32dd:	movl %edi, %edi
0x004d32df:	pushl %ebp
0x004d32e0:	movl %ebp, %esp
0x004d32e2:	movl %eax, 0x8(%ebp)
0x004d32e5:	movl 0x59b7c4, %eax
0x004d32ea:	popl %ebp
0x004d32eb:	ret

0x004d0b94:	pushl %esi
0x004d0b95:	call 0x004de7ca
0x004de7ca:	movl %edi, %edi
0x004de7cc:	pushl %ebp
0x004de7cd:	movl %ebp, %esp
0x004de7cf:	movl %eax, 0x8(%ebp)
0x004de7d2:	movl 0x59b8e4, %eax
0x004de7d7:	popl %ebp
0x004de7d8:	ret

0x004d0b9a:	pushl %esi
0x004d0b9b:	call 0x004e0883
0x004e0883:	movl %edi, %edi
0x004e0885:	pushl %ebp
0x004e0886:	movl %ebp, %esp
0x004e0888:	movl %eax, 0x8(%ebp)
0x004e088b:	movl 0x59ba58, %eax
0x004e0890:	popl %ebp
0x004e0891:	ret

0x004d0ba0:	pushl %esi
0x004d0ba1:	call 0x004e0671
0x004e0671:	movl %edi, %edi
0x004e0673:	pushl %ebp
0x004e0674:	movl %ebp, %esp
0x004e0676:	movl %eax, 0x8(%ebp)
0x004e0679:	movl 0x59ba44, %eax
0x004e067e:	movl 0x59ba48, %eax
0x004e0683:	movl 0x59ba4c, %eax
0x004e0688:	movl 0x59ba50, %eax
0x004e068d:	popl %ebp
0x004e068e:	ret

0x004d0ba6:	pushl %esi
0x004d0ba7:	call 0x0042bcff
0x0042bcff:	ret

0x004d0bac:	pushl %esi
0x004d0bad:	call 0x004d5179
0x004d5179:	pushl $0x4d50f5<UINT32>
0x004d517e:	call 0x004d1c63
0x004d5183:	popl %ecx
0x004d5184:	movl 0x59b7c8, %eax
0x004d5189:	ret

0x004d0bb2:	pushl $0x4d0b44<UINT32>
0x004d0bb7:	call 0x004d1c63
0x004d0bbc:	addl %esp, $0x24<UINT8>
0x004d0bbf:	movl 0x595030, %eax
0x004d0bc4:	popl %esi
0x004d0bc5:	ret

0x004d2145:	pushl 0x59b484
0x004d214b:	call 0x004d1c63
0x004d2150:	pushl 0x59b488
0x004d2156:	movl 0x59b484, %eax
0x004d215b:	call 0x004d1c63
0x004d2160:	pushl 0x59b48c
0x004d2166:	movl 0x59b488, %eax
0x004d216b:	call 0x004d1c63
0x004d2170:	pushl 0x59b490
0x004d2176:	movl 0x59b48c, %eax
0x004d217b:	call 0x004d1c63
0x004d2180:	addl %esp, $0x10<UINT8>
0x004d2183:	movl 0x59b490, %eax
0x004d2188:	call 0x004df9c7
0x004df9c7:	movl %edi, %edi
0x004df9c9:	pushl %esi
0x004df9ca:	pushl %edi
0x004df9cb:	xorl %esi, %esi
0x004df9cd:	movl %edi, $0x59b8e8<UINT32>
0x004df9d2:	cmpl 0x595dec(,%esi,8), $0x1<UINT8>
0x004df9da:	jne 0x004df9fa
0x004df9dc:	leal %eax, 0x595de8(,%esi,8)
0x004df9e3:	movl (%eax), %edi
0x004df9e5:	pushl $0xfa0<UINT32>
0x004df9ea:	pushl (%eax)
0x004df9ec:	addl %edi, $0x18<UINT8>
0x004df9ef:	call 0x004e08a1
0x004e08a1:	pushl $0x10<UINT8>
0x004e08a3:	pushl $0x5763c0<UINT32>
0x004e08a8:	call 0x004ceaa0
0x004e08ad:	andl -4(%ebp), $0x0<UINT8>
0x004e08b1:	pushl 0xc(%ebp)
0x004e08b4:	pushl 0x8(%ebp)
0x004e08b7:	call InitializeCriticalSectionAndSpinCount@KERNEL32.dll
InitializeCriticalSectionAndSpinCount@KERNEL32.dll: API Node	
0x004e08bd:	movl -28(%ebp), %eax
0x004e08c0:	jmp 0x004e08f1
0x004e08f1:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004e08f8:	movl %eax, -28(%ebp)
0x004e08fb:	call 0x004ceae5
0x004ceae5:	movl %ecx, -16(%ebp)
0x004ceae8:	movl %fs:0, %ecx
0x004ceaef:	popl %ecx
0x004ceaf0:	popl %edi
0x004ceaf1:	popl %edi
0x004ceaf2:	popl %esi
0x004ceaf3:	popl %ebx
0x004ceaf4:	movl %esp, %ebp
0x004ceaf6:	popl %ebp
0x004ceaf7:	pushl %ecx
0x004ceaf8:	ret

0x004e0900:	ret

0x004df9f4:	popl %ecx
0x004df9f5:	popl %ecx
0x004df9f6:	testl %eax, %eax
0x004df9f8:	je 12
0x004df9fa:	incl %esi
0x004df9fb:	cmpl %esi, $0x24<UINT8>
0x004df9fe:	jl 0x004df9d2
0x004dfa00:	xorl %eax, %eax
0x004dfa02:	incl %eax
0x004dfa03:	popl %edi
0x004dfa04:	popl %esi
0x004dfa05:	ret

0x004d218d:	testl %eax, %eax
0x004d218f:	je 101
0x004d2191:	pushl $0x4d1f44<UINT32>
0x004d2196:	pushl 0x59b484
0x004d219c:	call 0x004d1cde
0x004d1cde:	movl %edi, %edi
0x004d1ce0:	pushl %ebp
0x004d1ce1:	movl %ebp, %esp
0x004d1ce3:	pushl %esi
0x004d1ce4:	pushl 0x59514c
0x004d1cea:	movl %esi, 0x52a294
0x004d1cf0:	call TlsGetValue@KERNEL32.dll
0x004d1cf2:	testl %eax, %eax
0x004d1cf4:	je 33
0x004d1cf6:	movl %eax, 0x595148
0x004d1cfb:	cmpl %eax, $0xffffffff<UINT8>
0x004d1cfe:	je 0x004d1d17
0x004d1d17:	movl %esi, $0x547698<UINT32>
0x004d1d1c:	pushl %esi
0x004d1d1d:	call GetModuleHandleW@KERNEL32.dll
0x004d1d23:	testl %eax, %eax
0x004d1d25:	jne 0x004d1d32
0x004d1d32:	pushl $0x5476b4<UINT32>
0x004d1d37:	pushl %eax
0x004d1d38:	call GetProcAddress@KERNEL32.dll
0x004d1d3e:	testl %eax, %eax
0x004d1d40:	je 8
0x004d1d42:	pushl 0x8(%ebp)
0x004d1d45:	call DecodePointer@KERNEL32.DLL
DecodePointer@KERNEL32.DLL: API Node	
0x004d1d47:	movl 0x8(%ebp), %eax
0x004d1d4a:	movl %eax, 0x8(%ebp)
0x004d1d4d:	popl %esi
0x004d1d4e:	popl %ebp
0x004d1d4f:	ret

0x004d21a1:	popl %ecx
0x004d21a2:	call FlsAlloc@KERNEL32.DLL
FlsAlloc@KERNEL32.DLL: API Node	
0x004d21a4:	movl 0x595148, %eax
0x004d21a9:	cmpl %eax, $0xffffffff<UINT8>
0x004d21ac:	je 72
0x004d21ae:	pushl $0x214<UINT32>
0x004d21b3:	pushl $0x1<UINT8>
0x004d21b5:	call 0x004d8d77
0x004d8d77:	movl %edi, %edi
0x004d8d79:	pushl %ebp
0x004d8d7a:	movl %ebp, %esp
0x004d8d7c:	pushl %esi
0x004d8d7d:	pushl %edi
0x004d8d7e:	xorl %esi, %esi
0x004d8d80:	pushl $0x0<UINT8>
0x004d8d82:	pushl 0xc(%ebp)
0x004d8d85:	pushl 0x8(%ebp)
0x004d8d88:	call 0x004e0901
0x004e0901:	pushl $0xc<UINT8>
0x004e0903:	pushl $0x5763e0<UINT32>
0x004e0908:	call 0x004ceaa0
0x004e090d:	movl %ecx, 0x8(%ebp)
0x004e0910:	xorl %edi, %edi
0x004e0912:	cmpl %ecx, %edi
0x004e0914:	jbe 46
0x004e0916:	pushl $0xffffffe0<UINT8>
0x004e0918:	popl %eax
0x004e0919:	xorl %edx, %edx
0x004e091b:	divl %eax, %ecx
0x004e091d:	cmpl %eax, 0xc(%ebp)
0x004e0920:	sbbl %eax, %eax
0x004e0922:	incl %eax
0x004e0923:	jne 0x004e0944
0x004e0944:	imull %ecx, 0xc(%ebp)
0x004e0948:	movl %esi, %ecx
0x004e094a:	movl 0x8(%ebp), %esi
0x004e094d:	cmpl %esi, %edi
0x004e094f:	jne 0x004e0954
0x004e0954:	xorl %ebx, %ebx
0x004e0956:	movl -28(%ebp), %ebx
0x004e0959:	cmpl %esi, $0xffffffe0<UINT8>
0x004e095c:	ja 105
0x004e095e:	cmpl 0x59e6e8, $0x3<UINT8>
0x004e0965:	jne 0x004e09b2
0x004e09b2:	cmpl %ebx, %edi
0x004e09b4:	jne 97
0x004e09b6:	pushl %esi
0x004e09b7:	pushl $0x8<UINT8>
0x004e09b9:	pushl 0x59b494
0x004e09bf:	call HeapAlloc@KERNEL32.dll
HeapAlloc@KERNEL32.dll: API Node	
0x004e09c5:	movl %ebx, %eax
0x004e09c7:	cmpl %ebx, %edi
0x004e09c9:	jne 0x004e0a17
0x004e0a17:	movl %eax, %ebx
0x004e0a19:	call 0x004ceae5
0x004e0a1e:	ret

0x004d8d8d:	movl %edi, %eax
0x004d8d8f:	addl %esp, $0xc<UINT8>
0x004d8d92:	testl %edi, %edi
0x004d8d94:	jne 0x004d8dbd
0x004d8dbd:	movl %eax, %edi
0x004d8dbf:	popl %edi
0x004d8dc0:	popl %esi
0x004d8dc1:	popl %ebp
0x004d8dc2:	ret

0x004d21ba:	movl %esi, %eax
0x004d21bc:	popl %ecx
0x004d21bd:	popl %ecx
0x004d21be:	testl %esi, %esi
0x004d21c0:	je 52
0x004d21c2:	pushl %esi
0x004d21c3:	pushl 0x595148
0x004d21c9:	pushl 0x59b48c
0x004d21cf:	call 0x004d1cde
0x004d1d00:	pushl %eax
0x004d1d01:	pushl 0x59514c
0x004d1d07:	call TlsGetValue@KERNEL32.dll
0x004d1d09:	call FlsGetValue@KERNEL32.DLL
FlsGetValue@KERNEL32.DLL: API Node	
0x004d1d0b:	testl %eax, %eax
0x004d1d0d:	je 0x004d1d17
0x004d21d4:	popl %ecx
0x004d21d5:	call FlsSetValue@KERNEL32.DLL
FlsSetValue@KERNEL32.DLL: API Node	
0x004d21d7:	testl %eax, %eax
0x004d21d9:	je 27
0x004d21db:	pushl $0x0<UINT8>
0x004d21dd:	pushl %esi
0x004d21de:	call 0x004d1dca
0x004d1dca:	pushl $0xc<UINT8>
0x004d1dcc:	pushl $0x575f90<UINT32>
0x004d1dd1:	call 0x004ceaa0
0x004d1dd6:	movl %esi, $0x547698<UINT32>
0x004d1ddb:	pushl %esi
0x004d1ddc:	call GetModuleHandleW@KERNEL32.dll
0x004d1de2:	testl %eax, %eax
0x004d1de4:	jne 0x004d1ded
0x004d1ded:	movl -28(%ebp), %eax
0x004d1df0:	movl %esi, 0x8(%ebp)
0x004d1df3:	movl 0x5c(%esi), $0x547610<UINT32>
0x004d1dfa:	xorl %edi, %edi
0x004d1dfc:	incl %edi
0x004d1dfd:	movl 0x14(%esi), %edi
0x004d1e00:	testl %eax, %eax
0x004d1e02:	je 36
0x004d1e04:	pushl $0x547688<UINT32>
0x004d1e09:	pushl %eax
0x004d1e0a:	movl %ebx, 0x52a3f4
0x004d1e10:	call GetProcAddress@KERNEL32.dll
0x004d1e12:	movl 0x1f8(%esi), %eax
0x004d1e18:	pushl $0x5476b4<UINT32>
0x004d1e1d:	pushl -28(%ebp)
0x004d1e20:	call GetProcAddress@KERNEL32.dll
0x004d1e22:	movl 0x1fc(%esi), %eax
0x004d1e28:	movl 0x70(%esi), %edi
0x004d1e2b:	movb 0xc8(%esi), $0x43<UINT8>
0x004d1e32:	movb 0x14b(%esi), $0x43<UINT8>
0x004d1e39:	movl 0x68(%esi), $0x595160<UINT32>
0x004d1e40:	pushl $0xd<UINT8>
0x004d1e42:	call 0x004dfb43
0x004dfb43:	movl %edi, %edi
0x004dfb45:	pushl %ebp
0x004dfb46:	movl %ebp, %esp
0x004dfb48:	movl %eax, 0x8(%ebp)
0x004dfb4b:	pushl %esi
0x004dfb4c:	leal %esi, 0x595de8(,%eax,8)
0x004dfb53:	cmpl (%esi), $0x0<UINT8>
0x004dfb56:	jne 0x004dfb6b
0x004dfb6b:	pushl (%esi)
0x004dfb6d:	call EnterCriticalSection@KERNEL32.dll
EnterCriticalSection@KERNEL32.dll: API Node	
0x004dfb73:	popl %esi
0x004dfb74:	popl %ebp
0x004dfb75:	ret

0x004d1e47:	popl %ecx
0x004d1e48:	andl -4(%ebp), $0x0<UINT8>
0x004d1e4c:	pushl 0x68(%esi)
0x004d1e4f:	call InterlockedIncrement@KERNEL32.dll
InterlockedIncrement@KERNEL32.dll: API Node	
0x004d1e55:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004d1e5c:	call 0x004d1e9f
0x004d1e9f:	pushl $0xd<UINT8>
0x004d1ea1:	call 0x004dfa69
0x004dfa69:	movl %edi, %edi
0x004dfa6b:	pushl %ebp
0x004dfa6c:	movl %ebp, %esp
0x004dfa6e:	movl %eax, 0x8(%ebp)
0x004dfa71:	pushl 0x595de8(,%eax,8)
0x004dfa78:	call LeaveCriticalSection@KERNEL32.dll
LeaveCriticalSection@KERNEL32.dll: API Node	
0x004dfa7e:	popl %ebp
0x004dfa7f:	ret

0x004d1ea6:	popl %ecx
0x004d1ea7:	ret

0x004d1e61:	pushl $0xc<UINT8>
0x004d1e63:	call 0x004dfb43
0x004d1e68:	popl %ecx
0x004d1e69:	movl -4(%ebp), %edi
0x004d1e6c:	movl %eax, 0xc(%ebp)
0x004d1e6f:	movl 0x6c(%esi), %eax
0x004d1e72:	testl %eax, %eax
0x004d1e74:	jne 8
0x004d1e76:	movl %eax, 0x595768
0x004d1e7b:	movl 0x6c(%esi), %eax
0x004d1e7e:	pushl 0x6c(%esi)
0x004d1e81:	call 0x004d59b6
0x004d59b6:	movl %edi, %edi
0x004d59b8:	pushl %ebp
0x004d59b9:	movl %ebp, %esp
0x004d59bb:	pushl %ebx
0x004d59bc:	pushl %esi
0x004d59bd:	movl %esi, 0x52a16c
0x004d59c3:	pushl %edi
0x004d59c4:	movl %edi, 0x8(%ebp)
0x004d59c7:	pushl %edi
0x004d59c8:	call InterlockedIncrement@KERNEL32.dll
0x004d59ca:	movl %eax, 0xb0(%edi)
0x004d59d0:	testl %eax, %eax
0x004d59d2:	je 0x004d59d7
0x004d59d7:	movl %eax, 0xb8(%edi)
0x004d59dd:	testl %eax, %eax
0x004d59df:	je 0x004d59e4
0x004d59e4:	movl %eax, 0xb4(%edi)
0x004d59ea:	testl %eax, %eax
0x004d59ec:	je 0x004d59f1
0x004d59f1:	movl %eax, 0xc0(%edi)
0x004d59f7:	testl %eax, %eax
0x004d59f9:	je 0x004d59fe
0x004d59fe:	leal %ebx, 0x50(%edi)
0x004d5a01:	movl 0x8(%ebp), $0x6<UINT32>
0x004d5a08:	cmpl -8(%ebx), $0x595688<UINT32>
0x004d5a0f:	je 0x004d5a1a
0x004d5a11:	movl %eax, (%ebx)
0x004d5a13:	testl %eax, %eax
0x004d5a15:	je 0x004d5a1a
0x004d5a1a:	cmpl -4(%ebx), $0x0<UINT8>
0x004d5a1e:	je 0x004d5a2a
0x004d5a2a:	addl %ebx, $0x10<UINT8>
0x004d5a2d:	decl 0x8(%ebp)
0x004d5a30:	jne 0x004d5a08
0x004d5a32:	movl %eax, 0xd4(%edi)
0x004d5a38:	addl %eax, $0xb4<UINT32>
0x004d5a3d:	pushl %eax
0x004d5a3e:	call InterlockedIncrement@KERNEL32.dll
0x004d5a40:	popl %edi
0x004d5a41:	popl %esi
0x004d5a42:	popl %ebx
0x004d5a43:	popl %ebp
0x004d5a44:	ret

0x004d1e86:	popl %ecx
0x004d1e87:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004d1e8e:	call 0x004d1ea8
0x004d1ea8:	pushl $0xc<UINT8>
0x004d1eaa:	call 0x004dfa69
0x004d1eaf:	popl %ecx
0x004d1eb0:	ret

0x004d1e93:	call 0x004ceae5
0x004d1e98:	ret

0x004d21e3:	popl %ecx
0x004d21e4:	popl %ecx
0x004d21e5:	call GetCurrentThreadId@KERNEL32.dll
0x004d21eb:	orl 0x4(%esi), $0xffffffff<UINT8>
0x004d21ef:	movl (%esi), %eax
0x004d21f1:	xorl %eax, %eax
0x004d21f3:	incl %eax
0x004d21f4:	jmp 0x004d21fd
0x004d21fd:	popl %edi
0x004d21fe:	popl %esi
0x004d21ff:	ret

0x004cb513:	testl %eax, %eax
0x004cb515:	jne 0x004cb51f
0x004cb51f:	call 0x004d1c17
0x004d1c17:	movl %edi, %edi
0x004d1c19:	pushl %esi
0x004d1c1a:	movl %eax, $0x56f92c<UINT32>
0x004d1c1f:	movl %esi, $0x56f92c<UINT32>
0x004d1c24:	pushl %edi
0x004d1c25:	movl %edi, %eax
0x004d1c27:	cmpl %eax, %esi
0x004d1c29:	jae 0x004d1c3a
0x004d1c3a:	popl %edi
0x004d1c3b:	popl %esi
0x004d1c3c:	ret

0x004cb524:	movl -4(%ebp), %ebx
0x004cb527:	call 0x004d19c3
0x004d19c3:	pushl $0x54<UINT8>
0x004d19c5:	pushl $0x575f70<UINT32>
0x004d19ca:	call 0x004ceaa0
0x004d19cf:	xorl %edi, %edi
0x004d19d1:	movl -4(%ebp), %edi
0x004d19d4:	leal %eax, -100(%ebp)
0x004d19d7:	pushl %eax
0x004d19d8:	call GetStartupInfoA@KERNEL32.dll
GetStartupInfoA@KERNEL32.dll: API Node	
0x004d19de:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004d19e5:	pushl $0x40<UINT8>
0x004d19e7:	pushl $0x20<UINT8>
0x004d19e9:	popl %esi
0x004d19ea:	pushl %esi
0x004d19eb:	call 0x004d8d77
0x004d19f0:	popl %ecx
0x004d19f1:	popl %ecx
0x004d19f2:	cmpl %eax, %edi
0x004d19f4:	je 532
0x004d19fa:	movl 0x59e700, %eax
0x004d19ff:	movl 0x59e6ec, %esi
0x004d1a05:	leal %ecx, 0x800(%eax)
0x004d1a0b:	jmp 0x004d1a3d
0x004d1a3d:	cmpl %eax, %ecx
0x004d1a3f:	jb 0x004d1a0d
0x004d1a0d:	movb 0x4(%eax), $0x0<UINT8>
0x004d1a11:	orl (%eax), $0xffffffff<UINT8>
0x004d1a14:	movb 0x5(%eax), $0xa<UINT8>
0x004d1a18:	movl 0x8(%eax), %edi
0x004d1a1b:	movb 0x24(%eax), $0x0<UINT8>
0x004d1a1f:	movb 0x25(%eax), $0xa<UINT8>
0x004d1a23:	movb 0x26(%eax), $0xa<UINT8>
0x004d1a27:	movl 0x38(%eax), %edi
0x004d1a2a:	movb 0x34(%eax), $0x0<UINT8>
0x004d1a2e:	addl %eax, $0x40<UINT8>
0x004d1a31:	movl %ecx, 0x59e700
0x004d1a37:	addl %ecx, $0x800<UINT32>
0x004d1a41:	cmpw -50(%ebp), %di
0x004d1a45:	je 266
0x004d1a4b:	movl %eax, -48(%ebp)
0x004d1a4e:	cmpl %eax, %edi
0x004d1a50:	je 255
0x004d1a56:	movl %edi, (%eax)
0x004d1a58:	leal %ebx, 0x4(%eax)
0x004d1a5b:	leal %eax, (%ebx,%edi)
0x004d1a5e:	movl -28(%ebp), %eax
0x004d1a61:	movl %esi, $0x800<UINT32>
0x004d1a66:	cmpl %edi, %esi
0x004d1a68:	jl 0x004d1a6c
0x004d1a6c:	movl -32(%ebp), $0x1<UINT32>
0x004d1a73:	jmp 0x004d1ad0
0x004d1ad0:	cmpl 0x59e6ec, %edi
0x004d1ad6:	jl -99
0x004d1ad8:	jmp 0x004d1ae0
0x004d1ae0:	andl -32(%ebp), $0x0<UINT8>
0x004d1ae4:	testl %edi, %edi
0x004d1ae6:	jle 0x004d1b55
0x004d1b55:	xorl %ebx, %ebx
0x004d1b57:	movl %esi, %ebx
0x004d1b59:	shll %esi, $0x6<UINT8>
0x004d1b5c:	addl %esi, 0x59e700
0x004d1b62:	movl %eax, (%esi)
0x004d1b64:	cmpl %eax, $0xffffffff<UINT8>
0x004d1b67:	je 0x004d1b74
0x004d1b74:	movb 0x4(%esi), $0xffffff81<UINT8>
0x004d1b78:	testl %ebx, %ebx
0x004d1b7a:	jne 0x004d1b81
0x004d1b7c:	pushl $0xfffffff6<UINT8>
0x004d1b7e:	popl %eax
0x004d1b7f:	jmp 0x004d1b8b
0x004d1b8b:	pushl %eax
0x004d1b8c:	call GetStdHandle@KERNEL32.dll
GetStdHandle@KERNEL32.dll: API Node	
0x004d1b92:	movl %edi, %eax
0x004d1b94:	cmpl %edi, $0xffffffff<UINT8>
0x004d1b97:	je 67
0x004d1b99:	testl %edi, %edi
0x004d1b9b:	je 63
0x004d1b9d:	pushl %edi
0x004d1b9e:	call GetFileType@KERNEL32.dll
GetFileType@KERNEL32.dll: API Node	
0x004d1ba4:	testl %eax, %eax
0x004d1ba6:	je 52
0x004d1ba8:	movl (%esi), %edi
0x004d1baa:	andl %eax, $0xff<UINT32>
0x004d1baf:	cmpl %eax, $0x2<UINT8>
0x004d1bb2:	jne 6
0x004d1bb4:	orb 0x4(%esi), $0x40<UINT8>
0x004d1bb8:	jmp 0x004d1bc3
0x004d1bc3:	pushl $0xfa0<UINT32>
0x004d1bc8:	leal %eax, 0xc(%esi)
0x004d1bcb:	pushl %eax
0x004d1bcc:	call 0x004e08a1
0x004d1bd1:	popl %ecx
0x004d1bd2:	popl %ecx
0x004d1bd3:	testl %eax, %eax
0x004d1bd5:	je 55
0x004d1bd7:	incl 0x8(%esi)
0x004d1bda:	jmp 0x004d1be6
0x004d1be6:	incl %ebx
0x004d1be7:	cmpl %ebx, $0x3<UINT8>
0x004d1bea:	jl 0x004d1b57
0x004d1b81:	movl %eax, %ebx
0x004d1b83:	decl %eax
0x004d1b84:	negl %eax
0x004d1b86:	sbbl %eax, %eax
0x004d1b88:	addl %eax, $0xfffffff5<UINT8>
0x004d1bf0:	pushl 0x59e6ec
0x004d1bf6:	call SetHandleCount@KERNEL32.dll
SetHandleCount@KERNEL32.dll: API Node	
0x004d1bfc:	xorl %eax, %eax
0x004d1bfe:	jmp 0x004d1c11
0x004d1c11:	call 0x004ceae5
0x004d1c16:	ret

0x004cb52c:	testl %eax, %eax
0x004cb52e:	jnl 0x004cb538
0x004cb538:	call 0x004d19bd
0x004d19bd:	jmp GetCommandLineW@KERNEL32.dll
GetCommandLineW@KERNEL32.dll: API Node	
0x004cb53d:	movl 0x59e814, %eax
0x004cb542:	call 0x004d1966
0x004d1966:	movl %edi, %edi
0x004d1968:	pushl %esi
0x004d1969:	call GetEnvironmentStringsW@KERNEL32.dll
GetEnvironmentStringsW@KERNEL32.dll: API Node	
0x004d196f:	movl %esi, %eax
0x004d1971:	xorl %ecx, %ecx
0x004d1973:	cmpl %esi, %ecx
0x004d1975:	jne 0x004d197b
0x004d197b:	cmpw (%esi), %cx
0x004d197e:	je 14
0x004d1980:	incl %eax
0x004d1981:	incl %eax
0x004d1982:	cmpw (%eax), %cx
0x004d1985:	jne 0x004d1980
0x004d1987:	incl %eax
0x004d1988:	incl %eax
0x004d1989:	cmpw (%eax), %cx
0x004d198c:	jne 0x004d1980
0x004d198e:	subl %eax, %esi
0x004d1990:	incl %eax
0x004d1991:	pushl %ebx
0x004d1992:	incl %eax
0x004d1993:	movl %ebx, %eax
0x004d1995:	pushl %edi
0x004d1996:	pushl %ebx
0x004d1997:	call 0x004d8d32
0x004d8d32:	movl %edi, %edi
0x004d8d34:	pushl %ebp
0x004d8d35:	movl %ebp, %esp
0x004d8d37:	pushl %esi
0x004d8d38:	pushl %edi
0x004d8d39:	xorl %esi, %esi
0x004d8d3b:	pushl 0x8(%ebp)
0x004d8d3e:	call 0x004cebd4
0x004cebd4:	movl %edi, %edi
0x004cebd6:	pushl %ebp
0x004cebd7:	movl %ebp, %esp
0x004cebd9:	pushl %esi
0x004cebda:	movl %esi, 0x8(%ebp)
0x004cebdd:	cmpl %esi, $0xffffffe0<UINT8>
0x004cebe0:	ja 161
0x004cebe6:	pushl %ebx
0x004cebe7:	pushl %edi
0x004cebe8:	movl %edi, 0x52a1e0
0x004cebee:	cmpl 0x59b494, $0x0<UINT8>
0x004cebf5:	jne 0x004cec0f
0x004cec0f:	movl %eax, 0x59e6e8
0x004cec14:	cmpl %eax, $0x1<UINT8>
0x004cec17:	jne 14
0x004cec19:	testl %esi, %esi
0x004cec1b:	je 4
0x004cec1d:	movl %eax, %esi
0x004cec1f:	jmp 0x004cec24
0x004cec24:	pushl %eax
0x004cec25:	jmp 0x004cec43
0x004cec43:	pushl $0x0<UINT8>
0x004cec45:	pushl 0x59b494
0x004cec4b:	call HeapAlloc@KERNEL32.dll
0x004cec4d:	movl %ebx, %eax
0x004cec4f:	testl %ebx, %ebx
0x004cec51:	jne 0x004cec81
0x004cec81:	popl %edi
0x004cec82:	movl %eax, %ebx
0x004cec84:	popl %ebx
0x004cec85:	jmp 0x004cec9b
0x004cec9b:	popl %esi
0x004cec9c:	popl %ebp
0x004cec9d:	ret

0x004d8d43:	movl %edi, %eax
0x004d8d45:	popl %ecx
0x004d8d46:	testl %edi, %edi
0x004d8d48:	jne 0x004d8d71
0x004d8d71:	movl %eax, %edi
0x004d8d73:	popl %edi
0x004d8d74:	popl %esi
0x004d8d75:	popl %ebp
0x004d8d76:	ret

0x004d199c:	movl %edi, %eax
0x004d199e:	popl %ecx
0x004d199f:	testl %edi, %edi
0x004d19a1:	jne 0x004d19b0
0x004d19b0:	pushl %ebx
0x004d19b1:	pushl %esi
0x004d19b2:	pushl %edi
0x004d19b3:	call 0x004cb7d0
0x004cb7d0:	pushl %ebp
0x004cb7d1:	movl %ebp, %esp
0x004cb7d3:	pushl %edi
0x004cb7d4:	pushl %esi
0x004cb7d5:	movl %esi, 0xc(%ebp)
0x004cb7d8:	movl %ecx, 0x10(%ebp)
0x004cb7db:	movl %edi, 0x8(%ebp)
0x004cb7de:	movl %eax, %ecx
0x004cb7e0:	movl %edx, %ecx
0x004cb7e2:	addl %eax, %esi
0x004cb7e4:	cmpl %edi, %esi
0x004cb7e6:	jbe 0x004cb7f0
0x004cb7f0:	cmpl %ecx, $0x100<UINT32>
0x004cb7f6:	jb 0x004cb817
0x004cb7f8:	cmpl 0x59e6e4, $0x0<UINT8>
0x004cb7ff:	je 0x004cb817
0x004cb817:	testl %edi, $0x3<UINT32>
0x004cb81d:	jne 21
0x004cb81f:	shrl %ecx, $0x2<UINT8>
0x004cb822:	andl %edx, $0x3<UINT8>
0x004cb825:	cmpl %ecx, $0x8<UINT8>
0x004cb828:	jb 0x004cb854
0x004cb82a:	rep movsl %es:(%edi), %ds:(%esi)
0x004cb82c:	jmp 0x004cb954
0x004cb954:	movl %eax, 0x8(%ebp)
0x004cb957:	popl %esi
0x004cb958:	popl %edi
0x004cb959:	leave
0x004cb95a:	ret

0x004d19b8:	addl %esp, $0xc<UINT8>
0x004d19bb:	jmp 0x004d19a3
0x004d19a3:	pushl %esi
0x004d19a4:	call FreeEnvironmentStringsW@KERNEL32.dll
FreeEnvironmentStringsW@KERNEL32.dll: API Node	
0x004d19aa:	movl %eax, %edi
0x004d19ac:	popl %edi
0x004d19ad:	popl %ebx
0x004d19ae:	popl %esi
0x004d19af:	ret

0x004cb547:	movl 0x59af10, %eax
0x004cb54c:	call 0x004d18b8
0x004d18b8:	movl %edi, %edi
0x004d18ba:	pushl %ebp
0x004d18bb:	movl %ebp, %esp
0x004d18bd:	pushl %ecx
0x004d18be:	pushl %ecx
0x004d18bf:	pushl %ebx
0x004d18c0:	pushl %esi
0x004d18c1:	pushl %edi
0x004d18c2:	pushl $0x104<UINT32>
0x004d18c7:	movl %esi, $0x59b278<UINT32>
0x004d18cc:	pushl %esi
0x004d18cd:	xorl %eax, %eax
0x004d18cf:	xorl %ebx, %ebx
0x004d18d1:	pushl %ebx
0x004d18d2:	movw 0x59b480, %ax
0x004d18d8:	call GetModuleFileNameW@KERNEL32.dll
GetModuleFileNameW@KERNEL32.dll: API Node	
0x004d18de:	movl %eax, 0x59e814
0x004d18e3:	movl 0x59af44, %esi
0x004d18e9:	cmpl %eax, %ebx
0x004d18eb:	je 7
0x004d18ed:	movl %edi, %eax
0x004d18ef:	cmpw (%eax), %bx
0x004d18f2:	jne 0x004d18f6
0x004d18f6:	leal %eax, -4(%ebp)
0x004d18f9:	pushl %eax
0x004d18fa:	pushl %ebx
0x004d18fb:	leal %ebx, -8(%ebp)
0x004d18fe:	xorl %ecx, %ecx
0x004d1900:	movl %eax, %edi
0x004d1902:	call 0x004d1767
0x004d1767:	movl %edi, %edi
0x004d1769:	pushl %ebp
0x004d176a:	movl %ebp, %esp
0x004d176c:	pushl %ecx
0x004d176d:	pushl %esi
0x004d176e:	xorl %edx, %edx
0x004d1770:	pushl %edi
0x004d1771:	movl %edi, 0xc(%ebp)
0x004d1774:	movl (%ebx), %edx
0x004d1776:	movl %esi, %ecx
0x004d1778:	movl (%edi), $0x1<UINT32>
0x004d177e:	cmpl 0x8(%ebp), %edx
0x004d1781:	je 0x004d178c
0x004d178c:	cmpw (%eax), $0x22<UINT8>
0x004d1790:	jne 0x004d17a5
0x004d1792:	movl %edi, 0xc(%ebp)
0x004d1795:	xorl %ecx, %ecx
0x004d1797:	testl %edx, %edx
0x004d1799:	sete %cl
0x004d179c:	pushl $0x22<UINT8>
0x004d179e:	incl %eax
0x004d179f:	incl %eax
0x004d17a0:	movl %edx, %ecx
0x004d17a2:	popl %ecx
0x004d17a3:	jmp 0x004d17bd
0x004d17bd:	testl %edx, %edx
0x004d17bf:	jne 0x004d178c
0x004d17a5:	incl (%ebx)
0x004d17a7:	testl %esi, %esi
0x004d17a9:	je 0x004d17b3
0x004d17b3:	movzwl %ecx, (%eax)
0x004d17b6:	incl %eax
0x004d17b7:	incl %eax
0x004d17b8:	testw %cx, %cx
0x004d17bb:	je 0x004d17f9
0x004d17c1:	cmpw %cx, $0x20<UINT8>
0x004d17c5:	je 6
0x004d17c7:	cmpw %cx, $0x9<UINT8>
0x004d17cb:	jne 0x004d178c
0x004d17f9:	decl %eax
0x004d17fa:	decl %eax
0x004d17fb:	jmp 0x004d17d7
0x004d17d7:	andl -4(%ebp), $0x0<UINT8>
0x004d17db:	xorl %edx, %edx
0x004d17dd:	cmpw (%eax), %dx
0x004d17e0:	je 0x004d18a9
0x004d18a9:	movl %eax, 0x8(%ebp)
0x004d18ac:	cmpl %eax, %edx
0x004d18ae:	je 0x004d18b2
0x004d18b2:	incl (%edi)
0x004d18b4:	popl %edi
0x004d18b5:	popl %esi
0x004d18b6:	leave
0x004d18b7:	ret

0x004d1907:	movl %ebx, -4(%ebp)
0x004d190a:	popl %ecx
0x004d190b:	popl %ecx
0x004d190c:	cmpl %ebx, $0x3fffffff<UINT32>
0x004d1912:	jae 74
0x004d1914:	movl %ecx, -8(%ebp)
0x004d1917:	cmpl %ecx, $0x7fffffff<UINT32>
0x004d191d:	jae 63
0x004d191f:	leal %eax, (%ecx,%ebx,2)
0x004d1922:	addl %eax, %eax
0x004d1924:	addl %ecx, %ecx
0x004d1926:	cmpl %eax, %ecx
0x004d1928:	jb 52
0x004d192a:	pushl %eax
0x004d192b:	call 0x004d8d32
0x004d1930:	movl %esi, %eax
0x004d1932:	popl %ecx
0x004d1933:	testl %esi, %esi
0x004d1935:	je 39
0x004d1937:	leal %eax, -4(%ebp)
0x004d193a:	pushl %eax
0x004d193b:	leal %ecx, (%esi,%ebx,4)
0x004d193e:	pushl %esi
0x004d193f:	leal %ebx, -8(%ebp)
0x004d1942:	movl %eax, %edi
0x004d1944:	call 0x004d1767
0x004d1783:	movl %ecx, 0x8(%ebp)
0x004d1786:	addl 0x8(%ebp), $0x4<UINT8>
0x004d178a:	movl (%ecx), %esi
0x004d17ab:	movw %cx, (%eax)
0x004d17ae:	movw (%esi), %cx
0x004d17b1:	incl %esi
0x004d17b2:	incl %esi
0x004d18b0:	movl (%eax), %edx
0x004d1949:	movl %eax, -4(%ebp)
0x004d194c:	decl %eax
0x004d194d:	popl %ecx
0x004d194e:	movl 0x59af24, %eax
0x004d1953:	popl %ecx
0x004d1954:	movl 0x59af2c, %esi
0x004d195a:	xorl %eax, %eax
0x004d195c:	jmp 0x004d1961
0x004d1961:	popl %edi
0x004d1962:	popl %esi
0x004d1963:	popl %ebx
0x004d1964:	leave
0x004d1965:	ret

0x004cb551:	testl %eax, %eax
0x004cb553:	jnl 0x004cb55d
0x004cb55d:	call 0x004d1689
0x004d1689:	movl %edi, %edi
0x004d168b:	pushl %esi
0x004d168c:	movl %esi, 0x59af10
0x004d1692:	pushl %edi
0x004d1693:	xorl %edi, %edi
0x004d1695:	testl %esi, %esi
0x004d1697:	jne 0x004d16b3
0x004d16b3:	movzwl %eax, (%esi)
0x004d16b6:	testw %ax, %ax
0x004d16b9:	jne 0x004d16a1
0x004d16a1:	cmpw %ax, $0x3d<UINT8>
0x004d16a5:	je 0x004d16a8
0x004d16a8:	pushl %esi
0x004d16a9:	call 0x004cbefb
0x004cbefb:	movl %edi, %edi
0x004cbefd:	pushl %ebp
0x004cbefe:	movl %ebp, %esp
0x004cbf00:	movl %eax, 0x8(%ebp)
0x004cbf03:	movw %cx, (%eax)
0x004cbf06:	incl %eax
0x004cbf07:	incl %eax
0x004cbf08:	testw %cx, %cx
0x004cbf0b:	jne 0x004cbf03
0x004cbf0d:	subl %eax, 0x8(%ebp)
0x004cbf10:	sarl %eax
0x004cbf12:	decl %eax
0x004cbf13:	popl %ebp
0x004cbf14:	ret

0x004d16ae:	popl %ecx
0x004d16af:	leal %esi, 0x2(%esi,%eax,2)
0x004d16a7:	incl %edi
0x004d16bb:	pushl %ebx
0x004d16bc:	pushl $0x4<UINT8>
0x004d16be:	incl %edi
0x004d16bf:	pushl %edi
0x004d16c0:	call 0x004d8d77
0x004d16c5:	movl %ebx, %eax
0x004d16c7:	popl %ecx
0x004d16c8:	popl %ecx
0x004d16c9:	movl 0x59af38, %ebx
0x004d16cf:	testl %ebx, %ebx
0x004d16d1:	jne 0x004d16d8
0x004d16d8:	movl %esi, 0x59af10
0x004d16de:	jmp 0x004d1724
0x004d1724:	cmpw (%esi), $0x0<UINT8>
0x004d1728:	jne 0x004d16e0
0x004d16e0:	pushl %esi
0x004d16e1:	call 0x004cbefb
0x004d16e6:	movl %edi, %eax
0x004d16e8:	incl %edi
0x004d16e9:	cmpw (%esi), $0x3d<UINT8>
0x004d16ed:	popl %ecx
0x004d16ee:	je 0x004d1721
0x004d1721:	leal %esi, (%esi,%edi,2)
0x004d16f0:	pushl $0x2<UINT8>
0x004d16f2:	pushl %edi
0x004d16f3:	call 0x004d8d77
0x004d16f8:	popl %ecx
0x004d16f9:	popl %ecx
0x004d16fa:	movl (%ebx), %eax
0x004d16fc:	testl %eax, %eax
0x004d16fe:	je 80
0x004d1700:	pushl %esi
0x004d1701:	pushl %edi
0x004d1702:	pushl %eax
0x004d1703:	call 0x004cc9ba
0x004cc9ba:	movl %edi, %edi
0x004cc9bc:	pushl %ebp
0x004cc9bd:	movl %ebp, %esp
0x004cc9bf:	movl %edx, 0x8(%ebp)
0x004cc9c2:	pushl %ebx
0x004cc9c3:	pushl %esi
0x004cc9c4:	pushl %edi
0x004cc9c5:	xorl %edi, %edi
0x004cc9c7:	cmpl %edx, %edi
0x004cc9c9:	je 7
0x004cc9cb:	movl %ebx, 0xc(%ebp)
0x004cc9ce:	cmpl %ebx, %edi
0x004cc9d0:	ja 0x004cc9f0
0x004cc9f0:	movl %esi, 0x10(%ebp)
0x004cc9f3:	cmpl %esi, %edi
0x004cc9f5:	jne 0x004cc9fe
0x004cc9fe:	movl %ecx, %edx
0x004cca00:	movzwl %eax, (%esi)
0x004cca03:	movw (%ecx), %ax
0x004cca06:	incl %ecx
0x004cca07:	incl %ecx
0x004cca08:	incl %esi
0x004cca09:	incl %esi
0x004cca0a:	cmpw %ax, %di
0x004cca0d:	je 0x004cca12
0x004cca0f:	decl %ebx
0x004cca10:	jne 0x004cca00
0x004cca12:	xorl %eax, %eax
0x004cca14:	cmpl %ebx, %edi
0x004cca16:	jne 0x004cc9eb
0x004cc9eb:	popl %edi
0x004cc9ec:	popl %esi
0x004cc9ed:	popl %ebx
0x004cc9ee:	popl %ebp
0x004cc9ef:	ret

0x004d1708:	addl %esp, $0xc<UINT8>
0x004d170b:	testl %eax, %eax
0x004d170d:	je 0x004d171e
0x004d171e:	addl %ebx, $0x4<UINT8>
0x004d172a:	pushl 0x59af10
0x004d1730:	call 0x004cec9e
0x004cec9e:	pushl $0xc<UINT8>
0x004ceca0:	pushl $0x575ed0<UINT32>
0x004ceca5:	call 0x004ceaa0
0x004cecaa:	movl %esi, 0x8(%ebp)
0x004cecad:	testl %esi, %esi
0x004cecaf:	je 117
0x004cecb1:	cmpl 0x59e6e8, $0x3<UINT8>
0x004cecb8:	jne 0x004cecfd
0x004cecfd:	pushl %esi
0x004cecfe:	pushl $0x0<UINT8>
0x004ced00:	pushl 0x59b494
0x004ced06:	call HeapFree@KERNEL32.dll
HeapFree@KERNEL32.dll: API Node	
0x004ced0c:	testl %eax, %eax
0x004ced0e:	jne 0x004ced26
0x004ced26:	call 0x004ceae5
0x004ced2b:	ret

0x004d1735:	andl 0x59af10, $0x0<UINT8>
0x004d173c:	andl (%ebx), $0x0<UINT8>
0x004d173f:	movl 0x59e800, $0x1<UINT32>
0x004d1749:	xorl %eax, %eax
0x004d174b:	popl %ecx
0x004d174c:	popl %ebx
0x004d174d:	popl %edi
0x004d174e:	popl %esi
0x004d174f:	ret

0x004cb562:	testl %eax, %eax
0x004cb564:	jnl 0x004cb56e
0x004cb56e:	pushl %ebx
0x004cb56f:	call 0x004d097d
0x004d097d:	movl %edi, %edi
0x004d097f:	pushl %ebp
0x004d0980:	movl %ebp, %esp
0x004d0982:	cmpl 0x546fb0, $0x0<UINT8>
0x004d0989:	je 25
0x004d098b:	pushl $0x546fb0<UINT32>
0x004d0990:	call 0x004dc8d0
0x004dc8d0:	movl %edi, %edi
0x004dc8d2:	pushl %ebp
0x004dc8d3:	movl %ebp, %esp
0x004dc8d5:	pushl $0xfffffffe<UINT8>
0x004dc8d7:	pushl $0x576208<UINT32>
0x004dc8dc:	pushl $0x4cdb30<UINT32>
0x004dc8e1:	movl %eax, %fs:0
0x004dc8e7:	pushl %eax
0x004dc8e8:	subl %esp, $0x8<UINT8>
0x004dc8eb:	pushl %ebx
0x004dc8ec:	pushl %esi
0x004dc8ed:	pushl %edi
0x004dc8ee:	movl %eax, 0x594ea0
0x004dc8f3:	xorl -8(%ebp), %eax
0x004dc8f6:	xorl %eax, %ebp
0x004dc8f8:	pushl %eax
0x004dc8f9:	leal %eax, -16(%ebp)
0x004dc8fc:	movl %fs:0, %eax
0x004dc902:	movl -24(%ebp), %esp
0x004dc905:	movl -4(%ebp), $0x0<UINT32>
0x004dc90c:	pushl $0x400000<UINT32>
0x004dc911:	call 0x004dc840
0x004dc840:	movl %edi, %edi
0x004dc842:	pushl %ebp
0x004dc843:	movl %ebp, %esp
0x004dc845:	movl %ecx, 0x8(%ebp)
0x004dc848:	movl %eax, $0x5a4d<UINT32>
0x004dc84d:	cmpw (%ecx), %ax
0x004dc850:	je 0x004dc856
0x004dc856:	movl %eax, 0x3c(%ecx)
0x004dc859:	addl %eax, %ecx
0x004dc85b:	cmpl (%eax), $0x4550<UINT32>
0x004dc861:	jne -17
0x004dc863:	xorl %edx, %edx
0x004dc865:	movl %ecx, $0x10b<UINT32>
0x004dc86a:	cmpw 0x18(%eax), %cx
0x004dc86e:	sete %dl
0x004dc871:	movl %eax, %edx
0x004dc873:	popl %ebp
0x004dc874:	ret

0x004dc916:	addl %esp, $0x4<UINT8>
0x004dc919:	testl %eax, %eax
0x004dc91b:	je 85
0x004dc91d:	movl %eax, 0x8(%ebp)
0x004dc920:	subl %eax, $0x400000<UINT32>
0x004dc925:	pushl %eax
0x004dc926:	pushl $0x400000<UINT32>
0x004dc92b:	call 0x004dc880
0x004dc880:	movl %edi, %edi
0x004dc882:	pushl %ebp
0x004dc883:	movl %ebp, %esp
0x004dc885:	movl %eax, 0x8(%ebp)
0x004dc888:	movl %ecx, 0x3c(%eax)
0x004dc88b:	addl %ecx, %eax
0x004dc88d:	movzwl %eax, 0x14(%ecx)
0x004dc891:	pushl %ebx
0x004dc892:	pushl %esi
0x004dc893:	movzwl %esi, 0x6(%ecx)
0x004dc897:	xorl %edx, %edx
0x004dc899:	pushl %edi
0x004dc89a:	leal %eax, 0x18(%eax,%ecx)
0x004dc89e:	testl %esi, %esi
0x004dc8a0:	jbe 27
0x004dc8a2:	movl %edi, 0xc(%ebp)
0x004dc8a5:	movl %ecx, 0xc(%eax)
0x004dc8a8:	cmpl %edi, %ecx
0x004dc8aa:	jb 9
0x004dc8ac:	movl %ebx, 0x8(%eax)
0x004dc8af:	addl %ebx, %ecx
0x004dc8b1:	cmpl %edi, %ebx
0x004dc8b3:	jb 0x004dc8bf
0x004dc8bf:	popl %edi
0x004dc8c0:	popl %esi
0x004dc8c1:	popl %ebx
0x004dc8c2:	popl %ebp
0x004dc8c3:	ret

0x004dc930:	addl %esp, $0x8<UINT8>
0x004dc933:	testl %eax, %eax
0x004dc935:	je 59
0x004dc937:	movl %eax, 0x24(%eax)
0x004dc93a:	shrl %eax, $0x1f<UINT8>
0x004dc93d:	notl %eax
0x004dc93f:	andl %eax, $0x1<UINT8>
0x004dc942:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004dc949:	movl %ecx, -16(%ebp)
0x004dc94c:	movl %fs:0, %ecx
0x004dc953:	popl %ecx
0x004dc954:	popl %edi
0x004dc955:	popl %esi
0x004dc956:	popl %ebx
0x004dc957:	movl %esp, %ebp
0x004dc959:	popl %ebp
0x004dc95a:	ret

0x004d0995:	popl %ecx
0x004d0996:	testl %eax, %eax
0x004d0998:	je 0x004d09a4
0x004d09a4:	call 0x004dc783
0x004dc783:	movl %edi, %edi
0x004dc785:	pushl %esi
0x004dc786:	pushl %edi
0x004dc787:	xorl %edi, %edi
0x004dc789:	leal %esi, 0x595d70(%edi)
0x004dc78f:	pushl (%esi)
0x004dc791:	call 0x004d1c63
0x004d1c85:	pushl %eax
0x004d1c86:	pushl 0x59514c
0x004d1c8c:	call TlsGetValue@KERNEL32.dll
0x004d1c8e:	call FlsGetValue@KERNEL32.DLL
0x004d1c90:	testl %eax, %eax
0x004d1c92:	je 8
0x004d1c94:	movl %eax, 0x1f8(%eax)
0x004d1c9a:	jmp 0x004d1cc3
0x004dc796:	addl %edi, $0x4<UINT8>
0x004dc799:	popl %ecx
0x004dc79a:	movl (%esi), %eax
0x004dc79c:	cmpl %edi, $0x28<UINT8>
0x004dc79f:	jb 0x004dc789
0x004dc7a1:	popl %edi
0x004dc7a2:	popl %esi
0x004dc7a3:	ret

0x004d09a9:	pushl $0x52a7e8<UINT32>
0x004d09ae:	pushl $0x52a7cc<UINT32>
0x004d09b3:	call 0x004d0959
0x004d0959:	movl %edi, %edi
0x004d095b:	pushl %ebp
0x004d095c:	movl %ebp, %esp
0x004d095e:	pushl %esi
0x004d095f:	movl %esi, 0x8(%ebp)
0x004d0962:	xorl %eax, %eax
0x004d0964:	jmp 0x004d0975
0x004d0975:	cmpl %esi, 0xc(%ebp)
0x004d0978:	jb 0x004d0966
0x004d0966:	testl %eax, %eax
0x004d0968:	jne 16
0x004d096a:	movl %ecx, (%esi)
0x004d096c:	testl %ecx, %ecx
0x004d096e:	je 0x004d0972
0x004d0972:	addl %esi, $0x4<UINT8>
0x004d0970:	call 0x004d12f1
0x004ccf12:	movl %edi, %edi
0x004ccf14:	pushl %esi
0x004ccf15:	pushl $0x4<UINT8>
0x004ccf17:	pushl $0x20<UINT8>
0x004ccf19:	call 0x004d8d77
0x004ccf1e:	movl %esi, %eax
0x004ccf20:	pushl %esi
0x004ccf21:	call 0x004d1c63
0x004ccf26:	addl %esp, $0xc<UINT8>
0x004ccf29:	movl 0x59e808, %eax
0x004ccf2e:	movl 0x59e804, %eax
0x004ccf33:	testl %esi, %esi
0x004ccf35:	jne 0x004ccf3c
0x004ccf3c:	andl (%esi), $0x0<UINT8>
0x004ccf3f:	xorl %eax, %eax
0x004ccf41:	popl %esi
0x004ccf42:	ret

0x004d2564:	call 0x004d2502
0x004d2502:	movl %edi, %edi
0x004d2504:	pushl %ebp
0x004d2505:	movl %ebp, %esp
0x004d2507:	subl %esp, $0x18<UINT8>
0x004d250a:	xorl %eax, %eax
0x004d250c:	pushl %ebx
0x004d250d:	movl -4(%ebp), %eax
0x004d2510:	movl -12(%ebp), %eax
0x004d2513:	movl -8(%ebp), %eax
0x004d2516:	pushl %ebx
0x004d2517:	pushfl
0x004d2518:	popl %eax
0x004d2519:	movl %ecx, %eax
0x004d251b:	xorl %eax, $0x200000<UINT32>
0x004d2520:	pushl %eax
0x004d2521:	popfl
0x004d2522:	pushfl
0x004d2523:	popl %edx
0x004d2524:	subl %edx, %ecx
0x004d2526:	je 0x004d2547
0x004d2547:	popl %ebx
0x004d2548:	testl -4(%ebp), $0x4000000<UINT32>
0x004d254f:	je 0x004d255f
0x004d255f:	xorl %eax, %eax
0x004d2561:	popl %ebx
0x004d2562:	leave
0x004d2563:	ret

0x004d2569:	movl 0x59e6e4, %eax
0x004d256e:	xorl %eax, %eax
0x004d2570:	ret

0x004d584f:	cmpl 0x59e80c, $0x0<UINT8>
0x004d5856:	jne 18
0x004d5858:	pushl $0xfffffffd<UINT8>
0x004d585a:	call 0x004d56b5
0x004d56b5:	pushl $0x14<UINT8>
0x004d56b7:	pushl $0x576080<UINT32>
0x004d56bc:	call 0x004ceaa0
0x004d56c1:	orl -32(%ebp), $0xffffffff<UINT8>
0x004d56c5:	call 0x004d1f2a
0x004d1f2a:	movl %edi, %edi
0x004d1f2c:	pushl %esi
0x004d1f2d:	call 0x004d1eb1
0x004d1eb1:	movl %edi, %edi
0x004d1eb3:	pushl %esi
0x004d1eb4:	pushl %edi
0x004d1eb5:	call GetLastError@KERNEL32.dll
GetLastError@KERNEL32.dll: API Node	
0x004d1ebb:	pushl 0x595148
0x004d1ec1:	movl %edi, %eax
0x004d1ec3:	call 0x004d1d59
0x004d1d59:	movl %edi, %edi
0x004d1d5b:	pushl %esi
0x004d1d5c:	pushl 0x59514c
0x004d1d62:	call TlsGetValue@KERNEL32.dll
0x004d1d68:	movl %esi, %eax
0x004d1d6a:	testl %esi, %esi
0x004d1d6c:	jne 0x004d1d89
0x004d1d89:	movl %eax, %esi
0x004d1d8b:	popl %esi
0x004d1d8c:	ret

0x004d1ec8:	call FlsGetValue@KERNEL32.DLL
0x004d1eca:	movl %esi, %eax
0x004d1ecc:	testl %esi, %esi
0x004d1ece:	jne 0x004d1f1e
0x004d1f1e:	pushl %edi
0x004d1f1f:	call SetLastError@KERNEL32.dll
SetLastError@KERNEL32.dll: API Node	
0x004d1f25:	popl %edi
0x004d1f26:	movl %eax, %esi
0x004d1f28:	popl %esi
0x004d1f29:	ret

0x004d1f32:	movl %esi, %eax
0x004d1f34:	testl %esi, %esi
0x004d1f36:	jne 0x004d1f40
0x004d1f40:	movl %eax, %esi
0x004d1f42:	popl %esi
0x004d1f43:	ret

0x004d56ca:	movl %edi, %eax
0x004d56cc:	movl -36(%ebp), %edi
0x004d56cf:	call 0x004d53b0
0x004d53b0:	pushl $0xc<UINT8>
0x004d53b2:	pushl $0x576060<UINT32>
0x004d53b7:	call 0x004ceaa0
0x004d53bc:	call 0x004d1f2a
0x004d53c1:	movl %edi, %eax
0x004d53c3:	movl %eax, 0x595684
0x004d53c8:	testl 0x70(%edi), %eax
0x004d53cb:	je 0x004d53ea
0x004d53ea:	pushl $0xd<UINT8>
0x004d53ec:	call 0x004dfb43
0x004d53f1:	popl %ecx
0x004d53f2:	andl -4(%ebp), $0x0<UINT8>
0x004d53f6:	movl %esi, 0x68(%edi)
0x004d53f9:	movl -28(%ebp), %esi
0x004d53fc:	cmpl %esi, 0x595588
0x004d5402:	je 0x004d543a
0x004d543a:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004d5441:	call 0x004d544b
0x004d544b:	pushl $0xd<UINT8>
0x004d544d:	call 0x004dfa69
0x004d5452:	popl %ecx
0x004d5453:	ret

0x004d5446:	jmp 0x004d53d6
0x004d53d6:	testl %esi, %esi
0x004d53d8:	jne 0x004d53e2
0x004d53e2:	movl %eax, %esi
0x004d53e4:	call 0x004ceae5
0x004d53e9:	ret

0x004d56d4:	movl %ebx, 0x68(%edi)
0x004d56d7:	movl %esi, 0x8(%ebp)
0x004d56da:	call 0x004d5454
0x004d5454:	movl %edi, %edi
0x004d5456:	pushl %ebp
0x004d5457:	movl %ebp, %esp
0x004d5459:	subl %esp, $0x10<UINT8>
0x004d545c:	pushl %ebx
0x004d545d:	xorl %ebx, %ebx
0x004d545f:	pushl %ebx
0x004d5460:	leal %ecx, -16(%ebp)
0x004d5463:	call 0x004cc320
0x004cc320:	movl %edi, %edi
0x004cc322:	pushl %ebp
0x004cc323:	movl %ebp, %esp
0x004cc325:	movl %eax, 0x8(%ebp)
0x004cc328:	pushl %esi
0x004cc329:	movl %esi, %ecx
0x004cc32b:	movb 0xc(%esi), $0x0<UINT8>
0x004cc32f:	testl %eax, %eax
0x004cc331:	jne 99
0x004cc333:	call 0x004d1f2a
0x004cc338:	movl 0x8(%esi), %eax
0x004cc33b:	movl %ecx, 0x6c(%eax)
0x004cc33e:	movl (%esi), %ecx
0x004cc340:	movl %ecx, 0x68(%eax)
0x004cc343:	movl 0x4(%esi), %ecx
0x004cc346:	movl %ecx, (%esi)
0x004cc348:	cmpl %ecx, 0x595768
0x004cc34e:	je 0x004cc362
0x004cc362:	movl %eax, 0x4(%esi)
0x004cc365:	cmpl %eax, 0x595588
0x004cc36b:	je 0x004cc383
0x004cc383:	movl %eax, 0x8(%esi)
0x004cc386:	testb 0x70(%eax), $0x2<UINT8>
0x004cc38a:	jne 20
0x004cc38c:	orl 0x70(%eax), $0x2<UINT8>
0x004cc390:	movb 0xc(%esi), $0x1<UINT8>
0x004cc394:	jmp 0x004cc3a0
0x004cc3a0:	movl %eax, %esi
0x004cc3a2:	popl %esi
0x004cc3a3:	popl %ebp
0x004cc3a4:	ret $0x4<UINT16>

0x004d5468:	movl 0x59b7cc, %ebx
0x004d546e:	cmpl %esi, $0xfffffffe<UINT8>
0x004d5471:	jne 0x004d5491
0x004d5491:	cmpl %esi, $0xfffffffd<UINT8>
0x004d5494:	jne 0x004d54a8
0x004d5496:	movl 0x59b7cc, $0x1<UINT32>
0x004d54a0:	call GetACP@KERNEL32.dll
GetACP@KERNEL32.dll: API Node	
0x004d54a6:	jmp 0x004d5483
0x004d5483:	cmpb -4(%ebp), %bl
0x004d5486:	je 69
0x004d5488:	movl %ecx, -8(%ebp)
0x004d548b:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x004d548f:	jmp 0x004d54cd
0x004d54cd:	popl %ebx
0x004d54ce:	leave
0x004d54cf:	ret

0x004d56df:	movl 0x8(%ebp), %eax
0x004d56e2:	cmpl %eax, 0x4(%ebx)
0x004d56e5:	je 343
0x004d56eb:	pushl $0x220<UINT32>
0x004d56f0:	call 0x004d8d32
0x004d56f5:	popl %ecx
0x004d56f6:	movl %ebx, %eax
0x004d56f8:	testl %ebx, %ebx
0x004d56fa:	je 326
0x004d5700:	movl %ecx, $0x88<UINT32>
0x004d5705:	movl %esi, 0x68(%edi)
0x004d5708:	movl %edi, %ebx
0x004d570a:	rep movsl %es:(%edi), %ds:(%esi)
0x004d570c:	andl (%ebx), $0x0<UINT8>
0x004d570f:	pushl %ebx
0x004d5710:	pushl 0x8(%ebp)
0x004d5713:	call 0x004d54d0
0x004d54d0:	movl %edi, %edi
0x004d54d2:	pushl %ebp
0x004d54d3:	movl %ebp, %esp
0x004d54d5:	subl %esp, $0x20<UINT8>
0x004d54d8:	movl %eax, 0x594ea0
0x004d54dd:	xorl %eax, %ebp
0x004d54df:	movl -4(%ebp), %eax
0x004d54e2:	pushl %ebx
0x004d54e3:	movl %ebx, 0xc(%ebp)
0x004d54e6:	pushl %esi
0x004d54e7:	movl %esi, 0x8(%ebp)
0x004d54ea:	pushl %edi
0x004d54eb:	call 0x004d5454
0x004d54a8:	cmpl %esi, $0xfffffffc<UINT8>
0x004d54ab:	jne 0x004d54bf
0x004d54bf:	cmpb -4(%ebp), %bl
0x004d54c2:	je 7
0x004d54c4:	movl %eax, -8(%ebp)
0x004d54c7:	andl 0x70(%eax), $0xfffffffd<UINT8>
0x004d54cb:	movl %eax, %esi
0x004d54f0:	movl %edi, %eax
0x004d54f2:	xorl %esi, %esi
0x004d54f4:	movl 0x8(%ebp), %edi
0x004d54f7:	cmpl %edi, %esi
0x004d54f9:	jne 0x004d5509
0x004d5509:	movl -28(%ebp), %esi
0x004d550c:	xorl %eax, %eax
0x004d550e:	cmpl 0x595590(%eax), %edi
0x004d5514:	je 145
0x004d551a:	incl -28(%ebp)
0x004d551d:	addl %eax, $0x30<UINT8>
0x004d5520:	cmpl %eax, $0xf0<UINT32>
0x004d5525:	jb 0x004d550e
0x004d5527:	cmpl %edi, $0xfde8<UINT32>
0x004d552d:	je 368
0x004d5533:	cmpl %edi, $0xfde9<UINT32>
0x004d5539:	je 356
0x004d553f:	movzwl %eax, %di
0x004d5542:	pushl %eax
0x004d5543:	call IsValidCodePage@KERNEL32.dll
IsValidCodePage@KERNEL32.dll: API Node	
0x004d5549:	testl %eax, %eax
0x004d554b:	je 338
0x004d5551:	leal %eax, -24(%ebp)
0x004d5554:	pushl %eax
0x004d5555:	pushl %edi
0x004d5556:	call GetCPInfo@KERNEL32.dll
GetCPInfo@KERNEL32.dll: API Node	
0x004d555c:	testl %eax, %eax
0x004d555e:	je 307
0x004d5564:	pushl $0x101<UINT32>
0x004d5569:	leal %eax, 0x1c(%ebx)
0x004d556c:	pushl %esi
0x004d556d:	pushl %eax
0x004d556e:	call 0x004cb630
0x004cb630:	movl %edx, 0xc(%esp)
0x004cb634:	movl %ecx, 0x4(%esp)
0x004cb638:	testl %edx, %edx
0x004cb63a:	je 105
0x004cb63c:	xorl %eax, %eax
0x004cb63e:	movb %al, 0x8(%esp)
0x004cb642:	testb %al, %al
0x004cb644:	jne 22
0x004cb646:	cmpl %edx, $0x100<UINT32>
0x004cb64c:	jb 0x004cb65c
0x004cb64e:	cmpl 0x59e6e4, $0x0<UINT8>
0x004cb655:	je 0x004cb65c
0x004cb65c:	pushl %edi
0x004cb65d:	movl %edi, %ecx
0x004cb65f:	cmpl %edx, $0x4<UINT8>
0x004cb662:	jb 49
0x004cb664:	negl %ecx
0x004cb666:	andl %ecx, $0x3<UINT8>
0x004cb669:	je 0x004cb677
0x004cb677:	movl %ecx, %eax
0x004cb679:	shll %eax, $0x8<UINT8>
0x004cb67c:	addl %eax, %ecx
0x004cb67e:	movl %ecx, %eax
0x004cb680:	shll %eax, $0x10<UINT8>
0x004cb683:	addl %eax, %ecx
0x004cb685:	movl %ecx, %edx
0x004cb687:	andl %edx, $0x3<UINT8>
0x004cb68a:	shrl %ecx, $0x2<UINT8>
0x004cb68d:	je 6
0x004cb68f:	rep stosl %es:(%edi), %eax
0x004cb691:	testl %edx, %edx
0x004cb693:	je 0x004cb69f
0x004cb695:	movb (%edi), %al
0x004cb697:	addl %edi, $0x1<UINT8>
0x004cb69a:	subl %edx, $0x1<UINT8>
0x004cb69d:	jne -10
0x004cb69f:	movl %eax, 0x8(%esp)
0x004cb6a3:	popl %edi
0x004cb6a4:	ret

0x004d5573:	xorl %edx, %edx
0x004d5575:	incl %edx
0x004d5576:	addl %esp, $0xc<UINT8>
0x004d5579:	movl 0x4(%ebx), %edi
0x004d557c:	movl 0xc(%ebx), %esi
0x004d557f:	cmpl -24(%ebp), %edx
0x004d5582:	jbe 248
0x004d5588:	cmpb -18(%ebp), $0x0<UINT8>
0x004d558c:	je 0x004d5661
0x004d5661:	leal %eax, 0x1e(%ebx)
0x004d5664:	movl %ecx, $0xfe<UINT32>
0x004d5669:	orb (%eax), $0x8<UINT8>
0x004d566c:	incl %eax
0x004d566d:	decl %ecx
0x004d566e:	jne 0x004d5669
0x004d5670:	movl %eax, 0x4(%ebx)
0x004d5673:	call 0x004d518a
0x004d518a:	subl %eax, $0x3a4<UINT32>
0x004d518f:	je 34
0x004d5191:	subl %eax, $0x4<UINT8>
0x004d5194:	je 23
0x004d5196:	subl %eax, $0xd<UINT8>
0x004d5199:	je 12
0x004d519b:	decl %eax
0x004d519c:	je 3
0x004d519e:	xorl %eax, %eax
0x004d51a0:	ret

0x004d5678:	movl 0xc(%ebx), %eax
0x004d567b:	movl 0x8(%ebx), %edx
0x004d567e:	jmp 0x004d5683
0x004d5683:	xorl %eax, %eax
0x004d5685:	movzwl %ecx, %ax
0x004d5688:	movl %eax, %ecx
0x004d568a:	shll %ecx, $0x10<UINT8>
0x004d568d:	orl %eax, %ecx
0x004d568f:	leal %edi, 0x10(%ebx)
0x004d5692:	stosl %es:(%edi), %eax
0x004d5693:	stosl %es:(%edi), %eax
0x004d5694:	stosl %es:(%edi), %eax
0x004d5695:	jmp 0x004d563f
0x004d563f:	movl %esi, %ebx
0x004d5641:	call 0x004d521d
0x004d521d:	movl %edi, %edi
0x004d521f:	pushl %ebp
0x004d5220:	movl %ebp, %esp
0x004d5222:	subl %esp, $0x51c<UINT32>
0x004d5228:	movl %eax, 0x594ea0
0x004d522d:	xorl %eax, %ebp
0x004d522f:	movl -4(%ebp), %eax
0x004d5232:	pushl %ebx
0x004d5233:	pushl %edi
0x004d5234:	leal %eax, -1304(%ebp)
0x004d523a:	pushl %eax
0x004d523b:	pushl 0x4(%esi)
0x004d523e:	call GetCPInfo@KERNEL32.dll
0x004d5244:	movl %edi, $0x100<UINT32>
0x004d5249:	testl %eax, %eax
0x004d524b:	je 251
0x004d5251:	xorl %eax, %eax
0x004d5253:	movb -260(%ebp,%eax), %al
0x004d525a:	incl %eax
0x004d525b:	cmpl %eax, %edi
0x004d525d:	jb 0x004d5253
0x004d525f:	movb %al, -1298(%ebp)
0x004d5265:	movb -260(%ebp), $0x20<UINT8>
0x004d526c:	testb %al, %al
0x004d526e:	je 0x004d529e
0x004d529e:	pushl $0x0<UINT8>
0x004d52a0:	pushl 0xc(%esi)
0x004d52a3:	leal %eax, -1284(%ebp)
0x004d52a9:	pushl 0x4(%esi)
0x004d52ac:	pushl %eax
0x004d52ad:	pushl %edi
0x004d52ae:	leal %eax, -260(%ebp)
0x004d52b4:	pushl %eax
0x004d52b5:	pushl $0x1<UINT8>
0x004d52b7:	pushl $0x0<UINT8>
0x004d52b9:	call 0x004e188c
0x004e188c:	movl %edi, %edi
0x004e188e:	pushl %ebp
0x004e188f:	movl %ebp, %esp
0x004e1891:	subl %esp, $0x10<UINT8>
0x004e1894:	pushl 0x8(%ebp)
0x004e1897:	leal %ecx, -16(%ebp)
0x004e189a:	call 0x004cc320
0x004e189f:	pushl 0x24(%ebp)
0x004e18a2:	leal %ecx, -16(%ebp)
0x004e18a5:	pushl 0x20(%ebp)
0x004e18a8:	pushl 0x1c(%ebp)
0x004e18ab:	pushl 0x18(%ebp)
0x004e18ae:	pushl 0x14(%ebp)
0x004e18b1:	pushl 0x10(%ebp)
0x004e18b4:	pushl 0xc(%ebp)
0x004e18b7:	call 0x004e16d2
0x004e16d2:	movl %edi, %edi
0x004e16d4:	pushl %ebp
0x004e16d5:	movl %ebp, %esp
0x004e16d7:	pushl %ecx
0x004e16d8:	pushl %ecx
0x004e16d9:	movl %eax, 0x594ea0
0x004e16de:	xorl %eax, %ebp
0x004e16e0:	movl -4(%ebp), %eax
0x004e16e3:	movl %eax, 0x59bab8
0x004e16e8:	pushl %ebx
0x004e16e9:	pushl %esi
0x004e16ea:	xorl %ebx, %ebx
0x004e16ec:	pushl %edi
0x004e16ed:	movl %edi, %ecx
0x004e16ef:	cmpl %eax, %ebx
0x004e16f1:	jne 58
0x004e16f3:	leal %eax, -8(%ebp)
0x004e16f6:	pushl %eax
0x004e16f7:	xorl %esi, %esi
0x004e16f9:	incl %esi
0x004e16fa:	pushl %esi
0x004e16fb:	pushl $0x5653f8<UINT32>
0x004e1700:	pushl %esi
0x004e1701:	call GetStringTypeW@KERNEL32.dll
GetStringTypeW@KERNEL32.dll: API Node	
0x004e1707:	testl %eax, %eax
0x004e1709:	je 8
0x004e170b:	movl 0x59bab8, %esi
0x004e1711:	jmp 0x004e1747
0x004e1747:	movl -8(%ebp), %ebx
0x004e174a:	cmpl 0x18(%ebp), %ebx
0x004e174d:	jne 0x004e1757
0x004e1757:	movl %esi, 0x52a408
0x004e175d:	xorl %eax, %eax
0x004e175f:	cmpl 0x20(%ebp), %ebx
0x004e1762:	pushl %ebx
0x004e1763:	pushl %ebx
0x004e1764:	pushl 0x10(%ebp)
0x004e1767:	setne %al
0x004e176a:	pushl 0xc(%ebp)
0x004e176d:	leal %eax, 0x1(,%eax,8)
0x004e1774:	pushl %eax
0x004e1775:	pushl 0x18(%ebp)
0x004e1778:	call MultiByteToWideChar@KERNEL32.dll
MultiByteToWideChar@KERNEL32.dll: API Node	
0x004e177a:	movl %edi, %eax
0x004e177c:	cmpl %edi, %ebx
0x004e177e:	je 171
0x004e1784:	jle 60
0x004e1786:	cmpl %edi, $0x7ffffff0<UINT32>
0x004e178c:	ja 52
0x004e178e:	leal %eax, 0x8(%edi,%edi)
0x004e1792:	cmpl %eax, $0x400<UINT32>
0x004e1797:	ja 19
0x004e1799:	call 0x004cdcc0
0x004cdcc0:	pushl %ecx
0x004cdcc1:	leal %ecx, 0x8(%esp)
0x004cdcc5:	subl %ecx, %eax
0x004cdcc7:	andl %ecx, $0xf<UINT8>
0x004cdcca:	addl %eax, %ecx
0x004cdccc:	sbbl %ecx, %ecx
0x004cdcce:	orl %eax, %ecx
0x004cdcd0:	popl %ecx
0x004cdcd1:	jmp 0x004ce850
0x004ce850:	pushl %ecx
0x004ce851:	leal %ecx, 0x4(%esp)
0x004ce855:	subl %ecx, %eax
0x004ce857:	sbbl %eax, %eax
0x004ce859:	notl %eax
0x004ce85b:	andl %ecx, %eax
0x004ce85d:	movl %eax, %esp
0x004ce85f:	andl %eax, $0xfffff000<UINT32>
0x004ce864:	cmpl %ecx, %eax
0x004ce866:	jb 10
0x004ce868:	movl %eax, %ecx
0x004ce86a:	popl %ecx
0x004ce86b:	xchgl %esp, %eax
0x004ce86c:	movl %eax, (%eax)
0x004ce86e:	movl (%esp), %eax
0x004ce871:	ret

0x004e179e:	movl %eax, %esp
0x004e17a0:	cmpl %eax, %ebx
0x004e17a2:	je 28
0x004e17a4:	movl (%eax), $0xcccc<UINT32>
0x004e17aa:	jmp 0x004e17bd
0x004e17bd:	addl %eax, $0x8<UINT8>
0x004e17c0:	movl %ebx, %eax
0x004e17c2:	testl %ebx, %ebx
0x004e17c4:	je 105
0x004e17c6:	leal %eax, (%edi,%edi)
0x004e17c9:	pushl %eax
0x004e17ca:	pushl $0x0<UINT8>
0x004e17cc:	pushl %ebx
0x004e17cd:	call 0x004cb630
0x004e17d2:	addl %esp, $0xc<UINT8>
0x004e17d5:	pushl %edi
0x004e17d6:	pushl %ebx
0x004e17d7:	pushl 0x10(%ebp)
0x004e17da:	pushl 0xc(%ebp)
0x004e17dd:	pushl $0x1<UINT8>
0x004e17df:	pushl 0x18(%ebp)
0x004e17e2:	call MultiByteToWideChar@KERNEL32.dll
0x004e17e4:	testl %eax, %eax
0x004e17e6:	je 17
0x004e17e8:	pushl 0x14(%ebp)
0x004e17eb:	pushl %eax
0x004e17ec:	pushl %ebx
0x004e17ed:	pushl 0x8(%ebp)
0x004e17f0:	call GetStringTypeW@KERNEL32.dll
0x004e17f6:	movl -8(%ebp), %eax
0x004e17f9:	pushl %ebx
0x004e17fa:	call 0x004e12c8
0x004e12c8:	movl %edi, %edi
0x004e12ca:	pushl %ebp
0x004e12cb:	movl %ebp, %esp
0x004e12cd:	movl %eax, 0x8(%ebp)
0x004e12d0:	testl %eax, %eax
0x004e12d2:	je 18
0x004e12d4:	subl %eax, $0x8<UINT8>
0x004e12d7:	cmpl (%eax), $0xdddd<UINT32>
0x004e12dd:	jne 0x004e12e6
0x004e12e6:	popl %ebp
0x004e12e7:	ret

0x004e17ff:	movl %eax, -8(%ebp)
0x004e1802:	popl %ecx
0x004e1803:	jmp 0x004e187a
0x004e187a:	leal %esp, -20(%ebp)
0x004e187d:	popl %edi
0x004e187e:	popl %esi
0x004e187f:	popl %ebx
0x004e1880:	movl %ecx, -4(%ebp)
0x004e1883:	xorl %ecx, %ebp
0x004e1885:	call 0x004cb615
0x004cb615:	cmpl %ecx, 0x594ea0
0x004cb61b:	jne 2
0x004cb61d:	rep ret

0x004e188a:	leave
0x004e188b:	ret

0x004e18bc:	addl %esp, $0x1c<UINT8>
0x004e18bf:	cmpb -4(%ebp), $0x0<UINT8>
0x004e18c3:	je 7
0x004e18c5:	movl %ecx, -8(%ebp)
0x004e18c8:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x004e18cc:	leave
0x004e18cd:	ret

0x004d52be:	xorl %ebx, %ebx
0x004d52c0:	pushl %ebx
0x004d52c1:	pushl 0x4(%esi)
0x004d52c4:	leal %eax, -516(%ebp)
0x004d52ca:	pushl %edi
0x004d52cb:	pushl %eax
0x004d52cc:	pushl %edi
0x004d52cd:	leal %eax, -260(%ebp)
0x004d52d3:	pushl %eax
0x004d52d4:	pushl %edi
0x004d52d5:	pushl 0xc(%esi)
0x004d52d8:	pushl %ebx
0x004d52d9:	call 0x004e168d
0x004e168d:	movl %edi, %edi
0x004e168f:	pushl %ebp
0x004e1690:	movl %ebp, %esp
0x004e1692:	subl %esp, $0x10<UINT8>
0x004e1695:	pushl 0x8(%ebp)
0x004e1698:	leal %ecx, -16(%ebp)
0x004e169b:	call 0x004cc320
0x004e16a0:	pushl 0x28(%ebp)
0x004e16a3:	leal %ecx, -16(%ebp)
0x004e16a6:	pushl 0x24(%ebp)
0x004e16a9:	pushl 0x20(%ebp)
0x004e16ac:	pushl 0x1c(%ebp)
0x004e16af:	pushl 0x18(%ebp)
0x004e16b2:	pushl 0x14(%ebp)
0x004e16b5:	pushl 0x10(%ebp)
0x004e16b8:	pushl 0xc(%ebp)
0x004e16bb:	call 0x004e12e8
0x004e12e8:	movl %edi, %edi
0x004e12ea:	pushl %ebp
0x004e12eb:	movl %ebp, %esp
0x004e12ed:	subl %esp, $0x14<UINT8>
0x004e12f0:	movl %eax, 0x594ea0
0x004e12f5:	xorl %eax, %ebp
0x004e12f7:	movl -4(%ebp), %eax
0x004e12fa:	pushl %ebx
0x004e12fb:	pushl %esi
0x004e12fc:	xorl %ebx, %ebx
0x004e12fe:	pushl %edi
0x004e12ff:	movl %esi, %ecx
0x004e1301:	cmpl 0x59bab4, %ebx
0x004e1307:	jne 0x004e1341
0x004e1309:	pushl %ebx
0x004e130a:	pushl %ebx
0x004e130b:	xorl %edi, %edi
0x004e130d:	incl %edi
0x004e130e:	pushl %edi
0x004e130f:	pushl $0x5653f8<UINT32>
0x004e1314:	pushl $0x100<UINT32>
0x004e1319:	pushl %ebx
0x004e131a:	call LCMapStringW@KERNEL32.dll
LCMapStringW@KERNEL32.dll: API Node	
0x004e1320:	testl %eax, %eax
0x004e1322:	je 8
0x004e1324:	movl 0x59bab4, %edi
0x004e132a:	jmp 0x004e1341
0x004e1341:	cmpl 0x14(%ebp), %ebx
0x004e1344:	jle 0x004e1368
0x004e1368:	movl %eax, 0x59bab4
0x004e136d:	cmpl %eax, $0x2<UINT8>
0x004e1370:	je 428
0x004e1376:	cmpl %eax, %ebx
0x004e1378:	je 420
0x004e137e:	cmpl %eax, $0x1<UINT8>
0x004e1381:	jne 460
0x004e1387:	movl -8(%ebp), %ebx
0x004e138a:	cmpl 0x20(%ebp), %ebx
0x004e138d:	jne 0x004e1397
0x004e1397:	movl %esi, 0x52a408
0x004e139d:	xorl %eax, %eax
0x004e139f:	cmpl 0x24(%ebp), %ebx
0x004e13a2:	pushl %ebx
0x004e13a3:	pushl %ebx
0x004e13a4:	pushl 0x14(%ebp)
0x004e13a7:	setne %al
0x004e13aa:	pushl 0x10(%ebp)
0x004e13ad:	leal %eax, 0x1(,%eax,8)
0x004e13b4:	pushl %eax
0x004e13b5:	pushl 0x20(%ebp)
0x004e13b8:	call MultiByteToWideChar@KERNEL32.dll
0x004e13ba:	movl %edi, %eax
0x004e13bc:	cmpl %edi, %ebx
0x004e13be:	je 0x004e1553
0x004e1553:	xorl %eax, %eax
0x004e1555:	jmp 0x004e167b
0x004e167b:	leal %esp, -32(%ebp)
0x004e167e:	popl %edi
0x004e167f:	popl %esi
0x004e1680:	popl %ebx
0x004e1681:	movl %ecx, -4(%ebp)
0x004e1684:	xorl %ecx, %ebp
0x004e1686:	call 0x004cb615
0x004e168b:	leave
0x004e168c:	ret

0x004e16c0:	addl %esp, $0x20<UINT8>
0x004e16c3:	cmpb -4(%ebp), $0x0<UINT8>
0x004e16c7:	je 7
0x004e16c9:	movl %ecx, -8(%ebp)
0x004e16cc:	andl 0x70(%ecx), $0xfffffffd<UINT8>
0x004e16d0:	leave
0x004e16d1:	ret

0x004d52de:	addl %esp, $0x44<UINT8>
0x004d52e1:	pushl %ebx
0x004d52e2:	pushl 0x4(%esi)
0x004d52e5:	leal %eax, -772(%ebp)
0x004d52eb:	pushl %edi
0x004d52ec:	pushl %eax
0x004d52ed:	pushl %edi
0x004d52ee:	leal %eax, -260(%ebp)
0x004d52f4:	pushl %eax
0x004d52f5:	pushl $0x200<UINT32>
0x004d52fa:	pushl 0xc(%esi)
0x004d52fd:	pushl %ebx
0x004d52fe:	call 0x004e168d
0x004d5303:	addl %esp, $0x24<UINT8>
0x004d5306:	xorl %eax, %eax
0x004d5308:	movzwl %ecx, -1284(%ebp,%eax,2)
0x004d5310:	testb %cl, $0x1<UINT8>
0x004d5313:	je 0x004d5323
0x004d5323:	testb %cl, $0x2<UINT8>
0x004d5326:	je 0x004d533d
0x004d533d:	movb 0x11d(%esi,%eax), $0x0<UINT8>
0x004d5345:	incl %eax
0x004d5346:	cmpl %eax, %edi
0x004d5348:	jb -66
0x004d534a:	jmp 0x004d53a2
0x004d53a2:	movl %ecx, -4(%ebp)
0x004d53a5:	popl %edi
0x004d53a6:	xorl %ecx, %ebp
0x004d53a8:	popl %ebx
0x004d53a9:	call 0x004cb615
0x004d53ae:	leave
0x004d53af:	ret

0x004d5646:	jmp 0x004d5502
0x004d5502:	xorl %eax, %eax
0x004d5504:	jmp 0x004d56a6
0x004d56a6:	movl %ecx, -4(%ebp)
0x004d56a9:	popl %edi
0x004d56aa:	popl %esi
0x004d56ab:	xorl %ecx, %ebp
0x004d56ad:	popl %ebx
0x004d56ae:	call 0x004cb615
0x004d56b3:	leave
0x004d56b4:	ret

0x004d5718:	popl %ecx
0x004d5719:	popl %ecx
0x004d571a:	movl -32(%ebp), %eax
0x004d571d:	testl %eax, %eax
0x004d571f:	jne 252
0x004d5725:	movl %esi, -36(%ebp)
0x004d5728:	pushl 0x68(%esi)
0x004d572b:	call InterlockedDecrement@KERNEL32.dll
InterlockedDecrement@KERNEL32.dll: API Node	
0x004d5731:	testl %eax, %eax
0x004d5733:	jne 17
0x004d5735:	movl %eax, 0x68(%esi)
0x004d5738:	cmpl %eax, $0x595160<UINT32>
0x004d573d:	je 0x004d5746
0x004d5746:	movl 0x68(%esi), %ebx
0x004d5749:	pushl %ebx
0x004d574a:	movl %edi, 0x52a16c
0x004d5750:	call InterlockedIncrement@KERNEL32.dll
0x004d5752:	testb 0x70(%esi), $0x2<UINT8>
0x004d5756:	jne 234
0x004d575c:	testb 0x595684, $0x1<UINT8>
0x004d5763:	jne 221
0x004d5769:	pushl $0xd<UINT8>
0x004d576b:	call 0x004dfb43
0x004d5770:	popl %ecx
0x004d5771:	andl -4(%ebp), $0x0<UINT8>
0x004d5775:	movl %eax, 0x4(%ebx)
0x004d5778:	movl 0x59b7dc, %eax
0x004d577d:	movl %eax, 0x8(%ebx)
0x004d5780:	movl 0x59b7e0, %eax
0x004d5785:	movl %eax, 0xc(%ebx)
0x004d5788:	movl 0x59b7e4, %eax
0x004d578d:	xorl %eax, %eax
0x004d578f:	movl -28(%ebp), %eax
0x004d5792:	cmpl %eax, $0x5<UINT8>
0x004d5795:	jnl 0x004d57a7
0x004d5797:	movw %cx, 0x10(%ebx,%eax,2)
0x004d579c:	movw 0x59b7d0(,%eax,2), %cx
0x004d57a4:	incl %eax
0x004d57a5:	jmp 0x004d578f
0x004d57a7:	xorl %eax, %eax
0x004d57a9:	movl -28(%ebp), %eax
0x004d57ac:	cmpl %eax, $0x101<UINT32>
0x004d57b1:	jnl 0x004d57c0
0x004d57b3:	movb %cl, 0x1c(%eax,%ebx)
0x004d57b7:	movb 0x595380(%eax), %cl
0x004d57bd:	incl %eax
0x004d57be:	jmp 0x004d57a9
0x004d57c0:	xorl %eax, %eax
0x004d57c2:	movl -28(%ebp), %eax
0x004d57c5:	cmpl %eax, $0x100<UINT32>
0x004d57ca:	jnl 0x004d57dc
0x004d57cc:	movb %cl, 0x11d(%eax,%ebx)
0x004d57d3:	movb 0x595488(%eax), %cl
0x004d57d9:	incl %eax
0x004d57da:	jmp 0x004d57c2
0x004d57dc:	pushl 0x595588
0x004d57e2:	call InterlockedDecrement@KERNEL32.dll
0x004d57e8:	testl %eax, %eax
0x004d57ea:	jne 0x004d57ff
0x004d57ff:	movl 0x595588, %ebx
0x004d5805:	pushl %ebx
0x004d5806:	call InterlockedIncrement@KERNEL32.dll
0x004d5808:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004d580f:	call 0x004d5816
0x004d5816:	pushl $0xd<UINT8>
0x004d5818:	call 0x004dfa69
0x004d581d:	popl %ecx
0x004d581e:	ret

0x004d5814:	jmp 0x004d5846
0x004d5846:	movl %eax, -32(%ebp)
0x004d5849:	call 0x004ceae5
0x004d584e:	ret

0x004d585f:	popl %ecx
0x004d5860:	movl 0x59e80c, $0x1<UINT32>
0x004d586a:	xorl %eax, %eax
0x004d586c:	ret

0x004d5e73:	movl %eax, 0x59e6e0
0x004d5e78:	pushl %esi
0x004d5e79:	pushl $0x14<UINT8>
0x004d5e7b:	popl %esi
0x004d5e7c:	testl %eax, %eax
0x004d5e7e:	jne 7
0x004d5e80:	movl %eax, $0x200<UINT32>
0x004d5e85:	jmp 0x004d5e8d
0x004d5e8d:	movl 0x59e6e0, %eax
0x004d5e92:	pushl $0x4<UINT8>
0x004d5e94:	pushl %eax
0x004d5e95:	call 0x004d8d77
0x004d5e9a:	popl %ecx
0x004d5e9b:	popl %ecx
0x004d5e9c:	movl 0x59d6d4, %eax
0x004d5ea1:	testl %eax, %eax
0x004d5ea3:	jne 0x004d5ec3
0x004d5ec3:	xorl %edx, %edx
0x004d5ec5:	movl %ecx, $0x595778<UINT32>
0x004d5eca:	jmp 0x004d5ed1
0x004d5ed1:	movl (%edx,%eax), %ecx
0x004d5ed4:	addl %ecx, $0x20<UINT8>
0x004d5ed7:	addl %edx, $0x4<UINT8>
0x004d5eda:	cmpl %ecx, $0x5959f8<UINT32>
0x004d5ee0:	jl 0x004d5ecc
0x004d5ecc:	movl %eax, 0x59d6d4
0x004d5ee2:	pushl $0xfffffffe<UINT8>
0x004d5ee4:	popl %esi
0x004d5ee5:	xorl %edx, %edx
0x004d5ee7:	movl %ecx, $0x595788<UINT32>
0x004d5eec:	pushl %edi
0x004d5eed:	movl %eax, %edx
0x004d5eef:	sarl %eax, $0x5<UINT8>
0x004d5ef2:	movl %eax, 0x59e700(,%eax,4)
0x004d5ef9:	movl %edi, %edx
0x004d5efb:	andl %edi, $0x1f<UINT8>
0x004d5efe:	shll %edi, $0x6<UINT8>
0x004d5f01:	movl %eax, (%edi,%eax)
0x004d5f04:	cmpl %eax, $0xffffffff<UINT8>
0x004d5f07:	je 8
0x004d5f09:	cmpl %eax, %esi
0x004d5f0b:	je 4
0x004d5f0d:	testl %eax, %eax
0x004d5f0f:	jne 0x004d5f13
0x004d5f13:	addl %ecx, $0x20<UINT8>
0x004d5f16:	incl %edx
0x004d5f17:	cmpl %ecx, $0x5957e8<UINT32>
0x004d5f1d:	jl 0x004d5eed
0x004d5f1f:	popl %edi
0x004d5f20:	xorl %eax, %eax
0x004d5f22:	popl %esi
0x004d5f23:	ret

0x004d7a3e:	andl 0x59d6d0, $0x0<UINT8>
0x004d7a45:	call 0x004d2502
0x004d7a4a:	movl 0x59d6d0, %eax
0x004d7a4f:	xorl %eax, %eax
0x004d7a51:	ret

0x004d12f1:	pushl $0x4d12af<UINT32>
0x004d12f6:	call SetUnhandledExceptionFilter@KERNEL32.dll
SetUnhandledExceptionFilter@KERNEL32.dll: API Node	
0x004d12fc:	xorl %eax, %eax
0x004d12fe:	ret

0x004d097a:	popl %esi
0x004d097b:	popl %ebp
0x004d097c:	ret

0x004d09b8:	popl %ecx
0x004d09b9:	popl %ecx
0x004d09ba:	testl %eax, %eax
0x004d09bc:	jne 66
0x004d09be:	pushl $0x4d1c3d<UINT32>
0x004d09c3:	call 0x004ccf7f
0x004ccf7f:	movl %edi, %edi
0x004ccf81:	pushl %ebp
0x004ccf82:	movl %ebp, %esp
0x004ccf84:	pushl 0x8(%ebp)
0x004ccf87:	call 0x004ccf43
0x004ccf43:	pushl $0xc<UINT8>
0x004ccf45:	pushl $0x575e10<UINT32>
0x004ccf4a:	call 0x004ceaa0
0x004ccf4f:	call 0x004d092a
0x004d092a:	pushl $0x8<UINT8>
0x004d092c:	call 0x004dfb43
0x004d0931:	popl %ecx
0x004d0932:	ret

0x004ccf54:	andl -4(%ebp), $0x0<UINT8>
0x004ccf58:	pushl 0x8(%ebp)
0x004ccf5b:	call 0x004cce58
0x004cce58:	movl %edi, %edi
0x004cce5a:	pushl %ebp
0x004cce5b:	movl %ebp, %esp
0x004cce5d:	pushl %ecx
0x004cce5e:	pushl %ebx
0x004cce5f:	pushl %esi
0x004cce60:	pushl %edi
0x004cce61:	pushl 0x59e808
0x004cce67:	call 0x004d1cde
0x004d1d0f:	movl %eax, 0x1fc(%eax)
0x004d1d15:	jmp 0x004d1d3e
0x004cce6c:	pushl 0x59e804
0x004cce72:	movl %edi, %eax
0x004cce74:	movl -4(%ebp), %edi
0x004cce77:	call 0x004d1cde
0x004cce7c:	movl %esi, %eax
0x004cce7e:	popl %ecx
0x004cce7f:	popl %ecx
0x004cce80:	cmpl %esi, %edi
0x004cce82:	jb 131
0x004cce88:	movl %ebx, %esi
0x004cce8a:	subl %ebx, %edi
0x004cce8c:	leal %eax, 0x4(%ebx)
0x004cce8f:	cmpl %eax, $0x4<UINT8>
0x004cce92:	jb 119
0x004cce94:	pushl %edi
0x004cce95:	call 0x004d0d1b
0x004d0d1b:	pushl $0x10<UINT8>
0x004d0d1d:	pushl $0x575f30<UINT32>
0x004d0d22:	call 0x004ceaa0
0x004d0d27:	xorl %eax, %eax
0x004d0d29:	movl %ebx, 0x8(%ebp)
0x004d0d2c:	xorl %edi, %edi
0x004d0d2e:	cmpl %ebx, %edi
0x004d0d30:	setne %al
0x004d0d33:	cmpl %eax, %edi
0x004d0d35:	jne 0x004d0d54
0x004d0d54:	cmpl 0x59e6e8, $0x3<UINT8>
0x004d0d5b:	jne 0x004d0d95
0x004d0d95:	pushl %ebx
0x004d0d96:	pushl %edi
0x004d0d97:	pushl 0x59b494
0x004d0d9d:	call HeapSize@KERNEL32.dll
HeapSize@KERNEL32.dll: API Node	
0x004d0da3:	movl %esi, %eax
0x004d0da5:	movl %eax, %esi
0x004d0da7:	call 0x004ceae5
0x004d0dac:	ret

0x004cce9a:	movl %edi, %eax
0x004cce9c:	leal %eax, 0x4(%ebx)
0x004cce9f:	popl %ecx
0x004ccea0:	cmpl %edi, %eax
0x004ccea2:	jae 0x004cceec
0x004cceec:	pushl 0x8(%ebp)
0x004cceef:	call 0x004d1c63
0x004ccef4:	movl (%esi), %eax
0x004ccef6:	addl %esi, $0x4<UINT8>
0x004ccef9:	pushl %esi
0x004ccefa:	call 0x004d1c63
0x004cceff:	popl %ecx
0x004ccf00:	movl 0x59e804, %eax
0x004ccf05:	movl %eax, 0x8(%ebp)
0x004ccf08:	popl %ecx
0x004ccf09:	jmp 0x004ccf0d
0x004ccf0d:	popl %edi
0x004ccf0e:	popl %esi
0x004ccf0f:	popl %ebx
0x004ccf10:	leave
0x004ccf11:	ret

0x004ccf60:	popl %ecx
0x004ccf61:	movl -28(%ebp), %eax
0x004ccf64:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004ccf6b:	call 0x004ccf79
0x004ccf79:	call 0x004d0933
0x004d0933:	pushl $0x8<UINT8>
0x004d0935:	call 0x004dfa69
0x004d093a:	popl %ecx
0x004d093b:	ret

0x004ccf7e:	ret

0x004ccf70:	movl %eax, -28(%ebp)
0x004ccf73:	call 0x004ceae5
0x004ccf78:	ret

0x004ccf8c:	negl %eax
0x004ccf8e:	sbbl %eax, %eax
0x004ccf90:	negl %eax
0x004ccf92:	popl %ecx
0x004ccf93:	decl %eax
0x004ccf94:	popl %ebp
0x004ccf95:	ret

0x004d09c8:	movl %eax, $0x52a760<UINT32>
0x004d09cd:	movl (%esp), $0x52a7c8<UINT32>
0x004d09d4:	call 0x004d093c
0x004d093c:	movl %edi, %edi
0x004d093e:	pushl %ebp
0x004d093f:	movl %ebp, %esp
0x004d0941:	pushl %esi
0x004d0942:	movl %esi, %eax
0x004d0944:	jmp 0x004d0951
0x004d0951:	cmpl %esi, 0x8(%ebp)
0x004d0954:	jb 0x004d0946
0x004d0946:	movl %eax, (%esi)
0x004d0948:	testl %eax, %eax
0x004d094a:	je 0x004d094e
0x004d094e:	addl %esi, $0x4<UINT8>
0x004d094c:	call 0x005298e0
0x005298fc:	pushl $0x529c4f<UINT32>
0x00529901:	call 0x004ccf7f
0x00529906:	popl %ecx
0x00529907:	ret

0x00529908:	pushl $0x529c59<UINT32>
0x0052990d:	call 0x004ccf7f
0x00529912:	popl %ecx
0x00529913:	ret

0x00529b75:	movl %ecx, $0x59abd8<UINT32>
0x00529b7a:	jmp 0x004b6467
0x004b6467:	movl %eax, %ecx
0x004b6469:	movl (%eax), $0x5437d8<UINT32>
0x004b646f:	xorl %ecx, %ecx
0x004b6471:	movl 0x10(%eax), $0x2<UINT32>
0x004b6478:	movl 0x8(%eax), %ecx
0x004b647b:	movl 0xc(%eax), %ecx
0x004b647e:	movw 0x14(%eax), %cx
0x004b6482:	movw 0x16(%eax), %cx
0x004b6486:	movl 0x4(%eax), %eax
0x004b6489:	ret

0x00529bab:	call GetProcessHeap@KERNEL32.dll
GetProcessHeap@KERNEL32.dll: API Node	
0x00529bb1:	pushl $0x529cd6<UINT32>
0x00529bb6:	movl 0x59bad0, $0x54c54c<UINT32>
0x00529bc0:	movl 0x59bad4, %eax
0x00529bc5:	movb 0x59bad8, $0x0<UINT8>
0x00529bcc:	call 0x004ccf7f
0x00529bd1:	popl %ecx
0x00529bd2:	ret

0x00529bd3:	pushl $0x59bad0<UINT32>
0x00529bd8:	movl %ecx, $0x59badc<UINT32>
0x00529bdd:	call 0x004e92d5
0x004e92d5:	movl %edi, %edi
0x004e92d7:	pushl %ebp
0x004e92d8:	movl %ebp, %esp
0x004e92da:	movl %eax, %ecx
0x004e92dc:	movl %ecx, 0x8(%ebp)
0x004e92df:	movl 0x4(%eax), %ecx
0x004e92e2:	movl (%eax), $0x54c560<UINT32>
0x004e92e8:	xorl %ecx, %ecx
0x004e92ea:	movl 0x14(%eax), $0x2<UINT32>
0x004e92f1:	movl 0xc(%eax), %ecx
0x004e92f4:	movl 0x10(%eax), %ecx
0x004e92f7:	movw 0x18(%eax), %cx
0x004e92fb:	movw 0x1a(%eax), %cx
0x004e92ff:	movl 0x8(%eax), %eax
0x004e9302:	popl %ebp
0x004e9303:	ret $0x4<UINT16>

0x00529be2:	pushl $0x529ce0<UINT32>
0x00529be7:	call 0x004ccf7f
0x00529bec:	popl %ecx
0x00529bed:	ret

0x00529bee:	movl %ecx, $0x59baf8<UINT32>
0x00529bf3:	call 0x004e94dd
0x004e94dd:	movl %edi, %edi
0x004e94df:	pushl %esi
0x004e94e0:	movl %esi, %ecx
0x004e94e2:	call 0x004e94a9
0x004e94a9:	movl %edi, %edi
0x004e94ab:	pushl %esi
0x004e94ac:	movl %esi, %ecx
0x004e94ae:	leal %ecx, 0x14(%esi)
0x004e94b1:	call 0x004e9448
0x004e9448:	movl %edi, %edi
0x004e944a:	pushl %esi
0x004e944b:	pushl $0x18<UINT8>
0x004e944d:	movl %esi, %ecx
0x004e944f:	pushl $0x0<UINT8>
0x004e9451:	pushl %esi
0x004e9452:	call 0x004cb630
0x004e9457:	addl %esp, $0xc<UINT8>
0x004e945a:	movl %eax, %esi
0x004e945c:	popl %esi
0x004e945d:	ret

0x004e94b6:	xorl %eax, %eax
0x004e94b8:	movl 0x2c(%esi), %eax
0x004e94bb:	movl 0x30(%esi), %eax
0x004e94be:	movl 0x34(%esi), %eax
0x004e94c1:	movl %eax, %esi
0x004e94c3:	popl %esi
0x004e94c4:	ret

0x004e94e7:	movl %eax, $0x400000<UINT32>
0x004e94ec:	leal %ecx, 0x14(%esi)
0x004e94ef:	movl (%esi), $0x38<UINT32>
0x004e94f5:	movl 0x8(%esi), %eax
0x004e94f8:	movl 0x4(%esi), %eax
0x004e94fb:	movl 0xc(%esi), $0x900<UINT32>
0x004e9502:	movl 0x10(%esi), $0x54c588<UINT32>
0x004e9509:	call 0x004e945e
0x004e945e:	pushl $0xc<UINT8>
0x004e9460:	pushl $0x576508<UINT32>
0x004e9465:	call 0x004ceaa0
0x004e946a:	andl -4(%ebp), $0x0<UINT8>
0x004e946e:	pushl %ecx
0x004e946f:	call InitializeCriticalSection@KERNEL32.dll
InitializeCriticalSection@KERNEL32.dll: API Node	
0x004e9475:	andl -28(%ebp), $0x0<UINT8>
0x004e9479:	jmp 0x004e9499
0x004e9499:	movl -4(%ebp), $0xfffffffe<UINT32>
0x004e94a0:	movl %eax, -28(%ebp)
0x004e94a3:	call 0x004ceae5
0x004e94a8:	ret

0x004e950e:	testl %eax, %eax
0x004e9510:	jnl 0x004e9519
0x004e9519:	movl %eax, %esi
0x004e951b:	popl %esi
0x004e951c:	ret

0x00529bf8:	pushl $0x529ceb<UINT32>
0x00529bfd:	call 0x004ccf7f
0x00529c02:	popl %ecx
0x00529c03:	ret

0x00529c04:	pushl $0x900<UINT32>
0x00529c09:	pushl $0x0<UINT8>
0x00529c0b:	call 0x004ec017
0x004ec017:	movl %edi, %edi
0x004ec019:	pushl %ebp
0x004ec01a:	movl %ebp, %esp
0x004ec01c:	call 0x004ad714
0x004ad714:	pushl $0x4ad077<UINT32>
0x004ad719:	movl %ecx, $0x599000<UINT32>
0x004ad71e:	call 0x004c178d
0x004c178d:	pushl $0x4<UINT8>
0x004c178f:	movl %eax, $0x5275f6<UINT32>
0x004c1794:	call 0x004ce1f3
0x004ce1f3:	pushl %eax
0x004ce1f4:	pushl %fs:0
0x004ce1fb:	leal %eax, 0xc(%esp)
0x004ce1ff:	subl %esp, 0xc(%esp)
0x004ce203:	pushl %ebx
0x004ce204:	pushl %esi
0x004ce205:	pushl %edi
0x004ce206:	movl (%eax), %ebp
0x004ce208:	movl %ebp, %eax
0x004ce20a:	movl %eax, 0x594ea0
0x004ce20f:	xorl %eax, %ebp
0x004ce211:	pushl %eax
0x004ce212:	pushl -4(%ebp)
0x004ce215:	movl -4(%ebp), $0xffffffff<UINT32>
0x004ce21c:	leal %eax, -12(%ebp)
0x004ce21f:	movl %fs:0, %eax
0x004ce225:	ret

0x004c1799:	movl %esi, %ecx
0x004c179b:	xorl %eax, %eax
0x004c179d:	cmpl 0x8(%ebp), %eax
0x004c17a0:	setne %al
0x004c17a3:	testl %eax, %eax
0x004c17a5:	jne 0x004c17ac
0x004c17ac:	cmpl (%esi), $0x0<UINT8>
0x004c17af:	jne 0x004c17e7
0x004c17b1:	movl %ecx, 0x59ac20
0x004c17b7:	testl %ecx, %ecx
0x004c17b9:	jne 0x004c17dc
0x004c17bb:	movl %ecx, $0x59ac24<UINT32>
0x004c17c0:	movl -16(%ebp), %ecx
0x004c17c3:	andl -4(%ebp), $0x0<UINT8>
0x004c17c7:	call 0x004c14a3
0x004c14a3:	xorl %eax, %eax
0x004c14a5:	pushl %esi
0x004c14a6:	movl %esi, %ecx
0x004c14a8:	movl 0x14(%esi), %eax
0x004c14ab:	movl 0x18(%esi), $0x4<UINT32>
0x004c14b2:	movl 0x4(%esi), %eax
0x004c14b5:	movl 0x8(%esi), $0x1<UINT32>
0x004c14bc:	movl 0xc(%esi), %eax
0x004c14bf:	movl 0x10(%esi), %eax
0x004c14c2:	call TlsAlloc@KERNEL32.dll
0x004c14c8:	movl (%esi), %eax
0x004c14ca:	cmpl %eax, $0xffffffff<UINT8>
0x004c14cd:	jne 0x004c14d4
0x004c14d4:	leal %eax, 0x1c(%esi)
0x004c14d7:	pushl %eax
0x004c14d8:	call InitializeCriticalSection@KERNEL32.dll
0x004c14de:	movl %eax, %esi
0x004c14e0:	popl %esi
0x004c14e1:	ret

0x004c17cc:	orl -4(%ebp), $0xffffffff<UINT8>
0x004c17d0:	movl %ecx, %eax
0x004c17d2:	movl 0x59ac20, %ecx
0x004c17d8:	testl %eax, %eax
0x004c17da:	je -53
0x004c17dc:	call 0x004c138b
0x004c138b:	movl %edi, %edi
0x004c138d:	pushl %ebp
0x004c138e:	movl %ebp, %esp
0x004c1390:	pushl %ecx
0x004c1391:	pushl %ecx
0x004c1392:	pushl %ebx
0x004c1393:	pushl %esi
0x004c1394:	movl %esi, %ecx
0x004c1396:	leal %eax, 0x1c(%esi)
0x004c1399:	pushl %edi
0x004c139a:	pushl %eax
0x004c139b:	movl -4(%ebp), %eax
0x004c139e:	call EnterCriticalSection@KERNEL32.dll
0x004c13a4:	movl %ebx, 0x4(%esi)
0x004c13a7:	movl %edi, 0x8(%esi)
0x004c13aa:	cmpl %edi, %ebx
0x004c13ac:	jnl 0x004c13bb
0x004c13bb:	xorl %edi, %edi
0x004c13bd:	incl %edi
0x004c13be:	cmpl %ebx, %edi
0x004c13c0:	jle 0x004c13dd
0x004c13dd:	movl %eax, 0x10(%esi)
0x004c13e0:	addl %ebx, $0x20<UINT8>
0x004c13e3:	testl %eax, %eax
0x004c13e5:	jne 21
0x004c13e7:	pushl $0x8<UINT8>
0x004c13e9:	pushl %ebx
0x004c13ea:	call 0x004b6440
0x004b6440:	movl %edi, %edi
0x004b6442:	pushl %ebp
0x004b6443:	movl %ebp, %esp
0x004b6445:	pushl %ecx
0x004b6446:	pushl 0xc(%ebp)
0x004b6449:	leal %eax, -4(%ebp)
0x004b644c:	pushl 0x8(%ebp)
0x004b644f:	pushl %eax
0x004b6450:	call 0x004ad798
0x004ad798:	movl %edi, %edi
0x004ad79a:	pushl %ebp
0x004ad79b:	movl %ebp, %esp
0x004ad79d:	movl %eax, 0xc(%ebp)
0x004ad7a0:	mull %eax, 0x10(%ebp)
0x004ad7a3:	testl %edx, %edx
0x004ad7a5:	ja 5
0x004ad7a7:	cmpl %eax, $0xffffffff<UINT8>
0x004ad7aa:	jbe 0x004ad7b3
0x004ad7b3:	movl %ecx, 0x8(%ebp)
0x004ad7b6:	movl (%ecx), %eax
0x004ad7b8:	xorl %eax, %eax
0x004ad7ba:	popl %ebp
0x004ad7bb:	ret

0x004b6455:	addl %esp, $0xc<UINT8>
0x004b6458:	testl %eax, %eax
0x004b645a:	jnl 0x004b6462
0x004b6462:	movl %eax, -4(%ebp)
0x004b6465:	leave
0x004b6466:	ret

0x004c13ef:	popl %ecx
0x004c13f0:	popl %ecx
0x004c13f1:	pushl %eax
0x004c13f2:	pushl $0x2<UINT8>
0x004c13f4:	call GlobalAlloc@KERNEL32.dll
GlobalAlloc@KERNEL32.dll: API Node	
0x004c13fa:	jmp 0x004c1426
0x004c1426:	testl %eax, %eax
0x004c1428:	jne 0x004c144d
0x004c144d:	pushl %eax
0x004c144e:	call GlobalLock@KERNEL32.dll
GlobalLock@KERNEL32.dll: API Node	
0x004c1454:	movl %ecx, 0x4(%esi)
0x004c1457:	movl %edx, %ebx
0x004c1459:	subl %edx, %ecx
0x004c145b:	shll %edx, $0x3<UINT8>
0x004c145e:	pushl %edx
0x004c145f:	movl -8(%ebp), %eax
0x004c1462:	leal %eax, (%eax,%ecx,8)
0x004c1465:	pushl $0x0<UINT8>
0x004c1467:	pushl %eax
0x004c1468:	call 0x004cb630
0x004c146d:	movl %eax, -8(%ebp)
0x004c1470:	addl %esp, $0xc<UINT8>
0x004c1473:	movl 0x4(%esi), %ebx
0x004c1476:	movl 0x10(%esi), %eax
0x004c1479:	cmpl %edi, 0xc(%esi)
0x004c147c:	jl 6
0x004c147e:	leal %eax, 0x1(%edi)
0x004c1481:	movl 0xc(%esi), %eax
0x004c1484:	movl %eax, 0x10(%esi)
0x004c1487:	pushl -4(%ebp)
0x004c148a:	leal %eax, (%eax,%edi,8)
0x004c148d:	orl (%eax), $0x1<UINT8>
0x004c1490:	leal %eax, 0x1(%edi)
0x004c1493:	movl 0x8(%esi), %eax
0x004c1496:	call LeaveCriticalSection@KERNEL32.dll
0x004c149c:	movl %eax, %edi
0x004c149e:	popl %edi
0x004c149f:	popl %esi
0x004c14a0:	popl %ebx
0x004c14a1:	leave
0x004c14a2:	ret

0x004c17e1:	movl (%esi), %eax
0x004c17e3:	testl %eax, %eax
0x004c17e5:	je -64
0x004c17e7:	pushl (%esi)
0x004c17e9:	movl %ecx, 0x59ac20
0x004c17ef:	call 0x004c11fd
0x004c11fd:	movl %edi, %edi
0x004c11ff:	pushl %ebp
0x004c1200:	movl %ebp, %esp
0x004c1202:	pushl %ebx
0x004c1203:	pushl %esi
0x004c1204:	movl %esi, %ecx
0x004c1206:	pushl %edi
0x004c1207:	leal %ebx, 0x1c(%esi)
0x004c120a:	pushl %ebx
0x004c120b:	call EnterCriticalSection@KERNEL32.dll
0x004c1211:	movl %edi, 0x8(%ebp)
0x004c1214:	testl %edi, %edi
0x004c1216:	jle 39
0x004c1218:	cmpl %edi, 0xc(%esi)
0x004c121b:	jnl 34
0x004c121d:	pushl (%esi)
0x004c121f:	call TlsGetValue@KERNEL32.dll
0x004c1225:	testl %eax, %eax
0x004c1227:	je 0x004c123f
0x004c123f:	pushl %ebx
0x004c1240:	call LeaveCriticalSection@KERNEL32.dll
0x004c1246:	xorl %eax, %eax
0x004c1248:	popl %edi
0x004c1249:	popl %esi
0x004c124a:	popl %ebx
0x004c124b:	popl %ebp
0x004c124c:	ret $0x4<UINT16>

0x004c17f4:	movl %edi, %eax
0x004c17f6:	testl %edi, %edi
0x004c17f8:	jne 0x004c180d
0x004c17fa:	call 0x004ad077
0x004ad077:	pushl $0x164<UINT32>
0x004ad07c:	call 0x004c11ca
0x004c11ca:	movl %edi, %edi
0x004c11cc:	pushl %ebp
0x004c11cd:	movl %ebp, %esp
0x004c11cf:	pushl 0x8(%ebp)
0x004c11d2:	pushl $0x40<UINT8>
0x004c11d4:	call LocalAlloc@KERNEL32.dll
LocalAlloc@KERNEL32.dll: API Node	
0x004c11da:	testl %eax, %eax
0x004c11dc:	jne 0x004c11e3
0x004c11e3:	popl %ebp
0x004c11e4:	ret $0x4<UINT16>

0x004ad081:	testl %eax, %eax
0x004ad083:	je 7
0x004ad085:	movl %ecx, %eax
0x004ad087:	jmp 0x004acf79
0x004acf79:	movl %eax, %ecx
0x004acf7b:	xorl %edx, %edx
0x004acf7d:	xorl %ecx, %ecx
0x004acf7f:	movl (%eax), $0x541dd0<UINT32>
0x004acf85:	movl 0x34(%eax), %edx
0x004acf88:	movl 0x54(%eax), %edx
0x004acf8b:	movl 0x4c(%eax), %ecx
0x004acf8e:	movl 0x50(%eax), %edx
0x004acf91:	ret

0x004c17fd:	movl %ecx, 0x59ac20
0x004c1803:	movl %edi, %eax
0x004c1805:	pushl %edi
0x004c1806:	pushl (%esi)
0x004c1808:	call 0x004c154a
0x004c154a:	pushl $0x10<UINT8>
0x004c154c:	movl %eax, $0x5275cb<UINT32>
0x004c1551:	call 0x004ce226
0x004ce226:	pushl %eax
0x004ce227:	pushl %fs:0
0x004ce22e:	leal %eax, 0xc(%esp)
0x004ce232:	subl %esp, 0xc(%esp)
0x004ce236:	pushl %ebx
0x004ce237:	pushl %esi
0x004ce238:	pushl %edi
0x004ce239:	movl (%eax), %ebp
0x004ce23b:	movl %ebp, %eax
0x004ce23d:	movl %eax, 0x594ea0
0x004ce242:	xorl %eax, %ebp
0x004ce244:	pushl %eax
0x004ce245:	movl -16(%ebp), %esp
0x004ce248:	pushl -4(%ebp)
0x004ce24b:	movl -4(%ebp), $0xffffffff<UINT32>
0x004ce252:	leal %eax, -12(%ebp)
0x004ce255:	movl %fs:0, %eax
0x004ce25b:	ret

0x004c1556:	movl %edi, %ecx
0x004c1558:	movl -24(%ebp), %edi
0x004c155b:	leal %esi, 0x1c(%edi)
0x004c155e:	pushl %esi
0x004c155f:	movl -20(%ebp), %esi
0x004c1562:	call EnterCriticalSection@KERNEL32.dll
0x004c1568:	movl %eax, 0x8(%ebp)
0x004c156b:	xorl %ebx, %ebx
0x004c156d:	cmpl %eax, %ebx
0x004c156f:	jle 251
0x004c1575:	cmpl %eax, 0xc(%edi)
0x004c1578:	jge 242
0x004c157e:	pushl (%edi)
0x004c1580:	call TlsGetValue@KERNEL32.dll
0x004c1586:	movl %esi, %eax
0x004c1588:	cmpl %esi, %ebx
0x004c158a:	je 0x004c15bc
0x004c15bc:	pushl $0x10<UINT8>
0x004c15be:	movl -4(%ebp), %ebx
0x004c15c1:	call 0x004c11ca
0x004c15c6:	cmpl %eax, %ebx
0x004c15c8:	je 10
0x004c15ca:	movl (%eax), $0x545a7c<UINT32>
0x005275cb:	movl %edx, 0x8(%esp)
0x005275cf:	leal %eax, 0xc(%edx)
0x005275d2:	movl %ecx, -32(%edx)
0x005275d5:	xorl %ecx, %eax
0x005275d7:	call 0x004cb615
0x005275dc:	movl %eax, $0x575204<UINT32>
0x005275e1:	jmp 0x004cde9a
0x004cde9a:	pushl %ebp
0x004cde9b:	movl %ebp, %esp
0x004cde9d:	subl %esp, $0x8<UINT8>
0x004cdea0:	pushl %ebx
0x004cdea1:	pushl %esi
0x004cdea2:	pushl %edi
0x004cdea3:	cld
0x004cdea4:	movl -4(%ebp), %eax
0x004cdea7:	xorl %eax, %eax
0x004cdea9:	pushl %eax
0x004cdeaa:	pushl %eax
0x004cdeab:	pushl %eax
0x004cdeac:	pushl -4(%ebp)
0x004cdeaf:	pushl 0x14(%ebp)
0x004cdeb2:	pushl 0x10(%ebp)
0x004cdeb5:	pushl 0xc(%ebp)
0x004cdeb8:	pushl 0x8(%ebp)
0x004cdebb:	call 0x004dd8e5
0x004dd8e5:	movl %edi, %edi
0x004dd8e7:	pushl %ebp
0x004dd8e8:	movl %ebp, %esp
0x004dd8ea:	pushl %ebx
0x004dd8eb:	pushl %esi
0x004dd8ec:	pushl %edi
0x004dd8ed:	call 0x004d1f2a
0x004dd8f2:	cmpl 0x20c(%eax), $0x0<UINT8>
0x004dd8f9:	movl %eax, 0x18(%ebp)
0x004dd8fc:	movl %ecx, 0x8(%ebp)
0x004dd8ff:	movl %edi, $0xe06d7363<UINT32>
0x004dd904:	movl %esi, $0x1fffffff<UINT32>
0x004dd909:	movl %ebx, $0x19930522<UINT32>
0x004dd90e:	jne 32
0x004dd910:	movl %edx, (%ecx)
0x004dd912:	cmpl %edx, %edi
0x004dd914:	je 26
0x004dd916:	cmpl %edx, $0x80000026<UINT32>
0x004dd91c:	je 18
0x004dd91e:	movl %edx, (%eax)
0x004dd920:	andl %edx, %esi
0x004dd922:	cmpl %edx, %ebx
0x004dd924:	jb 10
0x004dd926:	testb 0x20(%eax), $0x1<UINT8>
0x004dd92a:	jne 0x004dd9c3
0x004dd9c3:	xorl %eax, %eax
0x004dd9c5:	incl %eax
0x004dd9c6:	popl %edi
0x004dd9c7:	popl %esi
0x004dd9c8:	popl %ebx
0x004dd9c9:	popl %ebp
0x004dd9ca:	ret

0x004cdec0:	addl %esp, $0x20<UINT8>
0x004cdec3:	movl -8(%ebp), %eax
0x004cdec6:	popl %edi
0x004cdec7:	popl %esi
0x004cdec8:	popl %ebx
0x004cdec9:	movl %eax, -8(%ebp)
0x004cdecc:	movl %esp, %ebp
0x004cdece:	popl %ebp
0x004cdecf:	ret

0x004c15d0:	movl %esi, %eax
0x004c15d2:	jmp 0x004c15d6
0x004c15d6:	orl -4(%ebp), $0xffffffff<UINT8>
0x004c15da:	pushl %esi
0x004c15db:	leal %ecx, 0x14(%edi)
0x004c15de:	movl 0x8(%esi), %ebx
0x004c15e1:	movl 0xc(%esi), %ebx
0x004c15e4:	call 0x004c12fc
0x004c12fc:	movl %edi, %edi
0x004c12fe:	pushl %ebp
0x004c12ff:	movl %ebp, %esp
0x004c1301:	pushl %esi
0x004c1302:	pushl %edi
0x004c1303:	movl %edi, 0x8(%ebp)
0x004c1306:	pushl %edi
0x004c1307:	movl %esi, %ecx
0x004c1309:	call 0x004c12e2
0x004c12e2:	movl %edi, %edi
0x004c12e4:	pushl %ebp
0x004c12e5:	movl %ebp, %esp
0x004c12e7:	cmpl 0x8(%ebp), $0x0<UINT8>
0x004c12eb:	jne 0x004c12f2
0x004c12f2:	movl %eax, 0x4(%ecx)
0x004c12f5:	addl %eax, 0x8(%ebp)
0x004c12f8:	popl %ebp
0x004c12f9:	ret $0x4<UINT16>

0x004c130e:	movl %ecx, (%esi)
0x004c1310:	movl (%eax), %ecx
0x004c1312:	movl (%esi), %edi
0x004c1314:	popl %edi
0x004c1315:	popl %esi
0x004c1316:	popl %ebp
0x004c1317:	ret $0x4<UINT16>

0x004c15e9:	jmp 0x004c15a1
0x004c15a1:	cmpl 0xc(%esi), %ebx
0x004c15a4:	jne 0x004c1601
0x004c15a6:	pushl $0x4<UINT8>
0x004c15a8:	pushl 0xc(%edi)
0x004c15ab:	call 0x004b6440
0x004c15b0:	popl %ecx
0x004c15b1:	popl %ecx
0x004c15b2:	pushl %eax
0x004c15b3:	pushl %ebx
0x004c15b4:	call LocalAlloc@KERNEL32.dll
0x004c15ba:	jmp 0x004c1619
0x004c1619:	cmpl %eax, %ebx
0x004c161b:	jne 0x004c162b
0x004c162b:	movl %ecx, 0x8(%esi)
0x004c162e:	movl 0xc(%esi), %eax
0x004c1631:	movl %edx, 0xc(%edi)
0x004c1634:	subl %edx, %ecx
0x004c1636:	shll %edx, $0x2<UINT8>
0x004c1639:	pushl %edx
0x004c163a:	leal %eax, (%eax,%ecx,4)
0x004c163d:	pushl %ebx
0x004c163e:	pushl %eax
0x004c163f:	call 0x004cb630
0x004c1644:	movl %eax, 0xc(%edi)
0x004c1647:	addl %esp, $0xc<UINT8>
0x004c164a:	pushl %esi
0x004c164b:	movl 0x8(%esi), %eax
0x004c164e:	pushl (%edi)
0x004c1650:	call TlsSetValue@KERNEL32.dll
0x004c1656:	movl %ecx, 0x8(%ebp)
0x004c1659:	movl %eax, 0xc(%esi)
0x004c165c:	cmpl %eax, %ebx
0x004c165e:	je 11
0x004c1660:	cmpl %ecx, 0x8(%esi)
0x004c1663:	jnl 6
0x004c1665:	movl %edx, 0xc(%ebp)
0x004c1668:	movl (%eax,%ecx,4), %edx
0x004c166b:	pushl -20(%ebp)
0x004c166e:	jmp 0x004c1671
0x004c1671:	call LeaveCriticalSection@KERNEL32.dll
0x004c1677:	call 0x004ce2cb
0x004ce2cb:	movl %ecx, -12(%ebp)
0x004ce2ce:	movl %fs:0, %ecx
0x004ce2d5:	popl %ecx
0x004ce2d6:	popl %edi
0x004ce2d7:	popl %edi
0x004ce2d8:	popl %esi
0x004ce2d9:	popl %ebx
0x004ce2da:	movl %esp, %ebp
0x004ce2dc:	popl %ebp
0x004ce2dd:	pushl %ecx
0x004ce2de:	ret

0x004c167c:	ret $0x8<UINT16>

0x004c180d:	movl %eax, %edi
0x004c180f:	call 0x004ce2cb
0x004c1814:	ret $0x4<UINT16>

0x004ad723:	testl %eax, %eax
0x004ad725:	jne 0x004ad72c
0x004ad72c:	movl %eax, 0x4(%eax)
0x004ad72f:	testl %eax, %eax
0x004ad731:	jne 19
0x004ad733:	pushl $0x4ad6e5<UINT32>
0x004ad738:	movl %ecx, $0x598ffc<UINT32>
0x004ad73d:	call 0x004c1269
0x004c1269:	pushl $0x8<UINT8>
0x004c126b:	movl %eax, $0x5275b0<UINT32>
0x004c1270:	call 0x004ce226
0x004c1275:	movl %esi, %ecx
0x004c1277:	movl %eax, (%esi)
0x004c1279:	testl %eax, %eax
0x004c127b:	jne 0x004c129e
0x004c127d:	pushl $0x10<UINT8>
0x004c127f:	call 0x004c2a52
0x004c2a52:	movl %edi, %edi
0x004c2a54:	pushl %ebp
0x004c2a55:	movl %ebp, %esp
0x004c2a57:	pushl %ebx
0x004c2a58:	pushl %esi
0x004c2a59:	pushl %edi
0x004c2a5a:	movl %edi, 0x8(%ebp)
0x004c2a5d:	cmpl %edi, $0x11<UINT8>
0x004c2a60:	jb 0x004c2a67
0x004c2a67:	cmpl 0x59acb4, $0x0<UINT8>
0x004c2a6e:	jne 0x004c2a75
0x004c2a70:	call 0x004c29e9
0x004c29e9:	cmpl 0x59acb4, $0x0<UINT8>
0x004c29f0:	jne 21
0x004c29f2:	pushl $0x59ae50<UINT32>
0x004c29f7:	movl 0x59acb4, $0x1<UINT32>
0x004c2a01:	call InitializeCriticalSection@KERNEL32.dll
0x004c2a07:	movl %eax, 0x59acb4
0x004c2a0c:	ret

0x004c2a75:	movl %ebx, 0x52a148
0x004c2a7b:	leal %esi, 0x59ae68(,%edi,4)
0x004c2a82:	cmpl (%esi), $0x0<UINT8>
0x004c2a85:	jne 0x004c2ab1
0x004c2a87:	pushl $0x59ae50<UINT32>
0x004c2a8c:	call EnterCriticalSection@KERNEL32.dll
0x004c2a8e:	cmpl (%esi), $0x0<UINT8>
0x004c2a91:	jne 19
0x004c2a93:	movl %eax, %edi
0x004c2a95:	imull %eax, %eax, $0x18<UINT8>
0x004c2a98:	addl %eax, $0x59acb8<UINT32>
0x004c2a9d:	pushl %eax
0x004c2a9e:	call InitializeCriticalSection@KERNEL32.dll
0x004c2aa4:	incl (%esi)
0x004c2aa6:	pushl $0x59ae50<UINT32>
0x004c2aab:	call LeaveCriticalSection@KERNEL32.dll
0x004c2ab1:	imull %edi, %edi, $0x18<UINT8>
0x004c2ab4:	addl %edi, $0x59acb8<UINT32>
0x004c2aba:	pushl %edi
0x004c2abb:	call EnterCriticalSection@KERNEL32.dll
0x004c2abd:	popl %edi
0x004c2abe:	popl %esi
0x004c2abf:	popl %ebx
0x004c2ac0:	popl %ebp
0x004c2ac1:	ret $0x4<UINT16>

0x004c1284:	movl %eax, (%esi)
0x004c1286:	andl -4(%ebp), $0x0<UINT8>
0x004c128a:	testl %eax, %eax
0x004c128c:	jne 5
0x004c128e:	call 0x004ad6e5
0x004ad6e5:	pushl $0x4<UINT8>
0x004ad6e7:	movl %eax, $0x526866<UINT32>
0x004ad6ec:	call 0x004ce1f3
0x004ad6f1:	pushl $0x8c<UINT32>
0x004ad6f6:	call 0x004c11ca
0x004ad6fb:	movl %ecx, %eax
0x004ad6fd:	movl -16(%ebp), %ecx
0x004ad700:	xorl %eax, %eax
0x004ad702:	movl -4(%ebp), %eax
0x004ad705:	cmpl %ecx, %eax
0x004ad707:	je 5
0x004ad709:	call 0x004ad6cf
0x004ad6cf:	movl %edi, %edi
0x004ad6d1:	pushl %esi
0x004ad6d2:	pushl $0x1<UINT8>
0x004ad6d4:	movl %esi, %ecx
0x004ad6d6:	call 0x004ad594
0x004ad594:	pushl $0xc<UINT8>
0x004ad596:	movl %eax, $0x526842<UINT32>
0x004ad59b:	call 0x004ce226
0x004ad5a0:	movl %esi, %ecx
0x004ad5a2:	movl -20(%ebp), %esi
0x004ad5a5:	movl (%esi), $0x541de0<UINT32>
0x00526842:	movl %edx, 0x8(%esp)
0x00526846:	leal %eax, 0xc(%edx)
0x00526849:	movl %ecx, -28(%edx)
0x0052684c:	xorl %ecx, %eax
0x0052684e:	call 0x004cb615
0x00526853:	movl %eax, $0x573ad0<UINT32>
0x00526858:	jmp 0x004cde9a
0x004ad5ab:	xorl %edi, %edi
0x004ad5ad:	movl 0x1c(%esi), %edi
0x004ad5b0:	movl 0x20(%esi), %edi
0x004ad5b3:	leal %ebx, 0x34(%esi)
0x004ad5b6:	movl %ecx, %ebx
0x004ad5b8:	movl 0x24(%esi), %edi
0x004ad5bb:	movl 0x28(%esi), %edi
0x004ad5be:	call 0x00401b40
0x00401b40:	pushl %ebp
0x00401b41:	movl %ebp, %esp
0x00401b43:	pushl %ecx
0x00401b44:	movl -4(%ebp), %ecx
0x00401b47:	call 0x00401b30
0x00401b30:	pushl %ebp
0x00401b31:	movl %ebp, %esp
0x00401b33:	call 0x004b637a
0x004b637a:	movl %eax, $0x59abd8<UINT32>
0x004b637f:	ret

0x00401b38:	popl %ebp
0x00401b39:	ret

0x00401b4c:	pushl %eax
0x00401b4d:	movl %ecx, -4(%ebp)
0x00401b50:	call 0x00401ae0
0x00401ae0:	pushl %ebp
0x00401ae1:	movl %ebp, %esp
0x00401ae3:	subl %esp, $0xc<UINT8>
0x00401ae6:	movl -12(%ebp), %ecx
0x00401ae9:	xorl %eax, %eax
0x00401aeb:	cmpl 0x8(%ebp), $0x0<UINT8>
0x00401aef:	setne %al
0x00401af2:	movl -8(%ebp), %eax
0x00401af5:	cmpl -8(%ebp), $0x0<UINT8>
0x00401af9:	jne 0x00401b05
0x00401b05:	xorl %ecx, %ecx
0x00401b07:	jne -32
0x00401b09:	movl %edx, 0x8(%ebp)
0x00401b0c:	movl %eax, (%edx)
0x00401b0e:	movl %ecx, 0x8(%ebp)
0x00401b11:	movl %edx, 0xc(%eax)
0x00401b14:	call 0x004b648a
0x004b648a:	xorl %edx, %edx
0x004b648c:	leal %eax, 0x10(%ecx)
0x004b648f:	incl %edx
0x004b6490:	xaddl (%eax), %edx
0x004b6494:	leal %eax, 0x4(%ecx)
0x004b6497:	ret

0x00401b16:	movl -4(%ebp), %eax
0x00401b19:	movl %eax, -4(%ebp)
0x00401b1c:	pushl %eax
0x00401b1d:	movl %ecx, -12(%ebp)
0x00401b20:	call 0x00402330
0x00402330:	pushl %ebp
0x00402331:	movl %ebp, %esp
0x00402333:	pushl %ecx
0x00402334:	movl -4(%ebp), %ecx
0x00402337:	movl %ecx, 0x8(%ebp)
0x0040233a:	call 0x00402310
0x00402310:	pushl %ebp
0x00402311:	movl %ebp, %esp
0x00402313:	pushl %ecx
0x00402314:	movl -4(%ebp), %ecx
0x00402317:	movl %eax, -4(%ebp)
0x0040231a:	addl %eax, $0x10<UINT8>
0x0040231d:	movl %esp, %ebp
0x0040231f:	popl %ebp
0x00402320:	ret

0x0040233f:	movl %ecx, -4(%ebp)
0x00402342:	movl (%ecx), %eax
0x00402344:	movl %esp, %ebp
0x00402346:	popl %ebp
0x00402347:	ret $0x4<UINT16>

0x00401b25:	movl %eax, -12(%ebp)
0x00401b28:	movl %esp, %ebp
0x00401b2a:	popl %ebp
0x00401b2b:	ret $0x4<UINT16>

0x00401b55:	movl %eax, -4(%ebp)
0x00401b58:	movl %esp, %ebp
0x00401b5a:	popl %ebp
0x00401b5b:	ret

0x004ad5c3:	movl 0x40(%esi), %edi
0x004ad5c6:	movl 0x44(%esi), %edi
0x004ad5c9:	orl 0x50(%esi), $0xffffffff<UINT8>
0x004ad5cd:	movl -4(%ebp), %edi
0x004ad5d0:	movl 0x54(%esi), %edi
0x004ad5d3:	movl 0x68(%esi), %edi
0x004ad5d6:	movl 0x6c(%esi), %edi
0x004ad5d9:	movb %al, 0x8(%ebp)
0x004ad5dc:	pushl $0x1000<UINT32>
0x004ad5e1:	movl %ecx, %ebx
0x004ad5e3:	movl 0x28(%esi), $0x20<UINT32>
0x004ad5ea:	movl 0x20(%esi), $0x14<UINT32>
0x004ad5f1:	movl 0x18(%esi), %edi
0x004ad5f4:	movb 0x14(%esi), %al
0x004ad5f7:	movb -4(%ebp), $0x2<UINT8>
0x004ad5fb:	call 0x00401dc0
0x00401dc0:	pushl %ebp
0x00401dc1:	movl %ebp, %esp
0x00401dc3:	subl %esp, $0x10<UINT8>
0x00401dc6:	movl -16(%ebp), %ecx
0x00401dc9:	movl %ecx, -16(%ebp)
0x00401dcc:	call 0x00402260
0x00402260:	pushl %ebp
0x00402261:	movl %ebp, %esp
0x00402263:	pushl %ecx
0x00402264:	movl -4(%ebp), %ecx
0x00402267:	movl %eax, -4(%ebp)
0x0040226a:	movl %eax, (%eax)
0x0040226c:	subl %eax, $0x10<UINT8>
0x0040226f:	movl %esp, %ebp
0x00402271:	popl %ebp
0x00402272:	ret

0x00401dd1:	movl -12(%ebp), %eax
0x00401dd4:	movl %eax, -12(%ebp)
0x00401dd7:	movl %ecx, $0x1<UINT32>
0x00401ddc:	subl %ecx, 0xc(%eax)
0x00401ddf:	movl -4(%ebp), %ecx
0x00401de2:	movl %edx, -12(%ebp)
0x00401de5:	movl %eax, 0x8(%edx)
0x00401de8:	subl %eax, 0x8(%ebp)
0x00401deb:	movl -8(%ebp), %eax
0x00401dee:	movl %ecx, -4(%ebp)
0x00401df1:	orl %ecx, -8(%ebp)
0x00401df4:	jnl 12
0x00401df6:	movl %edx, 0x8(%ebp)
0x00401df9:	pushl %edx
0x00401dfa:	movl %ecx, -16(%ebp)
0x00401dfd:	call 0x00401d20
0x00401d20:	pushl %ebp
0x00401d21:	movl %ebp, %esp
0x00401d23:	subl %esp, $0xc<UINT8>
0x00401d26:	movl -12(%ebp), %ecx
0x00401d29:	movl %ecx, -12(%ebp)
0x00401d2c:	call 0x00402260
0x00401d31:	movl -4(%ebp), %eax
0x00401d34:	movl %eax, -4(%ebp)
0x00401d37:	movl %ecx, 0x4(%eax)
0x00401d3a:	cmpl %ecx, 0x8(%ebp)
0x00401d3d:	jle 0x00401d48
0x00401d48:	movl %ecx, -4(%ebp)
0x00401d4b:	call 0x00401bc0
0x00401bc0:	pushl %ebp
0x00401bc1:	movl %ebp, %esp
0x00401bc3:	pushl %ecx
0x00401bc4:	movl -4(%ebp), %ecx
0x00401bc7:	movl %eax, -4(%ebp)
0x00401bca:	xorl %ecx, %ecx
0x00401bcc:	cmpl 0xc(%eax), $0x1<UINT8>
0x00401bd0:	setg %cl
0x00401bd3:	movb %al, %cl
0x00401bd5:	movl %esp, %ebp
0x00401bd7:	popl %ebp
0x00401bd8:	ret

0x00401d50:	movzbl %ecx, %al
0x00401d53:	testl %ecx, %ecx
0x00401d55:	je 14
0x00401d57:	movl %edx, 0x8(%ebp)
0x00401d5a:	pushl %edx
0x00401d5b:	movl %ecx, -12(%ebp)
0x00401d5e:	call 0x00401be0
0x00401be0:	pushl %ebp
0x00401be1:	movl %ebp, %esp
0x00401be3:	subl %esp, $0x1c<UINT8>
0x00401be6:	movl -20(%ebp), %ecx
0x00401be9:	movl %ecx, -20(%ebp)
0x00401bec:	call 0x00402260
0x00401bf1:	movl -16(%ebp), %eax
0x00401bf4:	movl %eax, -16(%ebp)
0x00401bf7:	movl %ecx, 0x4(%eax)
0x00401bfa:	movl -8(%ebp), %ecx
0x00401bfd:	movl %edx, -16(%ebp)
0x00401c00:	movl %eax, (%edx)
0x00401c02:	movl %ecx, -16(%ebp)
0x00401c05:	movl %ecx, (%ecx)
0x00401c07:	movl %edx, (%eax)
0x00401c09:	movl %eax, 0x10(%edx)
0x00401c0c:	call 0x004b6af3
0x004b6af3:	movl %eax, %ecx
0x004b6af5:	ret

0x00401c0e:	movl -24(%ebp), %eax
0x00401c11:	pushl $0x2<UINT8>
0x00401c13:	movl %ecx, 0x8(%ebp)
0x00401c16:	pushl %ecx
0x00401c17:	movl %edx, -24(%ebp)
0x00401c1a:	movl %eax, (%edx)
0x00401c1c:	movl %ecx, -24(%ebp)
0x00401c1f:	movl %edx, (%eax)
0x00401c21:	call 0x004b6380
0x004b6380:	movl %edi, %edi
0x004b6382:	pushl %ebp
0x004b6383:	movl %ebp, %esp
0x004b6385:	pushl %esi
0x004b6386:	movl %esi, 0x8(%ebp)
0x004b6389:	pushl %edi
0x004b638a:	movl %edi, %ecx
0x004b638c:	testl %esi, %esi
0x004b638e:	jnl 0x004b6394
0x004b6394:	leal %eax, 0x1(%esi)
0x004b6397:	imull %eax, 0xc(%ebp)
0x004b639b:	addl %eax, $0x10<UINT8>
0x004b639e:	pushl %eax
0x004b639f:	call 0x004cebd4
0x004b63a4:	popl %ecx
0x004b63a5:	testl %eax, %eax
0x004b63a7:	je -25
0x004b63a9:	andl 0x4(%eax), $0x0<UINT8>
0x004b63ad:	movl (%eax), %edi
0x004b63af:	movl 0xc(%eax), $0x1<UINT32>
0x004b63b6:	movl 0x8(%eax), %esi
0x004b63b9:	popl %edi
0x004b63ba:	popl %esi
0x004b63bb:	popl %ebp
0x004b63bc:	ret $0x8<UINT16>

0x00401c23:	movl -12(%ebp), %eax
0x00401c26:	cmpl -12(%ebp), $0x0<UINT8>
0x00401c2a:	jne 0x00401c31
0x00401c31:	movl %eax, -8(%ebp)
0x00401c34:	cmpl %eax, 0x8(%ebp)
0x00401c37:	jnl 8
0x00401c39:	movl %ecx, -8(%ebp)
0x00401c3c:	movl -28(%ebp), %ecx
0x00401c3f:	jmp 0x00401c47
0x00401c47:	movl %eax, -28(%ebp)
0x00401c4a:	addl %eax, $0x1<UINT8>
0x00401c4d:	movl -4(%ebp), %eax
0x00401c50:	movl %ecx, -4(%ebp)
0x00401c53:	pushl %ecx
0x00401c54:	movl %ecx, -16(%ebp)
0x00401c57:	call 0x00402310
0x00401c5c:	pushl %eax
0x00401c5d:	movl %edx, -4(%ebp)
0x00401c60:	pushl %edx
0x00401c61:	movl %ecx, -12(%ebp)
0x00401c64:	call 0x00402310
0x00401c69:	pushl %eax
0x00401c6a:	call 0x00402730
0x00402730:	pushl %ebp
0x00402731:	movl %ebp, %esp
0x00402733:	movl %eax, 0x14(%ebp)
0x00402736:	shll %eax
0x00402738:	pushl %eax
0x00402739:	movl %ecx, 0x10(%ebp)
0x0040273c:	pushl %ecx
0x0040273d:	movl %edx, 0xc(%ebp)
0x00402740:	shll %edx
0x00402742:	pushl %edx
0x00402743:	movl %eax, 0x8(%ebp)
0x00402746:	pushl %eax
0x00402747:	call 0x004cbb35
0x004cbb35:	movl %edi, %edi
0x004cbb37:	pushl %ebp
0x004cbb38:	movl %ebp, %esp
0x004cbb3a:	pushl %esi
0x004cbb3b:	movl %esi, 0x14(%ebp)
0x004cbb3e:	pushl %edi
0x004cbb3f:	xorl %edi, %edi
0x004cbb41:	cmpl %esi, %edi
0x004cbb43:	jne 0x004cbb49
0x004cbb49:	cmpl 0x8(%ebp), %edi
0x004cbb4c:	jne 0x004cbb69
0x004cbb69:	cmpl 0x10(%ebp), %edi
0x004cbb6c:	je 22
0x004cbb6e:	cmpl 0xc(%ebp), %esi
0x004cbb71:	jb 17
0x004cbb73:	pushl %esi
0x004cbb74:	pushl 0x10(%ebp)
0x004cbb77:	pushl 0x8(%ebp)
0x004cbb7a:	call 0x004cb7d0
0x004cb7e8:	cmpl %edi, %eax
0x004cb7ea:	jb 420
0x004cb854:	jmp 0x004cb908
0x004cb93b:	jmp 0x004cb968
0x004cb968:	movb %al, (%esi)
0x004cb96a:	movb (%edi), %al
0x004cb96c:	movb %al, 0x1(%esi)
0x004cb96f:	movb 0x1(%edi), %al
0x004cb972:	movl %eax, 0x8(%ebp)
0x004cb975:	popl %esi
0x004cb976:	popl %edi
0x004cb977:	leave
0x004cb978:	ret

0x004cbb7f:	addl %esp, $0xc<UINT8>
0x004cbb82:	jmp 0x004cbb45
0x004cbb45:	xorl %eax, %eax
0x004cbb47:	jmp 0x004cbbae
0x004cbbae:	popl %edi
0x004cbbaf:	popl %esi
0x004cbbb0:	popl %ebp
0x004cbbb1:	ret

0x0040274c:	addl %esp, $0x10<UINT8>
0x0040274f:	popl %ebp
0x00402750:	ret

0x00401c6f:	addl %esp, $0x10<UINT8>
0x00401c72:	movl %eax, -12(%ebp)
0x00401c75:	movl %ecx, -8(%ebp)
0x00401c78:	movl 0x4(%eax), %ecx
0x00401c7b:	movl %ecx, -16(%ebp)
0x00401c7e:	call 0x004022d0
0x004022d0:	pushl %ebp
0x004022d1:	movl %ebp, %esp
0x004022d3:	pushl %ecx
0x004022d4:	movl -4(%ebp), %ecx
0x004022d7:	movl %eax, -4(%ebp)
0x004022da:	addl %eax, $0xc<UINT8>
0x004022dd:	orl %ecx, $0xffffffff<UINT8>
0x004022e0:	xaddl (%eax), %ecx
0x004022e4:	decl %ecx
0x004022e5:	testl %ecx, %ecx
0x004022e7:	jg 0x00402300
0x00402300:	movl %esp, %ebp
0x00402302:	popl %ebp
0x00402303:	ret

0x00401c83:	movl %edx, -12(%ebp)
0x00401c86:	pushl %edx
0x00401c87:	movl %ecx, -20(%ebp)
0x00401c8a:	call 0x00402330
0x00401c8f:	movl %esp, %ebp
0x00401c91:	popl %ebp
0x00401c92:	ret $0x4<UINT16>

0x00401d63:	jmp 0x00401db2
0x00401db2:	movl %esp, %ebp
0x00401db4:	popl %ebp
0x00401db5:	ret $0x4<UINT16>

0x00401e02:	movl %eax, -16(%ebp)
0x00401e05:	movl %eax, (%eax)
0x00401e07:	movl %esp, %ebp
0x00401e09:	popl %ebp
0x00401e0a:	ret $0x4<UINT16>

0x004ad600:	xorl %ebx, %ebx
0x004ad602:	incl %ebx
0x004ad603:	movl -4(%ebp), %ebx
0x004ad606:	jmp 0x004ad629
0x004ad629:	pushl $0xc<UINT8>
0x004ad62b:	movl 0x30(%esi), %ebx
0x004ad62e:	movl 0x44(%esi), $0x18<UINT32>
0x004ad635:	call 0x004accfa
0x004accfa:	movl %edi, %edi
0x004accfc:	pushl %ebp
0x004accfd:	movl %ebp, %esp
0x004accff:	pushl %esi
0x004acd00:	jmp 0x004acd15
0x004acd15:	pushl 0x8(%ebp)
0x004acd18:	call 0x004cebd4
0x004acd1d:	movl %esi, %eax
0x004acd1f:	popl %ecx
0x004acd20:	testl %esi, %esi
0x004acd22:	je -34
0x004acd24:	movl %eax, %esi
0x004acd26:	popl %esi
0x004acd27:	popl %ebp
0x004acd28:	ret

0x004ad63a:	movl 0x78(%esi), %eax
0x004ad63d:	movl (%esp), $0x188<UINT32>
0x004ad644:	call 0x004c11ca
0x004ad649:	movl %ecx, %eax
0x004ad64b:	movl 0x8(%ebp), %ecx
0x004ad64e:	movb -4(%ebp), $0x4<UINT8>
0x004ad652:	cmpl %ecx, %edi
0x004ad654:	je 7
0x004ad656:	call 0x004ad286
0x004ad286:	pushl $0x4<UINT8>
0x004ad288:	movl %eax, $0x5277c2<UINT32>
0x004ad28d:	call 0x004ce1f3
0x004ad292:	movl %esi, %ecx
0x004ad294:	pushl $0x541df4<UINT32>
0x004ad299:	leal %ecx, -16(%ebp)
0x004ad29c:	call 0x00402b20
0x00402b20:	pushl %ebp
0x00402b21:	movl %ebp, %esp
0x00402b23:	pushl $0xffffffff<UINT8>
0x00402b25:	pushl $0x5298b8<UINT32>
0x00402b2a:	movl %eax, %fs:0
0x00402b30:	pushl %eax
0x00402b31:	pushl %ecx
0x00402b32:	movl %eax, 0x594ea0
0x00402b37:	xorl %eax, %ebp
0x00402b39:	pushl %eax
0x00402b3a:	leal %eax, -12(%ebp)
0x00402b3d:	movl %fs:0, %eax
0x00402b43:	movl -16(%ebp), %ecx
0x00402b46:	call 0x00401b30
0x00402b4b:	pushl %eax
0x00402b4c:	movl %ecx, -16(%ebp)
0x00402b4f:	call 0x00401ae0
0x00402b54:	movl -4(%ebp), $0x0<UINT32>
0x00402b5b:	movl %eax, 0x8(%ebp)
0x00402b5e:	pushl %eax
0x00402b5f:	movl %ecx, -16(%ebp)
0x00402b62:	call 0x004028a0
0x004028a0:	pushl %ebp
0x004028a1:	movl %ebp, %esp
0x004028a3:	subl %esp, $0xc<UINT8>
0x004028a6:	movl -12(%ebp), %ecx
0x004028a9:	movb -1(%ebp), $0x0<UINT8>
0x004028ad:	cmpl 0x8(%ebp), $0x0<UINT8>
0x004028b1:	je 41
0x004028b3:	movl %eax, 0x8(%ebp)
0x004028b6:	shrl %eax, $0x10<UINT8>
0x004028b9:	testl %eax, %eax
0x004028bb:	jne 0x004028dc
0x004028dc:	movb %al, -1(%ebp)
0x004028df:	movl %esp, %ebp
0x004028e1:	popl %ebp
0x004028e2:	ret $0x4<UINT16>

0x00402b67:	movzbl %ecx, %al
0x00402b6a:	testl %ecx, %ecx
0x00402b6c:	jne 12
0x00402b6e:	movl %edx, 0x8(%ebp)
0x00402b71:	pushl %edx
0x00402b72:	movl %ecx, -16(%ebp)
0x00402b75:	call 0x00402b00
0x00402b00:	pushl %ebp
0x00402b01:	movl %ebp, %esp
0x00402b03:	pushl %ecx
0x00402b04:	movl -4(%ebp), %ecx
0x00402b07:	movl %eax, 0x8(%ebp)
0x00402b0a:	pushl %eax
0x00402b0b:	movl %ecx, -4(%ebp)
0x00402b0e:	call 0x00402ae0
0x00402ae0:	pushl %ebp
0x00402ae1:	movl %ebp, %esp
0x00402ae3:	pushl %ecx
0x00402ae4:	movl -4(%ebp), %ecx
0x00402ae7:	movl %eax, 0x8(%ebp)
0x00402aea:	pushl %eax
0x00402aeb:	movl %ecx, -4(%ebp)
0x00402aee:	call 0x00402ab0
0x00402ab0:	pushl %ebp
0x00402ab1:	movl %ebp, %esp
0x00402ab3:	pushl %ecx
0x00402ab4:	movl -4(%ebp), %ecx
0x00402ab7:	movl %eax, 0x8(%ebp)
0x00402aba:	pushl %eax
0x00402abb:	call 0x00402a90
0x00402a90:	pushl %ebp
0x00402a91:	movl %ebp, %esp
0x00402a93:	cmpl 0x8(%ebp), $0x0<UINT8>
0x00402a97:	jne 0x00402a9d
0x00402a9d:	movl %eax, 0x8(%ebp)
0x00402aa0:	pushl %eax
0x00402aa1:	call 0x004cbefb
0x00402aa6:	addl %esp, $0x4<UINT8>
0x00402aa9:	popl %ebp
0x00402aaa:	ret

0x00402ac0:	addl %esp, $0x4<UINT8>
0x00402ac3:	pushl %eax
0x00402ac4:	movl %ecx, 0x8(%ebp)
0x00402ac7:	pushl %ecx
0x00402ac8:	movl %ecx, -4(%ebp)
0x00402acb:	call 0x004029d0
0x004029d0:	pushl %ebp
0x004029d1:	movl %ebp, %esp
0x004029d3:	subl %esp, $0x10<UINT8>
0x004029d6:	movl -16(%ebp), %ecx
0x004029d9:	cmpl 0xc(%ebp), $0x0<UINT8>
0x004029dd:	jne 0x004029ec
0x004029ec:	cmpl 0x8(%ebp), $0x0<UINT8>
0x004029f0:	jne 0x004029fc
0x004029fc:	movl %ecx, -16(%ebp)
0x004029ff:	call 0x004017c0
0x004017c0:	pushl %ebp
0x004017c1:	movl %ebp, %esp
0x004017c3:	pushl %ecx
0x004017c4:	movl -4(%ebp), %ecx
0x004017c7:	movl %ecx, -4(%ebp)
0x004017ca:	call 0x00402260
0x004017cf:	movl %eax, 0x4(%eax)
0x004017d2:	movl %esp, %ebp
0x004017d4:	popl %ebp
0x004017d5:	ret

0x00402a04:	movl -4(%ebp), %eax
0x00402a07:	movl %ecx, -16(%ebp)
0x00402a0a:	call 0x00401f10
0x00401f10:	pushl %ebp
0x00401f11:	movl %ebp, %esp
0x00401f13:	pushl %ecx
0x00401f14:	movl -4(%ebp), %ecx
0x00401f17:	movl %eax, -4(%ebp)
0x00401f1a:	movl %eax, (%eax)
0x00401f1c:	movl %esp, %ebp
0x00401f1e:	popl %ebp
0x00401f1f:	ret

0x00402a0f:	movl %ecx, 0x8(%ebp)
0x00402a12:	subl %ecx, %eax
0x00402a14:	sarl %ecx
0x00402a16:	movl -8(%ebp), %ecx
0x00402a19:	movl %edx, 0xc(%ebp)
0x00402a1c:	pushl %edx
0x00402a1d:	movl %ecx, -16(%ebp)
0x00402a20:	call 0x00401e10
0x00401e10:	pushl %ebp
0x00401e11:	movl %ebp, %esp
0x00401e13:	pushl %ecx
0x00401e14:	movl -4(%ebp), %ecx
0x00401e17:	movl %eax, 0x8(%ebp)
0x00401e1a:	pushl %eax
0x00401e1b:	movl %ecx, -4(%ebp)
0x00401e1e:	call 0x00401dc0
0x00401e23:	movl %esp, %ebp
0x00401e25:	popl %ebp
0x00401e26:	ret $0x4<UINT16>

0x00402a25:	movl -12(%ebp), %eax
0x00402a28:	movl %eax, -8(%ebp)
0x00402a2b:	cmpl %eax, -4(%ebp)
0x00402a2e:	ja 0x00402a55
0x00402a55:	movl %eax, 0xc(%ebp)
0x00402a58:	pushl %eax
0x00402a59:	movl %ecx, 0x8(%ebp)
0x00402a5c:	pushl %ecx
0x00402a5d:	movl %ecx, -16(%ebp)
0x00402a60:	call 0x004029b0
0x004029b0:	pushl %ebp
0x004029b1:	movl %ebp, %esp
0x004029b3:	pushl %ecx
0x004029b4:	movl -4(%ebp), %ecx
0x004029b7:	movl %ecx, -4(%ebp)
0x004029ba:	call 0x00402260
0x004029bf:	movl %eax, 0x8(%eax)
0x004029c2:	movl %esp, %ebp
0x004029c4:	popl %ebp
0x004029c5:	ret

0x00402a65:	pushl %eax
0x00402a66:	movl %edx, -12(%ebp)
0x00402a69:	pushl %edx
0x00402a6a:	call 0x00402730
0x004cb900:	movl %eax, -24(%esi,%ecx,4)
0x004cb904:	movl -24(%edi,%ecx,4), %eax
0x004cb908:	movl %eax, -20(%esi,%ecx,4)
0x004cb90c:	movl -20(%edi,%ecx,4), %eax
0x004cb910:	movl %eax, -16(%esi,%ecx,4)
0x004cb914:	movl -16(%edi,%ecx,4), %eax
0x004cb918:	movl %eax, -12(%esi,%ecx,4)
0x004cb91c:	movl -12(%edi,%ecx,4), %eax
0x004cb920:	movl %eax, -8(%esi,%ecx,4)
0x004cb924:	movl -8(%edi,%ecx,4), %eax
0x004cb928:	movl %eax, -4(%esi,%ecx,4)
0x004cb92c:	movl -4(%edi,%ecx,4), %eax
0x004cb930:	leal %eax, (,%ecx,4)
0x004cb937:	addl %esi, %eax
0x004cb939:	addl %edi, %eax
0x00402a6f:	addl %esp, $0x10<UINT8>
0x00402a72:	movl %eax, 0xc(%ebp)
0x00402a75:	pushl %eax
0x00402a76:	movl %ecx, -16(%ebp)
0x00402a79:	call 0x00401e50
0x00401e50:	pushl %ebp
0x00401e51:	movl %ebp, %esp
0x00401e53:	pushl %ecx
0x00401e54:	movl -4(%ebp), %ecx
0x00401e57:	movl %eax, 0x8(%ebp)
0x00401e5a:	pushl %eax
0x00401e5b:	movl %ecx, -4(%ebp)
0x00401e5e:	call 0x00402280
0x00402280:	pushl %ebp
0x00402281:	movl %ebp, %esp
0x00402283:	pushl %ecx
0x00402284:	movl -4(%ebp), %ecx
0x00402287:	cmpl 0x8(%ebp), $0x0<UINT8>
0x0040228b:	jl 16
0x0040228d:	movl %ecx, -4(%ebp)
0x00402290:	call 0x00402260
0x00402295:	movl %ecx, 0x8(%ebp)
0x00402298:	cmpl %ecx, 0x8(%eax)
0x0040229b:	jle 0x004022a7
0x004022a7:	movl %ecx, -4(%ebp)
0x004022aa:	call 0x00402260
0x004022af:	movl %edx, 0x8(%ebp)
0x004022b2:	movl 0x4(%eax), %edx
0x004022b5:	movl %eax, -4(%ebp)
0x004022b8:	movl %ecx, (%eax)
0x004022ba:	xorl %edx, %edx
0x004022bc:	movl %eax, 0x8(%ebp)
0x004022bf:	movw (%ecx,%eax,2), %dx
0x004022c3:	movl %esp, %ebp
0x004022c5:	popl %ebp
0x004022c6:	ret $0x4<UINT16>

0x00401e63:	movl %esp, %ebp
0x00401e65:	popl %ebp
0x00401e66:	ret $0x4<UINT16>

0x00402a7e:	movl %esp, %ebp
0x00402a80:	popl %ebp
0x00402a81:	ret $0x8<UINT16>

0x00402ad0:	movl %esp, %ebp
0x00402ad2:	popl %ebp
0x00402ad3:	ret $0x4<UINT16>

0x00402af3:	movl %eax, -4(%ebp)
0x00402af6:	movl %esp, %ebp
0x00402af8:	popl %ebp
0x00402af9:	ret $0x4<UINT16>

0x00402b13:	movl %eax, -4(%ebp)
0x00402b16:	movl %esp, %ebp
0x00402b18:	popl %ebp
0x00402b19:	ret $0x4<UINT16>

0x00402b7a:	movl -4(%ebp), $0xffffffff<UINT32>
0x00402b81:	movl %eax, -16(%ebp)
0x00402b84:	movl %ecx, -12(%ebp)
0x00402b87:	movl %fs:0, %ecx
0x00402b8e:	popl %ecx
0x00402b8f:	movl %esp, %ebp
0x00402b91:	popl %ebp
0x00402b92:	ret $0x4<UINT16>

0x004ad2a1:	leal %eax, -16(%ebp)
0x004ad2a4:	xorl %edi, %edi
0x004ad2a6:	pushl %eax
0x004ad2a7:	movl %ecx, %esi
0x004ad2a9:	movl -4(%ebp), %edi
0x004ad2ac:	call 0x004ad218
0x004ad218:	movl %edi, %edi
0x004ad21a:	pushl %ebp
0x004ad21b:	movl %ebp, %esp
0x004ad21d:	pushl %esi
0x004ad21e:	pushl 0x8(%ebp)
0x004ad221:	movl %esi, %ecx
0x004ad223:	leal %ecx, 0xc(%esi)
0x004ad226:	movl (%esi), $0x541de8<UINT32>
0x004ad22c:	call 0x004ad131
0x004ad131:	movl %edi, %edi
0x004ad133:	pushl %ebp
0x004ad134:	movl %ebp, %esp
0x004ad136:	pushl %esi
0x004ad137:	pushl 0x8(%ebp)
0x004ad13a:	movl %esi, %ecx
0x004ad13c:	call 0x004ad08f
0x004ad08f:	movl %edi, %edi
0x004ad091:	pushl %ebp
0x004ad092:	movl %ebp, %esp
0x004ad094:	movl %eax, 0x8(%ebp)
0x004ad097:	movl %eax, (%eax)
0x004ad099:	pushl %esi
0x004ad09a:	subl %eax, $0x10<UINT8>
0x004ad09d:	pushl %eax
0x004ad09e:	movl %esi, %ecx
0x004ad0a0:	call 0x00402dc0
0x00402dc0:	pushl %ebp
0x00402dc1:	movl %ebp, %esp
0x00402dc3:	subl %esp, $0x8<UINT8>
0x00402dc6:	movl -4(%ebp), $0x0<UINT32>
0x00402dcd:	movl %eax, 0x8(%ebp)
0x00402dd0:	movl %ecx, (%eax)
0x00402dd2:	movl %edx, 0x8(%ebp)
0x00402dd5:	movl %eax, (%edx)
0x00402dd7:	movl %edx, (%ecx)
0x00402dd9:	movl %ecx, %eax
0x00402ddb:	movl %eax, 0x10(%edx)
0x00402dde:	call 0x004b6af3
0x00402de0:	movl -8(%ebp), %eax
0x00402de3:	movl %ecx, 0x8(%ebp)
0x00402de6:	call 0x004028f0
0x004028f0:	pushl %ebp
0x004028f1:	movl %ebp, %esp
0x004028f3:	pushl %ecx
0x004028f4:	movl -4(%ebp), %ecx
0x004028f7:	movl %eax, -4(%ebp)
0x004028fa:	xorl %ecx, %ecx
0x004028fc:	cmpl 0xc(%eax), $0x0<UINT8>
0x00402900:	setl %cl
0x00402903:	movb %al, %cl
0x00402905:	movl %esp, %ebp
0x00402907:	popl %ebp
0x00402908:	ret

0x00402deb:	movzbl %ecx, %al
0x00402dee:	testl %ecx, %ecx
0x00402df0:	jne 26
0x00402df2:	movl %edx, 0x8(%ebp)
0x00402df5:	movl %eax, -8(%ebp)
0x00402df8:	cmpl %eax, (%edx)
0x00402dfa:	jne 16
0x00402dfc:	movl %ecx, 0x8(%ebp)
0x00402dff:	movl -4(%ebp), %ecx
0x00402e02:	movl %ecx, -4(%ebp)
0x00402e05:	call 0x00402f20
0x00402f20:	pushl %ebp
0x00402f21:	movl %ebp, %esp
0x00402f23:	pushl %ecx
0x00402f24:	movl -4(%ebp), %ecx
0x00402f27:	movl %eax, -4(%ebp)
0x00402f2a:	addl %eax, $0xc<UINT8>
0x00402f2d:	movl %ecx, $0x1<UINT32>
0x00402f32:	xaddl (%eax), %ecx
0x00402f36:	movl %esp, %ebp
0x00402f38:	popl %ebp
0x00402f39:	ret

0x00402e0a:	jmp 0x00402e69
0x00402e69:	movl %eax, -4(%ebp)
0x00402e6c:	movl %esp, %ebp
0x00402e6e:	popl %ebp
0x00402e6f:	ret

0x004ad0a5:	addl %eax, $0x10<UINT8>
0x004ad0a8:	movl (%esi), %eax
0x004ad0aa:	popl %ecx
0x004ad0ab:	movl %eax, %esi
0x004ad0ad:	popl %esi
0x004ad0ae:	popl %ebp
0x004ad0af:	ret $0x4<UINT16>

0x004ad141:	movl %eax, %esi
0x004ad143:	popl %esi
0x004ad144:	popl %ebp
0x004ad145:	ret $0x4<UINT16>

0x004ad231:	andl 0x4(%esi), $0x0<UINT8>
0x004ad235:	movb 0x8(%esi), $0x0<UINT8>
0x004ad239:	movl %eax, %esi
0x004ad23b:	popl %esi
0x004ad23c:	popl %ebp
0x004ad23d:	ret $0x4<UINT16>

0x004ad2b1:	movl %ecx, -16(%ebp)
0x004ad2b4:	addl %ecx, $0xfffffff0<UINT8>
0x004ad2b7:	call 0x004022d0
0x004ad2bc:	movl (%esi), $0x541df0<UINT32>
0x004ad2c2:	movl 0x10(%esi), %edi
0x004ad2c5:	movl 0x14(%esi), %edi
0x004ad2c8:	movl 0x18(%esi), %edi
0x004ad2cb:	movl 0x1c(%esi), %edi
0x004ad2ce:	movl 0x20(%esi), %edi
0x004ad2d1:	movl 0x24(%esi), %edi
0x004ad2d4:	movl 0x28(%esi), %edi
0x004ad2d7:	movl 0x2c(%esi), %edi
0x004ad2da:	movl 0x30(%esi), %edi
0x004ad2dd:	movl 0x34(%esi), %edi
0x004ad2e0:	movl 0x38(%esi), %edi
0x004ad2e3:	movl 0x3c(%esi), %edi
0x004ad2e6:	movl 0x40(%esi), %edi
0x004ad2e9:	movl 0x44(%esi), %edi
0x004ad2ec:	movl 0x48(%esi), %edi
0x004ad2ef:	movl 0x4c(%esi), %edi
0x004ad2f2:	movl 0x50(%esi), %edi
0x004ad2f5:	movl 0x54(%esi), %edi
0x004ad2f8:	movl 0x58(%esi), %edi
0x004ad2fb:	movl 0x5c(%esi), %edi
0x004ad2fe:	movl 0x60(%esi), %edi
0x004ad301:	movl 0x64(%esi), %edi
0x004ad304:	movl 0x68(%esi), %edi
0x004ad307:	movl 0x6c(%esi), %edi
0x004ad30a:	movl 0x70(%esi), %edi
0x004ad30d:	movl 0x74(%esi), %edi
0x004ad310:	movl 0x78(%esi), %edi
0x004ad313:	movl 0x7c(%esi), %edi
0x004ad316:	movl 0x80(%esi), %edi
0x004ad31c:	movl 0x84(%esi), %edi
0x004ad322:	movl 0x88(%esi), %edi
0x004ad328:	movl 0x8c(%esi), %edi
0x004ad32e:	movl 0x90(%esi), %edi
0x004ad334:	movl 0x94(%esi), %edi
0x004ad33a:	movl 0x98(%esi), %edi
0x004ad340:	movl 0x9c(%esi), %edi
0x004ad346:	movl 0xa0(%esi), %edi
0x004ad34c:	movl 0xa4(%esi), %edi
0x004ad352:	movl 0xa8(%esi), %edi
0x004ad358:	movl 0xac(%esi), %edi
0x004ad35e:	movl 0xb0(%esi), %edi
0x004ad364:	movl 0xb4(%esi), %edi
0x004ad36a:	movl 0xb8(%esi), %edi
0x004ad370:	movl 0xbc(%esi), %edi
0x004ad376:	movl 0xc0(%esi), %edi
0x004ad37c:	movl 0xc4(%esi), %edi
0x004ad382:	movl 0xc8(%esi), %edi
0x004ad388:	movl 0xcc(%esi), %edi
0x004ad38e:	movl 0xd0(%esi), %edi
0x004ad394:	movl 0xd4(%esi), %edi
0x004ad39a:	movl 0xd8(%esi), %edi
0x004ad3a0:	movl 0xdc(%esi), %edi
0x004ad3a6:	movl 0xe0(%esi), %edi
0x004ad3ac:	movl 0xe4(%esi), %edi
0x004ad3b2:	movl 0xe8(%esi), %edi
0x004ad3b8:	movl 0xec(%esi), %edi
0x004ad3be:	movl 0xf0(%esi), %edi
0x004ad3c4:	movl 0xf4(%esi), %edi
0x004ad3ca:	movl 0xf8(%esi), %edi
0x004ad3d0:	movl 0xfc(%esi), %edi
0x004ad3d6:	movl 0x100(%esi), %edi
0x004ad3dc:	movl 0x104(%esi), %edi
0x004ad3e2:	movl 0x108(%esi), %edi
0x004ad3e8:	movl 0x10c(%esi), %edi
0x004ad3ee:	movl 0x110(%esi), %edi
0x004ad3f4:	movl 0x114(%esi), %edi
0x004ad3fa:	movl 0x118(%esi), %edi
0x004ad400:	movl 0x11c(%esi), %edi
0x004ad406:	movl 0x120(%esi), %edi
0x004ad40c:	movl 0x124(%esi), %edi
0x004ad412:	movl 0x128(%esi), %edi
0x004ad418:	movl 0x12c(%esi), %edi
0x004ad41e:	movl 0x130(%esi), %edi
0x004ad424:	movl 0x134(%esi), %edi
0x004ad42a:	movl 0x138(%esi), %edi
0x004ad430:	movl 0x13c(%esi), %edi
0x004ad436:	movl 0x140(%esi), %edi
0x004ad43c:	movl 0x144(%esi), %edi
0x004ad442:	movl 0x148(%esi), %edi
0x004ad448:	movl 0x14c(%esi), %edi
0x004ad44e:	movl 0x150(%esi), %edi
0x004ad454:	movl 0x154(%esi), %edi
0x004ad45a:	movl 0x158(%esi), %edi
0x004ad460:	movl 0x15c(%esi), %edi
0x004ad466:	movl 0x160(%esi), %edi
0x004ad46c:	movl 0x164(%esi), %edi
0x004ad472:	movl 0x168(%esi), %edi
0x004ad478:	movl 0x16c(%esi), %edi
0x004ad47e:	movl 0x170(%esi), %edi
0x004ad484:	movl 0x174(%esi), %edi
0x004ad48a:	movl 0x178(%esi), %edi
0x004ad490:	movl 0x17c(%esi), %edi
0x004ad496:	movl 0x180(%esi), %edi
0x004ad49c:	movl 0x184(%esi), %edi
0x004ad4a2:	movl %eax, %esi
0x004ad4a4:	call 0x004ce2cb
0x004ad4a9:	ret

0x004ad65b:	jmp 0x004ad65f
0x004ad65f:	movl %ecx, 0x78(%esi)
0x004ad662:	pushl $0x64<UINT8>
0x004ad664:	movb -4(%ebp), %bl
0x004ad667:	movl (%ecx), %eax
0x004ad669:	call 0x004c11ca
0x004ad66e:	movl %ecx, %eax
0x004ad670:	movl 0x8(%ebp), %ecx
0x004ad673:	movb -4(%ebp), $0x5<UINT8>
0x004ad677:	cmpl %ecx, %edi
0x004ad679:	je 7
0x004ad67b:	call 0x004ad4ca
0x004ad4ca:	pushl $0x4<UINT8>
0x004ad4cc:	movl %eax, $0x5277c2<UINT32>
0x004ad4d1:	call 0x004ce1f3
0x004ad4d6:	movl %esi, %ecx
0x004ad4d8:	pushl $0x541e18<UINT32>
0x004ad4dd:	leal %ecx, -16(%ebp)
0x004ad4e0:	call 0x00402b20
0x004ad4e5:	leal %eax, -16(%ebp)
0x004ad4e8:	xorl %edi, %edi
0x004ad4ea:	pushl %eax
0x004ad4eb:	movl %ecx, %esi
0x004ad4ed:	movl -4(%ebp), %edi
0x004ad4f0:	call 0x004ad218
0x005277c2:	movl %edx, 0x8(%esp)
0x005277c6:	leal %eax, 0xc(%edx)
0x005277c9:	movl %ecx, -20(%edx)
0x005277cc:	xorl %ecx, %eax
0x005277ce:	call 0x004cb615
0x005277d3:	movl %eax, $0x575518<UINT32>
0x005277d8:	jmp 0x004cde9a
0x004ad4f5:	movl %ecx, -16(%ebp)
0x004ad4f8:	addl %ecx, $0xfffffff0<UINT8>
0x004ad4fb:	call 0x004022d0
0x004ad500:	movl (%esi), $0x541e14<UINT32>
0x004ad506:	movl 0x10(%esi), %edi
0x004ad509:	movl 0x14(%esi), %edi
0x004ad50c:	movl 0x18(%esi), %edi
0x004ad50f:	movl 0x1c(%esi), %edi
0x004ad512:	movl 0x20(%esi), %edi
0x004ad515:	movl 0x24(%esi), %edi
0x004ad518:	movl 0x28(%esi), %edi
0x004ad51b:	movl 0x2c(%esi), %edi
0x004ad51e:	movl 0x30(%esi), %edi
0x004ad521:	movl 0x34(%esi), %edi
0x004ad524:	movl 0x38(%esi), %edi
0x004ad527:	movl 0x3c(%esi), %edi
0x004ad52a:	movl 0x40(%esi), %edi
0x004ad52d:	movl 0x44(%esi), %edi
0x004ad530:	movl 0x48(%esi), %edi
0x004ad533:	movl 0x4c(%esi), %edi
0x004ad536:	movl 0x50(%esi), %edi
0x004ad539:	movl 0x54(%esi), %edi
0x004ad53c:	movl 0x58(%esi), %edi
0x004ad53f:	movl 0x5c(%esi), %edi
0x004ad542:	movl 0x60(%esi), %edi
0x004ad545:	movl %eax, %esi
0x004ad547:	call 0x004ce2cb
0x004ad54c:	ret

0x004ad680:	jmp 0x004ad684
0x004ad684:	movl %ecx, 0x78(%esi)
0x004ad687:	pushl $0x14<UINT8>
0x004ad689:	movb -4(%ebp), %bl
0x004ad68c:	movl 0x4(%ecx), %eax
0x004ad68f:	call 0x004c11ca
0x004ad694:	movl %ecx, %eax
0x004ad696:	movl 0x8(%ebp), %ecx
0x004ad699:	movb -4(%ebp), $0x6<UINT8>
0x004ad69d:	cmpl %ecx, %edi
0x004ad69f:	je 7
0x004ad6a1:	call 0x004ad54d
0x004ad54d:	pushl $0x4<UINT8>
0x004ad54f:	movl %eax, $0x5277c2<UINT32>
0x004ad554:	call 0x004ce1f3
0x004ad559:	movl %esi, %ecx
0x004ad55b:	pushl $0x541e3c<UINT32>
0x004ad560:	leal %ecx, -16(%ebp)
0x004ad563:	call 0x00402b20
0x004ad568:	andl -4(%ebp), $0x0<UINT8>
0x004ad56c:	leal %eax, -16(%ebp)
0x004ad56f:	pushl %eax
0x004ad570:	movl %ecx, %esi
0x004ad572:	call 0x004ad218
0x004ad577:	movl %ecx, -16(%ebp)
0x004ad57a:	addl %ecx, $0xfffffff0<UINT8>
0x004ad57d:	call 0x004022d0
0x004ad582:	movl (%esi), $0x541e38<UINT32>
0x004ad588:	andl 0x10(%esi), $0x0<UINT8>
0x004ad58c:	movl %eax, %esi
0x004ad58e:	call 0x004ce2cb
0x004ad593:	ret

0x004ad6a6:	jmp 0x004ad6aa
0x004ad6aa:	movl %ecx, 0x78(%esi)
0x004ad6ad:	movl 0x8(%ecx), %eax
0x004ad6b0:	movl 0x7c(%esi), %ebx
0x004ad6b3:	movl 0x80(%esi), %edi
0x004ad6b9:	movl 0x84(%esi), %edi
0x004ad6bf:	movl 0x88(%esi), %edi
0x004ad6c5:	movl %eax, %esi
0x004ad6c7:	call 0x004ce2cb
0x004ad6cc:	ret $0x4<UINT16>

0x004ad6db:	movl (%esi), $0x541e58<UINT32>
0x004ad6e1:	movl %eax, %esi
0x004ad6e3:	popl %esi
0x004ad6e4:	ret

0x004ad70e:	call 0x004ce2cb
0x004ad713:	ret

0x004c1291:	movl (%esi), %eax
0x004c1293:	orl -4(%ebp), $0xffffffff<UINT8>
0x004c1297:	pushl $0x10<UINT8>
0x004c1299:	call 0x004c2ac4
0x004c2ac4:	movl %edi, %edi
0x004c2ac6:	pushl %ebp
0x004c2ac7:	movl %ebp, %esp
0x004c2ac9:	movl %eax, 0x8(%ebp)
0x004c2acc:	cmpl %eax, $0x11<UINT8>
0x004c2acf:	jb 0x004c2ad6
0x004c2ad6:	imull %eax, %eax, $0x18<UINT8>
0x004c2ad9:	addl %eax, $0x59acb8<UINT32>
0x004c2ade:	pushl %eax
0x004c2adf:	call LeaveCriticalSection@KERNEL32.dll
0x004c2ae5:	popl %ebp
0x004c2ae6:	ret $0x4<UINT16>

0x004c129e:	movl %eax, (%esi)
0x004c12a0:	call 0x004ce2cb
0x004c12a5:	ret $0x4<UINT16>

0x004ad742:	testl %eax, %eax
0x004ad744:	je -31
0x004ad746:	ret

0x004ec021:	movb %cl, 0x8(%ebp)
0x004ec024:	movb 0x14(%eax), %cl
0x004ec027:	xorl %eax, %eax
0x004ec029:	incl %eax
0x004ec02a:	popl %ebp
0x004ec02b:	ret $0x8<UINT16>

0x00529c10:	pushl $0x4ec02e<UINT32>
0x00529c15:	call 0x004ccf7f
0x00529c1a:	popl %ecx
0x00529c1b:	movb 0x59bb40, %al
0x00529c20:	ret

0x00529914:	pushl $0x529c63<UINT32>
0x00529919:	call 0x004ccf7f
0x0052991e:	popl %ecx
0x0052991f:	ret

0x00529920:	pushl $0x529c6e<UINT32>
0x00529925:	call 0x004ccf7f
0x0052992a:	popl %ecx
0x0052992b:	ret

0x0052992c:	pushl $0x529c79<UINT32>
0x00529931:	call 0x004ccf7f
0x00529936:	popl %ecx
0x00529937:	ret

0x00529938:	pushl $0x529c84<UINT32>
0x0052993d:	call 0x004ccf7f
0x00529942:	popl %ecx
0x00529943:	ret

0x00529944:	pushl $0x54325c<UINT32>
0x00529949:	call RegisterWindowMessageW@USER32.dll
RegisterWindowMessageW@USER32.dll: API Node	
0x0052994f:	movl 0x59a838, %eax
0x00529954:	ret

0x00529955:	movl %ecx, $0x59a840<UINT32>
0x0052995a:	call 0x004b4a8c
0x004b4a8c:	movl %edi, %edi
0x004b4a8e:	pushl %esi
0x004b4a8f:	movl %esi, %ecx
0x004b4a91:	call 0x004ad714
0x004c1229:	cmpl %edi, 0x8(%eax)
0x004c122c:	jnl 0x004c123f
0x004c122e:	movl %eax, 0xc(%eax)
0x004c1231:	movl %edi, (%eax,%edi,4)
0x004c1234:	pushl %ebx
0x004c1235:	call LeaveCriticalSection@KERNEL32.dll
0x004c123b:	movl %eax, %edi
0x004c123d:	jmp 0x004c1248
0x004b4a96:	movl 0x1c(%esi), %eax
0x004b4a99:	xorl %eax, %eax
0x004b4a9b:	incl %eax
0x004b4a9c:	xorl %ecx, %ecx
0x004b4a9e:	movl 0x4(%esi), %eax
0x004b4aa1:	movl 0x14(%esi), %eax
0x004b4aa4:	movl 0x8(%esi), %ecx
0x004b4aa7:	movl 0xc(%esi), %ecx
0x004b4aaa:	movl 0x10(%esi), %ecx
0x004b4aad:	movl 0x18(%esi), %ecx
0x004b4ab0:	movl %eax, %esi
0x004b4ab2:	popl %esi
0x004b4ab3:	ret

0x0052995f:	xorl %eax, %eax
0x00529961:	pushl $0x529c8e<UINT32>
0x00529966:	movl 0x59a840, $0x542bfc<UINT32>
0x00529970:	movl 0x59a870, $0x542b6c<UINT32>
0x0052997a:	movl 0x59a874, $0x542be0<UINT32>
0x00529984:	movl 0x59a860, %eax
0x00529989:	movb 0x59a864, %al
0x0052998e:	movl 0x59a86c, %eax
0x00529993:	movl 0x59a878, %eax
0x00529998:	movl 0x59a87c, %eax
0x0052999d:	movl 0x59a880, %eax
0x005299a2:	movl 0x59a884, %eax
0x005299a7:	movl 0x59a888, %eax
0x005299ac:	movl 0x59a88c, %eax
0x005299b1:	movl 0x59a890, %eax
0x005299b6:	call 0x004ccf7f
0x005299bb:	popl %ecx
0x005299bc:	ret

0x005299bd:	movl %ecx, $0x59a898<UINT32>
0x005299c2:	call 0x004b4a8c
0x005299c7:	xorl %eax, %eax
0x005299c9:	pushl $0x529c98<UINT32>
0x005299ce:	movl 0x59a898, $0x542bfc<UINT32>
0x005299d8:	movl 0x59a8c8, $0x542b6c<UINT32>
0x005299e2:	movl 0x59a8cc, $0x542be0<UINT32>
0x005299ec:	movl 0x59a8b8, $0x1<UINT32>
0x005299f6:	movb 0x59a8bc, %al
0x005299fb:	movl 0x59a8c4, %eax
0x00529a00:	movl 0x59a8d0, %eax
0x00529a05:	movl 0x59a8d4, %eax
0x00529a0a:	movl 0x59a8d8, %eax
0x00529a0f:	movl 0x59a8dc, %eax
0x00529a14:	movl 0x59a8e0, %eax
0x00529a19:	movl 0x59a8e4, %eax
0x00529a1e:	movl 0x59a8e8, %eax
0x00529a23:	call 0x004ccf7f
0x00529a28:	popl %ecx
0x00529a29:	ret

0x00529a2a:	movl %ecx, $0x59a8f0<UINT32>
0x00529a2f:	call 0x004b4a8c
0x00529a34:	orl 0x59a910, $0xffffffff<UINT8>
0x00529a3b:	xorl %eax, %eax
0x00529a3d:	pushl $0x529ca2<UINT32>
0x00529a42:	movl 0x59a8f0, $0x542bfc<UINT32>
0x00529a4c:	movl 0x59a920, $0x542b6c<UINT32>
0x00529a56:	movl 0x59a924, $0x542be0<UINT32>
0x00529a60:	movb 0x59a914, %al
0x00529a65:	movl 0x59a91c, %eax
0x00529a6a:	movl 0x59a928, %eax
0x00529a6f:	movl 0x59a92c, %eax
0x00529a74:	movl 0x59a930, %eax
0x00529a79:	movl 0x59a934, %eax
0x00529a7e:	movl 0x59a938, %eax
0x00529a83:	movl 0x59a93c, %eax
0x00529a88:	movl 0x59a940, %eax
0x00529a8d:	call 0x004ccf7f
0x00529a92:	popl %ecx
0x00529a93:	ret

0x00529a94:	movl %ecx, $0x59a948<UINT32>
0x00529a99:	call 0x004b4a8c
0x00529a9e:	xorl %eax, %eax
0x00529aa0:	pushl $0x529cac<UINT32>
0x00529aa5:	movl 0x59a948, $0x542bfc<UINT32>
0x00529aaf:	movl 0x59a978, $0x542b6c<UINT32>
0x00529ab9:	movl 0x59a97c, $0x542be0<UINT32>
0x00529ac3:	movl 0x59a968, $0xfffffffe<UINT32>
0x00529acd:	movb 0x59a96c, %al
0x00529ad2:	movl 0x59a974, %eax
0x00529ad7:	movl 0x59a980, %eax
0x00529adc:	movl 0x59a984, %eax
0x00529ae1:	movl 0x59a988, %eax
0x00529ae6:	movl 0x59a98c, %eax
0x00529aeb:	movl 0x59a990, %eax
0x00529af0:	movl 0x59a994, %eax
0x00529af5:	movl 0x59a998, %eax
0x00529afa:	call 0x004ccf7f
0x00529aff:	popl %ecx
0x00529b00:	ret

0x00529b01:	pushl $0x0<UINT8>
0x00529b03:	movl %ecx, $0x59a9a8<UINT32>
0x00529b08:	call 0x004adb6e
0x004adb6e:	movl %edi, %edi
0x004adb70:	pushl %ebp
0x004adb71:	movl %ebp, %esp
0x004adb73:	movl %eax, %ecx
0x004adb75:	movl %ecx, 0x8(%ebp)
0x004adb78:	movl 0x4(%eax), %ecx
0x004adb7b:	popl %ebp
0x004adb7c:	ret $0x4<UINT16>

0x00529b0d:	andl 0x59a9b4, $0x0<UINT8>
0x00529b14:	andl 0x59a9b8, $0x0<UINT8>
0x00529b1b:	pushl $0x529cb6<UINT32>
0x00529b20:	movl 0x59a9a8, $0x543560<UINT32>
0x00529b2a:	movl 0x59aabc, $0xf022<UINT32>
0x00529b34:	call 0x004ccf7f
0x00529b39:	popl %ecx
0x00529b3a:	ret

0x00529b3b:	pushl $0x0<UINT8>
0x00529b3d:	movl %ecx, $0x59aac0<UINT32>
0x00529b42:	call 0x004adb6e
0x00529b47:	andl 0x59aacc, $0x0<UINT8>
0x00529b4e:	andl 0x59aad0, $0x0<UINT8>
0x00529b55:	pushl $0x529cc1<UINT32>
0x00529b5a:	movl 0x59aac0, $0x54357c<UINT32>
0x00529b64:	movl 0x59abd4, $0xf024<UINT32>
0x00529b6e:	call 0x004ccf7f
0x00529b73:	popl %ecx
0x00529b74:	ret

0x00529b7f:	movl %ecx, $0x59ac60<UINT32>
0x00529b84:	call 0x004c2144
0x004c2144:	movl %edi, %edi
0x004c2146:	pushl %ebx
0x004c2147:	pushl %esi
0x004c2148:	pushl %edi
0x004c2149:	movl %esi, %ecx
0x004c214b:	call 0x004c20e8
0x004c20e8:	movl %edi, %edi
0x004c20ea:	pushl %ebx
0x004c20eb:	pushl %esi
0x004c20ec:	movl %esi, 0x52a630
0x004c20f2:	pushl %edi
0x004c20f3:	pushl $0xb<UINT8>
0x004c20f5:	movl %edi, %ecx
0x004c20f7:	call GetSystemMetrics@USER32.dll
GetSystemMetrics@USER32.dll: API Node	
0x004c20f9:	pushl $0xc<UINT8>
0x004c20fb:	movl 0x8(%edi), %eax
0x004c20fe:	call GetSystemMetrics@USER32.dll
0x004c2100:	pushl $0x2<UINT8>
0x004c2102:	movl 0xc(%edi), %eax
0x004c2105:	call GetSystemMetrics@USER32.dll
0x004c2107:	incl %eax
0x004c2108:	pushl $0x3<UINT8>
0x004c210a:	movl 0x59ac60, %eax
0x004c210f:	call GetSystemMetrics@USER32.dll
0x004c2111:	incl %eax
0x004c2112:	pushl $0x0<UINT8>
0x004c2114:	movl 0x59ac64, %eax
0x004c2119:	call GetDC@USER32.dll
GetDC@USER32.dll: API Node	
0x004c211f:	movl %esi, 0x52a0d8
0x004c2125:	movl %ebx, %eax
0x004c2127:	pushl $0x58<UINT8>
0x004c2129:	pushl %ebx
0x004c212a:	call GetDeviceCaps@GDI32.dll
GetDeviceCaps@GDI32.dll: API Node	
0x004c212c:	pushl $0x5a<UINT8>
0x004c212e:	pushl %ebx
0x004c212f:	movl 0x18(%edi), %eax
0x004c2132:	call GetDeviceCaps@GDI32.dll
0x004c2134:	pushl %ebx
0x004c2135:	pushl $0x0<UINT8>
0x004c2137:	movl 0x1c(%edi), %eax
0x004c213a:	call ReleaseDC@USER32.dll
ReleaseDC@USER32.dll: API Node	
0x004c2140:	popl %edi
0x004c2141:	popl %esi
0x004c2142:	popl %ebx
0x004c2143:	ret

0x004c2150:	xorl %ebx, %ebx
0x004c2152:	movl %ecx, %esi
0x004c2154:	movl 0x24(%esi), %ebx
0x004c2157:	call 0x004c20a2
0x004c20a2:	movl %edi, %edi
0x004c20a4:	pushl %esi
0x004c20a5:	pushl %edi
0x004c20a6:	movl %edi, 0x52a660
0x004c20ac:	pushl $0xf<UINT8>
0x004c20ae:	movl %esi, %ecx
0x004c20b0:	call GetSysColor@USER32.dll
GetSysColor@USER32.dll: API Node	
0x004c20b2:	pushl $0x10<UINT8>
0x004c20b4:	movl 0x28(%esi), %eax
0x004c20b7:	call GetSysColor@USER32.dll
0x004c20b9:	pushl $0x14<UINT8>
0x004c20bb:	movl 0x2c(%esi), %eax
0x004c20be:	call GetSysColor@USER32.dll
0x004c20c0:	pushl $0x12<UINT8>
0x004c20c2:	movl 0x30(%esi), %eax
0x004c20c5:	call GetSysColor@USER32.dll
0x004c20c7:	pushl $0x6<UINT8>
0x004c20c9:	movl 0x34(%esi), %eax
0x004c20cc:	call GetSysColor@USER32.dll
0x004c20ce:	movl %edi, 0x52a5d4
0x004c20d4:	pushl $0xf<UINT8>
0x004c20d6:	movl 0x38(%esi), %eax
0x004c20d9:	call GetSysColorBrush@USER32.dll
GetSysColorBrush@USER32.dll: API Node	
0x004c20db:	pushl $0x6<UINT8>
0x004c20dd:	movl 0x24(%esi), %eax
0x004c20e0:	call GetSysColorBrush@USER32.dll
0x004c20e2:	popl %edi
0x004c20e3:	movl 0x20(%esi), %eax
0x004c20e6:	popl %esi
0x004c20e7:	ret

0x004c215c:	movl %edi, 0x52a5d0
0x004c2162:	pushl $0x7f02<UINT32>
0x004c2167:	pushl %ebx
0x004c2168:	call LoadCursorW@USER32.dll
LoadCursorW@USER32.dll: API Node	
0x004c216a:	pushl $0x7f00<UINT32>
0x004c216f:	pushl %ebx
0x004c2170:	movl 0x3c(%esi), %eax
0x004c2173:	call LoadCursorW@USER32.dll
0x004c2175:	pushl $0x2<UINT8>
0x004c2177:	movl 0x40(%esi), %eax
0x004c217a:	popl %eax
0x004c217b:	movl 0x10(%esi), %eax
0x004c217e:	movl 0x14(%esi), %eax
0x004c2181:	popl %edi
0x004c2182:	movl 0x50(%esi), %ebx
0x004c2185:	movl 0x44(%esi), %ebx
0x004c2188:	movl %eax, %esi
0x004c218a:	popl %esi
0x004c218b:	popl %ebx
0x004c218c:	ret

0x00529b89:	pushl $0x529ccc<UINT32>
0x00529b8e:	call 0x004ccf7f
0x00529b93:	popl %ecx
0x00529b94:	ret

0x00529b95:	pushl $0x594cd8<UINT32>
0x00529b9a:	call 0x004c119f
0x004c119f:	movl %edi, %edi
0x004c11a1:	pushl %ebp
0x004c11a2:	movl %ebp, %esp
0x004c11a4:	pushl %esi
0x004c11a5:	call 0x004ad714
0x004c11aa:	pushl $0x0<UINT8>
0x004c11ac:	movl %esi, %eax
0x004c11ae:	call 0x004c2a52
0x004c11b3:	pushl 0x8(%ebp)
0x004c11b6:	leal %ecx, 0x1c(%esi)
0x004c11b9:	call 0x004c12fc
0x004c11be:	pushl $0x0<UINT8>
0x004c11c0:	call 0x004c2ac4
0x004c11c5:	popl %esi
0x004c11c6:	popl %ebp
0x004c11c7:	ret $0x4<UINT16>

0x00529b9f:	ret

0x00529ba0:	pushl $0x594da0<UINT32>
0x00529ba5:	call 0x004c119f
0x00529baa:	ret

0x00529c30:	pushl $0x529d00<UINT32>
0x00529c35:	call 0x004ccf7f
0x00529c3a:	popl %ecx
0x00529c3b:	ret

0x005298e0:	pushl %ebp
0x005298e1:	movl %ebp, %esp
0x005298e3:	movl %ecx, $0x59bb68<UINT32>
0x005298e8:	call 0x004ffa70
0x004ffa70:	pushl %ebp
0x004ffa71:	movl %ebp, %esp
0x004ffa73:	pushl $0xffffffff<UINT8>
0x004ffa75:	pushl $0x527fde<UINT32>
0x004ffa7a:	movl %eax, %fs:0
0x004ffa80:	pushl %eax
0x004ffa81:	pushl %ecx
0x004ffa82:	movl %eax, 0x594ea0
0x004ffa87:	xorl %eax, %ebp
0x004ffa89:	pushl %eax
0x004ffa8a:	leal %eax, -12(%ebp)
0x004ffa8d:	movl %fs:0, %eax
0x004ffa93:	movl -16(%ebp), %ecx
0x004ffa96:	pushl $0x0<UINT8>
0x004ffa98:	movl %ecx, -16(%ebp)
0x004ffa9b:	call 0x004bdcea
0x004bdcea:	pushl $0x4<UINT8>
0x004bdcec:	movl %eax, $0x52709e<UINT32>
0x004bdcf1:	call 0x004ce1f3
0x004bdcf6:	movl %esi, %ecx
0x004bdcf8:	movl -16(%ebp), %esi
0x004bdcfb:	call 0x004bc912
0x004bc912:	pushl $0x4<UINT8>
0x004bc914:	movl %eax, $0x527048<UINT32>
0x004bc919:	call 0x004ce1f3
0x004bc91e:	movl %esi, %ecx
0x004bc920:	movl -16(%ebp), %esi
0x004bc923:	call 0x004b4a8c
0x004bc928:	xorl %eax, %eax
0x004bc92a:	movl %ecx, %esi
0x004bc92c:	movl -4(%ebp), %eax
0x004bc92f:	movl (%esi), $0x54481c<UINT32>
0x004bc935:	movl 0x34(%esi), %eax
0x004bc938:	movl 0x38(%esi), %eax
0x004bc93b:	call 0x004bc5d1
0x004bc5d1:	movl %edi, %edi
0x004bc5d3:	pushl %esi
0x004bc5d4:	movl %esi, %ecx
0x004bc5d6:	pushl %edi
0x004bc5d7:	xorl %edi, %edi
0x004bc5d9:	movl 0x20(%esi), %edi
0x004bc5dc:	movl 0x24(%esi), %edi
0x004bc5df:	movl 0x2c(%esi), %edi
0x004bc5e2:	movl 0x30(%esi), %edi
0x004bc5e5:	call 0x004ad148
0x004ad148:	pushl $0x4ad077<UINT32>
0x004ad14d:	movl %ecx, $0x599000<UINT32>
0x004ad152:	call 0x004c178d
0x004ad157:	testl %eax, %eax
0x004ad159:	jne 0x004ad160
0x004ad160:	ret

0x004bc5ea:	movl 0x34(%eax), %edi
0x004bc5ed:	movl 0x54(%eax), %edi
0x004bc5f0:	addl %eax, $0x4c<UINT8>
0x004bc5f3:	pushl %eax
0x004bc5f4:	call GetCursorPos@USER32.dll
GetCursorPos@USER32.dll: API Node	
0x004bc5fa:	movl 0x40(%esi), %edi
0x004bc5fd:	movl 0x3c(%esi), %edi
0x004bc600:	popl %edi
0x004bc601:	movl 0x28(%esi), $0x1<UINT32>
0x004bc608:	popl %esi
0x004bc609:	ret

0x004bc940:	movl %eax, %esi
0x004bc942:	call 0x004ce2cb
0x004bc947:	ret

0x004bdd00:	xorl %edi, %edi
0x004bdd02:	movl -4(%ebp), %edi
0x004bdd05:	movl (%esi), $0x545354<UINT32>
0x004bdd0b:	cmpl 0x8(%ebp), %edi
0x004bdd0e:	je 0x004bdd1e
0x004bdd1e:	movl 0x50(%esi), %edi
0x004bdd21:	call 0x004ad714
0x004bdd26:	movl %ebx, %eax
0x004bdd28:	cmpl %ebx, %edi
0x004bdd2a:	jne 0x004bdd31
0x004bdd31:	leal %ecx, 0x74(%ebx)
0x004bdd34:	call 0x004ad204
0x004ad204:	pushl $0x4ad11c<UINT32>
0x004ad209:	call 0x004c178d
0x004c13ae:	movl %eax, 0x10(%esi)
0x004c13b1:	testb (%eax,%edi,8), $0x1<UINT8>
0x004c13b5:	je 0x004c1479
0x004ad11c:	pushl $0x54<UINT8>
0x004ad11e:	call 0x004c11ca
0x004ad123:	testl %eax, %eax
0x004ad125:	je 7
0x004ad127:	movl %ecx, %eax
0x004ad129:	jmp 0x004ad0d2
0x004ad0d2:	movl %eax, %ecx
0x004ad0d4:	xorl %ecx, %ecx
0x004ad0d6:	movl (%eax), $0x541dd8<UINT32>
0x005275f6:	movl %edx, 0x8(%esp)
0x005275fa:	leal %eax, 0xc(%edx)
0x005275fd:	movl %ecx, -20(%edx)
0x00527600:	xorl %ecx, %eax
0x00527602:	call 0x004cb615
0x00527607:	movl %eax, $0x575230<UINT32>
0x0052760c:	jmp 0x004cde9a
0x004ad0dc:	movl 0x8(%eax), %ecx
0x004ad0df:	movl 0xc(%eax), %ecx
0x004ad0e2:	orl 0x44(%eax), $0xffffffff<UINT8>
0x004ad0e6:	orl 0x4c(%eax), $0xffffffff<UINT8>
0x004ad0ea:	movl 0x48(%eax), %ecx
0x004ad0ed:	movl 0xc(%eax), $0x6c<UINT32>
0x004ad0f4:	movl 0x28(%eax), $0x4accde<UINT32>
0x004ad0fb:	ret

0x004c158c:	movl %ecx, 0x8(%ebp)
0x004c158f:	cmpl %ecx, 0x8(%esi)
0x004c1592:	jl 0x004c1659
0x004c1598:	cmpl 0xc(%ebp), %ebx
0x004c159b:	je 184
0x004c1601:	pushl $0x2<UINT8>
0x004c1603:	pushl $0x4<UINT8>
0x004c1605:	pushl 0xc(%edi)
0x004c1608:	call 0x004b6440
0x004c160d:	popl %ecx
0x004c160e:	popl %ecx
0x004c160f:	pushl %eax
0x004c1610:	pushl 0xc(%esi)
0x004c1613:	call LocalReAlloc@KERNEL32.dll
LocalReAlloc@KERNEL32.dll: API Node	
0x004ad20e:	testl %eax, %eax
0x004ad210:	jne 0x004ad217
0x004ad217:	ret

0x004bdd39:	cmpl %eax, %edi
0x004bdd3b:	je -17
0x004bdd3d:	movl 0x4(%eax), %esi
0x004bdd40:	call GetCurrentThread@KERNEL32.dll
GetCurrentThread@KERNEL32.dll: API Node	
0x004bdd46:	movl 0x2c(%esi), %eax
0x004bdd49:	call GetCurrentThreadId@KERNEL32.dll
0x004bdd4f:	movl 0x30(%esi), %eax
0x004bdd52:	movl 0x4(%ebx), %esi
0x004bdd55:	xorl %eax, %eax
0x004bdd57:	movw 0x92(%esi), %ax
0x004bdd5e:	movw 0x90(%esi), %ax
0x004bdd65:	movl 0x44(%esi), %edi
0x004bdd68:	movl 0x7c(%esi), %edi
0x004bdd6b:	movl 0x64(%esi), %edi
0x004bdd6e:	movl 0x68(%esi), %edi
0x004bdd71:	movl 0x54(%esi), %edi
0x004bdd74:	movl 0x60(%esi), %edi
0x004bdd77:	movl 0x88(%esi), %edi
0x004bdd7d:	movl 0x58(%esi), %edi
0x004bdd80:	movl 0x48(%esi), %edi
0x004bdd83:	movl 0x8c(%esi), %edi
0x004bdd89:	movl 0x80(%esi), %edi
0x004bdd8f:	movl 0x84(%esi), %edi
0x004bdd95:	movl 0x70(%esi), %edi
0x004bdd98:	movl 0x74(%esi), %edi
0x004bdd9b:	movl 0x94(%esi), %edi
0x004bdda1:	movl 0x9c(%esi), %edi
0x004bdda7:	movl 0x5c(%esi), %edi
0x004bddaa:	movl 0x6c(%esi), %edi
0x004bddad:	movl 0x98(%esi), $0x200<UINT32>
0x004bddb7:	movl %eax, %esi
0x004bddb9:	call 0x004ce2cb
0x004bddbe:	ret $0x4<UINT16>

0x004ffaa0:	movl -4(%ebp), $0x0<UINT32>
0x004ffaa7:	movl %eax, -16(%ebp)
0x004ffaaa:	movl (%eax), $0x56407c<UINT32>
0x004ffab0:	movl %ecx, -16(%ebp)
0x004ffab3:	addl %ecx, $0x108<UINT32>
0x004ffab9:	call 0x004b5123
0x004b5123:	movl %eax, %ecx
0x004b5125:	xorl %ecx, %ecx
0x004b5127:	movl (%eax), $0x54359c<UINT32>
0x004b512d:	movl 0x4(%eax), %ecx
0x004b5130:	movl 0x8(%eax), %ecx
0x004b5133:	movl 0xc(%eax), %ecx
0x004b5136:	ret

0x004ffabe:	movl %ecx, -16(%ebp)
0x004ffac1:	movl 0xc0(%ecx), $0x0<UINT32>
0x004ffacb:	movl %edx, -16(%ebp)
0x004fface:	movl 0xc4(%edx), $0x0<UINT32>
0x004ffad8:	movl %eax, -16(%ebp)
0x004ffadb:	movl 0x11c(%eax), $0xffffffff<UINT32>
0x004ffae5:	movl %ecx, -16(%ebp)
0x004ffae8:	movl 0x120(%ecx), $0x0<UINT32>
0x004ffaf2:	movl %edx, $0x61bd<UINT32>
0x004ffaf7:	movl %eax, -16(%ebp)
0x004ffafa:	movw 0x118(%eax), %dx
0x004ffb01:	xorl %ecx, %ecx
0x004ffb03:	movl %edx, -16(%ebp)
0x004ffb06:	movw 0x140(%edx), %cx
0x004ffb0d:	xorl %eax, %eax
0x004ffb0f:	movl %ecx, -16(%ebp)
0x004ffb12:	movw 0x540(%ecx), %ax
0x004ffb19:	xorl %edx, %edx
0x004ffb1b:	movl %eax, -16(%ebp)
0x004ffb1e:	movw 0x940(%eax), %dx
0x004ffb25:	xorl %ecx, %ecx
0x004ffb27:	movl %edx, -16(%ebp)
0x004ffb2a:	movw 0xd40(%edx), %cx
0x004ffb31:	xorl %eax, %eax
0x004ffb33:	movl %ecx, -16(%ebp)
0x004ffb36:	movw 0x1140(%ecx), %ax
0x004ffb3d:	xorl %edx, %edx
0x004ffb3f:	movl %eax, -16(%ebp)
0x004ffb42:	movw 0x15c0(%eax), %dx
0x004ffb49:	movl %ecx, -16(%ebp)
0x004ffb4c:	movl 0x19cc(%ecx), $0x0<UINT32>
0x004ffb56:	movl %edx, -16(%ebp)
0x004ffb59:	movl 0x19c8(%edx), $0x0<UINT32>
0x004ffb63:	movl %eax, -16(%ebp)
0x004ffb66:	movl 0x19c4(%eax), $0x0<UINT32>
0x004ffb70:	movl %ecx, -16(%ebp)
0x004ffb73:	movl 0x19c0(%ecx), $0x0<UINT32>
0x004ffb7d:	movl %edx, -16(%ebp)
0x004ffb80:	movl 0x1af0(%edx), $0x1<UINT32>
0x004ffb8a:	movl %eax, -16(%ebp)
0x004ffb8d:	movl 0x1af4(%eax), $0x0<UINT32>
0x004ffb97:	movl %ecx, -16(%ebp)
0x004ffb9a:	movl 0x1af8(%ecx), $0x0<UINT32>
0x004ffba4:	movl %edx, -16(%ebp)
0x004ffba7:	movl 0x1afc(%edx), $0x0<UINT32>
0x004ffbb1:	movl %eax, -16(%ebp)
0x004ffbb4:	movl 0x1b00(%eax), $0x1<UINT32>
0x004ffbbe:	movl %ecx, -16(%ebp)
0x004ffbc1:	movl 0x1b04(%ecx), $0x1<UINT32>
0x004ffbcb:	movl %edx, -16(%ebp)
0x004ffbce:	movl 0x1b1c(%edx), $0x0<UINT32>
0x004ffbd8:	movl %eax, -16(%ebp)
0x004ffbdb:	movl 0x1b08(%eax), $0x1<UINT32>
0x004ffbe5:	movl %ecx, -16(%ebp)
0x004ffbe8:	movl 0x1b0c(%ecx), $0x0<UINT32>
0x004ffbf2:	movl %edx, -16(%ebp)
0x004ffbf5:	movl 0x1b10(%edx), $0x1<UINT32>
0x004ffbff:	movl %eax, -16(%ebp)
0x004ffc02:	movl 0x1b14(%eax), $0x0<UINT32>
0x004ffc0c:	movl %ecx, -16(%ebp)
0x004ffc0f:	movl 0x1b18(%ecx), $0x1<UINT32>
0x004ffc19:	movl %edx, -16(%ebp)
0x004ffc1c:	movl 0x1b28(%edx), $0x1<UINT32>
0x004ffc26:	movl %eax, -16(%ebp)
0x004ffc29:	movl 0x1b20(%eax), $0x1<UINT32>
0x004ffc33:	movl %ecx, -16(%ebp)
0x004ffc36:	movl 0xb8(%ecx), $0x0<UINT32>
0x004ffc40:	movl %edx, -16(%ebp)
0x004ffc43:	movl 0x1a38(%edx), $0x0<UINT32>
0x004ffc4d:	pushl $0x80<UINT32>
0x004ffc52:	pushl $0x0<UINT8>
0x004ffc54:	movl %eax, -16(%ebp)
0x004ffc57:	addl %eax, $0x1540<UINT32>
0x004ffc5c:	pushl %eax
0x004ffc5d:	call 0x004cb630
0x004ffc62:	addl %esp, $0xc<UINT8>
0x004ffc65:	movl %ecx, -16(%ebp)
0x004ffc68:	movl 0x1a3c(%ecx), $0x0<UINT32>
0x004ffc72:	movl %edx, -16(%ebp)
0x004ffc75:	movl 0x12c(%edx), $0x500<UINT32>
0x004ffc7f:	movl %eax, -16(%ebp)
0x004ffc82:	movl 0x130(%eax), $0x3c0<UINT32>
0x004ffc8c:	movl %ecx, -16(%ebp)
0x004ffc8f:	movl 0x134(%ecx), $0x384<UINT32>
0x004ffc99:	movl %edx, -16(%ebp)
0x004ffc9c:	movl 0x138(%edx), $0x258<UINT32>
0x004ffca6:	movl %eax, -16(%ebp)
0x004ffca9:	movl 0x13c(%eax), $0x2<UINT32>
0x004ffcb3:	movl %ecx, -16(%ebp)
0x004ffcb6:	movl 0x1b2c(%ecx), $0x3e8<UINT32>
0x004ffcc0:	movl %edx, -16(%ebp)
0x004ffcc3:	movl 0x1b34(%edx), $0x0<UINT32>
0x004ffccd:	movl %eax, -16(%ebp)
0x004ffcd0:	movl 0x1b30(%eax), $0x0<UINT32>
0x004ffcda:	movl %ecx, -16(%ebp)
0x004ffcdd:	movl 0x1b38(%ecx), $0x0<UINT32>
0x004ffce7:	movl -4(%ebp), $0xffffffff<UINT32>
0x004ffcee:	movl %eax, -16(%ebp)
0x004ffcf1:	movl %ecx, -12(%ebp)
0x004ffcf4:	movl %fs:0, %ecx
0x004ffcfb:	popl %ecx
0x004ffcfc:	movl %esp, %ebp
0x004ffcfe:	popl %ebp
0x004ffcff:	ret

0x005298ed:	pushl $0x529c40<UINT32>
0x005298f2:	call 0x004ccf7f
0x005298f7:	addl %esp, $0x4<UINT8>
0x005298fa:	popl %ebp
0x005298fb:	ret

0x004d0956:	popl %esi
0x004d0957:	popl %ebp
0x004d0958:	ret

0x004d09d9:	cmpl 0x59e810, $0x0<UINT8>
0x004d09e0:	popl %ecx
0x004d09e1:	je 0x004d09fe
0x004d09fe:	xorl %eax, %eax
0x004d0a00:	popl %ebp
0x004d0a01:	ret

0x004cb574:	popl %ecx
0x004cb575:	cmpl %eax, %esi
0x004cb577:	je 0x004cb580
0x004cb580:	call 0x004d1643
0x004d1643:	movl %eax, 0x59e814
0x004d1648:	xorl %edx, %edx
0x004d164a:	testl %eax, %eax
0x004d164c:	jne 0x004d1653
0x004d1653:	movzwl %ecx, (%eax)
0x004d1656:	cmpw %cx, $0x20<UINT8>
0x004d165a:	ja 0x004d1665
0x004d1665:	cmpw %cx, $0x22<UINT8>
0x004d1669:	jne 0x004d1674
0x004d166b:	xorl %ecx, %ecx
0x004d166d:	testl %edx, %edx
0x004d166f:	sete %cl
0x004d1672:	movl %edx, %ecx
0x004d1674:	incl %eax
0x004d1675:	incl %eax
0x004d1676:	jmp 0x004d1653
0x004d165c:	testw %cx, %cx
0x004d165f:	je 0x004d1688
0x004d1688:	ret

0x004cb585:	testb -60(%ebp), %bl
0x004cb588:	je 0x004cb590
0x004cb590:	pushl $0xa<UINT8>
0x004cb592:	popl %ecx
0x004cb593:	pushl %ecx
0x004cb594:	pushl %eax
0x004cb595:	pushl %esi
0x004cb596:	pushl $0x400000<UINT32>
0x004cb59b:	call 0x004ec00c
0x004ec00c:	movl %edi, %edi
0x004ec00e:	pushl %ebp
0x004ec00f:	movl %ebp, %esp
0x004ec011:	popl %ebp
0x004ec012:	jmp 0x004ec041
0x004ec041:	movl %edi, %edi
0x004ec043:	pushl %ebp
0x004ec044:	movl %ebp, %esp
0x004ec046:	pushl %ebx
0x004ec047:	pushl %esi
0x004ec048:	pushl %edi
0x004ec049:	orl %ebx, $0xffffffff<UINT8>
0x004ec04c:	call 0x004bc578
0x004bc578:	call 0x004ad747
0x004ad747:	call 0x004ad714
0x004ad74c:	movl %ecx, %eax
0x004ad74e:	addl %ecx, $0x74<UINT8>
0x004ad751:	call 0x004ad204
0x004ad756:	testl %eax, %eax
0x004ad758:	jne 0x004ad75f
0x004ad75f:	ret

0x004bc57d:	movl %eax, 0x4(%eax)
0x004bc580:	ret

0x004ec051:	movl %esi, %eax
0x004ec053:	call 0x004ad714
0x004ec058:	pushl 0x14(%ebp)
0x004ec05b:	movl %edi, 0x4(%eax)
0x004ec05e:	pushl 0x10(%ebp)
0x004ec061:	pushl 0xc(%ebp)
0x004ec064:	pushl 0x8(%ebp)
0x004ec067:	call 0x004cac11
0x004cac11:	movl %edi, %edi
0x004cac13:	pushl %ebp
0x004cac14:	movl %ebp, %esp
0x004cac16:	pushl %esi
0x004cac17:	movl %esi, 0x52a1cc
0x004cac1d:	pushl $0x0<UINT8>
0x004cac1f:	call SetErrorMode@KERNEL32.dll
SetErrorMode@KERNEL32.dll: API Node	
0x004cac21:	orl %eax, $0x8001<UINT32>
0x004cac26:	pushl %eax
0x004cac27:	call SetErrorMode@KERNEL32.dll
0x004cac29:	call 0x004ad714
0x004cac2e:	movl %esi, 0x8(%ebp)
0x004cac31:	movl %ecx, %eax
0x004cac33:	movl 0x8(%eax), %esi
0x004cac36:	movl 0xc(%eax), %esi
0x004cac39:	call 0x004ace40
0x004ace40:	movl %edi, %edi
0x004ace42:	pushl %ebp
0x004ace43:	movl %ebp, %esp
0x004ace45:	subl %esp, $0x230<UINT32>
0x004ace4b:	movl %eax, 0x594ea0
0x004ace50:	xorl %eax, %ebp
0x004ace52:	movl -4(%ebp), %eax
0x004ace55:	pushl %esi
0x004ace56:	pushl %edi
0x004ace57:	movl %esi, %ecx
0x004ace59:	call 0x004acd44
0x004acd44:	cmpl 0x598ff8, $0x0<UINT8>
0x004acd4b:	jne 100
0x004acd4d:	pushl $0x541db8<UINT32>
0x004acd52:	call GetModuleHandleW@KERNEL32.dll
0x004acd58:	movl 0x598ff8, %eax
0x004acd5d:	testl %eax, %eax
0x004acd5f:	jne 0x004acd66
0x004acd66:	pushl %esi
0x004acd67:	movl %esi, 0x52a3f4
0x004acd6d:	pushl $0x541da8<UINT32>
0x004acd72:	pushl %eax
0x004acd73:	call GetProcAddress@KERNEL32.dll
0x004acd75:	pushl $0x541d98<UINT32>
0x004acd7a:	pushl 0x598ff8
0x004acd80:	movl 0x598fe4, %eax
0x004acd85:	call GetProcAddress@KERNEL32.dll
0x004acd87:	pushl $0x541d88<UINT32>
0x004acd8c:	pushl 0x598ff8
0x004acd92:	movl 0x598fe8, %eax
0x004acd97:	call GetProcAddress@KERNEL32.dll
0x004acd99:	pushl $0x541d74<UINT32>
0x004acd9e:	pushl 0x598ff8
0x004acda4:	movl 0x598fec, %eax
0x004acda9:	call GetProcAddress@KERNEL32.dll
0x004acdab:	movl 0x598ff0, %eax
0x004acdb0:	popl %esi
0x004acdb1:	ret

0x004ace5e:	movl %edi, 0x8(%esi)
0x004ace61:	xorl %eax, %eax
0x004ace63:	movw -6(%ebp), %ax
0x004ace67:	movw -8(%ebp), %ax
0x004ace6b:	pushl $0x105<UINT32>
0x004ace70:	leal %eax, -528(%ebp)
0x004ace76:	pushl %eax
0x004ace77:	pushl %edi
0x004ace78:	call GetModuleFileNameW@KERNEL32.dll
0x004ace7e:	testl %eax, %eax
0x004ace80:	je 0x004acf2e
0x004acf2e:	movl %ecx, -4(%ebp)
0x004acf31:	popl %edi
0x004acf32:	xorl %ecx, %ebp
0x004acf34:	popl %esi
0x004acf35:	call 0x004cb615
0x004acf3a:	leave
0x004acf3b:	ret

0x004cac3e:	call 0x004ad714
0x004cac43:	movl %eax, 0x4(%eax)
0x004cac46:	testl %eax, %eax
0x004cac48:	je 22
0x004cac4a:	movl %ecx, 0x10(%ebp)
0x004cac4d:	movl 0x48(%eax), %ecx
0x004cac50:	movl %ecx, 0x14(%ebp)
0x004cac53:	movl 0x4c(%eax), %ecx
0x004cac56:	movl %ecx, %eax
0x004cac58:	movl 0x44(%eax), %esi
0x004cac5b:	call 0x004caa7c
0x004caa7c:	movl %edi, %edi
0x004caa7e:	pushl %ebp
0x004caa7f:	movl %ebp, %esp
0x004caa81:	subl %esp, $0x618<UINT32>
0x004caa87:	movl %eax, 0x594ea0
0x004caa8c:	xorl %eax, %ebp
0x004caa8e:	movl -4(%ebp), %eax
0x004caa91:	pushl %ebx
0x004caa92:	pushl %esi
0x004caa93:	pushl %edi
0x004caa94:	movl %esi, %ecx
0x004caa96:	call 0x004ad714
0x004caa9b:	movl %ebx, %eax
0x004caa9d:	movl %eax, 0x44(%esi)
0x004caaa0:	movl 0x8(%ebx), %eax
0x004caaa3:	movl %eax, 0x44(%esi)
0x004caaa6:	movl 0xc(%ebx), %eax
0x004caaa9:	movl %edi, $0x104<UINT32>
0x004caaae:	pushl %edi
0x004caaaf:	leal %eax, -524(%ebp)
0x004caab5:	pushl %eax
0x004caab6:	pushl 0x44(%esi)
0x004caab9:	call GetModuleFileNameW@KERNEL32.dll
0x004caabf:	testl %eax, %eax
0x004caac1:	je 0x004caac7
0x004caac7:	call 0x004b50d4
0x004b50d4:	movl %edi, %edi
0x004b50d6:	pushl %ebp
0x004b50d7:	movl %ebp, %esp
0x004b50d9:	pushl %ecx
0x004b50da:	pushl $0x5742d0<UINT32>
0x004b50df:	leal %eax, -4(%ebp)
0x004b50e2:	pushl %eax
0x004b50e3:	movl -4(%ebp), $0x59aac0<UINT32>
0x004b50ea:	call 0x004cda5d
0x004cda5d:	movl %edi, %edi
0x004cda5f:	pushl %ebp
0x004cda60:	movl %ebp, %esp
0x004cda62:	subl %esp, $0x20<UINT8>
0x004cda65:	movl %eax, 0x8(%ebp)
0x004cda68:	pushl %esi
0x004cda69:	pushl %edi
0x004cda6a:	pushl $0x8<UINT8>
0x004cda6c:	popl %ecx
0x004cda6d:	movl %esi, $0x546f90<UINT32>
0x004cda72:	leal %edi, -32(%ebp)
0x004cda75:	rep movsl %es:(%edi), %ds:(%esi)
