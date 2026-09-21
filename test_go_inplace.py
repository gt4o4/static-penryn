#!/usr/bin/env python3
"""Exhaustive/random/page-boundary tests for the stack-neutral Go counter."""
import io
import json
import os
from pathlib import Path
import resource
import subprocess
import tempfile
import unittest

from elftools.elf.elffile import ELFFile

import go_inplace


BRIDGES = r'''
.intel_syntax noprefix
.text
.global count_slice, count_string, state_test
count_slice:
    push rbx
    push r12
    push r13
    sub rsp, 48
    mov [rsp], rdi
    mov [rsp+8], rsi
    mov [rsp+16], rsi
    mov [rsp+24], dl
    call go_count_slice
    mov rax, [rsp+32]
    add rsp, 48
    pop r13
    pop r12
    pop rbx
    ret
go_count_slice:
    mov rsi, [rsp+8]
    mov rbx, [rsp+16]
    mov al, [rsp+32]
    lea r8, [rsp+40]
    jmp countbody
count_string:
    push rbx
    push r12
    push r13
    sub rsp, 32
    mov [rsp], rdi
    mov [rsp+8], rsi
    mov [rsp+16], dl
    call go_count_string
    mov rax, [rsp+24]
    add rsp, 32
    pop r13
    pop r12
    pop rbx
    ret
go_count_string:
    mov rsi, [rsp+8]
    mov rbx, [rsp+16]
    mov al, [rsp+24]
    lea r8, [rsp+32]
    jmp countbody
// state_test(buffer, length, byte, output): seed all non-clobbered state,
// including DF and the complete 128-byte red zone below countbody's RSP.
state_test:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 280
    mov [rsp+256], rcx
    mov [rsp+264], rdi
    mov [rsp+272], rsi
    mov rbx, rsi
    mov rsi, rdi
    mov eax, edx
    lea r8, [rsp+248]
    mov ebp, 0x12345678
    mov r9d, 0x23456789
    mov r11d, 0x3456789a
    mov r13d, 0x456789ab
    mov r14d, 0x56789abc
    mov r15d, 0x6789abcd
    .irp reg,2,3,4,5,6,7,8,9,10,11,12,13,14,15
      pcmpeqd xmm\reg, xmm\reg
    .endr
    .irp off,16,24,32,40,48,56,64,72,80,88,96,104,112,120,128,136
      mov qword ptr [rsp-\off], 0x11223344
    .endr
    std
    call countbody
    pushfq
    pop rdx
    cld
    and edx, 0x400
    cmp edx, 0x400
    jne .Lbad
    cmp rbp, 0x12345678
    jne .Lbad
    cmp r9, 0x23456789
    jne .Lbad
    cmp r11, 0x3456789a
    jne .Lbad
    cmp r13, 0x456789ab
    jne .Lbad
    cmp r14, 0x56789abc
    jne .Lbad
    cmp r15, 0x6789abcd
    jne .Lbad
    cmp rsi, [rsp+264]
    jne .Lbad
    lea rax, [rsp+248]
    cmp r8, rax
    jne .Lbad
    pcmpeqd xmm0, xmm0
    .irp reg,2,3,4,5,6,7,8,9,10,11,12,13,14,15
      pcmpeqb xmm\reg, xmm0
      pmovmskb eax, xmm\reg
      cmp eax, 65535
      jne .Lbad
    .endr
    .irp off,16,24,32,40,48,56,64,72,80,88,96,104,112,120,128,136
      cmp qword ptr [rsp-\off], 0x11223344
      jne .Lbad
    .endr
    mov rcx, [rsp+256]
    mov rax, [rsp+248]
    mov [rcx], rax
    xor eax, eax
    jmp .Lrestore
.Lbad:
    mov eax, 1
.Lrestore:
    add rsp, 280
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.section .note.GNU-stack,"",@progbits
'''

C_TEST = r'''
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
extern uint64_t count_slice(const void *, size_t, unsigned char);
extern uint64_t count_string(const void *, size_t, unsigned char);
extern int state_test(const void *, size_t, unsigned char, uint64_t *);
static uint64_t cases;
static uint64_t rng=0x1029384756abcdefULL;
static uint64_t random64(void) { rng^=rng<<13; rng^=rng>>7; rng^=rng<<17; return rng; }
static void check(const unsigned char *p, size_t n, unsigned char c, int state) {
    uint64_t expected=0, out=0;
    for(size_t i=0;i<n;i++) expected += p[i]==c;
    uint64_t a=count_slice(p,n,c),b=count_string(p,n,c);
    if(a!=expected || b!=expected) {
        fprintf(stderr,"count mismatch length=%zu byte=%u expected=%lu got=%lu/%lu\n",n,c,expected,a,b); exit(1);
    }
    if(state && (state_test(p,n,c,&out) || out!=expected)) {
        fprintf(stderr,"state mismatch length=%zu byte=%u\n",n,c); exit(2);
    }
    cases++;
}
int main(void) {
    unsigned char data[65536+64];
    for(size_t i=0;i<sizeof(data);i++) data[i]=(unsigned char)(i*73+(i>>3));
    for(unsigned c=0;c<256;c++) for(size_t n=0;n<=128;n++) for(unsigned offset=0;offset<32;offset++)
        check(data+offset,n,c,n%31==0 && offset==0);
    for(unsigned mask=0;mask<65536;mask++) {
        for(unsigned i=0;i<16;i++) data[i]=(mask&(1u<<i))?0x42:0x24;
        check(data,16,0x42,0);
    }
    for(unsigned trial=0;trial<4000;trial++) {
        size_t n=random64()%65536,offset=random64()%32; unsigned char c=random64();
        for(size_t i=0;i<n;i++) data[offset+i]=(unsigned char)random64();
        check(data+offset,n,c,1);
    }
    long page=sysconf(_SC_PAGESIZE);
    if(page!=4096) { fprintf(stderr,"requires x86 Linux 4096-byte base pages\n"); return 3; }
    unsigned char *map=mmap(NULL,page*3,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(map==MAP_FAILED || mprotect(map+page,page,PROT_READ|PROT_WRITE)) return 4;
    unsigned char *live=map+page;
    for(unsigned c=0;c<256;c++) {
        memset(live,c,page);
        for(size_t n=0;n<=128;n++) {
            check(live,n,c,1);
            check(live+page-n,n,c,1);
            check(live+page-n,n,c^0xff,1);
        }
    }
    check(NULL,0,1,1); check(map,0,1,1); check(map+page*2,0,1,1);
    check(live,page,255,1);
    munmap(map,page*3);
    printf("PASS %lu cases (Count, CountString, randomized state and guard pages)\n",cases);
    return 0;
}
'''

GO_TEST = r'''
package main
import("bytes";"fmt";"runtime";"strings";"sync")
//go:noinline
func check(depth int, b []byte, c byte) {
    var pad [129]byte
    pad[depth%129]=byte(depth)
    if depth>0 { check(depth-1,b,c); if pad[depth%129]!=byte(depth) {panic("stack")} ; return }
    expected:=0; for _,x:=range b {if x==c {expected++}}
    if bytes.Count(b,[]byte{c})!=expected || strings.Count(string(b),string([]byte{c}))!=expected {panic("count")}
}
func main(){
    var wg sync.WaitGroup
    for g:=0;g<4;g++ {wg.Add(1);go func(g int){defer wg.Done();for n:=0;n<4096;n++ {
        b:=make([]byte,n%1031);for i:=range b {b[i]=byte(i*71+g)};check(12,b,byte(n));if n%101==0 {runtime.GC()}
    }}(g)};wg.Wait();fmt.Println("PASS Go Count/CountString concurrent GC and stack growth")
}
'''


class InplaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        resource.setrlimit(resource.RLIMIT_CORE, (0, resource.getrlimit(resource.RLIMIT_CORE)[1]))
        cls.temporary = tempfile.TemporaryDirectory(prefix='penryn-inplace-test-')
        cls.work = Path(cls.temporary.name)
        cls.body, cls.symbols = go_inplace.assemble(cls.work)
        (cls.work / 'bridges.S').write_text(BRIDGES)
        (cls.work / 'test.c').write_text(C_TEST)
        cls.binary = cls.work / 'counter-test'
        subprocess.run(['cc', '-O2', '-march=core2', '-fno-tree-vectorize', '-o', str(cls.binary),
                        str(cls.work/'test.c'), str(cls.work/'bridges.S'), str(cls.work/'countbody.S')],
                       check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_native_exhaustive_random_guard_pages_and_register_contract(self):
        result=subprocess.run([str(self.binary)],check=True,capture_output=True,text=True,timeout=120)
        self.assertIn('PASS',result.stdout)
        print(result.stdout.strip(),flush=True)

    def test_penryn_exhaustive_random_guard_pages_and_register_contract(self):
        env=dict(os.environ);env.pop('LD_PRELOAD',None);env.pop('LD_LIBRARY_PATH',None)
        result=subprocess.run(['qemu-x86_64','-cpu','Penryn','-U','LD_PRELOAD','-U','LD_LIBRARY_PATH',str(self.binary)],
                              env=env,check=True,capture_output=True,text=True,timeout=180)
        self.assertIn('PASS',result.stdout)

    def test_wrong_binary_and_missing_metadata_refused(self):
        with self.assertRaisesRegex(ValueError,'pinned agy'):
            go_inplace.plan(b'unknown',None,{})

    def test_static_stack_and_isa_audit(self):
        self.assertEqual(len(self.body),448)
        with self.assertRaisesRegex(ValueError,'RSP'):
            go_inplace.audit(b'\x48\x83\xec\x08\xc3',5,5)
        with self.assertRaisesRegex(ValueError,'unexpected'):
            go_inplace.audit(b'\xf3\x48\x0f\xb8\xc0\xc3',6,6)

    def test_go_count_and_countstring_gc_and_stack_growth(self):
        source=self.work/'main.go';source.write_text(GO_TEST)
        binary=self.work/'go-count'
        env=dict(os.environ,CGO_ENABLED='0',GOAMD64='v1',GOCACHE=str(self.work/'go-cache'))
        subprocess.run(['go','build','-o',str(binary),str(source)],env=env,check=True,capture_output=True,timeout=180)
        data=bytearray(binary.read_bytes());elf=ELFFile(io.BytesIO(data))
        syms={s.name:s for s in elf.get_section_by_name('.symtab').iter_symbols()}
        symbol=syms['countbody'];start=symbol['st_value'];size=symbol['st_size']
        self.assertGreaterEqual(size,self.symbols['countbody_end'])
        section=elf.get_section(symbol['st_shndx']);offset=section['sh_offset']+start-section['sh_addr']
        # Fixture-only substitution: this is not a way around plan()'s input
        # and metadata checks. The deployed recipe remains pinned to agy.
        data[offset:offset+size]=self.body[:self.symbols['countbody_end']]+b'\xcc'*(size-self.symbols['countbody_end'])
        binary.write_bytes(data)
        for qemu in (False,True):
            command=['qemu-x86_64','-cpu','Penryn',str(binary)] if qemu else [str(binary)]
            result=subprocess.run(command,env=dict(env,GOGC='1'),check=True,capture_output=True,text=True,timeout=180)
            self.assertIn('PASS Go',result.stdout)


class DispatchTests(unittest.TestCase):
    def test_zero_capability_excludes_instruction_but_not_bypass(self):
        from iced_x86 import Decoder
        # cmp byte [rip+0x20],0; je safe; popcnt rax,rax; safe: ret
        code=bytes.fromhex('803d2000000000 7405 f3480fb8c0 c3')
        instructions=list(Decoder(64,code,ip=0x1000))
        forced=go_inplace.flag_false_edges(instructions,0x1027)
        self.assertNotIn(0x1009,go_inplace.reachable(instructions,forced))
        self.assertIn(0x1009,go_inplace.reachable(instructions))
        # A second entry bypasses the check. No forced branch applies there.
        self.assertIn(0x1009,go_inplace.reachable(instructions[2:],forced))

    def test_unknown_dispatch_input_refused(self):
        with self.assertRaisesRegex(ValueError,'pinned agy'):
            go_inplace.dormant(b'unknown',None,{})

    def test_helper_references_cannot_bypass_guard_or_escape(self):
        import struct
        from unittest.mock import patch
        class Section(dict):
            def data(self):return self['blob']
        class Elf:
            def __init__(self,data):self.data=data
            def iter_sections(self):
                return iter([Section(sh_flags=6,sh_type='SHT_PROGBITS',sh_addr=0x1000,blob=self.data[:0x30])])
            def iter_segments(self):
                return iter([dict(p_type='PT_LOAD',p_flags=5,p_vaddr=0x1000,p_offset=0,p_filesz=len(self.data))])
        metadata={'tables':[{'functions':[{'name':'caller','start':0x1000,'end':0x1020},
                                          {'name':'helper','start':0x1020,'end':0x1030}]}]}
        def run(code,extra=b''):
            data=code+b'\x90'*(0x20-len(code))+b'\xc3'+b'\x90'*15+extra
            return go_inplace._closed_direct_references(data,Elf(data),metadata,[(0x1020,0x1030)],{0x1020})
        with patch.object(go_inplace,'CRC_CALLS',{0x1000:0x1020}):
            self.assertEqual(run(b'\xe8'+struct.pack('<i',0x1b)+b'\xc3'),[(0x1000,0x1020)])
            with self.assertRaisesRegex(ValueError,'bypasses'):
                run(b'\xe8'+struct.pack('<i',0x1c)+b'\xc3')
            with self.assertRaisesRegex(ValueError,'bypasses'):
                run(b'\xeb\x1f\xc3')
            with self.assertRaisesRegex(ValueError,'escapes'):
                run(b'\x48\x8d\x05'+struct.pack('<i',0x19)+b'\xc3')
            with self.assertRaisesRegex(ValueError,'literal'):
                run(b'\xe8'+struct.pack('<i',0x1b)+b'\xc3',struct.pack('<Q',0x1020))


if __name__=='__main__':unittest.main()
