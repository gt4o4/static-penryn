#!/usr/bin/env python3
"""Exercise native unwinding from patched PCs, faults, and Go runtime gates.

The signal tests intentionally use libgcc's real unwinder from a warmed-up
signal handler. They measure the implementation, not a general assertion
that arbitrary application callbacks are async-signal-safe.
"""
import io
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

from elftools.elf.elffile import ELFFile
from iced_x86 import Decoder,Mnemonic

import unwind

HERE = Path(__file__).resolve().parent

C_FIXTURE = r'''
#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <sys/time.h>
#include <ucontext.h>
#include <unistd.h>
#include <unwind.h>

extern void caller(unsigned long);
extern char caller_return[];
static uintptr_t stub_begin, stub_end;
static volatile sig_atomic_t samples, in_stub, failures;
struct walk { int found; };
static _Unwind_Reason_Code visit(struct _Unwind_Context *c, void *opaque) {
  struct walk *w = opaque;
  uintptr_t ip = _Unwind_GetIP(c);
  if (ip == (uintptr_t)caller_return) w->found = 1;
  return _URC_NO_REASON;
}
static void handler(int sig, siginfo_t *info, void *opaque) {
  ucontext_t *ctx = opaque;
  uintptr_t ip = ctx->uc_mcontext.gregs[REG_RIP];
  struct walk w = {0};
  _Unwind_Backtrace(visit, &w);
  samples++;
  if (ip >= stub_begin && ip < stub_end) {
    in_stub++;
    if (!w.found) failures++;
  }
  if (sig == SIGSEGV) {
    int ok = ip >= stub_begin && ip < stub_end && w.found && info->si_addr == 0;
    if (ok) write(1, "FAULT_UNWIND_OK\n", 16);
    _exit(ok ? 0 : 23);
  }
}
int main(int argc, char **argv) {
  if (argc != 4) return 2;
  stub_begin = strtoull(argv[1], 0, 0);
  stub_end = strtoull(argv[2], 0, 0);
  struct walk warm = {0};
  _Unwind_Backtrace(visit, &warm);
  struct sigaction action = {.sa_sigaction=handler, .sa_flags=SA_SIGINFO};
  sigemptyset(&action.sa_mask);
  sigaction(SIGALRM,&action,0); sigaction(SIGSEGV,&action,0);
  if (argv[3][0] == 'f') { caller(0); return 24; }
  struct itimerval timer = {{0, 500},{0,500}};
  setitimer(ITIMER_REAL,&timer,0);
  for (int i=0;i<500 && (samples<80 || in_stub<20);i++) caller(500000);
  timer.it_interval.tv_usec=timer.it_value.tv_usec=0;
  setitimer(ITIMER_REAL,&timer,0);
  printf("samples=%d in_stub=%d failures=%d\n", samples,in_stub,failures);
  return in_stub>=20 && failures==0 ? 0 : 25;
}
'''

# Walk the interrupted frame chain directly, independently of libgcc/CFI.
# A DWARF-only test would miss a trampoline repurposing RBP temporarily.
FRAME_C_FIXTURE = C_FIXTURE.replace('#include <unwind.h>',
    '#include <unwind.h>\n#include <pthread.h>\nstatic uintptr_t stack_low,stack_high;').replace(
    'struct walk w = {0};\n  _Unwind_Backtrace(visit, &w);\n  samples++;',
    '''struct walk w = {0};
  uintptr_t bp = ctx->uc_mcontext.gregs[REG_RBP];
  for (int depth=0; depth<32 && bp>=stack_low && bp<=stack_high-16 && !(bp&7); depth++) {
    uintptr_t *frame=(uintptr_t *)bp;
    if (frame[1] == (uintptr_t)caller_return) { w.found=1; break; }
    if (frame[0]<=bp) break;
    bp=frame[0];
  }
  samples++;''').replace(
    'stub_begin = strtoull(argv[1], 0, 0);',
    '''pthread_attr_t attr; void *stack; size_t size;
  if (pthread_getattr_np(pthread_self(), &attr) || pthread_attr_getstack(&attr,&stack,&size)) return 26;
  pthread_attr_destroy(&attr);
  stack_low=(uintptr_t)stack; stack_high=stack_low+size;
  stub_begin = strtoull(argv[1], 0, 0);''')

ASM_FIXTURE = r'''
.intel_syntax noprefix
.text
.global caller
.type caller,@function
caller:
.cfi_startproc
sub rsp,8
.cfi_adjust_cfa_offset 8
call exercise
.global caller_return
caller_return:
add rsp,8
.cfi_adjust_cfa_offset -8
ret
.cfi_endproc
.size caller,.-caller
.global exercise
.type exercise,@function
exercise:
.cfi_startproc
push rbx
.cfi_adjust_cfa_offset 8
.cfi_offset rbx,-16
mov r8,rdi
mov rax,-1
.Lagain:
BODY
dec r8
jnz .Lagain
pop rbx
.cfi_adjust_cfa_offset -8
.cfi_restore rbx
ret
.cfi_endproc
.size exercise,.-exercise
.section .note.GNU-stack,"",@progbits
'''


class RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, hard = resource.getrlimit(resource.RLIMIT_CORE)
        resource.setrlimit(resource.RLIMIT_CORE, (0, hard))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='penryn-runtime-')
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)

    def compile(self, body):
        (self.work/'fixture.c').write_text(C_FIXTURE)
        (self.work/'fixture.S').write_text(ASM_FIXTURE.replace('BODY',body))
        binary = self.work/'original'
        subprocess.run(['cc','-O2','-fomit-frame-pointer','-fasynchronous-unwind-tables',
                        '-no-pie',str(self.work/'fixture.c'),str(self.work/'fixture.S'),
                        '-o',str(binary)],check=True)
        return binary

    def patch(self, binary, *extra):
        output = self.work/'patched'
        run = subprocess.run([sys.executable,str(HERE/'patch.py'),str(binary),str(output),
                              '--allow-relocate','--require-unwind',*extra],
                             capture_output=True,text=True,timeout=90)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr)
        report = json.loads(Path(str(output)+'.json').read_text())
        with output.open('rb') as stream:
            sec = ELFFile(stream).get_section_by_name('.penryn')
            self.assertIsNotNone(sec)
            limits = [hex(sec['sh_addr']),hex(sec['sh_addr']+sec['sh_size'])]
        return output,limits,report

    def test_timer_backtraces_from_scalar_replacements(self):
        binary = self.compile('popcnt rbx,rax\ncrc32 rdx,rax\npcmpgtq xmm1,xmm2')
        output,limits,_ = self.patch(binary,'--no-dataflow')
        result = subprocess.run([str(output),*limits,'timer'],capture_output=True,text=True,timeout=25)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('failures=0',result.stdout)
        print('native timer:',result.stdout.strip())

    def test_frame_pointer_walks_during_string_helper(self):
        assembly = ASM_FIXTURE.replace('BODY','pcmpestri xmm1,xmm2,0x0c')
        assembly = assembly.replace('sub rsp,8\n.cfi_adjust_cfa_offset 8\ncall exercise',
            'push rbp\n.cfi_def_cfa_offset 16\n.cfi_offset rbp,-16\n'
            'mov rbp,rsp\n.cfi_def_cfa_register rbp\ncall exercise')
        assembly = assembly.replace('add rsp,8\n.cfi_adjust_cfa_offset -8\nret',
            'pop rbp\n.cfi_def_cfa rsp,8\n.cfi_restore rbp\nret')
        assembly = assembly.replace('push rbx\n.cfi_adjust_cfa_offset 8\n.cfi_offset rbx,-16',
            'push rbp\n.cfi_def_cfa_offset 16\n.cfi_offset rbp,-16\n'
            'mov rbp,rsp\n.cfi_def_cfa_register rbp\npush rbx\n.cfi_offset rbx,-24')
        assembly = assembly.replace('pop rbx\n.cfi_adjust_cfa_offset -8\n.cfi_restore rbx\nret',
            'pop rbx\n.cfi_restore rbx\npop rbp\n.cfi_def_cfa rsp,8\n.cfi_restore rbp\nret')
        (self.work/'fixture.c').write_text(FRAME_C_FIXTURE)
        (self.work/'fixture.S').write_text(assembly)
        binary = self.work/'original'
        subprocess.run(['cc','-O2','-fno-omit-frame-pointer','-no-pie',
                        str(self.work/'fixture.c'),str(self.work/'fixture.S'),
                        '-o',str(binary)],check=True)
        output,limits,_ = self.patch(binary,'--no-dataflow')
        result = subprocess.run([str(output),*limits,'timer'],capture_output=True,text=True,timeout=25)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('failures=0',result.stdout)
        print('native frame pointers:',result.stdout.strip())

    def test_fault_backtrace_and_fault_address_under_penryn(self):
        binary = self.compile('popcnt rax,QWORD PTR [rdi]')
        output,limits,_ = self.patch(binary)
        env = os.environ.copy();env.pop('LD_PRELOAD',None)
        control = subprocess.run(['qemu-x86_64','-cpu','Penryn',str(binary),'0','0','fault'],
                                 capture_output=True,env=env,timeout=10)
        self.assertEqual(control.returncode,-signal.SIGILL,control.stderr)
        result = subprocess.run(['qemu-x86_64','-cpu','Penryn',str(output),*limits,'fault'],
                                capture_output=True,env=env,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn(b'FAULT_UNWIND_OK',result.stdout)

    def test_timer_backtraces_from_string_helper(self):
        binary = self.compile('mov edx,16\nmov eax,16\npcmpestri xmm1,xmm2,0')
        output,limits,_ = self.patch(binary,'--no-dataflow')
        result = subprocess.run([str(output),*limits,'timer'],capture_output=True,text=True,timeout=25)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('failures=0',result.stdout)
        print('native string timer:',result.stdout.strip())

    def test_timer_backtraces_from_shared_frame_region(self):
        binary = self.compile('popcnt rbx,rax\nadd rbx,rdx\npopcnt rdx,rax\n'
                              'popcnt rsi,rax\npopcnt rdi,rax')
        output,limits,report = self.patch(binary,'--no-dataflow','--regions')
        self.assertGreater(report['fused_regions'],0)
        self.assertTrue(report['unwind']['native_coverage_complete'])
        result = subprocess.run([str(output),*limits,'timer'],capture_output=True,text=True,timeout=25)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('failures=0',result.stdout)
        print('native shared-frame timer:',result.stdout.strip())

    def test_dynamic_stack_anchor_cfi(self):
        # These rows reconstruct the original frame-pointer CFA after the
        # trampoline saves RBP, repurposes it, then aligns RSP dynamically.
        from elftools.dwarf.callframe import CFARule,RegisterRule
        inherited = {'cfa':CFARule(reg=6,offset=16),16:RegisterRule('OFFSET',-8),
                     6:RegisterRule('OFFSET',-16)}
        code=bytes.fromhex('488d64248055488bec4883e4f0')
        machine=unwind.Machine()
        for ins in Decoder(64,code):
            machine.step(ins)
            machine.rules(inherited)
        self.assertIsNone(machine.delta)
        self.assertIn(6,machine.anchors)
        stack_cfa = {**inherited,'cfa':CFARule(reg=7,offset=16)}
        self.assertTrue(machine.rules(stack_cfa)[0].startswith('.cfi_escape 15,'))

    def test_missing_original_fde_is_explicit_gap(self):
        binary=self.compile('popcnt rbx,rax')
        with binary.open('rb') as stream:
            index=unwind.Index(ELFFile(stream))
            with self.assertRaisesRegex(unwind.Unsupported,'no native'):
                index.row(1)

    def test_original_signal_frame_is_refused(self):
        binary=self.compile('popcnt rbx,rax')
        with binary.open('rb') as stream:
            index=unwind.Index(ELFFile(stream))
            fde=index.fdes[-1]
            fde.cie.header['augmentation']=b'zRS'
            with self.assertRaisesRegex(unwind.Unsupported,'signal frame'):
                index.row(fde['initial_location'])

    def test_helper_lsda_is_refused(self):
        binary=self.compile('popcnt rbx,rax')
        with binary.open('rb') as stream:
            fde=unwind.Index(ELFFile(stream)).fdes[-1]
            fde.lsda_pointer=0x1234
            with self.assertRaisesRegex(unwind.Unsupported,'landing pads'):
                unwind._helper_assembly(fde)

    def test_untracked_stack_write_refused(self):
        machine=unwind.Machine()
        with self.assertRaisesRegex(unwind.Unsupported,'untracked'):
            machine.step(Decoder(64,bytes.fromhex('4889c4')).decode())


class GoMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('go'):
            raise unittest.SkipTest('Go compiler required for runtime metadata fixtures')
        cls.tmp = tempfile.TemporaryDirectory(prefix='penryn-go-metadata-')
        cls.work = Path(cls.tmp.name)
        cls.helper = cls.work/'penryn-go-metadata'
        subprocess.run(['go','build','-o',str(cls.helper),str(HERE/'go_metadata.go')],check=True)
        cls.binary = cls.work/'go-original'
        env = {**os.environ,'GO111MODULE':'off','GOAMD64':'v1'}
        subprocess.run(['go','build','-o',str(cls.binary),'.'],cwd=HERE/'runtime-fixtures/go',env=env,check=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_standard_library_recovers_stripped_go(self):
        stripped = self.work/'go-stripped'
        subprocess.run(['objcopy','--strip-all',str(self.binary),str(stripped)],check=True)
        metadata = unwind.load_go_metadata(stripped,self.helper)
        self.assertTrue(metadata['tables'])
        self.assertEqual(metadata['rejected_candidates'],[])
        functions = [f for t in metadata['tables'] for f in t['functions']]
        self.assertTrue(any('main.forcedPopcnt' in f['name'] for f in functions))

    def test_go_sites_fail_runtime_gate(self):
        metadata = unwind.load_go_metadata(self.binary,self.helper)
        with self.binary.open('rb') as stream:
            elf=ELFFile(stream)
            functions = [f for t in metadata['tables'] for f in t['functions']]
            force = next(f for f in functions if 'main.forcedPopcnt' in f['name'])
            text = elf.get_section_by_name('.text')
            offset = force['start']-text['sh_addr']
            instructions=list(Decoder(64,text.data()[offset:offset+force['end']-force['start']],ip=force['start']))
            ins=next(i for i in instructions if i.mnemonic==Mnemonic.POPCNT)
            audit=unwind.audit_runtime(elf,[SimpleNamespace(insns=[ins])],metadata)
        self.assertEqual(len(audit['go_patch_sites']),1)
        self.assertFalse(audit['production_ready'])
        self.assertFalse(audit['go_safepoints_supported'])
        self.assertTrue(audit['strict_runtime_reasons'])

    def test_require_unwind_refuses_go_before_publishing(self):
        output = self.work/'go-strict'
        env = {**os.environ,'PENRYN_GOMETA':str(self.helper)}
        result = subprocess.run([sys.executable,str(HERE/'patch.py'),str(self.binary),str(output),
                                 '--allow-relocate','--require-unwind'],
                                capture_output=True,text=True,timeout=90,env=env)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Go',result.stdout+result.stderr)
        self.assertFalse(output.exists())
        self.assertFalse(Path(str(output)+'.json').exists())


if __name__=='__main__':
    unittest.main()
