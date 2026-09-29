#!/usr/bin/env python3
"""Profiler counter, PIE/interpreter, identity and perf mapping regressions."""
import hashlib
import io
import json
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import unittest

from elftools.elf.elffile import ELFFile

from static_penryn import profile as profiler
from static_penryn import workloads


class ProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        resource.setrlimit(resource.RLIMIT_CORE, (0, resource.getrlimit(resource.RLIMIT_CORE)[1]))

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='penryn-profile-test-')
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)

    def fixture(self, pie=False):
        source = self.work / 'input.S'
        source.write_text('''
.intel_syntax noprefix
.text
.global _start
_start:
    mov ecx, 1000
    xor edi, edi
    jmp probe
.section .penryn,"ax",@progbits
.global probe, increment_end, probe_end
probe:
    add edi, 1
increment_end:
    dec ecx
    jnz probe
probe_end:
    cmp edi, 1000
    jne failed
    xor edi, edi
    mov eax, 60
    syscall
failed:
    mov edi, 1
    mov eax, 60
    syscall
.section .note.GNU-stack,"",@progbits
''')
        binary = self.work / 'input'
        # Keep the compiler's matching libc in DT_NEEDED/RUNPATH: this host's
        # /etc/ld.so.preload otherwise pulls a different libc into empty PIEs.
        subprocess.run(['cc', '-nostdlib', '-pie' if pie else '-no-pie',
                        *(['-Wl,--no-as-needed', '-lc'] if pie else []),
                        '-o', str(binary), str(source)], capture_output=True, check=True)
        data = binary.read_bytes()
        elf = ELFFile(io.BytesIO(data))
        symbols = {s.name: s['st_value'] for s in elf.get_section_by_name('.symtab').iter_symbols()}
        report = dict(input_sha256='0' * 64, output_sha256=hashlib.sha256(data).hexdigest(),
                      patches=[dict(address=hex(elf['e_entry']), stub=hex(symbols['probe']),
                                    stub_end=hex(symbols['probe_end']), instructions=['fixture add'],
                                    instruction_ranges=[dict(original_address=hex(elf['e_entry']),
                                                             start=hex(symbols['probe']),
                                                             end=hex(symbols['increment_end']), mnemonic='ADD')])])
        report_path = self.work / 'input.json'
        report_path.write_text(json.dumps(report))
        return binary, report_path

    def test_exact_instruction_and_region_counts_exec(self):
        binary, report = self.fixture()
        model = profiler.load_model(binary, report)
        result = profiler.count(model, [], self.work / 'count')
        site = next(r for r in result['rows'] if r['kind'] == 'site')
        instruction = next(r for r in result['rows'] if r['kind'] == 'instruction')
        self.assertEqual((site['entries'], site['generated_instructions']), (1000, 3000))
        self.assertEqual((instruction['entries'], instruction['generated_instructions']), (1000, 1000))
        self.assertEqual(result['load_bias'], '0x0')

    def test_pie_interpreter_does_not_determine_main_load_bias(self):
        binary, report = self.fixture(pie=True)
        elf = ELFFile(io.BytesIO(binary.read_bytes()))
        self.assertTrue(any(s['p_type'] == 'PT_INTERP' for s in elf.iter_segments()))
        result = profiler.count(profiler.load_model(binary, report), [], self.work / 'count')
        self.assertEqual(result['site_counts'][0]['executions'], 1000)
        self.assertNotEqual(result['load_bias'], '0x0')

    def test_grouped_four_instruction_counts_remain_stable(self):
        source = self.work / 'four.S'
        source.write_text('''
.intel_syntax noprefix
.text
.global _start
_start:
    mov ecx, 37
    mov rdi, -1
again:
    popcnt rax, rdi
    mov r10, rax
    popcnt rbx, rdi
    add r10, rbx
    popcnt r8, rdi
    mov r11, r8
    popcnt r9, rdi
    sub r11, r9
    dec ecx
    jnz again
    xor edi, edi
    mov eax, 60
    syscall
.section .note.GNU-stack,"",@progbits
''')
        binary = self.work / 'four'
        subprocess.run(['cc', '-nostdlib', '-no-pie', '-o', str(binary), str(source)],
                       capture_output=True, check=True)
        profiles, addresses = [], None
        for grouped in (False, True):
            output = self.work / ('grouped' if grouped else 'separate')
            rewritten = subprocess.run([sys.executable, '-m', 'static_penryn.patch', str(binary), str(output),
                                        *(['--regions', '--allow-relocate'] if grouped else [])], capture_output=True)
            self.assertEqual(rewritten.returncode, 0, (rewritten.stdout + rewritten.stderr).decode(errors='replace'))
            report = json.loads(Path(str(output) + '.json').read_text())
            if grouped:
                self.assertEqual(len(report['patches']), 1, 'fixture must exercise a real fused region')
            else:
                self.assertEqual(len(report['patches']), 4)
                addresses = {p['address'] for p in report['patches']}
            profile = profiler.count(profiler.load_model(output, str(output) + '.json'), [],
                                     self.work / ('count-grouped' if grouped else 'count-separate'))
            weights = {r['address']: r['executions'] for r in profile['site_counts'] if r['address'] in addresses}
            self.assertEqual(len(weights), 4)
            self.assertEqual(set(weights.values()), {37})
            self.assertEqual(len(profile['site_counts']), len({r['address'] for r in profile['site_counts']}))
            profiles.append(weights)
        self.assertEqual(profiles[0], profiles[1])

    def test_loader_preinit_before_entry_is_counted(self):
        # The loader runs PREINIT_ARRAY before _start. entry_seen is an
        # identity check, not a condition for arming counters.
        source=self.work/'preinit.S'
        source.write_text('''
.intel_syntax noprefix
.text
.global _start
_start:
    mov edi, 1
    cmp dword ptr [rip + ready], 1
    jne done
    xor edi, edi
done:
    mov eax, 60
    syscall
.section .penryn,"ax",@progbits
.global preinit, preinit_end
preinit:
    mov dword ptr [rip + ready], 1
    ret
preinit_end:
.section .preinit_array,"aw",@preinit_array
    .quad preinit
.bss
ready:
    .zero 4
.section .note.GNU-stack,"",@progbits
''')
        binary=self.work/'preinit'
        subprocess.run(['cc','-nostdlib','-pie','-Wl,--no-as-needed','-lc',
                        '-o',str(binary),str(source)],check=True,capture_output=True)
        data=binary.read_bytes();elf=ELFFile(io.BytesIO(data))
        symbols={s.name:s['st_value'] for s in elf.get_section_by_name('.symtab').iter_symbols()}
        report=dict(input_sha256='0'*64,output_sha256=hashlib.sha256(data).hexdigest(),patches=[],
                    helpers=[dict(name='preinit',start=symbols['preinit'],end=symbols['preinit_end'])])
        path=self.work/'preinit.json';path.write_text(json.dumps(report))
        result=profiler.count(profiler.load_model(binary,path),[],self.work/'count-preinit')
        self.assertEqual((result['rows'][0]['entries'],result['rows'][0]['generated_instructions']),(1,2))

    def test_wrong_binary_rejected_before_execution(self):
        binary, report = self.fixture()
        with binary.open('ab') as f:
            f.write(b'changed')
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            profiler.load_model(binary, report)

    def test_inplace_code_counts_without_inventing_instruction_weights(self):
        binary, path = self.fixture()
        report = json.loads(path.read_text())
        start = int(report['patches'][0]['stub'], 16)
        end = int(report['patches'][0]['stub_end'], 16)
        report['patches'] = []
        report['inplace_patches'] = [dict(address=start, evidence=dict(function='counter', code_bytes=end-start))]
        path.write_text(json.dumps(report))
        result = profiler.count(profiler.load_model(binary, path), [], self.work/'count-inplace')
        self.assertEqual(result['site_counts'], [])
        helper = next(row for row in result['rows'] if row['kind'] == 'helper')
        self.assertTrue(helper['inplace'])
        self.assertEqual((helper['entries'], helper['generated_instructions']), (1000, 3000))

    def test_wrong_runtime_bias_does_not_silently_report_zero(self):
        binary, report = self.fixture()
        model = profiler.load_model(binary, report)
        model['code_start'] -= 4096
        with self.assertRaisesRegex(RuntimeError, 'load-bias'):
            profiler.count(model, [], self.work / 'count')

    def test_reject_overlapping_ranges(self):
        binary, report_path = self.fixture()
        report = json.loads(report_path.read_text())
        report['patches'].append(report['patches'][0])
        report_path.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, 'overlapping'):
            profiler.load_model(binary, report_path)

    def test_old_report_requires_explicit_advisory_opt_in(self):
        binary, report_path = self.fixture()
        report = json.loads(report_path.read_text())
        del report['patches'][0]['stub_end']
        report_path.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, 'exact stub'):
            profiler.load_model(binary, report_path)
        model = profiler.load_model(binary, report_path, legacy=True)
        self.assertEqual(model['range_accuracy'], 'inferred')

    def test_environment_does_not_inherit_credentials(self):
        import os
        from unittest.mock import patch
        with patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'do-not-copy', 'LD_PRELOAD': 'do-not-copy'}):
            env = profiler.environment(self.work / 'home')
        self.assertNotIn('ANTHROPIC_API_KEY', env)
        self.assertNotIn('LD_PRELOAD', env)
        self.assertEqual(env['SIMDUTF_FORCE_IMPLEMENTATION'], 'westmere')

    def test_perf_overlapping_mappings_preserve_surviving_intervals(self):
        model = dict(binary='/tmp/patched', loads=[dict(p_vaddr=0, p_offset=0, p_filesz=0x4000),
                                                 dict(p_vaddr=0x3000, p_offset=0x5000, p_filesz=0x1000)],
                     rows=[dict(kind='site', start=0x1000, end=0x1010, original_address='0x400'),
                           dict(kind='helper', start=0x3000, end=0x3010, name='shared')])
        script = '''
 10/10 1.0: cpu-clock:u: 601001
 10/10 2.0: PERF_RECORD_MMAP2 10/10: [0x600000(0x4000) @ 0 <abcd>]: r-xp /tmp/patched
 10/10 2.1: PERF_RECORD_MMAP2 10/10: [0x603000(0x1000) @ 0x5000 <abcd>]: r-xp /tmp/patched
 10/10 3.0: cpu-clock:u: 601001
 10/11 3.1: cpu-clock:u: 603001
 10/10 3.2: cpu-clock:u: 602001
 10/10 3.3: cpu-clock:u: 700001
 10/10 4.0: PERF_RECORD_MMAP2 10/10: [0x601000(0x1000) @ 0 <dcba>]: r-xp /tmp/unrelated
 10/10 4.1: cpu-clock:u: 601001
'''
        result = profiler.parse_perf(model, script)
        self.assertEqual(result['total_samples'], 5)
        self.assertEqual(result['executable_outside_patch_samples'], 1)
        self.assertEqual(result['other_mapping_samples'], 2)
        self.assertEqual([r['samples'] for r in result['rows']], [1, 1])
        # A different file with the same basename (or a case variation) must
        # remove an overwritten mapping without being attributed to this ELF.
        for other in ('/another/patched', '/tmp/Patched'):
            self.assertEqual(profiler.parse_perf(model, script.replace('/tmp/unrelated', other)), result)

    def test_perf_bad_format_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'sample format'):
            profiler.parse_perf(dict(binary='/tmp/b', rows=[], loads=[]), 'unrecognized cpu-clock:u sample')
        with self.assertRaisesRegex(ValueError, 'no matching executable'):
            profiler.parse_perf(dict(binary='/tmp/b', rows=[], loads=[]), '10/10 1.0: cpu-clock:u: 4000')

    def test_perf_shared_file_page_resolves_only_executable_segment(self):
        # Claude's read-only and executable LOADs share a file page while
        # having different virtual addresses; MMAP records are executable.
        model = dict(loads=[dict(p_vaddr=0x200000, p_offset=0x1000, p_filesz=0x1721a0c, p_flags=4),
                            dict(p_vaddr=0x1922c00, p_offset=0x1722c00, p_filesz=0x3ae5200, p_flags=5)])
        self.assertEqual(profiler.mmap_bias(model, 0x1922000, 0x1722000), 0)

    def test_fixture_determinism_and_independent_search_output(self):
        first, expected1 = workloads.fixture(self.work / 'one', files=9, lines=17)
        second, expected2 = workloads.fixture(self.work / 'two', files=9, lines=17)
        self.assertEqual(first, second)
        self.assertEqual(expected1['rg-search'].count(b'\n'), first['matching_lines'])
        self.assertEqual(expected1['rg-files'].count(b'\n'), 9)
        self.assertEqual(expected1['rg-utf8'].count(b':17\n'), 9)
        self.assertEqual(expected1['rg-search'].replace(b'/one/', b'/two/'), expected2['rg-search'])


if __name__ == '__main__':
    unittest.main()
