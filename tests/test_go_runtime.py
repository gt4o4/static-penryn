"""Go runtime recognition, original-frame unwinding, GC and PIE relocation."""
import io
import json
import os
import resource
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from types import SimpleNamespace

from elftools.elf.elffile import ELFFile
from iced_x86 import Decoder, Mnemonic, Register

from static_penryn import go_runtime

HERE = Path(__file__).resolve().parent
GO = shutil.which('go') or '/nix/store/hfb2fkwkkr6jdcg2ggibvf1zablw7i57-go-1.26.7/share/go/bin/go'


class Encoding(unittest.TestCase):
    def test_constant_pc_roundtrip(self):
        for value in (-5, -2, -1, 0, 1, 152, 65536):
            raw = b'\0' + go_runtime.constpc(value, 137)
            self.assertEqual(go_runtime.pcvalues(raw, 1, 20, 157), [(20, 157, value)])

    def test_invalid_tables_fail_closed(self):
        for raw in (b'\0\x80', b'\0\x80\x80\x80\x80\x80', b'\0\x80\x80\x80\x80\x10', b'\0\x02\0\0', b'\0\x02\x7f\0'):
            with self.assertRaises(go_runtime.Unsupported):
                go_runtime.pcvalues(raw, 1, 0, 100)

    def test_pinned_legacy_init_call_redirection(self):
        chunks = {0x67fe016: bytes.fromhex('488d0da3e85303'),
                  0x9d3c8c0: bytes.fromhex('554889e5415741564155415453504889d34989f64189ff'),
                  0x9d3c8d7: bytes.fromhex('e8d0320000')}
        audit = SimpleNamespace(profile={'name': 'agy-1.2.7-go1.28-20260721-RC03-pinned'},
                                read=lambda address, size: chunks[address][:size],
                                offset=lambda address, size: address)
        patch = go_runtime.legacy_init_patch(audit, 0x9d3fbac, 0x10240000)
        call = next(iter(Decoder(64, patch['new'], ip=0x9d3c8d7)))
        self.assertEqual(call.near_branch_target, 0x10240000)
        self.assertEqual(call.mnemonic, Mnemonic.CALL)
        self.assertEqual(patch['old'], chunks[0x9d3c8d7])
        chunks[0x9d3c8d7] = b'\x90' * 5
        with self.assertRaises(go_runtime.Unsupported):
            go_runtime.legacy_init_patch(audit, 0x9d3fbac, 0x10240000)
        with self.assertRaises(go_runtime.Unsupported):
            go_runtime.legacy_init_patch(audit, 0, 0x10240000)

    def test_pinned_preinit_relocation_preserves_callback_order(self):
        tags = [SimpleNamespace(entry=SimpleNamespace(d_tag=key,d_val=value))
                for key,value in [('DT_PREINIT_ARRAY',0x9f45840),('DT_PREINIT_ARRAYSZ',16)]]
        dynamic=SimpleNamespace(iter_tags=lambda: iter(tags))
        class Rela(dict):
            def data(self):
                return struct.pack('<QQqQQq',0x9f45840,8,0x9c0ffa0,0x9f45848,8,0x9c741b0)
        rela=Rela(sh_type='SHT_RELA',sh_flags=2,sh_offset=0x100)
        chunks={0x9f45840:bytes(16),0x9c0ffa0:bytes.fromhex('554889e55350e8757412004883c4085b5dc3')}
        audit=SimpleNamespace(profile={'name':'agy-1.2.7-go1.28-20260721-RC03-pinned'},
                              elf=SimpleNamespace(get_section_by_name=lambda name:dynamic,
                                                  iter_sections=lambda:iter([rela])),
                              read=lambda address,size:chunks[address][:size])
        plan=go_runtime.preinit_registration(audit,0x10240000)
        self.assertEqual(plan['target'],0x9c0ffa0)
        self.assertEqual(plan['patches'],[dict(offset=0x110,old=struct.pack('<q',0x9c0ffa0),
                                             new=struct.pack('<q',0x10240000))])
        self.assertEqual(plan['evidence']['original_second_callback'],0x9c741b0)
        chunks[0x9f45840]=b'\xff'*16
        with self.assertRaises(go_runtime.Unsupported):
            go_runtime.preinit_registration(audit,0x10240000)

    def test_forbidden_stub_stack_and_calls(self):
        for code in (b'\x50\xe9\x00\x00\x00\x00', b'\xe8\0\0\0\0\xe9\0\0\0\0'):
            with self.assertRaises(go_runtime.Unsupported):
                go_runtime.validate_code(code, 0x1000, 0x1000+len(code), 0x1000+len(code))


class TypeGuard(unittest.TestCase):
    def proof(self, read=None, offset=None):
        chunks={0x6884f9d:bytes.fromhex('48833d6b48440500'),
                0x6884fa5:bytes.fromhex('0f8427010000'),
                0x68850d2:bytes.fromhex('4881c4c80200005dc3')}
        words={0xbcc9810:0,0xbcca438:0xbcc95e0}
        audit=SimpleNamespace(profile=dict(name='agy-1.2.7-go1.28-20260721-RC03-pinned',
                                          module=0xbcc95e0,lastmoduledatap=0xbcca438,next=0x230,size=568),
                              read=read or (lambda a,n:chunks[a][:n]),
                              offset=offset or (lambda a,n:a), word=lambda a:words[a])
        metadata=0x10242000
        fixups=[(0xbcc9810,metadata),(0xbcca438,metadata)]
        return audit,bytearray(568),metadata,fixups,chunks,words

    def test_typeless_guard_refuses_changed_topology_types_and_fixups(self):
        audit,blob,metadata,fixups,chunks,words=self.proof()
        patch=go_runtime.typelinks_fast_path_patch(audit,blob,metadata,fixups)
        self.assertEqual(patch['offset'],0x6884fa0)
        self.assertEqual(0x6884fa5+struct.unpack('<i',patch['new'])[0],metadata+0x230)
        for field in (0x128,0x130,0x138,0x140,0x148,0x150,0x160,0x180,0x228,0x230):
            populated=bytearray(blob);populated[field]=1
            with self.assertRaises(go_runtime.Unsupported):
                go_runtime.typelinks_fast_path_patch(audit,populated,metadata,fixups)
        for field in (0x124,0x128,0x15c,0x180,0x228,0x230):
            with self.assertRaises(go_runtime.Unsupported):
                go_runtime.typelinks_fast_path_patch(audit,blob,metadata,fixups+[(metadata+field,1)])
        for slot in (0xbcc9810,0xbcca438):
            old=words[slot];words[slot]=0x12345678
            with self.assertRaises(go_runtime.Unsupported):
                go_runtime.typelinks_fast_path_patch(audit,blob,metadata,fixups)
            words[slot]=old
        for wrong in (fixups[:-1],fixups+[(0xbcca438,0xbcc95e0)],fixups+[(0xbcca434,metadata)]):
            with self.assertRaises(go_runtime.Unsupported):
                go_runtime.typelinks_fast_path_patch(audit,blob,metadata,wrong)
        for pc in chunks:
            old=chunks[pc];chunks[pc]=b'\x90'*len(old)
            with self.assertRaises(go_runtime.Unsupported):
                go_runtime.typelinks_fast_path_patch(audit,blob,metadata,fixups)
            chunks[pc]=old
        far=0x1000000000
        with self.assertRaises(go_runtime.Unsupported):
            go_runtime.typelinks_fast_path_patch(audit,blob,far,[(a,far) for a,_ in fixups])
        audit.profile={'name':'go1.26-amd64'}
        self.assertIsNone(go_runtime.typelinks_fast_path_patch(audit,blob,metadata,fixups))

    def test_exact_guard_keeps_slow_path_for_later_module(self):
        with tempfile.TemporaryDirectory(prefix='penryn-type-guard-') as name:
            output=Path(name)/'original'
            subprocess.run(['cc','-no-pie','-Wl,--section-start=.exact_guard=0x6884f9d',
                            '-Wl,--section-start=.original_next=0xbcc9810',
                            '-Wl,--section-start=.synthetic_next=0x10242230',
                            '-o',str(output),str(HERE/'fixtures/typelinks-guard.c'),
                            str(HERE/'fixtures/typelinks-guard.S')],check=True,capture_output=True)
            data=output.read_bytes();elf=ELFFile(io.BytesIO(data))
            segments=[s for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
            def offset(a,n):
                return next(s['p_offset']+a-s['p_vaddr'] for s in segments
                            if s['p_vaddr']<=a and a+n<=s['p_vaddr']+s['p_filesz'])
            audit,blob,metadata,fixups,_,_=self.proof(read=lambda a,n:data[offset(a,n):offset(a,n)+n],offset=offset)
            def run(path,*args):
                result=subprocess.run([str(path),*args],capture_output=True,text=True,timeout=10)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                return result.stdout.strip()
            self.assertEqual(run(output),'0')
            self.assertEqual(run(output,'synthetic'),'1')
            self.assertEqual(run(output,'plugin'),'1')
            patch=go_runtime.typelinks_fast_path_patch(audit,blob,metadata,fixups)
            updated=bytearray(data)
            updated[patch['offset']:patch['offset']+4]=patch['new']
            fixed=Path(name)/'fixed';fixed.write_bytes(updated);fixed.chmod(0o755)
            self.assertEqual(run(fixed,'synthetic'),'0')
            self.assertEqual(run(fixed,'plugin'),'1')
            # Only the CMP displacement changed: same opcode, immediate and JE.
            begin=offset(0x6884f9d,14)
            self.assertEqual(updated[begin:begin+3],data[begin:begin+3])
            self.assertEqual(updated[begin+7:begin+14],data[begin+7:begin+14])


class LegacyStartup(unittest.TestCase):
    def test_nonempty_preinit_array_is_rejected_before_dt_init(self):
        with tempfile.TemporaryDirectory(prefix='penryn-preinit-rejection-') as name:
            output=Path(name)/'preinit'
            subprocess.run(['cc','-fPIE','-pie','-nostartfiles','-Wl,-e,legacy_entry',
                            '-Wl,-init,replacement_init','-Wa,--defsym,TEST_PREINIT=1',
                            '-o',str(output),str(HERE/'fixtures/legacy-init.c'),
                            str(HERE/'fixtures/legacy-init.S')],check=True,capture_output=True)
            elf=ELFFile(io.BytesIO(output.read_bytes()))
            tags={tag.entry.d_tag:tag.entry.d_val for tag in elf.get_section_by_name('.dynamic').iter_tags()}
            self.assertEqual(tags['DT_PREINIT_ARRAYSZ'],8)
            self.assertIn('DT_INIT',tags)
            audit=SimpleNamespace(elf=elf,profile={'name':'go1.26-amd64'})
            with self.assertRaisesRegex(go_runtime.Unsupported,'nonempty preinit array'):
                go_runtime.preinit_registration(audit,0x100000)

    def test_real_legacy_callback_bypasses_dt_init_and_checked_call_repairs_it(self):
        with tempfile.TemporaryDirectory(prefix='penryn-legacy-startup-') as name:
            directory=Path(name)
            original=directory/'legacy'
            subprocess.run(['cc','-fPIE','-pie','-nostartfiles','-Wl,-e,legacy_entry',
                            '-Wl,-init,replacement_init','-o',str(original),
                            str(HERE/'fixtures/legacy-init.c'),
                            str(HERE/'fixtures/legacy-init.S')],check=True,capture_output=True)
            data=original.read_bytes()
            def audit_for(raw):
                elf=ELFFile(io.BytesIO(raw))
                segments=[p for p in elf.iter_segments() if p['p_type']=='PT_LOAD']
                def offset(address,size):
                    return next(p['p_offset']+address-p['p_vaddr'] for p in segments
                                if p['p_vaddr']<=address and address+size<=p['p_vaddr']+p['p_filesz'])
                return SimpleNamespace(elf=elf,offset=offset,read=lambda a,n:raw[offset(a,n):offset(a,n)+n])
            audit=audit_for(data)
            symbols={s.name:s['st_value'] for s in audit.elf.get_section_by_name('.symtab').iter_symbols()}
            negative=subprocess.run([str(original)],capture_output=True,text=True,timeout=10)
            self.assertEqual(negative.returncode,31,negative.stdout+negative.stderr)
            self.assertEqual(negative.stdout,'DT_INIT_BYPASSED\n')
            with self.assertRaises(go_runtime.Unsupported):
                go_runtime.verify_dynamic_init_entry(audit)
            patch=go_runtime.checked_init_call_patch(audit,symbols['legacy_callback_call'],
                                                     symbols['old_init'],symbols['replacement_init'])
            updated=bytearray(data)
            updated[patch['offset']:patch['offset']+5]=patch['new']
            output=directory/'fixed'
            output.write_bytes(updated);output.chmod(0o755)
            positive=subprocess.run([str(output)],capture_output=True,text=True,timeout=10)
            self.assertEqual(positive.returncode,0,positive.stdout+positive.stderr)
            self.assertEqual(positive.stdout,'LEGACY_INIT_OK\n')
            # A null legacy init argument makes glibc run the existing DT_INIT.
            null_init=bytearray(data)
            argument=audit.offset(symbols['legacy_init_argument'],7)
            null_init[argument:argument+7]=b'\x31\xc9'+b'\x90'*5
            evidence=go_runtime.verify_dynamic_init_entry(audit_for(null_init))
            self.assertEqual(evidence['init_argument'],0)
            output.write_bytes(null_init)
            null_run=subprocess.run([str(output)],capture_output=True,text=True,timeout=10)
            self.assertEqual(null_run.returncode,0,null_run.stdout+null_run.stderr)
            # Segment overrides and far calls do not use the proven flat GOT target.
            call_offset=audit.offset(evidence['call'],6)
            for segment in (0x64,0x65):
                segmented=bytearray(null_init)
                segmented[call_offset-7:call_offset]=b'\x90'*6+bytes([segment])
                with self.assertRaises(go_runtime.Unsupported):
                    go_runtime.verify_dynamic_init_entry(audit_for(segmented))
            far=bytearray(null_init)
            far[call_offset+1]=0x1d
            with self.assertRaises(go_runtime.Unsupported):
                go_runtime.verify_dynamic_init_entry(audit_for(far))
            # A store can invalidate the GOT relocation before the eventual call.
            store=bytearray(null_init)
            call_ins=next(iter(Decoder(64,data[call_offset:call_offset+6],ip=evidence['call'])))
            write_pc=evidence['call']-7
            store[call_offset-7:call_offset]=b'\x48\x89\x05'+struct.pack('<i',call_ins.ip_rel_memory_address-evidence['call'])
            with self.assertRaisesRegex(go_runtime.Unsupported,'writes memory'):
                go_runtime.verify_dynamic_init_entry(audit_for(store))
            # Point the validated GOT relocation at a different dynamic import.
            bad=bytearray(null_init)
            symtab=audit.elf.get_section_by_name('.dynsym')
            puts=next(i for i,s in enumerate(symtab.iter_symbols()) if s.name=='puts')
            for section in audit.elf.iter_sections():
                if section['sh_type']!='SHT_RELA':
                    continue
                for index,(address,info,addend) in enumerate(struct.iter_unpack('<QQq',section.data())):
                    if info & 0xffffffff == 6 and symtab.get_symbol(info>>32).name=='__libc_start_main':
                        struct.pack_into('<Q',bad,section['sh_offset']+index*24+8,(puts<<32)|6)
            with self.assertRaises(go_runtime.Unsupported):
                go_runtime.verify_dynamic_init_entry(audit_for(bad))


@unittest.skipUnless(os.path.exists(GO), 'Go compiler unavailable')
class Registration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, hard = resource.getrlimit(resource.RLIMIT_CORE)
        resource.setrlimit(resource.RLIMIT_CORE, (0, hard))
        cls.temp = tempfile.TemporaryDirectory(prefix='penryn-go-metadata-test-')
        cls.work = Path(cls.temp.name)
        (cls.work/'main.go').write_bytes((HERE/'fixtures/go-metadata-main.go').read_bytes())
        (cls.work/'force_amd64.s').write_bytes((HERE/'fixtures/go-metadata-force.s').read_bytes())
        cls.helper = cls.work/'penryn-go-metadata'
        subprocess.run([GO, 'build', '-o', str(cls.helper), str(HERE.parent/'static_penryn/go_metadata.go')],
                       check=True, capture_output=True, env={**os.environ, 'GOMAXPROCS':'2'})

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def prepare(self, pie, external=False):
        from static_penryn import go_lower
        from static_penryn import patch
        from static_penryn import unwind
        original = self.work/('original-external' if external else ('original-pie' if pie else 'original'))
        subprocess.run([GO, 'build', '-buildmode='+('pie' if pie else 'exe'), '-o', str(original), *(['-ldflags=-linkmode external'] if external else []), '.'],
                       cwd=self.work, check=True, capture_output=True,
                       env={**os.environ, 'GO111MODULE':'off', 'GOAMD64':'v1', 'GOMAXPROCS':'2'})
        data = original.read_bytes()
        elf = ELFFile(io.BytesIO(data))
        meta = json.loads(subprocess.check_output([str(self.helper), str(original)]))
        audit = go_runtime.Audit(data, elf, meta)
        self.assertIsNone(audit.profile_error)
        load_off = patch.align(len(data))
        load_va = patch.align(max(s['p_vaddr'] + s['p_memsz'] for s in elf.iter_segments() if s['p_type']=='PT_LOAD'))
        code_off = patch.align((elf['e_phnum'] + 3) * 56, 64)
        code_va = load_va + code_off
        body, ranges, sites, syms = bytearray(), [], [], {}
        for n, name in enumerate(('main.forcedPopcnt', 'main.framedPopcnt')):
            fn = next(f for f in audit.functions if f['name']==name)
            ins = next(i for i in Decoder(64, audit.read(fn['start'], fn['end']-fn['start']),ip=fn['start']) if i.mnemonic==Mnemonic.POPCNT)
            source, _ = go_lower.lower_popcnt(ins, dead_xmms=frozenset({Register.XMM0}))
            for key in ('55', '33', '0f', '01'):
                source = source.replace('.Lpenryn_pop'+key, 'pop'+key)
            definitions = '\n'.join(f'.set pop{key}, {code_va+4096+i*8}' for i,key in enumerate(('55','33','0f','01')))
            source += '\n'+definitions
            start = code_va + len(body)
            assembly = '.intel_syntax noprefix\n.text\n.global go_init\ngo_init:\n' + source + f'\n.set resume, {ins.next_ip}\njmp resume\n'
            emitted = go_runtime._assemble(assembly, start, self.work/f'lower-{pie}-{n}')
            ranges.append(dict(start=start,end=start+len(emitted),original_pc=ins.ip,continuation=ins.next_ip,code=emitted))
            syms[f'site_{n}'] = start
            sites.append(SimpleNamespace(ip=ins.ip,end=ins.next_ip,offset=audit.offset(ins.ip),cave=None))
            body.extend(emitted)
        code_end=code_va+len(body)
        body.extend(bytes(4096-len(body)))
        body.extend(struct.pack('<4Q',0x5555555555555555,0x3333333333333333,0x0f0f0f0f0f0f0f0f,0x0101010101010101))
        installer_va = patch.align(code_va+len(body)+4096,16)
        metadata_va = patch.align(installer_va + 512)
        native=None
        for attempt in range(4):
            result = go_runtime.build(audit,ranges,metadata_va,installer_va,self.work/f'installer-{pie}')
            cfi_work=self.work/f'cfi-{pie}'
            cfi_work.mkdir(exist_ok=True)
            native=unwind.build(elf,body,code_va,[],code_va+patch.align(len(body),8),cfi_work,
                                extra_helpers=[(result['constructor_elf'],installer_va,
                                                installer_va+len(result['constructor_bytes']),'go_initializer')])
            self.assertEqual(native.report['uncovered_ranges'],[])
            next_va=patch.align(code_va+patch.align(len(body),8)+len(native.blob),16)
            if next_va==installer_va:
                break
            installer_va=next_va
            metadata_va=patch.align(installer_va+512)
        else:
            self.fail('Go initializer/native CFI layout did not converge')
        self.assertLess(len(result['constructor_bytes']),512)
        self.assertEqual([x['pcsp'] for x in result['report']['ranges']],[0,72])
        syms.update(_penryn_code_end=code_end,_penryn_rodata_begin=code_va+4096)
        output = self.work/('patched-pie' if pie else 'patched')
        output.write_bytes(patch.rewrite(data,elf,sites,body,syms,load_off,load_va,code_off,
                           unwind_result=native,go_result=result,go_metadata_va=metadata_va,go_installer_va=installer_va))
        output.chmod(0o755)
        anchor=next(f['start'] for f in audit.functions if f['name']=='main.anchor')
        args=[hex(anchor),hex(ranges[0]['start']+2),hex(ranges[1]['start']+2)]
        return output,args,result

    def check_run(self, pie, external=False):
        output,args,result=self.prepare(pie, external)
        profile=self.work/('pie.pprof' if pie else 'exe.pprof')
        env=dict(os.environ)
        image=ELFFile(io.BytesIO(output.read_bytes()))
        interp=next((p.get_interp_name() for p in image.iter_segments() if p['p_type']=='PT_INTERP'),None)
        if interp and interp.startswith('/nix/store/'):
            # This host has an old libeatmydata in /etc/ld-nix.so.preload.
            # Keep each fixture's libc paired with its own ELF interpreter.
            env['LD_LIBRARY_PATH']=str(Path(interp).parent)
        run=subprocess.run([str(output),*args,str(profile)],capture_output=True,text=True,timeout=60,env=env)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr)
        self.assertEqual(run.stdout.count('GO_FUNCTION_OK main.'),2,run.stdout)
        self.assertIn('GO_METADATA_STRESS_OK',run.stdout)
        report=subprocess.run([GO,'tool','pprof','-top','-nodecount=100',str(output),str(profile)],
                              capture_output=True,text=True,timeout=30)
        self.assertEqual(report.returncode,0,report.stderr)
        self.assertTrue('main.forcedPopcnt' in report.stdout or 'main.framedPopcnt' in report.stdout,report.stdout)
        self.assertNotIn('_ExternalCode',report.stdout,report.stdout)
        return output,args

    @unittest.skipUnless(shutil.which('qemu-x86_64'), 'QEMU user emulator unavailable')
    def test_penryn_gc_and_negative_control(self):
        output,args,result=self.prepare(False)
        original_args=[args[0], *[hex(r['original_pc']) for r in result['report']['ranges']]]
        negative=subprocess.run(['qemu-x86_64','-cpu','Penryn',str(self.work/'original'),
                                  *original_args,str(self.work/'negative.pprof')],
                                 capture_output=True,text=True,timeout=30)
        self.assertNotEqual(negative.returncode,0)
        self.assertIn('SIGILL',negative.stdout+negative.stderr)
        positive=subprocess.run(['qemu-x86_64','-cpu','Penryn',str(output),*args,str(self.work/'qemu.pprof')],
                                 capture_output=True,text=True,timeout=90)
        self.assertEqual(positive.returncode,0,positive.stdout+positive.stderr)
        self.assertIn('GO_METADATA_STRESS_OK',positive.stdout)

    def test_entry_registration_and_original_frames(self):
        self.check_run(False)

    def test_pie_entry_registration_and_original_frames(self):
        self.check_run(True)

    def test_external_pie_dt_init_registration(self):
        self.check_run(True, True)


if __name__=='__main__':
    unittest.main()
