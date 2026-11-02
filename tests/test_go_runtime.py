"""Go runtime recognition, original-frame unwinding, GC and PIE relocation."""
from collections.abc import Callable, Iterator
from dataclasses import dataclass
import io
import os
import resource
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
from typing import ClassVar
import unittest

from elftools.elf.dynamic import DynamicSection, DynamicTag
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section, SymbolTableSection
from elftools.elf.segments import InterpSegment
from iced_x86 import Decoder, Mnemonic, Register

from static_penryn import checked, go_lower, go_runtime, gometa, patch, unwind
from static_penryn.go_runtime import BuildResult, LayoutProfile, StubRange

HERE = Path(__file__).resolve().parent
GO = shutil.which('go') or 'go'

# Audit._profile's two layouts. A test audit carries a whole profile; the code
# under test reads only its name and, for agy's typelinks guard, the topology.
AGY: LayoutProfile = dict(name=go_runtime.AGY_PROFILE, size=568, next=560, textsectmap=360,
                          gofunc=344, hasmain=512, gcdatamask=520, gcbssmask=536, abi_internal=False)
GO126: LayoutProfile = dict(name='go1.26-amd64', size=592, next=584, textsectmap=336, gofunc=320,
                            hasmain=536, gcdatamask=544, gcbssmask=560, abi_internal=True)


def supplied[T](value: T | None, name: str) -> T:
    if value is None:
        raise AttributeError(f'this test audit has no {name}')
    return value


class FakeAudit(go_runtime.Audit):
    """An Audit made only of what a test passes: the ELF scan is skipped, and
    a reader the test did not pass is missing (AttributeError)."""
    def __init__(self, *, profile: LayoutProfile | None = None, elf: ELFFile | None = None,
                 read: Callable[[int, int], bytes] | None = None,
                 offset: Callable[[int, int], int] | None = None,
                 word: Callable[[int], int] | None = None) -> None:
        self.profile = profile
        if elf is not None:
            self.elf = elf
        self._read, self._offset, self._word = read, offset, word

    def read(self, address: int, size: int) -> bytes:
        return supplied(self._read, 'read')(address, size)

    def offset(self, address: int, size: int = 1) -> int:
        return supplied(self._offset, 'offset')(address, size)

    def word(self, address: int) -> int:
        return supplied(self._word, 'word')(address)


@dataclass
class Entry:
    """pyelftools' Elf_Dyn record."""
    d_tag: str | int
    d_val: int


class Tag(DynamicTag):
    """A dynamic tag without the string table pyelftools' constructor needs."""
    def __init__(self, d_tag: str, d_val: int) -> None:
        self.entry = Entry(d_tag, d_val)


class Encoding(unittest.TestCase):
    def test_constant_pc_roundtrip(self) -> None:
        for value in (-5, -2, -1, 0, 1, 152, 65536):
            raw = b'\0' + go_runtime.constpc(value, 137)
            expected: go_runtime.PCValues = [(20, 157, value)]
            self.assertEqual(go_runtime.pcvalues(raw, 1, 20, 157), expected)

    def test_invalid_tables_fail_closed(self) -> None:
        for raw in (b'\0\x80', b'\0\x80\x80\x80\x80\x80', b'\0\x80\x80\x80\x80\x10', b'\0\x02\0\0', b'\0\x02\x7f\0'):
            with self.assertRaises(go_runtime.Unsupported):
                go_runtime.pcvalues(raw, 1, 0, 100)

    def test_pinned_legacy_init_call_redirection(self) -> None:
        chunks = {0x67fe016: bytes.fromhex('488d0da3e85303'),
                  0x9d3c8c0: bytes.fromhex('554889e5415741564155415453504889d34989f64189ff'),
                  0x9d3c8d7: bytes.fromhex('e8d0320000')}
        audit = FakeAudit(profile=AGY, read=lambda address, size: chunks[address][:size],
                          offset=lambda address, size: address)
        patch = go_runtime.legacy_init_patch(audit, 0x9d3fbac, 0x10240000)
        assert patch is not None
        call = next(iter(Decoder(64, patch['new'], ip=0x9d3c8d7)))
        self.assertEqual(call.near_branch_target, 0x10240000)
        self.assertEqual(call.mnemonic, Mnemonic.CALL)
        self.assertEqual(patch['old'], chunks[0x9d3c8d7])
        chunks[0x9d3c8d7] = b'\x90' * 5
        with self.assertRaises(go_runtime.Unsupported):
            go_runtime.legacy_init_patch(audit, 0x9d3fbac, 0x10240000)
        with self.assertRaises(go_runtime.Unsupported):
            go_runtime.legacy_init_patch(audit, 0, 0x10240000)

    def test_pinned_preinit_relocation_preserves_callback_order(self) -> None:
        tags: list[DynamicTag] = [Tag(key,value)
                for key,value in [('DT_PREINIT_ARRAY',0x9f45840),('DT_PREINIT_ARRAYSZ',16)]]
        # pyelftools' Section reads its items from self.header.
        class Dynamic(DynamicSection):
            def __init__(self) -> None:pass
            def iter_tags(self,type:str|None=None) -> Iterator[DynamicTag]:return iter(tags)
        dynamic=Dynamic()
        class Rela(Section):
            def __init__(self,**header:int|str) -> None:self.header=header
            def data(self) -> bytes:
                return struct.pack('<QQqQQq',0x9f45840,8,0x9c0ffa0,0x9f45848,8,0x9c741b0)
        rela=Rela(sh_type='SHT_RELA',sh_flags=2,sh_offset=0x100)
        class Elf(ELFFile):
            def __init__(self) -> None:pass
            def get_section_by_name(self,name:str) -> Section|None:return dynamic
            def iter_sections(self,type:str|None=None) -> Iterator[Section]:return iter([rela])
        chunks={0x9f45840:bytes(16),0x9c0ffa0:bytes.fromhex('554889e55350e8757412004883c4085b5dc3')}
        audit=FakeAudit(profile=AGY,elf=Elf(),read=lambda address,size:chunks[address][:size])
        plan=go_runtime.preinit_registration(audit,0x10240000)
        assert plan is not None
        self.assertEqual(plan['target'],0x9c0ffa0)
        patches:list[go_runtime.LoaderPatch]=[dict(offset=0x110,old=struct.pack('<q',0x9c0ffa0),
                                                   new=struct.pack('<q',0x10240000))]
        self.assertEqual(plan['patches'],patches)
        self.assertEqual(plan['evidence']['original_second_callback'],0x9c741b0)
        chunks[0x9f45840]=b'\xff'*16
        with self.assertRaises(go_runtime.Unsupported):
            go_runtime.preinit_registration(audit,0x10240000)

    def test_forbidden_stub_stack_and_calls(self) -> None:
        for code in (b'\x50\xe9\x00\x00\x00\x00', b'\xe8\0\0\0\0\xe9\0\0\0\0'):
            with self.assertRaises(go_runtime.Unsupported):
                go_runtime.validate_code(code, 0x1000, 0x1000+len(code), 0x1000+len(code))


class TypeGuard(unittest.TestCase):
    def proof(self, read: Callable[[int, int], bytes] | None = None, offset: Callable[[int, int], int] | None = None
              ) -> tuple[FakeAudit, bytearray, int, list[tuple[int, int]], dict[int, bytes], dict[int, int]]:
        chunks={0x6884f9d:bytes.fromhex('48833d6b48440500'),
                0x6884fa5:bytes.fromhex('0f8427010000'),
                0x68850d2:bytes.fromhex('4881c4c80200005dc3')}
        words={0xbcc9810:0,0xbcca438:0xbcc95e0}
        audit=FakeAudit(profile={**AGY,'module':0xbcc95e0,'lastmoduledatap':0xbcca438,'next':0x230,'size':568},
                        read=read or (lambda a,n:chunks[a][:n]),
                        offset=offset or (lambda a,n:a), word=lambda a:words[a])
        metadata=0x10242000
        fixups=[(0xbcc9810,metadata),(0xbcca438,metadata)]
        return audit,bytearray(568),metadata,fixups,chunks,words

    def test_typeless_guard_refuses_changed_topology_types_and_fixups(self) -> None:
        audit,blob,metadata,fixups,chunks,words=self.proof()
        patch=go_runtime.typelinks_fast_path_patch(audit,blob,metadata,fixups)
        assert patch is not None
        self.assertEqual(patch['offset'],0x6884fa0)
        self.assertEqual(0x6884fa5+checked.unpack_ints('<i',patch['new'])[0],metadata+0x230)
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
            code=chunks[pc];chunks[pc]=b'\x90'*len(code)
            with self.assertRaises(go_runtime.Unsupported):
                go_runtime.typelinks_fast_path_patch(audit,blob,metadata,fixups)
            chunks[pc]=code
        far=0x1000000000
        with self.assertRaises(go_runtime.Unsupported):
            go_runtime.typelinks_fast_path_patch(audit,blob,far,[(a,far) for a,_ in fixups])
        audit.profile=GO126
        self.assertIsNone(go_runtime.typelinks_fast_path_patch(audit,blob,metadata,fixups))

    def test_exact_guard_keeps_slow_path_for_later_module(self) -> None:
        with tempfile.TemporaryDirectory(prefix='penryn-type-guard-') as name:
            output=Path(name)/'original'
            subprocess.run(['cc','-no-pie','-Wl,--section-start=.exact_guard=0x6884f9d',
                            '-Wl,--section-start=.original_next=0xbcc9810',
                            '-Wl,--section-start=.synthetic_next=0x10242230',
                            '-o',str(output),str(HERE/'fixtures/typelinks-guard.c'),
                            str(HERE/'fixtures/typelinks-guard.S')],check=True,capture_output=True)
            data=output.read_bytes();elf=ELFFile(io.BytesIO(data))
            segments=[s for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
            def offset(a:int,n:int) -> int:
                return next(s['p_offset']+a-s['p_vaddr'] for s in segments
                            if s['p_vaddr']<=a and a+n<=s['p_vaddr']+s['p_filesz'])
            audit,blob,metadata,fixups,_,_=self.proof(read=lambda a,n:data[offset(a,n):offset(a,n)+n],offset=offset)
            def run(path:Path,*args:str) -> str:
                result=subprocess.run([str(path),*args],capture_output=True,text=True,timeout=10)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                return result.stdout.strip()
            self.assertEqual(run(output),'0')
            self.assertEqual(run(output,'synthetic'),'1')
            self.assertEqual(run(output,'plugin'),'1')
            patch=go_runtime.typelinks_fast_path_patch(audit,blob,metadata,fixups)
            assert patch is not None
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
    def test_nonempty_preinit_array_is_rejected_before_dt_init(self) -> None:
        with tempfile.TemporaryDirectory(prefix='penryn-preinit-rejection-') as name:
            output=Path(name)/'preinit'
            subprocess.run(['cc','-fPIE','-pie','-nostartfiles','-Wl,-e,legacy_entry',
                            '-Wl,-init,replacement_init','-Wa,--defsym,TEST_PREINIT=1',
                            '-o',str(output),str(HERE/'fixtures/legacy-init.c'),
                            str(HERE/'fixtures/legacy-init.S')],check=True,capture_output=True)
            elf=ELFFile(io.BytesIO(output.read_bytes()))
            dynamic=elf.get_section_by_name('.dynamic');assert isinstance(dynamic,DynamicSection)
            tags={tag.entry.d_tag:tag.entry.d_val for tag in dynamic.iter_tags()}
            self.assertEqual(tags['DT_PREINIT_ARRAYSZ'],8)
            self.assertIn('DT_INIT',tags)
            audit=FakeAudit(elf=elf,profile=GO126)
            with self.assertRaisesRegex(go_runtime.Unsupported,'nonempty preinit array'):
                go_runtime.preinit_registration(audit,0x100000)

    def test_real_legacy_callback_bypasses_dt_init_and_checked_call_repairs_it(self) -> None:
        with tempfile.TemporaryDirectory(prefix='penryn-legacy-startup-') as name:
            directory=Path(name)
            original=directory/'legacy'
            subprocess.run(['cc','-fPIE','-pie','-nostartfiles','-Wl,-e,legacy_entry',
                            '-Wl,-init,replacement_init','-o',str(original),
                            str(HERE/'fixtures/legacy-init.c'),
                            str(HERE/'fixtures/legacy-init.S')],check=True,capture_output=True)
            data=original.read_bytes()
            def audit_for(raw:bytes|bytearray) -> FakeAudit:
                image=bytes(raw)  # Audit.read returns bytes
                elf=ELFFile(io.BytesIO(image))
                segments=[p for p in elf.iter_segments() if p['p_type']=='PT_LOAD']
                def offset(address:int,size:int) -> int:
                    return next(p['p_offset']+address-p['p_vaddr'] for p in segments
                                if p['p_vaddr']<=address and address+size<=p['p_vaddr']+p['p_filesz'])
                return FakeAudit(elf=elf,offset=offset,read=lambda a,n:image[offset(a,n):offset(a,n)+n])
            audit=audit_for(data)
            symtab=audit.elf.get_section_by_name('.symtab');assert isinstance(symtab,SymbolTableSection)
            symbols={s.name:s['st_value'] for s in symtab.iter_symbols()}
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
            store[call_offset-7:call_offset]=b'\x48\x89\x05'+struct.pack('<i',call_ins.ip_rel_memory_address-evidence['call'])
            with self.assertRaisesRegex(go_runtime.Unsupported,'writes memory'):
                go_runtime.verify_dynamic_init_entry(audit_for(store))
            # Point the validated GOT relocation at a different dynamic import.
            bad=bytearray(null_init)
            symtab=audit.elf.get_section_by_name('.dynsym');assert isinstance(symtab,SymbolTableSection)
            puts=next(i for i,s in enumerate(symtab.iter_symbols()) if s.name=='puts')
            for section in audit.elf.iter_sections():
                if section['sh_type']!='SHT_RELA':
                    continue
                for index,(_,info,_) in enumerate(checked.iter_ints('<QQq',section.data())):
                    if info & 0xffffffff == 6 and symtab.get_symbol(info>>32).name=='__libc_start_main':
                        struct.pack_into('<Q',bad,section['sh_offset']+index*24+8,(puts<<32)|6)
            with self.assertRaises(go_runtime.Unsupported):
                go_runtime.verify_dynamic_init_entry(audit_for(bad))


class Registration(unittest.TestCase):
    temp: ClassVar[tempfile.TemporaryDirectory[str]]
    work: ClassVar[Path]
    helper: ClassVar[Path]

    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which(GO) is None:
            raise unittest.SkipTest('Go compiler unavailable')
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
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def prepare(self, pie: bool, external: bool = False) -> tuple[Path, list[str], BuildResult]:
        original = self.work/('original-external' if external else ('original-pie' if pie else 'original'))
        subprocess.run([GO, 'build', '-buildmode='+('pie' if pie else 'exe'), '-o', str(original), *(['-ldflags=-linkmode external'] if external else []), '.'],
                       cwd=self.work, check=True, capture_output=True,
                       env={**os.environ, 'GO111MODULE':'off', 'GOAMD64':'v1', 'GOMAXPROCS':'2'})
        elf = patch.load_elf(original)
        self.addCleanup(elf.close)  # pwntools keeps the file and its mmap open
        data = elf.data
        meta = gometa.parse(subprocess.check_output([str(self.helper), str(original)]))
        audit = go_runtime.Audit(data, elf, meta)
        self.assertIsNone(audit.profile_error)
        load_off = patch.align(len(data))
        load_va = patch.align(max(s['p_vaddr'] + s['p_memsz'] for s in elf.iter_segments() if s['p_type']=='PT_LOAD'))
        code_off = patch.align((elf['e_phnum'] + 3) * 56, 64)
        code_va = load_va + code_off
        ranges: list[StubRange]
        sites: list[patch.Site]
        syms: dict[str, int]
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
            sites.append(patch.Site(insns=[ins],end=ins.next_ip,offset=audit.offset(ins.ip),cave=None))
            body.extend(emitted)
        code_end=code_va+len(body)
        body.extend(bytes(4096-len(body)))
        body.extend(struct.pack('<4Q',0x5555555555555555,0x3333333333333333,0x0f0f0f0f0f0f0f0f,0x0101010101010101))
        installer_va = patch.align(code_va+len(body)+4096,16)
        metadata_va = patch.align(installer_va + 512)
        native: unwind.Result | None = None
        no_gaps: list[unwind.Range] = []
        for _ in range(4):
            result = go_runtime.build(audit,ranges,metadata_va,installer_va,self.work/f'installer-{pie}')
            cfi_work=self.work/f'cfi-{pie}'
            cfi_work.mkdir(exist_ok=True)
            constructor=result['constructor_elf']
            assert constructor is not None
            native=unwind.build(elf,body,code_va,[],code_va+patch.align(len(body),8),cfi_work,
                                extra_helpers=[(constructor,installer_va,
                                                installer_va+len(result['constructor_bytes']),'go_initializer')])
            self.assertEqual(native.report['uncovered_ranges'],no_gaps)
            next_va=patch.align(code_va+patch.align(len(body),8)+len(native.blob),16)
            if next_va==installer_va:
                break
            installer_va=next_va
            metadata_va=patch.align(installer_va+512)
        else:
            self.fail('Go initializer/native CFI layout did not converge')
        self.assertLess(len(result['constructor_bytes']),512)
        pcsp=[x['pcsp'] for x in result['report']['ranges']]
        stack_deltas: list[int] = [0,72]
        self.assertEqual(pcsp,stack_deltas)
        syms.update(_penryn_code_end=code_end,_penryn_rodata_begin=code_va+4096)
        output = self.work/('patched-pie' if pie else 'patched')
        output.write_bytes(patch.rewrite(data,elf,sites,body,syms,load_off,load_va,code_off,
                           unwind_result=native,go_result=result,go_metadata_va=metadata_va,go_installer_va=installer_va))
        output.chmod(0o755)
        anchor=next(f['start'] for f in audit.functions if f['name']=='main.anchor')
        args=[hex(anchor),hex(ranges[0]['start']+2),hex(ranges[1]['start']+2)]
        return output,args,result

    def check_run(self, pie: bool, external: bool = False) -> tuple[Path, list[str]]:
        output,args,result=self.prepare(pie, external)
        profile=self.work/('pie.pprof' if pie else 'exe.pprof')
        env=dict(os.environ)
        image=ELFFile(io.BytesIO(output.read_bytes()))
        interp=next((p.get_interp_name() for p in image.iter_segments()
                     if p['p_type']=='PT_INTERP' and isinstance(p,InterpSegment)),None)
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

    def test_penryn_gc_and_negative_control(self) -> None:
        if not shutil.which('qemu-x86_64'):
            self.skipTest('QEMU user emulator unavailable')
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

    def test_entry_registration_and_original_frames(self) -> None:
        self.check_run(False)

    def test_pie_entry_registration_and_original_frames(self) -> None:
        self.check_run(True)

    def test_external_pie_dt_init_registration(self) -> None:
        self.check_run(True, True)


if __name__=='__main__':
    unittest.main()
