"""Version-checked Go metadata for stack-neutral, jump-entered replacements.

This backend is deliberately separate from DWARF CFI. Go's own module list,
function table, pcsp and pointer maps describe its stacks. The initial backend
accepts a tiny no-call instruction contract and registers a separate text-only
module before the original program starts its Go runtime.
"""
from bisect import bisect_right
import hashlib
import io
import re
from pathlib import Path
import struct
import subprocess
import tempfile

from elftools.elf.elffile import ELFFile
from iced_x86 import Decoder, InstructionInfoFactory, Mnemonic, OpAccess, Register, RegisterExt, FlowControl, EncodingKind, Code

AGY_SHA256 = 'baff3db5e4c09635709fa9838e4038c9b4f2c164ce7a80a18059393797d6802c'


class Unsupported(ValueError):
    """The original program or requested replacement is outside the proof."""


def uvarint(data, offset):
    value = 0
    for shift in range(0, 35, 7):
        if offset >= len(data):
            raise Unsupported('truncated Go PC value table')
        byte = data[offset]
        if shift == 28 and byte > 15:
            raise Unsupported('overflow in Go PC value table')
        offset += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise Unsupported('overflow in Go PC value table')


def putvarint(value):
    if not 0 <= value <= 0xffffffff:
        raise Unsupported('Go PC value exceeds uint32')
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return result


def pcvalues(data, offset, start, end):
    """Decode Go runtime.step's signed value deltas and unsigned PC deltas."""
    if offset == 0:
        return [(start, end, -1)]
    if offset >= len(data):
        raise Unsupported('Go PC value offset is outside pctab')
    result, pc, value, first = [], start, -1, True
    while True:
        delta, offset = uvarint(data, offset)
        if delta == 0 and not first:
            break
        value += -(delta >> 1) - 1 if delta & 1 else delta >> 1
        amount, offset = uvarint(data, offset)
        if amount == 0 or pc + amount > end:
            raise Unsupported('Go PC value interval is empty or leaves its function')
        result.append((pc, pc + amount, value))
        pc += amount
        first = False
        if len(result) > end - start:
            raise Unsupported('unbounded Go PC value table')
    # Go's final alignment padding can be outside its PC tables.
    if not result:
        raise Unsupported('empty Go PC value table')
    return result


def constpc(value, length):
    delta = value + 1
    encoded = (-delta * 2 - 1) if delta < 0 else delta * 2
    return bytes(putvarint(encoded) + putvarint(length) + b'\0')


class Audit:
    def __init__(self, data, elf, metadata):
        self.data, self.elf, self.metadata = data, elf, metadata
        self.segments = [p for p in elf.iter_segments() if p['p_type'] == 'PT_LOAD']
        self.relative = {}
        for section in elf.iter_sections():
            if section['sh_type'] == 'SHT_RELA' and section['sh_flags'] & 2:
                raw = section.data()
                if len(raw) % 24:
                    raise Unsupported('malformed ELF RELA section')
                self.relative.update({a: c for a, b, c in struct.iter_unpack('<QQq', raw) if b == 8})
        self.functions = sorted((f for t in metadata.get('tables', []) for f in t['functions']), key=lambda f: f['start'])
        self.starts = [f['start'] for f in self.functions]
        self.tables = metadata.get('tables', [])
        self.cache = {}
        self.profile = None
        self.profile_error = None
        if len(self.tables) != 1:
            self.profile_error = 'exactly one original Go module is required'
        else:
            try:
                self.profile = self._profile()
            except Unsupported as error:
                self.profile_error = str(error)
        self.candidate_provenance = self._candidate_provenance()

    def _candidate_provenance(self):
        result = []
        for reason in self.metadata.get("rejected_candidates", []):
            match = re.match(r"0x([0-9a-f]+):", reason)
            if not match:
                result.append(dict(reason=reason, classification="unresolved"))
                continue
            address = int(match.group(1), 16)
            refs = {slot for slot, value in self.relative.items() if value == address}
            needle = struct.pack("<Q", address)
            for section in self.elf.iter_sections():
                if section["sh_type"] == "SHT_NOBITS" or not section["sh_flags"] & 2 or section["sh_flags"] & 4:
                    continue
                begin, limit = section["sh_offset"], section["sh_offset"] + section["sh_size"]
                cursor = begin
                while True:
                    at = self.data.find(needle, cursor, limit)
                    if at < 0:
                        break
                    cursor = at + 1
                    slot = section["sh_addr"] + at - begin
                    if slot % 8 == 0:
                        refs.add(slot)
            result.append(dict(address=address, reason=reason, references=sorted(refs),
                               classification="referenced-unhandled-candidate" if refs else "unreferenced-header-magic",
                               evidence="all allocated non-executable aligned pointer words and RELATIVE relocations inspected"))
        return result

    def offset(self, address, size=1):
        for segment in self.segments:
            if segment['p_vaddr'] <= address and address + size <= segment['p_vaddr'] + segment['p_filesz']:
                return segment['p_offset'] + address - segment['p_vaddr']
        raise Unsupported(f'Go metadata address 0x{address:x} is not file backed')

    def read(self, address, size):
        at = self.offset(address, size)
        return self.data[at:at + size]

    def word(self, address):
        return self.relative.get(address, struct.unpack('<Q', self.read(address, 8))[0])

    def function(self, pc):
        index = bisect_right(self.starts, pc) - 1
        if index < 0 or pc >= self.functions[index]['end']:
            raise Unsupported('PC has no verified Go function')
        f = self.functions[index]
        if f['start'] in self.cache:
            return self.cache[f['start']]
        table = next(t for t in self.tables if t['functions'][0]['start'] <= pc < t['functions'][-1]['end'])
        header = self.read(table['address'], 72)
        offsets = struct.unpack_from('<5Q', header, 32)
        pctab = self.read(table['address'] + offsets[3], offsets[4] - offsets[3])
        address = f.get('metadata_address')
        if address is None:
            # Backwards compatible with reports made by the original helper.
            local = bisect_right([x['start'] for x in table['functions']], f['start']) - 1
            item = self.read(table['address'] + offsets[4] + local * 8, 8)
            address = table['address'] + offsets[4] + struct.unpack_from('<I', item, 4)[0]
        raw = self.read(address, 44)
        fields = struct.unpack('<Ii i IIIIII i BBBB'.replace(' ', ''), raw)
        entry, name, args, deferreturn, pcsp, pcfile, pcln, npcdata, cuoffset, line, funcid, flag, pad, nfuncdata = fields
        if entry + table['text'] != f['start'] or not 0 <= name < offsets[1] - offsets[0] or pad != 0 or npcdata > 16 or nfuncdata > 16:
            raise Unsupported('Go _func fixed layout validation failed')
        original_name = self.read(table['address'] + offsets[0] + name, len(f['name'].encode()) + 1)
        if original_name != f['name'].encode() + b'\0':
            raise Unsupported('Go _func name disagrees with debug/gosym')
        tail = self.read(address + 44, 4 * (npcdata + nfuncdata))
        items = struct.unpack(f'<{npcdata + nfuncdata}I', tail) if tail else ()
        pcd = [pcvalues(pctab, v, f['start'], f['end']) for v in items[:npcdata]]
        out = dict(f, metadata_address=address, args=args, deferreturn=deferreturn,
                   pcsp_offset=pcsp, pcsp=pcvalues(pctab, pcsp, f['start'], f['end']),
                   pcfile=pcvalues(pctab, pcfile, f['start'], f['end']),
                   pcln=pcvalues(pctab, pcln, f['start'], f['end']), pcdata=pcd,
                   cu_offset=cuoffset, start_line=line, func_id=funcid, func_flag=flag,
                   funcdata=list(items[npcdata:]), table=table)
        self.cache[f['start']] = out
        return out

    def site(self, pc):
        f = self.function(pc)
        def value(rows):
            for begin, end, result in rows:
                if begin <= pc < end:
                    return result
            raise Unsupported('original PC lies outside its Go PC value table')
        if f['pcsp_offset'] == 0:
            raise Unsupported('original function has no Go pcsp table')
        return dict(function=f['name'], start=f['start'], end=f['end'], pcsp=value(f['pcsp']),
                    pcfile=value(f['pcfile']), pcln=value(f['pcln']),
                    pcdata=[value(rows) for rows in f['pcdata']], funcdata=f['funcdata'],
                    args=f['args'], cu_offset=f['cu_offset'], start_line=f['start_line'],
                    func_id=f['func_id'], func_flag=f['func_flag'],
                    layout_profile=self.profile['name'] if self.profile else None,
                    abi_internal=self.abi_internal(f))

    def replacement_site(self, pc):
        """Check source-side constraints before selecting a Go lowering."""
        if not self.profile:
            raise Unsupported(self.profile_error or 'Go runtime layout is unverified')
        f, site = self.function(pc), self.site(pc)
        if f['func_id'] != 0 or f['func_flag'] & ~4 or f['deferreturn'] or f['args'] < 0:
            raise Unsupported('Go source uses special runtime, SP-write, unknown args or defer-return semantics')
        if len(f['funcdata']) > 4 and f['funcdata'][4] != 0xffffffff:
            raise Unsupported('Go source has open-coded defer metadata')
        if site['pcsp'] < 0 or site['pcsp'] % 8 or site['pcsp'] > 0x7fffffff:
            raise Unsupported('Go source has an invalid stack delta')
        for value in f['funcdata']:
            if value != 0xffffffff:
                self.offset(self.profile['gofunc_address'] + value)
        original = next(iter(Decoder(64, self.read(pc, min(15, f['end'] - pc)), ip=pc)))
        if original.mnemonic != Mnemonic.POPCNT or original.memory_base or original.memory_index:
            raise Unsupported('initial Go backend supports register-only POPCNT')
        site['continuation'] = original.next_ip
        return site

    def abi_internal(self, function):
        return bool(self.profile and self.profile.get('abi_internal') and function['func_flag'] == 0
                    and function['func_id'] == 0 and not function['name'].endswith('.abi0'))

    def inplace(self, name):
        f = next((f for f in self.functions if f['name'] == name), None)
        if not f:
            raise Unsupported('in-place function is missing from Go metadata')
        detail = self.function(f['start'])
        if not self.profile:
            raise Unsupported(self.profile_error)
        if detail['func_id'] != 0 or detail['func_flag'] != 4 or detail['pcsp_offset'] == 0:
            raise Unsupported('in-place recipe needs an ordinary Go assembly function with pcsp')
        if any(v != 0 for _, _, v in detail['pcsp']):
            raise Unsupported('in-place recipe has a nonzero original stack delta')
        # FuncFlagAsm alone disables async preemption. Confirm every original
        # executable byte has zero pcsp; any final padding is separately pinned.
        return dict(layout_profile=self.profile['name'], function=name, func_flag=4,
                    func_id=0, pcsp=detail['pcsp'], pcdata=detail['pcdata'],
                    asm_disables_async_preemption=True, inplace_stack_neutral_verified=True)

    def _profile(self):
        table = self.tables[0]
        module = table.get('module_address', 0)
        if not module:
            candidates = [a for a, value in self.relative.items() if value == table['address']]
            if self.elf['e_type'] == 'ET_EXEC':
                symbol = self.elf.get_section_by_name('.symtab')
                if symbol:
                    candidates += [s['st_value'] for s in symbol.iter_symbols() if s.name == 'runtime.firstmoduledata']
            candidates = [a for a in candidates if self._prefix(a, table)]
            if len(candidates) != 1:
                raise Unsupported('cannot identify a unique original runtime.moduledata')
            module = candidates[0]
        if not self._prefix(module, table):
            raise Unsupported('original runtime.moduledata prefix disagrees with pclntab')
        version = self.metadata.get('go_build_version', '')
        digest = hashlib.sha256(self.data).hexdigest()
        if digest == AGY_SHA256:
            profile = dict(name='agy-1.2.7-go1.28-20260721-RC03-pinned', size=568,
                           next=560, textsectmap=360, gofunc=344, hasmain=512,
                           gcdatamask=520, gcbssmask=536, abi_internal=False)
            # The complete input digest pins every consumer of this private ABI.
            # Runtime findfunc and modulesinit independently use next+0x230.
            if module != 0xbcc95e0 or b'go1.28-20260721-RC03' not in self.data:
                raise Unsupported('pinned agy module/version unexpectedly differs')
        elif version.startswith('go1.26.'):
            profile = dict(name='go1.26-amd64', size=592, next=584, textsectmap=336,
                           gofunc=320, hasmain=536, gcdatamask=544, gcbssmask=560,
                           abi_internal=True)
            self._verify_dwarf_layout(profile)
        else:
            raise Unsupported(f'unsupported Go runtime layout: {version or "no build version"}')
        if self.word(module + profile['next']) != 0:
            raise Unsupported('pre-existing Go module chain is not supported')
        refs = [a for a, value in self.relative.items() if value == module]
        symbols = self.elf.get_section_by_name('.symtab')
        if symbols:
            named = [s['st_value'] for s in symbols.iter_symbols() if s.name == 'runtime.lastmoduledatap']
            if named:
                refs = named
        if len(refs) != 1 or self.word(refs[0]) != module:
            raise Unsupported('cannot identify unique original runtime.lastmoduledatap')
        profile.update(module=module, lastmoduledatap=refs[0], gofunc_address=self.word(module + profile['gofunc']))
        # Header-bearing module is the only supported linked module. Unreferenced
        # magic strings are reported separately; they cannot veto verified code.
        profile['rejected_candidates'] = self.metadata.get('rejected_candidates', [])
        return profile

    def _prefix(self, address, table):
        try:
            offsets = struct.unpack_from('<5Q', self.read(table['address'], 72), 32)
            return (self.word(address) == table['address'] and
                    all(self.word(address + field) == table['address'] + offset
                        for field, offset in zip((8, 32, 56, 80, 104, 128), (*offsets, offsets[-1]))) and
                    self.word(address + 176) == table['text'] and
                    self.word(address + 160) == table['functions'][0]['start'] and
                    self.word(address + 168) == table['functions'][-1]['end'])
        except Unsupported:
            return False

    def _verify_dwarf_layout(self, profile):
        # Go's ABIInternal is not a public binary ABI. Accept an exact release
        # family only after the binary's own DWARF confirms its private layout.
        dwarf = self.elf.get_dwarf_info(relocate_dwarf_sections=False, follow_links=False)
        for unit in dwarf.iter_CUs():
            for die in unit.iter_DIEs():
                name = die.attributes.get('DW_AT_name')
                if die.tag != 'DW_TAG_structure_type' or not name or name.value != b'runtime.moduledata':
                    continue
                fields = {d.attributes['DW_AT_name'].value.decode(): d.attributes['DW_AT_data_member_location'].value
                          for d in die.iter_children() if d.tag == 'DW_TAG_member'}
                if (die.attributes['DW_AT_byte_size'].value != profile['size'] or
                    any(fields.get(key) != profile[key] for key in ('next', 'textsectmap', 'gofunc', 'hasmain', 'gcdatamask', 'gcbssmask'))):
                    raise Unsupported('Go moduledata DWARF layout differs from supported profile')
                return
        raise Unsupported('Go release profile requires self-contained moduledata DWARF')


def validate_code(code, start, end, continuation):
    """Independent structural audit; lowering additionally proves scratch saves."""
    if len(code) != end - start:
        raise Unsupported('Go stub range does not match emitted bytes')
    instructions = list(Decoder(64, code, ip=start))
    if not instructions or any(i.is_invalid or i.is_privileged or i.has_lock_prefix or i.encoding != EncodingKind.LEGACY for i in instructions):
        raise Unsupported('Go stub contains undecodable code')
    starts = {i.ip for i in instructions}
    factory = InstructionInfoFactory()
    writes = {OpAccess.WRITE, OpAccess.COND_WRITE, OpAccess.READ_WRITE, OpAccess.READ_COND_WRITE}
    for ins in instructions:
        if ins.flow_control not in (FlowControl.NEXT, FlowControl.CONDITIONAL_BRANCH, FlowControl.UNCONDITIONAL_BRANCH):
            raise Unsupported('Go stub contains a call, return, trap or indirect transfer')
        if ins.flow_control != FlowControl.NEXT:
            target = ins.near_branch_target
            if target not in starts and not (ins == instructions[-1] and target == continuation):
                raise Unsupported('Go stub has an unrecognized outgoing branch')
        for reg in factory.info(ins).used_registers():
            full = RegisterExt.full_register(reg.register)
            if reg.access in writes and full in (Register.RSP, Register.RBP, Register.R14, Register.ZMM15):
                raise Unsupported('Go stub writes a reserved stack/runtime register')
        for memory in factory.info(ins).used_memory():
            if memory.access in writes:
                raise Unsupported('Go stub writes memory')
            if ins.memory_base != Register.RIP and ins.mnemonic != Mnemonic.LEA:
                raise Unsupported('Go stub may fault on a nonconstant memory read')
    if instructions[-1].flow_control != FlowControl.UNCONDITIONAL_BRANCH or instructions[-1].near_branch_target != continuation:
        raise Unsupported('Go stub lacks a direct continuation jump')


def _assemble(source, address, work=None, with_elf=False):
    if work is None:
        with tempfile.TemporaryDirectory(prefix='penryn-go-init-') as temp:
            return _assemble(source, address, Path(temp), with_elf=with_elf)
    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)
    assembly, obj, linked = work / 'go-init.S', work / 'go-init.o', work / 'go-init.elf'
    definitions = re.findall(r'^\.set (\w+), (\d+)$', source, flags=re.M)
    source = re.sub(r'^\.set (\w+), (\d+)$', r'.extern \1', source, flags=re.M)
    assembly.write_text(source)
    subprocess.run(['cc', '-c', '-o', str(obj), str(assembly)], check=True, capture_output=True)
    subprocess.run(['ld', '-m', 'elf_x86_64', '-Ttext', hex(address), '-e', 'go_init',
                    '-o', str(linked), str(obj), *[f'--defsym={key}={value}' for key, value in definitions]], check=True, capture_output=True)
    elf = ELFFile(io.BytesIO(linked.read_bytes()))
    code = elf.get_section_by_name('.text').data()
    return (code, linked.read_bytes()) if with_elf else code


def verify_dynamic_init_entry(audit):
    """Require a direct CRT path passing null init to __libc_start_main.

    Modern glibc selects DT_INIT only when its fourth argument is null. A
    caller-supplied init callback is a separate startup contract and is not
    covered by this generic path.
    """
    entry = audit.elf['e_entry']
    first_call = None
    zero_rcx = False
    factory = InstructionInfoFactory()
    writes = {OpAccess.WRITE, OpAccess.COND_WRITE, OpAccess.READ_WRITE, OpAccess.READ_COND_WRITE}
    remaining = next((p['p_vaddr'] + p['p_filesz'] - entry for p in audit.elf.iter_segments()
                      if p['p_type'] == 'PT_LOAD' and p['p_flags'] & 1
                      and p['p_vaddr'] <= entry < p['p_vaddr'] + p['p_filesz']), 0)
    if not remaining:
        raise Unsupported('dynamic Go CRT entry is not file-backed executable code')
    for ins in Decoder(64, audit.read(entry, min(96, remaining)), ip=entry):
        if ins.is_invalid or ins.is_privileged:
            raise Unsupported('unrecognized dynamic Go CRT entry')
        if ins.flow_control == FlowControl.INDIRECT_CALL:
            if ins.code != Code.CALL_RM64 or ins.memory_base != Register.RIP or ins.memory_segment in (Register.FS, Register.GS):
                raise Unsupported('dynamic Go CRT requires an unsegmented near GOT call')
            first_call = ins
            break
        if ins.flow_control != FlowControl.NEXT:
            raise Unsupported('dynamic Go CRT entry is not a straight-line libc startup call')
        info = factory.info(ins)
        if any(memory.access in writes for memory in info.used_memory()) and ins.mnemonic != Mnemonic.PUSH:
            raise Unsupported('dynamic Go CRT writes memory before its startup call')
        if any(RegisterExt.full_register(reg.register) == Register.RSP and reg.access in writes for reg in info.used_registers()):
            valid_stack = ins.mnemonic == Mnemonic.PUSH or (ins.mnemonic == Mnemonic.POP and ins.op0_register != Register.RSP)
            if ins.mnemonic == Mnemonic.AND and ins.op0_register == Register.RSP:
                from iced_x86 import OpKind
                valid_stack = ins.op1_kind in (OpKind.IMMEDIATE8TO64, OpKind.IMMEDIATE32TO64) and ins.immediate(1) == 0xfffffffffffffff0
            if not valid_stack:
                raise Unsupported('dynamic Go CRT changes its initial stack unexpectedly')
        if any(RegisterExt.full_register(reg.register) == Register.RCX and reg.access in writes
               for reg in factory.info(ins).used_registers()):
            zero_rcx = (ins.mnemonic == Mnemonic.XOR and ins.op0_register in (Register.RCX, Register.ECX)
                        and ins.op1_register == ins.op0_register)
            if ins.mnemonic == Mnemonic.MOV and ins.op0_register in (Register.RCX, Register.ECX):
                # The ordinary CRT uses XOR. No inference is made from memory,
                # another register, or a partial-register write.
                from iced_x86 import OpKind
                zero_rcx = ins.op1_kind in (OpKind.IMMEDIATE32, OpKind.IMMEDIATE32TO64, OpKind.IMMEDIATE64) and ins.immediate(1) == 0
    if first_call is None or not zero_rcx:
        raise Unsupported('dynamic Go CRT does not prove a null legacy init callback')
    got = first_call.ip_rel_memory_address
    targets = []
    for section in audit.elf.iter_sections():
        if section['sh_type'] != 'SHT_RELA' or not section['sh_flags'] & 2:
            continue
        symbols = audit.elf.get_section(section['sh_link'])
        for address, info, addend in struct.iter_unpack('<QQq', section.data()):
            if address == got and info & 0xffffffff in (6, 7):
                targets.append(symbols.get_symbol(info >> 32).name)
    if targets != ['__libc_start_main']:
        raise Unsupported('dynamic Go CRT call is not uniquely relocated to __libc_start_main')
    return dict(kind='verified-null-libc-start-main-init', entry=entry,
                call=first_call.ip, import_name='__libc_start_main', init_argument=0)


def preinit_registration(audit, installer_va):
    """Register before agy's first preinit callback; reject unknown preinit code."""
    dynamic = audit.elf.get_section_by_name('.dynamic')
    if dynamic is None:
        return None
    pointers = [tag.entry.d_val for tag in dynamic.iter_tags() if tag.entry.d_tag == 'DT_PREINIT_ARRAY']
    sizes = [tag.entry.d_val for tag in dynamic.iter_tags() if tag.entry.d_tag == 'DT_PREINIT_ARRAYSZ']
    if not pointers and not sizes:
        return None
    if len(pointers) != 1 or len(sizes) != 1:
        raise Unsupported('ambiguous or incomplete Go executable preinit array')
    if sizes[0] == 0:
        return None
    if audit.profile['name'] != 'agy-1.2.7-go1.28-20260721-RC03-pinned':
        raise Unsupported('nonempty preinit array may execute Go before DT_INIT registration')
    if pointers != [0x9f45840] or sizes != [16]:
        raise Unsupported('pinned agy preinit array changed')
    slots = {0x9f45840: 0x9c0ffa0, 0x9f45848: 0x9c741b0}
    found = {}
    for section in audit.elf.iter_sections():
        if section['sh_type'] != 'SHT_RELA' or not section['sh_flags'] & 2:
            continue
        for index, (address, info, addend) in enumerate(struct.iter_unpack('<QQq', section.data())):
            if address not in slots:
                continue
            if address in found or info != 8 or addend != slots[address]:
                raise Unsupported('pinned agy preinit relocation changed')
            found[address] = section['sh_offset'] + index * 24 + 16
    if set(found) != set(slots) or audit.read(0x9f45840, 16) != bytes(16):
        raise Unsupported('pinned agy preinit relocation/slot proof is incomplete')
    first = bytes.fromhex('554889e55350e8757412004883c4085b5dc3')
    if audit.read(0x9c0ffa0, len(first)) != first:
        raise Unsupported('pinned agy first preinit callback changed')
    original_target = slots[0x9f45840]
    return dict(target=original_target,
                patches=[dict(offset=found[0x9f45840], old=struct.pack('<q', original_target),
                              new=struct.pack('<q', installer_va))],
                evidence=dict(kind='pinned-first-preinit-relative-relocation', array=pointers[0],
                              array_bytes=sizes[0], original_first_callback=original_target,
                              original_second_callback=slots[0x9f45848], initializer=installer_va,
                              relocation_addend_offset=found[0x9f45840], raw_slots_unchanged=True))


def checked_init_call_patch(audit, address, original_target, installer_va):
    """Patch one already-identified direct initializer call, checking its target."""
    original = audit.read(address, 5)
    if len(original) != 5 or original[0] != 0xe8 or address + 5 + struct.unpack_from('<i', original, 1)[0] != original_target:
        raise Unsupported('verified legacy init call bytes/target changed')
    displacement = installer_va - address - 5
    if not -(1 << 31) <= displacement < (1 << 31):
        raise Unsupported('Go initializer is outside legacy init CALL rel32 reach')
    replacement = b'\xe8' + struct.pack('<i', displacement)
    return dict(offset=audit.offset(address, 5), old=original, new=replacement)


def legacy_init_patch(audit, original_init, installer_va):
    """Redirect agy's pinned pre-glibc-2.34 CRT initializer call.

    A non-null init callback passed to __libc_start_main bypasses DT_INIT for
    the main executable. Its direct call must therefore reach the new wrapper.
    This is deliberately an exact-input recipe, not a CRT-pattern heuristic.
    """
    if audit.profile['name'] != 'agy-1.2.7-go1.28-20260721-RC03-pinned':
        return None
    entry, callback, call, target = 0x67fe016, 0x9d3c8c0, 0x9d3c8d7, 0x9d3fbac
    if original_init != target:
        raise Unsupported('pinned agy DT_INIT target changed')
    if audit.read(entry, 7) != bytes.fromhex('488d0da3e85303'):
        raise Unsupported('pinned agy entry no longer passes its legacy init callback')
    prefix = bytes.fromhex('554889e5415741564155415453504889d34989f64189ff')
    if audit.read(callback, len(prefix)) != prefix:
        raise Unsupported('pinned agy legacy init callback changed')
    original = bytes.fromhex('e8d0320000')
    if audit.read(call, 5) != original:
        raise Unsupported('pinned agy legacy init call changed')
    patch = checked_init_call_patch(audit, call, target, installer_va)
    patch['evidence'] = dict(kind='pinned-legacy-init-call', address=call,
                             callback=callback, original_target=target,
                             initializer=installer_va,
                             original_bytes=original.hex(), replacement_bytes=patch['new'].hex())
    return patch


def typelinks_fast_path_patch(audit, blob, metadata_va, fixups):
    """Preserve agy's single-type-module fast path without hiding later modules.

    The generated module has no types. Standard module registration appends
    through lastmoduledatap, so a later module makes its next pointer non-null
    and selects the untouched original type-deduplication path.
    """
    profile = audit.profile
    if profile['name'] != 'agy-1.2.7-go1.28-20260721-RC03-pinned':
        return None
    if (profile['module'], profile['lastmoduledatap'], profile['next'], profile['size']) != (0xbcc95e0, 0xbcca438, 0x230, 568):
        raise Unsupported('pinned agy module topology/layout changed')
    if len(blob) < profile['size']:
        raise Unsupported('truncated synthetic Go module')
    # Keep the original gofunc reference at 0x158, but require all type fields,
    # auxiliary type/link tables, typemap and next to remain initially empty.
    empty_ranges = ((0x128, 0x158), (0x160, 0x238))
    if any(any(blob[start:end]) for start, end in empty_ranges):
        raise Unsupported('typelinks fast path requires an empty synthetic type module and nil next')
    if any(slot < metadata_va + end and metadata_va + start < slot + 8
           for slot, _ in fixups for start, end in empty_ranges):
        raise Unsupported('initializer fixup would populate synthetic type fields or next')
    original_next = profile['module'] + profile['next']
    if audit.word(original_next) != 0 or audit.word(profile['lastmoduledatap']) != profile['module']:
        raise Unsupported('typelinks fast path requires exactly one original module')
    for slot in (original_next, profile['lastmoduledatap']):
        if [(location, value) for location, value in fixups
                if location < slot + 8 and slot < location + 8] != [(slot, metadata_va)]:
            raise Unsupported('typelinks fast path requires publishing the synthetic module as the new tail')
    pc, branch, epilogue = 0x6884f9d, 0x6884fa5, 0x68850d2
    original = bytes.fromhex('48833d6b48440500')
    if (audit.read(pc, 8) != original or audit.read(branch, 6) != bytes.fromhex('0f8427010000')
            or audit.read(epilogue, 9) != bytes.fromhex('4881c4c80200005dc3')):
        raise Unsupported('pinned agy typelinks guard, branch or return epilogue changed')
    new_slot = metadata_va + profile['next']
    displacement = new_slot - branch
    if not -(1 << 31) <= displacement < (1 << 31):
        raise Unsupported('synthetic module next is outside typelinks RIP-relative reach')
    return dict(offset=audit.offset(pc + 3, 4), old=original[3:7],
                new=struct.pack('<i', displacement),
                evidence=dict(kind='pinned-empty-type-module-guard', address=pc,
                              original_slot=original_next, replacement_slot=new_slot,
                              branch=branch, fast_return=epilogue, modified_bytes=4,
                              type_fields_and_fixups_empty=True,
                              original_module_count=1, synthetic_is_published_tail=True,
                              future_module_append='non-null synthetic.next selects unchanged slow path'))


def build(audit, ranges, metadata_va, installer_va, work=None):
    """Build one text-only module and a pre-runtime PIE-safe initializer.

    Ranges are contiguous dictionaries with start/end/original_pc/continuation
    and exact code bytes. A stub enters with JMP, so its pcsp is copied from
    the original PC without adding a synthetic call frame. The return value's
    checked patches redirect the verified preinit/DT_INIT/ELF-entry startup route
    and preserve the pinned empty-type-module guard. Pointer
    values (including original addresses) are written with RIP-relative code
    at startup, after the ELF loader has applied its normal relocations.
    """
    if not audit.profile:
        raise Unsupported(audit.profile_error or 'Go runtime layout is unverified')
    if not ranges:
        raise Unsupported('no Go stub ranges to register')
    ranges = sorted(ranges, key=lambda r: r['start'])
    if any(left['end'] != right['start'] for left, right in zip(ranges, ranges[1:])):
        raise Unsupported('Go module must cover only contiguous Go stub code')
    if metadata_va % 8:
        raise Unsupported('Go metadata address must be aligned to 8 bytes')
    text, end = ranges[0]['start'], ranges[-1]['end']
    if not 0 < end - text < 0x100000000:
        raise Unsupported('Go text module exceeds the uint32 function-offset format')
    profile = audit.profile
    names, files, cutab, pctab = bytearray(b'\0'), bytearray(), bytearray(), bytearray(b'\0')
    prepared, coverage = [], []
    for item in ranges:
        pc = item['original_pc']
        f, site = audit.function(pc), audit.replacement_site(pc)
        if f['func_id'] != 0 or f['func_flag'] & ~4 or f['deferreturn']:
            raise Unsupported('Go source uses special runtime, SP-write or defer-return semantics')
        if len(f['funcdata']) > 4 and f['funcdata'][4] != 0xffffffff:
            raise Unsupported('Go source has open-coded defer metadata')
        if site['pcsp'] < 0 or site['pcsp'] % 8 or site['pcsp'] > 0x7fffffff:
            raise Unsupported('Go source has an invalid stack delta')
        original = next(iter(Decoder(64, audit.read(pc, min(15, f['end'] - pc)), ip=pc)))
        if original.mnemonic != Mnemonic.POPCNT or original.memory_base or original.memory_index:
            raise Unsupported('initial Go backend supports register-only POPCNT')
        if item['continuation'] != original.next_ip:
            raise Unsupported('Go stub may replace only one complete original instruction')
        validate_code(item['code'], item['start'], item['end'], item['continuation'])
        length = item['end'] - item['start']
        nameoff = len(names)
        names += f['name'].encode() + b'\0'
        table = f['table']
        header = audit.read(table['address'], 72)
        offsets = struct.unpack_from('<5Q', header, 32)
        fileoff = len(files)
        fileno = site['pcfile']
        if fileno < 0:
            filename = b'?'
        else:
            slot = f['cu_offset'] + fileno
            if slot * 4 + 4 > offsets[2] - offsets[1]:
                raise Unsupported('original Go CU file index is out of bounds')
            original_offset = struct.unpack('<I', audit.read(table['address'] + offsets[1] + slot * 4, 4))[0]
            if original_offset >= offsets[3] - offsets[2]:
                raise Unsupported('original Go filename offset is out of bounds')
            raw = audit.read(table['address'] + offsets[2] + original_offset, offsets[3] - offsets[2] - original_offset)
            terminator = raw.find(b'\0')
            if terminator < 0:
                raise Unsupported('unterminated original Go filename')
            filename = raw[:terminator]
        files += filename + b'\0'
        cutab += struct.pack('<I', fileoff)
        def encoded(value):
            offset = len(pctab)
            pctab.extend(constpc(value, length))
            return offset
        pcsp, pcfile, pcln = encoded(site['pcsp']), encoded(len(prepared)), encoded(site['pcln'])
        original_pcd = list(site['pcdata'])
        original_pcd += [-1] * max(0, 3 - len(original_pcd))
        original_pcd[0] = -2  # UnsafePointUnsafe: no GC/preemption with hidden scratch pointers.
        original_pcd[2] = -1  # No synthetic inline tree: source file/line/name are explicit.
        pcd = [encoded(value) for value in original_pcd]
        rawfunc = struct.pack('<Ii i IIIIII i BBBB'.replace(' ', ''), item['start'] - text, nameoff,
                              f['args'], 0, pcsp, pcfile, pcln, len(pcd), 0,
                              f['start_line'], 0, 4, 0, len(f['funcdata']))
        rawfunc += struct.pack(f'<{len(pcd) + len(f["funcdata"])}I', *pcd, *f['funcdata'])
        prepared.append(rawfunc)
        coverage.append(dict(start=item['start'], end=item['end'], original_pc=pc,
                             original_function=f['name'], pcsp=site['pcsp'], unsafe_point=-2,
                             func_flag=4, pointer_maps='original FUNCDATA and source stack-map index',
                             stack_bytes_added=0, original_call_frame=True))
    pcln = bytearray(8 * (len(prepared) + 1))
    for index, (item, rawfunc) in enumerate(zip(ranges, prepared)):
        struct.pack_into('<II', pcln, index * 8, item['start'] - text, len(pcln))
        pcln.extend(rawfunc)
    struct.pack_into('<II', pcln, len(prepared) * 8, end - text, 0)
    # Go runtime.findfunc uses one 20-byte bucket per 4096 bytes, with sixteen
    # 256-byte subbuckets containing an index delta relative to its uint32 base.
    findtab = bytearray()
    starts = [item['start'] for item in ranges]
    for base in range(text, end, 4096):
        first = max(0, bisect_right(starts, base) - 1)
        deltas = [max(0, bisect_right(starts, min(base + sub * 256, end - 1)) - 1) - first for sub in range(16)]
        if max(deltas) > 255:
            raise Unsupported('Go findfunc subbucket exceeds its 8-bit index delta')
        findtab += struct.pack('<I16B', first, *deltas)
    blob = bytearray(profile['size'])
    fixups = []
    def append(raw, alignment=8):
        blob.extend(b'\0' * (-len(blob) % alignment))
        position = len(blob)
        blob.extend(raw)
        return position
    header_at = append(b'\0' * 72)
    names_at, cutab_at, files_at, pctab_at, pcln_at, find_at = [append(raw) for raw in (names, cutab, files, pctab, pcln, findtab)]
    empty_gc_at = append(b'\0')
    struct.pack_into('<I4B8Q', blob, header_at, 0xfffffff1, 0, 0, 1, 8, len(ranges), len(ranges),
                     0, names_at-header_at, cutab_at-header_at, files_at-header_at, pctab_at-header_at, pcln_at-header_at)
    def pointer(slot, address):
        fixups.append((metadata_va + slot, address))
    pointer(0, metadata_va + header_at)
    for slot, at, count in ((8, names_at, len(names)), (32, cutab_at, len(ranges)),
                            (56, files_at, len(files)), (80, pctab_at, len(pctab)),
                            (104, pcln_at, len(pcln)), (128, pcln_at, len(ranges)+1)):
        pointer(slot, metadata_va + at)
        struct.pack_into('<QQ', blob, slot + 8, count, count)
    pointer(152, metadata_va + find_at)
    for slot, address in ((160, text), (168, end), (176, text), (184, end),
                          (profile['gofunc'], profile['gofunc_address']),
                          (280, metadata_va + empty_gc_at), (288, metadata_va + empty_gc_at)):
        pointer(slot, address)
    # Zero-sized data/type ranges and empty initializers/hashes are intentional:
    # this module describes existing frames, it owns no Go roots or Go objects.
    dynamic = audit.elf.get_section_by_name('.dynamic')
    preinit = preinit_registration(audit, installer_va)
    target, patch_offset, method = audit.elf['e_entry'], 24, 'ELF entry before Go runtime startup'
    if dynamic:
        for index, tag in enumerate(dynamic.iter_tags()):
            if tag.entry.d_tag == 'DT_INIT':
                target = tag.entry.d_val
                patch_offset = dynamic['sh_offset'] + index * 16 + 8
                method = 'DT_INIT before original constructors'
                if target == 0:
                    raise Unsupported('null original DT_INIT is unsupported')
                break
        else:
            if any(tag.entry.d_tag in ('DT_INIT_ARRAY', 'DT_PREINIT_ARRAY', 'DT_NEEDED')
                   for tag in dynamic.iter_tags()):
                raise Unsupported('dynamic Go binary without DT_INIT may start Go in a constructor')
            method = 'ELF entry after PIE relocations; no constructor arrays or linked libraries'
    legacy_patch = None if preinit is not None else legacy_init_patch(audit, target, installer_va)
    startup_entry = None
    if preinit is not None:
        target = preinit['target']
        method = 'first verified preinit callback before original executable initialization'
    elif method.startswith('DT_INIT') and legacy_patch is None:
        startup_entry = verify_dynamic_init_entry(audit)
    if legacy_patch is not None:
        method = 'DT_INIT and verified legacy init callback before original constructors'
    # These original words must remain writable after normal loader relocation.
    for address in (profile['module'] + profile['next'], profile['lastmoduledatap']):
        if not any(p['p_flags'] & 2 and p['p_vaddr'] <= address and address+8 <= p['p_vaddr']+p['p_memsz'] for p in audit.segments):
            raise Unsupported('original Go registration pointer is not writable')
        for p in audit.elf.iter_segments():
            if p['p_type'] == 'PT_GNU_RELRO' and p['p_vaddr'] <= address < p['p_vaddr']+p['p_memsz']:
                raise Unsupported('original Go registration pointer is protected by RELRO')
    has_caller = preinit is not None or method.startswith('DT_INIT')
    lines = ['.intel_syntax noprefix', '.text', '.global go_init', '.type go_init,@function',
             'go_init:', '.cfi_startproc', '.cfi_def_cfa rsp, 8' if has_caller else '.cfi_def_cfa rsp, 0']
    if not has_caller:
        lines.append('.cfi_undefined rip')
    lines += ['push rax', '.cfi_adjust_cfa_offset 8']
    fixups += [(profile['module'] + profile['next'], metadata_va), (profile['lastmoduledatap'], metadata_va)]
    for index, (slot, value) in enumerate(fixups):
        if any(not -(1 << 31) < address - installer_va < (1 << 31) for address in (slot, value)):
            raise Unsupported('Go initializer exceeds RIP-relative addressing reach')
        lines += [f'.set ptr_{index}, {value}', f'.set slot_{index}, {slot}',
                  f'lea rax, [rip + ptr_{index}]', f'mov [rip + slot_{index}], rax']
    lines += ['pop rax', '.cfi_adjust_cfa_offset -8', f'.set original_start, {target}', 'jmp original_start',
              '.cfi_endproc', '.global go_init_end', 'go_init_end:', '.size go_init, .-go_init',
              '.section .note.GNU-stack,"",@progbits']
    constructor, constructor_elf_data = _assemble('\n'.join(lines) + '\n', installer_va, work, with_elf=True)
    patch = dict(offset=patch_offset, old=audit.data[patch_offset:patch_offset + 8], new=struct.pack('<Q', installer_va))
    patches = preinit['patches'] if preinit is not None else [patch] + ([legacy_patch] if legacy_patch is not None else [])
    type_fast_path = typelinks_fast_path_patch(audit, blob, metadata_va, fixups)
    if type_fast_path is not None:
        patches.append(type_fast_path)
    return dict(blob=bytes(blob), alignment=8, constructor_bytes=constructor, patches=patches,
                constructor_elf=str(Path(work)/'go-init.elf') if work is not None else None,
                constructor_elf_data=constructor_elf_data,
                report=dict(layout_profile=profile['name'], registration=method, original_module=profile['module'],
                            module_address=metadata_va, text_start=text, text_end=end, metadata_bytes=len(blob),
                            legacy_init_hook=legacy_patch['evidence'] if legacy_patch is not None else None,
                            startup_entry=startup_entry,
                            preinit_hook=preinit['evidence'] if preinit is not None else None,
                            typelinks_fast_path=type_fast_path['evidence'] if type_fast_path is not None else None,
                            constructor_bytes=len(constructor), ranges=coverage, coverage_complete=True,
                            constructor_frame='SysV caller CFA=RSP+8' if has_caller else 'ELF entry CFA=RSP; undefined return address',
                            stack_growth='unchanged original pcsp; no extra stack use',
                            preemption='all stub PCs unsafe and assembly-marked',
                            source_locations='original function/file/line; inline expansion omitted'))
