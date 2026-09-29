"""Native backtrace metadata for jump-entered replacement code.

pyelftools decodes the original unwind rows; GNU as/ld emit the new FDEs.
Only the 12-byte GNU EH header and its sorted relative index are serialized
here. This describes native unwinding, not C++ exception landing pads, Go
safepoints, precise signal contexts, or stack-growth checks.
"""

from bisect import bisect_right
from dataclasses import dataclass
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess

from elftools.dwarf.callframe import FDE
from elftools.elf.elffile import ELFFile
import iced_x86 as ix


DWARF_REG = {
    ix.Register.RAX: 0, ix.Register.RDX: 1, ix.Register.RCX: 2,
    ix.Register.RBX: 3, ix.Register.RSI: 4, ix.Register.RDI: 5,
    ix.Register.RBP: 6, ix.Register.RSP: 7,
    **{getattr(ix.Register, f"R{i}"): i for i in range(8, 16)},
}
CALLEE = (3, 6, 12, 13, 14, 15)
WRITES = (ix.OpAccess.WRITE, ix.OpAccess.COND_WRITE, ix.OpAccess.READ_WRITE,
          ix.OpAccess.READ_COND_WRITE)


class Unsupported(ValueError):
    pass


class Index:
    def __init__(self, elf, *, frame_recovery=None):
        self.elf = elf
        self.frame_recovery = frame_recovery
        self.inferred = {}
        section = elf.get_section_by_name('.eh_frame')
        self.address = section['sh_addr'] if section is not None else 0
        dwarf = elf.get_dwarf_info(relocate_dwarf_sections=False, follow_links=False)
        self.fdes = sorted((f for f in dwarf.EH_CFI_entries() if isinstance(f, FDE)
                            and f['address_range']), key=lambda f: f['initial_location']) if dwarf.has_EH_CFI() else []
        self.starts = [f['initial_location'] for f in self.fdes]
        self.prefix_ends = []
        maximum = 0
        for fde in self.fdes:
            maximum = max(maximum, fde['initial_location'] + fde['address_range'])
            self.prefix_ends.append(maximum)
        self.cache = {}

    def row(self, pc):
        j = bisect_right(self.starts, pc) - 1
        covering = []
        while j >= 0 and self.prefix_ends[j] > pc:
            if pc < self.starts[j] + self.fdes[j]['address_range']:
                covering.append(j)
                if len(covering) > 1:
                    raise Unsupported('multiple original FDEs cover this PC; native frame is ambiguous')
            j -= 1
        if not covering:
            if self.frame_recovery is not None:
                try:
                    row = self.frame_recovery.row(pc)
                except ValueError as error:
                    raise Unsupported(f'original PC has no native FDE; frame inference: {error}') from error
                self.inferred[pc] = self.frame_recovery.evidence(pc)
                return row
            raise Unsupported('original PC has no native .eh_frame FDE')
        j = covering[0]
        fde = self.fdes[j]
        if fde.cie['return_address_register'] != 16:
            raise Unsupported('nonstandard return-address register')
        augmentation = fde.cie['augmentation']
        if isinstance(augmentation, str):
            augmentation = augmentation.encode()
        if b'S' in augmentation:
            raise Unsupported('original CIE describes a signal frame')
        if j not in self.cache:
            table = fde.get_decoded().table
            self.cache[j] = ([r['pc'] for r in table], table)
        starts, rows = self.cache[j]
        return rows[bisect_right(starts, pc) - 1]

    def entries(self):
        return [(f['initial_location'], self.address + f.offset) for f in self.fdes]


def _sleb(value):
    result = []
    while True:
        byte = value & 127
        value >>= 7
        done = (value == 0 and not byte & 64) or (value == -1 and byte & 64)
        result.append(byte if done else byte | 128)
        if done:
            return result


def _uleb(value):
    result = []
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    return result + [value]


def _breg(register, offset):
    if not 0 <= register < 32:
        raise Unsupported('unsupported DWARF base register')
    return [0x70 + register] + _sleb(offset)


def _escape(code):
    return '.cfi_escape ' + ','.join(str(n) for n in code)


def _signed(value):
    return (value ^ (1 << 63)) - (1 << 63)


class Machine:
    """Track original GPR values and stack slots, not arithmetic semantics."""
    def __init__(self):
        self.delta = 0  # current RSP = original RSP - delta
        self.origins = {r: r for r in range(16)}
        self.slots = {}  # original-RSP-relative byte offset -> original register
        self.anchors = {}  # current register = original RSP + offset

    def stack(self, offset=0):
        if self.delta is not None:
            return _breg(7, self.delta + offset)
        if self.anchors:
            reg, displacement = next(iter(sorted(self.anchors.items())))
            return _breg(reg, offset - displacement)
        raise Unsupported('dynamic RSP without a preserved stack anchor')

    def original(self, register, address=False):
        if register == 7:
            return self.stack()
        for current, original in self.origins.items():
            if original == register:
                return _breg(current, 0)
        for offset, original in sorted(self.slots.items()):
            if original == register:
                expression = self.stack(offset)
                return expression if address else expression + [0x06]  # deref
        raise Unsupported(f'original DWARF register {register} is unavailable')

    def rules(self, inherited):
        cfa = inherited['cfa']
        if cfa.expr is not None:
            raise Unsupported('original CFA uses an expression')
        if cfa.reg == 7 and self.delta is not None:
            lines = [f'.cfi_def_cfa 7,{cfa.offset + self.delta}']
        elif cfa.reg != 7 and self.origins.get(cfa.reg) == cfa.reg:
            lines = [f'.cfi_def_cfa {cfa.reg},{cfa.offset}']
        else:
            expression = self.original(cfa.reg) + [0x11] + _sleb(cfa.offset) + [0x22]
            lines = [_escape([0x0f] + _uleb(len(expression)) + expression)]
        # Missing ABI callee-saved rows mean the incoming value remains in
        # that register. Do not invent preservation for caller-saved values.
        registers = sorted(set(CALLEE) | {k for k in inherited if isinstance(k, int)})
        for register in registers:
            rule = inherited.get(register)
            kind, argument = (rule.type, rule.arg) if rule else ('SAME_VALUE', None)
            if kind == 'OFFSET':
                lines.append(f'.cfi_offset {register},{argument}')
            elif kind == 'VAL_OFFSET':
                lines.append(f'.cfi_val_offset {register},{argument}')
            elif kind == 'UNDEFINED':
                lines.append(f'.cfi_undefined {register}')
            elif kind in ('SAME_VALUE', 'REGISTER'):
                original = register if kind == 'SAME_VALUE' else argument
                if original == 16:
                    raise Unsupported('return address held in live instruction pointer')
                expression = self.original(original)
                lines.append(_escape([0x16] + _uleb(register) + _uleb(len(expression)) + expression))
            else:
                raise Unsupported(f'original register rule {kind} is not supported')
        return lines

    def step(self, ins, *, terminal=False):
        if ins.is_invalid or ins.has_lock_prefix or ins.is_privileged:
            raise Unsupported(f'unsupported generated instruction: {ins}')
        if ins.flow_control not in (ix.FlowControl.NEXT, ix.FlowControl.CALL):
            if terminal and ins.flow_control in (ix.FlowControl.UNCONDITIONAL_BRANCH,
                                                ix.FlowControl.CONDITIONAL_BRANCH,
                                                ix.FlowControl.RETURN):
                return
            raise Unsupported(f'nonlinear generated range: {ins}')
        if ins.flow_control == ix.FlowControl.CALL:
            # The return address is pushed only while the callee runs. Its
            # own compiler-produced FDE covers that interval; this row is
            # for the trampoline's return PC. SysV callee saves survive.
            for r in (0, 1, 2, 4, 5, 8, 9, 10, 11):
                self.origins.pop(r, None)
                self.anchors.pop(r, None)
            return
        before_origins = dict(self.origins)
        before_anchors = dict(self.anchors)
        old_delta = self.delta
        changed_rsp = False
        if ins.mnemonic in (ix.Mnemonic.PUSH, ix.Mnemonic.PUSHFQ):
            if self.delta is None or ins.stack_pointer_increment != -8:
                raise Unsupported('non-qword push or push after dynamic alignment')
            self.delta += 8
            changed_rsp = True
            source = DWARF_REG.get(ins.op0_register) if ins.op_count else None
            self.slots[-self.delta] = before_origins.get(source)
        elif ins.mnemonic in (ix.Mnemonic.POP, ix.Mnemonic.POPFQ):
            if self.delta is None or ins.stack_pointer_increment != 8:
                raise Unsupported('non-qword pop or pop after dynamic alignment')
            restored = self.slots.pop(-self.delta, None)
            self.delta -= 8
            changed_rsp = True
            if ins.mnemonic == ix.Mnemonic.POP:
                destination = DWARF_REG.get(ins.op0_register)
                if destination is None or destination == 7:
                    raise Unsupported('non-GPR pop or pop rsp')
                self.origins[destination] = restored
                self.anchors.pop(destination, None)
                return
        elif ins.op0_kind == ix.OpKind.REGISTER and ins.op0_register == ix.Register.RSP:
            changed_rsp = True
            if (ins.mnemonic == ix.Mnemonic.LEA and ins.memory_base == ix.Register.RSP
                    and ins.memory_index == ix.Register.NONE and self.delta is not None):
                self.delta -= _signed(ins.memory_displacement)
            elif (ins.mnemonic in (ix.Mnemonic.ADD, ix.Mnemonic.SUB)
                  and ins.op1_kind in (ix.OpKind.IMMEDIATE8TO64, ix.OpKind.IMMEDIATE32TO64)
                  and self.delta is not None):
                value = _signed(ins.immediate(1))
                self.delta += value if ins.mnemonic == ix.Mnemonic.SUB else -value
            elif ins.mnemonic == ix.Mnemonic.MOV and ins.op1_register in DWARF_REG:
                source = DWARF_REG[ins.op1_register]
                if source not in before_anchors:
                    raise Unsupported('RSP restored from an untracked register')
                self.delta = -before_anchors[source]
            elif (ins.mnemonic == ix.Mnemonic.AND and ins.op1_kind in
                  (ix.OpKind.IMMEDIATE8TO64, ix.OpKind.IMMEDIATE32TO64)
                  and _signed(ins.immediate(1)) == -16 and before_anchors):
                self.delta = None
            else:
                raise Unsupported(f'untracked stack change: {ins}')
        info = ix.InstructionInfoFactory().info(ins)
        for used in info.used_registers():
            full = ix.RegisterExt.full_register(used.register)
            register = DWARF_REG.get(full)
            if used.access in WRITES and register is not None:
                if register == 7:
                    if not changed_rsp:
                        raise Unsupported(f'untracked implicit RSP write: {ins}')
                    continue
                self.origins.pop(register, None)
                self.anchors.pop(register, None)
        if (ins.mnemonic == ix.Mnemonic.MOV and ins.op0_kind == ix.OpKind.REGISTER
                and ins.op1_kind == ix.OpKind.REGISTER and ins.op0_register in DWARF_REG
                and ins.op1_register in DWARF_REG):
            destination, source = DWARF_REG[ins.op0_register], DWARF_REG[ins.op1_register]
            if destination != 7:
                self.origins[destination] = before_origins.get(source)
                if source == 7 and old_delta is not None:
                    self.origins.pop(destination, None)
                    self.anchors[destination] = -old_delta
                elif source in before_anchors:
                    self.anchors[destination] = before_anchors[source]
        for memory in info.used_memory():
            if memory.access not in WRITES:
                continue
            base = DWARF_REG.get(memory.base)
            if memory.index != ix.Register.NONE or base is None:
                continue
            offset = (-old_delta if base == 7 and old_delta is not None
                      else before_anchors.get(base))
            if offset is None:
                continue
            offset += _signed(memory.displacement)
            size = ix.MemorySizeExt.size(memory.memory_size)
            for slot in list(self.slots):
                if slot < offset + size and slot + 8 > offset:
                    self.slots.pop(slot)
            # PUSH was already recorded, including its implicit memory write.
            if ins.mnemonic == ix.Mnemonic.PUSH:
                self.slots[-self.delta] = before_origins.get(DWARF_REG.get(ins.op0_register))
            elif (ins.mnemonic == ix.Mnemonic.MOV and size == 8
                  and ins.op1_kind == ix.OpKind.REGISTER):
                self.slots[offset] = before_origins.get(DWARF_REG.get(ins.op1_register))


def assembly_for_range(index, code, start, original_pc):
    inherited = index.row(original_pc)
    machine = Machine()
    lines = ['.cfi_startproc simple', '.cfi_return_column 16']
    previous = machine.rules(inherited)
    lines += previous
    instructions = list(ix.Decoder(64, code, ip=start))
    for n, ins in enumerate(instructions):
        lines.append(f'.zero {ins.len}')
        # A relocated conditional exit can precede the continuation jump.
        # Its taken edge leaves this FDE; the fallthrough retains the same
        # state. Internal branches still need a real CFG and remain refused.
        external_exit = (ins.flow_control in (ix.FlowControl.UNCONDITIONAL_BRANCH,
                                              ix.FlowControl.CONDITIONAL_BRANCH)
                         and not start <= ins.near_branch_target < start+len(code))
        machine.step(ins, terminal=n == len(instructions) - 1 or external_exit)
        if n != len(instructions) - 1:
            current = machine.rules(inherited)
            if current != previous:
                # Each line replaces one CFA/register rule. Keep identical
                # rules in force instead of repeating every preserved GPR
                # after each PUSH/POP; this materially shrinks the FDEs.
                lines += [rule for rule in current if rule not in previous]
                previous = current
    lines.append('.cfi_endproc')
    return lines


def _original_rules(row):
    """Re-emit compiler-authored helper rules without inferring its CFG."""
    cfa = row['cfa']
    if cfa.expr is None:
        lines = [f'.cfi_def_cfa {cfa.reg},{cfa.offset}']
    else:
        lines = [_escape([0x0f] + _uleb(len(cfa.expr)) + list(cfa.expr))]
    for register in sorted(k for k in row if isinstance(k, int)):
        rule = row[register]
        if rule.type in ('OFFSET', 'VAL_OFFSET', 'REGISTER'):
            directive = {'OFFSET': 'offset', 'VAL_OFFSET': 'val_offset', 'REGISTER': 'register'}[rule.type]
            lines.append(f'.cfi_{directive} {register},{rule.arg}')
        elif rule.type in ('SAME_VALUE', 'UNDEFINED'):
            lines.append(f'.cfi_{rule.type.lower()} {register}')
        elif rule.type in ('EXPRESSION', 'VAL_EXPRESSION'):
            opcode = 0x10 if rule.type == 'EXPRESSION' else 0x16
            lines.append(_escape([opcode] + _uleb(register) + _uleb(len(rule.arg)) + list(rule.arg)))
        else:
            raise Unsupported(f'unsupported compiler CFI rule {rule.type}')
    return lines


def _helper_assembly(fde):
    if fde.cie['return_address_register'] != 16:
        raise Unsupported('nonstandard helper return-address register')
    if (fde.cie.augmentation_dict.get('personality') is not None
            or fde.lsda_pointer is not None):
        raise Unsupported('helper has exception personality/landing pads')
    rows = fde.get_decoded().table
    position = fde['initial_location']
    end = position + fde['address_range']
    result = ['.cfi_startproc simple', '.cfi_return_column 16']
    previous_registers = set()
    for row in rows:
        if row['pc'] < position or row['pc'] > end:
            raise Unsupported('compiler CFI row outside helper range')
        if row['pc'] != position:
            result.append(f'.zero {row["pc"] - position}')
            position = row['pc']
        current_registers = {r for r in row if isinstance(r, int)}
        # A compiler's restore operation removes a rule from the decoded
        # row when that register had the default incoming location. Copying
        # only present keys would leave a stale stack-slot rule in force.
        result += [f'.cfi_same_value {r}' for r in sorted(previous_registers-current_registers)]
        result += _original_rules(row)
        previous_registers = current_registers
    if position != end:
        result.append(f'.zero {end-position}')
    return result + ['.cfi_endproc']


@dataclass
class Result:
    blob: bytes
    sections: list
    header_address: int
    header_size: int
    report: dict


def build(elf, blob, code_address, ranges, metadata_address, work, *, helper_elf=None,
          frame_recovery=None, extra_helpers=()):
    """Emit new FDEs and a merged GNU index, with explicit uncovered ranges.

    Each range is {start, end, original_pc}. Ranges must start at an original
    instruction boundary with the original machine state, and contain a
    complete lowering (or one relocated instruction). `metadata_address`
    is the final VA of the returned bytes. Integrator must install/replace
    PT_GNU_EH_FRAME using header_address/header_size and map these bytes.
    """
    work = Path(work)
    index = Index(elf, frame_recovery=frame_recovery)
    assembly, layout, covered, gaps = [], [], [], []
    previous_end = code_address
    for n, item in enumerate(sorted(ranges, key=lambda r: r['start'])):
        start, end, original_pc = item['start'], item['end'], item['original_pc']
        if not code_address <= start < end <= code_address + len(blob) or start < previous_end:
            raise ValueError('invalid or overlapping unwind range')
        previous_end = end
        if item.get('runtime') == 'go':
            gaps.append({**item, 'reason': 'Go frame needs runtime metadata; SysV frame inference is inapplicable'})
            continue
        try:
            body = assembly_for_range(index, blob[start-code_address:end-code_address], start, original_pc)
        except Unsupported as error:
            gaps.append({**item, 'reason': str(error)})
            continue
        assembly += [f'.section .text.unwind_{n},"ax",@progbits'] + body
        layout.append(f'.text.unwind_{n} {start} : {{ *(.text.unwind_{n}) }}')
        covered.append({**item, 'source': 'inferred-native-cfg' if original_pc in index.inferred else 'original-fde'})
    helper_count = 0
    helper_inputs = list(extra_helpers)
    if helper_elf is not None:
        helper_inputs.insert(0, (helper_elf, code_address, code_address + len(blob), 'compiler_helper'))
    for helper_path, allowed_start, allowed_end, helper_kind in helper_inputs:
        with Path(helper_path).open('rb') as stream:
            helpers = Index(ELFFile(stream))
            if helper_kind == 'go_initializer' and [
                    (f['initial_location'], f['initial_location'] + f['address_range'])
                    for f in helpers.fdes] != [(allowed_start, allowed_end)]:
                raise ValueError('Go initializer needs complete compiler-authored CFI')
            for n, fde in enumerate(helpers.fdes):
                start, end = fde['initial_location'], fde['initial_location'] + fde['address_range']
                item = {'start': start, 'end': end, 'kind': helper_kind}
                if not allowed_start <= start < end <= allowed_end:
                    raise ValueError('helper FDE lies outside injected payload')
                if any(start < r['end'] and end > r['start'] for r in ranges + covered):
                    raise ValueError('helper FDE overlaps instruction-lowering range')
                try:
                    body = _helper_assembly(fde)
                except Unsupported as error:
                    gaps.append({**item, 'reason': str(error)})
                    continue
                name = f'.text.helper_unwind_{helper_count}'
                assembly += [f'.section {name},"ax",@progbits'] + body
                layout.append(f'{name} {start} : {{ *({name}) }}')
                covered.append(item)
                helper_count += 1
    fde_blob, new_entries = b'', []
    if covered:
        source = work / 'unwind.S'
        source.write_text('\n'.join(assembly) + '\n.section .note.GNU-stack,"",@progbits\n')
        script = work / 'unwind.ld'
        script.write_text('SECTIONS {\n' + '\n'.join(layout) +
                          f'\n.eh_frame {metadata_address} : {{ KEEP(*(.eh_frame)) }}\n'
                          '/DISCARD/ : { *(.note*) *(.comment) }\n}\n')
        subprocess.run(['cc', '-c', str(source), '-o', str(work/'unwind.o')], check=True)
        subprocess.run(['ld', '-T', str(script), '-o', str(work/'unwind.elf'), str(work/'unwind.o')], check=True)
        with (work/'unwind.elf').open('rb') as stream:
            linked = ELFFile(stream)
            section = linked.get_section_by_name('.eh_frame')
            if section['sh_addr'] != metadata_address:
                raise ValueError('linker moved unwind section')
            fde_blob = section.data()
            new_entries = Index(linked).entries()
    if not fde_blob and not index.address:
        # Even an empty index must point at a valid zero-terminated CFI
        # stream, never at its own GNU header interpreted as an FDE.
        fde_blob = bytes(4)
    header_offset = (len(fde_blob) + 3) & -4
    header_address = metadata_address + header_offset
    entries = sorted(index.entries() + new_entries)
    frame_address = index.address if index.address else metadata_address
    try:
        header = struct.pack('<BBBBiI', 1, 0x1b, 0x03, 0x3b,
                             frame_address - (header_address + 4), len(entries))
        header += b''.join(struct.pack('<ii', start - header_address, fde - header_address)
                           for start, fde in entries)
    except struct.error as error:
        raise Unsupported('GNU unwind header exceeds signed 32-bit relative reach') from error
    sections = ([{'name': '.penryn.eh_frame', 'offset': 0, 'size': len(fde_blob), 'alignment': 8}]
                if fde_blob else [])
    sections.append({'name': '.penryn.eh_frame_hdr', 'offset': header_offset,
                     'size': len(header), 'alignment': 4})
    report = {'covered_ranges': covered, 'uncovered_ranges': gaps,
              'original_fdes': len(index.fdes), 'new_fdes': len(new_entries),
              'compiler_helper_fdes': helper_count,
              'inferred_ranges': sum(r.get('source') == 'inferred-native-cfg' for r in covered),
              'frame_recovery': frame_recovery.report() if frame_recovery is not None else None,
              'native_coverage_complete': not gaps,
              'native_backtrace_only': True, 'go_safepoints_supported': False,
              'exception_landing_pads_supported': False,
              'precise_original_fault_context_supported': False}
    return Result(fde_blob + bytes(header_offset-len(fde_blob)) + header, sections,
                  header_address, len(header), report)


def audit_runtime(elf, sites, go_metadata=None):
    """Explicit runtime gate; a passing smoke test cannot make this safe."""
    tables = (go_metadata or {}).get('tables', [])
    functions = sorted((f for table in tables for f in table['functions']), key=lambda f: f['start'])
    starts = [f['start'] for f in functions]
    go_sites = []
    for site in sites:
        for ins in site.insns:
            j = bisect_right(starts, ins.ip) - 1
            if j >= 0 and ins.ip < functions[j]['end']:
                go_sites.append({'address': ins.ip, 'function': functions[j]['name'],
                                 'instruction': str(ins)})
    return {'go_metadata_audited': go_metadata is not None,
            'go_tables': len(tables), 'go_functions': len(functions),
            'go_patch_sites': go_sites,
            'known_go_sites_unhandled': len(go_sites),
            'go_safepoints_supported': False,
            'go_stack_growth_supported': False,
            'production_ready': False,
            'strict_runtime_reasons': ([f'{len(go_sites)} patched instructions belong to Go runtime metadata; appended PCs and scratch stack are not registered'] if go_sites else []) +
                (['Go metadata was not audited'] if go_metadata is None else []) +
                (['unresolved Go metadata candidates'] if (go_metadata or {}).get('rejected_candidates') else []) +
                (['Go build information exists without a validated pclntab'] if
                 (go_metadata or {}).get('go_build_version') and not tables else [])}


def load_go_metadata(path, helper=None):
    """Use the packaged standard-library helper; never compile during patching."""
    helper = helper or os.environ.get('PENRYN_GOMETA') or shutil.which('penryn-go-metadata')
    if not helper:
        return None
    result = subprocess.run([str(helper), str(path)], check=True, capture_output=True, text=True)
    metadata = json.loads(result.stdout)
    if not isinstance(metadata.get('tables'), list) or not isinstance(metadata.get('rejected_candidates'), list):
        raise ValueError('invalid Go metadata helper report')
    return metadata
