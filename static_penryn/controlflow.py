"""Bounded control-flow evidence from iced decoding and ELF metadata.

This supplements entry-point protection; it does not claim complete recovery
of indirect control flow. Relative jump tables are recognized only with an
explicit unsigned range check and the conventional sign-extend/add dispatch.
Every recovered entry is protected even if execution profiles never visit it.
Function boundaries come from ELF symbols and pyelftools' DWARF FDE parser.
"""
from array import array
from bisect import bisect_right
from collections import Counter, deque
from collections.abc import Iterable
from heapq import merge
from typing import TypedDict

import iced_x86 as ix
from elftools.dwarf.callframe import FDE
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from .checked import iter_ints


class RelativeTable(TypedDict):
    """One recovered rel32 jump table; `targets` are sorted and unique."""
    table: int
    entries: int
    entry_size: int
    dispatch: int
    guard: int
    default: int
    targets: list[int]


class CFGReport(TypedDict):
    function_ranges: int
    function_sources: dict[str, int]
    relative_table_candidates: int
    relative_tables: list[RelativeTable]
    instruction_boundary_bytes: int
    block_leaders: int
    indirect_recovery_complete: bool


class Recovery:
    """Feed the existing linear scan; retain starts as one bit per code byte.

    `lookup(ip)` decodes at a previously observed instruction boundary only.
    `bounds(ip)` returns a conservative function interval or None. Together
    these implement dataflow.analyze's optional bounded successor callback.
    Call finish() after all executable sections have been fed, before lookup.
    Extra function_ranges are (start, end, name) records from another parser.
    """

    def __init__(self, elf: ELFFile, *, function_ranges: Iterable[tuple[int, int, str]] = (),
                 max_table_entries: int = 4096) -> None:
        self.elf = elf
        self.targets: set[int] = set()
        # (start, end, name, source)
        self.functions: list[tuple[int, int, str, str]] = []
        self.tables: list[RelativeTable] = []
        self.max_table_entries = max_table_entries
        self.window: deque[ix.Instruction] = deque(maxlen=12)
        self._factory = ix.InstructionInfoFactory()
        self._finished = False
        self._current: tuple[int, int, int, bytearray] | None = None
        self._last: int | None = None
        # (start, end, file offset, instruction-start bitmap)
        self._section: list[tuple[int, int, int, bytearray]] = []
        # (start, end, file offset)
        self._readable: list[tuple[int, int, int]] = []
        self._starts: list[int] = []
        self._function_starts: list[int] = []
        self._function_ends: list[int] = []
        self._functions_dirty = True
        self._table_keys: set[tuple[int, int, int]] = set()
        self._candidate_count = 0
        self._leaders: set[int] = set()
        self._ordered_leaders = array('Q')
        self._leaders_dirty = True
        self._pending_leader: int | None = None
        loads = [seg for seg in elf.iter_segments() if seg['p_type'] == 'PT_LOAD']
        for sec in elf.iter_sections():
            start, count = sec['sh_addr'], sec['sh_size']
            if (sec['sh_flags'] & 2 and not sec['sh_flags'] & (1 | 0x800)
                    and sec['sh_type'] == 'SHT_PROGBITS' and count
                    and any(seg['p_flags'] & 4 and not seg['p_flags'] & 2
                            and seg['p_vaddr'] <= start
                            and start + count <= seg['p_vaddr'] + seg['p_filesz']
                            and sec['sh_offset'] == seg['p_offset'] + start - seg['p_vaddr']
                            for seg in loads)):
                self._readable.append((start, start + count, sec['sh_offset']))
            if sec['sh_flags'] & 4 and count:
                self._section.append((start, start + count, sec['sh_offset'],
                                      bytearray((count + 7) // 8)))
                self._leaders.update((start, start + count))
        def section_start(item: tuple[int, int, int, bytearray]) -> int:
            return item[0]

        self._section.sort(key=section_start)
        self._starts = [item[0] for item in self._section]
        self._readable.sort()
        self._read_starts = [item[0] for item in self._readable]
        for sec in elf.iter_sections():
            if isinstance(sec, SymbolTableSection):
                for sym in sec.iter_symbols():
                    if sym['st_info']['type'] == 'STT_FUNC' and self.is_code(sym['st_value']):
                        self.targets.add(sym['st_value'])
                        if sym['st_size']:
                            self.add_functions([(sym['st_value'],
                                                 sym['st_value'] + sym['st_size'],
                                                 sym.name)], source='symbol')
        eh_frame = elf.get_section_by_name('.eh_frame')
        if eh_frame is not None and eh_frame['sh_size']:
            # pyelftools understands DW_EH_PE encodings and FDE/CIE relations;
            # do not duplicate that decoder or follow external debug links.
            try:
                dwarf = elf.get_dwarf_info(relocate_dwarf_sections=False, follow_links=False)
                for entry in dwarf.EH_CFI_entries():
                    if isinstance(entry, FDE):
                        start = entry['initial_location']
                        end = start + entry['address_range']
                        self.add_functions([(start, end, '')], source='eh_frame')
            except Exception as exc:
                raise ValueError(f'cannot recover .eh_frame function ranges: {exc}') from exc
        self.add_functions(function_ranges, source='external')

    def is_code(self, address: int) -> bool:
        index = bisect_right(self._starts, address) - 1
        return index >= 0 and address < self._section[index][1]

    @property
    def table_ranges(self) -> list[tuple[int, int]]:
        """Data spans to protect from rewriting, including tables in RX text."""
        return [(item['table'], item['table'] + item['entries'] * item['entry_size'])
                for item in self.tables]

    def add_functions(self, ranges: Iterable[tuple[int, int, str]], *, source: str = 'external') -> None:
        """Add parser-derived ranges; malformed/foreign ranges are ignored."""
        for start, end, name in ranges:
            index = bisect_right(self._starts, start) - 1
            if (index >= 0 and start < end <= self._section[index][1]
                    and start >= self._section[index][0]):
                self.functions.append((start, end, name, source))
                self.targets.add(start)
                self._leaders.update((start, end))
                self._leaders_dirty = True
                self._functions_dirty = True

    def _index_functions(self) -> None:
        if not self._functions_dirty:
            return
        self.functions = sorted(set(self.functions))
        self._function_starts = [item[0] for item in self.functions]
        maximum = 0
        self._function_ends = []
        for _, end, _, _ in self.functions:
            maximum = max(maximum, end)
            self._function_ends.append(maximum)
        self._functions_dirty = False

    def bounds(self, address: int) -> tuple[int, int] | None:
        """Intersect all covering symbol/FDE intervals; gaps remain unknown."""
        self._index_functions()
        index = bisect_right(self._function_starts, address) - 1
        begin, end = 0, 1 << 64
        found = False
        while index >= 0 and self._function_ends[index] > address:
            lo, hi, _, _ = self.functions[index]
            if lo <= address < hi:
                begin, end = max(begin, lo), min(end, hi)
                found = True
            index -= 1
        return (begin, end) if found else None

    def _index_leaders(self) -> None:
        if self._leaders_dirty:
            self._leaders.update(self.targets)
            if not self._ordered_leaders:
                self._ordered_leaders = array('Q', sorted(self._leaders))
            else:
                # add_functions remains usable after finish without rebuilding
                # a multi-million-entry Python set from the frozen index.
                ordered = array('Q')
                previous: int | None = None
                for address in merge(self._ordered_leaders, sorted(self._leaders)):
                    if address != previous:
                        ordered.append(address)
                        previous = address
                self._ordered_leaders = ordered
            self._leaders.clear()
            self._leaders_dirty = False

    def block_bounds(self, address: int) -> tuple[int, int] | None:
        """Return a verified, branch-delimited interval even without symbols.

        Leaders include section/function boundaries, recovered table targets,
        direct branch targets and ordinary code after control-flow operations.
        Consecutive terminators/invalid instructions share a pending boundary;
        grouping always rejects such instructions, even within one interval.
        Unknown indirect entries remain an explicit limitation; the planner
        still protects independently recovered address-taken sites.
        """
        if self.lookup(address) is None:
            return None
        self._index_leaders()
        index = bisect_right(self._ordered_leaders, address) - 1
        if index < 0 or index + 1 >= len(self._ordered_leaders):
            return None
        start, end = self._ordered_leaders[index:index + 2]
        if self.lookup(start) is None:
            return None
        return start, end

    def lookup(self, address: int) -> ix.Instruction | None:
        if not self._finished:
            raise ValueError('finish the linear scan before successor lookup')
        index = bisect_right(self._starts, address) - 1
        if index < 0:
            return None
        start, end, offset, bitmap = self._section[index]
        if not start <= address < end:
            return None
        relative = address - start
        if not bitmap[relative >> 3] & (1 << (relative & 7)):
            return None
        self.elf.stream.seek(offset + relative)
        ins = ix.Decoder(64, self.elf.stream.read(min(15, end - address)), ip=address).decode()
        return None if ins.is_invalid else ins

    def _read_table(self, address: int, count: int) -> bytes | None:
        index = bisect_right(self._read_starts, address) - 1
        if index < 0:
            return None
        start, end, offset = self._readable[index]
        if address + count > end:
            return None
        self.elf.stream.seek(offset + address - start)
        data = self.elf.stream.read(count)
        return data if len(data) == count else None

    def feed(self, ins: ix.Instruction) -> None:
        if self._finished:
            raise ValueError('cannot feed after finish')
        if self._current is None or not self._current[0] <= ins.ip < self._current[1]:
            index = bisect_right(self._starts, ins.ip) - 1
            self._current = self._section[index] if index >= 0 else None
        if self._current is None or not self._current[0] <= ins.ip < self._current[1]:
            raise ValueError('decoded instruction is outside executable sections')
        relative = ins.ip - self._current[0]
        self._current[3][relative >> 3] |= 1 << (relative & 7)
        if ins.ip != self._last:
            self.window.clear()
        control = ins.flow_control != ix.FlowControl.NEXT or ins.is_invalid
        if self._pending_leader is not None and (not control or ins.ip != self._last):
            self._leaders.add(self._pending_leader)
            self._leaders_dirty = True
        self._last = ins.next_ip
        self.window.append(ins)
        self._pending_leader = ins.next_ip if control else None
        if control:
            if ins.op_count and ins.op0_kind in (
                    ix.OpKind.NEAR_BRANCH16, ix.OpKind.NEAR_BRANCH32,
                    ix.OpKind.NEAR_BRANCH64):
                self._leaders.add(ins.near_branch_target)
            self._leaders_dirty = True
        if (ins.flow_control == ix.FlowControl.INDIRECT_BRANCH
                and ins.mnemonic == ix.Mnemonic.JMP
                and ins.op0_kind == ix.OpKind.REGISTER):
            self._recover_relative_table()

    def _writes(self, ins: ix.Instruction, register: ix.Register_) -> bool:
        for use in self._factory.info(ins).used_registers():
            if (ix.RegisterExt.full_register(use.register) == register
                    and use.access in (ix.OpAccess.WRITE, ix.OpAccess.COND_WRITE,
                                       ix.OpAccess.READ_WRITE, ix.OpAccess.READ_COND_WRITE)):
                return True
        return False

    def _recover_relative_table(self) -> None:
        window = list(self.window)
        if len(window) < 6:
            return
        load, add, jump = window[-3:]
        dest = jump.op0_register
        if not (ix.RegisterExt.is_gpr64(dest)
                and add.mnemonic == ix.Mnemonic.ADD
                and add.op0_kind == add.op1_kind == ix.OpKind.REGISTER
                and add.op0_register == dest and ix.RegisterExt.is_gpr64(add.op1_register)
                and load.mnemonic == ix.Mnemonic.MOVSXD
                and load.op0_kind == ix.OpKind.REGISTER and load.op0_register == dest
                and load.op1_kind == ix.OpKind.MEMORY and load.memory_index_scale == 4
                and load.memory_displacement == 0
                and load.memory_base == add.op1_register
                and ix.RegisterExt.is_gpr64(load.memory_index)
                and load.memory_base != dest and not load.segment_prefix):
            return
        self._candidate_count += 1
        base, index = load.memory_base, load.memory_index
        prefix = window[:-3]
        lea_index: int | None = None
        for j in range(len(prefix) - 1, -1, -1):
            ins = prefix[j]
            if self._writes(ins, base):
                if (ins.mnemonic == ix.Mnemonic.LEA and ins.op0_register == base
                        and ins.is_ip_rel_memory_operand and ins.memory_base == ix.Register.RIP):
                    lea_index = j
                break
        if lea_index is None:
            return
        table = prefix[lea_index].ip_rel_memory_address
        guard: tuple[ix.Instruction, ix.Instruction, int] | None = None
        for j in range(len(prefix) - 2, -1, -1):
            cmp_ins, branch = prefix[j:j + 2]
            if not (cmp_ins.mnemonic == ix.Mnemonic.CMP
                    and cmp_ins.op0_kind == ix.OpKind.REGISTER
                    and ix.RegisterExt.full_register(cmp_ins.op0_register) == index
                    and cmp_ins.op1_kind in (ix.OpKind.IMMEDIATE8TO32, ix.OpKind.IMMEDIATE32,
                                            ix.OpKind.IMMEDIATE8TO64, ix.OpKind.IMMEDIATE32TO64)
                    and branch.mnemonic in (ix.Mnemonic.JA, ix.Mnemonic.JAE)):
                continue
            count = cmp_ins.immediate(1) + (branch.mnemonic == ix.Mnemonic.JA)
            if not 0 < count <= self.max_table_entries:
                continue
            between = prefix[j + 2:]
            if any(self._writes(ins, index) or ins.flow_control != ix.FlowControl.NEXT
                   for ins in between):
                continue
            # The out-of-range path must leave this dispatch sequence.
            if cmp_ins.ip <= branch.near_branch_target <= jump.ip:
                continue
            guard = (cmp_ins, branch, count)
            break
        if guard is None:
            return
        cmp_ins, branch, count = guard
        raw = self._read_table(table, count * 4)
        if raw is None:
            return
        targets = [table + value for (value,) in iter_ints('<i', raw)]
        if not all(self.is_code(target) for target in targets):
            return
        key = (table, count, jump.ip)
        if key in self._table_keys:
            return
        self._table_keys.add(key)
        self.targets.update(targets)
        self._leaders_dirty = True
        self.tables.append({'table': table, 'entries': count, 'entry_size': 4,
                            'dispatch': jump.ip, 'guard': cmp_ins.ip,
                            'default': branch.near_branch_target,
                            'targets': sorted(set(targets))})

    def finish(self) -> CFGReport:
        if self._pending_leader is not None:
            self._leaders.add(self._pending_leader)
            self._leaders_dirty = True
            self._pending_leader = None
        self._index_functions()
        self._index_leaders()
        self._finished = True
        return {'function_ranges': len(self.functions),
                'function_sources': dict(Counter(item[3] for item in self.functions)),
                'relative_table_candidates': self._candidate_count,
                'relative_tables': self.tables,
                'instruction_boundary_bytes': sum(len(item[3]) for item in self._section),
                'block_leaders': len(self._ordered_leaders),
                'indirect_recovery_complete': False}
