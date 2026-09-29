"""Bounded native-frame inference using decoded CALL entries and whole CFGs.

This is inferred evidence under the ordinary SysV calling convention, never
compiler-authored CFI. No byte-pattern prologue search supplies an entry. Every
reachable predecessor participates in a finite dataflow fixed point; unknown
edges, incompatible stack depths, pivots and known interior entries fail shut.
The usual ABI assumption that unrelated memory stores do not overwrite saved
caller state is explicit. Arbitrary undiscovered indirect entries cannot be
excluded by static disassembly and are not claimed to have been excluded.
"""
from array import array
from bisect import bisect_left, bisect_right
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass

import iced_x86 as ix
from elftools.dwarf.callframe import CFARule, RegisterRule
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection


DWARF = {ix.Register.RAX: 0, ix.Register.RDX: 1, ix.Register.RCX: 2,
         ix.Register.RBX: 3, ix.Register.RSI: 4, ix.Register.RDI: 5,
         ix.Register.RBP: 6, ix.Register.RSP: 7,
         **{getattr(ix.Register, f'R{n}'): n for n in range(8, 16)}}
CALLEE = frozenset((3, 6, 12, 13, 14, 15))
WRITES = {ix.OpAccess.WRITE, ix.OpAccess.COND_WRITE,
          ix.OpAccess.READ_WRITE, ix.OpAccess.READ_COND_WRITE}
BRANCHES = {ix.FlowControl.CONDITIONAL_BRANCH, ix.FlowControl.UNCONDITIONAL_BRANCH}
NEAR = {ix.OpKind.NEAR_BRANCH16, ix.OpKind.NEAR_BRANCH32, ix.OpKind.NEAR_BRANCH64}


class Gap(ValueError):
    """Inference could not establish one unambiguous native frame."""


def signed(value):
    return value - (1 << 64) if value & (1 << 63) else value


@dataclass(frozen=True)
class State:
    # All offsets refer to entry RSP, whose return address occupies offset 0.
    sp: int = 0
    values: tuple = tuple(r if r in CALLEE else None for r in range(16))
    anchors: tuple = (None,) * 16
    slots: tuple = ((0, 16),)
    constants: tuple = (None,) * 16

    def join(self, other):
        if self.sp != other.sp:
            raise Gap('predecessors disagree about stack depth')
        values = tuple(a if a == b else None for a, b in zip(self.values, other.values))
        anchors = tuple(a if a == b else None for a, b in zip(self.anchors, other.anchors))
        other_slots = dict(other.slots)
        slots = tuple((offset, value) for offset, value in self.slots
                      if other_slots.get(offset) == value)
        constants = tuple(a | b if a is not None and b is not None and len(a | b) <= 8 else None
                          for a, b in zip(self.constants, other.constants))
        return State(self.sp, values, anchors, slots, constants)

    def row(self, pc):
        if dict(self.slots).get(0) != 16:
            raise Gap('entry return address is no longer recoverable')
        cfa = (CFARule(6, 8 - self.anchors[6]) if self.anchors[6] is not None
               else CFARule(7, 8 - self.sp))
        row = {'pc': pc, 'cfa': cfa, 16: RegisterRule('OFFSET', -8)}
        for register in CALLEE:
            if self.values[register] == register:
                row[register] = RegisterRule('SAME_VALUE')
                continue
            slots = [offset for offset, value in self.slots if value == register]
            if slots:
                row[register] = RegisterRule('OFFSET', slots[-1] - 8)
            elif register in self.values:
                row[register] = RegisterRule('REGISTER', self.values.index(register))
            else:
                raise Gap(f'callee-saved DWARF register {register} has no recoverable incoming value')
        return row

    def balanced(self):
        return (self.sp == 0 and dict(self.slots).get(0) == 16
                and all(self.values[r] == r for r in CALLEE))


def step(state, ins, info):
    """Transfer stack and saved-register facts; arithmetic remains opaque."""
    if ins.is_invalid or ins.is_privileged:
        raise Gap('invalid or privileged instruction in native function')
    values, anchors, slots = list(state.values), list(state.anchors), dict(state.slots)
    constants = list(state.constants)
    sp = state.sp

    def address(base, index=ix.Register.NONE, displacement=0):
        reg = DWARF.get(base)
        full = DWARF.get(ix.RegisterExt.full_register(base))
        if reg is None and full is not None and (full == 7 or state.anchors[full] is not None):
            raise Gap('truncated address of an inferred stack anchor')
        anchor = state.sp if reg == 7 else state.anchors[reg] if reg is not None else None
        if anchor is not None and index != ix.Register.NONE:
            raise Gap('indexed access to an inferred stack anchor')
        return None if anchor is None else anchor + signed(displacement)

    def store(offset, size, value=None):
        if not size:
            raise Gap('unknown-size write to an inferred stack anchor')
        for saved in list(slots):
            if saved < offset + size and saved + 8 > offset:
                del slots[saved]
        if size == 8 and value is not None:
            slots[offset] = value

    if ins.flow_control in (ix.FlowControl.CALL, ix.FlowControl.INDIRECT_CALL):
        if ins.code not in (ix.Code.CALL_REL32_64, ix.Code.CALL_RM64):
            raise Gap('non-near native call does not establish a SysV frame')
        # A normal ABI call returns with the same RSP and callee-saved values.
        # Red-zone saves are not preserved across its pushed return address.
        slots = {offset: value for offset, value in slots.items() if offset >= sp}
        for r in range(16):
            if r not in CALLEE and r != 7:
                values[r] = anchors[r] = None
                constants[r] = None
        return State(sp, tuple(values), tuple(anchors), tuple(sorted(slots.items())), tuple(constants))

    if ins.mnemonic in (ix.Mnemonic.PUSH, ix.Mnemonic.PUSHFQ):
        if ins.stack_pointer_increment != -8:
            raise Gap('non-qword native push')
        sp -= 8
        if sp < -(1 << 20):
            raise Gap('native stack depth exceeds the bounded ABI model')
        source = DWARF.get(ins.op0_register) if ins.op_count else None
        store(sp, 8, state.values[source] if source is not None else None)
        return State(sp, tuple(values), tuple(anchors), tuple(sorted(slots.items())), tuple(constants))
    if ins.mnemonic in (ix.Mnemonic.POP, ix.Mnemonic.POPFQ, ix.Mnemonic.LEAVE):
        if ins.mnemonic == ix.Mnemonic.LEAVE:
            if ins.code != ix.Code.LEAVEQ or state.anchors[6] is None:
                raise Gap('LEAVE has no established frame anchor')
            sp, destination = state.anchors[6], 6
        elif ins.mnemonic == ix.Mnemonic.POPFQ:
            destination = None
        else:
            destination = DWARF.get(ins.op0_register)
            if destination is None or destination == 7 or ins.stack_pointer_increment != 8:
                raise Gap('non-qword/register pop or POP RSP')
        if destination is not None:
            values[destination], anchors[destination] = slots.get(sp), None
            constants[destination] = None
        sp += 8
        if not -(1 << 20) <= sp <= 0:
            raise Gap('native stack depth exceeds the bounded ABI model')
        slots = {offset: value for offset, value in slots.items() if offset >= sp}
        return State(sp, tuple(values), tuple(anchors), tuple(sorted(slots.items())), tuple(constants))

    changed_sp = False
    writes_sp = any(ix.RegisterExt.full_register(used.register) == ix.Register.RSP
                    and used.access in WRITES for used in info.used_registers())
    if (writes_sp and ins.op_count and ins.op0_kind == ix.OpKind.REGISTER
            and ins.op0_register == ix.Register.RSP):
        changed_sp = True
        if (ins.mnemonic in (ix.Mnemonic.ADD, ix.Mnemonic.SUB)
                and ins.op1_kind in (ix.OpKind.IMMEDIATE8TO64, ix.OpKind.IMMEDIATE32TO64)):
            amount = signed(ins.immediate(1))
            sp += amount if ins.mnemonic == ix.Mnemonic.ADD else -amount
        elif (ins.mnemonic == ix.Mnemonic.MOV and ins.op1_kind == ix.OpKind.REGISTER
              and ins.op1_register in DWARF and state.anchors[DWARF[ins.op1_register]] is not None):
            sp = state.anchors[DWARF[ins.op1_register]]
        elif ins.mnemonic == ix.Mnemonic.LEA:
            new_sp = address(ins.memory_base, ins.memory_index, ins.memory_displacement)
            if new_sp is None:
                raise Gap('untracked LEA stack pivot')
            sp = new_sp
        else:
            raise Gap('dynamic alignment or untracked stack pivot')
        if not -(1 << 20) <= sp <= 0:
            raise Gap('native stack depth exceeds the bounded ABI model')
        if sp > state.sp:
            slots = {offset: value for offset, value in slots.items() if offset >= sp}

    for used in info.used_registers():
        register = DWARF.get(ix.RegisterExt.full_register(used.register))
        if register is not None and used.access in WRITES:
            if register == 7:
                if not changed_sp:
                    raise Gap('untracked implicit/partial RSP write')
            else:
                values[register] = anchors[register] = None
                constants[register] = None
    if ins.mnemonic == ix.Mnemonic.MOV and ins.op0_kind == ix.OpKind.REGISTER:
        destination = DWARF.get(ins.op0_register)
        if destination is not None and destination != 7:
            if ins.op1_kind == ix.OpKind.REGISTER and ins.op1_register in DWARF:
                source = DWARF[ins.op1_register]
                values[destination] = state.values[source]
                anchors[destination] = state.sp if source == 7 else state.anchors[source]
            elif ins.op1_kind == ix.OpKind.MEMORY and ix.MemorySizeExt.size(ins.memory_size) == 8:
                offset = address(ins.memory_base, ins.memory_index, ins.memory_displacement)
                if offset is not None:
                    if ins.segment_prefix in (ix.Register.FS, ix.Register.GS):
                        raise Gap('segmented load through an inferred stack anchor')
                    values[destination] = dict(state.slots).get(offset)
    elif ins.mnemonic == ix.Mnemonic.LEA and ins.op0_register in DWARF:
        destination = DWARF[ins.op0_register]
        if destination != 7:
            anchors[destination] = address(ins.memory_base, ins.memory_index, ins.memory_displacement)

    if ins.op_count and ins.op0_kind == ix.OpKind.REGISTER:
        destination = DWARF.get(ix.RegisterExt.full_register(ins.op0_register))
        width = ix.RegisterExt.size(ins.op0_register)
        if destination is not None and destination != 7 and width in (4, 8):
            if ins.mnemonic == ix.Mnemonic.MOV:
                if ins.op1_kind in (ix.OpKind.IMMEDIATE32, ix.OpKind.IMMEDIATE64,
                                    ix.OpKind.IMMEDIATE32TO64):
                    constants[destination] = frozenset((ins.immediate(1),))
                elif ins.op1_kind == ix.OpKind.REGISTER:
                    source = DWARF.get(ix.RegisterExt.full_register(ins.op1_register))
                    if source is not None and state.constants[source] is not None:
                        mask = (1 << (width * 8)) - 1
                        constants[destination] = frozenset(value & mask for value in state.constants[source])
            elif ins.mnemonic == ix.Mnemonic.LEA and ins.is_ip_rel_memory_operand:
                constants[destination] = frozenset((ins.ip_rel_memory_address & ((1 << (width * 8)) - 1),))

    for memory in info.used_memory():
        if memory.access not in WRITES:
            continue
        offset = address(memory.base, memory.index, memory.displacement)
        if offset is not None:
            if memory.segment in (ix.Register.FS, ix.Register.GS):
                raise Gap('segmented write through an inferred stack anchor')
            if ins.has_rep_prefix or ins.has_repne_prefix:
                raise Gap('repeated write through an inferred stack anchor')
            size = ix.MemorySizeExt.size(memory.memory_size)
            source = DWARF.get(ins.op1_register) if ins.op_count > 1 else None
            value = (state.values[source] if ins.mnemonic == ix.Mnemonic.MOV
                     and ins.op1_kind == ix.OpKind.REGISTER and source is not None else None)
            store(offset, size, value)
    return State(sp, tuple(values), tuple(anchors), tuple(sorted(slots.items())), tuple(constants))


class Recovery:
    """Feed once with the existing decoder, finish, then query inferred rows.

    A direct CALL is entry evidence, not proof that undiscovered indirect
    entries do not exist. Reports keep that distinction explicit. Successful
    analyses and gaps are cached, with a bounded LRU of compact per-PC states.
    """
    def __init__(self, elf, recovery, *, max_instructions=8192, max_bytes=65536,
                 max_cache=128):
        self.elf, self.decoded = elf, recovery
        self.max_instructions, self.max_bytes, self.max_cache = max_instructions, max_bytes, max_cache
        self.entries, self.sizes = {}, {}
        self._targets, self._sources = array('Q'), array('Q')
        self._incoming, self._low, self._high = array('Q'), array('Q'), array('Q')
        self._starts, self._address_taken = [], []
        self._pending_loads, self._last_ip = {}, None
        self._slot_calls, self._slot_writers = {}, {}
        self._write_addresses, self._write_pcs, self._write_sizes = array('Q'), array('Q'), array('I')
        self.dispatchers = []
        self._relocations = []
        self._finished = False
        self.cache, self.decisions = OrderedDict(), {}
        self.factory = ix.InstructionInfoFactory()
        for section in elf.iter_sections():
            if isinstance(section, RelocationSection):
                self._relocations.extend(rel['r_offset'] for rel in section.iter_relocations())
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    if symbol['st_info']['type'] == 'STT_FUNC' and symbol['st_value']:
                        start = symbol['st_value']
                        self.entries.setdefault(start, set()).add('symbol')
                        if symbol['st_size']:
                            self.sizes[start] = min(self.sizes.get(start, 1 << 64), symbol['st_size'])
        self._relocations.sort()

    def feed(self, ins):
        if self._finished:
            raise ValueError('native-frame scan already finished')
        if self._last_ip != ins.ip:
            self._pending_loads.clear()
        self._last_ip = ins.next_ip
        if ins.op_count and ins.op0_kind in NEAR:
            if ins.flow_control == ix.FlowControl.CALL:
                self.entries.setdefault(ins.near_branch_target, set()).add('direct-call')
            elif ins.flow_control in BRANCHES:
                self._targets.append(ins.near_branch_target)
                self._sources.append(ins.ip)

        # A short, uninterrupted load->CALL use establishes a function-pointer
        # slot. Merely taking a code address or finding pointer-shaped data does
        # not establish a function entry. Full CFG validation follows in finish.
        slot = self._static_memory(ins)
        if ins.flow_control == ix.FlowControl.INDIRECT_CALL and ins.code == ix.Code.CALL_RM64:
            call_slot = (self._pending_loads.get(ins.op0_register, (None, 0))[0]
                         if ins.op0_kind == ix.OpKind.REGISTER else slot)
            if call_slot is not None:
                self._slot_calls.setdefault(call_slot, set()).add(ins.ip)
        if self._pending_loads or slot is not None:
            info = self.factory.info(ins)
            for used in info.used_registers():
                if used.access in WRITES:
                    self._pending_loads.pop(ix.RegisterExt.full_register(used.register), None)
            self._pending_loads = {reg: (value, remaining - 1)
                                   for reg, (value, remaining) in self._pending_loads.items()
                                   if remaining > 1}
            if slot is not None:
                for memory in info.used_memory():
                    if memory.access in WRITES:
                        self._write_addresses.append(slot)
                        self._write_pcs.append(ins.ip)
                        self._write_sizes.append(ix.MemorySizeExt.size(memory.memory_size) or (1 << 20))
                if (ins.mnemonic == ix.Mnemonic.MOV and ins.op0_kind == ix.OpKind.REGISTER
                        and ins.op0_register in DWARF and ins.op1_kind == ix.OpKind.MEMORY
                        and ix.MemorySizeExt.size(ins.memory_size) == 8):
                    self._pending_loads[ins.op0_register] = (slot, 8)
        if ins.flow_control != ix.FlowControl.NEXT:
            self._pending_loads.clear()

    @staticmethod
    def _static_memory(ins):
        if ins.segment_prefix in (ix.Register.FS, ix.Register.GS):
            return None
        if ins.is_ip_rel_memory_operand:
            return ins.ip_rel_memory_address
        if ((ins.op_count and ins.op0_kind == ix.OpKind.MEMORY
             or ins.op_count > 1 and ins.op1_kind == ix.OpKind.MEMORY)
                and ins.memory_base == ix.Register.NONE and ins.memory_index == ix.Register.NONE):
            return ins.memory_displacement
        return None

    def finish(self, *, address_taken=()):
        if self._finished:
            return
        self.entries = {pc: sources for pc, sources in self.entries.items()
                        if self.decoded.lookup(pc) is not None}
        self._starts = sorted(self.entries)
        self._address_taken = sorted(set(address_taken))
        for index in sorted(range(len(self._targets)), key=self._targets.__getitem__):
            target, source = self._targets[index], self._sources[index]
            if self._incoming and self._incoming[-1] == target:
                self._low[-1], self._high[-1] = min(self._low[-1], source), max(self._high[-1], source)
            else:
                self._incoming.append(target)
                self._low.append(source)
                self._high.append(source)
        self._targets, self._sources = array('Q'), array('Q')
        slots = sorted(self._slot_calls)
        self._slot_writers = {slot: set() for slot in slots}
        for address, pc, size in zip(self._write_addresses, self._write_pcs, self._write_sizes):
            index = bisect_left(slots, max(0, address - 7))
            while index < len(slots) and slots[index] < address + size:
                self._slot_writers[slots[index]].add(pc)
                index += 1
        self._write_addresses, self._write_pcs, self._write_sizes = array('Q'), array('Q'), array('I')
        self._discover_dispatchers()
        self._finished = True

    def _bounds(self, start):
        index = bisect_right(self._starts, start)
        section_end = next((sec['sh_addr'] + sec['sh_size'] for sec in self.elf.iter_sections()
                            if sec['sh_flags'] & 4 and sec['sh_addr'] <= start < sec['sh_addr'] + sec['sh_size']), start)
        return min(section_end, start + self.max_bytes,
                   self._starts[index] if index < len(self._starts) else section_end,
                   start + self.sizes.get(start, self.max_bytes))

    def _slot_initializer(self, slot):
        # ET_DYN relocation semantics are deliberately outside this narrow
        # non-PIE dispatcher proof. Never infer a runtime value from a RELA
        # destination's unrelated pre-relocation bytes.
        if self.elf['e_type'] != 'ET_EXEC':
            raise Gap('indirect-call initializer requires a non-PIE native image')
        relocation = bisect_left(self._relocations, max(0, slot - 7))
        if relocation < len(self._relocations) and self._relocations[relocation] < slot + 8:
            raise Gap('indirect-call slot has loader relocation semantics')
        for segment in self.elf.iter_segments():
            if (segment['p_type'] == 'PT_LOAD' and segment['p_vaddr'] <= slot
                    and slot + 8 <= segment['p_vaddr'] + segment['p_filesz']):
                self.elf.stream.seek(segment['p_offset'] + slot - segment['p_vaddr'])
                return int.from_bytes(self.elf.stream.read(8), 'little')
        raise Gap('indirect-call slot has no file-backed initializer')

    def _discover_dispatchers(self):
        # At most 256 indirect slots receive whole-function discovery. Ordinary
        # direct/symbol inference is unaffected when this optional budget fills.
        attempts = 0
        for slot in sorted(self._slot_calls):
            evidence = {'slot': slot, 'call_sites': sorted(self._slot_calls[slot]),
                        'source': 'verified-indirect-call-slot', 'accepted': False}
            start, previous = None, None
            try:
                start = self._slot_initializer(slot)
                evidence['entry'] = start
                if self.decoded.lookup(start) is None:
                    raise Gap('indirect-call initializer is not a verified code boundary')
                if attempts >= 256:
                    raise Gap('indirect-call dispatcher discovery budget exceeded')
                attempts += 1
                previous = self.entries.get(start)
                self.entries[start] = set(previous or ()) | {'indirect-call-slot-initializer'}
                self._starts = sorted(self.entries)
                proof = {}
                analysis = self._analyze(start, self._bounds(start), proof=proof)
                addresses, ids, states = analysis
                tails = proof['tail_targets']
                for pc in self._slot_writers[slot]:
                    pos = bisect_left(addresses, pc)
                    if pos == len(addresses) or addresses[pos] != pc:
                        raise Gap('indirect-call slot is written outside its proven dispatcher')
                    ins = self.decoded.lookup(pc)
                    source = DWARF.get(ins.op1_register) if ins.op_count > 1 else None
                    constants = states[ids[pos]].constants[source] if source is not None else None
                    if (ins.mnemonic != ix.Mnemonic.MOV or ins.op0_kind != ix.OpKind.MEMORY
                            or ins.op1_kind != ix.OpKind.REGISTER or self._static_memory(ins) != slot
                            or ix.MemorySizeExt.size(ins.memory_size) != 8
                            or constants is None or not constants <= tails):
                        raise Gap('indirect-call slot store has no verified ABI tail target')
                for target in tails:
                    self.entries.setdefault(target, set()).add('verified-dispatch-tail')
                evidence.update(accepted=True, tail_targets=sorted(tails),
                                known_writers=sorted(self._slot_writers[slot]),
                                reachable_instructions=len(addresses))
            except Gap as error:
                if start is not None and start in self.entries:
                    if previous is None:
                        self.entries.pop(start)
                    else:
                        self.entries[start] = previous
                evidence['reason'] = str(error)
            self.dispatchers.append(evidence)
            self._starts = sorted(self.entries)

    def _analyze(self, start, end, *, proof=None):
        incoming, queue = {start: State()}, deque([start])
        visits, exits = 0, 0
        while queue:
            pc = queue.popleft()
            state = incoming[pc]
            visits += 1
            if visits > self.max_instructions * 8 or len(incoming) > self.max_instructions:
                raise Gap('native CFG inference budget exceeded')
            ins = self.decoded.lookup(pc)
            if ins is None or not start <= pc < ins.next_ip <= end:
                raise Gap('CFG reaches an unknown boundary or escapes its entry interval')
            edge = bisect_left(self._incoming, pc)
            if (pc != start and edge < len(self._incoming) and self._incoming[edge] == pc
                    and (self._low[edge] < start or self._high[edge] >= end)):
                raise Gap('external direct branch enters the function interior')
            pointer = bisect_left(self._address_taken, pc)
            if pc != start and pointer < len(self._address_taken) and self._address_taken[pointer] == pc:
                raise Gap('address-taken interior entry has no proven incoming frame')
            state.row(pc)  # Callee saves must remain recoverable at every PC.
            flow = ins.flow_control
            if flow == ix.FlowControl.RETURN:
                if ins.mnemonic != ix.Mnemonic.RET or ins.op_count or not state.balanced():
                    raise Gap('return lacks a balanced SysV frame')
                exits += 1
                continue
            if flow == ix.FlowControl.INDIRECT_BRANCH:
                register = DWARF.get(ins.op0_register) if ins.op0_kind == ix.OpKind.REGISTER else None
                constants = state.constants[register] if register is not None else None
                if (not constants or not state.balanced()
                        or any(self.decoded.lookup(target) is None for target in constants)
                        or (proof is None and any(target not in self.entries for target in constants))):
                    raise Gap('indirect tail lacks constant targets and a restored ABI frame')
                exits += 1
                continue
            if flow in (ix.FlowControl.INTERRUPT,
                        ix.FlowControl.EXCEPTION, ix.FlowControl.XBEGIN_XABORT_XEND):
                raise Gap('unknown indirect, interrupt, or exceptional CFG edge')
            after = step(state, ins, self.factory.info(ins))
            successors = []
            if flow in BRANCHES:
                if ins.op0_kind not in NEAR:
                    raise Gap('non-near control transfer')
                target = ins.near_branch_target
                if start <= target < end:
                    successors.append(target)
                elif target in self.entries and after.balanced():
                    exits += 1  # A balanced ordinary ABI tail call.
                else:
                    raise Gap('branch escapes to an unproved native frame')
                if flow == ix.FlowControl.CONDITIONAL_BRANCH:
                    successors.append(ins.next_ip)
            elif flow in (ix.FlowControl.NEXT, ix.FlowControl.CALL, ix.FlowControl.INDIRECT_CALL):
                successors.append(ins.next_ip)
            else:
                raise Gap('unsupported native control flow')
            for target in successors:
                if not start <= target < end:
                    raise Gap('fall-through crosses a different native entry')
                combined = incoming[target].join(after) if target in incoming else after
                if target not in incoming or combined != incoming[target]:
                    incoming[target] = combined
                    queue.append(target)
        if not exits:
            raise Gap('function has no proven balanced return or tail exit')
        # Revalidate all final states after the predecessor fixed point.
        for pc, state in incoming.items():
            state.row(pc)
        if proof is not None:
            proof['tail_targets'] = frozenset(target for pc, state in incoming.items()
                if self.decoded.lookup(pc).flow_control == ix.FlowControl.INDIRECT_BRANCH
                for target in state.constants[DWARF[self.decoded.lookup(pc).op0_register]])
        addresses = array('Q', sorted(incoming))
        unique, ids, numbers = [], array('I'), {}
        for pc in addresses:
            state = incoming[pc]
            if state not in numbers:
                numbers[state] = len(unique)
                unique.append(state)
            ids.append(numbers[state])
        return addresses, ids, unique

    def row(self, pc):
        if not self._finished:
            raise ValueError('finish native-frame scan before querying rows')
        evidence = {'original_pc': pc, 'source': 'inferred-native-cfg',
                    'compiler_authored': False, 'unknown_indirect_entries_excluded': False,
                    'assumptions': ['ordinary SysV CALL/return and callee-save convention',
                                    'unrelated memory stores do not overwrite saved caller state',
                                    'indirect-call slots are not modified through undiscovered aliases']}
        try:
            index = bisect_right(self._starts, pc) - 1
            if index < 0:
                raise Gap('no trusted symbol or decoded CALL entry precedes this PC')
            start = self._starts[index]
            end = self._bounds(start)
            evidence.update(entry=start, entry_sources=sorted(self.entries[start]), interval_end=end)
            if not start <= pc < end:
                raise Gap('PC is outside the bounded trusted-entry interval')
            if start not in self.cache:
                try:
                    self.cache[start] = self._analyze(start, end)
                except Gap as error:
                    self.cache[start] = str(error)
                if len(self.cache) > self.max_cache:
                    self.cache.popitem(last=False)
            self.cache.move_to_end(start)
            analysis = self.cache[start]
            if isinstance(analysis, str):
                raise Gap(analysis)
            addresses, ids, states = analysis
            position = bisect_left(addresses, pc)
            if position == len(addresses) or addresses[position] != pc:
                raise Gap('PC is not reachable from its trusted entry')
            row = states[ids[position]].row(pc)
            evidence.update(accepted=True, reachable_instructions=len(addresses),
                            cfa_register=row['cfa'].reg, cfa_offset=row['cfa'].offset)
            self.decisions[pc] = evidence
            return row
        except Gap as error:
            self.decisions[pc] = {**evidence, 'accepted': False, 'reason': str(error)}
            raise

    def evidence(self, pc):
        return self.decisions.get(pc)

    def report(self):
        values = list(self.decisions.values())
        return {'accepted': sum(item['accepted'] for item in values),
                'rejected': sum(not item['accepted'] for item in values),
                'reasons': dict(Counter(item['reason'] for item in values if not item['accepted'])),
                'entries': len(self.entries), 'queries': values,
                'indirect_dispatchers': self.dispatchers,
                'indirect_slot_budget': 256,
                'indirect_slot_count': len(self._slot_calls),
                'compiler_authored': False, 'unknown_indirect_entries_excluded': False}
