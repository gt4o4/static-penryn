from collections.abc import Mapping
from typing import Literal, overload


_SegmentInt = Literal[
    'p_offset', 'p_vaddr', 'p_paddr', 'p_filesz', 'p_memsz', 'p_flags', 'p_align',
]

class Segment:
    header: Mapping[str, int | str]
    @overload
    def __getitem__(self, name: _SegmentInt) -> int: ...
    @overload
    def __getitem__(self, name: Literal['p_type']) -> str | int: ...

class InterpSegment(Segment):
    def get_interp_name(self) -> str: ...
