from collections.abc import Iterator
from typing import Literal

from elftools.elf.sections import Section

class Relocation:
    def is_RELA(self) -> bool: ...
    def __getitem__(
        self, name: Literal['r_offset', 'r_info', 'r_info_sym', 'r_info_type', 'r_addend']
    ) -> int: ...

class RelocationSection(Section):
    def num_relocations(self) -> int: ...
    def iter_relocations(self) -> Iterator[Relocation]: ...
