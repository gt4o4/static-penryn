from collections.abc import Iterator
from typing import Protocol

from elftools.elf.sections import Section

# pyelftools' entries are construct Containers; no DynamicEntry class exists.
class DynamicEntry(Protocol):
    @property
    def d_tag(self) -> str | int: ...
    @property
    def d_val(self) -> int: ...

class DynamicTag:
    entry: DynamicEntry

class DynamicSection(Section):
    def iter_tags(self, type: str | None = None) -> Iterator[DynamicTag]: ...
