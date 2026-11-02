from collections.abc import Iterator

from elftools.dwarf.die import DIE

class CompileUnit:
    def iter_DIEs(self) -> Iterator[DIE]: ...
