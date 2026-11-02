# Decoded rows are dicts keyed by 'pc' (int), 'cfa' (CFARule) and DWARF
# register numbers (RegisterRule); callers narrow each value they read.
from typing import IO, Literal, NamedTuple, overload

from elftools.dwarf.structs import DWARFStructs

class CFARule:
    reg: int | None
    offset: int | None
    expr: list[int] | None
    def __init__(
        self, reg: int | None = None, offset: int | None = None, expr: list[int] | None = None
    ) -> None: ...

class RegisterRule:
    type: str
    arg: int | list[int] | None
    def __init__(self, type: str, arg: int | list[int] | None = None) -> None: ...

type CFIRow = dict[str | int, int | CFARule | RegisterRule]

class DecodedCallFrameTable(NamedTuple):
    table: list[CFIRow]
    reg_order: list[int]

class CIE:
    header: dict[str, object]
    augmentation_dict: dict[str, object]
    @overload
    def __getitem__(self, name: Literal['augmentation']) -> str | bytes: ...
    @overload
    def __getitem__(self, name: Literal['return_address_register']) -> int: ...

class FDE:
    offset: int
    cie: CIE
    header: dict[str, object]
    lsda_pointer: int | None
    def __getitem__(self, name: Literal['initial_location', 'address_range']) -> int: ...
    def get_decoded(self) -> DecodedCallFrameTable: ...

class ZERO:
    offset: int

class CallFrameInfo:
    def __init__(
        self, stream: IO[bytes], size: int, address: int, base_structs: DWARFStructs,
        for_eh_frame: bool = False,
    ) -> None: ...
    def get_entries(self) -> list[CIE | FDE | ZERO]: ...
