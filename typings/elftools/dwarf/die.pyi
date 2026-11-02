# value depends on the attribute form (ints, bytes, lists for block
# forms), so callers narrow them.
from collections.abc import Iterator
from typing import NamedTuple

class AttributeValue(NamedTuple):
    name: str | int
    form: str
    value: object
    offset: int

class DIE:
    tag: str | int | None
    attributes: dict[str | int, AttributeValue]
    def iter_children(self) -> Iterator[DIE]: ...
