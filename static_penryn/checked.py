"""Typed boundaries for values whose types Python cannot see.

Decoded JSON, struct records and iced's constant tables reach the rest of the
package only through these checks: callers get the declared type or a
ValueError, never Any.
"""
from collections.abc import Buffer, Iterator
import json
import re
import struct
from typing import TypeIs, cast


def is_object(value: object) -> TypeIs[dict[str, object]]:
    if not isinstance(value, dict):
        return False
    return all(isinstance(key, str) for key in value)


def is_list(value: object) -> TypeIs[list[object]]:
    return isinstance(value, list)


def load_json(text: str | bytes) -> object:
    value: object = json.loads(text)
    return value


def as_object(value: object, what: str) -> dict[str, object]:
    if not is_object(value):
        raise ValueError(f'{what} is not a JSON object')
    return value


def as_list(value: object, what: str) -> list[object]:
    if not is_list(value):
        raise ValueError(f'{what} is not a JSON array')
    return value


def as_int(value: object, what: str) -> int:
    # JSON true/false decode to bool, an int subclass, but are not numbers.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f'{what} is not an integer')
    return value


def as_str(value: object, what: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f'{what} is not a string')
    return value


def member(obj: dict[str, object], key: str, what: str) -> object:
    if key not in obj:
        raise ValueError(f'{what} lacks {key!r}')
    return obj[key]


def required[T](value: T | None, what: str) -> T:
    """VALUE, which an earlier check or option guarantees; None is a ValueError."""
    if value is None:
        raise ValueError(f'{what} is unexpectedly missing')
    return value


# Integer-only struct formats: byte order, then counted integer, bool or pad
# codes. struct returns exactly one int per non-pad code for such a format.
_INT_FORMAT = re.compile(r'[@=<>!]?(?:[0-9]*[xbBhHiIlLqQnNP?])+')


def _int_format(fmt: str) -> str:
    if not _INT_FORMAT.fullmatch(fmt):
        raise ValueError(f'struct format {fmt!r} has non-integer fields')
    return fmt


def unpack_ints(fmt: str, data: Buffer, offset: int = 0) -> tuple[int, ...]:
    """struct.unpack_from for an integer-only format, typed."""
    return cast(tuple[int, ...], struct.unpack_from(_int_format(fmt), data, offset))


def iter_ints(fmt: str, data: Buffer) -> Iterator[tuple[int, ...]]:
    """struct.iter_unpack for an integer-only format, typed."""
    return cast(Iterator[tuple[int, ...]], struct.iter_unpack(_int_format(fmt), data))


def constants(namespace: object) -> dict[str, int]:
    """Name -> value of an iced constant module such as Register or Mnemonic.

    iced binds these as plain ints at runtime, which vars() cannot type.
    """
    items: dict[str, object] = vars(namespace)
    return {name: value for name, value in items.items()
            if not name.startswith('_') and isinstance(value, int)}
