"""The Go metadata helper's report (go_metadata.go), checked when loaded."""
from typing import NotRequired, TypedDict

from .checked import as_int, as_list, as_object, as_str, load_json, member


class GoFunction(TypedDict):
    start: int
    end: int
    name: str
    metadata_address: int


class GoTable(TypedDict):
    address: int
    text: int
    text_source: str
    module_address: NotRequired[int]
    functions: list[GoFunction]


class GoMetadata(TypedDict):
    parser: str
    tables: list[GoTable]
    rejected_candidates: list[str]
    go_build_version: NotRequired[str]


def _function(value: object) -> GoFunction:
    what = 'Go metadata function'
    obj = as_object(value, what)
    return GoFunction(start=as_int(member(obj, 'start', what), what),
                      end=as_int(member(obj, 'end', what), what),
                      name=as_str(member(obj, 'name', what), what),
                      metadata_address=as_int(member(obj, 'metadata_address', what), what))


def _table(value: object) -> GoTable:
    what = 'Go metadata table'
    obj = as_object(value, what)
    table = GoTable(address=as_int(member(obj, 'address', what), what),
                    text=as_int(member(obj, 'text', what), what),
                    text_source=as_str(member(obj, 'text_source', what), what),
                    functions=[_function(f) for f in as_list(member(obj, 'functions', what), what)])
    if 'module_address' in obj:
        table['module_address'] = as_int(obj['module_address'], what)
    return table


def parse(raw: str | bytes) -> GoMetadata:
    """Return the helper's report; any other shape is a ValueError."""
    what = 'invalid Go metadata helper report'
    obj = as_object(load_json(raw), what)
    tables = as_list(member(obj, 'tables', what), what)
    rejected = as_list(member(obj, 'rejected_candidates', what), what)
    metadata = GoMetadata(parser=as_str(member(obj, 'parser', what), what),
                          tables=[_table(t) for t in tables],
                          rejected_candidates=[as_str(r, what) for r in rejected])
    if 'go_build_version' in obj:
        metadata['go_build_version'] = as_str(obj['go_build_version'], what)
    return metadata
