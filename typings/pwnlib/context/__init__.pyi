from contextlib import AbstractContextManager

class ContextType:
    log_level: int
    def local(self, *, log_level: str = ...) -> AbstractContextManager[None]: ...

context: ContextType
