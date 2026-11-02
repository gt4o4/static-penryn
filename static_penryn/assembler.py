"""x86-64 assembly with LLVM's integrated assembler (llvmlite), no assembler program.

Every generated source is GNU-syntax assembly (Intel syntax where it says so)
that needs no C preprocessor. assemble() returns the relocatable ELF object
`cc -c` used to produce, so the callers' own ld links stay as they are.
Compared with GNU as (README's records), it gives the same code, relocations,
symbols and CFI rows; LLVM repeats each FDE's opening rules instead of
sharing them in the CIE.

llvmlite installs no LLVM diagnostic handler, so LLVM reports an invalid
source by printing the error and calling exit(). assemble() emits through a
small C shim that TinyCC's libtcc (PENRYN_LIBTCC) compiles in memory:
penryn_emit calls setjmp, then llvmlite's exported
LLVMPY_TargetMachineEmitToMemory, and penryn_on_exit, an exit handler
registered with glibc's __cxa_atexit, longjmps back while armed, so LLVM's
exit becomes a ValueError here. That is undefined behaviour by the C
standard (C11 7.22.4.4p3, and C++ [csetjmp.syn] for LLVM's skipped
destructors), chosen on 2026-11-02 at the owner's direction; never put a
Python frame between setjmp and LLVM. It relies on glibc (handlers receive
the exit status, the x86-64 jmp_buf is 200 bytes) and has known gaps: exit()
has already run the thread's TLS destructors and every handler newer than
ours, LLVM's aborted emission is leaked, and abort() (LLVM's fatal errors) is
not caught. It is single-threaded by construction (one jmp_buf, one armed
flag, fd 2 swapped during each emission): never call assemble() from two
threads at once.
"""
from collections.abc import Callable
import ctypes
import os
import sys
import tempfile

import llvmlite.binding as llvm
from llvmlite.utils import get_library_name

_TRIPLE = 'x86_64-unknown-linux-gnu'
_MACHINE: list[llvm.TargetMachine] = []

# penryn_emit(emitter, machine, module, error) returns the emitter's memory
# buffer, or 256 + (status & 255), the status as the OS would report it,
# after penryn_on_exit(arg, status), run by glibc's exit() while armed,
# longjmps back. No headers: glibc's x86-64 jmp_buf is
# 200 bytes, and libtcc gets _setjmp and longjmp through tcc_add_symbol.
_SHIM = r'''
typedef void *(*emitter)(void *, void *, int, const char **);
static long jb[25];
static volatile int armed;
int _setjmp(long *);
void longjmp(long *, int);

void *penryn_emit(emitter emit, void *tm, void *mod, const char **err)
{
    int r = _setjmp(jb);
    if (r)
        return (void *)(long)r;
    armed = 1;
    void *mb = emit(tm, mod, 1, err);
    armed = 0;
    return mb;
}

void penryn_on_exit(void *arg, int status)
{
    if (armed) {
        armed = 0;
        longjmp(jb, 256 + (status & 255));
    }
}
'''

_TCC_OUTPUT_MEMORY = 1
_TCC_ERRORS: list[str] = []
_TccErrorFunc = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_char_p)


def _tcc_error(opaque: int | None, message: bytes | None) -> None:
    _TCC_ERRORS.append((message or b'').decode(errors='replace'))


# Kept for the process's lifetime, like the libtcc state it is installed on.
_TCC_ERROR_FUNC = _TccErrorFunc(_tcc_error)

type _Emit = Callable[[llvm.TargetMachine, llvm.ModuleRef, ctypes.c_char_p], int | None]
_NATIVE: list[tuple[_Emit, Callable[[int], bytes], Callable[[ctypes.c_char_p], str]]] = []


def _machine() -> llvm.TargetMachine:
    if not _MACHINE:
        llvm.initialize_native_target()
        llvm.initialize_native_asmprinter()
        llvm.initialize_native_asmparser()
        _MACHINE.append(llvm.Target.from_triple(_TRIPLE)
                        .create_target_machine(reloc='static', codemodel='small'))
    return _MACHINE[0]


def _ir_string(text: str) -> str:
    # LLVM IR string literal: printable ASCII except '"' and '\' stays, every
    # other byte becomes \XX.
    return ''.join(c if ' ' <= c <= '~' and c not in '"\\'
                   else ''.join(f'\\{b:02X}' for b in c.encode()) for c in text)


def _address(function: 'ctypes._NamedFuncPointer') -> int:
    address = ctypes.cast(function, ctypes.c_void_p).value
    if address is None:
        raise OSError('null function address')
    return address


def _compile_shim(libc: ctypes.CDLL) -> tuple[int, int]:
    """Compile _SHIM in memory with libtcc; return penryn_emit and penryn_on_exit."""
    path = os.environ.get('PENRYN_LIBTCC')
    if not path:
        raise OSError('PENRYN_LIBTCC is unset: point it at TinyCC\'s lib/libtcc.so '
                      '(the Nix wrapper sets it; AGENTS.md has the checkout command)')
    try:
        tcc = ctypes.CDLL(path)
    except OSError as error:
        raise OSError(f'cannot load PENRYN_LIBTCC={path}: {error}') from error
    new, set_error, options = tcc['tcc_new'], tcc['tcc_set_error_func'], tcc['tcc_set_options']
    output, compile_string = tcc['tcc_set_output_type'], tcc['tcc_compile_string']
    add_symbol, relocate, get_symbol = tcc['tcc_add_symbol'], tcc['tcc_relocate'], tcc['tcc_get_symbol']
    new.restype, new.argtypes = ctypes.c_void_p, []
    set_error.restype, set_error.argtypes = None, [ctypes.c_void_p, ctypes.c_void_p, _TccErrorFunc]
    options.restype, options.argtypes = ctypes.c_int, [ctypes.c_void_p, ctypes.c_char_p]
    output.restype, output.argtypes = ctypes.c_int, [ctypes.c_void_p, ctypes.c_int]
    compile_string.restype, compile_string.argtypes = ctypes.c_int, [ctypes.c_void_p, ctypes.c_char_p]
    add_symbol.restype, add_symbol.argtypes = ctypes.c_int, [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p]
    relocate.restype, relocate.argtypes = ctypes.c_int, [ctypes.c_void_p]
    get_symbol.restype, get_symbol.argtypes = ctypes.c_void_p, [ctypes.c_void_p, ctypes.c_char_p]

    def check(step: str, status: int) -> None:
        if status:
            raise OSError(f'libtcc could not build the assembler shim ({step}): '
                          + ('; '.join(_TCC_ERRORS) or 'no message'))

    # Load-bearing: never tcc_delete() this state. Every registered exit
    # handler entry points into its code and runs at the process's exit,
    # after Python has finalized.
    state: int | None = new()
    if not state:
        raise OSError('libtcc could not build the assembler shim (tcc_new)')
    installed: None = set_error(state, None, _TCC_ERROR_FUNC)
    configured: int = options(state, b'-nostdlib')
    check('options', configured)
    typed: int = output(state, _TCC_OUTPUT_MEMORY)
    check('output type', typed)
    compiled: int = compile_string(state, _SHIM.encode())
    check('compile', compiled)
    for name in ('_setjmp', 'longjmp'):
        added: int = add_symbol(state, name.encode(), _address(libc[name]))
        check(name, added)
    relocated: int = relocate(state)
    check('relocate', relocated)
    emit: int | None = get_symbol(state, b'penryn_emit')
    on_exit: int | None = get_symbol(state, b'penryn_on_exit')
    if not emit or not on_exit:
        raise OSError('libtcc could not build the assembler shim (symbols)')
    return emit, on_exit


def _native() -> tuple[_Emit, Callable[[int], bytes], Callable[[ctypes.c_char_p], str]]:
    """Build the shim once; return emit, read-and-dispose and error-string helpers."""
    if not _NATIVE:
        _machine()
        libc = ctypes.CDLL(None)
        lib = ctypes.CDLL(os.path.join(os.path.dirname(llvm.__file__), get_library_name()))
        emit_address, on_exit = _compile_shim(libc)
        shim = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                ctypes.c_void_p)(emit_address)
        emitter = _address(lib['LLVMPY_TargetMachineEmitToMemory'])
        register = libc['__cxa_atexit']
        register.restype, register.argtypes = ctypes.c_int, [ctypes.c_void_p] * 3
        start, size = lib['LLVMPY_GetBufferStart'], lib['LLVMPY_GetBufferSize']
        start.restype, start.argtypes = ctypes.c_void_p, [ctypes.c_void_p]
        size.restype, size.argtypes = ctypes.c_size_t, [ctypes.c_void_p]
        dispose, dispose_string = lib['LLVMPY_DisposeMemoryBuffer'], lib['LLVMPY_DisposeString']
        dispose.restype, dispose.argtypes = None, [ctypes.c_void_p]
        dispose_string.restype, dispose_string.argtypes = None, [ctypes.c_char_p]

        def emit(machine: llvm.TargetMachine, module: llvm.ModuleRef, error: ctypes.c_char_p) -> int | None:
            # A fresh entry per emission keeps ours the newest, so glibc runs
            # it first; spent and disarmed entries (40 B each) stay listed.
            registered: int = register(on_exit, None, None)
            if registered:
                raise OSError('__cxa_atexit failed')
            buffer: int | None = shim(emitter, machine, module, ctypes.addressof(error))
            return buffer

        def read(buffer: int) -> bytes:
            pointer: int | None = start(buffer)
            length: int = size(buffer)
            try:
                if pointer is None:
                    raise OSError('LLVM returned a buffer without data')
                return ctypes.string_at(pointer, length)
            finally:
                disposed: None = dispose(buffer)

        def take(error: ctypes.c_char_p) -> str:
            text = (error.value or b'').decode(errors='replace')
            disposed: None = dispose_string(error)
            return text

        _NATIVE.append((emit, read, take))
    return _NATIVE[0]


def assemble(source: str) -> bytes:
    """Return the relocatable x86-64 ELF object for assembly SOURCE.

    An LLVM exit() during the emission raises ValueError with LLVM's message
    (module docstring); LLVM's other diagnostics pass through to stderr.
    """
    emit, read, take = _native()
    module = llvm.parse_assembly(f'module asm "{_ir_string(source)}"\n')
    error = ctypes.c_char_p()
    with tempfile.TemporaryFile() as diagnostics:
        saved = os.dup(2)
        os.dup2(diagnostics.fileno(), 2)
        try:
            buffer = emit(_machine(), module, error)
        finally:
            os.dup2(saved, 2)
            os.close(saved)
        diagnostics.seek(0)
        message = diagnostics.read().decode(errors='replace').strip()
    if buffer is not None and buffer < 4096:
        raise ValueError(f'LLVM called exit({buffer - 256}) on generated assembly: {message}')
    if message:
        print(message, file=sys.stderr)
    if buffer is None:
        raise RuntimeError(f'LLVM emission failed: {take(error)}')
    return read(buffer)
