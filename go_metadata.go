// Recover Go function boundaries with the standard library's debug/gosym.
// Metadata addresses let the fail-closed Python backend inspect selected functions.
package main

import (
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

type Function struct {
	Start    uint64 `json:"start"`
	End      uint64 `json:"end"`
	Name     string `json:"name"`
	Metadata uint64 `json:"metadata_address"`
}
type Table struct {
	Address   uint64     `json:"address"`
	Text      uint64     `json:"text"`
	Source    string     `json:"text_source"`
	Module    uint64     `json:"module_address,omitempty"`
	Functions []Function `json:"functions"`
}
type Report struct {
	Parser    string   `json:"parser"`
	Tables    []Table  `json:"tables"`
	Rejected  []string `json:"rejected_candidates"`
	GoVersion string   `json:"go_build_version,omitempty"`
}

func parse(data []byte, text uint64) (result *gosym.Table, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("gosym rejected table: %v", r)
		}
	}()
	return gosym.NewTable(nil, gosym.NewLineTable(data, text))
}

func run(path string) error {
	f, err := elf.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS64 || f.Machine != elf.EM_X86_64 || f.ByteOrder != binary.LittleEndian {
		return fmt.Errorf("expected little-endian ELF64 x86-64")
	}
	sectionData := map[*elf.Section][]byte{}
	dataFor := func(s *elf.Section) ([]byte, error) {
		if d, ok := sectionData[s]; ok {
			return d, nil
		}
		d, err := s.Data()
		if err == nil {
			sectionData[s] = d
		}
		return d, err
	}
	// Resolve load-bias-independent R_X86_64_RELATIVE values without applying
	// relocations or trusting the names of allocated sections.
	relative := map[uint64]uint64{}
	for _, s := range f.Sections {
		if s.Type != elf.SHT_RELA || s.Flags&elf.SHF_ALLOC == 0 {
			continue
		}
		d, err := dataFor(s)
		if err != nil {
			return err
		}
		if len(d)%24 != 0 {
			return fmt.Errorf("malformed RELA section")
		}
		for i := 0; i < len(d); i += 24 {
			if binary.LittleEndian.Uint64(d[i+8:]) == uint64(elf.R_X86_64_RELATIVE) {
				relative[binary.LittleEndian.Uint64(d[i:])] = binary.LittleEndian.Uint64(d[i+16:])
			}
		}
	}
	executable := func(pc uint64) bool {
		for _, s := range f.Sections {
			if s.Flags&elf.SHF_EXECINSTR != 0 && pc >= s.Addr && pc-s.Addr < s.Size {
				return true
			}
		}
		return false
	}
	word := func(addr uint64) (uint64, bool) {
		if value, ok := relative[addr]; ok {
			return value, true
		}
		for _, s := range f.Sections {
			if s.Type != elf.SHT_NOBITS && addr >= s.Addr && addr-s.Addr <= s.Size && s.Size-(addr-s.Addr) >= 8 {
				d, e := dataFor(s)
				if e == nil {
					return binary.LittleEndian.Uint64(d[addr-s.Addr:]), true
				}
			}
		}
		return 0, false
	}
	r := Report{Parser: "Go standard library debug/elf + debug/gosym", Tables: []Table{}, Rejected: []string{}}
	if info, err := buildinfo.ReadFile(path); err == nil {
		r.GoVersion = info.GoVersion
	}
	// The eight-byte header alone is only a candidate. gosym, the header
	// bounds, and executable function ranges independently validate it.
	for _, s := range f.Sections {
		if s.Type == elf.SHT_NOBITS || s.Flags&elf.SHF_ALLOC == 0 || s.Flags&elf.SHF_EXECINSTR != 0 {
			continue
		}
		data, err := dataFor(s)
		if err != nil {
			return err
		}
		for at := 0; at < len(data); {
			i := bytes.Index(data[at:], []byte{0xff, 0xff, 0xff, 0, 0, 1, 8})
			if i < 0 {
				break
			}
			i += at - 1
			at = i + 8
			if i < 0 {
				continue
			}
			magic := data[i]
			if magic != 0xf1 && magic != 0xf0 && magic != 0xfa && magic != 0xfb {
				continue
			}
			address := s.Addr + uint64(i)
			d := data[i:]
			reject := func(reason string) { r.Rejected = append(r.Rejected, fmt.Sprintf("0x%x: %s", address, reason)) }
			if magic != 0xf1 {
				reject("Go pclntab predates supported 1.20+ metadata layout")
				continue
			}
			if len(d) < 72 {
				reject("truncated Go 1.20+ header")
				continue
			}
			get := func(i int) uint64 { return binary.LittleEndian.Uint64(d[i:]) }
			nfunc := get(8)
			if nfunc == 0 || nfunc > uint64(len(d))/8 || get(16) > uint64(len(d))/4 {
				reject("invalid function count")
				continue
			}
			valid := true
			previousOffset := uint64(72)
			for j := 32; j <= 64; j += 8 {
				if get(j) >= uint64(len(d)) || get(j) < previousOffset {
					valid = false
				}
				previousOffset = get(j)
			}
			if !valid {
				reject("header offsets outside section")
				continue
			}
			if (nfunc+1)*8 > uint64(len(d))-get(64) {
				reject("function table extends outside section")
				continue
			}
			var module uint64
			text, source := get(24), "pcHeader.textStart"
			if value, ok := relative[address+24]; ok {
				text = value
				source = "relocated pcHeader.textStart"
			}
			if text == 0 {
				// C-archive links leave pcHeader.textStart zero. For the known
				// Go 1.20+ moduledata prefix, require all five table pointers,
				// ftab, minpc and text to agree before accepting its text base.
				candidates := map[uint64]bool{}
				for candidate, value := range relative {
					if value == address {
						candidates[candidate] = true
					}
				}
				needle := make([]byte, 8)
				binary.LittleEndian.PutUint64(needle, address)
				for _, other := range f.Sections {
					if other.Type == elf.SHT_NOBITS || other.Flags&elf.SHF_ALLOC == 0 || other.Flags&elf.SHF_EXECINSTR != 0 {
						continue
					}
					od, err := dataFor(other)
					if err != nil {
						return err
					}
					for off := 0; off < len(od); {
						pos := bytes.Index(od[off:], needle)
						if pos < 0 {
							break
						}
						pos += off
						off = pos + 1
						if (other.Addr+uint64(pos))%8 == 0 {
							candidates[other.Addr+uint64(pos)] = true
						}
					}
				}
				for candidate := range candidates {
					good := true
					for _, pair := range [][2]uint64{{8, 32}, {32, 40}, {56, 48}, {80, 56}, {104, 64}, {128, 64}} {
						v, ok := word(candidate + pair[0])
						if !ok || v != address+get(int(pair[1])) {
							good = false
							break
						}
					}
					base, ok := word(candidate + 176)
					minpc, ok2 := word(candidate + 160)
					maxpc, ok3 := word(candidate + 168)
					if good && ok && ok2 && ok3 && base == minpc && maxpc > base && executable(base) && executable(maxpc-1) {
						text = base
						module = candidate
						source = "validated Go 1.20+ moduledata prefix"
						break
					}
				}
			}
			if text == 0 || !executable(text) {
				reject("no validated runtime.text base; cannot recover function addresses")
				continue
			}
			tab, err := parse(d, text)
			if err != nil {
				reject(err.Error())
				continue
			}
			if uint64(len(tab.Funcs)) != nfunc {
				reject("gosym function count disagrees")
				continue
			}
			out := Table{Address: address, Text: text, Source: source, Module: module, Functions: make([]Function, 0, len(tab.Funcs))}
			var previousEnd uint64
			for index, fn := range tab.Funcs {
				if fn.End <= fn.Entry || fn.Entry < previousEnd || !executable(fn.Entry) || !executable(fn.End-1) {
					valid = false
					break
				}
				out.Functions = append(out.Functions, Function{fn.Entry, fn.End, fn.Name, address + get(64) + uint64(binary.LittleEndian.Uint32(d[get(64)+uint64(index)*8+4:]))})
				previousEnd = fn.End
			}
			if !valid {
				reject("Go function range outside executable sections")
				continue
			}
			r.Tables = append(r.Tables, out)
		}
	}
	sort.Slice(r.Tables, func(i, j int) bool { return r.Tables[i].Address < r.Tables[j].Address })
	return json.NewEncoder(os.Stdout).Encode(r)
}
func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: penryn-go-metadata ELF")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
