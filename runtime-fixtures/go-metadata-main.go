// Standalone companion to go-metadata-force.s, copied into a temporary package.
package main

import (
	"fmt"
	"os"
	"reflect"
	"runtime"
	"runtime/pprof"
	"strconv"
	"sync"
)

func forcedPopcnt(value uint64) uint64
func framedPopcnt(value uint64) uint64

//go:noinline
func anchor() { runtime.KeepAlive(nil) }

//go:noinline
func recursive(depth int, value *uint64) uint64 {
	var live [32]*uint64
	for i := range live {
		live[i] = value
	}
	var result uint64
	if depth == 0 {
		result = framedPopcnt(*value)
	} else {
		result = recursive(depth-1, value)
	}
	runtime.KeepAlive(live)
	return result
}

func main() {
	anchor()
	if len(os.Args) != 5 {
		panic("expected anchor VA, leaf stub VA, framed stub VA, profile path")
	}
	original, _ := strconv.ParseUint(os.Args[1], 0, 64)
	for _, arg := range os.Args[2:4] {
		raw, _ := strconv.ParseUint(arg, 0, 64)
		pc := reflect.ValueOf(anchor).Pointer() + uintptr(raw-original)
		fn := runtime.FuncForPC(pc)
		if fn == nil || fn.Name() == "" {
			panic("registered stub is missing from runtime.findfunc")
		}
		file, line := fn.FileLine(pc)
		if file == "" || line <= 0 {
			panic("registered source location missing")
		}
		fmt.Printf("GO_FUNCTION_OK %s %s:%d\n", fn.Name(), file, line)
	}
	file, err := os.Create(os.Args[4])
	if err != nil {
		panic(err)
	}
	if err := pprof.StartCPUProfile(file); err != nil {
		panic(err)
	}
	runtime.GOMAXPROCS(2)
	var group sync.WaitGroup
	for worker := 0; worker < 2; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for round := 0; round < 24; round++ {
				word := uint64(0x0101010101010101)
				if recursive(64, &word) != 8 {
					panic("incorrect count after stack growth")
				}
				live := make([]*uint64, 128)
				for i := range live {
					value := uint64(i)
					live[i] = &value
				}
				for i := 0; i < 100000; i++ {
					if forcedPopcnt(0xff00ff00ff00ff00) != 32 || framedPopcnt(0x0101010101010101) != 8 {
						panic("incorrect count")
					}
				}
				runtime.GC()
				runtime.KeepAlive(live)
			}
		}()
	}
	group.Wait()
	pprof.StopCPUProfile()
	file.Close()
	fmt.Println("GO_METADATA_STRESS_OK gc=48 popcnt=9600048 stack_depth=64")
}
