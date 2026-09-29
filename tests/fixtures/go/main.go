// A bounded GC, small-goroutine-stack and CPU-profiler stress workload.
// The forced instruction bypasses CPU dispatch for a real SIGILL control.
package main

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"sync"
)

func forcedPopcnt(value uint64) uint64

func main() {
	rounds := 120
	if value := os.Getenv("PENRYN_STRESS_ROUNDS"); value != "" {
		var err error
		rounds, err = strconv.Atoi(value)
		if err != nil || rounds < 1 || rounds > 10000 {
			panic("PENRYN_STRESS_ROUNDS must be 1..10000 per goroutine")
		}
	}
	if forcedPopcnt(0xff00ff00ff00ff00) != 32 {
		panic("incorrect POPCNT")
	}
	if len(os.Args) == 2 {
		file, err := os.Create(os.Args[1])
		if err != nil {
			panic(err)
		}
		if err := pprof.StartCPUProfile(file); err != nil {
			panic(err)
		}
		defer file.Close()
		defer pprof.StopCPUProfile()
	}
	runtime.GOMAXPROCS(2)
	var group sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for round := 0; round < rounds; round++ {
				live := make([][]byte, 256)
				for i := range live {
					live[i] = make([]byte, 64+i*8)
					live[i][0] = byte(forcedPopcnt(uint64(i)))
				}
				for i := 0; i < 50000; i++ {
					if forcedPopcnt(0xff00ff00ff00ff00) != 32 {
						panic("incorrect POPCNT under GC")
					}
				}
				runtime.GC()
				runtime.KeepAlive(live)
			}
		}()
	}
	group.Wait()
	fmt.Printf("GC_STRESS_OK rounds=%d forced_popcnt=%d\n", rounds*4, rounds*4*50256)
}
