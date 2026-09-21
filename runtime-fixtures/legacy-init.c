#include <stdio.h>
static volatile int initialized;
__attribute__((noinline)) void old_init(void) { __asm__ volatile ("" ::: "memory"); }
void replacement_init(void) { initialized = 1; old_init(); }
int main(void) {
    puts(initialized ? "LEGACY_INIT_OK" : "DT_INIT_BYPASSED");
    return initialized ? 0 : 31;
}
