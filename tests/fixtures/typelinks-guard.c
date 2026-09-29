#include <stdio.h>
#include <string.h>
extern void *original_next, *synthetic_next;
extern int invoke_guard(void);
int main(int argc, char **argv) {
    original_next = argc > 1 ? &synthetic_next : NULL;
    synthetic_next = argc > 1 && strcmp(argv[1], "plugin") == 0 ? &original_next : NULL;
    printf("%d\n", invoke_guard());
    return 0;
}
