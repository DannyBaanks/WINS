#include <stdio.h>
extern unsigned long long mach_absolute_time(void);

int main(void) {
    printf("t=%llu\n", mach_absolute_time());
    return 0;
}
