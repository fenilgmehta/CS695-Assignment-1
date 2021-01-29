#include <stddef.h>
#include <stdint.h>
#include <uchar.h>

// static void outb(uint16_t port, uint8_t value) {
//     asm("outb %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
// }

static inline void outb(uint16_t port, uint32_t value) {
    asm("out %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}

static inline uint32_t inb(uint16_t port) {
    uint32_t ret;
    asm("in %1, %0" : "=a"(ret) : "Nd"(port) : "memory" );
    return ret;
}

void printVal(uint32_t val) {
    outb(235, val);
}

// NOTE: it will return the number of exits incurred by the guest, as seen by the hypervisor
uint32_t getNumExits() {
    return inb(235);
}

// NOTE: IMPORTANT: you can assume that strings are null terminated
void display(const char *str) {
    outb(237, (uint32_t) ((intptr_t) str));
}

// REFER: https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
//            Range 225–241 is reserved
// Port Usage:
//     0xE9 = 233 = print uint32_t as char32_t
//     0xEB = 235 = print uint32_t as integer
//     0xED = 237 = print uint32_t as char* which is a null terminated string

void
__attribute__((noreturn))
__attribute__((section(".start")))
_start(void) {
    const char *p;

    for (p = "Hello, world!\n"; *p; ++p)
        outb(233, *p);

    uint32_t numExits = getNumExits();  // numExits should be 15 = 14 (due to hello world) + 1 (due to this call)
    printVal(numExits);  // total exits = 16, will print numExits (i.e. 15)
    display("GUEST: display called with one guest exit :)\n");  // total exits = 17
    numExits = getNumExits();  // total exits = 18
    printVal(numExits);  // total exits = 19, will print numExits (i.e. 18)

    *(long *) 0x400 = 42;

    for (;;)
        asm("hlt" : /* empty */ : "a" (42) : "memory");  // total exits = 20
}
