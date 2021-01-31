#include <stddef.h>
#include <stdint.h>
#include <uchar.h>
#include <fcntl.h>
#include <unistd.h>



// REFER: https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
//            Range 225–241 is reserved
// Port Usage:
//     0xE9 = 233 = print uint32_t as char32_t
//     0xEB = 235 = print uint32_t as integer
//     0xED = 237 = print uint32_t as char* which is a null terminated string
//     0xEF = 239 = file system functionalities such as: open, close, read, write



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

void printChar(const char ch) {
    outb(233, ch);
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

// REFER: https://www.geeksforgeeks.org/input-output-system-calls-c-create-open-close-read-write/
// REFER: http://www.di.uevora.pt/~lmr/syscalls.html#:~:text=File%20Structure,-Creating
// NOTE: Ma'am said: The Linux system call semantics are a good model for implementation.

/* 1. creat
 * 2. open
 * 3. close
 * 4. read
 * 5. write
 * */

uint32_t FILE_IO_PORT = 239;

// REFER: https://www.geeksforgeeks.org/enumeration-enum-c/
enum FileSystemOperationType {
    ENUM_FILE_OPEN_ADV = 1, ENUM_FILE_OPEN = 3, ENUM_FILE_CLOSE = 5, ENUM_FILE_READ = 7, ENUM_FILE_WRITE = 9,
    ENUM_FILE_LSEEK = 11
};

struct FileSystemOperation {
    enum FileSystemOperationType operation_type;

    const char *param_path;
    int param_flags;
    mode_t param_mode;  // This is an integer
    int param_fd;
    void *param_buf;
    size_t param_cnt;
    off_t param_offset;

    int return_result_int;
    size_t return_result_size_t;
    off_t return_result_off_t;
};

struct FileSystemOperation file_hypercall(struct FileSystemOperation fso) {
    // printVal((intptr_t) (&fso));
    outb(FILE_IO_PORT, (intptr_t) (&fso));
    return fso;
}

int file_open_adv(const char *Path, int flags, mode_t mode) {
    struct FileSystemOperation fso = {
            .operation_type = ENUM_FILE_OPEN_ADV,
            .param_path = Path,
            .param_flags = flags,
            .param_mode = mode
    };
    return file_hypercall(fso).return_result_int;
}

int file_open(const char *Path, int flags) {
    struct FileSystemOperation fso = {
            .operation_type = ENUM_FILE_OPEN,
            .param_path = Path,
            .param_flags = flags,
    };
    return file_hypercall(fso).return_result_int;
}

int file_creat(const char *pathname, mode_t mode) {
    return file_open_adv(pathname, O_CREAT | O_WRONLY | O_TRUNC, mode);
}

int file_close(int fd) {
    struct FileSystemOperation fso = {
            .operation_type = ENUM_FILE_CLOSE,
            .param_fd = fd
    };
    return file_hypercall(fso).return_result_int;
}

size_t file_read(int fd, void *buf, size_t cnt) {
    struct FileSystemOperation fso = {
            .operation_type = ENUM_FILE_READ,
            .param_fd = fd,
            .param_buf = buf,
            .param_cnt = cnt
    };
    return file_hypercall(fso).return_result_size_t;
}

size_t file_write(int fd, void *buf, size_t cnt) {
    struct FileSystemOperation fso = {
            .operation_type = ENUM_FILE_WRITE,
            .param_fd = fd,
            .param_buf = buf,
            .param_cnt = cnt
    };
    return file_hypercall(fso).return_result_size_t;
}

// REFER: https://man7.org/linux/man-pages/man2/lseek.2.html
off_t file_seek(int fd, off_t offset, int whence) {
    struct FileSystemOperation fso = {
            .operation_type = ENUM_FILE_LSEEK,
            .param_fd = fd,
            .param_offset = offset,
            .param_flags = whence
    };
    return file_hypercall(fso).return_result_off_t;
}



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

    // Create "temp.txt" if it does not exists and write to it
    int filefd1 = file_open_adv("./temp.txt", O_CREAT | O_RDWR, S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR);
    printVal(filefd1);  // Print the file descriptor
    file_seek(filefd1, 0, SEEK_END);  // Move the file writer to the end of the file
    file_write(filefd1, "12345\n", 6);
    file_close(filefd1);

    // Read from "temp.txt"
    char buff[1024];
    int filefd2 = file_open("./temp.txt", O_RDONLY);
    size_t cnt = file_read(filefd2, buff, 1024);
    file_close(filefd2);
    buff[cnt] = '\0';  // NOTE: this is necessary because read call will not add '\0' to the buffer
    printVal(cnt);  // Print bytes read from the file
    display(buff);

    *(long *) 0x400 = 42;

    for (;;)
        asm("hlt" : /* empty */ : "a" (42) : "memory");  // total exits = 20
}
