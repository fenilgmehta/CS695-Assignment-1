#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <linux/kvm.h>

// REFER: https://stackoverflow.com/questions/52240592/what-exatly-are-char16-t-and-char32-t-and-where-can-i-find-them
#include <uchar.h>

/* CR0 bits */
#define CR0_PE 1u
#define CR0_MP (1U << 1)
#define CR0_EM (1U << 2)
#define CR0_TS (1U << 3)
#define CR0_ET (1U << 4)
#define CR0_NE (1U << 5)
#define CR0_WP (1U << 16)
#define CR0_AM (1U << 18)
#define CR0_NW (1U << 29)
#define CR0_CD (1U << 30)
#define CR0_PG (1U << 31)

/* CR4 bits */
#define CR4_VME 1
#define CR4_PVI (1U << 1)
#define CR4_TSD (1U << 2)
#define CR4_DE (1U << 3)
#define CR4_PSE (1U << 4)
#define CR4_PAE (1U << 5)
#define CR4_MCE (1U << 6)
#define CR4_PGE (1U << 7)
#define CR4_PCE (1U << 8)
#define CR4_OSFXSR (1U << 8)
#define CR4_OSXMMEXCPT (1U << 10)
#define CR4_UMIP (1U << 11)
#define CR4_VMXE (1U << 13)
#define CR4_SMXE (1U << 14)
#define CR4_FSGSBASE (1U << 16)
#define CR4_PCIDE (1U << 17)
#define CR4_OSXSAVE (1U << 18)
#define CR4_SMEP (1U << 20)
#define CR4_SMAP (1U << 21)

#define EFER_SCE 1
#define EFER_LME (1U << 8)
#define EFER_LMA (1U << 10)
#define EFER_NXE (1U << 11)

/* 32-bit page directory entry bits */
#define PDE32_PRESENT 1
#define PDE32_RW (1U << 1)
#define PDE32_USER (1U << 2)
#define PDE32_PS (1U << 7)

/* 64-bit page * entry bits */
#define PDE64_PRESENT 1
#define PDE64_RW (1U << 1)
#define PDE64_USER (1U << 2)
#define PDE64_ACCESSED (1U << 5)
#define PDE64_DIRTY (1U << 6)
#define PDE64_PS (1U << 7)
#define PDE64_G (1U << 8)

#define printfdebug(...) printf("\033[0;31m" "DEBUG: " "\033[0m" __VA_ARGS__)

struct vm {
    int sys_fd;
    int fd;
    char *mem;
};

void vm_init(struct vm *vm, size_t mem_size) {
    int api_ver;
    struct kvm_userspace_memory_region memreg;

    vm->sys_fd = open("/dev/kvm", O_RDWR);
    if (vm->sys_fd < 0) {
        perror("open /dev/kvm");
        exit(1);
    }

    api_ver = ioctl(vm->sys_fd, KVM_GET_API_VERSION, 0);
    if (api_ver < 0) {
        perror("KVM_GET_API_VERSION");
        exit(1);
    }

    if (api_ver != KVM_API_VERSION) {
        fprintf(stderr, "Got KVM api version %d, expected %d\n",
                api_ver, KVM_API_VERSION);
        exit(1);
    }

    vm->fd = ioctl(vm->sys_fd, KVM_CREATE_VM, 0);
    if (vm->fd < 0) {
        perror("KVM_CREATE_VM");
        exit(1);
    }

    if (ioctl(vm->fd, KVM_SET_TSS_ADDR, 0xfffbd000) < 0) {
        perror("KVM_SET_TSS_ADDR");
        exit(1);
    }

    printfdebug("Part A: size of the guest memory = %zu\n", mem_size);
    // NOTE: Part A: Guest memory is allocated from the below line of the host OS
    vm->mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    // NOTE: "vm->mem" is a pointer to the host's virtual memory to a block of memory
    //       of size equal to "mem_size"
    printfdebug("virtual address space of the simple hypervisor at which 'vm->mem' is mapped = %p\n", (void *) vm->mem);

    if (vm->mem == MAP_FAILED) {
        perror("mmap mem");
        exit(1);
    }

    madvise(vm->mem, mem_size, MADV_MERGEABLE);

    // REFER: https://unix.stackexchange.com/questions/566243/explain-kvm-userspace-memory-region-structure
    // NOTE: "memory_size" bytes are mapped into the guest memory, starting at physical
    //       address "guest_phys_addr" (from the guest’s perspective), using memory at
    //       linear address "userspace_addr" (from the host’s perspective).
    memreg.slot = 0;
    memreg.flags = 0;
    memreg.guest_phys_addr = 0;  // NOTE: This line ensure that the memory block pointed to by
                                 //       "vm->mem" is mapped to the guest's physical address 0
    memreg.memory_size = mem_size;
    memreg.userspace_addr = (unsigned long) vm->mem;
    if (ioctl(vm->fd, KVM_SET_USER_MEMORY_REGION, &memreg) < 0) {
        perror("KVM_SET_USER_MEMORY_REGION");
        exit(1);
    }
}

struct vcpu {
    int fd;
    struct kvm_run *kvm_run;
};

void vcpu_init(struct vm *vm, struct vcpu *vcpu) {
    int vcpu_mmap_size;

    vcpu->fd = ioctl(vm->fd, KVM_CREATE_VCPU, 0);
    if (vcpu->fd < 0) {
        perror("KVM_CREATE_VCPU");
        exit(1);
    }

    vcpu_mmap_size = ioctl(vm->sys_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (vcpu_mmap_size <= 0) {
        perror("KVM_GET_VCPU_MMAP_SIZE");
        exit(1);
    }

    // NOTE: Part A: The below line allocates a small portion of VCPU runtime memory from
    //               the host OS to store the information it has to exchange with KVM.
    vcpu->kvm_run = mmap(NULL, vcpu_mmap_size, PROT_READ | PROT_WRITE,
                         MAP_SHARED, vcpu->fd, 0);
    printfdebug("Part A: 'vcpu_mmap_size' = %d\n", vcpu_mmap_size);
    printfdebug("Part A: VCPU runtime memory location in virutal address space of the hypervisor = %p\n",
                vcpu->kvm_run);

    if (vcpu->kvm_run == MAP_FAILED) {
        perror("mmap kvm_run");
        exit(1);
    }
}

int run_vm(struct vm *vm, struct vcpu *vcpu, size_t sz) {
    struct kvm_regs regs;
    uint64_t memval = 0;

    printfdebug("Port number used for IO = %d (i.e. 0x%X)\n", 0xE9, 0xE9);
    // NOTE: the below variable keeps the count of:
    //           1. total exits from guest to VMM
    //           2. exits from guest to VMM due to IO
    static uint64_t exit_count = 0, io_count = 0;
    // static uint16_t flag = 1;
    for (;;) {
        // REFER: https://lwn.net/Articles/658512/
        // NOTE: Note that KVM_RUN runs the VM in the context of the current thread and doesn't return until emulation
        //       stops. To run a multi-CPU VM, the user-space process must spawn multiple threads, and call KVM_RUN for
        //       different virtual CPUs in different threads.
        // NOTE: Part A: the below statement switch the control from running the hypervisor to running the guest
        //               and switches back to the hypervisor from the guest
        if (ioctl(vcpu->fd, KVM_RUN, 0) < 0) {
            perror("KVM_RUN");
            exit(1);
        }
        exit_count += 1;  // DEBUG

        switch (vcpu->kvm_run->exit_reason) {
            // NOTE: We treat a "hlt" instruction as a sign that we're done,
            //       since we have nothing to ever wake us back up
            case KVM_EXIT_HLT:
                goto check;

            case KVM_EXIT_IO:
                io_count += 1;
                char *p = (char *) vcpu->kvm_run;
                char *port_data_ptr = p + vcpu->kvm_run->io.data_offset;

                if (vcpu->kvm_run->io.direction == KVM_EXIT_IO_OUT) {
                    // printfdebug("DELETE THIS LINE: reason is KVM_EXIT_IO_OUT, port = %d\n", vcpu->kvm_run->io.port);
                    // printfdebug("Part A: (char *) vcpu->kvm_run = p = %p\n", p);
                    // printfdebug("            p + vcpu->kvm_run->io.data_offset = %p\n", p + vcpu->kvm_run->io.data_offset);
                    // printfdebug("            vcpu->kvm_run->io.data_offset = %llu\n", vcpu->kvm_run->io.data_offset);  // always remain 4096

                    if (vcpu->kvm_run->io.port == 233) {
                        // PORT NUMBER:   0xE9 = 233 = print uint32_t as char32_t
                        // fwrite(p + vcpu->kvm_run->io.data_offset, vcpu->kvm_run->io.size, 1, stdout);
                        fprintf(stdout, "%c", ((char32_t *) port_data_ptr)[0]);
                        fflush(stdout);
                    } else if (vcpu->kvm_run->io.port == 235) {
                        // PORT NUMBER:   0xEB = 235 = print uint32_t as integer
                        fprintf(stdout, "printVal value = %d\n", ((uint32_t *) port_data_ptr)[0]);
                        fflush(stdout);
                    } else if (vcpu->kvm_run->io.port == 237) {
                        // PORT NUMBER:   0xED = 237 = print uint32_t as char* which is a null terminated string
                        fprintf(stdout, "%s", vm->mem + ((uint32_t *) port_data_ptr)[0]);
                        fflush(stdout);
                    } else {
                        printfdebug("UNEXPECTED KVM_EXIT_IO_OUT vcpu->kvm_run->io.port = %d", vcpu->kvm_run->io.port);
                    }
                } else if (vcpu->kvm_run->io.direction == KVM_EXIT_IO_IN) {
                    // printfdebug("DELETE THIS LINE: reason is KVM_EXIT_IO_IN, port = %d\n", vcpu->kvm_run->io.port);
                    if (vcpu->kvm_run->io.port == 235) {
                        ((uint32_t *) port_data_ptr)[0] = exit_count;
                    } else {
                        printfdebug("UNEXPECTED KVM_EXIT_IO_IN vcpu->kvm_run->io.port = %d", vcpu->kvm_run->io.port);
                    }
                }
                continue;

            /* fall through */
            default:
                fprintf(stderr, "Got exit_reason %d, expected KVM_EXIT_HLT (%d)\n",
                        vcpu->kvm_run->exit_reason, KVM_EXIT_HLT);
                exit(1);
        }
    }

    check:
    printfdebug("Part A: exit_count = %lu\n", exit_count);
    printfdebug("Part A: io_count = %lu\n", io_count);
    printfdebug("            14 IO exits are because of 'Hello, world!' which is of length 13 and '\\n' which is of length 1\n");
    if (ioctl(vcpu->fd, KVM_GET_REGS, &regs) < 0) {
        perror("KVM_GET_REGS");
        exit(1);
    }

    if (regs.rax != 42) {
        printf("Wrong result: {E,R,}AX is %lld\n", regs.rax);
        return 0;
    }

    // NOTE: Part A: the below line reads the value 42
    memcpy(&memval, &vm->mem[0x400], sz);
    if (memval != 42) {
        printf("Wrong result: memory at 0x400 is %lld\n",
               (unsigned long long) memval);
        return 0;
    }

    return 1;
}

extern const unsigned char guest16[], guest16_end[];

int run_real_mode(struct vm *vm, struct vcpu *vcpu) {
    struct kvm_sregs sregs;
    struct kvm_regs regs;

    printf("Testing real mode\n");

    if (ioctl(vcpu->fd, KVM_GET_SREGS, &sregs) < 0) {
        perror("KVM_GET_SREGS");
        exit(1);
    }

    sregs.cs.selector = 0;
    sregs.cs.base = 0;

    if (ioctl(vcpu->fd, KVM_SET_SREGS, &sregs) < 0) {
        perror("KVM_SET_SREGS");
        exit(1);
    }

    memset(&regs, 0, sizeof(regs));
    /* Clear all FLAGS bits, except bit 1 which is always set. */
    regs.rflags = 2;
    regs.rip = 0;

    if (ioctl(vcpu->fd, KVM_SET_REGS, &regs) < 0) {
        perror("KVM_SET_REGS");
        exit(1);
    }

    memcpy(vm->mem, guest16, guest16_end - guest16);
    return run_vm(vm, vcpu, 2);
}

static void setup_protected_mode(struct kvm_sregs *sregs) {
    struct kvm_segment seg = {
            .base = 0,
            .limit = 0xffffffff,
            .selector = 1 << 3,
            .present = 1,
            .type = 11, /* Code: execute, read, accessed */
            .dpl = 0,
            .db = 1,
            .s = 1, /* Code/data */
            .l = 0,
            .g = 1, /* 4KB granularity */
    };

    sregs->cr0 |= CR0_PE; /* enter protected mode */

    sregs->cs = seg;

    seg.type = 3; /* Data: read/write, accessed */
    seg.selector = 2 << 3;
    sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = seg;
}

extern const unsigned char guest32[], guest32_end[];

int run_protected_mode(struct vm *vm, struct vcpu *vcpu) {
    struct kvm_sregs sregs;
    struct kvm_regs regs;

    printf("Testing protected mode\n");

    if (ioctl(vcpu->fd, KVM_GET_SREGS, &sregs) < 0) {
        perror("KVM_GET_SREGS");
        exit(1);
    }

    setup_protected_mode(&sregs);

    if (ioctl(vcpu->fd, KVM_SET_SREGS, &sregs) < 0) {
        perror("KVM_SET_SREGS");
        exit(1);
    }

    memset(&regs, 0, sizeof(regs));
    /* Clear all FLAGS bits, except bit 1 which is always set. */
    regs.rflags = 2;
    regs.rip = 0;

    if (ioctl(vcpu->fd, KVM_SET_REGS, &regs) < 0) {
        perror("KVM_SET_REGS");
        exit(1);
    }

    memcpy(vm->mem, guest32, guest32_end - guest32);
    return run_vm(vm, vcpu, 4);
}

static void setup_paged_32bit_mode(struct vm *vm, struct kvm_sregs *sregs) {
    uint32_t pd_addr = 0x2000;
    uint32_t *pd = (void *) (vm->mem + pd_addr);

    /* A single 4MB page to cover the memory region */
    pd[0] = PDE32_PRESENT | PDE32_RW | PDE32_USER | PDE32_PS;
    /* Other PDEs are left zeroed, meaning not present. */

    sregs->cr3 = pd_addr;
    sregs->cr4 = CR4_PSE;
    sregs->cr0
            = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
    sregs->efer = 0;
}

int run_paged_32bit_mode(struct vm *vm, struct vcpu *vcpu) {
    struct kvm_sregs sregs;
    struct kvm_regs regs;

    printf("Testing 32-bit paging\n");

    if (ioctl(vcpu->fd, KVM_GET_SREGS, &sregs) < 0) {
        perror("KVM_GET_SREGS");
        exit(1);
    }

    setup_protected_mode(&sregs);
    setup_paged_32bit_mode(vm, &sregs);

    if (ioctl(vcpu->fd, KVM_SET_SREGS, &sregs) < 0) {
        perror("KVM_SET_SREGS");
        exit(1);
    }

    memset(&regs, 0, sizeof(regs));
    /* Clear all FLAGS bits, except bit 1 which is always set. */
    regs.rflags = 2;
    regs.rip = 0;

    if (ioctl(vcpu->fd, KVM_SET_REGS, &regs) < 0) {
        perror("KVM_SET_REGS");
        exit(1);
    }

    memcpy(vm->mem, guest32, guest32_end - guest32);
    return run_vm(vm, vcpu, 4);
}

extern const unsigned char guest64[], guest64_end[];

static void setup_64bit_code_segment(struct kvm_sregs *sregs) {
    struct kvm_segment seg = {
            .base = 0,
            .limit = 0xffffffff,
            .selector = 1 << 3,
            .present = 1,
            .type = 11, /* Code: execute, read, accessed */
            .dpl = 0,
            .db = 0,
            .s = 1, /* Code/data */
            .l = 1,
            .g = 1, /* 4KB granularity */
    };

    // NOTE: Part A: this line tells the guest that the Code Segment
    //               starts at base 0 and has a limit of "0xffffffff"
    sregs->cs = seg;

    seg.type = 3; /* Data: read/write, accessed */
    seg.selector = 2 << 3;
    sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = seg;
}

/* NOTE: Part A: setup the guest page table */
static void setup_long_mode(struct vm *vm, struct kvm_sregs *sregs) {
    // REFER: https://ricklarabee.blogspot.com/2017/01/virtual-memory-page-tables-and-one-bit.html
    // REFER: https://stackoverflow.com/questions/18666128/what-is-pml4-short-for
    // REFER: https://www.pagetable.com/?p=14#post-14:~:text=256%20TB%20of%20address%20space%20seemed%20to%20be%20enough%20for%20now

    // NOTE: 4 Levels:
    //          1. Page Map Level 4 (PML4)
    //          2. Page Directory Pointer Table (PDPT)
    //          3. Page Directory Table (PDT)
    //          4. Page Table (PT)
    //             FINALLY the physical page is found :)

    // NOTE: Page Map Level 4 (PML4), basically it's just the way AMD decided to label page tables.
    uint64_t pml4_addr = 0x2000;  // 8 KB == pow(2,13) == 8192 byte position
    uint64_t *pml4 = (void *) (vm->mem + pml4_addr);

    // NOTE: Page Directory Pointer Table (PDPT)
    uint64_t pdpt_addr = 0x3000;  // 12 KB == 12288 byte position
    uint64_t *pdpt = (void *) (vm->mem + pdpt_addr);

    // NOTE: Page Directory (PD)
    uint64_t pd_addr = 0x4000;  // 16 KB == pow(2,14) == 16384 byte position
    uint64_t *pd = (void *) (vm->mem + pd_addr);

    printfdebug("Range of Guest Page Table addresses\n");
    printfdebug("    TableName                           = [Guest Physical Address Space) and [Host Virtual Address Space)\n");
    printfdebug("    Page Map Level 4 (PML4)             = [0x%lX, 0x%lX)               and [%p, %p)\n", pml4_addr, pml4_addr+sizeof(uint64_t), pml4, pml4+1);
    printfdebug("    Page Directory Pointer Table (PDPT) = [0x%lX, 0x%lX)               and [%p, %p)\n", pdpt_addr, pdpt_addr+sizeof(uint64_t), pdpt, pdpt+1);
    printfdebug("    Page Directory (PD)                 = [0x%lX, 0x%lX)               and [%p, %p)\n", pd_addr, pd_addr+sizeof(uint64_t), pd, pd+1);

    // NOTE: 0th bit ---> Present or not
    // NOTE: 1st bit ---> Read/Write (R/W) Bit. Bit 1. - if 0, writes may not be allowed
    // NOTE: 2nd bit ---> User/Supervisor (U/S) Bit. Bit 2. - If 0, user-mode access (ring 3) is not allowed
    // REFER: https://www.cs.albany.edu/~sdc/CSI500/Spr10/Classes/C15/intelpaging83-94.pdf
    //            Each page-directory entry contains a PS (page size) flag that specifies whether
    //            the entry points to a page table whose entries in turn point to 4-KByte pages (PS set to 0)
    //            or whether the page-directory entry points directly to a 4-MByte (PSE and PS set to 1) or
    //            2-MByte page(PAE and PS set to 1)
    //                NOTE: PAE and PSE bit are there in CR4 register
    //                NOTE: in the below code, PS bit (in Page Directory) and PAE bit (in CR4 register)
    pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;
    pdpt[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;
    pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS;  // NOTE: each entry points to 2 MBytes page (IMPORTANT)

    // REFER: https://en.wikipedia.org/wiki/Control_register   (IMPORTANT - CR0,CR1,...,CR7 and EFER registers)
    sregs->cr3 = pml4_addr;  // NOTE: CR3 points to Page Map Level 4 (PML4)
    sregs->cr4 = CR4_PAE;  // NOTE: in CR4 register only the "Physical Address Extension (PAE)" bit is set.
                           //           If set, changes page table layout to translate 32-bit virtual
                           //           addresses into extended 36-bit physical addresses.
    // NOTE: CR0 has various control flags that modify the basic operation of the processor
    sregs->cr0 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
    sregs->efer = EFER_LME | EFER_LMA;  // NOTE: LME (Long Mode Enable), LMA (Long Mode Active)

    setup_64bit_code_segment(sregs);
}

int run_long_mode(struct vm *vm, struct vcpu *vcpu) {
    struct kvm_sregs sregs;
    struct kvm_regs regs;

    printf("Testing 64-bit mode\n");

    if (ioctl(vcpu->fd, KVM_GET_SREGS, &sregs) < 0) {
        perror("KVM_GET_SREGS");
        exit(1);
    }

    setup_long_mode(vm, &sregs);

    if (ioctl(vcpu->fd, KVM_SET_SREGS, &sregs) < 0) {
        perror("KVM_SET_SREGS");
        exit(1);
    }

    // REFER: https://en.wikibooks.org/wiki/X86_Assembly/X86_Architecture
    memset(&regs, 0, sizeof(regs));
    /* Clear all FLAGS bits, except bit 1 which is always set. */
    regs.rflags = 2;
    regs.rip = 0;  // NOTE: Part A: This instruction sets the instruction pointer to 0
    /* Create stack at top of 2 MB page and grow down. */
    regs.rsp = 2 << 20;  // NOTE: Part A: Kernel stack is setup

    if (ioctl(vcpu->fd, KVM_SET_REGS, &regs) < 0) {
        perror("KVM_SET_REGS");
        exit(1);
    }

    // NOTE: Part A: the below line copies the guest code into the guest memory area
    printfdebug("Part A: range of code: [0, 0x%lX)\n", guest64_end - guest64);
    printfdebug("Part A: location of the code in hypervisor's virtual memory = %p\n", vm->mem);
    memcpy(vm->mem, guest64, guest64_end - guest64);
    return run_vm(vm, vcpu, 8);
}


int main(int argc, char **argv) {
    struct vm vm;
    struct vcpu vcpu;
    enum {
        REAL_MODE,
        PROTECTED_MODE,
        PAGED_32BIT_MODE,
        LONG_MODE,
    } mode = REAL_MODE;
    int opt;

    while ((opt = getopt(argc, argv, "rspl")) != -1) {
        switch (opt) {
            case 'r':
                mode = REAL_MODE;
                break;

            case 's':
                mode = PROTECTED_MODE;
                break;

            case 'p':
                mode = PAGED_32BIT_MODE;
                break;

            case 'l':
                mode = LONG_MODE;
                break;

            default:
                fprintf(stderr, "Usage: %s [ -r | -s | -p | -l ]\n",
                        argv[0]);
                return 1;
        }
    }

    vm_init(&vm, 0x200000);
    vcpu_init(&vm, &vcpu);

    switch (mode) {
        case REAL_MODE:
            return !run_real_mode(&vm, &vcpu);

        case PROTECTED_MODE:
            return !run_protected_mode(&vm, &vcpu);

        case PAGED_32BIT_MODE:
            return !run_paged_32bit_mode(&vm, &vcpu);

        case LONG_MODE:
            return !run_long_mode(&vm, &vcpu);
    }

    return 1;
}
