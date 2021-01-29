# Answers to Question asked in the Assignment

- Fact: virtual address space of the host is the same as virtual address space of the hypervisor process
- Search for all statements having the words `DEBUG` and `NOTE` to get answers to the below questions.
- **IMPORTANT** - write answers to TODO
    * i.e. Help required
- Primary Reference:
    - https://en.wikibooks.org/wiki/X86_Assembly/X86_Architecture
    - https://en.wikipedia.org/wiki/Control_register
    - https://lwn.net/Articles/658511/

---

[comment]: <> (NOTE: the virtual address space of host and hypervisor are one and the same thing)

### Part A
What is the size of the guest memory (that the guest perceives as its physical memory) that is setup in the function vm_init? How and where in the hyprevisor code is this guest memory allocated from the host OS? At what virtual address is this memory mapped into the virtual address space of this simple hypervisor? (Note that the address returned by mmap is a host virtual address.)
- Q1: What is the size of the guest memory (that the guest perceives as its physical memory) that is setup in the function vm_init? How and where in the hypervisor code is this guest memory allocated from the host OS? At what virtual address is this memory mapped into the virtual address space of this simple hypervisor? (Note that the address returned by mmap is a host virtual address.)
    - `0x200000 == 2097152 == pow(2,21) == 2 MB` bytes of memory is allocated as the RAM for the guest
    - Memory is allocated using the `mmap` function call. In the hypervisor code, Refer: `NOTE: Part A: Guest memory is allocated from the below line of the host OS`
    - Refer: `virtual address space of the simple hypervisor at which 'vm->mem' is mapped`

- Q2: Besides the guest memory, every VCPU also allocates a small portion of VCPU runtime memory from the host OS in the function , to store the information it has to exchange with KVM. In which lines of the program is this memory allocated, what is its size, and where is it located in the virutal address space of the hypervisor?
    - Refer `NOTE: Part A: The below line allocates a small portion of VCPU runtime memory from` to get the line which allocates the memory
    - Size of the memory allocated = `12288 Bytes = 12 KB`
        - Refer: `Part A: 'vcpu_mmap_size'`
    - Refer: `Part A: VCPU runtime memory location in virutal address space of the hypervisor`

- Q3: The guest memory area is formatted to contain the guest code (which is made available as an extern char array in the executable), the guest page table, and a kernel stack. Can you identify where in the code each of these is setup? What range of addresses do each of these occupy, in the guest physical address space, and the host virtual address space? That is, can you visualize the physical address space of the guest VM, as well as the virtual address space of the host user process that is setting up the VM?
    - Refer: `NOTE: Part A: the below line copies the guest code into the guest memory area`
        - Refer: `Part A: range of code`
        - The guest code starts from the address 0 in the guest's physical address space.
            - Refer: `NOTE: This line ensure that the memory block pointed to by`
    - Refer: `NOTE: Part A: setup the guest page table`
        - Guest Page Table occupies the range `[0x2000 to 0x5000)` in the guest physical address space
    - Refer: `NOTE: Part A: Kernel stack is setup`
        - Stack is created at the top of the 2 MB page and grow down. Initially the Kernel Stack is empty.
    - Refer: `Range of Guest Page Table addresses`

- Q4: A more detailed study of the code will help you understand the structure of the guest page table, and how the guest virtual address space is mapped to its physical address space using its page table. How many levels does the guest page table have in long mode? How many pages does it occupy? What are the (guest) virutal-to-physical mappings setup in the guest page table? What parts of the guest virtual address space is mapped by this page table? Can you visualize the page table structure and the address translation in the guest?
    - Guest page table has `3 levels`
        - 48 bit address is translated using the following scheme: 9 bits table 1, 9 bits table 2, 9 bits table 3, 21 bits inside the page
    - It occupies only 1 page because each page is of `2 MBytes page` and size of PML4, PDPT and PDT is just `3 * sizeof(uint64_t) = 3 * 8 = 24 Bytes`
    - The guest page table setup is such that virtual address and physical address point to the same memory in the guest memory (i.e. guest RAM)
    - The full guest memory (i.e. 2MB guest RAM) is mapped by the page table because it sets the limit to `0xffffffff` and only the lower 21 bits can be non-zero
        - Refer: `static void setup_64bit_code_segment(struct kvm_sregs *sregs)`

- Q5: At what (guest virtual) address does the guest start execution when it runs? Where is this address configured?
    - The guest starts its execution at guest virtual address 0
    - Refer: `NOTE: Part A: This instruction sets the instruction pointer to 0`
    - Refer: `NOTE: Part A: this line tells the guest that the Code Segment`
    
- Q6: At which line in the hypervisor program does the control switch from running the hypervisor to running the guest? At which line does the control switch back to the hypervisor from the guest?
    - Refer: `NOTE: Part A: the below statement switch the control from running the hypervisor to running the guest`

- Q7: Can you fully understand how the "Hello, world!" string is printed out by the guest via the hypervisor? What port number is used for this communication? How can you read the port number and the value written to the port within the hypervisor? Which memory buffer is used to communicate the value written by the guest to the hypervisor? How many exits (from guest to hypervisor) are required to print out the complete string?
    - The [`guest.c`](./guest.c) file uses a `for loop` (at line 14) to print each character on the port `0xE9` which causes exit to the hypervisor.
    - The value written to the port is read using `((char *) vcpu->kvm_run) + vcpu->kvm_run->io.data_offset` and the length is known using `vcpu->kvm_run->io.size`
    - The memory allocated in `vcpu_init` is used as a buffer to communicate the value written by the guest to the hypervisor.
        - Refer: `Part A: VCPU runtime memory location in virutal address space of the hypervisor`
    - Refer: `printfdebug("Port number used for IO = %d (i.e. 0x%X)\n", 0xE9, 0xE9);`
- Q8: Can you figure out what's happening with the number 42? Where is it written in the guest and where is it read out in the hypervisor?
    - The number 42 is written to `0x400 = 1024 Bytes` in guests virtual memory by `guest.c` at line 17
    - Refer: `Part A: the below line reads the value 42`
 
---

### Part B
- two

---

### Part C
- three