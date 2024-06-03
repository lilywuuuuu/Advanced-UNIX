#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace std;

int child_pid = -1;
uintptr_t text_section_end = 0;
uintptr_t entry_point = 0;
uintptr_t cur_addr;
vector<uintptr_t> breakpoints;
vector<long> original_data;
size_t inst_count;
bool loaded = false;
bool is_entering = true;
uintptr_t bp = 0;
int track = 0;

void print_load_program() {
    printf("** please load a program first.\n");
}

void print_program_terminated() {
    printf("** the target program terminated.\n");
}

vector<string> split(const string &str) {
    istringstream iss(str);
    vector<string> tokens;
    string token;
    while (iss >> token) {
        tokens.push_back(token);
    }
    return tokens;
}

void error(const string &msg) {
    cerr << "** error: " << msg << endl;
}

uintptr_t get_entry_point(const string &path) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd == -1) {
        return 0;
    }

    Elf64_Ehdr ehdr;
    read(fd, &ehdr, sizeof(ehdr));

    close(fd);
    return ehdr.e_entry;
}

void get_text_section_end(const char *program_path) {
    int fd = open(program_path, O_RDONLY);

    Elf64_Ehdr ehdr;
    Elf64_Shdr shdr;
    read(fd, &ehdr, sizeof(ehdr));
    lseek(fd, ehdr.e_shoff, SEEK_SET);

    for (int i = 0; i < ehdr.e_shnum; i++) {
        read(fd, &shdr, sizeof(shdr));
        if (shdr.sh_type == SHT_PROGBITS && (shdr.sh_flags & SHF_EXECINSTR)) {
            close(fd);
            text_section_end = shdr.sh_addr + shdr.sh_size;
            return;
        }
    }
    close(fd);
    fprintf(stderr, "Executable section not found\n");
    exit(EXIT_FAILURE);
}

void disassemble(uintptr_t addr, int length) {
    csh handle;
    cs_insn *insn;
    size_t count;
    uint8_t code[15 * length];

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return;
    }

    for (int i = 0; i < length * 15; i += 8) {
        *(long *)(code + i) = ptrace(PTRACE_PEEKDATA, child_pid, addr + i, NULL);
    }

    // printf("Code bytes at %lx:\n", addr);
    // for (size_t i = 0; i < sizeof(code); i++) {
    //     printf("%02x ", code[i]);
    // } printf("\n");

    // cs_opt_skipdata skipdata = {
    //     .mnemonic = "db",
    //     .callback = NULL,
    //     .user_data = NULL
    // };
    // cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    // cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    // cs_option(handle, CS_OPT_SKIPDATA_SETUP, (size_t)&skipdata);

    for (size_t i = 0; i<sizeof(code); i++){
        if (code[i] == 0xcc){
            for (size_t j = 0; j<breakpoints.size(); j++){
                if (breakpoints[j] == addr + i){
                    code[i] = original_data[j] & 0xff;
                }
            }
        }
    }

    count = cs_disasm(handle, code, sizeof(code), addr, length, &insn);
    if (count > 0) {
        for (size_t i = 0; i < count; i++) { 
            if (insn[i].address >= text_section_end) {
                printf("** the address is out of the range of the text section.\n");
                break;
            }

            printf("      %lx: ", insn[i].address);
            for (int j = 0; j < insn[i].size; j++) {
                printf("%02x ", insn[i].bytes[j]);
            }
            for (int j = insn[i].size; j < 12; j++) {
                printf("   ");
            }
            printf("%-10s %s\n", insn[i].mnemonic, insn[i].op_str);
        }
        cs_free(insn, count);
    } else {
        cs_err err = cs_errno(handle);
        if (err != 0)
            printf("** CS Error: %s\n", cs_strerror(err));
        else
            print_program_terminated();
    }

    cs_close(&handle);
}

void handle_load(const string &path) {
    if (child_pid != -1) {
        error("a program is already loaded");
        return;
    }

    entry_point = get_entry_point(path);
    if (entry_point == 0) {
        error("failed to get entry point");
        return;
    }
    get_text_section_end(path.c_str());

    child_pid = fork();
    if (child_pid == 0) {
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        execl(path.c_str(), path.c_str(), nullptr);
        perror("execl");
        exit(1);
    } else {
        waitpid(child_pid, nullptr, 0);
        printf("** program '%s' loaded. entry point 0x%lx.\n", path.c_str(), entry_point);
        disassemble(entry_point, 5);
        loaded = true;
    }
}

long set_breakpoint(uintptr_t addr) {
    long original = ptrace(PTRACE_PEEKDATA, child_pid, addr, NULL);
    ptrace(PTRACE_POKEDATA, child_pid, addr, (original & ~0xff) | 0xcc);
    return original;
}

void handle_break(uintptr_t addr) {
    printf("** set a breakpoint at 0x%lx.\n", addr);
    long original = set_breakpoint(addr);
    breakpoints.push_back(addr);
    original_data.push_back(original);

}

void delete_break(size_t index) {
    if (index >= breakpoints.size() || breakpoints[index] == 0) {
        printf("** breakpoint %ld does not exist.\n", index);
        return;
    }
    long cur = ptrace(PTRACE_PEEKDATA, child_pid, breakpoints[index], NULL);
    ptrace(PTRACE_POKEDATA, child_pid, breakpoints[index], (cur & ~0xff) | original_data[index]);
    printf("** delete breakpoint %ld.\n", index);
    breakpoints[index] = 0;
}

void handle_info_break() {
    bool no_break = true; 
    for (size_t i=0; i<breakpoints.size(); i++){
        if (breakpoints[i] != 0) no_break = false;
    }
    if (no_break) {
        printf("** no breakpoints.\n");
        return;
    }

    cout << "Num\tAddress" << endl;
    for (size_t i = 0; i < breakpoints.size(); i++) {
        if (breakpoints[i] == 0) continue;
        cout << i << "\t0x" << hex << breakpoints[i] << endl;
    }
}

void process_breakpoint(uintptr_t rip) {
    printf("** hit a breakpoint at 0x%lx.\n", rip);

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

    // find original instruction at breakpoint address and restore it
    long cur_binary = ptrace(PTRACE_PEEKDATA, child_pid, rip, NULL);
    for (size_t j = 0; j<breakpoints.size(); j++){
        if (breakpoints[j] == rip){
            ptrace(PTRACE_POKEDATA, child_pid, rip, (cur_binary & ~0xff) | original_data[j]);
            break;
        }
    }
    // ptrace(PTRACE_POKEDATA, child_pid, rip, (cur_binary & ~0xff) | instructions[i].bytes[0]);
    ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
    waitpid(child_pid, NULL, 0);
    track = 1;
    bp = rip;
    regs.rip = rip;

    // cout << "RIP: " << hex << regs.rip << endl;
    ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

    // cout << "RIP: " << hex << regs.rip << endl;
}

void check_breakpoint() {
    if (bp) {
        if (track)
            track--;
        else {
            set_breakpoint(bp);
            bp = 0;
        }
    }
}

void handle_patch(uintptr_t addr, uint64_t value, size_t len) {
    uint64_t mask = (1ULL << (len * 8)) - 1;
    long cur = ptrace(PTRACE_PEEKDATA, child_pid, addr, NULL);
    value = (cur & ~mask) | value;
    ptrace(PTRACE_POKEDATA, child_pid, addr, value);
    printf("** patch memory at address 0x%lx.\n", addr);
    // check if the patch was a breakpoint
    for (size_t i = 0; i < len; i++) {
        if (((cur >> (i * 8)) & 0xFF) == 0xCC) {
            set_breakpoint(addr + i);
        }
    }
}

void handle_si() {
    check_breakpoint();

    ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
    waitpid(child_pid, NULL, 0);

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

    uintptr_t rip = regs.rip;
    // cout << "RIP: " << hex << rip << endl;
    auto it = find(breakpoints.begin(), breakpoints.end(), rip);
    if (it != breakpoints.end()) {
        process_breakpoint(rip);
    }
    disassemble(rip, 5);
    cur_addr = rip;
}

void handle_cont() {
    check_breakpoint();

    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    int status;
    waitpid(child_pid, &status, 0);

    // Check if the child process hit a breakpoint
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        // Get the current instruction pointer
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

        // cout << "RIP: " << hex << regs.rip << endl;
        process_breakpoint(regs.rip - 1);
        disassemble(regs.rip - 1, 5);

    } else if (WIFEXITED(status)) {
        print_program_terminated();
    }
}

void handle_syscall() {
    check_breakpoint();

    int status;
    ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
    waitpid(child_pid, &status, 0);

    if (WIFSTOPPED(status)) {
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        // cout << "RIP: " << hex << regs.rip << endl;
        // cout << "regs.orig_rax: " << regs.orig_rax << endl;
        if (regs.orig_rax > 300) {  // breakpoint
            process_breakpoint(regs.rip - 1);
            disassemble(regs.rip - 1, 5);
        } else if (is_entering) {  // entering syscall
            printf("** enter a syscall(%lld) at 0x%llx.\n", regs.orig_rax, regs.rip - 2);
            disassemble(regs.rip - 2, 5);
            is_entering = false;
        } else {  // leaving syscall
            printf("** leave a syscall(%lld) = %lld at 0x%llx.\n", regs.orig_rax, regs.rax, regs.rip - 2);
            disassemble(regs.rip - 2, 5);
            is_entering = true;
        }
    } else if (WIFEXITED(status)) {
        print_program_terminated();
    }
}

void handle_info_reg() {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

    printf("$rax 0x%016llx    $rbx 0x%016llx    $rcx 0x%016llx\n", regs.rax, regs.rbx, regs.rcx);
    printf("$rdx 0x%016llx    $rsi 0x%016llx    $rdi 0x%016llx\n", regs.rdx, regs.rsi, regs.rdi);
    printf("$rbp 0x%016llx    $rsp 0x%016llx    $r8  0x%016llx\n", regs.rbp, regs.rsp, regs.r8);
    printf("$r9  0x%016llx    $r10 0x%016llx    $r11 0x%016llx\n", regs.r9, regs.r10, regs.r11);
    printf("$r12 0x%016llx    $r13 0x%016llx    $r14 0x%016llx\n", regs.r12, regs.r13, regs.r14);
    printf("$r15 0x%016llx    $rip 0x%016llx    $eflags 0x%016llx\n", regs.r15, regs.rip, regs.eflags);
}

void handle_command(const string &cmd) {
    auto tokens = split(cmd);
    if (tokens.empty()) return;

    const string &command = tokens[0];
    if (command == "load") {
        if (tokens.size() != 2) {
            cout << "usage: load <path to file>" << endl;
            return;
        }
        handle_load(tokens[1]);
    } else if (command == "si") {
        if (!loaded) {
            print_load_program();
            return;
        }
        handle_si();
    } else if (command == "cont") {
        if (!loaded) {
            print_load_program();
            return;
        }
        handle_cont();
    } else if (command == "info") {
        if (!loaded) {
            print_load_program();
            return;
        }
        if (tokens.size() != 2) {
            cout << "usage: info <reg | break>" << endl;
            return;
        }
        if (tokens[1] == "reg")
            handle_info_reg();
        else if (tokens[1] == "break")
            handle_info_break();
        else
            cout << "usage: info <reg | break>" << endl;

    } else if (command == "break") {
        if (!loaded) {
            print_load_program();
            return;
        }
        if (tokens.size() != 2) {
            cout << "usage: break <hex address>" << endl;
            return;
        }
        try {
            if (tokens[1].find_first_not_of("0123456789abcdefABCDEF", 2) != string::npos) {
                throw out_of_range("Invalid hex number");
            } else if (tokens[1] == "0x") {
                throw out_of_range("Invalid hex number");
            }
            uintptr_t addr = stoul(tokens[1], NULL, 16);
            handle_break(addr);
        } catch (const exception &e) {
            cout << "usage: break <hex address>" << endl;
            return;
        }
    } else if (command == "delete") {
        if (!loaded) {
            print_load_program();
            return;
        }
        if (tokens.size() != 2) {
            cout << "usage: delete <id>" << endl;
            return;
        }
        size_t index = stoul(tokens[1]);
        delete_break(index);
    } else if (command == "patch") {
        if (!loaded) {
            print_load_program();
            return;
        }
        if (tokens.size() != 4) {
            cout << "usage: patch <hex address> <hex value> <len>" << endl;
        }
        uintptr_t addr = stoul(tokens[1], nullptr, 16);
        uint64_t value = stoull(tokens[2], nullptr, 16);
        size_t len = stoul(tokens[3]);
        handle_patch(addr, value, len);
    } else if (command == "syscall") {
        if (!loaded) {
            print_load_program();
            return;
        }
        handle_syscall();
    } else {
        cout << "unkown command." << endl;
    }
}

int main(int argc, char *argv[]) {
    string path;
    if (argc == 2) {
        path = argv[1];
        handle_load(path);
    }

    while (true) {
        printf("(sdb) ");

        string cmd;
        getline(cin, cmd);

        handle_command(cmd);
    }

    return 0;
}
