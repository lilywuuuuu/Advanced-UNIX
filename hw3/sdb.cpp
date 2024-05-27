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
uintptr_t entry_point = 0;
uintptr_t cur_addr;
vector<uintptr_t> breakpoints;
vector<long> original_data;
cs_insn *instructions;
size_t inst_count;
bool loaded = false;

void print_prompt() {
    printf("(sdb) ");
}

void print_load_program() {
    printf("** please load a program first.\n");
}

void print_out_of_range() {
    printf("** the address is out of the range of the text section.\n");
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

void save_instructions(uintptr_t addr) {
    csh handle;
    uint8_t code[15 * 20];

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return;
    }

    for (int i = 0; i < 15 * 20; i += 8) {
        *(long *)(code + i) = ptrace(PTRACE_PEEKDATA, child_pid, addr + i, NULL);
    }

    inst_count = cs_disasm(handle, code, sizeof(code), addr, 0, &instructions);
    cs_close(&handle);
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
    // for (int i = 0; i < sizeof(code); i++) {
    //     printf("%02x ", code[i]);
    // } printf("\n");

    count = cs_disasm(handle, code, sizeof(code), addr, length * 2, &insn);
    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            if ((int)i == length) break;
            if (insn[i].size == 2 && insn[i].bytes[0] == 0 && insn[i].bytes[1] == 0) {
                print_out_of_range();
                break;
            }
            if (insn[i].size == 1 && insn[i].bytes[0] == 0xcc) {
                for (size_t j = 0; j < inst_count; j++) {
                    if (instructions[j].address == insn[i].address) {
                        printf("      %lx: ", insn[i].address);
                        for (int k = 0; k < instructions[j].size; k++) {
                            printf("%02x ", instructions[j].bytes[k]);
                        }
                        for (int k = instructions[j].size; k < 15; k++) {
                            printf("   ");
                        }
                        printf("%-10s %s\n", instructions[j].mnemonic, instructions[j].op_str);
                        if (instructions[j].size != 1) {
                            i++;
                            length++;
                        }
                        break;
                    }
                }
                continue;
            }
            printf("      %lx: ", insn[i].address);
            for (int j = 0; j < insn[i].size; j++) {
                printf("%02x ", insn[i].bytes[j]);
            }
            for (int j = insn[i].size; j < 15; j++) {
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
    }
    save_instructions(entry_point);
    loaded = true;
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

void handle_info_break() {
    if (breakpoints.empty()) {
        cout << "** no breakpoints." << endl;
        return;
    }

    cout << "Num \t Address" << endl;
    for (size_t i = 0; i < breakpoints.size(); i++) {
        cout << i << "\t 0x" << hex << breakpoints[i] << endl;
    }
}

void handle_delete_break(size_t index) {
    if (index >= breakpoints.size()) {
        printf("** breakpoint %ld does not exist.\n", index);
        return;
    }
    breakpoints.erase(breakpoints.begin() + index);
    printf("** delete breakpoint %ld.\n", index);
}

void process_breakpoint(uintptr_t rip) {
    printf("** hit a breakpoint at 0x%lx\n", rip);

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

    for (size_t i = 0; i < inst_count; i++) {
        if (instructions[i].address == rip) {
            if (instructions[i].size != 1) {
                regs.rip++;
                ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
                break;
            }
        }
    }
}

void handle_patch(uintptr_t addr, uint64_t value, size_t len) {
    ptrace(PTRACE_POKEDATA, child_pid, addr, value);
    cout << len << endl;
    printf("** patch memory at address 0x%lx.\n", addr);
}

void handle_si() {
    ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
    waitpid(child_pid, NULL, 0);

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

    uintptr_t rip = regs.rip;
    cout << "RIP: " << hex << rip << endl;
    auto it = find(breakpoints.begin(), breakpoints.end(), rip);
    if (it != breakpoints.end()) {
        process_breakpoint(rip);
    }
    disassemble(rip, 5);
    cur_addr = rip; 
}

void handle_cont() {
    // Continue the execution of the child process
    if (ptrace(PTRACE_CONT, child_pid, NULL, NULL) == -1) {
        perror("ptrace");
        return;
    }

    // Wait for the child process to stop
    int status;
    if (waitpid(child_pid, &status, 0) == -1) {
        perror("waitpid");
        return;
    }

    // Check if the child process hit a breakpoint
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        // Get the current instruction pointer
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        uintptr_t rip = regs.rip;

        cout << "RIP: " << hex << regs.rip << endl;
        auto it = find(breakpoints.begin(), breakpoints.end(), rip);
        if (it != breakpoints.end()) {
            process_breakpoint(rip);
            disassemble(rip, 5);
        }

        // // Check if the instruction pointer is at the breakpoint address
        // for (size_t i = 0; i < breakpoints.size(); i++) {
        //     if (regs.rip == breakpoints[i] + 1) {
        //         process_breakpoint(breakpoints[i]);
        //         disassemble(breakpoints[i], 5);
        //         break;
        //     }
        // }
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

void handle_syscall() {
    // Implement syscall functionality similar to si and cont.
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
        handle_delete_break(index);
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
        print_prompt();

        string cmd;
        getline(cin, cmd);

        handle_command(cmd);
    }

    return 0;
}
