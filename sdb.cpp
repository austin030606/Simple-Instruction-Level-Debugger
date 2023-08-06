#include <map>
#include <elf.h>
#include <vector>
#include <string>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#include <iomanip>
#include <fstream>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <iostream>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <unordered_map>
#include <capstone/capstone.h>
using namespace std;

bool hasAnchor = false;
struct user_regs_struct anchorRegs;
vector<pair<unsigned long, unsigned long> > writable;
vector<vector<unsigned char> > pages;
vector<unsigned long> breakpoints;
unordered_map<unsigned long, bool> isBreakpoint;
unordered_map<unsigned long, long> textAt;
unordered_map<unsigned long, cs_insn> insnAt;

void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}

static inline Elf64_Shdr *elf_sheader(Elf64_Ehdr *hdr) {
	return (Elf64_Shdr *)((long)hdr + hdr->e_shoff);
}
 
static inline Elf64_Shdr *elf_section(Elf64_Ehdr *hdr, int idx) {
	return &(elf_sheader(hdr)[idx]);
}

static inline char *elf_str_table(Elf64_Ehdr *hdr) {
	if(hdr->e_shstrndx == SHN_UNDEF) return NULL;
	return (char *)hdr + elf_section(hdr, hdr->e_shstrndx)->sh_offset;
}
 
static inline char *elf_lookup_string(Elf64_Ehdr *hdr, int offset) {
	char *strtab = elf_str_table(hdr);
	if(strtab == NULL) return NULL;
	return strtab + offset;
}

void peekBytes(pid_t pid, unsigned long addr, int size, unsigned char *buf, int bufsize) {
    for (int i = 0; i < bufsize; i++) 
        buf[i] = 0;
    for (int i = 0; i < size; i += 8) {
        unsigned long text = ptrace(PTRACE_PEEKTEXT, pid, addr + i, 0);
        for (int j = 0; j < 8; j++) {
            buf[i + j] = text & 0xff;
            text >>= 8;
        }
    }
}

vector<string> split(string str, char c) {
    vector<string> res;
    string cur = "";
    int size = str.size();
    for (int i = 0; i < size; i++) {
        if (str[i] == c) {
            if (cur != "") res.push_back(cur);
            cur = "";
        } else {
            cur.push_back(str[i]);
        }
    }
    if (cur != "") res.push_back(cur);
    return res;
}

void unsetBreakpoints(pid_t pid) {
    for (unsigned long i = 0; i < breakpoints.size(); i++) {
        unsigned long breakAddr = breakpoints[i];
        if (ptrace(PTRACE_POKETEXT, pid, breakAddr, (textAt[breakAddr] & 0xffffffffffffff00) | insnAt[breakAddr].bytes[0]) != 0) errquit("ptrace(POKETEXT)");
    }
}

void setBreakpoints(pid_t pid) {
    for (unsigned long i = 0; i < breakpoints.size(); i++) {
        unsigned long breakAddr = breakpoints[i];
        // fixed version is on e3
        if (ptrace(PTRACE_POKETEXT, pid, breakAddr, (textAt[breakAddr] & 0xffffffffffffff00) | 0xcc) != 0) errquit("ptrace(POKETEXT)");
    }
}

void snapPages(pid_t pid) {
    for (unsigned long k = 0; k < writable.size(); k++) {
        unsigned long start = writable[k].first, end = writable[k].second;
        unsigned long size = end - start;
        pages[k].resize(0);
        pages[k].resize(size, 0);
        for (unsigned long i = 0; i < size; i += 8) {
            unsigned long text = ptrace(PTRACE_PEEKTEXT, pid, start + i, 0);
            // if (i == 0x22bc0) cout << text << '\n';
            for (int j = 0; j < 8; j++) {
                pages[k][i + j] = text & 0xff;
                text >>= 8;
                // if (i == 0x22bc0) cout << (int)(pages[k][i + j]) << ' ';
            }
            // if (i == 0x22bc0) cout << '\n';
        }
    }
}

void resetPages(pid_t pid) {
    for (unsigned long k = 0; k < writable.size(); k++) {
        unsigned long start = writable[k].first, end = writable[k].second;
        unsigned long size = end - start;
        for (unsigned long i = 0; i < size; i += 8) {
            unsigned long text = 0;
            // cout << i << '\n';
            for (int j = 7; j >= 0; j--) {
                // cout << pages[k][i + j] << ' ';
                text |= pages[k][i + j];
                if (j != 0) text <<= 8;
            }
            // cout << '\n';
            // for (int j = 7; j >= 0; j--) {
            //     cout << (int)(pages[k][i + j]) << ' ';
            // }
            // cout << '\n' << text;
            // unsigned long tmp = ptrace(PTRACE_PEEKTEXT, pid, start + i, 0);
            // cout << '\n' << tmp << '\n' << '\n';
            ptrace(PTRACE_POKETEXT, pid, start + i, text);
        }
    }
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
        cout << "Usage: ./sdb [program]" << '\n';
        return 0;
    }
    setvbuf(stdin, nullptr, _IONBF, 0);
    // check elf for text segment address(assuming the program is static-nopie)
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) errquit("open");

    void *mem = mmap(NULL, lseek(fd, 0, SEEK_END), PROT_READ, MAP_PRIVATE, fd, 0);
    if (mem == MAP_FAILED) errquit("mmap");

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)mem;
    unsigned long textAddr, textSize;
    for (int i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr *curshdr = elf_section(ehdr, i);
        if (curshdr->sh_name == SHN_UNDEF) continue;
        char *sname = elf_lookup_string(ehdr, curshdr->sh_name);
        if (strcmp(sname, ".text") == 0) {
            textAddr = curshdr->sh_addr;
            textSize = curshdr->sh_size;
        }
    }

    pid_t child;
	if ((child = fork()) < 0) errquit("fork");
	if (child == 0) {
		if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace@child");
		execvp(argv[1], argv+1);
		errquit("execvp");
	} else {
        bool first = true;
        csh handle;
        cs_insn *insn;
        string command = "";
		int status;
        unsigned long nextAddr = textAddr, endAddr = textAddr + textSize;
        struct user_regs_struct regs;
		if (waitpid(child, &status, 0) < 0) errquit("waitpid");
		ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
        if (ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
        cout << "** program \'" << argv[1] << "\' loaded. entry point 0x" << hex << regs.rip << '\n';
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return -1;

        string path = "/proc/", line;
        path += to_string(child);
        path += "/maps";
        ifstream file(path);
        while (getline(file, line)) {
            vector<string> fields = split(line, ' ');
            if (fields[1][1] == 'w') {
                // find writable addresses
                vector<string> addresses = split(fields[0], '-');
                unsigned long start, end;
                start = stol(addresses[0], 0, 16);
                end = stol(addresses[1], 0, 16);
                writable.push_back({start, end});
                // cout << start << ' ' << end << ' ' << fields[1] << '\n';
            }
        }
        pages.resize(writable.size());
        
        do {
            // get arguments
            vector<string> arguments;
            arguments = split(command, ' ');
            if (!first) {
                if (arguments.size() == 0 || arguments.size() > 2) {
                    cout << "(sdb) ";
                    first = false;
                    continue;
                }
                command = arguments[0];
            }
            // command handling
            if (command == "si" && arguments.size() == 1) {
                ptrace(PTRACE_SINGLESTEP, child, 0, 0);
                if (waitpid(child, &status, 0) < 0) errquit("waitpid");
                if (WIFEXITED(status)) {
                    cout << "** the target program terminated.\n";
                    break;
                }
                if (ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
                // cout << "rip after si: " << regs.rip << '\n';
                nextAddr = regs.rip;
                if (isBreakpoint[nextAddr]) {
                    cout << "** hit a breakpoint at 0x" << nextAddr << ".\n";
                }
            } else if (command == "cont" && arguments.size() == 1) {
                ptrace(PTRACE_SINGLESTEP, child, 0, 0);
                if (waitpid(child, &status, 0) < 0) errquit("waitpid");
                if (WIFEXITED(status)) {
                    cout << "** the target program terminated.\n";
                    break;
                }
                setBreakpoints(child);
                ptrace(PTRACE_CONT, child, 0, 0);
                if (waitpid(child, &status, 0) < 0) errquit("waitpid");
                if (WIFEXITED(status)) {
                    cout << "** the target program terminated.\n";
                    break;
                }
                unsetBreakpoints(child);
                if (ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
                // cout << "rip after si: " << regs.rip << '\n';
                nextAddr = regs.rip - 1;
                if (isBreakpoint[nextAddr]) {
                    cout << "** hit a breakpoint at 0x" << nextAddr << ".\n";
                    regs.rip--;
                    if (ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) errquit("ptrace(SETREGS)");
                }
            } else if (command == "break" && arguments.size() == 2) {
                string tmp = arguments[1];
                if (!isxdigit(tmp[0])) {
                    cout << "(sdb) ";
                    first = false;
                    continue;
                }
                unsigned long breakAddr = stol(tmp, 0, 16);
                if (breakAddr < textAddr || breakAddr >= endAddr) {
                    cout << "(sdb) ";
                    first = false;
                    continue;
                }
                // cout << "break address: " << breakAddr << '\n';
                textAt[breakAddr] = ptrace(PTRACE_PEEKTEXT, child, breakAddr, 0);
                isBreakpoint[breakAddr] = true;
                size_t count = 0;
                unsigned char buf[25] = {0};
                peekBytes(child, breakAddr, 20, buf, 25);
                count = cs_disasm(handle, (const uint8_t*)buf, 20, nextAddr, 1, &insn);
                insnAt[breakAddr] = insn[0];
                cs_free(insn, count);
                breakpoints.push_back(breakAddr);
                // if (ptrace(PTRACE_POKETEXT, child, breakAddr, (textAt[breakAddr] & 0xffffffffffffff00) | 0xcc) != 0) errquit("ptrace(POKETEXT)");
                cout << "** set a breakpoint at 0x" << breakAddr << ".\n";
            } else if (command == "anchor" && arguments.size() == 1){
                hasAnchor = true;
                if (ptrace(PTRACE_GETREGS, child, 0, &anchorRegs) != 0) errquit("ptrace(GETREGS)");
                snapPages(child);
                cout << "** dropped an anchor\n";
            } else if (command == "timetravel" && arguments.size() == 1 && hasAnchor){
                if (ptrace(PTRACE_SETREGS, child, 0, &anchorRegs) != 0) errquit("ptrace(GETREGS)");
                resetPages(child);
                cout << "** go back to the anchor point\n";
                if (ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
                // cout << "rip: " << regs.rip << '\n';
                nextAddr = regs.rip;
            } else {
                if (ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace(GETREGS)");
                // cout << "rip: " << regs.rip << '\n';
                nextAddr = regs.rip;
            }

            // if it's one of these cases, show disassembly
            if ((command == "si" && arguments.size() == 1) || (command == "cont" && arguments.size() == 1) || command == "timetravel" || first) {
                // disassemble
                size_t count = 0;
                unsigned char buf[80] = {0};
                peekBytes(child, nextAddr, 75, buf, 80);
                count = cs_disasm(handle, (const uint8_t*)buf, 75, nextAddr, 5, &insn);
                for (size_t i = 0; i < count; i++) {
                    // print address
                    if (insn[i].address >= endAddr) {
                        cout << "** the address is out of the range of the text section.\n";
                        break;
                    }
                    cout << '\t' << insn[i].address << ":";
                    // print bytes
                    for (int j = 0; j < insn[i].size; j++) {
                        cout << ' ' << setw(2) << setfill('0') << (int)insn[i].bytes[j];
                    }
                    int tmp = insn[i].size;
                    while (tmp < 12) {
                        cout << '\t';
                        tmp += 3;
                    }
                    cout << insn[i].mnemonic << '\t' << insn[i].op_str << '\n';
                }
                cs_free(insn, count);
            }
            cout << "(sdb) ";
            first = false;
        } while (getline(cin, command));
	}
	return 0;
}