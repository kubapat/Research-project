#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <seccomp.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <errno.h>
#include <signal.h>

// 1. Execution initiation
void setup_seccomp_for_execution_initiation() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    seccomp_load(ctx);
}

// 2. Loading shared libraries
void setup_seccomp_for_loading_shared_libraries() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_load(ctx);
}

// 3. Memory and environment setup
void setup_seccomp_for_memory_and_environment_setup() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    seccomp_load(ctx);
}

// 4. Reading configuration and directories
void setup_seccomp_for_reading_configuration_and_directories() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcwd), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
    seccomp_load(ctx);
}

// 5. Output handling
void setup_seccomp_for_output_handling() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_load(ctx);
}

// 6. Error handling
void setup_seccomp_for_error_handling() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_load(ctx);
}

// 7. Process termination
void setup_seccomp_for_process_termination() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_load(ctx);
}

void detect_and_switch_phase(int phase) {
    switch (phase) {
        case 1:
            setup_seccomp_for_execution_initiation();
            break;
        case 2:
            setup_seccomp_for_loading_shared_libraries();
            break;
        case 3:
            setup_seccomp_for_memory_and_environment_setup();
            break;
        case 4:
            setup_seccomp_for_reading_configuration_and_directories();
            break;
        case 5:
            setup_seccomp_for_output_handling();
            break;
        case 6:
            setup_seccomp_for_error_handling();
            break;
        case 7:
            setup_seccomp_for_process_termination();
            break;
        default:
            fprintf(stderr, "Unknown phase: %d\n", phase);
            exit(EXIT_FAILURE);
    }
}

void trace_and_monitor(pid_t child_pid) {
    int status;
    int phase = 1;
    struct user_regs_struct regs;

    detect_and_switch_phase(phase);

    while (1) {
        waitpid(child_pid, &status, 0);

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            break;
        }

        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);

        switch (regs.orig_rax) {
            case SYS_execve:
                phase = 1;
                break;
            case SYS_access:
            case SYS_openat:
            case SYS_fstat:
            case SYS_mmap:
            case SYS_close:
                phase = 2;
                break;
            case SYS_arch_prctl:
            case SYS_mprotect:
            case SYS_munmap:
            case SYS_brk:
                phase = 3;
                break;
            case SYS_getcwd:
            case SYS_stat:
                phase = 4;
                break;
            case SYS_write:
                if (regs.rdi == 2) { // STDERR file descriptor
                    phase = 6;
                } else {
                    phase = 5;
                }
                break;
            case SYS_close:
            case SYS_exit_group:
                phase = 7;
                break;
            default:
                break;
        }

        detect_and_switch_phase(phase);

        ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
    }
}

int main(int argc, char *argv[]) {
    pid_t child_pid;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s /bin/pwd [args]\n", argv[0]);
        return EXIT_FAILURE;
    }

    child_pid = fork();

    if (child_pid == -1) {
        perror("fork");
        return EXIT_FAILURE;
    }

    if (child_pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execvp(argv[1], &argv[1]);
        perror("execvp");
        exit(EXIT_FAILURE);
    } else {
        trace_and_monitor(child_pid);
    }

    return EXIT_SUCCESS;
}
