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
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 0);
    seccomp_load(ctx);
}

// 2. Loading shared libraries
void setup_seccomp_for_loading_shared_libraries() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    seccomp_load(ctx);
}

// 3. Reading configuration files
void setup_seccomp_for_reading_configuration_files() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pread64), 0);
    seccomp_load(ctx);
}

// 4. Initializing logging
void setup_seccomp_for_initializing_logging() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
    seccomp_load(ctx);
}

// 5. Setting up worker processes
void setup_seccomp_for_setting_up_worker_processes() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(umask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socketpair), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
    seccomp_load(ctx);
}

// 6. Opening necessary files and directories
void setup_seccomp_for_opening_necessary_files_and_directories() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents64), 0);
    seccomp_load(ctx);
}

// 7. Creating and configuring sockets
void setup_seccomp_for_creating_and_configuring_sockets() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsockopt), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(bind), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(listen), 0);
    seccomp_load(ctx);
}

// 8. Setting up signal handlers
void setup_seccomp_for_setting_up_signal_handlers() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
    seccomp_load(ctx);
}

// 9. Worker process initialization
void setup_seccomp_for_worker_process_initialization() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setgid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 0);
    seccomp_load(ctx);
}

// 10. Entering event loop
void setup_seccomp_for_entering_event_loop() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_create), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(eventfd2), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_ctl), 0);
    seccomp_load(ctx);
}

// 11. Accepting and serving requests
void setup_seccomp_for_accepting_and_serving_requests() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_wait), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettimeofday), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept4), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsockopt), 0);
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
            setup_seccomp_for_reading_configuration_files();
            break;
        case 4:
            setup_seccomp_for_initializing_logging();
            break;
        case 5:
            setup_seccomp_for_setting_up_worker_processes();
            break;
        case 6:
            setup_seccomp_for_opening_necessary_files_and_directories();
            break;
        case 7:
            setup_seccomp_for_creating_and_configuring_sockets();
            break;
        case 8:
            setup_seccomp_for_setting_up_signal_handlers();
            break;
        case 9:
            setup_seccomp_for_worker_process_initialization();
            break;
        case 10:
            setup_seccomp_for_entering_event_loop();
            break;
        case 11:
            setup_seccomp_for_accepting_and_serving_requests();
            break;
        default:
            fprintf(stderr, "Invalid phase: %d\n", phase);
            exit(EXIT_FAILURE);
    }
}

void trace_and_monitor(pid_t child) {
    int status;
    struct user_regs_struct regs;
    int current_phase = 1;

    waitpid(child, &status, 0);

    if (WIFEXITED(status))
        return;

    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);

    while (1) {
        ptrace(PTRACE_SYSCALL, child, 0, 0);
        waitpid(child, &status, 0);
        if (WIFEXITED(status)) break;

        ptrace(PTRACE_GETREGS, child, 0, &regs);

        switch (regs.orig_rax) {
            case SYS_execve:
                if (current_phase == 1) {
                    detect_and_switch_phase(2);
                    current_phase = 2;
                }
                break;
            case SYS_access:
            case SYS_openat:
                if (current_phase == 2) {
                    detect_and_switch_phase(3);
                    current_phase = 3;
                }
                break;
            case SYS_pread64:
                if (current_phase == 3) {
                    detect_and_switch_phase(4);
                    current_phase = 4;
                }
                break;
            case SYS_futex:
                if (current_phase == 4) {
                    detect_and_switch_phase(5);
                    current_phase = 5;
                }
                break;
            case SYS_clone:
                if (current_phase == 5) {
                    detect_and_switch_phase(6);
                    current_phase = 6;
                }
                break;
            case SYS_getdents64:
                if (current_phase == 6) {
                    detect_and_switch_phase(7);
                    current_phase = 7;
                }
                break;
            case SYS_socket:
                if (current_phase == 7) {
                    detect_and_switch_phase(8);
                    current_phase = 8;
                }
                break;
            case SYS_rt_sigaction:
                if (current_phase == 8) {
                    detect_and_switch_phase(9);
                    current_phase = 9;
                }
                break;
            case SYS_setgid:
            case SYS_setuid:
            case SYS_prctl:
                if (current_phase == 9) {
                    detect_and_switch_phase(10);
                    current_phase = 10;
                }
                break;
            case SYS_epoll_create:
            case SYS_eventfd2:
            case SYS_epoll_ctl:
                if (current_phase == 10) {
                    detect_and_switch_phase(11);
                    current_phase = 11;
                }
                break;
            case SYS_epoll_wait:
            case SYS_gettimeofday:
            case SYS_accept4:
            case SYS_recvfrom:
            case SYS_stat:
            case SYS_writev:
            case SYS_write:
            case SYS_setsockopt:
                if (current_phase == 11) {
                    // No next phase
                }
                break;
            default:
                break;
        }

        ptrace(PTRACE_SYSCALL, child, 0, 0);
        waitpid(child, &status, 0);
        if (WIFEXITED(status))
            break;
    }
}


int main(void) {
    pid_t child = fork();
    if (child == 0) { // Child process
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execl("/usr/sbin/nginx", "nginx", (char *)NULL);
    } else if (child > 0) { // Parent process
        trace_and_monitor(child);
    } else {
        // Fork failed
        perror("fork");
        exit(EXIT_FAILURE);
    }

    return 0;
}
