#include <iostream>
#include <sched.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <fstream>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>

#define CGROUP_FOLDER "/sys/fs/cgroup/pids/container/"
#define concat(a,b) (a"" b)

#define errExit(msg) \    
do { perror(msg); exit(EXIT_FAILURE); \
} while (0)

#define fatal_error(...) \
do { \
    fprintf(stderr, "namespace_test \033[1;31merror:\033[0m "); \
    fprintf(stderr, __VA_ARGS__ ); \
    fprintf(stderr, "\n"); \
    exit(EXIT_FAILURE); \
} while(0)

struct child_args {
    char **argv; 
    int pipe_fd[2];  
};

static void proc_setgroups_write(pid_t child_pid, char *str)
{
    char setgroups_path[PATH_MAX];
    int fd;

    snprintf(setgroups_path, PATH_MAX, "/proc/%jd/setgroups",
            (intmax_t) child_pid);

    fd = open(setgroups_path, O_RDWR);

    if (fd == -1) {
        if (errno != ENOENT)
            fprintf(stderr, "ERROR: open %s: %s\n", setgroups_path,
                strerror(errno));
        return;
    }

    if (write(fd, str, strlen(str)) == -1)
        fprintf(stderr, "ERROR: write %s: %s\n", setgroups_path,
            strerror(errno));

    close(fd);
}

static void update_map(char *mapping, char *map_file)
{
    int fd;
    size_t map_len;

    map_len = strlen(mapping);
    for (int j = 0; j < map_len; j++)
        if (mapping[j] == ',')
            mapping[j] = '\n';

    fd = open(map_file, O_RDWR);
    if (fd == -1) {
        fprintf(stderr, "ERROR: open %s: %s\n", map_file,
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (write(fd, mapping, map_len) != map_len) {
        fprintf(stderr, "ERROR: write %s: %s\n", map_file,
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    close(fd);
}

char *stack_memory() {
    const int stackSize = 65536; // 64KB
    auto *stack = new (std::nothrow) char[stackSize];

    if(stack == nullptr) {
        printf("Cannot allocate memory \n");
        exit(EXIT_FAILURE);
    }

    return stack+stackSize;
}

template <typename Function>
void clone_process(Function&& function, int flags) {
    auto pid = clone(function, stack_memory(), flags, 0);
    if (pid == -1)
        errExit("clone");

    wait(nullptr);
}

template <typename...T>
int run(T... params) {
    char *args[] = {(char*)params..., (char*)0}; // array of commands
    return execvp(args[0], args);
}

void setup_root(const char* folder) {
    chroot(folder); // set root directory - decrease visibility
    chdir("/");
}

void setHostName(std::string hostname) {
  sethostname(hostname.c_str(), hostname.size());
}

void setup_variables() {
    clearenv();
    setenv("TERM", "xterm-256color", 0);
    setenv("PATH", "/bin/:/sbin/:usr/bin:/usr/sbin", 0);
}

// update file with your value
void write_rule(const char* path, const char* value) {
    int fp = open(path, O_WRONLY | O_APPEND );
    write(fp, value, strlen(value));
    close(fp);
}

// limit number of processes that can be created inside container
void limitProcessCreation() {
    mkdir( CGROUP_FOLDER, S_IRUSR | S_IWUSR);

    const char* pid = std::to_string(getpid()).c_str();

    write_rule(concat(CGROUP_FOLDER, "cgroup.procs"), pid);
    write_rule(concat(CGROUP_FOLDER, "notify_on_release"), "1");
    write_rule(concat(CGROUP_FOLDER, "pids.max"), "5");
    // max of 5 processes can be created by our child process
}

int child(void *args) {    
    struct child_args *cargs = (struct child_args *)args;
    char ch;
    close(cargs->pipe_fd[1]); // close write part of pipe, this will be used by parent

    if (read(cargs->pipe_fd[0], &ch, 1) != 0) { // read from pipe
        fprintf(stderr, "Failure in child: read from pipe returned != 0\n");
        exit(EXIT_FAILURE);
    }

    close(cargs->pipe_fd[0]); // close pipe

    limitProcessCreation(); // won't work with non-root host user (mapping) -> run with sudo 
    
    printf("child process: %d with user %d\n", getpid(), getuid());
    setHostName("container1"); // change hostname
    setup_variables();

    setup_root("./root");

    mount("proc", "/proc", "proc", 0, 0); // mount proc file system

    auto runThis = [](void *args) -> int { run("/bin/sh"); };

    clone_process(runThis, SIGCHLD);

    umount("/proc");
    return EXIT_SUCCESS;
}

int main() {
    pid_t child_pid;
    struct child_args args;

    int map_zero = 1;
    char* uid_map = NULL;
    char* gid_map = NULL;

    const int MAP_BUF_SIZE = 100;
    char map_buf[MAP_BUF_SIZE];
    char map_path[PATH_MAX];

    printf("Hello from parent process %d with user %d! \n", getpid(), getuid());

    if (pipe(args.pipe_fd) == -1)
        errExit("pipe");

    child_pid = clone(child, stack_memory(), CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | CLONE_NEWUSER | SIGCHLD , &args);
    // CLONE_NEWPID - isolate shell
    // CLONE_NEWUTS - clone global namespace (UTS)
    // CLONE_NEWNS - get copy of parent's mounted filesystem, changes only reflect in child
    // CLONE_NEWUSER - new user namespace
    if (child_pid == -1)
        errExit("clone"); // if child creation fails

    if (uid_map != NULL || map_zero) {
        snprintf(map_path, PATH_MAX, "/proc/%jd/uid_map",
                (intmax_t) child_pid);
        if (map_zero) {
            snprintf(map_buf, MAP_BUF_SIZE, "0 %jd 1",
                    (intmax_t) getuid());
            uid_map = map_buf;
        }
        update_map(uid_map, map_path); // map user 1000 on host to user 0 (root) in container
    }

    if (gid_map != NULL || map_zero) {
        proc_setgroups_write(child_pid, "deny");

        snprintf(map_path, PATH_MAX, "/proc/%jd/gid_map",
                (intmax_t) child_pid);
        if (map_zero) {
            snprintf(map_buf, MAP_BUF_SIZE, "0 %ld 1",
                    (intmax_t) getgid());
            gid_map = map_buf;
        }
        update_map(gid_map, map_path); // map user 1000 on host to user 0 (root) in container again
    }

    close(args.pipe_fd[1]); // close pipe

    if (waitpid(child_pid, NULL, 0) == -1) // wait for child
        errExit("waitpid");

    return EXIT_SUCCESS;
}