#include <stdio.h>
#include <stdlib.h>
#include <spawn.h>
#include <string.h>
#include <sys/wait.h>

extern char **environ;

int main(int argc, char **argv) {
    char *buffer = malloc(128);
    const char *program = (argc > 0 && argv != NULL && argv[0] != NULL) ? argv[0] : "";

    if (buffer == NULL) {
        fputs("malloc failed\n", stderr);
        return 1;
    }

    if (strcmp(program, "captest.bin") == 0) {
        posix_spawn_file_actions_t actions;
        char *child_argv[] = {
            "hello",
            "spawned",
            NULL,
        };
        pid_t child_pid = -1;
        int status = -1;
        int rc = posix_spawn_file_actions_init(&actions);

        if (rc != 0) {
            snprintf(buffer, 128, "file_actions_init failed rc=%d\n", rc);
            fputs(buffer, stderr);
            free(buffer);
            return 2;
        }

        rc = posix_spawn_file_actions_addclose(&actions, 0);
        if (rc == 0) {
            rc = posix_spawn_file_actions_adddup2(&actions, 2, 1);
        }
        if (rc != 0) {
            snprintf(buffer, 128, "file_actions setup failed rc=%d\n", rc);
            fputs(buffer, stderr);
            posix_spawn_file_actions_destroy(&actions);
            free(buffer);
            return 3;
        }

        rc = posix_spawn(
            &child_pid,
            "/bin/hello",
            &actions,
            NULL,
            child_argv,
            environ
        );
        posix_spawn_file_actions_destroy(&actions);
        if (rc != 0) {
            snprintf(buffer, 128, "posix_spawn failed rc=%d\n", rc);
            fputs(buffer, stderr);
            free(buffer);
            return 4;
        }

        if (waitpid(child_pid, &status, 0) != child_pid) {
            fputs("waitpid failed\n", stderr);
            free(buffer);
            return 5;
        }

        snprintf(
            buffer,
            128,
            "waitpid status=%d exited=%d code=%d\n",
            status,
            WIFEXITED(status),
            WEXITSTATUS(status)
        );
        fputs(buffer, stdout);
        free(buffer);
        return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : 6;
    }

    snprintf(buffer, 128, "hello from mochiOS, argc=%d\n", argc);
    fputs(buffer, stdout);
    free(buffer);

    (void)argv;
    return 0;
}
