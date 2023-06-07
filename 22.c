#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char** argv) {
    uint output = 3634215345;
    uint seed = 1686106350; // actual seed: 1686106364

    printf("Looking for %u...\n", output);

    for ( ; ; seed++) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork: ");
            exit(1);
        } else if (pid == 0) {
            // child
            char argv1[20];
            sprintf(argv1, "%u", seed);
            char argv2[20];
            sprintf(argv2, "%u", output);

            char* argv0 = "./mt";
            char* args[] = { argv0, argv1, argv2, NULL };

            if (execve(argv0, args, NULL) == -1) {
                printf("execve error!\n");
                exit(EXIT_FAILURE);
            }
        } else {
            // parent
            int status;
            if (waitpid(pid, &status, 0) == -1) {
                perror("waitpid: ");
                exit(EXIT_FAILURE);
            }

            if (WIFEXITED(status)) {
                int es = WEXITSTATUS(status);
                if (es == 0) {
                    break;
                }
            }
        }
    }
}
