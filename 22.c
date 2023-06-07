#include <stdlib.h>
#include <stdio.h>

int main(int argc, char** argv) {
    if (argc != 2) {
        printf("Must pass in the output of the PRNG.\n");
        return 1;
    }

    int output = atoi(argv[1]);

    printf("Looking for %d...\n", output);

    uint seed = 1686101924;
    do {
        srand(seed++);
    } while (rand() != output);

    printf("Seed: %d\n", seed);
}
