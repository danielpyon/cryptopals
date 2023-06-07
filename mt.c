#include <stdlib.h>
#include <stdio.h>

int main(int argc, char** argv) {
    uint seed = (uint)strtoul(argv[1], NULL, 0);
    uint output = (uint)strtoul(argv[2], NULL, 0);

    srand(seed);
    
    printf("seed(%u): %u\n", seed, rand());
    exit(1);
    
    if (rand() == output) {
        printf("Seed: %u\n", seed);
        exit(0);
    }
    exit(1);
}
