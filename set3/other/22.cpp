#include <iostream>
#include <random>

int main(int argc, char** argv) {
    unsigned output = 968466351; // the output from 22.go
    unsigned seed = 1686101924; // a lower bound on the seed

    std::cout << "Looking for " << output << "..." << std::endl;

    for ( ; ; seed++) {
        std::mt19937 mt{ seed };
        if (mt() == output) {
            std::cout << "Seed: " << seed << std::endl;
            break;
        }
    }

    return 0;
}
