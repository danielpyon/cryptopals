#include <iostream>
#include <random>

int main() {
    unsigned seed = 19650218;
	std::mt19937 mt{seed};
	std::cout << mt() << std::endl;
	return 0;
}
