#include <iostream>
#include <vector>

#include "io_utils.h"
#include "number_theory.h"

namespace {

void printMenu() {
    std::cout << "\n===== Number theory toolkit =====\n"
              << "1. Euler's totient function phi(n)\n"
              << "2. Extended Euclidean algorithm\n"
              << "3. Chinese Remainder Theorem\n"
              << "0. Exit\n";
}

void runEuler() {
    long long n = readLongLong("Enter n (n >= 1): ", 1);
    std::cout << "phi(" << n << ") = " << eulerPhi(n) << "\n";
}

void runExtendedGcd() {
    long long a = readLongLong("Enter a: ");
    long long b = readLongLong("Enter b: ");

    ExtGcdResult r = extendedGcd(a, b);
    std::cout << "gcd(" << a << ", " << b << ") = " << r.gcd << "\n"
              << "Bezout coefficients: x = " << r.x << ", y = " << r.y << "\n"
              << a << " * (" << r.x << ") + " << b << " * (" << r.y << ") = " << r.gcd << "\n";

    // If gcd is 1, x is the modular inverse of a modulo b
    if (r.gcd == 1 && b > 1) {
        long long inv = ((r.x % b) + b) % b;
        std::cout << "Modular inverse of " << a << " modulo " << b << " is " << inv << "\n";
    }
}

void runCrt() {
    long long count = readLongLong("Number of congruences (>= 1): ", 1);

    std::vector<long long> remainders;
    std::vector<long long> moduli;

    for (long long i = 1; i <= count; ++i) {
        std::cout << "Congruence #" << i << ": x = a (mod m)\n";
        remainders.push_back(readLongLong("  a = "));
        moduli.push_back(readLongLong("  m (m >= 1) = ", 1));
    }

    CrtResult res = chineseRemainder(remainders, moduli);

    switch (res.status) {
        case CrtStatus::Ok:
            std::cout << "Solution: x = " << res.value << " (mod " << res.modulus << ")\n"
                      << "All solutions: x = " << res.value << " + " << res.modulus << " * k\n";
            break;
        case CrtStatus::NoSolution:
            std::cout << "The system has no solution.\n";
            break;
        case CrtStatus::Overflow:
            std::cout << "The resulting modulus is too large for 64-bit integers.\n";
            break;
    }
}

} // namespace

int main() {
    while (true) {
        printMenu();
        long long choice = readLongLong("Your choice: ");

        switch (choice) {
            case 1: runEuler(); break;
            case 2: runExtendedGcd(); break;
            case 3: runCrt(); break;
            case 0: std::cout << "Goodbye!\n"; return 0;
            default: std::cout << "Unknown option, try again.\n";
        }
    }
}