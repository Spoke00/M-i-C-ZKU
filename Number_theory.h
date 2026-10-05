#ifndef NUMBER_THEORY_H
#define NUMBER_THEORY_H

#include <vector>

// Result of the extended Euclidean algorithm: a*x + b*y = gcd
struct ExtGcdResult {
    long long gcd;
    long long x;
    long long y;
};

// Possible outcomes of solving a system of congruences
enum class CrtStatus {
    Ok,         // solution exists and was found
    NoSolution, // system is inconsistent
    Overflow    // the resulting modulus does not fit into long long
};

// Result of the Chinese Remainder Theorem solver: x = value (mod modulus)
struct CrtResult {
    CrtStatus status;
    long long value;
    long long modulus;
};

// Euler's totient function: count of numbers in [1, n] coprime with n (n >= 1)
long long eulerPhi(long long n);

// Extended Euclidean algorithm for any integers a and b
ExtGcdResult extendedGcd(long long a, long long b);

// Solves x = remainders[i] (mod moduli[i]) for all i.
// Moduli do not have to be pairwise coprime; moduli must be >= 1.
CrtResult chineseRemainder(const std::vector<long long>& remainders,
                           const std::vector<long long>& moduli);

#endif