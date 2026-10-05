#include "number_theory.h"

#include <climits>

namespace {

// Reduces value into the range [0, mod)
long long normalize(long long value, long long mod) {
    long long r = value % mod;
    return r < 0 ? r + mod : r;
}

} // namespace

long long eulerPhi(long long n) {
    long long result = n;

    // Factorize n by trial division and apply phi = n * prod(1 - 1/p)
    for (long long p = 2; p * p <= n; ++p) {
        if (n % p == 0) {
            while (n % p == 0) {
                n /= p;
            }
            result -= result / p;
        }
    }

    // Remaining part is a prime factor greater than sqrt(original n)
    if (n > 1) {
        result -= result / n;
    }
    return result;
}

ExtGcdResult extendedGcd(long long a, long long b) {
    long long oldR = a, r = b;
    long long oldX = 1, x = 0;
    long long oldY = 0, y = 1;

    // Iterative version: keeps invariants a*oldX + b*oldY = oldR
    while (r != 0) {
        long long q = oldR / r;

        long long tmp = oldR - q * r;
        oldR = r;
        r = tmp;

        tmp = oldX - q * x;
        oldX = x;
        x = tmp;

        tmp = oldY - q * y;
        oldY = y;
        y = tmp;
    }

    // Make the gcd non-negative
    if (oldR < 0) {
        oldR = -oldR;
        oldX = -oldX;
        oldY = -oldY;
    }
    return {oldR, oldX, oldY};
}

CrtResult chineseRemainder(const std::vector<long long>& remainders,
                           const std::vector<long long>& moduli) {
    long long curR = normalize(remainders[0], moduli[0]);
    long long curM = moduli[0];

    // Merge congruences one by one: x = curR (mod curM) and x = r2 (mod m2)
    for (std::size_t i = 1; i < moduli.size(); ++i) {
        long long m2 = moduli[i];
        long long r2 = normalize(remainders[i], m2);

        ExtGcdResult e = extendedGcd(curM, m2);
        long long g = e.gcd;
        long long diff = r2 - curR;

        // The system is solvable only if gcd divides the difference
        if (diff % g != 0) {
            return {CrtStatus::NoSolution, 0, 0};
        }

        // lcm(curM, m2) must fit into long long
        __int128 lcm = static_cast<__int128>(curM) / g * m2;
        if (lcm > LLONG_MAX) {
            return {CrtStatus::Overflow, 0, 0};
        }

        // Solve (curM/g) * t = diff/g (mod m2/g); e.x is the inverse of curM/g
        long long m2g = m2 / g;
        __int128 t = static_cast<__int128>(diff / g) % m2g;
        t = t * (e.x % m2g) % m2g;
        if (t < 0) {
            t += m2g;
        }

        __int128 x = curR + static_cast<__int128>(curM) * t;
        x %= lcm;
        if (x < 0) {
            x += lcm;
        }

        curR = static_cast<long long>(x);
        curM = static_cast<long long>(lcm);
    }

    return {CrtStatus::Ok, curR, curM};
}