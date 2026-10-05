#ifndef IO_UTILS_H
#define IO_UTILS_H

#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>

// Reads a long long from the console, repeating until the input is valid
// and not less than minValue.
inline long long readLongLong(const std::string& prompt,
                              long long minValue = std::numeric_limits<long long>::min()) {
    while (true) {
        std::cout << prompt;
        long long value;
        if (std::cin >> value && value >= minValue) {
            return value;
        }

        if (std::cin.eof()) {
            std::cout << "\nInput closed. Exiting.\n";
            std::exit(0);
        }

        // Clear the error state and discard the rest of the line
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cout << "Invalid input, please try again.\n";
    }
}

#endif