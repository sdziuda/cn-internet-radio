#ifndef MIMUW_SIK_ERR_H
#define MIMUW_SIK_ERR_H

#include <cstdio>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <stdbool.h>

// Evaluate `x`: if non-zero, describe it as a standard error code and exit with an error.
#define CHECK(x)                                                            \
    do {                                                                    \
        int err = (x);                                                      \
        if (err != 0) {                                                     \
            std::cerr << "Error: " << #x << " returned " << err << " in "   \
                      << __func__ << " at " << __FILE__ << ":" << __LINE__  \
                      << "\n" << strerror(err) << "\n";                     \
            exit(EXIT_FAILURE);                                             \
        }                                                                   \
    } while (0)

// Evaluate `x`: if false, print an error message and exit with an error.
#define ENSURE(x)                                                         \
    do {                                                                  \
        bool result = (x);                                                \
        if (!result) {                                                    \
            std::cerr << "Error: " << #x << " was false in " << __func__  \
                      << " at " << __FILE__ << ":" << __LINE__ << "\n";   \
            exit(EXIT_FAILURE);                                           \
        }                                                                 \
    } while (0)

// Check if errno is non-zero, and if so, print an error message and exit with an error.
#define PRINT_ERRNO()                                                   \
do {                                                                    \
        if (errno != 0) {                                               \
            std::cerr << "Error: errno " << errno << " in " << __func__ \
                      << " at " << __FILE__ << ":" << __LINE__ << "\n"  \
                      << strerror(errno) << "\n";                       \
            exit(EXIT_FAILURE);                                         \
        }                                                               \
    } while (0)


// Set `errno` to 0 and evaluate `x`. If `errno` changed, describe it and exit.
#define CHECK_ERRNO(x)                                                             \
    do {                                                                           \
        errno = 0;                                                                 \
        (void) (x);                                                                \
        PRINT_ERRNO();                                                             \
    } while (0)

// Note: the while loop above wraps the statements so that the macro can be used with a semicolon
// for example: if (a) CHECK(x); else CHECK(y);


// Print an error message and exit with an error.
inline static void fatal(const char *fmt, ...) {
    va_list fmt_args;

    std::cerr << "Error: ";
    va_start(fmt_args, fmt);
    vfprintf(stderr, fmt, fmt_args);
    va_end(fmt_args);
    std::cerr << "\n";
    exit(EXIT_FAILURE);
}

#endif // MIMUW_SIK_ERR_H
