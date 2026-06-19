/*
 * angr-friendly Linux target.
 *
 * This keeps the same password logic as crackme.c, but avoids libc/stdio so
 * macOS clang can cross-compile it to an ELF relocatable object without a
 * Linux sysroot. The native crackme.c executable is still used for concrete
 * runtime verification.
 */

void gadget_trap(void) {
    while (1) {
    }
}

int check_password(char *input) {
    if (input[0] == 0 || input[1] == 0 || input[2] == 0 || input[3] == 0) {
        return 0;
    }

    if (input[0] == 'A') {
        if (input[1] == 'B') {
            gadget_trap();
        }

        if (input[1] == 'Z') {
            if ((input[2] ^ 0x12) == 'q') {
                if ((input[3] + 3) == 'H') {
                    return 1;
                }
            }
        }
    }

    return 0;
}
