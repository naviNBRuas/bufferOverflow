#include <stdio.h>
#include <string.h>

void vulnerable_function() {
    char buffer[64];

    printf("Enter some text: ");
    gets(buffer); // Dangerous function, vulnerable to buffer overflow, use fgets for security.
    // fgets(char *restrict s, int n, FILE *restrict stream)

    printf("You entered: %s\n", buffer);
}

int main() {
    vulnerable_function();
    return 0;
}
