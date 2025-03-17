#include <stdio.h>
#include <string.h>

#define BUFFER_SIZE 64

void secure_function() {
    char buffer[BUFFER_SIZE];

    printf("Enter some text: ");
    fgets(buffer, BUFFER_SIZE, stdin);

    // Remove the newline character from the buffer, if present
    buffer[strcspn(buffer, "\n")] = '\0';

    printf("You entered: %s\n", buffer);
}

int main() {
    secure_function();
    return 0;
}
