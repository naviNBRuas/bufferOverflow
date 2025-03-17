#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void win() {
    printf("You have won!\n");
    system("/bin/sh");
}

void vuln() {
    char buffer[64];
    gets(buffer); // Vulnerable function
}

int main() {
    vuln();
    return 0;
}