#include <stdio.h>
#include <string.h>

int main() {
    char buf[10];
    char large_input[] = "This string is much longer than ten characters";

    // 1. Finding: Insecure Function (gets)
    gets(buf); 

    // 2. Finding: Potential Buffer Overflow (strcpy)
    strcpy(buf, large_input);

    // 3. Finding: Insecure Function (sprintf)
    sprintf(buf, "%s", large_input);

    return 0;
}
