#include <stdio.h>
int main() {
    char str[10];
    // This function is so dangerous it is literally banned in modern C
    gets(str); 
    printf("%s", str);
    return 0;
}



