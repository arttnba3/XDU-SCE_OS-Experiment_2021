#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <pwd.h>
#include <sys/types.h>
#include "func.c"

int main(void)
{
    init();

    while(1)
    {
        memset(args, 0, sizeof(char*) * 0x100);
        typePrompt();
        int flag = readCommand();
        if(flag == FLAG_NULL_INPUT)
            continue;
        analyseCommand();
        if(innerCommand())
            continue;

        createChild(flag);
    }
    return 0;
}
