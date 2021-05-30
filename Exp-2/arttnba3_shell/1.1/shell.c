#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <wait.h>
#include <pwd.h>
#include <readline/readline.h>
#include <readline/history.h>
#include "func.c"

int main(void)
{
    init();

    while(1)
    {
        if(command_buf)
        {
            free(command_buf);
            command_buf = NULL;
        }
        memset(args, 0, sizeof(char*) * 0x100);
        
        getTypePrompt();
        command_buf = readline(type_prompt);

        int flag = analyseCommand();
        if(flag == FLAG_NULL_INPUT)
        {
            puts("");
            continue;
        }

        if(innerCommand())
            continue;
        
        createChild(flag);
    }
    return 0;
}
