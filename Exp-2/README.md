# 实验二、多进程编程

## **一、实验题目**

Project 1—UNIX Shell and History Feature

This project consists of designing a C program to serve as a shell interface

that accepts user commands and then executes each command in a separate

process. This project can be completed on any Linux, UNIX, or Mac OS X system.

A shell interface gives the user a prompt, after which the next command

is entered. The example below illustrates the prompt osh> and the user’s

next command: cat prog.c. (This command displays the file prog.c on the

terminal using the UNIX cat command.)

osh> cat prog.c

One technique for implementing a shell interface is to have the parent process

first read what the user enters on the command line (in this case, cat

prog.c), and then create a separate child process that performs the command.

Unless otherwise specified, the parent process waits for the child to exit

before continuing. This is similar in functionality to the new process creation

illustrated in Figure 3.10. However, UNIX shells typically also allow the child

process to run in the background, or concurrently. To accomplish this, we add

an ampersand (&) at the end of the command. Thus, if we rewrite the above

command as

osh> cat prog.c &

the parent and child processes will run concurrently.

The separate child process is created using the fork() system call, and the

user’s command is executed using one of the system calls in the exec() family

(as described in Section 3.3.1).

A C program that provides the general operations of a command-line shell

is supplied in Figure 3.36. The main() function presents the prompt osh->

and outlines the steps to be taken after input from the user has been read. The

main() function continually loops as long as should run equals 1; when the

user enters exit at the prompt, your program will set should run to 0 and

terminate.

This project is organized into two parts: (1) creating the child process and

executing the command in the child, and (2) modifying the shell to allow a

history feature.

## **二、相关原理与知识**

**（完成实验所用到的相关原理与知识）**

Linux 进程相关基础知识

Linux 下的 C 编程

命令行解析

## **三、实验过程**

**（清晰展示实际操作过程，相关截图及解释）**

通常而言，一个shell可以简化为如下形式：

> 参考自《现代操作系统》P31 图 1-19

```c
while(1)
{
    typePrompt();
    readCommand();

    int pid = fork();

    if(pid < 0)
    {
        puts("Unable to fork the child, inner error.");
    }
    else if(pid == 0) // the child thread
    {
        execve(command); //execve the command
    }
    else // the parent thread
    {
        wait(NULL); //waiting for the child to exit
    }
}
```

当我们在shell中进行输入时，fork()出子进程来执行我们的输入，父进程则等待我们的子进程执行完成

### I.打印提示符

一个“比较好看”的shell应当形如如下形式：

> bash，大多数Linux发行版上默认的shell

![image.png](https://i.loli.net/2021/03/04/JSlezZnQ3GPFfXy.png)

即我们在输入命令之前应当有如下结构的提示符：

```shell
user@hostname:current_path$
```

- 获取用户相关信息可以使用```getpwuid(getuid())```获取一个```passwd```结构体

- 获取主机名则可以使用``` gethostname() ```函数

- 获取当前路径可以使用```getcwd()```函数，按照bash的风格若是包含当前用户的home路径则我们应当将其缩写为```~```
- 改变字体颜色则可以用相应的转义序列控制字符，便不在此赘叙

最终我们得到的打印提示符的函数如下：

```c
uid_t uid;
int user_path_len;
char local_host_name[0x100];
char user_path[0x100];
char current_path[0x200];
struct passwd * user_info = NULL;

void typePrompt(void)
{
    uid = getuid();
    user_info = getpwuid(uid);
    user_path_len = strlen(user_info->pw_dir);

    if(gethostname(local_host_name, 0x100))
    {
        printf("\033[31m\033[1m[x] Unable to get the hostname, inner error.\033[0m\n");
        exit(-1);
    }

    if(!getcwd(current_path, 0x200))
    {
        printf("\033[31m\033[1m[x] Unable to get the current path, inner error.\033[0m\n");
        exit(-1);
    }

    if(uid == 0) // for root, no color
    {
        printf(user_info->pw_name);
        printf("@");
        printf(local_host_name);
        printf(":");
        if(strlen(current_path) > user_path_len)
        {
            memcpy(user_path, current_path, user_path_len);
            user_path[user_path_len] = '\0';
            if(!strcmp(user_path, user_info->pw_dir))
            {
                printf("~");
                printf(current_path + user_path_len);
            }
            else
                printf(current_path);
        }
        else
        {
            printf(current_path);
        }
        printf("# ");
    }
    else
    {
        printf("\033[32m\033[1m");
        printf(user_info->pw_name);
        printf("@");
        printf(local_host_name);
        printf("\033[0m\033[1m");
        printf(":");
        printf("\033[34m");
        if(strlen(current_path) > user_path_len)
        {
            memcpy(user_path, current_path, user_path_len);
            user_path[user_path_len] = '\0';
            if(!strcmp(user_path, user_info->pw_dir))
            {
                printf("~");
                printf(current_path + user_path_len);
            }
            else
                printf(current_path);
        }
        else
        {
            printf(current_path);
        }
        printf("\033[0m");
        printf("$ ");
    }
}
```

简单测试一下，以假乱真还是没什么问题的（）

![image.png](https://i.loli.net/2021/03/04/L73rDxGoI4ifbRX.png)

### II.输入读取

对于用户的一次输入，毫无疑问我们不应当也不可能无限进行读取，因此我们应当对输入的读取的字符的上限做一个限制，超出这个限制长度往后的字符尽数丢弃

同样地，为了避免一开始就分配过大的内存空间，笔者选择使用malloc进行动态内存分配，一开始时先分配一个适当大小的缓冲区，后续若输入超出这个大小则重新分配一个两倍大小的缓冲区

对于输入历史是否记录，我们还需要进行判断，若是用户仅仅是在不断敲击```ENTER```，那么就没必要记录了

#### 后台执行

有的时候我们想要让应用被放到后台去执行，那么我们的父进程（shell）就不应当等待子进程，笔者选择仿照bash的方式——若最后一个字符是```'&'```则不等待子进程执行，这里我们选择在读取命令时使用一个返回值进行标识

#### 历史命令

为了模拟bash的功能，我们还应当实现```!!```执行上一条命令、```!数字```执行历史记录中的某条命令，简单判断即可 

完整代码如下：

```c
int readCommand(void)
{
    unsigned long long count = 0;
    char ch;
    while((ch = getchar()) != '\n')
    {
        if(count == command_buf_size)
        {
            if(2 * command_buf_size > BUF_MAX) //overflow
            {
                while((ch = getchar()) != '\n')
                    continue;
                break;
            }
            char * new_buf = (char*)malloc(2 * command_buf_size);
            if(!new_buf) //malloc error
            {
                while((ch = getchar()) != '\n')
                    continue;
                break;
            }
            memcpy(new_buf, command_buf, command_buf_size);
            command_buf_size *= 2;
            free(command_buf);
            command_buf = new_buf;
        }
        command_buf[count++] = ch;
    }
    command_buf[count] = '\0';
    if(count == 0)
        return FLAG_NULL_INPUT;
    
    if(count > 1)
    {
        if (command_buf[0] == '!')
        {
            if (command_buf[1] == '!')
            {
                if(!his_full && his_count == 0)
                {
                    puts("\033[31m\033[1m[x] No available command, history is empty.\033[0m");
                    return FLAG_NULL_INPUT;
                }

                char * temp = malloc(command_buf_size);
                int flag = FLAG_EXECVE_WAIT;

                if(command_buf[count - 1] == '&')
                {
                    command_buf[count - 1] = '\0';
                    flag = FLAG_EXECVE_BACKGROUND;
                }

                strcpy(temp, history[((his_count + HIS_MAX - 1) % HIS_MAX)]);
                strncat(temp, command_buf + 2, command_buf_size - strlen(temp));
                strcpy(command_buf, temp);
                free(temp);
                historyRecord();
                printf("\n%s\n", command_buf);
                return flag;
            }
            else if (command_buf[1] >= '0' && command_buf[1] <= '9')
            {
                int num_end = 1;
                while(command_buf[num_end] >= '0' && command_buf[num_end] <= '9')
                    num_end++;
                char ch = command_buf[num_end];
                command_buf[num_end] = '\0';
                int his = atoi(command_buf + 1);
                command_buf[num_end] = ch;

                if (his < 0 || his >= HIS_MAX || !history[his])
                {
                    puts("\033[31m\033[1m[x] No available command, invalid history index.\033[0m");
                    return FLAG_NULL_INPUT;
                }

                char * temp = malloc(command_buf_size);
                int flag = FLAG_EXECVE_WAIT;

                if(command_buf[count - 1] == '&')
                {
                    command_buf[count - 1] = '\0';
                    flag = FLAG_EXECVE_BACKGROUND;
                }

                strcpy(temp, history[his]);
                strncat(temp, command_buf + num_end, command_buf_size - strlen(temp));
                strcpy(command_buf, temp);
                free(temp);
                historyRecord();
                printf("\n%s\n", command_buf);
                return flag;
            }
        }
    }

    historyRecord();
    
    if(command_buf[count - 1] == '&')
    {
        command_buf[count - 1] = '\0';
        return FLAG_EXECVE_BACKGROUND;
    }
    return FLAG_EXECVE_WAIT;
}
```

### III.命令行解析

最为简单的解析方式便是使用```strtok()```函数进行分割，这里我们选择以空格```" "```作为分隔符

同样地，一行命令中的参数数量不应当过多，我们应当限制仅读取一定数量的参数

代码如下：

```c
#define ARGS_MAX 0x100

char * args[0x100];
int args_count = 0;

void analyseCommand(void)
{
    args_count = 0;
    args[args_count] = strtok(command_buf, " ");
    char * ptr;
    while(ptr = strtok(NULL, " "))
    {
        args_count++;
        args[args_count] = ptr;
        if(args_count + 1 == ARGS_MAX)
            break;
    }
}
```

### IV.命令执行

相比起```execve()```，```execvp()```函数更适合用以执行我们输入的命令，同时我们解析后的命令行格式可以直接传入，较为方便

```c
void createChild(int flag)
{
    int pid = fork();

    if(pid < 0) // failed to fork a new thread
        printf("\033[31m\033[1m[x] Unable to fork the child, inner error.\033[0m\n");
    else if(pid == 0) // the child thread
        execvp(args[0], args);
    else // the parent thread
        if(flag == FLAG_EXECVE_WAIT)
            wait(NULL); //waiting for the child to exit
}
```

### V.内建命令

部分命令如```cd```（改变当前工作目录）、```history```（查看历史）、```exit```（退出）等命令若是直接使用execvp()执行的话我们会发现**毫无效果**，因此这几个命令我们需要自行建立在我们的shell当中

- ```cd```命令可以直接使用```chdir()```函数改变当前工作目录，需要注意的是对于字符串```"~"```我们应当单独解析——将其替换为用户工作目录后再进行字符串拼接
- ```history```命令则需要我们预先有一个储存历史命令的缓冲区，同时当历史记录达到上限时我们应当进行清除，这里我们选择模拟一个循环链表以在历史命令满之后每次输入命令时都会去除现存的最早的命令
- ```exit```命令则只需要在主进程中识别到该字符串时直接调用```exit()```即可

同样地，在主进程若是检测到输入的命令为内建命令，则应当**不调用**```execvp()```，在这里笔者选择添加一个返回值进行判定

代码如下：

```c
static char * history[HIS_MAX];
static int his_count = 0;
static int his_start = 0;
static int his_full = 0;

int innerCommand(void)
{
    if(!strcmp(args[0], "exit"))
    {
        puts("Exit the a3shell now, see you again!");
        exit(-1);
    }
    else if(!strcmp(args[0], "cd"))
    {
        if(args_count > 1)
            puts("cd: too many arguments");
        else
        {
            if(args[1][0] == '~' && args[1][1] == '/')
            {
                char * dir = malloc(strlen(args[1]) + strlen(user_info->pw_dir));
                strcpy(dir, user_info->pw_dir);
                strncat(dir, args[1][1], strlen(args[1]) - 1);
                chdir(dir);
                free(dir);
                dir = NULL;
            }
            else
                chdir(args[1]);
        }
        return 1;
    }
    else if(!strcmp(args[0], "history"))
    {
        if(args[1] && !strcmp(args[1], "-c"))
        {
            his_count = 0;
            his_full = 0;
            his_start = 0;
            return 1;
        }
        int count = 0;
        if(his_full)
        {
            for(int i = his_start; i < HIS_MAX; i++)
            {
                printf(" %d  ", count++);
                puts(history[i]);
            }
            for(int i = 0; i < his_start;i++)
            {
                printf(" %d  ", count++);
                puts(history[i]);
            }
        }
        else
        {
            for(int i = 0; i < his_count; i++)
            {
                printf(" %d  ", count++);
                puts(history[i]);
            }
        }
        return 1;
    }
    return 0;
}

void historyRecord(void)//to record the history
{
    history[his_count] = malloc(strlen(command_buf));
    strcpy(history[his_count], command_buf);
    his_count++;
    if(his_full)
    {
        his_start++;
        his_start %= HIS_MAX;
    }
    if(his_count == HIS_MAX)
    {
        his_count = 0;
        his_full = 1;
    }
}
```

### VI.代码测试

最终我们的主程序如下：

```c
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

```

> 完整代码见[https://github.com/arttnba3/a3shell](https://github.com/arttnba3/a3shell)

**至此，v1.0版的shell的功能已经基本上全部完成，他成功实现了一个shell应当有的基本功能**

### VII.MORE POWERFUL SHELL

毫无疑问的是，一个成熟易用的shell应当还要具备如```代码补全```、```上下切换历史记录```等功能，因此我们决定为我们的shell添加这样的功能，让她成为一个更加强大的shell

在这里我们将会用到一个库[The GNU Readline Library](https://tiswww.case.edu/php/chet/readline/rltop.html)

#### 安装readline库

```shell
$ sudo apt-get install libreadline-gplv2-dev
$ sudo apt-get install libreadline6-dev
```

也可以在[这里](http://git.savannah.gnu.org/cgit/readline.git/snapshot/readline-master.tar.gz)下载源码

#### 使用readline读取输入

需要```#include <readline/readline.h>```

只需要将我们原来的```readCommand()```函数换为```readline()```函数即可，返回值即为读取到的输入

需要注意的是**我们需要手动进行释放，否则会造成内存泄漏**

readline()函数接收一个参数作为输入前的提示符，我们只需要稍微原有函数将拼接好的提示符传入即可

✳需要注意的是**我们传入的提示符字符串应当以**```'\001'```**开头**、```'\002'```**结尾**

对于空行而言，readline()将会返回一个空字符串（buf[0] == '\0'）而不是NULL

#### 记录历史输入

readline库提供了强大的历史输入记录功能，在使用```readline()```函数读取输入后我们可以使用```add_history()```记录输入，传入的参数则是readline()返回的字符串

**添加历史后我们便可以像普通的shell那样使用↑↓来显示历史输入记录**

打印的功能依然需要我们自定义，在readline lib中使用一个```HIST_ENTRY```结构体数组来记录我们传入的历史输入，而使用```history_list()```便可以获得指向该结构体数组的指针

使用```clear_history()```则可以清除所有历史记录

代码如下：

```c
#include <readline/history.h>

...

HIST_ENTRY ** his = history_list();
for(int i = 0; his[i]; i++)
{
    printf(" %d\t\t", i);
    puts(his[i]->line);
}
```

#### 编译运行

需要注意的是我们编译时应当添加上```-lreadline```参数

> 示例：
>
> ```shell
> $ gcc shell.c -o a3sh -lreadline
> ```
>
> 程序完整代码见[https://github.com/arttnba3/a3shell](https://github.com/arttnba3/a3shell)

## 四、实验结果与分析

### V1.0 版

编译运行，示意图如下，左边为```a3shell```，右边为```bash```

![image.png](https://i.loli.net/2021/03/05/dVrnBjGHvlz9Ioe.png)

### V1.1 版

大概效果图如下（自动补全的效果没法表现出来，感受一下...）

![image.png](https://i.loli.net/2021/03/05/a2PZdr8ULscwjky.png)

## **五、问题总结**

在思考如何实现命令补全功能时曾经想过使用诸如getch()等无缓冲输入来实现，但是比较麻烦，后面经过使用谷歌等搜索引擎发现 readline 运行库，很好地解决了这个问题，不足的是无法在未安装该运行库的系统上使用，因而将未重构版本作为1.0版本，重构后版本作为1.1版本