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

#define BUF_MAX 0x10000
#define ARGS_MAX 0x100
#define HIS_MAX 0x100

#define FLAG_NULL_INPUT -1
#define FLAG_EXECVE_BACKGROUND 0
#define FLAG_EXECVE_WAIT 1

uid_t uid;
int user_path_len;
char local_host_name[0x100];
char user_path[0x100];
char current_path[0x200];
char type_prompt[0x300];
struct passwd * user_info = NULL;

static char * command_buf = NULL;
static int command_buf_size = 0;

static char * args[ARGS_MAX];
static int args_count = 0;

void init(void);
void getTypePrompt(void);
int analyseCommand(void);
int innerCommand(void);
void createChild(int flag);