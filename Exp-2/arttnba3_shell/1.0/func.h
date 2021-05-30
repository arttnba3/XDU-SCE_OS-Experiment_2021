#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <pwd.h>
#include <sys/types.h>

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
struct passwd * user_info = NULL;

static char * command_buf = NULL;
static int command_buf_size = 0;

static char * args[ARGS_MAX];
static int args_count = 0;

static char * history[HIS_MAX];
static int his_count = 0;
static int his_start = 0;
static int his_full = 0;

void init(void);
void typePrompt(void);
int readCommand(void);
void analyseCommand(void);
int innerCommand(void);
void historyRecord(void);
void createChild(int flag);