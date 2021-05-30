#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdint.h>

int main(int argc, char ** argv)
{
    struct stat src_st;
    FILE * dst_file;
    int src_fd;
    char * buf;

    if (argc != 3)
    {
        puts("Usage: ./mycp source_file_path destination_file_path");
        exit(0);
    }

    src_fd = open(argv[1], O_RDONLY);
    if (src_fd == -1)
    {
        puts("Failed to open the source file!");
        exit(-1);
    }
    printf("fd of src: %d\n", src_fd);

    dst_file = fopen(argv[2], "wb+");
    if (dst_file == NULL)
    {
        puts("Failed to open the destination file!");
        exit(-1);
    }

    fstat(src_fd, &src_st); // get source file length
    buf = (char*) malloc(sizeof(char) * src_st.st_size);
    read(src_fd, buf, src_st.st_size);

    fwrite(buf, sizeof(char), src_st.st_size, dst_file);

    puts("Done.");
    fclose(dst_file);
    close(src_fd);
    return 0;
}