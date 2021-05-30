#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>

pthread_t thread_sorter_1, thread_sorter_2, thread_consolidator;

void * threadSorterOne(void * argv);
void * threadSorterTwo(void * argv);
void * threadConsolidator(void * argv);

int *arr, *arr1, *arr2;
int total, half;

int main(void)
{
    char buf[0x10];

    puts("Please input the amount of the nums you\'d like to sort:");
    scanf("%d", &total);
    if (total < 1)
    {
        puts("Invalid input!");
        exit(-1);
    }

    arr = (int*) malloc(sizeof(int) * total);
    if (arr == NULL)
    {
        puts("Error in malloc!");
        exit(-1);
    }

    for (int i = 0; i < total; i++)
    {
        scanf("%d", arr + i);
    }

    if (total != 1)
    {
        arr1 = (int*) malloc(sizeof(int) * total);
        arr2 = (int*) malloc(sizeof(int) * total);
        half = total / 2;
        memcpy(arr1, arr, sizeof(int) * half);
        memcpy(arr2, arr + half, sizeof(int) * (total - half));

        puts("The following nums will be sorted by thread 1:");
        for (int i = 0; i < half; i++)
            printf("%d ", arr1[i]);
        puts("");

        puts("The following nums will be sorted by thread 2:");
        for (int i = 0; i < total - half; i++)
            printf("%d ", arr2[i]);
        puts("");

        pthread_create(&thread_sorter_1, NULL, threadSorterOne, NULL);
        pthread_create(&thread_sorter_2, NULL, threadSorterTwo, NULL);
        pthread_join(thread_sorter_1, NULL);
        pthread_join(thread_sorter_2, NULL);

        pthread_create(&thread_consolidator, NULL, threadConsolidator, NULL);
        pthread_join(thread_consolidator, NULL);
    }

    puts("The result sorted out: ");
    for (int i = 0; i < total; i++)
        printf("%d ", arr[i]);
    puts("");

    return 0;
}

void * threadSorterOne(void * argv)
{
    int temp;
    for (int i = 0; i < half - 1; i++)
    {
        for (int j = 0; j < half - 1 - i; j++)
        {
            if (arr1[j] > arr1[j + 1])
            {
                temp = arr1[j + 1];
                arr1[j + 1] = arr1[j];
                arr1[j] = temp;
            }
        }
    }
    pthread_exit(0);
}

void * threadSorterTwo(void * argv)
{
    int temp;
    for (int i = 0; i < total - half - 1; i++)
    {
        for (int j = 0; j < total - half - 1 - i; j++)
        {
            if (arr2[j] > arr2[j + 1])
            {
                temp = arr2[j + 1];
                arr2[j + 1] = arr2[j];
                arr2[j] = temp;
            }
        }
    }
    pthread_exit(0);
}

void * threadConsolidator(void * argv)
{
    for (int i = 0, j = 0, ptr = 0; i != half || j != (total - half);ptr++)
        arr[ptr] = ((i != half )? ((j != (total - half)) ? (arr1[i] < arr2[j] ? arr1[i++] : arr2[j++]) : arr1[i++]) : arr2[j++]);
    pthread_exit(0);
}