#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <semaphore.h>

#define BUFFER_SIZE 0x100

int items_queue[BUFFER_SIZE];
pthread_mutex_t queue_mutex, con_no_mutex, pro_no_mutex;
sem_t empty, full;

int front = 0, end = 0;
int producer_nums, consumer_nums;
int producer_no = 0, consumer_no = 0;
int running_time;
int total_consume = 0, total_produce = 0;

pthread_t * consumer, *producer;

void insertItem(int item)
{
    items_queue[front++] = item;
    front %= BUFFER_SIZE;
}

int removeItem(void)
{
    end %= BUFFER_SIZE;
    return items_queue[end++];
}

void * consumerThread(void * args)
{
    int thread_no, item;

    pthread_mutex_lock(&con_no_mutex);
    thread_no = ++consumer_no;
    pthread_mutex_unlock(&con_no_mutex);

    while (1)
    {
        if (rand() % 2)
        {
            sleep(rand() % 10); // avoid sleeping for tooooooooo long
        }
        else
        {
            sem_wait(&full);
            pthread_mutex_lock(&queue_mutex);
            item = removeItem();
            printf("=== consumer %d consumes: %d ===\n", thread_no, item);
            total_consume += item;
            pthread_mutex_unlock(&queue_mutex);
            sem_post(&empty);
        }
    }
}

void * producerThread(void * args)
{
    int thread_no, item;

    pthread_mutex_lock(&pro_no_mutex);
    thread_no = ++producer_no;
    pthread_mutex_unlock(&pro_no_mutex);

    while (1)
    {
        if (rand() % 2)
        {
            sleep(rand() % 10); // avoid sleeping for tooooooooo long
        }
        else
        {
            sem_wait(&empty);
            pthread_mutex_lock(&queue_mutex);
            do
            {
                item = rand() % 100; 
            } while (item == 0); // it's not so good for a lazy producer to produce nothing
            insertItem(item);
            printf("=== producer %d produce: %d ===\n", thread_no, item);
            total_produce += item;
            pthread_mutex_unlock(&queue_mutex);
            sem_post(&full);
        }
    }
}

int main(int argc, char ** argv)
{
    if (argc != 4)
    {
        puts("Usage: ./c_p time producer_nums consumer_nums");
        exit(0);
    }

    running_time = atoi(argv[1]);
    producer_nums = atoi(argv[2]);
    consumer_nums = atoi(argv[3]);
    if (running_time < 0 || producer_nums < 0 || consumer_nums < 0)
    {
        puts("Invalid arguments!");
        return 0;
    }

    sem_init(&empty, 0, (BUFFER_SIZE > producer_nums ? producer_nums : BUFFER_SIZE));
    sem_init(&full, 0, 0);
    pthread_mutex_init(&queue_mutex, NULL);
    pthread_mutex_init(&con_no_mutex, NULL);
    pthread_mutex_init(&pro_no_mutex, NULL);

    srand(time(NULL));

    consumer = (pthread_t*) malloc(sizeof(pthread_t) * consumer_nums);
    producer = (pthread_t*) malloc(sizeof(pthread_t) * producer_nums);

    for (int i = 0; i < consumer_nums;i++)
        pthread_create(consumer + i, NULL, consumerThread, NULL);

    for (int i = 0; i < producer_nums;i++)
        pthread_create(producer + i, NULL, producerThread, NULL);

    sleep(running_time);
    pthread_mutex_lock(&queue_mutex);
    printf("totally produce: %d, totally consume: %d\n", total_produce, total_consume);
    exit(0);
}