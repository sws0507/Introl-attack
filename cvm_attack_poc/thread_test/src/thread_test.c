#include <stdio.h>
#include <pthread.h>
__thread unsigned long thread_local_var1 = 0x09491234; //tp + 0
__thread unsigned long thread_local_var2 = 0x094912a3; //tp + 8
__thread unsigned long thread_local_var3 = 0x094912af; //tp + 16
static unsigned long read_tp(void)
{
    unsigned long tp;
    __asm__ volatile ("mv %0, tp" : "=r"(tp));
    return tp;
}

static void write_tp(unsigned long tp)
{
    __asm__ volatile ("mv tp, %0" : : "r"(tp));
    return;
}

static void *worker(void *arg)
{
    long id = (long)arg;
    printf("[T%ld] TCB Address (pthread_self): %p\n", id, (void *)pthread_self());
    unsigned long tp = read_tp();
    /* 为了证明 TLS 是每个线程独立的，这里每个线程把值改成不同的 */
    thread_local_var1 += id;
    thread_local_var2 += id;
    thread_local_var3 += id;

    printf("[T%ld] tp=%lx\n", id, tp);
    printf("[T%ld] v1=0x%lx v2=0x%lx v3=0x%lx\n",
           id, thread_local_var1, thread_local_var2, thread_local_var3);
    // tp -> tp - 240
    for(int i = 0; i < 84; i++){
        tp -= 24;
        write_tp(tp);
        printf("[T%ld rank%d] tp=%lx\n", id, i, tp);
        printf("[T%ld rank%d] v1=0x%lx v2=0x%lx v3=0x%lx\n",
           id, i, thread_local_var1, thread_local_var2, thread_local_var3);
    }
    tp += 2016;
    write_tp(tp);
    /* 
    //tp - 212 -> tp + 4
    tp -= 212;
    for(int i = 0; i < 9; i++){
        tp += 24;
        write_tp(tp);
        printf("[T%ld rank%d] tp=%lx\n", id, i, tp);
        printf("[T%ld rank%d] v1=0x%lx v2=0x%lx v3=0x%lx\n",
           id, i, thread_local_var1, thread_local_var2, thread_local_var3);
    }
    tp -= 4;
    write_tp(tp);
    */

    /*
    tp -= 212;
    write_tp(tp);
    printf("[T%ld changed] tp=%lx\n", id, tp);
    printf("[T%ld changed] v1=0x%lx v2=0x%lx v3=0x%lx\n",
           id, thread_local_var1, thread_local_var2, thread_local_var3);
    tp += 212;
    write_tp(tp);
    */
    return NULL;
}

int main()
{
    pthread_t th1;
    int ret = pthread_create(&th1, NULL, worker, (void *)1);
    if (ret != 0) {
        fprintf(stderr, "pthread_create failed: %d\n", ret);
        return 1;
    }
    printf("TCB Address (from th1): %p\n", (void *)th1);

    pthread_join(th1, NULL);

    /*
    pthread_t th[3];

    for (long i = 0; i < 3; i++) {
        int ret = pthread_create(&th[i], NULL, worker, (void *)i);
        if (ret != 0) {
            fprintf(stderr, "pthread_create failed: %d\n", ret);
            return 1;
        }
    }

    for (int i = 0; i < 3; i++) {
        pthread_join(th[i], NULL);
    }
    */
    // main thread
    printf("[Main] v1=0x%lx v2=0x%lx v3=0x%lx\n",
           thread_local_var1, thread_local_var2, thread_local_var3);

    return 0;
}