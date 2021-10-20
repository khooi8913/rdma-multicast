#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

int main(int argc, char **argv) {
    static const int RDMA_BUFFER_SIZE = 16;
    char * ptr_rdma_memory = malloc(RDMA_BUFFER_SIZE);
    for (int i = 0; i < (int)(RDMA_BUFFER_SIZE / 4); i++) {
        *(uint32_t*)(ptr_rdma_memory + 4 * i) = i;
    }
    
    printf("%d\n", *(uint32_t*)(ptr_rdma_memory));
    printf("%d\n", *(uint32_t*)(ptr_rdma_memory + 4));
    printf("%d\n", *(uint32_t*)(ptr_rdma_memory + 8));
    printf("%d\n", *(uint32_t*)(ptr_rdma_memory + 12));

    FILE* fp = fopen("test.txt", "w");
    if (fp == NULL) {
        exit(-1);
    }
    
    for (int i = 0; i < (int)(RDMA_BUFFER_SIZE / 4); i++) {
        fprintf(fp, "%d", *(uint32_t*)(ptr_rdma_memory + 4 * i));
    }
    fclose(fp);

    return 0;
}