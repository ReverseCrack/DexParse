#include "read_file.h"

void read_binary(int row, int column, int num, unsigned char *data, char *filename) {
    FILE *fp;
    fp = fopen(filename, "rb");

    int currentAddress = 0;
    int startAddress = row + column;

    char element;
    int i = 0;
    while (!feof(fp)) {
        element = getc(fp);
        if (currentAddress == startAddress) {
            *(data + i) = element;
            if (i == (num - 1)) {
                break;
            }
            i++;
        } else {
            currentAddress++;
        }
    }

    fclose(fp);
    free(fp);
}

void read_binary_by_address(int address, int size, unsigned char *data, char *filename) {
    FILE *fp;
    fp = fopen(filename, "rb");
//    printf("\nread_binary_by_address  address:%2.2X  size:%2.2X\n", address, size);
    int currentAddress = 0;
    int startAddress = address;
    unsigned char element;
    int i = 0;
    while (!feof(fp)) {
        element = getc(fp);
        if (currentAddress == startAddress) {
            *(data + i) = element;
//            printf("i = %d\t element = %2.2X\tresult[%d]=%2.2X\n", i, element, i, *(data + i));
            if (i == (size - 1)) {
                break;
            }
            i++;
        } else {
            currentAddress++;
        }
    }

    fclose(fp);
    free(fp);
}