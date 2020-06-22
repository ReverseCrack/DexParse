//
// Created by Dio on 2020/6/16.
//

#include <stdio.h>
#include <stdlib.h>

#ifndef DEXFILE_PARSER_READ_BINARY_FILE_H
#define DEXFILE_PARSER_READ_BINARY_FILE_H

//根据行和列 取数据
void read_binary(int row, int column, int num, unsigned char *data, char *filename);

//根据具体地址取数据
void read_binary_by_address(int address, int size, unsigned char *data, char *filename);

#endif //DEXFILE_PARSER_READ_BINARY_FILE_H
