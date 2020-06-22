#include <stdio.h>
#include <math.h>
#include <string.h>
#include "read_file.h"
#include "DexFile.h"

char *filename = "C:\\Users\\zhend\\Desktop\\Dex\\classes2.dex";
int index_current = 0;
struct DexFile dexFile;
struct DexHeader header;

void read_data_toData(unsigned char *result, int size, int address_current);

void read_data_toNumber(unsigned *number, int size, int address_current);

long read_data_ret_Number(int size, int address_current);

long charArrToLong(const unsigned char *param, int size);

void setDexHeader();

void setDexStringId();

void setDexTypeId();

void setProtoIdId();

void setDexFieldId();

void setDexMethodId();

void setDexClassDef();

int main() {
    setDexHeader();
    dexFile.pHeader = &header;
    setDexStringId();
    setDexTypeId();
    setProtoIdId();
    setDexFieldId();
    setDexMethodId();
    setDexClassDef();

//    printf("\n============  current ============\n");
//    struct DexMethodId tmpStru = *(dexFile.pMethodIds + 189);
//    printf("classIdx = %s\tprotoIdx = %s\tnameIdx:%s\n", tmpStru.classIdx, tmpStru.protoIdx, tmpStru.nameIdx);

//    printf("\n============  current ============\n");
//    struct DexFieldId tmpStru = *(dexFile.pFieldIds + 0x9);
//    printf("classIdx = %s\ttypeIdx = %s\tnameIdx:%s\n", tmpStru.classIdx, tmpStru.typeIdx, tmpStru.nameIdx);

//    struct DexProtoId *tmpStru = (dexFile.pProtoIds + 0x1);
//    printf("\n============  current ============\n");
//    printf("shortyIdx = %s\treturnTypeIdx = %s\tcount:%ld\n", (*tmpStru).shortyIdx, (*tmpStru).returnTypeIdx,
//           (*tmpStru).count);
//    for (int i = 0; i < (*tmpStru).count; i++) {
//        unsigned char *tmp = *((*tmpStru).parmas + i);
//        printf("param%d = %s\t\t", i, tmp);
//    }

//    struct DexTypeId tmpStru = *(dexFile.pTypeIds + 0xAA);
//    printf("============  current ============\n");
//    printf("value_in_strlist = %s", tmpStru.value_in_strlist);

//    struct DexString tmpStru = *(dexFile.pString + 0x1);
//    printf("============  current ============\n");
//    printf("startAddress = %2.2lX\tsize = %2.2lX\tvalue = %s\n", tmpStru.startAddress, tmpStru.size, tmpStru.value);
    return 0;
}

void setDexClassDef() {
    long size = header.classDefsSize;
    long offset = header.classDefsOff;
    dexFile.pClassDefs = malloc(sizeof(struct DexClassDef) * size);
    for (int i = 0; i < size; i++) {
        struct DexClassDef dexClassDef;
        printf("start ================ %2.2d ====================\n", i);

        long classIdx_offset = read_data_ret_Number(4, offset);
//        printf("classIdx_offset:%2.2lX\toffset:%2.2lX\n", classIdx_offset, offset);
        struct DexTypeId dexTypeId1 = *(dexFile.pTypeIds + classIdx_offset);
        dexClassDef.classIdx = dexTypeId1.value_in_strlist;
        printf("classIdx:%s\n", dexClassDef.classIdx);

        long accessFlags_offset = read_data_ret_Number(4, offset + 4);
        dexClassDef.accessFlags = accessFlags_offset;
        printf("accessFlags:%2.2lX\n", dexClassDef.accessFlags);

        long superclassIdx_offset = read_data_ret_Number(4, offset + 8);
//        printf("classIdx_offset:%2.2lX\toffset:%2.2lX\n", classIdx_offset, offset);
        struct DexTypeId dexTypeId3 = *(dexFile.pTypeIds + superclassIdx_offset);
        dexClassDef.superclassIdx = dexTypeId3.value_in_strlist;
        printf("superclassIdx:%s\n", dexClassDef.superclassIdx);

        long interfacesOff_offset = read_data_ret_Number(4, offset + 12);
        dexClassDef.interfacesOff = interfacesOff_offset;
        printf("sinterfacesOff:%2.2lX\n", dexClassDef.interfacesOff);

        long sourceFileIdx_offset = read_data_ret_Number(4, offset + 16);
        dexClassDef.sourceFileIdx = sourceFileIdx_offset;
        printf("sourceFileIdx:%2.2lX\n", dexClassDef.sourceFileIdx);

        long annotationsOff_offset = read_data_ret_Number(4, offset + 20);
        dexClassDef.annotationsOff = annotationsOff_offset;
        printf("annotationsOff:%2.2lX\n", dexClassDef.annotationsOff);

        long classDataOff_offset = read_data_ret_Number(4, offset + 24);
        dexClassDef.classDataOff = classDataOff_offset;
        printf("classDataOff:%2.2lX\n", dexClassDef.classDataOff);

        long staticValuesOff_offset = read_data_ret_Number(4, offset + 24);
        dexClassDef.staticValuesOff = staticValuesOff_offset;
        printf("staticValuesOff:%2.2lX\n", dexClassDef.staticValuesOff);

        printf("end ================ %2.2d ====================\n", i);

        offset += 32;
//        if (i == 2) {
//            break;
//        }
    }
}

void setDexMethodId() {
    long size = header.methodIdsSize;
    long offset = header.methodIdsOff;
    dexFile.pMethodIds = malloc(sizeof(struct DexMethodId) * size);
    for (int i = 0; i < size; i++) {
        struct DexMethodId dexMethodId;

        long classIdx_offset = read_data_ret_Number(2, offset);
//        printf("classIdx_offset:%2.2lX\toffset:%2.2lX\n", classIdx_offset, offset);
        struct DexTypeId dexTypeId1 = *(dexFile.pTypeIds + classIdx_offset);

        long typeIdx_offset = read_data_ret_Number(2, offset + 2);
        struct DexProtoId dexProtoId = *(dexFile.pProtoIds + typeIdx_offset);

        long nameIdx_offset = read_data_ret_Number(4, offset + 4);
        struct DexString dexString = *(dexFile.pString + nameIdx_offset);

//        printf("%2.2d ", i);
//        printf("classIdx = %s\t", dexTypeId1.value_in_strlist);
//        printf("typeIdx = %s\t", dexTypeId2.value_in_strlist);
//        printf("\nshortyIdx = %s\treturnTypeIdx = %s\tcount:%ld\n", dexProtoId.shortyIdx, dexProtoId.returnTypeIdx,
//               dexProtoId.count);
//        for (int k = 0; k < dexProtoId.count; k++) {
//            unsigned char *tmp = *(dexProtoId.parmas + i);
//            printf("param%d = %s\t\t", i, tmp);
//        }
//        printf("\n");
//        printf("nameIdx = %s\n", dexString.value);

        dexMethodId.classIdx = dexTypeId1.value_in_strlist;
        dexMethodId.protoIdx = dexProtoId.returnTypeIdx;
        dexMethodId.nameIdx = dexString.value;

        *(dexFile.pMethodIds + i) = dexMethodId;
        offset += 8;
//        if (i == 10) {
//            break;
//        }
    }
}

void setDexFieldId() {
    long size = header.fieldIdsSize;
    long offset = header.fieldIdsOff;
    dexFile.pFieldIds = malloc(sizeof(struct DexFieldId) * size);
    for (int i = 0; i < size; i++) {
        struct DexFieldId pFieldIds;

        long classIdx_offset = read_data_ret_Number(2, offset);
//        printf("classIdx_offset:%2.2lX\toffset:%2.2lX\n", classIdx_offset, offset);
        struct DexTypeId dexTypeId1 = *(dexFile.pTypeIds + classIdx_offset);

        long typeIdx_offset = read_data_ret_Number(2, offset + 2);
        struct DexTypeId dexTypeId2 = *(dexFile.pTypeIds + typeIdx_offset);

        long nameIdx_offset = read_data_ret_Number(4, offset + 4);
        struct DexString dexString = *(dexFile.pString + nameIdx_offset);

//        printf("%2.2d ", i);
//        printf("classIdx = %s\t", dexTypeId1.value_in_strlist);
//        printf("typeIdx = %s\t", dexTypeId2.value_in_strlist);
//        printf("nameIdx = %s\n", dexString.value);

        pFieldIds.classIdx = dexTypeId1.value_in_strlist;
        pFieldIds.typeIdx = dexTypeId2.value_in_strlist;
        pFieldIds.nameIdx = dexString.value;

        *(dexFile.pFieldIds + i) = pFieldIds;
        offset += 8;
//        if (i == 10) {
//            break;
//        }
    }
}

void setProtoIdId() {
    long size = header.protoIdsSize;
    long offset = header.protoIdsOff;
    dexFile.pProtoIds = malloc(sizeof(struct DexProtoId) * size);
    for (int i = 0; i < size; i++) {
        struct DexProtoId dexProtoId;
        //方法类型 所在的偏移
        long shortyIdx_offset = read_data_ret_Number(4, offset);
        //根据偏移 取到方法类型
        struct DexString dexString = *(dexFile.pString + shortyIdx_offset);
        dexProtoId.shortyIdx = dexString.value;

        //返回值类型 所在的偏移
        long returnTypeIdx_offset = read_data_ret_Number(4, offset + 4);
        struct DexTypeId dexTypeId = *(dexFile.pTypeIds + returnTypeIdx_offset);
        //根据偏移 取到返回值类型
        dexProtoId.returnTypeIdx = dexTypeId.value_in_strlist;

        //传入参数列表 所在位置的偏移
        long parametersOff = read_data_ret_Number(4, offset + 8);
        if (parametersOff == 0) {//如果传入参数列表为0,则说明没有传入参数,此时要做特殊处理
            dexProtoId.count = 0;
            dexProtoId.parmas = NULL;
        } else {
            //读取偏移的后 4 byte 获取 参数个数
            long param_count = read_data_ret_Number(4, parametersOff);
            //依次往后存放的是 count 个参数在 DexTypeId 里的下标index, 每个index占2 byte
            parametersOff += 4;
            dexProtoId.count = param_count;//参数个数
            dexProtoId.parmas = malloc(sizeof(char *) * param_count);
            for (int j = 0; j < param_count; j++) {
                long param_index = read_data_ret_Number(2, parametersOff);
                struct DexTypeId tmpStru = *(dexFile.pTypeIds + param_index);
//                printf("value_in_strlist = %s\n", tmpStru.value_in_strlist);
                *(dexProtoId.parmas + j) = tmpStru.value_in_strlist;
                parametersOff += 2;
            }
        }
//        printf("\n%2.2d offset = %2.2lX\t", i, offset);
//        printf(" parametersOff:%2.2lX\t", parametersOff);
//        printf("param_count:%ld", dexProtoId.count);
        offset += 4 * 3;//作相应的偏移
        *(dexFile.pProtoIds + i) = dexProtoId;;
    }
}

void setDexTypeId() {
    int size = header.typeIdsSize; //个数
    int offset = header.typeIdsOff;//偏移所在的起始位置
    //从起始位置开始，把所有偏移取出存进数组
    long allAddress[size];
    for (int i = 0; i < size; i++) {
        long addr = read_data_ret_Number(4, offset);
        allAddress[i] = addr;
        offset += 4;
    }
//    printf("size = %2.2X",size);
    dexFile.pTypeIds = malloc(sizeof(struct DexTypeId) * size);
    for (int j = 0; j < size; j++) {
        struct DexTypeId dexTypeId;
        dexTypeId.offset = allAddress[j];
        struct DexString tmpStru = *(dexFile.pString + dexTypeId.offset);
        dexTypeId.value_in_strlist = tmpStru.value;
        *(dexFile.pTypeIds + j) = dexTypeId;
    }
}

void setDexStringId() {
    int size = header.stringIdsSize;
    int offset = header.stringIdsOff;
    long allAddress[size];
    for (int i = 0; i < size; i++) {
        long addr = read_data_ret_Number(4, offset);
        allAddress[i] = addr;
        offset += 4;
    }
//    printf("\nsize = %2.2X\n",size);
    dexFile.pString = malloc(sizeof(struct DexString) * size);
    for (int j = 0; j < size - 1; j++) {
        struct DexString dexString;
        int startAddress = allAddress[j];
        int length = allAddress[j + 1] - allAddress[j];
        unsigned char *tmp = (unsigned char *) malloc(sizeof(char) * length);
        read_binary_by_address(startAddress, length, tmp, filename);
/*        printf("========== test ===========\n");
        for (int k = 0; k < dexEveryString.size; k++) {
            printf("%2.2X", *(tmp + k));
        }*/
        dexString.startAddress = startAddress;
        dexString.size = length;
        dexString.value = tmp;
        *(dexFile.pString + j) = dexString;
    }
}

void setDexHeader() {
    read_data_toData(header.magic, 8, index_current);
    index_current += 8;
//    printf("magic:%s\n", header.magic);
/*    for (int i = 0; i < 8; i++) {
        printf("%2.2X", header.magic[i]);
        printf(" ");
    }
    printf("\n");*/

    read_data_toNumber(&header.checksum, 4, index_current);
    index_current += 4;
//    printf("checksum:%2.2X\n", header.checksum);

    read_data_toData(header.signature, 20, index_current);
    index_current += 20;
/*    printf("signature:");
    for (int i = 0; i < 20; i++) {
        printf("%2.2X", header.signature[i]);
    }
    printf("\n");*/

    read_data_toNumber(&header.fileSize, 4, index_current);
    index_current += 4;
//    printf("fileSize:%2.2X\n", header.fileSize);

    read_data_toNumber(&header.headerSize, 4, index_current);
    index_current += 4;
//    printf("headerSize:%2.2X\n", header.headerSize);

    read_data_toNumber(&header.endianTag, 4, index_current);
    index_current += 4;
//    printf("endianTag:%2.2X\n", header.endianTag);

    read_data_toNumber(&header.linkSize, 4, index_current);
    index_current += 4;
//    printf("linkSize:%2.2X\n", header.linkSize);

    read_data_toNumber(&header.linkOff, 4, index_current);
    index_current += 4;
//    printf("linkOff:%2.2X\n", header.linkOff);

    read_data_toNumber(&header.mapOff, 4, index_current);
    index_current += 4;
//    printf("mapOff:%2.2X\n", header.mapOff);

    read_data_toNumber(&header.stringIdsSize, 4, index_current);
    index_current += 4;
//    printf("stringIdsSize:%2.2X\n", header.stringIdsSize);

    read_data_toNumber(&header.stringIdsOff, 4, index_current);
    index_current += 4;
//    printf("stringIdsOff:%2.2X\n", header.stringIdsOff);

    read_data_toNumber(&header.typeIdsSize, 4, index_current);
    index_current += 4;
//    printf("typeIdsSize:%2.2X\n", header.typeIdsSize);

    read_data_toNumber(&header.typeIdsOff, 4, index_current);
    index_current += 4;
//    printf("typeIdsOff:%2.2X\n", header.typeIdsOff);

    read_data_toNumber(&header.protoIdsSize, 4, index_current);
    index_current += 4;
//    printf("protoIdsSize:%2.2X\n", header.protoIdsSize);

    read_data_toNumber(&header.protoIdsOff, 4, index_current);
    index_current += 4;
//    printf("protoIdsOff:%2.2X\n", header.protoIdsOff);

    read_data_toNumber(&header.fieldIdsSize, 4, index_current);
    index_current += 4;
//    printf("fieldIdsSize:%2.2X\n", header.fieldIdsSize);

    read_data_toNumber(&header.fieldIdsOff, 4, index_current);
    index_current += 4;
//    printf("fieldIdsOff:%2.2X\n", header.fieldIdsOff);

    read_data_toNumber(&header.methodIdsSize, 4, index_current);
    index_current += 4;
//    printf("methodIdsSize:%2.2X\n", header.methodIdsSize);

    read_data_toNumber(&header.methodIdsOff, 4, index_current);
    index_current += 4;
//    printf("methodIdsOff:%2.2X\n", header.methodIdsOff);

    read_data_toNumber(&header.classDefsSize, 4, index_current);
    index_current += 4;
    printf("classDefsSize:%2.2X\n", header.classDefsSize);

    read_data_toNumber(&header.classDefsOff, 4, index_current);
    index_current += 4;
    printf("classDefsOff:%2.2X\n", header.classDefsOff);

    read_data_toNumber(&header.dataSize, 4, index_current);
    index_current += 4;
//    printf("dataSize:%2.2X\n", header.dataSize);

    read_data_toNumber(&header.dataOff, 4, index_current);
    index_current += 4;
//    printf("dataOff:%2.2X\n", header.dataOff);
}

void read_data_toData(unsigned char *result, int size, int address_current) {
    unsigned char data[size];
    read_binary_by_address(address_current, size, data, filename);
    strcpy(result, data);
}

void read_data_toNumber(unsigned *number, int size, int address_current) {
    unsigned char data[size];
    read_binary_by_address(address_current, size, data, filename);
    long headerSize_number = charArrToLong(data, size);
    *number = headerSize_number;
}

long read_data_ret_Number(int size, int address_current) {
    unsigned char data[size];
    read_binary_by_address(address_current, size, data, filename);
/*    printf("===== 33 ====\n");
    for (int i = 0; i < size; i++) {
        printf("%2.2X", data[i]);
        printf(" ");
    }
    printf("\n");*/
    long headerSize_number = charArrToLong(data, size);
    return headerSize_number;
}

//char[] 数组转换成 long
long charArrToLong(const unsigned char *param, int size) {
    long result = 0;
    for (int i = 0; i < size; i++) {
        unsigned char element = *(param + i);
        short tmp = (short) element;
        unsigned long tmp2 = tmp * pow(0x100, i);
        result += tmp2;
//        printf("tmp:%2.2X === tmp2:%2.2X === %d === result:%2.2X\n", tmp, tmp2, i, result);
    }
//    printf("result:\n%2.2X\n", result);
    return result;
}