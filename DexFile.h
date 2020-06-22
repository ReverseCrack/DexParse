//
// Created by Dio on 2020/6/18.
//

#include <stdint.h>

#ifndef DEXFILE_PARSER_DEXFILE_H
#define DEXFILE_PARSER_DEXFILE_H

/*
 * These match the definitions in the VM specification.
 */
typedef uint8_t u1;
typedef uint16_t u2;
typedef uint32_t u4;
typedef uint64_t u8;
typedef int8_t s1;
typedef int16_t s2;
typedef int32_t s4;
typedef int64_t s8;

/*
 * 160-bit SHA-1 digest.
 */
enum {
    kSHA1DigestLen = 20, kSHA1DigestOutputLen = kSHA1DigestLen * 2 + 1
};

/*
 * access flags and masks; the "standard" ones are all <= 0x4000
 *
 * Note: There are related declarations in vm/oo/Object.h in the ClassFlags
 * enum.
 */
enum {
    ACC_PUBLIC = 0x00000001,       // class, field, method, ic
    ACC_PRIVATE = 0x00000002,       // field, method, ic
    ACC_PROTECTED = 0x00000004,       // field, method, ic
    ACC_STATIC = 0x00000008,       // field, method, ic
    ACC_FINAL = 0x00000010,       // class, field, method, ic
    ACC_SYNCHRONIZED = 0x00000020,       // method (only allowed on natives)
    ACC_SUPER = 0x00000020,       // class (not used in Dalvik)
    ACC_VOLATILE = 0x00000040,       // field
    ACC_BRIDGE = 0x00000040,       // method (1.5)
    ACC_TRANSIENT = 0x00000080,       // field
    ACC_VARARGS = 0x00000080,       // method (1.5)
    ACC_NATIVE = 0x00000100,       // method
    ACC_INTERFACE = 0x00000200,       // class, ic
    ACC_ABSTRACT = 0x00000400,       // class, method, ic
    ACC_STRICT = 0x00000800,       // method
    ACC_SYNTHETIC = 0x00001000,       // field, method, ic
    ACC_ANNOTATION = 0x00002000,       // class, ic (1.5)
    ACC_ENUM = 0x00004000,       // class, field, ic (1.5)
    ACC_CONSTRUCTOR = 0x00010000,       // method (Dalvik only)
    ACC_DECLARED_SYNCHRONIZED =
    0x00020000,       // method (Dalvik only)
    ACC_CLASS_MASK =
    (ACC_PUBLIC | ACC_FINAL | ACC_INTERFACE | ACC_ABSTRACT
     | ACC_SYNTHETIC | ACC_ANNOTATION | ACC_ENUM),
    ACC_INNER_CLASS_MASK =
    (ACC_CLASS_MASK | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC),
    ACC_FIELD_MASK =
    (ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL
     | ACC_VOLATILE | ACC_TRANSIENT | ACC_SYNTHETIC | ACC_ENUM),
    ACC_METHOD_MASK =
    (ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL
     | ACC_SYNCHRONIZED | ACC_BRIDGE | ACC_VARARGS | ACC_NATIVE
     | ACC_ABSTRACT | ACC_STRICT | ACC_SYNTHETIC | ACC_CONSTRUCTOR
     | ACC_DECLARED_SYNCHRONIZED),
};

/*
 * Direct-mapped "header_item" struct.
 */
struct DexHeader {
    u1 magic[8];       //取值必须是字符串 "dex\n035\0" 或者字节byte数组 {0x64 0x65 0x78 0x0a 0x30 0x33 0x35 0x00}
    u4 checksum;       //文件内容的校验和,不包括magic和自己,主要用于检查文件是否损坏
    u1 signature[kSHA1DigestLen];      //签名信息,不包括 magic\checksum和自己
    u4 fileSize;       //整个文件的长度,单位为字节,包括所有的内容
    u4 headerSize;     //默认是0x70个字节
    u4 endianTag;      //大小端标签，标准.dex文件为小端，此项一般固定为0x12345678常量
    u4 linkSize;       //链接数据的大小
    u4 linkOff;        //链接数据的偏移值
    u4 mapOff;         //map item的偏移地址，该item属于data区里的内容，值要大于等于dataOff的大小
    u4 stringIdsSize;      //DEX中用到的所有字符串内容的大小*
    u4 stringIdsOff;       //DEX中用到的所有字符串内容的偏移量
    u4 typeIdsSize;        //DEX中类型数据结构的大小
    u4 typeIdsOff;         //DEX中类型数据结构的偏移值
    u4 protoIdsSize;       //DEX中的元数据信息数据结构的大小
    u4 protoIdsOff;        //DEX中的元数据信息数据结构的偏移值
    u4 fieldIdsSize;       //DEX中字段信息数据结构的大小
    u4 fieldIdsOff;        //DEX中字段信息数据结构的偏移值
    u4 methodIdsSize;      //DEX中方法信息数据结构的大小
    u4 methodIdsOff;       //DEX中方法信息数据结构的偏移值
    u4 classDefsSize;      //DEX中的类信息数据结构的大小
    u4 classDefsOff;       //DEX中的类信息数据结构的偏移值
    u4 dataSize;           //DEX中数据区域的结构信息的大小
    u4 dataOff;            //DEX中数据区域的结构信息的偏移值
};

/*
 * Direct-mapped "field_id_item".
 */
struct DexProtoId {
    unsigned char *shortyIdx;          /* 值为一个string_ids的index号，用来说明该method原型 */
    unsigned char *returnTypeIdx;      /* 值为一个type_ids的index，表示该method原型的返回值类型 */
//    u4 parametersOff;      /* 指定method原型的参数列表type_list，若method没有参数，则值为0. 参数的格式是type_list */
    long count; //参数个数
    unsigned char **parmas;
};

/*
 * Direct-mapped "type_id_item".
 */
struct DexTypeId {
    long offset; // 在字符串 表中的 下标
    unsigned char *value_in_strlist;//在字符串列表里的值
};

//字符串区信息
struct DexString {
    long startAddress;//起始地址
    long size;//长度
    unsigned char *value;//内容
};

/*
 * Direct-mapped "field_id_item".
 */
struct DexFieldId {
    unsigned char *classIdx;           /* field所属的class类型，class_idx的值时type_ids的一个index，指向所属的类 */
    unsigned char *typeIdx;            /* field的类型，值是type_ids的一个index */
    unsigned char *nameIdx;            /* field的名称，它的值是string_ids的一个index */
};

/*
 * Direct-mapped "method_id_item".
 */
struct DexMethodId {
    unsigned char *classIdx;           /* method所属的class类型，class_idx的值是type_ids的一个index，必须指向一个class类型 */
    unsigned char *protoIdx;           /* method的原型，指向proto_ids的一个index */
    unsigned char *nameIdx;            /* method的名称，值为string_ids的一个index */
};


/*
 * Direct-mapped "type_item".
 */
struct DexTypeItem {
    u2 typeIdx;            /* index into typeIds */
};

/*
 * Direct-mapped "type_list".
 */
struct DexTypeList {
    u4 size;               /* #of entries in list */
    struct DexTypeItem list[1];    /* entries */
};

/*
 * Direct-mapped "class_def_item".
 */
struct DexClassDef {
    unsigned char *classIdx;           /* 描述具体的class类型，值是type_ids的一个index，值必须是一个class类型，不能是数组或者基本类型 */
    long accessFlags;        /* 描述class的访问类型，如public,final,static等 */
    unsigned char *superclassIdx;      /* 描述父类的类型，值必须是一个class类型，不能是数组雷兴国或者基本类型 */
    long interfacesOff;      /* 值为偏移地址，被指向的数据结构为type_list，class若没有interfaces，值为0 */
    long sourceFileIdx;      /* 表示源代码文件的信息，值为string_ids的一个index。若此项信息丢失，此项赋值为NO_INDEX=0xFFFFFFFF */
    long annotationsOff;     /* 值为偏移地址，指向的内容是该class的注解，位置在data区，格式为annotations_directory_item，若没有此项，值为0 */
    long classDataOff;       /* 值为偏移地址，指向的内容是该class的使用到的数据，位置在data区，格式为class_data_item。无偶没有此项，则值为0 */
    long staticValuesOff;    /* 值为偏移地址，指向data区里的一个列表，格式为encoded_array_item。若没有此项，值为0. */
};

struct DexFile {
    /* directly-mapped "opt" header */
    //const DexOptHeader* pOptHeader;

    /*
        对应关系如下
        DexHeader*    pHeader   ---->struct header_item dex_header
        DexStringId*  pStringIds---->struct string_id_list dex_string_ids
        DexTypeId*    pTypeIds  ---->struct type_id_list dex_type_ids
        DexFieldId*   pFieldIds ---->struct field_id_list dex_field_ids
        DexMethodId*  pMethodIds---->struct method_id_list dex_method_ids
        DexProtoId*   pProtoIds ---->struct proto_id_list dex_proto_ids
        DexClassDef*  pClassDefs---->struct class_def_item_list dex_class_defs
        DexLink*      pLinkData ---->struct map_list_type dex_map_list
     */

    /* pointers to directly-mapped structs and arrays in base DEX */
    struct DexHeader *pHeader;        //DEX 文件头，记录了一些当前文件的信息以及其他数据结构在文件中的偏移量
    struct DexString *pString;        //数组,元素类型为string_id_item,存储字符串相关的信息
    struct DexTypeId *pTypeIds;       //数组,存储类型相关的信息
    struct DexProtoId *pProtoIds;      //数组,存储成员变量信息,包括变量名和类型等
    struct DexFieldId *pFieldIds;      //数组,存储成员变量信息,包括变量名和类型等
    struct DexMethodId *pMethodIds;     //数组,存储成员函数信息包括函数名 参数和返回值类型
    struct DexClassDef *pClassDefs;     //数组,存储类的信息
};

#endif //DEXFILE_PARSER_DEXFILE_H
