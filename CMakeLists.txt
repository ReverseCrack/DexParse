cmake_minimum_required(VERSION 3.15)
project(DexFile_Parser C)

set(CMAKE_C_STANDARD 99)

add_executable(DexFile_Parser main.c read_file.h read_file.c DexFile.h)