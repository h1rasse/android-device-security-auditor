cmake_minimum_required(VERSION 3.22.1)
project("securityauditor")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(security_auditor SHARED security_auditor.c)

target_compile_options(security_auditor PRIVATE $<$<COMPILE_LANGUAGE:C>:-Wall;-Wextra;-Wpedantic;-Wconversion;-Wshadow>)
