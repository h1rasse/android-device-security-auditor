cmake_minimum_required(VERSION 3.22.1)
project("securityauditor")

add_library(security_auditor SHARED security_auditor.c)

target_compile_options(security_auditor PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
