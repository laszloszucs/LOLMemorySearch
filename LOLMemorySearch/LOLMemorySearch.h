#include <windows.h>
#include <iostream>
#include <vector>
#include <string>


int compare_pattern(const unsigned char *buffer, const unsigned char *pattern, const char *mask);

std::vector<DWORD> find_pattern(const unsigned char *buffer, DWORD size, unsigned char *pattern, char *mask, DWORD start);

std::vector<DWORD> find_pattern_process(HANDLE process, DWORD start, DWORD end, unsigned char *pattern, char* mask);

DWORD get_pointer_at_address(HANDLE process, DWORD addr);

std::string get_name(HANDLE process, DWORD addr);

void header_test(HANDLE process, DWORD addr, std::ofstream& f);

DWORD get_num_offset(HANDLE process, DWORD baseAddress);

DWORD get_baseaddr(char *module_name, DWORD pid);

