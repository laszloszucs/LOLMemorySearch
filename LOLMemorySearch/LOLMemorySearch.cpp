#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <tlhelp32.h>
#include <stdlib.h>
#include <wchar.h>

#include <fstream>
#include "LOLMemorySearch.h"

#define NOT_A_POINTER(addr) ((addr) < 0x10000 || (addr) >= 0xFFFFFFFE)

using namespace std;

int compare_pattern(const unsigned char *buffer, const unsigned char *pattern, const char *mask){
	for (; *mask; ++mask, ++buffer, ++pattern)
	{
		if (*mask == 'x' && *buffer != *pattern) return 0;
	}
	return (*mask) == 0;
}

vector<DWORD> find_pattern(const unsigned char *buffer, DWORD size, unsigned char *pattern, char *mask, DWORD start){
	vector<DWORD> candidates;
	for (int i = 0; i < size; i++){
		if (compare_pattern((buffer + i), pattern, mask)) candidates.push_back(i + start);
	}
	return candidates;
}
vector<DWORD> find_pattern_process(HANDLE process, DWORD start, DWORD end, unsigned char *pattern, char* mask){
	DWORD size = end - start;
	unsigned char *buffer = (unsigned char *)malloc(size + 1);
	vector<DWORD> candidates;
	if (ReadProcessMemory(process, (PVOID)start, buffer, size, NULL) == 0){
		cout << "ReadProcessMemory failed." << endl;
		return candidates;
	}
	candidates = find_pattern(buffer, size, pattern, mask, start);
	return candidates;
}

DWORD get_pointer_at_address(HANDLE process, DWORD addr){
	unsigned char buffer[4];
	unsigned char * bufferp = buffer;
	ReadProcessMemory(process, (PVOID)addr, bufferp, 4, NULL);
	DWORD ret = (buffer[3] << 6 * 4) +
		(buffer[2] << 4 * 4) +
		(buffer[1] << 2 * 4) +
		(buffer[0]);
	return ret;
}

string get_name(HANDLE process, DWORD addr){
	char buffer[24];
	char * bufferp = buffer;
	ReadProcessMemory(process, (PVOID)(addr + 0x28), bufferp, 24, NULL);
	string name(buffer);

	return name;
}

void header_test(HANDLE process, DWORD addr, ofstream& f){
	f << get_name(process, addr) << endl;
	unsigned char buffer[40];
	unsigned char * bufferp = buffer;
	ReadProcessMemory(process, (PVOID)(addr), bufferp, 40, NULL);

	for (int i = 0; i < 40; i++){
		f << hex << (int)buffer[i] << ' ';
	}
	f << endl;
}


DWORD get_num_offset(HANDLE process, DWORD baseAddress){
	char *mask = "xx????xx????";
	char *pattern = "\x8B\x35\x9C\x9C\xD2\x03\x8B\x3D\xA0\x9C\xD2\x03";
	DWORD start = baseAddress + 0x1000;
	vector<DWORD> candidates;
	vector<DWORD> candidates1;
	vector<DWORD> candidates2;
	candidates = find_pattern_process(process, start, start + 0xB87FFF, (PBYTE)pattern, mask);
	int c = 1;
	for (auto candidate : candidates){
		cout << "Candidate " << dec << c << endl;
		cout << "Address: " << hex << candidate << endl;
		cout << endl;
		candidates2.push_back(get_pointer_at_address(process, candidate + 2));
		candidates2.push_back(get_pointer_at_address(process, candidate + 8));

		cout << endl;
		c++;

	}
	vector<DWORD> candidates3;
	vector<DWORD> candidates4;
	for (int i = 0; i < candidates2.size(); i += 2){
		if (candidates2[i + 1] == candidates2[i] + 4 && !NOT_A_POINTER(candidates2[i])){
			candidates3.push_back(candidates2[i]);
			candidates4.push_back(candidates2[i + 1]);
			cout << hex << candidates2[i] << endl;
		}
	}
	vector<boolean> candidatebool;
	vector<DWORD> candidates1s;
	vector<int> candidates1size;
	for (int i = 0; i < candidates3.size(); i++){
		DWORD p1 = get_pointer_at_address(process, candidates3[i]);
		DWORD p2 = get_pointer_at_address(process, candidates4[i]);
		cout << hex << p1 << endl << p2 << endl << (p2 - p1) / 4 << endl;
		if (!NOT_A_POINTER(p1) && !NOT_A_POINTER(p2) && (p2 - p1) % 4 == 0 && (p2 - p1) / 4 <= 12){
			candidates1s.push_back(p1);
			candidates1size.push_back((p2 - p1) / 4);
		}
	}
	for (int i = 0; i < candidates1s.size(); i++){
		cout << hex << candidates1s[i] << " passed" << endl;

	}
	vector<DWORD> entityAddresses;
	for (int i = 0; i < candidates1s.size(); i++){
		for (int j = 0; j < candidates1size[i]; j++){
			DWORD pent = get_pointer_at_address(process, candidates1s[i] + j * 4);
			if (find(entityAddresses.begin(), entityAddresses.end(), pent) == entityAddresses.end())
				entityAddresses.push_back(pent);
			cout << hex << candidates1s[i] << ' ' << dec << j << endl;
		}
	}
	for (int i = 0; i < entityAddresses.size(); i++){
		cout << hex << entityAddresses[i] << " entity" << endl;

	}
	ofstream f;
	f.open("debug.txt");

	for (auto a : entityAddresses){
		header_test(process, a, f);
	}
	f.close();
	return 1;
}

DWORD get_baseaddr(char *module_name, DWORD pid)
{
	MODULEENTRY32 module_entry;
	memset(&module_entry, 0, sizeof(module_entry));

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);

	if (!snapshot)
		return 0;

	module_entry.dwSize = sizeof(module_entry);
	bool bModule = Module32First(snapshot, &module_entry);

	while (bModule)
	{

		size_t i;
		char * szModC = module_entry.szModule;
		int nChars = MultiByteToWideChar(CP_ACP, 0, szModC, -1, NULL, 0);
		WCHAR * szModW = new WCHAR[nChars];
		MultiByteToWideChar(CP_ACP, 0, szModC, -1, (LPWSTR)szModW, nChars);


		char * szMod = (char *)malloc(255);
		wcstombs_s(&i, szMod, 255, szModW, 255);
		if (!strcmp(szMod, module_name))
		{
			CloseHandle(snapshot);
			return (DWORD)module_entry.modBaseAddr;
		}

		bModule = Module32Next(snapshot, &module_entry);
	}

	CloseHandle(snapshot);

	return 0;
}

int main(void)
{
	int n;

	DWORD pid;
	HWND window = FindWindowA(NULL, "League of Legends (TM) Client"); // 1
	GetWindowThreadProcessId(window, &pid); // 2
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid); // 3
	DWORD baseAddress = get_baseaddr("League of Legends.exe", pid);
	cout << hex << baseAddress << endl;
	DWORD num = get_num_offset(process, baseAddress);
	cout << pid << endl;
	cout << hex << num << endl;
	cin >> n;
	return 0;
}

