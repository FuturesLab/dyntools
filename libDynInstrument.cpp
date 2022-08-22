#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <cstring>
#include <vector>
#include <algorithm>
#include <sys/types.h>
#include <sys/shm.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

using namespace std;

/* Prints current block's transfer type, address, 
 * and destination address (if conditional jump). */

void Patch_cft(char * type, unsigned long addr, unsigned long dest){

	char addrStr[64];
	char destStr[64];
	sprintf(addrStr, "%06X", (int)addr & 0xffffff);
	sprintf(destStr, "%06X", (int)dest & 0xffffff);

	printf("%s, %s, %s\n", type, addrStr, destStr);
}

/* Same as Patch_cft except trace is recorded to
 * the file passed in as tracePath. */

void Patch_cftToLog(char * type, unsigned long addr, unsigned long dest, char * tracePath){

	char addrStr[64];
	char destStr[64];
	sprintf(addrStr, "%06X", (int)addr & 0xffffff);
	sprintf(destStr, "%06X", (int)dest & 0xffffff);

	static FILE *traceFile = fopen(tracePath, "a+");
	fprintf(traceFile, "%s, %s, %s\n", type, addrStr, destStr);  
}