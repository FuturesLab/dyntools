#include <cstdlib>
#include <iostream>
#include <vector>
#include <string>
#include <stdlib.h>
#include <sstream>
#include <climits>
#include <cstring>
#include <fstream>
#include <getopt.h>
using namespace std;

/* DyninstAPI includes */

#include "BPatch.h"
#include "BPatch_binaryEdit.h"
#include "BPatch_flowGraph.h"
#include "BPatch_function.h"
#include "BPatch_point.h"
#include "BPatch_object.h"
#include "CFG.h"
#include "CodeObject.h"
#include "InstructionDecoder.h"
using namespace Dyninst;
using namespace ParseAPI;
using namespace InstructionAPI;
using namespace PatchAPI;

bool verbose = false;
bool skipFuncs = false;
bool instrumentedExit = false;
bool fixBPatch=true;
char * originalBinary = NULL;
char * outputBinary = NULL;
char * skipAddrsListPath = NULL;
char * analysisOutPath = NULL;
char * tracePath = NULL;
int minBlockSize = 1;
int numSkipBlocks = 0;
set <string> skipLibraries;
set <string> skipFunctions;
set <long> skipAddresses;

BPatch_function *Patch_cft;
BPatch_function *Patch_cftToLog;
BPatch_binaryEdit *appBin;

const char *instLibrary = "libDynInstrument.so";

static const char *OPT_STR = "O:T:M:N:X:A:VFBb";
static const char *USAGE = " [input_binary] [analysis_options]\n \
	Analysis options:\n \
		-O: output instrumented bin path\n \
		-M: minimum block size (default: 1)\n \
		-N: number of blocks to skip (default: 0)\n \
		-X: path to list of block addresses to skip\n \
		-A: path to output analysis log\n \
		-F: skip blacklisted functions\n \
		-T: output log path for CFT tracing\n \
		-B: fix BPatch (fixes segfaults in some binaries) (on by default)\n \
		-b: don't fix BPatch\n \
	Additional options:\n \
		-V: verbose mode\n";

bool parseOptions(int argc, char **argv){
	originalBinary = argv[1];
	int c;
	while ((c = getopt(argc, argv, OPT_STR)) != -1){
		switch ((char) c) {

			case 'O':	
				outputBinary = optarg;
				break;

			case 'T':	
				tracePath = optarg;
				break;

			case 'M':	
				minBlockSize = atoi(optarg);
				break;

			case 'N':
				numSkipBlocks = atoi(optarg);
				break;		

			case 'X':
            	skipAddrsListPath = optarg;
            	break;

			case 'A':
	            analysisOutPath = optarg;
	            break; 

	        case 'F':
	        	skipFuncs = true;
	        	break;

			case 'B': 
				fixBPatch = true;
				break;

			case 'b': 
				fixBPatch = false;
				break;

			case 'V':
				verbose = true;
				break;

			default:
				cerr << "Usage: " << argv[0] << USAGE;
				return false;
		}
	}

	if (originalBinary == NULL) {
		cerr << "Input binary is required!\n" << endl;
		cerr << "Usage: " << argv[0] << USAGE;
		return false;
	}

	if (analysisOutPath)
		remove(analysisOutPath);

	return true;
}


/* Initialize list of functions to skip. */

void initSkipFunctions(){
	skipFunctions.insert(".init");
	skipFunctions.insert("init");
	skipFunctions.insert("_init");
	skipFunctions.insert("start");
	skipFunctions.insert("_start");
	skipFunctions.insert("fini");
	skipFunctions.insert("_fini");
	skipFunctions.insert("register_tm_clones");
	skipFunctions.insert("deregister_tm_clones");
	skipFunctions.insert("frame_dummy");
	skipFunctions.insert("__do_global_ctors_aux");
	skipFunctions.insert("__do_global_dtors_aux");
	skipFunctions.insert("__libc_csu_init");
	skipFunctions.insert("__libc_csu_fini");
	skipFunctions.insert("__libc_start_main");
	skipFunctions.insert("__gmon_start__");
	skipFunctions.insert("__cxa_atexit");
	skipFunctions.insert("__cxa_finalize");
	skipFunctions.insert("__assert_fail");
	skipFunctions.insert("free");
	skipFunctions.insert("fnmatch");
	skipFunctions.insert("readlinkat");
	skipFunctions.insert("malloc");
	skipFunctions.insert("calloc");
	skipFunctions.insert("realloc");
	skipFunctions.insert("argp_failure");
	skipFunctions.insert("argp_help");
	skipFunctions.insert("argp_state_help");
	skipFunctions.insert("argp_error");
	skipFunctions.insert("argp_parse");
	skipFunctions.insert("__afl_maybe_log");
	skipFunctions.insert("__fsrvonly_store");
	skipFunctions.insert("__fsrvonly_return");
	skipFunctions.insert("__fsrvonly_setup");
	skipFunctions.insert("__fsrvonly_setup_first");
	skipFunctions.insert("__fsrvonly_forkserver");
	skipFunctions.insert("__fsrvonly_fork_wait_loop");
	skipFunctions.insert("__fsrvonly_fork_resume");
	skipFunctions.insert("__fsrvonly_die");
	skipFunctions.insert("__fsrvonly_setup_abort");
	skipFunctions.insert(".AFL_SHM_ENV");
	return;
}


/* Initialize list of addresses to skip from user-provided file. */

void initSkipAddresses(){
    if (skipAddrsListPath != NULL && access(skipAddrsListPath, R_OK) == 0){
    	char line[256];
        FILE *skipAddrsListFile = fopen(skipAddrsListPath, "r"); 

        while (fgets(line, sizeof(line), skipAddrsListFile)){
        	unsigned long addr = atoi(line);
            skipAddresses.insert(addr);
        }

        fclose(skipAddrsListFile);

    }
    return;
}


/* Initialize list of libraries to skip. */

void initSkipLibraries ()
{
	skipLibraries.insert("libDynInstrument.so");		
	skipLibraries.insert("libDynInstrument.cpp");	
	skipLibraries.insert("libc.so.6");
	skipLibraries.insert("libc.so.7");
	skipLibraries.insert("ld-2.5.so");
	skipLibraries.insert("ld-linux.so.2");
	skipLibraries.insert("ld-lsb.so.3");
	skipLibraries.insert("ld-linux-x86-64.so.2");
	skipLibraries.insert("ld-lsb-x86-64.so");
	skipLibraries.insert("ld-elf.so.1");
	skipLibraries.insert("ld-elf32.so.1");
	skipLibraries.insert("libstdc++.so.6");
	return;
}


/* Extracts function based on input name. Useful for getting instrumentation library callbacks. */

BPatch_function *findFuncByName(BPatch_image * appImg, char *func) {
	vector < BPatch_function * >funcs;

	if (NULL == appImg->findFunction(func, funcs) || !funcs.size()
			|| NULL == funcs[0]) {
		cerr << "Failed to find " << func << " function." << endl;
		return NULL;
	}

	return funcs[0];
}


/* Helper function to retrieve transfer insn's mnemonic. */

string getTransferMnem(BPatch_basicBlock *src){
	ParseAPI::Block *block = ParseAPI::convert(src);
	ParseAPI::Block::Insns insns;
	block->getInsns(insns);
	Instruction::Ptr insn = insns.rbegin()->second;
	Operation mnem = insn->getOperation();
	
	return mnem.format();
}


/* Helper function to retrieve instruction's first opcode byte. */

unsigned char getTransferOpcode(BPatch_basicBlock *src){
	ParseAPI::Block *block = ParseAPI::convert(src);
	Block::Insns insns;
	block->getInsns(insns);
	Instruction::Ptr insn = insns.rbegin()->second;
	unsigned char opcode = insn->rawByte(0);

	return opcode;
}


/* Helper to get the block's transfer type. This is a little 
 * hacky; as Dyninst does not reliably support transfer types, 
 * this instead checks their mnemonic and opcode first byte. 
 * For the latter we refer to x86 ISA specifications -- i.e.,
 * any 0xFF byte indicates an indirect transfer. More can be 
 * found here: https://www.felixcloutier.com/x86/jmp. */

string getTransferType(BPatch_basicBlock *block, string mnem){
	unsigned char opcode = getTransferOpcode(block);

	if ((mnem.find("j") != string::npos) or
		(mnem.find("J") != string::npos)){

		if ((mnem.find("jm") != string::npos) or
			(mnem.find("JM") != string::npos)){
			
			if ((opcode == 0xff) or (opcode == 0xFF))
				return "UncIndJMP";
			else
				return "UncDirJMP";
		}
		else
			return "CndDirJMP";
	}
		
	if ((mnem.find("call") != string::npos) or
		(mnem.find("CALL") != string::npos)){

		if ((opcode == 0xff) or (opcode == 0xFF))
			return "IndCALL";
		else
			return "DirCALL";

	}
		
	if ((mnem.find("ret") != string::npos) or
		(mnem.find("RET") != string::npos))
		return "RET";

	/* If no type detected, return our junk type. */

	return "None";
}


/* Helper to get target address of any direct conditional 
 * transfer jump. For all else this returns the 0 address. */

unsigned long getTransferTarg(BPatch_basicBlock *block){
	vector <BPatch_edge *> outEdges;
	block->getOutgoingEdges(outEdges);

	if (outEdges.size() > 1){
		auto edgeIter = outEdges.begin();
		for(; edgeIter != outEdges.end(); edgeIter++) {	
			if ((*edgeIter)->getType() == BPatch_edgeType::CondJumpTaken)
				return (*edgeIter)->getTarget()->getStartAddress();
		}	
	}

	return 0;
}


/* Instrument the basic block. */

void instrumentBlock(BPatch_basicBlock *block) {
	unsigned long addr = block->getStartAddress();
	unsigned long targ = getTransferTarg(block);
	string mnem = getTransferMnem(block);
	string type = getTransferType(block, mnem);

	if (verbose)
		cout << mnem << " " << type << " " << hex << 
		addr << " " << hex << targ << endl;

	/* Obtain the block's entry point. */

	BPatch_point *patchPoint = block->findEntryPoint();

	/* Set up the patch callback and its args. */

	vector <BPatch_snippet *> patchArgs;

	BPatch_constExpr argType(type.c_str());
	patchArgs.push_back(&argType);

	BPatch_constExpr argAddr(addr);
	patchArgs.push_back(&argAddr);

	BPatch_constExpr argTarg(targ);
	patchArgs.push_back(&argTarg);

	/* Insert additional arg(s) / insert callback 
	 * depending on existence of trace path. */

	BPatchSnippetHandle *handle;
	
	if (!tracePath) {
		BPatch_funcCallExpr patch(*Patch_cft, patchArgs);
		handle = appBin->insertSnippet(patch, *patchPoint, 
			BPatch_callBefore, BPatch_lastSnippet);
	}

	else {
		BPatch_constExpr argTracePath(tracePath);
		patchArgs.push_back(&argTracePath);
		BPatch_funcCallExpr patch(*Patch_cftToLog, patchArgs);
		handle = appBin->insertSnippet(patch, *patchPoint, 
			BPatch_callBefore, BPatch_lastSnippet);
	}
	
	/* Verify instrumentation worked. */

	if (!handle)
		cerr << "## Failed to instrument at 0x" << hex << addr << endl;
	
	return;
}


int main(int argc, char **argv) {

	/* Block/edge sets. */

	set <BPatch_basicBlock *> allBlocks;

	/* Parse arguments. */

	if (!parseOptions(argc, argv)) return EXIT_FAILURE;

	/* Initialize libraries, addresses, and functions to skip. */

	initSkipLibraries();
    initSkipAddresses();
	if (skipFuncs) initSkipFunctions();

	/* Set up Dyninst objects and verify input binary. */

	BPatch bpatch;

	if (fixBPatch==true){
		bpatch.setDelayedParsing(true);    // ???
		bpatch.setLivenessAnalysis(false); // ++speed on true (but crashes) 
		bpatch.setMergeTramp(true);        // ++speed on true
		bpatch.setInstrStackFrames(false); // ++speed on false
		bpatch.setTrampRecursive(true);    // ++speed on true 
	}	

	appBin = bpatch.openBinary(originalBinary, false);
	
	if (appBin == NULL) {
		cerr << "Failed to open binary" << endl;
		return EXIT_FAILURE;
	}

	BPatch_image *appImg = appBin->getImage();

	/* Set up instrumentation library for callbacks. */

	if (!appBin->loadLibrary(instLibrary)) {
		cerr << "Failed to open instrumentation library " << instLibrary << endl;
		cerr << "It needs to be located in the curent working directory." << endl;
		return EXIT_FAILURE;
	}

	Patch_cft = findFuncByName(appImg, (char *) "Patch_cft");
	Patch_cftToLog = findFuncByName(appImg, (char *) "Patch_cftToLog");

	/* Iterate through the binary's modules. */

	vector <BPatch_module *> *mods = appImg->getModules();
	auto modIter = mods->begin();
	for(; modIter != mods->end(); modIter++) {
		BPatch_module *mod = (*modIter);

		/* Extract module name and skip if in skipLibraries. */

		char modName[1024];
		if (skipLibraries.find(mod->getName(modName, 1024)) != skipLibraries.end()) {
			continue;
		}

		/* Iterate through all functions. */

		vector < BPatch_function * > *funcs = (*modIter)->getProcedures();
		auto funcIter = funcs->begin();
		for(; funcIter != funcs->end(); funcIter++) {
			BPatch_function *func = (*funcIter);

			/* Extract function name and skip if in skipFunctions. */

			if (skipFunctions.find(func->getName()) != skipFunctions.end()) {
				continue;
			}

			/* Iterate through all blocks. */

			BPatch_flowGraph *cfg = func->getCFG();
			set < BPatch_basicBlock * > blocks;
			cfg->getAllBasicBlocks(blocks);

			auto blockIter = blocks.begin();
			for (; blockIter != blocks.end(); blockIter++){
				allBlocks.insert((*blockIter));
			}
		}
	}

	/* Instrument each block. */

	auto blockIter = allBlocks.begin();
	for (; blockIter != allBlocks.end(); blockIter++)
		instrumentBlock((*blockIter));

	/* Output the binary. */

	if (outputBinary){
		cout << "## Saving the instrumented binary to " << outputBinary << " ..." << endl;
		if (!appBin->writeFile(outputBinary)) {
			cerr << "## Failed to write output file: " << outputBinary << endl;
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}
