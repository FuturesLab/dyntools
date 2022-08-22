#include <cstdlib>
#include <iostream>
#include <vector>
#include <string>
#include <stdlib.h>
#include <sstream>
#include <climits>
#include <cstring>
#include <fstream>
#include <tuple>
#include <getopt.h>
using namespace std;

/* DyninstAPI includes */

#include "BPatch.h"
#include "BPatch_binaryEdit.h"
#include "BPatch_flowGraph.h"
#include "BPatch_function.h"
#include "BPatch_point.h"
#include "CFG.h"
#include "CodeObject.h"
#include "InstructionDecoder.h"
using namespace Dyninst;
using namespace ParseAPI;
using namespace InstructionAPI;

bool verbose = false;
bool skipInitFuncs = false;
bool getCritEdgeStats = false;
bool getFuncNames = false;

char * originalBinary = NULL;
char * addrsToSkipListPath = NULL;

int minBlockSize = 1;
int numSkipBlocks = 0;

set <string> libsToSkip;
set <string> initFuncsToSkip;
set <long> skipAddresses;

static const char *OPT_STR = "M:N:A:VICF";
static const char *USAGE = " [input_binary] [analysis_options]\n \
	Analysis options:\n \
		-M: minimum block size (default: 1)\n \
		-N: number of blocks to skip (default: 0)\n \
		-A: path to list of block addresses to skip\n \
		-O: path to output analysis log\n \
		-I: skip initialization functions (e.g., _start)\n \
		-C: get stats on critical edges\n \
		-F: get names of all functions analyzed\n \
	Additional options:\n \
		-V: verbose mode\n";

bool parseOptions(int argc, char **argv){
	originalBinary = argv[1];
	int c;
	while ((c = getopt(argc, argv, OPT_STR)) != -1){
		switch ((char) c) {

			case 'M':	
				minBlockSize = atoi(optarg);
				break;

			case 'N':
				numSkipBlocks = atoi(optarg);
				break;		

			case 'A':
            	addrsToSkipListPath = optarg;
            	break;

	        case 'I':
	        	skipInitFuncs = true;
	        	break;

	        case 'C':
	        	getCritEdgeStats = true;
	        	break;

	        case 'F':
	        	getFuncNames = true;
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

	return true;
}


/* Extracts function based on input name. Useful for getting instrumentation library callbacks. */

BPatch_function *findFuncByName(BPatch_image * appImage, char *func) {
	vector < BPatch_function * >funcs;

	if (NULL == appImage->findFunction(func, funcs) || !funcs.size()
			|| NULL == funcs[0]) {
		cerr << "Failed to find " << func << " function." << endl;
		return NULL;
	}

	return funcs[0];
}


/* Initialize list of functions to skip. */

void initSkipInitFuncs(){
	initFuncsToSkip.insert(".init");
	initFuncsToSkip.insert("init");
	initFuncsToSkip.insert("_init");
	initFuncsToSkip.insert("start");
	initFuncsToSkip.insert("_start");
	initFuncsToSkip.insert("fini");
	initFuncsToSkip.insert("_fini");
	initFuncsToSkip.insert("register_tm_clones");
	initFuncsToSkip.insert("deregister_tm_clones");
	initFuncsToSkip.insert("frame_dummy");
	initFuncsToSkip.insert("__do_global_ctors_aux");
	initFuncsToSkip.insert("__do_global_dtors_aux");
	initFuncsToSkip.insert("__libc_csu_init");
	initFuncsToSkip.insert("__libc_csu_fini");
	initFuncsToSkip.insert("__libc_start_main");
	initFuncsToSkip.insert("__gmon_start__");
	initFuncsToSkip.insert("__cxa_atexit");
	initFuncsToSkip.insert("__cxa_finalize");
	initFuncsToSkip.insert("__assert_fail");
	initFuncsToSkip.insert("free");
	initFuncsToSkip.insert("fnmatch");
	initFuncsToSkip.insert("readlinkat");
	initFuncsToSkip.insert("malloc");
	initFuncsToSkip.insert("calloc");
	initFuncsToSkip.insert("realloc");
	initFuncsToSkip.insert("argp_failure");
	initFuncsToSkip.insert("argp_help");
	initFuncsToSkip.insert("argp_state_help");
	initFuncsToSkip.insert("argp_error");
	initFuncsToSkip.insert("argp_parse");
	initFuncsToSkip.insert("__afl_maybe_log");
	initFuncsToSkip.insert("__fsrvonly_store");
	initFuncsToSkip.insert("__fsrvonly_return");
	initFuncsToSkip.insert("__fsrvonly_setup");
	initFuncsToSkip.insert("__fsrvonly_setup_first");
	initFuncsToSkip.insert("__fsrvonly_forkserver");
	initFuncsToSkip.insert("__fsrvonly_fork_wait_loop");
	initFuncsToSkip.insert("__fsrvonly_fork_resume");
	initFuncsToSkip.insert("__fsrvonly_die");
	initFuncsToSkip.insert("__fsrvonly_setup_abort");
	initFuncsToSkip.insert(".AFL_SHM_ENV");
	return;
}


/* Initialize list of addresses to skip from user-provided file. */

void initSkipAddrs(){
    if (addrsToSkipListPath != NULL && access(addrsToSkipListPath, R_OK) == 0){
    	char line[256];
        FILE *skipAddrsListFile = fopen(addrsToSkipListPath, "r"); 

        while (fgets(line, sizeof(line), skipAddrsListFile)){
        	unsigned long addr = atoi(line);
            skipAddresses.insert(addr);
        }

        fclose(skipAddrsListFile);

    }
    return;
}


/* Initialize list of libraries to skip. */

void initLibsToSkip ()
{
	libsToSkip.insert("libDynInstrument.so");		
	libsToSkip.insert("libc.so.6");
	libsToSkip.insert("libc.so.7");
	libsToSkip.insert("ld-2.5.so");
	libsToSkip.insert("ld-linux.so.2");
	libsToSkip.insert("ld-lsb.so.3");
	libsToSkip.insert("ld-linux-x86-64.so.2");
	libsToSkip.insert("ld-lsb-x86-64.so");
	libsToSkip.insert("ld-elf.so.1");
	libsToSkip.insert("ld-elf32.so.1");
	libsToSkip.insert("libstdc++.so.6");
	return;
}


/* Returns the transfer type string based on Dyninst's ParseAPI EdgeTypeEnum. */

static string getTypeString(int type)
{
	if (type == ParseAPI::CALL)           return "call";
	if (type == ParseAPI::COND_TAKEN)     return "cond-taken";
	if (type == ParseAPI::COND_NOT_TAKEN) return "cond-not-taken"; 
	if (type == ParseAPI::INDIRECT)       return "indirect"; 
	if (type == ParseAPI::DIRECT)         return "direct"; 
	if (type == ParseAPI::FALLTHROUGH)	  return "fallthrough";
	if (type == ParseAPI::CATCH)  		  return "catch";
	if (type == ParseAPI::CALL_FT)		  return "call-ft";
	if (type == ParseAPI::RET)			  return "ret";
	return "unknown";
}


/* Helper function to retrieve transfer insn's mnemonic. */

string getTransferMnem(Block *src){
	Block::Insns insns;
	src->getInsns(insns);
	Instruction::Ptr insn = insns.rbegin()->second;
	Operation mnem = insn->getOperation();
	
	return mnem.format();
}


/* Helper function to retrieve instruction's first opcode byte. */

unsigned char getTransferOpcode(Block *src){
	Block::Insns insns;
	src->getInsns(insns);
	Instruction::Ptr insn = insns.rbegin()->second;
	unsigned char opcode = insn->rawByte(0);

	return opcode;
}


/* Takes in a set of edges and categorizes each by their x86 transfer type. */

void getTransferTypes(set <Edge *> edges, 
	int &Count_CndDirJMP, int &Count_CndDirJMP_Targ, int &Count_CndDirJMP_Fall,
	int &Count_UncDirJMP, int &Count_UncIndJMP, 
	int &Count_DirCALL, int &Count_IndCALL, 
	int &Count_RET, int &Count_EXCPH){

	/* Reset all counters. */

	Count_CndDirJMP = 0;
	Count_CndDirJMP_Targ = 0;
	Count_CndDirJMP_Fall = 0;
	Count_UncDirJMP = 0;
	Count_UncIndJMP = 0;
	Count_DirCALL = 0;
	Count_IndCALL = 0;
	Count_RET = 0;
	Count_EXCPH = 0;
	
	auto edgeIter = edges.begin();
	for(; edgeIter != edges.end(); edgeIter++) {
		Edge * edge = (*edgeIter);

		/* Extract the edge's type and transfer mnemonic. */

		string edgeType = getTypeString(edge->type());
		string mnem = getTransferMnem(edge->src());

		/* Dyninst's ParseAPI's EdgeTypeEnum is unintuitive. Below are my translations: 
		 * 
		 *    COND_TAKEN     = Conditional jump "target" branch; always direct on x86.
		 *    COND_NOT_TAKEN = Conditional jump "fall-thru" branch; we'll call it conditional direct.
		 *    DIRECT         = Unconditional direct jumps (e.g., JMP 0x100).
		 *    INDIRECT       = Unconditional indirect jumps.
		 *    RET            = Return calls; always indirect. 
		 *    CALL           = Function call; can be direct and indirect.
		 *    CALL_FT        = Call "fall-through"; this is a pseudo-edge.
		 *    FALLTHROUGH    = Non-branching "fall-through"; this is a pseudo-edge.
		 *    CATCH          = "Exception handler"; we'll ignore these. */   

		/* Conditional jump; only direct on x86. */

		if (edgeType == "cond-taken"){ 
			Count_CndDirJMP++;
			Count_CndDirJMP_Targ++;
		}

		if (edgeType == "cond-not-taken"){
			Count_CndDirJMP++;
			Count_CndDirJMP_Fall++;
		}

		/* Unconditional jumps; can be direct/indirect. */

		if (edgeType == "direct"){
			Count_UncDirJMP++;
		}

		if (edgeType == "indirect"){
			Count_UncIndJMP++;
		}

		/* Dyninst doesn't support direct/indirect call edge typing.
		 * so a workaround is to differentiate based on sink edges. */

		if (edgeType == "call"){

			if (edge->sinkEdge() == true){
				Count_IndCALL++;
			}
			else {
				Count_DirCALL++;
			}
		}

		/* Returns; always indirect. */

		if (edgeType == "ret")
			Count_RET++;

		/* Error-handling edges. Unclear, but probably indirect. */

		if (edgeType == "catch"){
			Count_EXCPH++;
		}
	}

	return;
}


/* Updates global set of critical edges. */

void getCriticalEdges(set <Edge *> &edges, set <Edge *> &crit){

	auto edgeIter = edges.begin();
	for(; edgeIter != edges.end(); edgeIter++) {
		Edge *edge = (*edgeIter);

		/* Set up set of source block's outgoing edges. */

		Block *src = edge->src();
		set <Edge *> srcOutSet;

		auto srcOutIter = src->targets().begin();
		for(; srcOutIter != src->targets().end(); srcOutIter++) {
			Edge *srcOutEdge = (*srcOutIter);
			
			/* Check if the edge is in the parent set of edges.
			 * This is important to screen for pseudo-edges. */

			if (edges.find(srcOutEdge) != edges.end())
				srcOutSet.insert(srcOutEdge);				
		}

		/* Set up set of target block's incoming edges. */

		Block *trg = edge->trg();
		set <Edge *> trgInSet;

		auto trgInIter = trg->sources().begin();
		for(; trgInIter != trg->sources().end(); trgInIter++) {
			Edge *trgInEdge = (*trgInIter);

			/* Check if the edge is in the parent set of edges.
			 * This is important to screen for pseudo-edges. */

			if (edges.find(trgInEdge) != edges.end())
				trgInSet.insert(trgInEdge);
		}

		/* A critical edge is an edge whose source block has 2+ outgoing edges, 
		 * and whose target block has 2+ incoming edges. */

		if ((srcOutSet.size() >= 2) and (trgInSet.size() >= 2))
			crit.insert(edge);
	}

	return;
}


/* Helper function to extract all CFG edges based on their type. 
 * Exclude call-ft because conditional calls don't exist on x86. 
 * Exclude fallthroughs because these are not from cond. jumps. */

void getAllEdges(Block *block, set <Edge *> &edges){

	auto outIter = block->targets().begin();
	for(; outIter != block->targets().end(); outIter++) {
		Edge *edge = (*outIter);

		string edgeType = getTypeString(edge->type());
		if ((edgeType == "call-ft") or 
			(edgeType == "fallthrough") or 
			(edgeType == "catch")){
			continue;
		}

		edges.insert(edge);
	}

	auto inIter = block->sources().begin();
	for(; inIter != block->sources().end(); inIter++) {
		Edge *edge = (*inIter);

		string edgeType = getTypeString(edge->type());
		if ((edgeType == "call-ft") or 
			(edgeType == "fallthrough") or 
			(edgeType == "catch")){
			continue;
		}

		edges.insert(edge);
	}

	return;
}


/* Helper function to print transfer types. */

void printTransferTypes(set <Edge *> edges, 
	int &Count_CndDirJMP, int &Count_CndDirJMP_Targ, int &Count_CndDirJMP_Fall,
	int &Count_UncDirJMP, int &Count_UncIndJMP, 
	int &Count_DirCALL, int &Count_IndCALL, 
	int &Count_RET, int &Count_EXCPH){

	cout << "## Total Edges      : " << edges.size() << endl;
	cout << "##  Cnd. Dir. Jumps : " << Count_CndDirJMP << endl;
    cout << "##       Targ Edges : " << Count_CndDirJMP_Targ << endl;
    cout << "##       Fall Edges : " << Count_CndDirJMP_Fall << endl;
    cout << "##  Unc. Dir. Jumps : " << Count_UncDirJMP << endl;
    cout << "##  Unc. Ind. Jumps : " << Count_UncIndJMP << endl;
   	cout << "##  Dir. Calls      : " << Count_DirCALL << endl;
   	cout << "##  Ind. Calls      : " << Count_IndCALL << endl;
   	cout << "##  Returns         : " << Count_RET << endl;
   	cout << "##  Excep.-handling : " << "N/A" << endl;
   	cout << endl;

   	if (verbose) {
   		cout << "Edges, CndDirJMP, CndDirJMPTarg, CndDirJMPFall, UncDirJMP, UncIndJMP, DirCALL, IndCALL, RET, EXCPH" << endl;
   		cout << edges.size() << ", ";
   		cout << Count_CndDirJMP << ", ";
   		cout << Count_CndDirJMP_Targ << ", ";
		cout << Count_CndDirJMP_Fall << ", ";
		cout << Count_UncDirJMP << ", ";
		cout << Count_UncIndJMP << ", ";
		cout << Count_DirCALL << ", ";
		cout << Count_IndCALL << ", ";
		cout << Count_RET << ", ";
		cout << "N/A" << endl;
		cout << endl;
   	}
}


int main(int argc, char **argv) {

	/* Block/edge sets. */

	set <Block *> allBlocks;
	set <Function *> allFuncs;
	set <Edge *> allEdges;
	set <Edge *> critEdges;

	/* Frequency counter vars. */

	int Count_CndDirJMP = 0;
	int Count_CndDirJMP_Targ = 0;
	int Count_CndDirJMP_Fall = 0;
	int Count_UncDirJMP = 0;
	int Count_UncIndJMP = 0;
	int Count_DirCALL = 0;
	int Count_IndCALL = 0;
	int Count_RET = 0;
	int Count_EXCPH = 0;

	/* Parse arguments. */

	if (!parseOptions(argc, argv)) return EXIT_FAILURE;

	/* Initialize libraries, addresses, and functions to skip. */

	initLibsToSkip();
    initSkipAddrs();
	if (skipInitFuncs) initSkipInitFuncs();

	/* Set up Dyninst objects and verify input binary. */

	SymtabCodeSource *appSym;
	CodeObject *appCode;
	appSym 	= new SymtabCodeSource(originalBinary);
	appCode = new CodeObject(appSym);

	if (appSym == NULL or appCode == NULL) {
		cerr << "Failed to open binary!" << endl;
		return EXIT_FAILURE;
	}

	/* Iterate through the binary's functions. */

	appCode->parse();
	const CodeObject::funclist& funcs = appCode->funcs();
	
	auto funcIter = funcs.begin();
	for(; funcIter != funcs.end(); ++funcIter) {
		Function *func = (*funcIter);

		/* Extract function name and skip if in initFuncsToSkip. */

		if (initFuncsToSkip.find(func->name()) != initFuncsToSkip.end()) {
			continue;
		}

		/* Iterate through all basic blocks and get the edges. */

		auto blockIter = func->blocks().begin();
		for(; blockIter != func->blocks().end(); blockIter++) {
			Block *block = (*blockIter);

			/* Extract all in and out edges. Prune exception-handler edges, 
			 * and "pseudo" edges (e.g., call-ft, fallthrough). */

			getAllEdges(block, allEdges);
			allBlocks.insert(block);
		}

		allFuncs.insert(func);
	}

	cout << originalBinary << endl;

	/* Transfer stats for entire binary. */

	cout << "## --- Control-flow Stats ---" << endl;
	cout << "## Total Blocks     : " << allBlocks.size() << endl;
	cout << "## Total Funcs      : " << allFuncs.size() << endl;
	getTransferTypes(allEdges, Count_CndDirJMP, Count_CndDirJMP_Targ, Count_CndDirJMP_Fall, 
		Count_UncDirJMP, Count_UncIndJMP, Count_DirCALL, Count_IndCALL, Count_RET, Count_EXCPH);
	printTransferTypes(allEdges, Count_CndDirJMP, Count_CndDirJMP_Targ, Count_CndDirJMP_Fall, 
		Count_UncDirJMP, Count_UncIndJMP, Count_DirCALL, Count_IndCALL, Count_RET, Count_EXCPH);
	
	/* (optional) Get stats of critical edges. */ 

	if (getCritEdgeStats){
		cout << "## --- Critical Edge Stats ---" << endl;
		getCriticalEdges(allEdges, critEdges);
		getTransferTypes(critEdges, Count_CndDirJMP, Count_CndDirJMP_Targ, Count_CndDirJMP_Fall, 
			Count_UncDirJMP, Count_UncIndJMP, Count_DirCALL, Count_IndCALL, Count_RET, Count_EXCPH);
		printTransferTypes(critEdges, Count_CndDirJMP, Count_CndDirJMP_Targ, Count_CndDirJMP_Fall, 
			Count_UncDirJMP, Count_UncIndJMP, Count_DirCALL, Count_IndCALL, Count_RET, Count_EXCPH);
	}

	/* (optional) Get names of functions analyzed. */ 

	if (getFuncNames){
		cout << "## --- Functions Analyzed ---" << endl;
		auto funcIter = allFuncs.begin();
		for(; funcIter != allFuncs.end(); ++funcIter) {
			Function *func = (*funcIter);
			cout << func->name() << endl;
		}
	}


	cout << endl;

	return EXIT_SUCCESS;
}
