#include <cstdlib>
#include <iostream>
#include <vector>
#include <string>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sstream>
#include <climits>
#include <cstring>
#include <fstream>
#include <getopt.h>
#include <sys/wait.h>
#include <sys/time.h>
using namespace std;

string dataDumpPath;
string sizeDumpPath;
string tracePath;
string outFilePath;
string outDir;
int maxExecs;
int devNullFD = -1;
int totalExecs = 0;
int timeout = 100;
bool useBPatchFixes=true;

static const char *OPT_STR = "I:S:F:T:t:M:Bb";
static const char *USAGE = " [options] -- [./target] [args]\n \
  Options:\n \
    -I: input dump path\n \
    -S: sizes dump path\n \
    -F: replacement for .cur_input\n \
    -T: output trace path\n \
    -t: trace timeout in ms (default: 500ms)\n \
    -M: max execs\n \
    -B: apply BPatch fixes (on by default)\n \
    -b: don't apply BPatch fixes\n" ;

bool parseOptions(int argc, char **argv){
  int c;
  while ((c = getopt(argc, argv, OPT_STR)) != -1){
    switch ((char) c) {

      case 'I': 
        dataDumpPath = optarg;
        break;

      case 'S': 
        sizeDumpPath = optarg;
        break;

      case 'F': 
        outFilePath = optarg;
        break;

      case 'T': 
        tracePath = optarg;
        break;

      case 't': 
        timeout = atoi(optarg);
        break;

      case 'M': 
        maxExecs = atoi(optarg);
        break;

      case 'B': 
        useBPatchFixes = true;
        break;

      case 'b': 
        useBPatchFixes = false;
        break;

      default:
        cerr << "Usage: " << argv[0] << USAGE;
        return false;
    }
  }

  if (dataDumpPath.empty() or sizeDumpPath.empty() or tracePath.empty()) {
    cerr << "Input data/sizes dumps and output trace file is required!\n" << endl;
    cerr << "Usage: " << argv[0] << USAGE;
    return false;
  }

  return true;
}


/* Sets up argument array for target binary. */

void setupArgv(char ** argv){
  if (outFilePath.empty())
    outFilePath = ".cur_input";

  int i = 0;
  while (argv[i]) {
    
    if (string(argv[i]) == "@@"){
      argv[i] = (char *) outFilePath.c_str();
    }

    i++;
  }
}

/* Helper function to execute any passed in arguments. */

void execute(char * args[], char * pidName, int printOutput, int timeout){
  int pidFork, status;
  static struct itimerval it;

  pidFork = fork();
  if (pidFork < 0 ){
    fprintf(stderr, "%s: %s\n", pidName, strerror(errno));
    exit(EXIT_FAILURE);
  }
  
  /* Set start timer. */

  if (timeout > 0){
    it.it_value.tv_sec = (timeout / 1000);
    it.it_value.tv_usec = (timeout % 1000) * 1000;
    setitimer(ITIMER_REAL, &it, NULL);
  }

  if (pidFork == 0){

    if (!printOutput){
      setsid();
      dup2(devNullFD, 1); 
      dup2(devNullFD, 2); 
    }
    
    if (execvp(args[0], args) < 0){
      if (printOutput)
        fprintf(stderr, "%s: %s\n", pidName, strerror(errno));
    }
    
    exit(0);
  }

  /* Deactivate timer. */

  if (timeout > 0){
    it.it_value.tv_sec = 0;
    it.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL, &it, NULL);
  }
  
  if (waitpid(pidFork, &status, 0) <= 0){
    fprintf(stderr, "%s: %s\n", pidName, strerror(errno));
    exit(EXIT_FAILURE);
  }

  return;
}

/* Set up any necessary global variables. */

void setupGlobals(){

  /* Setup null file descriptor. */

  devNullFD = open("/dev/null", O_RDWR);

  /* Set up fresh trace path. */

  if (!tracePath.empty()) remove(tracePath.c_str());

  return;
}

/* Executes the application, monitoring for timeout. */

void runTarget(char ** argv, int timeout){

  if (!tracePath.empty()){
    FILE *traceFile = fopen(tracePath.c_str(), "a+");
    fprintf(traceFile, "\n## START OF TRACE\n");  
    fclose(traceFile);
  }

  execute(argv, argv[0], 0, timeout);

  return;
}


int main(int argc, char** argv) {

  /* Parse arguments. */

  if (!parseOptions(argc, argv)) return EXIT_FAILURE;

  /* Set up arguments and global vars. */

  setupArgv(argv + optind + 1);
  setupGlobals();

  /* Open dumps and start parsing. */

  FILE * data  = fopen(dataDumpPath.c_str(), "rb");
  FILE * sizes = fopen(sizeDumpPath.c_str(), "r");

  cout << "## Starting replay..." << endl;

  char line[256];
  while (fgets(line, sizeof(line), sizes)) {

    /* Read line from sizes file. */

    size_t size = (size_t) atoi(line);  
    if(size <= 0) {
      printf("ERROR: malformed sizes file\n");
      exit(EXIT_FAILURE);
    }

    /* Read size bytes into buffer. */

    char buffer[size];
    if(fread(buffer, 1, size, data) != size) {
      perror("ERROR: data not read from input dump");
      exit(EXIT_FAILURE);
    }

    /* Write size bytes to out file. */

    FILE * tmp = fopen(outFilePath.c_str(), "wb");
    if(fwrite(buffer, 1, size, tmp) != size) {
      perror("ERROR: problem creating temporary input file");
      exit(EXIT_FAILURE);
    }    
    fclose(tmp);

    /* Run the test case. */

    runTarget(argv + optind, timeout);

    /* Check max execs if specified. */

    totalExecs++;
    if (maxExecs > 0){
      if (totalExecs >= maxExecs)
        break;
    }
  }

  cout << "## Replay completed." << endl;

  exit(0);
}
