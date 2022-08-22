# Dyninst vars - edit DYN_ROOT accordingly

DYN_ROOT 	= /home/osboxes/Desktop/dynBuildDir
CC 			= gcc 
CXX 		= g++
CXXFLAGS 	= -g -Wall -O3 -std=c++11
LIBFLAGS 	= -fpic -shared
LDFLAGS 	= -I/usr/include -I$(DYN_ROOT)/include -L$(DYN_ROOT)/lib \
				-ldyninstAPI -lpatchAPI -linstructionAPI -lparseAPI -lsymtabAPI \
				-lsymLite -lboost_system -lcommon -liberty 

all: dsAnalyzeCFG dtAnalyzeCFG dtAnalyzeEdgeFreqs dtCollect dtInstrument libDynInstrument 

dsAnalyzeCFG: dsAnalyzeCFG.cpp
	$(CXX) -Wl,-rpath-link,$(DYN_ROOT)/lib -Wl,-rpath-link,$(DYN_ROOT)/include $(CXXFLAGS) -o dsAnalyzeCFG dsAnalyzeCFG.cpp $(LDFLAGS)

dtAnalyzeCFG:
	cython --embed dtAnalyzeCFG.py -3
	$(CC) -O3 -o dtAnalyzeCFG dtAnalyzeCFG.c `python3-config --cflags --ldflags`

dtAnalyzeEdgeFreqs:
	cython --embed dtAnalyzeEdgeFreqs.py -3
	$(CC) -O3 -o dtAnalyzeEdgeFreqs dtAnalyzeEdgeFreqs.c `python3-config --cflags --ldflags`

dtCollect: dtCollect.cpp
	$(CXX) $(CXXFLAGS) -o dtCollect dtCollect.cpp

dtInstrument: dtInstrument.cpp
	$(CXX) -Wl,-rpath-link,$(DYN_ROOT)/lib -Wl,-rpath-link,$(DYN_ROOT)/include $(CXXFLAGS) -o dtInstrument dtInstrument.cpp $(LDFLAGS)

libDynInstrument: libDynInstrument.cpp
	$(CXX) $(CXXFLAGS) -o libDynInstrument.so libDynInstrument.cpp $(LDFLAGS) $(LIBFLAGS)

clean:
	rm -rf dsAnalyzeCFG dtAnalyzeCFG dtAnalyzeEdgeFreqs dtCollect dtInstrument *.o *.so *.pyc 
