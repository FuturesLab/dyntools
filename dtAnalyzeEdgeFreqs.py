#!/usr/bin/python3
import sys
import argparse
from ast import literal_eval

# Parses the trace file and generates CFG accordingly.

def parseTraces(tracePath, logPath, maxTraces, critEdges, verbose):
	data = []
	Count_Traces = 0
	freqsDict = {}

	with open(tracePath, "r") as traceFile:

		if (verbose):
			header = "# Count_Edges, Count_CritEdges, " \
				"Count_CritEdgesCndDirJMP_Targ, Count_CritEdgesCndDirJMP_Fall, " \
				"Count_CritEdgesUncDirJMP, Count_CritEdgesUncIndJMP, " \
				"Count_CritEdgesDirCALL, Count_CritEdgesIndCALL, " \
				"Count_CritEdgesRET, Count_CritEdgesOther:"

			print(header)

		# Read line by line

		for i, line in enumerate(traceFile):

			# If hit our delimiter, process current trace

			if line.startswith("## START"):
				Count_Traces += 1
				trace = data

				# Progress logging

				if logPath != "":
					logFile = open(logPath, "w+")
					logFile.write("%i traces processed\n" % Count_Traces)
					logFile.close()
				
				# Read trace line by line, skipping header.

				Count_Edges = 0
				Count_CritEdges = 0
				Count_CritEdgesCndDirJMP_Targ = 0
				Count_CritEdgesCndDirJMP_Fall = 0
				Count_CritEdgesUncDirJMP = 0
				Count_CritEdgesUncIndJMP = 0
				Count_CritEdgesDirCALL = 0
				Count_CritEdgesIndCALL = 0
				Count_CritEdgesRET = 0
				Count_CritEdgesOther = 0

				for j in range(1, len(trace)-1):

					# Retrieve and set both blocks and their edge

					rawSrc = trace[j].strip().split(", ")
					rawTrg = trace[j+1].strip().split(", ")

					# Stop read if hit the last (empty) line

					if (rawTrg == ['']):
						break	

					try:
						# Retrive source/target blocks, or generate new ones

						(srcCftInsn, source, srcCftTarg) = rawSrc
						(trgCftInsn, target, trgCftTarg) = rawTrg	

						# Generate edge and add to our dictionary

						edgeKey = "%s:%s" % (source, target)
						if edgeKey in critEdges:
							Count_CritEdges+=1

							if (srcCftInsn == "CndDirJMP"):
								if (srcCftTarg == target):
									Count_CritEdgesCndDirJMP_Targ+=1
								else:
									Count_CritEdgesCndDirJMP_Fall+=1

							if (srcCftInsn == "UncDirJMP"):
								Count_CritEdgesUncDirJMP+=1

							if (srcCftInsn == "UncIndJMP"):
								Count_CritEdgesUncIndJMP+=1

							if (srcCftInsn == "DirCALL"):
								Count_CritEdgesDirCALL+=1								

							if (srcCftInsn == "IndCALL"):
								Count_CritEdgesIndCALL+=1
							
							if (srcCftInsn == "RET"):
								Count_CritEdgesRET+=1
							
							if (srcCftInsn == "None"):
								Count_CritEdgesOther+=1

						Count_Edges+=1
													
					except:
						continue

				freqs = {"Count_AllEdges":Count_Edges, "Count_CritEdges":Count_CritEdges, \
					"Count_CritEdgesCndDirJMP_Targ":Count_CritEdgesCndDirJMP_Targ, "Count_CritEdgesCndDirJMP_Fall":Count_CritEdgesCndDirJMP_Fall, \
					"Count_CritEdgesUncDirJMP":Count_CritEdgesUncDirJMP, "Count_CritEdgesUncIndJMP":Count_CritEdgesUncIndJMP, \
					"Count_CritEdgesDirCALL":Count_CritEdgesDirCALL, "Count_CritEdgesIndCALL":Count_CritEdgesIndCALL, \
					"Count_CritEdgesRET":Count_CritEdgesRET, "Count_CritEdgesOther":Count_CritEdgesOther}
				
				if (verbose == True):
					string = "%i, %i, %i, %i, %i, %i, %i, %i, %i, %i" % (
						Count_Edges, Count_CritEdges, \
						Count_CritEdgesCndDirJMP_Targ, Count_CritEdgesCndDirJMP_Fall, \
						Count_CritEdgesUncDirJMP, Count_CritEdgesUncIndJMP, \
						Count_CritEdgesDirCALL, Count_CritEdgesIndCALL, \
						Count_CritEdgesRET, Count_CritEdgesOther)

					print(string)

				freqsDict[Count_Traces] = freqs

				data = []

			data.append(line)

			# Compare to maxTraces and exit accordingly.

			if (maxTraces > 0 and Count_Traces > maxTraces):

				return freqsDict

	return freqsDict


# Helper to parse critical edges from dtAnalyzeCFG-generated stats file.

def parseStats(statsPath):
	critEdges = {}

	with open(statsPath, "r") as statsFile:

		for line in statsFile.readlines():
			if line.startswith("##") or len(line) < 2:
				continue
			
			edge = literal_eval(line)

			if ("trgInAddrs" in edge.keys()):
				edgeKey = "%s:%s" % (edge["source"], edge["target"])
				critEdges[edgeKey] = edge

	return critEdges


# Compute frequency statistics.

def computeFreqStats(freqsDict):

	#for trace in freqsDict:
		#print (freqsDict[trace])

	return


# Parse args.

def parseArgs():
	p = argparse.ArgumentParser()
	p.add_argument("-S", dest="statsPath", required=True, help="dtAnalyzeCFG-generated stats path.", default="", action='store')
	p.add_argument("-T", dest="tracePath", required=True, help="dtCollect-generated trace path.", default="", action='store')
	p.add_argument("-L", dest="logPath", required=False, help="Output log path.", default="", action='store')
	p.add_argument("-M", dest="maxTraces", required=False, help="Maximum Count_ber of traces.", default=0, action='store', type=int)
	p.add_argument("-V", dest="verbose", required=False, help="Verbose output.", default=False, action='store_true')
	return p.parse_args()

def main():
	args = parseArgs()
	statsPath = args.statsPath
	tracePath = args.tracePath
	logPath = args.logPath
	maxTraces = args.maxTraces
	verbose = args.verbose

	critEdges = parseStats(statsPath)

	freqsDict = parseTraces(tracePath, logPath, maxTraces, critEdges, verbose)

	computeFreqStats(freqsDict)
	# Get the CFG from the parsed traces

	#print ("## --- Control-flow Stats ---")
	#(cfgBlocks, cfgEdges) = getCFG(tracePath, logPath, maxTraces, verbose)
	#getAndPrintTransferStats(cfgEdges)

	#print ("\n## --- Critical Edge Stats ---")
	#critEdges = getCriticalEdges(cfgBlocks, cfgEdges, verbose)
	#getAndPrintTransferStats(critEdges)


if __name__ == "__main__":
	main()