#!/usr/bin/python3
import sys
import argparse

# Parses the trace file and generates CFG accordingly.

def getCFG(tracePath, logPath, maxTraces, verbose):
	cfgBlocks = {}
	cfgEdges = {}
	data = []
	numTraces = 0

	with open(tracePath, "r") as traceFile:

		# Read line by line

		for i, line in enumerate(traceFile):

			# If hit our delimiter, process current trace

			if line.startswith("## START"):
				numTraces += 1
				trace = data

				# Progress logging

				if logPath != "":
					logFile = open(logPath, "w+")
					logFile.write("%i traces processed\n" % numTraces)
					logFile.close()
				
				# Read trace line by line, skipping header.

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
						if source not in cfgBlocks.keys():
							cfgBlocks[source] = {"cftInsn":srcCftInsn,"cftTarg":srcCftTarg, \
								"inAddrs":set(), "outAddrs":set()}

						(trgCftInsn, target, trgCftTarg) = rawTrg	
						if target not in cfgBlocks.keys():
							cfgBlocks[target] = {"cftInsn":trgCftInsn,"cftTarg":trgCftTarg, \
								"inAddrs":set(), "outAddrs":set()}
						
						# Update source outgoing edge / target incoming edge addrs.

						cfgBlocks[source]["outAddrs"].add(target)
						cfgBlocks[target]["inAddrs"].add(source)

						# Generate edge and add to our dictionary

						edgeKey = "%s:%s" % (source, target)
						if edgeKey not in cfgEdges:
							cftType = srcCftInsn

							# Handle cond. direct target/fallthru distinction

							if (cftType == "CndDirJMP"):
								if (srcCftTarg == target):
									cftType = "CndDirJMP_Targ"
								else:
									cftType = "CndDirJMP_Fall"

							edge = {"source":source, "target":target, "cftType":cftType}

							if (verbose == True):
								print (edge)
							
							cfgEdges[edgeKey] = edge

					except:
						continue

				data = []

			data.append(line)

			# Compare to maxTraces and exit accordingly.

			if (maxTraces > 0 and numTraces > maxTraces):

				return (cfgBlocks, cfgEdges)

	return (cfgBlocks, cfgEdges)


# Helper function to extract all CFG edges based on their type. 

def getAndPrintTransferStats(cfgEdges):
	Count_CndDirJMP_Targ = 0
	Count_CndDirJMP_Fall = 0
	Count_UncDirJMP = 0
	Count_UncIndJMP = 0
	Count_DirCALL = 0
	Count_IndCALL = 0
	Count_RET = 0
	Count_Other = 0

	for edge in cfgEdges:
		cftType = cfgEdges[edge]["cftType"]

		if (cftType == "CndDirJMP_Targ"):
			Count_CndDirJMP_Targ+=1

		if (cftType == "CndDirJMP_Fall"):
			Count_CndDirJMP_Fall+=1

		if (cftType == "UncDirJMP"):
			Count_UncDirJMP+=1

		if (cftType == "UncIndJMP"):
			Count_UncIndJMP+=1

		if (cftType == "DirCALL"):
			Count_DirCALL+=1

		if (cftType == "IndCALL"):
			Count_IndCALL+=1

		if (cftType == "RET"):
			Count_RET+=1

		if (cftType == "None"):
			Count_Other+=1

	printTransferTypes(cfgEdges, Count_CndDirJMP_Targ, Count_CndDirJMP_Fall, \
		Count_UncDirJMP, Count_UncIndJMP, \
		Count_DirCALL, Count_IndCALL, \
		Count_RET, Count_Other)

	return


## Helper function to get critical eges.

def getCriticalEdges(cfgBlocks, cfgEdges, verbose):
	critEdges = {}

	# Critical edge definition: any edge whose
	# start block has 2+ outgoing edges, or whose
	# end block has 2+ incoming edges.

	for edgeKey in cfgEdges:

		cftType = cfgEdges[edgeKey]["cftType"]
		source  = cfgEdges[edgeKey]["source"]
		target  = cfgEdges[edgeKey]["target"]
		srcOutAddrs = cfgBlocks[source]["outAddrs"]
		trgInAddrs  = cfgBlocks[target]["inAddrs"]

		if ((len(srcOutAddrs) >= 2) and \
			(len(trgInAddrs) >= 2)):
			
			critEdge = {"cftType":cftType, "source":source, "target":target, \
				"srcOutAddrs":srcOutAddrs, "trgInAddrs":trgInAddrs}
			
			if (verbose==True):
				print (critEdge)

			critEdges[edgeKey] = critEdge

	return critEdges


# Helper function to print transfer types. 

def printTransferTypes(edges, Count_CndDirJMP_Targ, Count_CndDirJMP_Fall, \
		Count_UncDirJMP, Count_UncIndJMP, \
		Count_DirCALL, Count_IndCALL, \
		Count_RET, Count_Other):

	print ("## Total Branches   : %i" % len(edges))
	print ("##  Cnd. Dir. Jumps : %i" % (Count_CndDirJMP_Targ + Count_CndDirJMP_Fall))
	print ("##       Targ Edges : %i" % Count_CndDirJMP_Targ)
	print ("##       Fall Edges : %i" % Count_CndDirJMP_Fall)
	print ("##  Unc. Dir. Jumps : %i" % Count_UncDirJMP)
	print ("##  Unc. Ind. Jumps : %i" % Count_UncIndJMP)
	print ("##  Dir. Calls      : %i" % Count_DirCALL)
	print ("##  Ind. Calls      : %i" % Count_IndCALL)
	print ("##  Returns         : %i" % Count_RET)
	print ("##  Other           : %i" % Count_Other)

	return

# Parse args.

def parseArgs():
	p = argparse.ArgumentParser()
	p.add_argument("-T", dest="tracePath", required=True, help="dtCollect-generated trace path.", default="", action='store')
	p.add_argument("-L", dest="logPath", required=False, help="Output log path.", default="", action='store')
	p.add_argument("-M", dest="maxTraces", required=False, help="Maximum number of traces.", default=0, action='store', type=int)
	p.add_argument("-V", dest="verbose", required=False, help="Verbose output.", default=False, action='store_true')
	return p.parse_args()


def main():
	args = parseArgs()
	tracePath = args.tracePath
	logPath = args.logPath
	maxTraces = args.maxTraces
	verbose = args.verbose

	# Get the CFG from the parsed traces

	print ("## --- Control-flow Stats ---")
	(cfgBlocks, cfgEdges) = getCFG(tracePath, logPath, maxTraces, verbose)
	getAndPrintTransferStats(cfgEdges)

	print ("\n## --- Critical Edge Stats ---")
	critEdges = getCriticalEdges(cfgBlocks, cfgEdges, verbose)
	getAndPrintTransferStats(critEdges)


if __name__ == "__main__":
	main()