import sys
import re
import string
import os

trace_path = sys.argv[1]
num_insns = sys.argv[2]
num_accesses_file=sys.argv[3]
hits_file=sys.argv[4]
misses_file = sys.argv[5]
trace_nos_file = sys.argv[6]

def main():
 with open(num_insns,"w") as insns_output,open(hits_file,'w') as hit_output,open(num_accesses_file,'w') as num_output,open(misses_file,'w') as miss_output,open(trace_nos_file,'w') as trace_output:
  for root, dirs, files in os.walk(trace_path):
   for file in files:
    with open(file) as f:
     if file.endswith(".classified"):
      trace_output.write(file+"\n")
      trace_lines = (line.rstrip() for line in f)
      trace_lines = list(line for line in trace_lines if line)
      insns = 0
      num_accesses = 0
      hits = 0
      for text in trace_lines:
       if(not(text=="Irrelevant to Trace")):
        if(text=="Non-memory instruction"):
         insns = insns + 1
        else:
         num_accesses+=1
        if(text == "Hit"):
         hits+=1
     
      insns_output.write(str(insns) + "\n")
      hit_output.write(str(hits)+"\n")
      num_output.write(str(num_accesses)+"\n")
      miss_output.write(str(num_accesses-hits)+"\n")

main()
