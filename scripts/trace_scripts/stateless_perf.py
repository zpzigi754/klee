import sys
import re
import string
import os

num_insns = sys.argv[1]
num_accesses_file=sys.argv[2]
hits_file=sys.argv[3]
trace_nos = sys.argv[4]
perf_out = sys.argv[5]


dram_latency = 200
l1_latency = 2
cpi = 1 

with open (perf_out,'w') as output:
 with open(num_insns,'r') as f1, open(num_accesses_file,'r') as f2,open(hits_file,'r') as f3,open(trace_nos,'r') as f4:
  for line1, line2, line3, line4 in zip(f1,f2,f3,f4):
   l1=int(line1)
   l2=int(line2)
   l3=int(line3)
   line4 = line4.strip()
   line4 = line4.replace(".packet.stateless_mem_trace.classified","")
   perf = l1*cpi + (l2-l3)*dram_latency + l3*l1_latency
   output.write(line4 + "," + "instruction count"+ "," +str(l1+l2)+"\n")
   output.write(line4 + "," + "memory instructions"+ ","+ str(l2)+"\n")
   output.write(line4 + "," + "execution cycles"+ "," +str(perf)+"\n")
	


