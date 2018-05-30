import sys
import re
import string 
import os

trace_path = sys.argv[1]
stateful_file = sys.argv[2]
dpdk_file = sys.argv[3]
time_file = sys.argv[4]
verification_file = sys.argv[5]

stateful_fns = {}
verif_fns = {}
dpdk_fns = {}
time_fns = {}
symbol_re = re.compile('klee*')
symbol2_re = re.compile('exit@plt*')

def main():
 with open(stateful_file,"r") as stateful:
  stateful_fns = (line.rstrip() for line in stateful) 
  stateful_fns = list(line for line in stateful_fns if line)

 with open(verification_file,"r") as verif:
  verif_fns = (line.rstrip() for line in verif)
  verif_fns = list(line for line in verif_fns if line)

 with open(dpdk_file,"r") as dpdk:
  dpdk_fns = (line.rstrip() for line in dpdk)
  dpdk_fns = list(line for line in dpdk_fns if line)

 with open(time_file,"r") as time:
  time_fns = (line.rstrip() for line in time)
  time_fns = list(line for line in time_fns if line)

 for root, dirs, files in os.walk(trace_path):
  for file in files:
   with open(file) as f:
    if file.endswith(".packet_relevant_instructions"):
     trace_lines = (line.rstrip() for line in f)
     trace_lines = list(line for line in trace_lines if line)
     dump_file=file.replace('.packet_relevant_instructions','.packet.demarcated')
     with open(dump_file,"w") as output:
      for text in trace_lines:
       index1 = find_nth(text,"|",1)
       index2 = find_nth(text,"|",2)
       fn_call_stack = text[index1+1:index2-1]
       words = fn_call_stack.split()
     
       stateful = 0
       dpdk = 0
       time = 0
       verif = 0

       for fn_name in words:
        if(fn_name in stateful_fns):
	 stateful = 1
         break
        elif(fn_name in dpdk_fns):
         dpdk = 1
         break
        elif(fn_name in time_fns):
         time = 1
         break
        elif(fn_name in verif_fns or symbol_re.match(fn_name) or symbol2_re.match(fn_name)):
         verif = 1
         break
       if(stateful):
        output.write("Call to libVig model - " + fn_name + "\n")
       elif(dpdk):
	output.write("Call to DPDK model - " + fn_name + "\n")
       elif(time):
        output.write("Call to Time model - " + fn_name + "\n")
       elif(verif):
        output.write("Call to Verification Code - " + fn_name + "\n")
       else:
        output.write(text)
        output.write("\n") 

  
def find_nth(haystack, needle, n):
 start = haystack.find(needle)
 while start >= 0 and n > 1:
  start = haystack.find(needle, start+len(needle))
  n -= 1
 return start

main()
