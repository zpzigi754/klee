import re
import sys
import subprocess
import string
import os

trace_path = sys.argv[1] 
hit_rate_file=sys.argv[2]
cold_miss_rate_file=sys.argv[3]
num_accesses_file=sys.argv[4]
def main():
 with open(hit_rate_file,'w') as hit_output,open(num_accesses_file,'w') as num_output, open(cold_miss_rate_file,'w') as cold_output:
  for root, dirs, files in os.walk(trace_path):
   for file in files:
    with open(file,'r') as f:
     if file.endswith(".classified"):
      trace_lines = (line.rstrip() for line in f)
      trace_lines = list(line for line in trace_lines if line)
      num_accesses = 0
      hits = 0 
      cold_misses=0
      for text in trace_lines:
       num_accesses+=1
       if(text == "Hit"):
        hits+=1
       elif(text == "Cold Miss"):
	cold_misses+=1
      if(num_accesses >0):
       hit_rate=str((100*hits)/num_accesses)
       cold_miss_rate=str((100*cold_misses)/num_accesses)
       hit_output.write(hit_rate+"\n")
       cold_output.write(cold_miss_rate+"\n")
       num_output.write(str(num_accesses)+"\n")

main()
      
