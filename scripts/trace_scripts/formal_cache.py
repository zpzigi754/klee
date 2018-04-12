import re
import sys
import subprocess
import string
import os

trace_path = sys.argv[1]  #Symbolic address trace
cache_size=32768
cache_block_size = 64
set_associativity = 8
set_size = cache_block_size*set_associativity
num_sets = cache_size/set_size
cache_contents=[[] for _ in xrange(num_sets)]
cache_ages=[[] for _ in xrange(num_sets)]

#Assuming replacement policy is LRU 

symbol_re = re.compile("Irrelevant to Trace")
symbol2_re = re.compile("Non-memory instruction")
def main():
   global cache_contents
   global cache_ages
   for root, dirs, files in os.walk(trace_path):
    for file in files:
     with open(file) as f:
      if file.endswith(".stateless_mem_trace"):
       trace_lines = (line.rstrip() for line in f)
       trace_lines = list(line for line in trace_lines if line)
       dump_file=file.replace('.stateless_mem_trace','.stateless_mem_trace.classified')

       with open(dump_file,"w") as output:
        for text in trace_lines:
         m1=symbol_re.match(text)
         m2=symbol2_re.match(text)
         if(m1):
          age_cache_contents()
          output.write(text+"\n")
         elif(m2):
          output.write(text+"\n")
         else:
          addr=int(text,16)
          block_no=addr/cache_block_size
          set_no=block_no % num_sets
 	  if block_no in cache_contents[set_no]:
	   index=cache_contents[set_no].index(block_no)
           if cache_ages[set_no][index] < set_associativity:
            output.write("Hit\n")
           else:
            output.write("Miss\n")
          else:
           output.write("Cold Miss\n")
           cache_contents[set_no].append(block_no)
 	   cache_ages[set_no].append(None)
          update_ages(block_no,set_no)
         
   
def age_cache_contents():
 global cache_contents
 global cache_ages
 for x in xrange(len(cache_ages)):
  for y in xrange(len(cache_ages[x])):
   cache_ages[x][y]=set_associativity+1 # Clear cache
   #cache_ages[x][y] = cache_ages[x][y] # Don't clear cache.

def update_ages(block_num,set_num):
 global cache_contents
 global cache_ages
 index=cache_contents[set_num].index(block_num)
 age=cache_ages[set_num][index]
 for x in xrange(len(cache_ages[set_num])):
  if(x==index):
   cache_ages[set_num][x] = 0
  elif(not(x==index) and cache_ages[set_num][x]<=age):
   cache_ages[set_num][x] += 1 
  
main()
