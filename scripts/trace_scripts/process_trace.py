#!/usr/bin/env python

import re
import sys
import subprocess
import string
import os

trace_path = sys.argv[1]

def main():
 i=1
 for root, dirs, files in os.walk(trace_path):
  for file in files:
   with open(file) as f:
    if file.endswith(".instructions"):
     trace_lines = (line.rstrip() for line in f)
     trace_lines = list(line for line in trace_lines if line)
     dump_file=file.replace('.instructions','.packet_relevant_instructions')
     packet_code = 0
     with open(dump_file,"w") as output:
      for text in trace_lines:
       index1 = find_nth(text,"|",2)
       index2 = find_nth(text,"|",3)
       fn = text[index1+1:index2].strip()
       if(packet_code == 0):
        if(fn == "rte_eth_rx_burst"):
         packet_code = 1
       
       if(packet_code == 1):
        if(fn == "exit@plt"):
         packet_code = 2
  
       if(packet_code == 1):
        output.write(text)
        output.write("\n")
        



def find_nth(haystack, needle, n):
 start = haystack.find(needle)
 while start >= 0 and n > 1:
  start = haystack.find(needle, start+len(needle))
  n -= 1
 return start


main()
