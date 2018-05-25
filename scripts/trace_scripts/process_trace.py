#!/usr/bin/env python

import re
import sys
import subprocess
import string
import os

trace_file = sys.argv[1]
dump_file=trace_file.replace('.instructions','.packet_relevant_instructions')

def main():
   with open(trace_file) as infile:
    with open(dump_file,"w") as output:
     for line in infile:
      text = line.rstrip()
      packet_code = 0
      start = 0
      end = -1
      index1 = find_nth(text,"|",1)
      index2 = find_nth(text,"|",2)
      fn_call_stack = text[index1+1:index2-1]
      words = fn_call_stack.split()
      temp_start = 0
      temp_end = 0
      for fn in words:
 	if(fn == "rte_eth_rx_burst"):
          temp_start = 1
          continue
       
        if(fn == "rte_eth_tx_burst"):
          temp_end = 1
	  continue
 
	if(fn == "exit@plt"):
	  end =1
          break
        
      if(start == 0 and temp_start == 1):
	 start = 1
	
      if(end == -1 and temp_end == 1):
	 end = 0
	
      if(end == 0 and temp_end == 0):
	 end = 1

      if(start>end and start >0):
         output.write(text)
         output.write("\n")
      elif (start<=end):
	 break



def find_nth(haystack, needle, n):
 start = haystack.find(needle)
 while start >= 0 and n > 1:
  start = haystack.find(needle, start+len(needle))
  n -= 1
 return start


main()
