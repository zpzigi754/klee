import sys
import re
import string
import os

trace_path = sys.argv[1]

def main():
 for root, dirs, files in os.walk(trace_path):
  for file in files:
   with open(file) as f:
    if file.endswith(".demarcated"):
     trace_lines = (line.rstrip() for line in f)
     trace_lines = list(line for line in trace_lines if line)
     dump_file=file.replace('.demarcated','.stateless_mem_trace')
     
     with open(dump_file,"w") as output:
      irrelevant=0
      for text in trace_lines:
       if(text.startswith("Call")):
        output.write("Irrelevant to Trace\n")
       else:
        index = find_nth(text,"|",4)
        text = text[index+1:]
        if(text == ""):
         output.write("Non-memory instruction\n")
        words = text.split() 
        i=0
        while i < len(words):
         words[i]=words[i][1:]
         output.write(words[i])
  	 output.write("\n")
         i+=1
       


def find_nth(haystack, needle, n):
 start = haystack.find(needle)
 while start >= 0 and n > 1:
  start = haystack.find(needle, start+len(needle))
  n -= 1
 return start

main()

