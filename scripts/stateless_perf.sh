#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

py_scripts_dir=$SCRIPT_DIR/trace_scripts
traces_dr=${1:-klee-last} #traces_dir needs to contain files with the name *.packet_relevant_instructions 
output=${2:-stateless-perf.txt}


cd $traces_dr

parallel "$py_scripts_dir/process_trace.sh {} \$(basename {} .instructions).packet_relevant_instructions" ::: *.instructions

python $py_scripts_dir/demarcate_trace.py ./ $py_scripts_dir/fn_lists/stateful_fns.txt $py_scripts_dir/fn_lists/dpdk_fns.txt $py_scripts_dir/fn_lists/time_fns.txt $py_scripts_dir/fn_lists/verif_fns.txt 
python $py_scripts_dir/print_addresses.py ./
python $py_scripts_dir/formal_cache.py ./
python $py_scripts_dir/stateless_stats.py ./ comp_insns num_accesses num_hits num_misses trace_nos
python $py_scripts_dir/stateless_perf.py  comp_insns num_accesses num_hits trace_nos $output 

rm -f $traces_dr/*.packet.stateless_mem_trace \
      $traces_dr/*.packet.stateless_mem_trace.classified
