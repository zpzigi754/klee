#!/bin/bash
inp=$1
op=$2

if [ "$inp" -nt "$op" ]; then
  echo "$inp -> $op"

  if grep -q "rte_eth_rx_burst" $1; then  
  START=$(grep -n -m 1 "rte_eth_rx_burst" $1 |sed  's/\([0-9]*\).*/\1/')

  if grep -q "rte_eth_tx_burst"  $1; then 
    END=$(grep -n "rte_eth_tx_burst" $1 | tail -1 |sed  's/\([0-9]*\).*/\1/')
  else
    END=$(grep -n "exit@plt" $1 | tail -1 |sed  's/\([0-9]*\).*/\1/')
  fi
  ENDEND=$((END+1))
  sed -n ""$START","$END"p;"$ENDEND"q" $1 > $2

  else
    echo " ">$2
  fi
fi
