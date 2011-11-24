#!/bin/bash

ifconfig | grep -o -m1 'inet addr:[^ ]*';
echo "Cpu: " && cat /proc/cpuinfo | grep "model name";
echo "Network: " && lspci | grep Ethernet;
ips=(172.31.10.37 172.31.10.39 172.31.10.40 172.31.10.41 172.31.1.1 172.30.1.1)
pckgcnt=10000
names[0]="One Pckg";
names[1]="Two Pckg";
names[2]="Two Pckg MTU*2";

cmds[0]="ping -s 1472 -i 0.001 -q -c $pckgcnt";
cmds[1]="ping -s 1473 -i 0.001 -q -c $pckgcnt";
cmds[2]="ping -s 2972 -i 0.001 -q -c $pckgcnt";

for((i=0;i<${#cmds[@]};i++))
do
  echo "";
  echo "${names[$i]}";
  echo "";
  for ip in ${ips[@]}
  do
    echo -n -e "$ip \t" && ${cmds[$i]} $ip | tail -n 1;
  done
done

<<TEST
echo "One Package";
echo "";

for ip in ${ips[@]}
do
  echo -n "$ip " && ping $ip -s 1472 -i 0.001 -c $pckgcnt -q | tail -n 1;
done


echo "";
echo "Two Packages";
echo "";

for ip in ${ips[@]}
do
  echo -n "$ip " && ping $ip -s 1473  -i 0.001 -c $pckgcnt -q | tail -n 1;
done
TEST


