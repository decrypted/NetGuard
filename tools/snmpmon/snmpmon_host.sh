HOST=$1
source "./config/default"
source "./config/defaultcheck"
source "./switches/$HOST"



# Host Check
for cmd in ${hostValues[@]}
do
  val=`snmpget $etherOParm $cmdline $HOST $cmd`
  eval "$cmd=\"$val\""
  if [ $? -ne 0 ] ; then
    eval "$cmd="""""
  fi
done
for((i=0;i<${#hostValOid[@]};i++))
do
  name=${hostValName[$i]}
  val=`snmpget $etherOParm $cmdline $HOST ${hostValOid[$i]}`
  eval "$name=\"$val\""
done
hostcheck

# Ports

ifcnt=`snmpget -Oqv $cmdline $HOST ifNumber.0`
if [ $? -ne 0 ] ; then
  exit 1;
fi


for((port=1;port<=$ifcnt;port++))
do
  type=`snmpget -Oqv $cmdline $HOST ifType.$port`
  if [ $? -eq 0 ] ; then
    if [ $type == $etherType ] ; then
      for cmd in ${etherValues[@]}
      do
        val=`snmpget $etherOParm $cmdline $HOST  $cmd.$port`;
        eval "$cmd=\"$val\""
        if [ $? -ne 0 ] ; then
          eval "$cmd="""""
        fi
      done
      for((i=0;i<${#etherValOid[@]};i++))
      do
        $name=${etherValName[$i]}
        val=`snmpget $etherOParm $cmdline $HOST ${etherValOid[$i]}`
        eval "$name=\"$val\""
        if [ $? -ne 0 ] ; then
          eval "$cmd="""""
        fi
      done
      if [ $defaultcheck -eq 1 ] ; then
        defaultcheck
      fi
      portcheck
    fi
  fi
done

