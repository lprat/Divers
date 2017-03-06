#/bin/sh
# Scan Spoofing By Lionel PRAT aka Anti-Social

echo "Scan spoofing by Lionel PRAT aka Anti-Social"
echo "Proof Of Concept"
echo "cronos56@yahoo.com"

if [ $# -le 4 ]
then
                echo "Usage: $0 (ip_src) (ip_dst) (interface[ETH0/PPP0]) (port_depart) (port_fin) [nbr_syn=25] [diff_id=10] [port_src=1027] [time=0] [winid=256(or [nowid])] [-f (pushflag)]"
	echo "Ex: $0 www.fbi.com www.police.com eth0 21 25"
	echo "Pour l'ip source verifier que l'ip accept l'imp & qui n'est pas trop de connection."
	exit 0
else
	if [ $# -gt 6 ]
	then
		probe=$6
	else
		probe=25
	fi
	if [ $# -gt 7 ]
	then
		diff=$7
	else
		diff=10
	fi
                if [ $# -gt 8 ]
	then
		psrc=$8
	else
		psrc=1027
	fi
	if [ $# -gt 9 ]
	then
		time=$9
	else
		time=0
	fi
	if [ $# -gt 10 ]
	then
		wid=$10
	else
		wid=0
	fi
	if [ $# -gt 11 ]
	then
		flag=$11
	else
		flag=""
	fi
	port=$4
	while [ "$port" -le "$5" ]
	do
                (./sspoof -s $1 -h $2 -p $port -i $3 -d $diff -m $probe $flag -l $psrc -t $time )
                 if [ $wid = nowid ]
                 then
                         (./sspoof -s $1 -h $2 -p $port -i $3 -d $diff -m $probe $flag -l $psrc -t $time)
                 else
                        if [ -z $wid ]
                        then
                                (./sspoof -s $1 -h $2 -p $port -i $3 -d $diff -m $probe -W $wid $flag -l $psrc -t $time)
                         fi
                  fi
	((port=$port+1))
	done
fi
echo "ByeBye!"
exit 0