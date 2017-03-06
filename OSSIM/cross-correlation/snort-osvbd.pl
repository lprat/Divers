#!/usr/bin/perl
#use: grep -iE "^alert" /etc/snort/rules/*.rules | grep -i "osv" | ./snort-osv.pl >  snort_osvdb.sql
#add to ossim base corelation mysql -p ossim < snort_osvdb.sql
print STDERR "Create file sql snort<->osvbd...wait...\n";
$i=0;
$j=0;
$n=0;
while($line = <STDIN>)
{
        $i++;
        $n=0;
        if ($line =~ /osvdb.org\/(\d+)\;/ || $line =~ /osvdb\/(\d+)\;/)
        {
                $osvdb_id = $1;
                if ($line =~ /sid\:\s?(\d+)\;/)
                {
                  $snort_sid = $1;
                  print "INSERT INTO plugin_reference (plugin_id, plugin_sid, reference_id, reference_sid) VALUES (1001, $snort_sid, 5003, $osvdb_id);\n";
                        $j++;
                        $n=1;
                }
        }
        if($n == 0){
                print STDERR "ERROR PARSING:  $line";
        }

}
print STDERR "Number of occurrences found: $i  ->  Number of occurrences written: $j\n";
