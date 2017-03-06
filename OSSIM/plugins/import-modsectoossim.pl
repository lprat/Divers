#!/usr/bin/perl
#import-modsectoossim.pl
@filex = ();
@idx = ();
@prio = ();

$ret=`grep -iRE "[^#]*SecRule.*,id\:" /etc/apache2/mod_sec/activated_rules/ |awk -F "id:\'" '{print $2}' |awk -F "\'" '{print $1}' > /tmp/analiz2`;
$ret=`grep -iRE "[^#]*SecRule.*,id\:" /etc/apache2/mod_sec/activated_rules/ |awk -F "id:\'" '{print $1}' |awk -F ":" '{print $1}' |awk -F "\/" '{print $NF}' | sed -e s/modsecurit
y_crs_[0-9]*_//g |sed s/.conf//g > /tmp/analiz1`;
open(FILE3,"/etc/ossim.modsec") or die "/etc/ossim.modsec";
open(FILE,"/tmp/analiz1") or die "/tmp/analiz1";
open(FILE2,"/tmp/analiz2") or die "/tmp/analiz2";
while($line = <FILE>)
{
   $line =~ s/[\t\n]//g;
   push (@filex, $line);
}
while($line = <FILE2>)
{
  $line =~ s/[^0-9]+//g;
  push (@idx, $line);
}
close(FILE2);
close(FILE);
while($line = <FILE3>)
{
  $line =~ s/[\t\n]//g;
  push (@prio, $line);
}
close(FILE3);
print STDOUT "-- apache modsecurity\n";
print STDOUT "-- plugin_id: 1561\n";
print STDOUT "--\n";
print STDOUT "-- $Id: modsecurity.sql, auto create script Lionel PRAT Exp $\n";
print STDOUT "--\n";
print STDOUT "\n";
print STDOUT "DELETE FROM plugin_sid where plugin_id = \"1561\";\n";
print STDOUT "DELETE FROM plugin WHERE id = \"1561\";\n";
print STDOUT "\n";
print STDOUT "INSERT INTO plugin (id, type, name, description) VALUES (1561, 1, 'modsecurity', 'ModSecurity');\n";
#print STDOUT "\n";
for ($i=0;$i<=$#idx;$i++) {
        for ($j=0;$j<=$#prio;$j++) {
                ($l,$p,$r) = split(",",$prio[$j]);
                if($filex[$i] eq $l){
                        print STDOUT "INSERT INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (1561, $idx[$i], NULL, NULL, \'$filex[$i]\
' ,$p ,$r);\n";
                }
        }
}
