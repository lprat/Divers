#!/usr/bin/perl
use POSIX qw(strftime);
#$ret=`/bin/rm -f /tmp/malware-spye /tmp/tmp-malware`;
#$ret=`/usr/bin/wget http://mirror.malwaredomains.com/files/domains.txt -O /tmp/tmp-malware`;
$ret=`/bin/grep -v "#" /tmp/tmp-malware | /usr/bin/awk '{print \$1}' > /tmp/malwaredomains.bl`;
#$ret=`/usr/bin/wget --no-check-certificate https://spyeyetracker.abuse.ch/blocklist.php?download=domainblocklist -O /tmp/malware-spye`;
sleep(10);
@doma = ();
print "Analyse des bases malware\n";
open (FILE, '/tmp/malwaredomains.bl') or die "cannot open < input.txt: $!";
while ($line = <FILE>) {
        chomp;
        $line =~ s/[ \t\n]+//g;
        if (!($line =~ "//") && !($line eq "")) {
                push (@doma, $line);
         }
}
close (FILE);
print "Fin analyse 1er fichier\n";
open (FILE, '/tmp/malware-spye') or die "cannot open < input.txt: $!";
while ($line = <FILE>) {
        chomp;
        $line =~ s/[ \t\n]+//g;
        if (!($line =~ "#") && !($line eq "")) {
                push (@doma, $line);
         }
}
close (FILE);
print "Fin analyse 2eme fichier\n";
open (FILE, '/etc/blacklist-bh-dns.local') or die "cannot open < input.txt: $!";
while ($line = <FILE>) {
        chomp;
        $line =~ s/[ \t\n]+//g;
        if (!($line =~ "#") && !($line eq "")) {
                push (@doma, $line);
         }
}
close (FILE);
print "Fin analyse 3eme fichier\n";
$fin=$#doma;
print "Demarrage de l'analyse des logs\n";
while ($line = <STDIN>){
    chomp;
# print "$line";
 ($ip,$domain) = split(" ",$line);
 $ip =~ s/[ \t\n]+//g;
 $domain =~ s/[ \t\n]+//g;
# print "DEBUG: $domain - $ip\n";
# print "$ip $domain\n";
 $i=0;
 $trouve=0;
 while($trouve==0){
        if($domain =~ $doma[$i]){
                $trouve=1;
                print STDERR strftime("%a %b %d %Y %H:%M:%S %z", localtime(time()))." Trouve $ip query $domain   MALWARE:$doma[$i] !!!!\n";
        } else {
                if ($i<$fin){
                        $i++;
                } else {
                        $trouve=1;
                }
        }
 }
}
