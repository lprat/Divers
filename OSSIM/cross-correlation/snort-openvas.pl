#!/usr/bin/perl
#verify path of command and path of snort rules
#use: ./snort-nessus.pl >  snort_nessus_tmp.sql
#cat snort_nessus_tmp.sql | sort | uniq > snort_nessus.sql
#ossimdb | cat snort_nessus.sql
$wget="/usr/bin/wget";
$bzip2="/bin/bzip2";
$mkdir="/bin/mkdir";
$tar="/bin/tar";
$rm="/bin/rm";
$sed="/bin/sed";
$grep="/bin/grep";
print STDERR "Download openvas-nvt-feed-current.tar.bz2\n";
$exec="$mkdir /tmp/openvas-tmp/";
$cmd=`$exec`;
$exec="$wget http://www.openvas.org/openvas-nvt-feed-current.tar.bz2 -O /tmp/openvas-tmp/openvas-nvt-feed-current.tar.bz2";
$cmd=`$exec`;
print STDERR "Uncompress openvas-nvt-feed-current.tar.bz2\n";
$exec="$bzip2 -d /tmp/openvas-tmp/openvas-nvt-feed-current.tar.bz2";
$cmd=`$exec`;
$exec="$tar -xf /tmp/openvas-tmp/openvas-nvt-feed-current.tar -C /tmp/openvas-tmp/";
$cmd=`$exec`;
print STDERR "Create file SID nessus to analyz\n";
$exec=`$grep -iE "script_id|script_bugtraq_id|script_cve_id" /tmp/openvas-tmp/*.nasl | $sed -e 's/\"//g' | $sed -e 's/\\\s//g' | $sed -e 's/,CVE\-/\\\nscript_cve_id\(/g' | $sed -e
 's/CVE\-//g' | $sed -e 's/\,/\\\nscript_bugtraq_id\(/g' > /tmp/openvas-tmp/analyz.lio`;
open(FILE,"</tmp/openvas-tmp/analyz.lio") or die "Can't open /tmp/openvas-tmp/analyz.lio";

print STDERR "Create liste parse snort rules...wait...\n";
$exec=`$grep -iE "^alert" /etc/snort/rules/*.rules | $grep -iE "cve|bugtraq" > /tmp/openvas-tmp/analyz.lio2`;
open(FILE2,"</tmp/openvas-tmp/analyz.lio2") or die "Can't open /tmp/openvas-tmp/analyz.lio2";
@srules = ();
@scve = ();
@sbug = ();
$i=0;
$j=0;
$n=0;
while($line = <FILE2>)
{

$bug = 0;
$cve = 0;
$bugtraq = "NULL";
$rcve = "NULL";
        $i++;
        $n=0;
        if ($line =~ /sid\:\s?(\d+)\s?\;/)
        {
            $snort_sid = $1;
            if ($line =~ /bugtraq\s?,\s?(\d+)\s?\;/)
            {
                $bugtraq = $1;
                $bug = 1;
            }
  
            if ($line =~ /cve\s?,\s?(\d+)-(\d+)\s?\;/ || $line =~ /cve\s?,\s?CVE\-(\d+)-(\d+)\s?\;/ )
            {
                $rcve = $1."-".$2;
                $cve = 1;
            }
                  if($cve == 1 || $bug == 1) {
                    push (@srules, $snort_sid);
                    push (@scve, $rcve);
                    push (@sbug, $bugtraq);
                     $j++; $n=1;
#                    print STDERR "DEBUG INFO: snort:$snort_sid -> bugtraq:$bugtraq & cve:$rcve\n";
                  }
                       
        }
        if($n == 0){
#                print STDERR "DEBUG PARSING:  $line";
        }

}
close (FILE2);
print STDERR "Number of occurrences found: $i  ->  Number of occurrences written: $j\n";
print STDERR "Analyz nessus file and create sql file...wait...\n";
$fin=$#srules;
$nessus_id="";
while($line = <FILE>)
{
  if($line =~ /script_id\((\d+)\)\;/)
  {
     $nessus_id = $1;
  }
  if($line =~ /script_bugtraq_id\((\d+)/ ){
           $bugtraq_id = $1;
            $i=0;
            $trouve=0;
            while($trouve==0){
              if($bugtraq_id eq $sbug[$i]){
                $trouve=1;
                print "INSERT INTO plugin_reference (plugin_id, plugin_sid, reference_id, reference_sid) VALUES (1001, $srules[$i], 3001, $nessus_id);\n";
              } else {
                if ($i<$fin){
                        $i++;
                } else {
                        $trouve=1;
                }
              }
            }
   }
   if($line =~ /script_cve_id\((\d+)-(\d+)/ ){
           $cve_id = $1."-".$2;
           $i=0;
            $trouve=0;
            while($trouve==0){
              if($cve_id eq $scve[$i]){
                $trouve=1;
                print "INSERT INTO plugin_reference (plugin_id, plugin_sid, reference_id, reference_sid) VALUES (1001, $srules[$i], 3001, $nessus_id);\n";
              } else {
                if ($i<$fin){
                        $i++;
                } else {
                        $trouve=1;
                }
              }
            }
    }
}
close (FILE);
print STDERR "remove /tmp/openvas-tmp file\n";
$exec="$rm -rf /tmp/openvas-tmp/";
$cmd=`$exec`;
