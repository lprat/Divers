#!/usr/bin/perl
#use: grep -iE "^alert" /etc/snort/rules/*.rules | grep -vi "osvbd" | grep -iE "cve|bugtraq" | ./snort-osvWxml.pl >  snort_osvdbWxml.sql
#add to ossim base corelation mysql -p ossim < snort_osvdbWxml.sql
if(!$ARGV[0])
{
  print "Example usage:  grep -iE \"^alert\" /etc/snort/rules/*.rules | grep -vi \"osvbd\" | grep -iE \"cve|bugtraq\" | $0 osvdb.xml > snort_osvdbWxml.sql\n";
  exit();
}
open(FILE,"<$ARGV[0]") or die "Can't open $ARGV[0]";

print STDERR "Create liste parse snort rules...wait...\n";
@srules = ();
@scve = ();
@sbug = ();
$i=0;
$j=0;
$n=0;
while($line = <STDIN>)
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
#print "INSERT INTO plugin_reference (plugin_id, plugin_sid, reference_id, reference_sid) VALUES (1001, $snort_sid, 5003, $osvdb_id);\n";
print STDERR "Number of occurrences found: $i  ->  Number of occurrences written: $j\n";
print STDERR "Analyz XML  osvdb and create sql file...wait...\n";
$fin=$#srules;
while($line = <FILE>)
{
  if($line =~ /vuln osvdb_id="(\d+)"/)
  {
     $osvdb_id = $1;
      while($temp  = <FILE>)
      {
        if($temp =~ /Bugtraq\sID"\>(\d+)\</){
           $bugtraq_id = $1;
            $i=0;
            $trouve=0;
            $ok=0;
            while($trouve==0){
              if($bugtraq_id eq $sbug[$i]){
                $trouve=1;
                print "INSERT INTO plugin_reference (plugin_id, plugin_sid, reference_id, reference_sid) VALUES (1001, $srules[$i], 5003, $osvdb_id);\n";
                $ok=1;
              } else {
                if ($i<$fin){
                        $i++;
                } else {
                        $trouve=1;
                }
              }
            }
           if($ok==1){
                $last;
           }
        }
        if($temp =~ /CVE\sID"\>(\d+)-(\d+)\</){
           $cve_id = $1."-".$2;
           $i=0;
            $trouve=0;
            $ok=0;
            while($trouve==0){
              if($cve_id eq $scve[$i]){
                $trouve=1;
                print "INSERT INTO plugin_reference (plugin_id, plugin_sid, reference_id, reference_sid) VALUES (1001, $srules[$i], 5003, $osvdb_id);\n";
                $ok=1;
              } else {
                if ($i<$fin){
                        $i++;
                } else {
                        $trouve=1;
                }
              }
            }
           if($ok==1){
                $last;
           }
        }
        if($temp =~ /\<\/vuln\>/){
           last;
        }
      }
  }
}
close (FILE);
