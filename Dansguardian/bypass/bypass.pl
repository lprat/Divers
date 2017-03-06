#!/usr/bin/perl
use strict;
use CGI;
use Digest::MD5 qw(md5 md5_hex);
 
# Script basé sur script de Kevin Hughes & stefan.bauer
 
my $cgi = new CGI;
 
my $reason = $cgi->param('reason');
my $sip = $cgi->param('ip');
my $url = $cgi->param('deniedurl');
my $magic = 'TON-PASS-DE-BYPASS';
 

#Generating HASH for dgbypass
if (!($url =~/^.*\/\/(.*?)([\/\:].*?)$/)) {
        $url = "$url/";
}
my $unixtime = time + 300;
my $hashstring = $url . $magic . $sip . $unixtime;
my $hex_hash = md5_hex $hashstring;
my $hash = uc($hex_hash . $unixtime);

if(lc ($reason) =~ /virus or bad content detected/){
        if($reason =~ /UNOFFICIAL/){
                if ($url =~ m/\?/) {
                        my $bypass_url = $url . "&GIBYPASS=" . $hash;
                        print $cgi->redirect (-url =>$bypass_url);
                }
                else {
                        my $bypass_url = $url . "?GIBYPASS=" . $hash;
                        print $cgi->redirect (-url =>$bypass_url);
                }
        }
        else{
                print "<br><strong><font bgcolor=\"#3300ff\">Ce site contient un virus pouvant endommager votre ordinateur.</font></strong><br><br>";
        }
}
else {
        if ($url =~ m/\?/) {
                my $bypass_url = $url . "&GBYPASS=" . $hash;
                print $cgi->redirect (-url =>$bypass_url);
        }
        else {
                my $bypass_url = $url . "?GBYPASS=" . $hash;
                print $cgi->redirect (-url =>$bypass_url);
        }
}

