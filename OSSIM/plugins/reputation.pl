#!/usr/bin/perl
# load LWP library:
use LWP::UserAgent;
use HTML::Parse;
$num_args = $#ARGV + 1;
if ($num_args != 1) {
  print "\nUsage: reputation.pl IP ou domaine\n";
  exit;
}
#si vous voulez éviter une faille de sécurité, rajoutez un filtrage de l'entrer en limitant :
# [A-Za-z0-9\.\-]
#URL
my $url = "http://amada.abuse.ch/?search=$ARGV[0]";
my $url2 = "http://www.threatexpert.com/reports.aspx?find=$ARGV[0]";
my $ua = new LWP::UserAgent;
# $ua->agent('Mozilla/5.5 (compatible; MSIE 5.5; Windows NT 5.1)');
# timeout:
$ua->timeout(15);
my $request = HTTP::Request->new('GET');
$request->url($url);
my $response = $ua->request($request);
my $code = $response->code;
my $headers = $response->headers_as_string;
my $body =  $response->content;
#print $body;
my $pays=0;
my $abuse=0;
if ($body =~ /results/i){
        $abuse=1;
}
# threatexpert
my $request2 = HTTP::Request->new('GET');
$request2->url($url2);
my $response2 = $ua->request($request2);
my $body2 =  $response2->content;
if ($body2 =~ /There were no ThreatExpert reports/i){
        #no
}else{
        $abuse=1;
}
my $cmd_test2=`/bin/grep -iE "^$ARGV[0]#" /etc/ossim/server/reputation.data`; 
if ($cmd_test2 =~ /,/){
        $abuse=1;
}
my $cmd_test=`/usr/bin/jwhois $ARGV[0] | /bin/grep -iE "Country\:[\t\ ]+\Ru|Country\:[\t\ ]+\Cn"`;
if ($cmd_test =~ /Country/i){
        $pays=1;
}
if($pays==1 && $abuse==1){
        print "Result: 1";
}
if($pays==0 && $abuse==1){
        print "Result: 3";
}
if($pays==1 && $abuse==0){
        print "Result: 4";
}
if($pays==0 && $abuse==0){
        print "Result: 0";
}
