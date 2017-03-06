#!/usr/bin/perl
#Lionel PRAT script inverse resolve for pintrace modified in BAP 0.6
##
#Il s'agit d'un script qui permet de résoudre en inverse le chemin pris par l’exécution d'un programme, sur une condition basé sur un test en caractère simple ASCII . Il utilise les outils de BAP & STP. Si vous connaissez FuzzGrind de Gabriel Campana, il s'agit d'un outil très proche, avec des possibilités avancées. Fuzzgrind ne permet que d'obtenir un fuzz sur des données “taint” issue de fichier. Alors que l'outil pintrace permet le trace de tous types de données “taint”. Le script utilise pintrace modifié pour obtenir les “mixed Taint”, il s'agit de données “castées” par exemple par des fonctions atoi() ou des données modifiées par exemple strlen()… Car si on essai de résoudre une condition sur des données “castées” ou modifiées avec STP, cela n'est pas possible. Il faut donc essayer de suivre les données taint, afin de comprendre les modifications apportés pour arriver a créer un arbre pouvant contenir tous les chemins possibles de l’exécution par les caractéristiques des données dynamiques. 
##
use strict;
use Getopt::Std;
our ($opt_s, $opt_e, $opt_g, $opt_n, $opt_f, $opt_p, $opt_a, $opt_c);
my $opt_string = 'gsne:f:p:a:c:';
getopts( "$opt_string");# or die "Usage: fuzz.pl (-g/-s/-f [file]/-n/-e [varenv]/-c [number]) -p prog_scan -a argument_prog_start\n -g is args taint\n -s is stdin taint\n -n is network taint\n -f [file] is file taint and add file path\n -e taint environement var\n -c Call thread to wath [-1 for all|default 3]\n";
my $pgr="";
my $option="";
my $argp="";
if ($opt_p)  
{
  print "-p $opt_p\n\n";
  $pgr="$opt_p";
} else {
  print "Usage: fuzz.pl (-g/-s/-f [file]/-n/-e [varenv]/-a/-c [number]) -p prog_scan [-a argument_prog_start]\n -g is args taint\n -s is stdin taint\n -n is network taint\n -f [file] is file taint and add file path\n -e taint environement var\n -c Call thread to wath [-1 for all|default 3]\n";
  exit;
}

if ($opt_a)
{
  $argp="$opt_a";
}

if ($opt_s)
{
  print "Stdin Taint search...\n";
  $option=$option."-taint_stdin";
}

if ($opt_g)
{
  print "Args Taint search...\n";
  $option=$option." -taint_args"; 
}

if( $opt_f )
{
  print "Files Taint search...\n";
  $option=$option." -taint_files $opt_f";
}

if( $opt_n ) 
{
  print "Network stream Taint search...\n";
  $option=$option." -taint_net";
}

if( $opt_e )
{
  print "Network stream Taint search...\n";
  $option=$option." -taint_env $opt_e";
}

if( $opt_c )
{
  print "Call information 3...\n";
  $option=$option." -watch_thread $opt_c";
}else {
	$option=$option." -watch_thread 3";
}

my $i=1;
my $z=1;
my $stop=1;
print "$pgr run trace $i Taint...\n";
my $null=`rm -f *-trace.bpt`;
print "Run: ../pin/pin -t ./obj-ia32/gentrace.so -o trace.bpt $option -- $pgr $argp 2>/tmp/trace.log\n";
my $result1=`../pin/pin -t ./obj-ia32/gentrace.so -o trace.bpt $option -- $pgr $argp 2>/tmp/trace.log`;
my $taintmixt=`/bin/grep "Tainted memory:" /tmp/trace.log|/bin/grep "tagged ffffffff"`;
if($taintmixt=~/Tainted memory/){
	print "TAINT MIXTE DETECTED!!!!!!\n";
	if($taintmixt=~/cmp/){
		print "Detected on CMP asm instruction...\n";
	}
	my $taintmem=`tac /tmp/trace.log |sed '/Tainted Mem/,\$d' | /bin/grep "Addr:"`;
        print "Memory Tainted Stat:\n";
	print $taintmem;
}else{
	print "No Tainted Mixte Detected!!!!\n";
}
print "Ok.\n";
print "Create trace AST...";
my $result2=`../utils/iltrans -serializedtrace *-trace.bpt -trace-concrete -uniqueify-labels -pp-ast trace.il`;
print "Ok.\nFind Condition R_ZF (taint)...\n";
my $resultgrep="";
while($stop){
$resultgrep=`grep -iEn "assert [\~\(]+R_" trace.il|/bin/sed -n '\$p'`;
#foreach my $n (@resultgrep) {
#    $finn=$n;
#}
if($resultgrep =~ /assert/){
my ($nline)=split(':',$resultgrep);
my $asserd=$resultgrep;
$asserd =~ s/^$nline\://;

print "Resultat R_ZF: line: $nline, type: $asserd\n";
$null=`sed -i '$nline,\$d' trace.il`; 
my $occur=0;
my $occurR=0;
my @occurrence_caract = $asserd =~ /(R_)/g;
$occurR = scalar(@occurrence_caract);
print "OccurR == $occurR\n";
if($occurR > 1){
   my $occurP=0;
   my @occurrence_caract = $asserd =~ /(\()/g;
   $occurP = scalar(@occurrence_caract);
   print "occur P=$occurP\n";
   if($occurP == 0){
	$asserd =~ s/assert[\s]+/$1assert \~\(/;
	$asserd =~ s/$/$1\)/;
        print "Change: $asserd\n";
	$null=`echo "$asserd" >> trace.il`;
   }
   elsif($occurP == 1){
	$asserd =~ s/assert[\s]+/$1assert \~/;
        print "Change: $asserd\n";
	$null=`echo "$asserd" >> trace.il`;
   }
   else{
	#probleme
	print("Solve error, trop de paranthese sur contrainte...\n");
	exit;
   } 
}
else {
	my @occurrence_caract = $asserd =~ /(~)/g;
	$occur = scalar(@occurrence_caract);
	print "nbr ~ = $occur\n";
	if($occur % 2){
        $asserd =~ s/\~//g;
	print "Change $asserd\n";
	$null=`echo "$asserd" >> trace.il`;
	} else {
        $asserd =~ s/\~//g;
	$asserd =~ s/R_/\~R_/;
	print "Change $asserd\n"; 
	$null=`echo "$asserd" >> trace.il`;
	}
}
my $solve=`../utils/topredicate -q -il trace.il -stp-out f -solve 2>&1 |/bin/sed -n '\$p'`;
if($solve =~ /Valid/){
	# No result, cmp -1
	# suppr nline
	$null=`sed -i '$nline,\$d' trace.il`; 
	#reloop
} else {
	#result Ok
	my $stp=`stp -p f`;
	print "Solution:\n $stp \n\n";
	$stop=0;
}
} else{
	print ("No solve possible... Sorry!\n");
	$stop=0;
}
}
