#Modification du plugin FromNotReplyTo.pm. Permet de régler de nombreux problèmes de phishing où la personne met un mail faux avec un reply sur son vrai mail… Attention au problème de faux positif surtout sur les serveurs de liste. 
package FromNotReplyTo;
1;

use strict;

use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;
our @ISA = qw(Mail::SpamAssassin::Plugin);


sub new {
        my ($class, $mailsa) = @_;
        $class = ref($class) || $class;
        my $self = $class->SUPER::new( $mailsa );
        bless ($self, $class);
        $self->register_eval_rule ( 'check_for_from_not_reply_to' );
        
        return $self;
}


# Often spam uses different From: and Reply-To:
# while most legitimate e-mails does not.
sub check_for_from_not_reply_to {
        my ($self, $msg) = @_;

        my $from = lc($msg->get( 'From:addr' ));
        my $replyTo = lc($msg->get( 'Reply-To:addr' ));
        #if ($replyTo eq '') {
        #       return 0;
        #}
        Mail::SpamAssassin::Plugin::dbg( "FromNotReplyTo: Comparing '$from'/'$replyTo'" );
        my ($userX, $domaineX) = split("\@",$from);
        my ($userY, $domaineY) = split("\@",$replyTo);
        #Mail::SpamAssassin::Plugin::dbg( "FromNotReplyTo: Comparing '$domaineY'/'$domaineX'" );
        #$domaineX =~ s/[\t\n ]//g;
        #$domaineY =~ s/[\t\n ]//g;
        if($replyTo ne ''){
                if ( $replyTo =~ /ton-domain\.fr/ ) {
                        return 0;
                }
                #mettre en place un fichier contenant une liste blanche...
        }
        #my $return_sys = `echo "From=$from compare replyTo=$replyTo" >> /tmp/spam-test`;
        if ( $from ne '' && $replyTo ne '' && $domaineX ne $domaineY ) {
                #Mail::SpamAssassin::Plugin::dbg( "FromNotReplyTo: return 1" );
                return 1;
        }
        #Mail::SpamAssassin::Plugin::dbg( "FromNotReplyTo: return 0" );
        return 0;
}
