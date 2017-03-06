
#!/bin/sh
#############################
# Auteurs  : Gangstuck      #
#            Lionel         #
#---------------------------#
#  - Diverses Fonctions -   #
#############################

FILE = $1
ANALYSE = "log_seg"

COUNT=`/bin/wc -l`

############################################################################

function infosys()
{
        echo "- Affichage des informations systeme"
        echo "================================================="
        echo " + Type de machine  : `uname -m`"
        echo " + Type de système  : `uname -s`"
        echo " + Nom d'hôte       : `uname -n`"
        echo " + Version          : `uname -r`"
        echo "================================================="
}

############################################################################

function cherche_fault()
{
        echo "- Recherche de Segfault"
        echo "================================================="
        if [ -r $FILE ]; then
           echo "Traitement de $FILE : `$COUNT $FILE` lignes..."
           /bin/cat $FILE | /bin/grep "^SEG" > log_seg
           echo "Nous avons trouvé `$COUNT log_seg` messages dans $FILE"
           echo "-------------------------------------"
           /bin/cat log_seg
           echo "-------------------------------------"
           /bin/rm log_seg
        else
           echo "$FILE n'exite pas !"
        fi
        echo "================================================="
}
