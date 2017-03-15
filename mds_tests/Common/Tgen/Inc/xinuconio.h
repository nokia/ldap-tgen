/******************************************************************************
* Copyright (C) janvier 2001 Biblothèque de fonctions mettant en oeuvre les   *
* bases de données terminfo : xinuconio.h                                     *
*                                                                             *
* Auteur : Alain Riffart, ariffart@club-internet.fr                           *
*                                                                             *
* Ce programme est libre, vous pouvez le redistribuer et/ou le modifier selon *
* les termes de la Licence Publique Générale GNU publiée par la Free Software *
* Foundation (version 2 ou bien toute autre version ultérieure choisie par    *
* vous).                                                                      *
*                                                                             *
* Ce programme est distribué car potentiellement utile, mais SANS AUCUNE      *
* GARANTIE, ni explicite ni implicite, y compris les garanties de             *
* commercialisation ou d'adaptation dans un but spécifique. Reportez-vous à   *
* la Licence Publique Générale GNU pour plus de détails.                      *
*                                                                             *
* Vous devez avoir reçu une copie de la Licence Publique Générale GNU en même *
* temps que ce programme ; si ce n'est pas le cas, écrivez à la Free Software *
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307,        *
* États-Unis.                                                                 *
******************************************************************************/

#include <ncurses.h>

/* Par défaut les données de la base terminfo sont cherchées dans un fichier
   pour un terminal linux. Les modifications sont simples à apporter si vous
   voulez vous référer à la base de données d'un autre terminal *************/

# define termi setupterm("linux",fileno(stdin),NULL)


/*********** Directives de compilation utiles à la fonction clrscr ***********/

# define efecran tigetstr("clear")

/*********** Directives de compilation utiles à la fonction clreol ***********/

# define efli tigetstr("el")

/*********** Directives de compilation utiles à la fonction delline **********/

# define delli tigetstr("dl1")

/*********** Directives de compilation utiles à la fonction insline **********/

# define insli tigetstr("il1")

/*********** Directives de compilation utiles à la fonction highvideo ********/

# define hivi tigetstr("bold")

/*********** Directives de compilation utiles à la fonction lowvideo ********/ 

# define lovi tigetstr("dim")

/***** Directives de compilation utiles à la fonction clreol normalvideo *****/

# define novi tigetstr("sgr0")

/******* Directives de compilation utiles à la fonction _setcursortype *******/

/* Trois directives pour produire trois séquences d'échappement qui  permettent
   de gérer l'apparence du curseur :
   efcur -> curseur invisible
   gdcur -> curseur pavé
   curseur -> curseur un trait ***********************************************/

# define efcur tigetstr("civis")   
# define gdcur tigetstr("cvvis")
# define curseur tigetstr("cnorm")

/* Trois constantes qui serviront de paramètres à la fonction _setcursortype */

# define _NOCURSOR 0      // Curseur invisible
# define _NORMALCURSOR 1  // Curseur en surbrillance ou pavé szlon systèmes
# define _SOLIDCURSOR 2   // Curseur normal réduit à un trait

/********** Directives de compilation utiles à la fonction gotoxy ************/

# define posxy tigetstr("cup")

/********* Directives de compilation utiles à la fonction textcolor **********/

# define coult tigetstr("setaf")

/********** Directives de compilation utiles à la fonction gotoxy ************/

# define coulf tigetstr("setab")

/***** Les identificateurs de couleurs valables pour le fond et la forme *****/

# define noir 0
# define rouge 1
# define vert 2
# define jaune 3
# define bleu 4
# define magenta 5
# define cyan 6
# define blanc 7



/********** Directives de compilation utiles à la fonction textattr **********/

/* Les neufs paramètres nécessaires à la fonction textattr
  - surbri pour surbrillance
  - ssli pour soulignement
  - invi pour inversion vidéo
  - cligno pour clignotement
  - bint pour basse intensité
  - gras pour affichage en caratères gras
  - invis pour affichage invisible
  - prote pour affichage protégé
  - altcar pour activation désactivation de la touche alternate 
  - defmod pour la réinitialisation des modes d'affichage par défaut *********/

# define surbri 256
# define ssli 128
# define invi 64
# define cligno 32
# define bint 16
# define gras 8
# define invis 4
# define prote 2
# define altcar 1
# define defmode 0

/***************  Récupération de la  valeur de la capacité sgr **************/

# define modaf tigetstr("sgr")

/******************************** Les prototypes *****************************/

void clrscr (void);
void clreol (void);
void delline (void);
void insline (void);
void highvideo (void);
void lowvideo (void);
void normalvideo (void);
void _setcursortype (int _type);
void gotoxy (int x, int y);
void textcolor (int _color);
void textbackground (int _color);
void textattr (int _mode);
int _lignes(void);
int _colonnes();
