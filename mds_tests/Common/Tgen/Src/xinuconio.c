/******************************************************************************
* Copyright (C) janvier 2001 Biblothèque de fonctions mettant en oeuvre les   *
* bases de données terminfo : xinuconio.c                                     *
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

#include "xinuconio.h"

void inittermi()
{
  static int oktermi=0;
  if (!oktermi)
    oktermi= !termi;
}

void clrscr(void)
{
  inittermi();
  putp(efecran);
}

void clreol(void)
{
  inittermi();
  putp(efli);
}

void delline(void)
{
  inittermi();
  putp(delli);
}

void insline(void)
{
  inittermi();
  putp(insli);
}

void highvideo (void)
{
  inittermi();
  putp(hivi);
}

void lowvideo (void)
{
  inittermi();
  putp(lovi);
}

void normalvideo (void)
{
  inittermi();
  putp(novi);
}

void _setcursortype(int _type)
{
  inittermi();
  switch(_type){
  case 0 :
    putp(efcur);
    break;
  case 2 :
    putp(gdcur);
    break;
  default :
    putp(curseur);
  }
}

void gotoxy(int x, int y)
{
  inittermi();
  putp(tparm(posxy,y-1,x-1));
}
 
void textcolor(int _color)
{
  inittermi();
  putp(tparm(coult, _color));
}

void textbackground(int _color)
{
  inittermi;
  putp(tparm(coulf, _color));
}

 
void textattr(int _mode)
{
  inittermi();
  putp(tparm(modaf,_mode & surbri, _mode & ssli, _mode & invi,
	     _mode & cligno, _mode & bint, _mode & gras, _mode & invis,
	     _mode & prote, _mode & altcar));
}
    
int _lignes(void)
{
  inittermi();
  return tigetnum("lines");
}

int _colonnes(void)
{
  inittermi();
  return tigetnum("cols");
}
