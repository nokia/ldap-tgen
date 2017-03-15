/*
 * PROFILE.H
 */

#ifndef PROFILE_H
#define PROFILE_H

  BOOL ProfileIniExist( const char *ini ); 
 
  char *ProfileGetString( const char *ini, const char *section, const char *key, 
                          const char *defvalue, char *buffer, int length ); 
  int   ProfileGetInt( const char *ini, const char *section, const char *key, int defvalue ); 
  short ProfileGetShort( const char *ini, const char *section, const char *key, short defvalue ); 
  BOOL  ProfileGetBool( const char *ini, const char *section, const char *key, BOOL defvalue ); 
  int   ProfileGetIpAddr( const char *ini, const char *section, const char *key, const char *defvalue ); 
 
  typedef BOOL (* PROFILE_ENUM_PROFILEPROC)( const char *section, void *param ); 
 
  BOOL ProfileEnumSections( const char *ini, PROFILE_ENUM_PROFILEPROC enumproc, void *param ); 

#ifndef FILE
#include <stdio.h>
#endif
  char *expenv( char *out, const char *in );
  FILE *fopenexp( const char *fname, const char *type );
#endif
