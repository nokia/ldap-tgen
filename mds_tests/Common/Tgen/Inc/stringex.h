/*
 * STRINGEX.H
 *
 * Last update : $Author:: Jkunnen            $
 *               $Date:: 12/09/98 3:03p       $
 *               $Revision:: 7                $
 */

#ifndef STRINGEX_H
#define STRINGEX_H



#ifdef VMS

/* VMS does not have str*icmp - use str*casecmp defined in c-file */ 

#define stricmp strcasecmp
#define strnicmp strncasecmp
/*
int strcasecmp( const char *s1, const char *s2 );
int strncasecmp( const char *s1, const char *s2, size_t n );
*/

#elif defined(WIN32) 

/* use built-in str*icmp */
#define strcasecmp stricmp 
#define strncasecmp strnicmp

#elif defined(SOLARIS) || (defined(__osf__) && defined(__alpha))

/* use built-in str*casecmp */
#define stricmp strcasecmp
#define strnicmp strncasecmp

#else

/* unknown implementation */
// EmA, 03/12/2002, for integration in Tgen
//#error "Platform not supported"
#define stricmp strcasecmp
#define strnicmp strncasecmp

#endif


#ifdef NO_STRRCHR
/* use strrchr defined in c-file */
char *strrchr( const char *string, int c );
#endif


/* renamed functions */
#define strrevchr strrchr
#define stricmpn strnicmp
#define strnchr strchrn


  char *strrevcpy( char *dst, const char *src );
  char *strtolower( char *str );
  char *strtoupper( char *str );
  char *strchrn( const char *text, int c, int n );


#endif
