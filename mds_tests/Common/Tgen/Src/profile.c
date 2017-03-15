/*
 * PROFILE.C
 *
 * Last update : $Author:: Kdethier           $
 *               $Date:: 27-11-97 15:05       $
 *               $Revision:: 5                $
 *
 * mod JHER 08/11/99 : GetInt() will now read hexadecimal numbers too
 *		       optimized the read-routine StripWS()
 * mod JHER 12/05/00 : GetIniFile will buffer the entire file in memory
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
 	
//EmA 26/08/2010 for "$include ..." option:
// #include <unistd.h>

//#include "types.h"          // EmA, 03/12/2002, for integration in Tgen
#include "typedef.h"				// EmA, 03/12/2002, added for integration in Tgen
#include "stringex.h"
#include "profile.h"
#include "tdebug.h"
//#include "memory.h"         // EmA, 03/12/2002, for integration in Tgen

//#include "smclog.h"	/* KBDA 071298*/ // EmA, 03/12/2002, for integration in Tgen
#define SOURCE_NAME "profile."

#define MAX_LINE_LENGTH   8192
#define MAX_FIELNAME_LENGTH   128

#ifndef WIN32
#define FOPEN_MODE  "r"
#else
#define FOPEN_MODE  "rt"
#endif

/******************************************************************************/
static char *StripWS( char *line )
/******************************************************************************/
// strip whitespace on the left and right of the string (very fast)
{
    char *p;

    // trim whitespace on the left (works also when empty line)
    while ( isspace(*line) )
      line++;

    // strip comments (works also for empty line)
    for ( p = line ; *p ; p++ )
    {
      if ( (*p == ';') || (*p == '#') )
      {
		*p = '\0';
		break;
      }
    }

    if ( *line )
    {
      // p now points to the \0 char ....
      
      // trim whitespace on the right (including CR, LF and CRLF)
      for ( p--; (p >= line) && isspace(*p) ; p-- )
      {
		  *p = '\0';
      }
    }

    return line;
}

/******************************************************************************/
static void StripClose( char *line )
/******************************************************************************/
{
  int length;

  length = strlen( line )-1;
  while ( length >= 0 )
  {
    if ( line[length] == ']' )
    {
      line[length] = 0;
      length--;
    }
    else
      break;
  }
}

/******************************************************************************/
static const char *GetIncludedFile ( const char * dir, const char *file )
/******************************************************************************/
{
char *buf = NULL;
int   buflen = 0;
FILE *fp;
char  fname[MAX_FIELNAME_LENGTH];

  if ( file == NULL )
    return NULL;

  strcpy(fname, dir);
  strcat(fname, "/");
  strcat(fname, file);

  if ( !ProfileIniExist(fname) ) {
	   TRACE_CRITICAL("tgen: main: can't read ini-file %s\n", fname);
	   exit(1);
  } else {
	  TRACE_CORE("tgen: main: read included file %s\n", fname);
  }

  fp = fopenexp( fname, FOPEN_MODE );
  if ( NULL == fp )
    return NULL;

  while ( !feof(fp) )
  {
    char line[MAX_LINE_LENGTH];
    char *p;
    int len;

    line[0] = '\0';
    if ( NULL == fgets(line, sizeof(line)-1, fp) )
      break;
    p = StripWS(line);
    if ( *p == '\0' )
      continue;	      // skip empty line or comment line ...

	if ( *p == '$' && !strncmp(line, "$include ", 9) ) {
		// include a file (starting from containing ini file location)
		p = GetIncludedFile( dirname(fname), &line[9] );
	}

    // store the new line at the end of buf, and increase buflen
    len = strlen(p);
    buf = realloc(buf, buflen + len + 2);
    memcpy(&buf[buflen], p, len);
    buf[buflen + len] = '\n';
    buf[buflen + len + 1] = '\0';
    buflen += len + 1;

	//free(p);	// added by EmA (26/08/2010)
  }
 
  fclose(fp);

  return (const char *)buf;
}


/******************************************************************************/
static const char *GetIniFile ( const char *fname )
/******************************************************************************/
{
  static char *ls_previousFile = NULL;
  static char *ls_cachedFile = NULL;
  static int   ls_cachedBytes = 0;
  FILE *fp;

  if ( fname == NULL )
    return NULL;

  if ( ls_previousFile && (strcmp(ls_previousFile, fname) == 0) )
    return (const char *)ls_cachedFile;

  if ( ls_previousFile )
  {
// EmA,03/12/2002: patch for integration in Tgen
//    MemoryFree(ls_previousFile);
    free(ls_previousFile);
    ls_previousFile = NULL;
  }
// EmA,03/12/2002: patch for integration in Tgen
//  ls_previousFile = MemoryStrdup(fname);
  ls_previousFile = strdup(fname);


  if ( ls_cachedFile )
  {
// EmA,03/12/2002: patch for integration in Tgen
//    MemoryFree(ls_cachedFile);
    free(ls_cachedFile);
    ls_cachedFile = NULL;
  }
  ls_cachedBytes = 0;

  fp = fopenexp( fname, FOPEN_MODE );
  if ( NULL == fp )
    return NULL;

  while ( !feof(fp) )
  {
    char line[MAX_LINE_LENGTH];
    char *p;
    int len;

    line[0] = '\0';
    if ( NULL == fgets(line, sizeof(line)-1, fp) )
      break;
    p = StripWS(line);
    if ( *p == '\0' )
      continue;	      // skip empty line or comment line ...

	if ( *p == '$' && !strncmp(line, "$include ", 9) ) {
		// include a file (starting from containing ini file location)
		TRACE_CORE("tgen: main: read included file %s\n", &line[9]);
		char *save_fname = strdup(fname);
		p = GetIncludedFile( dirname(save_fname), &line[9] );
	}

    // store the new line at the end of ls_cachedFile, and increase ls_cachedBytes
    len = strlen(p);
// EmA,03/12/2002: patch for integration in Tgen
//    ls_cachedFile = MemoryRealloc(ls_cachedFile, ls_cachedBytes + len + 2);
    ls_cachedFile = realloc(ls_cachedFile, ls_cachedBytes + len + 2);
    memcpy(&ls_cachedFile[ls_cachedBytes], p, len);
    ls_cachedFile[ls_cachedBytes + len] = '\n';
    ls_cachedFile[ls_cachedBytes + len + 1] = '\0';
    ls_cachedBytes += len + 1;

	//free(p);	// added by EmA (26/08/2010)
  }
 
  fclose(fp);

  return (const char *)ls_cachedFile;
}

/******************************************************************************/
static BOOL FindKey( const char *data, const char *section, const char *key, char *value )
/******************************************************************************/
{
  char *test;
  char *p;
  BOOL inside_section = FALSE;
  char line[MAX_LINE_LENGTH];
  char section_test[MAX_LINE_LENGTH];

  sprintf(section_test, "[%s]", section);
  value[0] = '\0';

  while ( *data )
  {
    // break 'data' in pieces (split on \n), and store it in line
    line[0] = '\0';
    p = strchr(data, '\n');
    if ( p )
    {
      assert((p-data) < MAX_LINE_LENGTH);
      memcpy(line, data, p - data);
      line[p - data] = '\0';
      data = p+1;
    }
    else
    {
      p = (char *)(data + strlen(data));
      assert((p-data) < MAX_LINE_LENGTH);
      memcpy(line, data, p - data);
      line[p - data] = '\0';
      data = p;	// \0 ==> will stop next loop
    }

    p = StripWS(line);
    if ( *p == '\0' )
      continue;

    if ( inside_section == FALSE )
    {
      if ( *p == '[' )	// quick test
      {
		if ( stricmp(p, section_test) == 0 )
		  inside_section = TRUE;
      }
      continue;
    }
    else
    {
      if ( *p == '[' )	  // next section has started...
		  break ;
      test = strchr(p, '=');
      if ( test )
      {
		*test++ = '\0';
		if ( stricmp(key, StripWS(p)) == 0 )
		{
		  strcpy(value, StripWS(test));
		  return TRUE;
		}
      }
    }
  }
  return FALSE;
}

/******************************************************************************/
static BOOL GetString( const char *ini, const char *section, const char *key, char *value )
/******************************************************************************/
{
  const char *data = NULL;

  value[0] = '\0';

  data = GetIniFile(ini);
  if ( data )
    return FindKey( data, section, key, value );
  else
    return FALSE;
}

/******************************************************************************/
char *ProfileGetString( const char *ini, const char *section, const char *key,
		       const char *defvalue, char *buffer, int length )
/******************************************************************************/
{
  char        value[MAX_LINE_LENGTH];

  if ( GetString( ini, section, key, value ) == FALSE ) {
	  if (!defvalue)
		  return NULL;
	  else
		  strcpy(value, defvalue);
  }

  strncpy( buffer, value, length-1 );
  buffer[length-1] = 0;

  TRACE_CORE("read string: [%s] %s = %s\n", section, key, buffer);
  return buffer;
}

/******************************************************************************/
int ProfileGetInt( const char *ini, const char *section, const char *key, int defvalue )
/******************************************************************************/
{
  char        value[MAX_LINE_LENGTH];

  if ( GetString( ini, section, key, value ) )
  {
    if ( strnicmp( value, "0x", 2) == 0 )     // hexadecimal number !
    {
      return strtol(value, NULL, 16);
    }
    else
    {

      TRACE_CORE("read int: [%s] %s = %s\n", section, key, value);
      return atoi(value);
    }
  }

  TRACE_CORE("read int: [%s] %s = (def)%d\n", section, key, defvalue);
  return( defvalue );
}

/******************************************************************************/
short ProfileGetShort( const char *ini, const char *section, const char *key, short defvalue )
/******************************************************************************/
{
  return( (short)ProfileGetInt( ini, section, key, defvalue ) );
}

/******************************************************************************/
BOOL ProfileGetBool( const char *ini, const char *section, const char *key, BOOL defvalue )
/******************************************************************************/
{
  char        value[MAX_LINE_LENGTH];

  if ( GetString( ini, section, key, value ) )
  {
    if ( 0 == stricmp( value, "true" ) || 
	 0 == stricmp( value, "yes" ) ||
	 0 == stricmp( value, "1" ) )
    {
      return( TRUE );
    }
    else
      return( FALSE );
  }
  else
    return( defvalue );
}

/******************************************************************************/
static int NetWorkIpAddrToUINT32( const char *ip_str )
/******************************************************************************/
{
  char   buf[6];
  char  *ptr;
  int    i;
  int    count;
  int    ipaddr;
  int    cur_byte;

  ipaddr = 0;
  for (i = 0; i < 4; i++)
  {
    ptr = buf;
    count = 0;
    *ptr = '\0';
    while (*ip_str != '.' && *ip_str != '\0' && count < 4)
    {
      if (! isdigit(*ip_str))
	return(0);
      *ptr++ = *ip_str++;
      count++;
    }
    if (count >= 4 || count == 0)
    {
      return (0);
    }
    *ptr = '\0';
    cur_byte = atoi(buf);
    if (cur_byte < 0 || cur_byte > 255)
    {
      return (0);
    }
    ip_str++;
    ipaddr = (ipaddr << 8) | cur_byte;
  }
  return (ipaddr);
}

/******************************************************************************/
int ProfileGetIpAddr( const char *ini, const char *section, const char *key, const char *defvalue )
/******************************************************************************/
{
  char        value[MAX_LINE_LENGTH];

  if ( GetString( ini, section, key, value ) == FALSE )
    strcpy(value, defvalue);

  return( NetWorkIpAddrToUINT32( value ) );
}

/******************************************************************************/
BOOL ProfileEnumSections( const char *ini, PROFILE_ENUM_PROFILEPROC enumproc, void *param )
/******************************************************************************/
{
  const char *data = NULL;
  char *p;
  char line[MAX_LINE_LENGTH];

  data = GetIniFile(ini);
  if ( data == NULL )
    return TRUE;

  while ( *data )
  {
    // break 'data' in pieces (split on \n), and store it in line
    line[0] = '\0';
    p = strchr(data, '\n');
    if ( p )
    {
      assert((p-data) < MAX_LINE_LENGTH);
      memcpy(line, data, p - data);
      line[p - data] = '\0';
      data = p+1;
    }
    else
    {
      p = (char *)(data + strlen(data));
      assert((p-data) < MAX_LINE_LENGTH);
      memcpy(line, data, p - data);
      line[p - data] = '\0';
      data = p;	// \0 ==> will stop next loop
    }

    p = StripWS(line);
    if ( *p == '\0' )
      continue;

    if ( *p == '[' )	// quick test
    {
      StripClose(p);
      if ( !enumproc( p+1, param ) )
			return FALSE;
    }
  }
  return TRUE;
}

/******************************************************************************/
BOOL ProfileIniExist( const char *ini ) 
/******************************************************************************/
{ 
  FILE *f; 
  f = fopenexp( ini, FOPEN_MODE ); 
  if ( NULL == f ) 
    return( FALSE ); 
  fclose( f ); 
  return( TRUE ); 
}

/******************************************************************************/
char *expenv( char *out, const char *in )
/******************************************************************************/
{
  char *p, *q, tmp[ 256 ];
 
  out[ 0 ] = '\0';
  for( p = ( char * ) in; q = strchr( p, '$' ); p = q ) {
    strncat( out, p, q - p );
    p = q;
    if( !( q = strchr( p, '/' ) ) )
        q = p + strlen( p );
    strncpy( tmp, p + 1, q - p - 1 );
    tmp[ q - p - 1 ] = '\0';
    if( p = getenv( tmp ) )
      strcat( out, p );
  }
  strcat( out, p );
  return out;
}

/******************************************************************************/
FILE *fopenexp( const char *fname, const char *type )
/******************************************************************************/
{
  char exp_fname[ 1024 ];
/* 1024 should be enough for any pathname after expansion.
   (Check MAXPATHLEN in sys/param.h for UNIX)
*/
 
  expenv( exp_fname, fname );
  return( fopen( exp_fname, type ) );
}
