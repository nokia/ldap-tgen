/*
 * MEMORY.H
 *
 * Last update : $Author:: Kdethier           $
 *               $Date:: 15-12-97 15:17       $
 *               $Revision:: 8                $
 */

#ifndef MEMORY_H
#define MEMORY_H

#ifdef NDEBUG
#define NOMEMCHECK  1
#undef MEMDEBUG
#endif


/* VMS Must use memory wrappers to use LIB$GET_VM/LIB$FREE_VM */
#ifdef VMS
#undef NOMEMCHECK
#endif

#ifdef NOMEMCHECK

#define MemoryIsValid( _s )         (TRUE)
#define MemoryAlloc( _s )           (malloc)( (_s) )
#define MemoryFree( _b )            (free)( (_b) )
#define MemoryRealloc( _b, _s )     ( (_b) ? (realloc)( (_b), (_s) ) : (malloc)( (_s) ) )
#define MemoryInit()                (TRUE)
#define MemoryCalloc( _n, _s )      (calloc)( (_n), (_s) )
#define MemoryStrdup( _s )          (strdup)( (_s) )

#else

#include <string.h> /* must include this BEFORE redefining str*functions */

  typedef struct
  {
    int alloccount;
    int freecount;
    int allocated;
  } MEMORYINFO;

  BOOL  MemoryInit();
  void  MemoryGetInfo( MEMORYINFO *info );

  BOOL  MemoryIsValid( void *buffer );
#ifndef MEMDEBUG
  void *MemoryAlloc( unsigned int size );
  void *MemoryRealloc( void *buffer, unsigned int newsize );
#endif
  void  MemoryFree( void *buffer );
  void *MemoryCalloc( int number, unsigned int size );
  char *MemoryStrdup( const char *string );

#ifdef MEMDEBUG
  void *MemoryDebugAlloc( unsigned int size, char *filename, int linenr );
  void *MemoryDebugRealloc( void *buffer, unsigned int newsize, char *filename, int linenr );
  void *MemoryCheck( void *buffer, unsigned int size, int type, char *filename, int linenr );

#define MemoryAlloc( size )		  MemoryDebugAlloc( (size), __FILE__, __LINE__ )
#define MemoryRealloc( buffer, newsize )  MemoryDebugRealloc( (buffer), (newsize), __FILE__, __LINE__ )

#define MEMDEBUG_STRCPY		0
#define MEMDEBUG_STRNCPY	1
#define MEMDEBUG_STRCAT		2
#define MEMDEBUG_STRNCAT	3
#define MEMDEBUG_MEMCPY		4
#define MEMDEBUG_MEMSET		5

#define strcpy(d,s)		(strcpy)(MemoryCheck(d,strlen(s)+1,MEMDEBUG_STRCPY,__FILE__,__LINE__),s)
#define strncpy(d,s,i)		(strncpy)(MemoryCheck(d,i,MEMDEBUG_STRNCPY,__FILE__,__LINE__),s,i)
#define strcat(d,s)		(strcat)(MemoryCheck(d,strlen(s)+strlen(d)+1,MEMDEBUG_STRCAT,__FILE__,__LINE__),s)
#define strncat(d,s,i)		(strncat)(MemoryCheck(d,i+strlen(d)+1,MEMDEBUG_STRNCAT,__FILE__,__LINE__),s,i)
#define memcpy(d,s,i)		(memcpy)(MemoryCheck(d,i,MEMDEBUG_MEMCPY,__FILE__,__LINE__),s,i)
#define memset(d,c,i)		(memset)(MemoryCheck(d,i,MEMDEBUG_MEMSET,__FILE__,__LINE__),c,i)
#endif

#endif

#ifdef strcmp
#undef strcmp
#endif
#define strcmp(d,s)		(strcmp)((d) ? (const char*)(d) : "", (s) ? (const char*)(s) : "")

#ifdef strncmp
#undef strncmp
#endif
#define strncmp(d,s,i)		(strncmp)((d) ? (const char*)(d) : "", (s) ? (const char*)(s) : "", i)

#ifdef strlen
#undef strlen
#endif
#define strlen(s)		((s) ? (strlen)((const char*)(s)) : 0)

#ifndef WIN32
#define strcasecmp(d,s)		(strcasecmp)((d) ? (const char*)(d) : "", (s) ? (const char*)(s) : "")
#define strncasecmp(d,s,i)	(strncasecmp)((d) ? (const char*)(d) : "", (s) ? (const char*)(s) : "",i)
#endif

#endif
