
#include <sys/timeb.h>
#include <stdio.h>
#include <stdarg.h>
#ifdef __TGEN_ON_LINUX_TIMESPEC
#include <time.h>
#else
#include <sys/time.h>
#endif

extern FILE *		    tcRptFile 		    ;
extern FILE *		    tcCsvFile		    ;
extern FILE *		    tcLogFile 		    ;


extern void generic_trace(FILE *file, char *type, char *fmt, char* filename, int linenum, ...);


#define TRACE_CRITICAL(fmt, ... ) 	{\
	generic_trace(tcLogFile, "CRITIC", fmt, strrchr(__FILE__, '/')+1, __LINE__, ## __VA_ARGS__ ); \
	fprintf(stdout,fmt, ## __VA_ARGS__ );\
									}
#define TRACE_TRAFIC(fmt, ... ) 	if (verbose>1) generic_trace(tcLogFile, "TRAFIC", fmt, strrchr(__FILE__, '/')+1, __LINE__, ## __VA_ARGS__ )
#define TRACE_CONSOLE(fmt, ... ) 	fprintf(stdout,fmt, ## __VA_ARGS__ )
#define TRACE_ERROR(fmt, ... ) 		generic_trace(tcLogFile, "ERROR ", fmt, strrchr(__FILE__, '/')+1, __LINE__, ## __VA_ARGS__ )
#define TRACE_DEBUG(fmt, ... ) 		if (debug) generic_trace(tcLogFile, "DEBUG ", fmt, strrchr(__FILE__, '/')+1, __LINE__, ## __VA_ARGS__ )
#define TRACE_CORE(fmt, ... ) 		generic_trace(tcLogFile, "CORE  ", fmt, strrchr(__FILE__, '/')+1, __LINE__, ## __VA_ARGS__ )

            