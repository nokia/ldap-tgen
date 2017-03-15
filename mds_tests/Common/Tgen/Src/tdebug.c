#include <pthread.h>
#include "tdebug.h"
#include "tconf.h"

extern pthread_key_t    tThreadIdKey;

/******************************************************************************/
void generic_trace(FILE *fd, char *type, char *fmt, char* filename, int linenum, ...)
/******************************************************************************/
{
char			format[1024];
va_list 		ap;
time_t 			now;
struct tm 		ptm;
struct timeb 	ptb;
int				thid = (int)pthread_getspecific(tThreadIdKey);

	if (nolog_option == 0 || (type != "ERROR ") && (nolog_option == 2)){
		ftime(&ptb);
		now = ptb.time;
		localtime_r(&now, &ptm );

		va_start(ap, fmt);
		sprintf(format, "%02d/%02d/%d %02d:%02d:%02d.%03d | T%3d | %s | %s:%d | %s",
				ptm.tm_mday, ptm.tm_mon+1, 1900+ptm.tm_year, ptm.tm_hour, ptm.tm_min, ptm.tm_sec, ptb.millitm,
				thid, type, filename, linenum,
				fmt);

		vfprintf(fd, format, ap);
		va_end(ap);

		fflush(fd);
	}
}


