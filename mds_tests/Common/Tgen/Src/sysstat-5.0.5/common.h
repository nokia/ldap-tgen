/*
 * sysstat: System performance tools for Linux
 * (C) 1999-2004 by Sebastien Godard (sysstat <at> wanadoo.fr)
 */

#ifndef _COMMON_H
#define _COMMON_H

#include <time.h>

#define FALSE	0
#define TRUE	1

#define MINIMUM(a,b)	((a) < (b) ? (a) : (b))

#define NR_CPUS		1024

/*
 * Size of /proc/interrupts line (at NR_CPUS # of cpus)
 * 4 spaces for interrupt # field ; 11 spaces for each interrupt field.
 */
#define INTERRUPTS_LINE	(4 + 11 * NR_CPUS)

/* Keywords */
#define K_ISO	"ISO"
#define K_ALL	"ALL"

/* Files */
#define STAT		"/proc/stat"
#define PPARTITIONS	"/proc/partitions"
#define DISKSTATS	"/proc/diskstats"
#define INTERRUPTS	"/proc/interrupts"
#define SYSFS_BLOCK	"/sys/block"
#define S_STAT		"stat"

#define MAX_FILE_LEN	256
#define MAX_PF_NAME	1024

#define NR_DEV_PREALLOC		4
#define NR_DISK_PREALLOC	3

/* Define flags */
#define F_BOOT_STATS		0x100000
#define D_PARTITIONS		0x200000
#define F_HAS_DISKSTATS		0x400000
#define F_HAS_PPARTITIONS	0x800000

#define WANT_BOOT_STATS(m)	(((m) & F_BOOT_STATS) == F_BOOT_STATS)
#define DISPLAY_PARTITIONS(m)	(((m) & D_PARTITIONS) == D_PARTITIONS)
#define HAS_DISKSTATS(m)	(((m) & F_HAS_DISKSTATS) == F_HAS_DISKSTATS)
#define HAS_PPARTITIONS(m)	(((m) & F_HAS_PPARTITIONS) == F_HAS_PPARTITIONS)


#define CNT_DEV		0
#define CNT_PART	1

#define S_VALUE(m,n,p)	(((double) ((n) - (m))) / (p) * HZ)

/* new define to normalize to %; HZ is 1024 on IA64 and % should be normalized to 100 */
#define SP_VALUE(m,n,p)	(((double) ((n) - (m))) / (p) * 100)

/*
 * 0: stats at t,
 * 1: stats at t' (t+T or t-T),
 * 2: average.
 */
#define DIM	3

/* Environment variable */
#define TM_FMT_VAR	"S_TIME_FORMAT"

#define DIGITS		"0123456789"

#define UTSNAME_LEN	65

#define NR_DISKS	4

#define DISP_HDR	1

/* Functions */
extern char	   *device_name(char *);
extern unsigned int get_disk_io_nr(void);
extern int	    get_kb_shift(void);
extern time_t	    get_localtime(struct tm *);
extern int	    get_cpu_nr(int *, unsigned int);
extern int	    get_sysfs_dev_nr(int);
extern int	    get_diskstats_dev_nr(int);
extern int	    get_ppartitions_dev_nr(void);
extern int	    get_win_height(void);
extern void	    init_nls(void);
extern double       ll_s_value(unsigned long long, unsigned long long,
			       unsigned long long);
extern double       ll_sp_value(unsigned long long, unsigned long long,
				unsigned long long);
extern void	    print_gal_header(struct tm *, char *, char *, char *);

#endif  /* _COMMON_H */
