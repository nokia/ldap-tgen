/*
 * iostat: report CPU and I/O statistics
 * (C) 1999-2004 by Sebastien Godard (sysstat <at> wanadoo.fr)
 */

#ifndef _IOSTAT_H
#define _IOSTAT_H

#include "common.h"

#define MAX_NAME_LEN	72

#define D_CPU_ONLY	0x001
#define D_DISK_ONLY	0x002
#define D_TIMESTAMP	0x004
#define D_EXTENDED	0x008
#define D_PART_ALL	0x010
#define D_KILOBYTES	0x020
#define F_HAS_SYSFS	0x040
#define F_OLD_KERNEL	0x080
#define D_UNFILTERED	0x100
/* 0x100000:0x800000 -> reserved (cf. common.h) */

#define DISPLAY_CPU_ONLY(m)	(((m) & D_CPU_ONLY) == D_CPU_ONLY)
#define DISPLAY_DISK_ONLY(m)	(((m) & D_DISK_ONLY) == D_DISK_ONLY)
#define DISPLAY_TIMESTAMP(m)	(((m) & D_TIMESTAMP) == D_TIMESTAMP)
#define DISPLAY_EXTENDED(m)	(((m) & D_EXTENDED) == D_EXTENDED)
#define DISPLAY_PART_ALL(m)	(((m) & D_PART_ALL) == D_PART_ALL)
#define DISPLAY_KILOBYTES(m)	(((m) & D_KILOBYTES) == D_KILOBYTES)
#define HAS_SYSFS(m)		(((m) & F_HAS_SYSFS) == F_HAS_SYSFS)
#define HAS_OLD_KERNEL(m)	(((m) & F_OLD_KERNEL) == F_OLD_KERNEL)
#define DISPLAY_UNFILTERED(m)	(((m) & D_UNFILTERED) == D_UNFILTERED)

#define DT_DEVICE	0
#define DT_PARTITION	1


struct comm_stats {
   unsigned long long uptime;
   unsigned long long uptime0;
   unsigned long long cpu_iowait;
   unsigned long long cpu_idle;
   unsigned long long cpu_user;
   unsigned long long cpu_nice;
   unsigned long long cpu_system;
};

#define COMM_STATS_SIZE	(sizeof(struct comm_stats))

/*
 * Structures for I/O stats.
 * The number of structures allocated corresponds to the number of devices
 * present in the system, plus a preallocation number to handle those
 * that can be registered dynamically.
 * The number of devices is found by using /sys filesystem (if mounted),
 * or the number of "disk_io:" entries in /proc/stat (2.4 kernels),
 * else the default value is 4 (for old kernels, which maintained stats
 * for the first four devices in /proc/stat).
 * For each io_stats structure allocated corresponds a io_hdr_stats structure.
 * A io_stats structure is considered as unused or "free" (containing no stats
 * for a particular device) if the 'major' field of the io_hdr_stats
 * structure is set to 0.
 */
struct io_stats {
   /* # of read operations issued to the device */
   unsigned long rd_ios				__attribute__ ((aligned (8)));
   /* # of read requests merged */
   unsigned long rd_merges			__attribute__ ((packed));
   /* # of sectors read */
   unsigned long long rd_sectors		__attribute__ ((packed));
   /* Time of read requests in queue */
   unsigned long rd_ticks			__attribute__ ((packed));
   /* # of write operations issued to the device */
   unsigned long wr_ios				__attribute__ ((packed));
   /* # of write requests merged */
   unsigned long wr_merges			__attribute__ ((packed));
   /* # of sectors written */
   unsigned long long wr_sectors		__attribute__ ((packed));
   /* Time of write requests in queue */
   unsigned long wr_ticks			__attribute__ ((packed));
   /* # of I/Os in progress */
   unsigned long ios_pgr			__attribute__ ((packed));
   /* # of ticks total (for this device) for I/O */
   unsigned long tot_ticks			__attribute__ ((packed));
   /* # of ticks requests spent in queue */
   unsigned long rq_ticks			__attribute__ ((packed));
   /* # of I/O done since last reboot */
   unsigned long dk_drive			__attribute__ ((packed));
   /* # of blocks read */
   unsigned long dk_drive_rblk			__attribute__ ((packed));
   /* # of blocks written */
   unsigned long dk_drive_wblk			__attribute__ ((packed));
};

#define IO_STATS_SIZE	(sizeof(struct io_stats))

struct io_hdr_stats {
   unsigned int  active				__attribute__ ((aligned (8)));
   unsigned int  major				__attribute__ ((packed));
   unsigned int  index				__attribute__ ((packed));
            char name[MAX_NAME_LEN]		__attribute__ ((packed));
};

#define IO_HDR_STATS_SIZE	(sizeof(struct io_hdr_stats))

/* List of devices entered on the command line */
struct io_dlist {
   /* Indicate whether its partitions are to be displayed or not */
   int  disp_part				__attribute__ ((aligned (8)));
   /* Device name */
   char dev_name[MAX_NAME_LEN]			__attribute__ ((packed));
};

#define IO_DLIST_SIZE	(sizeof(struct io_dlist))

#endif  /* _IOSTAT_H */
