/*
 * mpstat: per-processor statistics
 * (C) 2000-2004 by Sebastien Godard (sysstat <at> wanadoo.fr)
 */

#ifndef _MPSTAT_H
#define _MPSTAT_H


struct mp_stats {
   unsigned long long cpu_idle			__attribute__ ((aligned (8)));
   unsigned long long cpu_iowait		__attribute__ ((packed));
   unsigned long long cpu_user			__attribute__ ((packed));
   unsigned long long cpu_nice			__attribute__ ((packed));
   unsigned long long cpu_system		__attribute__ ((packed));
   unsigned long long cpu_hardirq		__attribute__ ((packed));
   unsigned long long cpu_softirq		__attribute__ ((packed));
   unsigned long long irq			__attribute__ ((packed));
   /* Structure must be a multiple of 8 bytes, since we use an array of structures.
    * Each structure is *aligned*, and we want the structures to be packed together. */
};

#define MP_STATS_SIZE	(sizeof(struct mp_stats))


struct mp_timestamp {
   unsigned long long uptime;
   unsigned long long uptime0;
   unsigned char hour;		/* (0-23) */
   unsigned char minute;	/* (0-59) */
   unsigned char second;	/* (0-59) */
};

#endif
