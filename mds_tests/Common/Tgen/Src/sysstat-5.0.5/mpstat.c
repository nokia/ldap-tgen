/*
 * mpstat: per-processor statistics
 * (C) 2000-2004 by Sebastien GODARD (sysstat <at> wanadoo.fr)
 *
 ***************************************************************************
 * This program is free software; you can redistribute it and/or modify it *
 * under the terms of the GNU General Public License as published  by  the *
 * Free Software Foundation; either version 2 of the License, or (at  your *
 * option) any later version.                                              *
 *                                                                         *
 * This program is distributed in the hope that it  will  be  useful,  but *
 * WITHOUT ANY WARRANTY; without the implied warranty  of  MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License *
 * for more details.                                                       *
 *                                                                         *
 * You should have received a copy of the GNU General Public License along *
 * with this program; if not, write to the Free Software Foundation, Inc., *
 * 675 Mass Ave, Cambridge, MA 02139, USA.                                 *
 ***************************************************************************
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <sys/utsname.h>
#include <sys/param.h>	/* for HZ */

#include "version.h"
#include "mpstat.h"
#include "common.h"


#ifdef USE_NLS
#include <locale.h>
#include <libintl.h>
#define _(string) gettext(string)
#else
#define _(string) (string)
#endif


struct mp_stats *st_mp_cpu[DIM];
/* NOTE: Use array of _char_ for bitmaps to avoid endianness problems...*/
unsigned char *cpu_bitmap;	/* Bit 0: Global; Bit 1: 1st proc; etc. */
struct mp_timestamp st_mp_tstamp[DIM];
/* Nb of processors on the machine. A value of 1 means two processors */
int cpu_nr = -1;
long interval = 0, count = 0;
unsigned int flags = 0;


/*
 ***************************************************************************
 * Print usage and exit
 ***************************************************************************
 */
void usage(char *progname)
{
   fprintf(stderr, _("sysstat version %s\n"
		   "(C) Sebastien Godard\n"
	           "Usage: %s [ options... ] [ <interval> [ <count> ] ]\n"
		   "Options are:\n"
		   "[ -P { <cpu> | ALL } ] [ -V ]\n"),
	   VERSION, progname);
   exit(1);
}


/*
 ***************************************************************************
 * SIGALRM signal handler
 ***************************************************************************
 */
void alarm_handler(int sig)
{
   signal(SIGALRM, alarm_handler);
   alarm(interval);
}


/*
 ***************************************************************************
 * Allocate mp_stats structures and cpu bitmap
 ***************************************************************************
 */
void salloc_mp_cpu(int nr_cpus)
{
   int i;

   for (i = 0; i < DIM; i++) {
      if ((st_mp_cpu[i] = (struct mp_stats *) malloc(MP_STATS_SIZE * nr_cpus)) == NULL) {
	 perror("malloc");
	 exit(4);
      }

      memset(st_mp_cpu[i], 0, MP_STATS_SIZE * nr_cpus);
   }

   if ((cpu_bitmap = (unsigned char *) malloc((nr_cpus >> 3) + 1)) == NULL) {
      perror("malloc");
      exit(4);
   }

   memset(cpu_bitmap, 0, (nr_cpus >> 3) + 1);
}


/*
 ***************************************************************************
 * Core function used to display statistics
 ***************************************************************************
 */
void write_stats_core(short prev, short curr, short dis,
		      char *prev_string, char *curr_string)
{
   struct mp_stats *st_mp_cpu_i, *st_mp_cpu_j;
   unsigned long long itv;
   int cpu;

   /*
    * Under very special circumstances, STDOUT may become unavailable,
    * This is what we try to guess here
    */
   if (write(STDOUT_FILENO, "", 0) == -1) {
      perror("stdout");
      exit(6);
   }

   /*
    * Interval value in jiffies, multiplied by the number of proc.
    * The interval should always be smaller than 0xffffffff (ULONG_MAX on
    * 32-bit architectures), except perhaps if it is the interval since
    * system startup (we want stats since boot time).
    * Interval is and'ed with mask 0xffffffff to handle overflow conditions
    * that may happen since uptime values are unsigned long long but are
    * calculated as a sum of values that _may_ be unsigned long only...
    */
   if (WANT_BOOT_STATS(flags))
      itv = st_mp_tstamp[curr].uptime;
   else
      itv = (st_mp_tstamp[curr].uptime - st_mp_tstamp[prev].uptime) & 0xffffffff;

   if (!itv)	/* Paranoia checking */
      itv = 1;

   /* Print stats */
   if (dis)
      printf(_("\n%-11s  CPU   %%user   %%nice %%system %%iowait    %%irq   %%soft   %%idle    intr/s\n"),
	     prev_string);

   /* Check if we want global stats among all proc */
   if (*cpu_bitmap & 1) {

      printf(_("%-11s  all"), curr_string);

      printf("  %6.2f  %6.2f  %6.2f  %6.2f  %6.2f  %6.2f",
	     ll_sp_value(st_mp_cpu[prev]->cpu_user,    st_mp_cpu[curr]->cpu_user,    itv),
 	     ll_sp_value(st_mp_cpu[prev]->cpu_nice,    st_mp_cpu[curr]->cpu_nice,    itv),
	     ll_sp_value(st_mp_cpu[prev]->cpu_system,  st_mp_cpu[curr]->cpu_system,  itv),
	     ll_sp_value(st_mp_cpu[prev]->cpu_iowait,  st_mp_cpu[curr]->cpu_iowait,  itv),
	     ll_sp_value(st_mp_cpu[prev]->cpu_hardirq, st_mp_cpu[curr]->cpu_hardirq, itv),
	     ll_sp_value(st_mp_cpu[prev]->cpu_softirq, st_mp_cpu[curr]->cpu_softirq, itv));

      if (st_mp_cpu[curr]->cpu_idle < st_mp_cpu[prev]->cpu_idle)
	 printf("    %.2f", 0.0);	/* Handle buggy kernels */
      else
	 printf("  %6.2f",
		ll_sp_value(st_mp_cpu[prev]->cpu_idle, st_mp_cpu[curr]->cpu_idle, itv));
   }

   /*
    * Here, we reduce the interval value to one processor,
    * using the uptime computed for proc#0.
    */
   if (cpu_nr) {
      if (WANT_BOOT_STATS(flags))
	 itv = st_mp_tstamp[curr].uptime0;
      else
	 itv = (st_mp_tstamp[curr].uptime0 - st_mp_tstamp[prev].uptime0) & 0xffffffff;
      if (!itv)
	 itv = 1;
   }

   if (*cpu_bitmap & 1) {
       printf(" %9.2f\n",
	  ll_s_value(st_mp_cpu[prev]->irq, st_mp_cpu[curr]->irq, itv));
   }

   for (cpu = 1; cpu <= cpu_nr + 1; cpu++) {

      /* Check if we want stats about this proc */
      if (!(*(cpu_bitmap + (cpu >> 3)) & (1 << (cpu & 0x07))))
	 continue;

      printf("%-11s %4d", curr_string, cpu - 1);

      st_mp_cpu_i = st_mp_cpu[curr] + cpu;
      st_mp_cpu_j = st_mp_cpu[prev] + cpu;

      printf("  %6.2f  %6.2f  %6.2f  %6.2f  %6.2f  %6.2f",
	     ll_sp_value(st_mp_cpu_j->cpu_user,    st_mp_cpu_i->cpu_user,    itv),
	     ll_sp_value(st_mp_cpu_j->cpu_nice,    st_mp_cpu_i->cpu_nice,    itv),
	     ll_sp_value(st_mp_cpu_j->cpu_system,  st_mp_cpu_i->cpu_system,  itv),
	     ll_sp_value(st_mp_cpu_j->cpu_iowait,  st_mp_cpu_i->cpu_iowait,  itv),
	     ll_sp_value(st_mp_cpu_j->cpu_hardirq, st_mp_cpu_i->cpu_hardirq, itv),
	     ll_sp_value(st_mp_cpu_j->cpu_softirq, st_mp_cpu_i->cpu_softirq, itv));

      if (st_mp_cpu_i->cpu_idle < st_mp_cpu_j->cpu_idle)
	 printf("    %.2f", 0.0);
      else
	 printf("  %6.2f",
		ll_sp_value(st_mp_cpu_j->cpu_idle, st_mp_cpu_i->cpu_idle, itv));

      printf(" %9.2f\n",
	     ll_s_value(st_mp_cpu_j->irq, st_mp_cpu_i->irq, itv));
   }
}


/*
 ***************************************************************************
 * Print statistics average
 ***************************************************************************
 */
void write_stats_avg(short curr, short dis)
{
   char string[16];

   strcpy(string, _("Average:"));
   write_stats_core(2, curr, dis, string, string);
}


/*
 ***************************************************************************
 * Print statistics
 ***************************************************************************
 */
void write_stats(short curr, short dis, struct tm *loc_time)
{
   char cur_time[2][16];

   /*
    * Get previous timestamp
    * NOTE: loc_time structure must have been init'ed before!
    */
   loc_time->tm_hour = st_mp_tstamp[!curr].hour;
   loc_time->tm_min  = st_mp_tstamp[!curr].minute;
   loc_time->tm_sec  = st_mp_tstamp[!curr].second;
   strftime(cur_time[!curr], 16, "%X", loc_time);

   /* Get current timestamp */
   loc_time->tm_hour = st_mp_tstamp[curr].hour;
   loc_time->tm_min  = st_mp_tstamp[curr].minute;
   loc_time->tm_sec  = st_mp_tstamp[curr].second;
   strftime(cur_time[curr], 16, "%X", loc_time);

   write_stats_core(!curr, curr, dis, cur_time[!curr], cur_time[curr]);
}


/*
 ***************************************************************************
 * Read stats from /proc/stat
 * See kernel sources:
 * 2.4: linux/fs/proc/proc_misc.c: kstat_read_proc()
 * 2.6: linux/fs/proc/proc_misc.c: show_stat()
 ***************************************************************************
 */
void read_proc_stat(short curr)
{
   FILE *statfp;
   struct mp_stats *st_mp_cpu_i;
   static char line[80];
   unsigned long long cc_user, cc_nice, cc_system, cc_hardirq, cc_softirq;
   unsigned long long cc_idle, cc_iowait;
   int proc_nb;

   /* Open stat file */
   if ((statfp = fopen(STAT, "r")) == NULL) {
      fprintf(stderr, _("Cannot open %s: %s\n"), STAT, strerror(errno));
      exit(2);
   }

   while (fgets(line, 80, statfp) != NULL) {

      if (!strncmp(line, "cpu ", 4)) {
	 /*
	  * Read the number of jiffies spent in the different modes
	  * among all proc. CPU usage is not reduced to one
	  * processor to avoid rounding problems.
	  */
	 st_mp_cpu[curr]->cpu_iowait = 0;	/* For pre 2.5 kernels */
	 cc_hardirq = cc_softirq = 0;
	 /* CPU counters became unsigned long long with kernel 2.6.5 */
	 sscanf(line + 5, "%llu %llu %llu %llu %llu %llu %llu",
		&(st_mp_cpu[curr]->cpu_user),
		&(st_mp_cpu[curr]->cpu_nice),
		&(st_mp_cpu[curr]->cpu_system),
		&(st_mp_cpu[curr]->cpu_idle),
		&(st_mp_cpu[curr]->cpu_iowait),
		&(st_mp_cpu[curr]->cpu_hardirq),
		&(st_mp_cpu[curr]->cpu_softirq));

	 /*
	  * Compute the uptime of the system in jiffies (1/100ths of a second
	  * if HZ=100).
	  * Machine uptime is multiplied by the number of processors here.
	  */
	 st_mp_tstamp[curr].uptime = st_mp_cpu[curr]->cpu_user +
	                             st_mp_cpu[curr]->cpu_nice +
	                             st_mp_cpu[curr]->cpu_system +
	                             st_mp_cpu[curr]->cpu_idle +
	                             st_mp_cpu[curr]->cpu_iowait +
	    			     st_mp_cpu[curr]->cpu_hardirq +
	    			     st_mp_cpu[curr]->cpu_softirq;
      }

      else if (!strncmp(line, "cpu", 3)) {
	 /*
	  * Read the number of jiffies spent in the different modes
	  * (user, nice, etc.) for current proc.
	  * This is done only on SMP machines.
	  */
	 cc_iowait = cc_hardirq = cc_softirq = 0;
	 sscanf(line + 3, "%d %llu %llu %llu %llu %llu %llu %llu",
		&proc_nb,
		&cc_user, &cc_nice, &cc_system, &cc_idle, &cc_iowait,
		&cc_hardirq, &cc_softirq);

	 if (proc_nb <= cpu_nr) {
	    st_mp_cpu_i = st_mp_cpu[curr] + proc_nb + 1;
	    st_mp_cpu_i->cpu_user    = cc_user;
	    st_mp_cpu_i->cpu_nice    = cc_nice;
	    st_mp_cpu_i->cpu_system  = cc_system;
	    st_mp_cpu_i->cpu_idle    = cc_idle;
	    st_mp_cpu_i->cpu_iowait  = cc_iowait;
	    st_mp_cpu_i->cpu_hardirq = cc_hardirq;
	    st_mp_cpu_i->cpu_softirq = cc_softirq;
	 }
	 /* else:
	  * Additional CPUs have been dynamically registered in /proc/stat.
	  * mpstat won't crash, but the CPU stats might be false...
	  */
	
	 if (!proc_nb)
	    /*
	     * Compute uptime reduced for one proc,
	     * using jiffies count for proc#0.
	     */
	    st_mp_tstamp[curr].uptime0 = cc_user + cc_nice + cc_system +
	       				 cc_idle + cc_iowait + cc_hardirq +
	    				 cc_softirq;
      }

      else if (!strncmp(line, "intr ", 5))
	 /*
	  * Read total number of interrupts received since system boot.
	  * Interrupts counter became unsigned long long with kernel 2.6.5.
	  */
	 sscanf(line + 5, "%llu", &(st_mp_cpu[curr]->irq));
   }

   /* Close stat file */
   fclose(statfp);
}


/*
 ***************************************************************************
 * Read stats from /proc/interrupts
 * See kernel sources:
 * 2.4: linux/arch/{i386,...}/kernel/irq.c: get_irq_list()
 * 2.6: linux/arch/{i386,...}/kernel/irq.c: show_interrupts()
 ***************************************************************************
 */
void read_interrupts_stat(short curr)
{
   FILE *irqfp;
   struct mp_stats *st_mp_cpu_i;
   static char line[INTERRUPTS_LINE];
   unsigned long irq = 0;
   unsigned int cpu;

   for (cpu = 0; cpu <= cpu_nr; cpu++) {
      st_mp_cpu_i = st_mp_cpu[curr] + cpu +1;
      st_mp_cpu_i->irq = 0;
   }

   /* Open interrupts file */
   if ((irqfp = fopen(INTERRUPTS, "r")) != NULL) {

      while (fgets(line, INTERRUPTS_LINE, irqfp) != NULL) {

	 if (isdigit(line[2])) {
	
	    for (cpu = 0; cpu <= cpu_nr; cpu++) {
	       st_mp_cpu_i = st_mp_cpu[curr] + cpu + 1;
	       sscanf(line + 4 + 11 * cpu, " %10lu", &irq);
	       st_mp_cpu_i->irq += irq;
	    }
	 }
      }

      /* Close serial file */
      fclose(irqfp);
   }
}


/*
 ***************************************************************************
 * Main loop: read stats from the relevant sources,
 * and display them.
 ***************************************************************************
 */
void rw_mp_stat_loop(short dis_hdr, unsigned long lines, int rows,
		     struct tm *loc_time)
{
   short curr = 1, dis = 1;

   do {

      /* Resetting the structure not needed since every fields will be set */

      /* Save time */
      get_localtime(loc_time);

      st_mp_tstamp[curr].hour   = loc_time->tm_hour;
      st_mp_tstamp[curr].minute = loc_time->tm_min;
      st_mp_tstamp[curr].second = loc_time->tm_sec;

      /* Read stats */
      read_proc_stat(curr);
      read_interrupts_stat(curr);

      /* Write stats */
      if (!dis_hdr) {
	 dis = lines / rows;
	 if (dis)
	    lines %= rows;
	 lines++;
      }
      write_stats(curr, dis, loc_time);

      /* Flush data */
      fflush(stdout);

      if (count > 0)
	 count--;
      if (count) {
	 curr ^= 1;
	 pause();
      }
   }
   while (count);

   /* Write stats average */
   write_stats_avg(curr, dis_hdr);
}


/*
 ***************************************************************************
 * Main entry to the program
 ***************************************************************************
 */
int main(int argc, char **argv)
{
   int opt = 0, i;
   struct utsname header;
   short dis_hdr = -1, opt_used = 0;
   unsigned long lines = 0;
   int rows = 23;
   struct tm loc_time;

#ifdef USE_NLS
   /* Init National Language Support */
   init_nls();
#endif

   /* How many processors on this machine ? */
   get_cpu_nr(&cpu_nr, ~0);

   /*
    * cpu_nr: a value of 1 means there are 2 processors (0 and 1).
    * In this case, we have to allocate 3 structures: global, proc0 and proc1.
    */
   salloc_mp_cpu(cpu_nr + 2);

   while (++opt < argc) {

      if (!strcmp(argv[opt], "-V"))
	 usage(argv[0]);

      else if (!strcmp(argv[opt], "-P")) {
	 /* '-P ALL' can be used on UP machines */
	 if (argv[++opt]) {
	    opt_used = 1;
	    dis_hdr++;
	    if (!strcmp(argv[opt], K_ALL)) {
	       if (cpu_nr)
		  dis_hdr = 9;
	       /*
		* Set bit for every processor.
		* Also indicate to display stats for CPU 'all'.
		*/
	       memset(cpu_bitmap, 0xff, ((cpu_nr + 1 + (cpu_nr > 0)) >> 3) + 1);
	    }
	    else {
	       if (strspn(argv[opt], DIGITS) != strlen(argv[opt]))
		  usage(argv[0]);
	       i = atoi(argv[opt]);	/* Get cpu number */
	       if (i > cpu_nr) {
		  fprintf(stderr, _("Not that many processors!\n"));
		  exit(1);
	       }
	       i++;
	       *(cpu_bitmap + (i >> 3)) |= 1 << (i & 0x07);
	    }
	 }
	 else
	    usage(argv[0]);
      }

      else if (!interval) {		/* Get interval */
	 if ((strspn(argv[opt], DIGITS) != strlen(argv[opt])) ||
	     WANT_BOOT_STATS(flags))
	    usage(argv[0]);
	 interval = atol(argv[opt]);
	 if (!interval)
	    flags |= F_BOOT_STATS;
	 else if (interval < 0)
	   usage(argv[0]);
	 count = -1;
      }

      else if (count <= 0) {		/* Get count value */
	 if (strspn(argv[opt], DIGITS) != strlen(argv[opt]))
	    usage(argv[0]);
	 count = atol(argv[opt]);
	 if (count < 1)
	   usage(argv[0]);
      }

      else
	 usage(argv[0]);
   }

   if (!opt_used)
      /* Option -P not used: set bit 0 (global stats among all proc) */
      *cpu_bitmap = 1;
   if (dis_hdr < 0)
      dis_hdr = 0;
   if (!dis_hdr) {
      /* Get window size */
      rows = get_win_height();
      lines = rows;
   }
   if (!interval)
      /* Interval not set => display stats since boot time */
      flags |= F_BOOT_STATS;

   /* Get time */
   get_localtime(&loc_time);

   /* Get system name, release number and hostname */
   uname(&header);
   print_gal_header(&loc_time, header.sysname, header.release, header.nodename);

   st_mp_tstamp[0].hour   = loc_time.tm_hour;
   st_mp_tstamp[0].minute = loc_time.tm_min;
   st_mp_tstamp[0].second = loc_time.tm_sec;

   /* Read stats */
   read_proc_stat(0);
   read_interrupts_stat(0);

   if (WANT_BOOT_STATS(flags)) {
      /* Display since boot time */
      st_mp_tstamp[1] = st_mp_tstamp[0];

      memset(st_mp_cpu[1], 0, MP_STATS_SIZE * (cpu_nr + 2));

      write_stats(0, DISP_HDR, &loc_time);
      exit(0);
   }

   /* Set a handler for SIGALRM */
   alarm_handler(0);

   /* Save the first stats collected. Will be used to compute the average */
   st_mp_tstamp[2] = st_mp_tstamp[0];
   memcpy(st_mp_cpu[2], st_mp_cpu[0], MP_STATS_SIZE * (cpu_nr + 2));

   pause();

   /* Main loop */
   rw_mp_stat_loop(dis_hdr, lines, rows, &loc_time);

   return 0;
}
