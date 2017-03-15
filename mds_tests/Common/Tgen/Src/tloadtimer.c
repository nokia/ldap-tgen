char *copyright =
    "Copyright (c) Alcatel CIT";
/*
 ** FILE         : tloadtimer.c
 ** AUTHOR       : E. Anthoine
 ** DATE         : 16-OCT-2002
 ** PURPOSE		  : give CPU load of HssMain when asked by a client
 ** BUILD        : cc tloadtimer.c -o tloadtimer
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>

#define BUFLEN			64
#define NB_MAX_CMD	10


extern int						nb_proc;
extern char 					cpuLoads[BUFLEN];
extern char						proc_name[NB_MAX_CMD][BUFLEN];
extern int						proc_load[NB_MAX_CMD];
extern int						showThreads;

static timespec_t				schedulingExpirationTime;
//static timespec_t          schedulingTick;
static pthread_mutex_t		timerMutex;
static pthread_cond_t		timerCond;


#include "os.h"
#include <signal.h>
#include <setjmp.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/table.h>
#include <sys/user.h>
#include <mach.h>
#include <mach/mach_types.h>

/* includes specific to top */
#include "display.h"		/* interface to display package */
#include "screen.h"		/* interface to screen package */
#include "top.h"
#include "machine.h"
#include "utils.h"

struct osf1_top_proc {
    size_t		p_mach_virt_size;
    char			p_mach_state;
    fixpt_t		p_mach_pct_cpu; /* aka p_pctcpu */
    int			used_ticks;
    size_t		process_size;
    pid_t		p_pid;
    uid_t		p_ruid;
    char			p_pri;
    char			p_nice;
    size_t		p_rssize;
    char			u_comm[PI_COMLEN + 1];
} ;

/* get_process_info passes back a handle.  This is what it looks like: */
struct handle
{
	struct osf1_top_proc		**next_proc;	/* points to next valid proc pointer */
	int							remaining;		/* number of pointers remaining */
};


/* Size of the stdio buffer given to stdout */
#define Buffersize	2048
/* The buffer that stdio will use */
char stdoutbuf[Buffersize];

/* imported from screen.c */
extern int overstrike;

/* internal routines */
void quit();

/* values which need to be accessed by signal handlers */
static int max_topn;		/* maximum displayable processes */

/* miscellaneous things */
char *myname = "top";
jmp_buf jmp_int;

/* routines that don't return int */

char *username();
char *ctime();
char *kill_procs();
char *renice_procs();

#ifdef ORDER
extern int (*proc_compares[])();
#else
extern int proc_compare();
#endif
time_t time();

caddr_t get_process_info();

/* different routines for displaying the user's identification */
/* (values assigned to get_userid) */
char *username();
char *itoa7();

/* display routines that need to be predeclared */
int i_loadave();
int u_loadave();
int i_procstates();
int u_procstates();
int i_cpustates();
int u_cpustates();
int i_memory();
int u_memory();
int i_message();
int u_message();
int i_header();
int u_header();
int i_process();
int u_process();

/* pointers to display routines */
int (*d_loadave)() = i_loadave;
int (*d_procstates)() = i_procstates;
int (*d_cpustates)() = i_cpustates;
int (*d_memory)() = i_memory;
int (*d_message)() = i_message;
int (*d_header)() = i_header;
int (*d_process)() = i_process;


#ifdef 0
#define TH_STATE_RUNNING	1	/* thread is running normally */
#define TH_STATE_STOPPED	2	/* thread is stopped */
#define TH_STATE_WAITING	3	/* thread is waiting normally */
#define TH_STATE_UNINTERRUPTIBLE 4	/* thread is in an uninterruptible wait */
#define TH_STATE_HALTED		5	/* thread is halted at a clean point */
#endif

#define TH_STATE_2_STRING(state) \
	( (state) == TH_STATE_RUNNING ? "run  " : \
		( (state) == TH_STATE_STOPPED ? "stop " : \
			( (state) == TH_STATE_WAITING ? "wait " : \
				( (state) == TH_STATE_UNINTERRUPTIBLE ? "unint" : \
					( (state) == TH_STATE_HALTED ? "halt " : "unk  " )))))

/************************************************************************************/
void *timerWork (void *param)
/************************************************************************************/
{
int							i, j, k;
int							active_procs;
struct system_info		systemInfo;
struct statics				statics;
caddr_t						processes;
struct process_select	ps;
struct osf1_top_proc		*pp;
struct user					u;
struct handle *			hp;
static timespec_t			schedulingTick;
struct timeval				now;
char 							*uname_field = "USERNAME";
char							interactive = 2;

char							myBuf[1024];
int							numline;

task_t							thistask;
task_basic_info_data_t		taskinfo;
unsigned int					taskinfo_l;
thread_array_t					threadarr;
unsigned int					threadarr_l;
thread_basic_info_t			threadinfo;
thread_basic_info_data_t	threadinfodata;
unsigned int					threadinfo_l;

/*
	if ( pthread_mutex_init(&timerMutex, NULL) > 0 ) {
		perror("tloadserver: pthread_mutex_init failed");
		exit(1);
	}
	if ( pthread_cond_init(&timerCond, NULL) > 0 ) {
		perror("tloadserver: pthread_cond_init failed");
		exit(1);
	}
*/
		
   /* initialize some selection options */
   ps.idle    = 1;
   ps.system  = 0;
   ps.uid     = -1;
   ps.command = NULL;

	/* initialize the kernel memory interface */
	if (machine_init(&statics) == -1) {
	 	perror("tloadserver: machine_init failure");
		exit(1);
	}

	if (showThreads) {
	   setbuffer(stdout, stdoutbuf, Buffersize);

		init_hash();

	   /* initialize termcap */
	   init_termcap(interactive);

	   /* initialize display interface */
	   if ((max_topn = display_init(&statics)) == -1) {
			fprintf(stderr, "%s: can't allocate sufficient memory\n", myname);
			exit(1);
	   }
	    
	   /* setup the jump buffer for stops */
	   if (setjmp(jmp_int) != 0) {
			/* control ends up here after an interrupt */
			reset_display();
	   }
	}
   
	while (1) {
		numline = 0;

		/* get the current stats */
		get_system_info(&systemInfo);

		/* get the current set of processes */
		processes = get_process_info(&systemInfo, &ps, NULL);
		
		// reset proc_load
		memset((char *)proc_load, 0, sizeof(proc_load));

		active_procs = systemInfo.p_active;
		hp = (struct handle *)processes;
		/* now show the top "n" processes. */
		for (i=0; i<active_procs; i++) {
			pp = *(hp->next_proc++);
    		hp->remaining--;

			/* get the process's user struct and set cputime */
			if ( pp && table(TBL_UAREA,pp->p_pid,&u,1,sizeof(struct user)) >= 0 ) {
                          
			   for (j=0; j<nb_proc; j++) {
			  		if ( u.u_comm && strstr(u.u_comm, proc_name[j]) != 0 ) {
/*
						printf("%5d %5.2f%% %.14s\n",
							pp->p_pid,
							100.0 * ((double)pp->p_mach_pct_cpu / 10000.0),
							printable(u.u_comm));
*/
			  			proc_load[j] = pp->p_mach_pct_cpu;

						if (showThreads) {
/*							
    sprintf(fmt,
	    	"%5d %-8.8s %3d %4d %5s %5s %-5s %-6s %5.2f%% %.14s",
	    pp->p_pid,
	    (*get_userid)(pp->p_ruid),
	    pp->p_pri,
	    pp->p_nice,
            format_k(pp->p_mach_virt_size/1024),
            format_k(pp->p_rssize/1000),
	    state_abbrev[pp->p_mach_state],
	    format_time(cputime),
	    100.0 * ((double)pp->p_mach_pct_cpu / 10000.0),
	    printable(u.u_comm));
*/

							sprintf(myBuf, "Threads of process %.14s\t(pid: %5d   cpu: %5.2f%%   ",
								printable(u.u_comm),
								pp->p_pid,
								100.0 * ((double)pp->p_mach_pct_cpu / 10000.0));
							sprintf(myBuf + strlen(myBuf), "res mem: %5s    virt mem: %5s   ",
      						format_k(pp->p_rssize/1000),
								format_k(pp->p_mach_virt_size/1024));
										
							if(task_by_unix_pid(task_self(), pp->p_pid, &thistask) == KERN_SUCCESS){

								taskinfo_l = TASK_BASIC_INFO_COUNT;
								
								if (task_info(thistask, TASK_BASIC_INFO, (task_info_t) &taskinfo, &taskinfo_l) == KERN_SUCCESS) {

//									int minim_state = 99, mcurp = 1000, mbasp = 1000, mslpt = 999;
							
									(void)task_threads(thistask, &threadarr, &threadarr_l);
									threadinfo = &threadinfodata;
									
									sprintf(myBuf + strlen(myBuf), "nb threads: %d", threadarr_l);
									(*d_process)(numline++, myBuf);

									sprintf(myBuf, "     ID     STATE    IDLE   PRIO   CPU");
									(*d_process)(numline++, myBuf);
									for(k=0; k<threadarr_l; k++) {
										
										threadinfo_l = THREAD_BASIC_INFO_COUNT;
										
										if (thread_info(threadarr[k], THREAD_BASIC_INFO, (thread_info_t)threadinfo, &threadinfo_l) == KERN_SUCCESS) {
											// printf("       ID    STATE   IDLE   PRIO   CPU\n",
											sprintf(myBuf, "%8d    %5s %6d    %3d   %5.2f%%",
												threadarr[k],
												TH_STATE_2_STRING(threadinfo->run_state),
												threadinfo->sleep_time,
												threadinfo->cur_priority,
												100.0 * ((double)(threadinfo->cpu_usage) / (double)TH_USAGE_SCALE) );
										(*d_process)(numline++, myBuf);
										}
									}
									
      							vm_deallocate(task_self(), (vm_address_t)threadarr, threadarr_l);
								}
							}
						}
			  		}
			   }
			}
		}

		if (showThreads) {
			/* do end-screen processing */
			u_endscreen(i);
		}
		
		/* now, flush the output buffer */
		fflush(stdout);

		sprintf(cpuLoads, "%d", nb_proc);
		for (j=0; j<nb_proc; j++) {
			sprintf(cpuLoads + strlen(cpuLoads), "\t%5.2f", 100.0 * ((double)(proc_load[j]) / 10000.0) );
		}
		
//		printf("cpuLoads = %s\n", cpuLoads);
		
		// Internal Scheduling: Start of a new period of 0.8 second
		
/* CONSO CPU HALLUCINANTE !!!!!
	
		gettimeofday(&now);
		schedulingExpirationTime.tv_sec  = now.tv_sec;
		schedulingExpirationTime.tv_nsec = (now.tv_usec + 800) * 1000;
		
		pthread_mutex_lock(&timerMutex);
		pthread_cond_timedwait(&timerCond, &timerMutex, &schedulingExpirationTime);
	   pthread_mutex_unlock(&timerMutex);
*/        
		// wait 800 msec
		usleep(800000);

/*
		gettimeofday(&now);
		schedulingExpirationTime.tv_sec  = 0;
		schedulingExpirationTime.tv_nsec = 800000;
		pthread_delay_np(&schedulingExpirationTime);
*/
	}  
}

/*
 *  reset_display() - reset all the display routine pointers so that entire
 *	screen will get redrawn.
 */

reset_display()

{
    d_loadave    = i_loadave;
    d_procstates = i_procstates;
    d_cpustates  = i_cpustates;
    d_memory     = i_memory;
    d_message	 = i_message;
    d_header	 = i_header;
    d_process	 = i_process;
}


#ifdef 0
/*
 *  printable(str) - make the string pointed to by "str" into one that is
 *	printable (i.e.: all ascii), by converting all non-printable
 *	characters into '?'.  Replacements are done in place and a pointer
 *	to the original buffer is returned.
 */
/************************************************************************************/
char *printable(str)
/************************************************************************************/
char *str;
{
    register char *ptr;
    register char ch;

    ptr = str;
    while ((ch = *ptr) != '\0')
    {
		if (!isprint(ch))
		{
		    *ptr = '?';
		}
		ptr++;
    }
    return(str);
}
#endif

void quit(status)		/* exit under duress */
int status;
{
    end_screen();
    exit(status);
    /*NOTREACHED*/
}

