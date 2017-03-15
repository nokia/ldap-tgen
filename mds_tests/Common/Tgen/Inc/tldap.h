#ifndef tLdap_h
#define tLdap_h

#include "taction.h"
#include "ldap.h"
#include "tinit.h"
#include "texec.h"

extern struct timeval	    ldaptv;

typedef struct tLdapReqCtx {
	int             attrs_nb;
	int				cmds_nb;
	char            **attrs_type;
	char			**cmds_type;
	char            **attrs_value;
	char			**cmds_value;    
	int             *attrs_ope;
	int				*cmds_ope;
//	LDAPControl 	*c;
	LDAPControl 	**ctrls;
// following used only in asynchronous mode:
	LDAPMessage 	*res;
	int				rc;
	struct timeval	time;
} tLdapReqCtx;

typedef struct tLdapList {
	struct tLdapList	*next;
	struct tLdapList 	*last;
	int					msgid;
	tSleep 				*sleepCtx;
} tLdapList;

typedef struct  tLdapLd {
    LDAP *				ld;
	tLdapList *			ldReq;
	tLdapList *			ldResp;
	pthread_mutex_t* 	mutex;
	pthread_cond_t*		cond;
	char *          	serverHost;
	int             	serverPort;
	int	 				KeyThead;
	int					rebind;
} tLdapLd;

extern tLdapLd*		tLdapLdTab;


int tLdapInit();
int tLdapReinit();
int tLdapClose();

//private calls:
int     simpleBindRequest(LDAP** ld, char dolock, LDAPControl **sctrl);
int     unbindRequest(LDAP **, char dolock);

//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
//LDAP Interface for texec
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

int     tLdap_BindRequest (
//                        LDAP** ld, 
                        int* realBind,
						LDAPControl **sctrl);

int     tLdap_UnbindRequest (
//                        LDAP** ld, 
                        int* realBind);

int     tLdap_abandon(
                        LDAP**   ld,
						char	 dolock
                     );

int     tLdap_Rebind(
                        LDAP**   ld,
						char	 dolock
                     );

void tLdap_freeCtx( tLdapReqCtx *reqCtx );

int tLdap_SearchResult(
	                    LDAP_CONST char *base,
	                    int             scope,
	                    LDAP_CONST char *filter,
	                    char            *attr_list,
	                    char            *cmd_list,
	                    tCmdRes         **cmd_res,
                        long            id,
                        int             waitForRc,
						tLdapReqCtx		*reqCtx
	                    );

int     tLdap_SearchRequest(
//	                    LDAP            *ld,   
	                    LDAP_CONST char *base,
	                    int             scope,
	                    LDAP_CONST char *filter,
	                    char            *attr_list,
	                    char            *cmd_list,
	                    tCmdRes         **cmd_res,
                        long            id,
                        LDAPControl		**sctrl,
                        int             waitForRc,
                        int				unLimitSize
	                    );

int tLdap_SearchRequest_async(
	                    LDAP_CONST char *base,
	                    int             scope,
	                    LDAP_CONST char *filter,
	                    char            *attr_list,
	                    char            *cmd_list,
//	                    tCmdRes         **cmd_res,
//                        long            id,
                        LDAPControl		**sctrl,
//                        int             waitForRc,
						tSleep			*ctx,
                        int				unLimitSize
	                    );

int     tLdap_ModifyRequest(
//	                    LDAP            *ld,
	                    LDAP_CONST char *dn,
	                    char            *attr_list,
						LDAPControl **sctrl
	                    );

int     tLdap_AddRequest(
//	                    LDAP            *ld,
	                    LDAP_CONST char *dn,
	                    char            *attr_list,
						LDAPControl **sctrl
	                    );

int     tLdap_DeleteRequest(
//	                    LDAP            *ld,
	                    LDAP_CONST char *dn,
						LDAPControl **sctrl
	                    );



#define tLdap_getLdId(TID2)      \
                ( TID2<WORKTHR ? TID2 : (TID2-WORKTHR)%tcLdapBindNb )
                
#define tLdap_getLd(TID2)      \
                ( tLdapLdTab[ tLdap_getLdId(TID2) ].ld )
                
#define tLdap_getLdReqList(TID2)      \
                ( tLdapLdTab[ tLdap_getLdId(TID2) ].ldReq )

#define tLdap_getLdRespList(TID2)      \
                ( tLdapLdTab[ tLdap_getLdId(TID2) ].ldResp )

#define tLdap_getLdMutex(TID2)      \
                ( tLdapLdTab[ tLdap_getLdId(TID2) ].mutex )

#define tLdap_getLdCond(TID2)      \
                ( tLdapLdTab[ tLdap_getLdId(TID2) ].cond )



int insert_Request(int ldId, int msgid, tSleep *ctx);
tSleep *getAndRemove_firstResponse(int ldId);
tSleep *getAndMove_RequestToResponse(int ldId, int msgid, LDAPMessage *res, int rc, long *tm);
void treatError_Ld(int ldId, int myerrno);
int getAndRemove_Request(int ldId, tSleep *sleepCtx);
int result2error( LDAP *ld, LDAPMessage *r, int freeit );


#endif	                    
