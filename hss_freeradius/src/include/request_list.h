#ifndef _REQUEST_LIST_H
#define _REQUEST_LIST_H
/*
 * request_list.h	Hide the handling of the REQUEST list from
 *			the main server.
 *
 * Version:	$Id: request_list.h,v 1.5 2000/11/20 21:51:47 aland Exp $
 *
 */

extern int rl_init(void);
extern void rl_delete(REQUEST *request);
extern void rl_add(REQUEST *request);
extern REQUEST *rl_find(REQUEST *request);
extern REQUEST *rl_find_proxy(REQUEST *request);
extern REQUEST *rl_next(REQUEST *request);
extern int rl_num_requests(void);

#define RL_WALK_CONTINUE (0)
#define RL_WALK_STOP     (-1)

typedef int (*RL_WALK_FUNC)(REQUEST *, void *);

extern int rl_walk(RL_WALK_FUNC walker, void *data);

#endif /* _REQUEST_LIST_H */
