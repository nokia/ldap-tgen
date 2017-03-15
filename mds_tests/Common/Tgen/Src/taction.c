
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

//#include "tconf.h"
//#include "texec.h"
#include "taction.h"


//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// DATA PART
//
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

tCmdRes*    tAction_mallocCmdRes( ) {
    
    tCmdRes     *l_cmd_res;     
    
    l_cmd_res =(tCmdRes *)malloc( sizeof(tCmdRes) );
    l_cmd_res->base = NULL;
    l_cmd_res->filter = NULL;
    
    return l_cmd_res;
}    


void        tAction_freeCmdRes( tCmdRes **cmd_res) {
    
    if( (*cmd_res) ) {
        if( (*cmd_res)->base) {
            free((*cmd_res)->base); 
        }
        if( (*cmd_res)->filter) {
            free((*cmd_res)->filter); 
        }
        free((*cmd_res));
		(*cmd_res) = NULL;
    }        
    
}    

//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// INIT PART
//
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

/******************************************************************************/
//
/******************************************************************************/ 
int tActionInit() {
    return 0;   
}    
