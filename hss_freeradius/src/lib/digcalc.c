/*
 * digcalc.c
 *
 *	Procedures for the HTTP Digest Authentication
 * Adapted from RFC 2617 by EmA,21/08/2002
 *
 */

//#include <global.h>
#include <md5.h>

#include <string.h>
#include <stdio.h>
#include "digcalc.h"

/******************************************************************************/
static void CvtHex(
    IN HASH Bin,
    OUT HASHHEX Hex
    )
/******************************************************************************/
{
    unsigned short i;
    unsigned char j;

    for (i = 0; i < HASHLEN; i++) {
        j = (Bin[i] >> 4) & 0xf;
        if (j <= 9)
            Hex[i*2] = (j + '0');
         else
            Hex[i*2] = (j + 'a' - 10);
        j = Bin[i] & 0xf;
        if (j <= 9)
            Hex[i*2+1] = (j + '0');
         else
            Hex[i*2+1] = (j + 'a' - 10);
    }
    Hex[HASHHEXLEN] = '\0';
}

/******************************************************************************/
static void hex2bin( char* inHex, char *outBin, int outsize )
/******************************************************************************/
/*
	'0'=d(48) .... '9'=d(57)
	'a'=d(97) .... 'f'=d(102)
	'A'=d(65) .... 'F'=d(70)
*/
{
unsigned char i;
char	pF, pf;

    for (i = 0; i < outsize; i++) {
    	pF = inHex[2*i];
    	pf = inHex[2*i + 1];
    	
    	if ( (pF >= '0') && (pF <= '9') )
    		outBin[i] = (pF-'0') << 4;
    	else if ( (pF >= 'a') && (pF <= 'f') )
    		outBin[i] = (pF-'a'+10) << 4;
    	else if ( (pF >= 'A') && (pF <= 'F') )
    		outBin[i] = (pF-'A'+10) << 4;
    	else
    		outBin[i] = 0;
    	
    	if ( (pf >= '0') && (pf <= '9') )
    		outBin[i] += (pf-'0');
    	else if ( (pf >= 'a') && (pf <= 'f') )
    		outBin[i] += (pf-'a'+10);
    	else if ( (pf >= 'A') && (pf <= 'F') )
    		outBin[i] += (pf-'A'+10);
    	else
    		outBin[i] += 0;
    }
}

/******************************************************************************/
char * unquote_strdup(const char *str)
/******************************************************************************/
{
int				i, j;
char				*result;
int				len, res_len;

	if (!str)
		return NULL;
	
	len = strlen(str);

//	printf("unq(%s) = ", str);
	
	// skip space inhead of quoted string
	i = 0;
	while ( str[i] && isspace( (unsigned char *)str[i] ) )
		i++;

	if ( str[i] != '"' ) {
		// first char is not " : return input string unchanged
		if ( !(result = (char *)malloc( len + 1)) )
			return NULL;
		strncpy(result, str, len);
		result[len] = 0;
		return result;
	}
	
	// skip space intail of quoted string
	j = len - 1;
	while ( str[j] && isspace( (unsigned char *)str[j] ) )
		j--;

	if ( str[j] != '"' ) {
		// first char is not " : return input string unchanged
		if ( !(result = (char *)malloc( len + 1)) )
			return NULL;
		strncpy(result, str, len);
		result[len] = 0;
		return result;
	}
	
	res_len =  j - i - 1;

	if (res_len < 0) {
		// case str=" : return input string unchanged
		if ( !(result = (char *)malloc( len + 1)) )
			return NULL;
		strncpy(result, str, len);
		result[len] = 0;
		return result;
	}

	if ( !(result = (char *)malloc( res_len + 1)) )
		return NULL;
	if (res_len) strncpy(result, str + i + 1, res_len);	// no copy in case: str=""
	result[res_len] = 0;
	
//	printf("%s\n", result);
	
	return result;
}


/******************************************************************************/
/* calculate H(A1) as per spec */
void DigestCalcHA1(
    IN char * pszAlg,
    IN char * pszUserName,
    IN char * pszRealm,
    IN char * pszPassword,
    IN char * pszNonce,
    IN char * pszCNonce,
    OUT HASHHEX SessionKey
    )
/******************************************************************************/
{
MD5_CTX	Md5Ctx;
HASH		HA1;
char *	unqUserName	= unquote_strdup(pszUserName);
char *	unqRealm		= unquote_strdup(pszRealm);
char *	unqNonce		= unquote_strdup(pszNonce);
char *	unqCNonce	= unquote_strdup(pszCNonce);

   MD5Init(&Md5Ctx);
   MD5Update(&Md5Ctx, unqUserName, strlen(unqUserName));
   MD5Update(&Md5Ctx, ":", 1);
   MD5Update(&Md5Ctx, unqRealm, strlen(unqRealm));
   MD5Update(&Md5Ctx, ":", 1);
   MD5Update(&Md5Ctx, pszPassword, strlen(pszPassword));
   MD5Final(HA1, &Md5Ctx);
   CvtHex(HA1, SessionKey);

   if ( pszAlg && (strcmp(pszAlg, "md5-sess") == 0) ) {       // EmA,23/08/2002: debugged !!!

   	MD5Init(&Md5Ctx);
#ifdef _DIGEST_BINARY
      MD5Update(&Md5Ctx, HA1, HASHLEN);
#else
      MD5Update(&Md5Ctx, SessionKey, HASHHEXLEN);  	// EmA,21/08/2002: debugged !!!
#endif
      MD5Update(&Md5Ctx, ":", 1);
      MD5Update(&Md5Ctx, unqNonce, strlen(unqNonce));
      MD5Update(&Md5Ctx, ":", 1);
      MD5Update(&Md5Ctx, unqCNonce, strlen(unqCNonce));
      MD5Final(HA1, &Md5Ctx);
   	CvtHex(HA1, SessionKey);
	}
	
   free(unqUserName);
   free(unqRealm);
   free(unqNonce);
   free(unqCNonce);
}

/******************************************************************************/
/* calculate request-digest/response-digest as per HTTP Digest spec */
void DigestCalcResponse(
    IN HASHHEX HA1,           /* H(A1) */
    IN char * pszNonce,       /* nonce from server */
    IN char * pszNonceCount,  /* 8 hex digits */
    IN char * pszCNonce,      /* client nonce */
    IN char * pszQop,         /* qop-value: "", "auth", "auth-int" */
    IN char * pszMethod,      /* method from the request */
    IN char * pszDigestUri,   /* requested URL */
    IN HASHHEX HEntity,       /* H(entity body) if qop="auth-int" */
    OUT HASHHEX Response      /* request-digest or response-digest */
    )
/******************************************************************************/
{
MD5_CTX	Md5Ctx;
HASH		HA2;
HASH		RespHash;
HASHHEX	HA2Hex;
char *	unqNonce			= unquote_strdup(pszNonce);
char *	unqCNonce		= unquote_strdup(pszCNonce);
char *	unqQop			= unquote_strdup(pszQop);
char		buf16[HASHLEN];
char		buf4[4];

   // calculate H(A2)
   MD5Init(&Md5Ctx);
   MD5Update(&Md5Ctx, pszMethod, strlen(pszMethod));
   MD5Update(&Md5Ctx, ":", 1);
   MD5Update(&Md5Ctx, pszDigestUri, strlen(pszDigestUri));
   if (pszQop && (strcmp(pszQop, "auth-int") == 0) ) {        // EmA,23/08/2002: debugged !!!
      MD5Update(&Md5Ctx, ":", 1);
#ifdef _DIGEST_BINARY
		hex2bin(HEntity, buf16, HASHLEN);
      MD5Update(&Md5Ctx, buf16, HASHLEN);
#else
      MD5Update(&Md5Ctx, HEntity, HASHHEXLEN);
#endif
   }
   MD5Final(HA2, &Md5Ctx);
   CvtHex(HA2, HA2Hex);

   // calculate response
   MD5Init(&Md5Ctx);
#ifdef _DIGEST_BINARY
	hex2bin(HA1, buf16, HASHLEN);
   MD5Update(&Md5Ctx, buf16, HASHLEN);
#else
   MD5Update(&Md5Ctx, HA1, HASHHEXLEN);
#endif
   MD5Update(&Md5Ctx, ":", 1);
   MD5Update(&Md5Ctx, unqNonce, strlen(unqNonce));
   MD5Update(&Md5Ctx, ":", 1);

   if (pszQop && *pszQop) { 	       								// EmA,23/08/2002: debugged !!!
#ifdef _DIGEST_BINARY
		hex2bin(pszNonceCount, buf4, 4);
		MD5Update(&Md5Ctx, buf4, 4);
#else
		MD5Update(&Md5Ctx, pszNonceCount, strlen(pszNonceCount));
#endif
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, unqCNonce, strlen(unqCNonce));
		MD5Update(&Md5Ctx, ":", 1);
		MD5Update(&Md5Ctx, unqQop, strlen(unqQop));
		MD5Update(&Md5Ctx, ":", 1);
   }
   
#ifdef _DIGEST_BINARY
   MD5Update(&Md5Ctx, HA2, HASHLEN);
#else
   MD5Update(&Md5Ctx, HA2Hex, HASHHEXLEN);
#endif
   MD5Final(RespHash, &Md5Ctx);
   CvtHex(RespHash, Response);

   free(unqNonce);
   free(unqCNonce);
   free(unqQop);
}

