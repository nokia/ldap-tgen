
int tSelectInit ();
int tSelectRegisterSocket (int threadId, int sock);
int tSelectUnregisterSocket (int threadId, int sock);
int tSelectIsFdSet (int fd);
void tSelect (int key);

