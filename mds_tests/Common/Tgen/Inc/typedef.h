#ifndef TYPEDEF_H
#define TYPEDEF_H

#ifdef FALSE
#undef FALSE
#endif

#ifdef TRUE
#undef TRUE
#endif

typedef enum BOOL {
    FALSE,
    TRUE
}  BOOL;

typedef enum SQL {
    SQL_OK
}  SQL;

#endif
