#include "pam_unix_auth.h"
/*
 * XXX - Take care with this. It could confuse the logic of a trailing
 *       else
 */

#define IF_NO_PAMH(pamh,ERR)                      \
do {                                              \
    if ((pamh) == NULL) {                         \
        return ERR;                               \
    }                                             \
} while(0)

#define __PAM_FROM_MODULE(pamh)  ((pamh)->caller_is == _PAM_CALLED_FROM_MODULE)

int pam_authenticate(pam_handle_t *pamh, int flags);
