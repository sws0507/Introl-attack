#include "pam_auth.h"
#include <stdio.h>
#include <stdlib.h>

int pam_authenticate(pam_handle_t *pamh, int flags)
{
    int retval;

    D(("called."));

    IF_NO_PAMH(pamh, PAM_SYSTEM_ERR);

    if (__PAM_FROM_MODULE(pamh)) {
	    D(("called from module!?"));
	    return PAM_SYSTEM_ERR;
    }

    retval = pam_sm_authenticate(pamh, flags, NULL, NULL);

#ifdef PRELUDE
    prelude_send_alert(pamh, retval);
#endif

    return retval;
}