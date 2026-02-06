#include <stdio.h>
#include <stdlib.h>
#include "pam_auth.h"

void set_pamh(pam_handle_t *pamh, const char *password) {
    if (pamh == NULL) {
        printf("pam_handle_t is NULL\n");
        return;
    }
    pamh->user = "sws123"; // Set a default username
    pamh->authtok = strdup(password);
    if (pamh->authtok == NULL) {
        printf("Failed to set authtok\n");
    }
}

int main(int argc, char *argv[]){
    int retval;
    if (argc < 2) {
        printf("Usage: %s <password>\n", argv[0]);
        return 1;
    }
    else{
        printf("Password is %s\n", argv[1]);
    }
    pam_handle_t *pamh = malloc(sizeof(pam_handle_t));
    set_pamh(pamh, argv[1]);
    retval = pam_authenticate(pamh, PAM_SILENT);
    if(retval){
        printf("Authentication failed with error code: %d\n", retval);
    } else {
        printf("Authentication succeeded!\n");
    }
    return 0;
}