#include <stdio.h>
#include <stdlib.h>
#include "monitor.h"

ServerOptions options = {
    .permit_root_login = 0,
    .permit_empty_passwd = 0,
    .password_authentication = 0,
};

void set_options(int permit_root_login, int permit_empty_passwd, int password_authentication){
    options.permit_root_login = permit_root_login;
    options.permit_empty_passwd = permit_empty_passwd;
    options.password_authentication = password_authentication;
}

struct ssh *create_ssh_instance(char *name, char *passwd){
    struct ssh *ssh = malloc(sizeof(ssh));
    if (!ssh) return NULL;

    struct Authctxt *authctxt = malloc(sizeof(struct Authctxt));
    if (!authctxt) {
        free(ssh);
        return NULL;
    }
    
    struct passwd *pw = malloc(sizeof(struct passwd));
    pw->pw_name = name;
    pw->pw_passwd = passwd;
    pw->pw_uid = 1;
    
    authctxt->valid = 1;  
    authctxt->pw = pw ? pw : NULL;
    
    ssh->authctxt = authctxt;

    set_options(1, 0, 1);
    return ssh;
}

struct sshbuf *get_sshbuffer(char *data){
    struct sshbuf *sshbuffer = malloc(sizeof(struct sshbuf));
    sshbuffer->data = data;
    return sshbuffer;
}

int main(int argc, char *argv[]){
    struct ssh *ssh = create_ssh_instance(USERNAME, PASSWORD);
    int sock = 0;
    int result;
    if(!argc){
        printf("Error argc!\n");
        return 0;
    }
    printf("Password is %s\n", argv[1]);
    struct sshbuf *sshbuffer = get_sshbuffer(argv[1]);
    result = mm_answer_authpassword(ssh, sock, sshbuffer);
    if(result){
        printf("Authentication succeeded!\n");
    }
    else{
        printf("Authentication failed!\n");
    }
    return 0;
}