#ifndef AUTH_H
#define AUTH_H

#include <pwd.h>
#include <sys/types.h>

typedef long   __darwin_time_t;  

#define EVP_PKEY	void
#define MAX_PASSWORD_LEN	1024
#define	PERMIT_YES		3

typedef struct {
    int     permit_root_login;      /* PERMIT_*, see above */
    int     permit_empty_passwd;	/* If false, do not permit empty passwords. */
    int     password_authentication;	/* If true, permit password authentication. */

} ServerOptions;

extern ServerOptions options;

struct ssh {
	/* Client/Server authentication context */
	void *authctxt;
};

struct Authctxt {
    int valid;		/* user exists and is allowed to login */
	struct passwd   *pw;		/* set if 'valid' */
};

typedef struct Authctxt Authctxt;

int auth_password(struct ssh *ssh, const char *password);
int sys_auth_passwd(struct ssh *ssh, const char *password);
char *shadow_pw(struct passwd *pw);
char *xcrypt(const char *password, const char *salt);

#endif /* AUTH_H */