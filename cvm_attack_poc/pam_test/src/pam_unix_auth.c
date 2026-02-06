#include "pam_unix_auth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

# define INT_MAX 2147483647
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	unsigned long long ctrl;
	int retval, *ret_data = NULL;
	const char *name;
	const char *p;

	D(("called."));

	ctrl = _set_ctrl(pamh, flags, NULL, NULL, NULL, argc, argv);

	/* Get a few bytes so we can pass our return value to
	   pam_sm_setcred() and pam_sm_acct_mgmt(). */
	ret_data = malloc(sizeof(int));
	if (!ret_data) {
		D(("cannot malloc ret_data"));
		//pam_syslog(pamh, LOG_CRIT, "pam_unix_auth: cannot allocate ret_data");
		return PAM_BUF_ERR;
	}

	/* get the user'name' */

	retval = pam_get_user(pamh, &name, NULL);
	if (retval == PAM_SUCCESS) {
		/*
		 * Various libraries at various times have had bugs related to
		 * '+' or '-' as the first character of a user name. Don't
		 * allow these characters here.
		 */
		if (name[0] == '-' || name[0] == '+') {
			//pam_syslog(pamh, LOG_NOTICE, "bad username [%s]", name);
			retval = PAM_USER_UNKNOWN;
			AUTH_RETURN;
		}
		//if (on(UNIX_DEBUG, ctrl))
			//pam_syslog(pamh, LOG_DEBUG, "username [%s] obtained", name);
	} 
	else {
		if (retval == PAM_CONV_AGAIN) {
			D(("pam_get_user/conv() function is not ready yet"));
			/* it is safe to resume this function so we translate this
			 * retval to the value that indicates we're happy to resume.
			 */
			retval = PAM_INCOMPLETE;
		} 
		else if (on(UNIX_DEBUG, ctrl)) {
			//pam_syslog(pamh, LOG_DEBUG, "could not obtain username");
		}
		AUTH_RETURN;
	}

	/* if this user does not have a password... */

	if (_unix_blankpasswd()) {
		//pam_syslog(pamh, LOG_DEBUG, "user [%s] has blank password; authenticated without it", name);
		name = NULL;
		retval = PAM_SUCCESS;
		AUTH_RETURN;
	}
	/* get this user's authentication token */

	retval = pam_get_authtok(pamh, &p);
	if (retval != PAM_SUCCESS) {
		if (retval != PAM_CONV_AGAIN) {
			//pam_syslog(pamh, LOG_CRIT,"auth could not identify password for [%s]", name);
		} else {
			D(("conversation function is not ready yet"));
			/*
			 * it is safe to resume this function so we translate this
			 * retval to the value that indicates we're happy to resume.
			 */
			retval = PAM_INCOMPLETE;
		}
		name = NULL;
		AUTH_RETURN;
	}
	D(("user=%s, password=[%s]", name, p));

	/* verify the password of this user */
	retval = _unix_verify_password(name, p);
	name = p = NULL;

	AUTH_RETURN;
}

/*
 * _unix_blankpasswd() is a quick check for a blank password
 *
 * returns TRUE if user does not have a password
 * - to avoid prompting for one in such cases (CG)
 */

int _unix_blankpasswd()
{
	return 0;
}


/*
 * set the control flags for the UNIX module.
 */

unsigned long long _set_ctrl(pam_handle_t *pamh, int flags, int *remember,
			     int *rounds, int *pass_min_len, int argc,
			     const char **argv)
{
	unsigned long long ctrl;
	char *val;
	int j;

	D(("called."));

	ctrl = UNIX_DEFAULTS;	/* the default selection of options */

	/* set some flags manually */

	if (getuid() == 0 && !(flags & PAM_CHANGE_EXPIRED_AUTHTOK)) {
		D(("IAMROOT"));
		set(UNIX__IAMROOT, ctrl);
	}
	if (flags & PAM_UPDATE_AUTHTOK) {
		D(("UPDATE_AUTHTOK"));
		set(UNIX__UPDATE, ctrl);
	}
	if (flags & PAM_PRELIM_CHECK) {
		D(("PRELIM_CHECK"));
		set(UNIX__PRELIM, ctrl);
	}
	if (flags & PAM_SILENT) {
		D(("SILENT"));
		set(UNIX__QUIET, ctrl);
	}

	/* preset encryption method with value from /etc/login.defs */
	val = "sha256";
	if (val) {
		for (j = 0; j < UNIX_CTRLS_; ++j) {
	    	if (unix_args[j].token && unix_args[j].is_hash_algo
			&& !strncasecmp(val, unix_args[j].token, strlen(unix_args[j].token))) {
	      		break;
	    	}
	  	}
	  	if (j >= UNIX_CTRLS_) {
	    	//pam_syslog(pamh, LOG_WARNING, "unrecognized ENCRYPT_METHOD value [%s]", val);
	  	} else {
			ctrl &= unix_args[j].mask;	/* for turning things off */
	    	ctrl |= unix_args[j].flag;	/* for turning things on  */
	  	}
	  	free (val);
	}

	/* now parse the arguments to this module */

	for (; argc-- > 0; ++argv) {
		const char *str = NULL;

		D(("pam_unix arg: %s", *argv));

		for (j = 0; j < UNIX_CTRLS_; ++j) {
			if (unix_args[j].token
			    && (str = pam_str_skip_prefix_len(*argv,
							      unix_args[j].token,
							      strlen(unix_args[j].token))) != NULL) {
				break;
			}
		}

		if (str == NULL) {
			//pam_syslog(pamh, LOG_ERR, "unrecognized option [%s]", *argv);
		} else {
			/* special cases */
			if (j == UNIX_REMEMBER_PASSWD) {
				if (remember == NULL) {
					//pam_syslog(pamh, LOG_ERR, "option remember not allowed for this module type");
					continue;
				}
				if (_unix_strtoi(str, -1, remember)) {
					//pam_syslog(pamh, LOG_ERR, "option remember invalid [%s]", str);
					continue;
				}
				if (*remember > 400)
					*remember = 400;
			} else if (j == UNIX_MIN_PASS_LEN) {
				if (pass_min_len == NULL) {
					//pam_syslog(pamh, LOG_ERR, "option minlen not allowed for this module type");
					continue;
				}
				if (_unix_strtoi(str, 0, pass_min_len)) {
					//pam_syslog(pamh, LOG_ERR, "option minlen invalid [%s]", str);
					continue;
				}
			} else if (j == UNIX_ALGO_ROUNDS) {
				if (rounds == NULL) {
					//pam_syslog(pamh, LOG_ERR, "option rounds not allowed for this module type");
					continue;
				}
				if (_unix_strtoi(str, 0, rounds)) {
					//pam_syslog(pamh, LOG_ERR, "option rounds invalid [%s]", str);
					continue;
				}
			}

			ctrl &= unix_args[j].mask;	/* for turning things off */
			ctrl |= unix_args[j].flag;	/* for turning things on  */
		}
	}

	if (UNIX_DES_CRYPT(ctrl)
	    && pass_min_len && *pass_min_len > 8)
	  {
	    //pam_syslog (pamh, LOG_NOTICE, "Password minlen reset to 8 characters");
	    *pass_min_len = 8;
	  }

	if (flags & PAM_DISALLOW_NULL_AUTHTOK) {
		D(("DISALLOW_NULL_AUTHTOK"));
		set(UNIX__NONULL, ctrl);
	}

	/* Read number of rounds for sha256, sha512 and yescrypt */
	if (off(UNIX_ALGO_ROUNDS, ctrl) && rounds != NULL) {
		const char *key = NULL;
		if (on(UNIX_YESCRYPT_PASS, ctrl))
			key = "YESCRYPT_COST_FACTOR";
		else if (on(UNIX_SHA256_PASS, ctrl) || on(UNIX_SHA512_PASS, ctrl))
			key = "SHA_CRYPT_MAX_ROUNDS";
		else
			key = NULL;

		if (key != NULL) {
			val = "";
			if (val) {
				if (_unix_strtoi(val, 0, rounds)){
					//pam_syslog(pamh, LOG_ERR, "option %s invalid [%s]", key, val);
				}
				else
					set(UNIX_ALGO_ROUNDS, ctrl);
				free (val);
			}
		}
	}

	/* Set default rounds for blowfish, gost-yescrypt and yescrypt */
	if (off(UNIX_ALGO_ROUNDS, ctrl) && rounds != NULL) {
		if (on(UNIX_BLOWFISH_PASS, ctrl) ||
		    on(UNIX_GOST_YESCRYPT_PASS, ctrl) ||
		    on(UNIX_YESCRYPT_PASS, ctrl)) {
			*rounds = 5;
			set(UNIX_ALGO_ROUNDS, ctrl);
		}
	}

	/* Enforce sane "rounds" values */
	if (on(UNIX_ALGO_ROUNDS, ctrl)) {
		if (on(UNIX_GOST_YESCRYPT_PASS, ctrl) ||
		    on(UNIX_YESCRYPT_PASS, ctrl)) {
			if (*rounds < 3)
				*rounds = 3;
			else if (*rounds > 11)
				*rounds = 11;
		} else if (on(UNIX_BLOWFISH_PASS, ctrl)) {
			if (*rounds < 4)
				*rounds = 4;
			else if (*rounds > 31)
				*rounds = 31;
		} else if (on(UNIX_SHA256_PASS, ctrl) || on(UNIX_SHA512_PASS, ctrl)) {
			if ((*rounds < 1000) || (*rounds == INT_MAX)) {
				/* don't care about bogus values */
				*rounds = 0;
				unset(UNIX_ALGO_ROUNDS, ctrl);
			} else if (*rounds >= 10000000) {
				*rounds = 9999999;
			}
		}
	}

	/* auditing is a more sensitive version of debug */

	if (on(UNIX_AUDIT, ctrl)) {
		set(UNIX_DEBUG, ctrl);
	}
	/* return the set of flags */

	D(("done."));
	return ctrl;
}

static int _unix_strtoi(const char *str, int minval, int *result)
{
	char *ep;
	long value = strtol(str, &ep, 10);
	if (value < minval || value > INT_MAX || str == ep || *ep != '\0') {
		*result = minval;
		return -1;
	}
	*result = (int)value;
	return 0;
}

/*
 * This function is the 'preferred method to obtain the username'.
 */

int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt)
{
    const char *use_prompt;
    int retval;

    D(("called."));

    IF_NO_PAMH(pamh, PAM_SYSTEM_ERR);

    if (user == NULL) {
        /* ensure that the module has supplied a destination */
		return PAM_SYSTEM_ERR;
    } 
	else{
		*user = NULL;
	}

    if (pamh->user) {    /* have one so return it */
		*user = pamh->user;
		return PAM_SUCCESS;
    }

    /* will need a prompt */
    if (prompt != NULL)
      use_prompt = prompt;
    else if (pamh->prompt != NULL)
      use_prompt = pamh->prompt;
    else
      use_prompt = _("login:");

    switch (retval) {
	case PAM_SUCCESS:
	case PAM_BUF_ERR:
	case PAM_CONV_AGAIN:
	case PAM_CONV_ERR:
	    break;
	default:
	    retval = PAM_CONV_ERR;
    }

    D(("completed"));
    return retval;        /* pass on any error from conversation */
}

int pam_get_authtok(pam_handle_t *pamh, const char **authtok)
{
	char *pwd = pamh->authtok;
	if(pwd == NULL) {
		//pam_syslog(pamh, LOG_ERR, "authtok is NULL");
		return PAM_AUTHTOK_ERR;
	}
	else if(pwd[0] == '\0') {
		//pam_syslog(pamh, LOG_ERR, "authtok is empty");
		return PAM_AUTHTOK_ERR;
	}
	else{
		*authtok = pwd;
		//pam_syslog(pamh, LOG_DEBUG, "authtok is set to %s", *authtok);
		return PAM_SUCCESS;
	}
}

int _unix_verify_password(const char *name, const char *p){
	if(name == NULL || p == NULL) {
		return PAM_AUTH_ERR;
	}
	// Simulate password verification logic
	// In a real implementation, this would check against a password database
	else if(p[0] == '\0') {
		return PAM_AUTH_ERR;
	}
	else if(strcmp(name, "root") == 0) {
		if(strcmp(p, "root") == 0) {
			// Simulate successful authentication for root
			return PAM_SUCCESS;
		}
		else{
			// Simulate failed authentication for root
			return PAM_AUTH_ERR;
		}
	} 
	else if(strcmp(p, "sws123") == 0) {
		if(strcmp(p, "sws123") == 0) {
			// Simulate successful authentication for root
			return PAM_SUCCESS;
		}
		else{
			// Simulate failed authentication for root
			return PAM_AUTH_ERR;
		}
	} 
	else {
		// Simulate failed authentication
		return PAM_AUTH_ERR;
	}
}
