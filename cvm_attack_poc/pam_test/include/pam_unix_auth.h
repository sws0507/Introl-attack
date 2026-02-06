/* This is a blind structure; users aren't allowed to see inside a
 * pam_handle_t, so we don't define struct pam_handle here.  This is
 * defined in a file private to the PAM library.  (i.e., it's private
 * to PAM service modules, too!)  */
#include <stddef.h>
#define PAM_POC 1

typedef struct pam_handle pam_handle_t;

struct pam_handle {
    char *authtok;
    unsigned caller_is;
    //struct pam_conv *pam_conversation;
    char *oldauthtok;
    char *prompt;                /* for use by pam_get_user() */
    char *service_name;
    char *user;
    char *rhost;
    char *ruser;
    char *tty;
    char *xdisplay;
    char *authtok_type;          /* PAM_AUTHTOK_TYPE */
    //struct pam_data *data;
    //struct pam_environ *env;      /* structure to maintain environment list */
    //struct _pam_fail_delay fail_delay;   /* helper function for easy delays */
    //struct pam_xauth_data xauth;        /* auth info for X display */
    //struct service handlers;
    //struct _pam_former_state former;  /* library state - support for event driven applications */
    const char *mod_name;	/* Name of the module currently executed */
    int mod_argc;               /* Number of module arguments */
    char **mod_argv;            /* module arguments */
    int choice;			/* Which function we call from the module */

#ifdef HAVE_LIBAUDIT
    int audit_state;             /* keep track of reported audit messages */
#endif
    int authtok_verified;
    char *confdir;
};

#define D(x)                             do { } while (0)

/*
 * macro to determine if a given flag is on
 */

#define on(x,ctrl)  (unix_args[x].flag & (ctrl))

/*
 * macro to determine that a given flag is NOT on
 */

#define off(x,ctrl) (!on(x,ctrl))

/*
 * macro to turn on/off a ctrl flag manually
 */

#define set(x,ctrl)   ((ctrl) = ((ctrl)&unix_args[x].mask)|unix_args[x].flag)
#define unset(x,ctrl) ((ctrl) &= ~(unix_args[x].flag))

/* the generic mask */

#define _ALL_ON_  (~0ULL)

/* ---------------------- The Linux-PAM flags -------------------- */
/*
 * here is the string to inform the user that the new passwords they
 * typed were not the same.
 */

/* type definition for the control options */

typedef struct {
	const char *token;
	unsigned long long mask;	/* shall assume 64 bits of flags */
	unsigned long long flag;
        unsigned int is_hash_algo;
} UNIX_Ctrls;

/* Authentication service should not generate any messages */
#define PAM_SILENT			0x8000U

/* Note: these flags are used by pam_authenticate{,_secondary}() */

/* The authentication service should return PAM_AUTH_ERROR if the
 * user has a null authentication token */
#define PAM_DISALLOW_NULL_AUTHTOK	0x0001U

/* Note: these flags are used for pam_setcred() */

/* Set user credentials for an authentication service */
#define PAM_ESTABLISH_CRED              0x0002U

/* Delete user credentials associated with an authentication service */
#define PAM_DELETE_CRED                 0x0004U

/* Reinitialize user credentials */
#define PAM_REINITIALIZE_CRED           0x0008U

/* Extend lifetime of user credentials */
#define PAM_REFRESH_CRED                0x0010U

/* Note: these flags are used by pam_chauthtok */

/* The password service should only update those passwords that have
 * aged.  If this flag is not passed, the password service should
 * update all passwords. */
#define PAM_CHANGE_EXPIRED_AUTHTOK	0x0020U

/* The following two flags are for use across the Linux-PAM/module
 * interface only. The Application is not permitted to use these
 * tokens.
 *
 * The password service should only perform preliminary checks.  No
 * passwords should be updated. */
#define PAM_PRELIM_CHECK		0x4000

/* The password service should update passwords Note: PAM_PRELIM_CHECK
 * and PAM_UPDATE_AUTHTOK cannot both be set simultaneously! */
#define PAM_UPDATE_AUTHTOK		0x2000

/* ----------------- The Linux-PAM return values ------------------ */

#define PAM_SUCCESS 0		/* Successful function return */
#define PAM_OPEN_ERR 1		/* dlopen() failure when dynamically */
				/* loading a service module */
#define PAM_SYMBOL_ERR 2	/* Symbol not found */
#define PAM_SERVICE_ERR 3	/* Error in service module */
#define PAM_SYSTEM_ERR 4	/* System error */
#define PAM_BUF_ERR 5		/* Memory buffer error */
#define PAM_PERM_DENIED 6	/* Permission denied */
#define PAM_AUTH_ERR 7		/* Authentication failure */
#define PAM_CRED_INSUFFICIENT 8	/* Can not access authentication data */
				/* due to insufficient credentials */
#define PAM_AUTHINFO_UNAVAIL 9	/* Underlying authentication service */
				/* can not retrieve authentication */
				/* information  */
#define PAM_USER_UNKNOWN 10	/* User not known to the underlying */
				/* authentication module */
#define PAM_MAXTRIES 11		/* An authentication service has */
				/* maintained a retry count which has */
				/* been reached.  No further retries */
				/* should be attempted */
#define PAM_NEW_AUTHTOK_REQD 12	/* New authentication token required. */
				/* This is normally returned if the */
				/* machine security policies require */
				/* that the password should be changed */
				/* because the password is NULL or it */
				/* has aged */
#define PAM_ACCT_EXPIRED 13	/* User account has expired */
#define PAM_SESSION_ERR 14	/* Can not make/remove an entry for */
				/* the specified session */
#define PAM_CRED_UNAVAIL 15	/* Underlying authentication service */
				/* can not retrieve user credentials */
                                /* unavailable */
#define PAM_CRED_EXPIRED 16	/* User credentials expired */
#define PAM_CRED_ERR 17		/* Failure setting user credentials */
#define PAM_NO_MODULE_DATA 18	/* No module specific data is present */
#define PAM_CONV_ERR 19		/* Conversation error */
#define PAM_AUTHTOK_ERR 20	/* Authentication token manipulation error */
#define PAM_AUTHTOK_RECOVERY_ERR 21 /* Authentication information */
				    /* cannot be recovered */
#define PAM_AUTHTOK_LOCK_BUSY 22   /* Authentication token lock busy */
#define PAM_AUTHTOK_DISABLE_AGING 23 /* Authentication token aging disabled */
#define PAM_TRY_AGAIN 24	/* Preliminary check by password service */
#define PAM_IGNORE 25		/* Ignore underlying account module */
				/* regardless of whether the control */
				/* flag is required, optional, or sufficient */
#define PAM_ABORT 26            /* Critical error (?module fail now request) */
#define PAM_AUTHTOK_EXPIRED  27 /* user's authentication token has expired */
#define PAM_MODULE_UNKNOWN   28 /* module is not known */

#define PAM_BAD_ITEM         29 /* Bad item passed to pam_*_item() */
#define PAM_CONV_AGAIN       30 /* conversation function is event driven and data is not available yet */
#define PAM_INCOMPLETE       31 /* please call this function again to
                   complete authentication stack. Before
				   calling again, verify that conversation
				   is completed */

/*
 * Add new #define's here - take care to also extend the libpam code:
 * pam_strerror() and "libpam/pam_tokens.h" .
 */

#define _PAM_RETURN_VALUES 32   /* this is the number of return values */

/* end of macro definitions definitions for the control flags */

/* ****************************************************************** *
 * ctrl flags proper..
 */

/*
 * here are the various options recognized by the unix module. They
 * are enumerated here and then defined below. Internal arguments are
 * given NULL tokens.
 */

#define UNIX__OLD_PASSWD          0	/* internal */
#define UNIX__VERIFY_PASSWD       1	/* internal */
#define UNIX__IAMROOT             2	/* internal */

#define UNIX_AUDIT                3	/* print more things than debug.. some information may be sensitive */
#define UNIX_USE_FIRST_PASS       4
#define UNIX_TRY_FIRST_PASS       5
#define UNIX_AUTHTOK_TYPE         6	/* TYPE for pam_get_authtok() */

#define UNIX__PRELIM              7	/* internal */
#define UNIX__UPDATE              8	/* internal */
#define UNIX__NONULL              9	/* internal */
#define UNIX__QUIET              10	/* internal */
#define UNIX_USE_AUTHTOK         11	/* insist on reading PAM_AUTHTOK */
#define UNIX_SHADOW              12	/* signal shadow on */
#define UNIX_MD5_PASS            13	/* force the use of MD5 passwords */
#define UNIX__NULLOK             14	/* Null token ok */
#define UNIX_DEBUG               15	/* send more info to syslog(3) */
#define UNIX_NODELAY             16	/* admin does not want a fail-delay */
#define UNIX_NIS                 17	/* wish to use NIS for pwd */
#define UNIX_BIGCRYPT            18	/* use DEC-C2 crypt()^x function */
#define UNIX_LIKE_AUTH           19	/* need to auth for setcred to work */
#define UNIX_REMEMBER_PASSWD     20	/* Remember N previous passwords */
#define UNIX_NOREAP              21     /* don't reap child process */
#define UNIX_BROKEN_SHADOW       22     /* ignore errors reading password aging * information during acct management */
#define UNIX_SHA256_PASS         23	/* new password hashes will use SHA256 */
#define UNIX_SHA512_PASS         24	/* new password hashes will use SHA512 */
#define UNIX_ALGO_ROUNDS         25	/* optional number of rounds for new password hash algorithms */
#define UNIX_BLOWFISH_PASS       26	/* new password hashes will use blowfish */
#define UNIX_MIN_PASS_LEN        27	/* min length for password */
#define UNIX_QUIET		 28	/* Don't print informational messages */
#define UNIX_NO_PASS_EXPIRY      29     /* Don't check for password expiration if not used for authentication */
#define UNIX_DES                 30     /* DES, default */
#define UNIX_GOST_YESCRYPT_PASS  31     /* new password hashes will use gost-yescrypt */
#define UNIX_YESCRYPT_PASS       32     /* new password hashes will use yescrypt */
#define UNIX_NULLRESETOK         33     /* allow empty password if password reset is enforced */
/* -------------- */
#define UNIX_CTRLS_              34	/* number of ctrl arguments defined */

#define UNIX_DES_CRYPT(ctrl)	(off(UNIX_MD5_PASS,ctrl)&&off(UNIX_BIGCRYPT,ctrl)&&off(UNIX_SHA256_PASS,ctrl)&&off(UNIX_SHA512_PASS,ctrl)&&off(UNIX_BLOWFISH_PASS,ctrl)&&off(UNIX_GOST_YESCRYPT_PASS,ctrl)&&off(UNIX_YESCRYPT_PASS,ctrl))

static const UNIX_Ctrls unix_args[UNIX_CTRLS_] =
{
/* symbol                      token name          ctrl mask                  ctrl             *
 * --------------------------- -------------------- ------------------------- ---------------- */

/* UNIX__OLD_PASSWD */         {NULL,               _ALL_ON_,                              01, 0},
/* UNIX__VERIFY_PASSWD */      {NULL,               _ALL_ON_,                              02, 0},
/* UNIX__IAMROOT */            {NULL,               _ALL_ON_,                              04, 0},
/* UNIX_AUDIT */               {"audit",            _ALL_ON_,                             010, 0},
/* UNIX_USE_FIRST_PASS */      {"use_first_pass",   _ALL_ON_^(060ULL),                    020, 0},
/* UNIX_TRY_FIRST_PASS */      {"try_first_pass",   _ALL_ON_^(060ULL),                    040, 0},
/* UNIX_AUTHTOK_TYPE */        {"authtok_type=",    _ALL_ON_,                            0100, 0},
/* UNIX__PRELIM */             {NULL,               _ALL_ON_^(0600ULL),                  0200, 0},
/* UNIX__UPDATE */             {NULL,               _ALL_ON_^(0600ULL),                  0400, 0},
/* UNIX__NONULL */             {NULL,               _ALL_ON_,                           01000, 0},
/* UNIX__QUIET */              {NULL,               _ALL_ON_,                           02000, 0},
/* UNIX_USE_AUTHTOK */         {"use_authtok",      _ALL_ON_,                           04000, 0},
/* UNIX_SHADOW */              {"shadow",           _ALL_ON_,                          010000, 0},
/* UNIX_MD5_PASS */            {"md5",              _ALL_ON_^(015660420000ULL),        020000, 1},
/* UNIX__NULLOK */             {"nullok",           _ALL_ON_^(01000ULL),                    0, 0},
/* UNIX_DEBUG */               {"debug",            _ALL_ON_,                          040000, 0},
/* UNIX_NODELAY */             {"nodelay",          _ALL_ON_,                         0100000, 0},
/* UNIX_NIS */                 {"nis",              _ALL_ON_,                         0200000, 0},
/* UNIX_BIGCRYPT */            {"bigcrypt",         _ALL_ON_^(015660420000ULL),       0400000, 1},
/* UNIX_LIKE_AUTH */           {"likeauth",         _ALL_ON_,                        01000000, 0},
/* UNIX_REMEMBER_PASSWD */     {"remember=",        _ALL_ON_,                        02000000, 0},
/* UNIX_NOREAP */              {"noreap",           _ALL_ON_,                        04000000, 0},
/* UNIX_BROKEN_SHADOW */       {"broken_shadow",    _ALL_ON_,                       010000000, 0},
/* UNIX_SHA256_PASS */         {"sha256",           _ALL_ON_^(015660420000ULL),     020000000, 1},
/* UNIX_SHA512_PASS */         {"sha512",           _ALL_ON_^(015660420000ULL),     040000000, 1},
/* UNIX_ALGO_ROUNDS */         {"rounds=",          _ALL_ON_,                      0100000000, 0},
/* UNIX_BLOWFISH_PASS */       {"blowfish",         _ALL_ON_^(015660420000ULL),    0200000000, 1},
/* UNIX_MIN_PASS_LEN */        {"minlen=",          _ALL_ON_,                      0400000000, 0},
/* UNIX_QUIET */               {"quiet",            _ALL_ON_,                     01000000000, 0},
/* UNIX_NO_PASS_EXPIRY */      {"no_pass_expiry",   _ALL_ON_,                     02000000000, 0},
/* UNIX_DES */                 {"des",              _ALL_ON_^(015660420000ULL),             0, 1},
/* UNIX_GOST_YESCRYPT_PASS */  {"gost_yescrypt",    _ALL_ON_^(015660420000ULL),   04000000000, 1},
/* UNIX_YESCRYPT_PASS */       {"yescrypt",         _ALL_ON_^(015660420000ULL),  010000000000, 1},
/* UNIX_NULLRESETOK */         {"nullresetok",      _ALL_ON_,                    020000000000, 0},
};

#define UNIX_DEFAULTS  (unix_args[UNIX__NONULL].flag)



/*
 * Returns NULL if STR does not start with PREFIX,
 * or a pointer to the first char in STR after PREFIX.
 * The length of PREFIX is specified by PREFIX_LEN.
 */
static inline const char *
pam_str_skip_prefix_len(const char *str, const char *prefix, size_t prefix_len)
{
	return strncmp(str, prefix, prefix_len) ? NULL : str + prefix_len;
}

/*
 * PAM framework looks for these entry-points to pass control to the
 * authentication module.
 */

/* Fun starts here :)

 * pam_sm_authenticate() performs UNIX/shadow authentication
 *
 *      First, if shadow support is available, attempt to perform
 *      authentication using shadow passwords. If shadow is not
 *      available, or user does not have a shadow password, fallback
 *      onto a normal UNIX authentication
 */
#ifdef PAM_POC
#define AUTH_RETURN						\
do {									\
	return retval;						\
} while (0)
#else
#define AUTH_RETURN						\
do {									\
	D(("recording return code for next time [%d]",		\
				retval));			\
	*ret_data = retval;					\
	pam_set_data(pamh, "unix_setcred_return",		\
			 (void *) ret_data, setcred_free);	\
	D(("done. [%s]", pam_strerror(pamh, retval)));		\
	return retval;						\
} while (0)
#endif

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

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv);
int _unix_blankpasswd();
unsigned long long _set_ctrl(pam_handle_t *pamh, int flags, int *remember,
			     int *rounds, int *pass_min_len, int argc,
			     const char **argv);
int _unix_strtoi(const char *str, int minval, int *result);
int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt);
int pam_get_authtok(pam_handle_t *pamh, const char **authtok);
int _unix_verify_password(const char *name, const char *password);
