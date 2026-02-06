#ifndef MONITOR_H
#define MONITOR_H

#include "auth.h"

#define USERNAME "sws1234"
#define PASSWORD "sws1234"

struct sshbuf {
	char *data;		/* Data */
};

int mm_answer_authpassword(struct ssh *ssh, int sock, struct sshbuf *m);

#endif /* MONITOR_H */