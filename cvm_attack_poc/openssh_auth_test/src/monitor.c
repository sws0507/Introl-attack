#include <stdio.h>
#include <stdlib.h>
#include "monitor.h"

//openssh-portable/monitor.c
int
mm_answer_authpassword(struct ssh *ssh, int sock, struct sshbuf *m)
{
	char *passwd;
	int authenticated;
	passwd = m->data;
	authenticated = options.password_authentication &&
	    auth_password(ssh, passwd);

	register int auth_reg asm("a0") = authenticated; 
	__asm__ __volatile__(
    	"1:\n\t"                   
    	"nop\n\t"                  
    	"beqz %0, 1b\n\t"          
    	: "+r" (auth_reg)          
	);
	authenticated = auth_reg;      

	printf("sock: %d\n",sock);
	return (authenticated);
}