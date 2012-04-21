/*
 * ifdown.c	Find all network interfaces on the system and
 *		shut them down.
 *
 */
char *v_ifdown = "@(#)ifdown.c  1.11  02-Jun-1998  miquels@cistron.nl";

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <net/if.h>
#include <netinet/in.h>

/*
 *	First, we find all shaper devices and down them. Then we
 *	down all real interfaces. This is because the comment in the
 *	shaper driver says "if you down the shaper device before the
 *	attached inerface your computer will follow".
 */
int ifdown(void)
{
	return 0;
}
