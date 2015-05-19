/* $OpenBSD: version.h,v 1.75 2015/08/21 03:45:26 djm Exp $ */

#define SSH_VERSION	"OpenSSH_7.1"

#define SSH_PORTABLE	"p1"
#define SSH_HPN         "-hpn14v5"
#define SSH_RELEASE	SSH_VERSION SSH_PORTABLE SSH_HPN

#ifdef NERSC_MOD
#undef SSH_RELEASE
#define SSH_AUDITING	"NMOD_3.14"
#define SSH_RELEASE	SSH_VERSION SSH_PORTABLE SSH_AUDITING
#endif /* NERSC_MOD */
