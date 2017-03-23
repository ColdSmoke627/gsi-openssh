/* $OpenBSD: version.h,v 1.77 2016/07/24 11:45:36 djm Exp $ */

#define SSH_VERSION	"OpenSSH_7.3"
#ifdef GSI
#define GSI_VERSION	" GSI"
#else
#define GSI_VERSION	""
#endif

#ifdef KRB5
#define KRB5_VERSION	" KRB5"
#else
#define KRB5_VERSION	""
#endif

#ifdef MECHGLUE
#define MGLUE_VERSION	" MECHGLUE"
#else
#define MGLUE_VERSION	""
#endif

#define SSH_PORTABLE	"p1"
#define GSI_PORTABLE	"a-GSI"
#define SSH_HPN		"-hpn14v12"
#define SSH_RELEASE	SSH_VERSION SSH_PORTABLE SSH_HPN

#ifdef NERSC_MOD
#undef SSH_RELEASE
#define SSH_AUDITING	"NMOD_3.19"
#define SSH_RELEASE	SSH_VERSION SSH_PORTABLE SSH_HPN SSH_AUDITING
#else
#define SSH_AUDITING	""
#endif /* NERSC_MOD */

#undef SSH_RELEASE
#define SSH_RELEASE	SSH_VERSION SSH_PORTABLE GSI_PORTABLE " " SSH_AUDITING SSH_HPN \
                        GSI_VERSION KRB5_VERSION MGLUE_VERSION
