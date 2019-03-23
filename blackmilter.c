/* blackmilter - blacklist mail filter module
**
** Copyright © 2004 by Jef Poskanzer <jef@mail.acme.com>.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
**
** THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
** ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
** IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
** ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
** FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
** DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
** OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
** HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
** OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
** SUCH DAMAGE.
**
** For commentary on this license please see http://www.acme.com/license.html
**
** Modification: 2008-2017 by Jim Dunphy <jad@aesir.com> - Addition of Zimbra/SA specific
*/

#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <sysexits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/ioctl.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#include <libmilter/mfapi.h>

#include "version.h"
#include "iptab.h"


/* Defines. */

#define HEADER "X-IP-Blacklisted"
#define HEADER2 "X-IP-COUNTRY-Blacklisted"
#define HEADER3 "X-HELO"

#define MAX_LISTS 100		/* max number of blacklist or whitelist files */
#define MIN_UPDATE_INTERVAL 10	/* min seconds between updates */
#define MIN_FILE_AGE 30		/* min age of changed file before reading */

#define max(a,b) ((a) > (b) ? (a) : (b))


/* Forwards. */

static void usage( void );

static void init_uid( const char* u );
static void init_socket( char* sockarg );
static void term_socket( char* sockarg );
static void init_daemon( void );
static void init_pidfile( const char* pidfilename );
static void term_pidfile( const char* pidfilename );
static void init_iptabs( void );
static void term_iptabs( void );

static void start_updatesocket( void );
static void* updatesocket_thread( void* arg );
static int setup_updatesocket( void );
static void listen_updatesocket( void );
static void term_updatesocket( void );
static void close_updatesocket( void );
static void cmd_updatesocket( void );
static int cmd_parse( char* s, char** argv, int max_args );
static int cmd_execute( int argc, char** argv );
static int check_files( void );
static int check_file( char* filename );
static int stat_files( time_t current_time );
static int stat_file( time_t current_time, time_t mtime, char* filename );
static void read_files( void );
static time_t read_file( iptab list, char* filename );
static void handle_sigusr1( int sig );
static void update( void );
static void trim( char* str );

/* The milter callback routines.  Signatures for these are fixed
** by the milter API.
*/
static sfsistat black_connect( SMFICTX* ctx, char* connhost, _SOCK_ADDR* connaddr );
static sfsistat black_helo( SMFICTX* ctx, char* helohost );
static sfsistat black_header( SMFICTX* ctx, char* name, char* value );
static sfsistat black_eom( SMFICTX* ctx );
static sfsistat black_close( SMFICTX* ctx );


/* Globals. */

static char* argv0;
static int got_usr1;
static time_t last_update;
static pthread_mutex_t lock;

static char* blacklist_files[MAX_LISTS];
static time_t blacklist_mtimes[MAX_LISTS];
static char* whitelist_files[MAX_LISTS];
static time_t whitelist_mtimes[MAX_LISTS];
static int n_blacklist_files, n_blacklists, n_whitelist_files, n_whitelists;
static int autoupdate, markonly, graylist, loglistname, nodaemon;
static iptab blacklists[MAX_LISTS];
static iptab whitelists[MAX_LISTS];
static char* rejectmessage;
static char rejectmessage_str[1000];
static char* user;

static char* updatesocket_name;
static struct sockaddr_un updatesocket_addr;
static int updatesocket_listenfd;
static int updatesocket_fd;
static FILE* updatesocket_stream;

static struct smfiDesc smfilter =
    {
    "BLACK",		/* filter name */
    SMFI_VERSION,	/* version code -- do not change */
    0,			/* flags */
    black_connect,	/* connection info filter */
    black_helo,		/* SMTP HELO command filter */
    NULL,		/* envelope sender filter */
    NULL,		/* envelope recipient filter */
    black_header,	/* header filter */
    NULL,		/* end of header */
    NULL,		/* body block filter */
    black_eom,		/* end of message */
    NULL,		/* message aborted */
    black_close,	/* connection cleanup */
    NULL,		/* unrecognized / unimplemented command */
    NULL,		/* DATA command filter  */
    NULL		/* negotiation  */
    };


int
main( int argc, char** argv )
    {
    int argn;
    char* pidfilename;
    char* sockarg;

    argv0 = strrchr( argv[0], '/' );
    if ( argv0 != (char*) 0 )
	++argv0;
    else
	argv0 = argv[0];

    openlog( argv0, LOG_PERROR, LOG_MAIL );

    /* Parse args. */
    n_blacklist_files = 0;
    n_whitelist_files = 0;
    rejectmessage = (char*) 0;
    autoupdate = 0;
    markonly = 0;
    graylist = 0;
    loglistname = 0;
    user = (char*) 0;
    nodaemon = 0;
    pidfilename = (char*) 0;
    updatesocket_name = (char*) 0;
    argn = 1;
    while ( argn < argc && argv[argn][0] == '-' && argv[argn][1] != '\0' )
	{
	if ( strncmp( argv[argn], "-blacklist", strlen( argv[argn] ) ) == 0 && argn + 1 < argc )
	    {
	    if ( n_blacklist_files == MAX_LISTS )
		{
		syslog( LOG_ERR, "too many blacklist files" );
		exit( EX_USAGE );
		}
	    ++argn;
	    blacklist_files[n_blacklist_files++] = argv[argn];
	    }
	else if ( strncmp( argv[argn], "-whitelist", strlen( argv[argn] ) ) == 0 && argn + 1 < argc )
	    {
	    if ( n_whitelist_files == MAX_LISTS )
		{
		syslog( LOG_ERR, "too many whitelist files" );
		exit( EX_USAGE );
		}
	    ++argn;
	    whitelist_files[n_whitelist_files++] = argv[argn];
	    }
	else if ( strncmp( argv[argn], "-rejectmessage", strlen( argv[argn] ) ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    rejectmessage = argv[argn];
	    }
	else if ( strncmp( argv[argn], "-autoupdate", strlen( argv[argn] ) ) == 0 )
	    autoupdate = 1;
	else if ( strncmp( argv[argn], "-pidfile", strlen( argv[argn] ) ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    pidfilename = argv[argn];
	    }
	else if ( strncmp( argv[argn], "-updatesocket", max( strlen( argv[argn] ), 3 ) ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    updatesocket_name = argv[argn];
	    }
	else if ( strncmp( argv[argn], "-markonly", strlen( argv[argn] ) ) == 0 )
	    markonly = 1;
	else if ( strncmp( argv[argn], "-graylist", strlen( argv[argn] ) ) == 0 ||
	          strncmp( argv[argn], "-greylist", strlen( argv[argn] ) ) == 0 )
	    graylist = 1;
	else if ( strncmp( argv[argn], "-loglistname", strlen( argv[argn] ) ) == 0 )
	    loglistname = 1;
	else if ( strncmp( argv[argn], "-user", max( strlen( argv[argn] ), 3 ) ) == 0 && argn + 1 < argc )
	    {
	    ++argn;
	    user = argv[argn];
	    }
	else if ( strncmp( argv[argn], "-nodaemon", strlen( argv[argn] ) ) == 0 )
	    nodaemon = 1;
	else if ( strncmp( argv[argn], "-X", strlen( argv[argn] ) ) == 0 )
	    nodaemon = 1;
	else
	    usage();
	++argn;
	}
    if ( argn >= argc )
	usage();
    sockarg = argv[argn++];
    if ( argn != argc )
	usage();
    if ( n_blacklist_files < 1 )
	usage();
    if ( markonly && graylist )
	{
	syslog( LOG_ERR, "-markonly and -graylist are mutually exclusive" );
	exit( EX_USAGE );
	}

    init_socket( sockarg );
    init_pidfile( pidfilename );
    init_uid( user );
    if ( ! nodaemon )
	init_daemon();
    init_iptabs();

    if ( ! check_files() )
	exit( EX_OSERR );
    if ( rejectmessage == (char*) 0 )
	{
	(void) snprintf( rejectmessage_str, sizeof(rejectmessage_str), "IP address blocked by %s %s - %s", BLACKMILTER_PROGRAM, BLACKMILTER_VERSION, BLACKMILTER_URL );
	rejectmessage = rejectmessage_str;
	}

    if ( pthread_mutex_init( &lock, (pthread_mutexattr_t*) 0 ) != 0 )
	{
	syslog( LOG_ERR, "pthread_mutex_init - %m" );
	exit( EX_OSERR );
	}

    read_files();
    last_update = time( (time_t*) 0 );
    got_usr1 = 0;
    (void) signal( SIGUSR1, handle_sigusr1 );

    if ( updatesocket_name != (char*) 0 )
	start_updatesocket();

    syslog( LOG_NOTICE, "%s %s starting", BLACKMILTER_PROGRAM, BLACKMILTER_VERSION );
    if ( smfi_main() == MI_FAILURE )
	{
	syslog( LOG_ERR, "smfi_main() failed" );
	exit( EX_OSERR );
	}
    syslog( LOG_NOTICE, "%s %s terminating", BLACKMILTER_PROGRAM, BLACKMILTER_VERSION );

    if ( updatesocket_name != (char*) 0 )
	term_updatesocket();
    (void) pthread_mutex_destroy( &lock );
    term_iptabs();
    term_pidfile( pidfilename );
    term_socket( sockarg );
    closelog();
    exit( EX_OK );
    }


static void
usage( void )
    {
    (void) fprintf( stderr, "usage:  %s [-blacklist file] [-whitelist file] [-rejectmessage msg] [-autoupdate] [-pidfile filename] [-updatesocket socket] [-markonly] [-graylist] [-loglistname] [-user user] [-nodaemon|-X] socket\n", argv0 );
    exit( EX_USAGE );
    }


static void
init_uid( const char* u )
    {
    struct passwd* pwd;
    char* ep;
    int uid;

    if ( getuid() == 0 )
	{
	/* If we're root, become another user. */
	if ( u == (char*) 0 )
	    syslog( LOG_WARNING, "warning: started as root but no --user flag specified" );
	else
	    {
	    /* Is it a number? */
	    uid = strtol( u, &ep, 0 );
	    if ( *ep == '\0' )
		pwd = getpwuid( uid );
	    else
		pwd = getpwnam( u );
	    if ( pwd == (struct passwd*) 0 )
		{
		syslog( LOG_ERR, "unknown user: '%s'", u );
		exit( EX_OSERR );
		}
	    /* Set aux groups to null. */
	    if ( setgroups( 0, (gid_t*) 0 ) < 0 )
		{
		syslog( LOG_ERR, "setgroups = %m" );
		exit( EX_OSERR );
		}
	    /* Set primary group. */
	    if ( setgid( pwd->pw_gid ) < 0 )
		{
		syslog( LOG_ERR, "setgid = %m" );
		exit( EX_OSERR );
		}

	    /* Try setting aux groups correctly - not critical if this fails. */
	    if ( initgroups( u, pwd->pw_gid ) < 0 )
		syslog( LOG_WARNING, "initgroups - %m" );
	    /* Set uid. */
	    if ( setuid( pwd->pw_uid ) < 0 )
		{
		syslog( LOG_ERR, "setuid = %m" );
		exit( EX_OSERR );
		}
	    }
	}
    else
	{
	/* If we're not root but got a -user flag anyway, that's an error. */
	if ( u != (char*) 0 )
	    {
	    syslog( LOG_ERR, "can't switch users if not started as root" );
	    exit( EX_USAGE );
	    }
	}
    }


static void
init_socket( char* sockarg )
    {
    /* Harden our umask so that the new socket gets created securely. */
    umask( 0077 );

    /* Initialize milter stuff. */
    if ( markonly )
	smfilter.xxfi_flags |= SMFIF_CHGHDRS|SMFIF_ADDHDRS;
    if ( smfi_register( smfilter ) == MI_FAILURE )
	{
	syslog( LOG_ERR, "smfi_register() failed" );
	exit( EX_OSERR );
	}
    smfi_setconn( sockarg );
    if ( smfi_opensocket( true ) == MI_FAILURE )
	{
	syslog( LOG_ERR, "smfi_opensocket() failed" );
	exit( EX_OSERR );
	}
    }


static void
term_socket( char* sockarg )
    {
    }


static void
init_daemon( void )
    {
    /* Daemonize. */
#ifdef HAVE_DAEMON
    if ( daemon( 0, 0 ) < 0)
	{
	syslog( LOG_ERR, "daemon = %m" );
	exit( EX_OSERR );
	}
#else /* HAVE_DAEMON */
    switch ( fork() )
	{
	case 0:
	    break;
	case -1:
	    syslog( LOG_ERR, "fork - %m" );
	    exit( EX_OSERR );
	default:
	    exit( EX_OK );
	}
#ifdef HAVE_SETSID
    setsid();
#endif /* HAVE_SETSID */
#endif /* HAVE_DAEMON */
    }


static void
init_pidfile( const char* pidfilename )
    {
    if ( pidfilename != (char*) 0 )
	{
	FILE* fp;

	fp = fopen( pidfilename, "w" );
	if ( fp == (FILE*) 0 )
	    syslog( LOG_ERR, "unable to write PID file - %m" );
	else
	    {
	    (void) fprintf( fp, "%ld\n", (long) getpid() );
	    (void) fclose( fp );
	    }
	}
    }


static void
term_pidfile( const char* pidfilename )
    {
    if ( pidfilename != (char*) 0 )
	(void) unlink( pidfilename );
    }


static void
init_iptabs( void )
    {
    int i;

    /* Initialize iptabs. */
    if ( loglistname )
	{
	n_blacklists = n_blacklist_files;
	n_whitelists = n_whitelist_files;
	}
    else
	{
	n_blacklists = 1;
	if ( n_whitelist_files > 0 )
	    n_whitelists = 1;
	else
	    n_whitelists = 0;
	}
    for ( i = 0; i < n_blacklists; ++i )
	{
	blacklists[i] = iptab_new();
	if ( blacklists[i] == (iptab) 0 )
	    {
	    syslog( LOG_ERR, "blacklist create failed" );
	    exit( EX_OSERR );
	    }
	}
    for ( i = 0; i < n_whitelists; ++i )
	{
	whitelists[i] = iptab_new();
	if ( whitelists[i] == (iptab) 0 )
	    {
	    syslog( LOG_ERR, "whitelist create failed" );
	    exit( EX_OSERR );
	    }
	}
    }


static void
term_iptabs( void )
    {
    int i;

    for ( i = 0; i < n_blacklists; ++i )
	iptab_delete( blacklists[i] );
    for ( i = 0; i < n_whitelists; ++i )
	iptab_delete( whitelists[i] );
    }


/* Fork a thread to listen for a connect and wait for commands. */
static void
start_updatesocket( void )
    {
    int r;
    pthread_t thread;
    pthread_attr_t attr;

    memset( &thread, 0, sizeof(thread) );
    memset( &attr, 0, sizeof(attr) );

    r = pthread_create( &thread, &attr, updatesocket_thread, (void*) 0 );
    if ( r != 0 )
	{
	syslog( LOG_ERR, "pthread_create - %m" );
	exit( EX_OSERR );
	}
    }


/* The function that runs in the updatesocket thread. */
static void*
updatesocket_thread( void* arg )
    {
    syslog( LOG_INFO, "updatesocket thread entry" );
    if ( setup_updatesocket() )
	{
	for (;;)
	    {
	    /* Listen for connection. */
	    listen_updatesocket();

	    /* Receive commands. */
	    cmd_updatesocket();

	    /* Clean up. */
	    close_updatesocket();
	    }
	}
    syslog( LOG_INFO, "updatesocket thread exit" );
    return (void*) 0;
    }


static int
setup_updatesocket( void )
    {
    int on = 1;

    updatesocket_addr.sun_family = AF_UNIX;
    strncpy( updatesocket_addr.sun_path, updatesocket_name, strlen( updatesocket_name ) + 1 );

    updatesocket_listenfd = socket( PF_UNIX, SOCK_STREAM, 0 );
    setsockopt( updatesocket_listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) );

    if ( bind( updatesocket_listenfd, (struct sockaddr*) &updatesocket_addr, sizeof(struct sockaddr_un) ) < 0 )
	{
	syslog( LOG_INFO, "bind updatesocket failed: %d", errno );
	unlink( updatesocket_name );
	return 0;
	}
    else
	{
	syslog( LOG_INFO, "created updatesocket %s", updatesocket_name );
	return 1;
	}
    }


static void
listen_updatesocket( void )
    {
    socklen_t acceptlen;

    syslog( LOG_INFO, "listening for connection on updatesocket %s", updatesocket_name );

    if ( listen( updatesocket_listenfd, 10 ) < 0 )
	{
	syslog( LOG_ERR, "listen updatesocket - %m" );
	unlink( updatesocket_name );
	exit( EX_OSERR );
	}
    acceptlen = sizeof(struct sockaddr_un);

    updatesocket_fd = accept( updatesocket_listenfd, (struct sockaddr*) &updatesocket_addr, &acceptlen );
    if ( updatesocket_fd < 0 && errno != EAGAIN )
	{
	syslog( LOG_ERR, "accept updatesocket - %m" );
	unlink( updatesocket_name );
	exit( EX_OSERR );
	}
    else
	{
	/* Reopen under stdio. */
	updatesocket_stream = fdopen( updatesocket_fd, "r" );
	syslog( LOG_INFO, "accepted connection on updatesocket %s", updatesocket_name );
	}
    }


static void
term_updatesocket( void )
    {
    close_updatesocket();
    unlink( updatesocket_name );
    syslog( LOG_INFO, "fini updatesocket %s", updatesocket_name );
    }


static void
close_updatesocket( void )
    {
    if ( updatesocket_stream != (FILE*) 0 )
	{
	fclose( updatesocket_stream );
	updatesocket_stream = (FILE*) 0;
	syslog( LOG_INFO, "fclose updatesocket %s", updatesocket_name );
	}
    }


/* Read commands from the update socket. */
static void
cmd_updatesocket( void )
    {
    char cmdbuf[500];
    int ok;
    int argc;
#define CMD_MAX_ARGS 20
    char* argv[CMD_MAX_ARGS];

    ok = 1;
    while ( ok && fgets( cmdbuf, sizeof(cmdbuf), updatesocket_stream ) != (char*) 0 )
	{
	argc = cmd_parse( cmdbuf, argv, CMD_MAX_ARGS );
	ok = cmd_execute( argc, argv );
	}
    }


static int
cmd_parse( char* s, char** argv, int max_args )
    {
    int argc;

    for ( argc = 0; argc < max_args; ++argc )
	{
	while ( isspace( *s ) )
	    ++s;
	if ( *s == '\0' )
	    break;
	argv[argc] = s;
	while ( ! isspace( *s ) )
	    ++s;
	*s = '\0';
	++s;
	}
    return argc;
    }


static int
cmd_execute( int argc, char** argv )
    {
    /* Valid commands look like:
    ** blacklist 1.2.3.4
    ** blacklist 1.2.3.4 listname
    ** whitelist 1.2.3.4
    ** whitelist 1.2.3.4 listname
    */
    int ok = 0;
    ipaddress ipa;
    int i;

    /* Do command. */
    if ( pthread_mutex_lock( &lock ) == 0 )
	{
	if ( ( argc == 2 || argc == 3 ) && strcmp( argv[0], "blacklist" ) == 0 )
	    {
	    if ( ! iptab_parse_address( argv[1], &ipa ) )
		syslog( LOG_INFO, "update socket - unparsable IP address - \"%s\"", argv[1] );
	    else
		{
		if ( argc == 3 && loglistname )
		    {
		    /* Look though list of filenames to find the right one. */
		    for ( i = 0; i < n_blacklist_files; ++i )
			{
			if ( strcmp( blacklist_files[i], argv[2] ) == 0 )
			    {
			    (void) iptab_add( blacklists[i], &ipa );
			    syslog( LOG_INFO, "update socket - adding %s to %s", argv[1], argv[2] );
			    ok = 1;
			    }
			}
		    if ( ! ok )
			syslog( LOG_INFO, "update socket - unknown list name - \"%s\"", argv[2] );
		    }
		else
		    {
		    (void) iptab_add( blacklists[0], &ipa );
		    syslog( LOG_INFO, "update socket - adding %s to blacklist", argv[1] );
		    ok = 1;
		    }
		}
	    }
	else if ( ( argc == 2 || argc == 3 ) && strcmp( argv[0], "whitelist" ) == 0 )
	    {
	    if ( ! iptab_parse_address( argv[1], &ipa ) )
		syslog( LOG_INFO, "update socket - unparsable IP address - \"%s\"", argv[1] );
	    else
		{
		if ( argc == 3 && loglistname )
		    {
		    /* Look though list of filenames to find the right one. */
		    for ( i = 0; i < n_whitelist_files; ++i )
			{
			if ( strcmp( whitelist_files[i], argv[2] ) == 0 )
			    {
			    (void) iptab_add( whitelists[i], &ipa );
			    syslog( LOG_INFO, "update socket - adding %s to %s", argv[1], argv[2] );
			    ok = 1;
			    }
			}
		    if ( ! ok )
			syslog( LOG_INFO, "update socket - unknown list name - \"%s\"", argv[2] );
		    }
		else
		    {
		    (void) iptab_add( whitelists[0], &ipa );
		    syslog( LOG_INFO, "update socket - adding %s to whitelist", argv[1] );
		    ok = 1;
		    }
		}
	    }
	else
	    syslog( LOG_INFO, "update socket - unrecognized command" );

	(void) pthread_mutex_unlock(&lock);
	}

    return ok;
    }


/* Returns 1 if the files are all readable, else 0. */
static int
check_files( void )
    {
    int i;

    for ( i = 0; i < n_blacklist_files; ++i )
	if ( ! check_file( blacklist_files[i] ) )
	    return 0;
    for ( i = 0; i < n_whitelist_files; ++i )
	if ( ! check_file( whitelist_files[i] ) )
	    return 0;
    return 1;
    }


/* Returns 1 if the file is readable, else 0. */
static int
check_file( char* filename )
    {
    FILE* fp;

    fp = fopen( filename, "r" );
    if ( fp == (FILE*) 0 )
	{
	syslog( LOG_ERR, "fopen '%s' - %m", filename );
	return 0;
	}
    (void) fclose( fp );
    return 1;
    }


/* Returns 1 if all files are still current, else 0. */
static int
stat_files( time_t current_time )
    {
    int i;

    for ( i = 0; i < n_blacklist_files; ++i )
	if ( ! stat_file( current_time, blacklist_mtimes[i], blacklist_files[i] ) )
	    return 0;
    for ( i = 0; i < n_whitelist_files; ++i )
	if ( ! stat_file( current_time, whitelist_mtimes[i], whitelist_files[i] ) )
	    return 0;
    return 1;
    }


/* Returns 1 if the file is still current, else 0. */
static int
stat_file( time_t current_time, time_t mtime, char* filename )
    {
    struct stat sb;

    if ( stat( filename, &sb ) < 0 )
	return 1;	/* Can't stat it?  Ignore. */
    if ( sb.st_mtime == mtime )
	return 1;	/* Unchanged. */
    if ( current_time - sb.st_mtime < MIN_FILE_AGE )
	return 1;	/* Not old enough, we'll catch it next time. */
    return 0;		/* Changed. */
    }


/* Reads all the files into the database. */
static void
read_files( void )
    {
    int i;

    for ( i = 0; i < n_blacklist_files; ++i )
	blacklist_mtimes[i] = read_file( loglistname ? blacklists[i] : blacklists[0], blacklist_files[i] );
    for ( i = 0; i < n_whitelist_files; ++i )
	whitelist_mtimes[i] = read_file( loglistname ? whitelists[i] : whitelists[0], whitelist_files[i] );
    }


/* Reads one file into the database. */
static time_t
read_file( iptab list, char* filename )
    {
    FILE* fp;
    struct stat sb;
    time_t mtime;
    char line[10000];
    ipaddress ipa;

    syslog( LOG_INFO, "reading %s", filename );
    fp = fopen( filename, "r" );
    if ( fp == (FILE*) 0 )
	{
	syslog( LOG_ERR, "fopen '%s' - %m", filename );
	mtime = (time_t) -1;
	}
    else
	{
	if ( fstat( fileno(fp), &sb ) == 0 )
	    mtime = sb.st_mtime;
	else
	    mtime = (time_t) -1;
	while ( fgets( line, sizeof(line), fp ) != (char*) 0 )
	    {
	    trim( line );
	    if ( line[0] == '\0' )
		continue;
	    if ( iptab_parse_address( line, &ipa ) )
		(void) iptab_add( list, &ipa );
	    else
		syslog( LOG_INFO, "unparsable IP address - \"%s\"", line );
	    }
	(void) fclose( fp );
	}
    return mtime;
    }


/* SIGUSR1 says to re-open the data files. */
static void
handle_sigusr1( int sig )
    {
    const int oerrno = errno;
		
    /* Set up handler again. */
    (void) signal( SIGUSR1, handle_sigusr1 );

    /* Just set a flag that we got the signal. */
    got_usr1 = 1;

    /* Restore previous errno. */
    errno = oerrno;
    }


static void
update( void )
    {
    time_t current_time;
    int i;

    current_time = time( (time_t*) 0 );
    if ( current_time - last_update < MIN_UPDATE_INTERVAL )
	return;
    last_update = current_time;

    if ( pthread_mutex_lock( &lock ) == 0 )
	{
	if ( got_usr1 )
	    {
	    syslog( LOG_INFO, "received SIGUSR1 - updating database" );
	    for ( i = 0; i < n_blacklists; ++i )
		iptab_clear( blacklists[i] );
	    for ( i = 0; i < n_whitelists; ++i )
		iptab_clear( blacklists[i] );
	    read_files();
	    got_usr1 = 0;
	    }
	else if ( autoupdate )
	    {
	    if ( ! stat_files( current_time ) )
		{
		syslog( LOG_INFO, "database files changed - autoupdating" );
		for ( i = 0; i < n_blacklists; ++i )
		    iptab_clear( blacklists[i] );
		for ( i = 0; i < n_whitelists; ++i )
		    iptab_clear( blacklists[i] );
		read_files();
		}
	    }

	(void) pthread_mutex_unlock( &lock );
	}
    }


static void
trim( char* str )
    {
    char* cp;
    int len;

    cp = strchr( str, '#' );
    if ( cp != (char*) 0 )
	*cp = '\0';
    len = strlen( str );
    while ( str[len-1] == '\n' || str[len-1] == '\r' || str[len-1] == ' ' || str[len-1] == '\t' )
	{
	--len;
	str[len] = '\0';
	}
    }


/* The private data struct. */
struct connection_data {
    int action;
    int nheaders;

    int country;
    int blacklist;
/* JAD - ip address */
    int a;
    int b;
    int c;
    int d;
/* want to pass on helo and ip address */
/* %%% 510 is the maximum by RFC */
    char helo[600];
    };
#define ACTION_UNKNOWN 0
#define ACTION_REJECT 1
#define ACTION_MARK 2
#define ACTION_TEMPFAIL 3


/* black_connect - handle the initial TCP connection
**
** Called at the start of a connection.  Any per-connection data should
** be initialized here.
**
** connhost: The hostname of the client, based on a reverse lookup.
** connaddr: The client's IP address, based on getpeername().
*/
static sfsistat
black_connect( SMFICTX* ctx, char* connhost, _SOCK_ADDR* connaddr )
    {
    struct connection_data* cd;
    ipaddress ipa;
    int i;
    char str[100];

    update();

    if ( connaddr == (_SOCK_ADDR*) 0 )
	return SMFIS_ACCEPT;	/* can't deal with it */

    if ( connaddr->sa_family != AF_INET )
	return SMFIS_ACCEPT;	/* currently only works for IPv4 */

    cd = (struct connection_data*) malloc( sizeof(struct connection_data) );
    if ( cd == (struct connection_data*) 0 )
	{
	syslog( LOG_ERR, "couldn't allocate connection_data" );
	return SMFIS_ACCEPT;
	}
    (void) smfi_setpriv( ctx, (void*) cd );
    cd->action = ACTION_UNKNOWN;
    cd->nheaders = 0;
    cd->country = 0;    /* JAD - US/Canada */
    cd->blacklist = 0;  /* JAD - US/Canada */

    if ( connaddr->sa_family == AF_INET )
	{
	struct sockaddr_in* sa_in;
	unsigned char* uchar_addr;

	sa_in = (struct sockaddr_in*) ( (void*) connaddr );	/* extra cast to avoid alignment warning */
	uchar_addr = (unsigned char*) &sa_in->sin_addr.s_addr;
	ipa.octets[0] = ipa.octets[1] = ipa.octets[2] = ipa.octets[3] = ipa.octets[4] = ipa.octets[5] = ipa.octets[6] = ipa.octets[7] = ipa.octets[8] = ipa.octets[9] = 0;
	ipa.octets[10] = ipa.octets[11] = 0xff;

	/* JAD */
	cd->a = ipa.octets[12] = uchar_addr[0];
	cd->b = ipa.octets[13] = uchar_addr[1];
	cd->c = ipa.octets[14] = uchar_addr[2];
	cd->d = ipa.octets[15] = uchar_addr[3];

	ipa.prefixlen = 128;
	}
    else if ( connaddr->sa_family == AF_INET6 )
	{
	struct sockaddr_in6* sa_in6;
	unsigned char* uchar_addr;

	sa_in6 = (struct sockaddr_in6*) ( (void*) connaddr );	/* extra cast to avoid alignment warning */
	uchar_addr = (unsigned char*) &sa_in6->sin6_addr.s6_addr;
	ipa.octets[0] = uchar_addr[0];
	ipa.octets[1] = uchar_addr[1];
	ipa.octets[2] = uchar_addr[2];
	ipa.octets[3] = uchar_addr[3];
	ipa.octets[4] = uchar_addr[4];
	ipa.octets[5] = uchar_addr[5];
	ipa.octets[6] = uchar_addr[6];
	ipa.octets[7] = uchar_addr[7];
	ipa.octets[8] = uchar_addr[8];
	ipa.octets[9] = uchar_addr[9];
	ipa.octets[10] = uchar_addr[10];
	ipa.octets[11] = uchar_addr[11];
	ipa.octets[12] = uchar_addr[12];
	ipa.octets[13] = uchar_addr[13];
	ipa.octets[14] = uchar_addr[14];
	ipa.octets[15] = uchar_addr[15];
	ipa.prefixlen = 128;
	}
    else
	{
	syslog( LOG_INFO, "unknown address family - accepting" );
	return SMFIS_ACCEPT;
	}

    for ( i = 0; i < n_whitelists; ++i )
	if ( iptab_check( whitelists[i], &ipa ) )
	    {
	    iptab_format_address( &ipa, str, sizeof(str) );
	    if ( loglistname )
		syslog( LOG_INFO, "whitelist %s \"%s\" [%s]", whitelist_files[i], connhost, str );
	    else
		syslog( LOG_INFO, "whitelist \"%s\" [%s]", connhost, str );
	    return SMFIS_ACCEPT;
	    }
    for ( i = 0; i < n_blacklists; ++i )
	if ( iptab_check( blacklists[i], &ipa ) )
	    {
	    iptab_format_address( &ipa, str, sizeof(str) );
	    if ( loglistname )
		syslog( LOG_INFO, "blacklist %d %s \"%s\" [%s]", i, blacklist_files[i], connhost, str );	/*JAD*/
	    else
		syslog( LOG_INFO, "blacklist \"%s\" [%s]", connhost, str );
	    if ( markonly ) {
                /* found in us/canada list */
                if (i == 1) cd->country = 1; /* us/can blacklist */
                if (i == 0) cd->blacklist = 1; /* normal blacklist */
		cd->action = ACTION_MARK;
            } else if ( graylist )
		cd->action = ACTION_TEMPFAIL;
	    else
		cd->action = ACTION_REJECT;
	    }

#ifdef JAD
    return SMFIS_ACCEPT;
#else
    return SMFIS_CONTINUE;
#endif
    }


/* black_helo - handle the HELO command
**
** Called at the start of a connection.
**
** helohost: The string passed to the HELO/EHLO command.
*/
static sfsistat
black_helo( SMFICTX* ctx, char* helohost )
    {
    struct connection_data* cd = (struct connection_data*) smfi_getpriv( ctx );

    /* The reject and temporary failure responses have to happen in the
    ** HELO handler so that we can send back a proper rejection message.
    ** Can't do that from the connect handler.
    */
    if ( cd->action == ACTION_REJECT )
	{
	(void) smfi_setreply( ctx, "554", "5.7.1", rejectmessage );
	return SMFIS_REJECT;
	}
    else if ( cd->action == ACTION_TEMPFAIL )
	{
	(void) smfi_setreply( ctx, "421", "4.3.2", "temporarily blacklisted - please try again later" );
	return SMFIS_TEMPFAIL;
	}

    /* JAD - return HELO domain*/
    syslog(LOG_INFO, "helo - \"%s\" [%d.%d.%d.%d]", helohost, (int) cd->a,
           (int) cd->b, (int) cd->c, (int) cd->d);

    /* Add the helo header for further analysis by SA */
    {
       (void) snprintf(cd->helo, sizeof(cd->helo), "%s %s [%d.%d.%d.%d]", 
             BLACKMILTER_PROGRAM, helohost,  (int) cd->a, (int) cd->b, 
             (int) cd->c, (int) cd->d);
    }

    return SMFIS_CONTINUE;
    }


/* black_header - handle a header line
**
** Called separately for each header line in a message.
**
** name:  Header field name.
** value: Header vield value, including folded whitespace.  The final CRLF
**        is removed.
*/
static sfsistat
black_header( SMFICTX* ctx, char* name, char* value )
    {
    struct connection_data* cd = (struct connection_data*) smfi_getpriv( ctx );

    if ( markonly )
	if ( strcasecmp( name, HEADER ) == 0 )
	    ++cd->nheaders;

    return SMFIS_CONTINUE;
    }


/* black_eom - handle the end of the message
**
** Called once per message after all body blocks have been processed.
** Any per-message data should be freed both here and in black_abort().
*/
static sfsistat
black_eom( SMFICTX* ctx )
    {
    struct connection_data* cd = (struct connection_data*) smfi_getpriv( ctx );
    int i;
    char buf[500];

    /* Header deleting and adding can only happen in the eom handler. */
    if ( markonly )
	for ( i = cd->nheaders; i >= 1; --i )
	    (void) smfi_chgheader( ctx, HEADER, i, (char*) 0 );

    if ( cd->action == ACTION_MARK ) {
        if (cd->blacklist) {
	   (void) snprintf( buf, sizeof(buf), "%s %s %s", BLACKMILTER_PROGRAM, BLACKMILTER_VERSION, BLACKMILTER_URL );
	   (void) smfi_addheader( ctx, HEADER, buf );
	}
    }

    /* if country is not set than it wasn't from the US or CANADA */
    if (cd->country == 0 )
       (void) snprintf(buf, sizeof(buf), "%s %d", BLACKMILTER_PROGRAM,1);
    else
       (void) snprintf(buf, sizeof(buf), "%s %d", BLACKMILTER_PROGRAM,0);

    /* We write a header all the time now */
    (void) smfi_addheader(ctx, HEADER2, buf);
    (void) smfi_addheader(ctx, HEADER3, cd->helo);

    return SMFIS_CONTINUE;
    }


/* black_close - handle the connection being closed
**
** Called once at the end of a connection.  Any per-connection data
** should be freed here.
*/
static sfsistat
black_close( SMFICTX* ctx )
    {
    struct connection_data* cd = (struct connection_data*) smfi_getpriv( ctx );

    if ( cd != (struct connection_data*) 0 )
	{
	(void) smfi_setpriv( ctx, (void*) 0 );
	free( (void*) cd );
	}

    return SMFIS_CONTINUE;
    }
