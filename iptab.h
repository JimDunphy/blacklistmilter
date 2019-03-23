/* iptab.h - header file for the IP table module
**
** This package stores a set of IPv4/IPv6 address. You can add
** addresses to the set, and check if an address is present or not.
** There are also some auxiliary routines for things like parsing
** and formatting addresses.
**
** The data structure is a hash table, with some enhancements to
** deal with netmasks/prefixes. Both speed and storage efficiency
** are good.
**
**
** Copyright © 2015 by Jef Poskanzer <jef@mail.acme.com>.
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
*/

#ifndef _IPTAB_H_
#define _IPTAB_H_

#include <stdbool.h>

/* Opaque type. */
typedef void* iptab;

/* A parsed IP address. */
typedef struct _ipaddress {
    unsigned char octets[16];
    unsigned int prefixlen;
    } ipaddress;


/* Creates a new iptab.  Returns 0 on failure. */
iptab iptab_new( void );

/* Clears an iptab. */
void iptab_clear( iptab ipt );

/* Gets rid of an iptab. */
void iptab_delete( iptab ipt );

/* Parses a string IP address, either IPv4 or IPv6. */
bool iptab_parse_address( const char* str, ipaddress* ipa );

/* Formats an IP address into a string. */
char* iptab_format_address( const ipaddress* ipa, char* str, size_t size );

/* Adds an IP address to an iptab. */
bool iptab_add( iptab ipt, const ipaddress* ipa );

/* Checks if an IP address is in an iptab. */
bool iptab_check( const iptab ipt, const ipaddress* ipa );

/* Does a network include an address? */
bool iptab_includes( const ipaddress* ipn, const ipaddress* ipa );

/* Is an address IPv4 or not? */
bool iptab_is_ipv4( const ipaddress* ipa );

/* Describes the most recent error. */
char* iptab_error_str( void );

#ifdef STATS
/* Return stats since last call. */
void iptab_stats( int* mallocs, int* frees, ssize_t* memchange, int* collisions, int* expansions );
#endif /* STATS */

#endif /* _IPTAB_H_ */
