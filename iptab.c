/* iptab.c - tables of IP addresses
**
** Fast lookup tables for IP addresses. Currently implementation
** is hash tables.
**
** Also includes some routines for parsing and formatting addresses,
** along the lines of inet_pton(3) / inet_ntop(3).
**
** The package can optionally be compiled with -DSTATS, which adds
** some instrumentation and a routine for returning the numbers.
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

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "iptab.h"


struct _real_iptab {
    unsigned int size, count;
    ipaddress** addresses;
    };
typedef struct _real_iptab* real_iptab;

/* Bit masks starting at the MSB. The array index is the number of bits set. */
static unsigned char bitmask[8] = {
    0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe };

typedef enum { ite_none, ite_memory, ite_componentbounds, ite_widthbounds, ite_length, ite_widthinvalid, ite_badv4, ite_badv6, ite_nonprefixnonzero, ite_shouldnthappen } iptab_err ;
static iptab_err err = ite_none;

#ifdef STATS

static void* my_malloc( size_t size );
static void my_free( void* ptr );
#ifdef notdef
static void* my_realloc( void* ptr, size_t size );
static char* my_strdup( const char* str );
#endif /* notdef */

static int stats_mallocs = 0;
static int stats_frees = 0;
static ssize_t stats_memchange = 0;
static int stats_collisions = 0;
static int stats_expansions = 0;

#else /* STATS */

#define my_malloc( size ) malloc( size )
#define my_free( ptr ) free( ptr )
#ifdef notdef
#define my_realloc( ptr, size ) realloc( ptr, size )
#define my_strdup( str ) strdup( str )
#endif /* notdef */

#endif /* STATS */


static unsigned int
hash_address( const ipaddress* ipa )
    {
    unsigned int hash = 5381;
    int i;

    for ( i = 0; i < 16; ++i )
	hash = ( ( hash << 5 ) + hash ) ^ ipa->octets[i];
    hash = ( ( hash << 5 ) + hash ) ^ ipa->prefixlen;

    return hash;
    }


static bool
address_eq( const ipaddress* ipa1, const ipaddress* ipa2 )
    {
    int i;

    for ( i = 0; i < 16; ++i )
	if ( ipa1->octets[i] != ipa2->octets[i] )
	    return false;
    if ( ipa1->prefixlen != ipa2->prefixlen )
	return false;
    return true;
    }


static unsigned int
find_hash_entry( ipaddress** addresses, unsigned int size, const ipaddress* ipa )
    {
    unsigned int hash;

    hash = hash_address( ipa ) % size;
    for (;;)
	{
	if ( addresses[hash] == (ipaddress*) 0 )
	    return hash;
	if ( address_eq( addresses[hash], ipa ) )
	    return hash;
	++hash;
	if ( hash > size )
	    hash = 0;
#ifdef STATS
	++stats_collisions;
#endif /* STATS */
	}
    }


iptab
iptab_new( void )
    {
    real_iptab ript;

    ript = (real_iptab) my_malloc( sizeof(struct _real_iptab) );
    if ( ript == (real_iptab) 0 )
	{
	err = ite_memory;
	return (iptab) 0;
	}
    ript->size = 10000;
    ript->count = 0;
    ript->addresses = (ipaddress**) my_malloc( ript->size * sizeof(ipaddress*) );
    if ( ript->addresses == (ipaddress**) 0 )
	{
	my_free( (void*) ript );
	err = ite_memory;
	return (iptab) 0;
	}
    bzero( (void*) ript->addresses, ript->size * sizeof(ipaddress*) );

    return (iptab) ript;
    }


void
iptab_clear( iptab ipt )
    {
    real_iptab ript = (real_iptab) ipt;
    int i;

    for ( i = 0; i < ript->size; ++i )
	{
	if ( ript->addresses[i] != (ipaddress*) 0 )
	    my_free( (void*) ript->addresses[i] );
	ript->addresses[i] = (ipaddress*) 0;
	}
    ript->count = 0;
    }


void
iptab_delete( iptab ipt )
    {
    real_iptab ript = (real_iptab) ipt;

    iptab_clear( ipt );
    my_free( (void*) ript->addresses );
    my_free( (void*) ript );
    }


static bool
parse_shorts( const char* str, ipaddress* ipa )
    {
    int s[8], w, i;

    for ( i = 0; i < 8; ++i )
	s[i] = 0;
    if ( sscanf( str, "%x:%x:%x:%x:%x:%x:%x:%x", &s[0], &s[1], &s[2], &s[3], &s[4], &s[5], &s[6], &s[7] ) == 8 )
	w = 128;
    else if ( sscanf( str, "%x:%x:%x:%x:%x:%x:%x", &s[0], &s[1], &s[2], &s[3], &s[4], &s[5], &s[6] ) == 7 )
	w = 112;
    else if ( sscanf( str, "%x:%x:%x:%x:%x:%x", &s[0], &s[1], &s[2], &s[3], &s[4], &s[5] ) == 6 )
	w = 96;
    else if ( sscanf( str, "%x:%x:%x:%x:%x", &s[0], &s[1], &s[2], &s[3], &s[4] ) == 5 )
	w = 80;
    else if ( sscanf( str, "%x:%x:%x:%x", &s[0], &s[1], &s[2], &s[3] ) == 4 )
	w = 64;
    else if ( sscanf( str, "%x:%x:%x", &s[0], &s[1], &s[2] ) == 3 )
	w = 48;
    else if ( sscanf( str, "%x:%x", &s[0], &s[1] ) == 2 )
	w = 32;
    else if ( sscanf( str, "%x", &s[0] ) == 1 )
	w = 16;
    else
	w = 0;

    for ( i = 0; i < 8; ++i )
	if ( s[i] < 0 || s[i] > 0xffff )
	    {
	    err = ite_componentbounds;
	    return false;
	    }
    if ( w < 0 || w > 128 )
	{
	err = ite_widthbounds;
	return false;
	}

    for ( i = 0; i < 8; ++i )
	{
	ipa->octets[i * 2] = s[i] >> 8;
	ipa->octets[i * 2 + 1] = s[i] & 0xff;
	}
    ipa->prefixlen = w;

    return true;
    }

bool
iptab_parse_address( const char* str, ipaddress* ipa )
    {
    const char* slash;
    int i, w;
    int prefix_octet, prefix_bit;
    unsigned char prefix_bitmask;

    /* Initialize to all zero. */
    for ( i = 0; i < 16; ++i )
	ipa->octets[i] = 0;

    if ( strchr( str, ':' ) != (char*) 0 )
	{
	/* IPv6 address. */
	const char* doublecolon;
	int o;

	/* Is there a double colon? There can be either 0 or 1, not more. */
	doublecolon = strstr( str, "::" );
	if ( doublecolon == (char*) 0 )
	    {
	    if ( ! parse_shorts( str, ipa ) )
		return false;
	    w = ipa->prefixlen;
	    }
	else
	    {
	    ipaddress left, right;

	    if ( ! parse_shorts( str, &left ) )
		return false;
	    if ( ! parse_shorts( doublecolon + 2, &right ) )
		return false;
	    if ( left.prefixlen + right.prefixlen >= 112 )
		{
		err = ite_length;
		return false;
		}
	    o = left.prefixlen / 8;
	    for ( i = 0; i < o; ++i )
		ipa->octets[i] = left.octets[i];
	    o = right.prefixlen / 8;
	    for ( i = 0; i < o; ++i )
		ipa->octets[16 - o + i] = right.octets[i];
	    if ( right.prefixlen != 0 )
		w = 128;
	    else
		w = left.prefixlen;
	    }

	/* Is there a /width? */
	slash = strchr( str, '/' );
	if ( slash != (const char*) 0 )
	    {
	    if ( sscanf( slash, "/%d", &ipa->prefixlen ) != 1 )
		{
		err = ite_widthinvalid;
		return false;
		}
	    }
	if ( w < 0 || w > 128 )
	    {
	    err = ite_widthbounds;
	    return false;
	    }
	ipa->prefixlen = w;
	}
    else
	{
	/* IPv4 address. */
	int b[4];

	/* Initialize to ::ffff:0:0, the IPv4-mapped IPv6 address. The v4
	** address goes in the last four octets, and the prefix len is
	** the v4 netmask width plus 96.
	*/
	ipa->octets[10] = ipa->octets[11] = 0xff;

	/* Parse the dotted quad. */
	for ( i = 0; i < 4; ++i )
	    b[i] = 0;
	if ( sscanf( str, "%d.%d.%d.%d", &b[0], &b[1], &b[2], &b[3] ) == 4 )
	    w = 32;
	else if ( sscanf( str, "%d.%d.%d", &b[0], &b[1], &b[2] ) == 3 )
	    w = 24;
	else if ( sscanf( str, "%d.%d", &b[0], &b[1] ) == 2 )
	    w = 16;
	else if ( sscanf( str, "%d", &b[0] ) == 1 )
	    w = 8;
	else
	    {
	    err = ite_badv4;
	    return false;
	    }

	/* Is there a /width? */
	slash = strchr( str, '/' );
	if ( slash != (const char*) 0 )
	    {
	    if ( sscanf( slash, "/%d", &w ) != 1 )
		{
		err = ite_widthinvalid;
		return false;
		}
	    }

	for ( i = 0; i < 4; ++i )
	    if ( b[i] < 0 || b[i] > 255 )
		{
		err = ite_componentbounds;
		return false;
		}
	if ( w < 0 || w > 32 )
	    {
	    err = ite_widthbounds;
	    return false;
	    }

	for ( i = 0; i < 4; ++i )
	    ipa->octets[i + 12] = b[i];
	ipa->prefixlen = w + 96;
	}

    /* Be sure that the non-prefix part is all zero. */
    prefix_octet = ipa->prefixlen / 8;
    prefix_bit = ipa->prefixlen - prefix_octet * 8;
    prefix_bitmask = bitmask[prefix_bit];
    if ( prefix_octet < 16 &&
	 ( ipa->octets[prefix_octet] & ~ prefix_bitmask ) != 0 )
	{
	err = ite_nonprefixnonzero;
	return false;
	}
    for ( i = prefix_octet + 1; i < 16; ++i )
	if ( ipa->octets[i] != 0 )
	    {
	    err = ite_nonprefixnonzero;
	    return false;
	    }

    return true;
    }


char*
iptab_format_address( const ipaddress* ipa, char* str, size_t size )
    {
    if ( iptab_is_ipv4( ipa ) )
	{
	if ( ipa->prefixlen == 128 )
	    snprintf(
	      str, size, "%d.%d.%d.%d",
	      ipa->octets[12], ipa->octets[13],
	      ipa->octets[14], ipa->octets[15] );
	else
	    snprintf(
	      str, size, "%d.%d.%d.%d/%d",
	      ipa->octets[12], ipa->octets[13],
	      ipa->octets[14], ipa->octets[15],
	      ipa->prefixlen - 96 );
	}
    else
	{
	if ( ipa->prefixlen == 128 )
	    snprintf(
	      str, size, "%x:%x:%x:%x:%x:%x:%x:%x",
	      ipa->octets[0] << 8 | ipa->octets[1],
	      ipa->octets[2] << 8 | ipa->octets[3],
	      ipa->octets[4] << 8 | ipa->octets[5],
	      ipa->octets[6] << 8 | ipa->octets[7],
	      ipa->octets[8] << 8 | ipa->octets[9],
	      ipa->octets[10] << 8 | ipa->octets[11],
	      ipa->octets[12] << 8 | ipa->octets[13],
	      ipa->octets[14] << 8 | ipa->octets[15] );
	else
	    snprintf(
	      str, size, "%x:%x:%x:%x:%x:%x:%x:%x/%d",
	      ipa->octets[0] << 8 | ipa->octets[1],
	      ipa->octets[2] << 8 | ipa->octets[3],
	      ipa->octets[4] << 8 | ipa->octets[5],
	      ipa->octets[6] << 8 | ipa->octets[7],
	      ipa->octets[8] << 8 | ipa->octets[9],
	      ipa->octets[10] << 8 | ipa->octets[11],
	      ipa->octets[12] << 8 | ipa->octets[13],
	      ipa->octets[14] << 8 | ipa->octets[15],
	      ipa->prefixlen );
	/* Should elide the longest run of zeroes. */
	}

    return str;
    }


static bool
iptab_add_i( iptab ipt, const ipaddress* ipa )
    {
    real_iptab ript = (real_iptab) ipt;
    unsigned int hash;

    hash = find_hash_entry( ript->addresses, ript->size, ipa );
    if ( ript->addresses[hash] != (ipaddress*) 0 )
	return true;	/* already in the table */

    if ( ript->count * 4 >= ript->size )
	{
	/* Expand and rehash. */
	unsigned int new_size;
	ipaddress** new_addresses;
	int i;

	new_size = ript->size * 2;
	new_addresses = (ipaddress**) my_malloc( new_size * sizeof(ipaddress*) );
	if ( new_addresses == (ipaddress**) 0 )
	    {
	    err = ite_memory;
	    return false;
	    }
	bzero( (void*) new_addresses, new_size * sizeof(ipaddress*) );
	for ( i = 0; i < ript->size; ++i )
	    {
	    if ( ript->addresses[i] != (ipaddress*) 0 )
		{
		hash = find_hash_entry( new_addresses, new_size, ript->addresses[i] );
		if ( new_addresses[hash] != (ipaddress*) 0 )
		    {
		    err = ite_shouldnthappen;
		    return false;	/* shouldn't happen */
		    }
		new_addresses[hash] = ript->addresses[i];
		}
	    }
	ript->size = new_size;
	my_free( (void*) ript->addresses );
	ript->addresses = new_addresses;
#ifdef STATS
	++stats_expansions;
#endif /* STATS */
	/* And rehash the address being added with the new size. */
	hash = find_hash_entry( ript->addresses, ript->size, ipa );
	if ( ript->addresses[hash] != (ipaddress*) 0 )
	    {
	    err = ite_shouldnthappen;
	    return false;	/* shouldn't happen */
	    }
	}

    ript->addresses[hash] = (ipaddress*) my_malloc( sizeof(ipaddress) );
    if ( ript->addresses[hash] == (ipaddress*) 0 )
	{
	err = ite_memory;
	return false;
	}
    *ript->addresses[hash] = *ipa;
    ++ript->count;
    return true;
    }


bool
iptab_add( iptab ipt, const ipaddress* ipa )
    {
    int prefix_octet, prefix_bit;
    unsigned char prefix_bitmask;
    ipaddress ipa1, ipa2;

    prefix_octet = ipa->prefixlen / 8;
    prefix_bit = ipa->prefixlen - prefix_octet * 8;

    /* If the prefixlen is divisible by 8, add it directly. */
    if ( prefix_bit == 0 )
	return iptab_add_i( ipt, ipa );

    /* Handle non-8-bit prefixlens via recursive binary decomposition. */
    ipa1 = ipa2 = *ipa;
    ipa1.prefixlen = ipa2.prefixlen = ipa->prefixlen + 1;
    prefix_bitmask = bitmask[prefix_bit];
    ipa1.octets[prefix_octet] |= ~ prefix_bitmask;
    ipa2.octets[prefix_octet] &= prefix_bitmask;
    return iptab_add( ipt, &ipa1 ) && iptab_add( ipt, &ipa2 );
    }


bool
iptab_check( const iptab ipt, const ipaddress* ipa )
    {
    real_iptab ript = (real_iptab) ipt;
    ipaddress tipa;
    int i;
    unsigned int hash;

    /* Loop checking successively shorter prefixes. */
    tipa = *ipa;
    i = tipa.prefixlen / 8 - 1;
    while ( i >= 0 )
	{
	hash = find_hash_entry( ript->addresses, ript->size, &tipa );
	if ( ript->addresses[hash] != (ipaddress*) 0 )
	    return true;
	tipa.octets[i] = 0;
	tipa.prefixlen -= 8;
	--i;
	}
    return false;
    }


static bool
make_mask( int prefixlen, ipaddress* ipa )
    {
    int prefix_octet, prefix_bit;
    unsigned char prefix_bitmask;
    int i;

    if ( prefixlen < 0 || prefixlen > 128 )
	{
	err = ite_widthbounds;
	return false;
	}

    prefix_octet = prefixlen / 8;
    prefix_bit = prefixlen - prefix_octet * 8;
    prefix_bitmask = bitmask[prefix_bit];
    for ( i = 0; i < 16; ++i )
	{
	if ( i < prefix_octet )
	    ipa->octets[i] = 0xff;
	else if ( i == prefix_octet )
	    ipa->octets[i] = prefix_bitmask;
	else
	    ipa->octets[i] = 0;
	}

    ipa->prefixlen = prefixlen;
    return true;
    }


bool
iptab_includes( const ipaddress* ipn, const ipaddress* ipa )
    {
    ipaddress ipm;
    int i;

    if ( ipa->prefixlen < ipn->prefixlen )
	return false;
    if ( ! make_mask( ipn->prefixlen, &ipm ) )
	return false;
    for ( i = 0; i < 16; ++i )
	if ( ( ipa->octets[i] & ipm.octets[i] ) != ( ipn->octets[i] & ipm.octets[i] ) )
	    return false;
    return true;
    }


bool
iptab_is_ipv4( const ipaddress* ipa )
    {
    int i;

    for ( i = 0; i < 10; ++i )
	if ( ipa->octets[i] != 0 )
	    return false;
    if ( ipa->octets[10] == 0xff && ipa->octets[11] == 0xff )
	return true;
    return false;
    }


char*
iptab_error_str( void )
    {
    switch ( err )
	{
	case ite_none: return "no error";
	case ite_memory: return "out of memory";
	case ite_componentbounds: return "address component is out of bounds";
	case ite_widthbounds: return "prefix/netmask width is out of bounds";
	case ite_length: return "address is too long";
	case ite_widthinvalid: return "prefix/netmask width is invalid";
	case ite_badv4: return "invalid IPv4 address";
	case ite_badv6: return "invalid IPv6 address";
	case ite_nonprefixnonzero: return "non-prefix part is non-zero";
	case ite_shouldnthappen: return "shouldn't happen";
	default: return "unknown error";
	}
    }


#ifdef STATS

static void*
my_malloc( size_t size )
    {
    size_t* real_ptr;
    void* ptr;

    ++stats_mallocs;
    stats_memchange += size;
    real_ptr = (size_t*) malloc( size + sizeof(size_t) );
    *real_ptr = size;
    ptr = (void*) ( real_ptr + 1 );
    return ptr;
    }


static void
my_free( void* ptr )
    {
    size_t* real_ptr;
    size_t size;

    real_ptr = (size_t*) ptr;
    real_ptr -= 1;
    size = *real_ptr;
    ++stats_frees;
    stats_memchange -= size;
    free( real_ptr );
    }


#ifdef notdef

static void*
my_realloc( void* ptr, size_t size )
    {
    void* newptr = my_malloc( size );

    memcpy( newptr, ptr, size );
    my_free( ptr );
    return newptr;
    }


static char*
my_strdup( const char* str )
    {
    char* newstr = my_malloc( strlen( str ) + 1 );

    (void) strcpy( newstr, str );
    return newstr;
    }

#endif /* notdef */


void
iptab_stats( int* mallocsP, int* freesP, ssize_t* memchangeP, int* collisionsP, int* expansionsP )
    {
    *mallocsP = stats_mallocs;
    *freesP = stats_frees;
    *memchangeP = stats_memchange;
    *collisionsP = stats_collisions;
    *expansionsP = stats_expansions;

    stats_mallocs = 0;
    stats_frees = 0;
    stats_memchange = 0;
    stats_collisions = 0;
    stats_expansions = 0;
    }

#endif /* STATS */
