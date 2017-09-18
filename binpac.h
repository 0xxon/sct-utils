/*
This is a modified include file of BinPAC.
See https://www.bro.org/sphinx/components/binpac/README.html

Separate copyright for this file:

Copyright (c) 1995-2013, The Regents of the University of California
through the Lawrence Berkeley National Laboratory and the
International Computer Science Institute. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

(1) Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.

(2) Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

(3) Neither the name of the University of California, Lawrence Berkeley
    National Laboratory, U.S. Dept. of Energy, International Computer
    Science Institute, nor the names of contributors may be used to endorse
    or promote products derived from this software without specific prior
    written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

Note that some files in the distribution may carry their own copyright
notices.
*/

#ifndef binpac_h
#define binpac_h

#include <sys/param.h>

/* #undef HOST_BIGENDIAN */
#ifdef HOST_BIGENDIAN
#  define HOST_BYTEORDER	bigendian
#else
#  define HOST_BYTEORDER	littleendian
#endif

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string>
#include <memory>

// Expose C99 functionality from inttypes.h, which would otherwise not be
// available in C++.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <inttypes.h>

#define BINPAC_ASSERT(x)	assert(x)

using namespace std;

namespace binpac {

const int bigendian = 0;
const int littleendian = 1;
const int unspecified_byteorder = -1;

#ifndef pac_type_defs
#define pac_type_defs

typedef int8_t		int8;
typedef int16_t		int16;
typedef int32_t		int32;
typedef int64_t		int64;
typedef uint8_t		uint8;
typedef uint16_t	uint16;
typedef uint32_t	uint32;
typedef uint64_t	uint64;
typedef void		*nulptr;
typedef void		*voidptr;
typedef uint8		*byteptr;
typedef const uint8	*const_byteptr;
typedef const char	*const_charptr;

#if 4 != 4
#error "unexpected size of unsigned int"
#endif

#endif /* pac_type_defs */

/* Handling byte order */

namespace {

inline int16 pac_swap(int16 x)
	{
	return (x >> 8) | ((x & 0xff) << 8);
	}

inline uint16 pac_swap(uint16 x)
	{
	return (x >> 8) | ((x & 0xff) << 8);
	}

inline int32 pac_swap(int32 x)
	{
	return 	(x >> 24) | 
		((x & 0xff0000) >> 8) | 
		((x & 0xff00) << 8) | 
		((x & 0xff) << 24);
	}

inline uint32 pac_swap(uint32 x)
	{
	return 	(x >> 24) | 
		((x & 0xff0000) >> 8) | 
		((x & 0xff00) << 8) | 
		((x & 0xff) << 24);
	}

inline int64 pac_swap(int64 i)
	{
	unsigned char c;
	union {
		uint64 i;
		unsigned char c[8];
	} x;

	x.i = i;
	c = x.c[0]; x.c[0] = x.c[7]; x.c[7] = c;
	c = x.c[1]; x.c[1] = x.c[6]; x.c[6] = c;
	c = x.c[2]; x.c[2] = x.c[5]; x.c[5] = c;
	c = x.c[3]; x.c[3] = x.c[4]; x.c[4] = c;
	return x.i;
	}

inline uint64 pac_swap(uint64 i)
	{
	unsigned char c;
	union {
		uint64 i;
		unsigned char c[8];
	} x;

	x.i = i;
	c = x.c[0]; x.c[0] = x.c[7]; x.c[7] = c;
	c = x.c[1]; x.c[1] = x.c[6]; x.c[6] = c;
	c = x.c[2]; x.c[2] = x.c[5]; x.c[5] = c;
	c = x.c[3]; x.c[3] = x.c[4]; x.c[4] = c;
	return x.i;
	}

#define FixByteOrder(byteorder, x)	(byteorder == HOST_BYTEORDER ? (x) : pac_swap(x))

template <class T>
inline T UnMarshall(const u_char *data, int byteorder)
	{
	T result = 0;
	for ( int i = 0; i < (int) sizeof(T); ++i )
		result = ( result << 8 ) | 
			data[byteorder == bigendian ? i : sizeof(T) - 1 - i];
	return result;
	}

inline const char* do_fmt(const char* format, va_list ap)
	{
	static char buf[1024];
	vsnprintf(buf, sizeof(buf), format, ap);
	return buf;
	}

inline string strfmt(const char* format, ...)
	{
	va_list ap;
	va_start(ap, format);
	const char* r = do_fmt(format, ap);
	va_end(ap);
	return string(r);
	}

} // anonymous namespace

#define binpac_fmt(x...) strfmt(x).c_str()

class RefCount
{
public:
	RefCount() 	{ count = 1; }
	virtual ~RefCount() {}
	void Ref() 	{ ++count; }
	int Unref() 	{ BINPAC_ASSERT(count > 0); return --count; }

private:
	int count;
};

namespace {
	inline void Unref(RefCount *x)
		{
		if ( x && x->Unref() <= 0 )
			delete x;
		}
}  // anonymous namespace

} // namespace binpac

#include "binpac_analyzer.h"
#include "binpac_buffer.h"
#include "binpac_bytestring.h"
#include "binpac_exception.h"
// #include "binpac_regex.h"

#endif /* binpac_h */
