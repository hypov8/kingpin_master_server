/*

GS enctype1 servers list decoder 0.1a
by Luigi Auriemma
e-mail: aluigi@autistici.org
web:    aluigi.org


INTRODUCTION
============
This is the algorithm used to decrypt the data sent by the Gamespy
master server (or any other compatible server) using the enctype 1
method.


THANX TO
========
REC (http://www.backerstreet.com/rec/rec.htm) which has helped me in many
parts of the code.


LICENSE
=======
    Copyright 2005,2006,2007,2008 Luigi Auriemma

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

    http://www.gnu.org/licenses/gpl.txt

*/


#include "common.h"

unsigned char gsvalfunc(int reg) {
    if(reg < 26) return ((u8)reg + 'A');
    if(reg < 52) return ((u8)reg + 'G');
    if(reg < 62) return ((u8)reg - 4);
    if(reg == 62) return ('+');
    if(reg == 63) return ('/');
    return(0);
}
										//null				TXKOAT.....			QFWxY2 (kp)
unsigned char *gsseckey(  unsigned char *dst,  unsigned char *src,  unsigned char *key, int enctype) 
{
    int             i, size,  keysz;
    unsigned char   enctmp[256], tmp[66], x,  y, z, a, b,*p;
	static const unsigned char enctype1_data[257] = /* pre-built */
    "\x01\xba\xfa\xb2\x51\x00\x54\x80\x75\x16\x8e\x8e\x02\x08\x36\xa5"
    "\x2d\x05\x0d\x16\x52\x07\xb4\x22\x8c\xe9\x09\xd6\xb9\x26\x00\x04"
    "\x06\x05\x00\x13\x18\xc4\x1e\x5b\x1d\x76\x74\xfc\x50\x51\x06\x16"
    "\x00\x51\x28\x00\x04\x0a\x29\x78\x51\x00\x01\x11\x52\x16\x06\x4a"
    "\x20\x84\x01\xa2\x1e\x16\x47\x16\x32\x51\x9a\xc4\x03\x2a\x73\xe1"
    "\x2d\x4f\x18\x4b\x93\x4c\x0f\x39\x0a\x00\x04\xc0\x12\x0c\x9a\x5e"
    "\x02\xb3\x18\xb8\x07\x0c\xcd\x21\x05\xc0\xa9\x41\x43\x04\x3c\x52"
    "\x75\xec\x98\x80\x1d\x08\x02\x1d\x58\x84\x01\x4e\x3b\x6a\x53\x7a"
    "\x55\x56\x57\x1e\x7f\xec\xb8\xad\x00\x70\x1f\x82\xd8\xfc\x97\x8b"
    "\xf0\x83\xfe\x0e\x76\x03\xbe\x39\x29\x77\x30\xe0\x2b\xff\xb7\x9e"
    "\x01\x04\xf8\x01\x0e\xe8\x53\xff\x94\x0c\xb2\x45\x9e\x0a\xc7\x06"
    "\x18\x01\x64\xb0\x03\x98\x01\xeb\x02\xb0\x01\xb4\x12\x49\x07\x1f"
    "\x5f\x5e\x5d\xa0\x4f\x5b\xa0\x5a\x59\x58\xcf\x52\x54\xd0\xb8\x34"
    "\x02\xfc\x0e\x42\x29\xb8\xda\x00\xba\xb1\xf0\x12\xfd\x23\xae\xb6"
    "\x45\xa9\xbb\x06\xb8\x88\x14\x24\xa9\x00\x14\xcb\x24\x12\xae\xcc"
    "\x57\x56\xee\xfd\x08\x30\xd9\xfd\x8b\x3e\x0a\x84\x46\xfa\x77\xb8";

    if(!dst) {
        dst = malloc(89);
        if(!dst) return(NULL);
    }
//1
    size = strlen((const char*)src);
    if((size < 1) || (size > 65)) {
        dst[0] = 0;
        return(dst);
    }
    keysz = strlen((const char*)key);
//2
    for(i = 0; i < 256; i++) {
        enctmp[i] = (u8)i;
    }
//3
    a = 0;
    for(i = 0; i < 256; i++) {
		a = ( ( enctmp[ i ] + key[ i % keysz ] ) + a ) & 0xff; //wrap
        x = enctmp[a];
        enctmp[a] = enctmp[i];
        enctmp[i] = x;
    }
//4
    a = 0;
    b = 0;
    for(i = 0; src[i]; i++) {
		a = ((src[i] + 1) + a) & 0xff; //wrap
        x = enctmp[a];
		b = (x +b) & 0xff; //wrap
        y = enctmp[b];
        enctmp[b] = x;
        enctmp[a] = y;
        tmp[i] = src[i] ^ enctmp[(x + y) & 0xff];
    }
	//5
    for(size = i; size % 3; size++) {
        tmp[size] = 0;
    }

	//encryption
    if(enctype == 1) {
        for(i = 0; i < size; i++) {
            tmp[i] = enctype1_data[tmp[i]];
        }
    } else if(enctype == 2) {
        for(i = 0; i < size; i++) {
            tmp[i] ^= key[i % keysz];
        }
    }


	//6
    p = dst;
    for(i = 0; i < size; i += 3) {
        x = tmp[i];
        y = tmp[i + 1];
        z = tmp[i + 2];
        *p++ = gsvalfunc(x >> 2);
        *p++ = gsvalfunc(((x & 3) << 4) | (y >> 4));
        *p++ = gsvalfunc(((y & 15) << 2) | (z >> 6));
        *p++ = gsvalfunc(z & 63);
    }
    *p = 0;

    return(dst);
}


#define listCnt 6
gamesList_t gameList[listCnt] =
{
	{ "GameSpy Lite",			"gspylite",		"mgNUaC" }, //gamespy
	{ "GameSpy 3D",				"gamespy2",		"d4kZca" },	//gslist
	{ "GameSpy Arcade",			"gslive",		"Xn221z" },	//encrypted -1. use??
	{ "Kingpin: Life of Crime", "kingpin",		"QFWxY2" },
	{ "Kingpin Q3",				"kingpinq3",	"QFWxY2" }, //generate key?
	{ "Quake II",				"quake2",		"rtW0xg" }
};

//check gamename validation
int gslist_step_2(u8 *validate, char* browser, int enctype) 
{
	int i;
    u8      *sec    = (u8*)M2B_KEY;

	for (i = 0; i < listCnt; i++)
	{
		if (strcmp(gameList[i].short_name, browser)==0)
		{
			// found browser
			break;
		}
	}

	//browser not supported
	if (i >= listCnt)
		return 0;
 
	//compare validate string
	gsseckey(validate, sec, (u8*)gameList[i].code_name, enctype); //"QFWxY2""
	MsgPrint(MSG_DEBUG, "Validate:    %s -> %s\n", M2B_KEY, validate);
	return 1;
}

