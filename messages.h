/*
	messages.h

	Message management for xrealmaster

	Copyright (C) 2004  Mathieu Olivier

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
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/


#ifndef _MESSAGES_H_
#define _MESSAGES_H_




// ---------- Public functions ---------- //

// Parse a packet to figure out what to do with it
void	HandleMessage(const char *msg, const struct sockaddr_in *address);

///hypov8 gamespy specific requests
void		HandleGspyMessage(const char *msg, const struct sockaddr_in *address, SOCKET_NET clientSock);
void		HandleMessageKPQ3(const char *msg, const struct sockaddr_in *address);
qboolean	IsInitialGameSpyPacket(const char *msg);

//unsigned char *gsseckey(unsigned char *dst, unsigned char *src, unsigned char *key, int enctype);

#endif							// _MESSAGES_H_
